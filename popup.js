// popup.js: runs each time the toolbar icon is clicked.
//
// It collects data from three places, turns it into findings, scores them, and
// draws the result. The popup page is destroyed when it closes, so every click
// is a fresh scan and nothing is remembered here.

const MISCONFIG = "A02:2025 Security Misconfiguration";
const CRYPTO = "A04:2025 Cryptographic Failures";

const SEVERITY_ORDER = { high: 0, medium: 1, low: 2 };
const SEVERITY_PENALTY = { high: 20, medium: 10, low: 5 };
const NEXT_GRADES = [
  { grade: "D", score: 60 },
  { grade: "C", score: 70 },
  { grade: "B", score: 80 },
  { grade: "A", score: 90 },
];

// Every check the scan can run, used to explain what a page did right.
// "needs" says what data the check requires, so a check that could not run is
// never reported as passed.
const CHECKS = [
  { id: "https", needs: "web", passed: "Page is served over HTTPS" },
  { id: "header-content-security-policy", needs: "headers", passed: "Content-Security-Policy is set" },
  { id: "header-strict-transport-security", needs: "headers", passed: "Strict-Transport-Security is set" },
  { id: "header-x-frame-options", needs: "headers", passed: "Protected against framing (clickjacking)" },
  { id: "header-x-content-type-options", needs: "headers", passed: "X-Content-Type-Options is set" },
  { id: "header-referrer-policy", needs: "headers", passed: "Referrer-Policy is set" },
  { id: "header-permissions-policy", needs: "headers", passed: "Permissions-Policy is set" },
  { id: "info-disclosure", needs: "headers", passed: "No server software named in checked headers" },
  { id: "cookie-secure", needs: "web", passed: "No cookies missing Secure" },
  { id: "cookie-httponly", needs: "web", passed: "No cookies missing HttpOnly" },
  { id: "cookie-samesite", needs: "web", passed: "No cookies with a weak SameSite" },
  { id: "password-http", needs: "dom", passed: "No password field exposed over HTTP" },
  { id: "mixed-active", needs: "dom", passed: "No active mixed content", httpsOnly: true },
  { id: "mixed-passive", needs: "dom", passed: "No passive mixed content", httpsOnly: true },
  { id: "lib-jquery", needs: "dom", passed: "No outdated jQuery detected" },
  { id: "lib-angularjs", needs: "dom", passed: "No AngularJS 1.x detected" },
  { id: "lib-lodash", needs: "dom", passed: "No outdated Lodash detected" },
  { id: "lib-bootstrap", needs: "dom", passed: "No outdated Bootstrap detected" },
  { id: "sri", needs: "dom", passed: "No external scripts missing integrity" },
];

// The latest scan and the fixes being previewed. Lost when the popup closes.
let currentScan = null;
let explainMode = loadExplainMode();
const previewedFixes = new Set();

const RESTRICTED_PAGE_MESSAGE = "Chrome does not let extensions read its own pages. Open a website to scan it.";

// ---------- Explanation style ----------

// Plain English is the default. localStorage only remembers this one choice.
function loadExplainMode() {
  try {
    return localStorage.getItem("explainMode") === "technical" ? "technical" : "plain";
  } catch {
    return "plain";
  }
}

function setExplainMode(mode) {
  explainMode = mode;
  try {
    localStorage.setItem("explainMode", mode);
  } catch {
    // The choice just will not be remembered.
  }
  applyExplainMode();
  if (currentScan) drawResults();
}

function applyExplainMode() {
  document.body.dataset.mode = explainMode;
  document.getElementById("mode-plain").setAttribute("aria-pressed", String(explainMode === "plain"));
  document.getElementById("mode-technical").setAttribute("aria-pressed", String(explainMode === "technical"));
}

function displayTitle(finding) {
  return explainMode === "plain" ? plainTitle(finding) : finding.title;
}

// ---------- Collecting data ----------

// Runs in the page's own JavaScript world ("MAIN"), the only place that can see
// window.jQuery and friends.
//
// Chrome converts this function to text and re-creates it inside the page, so
// it must be self-contained: it cannot use anything defined elsewhere in this
// file. It is wrapped in try/catch because the page controls these objects.
function readPageGlobals() {
  const found = [];
  const add = (id, version) => {
    if (typeof version === "string" && /^\d+(\.\d+)*/.test(version)) found.push({ id, version });
  };
  try {
    const jq = window.jQuery;
    add("jquery", jq?.fn?.jquery);
    add("angularjs", window.angular?.version?.full);
    // Underscore also exposes _.VERSION. flowRight exists only in Lodash.
    if (typeof window._?.flowRight === "function") add("lodash", window._.VERSION);
    add("bootstrap", window.bootstrap?.Tooltip?.VERSION || jq?.fn?.tooltip?.Constructor?.VERSION);
  } catch {
    // A hostile or unusual page object. The script URL checks still run.
  }
  return found;
}

async function getPageLibraries(tabId) {
  try {
    const [injection] = await chrome.scripting.executeScript({
      target: { tabId },
      world: "MAIN",
      injectImmediately: true,
      func: readPageGlobals,
    });
    return injection?.result || [];
  } catch {
    return [];
  }
}

// Asks content.js for its DOM report. Tabs opened before the extension was
// installed do not have content.js yet, so sendMessage fails with "Receiving
// end does not exist". In that case inject it now and ask once more.
async function getDomReport(tabId) {
  const message = { type: "SCAN_DOM", pageLibraries: await getPageLibraries(tabId) };
  try {
    return await chrome.tabs.sendMessage(tabId, message, { frameId: 0 });
  } catch {
    try {
      await chrome.scripting.executeScript({ target: { tabId }, files: ["content.js"] });
      return await chrome.tabs.sendMessage(tabId, message, { frameId: 0 });
    } catch {
      return null; // Pages Chrome does not let extensions touch.
    }
  }
}

async function getHeaderCapture(tabId) {
  try {
    return await chrome.runtime.sendMessage({ type: "GET_HEADERS", tabId });
  } catch {
    return null;
  }
}

// ---------- Header checks (A02) ----------

function toHeaderMap(headers) {
  const map = new Map();
  for (const { name, value } of headers) {
    const key = name.toLowerCase();
    map.set(key, map.has(key) ? `${map.get(key)}, ${value}` : value);
  }
  return map;
}

// True when we cannot tell whether an HTTPS page sends HSTS. Chrome's HTTP cache
// does not keep that header, so its absence from a cached response proves nothing.
// Over plain HTTP the header has no effect anyway, so the answer does not change.
function isHstsUnknown(headers, pageUrl, capture) {
  return pageUrl.protocol === "https:" && capture.fromCache && !headers.has("strict-transport-security");
}

function checkSecurityHeaders(headers, pageUrl, dom, capture) {
  const findings = [];
  const isHttps = pageUrl.protocol === "https:";

  const missing = (severity, name, detail, fix) =>
    findings.push({
      id: `header-${name.toLowerCase()}`,
      severity,
      category: MISCONFIG,
      title: `Missing ${name} header`,
      detail,
      fix,
    });

  if (!headers.has("content-security-policy") && !dom?.hasMetaCsp) {
    const reportOnly = headers.has("content-security-policy-report-only")
      ? " A report-only policy is present, but it does not block anything."
      : "";
    missing(
      "high",
      "Content-Security-Policy",
      `Nothing limits which scripts this page may load or run, so any injected script executes freely.${reportOnly}`,
      "Add a Content-Security-Policy header on the server response."
    );
  }

  if (!headers.has("strict-transport-security") && !isHstsUnknown(headers, pageUrl, capture)) {
    if (isHttps) {
      missing(
        "medium",
        "Strict-Transport-Security",
        "Browsers are not told to insist on HTTPS, so a first visit or a typed http:// link can be intercepted.",
        "Add Strict-Transport-Security: max-age=31536000; includeSubDomains on HTTPS responses."
      );
    } else {
      missing(
        "low",
        "Strict-Transport-Security",
        "Browsers ignore this header over plain HTTP, so it can only start protecting users once the site moves to HTTPS.",
        "After enabling HTTPS, add Strict-Transport-Security: max-age=31536000; includeSubDomains."
      );
    }
  }

  // A CSP frame-ancestors directive does the same job and takes priority.
  const hasFrameAncestors = /frame-ancestors/i.test(headers.get("content-security-policy") || "");
  if (!headers.has("x-frame-options") && !hasFrameAncestors) {
    missing(
      "medium",
      "X-Frame-Options",
      "Other sites can load this page in a hidden frame and trick users into clicking on it (clickjacking).",
      "Add X-Frame-Options: DENY, or a CSP frame-ancestors directive."
    );
  }

  if (!headers.has("x-content-type-options")) {
    missing(
      "medium",
      "X-Content-Type-Options",
      "Browsers may guess a file's type, which can turn an uploaded file into something that runs as a script.",
      "Add X-Content-Type-Options: nosniff."
    );
  }

  if (!headers.has("referrer-policy")) {
    missing(
      "low",
      "Referrer-Policy",
      "Without an explicit policy, this site relies on the browser default for what URL data other sites receive in the Referer header.",
      "Add Referrer-Policy: strict-origin-when-cross-origin."
    );
  }

  if (!headers.has("permissions-policy")) {
    const legacy = headers.has("feature-policy") ? " The older Feature-Policy header is present, but it is deprecated." : "";
    missing(
      "low",
      "Permissions-Policy",
      `The page does not limit which browser features, such as camera or geolocation, it and its frames can use.${legacy}`,
      "Add a Permissions-Policy header that turns off features the site does not use."
    );
  }

  return findings;
}

function checkInfoDisclosure(headers) {
  const items = ["server", "x-powered-by", "x-aspnet-version"]
    .filter((name) => headers.has(name))
    .map((name) => `${name}: ${headers.get(name)}`);

  if (items.length === 0) return [];

  // A version number is what lets an attacker match known CVEs.
  const revealsVersion = items.some((item) => /\d+\.\d+/.test(item));
  return [
    {
      id: "info-disclosure",
      severity: revealsVersion ? "medium" : "low",
      category: MISCONFIG,
      title: revealsVersion ? "Server software version disclosed" : "Server software disclosed",
      detail: "Response headers name the server technology, which helps an attacker pick known exploits.",
      fix: "Remove or blank the Server, X-Powered-By, and X-AspNet-Version headers.",
      items,
    },
  ];
}

// ---------- Cookie checks (A02) ----------

function checkCookies(cookies) {
  const names = (predicate) => cookies.filter(predicate).map((cookie) => cookie.name);
  const plural = (list) => `${list.length} cookie${list.length === 1 ? "" : "s"}`;
  const findings = [];

  const noSecure = names((cookie) => !cookie.secure);
  if (noSecure.length > 0) {
    findings.push({
      id: "cookie-secure",
      severity: "medium",
      category: MISCONFIG,
      title: `${plural(noSecure)} missing Secure`,
      detail: "These cookies can be sent over unencrypted HTTP, where anyone on the network path can read them.",
      fix: "Set the Secure flag on every cookie.",
      items: noSecure,
    });
  }

  const noHttpOnly = names((cookie) => !cookie.httpOnly);
  if (noHttpOnly.length > 0) {
    findings.push({
      id: "cookie-httponly",
      severity: "medium",
      category: MISCONFIG,
      title: `${plural(noHttpOnly)} missing HttpOnly`,
      detail: "JavaScript can read these, so an XSS bug can steal them. This matters most for session cookies; some preference cookies are readable on purpose.",
      fix: "Set the HttpOnly flag on session and authentication cookies.",
      items: noHttpOnly,
    });
  }

  // "unspecified" means no attribute was sent, and "no_restriction" is SameSite=None.
  const weakSameSite = names((cookie) => cookie.sameSite === "unspecified" || cookie.sameSite === "no_restriction");
  if (weakSameSite.length > 0) {
    findings.push({
      id: "cookie-samesite",
      severity: "low",
      category: MISCONFIG,
      title: `${plural(weakSameSite)} without a restrictive SameSite`,
      detail: "These have no SameSite attribute or use SameSite=None, which leaves less protection against cross-site request forgery.",
      fix: "Set SameSite=Lax or SameSite=Strict on cookies.",
      items: weakSameSite,
    });
  }

  return findings;
}

// ---------- Transport check (A04) ----------

function checkTransport(pageUrl) {
  if (pageUrl.protocol !== "http:") return [];
  const isLocal = ["localhost", "127.0.0.1", "[::1]"].includes(pageUrl.hostname);
  return [
    {
      id: "https",
      severity: "high",
      category: CRYPTO,
      title: "Page is not served over HTTPS",
      detail: isLocal
        ? "This traffic stays on your machine because it is localhost, but the same setup on a real host would expose everything on the network."
        : "Everything on this page, including cookies and form data, travels unencrypted and can be read or changed in transit.",
      fix: "Serve the site over HTTPS and redirect all HTTP requests to it.",
    },
  ];
}

// ---------- Score and grade ----------

function totalPenalty(findings) {
  return findings.reduce((total, finding) => total + SEVERITY_PENALTY[finding.severity], 0);
}

function computeScore(findings) {
  return Math.max(0, 100 - totalPenalty(findings));
}

function computeGrade(score) {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

// ---------- Explaining the score ----------

// Sorts every check into passed or not counted. A check is passed only when it
// ran and produced no finding.
function buildCoverage(findings, { isWeb, isHttps, hasHeaders, hasDom, hstsUnknown }) {
  const found = new Set(findings.map((finding) => finding.id));
  const available = { web: isWeb, headers: hasHeaders, dom: hasDom };
  const passed = [];
  const unchecked = [];

  for (const check of CHECKS) {
    if (found.has(check.id) || (check.httpsOnly && !isHttps)) continue;
    if (check.id === "header-strict-transport-security" && hstsUnknown) {
      unchecked.push("Strict-Transport-Security, because the page came from the browser cache");
    } else if (available[check.needs]) {
      passed.push(check.passed);
    }
  }

  if (isWeb && !hasHeaders) unchecked.push("Security header checks, because response headers were not captured");
  if (!isWeb) unchecked.push("Header and cookie checks, because a local file has neither");
  if (!hasDom) unchecked.push("Page content checks, because Chrome blocked access to this page");
  return { passed, unchecked };
}

// The fewest findings to fix, biggest penalty first, to reach the next grade.
function planNextGrade(findings) {
  const score = computeScore(findings);
  const target = NEXT_GRADES.find((next) => next.score > score);
  if (!target) return null;

  const ordered = [...findings].sort((a, b) => SEVERITY_PENALTY[b.severity] - SEVERITY_PENALTY[a.severity]);
  let raw = 100 - totalPenalty(findings);
  let count = 0;
  for (const finding of ordered) {
    if (raw >= target.score) break;
    raw += SEVERITY_PENALTY[finding.severity];
    count += 1;
  }
  return { ...target, count };
}

function fixPlanText(findings, pageLabel) {
  const lines = [`Risk Pro fix plan for ${pageLabel}`, ""];
  const ordered = [...findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  ordered.forEach((finding, index) => {
    const mitigation = MITIGATIONS[finding.id];
    lines.push(`${index + 1}. [${finding.severity.toUpperCase()}] ${finding.title} (${finding.category})`);
    lines.push(`   Fix: ${finding.fix}`);
    (mitigation?.steps || []).forEach((step) => lines.push(`   - ${step}`));
    (mitigation?.snippets || []).forEach((snippet) => {
      lines.push(`   ${snippet.label}:`);
      snippet.code.split("\n").forEach((line) => lines.push(`     ${line}`));
    });
    lines.push("");
  });
  lines.push("Test every change before release. These are starting points, not guaranteed fixes.");
  return lines.join("\n");
}

async function copyWithFeedback(button, text) {
  const label = button.textContent;
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = "Copied";
  } catch {
    button.textContent = "Could not copy";
  }
  setTimeout(() => {
    button.textContent = label;
  }, 1500);
}

// ---------- Rendering ----------

// Every value goes in through textContent, never innerHTML. Cookie names, header
// values, and URLs are controlled by the site being scanned, so treating them as
// HTML would let a scanned page inject markup into this extension.
function renderMitigation(node, finding) {
  const mitigation = MITIGATIONS[finding.id];
  if (!mitigation) return;

  const box = node.querySelector(".mitigate");
  box.hidden = false;
  box.querySelector(".mitigate-owner span").textContent = mitigation.owner;
  box.querySelector(".mitigate-visitor span").textContent = mitigation.visitor;

  const steps = box.querySelector(".mitigate-steps");
  for (const step of mitigation.steps) {
    const li = document.createElement("li");
    li.textContent = step;
    steps.append(li);
  }

  const snippets = box.querySelector(".mitigate-snippets");
  for (const { label, code } of mitigation.snippets) {
    const wrap = document.createElement("div");
    wrap.className = "snippet";
    const head = document.createElement("div");
    head.className = "snippet-head";
    const name = document.createElement("span");
    name.textContent = label;
    const copy = document.createElement("button");
    copy.type = "button";
    copy.textContent = "Copy";
    copy.addEventListener("click", () => copyWithFeedback(copy, code));
    head.append(name, copy);
    const pre = document.createElement("pre");
    pre.textContent = code;
    wrap.append(head, pre);
    snippets.append(wrap);
  }
}

function renderFinding(finding, template) {
  const node = template.content.cloneNode(true);
  const dot = node.querySelector(".dot");
  dot.classList.add(`dot-${finding.severity}`);
  dot.title = `${finding.severity} severity`;
  dot.setAttribute("role", "img");
  dot.setAttribute("aria-label", dot.title);
  node.querySelector(".finding-title").textContent = displayTitle(finding);
  const plain = PLAIN[finding.id];
  if (plain) {
    renderRichText(node.querySelector(".plain-means span"), plain.means);
    node.querySelector(".plain-do span").textContent = MITIGATIONS[finding.id]?.visitor || "Be careful with personal details on this page.";
    node.querySelector(".plain-technical").textContent = `Technical name: ${finding.title}`;
  }
  node.querySelector(".mitigate-summary").textContent =
    explainMode === "plain" ? "For the site owner: how to fix it" : "How to mitigate this";
  node.querySelector(".finding-category").textContent = finding.category;
  node.querySelector(".finding-detail").textContent = finding.detail;
  node.querySelector(".finding-fix span").textContent = finding.fix;

  if (finding.items?.length) {
    const details = node.querySelector(".finding-items");
    details.hidden = false;
    details.querySelector("summary").textContent = `Show ${finding.items.length} affected`;
    for (const item of finding.items) {
      const li = document.createElement("li");
      li.textContent = item;
      details.querySelector("ul").append(li);
    }
  }

  renderMitigation(node, finding);

  // A preview needs a real score to start from, so partial scans do not get one.
  if (currentScan?.isGraded) {
    const simulate = node.querySelector(".simulate");
    simulate.hidden = false;
    simulate.querySelector("input").checked = previewedFixes.has(finding);
    simulate.querySelector("input").addEventListener("change", (event) => {
      if (event.target.checked) previewedFixes.add(finding);
      else previewedFixes.delete(finding);
      renderProjection();
    });
  }
  return node;
}

function renderProjection() {
  const box = document.getElementById("projection");
  box.hidden = previewedFixes.size === 0;
  if (box.hidden) return;

  const current = computeScore(currentScan.findings);
  const remaining = currentScan.findings.filter((finding) => !previewedFixes.has(finding));
  const projected = computeScore(remaining);
  const count = previewedFixes.size;
  const raw = 100 - totalPenalty(remaining);
  // While the raw score is below zero the shown score stays 0, so show the raw
  // change. Otherwise a real improvement would look like "+0".
  const change = raw < 0 ? `raw score ${raw}` : `+${projected - current}`;
  box.textContent = `With ${count} fix${count === 1 ? "" : "es"}: ${computeGrade(projected)}, ${projected} (${change})`;
}

function renderList(id, entries) {
  const list = document.getElementById(id);
  list.replaceChildren(
    ...entries.map(({ text, points, className }) => {
      const li = document.createElement("li");
      if (className) li.className = className;
      const mark = document.createElement("span");
      mark.className = "why-points";
      mark.textContent = points;
      const label = document.createElement("span");
      label.textContent = text;
      li.append(mark, label);
      return li;
    })
  );
}

function renderWhy({ findings, isGraded, coverage }) {
  const penalty = totalPenalty(findings);
  const raw = 100 - penalty;
  const score = Math.max(0, raw);
  const count = `${findings.length} finding${findings.length === 1 ? "" : "s"}`;

  let math = `Start at 100. ${count} cost ${penalty} points, so the score is ${score}.`;
  if (findings.length === 0) math = "Start at 100. No check found a problem, so nothing was subtracted.";
  if (raw < 0) math = `Start at 100. ${count} cost ${penalty} points, for a raw score of ${raw}. The score stops at 0.`;
  if (!isGraded) math = `No grade yet because this scan is partial. The ${count} shown would cost ${penalty} points so far.`;
  document.getElementById("why-math").textContent = math;

  const next = isGraded ? planNextGrade(findings) : null;
  const nextBox = document.getElementById("why-next");
  nextBox.hidden = !next;
  if (next) {
    nextBox.textContent = `To reach ${next.grade} (${next.score}+): fix the ${next.count} highest-impact finding${next.count === 1 ? "" : "s"}.`;
  }

  // Points lost per OWASP category.
  const table = document.getElementById("why-categories");
  const byCategory = new Map();
  for (const finding of findings) {
    byCategory.set(finding.category, (byCategory.get(finding.category) || 0) + SEVERITY_PENALTY[finding.severity]);
  }
  table.hidden = byCategory.size === 0;
  table.tBodies[0].replaceChildren(
    ...[...byCategory].map(([category, points]) => {
      const row = table.tBodies[0].insertRow();
      row.insertCell().textContent = category;
      row.insertCell().textContent = `-${points}`;
      return row;
    })
  );

  const ordered = [...findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  renderList(
    "why-lost",
    ordered.length
      ? ordered.map((finding) => ({ text: displayTitle(finding), points: `-${SEVERITY_PENALTY[finding.severity]}`, className: `lost-${finding.severity}` }))
      : [{ text: "Nothing. No check found a problem.", points: "0" }]
  );
  renderList(
    "why-passed",
    coverage.passed.length
      ? coverage.passed.map((text) => ({ text, points: "OK", className: "passed" }))
      : [{ text: "No check could confirm a pass on this page.", points: "--" }]
  );

  document.getElementById("why-unchecked-box").hidden = coverage.unchecked.length === 0;
  renderList("why-unchecked", coverage.unchecked.map((text) => ({ text, points: "?" })));

  document.getElementById("copy-plan").hidden = findings.length === 0;
}

function showTab(which) {
  for (const name of ["findings", "why", "learn"]) {
    document.getElementById(`panel-${name}`).hidden = name !== which;
    document.getElementById(`tab-${name}`).setAttribute("aria-selected", String(name === which));
  }
}

function showNotice(text, { withReload = false } = {}) {
  document.getElementById("notice-text").textContent = text;
  document.getElementById("notice-button").hidden = !withReload;
  document.getElementById("notice").hidden = false;
}

function clearResults() {
  for (const id of ["summary", "notice", "clean", "foot", "tabs", "projection", "mode", "verdict"]) {
    document.getElementById(id).hidden = true;
  }
  document.getElementById("findings").replaceChildren();
  previewedFixes.clear();
  currentScan = null;
  showTab("findings");
}

function renderResults(scan) {
  currentScan = scan;
  drawResults();
}

// Also runs when the explanation style changes, so it must replace what is shown.
function drawResults() {
  const { findings, isGraded, scanNote, footer, coverage } = currentScan;
  const sorted = [...findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  const score = computeScore(sorted);
  const grade = isGraded ? computeGrade(score) : "?";

  const gradeBox = document.getElementById("grade");
  gradeBox.textContent = grade;
  gradeBox.dataset.grade = grade;
  gradeBox.setAttribute("aria-label", `Security grade ${grade}`);
  document.getElementById("score").textContent = isGraded ? score : "--";
  document.getElementById("scan-note").textContent = scanNote;

  for (const severity of ["high", "medium", "low"]) {
    const count = sorted.filter((finding) => finding.severity === severity).length;
    document.getElementById(`count-${severity}`).textContent = count;
  }
  document.getElementById("summary").hidden = false;

  document.getElementById("clean").hidden = !(isGraded && sorted.length === 0);

  const template = document.getElementById("finding-template");
  document.getElementById("findings").replaceChildren(...sorted.map((finding) => renderFinding(finding, template)));

  const verdict = verdictFor(sorted, isGraded);
  const verdictBox = document.getElementById("verdict");
  verdictBox.dataset.level = verdict.level;
  document.getElementById("verdict-title").textContent = verdict.title;
  document.getElementById("verdict-text").textContent = verdict.text;
  verdictBox.hidden = explainMode !== "plain";
  document.getElementById("mode").hidden = false;
  renderLearnPanel(document.getElementById("panel-learn"), sorted);

  renderWhy({ findings, isGraded, coverage });
  document.getElementById("tabs").hidden = false;

  const foot = document.getElementById("foot");
  foot.textContent = footer;
  foot.hidden = false;
}

// ---------- The scan ----------

async function scanTab(tab) {
  clearResults();

  // Chrome hides tab.url on pages the extension has no access to, such as
  // chrome:// pages, so a missing URL means the same thing as a blocked scheme.
  let pageUrl;
  try {
    pageUrl = new URL(tab.url);
  } catch {
    showNotice(RESTRICTED_PAGE_MESSAGE);
    return;
  }

  const isWeb = pageUrl.protocol === "http:" || pageUrl.protocol === "https:";
  const isFile = pageUrl.protocol === "file:";
  document.getElementById("host").textContent = isFile ? "local file" : pageUrl.host;

  if (!isWeb && !isFile) {
    showNotice(RESTRICTED_PAGE_MESSAGE);
    return;
  }

  if (isFile && !(await chrome.extension.isAllowedFileSchemeAccess())) {
    showNotice('To scan local files, open chrome://extensions, click Details on Risk Pro, and turn on "Allow access to file URLs". Then reload this page.');
    return;
  }

  showNotice("Scanning…");

  const [capture, cookies, dom] = await Promise.all([
    isWeb ? getHeaderCapture(tab.id) : null,
    isWeb ? chrome.cookies.getAll({ url: tab.url }) : [],
    getDomReport(tab.id),
  ]);

  document.getElementById("notice").hidden = true;

  // Headers are stored when a page is loaded, and some navigations (the back
  // button, for example) restore a page without a new request. A capture from a
  // different origin belongs to some other page, so we must not grade with it.
  const hasHeaders = Boolean(capture) && new URL(capture.url).origin === pageUrl.origin;
  const headers = toHeaderMap(hasHeaders ? capture.headers : []);

  const findings = [
    ...checkTransport(pageUrl),
    ...(hasHeaders ? checkSecurityHeaders(headers, pageUrl, dom, capture) : []),
    ...(hasHeaders ? checkInfoDisclosure(headers) : []),
    ...checkCookies(cookies),
    ...(dom?.findings || []),
  ];

  // A grade from incomplete data would look better than it should, so a partial
  // scan shows its findings but no letter.
  const isComplete = dom !== null && (isFile || hasHeaders);

  let scanNote = "Full passive scan";
  if (isFile) scanNote = "Page content checks only";
  if (!isComplete) scanNote = "Partial scan, no grade";

  if (isWeb && !hasHeaders) {
    showNotice("This page loaded before Risk Pro could capture its response headers. Reload to run the full scan.", { withReload: true });
  } else if (isFile) {
    showNotice("A local file has no HTTP headers or cookies, so only page content was checked.");
  } else if (dom === null) {
    showNotice("Chrome blocked access to this page's content, so only headers and cookies were checked.");
  } else if (isHstsUnknown(headers, pageUrl, capture)) {
    scanNote = "Full scan, HSTS not checked";
    showNotice("This page came from the browser cache, which does not keep the Strict-Transport-Security header. Reload to check it.", { withReload: true });
  }

  const countOf = (count, noun) => `${count} ${noun}${count === 1 ? "" : "s"}`;
  const stats = dom?.stats;
  const parts = [
    isWeb && hasHeaders ? countOf(headers.size, "header") : null,
    isWeb ? countOf(cookies.length, "cookie") : null,
    stats ? countOf(stats.scripts, "script") : null,
    stats ? countOf(stats.forms, "form") : null,
  ].filter(Boolean);

  renderResults({
    findings,
    isGraded: isComplete,
    scanNote,
    pageLabel: isFile ? "a local file" : pageUrl.host,
    coverage: buildCoverage(findings, {
      isWeb,
      isHttps: pageUrl.protocol === "https:",
      hasHeaders,
      hasDom: dom !== null,
      hstsUnknown: hasHeaders && isHstsUnknown(headers, pageUrl, capture),
    }),
    footer: `Checked ${parts.join(" · ")}. Read-only; nothing left this browser.`,
  });
}

function reloadAndRescan(tabId) {
  showNotice("Reloading…");
  const onUpdated = (updatedTabId, changeInfo, tab) => {
    if (updatedTabId === tabId && changeInfo.status === "complete") {
      chrome.tabs.onUpdated.removeListener(onUpdated);
      scanTab(tab);
    }
  };
  chrome.tabs.onUpdated.addListener(onUpdated);
  // bypassCache makes this a real network request, so fresh headers get captured.
  chrome.tabs.reload(tabId, { bypassCache: true });
}

async function main() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  document.getElementById("notice-button").addEventListener("click", () => reloadAndRescan(tab.id));
  document.getElementById("tab-findings").addEventListener("click", () => showTab("findings"));
  document.getElementById("tab-why").addEventListener("click", () => showTab("why"));
  document.getElementById("tab-learn").addEventListener("click", () => showTab("learn"));
  document.getElementById("mode-plain").addEventListener("click", () => setExplainMode("plain"));
  document.getElementById("mode-technical").addEventListener("click", () => setExplainMode("technical"));
  applyExplainMode();
  document.getElementById("copy-plan").addEventListener("click", (event) => {
    copyWithFeedback(event.target, fixPlanText(currentScan.findings, currentScan.pageLabel));
  });
  await scanTab(tab);
}

main().catch(() => {
  showNotice("The scan could not finish. Reload the page and try again.");
});
