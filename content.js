// content.js: runs inside the page, in Chrome's "isolated world".
//
// It shares the page's DOM but not the page's JavaScript variables, so it can
// see <script> tags and <form> elements but window.jQuery is undefined here.
// The popup reads those variables separately and passes them in with the scan
// request (see readPageGlobals in popup.js).
//
// Everything here only reads the page. Nothing is changed or sent anywhere.

// The whole file is wrapped in a function so that injecting it a second time
// (popup.js does this for tabs opened before the extension was installed) does
// not fail by redeclaring the consts below.
(() => {
  const SUPPLY_CHAIN = "A03:2025 Software Supply Chain Failures";
  const CRYPTO = "A04:2025 Cryptographic Failures";
  const MAX_ITEM_LENGTH = 140;

  function clip(text) {
    return text.length > MAX_ITEM_LENGTH ? `${text.slice(0, MAX_ITEM_LENGTH - 1)}…` : text;
  }

  // Resolves a raw attribute value the way the browser would. Returns null for
  // values that are not valid URLs.
  function resolveUrl(raw) {
    try {
      return new URL(raw, document.baseURI);
    } catch {
      return null;
    }
  }

  // ---------- Version helpers ----------

  function isOlderThan(version, target) {
    const a = version.split(".").map((part) => parseInt(part, 10) || 0);
    const b = target.split(".").map((part) => parseInt(part, 10) || 0);
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
      const diff = (a[i] || 0) - (b[i] || 0);
      if (diff !== 0) return diff < 0;
    }
    return false;
  }

  function majorVersion(version) {
    return parseInt(version, 10);
  }

  // ---------- Outdated JS libraries (A03) ----------

  // Each urlPattern requires a "/" right before the library name, so
  // /react-bootstrap@1.0.0/ and /jquery-ui/1.12.1/ do not match. The optional
  // ".js" handles cdnjs paths like /lodash.js/4.17.15/ and /angular.js/1.8.2/.
  const LIBRARY_RULES = [
    {
      id: "jquery",
      label: "jQuery",
      urlPatterns: [
        /\/jquery[-.@/]v?(\d+\.\d+(?:\.\d+)?)/i,
        /\/jquery(?:\.min)?\.js\?(?:ver|v)=(\d+\.\d+(?:\.\d+)?)/i,
      ],
      isAffected: (version) => isOlderThan(version, "3.5.0"),
      severity: "high",
      note: "CVE-2020-11022 and CVE-2020-11023: cross-site scripting through jQuery's HTML manipulation methods, fixed in 3.5.0.",
      fix: "Upgrade jQuery to 3.5.0 or later.",
    },
    {
      id: "angularjs",
      label: "AngularJS",
      urlPatterns: [/\/angular(?:\.js|js)?[-.@/]v?(\d+\.\d+(?:\.\d+)?)/i],
      // Only the 1.x line is AngularJS. A URL with a 2+ version is modern Angular.
      isAffected: (version) => majorVersion(version) === 1,
      severity: "high",
      note: "Official AngularJS support ended in January 2022, so the 1.x line gets no further security fixes from its maintainers. Example: CVE-2023-26116, a ReDoS in angular.copy().",
      fix: "Migrate off AngularJS 1.x to a supported framework.",
    },
    {
      id: "lodash",
      label: "Lodash",
      urlPatterns: [/\/lodash(?:\.js)?[-.@/]v?(\d+\.\d+(?:\.\d+)?)/i],
      isAffected: (version) => isOlderThan(version, "4.17.21"),
      severity: "high",
      note: "CVE-2021-23337: command injection through _.template, fixed in 4.17.21.",
      fix: "Upgrade Lodash to 4.17.21 or later.",
    },
    {
      id: "bootstrap",
      label: "Bootstrap",
      urlPatterns: [/\/bootstrap[-.@/]v?(\d+\.\d+(?:\.\d+)?)/i],
      // CVE-2019-8331 was also fixed on the 3.x line in 3.4.1, so 3.4.1 and
      // later 3.x releases are not affected even though they are below 4.3.1.
      isAffected: (version) =>
        isOlderThan(version, "4.3.1") &&
        !(majorVersion(version) === 3 && !isOlderThan(version, "3.4.1")),
      severity: "medium",
      note: "CVE-2019-8331: cross-site scripting through the tooltip and popover data-template attribute, fixed in 4.3.1 and 3.4.1.",
      fix: "Upgrade Bootstrap to 4.3.1 or later.",
    },
  ];

  function checkLibraries(scriptUrls, pageLibraries) {
    // Map of library id -> Map of version -> where we saw it.
    const seen = new Map(LIBRARY_RULES.map((rule) => [rule.id, new Map()]));

    for (const { id, version } of pageLibraries) {
      seen.get(id)?.set(version, "loaded in the page");
    }

    for (const url of scriptUrls) {
      for (const rule of LIBRARY_RULES) {
        for (const pattern of rule.urlPatterns) {
          const match = url.match(pattern);
          if (match && !seen.get(rule.id).has(match[1])) {
            seen.get(rule.id).set(match[1], clip(url));
          }
        }
      }
    }

    const findings = [];
    for (const rule of LIBRARY_RULES) {
      const affected = [...seen.get(rule.id)].filter(([version]) => rule.isAffected(version));
      if (affected.length === 0) continue;

      const versions = affected.map(([version]) => version).join(", ");
      findings.push({
        id: `lib-${rule.id}`,
        severity: rule.severity,
        category: SUPPLY_CHAIN,
        title: `Outdated ${rule.label} ${versions}`,
        detail: rule.note,
        fix: rule.fix,
        items: affected.map(([version, where]) => `${rule.label} ${version}: ${where}`),
      });
    }
    return findings;
  }

  // ---------- External scripts without SRI (A03) ----------

  function checkSubresourceIntegrity(scripts) {
    const missing = scripts
      .filter((script) => script.src)
      .map((script) => ({ url: resolveUrl(script.src), integrity: script.getAttribute("integrity") }))
      .filter(
        ({ url, integrity }) =>
          url && /^https?:$/.test(url.protocol) && url.origin !== location.origin && !integrity
      )
      .map(({ url }) => clip(url.href));

    if (missing.length === 0) return [];

    return [
      {
        id: "sri",
        severity: "medium",
        category: SUPPLY_CHAIN,
        title: `${missing.length} external script${missing.length === 1 ? "" : "s"} without Subresource Integrity`,
        detail:
          "These scripts load from another origin with no integrity hash. If that host is compromised, the browser runs the altered code with full access to this page.",
        fix: 'Add integrity="sha384-..." and crossorigin="anonymous" to each external script tag.',
        items: missing,
      },
    ];
  }

  // ---------- Password fields and forms (A04) ----------

  function describeForm(form) {
    const raw = form.getAttribute("action");
    return raw ? `form submitting to ${clip(resolveUrl(raw)?.href || raw)}` : "form submitting to this page";
  }

  function checkPasswordForms() {
    const fields = [...document.querySelectorAll('input[type="password"]')];
    if (fields.length === 0) return [];

    const pageIsHttp = location.protocol === "http:";
    const forms = new Set(fields.map((field) => field.form).filter(Boolean));

    // Use getAttribute, not form.action. If the form contains an input named
    // "action", form.action returns that input element instead of the URL.
    const httpForms = [...forms].filter((form) => {
      const raw = form.getAttribute("action");
      return raw && resolveUrl(raw)?.protocol === "http:";
    });

    if (pageIsHttp) {
      const looseFields = fields.filter((field) => !field.form).length;
      return [
        {
          id: "password-http",
          severity: "high",
          category: CRYPTO,
          title: "Password field on a page without HTTPS",
          detail:
            "Passwords typed here can be read or changed by anyone on the network path, because the page itself is not protected by TLS.",
          fix: "Serve the login page and its form target over HTTPS only.",
          items: [
            ...[...forms].map(describeForm),
            ...(looseFields ? [`${looseFields} password field(s) outside a form, sent by script`] : []),
          ],
        },
      ];
    }

    if (httpForms.length > 0) {
      return [
        {
          id: "password-http",
          severity: "high",
          category: CRYPTO,
          title: "Password form submits over HTTP",
          detail: "The form sends the password in plain text, whatever protocol the page itself uses.",
          fix: "Change the form action to an HTTPS URL.",
          items: httpForms.map(describeForm),
        },
      ];
    }

    return [];
  }

  // ---------- Mixed content (A04) ----------

  // "Active" content can run code or restyle the page. "Passive" can only be
  // displayed. Browsers treat active mixed content far more strictly.
  const MIXED_CONTENT_SOURCES = [
    { selector: "script[src]", attribute: "src", active: true },
    { selector: 'link[rel~="stylesheet"][href]', attribute: "href", active: true },
    { selector: "iframe[src]", attribute: "src", active: true },
    { selector: "object[data]", attribute: "data", active: true },
    { selector: "embed[src]", attribute: "src", active: true },
    { selector: "img[src]", attribute: "src", active: false },
    { selector: "audio[src]", attribute: "src", active: false },
    { selector: "video[src]", attribute: "src", active: false },
    { selector: "source[src]", attribute: "src", active: false },
  ];

  function checkMixedContent() {
    if (location.protocol !== "https:") return [];

    const active = [];
    const passive = [];
    for (const { selector, attribute, active: isActive } of MIXED_CONTENT_SOURCES) {
      for (const element of document.querySelectorAll(selector)) {
        const url = resolveUrl(element.getAttribute(attribute));
        if (url?.protocol === "http:") (isActive ? active : passive).push(clip(url.href));
      }
    }

    const findings = [];
    if (active.length > 0) {
      findings.push({
        id: "mixed-active",
        severity: "high",
        category: CRYPTO,
        title: `Active mixed content (${active.length})`,
        detail: "This HTTPS page references scripts, styles, or frames over plain HTTP. Tampering with those can take over the page.",
        fix: "Load every script, stylesheet, and frame over HTTPS.",
        items: active,
      });
    }
    if (passive.length > 0) {
      findings.push({
        id: "mixed-passive",
        severity: "medium",
        category: CRYPTO,
        title: `Passive mixed content (${passive.length})`,
        detail: "This HTTPS page references images or media over plain HTTP, which can be viewed or swapped on the network.",
        fix: "Load images and media over HTTPS.",
        items: passive,
      });
    }
    return findings;
  }

  // ---------- Entry point ----------

  function scanPage(pageLibraries) {
    const scripts = [...document.scripts];
    const scriptUrls = scripts.map((script) => script.src).filter(Boolean);

    return {
      findings: [
        ...checkPasswordForms(),
        ...checkMixedContent(),
        ...checkLibraries(scriptUrls, pageLibraries),
        ...checkSubresourceIntegrity(scripts),
      ],
      // A CSP can also be delivered in the HTML. popup.js needs this so it does
      // not report CSP as missing just because the header is absent.
      hasMetaCsp: Boolean(document.querySelector('meta[http-equiv="Content-Security-Policy" i]')),
      stats: { scripts: scripts.length, forms: document.forms.length },
    };
  }

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.type !== "SCAN_DOM") return false;
    sendResponse(scanPage(message.pageLibraries || []));
    return false;
  });
})();
