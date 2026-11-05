// plainenglish.js: explains scan results to people with no security background.
//
// This file only changes how results are worded. It does not affect the checks
// or the score. In the text below, [[term|words]] shows "words" as a button that
// explains GLOSSARY.term when tapped.

const GLOSSARY = {
  cookie: {
    term: "Cookie",
    text: "A small note a website saves in your browser so it remembers you, like a wristband at an event. If someone steals a login cookie, they may be able to get into your account without your password.",
  },
  https: {
    term: "HTTPS",
    text: "A protected connection, like a sealed envelope. Without it, your information travels more like a postcard that others along the way could read.",
  },
  padlock: {
    term: "Padlock",
    text: "The symbol browsers use for a protected connection. It means the envelope is sealed, not that the sender is honest. Scam sites can use HTTPS too.",
  },
  library: {
    term: "Code library",
    text: "Ready-made code a website builds on, like a part in a machine. When an old part has a known weakness, the site should replace it.",
  },
  header: {
    term: "Security header",
    text: "A safety instruction a website gives your browser, such as telling it not to let other sites display this page inside theirs.",
  },
  script: {
    term: "Script",
    text: "A small program a website runs inside your browser. Most are harmless, but a harmful one can read what you do on the page.",
  },
};

// One entry per finding id. "means" says why it matters to an ordinary person.
const PLAIN = {
  https: {
    title: "This page is not protected",
    means: "This page does not use [[https|HTTPS]], so what you send could be read or changed by others on the network.",
    lesson: "connection",
  },
  "password-http": {
    title: "Your password is not protected here",
    means: "A password typed on this page could be read as it travels, because it is not properly protected by [[https|HTTPS]].",
    lesson: "password",
  },
  "mixed-active": {
    title: "Part of this page is not protected",
    means: "The address looks protected, but some of the page's code loads without [[https|HTTPS]]. Someone could tamper with it and change what the page does.",
    lesson: "connection",
  },
  "mixed-passive": {
    title: "Some pictures or media are not protected",
    means: "Images or media on this page load without [[https|HTTPS]], so someone on the network could see or swap them.",
    lesson: "connection",
  },
  "cookie-secure": {
    title: "Some saved notes could travel unprotected",
    means: "This site's [[cookie|cookies]] can be sent without a protected connection, where someone on the same network might read them.",
    lesson: "cookies",
  },
  "cookie-httponly": {
    title: "Harmful code could read some saved notes",
    means: "If this site has a certain kind of bug, harmful [[script|code]] could read its [[cookie|cookies]]. If one of them keeps you logged in, someone could misuse it.",
    lesson: "cookies",
  },
  "cookie-samesite": {
    title: "Other sites could send requests while you are logged in",
    means: "This site's [[cookie|cookies]] have less protection against a trick where another site acts on your behalf while you are logged in.",
    lesson: "cookies",
  },
  "lib-jquery": {
    title: "The site uses an old part with known weaknesses",
    means: "This site runs an old [[library|code library]] called jQuery. Its known weaknesses could help an attacker if the site uses it in an unsafe way.",
    lesson: "updates",
  },
  "lib-angularjs": {
    title: "The site uses a part that is no longer supported",
    means: "This site runs AngularJS, a [[library|code library]] that no longer gets official security fixes from its makers.",
    lesson: "updates",
  },
  "lib-lodash": {
    title: "The site uses an old part with known weaknesses",
    means: "This site runs an old [[library|code library]] called Lodash. Newer versions fix a known weakness.",
    lesson: "updates",
  },
  "lib-bootstrap": {
    title: "The site uses an old part with known weaknesses",
    means: "This site runs an old [[library|code library]] called Bootstrap. Newer versions fix a known weakness.",
    lesson: "updates",
  },
  sri: {
    title: "The site trusts outside code without checking it",
    means: "This page runs [[script|code]] from another website without checking it has not been changed. If that website is hacked, this page could be affected too.",
    lesson: "defences",
  },
  "header-content-security-policy": {
    title: "A safety rule against harmful code is missing",
    means: "This site has not set a [[header|safety instruction]] that limits which [[script|code]] can run, so a bug here could do more harm.",
    lesson: "defences",
  },
  "header-strict-transport-security": {
    title: "The site does not insist on a protected connection",
    means: "This site does not tell your browser to always use [[https|HTTPS]], so a first visit or an old link could start unprotected.",
    lesson: "connection",
  },
  "header-x-frame-options": {
    title: "This page could be hidden inside another site",
    means: "Without this [[header|safety instruction]], another site could show this page in disguise and trick you into clicking something you did not intend.",
    lesson: "defences",
  },
  "header-x-content-type-options": {
    title: "Your browser may have to guess file types",
    means: "Without this [[header|safety instruction]], a browser may guess what a file is, which attackers can sometimes use to run harmful [[script|code]].",
    lesson: "defences",
  },
  "header-referrer-policy": {
    title: "Other sites may see where you came from",
    means: "This site has not set a clear [[header|instruction]] about what address details are shared when you follow a link. Your browser's default still applies.",
    lesson: "defences",
  },
  "header-permissions-policy": {
    title: "Access to device features is not limited",
    means: "This site has not used this [[header|safety instruction]] to switch off features like camera or location. Your browser should still ask before a site uses them.",
    lesson: "defences",
  },
  "info-disclosure": {
    title: "The site reveals what software it runs",
    means: "This site tells visitors what software it uses, which can make it easier for attackers to look for known weaknesses.",
    lesson: "defences",
  },
};

const LESSONS = {
  password: {
    title: "When is it OK to type a password?",
    points: [
      "Only type it after you have checked the address is the site you meant to visit.",
      "Open important sites from a bookmark or by typing the address, not from a link in a message.",
      "Use a different password for each important account, so one leak does not unlock the others.",
    ],
    quiz: {
      question: "A message says your account is locked and gives a link. What is the safest move?",
      options: ["Click the link and log in quickly", "Open the site yourself and check there", "Reply with your password"],
      answer: 1,
      why: "Opening the site yourself means a fake link cannot take you to a lookalike page.",
    },
  },
  connection: {
    title: "What does a protected connection do?",
    points: [
      "HTTPS works like a sealed envelope, so others on the network should not be able to read what you send.",
      "Without it, avoid typing passwords, card numbers, or personal details.",
      "Be extra careful on public Wi-Fi, where you do not know who else is connected.",
    ],
    quiz: {
      question: "A page does not use HTTPS, and it asks for your card number. What should you do?",
      options: ["Enter it, since the page looks professional", "Do not enter it", "Enter it, but only on public Wi-Fi"],
      answer: 1,
      why: "Without HTTPS, your card number could be read on its way to the site, however professional the page looks.",
    },
  },
  cookies: {
    title: "What are cookies, and why do they matter?",
    points: [
      "A cookie is a small note that helps a site remember you, like a wristband at an event.",
      "A login cookie can act like a key to your account while you stay logged in.",
      "Log out when you finish, especially on shared computers.",
    ],
    quiz: {
      question: "You used a shared lab computer to check your email. What should you do before leaving?",
      options: ["Log out", "Close the screen only", "Nothing, since the password is hidden"],
      answer: 0,
      why: "Logging out ends the session, so the next person cannot simply carry on as you.",
    },
  },
  updates: {
    title: "Why do old software parts matter?",
    points: [
      "Known weaknesses in old software are public, so attackers can look them up.",
      "Only the website's owner can update the code it runs, but you can tell them about it.",
      "Do your part by keeping your own browser, phone, and apps updated.",
    ],
    quiz: {
      question: "Why do updates matter so much?",
      options: ["They mainly change how apps look", "They often fix known security weaknesses", "They only matter for large companies"],
      answer: 1,
      why: "Updates often fix weaknesses that attackers already know about.",
    },
  },
  defences: {
    title: "What are a website's hidden defences?",
    points: [
      "Good sites add extra safety rules behind the scenes, and you normally cannot see them.",
      "A missing rule is a weak spot, not proof that the site is dangerous.",
      "Take more care when a site with missing rules also asks for sensitive details.",
    ],
    quiz: {
      question: "This tool says a safety rule is missing. What does that mean?",
      options: ["The site has definitely been hacked", "The site has a weak spot worth being careful about", "Your computer has a virus"],
      answer: 1,
      why: "It is a weak spot. It does not prove an attack has happened or that your device is affected.",
    },
  },
  padlock: {
    title: "A padlock does not mean a site is honest",
    points: [
      "A padlock means the connection is protected. It says nothing about who runs the site.",
      "Scam sites can use HTTPS and can look completely professional.",
      "Check the address, and be suspicious of pressure like \"act now\" or offers that seem too good to be true.",
    ],
    quiz: {
      question: "A scholarship site has a padlock and asks for your university password. Is it safe?",
      options: ["Yes, the padlock proves it", "Not necessarily, so check it through your university's official site", "Yes, if the design looks good"],
      answer: 1,
      why: "A padlock only protects the connection. Scam sites can have one too.",
    },
  },
};

const EMERGENCY_STEPS = [
  "Open the real site yourself, by typing its address or using a bookmark, and change your password.",
  "Change it anywhere else you used the same password.",
  "Turn on multi-factor authentication, if the service offers it.",
  "Check for recent logins or activity you do not recognise.",
  "If bank or card details were involved, contact your bank straight away.",
  "Report it to the service, or to your university's IT team if it was a university account.",
];

const EVERYDAY_HABITS = [
  "Open important sites from a bookmark or by typing the address.",
  "Use different passwords, and turn on multi-factor authentication.",
  "Slow down when a message creates panic or urgency.",
  "Log out on shared computers, and keep your software updated.",
];

const STOP_IDS = new Set(["https", "password-http", "mixed-active"]);

// Decides the top-line message. It never says "safe", because no scan can know that.
function verdictFor(findings, isComplete) {
  if (findings.some((finding) => STOP_IDS.has(finding.id))) {
    return {
      level: "stop",
      title: "Stop: do not type your password here",
      text: "This page is not fully protected, so others on the network could read or change what you send.",
    };
  }
  if (!isComplete) {
    return { level: "unknown", title: "Not finished checking", text: "We could not check everything on this page, so do not rely on this result yet." };
  }
  if (findings.some((finding) => finding.severity !== "low")) {
    return {
      level: "careful",
      title: "Be careful: this site has some weak spots",
      text: "Think twice before sharing passwords or personal details. This does not prove the site is dangerous.",
    };
  }
  return {
    level: "clear",
    title: "No major warning signs, but scams can look clean",
    text: "We did not spot a serious problem in how this site is set up. We cannot tell if it is honest, so check that it is the site you meant to visit.",
  };
}

function plainTitle(finding) {
  return PLAIN[finding.id]?.title || finding.title;
}

// ---------- Shared drawing helpers, used by the popup and the website ----------

function makeEl(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

// Turns [[term|words]] into a button that shows the explanation under the text.
// Text only ever comes from this file and is added with text nodes, never as HTML.
function renderRichText(target, text) {
  target.replaceChildren();
  text.split(/(\[\[\w+\|[^\]]+\]\])/).forEach((part) => {
    const match = part.match(/^\[\[(\w+)\|([^\]]+)\]\]$/);
    if (!match || !GLOSSARY[match[1]]) {
      target.append(document.createTextNode(part));
      return;
    }
    const entry = GLOSSARY[match[1]];
    const button = makeEl("button", "term", match[2]);
    button.type = "button";
    button.setAttribute("aria-expanded", "false");
    let definition = null;
    button.addEventListener("click", () => {
      if (definition) {
        definition.remove();
        definition = null;
        button.setAttribute("aria-expanded", "false");
        return;
      }
      definition = makeEl("div", "term-def");
      definition.append(makeEl("b", "", `${entry.term}: `), document.createTextNode(entry.text));
      target.closest("p, div").after(definition);
      button.setAttribute("aria-expanded", "true");
    });
    target.append(button);
  });
}

function buildQuiz(quiz) {
  const box = makeEl("div", "quiz");
  box.append(makeEl("div", "quiz-label", "Quick check"), makeEl("p", "quiz-q", quiz.question));
  const options = makeEl("div", "quiz-options");
  const feedback = makeEl("p", "quiz-feedback");
  feedback.hidden = true;
  quiz.options.forEach((label, index) => {
    const button = makeEl("button", "quiz-option", label);
    button.type = "button";
    button.addEventListener("click", () => {
      const right = index === quiz.answer;
      options.querySelectorAll("button").forEach((other) => other.classList.remove("right", "wrong"));
      button.classList.add(right ? "right" : "wrong");
      feedback.hidden = false;
      feedback.textContent = `${right ? "Correct." : "Not quite."} ${quiz.why}`;
    });
    options.append(button);
  });
  box.append(options, feedback);
  return box;
}

function buildLesson(lesson, open) {
  const details = makeEl("details", "lesson");
  details.open = open;
  details.append(makeEl("summary", "", lesson.title));
  const list = makeEl("ul");
  lesson.points.forEach((point) => list.append(makeEl("li", "", point)));
  details.append(list, buildQuiz(lesson.quiz));
  return details;
}

// Lessons chosen from what the scan found. The padlock lesson always comes last,
// because a clean result is when people most need it.
function lessonKeysFor(findings) {
  const order = { high: 0, medium: 1, low: 2 };
  const keys = [...findings]
    .sort((a, b) => order[a.severity] - order[b.severity])
    .map((finding) => PLAIN[finding.id]?.lesson)
    .filter(Boolean);
  return [...new Set([...keys, "padlock"])];
}

function renderLearnPanel(container, findings) {
  container.replaceChildren();
  const foundCount = lessonKeysFor(findings).length - 1;
  container.append(
    makeEl("p", "learn-intro", foundCount > 0
      ? `Based on this page, here ${foundCount === 1 ? "is 1 short lesson" : `are ${foundCount} short lessons`} worth knowing, plus one for every website.`
      : "We did not find a red flag to teach from here, but this lesson applies to every website.")
  );

  lessonKeysFor(findings).forEach((key, index) => container.append(buildLesson(LESSONS[key], index === 0)));

  const emergency = makeEl("details", "lesson emergency");
  emergency.open = findings.some((finding) => STOP_IDS.has(finding.id));
  emergency.append(makeEl("summary", "", "Already typed your password? Do this now"));
  const steps = makeEl("ol");
  EMERGENCY_STEPS.forEach((step) => steps.append(makeEl("li", "", step)));
  emergency.append(steps);
  container.append(emergency);

  container.append(makeEl("h2", "learn-title", "Four habits for every website"));
  const habits = makeEl("ul", "learn-habits");
  EVERYDAY_HABITS.forEach((habit) => habits.append(makeEl("li", "", habit)));
  container.append(habits);
}
