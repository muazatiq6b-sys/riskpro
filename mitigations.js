// mitigations.js: how to reduce each risk, looked up by finding id.
//
// owner:    who can actually fix it.
// steps:    what that person should do, in order.
// snippets: example server configuration to adapt and test. Never paste into
//           production without testing, especially Content-Security-Policy.
// visitor:  what an ordinary user of the site can do today.
//
// The extension only shows this advice. It never changes a website or server.

const VISITOR_NOTHING =
  "You cannot fix this yourself, and it does not prove the site is unsafe. Keep your browser updated and tell the site's administrator.";

const MITIGATIONS = {
  "header-content-security-policy": {
    owner: "Site developer or server administrator",
    steps: [
      "List where the site's scripts, styles, and images come from.",
      "Send the policy as Content-Security-Policy-Report-Only first, and watch for what it would block.",
      "Correct any problems, then switch to the enforcing header.",
    ],
    snippets: [
      { label: "Nginx", code: `add_header Content-Security-Policy "default-src 'self'" always;` },
      { label: "Node (Express + Helmet)", code: `app.use(helmet.contentSecurityPolicy());` },
    ],
    visitor: VISITOR_NOTHING,
  },
  "header-strict-transport-security": {
    owner: "Server administrator",
    steps: [
      "Make sure the whole site and its subdomains work over HTTPS.",
      "Start with a short max-age, such as 300 seconds, and confirm nothing breaks.",
      "Raise max-age to one year.",
    ],
    snippets: [
      { label: "Nginx", code: `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;` },
      { label: "Node (Express + Helmet)", code: `app.use(helmet.hsts({ maxAge: 31536000 }));` },
    ],
    visitor: "Type https:// yourself or use a bookmark, so that you do not start on an unprotected link.",
  },
  "header-x-frame-options": {
    owner: "Site developer or server administrator",
    steps: [
      "Check whether any page legitimately needs to appear in a frame on another site.",
      "Send DENY, or SAMEORIGIN if your own site frames the page.",
    ],
    snippets: [
      { label: "Nginx", code: `add_header X-Frame-Options "DENY" always;` },
      { label: "Node (Express + Helmet)", code: `app.use(helmet.frameguard({ action: "deny" }));` },
    ],
    visitor: VISITOR_NOTHING,
  },
  "header-x-content-type-options": {
    owner: "Server administrator",
    steps: [
      "Check that the server sends the correct Content-Type for its files.",
      "Add the nosniff header to all responses.",
    ],
    snippets: [
      { label: "Nginx", code: `add_header X-Content-Type-Options "nosniff" always;` },
      { label: "Node (Express + Helmet)", code: `app.use(helmet.noSniff());` },
    ],
    visitor: VISITOR_NOTHING,
  },
  "header-referrer-policy": {
    owner: "Server administrator",
    steps: ["Add the header to all responses.", "Check that any analytics or login flows relying on the Referer still work."],
    snippets: [
      { label: "Nginx", code: `add_header Referrer-Policy "strict-origin-when-cross-origin" always;` },
      { label: "Node (Express + Helmet)", code: `app.use(helmet.referrerPolicy({ policy: "strict-origin-when-cross-origin" }));` },
    ],
    visitor: VISITOR_NOTHING,
  },
  "header-permissions-policy": {
    owner: "Server administrator",
    steps: ["List the browser features the site really uses.", "Turn off the rest, and test the pages that use camera, microphone, or location."],
    snippets: [
      { label: "Nginx", code: `add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;` },
      { label: "Node (Express)", code: `app.use((req, res, next) => {\n  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");\n  next();\n});` },
    ],
    visitor: "Only allow camera, microphone, or location when you asked the site to use them.",
  },
  "info-disclosure": {
    owner: "Server administrator",
    steps: [
      "Hide version details in the server and framework configuration.",
      "Keep the software patched. Hiding a version does not fix an out-of-date server.",
    ],
    snippets: [
      { label: "Nginx", code: `server_tokens off;\nproxy_hide_header X-Powered-By;\nproxy_hide_header X-AspNet-Version;` },
      { label: "Node (Express)", code: `app.disable("x-powered-by");` },
    ],
    visitor: VISITOR_NOTHING,
  },
  "cookie-secure": {
    owner: "Site developer",
    steps: ["Serve the site over HTTPS.", "Add the Secure flag wherever each cookie is set."],
    snippets: [
      { label: "Node (Express)", code: `res.cookie("sessionid", value, { secure: true });` },
      { label: "Nginx (1.19.3+, proxied apps)", code: `proxy_cookie_flags ~ secure;` },
    ],
    visitor: "Avoid logging in on public Wi-Fi if this site is not fully on HTTPS, and log out when you finish.",
  },
  "cookie-httponly": {
    owner: "Site developer",
    steps: [
      "Identify session and login cookies. These need the flag most.",
      "Check that your own JavaScript does not need to read them, then add HttpOnly.",
    ],
    snippets: [
      { label: "Node (Express)", code: `res.cookie("sessionid", value, { httpOnly: true });` },
      { label: "Nginx (1.19.3+, proxied apps)", code: `proxy_cookie_flags ~ httponly;` },
    ],
    visitor: "Log out when you finish, especially on a shared computer.",
  },
  "cookie-samesite": {
    owner: "Site developer",
    steps: ["Use Lax for most cookies, or Strict for sensitive ones.", "Test login flows that arrive from another site."],
    snippets: [
      { label: "Node (Express)", code: `res.cookie("sessionid", value, { sameSite: "lax" });` },
      { label: "Nginx (1.19.3+, proxied apps)", code: `proxy_cookie_flags ~ samesite=lax;` },
    ],
    visitor: "Log out of important accounts before following links from messages or unknown sites.",
  },
  https: {
    owner: "Server administrator",
    steps: [
      "Get a TLS certificate. Let's Encrypt offers them free.",
      "Turn on HTTPS and redirect all HTTP requests to it.",
      "Then add Strict-Transport-Security.",
    ],
    snippets: [{ label: "Nginx", code: `server {\n  listen 80;\n  return 301 https://$host$request_uri;\n}` }],
    visitor: "Do not enter passwords, card numbers, or personal details on this page.",
  },
  "password-http": {
    owner: "Site developer",
    steps: ["Serve the login page over HTTPS.", "Point the form's action at an https:// address.", "Reset passwords if they may have been exposed."],
    snippets: [{ label: "HTML", code: `<form action="https://example.test/login" method="post">` }],
    visitor: "Do not type your password here. If you already did, change it, and change it anywhere else you reuse it.",
  },
  "mixed-active": {
    owner: "Site developer",
    steps: ["Change the listed http:// addresses to https://.", "Add the CSP directive below as a safety net, not a replacement."],
    snippets: [{ label: "Nginx", code: `add_header Content-Security-Policy "upgrade-insecure-requests" always;` }],
    visitor: "Avoid entering sensitive details on this page until the problem is fixed.",
  },
  "mixed-passive": {
    owner: "Site developer",
    steps: ["Change the listed http:// addresses to https://.", "Host the file yourself if its source does not offer HTTPS."],
    snippets: [{ label: "HTML", code: `<img src="https://example.test/photo.png" alt="">` }],
    visitor: "Be careful about trusting images or media on this page. They could be altered.",
  },
  "lib-jquery": {
    owner: "Site developer",
    steps: ["Upgrade to jQuery 3.5.0 or later.", "Use the jQuery Migrate plugin to find code the upgrade breaks.", "Test the site before release."],
    snippets: [{ label: "npm", code: `npm install jquery@latest` }],
    visitor: VISITOR_NOTHING,
  },
  "lib-angularjs": {
    owner: "Site developer",
    steps: ["Plan a move to a supported framework, since AngularJS gets no further official fixes.", "Migrate the most exposed pages first.", "Until then, sanitize user input and enforce a strict CSP."],
    snippets: [],
    visitor: VISITOR_NOTHING,
  },
  "lib-lodash": {
    owner: "Site developer",
    steps: ["Upgrade to Lodash 4.17.21 or later.", "Avoid passing untrusted input to _.template.", "Check dependencies that bundle their own copy."],
    snippets: [{ label: "npm", code: `npm install lodash@latest\nnpm ls lodash` }],
    visitor: VISITOR_NOTHING,
  },
  "lib-bootstrap": {
    owner: "Site developer",
    steps: ["Move to 3.4.1 if you must stay on 3.x, or to 4.3.1 or later.", "A major upgrade changes markup, so test your pages.", "Do not build tooltip templates from untrusted input."],
    snippets: [{ label: "npm", code: `npm install bootstrap@latest` }],
    visitor: VISITOR_NOTHING,
  },
  sri: {
    owner: "Site developer",
    steps: ["Generate a hash for the exact file you use.", "Add integrity and crossorigin to its script tag.", "Regenerate the hash each time the file version changes."],
    snippets: [
      { label: "Generate the hash", code: `openssl dgst -sha384 -binary library.js | openssl base64 -A` },
      { label: "HTML", code: `<script src="https://cdn.example.test/library.js"\n  integrity="sha384-YOUR_HASH"\n  crossorigin="anonymous"></script>` },
    ],
    visitor: VISITOR_NOTHING,
  },
};
