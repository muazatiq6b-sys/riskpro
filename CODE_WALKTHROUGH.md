# Risk Pro code walkthrough

This goes file by file, then function by function. Each entry says what the code does, what data it touches, and which Chrome API it uses and why. Lines marked **Beginner trap** are where people new to extensions usually get stuck, and they make good answers when a judge asks a hard question.

## How the data flows

```
 Page loads
    │
    ├─► background.js  captures the response headers ──► chrome.storage.session
    └─► content.js     waits inside the page

 You click the icon: popup.js starts
    │
    ├─ 1. asks background.js for the headers          (runtime.sendMessage)
    ├─ 2. reads cookies directly                      (cookies.getAll)
    ├─ 3. reads window.jQuery etc. in the page        (scripting.executeScript, world: MAIN)
    ├─ 4. asks content.js to scan, passing step 3     (tabs.sendMessage)
    │
    └─ merges all findings ─► score ─► grade ─► draws the popup
```

Only `popup.js` scores and draws. It is destroyed when the popup closes, so every click is a new scan.

---

## manifest.json

The file Chrome reads first. It declares the three parts and what they may do.

| Entry | Why it is needed |
|---|---|
| `manifest_version: 3` | The current extension platform. |
| `webRequest` | Lets `background.js` observe response headers. |
| `cookies` | Lets `popup.js` read cookie flags, including `HttpOnly` cookies that page scripts cannot see. |
| `storage` | Gives access to `chrome.storage.session`. |
| `scripting` | Lets `popup.js` read page variables and inject `content.js` into tabs that do not have it yet. |
| `host_permissions: <all_urls>` | The other APIs only work on sites listed here. It also makes `tab.url` readable. |
| `background.service_worker` | Registers `background.js`. |
| `content_scripts` | Runs `content.js` in every page once the page is idle. |
| `action.default_popup` | Opens `popup.html` when the icon is clicked. |

**Beginner trap:** `webRequest` on its own does nothing. The permission allows the API, and `host_permissions` says which sites it applies to. You need both.

---

## background.js (service worker)

Exists because the headers of a page's own document are not available to JavaScript in that page. `webRequest` is available here, so this file watches headers as they arrive and saves them per tab.

**Beginner trap, the most important one in the project:** this worker is not a long-running process. Chrome stops it after about 30 seconds idle, and every variable is lost. A plain `const headersByTab = {}` would work in a quick test and then fail during a demo, with the headers gone after you talk for a minute. That is why captures go into `chrome.storage.session`, which survives the worker stopping. I tested this by stopping the worker: the next scan woke it and still found the headers.

### `storageKey(tabId)` and `cacheKey(tabId)`
Build the storage key names, such as `headers:42`. Data: a tab ID. API: none.

### `captureHeaders(details)`
Saves one response's headers for its tab.
- **Data:** reads `details.tabId`, `url`, `statusCode`, and `responseHeaders`. Writes to session storage.
- **API:** `chrome.storage.session.set`, called from the `webRequest.onHeadersReceived` event.
- It skips `tabId < 0`, which means the request does not belong to a tab.
- It drops `Set-Cookie`, because that header holds cookie values we have no reason to keep. Cookie flags come from `chrome.cookies`.
- If a page redirects, this runs once per hop and the final response overwrites the earlier ones, which is what we want.

### `webRequest.onHeadersReceived.addListener(...)`
Connects `captureHeaders` to the browser.
- The filter `{ urls: ["<all_urls>"], types: ["main_frame"] }` means top-level page loads only, not every image and script.
- `["responseHeaders"]` asks Chrome to include the headers. Without it, `details.responseHeaders` is undefined.

**Beginner trap:** listeners must be registered at the top level of the file, not inside a callback or after an `await`. When Chrome wakes the worker for an event, it only delivers it to listeners that exist by the end of the first run of the file.

### `webRequest.onResponseStarted` listener
Records `details.fromCache` for the tab.

It exists because of a bug found in testing: Chrome's HTTP cache does not store `Strict-Transport-Security`. A page reloaded from cache looked like it had never sent HSTS (9 headers fresh, 8 from cache), which produced a false finding. `onHeadersReceived` does not say whether a response came from cache, and this event does.

### `tabs.onRemoved` listener
Deletes a tab's saved data when the tab closes. API: `chrome.storage.session.remove`.

### `runtime.onMessage` listener
Answers `GET_HEADERS` from the popup.
- **Data:** reads the tab's capture and cache flag, then replies with both merged, or `null`.
- **API:** `chrome.runtime.onMessage`, `chrome.storage.session.get`.

**Beginner trap:** the `return true` at the end. Reading storage is asynchronous, so the reply happens after the function has returned. By default Chrome closes the message channel when the function returns, and the popup receives `undefined` with no error. `return true` tells Chrome to keep the channel open.

---

## content.js (content script)

Runs inside the page in an **isolated world**: it shares the DOM with the page, but has its own separate JavaScript variables. It can see every `<script>` tag and `<form>`, but `window.jQuery` is `undefined` here even when the page has loaded jQuery.

The file is wrapped in `(() => { ... })()` so that injecting it a second time does not fail by redeclaring its `const`s.

### `clip(text)`
Shortens long strings to 140 characters so a huge URL cannot wreck the layout.

### `resolveUrl(raw)`
Turns a raw attribute into a full `URL` object the way the browser would, using `document.baseURI`. Returns `null` if invalid. Used by every check that looks at URLs.

### `isOlderThan(version, target)` and `majorVersion(version)`
Compare version numbers part by part as numbers.

**Beginner trap:** comparing as strings gives wrong answers, because `"3.10.0" < "3.5.0"` is `true` for strings. These split on `.` and compare numbers.

### `LIBRARY_RULES`
A table with one entry per library: its URL patterns, an `isAffected` test, severity, CVE note, and fix.

| Library | Flagged when | Note |
|---|---|---|
| jQuery | below 3.5.0 | CVE-2020-11022, CVE-2020-11023 |
| AngularJS | any 1.x | Official support ended in January 2022; CVE-2023-26116 as an example |
| Lodash | below 4.17.21 | CVE-2021-23337 |
| Bootstrap | below 4.3.1, except 3.4.1+ on the 3.x line | CVE-2019-8331, which was also fixed in 3.4.1 |

**Beginner trap:** each pattern requires a `/` right before the library name. Without that, `/react-bootstrap@1.0.0/` would be reported as Bootstrap. A test page with 10 lookalike script URLs produced no false findings.

### `checkLibraries(scriptUrls, pageLibraries)`
Merges two sources into findings: versions read from page variables (passed in from the popup) and versions matched in script URLs.
- **Data:** script URLs and the `pageLibraries` array.
- **API:** none, plain logic.
- It collects versions per library in a `Map` so the same version found both ways is listed once. If a page has two different old versions, they appear in one finding, and the finding is only charged once.

### `checkSubresourceIntegrity(scripts)`
Finds scripts from another origin with no `integrity` attribute.
- **Data:** `<script>` elements, `location.origin`.
- A subdomain counts as another origin, because that is how browsers define it.

### `describeForm(form)`
Builds the readable text for a finding's list, such as `form submitting to http://...`.

### `checkPasswordForms()`
Reports password fields that are not protected in transit.
- **Data:** `input[type="password"]`, each field's form, the form's `action` attribute, `location.protocol`.
- On an HTTP page it reports one finding covering everything, including fields outside any form.
- On an HTTPS page it only reports forms whose action is `http:`.

**Beginner trap:** the code uses `form.getAttribute("action")`, not `form.action`. If a form contains `<input name="action">`, which is common, `form.action` returns that input element instead of the URL. The test page includes this exact trap.

### `MIXED_CONTENT_SOURCES` and `checkMixedContent()`
On HTTPS pages only, look through the listed elements for `http:` URLs.
- **Active** (scripts, stylesheets, frames, objects, embeds) is high severity, because tampering can take over the page.
- **Passive** (images, audio, video) is medium severity.

### `scanPage(pageLibraries)`
Runs all of the above and returns `{ findings, hasMetaCsp, stats }`.

`hasMetaCsp` exists because a CSP can also be set by a `<meta>` tag in the HTML. The popup needs to know, so it does not call CSP missing just because the header is absent.

### `runtime.onMessage` listener
Replies to `SCAN_DOM`. Because `scanPage` is synchronous, it can call `sendResponse` immediately and does not need `return true`.

---

## popup.html and popup.css

`popup.html` holds the static structure and a `<template>` that is cloned for each finding. Sections start `hidden` and `popup.js` reveals the right ones.

**Beginner trap:** extension pages cannot use inline scripts or `onclick="..."` attributes. Chrome's default security policy blocks them. That is why the HTML links `popup.js` as a file and the button uses `addEventListener`.

`popup.css` sets the 380px width and all the colors. `[hidden] { display: none !important; }` matters because a CSS `display: flex` rule would otherwise override the `hidden` attribute and the section would stay visible.

---

## popup.js

### Collecting data

#### `readPageGlobals()`
Reads library versions from page variables. It runs in the page, not in the popup.
- **Data:** `window.jQuery.fn.jquery`, `window.angular.version.full`, `window._.VERSION`, `window.bootstrap.Tooltip.VERSION` or `jQuery.fn.tooltip.Constructor.VERSION`.
- Checks for `_.flowRight` before trusting `_.VERSION`, because Underscore also has `_.VERSION` and would otherwise be mistaken for an old Lodash.

**Beginner trap:** Chrome converts this function to text and re-creates it inside the page, so it cannot use anything defined elsewhere in `popup.js`. Using a constant from the top of the file would throw an error, even though it looks fine in your editor.

#### `getPageLibraries(tabId)`
Runs `readPageGlobals` in the page. API: `chrome.scripting.executeScript`.

**Beginner trap:** `world: "MAIN"` is the whole point of this call. The default is the isolated world, where `window.jQuery` is undefined and the check silently finds nothing. Running through this API also means the page's own CSP cannot block it, which is not true of adding a `<script>` tag to the page.

#### `getDomReport(tabId)`
Sends `SCAN_DOM` to `content.js` and returns the report.
- **API:** `chrome.tabs.sendMessage`, then `chrome.scripting.executeScript` with `files` as a fallback.
- **Why the fallback:** tabs opened before the extension was installed have no content script. `sendMessage` fails with "Receiving end does not exist", so the code injects `content.js` and asks again. Returns `null` if Chrome blocks the page entirely.

#### `getHeaderCapture(tabId)`
Asks `background.js` for the headers. API: `chrome.runtime.sendMessage`. Sending the message wakes the worker if Chrome has stopped it.

### Header, cookie, and transport checks

#### `toHeaderMap(headers)`
Converts the header list into a `Map` with lowercase keys, because HTTP header names are not case-sensitive.

#### `isHstsUnknown(headers, pageUrl, capture)`
True on an HTTPS page served from cache with no HSTS visible. In that case the header's absence proves nothing, so the check is skipped and the popup offers a reload. Over HTTP the header does nothing anyway, so the finding stands.

#### `checkSecurityHeaders(headers, pageUrl, dom, capture)`
Reports each missing header.

| Header | Severity | Also accepted |
|---|---|---|
| Content-Security-Policy | high | A `<meta>` CSP. Report-only does not count, since it blocks nothing. |
| Strict-Transport-Security | medium on HTTPS, low on HTTP | Browsers ignore it over HTTP. |
| X-Frame-Options | medium | A CSP `frame-ancestors` directive. |
| X-Content-Type-Options | medium | |
| Referrer-Policy | low | |
| Permissions-Policy | low | The older Feature-Policy header does not count, but is mentioned in the detail. |

#### `checkInfoDisclosure(headers)`
Combines `Server`, `X-Powered-By`, and `X-AspNet-Version` into one finding. Medium if a version number appears, low otherwise, because the version is what lets an attacker look up known CVEs.

#### `checkCookies(cookies)`
Creates one finding per missing flag, listing cookie names and never values.
- **Secure:** medium. **HttpOnly:** medium. **SameSite:** low.

**Beginner trap:** Chrome's values are not the words from the header. No attribute is `"unspecified"`, and `SameSite=None` is `"no_restriction"`.

#### `checkTransport(pageUrl)`
High severity if the page is `http:`. On localhost the detail text says plainly that traffic stays on the machine.

### Score and grade

#### `computeScore(findings)`
Starts at 100, subtracts 20, 10, or 5 per high, medium, or low finding, and stops at 0.

#### `computeGrade(score)`
A is 90+, B is 80+, C is 70+, D is 60+, F is below 60.

### Rendering

#### `renderFinding(finding, template)`
Clones the template and fills in one finding.

**Beginner trap, and a good security point to mention:** everything goes in through `textContent`, never `innerHTML`. Header values, cookie names, and URLs come from the site being scanned. A site could name a cookie `<img src=x onerror=...>`, and `innerHTML` would treat that as markup inside the extension. I tested this with hostile values: they display as plain text and nothing runs.

#### `showNotice(text, options)` and `clearResults()`
Show the message box, with an optional reload button, and reset the page before each scan.

#### `renderResults({ findings, isGraded, scanNote, footer })`
Sorts findings high to low, computes the score and grade, fills in the summary and counts, and shows the clean state only when there are no findings and the scan was gradable.

### The scan

#### `scanTab(tab)`
The main function. In order:
1. Parses `tab.url`. Chrome hides the URL on pages like `chrome://version`, which leads to the "cannot read its own pages" message.
2. For `file:` pages, checks `chrome.extension.isAllowedFileSchemeAccess()` and explains the setting if it is off.
3. Collects headers, cookies, and the DOM report in parallel with `Promise.all`. API: `chrome.cookies.getAll`.
4. Decides whether the header capture is usable. A capture from a different origin belongs to another page, so it is ignored.
5. Merges all findings and decides whether the result can be graded.
6. Calls `renderResults`.

**Design decision to be ready to explain:** when headers are missing, the popup shows `?` and not a letter. Scoring without the header checks would make the site look better than it is.

#### `reloadAndRescan(tabId)`
Runs when the reload button is clicked. Waits for `chrome.tabs.onUpdated` to report `complete`, then scans again. Uses `chrome.tabs.reload(tabId, { bypassCache: true })` so a real network request happens and fresh headers are captured.

#### `main()`
Finds the active tab with `chrome.tabs.query({ active: true, currentWindow: true })`, connects the reload button, and runs `scanTab`. The `.catch` at the bottom shows a message if anything unexpected fails.

### Plain English mode and learning (`plainenglish.js`)

This file changes only the wording. The checks and the score stay exactly the same.

- `GLOSSARY`, `PLAIN`, and `LESSONS` hold the word explanations, the plain wording for each finding id, and the lessons with their quick checks.
- `verdictFor(findings, isComplete)` picks the top message. **It deliberately never says "safe"**, because a scan can't know whether a site is honest.
- `renderRichText(target, text)` turns `[[cookie|cookies]]` into a button that shows an explanation. It adds text as text nodes, never as HTML.
- `lessonKeysFor(findings)` chooses lessons from what was found, without repeats, and always ends with the padlock lesson.
- `renderLearnPanel(container, findings)` draws the Learn tab. The "already typed your password" steps open by themselves when the verdict is Stop.
- In `popup.js`, `setExplainMode(mode)` switches styles and remembers the choice in `localStorage`. `drawResults()` redraws from the saved scan, so switching does not scan again.

### Mitigation and score explanation

#### `mitigations.js`
A lookup table with one entry per finding `id`: who can fix it, the steps, example server configuration, and advice for an ordinary visitor. It only contains advice. **Risk Pro never changes a website or server.** An extension cannot fix someone else's server, and trying to would break the project's read-only promise.

#### `CHECKS`
Lists every check and how to describe a pass. This is how the popup can say why a page did not lose more points.

#### `buildCoverage(findings, context)`
Sorts checks into passed and not counted. A check counts as passed only if it actually ran and produced no finding, so missing data can never look like a pass.

#### `totalPenalty(findings)` and `planNextGrade(findings)`
`totalPenalty` adds up the points lost. `planNextGrade` works out the fewest fixes, largest penalty first, needed to reach the next grade.

**Beginner trap:** the visible score stops at 0, but the raw score can go lower. A page 110 points below zero can gain 20 points and still show 0, which is why the preview shows the raw score in that case.

#### `renderMitigation(node, finding)`
Fills in the "How to mitigate this" section and connects each Copy button.

#### `renderProjection()`
Recalculates the grade as if the ticked findings were fixed. It is only a preview: it changes nothing and is lost when the popup closes.

#### `renderWhy(...)` and `showTab(which)`
Draw the "Why this score?" tab: the arithmetic, points lost by OWASP category and by finding, checks passed, and anything not counted.

#### `fixPlanText(findings, pageLabel)` and `copyWithFeedback(button, text)`
Build the plain-text fix plan and copy text to the clipboard. API: `navigator.clipboard.writeText`.

---

## site/ (presentation website, not part of the extension)

`site/index.html` shows the same scoring on fictional sites, and works offline by double-clicking. `site/mitigations.js` and `site/plainenglish.js` are copies of the extension's files, so copy them again if you change the wording. The Northwind results match the test site. Harbour College and Bright Future Scholarships are handwritten samples, and the page labels them that way.

---

## test/ (not part of the extension)

| File | Purpose |
|---|---|
| `serve.ps1` | A small HTTP server using only built-in PowerShell. It listens on loopback only and serves a fixed list of routes. |
| `vulnerable.html` | Bad on purpose. Served with weak headers and cookies. |
| `clean.html` | The same site, fixed, for showing the grade rise. |
| `lib/*.js` | Fake libraries that only report a version number. No vulnerable code is shipped. |

`lib/utils.js` has no version in its name, so only the page-variable check can find it. That makes it good proof that the `MAIN` world call works. Its Lodash finding says "loaded in the page", while Bootstrap's shows the URL it was matched from.
