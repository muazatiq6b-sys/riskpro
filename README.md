# Risk Pro

A Chrome extension that gives the page you are viewing a security grade in one click, using passive checks mapped to the OWASP Top 10 2025.

It only reads what your browser has already received. It sends no attack payloads, makes no network calls of its own, and has no backend, dependencies, or build step.

## Install

1. Go to `chrome://extensions`.
2. Turn on **Developer mode**.
3. Click **Load unpacked** and select this folder.
4. Pin Risk Pro from the puzzle-piece menu, then open a page and click the icon.

Pages that were already open will show a **Reload page and scan** button, because their headers were sent before the extension was installed.

To scan local `file://` pages, click **Details** on the extension card and turn on **Allow access to file URLs**.

## Try it without any setup

A deliberately insecure test site is included. It needs only Windows PowerShell and works offline:

```powershell
powershell -ExecutionPolicy Bypass -File test\serve.ps1
```

| URL | Result |
|---|---|
| `http://localhost:8000/vulnerable/` | **F**, 0/100 |
| `http://localhost:8000/clean/` | **B**, 80/100 (the only finding left is no HTTPS) |

To use OWASP Juice Shop as a target with Docker:

```powershell
docker run --rm -p 127.0.0.1:3000:3000 bkimminich/juice-shop
```

Only scan sites you own or have permission to test.

## Plain English mode and learning

Results open in **Plain English** by default, with a clear message at the top such as "Stop: do not type your password here". Each risk says what it means for you and what you can do, and words like "cookie" can be tapped for a simple explanation. **Technical** mode shows the original detail.

The **Learn the basics** tab offers short lessons chosen from what the scan found, each with a one-question check, plus steps to follow if you already typed your password somewhere unsafe. It never tells you a site is safe, because a scan cannot know that.

## Mitigation and score explanation

Each finding has a **How to mitigate this** section that shows who can fix it, the steps, example server configuration to copy, and what an ordinary visitor can do today. Tick **Preview score with this fixed** to see how the grade would change.

The **Why this score?** tab shows the arithmetic, the points lost by OWASP category and by finding, what the page did right, what could not be checked, and the fewest fixes needed to reach the next grade. **Copy full fix plan** copies all of it as text.

Risk Pro only gives advice. It does not change websites or servers, and example configuration must be tested before use.

## Presentation website

Double-click `site/index.html` to open an interactive tour on fictional sites. It works offline.

## What it checks

| Check | OWASP category | Severity |
|---|---|---|
| Missing Content-Security-Policy | A02:2025 Security Misconfiguration | High |
| Missing Strict-Transport-Security | A02:2025 Security Misconfiguration | Medium (low on HTTP) |
| Missing X-Frame-Options | A02:2025 Security Misconfiguration | Medium |
| Missing X-Content-Type-Options | A02:2025 Security Misconfiguration | Medium |
| Missing Referrer-Policy | A02:2025 Security Misconfiguration | Low |
| Missing Permissions-Policy | A02:2025 Security Misconfiguration | Low |
| Server, X-Powered-By, or X-AspNet-Version disclosed | A02:2025 Security Misconfiguration | Medium with a version, otherwise low |
| Cookies missing Secure or HttpOnly | A02:2025 Security Misconfiguration | Medium |
| Cookies without a restrictive SameSite | A02:2025 Security Misconfiguration | Low |
| Page not served over HTTPS | A04:2025 Cryptographic Failures | High |
| Active mixed content | A04:2025 Cryptographic Failures | High |
| Passive mixed content | A04:2025 Cryptographic Failures | Medium |
| Password field on HTTP, or a form posting to HTTP | A04:2025 Cryptographic Failures | High |
| Outdated jQuery (below 3.5.0), AngularJS (any 1.x), Lodash (below 4.17.21) | A03:2025 Software Supply Chain Failures | High |
| Outdated Bootstrap (below 4.3.1, excluding patched 3.4.1+) | A03:2025 Software Supply Chain Failures | Medium |
| External scripts without Subresource Integrity | A03:2025 Software Supply Chain Failures | Medium |

## Grading

The score starts at 100 and loses 20 per high, 10 per medium, and 5 per low finding, with a floor of 0.

| Grade | Score |
|---|---|
| A | 90+ |
| B | 80+ |
| C | 70+ |
| D | 60+ |
| F | Below 60 |

The severities and weights are this project's own judgment, not an official OWASP score. If response headers could not be captured, the popup shows `?` and not a letter, because a partial scan would look better than it should.

## How it works

| File | Role |
|---|---|
| `manifest.json` | Declares the parts and permissions (Manifest V3). |
| `background.js` | Service worker. Captures real response headers with `chrome.webRequest`. |
| `content.js` | Runs in the page. Checks forms, scripts, mixed content, and library versions. |
| `popup.html`, `popup.js`, `popup.css` | Collects everything, scores it, explains the score, and draws the result. |
| `mitigations.js` | The advice shown for each finding. |
| `plainenglish.js` | Plain-language wording, the word explanations, and the lessons. |
| `site/` | Presentation website. Not part of the extension. |
| `test/` | Local test site. Not part of the extension. |

See [CODE_WALKTHROUGH.md](CODE_WALKTHROUGH.md) for a function-by-function explanation and [DEMO.md](DEMO.md) for the live demo script.

## Limits

This is a passive surface check, not a security audit. It does no active testing and cannot see server-side code, so it will not find SQL injection, broken access control, or logic flaws. A good grade does not mean a site is secure. It reads only the top-level page, so iframes and shadow DOM are not inspected, and libraries hidden inside bundled code may go undetected.
