# Risk Pro live demo script

## Before anything else: check with an organiser

Section 3 of the rulebook says projects must be created during the hackathon, and that an existing project with a different name or redesigned interface does not qualify. Parts of this project were built on 3 November. Tell an organiser and get a clear answer before you submit it.

Section 6 asks for fictional examples and no testing of real systems without authorisation. Use the test site and `site/index.html` in your demo, not real websites.

## The 5-minute version for the judges

Make sure you cover what Section 7 asks for, then leave 2 minutes for questions.

| Time | Do this | Cover this |
|---|---|---|
| 0:00 | Open `site/index.html` | **The problem:** students trust a padlock and cannot see how a site is set up. |
| 0:45 | Click the **Bright Future Scholarships** sample | **The lesson:** this fictional scam gets an A. A good setup does not make a site honest. |
| 1:15 | Open the real extension on `http://localhost:8000/vulnerable/` | **How it works:** it says "Stop: do not type your password here" and gives F, 0/100. |
| 1:45 | Ask "Who knows what a cookie is?", then tap the word **cookies** in a risk | **Plain English:** the wristband explanation. Switch to **Technical** to show the same risk for developers. |
| 2:30 | Open **Learn the basics** and answer one quick check | **Awareness:** lessons chosen from this page's red flags, plus what to do if you already typed a password. |
| 3:15 | Back on **Risks**, open **For the site owner: how to fix it** and tick the preview | **Mitigation:** who fixes it and how. |
| 3:45 | Open **Why this score?** | **The score explained:** 17 findings cost 210 points, and it needs 11 fixes to reach D. |
| 4:15 | Scan `http://localhost:8000/clean/` | **The result:** the same site with fixes scores B, 80/100. |
| 4:40 | Close with the limits | **Honesty:** it checks setup, not honesty, and never promises a site is safe. |

Also be ready to say how AI was used and which decisions were yours, as Section 4 requires. Change the examples and habits to ones you chose yourself.

## Read this first: Docker is not installed on this laptop

When this was built, `docker` was not on the PATH and Docker Desktop was not installed. You have two routes:

| Route | Setup time | What you need |
|---|---|---|
| **Built-in test target (recommended)** | About 1 minute | Nothing. It runs on Windows PowerShell. |
| Juice Shop in Docker | Allow 30+ minutes, and it may ask for a restart | Docker Desktop, plus internet for the install and image download |

Rehearse the built-in target first, because it works offline and its results are confirmed. Add Juice Shop only if you have time left. Do not start a Docker install near your presentation slot.

Status of each route:
- **Built-in test target:** run on this laptop's Chrome 156 through an automated script. The numbers below are real.
- **Juice Shop:** not run. The expected findings below come from reading its source code.

---

## Before the demo (do this once)

### 1. Install the extension
1. In Chrome, go to `chrome://extensions`.
2. Turn on **Developer mode** (top right).
3. Click **Load unpacked** and select `C:\Users\Hp\Documents\Hackathon`.
4. Check that the Risk Pro card shows no red **Errors** button.
5. Click the puzzle-piece icon in the toolbar and pin Risk Pro.

Install it **before** opening your target page. If a page was already open, the popup shows `?` with a **Reload page and scan** button. Click it and you get the full result.

### 2. Start the built-in test target
Open PowerShell in the project folder:

```powershell
cd C:\Users\Hp\Documents\Hackathon
powershell -ExecutionPolicy Bypass -File test\serve.ps1
```

Leave that window open. Press Ctrl+C to stop it.

### 3. Optional: start Juice Shop
Install Docker Desktop first (it uses WSL2 on Windows 11 Home), then:

```powershell
docker run --rm -p 127.0.0.1:3000:3000 bkimminich/juice-shop
```

Wait for the log to say the server is listening on port 3000, then open `http://localhost:3000`.

Keep `127.0.0.1` in that command. Juice Shop is deliberately vulnerable, and without it the app could be reachable by anyone on the hackathon Wi-Fi.

Download the image before you arrive at the venue if you can.

---

## The demo (about 3 minutes)

### Step 1: The hook (30 seconds)
Open `http://localhost:8000/vulnerable/`. It looks like an ordinary login page.

> "This looks like any login page. Can you tell if it's safe? Risk Pro answers that in one click, using only what the browser can already see."

### Step 2: The scan (45 seconds)
Click the Risk Pro icon.

**Judges see:** a large red **F**, **0 / 100**, and **6 high, 7 medium, 4 low**.

> "Every finding has a severity, its OWASP Top 10 2025 category, what's wrong, and one line on how to fix it."

Read out the top finding and its fix.

### Step 3: Show the depth (45 seconds)
Scroll to **Outdated Lodash 4.17.15** and click **Show 1 affected**. It says "loaded in the page".

> "The file is just called utils.js, so the URL doesn't reveal it. We found the version by reading the page's own JavaScript."

Scroll to **Server software version disclosed** and click **Show 3 affected**.

> "These are real HTTP headers, Apache and PHP versions. A web page can't read its own response headers, so this is something only an extension can do."

### Step 4: The payoff (30 seconds)
Open `http://localhost:8000/clean/` and click the icon.

**Judges see:** a **B**, **80 / 100**, and **1 high**.

> "Same site, with the fixes the tool recommended. It went from F to B. The one thing left is HTTPS, which my local test server doesn't have, and the tool still reports that honestly."

### Step 5: Be honest about limits (15 seconds)
> "It's a first look and not a pen test. It sends no attacks and only checks what the browser can see. A good grade doesn't mean a site is secure."

Saying this before anyone asks earns credibility with security judges.

### If you are using Juice Shop
Open `http://localhost:3000` and click the icon. Based on its source code, expect at least:

| Finding | Severity |
|---|---|
| Page is not served over HTTPS | high |
| Missing Content-Security-Policy | high |
| Missing Strict-Transport-Security | low |
| Missing Referrer-Policy | low |
| Missing Permissions-Policy | low |

That is about **45 / 100, an F**, before any cookie findings. Then go to `http://localhost:3000/#/login` and click the icon again. A **Password field on a page without HTTPS** finding should appear, because the scan reads the live page on every click.

Juice Shop sets `X-Frame-Options` and `X-Content-Type-Options`, and the tool should correctly **not** flag those. It's a good point to mention: the tool doesn't just report everything as broken.

The current Juice Shop page has no external `<script src>` tags in its source, so do not promise SRI or outdated-library findings there. Use the built-in target to show those. **Run Juice Shop once before presenting and update these numbers with what you actually see.**

---

## Backup plans

**If Docker fails:** use the built-in test target above. It was designed for this. Nothing about the demo changes.

**If PowerShell or the server also fails:** scan the file directly.
1. In `chrome://extensions`, click **Details** on Risk Pro and turn on **Allow access to file URLs**.
2. Open `C:\Users\Hp\Documents\Hackathon\test\vulnerable.html` in Chrome.
3. Click the icon.

You get an **F** with the note "Page content checks only". A local file has no HTTP headers or cookies, so those checks do not run. The Developer Tools console on that page shows a failed script load when the server is off, which is expected.

**If you own a deployed site:** you can also scan that. Only scan sites you own or have permission to test.

---

## Things that can surprise you on stage

| What happens | Why | What to do |
|---|---|---|
| Popup shows `?` | The page loaded before the extension could capture headers, usually after installing or reloading the extension. | Click **Reload page and scan**. |
| Popup closes by itself | Popups close when you click outside them. | Click the icon again. It rescans instantly. |
| Cookie findings on one localhost port come from another | Cookies are not separated by port, so `localhost:3000` cookies also appear on `localhost:8000`. | Run the built-in target first, or explain it. It is true browser behavior. |
| `/clean/` scores below B after using Juice Shop | Same reason, Juice Shop's cookies are shared. | Clear `localhost` cookies, or use a separate Chrome profile for Juice Shop. |
| You edited the code and nothing changed | Chrome is running the old copy. | Click the reload icon on the extension's card, then reload the page. |
| "Scanning…" stays up on a slow page | The content check waits for the page to finish loading. | Wait for the page to finish. |

---

## 5 likely judge questions

**1. How is this different from running a real scanner like ZAP?**
ZAP actively sends requests and attack payloads. This only reads what the browser already received. It is much narrower, but it is instant, safe to use on any page, and needs no setup. It's a first look, not a replacement.

**2. Why build an extension at all? Couldn't a bookmarklet do it?**
Page JavaScript can't read the response headers of its own document, and it can't see `HttpOnly` cookies. `chrome.webRequest` and `chrome.cookies` can. Those are the checks that make the tool useful.

**3. You request access to all sites. Why should anyone trust that?**
The checks only work if the extension can see the page you are on. It makes no network calls of its own and has no backend. It shows cookie names but never displays or stores their values. The code is plain JavaScript that anyone can read.

**4. How accurate is it? What about false positives?**
It can report false positives, because it sees only the surface. A missing `HttpOnly` flag may be intentional on a preference cookie, and a backported library fix would not be visible from its version number. We reduced several specific false alarms: lookalike names like `react-bootstrap`, Underscore posing as Lodash, CSP set through a `<meta>` tag, and Chrome's cache hiding the HSTS header.

**5. How is the grade calculated, and is it an official OWASP score?**
It is not official. It starts at 100 and subtracts 20, 10, or 5 per high, medium, or low finding. The categories come from the OWASP Top 10 2025, but the severities and the weights are our own judgment. The grade is a quick signal and not a measurement of real risk.

**If you get a technical follow-up:** "Why do the parts send messages rather than share variables?" See the Beginner traps in `CODE_WALKTHROUGH.md`.

---

## What not to claim

- ❌ "It finds vulnerabilities in your site." It finds missing protections and outdated versions, not proven exploits.
- ❌ "An A means the site is secure." It says nothing about SQL injection, broken access control, or server logic.
- ❌ "It covers the OWASP Top 10." It touches 3 of the 10 categories (A02, A03, A04), and only partly.
- ❌ "It finds all outdated libraries." It checks 4 libraries, and bundled code often hides them.
- ✅ "It's a fast, passive first look at what the browser can see, mapped to OWASP categories."
