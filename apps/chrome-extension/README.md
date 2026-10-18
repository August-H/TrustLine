# TrustLine Chrome extension

The Manifest V3 extension shows scores from the Python daemon and starts remote
Cloudflare Browser Run reviews from the **Deep scan** button.

## Run it

1. Configure the daemon's TypeSafe and Cloudflare keys and connect your ChatGPT
   subscription as described in [daemon setup](../macos-daemon/README.md).
2. Start the daemon with `.venv/bin/python run.py serve` from `apps/macos-daemon`.
   It starts both the inspection proxy on port 8899 and the extension API on 8765.
3. Open `chrome://extensions`, enable **Developer mode**, click **Load unpacked**,
   and select this `apps/chrome-extension` directory. Pin TrustLine.
4. After updating the extension, click its **Reload** button in `chrome://extensions`.

The extension can request scores and cloud reviews in an ordinary Chrome window.

## Checking sites before they open

With **Auto-scan websites** on, a `declarativeNetRequest` session rule sends every
top-level http(s) navigation to `scanning.html` before any request reaches the site.
The page asks the daemon for a `navigate` scan: the Jev address score plus the same
Cloudflare and ChatGPT page check as **Deep scan**. Unlike the Deep scan button it
joins a cloud check already running for that page, reuses a finished one, and skips
the cloud for pages approved in the last 24 hours. Verified domains skip both models.
Jev's confidence decides whether the cloud is needed (constants in the daemon's
`api.py`). Jev answers TrustLine's address questions as yes/no probabilities, which
have no `confidence` field, so the daemon uses TypeSafe's Noul conversion,
`jev_confidence = |2p − 1|`: 0 when Jev can't tell, 1 when it is certain either way.

| Jev confidence and trust score | What happens |
| --- | --- |
| 85%+ confident the address is fine (`NAVIGATION_CONFIDENCE`) | Opens with no cloud check. |
| 85%+ confident it is fake | Warning page, no cloud check. |
| Under 85% confident, trust score 70+ (`PASSING_SCORE`) | Opens with no cloud check, then a prompt appears in the page's top-right corner, under the toolbar icon: "This website may not be safe. **Click Here** to run a deep scan." |
| Under 85% confident, trust score under 70, or no score | Cloud check on the loading screen. |

A cloud block from the last two minutes still applies at any score. The prompt
(`nudge.js`) is injected with `chrome.scripting` into a closed shadow root, so the
page's styles can't change it and its scripts can't click it. **Click Here** runs a
Deep scan of that tab; a block sends the tab to the warning page. Each prompt shows
once, after the page finishes loading.

The screen stays hidden (a blank tab) while the address is scored. When no cloud
check is needed, the tab goes straight on and the screen never appears. When one
is, the screen appears, usually for several seconds to a minute, then:

- **Safe:** the domain is cleared for the rest of the browser session and the tab
  continues to the destination.
- **Suspicious or dangerous:** the tab goes to `warning.html` (when blocking is on).
- **Cloud check inconclusive, timed out or not configured:** the address check
  decides, as it did before cloud checks were added, and the reasons say so.
- **Daemon offline:** the page loads anyway, and the domain is checked again after
  60 seconds. Without a daemon there is no verdict to act on.

This needs `declarativeNetRequestWithHostAccess`, `scripting` (for the prompt) and
access to all http(s) sites.
Domains you allow from the warning page, `localhost` and `127.0.0.1` are never held.

Preview the screen without the daemon: open
`scanning.html?url=https%3A%2F%2Fexample.com&demo=safe` (or `demo=suspicious`,
`demo=dangerous`).

## Scores and Deep scan

- Domains in SQLite's permanent `approved_sites` table, including their subdomains,
  show **100** and skip Jev and Cloudflare. Initially these are YouTube and LinkedIn.
- Other domains show `round(100 * (1 - Jev suspiciousness probability))`.
  A Jev probability of 0.91 therefore displays a trust score of 9. Jev receives only
  origin metadata, not cookies, page contents, URL paths, or query parameters.
- **Deep scan** starts a cloud browser review using the daemon's existing Cloudflare
  and ChatGPT configuration. The service worker polls its job so closing the popup
  does not stop the review. A pending proxy review is reused; a completed review
  is rescanned when Deep scan is clicked again.
- The cloud verdict and evidence control the result and dangerous-site warning.
  After a Deep scan, the score is the lower of the Jev URL score and Jev's score for
  the page the cloud browser loaded. A blocked page never scores above 39, the top
  of the Dangerous zone, even when the URL looked fine.
- Successful page reviews persist for 24 hours in `scanned_pages`, separate from
  permanent trusted domains. These page approvals do not give the whole domain 100.
- Missing Jev results display `--`. An unavailable cloud review reports a failure or
  inconclusive result. The installed extension never generates mock scores.

Auto-scan runs the loading screen's cloud page check before navigation and a quick
database/Jev check on pages it lets through. Turning it off controls
extension scans and warning redirects, not the separate proxy's enforcement.

## Loopback API

Base URL: `http://127.0.0.1:8765`. Set `serve --api-port PORT` and update
`CONFIG.DAEMON_BASE_URL` plus manifest host permissions to use a different port.

- `GET /health`: daemon version and whether cloud review is configured.
- `POST /v1/analyze`: JSON `{ "url": "https://example.com/", "mode": "quick" }`.
  Returns `score`, `verdict`, `verified`, `score_source`, `jev_probability`,
  `jev_status`, `reasons` and `target_url`. `jev_status` is Jev's own result
  (`suspicious`, `uncertain`, `not_flagged`, `unscored` or `skipped`) and is kept
  even when a cloud review changes `verdict`. Use `"mode": "deep"` to also receive a `review` containing a
  job `token`, `status`, `reason` and `evidence`; it always runs a fresh cloud check.
  `"mode": "navigate"` returns the same `review` but reuses pending, finished or
  24-hour-approved checks, omits `review` when cloud checks are not configured, and
  leaves the address verdict in place when the check is inconclusive. It skips the
  cloud when `jev_confidence` is 0.85 or more, and for passing scores (70+) under
  that it returns `"verdict": "safe"` with `"unsure": true`. Every non-verified
  response includes `jev_confidence`.
- `GET /v1/reviews/TOKEN`: poll `pending`, `allow`, `block`, or `inconclusive`.

The API binds only to loopback, rejects website origins and non-loopback Host
headers, and requires JSON for analysis. Cloud reviews share the proxy's bounded
queue, privacy restrictions and SQLite approval store. API requests are not logged.
No API keys or ChatGPT tokens are returned to the extension.

## Warning page and preview

When Jev flags a site as suspicious, the tab redirects to the bundled
`warning.html` in its "This site looks suspicious" form. A completed cloud review
overrides that flag. Other dangerous verdicts, such as a cloud review block, show
the same page in its "This site may be dangerous" form. The user can go back,
expand the reasons, or acknowledge the risks, wait five seconds, manually type
the hostname, and allow that hostname for the browser session. This override is
extension-only and cannot override a daemon block or alter its SQLite database.

Open `popup.html` from a local web server for a standalone UI preview. The preview
switcher is hidden in the installed extension so demo scores cannot replace real
scores. `Test warning` remains available for checking the warning-page UI.

## Tests

```sh
node --test apps/chrome-extension/tests/background.test.cjs
apps/macos-daemon/.venv/bin/python -m unittest discover -s apps/macos-daemon/tests -q
```
