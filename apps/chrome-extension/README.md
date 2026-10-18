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
The page asks the daemon for a quick score, shows for at least a second, then:

- **Safe:** the domain is cleared for the rest of the browser session and the tab
  continues to the destination.
- **Suspicious or dangerous:** the tab goes to `warning.html` (when blocking is on).
- **Daemon offline:** the page loads anyway, and the domain is checked again after
  60 seconds. Without a daemon there is no verdict to act on.

This needs `declarativeNetRequestWithHostAccess` and access to all http(s) sites.
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

Auto-scan runs quick database/Jev checks on navigation. Turning it off controls
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
  job `token`, `status`, `reason` and `evidence`.
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
