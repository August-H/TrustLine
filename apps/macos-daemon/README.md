# TrustLine background process

TrustLine runs a local Python HTTP(S) proxy with three routes:

1. Approved destinations, initially YouTube and LinkedIn, pass through without
   model calls. Their HTTPS connections remain encrypted end to end.
2. Unapproved destinations with a Jev probability of at least 0.90 redirect to
   `https://blocked.example.com/`. The proxy serves this page itself.
3. All other unapproved pages show a checking page while a remote browser review
   runs. They cannot load locally until the review completes with `allow`.

Uncertain scores, low metadata scores, model failures, exhausted quotas, missing
configuration, and queue overload never approve an unknown page. Failed or
inconclusive reviews keep it blocked. A low origin score does not establish that
page content is safe. No Chrome extension is required.

## Setup

Use Python 3.12 or newer. From `apps/macos-daemon`:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Playwright is used only as a client for Cloudflare-hosted Chromium. You do not
need to run `playwright install`, and TrustLine never launches a local browser to
inspect uncertain sites.

Put these settings in `apps/macos-daemon/.env`, beside `run.py`:

```dotenv
TYPESAFE_API_KEY=your_typesafe_key
CLOUDFLARE_ACCOUNT_ID=your_cloudflare_account_id
CLOUDFLARE_API_TOKEN=your_cloudflare_browser_token
```

Obtain the TypeSafe key from the [TypeSafe console](https://console.typesafe.ai).
For Cloudflare, enable Browser Run and create an API token with **Browser
Rendering - Edit** permission for your account. Follow the official
[Cloudflare CDP setup](https://developers.cloudflare.com/browser-run/cdp/playwright/).
The Cloudflare account ID is a 32-character identifier. The token and ID are
required even on Cloudflare's free plan. No Worker deployment or VPS is needed.

The service reads `.env` at startup, including under launchd. Environment
variables take precedence. The file is excluded from Git. Restart the process
after editing it. The TypeSafe key also supports the existing Keychain fallback.

## Connect your ChatGPT subscription

```sh
.venv/bin/python run.py chatgpt-login
```

Choose **Continue with ChatGPT** in the browser and authorize ChatGPT plan usage
for **TrustLine**. The current official preview supports eligible Plus and Pro
accounts for local personal projects and open-source clients. Your account must
also provide `gpt-6.1-sol`. TrustLine checks the account's model catalog before
inference and does not substitute another model.

This uses the official Sign in with ChatGPT flow with PKCE, state, signed ID-token
verification, and rotating refresh tokens. It does not read Codex's credentials
or require an OpenAI API key. Model calls use your explicitly authorized ChatGPT
plan, subject to its usage limits and credit settings. There is no automatic API
billing fallback. Manage the app's access and credit settings in
[ChatGPT Settings → Usage](https://chatgpt.com/settings/usage).

The subscription route currently excludes OpenAI's native `computer` tool.
TrustLine instead sends screenshots and rendered page observations to GPT-6.1 Sol
and validates a small JSON browser-action protocol. The model can scroll, select
a link by screenshot coordinates, navigate within the same origin, and finish
with `allow`, `block`, or `inconclusive`. Selecting a link resolves its URL and
performs guarded navigation, rather than executing an arbitrary button handler.
This is a custom browser agent, with the model hosted by OpenAI and the browser
hosted by Cloudflare.

```sh
.venv/bin/python run.py chatgpt-status
.venv/bin/python run.py check-config
.venv/bin/python run.py chatgpt-accounts
.venv/bin/python run.py chatgpt-login --new-account
.venv/bin/python run.py chatgpt-select ACCOUNT_ID
.venv/bin/python run.py chatgpt-logout
```

Status commands never print tokens. Account registrations and credentials are
stored separately under the state directory's `chatgpt` folder, with owner-only
permissions. Login and token refreshes are serialized between CLI and daemon
processes. Credentials stay on your Mac and are never sent to Cloudflare. Restart
the daemon after connecting an account or changing Cloudflare configuration.

References: [registration](https://developers.openai.com/siwc/token-sharing-open-source/sign-in),
[inference](https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference),
[subscription limitations](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations).

## Start the proxy and route Chrome

```sh
.venv/bin/python run.py serve
```

The proxy listens on `127.0.0.1:8899`, and the Chrome extension API listens on
`127.0.0.1:8765`. The API shares the same Jev worker, cloud review queue and SQLite
approvals. `serve --api-port PORT` changes the API port. Options include `serve --port 8899
--threshold 0.95 --money-threshold 0.6 --model jev-latest`. When Jev judges a site
to be about crypto, finance, or shopping, the stricter `--money-threshold` (default
0.6) replaces `--threshold` (default 0.8). Both are starting policies, not
validated measures of real-world detection accuracy.

All commands accept `--state-dir PATH` before the command name. The default is
`~/Library/Application Support/TrustLine`. Use the same directory for sign-in,
service startup, and Chrome launch.

In another terminal:

```sh
.venv/bin/python run.py launch-chrome
```

This opens a separate Chrome profile routed through the proxy with QUIC disabled.
Your ordinary Chrome windows are not automatically routed through TrustLine.
Close all windows of the TrustLine profile before relaunching with another port.

## Trust the HTTPS interception certificate

On its first launch, the proxy creates a local CA under the state directory's
`certificates` folder. Chrome must trust it to receive HTTPS redirects and the
checking/blocked pages.

With the proxy running:

```sh
open -a "Keychain Access" "$HOME/Library/Application Support/TrustLine/certificates/mitmproxy-ca-cert.pem"
```

Import the public certificate into your login keychain, locate it, open its Trust
settings, and trust it for SSL. Authenticate if macOS requests it. Restart the
TrustLine Chrome profile if needed. Without this setup, intercepted HTTPS sites
show certificate errors. Do not disable Chrome certificate verification.

TrustLine does not install certificates, enable trust, or modify system proxy
settings automatically. Keep `mitmproxy-ca.pem`, which includes the private key,
private. The local blocked/checking host is intercepted and served inside the
proxy; no DNS record, website hosting, or certificate for example.com is needed.
It works only in the Chrome session using this proxy and trusting its CA.

## Review behavior and privacy

For the URL check, Jev receives only origin, hostname, HTTP method, resource type,
HTTPS flag, punycode flag, the top-level domain, and whether that top-level domain
is in `SKEPTICAL_TLDS` (`inspection.py`: cheap endings common on scam sites, such
as .xyz, .cc and .top). It receives no path, query, headers, cookies, or page
content. On those endings the question tells Jev to be sceptical: any further cue,
such as a brand, crypto, reward, login or support word, a service prefix like
`app-`, or a random-looking name, is enough to flag it; the ending alone is not.
Each request asks whether the metadata meets the stated suspicious-origin criteria, whether the hostname misspells a well-known name, and
whether the site is about crypto, finance, or shopping. For the misspelling check,
code supplies candidate readings of the hostname with common substitutions undone
(`visu4lstudio` reads as `visualstudio`). The higher of the first two
probabilities is the result. It is not a separate severity score. These are Noul
(yes/no) questions, which return no `confidence` field, so the extension API reports
`jev_confidence = |2p − 1|` from that result, TypeSafe's suggested conversion for a
Noul: 0 when yes and no are equally likely, 1 when Jev is certain. The extension's
loading screen skips the cloud check at 0.85 or more (`NAVIGATION_CONFIDENCE` in
`api.py`).

For remote review, Cloudflare receives the destination origin and path. OpenAI
receives the remote browser's rendered text, page/link/form metadata, screenshots,
and action history. Jev receives the landing page's origin, title, rendered text,
and form fields (input types and names, and where each form submits), but no path,
screenshot, or link targets. If Jev finds phishing or scam signs on the page above
the applicable threshold, the review blocks the page, even when the cloud model
would allow it or fails to finish. No local cookies, login sessions, form values, request bodies,
or ChatGPT tokens are sent to the website or Cloudflare. Queries, URL credentials,
and fragments are withheld. A successful check without query parameters cannot
approve a URL containing them; those links remain inconclusive. Hash-only routes
are not visible to an HTTP proxy and cannot be checked as distinct pages.

A review uses a new remote context with downloads, service workers, WebSockets,
form submissions, typing, and arbitrary script execution by the model disabled.
Fixed extraction code reads the DOM. Cloudflare session guardrails permit the
target hostname, its subdomains, and Cloudflare's common CDN set. Additional
client-side checks deny non-public resolved IPs, unusual ports, non-GET/HEAD
requests, and cross-origin navigations. This is defense in depth, not a guarantee
against every browser exploit or DNS rebinding scenario.

The worker permits at most six model actions and 90 seconds including queue time,
with one review running and at most eight pending. Remote sessions close in a
`finally` block and also have a short Cloudflare keep-alive timeout. Model input,
screenshots, reasons, and evidence remain in memory. Successful page approvals
are saved in SQLite as described below. Model/provider data handling still
follows their respective terms.

On approval, the browser returns to the checked page. The checking-page token
lasts at most 120 seconds from job creation. A successful page approval lasts
24 hours and applies to that exact page URL plus its first-party assets.
Another page or iframe needs its own review. Third-party
assets remain independently checked and may be blocked, so some sites will not
function fully. An incomplete remote render cannot receive an automatic pass.
Scam pages can also show different content to cloud browsers, so the verdict is
an assessment of what was observed, not a safety certificate.

Top-level GET navigations can be remotely reviewed. POST navigations remain
blocked without replaying form data. Suspicious background requests receive 403;
a response to an image, script, iframe, or fetch cannot navigate its containing
tab. Cached pages and service-worker responses without network requests cannot
be controlled by the proxy. Restart Chrome to clear existing uninspected tunnels.

## Approved destinations

The database initially includes `youtube.com` and `linkedin.com`, with their
subdomains. Other domains loaded by those sites are evaluated independently.
Complete domain labels are required, so `youtube.com.evil.example` never matches.
Private/reserved literal IPs, single-label hosts, and common local hostname
suffixes bypass cloud inspection for local network compatibility.

```sh
.venv/bin/python run.py approved
.venv/bin/python run.py approve trusted.example
.venv/bin/python run.py revoke trusted.example
```

Changes affect new requests and new TLS connections. Existing approved tunnels
remain encrypted until the browser reconnects. Domain revocations survive restart.
This implementation keeps the existing seed list; it does not automatically trust
200 popularity-ranked domains.

## Save successful page scans

Successful cloud reviews automatically add a row to `scanned_pages` in the same
`approved.sqlite3` database. The default path is
`~/Library/Application Support/TrustLine/approved.sqlite3`. Returning to the same
page skips JEV and Cloudflare for 24 hours, including after the daemon restarts.
Expired approvals require another scan. Failed, blocked, inconclusive, or
privacy-limited reviews never earn an approval. A successful API call alone does
not qualify; the final review verdict must be `allow`.

Each row stores a SHA-256 hash of the normalized page URL, its origin and hostname,
the approval/expiry times, and a review-policy version. Full paths, query tokens,
page contents, screenshots, and model explanations are not stored in SQLite.
The cache retains at most 10,000 approvals. It remains separate from
`approved_sites`, which grants an intentional, permanent domain bypass.
Previously scanned pages still use TLS interception to match the exact URL.

`revoke DOMAIN` also clears scanned-page approvals for that domain and its
subdomains. Running `review URL` forces a fresh remote check and invalidates the
previous approval before scanning. A subsequent failed or blocked scan cannot
reuse the old approval. Database failures keep the page blocked.

## Run at login

```sh
.venv/bin/python scripts/install_macos.py
```

The installer writes a user LaunchAgent. Stop a foreground proxy, then run the
printed `launchctl bootstrap` command. Keep the checkout and virtual environment
at the same paths, or reinstall the LaunchAgent after moving them.

```sh
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.trustline.daemon.plist"
tail -f "$HOME/Library/Logs/TrustLine/daemon.log"
```

The existing `.env` and protected ChatGPT session are used at login. Generic
errors go to `daemon.error.log`. Flow dumps, URL logs, and TLS secret logs are
disabled. Each newly blocked model verdict prints `suspicious website`.

## Restart after changes

Restart the daemon after pulling new code or editing `.env`; it only reads both at
startup. Then reload TrustLine in `chrome://extensions` if extension files changed.

Check which way it is running:

```sh
launchctl print "gui/$(id -u)/com.trustline.daemon" >/dev/null 2>&1 \
  && echo "LaunchAgent" || pgrep -fl "run.py.*serve"
```

**LaunchAgent** (installed with `scripts/install_macos.py`): restart it in place.

```sh
launchctl kickstart -k "gui/$(id -u)/com.trustline.daemon"
```

**Foreground** (started with `run.py serve` in a terminal): press Ctrl+C in that
terminal, then start it again from `apps/macos-daemon`:

```sh
.venv/bin/python run.py serve
```

If no terminal window is running it but `pgrep` still lists a process, stop it with
`pkill -f "run.py.*serve"` first. Run only one copy: a second one exits with
`TrustLine is already running in this state directory`.

Confirm it is back:

```sh
curl -s http://127.0.0.1:8765/health
```

It should print `"status": "ok"` and, when Cloudflare and ChatGPT are set up,
`"cloud_review_configured": true`.

## Verify

From the repository root:

```sh
apps/macos-daemon/.venv/bin/python -m unittest discover -s apps/macos-daemon/tests -v
```

Tests use simulated model/remote-browser responses, temporary certificates, and
local fixture servers. They verify TLS interception, certificate validation,
allowlist passthrough, the subscription request contract, token verification and
refresh, review isolation, and that pending pages never contact the origin.
They do not change system trust or read your browsing history.

The optional live Jev smoke check makes five requests with synthetic origins:

```sh
apps/macos-daemon/.venv/bin/python apps/macos-daemon/scripts/check_live_jev.py
```

It writes an ignored report under `apps/macos-daemon/build`. This diagnostic
checks JEV integration rather than the full cloud review workflow. A live remote
review additionally requires completing ChatGPT sign-in and configuring Cloudflare.

To exercise the three routes with live services and a controlled scam fixture:

```sh
apps/macos-daemon/.venv/bin/python apps/macos-daemon/scripts/check_live_flow.py --include-scam-fixture
```

This uses synthetic proxy flow objects, live JEV and GPT-6.1 requests, and two
Cloudflare browser sessions. It does not change browser settings or load a
suspicious website locally. The second cloud session renders a synthetic scam
page with JavaScript-generated content, rather than visiting a live scam site.
It writes `apps/macos-daemon/build/live-flow-report.json` and uses the default
ChatGPT state directory. Allow time between fresh sessions on the free plan.
The service retries a Cloudflare `429` acquisition once after at least 20 seconds,
respecting a numeric `Retry-After` up to 30 seconds, within the review's overall
time budget. Longer limits, repeated failures, and authorization errors leave the
site blocked.

After configuration, test a single public page without sending Chrome traffic:

```sh
cd apps/macos-daemon
.venv/bin/python run.py review https://example.com/
```

This consumes your authorized ChatGPT plan allowance and Cloudflare browser time.
It prints the final verdict, short reason, and evidence, without printing tokens.

## Stop and remove

Close the TrustLine Chrome session before stopping the proxy. A foreground process
stops with Ctrl+C. For the LaunchAgent:

```sh
launchctl bootout "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.trustline.daemon.plist"
```

Use `chatgpt-logout` to revoke the renewable session. If remote revocation cannot
be confirmed, disconnect TrustLine in ChatGPT Settings. Remove the LaunchAgent
plist and TrustLine CA from Keychain Access, and restore any proxy settings you
changed manually. The state directory contains the Chrome profile, CA, domain
allowlist, and protected ChatGPT credentials.

## Chrome extension integration

Load [the extension](../chrome-extension/README.md) to see database/Jev trust scores
or start a **Deep scan** in Cloudflare Browser Run. `serve` starts the loopback API
alongside the proxy; there is no second process to configure. The API provides
`GET /health`, `POST /v1/analyze`, and `GET /v1/reviews/TOKEN` on port 8765.
It accepts Chrome extension origins and native clients with no Origin header,
requires JSON for analysis, rejects website origins and non-loopback Host headers,
and does not log requests.

The extension score is 100 for permanent verified domains. Otherwise it is the
rounded inverse of Jev's suspiciousness probability, multiplied by 100, or null
when Jev cannot score the URL. A completed cloud review lowers it to Jev's score
for the loaded page when that is lower, and a blocked page never scores above 39,
the top of the Dangerous zone. Successful reviews still save
exact-page approvals to SQLite for 24 hours; they do not promote a domain into the
permanent verified list. Explicit Deep scans repeat completed reviews and reuse
reviews already pending in the proxy. The extension's loading screen uses
`navigate` mode instead, which also reuses completed reviews and 24-hour page
approvals, so opening a page does not repeat a cloud check. Known verified domains
always bypass both models, including when Deep scan is requested.
