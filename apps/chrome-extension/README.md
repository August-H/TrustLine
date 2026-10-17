# TrustLine Chrome Extension

Manifest V3 popup + service worker that shows how trustworthy the active tab is, backed by the TrustLine macOS daemon.

## Load it in Chrome

1. Open `chrome://extensions` and enable **Developer mode**.
2. Click **Load unpacked** and select this `apps/chrome-extension` folder.
3. Pin TrustLine from the puzzle-piece menu. The toolbar shield turns green, amber or red per tab.

You can also open `popup.html` from any local web server to preview the UI with demo data (no Chrome APIs needed).

## Files

| File | Purpose |
| --- | --- |
| `manifest.json` | MV3 manifest (`tabs`, `storage`, host access to the daemon on port 8765) |
| `background.js` | Service worker: daemon client, mock analyzer, auto-scan, toolbar icon/badge, warning redirect |
| `popup.html` / `popup.css` / `popup.js` | Popup UI (status card, Trust Meter, Deep Scan, auto-scan toggle, preview switcher) |
| `warning.html` / `warning.css` / `warning.js` | Bundled warning landing page used when a dangerous site is blocked |

## Daemon API contract (proposed)

The daemon has no code in the repo yet, so the extension targets this contract. All settings live in `CONFIG` at the top of `background.js`.

Base URL: `http://127.0.0.1:8765`

### `GET /health`

```json
{ "status": "ok", "version": "0.1.0" }
```

Any 2xx response counts as online. The result is cached for 10 seconds.

### `POST /v1/analyze`

Request:

```json
{ "url": "https://example.com/login", "mode": "quick" }
```

`mode` is `"quick"` (on navigation, 8 s timeout) or `"deep"` (the Deep Scan button, 90 s timeout).

Response:

```json
{
  "verdict": "safe",
  "score": 92,
  "reasons": ["Valid TLS certificate", "Domain registered 12 years ago"]
}
```

- `score`: 0–100, higher is more trustworthy. `trust_score` and `trustScore` are also accepted.
- `verdict`: `safe` | `suspicious` | `dangerous`. Aliases such as `blocked`, `malicious` and `warning` are mapped. If it is omitted, the verdict comes from the score (≥70 safe, ≥40 suspicious, otherwise dangerous).
- `reasons`: optional, up to 6 short strings shown as signals in the popup.

## Mock mode

If `/health` or `/v1/analyze` fails, the extension falls back to a local heuristic analyzer (HTTP, raw IPs, punycode, credential-bait keywords, abused TLDs, etc.), and the header pill reads **Mock Mode**. When the daemon comes back, it switches to **Daemon Active** on its own.

The **Preview** switcher at the bottom of the popup (Live / Safe / Suspicious / Dangerous) overrides only what the popup shows, for demos.

## Warning page

When auto-scan is on and a site comes back `dangerous`, the tab is redirected to the warning page. **Continue anyway** allowlists that domain for the browser session. To use the hosted page in `apps/web` instead, set `CONFIG.WARNING_PAGE_URL`; the page receives `url`, `verdict`, `score` and `reason` query parameters.
