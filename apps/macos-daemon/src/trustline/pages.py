"""Proxy-owned interstitials. No third-party assets or website HTML."""

import html
import json
import secrets

from mitmproxy import http


def response_page(title, message, *, token=None, status=200):
    nonce = secrets.token_urlsafe(18)
    script = ""
    if token:
        # Token is generated locally, never supplied by the target website.
        encoded = json.dumps(token)
        script = f'''<script nonce="{nonce}">
const token = {encoded};
async function update() {{
  try {{
    const response = await fetch('/_trustline/reviews/' + token, {{cache:'no-store', credentials:'omit'}});
    if (!response.ok) throw new Error();
    const result = await response.json();
    document.getElementById('message').textContent = result.reason;
    document.getElementById('details').textContent = result.evidence.join(' · ');
    if (result.status === 'allow') {{
      location.replace('/_trustline/continue/' + token);
    }} else if (result.status === 'block') {{
      location.replace('/');
    }} else if (result.status === 'pending') {{
      setTimeout(update, 1000);
    }} else {{
      document.getElementById('title').textContent = 'Website remains blocked';
    }}
  }} catch {{
    document.getElementById('message').textContent = 'The check is unavailable. The website remains blocked.';
  }}
}}
update();
</script>'''
    body = f'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>TrustLine · {html.escape(title)}</title>
<style nonce="{nonce}">
body{{margin:0;background:#10151d;color:#e8edf3;font:18px system-ui,sans-serif;line-height:1.6}}
main{{max-width:650px;margin:14vh auto;padding:32px}}small{{color:#94a3b8}}h1{{font-size:34px;line-height:1.2}}
a{{color:#91caff}}#details{{font-size:15px;color:#b9c6d4}}
</style></head><body><main><small>TRUSTLINE</small><h1 id="title">{html.escape(title)}</h1>
<p id="message">{html.escape(message)}</p><p id="details"></p>
<p><a href="https://chatgpt.com/settings/usage" target="_blank" rel="noreferrer">Manage ChatGPT plan usage</a></p>
</main>{script}</body></html>'''
    return http.Response.make(status, body.encode(), {
        "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    })


def redirect(url):
    return http.Response.make(303, b"", {
        "Location": url, "Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
        "Content-Type": "text/plain; charset=utf-8",
    })
