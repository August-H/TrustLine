"""Opt-in integration check: real models and cloud browsers, synthetic local flows.

Never changes Chrome/proxy/certificate settings or reads browser traffic. Uses
Cloudflare time and authorized ChatGPT/TypeSafe usage. No local browser launches.
"""

import argparse
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mitmproxy import connection, http
from trustline.__main__ import api_key, setting
from trustline.chatgpt import ChatGPTAccount, ChatGPTPlanClient
from trustline.inspection import ApprovedSites, Inspector, JevClient
from trustline.proxy import InspectionProxy, REDIRECT_URL
from trustline.remote import CloudflareBrowser, RemoteReviewer
from trustline.reviews import ReviewManager


def flow(url):
    target = urlsplit(url)
    item = http.HTTPFlow(
        connection.Client(peername=("127.0.0.1", 50000), sockname=("127.0.0.1", 8899)),
        connection.Server(address=(target.hostname, 443)),
    )
    item.request = http.Request.make("GET", url, headers={
        "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
    })
    return item


class CountedJev:
    def __init__(self):
        self.client = JevClient(api_key())
        self.probabilities = []

    def assess(self, observation):
        probability = self.client.assess(observation)
        self.probabilities.append(probability)
        return probability


class CountedReviewer:
    def __init__(self, delegate):
        self.delegate, self.calls = delegate, 0

    async def review(self, url):
        self.calls += 1
        return await self.delegate.review(url)


class ScamFixtureBrowser(CloudflareBrowser):
    async def start(self, target):
        await super().start(target)
        # A synthetic fixture, never a live phishing site. JavaScript constructs
        # the scam prompt after the cloud browser loads the initial HTML.
        await self.page.set_content('''<!doctype html><html><head><title>Account verification</title></head>
<body style="font:22px system-ui;background:#f5f6fa;padding:60px"><main>
<h1>Microsoft Account Security</h1><p>Your account will be permanently deleted in 10 minutes.</p>
<form><p>Enter your Microsoft password and current authentication code to unlock your account.</p>
<label>Password <input name="password" type="password"></label>
<label>Authentication code <input name="authentication-code"></label></form>
<section id="payment"></section></main><script>
document.querySelector('#payment').innerHTML = '<h2>Pay the security release fee</h2>' +
'<p>Purchase a $200 Apple gift card and send us the redemption code. Do not contact Microsoft support.</p>';
</script></body></html>''')


async def main(include_fixture):
    account_id, token = setting("CLOUDFLARE_ACCOUNT_ID"), setting("CLOUDFLARE_API_TOKEN")
    account = ChatGPTAccount(Path.home() / "Library/Application Support/TrustLine")
    if not account.status()["using_chatgpt_plan"] or not account_id or not token or not api_key():
        raise RuntimeError("Connect ChatGPT and configure TypeSafe and Cloudflare first")
    model = ChatGPTPlanClient(account)
    reviewer = CountedReviewer(RemoteReviewer(model, lambda: CloudflareBrowser(account_id, token)))
    jev, messages = CountedJev(), []
    report = {
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Synthetic proxy flow objects with live JEV, GPT-6.1 subscription inference, and Cloudflare browsers. "
                 "No local website load or browser settings changes. This does not measure real-world detection accuracy.",
        "checks": {}, "cases": [],
    }
    with tempfile.TemporaryDirectory(prefix="trustline-live-") as directory:
        addon = InspectionProxy(Inspector(ApprovedSites(Path(directory) / "approved.sqlite3"), jev,
            threshold=0.9, emit=lambda message, **kwargs: messages.append(message)), ReviewManager(reviewer))
        try:
            for url in ["https://www.youtube.com/", "https://www.linkedin.com/"]:
                item = flow(url)
                await addon.requestheaders(item)
                report["cases"].append({"url": url, "route": "trusted", "forward_allowed": item.response is None})
            report["checks"]["trusted_skips_both_models"] = (
                all(row["forward_allowed"] for row in report["cases"]) and not jev.probabilities and reviewer.calls == 0)

            suspicious = flow("https://micros0ft-login.example/")
            await addon.requestheaders(suspicious)
            fast_block = suspicious.response is not None and suspicious.response.headers.get("Location") == REDIRECT_URL
            report["cases"].append({"url": suspicious.request.pretty_url, "route": "obvious-scam",
                "jev_probability": jev.probabilities[-1], "redirected_to_blocked": fast_block})
            report["checks"]["obvious_scam_blocks_without_cloud_browser"] = fast_block and reviewer.calls == 0

            started = time.monotonic()
            unknown = flow("https://example.com/")
            await addon.requestheaders(unknown)
            location = unknown.response.headers.get("Location", "") if unknown.response else ""
            held = location.startswith(REDIRECT_URL + "_trustline/check/")
            report["checks"]["unknown_held_before_remote_review"] = held
            if held:
                review_id = location.rsplit("/", 1)[1]
                row = addon.reviews.get(review_id)
                cannot_continue = flow(REDIRECT_URL + "_trustline/continue/" + review_id)
                await addon.requestheaders(cannot_continue)
                report["checks"]["pending_review_cannot_continue"] = cannot_continue.response.status_code == 404
                checking = flow(location)
                await addon.requestheaders(checking)
                report["checks"]["checking_page_is_proxy_owned"] = checking.response.status_code == 200
                if row.task:
                    await row.task
                report["cases"].append({"url": unknown.request.pretty_url, "route": "cloud-review",
                    "jev_probability": jev.probabilities[-1], "elapsed_seconds": round(time.monotonic() - started, 2),
                    **addon.reviews.snapshot(review_id)})
                report["checks"]["live_example_page_approved"] = row.status == "allow"
                resumed = flow(unknown.request.pretty_url)
                await addon.requestheaders(resumed)
                report["checks"]["approved_page_can_continue"] = resumed.response is None
            if include_fixture:
                # Workers Free permits a new browser instance once per 20s.
                # Waiting with no browser open consumes no browser minutes.
                await asyncio.sleep(20)
                started = time.monotonic()
                fixture_result = await RemoteReviewer(model, lambda: ScamFixtureBrowser(account_id, token)).review("https://example.com/")
                report["cases"].append({"route": "controlled-scam-fixture", "javascript_constructed_dom": True,
                    "elapsed_seconds": round(time.monotonic() - started, 2), **fixture_result})
                report["checks"]["cloud_model_blocks_controlled_scam_fixture"] = fixture_result["verdict"] == "block"
            report["jev_calls"] = len(jev.probabilities)
            report["suspicious_console_messages"] = len(messages)
            output = ROOT / "build/live-flow-report.json"
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps(report, indent=2))
            return all(report["checks"].values())
        finally:
            addon.done()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--include-scam-fixture", action="store_true", help="Also render a synthetic scam fixture in a second cloud session")
    args = parser.parse_args()
    try:
        succeeded = asyncio.run(main(args.include_scam_fixture))
    except Exception:
        print("Live integration check could not finish. Credentials and provider errors were not printed.", file=sys.stderr)
        raise SystemExit(1) from None
    raise SystemExit(0 if succeeded else 1)
