"""Local integration fixture. Never used by the production service."""

import asyncio
import json
from pathlib import Path
import sys
from mitmproxy import ctx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from trustline.inspection import ApprovedSites, Inspector
from trustline.proxy import run_proxy

state = Path(sys.argv[1])
port, http_port, tls_port, untrusted_tls_port = map(int, sys.argv[2:])


class FakeJev:
    def assess(self, observation):
        with (state / "model-inputs.jsonl").open("a") as output:
            output.write(json.dumps(observation.model_state()) + "\n")
        return 0.05 if observation.hostname in {
            "clean.invalid", "wrong-host.invalid", "untrusted.invalid",
        } else 0.95


class LocalRouting:
    def load(self, loader):
        # Trust only the temporary fixture root in this test proxy, never in macOS.
        ctx.options.update(ssl_verify_upstream_trusted_ca=str(state / "fixture-cert.pem"))

    def server_connect(self, data):
        # Every upstream connection stays on loopback, including accidental ones.
        host, port = data.server.address
        target_port = tls_port if port == 443 else http_port
        if host == "untrusted.invalid":
            target_port = untrusted_tls_port
        data.server.address = ("127.0.0.1", target_port)


class FakeRemoteReviewer:
    async def review(self, url):
        # Deliberately delay approval to test that the origin is not contacted
        # while a remote browser job is outstanding.
        await asyncio.sleep(0.15)
        with (state / "remote-reviews.jsonl").open("a") as output:
            output.write(json.dumps({"url": url}) + "\n")
        return {"verdict": "allow", "reason": "Local test fixture reviewed", "evidence": ["Fixture body"]}


asyncio.run(run_proxy(state, Inspector(ApprovedSites(state / "approved.sqlite3"), FakeJev()),
                      port, extra_addons=[LocalRouting()], reviewer=FakeRemoteReviewer()))
