"""Opt-in live smoke check using synthetic metadata, never browser traffic."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from trustline.__main__ import api_key
from trustline.inspection import ApprovedSites, Inspector, JevClient


class CountingClient:
    def __init__(self, client):
        self.client = client
        self.calls = 0

    def assess(self, observation):
        self.calls += 1
        return self.client.assess(observation)


def main():
    os.umask(0o077)
    key = api_key()
    if not key:
        print("TYPESAFE_API_KEY is not configured", file=sys.stderr)
        return 1
    client = CountingClient(JevClient(key))
    cases = [
        ("https://www.youtube.com", "approved"),
        ("https://www.linkedin.com", "approved"),
        ("https://github.com", "ordinary"),
        ("https://docs.python.org", "ordinary"),
        ("https://cedar-notebook.example", "unfamiliar"),
        ("https://paypal.com.account-verify.example", "deceptive-looking"),
        ("https://micros0ft-login.example", "deceptive-looking"),
    ]
    messages = []
    rows = []
    with tempfile.TemporaryDirectory(prefix="trustline-jev-") as directory:
        inspector = Inspector(ApprovedSites(Path(directory) / "approved.sqlite3"), client,
                              emit=lambda message, **kwargs: messages.append(message))
        for origin, category in cases:
            before = client.calls
            start = time.monotonic()
            result = inspector.inspect({"url": origin})
            rows.append({"origin": origin, "fixture_category": category, **result,
                         "api_calls": client.calls - before,
                         "elapsed_ms": round((time.monotonic() - start) * 1000)})
        # A second observation of the same origin must reuse the local cache.
        cache_passed = False
        if "probability" in rows[2]:
            before = client.calls
            cached = inspector.inspect({"url": cases[2][0]})
            cache_passed = cached.get("cached") is True and client.calls == before
    approved_passed = all(row["status"] == "skipped" and row["api_calls"] == 0
                          for row in rows[:2])
    live_passed = all("probability" in row for row in rows[2:])
    output_passed = messages == ["suspicious website"] * sum(
        row["status"] == "suspicious" for row in rows
    )
    report = {
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "model": "jev-latest", "threshold": 0.8, "api_calls": client.calls,
        "scope": "Synthetic origin metadata only; no fixture websites were visited. "
                 "This smoke check does not measure real-world detection accuracy.",
        "checks": {"approved_sites_skip_api": approved_passed,
                   "all_live_calls_return_valid_probabilities": live_passed,
                   "repeat_origin_uses_cache": cache_passed,
                   "suspicious_console_messages": output_passed},
        "cases": rows,
    }
    output = ROOT / "build/jev-smoke-report.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if all(report["checks"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
