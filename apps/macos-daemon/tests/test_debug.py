import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from trustline import debug
from trustline.inspection import JevClient, Observation


class DebugLogTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "logs" / "debug.log"

    def tearDown(self):
        debug.disable()
        self.directory.cleanup()

    def lines(self):
        return self.path.read_text().splitlines()

    def test_nothing_is_written_while_debug_mode_is_off(self):
        debug.log("analyze", url="https://example.com/")
        self.assertFalse(self.path.exists())

    def test_events_are_one_line_each_with_readable_fields(self):
        debug.enable(self.path)
        debug.log("analyze", mode="navigate", p=0.0812, reason="Looks fine to me", money=True, review=None)
        line = self.lines()[-1]
        self.assertRegex(line, r"^\d\d:\d\d:\d\d\.\d{3} analyze ")
        for part in ['mode=navigate', 'p=0.081', 'reason="Looks fine to me"', 'money=true', 'review=null']:
            self.assertIn(part, line)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_long_values_are_cut_short(self):
        debug.enable(self.path)
        debug.log("x", text="a" * 1000)
        self.assertLess(len(self.lines()[-1]), 400)

    def test_safe_url_drops_credentials_query_and_fragment(self):
        self.assertEqual(debug.safe_url("https://user:pw@shop.example:8443/pay?token=secret#frag"),
                         "https://shop.example:8443/pay")

    def test_jev_requests_are_logged_with_answers_and_tokens_but_not_the_key(self):
        debug.enable(self.path)
        client = JevClient("test-secret")
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = json.dumps({
            "answers": {name: {"type": "noul", "noul": 0.2} for name in
                        ["suspicious", "lookalike", "money", "recognized"]},
            "usage": {"input_tokens": 912}}).encode()
        client.opener = Mock(open=Mock(return_value=response))
        client.assess(Observation.parse({"url": "https://example.com/private?token=hidden"}))
        line = self.lines()[-1]
        self.assertIn("jev ", line)
        self.assertIn("input_tokens=912", line)
        self.assertNotIn("test-secret", self.path.read_text())
        self.assertNotIn("hidden", self.path.read_text())


class DebugConsoleTests(unittest.TestCase):
    STATE = {
        "debug_log": "/tmp/debug.log",
        "settings": {"threshold": 0.8, "cloud_review": True},
        "jev": {"api_key_configured": True, "cooldown_seconds": 0, "cache_entries": 1, "recent": [
            {"origin": "https://zingoptions.com", "status": "uncertain", "probability": 0.08,
             "confidence": 0.84, "money_site": True, "recognized": 0.1, "expires_in": 42}]},
        "api": {"pending": 0},
        "reviews": {"pending": 1, "total": 1, "recent": [
            {"token": "abc123", "url": "https://zingoptions.com/", "status": "pending",
             "age_seconds": 3, "reason": "Checking", "page_probability": None}]},
    }

    def test_render_shows_state_then_the_newest_log_lines(self):
        screen = debug.render(self.STATE, [f"line {i}" for i in range(100)], 120, 30)
        self.assertIn("https://zingoptions.com", screen)
        self.assertIn("abc123 pending", screen)
        self.assertIn("line 99", screen)
        self.assertNotIn("line 0\n", screen)
        self.assertLessEqual(len(screen.splitlines()), 30)

    def test_render_explains_an_unavailable_daemon(self):
        screen = debug.render("The daemon isn't reachable on 127.0.0.1:8765. Is it running?", ["x"], 80, 20)
        self.assertIn("isn't reachable", screen)

    def test_fetch_state_reports_a_stopped_daemon_instead_of_failing(self):
        self.assertIn("isn't reachable", debug.fetch_state(1))

    def test_console_script_runs_the_console_from_the_daemon_folder(self):
        script = debug.console_script(Path("/tmp/state dir"), 8765)
        self.assertTrue(script.startswith("#!/bin/sh\n"))
        self.assertIn("debug-console --api-port 8765", script)
        self.assertIn("'/tmp/state dir'", script)
        self.assertIn(str(debug.DAEMON_DIR / "run.py"), script)

    def test_open_console_uses_terminal_on_macos_only(self):
        with tempfile.TemporaryDirectory() as directory, patch("trustline.debug.subprocess.Popen") as popen:
            with patch.object(debug.sys, "platform", "linux"):
                self.assertFalse(debug.open_console(Path(directory), 8765))
            popen.assert_not_called()
            with patch.object(debug.sys, "platform", "darwin"):
                self.assertTrue(debug.open_console(Path(directory), 8765))
            command = popen.call_args.args[0]
            self.assertEqual(command[:3], ["/usr/bin/open", "-a", "Terminal"])
            script = Path(command[3])
            self.assertEqual(script.stat().st_mode & 0o777, 0o700)
            self.assertIn("debug-console", script.read_text())


if __name__ == "__main__":
    unittest.main()


class ReviewErrorLogTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "debug.log"
        debug.enable(self.path)

    async def asyncTearDown(self):
        debug.disable()
        self.directory.cleanup()

    async def run_review(self, error):
        from trustline.reviews import ReviewManager
        from unittest.mock import AsyncMock
        manager = ReviewManager(Mock(review=AsyncMock(side_effect=error)))
        row = manager.start("https://ordinary.example/")
        await row.task
        manager.close()
        return [line for line in self.path.read_text().splitlines() if "review.error" in line][-1]

    async def test_trustline_errors_log_their_fixed_message(self):
        from trustline.remote import RemoteError
        line = await self.run_review(RemoteError("The browser left the inspected origin"))
        self.assertIn('message="The browser left the inspected origin"', line)

    async def test_other_errors_log_only_their_type(self):
        line = await self.run_review(RuntimeError("secret-token https://x.example/?session=1"))
        self.assertIn("error=RuntimeError", line)
        self.assertNotIn("secret-token", line)


class CloudErrorLogTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "debug.log"
        debug.enable(self.path)

    async def asyncTearDown(self):
        debug.disable()
        self.directory.cleanup()

    def test_browser_error_code_keeps_only_chromes_fixed_code(self):
        from trustline.remote import browser_error_code
        self.assertEqual(browser_error_code(Exception(
            "Page.goto: net::ERR_NAME_NOT_RESOLVED at https://shop.example/?token=secret")), "ERR_NAME_NOT_RESOLVED")
        self.assertEqual(browser_error_code(Exception("ERR_CERT_DATE_INVALID")), "ERR_CERT_DATE_INVALID")
        self.assertIsNone(browser_error_code(Exception("Target page, context or browser has been closed")))

    async def test_a_failed_cloud_review_logs_the_stage_and_error_code_without_the_url(self):
        from unittest.mock import AsyncMock
        from trustline.remote import RemoteReviewer
        browser = Mock(stage="loading the site", close=AsyncMock(), start=AsyncMock(side_effect=Exception(
            "Page.goto: net::ERR_CONNECTION_REFUSED at https://secret-shop.example/?session=abc")))
        with self.assertRaises(Exception):
            await RemoteReviewer(Mock(), lambda: browser).review("https://secret-shop.example/")
        line = [l for l in self.path.read_text().splitlines() if "cloud.error" in l][-1]
        self.assertIn('stage="loading the site"', line)
        self.assertIn("code=ERR_CONNECTION_REFUSED", line)
        self.assertNotIn("secret-shop", line)
