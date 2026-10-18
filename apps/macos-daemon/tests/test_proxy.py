import asyncio
import contextlib
import io
from pathlib import Path
import plistlib
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import Mock, AsyncMock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from mitmproxy import connection, http
from install_macos import install
from trustline.browser import chrome_command
from trustline.inspection import ApprovedSites, Inspector, JevError
from trustline.proxy import InspectionProxy, REDIRECT_URL, request_kind
from trustline.reviews import ReviewManager


def make_flow(url="https://flagged.invalid/private?secret=yes", method="GET", headers=None):
    flow = http.HTTPFlow(
        connection.Client(peername=("127.0.0.1", 50000), sockname=("127.0.0.1", 8899)),
        connection.Server(address=("flagged.invalid", 443)),
    )
    flow.request = http.Request.make(method, url, headers=headers or {
        "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
    })
    return flow


class ProxyTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.sites = ApprovedSites(Path(self.directory.name) / "approved.sqlite3")
        self.jev = Mock()
        self.jev.assess.return_value = (0.95, 0.0, 1.0)
        self.emit = Mock()
        self.addon = InspectionProxy(Inspector(self.sites, self.jev, emit=self.emit))
        self.addCleanup(self.addon.done)

    async def test_suspicious_page_gets_303_and_no_secret_metadata(self):
        flow = make_flow(method="POST")
        flow.request.headers["Cookie"] = "secret cookie"
        flow.request.content = b"password=private"
        await self.addon.requestheaders(flow)
        self.assertEqual(flow.response.status_code, 303)
        self.assertEqual(flow.response.headers["Location"], REDIRECT_URL)
        self.assertEqual(flow.response.headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(flow.response.headers["Cache-Control"], "no-store")
        self.assertEqual(flow.response.content, b"")
        self.assertTrue(flow.request.stream)
        state = self.jev.assess.call_args.args[0].model_state()
        self.assertEqual(state["url_origin"], "https://flagged.invalid")
        self.assertNotIn("secret", str(state))
        self.assertNotIn("private", str(state))
        self.emit.assert_called_once_with("suspicious website", flush=True)

    async def test_cached_suspicious_pages_still_redirect(self):
        for _ in range(2):
            flow = make_flow()
            await self.addon.requestheaders(flow)
            self.assertEqual(flow.response.status_code, 303)
        self.jev.assess.assert_called_once()
        self.emit.assert_called_once()

    async def test_approved_destinations_and_redirect_target_do_not_call_model(self):
        for host in ["youtube.com", "www.youtube.com", "linkedin.com"]:
            flow = make_flow(f"https://{host}/private")
            await self.addon.requestheaders(flow)
            self.assertIsNone(flow.response)
        self.jev.assess.assert_not_called()
        flow = make_flow(REDIRECT_URL)
        await self.addon.requestheaders(flow)
        self.assertEqual(flow.response.status_code, 200)
        self.assertIn(b"Website blocked", flow.response.content)
        self.jev.assess.assert_not_called()

    async def test_suspicious_subresources_are_blocked_without_tab_redirect(self):
        for destination in ["script", "iframe", "image", "empty"]:
            flow = make_flow(headers={"Sec-Fetch-Dest": destination, "Sec-Fetch-Mode": "cors"})
            await self.addon.requestheaders(flow)
            self.assertEqual(flow.response.status_code, 403)
            self.assertNotIn("Location", flow.response.headers)

    async def test_model_failure_holds_request_without_contacting_origin(self):
        self.jev.assess.side_effect = JevError("Unavailable")
        flow = make_flow()
        with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
            await self.addon.requestheaders(flow)
        self.assertEqual(flow.response.status_code, 303)
        self.assertIn("/_trustline/check/", flow.response.headers["Location"])
        self.assertNotIn("flagged.invalid", diagnostic.getvalue())

    async def test_overload_does_not_queue_unbounded_model_calls(self):
        self.addon.pending = 8
        flow = make_flow()
        with contextlib.redirect_stderr(io.StringIO()):
            await self.addon.requestheaders(flow)
        self.jev.assess.assert_not_called()
        self.assertEqual(flow.response.status_code, 303)

    async def test_low_metadata_score_still_requires_remote_page_review(self):
        self.jev.assess.return_value = (0.1, 0.0, 1.0)
        flow = make_flow()
        await self.addon.requestheaders(flow)
        self.assertEqual(flow.response.status_code, 303)
        self.assertIn("/_trustline/check/", flow.response.headers["Location"])

    async def test_approved_tls_is_not_decrypted(self):
        for host in ["www.youtube.com", "linkedin.com", "127.0.0.1"]:
            data = SimpleNamespace(context=SimpleNamespace(server=SimpleNamespace(address=(host, 443))),
                                   ignore_connection=False)
            self.addon.tls_clienthello(data)
            self.assertTrue(data.ignore_connection)
        data.context.server.address = ("youtube.com.evil.invalid", 443)
        data.ignore_connection = False
        self.addon.tls_clienthello(data)
        self.assertFalse(data.ignore_connection)
        self.jev.assess.assert_not_called()

    async def test_pending_page_cannot_continue_until_remote_approval(self):
        gate = asyncio.Event()
        reviewer = Mock()
        async def review(url):
            await gate.wait()
            return {"verdict": "allow", "reason": "Fixture page reviewed", "evidence": ["Rendered fixture"]}
        reviewer.review = AsyncMock(side_effect=review)
        self.addon.reviews = ReviewManager(reviewer)
        self.jev.assess.return_value = (0.5, 0.0, 1.0)
        url = "https://uncertain.invalid/article"
        flow = make_flow(url)
        await self.addon.requestheaders(flow)
        location = flow.response.headers["Location"]
        token = location.rsplit("/", 1)[1]
        forbidden_continue = make_flow(REDIRECT_URL + "_trustline/continue/" + token)
        await self.addon.requestheaders(forbidden_continue)
        self.assertEqual(forbidden_continue.response.status_code, 404)
        repeated = make_flow(url)
        await self.addon.requestheaders(repeated)
        self.assertEqual(repeated.response.status_code, 303)
        gate.set()
        await self.addon.reviews.get(token).task
        continuation = make_flow(REDIRECT_URL + "_trustline/continue/" + token)
        await self.addon.requestheaders(continuation)
        self.assertEqual(continuation.response.headers["Location"], url)
        allowed = make_flow(url)
        await self.addon.requestheaders(allowed)
        self.assertIsNone(allowed.response)
        different_page = make_flow("https://uncertain.invalid/other-page")
        await self.addon.requestheaders(different_page)
        self.assertEqual(different_page.response.status_code, 303)

    async def test_unreviewed_subresources_and_forms_cannot_escape(self):
        reviewer = Mock(review=AsyncMock())
        self.addon.reviews = ReviewManager(reviewer)
        self.jev.assess.return_value = (0.5, 0.0, 1.0)
        resource = make_flow(headers={"Sec-Fetch-Dest": "script"})
        await self.addon.requestheaders(resource)
        self.assertEqual(resource.response.status_code, 403)
        form = make_flow("https://uncertain.invalid/login", method="POST")
        form.request.content = b"password=do-not-send"
        await self.addon.requestheaders(form)
        self.assertEqual(form.response.status_code, 303)
        row = next(iter(self.addon.reviews.records.values()))
        self.assertEqual(row.status, "inconclusive")
        reviewer.review.assert_not_called()

    async def test_allowlist_changes_apply_to_new_connections(self):
        self.sites.remove("youtube.com")
        data = SimpleNamespace(context=SimpleNamespace(server=SimpleNamespace(address=("youtube.com", 443))),
                               ignore_connection=False)
        self.addon.tls_clienthello(data)
        self.assertFalse(data.ignore_connection)

    async def test_response_bodies_stream_without_analysis(self):
        flow = make_flow()
        flow.response = http.Response.make(200, b"private body")
        self.addon.responseheaders(flow)
        self.assertTrue(flow.response.stream)
        self.jev.assess.assert_not_called()


class SetupTests(unittest.TestCase):
    def test_html_fallback_does_not_mistake_an_iframe_for_a_top_level_navigation(self):
        self.assertEqual(request_kind(make_flow(headers={"Accept": "text/html"}).request), "main_frame")
        self.assertEqual(request_kind(make_flow(headers={"Accept": "text/html", "Sec-Fetch-Dest": "iframe"}).request), "sub_frame")

    def test_launcher_routes_chrome_without_disabling_certificate_verification(self):
        command = chrome_command(Path("/tmp/trustline"), 8899)
        self.assertIn("--proxy-server=http://127.0.0.1:8899", command)
        self.assertIn("--disable-quic", command)
        self.assertIn("--user-data-dir=/tmp/trustline/chrome-profile", command)
        self.assertFalse(any("ignore-certificate" in part for part in command))
        self.assertFalse(any("extension" in part for part in command))

    def test_installer_only_creates_launchagent_and_preserves_venv_interpreter(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            python = home / ".venv/bin/python"
            paths = install(home, python, ROOT / "run.py")
            agent = plistlib.loads(paths["agent"].read_bytes())
            self.assertEqual(agent["ProgramArguments"][0], str(python))
            self.assertEqual(agent["ProgramArguments"][-3:], ["serve", "--port", "8899"])
            self.assertTrue(agent["KeepAlive"])
            self.assertNotIn("EnvironmentVariables", agent)
            self.assertEqual(paths["agent"].stat().st_mode & 0o777, 0o600)
            self.assertFalse((home / "Library/Application Support/Google").exists())


if __name__ == "__main__":
    unittest.main()
