import asyncio
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import AsyncMock, Mock, patch
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from trustline.inspection import JevError
from trustline.reviews import ReviewManager, review_url
from trustline.remote import CloudflareBrowser, RemoteError, RemoteReviewer, page_features, page_state, public_url


class ReviewTests(unittest.IsolatedAsyncioTestCase):
    async def test_allow_is_scoped_to_page_and_temporary_first_party_assets(self):
        reviewer = Mock(review=AsyncMock(return_value={"verdict": "allow", "reason": "Observed fixture", "evidence": []}))
        manager = ReviewManager(reviewer)
        self.addCleanup(manager.close)
        row = manager.start("https://ordinary.example/article")
        self.assertFalse(manager.allowed(row.url, "main_frame", "GET"))
        await row.task
        self.assertTrue(manager.allowed(row.url, "main_frame", "GET"))
        self.assertFalse(manager.allowed("https://ordinary.example/different", "main_frame", "GET"))
        self.assertTrue(manager.allowed("https://ordinary.example/app.js", "script", "GET"))
        self.assertFalse(manager.allowed("https://third-party.example/app.js", "script", "GET"))
        self.assertFalse(manager.allowed("https://ordinary.example/app.js", "sub_frame", "GET"))
        self.assertFalse(manager.allowed(row.url, "main_frame", "POST"))
        with patch("trustline.reviews.time.monotonic", return_value=row.created + manager.ttl + 1):
            self.assertFalse(manager.allowed(row.url, "main_frame", "GET"))

    async def test_query_is_not_sent_or_approved_by_sanitized_page_result(self):
        reviewer = Mock(review=AsyncMock(return_value={"verdict": "allow", "reason": "Observed fixture", "evidence": []}))
        manager = ReviewManager(reviewer)
        self.addCleanup(manager.close)
        row = manager.start("https://ordinary.example/article?token=private")
        await row.task
        reviewer.review.assert_awaited_once_with("https://ordinary.example/article")
        self.assertEqual(row.status, "inconclusive")
        self.assertFalse(manager.allowed(row.url, "main_frame", "GET"))
        self.assertNotIn("private", str(manager.snapshot(row.token)))

    async def test_timeout_failure_malformed_output_and_no_configuration_stay_blocked(self):
        for result in [RuntimeError("secret-token"), {"verdict": "safe"}, {"verdict": "allow", "reason": 123}]:
            model = AsyncMock(side_effect=result) if isinstance(result, Exception) else AsyncMock(return_value=result)
            manager = ReviewManager(Mock(review=model))
            row = manager.start("https://ordinary.example/")
            await row.task
            self.assertEqual(row.status, "inconclusive")
            self.assertNotIn("secret-token", row.reason)
            manager.close()
        manager = ReviewManager()
        self.assertEqual(manager.start("https://ordinary.example/").status, "inconclusive")
        async def wait_forever(url):
            await asyncio.Event().wait()
        manager = ReviewManager(Mock(review=wait_forever), timeout=0.01)
        row = manager.start("https://ordinary.example/")
        await row.task
        self.assertEqual(row.status, "inconclusive")

    async def test_deduplication_and_pending_queue_limit(self):
        gate = asyncio.Event()
        async def review(url):
            await gate.wait()
        manager = ReviewManager(Mock(review=review), max_pending=1)
        self.addCleanup(manager.close)
        row = manager.start("https://ordinary.example/")
        self.assertIs(row, manager.start(row.url))
        self.assertEqual(manager.start("https://ordinary.example/second").status, "inconclusive")
        self.assertEqual(manager.snapshot(row.token)["status"], "pending")

    async def test_private_urls_and_credentials_never_go_to_cloud(self):
        for url in ["file:///etc/passwd", "https://user:password@ordinary.example/", "http://169.254.169.254/", "http://localhost/"]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                review_url(url)
        for url in ["https://ordinary.example:9000/", "https://ordinary.example/?token=secret"]:
            with self.assertRaises((ValueError, RemoteError)):
                public_url(url)


class RemoteReviewerTests(unittest.IsolatedAsyncioTestCase):
    def browser(self, **state):
        return Mock(start=AsyncMock(), close=AsyncMock(), act=AsyncMock(), observe=AsyncMock(return_value={
            "text": "A complete fixture page", "http_status": 200, "policy_blocks": [], **state,
        }))

    async def test_model_can_inspect_interact_then_return_verdict_and_browser_closes(self):
        browser = self.browser()
        model = Mock(action=Mock(side_effect=[{"action": "scroll", "y": 600},
            {"action": "finish", "verdict": "block", "reason": "Observed deceptive login", "evidence": ["Fixture"]}]))
        result = await RemoteReviewer(model, lambda: browser).review("https://ordinary.example/")
        self.assertEqual(result["verdict"], "block")
        browser.act.assert_awaited_once_with({"action": "scroll", "y": 600})
        self.assertEqual(model.action.call_count, 2)
        browser.close.assert_awaited_once()

    async def test_incomplete_or_error_pages_cannot_be_approved(self):
        for state in [{"policy_blocks": ["blocked dependency"]}, {"http_status": 403}, {"text": ""}]:
            browser = self.browser(**state)
            model = Mock(action=Mock(return_value={"action": "finish", "verdict": "allow"}))
            result = await RemoteReviewer(model, lambda: browser).review("https://ordinary.example/")
            self.assertEqual(result["verdict"], "inconclusive")
            browser.close.assert_awaited_once()

    async def test_limits_and_model_failure_close_browser(self):
        browser = self.browser()
        model = Mock(action=Mock(return_value={"action": "scroll", "y": 600}))
        result = await RemoteReviewer(model, lambda: browser, max_steps=2).review("https://ordinary.example/")
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertEqual(browser.act.await_count, 2)
        model.action.side_effect = RuntimeError("credential-must-not-leak")
        with self.assertRaises(RuntimeError):
            await RemoteReviewer(model, lambda: browser).review("https://ordinary.example/")
        self.assertEqual(browser.close.await_count, 2)

    def allowing_model(self):
        return Mock(action=Mock(return_value={"action": "finish", "verdict": "allow",
                                              "reason": "Looks fine", "evidence": []}))

    async def test_jev_page_check_blocks_a_scam_the_model_would_allow(self):
        for deceptive, money, verdict in [(0.85, 0.1, "block"), (0.65, 0.9, "block"),
                                          (0.65, 0.1, "allow"), (0.3, 0.9, "allow")]:
            with self.subTest(deceptive=deceptive, money=money):
                browser = self.browser(url="https://shop.example/sale?ref=private")
                jev = Mock(assess_page=Mock(return_value=(deceptive, money)))
                result = await RemoteReviewer(self.allowing_model(), lambda: browser, jev=jev,
                                              threshold=0.8, money_threshold=0.6).review("https://shop.example/")
                self.assertEqual(result["verdict"], verdict)
                self.assertEqual(result["page_probability"], deceptive)
                if verdict == "block":
                    self.assertEqual(result["reason"], "TrustLine found signs of a scam on this page.")
                    self.assertEqual(len(result["evidence"]), 1 + (money >= 0.5))
                jev.assess_page.assert_called_once()

    async def test_jev_scam_finding_still_blocks_when_the_model_fails(self):
        model = Mock(action=Mock(side_effect=RuntimeError("plan renewal failed")))
        for deceptive, blocks in [(0.95, True), (0.1, False)]:
            browser = self.browser(url="https://shop.example/")
            jev = Mock(assess_page=Mock(return_value=(deceptive, 0.9)))
            reviewer = RemoteReviewer(model, lambda: browser, jev=jev)
            if blocks:
                self.assertEqual((await reviewer.review("https://shop.example/"))["verdict"], "block")
            else:
                with self.assertRaises(RuntimeError):
                    await reviewer.review("https://shop.example/")
            browser.close.assert_awaited_once()

    async def test_unavailable_page_check_leaves_the_model_verdict(self):
        browser = self.browser(url="https://shop.example/")
        jev = Mock(assess_page=Mock(side_effect=JevError("Jev unavailable")))
        result = await RemoteReviewer(self.allowing_model(), lambda: browser, jev=jev).review("https://shop.example/")
        self.assertEqual(result["verdict"], "allow")

    def test_page_features_describe_what_the_page_asks_for(self):
        plain = page_features([{"url": "https://news.example/", "links": [{"url": "https://news.example/a"}]}])
        self.assertEqual(plain, {"sign_in": False, "payment": False, "external_form": False, "downloads": False})
        risky = page_features([{
            "url": "https://bank.example/login",
            "forms": [{"action": "https://collector.example/post",
                       "inputs": [{"type": "text", "name": "user"}, {"type": "password", "name": "pw"}]}],
            "fields": [{"type": "text", "name": "x", "autocomplete": "cc-number"}],
            "links": [{"url": "https://bank.example/setup.exe"}],
        }])
        self.assertEqual(risky, {"sign_in": True, "payment": True, "external_form": True, "downloads": True})
        # A same-site sign-in form is normal, and a download attribute counts as a download.
        local = page_features([{"url": "https://mail.example/",
                                "forms": [{"action": "https://mail.example/session",
                                           "inputs": [{"type": "password"}]}],
                                "links": [{"url": "https://mail.example/guide", "download": True}]}])
        self.assertEqual(local, {"sign_in": True, "payment": False, "external_form": False, "downloads": True})

    async def test_review_result_carries_page_features(self):
        browser = self.browser(url="https://shop.example/", fields=[{"type": "password"}])
        result = await RemoteReviewer(self.allowing_model(), lambda: browser).review("https://shop.example/")
        self.assertEqual(result["verdict"], "allow")
        self.assertTrue(result["page_features"]["sign_in"])

    def test_page_state_sends_only_origin_text_and_form_shape(self):
        state = page_state({
            "url": "https://shop.example/checkout?session=secret", "title": "Checkout", "text": "Pay now",
            "screenshot": "data:image/jpeg;base64,secret", "links": [{"url": "https://secret.example/"}],
            "forms": [{"method": "post", "action": "https://collector.example/steal?id=secret",
                       "inputs": [{"type": "password", "name": "pw"}]},
                      {"method": "get", "action": "javascript:void(0)", "inputs": []}],
        })
        self.assertEqual(state, {
            "url_origin": "https://shop.example", "hostname": "shop.example", "title": "Checkout",
            "text": "Pay now", "forms": [
                {"method": "post", "action_origin": "https://collector.example",
                 "inputs": [{"type": "password", "name": "pw"}]},
                {"method": "get", "action_origin": None, "inputs": []}],
        })
        self.assertNotIn("secret", json.dumps(state))

    async def test_cloudflare_browser_rejects_forms_private_networks_and_cross_origin_navigation(self):
        browser = CloudflareBrowser("a" * 32, "synthetic-token")
        browser.initial_origin = "https://ordinary.example"
        browser.check_public_host = AsyncMock(return_value=True)
        for url, method, navigation in [("https://ordinary.example/login", "POST", True),
                                        ("https://different.example/", "GET", True),
                                        ("file:///etc/passwd", "GET", False)]:
            request = Mock(url=url, method=method, resource_type="document", is_navigation_request=Mock(return_value=navigation))
            route = Mock(request=request, continue_=AsyncMock(), abort=AsyncMock())
            await browser.route(route)
            route.abort.assert_awaited_once()
            route.continue_.assert_not_awaited()
        for action in [{"action": "type", "text": "secret"}, {"action": "navigate", "url": "https://different.example/"},
                       {"action": "click_link", "x": -1, "y": 2}]:
            with self.assertRaises((ValueError, RemoteError)):
                await browser.act(action)

    async def test_cloudflare_uses_guarded_remote_cdp_and_deletes_session_without_local_launch(self):
        page = Mock(on=Mock(), goto=AsyncMock(return_value=Mock(status=200, headers={})))
        context = Mock(set_default_timeout=Mock(), set_default_navigation_timeout=Mock(),
                       route=AsyncMock(), route_web_socket=AsyncMock(), new_page=AsyncMock(return_value=page), on=Mock())
        connected = Mock(new_context=AsyncMock(return_value=context), close=AsyncMock())
        chromium = Mock(connect_over_cdp=AsyncMock(return_value=connected), launch=AsyncMock())
        runtime = Mock(chromium=chromium, stop=AsyncMock())
        factory = Mock(start=AsyncMock(return_value=runtime))
        browser = CloudflareBrowser("a" * 32, "synthetic-cloudflare-token")
        browser.check_public_host = AsyncMock(return_value=True)
        session_id = "12345678-abcd-1234-abcd-123456789abc"
        with patch("playwright.async_api.async_playwright", return_value=factory), \
                patch("trustline.remote.request_json", return_value={"sessionId": session_id}) as service:
            await browser.start("https://ordinary.example/article")
            await browser.close()
        acquisition = service.call_args_list[0]
        self.assertIn("/browser-run/devtools/browser?keep_alive=60000", acquisition.args[0])
        self.assertEqual(acquisition.kwargs["data"]["guardrails"]["allowedDomains"], ["ordinary.example", "*.ordinary.example"])
        endpoint = chromium.connect_over_cdp.call_args.args[0]
        self.assertTrue(endpoint.startswith("wss://api.cloudflare.com/"))
        self.assertTrue(endpoint.endswith(session_id))
        self.assertNotIn("synthetic-cloudflare-token", endpoint)
        chromium.launch.assert_not_awaited()
        self.assertFalse(connected.new_context.call_args.kwargs["accept_downloads"])
        self.assertEqual(connected.new_context.call_args.kwargs["service_workers"], "block")
        self.assertEqual(service.call_args_list[-1].kwargs["method"], "DELETE")
        connected.close.assert_awaited_once()
        runtime.stop.assert_awaited_once()

    async def test_cloudflare_rate_limit_waits_without_launching_and_retries_only_once(self):
        browser = CloudflareBrowser("a" * 32, "synthetic-token")
        error = HTTPError("https://api.cloudflare.com/", 429, "rate limited", {"Retry-After": "23"}, io.BytesIO())
        with patch("trustline.remote.request_json", side_effect=[error, {"sessionId": "fixture"}]) as acquire, \
                patch("trustline.remote.asyncio.sleep", new_callable=AsyncMock) as wait:
            result = await browser.acquire_session("ordinary.example")
        self.assertEqual(result["sessionId"], "fixture")
        self.assertEqual(acquire.call_count, 2)
        wait.assert_awaited_once_with(23)
        self.assertIsNone(browser.playwright)
        self.assertIsNone(browser.browser)
        for status, retry_after in [(429, "3600"), (403, "20"), (401, "20")]:
            error = HTTPError("https://api.cloudflare.com/", status, "unavailable", {"Retry-After": retry_after}, io.BytesIO())
            with patch("trustline.remote.request_json", side_effect=error) as acquire, \
                    patch("trustline.remote.asyncio.sleep", new_callable=AsyncMock) as wait:
                with self.assertRaises(RemoteError):
                    await browser.acquire_session("ordinary.example")
                acquire.assert_called_once()
                wait.assert_not_awaited()
        errors = [HTTPError("https://api.cloudflare.com/", 429, "rate limited", {}, io.BytesIO()) for _ in range(2)]
        with patch("trustline.remote.request_json", side_effect=errors) as acquire, \
                patch("trustline.remote.asyncio.sleep", new_callable=AsyncMock) as wait:
            with self.assertRaises(RemoteError):
                await browser.acquire_session("ordinary.example")
            self.assertEqual(acquire.call_count, 2)
            wait.assert_awaited_once_with(20)


if __name__ == "__main__":
    unittest.main()
