import asyncio
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import AsyncMock, Mock, patch
from urllib.error import HTTPError

from playwright.async_api import Error as BrowserError, TimeoutError as BrowserTimeout

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from trustline.inspection import JevError
from trustline.reviews import ReviewManager, review_url
from trustline.remote import (
    HTML_LIMIT, CloudflareBrowser, RemoteError, RemoteReviewer, allowed_domains,
    browser_error_code, compact_html, page_features, page_state, public_url, same_site_redirect,
)


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

    def test_page_html_is_compacted_for_jev_but_keeps_what_visitors_cannot_see(self):
        html = compact_html(
            "<html><head><meta name='robots' content='head-only'><script src='/preload.js'></script></head>"
            "\n<body>\n<style>body { color: red }</style><!-- note -->"
            "<svg viewBox='0 0 9 9'><path d='M0 0L9 9'/></svg><img src='data:image/png;base64,QUJDRA=='>"
            "<div hidden>Enter your seed phrase</div>"
            "<form action='https://collector.example/steal'><input type='hidden' name='wallet'></form>"
            "<script>window.ethereum.request({method:'eth_requestAccounts'})" + "x" * 5000 + "</script>"
            "</body></html>")
        for kept in ["Enter your seed phrase", "https://collector.example/steal", "name='wallet'",
                     "eth_requestAccounts", "<style></style>", "<svg viewBox='0 0 9 9'></svg>", "data:…"]:
            self.assertIn(kept, html)
        for dropped in ["color: red", "note", "M0 0L9 9", "QUJDRA==", "x" * 2001, "\n", "head-only", "preload.js"]:
            self.assertNotIn(dropped, html)
        self.assertEqual(len(compact_html("<p>" + "a " * 100000 + "</p>")), HTML_LIMIT)
        self.assertEqual(compact_html(None), "")

    def test_page_state_includes_compacted_html_only_when_present_and_wanted(self):
        observation = {"url": "https://shop.example/", "title": "Shop", "text": "Hi", "forms": [],
                       "html": "<body>  <p>Hi</p> </body>"}
        self.assertEqual(page_state(observation)["html"], "<body> <p>Hi</p> </body>")
        self.assertNotIn("html", page_state(observation, include_html=False))
        self.assertNotIn("html", page_state({**observation, "html": ""}))

    async def test_page_check_retries_without_html_when_jev_rejects_it(self):
        browser = self.browser(url="https://shop.example/")
        observation = await browser.observe()
        observation["html"] = "<body>" + "a " * 30000 + "</body>"
        browser.observe = AsyncMock(return_value=observation)
        jev = Mock(assess_page=Mock(side_effect=[JevError("Jev HTTP error 400"), (0.95, 0.9)]))
        result = await RemoteReviewer(self.allowing_model(), lambda: browser, jev=jev).review("https://shop.example/")
        self.assertEqual(result["verdict"], "block")
        first, second = (call.args[0] for call in jev.assess_page.call_args_list)
        self.assertIn("html", first)
        self.assertNotIn("html", second)

    def test_redirects_may_stay_on_the_same_site_but_not_leave_it(self):
        for before, after in [("https://siemens.com", "https://www.siemens.com"),
                              ("http://example.org", "https://example.org"),
                              ("https://www.github.com", "https://github.com"),
                              ("https://shop.example", "https://eu.shop.example")]:
            self.assertTrue(same_site_redirect(before, after), after)
        for before, after in [("https://siemens.com", "https://siemens.com.evil.example"),
                              ("https://bank.example", "https://example"),
                              ("https://example.org", "http://example.org"),
                              ("https://login.example", "https://other.example")]:
            self.assertFalse(same_site_redirect(before, after), after)
        self.assertEqual(allowed_domains("siemens.com"), ["siemens.com", "*.siemens.com"])
        self.assertEqual(allowed_domains("www.github.com"),
                         ["www.github.com", "*.www.github.com", "github.com", "*.github.com"])

    async def test_cloudflare_browser_follows_a_same_site_redirect_only(self):
        for landed, ok in [("https://www.siemens.com/en-us/", True), ("https://phish.example/", False)]:
            page = Mock(on=Mock(), goto=AsyncMock(return_value=Mock(status=200, headers={})), url=landed)
            context = Mock(set_default_timeout=Mock(), set_default_navigation_timeout=Mock(), route=AsyncMock(),
                           route_web_socket=AsyncMock(), new_page=AsyncMock(return_value=page), on=Mock())
            connected = Mock(new_context=AsyncMock(return_value=context), close=AsyncMock())
            runtime = Mock(chromium=Mock(connect_over_cdp=AsyncMock(return_value=connected)), stop=AsyncMock())
            browser = CloudflareBrowser("a" * 32, "synthetic-cloudflare-token")
            browser.check_public_host = AsyncMock(return_value=True)
            with patch("playwright.async_api.async_playwright", return_value=Mock(start=AsyncMock(return_value=runtime))), \
                    patch("trustline.remote.request_json", return_value={"sessionId": "12345678-abcd-1234-abcd-123456789abc"}):
                if ok:
                    await browser.start("https://siemens.com/")
                    self.assertEqual(browser.initial_origin, "https://www.siemens.com")
                    self.assertEqual(browser.initial_url, "https://siemens.com/")
                else:
                    with self.assertRaises(RemoteError):
                        await browser.start("https://siemens.com/")
                await browser.close()

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
        # The page's own loads count against approval; the file:// subresource does not.
        self.assertEqual(len(browser.blocked), 2)
        self.assertEqual(browser.background_blocks, 1)
        for action in [{"action": "type", "text": "secret"}, {"action": "navigate", "url": "https://different.example/"},
                       {"action": "click_link", "x": -1, "y": 2}]:
            with self.assertRaises((ValueError, RemoteError)):
                await browser.act(action)

    async def test_background_blocks_are_counted_but_only_main_page_blocks_void_approval(self):
        browser = CloudflareBrowser("a" * 32, "synthetic-token")
        browser.initial_origin = "https://ordinary.example"
        browser.check_public_host = AsyncMock(return_value=True)
        main_frame, ad_frame = object(), object()
        browser.page = Mock(main_frame=main_frame)
        for url, method, kind, navigation, frame in [
                ("https://ordinary.example/collect", "POST", "xhr", False, main_frame),      # analytics beacon
                ("https://ordinary.example/live", "GET", "eventsource", False, main_frame),  # event stream
                ("https://ads.example/frame", "GET", "document", True, ad_frame)]:            # cross-origin iframe
            request = Mock(url=url, method=method, resource_type=kind, frame=frame,
                           is_navigation_request=Mock(return_value=navigation))
            await browser.route(Mock(request=request, continue_=AsyncMock(), abort=AsyncMock()))
        self.assertEqual((browser.blocked, browser.background_blocks), ([], 3))
        request = Mock(url="https://evil.example/", method="GET", resource_type="document", frame=main_frame,
                       is_navigation_request=Mock(return_value=True))
        await browser.route(Mock(request=request, continue_=AsyncMock(), abort=AsyncMock()))
        self.assertEqual(browser.blocked, ["The page itself was blocked by the inspection policy"])

    async def test_asset_requests_cannot_exhaust_the_main_navigation_budget(self):
        browser = CloudflareBrowser("a" * 32, "synthetic-token")
        browser.initial_origin = "https://ordinary.example"
        browser.check_public_host = AsyncMock(return_value=True)
        browser.page = Mock(main_frame=object())
        for count in [150, 1500, 5000]:
            for navigation, kind in [(False, "script"), (True, "document")]:
                browser.requests = count
                request = Mock(url="https://ordinary.example/", method="GET", resource_type=kind,
                    frame=browser.page.main_frame, is_navigation_request=Mock(return_value=navigation))
                route = Mock(request=request, continue_=AsyncMock(), abort=AsyncMock())
                await browser.route(route)
                route.continue_.assert_awaited_once()
                route.abort.assert_not_awaited()
                self.assertEqual(browser.requests, count + 1)
        self.assertEqual(browser.blocked, [])

    async def test_only_main_document_server_redirects_may_change_to_a_same_site_origin(self):
        browser = CloudflareBrowser("a" * 32, "synthetic-token")
        browser.initial_origin = "https://ordinary.example"
        browser.check_public_host = AsyncMock(return_value=True)
        main, iframe = object(), object()
        browser.page = Mock(main_frame=main)
        for url, frame, redirected_from, allowed in [
            ("https://www.ordinary.example/", main, object(), True),
            ("https://www.ordinary.example/", main, None, False),
            ("https://www.ordinary.example/", iframe, object(), False),
            ("https://evil.example/", main, object(), False),
            ("http://ordinary.example/", main, object(), False),
        ]:
            request = Mock(url=url, method="GET", resource_type="document", frame=frame,
                redirected_from=redirected_from, is_navigation_request=Mock(return_value=True))
            route = Mock(request=request, continue_=AsyncMock(), abort=AsyncMock())
            await browser.route(route)
            self.assertEqual(route.continue_.await_count, int(allowed))
            self.assertEqual(route.abort.await_count, int(not allowed))

    async def test_an_http_to_https_upgrade_on_the_same_host_is_the_same_site(self):
        browser = CloudflareBrowser("a" * 32, "synthetic-token")
        browser.initial_origin = "http://edgetrust.example"
        browser.check_public_host = AsyncMock(return_value=True)
        self.assertTrue(browser.same_site("https://edgetrust.example"))
        self.assertTrue(browser.same_site("http://edgetrust.example"))
        self.assertFalse(browser.same_site("https://other.example"))
        self.assertFalse(browser.same_site("https://edgetrust.example.evil.example"))
        request = Mock(url="https://edgetrust.example/", method="GET", resource_type="document",
                       is_navigation_request=Mock(return_value=True))
        route = Mock(request=request, continue_=AsyncMock(), abort=AsyncMock())
        await browser.route(route)
        route.continue_.assert_awaited_once()
        browser.initial_origin = "http://edgetrust.example:8080"
        self.assertIsNone(browser.https_upgrade())
        browser.initial_origin = "https://edgetrust.example"
        self.assertIsNone(browser.https_upgrade())
        self.assertFalse(browser.same_site("http://edgetrust.example"))

    async def test_oversized_or_missing_scrolls_are_clamped_instead_of_failing_the_review(self):
        browser = CloudflareBrowser("a" * 32, "synthetic-token")
        browser.page = Mock(mouse=Mock(wheel=AsyncMock()))
        for y, expected in [(5000, 1600), (-3000, -1600), (600, 600), (None, 800), (412.6, 413)]:
            with patch("trustline.remote.asyncio.sleep", AsyncMock()):
                await browser.act({"action": "scroll", "y": y})
            self.assertEqual(browser.page.mouse.wheel.await_args.args, (0, expected))

    async def test_an_allow_stands_when_only_background_requests_were_blocked(self):
        browser = self.browser(url="https://shop.example/", background_requests_blocked=12)
        result = await RemoteReviewer(self.allowing_model(), lambda: browser).review("https://shop.example/")
        self.assertEqual(result["verdict"], "allow")

    async def test_cloudflare_uses_guarded_remote_cdp_and_deletes_session_without_local_launch(self):
        page = Mock(on=Mock(), goto=AsyncMock(return_value=Mock(status=200, headers={})),
                    url="https://ordinary.example/article")
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

    def test_only_main_document_responses_update_status_and_challenge_state(self):
        browser = CloudflareBrowser("a" * 32, "synthetic-token")
        browser.initial_origin = "https://ordinary.example"
        browser.page = Mock(main_frame=object(), url="https://ordinary.example/")
        def response(status, mitigation=None, *, frame=None, navigation=True):
            return Mock(status=status, headers={"cf-mitigated": mitigation} if mitigation else {},
                        request=Mock(is_navigation_request=Mock(return_value=navigation),
                                     frame=frame or browser.page.main_frame))
        browser.document_response(response(403, "challenge"))
        self.assertEqual((browser.http_status, browser.mitigation), (403, "challenge"))
        browser.document_response(response(200, navigation=False))
        browser.document_response(response(200, frame=object()))
        self.assertEqual((browser.http_status, browser.mitigation), (403, "challenge"))
        browser.document_response(response(200))
        self.assertEqual((browser.http_status, browser.mitigation), (200, None))
        browser.document_response(response(403, "guardrails"))
        self.assertEqual(len(browser.blocked), 1)

    def test_document_response_before_commit_does_not_read_the_old_page_url(self):
        browser = CloudflareBrowser("a" * 32, "synthetic-token")
        browser.initial_origin = "https://ordinary.example"
        browser.page = Mock(main_frame=object(), url="about:blank")
        response = Mock(status=200, headers={}, request=Mock(
            is_navigation_request=Mock(return_value=True), frame=browser.page.main_frame))
        browser.document_response(response)
        self.assertEqual(browser.http_status, 200)
        self.assertEqual(browser.initial_origin, "https://ordinary.example")
        browser.page.url = "https://www.ordinary.example/"
        browser.accept_document_origin()
        self.assertEqual(browser.initial_origin, "https://www.ordinary.example")

    async def test_challenge_clears_before_either_model_reads_the_actual_page(self):
        browser = CloudflareBrowser("a" * 32, "synthetic-token")
        browser.initial_origin = "https://ordinary.example"
        browser.http_status = 403
        browser.start = AsyncMock()
        browser.close = AsyncMock()
        browser.challenge_present = AsyncMock(side_effect=[True, False])
        browser.page = Mock(url="https://ordinary.example/", main_frame=object(),
            is_closed=Mock(return_value=False), screenshot=AsyncMock(return_value=b"jpeg"),
            evaluate=AsyncMock(return_value={"text": "Actual shop page", "html": "<body>Actual shop page</body>"}))
        model, jev = self.allowing_model(), Mock(assess_page=Mock(return_value=(0.1, 0.8)))
        async def cleared(_):
            model.action.assert_not_called()
            jev.assess_page.assert_not_called()
            browser.document_response(Mock(status=200, headers={}, request=Mock(
                is_navigation_request=Mock(return_value=True), frame=browser.page.main_frame)))
        with patch("trustline.remote.asyncio.sleep", side_effect=cleared) as wait:
            result = await RemoteReviewer(model, lambda: browser, jev=jev).review("https://ordinary.example/")
        self.assertEqual(result["verdict"], "allow")
        self.assertEqual(model.action.call_args.args[0]["http_status"], 200)
        self.assertEqual(model.action.call_args.args[0]["text"], "Actual shop page")
        self.assertEqual(jev.assess_page.call_args.args[0]["text"], "Actual shop page")
        wait.assert_awaited_once_with(0.5)
        browser.close.assert_awaited_once()

    async def test_persistent_challenge_stays_inconclusive_without_model_calls_or_probability(self):
        browser = CloudflareBrowser("a" * 32, "synthetic-token")
        browser.start = AsyncMock()
        browser.close = AsyncMock()
        browser.http_status, browser.mitigation = 403, "challenge"
        browser.page = Mock(is_closed=Mock(return_value=False), screenshot=AsyncMock(), evaluate=AsyncMock())
        model, jev = self.allowing_model(), Mock(assess_page=Mock())
        manager = ReviewManager(RemoteReviewer(model, lambda: browser, jev=jev))
        self.addCleanup(manager.close)
        with patch("trustline.remote.CHALLENGE_WAIT_SECONDS", 0.02):
            row = manager.start("https://ordinary.example/")
            await row.task
        self.assertEqual(row.status, "inconclusive")
        self.assertIn("browser check did not clear", row.reason)
        self.assertIsNone(row.page_probability)
        self.assertFalse(manager.allowed(row.url, "main_frame", "GET"))
        model.action.assert_not_called()
        jev.assess_page.assert_not_called()
        browser.page.screenshot.assert_not_awaited()
        browser.page.evaluate.assert_not_awaited()
        browser.close.assert_awaited_once()

    async def test_ordinary_page_does_not_wait_and_challenge_context_reload_is_rechecked(self):
        browser = CloudflareBrowser("a" * 32, "synthetic-token")
        browser.page = Mock(evaluate=AsyncMock(return_value=False))
        with patch("trustline.remote.asyncio.sleep", new_callable=AsyncMock) as wait:
            await browser.wait_for_site()
        wait.assert_not_awaited()
        browser.page.evaluate = AsyncMock(side_effect=[
            BrowserError("Execution context was destroyed, most likely because of a navigation"), False])
        with patch("trustline.remote.asyncio.sleep", new_callable=AsyncMock) as wait:
            await browser.wait_for_site()
        wait.assert_awaited_once_with(0.5)

    @unittest.skipUnless(shutil.which("node"), "Node.js executes the fixed challenge detector")
    async def test_fixed_challenge_detector_executes_and_ignores_embedded_widgets(self):
        browser = CloudflareBrowser("a" * 32, "synthetic-token")
        browser.page = Mock(evaluate=AsyncMock(return_value=False))
        await browser.challenge_present()
        script = browser.page.evaluate.await_args.args[0]
        cases = [
            {"title": "Shop", "text": "Welcome", "status": 200},
            {"title": "Just a moment...", "text": "Checking your browser", "status": 200},
            {"title": "Access denied", "text": "Checking your browser before accessing the site", "status": 403},
            {"title": "Sign in", "text": "Sign in. Verify you are human", "status": 200},
            {"title": "Shop", "text": "Product " * 400 + "Verify you are human", "status": 200},
            {"title": "", "text": "Please wait", "marker": True, "status": 200},
        ]
        # Execute the actual fixed JS sent to Playwright, so mocks cannot hide a
        # syntax error or a detector that flags an ordinary embedded widget.
        runner = """
            const {script, cases} = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
            const detect = eval('(' + script + ')');
            const results = cases.map(item => {
                globalThis.document = {title: item.title, body: {innerText: item.text},
                    querySelector: () => item.marker ? {} : null};
                return detect({status: item.status});
            });
            process.stdout.write(JSON.stringify(results));
        """
        result = subprocess.run([shutil.which("node"), "-e", runner],
                                input=json.dumps({"script": script, "cases": cases}),
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [False, True, True, False, False, True])

    async def test_challenge_wait_never_retries_a_navigation_blocked_by_policy(self):
        browser = CloudflareBrowser("a" * 32, "synthetic-token")
        browser.mitigation = "challenge"
        browser.blocked = ["A required navigation was blocked"]
        with patch("trustline.remote.asyncio.sleep", new_callable=AsyncMock) as wait:
            with self.assertRaisesRegex(RemoteError, "inspection policy"):
                await browser.wait_for_site()
        wait.assert_not_awaited()

    async def test_transient_navigation_failure_retries_in_the_same_guarded_page(self):
        for code in ("ERR_CONNECTION_RESET", "ERR_CONNECTION_CLOSED", "ERR_NETWORK_CHANGED",
                     "ERR_HTTP2_PROTOCOL_ERROR"):
            with self.subTest(code=code):
                browser = CloudflareBrowser("a" * 32, "synthetic-token")
                browser.initial_origin = "https://ordinary.example"
                response = Mock(status=200, headers={})
                browser.page = Mock(url="https://ordinary.example/",
                                    goto=AsyncMock(side_effect=[BrowserError(f"net::{code}"), response]))
                browser.stage = "loading the site"
                with patch("trustline.remote.asyncio.sleep", new_callable=AsyncMock) as wait:
                    self.assertIs(await browser.navigate("https://ordinary.example/"), response)
                self.assertEqual(browser.page.goto.await_count, 2)
                self.assertEqual(browser.page.goto.await_args_list[0], browser.page.goto.await_args_list[1])
                wait.assert_awaited_once_with(0.5)
                self.assertIsNone(browser.session_id)

    async def test_navigation_does_not_retry_persistent_errors_or_policy_blocks(self):
        for error, blocked in [
            (BrowserError("net::ERR_NAME_NOT_RESOLVED"), []),
            (BrowserError("net::ERR_CERT_DATE_INVALID"), []),
            (BrowserError("net::ERR_CONNECTION_REFUSED"), []),
            (BrowserError("net::ERR_FAILED"), []),
            (BrowserTimeout("Timeout exceeded"), []),
            (BrowserError("net::ERR_CONNECTION_RESET"), ["Navigation denied"]),
        ]:
            browser = CloudflareBrowser("a" * 32, "synthetic-token")
            browser.page = Mock(goto=AsyncMock(side_effect=error))
            browser.blocked = blocked
            with patch("trustline.remote.asyncio.sleep", new_callable=AsyncMock) as wait:
                with self.assertRaises(type(error)):
                    await browser.navigate("https://ordinary.example/")
            browser.page.goto.assert_awaited_once()
            wait.assert_not_awaited()

    async def test_repeated_reset_stays_blocked_and_explains_failure_without_private_error_text(self):
        error = BrowserError("Page.goto: net::ERR_CONNECTION_RESET at https://ordinary.example/?token=secret-token")
        browser = CloudflareBrowser("a" * 32, "synthetic-token")
        browser.page = Mock(goto=AsyncMock(side_effect=error))
        browser.stage = "loading the site"
        browser.start = browser.navigate
        browser.close = AsyncMock()
        browser.observe = AsyncMock()
        model, jev = self.allowing_model(), Mock(assess_page=Mock())
        manager = ReviewManager(RemoteReviewer(model, lambda: browser, jev=jev))
        self.addCleanup(manager.close)
        with patch("trustline.remote.asyncio.sleep", new_callable=AsyncMock), \
                patch("trustline.remote.debug.log") as log:
            row = manager.start("https://ordinary.example/")
            await row.task
        self.assertEqual(browser.page.goto.await_count, 2)
        self.assertEqual(row.status, "inconclusive")
        self.assertIn("connection to the website was reset", row.reason)
        self.assertIn("remains blocked", row.reason)
        self.assertFalse(manager.allowed(row.url, "main_frame", "GET"))
        self.assertNotIn("secret-token", str(manager.snapshot(row.token)))
        self.assertNotIn("secret-token", str(log.call_args_list))
        event = next(call for call in log.call_args_list if call.args == ("cloud.error",))
        self.assertEqual(event.kwargs["code"], "ERR_CONNECTION_RESET")
        browser.observe.assert_not_awaited()
        model.action.assert_not_called()
        jev.assess_page.assert_not_called()
        browser.close.assert_awaited_once()

    async def test_browser_setup_errors_get_fixed_explanations(self):
        for stage, explanation in [
            ("connecting to the Cloudflare browser", "could not connect"),
            ("configuring the Cloudflare browser", "could not prepare"),
            ("reading the page", "could not read"),
        ]:
            browser = self.browser()
            browser.stage = stage
            browser.start.side_effect = BrowserError("Authorization: secret-token wss://private.example/")
            with self.assertRaises(RemoteError) as caught:
                await RemoteReviewer(self.allowing_model(), lambda: browser).review("https://ordinary.example/")
            self.assertIn(explanation, str(caught.exception))
            self.assertNotIn("secret-token", str(caught.exception))
            self.assertNotIn("private.example", str(caught.exception))
            browser.close.assert_awaited_once()

    def test_browser_error_code_keeps_only_the_network_code(self):
        self.assertEqual(browser_error_code(BrowserError(
            "net::ERR_CONNECTION_RESET at https://ordinary.example/?token=secret")), "ERR_CONNECTION_RESET")
        self.assertIsNone(browser_error_code(BrowserError("wss://private.example/?token=secret")))

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
