import asyncio
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock

from tornado.testing import AsyncHTTPTestCase

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from trustline.api import ExtensionAPI, application, reviewed_score
from trustline.approvals import ReviewedPages
from trustline.inspection import ApprovedSites, Inspector, JevError
from trustline.proxy import InspectionProxy
from trustline.reviews import ReviewManager


def fixture(directory, probability=0.27, verdict="allow"):
    database = Path(directory) / "approved.sqlite3"
    jev = Mock(assess=Mock(return_value=(probability, 0.0)))
    reviewer = Mock(review=AsyncMock(return_value={
        "verdict": verdict, "reason": "Remote browser evidence", "evidence": ["Rendered page checked"]}))
    manager = ReviewManager(reviewer, approvals=ReviewedPages(database))
    proxy = InspectionProxy(Inspector(ApprovedSites(database), jev, threshold=0.9, emit=Mock()), manager)
    return proxy, jev, reviewer


class ExtensionAPITests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.proxy, self.jev, self.reviewer = fixture(self.directory.name)
        self.api = ExtensionAPI(self.proxy)

    async def asyncTearDown(self):
        self.proxy.done()
        self.proxy.executor.shutdown(wait=True)
        self.directory.cleanup()

    async def finish_review(self, result):
        row = self.proxy.reviews.get(result["review"]["token"])
        if row.task:
            await row.task
        return self.proxy.reviews.snapshot(row.token)

    async def test_verified_domain_and_subdomain_are_100_and_skip_both_models(self):
        for mode in ["quick", "deep"]:
            result = await self.api.analyze("https://www.youtube.com/watch?v=private#video", mode)
            self.assertEqual(result["score"], 100)
            self.assertTrue(result["verified"])
            self.assertEqual(result["score_source"], "verified_database")
            self.assertNotIn("review", result)
        self.jev.assess.assert_not_called()
        self.reviewer.review.assert_not_awaited()

    async def test_nonverified_score_is_inverse_jev_probability_and_only_metadata_reaches_jev(self):
        result = await self.api.analyze("https://youtube.com.attacker.example/private?token=secret", "quick")
        self.assertEqual(result["score"], 73)
        self.assertEqual(result["jev_probability"], 0.27)
        self.assertEqual(result["jev_status"], "uncertain")
        self.assertFalse(result["verified"])
        observation = self.jev.assess.call_args.args[0]
        self.assertEqual(observation.origin, "https://youtube.com.attacker.example")
        self.assertNotIn("secret", str(observation.model_state()))
        self.reviewer.review.assert_not_awaited()

    async def test_jev_status_survives_a_cloud_verdict(self):
        self.jev.assess.return_value = (0.95, 0.0)
        result = await self.api.analyze("https://ordinary.example/", "quick")
        self.assertEqual(result["jev_status"], "suspicious")
        self.assertEqual(result["verdict"], "dangerous")
        result = await self.api.analyze("https://ordinary.example/", "deep")
        result["review"] = await self.finish_review(result)
        self.api.apply_review(result)
        self.assertEqual(result["verdict"], "safe")
        self.assertEqual(result["jev_status"], "suspicious")

    async def test_unavailable_jev_does_not_invent_a_score_even_when_cloud_allows(self):
        self.jev.assess.side_effect = JevError("Jev unavailable")
        result = await self.api.analyze("https://ordinary.example/", "deep")
        result["review"] = await self.finish_review(result)
        self.api.apply_review(result)
        self.assertEqual(result["verdict"], "safe")
        self.assertIsNone(result["score"])

    async def test_deep_scan_calls_remote_and_persists_page_without_changing_jev_score(self):
        result = await self.api.analyze("https://ordinary.example/article", "deep")
        self.assertEqual(result["review"]["status"], "pending")
        self.assertFalse(self.proxy.reviews.allowed("https://ordinary.example/article", "main_frame", "GET"))
        result["review"] = await self.finish_review(result)
        self.api.apply_review(result)
        self.assertEqual(result["verdict"], "safe")
        self.assertEqual(result["score"], 73)
        self.reviewer.review.assert_awaited_once_with("https://ordinary.example/article")
        self.assertTrue(ReviewedPages(self.proxy.inspector.sites.path).contains("https://ordinary.example/article"))
        self.assertFalse(self.proxy.inspector.sites.contains("ordinary.example"))
        next_result = await self.api.analyze("https://ordinary.example/article", "quick")
        self.assertEqual(next_result["score"], 73)
        self.assertEqual(next_result["review"]["status"], "allow")

    async def test_blocking_cloud_verdict_caps_a_high_url_score(self):
        self.reviewer.review.return_value["verdict"] = "block"
        result = await self.api.analyze("https://ordinary.example/", "deep")
        result["review"] = await self.finish_review(result)
        self.api.apply_review(result)
        self.assertEqual(result["verdict"], "dangerous")
        self.assertEqual(result["score"], 39)
        self.assertFalse(self.proxy.reviews.allowed("https://ordinary.example/", "main_frame", "GET"))

    async def test_page_probability_lowers_the_score_for_later_quick_scans(self):
        self.reviewer.review.return_value["page_probability"] = 0.6
        result = await self.api.analyze("https://ordinary.example/", "deep")
        review = await self.finish_review(result)
        self.assertEqual(review["page_probability"], 0.6)
        later = await self.api.analyze("https://ordinary.example/", "quick")
        self.assertEqual(later["verdict"], "safe")
        self.assertEqual(later["score"], 40)

    def test_reviewed_score_combines_url_page_and_block(self):
        for score, page, status, expected in [(73, None, "allow", 73), (73, 0.6, "allow", 40),
                                              (20, 0.1, "allow", 20), (None, 0.25, "inconclusive", 75),
                                              (92, None, "block", 39), (92, 0.05, "block", 39),
                                              (12, None, "block", 12), (None, None, "block", None)]:
            with self.subTest(score=score, page=page, status=status):
                self.assertEqual(reviewed_score(score, {"status": status, "page_probability": page}), expected)

    async def test_explicit_deep_scan_repeats_completed_review_but_joins_pending_proxy_review(self):
        url = "https://ordinary.example/"
        first = self.proxy.reviews.start(url)
        result = await self.api.analyze(url, "deep")
        self.assertEqual(result["review"]["token"], first.token)
        await self.finish_review(result)
        old_task = first.task
        second = await self.api.analyze(url, "deep")
        self.assertEqual(result["review"]["token"], second["review"]["token"])
        self.assertIsNot(old_task, self.proxy.reviews.get(first.token).task)
        self.assertFalse(self.proxy.reviews.allowed(url, "main_frame", "GET"))
        await self.finish_review(second)
        self.assertEqual(self.reviewer.review.await_count, 2)

    async def test_held_proxy_page_resolves_to_original_target(self):
        row = self.proxy.reviews.start("https://ordinary.example/article")
        result = await self.api.analyze(f"https://blocked.example.com/_trustline/check/{row.token}", "deep")
        self.assertEqual(result["target_url"], row.url)
        self.assertEqual(result["review"]["token"], row.token)
        await self.finish_review(result)

    async def test_query_withheld_and_missing_cloud_configuration_are_inconclusive(self):
        result = await self.api.analyze("https://ordinary.example/article?token=private", "deep")
        review = await self.finish_review(result)
        self.assertEqual(review["status"], "inconclusive")
        self.reviewer.review.assert_awaited_once_with("https://ordinary.example/article")
        self.proxy.reviews.reviewer = None
        result = await self.api.analyze("https://ordinary.example/different", "deep")
        self.assertEqual(result["review"]["status"], "inconclusive")


class ExtensionHTTPTests(AsyncHTTPTestCase):
    def get_app(self):
        self.directory = tempfile.TemporaryDirectory()
        self.proxy, self.jev, self.reviewer = fixture(self.directory.name)
        return application(ExtensionAPI(self.proxy))

    def tearDown(self):
        self.proxy.done()
        self.proxy.executor.shutdown(wait=True)
        super().tearDown()
        self.directory.cleanup()

    def post(self, value, **headers):
        return self.fetch("/v1/analyze", method="POST", body=json.dumps(value),
                          headers={"Content-Type": "application/json", **headers})

    def test_health_and_verified_post_through_http(self):
        self.assertEqual(json.loads(self.fetch("/health").body)["status"], "ok")
        response = self.post({"url": "https://linkedin.com/", "mode": "deep"},
                             Origin="chrome-extension://" + "a" * 32)
        self.assertEqual(response.code, 200)
        self.assertEqual(json.loads(response.body)["score"], 100)
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_website_origins_rebinding_and_form_posts_are_rejected(self):
        for headers in [{"Origin": "https://attacker.example"}, {"Origin": "null"},
                        {"Host": "attacker.example"}]:
            self.assertEqual(self.post({"url": "https://ordinary.example/", "mode": "deep"}, **headers).code, 403)
        response = self.fetch("/v1/analyze", method="POST", body="url=https://ordinary.example/",
                              headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(response.code, 415)
        self.jev.assess.assert_not_called()
        self.reviewer.review.assert_not_awaited()

    def test_invalid_urls_modes_and_review_tokens(self):
        for body in [[], {"url": "file:///etc/passwd"}, {"url": "https://example.com", "mode": "bad"},
                     {"url": "https://blocked.example.com/"}, {"url": "https://example.com", "mode": []}]:
            self.assertEqual(self.post(body).code, 400)
        self.assertEqual(self.fetch("/v1/reviews/unknown-token").code, 404)

    def test_deep_scan_http_poll_returns_actual_remote_result(self):
        response = self.post({"url": "https://ordinary.example/", "mode": "deep"})
        result = json.loads(response.body)
        self.assertEqual(result["score"], 73)
        response = self.fetch("/v1/reviews/" + result["review"]["token"])
        self.assertEqual(json.loads(response.body)["status"], "allow")
        self.reviewer.review.assert_awaited_once_with("https://ordinary.example/")
