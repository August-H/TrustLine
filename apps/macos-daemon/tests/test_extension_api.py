import asyncio
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock

from tornado.testing import AsyncHTTPTestCase

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from trustline.api import ExtensionAPI, application, jev_confidence, reviewed_score
from trustline.approvals import ReviewedPages
from trustline.inspection import ApprovedSites, Inspector, JevError
from trustline.proxy import InspectionProxy
from trustline.reviews import ReviewManager


def fixture(directory, probability=0.27, verdict="allow"):
    database = Path(directory) / "approved.sqlite3"
    jev = Mock(assess=Mock(return_value=(probability, 0.0, 1.0)))
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
        self.jev.assess.return_value = (0.95, 0.0, 1.0)
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
                                              (20, 0.1, "allow", 20), (None, 0.25, "inconclusive", None),
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

    def low_score(self, probability=0.5):
        # 50: below the passing score, so a navigation check goes to the cloud.
        self.jev.assess.return_value = (probability, 0.0, 1.0)
        self.proxy.inspector.cache.clear()

    async def test_navigation_check_starts_one_cloud_review_and_reuses_it(self):
        self.low_score()
        url = "https://ordinary.example/article#section"
        result = await self.api.analyze(url, "navigate")
        self.assertEqual(result["review"]["status"], "pending")
        await self.finish_review(result)
        self.reviewer.review.assert_awaited_once_with("https://ordinary.example/article")
        again = await self.api.analyze(url, "navigate")
        self.assertEqual(again["review"]["status"], "allow")
        self.assertEqual(again["verdict"], "safe")
        self.assertEqual(self.reviewer.review.await_count, 1)

    async def test_navigation_check_joins_a_pending_review_without_restarting_it(self):
        self.low_score()
        url = "https://ordinary.example/"
        first = self.proxy.reviews.start(url)
        result = await self.api.analyze(url, "navigate")
        self.assertEqual(result["review"]["token"], first.token)
        await self.finish_review(result)
        self.assertEqual(self.reviewer.review.await_count, 1)

    async def test_navigation_check_skips_the_cloud_for_a_page_approved_earlier(self):
        url = "https://ordinary.example/article"
        ReviewedPages(self.proxy.inspector.sites.path).approve(url)
        for probability in [0.5, 0.27]:  # cloud band and unsure band
            self.low_score(probability)
            result = await self.api.analyze(url, "navigate")
            self.assertEqual(result["review"]["status"], "allow")
            self.assertEqual(result["verdict"], "safe")
            self.assertNotIn("unsure", result)
        self.reviewer.review.assert_not_awaited()

    async def test_navigation_block_caps_score_and_inconclusive_is_unscored(self):
        self.low_score()
        self.reviewer.review.return_value["verdict"] = "block"
        result = await self.api.analyze("https://ordinary.example/", "navigate")
        result["review"] = await self.finish_review(result)
        self.api.apply_review(result, keep_url_verdict=True)
        self.assertEqual((result["verdict"], result["score"]), ("dangerous", 39))
        self.reviewer.review.return_value["verdict"] = "inconclusive"
        result = await self.api.analyze("https://ordinary.example/other", "navigate")
        result["review"] = await self.finish_review(result)
        self.api.apply_review(result, keep_url_verdict=True)
        self.assertEqual((result["verdict"], result["score"]), ("suspicious", None))
        self.assertEqual(result["jev_status"], "uncertain")

    async def test_failed_deep_scan_hides_address_scores_and_percentages_in_later_results(self):
        self.reviewer.review.side_effect = RuntimeError("Unavailable")
        for index, probability in enumerate([0.09, 0.91]):
            self.low_score(probability)
            url = f"https://ordinary.example/failed-{index}"
            pending = await self.api.analyze(url, "deep")
            await self.finish_review(pending)
            for mode in ["quick", "navigate"]:
                result = await self.api.analyze(url, mode)
                self.assertEqual(result["review"]["status"], "inconclusive")
                self.assertEqual(result["assessment"], "undetermined")
                self.assertIsNone(result["score"])
                self.assertIsNone(result["score_source"])
                self.assertNotIn("%", " ".join(result["reasons"]))
                self.assertFalse(self.proxy.reviews.allowed(url, "main_frame", "GET"))

    def test_jev_confidence_is_the_noul_distance_from_even(self):
        for probability, expected in [(0.5, 0.0), (0.07, 0.86), (0.95, 0.9), (0.0, 1.0), (None, None)]:
            with self.subTest(probability=probability):
                self.assertEqual(jev_confidence(probability), expected)

    async def test_navigation_trusts_a_confident_pass_outright(self):
        for probability, score in [(0.07, 93), (0.05, 95)]:
            self.low_score(probability)
            result = await self.api.analyze("https://ordinary.example/", "navigate")
            self.assertEqual((result["score"], result["verdict"]), (score, "safe"))
            self.assertGreaterEqual(result["jev_confidence"], 0.85)
            self.assertNotIn("review", result)
            self.assertNotIn("unsure", result)
        self.reviewer.review.assert_not_awaited()

    async def test_navigation_blocks_a_confident_flag_without_a_cloud_check(self):
        self.low_score(0.95)
        result = await self.api.analyze("https://ordinary.example/", "navigate")
        self.assertEqual((result["score"], result["verdict"], result["jev_confidence"]), (5, "dangerous", 0.9))
        self.assertNotIn("review", result)
        self.reviewer.review.assert_not_awaited()

    async def test_navigation_passes_but_flags_a_low_confidence_pass(self):
        # A passing score is not enough: 90 means p = 0.1, only 80% confident.
        for index, (probability, score) in enumerate([(0.3, 70), (0.16, 84), (0.1, 90)]):
            self.low_score(probability)
            result = await self.api.analyze(f"https://ordinary.example/{index}", "navigate")
            self.assertEqual((result["score"], result["verdict"]), (score, "safe"))
            self.assertLess(result["jev_confidence"], 0.85)
            self.assertTrue(result["unsure"])
            self.assertIn("confident", result["reasons"][-1])
            self.assertNotIn("review", result)
        self.reviewer.review.assert_not_awaited()

    async def test_navigation_sends_an_unsure_failing_score_to_the_cloud(self):
        for index, probability in enumerate([0.31, 0.5, 0.9]):  # 69, 50 and 10, all under 85% confident
            self.low_score(probability)
            result = await self.api.analyze(f"https://ordinary.example/{index}", "navigate")
            await self.finish_review(result)
        self.assertEqual(self.reviewer.review.await_count, 3)

    def money_site(self, probability, recognized):
        self.jev.assess.return_value = (probability, 0.97, recognized)
        self.proxy.inspector.cache.clear()

    async def test_an_unrecognized_money_site_is_cloud_checked_despite_a_confident_score(self):
        # zingoptions.com: address score 92, a trading site Jev does not recognize.
        self.money_site(0.08, 0.1)
        result = await self.api.analyze("https://zingoptions.com/", "navigate")
        self.assertEqual(result["score"], 92)
        self.assertEqual(result["review"]["status"], "pending")
        self.assertIn("doesn't recognize", " ".join(result["reasons"]))
        self.reviewer.review.return_value["verdict"] = "block"
        result["review"] = await self.finish_review(result)
        self.api.apply_review(result, keep_url_verdict=True)
        self.assertEqual((result["verdict"], result["score"]), ("dangerous", 39))

    async def test_a_cloud_approved_unrecognized_money_site_shows_no_prompt(self):
        self.money_site(0.03, 0.1)
        await self.finish_review(await self.api.analyze("https://smallbroker.example/", "navigate"))
        again = await self.api.analyze("https://smallbroker.example/", "navigate")
        self.assertEqual((again["verdict"], again["review"]["status"]), ("safe", "allow"))
        self.assertNotIn("unsure", again)

    async def test_a_recognized_money_site_follows_the_confidence_rules(self):
        self.money_site(0.03, 0.95)
        result = await self.api.analyze("https://bigbank.example/", "navigate")
        self.assertEqual((result["verdict"], result["recognized_probability"]), ("safe", 0.95))
        self.assertNotIn("review", result)
        self.assertNotIn("unsure", result)
        self.reviewer.review.assert_not_awaited()

    async def test_a_confidently_fake_money_site_goes_straight_to_the_warning(self):
        self.money_site(0.97, 0.05)
        result = await self.api.analyze("https://fake-broker.example/", "navigate")
        self.assertEqual(result["verdict"], "dangerous")
        self.assertNotIn("review", result)
        self.reviewer.review.assert_not_awaited()

    async def test_an_unrecognized_money_site_is_held_when_the_cloud_check_cannot_run(self):
        self.proxy.reviews.reviewer = None
        self.money_site(0.03, 0.1)
        result = await self.api.analyze("https://smallbroker.example/", "navigate")
        self.assertEqual(result["verdict"], "suspicious")
        self.assertTrue(result["cloud_required"])
        self.assertNotIn("unsure", result)
        self.assertNotIn("review", result)
        self.assertEqual(result["assessment"], "undetermined")
        self.assertIsNone(result["score"])
        self.assertNotIn("%", " ".join(result["reasons"]))

    async def test_an_unrecognized_money_site_is_held_when_the_cloud_check_cannot_decide(self):
        self.money_site(0.07, 0.03)  # edgetrustcapital.com: score 93, money, unrecognized
        self.reviewer.review.return_value["verdict"] = "inconclusive"
        url = "https://edgetrustcapital.example/"
        pending = await self.api.analyze(url, "navigate")
        self.assertTrue(pending["cloud_required"])
        await self.finish_review(pending)
        result = await self.api.analyze(url, "navigate")
        self.assertEqual((result["review"]["status"], result["verdict"]), ("inconclusive", "suspicious"))

    async def test_holding_an_unchecked_money_site_never_softens_a_dangerous_verdict(self):
        self.proxy.reviews.reviewer = None
        self.money_site(0.89, 0.04)  # blackpinkofficial.store: flagged, 78% confident
        result = await self.api.analyze("https://blackpinkofficial.example/", "navigate")
        self.assertEqual(result["verdict"], "dangerous")
        self.assertTrue(result["cloud_required"])

    async def test_a_recognized_money_site_still_opens_with_the_prompt_without_cloud_review(self):
        self.proxy.reviews.reviewer = None
        self.money_site(0.2, 0.95)
        result = await self.api.analyze("https://bigbank.example/", "navigate")
        self.assertEqual(result["verdict"], "safe")
        self.assertTrue(result["unsure"])
        self.assertNotIn("cloud_required", result)

    async def test_unsure_is_only_reported_for_navigation(self):
        for mode in ["quick", "deep"]:
            result = await self.api.analyze("https://ordinary.example/", mode)
            self.assertNotIn("unsure", result)
            if mode == "deep":
                await self.finish_review(result)

    async def test_navigation_with_a_high_score_still_honors_an_earlier_block(self):
        url = "https://ordinary.example/vote"
        self.reviewer.review.return_value["verdict"] = "block"
        await self.finish_review(await self.api.analyze(url, "deep"))
        for probability in [0.07, 0.2]:  # confident and unsure bands
            self.low_score(probability)
            result = await self.api.analyze(url, "navigate")
            self.assertEqual((result["verdict"], result["score"]), ("dangerous", 39))
            self.assertNotIn("unsure", result)
        self.assertEqual(self.reviewer.review.await_count, 1)

    async def test_navigation_without_cloud_configuration_is_an_address_check(self):
        self.proxy.reviews.reviewer = None
        self.low_score()
        result = await self.api.analyze("https://ordinary.example/", "navigate")
        self.assertNotIn("review", result)
        self.assertEqual(result["score"], 50)
        verified = await self.api.analyze("https://linkedin.com/", "navigate")
        self.assertNotIn("review", verified)
        self.assertNotIn("unsure", verified)
        self.assertEqual(verified["score"], 100)

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

    def test_navigate_mode_is_accepted_over_http(self):
        self.jev.assess.return_value = (0.5, 0.0, 1.0)
        response = self.post({"url": "https://ordinary.example/", "mode": "navigate"})
        self.assertEqual(response.code, 200)
        self.assertIn(json.loads(response.body)["review"]["status"], {"pending", "allow"})

    def test_deep_scan_http_poll_returns_actual_remote_result(self):
        response = self.post({"url": "https://ordinary.example/", "mode": "deep"})
        result = json.loads(response.body)
        self.assertEqual(result["score"], 73)
        response = self.fetch("/v1/reviews/" + result["review"]["token"])
        self.assertEqual(json.loads(response.body)["status"], "allow")
        self.reviewer.review.assert_awaited_once_with("https://ordinary.example/")


class ExtensionDebugHTTPTests(AsyncHTTPTestCase):
    def get_app(self):
        self.directory = tempfile.TemporaryDirectory()
        self.proxy, self.jev, self.reviewer = fixture(self.directory.name)
        self.api = ExtensionAPI(self.proxy)
        return application(self.api, debug_state=True)

    def tearDown(self):
        self.proxy.done()
        self.proxy.executor.shutdown(wait=True)
        super().tearDown()
        self.directory.cleanup()

    def test_debug_state_lists_settings_jev_cache_and_reviews(self):
        self.fetch("/v1/analyze", method="POST", body=json.dumps({"url": "https://ordinary.example/", "mode": "deep"}),
                   headers={"Content-Type": "application/json"})
        state = json.loads(self.fetch("/v1/debug/state").body)
        self.assertEqual(state["settings"]["navigation_confidence"], 0.85)
        self.assertEqual(state["settings"]["reasoning_effort"], "high")
        self.assertEqual(state["jev"]["recent"][0]["origin"], "https://ordinary.example")
        self.assertEqual(state["jev"]["recent"][0]["probability"], 0.27)
        self.assertEqual(state["reviews"]["total"], 1)
        self.assertEqual(state["reviews"]["recent"][0]["url"], "https://ordinary.example/")

    def test_debug_state_is_loopback_and_extension_only_like_every_route(self):
        self.assertEqual(self.fetch("/v1/debug/state", headers={"Origin": "https://attacker.example"}).code, 403)


class ExtensionDebugOffTests(AsyncHTTPTestCase):
    def get_app(self):
        self.directory = tempfile.TemporaryDirectory()
        self.proxy, _, _ = fixture(self.directory.name)
        return application(ExtensionAPI(self.proxy))

    def tearDown(self):
        self.proxy.done()
        self.proxy.executor.shutdown(wait=True)
        super().tearDown()
        self.directory.cleanup()

    def test_debug_state_does_not_exist_unless_debug_mode_is_on(self):
        self.assertEqual(self.fetch("/v1/debug/state").code, 404)
