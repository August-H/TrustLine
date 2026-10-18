import contextlib
import io
import json
from http.client import IncompleteRead
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from trustline.inspection import (
    ApprovedSites, Inspector, JevClient, JevError, NoRedirects, Observation, lookalike_readings,
    normalize_origin,
)


class InspectionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.sites = ApprovedSites(Path(self.directory.name) / "approved.sqlite3")
        self.jev = Mock()
        self.jev.assess.return_value = 0.95
        self.inspector = Inspector(self.sites, self.jev)

    def tearDown(self):
        self.directory.cleanup()

    def inspect(self, url, **metadata):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            result = self.inspector.inspect({"url": url, **metadata})
        return result, output.getvalue()

    def test_approved_domains_and_subdomains_never_call_jev(self):
        for url in [
            "https://youtube.com", "https://www.youtube.com/watch?v=private",
            "https://WWW.YOUTUBE.COM./", "https://linkedin.com", "https://uk.linkedin.com/feed",
        ]:
            with self.subTest(url=url):
                result, output = self.inspect(url)
                self.assertEqual(result["status"], "skipped")
                self.assertEqual(output, "")
        self.jev.assess.assert_not_called()

    def test_lookalikes_userinfo_and_path_do_not_bypass_jev(self):
        for url in [
            "https://youtube.com.evil.example", "https://notyoutube.com",
            "https://notlinkedin.com", "https://youtube.com@evil.example",
            "https://evil.example/youtube.com", "https://evil.example/?next=https://linkedin.com",
        ]:
            with self.subTest(url=url):
                self.assertEqual(self.inspect(url)[0]["status"], "suspicious")
        self.assertEqual(self.jev.assess.call_count, 4)  # Three evil.example URLs share a cache key.

    def test_untrusted_page_context_cannot_exempt_an_unapproved_destination(self):
        result, output = self.inspect("https://cdn.example", page_url="https://www.youtube.com/watch",
                                      resource_type="script")
        self.assertEqual(result["status"], "suspicious")
        self.assertEqual(output, "suspicious website\n")
        self.jev.assess.assert_called_once()

    def test_navigation_away_does_not_inherit_approved_page(self):
        result, _ = self.inspect("https://evil.example", page_url="https://youtube.com",
                                 resource_type="main_frame")
        self.assertEqual(result["status"], "suspicious")
        self.jev.assess.assert_called_once()

    def test_local_addresses_are_not_sent_to_model(self):
        for url in ["http://localhost", "http://127.0.0.1", "https://192.168.1.1",
                    "http://[::1]", "http://printer.local", "http://intranet", "http://host.internal"]:
            with self.subTest(url=url):
                self.assertEqual(self.inspect(url)[0]["reason"], "local_address")
        self.jev.assess.assert_not_called()

    def test_page_context_is_not_used_as_a_local_address_exemption(self):
        result, _ = self.inspect("https://cdn.example", page_url="http://printer.local",
                                 resource_type="script")
        self.assertEqual(result["status"], "suspicious")
        self.jev.assess.assert_called_once()

    def test_suspicious_only_prints_exact_placeholder(self):
        result, output = self.inspect("https://evil.example")
        self.assertEqual(result["status"], "suspicious")
        self.assertEqual(output, "suspicious website\n")

    def test_threshold_and_uncertainty(self):
        for probability, status in [(0.8, "suspicious"), (0.79, "uncertain"),
                                    (0.5, "uncertain"), (0.2, "not_flagged"),
                                    (0.20000000000000004, "uncertain"), (0.1, "not_flagged")]:
            self.jev.assess.return_value = probability
            self.inspector.cache.clear()
            result, output = self.inspect("https://example.com")
            self.assertEqual(result["status"], status)
            self.assertEqual(bool(output), status == "suspicious")

    def test_cache_suppresses_repeated_model_calls_and_console_messages(self):
        self.inspect("https://evil.example/first")
        result, output = self.inspect("https://evil.example/second?token=private")
        self.assertTrue(result["cached"])
        self.assertEqual(output, "")
        self.jev.assess.assert_called_once()

    def test_approval_updates_override_cached_assessment(self):
        self.inspect("https://example.com")
        self.sites.add("example.com")
        self.assertEqual(self.inspect("https://example.com")[0]["status"], "skipped")
        self.jev.assess.assert_called_once()

    def test_revoking_seed_persists_after_reopening_database(self):
        self.sites.remove("youtube.com")
        reopened = ApprovedSites(self.sites.path)
        self.assertFalse(reopened.contains("youtube.com"))
        self.assertEqual(self.inspect("https://youtube.com")[0]["status"], "suspicious")

    def test_model_error_is_unscored_and_not_cached(self):
        self.jev.assess.side_effect = JevError("Jev connection failed or timed out")
        for _ in range(2):
            result, output = self.inspect("https://example.com")
            self.assertEqual(result["status"], "unscored")
            self.assertEqual(output, "")
        self.assertEqual(self.jev.assess.call_count, 2)

    def test_invalid_observations_do_not_reach_model(self):
        for data in [None, [], {"url": "file:///etc/passwd"}, {"url": "https://"},
                     {"url": "https://a.example:99999"}, {"url": "https://a.example\\@youtube.com"},
                     {"url": "https://a.example", "method": "GET\nsecret"},
                     {"url": "https://a.example", "resource_type": "secret-data"}]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.inspector.inspect(data)
        self.jev.assess.assert_not_called()

    def test_normalization_strips_secrets_and_handles_idna_and_ipv6(self):
        self.assertEqual(normalize_origin("https://user:password@EXAMPLE.com:443/private?q=secret#token"),
                         ("https://example.com", "example.com"))
        self.assertEqual(normalize_origin("https://bücher.example"),
                         ("https://xn--bcher-kva.example", "xn--bcher-kva.example"))
        self.assertEqual(normalize_origin("https://[2001:4860:4860::8888]:8443/path")[0],
                         "https://[2001:4860:4860::8888]:8443")

    def test_threshold_validation(self):
        for threshold in [float("nan"), float("inf"), -1, 0.4, 1.1]:
            with self.assertRaises(ValueError):
                Inspector(self.sites, self.jev, threshold=threshold)


class JevTests(unittest.TestCase):
    def setUp(self):
        self.client = JevClient("test-secret")
        self.observation = Observation.parse({
            "url": "https://user:secret@example.com/private?token=hidden#fragment",
            "page_url": "https://private-context.example", "resource_type": "script",
            "cookies": "secret-cookie", "headers": {"Authorization": "secret"},
        })

    def response(self, payload):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = json.dumps(payload).encode()
        self.client.opener = Mock()
        self.client.opener.open.return_value = response

    def answers(self, suspicious, lookalike=0.1):
        return {"answers": {"suspicious": {"type": "noul", "noul": suspicious},
                            "lookalike": {"type": "noul", "noul": lookalike}}}

    def test_official_contract_and_data_minimization(self):
        self.response({
            "model": "jev-1.13.0",
            **self.answers(0.9),
            "usage": {"input_tokens": 120, "output_tokens": 12},
        })
        self.assertEqual(self.client.assess(self.observation), 0.9)
        request = self.client.opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.typesafe.ai/v1/systemone")
        payload = json.loads(request.data)
        self.assertEqual(payload["model"], "jev-latest")
        self.assertEqual(set(payload["questions"]), {"suspicious", "lookalike"})
        for question in payload["questions"].values():
            self.assertEqual(question["type"], "noul")
            self.assertEqual(set(question["criteria"]), {"true", "false"})
        self.assertEqual(payload["questions"]["lookalike"]["instructions"]["readings"],
                         lookalike_readings("example.com"))
        self.assertEqual(request.get_header("Authorization"), "Bearer test-secret")
        self.assertEqual(request.get_header("Content-type"), "application/json")
        self.assertEqual(payload["state"], {
            "url_origin": "https://example.com", "hostname": "example.com", "method": "GET",
            "resource_type": "script", "uses_https": True, "has_punycode_label": False,
        })
        self.assertNotIn("secret", request.data.decode())
        self.assertNotIn("private-context", request.data.decode())

    def test_lookalike_answer_raises_the_probability(self):
        self.response(self.answers(0.05, lookalike=0.89))
        self.assertEqual(self.client.assess(self.observation), 0.89)

    def test_lookalike_readings_undo_character_substitutions(self):
        for hostname, reading in [("visu4lstudio.com", "visualstudio"), ("paypa1.com", "paypal"),
                                  ("linkedln.com", "linkedin"), ("githhub.com", "github"),
                                  ("rnicrosoft.com", "microsoft"), ("app1e-id.com", "apple-id")]:
            with self.subTest(hostname=hostname):
                self.assertIn(reading, lookalike_readings(hostname))
        self.assertNotIn("github", lookalike_readings("github.com"))
        self.assertEqual(lookalike_readings("8.8.8.8"), [])
        long_host = "l" * 60 + "1inkedin.example"
        self.assertLessEqual(len(lookalike_readings(long_host)), 24)
        self.assertIn("l" * 60 + "linkedin", lookalike_readings(long_host))

    def test_ip_origins_ask_only_the_main_question(self):
        self.response({"answers": {"suspicious": {"type": "noul", "noul": 0.3}}})
        observation = Observation.parse({"url": "https://8.8.8.8"})
        self.assertEqual(self.client.assess(observation), 0.3)
        payload = json.loads(self.client.opener.open.call_args.args[0].data)
        self.assertEqual(set(payload["questions"]), {"suspicious"})

    def test_invalid_probabilities_are_rejected(self):
        for value in [True, "0.9", None, -0.1, 1.1, float("nan"), float("inf")]:
            for answers in [self.answers(value), self.answers(0.1, lookalike=value)]:
                self.response(answers)
                with self.subTest(value=value), self.assertRaises(JevError):
                    self.client.assess(self.observation)

    def test_missing_or_wrong_answers_are_rejected(self):
        for payload in [{}, [], {"answers": {"suspicious": {"type": "choice", "noul": 0.9}}},
                        {"answers": {"suspicious": {"type": "noul", "noul": 0.9}}}]:
            self.response(payload)
            with self.assertRaises(JevError):
                self.client.assess(self.observation)

    def test_timeouts_and_http_errors_do_not_leak_response_details(self):
        self.client.opener = Mock()
        for error in [TimeoutError("secret URL"), URLError("secret"),
                      HTTPError("https://secret.example", 401, "secret", {}, None)]:
            self.client.opener.open.side_effect = error
            with self.assertRaises(JevError) as raised:
                self.client.assess(self.observation)
            self.assertNotIn("secret", str(raised.exception))

    def test_missing_api_key_never_makes_a_request(self):
        self.client.api_key = None
        self.client.opener = Mock()
        with self.assertRaises(JevError):
            self.client.assess(self.observation)
        self.client.opener.open.assert_not_called()

    def test_redirects_do_not_forward_credentials(self):
        self.assertIsNone(NoRedirects().redirect_request(None, None, 302, "", {}, "https://other.example"))

    def test_truncated_http_response_becomes_a_private_unscored_error(self):
        self.response({})
        self.client.opener.open.return_value.read.side_effect = IncompleteRead(b"private response", 100)
        with self.assertRaises(JevError) as raised:
            self.client.assess(self.observation)
        self.assertNotIn("private response", str(raised.exception))

    def test_rate_limits_back_off_across_requests_and_recover(self):
        self.response(self.answers(0.1))
        valid_response = self.client.opener.open.return_value
        self.client.opener.open.side_effect = [
            HTTPError("https://api.typesafe.ai/v1/systemone", 429, "rate limit", {}, None),
            HTTPError("https://api.typesafe.ai/v1/systemone", 529, "overload", {}, None),
            valid_response,
        ]
        with patch("trustline.inspection.time.monotonic", return_value=0) as clock:
            for now in [0, 0.5, 1, 2]:
                clock.return_value = now
                with self.assertRaises(JevError):
                    self.client.assess(self.observation)
            self.assertEqual(self.client.opener.open.call_count, 2)
            clock.return_value = 3
            self.assertEqual(self.client.assess(self.observation), 0.1)
            self.assertEqual(self.client.opener.open.call_count, 3)

    def test_rate_limit_respects_retry_after_header(self):
        self.client.opener = Mock()
        self.client.opener.open.side_effect = HTTPError(
            "https://api.typesafe.ai/v1/systemone", 429, "rate limit", {"Retry-After": "5"}, None,
        )
        with patch("trustline.inspection.time.monotonic", return_value=0) as clock:
            with self.assertRaises(JevError):
                self.client.assess(self.observation)
            clock.return_value = 4
            with self.assertRaises(JevError):
                self.client.assess(self.observation)
            self.client.opener.open.assert_called_once()


if __name__ == "__main__":
    unittest.main()
