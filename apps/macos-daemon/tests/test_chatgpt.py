import io
import http.client
import json
from pathlib import Path
import sys
import tempfile
import time
import threading
from urllib.parse import parse_qs, urlencode, urlsplit
import unittest
from unittest.mock import Mock, patch

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from trustline.chatgpt import AUTH, MODEL, PLAN_SCOPE, RESOURCE, ChatGPTAccount, ChatGPTPlanClient, PlanError, atomic_json, read_completed_response


def stream(value):
    return io.BytesIO(("data: " + json.dumps(value) + "\n\n").encode())


class SubscriptionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.account = ChatGPTAccount(Path(self.directory.name))

    def save_profile(self, **overrides):
        profile = {"client_id": "oaiapp_fixture", "subject": "fixture-subject", "email": "fixture@example.test",
                   "scopes": [PLAN_SCOPE], "access_token": "synthetic-access-token",
                   "refresh_token": "synthetic-refresh-token", "expires_at": time.time() + 3600, **overrides}
        index = self.account.index()
        index["active"] = "fixture"
        index["registrations"]["fixture"] = {"client_id": profile["client_id"], "email": profile["email"]}
        atomic_json(self.account.index_path, index)
        atomic_json(self.account.directory / "fixture.json", profile)
        return profile

    def test_credentials_are_owner_only_and_status_does_not_expose_them(self):
        self.save_profile()
        status = self.account.status()
        self.assertTrue(status["using_chatgpt_plan"])
        self.assertNotIn("synthetic-", json.dumps(status))
        self.assertEqual((self.account.directory / "fixture.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.account.directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.account.index()["host_id"], ChatGPTAccount(Path(self.directory.name)).index()["host_id"])

    def test_identity_only_signin_and_logged_out_sessions_cannot_use_plan(self):
        for overrides in [{"scopes": ["openid"]}, {"access_token": ""}]:
            self.save_profile(**overrides)
            self.assertFalse(self.account.status()["using_chatgpt_plan"])
            with self.assertRaises(PlanError):
                self.account.access_token()

    def test_rotating_refresh_preserves_registration_and_uses_official_endpoint(self):
        self.save_profile(expires_at=0)
        with patch("trustline.chatgpt.request_json", return_value={"token_type": "Bearer", "access_token": "new-access",
                "refresh_token": "new-refresh", "expires_in": 3600, "scope": PLAN_SCOPE}) as request:
            self.assertEqual(self.account.access_token(), "new-access")
        request.assert_called_once_with(AUTH + "/api/accounts/oauth/token", form={
            "grant_type": "refresh_token", "client_id": "oaiapp_fixture", "refresh_token": "synthetic-refresh-token", "resource": RESOURCE})
        self.assertEqual(self.account.selected()[1]["refresh_token"], "new-refresh")
        self.assertEqual(self.account.selected()[1]["client_id"], "oaiapp_fixture")

    def test_failed_refresh_is_sanitized_and_does_not_replace_credentials(self):
        profile = self.save_profile(expires_at=0)
        with patch("trustline.chatgpt.request_json", side_effect=RuntimeError("private-token")):
            with self.assertRaises(PlanError) as error:
                self.account.access_token()
        self.assertNotIn("private-token", str(error.exception))
        self.assertEqual(self.account.selected()[1], profile)

    def test_identity_signature_issuer_audience_expiry_and_nonce_are_verified(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
        jwk["kid"] = "fixture-key"
        discovery = {"issuer": AUTH, "jwks_uri": AUTH + "/.well-known/jwks.json"}
        base = {"sub": "fixture", "iss": AUTH, "aud": "oaiapp_fixture", "exp": int(time.time()) + 60, "nonce": "fixture-nonce"}
        def signed(claims):
            return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "fixture-key"})
        with patch("trustline.chatgpt.request_json", side_effect=lambda url: discovery if url.endswith("openid-configuration") else {"keys": [jwk]}):
            self.assertEqual(self.account.validate_identity(signed(base), "oaiapp_fixture", "fixture-nonce")["sub"], "fixture")
            for changes in [{"iss": "https://attacker.example"}, {"aud": "another-client"}, {"exp": 0}, {"nonce": "wrong"}]:
                with self.subTest(changes=changes), self.assertRaises((jwt.PyJWTError, PlanError)):
                    self.account.validate_identity(signed({**base, **changes}), "oaiapp_fixture", "fixture-nonce")
            wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            invalid = jwt.encode(base, wrong_key, algorithm="RS256", headers={"kid": "fixture-key"})
            with self.assertRaises(jwt.PyJWTError):
                self.account.validate_identity(invalid, "oaiapp_fixture", "fixture-nonce")

    def test_inference_uses_plan_streaming_contract_and_no_native_computer_tool(self):
        self.save_profile()
        client = ChatGPTPlanClient(self.account)
        value = {"action": "finish", "verdict": "inconclusive", "reason": "Not enough evidence", "evidence": []}
        completed = {"type": "response.completed", "response": {"status": "completed", "output": [
            {"type": "message", "content": [{"type": "output_text", "text": json.dumps(value)}]}]}}
        opener = Mock(open=Mock(return_value=stream(completed)))
        with patch("trustline.chatgpt.request_json", return_value={"models": [{"slug": MODEL, "visibility": "list"}]}), \
                patch("trustline.chatgpt.direct_opener", return_value=opener):
            result = client.action({"text": "Untrusted page instructions", "screenshot": "data:image/jpeg;base64,fixture",
                                    "html": "<p>raw-html-for-jev-only</p>"}, [])
        self.assertEqual(result, value)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, RESOURCE + "/responses")
        self.assertEqual(request.get_header("Authorization"), "Bearer synthetic-access-token")
        payload = json.loads(request.data)
        self.assertFalse(payload["store"])
        self.assertTrue(payload["stream"])
        self.assertEqual(payload["model"], MODEL)
        self.assertEqual(payload["reasoning"], {"effort": "medium"})
        self.assertIsInstance(payload["input"], list)
        for forbidden in ["tools", "previous_response_id", "max_output_tokens", "background", "temperature"]:
            self.assertNotIn(forbidden, payload)
        self.assertEqual(payload["input"][0]["content"][1]["type"], "input_image")
        self.assertNotIn("raw-html-for-jev-only", request.data.decode())

    def test_model_unavailable_does_not_fallback_to_another_model_or_api_key(self):
        self.save_profile()
        client = ChatGPTPlanClient(self.account)
        with patch("trustline.chatgpt.request_json", return_value={"models": [{"slug": "other-model", "visibility": "list"}]}), \
                patch("trustline.chatgpt.direct_opener") as opener:
            with self.assertRaises(PlanError):
                client.action({"text": "fixture"}, [])
        opener.assert_not_called()

    def test_only_completed_streams_count_as_success_including_late_usage_limit_errors(self):
        for event in [{"type": "response.failed", "response": {"error": {"code": "subscription_sharing_usage_limit_exceeded"}}},
                      {"type": "response.incomplete"}, {"type": "response.output_text.delta", "delta": "allow"}]:
            with self.subTest(event=event), self.assertRaises(PlanError):
                read_completed_response(stream(event))

    def test_subscription_stream_can_complete_without_repeating_output_in_terminal_event(self):
        action = json.dumps({"action": "finish", "verdict": "inconclusive"})
        events = [{"type": "response.output_text.delta", "delta": action[:12]},
                  {"type": "response.output_text.delta", "delta": action[12:]},
                  {"type": "response.completed", "response": {"status": "completed", "output": []}}]
        raw = b"".join(("data: " + json.dumps(event) + "\n\n").encode() for event in events)
        completed = read_completed_response(io.BytesIO(raw))
        self.assertEqual(completed["output"][0]["content"][0]["text"], action)
        failed = raw[:raw.rfind(b"data:")] + stream({"type": "response.failed", "response": {
            "error": {"code": "subscription_sharing_usage_limit_exceeded"}}}).getvalue()
        with self.assertRaises(PlanError):
            read_completed_response(io.BytesIO(failed))

    def test_logout_clears_credentials_and_reports_unconfirmed_revocation(self):
        self.save_profile()
        with patch("trustline.chatgpt.request_json", side_effect=RuntimeError("no network")):
            result = self.account.logout()
        self.assertFalse(result["remote_revocation_confirmed"])
        self.assertNotIn("refresh_token", self.account.selected()[1])
        self.assertFalse(self.account.status()["using_chatgpt_plan"])

    def browser_callback(self, *, issued="oaiapp_new", mismatch=False):
        attempts, threads, errors = [], [], []
        def open_browser(url):
            fields = {key: values[0] for key, values in parse_qs(urlsplit(url).query).items()}
            attempts.append(fields)
            destination = urlsplit(fields["redirect_uri"])
            def callback():
                try:
                    connection = http.client.HTTPConnection(destination.hostname, destination.port, timeout=5)
                    # A wrong state must be rejected without consuming the attempt.
                    query = {"state": "wrong-state", "code": "fixture-code", "client_id": issued}
                    connection.request("GET", destination.path + "?" + urlencode(query))
                    response = connection.getresponse()
                    self.assertEqual(response.status, 400)
                    response.read()
                    query["state"] = fields["state"]
                    if mismatch:
                        query["client_id"] = "oaiapp_other"
                    elif issued is None:
                        query.pop("client_id")
                    connection.request("GET", destination.path + "?" + urlencode(query))
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    response.read()
                    connection.close()
                except Exception as error:
                    errors.append(error)
            thread = threading.Thread(target=callback, daemon=True)
            threads.append(thread)
            thread.start()
            return True
        def finish():
            for thread in threads:
                thread.join(timeout=6)
            self.assertEqual(errors, [])
        self.addCleanup(finish)
        return open_browser, attempts

    def test_loopback_signin_validates_state_and_uses_issued_client_for_pkce_exchange(self):
        import base64
        import hashlib
        opener, attempts = self.browser_callback()
        tokens = {"token_type": "Bearer", "access_token": "new-access", "refresh_token": "new-refresh",
                  "id_token": "signed-fixture", "expires_in": 3600, "scope": PLAN_SCOPE}
        with patch("trustline.chatgpt.webbrowser.open", side_effect=opener), \
                patch("trustline.chatgpt.request_json", return_value=tokens) as exchange, \
                patch.object(self.account, "validate_identity", return_value={"sub": "new-subject", "email": "test@example.test"}) as verify:
            result = self.account.login()
        self.assertTrue(result["using_chatgpt_plan"])
        self.assertEqual(attempts[0]["client_id"], "dynamic_agent_client")
        self.assertEqual(attempts[0]["agent_name_hint"], "TrustLine")
        form = exchange.call_args.kwargs["form"]
        self.assertEqual(form["client_id"], "oaiapp_new")
        self.assertEqual(form["redirect_uri"], attempts[0]["redirect_uri"])
        challenge = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest()).rstrip(b"=").decode()
        self.assertEqual(challenge, attempts[0]["code_challenge"])
        verify.assert_called_once_with("signed-fixture", "oaiapp_new", attempts[0]["nonce"])

    def test_returning_signin_rejects_different_client_and_keeps_saved_credentials(self):
        saved = self.save_profile()
        opener, attempts = self.browser_callback(mismatch=True)
        with patch("trustline.chatgpt.webbrowser.open", side_effect=opener), \
                patch("trustline.chatgpt.request_json") as exchange:
            with self.assertRaises(PlanError):
                self.account.login()
        exchange.assert_not_called()
        self.assertEqual(attempts[0]["client_id"], "oaiapp_fixture")
        self.assertNotIn("agent_name_hint", attempts[0])
        self.assertEqual(self.account.selected()[1], saved)

    def test_failed_exchange_reuses_issued_registration_instead_of_registering_again(self):
        opener, attempts = self.browser_callback()
        with patch("trustline.chatgpt.webbrowser.open", side_effect=opener), \
                patch("trustline.chatgpt.request_json", side_effect=RuntimeError("fixture-exchange-failed")):
            for _ in range(2):
                with self.assertRaises(PlanError):
                    self.account.login()
        self.assertEqual(attempts[0]["client_id"], "dynamic_agent_client")
        self.assertEqual(attempts[1]["client_id"], "oaiapp_new")
        self.assertEqual(attempts[0]["ext_agent_host_id"], attempts[1]["ext_agent_host_id"])


if __name__ == "__main__":
    unittest.main()
