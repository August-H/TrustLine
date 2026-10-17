import datetime
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]


class QuietHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.visits.append(self.path)
        body = b"local fixture response"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def tls_fixture(directory, name, hostnames):
    server = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
    server.visits = []
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName(host) for host in hostnames
            ]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_path = directory / f"{name}-cert.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path = directory / f"{name}-key.pem"
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server, cert_path, cert.public_bytes(serialization.Encoding.DER)


class ProxyIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(dir="/tmp", prefix="tl-proxy-")
        cls.state = Path(cls.directory.name)
        cls.http_origin = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
        cls.http_origin.visits = []
        cls.tls_origin, cls.server_cert, cls.server_der = tls_fixture(
            cls.state, "fixture", ["youtube.com", "clean.invalid"],
        )
        cls.untrusted_origin, _, _ = tls_fixture(
            cls.state, "untrusted", ["untrusted.invalid"],
        )
        for server in [cls.http_origin, cls.tls_origin, cls.untrusted_origin]:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            cls.port = probe.getsockname()[1]
        cls.process = subprocess.Popen([
            sys.executable, str(ROOT / "tests/proxy_fixture.py"), str(cls.state), str(cls.port),
            str(cls.http_origin.server_port), str(cls.tls_origin.server_port),
            str(cls.untrusted_origin.server_port),
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        cls.addClassCleanup(cls.cleanup)
        deadline = time.monotonic() + 10
        while True:
            if cls.process.poll() is not None:
                raise AssertionError(cls.process.stderr.read().decode())
            try:
                with socket.create_connection(("127.0.0.1", cls.port), timeout=0.1):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    raise AssertionError("Proxy did not start")
                time.sleep(0.05)

    @classmethod
    def cleanup(cls):
        cls.process.terminate()
        cls.output, cls.diagnostics = cls.process.communicate(timeout=10)
        for server in [cls.http_origin, cls.tls_origin, cls.untrusted_origin]:
            server.shutdown()
            server.server_close()
        cls.directory.cleanup()

    def test_http_navigation_redirects_without_reaching_origin(self):
        before = len(self.http_origin.visits)
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        self.addCleanup(connection.close)
        connection.request("GET", "http://flagged.invalid/private?token=secret", headers={
            "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Cookie": "private-cookie",
        })
        response = connection.getresponse()
        self.assertEqual(response.status, 303)
        self.assertEqual(response.getheader("Location"), "https://blocked.example.com/")
        response.read()
        self.assertEqual(len(self.http_origin.visits), before)
        inputs = (self.state / "model-inputs.jsonl").read_text()
        self.assertNotIn("token", inputs)
        self.assertNotIn("secret", inputs)
        self.assertNotIn("private-cookie", inputs)

    def test_https_navigation_redirects_with_validated_local_ca(self):
        context = ssl.create_default_context(cafile=str(self.state / "certificates/mitmproxy-ca-cert.pem"))
        connection = http.client.HTTPSConnection("127.0.0.1", self.port, context=context, timeout=5)
        self.addCleanup(connection.close)
        connection.set_tunnel("tls-flagged.invalid", 443)
        before = len(self.tls_origin.visits)
        connection.request("GET", "/private?token=secret", headers={
            "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
        })
        response = connection.getresponse()
        self.assertEqual(response.status, 303)
        self.assertEqual(response.getheader("Location"), "https://blocked.example.com/")
        response.read()
        self.assertEqual(len(self.tls_origin.visits), before)

    def test_approved_https_passes_original_certificate_without_decryption(self):
        context = ssl.create_default_context(cafile=str(self.server_cert))
        connection = http.client.HTTPSConnection("127.0.0.1", self.port, context=context, timeout=5)
        self.addCleanup(connection.close)
        connection.set_tunnel("youtube.com", 443)
        connection.connect()
        self.assertEqual(connection.sock.getpeercert(binary_form=True), self.server_der)
        connection.request("GET", "/approved-fixture")
        response = connection.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.read(), b"local fixture response")
        inputs = self.state / "model-inputs.jsonl"
        self.assertNotIn("youtube.com", inputs.read_text() if inputs.exists() else "")

    def test_clean_http_request_is_forwarded(self):
        self.approve_via_checking_page("http://clean.invalid/clean-fixture")
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        self.addCleanup(connection.close)
        connection.request("GET", "http://clean.invalid/clean-fixture", headers={"Accept": "text/html"})
        response = connection.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.read(), b"local fixture response")

    def intercepted_connection(self, hostname, context=None):
        if context is None:
            context = ssl.create_default_context(
                cafile=str(self.state / "certificates/mitmproxy-ca-cert.pem"),
            )
        connection = http.client.HTTPSConnection("127.0.0.1", self.port,
                                                 context=context, timeout=5)
        self.addCleanup(connection.close)
        connection.set_tunnel(hostname, 443)
        return connection

    def test_clean_https_is_decrypted_and_forwarded_over_separate_tls(self):
        self.approve_via_checking_page("https://clean.invalid/clean-tls-fixture")
        connection = self.intercepted_connection("clean.invalid")
        connection.connect()
        # The client sees a proxy certificate, rather than the origin certificate.
        self.assertNotEqual(connection.sock.getpeercert(binary_form=True), self.server_der)
        connection.request("GET", "/clean-tls-fixture", headers={"Accept": "text/html"})
        response = connection.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.read(), b"local fixture response")
        self.assertIn("/clean-tls-fixture", self.tls_origin.visits)
        observations = [json.loads(line) for line in
                        (self.state / "model-inputs.jsonl").read_text().splitlines()]
        self.assertTrue(any(row["url_origin"] == "https://clean.invalid" for row in observations))

    def test_client_rejects_interception_without_trusting_proxy_ca(self):
        connection = self.intercepted_connection("tls-flagged.invalid", ssl.create_default_context())
        with self.assertRaises(ssl.SSLCertVerificationError):
            connection.connect()

    def test_proxy_rejects_upstream_certificate_with_wrong_hostname(self):
        self.approve_via_checking_page("https://wrong-host.invalid/must-not-reach-origin")
        before = len(self.tls_origin.visits)
        connection = self.intercepted_connection("wrong-host.invalid")
        connection.request("GET", "/must-not-reach-origin", headers={"Accept": "text/html"})
        response = connection.getresponse()
        self.assertEqual(response.status, 502)
        response.read()
        self.assertEqual(len(self.tls_origin.visits), before)

    def test_proxy_rejects_upstream_certificate_from_untrusted_ca(self):
        self.approve_via_checking_page("https://untrusted.invalid/must-not-reach-origin")
        before = len(self.untrusted_origin.visits)
        connection = self.intercepted_connection("untrusted.invalid")
        connection.request("GET", "/must-not-reach-origin", headers={"Accept": "text/html"})
        response = connection.getresponse()
        self.assertEqual(response.status, 502)
        response.read()
        self.assertEqual(len(self.untrusted_origin.visits), before)

    def approve_via_checking_page(self, url):
        from urllib.parse import urlsplit
        parsed = urlsplit(url)
        before = len(self.http_origin.visits) + len(self.tls_origin.visits) + len(self.untrusted_origin.visits)
        if parsed.scheme == "https":
            first = self.intercepted_connection(parsed.hostname)
            target = parsed.path
        else:
            first = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
            self.addCleanup(first.close)
            target = url
        first.request("GET", target, headers={"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate"})
        held = first.getresponse()
        self.assertEqual(held.status, 303)
        location = held.getheader("Location")
        held.read()
        self.assertTrue(location.startswith("https://blocked.example.com/_trustline/check/"))
        token = location.rsplit("/", 1)[1]
        self.assertEqual(len(self.http_origin.visits) + len(self.tls_origin.visits) + len(self.untrusted_origin.visits), before)
        # Interstitial is generated by the proxy. No DNS/upstream server exists
        # for blocked.example.com in these tests.
        control = self.intercepted_connection("blocked.example.com")
        control.request("GET", "/_trustline/check/" + token)
        page = control.getresponse()
        self.assertEqual(page.status, 200)
        self.assertIn(b"Checking this website", page.read())
        self.assertIn("default-src 'none'", page.getheader("Content-Security-Policy"))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            control.request("GET", "/_trustline/reviews/" + token)
            response = control.getresponse()
            result = json.loads(response.read())
            if result["status"] != "pending":
                self.assertEqual(result["status"], "allow")
                break
            time.sleep(0.025)
        else:
            self.fail("Fixture review did not finish")
        # Even after a successful remote result, no local origin request has
        # been sent. The user must navigate through the continuation.
        self.assertEqual(len(self.http_origin.visits) + len(self.tls_origin.visits) + len(self.untrusted_origin.visits), before)
        control.request("GET", "/_trustline/continue/" + token)
        continued = control.getresponse()
        self.assertEqual(continued.status, 303)
        self.assertEqual(continued.getheader("Location"), url)
        continued.read()

    def test_blocked_page_is_served_locally_without_reaching_origin(self):
        before = len(self.tls_origin.visits)
        control = self.intercepted_connection("blocked.example.com")
        control.request("GET", "/")
        response = control.getresponse()
        self.assertEqual(response.status, 200)
        self.assertIn(b"Website blocked", response.read())
        self.assertEqual(len(self.tls_origin.visits), before)


if __name__ == "__main__":
    unittest.main()
