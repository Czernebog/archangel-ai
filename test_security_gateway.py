"""Security and API regression tests for ARCHANGEL gateway."""
import http.client
import json
import threading
import unittest

import server


class GatewaySecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=3)

    def request(self, path, method="GET", data=None, origin=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = {}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if origin is not None:
            headers["Origin"] = origin
        conn.request(method, path, body=None if data is None else json.dumps(data), headers=headers)
        res = conn.getresponse()
        body = res.read()
        status = res.status
        hdr = dict(res.getheaders())
        conn.close()
        return status, body, hdr

    def test_health_endpoint(self):
        status, body, _ = self.request("/healthz")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ok"])

    def test_source_files_not_public(self):
        for path in ("/server.py", "/.github/workflows/quality-checks.yml", "/requirements.txt"):
            with self.subTest(path=path):
                status, _, _ = self.request(path)
                self.assertEqual(status, 404)

    def test_security_headers(self):
        status, _, hdr = self.request("/")
        self.assertEqual(status, 200)
        self.assertEqual(hdr.get("X-Frame-Options"), "DENY")
        self.assertEqual(hdr.get("X-Content-Type-Options"), "nosniff")
        self.assertIn("HttpOnly", hdr.get("Set-Cookie", ""))
        self.assertIn("SameSite=Strict", hdr.get("Set-Cookie", ""))

    def test_cross_origin_config_blocked(self):
        status, body, _ = self.request(
            "/api/config", "POST",
            {"provider": "openai", "model": "example", "api_key": "sample-key"},
            origin="https://attacker.example",
        )
        self.assertEqual(status, 403, body)

    def test_neural_tts_requires_session_key(self):
        origin = f"http://127.0.0.1:{self.port}"
        status, body, hdr = self.request(
            "/api/tts", "POST",
            {"text": "Hello", "language": "en", "gender": "female"}, origin=origin)
        self.assertEqual(status, 409, body)
        self.assertIn("application/json", hdr.get("Content-Type", ""))

    def test_cross_origin_tts_blocked(self):
        status, body, _ = self.request(
            "/api/tts", "POST",
            {"text": "Hello", "language": "en", "gender": "female"},
            origin="https://attacker.example")
        self.assertEqual(status, 403, body)

    def test_bad_provider_and_invalid_model(self):
        origin = f"http://127.0.0.1:{self.port}"
        status, _, _ = self.request(
            "/api/config", "POST",
            {"provider": "unknown", "model": "example"}, origin=origin)
        self.assertEqual(status, 400)
        status, _, _ = self.request(
            "/api/config", "POST",
            {"provider": "openai", "model": "bad" + chr(10) + "model", "api_key": "test"}, origin=origin)
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
