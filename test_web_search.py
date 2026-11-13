"""Regression tests for ARCHANGEL's opt-in web search."""
import json
import unittest

import web_search


class FakeResponse:
    status = 200

    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, max_bytes):
        return self.payload[:max_bytes]


class FakeOpener:
    def __init__(self, payload):
        self.payload = payload
        self.request = None
        self.timeout = None

    def open(self, req, timeout):
        self.request, self.timeout = req, timeout
        return FakeResponse(self.payload)


class WebSearchTests(unittest.TestCase):
    def test_no_key_is_safe_and_explicit(self):
        with self.assertRaises(web_search.WebSearchError) as err:
            web_search.search_web("python unittest", "")
        self.assertIn("BRAVE_SEARCH_API_KEY", str(err.exception))

    def test_query_length_limit(self):
        for query in ("", "x" * 251, "word " * 41):
            with self.subTest(query=query[:15]):
                with self.assertRaises(ValueError):
                    web_search.search_web(query, "test-key")

    def test_reject_nonpublic_links_and_strip_untrusted_markup(self):
        payload = {"web": {"results": [
            {"title": "<b>Python</b>", "description": "<script>fake()</script>Guide", "url": "https://docs.python.org/3/"},
            {"title": "internal", "url": "http://127.0.0.1:9999/private"},
            {"title": "javascript", "url": "javascript:alert(1)"},
            {"title": "credentials", "url": "https://user:pass@example.org/a"},
            {"title": "duplicate", "url": "https://docs.python.org/3/"},
        ]}}
        opener = FakeOpener(payload)
        rows = web_search.search_web("python", "secret-key", opener=opener)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["title"], "Python")
        self.assertNotIn("<", rows[0]["description"])
        self.assertEqual(rows[0]["url"], "https://docs.python.org/3/")
        self.assertEqual(opener.timeout, 9)
        self.assertIn("safesearch=strict", opener.request.full_url)
        self.assertEqual(opener.request.get_header("X-subscription-token"), "secret-key")

    def test_public_urls_only(self):
        for url in ("http://localhost/", "http://[::1]/", "http://192.168.1.1/",
                    "file:///etc/passwd", "https://example.local/", "https://a.invalid:99999/",
                    "https://user:pwd@example.org/"):
            with self.subTest(url=url):
                self.assertEqual(web_search.public_result_url(url), "")
        self.assertEqual(web_search.public_result_url("https://example.org/a#section"),
                         "https://example.org/a")

    def test_result_count_is_bounded(self):
        payload = {"web": {"results": [{"title": str(i), "url": "https://example.org/" + str(i)}
                                      for i in range(20)]}}
        rows = web_search.search_web("test", "secret-key", opener=FakeOpener(payload))
        self.assertEqual(len(rows), 6)


if __name__ == "__main__":
    unittest.main()
