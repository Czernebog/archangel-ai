"""Read-only research and code inspection regression suite (no network required)."""
import socket
import unittest
from unittest.mock import patch

import code_analyzer
import research_engine


class CodeAnalyzerTests(unittest.TestCase):
    def test_syntax_and_metrics(self):
        result = code_analyzer.analyze_python('def total(a, b):\n    return a + b\n\nclass Example:\n    pass\n')
        self.assertTrue(result['ok'])
        self.assertEqual(result['functions'], 1)
        self.assertEqual(result['classes'], 1)
        self.assertEqual(result['issues'], [])

    def test_syntax_error_includes_line(self):
        result = code_analyzer.analyze_python('def foo(:\n  pass')
        self.assertFalse(result['ok'])
        self.assertEqual(result['issues'][0]['level'], 'error')
        self.assertEqual(result['issues'][0]['line'], 1)

    def test_warns_without_running_source(self):
        source = 'raise RuntimeError("must never run")\n' + 'eval("1+1")\n' + 'try:\n  pass\nexcept:\n  pass\n'
        result = code_analyzer.analyze_python(source)
        self.assertTrue(result['ok'])
        self.assertGreaterEqual(len(result['issues']), 2)

    def test_large_code_rejected(self):
        with self.assertRaises(ValueError):
            code_analyzer.analyze_python('a' * 80001)


class ResearchTests(unittest.TestCase):
    def test_private_dns_rejected(self):
        with patch.object(socket, 'getaddrinfo', return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443)),
        ]):
            with self.assertRaises(ValueError):
                research_engine.verified_public_ips('example.org')

    def test_ip_literal_and_local_hosts_rejected(self):
        for host in ('127.0.0.1', '10.0.0.2', 'localhost', 'example.local', 'example..org'):
            with self.subTest(host=host):
                with self.assertRaises(ValueError):
                    research_engine.verified_public_ips(host)

    def test_http_and_nonstandard_ports_blocked_before_dns(self):
        with patch.object(research_engine, 'verified_public_ips') as dns:
            for link in ('http://example.org/', 'https://example.org:8443/x'):
                with self.subTest(link=link):
                    with self.assertRaises(ValueError):
                        research_engine.read_public_page(link)
            dns.assert_not_called()

    def test_research_limits_queries_pages_and_cites(self):
        calls, pages = [], []
        def fake_search(query, key, count=6):
            calls.append(query)
            return [{'title': 'Source ' + str(i), 'url': 'https://example.org/' + str(i),
                     'description': 'excerpt'} for i in range(len(calls)*8-8, len(calls)*8)]
        def fake_read(url):
            pages.append(url)
            return 'Public page text about the subject.', 'Example'
        result = research_engine.research('python security', 'fake-api', 'deep', search=fake_search, reader=fake_read)
        self.assertEqual(len(calls), 3)
        self.assertEqual(result['indexedCount'], 24)
        self.assertEqual(result['readCount'], 12)
        self.assertEqual(len(pages), 12)
        self.assertTrue(all(row['url'].startswith('https://') for row in result['sources']))

    def test_unexpected_source_parser_failure_is_isolated(self):
        def fake_search(query, key, count=6):
            return [
                {'title': 'Broken page', 'url': 'https://example.org/1'},
                {'title': 'Working page', 'url': 'https://example.org/2'},
            ]
        def fake_read(url):
            if url.endswith('/1'):
                raise RuntimeError('Malformed HTML parser failure')
            return 'Verified public page excerpt', ''
        result = research_engine.research('topic', 'test-api', search=fake_search, reader=fake_read)
        self.assertEqual(result['indexedCount'], 2)
        self.assertEqual(result['readCount'], 1)
        self.assertFalse(result['sources'][0]['read'])
        self.assertEqual(result['sources'][0]['text'], '')
        self.assertTrue(result['sources'][1]['read'])

    def test_unavailable_pages_not_faked(self):
        def fake_search(query, key, count=6):
            return [{'title': 'Example', 'url': 'https://example.org/1', 'description': 'snippet'}]
        def unreadable(url):
            raise ValueError('Unavailable')
        result = research_engine.research('test', 'fake-api', search=fake_search, reader=unreadable)
        self.assertEqual(result['readCount'], 0)
        self.assertEqual(result['sources'][0]['text'], '')
        self.assertFalse(result['sources'][0]['read'])


if __name__ == '__main__':
    unittest.main()
