"""Offline regressions for URL encoding and cross-layer state validation."""
import http.client
import unittest
from urllib.parse import urlsplit, urlunsplit
from unittest import mock

from test_server import server
import subscription_converter as converter
import test_converter_execution as fixtures


class AuditRegressions(unittest.TestCase):
    def test_unicode_url_is_an_ascii_uri_without_reencoding_escapes(self):
        source = 'https://例子.test/订阅/🙂?q=中文&x=%2B+keep%26&next=a/b?c=d'
        canonical = converter.http_url(source)
        self.assertEqual(canonical, 'https://xn--fsqu00a.test/%E8%AE%A2%E9%98%85/%F0%9F%99%82?q=%E4%B8%AD%E6%96%87&x=%2B+keep%26&next=a/b?c=d')
        self.assertEqual(converter.http_url(canonical), canonical)
        parts = urlsplit(canonical)
        with mock.patch('socket.create_connection', side_effect=AssertionError('network forbidden')):
            http.client.HTTPConnection(parts.hostname).putrequest('GET', urlunsplit(('', '', parts.path, parts.query, '')))

    def test_unicode_url_reaches_pinned_fetch_as_ascii(self):
        fixture = fixtures.FetchTests()
        fixture.fetch([fixtures.Response()], url='https://example.test/订阅?q=中文&x=%2B')
        request = fixture.requests[0][0]
        self.assertEqual(request, ('GET', '/%E8%AE%A2%E9%98%85?q=%E4%B8%AD%E6%96%87&x=%2B'))
        self.assertTrue(request[1].isascii())

    def test_url_percent_expansion_obeys_the_source_byte_budget(self):
        with self.assertRaises(converter.ConverterError):
            converter.http_url('https://example.test/' + '中' * 2000)

    def test_policy_controls_and_surrogates_fail_closed_in_both_paths(self):
        for character in [chr(i) for i in range(32)] + [chr(i) for i in range(127,160)] + ['\ud800', '\udfff']:
            with self.subTest(codepoint=ord(character)):
                policy = 'Group' + character + 'X'
                checked = server.validate_customization({'rules': [{'type': 'DOMAIN', 'value': 'example.test', 'policy': policy}]})
                self.assertFalse(checked['ok'])
                self.assertIsNone(server.normalize_configured_rule('DOMAIN', 'example.test', policy))

    def test_ordinary_unicode_policies_keep_the_same_normalization(self):
        for policy in ('DIRECT', '业务组🙂', 'Group-A + B', '香港 / Tokyo 01', 'a' * 128):
            expected = {'type': 'DOMAIN', 'value': 'example.test', 'policy': policy}
            checked = server.validate_customization({'rules': [expected]})
            self.assertTrue(checked['ok'])
            self.assertEqual(checked['rules'], [expected])
            self.assertEqual(server.normalize_configured_rule('DOMAIN', 'example.test', policy), expected)


if __name__ == '__main__':
    unittest.main()
