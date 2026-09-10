"""Mellow checks original semantics before the pinned engine can drop them."""
import base64
import json
import unittest
from unittest.mock import Mock

import converter_engine as engine
import converter_mellow as m
from subscription_converter import ConverterError

SS = {'name': 'Synthetic', 'type': 'ss', 'server': '192.0.2.1', 'port': 443,
      'cipher': 'aes-128-gcm', 'password': 'synthetic'}
VM = {'v': '2', 'ps': 'VMess', 'add': '192.0.2.4', 'port': '443',
      'id': '11111111-2222-4333-8444-555555555555', 'aid': '0', 'net': 'tcp', 'type': 'none', 'tls': 'tls'}


def uri(value):
    return 'vmess://' + base64.b64encode(json.dumps(value).encode()).decode()


def check(value):
    m.validate_sources([value.encode()])


class SourceTests(unittest.TestCase):
    def test_clash_and_plain_and_base64_uri_sources(self):
        check(json.dumps({'proxies': [SS]}))
        ss = 'ss://' + base64.b64encode(b'aes-128-gcm:synthetic').decode() + '@192.0.2.1:443#Synthetic'
        for value in (ss, uri(VM), ss + '\n' + uri(VM), 'ss://' + base64.b64encode(b'aes-128-gcm:synthetic@192.0.2.1:443').decode()):
            check(value)
            check(base64.b64encode(value.encode()).decode())
        for network in ('ws', 'h2'):
            check(uri(dict(VM, net=network, host='proxy.example.test', path='/relay', sni='tls.example.test')))

    def test_http_faketype_cipher_and_unknown_raw_fields_fail_closed(self):
        cases = [dict(VM, type='http'), dict(VM, scy='aes-128-gcm'), dict(VM, aid='1'),
                 dict(VM, net='http'), dict(VM, net='quic'), dict(VM, net='tcp', host='example.test'),
                 dict(VM, allowInsecure=True), dict(VM, flow='unknown'), dict(VM, v='1', net='ws', host='host;/path')]
        for value in cases:
            for source in (uri(value), base64.b64encode(uri(value).encode()).decode()):
                with self.subTest(shape='unsupported'), self.assertRaises(ConverterError) as exc:
                    check(source)
                self.assertEqual(exc.exception.code, 'MELLOW_SOURCE')

    def test_clash_unsupported_raw_fields_cannot_be_erased_by_normalization(self):
        for node in (dict(SS, plugin='obfs'), dict(SS, **{'dialer-proxy': 'Upstream'}),
                     dict(SS, type='trojan'), dict(SS, **{'client-fingerprint': 'chrome'})):
            with self.assertRaises(ConverterError): check(json.dumps({'proxies': [node]}))
        with self.assertRaises(ConverterError):
            check(json.dumps({'proxies': [SS], 'proxy-providers': {'remote': {'url': 'https://example.test'}}}))

    def test_other_dialects_malformed_and_mixed_unsupported_not_partial_success(self):
        ss = 'ss://YWVzLTEyOC1nY206c3ludGhldGlj@192.0.2.1:443'
        for value in ('[Proxy]\nS=ss,192.0.2.1,443', 'proxies: []', '{}', 'null',
                      ss + '?plugin=obfs', ss + '\ntrojan://x@192.0.2.2:443',
                      'vmess://not-base64', 'vmess://' + base64.b64encode(b'[]').decode()):
            with self.subTest(shape='bad-source'), self.assertRaises(ConverterError): check(value)

    def test_duplicate_raw_json_fields_rejected(self):
        raw = json.dumps(VM)[:-1] + ',"type":"http"}'
        with self.assertRaises(ConverterError):
            check('vmess://' + base64.b64encode(raw.encode()).decode())

    def test_intake_checks_upload_and_public_source_before_native_execution(self):
        bad = uri(dict(VM, type='http'))
        for remote in (False, True):
            fetch = Mock(return_value=[bad.encode()])
            payload = {'form': {'sources': ['https://example.test/source'] if remote else '',
                                'options': {'target': 'mellow'}}, 'uploads': [] if remote else [bad]}
            with self.assertRaises(ConverterError) as exc: engine.prepare(payload, fetch)
            self.assertEqual(exc.exception.code, 'MELLOW_SOURCE')
            payload['form']['options']['target'] = 'clash'
            engine.prepare(payload, fetch)  # Mellow restriction does not affect other targets.


if __name__ == '__main__':
    unittest.main()
