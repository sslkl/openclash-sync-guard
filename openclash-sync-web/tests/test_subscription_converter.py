"""No real subscriptions, network access or device writes in these tests."""
import copy
import json
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlencode
from test_server import server

c = server.converter
SOURCE = 'https://subscription.example.test/sub?token=synthetic-only&x=%2B'
FORM = {'sources': [SOURCE], 'options': dict(c.PRESET_OPTIONS), 'profile': 'router_a'}


class RequestTests(unittest.TestCase):
    def test_roundtrip_preserves_every_boolean_and_text(self):
        opts = {key: index % 2 == 0 for index, key in enumerate(c.BOOL_OPTIONS)}
        opts.update({key: '示例+ value@replacement' for key in c.TEXT_OPTIONS})
        opts.update(target='surge', ver=5, interval=3600, config='https://config.example.test/a.ini?q=a%2Bb')
        value = c.validate({'sources': [SOURCE, SOURCE, 'ss://YWVzLTEyOC1nY206c3ludGhldGlj@198.51.100.5:443#name'], 'options': opts})
        parsed = c.parse_link(value.link())
        self.assertEqual(parsed.sources, value.sources)
        self.assertEqual(parsed.options, opts)
        self.assertEqual(parsed.link(), value.link())

    def test_presets_match_existing_worker_parameters_and_are_independent(self):
        from pathlib import Path
        import ast
        tree = ast.parse((Path(server.ROOT).parent / 'openclash_worker.py').read_text())
        assignment = next(n for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'REQUIRED_QUERY' for t in n.targets))
        existing = ast.literal_eval(assignment.value)
        expected = {k: str(v).lower() if type(v) is bool else v for k, v in c.PRESET_OPTIONS.items()}
        self.assertEqual(expected, existing)
        caps = c.capabilities()
        self.assertEqual([p['id'] for p in caps['presets']], ['router_a', 'router_b'])
        caps['presets'][0]['options']['scv'] = True
        self.assertFalse(c.capabilities()['presets'][0]['options']['scv'])
        self.assertFalse(caps['presets'][1]['options']['scv'])

    def test_omitted_false_true_are_distinct(self):
        for extra in ({}, {'udp': False}, {'udp': True}):
            value = c.validate({'sources': SOURCE, 'options': extra})
            parsed = c.parse_link(value.link())
            self.assertEqual(parsed.options, dict(extra, target='clash'))

    def test_all_targets_and_surge_versions(self):
        for client in c.CLIENTS:
            checked = c.validate({'sources': SOURCE, 'options': {'target': client}})
            self.assertEqual(c.parse_link(checked.link()).options, checked.options)
        self.assertEqual(c.validate({'sources': SOURCE, 'options': {'target': 'surge'}}).options['ver'], 4)
        for version in range(2, 6):
            self.assertEqual(c.validate({'sources': SOURCE, 'options': {'target': 'surge', 'ver': version}}).options['ver'], version)

    def test_sources_are_ordered_and_line_separated_not_silently_deduplicated(self):
        checked = c.validate({'sources': ' '+SOURCE+'\r\n'+SOURCE+' | ss://opaque-data\n'})
        self.assertEqual(checked.sources, (SOURCE, SOURCE, 'ss://opaque-data'))
        query = parse_qs(checked.link().split('?', 1)[1])
        self.assertEqual(query['url'], ['|'.join(checked.sources)])

    def test_custom_backend_is_canonical_but_never_fetched(self):
        for source, expected in [('https://EXAMPLE.test', 'https://example.test/sub'),
                                 ('http://[::1]:25500/', 'http://[::1]:25500/sub'),
                                 (c.DEFAULT_BACKEND+'?', c.DEFAULT_BACKEND)]:
            with mock.patch('socket.socket', side_effect=AssertionError('network must not run')):
                checked = c.validate(dict(FORM, backend=source))
                self.assertEqual(checked.backend, expected)
                self.assertFalse(checked.summary()['network_executed'])

    def test_profile_does_not_silently_override_manual_options(self):
        checked = c.validate(dict(FORM, options={'target': 'quanx', 'udp': False}))
        self.assertEqual(checked.options, {'target': 'quanx', 'udp': False})

    def test_errors_and_summary_and_repr_do_not_leak_secrets(self):
        checked = c.validate(FORM)
        for value in (repr(checked), json.dumps(checked.summary())):
            self.assertNotIn('synthetic-only', value)
            self.assertNotIn('subscription.example', value)
        try:
            c.validate(dict(FORM, options={'include': 'synthetic-only\n'}))
        except c.ConverterError as exc:
            self.assertNotIn('synthetic-only', repr(exc) + json.dumps(c.failure(exc)))
        else:
            self.fail('invalid input accepted')

    def test_backend_authority_rejections(self):
        for backend in ('file:///etc/passwd', 'ftp://example.test/sub', 'http://u:p@example.test/sub',
                        'http://example.test/sub?token=secret', 'http://example.test/sub#fragment',
                        'http://example.test/other', 'http://example.test:0/sub', 'http://example.test:99999/sub',
                        'http://example.test:/sub', 'http://[fe80::1%25en0]/sub', 'http://example.test\\@evil.test/sub',
                        'http://bad_host/sub', 'http://example.test/%zz', '\thttp://example.test/sub'):
            with self.subTest(backend=backend), self.assertRaises(c.ConverterError):
                c.validate(dict(FORM, backend=backend))

    def test_invalid_request_types_and_control_characters(self):
        cases = [None, [], {}, {'sources': []}, {'sources': 123}, {'sources': [SOURCE]*33},
                 {'sources': '/etc/passwd'}, {'sources': 'data:text/plain,secret'},
                 {'sources': 'https://user:pass@example.test/sub'}, {'sources': 'ss://'},
                 {'sources': 'ss://bad|name', 'options': []}, {'sources': SOURCE, 'extra': True},
                 {'sources': SOURCE, 'profile': []}, {'sources': SOURCE, 'options': {'target': []}},
                 {'sources': SOURCE, 'options': {'udp': 1}}, {'sources': SOURCE, 'options': {'udp': 'false'}},
                 {'sources': SOURCE, 'options': {'filename': '../secret'}},
                 {'sources': SOURCE, 'options': {'interval': True}}, {'sources': SOURCE, 'options': {'interval': 0}},
                 {'sources': SOURCE, 'options': {'target': 'clash', 'ver': 3}}]
        for char in ('\0', '\t', '\r', '\x7f', '\x85', '\ud800'):
            cases.append({'sources': 'ss://x'+char+'y'})
        for case in cases:
            with self.subTest(shape=str(type(case))), self.assertRaises(c.ConverterError):
                c.validate(case)

    def test_unsafe_options_and_script_renaming_rejected(self):
        for name in c.BLOCKED_OPTIONS | {'arbitrary', 'url'}:
            with self.assertRaises(c.ConverterError):
                c.validate(dict(FORM, options={name: 'synthetic'}))
        for rename in ('script:function(){}', '!!script:filename.js', 'one@two| script:evil'):
            with self.assertRaises(c.ConverterError):
                c.validate(dict(FORM, options={'rename': rename}))

    def test_encoded_link_size_budget(self):
        for values in ([SOURCE] * 33, ['ss://'+'a'*16384], ['ss://'+'国'*5000]*4):
            with self.assertRaises(c.ConverterError):
                c.validate({'sources': values})

    def test_duplicate_encoded_and_malformed_link_parameters(self):
        base = c.DEFAULT_BACKEND+'?url='+urlencode({'v': SOURCE})[2:]
        for suffix in ('&target=clash&target=surge', '&udp=true&%75dp=false', '&url=ss://x',
                       '&include=%FF', '&include=%GG', '&include=%0A', '&flag', '&udp=TRUE',
                       '&interval=1.5', '&ver=4', '&token=secret', '&target=clash&'+ '&'.join('a'+str(i)+'=1' for i in range(55))):
            with self.subTest(suffix=suffix[:30]), self.assertRaises(c.ConverterError):
                c.parse_link(base+suffix)


class ConverterAPITests(unittest.TestCase):
    def post(self, path, body, authorized=True, origin=True):
        handler = object.__new__(server.Handler)
        handler.path = path
        handler.authorize = lambda: authorized
        handler.same_origin = lambda: origin
        handler.read_json = lambda: copy.deepcopy(body)
        output = []
        handler.send_json = lambda code, result: output.append((code, result))
        with mock.patch.object(server.BRIDGE, 'call') as call:
            handler.do_POST()
            call.assert_not_called()
        return output

    def test_authenticated_nonce_checked_validate_link_parse(self):
        for action in ('validate', 'link'):
            token = server.new_nonce()
            payload = {'nonce': token, 'form': FORM}
            code, result = self.post('/api/converter/'+action, payload)[0]
            self.assertEqual(code, 200)
            self.assertNotIn('synthetic-only', json.dumps(result['summary']))
            self.assertFalse(result['summary']['router_changed'])
            self.assertEqual(self.post('/api/converter/'+action, payload)[0][0], 409)
            if action == 'validate':
                self.assertNotIn('synthetic-only', json.dumps(result))
            else:
                code, parsed = self.post('/api/converter/parse', {'nonce': server.new_nonce(), 'link': result['link']})[0]
                self.assertEqual(code, 200)
                self.assertEqual(parsed['form']['sources'], [SOURCE])

    def test_auth_origin_and_nonce_fail_before_processing(self):
        self.assertEqual(self.post('/api/converter/link', {'form': FORM}, authorized=False), [])
        self.assertEqual(self.post('/api/converter/link', {'form': FORM}, origin=False)[0][0], 403)
        self.assertEqual(self.post('/api/converter/link', {'form': FORM})[0][0], 409)

    def test_invalid_input_no_sensitive_echo(self):
        for payload in ({'form': dict(FORM, options={'token': 'synthetic-only'})}, {'link': 'synthetic-only'}, {'form': FORM, 'unknown': 1}):
            code, result = self.post('/api/converter/link', dict(payload, nonce=server.new_nonce()))[0]
            self.assertEqual(code, 422)
            self.assertNotIn('synthetic-only', json.dumps(result))

    def test_capability_endpoint_is_authenticated(self):
        handler = object.__new__(server.Handler)
        handler.path = '/api/converter/options'
        handler.authorize = lambda: True
        output = []
        handler.send_json = lambda code, result: output.append((code, result))
        handler.do_GET()
        expected = c.capabilities()
        expected["execution"]["bridge_available"] = server.BRIDGE.enabled
        self.assertEqual(output, [(200, expected)])
        handler.authorize = lambda: False
        output.clear()
        handler.do_GET()
        self.assertEqual(output, [])


if __name__ == '__main__':
    unittest.main()
