"""Chain API contract, credential non-disclosure, state guards and router tests."""
import copy
import io
import json
import pathlib
import subprocess
import unittest
from unittest import mock
from test_server import server

ROOT = pathlib.Path(__file__).resolve().parents[1]
HASH = 'a' * 64
PROFILE = {'node': '上游 A', 'type': 'socks5', 'server': 'exit.example.com', 'port': 1080,
           'username': 'synthetic-user', 'password': 'synthetic-secret'}


class ChainValidationTests(unittest.TestCase):
    def test_protocols_and_private_addresses(self):
        for host in ('exit.example.com', '10.254.254.1', '192.168.254.254', 'fd00::2', '2001:db8::2'):
            self.assertTrue(server.validate_chain(dict(PROFILE, server=host))['ok'])
        self.assertTrue(server.validate_chain(dict(PROFILE, type='http', tls=True, sni='cert.example.com'))['ok'])
        ss = dict(PROFILE, type='ss', cipher='aes-128-gcm')
        del ss['username']
        self.assertTrue(server.validate_chain(ss)['ok'])

    def test_unsafe_inputs_rejected_without_echo(self):
        changes = [{'server': host} for host in ('http://exit.example.com', 'a/b', 'localhost', 'x.localhost',
            '0.0.0.0', '0.1.2.3', '127.0.0.1', '169.254.169.254', '224.0.0.1', '240.0.0.1', '::', '::1',
            'fe80::2', 'ff02::1', '::ffff:127.0.0.1', '::7f00:1')]
        changes += [{'port': item} for item in (0, -1, 65536, True, '1080', [], None)]
        changes += [{'type': []}, {'skip-cert-verify': True}, {'tls': 'true'}, {'keep_password': 1},
                    {'password': 'x' * 256}, {'username': ''}, {'password': ''}, {'sni': 'x.example.com'},
                    {'tls': True, 'sni': 'cert.example.com'}, {'node': '__OCS_UP_fake'}, {'node': 'DIRECT'}, {'node': 'bad\nname'}, {'password': '\ud800'}]
        for change in changes:
            with self.subTest(fields=list(change)):
                result = server.validate_chain(dict(PROFILE, **change))
                self.assertFalse(result['ok'])
                self.assertNotIn('synthetic-secret', json.dumps(result))

    def test_retention_never_synthesizes_or_returns_password(self):
        value = dict(PROFILE, keep_password=True)
        del value['password']
        self.assertTrue(server.validate_chain(value)['ok'])
        self.assertNotIn('password', server.validate_chain(value)['chain'])
        self.assertFalse(server.validate_chain(dict(PROFILE, keep_password=True))['ok'])

    def test_read_result_strict_schema_and_no_credentials(self):
        profile = dict(PROFILE, has_password=True)
        del profile['password']
        result = {'ok': True, 'nodes': [{'name': '上游 A', 'type': 'ss'}], 'chains': [profile],
                  'config_sha256': HASH, 'state_sha256': HASH}
        request = {'action': 'chain_read', 'target': 'router_a'}
        self.assertTrue(server.bridge_result_ok(request, result))
        for field in ('password', 'keep_password', 'original', 'unknown'):
            bad = copy.deepcopy(result)
            bad['chains'][0][field] = 'do-not-return'
            self.assertFalse(server.bridge_result_ok(request, bad))
        bad = copy.deepcopy(result)
        bad['chains'].append(bad['chains'][0])
        self.assertFalse(server.bridge_result_ok(request, bad))

    def test_false_or_malformed_test_success_rejected(self):
        req = {'action': 'chain_test', 'target': 'router_a', 'node': '上游 A'}
        result = {'ok': True, 'node': '上游 A', 'configuration': 'PASS', 'runtime': 'PASS',
                  'upstream': 'REACHABLE', 'chain': 'REACHABLE', 'verdict': 'PASS'}
        self.assertTrue(server.bridge_result_ok(req, result))
        for key in ('runtime', 'configuration', 'chain', 'verdict', 'node', 'upstream'):
            for invalid in ([], {}, None, 'BOGUS'):
                self.assertFalse(server.bridge_result_ok(req, dict(result, **{key: invalid})))
        self.assertFalse(server.bridge_result_ok(req, dict(result, runtime='UNKNOWN')))
        self.assertFalse(server.bridge_result_ok(req, dict(result, chain='UNREACHABLE')))
        self.assertFalse(server.bridge_result_ok(req, dict(result, upstream='UNREACHABLE')))
        self.assertFalse(server.bridge_result_ok(req, dict(result, upstream='UNKNOWN')))
        self.assertTrue(server.bridge_result_ok(req, dict(result, runtime='UNKNOWN', verdict='UNKNOWN')))


class ChainAPITests(unittest.TestCase):
    def post(self, path, payload, result=None):
        handler = object.__new__(server.Handler)
        handler.path = path
        handler.authorize = lambda: True
        handler.same_origin = lambda: True
        handler.read_json = lambda: copy.deepcopy(payload)
        output = []
        handler.send_json = lambda code, data: output.append((code, data))
        with mock.patch.object(server.BRIDGE, 'call', return_value=result or {'ok': True, 'message': 'synthetic'}) as call:
            handler.do_POST()
        self.assertEqual(len(output), 1)
        return (*output[0], call)

    def test_validation_does_not_consume_nonce_or_echo_input(self):
        nonce = server.new_nonce()
        code, data, call = self.post('/api/chain/validate', {'nonce': nonce, 'chain': PROFILE})
        self.assertEqual(code, 200)
        self.assertNotIn('synthetic-secret', json.dumps(data))
        self.assertTrue(server.consume_nonce(nonce))
        call.assert_not_called()

    def test_read_target_and_nonce_are_required(self):
        for payload in ({'target': 'router_a'}, {'target': 'missing', 'nonce': server.new_nonce()},
                        {'target': ['router_a'], 'nonce': server.new_nonce()}):
            code, _, call = self.post('/api/chain/read', payload)
            self.assertIn(code, (400, 409))
            call.assert_not_called()

    def test_apply_validated_payload_and_concurrency_hashes(self):
        nonce = server.new_nonce()
        payload = {'target': 'router_a', 'nonce': nonce, 'operation': 'upsert', 'chain': PROFILE,
                   'expected_config_sha256': HASH, 'expected_state_sha256': HASH}
        code, _, call = self.post('/api/chain/apply', payload)
        self.assertEqual(code, 200)
        call.assert_called_once()
        sent = call.call_args.args[0]
        self.assertEqual(sent['action'], 'chain_apply')
        self.assertEqual(sent['chain']['tls'], False)
        self.assertEqual(sent['expected_config_sha256'], HASH)
        code, _, call = self.post('/api/chain/apply', payload)
        self.assertEqual(code, 409)
        call.assert_not_called()

    def test_apply_missing_hash_unknown_fields_and_password_echo_rejected(self):
        base = {'target': 'router_a', 'operation': 'upsert', 'chain': PROFILE,
                'expected_config_sha256': HASH, 'expected_state_sha256': HASH}
        for changed in ({'expected_config_sha256': ''}, {'extra': 1}, {'chain': dict(PROFILE, port=-1)}):
            code, data, call = self.post('/api/chain/apply', dict(base, nonce=server.new_nonce(), **changed))
            self.assertIn(code, (409, 422))
            self.assertNotIn('synthetic-secret', json.dumps(data))
            call.assert_not_called()

    def test_cancel_and_fixed_probe_use_only_node(self):
        for path, extra in (('/api/chain/test', {}), ('/api/chain/apply', {'operation': 'remove',
                            'expected_config_sha256': HASH, 'expected_state_sha256': HASH})):
            payload = dict(extra, target='router_b', node='上游 A', nonce=server.new_nonce())
            code, _, call = self.post(path, payload)
            self.assertEqual(code, 200)
            self.assertEqual(call.call_args.args[0]['node'], '上游 A')
            payload.update(nonce=server.new_nonce(), url='http://127.0.0.1/')
            code, _, call = self.post(path, payload)
            self.assertEqual(code, 422)
            call.assert_not_called()

    def test_preview_cannot_claim_real_save_or_connectivity(self):
        for action in ('chain_apply', 'chain_test'):
            result = server.Bridge.demo({'action': action, 'target': 'router_a', 'node': '上游 A'})
            self.assertFalse(result['ok'])
            self.assertEqual(result['mode'], 'preview')

    def test_global_lock_guards_chain_operations(self):
        bridge = server.Bridge()
        bridge.helper = '/synthetic/helper'
        bridge.operation_lock.acquire()
        try:
            for action in ('chain_read', 'chain_apply', 'chain_test'):
                with mock.patch.object(bridge, '_call_unlocked') as call:
                    self.assertFalse(bridge.call({'action': action, 'target': 'router_a'})['ok'])
                    call.assert_not_called()
        finally:
            bridge.operation_lock.release()

    def test_chain_lock_is_held_during_call_and_released_on_every_exit(self):
        bridge = server.Bridge()
        bridge.helper = '/synthetic/helper'
        for action in ('chain_read', 'chain_apply', 'chain_test'):
            def check_lock(request):
                self.assertTrue(bridge.operation_lock.locked())
                return {'ok': True}
            with mock.patch.object(bridge, '_call_unlocked', side_effect=check_lock):
                self.assertTrue(bridge.call({'action': action})['ok'])
            self.assertFalse(bridge.operation_lock.locked())
            with mock.patch.object(bridge, '_call_unlocked', side_effect=RuntimeError('synthetic')):
                with self.assertRaises(RuntimeError):
                    bridge.call({'action': action})
            self.assertFalse(bridge.operation_lock.locked())

    def test_duplicate_json_members_are_rejected_before_dispatch(self):
        for body in (b'{"target":"router_a","target":"router_b"}',
                     b'{"chain":{"password":"synthetic-one","pass\\u0077ord":"synthetic-two"}}'):
            handler = type('FakeHandler', (), {
                'headers': {'Content-Type': 'application/json', 'Content-Length': str(len(body))},
                'rfile': io.BytesIO(body), 'close_connection': False,
                'header_values': server.Handler.header_values,
                'finish_request_reading': server.Handler.finish_request_reading,
            })()
            self.assertIsNone(server.Handler.read_json(handler))
            self.assertTrue(handler.close_connection)

    def test_duplicate_helper_members_and_unconfirmed_mutations_fail_closed(self):
        bridge = server.Bridge()
        bridge.helper = '/synthetic/helper'
        for action in ('chain_read', 'chain_apply', 'chain_test'):
            output = subprocess.CompletedProcess([], 0, b'{"ok":false,"ok":true}')
            with mock.patch.object(server.subprocess, 'run', return_value=output):
                result = bridge.call({'action': action, 'target': 'router_a'})
            self.assertFalse(result['ok'])
            self.assertEqual('写入状态 UNKNOWN' in result['message'], action == 'chain_apply')
            self.assertFalse(bridge.operation_lock.locked())

    def test_ruby_regressions(self):
        p = subprocess.run(['ruby', str(ROOT / 'tests/test_chain_customizer.rb')], capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertRegex(p.stdout, r'CHAIN_CUSTOMIZER_TESTS=\d+/\d+')


if __name__ == '__main__':
    unittest.main()
