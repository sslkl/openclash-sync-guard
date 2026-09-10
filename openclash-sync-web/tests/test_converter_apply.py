"""Conversion merge and guarded activation, all fixtures are synthetic."""
import copy
import json
import unittest
from unittest import mock
from test_server import server
import converter_apply as merge


def node(name, **extra):
    return dict(name=name, type='ss', server='192.0.2.1', port=443,
                cipher='aes-128-gcm', password='synthetic', **extra)


def base():
    return {'proxies': [node('old')], 'proxy-groups': [{'name': 'Proxy', 'type': 'select', 'proxies': ['old', 'DIRECT']}],
            'rules': ['DOMAIN,lan.example,DIRECT', 'MATCH,Proxy'],
            'dns': {'enable': True, 'nameserver': ['192.0.2.10'], 'fake-ip-filter': ['+.lan']},
            'tun': {'enable': False}, 'mixed-port': 7890, 'secret': 'synthetic-controller'}


def incoming():
    return {'proxies': [node('new')], 'proxy-groups': [{'name': 'Added', 'type': 'select', 'proxies': ['new']}],
            'rules': ['DOMAIN,new.example,Added', 'MATCH,Added'], 'dns': {'enable': False}, 'mixed-port': 9999}


def text(obj):
    return json.dumps(obj, ensure_ascii=False)


class MergeTests(unittest.TestCase):
    def plan(self, first=None, second=None, **kwargs):
        return merge.plan(text(first if first is not None else base()), text(second if second is not None else incoming()), **kwargs)

    def test_default_preserves_network_and_only_appends_nodes(self):
        result = self.plan(); parsed = json.loads(result['content'])
        expected = base(); expected['proxies'].append(node('new'))
        self.assertEqual(parsed, expected)
        self.assertEqual(result['groups'], ['Proxy'])
        self.assertFalse(result['summary']['router_changed'])
        self.assertEqual(result['expected_sha256'], merge.digest(text(base())))

    def test_full_merge_retains_final_route_prefix_and_selected_group_order(self):
        result = self.plan(mode='merge', group='Proxy'); parsed = json.loads(result['content'])
        self.assertEqual(parsed['rules'], ['DOMAIN,lan.example,DIRECT', 'DOMAIN,new.example,Added', 'MATCH,Proxy'])
        self.assertEqual(parsed['proxy-groups'][0]['proxies'], ['old', 'DIRECT', 'new'])
        self.assertEqual(result['summary']['final_rules_ignored'], 1)
        self.assertEqual(parsed['dns'], base()['dns'])

    def test_idempotent_reapply_preserves_identical_bytes(self):
        first = self.plan(mode='merge', group='Proxy')
        again = merge.plan(first['content'], text(incoming()), mode='merge', group='Proxy')
        self.assertTrue(again['summary']['no_change'])
        self.assertEqual(again['content'], first['content'])

    def test_conflict_never_overwrites_existing_or_chain_owned_nodes(self):
        for second in ({'proxies': [dict(node('old'), port=80)]}, {'proxies': [node('Proxy')]},
                       {'proxies': [node('__OCS_UP_internal')]}, {'proxies': [node('DIRECT')]},
                       {'proxies': [node('new'), node('new')]}):
            with self.subTest(kind='conflict'), self.assertRaises(merge.MergeError) as caught: self.plan(second=second)
            self.assertEqual(caught.exception.code, 'CONFLICT')

    def test_baseline_chain_and_custom_prefix_survive(self):
        value = base(); value['proxies'][0]['dialer-proxy'] = '__OCS_UP_original'
        value['proxies'].append(node('__OCS_UP_original'))
        result = json.loads(self.plan(first=value)['content'])
        self.assertEqual(result['proxies'][:2], value['proxies'])
        self.assertEqual(result['rules'], value['rules'])

    def test_references_cycles_providers_and_group_guard(self):
        cases = [{'proxies': [node('new', **{'dialer-proxy': 'missing'})]},
                 {'proxies': [node('new', **{'dialer-proxy': 'new'})]},
                 dict(incoming(), **{'proxy-groups': [{'name': 'Added', 'type': 'select', 'proxies': ['Added']}]}),
                 dict(incoming(), rules=['RULE-SET,unknown,Proxy']), dict(incoming(), rules=['SUB-RULE,x,Proxy'])]
        for second in cases:
            with self.subTest(kind='reference'), self.assertRaises(merge.MergeError): self.plan(second=second, mode='merge')
        for group in ('missing', 'Added'):
            with self.assertRaises(merge.MergeError): self.plan(mode='merge', group=group)

    def test_bounded_shape_alias_duplicate_and_invalid_inputs(self):
        for source in ('proxies: []\nproxies: []', 'proxies: &a [*a]', 'proxies: []', '[]', '\0', 'x' * (merge.MAX_BYTES + 1)):
            with self.subTest(kind='invalid'), self.assertRaises(merge.MergeError): merge.plan(text(base()), source)
        for changes in ({'mode': []}, {'mode': 'replace'}, {'group': []}):
            with self.assertRaises(merge.MergeError): self.plan(**changes)

    def test_no_change_uses_original_whitespace(self):
        raw = text(base()) + '\n\n'
        result = merge.plan(raw, text({'proxies': [node('old')]}))
        self.assertEqual(result['content'], raw)
        self.assertTrue(result['summary']['no_change'])


class ApplyAPITests(unittest.TestCase):
    def request(self, path, payload, *, baseline=None, digest=None, enabled=True, write_result=None):
        value = text(base()) if baseline is None else baseline
        read = {'ok': True, 'content': value, 'sha256': digest or merge.digest(value)}
        handler = object.__new__(server.Handler)
        outputs = []; handler.send_json = lambda status, result: outputs.append((status, result))
        def call(req):
            return read if req['action'] == 'read' else (write_result or {'ok': True, 'message': 'synthetic'})
        with mock.patch.object(server.BRIDGE, 'helper', '/synthetic/helper' if enabled else ''), mock.patch.object(server.BRIDGE, 'call', side_effect=call) as bridge:
            handler.handle_converter_router(path, copy.deepcopy(payload))
        self.assertEqual(len(outputs), 1)
        return *outputs[0], bridge

    def payload(self): return {'target': 'router_a', 'content': text(incoming()), 'mode': 'nodes', 'group': ''}

    def test_preview_only_reads_and_apply_uses_dedicated_activation_not_save(self):
        payload = self.payload()
        status, preview, calls = self.request('/api/converter/router-preview', payload)
        self.assertEqual(status, 200); self.assertEqual(calls.call_count, 1)
        payload.update(expected_sha256=preview['expected_sha256'], preview_sha256=preview['sha256'])
        status, _, calls = self.request('/api/converter/router-apply', payload)
        self.assertEqual(status, 200)
        sent = calls.call_args.args[0]
        self.assertEqual(sent['action'], 'converter_apply')
        self.assertEqual(sent['expected_sha256'], preview['expected_sha256'])
        self.assertNotIn('content', preview)
        expected = merge.plan(text(base()), payload['content'])
        self.assertEqual(sent['content'], expected['content'])
        self.assertEqual(merge.digest(sent['content']), preview['sha256'])
        self.assertNotIn('synthetic-controller', json.dumps(preview))

    def test_stale_baseline_or_input_never_writes(self):
        payload = self.payload(); _, preview, _ = self.request('/api/converter/router-preview', payload)
        payload.update(expected_sha256=preview['expected_sha256'], preview_sha256=preview['sha256'])
        for extra in ({'expected_sha256': 'a' * 64}, {'preview_sha256': 'b' * 64}, {'content': text({'proxies': [node('changed')]})}):
            status, result, calls = self.request('/api/converter/router-apply', dict(payload, **extra))
            self.assertEqual(status, 409); self.assertEqual(calls.call_count, 1)
            self.assertFalse(result['router_changed'])

    def test_invalid_read_demo_unknown_fields_and_failed_write(self):
        status, _, calls = self.request('/api/converter/router-preview', self.payload(), digest='f'*64)
        self.assertEqual(status, 502); self.assertEqual(calls.call_count, 1)
        status, _, calls = self.request('/api/converter/router-preview', self.payload(), enabled=False)
        self.assertEqual(status, 503); calls.assert_not_called()
        for extra in ({'target': []}, {'name': '../../file'}, {'group': []}):
            status, _, _ = self.request('/api/converter/router-preview', dict(self.payload(), **extra))
            self.assertEqual(status, 422)
        payload = self.payload(); _, preview, _ = self.request('/api/converter/router-preview', payload)
        payload.update(expected_sha256=preview['expected_sha256'], preview_sha256=preview['sha256'])
        status, result, _ = self.request('/api/converter/router-apply', payload, write_result={'ok': False, 'message': 'UNKNOWN'})
        self.assertEqual(status, 502); self.assertFalse(result['ok'])

    def test_bridge_rejects_missing_or_false_activation_evidence(self):
        req = {'action': 'converter_apply', 'target': 'router_a'}
        good = {'ok': True, 'sha256': 'a'*64, 'state_sha256': 'b'*64, 'service_restarted': True, 'runtime_verified': True}
        self.assertTrue(server.bridge_result_ok(req, good))
        for key in ('sha256', 'state_sha256', 'service_restarted', 'runtime_verified'):
            bad = dict(good); del bad[key]
            self.assertFalse(server.bridge_result_ok(req, bad))
        self.assertFalse(server.bridge_result_ok(req, dict(good, runtime_verified=False)))


if __name__ == '__main__': unittest.main()
