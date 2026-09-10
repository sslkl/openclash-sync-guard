"""Independent, synthetic-only merge boundaries; no router/server entrypoints.

These tests deliberately keep genuine regressions red. They never read runtime
configuration, invoke the privileged bridge, or contact a network endpoint.
"""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT.parent / 'vendor' / 'pyyaml-6.0.2'):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import converter_apply as merge


def node(name, **extra):
    return dict(name=name, type='http', server='192.0.2.23', port=8080, **extra)


def baseline():
    return {'proxies': [node('old')],
            'proxy-groups': [{'name': 'Existing', 'type': 'select', 'proxies': ['old', 'DIRECT']}],
            'rules': ['DOMAIN,baseline.example.test,DIRECT', 'MATCH,Existing'],
            'dns': {'enable': True, 'nameserver': ['192.0.2.53']},
            'tun': {'enable': False}, 'metadata': {'fixture': 'synthetic-only'}}


def text(value):
    # Escaped JSON is a lossless YAML input, including YAML-sensitive scalars.
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(',', ':'))


class ConverterAuditBoundaries(unittest.TestCase):
    def setUp(self):
        # Also safe when invoked outside the evidence runner. All production
        # transports/process constructors are traps, not real local listeners.
        for target in ('socket.socket', 'socket.create_connection', 'socket.getaddrinfo',
                       'subprocess.Popen', 'os.system'):
            self.enterContext(mock.patch(target, side_effect=AssertionError('offline test attempted external I/O')))

    def plan(self, first=None, second=None, **options):
        return merge.plan(text(baseline() if first is None else first),
                          text({'proxies': [node('fresh')]} if second is None else second), **options)

    def assert_error(self, code, first=None, second=None, **options):
        with self.assertRaises(merge.MergeError) as caught:
            self.plan(first, second, **options)
        self.assertEqual(caught.exception.code, code)

    def test_cross_namespace_and_group_conflicts_never_overwrite(self):
        cases = {
            'new-group-vs-old-node': [{'name': 'old', 'type': 'select', 'proxies': ['fresh']}],
            'new-group-vs-new-node': [{'name': 'fresh', 'type': 'select', 'proxies': ['old']}],
            'changed-existing-group': [{'name': 'Existing', 'type': 'select', 'proxies': ['fresh']}],
            'duplicate-identical-groups': [{'name': 'Added', 'type': 'select', 'proxies': ['fresh']}] * 2,
        }
        for label, groups in cases.items():
            with self.subTest(case=label):
                first = baseline()
                before = copy.deepcopy(first)
                self.assert_error('CONFLICT', first, {'proxies': [node('fresh')], 'proxy-groups': groups}, mode='merge')
                self.assertEqual(first, before)

    def test_identical_nested_mapping_order_preserves_original_bytes(self):
        first = baseline()
        first['proxies'][0]['smux'] = {'enabled': True, 'padding': False}
        imported = dict(reversed(list(first['proxies'][0].items())))
        imported['smux'] = {'padding': False, 'enabled': True}
        raw = text(first) + '\n\n'
        result = merge.plan(raw, text({'proxies': [imported]}))
        self.assertTrue(result['summary']['no_change'])
        self.assertEqual(result['content'], raw)
        self.assertEqual(result['sha256'], hashlib.sha256(raw.encode()).hexdigest())

    def test_same_name_boolean_numeric_content_change_is_a_conflict(self):
        for before, after in (({'udp': False}, {'udp': 0}),
                              ({'smux': {'enabled': True}}, {'smux': {'enabled': 1}})):
            with self.subTest(shape='nested' if 'smux' in before else 'scalar'):
                first = baseline()
                first['proxies'][0].update(before)
                imported = node('old', **after)
                self.assert_error('CONFLICT', first, {'proxies': [imported]})

    def test_appending_members_detects_a_new_cross_kind_cycle(self):
        second = {'proxies': [node('fresh', **{'dialer-proxy': 'Existing'})]}
        # A node may use this existing group until adding itself as a member
        # closes Existing -> fresh -> Existing.
        self.assertTrue(self.plan(second=second)['ok'])
        self.assert_error('REFERENCE', second=second, group='Existing')

    def test_diamond_and_repeated_edges_preserve_order_without_false_cycles(self):
        second = {'proxies': [node('left', **{'dialer-proxy': 'old'}),
                              node('right', **{'dialer-proxy': 'old'})],
                  'proxy-groups': [
                      {'name': 'Left', 'type': 'select', 'proxies': ['left', 'DIRECT']},
                      {'name': 'Right', 'type': 'select', 'proxies': ['right', 'old']},
                      {'name': 'Top', 'type': 'select', 'proxies': ['Left', 'Right', 'Left', 'DIRECT']}],
                  'rules': ['DOMAIN,new.example.test,Top']}
        result = self.plan(second=second, mode='merge', group='Existing')
        parsed = merge.document(result['content'], baseline=True)
        self.assertEqual(parsed['proxy-groups'][1:], second['proxy-groups'])
        self.assertEqual(parsed['proxy-groups'][0]['proxies'], ['old', 'DIRECT', 'left', 'right'])
        self.assertEqual(result['summary']['nodes_added'], 2)
        self.assertEqual(result['summary']['groups_added'], 3)
        self.assertEqual(result['summary']['group_members_added'], 2)

    def test_providers_resolve_only_against_the_preserved_baseline(self):
        first = baseline()
        first['proxy-providers'] = {'known': {'type': 'file', 'path': './synthetic-nodes.yaml'}}
        first['rule-providers'] = {'known-rules': {'type': 'file', 'path': './synthetic-rules.yaml'}}
        second = {'proxies': [node('fresh')],
                  'proxy-groups': [{'name': 'Added', 'type': 'select', 'proxies': ['fresh'], 'use': ['known']}],
                  'rules': ['RULE-SET,known-rules,Added'],
                  'proxy-providers': {'injected': {}, 'known': {'replacement': True}},
                  'rule-providers': {'injected': {}, 'known-rules': {'replacement': True}}}
        result = self.plan(first, second, mode='merge')
        parsed = merge.document(result['content'], baseline=True)
        for key in ('proxy-providers', 'rule-providers'):
            self.assertEqual(parsed[key], first[key])
        bad_group = copy.deepcopy(second)
        bad_group['proxy-groups'][0]['use'] = ['injected']
        self.assert_error('REFERENCE', first, bad_group, mode='merge')
        bad_rule = copy.deepcopy(second)
        bad_rule['rules'] = ['RULE-SET,injected,Added']
        self.assert_error('REFERENCE', first, bad_rule, mode='merge')

    def test_nodes_mode_ignores_unselected_sections_even_when_shapes_are_invalid(self):
        second = {'proxies': [node('fresh')], 'proxy-groups': 'not-a-list',
                  'rules': {'not': 'a-list'}, 'dns': {'enable': False},
                  'tun': {'enable': True}, 'proxy-providers': {'injected': {}}}
        result = self.plan(second=second)
        expected = baseline()
        expected['proxies'].append(node('fresh'))
        self.assertEqual(merge.document(result['content'], baseline=True), expected)
        self.assertEqual(result['summary']['groups_added'], 0)
        self.assertEqual(result['summary']['rules_added'], 0)

    def test_rule_deduplication_preserves_first_final_and_no_resolve(self):
        first = baseline()
        first['rules'] = ['DOMAIN,duplicate.example.test,DIRECT', 'FINAL,Existing',
                          'DOMAIN,after-final.example.test,REJECT', 'MATCH,DIRECT']
        rule = 'IP-CIDR,198.51.100.0/24,Existing,no-resolve'
        added = 'DOMAIN,fresh.example.test,fresh'
        second = {'proxies': [node('fresh')],
                  'rules': [first['rules'][0], rule, rule, added, 'MATCH,fresh', 'FINAL,fresh']}
        result = self.plan(first, second, mode='merge')
        parsed = merge.document(result['content'], baseline=True)
        self.assertEqual(parsed['rules'], first['rules'][:1] + [rule, added] + first['rules'][1:])
        self.assertEqual(result['summary']['rules_added'], 2)
        self.assertEqual(result['summary']['final_rules_ignored'], 2)
        again = merge.plan(result['content'], text(second), mode='merge')
        self.assertTrue(again['summary']['no_change'])
        self.assertEqual(again['content'], result['content'])

    def test_membership_only_change_is_not_reported_as_no_change(self):
        first = baseline()
        first['proxy-groups'][0]['proxies'] = ['DIRECT']
        result = self.plan(first, {'proxies': [node('old')]}, group='Existing')
        parsed = merge.document(result['content'], baseline=True)
        self.assertEqual(parsed['proxy-groups'][0]['proxies'], ['DIRECT', 'old'])
        self.assertEqual(parsed['proxies'], first['proxies'])
        self.assertEqual(parsed['rules'], first['rules'])
        self.assertEqual(result['summary']['nodes_added'], 0)
        self.assertEqual(result['summary']['group_members_added'], 1)
        self.assertFalse(result['summary']['no_change'])

    def test_selected_groups_require_supported_kind_and_static_members(self):
        for kind in ('select', 'url-test', 'fallback', 'load-balance'):
            with self.subTest(kind=kind):
                first = baseline()
                first['proxy-groups'][0]['type'] = kind
                result = self.plan(first, group='Existing')
                self.assertEqual(merge.document(result['content'], baseline=True)['proxy-groups'][0]['proxies'],
                                 ['old', 'DIRECT', 'fresh'])
        first = baseline()
        first['proxy-groups'][0]['type'] = 'relay'
        self.assert_error('REFERENCE', first, group='Existing')
        first = baseline()
        del first['proxy-groups'][0]['proxies']
        self.assert_error('REFERENCE', first, group='Existing')

    def test_deep_mixed_graph_is_iterative_and_rejects_long_cycle(self):
        count = 1536  # Deeper than Python's normal recursion limit, flat YAML.
        rows = [node('chain-%04d' % i, **{'dialer-proxy': 'chain-%04d' % (i + 1) if i + 1 < count else 'old'})
                for i in range(count)]
        second = {'proxies': rows,
                  'proxy-groups': [{'name': 'Entry', 'type': 'select', 'proxies': ['chain-0000']}]}
        result = self.plan(second=second, mode='merge')
        parsed = merge.document(result['content'], baseline=True)
        self.assertEqual(parsed['proxies'][1:], rows)
        self.assertEqual(result['summary']['nodes_added'], count)
        second['proxies'][-1]['dialer-proxy'] = 'Entry'
        self.assert_error('REFERENCE', second=second, mode='merge')

    def test_merged_structure_budget_is_checked_before_returning_success(self):
        first = {'proxies': [node('old-%04d' % i) for i in range(2100)],
                 'proxy-groups': [], 'rules': ['MATCH,DIRECT']}
        second = {'proxies': [node('new-%04d' % i) for i in range(2100)]}
        # Both inputs fit the real 20,000-value parser budget and 1 MiB byte cap;
        # their combined output does not fit the structure budget.
        self.assertEqual(len(merge.document(text(first), baseline=True)['proxies']), 2100)
        self.assertEqual(len(merge.document(text(second))['proxies']), 2100)
        self.assert_error('CONTENT', first, second)

    def test_output_byte_budget_counts_utf8_and_the_final_newline(self):
        first, second = baseline(), {'proxies': [node('新增-%d' % i) for i in range(4)]}
        expected = self.plan(first, second)['content']
        maximum = len(expected.encode('utf-8'))
        self.assertLess(max(len(text(first).encode()), len(text(second).encode())), maximum - 1)
        with mock.patch.object(merge, 'MAX_BYTES', maximum):
            result = self.plan(first, second)
            self.assertEqual(result['content'], expected)
            self.assertEqual(result['sha256'], hashlib.sha256(expected.encode()).hexdigest())
        with mock.patch.object(merge, 'MAX_BYTES', maximum - 1):
            self.assert_error('CONTENT', first, second)

    def test_utf8_name_and_rule_byte_limits_have_exact_edges(self):
        name = chr(0x1F642) * 128
        self.assertEqual(len(name.encode()), 512)
        self.assertTrue(self.plan(second={'proxies': [node(name)]})['ok'])
        self.assert_error('CONTENT', second={'proxies': [node(name + 'x')]})
        self.assert_error('REQUEST', group=name + 'x')
        prefix, suffix = 'DOMAIN,', ',DIRECT'
        room = 8192 - len(prefix.encode()) - len(suffix.encode())
        rule = prefix + '中' * (room // 3) + 'x' * (room % 3) + suffix
        self.assertEqual(len(rule.encode()), 8192)
        second = {'proxies': [node('fresh')], 'rules': [rule]}
        result = self.plan(second=second, mode='merge')
        self.assertIn(rule, merge.document(result['content'], baseline=True)['rules'])
        second['rules'] = [rule.replace(suffix, 'x' + suffix)]
        self.assert_error('CONTENT', second=second, mode='merge')

    def test_merged_opaque_scalars_are_lossless_on_yaml_reintake(self):
        for codepoint in (0x85, 0x2028, 0x2029, 0xFFFE, 0xFFFF):
            for placement in ('value-only', 'key-and-value'):
                with self.subTest(codepoint=hex(codepoint), placement=placement):
                    first = baseline()
                    marker = 'left' + chr(codepoint) + 'right'
                    key = 'key-' + chr(codepoint) if placement == 'key-and-value' else 'plain-key'
                    first['metadata'] = {'note': marker, key: [marker, False, 1e20]}
                    self.assertEqual(merge.document(text(first), baseline=True), first)
                    result = self.plan(first)
                    expected = copy.deepcopy(first)
                    expected['proxies'].append(node('fresh'))
                    self.assertEqual(json.loads(result['content']), expected)
                    try:
                        reparsed = merge.document(result['content'], baseline=True)
                    except merge.MergeError as exc:
                        self.fail('Successful plan emitted YAML that cannot be re-intaken: ' + exc.code)
                    self.assertEqual(reparsed, expected)
                    again = merge.plan(result['content'], text({'proxies': [node('fresh')]}))
                    self.assertTrue(again['summary']['no_change'])
                    self.assertEqual(again['content'], result['content'])


if __name__ == '__main__':
    unittest.main()
