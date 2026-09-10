"""Post-fix boundaries: synthetic values only; no transports or service entrypoints."""
import base64
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

import yaml
import converter_apply as merge
import converter_engine as engine
import converter_formats as formats
from subscription_converter import ConverterError


def node(name='old', **extra):
    return dict(name=name, type='http', server='192.0.2.60', port=8080, **extra)


def baseline():
    return {'proxies': [node()],
            'proxy-groups': [{'name': 'Existing', 'type': 'select', 'proxies': ['old', 'DIRECT']}],
            'rules': ['MATCH,Existing']}


def text(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(',', ':'))


def token_count(raw):
    # Independent lexical oracle, not a second scan inside product code.
    return sum(1 for _ in yaml.scan(raw, Loader=yaml.SafeLoader))


def token_fixture(size):
    first = baseline()
    first['proxies'][0]['audit'] = {str(i): {} for i in range(size)}
    second = {'proxies': [node('fresh', audit={str(i): {} for i in range(size)})]}
    combined = copy.deepcopy(first)
    combined['proxies'].extend(copy.deepcopy(second['proxies']))
    return first, second, combined


class OfflineCase(unittest.TestCase):
    def setUp(self):
        for target in ('socket.socket', 'socket.create_connection', 'socket.getaddrinfo',
                       'subprocess.Popen', 'os.system'):
            self.enterContext(mock.patch(target, side_effect=AssertionError('offline I/O forbidden')))

    def assert_error(self, error, code, function, *args, **kwargs):
        with self.assertRaises(error) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)


class MergeFinalRegressions(OfflineCase):
    def test_nested_array_types_lengths_and_order_are_conflicts_in_both_namespaces(self):
        cases = {
            'bool-int-two-arrays': ([[True]], [[1]]),
            'int-float-in-object': ([{'items': [1]}], [{'items': [1.0]}]),
            'float-int-reverse': ([[{'n': 9007199254740992.0}]], [[{'n': 9007199254740992}]]),
            'array-order': ([['a', 'b']], [['b', 'a']]),
            'array-length': ([[], [None]], [[], [None, None]]),
            'array-vs-mapping': ([{'items': []}], [{'items': {}}]),
        }
        for namespace in ('proxies', 'proxy-groups'):
            for label, (before, after) in cases.items():
                with self.subTest(namespace=namespace, case=label):
                    first = baseline()
                    first[namespace][0]['audit'] = before
                    second = copy.deepcopy(first)
                    second[namespace][0]['audit'] = after
                    self.assert_error(merge.MergeError, 'CONFLICT', merge.plan,
                                      text(first), text(second), mode='merge')

    def test_reordered_maps_inside_typed_arrays_keep_crlf_comments_and_noop_bytes(self):
        def reordered(value):
            if isinstance(value, dict):
                return {key: reordered(item) for key, item in reversed(list(value.items()))}
            return [reordered(item) for item in value] if isinstance(value, list) else value

        first = baseline()
        first['proxies'][0]['audit'] = [
            {'z': [True, 1, 1.0, None, -0.0, 1e20], 'a': {'left': [], 'right': {}}}]
        first['proxy-groups'][0]['audit'] = [[{'z': False, 'a': ['synthetic', 0.0]}]]
        raw = '# synthetic no-op\r\n' + json.dumps(first, indent=2).replace('\n', '\r\n') + '\r\n\r\n'
        result = merge.plan(raw, text(reordered(first)), mode='merge', group='Existing')
        self.assertTrue(result['summary']['no_change'])
        self.assertEqual(result['summary']['group_members_added'], 0)
        self.assertEqual(result['content'].encode(), raw.encode())
        digest = hashlib.sha256(raw.encode()).hexdigest()
        self.assertEqual((result['sha256'], result['expected_sha256']), (digest, digest))
        self.assertEqual(text(merge.document(result['content'], baseline=True)), text(first))

    def test_combined_real_token_overflow_is_rejected_below_shape_and_byte_budgets(self):
        first, second, combined = token_fixture(8400)
        candidate = formats.dump(combined, 'yaml', compact=True)
        self.assertIs(formats.shape(combined), combined)
        self.assertLess(len(candidate.encode()), merge.MAX_BYTES)
        self.assertGreater(token_count(candidate), formats.UniqueLoader.max_tokens)
        for value, is_baseline in ((first, True), (second, False)):
            self.assertLess(token_count(text(value)), formats.UniqueLoader.max_tokens)
            self.assertEqual(merge.document(text(value), baseline=is_baseline), value)
        self.assert_error(merge.MergeError, 'CONTENT', merge.plan, text(first), text(second))

    def test_exact_output_token_budget_is_readable_and_one_less_rejects(self):
        first, second, combined = token_fixture(4)
        candidate = formats.dump(combined, 'yaml', compact=True)
        required = token_count(candidate)
        self.assertLess(max(token_count(text(first)), token_count(text(second))), required - 1)
        for limit in (required, required - 1):
            with self.subTest(limit=limit), mock.patch.object(formats.UniqueLoader, 'max_tokens', limit):
                if limit < required:
                    self.assert_error(merge.MergeError, 'CONTENT', merge.plan, text(first), text(second))
                    continue
                result = merge.plan(text(first), text(second))
                self.assertEqual(result['content'], candidate)
                self.assertEqual(merge.document(result['content'], baseline=True), combined)
                again = merge.plan(result['content'], text(second))
                self.assertTrue(again['summary']['no_change'])
                self.assertEqual(again['content'], result['content'])


class StrictJSONFinalRegressions(OfflineCase):
    targets = ('singbox', 'sssub', 'ssd')

    def setUp(self):
        super().setUp()
        # JSON positives and negatives must never be delegated to a YAML parser.
        for target in ('converter_formats.yaml_load', 'converter_formats.load', 'yaml.load', 'yaml.safe_load'):
            self.enterContext(mock.patch(target, side_effect=AssertionError('JSON used YAML fallback')))

    def document(self, target, row):
        return [row] if target == 'sssub' else {'servers' if target == 'ssd' else 'outbounds': [row]}

    def wire(self, target, raw):
        return 'ssd://' + base64.b64encode(raw.encode()).decode() if target == 'ssd' else raw

    def with_fragment(self, target, fragment):
        row = text(node())[:-1] + ',"audit":[[' + fragment + ']]}'
        array = '[' + row + ']'
        return array if target == 'sssub' else '{"%s":%s}' % ('servers' if target == 'ssd' else 'outbounds', array)

    def reject(self, target, raw):
        self.assert_error(ConverterError, 'CONFIG_FORMAT', formats.json_load, raw)
        self.assert_error(ConverterError, 'RESULT', engine.validate_export, self.wire(target, raw), {'target': target})

    def test_unicode_and_object_local_keys_are_valid_lossless_strict_json(self):
        row = node(tag='synthetic-\U00010000\U0001f642\U0010ffff\u2028\u2029', audit={
            'key\U0001f680': '\u2028line\u2029', 'items': [{'same': 1}, {'same': 1.0}],
            'A': False, 'a': None, 'é': 'NFC', 'e\u0301': 'NFD', 'finite': [1e308, -0.0]})
        for target in self.targets:
            expected = self.document(target, row)
            for ascii_only in (False, True):
                with self.subTest(target=target, ascii_only=ascii_only):
                    raw = json.dumps(expected, ensure_ascii=ascii_only, allow_nan=False)
                    # JSON re-encoding distinguishes bool/int/float as well as text.
                    self.assertEqual(text(formats.json_load(raw)), text(expected))
                    self.assertIsNone(engine.validate_export(self.wire(target, raw), {'target': target}))

    def test_duplicate_keys_at_root_and_nested_array_paths_are_rejected(self):
        fragments = {
            'literal-nested': '{"enabled":true,"enabled":false}',
            'escaped-nested': r'{"name":"one","na\u006de":"two"}',
            'supplementary-nested': '{"🙂":1,"\\ud83d\\ude42":2}',
        }
        for target in self.targets:
            for label, fragment in fragments.items():
                with self.subTest(target=target, case=label):
                    self.reject(target, self.with_fragment(target, fragment))
        # sssub's root is an array: root-object cases belong to the other targets.
        for target, key, escaped in (('singbox', 'outbounds', r'out\u0062ounds'),
                                     ('ssd', 'servers', r'ser\u0076ers')):
            for repeated in (key, escaped):
                with self.subTest(target=target, root_key=repeated):
                    raw = '{"%s":[%s],"%s":[%s]}' % (key, text(node()), repeated, text(node()))
                    self.reject(target, raw)

    def test_nested_json_surrogates_and_nonfinite_numbers_fail_closed(self):
        fragments = {
            'high-surrogate-value': r'{"value":"\ud800"}',
            'low-surrogate-key': r'{"\udfff":0}',
            'reversed-pair': r'{"value":"\ude42\ud83d"}',
            'two-high-surrogates': r'{"value":"\ud800\ud800"}',
            'nan': '{"value":NaN}', 'infinity': '{"value":Infinity}',
            'negative-infinity': '{"value":-Infinity}',
            'overflow': '{"value":1e309}', 'negative-overflow': '{"value":-1e309}',
        }
        for target in self.targets:
            for label, fragment in fragments.items():
                with self.subTest(target=target, case=label):
                    self.reject(target, self.with_fragment(target, fragment))

    def test_yaml_compatible_non_json_syntax_never_uses_fallback(self):
        for target in self.targets:
            raw = text(self.document(target, node()))
            cases = {
                'single-quotes': raw.replace('"', "'"),
                'unquoted-key': raw.replace('"server":', 'server: '),
                'trailing-comma': raw.replace('}]', '},]'),
                'comment': raw + '\n# synthetic YAML-only comment\n',
                'document-marker': '---\n' + raw,
            }
            for label, malformed in cases.items():
                with self.subTest(target=target, case=label):
                    self.reject(target, malformed)


if __name__ == '__main__':
    unittest.main()
