"""Pure format audit regressions; synthetic data, no engine or external parser."""
import base64
import copy
import itertools
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'vendor' / 'pyyaml-6.0.2'))
import converter_formats as formats
import converter_mellow as mellow
import converter_surge as surge
from subscription_converter import ConverterError


NON_TEXT = (None, False, True, 0, 1.5, [], {}, (), set(), bytearray(b'custom: {}'))
SURGE_TEXT = ('[Proxy]\n'
              'N=ss,192.0.2.1,443,encrypt-method=aes-128-gcm,password=synthetic\n'
              '[Proxy Group]\n"出口 🚦"=select,N,DIRECT\n'
              '[Rule]\nDOMAIN-REGEX,"a,b","出口 🚦"\nFINAL,"出口 🚦"\n')


class ControlledErrors(unittest.TestCase):
    def assert_error(self, code, function, *args, **kwargs):
        with self.assertRaises(ConverterError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), code)

    def test_yaml_invalid_input_types_have_config_error(self):
        for value in NON_TEXT:
            with self.subTest(value=repr(value)):
                self.assert_error('CONFIG_FORMAT', formats.yaml_load, value)

    def test_auto_load_invalid_input_types_have_config_error(self):
        for value in NON_TEXT + (b'custom: {}',):
            with self.subTest(value=repr(value)):
                self.assert_error('CONFIG_FORMAT', formats.load, value)

    def test_explicit_toml_invalid_input_types_have_config_error(self):
        for value in NON_TEXT + (b'version=1',):
            with self.subTest(value=repr(value)):
                self.assert_error('CONFIG_FORMAT', formats.load, value, kind='toml')

    def test_detection_invalid_input_types_have_config_error(self):
        for value in NON_TEXT + (b'version=1',):
            with self.subTest(value=repr(value)):
                self.assert_error('CONFIG_FORMAT', formats.is_toml, value)

    def test_toml_dump_nonmapping_roots_have_config_error(self):
        for value in (None, False, True, 0, 1.5, 'synthetic', [], [1, {'x': 2}]):
            with self.subTest(value=value):
                # YAML still permits scalar/list roots; only TOML needs a table.
                decoded = formats.yaml_load(formats.dump(value, 'yaml'))
                self.assertEqual(decoded, value)
                self.assertIs(type(decoded), type(value))
                self.assert_error('CONFIG_FORMAT', formats.dump, value, 'toml')

    def test_surge_parse_nontext_inputs_have_surge_error(self):
        for value in NON_TEXT + (SURGE_TEXT.encode(),):
            with self.subTest(value=repr(value)):
                self.assert_error('SURGE_FORMAT', surge.parse, value)

    def test_surge_fields_nontext_inputs_have_surge_error(self):
        for value in NON_TEXT + (b'a,b',):
            for keep_quotes in (False, True):
                with self.subTest(value=repr(value), keep_quotes=keep_quotes):
                    self.assert_error('SURGE_FORMAT', surge.fields, value, keep_quotes=keep_quotes)

    def test_surge_policy_surrogates_have_surge_error(self):
        for value in ('\ud800', '\udfff', 'name\ud800', '\ud83d\udea6'):
            with self.subTest(value=ascii(value), entry='policy'):
                self.assert_error('SURGE_FORMAT', surge.policy, value)
            with self.subTest(value=ascii(value), entry='parse'):
                self.assert_error('SURGE_FORMAT', surge.parse, SURGE_TEXT.replace('出口 🚦', value))


class AcceptedShapeContracts(unittest.TestCase):
    def test_yaml_bytes_and_empty_input_contracts_are_preserved(self):
        text = 'custom: {name: "合成 🚦", enabled: true}\r\n'
        expected = {'custom': {'name': '合成 🚦', 'enabled': True}}
        for value in (text, text.encode()):
            with self.subTest(input_type=type(value).__name__):
                self.assertEqual(formats.yaml_load(value), expected)
                self.assertEqual(formats.load(value, kind='yaml'), (expected, 'yaml'))
        for value in ('', b'', '# synthetic comment\r\n'):
            with self.subTest(empty=repr(value)):
                self.assertIsNone(formats.yaml_load(value))
                with self.assertRaises(ConverterError) as caught:
                    formats.load(value, kind='yaml')
                self.assertEqual(caught.exception.code, 'CONFIG_FORMAT')
        self.assertEqual(formats.load('', kind='toml'), ({}, 'toml'))
        self.assertEqual(formats.load(formats.dump({}, 'toml'), kind='toml'), ({}, 'toml'))

    def test_duplicate_keys_are_rejected_across_structured_formats(self):
        cases = ((formats.yaml_load, 'outer: {x: 1, x: 2}'),
                 (formats.yaml_load, r'{"\ud83d\udea6": 1, "🚦": 2}'),
                 (formats.json_load, '{"x": 1, "x": 2}'),
                 (formats.json_load, r'{"\ud83d\udea6": 1, "🚦": 2}'),
                 (lambda text: formats.load(text, kind='toml'), 'version=1\nversion=2\n'),
                 (lambda text: formats.load(text, kind='toml'), 'x={a=1,a=2}\n'))
        for function, text in cases:
            with self.subTest(text=ascii(text)), self.assertRaises(ConverterError) as caught:
                function(text)
            self.assertEqual(caught.exception.code, 'CONFIG_FORMAT')

    def test_shape_budgets_and_unsafe_yaml_are_unchanged(self):
        self.assertEqual(len(formats.shape([0] * 19999)), 19999)
        value = 0
        for _ in range(32):
            value = [value]
        self.assertIs(formats.shape(value), value)
        for invalid in ([0] * 20000, [value]):
            with self.assertRaises(ConverterError) as caught:
                formats.shape(invalid)
            self.assertEqual(caught.exception.code, 'CONFIG_FORMAT')
        for text in ('x: &a []\ny: *a', 'x: {<<: {a: 1}}', 'x: !!python/object:synthetic {}',
                     'x: .nan', 'x: ' + '[' * 34 + '0' + ']' * 34):
            with self.subTest(text=text[:64]), self.assertRaises(ConverterError) as caught:
                formats.yaml_load(text)
            self.assertEqual(caught.exception.code, 'CONFIG_FORMAT')

    def test_surge_policy_byte_limit_is_not_a_character_limit(self):
        for char, count in (('a', 256), ('é', 128), ('🚦', 64)):
            with self.subTest(char=char):
                self.assertEqual(surge.policy(char * count), char * count)
                with self.assertRaises(ConverterError) as caught:
                    surge.policy(char * (count + 1))
                self.assertEqual(caught.exception.code, 'SURGE_FORMAT')

    def test_surge_crlf_unicode_quotes_and_backslashes_are_preserved(self):
        _, expected = surge.parse(SURGE_TEXT)
        self.assertEqual(expected['rule_targets'], ['出口 🚦', '出口 🚦'])
        self.assertEqual(expected['rules'], ['DOMAIN-REGEX,a,b,出口 🚦', 'MATCH,出口 🚦'])
        for ending in ('\n', '\r\n', '\r'):
            with self.subTest(ending=repr(ending)):
                rewritten, metadata = surge.parse(SURGE_TEXT.replace('\n', ending))
                self.assertEqual(metadata, expected)
                self.assertEqual(surge.parse(rewritten)[1], expected)
        self.assertEqual(surge.fields(r'one,"x\"y,z",(a,b)'), ['one', r'x\"y,z', '(a,b)'])
        self.assertEqual(surge.fields(r'one,"x\"y,z",(a,b)', keep_quotes=True),
                         ['one', r'"x\"y,z"', '(a,b)'])

    def test_duplicate_unicode_surge_labels_remain_errors(self):
        for text in (SURGE_TEXT.replace('[Rule]', '"出口 🚦"=select,DIRECT\n[Rule]'),
                     SURGE_TEXT.replace('[Proxy Group]', '"N"=ss,192.0.2.2,443\n[Proxy Group]')):
            with self.subTest(text=text), self.assertRaises(ConverterError) as caught:
                surge.parse(text)
            self.assertEqual(caught.exception.code, 'SURGE_FORMAT')


class WhitespaceScanContracts(unittest.TestCase):
    def test_toml_detection_matches_legacy_heuristic_on_bounded_corpus(self):
        legacy = re.compile(r'''^\s*(?:version|"version"|'version')\s*=''', re.M)
        whitespace = ('', ' ', '\t', '\r', '\n', '\r\n', '\v', '\f', '\u0085', '\u2003', '\u2028')
        for first, second, key, tail in itertools.product(whitespace, whitespace,
                ('version', '"version"', "'version'", 'Version', 'versioned'), ('=1', ' \n=1', ': 1')):
            text = first + second + key + tail
            with self.subTest(text=ascii(text)):
                self.assertEqual(formats.is_toml(text), bool(legacy.search(text)))
        self.assertFalse(formats.is_toml('\n' * 4000 + 'custom: {}\n'))
        self.assertTrue(formats.is_toml('\n' * 4000 + '"version" = 1\n'))

    def test_mellow_section_recognition_matches_legacy_trimmed_capture(self):
        legacy = re.compile(r'\[\s*([^\]]*)\s*\]')
        row = 'N, builtin, http, address=192.0.2.1, port=80, user=, pass='
        for leading, name, trailing, closing in itertools.product(('', ' ', '\t', '\u2003'),
                ('Endpoint', 'endpoint', 'Other', '', 'End]point'), ('', ' ', '\u0085'), ('', ']')):
            header = '[' + leading + name + trailing + closing
            match = legacy.fullmatch(header.strip())
            expected = [(1, [part.strip() for part in row.split(',')])] if match and match[1].strip() == 'Endpoint' else []
            with self.subTest(header=ascii(header)):
                self.assertEqual(list(mellow.rows(header + '\r\n' + row)), expected)

    def test_mellow_malformed_padded_sections_remain_rejected(self):
        for suffix in ('x', 'x]]'):
            text = '[Endpoint]\n[' + ' ' * 512 + suffix + '\n'
            with self.subTest(suffix=suffix), self.assertRaises(ConverterError) as caught:
                mellow.validate(text)
            self.assertEqual(caught.exception.code, 'RESULT')

    def test_mellow_padded_section_repair_preserves_other_bytes(self):
        node = dict(name='合成 🚦', type='ss', server='192.0.2.1', port=443,
                    cipher='aes-128-gcm', password='synthetic \\" 🚦')
        before = copy.deepcopy(node)
        prefix = '; 合成 header\r\n[ \tEndpoint\u2003 ]\r\n'
        suffix = '\r\n[RoutingRule]\rFINAL,DIRECT'
        native = prefix + '合成 🚦, ss, ss://Og@192.0.2.1:443' + suffix
        repaired = mellow.repair(native, formats.dump({'proxies': [node]}, 'yaml'))
        self.assertEqual(repaired, prefix + mellow.endpoint(node) + suffix)
        uri = list(mellow.rows(repaired))[0][1][2]
        auth = uri.split('://', 1)[1].split('@', 1)[0]
        self.assertEqual(base64.urlsafe_b64decode(auth + '=' * (-len(auth) % 4)).decode(),
                         'aes-128-gcm:' + node['password'])
        self.assertEqual(node, before)
        self.assertIsNone(mellow.validate(repaired))


if __name__ == '__main__':
    unittest.main()
