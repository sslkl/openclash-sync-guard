"""Small, synthetic-only format roundtrips and loss-prevention regressions."""
import base64
import json
import math
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'vendor' / 'pyyaml-6.0.2'))
import converter_formats as formats
import converter_mellow as mellow
import converter_surge as surge
from subscription_converter import ConverterError
import test_converter_mellow as mellow_fixture
import test_converter_mellow_sources as source_fixture
import test_converter_surge as surge_fixture


class StructuredRoundtripRegressions(unittest.TestCase):
    def test_yaml_scientific_floats_keep_value_and_type(self):
        values = [1e20, -1e20, 1e-7, -1e-7, 5e-324, -5e-324,
                  sys.float_info.max, 0.0, -0.0]
        data = {'custom': {'values': values, 'quoted': '1e+20'}}
        restored, kind = formats.load(formats.dump(data, 'yaml'))
        self.assertEqual(kind, 'yaml')
        self.assertEqual(restored, data)
        for expected, actual in zip(values, restored['custom']['values']):
            self.assertIs(type(actual), float)
            self.assertEqual(math.copysign(1, actual), math.copysign(1, expected))

    def test_scientific_float_resolver_is_local_and_keeps_validation(self):
        self.assertIsInstance(formats.yaml_load('value: 1e+20')['value'], float)
        self.assertIsInstance(formats.yaml_load('value: "1e+20"')['value'], str)
        self.assertIsInstance(formats.yaml.safe_load('value: 1e+20')['value'], str)
        for text in ('value: 1e9999', 'value: 1e20\nvalue: 2e20', 'value: &a 1e20'):
            with self.subTest(case=text), self.assertRaises(ConverterError):
                formats.yaml_load(text)

    def test_c1_characters_in_keys_and_values_roundtrip(self):
        for point in range(0x7f, 0xa0):
            char = chr(point)
            data = {'version': 1, 'custom': {'key' + char: '中文' + char + 'suffix',
                                            'nested': [char, r'\u0085', '\n\t"\\']}}
            for kind in ('yaml', 'toml'):
                with self.subTest(point=point, kind=kind):
                    text = formats.dump(data, kind)
                    self.assertIn('中文', text)
                    self.assertEqual(formats.load(text, kind=kind)[0], data)


    def test_unicode_line_separators_and_noncharacters_roundtrip(self):
        for point in (0x2028, 0x2029, 0xfffe, 0xffff):
            char = chr(point)
            data = {'version': 1, 'key' + char: '中文' + char + 'suffix'}
            for kind in ('yaml', 'toml'):
                with self.subTest(point=point, kind=kind):
                    self.assertEqual(formats.load(formats.dump(data, kind), kind=kind)[0], data)


class MellowSourceRegressions(unittest.TestCase):
    def test_integer_text_fields_do_not_become_omitted_defaults(self):
        for field in ('host', 'net', 'sni', 'ps'):
            for number in (0, 123):
                value = dict(source_fixture.VM, net='h2')
                value[field] = number
                raw = source_fixture.uri(value)
                for source in (raw, base64.b64encode(raw.encode()).decode()):
                    with self.subTest(field=field, number=number):
                        with self.assertRaises(ConverterError) as exc:
                            source_fixture.check(source)
                        self.assertEqual(exc.exception.code, 'MELLOW_SOURCE')

    def numeric_node(self):
        value = dict(source_fixture.VM, v=2, port=443, aid=0, net='h2',
                     host='one.test,two.test', path='/relay', sni='tls.test')
        raw = source_fixture.uri(value)
        source_fixture.check(raw)
        return mellow.raw_uri_node(raw)

    def test_numeric_version_port_and_alterid_stay_supported(self):
        node = self.numeric_node()
        self.assertEqual(node['port'], 443)
        self.assertEqual(node['alterId'], 0)
        self.assertEqual(node['h2-opts'], {'host': ['one.test', 'two.test'], 'path': '/relay'})
        mellow.validate(mellow_fixture.config(node))

    @mellow_fixture.requires_official_parser
    def test_numeric_source_roundtrips_through_official_parser(self):
        node = self.numeric_node()
        parsed = mellow_fixture.MellowOfficialParserTests().parse_config(mellow_fixture.config(node))
        outbound = parsed['outbounds'][0]
        self.assertEqual(outbound['settings']['vnext'][0]['port'], node['port'])
        self.assertEqual(outbound['streamSettings']['httpSettings'],
                         {'host': ['one.test', 'two.test'], 'path': '/relay'})
        self.assertEqual(outbound['streamSettings']['tlsSettings']['serverName'], 'tls.test')


class SurgeQuotingRegressions(unittest.TestCase):
    def source(self, group):
        return surge_fixture.SOURCE.replace('Probe=select,Synthetic-SS,DIRECT', group)

    def test_quoted_comma_reference_is_not_two_different_policies(self):
        with self.assertRaises(ConverterError) as exc:
            surge.parse(self.source('Probe=select,"Synthetic-SS,DIRECT"'))
        self.assertEqual(exc.exception.code, 'SURGE_FORMAT')

    def test_quoted_url_option_roundtrips_with_its_comma(self):
        source = self.source('Probe=url-test,Synthetic-SS,"url=https://example.test/a,b",interval=300')
        text, metadata = surge.parse(source)
        self.assertEqual(surge.parse(text)[1], metadata)
        result = surge.restore(surge_fixture.native(), metadata)
        self.assertEqual(result['proxy-groups'][0]['url'], 'https://example.test/a,b')
        self.assertEqual(result['proxy-groups'][0]['proxies'], ['Synthetic-SS'])

    def test_quoted_parenthesis_reference_preserves_its_name(self):
        source = self.source('Probe=select,"Node)",DIRECT').replace('Synthetic-SS=', '"Node)"=')
        text, metadata = surge.parse(source)
        self.assertEqual(surge.parse(text)[1], metadata)
        result = surge.restore(surge_fixture.native(('Node)',)), metadata)
        self.assertEqual(result['proxy-groups'][0]['proxies'], ['Node)', 'DIRECT'])

    def test_group_fields_are_tokenized_once(self):
        with patch.object(surge, 'fields', wraps=surge.fields) as split:
            surge.parse(surge_fixture.SOURCE)
        self.assertEqual(sum(call.args[0] == 'select,Synthetic-SS,DIRECT'
                             for call in split.call_args_list), 1)

    def test_quoted_duplicate_options_still_rejected(self):
        source = self.source('Probe=url-test,Synthetic-SS,url=https://example.test/,"interval=300",interval=600')
        with self.assertRaises(ConverterError):
            surge.parse(source)



class UnicodeScalarRegressions(unittest.TestCase):
    def test_json_escaped_supplementary_keys_and_values_roundtrip(self):
        data = {'version': 1, 'custom': {'name\U0001f642': '中文\U0001f680',
                                       'nested': ['\U00010000', '\U0010ffff']}}
        parsed, kind = formats.load(json.dumps(data))
        self.assertEqual((parsed, kind), (data, 'yaml'))
        for kind in ('yaml', 'toml'):
            with self.subTest(kind=kind):
                rendered = formats.dump(parsed, kind)
                self.assertEqual(rendered.encode().decode(), rendered)
                self.assertEqual(formats.load(rendered, kind=kind)[0], data)

    def test_unpaired_surrogates_rejected_in_parsed_and_native_shapes(self):
        for value in ('\ud800', '\udfff', '\ud800\ud800', '\udfff\ud800'):
            for data in ({'custom': {'name': value}}, {'custom': {value: 'value'}}):
                with self.subTest(value=ascii(value), key=value in data['custom']):
                    with self.assertRaises(ConverterError) as exc:
                        formats.yaml_load(json.dumps(data))
                    self.assertEqual(exc.exception.code, 'CONFIG_FORMAT')
                    with self.assertRaises(ConverterError):
                        formats.shape(data)
                    for kind in ('yaml', 'toml'):
                        with self.assertRaises(ConverterError):
                            formats.dump(data, kind)

    def test_literal_and_escaped_supplementary_keys_are_duplicates(self):
        for value in ('"\U0001f642": 1\n"\\ud83d\\ude42": 2\n',
                      '"\\ud83d\\ude42": 1\n"\U0001f642": 2\n'):
            with self.subTest(value=ascii(value)), self.assertRaises(ConverterError):
                formats.yaml_load(value)

    def test_export_validation_rejects_escaped_unpaired_surrogates(self):
        for field in ('name', 'server'):
            node = dict(mellow_fixture.SS)
            node[field] = '\ud800'
            with self.subTest(field=field), self.assertRaises(ConverterError) as exc:
                surge_fixture.engine.validate_export(json.dumps({'proxies': [node]}), {'target': 'clash'})
            self.assertEqual(exc.exception.code, 'RESULT')


class MellowUnicodeRegressions(unittest.TestCase):
    def repaired(self):
        node = dict(mellow_fixture.SS, name='Synthetic-\U0001f642', password='synthetic-\U0001f680')
        normalized = json.dumps({'proxies': [node]})
        mellow.validate_sources([normalized.encode()])
        native = mellow_fixture.NATIVE.replace(mellow_fixture.SS['name'], node['name'])
        normalized = json.dumps({'proxies': [node, mellow_fixture.VM]})
        return node, mellow.repair(native, normalized)

    def test_escaped_json_names_and_passwords_survive_source_check_and_repair(self):
        node, repaired = self.repaired()
        self.assertIn(mellow.endpoint(node), repaired)
        self.assertIn('Proxy, ' + node['name'] + ':Synthetic-VMess,', repaired)
        mellow.validate(repaired)

    @mellow_fixture.requires_official_parser
    def test_escaped_json_names_and_passwords_roundtrip_official_parser(self):
        node, repaired = self.repaired()
        parsed = mellow_fixture.MellowOfficialParserTests().parse_config(repaired)
        outbound = next(value for value in parsed['outbounds'] if value['tag'] == node['name'])
        self.assertEqual(outbound['settings']['servers'][0]['password'], node['password'])
        self.assertEqual(parsed['routing']['balancers'][0]['selector'],
                         [node['name'], mellow_fixture.VM['name']])


class SurgeRuleBoundaryRegressions(unittest.TestCase):
    def source(self, name):
        return surge_fixture.SOURCE.replace('Probe=select', '"' + name + '"=select').replace(
            ',Probe', ',"' + name + '"')

    def restored(self, source, **kwargs):
        text, metadata = surge.parse(source, **kwargs)
        self.assertEqual(surge.parse(text)[1], metadata)
        return surge.restore(surge_fixture.native(), metadata)

    def test_quoted_rule_targets_keep_parentheses_and_quote_characters(self):
        for name in ('Exit)', 'Exit(', "Exit'Label"):
            with self.subTest(name=name):
                result = self.restored(self.source(name))
                self.assertEqual(result['rules'], ['DOMAIN,probe.example.test,' + name, 'MATCH,' + name])
                self.assertEqual(result['proxy-groups'][0]['name'], name)

    def test_quoted_ruleset_target_survives_expansion_and_second_intake(self):
        source = self.source('Exit)').replace('DOMAIN,probe.example.test,"Exit)"',
                                             'RULE-SET,asset:rules,"Exit)",no-resolve')
        result = self.restored(source, dependency=lambda *_: 'IP-CIDR,192.0.2.0/24\n')
        self.assertEqual(result['rules'], ['IP-CIDR,192.0.2.0/24,Exit),no-resolve', 'MATCH,Exit)'])

    def test_quoted_regex_comma_survives_direct_and_imported_rules(self):
        expression = '^test{1,3}$'
        for imported in (False, True):
            with self.subTest(imported=imported):
                rule = 'RULE-SET,asset:rules,Probe' if imported else 'DOMAIN-REGEX,"' + expression + '",Probe'
                source = surge_fixture.SOURCE.replace('DOMAIN,probe.example.test,Probe', rule)
                result = self.restored(source, dependency=lambda *_: 'DOMAIN-REGEX,"' + expression + '"\n')
                self.assertEqual(result['rules'], ['DOMAIN-REGEX,' + expression + ',Probe', 'MATCH,Probe'])

    def test_restore_does_not_reparse_normalized_rule_strings(self):
        _, metadata = surge.parse(surge_fixture.SOURCE)
        with patch.object(surge, 'rule', side_effect=AssertionError('normalized rules must not be reparsed')):
            result = surge.restore(surge_fixture.native(), metadata)
        self.assertEqual(result['rules'][-1], 'MATCH,Probe')

    def test_quoted_unknown_rule_targets_still_fail_reference_validation(self):
        for name in ('Missing)', 'Missing(', "Missing'Label"):
            source = surge_fixture.SOURCE.replace('FINAL,Probe', 'FINAL,"' + name + '"')
            _, metadata = surge.parse(source)
            with self.subTest(name=name), self.assertRaises(ConverterError) as exc:
                surge.restore(surge_fixture.native(), metadata)
            self.assertEqual(exc.exception.code, 'SURGE_FORMAT')

    def test_no_resolve_policy_is_not_confused_with_a_rule_modifier(self):
        source = self.source('no-resolve').replace('DOMAIN,probe.example.test,"no-resolve"',
            'IP-CIDR,192.0.2.0/24,"no-resolve",no-resolve')
        result = self.restored(source)
        self.assertEqual(result['rules'], ['IP-CIDR,192.0.2.0/24,no-resolve,no-resolve', 'MATCH,no-resolve'])


if __name__ == '__main__':
    unittest.main()
