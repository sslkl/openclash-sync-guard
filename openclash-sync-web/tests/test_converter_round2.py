"""Synthetic format regressions; optional local Mihomo syntax checks only."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'vendor' / 'pyyaml-6.0.2'))
import converter_engine as engine
import converter_formats as formats
import converter_surge as surge
from subscription_converter import ConverterError

NODE = {'name': 'Synthetic-SS', 'type': 'ss', 'server': '192.0.2.1',
        'port': 443, 'cipher': 'aes-128-gcm', 'password': 'synthetic'}
SOURCE = '''[Proxy]
Synthetic-SS=ss,192.0.2.1,443,encrypt-method=aes-128-gcm,password=synthetic
[Proxy Group]
Probe=select,Synthetic-SS,DIRECT
[Rule]
DOMAIN,probe.example.test,Probe
FINAL,Probe
'''


def restored(rule, *, imported=False):
    source = SOURCE.replace('DOMAIN,probe.example.test,Probe',
                            'RULE-SET,asset:rules,Probe' if imported else rule + ',Probe')
    rewritten, metadata = surge.parse(source, dependency=lambda *_: rule + '\n')
    if surge.parse(rewritten)[1] != metadata:
        raise AssertionError('Surge second intake changed preservation metadata')
    document = {'proxies': [copy.deepcopy(NODE)], 'proxy-groups': [
        {'name': surge.SOURCE_PREFIX + '0', 'type': 'select', 'proxies': [NODE['name']]}]}
    return surge.restore(document, metadata)


class ClashExportFieldTests(unittest.TestCase):
    def test_old_field_full_exports_are_supported(self):
        for target in ('clash', 'clashr'):
            with self.subTest(target=target):
                engine.validate_export(json.dumps({'Proxy': [NODE]}),
                                       {'target': target, 'new_name': False, 'list': False})

    def test_list_mode_always_uses_new_field(self):
        for target in ('clash', 'clashr'):
            for new_name in (False, True):
                with self.subTest(target=target, new_name=new_name):
                    engine.validate_export(json.dumps({'proxies': [NODE]}),
                                           {'target': target, 'new_name': new_name, 'list': True})

    def test_default_and_explicit_new_field_remain_supported(self):
        for target in ('clash', 'clashr'):
            for opts in ({}, {'new_name': True}, {'list': True}):
                with self.subTest(target=target, options=opts):
                    engine.validate_export(json.dumps({'proxies': [NODE]}), {'target': target, **opts})

    def test_nonexpanded_and_script_default_modes_keep_new_fields(self):
        for target in ('clash', 'clashr'):
            for opts in ({'expand': False}, {'expand': False, 'script': True},
                         {'script': False}, {'script': True}):
                with self.subTest(target=target, options=opts):
                    engine.validate_export(json.dumps({'proxies': [NODE], 'Proxy': []}),
                                           {'target': target, 'new_name': False, **opts})

    def test_explicit_expansion_keeps_old_field_even_with_script_option(self):
        for script in (False, True):
            with self.subTest(script=script):
                engine.validate_export(json.dumps({'Proxy': [NODE], 'proxies': []}),
                                       {'target': 'clash', 'new_name': False, 'expand': True, 'script': script})

    def test_unselected_alias_cannot_hide_invalid_selected_field(self):
        for target in ('clash', 'clashr'):
            for opts, selected, other in (
                ({'new_name': False}, 'Proxy', 'proxies'),
                ({'new_name': True}, 'proxies', 'Proxy'),
                ({'new_name': False, 'list': True}, 'proxies', 'Proxy'),
                ({}, 'proxies', 'Proxy'),
                ({'new_name': False, 'expand': False}, 'proxies', 'Proxy'),
                ({'new_name': False, 'script': True}, 'proxies', 'Proxy'),
            ):
                for invalid in (None, [], {}, [NODE, NODE], [{'name': 'Invalid'}]):
                    with self.subTest(target=target, options=opts, invalid=invalid):
                        with self.assertRaises(ConverterError) as caught:
                            engine.validate_export(json.dumps({selected: invalid, other: [NODE]}),
                                                   {'target': target, **opts})
                        self.assertEqual(caught.exception.code, 'RESULT')

    def test_old_field_accepts_unicode_names_and_ipv6_servers(self):
        node = dict(NODE, name='合成-😀', server='2001:db8::1')
        document = {'Proxy': [node]}
        content = formats.dump(document, 'yaml')
        engine.validate_export(content, {'target': 'clash', 'new_name': False})
        self.assertEqual(formats.yaml_load(content), document)


class SurgeLogicalAliasTests(unittest.TestCase):
    def test_logical_aliases_are_canonicalized_at_every_depth(self):
        cases = (
            ('AND,((DEST-PORT,443),(IP6-CIDR,2001:db8::/32))',
             'AND,((DST-PORT,443),(IP-CIDR6,2001:db8::/32))'),
            ('OR,((DEST-PORT,443),(DEST-PORT,8443))',
             'OR,((DST-PORT,443),(DST-PORT,8443))'),
            ('NOT,((IP6-CIDR,2001:db8::/32,no-resolve))',
             'NOT,((IP-CIDR6,2001:db8::/32,no-resolve))'),
            ('AND,((OR,((DEST-PORT,443),(DEST-PORT,8443))),(NOT,((IP6-CIDR,2001:db8::/32))))',
             'AND,((OR,((DST-PORT,443),(DST-PORT,8443))),(NOT,((IP-CIDR6,2001:db8::/32))))'),
        )
        for original, expected in cases:
            with self.subTest(rule=original):
                self.assertEqual(restored(original)['rules'], [expected + ',Probe', 'MATCH,Probe'])

    def test_alias_words_in_payloads_and_quoted_regex_are_not_rewritten(self):
        original = 'AND,((DOMAIN-REGEX,"^(DEST-PORT,IP6-CIDR)$"),(DOMAIN-KEYWORD,DEST-PORT),(DEST-PORT,443))'
        expected = 'AND,((DOMAIN-REGEX,"^(DEST-PORT,IP6-CIDR)$"),(DOMAIN-KEYWORD,DEST-PORT),(DST-PORT,443)),Probe'
        self.assertEqual(restored(original)['rules'][0], expected)

    def test_imported_rules_survive_second_intake(self):
        original = 'AND,((DEST-PORT,443),(IP6-CIDR,2001:db8::/32))'
        expected = 'AND,((DST-PORT,443),(IP-CIDR6,2001:db8::/32)),Probe'
        self.assertEqual(restored(original, imported=True)['rules'][0], expected)

    def test_canonical_rules_are_unchanged(self):
        rule = 'AND,((DST-PORT,443),(IP-CIDR6,2001:db8::/32))'
        self.assertEqual(restored(rule)['rules'][0], rule + ',Probe')

    def test_existing_depth_limit_is_not_relaxed(self):
        rule = 'DEST-PORT,443'
        for _ in range(20):
            rule = 'NOT,((' + rule + '))'
        with self.assertRaises(ConverterError) as caught:
            restored(rule)
        self.assertEqual(caught.exception.code, 'SURGE_FORMAT')


MIHOMO = os.environ.get('OPENCLASH_TEST_MIHOMO', '')


@unittest.skipUnless(MIHOMO and Path(MIHOMO).is_file(), 'set OPENCLASH_TEST_MIHOMO for local syntax check')
class SurgeMihomoRoundtripTests(unittest.TestCase):
    def test_canonical_and_surge_alias_output_compile(self):
        for label, rule in (
            ('canonical', 'AND,((DST-PORT,443),(IP-CIDR6,2001:db8::/32))'),
            ('surge-alias', 'AND,((DEST-PORT,443),(IP6-CIDR,2001:db8::/32))'),
            ('nested-alias', 'AND,((OR,((DEST-PORT,443),(DEST-PORT,8443))),(NOT,((IP6-CIDR,2001:db8::/32))))'),
        ):
            with self.subTest(label=label):
                # Leave only synthetic compiler inputs in the caller's isolated TMPDIR.
                folder = Path(tempfile.mkdtemp(prefix='formats-mihomo-' + label + '-'))
                path = folder / 'synthetic.json'
                path.write_text(formats.dump(restored(rule), 'yaml'), encoding='utf-8')
                result = subprocess.run([MIHOMO, '-t', '-d', str(folder), '-f', str(path)],
                                        capture_output=True, text=True, timeout=15, check=False)
                print(json.dumps({'case': label, 'exit_code': result.returncode,
                                  'stdout': result.stdout, 'stderr': result.stderr}), flush=True)
                self.assertEqual(result.returncode, 0, 'local Mihomo rejected synthetic output')


if __name__ == '__main__':
    unittest.main()
