"""Surge preservation and fixed source-provenance protocol, entirely offline."""
import copy
import hashlib
import io
from pathlib import Path
import sys
import tarfile
import unittest
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'vendor' / 'pyyaml-6.0.2'))
import converter_engine as engine
import converter_formats as formats
import converter_sandbox as sandbox
import converter_surge as surge
from subscription_converter import ConverterError

SOURCE = '''[General]
loglevel=notify
[Proxy]
DIRECT=direct
Synthetic-SS=ss,192.0.2.1,443,encrypt-method=aes-128-gcm,password=synthetic
[Proxy Group]
Probe=select,Synthetic-SS,DIRECT
[Rule]
DOMAIN,probe.example.test,Probe
FINAL,Probe
'''


def native(names=('Synthetic-SS',), membership=None):
    return {'port': 7890, 'proxies': [{'name': name, 'type': 'ss', 'server': '192.0.2.1', 'port': 443,
                                      'cipher': 'aes-128-gcm', 'password': 'synthetic'} for name in names],
            'proxy-groups': [{'name': surge.SOURCE_PREFIX + str(index), 'type': 'select', 'proxies': list(nodes)}
                             for index, nodes in enumerate(membership or [names])], 'rules': ['MATCH,DIRECT']}


class ConverterSurgeTests(unittest.TestCase):
    def test_builtin_aliases_inline_nodes_and_order_preserved_without_mutation(self):
        _, metadata = surge.parse(SOURCE.replace('DIRECT=direct', 'DIRECT=direct\nLocal=direct\nBlock=reject'))
        document = native()
        before = copy.deepcopy((metadata, document))
        result = surge.restore(document, metadata)
        self.assertEqual(result['rules'], ['DOMAIN,probe.example.test,Probe', 'MATCH,Probe'])
        self.assertEqual(result['proxy-groups'], [{'name': 'Local', 'type': 'select', 'proxies': ['DIRECT']},
                                                {'name': 'Block', 'type': 'select', 'proxies': ['REJECT']},
                                                {'name': 'Probe', 'type': 'select', 'proxies': ['Synthetic-SS', 'DIRECT']}])
        self.assertEqual(result['proxies'], document['proxies'])
        self.assertEqual((metadata, document), before)

    def test_two_policy_paths_reused_and_reparsed_keep_exact_native_membership(self):
        source = SOURCE.replace('Probe=select,Synthetic-SS,DIRECT',
                                'Probe=select,Synthetic-SS,DIRECT\nHome=select,policy-path="asset:home"\nServer=select,policy-path=asset:server\nHomeAgain=select,DIRECT,policy-path=asset:home')
        calls = []
        def dependency(url, kind):
            calls.append((url, kind))
            return {'asset:home': 'a000.txt', 'asset:server': 'a001.txt'}[url]
        text, metadata = surge.parse(source, dependency=dependency)
        self.assertEqual(surge.parse(text)[1], metadata)
        self.assertEqual(surge.native_options(metadata), {'policy_sources': ['a000.txt', 'a001.txt'], 'include_primary': True})
        document = native(('Synthetic-SS', 'Residential', 'ServerNode'), [('Synthetic-SS',), ('Residential',), ('ServerNode',)])
        result = surge.restore(document, metadata)
        self.assertEqual([g['proxies'] for g in result['proxy-groups']], [['Synthetic-SS', 'DIRECT'], ['Residential'], ['ServerNode'], ['DIRECT', 'Residential']])
        self.assertEqual(len(calls), 3)
        self.assertFalse(any('_policy_path' in g for g in result['proxy-groups']))

    def test_no_inline_nodes_uses_only_policy_source(self):
        value = SOURCE.replace('Synthetic-SS=ss,192.0.2.1,443,encrypt-method=aes-128-gcm,password=synthetic\n', '').replace('Probe=select,Synthetic-SS,DIRECT', 'Probe=select,policy-path=asset:home')
        _, metadata = surge.parse(value, dependency=lambda *_: 'a000.txt')
        self.assertFalse(surge.native_options(metadata)['include_primary'])
        result = surge.restore(native(('Home',)), metadata)
        self.assertEqual(result['proxy-groups'][0]['proxies'], ['Home'])

    def test_rule_set_no_resolve_logical_rules_and_aliases_preserve_order(self):
        value = SOURCE.replace('DOMAIN,probe.example.test,Probe', 'RULE-SET,asset:rules,Probe,no-resolve\nAND,((DOMAIN,probe.example.test),(NETWORK,TCP)),Probe\nDEST-PORT,443,Probe')
        rules = '# synthetic\nDOMAIN-SUFFIX,example.test\nIP-CIDR,192.0.2.0/24,no-resolve\n'
        text, metadata = surge.parse(value, dependency=lambda url, kind: rules)
        self.assertNotIn('RULE-SET', text)
        result = surge.restore(native(), metadata)
        self.assertEqual(result['rules'], ['DOMAIN-SUFFIX,example.test,Probe,no-resolve', 'IP-CIDR,192.0.2.0/24,Probe,no-resolve',
                                           'AND,((DOMAIN,probe.example.test),(NETWORK,TCP)),Probe', 'DST-PORT,443,Probe', 'MATCH,Probe'])
        self.assertEqual(surge.parse(text)[1], metadata)

    def test_health_group_numeric_and_boolean_options(self):
        text = SOURCE.replace('Probe=select,Synthetic-SS,DIRECT', 'Probe=url-test,Synthetic-SS,url=https://example.test/generate_204,interval=300,timeout=5,tolerance=50,lazy=true')
        _, metadata = surge.parse(text)
        group = surge.restore(native(), metadata)['proxy-groups'][0]
        self.assertEqual((group['interval'], group['timeout'], group['tolerance'], group['lazy']), (300, 5000, 50, True))

    def test_empty_specs_bad_sections_duplicates_and_unknown_options_are_controlled(self):
        bad = [SOURCE.replace('Synthetic-SS=ss,192.0.2.1,443,encrypt-method=aes-128-gcm,password=synthetic', 'Synthetic-SS='),
               SOURCE.replace('Probe=select,Synthetic-SS,DIRECT', 'Probe='), SOURCE + '[Rule]\nFINAL,Probe\n',
               SOURCE.replace('DIRECT=direct', 'DIRECT=reject'), SOURCE.replace('Probe=select,Synthetic-SS,DIRECT', 'DIRECT=select,Synthetic-SS'),
               SOURCE.replace('Probe=select,Synthetic-SS,DIRECT', 'Probe=select,Synthetic-SS,policy-path=asset:a,policy-path=asset:b'),
               SOURCE.replace('Probe=select,Synthetic-SS,DIRECT', 'Probe=select,Synthetic-SS,unknown=true'),
               SOURCE.replace('Probe=select,Synthetic-SS,DIRECT', 'Probe=url-test,Synthetic-SS,interval=-1'),
               SOURCE.replace('Probe=select,Synthetic-SS,DIRECT', 'Probe=select,Synthetic-SS,'),
               SOURCE.replace('DOMAIN,probe.example.test,Probe', 'DOMAIN,probe.example.test,Probe,ignored'),
               SOURCE.replace('DOMAIN,probe.example.test,Probe', 'AND,((DOMAIN,x),(NETWORK,TCP),Probe'),
               SOURCE.replace('DOMAIN,probe.example.test,Probe', 'URL-REGEX,.*example.*,Probe')]
        for text in bad:
            with self.subTest(shape='malformed'), self.assertRaises(ConverterError):
                surge.parse(text, dependency=lambda *_: 'a000.txt')

    def test_paths_never_resolve_host_files_and_rule_set_cannot_silently_drop(self):
        for path in ('/etc/passwd', '../file', 'file:///etc/passwd', './a000.txt'):
            value = SOURCE.replace('Probe=select,Synthetic-SS,DIRECT', 'Probe=select,policy-path=' + path)
            with self.subTest(kind='host-path'), self.assertRaises(ConverterError):
                engine.prepare_tool({'operation': 'surge2clash', 'content': value}, fetch=Mock(side_effect=AssertionError('network')))
        for body in ('# empty', 'FINAL', 'DOMAIN,x,WRONG-GROUP', 'UNSUPPORTED,x'):
            with self.subTest(kind='bad-rule-set'), self.assertRaises(ConverterError):
                surge.parse(SOURCE.replace('DOMAIN,probe.example.test,Probe', 'RULE-SET,asset:rules,Probe'), dependency=lambda *_, body=body: body)

    def test_metadata_must_cover_all_sources_and_nodes(self):
        _, metadata = surge.parse(SOURCE)
        bad = [native(('Wrong',)), native(('Synthetic-SS', 'Synthetic-SS')), native((surge.SOURCE_PREFIX + '0',))]
        document = native(); document['proxy-groups'] = []; bad.append(document)
        document = native(); document['proxy-groups'][0]['proxies'] = ['DIRECT']; bad.append(document)
        document = native(('Synthetic-SS', 'Unattributed'), [('Synthetic-SS',)]); bad.append(document)
        document = native(); document['proxy-groups'][0]['name'] = []; bad.append(document)
        for document in bad:
            with self.subTest(shape='invalid-native-provenance'), self.assertRaises(ConverterError):
                surge.restore(document, metadata)

    def test_missing_reference_and_group_cycles_rejected(self):
        for spec in ('Probe=select,Missing', 'Probe=select,Probe', 'Probe=select,Other\nOther=select,Probe'):
            _, metadata = surge.parse(SOURCE.replace('Probe=select,Synthetic-SS,DIRECT', spec))
            with self.assertRaises(ConverterError): surge.restore(native(), metadata)
        _, metadata = surge.parse(SOURCE.replace('FINAL,Probe', 'FINAL,Missing'))
        with self.assertRaises(ConverterError): surge.restore(native(), metadata)

    def test_long_acyclic_group_graph_does_not_recurse(self):
        groups = [f'G{index}=select,G{index+1}' for index in range(1500)] + ['G1500=select,Synthetic-SS', 'Probe=select,G0']
        _, metadata = surge.parse(SOURCE.replace('Probe=select,Synthetic-SS,DIRECT', '\n'.join(groups)))
        self.assertEqual(len(surge.restore(native(), metadata)['proxy-groups']), 1502)

    def test_prepared_archive_calls_one_native_sub_with_source_id_groups(self):
        payload = {'operation': 'surge2clash', 'content': SOURCE.replace('Probe=select,Synthetic-SS,DIRECT', 'Probe=select,policy-path=asset:home'),
                   'resources': [{'name': 'home', 'content': 'proxies: []'}]}
        job, summary = engine.prepare_tool(payload, fetch=Mock(side_effect=AssertionError('network')))
        archive, target = sandbox.make_archive(job)
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            query = urlsplit(tar.extractfile('request.url').read().decode())
            self.assertEqual(query.path, '/sub')
            self.assertEqual(parse_qs(query.query), {'target': ['clash'], 'url': ['./s000.txt|./a000.txt']})
            prefs = tar.extractfile('pref.ini').read().decode()
            self.assertIn('__OCS_SURGE_SOURCE_0`select`!!GROUPID=0', prefs)
            self.assertIn('__OCS_SURGE_SOURCE_1`select`!!GROUPID=1', prefs)
        self.assertEqual(target, 'surge2clash')
        self.assertFalse(summary['network_executed'])
        self.assertFalse(summary['link_backend_used'])

    def test_root_revalidates_each_source_without_trusting_web(self):
        job, _ = engine.prepare_tool({'operation': 'surge2clash', 'content': SOURCE})
        bad = [{'policy_sources': ['s000.txt']}, {'policy_sources': ['/etc/passwd']}, {'policy_sources': ['a000.txt']},
               {'policy_sources': []}, {'policy_sources': 'a000.txt'}, {'policy_sources': [['a000.txt']]}, {'include_primary': 1}]
        for options in bad:
            job['options'] = {'target': 'surge2clash', 'include_primary': False, **options}
            with self.assertRaises(sandbox.SandboxError): sandbox.make_archive(job)

    def test_execute_restores_after_authenticating_result_and_updates_digest(self):
        raw = formats.dump(native(), 'yaml').encode()
        result = {'ok': True, 'content': raw.decode(), 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw), 'target': 'surge2clash',
                  'elapsed_ms': 1, 'engine': 'subconverter-0.9.1-36573b3-isolated', 'isolated': True, 'network': 'none', 'router_changed': False, 'cleanup_confirmed': True}
        bridge = Mock(enabled=True)
        bridge.call.return_value = result
        response = engine.execute({'operation': 'surge2clash', 'content': SOURCE}, bridge, tool=True)
        self.assertTrue(engine.result_ok({k: response[k] for k in engine.RESULT_FIELDS}, 'surge2clash'))
        self.assertTrue(response['summary']['upstream_group_rule_fix'])
        self.assertEqual(formats.yaml_load(response['content'])['rules'][-1], 'MATCH,Probe')
        result['sha256'] = '0' * 64
        with self.assertRaises(ConverterError): engine.execute({'operation': 'surge2clash', 'content': SOURCE}, bridge, tool=True)


if __name__ == '__main__':
    unittest.main()
