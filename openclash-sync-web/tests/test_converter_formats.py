"""Structured config preservation, import budgets, and non-executing parsing."""
import base64
import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
# Same pinned dependency as server.py, including standalone test invocation.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'vendor' / 'pyyaml-6.0.2'))
import converter_engine as engine
import converter_formats as formats
import converter_sandbox as sandbox
from subscription_converter import ConverterError


class ConverterFormatsTests(unittest.TestCase):
    def payload(self, config):
        return {'form': {'sources': '', 'options': {'target': 'clash'}}, 'uploads': ['proxies: []'],
                'config_content': config, 'resources': [
                    {'name': 'base.yaml', 'content': 'port: 17890\nallow-lan: false\n'},
                    {'name': 'rules.txt', 'content': 'DOMAIN,probe.example.test\n'}]}

    def files(self, payload):
        job, summary = engine.prepare(payload, fetch=Mock(side_effect=AssertionError('unexpected network')))
        sandbox.make_archive(job)
        return {item['name']: base64.b64decode(item['body']).decode() for item in job['files']}, job, summary

    def test_generated_toml_automatically_roundtrips_quoted_version(self):
        value = {'version': 1, 'custom': {'enable_rule_generator': True}}
        text = formats.dump(value, 'toml')
        self.assertEqual(formats.load(text), (value, 'toml'))
        self.assertEqual(formats.load(text.replace('"version"', "'version'")), (value, 'toml'))
        files, job, _ = self.files(self.payload(text))
        self.assertEqual(formats.load(files[job['options']['config']]), (value, 'toml'))

    def test_yaml_base_rules_groups_rename_and_template_args_preserved(self):
        value = {'custom': {'clash_rule_base': 'asset:base.yaml', 'enable_rule_generator': True,
                           'proxy_groups': [{'name': 'Probe', 'type': 'select', 'rule': ['.*']}],
                           'rulesets': [{'group': 'Probe', 'ruleset': 'asset:rules.txt'}, {'group': 'Probe', 'ruleset': '[]FINAL'}],
                           'rename_node': [{'match': 'Old', 'replace': 'New'}]},
                 'template_args': [{'key': 'title', 'value': 'Synthetic'}]}
        files, job, summary = self.files(self.payload(formats.dump(value, 'yaml')))
        result, kind = formats.load(files[job['options']['config']])
        self.assertEqual(kind, 'yaml')
        self.assertEqual(result['template_args'], value['template_args'])
        self.assertEqual(result['custom']['proxy_groups'], value['custom']['proxy_groups'])
        self.assertEqual(result['custom']['rename_node'], value['custom']['rename_node'])
        self.assertTrue(result['custom']['clash_rule_base'].startswith('./a'))
        self.assertTrue(result['custom']['rulesets'][0]['ruleset'].startswith('./a'))
        self.assertEqual(result['custom']['rulesets'][1]['ruleset'], '[]FINAL')
        self.assertFalse(summary['network_executed'])

    def test_yaml_imports_flatten_text_lists_and_preserve_order(self):
        payload = self.payload('custom:\n  proxy_groups:\n    - import: asset:groups.txt\n')
        payload['resources'] += [{'name': 'groups.txt', 'content': '!!import:asset:inner.txt\nLast`select`.*\n'},
                                 {'name': 'inner.txt', 'content': 'First`select`.*\n'}]
        files, job, _ = self.files(payload)
        data, _ = formats.load(files[job['options']['config']])
        path = data['custom']['proxy_groups'][0]['import'][2:]
        self.assertEqual(files[path], 'First`select`.*\nLast`select`.*\n')

    @unittest.skipIf(sys.version_info < (3, 11), 'TOML runtime requires Python 3.11+')
    def test_toml_recursive_imports_are_flattened_and_roundtrip(self):
        payload = self.payload('version=1\n[custom]\nclash_rule_base="asset:base.yaml"\n[[custom_groups]]\nimport="asset:groups.toml"\n[[rulesets]]\ngroup="Probe"\nruleset="asset:rules.txt"\n')
        payload['resources'] += [{'name': 'groups.toml', 'content': '[[custom_groups]]\nimport="asset:inner.toml"\n'},
                                 {'name': 'inner.toml', 'content': '[[custom_groups]]\nname="Probe"\ntype="select"\nrule=[".*"]\n'}]
        files, job, _ = self.files(payload)
        data, _ = formats.load(files[job['options']['config']], kind='toml')
        groups, _ = formats.load(files[data['custom_groups'][0]['import'][2:]], kind='toml')
        self.assertEqual(groups, {'custom_groups': [{'name': 'Probe', 'type': 'select', 'rule': ['.*']}]})
        self.assertTrue(data['rulesets'][0]['ruleset'].startswith('./a'))
        self.assertEqual(data['version'], 1)

    @unittest.skipIf(sys.version_info < (3, 11), 'TOML runtime requires Python 3.11+')
    def test_toml_recursion_missing_sections_duplicate_keys_and_dates_rejected(self):
        for text in ['version=1\nversion=1\n[custom]\n', 'version=true\n[custom]\n',
                     'version=1\n[custom]\ntime=1979-05-27\n', 'version=2\n[custom]\n']:
            with self.subTest(text=text), self.assertRaises(ConverterError): self.files(self.payload(text))
        payload = self.payload('version=1\n[custom]\n[[custom_groups]]\nimport="asset:loop.toml"\n')
        for body in ['[[custom_groups]]\nimport="asset:loop.toml"\n', '[[rulesets]]\ngroup="Probe"\nruleset="[]FINAL"\n']:
            payload['resources'] = [{'name': 'loop.toml', 'content': body}]
            with self.assertRaises(ConverterError): self.files(payload)

    def test_yaml_duplicate_anchors_tags_complex_keys_nonfinite_depth_rejected(self):
        invalid = ['custom: {}\ncustom: {}', 'custom: &a {}', 'custom: {<<: *a}',
                   'custom: !!python/object:os.system {}', 'custom: {1: x}',
                   'custom: {x: .nan}', 'custom: {x: 2000-01-01}',
                   'custom: ' + '[' * 40 + '0' + ']' * 40]
        for text in invalid:
            with self.subTest(text=text[:50]), self.assertRaises(ConverterError): self.files(self.payload(text))

    def test_structured_host_paths_and_dynamic_includes_rejected(self):
        for path in ['/etc/passwd', './local.yaml', 'file:///etc/passwd', 'asset:missing.yaml']:
            with self.subTest(path=path), self.assertRaises(ConverterError):
                self.files(self.payload(formats.dump({'custom': {'clash_rule_base': path}}, 'yaml')))
        for text in ['{% include x %}', '{{ fileGet("/etc/passwd") }}', '{{ webGet("https://example.test") }}']:
            payload = self.payload('custom:\n  clash_rule_base: asset:base.yaml\n')
            payload['resources'][0]['content'] = text
            with self.assertRaises(ConverterError): self.files(payload)

    def test_every_local_resource_is_reserved_before_remote_fetch(self):
        for tool in (False, True):
            fetch = Mock(return_value=[b'proxies: []'])
            resources = [{'name': 'big.txt', 'content': 'x' * 1000}]
            payload = {'operation': 'ruleset', 'urls': ['https://example.test/a'], 'resources': resources} if tool else {
                'form': {'sources': 'https://example.test/a', 'options': {'target': 'clash'}}, 'resources': resources}
            (engine.prepare_tool if tool else engine.prepare)(payload, fetch=fetch)
            self.assertEqual(fetch.call_args.kwargs['maximum'], engine.MAX_JOB_BYTES - 1000)

    def test_oversize_or_bad_resources_fail_before_any_network(self):
        for tool in (False, True):
            payload = {'operation': 'ruleset', 'content': 'abc', 'urls': ['https://example.test/a']} if tool else {
                'form': {'sources': 'https://example.test/a', 'options': {'target': 'clash'}}, 'uploads': ['abc']}
            for resources in [[{'name': 'big.txt', 'content': 'x' * engine.MAX_JOB_BYTES}],
                              [{'name': '../a', 'content': 'x'}], [{'name': 'a', 'content': 'x'}, {'name': 'a', 'content': 'y'}]]:
                fetch = Mock(side_effect=AssertionError('network before local validation'))
                with self.assertRaises(ConverterError):
                    (engine.prepare_tool if tool else engine.prepare)({**payload, 'resources': resources}, fetch=fetch)
                fetch.assert_not_called()

    def test_input_objects_not_mutated(self):
        payload = self.payload('custom:\n  clash_rule_base: asset:base.yaml\n')
        before = copy.deepcopy(payload)
        self.files(payload)
        self.assertEqual(payload, before)

    @unittest.skipIf(sys.version_info < (3, 11), 'TOML runtime requires Python 3.11+')
    def test_serializers_preserve_quoted_keys_unicode_and_scalar_types(self):
        data = {'version': 1, 'custom': {'x.y': '中文\\"\n', 'arr': [True, 123, 0.5, {'a': 'b'}]}}
        for kind in ('toml', 'yaml'):
            self.assertEqual(formats.load(formats.dump(data, kind), kind=kind)[0], data)
        with self.assertRaises(ConverterError): formats.dump({'a': None}, 'toml')
