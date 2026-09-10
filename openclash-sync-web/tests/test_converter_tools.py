"""Offline structured tool, virtual resource and isolated endpoint contracts."""
import base64
import io
from pathlib import Path
import sys
import tarfile
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import converter_engine as engine
import converter_sandbox as sandbox
from subscription_converter import ConverterError


class ConverterToolsTests(unittest.TestCase):
    def test_rule_tools_all_types_use_only_encoded_job_paths(self):
        for kind in range(1, 7):
            job, summary = engine.prepare_tool({'operation': 'ruleset', 'content': 'DOMAIN,example.test\n', 'options': {'type': kind}}, fetch=Mock(side_effect=AssertionError('network')))
            archive, target = sandbox.make_archive(job)
            self.assertEqual(target, 'ruleset')
            self.assertFalse(summary['network_executed'])
            with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
                url = tar.extractfile('request.url').read().decode()
                self.assertTrue(url.startswith('http://127.0.0.1:25500/getruleset?'))
                self.assertIn('type=' + str(kind), url)
                self.assertNotIn('example.test', url)
                pref = tar.extractfile('pref.ini').read().decode()
                self.assertIn('[server]\nlisten=127.0.0.1\nport=25500', pref)

    def test_template_assets_literal_includes_resolve_no_host_files(self):
        job, _ = engine.prepare_tool({'operation': 'template', 'content': '{% include "asset:part.tpl" %}\n{{ request.title }}',
                                     'resources': [{'name': 'part.tpl', 'content': 'Local asset'}],
                                     'options': {'variables': {'title': 'Synthetic'}}}, fetch=Mock(side_effect=AssertionError('network')))
        files = {item['name']: base64.b64decode(item['body']).decode() for item in job['files']}
        self.assertIn('./a000.txt', files['s000.txt'])
        self.assertEqual(files['a000.txt'], 'Local asset')
        sandbox.make_archive(job)

    def test_virtual_asset_ini_and_cycles(self):
        payload = {'form': {'sources': '', 'options': {'target': 'clash'}}, 'uploads': ['proxies: []'],
                   'config_content': '[custom]\nclash_rule_base=asset:base.yaml\nruleset=Proxy,asset:rules.txt\n',
                   'resources': [{'name': 'base.yaml', 'content': 'port: 7890'}, {'name': 'rules.txt', 'content': 'DOMAIN,example.test'}]}
        job, _ = engine.prepare(payload, fetch=Mock(side_effect=AssertionError('network')))
        self.assertEqual(len(job['files']), 4)
        sandbox.make_archive(job)
        payload['resources'][0]['content'] = '{% include "asset:base.yaml" %}'
        with self.assertRaises(ConverterError): engine.prepare(payload)
        payload['resources'][0]['name'] = '../base.yaml'
        with self.assertRaises(ConverterError): engine.prepare(payload)

    def test_tool_rejects_unknown_fields_control_bytes_paths_and_empty(self):
        invalid = [
            {'operation': 'getlocal', 'content': '/etc/passwd'},
            {'operation': 'ruleset', 'content': 'x', 'options': {'type': True}},
            {'operation': 'ruleset', 'content': 'x', 'options': {'group': 'x\npath=bad'}},
            {'operation': 'template', 'content': '{{ request.x }}', 'options': {'variables': {'path': '/etc/passwd'}}},
            {'operation': 'template', 'content': '{% include "/etc/passwd" %}'},
            {'operation': 'surge2clash', 'content': ''},
            {'operation': 'surge2clash', 'content': 'x', 'options': {'path': 'x'}},
        ]
        for value in invalid:
            with self.subTest(operation=value['operation']), self.assertRaises(ConverterError): engine.prepare_tool(value)

    def test_runner_revalidates_tools_independent_of_nonprivileged_web(self):
        job, _ = engine.prepare_tool({'operation': 'template', 'content': 'Hi'})
        for options in ({'target': 'template', 'variables': {'path': '/etc/passwd'}}, {'target': 'surge2clash', 'url': '/etc/passwd'},
                        {'target': 'ruleset', 'type': 1, 'input_format': [], 'group': 'Proxy'}):
            job['options'] = options
            with self.assertRaises(sandbox.SandboxError): sandbox.make_archive(job)
