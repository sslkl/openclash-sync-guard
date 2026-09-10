"""Script input budgets and root-owned archive boundaries. Native tests separate."""
import base64
import copy
import io
from pathlib import Path
import sys
import tarfile
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'vendor' / 'pyyaml-6.0.2'))
import converter_engine as engine
import converter_formats as formats
import converter_sandbox as sandbox
from subscription_converter import ConverterError


def payload():
    return {'form': {'sources': '', 'options': {'target': 'clash'}}, 'uploads': ['proxies: []']}


class ConverterScriptsTests(unittest.TestCase):
    def test_filter_sort_files_are_fixed_assets_never_query_arguments(self):
        request = payload()
        request['scripts'] = {'filter': 'function filter(node) { return false; }', 'sort': 'function compare(a,b) { return a.Remark < b.Remark; }'}
        original = copy.deepcopy(request)
        job, _ = engine.prepare(request, fetch=Mock(side_effect=AssertionError('network')))
        self.assertEqual(request, original)
        self.assertIs(job['options']['sort'], True)
        archive, _ = sandbox.make_archive(job)
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            prefs = tar.extractfile('pref.ini').read().decode()
            generator = tar.extractfile('request.url').read().decode()
            self.assertIn('enable_filter=true\nfilter_script=path:./a000.txt', prefs)
            self.assertIn('sort_script=path:./a001.txt', prefs)
            self.assertNotIn('script_file', generator)
            self.assertNotIn('function', generator)
            self.assertIn('sort=true', generator)

    def test_sort_conflict_rejects_before_remote_fetch(self):
        request = payload(); request['form']['sources'] = 'https://example.test/sub'
        request['form']['options']['sort'] = False; request['scripts'] = {'sort': 'function compare(a,b) { return true; }'}
        fetch = Mock(side_effect=AssertionError('network'))
        with self.assertRaises(ConverterError) as exc: engine.prepare(request, fetch=fetch)
        self.assertEqual(exc.exception.code, 'SCRIPT_SORT')
        fetch.assert_not_called()

    def test_invalid_scripts_and_oversize_reject_before_fetch(self):
        for scripts in (None, [], {'unknown': 'x'}, {'filter': False}, {'sort': 1}, {'filter': '\0'}, {'filter': 'x' * 65537}):
            request = payload(); request['form']['sources'] = 'https://example.test/sub'; request['scripts'] = scripts
            fetch = Mock(side_effect=AssertionError('network'))
            with self.assertRaises(ConverterError): engine.prepare(request, fetch=fetch)
            fetch.assert_not_called()

    def test_empty_script_is_not_enabled(self):
        request = payload(); request['scripts'] = {'filter': '', 'sort': ''}
        job, _ = engine.prepare(request)
        self.assertNotIn('filter_script_file', job['options'])
        self.assertNotIn('sort_script_file', job['options'])

    def test_script_virtual_file_reads_are_materialized_and_host_paths_reject(self):
        request = payload(); request['scripts'] = {'filter': 'function filter(n) { return fileGet("asset:data") == "drop"; }'}
        request['resources'] = [{'name': 'data', 'content': 'keep'}]
        job, _ = engine.prepare(request)
        bodies = {entry['name']: base64.b64decode(entry['body']).decode() for entry in job['files']}
        self.assertEqual(bodies['a000.txt'], 'keep')
        self.assertIn('fileGet("./a000.txt")', bodies[job['options']['filter_script_file']])
        for value in ('fileGet("/etc/passwd")', 'webGet("https://example.test/x")', 'readFile(input)', 'fetch(url)'):
            request['scripts']['filter'] = value
            with self.assertRaises(ConverterError): engine.prepare(request)

    def test_rename_emoji_script_assets_preserved_in_external_formats(self):
        for config in ('[custom]\nrename=!!script:path:asset:rename.js\n',
                       formats.dump({'custom': {'rename_node': [{'script': 'path:asset:rename.js'}]}}, 'yaml')):
            request = payload(); request['config_content'] = config
            request['resources'] = [{'name': 'rename.js', 'content': 'function rename(n) { return "Changed"; }'}]
            job, _ = engine.prepare(request)
            bodies = {entry['name']: base64.b64decode(entry['body']).decode() for entry in job['files']}
            self.assertTrue(any('script:path:./a000.txt' in body for body in bodies.values()))
            self.assertIn('function rename', bodies['a000.txt'])

    def test_root_rejects_source_file_script_non_asset_oversize_and_disabled_sort(self):
        request = payload(); request['scripts'] = {'sort': 'function compare(a,b) { return true; }'}
        valid, _ = engine.prepare(request)
        for path in ('s000.txt', '/etc/passwd', '../a000.txt', 'a999.txt'):
            job = copy.deepcopy(valid); job['options']['sort_script_file'] = path
            with self.assertRaises(sandbox.SandboxError): sandbox.make_archive(job)
        for value in (False, None):
            job = copy.deepcopy(valid)
            if value is None: job['options'].pop('sort')
            else: job['options']['sort'] = value
            with self.assertRaises(sandbox.SandboxError): sandbox.make_archive(job)
        job = copy.deepcopy(valid); job['files'][-1]['body'] = base64.b64encode(b'x' * 65537).decode()
        with self.assertRaises(sandbox.SandboxError): sandbox.make_archive(job)


if __name__ == '__main__':
    unittest.main()
