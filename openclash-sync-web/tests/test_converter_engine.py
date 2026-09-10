"""Synthetic-only preparation, global budgets, API and privileged dispatch."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest
import time
from unittest import mock

from test_server import server
import converter_engine as engine
import converter_sandbox as sandbox
from subscription_converter import ConverterError

ROOT = Path(__file__).resolve().parents[1]
YAML = 'proxies:\n  - {name: Synthetic, type: ss, server: 192.0.2.1, port: 443, cipher: aes-128-gcm, password: synthetic}\n'
URI = 'ss://YWVzLTEyOC1nY206c3ludGhldGlj@192.0.2.1:443#Synthetic'
URL = 'https://sub.example.test/source?token=synthetic'


def payload(**options):
    return {'form': {'sources': '', 'options': {'target': 'clash', **options}, 'profile': 'router_a'}, 'uploads': [YAML]}


def success(content=YAML):
    raw = content.encode()
    return {'ok': True, 'content': content, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw),
            'target': 'clash', 'elapsed_ms': 100, 'engine': 'subconverter-0.9.1-36573b3-isolated',
            'isolated': True, 'network': 'none', 'router_changed': False, 'cleanup_confirmed': True}


class PreparationTests(unittest.TestCase):
    def test_json_source_surrogate_pairs_are_normalized_for_native(self):
        document = {'proxies': [{'name': 'Synthetic-\U0001f642', 'type': 'ss',
                                'server': '192.0.2.1', 'port': 443,
                                'cipher': 'aes-128-gcm', 'password': 'synthetic-\U0001f680'}]}
        raw = json.dumps(document, ensure_ascii=True)
        for remote in (False, True):
            with self.subTest(remote=remote):
                value = dict(payload(), uploads=[raw])
                fetch = mock.Mock(side_effect=AssertionError('no fetch'))
                if remote:
                    value = {'form': {'sources': [URL], 'options': {'target': 'clash'}}}
                    fetch = mock.Mock(return_value=[raw.encode()])
                job, summary = engine.prepare(value, fetch)
                files, names, _ = sandbox.validate_job(job)
                native = files[names[0]]
                self.assertNotIn(b'\\ud83d', native)
                self.assertEqual(json.loads(native), document)
                self.assertEqual(summary['network_executed'], remote)

    def test_json_source_escaped_and_literal_have_identical_native_bytes(self):
        document = {'proxies': [{'name': 'Synthetic-\U0001f642', 'password': 'synthetic-\U0001f680'}]}
        self.assertEqual(engine.subscription_content(json.dumps(document, ensure_ascii=True).encode()),
                         engine.subscription_content(json.dumps(document, ensure_ascii=False).encode()))

    def test_json_source_normalized_duplicate_keys_are_rejected(self):
        value = '{"Synthetic-\U0001f642": 1, "Synthetic-\\ud83d\\ude42": 2}'
        with self.assertRaises(ConverterError) as exc:
            engine.subscription_content(value.encode())
        self.assertEqual(exc.exception.code, 'CONFIG_FORMAT')

    def test_json_source_unpaired_surrogates_are_rejected(self):
        for value in ('{"name":"\\ud800"}', '{"name":"\\udc00"}',
                      '{"\\ud800":1}', '{"name":"\\udc00\\ud800"}'):
            with self.subTest(shape='unpaired'):
                with self.assertRaises(ConverterError) as exc:
                    engine.subscription_content(value.encode())
                self.assertEqual(exc.exception.code, 'CONFIG_FORMAT')

    def test_json_source_normalization_uses_existing_structure_budgets(self):
        nested = 0
        for _ in range(34):
            nested = {'nested': nested}
        with self.assertRaises(ConverterError) as exc:
            engine.subscription_content(json.dumps(nested).encode())
        self.assertEqual(exc.exception.code, 'CONFIG_FORMAT')
        with mock.patch.object(engine.converter_formats.UniqueLoader, 'max_nodes', 3):
            with self.assertRaises(ConverterError) as exc:
                engine.subscription_content(b'{"a":1,"b":2,"c":3}')
        self.assertEqual(exc.exception.code, 'CONFIG_FORMAT')

    def test_non_json_subscription_bytes_keep_existing_handling(self):
        for raw in (YAML.encode(), b'[Proxy]\nSynthetic=direct\n',
                    base64.b64encode(URI.encode()), b'[{"legacy":"list-source"}]'):
            with self.subTest(shape='unchanged'):
                self.assertEqual(engine.subscription_content(raw), raw)
        self.assertEqual(engine.subscription_content(URI.encode()), base64.b64encode(URI.encode()))

    def test_json_source_normalization_preserves_scalar_types_and_text(self):
        document = {'metadata': {'count': 1e20, 'enabled': False, 'empty': None,
                                 'text': 'on true null 123\\literal\n中文\U0001f642'}}
        self.assertEqual(json.loads(engine.subscription_content(json.dumps(document).encode())), document)

    def test_json_source_normalization_rechecks_expanded_byte_limit(self):
        raw = b'{"a":[1,2,3,4,5]}'
        with mock.patch.object(engine, 'MAX_JOB_BYTES', len(raw)):
            with self.assertRaises(ConverterError) as exc:
                engine.subscription_content(raw)
        self.assertEqual(exc.exception.code, 'CONTENT')

    def test_upload_only_and_plain_share_links_need_no_fetch(self):
        request = payload(list=True)
        request['uploads'].append(URI)
        with mock.patch.object(engine, 'fetch_many', side_effect=AssertionError('no fetch')):
            job, summary = engine.prepare(request)
        files, names, options = sandbox.validate_job(job)
        self.assertEqual(names, ['s000.txt', 's001.txt'])
        self.assertEqual(files['s000.txt'], YAML.encode())
        self.assertEqual(base64.b64decode(files['s001.txt']), URI.encode())
        self.assertFalse(summary['network_executed'])
        self.assertFalse(summary['link_backend_used'])
        self.assertEqual(summary['profile'], 'router_a')
        self.assertFalse(summary['router_changed'])

    def test_source_order_duplicates_and_user_agent_kept_single_fetch(self):
        fetch = mock.Mock(return_value=[YAML.encode()])
        job, summary = engine.prepare({'form': {'sources': [URL, URI, URL], 'options': {'ua': 'Synthetic/1'}}}, fetch)
        self.assertEqual(fetch.call_args.args, ([URL],))
        self.assertEqual(fetch.call_args.kwargs['user_agent'], 'Synthetic/1')
        self.assertGreater(fetch.call_args.kwargs['timeout'], 0)
        self.assertLessEqual(fetch.call_args.kwargs['timeout'], 25)
        files, names, _ = sandbox.validate_job(job)
        self.assertEqual(files[names[0]], files[names[2]])
        self.assertEqual(base64.b64decode(files[names[1]]), URI.encode())
        self.assertEqual(summary['remote_source_count'], 1)
        self.assertTrue(summary['network_executed'])

    def test_external_ini_base_rules_and_import_lists_materialized(self):
        config_url, base_url, rules_url, import_url = ['https://example.test/' + part for part in ('config.ini', 'base.yaml', 'rules.txt', 'list.txt')]
        fixtures = {config_url: f'[custom]\nclash_rule_base={base_url}\nruleset=!!import:{import_url}\n'.encode(),
                    base_url: b'port: 7890\n', import_url: f'Proxy,clash-domain:{rules_url},86400\nProxy,[]FINAL\n'.encode(),
                    rules_url: b"payload:\n  - '+.example.com'\n"}
        seen = []
        def fetch(urls, **kwargs):
            seen.append((urls, kwargs))
            return [fixtures[url] for url in urls]
        value = payload(config=config_url)
        job, summary = engine.prepare(value, fetch)
        files, _, options = sandbox.validate_job(job)
        config = files[options['config'].split('/')[-1]].decode()
        self.assertIn('clash_rule_base=./a', config)
        self.assertIn('ruleset=!!import:./a', config)
        self.assertFalse(any(url.encode() in raw for url in fixtures for raw in files.values()))
        self.assertTrue(any(b'clash-domain:./a' in raw for raw in files.values()))
        self.assertEqual(summary['asset_count'], 4)
        self.assertGreater(seen[0][1]['maximum'], seen[-1][1]['maximum'])
        self.assertGreaterEqual(seen[0][1]['timeout'], seen[-1][1]['timeout'])

    def test_nested_imports_are_flattened_not_silently_skipped(self):
        fixtures = {'https://example.test/a': b'!!import:https://example.test/b\n',
                    'https://example.test/b': b'Proxy,[]FINAL\n'}
        value = payload()
        value['config_content'] = '[custom]\nruleset=!!import:https://example.test/a\n'
        job, _ = engine.prepare(value, lambda urls, **kwargs: [fixtures[url] for url in urls])
        files, _, _ = sandbox.validate_job(job)
        self.assertEqual(sum(raw == b'Proxy,[]FINAL\n' for raw in files.values()), 2)

    def test_large_import_is_linear_and_checks_deadline_while_parsing(self):
        budget = engine.IntakeBudget(mock.Mock(), 'Synthetic/1')
        pack = engine.AssetPack(budget, {})
        text = 'a\n' * 100000
        started = time.monotonic()
        self.assertEqual(pack.imported(text, 'rename-list'), text)
        # The old repeated sum scanned five billion entries for this fixture.
        self.assertLess(time.monotonic() - started, 2.0)
        with mock.patch.object(budget, 'time_left', side_effect=[1] * 100 + [ConverterError('FETCH_TIMEOUT')]):
            with self.assertRaises(ConverterError) as exc:
                pack.imported(text, 'rename-list')
        self.assertEqual(exc.exception.code, 'FETCH_TIMEOUT')

    def test_import_size_counts_utf8_and_separators_not_characters(self):
        pack = engine.AssetPack(engine.IntakeBudget(mock.Mock(), 'Synthetic/1'), {})
        with mock.patch.object(engine, 'MAX_JOB_BYTES', 6):
            self.assertEqual(pack.imported('中\na', 'rename-list'), '中\na\n')
            with self.assertRaises(ConverterError) as exc:
                pack.imported('中\n中', 'rename-list')
        self.assertEqual(exc.exception.code, 'FETCH_SIZE')

    def test_cycles_unsupported_dynamic_paths_and_local_files_are_rejected(self):
        for config in ('[custom]\nclash_rule_base=/etc/passwd', '[custom]\nruleset=Proxy,/etc/passwd',
                       '[custom]\nruleset=!!import:/etc/passwd', '[custom]\n{% include "secret" %}',
                       'custom:\n  clash_rule_base: /etc/passwd'):
            with self.subTest(shape='unsafe-config'), self.assertRaises(ConverterError):
                engine.prepare(dict(payload(), config_content=config))
        value = dict(payload(), config_content='[custom]\nruleset=!!import:https://example.test/a')
        with self.assertRaises(ConverterError) as exc:
            engine.prepare(value, lambda urls, **kwargs: [b'!!import:https://example.test/a'])
        self.assertEqual(exc.exception.code, 'DEPENDENCIES')

    def test_entire_dependency_graph_shares_time_and_byte_budgets(self):
        times = iter((0, 1, 2, 25.1))
        fetch = mock.Mock(return_value=[b'a'])
        with mock.patch.object(engine.time, 'monotonic', side_effect=lambda: next(times)):
            budget = engine.IntakeBudget(fetch, 'Synthetic/1')
            with self.assertRaises(ConverterError) as exc: budget.get([URL])
        self.assertEqual(exc.exception.code, 'FETCH_TIMEOUT')
        self.assertEqual(fetch.call_args.kwargs['timeout'], 23)
        budget = engine.IntakeBudget(mock.Mock(return_value=[b'ab']), 'Synthetic/1')
        budget.remaining = 1
        with self.assertRaises(ConverterError) as exc: budget.get([URL])
        self.assertEqual(exc.exception.code, 'FETCH_SIZE')

    def test_cross_source_and_upload_budgets_and_conflicting_config(self):
        cases = [dict(payload(), uploads=[YAML]*33), dict(payload(), config_content=1),
                 dict(payload(), uploads=['\ud800']), dict(payload(), uploads=['\0']), payload(target='auto'),
                 dict(payload(), form={'sources': '', 'profile': [], 'options': {}}),
                 dict(payload(config='https://example.test/a'), config_content='[custom]\n'),
                 dict(payload(), uploads=['x' * engine.MAX_JOB_BYTES, 'x'])]
        for value in cases:
            with self.subTest(shape='invalid-request'), self.assertRaises(ConverterError): engine.prepare(value)

    def test_result_success_and_failures_have_exact_schema_no_unknown_echo(self):
        result = success()
        self.assertTrue(engine.result_ok(result, 'clash'))
        for mutation in ({'unexpected': 'secret'}, {'bytes': True}, {'sha256': 'a'*64}, {'cleanup_confirmed': False},
                         {'network': 'bridge'}, {'target': 'surge'}, {'content': '\ud800'}, {'elapsed_ms': 60001}):
            self.assertFalse(engine.result_ok(dict(result, **mutation), 'clash'))
        self.assertTrue(engine.failure_ok({'ok': False, 'code': 'SANDBOX_CLEANUP', 'router_changed': False}))
        self.assertFalse(engine.failure_ok({'ok': False, 'code': [], 'router_changed': False}))
        self.assertFalse(engine.failure_ok({'ok': False, 'code': 'SANDBOX', 'router_changed': False, 'stderr': 'secret'}))

    def test_execute_lock_is_always_released_no_preview_execution(self):
        bridge = mock.Mock(enabled=False)
        with self.assertRaises(ConverterError): engine.execute(payload(), bridge)
        bridge.call.assert_not_called()
        bridge.enabled = True
        with engine.LOCK, self.assertRaises(ConverterError) as exc: engine.execute(payload(), bridge)
        self.assertEqual(exc.exception.code, 'CONVERTER_BUSY')
        bridge.call.return_value = success()
        result = engine.execute(payload(), bridge)
        self.assertEqual(bridge.call.call_args.args[0]['action'], 'converter_run')
        self.assertEqual(result['summary']['source_count'], 1)
        self.assertFalse(engine.LOCK.locked())
        bridge.call.return_value = dict(success(), secret='synthetic')
        with self.assertRaises(ConverterError) as exc: engine.execute(payload(), bridge)
        self.assertEqual(exc.exception.code, 'SANDBOX')
        self.assertFalse(engine.LOCK.locked())


class ExecutionAPITests(unittest.TestCase):
    def post(self, body, *, auth=True, origin=True):
        handler = object.__new__(server.Handler)
        handler.path = '/api/converter/execute'
        handler.authorize = lambda: auth
        handler.same_origin = lambda: origin
        handler.read_json = lambda: copy.deepcopy(body)
        output = []
        handler.send_json = lambda status, result: output.append((status, result))
        handler.do_POST()
        return output

    def test_auth_origin_nonce_before_engine_no_retry(self):
        body = dict(payload(), nonce=server.new_nonce())
        with mock.patch.object(engine, 'execute', return_value=success()) as execute:
            self.assertEqual(self.post(body, auth=False), [])
            self.assertEqual(self.post(body, origin=False)[0][0], 403)
            self.assertEqual(self.post(payload())[0][0], 409)
            execute.assert_not_called()
            self.assertEqual(self.post(body)[0][0], 200)
            self.assertEqual(self.post(body)[0][0], 409)
            execute.assert_called_once()
            self.assertNotIn('nonce', execute.call_args.args[0])

    def test_preview_is_explicit_unavailable_not_mocked_success(self):
        with mock.patch.object(server, 'BRIDGE', mock.Mock(enabled=False)):
            status, result = self.post(dict(payload(), nonce=server.new_nonce()))[0]
        self.assertEqual(status, 503)
        self.assertEqual(result['code'], 'SANDBOX_UNAVAILABLE')
        self.assertFalse(server.Bridge.demo({'action': 'converter_run'})['ok'])

    def test_bridge_validates_digest_exact_shape_and_safe_errors(self):
        request = {'action': 'converter_run', 'job': {'options': {'target': 'clash'}}}
        self.assertTrue(server.bridge_result_ok(request, success()))
        self.assertFalse(server.bridge_result_ok(request, dict(success(), secret='synthetic')))
        self.assertTrue(server.bridge_result_ok(request, {'ok': False, 'code': 'SANDBOX', 'router_changed': False}))
        self.assertFalse(server.bridge_result_ok(request, {'ok': False, 'code': 'secret', 'router_changed': False}))

    def test_local_converter_dispatch_rejects_router_target_and_other_fields(self):
        for value in ({'action': 'converter_run', 'job': {}}, {'action': 'converter_run', 'target': 'router_a', 'job': {}},
                      {'action': 'converter_run', 'job': {}, 'path': '/etc/passwd'}):
            process = subprocess.run([sys.executable, '-I', '-B', str(ROOT/'openclash_web_helper.py')],
                                     input=json.dumps(value).encode(), capture_output=True, timeout=5, check=False)
            result = json.loads(process.stdout)
            self.assertFalse(result['ok'])
            self.assertNotIn('synthetic', process.stdout.decode())
            self.assertEqual(process.stderr, b'')
