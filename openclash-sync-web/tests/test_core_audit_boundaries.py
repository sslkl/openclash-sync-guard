"""Independent request/format boundaries, using synthetic data and stubbed I/O.

No server, privileged helper, Docker, native converter, or real HTTP entrypoint
is imported or executed. A genuine regression remains a failing assertion.
"""
import base64
import copy
import hashlib
import json
import math
from pathlib import Path
import sys
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT.parent / 'vendor' / 'pyyaml-6.0.2'):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import converter_engine as engine
import converter_formats as formats
import subscription_converter as converter

URL = 'https://sources.example.test/synthetic.yaml'
URI = 'trojan://synthetic-only@192.0.2.44:443#合成节点'
YAML = 'proxies:\n  - {name: 合成节点, type: socks5, server: 192.0.2.44, port: 1080}\n'


def payload(**options):
    return {'form': {'backend': 'https://converter.example.test/sub', 'sources': [],
                     'options': dict(target='clash', **options)}, 'uploads': [YAML]}


def decoded_files(job):
    return {item['name']: base64.b64decode(item['body'], validate=True) for item in job['files']}


def envelope(content=YAML):
    raw = content.encode('utf-8')
    return {'ok': True, 'content': content, 'sha256': hashlib.sha256(raw).hexdigest(),
            'bytes': len(raw), 'target': 'clash', 'elapsed_ms': 1,
            'engine': 'subconverter-0.9.1-36573b3-isolated', 'isolated': True,
            'network': 'none', 'router_changed': False, 'cleanup_confirmed': True}


class CoreAuditBoundaries(unittest.TestCase):
    def setUp(self):
        for target in ('socket.socket', 'socket.create_connection', 'socket.getaddrinfo',
                       'subprocess.Popen', 'os.system'):
            self.enterContext(mock.patch(target, side_effect=AssertionError('offline test attempted external I/O')))
        self.no_fetch = mock.Mock(side_effect=AssertionError('unexpected HTTP request'))

    def assert_error(self, code, function, *args, **kwargs):
        with self.assertRaises(converter.ConverterError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def assert_typed_equal(self, actual, expected):
        # Ordinary equality conflates bool/int and positive/negative zero.
        self.assertIs(type(actual), type(expected))
        self.assertEqual(actual, expected)
        if isinstance(expected, dict):
            for key in expected:
                self.assert_typed_equal(actual[key], expected[key])
        elif isinstance(expected, list):
            for left, right in zip(actual, expected):
                self.assert_typed_equal(left, right)
        elif isinstance(expected, float) and expected == 0:
            self.assertEqual(math.copysign(1, actual), math.copysign(1, expected))

    def test_link_to_job_combines_profiles_tristate_iri_duplicates_and_uploads(self):
        iri = 'https://SOURCES.example.test/订阅?name=中文&literal=%252F'
        upload = {'proxies': [{'name': '组合🙂', 'type': 'http', 'server': '192.0.2.55', 'port': 8080}],
                  'metadata': {'flag': False, 'scientific': 1e20, 'empty': None}}
        for profile in ('manual', 'router_a', 'router_b'):
            for flag in (None, False, True):
                with self.subTest(profile=profile, flag=flag):
                    options = {'target': 'surge', 'ver': 5, 'filename': '组合.ini', 'ua': 'Synthetic-Boundary/1'}
                    if flag is not None:
                        options.update(udp=flag, list=flag)
                    form = {'backend': 'https://CONVERTER.example.test/', 'sources': [iri, URI, iri],
                            'options': options, 'profile': profile,
                            'parameters': {'theme': '夜间&A=1|2%25', 'empty': ''}}
                    before = copy.deepcopy(form)
                    request = converter.validate(form)
                    restored = converter.parse_link(request.link())
                    self.assertEqual(restored.backend, 'https://converter.example.test/sub')
                    self.assertEqual(restored.sources, request.sources)
                    self.assertEqual(restored.options, request.options)
                    self.assertEqual(restored.parameters, request.parameters)
                    # Profiles are display-only metadata and are not encoded in links.
                    self.assertEqual(restored.profile, 'manual')
                    self.assertEqual(restored.link(), request.link())
                    jobs = []
                    for model in (request, restored):
                        fetch = mock.Mock(return_value=[b'\xef\xbb\xbf' + YAML.encode()])
                        value = {'form': model.public_form(), 'uploads': [json.dumps(upload)]}
                        job, summary = engine.prepare(value, fetch=fetch)
                        fetch.assert_called_once()
                        self.assertEqual(fetch.call_args.args, ([request.sources[0]],))
                        self.assertEqual(fetch.call_args.kwargs['user_agent'], options['ua'])
                        self.assertEqual(summary['source_count'], 4)
                        self.assertEqual(summary['remote_source_count'], 1)
                        self.assertEqual(summary['profile'], model.profile)
                        self.assertFalse(summary['link_backend_used'])
                        self.assertFalse(summary['router_changed'])
                        files = decoded_files(job)
                        self.assertEqual(job['source_names'], ['s000.txt', 's001.txt', 's002.txt', 's003.txt'])
                        self.assertEqual(files['s000.txt'], YAML.encode())
                        self.assertEqual(files['s000.txt'], files['s002.txt'])
                        self.assertEqual(base64.b64decode(files['s001.txt'], validate=True), URI.encode())
                        self.assert_typed_equal(formats.yaml_load(files['s003.txt'].decode()), upload)
                        self.assertEqual(job['options'], options | {'parameters': form['parameters']})
                        jobs.append(job)
                    self.assertEqual(jobs[0], jobs[1])
                    self.assertEqual(form, before)

    def test_remote_and_upload_counts_share_exact_32_source_limit(self):
        value = payload()
        value['form']['sources'] = [URL] * 16
        value['uploads'] = [YAML] * 16
        fetch = mock.Mock(return_value=[YAML.encode()])
        job, summary = engine.prepare(value, fetch=fetch)
        self.assertEqual(summary['source_count'], 32)
        self.assertEqual(summary['remote_source_count'], 1)
        self.assertEqual(len(job['files']), 32)
        self.assertEqual(list(decoded_files(job).values()), [YAML.encode()] * 32)
        fetch.assert_called_once()
        value['uploads'].append(YAML)
        self.assert_error('SOURCES', engine.prepare, value, fetch=self.no_fetch)
        self.no_fetch.assert_not_called()

    def test_sources_and_materialized_script_resources_share_exact_64_file_limit(self):
        value = payload()
        value['uploads'] = [YAML] * 32
        for count in (31, 32):
            with self.subTest(resources=count):
                value['resources'] = [{'name': 'piece-%02d.txt' % index, 'content': 'piece-%02d' % index}
                                      for index in range(count)]
                script = '\n'.join('fileGet("asset:piece-%02d.txt");' % index for index in range(count))
                # A repeated reference reuses an existing asset, not another file.
                script += '\nreadFile("asset:piece-00.txt");'
                value['scripts'] = {'filter': script}
                if count == 32:
                    self.assert_error('FETCH_SIZE', engine.prepare, value, fetch=self.no_fetch)
                    continue
                job, summary = engine.prepare(value, fetch=self.no_fetch)
                files = decoded_files(job)
                self.assertEqual(len(files), 64)
                self.assertEqual(len(job['source_names']), 32)
                self.assertEqual(summary['asset_count'], 32)
                rewritten = files[job['options']['filter_script_file']].decode()
                for resource in value['resources']:
                    name, = [key for key, raw in files.items() if raw == resource['content'].encode()]
                    script = script.replace('asset:' + resource['name'], './' + name)
                self.assertEqual(rewritten, script)
                self.assertFalse(summary['network_executed'])
        self.no_fetch.assert_not_called()

    def test_one_url_used_as_subscription_and_base_is_fetched_once_but_transformed_by_kind(self):
        value = payload()
        value['uploads'] = []
        value['form']['sources'] = [URL]
        value['config_content'] = '[custom]\nclash_rule_base=' + URL + '\n'
        fetch = mock.Mock(return_value=[URI.encode()])
        job, summary = engine.prepare(value, fetch=fetch)
        fetch.assert_called_once()
        files = decoded_files(job)
        config = files[job['options']['config']].decode()
        base_name = config.split('clash_rule_base=./', 1)[1].strip()
        self.assertEqual(files[base_name], URI.encode())
        self.assertEqual(files[job['source_names'][0]], base64.b64encode(URI.encode()))
        self.assertNotEqual(base_name, job['source_names'][0])
        self.assertEqual(summary['remote_source_count'], 1)
        self.assertEqual(summary['asset_count'], 2)

    def test_http_cache_is_not_reused_by_a_later_request(self):
        value = payload()
        value['form']['sources'] = [URL, URL]
        value['uploads'] = []
        original = copy.deepcopy(value)
        first, second = YAML.encode(), YAML.replace('合成节点', '下一份').encode()
        fetch = mock.Mock(side_effect=[[first], [second]])
        left, _ = engine.prepare(value, fetch=fetch)
        right, _ = engine.prepare(value, fetch=fetch)
        self.assertEqual(list(decoded_files(left).values()), [first, first])
        self.assertEqual(list(decoded_files(right).values()), [second, second])
        self.assertEqual(fetch.call_count, 2)
        self.assertEqual(value, original)

    def test_invalid_fetch_batch_never_commits_partial_cache(self):
        urls = [URL, 'https://sources.example.test/second.yaml']
        for invalid in ([b'a', b''], [b'a'], (b'a', b'b'), [b'a', bytearray(b'b')]):
            with self.subTest(shape=repr(invalid)):
                fetch = mock.Mock(side_effect=[invalid, [b'a', b'b']])
                budget = engine.IntakeBudget(fetch, 'Synthetic-Boundary/1')
                self.assert_error('CONTENT', budget.get, urls)
                self.assertEqual(budget.cache, {})
                self.assertEqual(budget.remaining, engine.MAX_JOB_BYTES)
                self.assertEqual(budget.get(urls), [b'a', b'b'])
                self.assertEqual(budget.get([urls[1], urls[0], urls[1]]), [b'b', b'a', b'b'])
                self.assertEqual(fetch.call_count, 2)
                self.assertEqual(budget.remaining, engine.MAX_JOB_BYTES - 2)
                # A hot cache must still observe the shared wall-clock deadline.
                with mock.patch.object(engine.time, 'monotonic', return_value=budget.deadline):
                    self.assert_error('FETCH_TIMEOUT', budget.get, urls)
                self.assertEqual(fetch.call_count, 2)

    def test_duplicate_remote_uri_expansion_observes_final_byte_budget(self):
        value = payload()
        value['form']['sources'] = [URL, URL]
        value['uploads'] = []
        encoded = base64.b64encode(URI.encode())
        maximum = 2 * len(encoded)
        self.assertLess(2 * len(URI.encode()), maximum - 1)
        for cap in (maximum, maximum - 1):
            with self.subTest(cap=cap), mock.patch.object(engine, 'MAX_JOB_BYTES', cap):
                fetch = mock.Mock(return_value=[URI.encode()])
                if cap < maximum:
                    self.assert_error('FETCH_SIZE', engine.prepare, value, fetch=fetch)
                else:
                    job, _ = engine.prepare(value, fetch=fetch)
                    self.assertEqual(list(decoded_files(job).values()), [encoded, encoded])
                    self.assertEqual(sum(map(len, decoded_files(job).values())), maximum)
                fetch.assert_called_once()
                self.assertEqual(fetch.call_args.kwargs['maximum'], cap)

    def test_yaml_and_toml_resource_rewrites_preserve_opaque_typed_data(self):
        for kind in ('yaml', 'toml'):
            with self.subTest(kind=kind):
                opaque = {'text': 'on true null 001\\literal🙂', 'control': 'a\u0085b\u2029c\ufffe',
                          'false': False, 'one': 1, 'negative_zero': -0.0, 'scientific': 1e20,
                          'empty_table': {}, 'empty_array': [], 'nested': [{'01': '001', 'values': [True, 1, '1']}],
                          'reference_like_text': 'asset:not-a-dependency.txt'}
                if kind == 'yaml':
                    opaque['null'] = None
                rules = [{'group': '节点🙂', 'ruleset': 'asset:rules.txt'},
                         {'group': '节点🙂', 'ruleset': 'clash-classic:asset:rules.txt'}]
                document = {'version': 1, 'custom': {'clash_rule_base': 'asset:base.yaml', 'opaque': opaque}}
                if kind == 'toml':
                    document['rulesets'] = rules
                else:
                    document['custom']['rulesets'] = rules
                value = payload()
                value['resources'] = [{'name': 'base.yaml', 'content': 'proxies: []\n'},
                                      {'name': 'rules.txt', 'content': 'DOMAIN,synthetic.example.test\n'}]
                value['config_content'] = formats.dump(document, kind)
                before = copy.deepcopy(value)
                job, summary = engine.prepare(value, fetch=self.no_fetch)
                files = decoded_files(job)
                result, result_kind = formats.load(files[job['options']['config']].decode())
                self.assertEqual(result_kind, kind)
                expected = copy.deepcopy(document)
                base_name, = [key for key, raw in files.items() if raw == b'proxies: []\n']
                rules_name, = [key for key, raw in files.items() if raw == b'DOMAIN,synthetic.example.test\n']
                expected['custom']['clash_rule_base'] = './' + base_name
                expected_rules = expected['rulesets'] if kind == 'toml' else expected['custom']['rulesets']
                expected_rules[0]['ruleset'] = './' + rules_name
                expected_rules[1]['ruleset'] = 'clash-classic:./' + rules_name
                self.assert_typed_equal(result, expected)
                self.assertEqual(summary['asset_count'], 3)
                self.assertEqual(value, before)
        self.no_fetch.assert_not_called()

    def test_uri_export_encoding_depends_on_target_and_list_mode(self):
        schemes = {'ss': 'ss', 'ssr': 'ssr', 'trojan': 'trojan', 'v2ray': 'vmess', 'mixed': 'trojan'}
        for target, scheme in schemes.items():
            plain = scheme + '://synthetic-only\r\n\r\n'
            encoded = base64.urlsafe_b64encode(plain.encode()).decode().rstrip('=')
            for flag in (None, False, True):
                with self.subTest(target=target, list=flag):
                    options = {'target': target}
                    if flag is not None:
                        options['list'] = flag
                    accepted, rejected = (plain, encoded) if flag else (encoded, plain)
                    engine.validate_export(accepted, options)
                    self.assert_error('RESULT', engine.validate_export, rejected, options)
        # Quantumult list output is base64 even when list=True; normal output is INI.
        encoded = base64.b64encode(URI.encode()).decode()
        engine.validate_export(encoded, {'target': 'quan', 'list': True})
        self.assert_error('RESULT', engine.validate_export, URI, {'target': 'quan', 'list': True})
        engine.validate_export('[SERVER]\n合成 = socks, 192.0.2.44, 1080\n', {'target': 'quan', 'list': False})

    def test_json_exports_reject_literal_and_escaped_duplicate_keys(self):
        for target in ('singbox', 'sssub', 'ssd'):
            for second_key in ('server', r'ser\u0076er'):
                with self.subTest(target=target, second_key=second_key):
                    row = '{"type":"socks","server":"192.0.2.1","%s":"198.51.100.2","server_port":1080}' % second_key
                    content = '[' + row + ']'
                    if target != 'sssub':
                        content = '{"%s":%s}' % ('servers' if target == 'ssd' else 'outbounds', content)
                    if target == 'ssd':
                        content = 'ssd://' + base64.b64encode(content.encode()).decode()
                    self.assert_error('RESULT', engine.validate_export, content, {'target': target})

    def test_prepare_error_releases_lock_for_a_later_explicit_execution(self):
        lock = threading.Lock()
        bridge = mock.Mock(enabled=True)
        bridge.call.return_value = envelope()
        real_prepare = engine.prepare
        with mock.patch.object(engine, 'LOCK', lock), mock.patch.object(
                engine, 'prepare', side_effect=lambda value: real_prepare(value, fetch=self.no_fetch)):
            invalid = payload(sort=False)
            invalid['scripts'] = {'sort': 'function compare(a,b){return 0;}'}
            self.assert_error('SCRIPT_SORT', engine.execute, invalid, bridge)
            bridge.call.assert_not_called()
            self.assertFalse(lock.locked())
            result = engine.execute(payload(), bridge)
            self.assertTrue(result['ok'])
            self.assertEqual(result['content'], YAML)
            bridge.call.assert_called_once()
            self.assertFalse(lock.locked())
        self.no_fetch.assert_not_called()

    def test_bridge_exception_and_invalid_body_do_not_retry_or_leak_lock(self):
        lock = threading.Lock()
        bridge = mock.Mock(enabled=True)
        bridge.call.side_effect = [RuntimeError('synthetic bridge failure'), envelope('proxies: []\n'), envelope()]
        real_prepare = engine.prepare
        with mock.patch.object(engine, 'LOCK', lock), mock.patch.object(
                engine, 'prepare', side_effect=lambda value: real_prepare(value, fetch=self.no_fetch)):
            with self.assertRaisesRegex(RuntimeError, 'synthetic bridge failure'):
                engine.execute(payload(), bridge)
            self.assertEqual(bridge.call.call_count, 1)
            self.assertFalse(lock.locked())
            self.assert_error('RESULT', engine.execute, payload(), bridge)
            self.assertEqual(bridge.call.call_count, 2)
            self.assertFalse(lock.locked())
            result = engine.execute(payload(), bridge)
            self.assertEqual(result['content'], YAML)
            self.assertEqual(bridge.call.call_count, 3)
            self.assertFalse(lock.locked())
            for call in bridge.call.call_args_list:
                self.assertEqual(call.args[0]['action'], 'converter_run')
                self.assertEqual(list(decoded_files(call.args[0]['job']).values()), [YAML.encode()])
        self.no_fetch.assert_not_called()


if __name__ == '__main__':
    unittest.main()
