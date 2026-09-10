"""Synthetic-only HTTP isolation and native-runner boundary regression."""
import base64
import hashlib
import io
from pathlib import Path
import sys
import tarfile
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import converter_fetch as f
import converter_sandbox as s
from subscription_converter import ConverterError

SOURCE = b'proxies:\n  - name: Synthetic\n    type: ss\n    server: 192.0.2.1\n    port: 443\n    cipher: aes-128-gcm\n    password: synthetic\n'


def job():
    return {'version': 1, 'files': [{'name': 's000.txt', 'body': base64.b64encode(SOURCE).decode()}],
            'source_names': ['s000.txt'], 'options': {'target': 'clash', 'list': True, 'scv': False}}


class SandboxTests(unittest.TestCase):
    def test_archive_has_only_regular_fixed_paths_and_no_production_configuration(self):
        archive, target = s.make_archive(job())
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            self.assertEqual(tar.getnames(), ['s000.txt', 'default-base.txt', 'pref.ini', 'request.url'])
            self.assertTrue(all(m.isreg() and m.uid == 65534 and m.gid == 65534 and m.mode == 0o600 for m in tar))
            prefs = tar.extractfile('pref.ini').read().decode()
            self.assertNotIn('all_base.tpl', prefs)
            self.assertNotIn('http', tar.extractfile('default-base.txt').read().decode())
            request = urlsplit(tar.extractfile('request.url').read().decode())
        self.assertEqual(target, 'clash')
        for key in ('enable_cache=false', 'proxy_subscription=NONE', 'skip_failed_links=false', 'api_mode=false'):
            self.assertIn(key, prefs)
        self.assertNotIn('gistconf', prefs)
        self.assertIn('base_path=./', prefs)
        self.assertIn('clash_rule_base=./default-base.txt', prefs)
        self.assertNotIn('_rule_base=/job/', prefs)
        self.assertEqual(request.netloc, '127.0.0.1:25500')
        self.assertEqual(request.path, '/sub')
        self.assertEqual(parse_qs(request.query), {'target': ['clash'], 'list': ['true'], 'scv': ['false'], 'url': ['./s000.txt']})
        self.assertNotIn('-g -f', s.RUN_SCRIPT)
        self.assertLess(s.RUN_SCRIPT.index('[ \"$ready\" = true ]'), s.RUN_SCRIPT.index(': >/job/native.err'))
        self.assertLess(s.RUN_SCRIPT.index(': >/job/native.err'), s.RUN_SCRIPT.index('cat /job/request.url'))

    def test_reject_path_traversal_duplicate_files_and_output_or_argv_injection(self):
        candidates = []
        for path in ('../evil', '/etc/passwd', 'pref.ini', 'generate.ini', 's000.txt\narg=true', 's00.txt'):
            value = job(); value['files'][0]['name'] = path; candidates.append(value)
        value = job(); value['files'] *= 2; candidates.append(value)
        for key in ('path', 'direct', 'profile', 'url', 'token', 'upload', '--privileged'):
            value = job(); value['options'][key] = 'synthetic'; candidates.append(value)
        for val in ('safe\npath=/result', 'safe\r\n', '\x85', '\x00'):
            value = job(); value['options']['include'] = val; candidates.append(value)
        value = job(); value['source_names'] = ['/etc/passwd']; candidates.append(value)
        value = job(); value['options']['target'] = []; candidates.append(value)
        for value in candidates:
            with self.subTest(shape='invalid-job'), self.assertRaises(s.SandboxError):
                s.make_archive(value)

    def test_input_encoding_total_size_and_option_types(self):
        for body in ('@@@@', base64.b64encode(b'\xff').decode(), base64.b64encode(b'\0').decode(), base64.b64encode(b'a' * (s.MAX_CONTENT+1)).decode()):
            value = job(); value['files'][0]['body'] = body
            with self.assertRaises(s.SandboxError): s.make_archive(value)
        for key, item in [('list', 1), ('ver', True), ('interval', 0), ('config', 'https://example.test/')]:
            value = job(); value['options'][key] = item
            with self.assertRaises(s.SandboxError): s.make_archive(value)

    def test_native_command_is_locked_to_image_no_network_host_mount_or_logs(self):
        args = s.command('openclash-sync-converter-' + 'a'*24)
        self.assertEqual(args[args.index('--network')+1], 'none')
        self.assertEqual(args[args.index('--user')+1], '65534:65534')
        self.assertEqual(args[args.index('--pull')+1], 'never')
        self.assertEqual(args[args.index('--log-driver')+1], 'none')
        self.assertIn(s.IMAGE, args)
        self.assertIn('--read-only', args)
        self.assertIn('no-new-privileges:true', args)
        for arg in ('--mount', '--volume', '-v', '--publish', '--privileged', '--device', '--pid', '--ipc'):
            self.assertNotIn(arg, args)
        with self.assertRaises(s.SandboxError): s.command('subconverter')

    def test_success_result_digest_and_cleanup_only_owned_name(self):
        calls = []
        def run(args, **kwargs):
            calls.append(args)
            if args[1] == 'create': kwargs['stdout'].write(b'a'*64 + b'\n')
            if args[1] == 'start': kwargs['stdout'].write(SOURCE)
            return mock.Mock(returncode=0)
        with mock.patch.object(s.subprocess, 'run', side_effect=run): result = s.run_job(job())
        self.assertTrue(result['isolated'])
        self.assertFalse(result['router_changed'])
        self.assertEqual(result['sha256'], hashlib.sha256(SOURCE).hexdigest())
        name = calls[0][calls[0].index('--name')+1]
        self.assertEqual(calls[1], [s.DOCKER, 'start', '-ai', name])
        self.assertEqual(calls[2], [s.DOCKER, 'rm', '-f', name])
        self.assertEqual(calls[3], [s.DOCKER, 'ps', '-aq', '--no-trunc', '--filter', 'name=^/' + name + '$'])
        self.assertTrue(result['cleanup_confirmed'])

    def test_timeout_and_invalid_output_still_remove_only_this_job(self):
        for bad in (b'', b'\xff', b'x'*(s.MAX_OUTPUT+1), None):
            calls = []
            def run(args, *, calls=calls, bad=bad, **kwargs):
                calls.append(args)
                if args[1] == 'create': kwargs['stdout'].write(b'a'*64 + b'\n')
                if args[1] == 'start':
                    if bad is None: raise s.subprocess.TimeoutExpired(args, 30)
                    kwargs['stdout'].write(bad)
                return mock.Mock(returncode=0)
            with mock.patch.object(s.subprocess, 'run', side_effect=run), self.assertRaises(s.SandboxError):
                s.run_job(job())
            self.assertEqual(calls[-2][1:3], ['rm', '-f'])
            self.assertEqual(calls[-1][1:3], ['ps', '-aq'])


    def test_create_uncertainty_can_never_start_a_late_native_job(self):
        calls = []
        def run(args, **kwargs):
            calls.append(args)
            if args[1] == 'create': raise s.subprocess.TimeoutExpired('create', 10)
            return mock.Mock(returncode=0)
        with mock.patch.object(s.subprocess, 'run', side_effect=run), self.assertRaises(s.SandboxError) as exc:
            s.run_job(job())
        self.assertEqual(str(exc.exception), 'SANDBOX_CLEANUP')
        self.assertFalse(any(args[1] == 'start' for args in calls))

    def test_daemon_failure_or_remaining_container_cannot_claim_cleanup(self):
        for remaining, status in ((b'', 1), (b'a'*64, 0)):
            def run(args, *, remaining=remaining, status=status, **kwargs):
                if args[1] == 'create': kwargs['stdout'].write(b'a'*64 + b'\n')
                if args[1] == 'start': kwargs['stdout'].write(SOURCE)
                if args[1] == 'ps':
                    kwargs['stdout'].write(remaining)
                    return mock.Mock(returncode=status)
                return mock.Mock(returncode=1 if args[1] == 'rm' else 0)
            with mock.patch.object(s.subprocess, 'run', side_effect=run), self.assertRaises(s.SandboxError) as exc:
                s.run_job(job())
            self.assertEqual(str(exc.exception), 'SANDBOX_CLEANUP')

    def test_default_bases_do_not_install_upstream_mitm_scripts_or_remote_resources(self):
        for target in s.TARGETS:
            with self.subTest(target=target):
                value = s.default_base(target)
                for forbidden in ('[MITM]', '[mitm]', '[Script]', 'cron ', 'http://', 'https://', 'all_base.tpl'):
                    self.assertNotIn(forbidden, value)


class Response:
    def __init__(self, status=200, body=b'synthetic', headers=None):
        import email.message
        self.status, self.body = status, io.BytesIO(body)
        self.headers = email.message.Message()
        for key, value in (headers or {}).items():
            for item in value if isinstance(value, list) else [value]: self.headers[key] = item
    def read1(self, size): return self.body.read(size)
    def getheader(self, name, default=None): return self.headers.get(name, default)
    def close(self): pass


class FetchTests(unittest.TestCase):
    def test_address_policy_rejects_private_metadata_transition_and_ipv4_mapped(self):
        for ip in ('127.0.0.1', '192.0.2.20', '169.254.169.254', '100.64.2.3', '0.0.0.0', '10.254.254.1',
                   '224.0.0.1', '168.63.129.16', '192.0.2.1', '::1', '::', 'fd00:ec2::254', 'fe80::1', '::ffff:8.8.8.8',
                   '64:ff9b::a9fe:a9fe', '2002:7f00:1::', '2001::1', 'ff0e::1'):
            with self.subTest(address=ip), self.assertRaises(ConverterError): f.public_ip(ip)
        self.assertEqual(f.public_ip('8.8.8.8'), '8.8.8.8')
        self.assertEqual(f.public_ip('2606:4700:4700::1111'), '2606:4700:4700::1111')

    def test_dns_mixed_answer_and_timeout_are_rejected(self):
        with mock.patch.object(f.subprocess, 'run', return_value=mock.Mock(returncode=0, stdout=b'["8.8.8.8","127.0.0.1"]')):
            with self.assertRaises(ConverterError) as exc: f.resolve_public('example.test', 2)
            self.assertEqual(exc.exception.code, 'FETCH_ADDRESS')
        with mock.patch.object(f.subprocess, 'run', side_effect=f.subprocess.TimeoutExpired('dns', 2)):
            with self.assertRaises(ConverterError) as exc: f.resolve_public('example.test', 2)
            self.assertEqual(exc.exception.code, 'FETCH_DNS')

    def fetch(self, responses, url='https://example.test/sub?token=synthetic', maximum=1024, resolver=None):
        self.connections, self.requests = [], []
        owner = self
        class Connection:
            def __init__(self, *args): owner.connections.append(args); self.sock = mock.Mock()
            def connect(self): pass
            def request(self, *args, **kwargs): owner.requests.append((args, kwargs))
            def getresponse(self): return responses.pop(0)
            def close(self): pass
        with mock.patch.object(f, 'PinnedConnection', Connection), mock.patch.object(f, 'resolve_public', side_effect=resolver or (lambda h, t: ('8.8.8.8',))):
            return f.PublicFetcher(maximum=maximum).fetch(url)

    def test_pinned_ip_host_sni_and_only_explicit_headers(self):
        result = self.fetch([Response(headers={'Content-Length': '9'})])
        self.assertEqual(result.body, b'synthetic')
        self.assertNotIn('synthetic', repr(result))
        self.assertEqual(self.connections[0][:4], ('example.test', 443, '8.8.8.8', True))
        self.assertEqual(self.requests[0][0], ('GET', '/sub?token=synthetic'))
        self.assertEqual(set(self.requests[0][1]['headers']), {'User-Agent', 'Accept', 'Accept-Encoding', 'Connection'})

    def test_redirect_revalidates_and_never_requests_private_hop(self):
        def resolve(host, timeout):
            if host == '127.0.0.1': return (f.public_ip(host),)
            return ('8.8.8.8',)
        with self.assertRaises(ConverterError):
            self.fetch([Response(302, headers={'Location': 'http://127.0.0.1/'})], url='http://example.test', resolver=resolve)
        self.assertEqual(len(self.connections), 1)
        with self.assertRaises(ConverterError) as exc:
            self.fetch([Response(302, headers={'Location': 'http://other.test/'})])
        self.assertEqual(exc.exception.code, 'FETCH_DOWNGRADE')

    def test_size_compression_protocol_and_redirect_fail_closed(self):
        responses = [Response(body=b'large', headers={'Content-Length': '5'}), Response(body=b'large'),
                     Response(headers={'Content-Encoding': 'gzip'}), Response(headers={'Content-Length': ['9','9']}),
                     Response(headers={'Content-Length': '9', 'Transfer-Encoding': 'chunked'}),
                     Response(302, headers={'Location': ['http://a.test', 'http://b.test']}),
                     Response(401), Response(headers={'Content-Length': '-1'})]
        for response in responses:
            with self.subTest(status=response.status), self.assertRaises(ConverterError) as exc:
                self.fetch([response], maximum=4)
            self.assertNotIn('synthetic', str(exc.exception))

    def test_public_worker_rejects_private_input_without_network(self):
        # Exercise actual worker framing and failure sanitization, not just mocks.
        with self.assertRaises(ConverterError) as exc:
            f.fetch_many(['http://127.0.0.1/?token=synthetic'])
        self.assertEqual(exc.exception.code, 'FETCH_ADDRESS')


if __name__ == '__main__': unittest.main()
