"""Opt-in real Mihomo tests. All sockets are loopback; no public proxy is used.

OPENCLASH_TEST_MIHOMO=/absolute/path/to/verified/mihomo python3 -B -m unittest \
    discover -s tests -p test_chain_mihomo.py
The fixture's TEST-NET endpoint is intercepted by the synthetic upstream.
"""
from __future__ import annotations

import base64
import contextlib
import http.client
import json
import os
import select
from pathlib import Path
import shutil
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
BINARY = os.environ.get('OPENCLASH_TEST_MIHOMO', '')
NODE = 'Synthetic upstream A'
ENDPOINT = '198.51.100.8'
USER = 'fixture-user'
PASSWORD = 'fixture-password'


def exact(sock, size):
    result = b''
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise EOFError
        result += chunk
    return result


def headers(sock):
    data = b''
    while not data.endswith(b'\r\n\r\n'):
        data += exact(sock, 1)
        if len(data) > 16384:
            raise ValueError('oversized fixture request')
    return data.decode('ascii')


def socks_request(sock, authenticate=False):
    version, count = exact(sock, 2)
    if version != 5 or (2 if authenticate else 0) not in exact(sock, count):
        raise ValueError('fixture SOCKS greeting')
    sock.sendall(b'\x05\x02' if authenticate else b'\x05\x00')
    if authenticate:
        if exact(sock, 1) != b'\x01':
            raise ValueError('fixture auth version')
        user = exact(sock, exact(sock, 1)[0]).decode('utf-8')
        password = exact(sock, exact(sock, 1)[0]).decode('utf-8')
        valid = user == USER and password == PASSWORD
        sock.sendall(b'\x01\x00' if valid else b'\x01\x01')
        if not valid:
            raise ValueError('fixture rejected authentication')
    version, command, reserved, kind = exact(sock, 4)
    if (version, command, reserved) != (5, 1, 0):
        raise ValueError('fixture only accepts CONNECT')
    if kind == 1:
        host = socket.inet_ntop(socket.AF_INET, exact(sock, 4))
    elif kind == 3:
        host = exact(sock, exact(sock, 1)[0]).decode('ascii')
    else:
        raise ValueError('fixture address type')
    port = int.from_bytes(exact(sock, 2), 'big')
    sock.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
    return host, port


def http_connect(sock):
    request = headers(sock)
    first, *rows = request.split('\r\n')
    if first != 'CONNECT www.gstatic.com:80 HTTP/1.1':
        raise ValueError('unexpected CONNECT target')
    auth = 'Basic ' + base64.b64encode(f'{USER}:{PASSWORD}'.encode()).decode()
    fields = {line.split(':', 1)[0].lower(): line.split(':', 1)[1].strip() for line in rows if ':' in line}
    if fields.get('proxy-authorization') != auth:
        sock.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n')
        raise ValueError('fixture rejected authentication')
    sock.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')


class FixtureServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, address):
        self.errors.append('unexpected fixture handler error')


class FixtureHandler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(10)
        try:
            host, port = socks_request(sock)
            if (host, port) == (ENDPOINT, 1080):
                self.server.events.append('upstream-to-exit')
                if self.server.protocol == 'ss':
                    # Relay ciphertext to a real Shadowsocks listener in the same test core.
                    with socket.create_connection(('127.0.0.1', self.server.ss_port), timeout=10) as peer:
                        while True:
                            readable, _, _ = select.select([sock, peer], [], [], 10)
                            if not readable:
                                return
                            for source in readable:
                                data = source.recv(65536)
                                if not data:
                                    return
                                (peer if source is sock else sock).sendall(data)
                    return
                if self.server.tls_context:
                    sock = self.server.tls_context.wrap_socket(sock, server_side=True)
                if self.server.protocol == 'http':
                    http_connect(sock)
                else:
                    if socks_request(sock, authenticate=True) != ('www.gstatic.com', 80):
                        raise ValueError('unexpected nested destination')
                self.server.events.append('exit-authenticated')
            elif (host, port) == ('www.gstatic.com', 80):
                self.server.events.append('upstream-probe')
            else:
                raise ValueError('fixture will not access any other destination')
            request = headers(sock)
            if not request.startswith(('GET /generate_204 HTTP/1.1\r\n', 'HEAD /generate_204 HTTP/1.1\r\n')):
                raise ValueError('unexpected fixed probe')
            self.server.events.append('fixed-probe')
            # Mihomo's delay API rejects a measured 0 ms; make loopback deterministic.
            time.sleep(.01)
            sock.sendall(b'HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n')
        except (EOFError, ValueError, OSError) as error:
            self.server.events.append(type(error).__name__ + ":" + str(error))
        finally:
            if sock is not self.request:
                sock.close()


class FixtureSinkHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            http_connect(self.request)
            request = headers(self.request)
            if not request.startswith(('GET /generate_204 HTTP/1.1\r\n', 'HEAD /generate_204 HTTP/1.1\r\n')):
                raise ValueError('unexpected SS fixed probe')
            self.server.events.append('exit-authenticated')
            time.sleep(.01)
            self.request.sendall(b'HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n')
        except (EOFError, ValueError, OSError):
            self.server.events.append('sink-rejected')


def ruby_transform(config, state='', operation=None, profile=None):
    program = '''require "json"; require ARGV.shift
c=OpenClashCustomizer; x=JSON.parse(STDIN.read)
patch=x["operation"] == "remove" ? {"operation"=>"remove","node"=>x["node"]} : {"operation"=>"upsert","chain"=>x["profile"]}
r=c.render(x["config"].is_a?(String) ? x["config"] : YAML.dump(x["config"]), x["state"], c.chain_request(x["state"],patch))
puts JSON.generate({"config"=>r.config,"state"=>r.state,"decoded"=>c.safe_yaml(r.config),"view"=>c.chain_view(r.config,r.state)})
'''
    payload = dict(config=config, state=state, operation=operation, profile=profile, node=NODE)
    proc = subprocess.run(['ruby', '-e', program, str(ROOT / 'openclash_customizer.rb')],
                          input=json.dumps(payload), capture_output=True, text=True, timeout=15, check=False)
    if proc.returncode:
        raise AssertionError('Ruby transform failed (synthetic fixture)')
    return json.loads(proc.stdout)


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@unittest.skipUnless(BINARY and shutil.which('ruby'), 'set OPENCLASH_TEST_MIHOMO for real-core tests')
class RealMihomoChainTests(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self, protocol='socks5', password=PASSWORD, tls=False, cipher='aes-128-gcm'):
        with tempfile.TemporaryDirectory(prefix='openclash-real-chain-') as directory:
            root = Path(directory)
            controller = free_port()
            upstream = FixtureServer(('127.0.0.1', 0), FixtureHandler)
            upstream.protocol, upstream.events, upstream.errors = protocol, [], []
            upstream.tls_context = None
            if tls:
                command = ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout',
                           str(root/'key.pem'), '-out', str(root/'cert.pem'), '-days', '1', '-subj', '/CN=fixture.example.com']
                subprocess.run(command, check=True, capture_output=True, timeout=15)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(root/'cert.pem', root/'key.pem')
                upstream.tls_context = context
            thread = threading.Thread(target=upstream.serve_forever, daemon=True)
            thread.start()
            original = {'external-controller': f'127.0.0.1:{controller}', 'secret': 'synthetic-controller-only',
                        'log-level': 'silent', 'ipv6': False, 'dns': {'enable': False, 'fake-ip-filter': []},
                        'profile': {'store-selected': False, 'store-fake-ip': False},
                        'proxies': [{'name': NODE, 'type': 'socks5', 'server': '127.0.0.1', 'port': upstream.server_address[1]}],
                        'proxy-groups': [{'name': 'Fixture', 'type': 'select', 'proxies': [NODE]}], 'rules': ['MATCH,Fixture']}
            profile = dict(node=NODE, type=protocol, server=ENDPOINT, port=1080, username=USER, password=password)
            if tls:
                profile.update(tls=True, sni='fixture.example.com')
            sink, sink_thread = None, None
            if protocol == 'ss':
                sink = FixtureServer(('127.0.0.1', 0), FixtureSinkHandler)
                sink.events, sink.errors = upstream.events, upstream.errors
                sink_thread = threading.Thread(target=sink.serve_forever, daemon=True)
                sink_thread.start()
                upstream.ss_port = free_port()
                original['proxies'].append({'name': 'FixtureSink', 'type': 'http', 'server': '127.0.0.1',
                                            'port': sink.server_address[1], 'username': USER, 'password': PASSWORD})
                original['listeners'] = [{'name': 'fixture-ss-server', 'type': 'shadowsocks', 'listen': '127.0.0.1',
                                          'port': upstream.ss_port, 'cipher': cipher, 'password': PASSWORD,
                                          'udp': False, 'proxy': 'FixtureSink'}]
                profile.pop('username')
                profile['cipher'] = cipher
            process = None
            try:
                rendered = ruby_transform(original, profile=profile)
                (root/'config.yaml').write_text(rendered['config'])
                (root/'state').write_text(rendered['state'])
                (root/'node.json').write_text(json.dumps(NODE))
                (root/'state').chmod(0o600)
                (root/'config.yaml').chmod(0o600)
                check = subprocess.run([BINARY, '-t', '-d', str(root), '-f', str(root/'config.yaml')], capture_output=True, timeout=20, check=False)
                self.assertEqual(check.returncode, 0, 'real core rejected generated config')
                with (root/'core.log').open('wb') as output:
                    process = subprocess.Popen([BINARY, '-d', str(root), '-f', str(root/'config.yaml')], stdout=output, stderr=output)
                    ready = False
                    for _ in range(60):
                        if process.poll() is not None:
                            break
                        try:
                            connection = http.client.HTTPConnection('127.0.0.1', controller, timeout=.3)
                            connection.request('GET', '/version', headers={'Authorization': 'Bearer synthetic-controller-only'})
                            response = connection.getresponse()
                            ready = response.status == 200
                            response.read(); connection.close()
                            if ready:
                                break
                        except OSError:
                            pass
                        time.sleep(.05)
                    self.assertTrue(ready, 'real core controller did not become ready')
                    yield root, rendered, original, upstream
            finally:
                if process and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill(); process.wait(timeout=5)
                upstream.shutdown(); upstream.server_close(); thread.join(timeout=2)
                if sink:
                    sink.shutdown(); sink.server_close(); sink_thread.join(timeout=2)

    def probe(self, root):
        proc = subprocess.run(['ruby', str(ROOT/'openclash_customizer.rb'), 'chain-test', str(root/'config.yaml'),
                               str(root/'config.yaml'), str(root/'state'), str(root/'node.json')], capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(proc.returncode, 0, 'real core probe failed before classification')
        return json.loads(proc.stdout)

    def test_real_socks_and_http_chain_and_exact_cancel(self):
        for protocol in ('socks5', 'http', 'ss'):
            with self.subTest(protocol=protocol), self.fixture(protocol) as (root, rendered, original, upstream):
                result = self.probe(root)
                self.assertEqual(result['verdict'], 'PASS', result)
                self.assertEqual(result['upstream'], 'REACHABLE', (result, upstream.events))
                self.assertEqual(result['chain'], 'REACHABLE')
                self.assertIn('upstream-to-exit', upstream.events)
                self.assertIn('exit-authenticated', upstream.events)
                self.assertFalse(upstream.errors)
                restored = ruby_transform(rendered['config'], rendered['state'], operation='remove')
                self.assertEqual(restored['decoded'], original)
                self.assertEqual(restored['view']['chains'], [])
                self.assertNotIn(PASSWORD, json.dumps(rendered['view']))

    def test_all_supported_shadowsocks_ciphers_really_forward(self):
        for cipher in ('aes-256-gcm', 'chacha20-ietf-poly1305'):
            with self.subTest(cipher=cipher), self.fixture('ss', cipher=cipher) as (root, _, _, upstream):
                self.assertEqual(self.probe(root)['verdict'], 'PASS')
                self.assertIn('exit-authenticated', upstream.events)

    def test_wrong_exit_credentials_fail_even_when_upstream_reachable(self):
        for protocol in ('socks5', 'http', 'ss'):
            with self.subTest(protocol=protocol), self.fixture(protocol, password='incorrect-fixture-password') as (root, _, _, upstream):
                result = self.probe(root)
                self.assertEqual(result['upstream'], 'REACHABLE', (result, upstream.events))
                self.assertEqual(result['chain'], 'UNREACHABLE')
                self.assertEqual(result['verdict'], 'FAIL')
                self.assertNotIn('exit-authenticated', upstream.events)

    def test_untrusted_https_certificate_is_not_silently_accepted(self):
        with self.fixture('http', tls=True) as (root, _, _, upstream):
            result = self.probe(root)
            self.assertEqual(result['upstream'], 'REACHABLE', (result, upstream.events))
            self.assertEqual(result['chain'], 'UNREACHABLE')
            self.assertEqual(result['verdict'], 'FAIL')
            self.assertNotIn('exit-authenticated', upstream.events)


if __name__ == '__main__':
    unittest.main()
