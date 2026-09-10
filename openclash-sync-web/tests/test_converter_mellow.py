"""Synthetic-only endpoint fixtures; optional tests execute the real Mellow parser.

Run with OPENCLASH_TEST_MELLOW_PARSER pointing at the downloaded official
src/config/convert.js. No upstream source is copied into this project.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import converter_mellow as m
import converter_engine as engine
from subscription_converter import ConverterError


UUID = '11111111-2222-4333-8444-555555555555'
SS = dict(name='Synthetic-SS', type='ss', server='192.0.2.1', port=443,
          cipher='aes-128-gcm', password='synthetic')
VM = dict(name='Synthetic-VMess', type='vmess', server='192.0.2.4', port=443,
          uuid=UUID, alterId=0, cipher='auto', tls=True)
HTTP = dict(name='Synthetic-HTTP', type='http', server='proxy.example.test', port=8080)
SOCKS = dict(HTTP, name='Synthetic-SOCKS', type='socks5', port=1080)
NATIVE = ('[Endpoint]\nDIRECT, builtin, freedom\n'
          'Synthetic-SS, ss, ss://Og@192.0.2.1:443\n'
          'Synthetic-VMess, vmess1, vmess1://@192.0.2.4:443?network=&tls=\n'
          '\n[EndpointGroup]\nProxy, Synthetic-SS:Synthetic-VMess, latency, interval=300, timeout=6\n'
          '\n[RoutingRule]\nDOMAIN-SUFFIX,example.test,DIRECT\nFINAL,Proxy\n')
NORMAL = json.dumps({'proxies': [SS, VM]})


def config(*nodes):
    return '[Endpoint]\n' + '\n'.join(m.endpoint(node) for node in nodes) + '\n'


def query(node):
    return parse_qs(urlsplit(m.endpoint(node).split(', ', 2)[2]).query)


class MellowTests(unittest.TestCase):
    def test_upstream_empty_credentials_rejected_then_repaired(self):
        with self.assertRaises(ConverterError):
            m.validate(NATIVE)
        value = m.repair(NATIVE, NORMAL)
        m.validate(value)
        self.assertIn(base64.urlsafe_b64encode(b'aes-128-gcm:synthetic').decode().rstrip('='), value)
        self.assertIn(f'vmess1://{UUID}@192.0.2.4:443?network=tcp&tls=true', value)
        self.assertEqual(value.split('[EndpointGroup]')[1], NATIVE.split('[EndpointGroup]')[1])

    def test_builtin_empty_native_credentials_repaired_one_to_one(self):
        nodes = [dict(HTTP, username='synthetic-http', password='http-pass'),
                 dict(SOCKS, username='synthetic-socks', password='socks-pass')]
        native = config(HTTP, SOCKS)
        repaired = m.repair(native, json.dumps({'proxies': list(reversed(nodes))}))
        self.assertEqual(repaired, config(*nodes))
        for value in ('tls=true', 'user=duplicate', 'unknown=ignored'):
            bad = native.replace('port=8080', 'port=8080, ' + value)
            with self.assertRaises(ConverterError):
                m.repair(bad, json.dumps({'proxies': nodes}))

    def test_builtin_credentials_ipv6_and_ws_preserved(self):
        http = dict(HTTP, server='2001:db8::1', username='synthetic-user', password='synthetic')
        self.assertIn('address=2001:db8::1', m.endpoint(http))
        self.assertIn('user=synthetic-user, pass=synthetic', m.endpoint(http))
        node = dict(VM, network='ws', servername='tls.example.test',
                    **{'ws-opts': {'path': '/relay', 'headers': {'Host': 'ws.example.test'}},
                       'skip-cert-verify': False})
        uri = urlsplit(m.endpoint(node).split(', ', 2)[2])
        self.assertEqual(uri.path, '/relay')
        self.assertEqual(query(node)['tls.servername'], ['tls.example.test'])
        self.assertEqual(query(node)['ws.host'], ['ws.example.test'])
        self.assertEqual(query(node)['tls.allowinsecure'], ['false'])

    def test_fail_closed_on_identity_protocol_duplicate_or_missing_node(self):
        bad_normal = [dict(SS, server='192.0.2.99'), dict(SS, port=444),
                      dict(HTTP, name=SS['name'], server=SS['server'], port=SS['port'])]
        for node in bad_normal:
            with self.subTest(node=node['name']), self.assertRaises(ConverterError):
                m.repair(NATIVE, json.dumps({'proxies': [node, VM]}))
        for nodes in ([SS, SS, VM], [SS, VM, HTTP], [VM], [], [None], {'bad': SS}):
            with self.subTest(shape=type(nodes).__name__), self.assertRaises(ConverterError):
                m.repair(NATIVE, json.dumps({'proxies': nodes}))
        duplicate = NATIVE.replace('[Endpoint]\n', '[Endpoint]\n' + m.endpoint(SS) + '\n')
        with self.assertRaises(ConverterError):
            m.repair(duplicate, NORMAL)

    def test_omitted_unsupported_nodes_never_become_partial_success(self):
        for node in (dict(SS, name='Plugin', plugin='obfs'),
                     dict(HTTP, name='TLS', tls=True), dict(VM, name='HTTP-transport', network='http')):
            with self.subTest(kind=node['type']), self.assertRaises(ConverterError):
                m.repair(NATIVE, json.dumps({'proxies': [SS, VM, node]}))

    def test_order_and_non_endpoint_bytes_survive_mixed_newlines(self):
        base = '[Log]\r\nloglevel = warning\r\n; retained comment\n'
        for ending in ('\n', '\r\n'):
            for trailing in (True, False):
                native = base + NATIVE.replace('\n', ending)
                if not trailing:
                    native = native[:-len(ending)]
                original_lines = native.splitlines(keepends=True)
                repaired = m.repair(native, json.dumps({'proxies': [VM, SS]}))
                repaired_lines = repaired.splitlines(keepends=True)
                self.assertEqual(len(original_lines), len(repaired_lines))
                changed = {index for index, parts in m.rows(native) if parts[0] in {SS['name'], VM['name']}}
                for index, original in enumerate(original_lines):
                    if index not in changed:
                        self.assertEqual(repaired_lines[index], original)
                    else:
                        self.assertEqual(repaired_lines[index][len(repaired_lines[index].rstrip('\r\n')):],
                                         original[len(original.rstrip('\r\n')):])
                self.assertEqual([parts[0] for _, parts in m.rows(repaired)],
                                 ['DIRECT', SS['name'], VM['name']])

    def test_existing_base_endpoints_are_not_replaced_by_address(self):
        base = m.endpoint(dict(SS, name='Base-SS', password='different-synthetic'))
        native = NATIVE.replace('[Endpoint]\n', '[Endpoint]\n' + base + '\n')
        self.assertIn(base + '\n', m.repair(native, NORMAL))
        with self.assertRaises(ConverterError):
            m.repair(NATIVE, json.dumps({'proxies': [SS, VM, dict(SS, name='DIRECT')]}))

    def test_input_nodes_are_not_mutated(self):
        nodes = [SS, dict(VM, network='h2', **{'h2-opts': {'host': ['one.test', 'two.test'], 'path': '/relay'}})]
        before = copy.deepcopy(nodes)
        for node in nodes:
            m.endpoint(node)
        m.repair(NATIVE, json.dumps({'proxies': nodes}))
        self.assertEqual(nodes, before)

    def test_native_leading_empty_ssr_line_is_valid(self):
        value = base64.b64encode(b'\nssr://c3ludGhldGlj\n').decode()
        engine.validate_export(value, {'target': 'ssr', 'list': False})
        for value in ['\n', base64.b64encode(b'\n\n').decode()]:
            with self.assertRaises(ConverterError):
                engine.validate_export(value, {'target': 'ssr', 'list': False})

    def test_execute_reuses_prepared_sources_without_second_fetch(self):
        def result(value, target):
            raw = value.encode()
            return dict(ok=True, content=value, sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw),
                        target=target, elapsed_ms=1, engine='subconverter-0.9.1-36573b3-isolated',
                        isolated=True, network='none', router_changed=False, cleanup_confirmed=True)
        bridge = mock.Mock(enabled=True)
        bridge.call.side_effect = [result(NATIVE, 'mellow'), result(NORMAL, 'clash')]
        job = {'version': 1, 'files': [], 'source_names': [], 'options': {'target': 'mellow', 'list': False}}
        with mock.patch.object(engine, 'prepare', return_value=(job, {})) as prep:
            value = engine.execute({}, bridge)
        self.assertEqual(prep.call_count, 1)
        self.assertEqual(bridge.call.call_count, 2)
        self.assertTrue(value['summary']['upstream_endpoint_fix'])
        m.validate(value['content'])
        self.assertEqual(value['sha256'], hashlib.sha256(value['content'].encode()).hexdigest())
        mirror = bridge.call.call_args_list[1].args[0]['job']
        self.assertIs(mirror['files'], job['files'])
        self.assertIs(mirror['source_names'], job['source_names'])
        self.assertEqual(job['options']['target'], 'mellow')


class MellowEndpointTests(unittest.TestCase):
    def rejects(self, nodes):
        for index, node in enumerate(nodes):
            with self.subTest(case=index), self.assertRaises(ValueError):
                m.endpoint(node)

    def test_ss_aead_passwords_and_explicit_native_udp(self):
        for cipher in ('aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305'):
            for password in ('synthetic', '  合成空格  ', 'synthetic,;@?&=/#%+'):
                node = dict(SS, cipher=cipher, password=password, udp=True, tfo=False)
                uri = urlsplit(m.endpoint(node).split(', ', 2)[2])
                decoded = base64.urlsafe_b64decode(uri.username + '=' * (-len(uri.username) % 4)).decode()
                self.assertEqual(decoded, cipher + ':' + password)
                m.validate(config(node))

    def test_ss_unsupported_ciphers_plugins_and_password_shapes(self):
        self.rejects([dict(SS, cipher=c) for c in ('2022-blake3-aes-128-gcm', 'aes-192-gcm', 'unknown', '')]
                     + [dict(SS, password=p) for p in ('', 'not:representable', 'line\nbreak', None, 123)]
                     + [dict(SS, **opts) for opts in ({'plugin': 'obfs'}, {'plugin-opts': {'mode': 'tls'}},
                                                      {'tls': True}, {'tfo': True}, {'udp': False})])

    def test_builtin_plain_and_authenticated_shapes(self):
        for fixture in (HTTP, SOCKS):
            for credentials in ({}, {'username': '', 'password': ''},
                                {'username': 'fixture user', 'password': 'test:/@#?&%'},
                                {'username': '测试用户', 'password': '合成口令'}):
                m.validate(config(dict(fixture, tls=False, **credentials)))
            m.validate(config(dict(fixture, server='2001:db8::1')))
        m.validate(config(dict(HTTP, udp=False), dict(SOCKS, udp=True)))

    def test_builtin_tls_and_unrepresentable_credentials_rejected(self):
        for fixture in (HTTP, SOCKS):
            self.rejects([dict(fixture, **opts) for opts in
                          ({'tls': True}, {'tls': 'false'}, {'skip-cert-verify': True}, {'tfo': True},
                           {'username': 'user'}, {'password': 'password'}, {'username': False},
                           {'headers': {'Host': 'host.test'}}, {'sni': 'host.test'})])
            for field in ('username', 'password'):
                self.rejects([dict(fixture, **({'username': 'u', 'password': 'p'} | {field: value}))
                              for value in ('bad=value', 'bad,value', 'bad;value', ' leading', 'trailing ',
                                            '\u00a0trimmed', '\ufefftrimmed', 'line\nbreak', None)])
        self.rejects([dict(HTTP, username='bad:user', password='synthetic'), dict(HTTP, udp=True)])

    def test_socks_authentication_length_is_utf8_bytes(self):
        m.validate(config(dict(SOCKS, username='u' * 255, password='p' * 255)))
        self.rejects([dict(SOCKS, username='u' * 256, password='p'),
                      dict(SOCKS, username='u', password='合' * 86)])

    def test_vmess_tcp_tls_and_socket_booleans(self):
        for tls in (False, True):
            for tfo in (False, True):
                node = dict(VM, tls=tls, tfo=tfo, udp=True)
                self.assertEqual(query(node)['network'], ['tcp'])
                self.assertEqual(query(node)['tls'], [str(tls).lower()])
                self.assertEqual(query(node)['sockopt.tcpfastopen'], [str(tfo).lower()])
                m.validate(config(node))
        for field in ('tls', 'tfo', 'skip-cert-verify', 'udp'):
            self.rejects([dict(VM, **{field: v}) for v in ('false', 0, 1, None, [], {})])
        self.rejects([dict(VM, tls=False, **{'skip-cert-verify': True}), dict(VM, udp=False),
                      dict(VM, tls=False, servername='tls.example.test')])

    def test_vmess_alterid_cipher_and_unsupported_protocols(self):
        self.rejects([dict(VM, alterId=v) for v in (64, -1, '0', False, 0.0, None)]
                     + [dict(VM, cipher=v) for v in ('aes-128-gcm', 'none', 'zero', None)]
                     + [dict(VM, network=v) for v in ('grpc', 'quic', 'kcp', '', None, [])]
                     + [dict(VM, type=v) for v in ('vless', 'trojan', 'ssr', None, [])])
        self.rejects([dict(VM, **{field: value}) for field, value in
                      (('uuid', 'invalid'), ('dialer-proxy', 'upstream'), ('alpn', ['h2']),
                       ('client-fingerprint', 'chrome'), ('reality-opts', {}), ('smux', {'enabled': True}),
                       ('packet-encoding', 'xudp'), ('v2ray-http-upgrade', True))])

    def test_clash_http_transport_is_never_mellow_http2(self):
        self.rejects([dict(VM, network='http', tls=tls, **opts)
                      for tls in (False, True)
                      for opts in ({}, {'http-opts': {}}, {'http-opts': {'method': 'GET', 'path': ['/relay'],
                                                              'headers': {'Host': ['one.test']}}})])
        self.rejects([dict(VM, network='tcp', **{'tcp-opts': {'header': {'type': 'http'}}})])

    def test_websocket_legacy_modern_defaults_and_sni(self):
        modern = dict(VM, network='ws', **{'ws-opts': {'path': '/relay', 'headers': {'Host': 'ws.test'}}})
        legacy = dict(VM, network='ws', **{'ws-path': '/relay', 'ws-headers': {'Host': 'ws.test'}})
        self.assertEqual(m.endpoint(modern), m.endpoint(legacy))
        self.assertEqual(query(modern)['tls.servername'], ['ws.test'])
        self.assertEqual(query(dict(modern, servername='sni.test'))['tls.servername'], ['sni.test'])
        self.assertNotIn('tls.servername', query(dict(modern, tls=False)))
        for node in (dict(VM, network='ws'), dict(VM, network='ws', **{'ws-opts': {}})):
            m.validate(config(node))

    def test_websocket_option_types_unknown_keys_and_schema_conflicts(self):
        self.rejects([dict(VM, network='ws', **{'ws-opts': value}) for value in
                      (None, [], '', {'headers': None}, {'headers': []}, {'headers': {'Edge': 'x'}},
                       {'headers': {'Host': ['one.test']}}, {'headers': {'Host': ''}},
                       {'max-early-data': 2048}, {'early-data-header-name': 'Sec-WebSocket-Protocol'})])
        self.rejects([dict(VM, network='ws', **{'ws-opts': {}, field: value})
                      for field, value in (('ws-path', '/legacy'), ('ws-headers', {'Host': 'legacy.test'}))])
        self.rejects([dict(VM, network='ws', **{'ws-headers': value}) for value in (None, [], {'Edge': 'x'})])

    def test_sni_is_not_a_url_or_host_port(self):
        self.rejects([dict(VM, servername=value) for value in
                      ('tls.test:443', 'https://tls.test', 'tls.test/path', 'tls.test?query',
                       'tls.test#fragment', 'user@tls.test', '%74ls.test', 'tls.test..')])
        host_port = dict(VM, network='ws', **{'ws-opts': {'headers': {'Host': 'ws.test:8443'}}})
        self.rejects([host_port])
        self.assertEqual(query(dict(host_port, servername='ws.test'))['ws.host'], ['ws.test:8443'])
        self.assertEqual(query(dict(host_port, tls=False))['ws.host'], ['ws.test:8443'])

    def test_h2_host_list_path_and_unknown_options(self):
        for hosts in ([], ['one.test'], ['one.test', 'two.test', 'one.test']):
            node = dict(VM, network='h2', **{'h2-opts': {'host': hosts, 'path': '/relay'}})
            m.validate(config(node))
            if hosts:
                self.assertEqual(query(node)['http.host'], [','.join(hosts)])
        self.rejects([dict(VM, network='h2', **{'h2-opts': value}) for value in
                      (None, [], {'path': ['/relay']}, {'host': 'one.test'}, {'host': None}, {'host': [None]},
                       {'host': ['']}, {'host': ['one.test,two.test']}, {'host': ['one.test', ' two.test']},
                       {'headers': {'Host': ['one.test']}}, {'method': 'POST'}, {'unknown': True})])

    def test_transport_options_cannot_be_silently_discarded(self):
        for network in ('tcp', 'ws', 'h2'):
            fields = {'tcp': ('ws-opts', 'ws-headers', 'h2-opts'),
                      'ws': ('h2-opts', 'http-opts'), 'h2': ('ws-opts', 'ws-headers', 'http-opts')}[network]
            self.rejects([dict(VM, network=network, **{field: {}}) for field in fields])

    def test_query_injection_and_trimming_are_not_escaped_into_acceptance(self):
        for value in ('safe&tls.allowinsecure=true', 'safe=value', 'safe;comment', ' safe', 'safe ', 'a,b'):
            self.rejects([dict(VM, servername=value),
                          dict(VM, network='ws', **{'ws-opts': {'headers': {'Host': value}}}),
                          dict(VM, network='h2', **{'h2-opts': {'host': [value]}})])

    def test_encoded_uri_length_is_checked_before_returning_an_endpoint(self):
        self.rejects([dict(SS, password='p' * 4096),
                      dict(VM, network='ws', **{'ws-opts': {'path': '/' + 'p' * 4095}}),
                      dict(VM, network='h2', **{'h2-opts': {'path': '/' + 'p' * 4095}})])

    def test_name_server_and_port_shape_validation(self):
        for fixture in (SS, VM, HTTP, SOCKS):
            self.rejects([dict(fixture, name=v) for v in ('', ' leading', 'trailing ', 'a,b', 'a;b', 'a:b',
                                                         '\ufeffname', 'line\u2028break')]
                         + [dict(fixture, server=v) for v in ('', 'a@b', 'host/path', 'host?query', 'host#tag',
                                                              'host=value', 'host\\suffix', '例子.test', '%65xample.test')]
                         + [dict(fixture, port=v) for v in (0, 65536, True, False, '443', 443.0, None)])
            m.validate(config(dict(fixture, name='合成 节点 [A]', server='Proxy-1.Example.TEST')))
        for fixture in (SS, VM):
            self.rejects([dict(fixture, server=v) for v in ('2001:db8::1', '[2001:db8::1]')])


class MellowPathTests(unittest.TestCase):
    def test_encoded_paths_are_not_rejected_or_double_encoded(self):
        for network in ('ws', 'h2'):
            for path in ('/relay%2Fencoded%20path', '/%25%26%3D', '/a+b&c=d', '//relay', '/a\\b'):
                node = dict(VM, network=network, **{network + '-opts': {'path': path}})
                self.assertEqual(urlsplit(m.endpoint(node).split(', ', 2)[2]).path, path)
                m.validate(config(node))

    def test_whatwg_path_changes_and_ini_separators_are_rejected(self):
        for network in ('ws', 'h2'):
            for path in ('/家宽', '/a/../b', '/a/%2E%2e/b', '/%2e./b', '/./b', '/"quote', '/{brace}',
                         '/a?b', '/a#b', '/a,b', '/a;b', '/has space', 'relative', None, []):
                with self.subTest(network=network, path=path), self.assertRaises(ValueError):
                    m.endpoint(dict(VM, network=network, **{network + '-opts': {'path': path}}))


class MellowValidationTests(unittest.TestCase):
    def test_invalid_builtin_parameters_are_rejected_instead_of_ignored(self):
        for params in ('address=proxy.test, port=0', 'address=proxy.test, port=65536',
                       'address=proxy.test, port=443suffix', 'address=proxy.test, port=443, user=u',
                       'address=proxy.test, port=443, pass=p', 'address=proxy.test, port=443, tls=true',
                       'address=proxy.test, port=443, user=u, pass=p=q',
                       'address=proxy.test, port=443, user=u, pass=p, user=other'):
            for protocol in ('http', 'socks'):
                with self.subTest(params=params, protocol=protocol), self.assertRaises(ConverterError):
                    m.validate('[Endpoint]\nFixture, builtin, ' + protocol + ', ' + params + '\n')

    def test_invalid_uri_auth_address_query_and_percent_encoding(self):
        for uri in ('ss://Og@192.0.2.1:443', 'ss://aW52YWxpZA@192.0.2.1:443',
                    f'vmess1://{UUID}:unexpected@192.0.2.4:443?network=tcp',
                    f'vmess1://{UUID}@%31%39%32.0.2.4:443?network=tcp',
                    f'vmess1://{UUID}@[2001:db8::1]:443?network=tcp',
                    f'vmess1://{UUID}@192.0.2.4:443/path#ignored'):
            with self.subTest(uri=uri), self.assertRaises(ConverterError):
                m.validate('[Endpoint]\nFixture, ' + uri.split('://')[0] + ', ' + uri + '\n')
        for query_string in ('network=', 'network=grpc', 'network=tcp&tls=', 'tls=TRUE', 'unknown=value',
                             'tls=false&tls=true', 'ws.host=%ZZ', 'ws.host=%FF', 'mux=4suffix', 'mux=0',
                             'network=tcp&ws.host=ignored.test', 'network=tcp&http.host=ignored.test',
                             'network=tcp&header=http', 'tls=false&tls.servername=ignored.test',
                             'network=ws&kcp.mtu=1200', 'network=ws&quic.key=ignored'):
            with self.subTest(query=query_string), self.assertRaises(ConverterError):
                m.validate(f'[Endpoint]\nFixture, vmess1, vmess1://{UUID}@192.0.2.4:443?{query_string}\n')
        plugin = m.endpoint(SS) + '?plugin=obfs'
        with self.assertRaises(ConverterError):
            m.validate('[Endpoint]\n' + plugin + '\n')

    def test_section_case_inline_comments_and_duplicate_names(self):
        m.validate(config(SS).replace('[Endpoint]', '[Endpoint] ; fixture section'))
        for content in (config(SS).replace('[Endpoint]', '[endpoint]'),
                        config(SS).replace('[Endpoint]', '[ENDPOINT]'), config(SS, SS),
                        '[Endpoint]\nDIRECT, builtin, freedom\n', None, ''):
            with self.subTest(content_type=type(content).__name__), self.assertRaises(ConverterError):
                m.validate(content)


PARSER = os.environ.get('OPENCLASH_TEST_MELLOW_PARSER', '')


@unittest.skipUnless(PARSER and shutil.which('node'),
                     'set OPENCLASH_TEST_MELLOW_PARSER to official Mellow src/config/convert.js')
class MellowOfficialParserTests(unittest.TestCase):
    """The real parser, including INI sections and routing, not a URL approximation."""
    def parse_config(self, content):
        harness = r"""
const fs = require('node:fs'), vm = require('node:vm');
const warnings = [];
const context = {URL, module: {exports: {}}, require(name) {
  if (name === 'util') return require('node:util');
  if (name === 'electron-log') return {warn(...args) {warnings.push(args)}, info() {}, error() {}};
  if (name === 'base64url') return {decode(s) {return Buffer.from(s, 'base64url').toString('utf8')}};
  throw new Error('unexpected require');
}};
vm.runInNewContext(fs.readFileSync(process.argv[1], 'utf8'), context, {timeout: 1000});
const content = JSON.parse(fs.readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify({config: context.module.exports.constructJson(content), warnings}));
"""
        result = subprocess.run(['node', '-e', harness, PARSER], input=json.dumps(content),
                                text=True, capture_output=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 0, 'official parser failed (synthetic input)')
        parsed = json.loads(result.stdout)
        self.assertEqual(parsed['warnings'], [])
        return parsed['config']

    def parse(self, nodes):
        content = config(*nodes)
        m.validate(content)
        parsed = self.parse_config(content)['outbounds']
        self.assertEqual(len(parsed), len(nodes))
        self.assertEqual([value['tag'] for value in parsed], [node['name'] for node in nodes])
        return parsed

    def test_ss_ciphers_passwords_and_hostname_case_roundtrip(self):
        nodes = [dict(SS, name=f'SS-{index}', cipher=cipher, server='Proxy.Example.TEST', password=password)
                 for index, (cipher, password) in enumerate(zip(
                     ('aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305'),
                     ('synthetic', '  合成空格  ', 'synthetic,;@?&=/#%+')))]
        for node, parsed in zip(nodes, self.parse(nodes)):
            self.assertEqual(parsed['protocol'], 'shadowsocks')
            self.assertEqual(parsed['settings']['servers'][0],
                             dict(method=node['cipher'], password=node['password'],
                                  address=node['server'], port=node['port']))

    def test_builtin_authentication_and_ipv6_roundtrip(self):
        nodes = [dict(fixture, name=fixture['name'] + suffix, server='2001:db8::1', **credentials)
                 for fixture in (HTTP, SOCKS) for suffix, credentials in
                 (('-plain', {}), ('-auth', {'username': 'fixture user', 'password': '合成:/@#?&%'}))]
        for node, parsed in zip(nodes, self.parse(nodes)):
            self.assertEqual(parsed['protocol'], 'socks' if node['type'] == 'socks5' else 'http')
            server = parsed['settings']['servers'][0]
            self.assertEqual(server['address'], node['server'])
            self.assertEqual(server['port'], node['port'])
            if node.get('username'):
                self.assertEqual(server['users'], [{'user': node['username'], 'pass': node['password']}])
            else:
                self.assertNotIn('users', server)

    def test_uri_ipv6_retains_brackets_unlike_builtin_ipv6(self):
        content = config(SS, VM).replace('@192.0.2.1:443', '@[2001:db8::1]:443')
        content = content.replace('@192.0.2.4:443', '@[2001:db8::1]:443')
        parsed = self.parse_config(content)['outbounds']
        self.assertEqual(parsed[0]['settings']['servers'][0]['address'], '[2001:db8::1]')
        self.assertEqual(parsed[1]['settings']['vnext'][0]['address'], '[2001:db8::1]')
        for fixture in (SS, VM):
            with self.assertRaises(ValueError):
                m.endpoint(dict(fixture, server='2001:db8::1'))

    def test_repaired_builtin_credentials_roundtrip(self):
        nodes = [dict(HTTP, username='http-user', password='http-pass'),
                 dict(SOCKS, username='socks-user', password='socks-pass')]
        repaired = m.repair(config(HTTP, SOCKS), json.dumps({'proxies': list(reversed(nodes))}))
        parsed = self.parse_config(repaired)['outbounds']
        self.assertEqual([outbound['tag'] for outbound in parsed], [node['name'] for node in nodes])
        for node, outbound in zip(nodes, parsed):
            self.assertEqual(outbound['settings']['servers'][0]['users'],
                             [{'user': node['username'], 'pass': node['password']}])

    def test_vmess_tcp_tls_sni_certificate_and_tfo_roundtrip(self):
        nodes = [dict(VM, name='TCP-plain', tls=False), dict(VM, name='TCP-TLS', servername='tls.test',
                 tfo=True, **{'skip-cert-verify': False}), dict(VM, name='TCP-insecure', tfo=False,
                 **{'skip-cert-verify': True})]
        parsed = self.parse(nodes)
        for node, outbound in zip(nodes, parsed):
            self.assertEqual(outbound['settings']['vnext'][0],
                             {'users': [{'id': UUID}], 'address': node['server'], 'port': node['port']})
            self.assertEqual(outbound['streamSettings']['network'], 'tcp')
            self.assertEqual(outbound['streamSettings']['security'], 'tls' if node['tls'] else 'none')
            self.assertNotIn('httpSettings', outbound['streamSettings'])
            self.assertNotIn('tcpSettings', outbound['streamSettings'])
        self.assertEqual(parsed[1]['streamSettings']['tlsSettings'], {'serverName': 'tls.test', 'allowInsecure': False})
        self.assertEqual(parsed[2]['streamSettings']['tlsSettings'], {'allowInsecure': True})
        self.assertEqual(parsed[1]['streamSettings']['sockopt'], {'tcpFastOpen': True})
        self.assertEqual(parsed[2]['streamSettings']['sockopt'], {'tcpFastOpen': False})

    def test_websocket_legacy_modern_path_and_sni_roundtrip(self):
        modern = dict(VM, name='WS-new', network='ws', servername='tls.example.test',
                      **{'ws-opts': {'path': '/relay%2Fencoded%20path', 'headers': {'Host': 'ws.example.test'}}})
        legacy = dict(VM, name='WS-old', network='ws',
                      **{'ws-path': '/a+b&c=d', 'ws-headers': {'Host': 'ws.example.test'}})
        for node, parsed in zip((modern, legacy), self.parse([modern, legacy])):
            stream = parsed['streamSettings']
            path = node.get('ws-path', node.get('ws-opts', {}).get('path'))
            self.assertEqual(stream['network'], 'ws')
            self.assertEqual(stream['wsSettings'], {'path': path, 'headers': {'Host': 'ws.example.test'}})
            self.assertEqual(stream['tlsSettings']['serverName'], node.get('servername', 'ws.example.test'))

    def test_h2_host_order_and_path_roundtrip(self):
        nodes = [dict(VM, name='H2', network='h2', **{'h2-opts': {'path': '/relay%2Fencoded',
                 'host': ['one.test', 'two.test', 'one.test']}}), dict(VM, name='H2-default', network='h2')]
        parsed = self.parse(nodes)
        self.assertEqual(parsed[0]['streamSettings']['network'], 'h2')
        self.assertEqual(parsed[0]['streamSettings']['httpSettings'],
                         {'host': ['one.test', 'two.test', 'one.test'], 'path': '/relay%2Fencoded'})
        self.assertNotIn('httpSettings', parsed[1]['streamSettings'])
        self.assertNotIn('tcpSettings', parsed[0]['streamSettings'])
        cleartext = self.parse([dict(nodes[0], tls=False)])[0]['streamSettings']
        self.assertEqual(cleartext['security'], 'none')
        self.assertEqual(cleartext['httpSettings'], parsed[0]['streamSettings']['httpSettings'])

    def test_native_http_alias_is_http2_not_clash_tcp_http_obfuscation(self):
        content = f'[Endpoint]\nNative-H2, vmess1, vmess1://{UUID}@192.0.2.4:443/relay?network=http&tls=true&http.host=one.test\n'
        m.validate(content)  # An existing native base HTTP/2 endpoint is valid.
        stream = self.parse_config(content)['outbounds'][0]['streamSettings']
        self.assertEqual(stream['httpSettings'], {'path': '/relay', 'host': ['one.test']})
        self.assertNotIn('tcpSettings', stream)
        with self.assertRaises(ValueError):
            m.endpoint(dict(VM, network='http', **{'http-opts': {'path': ['/relay'], 'headers': {'Host': ['one.test']}}}))

    def test_names_order_groups_and_routing_survive_repair(self):
        native = NATIVE.replace(SS['name'], '合成 香港 A').replace(VM['name'], '合成 VMess B')
        nodes = [dict(VM, name='合成 VMess B'), dict(SS, name='合成 香港 A')]
        repaired = m.repair(native, json.dumps({'proxies': nodes}))
        before, after = self.parse_config(native), self.parse_config(repaired)
        self.assertEqual(after['routing'], before['routing'])
        self.assertEqual([outbound['tag'] for outbound in after['outbounds']],
                         ['DIRECT', '合成 香港 A', '合成 VMess B'])
        self.assertEqual(after['routing']['balancers'][0]['selector'], ['合成 香港 A', '合成 VMess B'])

    def test_whatwg_preserves_supported_encoded_and_ascii_paths(self):
        nodes = [dict(VM, name=f'{network}-{index}', network=network, **{network + '-opts': {'path': path}})
                 for network in ('ws', 'h2')
                 for index, path in enumerate(('/relay%2Fencoded%20path', '/%25%26%3D', '/a+b&c=d', '//relay', '/a\\b'))]
        for node, parsed in zip(nodes, self.parse(nodes)):
            settings = 'wsSettings' if node['network'] == 'ws' else 'httpSettings'
            self.assertEqual(parsed['streamSettings'][settings]['path'], node[node['network'] + '-opts']['path'])


if __name__ == '__main__':
    unittest.main()
