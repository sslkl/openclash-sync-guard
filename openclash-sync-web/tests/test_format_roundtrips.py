"""Synthetic format roundtrips; no native converter, network, or credentials."""
import base64
import copy
import json
import math
from pathlib import Path
import shutil
import sys
import tomllib
import unittest
from unittest import mock
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'vendor' / 'pyyaml-6.0.2'))
import converter_formats as formats
import converter_mellow as mellow
import converter_surge as surge
from subscription_converter import ConverterError
import test_converter_mellow as mellow_fixture
import test_converter_surge as surge_fixture


YAML_WITH_TOML_TEXT = (
    ('literal', 'custom:\n  note: |\n    version=1\n', 'version=1\n'),
    ('folded', 'custom:\n  note: >\n    "version" = 1\n    tail\n', '"version" = 1 tail\n'),
    ('quoted', 'custom:\n  note: "start\n    \'version\' = 1\n    end"\n', "start 'version' = 1 end"),
    ('section', 'custom:\n  note: |\n    version=1\n    [custom]\n', 'version=1\n[custom]\n'),
)


def assert_semantics(test, actual, expected):
    """Equality alone misses bool/int coercion, mapping order, and negative zero."""
    test.assertIs(type(actual), type(expected))
    if isinstance(expected, dict):
        test.assertEqual(list(actual), list(expected))
        for key in expected:
            assert_semantics(test, actual[key], expected[key])
    elif isinstance(expected, list):
        test.assertEqual(len(actual), len(expected))
        for item, original in zip(actual, expected):
            assert_semantics(test, item, original)
    else:
        test.assertEqual(actual, expected)
        if isinstance(expected, float):
            test.assertEqual(math.copysign(1, actual), math.copysign(1, expected))


class FormatDetectionTests(unittest.TestCase):
    def test_yaml_string_content_does_not_force_toml(self):
        for label, text, note in YAML_WITH_TOML_TEXT:
            with self.subTest(style=label):
                expected = ({'custom': {'note': note}}, 'yaml')
                self.assertEqual(formats.load(text, kind='yaml'), expected)
                self.assertEqual(formats.load(text), expected)

    def test_explicit_toml_never_falls_back(self):
        for label, text, _ in YAML_WITH_TOML_TEXT:
            with self.subTest(style=label), mock.patch.object(formats, 'yaml_load') as yaml_load:
                with self.assertRaises(ConverterError) as exc:
                    formats.load(text, kind='toml')
                self.assertEqual(exc.exception.code, 'CONFIG_FORMAT')
                yaml_load.assert_not_called()

    def test_successful_toml_shape_failure_never_falls_back(self):
        for value in ('1979-05-27T07:32:00Z', 'nan', 'inf'):
            with self.subTest(value=value), mock.patch.object(formats, 'yaml_load') as yaml_load:
                with self.assertRaises(ConverterError) as exc:
                    formats.load('version=1\nvalue=' + value)
                self.assertEqual(exc.exception.code, 'CONFIG_FORMAT')
                yaml_load.assert_not_called()

    def test_fallback_keeps_yaml_validation(self):
        prefix = 'custom:\n  note: |\n    version=1\n'
        for tail in ('  note: duplicate\n', '  value: .nan\n', '  value: &a []\n  copy: *a\n',
                     '  value: !!python/object:new {}\n'):
            with self.subTest(tail=tail), self.assertRaises(ConverterError) as exc:
                formats.load(prefix + tail)
            self.assertEqual(exc.exception.code, 'CONFIG_FORMAT')

    def test_dispatch_parses_each_candidate_only_once(self):
        cases = (('custom: {value: 1}\n', 'yaml', 1, 0),
                 ('"version" = 1\n[custom]\nvalue = 1\n', 'toml', 0, 1),
                 (YAML_WITH_TOML_TEXT[0][1], 'yaml', 1, 1))
        for text, kind, yaml_calls, toml_calls in cases:
            with self.subTest(kind=kind, toml_calls=toml_calls):
                with mock.patch.object(formats, 'yaml_load', wraps=formats.yaml_load) as yaml_load, \
                        mock.patch.object(tomllib, 'loads', wraps=tomllib.loads) as toml_load:
                    self.assertEqual(formats.load(text)[1], kind)
                    self.assertEqual(yaml_load.call_count, yaml_calls)
                    self.assertEqual(toml_load.call_count, toml_calls)


class StructuredSemanticRoundtrips(unittest.TestCase):
    def test_explicit_format_roundtrips_empty_nested_and_scalar_shapes(self):
        documents = ({}, {'version': 1, 'custom': {}}, {'version': 1, 'custom': {
            '': '', 'quoted"key': "'literal'", 'a.b': {'value': '中文 🚦'},
            'types': [True, False, 0, 1, -2**63, 2**63 - 1, 1.0, -0.0, 1e20, -5e-324],
            'strings': ['null', 'on', 'false', '2026-09-08', '1e20', '\n\t\\"', 'a\u0085b'],
            'containers': [{}, [], {'empty': [[], {}]}],
        }})
        for index, document in enumerate(documents):
            for kind in ('yaml', 'toml'):
                with self.subTest(document=index, kind=kind):
                    before = copy.deepcopy(document)
                    encoded = formats.dump(document, kind)
                    decoded, detected = formats.load(encoded, kind=kind)
                    self.assertEqual(detected, kind)
                    assert_semantics(self, decoded, before)
                    assert_semantics(self, document, before)
                    self.assertEqual(formats.dump(decoded, kind), encoded)

    def test_yaml_nulls_roundtrip_and_toml_nulls_are_not_dropped(self):
        for document in ({'value': None}, {'value': [None]}, {'value': {'nested': None}}):
            with self.subTest(document=document):
                assert_semantics(self, formats.load(formats.dump(document, 'yaml'))[0], document)
                with self.assertRaises(ConverterError) as exc:
                    formats.dump(document, 'toml')
                self.assertEqual(exc.exception.code, 'CONFIG_FORMAT')

    def test_sip008_shape_stays_json_through_yaml_serialization(self):
        server = {'id': 'synthetic-id', 'server': 'ss.example.test', 'server_port': 443,
                  'method': 'aes-128-gcm', 'password': ' 合成 🚦 ', 'plugin': '',
                  'plugin_opts': '', 'remarks': 'Synthetic "server"'}
        for servers in ([], [server], [dict(server, server_port=1), dict(server, server_port=65535)]):
            for ensure_ascii in (False, True):
                with self.subTest(count=len(servers), ensure_ascii=ensure_ascii):
                    document = {'version': 1, 'servers': servers}
                    raw = json.dumps(document, ensure_ascii=ensure_ascii)
                    loaded, kind = formats.load(raw)
                    self.assertEqual(kind, 'yaml')
                    assert_semantics(self, loaded, document)
                    encoded = formats.dump(loaded, 'yaml')
                    assert_semantics(self, json.loads(encoded), document)
                    assert_semantics(self, formats.load(encoded)[0], document)


class SurgeSemanticRoundtrips(unittest.TestCase):
    def test_ruleset_second_intake_and_restored_yaml_preserve_semantics(self):
        for name in ('合成 🚦', "Exit)'s", 'Exit"(quoted)'):
            delimiter = "'" if '"' in name else '"'
            quoted = delimiter + name + delimiter
            source = surge_fixture.SOURCE.replace('DIRECT=direct', 'DIRECT=direct\nLocal=direct\nBlock=reject')
            source = source.replace('Probe=select,Synthetic-SS,DIRECT', quoted + '=select,Synthetic-SS,Local,Block')
            source = source.replace('DOMAIN,probe.example.test,Probe', 'RULE-SET,asset:rules,' + quoted)
            source = source.replace('FINAL,Probe', 'DEST-PORT,443,' + quoted + '\nFINAL,' + quoted)
            imported = 'DOMAIN-SUFFIX,example.test\nIP6-CIDR,2001:db8::/32,no-resolve\nDOMAIN-REGEX,"a,b"\n'
            with self.subTest(name=name):
                dependencies = []
                def dependency(path, kind, *, dependencies=dependencies, imported=imported):
                    dependencies.append((path, kind))
                    return imported
                expanded, metadata = surge.parse(source, dependency=dependency)
                self.assertEqual(dependencies, [('asset:rules', 'rule-content')])
                self.assertEqual(surge.parse(expanded)[1], metadata)
                document = surge_fixture.native()
                original = copy.deepcopy((document, metadata))
                restored = surge.restore(document, metadata)
                self.assertEqual(restored['rules'], ['DOMAIN-SUFFIX,example.test,' + name,
                    'IP-CIDR6,2001:db8::/32,' + name + ',no-resolve', 'DOMAIN-REGEX,a,b,' + name,
                    'DST-PORT,443,' + name, 'MATCH,' + name])
                self.assertEqual(restored['proxy-groups'], [
                    {'name': 'Local', 'type': 'select', 'proxies': ['DIRECT']},
                    {'name': 'Block', 'type': 'select', 'proxies': ['REJECT']},
                    {'name': name, 'type': 'select', 'proxies': ['Synthetic-SS', 'Local', 'Block']}])
                assert_semantics(self, formats.load(formats.dump(restored, 'yaml'))[0], restored)
                self.assertEqual((document, metadata), original)

    def test_group_kinds_keep_order_and_typed_options(self):
        for kind in sorted(surge.GROUP_TYPES):
            for lazy in (False, True):
                group = {'name': 'Probe', 'type': kind, 'proxies': ['Synthetic-SS', 'DIRECT']}
                spec = kind + ',Synthetic-SS,DIRECT'
                if kind in {'url-test', 'fallback', 'load-balance'}:
                    group.update(url='https://example.test/path,a', interval=1, timeout=0, tolerance=0, lazy=lazy)
                    spec += ',url="https://example.test/path,a",interval=1,timeout=0,tolerance=0,lazy=' + str(lazy).lower()
                if kind == 'load-balance':
                    group['strategy'] = 'round-robin'
                    spec += ',strategy=round-robin'
                with self.subTest(kind=kind, lazy=lazy):
                    source = surge_fixture.SOURCE.replace('select,Synthetic-SS,DIRECT', spec)
                    text, metadata = surge.parse(source)
                    self.assertEqual(surge.parse(text)[1], metadata)
                    restored = surge.restore(surge_fixture.native(), metadata)
                    assert_semantics(self, restored['proxy-groups'], [group])
                    assert_semantics(self, formats.load(formats.dump(restored, 'yaml'))[0], restored)


def supported_nodes():
    nodes = [dict(mellow_fixture.SS, name='SS-' + str(i) + '-合成', cipher=cipher, port=port,
                  password=password, udp=True, tfo=False)
             for i, (cipher, port, password) in enumerate(zip(sorted(mellow.SS_CIPHERS),
                 (1, 443, 65535), (' synthetic ', '合成,;@?&=/#%+', '合成🚦')))]
    for fixture in (mellow_fixture.HTTP, mellow_fixture.SOCKS):
        for authenticated in (False, True):
            nodes.append(dict(fixture, name=fixture['name'] + ('-auth' if authenticated else '-plain'),
                server='2001:db8::1', username='合成 user' if authenticated else '',
                password='合成/@?&#%' if authenticated else ''))
    for network in ('tcp', 'ws', 'h2'):
        for tls in (False, True):
            node = dict(mellow_fixture.VM, name='VM-' + network + '-' + str(tls), network=network,
                        tls=tls, tfo=tls, **{'skip-cert-verify': False})
            if tls:
                node['servername'] = 'tls.example.test'
            if network == 'ws':
                node['ws-opts'] = {'path': '/relay%2Fpath', 'headers': {'Host': 'ws.example.test'}}
            elif network == 'h2':
                node['h2-opts'] = {'path': '/relay', 'host': ['one.test', 'two.test', 'one.test']}
            nodes.append(node)
    return nodes


def mellow_repair_pair(nodes):
    """Synthetic native empty-credential output, plus its exact expected repair."""
    prefix = '[Log]\nloglevel = warning\n[Endpoint]\nDIRECT, builtin, freedom\n'
    suffix = ('\n[EndpointGroup]\nProxy, ' + ':'.join(node['name'] for node in nodes)
              + ', latency, interval=300, timeout=6\n[RoutingRule]\nFINAL,Proxy\n')
    placeholders = []
    for node in nodes:
        kind, name, address = node['type'], node['name'], node['server'] + ':' + str(node['port'])
        if kind == 'ss':
            placeholders.append(name + ', ss, ss://Og@' + address)
        elif kind == 'vmess':
            placeholders.append(name + ', vmess1, vmess1://@' + address + '?network=&tls=')
        else:
            placeholders.append(mellow.endpoint(dict(node, username='', password='')))
    return (prefix + '\n'.join(placeholders) + '\n' + suffix,
            prefix + '\n'.join(mellow.endpoint(node) for node in nodes) + '\n' + suffix)


class MellowSemanticRoundtrips(unittest.TestCase):
    def test_supported_matrix_repairs_after_structured_roundtrip_without_mutation(self):
        nodes = supported_nodes()
        native, expected = mellow_repair_pair(nodes)
        for kind in ('yaml', 'toml'):
            with self.subTest(kind=kind):
                document = {'version': 1, 'proxies': list(reversed(nodes))}
                before = copy.deepcopy(document)
                decoded, _ = formats.load(formats.dump(document, kind), kind=kind)
                normalized = formats.dump(decoded, 'yaml')
                mellow.validate_sources([normalized.encode()])
                repaired = mellow.repair(native, normalized)
                self.assertEqual(repaired, expected)
                mellow.validate(repaired)
                self.assertEqual(mellow.repair(repaired, normalized), repaired)
                assert_semantics(self, document, before)

    def test_invalid_combinations_are_not_erased_by_structured_roundtrip(self):
        nodes = (dict(mellow_fixture.HTTP, username='partial'),
                 dict(mellow_fixture.HTTP, tls=True), dict(mellow_fixture.SOCKS, udp=False),
                 dict(mellow_fixture.VM, port=True),
                 dict(mellow_fixture.VM, network='tcp', **{'ws-opts': {'path': '/relay'}}),
                 dict(mellow_fixture.VM, network='ws', **{'ws-opts': {}, 'ws-path': '/relay'}))
        for index, node in enumerate(nodes):
            for kind in ('yaml', 'toml'):
                with self.subTest(node=index, kind=kind):
                    decoded, _ = formats.load(formats.dump({'proxies': [node]}, kind), kind=kind)
                    with self.assertRaises(ConverterError) as exc:
                        mellow.validate_sources([formats.dump(decoded, 'yaml').encode()])
                    self.assertEqual(exc.exception.code, 'MELLOW_SOURCE')

    def test_ss_uri_dialects_and_base64_lists_repair_to_same_semantics(self):
        for node in supported_nodes()[:3]:
            # This subset returns only source-carried fields, not synthetic flags.
            expected = {key: value for key, value in node.items() if key not in {'udp', 'tfo'}}
            auth = node['cipher'] + ':' + node['password']
            address = node['server'] + ':' + str(node['port'])
            b64 = lambda text: base64.urlsafe_b64encode(text.encode()).decode().rstrip('=')
            for value in (b64(auth) + '@' + address, b64(auth + '@' + address)):
                raw = 'ss://' + value + '#' + quote(node['name'])
                with self.subTest(cipher=node['cipher'], full_authority='@' not in value):
                    assert_semantics(self, mellow.raw_uri_node(raw), expected)
                    for source in (raw, base64.b64encode(raw.encode()).decode()):
                        mellow.validate_sources([source.encode()])
                    native, repaired = mellow_repair_pair([expected])
                    self.assertEqual(mellow.repair(native, formats.dump({'proxies': [expected]}, 'yaml')), repaired)

    @unittest.skipUnless(mellow_fixture.PARSER and shutil.which('node'),
                         'requires captured official Mellow parser and Node')
    def test_repaired_matrix_matches_cached_official_parser(self):
        nodes = supported_nodes()
        native, _ = mellow_repair_pair(nodes)
        normalized = formats.dump({'proxies': list(reversed(nodes))}, 'yaml')
        parser = mellow_fixture.MellowOfficialParserTests()
        before = parser.parse_config(native)
        after = parser.parse_config(mellow.repair(native, normalized))
        self.assertEqual(after['routing'], before['routing'])
        self.assertEqual(after['log'], before['log'])
        self.assertEqual([outbound['tag'] for outbound in after['outbounds']], ['DIRECT'] + [n['name'] for n in nodes])
        for node, outbound in zip(nodes, after['outbounds'][1:]):
            with self.subTest(name=node['name']):
                kind = node['type']
                if kind == 'vmess':
                    self.assertEqual(outbound['settings']['vnext'], [{'address': node['server'], 'port': node['port'],
                        'users': [{'id': node['uuid']}]}])
                    stream = {'network': node['network'], 'security': 'tls' if node['tls'] else 'none',
                              'sockopt': {'tcpFastOpen': node['tfo']}}
                    if node['tls']:
                        stream['tlsSettings'] = {'serverName': node['servername'], 'allowInsecure': False}
                    if node['network'] == 'ws':
                        stream['wsSettings'] = node['ws-opts']
                    elif node['network'] == 'h2':
                        stream['httpSettings'] = node['h2-opts']
                    self.assertEqual(outbound['streamSettings'], stream)
                    self.assertEqual(outbound['protocol'], 'vmess')
                else:
                    server = {'address': node['server'], 'port': node['port']}
                    if kind == 'ss':
                        server.update(method=node['cipher'], password=node['password'])
                    elif node['username']:
                        server['users'] = [{'user': node['username'], 'pass': node['password']}]
                    self.assertEqual(outbound['settings']['servers'], [server])
                    self.assertEqual(outbound['protocol'], {'ss': 'shadowsocks', 'socks5': 'socks', 'http': 'http'}[kind])


if __name__ == '__main__':
    unittest.main()
