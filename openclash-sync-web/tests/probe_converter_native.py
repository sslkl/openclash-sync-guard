"""Explicit WORKER-only synthetic native acceptance. Never auto-run with unit tests.

Run with the reviewed converter_sandbox module on a Docker host. This creates
short-lived no-network containers and checks cleanup; it never contacts nodes.
Output contains assertions, counts and timing only, not generated credentials.
"""
import base64
import json
import re
from urllib.parse import parse_qs, unquote, urlsplit

import converter_sandbox as sandbox

SYNTHETIC = '''proxies:
  - {name: Synthetic-SS, type: ss, server: 192.0.2.1, port: 443, cipher: aes-128-gcm, password: synthetic}
  - {name: Synthetic-SSR, type: ssr, server: 192.0.2.2, port: 443, cipher: aes-128-cfb, password: synthetic, protocol: origin, obfs: plain}
  - {name: Synthetic-Trojan, type: trojan, server: 192.0.2.3, port: 443, password: synthetic}
  - {name: Synthetic-VMess, type: vmess, server: 192.0.2.4, port: 443, uuid: 11111111-2222-4333-8444-555555555555, alterId: 0, cipher: auto, tls: true}
'''


def decode64(value):
    return base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True).decode()


def export_names(content, target, node_list):
    """Decode the format, including inner VMess/SSR payloads, before assertions."""
    if target in {'ss', 'ssr', 'trojan', 'v2ray', 'mixed'}:
        lines = (content if node_list else decode64(content.strip())).strip().splitlines()
        names = []
        for line in lines:
            scheme, _, value = line.partition('://')
            assert scheme in {'ss', 'ssr', 'vmess', 'trojan'}, 'share_scheme'
            if scheme == 'vmess':
                item = json.loads(decode64(value))
                assert item['add'].startswith('192.0.2.'), 'vmess_server'
                names.append(item['ps'])
            elif scheme == 'ssr':
                inner = decode64(value)
                query = parse_qs(inner.split('/?', 1)[1])
                names.append(decode64(query['remarks'][0]))
            else:
                url = urlsplit(line)
                assert url.hostname.startswith('192.0.2.'), 'share_server'
                names.append(unquote(url.fragment))
        return names
    if target == 'ssd':
        assert content.startswith('ssd://'), 'ssd_scheme'
        return [row['remarks'] for row in json.loads(decode64(content[6:]))['servers']]
    if target == 'sssub':
        rows = json.loads(content)
        assert isinstance(rows, list), 'sip008_list'
        return [row['remarks'] for row in rows]
    if target == 'singbox':
        data = json.loads(content)
        if not node_list:
            assert data['inbounds'][0]['listen'] == '127.0.0.1', 'base_listen'
            assert data['inbounds'][0]['listen_port'] == 7890, 'base_port'
            assert data['route']['final'] == 'Proxy', 'final_route'
        return [row['tag'] for row in data['outbounds'] if row.get('server')]
    if target == 'quan' and node_list:
        names = []
        for line in decode64(content.strip()).strip().splitlines():
            scheme, _, value = line.partition('://')
            if scheme == 'vmess':
                names.append(decode64(value).split(' = ', 1)[0])
            elif scheme == 'ssr':
                query = parse_qs(decode64(value).split('/?', 1)[1])
                names.append(decode64(query['remarks'][0]))
            else:
                assert scheme == 'ss', 'quantumult_share_scheme'
                names.append(unquote(urlsplit(line).fragment))
        return names
    if target in {'clash', 'clashr'}:
        assert re.search(r'^proxies:\s*$', content, re.M), 'yaml_proxies'
        if not node_list:
            assert 'port: 7890' in content and 'allow-lan: false' in content, 'base_settings'
            assert 'MATCH,Proxy' in content, 'final_rule'
    if not node_list:
        sections = {'surge': '[Proxy]', 'surfboard': '[Proxy]', 'loon': '[Proxy]', 'quanx': '[server_local]',
                    'quan': '[SERVER]', 'mellow': '[Endpoint]'}
        if target in sections:
            assert sections[target] in content, 'base_section'
    return list(dict.fromkeys(re.findall(r'Synthetic-(?:SS[R]?|Trojan|VMess)\b', content)))


def job(target, node_list):
    return {'version': 1, 'files': [{'name': 's000.txt', 'body': base64.b64encode(SYNTHETIC.encode()).decode()}],
            'source_names': ['s000.txt'], 'options': {'target': target, 'list': node_list}}


def remaining_jobs():
    code, body = sandbox.docker_metadata([sandbox.DOCKER, 'ps', '-aq', '--no-trunc',
                                          '--filter', 'name=^/openclash-sync-converter-'])
    assert code == 0, 'cleanup_query_failed'
    return len(body.splitlines())


def main():
    before = remaining_jobs()
    results = []
    matrix = [(target, node_list, None) for target in sorted(sandbox.TARGETS) for node_list in (False, True)]
    matrix += [('surge', node_list, version) for version in range(2, 6) for node_list in (False, True)]
    all_nodes = {'SS', 'SSR', 'Trojan', 'VMess'}
    expected_sets = {'mellow': {'SS', 'VMess'}, 'quan': {'SS', 'SSR', 'VMess'},
                     'ss': {'SS', 'SSR'}, 'ssd': {'SS', 'SSR'}, 'sssub': {'SS', 'SSR'},
                     'ssr': {'SSR'}, 'trojan': {'Trojan'}, 'v2ray': {'VMess'},
                     'surfboard': {'SS', 'Trojan', 'VMess'}}
    for target, node_list, version in matrix:
        record = {'target': target, 'list': node_list}
        case = job(target, node_list)
        if version is not None:
            case['options']['ver'] = version
            record['ver'] = version
        expected = expected_sets.get(target, all_nodes)
        if target == 'surge':
            expected = {'SS', 'Trojan', 'VMess'} if (version or 3) >= 4 else {'SS'}
        try:
            result = sandbox.run_job(case)
            assert result['cleanup_confirmed'], 'cleanup_unconfirmed'
            names = export_names(result['content'], target, node_list)
            assert set(names) == {'Synthetic-' + name for name in expected}, 'complete_expected_nodes'
            assert len(names) == len(set(names)), 'duplicate_export_nodes'
            record.update(ok=True, node_count=len(names), bytes=result['bytes'], elapsed_ms=result['elapsed_ms'])
        except (sandbox.SandboxError, AssertionError, ValueError, KeyError, TypeError) as exc:
            record.update(ok=False, error=type(exc).__name__)
            if isinstance(exc, AssertionError):
                record['assertion'] = str(exc)
        results.append(record)
    for label, value, options in [('invalid-source', 'not a subscription', {}),
                                  ('empty-proxies', 'proxies: []', {}),
                                  ('all-nodes-filtered', SYNTHETIC, {'exclude': '.*'})]:
        record = {'case': label}
        case = job('clash', False)
        case['files'][0]['body'] = base64.b64encode(value.encode()).decode()
        case['options'].update(options)
        try:
            sandbox.run_job(case)
            record.update(ok=False, assertion='invalid_source_accepted')
        except sandbox.SandboxError as exc:
            record.update(ok=str(exc) in {'SANDBOX', 'RESULT'}, code=str(exc))
        results.append(record)
    # External config, a relative imported ruleset list, and a relative base must
    # actually affect the output, not be silently ignored by scope-limited I/O.
    custom = job('clash', False)
    custom['options']['config'] = 'a000.txt'
    for name, value in {
        'a000.txt': '[custom]\nclash_rule_base=./a001.txt\nruleset=!!import:./a002.txt\ncustom_proxy_group=Probe`select`.*\n',
        'a001.txt': 'port: 17890\nallow-lan: false\nmode: rule\n',
        'a002.txt': 'Probe,./a003.txt\nProbe,[]FINAL\n',
        'a003.txt': 'DOMAIN,probe.example.test\n',
    }.items():
        custom['files'].append({'name': name, 'body': base64.b64encode(value.encode()).decode()})
    record = {'case': 'external-base-imported-rules'}
    try:
        result = sandbox.run_job(custom)
        assert result['cleanup_confirmed'], 'cleanup_unconfirmed'
        text = result['content']
        assert 'port: 17890' in text, 'custom_base'
        assert 'name: Probe' in text, 'custom_group'
        assert 'DOMAIN,probe.example.test,Probe' in text, 'custom_rules'
        assert 'MATCH,Probe' in text, 'custom_final'
        record.update(ok=True, elapsed_ms=result['elapsed_ms'])
    except (sandbox.SandboxError, AssertionError) as exc:
        record.update(ok=False, error=type(exc).__name__)
        if isinstance(exc, AssertionError): record['assertion'] = str(exc)
    results.append(record)
    rules = 'DOMAIN,probe.example.test\nDOMAIN-SUFFIX,example.test\nIP-CIDR,192.0.2.0/24,no-resolve\n'
    tools = []
    for kind in range(1, 7):
        tools.append(('ruleset-' + str(kind), rules, {'target': 'ruleset', 'type': kind, 'group': 'Probe', 'input_format': 'surge'},
                      '192.0.2.0/24' if kind == 4 else 'example.test', {}))
    tools += [('render-variable', 'Hello {{ request.title }}!', {'target': 'template', 'variables': {'title': 'Synthetic'}}, 'Hello Synthetic!', {}),
              ('render-include', '{% include "./a000.txt" %} {{ request.title }}', {'target': 'template', 'variables': {'title': 'Synthetic'}}, 'LocalSynthetic', {'a000.txt': 'Local'}),
              ('surge2clash-native-node-parser', '[General]\nloglevel=notify\n[Proxy]\nSynthetic-SS=ss,192.0.2.1,443,encrypt-method=aes-128-gcm,password=synthetic\n[Proxy Group]\nProbe=select,Synthetic-SS,DIRECT\n[Rule]\nDOMAIN,probe.example.test,Probe\nFINAL,Probe\n', {'target': 'surge2clash'}, 'Synthetic-SS', {})]
    for label, body, values, expected, resources in tools:
        record = {'case': label}
        case = {'version': 1, 'source_names': ['s000.txt'], 'options': values,
                'files': [{'name': name, 'body': base64.b64encode(content.encode()).decode()} for name, content in {'s000.txt': body, **resources}.items()]}
        try:
            result = sandbox.run_job(case)
            assert expected in result['content'], 'native_tool_result'
            assert result['cleanup_confirmed'], 'cleanup_unconfirmed'
            record.update(ok=True, bytes=result['bytes'], elapsed_ms=result['elapsed_ms'])
        except (sandbox.SandboxError, AssertionError) as exc:
            record.update(ok=False, error=type(exc).__name__, code=str(exc))
        results.append(record)
    after = remaining_jobs()
    report = {'ok': before == after == 0 and all(item['ok'] for item in results),
              'engine': 'subconverter-0.9.1-36573b3-isolated', 'image': sandbox.IMAGE,
              'containers_before': before, 'containers_after': after,
              'synthetic_only': True, 'router_changed': False, 'cases': results}
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
