"""Synthetic engine->native->engine acceptance; explicit invocation only.

Use cases() to prepare bounded no-network jobs on the client. Run those exact
jobs through converter_sandbox.run_job on the approved Docker host, then call
verify() here with returned results. No production subscriptions are inputs.
Reports contain assertions/counts only, never the converted node credentials.
"""
from __future__ import annotations
import copy
import hashlib
import json
from unittest.mock import Mock

import converter_engine as engine
import converter_formats as formats
from subscription_converter import ConverterError

NODES = '''proxies:
  - {name: Bravo, type: ss, server: 192.0.2.1, port: 443, cipher: aes-128-gcm, password: synthetic}
  - {name: Alpha, type: ss, server: 192.0.2.2, port: 443, cipher: aes-128-gcm, password: synthetic}
'''
SURGE = '''[General]
loglevel=notify
[Proxy]
DIRECT=direct
Inline=ss,192.0.2.3,443,encrypt-method=aes-128-gcm,password=synthetic
[Proxy Group]
Probe=select,Inline,DIRECT
[Rule]
DOMAIN,probe.example.test,Probe
FINAL,Probe
'''


def conversion(**extra):
    return {'form': {'sources': '', 'options': {'target': 'clash'}}, 'uploads': [NODES], **extra}


def cases():
    values = []
    def add(label, payload, expected, tool=False):
        prepare = engine.prepare_tool if tool else engine.prepare
        job, _ = prepare(payload, fetch=Mock(side_effect=AssertionError('unexpected_fetch')))
        values.append({'case': label, 'payload': payload, 'tool': tool, 'expected': expected, 'job': job})
    add('filter-script-removes-true', conversion(scripts={'filter': 'function filter(n) { return n.Remark == "Bravo"; }'}), {'names': ['Alpha']})
    add('sort-script-orders-nodes', conversion(scripts={'sort': 'function compare(a,b) { return a.Remark < b.Remark; }'}), {'names': ['Alpha', 'Bravo']})
    add('filter-sort-both-active', conversion(scripts={'filter': 'function filter(n) { return n.Remark == "Bravo"; }', 'sort': 'function compare(a,b) { return a.Remark < b.Remark; }'}), {'names': ['Alpha']})
    add('filter-virtual-file', conversion(scripts={'filter': 'function filter(n) { return n.Remark == fileGet("asset:drop.txt", true).trim(); }'}, resources=[{'name': 'drop.txt', 'content': 'Bravo'}]), {'names': ['Alpha']})
    for role, script in [('filter', 'function filter(n) { throw new Error("synthetic failure"); }'),
                         ('filter', 'function filter('), ('filter', 'function wrong(n) { return false; }'),
                         ('sort', 'function compare(a,b) { throw new Error("synthetic failure"); }'), ('sort', 'function compare(')]:
        add('script-error-' + str(len(values)), conversion(scripts={role: script}), {'error': 'SANDBOX'})
    add('filter-all-nodes-not-a-valid-export', conversion(scripts={'filter': 'function filter(n) { return true; }'}), {'error': 'RESULT'})
    for fmt in ('ini', 'yaml', 'toml'):
        resources = [{'name': 'rename.js', 'content': 'function rename(n) { return "Renamed-" + n.Remark; }'}]
        if fmt == 'ini': config = '[custom]\nrename=!!script:path:asset:rename.js\n'
        elif fmt == 'yaml': config = formats.dump({'custom': {'rename_node': [{'script': 'path:asset:rename.js'}]}}, 'yaml')
        else: config = formats.dump({'version': 1, 'custom': {}, 'rename_node': [{'script': 'path:asset:rename.js'}]}, 'toml')
        add('rename-script-' + fmt, conversion(config_content=config, resources=resources), {'names': ['Renamed-Bravo', 'Renamed-Alpha']})
    base_resources = [{'name': 'base.yaml', 'content': 'port: 17890\nallow-lan: false\nmode: rule\n'},
                      {'name': 'rules.txt', 'content': 'DOMAIN-SUFFIX,resource.example.test\n'}]
    yaml_config = {'custom': {'clash_rule_base': 'asset:base.yaml', 'enable_rule_generator': True, 'overwrite_original_rules': True,
                              'proxy_groups': [{'import': 'asset:groups.txt'}], 'rulesets': [{'import': 'asset:rules-list.txt'}],
                              'rename_node': [{'import': 'asset:rename.txt'}]}}
    resources = base_resources + [{'name': 'groups.txt', 'content': '!!import:asset:groups2.txt\n'},
                                  {'name': 'groups2.txt', 'content': 'Integrated`select`.*\n'},
                                  {'name': 'rules-list.txt', 'content': 'Integrated,asset:rules.txt\nIntegrated,[]FINAL\n'},
                                  {'name': 'rename.txt', 'content': '^@YAML-\n'}]
    expected = {'names': ['YAML-Bravo', 'YAML-Alpha'], 'port': 17890, 'groups': {'Integrated': ['YAML-Bravo', 'YAML-Alpha']},
                'rules': ['DOMAIN-SUFFIX,resource.example.test,Integrated', 'MATCH,Integrated']}
    add('yaml-nested-imports-base-rules-rename', conversion(config_content=formats.dump(yaml_config, 'yaml'), resources=resources), expected)
    toml_config = {'version': 1, 'custom': {'clash_rule_base': 'asset:base.yaml', 'enable_rule_generator': True, 'overwrite_original_rules': True},
                   'custom_groups': [{'import': 'asset:groups.toml'}], 'rulesets': [{'import': 'asset:rules.toml'}], 'rename_node': [{'match': '^', 'replace': 'TOML-'}]}
    resources = base_resources + [
        {'name': 'groups.toml', 'content': formats.dump({'custom_groups': [{'import': 'asset:groups2.toml'}]}, 'toml')},
        {'name': 'groups2.toml', 'content': formats.dump({'custom_groups': [{'name': 'Integrated', 'type': 'select', 'rule': ['.*']}]}, 'toml')},
        {'name': 'rules.toml', 'content': formats.dump({'rulesets': [{'group': 'Integrated', 'ruleset': 'asset:rules.txt'}, {'group': 'Integrated', 'ruleset': '[]FINAL'}]}, 'toml')}]
    expected = {'names': ['TOML-Bravo', 'TOML-Alpha'], 'port': 17890, 'groups': {'Integrated': ['TOML-Bravo', 'TOML-Alpha']},
                'rules': ['DOMAIN-SUFFIX,resource.example.test,Integrated', 'MATCH,Integrated']}
    add('toml-nested-imports-base-rules-rename', conversion(config_content=formats.dump(toml_config, 'toml'), resources=resources), expected)
    custom = conversion(config_content='[custom]\ncustom_proxy_group={{ request.title }}`select`.*\nruleset={{ request.title }},[]FINAL\n')
    custom['form']['parameters'] = {'title': 'Custom-A&B'}
    add('conversion-custom-template-parameters', custom,
        {'names': ['Bravo', 'Alpha'], 'groups': {'Custom-A&B': ['Bravo', 'Alpha']}, 'rules': ['MATCH,Custom-A&B']})
    add('template-resource-and-variable', {'operation': 'template', 'content': '{% include "asset:part.tpl" %}{{ request.title }}',
                                          'resources': [{'name': 'part.tpl', 'content': 'Synthetic-'}], 'options': {'variables': {'title': 'Template'}}}, {'text': 'Synthetic-Template'}, True)
    add('surge-inline-groups-rules', {'operation': 'surge2clash', 'content': SURGE}, {'names': ['Inline'], 'groups': {'Probe': ['Inline', 'DIRECT']},
                                                                               'rules': ['DOMAIN,probe.example.test,Probe', 'MATCH,Probe']}, True)
    resources = [{'name': 'home.yaml', 'content': NODES.replace('Bravo', 'Residential').replace('Alpha', 'ResidentialBackup')},
                 {'name': 'server.yaml', 'content': 'proxies:\n  - {name: ServerNode, type: ss, server: 192.0.2.4, port: 443, cipher: aes-128-gcm, password: synthetic}\n'},
                 {'name': 'rules.txt', 'content': 'DOMAIN,from-ruleset.example.test\nIP-CIDR,192.0.2.0/24,no-resolve\n'}]
    source = SURGE.replace('Probe=select,Inline,DIRECT', 'Probe=select,Inline,Home,Server,DIRECT\nHome=select,policy-path=asset:home.yaml\nServer=select,policy-path=asset:server.yaml\nHomeAgain=select,DIRECT,policy-path=asset:home.yaml')
    source = source.replace('DOMAIN,probe.example.test,Probe', 'RULE-SET,asset:rules.txt,Home\nAND,((DOMAIN,logical.example.test),(NETWORK,TCP)),Probe')
    expected = {'names': ['Inline', 'Residential', 'ResidentialBackup', 'ServerNode'],
                'groups': {'Probe': ['Inline', 'Home', 'Server', 'DIRECT'], 'Home': ['Residential', 'ResidentialBackup'], 'Server': ['ServerNode'], 'HomeAgain': ['DIRECT', 'Residential', 'ResidentialBackup']},
                'rules': ['DOMAIN,from-ruleset.example.test,Home', 'IP-CIDR,192.0.2.0/24,Home,no-resolve', 'AND,((DOMAIN,logical.example.test),(NETWORK,TCP)),Probe', 'MATCH,Probe']}
    add('surge-multiple-policy-paths-rule-set-logical', {'operation': 'surge2clash', 'content': source, 'resources': resources}, expected, True)
    source = SURGE.replace('Inline=ss,192.0.2.3,443,encrypt-method=aes-128-gcm,password=synthetic\n', '').replace('Probe=select,Inline,DIRECT', 'Probe=select,policy-path=asset:server.yaml')
    add('surge-policy-only-no-inline-proxy', {'operation': 'surge2clash', 'content': source, 'resources': resources}, {'names': ['ServerNode'], 'groups': {'Probe': ['ServerNode']}}, True)
    # Final release regressions: real native conversion must preserve the
    # same Unicode and quoted-policy boundaries as the synthetic unit tests.
    unicode_nodes = formats.yaml_load(NODES)
    for node in unicode_nodes['proxies']:
        node['name'] += '-\U0001f642'
        node['password'] += '-\U0001f680'
    for escaped in (True, False):
        add('unicode-json-' + ('escaped' if escaped else 'literal'),
            conversion(uploads=[json.dumps(unicode_nodes, ensure_ascii=escaped)]),
            {'names': ['Bravo-\U0001f642', 'Alpha-\U0001f642'],
             'node_fields': {node['name']: {'password': node['password']} for node in unicode_nodes['proxies']}})
    for index, policy in enumerate(('Exit)', 'Exit(', "Exit'Label")):
        quoted = '"' + policy + '"'
        source = SURGE.replace('Probe=select', quoted + '=select').replace(',Probe', ',' + quoted)
        add('surge-quoted-policy-' + str(index), {'operation': 'surge2clash', 'content': source},
            {'names': ['Inline'], 'groups': {policy: ['Inline', 'DIRECT']},
             'rules': ['DOMAIN,probe.example.test,' + policy, 'MATCH,' + policy]}, True)
    source = SURGE.replace('Probe=select', '"Exit)"=select').replace(',Probe', ',"Exit)"')
    source = source.replace('DOMAIN,probe.example.test,"Exit)"', 'RULE-SET,asset:rules.txt,"Exit)",no-resolve')
    add('surge-quoted-ruleset-policy', {'operation': 'surge2clash', 'content': source,
        'resources': [{'name': 'rules.txt', 'content': 'IP-CIDR,192.0.2.0/24\n'}]},
        {'names': ['Inline'], 'groups': {'Exit)': ['Inline', 'DIRECT']},
         'rules': ['IP-CIDR,192.0.2.0/24,Exit),no-resolve', 'MATCH,Exit)']}, True)
    for imported in (False, True):
        rule = 'RULE-SET,asset:rules.txt,Probe' if imported else 'DOMAIN-REGEX,"^test{1,3}$",Probe'
        source = SURGE.replace('DOMAIN,probe.example.test,Probe', rule)
        add('surge-regex-comma-' + ('imported' if imported else 'inline'),
            {'operation': 'surge2clash', 'content': source,
             'resources': [{'name': 'rules.txt', 'content': 'DOMAIN-REGEX,"^test{1,3}$"\n'}] if imported else []},
            {'names': ['Inline'], 'groups': {'Probe': ['Inline', 'DIRECT']},
             'rules': ['DOMAIN-REGEX,^test{1,3}$,Probe', 'MATCH,Probe']}, True)
    return values


def verify(prepared, native_results, topology):
    reports = []
    assert len(prepared) == len(native_results), 'native_result_count'
    for case, native in zip(prepared, native_results):
        record = {'case': case['case']}
        class Bridge:
            enabled = True
            def call(self, payload, *, case=case, native=native):
                assert payload == {'action': 'converter_run', 'job': case['job']}, 'exact_prepared_job'
                return native
        try:
            try:
                result = engine.execute(copy.deepcopy(case['payload']), Bridge(), tool=case['tool'])
            except ConverterError as exc:
                assert exc.code == case['expected'].get('error'), 'expected_error_' + exc.code
                record.update(ok=True, rejected=True, code=exc.code)
            else:
                expected = case['expected']
                assert 'error' not in expected, 'invalid_conversion_accepted'
                assert result['cleanup_confirmed'] and result['isolated'] and result['network'] == 'none', 'sandbox_evidence'
                assert result['summary']['network_executed'] is False and result['router_changed'] is False, 'no_network_or_router_change'
                assert result['sha256'] == hashlib.sha256(result['content'].encode()).hexdigest(), 'final_digest'
                if 'text' in expected:
                    assert result['content'] == expected['text'], 'rendered_template_content'
                else:
                    document = formats.yaml_load(result['content'])
                    names = [node['name'] for node in document['proxies']]
                    assert names == expected['names'], 'exact_node_order'
                    if 'node_fields' in expected:
                        nodes = {node['name']: node for node in document['proxies']}
                        assert all(all(nodes[name].get(key) == value for key, value in fields.items()) for name, fields in expected['node_fields'].items()), 'exact_unicode_node_fields'
                    if 'port' in expected: assert document['port'] == expected['port'], 'external_base_applied'
                    if 'groups' in expected:
                        groups = {g['name']: g['proxies'] for g in document['proxy-groups']}
                        assert groups == expected['groups'], 'exact_group_membership'
                    if 'rules' in expected: assert document['rules'] == expected['rules'], 'exact_rule_order'
                record.update(ok=True, bytes=result['bytes'], elapsed_ms=result['elapsed_ms'])
        except AssertionError as exc:
            record.update(ok=False, assertion=str(exc))
        reports.append(record)
    report = {'ok': topology.get('containers_before') == topology.get('containers_after') == 0 and all(case['ok'] for case in reports),
              'synthetic_only': True, 'production_deployed': False, 'router_changed': False, **topology, 'cases': reports}
    return report
