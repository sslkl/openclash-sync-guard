"""Conservative conversion-to-router merge. No filesystem or network access.

The caller supplies one freshly read main configuration and uses the existing
transactional writer with its SHA-256. Conversion never replaces network keys,
existing nodes/groups, custom ownership, or a router's final routing policy.
"""
from __future__ import annotations

import copy
import hashlib
import re

from converter_formats import dump, yaml_load

MAX_BYTES = 1024 * 1024
MAX_ITEMS = 10_000
BUILTINS = frozenset({'DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE', 'GLOBAL'})
MESSAGES = {
    'REQUEST': '合并请求格式无效。',
    'CONTENT': '只支持 1 MiB 以内、无锚点和重复字段的 Clash/Mihomo YAML。',
    'BASELINE': '当前主配置结构无法安全合并，未写入路由器。',
    'CONFLICT': '存在同名但内容不同的节点或策略组；请在转换结果中重命名，不会覆盖原配置或链式节点。',
    'REFERENCE': '转换结果存在未知引用、循环引用或不可用的规则来源，请先调整。',
    'STALE_BASELINE': '主配置已变化，请重新预览；未执行写入。',
    'STALE_PREVIEW': '输入与预览不一致，请重新预览；未执行写入。',
}


class MergeError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def digest(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def document(value, *, baseline=False):
    try:
        if not isinstance(value, str) or not value or len(value.encode()) > MAX_BYTES or '\0' in value:
            raise ValueError
        result = yaml_load(value)
        if not isinstance(result, dict):
            raise ValueError
        if not isinstance(result.get('proxies'), list) or (baseline and any(not isinstance(result.get(key), list) for key in ('proxy-groups', 'rules'))):
            raise ValueError
        return result
    except (ValueError, TypeError, RecursionError):
        raise MergeError('BASELINE' if baseline else 'CONTENT') from None


def name_ok(value):
    return isinstance(value, str) and 1 <= len(value.encode()) <= 512 and not re.search(r'[\x00-\x1f\x7f-\x9f]', value)


def same_content(left, right):
    """Compare parsed values without Python's bool/int coercion."""
    pending = [(left, right)]
    while pending:
        first, second = pending.pop()
        if type(first) is not type(second):
            return False
        if isinstance(first, dict):
            if first.keys() != second.keys():
                return False
            pending.extend((value, second[key]) for key, value in first.items())
        elif isinstance(first, list):
            if len(first) != len(second):
                return False
            pending.extend(zip(first, second))
        elif first != second:
            return False
    return True


def named_rows(rows, *, imported=False):
    if not isinstance(rows, list) or len(rows) > MAX_ITEMS:
        raise MergeError('CONTENT')
    result = {}
    for row in rows:
        if not isinstance(row, dict) or not name_ok(row.get('name')) or not name_ok(row.get('type')):
            raise MergeError('CONTENT')
        name = row['name']
        if name in result or name in BUILTINS or (imported and name.startswith('__OCS_UP_')):
            raise MergeError('CONFLICT')
        result[name] = row
    return result


def check_references(nodes, groups, baseline, added_names):
    known = set(nodes) | set(groups) | BUILTINS
    providers = baseline.get('proxy-providers', {})
    if not isinstance(providers, dict):
        raise MergeError('BASELINE')
    graph = {}
    for name, row in nodes.items():
        target = row.get('dialer-proxy')
        if target is not None and (not isinstance(target, str) or target not in known):
            raise MergeError('REFERENCE')
        graph[name] = [target] if target else []
    for name, row in groups.items():
        members, used = row.get('proxies', []), row.get('use', [])
        if not isinstance(members, list) or not isinstance(used, list) or any(not isinstance(n, str) or n not in known for n in members) or any(not isinstance(n, str) or n not in providers for n in used):
            raise MergeError('REFERENCE')
        graph[name] = members
    # Iterative DFS is bounded by nodes + edges and cannot exhaust Python's call
    # stack. Only new/changed graph roots are traversed; unrelated baseline data
    # stays opaque and is still checked by the router's real Mihomo validator.
    done, active = set(), set()
    for root in added_names:
        stack = [(root, False)]
        while stack:
            node, exiting = stack.pop()
            if exiting:
                active.remove(node)
                done.add(node)
                continue
            if node in done or node in BUILTINS:
                continue
            if node in active:
                raise MergeError('REFERENCE')
            active.add(node)
            stack.append((node, True))
            stack.extend((child, False) for child in reversed(graph.get(node, [])))


def plan(baseline_content, converted_content, *, mode='nodes', group=''):
    if not isinstance(mode, str) or mode not in {'nodes', 'merge'} or not isinstance(group, str) or (group and not name_ok(group)):
        raise MergeError('REQUEST')
    baseline = document(baseline_content, baseline=True)
    incoming = document(converted_content)
    nodes = named_rows(baseline['proxies'])
    groups = named_rows(baseline['proxy-groups'])
    if set(nodes) & set(groups):
        raise MergeError('BASELINE')
    new_nodes = named_rows(incoming['proxies'], imported=True)
    if not new_nodes:
        raise MergeError('CONTENT')
    new_groups = named_rows(incoming.get('proxy-groups', []), imported=True) if mode == 'merge' else {}
    if set(new_nodes) & set(new_groups):
        raise MergeError('CONFLICT')
    added_nodes, added_groups = [], []
    for incoming_rows, existing, other, added in ((new_nodes, nodes, groups, added_nodes), (new_groups, groups, nodes, added_groups)):
        for name, row in incoming_rows.items():
            if name in other or (name in existing and not same_content(row, existing[name])):
                raise MergeError('CONFLICT')
            if name not in existing:
                existing[name] = copy.deepcopy(row)
                added.append(name)
    changed_roots = added_nodes + added_groups
    group_members_added = 0
    if group:
        # Only explicitly selected existing select/url-test/fallback/load-balance
        # groups with a static member list may receive appended memberships.
        if group not in groups or group in added_groups or groups[group].get('type') not in {'select', 'url-test', 'fallback', 'load-balance'} or not isinstance(groups[group].get('proxies'), list):
            raise MergeError('REFERENCE')
        groups[group] = copy.deepcopy(groups[group])
        members = groups[group]['proxies']
        if any(not isinstance(name, str) for name in members):
            raise MergeError('BASELINE')
        membership = set(members)
        for name in new_nodes:
            if name not in membership:
                membership.add(name)
                groups[group]['proxies'].append(name)
                group_members_added += 1
        changed_roots.append(group)
    check_references(nodes, groups, baseline, changed_roots)
    result = copy.deepcopy(baseline)
    result['proxies'] = list(nodes.values())
    result['proxy-groups'] = list(groups.values())
    added_rules, ignored_final = [], 0
    if mode == 'merge':
        rules = incoming.get('rules', [])
        if not isinstance(rules, list) or len(rules) > MAX_ITEMS:
            raise MergeError('CONTENT')
        known = set(nodes) | set(groups) | BUILTINS
        seen = set(result['rules']) if all(isinstance(r, str) for r in result['rules']) else None
        if seen is None:
            raise MergeError('BASELINE')
        providers = baseline.get('rule-providers', {})
        if not isinstance(providers, dict):
            raise MergeError('BASELINE')
        for rule in rules:
            if not isinstance(rule, str) or not 1 <= len(rule.encode()) <= 8192 or re.search(r'[\x00-\x1f\x7f-\x9f]', rule):
                raise MergeError('CONTENT')
            parts = rule.split(',')
            if len(parts) < 2:
                raise MergeError('CONTENT')
            if parts[0] in {'MATCH', 'FINAL'}:
                ignored_final += 1
                continue
            policy = parts[-2] if parts[-1] == 'no-resolve' else parts[-1]
            if policy not in known or (parts[0] == 'RULE-SET' and parts[1] not in providers) or parts[0] == 'SUB-RULE':
                raise MergeError('REFERENCE')
            if rule not in seen:
                seen.add(rule)
                added_rules.append(rule)
        index = next((i for i, r in enumerate(result['rules']) if r.split(',', 1)[0] in {'MATCH', 'FINAL'}), len(result['rules']))
        result['rules'][index:index] = added_rules
    changed = bool(added_nodes or added_groups or added_rules or group_members_added)
    try:
        content = dump(result, 'yaml', compact=True) if changed else baseline_content
    except (ValueError, TypeError, RecursionError):
        raise MergeError('CONTENT') from None
    if len(content.encode()) > MAX_BYTES:
        raise MergeError('CONTENT')
    # Validate the combined budgets and YAML roundtrip, not just each input.
    # Keep exact baseline bytes for a no-op; never claim preservation on drift.
    if changed and not same_content(document(content), result):
        raise MergeError('CONTENT')
    selectable = [name for name, row in named_rows(baseline['proxy-groups']).items() if row.get('type') in {'select', 'url-test', 'fallback', 'load-balance'} and isinstance(row.get('proxies'), list)]
    return {'ok': True, 'content': content, 'sha256': digest(content), 'expected_sha256': digest(baseline_content),
            'groups': selectable, 'summary': {'mode': mode, 'nodes_added': len(added_nodes), 'groups_added': len(added_groups),
            'rules_added': len(added_rules), 'group_members_added': group_members_added, 'final_rules_ignored': ignored_final,
            'existing_nodes_preserved': True, 'network_settings_preserved': True, 'router_changed': False, 'no_change': not changed}}
