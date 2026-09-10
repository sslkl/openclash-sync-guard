"""Loss-aware Surge conversion around the fixed native node parser.

Dependencies are materialized before execution. Native source-ID groups retain
node provenance in one isolated conversion, even for several policy-paths. This
module never reads files, fetches URLs, or executes scripts.
"""
from __future__ import annotations

from copy import deepcopy
import re

from subscription_converter import ConverterError, http_url

RULE_TYPES = frozenset('DOMAIN DOMAIN-SUFFIX DOMAIN-KEYWORD DOMAIN-REGEX DOMAIN-WILDCARD GEOSITE GEOIP IP-CIDR IP-CIDR6 IP-ASN SRC-IP-CIDR SRC-PORT DST-PORT PROCESS-NAME PROCESS-PATH NETWORK AND OR NOT MATCH'.split())
RULE_ALIASES = {'FINAL': 'MATCH', 'DEST-PORT': 'DST-PORT', 'IP6-CIDR': 'IP-CIDR6'}
LOGICAL_RULE_TYPES = frozenset({'AND', 'OR', 'NOT'})
GROUP_TYPES = frozenset({'select', 'url-test', 'fallback', 'load-balance', 'relay'})
BUILTINS = frozenset({'DIRECT', 'REJECT', 'REJECT-DROP', 'PASS'})
SOURCE_PREFIX = '__OCS_SURGE_SOURCE_'
MAX_LINES = 30000


def unquote(value):
    value = value.strip()
    if value[:1] in {'"', "'"}:
        if len(value) < 2 or value[-1] != value[0]:
            raise ConverterError('SURGE_FORMAT')
        return value[1:-1]
    return value


def fields(value, *, keep_quotes=False):
    """Split top-level commas; retain quotes when rewriting for another parser."""
    if not isinstance(value, str):
        raise ConverterError('SURGE_FORMAT')
    normalize = str.strip if keep_quotes else unquote
    result, start, depth, quote, escaped = [], 0, 0, '', False
    for index, char in enumerate(value):
        if ord(char) < 32 and char != '\t' or 127 <= ord(char) <= 159:
            raise ConverterError('SURGE_FORMAT')
        if escaped:
            escaped = False
            continue
        if char == '\\':
            escaped = True
        elif quote:
            if char == quote:
                quote = ''
        elif char in {'"', "'"}:
            quote = char
        elif char == '(':
            depth += 1
            if depth > 32:
                raise ConverterError('SURGE_FORMAT')
        elif char == ')':
            depth -= 1
            if depth < 0:
                raise ConverterError('SURGE_FORMAT')
        elif char == ',' and not depth:
            result.append(normalize(value[start:index]))
            start = index + 1
    if quote or depth or escaped:
        raise ConverterError('SURGE_FORMAT')
    result.append(normalize(value[start:]))
    if not result or any(not item for item in result):
        raise ConverterError('SURGE_FORMAT')
    return result


def policy(value):
    if (not isinstance(value, str) or not value
            or re.search(r'[\x00-\x1f\x7f-\x9f\ud800-\udfff,`]', value) or len(value.encode()) > 256):
        raise ConverterError('SURGE_FORMAT')
    return value


def _logical_aliases(value):
    """Normalize only nested rule types, not regexes or other literal payloads.

    The enclosing rule's fields() check already bounds parenthesis depth to 32.
    """
    if not (value.startswith('(') and value.endswith(')')):
        raise ConverterError('SURGE_FORMAT')
    operands = []
    for operand in fields(value[1:-1], keep_quotes=True):
        if not (operand.startswith('(') and operand.endswith(')')):
            raise ConverterError('SURGE_FORMAT')
        row = fields(operand[1:-1], keep_quotes=True)
        row[0] = RULE_ALIASES.get(row[0], row[0])
        if row[0] in LOGICAL_RULE_TYPES:
            if len(row) < 2:
                raise ConverterError('SURGE_FORMAT')
            row[1] = _logical_aliases(row[1])
        operands.append('(' + ','.join(row) + ')')
    return '(' + ','.join(operands) + ')'


def rule(value):
    row = fields(value)
    row[0] = RULE_ALIASES.get(row[0], row[0])
    if row[0] not in RULE_TYPES:
        raise ConverterError('SURGE_FORMAT')
    size = 2 if row[0] == 'MATCH' else 3
    if len(row) != size and not (size == 3 and len(row) == 4 and row[-1] == 'no-resolve'):
        raise ConverterError('SURGE_FORMAT')
    target = policy(row[size - 1])
    if row[0] in LOGICAL_RULE_TYPES:
        row[1] = _logical_aliases(row[1])
    return ','.join(row), target


def parse(value, *, dependency=None):
    """Return rewritten text + preservation metadata; reject rather than drop."""
    if not isinstance(value, str):
        raise ConverterError('SURGE_FORMAT')
    sections, output, group_rows, rule_rows, section = {}, [], [], [], ''
    for line in value.splitlines():
        active = line.strip()
        if not active or active.startswith(('#', ';', '//')):
            output.append(line)
        elif active.startswith('[') and active.endswith(']'):
            section = active[1:-1]
            if section in sections:
                raise ConverterError('SURGE_FORMAT')
            sections[section] = []
            output.append(active)
        elif not section:
            raise ConverterError('SURGE_FORMAT')
        elif section == 'Rule' and re.match(r'^RULE-SET\s*,', active):
            raw_row = fields(active, keep_quotes=True)
            row = [unquote(item) for item in raw_row]
            if len(row) not in (3, 4) or (len(row) == 4 and row[3] != 'no-resolve') or dependency is None:
                raise ConverterError('SURGE_FORMAT')
            policy(row[2])
            added = []
            imported = dependency(row[1], 'rule-content')
            for entry in imported.splitlines():
                entry = entry.strip()
                if not entry or entry.startswith(('#', ';', '//')):
                    continue
                raw_cells = fields(entry, keep_quotes=True)
                cells = [unquote(item) for item in raw_cells]
                if len(cells) not in (2, 3) or (len(cells) == 3 and cells[-1] != 'no-resolve') or cells[0] in {'MATCH', 'FINAL'}:
                    raise ConverterError('SURGE_FORMAT')
                tail = ',no-resolve' if len(row) == 4 or len(cells) == 3 else ''
                # This text is still Surge input and will be parsed on intake
                # again. Keep its quotes, separately retaining the Clash rule.
                expanded = ','.join(raw_cells[:2]) + ',' + raw_row[2] + tail
                rule_rows.append(rule(expanded))
                added.append(expanded)
                if len(output) + len(added) > MAX_LINES:
                    raise ConverterError('FETCH_SIZE')
            if not added:
                raise ConverterError('SURGE_FORMAT')
            sections[section].extend(added)
            output.extend(added)
        else:
            if section == 'Proxy Group':
                name, equal, spec = active.partition('=')
                if not equal:
                    raise ConverterError('SURGE_FORMAT')
                row, rewritten = fields(spec, keep_quotes=True), []
                seen_keys = set()
                for item in row:
                    key, equals, val = unquote(item).partition('=')
                    key, val = key.strip(), unquote(val)
                    if equals:
                        if key in seen_keys:
                            raise ConverterError('SURGE_FORMAT')
                        seen_keys.add(key)
                    if equals and key == 'policy-path':
                        if dependency:
                            val = './' + dependency(val, 'subscription')
                        if not re.fullmatch(r'\./a[0-9]{3}\.txt', val):
                            raise ConverterError('SURGE_FORMAT')
                        item = 'policy-path=' + val
                    rewritten.append(item)
                active = name.strip() + '=' + ','.join(rewritten)
                group_rows.append((name, [unquote(item) for item in rewritten]))
            elif section == 'Rule':
                rule_rows.append(rule(active))
            sections[section].append(active)
            output.append(active)
        if len(output) > MAX_LINES:
            raise ConverterError('FETCH_SIZE')
    if not all(name in sections for name in ('Proxy', 'Proxy Group', 'Rule')):
        raise ConverterError('SURGE_FORMAT')
    groups, group_names, proxy_names, inline_names = [], set(), set(), set()
    for line in sections['Proxy']:
        name, equal, spec = line.partition('=')
        name = policy(unquote(name))
        kind = spec.partition(',')[0].strip().lower()
        if not equal or not kind or name in proxy_names:
            raise ConverterError('SURGE_FORMAT')
        proxy_names.add(name)
        if kind in ('direct', 'reject', 'reject-tinygif'):
            builtin = 'DIRECT' if kind == 'direct' else 'REJECT'
            if name in BUILTINS:
                if name != builtin:
                    raise ConverterError('SURGE_FORMAT')
            else:
                groups.append({'name': name, 'type': 'select', 'proxies': [builtin]})
                group_names.add(name)
        else:
            if name in BUILTINS:
                raise ConverterError('SURGE_FORMAT')
            inline_names.add(name)
    for name, row in group_rows:
        name = policy(unquote(name))
        if (name in group_names or name in proxy_names or name in BUILTINS) or row[0] not in GROUP_TYPES:
            raise ConverterError('SURGE_FORMAT')
        group = {'name': name, 'type': row[0], 'proxies': []}
        for item in row[1:]:
            key, equal, val = item.partition('=')
            key, val = key.strip(), unquote(val)
            if not equal:
                group['proxies'].append(policy(item))
            elif key == 'policy-path':
                group['_policy_path'] = val
            elif key in ('interval', 'timeout', 'tolerance'):
                if not val.isascii() or not val.isdigit() or len(val) > 8 or int(val) > 31536000:
                    raise ConverterError('SURGE_FORMAT')
                # Surge timeout is seconds; Mihomo proxy-group timeout is ms.
                group[key] = int(val) * (1000 if key == 'timeout' else 1)
            elif key == 'lazy':
                if val not in ('true', 'false'):
                    raise ConverterError('SURGE_FORMAT')
                group[key] = val == 'true'
            elif key == 'url':
                group[key] = http_url(val)
            elif key == 'strategy':
                if val not in ('consistent-hashing', 'round-robin'):
                    raise ConverterError('SURGE_FORMAT')
                group[key] = val
            else:
                raise ConverterError('SURGE_FORMAT')
        if group['type'] in ('url-test', 'fallback', 'load-balance') and ('url' not in group or not group.get('interval')):
            raise ConverterError('SURGE_FORMAT')
        if not group['proxies'] and '_policy_path' not in group:
            raise ConverterError('SURGE_FORMAT')
        groups.append(group)
        group_names.add(name)
    rules = [value for value, _ in rule_rows]
    preserved = {'groups': groups, 'rules': rules, 'inline_names': inline_names,
                 'rule_targets': [target for _, target in rule_rows]}
    if not rules or not (inline_names or native_options(preserved)['policy_sources']):
        raise ConverterError('SURGE_FORMAT')
    return '\n'.join(output) + '\n', preserved


def native_options(preserved):
    paths = list(dict.fromkeys(group['_policy_path'][2:] for group in preserved['groups'] if '_policy_path' in group))
    if len(paths) + bool(preserved['inline_names']) > 32:
        raise ConverterError('DEPENDENCIES')
    return {'policy_sources': paths, 'include_primary': bool(preserved['inline_names'])}


def restore(document, preserved):
    """Use native source-ID groups, never infer policy ownership from a name."""
    if not isinstance(document, dict) or not isinstance(document.get('proxies'), list) or not document['proxies']:
        raise ConverterError('RESULT')
    names = set()
    for node in document['proxies']:
        if not isinstance(node, dict) or not isinstance(node.get('name'), str) or not node['name'] or (node['name'] in names or node['name'] in BUILTINS):
            raise ConverterError('RESULT')
        names.add(node['name'])
    values = native_options(preserved)
    source_count = len(values['policy_sources']) + values['include_primary']
    markers = {SOURCE_PREFIX + str(index) for index in range(source_count)}
    native_groups = document.get('proxy-groups')
    if not isinstance(native_groups, list) or len(native_groups) != source_count or names & markers:
        raise ConverterError('RESULT')
    membership = {}
    for group in native_groups:
        if not isinstance(group, dict) or not isinstance(group.get('name'), str) or group['name'] not in markers or group['name'] in membership:
            raise ConverterError('RESULT')
        nodes = group.get('proxies')
        if not isinstance(nodes, list) or not nodes or any(not isinstance(name, str) or name not in names for name in nodes) or len(set(nodes)) != len(nodes):
            raise ConverterError('RESULT')
        membership[group['name']] = nodes
    if set().union(*(set(nodes) for nodes in membership.values())) != names:
        raise ConverterError('RESULT')
    if values['include_primary'] and set(membership[SOURCE_PREFIX + '0']) != preserved['inline_names']:
        # Native must not silently discard an inline proxy or rename a routing
        # target. Policy-path duplicates can safely retain their native suffix.
        raise ConverterError('SURGE_FORMAT')
    offset = int(values['include_primary'])
    sources = {'./' + path: membership[SOURCE_PREFIX + str(index + offset)] for index, path in enumerate(values['policy_sources'])}
    groups = deepcopy(preserved['groups'])
    group_names = {g['name'] for g in groups}
    if group_names & names:
        raise ConverterError('SURGE_FORMAT')
    valid = names | group_names | BUILTINS
    for group in groups:
        path = group.pop('_policy_path', None)
        if path:
            group['proxies'] = list(dict.fromkeys(group['proxies'] + sources[path]))
        if not group['proxies'] or any(name not in valid or name == group['name'] for name in group['proxies']):
            raise ConverterError('SURGE_FORMAT')
    # Targets were parsed before removing Surge quotes. Re-tokenizing Clash
    # strings would treat literal policy parentheses/quotes as Surge syntax.
    for target in preserved['rule_targets']:
        if target not in valid:
            raise ConverterError('SURGE_FORMAT')
    # Iterative topological validation avoids recursion limits for large but
    # valid policy graphs. Count each edge once, not quadratic list searches.
    graph = {g['name']: {name for name in g['proxies'] if name in group_names} for g in groups}
    incoming = dict.fromkeys(graph, 0)
    for children in graph.values():
        for child in children:
            incoming[child] += 1
    ready = [name for name, count in incoming.items() if not count]
    visited = 0
    while ready:
        name = ready.pop()
        visited += 1
        for child in graph[name]:
            incoming[child] -= 1
            if not incoming[child]:
                ready.append(child)
    if visited != len(graph):
        raise ConverterError('SURGE_FORMAT')
    return dict(document, **{'proxy-groups': groups, 'rules': list(preserved['rules'])})
