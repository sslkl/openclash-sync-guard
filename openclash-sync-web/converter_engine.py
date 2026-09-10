"""Prepare credential-bearing conversion jobs without sharing production state."""
from __future__ import annotations

import base64
import converter_formats
import converter_surge
import converter_mellow
import hashlib
import re
import threading
import time
from urllib.parse import urlsplit

from subscription_converter import (ConverterError, ConversionRequest, DEFAULT_BACKEND, NODE_SCHEMES,
                                    http_url, options, parameters, parameter_bytes, text, validate)
from converter_fetch import MAX_JOB_BYTES, TIMEOUT, fetch_many

LOCK = threading.Lock()
MAX_UPLOADS = 32
MAX_FILES = 64
FAILURE_CODES = frozenset({'REQUEST', 'CONTENT', 'RESULT', 'SANDBOX', 'SANDBOX_UNAVAILABLE',
                           'SANDBOX_CLEANUP', 'CONVERTER_BUSY'})
RESULT_FIELDS = frozenset({'ok', 'content', 'sha256', 'bytes', 'target', 'elapsed_ms', 'engine',
                           'isolated', 'network', 'router_changed', 'cleanup_confirmed'})
BASE_KEYS = frozenset(key + '_rule_base' for key in
                     ('clash', 'surge', 'surfboard', 'mellow', 'quan', 'quanx', 'loon', 'sssub', 'singbox'))
IMPORT_KEYS = frozenset({'custom_proxy_group', 'rename', 'emoji', 'ruleset', 'surge_ruleset'})
RULE_PREFIXES = ('clash-domain:', 'clash-ipcidr:', 'clash-classic:', 'quanx:', 'surge:')
DYNAMIC_RESOURCE = re.compile(r'\b(?:webGet|fetch|fileGet|readFile)\s*\(|{%\s*(?:include|extends|import)\b')


def content_bytes(value: object) -> bytes:
    if not isinstance(value, str):
        raise ConverterError('CONTENT')
    try:
        raw = value.encode('utf-8')
    except UnicodeError:
        raise ConverterError('CONTENT') from None
    if not raw or len(raw) > MAX_JOB_BYTES or '\0' in value:
        raise ConverterError('CONTENT')
    return raw


def decoded_content(raw: object) -> str:
    if not isinstance(raw, bytes):
        raise ConverterError('CONTENT')
    try:
        value = raw.decode('utf-8-sig')
    except UnicodeError:
        raise ConverterError('CONTENT') from None
    content_bytes(value)
    return value


def subscription_content(raw: bytes) -> bytes:
    value = decoded_content(raw)
    if value.lstrip().startswith('{'):
        # The native YAML reader rejects valid JSON UTF-16 surrogate pairs.
        # Normalize JSON/flow mappings with our bounded, duplicate-safe loader;
        # keep URI, base64, block-YAML and INI source handling unchanged.
        document, _ = converter_formats.load(value, kind='yaml')
        return content_bytes(converter_formats.dump(document, 'yaml'))
    lines = [line.strip() for line in value.strip().splitlines() if line.strip()]
    # The native parser decodes normal subscription contents once; encode pasted
    # URI lists here. Other subscription contents stay as-is.
    if lines and all(re.match(r'^[a-zA-Z0-9]+://', line) and line.split('://', 1)[0] in NODE_SCHEMES for line in lines):
        return base64.b64encode('\n'.join(lines).encode())
    return value.encode()


class IntakeBudget:
    """One wall/byte budget for sources AND every dependency, not per fetch."""
    def __init__(self, fetch, user_agent):
        self.fetch, self.user_agent = fetch, user_agent
        self.deadline = time.monotonic() + TIMEOUT
        self.remaining = MAX_JOB_BYTES
        self.cache = {}

    def time_left(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ConverterError('FETCH_TIMEOUT')
        return remaining

    def get(self, urls):
        self.time_left()
        urls = [http_url(url) for url in urls]
        pending = list(dict.fromkeys(url for url in urls if url not in self.cache))
        if len(self.cache) + len(pending) > MAX_FILES:
            raise ConverterError('DEPENDENCIES')
        if pending:
            if self.remaining <= 0:
                raise ConverterError('FETCH_SIZE')
            bodies = self.fetch(pending, user_agent=self.user_agent, timeout=self.time_left(), maximum=self.remaining)
            self.time_left()
            if not isinstance(bodies, list) or len(bodies) != len(pending) or any(not isinstance(raw, bytes) or not raw for raw in bodies):
                raise ConverterError('CONTENT')
            self.remaining -= sum(map(len, bodies))
            if self.remaining < 0:
                raise ConverterError('FETCH_SIZE')
            self.cache.update(zip(pending, bodies))
        return [self.cache[url] for url in urls]


class AssetPack:
    """Materialize INI configuration dependencies; never allow host paths.

    Cache is request-local. Import lists are flattened before the native parser's
    single import pass. Base templates may retain runtime health-check URLs, but
    dynamic file/network includes must not silently fail in a no-network sandbox.
    """
    def __init__(self, budget, files, resources=None):
        self.budget, self.files = budget, files
        self.cache, self.pending = {}, set()
        self.next_asset = 0
        self.total_bytes = sum(map(len, files.values()))
        self.resources = {}
        if resources is None:
            resources = []
        if not isinstance(resources, list) or len(resources) > MAX_FILES:
            raise ConverterError('DEPENDENCIES')
        for resource in resources:
            if not isinstance(resource, dict) or set(resource) != {'name', 'content'} or not isinstance(resource['name'], str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}', resource['name']) or '..' in resource['name'] or resource['name'] in self.resources:
                raise ConverterError('DEPENDENCIES')
            self.resources[resource['name']] = content_bytes(resource['content'])
        if sum(map(len, self.resources.values())) + self.total_bytes > MAX_JOB_BYTES:
            raise ConverterError('FETCH_SIZE')
        self.budget.remaining -= sum(map(len, self.resources.values()))
        if self.budget.remaining < 0:
            raise ConverterError('FETCH_SIZE')

    def add(self, raw):
        self.budget.time_left()
        if len(self.files) >= MAX_FILES or self.total_bytes + len(raw) > MAX_JOB_BYTES:
            raise ConverterError('FETCH_SIZE')
        name = 'a%03d.txt' % self.next_asset
        self.next_asset += 1
        self.files[name] = raw
        self.total_bytes += len(raw)
        return name

    def remote(self, url, kind='base'):
        local = isinstance(url, str) and url.startswith('asset:')
        if local and url[6:] not in self.resources:
            raise ConverterError('DEPENDENCIES')
        url = url if local else http_url(url)
        key = (url, kind)
        if key in self.cache:
            return self.cache[key]
        if key in self.pending or len(self.pending) >= 5:
            raise ConverterError('DEPENDENCIES')
        self.pending.add(key)
        try:
            value = decoded_content(self.resources[url[6:]] if local else self.budget.get([url])[0])
            if kind == 'external':
                value = self.external(value)
            elif kind.startswith('toml-'):
                value = self.toml_import(value, kind[5:])
            elif kind.endswith('-list'):
                value = self.imported(value, kind)
            elif kind == 'subscription':
                value = subscription_content(content_bytes(value)).decode()
            elif kind in {'base', 'script'}:
                value = self.template(value)
            name = self.add(content_bytes(value))
            self.cache[key] = name
            return name
        finally:
            self.pending.remove(key)

    def template(self, value):
        # Only explicit virtual assets can be used as local includes. There is
        # no ZIP extraction, host path mapping, or backend network fallback.
        pattern = r"asset:([a-zA-Z0-9][a-zA-Z0-9_.-]{0,63})"
        value = re.sub(pattern, lambda match: './' + self.remote(match.group(0), 'base'), value)
        # Literal includes and file reads must now name a materialized job file.
        check = re.sub(r"({%\s*(?:include|extends|import)\s+|\b(?:fileGet|readFile)\s*\(\s*)[\"']\./a[0-9]{3}\.txt[\"']", '', value)
        if DYNAMIC_RESOURCE.search(check):
            raise ConverterError('DEPENDENCIES')
        return value

    def script(self, value):
        if not isinstance(value, str):
            raise ConverterError('CONFIG_FORMAT')
        return 'path:./' + self.remote(value[5:], 'script') if value.startswith('path:') else self.template(value)

    def imported(self, value, kind):
        lines, total_bytes = [], 0
        for line in value.splitlines():
            self.budget.time_left()
            line = line.strip()
            if not line or line.startswith(('#', ';', '//')):
                continue
            if line.startswith('!!import:'):
                name = self.remote(line[len('!!import:'):], kind)
                additions = self.files[name].decode().splitlines()
            else:
                additions = [self.ruleset(line) if kind == 'ruleset-list' else
                             'script:' + self.script(line[9:] if line.startswith('!!script:') else line[7:]) if line.startswith(('!!script:', 'script:')) else line]
            # Count each emitted UTF-8 byte once, including separators. Repeated
            # imports must not expand unboundedly or rescan the accumulated list.
            for item in additions:
                self.budget.time_left()
                total_bytes += len(item.encode('utf-8')) + 1
                if total_bytes > MAX_JOB_BYTES:
                    raise ConverterError('FETCH_SIZE')
                lines.append(item)
        if not lines:
            raise ConverterError('CONTENT')
        return '\n'.join(lines) + '\n'

    def ruleset(self, value):
        group, comma, source = value.partition(',')
        if not comma or not group or not source:
            raise ConverterError('CONFIG_FORMAT')
        if source.startswith('[]'):
            return value
        link, separator, interval = source.partition(',')
        prefix = next((prefix for prefix in RULE_PREFIXES if link.startswith(prefix)), '')
        url = link[len(prefix):]
        if separator and (not interval.isascii() or not interval.isdigit() or len(interval) > 10):
            raise ConverterError('CONFIG_FORMAT')
        name = self.remote(url, 'rules')
        return group + ',' + prefix + './' + name + (',' + interval if separator else '')

    def rule_source(self, source):
        if not isinstance(source, str) or not source:
            raise ConverterError('CONFIG_FORMAT')
        if source.startswith('[]'):
            return source
        prefix = next((prefix for prefix in RULE_PREFIXES if source.startswith(prefix)), '')
        return prefix + './' + self.remote(source[len(prefix):], 'rules')

    def structured_items(self, items, name, kind):
        if not isinstance(items, list) or len(items) > 10000:
            raise ConverterError('CONFIG_FORMAT')
        result = []
        list_kinds = {'rulesets': 'ruleset-list', 'surge_ruleset': 'ruleset-list',
                      'proxy_groups': 'custom_proxy_group-list', 'custom_proxy_group': 'custom_proxy_group-list',
                      'rename_node': 'rename-list', 'emojis': 'emoji-list', 'emoji': 'emoji-list'}
        for item in items:
            self.budget.time_left()
            if not isinstance(item, dict):
                raise ConverterError('CONFIG_FORMAT')
            item = dict(item)
            if 'import' in item:
                if set(item) != {'import'}:
                    raise ConverterError('CONFIG_FORMAT')
                dependency_kind = 'toml-' + name if kind == 'toml' else list_kinds[name]
                local = self.remote(item['import'], dependency_kind)
                item['import'] = './' + local
            if name in {'rulesets', 'surge_ruleset'} and 'ruleset' in item:
                item['ruleset'] = self.rule_source(item['ruleset'])
            if 'script' in item:
                item['script'] = self.script(item['script'])
                # Pinned native YAML reader emits !!script: but its INI binding
                # recognizes only script:. Route script rows through one local
                # import, preserving native order and authorization checks.
                if kind == 'yaml' and name in {'rename_node', 'emojis', 'emoji'}:
                    if set(item) != {'script'}:
                        raise ConverterError('CONFIG_FORMAT')
                    item = {'import': './' + self.add(content_bytes('script:' + item['script'] + '\n'))}
            result.append(item)
        return result

    def toml_import(self, value, name):
        data, kind = converter_formats.load(value, kind='toml')
        if name not in data:
            raise ConverterError('CONFIG_FORMAT')
        rows = self.structured_items(data[name], name, kind)
        # TOML importer recurses differently from INI; flatten explicitly rather
        # than rely on a native second import pass that does not exist.
        flattened = []
        for row in rows:
            if 'import' in row:
                nested, _ = converter_formats.load(self.files[row['import'][2:]].decode(), kind='toml')
                flattened.extend(nested[name])
            else:
                flattened.append(row)
            if len(flattened) > 10000:
                raise ConverterError('FETCH_SIZE')
        return converter_formats.dump({name: flattened}, kind)

    def external_structured(self, value):
        data, kind = converter_formats.load(value)
        section = data.get('custom')
        if not isinstance(section, dict) or (kind == 'toml' and (type(data.get('version')) is not int or data['version'] != 1)):
            raise ConverterError('CONFIG_FORMAT')
        for key in BASE_KEYS:
            if section.get(key):
                section[key] = './' + self.remote(section[key], 'base')
        keys = ('custom_groups', 'rulesets', 'emoji', 'rename_node') if kind == 'toml' else ('proxy_groups', 'custom_proxy_group', 'rulesets', 'surge_ruleset', 'rename_node', 'emojis', 'emoji')
        source = data if kind == 'toml' else section
        for key in keys:
            if key in source:
                source[key] = self.structured_items(source[key], key, kind)
        return converter_formats.dump(data, kind)

    def external(self, value):
        if converter_formats.is_toml(value) or not re.search(r'^\s*\[custom\]\s*$', value, re.M):
            return self.external_structured(value)
        if DYNAMIC_RESOURCE.search(value):
            value = self.template(value)
        lines, section = [], ''
        for line in value.splitlines():
            self.budget.time_left()
            active = line.strip()
            if not active or active.startswith(('#', ';')):
                lines.append(line)
                continue
            if active.startswith('[') and active.endswith(']'):
                section = active[1:-1]
                lines.append(line)
                continue
            key, equals, item = active.partition('=')
            key, item = key.strip(), item.strip()
            if section == 'custom' and equals:
                if key in IMPORT_KEYS and item.startswith('!!import:'):
                    kind = 'ruleset-list' if key in {'ruleset', 'surge_ruleset'} else key + '-list'
                    line = key + '=!!import:./' + self.remote(item[len('!!import:'):], kind)
                elif key in {'rename', 'emoji'} and item.startswith(('!!script:', 'script:')):
                    line = key + '=script:' + self.script(item[9:] if item.startswith('!!script:') else item[7:])
                elif key in {'ruleset', 'surge_ruleset'}:
                    line = key + '=' + self.ruleset(item)
                elif key in BASE_KEYS and item:
                    line = key + '=./' + self.remote(item)
            lines.append(line)
        return '\n'.join(lines) + '\n'


def prepare(payload: object, fetch=fetch_many) -> tuple[dict, dict]:
    if not isinstance(payload, dict) or set(payload) - {'form', 'uploads', 'config_content', 'resources', 'scripts'} or 'form' not in payload:
        raise ConverterError('REQUEST')
    scripts = payload.get('scripts', {})
    if not isinstance(scripts, dict) or set(scripts) - {'filter', 'sort'}:
        raise ConverterError('REQUEST')
    script_bytes = {}
    for key, value in scripts.items():
        if value:
            script_bytes[key] = content_bytes(value)
            if len(script_bytes[key]) > 65536:
                raise ConverterError('CONTENT')
        elif not isinstance(value, str):
            raise ConverterError('CONTENT')
    uploads = payload.get('uploads', [])
    if not isinstance(uploads, list) or len(uploads) > MAX_UPLOADS:
        raise ConverterError('CONTENT')
    upload_bytes = [content_bytes(item) for item in uploads]
    form = payload['form']
    if not isinstance(form, dict) or set(form) - {'backend', 'sources', 'options', 'profile', 'parameters'}:
        raise ConverterError('REQUEST')
    if upload_bytes and form.get('sources') in ('', None, []):
        profile = form.get('profile', 'manual')
        if profile not in ('manual', 'router_a', 'router_b'):
            raise ConverterError('PROFILE')
        request = ConversionRequest(http_url(form.get('backend', DEFAULT_BACKEND), backend=True), (), options(form.get('options', {})), profile, parameters(form.get('parameters', {})))
        request.link()
    else:
        request = validate(form)
    if request.options['target'] == 'auto':
        raise ConverterError('EXECUTION_TARGET')
    if 'sort' in script_bytes and request.options.get('sort') is False:
        raise ConverterError('SCRIPT_SORT')
    config = payload.get('config_content', '')
    if not isinstance(config, str):
        raise ConverterError('CONTENT')
    if config:
        content_bytes(config)
        if request.options.get('config'):
            raise ConverterError('CONFIG_CONFLICT')
    if len(request.sources) + len(upload_bytes) > MAX_UPLOADS:
        raise ConverterError('SOURCES')
    if sum(map(len, upload_bytes)) + len(config.encode()) > MAX_JOB_BYTES:
        raise ConverterError('FETCH_SIZE')
    budget = IntakeBudget(fetch, request.options.get('ua', 'OpenClash-Sync-Converter/1'))
    custom_bytes = parameter_bytes(request.parameters)
    budget.remaining -= sum(map(len, upload_bytes)) + len(config.encode()) + sum(map(len, script_bytes.values())) + custom_bytes
    budget.remaining -= sum(len(source.encode()) for source in request.sources if urlsplit(source).scheme not in {'http', 'https'})
    files = {}
    # Reserve every explicit local resource before the first network request.
    pack = AssetPack(budget, files, payload.get('resources', []))
    remote_urls = list(dict.fromkeys(source for source in request.sources if urlsplit(source).scheme in {'http', 'https'}))
    remote = dict(zip(remote_urls, budget.get(remote_urls))) if remote_urls else {}
    originals = [remote[source] if source in remote else source.encode() for source in request.sources] + upload_bytes
    if sum(map(len, originals)) > MAX_JOB_BYTES:
        raise ConverterError('FETCH_SIZE')
    if request.options['target'] == 'mellow':
        converter_mellow.validate_sources(originals)
    files.update({'s%03d.txt' % index: subscription_content(raw) for index, raw in enumerate(originals)})
    names = list(files)
    pack.total_bytes = sum(map(len, files.values()))
    args = dict(request.options)
    if request.parameters:
        args['parameters'] = dict(request.parameters)
    if 'sort' in script_bytes:
        args['sort'] = True
    for key, raw in script_bytes.items():
        args[key + '_script_file'] = pack.add(content_bytes(pack.template(decoded_content(raw))))
    if config:
        args['config'] = pack.add(content_bytes(pack.external(config)))
    elif args.get('config'):
        args['config'] = pack.remote(args['config'], 'external')
    else:
        args.pop('config', None)
    budget.time_left()
    if sum(map(len, files.values())) + custom_bytes > MAX_JOB_BYTES:
        raise ConverterError('FETCH_SIZE')
    job = {'version': 1, 'source_names': names, 'options': args,
           'files': [{'name': name, 'body': base64.b64encode(raw).decode()} for name, raw in files.items()]}
    summary = {'source_count': len(names), 'remote_source_count': len(remote_urls),
               'asset_count': len(files) - len(names), 'profile': request.profile,
               'link_backend_used': False, 'router_changed': False, 'network_executed': bool(budget.cache)}
    return job, summary


def result_ok(result: object, target: str) -> bool:
    if not isinstance(result, dict) or set(result) != RESULT_FIELDS or result.get('ok') is not True or \
            result.get('target') != target or result.get('isolated') is not True or result.get('network') != 'none' or \
            result.get('router_changed') is not False or result.get('cleanup_confirmed') is not True:
        return False
    try:
        raw = content_bytes(result['content'])
    except ConverterError:
        return False
    return result['sha256'] == hashlib.sha256(raw).hexdigest() and type(result['bytes']) is int and result['bytes'] == len(raw) and \
        type(result['elapsed_ms']) is int and 0 <= result['elapsed_ms'] <= 60000 and result['engine'] == 'subconverter-0.9.1-36573b3-isolated'


def failure_ok(result: object) -> bool:
    return isinstance(result, dict) and set(result) == {'ok', 'code', 'router_changed'} and result['ok'] is False and \
        isinstance(result['code'], str) and result['code'] in FAILURE_CODES and result['router_changed'] is False


def prepare_tool(payload, fetch=fetch_many):
    if not isinstance(payload, dict) or set(payload) - {'operation', 'content', 'urls', 'options', 'resources'}:
        raise ConverterError('REQUEST')
    operation = payload.get('operation')
    if not isinstance(operation, str) or operation not in {'ruleset', 'template', 'surge2clash'}:
        raise ConverterError('REQUEST')
    values = payload.get('options', {})
    custom_bytes = 0
    if not isinstance(values, dict):
        raise ConverterError('REQUEST')
    if operation == 'ruleset':
        if set(values) - {'type', 'input_format', 'group'} or type(values.get('type', 1)) is not int or not 1 <= values.get('type', 1) <= 6:
            raise ConverterError('REQUEST')
        values = {'type': values.get('type', 1), 'input_format': values.get('input_format', 'surge'), 'group': values.get('group', 'Proxy')}
        if not isinstance(values['input_format'], str) or values['input_format'] not in {'surge', 'quanx', 'clash-domain', 'clash-ipcidr', 'clash-classic'}:
            raise ConverterError('REQUEST')
        group = values['group']
        try:
            text(group, 128)
        except ConverterError:
            raise ConverterError('REQUEST') from None
        if any(char in group for char in ',|`'):
            raise ConverterError('REQUEST')
    elif operation == 'template':
        if set(values) - {'variables'} or not isinstance(values.get('variables', {}), dict) or len(values.get('variables', {})) > 32:
            raise ConverterError('REQUEST')
        values = {'variables': values.get('variables', {})}
        for key, value in values['variables'].items():
            if not isinstance(key, str) or not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_.-]{0,63}', key) or key.lower() in {'path', 'constructor', 'prototype'}:
                raise ConverterError('REQUEST')
            try:
                text(value, 4096, empty=True)
            except ConverterError:
                raise ConverterError('REQUEST') from None
        custom_bytes = parameter_bytes(values['variables'])
    elif values:
        raise ConverterError('REQUEST')
    urls = payload.get('urls', [])
    if not isinstance(urls, list) or len(urls) > MAX_UPLOADS:
        raise ConverterError('REQUEST')
    urls = [http_url(url) for url in urls]
    content = payload.get('content', '')
    if not isinstance(content, str):
        raise ConverterError('CONTENT')
    bodies = [content_bytes(content)] if content else []
    budget = IntakeBudget(fetch, 'OpenClash-Sync-Converter/1')
    budget.remaining -= sum(map(len, bodies)) + custom_bytes
    files = {}
    pack = AssetPack(budget, files, payload.get('resources', []))
    if urls:
        bodies += budget.get(urls)
    if not bodies or len(bodies) > MAX_UPLOADS or (operation != 'ruleset' and len(bodies) != 1):
        raise ConverterError('CONTENT')
    files.update({'s%03d.txt' % index: content_bytes(decoded_content(raw)) for index, raw in enumerate(bodies)})
    names = list(files)
    pack.total_bytes = sum(map(len, files.values()))
    if operation == 'template':
        files[names[0]] = content_bytes(pack.template(files[names[0]].decode()))
    elif operation == 'surge2clash':
        def dependency(url, kind):
            local = pack.remote(url, 'rules' if kind == 'rule-content' else kind)
            return files[local].decode() if kind == 'rule-content' else local
        rewritten, preserved = converter_surge.parse(files[names[0]].decode(), dependency=dependency)
        files[names[0]] = content_bytes(rewritten)
        values = converter_surge.native_options(preserved)
    budget.time_left()
    if sum(map(len, files.values())) + custom_bytes > MAX_JOB_BYTES:
        raise ConverterError('FETCH_SIZE')
    return {'version': 1, 'source_names': names, 'options': {'target': operation, **values},
            'files': [{'name': name, 'body': base64.b64encode(raw).decode()} for name, raw in files.items()]}, {
                'source_count': len(names), 'remote_source_count': len(urls), 'asset_count': len(files)-len(names),
                'operation': operation, 'link_backend_used': False, 'network_executed': bool(budget.cache), 'router_changed': False}


def validate_export(content, options):
    """Reject HTTP-200 empty/invalid exports instead of claiming conversion.

    This is a bounded structural check, not a client runtime compatibility test.
    Rules/template tools may intentionally return no proxies and are excluded.
    """
    target = options['target']
    try:
        if target in {'clash', 'clashr'}:
            document = converter_formats.yaml_load(content)
            # Native defaults to expanded rules only when script is omitted;
            # non-expanded and provider/list exports force new field names.
            expanded = options.get('expand', 'script' not in options)
            legacy_names = options.get('new_name') is False and expanded and not options.get('list')
            node_key = 'Proxy' if legacy_names else 'proxies'
            # An unused template alias must not mask invalid selected output.
            nodes = document.get(node_key) if isinstance(document, dict) else None
            if not isinstance(nodes, list) or not nodes or any(not isinstance(n, dict) or not isinstance(n.get('name'), str) or not n['name'] or not n.get('server') for n in nodes):
                raise ValueError
            if len({n['name'] for n in nodes}) != len(nodes): raise ValueError
        elif target in {'singbox', 'sssub', 'ssd'}:
            value = content.strip()
            if target == 'ssd':
                if not value.startswith('ssd://'): raise ValueError
                value = base64.b64decode(value[6:] + '=' * (-len(value[6:]) % 4), validate=True).decode()
            document = converter_formats.json_load(value)
            nodes = document if target == 'sssub' else document.get('servers' if target == 'ssd' else 'outbounds')
            if not isinstance(nodes, list) or not any(isinstance(n, dict) and n.get('server') for n in nodes): raise ValueError
        elif target in {'ss', 'ssr', 'trojan', 'v2ray', 'mixed'} or (target == 'quan' and options.get('list')):
            value = content.strip()
            if not options.get('list') or target == 'quan':
                value = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True).decode()
            lines = [line.strip() for line in value.splitlines() if line.strip()]
            if not lines or any(not re.match(r'^(?:ss|ssr|vmess|trojan)://\S+$', line) for line in lines): raise ValueError
        elif target == 'mellow':
            converter_mellow.validate(content)
        else:
            expected = {'surge': 'proxy', 'surfboard': 'proxy', 'loon': 'proxy', 'quanx': 'server_local', 'quan': 'server', 'mellow': 'endpoint'}[target]
            section, count = '', 0
            for line in content.splitlines():
                line = line.strip()
                if line.startswith('[') and line.endswith(']'):
                    section = line[1:-1].lower(); continue
                if (options.get('list') or section == expected) and '=' in line and not line.startswith(('#', ';', '//')):
                    _, _, value = line.partition('=')
                    if ',' in value and value.strip().lower() not in {'direct', 'reject', 'reject-tinygif'}:
                        count += 1
            if not count: raise ValueError
    except (ConverterError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError):
        raise ConverterError('RESULT') from None


def execute(payload, bridge, *, tool=False):
    if not bridge.enabled:
        raise ConverterError('SANDBOX_UNAVAILABLE')
    if not LOCK.acquire(blocking=False):
        raise ConverterError('CONVERTER_BUSY')
    started = time.monotonic()
    try:
        job, summary = prepare_tool(payload) if tool else prepare(payload)
        result = bridge.call({'action': 'converter_run', 'job': job})
        if not result_ok(result, job['options']['target']):
            raise ConverterError(result['code'] if failure_ok(result) else 'SANDBOX')
        if not tool and job['options']['target'] == 'mellow':
            mirror = dict(job, options=dict(job['options'], target='clash', list=True))
            normalized = bridge.call({'action': 'converter_run', 'job': mirror})
            if not result_ok(normalized, 'clash'):
                raise ConverterError(normalized['code'] if failure_ok(normalized) else 'SANDBOX')
            raw = content_bytes(converter_mellow.repair(result['content'], normalized['content']))
            result = dict(result, content=raw.decode(), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            summary['upstream_endpoint_fix'] = True
        if not tool:
            validate_export(result['content'], job['options'])
        if tool and payload.get('operation') == 'surge2clash':
            source = next(item['body'] for item in job['files'] if item['name'] == job['source_names'][0])
            _, preserved = converter_surge.parse(base64.b64decode(source).decode())
            document = converter_surge.restore(converter_formats.yaml_load(result['content']), preserved)
            raw = content_bytes(converter_formats.dump(document, 'yaml'))
            result = dict(result, content=raw.decode(), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            summary['upstream_group_rule_fix'] = True
        return {key: result[key] for key in RESULT_FIELDS} | {
            'summary': summary | {'elapsed_ms': round((time.monotonic() - started) * 1000)}}
    finally:
        LOCK.release()
