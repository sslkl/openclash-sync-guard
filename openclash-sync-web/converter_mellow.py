"""Repair the pinned upstream Mellow exporter using a same-input Clash export.

Upstream 36573b3 reads unassigned local variables in proxyToMellow. Replace only
one-to-one matching endpoints; keep native names, ordering and other sections.
The supported subset is deliberately conservative: parsing a URI successfully
is not proof that Mellow implements the source protocol or its options.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import re
from urllib.parse import quote, unquote, urlencode, urlsplit

from converter_formats import yaml_load
from subscription_converter import ConverterError


UUID_PATTERN = r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}'
# Common AEAD methods supported by the legacy V2Ray-based client. In particular,
# passing a Shadowsocks 2022 method through ssParser does not add SS2022 support.
SS_CIPHERS = {'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305'}
COMMON_KEYS = {'name', 'type', 'server', 'port', 'dialer-proxy', 'udp', 'tfo'}
PROTOCOL_KEYS = {
    'ss': {'cipher', 'password'},
    'http': {'username', 'password', 'tls', 'skip-cert-verify'},
    'socks5': {'username', 'password', 'tls', 'skip-cert-verify'},
    'vmess': {'uuid', 'alterId', 'cipher', 'tls', 'servername', 'skip-cert-verify',
              'network', 'ws-opts', 'ws-path', 'ws-headers', 'h2-opts'},
}


def scalar(value, *, empty=False, unsafe=r'[\x00-\x20\x7f-\x9f,;]'):
    if (not isinstance(value, str) or (not empty and not value)
            or len(value.encode()) > 4096 or re.search(unsafe, value)
            or any(char in value for char in '\u2028\u2029\ufeff')):
        raise ValueError
    return value


def trimmed(value, *, empty=False, unsafe=r'[\x00-\x20\x7f-\x9f,;]'):
    value = scalar(value, empty=empty, unsafe=unsafe)
    if value != value.strip():
        raise ValueError
    return value


def endpoint_name(value):
    return trimmed(value, unsafe=r'[\x00-\x1f\x7f-\x9f,;:]')


def server_name(value, *, uri=False):
    value = scalar(value)
    if ':' in value:
        # WHATWG URL.hostname retains IPv6 brackets. ssParser/vmess1Parser copy
        # those brackets into V2Ray's address, not the original IP literal.
        # The builtin parser can carry an unbracketed IPv6 address losslessly.
        if uri or '%' in value:
            raise ValueError
        ipaddress.IPv6Address(value)
    elif (not re.fullmatch(r'[A-Za-z0-9_.-]+\.?', value)
          or len(value) > 253
          or any(not label or len(label) > 63 for label in value.removesuffix('.').split('.'))):
        raise ValueError
    return value


def boolean(node, key, default=False):
    value = node.get(key, default)
    if type(value) is not bool:
        raise ValueError
    return value


def options(value, allowed):
    if not isinstance(value, dict) or set(value) - allowed:
        raise ValueError
    return value


def path_value(path):
    # Mellow does not URI-decode pathname. Keep already encoded paths verbatim,
    # but reject characters/dot segments WHATWG URL would change or INI splits.
    scalar(path, empty=True, unsafe=r'[\x00-\x20\x7f-\x9f,;#?"<>\x60{}]')
    if not path.isascii() or path and not path.startswith('/'):
        raise ValueError
    if any(re.sub('%2e', '.', segment, flags=re.I) in {'.', '..'} for segment in path.split('/')):
        raise ValueError
    return path


def host_value(value):
    # The client decodes the complete query before splitting on '&' and '=';
    # encoding these separators cannot make them safe. Host lists also split
    # on commas, and their entries (and WS Host) are trimmed by the client.
    return trimmed(value, unsafe=r'[\x00-\x20\x7f-\x9f,;&=]')


def sni_value(value):
    # SNI is a server name, not an HTTP authority with a port or a URL. An
    # explicit SNI is required when WS Host cannot serve as a valid server name.
    return server_name(host_value(value))


def endpoint(node):
    if not isinstance(node, dict):
        raise ValueError
    kind = node.get('type')
    if not isinstance(kind, str) or kind not in PROTOCOL_KEYS:
        raise ValueError
    if set(node) - COMMON_KEYS - PROTOCOL_KEYS[kind]:
        raise ValueError
    name = endpoint_name(node.get('name'))
    server = server_name(node.get('server'), uri=kind in {'ss', 'vmess'})
    port = node.get('port')
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError
    if node.get('dialer-proxy', '') != '':
        raise ValueError
    # There is no per-outbound UDP enable/disable switch in these parsers.
    # Only an explicit flag matching the protocol's native capability is safe.
    if 'udp' in node and boolean(node, 'udp') != (kind != 'http'):
        raise ValueError
    tfo = boolean(node, 'tfo')
    if kind != 'vmess' and tfo:
        raise ValueError  # The SS/builtin parsers cannot carry socket options.
    address = server + ':' + str(port)
    if kind == 'ss':
        cipher = scalar(node.get('cipher'))
        if cipher not in SS_CIPHERS:
            raise ValueError
        password = scalar(node.get('password'), unsafe=r'[\x00-\x1f\x7f-\x9f:]')
        auth = base64.urlsafe_b64encode((cipher + ':' + password).encode()).decode().rstrip('=')
        uri = scalar(f'ss://{auth}@{address}')
        return f'{name}, ss, {uri}'
    tls = boolean(node, 'tls')
    scv = boolean(node, 'skip-cert-verify')
    if not tls and scv:
        raise ValueError
    if kind in {'http', 'socks5'}:
        if tls:
            raise ValueError
        user = trimmed(node.get('username', ''), empty=True, unsafe=r'[\x00-\x1f\x7f-\x9f,;=]')
        password = trimmed(node.get('password', ''), empty=True, unsafe=r'[\x00-\x1f\x7f-\x9f,;=]')
        if bool(user) != bool(password):
            raise ValueError  # Mellow silently removes partial credentials.
        if kind == 'http' and ':' in user:
            raise ValueError  # HTTP Basic user-id cannot contain its separator.
        if kind == 'socks5' and max(len(user.encode()), len(password.encode())) > 255:
            raise ValueError  # SOCKS5 username/password fields are one byte long.
        protocol = 'socks' if kind == 'socks5' else 'http'
        return f'{name}, builtin, {protocol}, address={server}, port={port}, user={user}, pass={password}'
    uuid = scalar(node.get('uuid'))
    if not re.fullmatch(UUID_PATTERN, uuid):
        raise ValueError
    # vmess1Parser supplies only users[].id: no alterId or cipher query fields.
    aid = node.get('alterId', 0)
    if type(aid) is not int or aid != 0 or node.get('cipher', 'auto') != 'auto':
        raise ValueError
    network = node.get('network', 'tcp')
    # Clash "http" is TCP HTTP-header obfuscation. Mellow "http" is an alias
    # for HTTP/2 and creates httpSettings, not tcpSettings.header. Never remap it.
    if not isinstance(network, str) or network not in {'tcp', 'ws', 'h2'}:
        raise ValueError
    transport_keys = {'ws-opts', 'ws-path', 'ws-headers', 'h2-opts'} & set(node)
    allowed = {'ws-opts', 'ws-path', 'ws-headers'} if network == 'ws' else {'h2-opts'} if network == 'h2' else set()
    if transport_keys - allowed:
        raise ValueError
    query = {'network': network, 'tls': str(tls).lower()}
    path, ws_host = '', ''
    if network == 'ws':
        if 'ws-opts' in node:
            if {'ws-path', 'ws-headers'} & set(node):
                raise ValueError  # Do not combine conflicting old/new schemas.
            values = options(node['ws-opts'], {'path', 'headers'})
            path = values.get('path', '')
            headers = options(values.get('headers', {}), {'Host'})
        else:
            path = node.get('ws-path', '')
            headers = options(node.get('ws-headers', {}), {'Host'})
        if 'Host' in headers:
            ws_host = host_value(headers['Host'])
            query['ws.host'] = ws_host
    elif network == 'h2':
        values = options(node.get('h2-opts', {}), {'path', 'host'})
        path = values.get('path', '')
        hosts = values.get('host', [])
        if not isinstance(hosts, list):
            raise ValueError
        if hosts:
            query['http.host'] = ','.join(host_value(host) for host in hosts)
    if 'servername' in node:
        sni = sni_value(node['servername'])
        if not tls:
            raise ValueError
        query['tls.servername'] = sni
    elif tls and ws_host:
        query['tls.servername'] = sni_value(ws_host)
    for source, dest in (('skip-cert-verify', 'tls.allowinsecure'), ('tfo', 'sockopt.tcpfastopen')):
        if source in node:
            query[dest] = str(node[source]).lower()
    uri = scalar(f'vmess1://{uuid}@{address}{path_value(path)}?{urlencode(query, quote_via=quote)}')
    return f'{name}, vmess1, {uri}'


def decoded64(value):
    if not isinstance(value, str):
        raise ValueError
    return base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True).decode('utf-8')


def raw_uri_node(line):
    """A small lossless source subset, before the upstream parser drops fields."""
    if line.startswith('ss://'):
        value, _, fragment = line[5:].partition('#')
        if '?' in value:
            raise ValueError  # Plugins/group overrides are not this subset.
        if '@' not in value:
            value = decoded64(value)
            auth, sep, address = value.rpartition('@')
            if not sep:
                raise ValueError
        else:
            auth, address = value.split('@', 1)
            auth = decoded64(auth)
        cipher, sep, password = auth.partition(':')
        uri = urlsplit('ss://' + address)
        if not sep or uri.username is not None or uri.query or uri.path not in {'', '/'}:
            raise ValueError
        return dict(name=unquote(fragment, errors='strict') or 'Source', type='ss', server=uri.hostname,
                    port=uri.port, cipher=cipher, password=password)
    if not line.startswith('vmess://'):
        raise ValueError
    # JSON V2RayN links only. Other VMess dialects need an explicit Clash input;
    # accepting them without an independent parser would revive silent loss.
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result
    value = json.loads(decoded64(line[8:]), object_pairs_hook=unique)
    allowed = {'v', 'ps', 'add', 'port', 'id', 'aid', 'scy', 'net', 'type', 'host', 'path', 'tls', 'sni'}
    if not isinstance(value, dict) or set(value) - allowed:
        raise ValueError
    if any(not isinstance(item, str)
           and (key not in {'v', 'port', 'aid'} or type(item) is not int)
           for key, item in value.items()):
        raise ValueError
    if str(value.get('v', '1')) not in {'1', '2'} or str(value.get('aid', '0')) != '0':
        raise ValueError
    if value.get('scy', 'auto') != 'auto' or value.get('type', '') not in {'', 'none'}:
        raise ValueError  # Includes TCP HTTP-header FakeType, lost by upstream.
    network = value.get('net', '') or 'tcp'
    if network not in {'tcp', 'ws', 'h2'} or value.get('tls', '') not in {'', 'tls'}:
        raise ValueError
    host, path = value.get('host', ''), value.get('path', '')
    if str(value.get('v', '1')) == '1' and (host or path):
        raise ValueError  # Version 1 overloads Host with a semicolon path.
    if network == 'tcp' and (host or path):
        raise ValueError
    port = str(value.get('port', ''))
    if not re.fullmatch(r'[0-9]{1,5}', port):
        raise ValueError
    node = dict(name=value.get('ps') or 'Source', type='vmess', server=value.get('add'), port=int(port),
                uuid=value.get('id'), alterId=0, cipher='auto', network=network, tls=value.get('tls') == 'tls')
    if value.get('sni'):
        node['servername'] = value['sni']
    if network == 'ws':
        node['ws-opts'] = {'path': path, 'headers': {'Host': host} if host else {}}
    elif network == 'h2':
        node['h2-opts'] = {'path': path, 'host': host.split(',') if isinstance(host, str) and host else []}
    return node


def validate_sources(originals):
    """Fail closed before native export can erase unsupported source semantics.

    Accept explicit Clash documents or plain/once-base64 SS and JSON VMess URI
    lists. Other source dialects remain available for other output clients.
    """
    try:
        for raw in originals:
            value = raw.decode('utf-8-sig').strip()
            if re.fullmatch(r'[A-Za-z0-9+/_=\s-]+', value):
                value = decoded64(''.join(value.split())).strip()
            if value.startswith(('ss://', 'vmess://')):
                nodes = [raw_uri_node(line.strip()) for line in value.splitlines() if line.strip()]
            else:
                document = yaml_load(value)
                if not isinstance(document, dict) or 'proxy-providers' in document:
                    raise ValueError
                nodes = document.get('proxies')
            if not isinstance(nodes, list) or not nodes or len(nodes) > 10000:
                raise ValueError
            for node in nodes:
                endpoint(node)
    except (ConverterError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError):
        raise ConverterError('MELLOW_SOURCE') from None


def rows(content):
    section = ''
    for index, line in enumerate(re.split(r'\r\n|\r|\n', content)):
        # Mirror getLinesBySection/removeLineComments, including case-sensitive
        # section names. An accepted [endpoint] would produce no client nodes.
        value = re.sub(r';[^*]*', '', line).strip()
        # The capture already includes whitespace, stripped below without overlap.
        match = re.fullmatch(r'\[([^\]]*)\]', value)
        if match:
            section = match[1].strip()
            continue
        if section != 'Endpoint' or not value:
            continue
        if value.startswith(('#', '//')) and ',' not in value:
            continue
        parts = [part.strip() for part in value.split(',')]
        if len(parts) < 3:
            raise ValueError
        yield index, parts


def parameters(parts):
    values = {}
    for item in parts:
        pair = item.split('=')
        if len(pair) != 2:
            raise ValueError
        key, value = (part.strip() for part in pair)
        if key not in {'address', 'port', 'user', 'pass'} or key in values:
            raise ValueError
        values[key] = value
    return values


def uri_endpoint(value, kind):
    scalar(value)
    uri = urlsplit(value)
    if (uri.scheme != kind or not uri.hostname or uri.port is None
            or not 1 <= uri.port <= 65535 or uri.password is not None or uri.fragment):
        raise ValueError
    server_name(uri.hostname, uri=True)
    # Python normalizes host case, unlike WHATWG opaque host parsing. Restrict
    # the raw authority too, so escape sequences/userinfo cannot alter address.
    authority = value.split('://', 1)[1].split('/', 1)[0].split('?', 1)[0]
    if authority.count('@') != 1 or not re.fullmatch(r'[A-Za-z0-9_.-]+:[0-9]+', authority.split('@')[1]):
        raise ValueError
    return uri


def validate(content):
    """Reject malformed endpoint fields the permissive client parser drops."""
    count, names = 0, set()
    try:
        for _, parts in rows(content):
            name, kind = endpoint_name(parts[0]), parts[1]
            if name in names:
                raise ValueError
            names.add(name)
            if kind == 'builtin':
                if parts[2] in {'freedom', 'blackhole', 'dns'}:
                    continue
                if parts[2] not in {'http', 'socks'}:
                    raise ValueError
                values = parameters(parts[3:])
                if not re.fullmatch(r'[0-9]+', values.get('port', '')):
                    raise ValueError
                endpoint(dict(name=name, type='http' if parts[2] == 'http' else 'socks5',
                              server=values.get('address'), port=int(values['port']),
                              username=values.get('user', ''), password=values.get('pass', '')))
            elif kind in {'ss', 'vmess1'}:
                if len(parts) != 3:
                    raise ValueError
                uri = uri_endpoint(parts[2], kind)
                if not uri.username:
                    raise ValueError
                if kind == 'ss':
                    if uri.query or uri.path not in {'', '/'}:
                        raise ValueError
                    auth = base64.b64decode(uri.username + '=' * (-len(uri.username) % 4), altchars=b'-_', validate=True).decode()
                    method, sep, password = auth.partition(':')
                    if not sep:
                        raise ValueError
                    endpoint(dict(name=name, type='ss', server=uri.hostname, port=uri.port,
                                  cipher=method, password=password))
                else:
                    if not re.fullmatch(UUID_PATTERN, uri.username):
                        raise ValueError
                    path_value(uri.path)
                    network = validate_vmess_query(uri.query)
                    if network not in {'ws', 'http', 'h2'} and uri.path not in {'', '/'}:
                        raise ValueError
            else:
                raise ValueError
            count += 1
        if not count:
            raise ValueError
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        raise ConverterError('RESULT') from None


def validate_vmess_query(query):
    # decodeURIComponent is applied before '&'/'=' splitting, and does not
    # translate '+'. Do not use parse_qs, which has different semantics.
    if re.search(r'%(?![0-9a-fA-F]{2})', query):
        raise ValueError
    fields = {}
    for item in unquote(query, errors='strict').split('&') if query else []:
        pair = item.split('=')
        if len(pair) != 2 or pair[0] in fields:
            raise ValueError
        fields[pair[0]] = pair[1]
    bools = {'tls', 'tls.allowinsecure', 'sockopt.tcpfastopen', 'kcp.congestion'}
    integers = {'mux', 'sockopt.tos', 'kcp.mtu', 'kcp.tti', 'kcp.uplinkcapacity', 'kcp.downlinkcapacity'}
    allowed = bools | integers | {'network', 'tls.servername', 'ws.host', 'http.host', 'header', 'quic.security', 'quic.key'}
    if set(fields) - allowed:
        raise ValueError
    # Existing native base endpoints may use Mellow's HTTP/2 alias or KCP/QUIC;
    # accepting those is not permission to map Clash HTTP obfuscation to HTTP/2.
    network = fields.get('network', 'tcp')
    if network not in {'tcp', 'ws', 'http', 'h2', 'kcp', 'mkcp', 'quic'}:
        raise ValueError
    if ('ws.host' in fields and network != 'ws'
            or 'http.host' in fields and network not in {'http', 'h2'}
            or any(key.startswith('kcp.') for key in fields) and network not in {'kcp', 'mkcp'}
            or any(key.startswith('quic.') for key in fields) and network != 'quic'
            or 'header' in fields and network not in {'kcp', 'mkcp', 'quic'}):
        raise ValueError
    if fields.get('tls', 'false') != 'true' and (
            'tls.servername' in fields or fields.get('tls.allowinsecure') == 'true'):
        raise ValueError
    for key, value in fields.items():
        scalar(value, unsafe=r'[\x00-\x1f\x7f-\x9f&=;]')
        if key in bools and value not in {'true', 'false'}:
            raise ValueError
        if key in integers and (not re.fullmatch(r'[0-9]+', value) or int(value) <= 0):
            raise ValueError
        if key == 'ws.host':
            host_value(value)
        if key == 'tls.servername':
            sni_value(value)
        if key == 'http.host':
            for host in value.split(','):
                host_value(host)
    return network


def repair(native, normalized):
    try:
        document = yaml_load(normalized)
        nodes = document['proxies']
        if not isinstance(nodes, list) or not nodes:
            raise ValueError
        by_name, replacements = {}, {}
        for node in nodes:
            replacement = endpoint(node)
            name = node['name']
            if name in by_name:
                raise ValueError
            by_name[name], replacements[name] = node, replacement
        lines = [line for line in re.findall(r'[^\r\n]*(?:\r\n?|\n|$)', native) if line]
        replaced = set()
        for index, parts in rows(native):
            node = by_name.get(parts[0])
            if node is None:
                continue  # Existing base endpoints still get validated.
            name = parts[0]
            if name in replaced:
                raise ValueError
            expected = {'ss': ('ss',), 'vmess': ('vmess1',),
                        'http': ('builtin', 'http'), 'socks5': ('builtin', 'socks')}[node['type']]
            if tuple(parts[1:1 + len(expected)]) != expected:
                raise ValueError
            if parts[1] in {'ss', 'vmess1'}:
                if len(parts) != 3:
                    raise ValueError
                original = uri_endpoint(parts[2], parts[1])
                if original.hostname != node['server'].lower() or original.port != node['port']:
                    raise ValueError
            else:
                original = parameters(parts[3:])
                if original.get('address') != node['server'] or original.get('port') != str(node['port']):
                    raise ValueError
            # Preserve all non-endpoint bytes, including mixed CRLF/LF and the
            # final-newline state. Replacing credentials must not rewrite rules.
            ending = lines[index][len(lines[index].rstrip('\r\n')):]
            lines[index] = replacements[name] + ending
            replaced.add(name)
        if replaced != set(by_name):
            raise ValueError  # Never silently omit normalized/unsupported nodes.
        value = ''.join(lines)
        validate(value)
        return value
    except (ConverterError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError):
        raise ConverterError('RESULT') from None
