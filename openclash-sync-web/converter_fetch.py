"""Bounded public-HTTP intake for conversion jobs, with DNS pinning per hop.

No urllib proxy discovery, cookies, forwarded browser headers or credentials.
URLs and response text are sensitive: never put them in exceptions or logs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import http.client
import ipaddress
import json
import socket
import ssl
import subprocess
import sys
import time
import signal
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

# -I worker mode deliberately excludes cwd; load only the installed sibling.
if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parent))
from subscription_converter import ConverterError, http_url, text

MAX_FETCH_BYTES = 1024 * 1024
MAX_JOB_BYTES = 1024 * 1024
MAX_REDIRECTS = 4
TIMEOUT = 25.0
# Transition mechanisms can reach a non-public embedded IPv4 endpoint even if
# the outer IPv6 happens to pass is_global on the host's Python version.
TRANSITION_NETS = tuple(ipaddress.ip_network(n) for n in (
    '64:ff9b::/96', '64:ff9b:1::/48', '2001::/32', '2002::/16'))
# Stable policy for special-use ranges whose is_global classification differs
# between supported Python releases. The IETF /24 has two global exceptions;
# deprecated 6to4 relays and documentation prefixes are never HTTP sources.
SPECIAL_FETCH_NETS = tuple(ipaddress.ip_network(n) for n in (
    '192.0.0.0/24', '192.88.99.0/24', '3fff::/20'))
GLOBAL_IETF_EXCEPTIONS = frozenset(ipaddress.ip_address(n) for n in (
    '192.0.0.9', '192.0.0.10'))
CLOUD_PLATFORM_IP = ipaddress.ip_address('168.63.129.16')
DNS_CODE = '''import json,socket,sys
try:
 r=socket.getaddrinfo(sys.argv[1],None,type=socket.SOCK_STREAM,proto=socket.IPPROTO_TCP)
 a=list(dict.fromkeys(x[4][0] for x in r))
 if not 1<=len(a)<=32: raise ValueError()
 print(json.dumps(a))
except Exception: sys.exit(1)
'''


def public_ip(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
        if ip not in GLOBAL_IETF_EXCEPTIONS and any(ip in net for net in SPECIAL_FETCH_NETS):
            raise ValueError
        if ip == CLOUD_PLATFORM_IP or '%' in value or not ip.is_global or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            raise ValueError
        if ip.version == 6 and (ip.ipv4_mapped is not None or any(ip in net for net in TRANSITION_NETS)):
            raise ValueError
        return ip.compressed
    except ValueError:
        raise ConverterError('FETCH_ADDRESS') from None


def resolve_public(host: str, timeout: float) -> tuple[str, ...]:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        # libc getaddrinfo has no deadline. A short-lived isolated process can be
        # killed and reaped; a timed-out thread would leak workers indefinitely.
        try:
            process = subprocess.run([sys.executable, '-I', '-B', '-c', DNS_CODE, host],
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     timeout=min(timeout, 5.0), check=False,
                                     env={'PATH': '/usr/bin:/bin'})
            if process.returncode or len(process.stdout) > 4096:
                raise ValueError
            values = json.loads(process.stdout)
            if not isinstance(values, list) or not 1 <= len(values) <= 32 or any(not isinstance(x, str) for x in values):
                raise ValueError
        except (OSError, ValueError, subprocess.TimeoutExpired):
            raise ConverterError('FETCH_DNS') from None
    else:
        values = [host]
    # Reject mixed public/private answers instead of picking only a public one.
    return tuple(dict.fromkeys(public_ip(value) for value in values))


class PinnedConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, address: str, tls: bool, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self.address, self.tls = address, tls

    def connect(self) -> None:
        # Numeric socket connect: no second hostname resolution (DNS rebinding).
        family = socket.AF_INET6 if ':' in self.address else socket.AF_INET
        connection = socket.socket(family, socket.SOCK_STREAM)
        try:
            connection.settimeout(self.timeout)
            connection.connect((self.address, self.port))
            if self.tls:
                connection = ssl.create_default_context().wrap_socket(connection, server_hostname=self.host)
            self.sock = connection
        except BaseException:
            connection.close()
            raise


@dataclass(frozen=True)
class Fetched:
    body: bytes = field(repr=False)
    content_type: str
    redirects: int
    status: int = 200


class PublicFetcher:
    def __init__(self, *, timeout: float = TIMEOUT, maximum: int = MAX_JOB_BYTES):
        self.deadline = time.monotonic() + timeout
        self.remaining = maximum

    def time_left(self) -> float:
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise ConverterError('FETCH_TIMEOUT')
        return left

    def fetch(self, value: str, *, user_agent: str = 'OpenClash-Sync-Converter/1',
              _method='GET', _body=None, _headers=None, _statuses=(200,), _redirects=True, _allow_empty=False) -> Fetched:
        url = http_url(value)
        if len(user_agent) > 256 or not user_agent.isascii() or any(ord(c) < 32 or ord(c) == 127 for c in user_agent):
            raise ConverterError('OPTION')
        seen = set()
        for hop in range(MAX_REDIRECTS + 1):
            if url in seen:
                raise ConverterError('FETCH_REDIRECT')
            seen.add(url)
            parts = urlsplit(url)
            host = parts.hostname
            # An explicit HTTP(S) source is not an arbitrary TCP port probe.
            port = parts.port or (443 if parts.scheme == 'https' else 80)
            if port not in (80, 443):
                raise ConverterError('FETCH_PORT')
            addresses = resolve_public(host, self.time_left())
            response = None
            connection = None
            try:
                # Try alternate, already validated IPs only for connect failures.
                for address in addresses:
                    connection = PinnedConnection(host, port, address, parts.scheme == 'https', min(self.time_left(), 6.0))
                    try:
                        connection.connect()
                        break
                    except (OSError, ssl.SSLError):
                        connection.close()
                else:
                    raise ConverterError('FETCH_CONNECT')
                path = urlunsplit(('', '', parts.path or '/', parts.query, ''))
                connected_socket = connection.sock
                connected_socket.settimeout(min(self.time_left(), 6.0))
                connection.request(_method, path, body=_body, headers={'User-Agent': user_agent, 'Accept': 'text/plain, */*',
                                                         'Accept-Encoding': 'identity', 'Connection': 'close', **(_headers or {})})
                response = connection.getresponse()
                if response.status in (301, 302, 303, 307, 308):
                    if not _redirects:
                        raise ConverterError('FETCH_REDIRECT')
                    locations = response.headers.get_all('Location', [])
                    if len(locations) != 1 or hop == MAX_REDIRECTS:
                        raise ConverterError('FETCH_REDIRECT')
                    # Fragments aren't sent on HTTP; strip them only after full
                    # syntax validation rather than hiding credentials/controls.
                    destination = http_url(urljoin(url, text(locations[0], 16384)))
                    if parts.scheme == 'https' and urlsplit(destination).scheme != 'https':
                        raise ConverterError('FETCH_DOWNGRADE')
                    url = destination
                    continue
                if response.status not in _statuses:
                    raise ConverterError('FETCH_STATUS')
                encodings = response.headers.get_all('Content-Encoding', [])
                lengths = response.headers.get_all('Content-Length', [])
                transfers = response.headers.get_all('Transfer-Encoding', [])
                if encodings and (len(encodings) != 1 or encodings[0].lower() != 'identity'):
                    raise ConverterError('FETCH_ENCODING')
                if len(lengths) > 1 or len(transfers) > 1 or (lengths and transfers) or (transfers and transfers[0].lower() != 'chunked'):
                    raise ConverterError('FETCH_PROTOCOL')
                cap = min(MAX_FETCH_BYTES, self.remaining)
                if lengths and (not lengths[0].isascii() or not lengths[0].isdigit() or len(lengths[0]) > 10):
                    raise ConverterError('FETCH_PROTOCOL')
                if lengths and int(lengths[0]) > cap:
                    raise ConverterError('FETCH_SIZE')
                chunks = []
                size = 0
                while True:
                    if getattr(response, 'isclosed', lambda: False)():
                        break
                    connected_socket.settimeout(min(self.time_left(), 6.0))
                    chunk = response.read1(min(65536, cap + 1 - size))
                    size += len(chunk)
                    if size > cap:
                        raise ConverterError('FETCH_SIZE')
                    if not chunk:
                        break
                    chunks.append(chunk)
                if (not size and not _allow_empty) or (lengths and size != int(lengths[0])):
                    raise ConverterError('FETCH_PROTOCOL')
                self.remaining -= size
                return Fetched(b''.join(chunks), response.getheader('Content-Type', '')[:128], hop, response.status)
            except ConverterError:
                raise
            except (OSError, ValueError, http.client.HTTPException):
                raise ConverterError('FETCH_CONNECT') from None
            finally:
                if response is not None:
                    response.close()
                if connection is not None:
                    connection.close()
        raise ConverterError('FETCH_REDIRECT')


def fetch_many(urls: list[str], *, user_agent: str = 'OpenClash-Sync-Converter/1',
               timeout: float = TIMEOUT, maximum: int = MAX_JOB_BYTES) -> list[bytes]:
    """Public API: a killable worker enforces an overall wall-clock deadline,
    including slow HTTP headers/trickle bodies and hostile DNS resolvers.
    """
    import base64
    if not isinstance(urls, list) or not 1 <= len(urls) <= 64:
        raise ConverterError('SOURCES')
    if type(timeout) not in (int, float) or not 0 < timeout <= TIMEOUT:
        raise ConverterError('FETCH_TIMEOUT')
    if type(maximum) is not int or not 1 <= maximum <= MAX_JOB_BYTES:
        raise ConverterError('FETCH_SIZE')
    urls = [http_url(url) for url in urls]
    request = json.dumps({'urls': urls, 'ua': user_agent, 'timeout': timeout, 'maximum': maximum}, ensure_ascii=False).encode()
    if len(request) > 2 * MAX_JOB_BYTES:
        raise ConverterError('FETCH_SIZE')
    try:
        process = subprocess.Popen([sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--worker'],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   start_new_session=True, env={'PATH': '/usr/bin:/bin'})
        try:
            raw, _ = process.communicate(request, timeout=timeout)
        except subprocess.TimeoutExpired:
            os_kill_group(process)
            raise ConverterError('FETCH_TIMEOUT') from None
        if process.returncode or len(raw) > 2 * MAX_JOB_BYTES:
            raise ConverterError('FETCH_CONNECT')
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ValueError
        if result.get('ok') is not True:
            code = result.get('code')
            raise ConverterError(code if isinstance(code, str) and code.startswith('FETCH_') else 'FETCH_CONNECT')
        if set(result) != {'ok', 'bodies'} or not isinstance(result['bodies'], list) or any(not isinstance(item, str) for item in result['bodies']):
            raise ValueError
        bodies = [base64.b64decode(item, validate=True) for item in result['bodies']]
        if len(bodies) != len(urls) or any(not body for body in bodies) or sum(map(len, bodies)) > maximum:
            raise ValueError
        return bodies
    except ConverterError:
        raise
    except (OSError, ValueError, TypeError, KeyError):
        raise ConverterError('FETCH_CONNECT') from None


def os_kill_group(process):
    import os
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.communicate()


if __name__ == '__main__':
    import base64
    import resource
    # macOS does not implement a usable RLIMIT_AS. Production WORKER is Linux;
    # developer tests still retain the process deadline and byte/CPU budgets.
    if sys.platform.startswith('linux'):
        resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024, 128 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    try:
        raw = sys.stdin.buffer.read(2 * MAX_JOB_BYTES + 1)
        if len(raw) > 2 * MAX_JOB_BYTES:
            raise ConverterError('FETCH_SIZE')
        request = json.loads(raw)
        if not isinstance(request, dict) or set(request) != {'urls', 'ua', 'timeout', 'maximum'} or not isinstance(request['urls'], list) or not 1 <= len(request['urls']) <= 64:
            raise ConverterError('FETCH_PROTOCOL')
        if type(request['timeout']) not in (int, float) or not 0 < request['timeout'] <= TIMEOUT or \
                type(request['maximum']) is not int or not 1 <= request['maximum'] <= MAX_JOB_BYTES:
            raise ConverterError('FETCH_PROTOCOL')
        fetcher = PublicFetcher(timeout=request['timeout'], maximum=request['maximum'])
        bodies = [base64.b64encode(fetcher.fetch(url, user_agent=request['ua']).body).decode() for url in request['urls']]
        result = {'ok': True, 'bodies': bodies}
    except ConverterError as exc:
        result = {'ok': False, 'code': exc.code}
    except Exception:
        result = {'ok': False, 'code': 'FETCH_CONNECT'}
    sys.stdout.write(json.dumps(result, separators=(',', ':')))
