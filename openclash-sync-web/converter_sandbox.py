#!/usr/bin/env python3
"""Root-owned, narrow one-shot converter runner. NEVER join the Docker group.

Only a fixed, locally present image may run. Inputs go over stdin to tmpfs;
there are no host mounts, published ports, production preferences or logs.
This module deliberately imports no project modules in the privileged process.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import io
import json
import os
import re
import resource
import secrets
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.parse import urlencode

IMAGE = 'sha256:73599336c72fda3758dee2888b0abe665b0256cad822905fe86d16132ef2f67b'
DOCKER = '/usr/bin/docker'
MAX_INPUT = 2 * 1024 * 1024
MAX_CONTENT = 1024 * 1024
MAX_OUTPUT = 1024 * 1024
TARGETS = frozenset('clash clashr singbox quan quanx loon mellow ss sssub ssd ssr surfboard surge trojan v2ray mixed'.split())
TOOL_TARGETS = frozenset({'ruleset', 'template', 'surge2clash'})
RULE_FORMATS = frozenset({'surge', 'quanx', 'clash-domain', 'clash-ipcidr', 'clash-classic'})
BOOL_KEYS = frozenset('emoji add_emoji remove_emoji append_type append_info tfo udp list sort script insert scv fdn expand new_name strict prepend classic tls13 surge.doh clash.doh'.split())
TEXT_KEYS = frozenset('include exclude rename group dev_id filename ua'.split())
INT_KEYS = {'ver': (2, 5), 'interval': (1, 31536000)}
MAX_PARAMETERS = 32
MAX_PARAMETER_BYTES = 4096
PARAMETER_KEY_PATTERN = r'[A-Za-z][A-Za-z0-9_.-]{0,63}'
# Intentionally duplicated: privileged code must not import writable app modules.
RESERVED_PARAMETERS = BOOL_KEYS | TEXT_KEYS | frozenset(INT_KEYS) | frozenset('''target config url path token upload upload_path groups ruleset profile_data
filter_script sort_script filter_script_file sort_script_file name dev_id
operation variables parameters input_format type policy_sources include_primary
version files source_names body backend sources profile resources scripts uploads
config_content upload download total expire constructor prototype __proto__
__defineGetter__ __defineSetter__ __lookupGetter__ __lookupSetter__'''.lower().split())
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/nonexistent', 'DOCKER_HOST': 'unix:///var/run/docker.sock'}
RUN_SCRIPT = '''set -eu
umask 077
# Paths and tar headers are constructed by the root-owned Python runner.
tar -xf - -C /job
/usr/bin/subconverter -f /job/pref.ini >/dev/null 2>>/job/native.err &
engine_pid=$!
trap 'kill "$engine_pid" 2>/dev/null || true; wait "$engine_pid" 2>/dev/null || true' EXIT HUP INT TERM
ready=false
attempt=0
while [ "$attempt" -lt 40 ]; do
    if wget -q -T 1 -O /dev/null http://127.0.0.1:25500/version 2>/dev/null; then ready=true; break; fi
    kill -0 "$engine_pid" 2>/dev/null || exit 1
    attempt=$((attempt + 1))
    sleep 0.05
done
[ "$ready" = true ]
# The pinned engine logs startup/INI autodetection before reading log_level.
# Readiness is the boundary: no user script has run yet. Retain all stderr from
# the actual request, including QuickJS exceptions despite native HTTP 200.
: >/job/native.err
wget -q -T 20 -O /job/result.txt "$(cat /job/request.url)" 2>/dev/null
[ ! -s /job/native.err ]
[ -f /job/result.txt ] && [ ! -L /job/result.txt ]
cat /job/result.txt
'''



class SandboxError(ValueError):
    pass


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SandboxError('REQUEST')
        result[key] = value
    return result


def safe_text(value, maximum):
    if not isinstance(value, str) or any(ord(c) < 32 or 127 <= ord(c) <= 159 or 0xd800 <= ord(c) <= 0xdfff for c in value):
        raise SandboxError('REQUEST')
    if len(value.encode('utf-8')) > maximum:
        raise SandboxError('REQUEST')
    return value


def parameter_bytes(values):
    return sum(len(key.encode()) + len(value.encode()) for key, value in values.items())


def validate_parameters(value):
    if not isinstance(value, dict) or len(value) > MAX_PARAMETERS:
        raise SandboxError('REQUEST')
    result = {}
    for key, item in value.items():
        if not isinstance(key, str) or not re.fullmatch(PARAMETER_KEY_PATTERN, key) or key.lower() in RESERVED_PARAMETERS:
            raise SandboxError('REQUEST')
        result[key] = safe_text(item, MAX_PARAMETER_BYTES)
    return result


def validate_job(job):
    if not isinstance(job, dict) or set(job) != {'version', 'files', 'options', 'source_names'} or job['version'] != 1 or type(job['version']) is not int:
        raise SandboxError('REQUEST')
    if not isinstance(job['files'], list) or not 1 <= len(job['files']) <= 64:
        raise SandboxError('REQUEST')
    files = {}
    total = 0
    for item in job['files']:
        if not isinstance(item, dict) or set(item) != {'name', 'body'} or not isinstance(item['name'], str) or not re.fullmatch(r'[sa][0-9]{3}\.txt', item['name']) or item['name'] in files:
            raise SandboxError('REQUEST')
        if not isinstance(item['body'], str) or len(item['body']) > MAX_INPUT:
            raise SandboxError('REQUEST')
        try:
            body = base64.b64decode(item['body'], validate=True)
            body.decode('utf-8')
        except (ValueError, UnicodeError):
            raise SandboxError('CONTENT') from None
        total += len(body)
        if not body or b'\0' in body or total > MAX_CONTENT:
            raise SandboxError('CONTENT')
        files[item['name']] = body
    names = job['source_names']
    if not isinstance(names, list) or not 1 <= len(names) <= 32 or any(not isinstance(n, str) or n not in files or not n.startswith('s') for n in names):
        raise SandboxError('REQUEST')
    values = job['options']
    if not isinstance(values, dict) or len(values) > 48 or not isinstance(values.get('target'), str) or values['target'] not in TARGETS | TOOL_TARGETS:
        raise SandboxError('REQUEST')
    target = values['target']
    if target in TOOL_TARGETS:
        if target == 'ruleset':
            if set(values) != {'target', 'type', 'group', 'input_format'} or type(values['type']) is not int or not 1 <= values['type'] <= 6:
                raise SandboxError('REQUEST')
            group = safe_text(values['group'], 128)
            if not group or any(c in group for c in ',|`') or not isinstance(values['input_format'], str) or values['input_format'] not in RULE_FORMATS:
                raise SandboxError('REQUEST')
        elif target == 'template':
            if set(values) != {'target', 'variables'} or not isinstance(values['variables'], dict) or len(values['variables']) > 32:
                raise SandboxError('REQUEST')
            for key, value in values['variables'].items():
                if not isinstance(key, str) or not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_.-]{0,63}', key) or key.lower() in {'path', 'constructor', 'prototype'}:
                    raise SandboxError('REQUEST')
                safe_text(value, 4096)
            if total + parameter_bytes(values['variables']) > MAX_CONTENT:
                raise SandboxError('CONTENT')
        elif set(values) - {'target', 'policy_sources', 'include_primary'}:
            raise SandboxError('REQUEST')
        elif target == 'surge2clash':
            paths, primary = values.get('policy_sources', []), values.get('include_primary', True)
            if not isinstance(paths, list) or type(primary) is not bool or not 1 <= len(paths) + primary <= 32:
                raise SandboxError('REQUEST')
            if any(not isinstance(path, str) or path not in files or not path.startswith('a') for path in paths) or len(set(paths)) != len(paths):
                raise SandboxError('REQUEST')
        if target != 'ruleset' and len(names) != 1:
            raise SandboxError('REQUEST')
        return files, names, dict(values)
    options = {}
    for key, value in values.items():
        if key == 'target':
            options[key] = value
        elif key == 'parameters':
            options[key] = validate_parameters(value)
            if total + parameter_bytes(options[key]) > MAX_CONTENT:
                raise SandboxError('CONTENT')
        elif key in BOOL_KEYS:
            if type(value) is not bool:
                raise SandboxError('REQUEST')
            options[key] = str(value).lower()
        elif key in TEXT_KEYS:
            options[key] = safe_text(value, 4096 if key == 'rename' else 1024)
        elif key in INT_KEYS:
            low, high = INT_KEYS[key]
            if type(value) is not int or not low <= value <= high:
                raise SandboxError('REQUEST')
            options[key] = str(value)
        elif key in {'config', 'filter_script_file', 'sort_script_file'}:
            if not isinstance(value, str) or value not in files or not value.startswith('a'):
                raise SandboxError('REQUEST')
            if key != 'config' and len(files[value]) > 65536:
                raise SandboxError('REQUEST')
            options[key] = './' + value
        else:
            raise SandboxError('REQUEST')
    if 'sort_script_file' in options and options.get('sort') != 'true':
        raise SandboxError('REQUEST')
    if 'ver' in options and options['target'] != 'surge':
        raise SandboxError('REQUEST')
    return files, names, options


def default_base(target):
    # Neutral export bases, not either router's operational configuration.
    # The upstream all_base.tpl contains third-party scripts/MITM/cron examples;
    # none of those are silently introduced into an exported configuration.
    if target in {'clash', 'clashr'}:
        return "port: 7890\nsocks-port: 7891\nallow-lan: false\nbind-address: 127.0.0.1\nmode: rule\nlog-level: warning\n"
    if target in {'singbox', 'sssub'}:
        return '{"log":{"level":"warn"},"inbounds":[{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":7890}],"outbounds":[],"route":{"rules":[]}}' if target == 'singbox' else '{}'
    sections = {
        'surge': '[General]\nloglevel=notify\ndns-server=system\n[Proxy]\n[Proxy Group]\n[Rule]\n',
        'surfboard': '[General]\nloglevel=notify\ninterface=127.0.0.1\n[Proxy]\n[Proxy Group]\n[Rule]\n',
        'loon': '[General]\ndns-server=system\nallow-wifi-access=false\n[Proxy]\n[Proxy Group]\n[Rule]\n',
        'quan': '[SERVER]\n[POLICY]\n[DNS]\n[TCP]\n[STATE]\n',
        'quanx': '[general]\n[dns]\n[policy]\n[server_local]\n[filter_local]\n',
        'mellow': '[Endpoint]\nDIRECT, builtin, freedom\nREJECT, builtin, blackhole\n[Routing]\ndomainStrategy=AsIs\n[DnsServer]\nlocalhost\n',
    }
    return sections.get(target, '\n')


def make_archive(job):
    files, names, options = validate_job(job)
    # Never read production preferences, profiles, or credentials.
    files["default-base.txt"] = default_base('clash' if options['target'] == 'surge2clash' else options['target']).encode()
    # Native fetchFile/fileExist(scope_limit=true) rejects absolute paths.
    # The process cwd is /job; use only the fixed relative job paths.
    base = "./default-base.txt"
    prefs = ['[common]', 'api_mode=false', 'enable_insert=false', 'default_url=',
             'proxy_subscription=NONE', 'proxy_config=NONE', 'proxy_ruleset=NONE',
             'base_path=./', 'reload_conf_on_request=false']
    prefs += [key + '=' + base for key in ('clash_rule_base', 'surge_rule_base', 'surfboard_rule_base',
              'mellow_rule_base', 'quan_rule_base', 'quanx_rule_base', 'loon_rule_base', 'sssub_rule_base', 'singbox_rule_base')]
    prefs += ['[node_pref]', 'sort_flag=false', 'skip_cert_verify=false', 'clash_use_new_field_name=true',
              '[managed_config]', 'write_managed_config=false', '[emojis]', 'add_emoji=false', 'remove_old_emoji=false',
              'rule=!!import:/base/snippets/emoji.txt', '[rulesets]', 'enabled=true',
              'overwrite_original_rules=true', 'ruleset=Proxy,[]FINAL',
              '[proxy_groups]', 'custom_proxy_group=Proxy`select`.*', '[template]',
              'template_path=./', '[server]', 'listen=127.0.0.1', 'port=25500', '[advanced]', 'log_level=fatal', 'print_debug_info=false',
              'enable_cache=false', 'async_fetch_ruleset=false', 'max_concurrent_threads=1',
              'max_allowed_download_size=1048576', 'max_allowed_rules=30000', 'max_allowed_rulesets=32',
              'skip_failed_links=false', 'script_clean_context=true']
    if options.get('filter_script_file'):
        offset = prefs.index('[node_pref]')
        prefs[offset:offset] = ['enable_filter=true', 'filter_script=path:' + options.pop('filter_script_file')]
    if options.get('sort_script_file'):
        offset = prefs.index('[managed_config]')
        prefs[offset:offset] = ['sort_script=path:' + options.pop('sort_script_file')]
    if options['target'] == 'surge2clash':
        # /surge2clash loses groups/rules and assigns every policy-path group ID
        # zero in this pinned upstream. /sub retains exact source provenance.
        source_paths = (['./' + names[0]] if options.get('include_primary', True) else [])
        source_paths += ['./' + name for name in options.get('policy_sources', [])]
        offset = prefs.index('custom_proxy_group=Proxy`select`.*')
        prefs[offset:offset + 1] = ['custom_proxy_group=__OCS_SURGE_SOURCE_%d`select`!!GROUPID=%d' % (index, index)
                                   for index in range(len(source_paths))]
        prefs[prefs.index('ruleset=Proxy,[]FINAL')] = 'ruleset=DIRECT,[]FINAL'
    files['pref.ini'] = ('\n'.join(prefs) + '\n').encode()
    if options['target'] in TOOL_TARGETS:
        if options['target'] == 'ruleset':
            prefix = options['input_format'] + ':'
            paths = '|'.join(prefix + './' + name for name in names)
            args = {'url': base64.urlsafe_b64encode(paths.encode()).decode(), 'type': options['type'],
                    'group': base64.urlsafe_b64encode(options['group'].encode()).decode()}
            endpoint = '/getruleset'
        elif options['target'] == 'template':
            args = {'path': './' + names[0], **options['variables']}
            endpoint = '/render'
        else:
            args = {'target': 'clash', 'url': '|'.join(source_paths)}
            endpoint = '/sub'
    else:
        args = {**options.pop('parameters', {}), **options, 'url': '|'.join('./' + name for name in names)}
        endpoint = '/sub'
    files['request.url'] = ('http://127.0.0.1:25500' + endpoint + '?' + urlencode(args)).encode()
    if len(files['request.url']) > 65536:
        raise SandboxError('CONTENT')
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.uid, info.gid, info.mtime = len(data), 0o600, 65534, 65534, 0
            tar.addfile(info, io.BytesIO(data))
    return archive.getvalue(), options['target']


def command(name):
    if not re.fullmatch(r'openclash-sync-converter-[0-9a-f]{24}', name):
        raise SandboxError('REQUEST')
    return [DOCKER, 'create', '--rm', '-i', '--pull', 'never', '--name', name,
            '--network', 'none', '--read-only', '--user', '65534:65534',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
            '--memory', '256m', '--memory-swap', '256m', '--cpus', '1', '--pids-limit', '32',
            '--ulimit', 'nofile=128:128', '--ulimit', 'fsize=2097152:2097152', '--ulimit', 'cpu=20:20',
            '--tmpfs', '/job:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=65534,gid=65534',
            '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=4m,mode=1777',
            '--log-driver', 'none', '--no-healthcheck', '--env', 'HOME=/job',
            '--workdir', '/job', '--entrypoint', '/bin/sh', IMAGE, '-c', RUN_SCRIPT]


def limit_output():
    # Runner has no threads. Cap hostile stdout even if native code is exploited.
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT + 1, MAX_OUTPUT + 1))


def docker_metadata(arguments, *, timeout=10):
    """Daemon responses are bounded too; do not forward its error text."""
    with tempfile.TemporaryFile() as output:
        process = subprocess.run(arguments, stdout=output, stderr=subprocess.DEVNULL,
                                 timeout=timeout, env=ENV, check=False, preexec_fn=limit_output)
        output.seek(0)
        body = output.read(4097)
        if len(body) > 4096:
            raise SandboxError('SANDBOX')
        return process.returncode, body


def cleanup_job(name):
    # Only this invocation's unpredictable, root-generated name is targeted.
    # rm can report "not found" after --rm. A successful *separate* daemon
    # listing must prove absence; a nonzero rm alone is never cleanup evidence.
    try:
        try:
            docker_metadata([DOCKER, 'rm', '-f', name], timeout=5)
        except subprocess.TimeoutExpired:
            pass
        code, body = docker_metadata([DOCKER, 'ps', '-aq', '--no-trunc',
                                      '--filter', 'name=^/' + name + '$'], timeout=5)
        return code == 0 and not body.strip()
    except (OSError, subprocess.TimeoutExpired, SandboxError):
        return False


def run_job(job):
    archive, target = make_archive(job)
    name = 'openclash-sync-converter-' + secrets.token_hex(12)
    started = time.monotonic()
    needs_cleanup, creation_uncertain = True, False
    # Separate create/start: a timed-out create can never later start an
    # unobserved native job. stdin is sent only after a confirmed creation.
    try:
        try:
            code, identifier = docker_metadata(command(name), timeout=10)
        except OSError:
            needs_cleanup = False  # The Docker client could not be spawned.
            raise SandboxError('SANDBOX_UNAVAILABLE') from None
        except subprocess.TimeoutExpired:
            creation_uncertain = True
            raise SandboxError('SANDBOX_CLEANUP') from None
        if code or re.fullmatch(rb'[0-9a-f]{64}\n?', identifier) is None:
            raise SandboxError('SANDBOX_UNAVAILABLE')
        # No user value is used as a command, image, path, mount, or container id.
        with tempfile.TemporaryFile() as output:
            try:
                process = subprocess.run([DOCKER, 'start', '-ai', name], input=archive,
                                         stdout=output, stderr=subprocess.DEVNULL,
                                         timeout=30, env=ENV, check=False, preexec_fn=limit_output)
            except (OSError, subprocess.TimeoutExpired):
                raise SandboxError('SANDBOX') from None
            if process.returncode:
                raise SandboxError('SANDBOX')
            output.seek(0)
            body = output.read(MAX_OUTPUT + 1)
            if not body or len(body) > MAX_OUTPUT or b'\0' in body:
                raise SandboxError('RESULT')
            try:
                content = body.decode('utf-8-sig')
            except UnicodeError:
                raise SandboxError('RESULT') from None
            encoded = content.encode()
            result = {'ok': True, 'content': content, 'sha256': hashlib.sha256(encoded).hexdigest(),
                      'bytes': len(encoded), 'target': target,
                      'engine': 'subconverter-0.9.1-36573b3-isolated', 'isolated': True,
                      'network': 'none', 'router_changed': False}
    finally:
        cleaned = cleanup_job(name) if needs_cleanup else True
        if creation_uncertain or not cleaned:
            # A late create may still appear as a *stopped*, empty container.
            # Never claim cleanup was proven in this uncertainty window.
            raise SandboxError('SANDBOX_CLEANUP') from None
    result['elapsed_ms'] = round((time.monotonic() - started) * 1000)
    result['cleanup_confirmed'] = True
    return result


def main():
    if os.geteuid() != 0:
        raise SandboxError('SANDBOX_UNAVAILABLE')
    # Cross-process budget. lstat/open/fstat checks protect the privileged lock.
    fd = os.open('/run/lock/openclash-sync-converter.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            raise SandboxError('SANDBOX_UNAVAILABLE')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SandboxError('CONVERTER_BUSY') from None
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if not raw or len(raw) > MAX_INPUT:
            raise SandboxError('REQUEST')
        job = json.loads(raw, object_pairs_hook=unique_object)
        return run_job(job)
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        result = main()
    except (SandboxError, OSError, ValueError, TypeError, RecursionError) as exc:
        code = str(exc) if isinstance(exc, SandboxError) else 'SANDBOX'
        result = {'ok': False, 'code': code, 'router_changed': False}
    sys.stdout.buffer.write(json.dumps(result, ensure_ascii=False, separators=(',', ':')).encode())
