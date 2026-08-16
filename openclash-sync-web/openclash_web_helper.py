#!/usr/bin/env python3
"""worker host root helper：只把白名单 JSON 动作转发到对应路由器 forced-command。"""

from __future__ import annotations

import json
import os
import resource
import stat
import subprocess
import sys
import tempfile

MAX = 2 * 1024 * 1024
TARGETS = {
    "router_a": ("192.0.2.10", "/etc/openclash-web/keys/router_a", "/etc/openclash-web/known_hosts"),
    "router_b": ("192.0.2.11", "/etc/openclash-web/keys/router_b", "/etc/openclash-web/known_hosts"),
}
ALLOWED = {"status", "read", "write", "stage_main", "update_maying", "update_nexitally", "rollback", "custom_read", "custom_apply"}
MAX_JSON_NODES = 20_000
MAX_JSON_DEPTH = 32


def fail(message: str, code: int = 1) -> None:
    print(json.dumps({"ok": False, "message": message}, ensure_ascii=False, separators=(",", ":")))
    raise SystemExit(code)


def json_shape_ok(value: object) -> bool:
    stack = [(value, 0)]
    nodes = 0
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            return False
        if isinstance(node, dict):
            stack.extend((child, depth + 1) for child in node.values())
        elif isinstance(node, list):
            stack.extend((child, depth + 1) for child in node)
    return True


def validate_directory_chain(path: str) -> None:
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        fail("受控 SSH 资产路径无效", 14)
    directory = os.path.dirname(path)
    try:
        while directory != "/":
            info = os.lstat(directory)
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or \
                    info.st_mode & 0o022:
                fail("受控 SSH 资产目录链权限、所有者或类型无效", 14)
            directory = os.path.dirname(directory)
    except OSError:
        fail("受控 SSH 资产目录链缺失", 14)


def validate_asset(path: str, *, maximum: int) -> None:
    try:
        info = os.lstat(path)
    except OSError:
        fail("受控 SSH 资产缺失", 14)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or \
            stat.S_IMODE(info.st_mode) != 0o600 or not 1 <= info.st_size <= maximum:
        fail("受控 SSH 资产权限、所有者、类型或大小无效", 14)
    validate_directory_chain(path)


def limit_child_output() -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX + 1, MAX + 1))


raw = sys.stdin.buffer.read(MAX + 1)
if not raw or len(raw) > MAX:
    fail("请求为空或超过限制", 10)
try:
    request = json.loads(raw)
except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
    fail("请求 JSON 无效", 11)
if not isinstance(request, dict) or not json_shape_ok(request) or request.get("action") not in ALLOWED:
    fail("动作不在白名单", 12)
target = request.get("target")
if target not in TARGETS:
    fail("目标不在白名单", 13)
host, key, known_hosts = TARGETS[target]
validate_asset(key, maximum=16 * 1024)
validate_asset(known_hosts, maximum=64 * 1024)
command = [
    "/usr/bin/ssh", "-F", "/dev/null", "-T", "-q", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
    "-o", "ConnectTimeout=8", "-o", "ConnectionAttempts=1", "-o", "StrictHostKeyChecking=yes",
    "-o", "ProxyCommand=none", "-o", "PermitLocalCommand=no", "-o", "RequestTTY=no",
    "-o", "ClearAllForwardings=yes", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
    "-o", "PreferredAuthentications=publickey", "-o", "PubkeyAuthentication=yes",
    "-o", "HostbasedAuthentication=no", "-o", "GSSAPIAuthentication=no",
    "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
    "-o", "NumberOfPasswordPrompts=0", "-o", "GlobalKnownHostsFile=/dev/null",
    "-o", f"UserKnownHostsFile={known_hosts}", "-i", key, f"root@{host}", "openclash-web-router-v1",
]
try:
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(
            command, input=raw, stdout=output, stderr=subprocess.DEVNULL,
            timeout=330, check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            preexec_fn=limit_child_output,
        )
        output.seek(0)
        response_bytes = output.read(MAX + 1)
except (OSError, subprocess.TimeoutExpired):
    fail("路由器受控操作超时或不可用", 15)
if result.returncode != 0 or not response_bytes or len(response_bytes) > MAX:
    fail("路由器拒绝操作或响应无效", 16)
try:
    response = json.loads(response_bytes)
except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
    fail("路由器响应不是有效 JSON", 17)
if not isinstance(response, dict) or not json_shape_ok(response) or not isinstance(response.get("ok"), bool):
    fail("路由器响应结构无效", 18)
sys.stdout.buffer.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode())
