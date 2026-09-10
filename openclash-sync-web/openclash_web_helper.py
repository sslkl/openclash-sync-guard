#!/usr/bin/env python3
"""WORKER root helper：白名单路由器 forced-command 与固定本机隔离转换入口。"""

from __future__ import annotations

import json
import hashlib
import math
import os
import resource
import stat
import subprocess
import sys
import tempfile

CONVERTER_RUNTIME_ID = "36fcfd654b671426f36171e83bc9e5b5ead8755c9f1b7fb98ef7825dc60d188a"
CONVERTER_SANDBOX_SHA256 = "08706408f2077eed11e0d30df66c752831e99d220617b546a50c287c1ff0468f"
MAX = 2 * 1024 * 1024
TARGETS = {
    "router_a": ("192.0.2.10", "/etc/openclash-web/keys/router_a", "/etc/openclash-web/known_hosts"),
    "router_b": ("192.0.2.11", "/etc/openclash-web/keys/router_b", "/etc/openclash-web/known_hosts"),
}
ALLOWED = {"status", "read", "write", "stage_main", "update_maying", "update_nexitally", "rollback", "custom_read", "custom_preview", "custom_apply", "route_check", "chain_read", "chain_apply", "chain_test", "converter_run", "converter_apply"}
MAX_JSON_NODES = 20_000
MAX_JSON_DEPTH = 32


def fail(message: str, code: int = 1) -> None:
    print(json.dumps({"ok": False, "message": message}, ensure_ascii=False, separators=(",", ":")))
    raise SystemExit(code)


def unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate members rather than allow different parsers to disagree."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def json_shape_ok(value: object) -> bool:
    stack = [(value, 0)]
    nodes = 0
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            return False
        if isinstance(node, dict):
            try:
                for key in node:
                    key.encode("utf-8")
            except (AttributeError, UnicodeError):
                return False
            stack.extend((child, depth + 1) for child in node.values())
        elif isinstance(node, list):
            stack.extend((child, depth + 1) for child in node)
        elif isinstance(node, str):
            try:
                node.encode("utf-8")
            except UnicodeError:
                return False
        elif isinstance(node, float) and not math.isfinite(node):
            return False
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


def run_converter(request: dict) -> None:
    # A separate local action: never fall through to SSH or accept a target.
    if set(request) != {"action", "job"} or not isinstance(request["job"], dict):
        fail("隔离转换请求结构无效", 12)
    path = f"/opt/openclash-sync-converter/{CONVERTER_RUNTIME_ID}/converter_sandbox.py"
    result = {"ok": False, "code": "SANDBOX_UNAVAILABLE", "router_changed": False}
    try:
        info = os.lstat(path)
        if os.geteuid() != 0 or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or \
                stat.S_IMODE(info.st_mode) != 0o444 or info.st_nlink != 1 or not 1 <= info.st_size <= 128 * 1024:
            raise ValueError
        validate_directory_chain(path)
        # The root runner is independently pinned, not loaded from the web cwd.
        with open(path, "rb") as source:
            if hashlib.sha256(source.read(128 * 1024 + 1)).hexdigest() != CONVERTER_SANDBOX_SHA256:
                raise ValueError
        with tempfile.TemporaryFile() as output:
            process = subprocess.run(
                ["/usr/bin/python3", "-I", "-B", path],
                input=json.dumps(request["job"], ensure_ascii=False, separators=(",", ":")).encode(),
                stdout=output, stderr=subprocess.DEVNULL, timeout=65, check=False,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}, preexec_fn=limit_child_output,
            )
            output.seek(0)
            raw_result = output.read(MAX + 1)
        if process.returncode or not raw_result or len(raw_result) > MAX:
            raise ValueError
        candidate = json.loads(raw_result, object_pairs_hook=unique_json_object)
        if not isinstance(candidate, dict) or not json_shape_ok(candidate) or type(candidate.get("ok")) is not bool:
            raise ValueError
        result = candidate  # Web validates the exact success/error shape and digest.
    except subprocess.TimeoutExpired:
        result = {"ok": False, "code": "SANDBOX_CLEANUP", "router_changed": False}
    except (OSError, ValueError, RecursionError):
        pass
    sys.stdout.buffer.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode())
    raise SystemExit(0)


raw = sys.stdin.buffer.read(MAX + 1)
if not raw or len(raw) > MAX:
    fail("请求为空或超过限制", 10)
try:
    request = json.loads(raw, object_pairs_hook=unique_json_object)
except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
    fail("请求 JSON 无效", 11)
if not isinstance(request, dict) or not json_shape_ok(request) or not isinstance(request.get("action"), str) or request["action"] not in ALLOWED:
    fail("动作不在白名单", 12)
if request["action"] == "converter_run":
    run_converter(request)
target = request.get("target")
if not isinstance(target, str) or target not in TARGETS:
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
            timeout=410, check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            preexec_fn=limit_child_output,
        )
        output.seek(0)
        response_bytes = output.read(MAX + 1)
except (OSError, subprocess.TimeoutExpired):
    fail("路由器受控操作超时或不可用", 15)
if not response_bytes or len(response_bytes) > MAX:
    fail("路由器拒绝操作或响应无效", 16)
try:
    response = json.loads(response_bytes, object_pairs_hook=unique_json_object)
except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
    fail("路由器响应不是有效 JSON", 17)
if not isinstance(response, dict) or not json_shape_ok(response) or not isinstance(response.get("ok"), bool):
    fail("路由器响应结构无效", 18)
# OpenClash 重启可能在 forced-command 已完整写出结果后重置 SSH
# 会话，使 ssh 尾部状态非零。响应仍只能来自通过严格 host key
# 验证的 forced-command；只在完整、有界且结构合法时接受它。
sys.stdout.buffer.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode())
