#!/usr/bin/env python3
"""OpenClash 同步器中文管理台（WORKER 本地 Web 服务）。"""

from __future__ import annotations

import hashlib
import hmac
import io
import ipaddress
import json
import math
import os
import re
import secrets
import stat
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DEFAULT_VENDORED_PYYAML = ROOT.parent / "vendor" / "pyyaml-6.0.2"
VENDORED_PYYAML = Path(os.environ.get("OPENCLASH_WEB_PYYAML_ROOT", str(DEFAULT_VENDORED_PYYAML)))
if not VENDORED_PYYAML.is_absolute() or not VENDORED_PYYAML.is_dir():
    raise RuntimeError("vendored PyYAML directory is required")
VENDORED_PYYAML = VENDORED_PYYAML.resolve(strict=True)
# Runtime dependencies are an immutable, content-addressed release. The app and
# helper pin the same ID; rolling back either app version restores its old pin.
CONVERTER_RUNTIME_ID = "36fcfd654b671426f36171e83bc9e5b5ead8755c9f1b7fb98ef7825dc60d188a"
CONVERTER_FILES = ("converter_apply.py", "converter_engine.py", "converter_fetch.py", "converter_formats.py",
                   "converter_mellow.py", "converter_services.py", "converter_sandbox.py", "converter_surge.py",
                   "static/converter.js", "static/converter_apply.js", "static/converter_services.js",
                   "subscription_converter.py")
CONVERTER_ROOT = ROOT if ROOT != Path("/opt/openclash-sync-web") and (ROOT / "subscription_converter.py").is_file() else \
    Path("/opt/openclash-sync-converter") / CONVERTER_RUNTIME_ID


def verify_converter_runtime(root: Path, expected: str) -> None:
    """Authenticate all code bytes before any import; no executable manifest."""
    current = root
    while True:
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or (info.st_uid, info.st_gid) != (0, 0) or info.st_mode & 0o022:
            raise RuntimeError("untrusted converter directory")
        if current.parent == current:
            break
        current = current.parent
    manifest = []
    seen = set()
    for directory, dirs, names in os.walk(root, followlinks=False):
        path = Path(directory)
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or (info.st_uid, info.st_gid) != (0, 0) or stat.S_IMODE(info.st_mode) != 0o555:
            raise RuntimeError("invalid converter release directory")
        if any((path / child).relative_to(root).as_posix() != "static" for child in dirs):
            raise RuntimeError("unexpected converter directory")
        seen.update((path / name).relative_to(root).as_posix() for name in names)
    if seen != set(CONVERTER_FILES) | {"SHA256SUMS"}:
        raise RuntimeError("invalid converter release files")
    for name in sorted(CONVERTER_FILES) + ["SHA256SUMS"]:
        path = root / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or (info.st_uid, info.st_gid) != (0, 0) or \
                stat.S_IMODE(info.st_mode) != 0o444 or info.st_nlink != 1 or not 1 <= info.st_size <= 2 * 1024 * 1024:
            raise RuntimeError("untrusted converter asset")
        body = path.read_bytes()
        if name == "SHA256SUMS":
            if body != "".join(manifest).encode() or hashlib.sha256(body).hexdigest() != expected:
                raise RuntimeError("converter release digest mismatch")
        else:
            manifest.append(f"{hashlib.sha256(body).hexdigest()}  {name}\n")


if CONVERTER_ROOT != ROOT:
    verify_converter_runtime(CONVERTER_ROOT, CONVERTER_RUNTIME_ID)
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(CONVERTER_ROOT))
sys.path.insert(0, str(VENDORED_PYYAML))

import subscription_converter as converter  # noqa: E402
import converter_engine  # noqa: E402
import converter_formats  # noqa: E402
import converter_apply  # noqa: E402
import converter_services  # noqa: E402

import yaml  # noqa: E402 - the pinned vendor directory must be inserted first
from yaml.constructor import ConstructorError  # noqa: E402

if yaml.__version__ != "6.0.2" or VENDORED_PYYAML not in Path(yaml.__file__).resolve(strict=True).parents:
    raise RuntimeError("PyYAML 6.0.2 is required")
STATIC = ROOT / "static"
MAX_BODY = 2 * 1024 * 1024
MAX_CONFIG = 1024 * 1024
MAX_YAML_NODES = 100_000
MAX_YAML_DEPTH = 64
NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
MAIN_CONFIG_NAME = "ProviderBase-ProviderSource.yaml"
ROLLBACK_PHRASE = "确认回滚主配置"
AUTH_REALM = "OpenClash Sync"
AUTH_USER = os.environ.get("OPENCLASH_WEB_AUTH_USER", "")
AUTH_HA1_FILE = os.environ.get("OPENCLASH_WEB_AUTH_HA1_FILE", "")
AUTH_REQUIRED = bool(AUTH_USER and AUTH_HA1_FILE)
ALLOWED_HOSTS = {item.strip() for item in os.environ.get(
    "OPENCLASH_WEB_ALLOWED_HOSTS", "127.0.0.1:8088,localhost:8088"
).lower().split(",") if item.strip()}


def parse_allowed_origins(raw: str, allowed_hosts: set[str]) -> set[str]:
    origins: set[str] = set()
    for item in raw.split(","):
        value = item.strip()
        if not value:
            continue
        parsed = urlparse(value)
        try:
            valid_port = parsed.port is not None or parsed.hostname is not None
        except ValueError as exc:
            raise RuntimeError("OPENCLASH_WEB_ALLOWED_ORIGINS 端口无效") from exc
        normalized_host = parsed.netloc.lower()
        if parsed.scheme.lower() not in {"http", "https"} or not valid_port or parsed.username is not None or \
                parsed.password is not None or parsed.path or parsed.params or parsed.query or parsed.fragment or \
                normalized_host not in allowed_hosts:
            raise RuntimeError("OPENCLASH_WEB_ALLOWED_ORIGINS 必须是与 ALLOWED_HOSTS 对应的纯 HTTP(S) Origin")
        origins.add(f"{parsed.scheme.lower()}://{normalized_host}")
    if not origins:
        raise RuntimeError("OPENCLASH_WEB_ALLOWED_ORIGINS 不能为空")
    return origins


ALLOWED_NETWORKS = tuple(ipaddress.ip_network(item.strip()) for item in os.environ.get(
    "OPENCLASH_WEB_ALLOWED_NETWORKS", "127.0.0.0/8,::1/128"
).split(",") if item.strip())
ALLOWED_ORIGINS = parse_allowed_origins(
    os.environ.get("OPENCLASH_WEB_ALLOWED_ORIGINS", ",".join(f"http://{host}" for host in ALLOWED_HOSTS)),
    ALLOWED_HOSTS,
)
LAN_BIND_ADDRESS = ipaddress.ip_address("192.0.2.20")
RENDERED_LAN_NETWORKS = "192.0.2.0/24,127.0.0.0/8"
LAN_CLIENT_NETWORKS = frozenset(
    ipaddress.ip_network(item) for item in RENDERED_LAN_NETWORKS.split(",")
)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$", re.IGNORECASE)
CUSTOM_RULE_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "IP-CIDR", "IP-CIDR6"}
CUSTOM_RULE_ORDER = {name: index for index, name in enumerate(("DOMAIN", "DOMAIN-SUFFIX", "IP-CIDR", "IP-CIDR6"))}
MAX_CUSTOM_ITEMS = 256
MAX_SUPPLEMENT_ITEMS = 10_000
MAX_EXACT_ITEM = 8192
MAX_AUTH_NONCES = 1024
MAX_AUTH_REPLAY = 4096
MAX_AUTH_FAILURE_CLIENTS = 1024
MAX_OPERATION_NONCES = 1024
MAX_JSON_NODES = 20_000
MAX_JSON_DEPTH = 32
MAX_HTTP_THREADS = 32
HTTP_READ_TIMEOUT = 30.0
HTTP_SOCKET_TIMEOUT = 30.0


@dataclass(frozen=True)
class Target:
    id: str
    name: str
    address: str


TARGETS = {
    "router_a": Target("router_a", "路由器 A", "192.0.2.10"),
    "router_b": Target("router_b", "路由器 B", "192.0.2.11"),
}


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
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
            if any(not isinstance(key, str) for key in node):
                return False
            try:
                for key in node:
                    key.encode("utf-8")
            except UnicodeError:
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


def bridge_result_ok(request: dict[str, Any], result: dict[str, Any]) -> bool:
    if not json_shape_ok(result) or not isinstance(result.get("ok"), bool):
        return False
    if request.get("action") == "converter_run":
        target = request.get("job", {}).get("options", {}).get("target")
        return converter_engine.result_ok(result, target) if result["ok"] else converter_engine.failure_ok(result)
    message = result.get("message")
    if message is not None and (not isinstance(message, str) or len(message.encode()) > 8192 or "\0" in message):
        return False
    if not result["ok"]:
        return isinstance(message, str)
    action = request.get("action")
    target = request.get("target")
    if action in {"chain_read", "chain_apply", "chain_test"}:
        return chain_result_ok(request, result)
    if action == "status":
        items = result.get("targets")
        if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict) or target not in TARGETS:
            return False
        item = items[0]
        expected = TARGETS[target]
        return item.get("id") == target and item.get("name") == expected.name and \
            item.get("address") == expected.address and all(
                isinstance(item.get(field), str) and 1 <= len(item[field].encode()) <= 256
                for field in ("state", "active")
            )
    if action == "read":
        return isinstance(result.get("content"), str) and len(result["content"].encode()) <= MAX_CONFIG and \
            isinstance(result.get("sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", result["sha256"]) is not None
    if action == "custom_read":
        if not all(isinstance(result.get(field), list) for field in (
            "groups", "rules", "fake_ip_filter", "owned_rules", "owned_fake_ip_filter",
            "supplemental_rules", "supplemental_fake_ip_filter", "owned_supplemental_rules",
            "owned_supplemental_fake_ip_filter", "configured_rules", "configured_fake_ip_filter",
        )):
            return False
        for field in ("rules", "owned_rules"):
            if len(result[field]) > MAX_CUSTOM_ITEMS or not all(
                isinstance(rule, dict) and set(rule) == {"type", "value", "policy"} and
                all(isinstance(rule[key], str) and rule[key] and not re.search(r"[\t\r\n\0]", rule[key])
                    for key in ("type", "value", "policy")) for rule in result[field]
            ):
                return False
        for field in ("groups", "fake_ip_filter", "owned_fake_ip_filter", "supplemental_rules",
                      "supplemental_fake_ip_filter", "owned_supplemental_rules",
                      "owned_supplemental_fake_ip_filter", "configured_rules", "configured_fake_ip_filter"):
            if not all(isinstance(item, str) and not re.search(r"[\t\r\n\0]", item) for item in result[field]):
                return False
            if field in {"fake_ip_filter", "owned_fake_ip_filter"} and len(result[field]) > MAX_CUSTOM_ITEMS:
                return False
            if "supplemental" in field and (len(result[field]) > MAX_SUPPLEMENT_ITEMS or
                    any(not 1 <= len(item.encode()) <= MAX_EXACT_ITEM for item in result[field])):
                return False
        if any(not name or "," in name for name in result["groups"]) or \
                len(set(result["groups"])) != len(result["groups"]):
            return False
        return all(isinstance(result.get(field), str) and re.fullmatch(r"[0-9a-f]{64}", result[field]) is not None
                   for field in ("state_sha256", "config_sha256"))
    if action == "route_check":
        return all(isinstance(result.get(field), str) for field in ("mode", "reachability", "certainty")) and \
            result["mode"] in {"DIRECT", "PROXY", "REJECT", "UNKNOWN"} and \
            result["reachability"] in {"REACHABLE", "UNREACHABLE", "BLOCKED", "UNKNOWN"} and \
            result["certainty"] in {"EXACT", "CONTEXTUAL", "UNKNOWN"} and all(
                isinstance(result.get(field), str) and 1 <= len(result[field].encode()) <= 256
                for field in ("policy", "rule_type")
            )
    if action == "converter_apply":
        return all(isinstance(result.get(field), str) and re.fullmatch(r"[0-9a-f]{64}", result[field]) is not None
                   for field in ("sha256", "state_sha256")) and \
            isinstance(result.get("service_restarted"), bool) and \
            isinstance(result.get("runtime_verified"), bool) and \
            result["runtime_verified"] == result["service_restarted"]
    if action == "stage_main":
        if not isinstance(result.get("sha256"), str) or re.fullmatch(r"[0-9a-f]{64}", result["sha256"]) is None or \
                not isinstance(result.get("service_restarted"), bool):
            return False
        health = result.get("node_health")
        if not isinstance(health, dict) or set(health) != {"maying", "nexitally"}:
            return False
        for provider in health.values():
            if not isinstance(provider, dict) or set(provider) != {"passed", "total"}:
                return False
            passed, total = provider["passed"], provider["total"]
            if isinstance(passed, bool) or isinstance(total, bool) or not isinstance(passed, int) or \
                    not isinstance(total, int) or not 0 <= passed <= total <= 100_000:
                return False
    return True


def root_owned_directory_chain(directory: Path) -> bool:
    if not directory.is_absolute() or ".." in directory.parts:
        return False
    current = directory
    try:
        while current != current.parent:
            info = current.lstat()
            if current.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                return False
            current = current.parent
    except OSError:
        return False
    return True


def auth_directory_chain_ok(directory: Path) -> bool:
    if not directory.is_absolute() or ".." in directory.parts:
        return False
    allowed_owners = {0, os.geteuid()}
    current = directory
    try:
        while True:
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or \
                    info.st_uid not in allowed_owners or info.st_mode & 0o022:
                return False
            if current == current.parent:
                return True
            current = current.parent
    except OSError:
        return False


def yaml_error(exc: yaml.YAMLError) -> dict[str, Any]:
    mark = getattr(exc, "problem_mark", None)
    problem = getattr(exc, "problem", None) or "YAML 语法不正确"
    return {
        "ok": False,
        "message": f"YAML 语法错误：{problem}",
        "line": mark.line + 1 if mark else None,
        "column": mark.column + 1 if mark else None,
    }


class StrictSafeLoader(converter_formats.BoundedSafeLoader):
    """Bound parsing and reject mapping keys PyYAML would silently overwrite."""
    max_tokens = MAX_YAML_NODES * 4
    max_nodes = MAX_YAML_NODES
    max_depth = MAX_YAML_DEPTH

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[str, Any]:
        mapping: dict[str, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise ConstructorError("while constructing a mapping", node.start_mark,
                                       "mapping key must be text", key_node.start_mark)
            if key in mapping:
                raise ConstructorError("while constructing a mapping", node.start_mark,
                                       f"duplicate mapping key: {key}", key_node.start_mark)
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def validate_yaml(content: str) -> dict[str, Any]:
    if not content.strip():
        return {"ok": False, "message": "配置内容不能为空", "line": 1, "column": 1}
    try:
        encoded = content.encode("utf-8")
    except UnicodeError:
        return {"ok": False, "message": "配置包含无效 Unicode 字符", "line": 1, "column": 1}
    if len(encoded) > MAX_CONFIG:
        return {"ok": False, "message": "配置超过 1 MiB 限制", "line": None, "column": None}
    try:
        # Budgets/anchors are rejected in the same pass before construction.
        parsed = yaml.load(content, Loader=StrictSafeLoader)  # nosec B506
    except yaml.YAMLError as exc:
        return yaml_error(exc)
    except (RecursionError, ValueError, UnicodeError):
        return {"ok": False, "message": "YAML 结构过深或编码无效", "line": 1, "column": 1}
    if not isinstance(parsed, dict):
        return {"ok": False, "message": "顶层必须是 YAML 映射（key: value）", "line": 1, "column": 1}
    stack = [(parsed, 1)]
    seen: set[int] = set()
    nodes = 0
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if nodes > MAX_YAML_NODES or depth > MAX_YAML_DEPTH:
            return {"ok": False, "message": "YAML 结构过深或项目过多", "line": 1, "column": 1}
        if isinstance(node, (dict, list)):
            identity = id(node)
            if identity in seen:
                return {"ok": False, "message": "YAML 不允许循环引用或重复容器别名", "line": 1, "column": 1}
            seen.add(identity)
            children = list(node.values()) if isinstance(node, dict) else node
            stack.extend((child, depth + 1) for child in children)
    required = ("proxies", "proxy-groups", "rules")
    missing = [key for key in required if key not in parsed]
    if missing:
        return {"ok": False, "message": f"缺少必要字段：{', '.join(missing)}", "line": 1, "column": 1}
    for key in required:
        if not isinstance(parsed[key], list):
            return {"ok": False, "message": f"字段 {key} 必须是列表（以 - 开头）", "line": 1, "column": 1}
    digest = hashlib.sha256(content.encode()).hexdigest()
    return {
        "ok": True,
        "message": "YAML 语法与基础结构检查通过",
        "sha256": digest,
        "summary": {
            "proxies": len(parsed["proxies"]),
            "groups": len(parsed["proxy-groups"]),
            "rules": len(parsed["rules"]),
        },
    }


def valid_rollback_phrase(value: str) -> bool:
    return hmac.compare_digest(value.encode("utf-8"), ROLLBACK_PHRASE.encode("utf-8"))


def read_auth_ha1() -> dict[str, str]:
    if not AUTH_REQUIRED:
        return {}
    try:
        path = Path(AUTH_HA1_FILE)
        before = path.lstat()
        if not path.is_absolute() or stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or \
                before.st_uid not in {0, os.geteuid()} or before.st_nlink != 1 or \
                not 1 <= before.st_size <= 128 or stat.S_IMODE(before.st_mode) not in {0o400, 0o440, 0o600, 0o640} or \
                not auth_directory_chain_ok(path.parent):
            raise RuntimeError("Web 登录认证摘要文件权限或类型无效")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            def identity(info: os.stat_result) -> tuple[int, ...]:
                return (
                    info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
                )
            if identity(opened) != identity(before):
                raise RuntimeError("Web 登录认证摘要在打开时发生变化")
            data = bytearray()
            while len(data) <= 128:
                chunk = os.read(descriptor, 129 - len(data))
                if not chunk:
                    break
                data.extend(chunk)
        finally:
            os.close(descriptor)
        after = path.lstat()
        if identity(after) != identity(before) or len(data) != before.st_size:
            raise RuntimeError("Web 登录认证摘要在读取时发生变化")
        lines = bytes(data).decode("ascii").splitlines()
    except OSError as exc:
        raise RuntimeError("无法读取 Web 登录认证摘要") from exc
    except UnicodeError as exc:
        raise RuntimeError("Web 登录认证摘要必须为 ASCII") from exc
    if len(lines) == 1 and re.fullmatch(r"[0-9a-f]{64}", lines[0].lower()):
        return {"SHA-256": lines[0].lower()}
    values: dict[str, str] = {}
    for line in lines:
        if line.startswith("sha256:") and re.fullmatch(r"[0-9a-f]{64}", line[7:].lower()):
            if "SHA-256" in values:
                raise RuntimeError("Web 登录认证摘要包含重复 SHA-256")
            values["SHA-256"] = line[7:].lower()
        elif line.startswith("md5:") and re.fullmatch(r"[0-9a-f]{32}", line[4:].lower()):
            if "MD5" in values:
                raise RuntimeError("Web 登录认证摘要包含重复 MD5")
            values["MD5"] = line[4:].lower()
        else:
            raise RuntimeError("Web 登录认证摘要格式无效")
    if "SHA-256" not in values:
        raise RuntimeError("Web 登录认证摘要缺少 SHA-256")
    return values


def normalize_domain(value: str) -> str | None:
    normalized = value.strip().lower().removesuffix(".")
    return normalized if DOMAIN_RE.fullmatch(normalized) else None


def normalize_fake_filter(value: str) -> str | None:
    normalized = value.strip().lower().removesuffix(".")
    prefix = ""
    if normalized.startswith(("*.", "+.")):
        prefix, normalized = normalized[:2], normalized[2:]
    domain = normalize_domain(normalized)
    return prefix + domain if domain else None


def custom_rule_sort_key(rule: dict[str, str]) -> tuple[int, str, str]:
    kind = rule["type"]
    value = rule["value"]
    if kind == "DOMAIN-SUFFIX":
        value_key = f"{999 - value.count('.'):03d}:{value.casefold()}"
    elif kind.startswith("IP-"):
        network = ipaddress.ip_network(value)
        value_key = f"{int(network.network_address):039d}:{999 - network.prefixlen:03d}"
    else:
        value_key = value.casefold()
    return (CUSTOM_RULE_ORDER[kind], value_key, rule["policy"].casefold())


def fake_filter_sort_key(value: str) -> tuple[str, int, str]:
    if value.startswith("*."):
        prefix, domain = 1, value[2:]
    elif value.startswith("+."):
        prefix, domain = 2, value[2:]
    else:
        prefix, domain = 0, value
    return (domain.casefold(), prefix, value.casefold())


def custom_rule_identity(rule: dict[str, str]) -> tuple[str, str, str]:
    return (rule["type"], rule["value"], rule["policy"])


CUSTOM_POLICY_INVALID = re.compile(r"[\x00-\x1f\x7f-\x9f\ud800-\udfff,]")


def valid_custom_policy(policy: str) -> bool:
    """One policy contract for API validation and configured-rule replay."""
    return bool(policy) and not CUSTOM_POLICY_INVALID.search(policy) and len(policy.encode("utf-8")) <= 128


def normalize_configured_rule(kind: str, raw: str, policy: str) -> dict[str, str] | None:
    """Fast-path one configured rule without invoking whole-state validation."""
    kind = kind.strip().upper()
    raw = raw.strip()
    policy = policy.strip()
    if kind not in CUSTOM_RULE_TYPES or not valid_custom_policy(policy):
        return None
    if kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
        normalized = normalize_domain(raw)
        if normalized is None:
            return None
    else:
        try:
            if kind == "IP-CIDR6" and "." in raw:
                return None
            network = ipaddress.ip_network(raw if "/" in raw else raw + ("/128" if ":" in raw else "/32"),
                                           strict=False)
            if kind == "IP-CIDR" and network.version != 4 or kind == "IP-CIDR6" and network.version != 6:
                return None
            normalized = str(network)
        except ValueError:
            return None
    return {"type": kind, "value": normalized, "policy": policy}


def configured_rule_matcher(value: str) -> tuple[str, str] | None:
    fields = value.split(",")
    if len(fields) < 3 or fields[0].upper() not in CUSTOM_RULE_TYPES:
        return None
    rule = normalize_configured_rule(fields[0], fields[1], fields[2])
    if rule is None:
        return None
    return (rule["type"], rule["value"])


def configured_replayable_rule_matcher(value: str) -> tuple[str, str] | None:
    """Return a matcher only when the exact rule can pass the Ruby replay path."""
    fields = value.split(",")
    matcher = configured_rule_matcher(value)
    if matcher is None or any(field != field.strip() for field in fields[:3]):
        return None
    return matcher


def configured_manageable_rule(value: str) -> dict[str, str] | None:
    fields = value.split(",")
    if len(fields) != 3 or fields[0] not in CUSTOM_RULE_TYPES:
        return None
    rule = normalize_configured_rule(fields[0], fields[1], fields[2])
    if rule is None:
        return None
    return rule if f"{rule['type']},{rule['value']},{rule['policy']}" == value else None


def analyze_custom_ownership(result: dict[str, Any]) -> dict[str, Any] | None:
    owned_rules = result.get("owned_rules")
    owned_filters = result.get("owned_fake_ip_filter")
    owned_supplemental_rules = result.get("owned_supplemental_rules", [])
    owned_supplemental_filters = result.get("owned_supplemental_fake_ip_filter", [])
    configured_rules = result.get("configured_rules")
    configured_filters = result.get("configured_fake_ip_filter")
    if not isinstance(owned_rules, list) or not isinstance(owned_filters, list) or \
            not isinstance(owned_supplemental_rules, list) or not isinstance(owned_supplemental_filters, list) or \
            not isinstance(configured_rules, list) or not isinstance(configured_filters, list):
        return None
    normalized_owned_rules: list[dict[str, str]] = []
    normalized_owned_filters: list[str] = []
    for item in owned_rules:
        checked_item = validate_customization({"rules": [item], "fake_ip_filter": []})
        if not checked_item["ok"]:
            return None
        normalized_owned_rules.append(checked_item["rules"][0])
    for item in owned_filters:
        checked_item = validate_customization({"rules": [], "fake_ip_filter": [item]})
        if not checked_item["ok"]:
            return None
        normalized_owned_filters.append(checked_item["fake_ip_filter"][0])
    if not all(isinstance(item, str) for item in owned_supplemental_rules + owned_supplemental_filters):
        return None
    if len({custom_rule_identity(rule) for rule in normalized_owned_rules}) != len(normalized_owned_rules) or \
            len(set(normalized_owned_filters)) != len(normalized_owned_filters):
        return None
    owned_text = [f"{rule['type']},{rule['value']},{rule['policy']}" for rule in normalized_owned_rules] + \
        list(owned_supplemental_rules)
    if configured_rules[:len(owned_text)] != owned_text:
        return None
    remaining_rules = list(configured_rules[len(owned_text):])
    remaining_filters = list(configured_filters)
    for item in normalized_owned_filters:
        try:
            remaining_filters.remove(item)
        except ValueError:
            return None
    for item in owned_supplemental_filters:
        try:
            remaining_filters.remove(item)
        except ValueError:
            return None
    managed = validate_customization({
        "rules": result.get("rules", []), "fake_ip_filter": result.get("fake_ip_filter", []),
        "supplemental_rules": result.get("supplemental_rules", []),
        "supplemental_fake_ip_filter": result.get("supplemental_fake_ip_filter", []),
    })
    if not managed["ok"]:
        return None
    managed_identities = {custom_rule_identity(rule) for rule in managed["rules"]}
    managed_text = {f"{rule['type']},{rule['value']},{rule['policy']}" for rule in managed["rules"]}
    if not all(custom_rule_identity(rule) in managed_identities for rule in normalized_owned_rules) or \
            not set(normalized_owned_filters).issubset(set(managed["fake_ip_filter"])) or \
            not set(owned_supplemental_rules).issubset(set(managed["supplemental_rules"])) or \
            not set(owned_supplemental_filters).issubset(set(managed["supplemental_fake_ip_filter"])):
        return None
    missing_rules = sorted((managed_text | set(managed["supplemental_rules"])) - set(configured_rules))
    missing_filters = sorted((set(managed["fake_ip_filter"]) | set(managed["supplemental_fake_ip_filter"])) - set(configured_filters))
    return {"owned_rules": normalized_owned_rules, "owned_filters": normalized_owned_filters,
            "owned_supplemental_rules": list(owned_supplemental_rules),
            "owned_supplemental_filters": list(owned_supplemental_filters),
            "unowned_rules": remaining_rules, "unowned_filters": remaining_filters,
            "missing_rules": missing_rules, "missing_filters": missing_filters}


def merge_custom_reads(results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    common_groups: set[str] | None = None
    ordered_groups: list[str] = []
    rules: dict[tuple[str, str], dict[str, str]] = {}
    filters: set[str] = set()
    supplemental_rules: dict[tuple[str, str], str] = {}
    supplemental_filters: set[str] = set()
    state_sha256: dict[str, str] = {}
    config_sha256: dict[str, str] = {}
    normalized_by_target: dict[str, tuple[list[dict[str, str]], list[str], list[str], list[str]]] = {}
    editable_rule_identities: set[tuple[str, str, str]] = set()
    editable_filter_keys: set[str] = set()
    configured_rules: set[str] = set()
    configured_filters: set[str] = set()
    configured_counts: dict[str, dict[str, int]] = {}
    unowned_configured_rules: set[str] = set()
    unowned_configured_filters: set[str] = set()
    unowned_rules_by_target: dict[str, list[str]] = {}
    unowned_filters_by_target: dict[str, list[str]] = {}
    missing_managed_by_target: dict[str, dict[str, list[str]]] = {}
    conflicts: list[str] = []
    for target in TARGETS:
        result = results[target]
        target_groups = result.get("groups")
        target_rules = result.get("rules")
        target_filters = result.get("fake_ip_filter")
        target_supplemental_rules = result.get("supplemental_rules", [])
        target_supplemental_filters = result.get("supplemental_fake_ip_filter", [])
        target_configured_rules = result.get("configured_rules", [])
        target_configured_filters = result.get("configured_fake_ip_filter", [])
        target_state = result.get("state_sha256")
        # Direct unit callers and rolling local fixtures may omit this field;
        # the bridge schema rejects such a response before production merge.
        target_config = result.get("config_sha256", target_state)
        if not isinstance(target_groups, list) or not all(isinstance(item, str) for item in target_groups) or \
                not isinstance(target_rules, list) or not isinstance(target_filters, list) or \
                not isinstance(target_supplemental_rules, list) or not isinstance(target_supplemental_filters, list) or \
                not isinstance(target_configured_rules, list) or not all(isinstance(item, str) for item in target_configured_rules) or \
                not isinstance(target_configured_filters, list) or not all(isinstance(item, str) for item in target_configured_filters) or \
                not isinstance(target_state, str) or not re.fullmatch(r"[0-9a-f]{64}", target_state) or \
                not isinstance(target_config, str) or not re.fullmatch(r"[0-9a-f]{64}", target_config):
            return {"ok": False, "message": f"{TARGETS[target].name} 返回的定制状态格式无效"}
        ownership = analyze_custom_ownership(result)
        if ownership is None:
            return {"ok": False, "message": f"{TARGETS[target].name} 返回的定制所有权或完整配置不一致"}
        group_set = set(target_groups)
        common_groups = group_set if common_groups is None else common_groups & group_set
        if not ordered_groups:
            ordered_groups = list(target_groups)
        checked = validate_customization({"rules": target_rules, "fake_ip_filter": target_filters,
                                          "supplemental_rules": target_supplemental_rules,
                                          "supplemental_fake_ip_filter": target_supplemental_filters})
        if not checked["ok"]:
            return {"ok": False, "message": f"{TARGETS[target].name} 的现有定制内容未通过语法检查"}
        for rule in checked["rules"]:
            editable_rule_identities.add(custom_rule_identity(rule))
            key = (rule["type"], rule["value"])
            previous = rules.get(key)
            if key in supplemental_rules:
                conflicts.append(f"{rule['type']} {rule['value']}")
            elif previous is not None and previous["policy"] != rule["policy"]:
                conflicts.append(f"{rule['type']} {rule['value']}")
            else:
                rules[key] = rule
        filters.update(checked["fake_ip_filter"])
        editable_filter_keys.update(checked["fake_ip_filter"])
        for item in checked["supplemental_rules"]:
            matcher = configured_replayable_rule_matcher(item)
            if matcher is None:
                return {"ok": False, "message": f"{TARGETS[target].name} 的完整规则补齐项格式无效"}
            previous = supplemental_rules.get(matcher)
            if previous is not None and previous != item:
                conflicts.append(f"{matcher[0]} {matcher[1]}")
            elif matcher in rules:
                conflicts.append(f"{matcher[0]} {matcher[1]}")
            else:
                supplemental_rules[matcher] = item
        supplemental_filters.update(checked["supplemental_fake_ip_filter"])
        configured_rules.update(target_configured_rules)
        configured_filters.update(target_configured_filters)
        unowned_configured_rules.update(ownership["unowned_rules"])
        unowned_configured_filters.update(ownership["unowned_filters"])
        unowned_rules_by_target[target] = list(ownership["unowned_rules"])
        unowned_filters_by_target[target] = list(ownership["unowned_filters"])
        missing_managed_by_target[target] = {
            "rules": list(ownership["missing_rules"]), "fake_ip_filter": list(ownership["missing_filters"])
        }
        configured_counts[target] = {"rules": len(target_configured_rules), "fake_ip_filter": len(target_configured_filters)}
        normalized_by_target[target] = (checked["rules"], checked["fake_ip_filter"],
                                        checked["supplemental_rules"], checked["supplemental_fake_ip_filter"])
        state_sha256[target] = target_state
        config_sha256[target] = target_config
    if conflicts:
        return {"ok": False, "message": "两个子网对相同匹配条件配置了不同策略，必须先人工确认：" + "、".join(sorted(set(conflicts)))}

    # Import only asymmetric baseline entries that the managed-state format
    # can reproduce byte-for-byte. Common subscription rules stay unowned and
    # are never copied or reordered. This turns a safe one-sided DOMAIN/IP or
    # Fake-IP item into an explicit save-time repair without claiming ownership
    # of the thousands of common subscription entries.
    imported_rules = 0
    imported_filters = 0
    imported_supplemental_rules = 0
    imported_supplemental_filters = 0
    unresolved_rules = 0
    unresolved_filters = 0
    rule_sets = {target: set(unowned_rules_by_target[target]) for target in TARGETS}
    filter_sets = {target: set(unowned_filters_by_target[target]) for target in TARGETS}
    all_unowned_rules = set().union(*rule_sets.values())
    all_unowned_filters = set().union(*filter_sets.values())
    asymmetric_rules = {
        item for item in all_unowned_rules if any(item not in rule_sets[target] for target in TARGETS)
    }
    asymmetric_filters = {
        item for item in all_unowned_filters if any(item not in filter_sets[target] for target in TARGETS)
    }
    matcher_forms: dict[tuple[str, str], set[str]] = {}
    for item in configured_rules:
        matcher = configured_rule_matcher(item)
        if matcher is not None:
            matcher_forms.setdefault(matcher, set()).add(item)
    filter_forms: dict[str, set[str]] = {}
    for item in configured_filters:
        normalized = normalize_fake_filter(item)
        if normalized is not None:
            filter_forms.setdefault(normalized, set()).add(item)
    baseline_conflicts: list[str] = []
    for item in sorted(asymmetric_rules):
        rule = configured_manageable_rule(item)
        matcher = configured_rule_matcher(item)
        if matcher is None:
            unresolved_rules += 1
            continue
        key = matcher
        if len(matcher_forms.get(key, set())) != 1:
            baseline_conflicts.append(f"{key[0]} {key[1]}")
            continue
        if rule is not None:
            previous = rules.get(key)
            if key in supplemental_rules or previous is not None and previous["policy"] != rule["policy"]:
                baseline_conflicts.append(f"{rule['type']} {rule['value']}")
            elif previous is None:
                rules[key] = rule
                imported_rules += 1
        else:
            replayable_matcher = configured_replayable_rule_matcher(item)
            if replayable_matcher is None:
                unresolved_rules += 1
                continue
            key = replayable_matcher
            if not 1 <= len(item.encode()) <= MAX_EXACT_ITEM or any(char in item for char in "\t\r\n\0"):
                unresolved_rules += 1
                continue
            if key in rules:
                baseline_conflicts.append(f"{key[0]} {key[1]}")
            elif key not in supplemental_rules:
                supplemental_rules[key] = item
                imported_supplemental_rules += 1
    for item in sorted(asymmetric_filters):
        if not 1 <= len(item.encode()) <= MAX_EXACT_ITEM or any(char in item for char in "\t\r\n\0"):
            unresolved_filters += 1
            continue
        normalized = normalize_fake_filter(item)
        if normalized is not None and len(filter_forms.get(normalized, set())) != 1:
            baseline_conflicts.append(f"Fake-IP {normalized}")
            continue
        if normalized == item and normalized not in filters and item not in supplemental_filters:
            filters.add(normalized)
            imported_filters += 1
        elif normalized == item:
            continue
        elif item not in supplemental_filters:
            supplemental_filters.add(item)
            imported_supplemental_filters += 1
    if baseline_conflicts:
        return {"ok": False, "message": "两个子网的完整配置存在无法自动取并集的同匹配条件冲突：" +
                "、".join(sorted(set(baseline_conflicts)))}
    imported = validate_customization({"rules": list(rules.values()), "fake_ip_filter": list(filters),
                                       "supplemental_rules": list(supplemental_rules.values()),
                                       "supplemental_fake_ip_filter": list(supplemental_filters)})
    if not imported["ok"]:
        return {"ok": False, "message": "两个子网可安全补齐的配置差异超过管理上限或无法规范化，请先人工审计"}
    common = common_groups or set()
    supplemental_policies = {item.split(",", -1)[2] for item in supplemental_rules.values()}
    unavailable = sorted(
        {rule["policy"] for rule in rules.values() if rule["policy"] != "DIRECT" and rule["policy"] not in common} |
        {policy for policy in supplemental_policies if policy != "DIRECT" and policy not in common}
    )
    if unavailable:
        return {"ok": False, "message": "以下策略组并非两个子网共同存在，无法安全统一：" + "、".join(unavailable)}
    merged_rules = imported["rules"]
    merged_filters = imported["fake_ip_filter"]
    editable_rules = [rule for rule in merged_rules if custom_rule_identity(rule) in editable_rule_identities]
    reconciliation_rules = [rule for rule in merged_rules if custom_rule_identity(rule) not in editable_rule_identities]
    editable_filters = [item for item in merged_filters if item in editable_filter_keys]
    reconciliation_filters = [item for item in merged_filters if item not in editable_filter_keys]
    merged_supplemental_rules = imported["supplemental_rules"]
    merged_supplemental_filters = imported["supplemental_fake_ip_filter"]
    groups = [name for name in ordered_groups if name in common]
    sorted_configured_rules = sorted(configured_rules, key=lambda item: (
        CUSTOM_RULE_ORDER.get(item.split(",", 1)[0], 99),
        (item.split(",", 2)[1] if "," in item else item).casefold(), item.casefold()
    ))
    sorted_configured_filters = sorted(configured_filters, key=lambda item: fake_filter_sort_key(item)
                                       if normalize_fake_filter(item) else (item.casefold(), 9, item.casefold()))
    sorted_unowned_rules = sorted(unowned_configured_rules, key=lambda item: (
        CUSTOM_RULE_ORDER.get(item.split(",", 1)[0], 99),
        (item.split(",", 2)[1] if "," in item else item).casefold(), item.casefold()
    ))
    sorted_unowned_filters = sorted(unowned_configured_filters, key=lambda item: fake_filter_sort_key(item)
                                    if normalize_fake_filter(item) else (item.casefold(), 9, item.casefold()))
    repairable_diverged = any(
        normalized_by_target[target][0] != merged_rules or normalized_by_target[target][1] != merged_filters or
        normalized_by_target[target][2] != merged_supplemental_rules or
        normalized_by_target[target][3] != merged_supplemental_filters
        for target in TARGETS
    ) or any(value["rules"] or value["fake_ip_filter"] for value in missing_managed_by_target.values())
    full_diverged = repairable_diverged or bool(asymmetric_rules or asymmetric_filters)
    return {"ok": True, "groups": groups, "rules": merged_rules, "fake_ip_filter": merged_filters,
            "editable_rules": editable_rules, "editable_fake_ip_filter": editable_filters,
            "reconciliation_rules": reconciliation_rules,
            "reconciliation_fake_ip_filter": reconciliation_filters,
            "supplemental_rules": merged_supplemental_rules,
            "supplemental_fake_ip_filter": merged_supplemental_filters,
            "configured_rules": sorted_configured_rules, "configured_fake_ip_filter": sorted_configured_filters,
            "unowned_configured_rules": sorted_unowned_rules,
            "unowned_configured_fake_ip_filter": sorted_unowned_filters,
            "unowned_rules_by_target": unowned_rules_by_target,
            "unowned_filters_by_target": unowned_filters_by_target,
            "missing_managed_by_target": missing_managed_by_target,
            "baseline_delta": {"rules": imported_rules + imported_supplemental_rules,
                               "fake_ip_filter": imported_filters + imported_supplemental_filters,
                               "exact_rules": imported_supplemental_rules,
                               "exact_fake_ip_filter": imported_supplemental_filters,
                               "unresolved_rules": unresolved_rules,
                               "unresolved_fake_ip_filter": unresolved_filters},
            "configured_counts": configured_counts, "state_sha256": state_sha256,
            "config_sha256": config_sha256,
            "repairable_diverged": repairable_diverged, "diverged": full_diverged}


CUSTOM_READ_PUBLIC_FIELDS = frozenset({
    "ok", "message", "groups", "rules", "fake_ip_filter", "editable_rules", "editable_fake_ip_filter",
    "reconciliation_rules", "reconciliation_fake_ip_filter", "supplemental_rules",
    "supplemental_fake_ip_filter", "configured_rules", "configured_fake_ip_filter",
    "unowned_configured_rules", "unowned_configured_fake_ip_filter", "baseline_delta", "configured_counts",
    "state_sha256", "config_sha256", "repairable_diverged", "diverged",
})


def public_custom_read(merged: dict[str, Any]) -> dict[str, Any]:
    """Project the merge result to the browser contract; keep per-target indexes server-side."""
    public = {key: value for key, value in merged.items() if key in CUSTOM_READ_PUBLIC_FIELDS}
    overrides: list[list[Any]] = []
    for index, item in enumerate(public.get("unowned_configured_rules", [])):
        if not isinstance(item, str):
            continue
        fields = item.split(",")
        matcher = configured_replayable_rule_matcher(item)
        if len(fields) < 2 or matcher is None:
            continue
        kind = fields[0].strip().upper()
        raw = fields[1].strip()
        browser_value = raw.lower().removesuffix(".") if kind.startswith("DOMAIN") else raw
        if matcher != (kind, browser_value):
            overrides.append([index, matcher[0], matcher[1]])
    public["unowned_rule_matcher_overrides"] = overrides
    return public


def validate_customization(value: Any) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    if not isinstance(value, dict):
        return {"ok": False, "message": "定制内容必须是对象", "errors": [{"section": "root", "index": 0, "field": "root", "message": "请求格式无效"}]}
    rules = value.get("rules", [])
    filters = value.get("fake_ip_filter", [])
    supplemental_rules = value.get("supplemental_rules", [])
    supplemental_filters = value.get("supplemental_fake_ip_filter", [])
    if not isinstance(rules, list):
        errors.append({"section": "rules", "index": 0, "field": "rules", "message": "分流规则必须是列表"})
        rules = []
    if not isinstance(filters, list):
        errors.append({"section": "fake_ip_filter", "index": 0, "field": "fake_ip_filter", "message": "Fake-IP Filter 必须是列表"})
        filters = []
    if not isinstance(supplemental_rules, list):
        errors.append({"section": "root", "index": 0, "field": "supplemental_rules", "message": "完整规则补齐清单格式无效"})
        supplemental_rules = []
    if not isinstance(supplemental_filters, list):
        errors.append({"section": "root", "index": 0, "field": "supplemental_fake_ip_filter", "message": "完整 Fake-IP 补齐清单格式无效"})
        supplemental_filters = []
    if len(rules) > MAX_CUSTOM_ITEMS:
        errors.append({"section": "rules", "index": MAX_CUSTOM_ITEMS, "field": "rules", "message": f"分流规则最多 {MAX_CUSTOM_ITEMS} 条"})
    if len(filters) > MAX_CUSTOM_ITEMS:
        errors.append({"section": "fake_ip_filter", "index": MAX_CUSTOM_ITEMS, "field": "fake_ip_filter", "message": f"Fake-IP Filter 最多 {MAX_CUSTOM_ITEMS} 条"})
    if len(supplemental_rules) > MAX_SUPPLEMENT_ITEMS:
        errors.append({"section": "root", "index": 0, "field": "supplemental_rules", "message": f"完整规则补齐清单最多 {MAX_SUPPLEMENT_ITEMS} 条"})
    if len(supplemental_filters) > MAX_SUPPLEMENT_ITEMS:
        errors.append({"section": "root", "index": 0, "field": "supplemental_fake_ip_filter", "message": f"完整 Fake-IP 补齐清单最多 {MAX_SUPPLEMENT_ITEMS} 条"})
    normalized_rules: list[dict[str, str]] = []
    matchers: set[tuple[str, str]] = set()
    for index, item in enumerate(rules[:MAX_CUSTOM_ITEMS]):
        if not isinstance(item, dict):
            errors.append({"section": "rules", "index": index, "field": "row", "message": "规则必须包含类型、值和策略"})
            continue
        if not all(isinstance(item.get(field), str) for field in ("type", "value", "policy")):
            errors.append({"section": "rules", "index": index, "field": "row", "message": "规则类型、值和策略必须是文本"})
            continue
        kind = item["type"].strip().upper()
        raw = item["value"].strip()
        policy = item["policy"].strip()
        if kind not in CUSTOM_RULE_TYPES:
            errors.append({"section": "rules", "index": index, "field": "type", "message": "请选择 DOMAIN、DOMAIN-SUFFIX、IP-CIDR 或 IP-CIDR6"})
            continue
        if not valid_custom_policy(policy):
            errors.append({"section": "rules", "index": index, "field": "policy", "message": "请选择 DIRECT（直连）或一个有效业务分组"})
        normalized = None
        if kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
            normalized = normalize_domain(raw)
            if not normalized:
                errors.append({"section": "rules", "index": index, "field": "value", "message": "域名格式错误；示例：api.example.com 或 example.com"})
        else:
            try:
                if kind == "IP-CIDR6" and "." in raw:
                    raise ValueError
                network = ipaddress.ip_network(raw if "/" in raw else raw + ("/128" if ":" in raw else "/32"), strict=False)
                if kind == "IP-CIDR" and network.version != 4:
                    raise ValueError
                if kind == "IP-CIDR6" and network.version != 6:
                    raise ValueError
                normalized = str(network)
            except ValueError:
                example = "198.51.100.0/24" if kind == "IP-CIDR" else "2001:db8::/32"
                errors.append({"section": "rules", "index": index, "field": "value", "message": f"IP/CIDR 格式错误；示例：{example}"})
        if normalized:
            matcher = (kind, normalized)
            if matcher in matchers:
                errors.append({"section": "rules", "index": index, "field": "value", "message": "该匹配条件已经存在，不能重复增加"})
            else:
                matchers.add(matcher)
                normalized_rules.append({"type": kind, "value": normalized, "policy": policy})
    normalized_filters: list[str] = []
    seen_filters: set[str] = set()
    for index, item in enumerate(filters[:MAX_CUSTOM_ITEMS]):
        if not isinstance(item, str):
            errors.append({"section": "fake_ip_filter", "index": index, "field": "value", "message": "Fake-IP Filter 条目必须是文本"})
            continue
        raw = item.strip()
        normalized = normalize_fake_filter(raw)
        if raw == "*":
            normalized = None
            message = "不允许孤立的 *，它会让几乎所有域名绕过 Fake-IP"
        else:
            message = "格式错误；示例：printer.lan、*.example.com 或 +.example.com"
        if not normalized:
            errors.append({"section": "fake_ip_filter", "index": index, "field": "value", "message": message})
        elif normalized in seen_filters:
            errors.append({"section": "fake_ip_filter", "index": index, "field": "value", "message": "该 Fake-IP Filter 已经存在，不能重复增加"})
        else:
            seen_filters.add(normalized)
            normalized_filters.append(normalized)
    normalized_supplemental_rules: list[str] = []
    supplement_rule_matchers: set[tuple[str, str]] = set()
    for index, item in enumerate(supplemental_rules[:MAX_SUPPLEMENT_ITEMS]):
        if not isinstance(item, str) or not 1 <= len(item.encode()) <= MAX_EXACT_ITEM or any(char in item for char in "\t\r\n\0"):
            errors.append({"section": "root", "index": index, "field": "supplemental_rules", "message": "完整规则补齐项格式无效"})
            continue
        matcher = configured_replayable_rule_matcher(item)
        if matcher is None:
            errors.append({"section": "root", "index": index, "field": "supplemental_rules", "message": "完整规则补齐项必须是有效的域名/IP 规则"})
        elif matcher in matchers or matcher in supplement_rule_matchers:
            errors.append({"section": "root", "index": index, "field": "supplemental_rules", "message": "完整规则补齐项与现有匹配条件重复"})
        else:
            supplement_rule_matchers.add(matcher)
            normalized_supplemental_rules.append(item)
    normalized_supplemental_filters: list[str] = []
    supplement_filter_keys: set[str] = set()
    supplement_filter_items: set[str] = set()
    for index, item in enumerate(supplemental_filters[:MAX_SUPPLEMENT_ITEMS]):
        if not isinstance(item, str) or not 1 <= len(item.encode()) <= MAX_EXACT_ITEM or any(char in item for char in "\t\r\n\0"):
            errors.append({"section": "root", "index": index, "field": "supplemental_fake_ip_filter", "message": "完整 Fake-IP 补齐项格式无效"})
            continue
        normalized = normalize_fake_filter(item)
        if item in supplement_filter_items:
            errors.append({"section": "root", "index": index, "field": "supplemental_fake_ip_filter", "message": "完整 Fake-IP 补齐项重复"})
        elif normalized is not None and (normalized in seen_filters or normalized in supplement_filter_keys):
            errors.append({"section": "root", "index": index, "field": "supplemental_fake_ip_filter", "message": "完整 Fake-IP 补齐项与现有条目等价重复"})
        else:
            if normalized is not None:
                supplement_filter_keys.add(normalized)
            supplement_filter_items.add(item)
            normalized_supplemental_filters.append(item)
    if errors:
        return {"ok": False, "message": f"发现 {len(errors)} 个输入错误", "errors": errors}
    normalized_rules.sort(key=custom_rule_sort_key)
    normalized_filters.sort(key=fake_filter_sort_key)
    normalized_supplemental_rules.sort(key=lambda item: (
        CUSTOM_RULE_ORDER.get(item.split(",", 1)[0].upper(), 99),
        (item.split(",", 2)[1] if "," in item else item).casefold(), item.casefold()
    ))
    normalized_supplemental_filters.sort(key=lambda item: fake_filter_sort_key(item)
                                         if normalize_fake_filter(item) else (item.casefold(), 9, item.casefold()))
    state_size = len("OPENCLASH_SYNC_CUSTOM_V1\n".encode())
    state_size += sum(len(f"RULE\t{item['type']}\t{item['value']}\t{item['policy']}\n".encode()) +
                      len(f"OWNED_RULE\t{item['type']}\t{item['value']}\t{item['policy']}\n".encode())
                      for item in normalized_rules)
    state_size += sum(len(f"FAKE\t{item}\n".encode()) + len(f"OWNED_FAKE\t{item}\n".encode())
                      for item in normalized_filters)
    state_size += sum(len(f"SUPPLEMENT_RULE\t{item}\n".encode()) +
                      len(f"OWNED_SUPPLEMENT_RULE\t{item}\n".encode())
                      for item in normalized_supplemental_rules)
    state_size += sum(len(f"SUPPLEMENT_FAKE\t{item}\n".encode()) +
                      len(f"OWNED_SUPPLEMENT_FAKE\t{item}\n".encode())
                      for item in normalized_supplemental_filters)
    if state_size > 1024 * 1024:
        return {"ok": False, "message": "统一补齐状态超过 1 MiB 安全上限", "errors": [
            {"section": "root", "index": 0, "field": "root", "message": "请先人工缩小需补齐的差异范围"}
        ]}
    return {"ok": True, "message": "分流与 Fake-IP Filter 语法检查通过", "rules": normalized_rules,
            "fake_ip_filter": normalized_filters, "supplemental_rules": normalized_supplemental_rules,
            "supplemental_fake_ip_filter": normalized_supplemental_filters,
            "summary": {"rules": len(normalized_rules) + len(normalized_supplemental_rules),
                        "fake_ip_filter": len(normalized_filters) + len(normalized_supplemental_filters)}}


class DigestAuth:
    def __init__(self, ha1: dict[str, str] | str) -> None:
        self.ha1 = {"SHA-256": ha1} if isinstance(ha1, str) else dict(ha1)
        self.nonces: dict[str, float] = {}
        self.replay: dict[tuple[str, str, int], float] = {}
        self.failures: dict[str, list[float]] = {}
        self.lock = threading.Lock()

    @staticmethod
    def parse(header: str) -> dict[str, str]:
        if not header.startswith("Digest "):
            return {}
        text = header[7:]
        field = re.compile(r'\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^,\s]+))\s*(,|$)')
        result: dict[str, str] = {}
        position = 0
        while position < len(text):
            match = field.match(text, position)
            if match is None:
                return {}
            name = match.group(1).lower()
            if name in result:
                return {}
            value = match.group(2) if match.group(2) is not None else match.group(3)
            result[name] = re.sub(r"\\(.)", r"\1", value) if match.group(2) is not None else value
            position = match.end()
            if match.group(4) == "":
                return result if position == len(text) else {}
            if position == len(text):
                return {}
        return result

    def _prune_failures(self, now: float) -> None:
        for key, values in list(self.failures.items()):
            recent = [stamp for stamp in values if stamp > now - 300]
            if recent:
                self.failures[key] = recent
            else:
                self.failures.pop(key, None)
        while len(self.failures) > MAX_AUTH_FAILURE_CLIENTS:
            self.failures.pop(next(iter(self.failures)), None)

    def _record_failure_locked(self, client: str, now: float) -> None:
        self._prune_failures(now)
        if client not in self.failures and len(self.failures) >= MAX_AUTH_FAILURE_CLIENTS:
            self.failures.pop(next(iter(self.failures)), None)
        self.failures.setdefault(client, []).append(now)

    def new_nonce(self) -> str:
        nonce = secrets.token_urlsafe(32)
        with self.lock:
            now = time.time()
            self.nonces = {key: expiry for key, expiry in self.nonces.items() if expiry >= now}
            self.replay = {key: stamp for key, stamp in self.replay.items() if key[0] in self.nonces}
            while len(self.nonces) >= MAX_AUTH_NONCES:
                oldest = next(iter(self.nonces))
                self.nonces.pop(oldest, None)
                self.replay = {key: stamp for key, stamp in self.replay.items() if key[0] != oldest}
            self.nonces[nonce] = now + 300
        return nonce

    def rate_limited(self, client: str) -> bool:
        now = time.time()
        with self.lock:
            self._prune_failures(now)
            recent = self.failures.get(client, [])
            if recent:
                self.failures[client] = recent
            else:
                self.failures.pop(client, None)
            return len(recent) >= 8

    def record_failure(self, client: str) -> None:
        with self.lock:
            self._record_failure_locked(client, time.time())

    @staticmethod
    def digest_hex(algorithm: str, value: bytes) -> str:
        if algorithm == "SHA-256":
            return hashlib.sha256(value).hexdigest()
        return hashlib.md5(value, usedforsecurity=False).hexdigest()

    def verify(self, method: str, uri: str, header: str, client: str) -> bool:
        if len(header) > 4096:
            self.record_failure(client)
            return False
        fields = self.parse(header)
        required = {"username", "realm", "nonce", "uri", "response", "qop", "nc", "cnonce"}
        if not required.issubset(fields) or fields.get("username") != AUTH_USER or fields.get("realm") != AUTH_REALM:
            self.record_failure(client)
            return False
        algorithm = fields.get("algorithm", "MD5").upper()
        if fields.get("uri") != uri or fields.get("qop") != "auth" or algorithm not in self.ha1:
            self.record_failure(client)
            return False
        if not re.fullmatch(r"[0-9a-fA-F]{8}", fields["nc"]) or not re.fullmatch(r"[A-Za-z0-9._~-]{8,128}", fields["cnonce"]):
            self.record_failure(client)
            return False
        digest_size = 64 if algorithm == "SHA-256" else 32
        if not re.fullmatch(rf"[0-9a-fA-F]{{{digest_size}}}", fields["response"]):
            self.record_failure(client)
            return False
        try:
            nc = int(fields["nc"], 16)
        except ValueError:
            self.record_failure(client)
            return False
        ha2 = self.digest_hex(algorithm, f"{method}:{uri}".encode())
        expected = self.digest_hex(
            algorithm,
            f"{self.ha1[algorithm]}:{fields['nonce']}:{fields['nc']}:{fields['cnonce']}:auth:{ha2}".encode(),
        )
        if not hmac.compare_digest(expected, fields["response"].lower()):
            self.record_failure(client)
            return False
        # 摘要比较完成后，在同一个锁区间内再次检查 nonce 与计数并登记，
        # 避免两个并发请求复用同一 nc，也避免在持锁时递归获取锁。
        with self.lock:
            now = time.time()
            if self.nonces.get(fields["nonce"], 0) < now:
                return False
            replay_key = (fields["nonce"], fields["cnonce"], nc)
            if nc < 1 or replay_key in self.replay:
                self._record_failure_locked(client, now)
                return False
            if len(self.replay) >= MAX_AUTH_REPLAY:
                # 当前 nonce 的并发计数预算耗尽时使其失效，让浏览器获取
                # 新 challenge；不丢弃旧记录，以免重新开放已见过的请求。
                expired_nonce = fields["nonce"]
                self.nonces.pop(expired_nonce, None)
                self.replay = {key: stamp for key, stamp in self.replay.items() if key[0] != expired_nonce}
                return False
            self.replay[replay_key] = time.time()
            self.failures.pop(client, None)
        return True


DIGEST_AUTH = DigestAuth(read_auth_ha1()) if AUTH_REQUIRED else None


CHAIN_PREFIX = "__OCS_UP_"
CHAIN_KEYS = {"node", "type", "server", "port", "username", "password", "tls", "sni", "cipher", "keep_password"}
CHAIN_CIPHERS = {"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"}


def chain_text(value: Any, maximum: int, empty: bool = False) -> bool:
    return isinstance(value, str) and (empty or bool(value)) and len(value.encode()) <= maximum and \
        not re.search(r"[\x00-\x1f\x7f]", value)


def chain_node_ok(value: Any) -> bool:
    return chain_text(value, 512) and not value.startswith(CHAIN_PREFIX) and \
        value not in {"DIRECT", "REJECT", "GLOBAL", "COMPATIBLE", "PASS"}


def validate_chain(value: Any) -> dict[str, Any]:
    """Validate the public allowlist; retention identity is rechecked on the router."""
    try:
        if not isinstance(value, dict) or set(value) - CHAIN_KEYS or not chain_node_ok(value.get("node")):
            raise ValueError
        item = dict(value)
        if item.get("type") not in {"socks5", "http", "ss"} or type(item.get("port")) is not int or not 1 <= item["port"] <= 65535:
            raise ValueError
        host = item.get("server")
        if not chain_text(host, 253):
            raise ValueError
        if ":" in host or re.fullmatch(r"[0-9.]+", host):
            address = ipaddress.ip_address(host)
            if address.is_loopback or address.is_unspecified or address.is_link_local or address.is_multicast or \
                    (address.version == 4 and (int(address) >> 24 == 0 or int(address) >> 28 >= 14)) or \
                    (address.version == 6 and (address.ipv4_mapped is not None or int(address) >> 32 == 0)):
                raise ValueError
            item["server"] = str(address)
        else:
            host = host.lower().removesuffix(".")
            if "." not in host or host.endswith(".localhost") or not re.fullmatch(
                    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*", host):
                raise ValueError
            item["server"] = host
        for key in ("username", "password", "sni", "cipher"):
            if key in item:
                if not chain_text(item[key], 1024 if key == "password" else 253, empty=True):
                    raise ValueError
                if not item[key]:
                    del item[key]
        if "tls" in item and type(item["tls"]) is not bool:
            raise ValueError
        if "keep_password" in item and type(item["keep_password"]) is not bool:
            raise ValueError
        retained = item.get("keep_password", False)
        if retained and item.get("password"):
            raise ValueError
        if item["type"] == "ss":
            if any(key in item for key in ("username", "tls", "sni")) or item.get("cipher") not in CHAIN_CIPHERS or not (item.get("password") or retained):
                raise ValueError
        else:
            if "cipher" in item or bool(item.get("username")) != bool(item.get("password") or retained):
                raise ValueError
            item.setdefault("tls", False)
            if "sni" in item:
                sni = item["sni"].lower().removesuffix(".")
                if item["type"] != "http" or not item["tls"] or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*", sni):
                    raise ValueError
                item["sni"] = sni
            if item["type"] == "socks5" and any(len(item.get(key, "").encode()) > 255 for key in ("username", "password")):
                raise ValueError
        return {"ok": True, "chain": item, "message": "链式配置格式通过；尚未连接远端或测试链路"}
    except (ValueError, TypeError, UnicodeError):
        return {"ok": False, "message": "链式配置无效：请检查节点、协议、服务器/IP、端口、认证与 TLS 字段；只接受代理服务地址，不接受 URL"}


def chain_result_ok(request: dict[str, Any], result: dict[str, Any]) -> bool:
    action = request["action"]
    if action == "chain_apply":
        return set(result) <= {"ok", "message"} and isinstance(result.get("message"), str)
    if action == "chain_test":
        if set(result) - {"ok", "message", "node", "configuration", "runtime", "upstream", "chain", "verdict"}:
            return False
        if not all(isinstance(result.get(key), str) for key in ("node", "configuration", "runtime", "verdict", "upstream", "chain")):
            return False
        if result.get("node") != request.get("node") or result.get("configuration") not in {"PASS", "FAIL"} or \
                result.get("runtime") not in {"PASS", "FAIL", "UNKNOWN"} or result.get("verdict") not in {"PASS", "FAIL", "UNKNOWN"} or \
                any(result.get(key) not in {"REACHABLE", "UNREACHABLE", "UNKNOWN"} for key in ("upstream", "chain")):
            return False
        return result["verdict"] != "PASS" or (result["configuration"] == "PASS" and result["runtime"] == "PASS" and
                                               result["upstream"] == "REACHABLE" and result["chain"] == "REACHABLE")
    if set(result) - {"ok", "message", "chains", "nodes", "config_sha256", "state_sha256"}:
        return False
    if not all(isinstance(result.get(key), str) and re.fullmatch(r"[0-9a-f]{64}", result[key]) for key in ("config_sha256", "state_sha256")):
        return False
    chains, nodes = result.get("chains"), result.get("nodes")
    if not isinstance(chains, list) or len(chains) > 32 or not isinstance(nodes, list) or len(nodes) > 20000:
        return False
    for item in nodes:
        if not isinstance(item, dict) or set(item) != {"name", "type"} or not chain_node_ok(item["name"]) or not chain_text(item["type"], 64):
            return False
    for item in chains:
        if not isinstance(item, dict) or "password" in item or "keep_password" in item or type(item.get("has_password")) is not bool:
            return False
        candidate = {key: value for key, value in item.items() if key != "has_password"}
        candidate["keep_password"] = item["has_password"]
        if not validate_chain(candidate)["ok"]:
            return False
    names = [item["name"] for item in nodes]
    managed = [item["node"] for item in chains]
    return len(set(names)) == len(names) and len(set(managed)) == len(managed) and set(managed) <= set(names)


class Bridge:
    """调用 root-owned helper。Web 进程不直接拥有路由器密钥。"""

    def __init__(self) -> None:
        self.helper = os.environ.get("OPENCLASH_WEB_HELPER", "")
        if self.helper:
            self._validate_helper()
        self.operation_lock = threading.Lock()

    def _validate_helper(self) -> None:
        path = Path(self.helper)
        try:
            info = path.lstat()
        except OSError as exc:
            raise RuntimeError("受控执行器不存在") from exc
        if not path.is_absolute() or ".." in path.parts or path.is_symlink() or not stat.S_ISREG(info.st_mode) or \
                info.st_uid != 0 or info.st_mode & 0o022 or not info.st_mode & 0o100 or \
                not 1 <= info.st_size <= 1024 * 1024 or not root_owned_directory_chain(path.parent):
            raise RuntimeError("受控执行器权限、所有者或类型无效")

    @property
    def enabled(self) -> bool:
        return bool(self.helper)

    def call(self, request: dict[str, Any]) -> dict[str, Any]:
        if not self.enabled:
            return self.demo(request)
        action = request.get("action")
        # status 只读运行态；其他操作跨两台路由器全局串行，既避免读取
        # 原子切换中的组合，也避免用户在两台设备上同时触发 OpenClash 重启。
        lock = self.operation_lock if action not in {"status", "converter_run"} else None
        if lock is not None and not lock.acquire(blocking=False):
            return {"ok": False, "message": "同步器正在执行另一项操作，请等待完成后重试"}
        try:
            return self._call_unlocked(request)
        finally:
            if lock is not None:
                lock.release()

    def _call_unlocked(self, request: dict[str, Any]) -> dict[str, Any]:
        if not self.enabled:
            return self.demo(request)
        mutating = request.get("action") not in {"status", "read", "custom_read", "route_check", "custom_preview", "chain_read", "chain_test", "converter_run"}
        failure_message = "无法确认远端操作结果；写入状态 UNKNOWN，请重新读取并核对后再操作" if mutating else \
            "受控执行器不可用或返回结果无效"
        try:
            command = [self.helper] if os.geteuid() == 0 else ["/usr/bin/sudo", "-n", self.helper]
            proc = subprocess.run(
                command, input=json_bytes(request), stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, timeout=75 if request.get("action") == "converter_run" else 420, check=False,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            )
        except (OSError, subprocess.TimeoutExpired):
            return {"ok": False, "message": failure_message}
        if proc.returncode != 0 or len(proc.stdout) > MAX_BODY:
            return {"ok": False, "message": failure_message}
        try:
            result = json.loads(proc.stdout, object_pairs_hook=unique_json_object)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
            return {"ok": False, "message": failure_message}
        return result if isinstance(result, dict) and bridge_result_ok(request, result) \
            else {"ok": False, "message": failure_message}

    def call_all(self, action: str, payloads: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
        if not self.operation_lock.acquire(blocking=False):
            return {"ok": False, "message": "同步器正在执行另一项操作，请等待完成后重试"}
        results: dict[str, dict[str, Any]] = {}
        try:
            requests = {}
            for target in TARGETS:
                requests[target] = {"action": action, "target": target}
                if payloads is not None:
                    requests[target].update(payloads.get(target, {}))
            # 两个子网的纯读取可以并行，但整个读取窗口仍持有全局锁，
            # 因此不会与 Candidate 切换、定制写入或 OpenClash 重启交叠。
            if action in {"status", "custom_read", "route_check"}:
                with ThreadPoolExecutor(max_workers=len(TARGETS), thread_name_prefix="openclash-read") as executor:
                    futures = {target: executor.submit(self._call_unlocked, request)
                               for target, request in requests.items()}
                    results = {target: futures[target].result() for target in TARGETS}
            else:
                for target, request in requests.items():
                    result = self._call_unlocked(request)
                    results[target] = result
                    if not result.get("ok"):
                        break
        finally:
            self.operation_lock.release()
        return self._batch_result(results)

    def custom_apply_all(self, customization: dict[str, Any], expected_state: dict[str, str],
                         expected_config: dict[str, str]) -> dict[str, Any]:
        if not self.operation_lock.acquire(blocking=False):
            return {"ok": False, "message": "同步器正在执行另一项操作，请等待完成后重试"}
        results: dict[str, dict[str, Any]] = {}
        try:
            with ThreadPoolExecutor(max_workers=len(TARGETS), thread_name_prefix="openclash-preflight") as executor:
                futures = {target: executor.submit(self._call_unlocked, {"action": "custom_read", "target": target})
                           for target in TARGETS}
                reads = {target: futures[target].result() for target in TARGETS}
            for target in TARGETS:
                current = reads[target]
                if not current.get("ok"):
                    return {"ok": False, "message": f"{TARGETS[target].name} 预检读取失败，尚未写入任何子网",
                            "results": {target: current}, "completed": [], "failed": target}
                if current.get("state_sha256") != expected_state[target] or \
                        current.get("config_sha256") != expected_config[target]:
                    return {"ok": False, "message": f"{TARGETS[target].name} 的定制状态或主配置已变化，请重新读取后再保存",
                            "results": {target: current}, "completed": [], "failed": target}
            merged = merge_custom_reads(reads)
            if not merged.get("ok"):
                return {"ok": False, "message": merged["message"], "results": reads, "completed": []}
            common_groups = set(merged["groups"])
            submitted_supplements = (customization.get("supplemental_rules", []),
                                     customization.get("supplemental_fake_ip_filter", []))
            merged_supplements = (merged["supplemental_rules"], merged["supplemental_fake_ip_filter"])
            if submitted_supplements != merged_supplements:
                return {"ok": False, "message": "完整规则补齐清单已变化或请求被修改，请重新读取后再保存",
                        "results": reads, "completed": []}
            missing = {rule["policy"] for rule in customization["rules"]
                       if rule["policy"] != "DIRECT" and rule["policy"] not in common_groups}
            missing.update(item.split(",", -1)[2] for item in customization.get("supplemental_rules", [])
                           if item.split(",", -1)[2] != "DIRECT" and item.split(",", -1)[2] not in common_groups)
            missing = sorted(missing)
            if missing:
                return {"ok": False, "message": "以下策略组并非两个子网共同存在，尚未写入：" + "、".join(missing),
                        "results": reads, "completed": []}
            existing_managed_rules = {custom_rule_identity(rule) for rule in merged["rules"]}
            existing_managed_filters = set(merged["fake_ip_filter"])
            baseline_conflicts: list[str] = []
            baseline_duplicates: list[str] = []
            for target in TARGETS:
                unowned_rules = merged["unowned_rules_by_target"][target]
                unowned_rule_forms: dict[tuple[str, str], list[str]] = {}
                for item in unowned_rules:
                    matcher = configured_rule_matcher(item)
                    if matcher is not None:
                        unowned_rule_forms.setdefault(matcher, []).append(item)
                unowned_filter_forms: dict[str, list[str]] = {}
                for item in merged["unowned_filters_by_target"][target]:
                    normalized = normalize_fake_filter(item)
                    if normalized is not None:
                        unowned_filter_forms.setdefault(normalized, []).append(item)
                for rule in customization["rules"]:
                    matcher = (rule["type"], rule["value"])
                    desired_text = f"{rule['type']},{rule['value']},{rule['policy']}"
                    matching = unowned_rule_forms.get(matcher, [])
                    if any(item != desired_text for item in matching):
                        baseline_conflicts.append(f"{TARGETS[target].name} {rule['type']} {rule['value']}")
                    elif matching and custom_rule_identity(rule) not in existing_managed_rules:
                        baseline_duplicates.append(f"{TARGETS[target].name} {rule['type']} {rule['value']}")
                for item in customization["fake_ip_filter"]:
                    matching_filters = unowned_filter_forms.get(item, [])
                    if any(value != item for value in matching_filters):
                        baseline_conflicts.append(f"{TARGETS[target].name} Fake-IP {item}")
                    elif matching_filters and item not in existing_managed_filters:
                        baseline_duplicates.append(f"{TARGETS[target].name} Fake-IP {item}")
            if baseline_conflicts:
                return {"ok": False, "message": "现有非同步器配置中存在同匹配条件但内容不同的项目，尚未写入：" +
                        "、".join(sorted(set(baseline_conflicts))), "results": reads, "completed": []}
            if baseline_duplicates:
                return {"ok": False, "message": "以下新增内容已存在于 OpenClash 非同步器配置中，不能重复增加：" +
                        "、".join(sorted(set(baseline_duplicates))), "results": reads, "completed": []}
            for target in TARGETS:
                preview = self._call_unlocked({"action": "custom_preview", "target": target,
                                               "customization": customization,
                                               "expected_state_sha256": expected_state[target],
                                               "expected_config_sha256": expected_config[target]})
                results[target] = preview
                if not preview.get("ok"):
                    return {"ok": False, "message": f"{TARGETS[target].name} 写入前预演失败，两个子网均未写入：" +
                            preview.get("message", "预演失败"), "results": results, "completed": [], "failed": target}
            results = {}
            for target in TARGETS:
                results[target] = self._call_unlocked({"action": "custom_apply", "target": target,
                                                       "customization": customization,
                                                       "expected_state_sha256": expected_state[target],
                                                       "expected_config_sha256": expected_config[target]})
                if not results[target].get("ok"):
                    break
        finally:
            self.operation_lock.release()
        return self._batch_result(results)

    @staticmethod
    def _batch_result(results: dict[str, dict[str, Any]]) -> dict[str, Any]:
        completed = [target for target, result in results.items() if result.get("ok")]
        failed = next((target for target, result in results.items() if not result.get("ok")), None)
        if failed is not None:
            message = results[failed].get("message", "操作失败")
            if completed:
                message = f"{TARGETS[completed[0]].name} 已完成，但 {TARGETS[failed].name} 失败：{message}；请勿把它视为双子网整体成功"
            else:
                message = f"{TARGETS[failed].name} 失败：{message}"
            return {"ok": False, "message": message, "results": results, "completed": completed, "failed": failed}
        return {"ok": True, "results": results, "completed": completed}

    @staticmethod
    def demo(request: dict[str, Any]) -> dict[str, Any]:
        if request.get("action") == "converter_run":
            return {"ok": False, "code": "SANDBOX_UNAVAILABLE", "router_changed": False}
        action = request.get("action")
        target = request.get("target")
        if action == "status":
            return {"ok": True, "mode": "preview", "targets": [
                {"id": item.id, "name": item.name, "address": item.address,
                 "state": "待连接", "active": "ProviderBase-ProviderSource.yaml"}
                for item in TARGETS.values()]}
        if action == "read":
            sample = "proxies:\n  - name: 示例节点\n    type: ss\nproxy-groups:\n  - name: 自动选择\n    type: select\n    proxies: [示例节点]\nrules:\n  - MATCH,自动选择\n"
            return {"ok": True, "mode": "preview", "content": sample,
                    "sha256": hashlib.sha256(sample.encode()).hexdigest(),
                    "message": "预览模式：部署受控执行器后读取真实配置"}
        if action == "chain_read":
            digest = hashlib.sha256(b"preview-chain-empty").hexdigest()
            return {"ok": True, "mode": "preview", "nodes": [{"name": "示例节点", "type": "ss"}], "chains": [],
                    "config_sha256": digest, "state_sha256": digest, "message": "预览模式：未读取真实路由器；未启用任何链式代理"}
        if action == "chain_apply":
            return {"ok": False, "mode": "preview", "message": "预览模式不保存链式配置；请连接受控路由器后应用"}
        if action == "chain_test":
            return {"ok": False, "mode": "preview", "message": "UNKNOWN：预览模式没有实际链路，无法测试"}
        if action == "custom_read":
            sample_rule = {"type": "DOMAIN", "value": "saved.example.com", "policy": "DIRECT"}
            sample_filter = "*.saved.example.com"
            digest = hashlib.sha256(b"preview-saved-customization").hexdigest()
            return {"ok": True, "mode": "preview", "groups": ["DIRECT", "Proxies", "AI"],
                    "rules": [sample_rule], "fake_ip_filter": [sample_filter],
                    "owned_rules": [sample_rule], "owned_fake_ip_filter": [sample_filter],
                    "supplemental_rules": [], "supplemental_fake_ip_filter": [],
                    "owned_supplemental_rules": [], "owned_supplemental_fake_ip_filter": [],
                    "configured_rules": ["DOMAIN,saved.example.com,DIRECT", "IP-CIDR,192.0.2.7,DIRECT"],
                    "configured_fake_ip_filter": [sample_filter],
                    "state_sha256": digest, "config_sha256": digest,
                    "message": "预览模式：部署受控执行器后读取真实定制项"}
        if action == "route_check":
            return {"ok": True, "mode": "UNKNOWN", "policy": "UNKNOWN",
                    "rule_type": "UNKNOWN", "reachability": "UNKNOWN", "certainty": "UNKNOWN",
                    "message": "预览模式：未连接路由器，无法判定当前规则与固定探针可达性"}
        labels = {"stage_main": "更新主配置", "update_maying": "更新 Maying 机场文件",
                  "update_nexitally": "更新 Nexitally 机场文件", "write": "保存配置",
                  "rollback": "回滚主配置", "custom_apply": "保存独立定制"}
        return {"ok": True, "mode": "preview", "message":
                f"已完成交互验证：{labels.get(action, action)} / {target}。预览模式未操作路由器。"}


BRIDGE = Bridge()
NONCES: dict[str, float] = {}
NONCE_LOCK = threading.Lock()


def new_nonce() -> str:
    value = secrets.token_urlsafe(24)
    with NONCE_LOCK:
        now = time.time()
        for key, expiry in list(NONCES.items()):
            if expiry < now:
                NONCES.pop(key, None)
        while len(NONCES) >= MAX_OPERATION_NONCES:
            NONCES.pop(next(iter(NONCES)), None)
        NONCES[value] = time.time() + 600
    return value


def consume_nonce(value: str) -> bool:
    now = time.time()
    with NONCE_LOCK:
        for key, expiry in list(NONCES.items()):
            if expiry < now:
                NONCES.pop(key, None)
        expiry = NONCES.pop(value, None)
    return bool(expiry and expiry >= now)


# Requests may put credentials in arbitrary paths; only fixed endpoint names
# are safe for durable access logs. Unknown methods/paths are never reflected.
LOG_ROUTES = frozenset({
    "/", "/index.html", "/app.css", "/app.js", "/OpenClash_Sync_Logo.png",
    "/converter.js", "/converter_apply.js", "/converter_services.js", "/healthz",
    "/api/bootstrap", "/api/status", "/api/validate", "/api/read", "/api/write",
    "/api/rollback", "/api/stage-main", "/api/update-maying", "/api/update-nexitally",
    "/api/custom/validate", "/api/custom/read", "/api/custom/apply", "/api/route-check",
    "/api/chain/validate", "/api/chain/read", "/api/chain/apply", "/api/chain/test",
    "/api/converter/options", "/api/converter/router-preview", "/api/converter/router-apply",
    "/api/converter/service", "/api/converter/tool", "/api/converter/execute",
    "/api/converter/parse", "/api/converter/validate", "/api/converter/link",
})


class RequestDeadlineReader(io.RawIOBase):
    """Apply one monotonic intake budget to every raw socket receive.

    A timeout around BufferedReader.read/readline alone only limits idle gaps;
    a peer that trickles bytes can otherwise keep a worker indefinitely.
    Buffer above this raw reader so each actual recv uses the remaining budget.
    """

    def __init__(self, raw: Any, connection: Any) -> None:
        super().__init__()
        self.raw = raw
        self.connection = connection
        self.deadline: float | None = None

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int | None:
        if self.deadline is not None:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("HTTP request read deadline exceeded")
            self.connection.settimeout(min(HTTP_SOCKET_TIMEOUT, remaining))
        return self.raw.readinto(buffer)

    def finish_reading(self) -> None:
        self.deadline = None
        self.connection.settimeout(HTTP_SOCKET_TIMEOUT)

    def close(self) -> None:
        try:
            self.raw.close()
        finally:
            super().close()


class Handler(SimpleHTTPRequestHandler):
    server_version = "OpenClashSyncWeb"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    rbufsize = 0  # The deadline reader must sit below, not above, buffering.

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(STATIC), **kwargs)

    def parse_request(self) -> bool:
        # One handler instance serves multiple HTTP/1.1 requests.
        self._json_body_consumed = False
        return super().parse_request()

    def setup(self) -> None:
        super().setup()
        self._deadline_reader = RequestDeadlineReader(self.rfile, self.connection)
        self.rfile = io.BufferedReader(self._deadline_reader)
        self.connection.settimeout(HTTP_SOCKET_TIMEOUT)

    def handle_one_request(self) -> None:
        # Reset for each keep-alive request, including its request line.
        self._deadline_reader.deadline = time.monotonic() + HTTP_READ_TIMEOUT
        try:
            super().handle_one_request()
        finally:
            self.finish_request_reading()

    def finish_request_reading(self) -> None:
        reader = getattr(self, "_deadline_reader", None)
        if reader is not None:
            reader.finish_reading()

    def handle_expect_100(self) -> bool:
        # 管理台不接受流式上传；避免在认证和正文上限校验前占用连接与线程。
        self.send_empty(417)
        self.close_connection = True
        return False

    def log_message(self, fmt: str, *args: Any) -> None:
        # 不反射请求行、未知路径、method、错误上下文或控制字符。
        try:
            route = urlparse(getattr(self, "path", "")).path
        except ValueError:
            route = ""
        if route not in LOG_ROUTES:
            route = "<unrecognized>"
        method = getattr(self, "command", None)
        if method not in {"GET", "HEAD", "POST", "OPTIONS"}:
            method = "OTHER"
        print(f"{self.client_ip() or 'UNKNOWN'} {method} {route}")

    def end_headers(self) -> None:
        self.finish_request_reading()  # Error and success replies use the normal send timeout.
        # Never reinterpret an unread request body as another HTTP request.
        # Early auth/Origin/method errors and GET/HEAD bodies are not drained.
        if getattr(self, "headers", None) is not None and not getattr(self, "_json_body_consumed", False):
            lengths = self.header_values("Content-Length")
            if self.header_values("Transfer-Encoding") or lengths and lengths != ["0"]:
                self.close_connection = True
        if getattr(self, "close_connection", False) and not any(
                line.lower().startswith(b"connection:") for line in getattr(self, "_headers_buffer", ())):
            self.send_header("Connection", "close")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        super().end_headers()

    def send_head(self):
        # Only the explicitly named scripts come from the pinned release.
        # Never expose its Python modules, manifest, or arbitrary path traversal.
        path = urlparse(self.path).path
        if path in {"/converter.js", "/converter_apply.js", "/converter_services.js"}:
            asset = CONVERTER_ROOT / "static" / path[1:]
            try:
                opened = asset.open("rb")
            except OSError:
                self.send_error(404)
                return None
            self.send_response(200)
            self.send_header("Content-Type", "text/javascript; charset=utf-8")
            self.send_header("Content-Length", str(os.fstat(opened.fileno()).st_size))
            self.end_headers()
            return opened
        return super().send_head()

    def send_json(self, status: int, value: Any) -> None:
        body = json_bytes(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if getattr(self, "command", "GET") != "HEAD":
            self.wfile.write(body)

    def send_empty(self, status: int, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        # BaseHTTPRequestHandler 对未知 method 会直接发 501；将它也纳入
        # 客户端网段、Host 与 Digest 边界，且不反射 method/path 到 HTML。
        if code == 501:
            if self.authorize():
                self.send_empty(405, {"Allow": "GET, HEAD, POST"})
            return
        super().send_error(code, message, explain)

    def send_auth_challenge(self) -> None:
        body = ("<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\">"
                "<title>需要登录</title><h1>OpenClash同步器需要登录</h1>"
                "<p>请在浏览器登录框输入用户名和密码。</p></html>").encode()
        nonce = DIGEST_AUTH.new_nonce() if DIGEST_AUTH is not None else ""
        self.send_response(401)
        self.send_header("WWW-Authenticate", f'Digest realm="{AUTH_REALM}", nonce="{nonce}", algorithm=SHA-256, qop="auth", charset=UTF-8')
        if DIGEST_AUTH is not None and "MD5" in DIGEST_AUTH.ha1:
            self.send_header("WWW-Authenticate", f'Digest realm="{AUTH_REALM}", nonce="{nonce}", algorithm=MD5, qop="auth"')
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def client_ip(self) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        try:
            return ipaddress.ip_address(self.client_address[0])
        except ValueError:
            return None

    def header_values(self, name: str) -> list[str]:
        values = (self.headers.get_all(name) or []) if hasattr(self.headers, "get_all") else [self.headers.get(name)]
        return [value for value in values if value is not None]

    def authorize(self) -> bool:
        client = self.client_ip()
        if client is None or not any(client in network for network in ALLOWED_NETWORKS):
            self.send_empty(403)
            return False
        hosts = self.header_values("Host")
        if len(hosts) != 1 or hosts[0].lower() not in ALLOWED_HOSTS:
            self.send_empty(421)
            return False
        try:
            path = urlparse(self.path).path
        except ValueError:
            # Malformed absolute-form targets must not escape the request handler
            # or produce tracebacks. Reject before Digest/route dispatch.
            self.close_connection = True
            self.send_empty(400)
            return False
        if path == "/healthz":
            return True
        if not AUTH_REQUIRED or DIGEST_AUTH is None:
            return True
        client_text = str(client)
        if DIGEST_AUTH.rate_limited(client_text):
            self.send_empty(429, {"Retry-After": "300"})
            return False
        authorizations = self.header_values("Authorization")
        if len(authorizations) > 1:
            self.send_empty(400)
            return False
        authorization = authorizations[0] if authorizations else ""
        if authorization and DIGEST_AUTH.verify(self.command, self.path, authorization, client_text):
            return True
        self.send_auth_challenge()
        return False

    def same_origin(self) -> bool:
        origins = self.header_values("Origin")
        fetch_sites = self.header_values("Sec-Fetch-Site")
        return len(origins) == 1 and origins[0].lower() in ALLOWED_ORIGINS and len(fetch_sites) <= 1 and \
            (not fetch_sites or fetch_sites[0] == "same-origin")

    def read_json(self) -> dict[str, Any] | None:
        def invalid() -> None:
            self.close_connection = True

        if self.header_values("Transfer-Encoding"):
            return invalid()
        content_types = self.header_values("Content-Type")
        if len(content_types) != 1 or content_types[0].split(";", 1)[0].strip().lower() != "application/json":
            return invalid()
        lengths = self.header_values("Content-Length")
        if len(lengths) != 1 or re.fullmatch(r"[0-9]{1,10}", lengths[0]) is None:
            return invalid()
        length = int(lengths[0])
        if length < 2 or length > MAX_BODY:
            return invalid()
        try:
            try:
                body = self.rfile.read(length)
            finally:
                # Do not apply the intake budget to JSON parsing or Bridge work.
                self.finish_request_reading()
            if len(body) != length:
                return invalid()
            self._json_body_consumed = True
            value = json.loads(body, object_pairs_hook=unique_json_object)
        except (OSError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
            return invalid()
        return value if isinstance(value, dict) and json_shape_ok(value) else invalid()

    def do_GET(self) -> None:
        if not self.authorize():
            return
        path = urlparse(self.path).path
        if path == "/api/bootstrap":
            self.send_json(200, {"ok": True, "nonce": new_nonce(), "mode": "live" if BRIDGE.enabled else "preview",
                                 "targets": [item.__dict__ for item in TARGETS.values()]})
            return
        if path == "/api/converter/options":
            capabilities = converter.capabilities()
            capabilities["execution"]["bridge_available"] = BRIDGE.enabled
            self.send_json(200, capabilities)
            return
        if path == "/api/status":
            if BRIDGE.enabled:
                combined = BRIDGE.call_all("status")
                if not combined.get("ok"):
                    self.send_json(503, combined)
                    return
                items = [item for target in TARGETS for item in combined["results"][target].get("targets", [])]
                self.send_json(200, {"ok": True, "targets": items})
            else:
                result = BRIDGE.call({"action": "status"})
                self.send_json(200 if result.get("ok") else 503, result)
            return
        if path == "/healthz":
            self.send_json(200, {"ok": True})
            return
        if path.startswith("/api/"):
            self.send_json(404, {"ok": False, "message": "接口不存在"})
            return
        if path == "/":
            self.path = "/index.html"
        if self.command == "HEAD":
            super().do_HEAD()
        else:
            super().do_GET()

    def handle_converter(self, path: str, data: dict[str, Any]) -> None:
        # Every conversion operation is authenticated and Origin/nonce protected.
        # execute uses public pinned intake + the fixed offline native runner;
        # the editable backend URL is used ONLY when building subscription links.
        try:
            if path in {"/api/converter/router-preview", "/api/converter/router-apply"}:
                self.handle_converter_router(path, data)
                return
            if path == "/api/converter/service":
                if not converter_engine.LOCK.acquire(blocking=False):
                    raise converter.ConverterError("CONVERTER_BUSY")
                try:
                    result = converter_services.execute(data)
                finally:
                    converter_engine.LOCK.release()
            elif path == "/api/converter/tool":
                result = converter_engine.execute(data, BRIDGE, tool=True)
            elif path == "/api/converter/execute":
                result = converter_engine.execute(data, BRIDGE)
            elif path == "/api/converter/parse":
                if set(data) != {"link"}:
                    raise converter.ConverterError("REQUEST")
                parsed = converter.parse_link(data["link"])
                result = {"ok": True, "form": parsed.public_form(), "summary": parsed.summary()}
            elif path in {"/api/converter/validate", "/api/converter/link"}:
                if set(data) != {"form"}:
                    raise converter.ConverterError("REQUEST")
                parsed = converter.validate(data["form"])
                result = {"ok": True, "summary": parsed.summary()}
                if path.endswith("/link"):
                    result["link"] = parsed.link()
            else:
                self.send_json(404, {"ok": False, "message": "转换接口不存在"})
                return
        except converter.ConverterError as exc:
            status = 409 if exc.code == "CONVERTER_BUSY" else 503 if exc.code == "SANDBOX_UNAVAILABLE" else 502 if exc.code.startswith("SANDBOX") else 422
            self.send_json(status, converter.failure(exc))
            return
        self.send_json(200, result)

    def handle_converter_router(self, path: str, data: dict[str, Any]) -> None:
        """Merge against the live baseline, then use the existing guarded writer."""
        apply = path.endswith("/router-apply")
        allowed = {"target", "content", "mode", "group"} | ({"expected_sha256", "preview_sha256"} if apply else set())
        try:
            target = data.get("target")
            if set(data) - allowed or not isinstance(target, str) or target not in TARGETS or "content" not in data:
                raise converter_apply.MergeError("REQUEST")
            if not BRIDGE.enabled:
                self.send_json(503, {"ok": False, "message": "路由器连接未启用，不能预览或应用真实配置。"})
                return
            if apply and any(not isinstance(data.get(key), str) or not re.fullmatch(r"[0-9a-f]{64}", data[key]) for key in ("expected_sha256", "preview_sha256")):
                raise converter_apply.MergeError("REQUEST")
            read = BRIDGE.call({"action": "read", "target": target, "name": MAIN_CONFIG_NAME})
            if not read.get("ok"):
                self.send_json(502, read)
                return
            if not isinstance(read.get("content"), str) or read.get("sha256") != converter_apply.digest(read["content"]):
                self.send_json(502, {"ok": False, "message": "读取的主配置缺少可信摘要，未执行写入。"})
                return
            if apply and data["expected_sha256"] != read["sha256"]:
                raise converter_apply.MergeError("STALE_BASELINE")
            result = converter_apply.plan(read["content"], data["content"], mode=data.get("mode", "nodes"), group=data.get("group", ""))
            checked = validate_yaml(result["content"])
            if not checked["ok"]:
                raise converter_apply.MergeError("CONTENT")
            if apply:
                if result["sha256"] != data["preview_sha256"]:
                    raise converter_apply.MergeError("STALE_PREVIEW")
                if result["summary"]["no_change"]:
                    self.send_json(200, {"ok": True, "target": target, "no_change": True, "sha256": read["sha256"], "message": "节点和规则已存在；未执行写入或重启，本次未验证当前运行配置。"})
                    return
                written = BRIDGE.call({"action": "converter_apply", "target": target, "name": MAIN_CONFIG_NAME,
                                       "content": result["content"], "expected_sha256": read["sha256"]})
                self.send_json(200 if written.get("ok") else 502, written)
                return
            # Preview needs only the digest, groups and change summary. Keep
            # baseline credentials/server settings on the server, not in the UI.
            result.pop("content")
            result["target"] = target
            self.send_json(200, result)
        except converter_apply.MergeError as exc:
            self.send_json(409 if exc.code.startswith("STALE") else 422,
                           {"ok": False, "code": exc.code, "message": converter_apply.MESSAGES[exc.code], "router_changed": False})

    def handle_chain(self, path: str, data: dict[str, Any]) -> None:
        """Authenticated, nonce-checked chain endpoint dispatch."""
        target = data.get("target")
        if not isinstance(target, str) or target not in TARGETS:
            self.send_json(400, {"ok": False, "message": "目标路由器无效"})
            return
        action = "chain_" + path.rsplit("/", 1)[1]
        request = {"action": action, "target": target}
        allowed_fields = {"target"}
        if action == "chain_apply":
            allowed_fields |= {"operation", "expected_state_sha256", "expected_config_sha256"}
            for field in ("expected_state_sha256", "expected_config_sha256"):
                value = data.get(field)
                if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                    self.send_json(409, {"ok": False, "message": "请先读取当前链式配置，不能使用缺失或过期摘要覆盖"})
                    return
                request[field] = value
            request["operation"] = data.get("operation")
            if request["operation"] == "upsert":
                allowed_fields.add("chain")
                checked = validate_chain(data.get("chain"))
                if not checked["ok"]:
                    self.send_json(422, checked)
                    return
                request["chain"] = checked["chain"]
            elif request["operation"] == "remove" and chain_node_ok(data.get("node")):
                allowed_fields.add("node")
                request["node"] = data["node"]
            else:
                self.send_json(422, {"ok": False, "message": "链式操作或节点无效"})
                return
        elif action == "chain_test":
            allowed_fields.add("node")
            if not chain_node_ok(data.get("node")):
                self.send_json(422, {"ok": False, "message": "链式节点无效"})
                return
            request["node"] = data["node"]
        if set(data) - allowed_fields:
            self.send_json(422, {"ok": False, "message": "链式请求包含不支持的字段"})
            return
        result = BRIDGE.call(request)
        if result.get("ok"):
            result["target"] = target
        self.send_json(200 if result.get("ok") else 502, result)
        return

    def do_POST(self) -> None:
        if not self.authorize():
            return
        if not self.same_origin():
            self.send_json(403, {"ok": False, "message": "请求来源校验失败"})
            return
        path = urlparse(self.path).path
        data = self.read_json()
        if data is None:
            self.send_json(400, {"ok": False, "message": "请求格式无效或内容过大"})
            return
        if path == "/api/validate":
            content = data.get("content", "")
            if not isinstance(content, str):
                self.send_json(400, {"ok": False, "message": "YAML 配置内容必须是文本", "line": 1, "column": 1})
                return
            self.send_json(200, validate_yaml(content))
            return
        if path == "/api/chain/validate":
            checked = validate_chain(data.get("chain"))
            # Validation responses must never echo credential input.
            self.send_json(200 if checked["ok"] else 422, {key: value for key, value in checked.items() if key != "chain"})
            return
        if path == "/api/custom/validate":
            checked = validate_customization(data.get("customization"))
            self.send_json(200 if checked["ok"] else 422, checked)
            return
        if not consume_nonce(str(data.pop("nonce", ""))):
            self.send_json(409, {"ok": False, "message": "操作凭证已过期，请刷新页面后重试"})
            return
        if path.startswith("/api/converter/"):
            self.handle_converter(path, data)
            return
        if path in {"/api/chain/read", "/api/chain/apply", "/api/chain/test"}:
            self.handle_chain(path, data)
            return
        batch_actions = {"/api/stage-main": "stage_main", "/api/update-maying": "update_maying",
                         "/api/update-nexitally": "update_nexitally"}
        if path in batch_actions:
            action = batch_actions[path]
            combined = BRIDGE.call_all(action)
            if combined.get("ok"):
                labels = {"stage_main": "主配置", "update_maying": "Maying", "update_nexitally": "Nexitally"}
                combined["message"] = f"两个子网的{labels[action]}更新均已完成"
                if any("七天备份清理未完成" in result.get("message", "") for result in combined["results"].values()):
                    combined["message"] += "；至少一个子网的过期备份清理为 HOLD，旧备份已保留"
            self.send_json(200 if combined.get("ok") else 502, combined)
            return
        if path == "/api/custom/read":
            combined = BRIDGE.call_all("custom_read")
            if not combined.get("ok"):
                self.send_json(502, combined)
                return
            merged = merge_custom_reads(combined["results"])
            if merged.get("ok"):
                delta = merged["baseline_delta"]
                safe_delta = delta["rules"] + delta["fake_ip_filter"]
                unresolved = delta["unresolved_rules"] + delta["unresolved_fake_ip_filter"]
                merged["message"] = "已读取两个子网并生成统一只读视图与可安全补齐清单"
                if merged["repairable_diverged"]:
                    merged["message"] += "；当前存在可管理差异，保存后将多不删、少补齐"
                    if safe_delta:
                        merged["message"] += f"（含 {safe_delta} 条完整配置中的可安全管理差异）"
                elif not unresolved:
                    merged["message"] += "；当前两边已一致"
                if unresolved:
                    merged["message"] += f"；另有 {unresolved} 条非管理格式差异仅展示、不自动写入，需人工确认"
            if merged.get("ok"):
                self.send_json(200, public_custom_read(merged))
            else:
                self.send_json(409, merged)
            return
        if path == "/api/custom/apply":
            checked = validate_customization(data.get("customization"))
            if not checked["ok"]:
                self.send_json(422, checked)
                return
            expected_state = data.get("expected_state_sha256")
            expected_config = data.get("expected_config_sha256")
            def valid_hash_map(value: Any) -> bool:
                return isinstance(value, dict) and set(value) == set(TARGETS) and all(
                    isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)
                    for digest in value.values()
                )
            if not valid_hash_map(expected_state) or not valid_hash_map(expected_config):
                self.send_json(409, {"ok": False, "message": "缺少两个子网读取时的状态或主配置 SHA-256，请重新读取后再保存"})
                return
            customization = {"rules": checked["rules"], "fake_ip_filter": checked["fake_ip_filter"],
                             "supplemental_rules": checked["supplemental_rules"],
                             "supplemental_fake_ip_filter": checked["supplemental_fake_ip_filter"]}
            combined = BRIDGE.custom_apply_all(customization, expected_state, expected_config)
            if combined.get("ok"):
                combined["message"] = "两个子网的分流规则与 Fake-IP 黑名单已统一保存并完成各自运行态检查"
                if any("七天备份清理未完成" in result.get("message", "") for result in combined["results"].values()):
                    combined["message"] += "；至少一个子网的过期备份清理为 HOLD，旧备份已保留"
            self.send_json(200 if combined.get("ok") else 502, combined)
            return
        if path == "/api/route-check":
            value = data.get("value")
            if not isinstance(value, str) or not 1 <= len(value.encode()) <= 2048 or any(char in value for char in "\r\n\0"):
                self.send_json(400, {"ok": False, "message": "请输入有效的网址、域名或 IP"})
                return
            source_ip = self.client_address[0]
            try:
                ipaddress.ip_address(source_ip)
            except ValueError:
                self.send_json(400, {"ok": False, "message": "客户端来源地址无效，无法建立判路上下文"})
                return
            combined = BRIDGE.call_all("route_check", {
                target: {"value": value.strip(), "source_ip": source_ip} for target in TARGETS
            })
            if combined.get("ok"):
                combined["message"] = "已按两个子网当前运行规则完成判定；可达性只使用固定健康探针，不会请求输入的网址"
            self.send_json(200 if combined.get("ok") else 502, combined)
            return
        target = str(data.get("target", ""))
        if target not in TARGETS:
            self.send_json(400, {"ok": False, "message": "目标子网无效"})
            return
        allowed = {"/api/read": "read", "/api/write": "write", "/api/rollback": "rollback"}
        action = allowed.get(path)
        if not action:
            self.send_json(404, {"ok": False, "message": "接口不存在"})
            return
        request: dict[str, Any] = {"action": action, "target": target}
        if action == "read":
            name = str(data.get("name", ""))
            if not NAME_RE.fullmatch(name.removesuffix(".yaml")):
                self.send_json(400, {"ok": False, "message": "文件名只能包含字母、数字、下划线和短横线"})
                return
            request["name"] = name.removesuffix(".yaml") + ".yaml"
        if action == "write":
            name, content, expected = data.get("name", ""), data.get("content", ""), data.get("expected_sha256", "")
            if not all(isinstance(value, str) for value in (name, content, expected)):
                self.send_json(400, {"ok": False, "message": "文件名、配置内容和 SHA-256 必须是文本"})
                return
            if not NAME_RE.fullmatch(name.removesuffix(".yaml")):
                self.send_json(400, {"ok": False, "message": "文件名只能包含字母、数字、下划线和短横线"})
                return
            normalized_name = name.removesuffix(".yaml") + ".yaml"
            if normalized_name != MAIN_CONFIG_NAME:
                self.send_json(409, {"ok": False, "message": "机场源文件仅允许只读浏览；请使用对应的受控更新操作"})
                return
            checked = validate_yaml(content)
            if not checked["ok"]:
                self.send_json(422, checked)
                return
            if not re.fullmatch(r"[0-9a-f]{64}", expected):
                self.send_json(409, {"ok": False, "message": "缺少读取时的 SHA-256，不能防止并发覆盖"})
                return
            request.update({"name": normalized_name, "content": content, "expected_sha256": expected})
        if action == "rollback":
            phrase = str(data.get("confirmation", ""))
            if not valid_rollback_phrase(phrase):
                self.send_json(400, {"ok": False, "message": "请输入完整确认短语：确认回滚主配置"})
                return
        result = BRIDGE.call(request)
        self.send_json(200 if result.get("ok") else 502, result)

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_OPTIONS(self) -> None:
        if self.authorize():
            self.send_empty(405, {"Allow": "GET, HEAD, POST"})

    def method_not_allowed(self) -> None:
        if self.authorize():
            self.send_empty(405, {"Allow": "GET, HEAD, POST"})

    do_PUT = method_not_allowed
    do_PATCH = method_not_allowed
    do_DELETE = method_not_allowed
    do_TRACE = method_not_allowed
    do_CONNECT = method_not_allowed


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Bound slow or malicious LAN clients before they consume all TasksMax."""

    def __init__(self, *args: Any, max_threads: int = MAX_HTTP_THREADS, **kwargs: Any) -> None:
        if not 1 <= max_threads <= 128:
            raise ValueError("invalid HTTP thread budget")
        self._request_slots = threading.BoundedSemaphore(max_threads)
        super().__init__(*args, **kwargs)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


def main() -> None:
    host = os.environ.get("OPENCLASH_WEB_HOST", "127.0.0.1")
    try:
        port = int(os.environ.get("OPENCLASH_WEB_PORT", "8088"))
    except ValueError as exc:
        raise RuntimeError("OPENCLASH_WEB_PORT 必须是整数") from exc
    try:
        bind_address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise RuntimeError("OPENCLASH_WEB_HOST 必须是明确的 IP 地址") from exc
    if bool(AUTH_USER) != bool(AUTH_HA1_FILE):
        raise RuntimeError("Digest 登录认证必须同时配置用户名与 HA1 文件")
    if not AUTH_REQUIRED:
        raise RuntimeError("Digest 登录认证必须启用，即使服务仅监听回环地址")
    if AUTH_USER and not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", AUTH_USER):
        raise RuntimeError("Digest 登录用户名格式无效")
    if bind_address.is_loopback:
        if not ALLOWED_NETWORKS or any(not network.is_loopback for network in ALLOWED_NETWORKS):
            raise RuntimeError("回环监听只允许回环客户端网段")
    elif bind_address == LAN_BIND_ADDRESS:
        if frozenset(ALLOWED_NETWORKS) != LAN_CLIENT_NETWORKS:
            raise RuntimeError("LAN 监听只允许离线渲染绑定的客户端网段")
        expected_host = f"{LAN_BIND_ADDRESS}:{port}"
        if ALLOWED_HOSTS != {expected_host} or ALLOWED_ORIGINS != {f"http://{expected_host}"}:
            raise RuntimeError("LAN 监听只允许与 192.0.2.20 端口一致的精确 HTTP Host 和 Origin")
        if not root_owned_directory_chain(STATIC):
            raise RuntimeError("LAN 监听要求 static 目录链由 root 持有且不可被组或其他用户写入")
    else:
        raise RuntimeError("OPENCLASH_WEB_HOST 只允许回环地址或 192.0.2.20")
    if not 1 <= port <= 65535:
        raise RuntimeError("OPENCLASH_WEB_PORT 必须在 1 到 65535 之间")
    server = BoundedThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    print(f"OpenClash 中文管理台：http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
