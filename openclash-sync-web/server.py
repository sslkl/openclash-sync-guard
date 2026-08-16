#!/usr/bin/env python3
"""OpenClash 同步器中文管理台（worker host 本地 Web 服务）。"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import stat
import subprocess
import threading
import time
from dataclasses import dataclass
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml
from yaml.tokens import AliasToken, AnchorToken


ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
MAX_BODY = 2 * 1024 * 1024
MAX_CONFIG = 1024 * 1024
MAX_YAML_NODES = 100_000
MAX_YAML_DEPTH = 64
NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
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
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$", re.I)
CUSTOM_RULE_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "IP-CIDR", "IP-CIDR6"}
MAX_CUSTOM_ITEMS = 256
MAX_AUTH_NONCES = 1024
MAX_AUTH_REPLAY = 4096
MAX_AUTH_FAILURE_CLIENTS = 1024
MAX_OPERATION_NONCES = 1024
MAX_JSON_NODES = 20_000
MAX_JSON_DEPTH = 32


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


def yaml_error(exc: yaml.YAMLError) -> dict[str, Any]:
    mark = getattr(exc, "problem_mark", None)
    problem = getattr(exc, "problem", None) or "YAML 语法不正确"
    return {
        "ok": False,
        "message": f"YAML 语法错误：{problem}",
        "line": mark.line + 1 if mark else None,
        "column": mark.column + 1 if mark else None,
    }


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
        tokens = 0
        for token in yaml.scan(content):
            tokens += 1
            if tokens > MAX_YAML_NODES * 4:
                return {"ok": False, "message": "YAML 词法项目过多", "line": 1, "column": 1}
            if isinstance(token, (AliasToken, AnchorToken)):
                return {"ok": False, "message": "YAML 不允许锚点或别名", "line": token.start_mark.line + 1,
                        "column": token.start_mark.column + 1}
        parsed = yaml.safe_load(content)
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
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size > 128 or info.st_mode & 0o022:
            raise RuntimeError("Web 登录认证摘要文件权限或类型无效")
        lines = path.read_text(encoding="ascii").splitlines()
    except OSError as exc:
        raise RuntimeError("无法读取 Web 登录认证摘要") from exc
    if len(lines) == 1 and re.fullmatch(r"[0-9a-f]{64}", lines[0].lower()):
        return {"SHA-256": lines[0].lower()}
    values: dict[str, str] = {}
    for line in lines:
        if line.startswith("sha256:") and re.fullmatch(r"[0-9a-f]{64}", line[7:].lower()):
            values["SHA-256"] = line[7:].lower()
        elif line.startswith("md5:") and re.fullmatch(r"[0-9a-f]{32}", line[4:].lower()):
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
    if normalized.startswith("*.") or normalized.startswith("+."):
        prefix, normalized = normalized[:2], normalized[2:]
    domain = normalize_domain(normalized)
    return prefix + domain if domain else None


def validate_customization(value: Any) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    if not isinstance(value, dict):
        return {"ok": False, "message": "定制内容必须是对象", "errors": [{"section": "root", "index": 0, "field": "root", "message": "请求格式无效"}]}
    rules = value.get("rules", [])
    filters = value.get("fake_ip_filter", [])
    if not isinstance(rules, list):
        errors.append({"section": "rules", "index": 0, "field": "rules", "message": "分流规则必须是列表"})
        rules = []
    if not isinstance(filters, list):
        errors.append({"section": "fake_ip_filter", "index": 0, "field": "fake_ip_filter", "message": "Fake-IP Filter 必须是列表"})
        filters = []
    if len(rules) > MAX_CUSTOM_ITEMS:
        errors.append({"section": "rules", "index": MAX_CUSTOM_ITEMS, "field": "rules", "message": f"分流规则最多 {MAX_CUSTOM_ITEMS} 条"})
    if len(filters) > MAX_CUSTOM_ITEMS:
        errors.append({"section": "fake_ip_filter", "index": MAX_CUSTOM_ITEMS, "field": "fake_ip_filter", "message": f"Fake-IP Filter 最多 {MAX_CUSTOM_ITEMS} 条"})
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
        if not policy or len(policy.encode()) > 128 or any(char in policy for char in "\r\n,"):
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
                errors.append({"section": "rules", "index": index, "field": "value", "message": "同一匹配条件不能重复定义"})
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
            errors.append({"section": "fake_ip_filter", "index": index, "field": "value", "message": "Fake-IP Filter 条目重复"})
        else:
            seen_filters.add(normalized)
            normalized_filters.append(normalized)
    if errors:
        return {"ok": False, "message": f"发现 {len(errors)} 个输入错误", "errors": errors}
    return {"ok": True, "message": "分流与 Fake-IP Filter 语法检查通过", "rules": normalized_rules,
            "fake_ip_filter": normalized_filters, "summary": {"rules": len(normalized_rules), "fake_ip_filter": len(normalized_filters)}}


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
            self.record_failure(client); return False
        fields = self.parse(header)
        required = {"username", "realm", "nonce", "uri", "response", "qop", "nc", "cnonce"}
        if not required.issubset(fields) or fields.get("username") != AUTH_USER or fields.get("realm") != AUTH_REALM:
            self.record_failure(client); return False
        algorithm = fields.get("algorithm", "MD5").upper()
        if fields.get("uri") != uri or fields.get("qop") != "auth" or algorithm not in self.ha1:
            self.record_failure(client); return False
        if not re.fullmatch(r"[0-9a-fA-F]{8}", fields["nc"]) or not re.fullmatch(r"[A-Za-z0-9._~-]{8,128}", fields["cnonce"]):
            self.record_failure(client); return False
        digest_size = 64 if algorithm == "SHA-256" else 32
        if not re.fullmatch(rf"[0-9a-fA-F]{{{digest_size}}}", fields["response"]):
            self.record_failure(client); return False
        try:
            nc = int(fields["nc"], 16)
        except ValueError:
            self.record_failure(client); return False
        ha2 = self.digest_hex(algorithm, f"{method}:{uri}".encode())
        expected = self.digest_hex(
            algorithm,
            f"{self.ha1[algorithm]}:{fields['nonce']}:{fields['nc']}:{fields['cnonce']}:auth:{ha2}".encode(),
        )
        if not hmac.compare_digest(expected, fields["response"].lower()):
            self.record_failure(client); return False
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
        lock = self.operation_lock if action != "status" else None
        if lock is not None and not lock.acquire(blocking=False):
            return {"ok": False, "message": "该路由器正在执行另一项操作，请等待完成后重试"}
        try:
            command = [self.helper] if os.geteuid() == 0 else ["/usr/bin/sudo", "-n", self.helper]
            proc = subprocess.run(
                command, input=json_bytes(request), stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, timeout=360, check=False,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            )
        except (OSError, subprocess.TimeoutExpired):
            return {"ok": False, "message": "受控执行器不可用或执行超时"}
        finally:
            if lock is not None:
                lock.release()
        if proc.returncode != 0 or len(proc.stdout) > MAX_BODY:
            return {"ok": False, "message": "远端操作未通过安全检查，未提交任何变更"}
        try:
            result = json.loads(proc.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
            return {"ok": False, "message": "受控执行器返回格式无效"}
        return result if isinstance(result, dict) and json_shape_ok(result) and isinstance(result.get("ok"), bool) \
            else {"ok": False, "message": "返回值类型无效"}

    @staticmethod
    def demo(request: dict[str, Any]) -> dict[str, Any]:
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
        if action == "custom_read":
            return {"ok": True, "mode": "preview", "groups": ["DIRECT", "Proxies", "AI"],
                    "rules": [], "fake_ip_filter": [], "state_sha256": hashlib.sha256(b"").hexdigest(),
                    "message": "预览模式：部署受控执行器后读取真实定制项"}
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


class Handler(SimpleHTTPRequestHandler):
    server_version = "OpenClashSyncWeb"
    sys_version = ""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(STATIC), **kwargs)

    def setup(self) -> None:
        super().setup()
        # 限制慢速请求占用线程；远端操作的墙钟超时由 Bridge 单独控制。
        self.connection.settimeout(30)

    def log_message(self, fmt: str, *args: Any) -> None:
        # 不记录请求体、查询参数、配置内容或订阅地址。
        print(f"{self.address_string()} {self.command} {urlparse(self.path).path}")

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        super().end_headers()

    def send_json(self, status: int, value: Any) -> None:
        body = json_bytes(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_empty(self, status: int, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", "0")
        self.end_headers()

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
        values = self.headers.get_all(name) if hasattr(self.headers, "get_all") else [self.headers.get(name)]
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
        path = urlparse(self.path).path
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
            return None

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
            body = self.rfile.read(length)
            if len(body) != length:
                return invalid()
            value = json.loads(body)
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
        if path == "/api/status":
            if BRIDGE.enabled:
                items = []
                for target in TARGETS:
                    result = BRIDGE.call({"action": "status", "target": target})
                    if not result.get("ok"):
                        self.send_json(503, result)
                        return
                    items.extend(result.get("targets", []))
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
        super().do_GET()

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
        if path == "/api/custom/validate":
            checked = validate_customization(data.get("customization"))
            self.send_json(200 if checked["ok"] else 422, checked)
            return
        if not consume_nonce(str(data.pop("nonce", ""))):
            self.send_json(409, {"ok": False, "message": "操作凭证已过期，请刷新页面后重试"})
            return
        target = str(data.get("target", ""))
        if target not in TARGETS:
            self.send_json(400, {"ok": False, "message": "目标路由器无效"})
            return
        allowed = {"/api/read": "read", "/api/stage-main": "stage_main",
                   "/api/update-maying": "update_maying", "/api/update-nexitally": "update_nexitally",
                   "/api/write": "write", "/api/rollback": "rollback",
                   "/api/custom/read": "custom_read", "/api/custom/apply": "custom_apply"}
        action = allowed.get(path)
        if not action:
            self.send_json(404, {"ok": False, "message": "接口不存在"})
            return
        request: dict[str, Any] = {"action": action, "target": target}
        if action == "custom_apply":
            checked = validate_customization(data.get("customization"))
            if not checked["ok"]:
                self.send_json(422, checked)
                return
            request["customization"] = {"rules": checked["rules"], "fake_ip_filter": checked["fake_ip_filter"]}
            expected_state = data.get("expected_state_sha256")
            if not isinstance(expected_state, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_state):
                self.send_json(409, {"ok": False, "message": "缺少读取时的定制状态 SHA-256，请重新读取后再保存"})
                return
            request["expected_state_sha256"] = expected_state
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
            checked = validate_yaml(content)
            if not checked["ok"]:
                self.send_json(422, checked)
                return
            if not re.fullmatch(r"[0-9a-f]{64}", expected):
                self.send_json(409, {"ok": False, "message": "缺少读取时的 SHA-256，不能防止并发覆盖"})
                return
            request.update({"name": name.removesuffix(".yaml") + ".yaml", "content": content, "expected_sha256": expected})
        if action == "rollback":
            phrase = str(data.get("confirmation", ""))
            if not valid_rollback_phrase(phrase):
                self.send_json(400, {"ok": False, "message": "请输入完整确认短语：确认回滚主配置"})
                return
        result = BRIDGE.call(request)
        self.send_json(200 if result.get("ok") else 502, result)

    def do_HEAD(self) -> None:
        if self.authorize():
            super().do_HEAD()

    def do_OPTIONS(self) -> None:
        if self.authorize():
            self.send_empty(405, {"Allow": "GET, HEAD, POST"})


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
    if AUTH_USER and not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", AUTH_USER):
        raise RuntimeError("Digest 登录用户名格式无效")
    if not bind_address.is_loopback and not AUTH_REQUIRED:
        raise RuntimeError("非回环监听必须配置 Digest 登录认证")
    if not bind_address.is_loopback:
        auth_path = Path(AUTH_HA1_FILE)
        if auth_path.stat().st_uid != 0 or not root_owned_directory_chain(auth_path.parent):
            raise RuntimeError("非回环监听要求认证摘要文件及目录链由 root 控制")
    if not 1 <= port <= 65535:
        raise RuntimeError("OPENCLASH_WEB_PORT 必须在 1 到 65535 之间")
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    print(f"OpenClash 中文管理台：http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
