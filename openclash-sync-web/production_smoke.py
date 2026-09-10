#!/usr/bin/env python3
"""生产 Web 只读/校验冒烟测试；不打印密码、配置内容或订阅数据。"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import re
import secrets
from pathlib import Path

from prepare_web_auth import load_local_password

HOST = "192.0.2.20"
PORT = 8088
AUTH_USER = "openclash-admin"
AUTH_REALM = "OpenClash Sync"
ORIGIN = f"http://{HOST}:{PORT}"
TARGETS = {"router_a", "router_b"}


def request(method: str, path: str, password: str, body: dict | None = None,
            same_origin: bool = True, timeout: float = 30,
            algorithm: str = "SHA-256") -> tuple[int, dict[str, str], bytes]:
    payload = None if body is None else json.dumps(body, ensure_ascii=False).encode()
    headers = {"Host": f"{HOST}:{PORT}"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
        if same_origin:
            headers.update({"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin"})
    # Digest 的第一次请求只用于取得挑战；不要在尚未认证时发送整份配置，
    # 否则服务端返回 401 并关闭连接时，大请求可能在客户端表现为 BrokenPipe。
    challenge_payload = b"{}" if payload is not None else None
    first = http.client.HTTPConnection(HOST, PORT, timeout=15)
    first.request(method, path, body=challenge_payload, headers=headers)
    challenge_response = first.getresponse()
    challenge_header_pairs = challenge_response.getheaders()
    challenge_headers = {key.lower(): value for key, value in challenge_header_pairs}
    challenge_response.read()
    first.close()
    if challenge_response.status != 401:
        return challenge_response.status, challenge_headers, b""
    challenges = [value for key, value in challenge_header_pairs if key.lower() == "www-authenticate"]
    challenge = next((value for value in challenges if f"algorithm={algorithm}" in value), "")
    nonce_match = re.search(r'nonce="([^"]+)"', challenge)
    if not nonce_match:
        raise RuntimeError(f"Digest {algorithm} challenge 无效")
    nonce = nonce_match.group(1)
    nc, cnonce = "00000001", secrets.token_hex(12)
    def digest(value: bytes) -> str:
        if algorithm == "SHA-256":
            return hashlib.sha256(value).hexdigest()
        return hashlib.md5(value, usedforsecurity=False).hexdigest()

    ha1 = digest(f"{AUTH_USER}:{AUTH_REALM}:{password}".encode())
    ha2 = digest(f"{method}:{path}".encode())
    response = digest(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}".encode())
    headers["Authorization"] = (
        f'Digest username="{AUTH_USER}", realm="{AUTH_REALM}", nonce="{nonce}", '
        f'uri="{path}", algorithm={algorithm}, response="{response}", qop=auth, '
        f'nc={nc}, cnonce="{cnonce}"'
    )
    connection = http.client.HTTPConnection(HOST, PORT, timeout=timeout)
    connection.request(method, path, body=payload, headers=headers)
    result = connection.getresponse()
    result_headers = {key.lower(): value for key, value in result.getheaders()}
    result_body = result.read()
    status = result.status
    connection.close()
    return status, result_headers, result_body


def json_request(method: str, path: str, password: str, body: dict | None = None) -> dict:
    status, _, payload = request(method, path, password, body)
    if status != 200:
        raise RuntimeError(f"{path} 返回 HTTP {status}")
    value = json.loads(payload)
    if not isinstance(value, dict) or value.get("ok") is not True:
        raise RuntimeError(f"{path} 响应结构无效")
    return value


def nonce(password: str) -> str:
    value = json_request("GET", "/api/bootstrap", password).get("nonce")
    if not isinstance(value, str) or len(value) < 20:
        raise RuntimeError("一次性操作凭证无效")
    return value


def write_unchanged(password: str, target: str, name: str) -> None:
    """读取后原样写回，验证编辑路径但不改变配置摘要。"""
    current = json_request("POST", "/api/read", password, {
        "nonce": nonce(password), "target": target, "name": name,
    })
    content, digest = current.get("content"), current.get("sha256")
    if not isinstance(content, str) or not isinstance(digest, str):
        raise RuntimeError("受管配置读取结果无效")
    written = json_request("POST", "/api/write", password, {
        "nonce": nonce(password), "target": target, "name": name,
        "content": content, "expected_sha256": digest,
    })
    if written.get("sha256") != digest:
        raise RuntimeError("无变化编辑导致配置摘要变化")


def require(condition: object, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def validate_homepage(status: int, page: bytes, expected_page: bytes, auth_label: str) -> None:
    """以当前发布的完整首页为准，不耦合可变的展示标题。"""
    require(status == 200 and page == expected_page and b"OpenClash_Sync_Logo.png" in expected_page,
            f"{auth_label} 登录或首页内容无效")


def validate_custom_read(custom: dict) -> dict[str, int]:
    """只验证公开定制响应的类型/形状，不要求用户当前定制为空。"""
    lists = {
        "rules": custom.get("rules"),
        "fake_ip_filter": custom.get("fake_ip_filter"),
        "supplemental_rules": custom.get("supplemental_rules"),
        "supplemental_fake_ip_filter": custom.get("supplemental_fake_ip_filter"),
        "unowned_configured_rules": custom.get("unowned_configured_rules"),
        "unowned_rule_matcher_overrides": custom.get("unowned_rule_matcher_overrides"),
    }
    require(all(isinstance(value, list) for value in lists.values()), "双子网定制公开清单形状无效")
    require(all(isinstance(rule, dict) and all(isinstance(rule.get(key), str) and rule.get(key)
                                               for key in ("type", "value", "policy"))
                for rule in lists["rules"]), "双子网定制规则形状无效")
    for field in ("fake_ip_filter", "supplemental_rules", "supplemental_fake_ip_filter",
                  "unowned_configured_rules"):
        require(all(isinstance(item, str) and item for item in lists[field]), f"{field} 清单形状无效")
    require(all(isinstance(item, list) and len(item) == 3 and
                isinstance(item[0], int) and item[0] >= 0 and
                isinstance(item[1], str) and item[1] and isinstance(item[2], str) and item[2]
                for item in lists["unowned_rule_matcher_overrides"]),
            "规范 matcher 覆盖清单形状无效")
    return {field: len(value) for field, value in lists.items()}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write-check",
        action="store_true",
        help="经 SSH 隧道在两台路由器各执行一次主配置读取后原样保存；会创建备份但不改变摘要",
    )
    parser.add_argument(
        "--candidate-auth",
        action="store_true",
        help="使用尚未 promote 的 .next 候选凭据；仅限远端更新已 COMMITTED 后的验收",
    )
    parser.add_argument(
        "--expect-legacy-md5",
        action="store_true",
        help="显式要求 MD5 challenge/login；默认要求 SHA-256-only",
    )
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent
    password = load_local_password(root, candidate=args.candidate_auth)

    connection = http.client.HTTPConnection(HOST, PORT, timeout=10)
    connection.request("GET", "/", headers={"Host": f"{HOST}:{PORT}"})
    unauthenticated = connection.getresponse()
    challenges = [value for key, value in unauthenticated.getheaders() if key.lower() == "www-authenticate"]
    challenge = next((value for value in challenges if "algorithm=SHA-256" in value), "")
    fallback = next((value for value in challenges if "algorithm=MD5" in value), "")
    content_type = unauthenticated.getheader("Content-Type", "")
    content_length = int(unauthenticated.getheader("Content-Length", "0"))
    unauthenticated.read()
    connection.close()
    require(unauthenticated.status == 401 and "algorithm=SHA-256" in challenge, "SHA-256 Digest challenge 无效")
    require(content_type.startswith("text/html") and content_length > 0, "401 必须返回非空 HTML")
    if args.expect_legacy_md5:
        require("algorithm=MD5" in fallback, "已要求 MD5 兼容，但 challenge 缺失")
    else:
        require(not fallback, "默认 SHA-256-only 模式不应暴露 MD5 challenge")

    connection = http.client.HTTPConnection(HOST, PORT, timeout=10)
    connection.request("GET", "/", headers={"Host": "invalid.example"})
    wrong_host = connection.getresponse()
    wrong_host.read()
    connection.close()
    require(wrong_host.status == 421, "错误 Host 未被 421 拒绝")

    expected_page = (root / "static" / "index.html").read_bytes()
    status, headers, page = request("GET", "/", password)
    validate_homepage(status, page, expected_page, "SHA-256")
    if args.expect_legacy_md5:
        md5_status, _, md5_page = request("GET", "/", password, algorithm="MD5")
        validate_homepage(md5_status, md5_page, expected_page, "MD5")
    for required in ("content-security-policy", "x-frame-options", "permissions-policy", "cache-control"):
        require(required in headers, f"缺少安全响应头：{required}")

    bootstrap = json_request("GET", "/api/bootstrap", password)
    require(bootstrap.get("mode") == "live" and isinstance(bootstrap.get("nonce"), str), "bootstrap 运行模式无效")
    status_data = json_request("GET", "/api/status", password)
    targets = status_data.get("targets", [])
    require({item.get("id") for item in targets} == {"router_a", "router_b"}, "路由器目标集合无效")
    require(all(item.get("state") == "运行中" for item in targets), "至少一台路由器不在运行中")

    managed = ("ProviderBase-ProviderSource.yaml", "ProviderSource.yaml", "ProviderBase.yaml")
    read_count = 0
    for target in ("router_a", "router_b"):
        for name in managed:
            result = json_request("POST", "/api/read", password, {
                "nonce": nonce(password), "target": target, "name": name,
            })
            content, digest = result.get("content"), result.get("sha256")
            require(isinstance(content, str) and len(content) > 100, "受管配置内容无效")
            require(isinstance(digest, str) and hashlib.sha256(content.encode()).hexdigest() == digest,
                    "受管配置摘要无效")
            read_count += 1
    custom = json_request("POST", "/api/custom/read", password, {"nonce": nonce(password)})
    custom_counts = validate_custom_read(custom)
    for field in ("state_sha256", "config_sha256"):
        digests = custom.get(field)
        require(isinstance(digests, dict) and set(digests) == TARGETS and
                all(re.fullmatch(r"[0-9a-f]{64}", value) for value in digests.values()),
                f"双子网 {field} 摘要无效")
    groups = custom.get("groups")
    require(isinstance(groups, list) and "AI" in groups and "Google" in groups and "🎯Direct" in groups,
            "双子网共同业务分组集合无效")

    validation = json_request("POST", "/api/custom/validate", password, {"customization": {
        "rules": [
            {"type": "DOMAIN", "value": "api.example.com", "policy": "DIRECT"},
            {"type": "IP-CIDR", "value": "192.0.2.123/24", "policy": "AI"},
        ],
        "fake_ip_filter": ["*.example.com"],
    }})
    require(validation.get("summary") == {"rules": 2, "fake_ip_filter": 1}, "合法定制校验摘要无效")

    invalid_status, _, invalid_payload = request("POST", "/api/custom/validate", password, {"customization": {
        "rules": [{"type": "IP-CIDR", "value": "999.1.1.1/24", "policy": "DIRECT"}],
        "fake_ip_filter": ["*"],
    }})
    invalid = json.loads(invalid_payload)
    require(invalid_status == 422 and len(invalid.get("errors", [])) == 2, "非法定制未被精确拒绝")
    require({item.get("section") for item in invalid["errors"]} == {"rules", "fake_ip_filter"},
            "非法定制错误位置无效")

    if args.write_check:
        for target in ("router_a", "router_b"):
            write_unchanged(password, target, "ProviderBase-ProviderSource.yaml")

    cross_status, _, _ = request("POST", "/api/custom/validate", password, {
        "customization": {"rules": [], "fake_ip_filter": []},
    }, same_origin=False)
    require(cross_status == 403, "跨站 POST 未被拒绝")

    print("DIRECT_HTTP=PASS")
    print("DIGEST_SHA256=PASS")
    print(f"SAFARI_DIGEST_FALLBACK={'PASS' if args.expect_legacy_md5 else 'DISABLED_AS_EXPECTED'}")
    print("HOST_ORIGIN_HEADERS=PASS")
    print("TITLE_LOGO=PASS")
    print("DUAL_ROUTER_STATUS=PASS")
    print(f"MANAGED_FILE_READS={read_count}/6_PASS")
    print(f"CUSTOM_READ_COMMON_GROUPS={len(groups)}_PASS")
    print("CUSTOM_READ_SHAPE=PASS|" + "|".join(
        f"{field}={custom_counts[field]}" for field in
        ("rules", "fake_ip_filter", "supplemental_rules", "supplemental_fake_ip_filter")
    ))
    print("CUSTOM_VALIDATION=PASS")
    print("CHINESE_ERROR_LOCATOR=PASS")
    print(f"MANAGED_FILE_NOOP_WRITES={'2/2_PASS' if args.write_check else 'SKIPPED'}")
    print("CROSS_SITE_POST=REJECTED")


if __name__ == "__main__":
    main()
