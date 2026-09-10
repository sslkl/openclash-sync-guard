#!/usr/bin/env python3
"""对两个子网执行可逆定制生产验收，最终清空测试定制。"""

from __future__ import annotations

import argparse
import json
import re
import time
from http.client import HTTPException
from pathlib import Path

from production_smoke import json_request, load_local_password, nonce, request

TEST_RULES = [
    {"type": "DOMAIN", "value": "syncsvc-openclash-audit.invalid", "policy": "DIRECT"},
    {"type": "IP-CIDR", "value": "192.0.2.123/24", "policy": "AI"},
    {"type": "IP-CIDR6", "value": "2001:db8:ffff::1/64", "policy": "Proxies"},
]
TEST_FILTERS = ["*.syncsvc-openclash-audit.invalid"]


TARGETS = {"router_a", "router_b"}
CUSTOM_FIELDS = (
    "rules", "fake_ip_filter", "supplemental_rules", "supplemental_fake_ip_filter",
)


def valid_hash_map(value: object) -> bool:
    return isinstance(value, dict) and set(value) == TARGETS and all(
        isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) for digest in value.values()
    )


def custom_read(secret: str) -> dict:
    value = json_request("POST", "/api/custom/read", secret, {
        "nonce": nonce(secret),
    })
    if not valid_hash_map(value.get("state_sha256")) or not valid_hash_map(value.get("config_sha256")):
        raise RuntimeError("双子网定制状态或主配置摘要无效")
    if not isinstance(value.get("supplemental_rules"), list) or \
            not isinstance(value.get("supplemental_fake_ip_filter"), list):
        raise RuntimeError("完整规则补齐清单无效")
    return value


def apply(secret: str, current: dict, rules: list[dict], filters: list[str]) -> dict:
    body = {
        "nonce": nonce(secret),
        "expected_state_sha256": current["state_sha256"],
        "expected_config_sha256": current["config_sha256"],
        "customization": {"rules": rules, "fake_ip_filter": filters,
                          "supplemental_rules": current["supplemental_rules"],
                          "supplemental_fake_ip_filter": current["supplemental_fake_ip_filter"]},
    }
    status, _, payload = request("POST", "/api/custom/apply", secret, body, timeout=420)
    if status != 200:
        try:
            message = json.loads(payload).get("message", "操作失败")
        except (UnicodeDecodeError, json.JSONDecodeError):
            message = "操作失败"
        raise RuntimeError(f"定制提交返回 HTTP {status}：{message}")
    value = json.loads(payload)
    if value.get("ok") is not True:
        raise RuntimeError("定制提交未通过")
    return value


def verify_noop_preserved(before: dict, result: dict, after: dict) -> None:
    results = result.get("results")
    if not isinstance(results, dict) or set(results) != TARGETS or not all(
        isinstance(value, dict) and value.get("ok") is True and
        "主配置内容未变化" in value.get("message", "")
        for value in results.values()
    ):
        raise RuntimeError("幂等提交未取得双端无变化回执")
    if set(result.get("completed", [])) != TARGETS or result.get("failed") is not None:
        raise RuntimeError("幂等提交未完整覆盖两个子网")
    for field in CUSTOM_FIELDS:
        if after.get(field) != before.get(field):
            raise RuntimeError(f"幂等提交后 {field} 发生变化")
    for field in ("state_sha256", "config_sha256"):
        if after.get(field) != before.get(field):
            raise RuntimeError(f"幂等提交后 {field} 发生变化")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--candidate-auth",
        action="store_true",
        help="使用远端已 COMMITTED、尚未 promote 的 .next 候选凭据",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--noop-current",
        action="store_true",
        help="原样提交当前定制并要求双端摘要不变；不创建或清空测试规则",
    )
    mode.add_argument(
        "--temporary-roundtrip",
        action="store_true",
        help="仅在双端定制为空时临时添加测试规则并清空；会改变配置并重启",
    )
    args = parser.parse_args(argv)
    secret = load_local_password(Path(__file__).resolve().parent, candidate=args.candidate_auth)
    baseline = custom_read(secret)
    if args.noop_current:
        print("TARGETS=router_a,router_b")
        print("BASELINE_CUSTOM=PRESERVED")
        started = time.monotonic()
        result = apply(secret, baseline, baseline["rules"], baseline["fake_ip_filter"])
        current = custom_read(secret)
        verify_noop_preserved(baseline, result, current)
        print(f"CUSTOM_NOOP_APPLY=PASS|seconds={time.monotonic() - started:.1f}")
        print("CUSTOM_STATE_AFTER=UNCHANGED")
        return
    if baseline.get("rules") or baseline.get("fake_ip_filter") or baseline.get("supplemental_rules") or \
            baseline.get("supplemental_fake_ip_filter"):
        raise RuntimeError("双子网已有用户定制或完整补齐项，生产验收拒绝覆盖")

    print("TARGETS=router_a,router_b")
    print("BASELINE_CUSTOM=EMPTY")
    attempted = False
    try:
        started = time.monotonic()
        attempted = True
        apply(secret, baseline, TEST_RULES, TEST_FILTERS)
        current = custom_read(secret)
        expected_rules = [
            {"type": "DOMAIN", "value": "syncsvc-openclash-audit.invalid", "policy": "DIRECT"},
            {"type": "IP-CIDR", "value": "192.0.2.0/24", "policy": "AI"},
            {"type": "IP-CIDR6", "value": "2001:db8:ffff::/64", "policy": "Proxies"},
        ]
        if current.get("rules") != expected_rules or current.get("fake_ip_filter") != TEST_FILTERS:
            raise RuntimeError("保存后定制读取结果不匹配")
        if current.get("supplemental_rules") or current.get("supplemental_fake_ip_filter"):
            raise RuntimeError("验收过程中出现意外完整补齐项")
        print(f"CUSTOM_APPLY=PASS|seconds={time.monotonic() - started:.1f}")
        print("NORMALIZATION=PASS")
    finally:
        if attempted:
            last_error: Exception | None = None
            current = None
            for _ in range(12):
                try:
                    current = custom_read(secret)
                    break
                except (
                    HTTPException,
                    OSError,
                    UnicodeDecodeError,
                    json.JSONDecodeError,
                    RuntimeError,
                ) as exc:  # 网络/重启窗口：有界重试后仍失败才上抛
                    last_error = exc
                    time.sleep(5)
            if current is None:
                raise RuntimeError(f"无法确认测试定制状态，必须人工恢复：{last_error}")
            current_rules = current.get("rules")
            current_filters = current.get("fake_ip_filter")
            if current_rules or current_filters:
                normalized_test_rules = [
                    {"type": "DOMAIN", "value": "syncsvc-openclash-audit.invalid", "policy": "DIRECT"},
                    {"type": "IP-CIDR", "value": "192.0.2.0/24", "policy": "AI"},
                    {"type": "IP-CIDR6", "value": "2001:db8:ffff::/64", "policy": "Proxies"},
                ]
                if current_rules != normalized_test_rules or current_filters != TEST_FILTERS:
                    raise RuntimeError("发现非本验收创建的定制，拒绝自动清理")
                started = time.monotonic()
                apply(secret, current, [], [])
                print(f"CUSTOM_CLEAR=PASS|seconds={time.monotonic() - started:.1f}")
            cleared = custom_read(secret)
            if cleared.get("rules") or cleared.get("fake_ip_filter") or cleared.get("supplemental_rules") or \
                    cleared.get("supplemental_fake_ip_filter"):
                raise RuntimeError("测试定制清理后仍有残留")
            print("FINAL_CUSTOM=EMPTY")


if __name__ == "__main__":
    main()
