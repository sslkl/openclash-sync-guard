#!/usr/bin/env python3
"""Render sanitized example assets into a deployment-specific, ignored directory."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import re
import shutil
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OPERATIONAL_FILES = (
    "maying_normalizer.py",
    "maying_converter_reconciler.py",
    "openclash_worker.py",
    "openclash_worker_forced_command.sh",
    "install_openclash_worker.sh",
    "openclash_router_stage_builder.rb",
    "openclash_router_stage_client.sh",
    "install_router_openclash_stage_client.sh",
    "uninstall_router_openclash_stage_client.sh",
    "uninstall_openclash_worker_key.sh",
    "router-openclash-sync-capability-audit.sh",
    "openclash-sync-web/server.py",
    "openclash-sync-web/openclash_web_helper.py",
    "openclash-sync-web/openclash_web_router_agent.lua",
    "openclash-sync-web/openclash_customizer.rb",
    "openclash-sync-web/openclash_custom_transaction.sh",
    "openclash-sync-web/openclash_custom_rollback_guard.sh",
    "openclash-sync-web/openclash_web_forced_command.sh",
    "openclash-sync-web/install_router_web_agent.sh",
    "openclash-sync-web/install_worker_web_console.sh",
    "openclash-sync-web/update_router_web_agent.sh",
    "openclash-sync-web/update_worker_web_console.sh",
    "openclash-sync-web/openclash-sync-web.service",
    "openclash-sync-web/prepare_web_auth.py",
    "openclash-sync-web/copy-web-login.sh",
    "openclash-sync-web/open-console-tunnel.sh",
    "openclash-sync-web/requirements.txt",
    "openclash-sync-web/static/index.html",
    "openclash-sync-web/static/app.css",
    "openclash-sync-web/static/app.js",
)


def require_text(config: dict[str, object], name: str, pattern: str) -> str:
    value = config.get(name)
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise ValueError(f"{name} 格式无效")
    return value


def require_host(config: dict[str, object], name: str) -> str:
    value = require_text(config, name, r"[0-9.]+")
    address = ipaddress.IPv4Address(value)
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        raise ValueError(f"{name} 不能是 unspecified、multicast 或 loopback")
    return str(address)


def load_config(path: Path) -> dict[str, str]:
    with path.open("rb") as handle:
        raw = tomllib.load(handle)
    expected = {
        "target_a_id", "target_b_id", "target_a_host", "target_b_host", "worker_host",
        "service_user", "main_config", "base_config", "source_config", "expected_core_sha256",
        "web_auth_user", "keychain_service", "allowed_networks",
    }
    if set(raw) != expected:
        missing = sorted(expected - set(raw))
        extra = sorted(set(raw) - expected)
        raise ValueError(f"配置字段不闭合：missing={missing}, extra={extra}")
    values = {
        "target_a_id": require_text(raw, "target_a_id", r"[a-z][a-z0-9_]{0,31}"),
        "target_b_id": require_text(raw, "target_b_id", r"[a-z][a-z0-9_]{0,31}"),
        "target_a_host": require_host(raw, "target_a_host"),
        "target_b_host": require_host(raw, "target_b_host"),
        "worker_host": require_host(raw, "worker_host"),
        "service_user": require_text(raw, "service_user", r"[a-z_][a-z0-9_-]{0,31}"),
        "main_config": require_text(raw, "main_config", r"[A-Za-z0-9][A-Za-z0-9_.-]{0,126}\.yaml"),
        "base_config": require_text(raw, "base_config", r"[A-Za-z0-9][A-Za-z0-9_.-]{0,126}\.yaml"),
        "source_config": require_text(raw, "source_config", r"[A-Za-z0-9][A-Za-z0-9_.-]{0,126}\.yaml"),
        "expected_core_sha256": require_text(raw, "expected_core_sha256", r"[0-9a-f]{64}"),
        "web_auth_user": require_text(raw, "web_auth_user", r"[A-Za-z0-9_.-]{1,64}"),
        "keychain_service": require_text(raw, "keychain_service", r"[A-Za-z0-9][A-Za-z0-9.-]{2,127}"),
        "allowed_networks": require_text(raw, "allowed_networks", r"[0-9A-Fa-f:.,/]+"),
    }
    if len({values["target_a_id"], values["target_b_id"]}) != 2:
        raise ValueError("两个 target id 必须不同")
    if len({values["target_a_host"], values["target_b_host"], values["worker_host"]}) != 3:
        raise ValueError("两个路由器与 worker host 地址必须不同")
    if len({values["main_config"], values["base_config"], values["source_config"]}) != 3:
        raise ValueError("三份受管 YAML 文件名必须不同")
    for network in values["allowed_networks"].split(","):
        ipaddress.ip_network(network, strict=False)
    return values


def replacements(values: dict[str, str]) -> tuple[tuple[str, str], ...]:
    return (
        ("ProviderBase-ProviderSource.yaml", values["main_config"]),
        ("ProviderBase.yaml", values["base_config"]),
        ("ProviderSource.yaml", values["source_config"]),
        ("router_a", values["target_a_id"]),
        ("router_b", values["target_b_id"]),
        (r"192\.0\.2\.10", values["target_a_host"].replace(".", r"\.")),
        (r"192\.0\.2\.11", values["target_b_host"].replace(".", r"\.")),
        (r"192\.0\.2\.20", values["worker_host"].replace(".", r"\.")),
        ("192.0.2.10", values["target_a_host"]),
        ("192.0.2.11", values["target_b_host"]),
        ("192.0.2.20", values["worker_host"]),
        ("syncsvc", values["service_user"]),
        ("0" * 64, values["expected_core_sha256"]),
        ("openclash-admin", values["web_auth_user"]),
        ("org.example.openclash-sync-web", values["keychain_service"]),
        ("192.0.2.0/24,127.0.0.0/8", values["allowed_networks"]),
    )


def apply_replacements(text: str, mapping: tuple[tuple[str, str], ...]) -> str:
    lookup = dict(mapping)
    if len(lookup) != len(mapping):
        raise ValueError("内部占位符重复")
    pattern = re.compile("|".join(re.escape(source) for source in lookup))
    return pattern.sub(lambda match: lookup[match.group(0)], text)


def render(config_path: Path, output: Path) -> None:
    values = load_config(config_path)
    if output.exists():
        raise FileExistsError(f"输出目录已存在：{output}")
    output.mkdir(parents=True, mode=0o700)
    manifest: list[str] = []
    try:
        mapping = replacements(values)
        for relative in OPERATIONAL_FILES:
            source = ROOT / relative
            destination = output / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            text = source.read_text(encoding="utf-8")
            text = apply_replacements(text, mapping)
            destination.write_text(text, encoding="utf-8")
            destination.chmod(source.stat().st_mode & 0o777)
            manifest.append(relative)
        files_text = "\n".join(manifest) + "\n"
        (output / "FILES").write_text(files_text, encoding="utf-8")
        sums = []
        for relative in manifest:
            digest = hashlib.sha256((output / relative).read_bytes()).hexdigest()
            sums.append(f"{digest}  {relative}")
        (output / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="ascii")
    except BaseException:
        shutil.rmtree(output, ignore_errors=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="渲染 OpenClash Sync Guard 部署资产")
    parser.add_argument("config", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    render(args.config.resolve(), args.output.resolve())
    print(f"RENDER=PASS\nOUTPUT={args.output.resolve()}\nLIVE_CHANGES=false")


if __name__ == "__main__":
    main()
