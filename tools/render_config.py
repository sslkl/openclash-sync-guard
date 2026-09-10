#!/usr/bin/env python3
"""Render explicit public assets into a new, offline deployment candidate.

No discovery of credentials or ignored configuration, no install, and no live
service changes. Binary/vendor bytes are preserved; all content pins are then
recomputed from the rendered payload, never copied from another deployment.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import ipaddress
from pathlib import Path
import re
import shutil
import stat
import tomllib

if __package__:
    from . import release_bindings
else:
    import release_bindings

ROOT = Path(__file__).absolute().parents[1]
VENDOR_MEMBERS = (
    "LICENSE", "SOURCE.json", "yaml/__init__.py", "yaml/composer.py",
    "yaml/constructor.py", "yaml/cyaml.py", "yaml/dumper.py", "yaml/emitter.py",
    "yaml/error.py", "yaml/events.py", "yaml/loader.py", "yaml/nodes.py",
    "yaml/parser.py", "yaml/reader.py", "yaml/representer.py", "yaml/resolver.py",
    "yaml/scanner.py", "yaml/serializer.py", "yaml/tokens.py",
)
BINARY_FILES = frozenset({"openclash-sync-web/static/OpenClash_Sync_Logo.png"})
OPERATIONAL_FILES = tuple(sorted((
    "maying-converter-shape-contract.json",
    "maying_normalizer.py", "maying_converter_reconciler.py", "openclash_worker.py",
    "openclash_worker_forced_command.sh", "install_openclash_worker.sh",
    "update_openclash_worker_contract.sh", "rollback_openclash_worker_contract.sh",
    "openclash_router_stage_builder.rb", "openclash_router_stage_client.sh",
    "install_router_openclash_stage_client.sh", "update_router_openclash_stage_assets.sh",
    "rollback_router_openclash_stage_assets.sh", "uninstall_router_openclash_stage_client.sh",
    "uninstall_openclash_worker_key.sh", "router-openclash-sync-capability-audit.sh",
    "tools/release_bindings.py",
    "openclash-sync-web/server.py", "openclash-sync-web/openclash_web_helper.py",
    "openclash-sync-web/openclash_web_router_agent.lua",
    "openclash-sync-web/openclash_customizer.rb",
    "openclash-sync-web/openclash_custom_transaction.sh",
    "openclash-sync-web/openclash_custom_rollback_guard.sh",
    "openclash-sync-web/openclash_web_forced_command.sh",
    "openclash-sync-web/install_router_web_agent.sh",
    "openclash-sync-web/install_worker_web_console.sh",
    "openclash-sync-web/update_router_web_agent.sh",
    "openclash-sync-web/update_worker_web_console.sh",
    "openclash-sync-web/install_router_backup_retention_schedule.sh",
    "openclash-sync-web/openclash-sync-web.service",
    "openclash-sync-web/prepare_web_auth.py",
    "openclash-sync-web/copy-web-login.sh", "openclash-sync-web/open-console-tunnel.sh",
    "openclash-sync-web/requirements.txt", "openclash-sync-web/requirements.in",
    "openclash-sync-web/production_smoke.py",
    "openclash-sync-web/production_custom_acceptance.py",
    "openclash-sync-web/converter_runtime_bundle.py",
    "openclash-sync-web/static/index.html", "openclash-sync-web/static/app.css",
    "openclash-sync-web/static/app.js", "openclash-sync-web/static/OpenClash_Sync_Logo.png",
) + tuple("openclash-sync-web/" + name for name in release_bindings.RUNTIME_FILES)
  + tuple("vendor/pyyaml-6.0.2/" + name for name in VENDOR_MEMBERS)))
if len(set(OPERATIONAL_FILES)) != len(OPERATIONAL_FILES):
    raise ValueError("duplicate operational source member")

UNSAFE_NETWORKS = tuple(ipaddress.IPv4Network(value) for value in (
    "0.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
))


def require_text(config: dict[str, object], name: str, pattern: str) -> str:
    value = config.get(name)
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise ValueError(f"{name} 格式无效")
    return value


def require_host(config: dict[str, object], name: str) -> str:
    value = require_text(config, name, r"[0-9.]+")
    address = ipaddress.IPv4Address(value)
    if address.is_loopback or any(address in network for network in UNSAFE_NETWORKS):
        raise ValueError(f"{name} 不能是 loopback、link-local、multicast 或保留地址")
    return str(address)


def normalize_networks(value: str, worker: str) -> str:
    entries = value.split(",")
    if not 1 <= len(entries) <= 16:
        raise ValueError("allowed_networks 必须包含 1 到 16 个 IPv4 网段")
    networks = []
    for entry in entries:
        network = ipaddress.ip_network(entry, strict=False)
        if network.version != 4 or any(network.overlaps(unsafe) for unsafe in UNSAFE_NETWORKS):
            raise ValueError("allowed_networks 拒绝 IPv6、默认路由及特殊/保留网段")
        if network in networks:
            raise ValueError("allowed_networks 包含重复网段")
        networks.append(network)
    # The fixed local/tunnel health path and worker self-check must remain usable.
    for required in (ipaddress.IPv4Address("127.0.0.1"), ipaddress.IPv4Address(worker)):
        if not any(required in network for network in networks):
            raise ValueError("allowed_networks 必须覆盖 loopback 和 worker_host")
    return ",".join(str(network) for network in sorted(networks))


def load_config(path: Path) -> dict[str, str]:
    path = path.absolute()
    raw = tomllib.loads(release_bindings.read_source(path.parent, path.name).decode("utf-8"))
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
    if values["service_user"] == "root":
        raise ValueError("service_user 必须是独立的非 root 服务用户")
    if values["expected_core_sha256"] == "0" * 64:
        raise ValueError("expected_core_sha256 不能是未配置的占位摘要")
    values["allowed_networks"] = normalize_networks(values["allowed_networks"], values["worker_host"])
    return values


def replacements(values: dict[str, str]) -> tuple[tuple[str, str], ...]:
    return (
        ("ProviderBase-ProviderSource.yaml", values["main_config"]),
        ("ProviderBase.yaml", values["base_config"]),
        ("ProviderSource.yaml", values["source_config"]),
        ("router_a", values["target_a_id"]), ("router_b", values["target_b_id"]),
        (r"192\.0\.2\.10", values["target_a_host"].replace(".", r"\.")),
        (r"192\.0\.2\.11", values["target_b_host"].replace(".", r"\.")),
        (r"192\.0\.2\.20", values["worker_host"].replace(".", r"\.")),
        ("192.0.2.10", values["target_a_host"]), ("192.0.2.11", values["target_b_host"]),
        ("192.0.2.20", values["worker_host"]), ("syncsvc", values["service_user"]),
        ("0" * 64, values["expected_core_sha256"]),
        ("openclash-admin", values["web_auth_user"]),
        ("org.example.openclash-sync-web", values["keychain_service"]),
        ("192.0.2.0/24,127.0.0.0/8", values["allowed_networks"]),
    )


def apply_replacements(text: str, mapping: tuple[tuple[str, str], ...]) -> str:
    lookup = dict(mapping)
    if len(lookup) != len(mapping):
        raise ValueError("内部占位符重复")
    # Replace identifier/address tokens, not prefixes inside router_agent.lua,
    # router_backup scripts or a different IPv4 address. Still use one pass so
    # one rendered value can never become another template placeholder.
    alternatives = []
    for source in lookup:
        escaped = re.escape(source)
        if source in {"router_a", "router_b"}:
            escaped = r"(?<![A-Za-z0-9_])" + escaped + r"(?![A-Za-z0-9_])"
        elif source == "syncsvc":
            escaped = r"(?<![A-Za-z0-9_-])" + escaped + r"(?![A-Za-z0-9_-])"
        elif re.fullmatch(r"[0-9]+(?:\\?\.[0-9]+){3}", source):
            escaped = r"(?<![A-Za-z0-9_.\\])" + escaped + r"(?![A-Za-z0-9_.\\])"
        alternatives.append(escaped)
    pattern = re.compile("|".join(alternatives))
    return pattern.sub(lambda match: lookup[match.group(0)], text)


def safe_output(path: Path) -> Path:
    path = path.absolute()
    if ".." in path.parts:
        raise ValueError("输出路径不能包含 ..")
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"输出目录已存在：{path}")
    for parent in reversed(path.parents):
        if parent.exists() or parent.is_symlink():
            if not stat.S_ISDIR(parent.lstat().st_mode):
                raise ValueError("输出目录的父路径不能是符号链接或特殊文件")
        else:
            parent.mkdir(mode=0o700)
    return path


def write_manifest(root: Path, members: list[str]) -> None:
    members = sorted(members)
    (root / "FILES").write_text("\n".join(members) + "\n", encoding="utf-8")
    sums = [f"{hashlib.sha256(release_bindings.read_source(root, name)).hexdigest()}  {name}"
            for name in members]
    (root / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="ascii")


def render(config_path: Path, output: Path) -> None:
    values = load_config(config_path)
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"输出目录已存在：{output}")
    mapping = replacements(values)
    prepared: dict[str, tuple[bytes, int]] = {}
    for relative in OPERATIONAL_FILES:
        source = release_bindings.regular_file(ROOT, relative)
        body = release_bindings.read_source(ROOT, relative)
        if relative not in BINARY_FILES and not relative.startswith("vendor/"):
            text = body.decode("utf-8")
            if "\0" in text:
                raise ValueError(f"NUL in text source: {relative}")
            body = apply_replacements(text, mapping).encode("utf-8")
            if relative.endswith(".py"):
                ast.parse(body, filename=relative)
        prepared[relative] = (body, stat.S_IMODE(source.lstat().st_mode))
    output = safe_output(output)
    output.mkdir(mode=0o700)
    created = output.lstat()
    try:
        for relative, (body, mode) in prepared.items():
            destination = output / relative
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            destination.write_bytes(body)
            destination.chmod(mode)
        release_bindings.bind_release(output)
        release_bindings.bind_release(output, check=True)
        web_members = [name.removeprefix("openclash-sync-web/") for name in OPERATIONAL_FILES
                       if name.startswith("openclash-sync-web/")]
        write_manifest(output / "openclash-sync-web", web_members)
        write_manifest(output, list(OPERATIONAL_FILES) + [
            "openclash-sync-web/FILES", "openclash-sync-web/SHA256SUMS"])
    except BaseException:
        # Only this newly created private candidate may be removed, never a source
        # tree or a pre-existing destination. Preserve a replaced directory.
        current = output.lstat()
        if (created.st_dev, created.st_ino) == (current.st_dev, current.st_ino):
            shutil.rmtree(output)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="渲染 OpenClash Sync Guard 离线部署资产")
    parser.add_argument("config", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    render(args.config, args.output)
    print(f"RENDER=PASS\nOUTPUT={args.output.absolute()}\nLIVE_CHANGES=false")


if __name__ == "__main__":
    main()
