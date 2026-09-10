#!/usr/bin/env python3
"""Bind public source or an offline deployment candidate to its exact payload.

No credential reads, network, installation, Docker or service commands. All
bindings are computed and source drift is checked before atomic file updates.
The disabled legacy LAN-only migrator must never be rebound to a new release.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile

RUNTIME_FILES = tuple(sorted((
    "subscription_converter.py", "converter_apply.py", "converter_engine.py",
    "converter_fetch.py", "converter_formats.py", "converter_mellow.py",
    "converter_services.py", "converter_sandbox.py", "converter_surge.py",
    "static/converter.js", "static/converter_apply.js", "static/converter_services.js",
)))
ROUTER_FILES = (
    "openclash_web_router_agent.lua", "openclash_web_forced_command.sh",
    "openclash_customizer.rb", "openclash_custom_transaction.sh",
    "openclash_custom_rollback_guard.sh",
)
LIMIT = 2 * 1024 * 1024


class BindingError(ValueError):
    pass


def regular_file(root: Path, relative: str) -> Path:
    parts = relative.split("/")
    if (not relative or any(part in ("", ".", "..") for part in parts)
            or "\\" in relative or ":" in relative or any(ord(c) < 32 for c in relative)):
        raise BindingError("invalid relative source path")
    if not stat.S_ISDIR(root.lstat().st_mode):
        raise BindingError("source root must be a directory, not a symlink")
    path = root
    for index, part in enumerate(parts):
        path = path / part
        mode = path.lstat().st_mode
        if not (stat.S_ISREG(mode) if index == len(parts) - 1 else stat.S_ISDIR(mode)):
            raise BindingError(f"nonregular source member: {relative}")
    info = path.lstat()
    if info.st_nlink != 1 or not 0 < info.st_size <= LIMIT or info.st_mode & 0o7000:
        raise BindingError(f"invalid source metadata: {relative}")
    return path


def read_source(root: Path, relative: str) -> bytes:
    """Read a bounded regular member without following links or blocking on FIFOs."""
    path = regular_file(root, relative)
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = relative.split("/")
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or not 0 < before.st_size <= LIMIT or before.st_mode & 0o7000):
                raise BindingError(f"invalid opened source: {relative}")
            body = stream.read(LIMIT + 1)
            after = os.fstat(stream.fileno())
        named = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
    finally:
        os.close(directory)
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                info.st_ctime_ns, info.st_mode, info.st_uid, info.st_gid, info.st_nlink)
    if (identity(before) != identity(after) or identity(after) != identity(named)
            or identity(named) != identity(path.lstat()) or len(body) != before.st_size):
        raise BindingError(f"source changed while reading: {relative}")
    return body


def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def replace_one(body: bytes, pattern: str, value: str, label: str) -> bytes:
    text, count = re.subn(pattern, lambda match: match.group(1) + value + match.group(2),
                          body.decode("utf-8"))
    if count != 1:
        raise BindingError(f"expected exactly one binding: {label}")
    return text.encode("utf-8")


def declared_runtime_files(body: bytes) -> tuple[str, ...]:
    tree = ast.parse(body)
    assignments = [node for node in tree.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == "FILES" for target in node.targets)]
    if len(assignments) != 1:
        raise BindingError("invalid runtime file declaration")
    value = assignments[0].value
    for expected in ("tuple", "sorted"):
        if not (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                and value.func.id == expected and len(value.args) == 1 and not value.keywords):
            raise BindingError("unexpected runtime file declaration")
        value = value.args[0]
    files = ast.literal_eval(value)
    if not isinstance(files, tuple) or not all(isinstance(name, str) for name in files):
        raise BindingError("unexpected runtime members")
    return tuple(sorted(files))


def planned_bindings(root: Path) -> tuple[dict[str, bytes], dict[str, str]]:
    if not stat.S_ISDIR(root.lstat().st_mode):
        raise BindingError("release root must not be a symlink")
    web = root / "openclash-sync-web"
    sources: dict[str, bytes] = {}
    def read(name: str) -> bytes:
        if name not in sources:
            sources[name] = read_source(web, name)
        return sources[name]
    if declared_runtime_files(read("converter_runtime_bundle.py")) != RUNTIME_FILES:
        raise BindingError("runtime file contract changed; review binding code first")
    payload = {name: read(name) for name in RUNTIME_FILES}
    if sum(map(len, payload.values())) > LIMIT:
        raise BindingError("runtime exceeds total size budget")
    for name, body in payload.items():
        body.decode("utf-8")
        if b"\0" in body:
            raise BindingError("NUL in runtime source")
        if name.endswith(".py"):
            ast.parse(body, filename=name)
    manifest = "".join(f"{digest(payload[name])}  {name}\n" for name in RUNTIME_FILES).encode()
    runtime_id = digest(manifest)
    sandbox_sha = digest(payload["converter_sandbox.py"])
    updates: dict[str, bytes] = {}
    for name in ("server.py", "openclash_web_helper.py"):
        updates[name] = replace_one(read(name),
            r'(?m)^(CONVERTER_RUNTIME_ID = ")[0-9a-f]{64}("[ \t]*)$', runtime_id, name)
    updates["openclash_web_helper.py"] = replace_one(updates["openclash_web_helper.py"],
        r'(?m)^(CONVERTER_SANDBOX_SHA256 = ")[0-9a-f]{64}("[ \t]*)$', sandbox_sha, "sandbox")
    router_hashes = {name: digest(read(name)) for name in ROUTER_FILES}
    for installer in ("install_router_web_agent.sh", "update_router_web_agent.sh"):
        body = read(installer)
        for name, sha in router_hashes.items():
            body = replace_one(body,
                rf"(?m)^([ \t]*{re.escape(name)}\) printf '%s\\n' )[0-9a-f]{{64}}(;;[ \t]*)$",
                sha, f"{installer}:{name}")
        updates[installer] = body
    updates["install_router_backup_retention_schedule.sh"] = replace_one(
        read("install_router_backup_retention_schedule.sh"),
        r"(?m)^(expected_customizer=)[0-9a-f]{64}([ \t]*)$",
        router_hashes["openclash_customizer.rb"], "retention customizer")
    for name, body in updates.items():
        if name.endswith(".py"):
            ast.parse(body, filename=name)
    for name, original in sources.items():
        if read_source(web, name) != original:
            raise BindingError(f"source changed during binding: {name}")
    return updates, {"runtime_id": runtime_id, "sandbox_sha256": sandbox_sha,
                     "customizer_sha256": router_hashes["openclash_customizer.rb"]}


def bind_release(root: Path, *, check: bool = False) -> dict[str, str]:
    root = root.absolute()
    updates, identities = planned_bindings(root)
    web = root / "openclash-sync-web"
    changes = {name: body for name, body in updates.items() if read_source(web, name) != body}
    if check:
        if changes:
            raise BindingError("stale release bindings: " + ", ".join(sorted(changes)))
        return identities
    for name, body in changes.items():
        path = regular_file(web, name)
        mode = stat.S_IMODE(path.lstat().st_mode)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(prefix=".binding-", dir=path.parent, delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.chmod(mode)
            os.replace(temporary, path)
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()
    return identities


def main() -> None:
    parser = argparse.ArgumentParser(description="Refresh or verify offline release bindings")
    parser.add_argument("--root", type=Path, default=Path(__file__).absolute().parents[1])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    bind_release(args.root, check=args.check)
    print("RELEASE_BINDINGS=PASS\nLIVE_CHANGES=false")


if __name__ == "__main__":
    main()
