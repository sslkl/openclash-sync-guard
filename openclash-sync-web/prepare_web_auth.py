#!/usr/bin/env python3
"""生成 Web 密码，优先写入 Keychain，失败时写入 Git 忽略的私有文件。"""

from __future__ import annotations

import argparse
import hashlib
import os
import pty
import secrets
import select
import signal
import tempfile
import time
from pathlib import Path


AUTH_USER = "openclash-admin"
AUTH_REALM = "OpenClash Sync"
KEYCHAIN_SERVICE = "org.example.openclash-sync-web"
SECURITY = "/usr/bin/security"
FALLBACK_SECRET = ".web-login-secret"


def build_ha1(password: str, algorithm: str = "sha256") -> str:
    source = f"{AUTH_USER}:{AUTH_REALM}:{password}".encode()
    if algorithm == "sha256":
        return hashlib.sha256(source).hexdigest()
    if algorithm == "md5":
        return hashlib.md5(source, usedforsecurity=False).hexdigest()
    raise ValueError("不支持的 Digest 算法")


def store_in_keychain(password: str, timeout: float = 20.0) -> None:
    pid, descriptor = pty.fork()
    if pid == 0:
        os.execv(SECURITY, [
            SECURITY, "add-generic-password", "-a", AUTH_USER, "-s", KEYCHAIN_SERVICE,
            "-l", "OpenClash 同步器 Web 登录", "-U", "-T", SECURITY, "-w",
        ])
    try:
        started = time.monotonic()
        deadline = time.monotonic() + timeout
        submitted = False
        while time.monotonic() < deadline:
            finished, status = os.waitpid(pid, os.WNOHANG)
            if finished:
                if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
                    raise RuntimeError("写入 macOS Keychain 失败；请确认登录钥匙串已解锁")
                return
            ready, _, _ = select.select([descriptor], [], [], 0.25)
            if ready:
                try:
                    output = os.read(descriptor, 4096)
                except OSError:
                    # macOS PTY 在 slave 正常关闭时通常返回 EIO；下一轮
                    # waitpid 才是成功/失败的权威结果。
                    output = b""
                if output and not submitted:
                    os.write(descriptor, password.encode() + b"\n")
                    submitted = True
            # 某些 security 版本不会刷新提示文本；等它完成终端设置后
            # 兜底提交一次，避免把密码预先写入而被 tcsetattr 清空。
            if not submitted and time.monotonic() - started >= 0.5:
                os.write(descriptor, password.encode() + b"\n")
                submitted = True
        for termination_signal, grace in ((signal.SIGTERM, 1.0), (signal.SIGKILL, 1.0)):
            try:
                os.kill(pid, termination_signal)
            except ProcessLookupError:
                break
            stop_deadline = time.monotonic() + grace
            while time.monotonic() < stop_deadline:
                finished, _ = os.waitpid(pid, os.WNOHANG)
                if finished:
                    break
                time.sleep(0.05)
            else:
                continue
            break
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass
        raise RuntimeError("写入 macOS Keychain 超时；请确认登录钥匙串已解锁")
    finally:
        os.close(descriptor)


def write_ha1(path: Path, sha256_value: str, md5_value: str | None = None) -> None:
    if not sha256_value or len(sha256_value) != 64 or any(char not in "0123456789abcdef" for char in sha256_value):
        raise ValueError("SHA-256 HA1 格式无效")
    if md5_value is not None and (len(md5_value) != 32 or any(char not in "0123456789abcdef" for char in md5_value)):
        raise ValueError("MD5 HA1 格式无效")
    content = sha256_value + "\n" if md5_value is None else f"sha256:{sha256_value}\nmd5:{md5_value}\n"
    descriptor, temporary = tempfile.mkstemp(prefix=".auth-ha1.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def write_secret(path: Path, value: str) -> None:
    if not value or len(value) < 32 or any(char in value for char in "\r\n"):
        raise ValueError("登录密码格式无效")
    descriptor, temporary = tempfile.mkstemp(prefix=".web-login-secret.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            handle.write(value + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="生成 OpenClash Sync Web Digest 登录凭据")
    parser.add_argument(
        "--enable-legacy-md5",
        action="store_true",
        help="为不支持 Digest SHA-256 的旧 Safari 额外生成 MD5 HA1（仅限受信任内网兼容）",
    )
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent
    password = secrets.token_urlsafe(36)
    sha256_digest = build_ha1(password, "sha256")
    md5_digest = build_ha1(password, "md5") if args.enable_legacy_md5 else None
    keychain = True
    try:
        store_in_keychain(password, timeout=5.0)
    except RuntimeError:
        keychain = False
        write_secret(root / FALLBACK_SECRET, password)
    write_ha1(root / ".auth-ha1", sha256_digest, md5_digest)
    del password, sha256_digest, md5_digest
    if keychain:
        print("Web 登录凭据已写入 macOS Keychain；部署摘要已准备完成。")
    else:
        print("Keychain 当前不可交互；登录凭据已写入 Git 忽略的本机 0600 私有文件。")
    if args.enable_legacy_md5:
        print("已显式启用旧 Safari MD5 Digest 兼容；仅应在受信任内网使用。")
    else:
        print("Digest 仅启用 SHA-256；未启用旧 Safari MD5 兼容。")
    print(f"登录用户名：{AUTH_USER}")


if __name__ == "__main__":
    main()
