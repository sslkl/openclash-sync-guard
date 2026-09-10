"""生成 Web 密码，优先写入 Keychain，失败时写入 Git 忽略的私有文件。"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import hmac
import os
import pty
import secrets
import select
import signal
import stat
import subprocess
import tempfile
import time
from pathlib import Path

AUTH_USER = "openclash-admin"
AUTH_REALM = "OpenClash Sync"
KEYCHAIN_SERVICE = "org.example.openclash-sync-web"
CANDIDATE_KEYCHAIN_SERVICE = KEYCHAIN_SERVICE + ".candidate"
SECURITY = "/usr/bin/security"
FALLBACK_SECRET = ".web-login-secret"
CANDIDATE_FALLBACK_SECRET = FALLBACK_SECRET + ".next"
AUTH_HA1 = ".auth-ha1"
CANDIDATE_AUTH_HA1 = AUTH_HA1 + ".next"


def build_ha1(password: str, algorithm: str = "sha256") -> str:
    source = f"{AUTH_USER}:{AUTH_REALM}:{password}".encode()
    if algorithm == "sha256":
        return hashlib.sha256(source).hexdigest()
    if algorithm == "md5":
        return hashlib.md5(source, usedforsecurity=False).hexdigest()
    raise ValueError("不支持的 Digest 算法")


def fsync_published_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise OSError("published credential metadata is invalid")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def store_in_keychain(
    password: str,
    timeout: float = 20.0,
    service: str = KEYCHAIN_SERVICE,
) -> None:
    pid, descriptor = pty.fork()
    if pid == 0:
        os.execv(SECURITY, [
            SECURITY, "add-generic-password", "-a", AUTH_USER, "-s", service,
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
        fsync_published_file(path)
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
        fsync_published_file(path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def read_auth_digests(path: Path) -> tuple[str, str | None]:
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise RuntimeError("本机认证摘要文件必须是 0600 普通文件")
        lines = path.read_text(encoding="ascii").splitlines()
    except OSError as exc:
        raise RuntimeError("无法读取本机认证摘要文件") from exc
    if len(lines) == 1 and len(lines[0]) == 64 and all(char in "0123456789abcdef" for char in lines[0]):
        return lines[0], None
    if (
        len(lines) == 2
        and lines[0].startswith("sha256:")
        and len(lines[0][7:]) == 64
        and all(char in "0123456789abcdef" for char in lines[0][7:])
        and lines[1].startswith("md5:")
        and len(lines[1][4:]) == 32
        and all(char in "0123456789abcdef" for char in lines[1][4:])
    ):
        return lines[0][7:], lines[1][4:]
    raise RuntimeError("本机认证摘要格式无效")


def read_private_secret(path: Path) -> str | None:
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            return None
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        return None
    if len(lines) != 1 or len(lines[0]) < 32:
        return None
    return lines[0]


def read_keychain(service: str, timeout: float = 5.0) -> str | None:
    try:
        result = subprocess.run(
            [SECURITY, "find-generic-password", "-a", AUTH_USER, "-s", service, "-w"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    try:
        value = result.stdout.decode("utf-8").rstrip("\n")
    except UnicodeError:
        return None
    return value if len(value) >= 32 and "\n" not in value and "\r" not in value else None


def delete_keychain(service: str, timeout: float = 5.0) -> None:
    try:
        result = subprocess.run(
            [SECURITY, "delete-generic-password", "-a", AUTH_USER, "-s", service],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("清理 macOS Keychain 候选凭据失败") from exc
    # security uses errSecItemNotFound (44) when the exact item is absent.
    if result.returncode not in (0, 44):
        raise RuntimeError("清理 macOS Keychain 候选凭据失败")


def local_password_values(root: Path, *, candidate: bool) -> tuple[str | None, str | None]:
    secret_name = CANDIDATE_FALLBACK_SECRET if candidate else FALLBACK_SECRET
    service = CANDIDATE_KEYCHAIN_SERVICE if candidate else KEYCHAIN_SERVICE
    return read_private_secret(root / secret_name), read_keychain(service)


def load_local_password(root: Path, *, candidate: bool = False) -> str:
    auth_name = CANDIDATE_AUTH_HA1 if candidate else AUTH_HA1
    expected, _ = read_auth_digests(root / auth_name)
    for value in local_password_values(root, candidate=candidate):
        if value is not None and hmac.compare_digest(build_ha1(value), expected):
            return value
    scope = "候选" if candidate else "当前"
    raise RuntimeError(f"未找到与{scope}认证摘要匹配的本机登录凭据")


def slot_contains_password(root: Path, password: str, *, candidate: bool) -> bool:
    return any(
        value is not None and hmac.compare_digest(value, password)
        for value in local_password_values(root, candidate=candidate)
    )


def normalize_password_backends(root: Path, password: str, *, candidate: bool) -> None:
    """Remove a readable stale duplicate only after the selected slot is valid."""
    fallback_value, keychain_value = local_password_values(root, candidate=candidate)
    fallback_name = CANDIDATE_FALLBACK_SECRET if candidate else FALLBACK_SECRET
    service = CANDIDATE_KEYCHAIN_SERVICE if candidate else KEYCHAIN_SERVICE
    if keychain_value is not None and hmac.compare_digest(keychain_value, password):
        if path_exists(root / fallback_name):
            remove_private_file(root / fallback_name)
    elif (
        fallback_value is not None
        and hmac.compare_digest(fallback_value, password)
        and keychain_value is not None
    ):
        delete_keychain(service)


def store_local_password(root: Path, password: str, *, candidate: bool) -> str:
    service = CANDIDATE_KEYCHAIN_SERVICE if candidate else KEYCHAIN_SERVICE
    secret_name = CANDIDATE_FALLBACK_SECRET if candidate else FALLBACK_SECRET
    try:
        store_in_keychain(password, timeout=5.0, service=service)
    except (OSError, RuntimeError):
        write_secret(root / secret_name, password)
        storage = "fallback"
    else:
        stored = read_keychain(service)
        if stored is None or not hmac.compare_digest(stored, password):
            write_secret(root / secret_name, password)
            storage = "fallback"
        else:
            storage = "keychain"
    if not slot_contains_password(root, password, candidate=candidate):
        raise RuntimeError("本机登录凭据写入后校验失败")
    return storage


def remove_private_file(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise RuntimeError("无法检查候选凭据文件") from exc
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
        raise RuntimeError("候选凭据文件必须是 0600 普通文件")
    try:
        path.unlink()
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as exc:
        raise RuntimeError("清理候选凭据文件失败") from exc


def cleanup_candidate(root: Path) -> None:
    # Keep the candidate digest until both password backends are retired. If
    # cleanup is interrupted, an equal current/candidate digest is resumable.
    delete_keychain(CANDIDATE_KEYCHAIN_SERVICE)
    remove_private_file(root / CANDIDATE_FALLBACK_SECRET)
    remove_private_file(root / CANDIDATE_AUTH_HA1)


def path_exists(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def acquire_auth_lock(root: Path) -> int:
    descriptor = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(descriptor)
        raise RuntimeError("另一个本机凭据事务正在执行；拒绝并发修改") from exc
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def release_auth_lock(descriptor: int) -> None:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def promote_candidate(root: Path) -> str:
    candidate_digests = read_auth_digests(root / CANDIDATE_AUTH_HA1)
    current_digests = read_auth_digests(root / AUTH_HA1)
    try:
        current_password = load_local_password(root)
    except RuntimeError:
        current_password = None

    if hmac.compare_digest(candidate_digests[0], current_digests[0]) and candidate_digests[1] == current_digests[1]:
        if current_password is not None:
            normalize_password_backends(root, current_password, candidate=False)
            cleanup_candidate(root)
            if load_local_password(root) != current_password:
                raise RuntimeError("候选清理后的 current 一致性校验失败")
            return "cleanup-resumed"
        # Repair the prior broken state where current HA1 was switched but the
        # candidate password was never copied into the current slot.
        candidate_password = load_local_password(root, candidate=True)
    else:
        candidate_password = load_local_password(root, candidate=True)
        if current_password is None and not slot_contains_password(root, candidate_password, candidate=False):
            raise RuntimeError("current 摘要与 current 密码槽不一致；拒绝覆盖")

    try:
        store_local_password(root, candidate_password, candidate=False)
        write_ha1(root / AUTH_HA1, *candidate_digests)
        if load_local_password(root) != candidate_password:
            raise RuntimeError("候选凭据提升后的 current 一致性校验失败")
    except BaseException as exc:
        if current_password is None:
            raise RuntimeError("修复 current 密码槽失败；candidate 完整保留，可重试 promote") from exc
        try:
            store_local_password(root, current_password, candidate=False)
            write_ha1(root / AUTH_HA1, *current_digests)
            if load_local_password(root) != current_password:
                raise RuntimeError("current 恢复校验失败")
            normalize_password_backends(root, current_password, candidate=False)
        except BaseException as recovery_exc:
            raise RuntimeError(
                "promote 失败且 current 自动恢复未通过；candidate 完整保留，需停止并检查本机状态"
            ) from recovery_exc
        raise RuntimeError("promote 失败；旧 current 已恢复，candidate 完整保留，可重试") from exc

    try:
        normalize_password_backends(root, candidate_password, candidate=False)
        cleanup_candidate(root)
    except BaseException as exc:
        raise RuntimeError("current 已提升，但 candidate 清理未完成；重跑 promote 可安全续完") from exc
    if load_local_password(root) != candidate_password:
        raise RuntimeError("候选清理后的 current 一致性校验失败")
    return "promoted"


def run_mode(args: argparse.Namespace, parser: argparse.ArgumentParser, root: Path) -> None:
    if args.promote_candidate:
        if args.enable_legacy_md5:
            parser.error("--promote-candidate 不接受 --enable-legacy-md5；算法已由候选摘要绑定")
        result = promote_candidate(root)
        if result == "cleanup-resumed":
            print("current 已验证；上次中断的 candidate 清理已安全完成。")
        else:
            print("候选凭据和认证摘要已提升到 current；candidate 槽已释放。")
        print("copy-web-login.sh 只从 current 槽复制与当前 HA1 匹配的密码。")
        print(f"登录用户名：{AUTH_USER}")
        return

    auth_name = CANDIDATE_AUTH_HA1 if args.candidate else AUTH_HA1
    if not args.candidate and path_exists(root / AUTH_HA1):
        parser.error("当前 .auth-ha1 已存在；更新或轮换必须使用 --candidate")
    if args.candidate:
        try:
            current_digests = read_auth_digests(root / AUTH_HA1)
            current_password = load_local_password(root)
        except RuntimeError as exc:
            parser.error(f"current 状态无效；拒绝生成候选：{exc}")
        if path_exists(root / CANDIDATE_AUTH_HA1):
            try:
                candidate_digests = read_auth_digests(root / CANDIDATE_AUTH_HA1)
            except RuntimeError as exc:
                parser.error(f"candidate 状态无效；拒绝覆盖：{exc}")
            if candidate_digests == current_digests:
                try:
                    cleanup_candidate(root)
                except RuntimeError as exc:
                    parser.error(f"上轮 candidate 清理失败；拒绝覆盖：{exc}")
            else:
                parser.error("已有未完成的 candidate；远端回退或 promote 前拒绝覆盖")
        del current_password, current_digests
    elif path_exists(root / FALLBACK_SECRET):
        parser.error("首次安装的本机密码文件已存在；拒绝覆盖")
    password = secrets.token_urlsafe(36)
    sha256_digest = build_ha1(password, "sha256")
    md5_digest = build_ha1(password, "md5") if args.enable_legacy_md5 else None
    storage = store_local_password(root, password, candidate=args.candidate)
    try:
        write_ha1(root / auth_name, sha256_digest, md5_digest)
        if load_local_password(root, candidate=args.candidate) != password:
            raise RuntimeError("生成后的摘要与密码槽不一致")
        normalize_password_backends(root, password, candidate=args.candidate)
    except BaseException:
        remove_private_file(root / auth_name)
        raise
    del password, sha256_digest, md5_digest
    if storage == "keychain":
        print("Web 登录凭据已写入 macOS Keychain；部署摘要已准备完成。")
    else:
        print("Keychain 当前不可交互；登录凭据已写入 Git 忽略的本机 0600 私有文件。")
    if args.enable_legacy_md5:
        print("已显式启用旧 Safari MD5 Digest 兼容；仅应在受信任内网使用。")
    else:
        print("Digest 仅启用 SHA-256；未启用旧 Safari MD5 兼容。")
    if args.candidate:
        print("已生成隔离的 .next 候选；远端 COMMITTED 和候选 smoke PASS 前不得 promote。")
    else:
        print("已生成首次安装凭据；现有部署的轮换不得使用此模式。")
    print(f"登录用户名：{AUTH_USER}")


def main(argv: list[str] | None = None, root: Path | None = None) -> None:
    parser = argparse.ArgumentParser(description="生成 OpenClash Sync Web Digest 登录凭据")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--candidate",
        action="store_true",
        help="为更新生成独立 .next 候选；不覆盖当前 HA1 或当前 Keychain 凭据",
    )
    mode.add_argument(
        "--promote-candidate",
        action="store_true",
        help="仅在远端更新 COMMITTED 且候选 smoke PASS 后，把 .next 提升为当前凭据",
    )
    parser.add_argument(
        "--enable-legacy-md5",
        action="store_true",
        help="为不支持 Digest SHA-256 的旧 Safari 额外生成 MD5 HA1（仅限受信任内网兼容）",
    )
    args = parser.parse_args(argv)
    root = root or Path(__file__).resolve().parent
    lock_descriptor = acquire_auth_lock(root)
    try:
        run_mode(args, parser, root)
    finally:
        release_auth_lock(lock_descriptor)


if __name__ == "__main__":
    main()
