from __future__ import annotations

import hashlib
import importlib.util
import pathlib
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("prepare_web_auth", ROOT / "prepare_web_auth.py")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class FakeKeychain:
    def __init__(self):
        self.values: dict[str, str] = {}
        self.fail_delete_once = False

    def store(self, password: str, timeout: float, service: str) -> None:
        del timeout
        self.values[service] = password

    def read(self, service: str, timeout: float = 5.0) -> str | None:
        del timeout
        return self.values.get(service)

    def delete(self, service: str, timeout: float = 5.0) -> None:
        del timeout
        if self.fail_delete_once:
            self.fail_delete_once = False
            raise RuntimeError("test-only cleanup failure")
        self.values.pop(service, None)


class PrepareWebAuthTests(unittest.TestCase):
    def test_ha1_contract(self):
        password = "test-only-password"
        source = f"openclash-admin:OpenClash Sync:{password}".encode()
        self.assertEqual(MODULE.build_ha1(password), hashlib.sha256(source).hexdigest())
        self.assertEqual(
            MODULE.build_ha1(password, "md5"),
            hashlib.md5(source, usedforsecurity=False).hexdigest(),
        )

    def test_legacy_md5_requires_explicit_flag(self):
        parser_source = (ROOT / "prepare_web_auth.py").read_text(encoding="utf-8")
        self.assertIn("--enable-legacy-md5", parser_source)
        self.assertIn("if args.enable_legacy_md5 else None", parser_source)

    def test_digest_file_is_single_line_and_private(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / ".auth-ha1"
            MODULE.write_ha1(path, "a" * 64)
            self.assertEqual(path.read_text(), "a" * 64 + "\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_dual_digest_file_is_two_lines_and_private(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / ".auth-ha1"
            MODULE.write_ha1(path, "a" * 64, "b" * 32)
            self.assertEqual(path.read_text(), "sha256:" + "a" * 64 + "\nmd5:" + "b" * 32 + "\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            source = (ROOT / "prepare_web_auth.py").read_text(encoding="utf-8")
            self.assertGreaterEqual(source.count("fsync_published_file(path)"), 2)

    def test_invalid_digest_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                MODULE.write_ha1(pathlib.Path(directory) / ".auth-ha1", "not-a-digest")
            with self.assertRaises(ValueError):
                MODULE.write_ha1(pathlib.Path(directory) / ".auth-ha1", "a" * 64, "not-md5")

    def test_secret_file_is_single_line_and_private(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / ".web-login-secret"
            MODULE.write_secret(path, "x" * 48)
            self.assertEqual(path.read_text(), "x" * 48 + "\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_keychain_timeout_is_bounded(self):
        original = MODULE.SECURITY
        MODULE.SECURITY = "/usr/bin/yes"
        started = time.monotonic()
        try:
            with self.assertRaises(RuntimeError):
                MODULE.store_in_keychain("test-only-password", timeout=0.1)
        finally:
            MODULE.SECURITY = original
        self.assertLess(time.monotonic() - started, 3.0)

    def test_auth_transaction_lock_rejects_parallel_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            descriptor = MODULE.acquire_auth_lock(root)
            try:
                with self.assertRaisesRegex(RuntimeError, "拒绝并发修改"):
                    MODULE.acquire_auth_lock(root)
            finally:
                MODULE.release_auth_lock(descriptor)
            replacement = MODULE.acquire_auth_lock(root)
            MODULE.release_auth_lock(replacement)

    def test_copy_helper_uses_current_slot_only(self):
        helper = (ROOT / "copy-web-login.sh").read_text(encoding="utf-8")
        self.assertIn("matches_current", helper)
        self.assertIn(".auth-ha1", helper)
        self.assertIn("shasum -a 256", helper)
        self.assertIn("拒绝借用 candidate", helper)
        self.assertNotIn(".web-login-secret.next", helper)
        self.assertNotIn("org.example.openclash-sync-web.candidate", helper)

    def test_existing_current_requires_candidate_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            MODULE.write_ha1(root / MODULE.AUTH_HA1, "a" * 64)
            with self.assertRaises(SystemExit):
                MODULE.main([], root=root)

    def test_two_candidate_promotions_release_and_reuse_candidate_slot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            keychain = FakeKeychain()
            original_password = "current-password-" + "o" * 32
            first_candidate = "candidate-one-" + "a" * 32
            second_candidate = "candidate-two-" + "b" * 32
            keychain.values[MODULE.KEYCHAIN_SERVICE] = original_password
            MODULE.write_ha1(root / MODULE.AUTH_HA1, MODULE.build_ha1(original_password))
            generated = iter((first_candidate, second_candidate))
            with (
                mock.patch.object(MODULE, "store_in_keychain", keychain.store),
                mock.patch.object(MODULE, "read_keychain", keychain.read),
                mock.patch.object(MODULE, "delete_keychain", keychain.delete),
                mock.patch.object(MODULE.secrets, "token_urlsafe", side_effect=lambda _size: next(generated)),
            ):
                MODULE.main(["--candidate"], root=root)
                self.assertEqual(MODULE.load_local_password(root), original_password)
                self.assertEqual(MODULE.load_local_password(root, candidate=True), first_candidate)
                MODULE.main(["--promote-candidate"], root=root)
                self.assertEqual(MODULE.load_local_password(root), first_candidate)
                self.assertFalse((root / MODULE.CANDIDATE_AUTH_HA1).exists())
                self.assertNotIn(MODULE.CANDIDATE_KEYCHAIN_SERVICE, keychain.values)

                MODULE.main(["--candidate"], root=root)
                self.assertEqual(MODULE.load_local_password(root), first_candidate)
                self.assertEqual(MODULE.load_local_password(root, candidate=True), second_candidate)
                MODULE.main(["--promote-candidate"], root=root)
                self.assertEqual(MODULE.load_local_password(root), second_candidate)
                self.assertEqual(keychain.values[MODULE.KEYCHAIN_SERVICE], second_candidate)
                self.assertFalse((root / MODULE.CANDIDATE_AUTH_HA1).exists())
                self.assertNotIn(MODULE.CANDIDATE_KEYCHAIN_SERVICE, keychain.values)

    def test_failed_promote_restores_current_and_keeps_candidate_for_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            keychain = FakeKeychain()
            current_password = "current-password-" + "c" * 32
            candidate_password = "candidate-password-" + "n" * 32
            keychain.values[MODULE.KEYCHAIN_SERVICE] = current_password
            keychain.values[MODULE.CANDIDATE_KEYCHAIN_SERVICE] = candidate_password
            current_digests = (MODULE.build_ha1(current_password), None)
            candidate_digests = (MODULE.build_ha1(candidate_password), None)
            MODULE.write_ha1(root / MODULE.AUTH_HA1, *current_digests)
            MODULE.write_ha1(root / MODULE.CANDIDATE_AUTH_HA1, *candidate_digests)
            original_write_ha1 = MODULE.write_ha1
            failed_once = False

            def fail_first_current_write(path, sha256_value, md5_value=None):
                nonlocal failed_once
                if path == root / MODULE.AUTH_HA1 and not failed_once:
                    failed_once = True
                    raise OSError("test-only publish failure")
                original_write_ha1(path, sha256_value, md5_value)

            with (
                mock.patch.object(MODULE, "store_in_keychain", keychain.store),
                mock.patch.object(MODULE, "read_keychain", keychain.read),
                mock.patch.object(MODULE, "delete_keychain", keychain.delete),
                mock.patch.object(MODULE, "write_ha1", side_effect=fail_first_current_write),
            ):
                with self.assertRaisesRegex(RuntimeError, "旧 current 已恢复"):
                    MODULE.main(["--promote-candidate"], root=root)
                self.assertEqual(MODULE.load_local_password(root), current_password)
                self.assertEqual(MODULE.load_local_password(root, candidate=True), candidate_password)
                self.assertEqual(MODULE.read_auth_digests(root / MODULE.AUTH_HA1), current_digests)
                self.assertEqual(MODULE.read_auth_digests(root / MODULE.CANDIDATE_AUTH_HA1), candidate_digests)
                MODULE.main(["--promote-candidate"], root=root)
                self.assertEqual(MODULE.load_local_password(root), candidate_password)
                self.assertFalse((root / MODULE.CANDIDATE_AUTH_HA1).exists())

    def test_interrupted_candidate_cleanup_is_resumed_without_rewriting_current(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            keychain = FakeKeychain()
            current_password = "current-password-" + "c" * 32
            candidate_password = "candidate-password-" + "n" * 32
            keychain.values[MODULE.KEYCHAIN_SERVICE] = current_password
            keychain.values[MODULE.CANDIDATE_KEYCHAIN_SERVICE] = candidate_password
            MODULE.write_ha1(root / MODULE.AUTH_HA1, MODULE.build_ha1(current_password))
            MODULE.write_ha1(root / MODULE.CANDIDATE_AUTH_HA1, MODULE.build_ha1(candidate_password))
            keychain.fail_delete_once = True
            with (
                mock.patch.object(MODULE, "store_in_keychain", keychain.store),
                mock.patch.object(MODULE, "read_keychain", keychain.read),
                mock.patch.object(MODULE, "delete_keychain", keychain.delete),
            ):
                with self.assertRaisesRegex(RuntimeError, "candidate 清理未完成"):
                    MODULE.main(["--promote-candidate"], root=root)
                self.assertEqual(MODULE.load_local_password(root), candidate_password)
                self.assertTrue((root / MODULE.CANDIDATE_AUTH_HA1).exists())
                MODULE.main(["--promote-candidate"], root=root)
                self.assertEqual(MODULE.load_local_password(root), candidate_password)
                self.assertFalse((root / MODULE.CANDIDATE_AUTH_HA1).exists())
                self.assertNotIn(MODULE.CANDIDATE_KEYCHAIN_SERVICE, keychain.values)

    def test_interrupted_current_slot_publish_is_resumed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            keychain = FakeKeychain()
            old_password = "old-current-password-" + "o" * 32
            candidate_password = "candidate-password-" + "n" * 32
            # Simulate SIGKILL after the current Keychain slot was overwritten,
            # but before the current HA1 was replaced.
            keychain.values[MODULE.KEYCHAIN_SERVICE] = candidate_password
            keychain.values[MODULE.CANDIDATE_KEYCHAIN_SERVICE] = candidate_password
            MODULE.write_ha1(root / MODULE.AUTH_HA1, MODULE.build_ha1(old_password))
            MODULE.write_ha1(root / MODULE.CANDIDATE_AUTH_HA1, MODULE.build_ha1(candidate_password))
            with (
                mock.patch.object(MODULE, "store_in_keychain", keychain.store),
                mock.patch.object(MODULE, "read_keychain", keychain.read),
                mock.patch.object(MODULE, "delete_keychain", keychain.delete),
            ):
                MODULE.main(["--promote-candidate"], root=root)
                self.assertEqual(MODULE.load_local_password(root), candidate_password)
                self.assertEqual(
                    MODULE.read_auth_digests(root / MODULE.AUTH_HA1),
                    (MODULE.build_ha1(candidate_password), None),
                )
                self.assertFalse((root / MODULE.CANDIDATE_AUTH_HA1).exists())
                self.assertNotIn(MODULE.CANDIDATE_KEYCHAIN_SERVICE, keychain.values)

    def test_successful_keychain_promotion_removes_stale_current_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            keychain = FakeKeychain()
            old_password = "old-current-password-" + "o" * 32
            candidate_password = "candidate-password-" + "n" * 32
            keychain.values[MODULE.KEYCHAIN_SERVICE] = old_password
            keychain.values[MODULE.CANDIDATE_KEYCHAIN_SERVICE] = candidate_password
            MODULE.write_secret(root / MODULE.FALLBACK_SECRET, old_password)
            MODULE.write_ha1(root / MODULE.AUTH_HA1, MODULE.build_ha1(old_password))
            MODULE.write_ha1(root / MODULE.CANDIDATE_AUTH_HA1, MODULE.build_ha1(candidate_password))
            with (
                mock.patch.object(MODULE, "store_in_keychain", keychain.store),
                mock.patch.object(MODULE, "read_keychain", keychain.read),
                mock.patch.object(MODULE, "delete_keychain", keychain.delete),
            ):
                MODULE.main(["--promote-candidate"], root=root)
                self.assertEqual(MODULE.load_local_password(root), candidate_password)
                self.assertFalse((root / MODULE.FALLBACK_SECRET).exists())

    def test_legacy_half_promote_rehomes_candidate_in_current_slot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            keychain = FakeKeychain()
            old_password = "old-current-password-" + "o" * 32
            deployed_password = "deployed-password-" + "d" * 32
            deployed_digest = MODULE.build_ha1(deployed_password)
            keychain.values[MODULE.KEYCHAIN_SERVICE] = old_password
            keychain.values[MODULE.CANDIDATE_KEYCHAIN_SERVICE] = deployed_password
            MODULE.write_ha1(root / MODULE.AUTH_HA1, deployed_digest)
            MODULE.write_ha1(root / MODULE.CANDIDATE_AUTH_HA1, deployed_digest)
            with (
                mock.patch.object(MODULE, "store_in_keychain", keychain.store),
                mock.patch.object(MODULE, "read_keychain", keychain.read),
                mock.patch.object(MODULE, "delete_keychain", keychain.delete),
            ):
                with self.assertRaisesRegex(RuntimeError, "当前认证摘要匹配"):
                    MODULE.load_local_password(root)
                MODULE.main(["--promote-candidate"], root=root)
                self.assertEqual(MODULE.load_local_password(root), deployed_password)
                self.assertEqual(keychain.values[MODULE.KEYCHAIN_SERVICE], deployed_password)
                self.assertFalse((root / MODULE.CANDIDATE_AUTH_HA1).exists())
                self.assertNotIn(MODULE.CANDIDATE_KEYCHAIN_SERVICE, keychain.values)

    def test_production_tools_use_explicit_checks_and_shared_loader(self):
        smoke = (ROOT / "production_smoke.py").read_text(encoding="utf-8")
        acceptance = (ROOT / "production_custom_acceptance.py").read_text(encoding="utf-8")
        self.assertNotIn("\n    assert ", smoke)
        self.assertIn("--expect-legacy-md5", smoke)
        self.assertIn("--candidate-auth", smoke)
        self.assertIn("load_local_password", acceptance)
        self.assertIn("--noop-current", acceptance)
        self.assertIn("--temporary-roundtrip", acceptance)
        self.assertIn("add_mutually_exclusive_group(required=True)", acceptance)
        self.assertIn('HOST = "192.0.2.20"', smoke)
        self.assertIn('PORT = 8088', smoke)
        self.assertIn("validate_custom_read", smoke)
        self.assertIn('write_unchanged(password, target, "ProviderBase-ProviderSource.yaml")', smoke)
        self.assertNotIn('write_unchanged(password, target, "ProviderSource.yaml")', smoke)


if __name__ == "__main__":
    unittest.main()
