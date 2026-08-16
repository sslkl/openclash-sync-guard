from __future__ import annotations

import hashlib
import importlib.util
import pathlib
import sys
import tempfile
import time
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("prepare_web_auth", ROOT / "prepare_web_auth.py")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


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

    def test_copy_helper_matches_candidate_against_current_ha1(self):
        helper = (ROOT / "copy-web-login.sh").read_text(encoding="utf-8")
        self.assertIn("matches_current", helper)
        self.assertIn(".auth-ha1", helper)
        self.assertIn("shasum -a 256", helper)
        self.assertIn("与当前部署摘要匹配", helper)


if __name__ == "__main__":
    unittest.main()
