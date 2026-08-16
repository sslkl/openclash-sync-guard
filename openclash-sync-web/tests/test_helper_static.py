from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class HelperStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "openclash_web_helper.py").read_text(encoding="utf-8")

    def test_ssh_assets_are_root_owned_private_regular_files(self):
        self.assertIn("os.lstat(path)", self.source)
        self.assertIn("info.st_uid != 0", self.source)
        self.assertIn("stat.S_IMODE(info.st_mode) != 0o600", self.source)
        self.assertIn('while directory != "/"', self.source)
        self.assertIn("info.st_mode & 0o022", self.source)

    def test_ssh_does_not_inherit_forwarding_or_password_fallback(self):
        for option in (
            "ClearAllForwardings=yes",
            "BatchMode=yes",
            "IdentitiesOnly=yes",
            "PasswordAuthentication=no",
            "KbdInteractiveAuthentication=no",
            "StrictHostKeyChecking=yes",
            "PreferredAuthentications=publickey",
            "HostbasedAuthentication=no",
            "GSSAPIAuthentication=no",
        ):
            self.assertIn(option, self.source)

    def test_json_failures_and_depth_are_bounded(self):
        self.assertIn("RecursionError", self.source)
        self.assertIn("MAX_JSON_NODES", self.source)
        self.assertIn("MAX_JSON_DEPTH", self.source)

    def test_router_output_is_file_size_limited_before_reading(self):
        self.assertIn("resource.RLIMIT_FSIZE", self.source)
        self.assertIn("tempfile.TemporaryFile", self.source)
        self.assertIn("output.read(MAX + 1)", self.source)


if __name__ == "__main__":
    unittest.main()
