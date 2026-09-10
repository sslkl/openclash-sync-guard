from __future__ import annotations

import pathlib
import json
import subprocess
import sys
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

    def test_complete_authenticated_json_is_parsed_before_ssh_tail_status(self):
        invalid_output = 'if not response_bytes or len(response_bytes) > MAX:'
        parse_output = 'response = json.loads(response_bytes, object_pairs_hook=unique_json_object)'
        validate_output = 'not isinstance(response.get("ok"), bool)'
        self.assertIn(invalid_output, self.source)
        self.assertIn(parse_output, self.source)
        self.assertIn(validate_output, self.source)
        self.assertNotIn("result.returncode != 0 or not response_bytes", self.source)
        self.assertLess(self.source.index(invalid_output), self.source.index(parse_output))
        self.assertLess(self.source.index(parse_output), self.source.index(validate_output))

    def test_duplicate_members_are_rejected_before_accessing_ssh_assets(self):
        for body in (b'{"action":"status","action":"chain_apply","target":"router_a"}',
                     b'{"action":"chain_apply","target":"router_a","chain":{"password":"one","pass\\u0077ord":"two"}}'):
            result = subprocess.run([sys.executable, '-B', str(ROOT / 'openclash_web_helper.py')],
                                    input=body, capture_output=True, check=False, timeout=5)
            self.assertEqual(result.returncode, 11)
            self.assertEqual(result.stderr, b'')
            self.assertFalse(json.loads(result.stdout)['ok'])
            self.assertNotIn(b'password', result.stdout)

    def test_malformed_input_is_rejected_before_accessing_ssh_assets(self):
        for request in ({"action": []}, {"action": "status", "target": []},
                        {"action": "status", "target": "router_a", "value": "\ud800"},
                        {"action": "status", "target": "router_a", "value": float("nan")}):
            with self.subTest(request=repr(request)):
                result = subprocess.run([sys.executable, "-B", str(ROOT / "openclash_web_helper.py")],
                                        input=json.dumps(request).encode(), capture_output=True, check=False, timeout=5)
                self.assertIn(result.returncode, (12, 13))
                self.assertEqual(result.stderr, b"")
                self.assertFalse(json.loads(result.stdout)["ok"])


if __name__ == "__main__":
    unittest.main()
