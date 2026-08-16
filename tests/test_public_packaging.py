from __future__ import annotations

import hashlib
import importlib.util
import pathlib
import re
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("render_config", ROOT / "tools/render_config.py")
RENDERER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RENDERER
SPEC.loader.exec_module(RENDERER)


def public_files():
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in {".git", ".ruff_cache", "__pycache__"} for part in path.parts):
            continue
        try:
            yield path, path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue


class PublicPackagingTests(unittest.TestCase):
    def test_no_private_workspace_or_device_markers(self):
        forbidden_patterns = (
            r"(?<![A-Za-z0-9_.-])/Users/[A-Za-z0-9_.-]+/(?:Documents|Desktop|Downloads|Library|Projects)/",
            r"(?<![A-Za-z0-9_.-])/home/[A-Za-z0-9_.-]+/(?:projects|Documents|Desktop|Downloads)/",
            r"\brouter_[0-9]+\b",
            r"\bVM[0-9]+\b",
            r"\b(?:10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2})\b",
        )
        for path, text in public_files():
            for pattern in forbidden_patterns:
                self.assertIsNone(re.search(pattern, text), path.relative_to(ROOT))

    def test_no_secret_shapes_or_authenticated_urls(self):
        patterns = (
            r"-----BEGIN [A-Z ]*PRIVATE " + r"KEY-----",
            r"(?:github_pat|gh[pousr])_[A-Za-z0-9_]{20,}",
            r"AKIA[0-9A-Z]{16}",
            r"https?://[^/\s:@]+:[^@\s/]+@",
            r"ssh-(?:ed25519|rsa)\s+[A-Za-z0-9+/]{40,}={0,3}",
        )
        for path, text in public_files():
            for pattern in patterns:
                self.assertIsNone(re.search(pattern, text, re.IGNORECASE), path.relative_to(ROOT))

    def test_no_secret_files_or_symlinks(self):
        forbidden_names = {
            "auth-ha1", ".auth-ha1", ".web-login-secret", "known_hosts",
            "config.local.toml",
        }
        for path in ROOT.rglob("*"):
            if ".git" in path.parts:
                continue
            self.assertFalse(path.is_symlink(), path)
            if path.is_file():
                self.assertNotIn(path.name, forbidden_names)
                self.assertFalse(path.name.startswith("id_"), path)
                self.assertNotIn(path.suffix, {".key", ".pem"})

        excluded_parts = {".git", ".ruff_cache", "__pycache__"}
        release_files = sorted(
            path.relative_to(ROOT).as_posix()
            for path in ROOT.rglob("*")
            if path.is_file()
            and not any(part in excluded_parts for part in path.parts)
            and path.suffix != ".pyc"
            and path.name not in {"FILES", "SHA256SUMS"}
        )
        manifest_text = (ROOT / "FILES").read_text(encoding="utf-8")
        self.assertTrue(manifest_text.endswith("\n"))
        self.assertNotIn("\n\n", manifest_text)
        self.assertEqual(release_files, manifest_text.splitlines())

        checksum_text = (ROOT / "SHA256SUMS").read_text(encoding="utf-8")
        self.assertTrue(checksum_text.endswith("\n"))
        self.assertNotIn("\n\n", checksum_text)
        checksum_lines = checksum_text.splitlines()
        self.assertEqual(len(release_files), len(checksum_lines))
        checksums = {}
        for line in checksum_lines:
            match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
            self.assertIsNotNone(match, line)
            digest, relative = match.groups()
            self.assertNotIn(relative, checksums)
            checksums[relative] = digest
        self.assertEqual(release_files, sorted(checksums))
        for relative in release_files:
            digest = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
            self.assertEqual(digest, checksums[relative], relative)

    def test_actions_are_pinned_and_renderer_is_closed(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        uses = re.findall(r"^\s*- uses:\s*(\S+)", workflow, re.MULTILINE)
        self.assertGreaterEqual(len(uses), 1)
        for action in uses:
            self.assertRegex(action, r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")
        for relative in RENDERER.OPERATIONAL_FILES:
            path = ROOT / relative
            self.assertTrue(path.is_file() and not path.is_symlink(), relative)

    def test_installers_pin_identity_modes_and_copied_bytes(self):
        worker = (ROOT / "install_openclash_worker.sh").read_text(encoding="utf-8")
        router = (ROOT / "install_router_openclash_stage_client.sh").read_text(encoding="utf-8")
        client = (ROOT / "openclash_router_stage_client.sh").read_text(encoding="utf-8")
        web_install = (ROOT / "openclash-sync-web/install_router_web_agent.sh").read_text(encoding="utf-8")
        web_update = (ROOT / "openclash-sync-web/update_router_web_agent.sh").read_text(encoding="utf-8")
        self.assertIn("ssh-keygen -lf", worker)
        self.assertIn("AUTHORIZED_KEYS_MODE", worker)
        self.assertIn("HOSTKEY_COUNT", router)
        self.assertIn("BUILDER_MODE", client)
        self.assertIn('pub="$key_type $key_data"', web_install)
        self.assertIn('cmp -s "$source" "$root/$name"', web_update)


if __name__ == "__main__":
    unittest.main()
