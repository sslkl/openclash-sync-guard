from __future__ import annotations

from collections import Counter
import hashlib
import os
import pathlib
import re
import stat
import unittest

from tools import release_bindings, render_config as RENDERER

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXCLUDED_DIRECTORIES = {".git", ".venv", "build", ".ruff_cache", ".mypy_cache", ".pytest_cache", "__pycache__"}
FORBIDDEN_NAMES = {"auth-ha1", ".auth-ha1", ".web-login-secret", "known_hosts", "config.local.toml"}
BINARY_MEMBERS = {"openclash-sync-web/static/OpenClash_Sync_Logo.png"}
# Source literals may have a raw \t or \n directly before an address; word
# boundaries miss those because the escape letter is itself a word character.
PRIVATE_ADDRESS_PATTERN = (
    r"(?<![0-9.])(?:10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}"
    r"|192\.168(?:\.\d{1,3}){2}"
    r"|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])(?:\.\d{1,3}){2})(?![0-9.])"
)

# Each entry is an individually reviewed *complete source line*, with an exact
# expected match count. These are synthetic RFC1918/CGNAT validation fixtures and
# invalid example authorities used to test credential rejection/redaction.
# There is no whole-file/test-directory exemption. Changing the value, host,
# context or multiplicity fails closed and requires a fresh review.
REVIEWED_SYNTHETIC_LINES = {
    ("openclash-sync-web/tests/test_chain_customizer.rb", "private_address",
     "22138a3a1bada04c430fa6bb630a261904fa81049fe8b4568b899e6925a99327"): 3,
    ("openclash-sync-web/tests/test_chain_frontend.py", "authenticated_url",
     "ba02a74ee9cc58099495c543749f118620b62cd66017e476d10d365d4fc72ac8"): 1,
    ("openclash-sync-web/tests/test_chain_server.py", "private_address",
     "85a775782fce585bfb6f375bce0ca9f40939dc85d0d5150545f0f2b4fb982c59"): 2,
    ("openclash-sync-web/tests/test_converter_execution.py", "private_address",
     "757afc300c7f91578c73be7c0741e4fc5e356358f09bf18182c7c6884df2d598"): 2,
    ("openclash-sync-web/tests/test_converter_services.py", "authenticated_url",
     "13216bc39f8615ec377ea59a59a025384afedd4ff05d9d8c039f3fb357b07da5"): 1,
    ("openclash-sync-web/tests/test_converter_tools_frontend.py", "authenticated_url",
     "9810bd44fe5dd43e53c300654f54989f296426c90de4b86346e1962b3d886b07"): 1,
    ("openclash-sync-web/tests/test_http_logging.py", "authenticated_url",
     "2e722a62359da5476f906ad85db30edd1d33d6c5e3dc326f10ba06fea2d9e4b2"): 1,
    ("openclash-sync-web/tests/test_openclash_customizer.rb", "private_address",
     "1deb8794cdc2105b310337d0b807be702525247f516d35937c419a6b3fd7a15a"): 1,
    ("openclash-sync-web/tests/test_openclash_customizer.rb", "private_address",
     "2578bcfd8d7e42c87201f988d4317d0738431efdcc47d623f3edc086522a07f0"): 1,
    ("openclash-sync-web/tests/test_openclash_customizer.rb", "private_address",
     "881c8139cc34681664be11a432deae724db87970188b869ddc49484a07a2be24"): 1,
    ("openclash-sync-web/tests/test_openclash_customizer.rb", "private_address",
     "945becee0e1bc527f3812b7afea48360756974204df3efc7eb8db532ab84bd58"): 1,
    ("openclash-sync-web/tests/test_openclash_customizer.rb", "private_address",
     "9d19a1ad08f61377d4867d720c4e68863ef34be2f4a64df45dffd768e28a27ae"): 1,
    ("openclash-sync-web/tests/test_openclash_customizer.rb", "private_address",
     "b296f45d63cd8f372e9d10ac134abf1a6436b7ac7e4fce568991ba0353597512"): 1,
    ("openclash-sync-web/tests/test_subscription_converter.py", "authenticated_url",
     "3a69fbc369e1c2166220f833a656958617eb3ad948974b014772430de59de2b4"): 1,
    ("openclash-sync-web/tests/test_subscription_converter.py", "authenticated_url",
     "83ce97eba800ddbe72cf11811fe8ae70b34c0eeec0872bbab17e2a5874bdb1f6"): 1,
}


def public_member(name: str) -> pathlib.Path:
    path = pathlib.PurePosixPath(name)
    if (not name or name != path.as_posix() or path.is_absolute()
            or any(part in (".", "..") or part in EXCLUDED_DIRECTORIES for part in path.parts)
            or any(part.lower() in FORBIDDEN_NAMES or part.lower().startswith(".env")
                   or part.startswith("id_") for part in path.parts)
            or path.suffix.lower() in {".key", ".pem", ".p12", ".pfx", ".db", ".sqlite", ".pyc", ".zip", ".tgz"}
            or any(character.isspace() for character in name)):
        raise ValueError("unsafe public source member")
    return release_bindings.regular_file(ROOT, name)


def declared_members() -> list[str]:
    text = release_bindings.read_source(ROOT, "FILES").decode("utf-8")
    names = text.splitlines()
    if not text.endswith("\n") or not names or names != sorted(set(names)):
        raise ValueError("public FILES must be sorted, unique and newline terminated")
    if any(name in {"FILES", "SHA256SUMS"} for name in names):
        raise ValueError("root manifest cannot include itself")
    for name in names:
        public_member(name)
    return names


def public_files():
    # Read only the reviewed release manifest. Never discover/read ignored local
    # config, authentication material, build candidates or the Git object store.
    for name in [*declared_members(), "FILES", "SHA256SUMS"]:
        path = public_member(name)
        if name in BINARY_MEMBERS:
            continue
        yield path, release_bindings.read_source(ROOT, name).decode("utf-8")


def source_inventory() -> list[str]:
    """Metadata-only completeness check; excluded directory contents are not visited."""
    names = []
    for directory, dirs, files in os.walk(ROOT, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name not in EXCLUDED_DIRECTORIES)
        for name in dirs:
            if not stat.S_ISDIR((pathlib.Path(directory) / name).lstat().st_mode):
                raise ValueError("public source directory must not be a symlink")
        for name in files:
            if name == ".git" or name.endswith(".pyc"):
                continue
            relative = (pathlib.Path(directory) / name).relative_to(ROOT).as_posix()
            public_member(relative)
            if relative not in {"FILES", "SHA256SUMS"}:
                names.append(relative)
    return sorted(names)


def reviewed_synthetic_line(relative: str, category: str, line: str, count: int) -> bool:
    key = (relative, category, hashlib.sha256(line.strip().encode("utf-8")).hexdigest())
    return REVIEWED_SYNTHETIC_LINES.get(key) == count


class PublicPackagingTests(unittest.TestCase):
    def assert_clean_categories(self, patterns):
        seen = Counter()
        for path, text in public_files():
            relative = path.relative_to(ROOT).as_posix()
            for number, line in enumerate(text.splitlines(), 1):
                for category, pattern in patterns.items():
                    matches = list(re.finditer(pattern, line, re.IGNORECASE))
                    if not matches:
                        continue
                    self.assertTrue(reviewed_synthetic_line(relative, category, line, len(matches)),
                                    f"unreviewed {category} at {relative}:{number}")
                    key = (relative, category, hashlib.sha256(line.strip().encode("utf-8")).hexdigest())
                    seen[key] += len(matches)
        expected = {key: count for key, count in REVIEWED_SYNTHETIC_LINES.items() if key[1] in patterns}
        self.assertEqual(dict(seen), expected, "synthetic fixture catalog changed; review required")

    def test_no_private_workspace_or_device_markers(self):
        device_pattern = r"(?:router[_-][0-9]+|VM[0-9]+)"
        for marker in ("VM" + "999", "router_" + "77", "router-" + "88"):
            for prefix, suffix in (("", ""), ("Static", "WebTests"), ("_", "_config")):
                with self.subTest(prefix=prefix, suffix=suffix):
                    self.assertIsNotNone(re.search(device_pattern, prefix + marker.lower() + suffix, re.IGNORECASE))
        for generic in ("WorkerWebTests", "router_a", "router_b", "VMess"):
            self.assertIsNone(re.search(device_pattern, generic, re.IGNORECASE))
        self.assert_clean_categories({
            "workspace": r"(?<![A-Za-z0-9_.-])/(?:Users/[A-Za-z0-9_.-]+/(?:Documents|Desktop|Downloads|Library|Projects)|home/[A-Za-z0-9_.-]+/(?:projects|Documents|Desktop|Downloads))/",
            "device": device_pattern,
            "private_address": PRIVATE_ADDRESS_PATTERN,
        })

    def test_private_address_scan_detects_source_escape_boundaries(self):
        addresses = [".".join(parts) for parts in (
            ("10", "254", "254", "1"), ("172", "16", "2", "3"),
            ("172", "31", "2", "3"), ("192", "168", "5", "7"),
            ("100", "64", "2", "3"), ("100", "127", "255", "254"),
        )]
        for address in addresses:
            for prefix in ("", " ", r"\t", r"\n", r"\r", "http://", "embedded"):
                for suffix in ("", r"\tAI", "/32,DIRECT", ":8080", "'"):
                    with self.subTest(prefix=prefix, suffix=suffix):
                        matches = re.findall(PRIVATE_ADDRESS_PATTERN, prefix + address + suffix)
                        self.assertEqual(matches, [address])

    def test_private_address_scan_ignores_documentation_and_larger_octets(self):
        for address in ("192.0.2.7", "198.51.100.7", "203.0.113.7",
                        "172.15.2.3", "172.32.2.3", "110.254.254.1",
                        "100.63.2.3", "100.128.2.3", "1100.64.2.3",
                        "1192.168.5.7", "10.254.254.1234"):
            with self.subTest(address=address):
                self.assertIsNone(re.search(PRIVATE_ADDRESS_PATTERN, address))

    def test_no_secret_shapes_or_authenticated_urls(self):
        self.assert_clean_categories({
            "key": r"-----BEGIN [A-Z ]*PRIVATE " + r"KEY-----",
            "token": r"(?:github_pat|gh[pousr])_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}",
            "authenticated_url": r"https?://[^/\s:@]+:[^@\s/]+@",
            "sshkey": r"ssh-(?:ed25519|rsa)\s+[A-Za-z0-9+/]{40,}={0,3}",
        })

    def test_synthetic_exceptions_are_exact_not_whole_file_exemptions(self):
        (relative, category, expected_hash), count = next(iter(REVIEWED_SYNTHETIC_LINES.items()))
        lines = release_bindings.read_source(ROOT, relative).decode("utf-8").splitlines()
        line = next(line for line in lines if hashlib.sha256(line.strip().encode()).hexdigest() == expected_hash)
        self.assertTrue(reviewed_synthetic_line(relative, category, line, count))
        self.assertFalse(reviewed_synthetic_line(relative, category, line + " # changed fixture", count))
        self.assertFalse(reviewed_synthetic_line("tests/new_fixture.py", category, line, count))
        self.assertFalse(reviewed_synthetic_line(relative, category, line, count + 1))

    def test_no_secret_files_or_symlinks(self):
        release_files = source_inventory()
        self.assertEqual(release_files, declared_members())
        checksum_text = release_bindings.read_source(ROOT, "SHA256SUMS").decode("ascii")
        self.assertTrue(checksum_text.endswith("\n"))
        self.assertNotIn("\n\n", checksum_text)
        checksum_lines = checksum_text.splitlines()
        self.assertEqual(len(release_files), len(checksum_lines))
        checksums = {}
        for line in checksum_lines:
            match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
            self.assertIsNotNone(match, "malformed checksum record")
            digest, relative = match.groups()
            self.assertNotIn(relative, checksums)
            public_member(relative)
            checksums[relative] = digest
        self.assertEqual(release_files, sorted(checksums))
        for relative in release_files:
            digest = hashlib.sha256(release_bindings.read_source(ROOT, relative)).hexdigest()
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
        self.assertIn('cmp -s "$source_dir/$source" "$root/$installed"', worker)
        self.assertIn("HOSTKEY_COUNT", router)
        self.assertIn('cmp -s "$source_dir/$file" "$root/bin/$file"', router)
        self.assertIn("BUILDER_MODE", client)
        self.assertIn('pub="$key_type $key_data"', web_install)
        self.assertTrue('cmp -s "$source_file" "$root/$name" || hold INSTALLED_HASH 27' in web_update,
                        "router update must compare staged source with installed bytes")


if __name__ == "__main__":
    unittest.main()
