from __future__ import annotations

import ast
import hashlib
import pathlib
import tempfile
import unittest
from unittest import mock

from tools import release_bindings

ROOT = pathlib.Path(__file__).resolve().parents[1]
from tools import render_config as MODULE


class RenderConfigTests(unittest.TestCase):
    def valid_config(self) -> str:
        return """
target_a_id = "gateway_a"
target_b_id = "gateway_b"
target_a_host = "198.51.100.10"
target_b_host = "203.0.113.11"
worker_host = "198.51.100.20"
service_user = "renderedsvc"
main_config = "Combined.yaml"
base_config = "Base.yaml"
source_config = "Source.yaml"
expected_core_sha256 = "abababababababababababababababababababababababababababababababab"
web_auth_user = "openclash-admin"
keychain_service = "org.example.rendered-openclash-sync"
allowed_networks = "198.51.100.0/24,203.0.113.0/24,127.0.0.0/8"
""".lstrip()

    def test_render_is_closed_and_contains_no_example_topology(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            config = root / "config.toml"
            output = root / "rendered"
            config.write_text(self.valid_config(), encoding="utf-8")
            MODULE.render(config, output)
            self.assertTrue((output / "SHA256SUMS").is_file())
            files = (output / "FILES").read_text(encoding="utf-8").splitlines()
            checksum_lines = (output / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
            self.assertEqual(files, sorted(files))
            self.assertEqual(len(files), len(checksum_lines))
            checksums = {}
            for line in checksum_lines:
                digest, relative = line.split("  ", 1)
                checksums[relative] = digest
            self.assertEqual(files, sorted(checksums))
            for relative in files:
                self.assertEqual(hashlib.sha256((output / relative).read_bytes()).hexdigest(), checksums[relative])
            combined = "\n".join(
                path.read_text(encoding="utf-8")
                for path in output.rglob("*")
                if path.is_file() and path.name not in {"FILES", "SHA256SUMS"}
                and path.relative_to(output).as_posix() not in MODULE.BINARY_FILES
            )
            for marker in (
                "192.0.2.10", "192.0.2.11", "192.0.2.20",
                r"192\.0\.2\.10", r"192\.0\.2\.11", r"192\.0\.2\.20",
            ):
                self.assertNotIn(marker, combined)
            self.assertNotRegex(combined, r"\brouter_[ab]\b")
            self.assertNotRegex(combined, r"(?<![A-Za-z0-9_-])syncsvc(?![A-Za-z0-9_-])")
            installer = (output / "install_router_openclash_stage_client.sh").read_text(encoding="utf-8")
            self.assertIn("= 198.51.100.20 ]", installer)
            self.assertIn("gateway_a|gateway_b", (output / "update_router_openclash_stage_assets.sh").read_text(encoding="utf-8"))

    def test_rejects_placeholder_core_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            config = pathlib.Path(directory).resolve() / "config.toml"
            config.write_text((ROOT / "config.example.toml").read_text(encoding="utf-8"), encoding="utf-8")
            with self.assertRaises(ValueError):
                MODULE.load_config(config)

    def test_refuses_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            config = root / "config.toml"
            output = root / "rendered"
            config.write_text(self.valid_config(), encoding="utf-8")
            output.mkdir()
            with self.assertRaises(FileExistsError):
                MODULE.render(config, output)

    def test_rejects_ipv6_for_shell_and_url_compatibility(self):
        with tempfile.TemporaryDirectory() as directory:
            config = pathlib.Path(directory).resolve() / "config.toml"
            config.write_text(
                self.valid_config().replace('worker_host = "198.51.100.20"', 'worker_host = "2001:db8::8"'),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                MODULE.load_config(config)

    def test_replacements_are_simultaneous_not_cascading(self):
        with tempfile.TemporaryDirectory() as directory:
            config = pathlib.Path(directory).resolve() / "config.toml"
            config.write_text(
                self.valid_config()
                .replace('target_a_id = "gateway_a"', 'target_a_id = "router_b"')
                .replace('target_b_id = "gateway_b"', 'target_b_id = "router_a"'),
                encoding="utf-8",
            )
            values = MODULE.load_config(config)
            rendered = MODULE.apply_replacements("router_a router_b", MODULE.replacements(values))
            self.assertEqual(rendered, "router_b router_a")


    def test_binary_vendor_and_release_bindings_are_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            config, output = root / "config.toml", root / "rendered"
            config.write_text(self.valid_config(), encoding="utf-8")
            MODULE.render(config, output)
            release_bindings.bind_release(output, check=True)
            for relative in MODULE.BINARY_FILES:
                self.assertEqual((ROOT / relative).read_bytes(), (output / relative).read_bytes())
            for name in MODULE.VENDOR_MEMBERS:
                relative = "vendor/pyyaml-6.0.2/" + name
                self.assertEqual((ROOT / relative).read_bytes(), (output / relative).read_bytes())
            self.assertEqual(19, len(MODULE.VENDOR_MEMBERS))
            members = set((output / "FILES").read_text().splitlines())
            self.assertEqual(set(MODULE.OPERATIONAL_FILES) | {
                "openclash-sync-web/FILES", "openclash-sync-web/SHA256SUMS"}, members)
            web_members = (output / "openclash-sync-web/FILES").read_text().splitlines()
            self.assertEqual(sorted(web_members), web_members)
            self.assertTrue(set(release_bindings.RUNTIME_FILES).issubset(web_members))
            self.assertNotIn("deploy_worker_lan_access.sh", web_members)
            for relative in members:
                if relative.endswith(".py"):
                    ast.parse((output / relative).read_bytes(), filename=relative)

    def test_lan_policy_and_managed_update_names_follow_rendered_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            config, output = root / "config.toml", root / "rendered"
            config.write_text(self.valid_config(), encoding="utf-8")
            MODULE.render(config, output)
            web = output / "openclash-sync-web"
            server = (web / "server.py").read_text()
            service = (web / "openclash-sync-web.service").read_text()
            self.assertIn('LAN_BIND_ADDRESS = ipaddress.ip_address("198.51.100.20")', server)
            allowlist = "127.0.0.0/8,198.51.100.0/24,203.0.113.0/24"
            self.assertIn('RENDERED_LAN_NETWORKS = "' + allowlist + '"', server)
            self.assertIn("OPENCLASH_WEB_ALLOWED_NETWORKS=" + allowlist, service)
            self.assertIn('if frozenset(ALLOWED_NETWORKS) != LAN_CLIENT_NETWORKS:', server)
            agent = (web / "openclash_web_router_agent.lua").read_text()
            self.assertIn('local base = "Base.yaml"', agent)
            self.assertIn('local source = "Source.yaml"', agent)
            self.assertIn('request.action=="update_maying" and base or source', agent)
            self.assertIn('local name=filename:sub(1,-6)', agent)
            worker = (output / "openclash_worker.py").read_text()
            helper = (web / "openclash_web_helper.py").read_text()
            self.assertIn('"198.51.100.20"', worker)
            for text in (helper, agent):
                self.assertIn('gateway_a', text)
                self.assertIn('gateway_b', text)

    def test_rejects_unbounded_or_unusable_networks(self):
        invalid = (
            "0.0.0.0/0", "::/0", "224.0.0.0/4", "240.0.0.0/4", "169.254.0.0/16",
            "0.0.0.0/8", "127.0.0.0/8", "198.51.100.0/24",
            "127.0.0.0/8,198.51.100.0/24,198.51.100.99/24",
        )
        for value in invalid:
            with self.subTest(networks=value):
                with self.assertRaises(ValueError):
                    MODULE.normalize_networks(value, "198.51.100.20")

    def test_networks_are_canonical_without_widening(self):
        value = "198.51.100.42/24,127.0.0.1/32,203.0.113.11/32"
        self.assertEqual(MODULE.normalize_networks(value, "198.51.100.20"),
                         "127.0.0.1/32,198.51.100.0/24,203.0.113.11/32")

    def test_rejects_root_service_and_zero_core_placeholder(self):
        configs = (
            self.valid_config().replace('service_user = "renderedsvc"', 'service_user = "root"'),
            self.valid_config().replace("ab" * 32, "0" * 64),
        )
        with tempfile.TemporaryDirectory() as directory:
            config = pathlib.Path(directory).resolve() / "config.toml"
            for text in configs:
                with self.subTest(config_kind="invalid privileged or unbound deployment"):
                    config.write_text(text)
                    with self.assertRaises(ValueError):
                        MODULE.load_config(config)

    def test_rejects_config_symlink_without_following_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            original = root / "original.toml"
            original.write_text(self.valid_config())
            config = root / "config.toml"
            config.symlink_to(original)
            with self.assertRaises(ValueError):
                MODULE.render(config, root / "rendered")
            self.assertFalse((root / "rendered").exists())

    def test_refuses_dangling_output_and_symlink_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            config = root / "config.toml"
            config.write_text(self.valid_config())
            dangling = root / "rendered"
            dangling.symlink_to(root / "absent", target_is_directory=True)
            with self.assertRaises(FileExistsError):
                MODULE.render(config, dangling)
            self.assertTrue(dangling.is_symlink())
            actual = root / "actual"
            actual.mkdir()
            alias = root / "alias"
            alias.symlink_to(actual, target_is_directory=True)
            with self.assertRaises(ValueError):
                MODULE.render(config, alias / "rendered")
            self.assertEqual([], list(actual.iterdir()))

    def test_source_symlink_is_rejected_before_output_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            config = root / "config.toml"
            config.write_text(self.valid_config())
            source = root / "source.py"
            source.symlink_to(ROOT / "openclash_worker.py")
            with mock.patch.object(MODULE, "ROOT", root), \
                    mock.patch.object(MODULE, "OPERATIONAL_FILES", ("source.py",)):
                with self.assertRaises(ValueError):
                    MODULE.render(config, root / "rendered")
            self.assertFalse((root / "rendered").exists())

    def test_binding_failure_removes_only_the_new_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            config, output = root / "config.toml", root / "rendered"
            config.write_text(self.valid_config())
            sentinel = root / "keep.txt"
            sentinel.write_text("unrelated caller file")
            with mock.patch.object(release_bindings, "bind_release", side_effect=ValueError("synthetic binding failure")):
                with self.assertRaisesRegex(ValueError, "synthetic binding failure"):
                    MODULE.render(config, output)
            self.assertFalse(output.exists())
            self.assertEqual("unrelated caller file", sentinel.read_text())
            self.assertEqual(self.valid_config(), config.read_text())

    def test_target_and_ip_prefixes_do_not_rename_unrelated_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            config = pathlib.Path(directory).resolve() / "config.toml"
            config.write_text(self.valid_config())
            values = MODULE.load_config(config)
            text = "router_a router_b openclash_web_router_agent.lua install_router_backup_retention_schedule.sh"
            self.assertEqual(MODULE.apply_replacements(text, MODULE.replacements(values)),
                             "gateway_a gateway_b openclash_web_router_agent.lua install_router_backup_retention_schedule.sh")
            for address in ("192.0.2.100", "192.0.2.110", r"192\.0\.2\.100", r"192\.0\.2\.110"):
                self.assertEqual(address, MODULE.apply_replacements(address, MODULE.replacements(values)))
            self.assertEqual("198.51.100.10 203.0.113.11 198.51.100.20",
                             MODULE.apply_replacements("192.0.2.10 192.0.2.11 192.0.2.20", MODULE.replacements(values)))


if __name__ == "__main__":
    unittest.main()
