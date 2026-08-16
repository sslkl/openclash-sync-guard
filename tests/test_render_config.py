from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("render_config", ROOT / "tools/render_config.py")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


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
            root = pathlib.Path(directory)
            config = root / "config.toml"
            output = root / "rendered"
            config.write_text(self.valid_config(), encoding="utf-8")
            MODULE.render(config, output)
            self.assertTrue((output / "SHA256SUMS").is_file())
            combined = "\n".join(
                path.read_text(encoding="utf-8")
                for path in output.rglob("*")
                if path.is_file() and path.name not in {"FILES", "SHA256SUMS"}
            )
            for marker in (
                "192.0.2.10", "192.0.2.11", "192.0.2.20",
                r"192\.0\.2\.10", r"192\.0\.2\.11", r"192\.0\.2\.20",
                "router_a", "router_b", "syncsvc",
            ):
                self.assertNotIn(marker, combined)
            installer = (output / "install_router_openclash_stage_client.sh").read_text(encoding="utf-8")
            self.assertIn("= 198.51.100.20 ]", installer)

    def test_rejects_placeholder_core_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            config = pathlib.Path(directory) / "config.toml"
            config.write_text((ROOT / "config.example.toml").read_text(encoding="utf-8"), encoding="utf-8")
            with self.assertRaises(ValueError):
                MODULE.load_config(config)

    def test_refuses_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            config = root / "config.toml"
            output = root / "rendered"
            config.write_text(self.valid_config(), encoding="utf-8")
            output.mkdir()
            with self.assertRaises(FileExistsError):
                MODULE.render(config, output)

    def test_rejects_ipv6_for_shell_and_url_compatibility(self):
        with tempfile.TemporaryDirectory() as directory:
            config = pathlib.Path(directory) / "config.toml"
            config.write_text(
                self.valid_config().replace('worker_host = "198.51.100.20"', 'worker_host = "2001:db8::8"'),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                MODULE.load_config(config)

    def test_replacements_are_simultaneous_not_cascading(self):
        with tempfile.TemporaryDirectory() as directory:
            config = pathlib.Path(directory) / "config.toml"
            config.write_text(
                self.valid_config()
                .replace('target_a_id = "gateway_a"', 'target_a_id = "router_b"')
                .replace('target_b_id = "gateway_b"', 'target_b_id = "router_a"'),
                encoding="utf-8",
            )
            values = MODULE.load_config(config)
            rendered = MODULE.apply_replacements("router_a router_b", MODULE.replacements(values))
            self.assertEqual(rendered, "router_b router_a")


if __name__ == "__main__":
    unittest.main()
