from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class StageContractStaticTests(unittest.TestCase):
    def text(self, name: str) -> str:
        return (ROOT / name).read_text(encoding="utf-8")

    def test_contract_is_redacted_and_closed(self):
        contract = json.loads(self.text("maying-converter-shape-contract.json"))
        self.assertEqual(contract["source_format"], "BASE64_SSR_URI_LIST")
        self.assertEqual(contract["allowed_top_level_keys"], ["allow-lan", "external-controller", "log-level", "mode", "port", "proxies", "proxy-groups", "rules", "socks-port"])
        self.assertEqual(contract["schema"], "publisher-v4-maying-converter-shape-contract-v2")
        self.assertEqual(contract["ignored_metadata_top_level_keys"], ["allow-lan", "external-controller", "log-level", "mode", "port", "socks-port"])
        self.assertEqual(len(contract["ignored_metadata_semantic_sha256"]), 64)
        self.assertEqual(
            [contract[key]["baseline"] for key in (
                "source_uri_count", "converted_proxy_count", "converted_group_count", "converted_rule_count",
            )],
            [110, 108, 13, 10231],
        )

    def test_vendored_pyyaml_is_closed_and_imported(self):
        vendor = ROOT / "vendor/pyyaml-6.0.2"
        expected = {
            "LICENSE", "SOURCE.json", "yaml/__init__.py", "yaml/composer.py", "yaml/constructor.py",
            "yaml/cyaml.py", "yaml/dumper.py", "yaml/emitter.py", "yaml/error.py", "yaml/events.py",
            "yaml/loader.py", "yaml/nodes.py", "yaml/parser.py", "yaml/reader.py", "yaml/representer.py",
            "yaml/resolver.py", "yaml/scanner.py", "yaml/serializer.py", "yaml/tokens.py",
        }
        actual = {path.relative_to(vendor).as_posix() for path in vendor.rglob("*") if path.is_file()}
        self.assertEqual(actual, expected)
        metadata = json.loads((vendor / "SOURCE.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["version"], "6.0.2")
        self.assertEqual(metadata["source_sha256"], "d584d9ec91ad65861cc08d42e834324ef890a082e591037abe114850ff7bbc3e")
        self.assertFalse(metadata["compiled_extensions_included"])
        script = (
            "import pathlib,sys; root=pathlib.Path(sys.argv[1]).resolve(); sys.path.insert(0,str(root)); "
            "import yaml; assert yaml.__version__=='6.0.2'; "
            "assert pathlib.Path(yaml.__file__).resolve().is_relative_to(root)"
        )
        subprocess.run([sys.executable, "-I", "-B", "-c", script, str(vendor)], check=True)

    def test_worker_builder_and_client_receipts_are_closed(self):
        worker = self.text("openclash_worker.py")
        builder = self.text("openclash_router_stage_builder.rb")
        client = self.text("openclash_router_stage_client.sh")
        for field in (
            "converter_udp_absent_count", "converter_udp_true_count", "converter_udp_false_count",
            "worker_udp_materialized_count", "normalized_udp_true_count", "ignored_rules_sha256",
            "ignored_top_level_key_set_sha256", "dns_semantic_sha256",
        ):
            self.assertIn(field, worker)
        for reason in ("CONVERTER_UDP_FALSE", "CONVERTER_UDP_TYPE", "UDP_COUNT_MISMATCH", "MAYING_DNS_UNEXPECTED"):
            self.assertIn(reason, worker)
            self.assertIn(reason, client)
        for field in (
            "base_dns_sha256", "candidate_dns_sha256", "maying_policy_host_count",
            "maying_policy_resolver_set_sha256", "maying_udp_true_count", "maying_tfo_false_count",
        ):
            self.assertIn(field, builder)
            self.assertIn(field, client)
        self.assertIn('[ "$candidate_sha" = "$builder_candidate_sha" ] || hold BUILDER_HASH', client)
        self.assertNotIn("uci set", client)
        self.assertNotIn("/etc/init.d/openclash restart", client)

    def test_transactional_upgrade_and_rollback_are_packaged(self):
        installer = self.text("install_openclash_worker.sh")
        update = self.text("update_openclash_worker_contract.sh")
        rollback = self.text("rollback_openclash_worker_contract.sh")
        manifest = self.text("FILES").splitlines()
        for name in (
            "maying-converter-shape-contract.json",
            "update_openclash_worker_contract.sh",
            "rollback_openclash_worker_contract.sh",
            "update_router_openclash_stage_assets.sh",
            "rollback_router_openclash_stage_assets.sh",
            "tests/test_stage_contract_static.py",
        ):
            self.assertIn(name, manifest)
        for name in (
            "update_openclash_worker_contract.sh",
            "rollback_openclash_worker_contract.sh",
            "update_router_openclash_stage_assets.sh",
            "rollback_router_openclash_stage_assets.sh",
            "tools/run_mihomo_syntax_check.sh",
            "tools/run_security_checks.sh",
        ):
            self.assertNotEqual((ROOT / name).stat().st_mode & 0o111, 0, name)
        self.assertIn("maying-converter-shape-contract.json", installer)
        self.assertLess(
            update.index('atomic_install "$staging/$contract" "$root/$contract"'),
            update.index('atomic_install "$staging/$worker" "$root/$worker"'),
        )
        self.assertIn("CONTRACT_PRESENT_BEFORE", update)
        self.assertIn("VENDOR_PRESENT_BEFORE", update)
        self.assertIn("VENDORED_PYYAML=6.0.2", update)
        self.assertIn("CURRENT_DRIFT", rollback)
        self.assertIn("ROLLBACK-COMMITTED", rollback)
        self.assertNotIn("systemctl", update + rollback)
        self.assertNotIn("/etc/init.d/openclash", update + rollback)

    def test_router_assets_have_locked_update_and_rollback(self):
        installer = self.text("install_router_openclash_stage_client.sh")
        update = self.text("update_router_openclash_stage_assets.sh")
        rollback = self.text("rollback_router_openclash_stage_assets.sh")
        audit = self.text("router-openclash-sync-capability-audit.sh")
        self.assertIn("router-openclash-sync-capability-audit.sh", installer)
        self.assertIn("cmp -s", installer)
        self.assertIn('flock -n 9 || hold LOCK', update)
        self.assertIn('atomic_install "$staging/$client" "$bin/$client"', update)
        self.assertIn("CLIENT_PUBLISHED_LAST=true", update)
        self.assertIn("CURRENT_DRIFT", rollback)
        self.assertIn("ACTIVE_CHANGED=false", update + rollback)
        self.assertIn("SYNC_CONTRACT_MARKERS", audit)


if __name__ == "__main__":
    unittest.main()
