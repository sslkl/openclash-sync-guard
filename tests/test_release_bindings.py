from __future__ import annotations

import ast
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from tools import release_bindings as BINDINGS

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "openclash-sync-web"
MEMBERS = set(BINDINGS.RUNTIME_FILES) | set(BINDINGS.ROUTER_FILES) | {
    "converter_runtime_bundle.py", "server.py", "openclash_web_helper.py",
    "install_router_web_agent.sh", "update_router_web_agent.sh",
    "install_router_backup_retention_schedule.sh",
}


def constant(path: Path, name: str):
    matches = [node.value for node in ast.parse(path.read_bytes()).body
               if isinstance(node, ast.Assign)
               and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    if len(matches) != 1:
        raise AssertionError(f"expected one constant: {name}")
    return ast.literal_eval(matches[0])


class ReleaseBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.web = self.root / "openclash-sync-web"
        for name in sorted(MEMBERS):
            destination = self.web / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(WEB / name, destination)
            destination.chmod((WEB / name).stat().st_mode & 0o777)

    def snapshot(self):
        return {name: ((self.web / name).read_bytes(), (self.web / name).stat().st_mode,
                       (self.web / name).stat().st_mtime_ns) for name in MEMBERS}

    def check_pins(self, identities):
        for name in ("server.py", "openclash_web_helper.py"):
            self.assertEqual(constant(self.web / name, "CONVERTER_RUNTIME_ID"), identities["runtime_id"])
        self.assertEqual(constant(self.web / "openclash_web_helper.py", "CONVERTER_SANDBOX_SHA256"),
                         hashlib.sha256((self.web / "converter_sandbox.py").read_bytes()).hexdigest())
        for installer in ("install_router_web_agent.sh", "update_router_web_agent.sh"):
            text = (self.web / installer).read_text()
            for name in BINDINGS.ROUTER_FILES:
                sha = hashlib.sha256((self.web / name).read_bytes()).hexdigest()
                self.assertRegex(text, re.escape(name) + r"\) printf '%s\\n' " + sha + r";;")
        expected = hashlib.sha256((self.web / "openclash_customizer.rb").read_bytes()).hexdigest()
        self.assertIn("expected_customizer=" + expected,
                      (self.web / "install_router_backup_retention_schedule.sh").read_text())

    def test_matches_runtime_builder_and_all_installer_pins(self):
        spec = importlib.util.spec_from_file_location("public_bundle_binding_test", WEB / "converter_runtime_bundle.py")
        bundle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bundle)
        identities = BINDINGS.bind_release(self.root)
        payload = {name: (self.web / name).read_bytes() for name in BINDINGS.RUNTIME_FILES}
        self.assertEqual(identities["runtime_id"], bundle.identity(payload))
        self.assertEqual(BINDINGS.RUNTIME_FILES, bundle.FILES)
        self.check_pins(identities)

    def test_second_binding_and_check_do_not_write(self):
        identities = BINDINGS.bind_release(self.root)
        before = self.snapshot()
        self.assertEqual(identities, BINDINGS.bind_release(self.root))
        self.assertEqual(identities, BINDINGS.bind_release(self.root, check=True))
        self.assertEqual(before, self.snapshot())

    def test_runtime_drift_is_detected_without_rewriting(self):
        old = BINDINGS.bind_release(self.root)
        member = self.web / "static/converter.js"
        member.write_bytes(member.read_bytes() + b"\n// synthetic binding drift\n")
        before = self.snapshot()
        with self.assertRaisesRegex(BINDINGS.BindingError, "stale release bindings"):
            BINDINGS.bind_release(self.root, check=True)
        self.assertEqual(before, self.snapshot())
        new = BINDINGS.bind_release(self.root)
        self.assertNotEqual(old["runtime_id"], new["runtime_id"])
        self.check_pins(new)

    def test_sandbox_and_customizer_changes_rebind_every_consumer(self):
        old = BINDINGS.bind_release(self.root)
        for name in ("converter_sandbox.py", "openclash_customizer.rb"):
            member = self.web / name
            member.write_bytes(member.read_bytes() + b"\n# synthetic binding drift\n")
        new = BINDINGS.bind_release(self.root)
        for name in ("runtime_id", "sandbox_sha256", "customizer_sha256"):
            self.assertNotEqual(old[name], new[name])
        self.check_pins(new)

    def test_member_contract_change_is_rejected_before_any_write(self):
        member = self.web / "converter_runtime_bundle.py"
        member.write_text(member.read_text().replace("'subscription_converter.py',", "'extra.py', 'subscription_converter.py',", 1))
        before = self.snapshot()
        with self.assertRaisesRegex(BINDINGS.BindingError, "runtime file contract changed"):
            BINDINGS.bind_release(self.root)
        self.assertEqual(before, self.snapshot())

    def test_duplicate_pin_is_rejected_before_any_write(self):
        member = self.web / "server.py"
        member.write_text(member.read_text() + '\nCONVERTER_RUNTIME_ID = "' + "a" * 64 + '"\n')
        before = self.snapshot()
        with self.assertRaisesRegex(BINDINGS.BindingError, "expected exactly one binding"):
            BINDINGS.bind_release(self.root)
        self.assertEqual(before, self.snapshot())

    def test_source_drift_during_planning_is_rejected(self):
        original = BINDINGS.read_source
        visits = {}
        def changed(root, name):
            data = original(root, name)
            visits[name] = visits.get(name, 0) + 1
            if name == "static/converter.js" and visits[name] > 1:
                return data + b"\n// synthetic drift\n"
            return data
        before = self.snapshot()
        with mock.patch.object(BINDINGS, "read_source", side_effect=changed):
            with self.assertRaisesRegex(BINDINGS.BindingError, "source changed during binding"):
                BINDINGS.bind_release(self.root)
        self.assertEqual(before, self.snapshot())

    def test_symlink_root_and_runtime_member_are_rejected(self):
        alias = self.root / "root-alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(BINDINGS.BindingError):
            BINDINGS.bind_release(alias)
        member = self.web / "static/converter.js"
        member.unlink()
        member.symlink_to(WEB / "static/converter.js")
        with self.assertRaises(BINDINGS.BindingError):
            BINDINGS.bind_release(self.root)

    def test_symlink_parent_directory_is_rejected(self):
        static = self.web / "static"
        for name in list(static.iterdir()):
            name.unlink()
        static.rmdir()
        static.symlink_to(WEB / "static", target_is_directory=True)
        with self.assertRaises(BINDINGS.BindingError):
            BINDINGS.bind_release(self.root)

    def test_hardlink_and_fifo_members_are_rejected(self):
        member = self.web / "static/converter.js"
        member.unlink()
        os.link(self.web / "static/converter_apply.js", member)
        with self.assertRaises(BINDINGS.BindingError):
            BINDINGS.bind_release(self.root)
        member.unlink()
        os.mkfifo(member)
        with self.assertRaises(BINDINGS.BindingError):
            BINDINGS.bind_release(self.root)

    def test_disabled_legacy_entrypoint_cannot_execute_a_migration(self):
        result = subprocess.run(["/bin/sh", str(WEB / "deploy_worker_lan_access.sh"), str(self.root)],
                                capture_output=True, text=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 64)
        self.assertIn("HOLD=LEGACY_LAN_MIGRATOR_DISABLED", result.stderr)
        self.assertIn("LIVE_CHANGES=false", result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
