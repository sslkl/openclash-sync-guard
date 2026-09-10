from __future__ import annotations

import hashlib
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
INSTALL = (ROOT / "install_worker_web_console.sh").read_text()
UPDATE = (ROOT / "update_worker_web_console.sh").read_text()
SERVER = (ROOT / "server.py").read_text()
SERVICE = (ROOT / "openclash-sync-web.service").read_text()


def heredoc(script: str, marker: str) -> str:
    opening = f"<<'{marker}'\n"
    start = script.index(opening) + len(opening)
    end = script.index(f"\n{marker}\n", start)
    return script[start:end] + "\n"


SOURCE_STAGER = heredoc(INSTALL, "PY_SOURCE_STAGE")
UPDATE_SOURCE_FILES = (
    "server.py",
    "openclash_web_helper.py",
    "openclash-sync-web.service",
    "auth-ha1",
    "static/index.html",
    "static/app.css",
    "static/app.js",
    "static/OpenClash_Sync_Logo.png",
)
INSTALL_SOURCE_FILES = UPDATE_SOURCE_FILES + ("router_a", "router_b", "known_hosts")
UPDATE_STAGE_LABELS = {
    "server.py": "app-server.py",
    "auth-ha1": "app-auth-ha1",
    "static/index.html": "static-index.html",
    "static/app.css": "static-app.css",
    "static/app.js": "static-app.js",
    "static/OpenClash_Sync_Logo.png": "static-logo.png",
    "openclash_web_helper.py": "helper",
    "openclash-sync-web.service": "service",
}


class SourceTrustBehaviorTests(unittest.TestCase):
    def test_web_runtime_uses_project_vendored_pyyaml(self):
        for script in (INSTALL, UPDATE):
            self.assertIn('$shared_vendor', script)
            self.assertIn('sys.path.insert(0, str(vendor))', script)
            self.assertIn('assert yaml.__version__ == "6.0.2"', script)
        self.assertIn('OPENCLASH_WEB_PYYAML_ROOT', SERVER)
        self.assertIn('raise RuntimeError("PyYAML 6.0.2 is required")', SERVER)

    def make_tree(self, root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
        source = root / "source"
        destination = root / "destination"
        source.mkdir(mode=0o700)
        destination.mkdir(mode=0o700)
        (source / "static").mkdir(mode=0o700)
        (source / "server.py").write_bytes(b"print('ok')\n")
        (source / "static" / "index.html").write_bytes(b"<p>ok</p>\n")
        os.chmod(source / "server.py", 0o600)
        os.chmod(source / "static" / "index.html", 0o600)
        return source, destination

    def run_stager(
        self, source: pathlib.Path, destination: pathlib.Path, *assets: str
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                "-",
                str(source),
                str(destination),
                str(os.getuid()),
                str(os.getgid()),
                *assets,
            ],
            input=SOURCE_STAGER,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_stager_copies_regular_private_assets_and_syncs_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, destination = self.make_tree(pathlib.Path(temporary).resolve())
            result = self.run_stager(source, destination, "server.py", "static/index.html")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertRegex(result.stdout.strip(), r"^\d+:\d+$")
            self.assertEqual((destination / "server.py").read_bytes(), b"print('ok')\n")
            self.assertEqual((destination / "static" / "index.html").read_bytes(), b"<p>ok</p>\n")
            self.assertEqual((destination / "server.py").stat().st_mode & 0o7777, 0o600)
            self.assertEqual((destination / "static").stat().st_mode & 0o7777, 0o700)

    def test_stager_rejects_symlink_asset(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, destination = self.make_tree(pathlib.Path(temporary).resolve())
            (source / "server.py").unlink()
            (source / "server.py").symlink_to("static/index.html")
            result = self.run_stager(source, destination, "server.py")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((destination / "server.py").exists())

    def test_stager_rejects_symlink_subdirectory(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, destination = self.make_tree(pathlib.Path(temporary).resolve())
            real_static = source / "real-static"
            (source / "static" / "index.html").replace(real_static)
            (source / "static").rmdir()
            (source / "static").symlink_to(real_static.name)
            result = self.run_stager(source, destination, "static/index.html")
            self.assertNotEqual(result.returncode, 0)

    def test_stager_rejects_group_writable_asset(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, destination = self.make_tree(pathlib.Path(temporary).resolve())
            # Intentionally create an insecure mode to verify fail-closed rejection.
            os.chmod(source / "server.py", 0o620)  # nosec B103
            result = self.run_stager(source, destination, "server.py")
            self.assertNotEqual(result.returncode, 0)

    def test_stager_rejects_non_private_source_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, destination = self.make_tree(pathlib.Path(temporary).resolve())
            # Intentionally create an insecure mode to verify fail-closed rejection.
            os.chmod(source, 0o750)  # nosec B103
            result = self.run_stager(source, destination, "server.py")
            self.assertNotEqual(result.returncode, 0)

    def test_stager_rejects_empty_asset(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, destination = self.make_tree(pathlib.Path(temporary).resolve())
            (source / "server.py").write_bytes(b"")
            result = self.run_stager(source, destination, "server.py")
            self.assertNotEqual(result.returncode, 0)

    def test_stager_rejects_hardlinked_asset(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, destination = self.make_tree(pathlib.Path(temporary).resolve())
            os.link(source / "server.py", source / "server.py.alias")
            result = self.run_stager(source, destination, "server.py")
            self.assertNotEqual(result.returncode, 0)

    def test_stager_rejects_undeclared_source_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, destination = self.make_tree(pathlib.Path(temporary).resolve())
            (source / "unexpected.txt").write_bytes(b"unexpected\n")
            os.chmod(source / "unexpected.txt", 0o600)
            result = self.run_stager(
                source, destination, "server.py", "static/index.html"
            )
            self.assertNotEqual(result.returncode, 0)


class RecoveryCleanupBehaviorTests(unittest.TestCase):
    def populate(
        self, root: pathlib.Path, names: tuple[str, ...], *, prefix: bytes = b"asset:"
    ) -> None:
        root.mkdir(mode=0o700, parents=True)
        for name in names:
            path = root / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes(prefix + name.encode("ascii") + b"\n")
            os.chmod(path, 0o600)

    def run_embedded(self, code: str, *arguments: object) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-I", "-B", "-", *(str(item) for item in arguments)],
            input=code,
            text=True,
            capture_output=True,
            check=False,
        )

    def snapshot(self, root: pathlib.Path) -> tuple[tuple[str, str, int, bytes], ...]:
        entries = []
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
            if path.is_dir():
                entries.append((relative, "directory", info.st_mode & 0o7777, b""))
            else:
                entries.append((relative, "file", info.st_mode & 0o7777, path.read_bytes()))
        return tuple(entries)

    def test_partial_source_consumption_is_recoverable_and_inode_bound(self):
        cases = (
            (
                heredoc(INSTALL, "PY_RECOVER_SOURCE"),
                INSTALL_SOURCE_FILES,
                lambda source, identity, stage: (
                    source,
                    identity,
                    stage,
                    "delete",
                    os.getuid(),
                    os.getgid(),
                ),
            ),
            (
                heredoc(UPDATE, "PY_SOURCE_CLEANUP"),
                UPDATE_SOURCE_FILES,
                lambda source, identity, stage: (
                    source,
                    identity,
                    stage,
                    "recovery",
                    os.getuid(),
                    os.getgid(),
                ),
            ),
        )
        for code, manifest, arguments in cases:
            with (
                self.subTest(marker=code.splitlines()[0]),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = pathlib.Path(temporary).resolve()
                source = root / "source"
                transaction = root / "transaction"
                stage = transaction / "source"
                transaction.mkdir(mode=0o700)
                self.populate(stage, manifest)
                self.populate(source, ("server.py", "static/index.html"))
                info = source.stat()
                identity = f"{info.st_dev}:{info.st_ino}"
                result = self.run_embedded(code, *arguments(source, identity, stage))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(source.exists())
                self.assertTrue(stage.exists())

    def test_partial_source_recovery_rejects_hardlinks(self):
        for marker, manifest, argument_builder in (
            (
                "PY_RECOVER_SOURCE",
                INSTALL_SOURCE_FILES,
                lambda source, identity, stage: (
                    source,
                    identity,
                    stage,
                    "delete",
                    os.getuid(),
                    os.getgid(),
                ),
            ),
            (
                "PY_SOURCE_CLEANUP",
                UPDATE_SOURCE_FILES,
                lambda source, identity, stage: (
                    source,
                    identity,
                    stage,
                    "recovery",
                    os.getuid(),
                    os.getgid(),
                ),
            ),
        ):
            code = heredoc(INSTALL if marker == "PY_RECOVER_SOURCE" else UPDATE, marker)
            with (
                self.subTest(marker=marker),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = pathlib.Path(temporary).resolve()
                source = root / "source"
                transaction = root / "transaction"
                stage = transaction / "source"
                transaction.mkdir(mode=0o700)
                self.populate(stage, manifest)
                self.populate(source, ("server.py",))
                os.link(source / "server.py", root / "external-link")
                info = source.stat()
                identity = f"{info.st_dev}:{info.st_ino}"
                result = self.run_embedded(
                    code, *argument_builder(source, identity, stage)
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(source.exists())

    def test_source_recovery_rejects_replaced_inode_and_preserves_stage(self):
        code = heredoc(UPDATE, "PY_SOURCE_CLEANUP")
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            source = root / "source"
            stage = root / "transaction" / "source"
            self.populate(source, ("server.py",))
            self.populate(stage, UPDATE_SOURCE_FILES)
            original = source.stat()
            identity = f"{original.st_dev}:{original.st_ino}"
            source.rename(root / "original-source")
            self.populate(source, ("server.py",))
            result = self.run_embedded(
                code,
                source,
                identity,
                stage,
                "recovery",
                os.getuid(),
                os.getgid(),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(source.exists())
            self.assertTrue(stage.exists())

    def test_update_stage_cleanup_accepts_proven_partial_and_rejects_drift(self):
        code = heredoc(UPDATE, "PY_STAGE_CLEANUP")
        for drift in (False, True):
            with (
                self.subTest(drift=drift),
                tempfile.TemporaryDirectory() as temporary,
            ):
                transaction = pathlib.Path(temporary).resolve() / "transaction"
                stage = transaction / "source"
                self.populate(stage, ("server.py",))
                digest = hashlib.sha256((stage / "server.py").read_bytes()).hexdigest()
                if drift:
                    digest = "0" * 64
                intent = transaction / "app-server.py.after-sha"
                intent.write_text(digest + "\n")
                os.chmod(intent, 0o600)
                result = self.run_embedded(
                    code, stage, "delete", os.getuid(), os.getgid()
                )
                self.assertEqual(result.returncode == 0, not drift, result.stderr)
                self.assertEqual(stage.exists(), drift)

    def test_source_validate_modes_preserve_source_and_stage(self):
        cases = (
            (heredoc(INSTALL, "PY_RECOVER_SOURCE"), INSTALL_SOURCE_FILES, "validate"),
            (heredoc(UPDATE, "PY_SOURCE_CLEANUP"), UPDATE_SOURCE_FILES, "validate"),
        )
        for code, manifest, mode in cases:
            with (
                self.subTest(marker=code.splitlines()[0]),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = pathlib.Path(temporary).resolve()
                source = root / "source"
                stage = root / "transaction" / "source"
                self.populate(source, manifest)
                self.populate(stage, manifest)
                source_info = source.stat()
                identity = f"{source_info.st_dev}:{source_info.st_ino}"
                source_before = self.snapshot(source)
                stage_before = self.snapshot(stage)

                result = self.run_embedded(
                    code,
                    source,
                    identity,
                    stage,
                    mode,
                    os.getuid(),
                    os.getgid(),
                )

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.snapshot(source), source_before)
                self.assertEqual(self.snapshot(stage), stage_before)

    def test_update_stage_validate_preserves_proven_stage(self):
        code = heredoc(UPDATE, "PY_STAGE_CLEANUP")
        with tempfile.TemporaryDirectory() as temporary:
            transaction = pathlib.Path(temporary).resolve() / "transaction"
            stage = transaction / "source"
            self.populate(stage, UPDATE_SOURCE_FILES)
            for asset, label in UPDATE_STAGE_LABELS.items():
                digest = hashlib.sha256((stage / asset).read_bytes()).hexdigest()
                intent = transaction / f"{label}.after-sha"
                intent.write_text(digest + "\n")
                os.chmod(intent, 0o600)
            before = self.snapshot(transaction)

            result = self.run_embedded(
                code, stage, "validate", os.getuid(), os.getgid()
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self.snapshot(transaction), before)

    def test_recovery_prevalidation_rejects_drift_without_deleting_evidence(self):
        source_code = heredoc(UPDATE, "PY_SOURCE_CLEANUP")
        stage_code = heredoc(UPDATE, "PY_STAGE_CLEANUP")
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            source = root / "source"
            transaction = root / "transaction"
            stage = transaction / "source"
            self.populate(source, UPDATE_SOURCE_FILES)
            self.populate(stage, UPDATE_SOURCE_FILES)
            source_info = source.stat()
            identity = f"{source_info.st_dev}:{source_info.st_ino}"
            (stage / "server.py").write_bytes(b"drifted stage\n")
            source_before = self.snapshot(source)
            stage_before = self.snapshot(stage)

            source_result = self.run_embedded(
                source_code,
                source,
                identity,
                stage,
                "validate",
                os.getuid(),
                os.getgid(),
            )

            self.assertNotEqual(source_result.returncode, 0)
            self.assertEqual(self.snapshot(source), source_before)
            self.assertEqual(self.snapshot(stage), stage_before)

            for asset, label in UPDATE_STAGE_LABELS.items():
                digest = hashlib.sha256((stage / asset).read_bytes()).hexdigest()
                if asset == "server.py":
                    digest = "0" * 64
                intent = transaction / f"{label}.after-sha"
                intent.write_text(digest + "\n")
                os.chmod(intent, 0o600)
            transaction_before = self.snapshot(transaction)

            stage_result = self.run_embedded(
                stage_code, stage, "validate", os.getuid(), os.getgid()
            )

            self.assertNotEqual(stage_result.returncode, 0)
            self.assertEqual(self.snapshot(transaction), transaction_before)


class WorkerWebDeployStaticTests(unittest.TestCase):
    def test_all_embedded_python_programs_parse(self):
        for script_name, script in (("install", INSTALL), ("update", UPDATE)):
            openers = tuple(re.finditer(r"<<'(PY_[A-Z0-9_]+)'[^\n]*\n", script))
            self.assertGreater(len(openers), 5)
            for opening in openers:
                marker = opening.group(1)
                end = script.index(f"\n{marker}\n", opening.end())
                code = script[opening.end() : end]
                with self.subTest(script=script_name, marker=marker):
                    compile(code, f"{script_name}:{marker}", "exec")

    def test_install_and_update_use_identical_descriptor_based_source_stager(self):
        self.assertEqual(SOURCE_STAGER, heredoc(UPDATE, "PY_SOURCE_STAGE"))
        for fragment in (
            "os.O_DIRECTORY | os.O_NOFOLLOW",
            "follow_symlinks=False",
            "before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns",
            "while view:",
            "if written <= 0:",
            "os.fsync(outputfd)",
            "source leaf must be private",
            "MAX_TOTAL = 32 * 1024 * 1024",
        ):
            self.assertIn(fragment, SOURCE_STAGER)
        for script in (INSTALL, UPDATE):
            self.assertIn('"$source" "$source_stage" 0 0', script)
            self.assertNotIn('install -m 0555 -o root -g root "$source/', script)
            self.assertNotIn('rm -rf "$source"', script)

    def test_source_cleanup_is_inode_bound_and_rejects_special_entries(self):
        install_cleanup = heredoc(INSTALL, "PY_SOURCE_BUNDLE")
        update_cleanup = heredoc(UPDATE, "PY_SOURCE_CLEANUP")
        self.assertIn("identity != expected_identity", install_cleanup)
        self.assertIn('f"{info.st_dev}:{info.st_ino}" != expected_identity', update_cleanup)
        for cleanup in (install_cleanup, update_cleanup):
            self.assertIn("follow_symlinks=False", cleanup)
            self.assertIn("st_nlink", cleanup)
            self.assertIn("os.fsync(parentfd)", cleanup)
        self.assertIn("source cleanup rejects special entries", update_cleanup)

    def test_install_pending_cleanup_uses_partial_recovery_not_full_attestation(self):
        pending = INSTALL[INSTALL.index("recover_pending(){") : INSTALL.index("asset_state(){")]
        cleanup = INSTALL[
            INSTALL.index("cleanup_bound_source(){") : INSTALL.index("recover_bound_source(){")
        ]
        self.assertIn('"$pending_tx/source"', pending)
        self.assertIn("preserve-intact", pending)
        self.assertIn("recover_bound_source", cleanup)
        self.assertIn("source_bundle attest", cleanup)
        self.assertIn("bound_policy", cleanup)
        self.assertIn("seen_files.issubset(files)", heredoc(INSTALL, "PY_RECOVER_SOURCE"))

    def test_install_rebinds_source_manifest_after_staging(self):
        stage = INSTALL.index("staged_source_identity=$(stage_source")
        attestation = INSTALL.index("post_stage_attestation=$(source_bundle_attestation install)", stage)
        comparison = INSTALL.index('[ "$post_stage_attestation" = "$source_identity $source_manifest_sha" ]', attestation)
        stage_validation = INSTALL.index('recover_bound_source "$source" "$source_identity" "$source_stage" validate', comparison)
        first_intent = INSTALL.index("write_intent app-server.py", stage_validation)
        self.assertLess(stage, attestation)
        self.assertLess(attestation, comparison)
        self.assertLess(comparison, stage_validation)
        self.assertLess(stage_validation, first_intent)

    def test_publication_uses_same_directory_atomic_replace_and_fsync(self):
        for script in (INSTALL, UPDATE):
            self.assertIn('.openclash-web-new-${transaction_id}-${label}', script)
            self.assertIn('.openclash-web-restore-${recovery_tx_id}-${label}', script)
            self.assertIn('set -C; : >"$temporary"', script)
            self.assertIn('cmp -s "$source_file" "$temporary"', script)
            self.assertIn('fsync_file "$temporary"', script)
            self.assertIn('mv -f "$temporary" "$target_file"', script)
            self.assertIn('fsync_path "$target_file"', script)
            self.assertNotIn('systemctl restart openclash-sync-web.service', script)

    def test_publish_intents_are_newline_terminated_digest_records(self):
        for script in (INSTALL, UPDATE):
            start = script.index("write_intent(){")
            write_intent = script[start : script.index("\n}", start) + 2]
            self.assertIn('intended_sha=$(sha "$source_file")', write_intent)
            self.assertIn("printf '%s\\n' \"$intended_sha\"", write_intent)
            self.assertNotIn('sha "$source_file" >"$partial"', write_intent)

    def test_web_uses_worker_managed_vendored_pyyaml_tree(self):
        shared = "/opt/publisher-v4-openclash-worker/vendor/pyyaml-6.0.2"
        self.assertIn(f"Environment=OPENCLASH_WEB_PYYAML_ROOT={shared}", SERVICE)
        self.assertIn('os.environ.get("OPENCLASH_WEB_PYYAML_ROOT"', SERVER)
        self.assertIn("VENDORED_PYYAML.resolve(strict=True)", SERVER)
        self.assertIn("VENDORED_PYYAML not in Path(yaml.__file__).resolve(strict=True).parents", SERVER)
        for script in (INSTALL, UPDATE):
            self.assertIn(f"shared_vendor={shared}", script)
            self.assertIn("shared_vendor_ok || hold SHARED_VENDOR", script)
            self.assertIn('"$(find "$shared_vendor" -type f | wc -l', script)
            self.assertIn("-eq 19", script)
            self.assertIn("d584d9ec91ad65861cc08d42e834324ef890a082e591037abe114850ff7bbc3e", script)
            self.assertIn('root in pathlib.Path(yaml.__file__).resolve(strict=True).parents', script)
            self.assertNotIn('$app/vendor/pyyaml-6.0.2', script)

    def test_target_partials_are_bound_to_transaction_and_unbound_residue_holds(self):
        for script in (INSTALL, UPDATE):
            self.assertIn("cleanup_target_partials(){", script)
            self.assertIn("secure_unlink_partial(){", script)
            self.assertIn("os.O_DIRECTORY | os.O_NOFOLLOW", script)
            self.assertIn("os.unlink(parts[-1], dir_fd=directory)", script)
            self.assertIn("os.fsync(directory)", script)
            self.assertIn("reject_unbound_target_partials(){", script)
            self.assertIn(".openclash-web-new-${cleanup_id}-", script)
            self.assertIn(".openclash-web-restore-${cleanup_id}-", script)
            self.assertIn("TARGET_PARTIAL_UNBOUND", script)
            self.assertIn("cleanup_target_partials", script)
            self.assertIn("cleanup_target_partials \"$residue_tx\"", script)
            rollback = script[script.index("rollback(){") : script.index("finish(){")]
            stop = rollback.index("stop_service_for_recovery")
            gate = rollback.index('if [ "$rollback_service_stopped" = true ]')
            cleanup = rollback.index("cleanup_target_partials")
            self.assertLess(stop, cleanup)
            self.assertLess(stop, gate)
            self.assertLess(gate, cleanup)
            self.assertIn(
                'rollback_ok=false; rollback_service_stopped=false',
                rollback[stop:gate],
            )
            self.assertLess(
                cleanup,
                rollback.index("write_status"),
            )
            self.assertIn("TARGET_PARTIAL_CLEANUP_FAILED", script)

    def test_install_rollback_is_hash_bound_and_never_recursive(self):
        self.assertIn("write_intent app-server.py", INSTALL)
        self.assertIn('intended_file=$transaction/$label.after-sha', INSTALL)
        self.assertIn('"$(sha "$target_file" 2>/dev/null || true)" = "$intended_sha"', INSTALL)
        self.assertIn('rmdir "$app/static" "$app" "$keys/keys" "$keys"', INSTALL)
        self.assertNotIn("rm -rf", INSTALL)
        self.assertIn('write_status ROLLBACK_FAILED', INSTALL)
        self.assertIn('systemctl disable --now openclash-sync-web.service', INSTALL)

    def test_update_arms_before_service_is_disabled_and_assets_change(self):
        arm = UPDATE.index('mv -f "$backup/ARMED.partial" "$backup/ARMED"')
        disable = UPDATE.index("systemctl disable --now openclash-sync-web.service", arm)
        publish = UPDATE.index('atomic_replace "$source_stage/server.py"', disable)
        enable = UPDATE.index("systemctl enable --now openclash-sync-web.service", publish)
        committed = UPDATE.index('mv -f "$backup/COMMITTED.partial" "$backup/COMMITTED"', enable)
        self.assertLess(arm, disable)
        self.assertLess(disable, publish)
        self.assertLess(publish, enable)
        self.assertLess(enable, committed)

    def test_update_backup_and_restore_are_hash_checked_and_synced(self):
        for fragment in (
            "SHA256SUMS.before",
            'stat -c \'%d:%i\' "$target_file"',
            'fsync_file "$backup/$label.before"',
            "sha256sum -c SHA256SUMS.before",
            'restore_asset "$app/server.py"',
            'restore_asset "$service"',
            'systemctl daemon-reload',
            "restored_healthy=true",
        ):
            self.assertIn(fragment, UPDATE)

    def test_update_rollback_failure_leaves_service_disabled(self):
        rollback = UPDATE[UPDATE.index("rollback(){") : UPDATE.index("finish(){")]
        self.assertIn("write_status ROLLBACK_FAILED", rollback)
        failure = rollback.index("write_status ROLLBACK_FAILED")
        self.assertIn("stop_service_for_recovery", rollback[:failure])
        stop_helper = UPDATE[
            UPDATE.index("stop_service_for_recovery(){") : UPDATE.index(
                "service_after_ok(){"
            )
        ]
        self.assertIn("systemctl disable --now openclash-sync-web.service", stop_helper)
        self.assertIn("ActiveState --value", stop_helper)
        self.assertIn("is-enabled openclash-sync-web.service", stop_helper)
        self.assertIn('rm -f "$backup/COMMITTED.partial" "$backup/COMMITTED"', rollback)

    def test_update_never_restores_after_backup_manifest_failure(self):
        rollback = UPDATE[UPDATE.index("rollback(){") : UPDATE.index("finish(){")]
        manifest = '(cd "$backup" && sha256sum -c SHA256SUMS.before >/dev/null 2>&1)'
        self.assertIn(manifest, rollback)
        self.assertLess(rollback.index(manifest), rollback.index('restore_asset "$app/server.py"'))
        self.assertIn("Never derive restore hashes", rollback)

    def test_install_binds_absent_service_and_independent_ssh_identities(self):
        self.assertIn('unit_state=$(systemctl show -p LoadState --value', INSTALL)
        self.assertIn('[ "$unit_state" = not-found ]', INSTALL)
        self.assertIn('[ "$service_mutation_started" = true ]', INSTALL)
        self.assertIn('[ "$router_a_public" != "$router_b_public" ]', INSTALL)
        self.assertIn('NR == 2 && router_a == 1 && router_b == 1', INSTALL)
        self.assertIn("KNOWN_HOST_REUSE", INSTALL)

    def test_commit_receipts_are_atomic_and_only_mark_success_after_fsync(self):
        for script, root in ((INSTALL, "transaction"), (UPDATE, "backup")):
            publish = script.index(f'mv -f "${root}/COMMITTED.partial" "${root}/COMMITTED"')
            sync = script.index(f'fsync_directory "${root}"', publish)
            committed = script.index("committed=true", sync)
            self.assertLess(publish, sync)
            self.assertLess(sync, committed)
            self.assertIn("RECEIPT_UNAVAILABLE=", script)

    def test_lifecycle_lock_is_shared_trusted_and_precedes_mutable_checks(self):
        install_lock = heredoc(INSTALL, "PY_LOCK")
        update_lock = heredoc(UPDATE, "PY_LOCK")
        self.assertEqual(install_lock, update_lock)
        self.assertIn("writable = info.st_mode & 0o022", install_lock)
        self.assertIn("writable and not info.st_mode & stat.S_ISVTX", install_lock)
        for script, first_check in (
            (INSTALL, 'for path in "$app" "$helper" "$service"'),
            (UPDATE, 'for directory in /opt "$app" "$app/static"'),
        ):
            self.assertIn("/run/lock/openclash-sync-web.lifecycle.lock", script)
            self.assertIn('exec 9<>"$lifecycle_lock"', script)
            self.assertIn('flock -n 9', script)
            self.assertIn('"/proc/$$/fd/9"', script)
            self.assertLess(
                script.index("acquire_lifecycle_lock || hold LIFECYCLE_LOCK"),
                script.index(first_check),
            )

    def test_prepared_and_active_are_durable_before_first_mutation(self):
        for script, root, first_mutation, cleanup_marker in (
            (
                INSTALL,
                "transaction",
                "target_mutation_started=true",
                "clear_lifecycle || hold LIFECYCLE_CLEANUP",
            ),
            (
                UPDATE,
                "backup",
                "systemctl disable --now openclash-sync-web.service",
                "clear_lifecycle || hold LIFECYCLE_CLEANUP",
            ),
        ):
            prepared = script.index(f'atomic_journal "${root}/PREPARED"')
            active = script.index('atomic_journal "$lifecycle_root/ACTIVE"', prepared)
            mutation = script.index(first_mutation, active)
            committed = script.index(f'mv -f "${root}/COMMITTED.partial" "${root}/COMMITTED"')
            cleanup = script.index(cleanup_marker, committed)
            self.assertLess(prepared, active)
            self.assertLess(active, mutation)
            self.assertLess(committed, cleanup)
            self.assertIn("/opt/openclash-sync-web-lifecycle", script)
            self.assertIn("fsync_directory \"$parent\"", script)

    def test_pending_precedes_transaction_creation_and_clears_before_active(self):
        for script, transaction_create in (
            (INSTALL, 'install -d -m 0700 -o root -g root "$transaction" "$source_stage"'),
            (UPDATE, 'install -d -m 0700 -o root -g root "$backup" "$source_stage"'),
        ):
            main = script[script.index("source=/tmp/openclash-sync-web-deploy") :]
            pending = main.index('atomic_journal "$lifecycle_root/PENDING"')
            self.assertLess(pending, main.index(transaction_create))
            self.assertIn("openclash-sync-web-pending-v1", main)
            clear = script[script.index("clear_lifecycle(){") : script.index(
                "cleanup_lifecycle_partials(){"
            )]
            self.assertLess(clear.index("clear_pending"), clear.index("clear_active"))

    def test_recovery_cleans_ephemera_before_terminal_status(self):
        install_recovery = INSTALL[
            INSTALL.index("recover_install_tx(){") : INSTALL.index("sha(){")
        ]
        update_recovery = UPDATE[
            UPDATE.index("recover_update_tx(){") : UPDATE.index("stage_source(){")
        ]
        for recovery, cleanup in (
            (install_recovery, "cleanup_recovery_ephemera"),
            (update_recovery, "cleanup_recovery_residue"),
        ):
            for status in ("ABORTED", "ROLLED_BACK"):
                status_position = recovery.index(f'journal_status "$tx" {status}')
                self.assertGreater(recovery.rfind(cleanup, 0, status_position), -1)

        for script, root in ((INSTALL, "transaction"), (UPDATE, "backup")):
            rollback = script[script.index("rollback(){") : script.index("finish(){")]
            status_position = rollback.index('write_status "$status"')
            self.assertLess(rollback.index("cleanup_source_stage"), status_position)
            self.assertIn("clear_lifecycle", rollback[status_position:])
            committed = script.index(f'mv -f "${root}/COMMITTED.partial" "${root}/COMMITTED"')
            lifecycle = script.index("clear_lifecycle || hold LIFECYCLE_CLEANUP", committed)
            self.assertLess(committed, lifecycle)

    def test_recovery_reuses_existing_terminal_status(self):
        for script, recovery_name, end_marker in (
            (INSTALL, "recover_install_tx(){", "recover_update_tx(){"),
            (INSTALL, "recover_update_tx(){", "sha(){"),
            (UPDATE, "recover_update_tx(){", "stage_source(){"),
        ):
            recovery = script[script.index(recovery_name) : script.index(end_marker, script.index(recovery_name))]
            terminal = recovery.index('terminal_status=$(terminal_recovery_status "$tx")')
            reuse = recovery.index('[ "$terminal_status" != NONE ]', terminal)
            first_new_status = min(
                position
                for marker in ('journal_status "$tx" ABORTED', 'journal_status "$tx" ROLLED_BACK')
                if (position := recovery.find(marker, reuse)) >= 0
            )
            self.assertLess(terminal, reuse)
            self.assertLess(reuse, first_new_status)
            self.assertIn("TERMINAL_STATUS_INVALID", recovery)

    def test_failure_terminals_are_immutable_and_fail_closed(self):
        for script in (INSTALL, UPDATE):
            status = script[script.index("journal_status(){") : script.index("clear_active(){")]
            for terminal in (
                "ABORTED",
                "ROLLED_BACK",
                "ROLLBACK_FAILED",
                "RECOVERY_FAILED",
                "COMMITTED_RECOVERY_FAILED",
            ):
                self.assertIn(terminal, status)
            self.assertIn('[ "$existing_status" = "$status" ] || return 1', status)
            terminal = script[
                script.index("terminal_recovery_status(){") : script.index(
                    "trusted_recovery_tx(){"
                    if script is INSTALL
                    else "recover_active(){",
                    script.index("terminal_recovery_status(){"),
                )
            ]
            self.assertIn("ROLLBACK_FAILED RECOVERY_FAILED COMMITTED_RECOVERY_FAILED", terminal)
            recovery = script[script.index("recover_update_tx(){") :]
            failure_gate = recovery.index(
                "ROLLBACK_FAILED|RECOVERY_FAILED|COMMITTED_RECOVERY_FAILED"
            )
            cleanup = recovery.index("cleanup_target_partials", failure_gate)
            self.assertLess(failure_gate, cleanup)

        install_active = INSTALL[INSTALL.index("recover_active(){") : INSTALL.index("recover_install_tx(){")]
        install_terminal = install_active.index(
            'active_terminal_status=$(terminal_recovery_status "$active_tx")'
        )
        self.assertLess(install_terminal, install_active.index('$active_tx/COMMITTED'))

        update_recovery = UPDATE[UPDATE.index("recover_update_tx(){") : UPDATE.index("stage_source(){")]
        update_terminal = update_recovery.index('terminal_status=$(terminal_recovery_status "$tx")')
        self.assertLess(update_terminal, update_recovery.index('$tx/COMMITTED'))

    def test_update_pending_orphan_preserves_failure_terminals(self):
        cleanup = UPDATE[UPDATE.index("cleanup_pending_orphan(){") : UPDATE.index("recover_pending(){")]
        self.assertIn('for status_name in ("ABORTED", "ROLLED_BACK")', cleanup)
        self.assertNotIn('"ROLLBACK_FAILED", "RECOVERY_FAILED"', cleanup)
        pending = UPDATE[UPDATE.index("recover_pending(){") : UPDATE.index("source_identity_ok(){")]
        terminal = pending.index('pending_terminal_status=$(terminal_recovery_status "$pending_tx")')
        failure_gate = pending.index(
            'ROLLBACK_FAILED|RECOVERY_FAILED|COMMITTED_RECOVERY_FAILED', terminal
        )
        cleanup_call = pending.index('cleanup_pending_orphan "$pending_tx"')
        self.assertLess(terminal, failure_gate)
        self.assertLess(failure_gate, cleanup_call)

    def test_nonterminal_update_recovery_stops_service_before_partial_cleanup(self):
        for script in (INSTALL, UPDATE):
            recovery = script[script.index("recover_update_tx(){") :]
            pending = recovery.index('[ "$recovery_pending_present" = true ]')
            stop = recovery.index("stop_service_for_recovery", pending)
            cleanup = recovery.index("cleanup_target_partials", pending)
            self.assertLess(stop, cleanup)

    def test_terminal_update_recovery_restores_service_before_cleanup(self):
        for script, start, end in (
            (INSTALL, "recover_update_tx(){", "sha(){"),
            (UPDATE, "recover_update_tx(){", "stage_source(){"),
        ):
            recovery = script[script.index(start) : script.index(end, script.index(start))]
            terminal = recovery.index('if [ "$terminal_status" != NONE ]')
            restore = recovery.index("TERMINAL_SERVICE_RESTORE_FAILED", terminal)
            cleanup = recovery.index("cleanup_recovery_", terminal)
            self.assertLess(terminal, restore)
            self.assertLess(restore, cleanup)

    def test_recovery_failures_disable_service_and_preserve_evidence(self):
        for script in (INSTALL, UPDATE):
            recovery_failed = script[
                script.index("recovery_failed(){") : script.index(
                    "recover_active(){", script.index("recovery_failed(){")
                )
            ]
            self.assertTrue(
                "systemctl disable --now openclash-sync-web.service" in recovery_failed
                or "stop_service_for_recovery" in recovery_failed
            )
            self.assertIn("journal_status", recovery_failed)
            active = script[
                script.index("recover_active(){") : script.index("stage_source(){")
            ]
            for reason in ("ACTIVE_INVALID", "PREPARED_INVALID", "PENDING_INVALID"):
                self.assertIn(reason, active)
            self.assertIn("COMMITTED_CLEANUP_FAILED", active)

    def test_update_recovery_accepts_incomplete_atomic_partials_only_as_ephemera(self):
        validation = UPDATE[
            UPDATE.index("validate_recovery_residue(){") : UPDATE.index(
                "cleanup_recovery_residue(){"
            )
        ]
        self.assertIn('journal_file_ok "$residue_tx/COMMITTED.partial"', validation)
        self.assertIn('armed_journal_ok "$residue_tx/ARMED"', validation)
        self.assertIn('journal_file_ok "$residue_tx/ARMED.partial"', validation)
        self.assertNotIn('armed_journal_ok "$residue_tx/ARMED.partial"', validation)

    def test_recovery_classifies_all_assets_and_fails_closed_on_third_state(self):
        for script in (INSTALL, UPDATE):
            self.assertIn("asset_state(){", script)
            self.assertIn("printf 'THIRD'", script)
            self.assertIn("RECOVERY_FAILED", script)
            self.assertIn("systemctl disable --now openclash-sync-web.service", script)
            self.assertIn("RECOVERED_COMMITTED", script)
            self.assertIn("service_after_ok", script)
            self.assertIn("stat -c '%a:%u:%g:%h'", script)
        for label in (
            "app-server.py",
            "app-auth-ha1",
            "static-index.html",
            "static-app.css",
            "static-app.js",
            "static-logo.png",
            "helper",
            "service",
        ):
            self.assertIn(f'"$tx/{label}.before"', UPDATE)
            self.assertIn(f'"$tx/{label}.after-sha"', UPDATE)
        for label in ("router-a", "router-b", "known-hosts", "sudoers"):
            self.assertIn(f'"$tx/{label}.after-sha"', INSTALL)

    def test_recovery_requires_complete_service_and_reload_state(self):
        for script in (INSTALL, UPDATE):
            recovery = script[: script.index("stage_source(){")]
            self.assertIn("systemctl is-enabled --quiet openclash-sync-web.service", recovery)
            self.assertIn("systemctl is-active --quiet openclash-sync-web.service", recovery)
            self.assertIn("service_after_ok", recovery)
        install_recovery = INSTALL[
            INSTALL.index("recover_update_tx(){") : INSTALL.index(
                "sha(){", INSTALL.index("recover_update_tx(){")
            )
        ]
        self.assertIn("systemctl daemon-reload >/dev/null 2>&1 || {", install_recovery)
        self.assertNotIn(
            "systemctl daemon-reload >/dev/null 2>&1 || true", install_recovery
        )

    def test_equal_before_and_after_hash_is_treated_as_after(self):
        for script, end_marker in (
            (INSTALL, "journal_file_ok"),
            (UPDATE, "atomic_restore"),
        ):
            start = script.index("asset_state(){")
            state = script[start : script.index(end_marker, start)]
            self.assertLess(
                state.index('[ "$current" = "$after" ]'),
                state.index('[ "$current" = "$before" ]'),
            )

    def test_fsync_committed_window_never_enters_rollback(self):
        for script, root in ((INSTALL, "transaction"), (UPDATE, "backup")):
            finish = script[script.index("finish(){") : script.index("trap finish EXIT")]
            self.assertIn(f'[ -e "${root}/COMMITTED" ]', finish)
            self.assertIn(f'[ -L "${root}/COMMITTED" ]', finish)
            self.assertIn("committed=true", finish)
            self.assertLess(finish.index("committed=true"), finish.index("|| rollback"))
            recovery = script[script.index("recover_active(){") :]
            self.assertIn("RECOVERED_COMMITTED", recovery)
            self.assertIn("clear_active", recovery)

    def test_lifecycle_journals_use_closed_schemas_and_exact_key_lookup(self):
        for script in (INSTALL, UPDATE):
            self.assertIn("journal_schema_ok(){", script)
            self.assertIn("index($0, key \"=\") == 1", script)
            self.assertIn("openclash-sync-web-active-v1", script)
            self.assertIn("openclash-sync-web-lifecycle-v1", script)
            self.assertIn("RECEIPT_SCHEMA", script)
            self.assertNotIn('sed -n "s/^$journal_key=//p"', script)
        self.assertIn("openclash-sync-web-install-v3", INSTALL)
        self.assertIn("openclash-sync-web-install-v4", INSTALL)
        self.assertIn("openclash-sync-web-install-v5", INSTALL)
        self.assertIn("openclash-sync-web-update-v3", UPDATE)
        self.assertIn("openclash-sync-web-update-v4", UPDATE)
        self.assertIn("openclash-sync-web-update-v5", UPDATE)
        self.assertIn("install_committed_journal_ok", INSTALL)
        self.assertIn("committed_journal_ok", UPDATE)

    def test_new_service_receipts_are_lan_tailnet_only_and_old_receipts_are_recovery_only(self):
        for script in (INSTALL, UPDATE):
            self.assertIn("service_listen_address(){", script)
            self.assertIn("127.0.0.1:8088|192.0.2.20:8088", script)
            self.assertIn("service_listen_ok", script)
        self.assertIn("SCHEMA=openclash-sync-web-install-v5", INSTALL)
        self.assertIn("SCHEMA=openclash-sync-web-update-v5", UPDATE)
        self.assertIn("'LISTEN=192.0.2.20:8088'", INSTALL)
        self.assertIn("'LISTEN=192.0.2.20:8088'", UPDATE)
        self.assertIn("Environment=OPENCLASH_WEB_HOST=192.0.2.20", SERVICE)
        self.assertIn("Environment=OPENCLASH_WEB_ALLOWED_HOSTS=192.0.2.20:8088", SERVICE)
        self.assertIn("Environment=OPENCLASH_WEB_ALLOWED_ORIGINS=http://192.0.2.20:8088", SERVICE)
        self.assertIn("Environment=OPENCLASH_WEB_ALLOWED_NETWORKS=192.0.2.0/24,127.0.0.0/8", SERVICE)
        self.assertNotIn("Environment=OPENCLASH_WEB_HOST=0.0.0.0", SERVICE)

    def test_recovery_stops_service_before_writes_and_proves_install_baseline(self):
        install_recovery = INSTALL[INSTALL.index("recover_install_tx(){") : INSTALL.index("sha(){")]
        update_recovery = UPDATE[UPDATE.index("recover_update_tx(){") : UPDATE.index("stage_source(){")]
        self.assertLess(
            install_recovery.index("stop_service_for_recovery"),
            install_recovery.index('rm -f "$target"'),
        )
        self.assertIn("service_install_baseline_ok", install_recovery)
        self.assertIn("LoadState --value", INSTALL)
        self.assertIn("= not-found", INSTALL)
        self.assertLess(
            update_recovery.index("stop_service_for_recovery"),
            update_recovery.index("atomic_restore"),
        )
        for script in (INSTALL, UPDATE):
            self.assertIn("ActiveState --value", script)
            self.assertIn("stat -c '%a:%u:%g:%h'", script)

    def test_completed_active_recovery_exits_before_starting_a_new_transaction(self):
        for script in (INSTALL, UPDATE):
            main = script[script.index("recovery_status=0") :]
            recovered = main.index('"$recovery_status" in')
            success = main.index("WORKER_WEB_RECOVERY=PASS", recovered)
            exit_success = main.index("exit 0", success)
            new_pending = main.index(
                'atomic_journal "$lifecycle_root/PENDING"', exit_success
            )
            self.assertLess(success, exit_success)
            self.assertLess(exit_success, new_pending)
            self.assertIn("NEW_TRANSACTION_STARTED=false", main[success:exit_success])

    def test_install_pending_recovery_exits_if_it_consumed_bound_source(self):
        recovery = INSTALL[
            INSTALL.index("recover_pending(){") : INSTALL.index("asset_state(){")
        ]
        cleanup = recovery.index("cleanup_bound_source")
        self.assertLess(cleanup, recovery.index("return 2", cleanup))
        main = INSTALL[INSTALL.index("pending_recovery_status=0") :]
        success = main.index("WORKER_WEB_RECOVERY=PASS")
        self.assertLess(success, main.index("exit 0", success))
        self.assertIn("PHASE=PENDING", main[success : main.index("exit 0", success)])

    def test_receipt_digests_are_precomputed_and_validated(self):
        for script in (INSTALL, UPDATE):
            self.assertNotRegex(script, r"printf[^\n]*\$\((?:sha|sha256sum)")
            self.assertIn("valid_digest", script)
            self.assertTrue(
                "committed_journal_ok" in script or "install_committed_journal_ok" in script
            )


if __name__ == "__main__":
    unittest.main()
