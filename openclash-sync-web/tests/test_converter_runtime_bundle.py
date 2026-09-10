"""Synthetic immutable release tests. No /opt writes, service or Docker calls."""
import ast
import concurrent.futures
import hashlib
from pathlib import Path
import os
import stat
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import converter_runtime_bundle as bundle


class RuntimeBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.files = {name: b'x = 1\n' if name.endswith('.py') else b'"use strict";\n' for name in bundle.FILES}
    def tearDown(self):
        for path, dirs, files in os.walk(self.root):
            os.chmod(path, 0o700)
        self.tmp.cleanup()
    def release(self):
        return bundle.publish(self.files, self.root / 'releases')
    def test_release_pins_match_current_payload_and_sandbox(self):
        source = Path(__file__).resolve().parents[1]
        files = bundle.source_files(source)
        expected = bundle.identity(files)
        def literal(name, variable):
            tree = ast.parse((source/name).read_bytes())
            values = [node.value for node in tree.body if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == variable for target in node.targets)]
            self.assertEqual(len(values), 1)
            return ast.literal_eval(values[0])
        self.assertEqual(literal("server.py", "CONVERTER_RUNTIME_ID"), expected)
        self.assertEqual(literal("openclash_web_helper.py", "CONVERTER_RUNTIME_ID"), expected)
        self.assertEqual(literal("openclash_web_helper.py", "CONVERTER_SANDBOX_SHA256"),
                         hashlib.sha256(files["converter_sandbox.py"]).hexdigest())
        self.assertEqual(set(literal("server.py", "CONVERTER_FILES")), set(bundle.FILES))

    def test_install_and_update_preflight_cover_exact_runtime_assets(self):
        source = Path(__file__).resolve().parents[1]
        for filename in ("install_worker_web_console.sh", "update_worker_web_console.sh"):
            script = (source/filename).read_text()
            code = script.split("<<'PY_CONVERTER_RUNTIME'\n", 1)[1].split("\nPY_CONVERTER_RUNTIME", 1)[0]
            tree = ast.parse(code)
            declarations = [node.value for node in tree.body if isinstance(node, ast.Assign)
                            and any(isinstance(target, ast.Name) and target.id == "files" for target in node.targets)]
            self.assertEqual(len(declarations), 1)
            self.assertEqual(ast.literal_eval(declarations[0]), set(bundle.FILES))
            self.assertIn('converter_runtime_ok "$source_stage/server.py" "$source_stage/openclash_web_helper.py"', script)

    def test_build_verify_idempotent_and_exact_modes(self):
        path = self.release()
        self.assertEqual(path.name, hashlib.sha256(bundle.canonical(self.files)).hexdigest())
        self.assertEqual(bundle.verify(path, path.name), self.files)
        self.assertEqual(self.release(), path)
        self.assertEqual(len(list(path.parent.glob('.candidate-*'))), 0)
        for name in (*bundle.FILES, 'SHA256SUMS'):
            self.assertEqual(stat.S_IMODE((path/name).stat().st_mode), 0o444)
            self.assertEqual((path/name).stat().st_nlink, 1)
        self.assertEqual(stat.S_IMODE((path/'static').stat().st_mode), 0o555)
    def test_new_destination_ignores_restrictive_umask_for_public_code_only(self):
        previous = os.umask(0o077)
        try:
            path = self.release()
        finally:
            os.umask(previous)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o555)
        self.assertEqual(stat.S_IMODE((path.parent/'.publish.lock').stat().st_mode), 0o600)
        self.assertEqual(bundle.verify(path, path.name), self.files)

    def test_existing_local_private_staging_root_remains_private(self):
        releases = self.root/'releases'; releases.mkdir(mode=0o700)
        path = self.release()
        self.assertEqual(stat.S_IMODE(releases.stat().st_mode), 0o700)
        self.assertEqual(bundle.verify(path, path.name), self.files)

    @staticmethod
    def root_owned(info):
        values = list(info); values[4] = values[5] = 0
        return os.stat_result(values)

    def test_production_repairs_trusted_private_root_before_publishing(self):
        destination = self.root/'public-runtime'; destination.mkdir(mode=0o700)
        native_lstat, native_fstat = Path.lstat, os.fstat
        with mock.patch.object(bundle, 'PRODUCTION_ROOT', destination), \
                mock.patch.object(bundle, 'directory_chain') as chain, \
                mock.patch.object(bundle.os, 'geteuid', return_value=0), \
                mock.patch.object(bundle.os, 'fstat', side_effect=lambda fd: self.root_owned(native_fstat(fd))), \
                mock.patch.object(Path, 'lstat', lambda path: self.root_owned(native_lstat(path))), \
                mock.patch.object(bundle, 'publish_locked', return_value=destination/'synthetic-final') as publish:
            bundle.publish(self.files, destination, production=True)
            chain.assert_any_call(destination, (0, 0))
            publish.assert_called_once_with(self.files, destination, bundle.identity(self.files), production=True)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((destination/'.publish.lock').stat().st_mode), 0o600)
        self.assertFalse((destination/'synthetic-final').exists())

    def test_public_directory_rejects_bad_owner_writable_mode_and_symlink(self):
        directory = self.root/'untrusted'; directory.mkdir(mode=0o700)
        with self.assertRaises(bundle.BundleError):
            bundle.make_public_directory(directory, owner=(os.getuid()+1, os.getgid()))
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        directory.chmod(0o777)
        with self.assertRaises(bundle.BundleError): bundle.make_public_directory(directory)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o777)
        directory.chmod(0o700)
        link = self.root/'link'; link.symlink_to(directory, target_is_directory=True)
        with self.assertRaises(OSError): bundle.make_public_directory(link)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)

    def test_public_directory_rejects_descriptor_name_drift(self):
        directory = self.root/'directory'; directory.mkdir(mode=0o700)
        native = Path.lstat
        def changed(path):
            info = list(native(path)); info[1] += 1
            return os.stat_result(info)
        with mock.patch.object(Path, 'lstat', changed):
            with self.assertRaises(bundle.BundleError): bundle.make_public_directory(directory)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)

    def test_both_production_preflights_reject_private_runtime_ancestor(self):
        source = Path(__file__).resolve().parents[1]
        release = self.release(); destination = release.parent
        app = self.root/'server.py'; helper = self.root/'helper.py'
        app.write_text(f'CONVERTER_RUNTIME_ID = {release.name!r}\n')
        helper.write_text(f'CONVERTER_RUNTIME_ID = {release.name!r}\nCONVERTER_SANDBOX_SHA256 = {hashlib.sha256(self.files["converter_sandbox.py"]).hexdigest()!r}\n')
        native = Path.lstat
        def owned_info(path):
            info = self.root_owned(native(path))
            if path != destination and destination not in path.parents:
                values = list(info)
                if stat.S_ISDIR(info.st_mode): values[0] = stat.S_IFDIR | 0o755
                info = os.stat_result(values)
            return info
        for filename in ('install_worker_web_console.sh', 'update_worker_web_console.sh'):
            script = (source/filename).read_text()
            code = script.split("<<'PY_CONVERTER_RUNTIME'\n", 1)[1].split('\nPY_CONVERTER_RUNTIME', 1)[0]
            needle = "pathlib.Path('/opt/openclash-sync-converter')"
            self.assertEqual(code.count(needle), 1)
            code = code.replace(needle, f'pathlib.Path({str(destination)!r})')
            for mode in (0o700, 0o750, 0o755):
                with self.subTest(script=filename, ancestor_mode=oct(mode)):
                    destination.chmod(mode)
                    with mock.patch.object(Path, 'lstat', owned_info), mock.patch.object(sys, 'argv', ['preflight', str(app), str(helper)]):
                        if mode == 0o755: exec(compile(code, filename, 'exec'), {})
                        else:
                            with self.assertRaisesRegex(AssertionError, 'service-user traversable'):
                                exec(compile(code, filename, 'exec'), {})

    def test_concurrent_identical_publications_never_replace_release(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.release(), range(8)))
        self.assertEqual(len(set(results)), 1)
        self.assertEqual(bundle.verify(results[0], results[0].name), self.files)
        self.assertEqual(len(list(results[0].parent.glob('.candidate-*'))), 0)
    def test_unexpected_files_or_directory_rejected(self):
        path = self.release(); path.chmod(0o755)
        (path/'unlisted').write_text('unexpected')
        path.chmod(0o555)
        with self.assertRaises(bundle.BundleError): bundle.verify(path, path.name)
    def test_tampered_manifest_and_release_id_rejected(self):
        path = self.release()
        with self.assertRaises(bundle.BundleError): bundle.verify(path, 'f'*64)
        manifest = path/'SHA256SUMS'; manifest.chmod(0o644); manifest.write_text('f'*64); manifest.chmod(0o444)
        with self.assertRaises(bundle.BundleError): bundle.verify(path, path.name)
    def test_bad_permissions_owner_symlink_hardlink_fifo_rejected(self):
        path = self.release()
        with self.assertRaises(bundle.BundleError): bundle.verify(path, path.name, owner=(os.getuid()+1, os.getgid()))
        asset = path/bundle.FILES[0]; asset.chmod(0o644)
        with self.assertRaises(bundle.BundleError): bundle.verify(path, path.name)
        asset.chmod(0o444)
        os.link(asset, self.root/'hardlink')
        with self.assertRaises(bundle.BundleError): bundle.read_file(path, bundle.FILES[0])
        (self.root/'symlink').symlink_to(asset)
        with self.assertRaises(OSError): bundle.read_file(self.root, 'symlink')
        os.mkfifo(self.root/'pipe')
        with self.assertRaises(bundle.BundleError): bundle.read_file(self.root, 'pipe')
    def test_nested_symlink_not_traversed(self):
        path=self.release()
        (self.root/'static').symlink_to(path/'static', target_is_directory=True)
        with self.assertRaises(OSError): bundle.read_file(self.root, 'static/converter.js')
    def test_failure_keeps_inactive_candidate_no_final(self):
        with mock.patch.object(bundle, 'verify', side_effect=bundle.BundleError('synthetic')):
            with self.assertRaises(bundle.BundleError): self.release()
        releases=self.root/'releases'
        self.assertFalse((releases/bundle.identity(self.files)).exists())
        self.assertEqual(len(list(releases.glob('.candidate-*'))), 1)
    def test_existing_empty_release_is_not_replaced(self):
        releases=self.root/'releases';releases.mkdir()
        final=releases/bundle.identity(self.files);final.mkdir();inode=final.stat().st_ino
        with self.assertRaises(bundle.BundleError): self.release()
        self.assertEqual(final.stat().st_ino,inode)
        self.assertEqual(list(final.iterdir()),[])
    def test_publication_lock_rejects_symlink_or_hardlink(self):
        releases=self.root/'releases';releases.mkdir()
        foreign=self.root/'foreign';foreign.write_bytes(b'do not change')
        (releases/'.publish.lock').symlink_to(foreign)
        with self.assertRaises(OSError): self.release()
        self.assertEqual(foreign.read_bytes(),b'do not change')
    def test_budget_manifest_and_syntax_fail_before_release(self):
        for files in ({}, dict(self.files, unexpected=b'x'), dict(self.files, **{bundle.FILES[0]:b'x'*(bundle.LIMIT+1)})):
            with self.assertRaises(bundle.BundleError): bundle.canonical(files)
        with self.assertRaises(SyntaxError): bundle.syntax({'broken.py':b'def (\n'})
        with self.assertRaises(UnicodeError): bundle.syntax({'a.js':b'\xff'})
    def test_read_detects_drift_no_output(self):
        path=self.release();native=os.fstat
        def changed(fd):
            info=native(fd)
            if stat.S_ISREG(info.st_mode):
                return mock.Mock(st_mode=info.st_mode, st_nlink=2)
            return info
        with mock.patch.object(bundle.os,'fstat',side_effect=changed):
            with self.assertRaises(bundle.BundleError): bundle.read_file(path,bundle.FILES[0])
    def test_production_destination_and_root_are_fixed(self):
        with self.assertRaises(bundle.BundleError): bundle.publish(self.files,self.root/'arbitrary',production=True)
        with mock.patch.object(bundle.os,'geteuid',return_value=1000):
            with self.assertRaises(bundle.BundleError): bundle.publish(self.files,bundle.PRODUCTION_ROOT,production=True)


if __name__ == '__main__': unittest.main()
