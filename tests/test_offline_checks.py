from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/run_offline_checks.sh"


class OfflineEntrypointTests(unittest.TestCase):
    """Exercise the real shell functions with isolated, synthetic test suites."""

    def run_fixture(self, files, *, worker=False, module=None, environment=None):
        source = SCRIPT.read_text(encoding="utf-8")
        functions, separator, _ = source.partition('\n[ "$#" -eq 0 ] || hold ')
        self.assertTrue(separator, "cannot locate the runner function boundary")
        if worker:
            entrypoints = [
                line for line in source.splitlines()
                if line.startswith(("run_check ", "run_unittests "))
                and any(name in line for name in (
                    "test_maying_converter_reconciler", "test_openclash_worker",
                ))
            ]
            self.assertTrue(entrypoints, "worker entrypoints must exist")
        elif module is not None:
            entrypoints = [f"run_unittests PYTHON_FIXTURE_TESTS modules {module}"]
        else:
            entrypoints = ["run_unittests PYTHON_FIXTURE_TESTS discover cases"]
        shell = "\n".join([
            functions, 'python_bin="$OFFLINE_FIXTURE_PYTHON"', *entrypoints,
            'printf "HARNESS_COMPLETED=true\\nHARNESS_SKIPPED=%s\\n" "$skipped"', "",
        ])
        env = {**os.environ, "OFFLINE_FIXTURE_PYTHON": sys.executable}
        for name in ("OPENCLASH_TEST_MIHOMO", "OPENCLASH_TEST_MELLOW_PARSER"):
            env.pop(name, None)
        env.update(environment or {})
        with tempfile.TemporaryDirectory(prefix="openclash-offline-entry-") as temporary:
            fixture = Path(temporary)
            (fixture / "cases").mkdir()
            for name, body in files.items():
                (fixture / name).write_text(textwrap.dedent(body), encoding="utf-8")
            script = fixture / "checks.sh"
            script.write_text(shell, encoding="utf-8")
            return subprocess.run(
                ["/bin/sh", str(script)], cwd=fixture, env=env, check=False,
                capture_output=True, text=True, timeout=20,
            )

    @staticmethod
    def worker_files(reconciler_code=0, worker_code=0):
        return {
            "test_maying_converter_reconciler.py": (
                'print("RECONCILER_EXECUTED")\n' f"raise SystemExit({reconciler_code})\n"
            ),
            "test_openclash_worker.py": (
                'print("WORKER_EXECUTED")\n' f"raise SystemExit({worker_code})\n"
            ),
        }

    def test_both_legacy_scripts_execute_after_first_successful_exit(self):
        result = self.run_fixture(self.worker_files(), worker=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("RECONCILER_EXECUTED"), 1)
        self.assertEqual(result.stdout.count("WORKER_EXECUTED"), 1)
        self.assertLess(result.stdout.index("RECONCILER_EXECUTED"),
                        result.stdout.index("WORKER_EXECUTED"))
        self.assertIn("PYTHON_RECONCILER_TESTS=PASS", result.stdout)
        self.assertIn("PYTHON_WORKER_TESTS=PASS", result.stdout)
        self.assertIn("HARNESS_COMPLETED=true", result.stdout)

    def test_reconciler_failure_stops_before_worker(self):
        result = self.run_fixture(self.worker_files(reconciler_code=23), worker=True)
        self.assertEqual(result.returncode, 23)
        self.assertIn("FAILED_CHECK=PYTHON_RECONCILER_TESTS", result.stdout)
        self.assertNotIn("WORKER_EXECUTED", result.stdout)
        self.assertNotIn("HARNESS_COMPLETED", result.stdout)

    def test_worker_failure_is_not_hidden_by_reconciler_success(self):
        result = self.run_fixture(self.worker_files(worker_code=29), worker=True)
        self.assertEqual(result.returncode, 29)
        self.assertIn("WORKER_EXECUTED", result.stdout)
        self.assertIn("FAILED_CHECK=PYTHON_WORKER_TESTS", result.stdout)
        self.assertNotIn("PYTHON_WORKER_TESTS=PASS", result.stdout)
        self.assertNotIn("HARNESS_COMPLETED", result.stdout)

    def test_inherited_python_optimization_cannot_disable_legacy_assertions(self):
        files = self.worker_files()
        files["test_openclash_worker.py"] = 'assert False, "synthetic failure"\n'
        result = self.run_fixture(files, worker=True, environment={"PYTHONOPTIMIZE": "2"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AssertionError", result.stderr)
        self.assertNotIn("HARNESS_COMPLETED", result.stdout)

    def test_success_reports_discovered_and_executed_count(self):
        result = self.run_fixture({"cases/test_sample.py": """
            import unittest
            class Sample(unittest.TestCase):
                def test_first(self): self.assertTrue(True)
                def test_second(self): self.assertEqual(1, 1)
        """})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PYTHON_FIXTURE_TESTS_DISCOVERED=2", result.stdout)
        self.assertIn("PYTHON_FIXTURE_TESTS_RUN=2", result.stdout)
        self.assertIn("PYTHON_FIXTURE_TESTS_SKIPPED=0", result.stdout)
        self.assertIn("HARNESS_COMPLETED=true", result.stdout)

    def test_discovery_import_system_exit_zero_is_failure(self):
        result = self.run_fixture({"cases/test_exits.py": "raise SystemExit(0)\n"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PYTHON_FIXTURE_TESTS=FAIL", result.stdout)
        self.assertIn("SystemExit: 0", result.stderr)
        self.assertNotIn("PYTHON_FIXTURE_TESTS=PASS", result.stdout)
        self.assertNotIn("HARNESS_COMPLETED", result.stdout)

    def test_discovery_import_nonzero_exit_is_failure(self):
        result = self.run_fixture({"cases/test_exits.py": "raise SystemExit(19)\n"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PYTHON_FIXTURE_TESTS=FAIL", result.stdout)
        self.assertIn("SystemExit: 19", result.stderr)
        self.assertNotIn("HARNESS_COMPLETED", result.stdout)

    def test_named_module_system_exit_zero_is_failure(self):
        result = self.run_fixture({"test_exits.py": "raise SystemExit(0)\n"}, module="test_exits")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PYTHON_FIXTURE_TESTS_ERROR=UNEXPECTED_SYSTEM_EXIT", result.stdout)
        self.assertNotIn("PYTHON_FIXTURE_TESTS=PASS", result.stdout)
        self.assertNotIn("HARNESS_COMPLETED", result.stdout)

    def test_named_module_nonzero_exit_is_failure(self):
        result = self.run_fixture({"test_exits.py": "raise SystemExit(19)\n"}, module="test_exits")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PYTHON_FIXTURE_TESTS_ERROR=UNEXPECTED_SYSTEM_EXIT", result.stdout)
        self.assertNotIn("HARNESS_COMPLETED", result.stdout)

    def test_empty_discovery_is_failure(self):
        result = self.run_fixture({})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PYTHON_FIXTURE_TESTS_ERROR=NO_TESTS_DISCOVERED", result.stdout)
        self.assertNotIn("HARNESS_COMPLETED", result.stdout)

    def test_discovered_but_unexecuted_test_is_failure(self):
        result = self.run_fixture({"cases/test_sample.py": """
            import unittest
            class Sample(unittest.TestCase):
                def test_hidden(self): self.assertTrue(True)
                def run(self, result=None): return result
        """})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PYTHON_FIXTURE_TESTS_DISCOVERED=1", result.stdout)
        self.assertIn("PYTHON_FIXTURE_TESTS_RUN=0", result.stdout)
        self.assertIn("PYTHON_FIXTURE_TESTS_ERROR=TEST_EXECUTION_COUNT_MISMATCH", result.stdout)
        self.assertNotIn("HARNESS_COMPLETED", result.stdout)

    def test_unittest_assertion_failure_propagates(self):
        result = self.run_fixture({"cases/test_sample.py": """
            import unittest
            class Sample(unittest.TestCase):
                def test_failure(self): self.fail("synthetic failure")
        """})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PYTHON_FIXTURE_TESTS_RUN=1", result.stdout)
        self.assertNotIn("PYTHON_FIXTURE_TESTS=PASS", result.stdout)
        self.assertNotIn("HARNESS_COMPLETED", result.stdout)

    def test_required_test_skip_is_failure(self):
        result = self.run_fixture({"cases/test_sample.py": """
            import unittest
            class Sample(unittest.TestCase):
                @unittest.skip("required feature unavailable")
                def test_required(self): self.assertTrue(True)
        """})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PYTHON_FIXTURE_TESTS_ERROR=UNEXPECTED_SKIPS", result.stdout)
        self.assertNotIn("HARNESS_COMPLETED", result.stdout)

    def test_unconfigured_optional_parser_skip_is_reported(self):
        result = self.run_fixture({"cases/test_sample.py": """
            import unittest
            class Sample(unittest.TestCase):
                @unittest.skip("OPENCLASH_TEST_MIHOMO is not configured")
                def test_optional(self): self.assertTrue(True)
        """})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PYTHON_FIXTURE_TESTS=PASS_WITH_SKIPS", result.stdout)
        self.assertIn("HARNESS_SKIPPED=1", result.stdout)

    def test_configured_parser_cannot_be_silently_skipped(self):
        result = self.run_fixture({"cases/test_sample.py": """
            import unittest
            class Sample(unittest.TestCase):
                @unittest.skip("OPENCLASH_TEST_MIHOMO is not configured")
                def test_optional(self): self.assertTrue(True)
        """}, environment={"OPENCLASH_TEST_MIHOMO": "/nonexistent/synthetic-parser"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PYTHON_FIXTURE_TESTS_ERROR=UNEXPECTED_SKIPS", result.stdout)
        self.assertNotIn("HARNESS_COMPLETED", result.stdout)


if __name__ == "__main__":
    unittest.main()
