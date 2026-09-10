"""Lua 5.1 regressions: mocked router I/O and harmless local shell framing."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RouterAgentLuaTests(unittest.TestCase):
    def run_harness(self, name: str, marker: str, counter: str):
        lua = os.environ.get("OPENCLASH_TEST_LUA") or shutil.which("lua5.1") or shutil.which("lua")
        if not lua:
            self.skipTest("Lua 5.1 unavailable; set OPENCLASH_TEST_LUA to run behavior tests")
        # An explicit but broken interpreter is a failure, not an implicit skip.
        result = subprocess.run(
            [lua, str(ROOT / "tests" / name), str(ROOT / "openclash_web_router_agent.lua")],
            cwd=ROOT, text=True, capture_output=True, timeout=30, check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(marker + "=PASS", result.stdout)
        self.assertRegex(result.stdout, counter + r"=[1-9][0-9]+")

    def test_mocked_agent_receipt_and_commit_paths(self):
        self.run_harness("test_router_agent_lua.lua", "LUA_AGENT_BEHAVIOR", "LUA_AGENT_CASES")

    def test_real_shell_exit_status_framing(self):
        self.run_harness("test_router_agent_capture.lua", "LUA_CAPTURE_STATUS", "LUA_CAPTURE_CASES")


if __name__ == "__main__":
    unittest.main()
