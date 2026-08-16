from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class CustomTransactionStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.transaction = (ROOT / "openclash_custom_transaction.sh").read_text()
        cls.guard = (ROOT / "openclash_custom_rollback_guard.sh").read_text()
        cls.agent = (ROOT / "openclash_web_router_agent.lua").read_text()
        cls.updater = (ROOT / "update_router_web_agent.sh").read_text()
        cls.forced_command = (ROOT / "openclash_web_forced_command.sh").read_text()

    def test_transaction_validates_before_and_after_atomic_switch(self):
        preflight = self.transaction.index('validate "$output"')
        switch = self.transaction.index('mv "$main_partial" "$main"')
        postflight = self.transaction.index('validate "$main"')
        self.assertLess(preflight, switch)
        self.assertLess(switch, postflight)

    def test_runtime_guard_is_armed_before_restart(self):
        arm = self.transaction.index('>"$arm"')
        guard = self.transaction.index('nohup "$guard"')
        restart = self.transaction.index('/etc/init.d/openclash restart')
        self.assertLess(arm, guard)
        self.assertLess(guard, restart)

    def test_guard_is_armed_before_static_file_switch(self):
        arm_call = self.transaction.index('arm_guard "$backup" "$guard_kind"')
        main_switch = self.transaction.index('mv "$main_partial" "$main"')
        state_switch = self.transaction.index('mv "$state_partial" "$state"')
        self.assertLess(arm_call, main_switch)
        self.assertLess(arm_call, state_switch)

    def test_background_children_do_not_inherit_transaction_lock(self):
        self.assertIn('"wait-$guard_kind" 9>&-', self.transaction)
        self.assertIn('/etc/init.d/openclash restart 9>&-', self.transaction)
        self.assertIn('exec 9>&-', self.guard)

    def test_static_recovery_does_not_restart_openclash(self):
        self.assertIn('wait-runtime|wait-static|restore-runtime|restore-static', self.guard)
        self.assertIn('case "$mode" in *-runtime)', self.guard)
        self.assertIn('[ "$candidate_config_sha" != "$previous_config_sha" ]', self.transaction)

    def test_runtime_verification_requires_new_core_identity(self):
        self.assertIn("old_identity=$old_pid:$old_start", self.transaction)
        identity_gate = self.transaction.index('[ "$pid:$start" != "$old_identity" ]')
        runtime_verify = self.transaction.index('ruby "$customizer" verify-runtime "$main" "$runtime"')
        self.assertLess(identity_gate, runtime_verify)

    def test_runtime_success_requires_armed_guard_and_expected_hashes(self):
        arm_gate = self.transaction.index('[ -f "$arm" ] && [ ! -L "$arm" ]')
        config_gate = self.transaction.index('= "$expected_config_sha"')
        state_gate = self.transaction.index('= "$expected_state_sha"')
        runtime_verify = self.transaction.index('ruby "$customizer" verify-runtime "$main" "$runtime"')
        self.assertLess(arm_gate, runtime_verify)
        self.assertLess(config_gate, runtime_verify)
        self.assertLess(state_gate, runtime_verify)

    def test_guard_accepts_only_committed_matching_hashes(self):
        self.assertIn('[ "$waiting" = true ] && [ -f "$backup/COMMITTED" ]', self.guard)
        self.assertIn('CONFIG_SHA256=', self.transaction)
        self.assertIn('STATE_SHA256=', self.transaction)
        self.assertIn('sha256sum "$main"', self.guard)
        self.assertIn('sha256sum "$state"', self.guard)

    def test_manual_main_write_rechecks_expected_hash_under_lock(self):
        expected = self.transaction.index('[ "$current_sha" = "$expected" ]')
        render = self.transaction.index('commit_render "$input"')
        self.assertLess(expected, render)

    def test_custom_apply_rechecks_state_hash_under_lock(self):
        self.assertIn('[ "$current_state_sha" = "$expected" ]', self.transaction)

    def test_inspect_returns_state_hash_while_lock_is_held(self):
        inspect = self.transaction.index('inspect)')
        ruby_inspect = self.transaction.index('ruby "$customizer" inspect', inspect)
        state_hash = self.transaction.index("STATE_SHA256\\t%s", inspect)
        self.assertLess(ruby_inspect, state_hash)

    def test_commit_marker_is_published_after_activation(self):
        activation = self.transaction.index('activate "$backup"')
        marker = self.transaction.index('mv "$committed_partial" "$backup/COMMITTED"')
        disarm = self.transaction.index('rm -f "$arm"', marker)
        self.assertLess(activation, marker)
        self.assertLess(marker, disarm)

    def test_guard_restricts_backup_and_arm_to_expected_roots(self):
        self.assertIn('[ "$backup" = "$backup_root/$backup_name" ]', self.guard)
        self.assertIn('[ "$arm" = "$arm_root/$arm_name" ]', self.guard)
        self.assertIn("/etc/init.d/openclash restart", self.guard)

    def test_router_agent_uses_unpredictable_private_temporary_paths(self):
        self.assertIn('mktemp " .. shell_quote(template)', self.agent)
        self.assertIn('make_temp_dir("/tmp/openclash-web-stage.XXXXXX"', self.agent)
        self.assertIn('make_temp_dir("/tmp/openclash-web-custom.XXXXXX"', self.agent)
        self.assertNotIn('path..".web.partial"', self.agent)
        self.assertIn('/etc/openclash/config/.openclash-web-*', self.transaction)

    def test_router_backups_require_two_non_nil_matching_hashes(self):
        self.assertIn("local source_sha=sha(path); if not source_sha then return nil end", self.agent)
        self.assertIn("not backup_sha or backup_sha~=source_sha", self.agent)

    def test_router_update_includes_forced_command(self):
        self.assertIn('openclash_web_forced_command.sh:/tmp/openclash-sync-web-forced-command.sh', self.updater)
        self.assertIn('deploy_file /tmp/openclash-sync-web-forced-command.sh', self.updater)

    def test_forced_command_clears_lua_loader_environment(self):
        for name in ("LUA_PATH", "LUA_CPATH", "LUA_INIT", "RUBYOPT", "RUBYLIB", "LD_PRELOAD", "LD_LIBRARY_PATH"):
            self.assertIn(name, self.forced_command)


if __name__ == "__main__":
    unittest.main()
