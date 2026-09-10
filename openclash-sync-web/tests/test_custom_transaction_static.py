from __future__ import annotations

import hashlib
import os
import pathlib
import re
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class CustomTransactionStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.transaction = (ROOT / "openclash_custom_transaction.sh").read_text()
        cls.guard = (ROOT / "openclash_custom_rollback_guard.sh").read_text()
        cls.agent = (ROOT / "openclash_web_router_agent.lua").read_text()
        cls.installer = (ROOT / "install_router_web_agent.sh").read_text()
        cls.updater = (ROOT / "update_router_web_agent.sh").read_text()
        cls.forced_command = (ROOT / "openclash_web_forced_command.sh").read_text()
        cls.tunnel = (ROOT / "open-console-tunnel.sh").read_text()
        cls.app = (ROOT / "static/app.js").read_text()
        cls.retention_schedule = (ROOT / "install_router_backup_retention_schedule.sh").read_text()

    def test_transaction_validates_before_and_after_atomic_switch(self):
        preflight = self.transaction.index('validate "$output"')
        switch = self.transaction.index('mv "$main_partial" "$main"')
        postflight = self.transaction.index('validate "$main"')
        self.assertLess(preflight, switch)
        self.assertLess(switch, postflight)

    def test_transaction_yaml_validation_matches_customizer_symbol_policy(self):
        self.assertIn('permitted_classes:[Symbol], aliases:false', self.transaction)
        self.assertNotIn('permitted_classes:[], aliases:false', self.transaction)
        self.assertIn('permitted_classes:[Symbol], aliases:false', self.agent)
        self.assertNotIn('permitted_classes:[], aliases:false', self.agent)

    def test_transaction_token_generation_uses_openwrt_hexdump(self):
        self.assertIn("hexdump -n 32 -v -e '1/1 \"%02x\"' /dev/urandom", self.transaction)
        self.assertNotIn("od -An -N32", self.transaction)

    def test_transaction_arms_cleanup_before_render_and_limits_request_paths(self):
        cleanup_trap = self.transaction.index("trap rollback EXIT")
        render = self.transaction.index('ruby "$customizer" render "$input"')
        self.assertLess(cleanup_trap, render)
        self.assertIn('"$state_root/replay.request"|/tmp/openclash-web-custom.*/*', self.transaction)
        self.assertIn('case "$tx" in "$state_root"/transaction.*)', self.transaction)

    def test_runtime_guard_is_armed_before_restart(self):
        arm = self.transaction.index('mv "$arm_partial" "$arm"')
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

    def test_transaction_signals_rollback_once_and_exit(self):
        abort = self.transaction[
            self.transaction.index("abort_transaction(){") :
            self.transaction.index("trap rollback EXIT")
        ]
        self.assertLess(abort.index("trap - EXIT HUP INT TERM"), abort.index("rollback"))
        self.assertLess(abort.index("rollback"), abort.index("exit 128"))
        self.assertIn("trap abort_transaction HUP INT TERM", self.transaction)
        self.assertNotIn("trap rollback EXIT HUP INT TERM", self.transaction)

    def test_background_children_do_not_inherit_transaction_lock(self):
        self.assertIn('"wait-$guard_kind" 9>&-', self.transaction)
        self.assertIn('/etc/init.d/openclash restart 9>&-', self.transaction)
        self.assertIn('exec 9>"$lock"', self.guard)
        self.assertIn('OPENCLASH_CUSTOM_TRANSACTION_LOCK_HELD', self.guard)
        self.assertIn('flock 9', self.guard)

    def test_static_recovery_does_not_restart_openclash(self):
        self.assertIn('wait-runtime|wait-static|restore-runtime|restore-static', self.guard)
        self.assertIn('[ "$recovery_kind" = runtime ]', self.guard)
        self.assertIn('[ "$candidate_config_sha" != "$previous_config_sha" ]', self.transaction)

    def test_runtime_guard_verifies_static_main_against_runtime(self):
        self.assertIn('ruby "$customizer" verify-runtime "$main" "$runtime" "$state"', self.guard)
        self.assertNotIn('ruby "$customizer" verify-runtime "$runtime" "$runtime" "$state"', self.guard)

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
        self.assertIn('if valid_commit; then', self.guard)
        self.assertIn('[ "$(sed -n \'s/^TOKEN=//p\' "$commit"', self.guard)
        self.assertIn('CONFIG_SHA256=', self.transaction)
        self.assertIn('STATE_SHA256=', self.transaction)
        self.assertIn('hash_file "$main"', self.guard)
        self.assertIn('hash_file "$state"', self.guard)
        self.assertIn('COMMITTED must', self.guard)

    def test_arm_is_generation_and_owner_bound(self):
        for field in (
            'SCHEMA=publisher-v4-openclash-custom-arm-v3',
            'TOKEN=$arm_token',
            'OWNER_PID=$$',
            'OWNER_STARTTIME=$owner_start',
            'BACKUP_MAIN_SHA256=$backup_main_sha',
            'BACKUP_STATE_SHA256=$state_backup_sha',
        ):
            self.assertIn(field, self.transaction)
        for field in ('SCHEMA', 'TOKEN', 'OWNER_PID', 'OWNER_STARTTIME', 'BACKUP_MAIN_SHA256'):
            self.assertIn(field, self.guard)
        self.assertIn('process_starttime "$owner_pid"', self.guard)
        self.assertIn('require_owner=true', self.guard)
        self.assertIn('recover-*) require_owner=false', self.guard)

    def test_runtime_transaction_snapshots_restores_and_verifies_selector_state(self):
        snapshot = self.transaction.index('selection-snapshot "$backup/runtime.before.yaml"')
        arm = self.transaction.index('arm_guard "$backup" "$guard_kind"')
        activation_call = self.transaction.index('activate "$backup" "$config_sha" "$state_sha"')
        marker = self.transaction.index('mv "$committed_partial" "$backup/COMMITTED"')
        self.assertLess(snapshot, arm)
        self.assertLess(arm, activation_call)
        self.assertLess(activation_call, marker)
        activate_body = self.transaction[
            self.transaction.index('activate(){') : self.transaction.index('commit_render(){')
        ]
        restart = activate_body.index('/etc/init.d/openclash restart')
        restore = activate_body.index('selection-restore "$runtime" "$backup/selections.before"')
        self.assertLess(restart, restore)
        self.assertIn('selection-verify "$runtime" "$backup/selections.before"', self.transaction)
        self.assertIn('SELECTIONS_RESTORED=$selections_restored', self.transaction)
        self.assertIn('SCHEMA=publisher-v4-openclash-custom-commit-v3', self.transaction)

    def test_runtime_rollback_restores_selector_state_before_accepting_recovery(self):
        runtime_restore = self.guard.index('atomic_restore "$backup/runtime.before.yaml" "$runtime"')
        selection_restore = self.guard.index('selection-restore "$runtime" "$backup/selections.before"')
        connectivity = self.guard.index('connectivity || return 1', runtime_restore)
        self.assertLess(runtime_restore, selection_restore)
        self.assertLess(selection_restore, connectivity)
        self.assertIn('selection-verify "$runtime" "$backup/selections.before"', self.guard)
        self.assertIn('BACKUP_SELECTION_SHA256', self.transaction)
        self.assertIn('BACKUP_SELECTION_SHA256', self.guard)

    def test_stale_arms_are_reconciled_under_transaction_lock(self):
        self.assertIn('reconcile_arms', self.transaction)
        self.assertIn('hold ACTIVE_ARM 25', self.transaction)
        self.assertIn('"recover-$candidate_kind"', self.transaction)
        self.assertNotIn('rm -f "$candidate_arm"', self.transaction)

    def test_recovery_is_atomic_and_hash_checked(self):
        for fragment in (
            'mktemp "$restore_dir/.openclash-rollback.XXXXXX"',
            'hash_file "$restore_partial"',
            'sync_file "$restore_partial"',
            'mv -f "$restore_partial" "$restore_target"',
            'sync_dir "$restore_dir"',
        ):
            self.assertIn(fragment, self.guard)
        self.assertIn('fail_marker RESTORE', self.guard)
        self.assertIn('STATUS=ROLLBACK_FAILED', self.guard)

    def test_guard_retries_transient_connectivity_without_weakening_both_checks(self):
        guard_connectivity = self.guard.split("connectivity(){", 1)[1].split("\n}", 1)[0]
        transaction_connectivity = self.transaction.split("connectivity(){", 1)[1].split("\n}", 1)[0]
        for source in (guard_connectivity, transaction_connectivity):
            self.assertIn('while [ "$attempt" -lt 3 ]', source)
            self.assertIn('nslookup www.gstatic.com 127.0.0.1', source)
            self.assertIn('https://www.gstatic.com/generate_204', source)
            self.assertIn('https://cp.cloudflare.com/generate_204', source)
            self.assertIn('[ "$dns_ok:$https_ok" = true:true ] && return 0', source)
            self.assertIn("sleep 2", source)

    def test_runtime_success_requires_full_verifier_before_commit(self):
        verifier_call = 'run_runtime_verifier "$main" "$runtime" "$backup/runtime.before.yaml" "$backup/main.yaml"'
        verifier = self.transaction.index(verifier_call)
        marker = self.transaction.index('mv "$committed_partial" "$backup/COMMITTED"')
        self.assertLess(verifier, marker)
        self.assertEqual(self.transaction.count(verifier_call), 2)
        self.assertIn('runtime.before.yaml', self.transaction)
        self.assertIn('runtime_verifier=/etc/openclash/publisher-v4/bin/openclash_runtime_verifier.rb', self.transaction)

    def test_restart_is_pid_starttime_bound_and_uci_is_rechecked(self):
        for fragment in (
            'write_restart_record RUNNING',
            'process_starttime "$restart_pid"',
            'kill -9 "$restart_pid"',
            'stop_owned_restart',
            'UCI_SHA256=$uci_before_sha',
            'wait_uci_digest "$uci_before_sha"',
        ):
            self.assertIn(fragment, self.transaction + self.guard)

    def test_post_restart_uci_waits_for_the_exact_protected_digest(self):
        for source, expected in ((self.transaction, "$uci_before_sha"), (self.guard, "$arm_uci_sha")):
            waiter = source[source.index("wait_uci_digest(){") :
                            source.index("\n}", source.index("wait_uci_digest(){")) + 2]
            self.assertIn('while [ "$uci_attempt" -lt 30 ]', waiter)
            self.assertIn('"$(uci_digest 2>/dev/null || true)" = "$expected_uci_sha"', waiter)
            self.assertIn("sleep 1", waiter)
            self.assertIn(f'wait_uci_digest "{expected}"', source)

    def test_uci_digest_ignores_only_proven_runtime_dnsmasq_fields_and_order(self):
        def digest_function(source: str) -> str:
            match = re.search(r"^uci_digest\(\)\{\n.*?^\}\n", source, re.MULTILINE | re.DOTALL)
            self.assertIsNotNone(match)
            return match.group(0)

        baseline = "\n".join((
            "openclash.config=openclash",
            "openclash.config.config_path='/etc/openclash/config/main.yaml'",
            "openclash.config.dnsmasq_noresolv='1'",
            "openclash.config.protected='same'",
        ))
        runtime_reordered = "\n".join((
            "openclash.config.protected='same'",
            "openclash.config.dnsmasq_resolvfile='/tmp/resolv.conf.d/resolv.conf.auto'",
            "openclash.config=openclash",
            "openclash.config.dnsmasq_noresolv='0'",
            "openclash.config.config_path='/etc/openclash/config/main.yaml'",
        ))
        protected_drift = runtime_reordered.replace("protected='same'", "protected='changed'")
        near_name_drift = runtime_reordered + "\nopenclash.config.dnsmasq_noresolv_extra='1'"

        with tempfile.TemporaryDirectory() as directory:
            fake_uci = pathlib.Path(directory) / "uci"
            fake_uci.write_text(
                "#!/bin/sh\n"
                "[ \"$1:$2:$3\" = '-q:show:openclash' ] || exit 91\n"
                "[ \"${UCI_FAIL:-0}\" = 0 ] || exit 92\n"
                "printf '%s\\n' \"$UCI_TEXT\"\n"
            )
            fake_uci.chmod(0o700)

            def run(function: str, value: str, *, fail: bool = False) -> subprocess.CompletedProcess[str]:
                environment = os.environ.copy()
                environment.update({
                    "PATH": f"{directory}:{environment['PATH']}",
                    "UCI_TEXT": value,
                    "UCI_FAIL": "1" if fail else "0",
                })
                return subprocess.run(
                    ["/bin/sh", "-c", function + "\nuci_digest"],
                    text=True,
                    capture_output=True,
                    env=environment,
                    check=False,
                )

            for source in (self.transaction, self.guard):
                function = digest_function(source)
                baseline_result = run(function, baseline)
                runtime_result = run(function, runtime_reordered)
                self.assertEqual(0, baseline_result.returncode, baseline_result.stderr)
                self.assertEqual(0, runtime_result.returncode, runtime_result.stderr)
                self.assertEqual(baseline_result.stdout, runtime_result.stdout)
                self.assertNotEqual(baseline_result.stdout, run(function, protected_drift).stdout)
                self.assertNotEqual(baseline_result.stdout, run(function, near_name_drift).stdout)
                self.assertNotEqual(0, run(function, baseline, fail=True).returncode)

        transaction_function = digest_function(self.transaction)
        guard_function = digest_function(self.guard)
        for function in (transaction_function, guard_function):
            self.assertEqual(1, function.count("dnsmasq_noresolv=/d"))
            self.assertEqual(1, function.count("dnsmasq_resolvfile=/d"))
            self.assertIn("LC_ALL=C sort", function)

    def test_commit_marker_is_token_bound_before_disarm(self):
        marker_token = self.transaction.index('"TOKEN=$arm_token"')
        marker = self.transaction.index('mv "$committed_partial" "$backup/COMMITTED"')
        disarm = self.transaction.index('rm -f "$arm"', marker)
        self.assertLess(marker_token, marker)
        self.assertLess(marker, disarm)
        self.assertIn('sync_dir "$state_root"', self.transaction)

    def test_manual_main_write_rechecks_expected_hash_under_lock(self):
        expected = self.transaction.index('[ "$current_sha" = "$expected" ]')
        render = self.transaction.index('commit_render "$input"')
        self.assertLess(expected, render)

    def test_custom_apply_and_preview_recheck_state_and_config_hashes_under_lock(self):
        self.assertIn('[ "$current_state_sha:$current_config_sha" = "$expected_state:$expected_config" ]', self.transaction)
        self.assertIn('preview)', self.transaction)
        self.assertIn('CUSTOM_PREVIEW=PASS', self.transaction)

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

    def test_stage_main_activates_only_after_transactional_backup_and_validation(self):
        stage = self.transaction.index('if [ "$label" = stage-main ]')
        activate = self.transaction.index('commit_render "$input" "$request" "$label" true', stage)
        self.assertGreater(activate, stage)
        agent_stage = self.agent.index('elseif request.action == "stage_main"')
        agent_health = self.agent.index('local health=node_health()', agent_stage)
        agent_reply = self.agent.index('reply({ok=true,message=message', agent_health)
        self.assertLess(agent_health, agent_reply)
        self.assertEqual(self.agent.count('local health=node_health()'), 1)

    def test_stage_main_recovers_only_from_unique_trusted_commit(self):
        stage = self.agent[
            self.agent.index('elseif request.action == "stage_main"') :
            self.agent.index('elseif request.action == "update_maying"')
        ]
        after_snapshot = stage.index('list_committed.." >"..shell_quote(after_path)')
        output_gate = stage.index('local output_pass=closed and journal_value(out,"ROUTER_STAGE")=="PASS"')
        self.assertLess(after_snapshot, output_gate)
        self.assertIn('local receipt_sha=receipt and trusted_stage_commit(receipt,target) or nil', stage)
        self.assertIn('if #matches==0 and not output_pass then', stage)
        self.assertIn('if #matches~=1 then failure("本次 Candidate 事务绑定不唯一，主配置未更新") end', stage)
        self.assertIn('if output_pass and output_sha and output_sha~=candidate_sha then', stage)
        self.assertIn('if candidate_digest~=candidate_sha then', stage)
        self.assertIn('if stage_recovered then message=message.."；已由可信 COMMITTED 回执恢复 Candidate 结果" end', stage)

    def test_router_pipes_use_explicit_exit_status_and_find_has_no_masking_pipeline(self):
        self.assertEqual(self.agent.count("io.popen("), 1)
        capture = self.agent[
            self.agent.index("local function capture(command)") :
            self.agent.index("local function sha(path)")
        ]
        self.assertIn("openclash_pipe_status=$?", capture)
        self.assertIn('bytes:find("OPENCLASH_PIPE_STATUS",1,true)', capture)
        self.assertIn('status == "0"', capture)
        listing = next(line for line in self.agent.splitlines() if "local list_committed=" in line)
        self.assertNotIn("|", listing)

    def test_stage_commit_trust_contract_is_fail_closed(self):
        helper = self.agent[
            self.agent.index('local function trusted_stage_commit') :
            self.agent.index('local function stage_failure_reason')
        ]
        for required in (
            'journal_value(bytes,"ROUTER_STAGE")~="PASS"',
            'journal_value(bytes,"TARGET")~=expected_target',
            'journal_value(bytes,"DNS_RESOLVER_REACHABILITY")~="PASS"',
            'journal_value(bytes,"ACTIVE_CHANGED")~="false"',
            'journal_value(bytes,"UCI_CHANGED")~="false"',
            'journal_value(bytes,"SERVICE_RESTARTED")~="false"',
            'valid_digest(digest)',
        ):
            self.assertIn(required, helper)

    def test_stage_failure_reason_is_sanitized_before_display(self):
        helper = self.agent[
            self.agent.index('local function stage_failure_reason') :
            self.agent.index('local function private_path')
        ]
        self.assertIn('#reason>64', helper)
        self.assertIn('reason:match("^[A-Z0-9_-]+$")', helper)
        self.assertIn('主配置生成或校验未通过（"..reason.."），未切换 ACTIVE', self.agent)

    def test_backup_retention_runs_after_commit_and_disarm(self):
        marker = self.transaction.index('mv "$committed_partial" "$backup/COMMITTED"')
        disarm = self.transaction.index('rm -f "$arm"', marker)
        retention = self.transaction.index('prune-backups "$backup_root" "$backup"', disarm)
        self.assertLess(marker, disarm)
        self.assertLess(disarm, retention)
        self.assertIn('BACKUP_RETENTION', self.transaction)

    def test_daily_retention_schedule_is_locked_marked_and_reversible(self):
        schedule = self.retention_schedule
        self.assertIn("23 4 * * * /usr/bin/flock -n /etc/openclash/publisher-v4/web-state/customizations.lock", schedule)
        self.assertIn("prune-backups-scheduled /etc/openclash/publisher-v4/web-backups", schedule)
        self.assertIn("OPENCLASH_SYNC_WEB_RETENTION_BEGIN", schedule)
        self.assertIn("OPENCLASH_SYNC_WEB_RETENTION_END", schedule)
        self.assertIn('cp "$cron_file" "$backup/root.crontab.before"', schedule)
        self.assertIn('restore(){', schedule)
        self.assertIn('reload_cron || hold CRON_RELOAD', schedule)
        self.assertIn("prune-backups-scheduled", (ROOT / "openclash_customizer.rb").read_text())
        for forbidden in ("/etc/init.d/openclash restart", "tailscale", "firewall", "uci set"):
            self.assertNotIn(forbidden, schedule.lower())

    def test_daily_retention_schedule_binds_current_customizer_digest(self):
        customizer_digest = hashlib.sha256((ROOT / "openclash_customizer.rb").read_bytes()).hexdigest()
        match = re.search(r"^expected_customizer=([0-9a-f]{64})$", self.retention_schedule, re.MULTILINE)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), customizer_digest)

    def test_route_check_never_puts_user_input_in_a_shell_command(self):
        route = self.agent.index('elseif request.action == "route_check"')
        block = self.agent[route:self.agent.index('else\n  failure("动作不在白名单")', route)]
        self.assertIn('fs.writefile(path,value.."\\n"..source_ip.."\\n")', block)
        self.assertIn('shell_quote(path)', block)
        self.assertNotIn('shell_quote(value)', block)
        self.assertNotIn('shell_quote(source_ip)', block)
        self.assertNotIn('json.stringify', block)
        self.assertIn('CONTEXTUAL=true', block)
        self.assertIn('REJECT=true', block)
        self.assertIn('BLOCKED=true', block)
        self.assertIn('result.mode==="REJECT"', self.app)
        self.assertIn('result.reachability==="UNREACHABLE"', self.app)
        self.assertIn('固定探针状态 UNKNOWN', self.app)
        self.assertIn('errors: Array.isArray(e.details) ? e.details : []', self.app)
        self.assertIn('data.baseline_delta||{}', self.app)
        self.assertIn('可补齐 ${safe} 条（完整原文 ${exact} 条）/ 超出页面范围 ${unresolved} 条', self.app)
        self.assertIn('HEALTH_URL = "http://www.gstatic.com/generate_204"', (ROOT / "openclash_customizer.rb").read_text())

    def test_frontend_batch_actions_have_no_target_selector_and_notice_has_no_timer(self):
        index = (ROOT / "static/index.html").read_text()
        css = (ROOT / "static/app.css").read_text()
        self.assertNotIn('id="updateTarget"', index)
        self.assertNotIn('id="customTarget"', index)
        self.assertIn('href="https://nxonearth.com" target="_blank" rel="noopener noreferrer"', index)
        self.assertNotIn('setTimeout(()=>box.classList.add("hidden")', self.app)
        self.assertIn('captureNodeHealth', self.app)
        self.assertIn('captureNodeHealth(data,isMain)', self.app)
        self.assertIn('lastNodeHealth[target]=null', self.app)
        self.assertIn('Number.isInteger(item.passed)', self.app)
        self.assertIn('await bootstrap(true)', self.app)
        self.assertIn('if(!preserveNotice)notice(e.message,true)', self.app)
        self.assertIn('configuredDuplicateResult', self.app)
        self.assertIn('data.unowned_rule_matcher_overrides.forEach', self.app)
        self.assertIn('matcherOverrides.get(index)||ruleMatcher(item)', self.app)
        self.assertIn('当前 OpenClash 配置中已存在相同规则', self.app)
        self.assertIn('当前 OpenClash 非同步器配置中已有同匹配条件但内容不同的规则', self.app)
        self.assertNotIn('data.rules.forEach(addRule)', self.app)
        self.assertNotIn('data.fake_ip_filter.forEach(addFilter)', self.app)
        self.assertIn('savedRules=(data.editable_rules||data.rules).map(cloneRule)', self.app)
        self.assertIn('reconciliationRules=(data.reconciliation_rules||[]).map(cloneRule)', self.app)
        self.assertIn('renderManagedRules', self.app)
        self.assertIn('renderManagedFilters', self.app)
        self.assertIn('await bootstrap(true,false)', self.app)
        self.assertIn('button.disabled=true', self.app)
        self.assertIn('id="managedRuleList"', index)
        self.assertIn('id="managedFilterList"', index)
        self.assertIn('已有手工定制不会重复铺满新增区域', index)
        self.assertIn('带 <code>no-resolve</code>、额外选项或非规范文本的项目按完整原文补齐', index)
        self.assertIn('<code>MATCH</code>、<code>GEOIP</code>、<code>RULE-SET</code> 等页面范围外规则只读展示', index)
        self.assertNotIn('复杂或非规范格式只展示并明确计数', index)
        self.assertIn('@media(max-width:480px)', css)
        self.assertIn('.route-form input{min-width:0;width:100%}', css)
        self.assertIn('.top-status{max-width:40vw;min-width:0', css)
        self.assertNotIn('历史备份不会删除', index)

    def test_guard_restricts_backup_and_arm_to_expected_roots(self):
        self.assertIn('[ "$backup" = "$backup_root/$backup_name" ]', self.guard)
        self.assertIn('[ "$arm" = "$state_root/$arm_name" ]', self.guard)
        self.assertIn("/etc/init.d/openclash restart", self.guard)

    def test_router_agent_uses_unpredictable_private_temporary_paths(self):
        self.assertIn('mktemp " .. shell_quote(template)', self.agent)
        self.assertIn('make_temp_dir("/tmp/openclash-web-stage.XXXXXX"', self.agent)
        self.assertIn('make_temp_dir("/tmp/openclash-web-custom.XXXXXX"', self.agent)
        self.assertNotIn('path..".web.partial"', self.agent)
        self.assertIn('/etc/openclash/config/.openclash-web-*', self.transaction)

    def test_router_agent_rejects_special_permission_bits(self):
        self.assertIn('info.modestr == mode_string', self.agent)
        self.assertIn('private_path(path,"reg","rw-------")', self.agent)
        self.assertIn('private_path(path,"dir","rwx------")', self.agent)
        self.assertNotIn("modedec", self.agent)

    def test_router_agent_binds_content_and_digest_to_one_stable_descriptor(self):
        for fragment in (
            'local file = nixio.open(path,"r")',
            'file:fileno()',
            'local digest_before = sha(descriptor_path)',
            'local digest_after = sha(descriptor_path)',
            'same_file(opened_before,opened_after)',
            'same_file(opened_after,named_after)',
            'return table.concat(chunks),digest_after',
        ):
            self.assertIn(fragment, self.agent)
        read = self.agent.index('elseif request.action == "read"')
        response = self.agent.index('reply({ok=true,content=content,sha256=digest', read)
        self.assertLess(self.agent.index('local content,digest=stable_read', read), response)
        self.assertNotIn('local digest=sha(path)', self.agent)

    def test_provider_files_are_read_only_and_main_uses_locked_transaction(self):
        write = self.agent.index('elseif request.action == "write"')
        reject = self.agent.index('if name~=main then failure(', write)
        temporary = self.agent.index("local tmp=make_temp_file", write)
        transaction = self.agent.index('custom_transaction).." replace "', write)
        self.assertLess(reject, temporary)
        self.assertLess(temporary, transaction)
        self.assertNotIn("local function atomic_restore", self.agent)
        self.assertIn("currentName===mainConfigName", self.app)

    def test_router_update_includes_forced_command(self):
        self.assertIn('openclash_web_forced_command.sh:/tmp/openclash-sync-web-forced-command.sh', self.updater)
        self.assertIn('atomic_publish "$source_file" "$root/$name"', self.updater)

    def test_router_web_expected_hashes_match_assets(self):
        for script in (self.installer, self.updater):
            expected = dict(
                re.findall(
                    r'^\s+(\S+\.(?:lua|sh|rb))\) printf \'%s\\n\' ([0-9a-f]{64});;$',
                    script,
                    re.MULTILINE,
                )
            )
            self.assertEqual(
                set(expected),
                {
                    'openclash_web_router_agent.lua',
                    'openclash_web_forced_command.sh',
                    'openclash_customizer.rb',
                    'openclash_custom_transaction.sh',
                    'openclash_custom_rollback_guard.sh',
                },
            )
            for name, digest in expected.items():
                self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), digest)

    def test_web_agents_share_lock_order_and_hold_all_mutations(self):
        for script in (self.installer, self.updater):
            activation = script.index('exec 8<>"$state_root/activation.lock"')
            stage = script.index('exec 9<>"$publisher_root/stage.lock"')
            customizations = script.index('exec 7<>"$state_root/customizations.lock"')
            self.assertLess(activation, stage)
            self.assertLess(stage, customizations)
            for lock_path, parent, fd in (
                ('$state_root/activation.lock', '$state_root', 8),
                ('$publisher_root/stage.lock', '$publisher_root', 9),
                ('$state_root/customizations.lock', '$state_root', 7),
                ('$auth_lock', '$auth_dir', 6),
            ):
                self.assertIn(f'ensure_lock_file "{lock_path}" "{parent}"', script)
                self.assertIn(f'flock -n {fd}', script)
                self.assertIn(f'lock_binding "{lock_path}" {fd}', script)
            binding = script[script.index('lock_binding(){') : script.index('ensure_lock_file(){')]
            self.assertIn('a.nlink==1', binding)
            self.assertIn('b.nlink==1', binding)
            self.assertIn('asset_manifest=', script)

    def test_router_rollback_disables_access_before_mutation_and_binds_removal(self):
        for script in (self.installer, self.updater):
            rollback = script[script.index('rollback(){') : script.index('finish(){')]
            stop = rollback.index('if stop_web_access_for_recovery; then')
            early_return = rollback.index('return', stop)
            first_cleanup = min(
                position
                for marker in ('cleanup_temporaries', 'cleanup_temporary')
                if (position := rollback.find(marker, early_return)) >= 0
            )
            self.assertLess(stop, early_return)
            self.assertLess(early_return, first_cleanup)
            self.assertIn('failure_reason=WEB_ACCESS_STOP_FAILED', rollback[:first_cleanup])

            remover = script[script.index('atomic_remove(){') : script.index('rollback(){')]
            self.assertIn('expected_digest=$2', remover)
            self.assertIn('opened.nlink==1', remover)
            self.assertIn('Digest::SHA256', remover)
            self.assertIn('File.unlink(path)', remover)

        updater_match = self.updater[
            self.updater.index('current_matches_backup(){') : self.updater.index('publish_active_update(){')
        ]
        self.assertIn('trusted_file "$backup/$name.before" -rw-------', updater_match)
        self.assertIn('installed_metadata "$target_file"', updater_match)
        updater_rollback = self.updater[
            self.updater.index('rollback(){') : self.updater.index('finish(){')
        ]
        self.assertIn('atomic_restore "$backup/$name.before" "$target_file" 0500 "$intended"', updater_rollback)
        self.assertIn('atomic_remove "$target_file" "$intended"', updater_rollback)
        updater_recovery = self.updater[
            self.updater.index('recover_prepared_update(){') : self.updater.index('rollback(){')
        ]
        self.assertIn(
            'atomic_restore "$recovery_backup/$recovery_name.before" "$root/$recovery_name" 0500 "$recovery_after"',
            updater_recovery,
        )
        self.assertIn('atomic_remove "$root/$recovery_name" "$recovery_after"', updater_recovery)

    def test_web_lifecycle_outer_lock_and_marker_order(self):
        for script in (self.installer, self.updater):
            outer = script.index('flock -n 5 || hold INSTALL_LOCK')
            activation = script.index('flock -n 8 || hold ACTIVATION_LOCK')
            stage = script.index('flock -n 9 || hold STAGE_LOCK')
            customizations = script.index('flock -n 7 || hold WEB_LOCK')
            marker = script.index(
                'if [ -e "$global_rollback_marker" ] || [ -L "$global_rollback_marker" ]',
                customizations,
            )
            self.assertLess(outer, activation)
            self.assertLess(activation, stage)
            self.assertLess(stage, customizations)
            self.assertLess(customizations, marker)
            self.assertIn('install_lock=/etc/openclash/.publisher-v4-install.lock', script)
            self.assertIn('lock_binding "$install_lock" 5', script)

        auth = self.installer.index('flock -n 6 || hold AUTHORIZED_KEYS_LOCK')
        marker = self.installer.index(
            'if [ -e "$global_rollback_marker" ] || [ -L "$global_rollback_marker" ]', auth
        )
        self.assertLess(auth, marker)
        self.assertLess(marker, self.installer.index('capture_runtime_baseline ||'))
        self.assertLess(
            self.installer.index('recover_prepared_install || case'),
            self.installer.index('[ ! -e "$root" ] && [ ! -L "$root" ] || hold WEB_ROOT_EXISTS'),
        )

    def test_web_lifecycle_journals_precede_mutation_and_finish_last(self):
        for script, operation in ((self.installer, "INSTALL"), (self.updater, "UPDATE")):
            pending = script.rindex(f'publish_pending {operation} "$backup"')
            backup_create = script.index('mkdir "$backup"', pending)
            self.assertIn('prepared=$state_root/web-lifecycle.PREPARED', script)
            self.assertIn('active_state=$state_root/web-lifecycle.ACTIVE', script)
            prepared = script.index(
                'atomic_publish_stream "$prepared" "$prepared_partial" <"$prepared_payload"',
                pending,
            )
            self.assertIn(f"'OP={operation}'", script[pending : prepared + 1])
            if operation == "INSTALL":
                first_mutation = script.index('mkdir "$root" || hold WEB_ROOT_CREATE', prepared)
                committed = script.index('mv -f "$backup/COMMITTED.partial" "$backup/COMMITTED"')
                active = script.index('publish_active_install "$backup"', committed)
            else:
                first_mutation = script.index('asset_mutation_started=true', prepared)
                committed = script.index('mv -f "$backup/COMMITTED.partial" "$backup/COMMITTED"')
                active = script.index('publish_active_update "$backup"', committed)
            source_cleanup = script.index('cleanup_sources || recovery_hold SOURCE_CLEANUP', active)
            cleanup = script.index('complete_lifecycle_journals "$pending_sha"', source_cleanup)
            passed = script.index(f"'ROUTER_WEB_{operation}=PASS'", cleanup)
            self.assertLess(pending, backup_create)
            self.assertLess(backup_create, prepared)
            self.assertLess(prepared, first_mutation)
            self.assertLess(first_mutation, committed)
            self.assertLess(committed, active)
            self.assertLess(active, source_cleanup)
            self.assertLess(source_cleanup, cleanup)
            self.assertLess(cleanup, passed)
            self.assertIn('PREPARED_THIRD_HASH', script)
            self.assertIn('COMMITTED_MIXED_STATE', script)
            self.assertIn('RECOVERED_COMMITTED=true', script)

            lifecycle = script[
                script.index('complete_lifecycle_journals(){') :
                script.index('\n}', script.index('complete_lifecycle_journals(){')) + 2
            ]
            prepared_remove = lifecycle.index('rm -f "$prepared"')
            pending_remove = lifecycle.index('rm -f "$pending"')
            self.assertLess(prepared_remove, pending_remove)
            self.assertGreaterEqual(lifecycle.count('fsync_directory "$state_root"'), 2)

    def test_web_recovery_classifies_before_writing_and_preserves_committed(self):
        install_recovery = self.installer[
            self.installer.index('recover_prepared_install(){') : self.installer.index('\n}', self.installer.index('recover_prepared_install(){')) + 2
        ]
        update_recovery = self.updater[
            self.updater.index('recover_prepared_update(){') : self.updater.index('\n}', self.updater.index('recover_prepared_update(){')) + 2
        ]
        for recovery in (install_recovery, update_recovery):
            classification = recovery.index('recovery_current=$(file_state')
            committed = recovery.rindex('if [ -e "$recovery_backup/COMMITTED"')
            first_recovery_write = recovery.index('rm -f', committed)
            self.assertLess(classification, committed)
            self.assertLess(committed, first_recovery_write)
            self.assertNotIn('rm -f "$recovery_backup/COMMITTED"', recovery)
            self.assertIn('receipt_runtime_stable_matches "$recovery_backup/COMMITTED"', recovery)
            self.assertIn('committed_history_matches_prepared', recovery)
            self.assertNotIn('CORE_PID_AFTER=$core_pid_before', recovery)

    def test_web_recovery_binds_runtime_receipts_and_rejects_hardlinks(self):
        runtime_fields = (
            "ACTIVE_BEFORE_SHA256",
            "UCI_BEFORE_SHA256",
            "CORE_SHA256",
            "CORE_PID_BEFORE",
            "CORE_START_BEFORE",
            "MAIN_BEFORE_SHA256",
            "RUNTIME_BEFORE_SHA256",
            "CUSTOM_STATE_BEFORE_SHA256",
        )
        for script in (self.installer, self.updater):
            self.assertIn("prepared_runtime_stable_matches(){", script)
            self.assertIn("receipt_runtime_stable_matches(){", script)
            self.assertIn("PREPARED_RUNTIME_DRIFT", script)
            self.assertIn("File.lstat(ARGV.fetch(0)).nlink == 1", script)
            prepared = script[script.index("prepared_payload=$backup/PREPARED.payload") :]
            first_mutation = prepared.index("atomic_publish ")
            prepared = prepared[:first_mutation]
            for field in runtime_fields:
                self.assertIn(field, prepared)

    def test_web_lifecycle_schemas_are_closed_and_digest_failures_are_visible(self):
        for script in (self.installer, self.updater):
            self.assertIn("journal_schema_ok(){", script)
            self.assertIn("index($0, key \"=\") == 1", script)
            self.assertIn("publisher-v4-router-web-active-v2", script)
            self.assertIn("publisher-v4-router-web-pending-v1", script)
            self.assertIn("PENDING_SHA256", script)
            self.assertIn("PREPARED_SHA256", script)
            self.assertIn("BACKUP_MANIFEST_SHA256", script)
            self.assertIn("SOURCE_INODE", script)
            self.assertIn("RECEIPT_SCHEMA", script)
            self.assertNotRegex(script, r"printf[^\n]*\$\((?:sha|sha256sum)")
            self.assertNotIn("sha(){ sha256sum", script)

    def test_historical_active_receipt_does_not_freeze_mutable_runtime(self):
        for script in (self.installer, self.updater):
            stable = script[
                script.index("receipt_runtime_stable_matches(){") :
                script.index("\n}", script.index("receipt_runtime_stable_matches(){")) + 2
            ]
            for field in (
                "ACTIVE_AFTER_SHA256",
                "UCI_AFTER_SHA256",
                "CORE_SHA256",
                "MAIN_AFTER_SHA256",
                "RUNTIME_AFTER_SHA256",
                "CUSTOM_STATE_AFTER_SHA256",
            ):
                self.assertIn(field, stable)
            self.assertNotIn("CORE_PID_AFTER", stable)
            self.assertNotIn("CORE_START_AFTER", stable)
            verify = script[script.index("verify_active_") : script.index("recover_prepared_", script.index("verify_active_"))]
            self.assertIn("receipt_auth_stable_matches", verify)
            self.assertNotIn("receipt_runtime_stable_matches", verify)
            self.assertIn("runtime_unchanged", verify)

    def test_committed_cleanup_finishes_before_prepared_is_removed(self):
        for script, operation in ((self.installer, "INSTALL"), (self.updater, "UPDATE")):
            final_active = script.rindex(f'publish_active_{operation.lower()} "$backup"')
            cleanup = script.index("cleanup_sources || recovery_hold SOURCE_CLEANUP", final_active)
            lifecycle = script.index('complete_lifecycle_journals "$pending_sha"', cleanup)
            passed = script.index(f"'ROUTER_WEB_{operation}=PASS'", lifecycle)
            self.assertLess(final_active, cleanup)
            self.assertLess(cleanup, lifecycle)
            self.assertLess(lifecycle, passed)
            self.assertRegex(script, r"cleanup_recovery_source(?:s)?\(")

    def test_web_update_validates_stable_active_state_before_new_baseline(self):
        self.assertIn("verify_active_update(){", self.updater)
        active_check = self.updater.index('if [ -e "$active_state" ]', self.updater.index('recover_prepared_update || case'))
        installed_check = self.updater.index('[ -d "$root" ]', active_check)
        verify = self.updater.index("verify_active_update", active_check)
        self.assertLess(verify, installed_check)
        self.assertIn("ACTIVE_STATE_DRIFT", self.updater[active_check:installed_check])

    def test_router_pending_covers_every_prepared_staging_window(self):
        for script, operation in ((self.installer, "INSTALL"), (self.updater, "UPDATE")):
            pending = script.rindex(f'publish_pending {operation} "$backup"')
            backup_create = script.index('mkdir "$backup"', pending)
            source_create = script.index('mkdir "$source_stage"', backup_create)
            prepared = script.index(
                'atomic_publish_stream "$prepared" "$prepared_partial" <"$prepared_payload"',
                source_create,
            )
            self.assertLess(pending, backup_create)
            self.assertLess(backup_create, source_create)
            self.assertLess(source_create, prepared)
            self.assertIn('pending_partial=$state_root/.web-lifecycle.PENDING.partial', script)
            self.assertIn('normalize_pending_partial || recovery_hold', script)
            self.assertIn('cleanup_pending_backup "$orphan_backup" "$orphan_op" || return 3', script)

            cleanup = script[
                script.index('cleanup_pending_backup(){') :
                script.index('\n}', script.index('cleanup_pending_backup(){')) + 2
            ]
            self.assertIn('Dir.children(backup).each', cleanup)
            self.assertIn('raise unless top_allowed.include?(name)', cleanup)
            self.assertIn('child_st.nlink==1', cleanup)

    def test_update_replaces_old_active_with_digest_bound_cas(self):
        publish = self.updater[
            self.updater.index('publish_active_update(){') :
            self.updater.index('\n}', self.updater.index('publish_active_update(){')) + 2
        ]
        for fragment in (
            'ACTIVE_RECEIPT_BEFORE_SHA256',
            '[ "$(sha "$active_state")" = "$expected_active_before_sha" ]',
            'atomic_replace_stream "$active_state" "$active_partial"',
            'SCHEMA=publisher-v4-router-web-active-v2',
            'PENDING_SHA256=$active_pending_sha',
            'PREPARED_SHA256=$active_prepared_sha',
        ):
            self.assertIn(fragment, publish)
        self.assertNotIn("CORE_PID", publish)

        prepared = self.updater[self.updater.rindex('prepared_payload=$backup/PREPARED.payload') :]
        receipt = prepared[prepared.index('COMMITTED') :]
        self.assertIn('ACTIVE_RECEIPT_BEFORE_PATH=$active_state', prepared)
        self.assertIn('ACTIVE_RECEIPT_BEFORE_SHA256=$active_receipt_before_sha', prepared)
        self.assertIn('ACTIVE_RECEIPT_BEFORE_SHA256=$active_receipt_before_sha', receipt)

    def test_update_preserves_and_recovers_authorized_keys_binding(self):
        for fragment in (
            'cp "$auth" "$backup/authorized_keys.before"',
            'sha256sum authorized_keys.before >>SHA256SUMS.before',
            'AUTHORIZED_KEYS_BEFORE_SHA256=$auth_before_sha',
            'AUTHORIZED_KEYS_AFTER_SHA256=$auth_before_sha',
            'web_access_disabled_digest "$recovery_backup/authorized_keys.before"',
            'atomic_restore_authorized_keys "$recovery_backup/authorized_keys.before"',
            'receipt_auth_stable_matches "$recovery_backup/COMMITTED"',
        ):
            self.assertIn(fragment, self.updater)
        self.assertIn('top_allowed << "authorized_keys.before"', self.updater)
        self.assertIn('[ "$auth_after_sha" = "$auth_before_sha" ]', self.updater)

    def test_source_bundles_reject_hardlinks_and_extra_files(self):
        for script, operation in ((self.installer, "INSTALL"), (self.updater, "UPDATE")):
            bundle = script[
                script.index('source_bundle_ok(){') :
                script.index('\n}', script.index('source_bundle_ok(){')) + 2
            ]
            self.assertIn('actual.sort==expected.sort', bundle)
            self.assertIn('(actual-expected).empty?', bundle)
            self.assertIn('entry.nlink==1', bundle)
            self.assertIn(f'source_bundle_ok "$source_stage" {operation} true', script)
            self.assertIn(f'source_bundle_ok "$recovery_source" {operation}', script)
            source_metadata = script[
                script.index('source_metadata(){') :
                script.index('\n}', script.index('source_metadata(){')) + 2
            ]
            self.assertIn('File.lstat(ARGV.fetch(0)).nlink == 1', source_metadata)

    def test_router_recovery_failures_disable_web_access(self):
        for script in (self.installer, self.updater):
            stop = script[
                script.index('stop_web_access_for_recovery(){') :
                script.index('\n}', script.index('stop_web_access_for_recovery(){')) + 2
            ]
            self.assertIn('openclash_web_forced_command.sh $target', stop)
            self.assertIn('openclash-web-$target', stop)
            self.assertIn('mv -f "$fail_closed_temporary" "$auth"', stop)
            self.assertIn('fsync_directory "$auth_dir"', stop)
            self.assertIn('recovery_hold PREPARED_INVALID', script)
            self.assertIn('recovery_hold ACTIVE_INVALID', script)
            self.assertIn('recovery_hold PENDING_INVALID', script)
            self.assertIn('stop_web_access_for_recovery; then web_access_disabled=true', script)

    def test_source_and_lifecycle_cleanup_cannot_be_reported_as_pass(self):
        for script, operation in ((self.installer, "INSTALL"), (self.updater, "UPDATE")):
            active = script.rindex(f'publish_active_{operation.lower()} "$backup"')
            source_cleanup = script.index('cleanup_sources || recovery_hold SOURCE_CLEANUP', active)
            lifecycle_cleanup = script.index('complete_lifecycle_journals "$pending_sha"', source_cleanup)
            passed = script.index(f"'ROUTER_WEB_{operation}=PASS'", lifecycle_cleanup)
            self.assertLess(active, source_cleanup)
            self.assertLess(source_cleanup, lifecycle_cleanup)
            self.assertLess(lifecycle_cleanup, passed)

            rollback = script[
                script.index('rollback(){') :
                script.index('\n}', script.index('rollback(){')) + 2
            ]
            self.assertLess(
                rollback.index('cleanup_sources || rollback_ok=false'),
                rollback.index('write_status ROLLED_BACK'),
            )

    def test_committed_recovery_is_not_bound_to_historical_pid(self):
        for script in (self.installer, self.updater):
            stable = script[
                script.index('receipt_runtime_stable_matches(){') :
                script.index('\n}', script.index('receipt_runtime_stable_matches(){')) + 2
            ]
            prepared_stable = script[
                script.index('prepared_runtime_stable_matches(){') :
                script.index('\n}', script.index('prepared_runtime_stable_matches(){')) + 2
            ]
            for function in (stable, prepared_stable):
                self.assertNotIn('CORE_PID', function)
                self.assertNotIn('CORE_START', function)
            recovery_start = script.index('recover_prepared_')
            recovery = script[recovery_start : script.index('\n}', recovery_start) + 2]
            self.assertIn('receipt_runtime_stable_matches', recovery)
            self.assertIn('prepared_runtime_stable_matches', recovery)

    def test_rolled_back_recovery_cleanup_is_resumable(self):
        for script in (self.installer, self.updater):
            recovery_start = script.index('recover_prepared_')
            recovery = script[recovery_start : script.index('\n}', recovery_start) + 2]
            status = recovery.rindex('write_status ROLLED_BACK')
            source_cleanup = recovery.index('cleanup_recovery_source', status)
            lifecycle_cleanup = recovery.index('complete_lifecycle_journals', source_cleanup)
            self.assertLess(status, source_cleanup)
            self.assertLess(source_cleanup, lifecycle_cleanup)
            self.assertIn('recovery_rolled_back=true', recovery)
            self.assertIn('source_bundle_complete=false', recovery)
            terminal_source_guard = '[ "$recovery_committed" = true ] || [ "$recovery_rolled_back" = true ] || return 2'
            self.assertGreaterEqual(recovery.count(terminal_source_guard), 2)

            committed = recovery.rindex('if [ -e "$recovery_backup/COMMITTED"')
            committed_history = recovery.index('committed_history_matches_prepared', committed)
            runtime_validation = recovery.index('receipt_runtime_stable_matches', committed_history)
            committed_cleanup = recovery.index('cleanup_recovery_temporaries "$root" || return 5', runtime_validation)
            committed_auth_cleanup = recovery.index('cleanup_recovery_auth_temporaries || return 5', committed_cleanup)
            noncommitted_guard = recovery.index('[ ! -L "$recovery_backup/COMMITTED" ] || return 2', committed_auth_cleanup)
            noncommitted_cleanup = recovery.index('cleanup_recovery_temporaries "$root" || return 5', noncommitted_guard)
            self.assertNotIn('cleanup_recovery_temporaries "$root" || return 5', recovery[:committed])
            self.assertLess(runtime_validation, committed_cleanup)
            self.assertLess(committed_cleanup, committed_auth_cleanup)
            self.assertLess(noncommitted_guard, noncommitted_cleanup)

            if script == self.updater:
                active_cas = recovery.index('[ "$(sha "$active_state")" = "$recovery_active_before_sha" ] || return 3', noncommitted_guard)
                self.assertLess(active_cas, noncommitted_cleanup)

            main_recovery = script[script.rindex('capture_runtime_baseline || hold') :]
            prepared_recovery = main_recovery.index('recover_prepared_')
            pending_recovery = main_recovery.index('recover_pending_without_prepared ||', prepared_recovery)
            web_temporary_cleanup = main_recovery.index(
                'cleanup_recovery_temporaries "$root" || recovery_hold',
                pending_recovery,
            )
            auth_temporary_cleanup = main_recovery.index(
                'cleanup_recovery_auth_temporaries || recovery_hold',
                pending_recovery,
            )
            self.assertNotIn('cleanup_recovery_auth_temporaries || recovery_hold', main_recovery[:pending_recovery])
            self.assertLess(pending_recovery, web_temporary_cleanup)
            self.assertLess(pending_recovery, auth_temporary_cleanup)

            status_writer = script[
                script.index('write_status(){') :
                script.index('\n}', script.index('write_status(){')) + 2
            ]
            self.assertIn('PENDING_SHA256=$pending_sha', status_writer)
            self.assertIn('PREPARED_SHA256=$prepared_sha', status_writer)
            self.assertIn('atomic_publish_stream "$backup/$status" "$status_partial"', status_writer)

            pending_recovery = script[
                script.index('recover_pending_without_prepared(){') :
                script.index('\n}', script.index('recover_pending_without_prepared(){')) + 2
            ]
            terminal = pending_recovery.index('$orphan_backup/ROLLED_BACK')
            digest_check = pending_recovery.index('PENDING_SHA256', terminal)
            pending_remove = pending_recovery.index('rm -f "$pending"', digest_check)
            self.assertLess(terminal, digest_check)
            self.assertLess(digest_check, pending_remove)

    def test_update_uses_pending_trap_until_prepared_is_durable(self):
        pending = self.updater.rindex('publish_pending UPDATE "$backup"')
        pending_trap = self.updater.index('trap pending_exit EXIT', pending)
        prepared = self.updater.index(
            'atomic_publish_stream "$prepared" "$prepared_partial" <"$prepared_payload"',
            pending_trap,
        )
        finish_trap = self.updater.index('trap finish EXIT', prepared)
        mutation = self.updater.index('asset_mutation_started=true', finish_trap)
        self.assertLess(pending_trap, prepared)
        self.assertLess(prepared, finish_trap)
        self.assertLess(finish_trap, mutation)

    def test_router_web_deploy_scripts_parse_as_shell(self):
        for name in ('install_router_web_agent.sh', 'update_router_web_agent.sh'):
            script = (ROOT / name).read_text()
            subprocess.run(
                ['sh', '-n', str(ROOT / name)],
                check=True,
                capture_output=True,
                text=True,
            )
            ruby_snippets = re.findall(r"ruby(?:\s+-r\S+)?\s+-e\s+'(.*?)'(?=\s)", script, re.DOTALL)
            self.assertGreaterEqual(len(ruby_snippets), 10)
            for snippet in ruby_snippets:
                subprocess.run(
                    ['ruby', '-c'],
                    input=snippet,
                    check=True,
                    capture_output=True,
                    text=True,
                )

    def test_web_assets_have_before_or_absent_backups_and_hash_manifest(self):
        for script in (self.installer, self.updater):
            self.assertIn('.before', script)
            self.assertIn('.absent', script)
            self.assertIn('SHA256SUMS.before', script)
            self.assertIn('sha256sum -c SHA256SUMS.before', script)
            self.assertIn('fsync_path "$backup/SHA256SUMS.before"', script)
            self.assertIn('source_stage=$backup/source', script)
            self.assertIn('expected_hash(){', script)
            self.assertIn('SOURCE_TRUST', script)
            self.assertIn('SOURCE_DRIFT', script)

    def test_web_publish_and_restore_are_atomic_and_synced(self):
        for script in (self.installer, self.updater):
            self.assertIn('mktemp "$root/.openclash-sync-web-new.XXXXXX"', script)
            self.assertIn('cmp -s "$source_file" "$temporary"', script)
            self.assertIn('fsync_path "$temporary"', script)
            self.assertIn('mv -f "$temporary" "$target_file"', script)
            self.assertIn('fsync_path "$target_file"', script)
            self.assertIn('fsync_directory "$root"', script)
            self.assertNotIn('cp "$source_file" "$root/', script)

    def test_web_failures_are_fail_closed(self):
        for script in (self.installer, self.updater):
            self.assertIn('write_status ROLLBACK_FAILED', script)
            self.assertIn('ROUTER_WEB_', script)
            self.assertNotIn('rm -rf "$root"', script)
            self.assertIn('COMMITTED.partial', script)
            self.assertIn('mv -f "$backup/COMMITTED.partial" "$backup/COMMITTED"', script)
            self.assertIn('RECEIPT_UNAVAILABLE', script)
            self.assertIn('cleanup_status_partials', script)

    def test_install_authorized_keys_is_atomic(self):
        self.assertIn('AUTHORIZED_KEYS_DIR_MODE', self.installer)
        self.assertIn('authorized_keys.new.XXXXXX', self.installer)
        self.assertIn('printf \'%s\\n\' "$entry" >>"$temporary"', self.installer)
        self.assertIn('cmp -s "$auth" "$temporary"', self.installer)
        self.assertIn('fsync_path "$temporary"', self.installer)
        self.assertIn('mv -f "$temporary" "$auth"', self.installer)
        self.assertIn('fsync_directory "$auth_dir"', self.installer)
        self.assertNotIn('>>"$auth"', self.installer)

    def test_web_update_binds_runtime_state_before_and_after_publish(self):
        for script in (self.installer, self.updater):
            self.assertIn('capture_runtime_baseline', script)
            self.assertIn('runtime_unchanged', script)
            self.assertIn('uci_digest', script)
            self.assertIn('process_starttime', script)
            self.assertIn('CORE_PID_BEFORE', script)
            self.assertIn('CORE_START_BEFORE', script)
            self.assertIn('ACTIVE_BEFORE_SHA256', script)
            self.assertIn('UCI_BEFORE_SHA256', script)
            self.assertIn('main_before_sha', script)
            self.assertIn('runtime_before_sha', script)
            self.assertIn('state_before_sha', script)
            self.assertIn('MAIN_BEFORE_SHA256', script)
            self.assertIn('RUNTIME_BEFORE_SHA256', script)
            self.assertIn('CUSTOM_STATE_BEFORE_SHA256', script)
            self.assertNotIn("'CONFIG_CHANGED=false'", script)
            self.assertNotIn("'SERVICE_RESTARTED=false'", script)

    def test_router_lifecycle_starttime_parser_chomps_proc_stat_newline(self):
        parser = 'File.binread("/proc/#{ARGV.fetch(0)}/stat",4096).chomp'
        for script in (self.installer, self.updater):
            self.assertIn(parser, script)

    def test_router_lua_syntax_check_uses_openwrt_compatible_environment_path(self):
        for script in (self.installer, self.updater):
            self.assertIn('OPENCLASH_LUA_SOURCE=', script)
            self.assertIn('os.getenv("OPENCLASH_LUA_SOURCE")', script)
            self.assertNotIn('loadfile(ARGV[1])', script)

    def test_web_update_does_not_remove_unrelated_temp_files(self):
        self.assertIn('temporary=', self.updater)
        self.assertNotIn('find "$root" -xdev -type f -name', self.updater)
        self.assertNotIn('rm -f "$agent_source" "$forced_source"', self.updater)

    def test_forced_command_clears_lua_loader_environment(self):
        for name in ("LUA_PATH", "LUA_CPATH", "LUA_INIT", "RUBYOPT", "RUBYLIB", "LD_PRELOAD", "LD_LIBRARY_PATH"):
            self.assertIn(name, self.forced_command)

    def test_console_tunnel_ignores_ambient_ssh_configuration(self):
        for fragment in (
            'ssh -F /dev/null', 'BatchMode=yes', 'IdentitiesOnly=yes',
            'StrictHostKeyChecking=yes', 'UserKnownHostsFile="$known_hosts_file"',
            'GlobalKnownHostsFile=/dev/null', 'ProxyCommand=none', 'ProxyJump=none',
            'PasswordAuthentication=no', 'KbdInteractiveAuthentication=no',
            '-i "$identity_file"', 'syncsvc@192.0.2.20',
        ):
            self.assertIn(fragment, self.tunnel)
        self.assertNotIn('syncsvc-worker', self.tunnel)
        self.assertIn('known_hosts 必须只包含 WORKER 的一条 Ed25519 记录', self.tunnel)
        self.assertIn("stat -f '%u:%Lp'", self.tunnel)
        self.assertNotIn('ls -ln "$file"', self.tunnel)
        self.assertIn('-L 127.0.0.1:18088:127.0.0.1:8088', self.tunnel)
        self.assertNotIn('-L 127.0.0.1:18088:192.0.2.20:8088', self.tunnel)


if __name__ == "__main__":
    unittest.main()
