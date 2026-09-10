"""Bounded frontend freshness/navigation regressions with synthetic-only I/O.

Reuse the real-HTML/Node harness. These are not production or visual acceptance.
"""
import unittest

import test_chain_frontend as chain_fixture
import test_converter_apply_frontend as apply_fixture
import test_converter_services_frontend as service_fixture


class FrontendStateLifecycleTests(unittest.TestCase):
    run_js = chain_fixture.ChainFrontendTests.run_js

    @classmethod
    def setUpClass(cls):
        chain_fixture.ChainFrontendTests.setUpClass.__func__(cls)
        cls.app += r'''
const goodTarget = () => response({ok:true,targets:[{id:'router_a',name:'Synthetic',
  address:'192.0.2.1',active:'current.yaml',state:'OK'}]});
const chainPass = () => response({ok:true,node:'Node A',configuration:'PASS',runtime:'PASS',
  upstream:'REACHABLE',chain:'REACHABLE',verdict:'PASS'});
const customPass = () => response({ok:true,rules:[],fake_ip_filter:[],summary:{rules:0,fake_ip_filter:0}});
'''

    def test_navigation_remains_available_while_all_mutations_stay_locked(self):
        self.run_js(r'''
const pending = deferred(); routes.set('/api/chain/read', () => pending.promise);
const running = $('#loadChain').click();
for (const nav of $$('.nav-item')) assert.equal(nav.disabled, false);
await $('[data-panel="editor"]').click();
assert.equal($('#editor').classList.contains('active'), true);
assert.equal($('#readConfig').disabled, true);
assert.equal($('#chainTarget').disabled, true);
assert.equal($('#refreshStatus').disabled, true);
assert.equal($('.panels').getAttribute('aria-busy'), 'true');
pending.resolve(response(fixtureRead())); await running;
assert.equal($('.panels').getAttribute('aria-busy'), 'false');
assert.equal($('#readConfig').disabled, false);
assert.equal($('#saveConfig').disabled, true);
assert.equal(requestLog.filter(r => r.path === '/api/chain/read').length, 1);
''')

    def test_new_status_failure_cannot_be_overwritten_by_old_success(self):
        self.run_js(r'''
const old = deferred(); routes.set('/api/status', () => old.promise);
const first = refresh(true);
routes.set('/api/status', () => {throw new Error('new status failure');});
assert.equal(await refresh(), false);
old.resolve(goodTarget()); assert.equal(await first, false);
assert.ok($('#targetGrid').textContent.includes('UNKNOWN'));
assert.ok(!$('#targetGrid').textContent.includes('current.yaml'));
assert.ok($('#notice').textContent.includes('new status failure'));
''')

    def test_old_status_failure_does_not_erase_new_success_or_notice(self):
        self.run_js(r'''
const old = deferred(); routes.set('/api/status', () => old.promise);
const first = refresh();
routes.set('/api/status', goodTarget); assert.equal(await refresh(), true);
notice('new operation receipt');
old.resolve(response({ok:false,message:'old failure'},503)); await first;
assert.ok($('#targetGrid').textContent.includes('current.yaml'));
assert.equal($('#notice').textContent, 'new operation receipt');
''')

    def test_connection_failure_marks_unknown_and_invalidates_pending_status(self):
        self.run_js(r'''
assert.equal(mode, 'live');
const pending = deferred(); routes.set('/api/status', () => pending.promise);
const old = refresh(true);
routes.set('/api/bootstrap', () => {throw new Error('unavailable');});
assert.equal(await bootstrap(true, false), false);
assert.equal(mode, 'unknown'); assert.equal(nonce, '');
assert.equal($('#chainPreview').classList.contains('hidden'), false);
assert.ok($('#chainPreview').textContent.includes('UNKNOWN'));
pending.resolve(goodTarget()); await old;
assert.ok($('#targetGrid').textContent.includes('UNKNOWN'));
''')

    def test_chain_failed_reread_discards_old_test_proof_but_keeps_draft(self):
        self.run_js(r'''
await loadFixture(); routes.set('/api/chain/test', chainPass); await $('#testChain').click();
assert.ok($('#chainTestResult').textContent.includes('PASS'));
await inputValue('chainServer', 'draft.example.test');
routes.set('/api/chain/read', () => {throw new Error('read unavailable');});
await $('#loadChain').click();
assert.equal(chainReady(), false); assert.equal($('#testChain').disabled, true);
assert.equal($('#chainServer').value, 'draft.example.test');
assert.ok(!$('#chainTestResult').textContent.includes('PASS'));
assert.ok($('#chainTestResult').textContent.includes('UNKNOWN'));
''')

    def test_other_view_write_invalidates_chain_test_proof(self):
        self.run_js(r'''
await loadFixture(); routes.set('/api/chain/test', chainPass); await $('#testChain').click();
invalidateViews(['router_b']); assert.equal(chainReady(), true);
assert.ok($('#chainTestResult').textContent.includes('PASS'));
invalidateViews(['router_a']); assert.equal(chainReady(), false);
assert.ok(!$('#chainTestResult').textContent.includes('PASS'));
assert.ok($('#chainTestResult').textContent.includes('UNKNOWN'));
''')

    def test_pending_custom_validation_cannot_revive_invalidated_binding(self):
        self.run_js(r'''
customStateHash = {router_a:'a'.repeat(64), router_b:'b'.repeat(64)};
customConfigHash = {...customStateHash};
const pending = deferred(); routes.set('/api/custom/validate', () => pending.promise);
const checked = validateCustom(); invalidateViews(['router_a']);
const message = $('#customValidation').textContent;
pending.resolve(customPass()); await checked;
assert.equal(customIsValid, false); assert.equal($('#saveCustom').disabled, true);
assert.equal($('#customValidation').textContent, message);
assert.equal(requestLog.find(r => r.path === '/api/custom/validate').signal.aborted, true);
''')

    def test_failed_custom_read_cancels_old_validation_and_leaves_visible_failure(self):
        self.run_js(r'''
const pending = deferred(); routes.set('/api/custom/validate', () => pending.promise);
const checked = validateCustom();
routes.set('/api/custom/read', () => {throw new Error('custom read failure');});
await $('#loadCustom').click();
const message = $('#customValidation').textContent;
assert.ok(message.includes('重新读取'));
pending.resolve(customPass()); await checked;
assert.equal(customIsValid, false); assert.equal($('#customValidation').textContent, message);
''')

    def test_route_results_expire_when_query_or_configuration_changes(self):
        self.run_js(r'''
routes.set('/api/route-check', () => response({ok:true,results:{router_a:{mode:'DIRECT',
  certainty:'EXACT',policy:'DIRECT',reachability:'REACHABLE'}}}));
await inputValue('routeValue','first.example.test'); await $('#checkRoute').click();
assert.ok($('#routeResult').textContent.includes('DIRECT'));
await inputValue('routeValue','second.example.test');
assert.equal($('#routeResult').textContent, '');
await $('#checkRoute').click(); invalidateViews(['router_a']);
assert.equal($('#routeResult').textContent, '');
''')

    def test_auth_refresh_failure_expires_evidence_without_erasing_drafts(self):
        self.run_js(r'''
await loadFixture(); routes.set('/api/chain/test', chainPass); await $('#testChain').click();
await inputValue('chainServer', 'draft.example.test');
currentTarget = 'router_a'; currentName = mainConfigName; currentHash = 'a'.repeat(64);
$('#yamlEditor').value = '# local draft'; yamlIsValid = true;
customStateHash = {router_a:'a'.repeat(64),router_b:'b'.repeat(64)};
customConfigHash = {...customStateHash};
routes.set('/api/bootstrap', () => response({ok:false,message:'synthetic auth expired'},401));
await $('#refreshStatus').click();
assert.equal(mode, 'unknown'); assert.equal(nonce, '');
assert.equal(chainReady(), false); assert.equal(currentHash, '');
assert.deepEqual(customStateHash, {}); assert.deepEqual(customConfigHash, {});
assert.ok(!$('#chainTestResult').textContent.includes('PASS'));
assert.ok($('#chainTestResult').textContent.includes('UNKNOWN'));
assert.equal($('#chainServer').value, 'draft.example.test');
assert.equal($('#yamlEditor').value, '# local draft');
routes.delete('/api/bootstrap'); routes.set('/api/status', goodTarget);
await $('#refreshStatus').click(); assert.equal(mode, 'live');
assert.ok($('#targetGrid').textContent.includes('current.yaml'));
assert.equal(chainReady(), false); assert.equal($('#testChain').disabled, true);
assert.equal($('#chainServer').value, 'draft.example.test');
''')

    def test_chain_test_reply_cannot_restore_pass_after_auth_renewal_failure(self):
        self.run_js(r'''
await loadFixture(); routes.set('/api/chain/test', chainPass);
routes.set('/api/bootstrap', () => response({ok:false,message:'synthetic auth expired'},401));
await $('#testChain').click();
assert.equal(mode, 'unknown'); assert.equal(chainReady(), false);
assert.ok($('#chainTestResult').textContent.includes('UNKNOWN'));
assert.ok(!$('#chainTestResult').textContent.includes('PASS'));
assert.equal(requestLog.filter(r => r.path === '/api/chain/test').length, 1);
''')

    def test_chain_read_auth_renewal_failure_preserves_draft_without_rebinding(self):
        self.run_js(r'''
await loadFixture(); await inputValue('chainServer', 'draft.example.test');
routes.set('/api/bootstrap', () => response({ok:false,message:'synthetic auth expired'},401));
await $('#loadChain').click();
assert.equal(mode, 'unknown'); assert.equal(chainReady(), false);
assert.equal($('#chainServer').value, 'draft.example.test');
assert.ok($('#chainReadState').textContent.includes('失效'));
''')

    def test_editor_read_auth_renewal_failure_preserves_draft_without_rebinding(self):
        self.run_js(r'''
await inputValue('yamlEditor', '# local draft');
routes.set('/api/read', () => response({ok:true,sha256:'a'.repeat(64),content:'# server read'}));
routes.set('/api/bootstrap', () => response({ok:false,message:'synthetic auth expired'},401));
await $('#readConfig').click();
assert.equal(mode, 'unknown'); assert.equal(currentHash, '');
assert.equal($('#yamlEditor').value, '# local draft');
assert.equal($('#saveConfig').disabled, true);
''')

    def test_custom_read_auth_renewal_failure_preserves_draft_without_rebinding(self):
        self.run_js(r'''
addRule({type:'DOMAIN',value:'draft.example.test',policy:'DIRECT'});
const before = JSON.stringify(collectCustom());
const hashes = {router_a:'a'.repeat(64),router_b:'b'.repeat(64)};
routes.set('/api/custom/read', () => response({ok:true,state_sha256:hashes,config_sha256:hashes,
  supplemental_rules:[],supplemental_fake_ip_filter:[],rules:[],fake_ip_filter:[],
  unowned_rule_matcher_overrides:[],groups:['DIRECT']}));
routes.set('/api/bootstrap', () => response({ok:false,message:'synthetic auth expired'},401));
await $('#loadCustom').click();
assert.equal(mode, 'unknown'); assert.deepEqual(customStateHash, {});
assert.equal(JSON.stringify(collectCustom()), before);
assert.equal($('#saveCustom').disabled, true);
''')

    def test_route_reply_after_auth_renewal_failure_is_not_current_evidence(self):
        self.run_js(r'''
routes.set('/api/route-check', () => response({ok:true,results:{router_a:{mode:'DIRECT',
  certainty:'EXACT',policy:'DIRECT',reachability:'REACHABLE'}}}));
routes.set('/api/bootstrap', () => response({ok:false,message:'synthetic auth expired'},401));
await inputValue('routeValue','fixture.example.test'); await $('#checkRoute').click();
assert.equal(mode, 'unknown'); assert.equal($('#routeResult').textContent, '');
assert.ok($('#notice').textContent.includes('UNKNOWN'));
''')

    def test_status_regions_and_navigation_have_accessible_associations(self):
        self.run_js(r'''
assert.equal($('[data-panel="updates"]').getAttribute('aria-current'), 'page');
for (const nav of $$('.nav-item')) assert.equal(nav.getAttribute('aria-controls'), nav.dataset.panel);
for (const id of ['customValidation','validationState']) {
  assert.equal($('#'+id).getAttribute('role'), 'status');
  assert.equal($('#'+id).getAttribute('aria-live'), 'polite');
}
assert.equal($('#chainKeepPassword').getAttribute('aria-describedby'), 'chainKeepHint');
''')


class FrontendConverterLifecycleTests(unittest.TestCase):
    run_js = apply_fixture.ConverterApplyFrontendTests.run_js

    @classmethod
    def setUpClass(cls):
        apply_fixture.ConverterApplyFrontendTests.setUpClass.__func__(cls)
        cls.app += r'''
async function boundViews() {
  await loadFixture();
  currentTarget = 'router_a'; currentName = mainConfigName; currentHash = 'a'.repeat(64);
  $('#fileName').value = mainConfigName; $('#yamlEditor').value = '# unsaved YAML';
  yamlIsValid = true; updateEditorSaveState();
  customStateHash = {router_a:'a'.repeat(64),router_b:'b'.repeat(64)};
  customConfigHash = {...customStateHash};
  await inputValue('chainServer','unsaved.example.test');
}
function assertExpiredViews() {
  assert.equal(currentHash, ''); assert.equal(chainReady(), false);
  assert.deepEqual(customStateHash, {}); assert.deepEqual(customConfigHash, {});
  assert.equal($('#yamlEditor').value, '# unsaved YAML');
  assert.equal($('#chainServer').value, 'unsaved.example.test');
  assert.ok($('#targetGrid').textContent.includes('UNKNOWN'));
}
'''

    def test_router_apply_expires_related_view_bindings_without_loading_drafts(self):
        self.run_js(r'''
await boundViews(); await applyFixture(); await readyApply(); requestLog.length = 0;
await $('#applyConverterResult').click(); assert.equal(applyState(), 'success');
assertExpiredViews();
assert.deepEqual(requestLog.map(r => r.path), [routerApplyPath, '/api/bootstrap']);
''')

    def test_uncertain_router_apply_also_expires_related_bindings_without_retry(self):
        self.run_js(r'''
await boundViews(); await applyFixture(); await readyApply();
routes.set(routerApplyPath, () => {throw new Error('lost reply');});
await $('#applyConverterResult').click(); assert.equal(applyState(), 'unknown');
assertExpiredViews(); assert.equal(callsTo(routerApplyPath).length, 1);
''')

    def test_cancelled_apply_preserves_existing_view_bindings(self):
        self.run_js(r'''
await boundViews(); await applyFixture(); await readyApply(); confirmation = false;
await $('#applyConverterResult').click();
assert.equal(currentHash, 'a'.repeat(64)); assert.equal(chainReady(), true);
assert.equal(callsTo(routerApplyPath).length, 0);
''')

    def test_other_target_apply_keeps_unrelated_editor_binding(self):
        self.run_js(r'''
await boundViews(); await applyFixture(); await readyApply();
currentTarget = 'router_b'; $('#editorTarget').value = 'router_b';
await $('#applyConverterResult').click();
assert.equal(currentHash, 'a'.repeat(64)); assert.equal(editorBindingValid(), true);
''')

    def test_other_view_mutation_expires_matching_converter_preview(self):
        self.run_js(r'''
await applyFixture(); await readyApply();
routes.set('/api/rollback', () => response({ok:true,message:'synthetic rollback'}));
await inputValue('rollbackPhrase', '确认回滚主配置'); await $('#rollbackButton').click();
assert.equal($('#applyConverterResult').disabled, true); assert.equal(applyState(), 'stale');
assert.equal($('#converterApplySummary').textContent, '');
assert.equal(callsTo(routerApplyPath).length, 0);
''')

    def test_unrelated_target_mutation_keeps_converter_preview(self):
        self.run_js(r'''
await applyFixture(); await readyApply(); invalidateViews(['router_b']);
updateConverterControls(); assert.equal($('#applyConverterResult').disabled, false);
assert.equal(applyState(), 'ready');
''')

    def test_connection_failure_expires_preview_without_erasing_conversion(self):
        self.run_js(r'''
await applyFixture(); await readyApply(); const content = $('#converterText').value;
routes.set('/api/bootstrap', () => {throw new Error('offline');});
await $('#refreshStatus').click();
assert.equal($('#applyConverterResult').disabled, true); assert.equal(mode, 'unknown');
assert.equal($('#converterText').value, content); assert.equal(callsTo(routerApplyPath).length, 0);
''')

    def test_failed_link_request_has_explicit_failure_state_without_stale_result(self):
        self.run_js(r'''
await converterFixture(); routes.set('/api/converter/link', validLink);
await $('#converterForm').dispatch('submit'); assert.ok(converterResult);
routes.set('/api/converter/link', () => response({ok:false,message:'synthetic failed'},503));
await $('#converterForm').dispatch('submit');
assert.equal(converterResult, ''); assert.equal($('#converterOutput').value, '');
assert.equal($('#copyConverter').disabled, true);
assert.equal($('#converterState').classList.contains('bad'), true);
assert.ok($('#converterState').textContent.includes('未成功'));
''')


class FrontendServiceLifecycleTests(unittest.TestCase):
    run_js = service_fixture.ServicesFrontendTests.run_js

    @classmethod
    def setUpClass(cls):
        service_fixture.ServicesFrontendTests.setUpClass.__func__(cls)
        cls.app += r'''
async function readServiceFile() {
  await serviceFixture('gist_get'); await inputValue('converterService-id', 'a'.repeat(32));
  await confirmService(); routes.set(servicePath, serviceOK); await service('send').click();
  assert.equal(service('importConfig').disabled, false);
}
'''

    def test_service_input_change_keeps_reference_but_disables_stale_import(self):
        self.run_js(r'''
await readServiceFile(); await inputValue('converterService-id', 'b'.repeat(32));
assert.equal(service('result').value, '[custom]\n');
assert.equal(service('copy').disabled, false);
assert.equal(service('importConfig').disabled, true);
await service('importConfig').click(); assert.equal($('#converterConfigContent').value, '');
assert.equal(callsToService().length, 1);
''')

    def test_failed_read_cannot_reimport_previous_file(self):
        self.run_js(r'''
await readServiceFile(); await inputValue('converterService-token','synthetic_second_token');
await confirmService(); routes.set(servicePath, () => {throw new Error('unavailable');});
await service('send').click();
assert.equal(service('result').value, '[custom]\n');
assert.equal(service('importConfig').disabled, true);
assert.equal(service('token').value, ''); assert.equal(callsToService().length, 2);
''')

    def test_malformed_read_response_is_not_partially_committed(self):
        self.run_js(r'''
await readServiceFile(); await inputValue('converterService-token','synthetic_second_token');
await confirmService();
routes.set(servicePath, () => response({ok:true,action:'gist_get',router_changed:false,
  content:'untrusted replacement',gist:{id:'a'.repeat(32),public:false,filenames:42}}));
await service('send').click();
assert.equal(service('result').value, '[custom]\n');
assert.equal(service('importConfig').disabled, true);
assert.equal(service('state').classList.contains('bad'), true);
assert.equal(service('token').value, '');
''')

    def test_missing_read_content_is_not_reported_as_success(self):
        self.run_js(r'''
await readServiceFile(); await inputValue('converterService-token','synthetic_second_token');
await confirmService(); routes.set(servicePath, () => response({ok:true,action:'gist_get',router_changed:false,
  gist:{id:'a'.repeat(32),public:false,filenames:['config.ini']}}));
await service('send').click(); assert.equal(service('state').classList.contains('bad'), true);
assert.equal(service('result').value, '[custom]\n'); assert.equal(service('importConfig').disabled, true);
''')

    def test_reconfirm_alone_does_not_invalidate_successful_file_and_clear_resets_it(self):
        self.run_js(r'''
await readServiceFile(); await confirmService(); assert.equal(service('importConfig').disabled, false);
await service('clear').click(); assert.equal(service('result').value, '');
assert.equal(service('importConfig').disabled, true); assert.equal(callsToService().length, 1);
''')
