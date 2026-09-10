"""Offline behavioral tests of the real apply JS + converter/app.js and HTML.

All transport, results and credentials are synthetic. This exercises the shared
Node DOM/async harness, not a browser layout or a production router transaction.
"""
import json
import unittest
import test_converter_frontend as fixture


class ConverterApplyFrontendTests(unittest.TestCase):
    run_js = fixture.ConverterFrontendTests.run_js

    @classmethod
    def setUpClass(cls):
        fixture.ConverterFrontendTests.setUpClass.__func__(cls)
        cls.apply_module = (fixture.ROOT / 'static/converter_apply.js').read_text()
        cls.app += '\n' + cls.apply_module
        cls.app += r'''
const routerPreviewPath = '/api/converter/router-preview', routerApplyPath = '/api/converter/router-apply';
const callsTo = path => requestLog.filter(item => item.path === path);
const applyState = () => $('#converterApplyState').getAttribute('data-state');
const applyText = () => $('#converterApplyState').textContent;
function previewResult(body, noChange = false) {
  return {ok:true, target:body.target, content:'SERVER-CONFIG-MUST-NOT-BE-CONSUMED',
    message:'SERVER-MESSAGE-MUST-NOT-BE-RENDERED', expected_sha256:'b'.repeat(64), sha256:(noChange ? 'b' : 'c').repeat(64),
    groups:['Existing', '<img src=x onerror=synthetic>', '__proto__', ' '], summary:{mode:body.mode,
      nodes_added:noChange ? 0 : 1, groups_added:!noChange && body.mode === 'merge' ? 1 : 0,
      rules_added:!noChange && body.mode === 'merge' ? 2 : 0, group_members_added:!noChange && body.group ? 1 : 0,
      final_rules_ignored:body.mode === 'merge' ? 1 : 0, existing_nodes_preserved:true,
      network_settings_preserved:true, router_changed:false, no_change:noChange}};
}
function appliedResult(extra = {}) {
  return {ok:true, sha256:'d'.repeat(64), state_sha256:'e'.repeat(64), service_restarted:true, runtime_verified:true, ...extra};
}
async function applyFixture() {
  await converterFixture();
  routes.set('/api/converter/execute', body => response(executionResult(body)));
  await $('#executeConverter').click();
  routes.set(routerPreviewPath, body => response(previewResult(body)));
  routes.set(routerApplyPath, () => response(appliedResult()));
  requestLog.length = 0;
}
async function readyApply() {
  await $('#previewConverterApply').click();
  assert.equal(applyState(), 'ready', applyText());
  assert.equal($('#applyConverterResult').disabled, false);
}
async function surgeFixture() {
  await inputValue('converter-surge2clash-content', '[Proxy]\nSynthetic input');
  routes.set('/api/converter/tool', body => response({...executionResult({form:{options:{target:body.operation}}}),
    summary:{source_count:1, asset_count:0, network_executed:false, link_backend_used:false,
      router_changed:false, operation:body.operation}}));
  await $('#converter-surge2clash-run').click();
}
'''

    def test_real_backend_plan_contract_with_or_without_server_content(self):
        baseline = json.dumps({'proxies': [], 'proxy-groups': [
            {'name': 'Existing', 'type': 'select', 'proxies': ['DIRECT']}], 'rules': ['MATCH,DIRECT']})
        incoming = json.dumps({'proxies': [{'name': 'Synthetic', 'type': 'ss',
            'server': '192.0.2.1', 'port': 443, 'cipher': 'aes-128-gcm', 'password': 'synthetic'}],
            'rules': ['DOMAIN,example.test,DIRECT', 'MATCH,DIRECT']})
        cases = []
        for mode in ('nodes', 'merge'):
            for with_content in (True, False):
                data = fixture.server.converter_apply.plan(baseline, incoming, mode=mode)
                data['target'] = 'router_a'
                if not with_content:
                    data.pop('content', None)
                cases.append({'mode': mode, 'result': data})
        self.run_js('const realCases = ' + json.dumps(cases) + ';\n'
                    + 'const realInput = ' + json.dumps(incoming) + ';\n' + r'''
await applyFixture(); await inputValue('converterText', realInput);
for (const item of realCases) {
  await inputValue('converterApplyMode', item.mode, 'change');
  routes.set(routerPreviewPath, () => response(item.result)); await readyApply();
  assert.ok(!$('#converterApplyMount').textContent.includes('password'));
  assert.ok(!$('#converterApplyMount').textContent.includes('192.0.2.1'));
}
''')

    def test_lazy_mount_labels_unique_ids_no_storage_or_copy(self):
        self.run_js(r'''
assert.equal(requestLog.length, 0);
await $('#converterApplyWorkspace').dispatch('toggle');
assert.equal(requestLog.length, 0);
assert.equal($('#previewConverterApply').disabled, true);
assert.equal($('#applyConverterResult').disabled, true);
assert.equal($('#converterApplySource').value, 'main');
assert.equal($('#converterApplyTarget').value, 'router_a');
assert.equal($('#converterApplyMode').value, 'nodes');
const labels = $('#converterApplyMount').querySelectorAll('label').map(el => el.getAttribute('for'));
for (const field of $('#converterApplyMount').querySelectorAll('select')) assert.ok(labels.includes(field.id));
for (const button of $('#converterApplyMount').querySelectorAll('button')) assert.equal(button.type, 'button');
const ids = document.querySelectorAll('[id]').map(el => el.id);
assert.equal(new Set(ids).size, ids.length);
assert.equal($('#converterApplyState').getAttribute('role'), 'status');
assert.equal($('#converterApplyState').getAttribute('aria-live'), 'polite');
''')
        for forbidden in ('innerHTML', 'localStorage', 'sessionStorage', 'indexedDB',
                          'clipboard', 'console.', 'fetch(', 'document.cookie'):
            self.assertNotIn(forbidden, self.apply_module)

    def test_preview_uses_exact_current_text_and_only_renders_safe_summary(self):
        self.run_js(r'''
await applyFixture();
await inputValue('converterText', syntheticText + '# edited\n');
const token = nonce;
routes.set(routerPreviewPath, body => {
  assert.deepEqual(Object.keys(body).sort(), ['content', 'group', 'mode', 'nonce', 'target']);
  assert.equal(body.content, syntheticText + '# edited\n'); assert.equal(body.nonce, token);
  assert.equal(body.target, 'router_a'); assert.equal(body.mode, 'nodes'); assert.equal(body.group, '');
  const result = previewResult(body);
  Object.defineProperty(result, 'content', {get() {throw Error('must not read server content');}});
  return response(result);
});
await readyApply();
assert.equal(callsTo(routerPreviewPath).length, 1); assert.equal(callsTo(routerApplyPath).length, 0);
const html = $('#converterApplyMount').innerHTML;
for (const secret of ['SERVER-CONFIG', 'SERVER-MESSAGE', 'password: synthetic', '192.0.2.1']) assert.ok(!html.includes(secret));
assert.ok($('#converterApplySummary').textContent.includes('新增节点1'));
assert.ok($('#converterApplySummary').textContent.includes('b'.repeat(64)));
assert.ok($('#converterApplySummary').textContent.includes('c'.repeat(64)));
assert.equal($('#converterApplyMount').querySelectorAll('img').length, 0);
assert.equal(callsTo('/api/bootstrap').length, 1); assert.notEqual(nonce, token);
''')

    def test_hash_fallback_matches_node_for_utf8_padding_and_bounded_large_input(self):
        self.run_js(r'''
await applyFixture();
Object.defineProperty(globalThis, 'crypto', {configurable:true, value:undefined});
for (const text of ['x', 'abc', 'a'.repeat(24), 'b'.repeat(55), 'c'.repeat(56), 'd'.repeat(64), '节点🙂\n', 'x'.repeat(1024 * 1024)]) {
  await inputValue('converterText', text); await readyApply();
  const expected = require('node:crypto').createHash('sha256').update(JSON.stringify(['main', 'router_a', 'nodes', '', text])).digest('hex');
  assert.ok($('#converterApplySummary').textContent.includes(expected));
}
''')

    def test_native_hash_is_used_and_rejected_digest_does_not_send_apply(self):
        self.run_js(r'''
await applyFixture(); let hashes = 0;
const subtle = require('node:crypto').webcrypto.subtle;
Object.defineProperty(globalThis, 'crypto', {configurable:true, value:{subtle:{digest:async (...args) => {hashes++; return subtle.digest(...args);}}}});
await readyApply(); assert.equal(hashes, 1);
globalThis.crypto.subtle.digest = async () => {throw Error('SENSITIVE local error');};
await $('#applyConverterResult').click();
assert.equal(callsTo(routerApplyPath).length, 0); assert.equal(operationBusy, false);
assert.equal(applyState(), 'error'); assert.ok(applyText().includes('尚未发送'));
assert.ok(!$('#notice').textContent.includes('SENSITIVE')); assert.ok(!applyText().includes('SENSITIVE'));
''')

    def test_groups_are_lazy_and_target_changes_reset_them(self):
        self.run_js(r'''
await applyFixture(); assert.equal($('#converterApplyGroup').disabled, true);
await readyApply(); const count = requestLog.length;
await inputValue('converterApplyGroup', 'Existing', 'change');
assert.equal(requestLog.length, count); assert.equal(applyState(), 'stale');
assert.equal($('#applyConverterResult').disabled, true); assert.equal($('#converterApplySummary').textContent, '');
await readyApply(); assert.equal(callsTo(routerPreviewPath).at(-1).body.group, 'Existing');
await inputValue('converterApplyTarget', 'router_b', 'change');
assert.equal($('#converterApplyGroup').value, ''); assert.equal($('#converterApplyGroup').querySelectorAll('option').length, 1);
assert.equal($('#converterApplyGroup').disabled, true); assert.equal($('#applyConverterResult').disabled, true);
await readyApply(); assert.equal(callsTo(routerPreviewPath).at(-1).body.target, 'router_b');
await inputValue('converterApplyGroup', '__proto__', 'change'); await readyApply();
assert.equal(callsTo(routerPreviewPath).at(-1).body.group, '__proto__'); assert.equal(({}).polluted, undefined);
''')

    def test_nodes_and_merge_with_real_surge_tool_result_and_manual_edits(self):
        self.run_js(r'''
await applyFixture(); await surgeFixture();
const main = syntheticText + '# main-only\n', surge = syntheticText + '# surge-only edited\n';
await inputValue('converterText', main); await inputValue('converter-surge2clash-result', surge);
await inputValue('converterApplySource', 'surge2clash', 'change');
await inputValue('converterApplyMode', 'merge', 'change');
await inputValue('converterApplyTarget', 'router_b', 'change');
requestLog.length = 0; await readyApply();
assert.equal(callsTo(routerPreviewPath)[0].body.content, surge); assert.equal(callsTo(routerPreviewPath)[0].body.mode, 'merge');
assert.ok($('#converterApplySummary').textContent.includes('忽略的 MATCH / FINAL 规则1'));
await $('#applyConverterResult').click(); assert.equal(applyState(), 'success');
const sent = callsTo(routerApplyPath)[0].body;
assert.equal(sent.content, surge); assert.equal(sent.mode, 'merge'); assert.equal(sent.target, 'router_b');
assert.equal($('#converterText').value, main); assert.equal($('#converter-surge2clash-result').value, surge);
await inputValue('converterApplySource', 'main', 'change'); await readyApply();
assert.equal(callsTo(routerPreviewPath).at(-1).body.content, main);
''')

    def test_every_binding_change_and_change_back_invalidates_permanently(self):
        self.run_js(r'''
await applyFixture(); await surgeFixture();
for (const [id, next, original, event] of [
  ['converterApplySource','surge2clash','main','change'], ['converterApplyTarget','router_b','router_a','change'],
  ['converterApplyMode','merge','nodes','change'], ['converterApplyGroup','Existing','','change'],
  ['converterText',syntheticText+'# changed\n',syntheticText,'input']]) {
  await readyApply(); const count = requestLog.length;
  await inputValue(id, next, event); assert.equal($('#applyConverterResult').disabled, true);
  await inputValue(id, original, event); assert.equal($('#applyConverterResult').disabled, true);
  assert.equal($('#converterApplySummary').textContent, '');
  await $('#applyConverterResult').click(); assert.equal(requestLog.length, count);
}
''')

    def test_programmatic_result_replacement_restore_and_clear_invalidate(self):
        self.run_js(r'''
await applyFixture(); await readyApply();
$('#converterText').value = syntheticText + '# replacement\n'; updateConverterControls();
assert.equal($('#applyConverterResult').disabled, true); assert.equal(applyState(), 'stale');
await readyApply(); await $('#restoreConverterText').click();
assert.equal($('#converterText').value, syntheticText); assert.equal($('#applyConverterResult').disabled, true);
await readyApply(); await $('#clearConverter').click();
assert.equal($('#converterText').value, ''); assert.equal($('#previewConverterApply').disabled, true);
assert.equal($('#applyConverterResult').disabled, true); assert.equal($('#converterApplySummary').textContent, '');
''')

    def test_surge_empty_and_clear_do_not_fallback_to_main_result(self):
        self.run_js(r'''
await applyFixture(); await inputValue('converterApplySource','surge2clash','change');
assert.equal($('#previewConverterApply').disabled, true); await $('#previewConverterApply').click();
assert.equal(requestLog.length, 0);
await surgeFixture(); await readyApply();
await inputValue('converter-surge2clash-result', '');
assert.equal($('#applyConverterResult').disabled, true); assert.equal($('#previewConverterApply').disabled, true);
await $('#converter-surge2clash-restore').click(); await readyApply();
await $('#converter-surge2clash-clear').click();
assert.equal($('#converter-surge2clash-result').value, ''); assert.equal($('#applyConverterResult').disabled, true);
assert.equal($('#converterText').value, syntheticText);
''')

    def test_empty_utf8_control_size_and_json_budget_rejected_before_nonce(self):
        self.run_js(r'''
await applyFixture();
for (const value of ['', ' \n ', 'x\0y', '\ud800', 'x'.repeat(1024*1024+1), '字'.repeat(350000), '\x01'.repeat(400000)]) {
  await inputValue('converterText', value); const count = requestLog.length;
  assert.equal($('#previewConverterApply').disabled, true);
  await $('#previewConverterApply').dispatch('click');
  assert.equal(requestLog.length, count); assert.equal(operationBusy, false); assert.equal($('#applyConverterResult').disabled, true);
}
await inputValue('converterText', syntheticText); await readyApply();
for (const [id, value] of [['converterApplyTarget','router_bad'], ['converterApplyMode','replace'],
  ['converterApplySource','unknown'], ['converterApplyGroup','not-read']]) {
  const original = $('#'+id).value; await inputValue(id, value, 'change'); const count = requestLog.length;
  await $('#previewConverterApply').dispatch('click'); assert.equal(requestLog.length, count);
  await inputValue(id, original, 'change');
}
''')

    def test_preview_mode_does_not_use_stale_schema_feature_flag(self):
        self.run_js(r'''
await applyFixture(); CONVERTER_SCHEMA.execution.router_apply_available = false;
updateConverterControls(); assert.equal($('#previewConverterApply').disabled, false); await readyApply();
fixtureMode = 'preview'; await runOperation('synthetic refresh', () => bootstrap(true, false));
assert.equal($('#previewConverterApply').disabled, true); assert.equal($('#applyConverterResult').disabled, true);
assert.equal($('#converterApplySummary').textContent, '');
const count = requestLog.length; await $('#previewConverterApply').dispatch('click'); assert.equal(requestLog.length, count);
fixtureMode = 'live'; await runOperation('synthetic refresh', () => bootstrap(true, false));
assert.equal($('#previewConverterApply').disabled, false); assert.equal($('#applyConverterResult').disabled, true);
''')

    def test_preview_lock_spans_request_nonce_renewal_and_double_click(self):
        self.run_js(r'''
await applyFixture(); const pending = deferred(), renewed = deferred(), posted = deferred();
routes.set(routerPreviewPath, body => {posted.resolve(); return pending.promise.then(() => response(previewResult(body)));});
const task = $('#previewConverterApply').click(); await posted.promise;
assert.equal(operationBusy, true);
for (const id of ['converterApplySource','converterApplyGroup','converterText','saveChain','readConfig','loadCustom']) assert.equal($('#'+id).disabled, true);
await $('#previewConverterApply').click(); await $('#previewConverterApply').dispatch('click');
assert.equal(callsTo(routerPreviewPath).length, 1);
routes.set('/api/bootstrap', () => renewed.promise); pending.resolve(); await waitTick();
assert.equal(operationBusy, true); assert.equal($('#applyConverterResult').disabled, true);
renewed.resolve(response({ok:true,nonce:'renewed-token',mode:'live'})); await task;
assert.equal(operationBusy, false); assert.equal(nonce, 'renewed-token'); assert.equal(applyState(), 'ready');
''')

    def test_preview_midflight_edits_or_mode_change_discard_response(self):
        self.run_js(r'''
await applyFixture();
for (const change of ['text', 'mode']) {
  const pending = deferred(), posted = deferred();
  routes.set(routerPreviewPath, body => {posted.resolve(); return pending.promise.then(() => response(previewResult(body)));});
  const task = $('#previewConverterApply').click(); await posted.promise;
  if (change === 'text') await inputValue('converterText', syntheticText + '# during request\n');
  else fixtureMode = 'preview';
  pending.resolve(); await task;
  assert.equal(applyState(), 'stale'); assert.equal($('#applyConverterResult').disabled, true);
  assert.equal($('#converterApplySummary').textContent, '');
}
assert.equal(callsTo(routerApplyPath).length, 0);
''')

    def test_repreview_failure_discards_old_proof_and_raw_response(self):
        self.run_js(r'''
await applyFixture(); await readyApply();
routes.set(routerPreviewPath, () => response({ok:false,message:'SENSITIVE-REPLY'}, 502));
await $('#previewConverterApply').click();
assert.equal(applyState(), 'error'); assert.equal($('#applyConverterResult').disabled, true);
assert.equal($('#converterApplySummary').textContent, ''); assert.ok(applyText().includes('未执行写入'));
assert.ok(!applyText().includes('SENSITIVE')); assert.ok(!$('#notice').textContent.includes('SENSITIVE'));
assert.equal(callsTo(routerPreviewPath).length, 2); assert.equal(operationBusy, false);
''')

    def test_untrusted_preview_shape_counters_hashes_and_groups_fail_closed(self):
        self.run_js(r'''
await applyFixture();
const mutations = [r=>{delete r.expected_sha256;}, r=>{r.sha256='X'.repeat(64);}, r=>{r.target='router_b';},
  r=>{r.summary.nodes_added=-1;}, r=>{r.summary.nodes_added=10001;}, r=>{r.summary.nodes_added=1.5;},
  r=>{r.summary.nodes_added='1';}, r=>{r.summary.mode='merge';}, r=>{r.summary.groups_added=1;},
  r=>{r.summary.existing_nodes_preserved=false;}, r=>{r.summary.network_settings_preserved=false;},
  r=>{r.summary.router_changed=true;}, r=>{r.summary.no_change=true;}, r=>{r.summary.group_members_added=1;},
  r=>{r.groups=['Same','Same'];}, r=>{r.groups=[''];}, r=>{r.groups=['bad\0group'];}, r=>{r.groups=['a'.repeat(513)];},
  r=>{r.groups=Array(10001).fill('many');}, r=>{r.summary=[];}, r=>{r.groups=null;}];
for (const mutate of mutations) {
  routes.set(routerPreviewPath, body => {const result=previewResult(body); mutate(result); return response(result);});
  await $('#previewConverterApply').click(); assert.equal(applyState(), 'error');
  assert.equal($('#applyConverterResult').disabled, true); assert.equal($('#converterApplySummary').textContent, '');
}
assert.equal(callsTo(routerApplyPath).length, 0);
''')

    def test_confirm_cancel_preserves_proof_no_post_or_credential_echo(self):
        self.run_js(r'''
await applyFixture(); await readyApply(); let message = '';
window.confirm = text => {message=text; return false;}; const count = requestLog.length;
await $('#applyConverterResult').click();
assert.equal(requestLog.length, count); assert.equal($('#applyConverterResult').disabled, false);
assert.equal(operationBusy, false); assert.equal(applyState(), 'ready');
for (const word of ['router_a','OpenClash','重启','短暂','另一子网']) assert.ok(message.includes(word));
assert.ok(!message.includes('synthetic')); assert.ok(!message.includes('192.0.2.1'));
''')

    def test_confirm_mutation_is_rechecked_and_never_sends(self):
        self.run_js(r'''
await applyFixture(); await readyApply();
window.confirm = () => {$('#converterText').value += '# changed in confirm\n'; return true;};
await $('#applyConverterResult').click();
assert.equal(callsTo(routerApplyPath).length, 0); assert.equal($('#applyConverterResult').disabled, true);
assert.equal(applyState(), 'stale'); assert.ok(applyText().includes('未发送应用'));
''')

    def test_apply_binds_exact_sha_nonce_and_stays_locked_until_renewed(self):
        self.run_js(r'''
await applyFixture(); await readyApply(); const token = nonce, pending=deferred(), renewed=deferred(), posted=deferred();
routes.set(routerApplyPath, body => {
  posted.resolve();
  assert.deepEqual(Object.keys(body).sort(), ['content','expected_sha256','group','mode','nonce','preview_sha256','target']);
  assert.equal(body.expected_sha256, 'b'.repeat(64)); assert.equal(body.preview_sha256, 'c'.repeat(64));
  assert.equal(body.content, $('#converterText').value); assert.equal(body.nonce, token);
  return pending.promise;
});
const task = $('#applyConverterResult').click(); await posted.promise;
assert.equal(operationBusy, true); assert.equal($('#applyConverterResult').disabled, true);
assert.equal($('#converterApplySummary').textContent, ''); assert.equal($('#converterText').disabled, true);
await $('#applyConverterResult').click(); await $('#applyConverterResult').dispatch('click');
assert.equal(callsTo(routerApplyPath).length, 1);
routes.set('/api/bootstrap', () => renewed.promise); pending.resolve(response(appliedResult())); await waitTick();
assert.equal(operationBusy, true); assert.equal($('#readConfig').disabled, true);
renewed.resolve(response({ok:true,nonce:'post-apply-nonce',mode:'live'})); await task;
assert.equal(operationBusy, false); assert.equal(applyState(), 'success'); assert.equal(nonce, 'post-apply-nonce');
assert.equal($('#applyConverterResult').disabled, true); await $('#applyConverterResult').click();
assert.equal(callsTo(routerApplyPath).length, 1);
assert.ok($('#converterApplySummary').textContent.includes('d'.repeat(64)));
''')

    def test_missing_auth_never_posts_and_releases_lock(self):
        self.run_js(r'''
await applyFixture(); nonce = '';
routes.set('/api/bootstrap', () => response({ok:false,message:'SECRET-AUTH'}, 401));
await $('#previewConverterApply').click();
assert.equal(callsTo(routerPreviewPath).length, 0); assert.equal(operationBusy, false);
assert.ok(applyText().includes('尚未发送')); assert.ok(!applyText().includes('SECRET'));
assert.equal(mode, 'unknown'); assert.equal($('#previewConverterApply').disabled, true);
routes.delete('/api/bootstrap'); await $('#refreshStatus').click(); assert.equal(mode, 'live');
await readyApply(); nonce = ''; const count = callsTo(routerApplyPath).length;
routes.set('/api/bootstrap', () => response({ok:false,message:'SECRET-AUTH'}, 401));
await $('#applyConverterResult').click(); assert.equal(callsTo(routerApplyPath).length, count);
assert.equal(operationBusy, false); assert.equal($('#applyConverterResult').disabled, true);
assert.ok(applyText().includes('尚未发送')); assert.ok(!$('#notice').textContent.includes('SECRET'));
''')

    def test_auth_renewal_during_apply_rechecks_changes_before_send(self):
        self.run_js(r'''
await applyFixture(); await readyApply(); nonce = ''; const auth = deferred(), started = deferred();
routes.set('/api/bootstrap', () => {started.resolve(); return auth.promise;});
const task = $('#applyConverterResult').click(); await started.promise;
assert.equal(operationBusy, true); await inputValue('converterApplyTarget','router_b','change');
auth.resolve(response({ok:true,nonce:'fresh-auth',mode:'live'})); await task;
assert.equal(callsTo(routerApplyPath).length, 0); assert.equal(applyState(), 'stale');
assert.equal($('#applyConverterResult').disabled, true); assert.equal(operationBusy, false);
''')

    def test_nonce_409_has_no_automatic_retry_or_false_unwritten_claim(self):
        self.run_js(r'''
await applyFixture(); await readyApply(); const token = nonce;
routes.set(routerApplyPath, () => response({ok:false,message:'SECRET expired nonce'}, 409));
await $('#applyConverterResult').click();
assert.equal(callsTo(routerApplyPath).length, 1); assert.notEqual(nonce, token); assert.equal(operationBusy, false);
assert.equal(applyState(), 'unknown'); assert.ok(applyText().includes('UNKNOWN'));
assert.ok(!applyText().includes('未执行写入')); assert.ok(!applyText().includes('SECRET'));
assert.equal($('#applyConverterResult').disabled, true);
''')

    def test_stale_409_and_validation_failures_clear_proof_with_safe_code(self):
        self.run_js(r'''
await applyFixture();
for (const code of ['STALE_BASELINE','STALE_PREVIEW','CONTENT','CONFLICT','REFERENCE','BASELINE','REQUEST']) {
  await readyApply();
  routes.set(routerApplyPath, () => response({ok:false,code,router_changed:false,message:'SECRET remote failure'},code.startsWith('STALE') ? 409 : 422));
  await $('#applyConverterResult').click();
  assert.equal(applyState(), code.startsWith('STALE') ? 'stale' : 'error'); assert.ok(applyText().includes(code));
  assert.ok(applyText().includes('未执行写入')); assert.ok(!applyText().includes('SECRET'));
  assert.equal($('#applyConverterResult').disabled, true); assert.equal($('#converterApplySummary').textContent, '');
}
assert.equal(callsTo(routerApplyPath).length, 7);
''')

    def test_missing_stale_write_evidence_and_lost_response_are_unknown(self):
        self.run_js(r'''
await applyFixture();
for (const result of [{ok:false,message:'SECRET'}, {ok:false,code:'STALE_BASELINE'},
  {ok:false,code:'STALE_PREVIEW',router_changed:true}]) {
  await readyApply(); routes.set(routerApplyPath, () => response(result,502)); await $('#applyConverterResult').click();
  assert.equal(applyState(), 'unknown'); assert.ok(!applyText().includes('未执行写入'));
}
await readyApply(); const pending = deferred(), posted = deferred();
routes.set(routerApplyPath, () => {posted.resolve(); return pending.promise.then(() => {throw Error('SECRET lost response');});});
const task = $('#applyConverterResult').click(); await posted.promise; pending.resolve(); await task;
assert.equal(applyState(), 'unknown'); assert.equal(operationBusy, false); assert.equal(callsTo(routerApplyPath).length, 4);
assert.equal($('#applyConverterResult').disabled, true); assert.ok(!$('#notice').textContent.includes('SECRET'));
''')

    def test_no_change_is_not_a_restart_or_runtime_verification(self):
        self.run_js(r'''
await applyFixture();
routes.set(routerPreviewPath, body => response(previewResult(body,true)));
routes.set(routerApplyPath, body => response({ok:true,target:body.target,no_change:true,sha256:'b'.repeat(64),message:'misleading success'}));
await readyApply(); assert.ok(applyText().includes('无新增变化'));
await $('#applyConverterResult').click(); assert.equal(applyState(), 'unchanged');
assert.ok(applyText().includes('未执行写入或重启')); assert.ok(applyText().includes('未验证'));
assert.ok(!applyText().includes('misleading')); assert.equal($('#applyConverterResult').disabled, true);
''')

    def test_unrestarted_or_unverified_results_are_not_presented_as_effective(self):
        self.run_js(r'''
await applyFixture();
for (const [restarted,verified,state] of [[true,true,'success'],[false,false,'unverified'],[true,false,'unknown'],[false,true,'unknown']]) {
  await readyApply(); routes.set(routerApplyPath, () => response(appliedResult({service_restarted:restarted,runtime_verified:verified})));
  await $('#applyConverterResult').click(); assert.equal(applyState(), state);
  assert.equal($('#applyConverterResult').disabled, true);
  if (state !== 'success') {assert.ok(!applyText().includes('验证通过')); assert.ok(applyText().includes('不能认定已生效'));}
}
''')

    def test_incomplete_or_contradictory_success_evidence_is_unknown(self):
        self.run_js(r'''
await applyFixture();
const variants = [{ok:true}, appliedResult({sha256:'bad'}), appliedResult({state_sha256:'bad'}),
  appliedResult({service_restarted:'true'}), appliedResult({runtime_verified:undefined}),
  appliedResult({target:'router_b'}), appliedResult({no_change:true}), appliedResult({no_change:'false'})];
for (const value of variants) {
  await readyApply(); routes.set(routerApplyPath, () => response(value)); await $('#applyConverterResult').click();
  assert.equal(applyState(), 'unknown'); assert.equal($('#applyConverterResult').disabled, true);
  assert.equal($('#converterApplySummary').textContent, '');
}
''')

    def test_success_never_refreshes_or_overwrites_editor_custom_chain_drafts(self):
        self.run_js(r'''
await applyFixture(); const editor = '# unrelated unsaved editor\n', result = syntheticText + '# result draft\n';
await inputValue('yamlEditor', editor); await inputValue('converterText', result);
await inputValue('chainServer','unsaved.example.test');
const flags = JSON.stringify(draftFlags()), oldBaseline = editorBaseline;
await readyApply(); requestLog.length = 0;
await $('#applyConverterResult').click();
assert.equal(applyState(), 'success'); assert.equal($('#yamlEditor').value, editor); assert.equal(editorBaseline, oldBaseline);
assert.equal($('#converterText').value, result); assert.equal($('#chainServer').value, 'unsaved.example.test');
assert.equal(JSON.stringify(draftFlags()), flags); assert.equal($('#applyConverterResult').disabled, true);
assert.deepEqual(requestLog.map(item => item.path), [routerApplyPath, '/api/bootstrap']);
''')

    def test_post_apply_nonce_refresh_failure_retains_actual_evidence_without_retry(self):
        self.run_js(r'''
await applyFixture(); await readyApply();
routes.set('/api/bootstrap', () => response({ok:false,message:'SECRET renewal failed'},401));
await $('#applyConverterResult').click();
assert.equal(applyState(), 'success'); assert.equal(nonce, ''); assert.equal(operationBusy, false);
assert.equal($('#applyConverterResult').disabled, true); assert.equal(callsTo(routerApplyPath).length, 1);
assert.ok(!$('#notice').textContent.includes('SECRET')); assert.ok(!applyText().includes('SECRET'));
''')


if __name__ == '__main__':
    unittest.main()
