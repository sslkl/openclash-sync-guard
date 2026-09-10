"""Execute both JS modules against the shared real-HTML DOM fixture."""
import json
import os
import shutil
import unittest
import test_chain_frontend as chain_fixture
from test_chain_frontend import PageParser, ROOT
from test_server import server


class ConverterFrontendTests(unittest.TestCase):
    run_js = chain_fixture.ChainFrontendTests.run_js

    @classmethod
    def setUpClass(cls):
        cls.html = (ROOT/'static/index.html').read_text()
        cls.page = PageParser(cls.html)
        cls.node = os.environ.get('OPENCLASH_TEST_NODE') or shutil.which('node')
        cls.module = (ROOT/'static/converter.js').read_text()
        cls.app = (ROOT/'static/app.js').read_text()+'\n'+cls.module
        cls.app += '\nconst CONVERTER_SCHEMA = '+json.dumps(server.converter.capabilities(), ensure_ascii=False)+';'
        cls.app += r'''
CONVERTER_SCHEMA.execution.bridge_available = true;
routes.set('/api/converter/options', () => response(CONVERTER_SCHEMA));
const exampleSource = 'https://sub.example.test/a?token=synthetic';
const syntheticText = 'proxies:\n  - {name: Synthetic, type: ss, server: 192.0.2.1, port: 443, cipher: aes-128-gcm, password: synthetic}\n';
function syntheticFile(name, content) {const bytes = new TextEncoder().encode(content); return {name, size: bytes.length, arrayBuffer: async () => bytes.buffer};}
function executionResult(body) {return {ok:true, content:syntheticText, bytes:converterBytes(syntheticText), sha256:'a'.repeat(64), target:body.form.options.target,
  elapsed_ms:410, engine:CONVERTER_SCHEMA.execution.engine, isolated:true, network:'none', router_changed:false, cleanup_confirmed:true,
  summary:{source_count:1,asset_count:0,network_executed:false,link_backend_used:false,router_changed:false}};}
async function converterFixture() {await $('#loadConverter').click(); await inputValue('converterSources',exampleSource);}
function validLink(body) {const query=new URLSearchParams({target:body.form.options.target,url:body.form.sources,...(body.form.parameters||{})}); return response({ok:true,link:CONVERTER_SCHEMA.backend+'?'+query,summary:{source_count:1,network_executed:false,router_changed:false,warnings:[]}});}
'''

    def test_load_is_lazy_defaults_are_safe_and_draft_is_clean(self):
        self.run_js(r'''
assert.equal(requestLog.length,0);
assert.equal(converterSchema,null);
await $('#loadConverter').click();
assert.equal(converterForm().profile,'router_a');
assert.equal(converterForm().options.scv,false);
assert.equal(converterForm().options.tfo,false);
assert.equal(converterDirty(),false);
assert.equal($('#converterParameters').value,'{}'); assert.equal($('#converterParameters').disabled,false);
assert.equal(Object.hasOwn(converterForm(),'parameters'),false);
assert.equal($('#generateConverter').disabled,true);
assert.equal($('#loadConverter').disabled,true);
assert.equal(converterOptionFields.size,Object.keys(CONVERTER_SCHEMA.booleans).length+Object.keys(CONVERTER_SCHEMA.texts).length+2);
''')

    def test_link_generation_under_global_lock_and_source_changes_invalidate(self):
        self.run_js(r'''
await converterFixture();
const pending=deferred(); routes.set('/api/converter/link', body=>{assert.equal(body.nonce,'token-1');return pending.promise;});
const task=$('#converterForm').dispatch('submit');
assert.equal(operationBusy,true); assert.equal($('#saveChain').disabled,true); assert.equal($('#converterSources').disabled,true);
assert.equal($('#converterParameters').disabled,true);
pending.resolve(validLink({form:converterForm()})); await task;
assert.equal(operationBusy,false); assert.equal($('#copyConverter').disabled,false); assert.equal($('#installConverter').disabled,false);
assert.ok(converterResult); assert.equal(nonce,'token-2');
await inputValue('converterSources',exampleSource+'2');
assert.equal(converterResult,''); assert.equal($('#copyConverter').disabled,true); assert.equal($('#converterOutput').value,'');
assert.equal(draftFlags().converter,true);
''')

    def test_option_tristate_and_profile_changes(self):
        self.run_js(r'''
await converterFixture();
const udp=converterOptionFields.get('udp').control;
assert.equal(udp.value,'true'); udp.value='false'; await udp.dispatch('change');
assert.equal(converterForm().options.udp,false); assert.equal(converterForm().profile,'manual');
udp.value=''; await udp.dispatch('change'); assert.equal(Object.hasOwn(converterForm().options,'udp'),false);
confirmation=false; await inputValue('converterProfile','router_b','change'); assert.equal(converterForm().profile,'manual');
confirmation=true; await inputValue('converterProfile','router_b','change'); assert.equal(converterForm().options.udp,true); assert.equal(converterForm().sources,exampleSource);
''')

    def test_import_preserves_values_no_network_and_clear(self):
        self.run_js(r'''
await converterFixture();
routes.set('/api/converter/parse',()=>response({ok:true,form:{sources:[exampleSource],backend:CONVERTER_SCHEMA.backend,profile:'manual',options:{target:'surge',ver:5,udp:false,include:'JP|HK'}}}));
await inputValue('converterImport','http://example.test/sub?url=synthetic');
confirmation=false; await $('#parseConverter').click(); assert.equal(requestLog.filter(r=>r.path==='/api/converter/parse').length,0);
confirmation=true; await $('#parseConverter').click();
assert.equal(converterForm().options.ver,5); assert.equal(converterForm().options.udp,false); assert.equal(converterForm().options.include,'JP|HK');
assert.equal($('#converterImport').value,'');
await $('#clearConverter').click(); assert.equal(converterForm().sources,''); assert.equal(converterDirty(),false); assert.equal(converterResult,'');
assert.ok(requestLog.every(r=>r.path.startsWith('/api/')));
''')

    def test_failures_do_not_leave_result_or_stuck_controls(self):
        self.run_js(r'''
await converterFixture(); routes.set('/api/converter/link',validLink);
await $('#converterForm').dispatch('submit'); assert.ok(converterResult);
routes.set('/api/converter/link',()=>response({ok:false,message:'请求失败'},422));
await $('#converterForm').dispatch('submit'); assert.equal(converterResult,''); assert.equal(operationBusy,false); assert.equal($('#converterSources').disabled,false);
assert.equal($('#copyConverter').disabled,true);
''')

    def test_link_response_cannot_replace_backend_or_launch_non_clash(self):
        self.run_js(r'''
await converterFixture();
routes.set('/api/converter/link',()=>response({ok:true,link:'https://evil.example/sub?target=clash',summary:{source_count:1,network_executed:false,router_changed:false}}));
await $('#converterForm').dispatch('submit'); assert.equal(converterResult,'');
await inputValue('converterTarget','quanx','change'); routes.set('/api/converter/link',validLink);
await $('#converterForm').dispatch('submit'); assert.ok(converterResult); assert.equal($('#installConverter').disabled,true);
''')

    def test_upload_and_paste_are_not_sent_until_execute_and_cannot_be_omitted_from_link(self):
        self.run_js(r'''
await $('#loadConverter').click(); requestLog.length=0;
$('#converterUpload').files=[syntheticFile('<img src=x>.yaml', syntheticText)];
await $('#converterUpload').dispatch('change');
assert.equal(converterUploads.length,1); assert.equal(converterDirty(),true);
assert.equal(requestLog.length,0); assert.equal($('#converterFiles').querySelectorAll('img').length,0);
assert.equal($('#executeConverter').disabled,false); assert.equal($('#generateConverter').disabled,true);
await $('#converterForm').dispatch('submit'); assert.equal(requestLog.length,0);
await inputValue('converterPaste','ss://c3ludGhldGlj@192.0.2.9:443#extra');
routes.set('/api/converter/execute',body=>{assert.equal(body.uploads.length,2);assert.equal(body.uploads[0],syntheticText);assert.equal(body.form.sources,'');return response(executionResult(body));});
await $('#executeConverter').click();
assert.equal(converterExport.current,true); assert.equal($('#converterText').value,syntheticText);
assert.equal($('#downloadConverter').disabled,false); assert.equal($('#copyConverterText').disabled,false);
assert.equal(converterResult,''); assert.ok(requestLog.every(item=>item.path.startsWith('/api/')));
''')

    def test_execute_uses_global_lock_does_not_retry_or_accept_missing_cleanup(self):
        self.run_js(r'''
await converterFixture(); const pending=deferred();
routes.set('/api/converter/execute',body=>{assert.equal(body.nonce,'token-1');return pending.promise;});
const task=$('#executeConverter').click(); await waitTick();
assert.equal(operationBusy,true); assert.equal($('#converterUpload').disabled,true); assert.equal($('#saveChain').disabled,true);
let result=executionResult({form:converterForm()}); result.cleanup_confirmed=false;
pending.resolve(response(result)); await task;
assert.equal(converterExport,null); assert.equal(operationBusy,false); assert.equal($('#executeConverter').disabled,false);
assert.equal(requestLog.filter(item=>item.path==='/api/converter/execute').length,1);
assert.ok($('#converterState').textContent.includes('未成功'));
for (const mutation of [{target:'surge'}, {network:'bridge'}, {bytes:1}, {router_changed:true}, {unexpected:'secret'}, {elapsed_ms:60001}]) {
  routes.set('/api/converter/execute',body=>response({...executionResult(body),...mutation}));
  await $('#executeConverter').click(); assert.equal(converterExport,null);
}
''')

    def test_manual_edits_survive_parameter_changes_and_failed_reconversion(self):
        self.run_js(r'''
await converterFixture(); routes.set('/api/converter/execute',body=>response(executionResult(body)));
await $('#executeConverter').click(); await inputValue('converterText',syntheticText+'# manual\n');
assert.equal($('#restoreConverterText').disabled,false); assert.ok($('#converterExportState').textContent.includes('已手动修改'));
await inputValue('converterSources',exampleSource+'2');
assert.equal(converterExport.current,false); assert.ok($('#converterText').value.includes('# manual'));
confirmation=false; const count=requestLog.length; await $('#executeConverter').click(); assert.equal(requestLog.length,count);
confirmation=true; routes.set('/api/converter/execute',()=>response({ok:false,message:'synthetic failure'},502));
await $('#executeConverter').click(); assert.ok($('#converterText').value.includes('# manual')); assert.equal(converterExport.current,false);
await $('#restoreConverterText').click(); assert.equal($('#converterText').value,syntheticText);
assert.equal(converterExport.current,false); assert.equal($('#restoreConverterText').disabled,true);
await $('#clearConverter').click(); assert.equal(converterExport,null); assert.equal($('#converterText').value,'');
assert.equal(converterDirty(),false); assert.equal($('#downloadConverter').disabled,true);
''')

    def test_files_utf8_budgets_and_config_conflicts_fail_before_network(self):
        self.run_js(r'''
await converterFixture(); requestLog.length=0;
$('#converterUpload').files=[{name:'invalid.txt',size:1,arrayBuffer:async()=>new Uint8Array([255]).buffer}];
await $('#converterUpload').dispatch('change'); assert.equal(converterUploads.length,0); assert.equal(operationBusy,false);
let opened=false;
$('#converterUpload').files=[{name:'huge.txt',size:1048577,arrayBuffer:async()=>{opened=true;throw Error('no');}}];
await $('#converterUpload').dispatch('change'); assert.equal(opened,false);
$('#converterConfigUpload').files=[syntheticFile('custom.ini','[custom]\n')];
await $('#converterConfigUpload').dispatch('change'); assert.equal($('#converterConfigContent').value,'[custom]\n');
await inputValue('converterConfig','https://example.test/custom.ini');
await $('#executeConverter').click(); assert.equal(requestLog.length,0); assert.equal(operationBusy,false);
assert.equal($('#generateConverter').disabled,true);
await $('#clearConverter').click(); assert.equal(converterHasLocal(),false); assert.equal($('#converterConfigContent').value,'');
''')

    def test_preview_auto_target_and_download_names_are_safe(self):
        self.run_js(r'''
CONVERTER_SCHEMA.execution.bridge_available=false;
await converterFixture(); assert.equal($('#executeConverter').disabled,true); assert.equal($('#generateConverter').disabled,false);
converterSchema.execution.bridge_available=true; updateConverterControls(); assert.equal($('#executeConverter').disabled,false);
await inputValue('converterTarget','auto','change'); assert.equal($('#executeConverter').disabled,true);
await inputValue('converterTarget','clash','change'); routes.set('/api/converter/execute',body=>response(executionResult(body)));
await $('#executeConverter').click();
const filename=converterOptionFields.get('filename').control; filename.value='../../.evil.html';
assert.equal(converterFilename(),'evil.yaml'); assert.ok(!converterFilename().includes('/'));
let blobs=[], revoked=[]; URL.createObjectURL=blob=>{blobs.push(blob);return 'blob:synthetic';}; URL.revokeObjectURL=url=>revoked.push(url);
await $('#downloadConverter').click(); assert.equal(blobs.length,1); assert.equal(await blobs[0].text(),syntheticText);
for (const callback of timers.values()) callback(); assert.deepEqual(revoked,['blob:synthetic']);
''')

    def test_script_inputs_are_local_and_use_explicit_script_contract(self):
        self.run_js(r'''
await converterFixture(); requestLog.length=0;
await inputValue('converterFilterScript','function filter(node) { return true; }');
await inputValue('converterSortScript','function compare(a, b) { return 0; }');
assert.equal(requestLog.length,0); assert.equal(converterDirty(),true);
assert.equal($('#generateConverter').disabled,true); assert.equal($('#validateConverter').disabled,true);
await $('#executeConverter').click(); assert.equal(requestLog.length,0); // router preset explicitly sets sort=false
const sort=converterOptionFields.get('sort').control; sort.value=''; await sort.dispatch('change');
routes.set('/api/converter/execute',body=>{
  assert.equal(body.scripts.filter,$('#converterFilterScript').value); assert.equal(body.scripts.sort,$('#converterSortScript').value);
  assert.equal(Object.hasOwn(body.form.options,'sort'),false); assert.equal(Object.hasOwn(body.form.options,'filter_script'),false);
  assert.deepEqual(body.resources,[]); return response(executionResult(body));
});
await $('#executeConverter').click(); assert.equal(converterExport.current,true);
await inputValue('converterFilterScript','changed'); assert.equal(converterExport.current,false);
await $('#clearConverter').click(); assert.equal($('#converterFilterScript').value,''); assert.equal($('#converterSortScript').value,'');
assert.equal(converterHasLocal(),false); assert.equal(converterDirty(),false);
''')

    def test_script_upload_is_atomic_bounded_and_never_evaluated(self):
        self.run_js(r'''
await converterFixture(); requestLog.length=0;
const source='throw new Error("must not execute in browser");';
$('#converterFilterScriptUpload').files=[syntheticFile('filter.js',source)];
await $('#converterFilterScriptUpload').dispatch('change'); assert.equal($('#converterFilterScript').value,source);
confirmation=false; $('#converterFilterScriptUpload').files=[syntheticFile('filter.js','replacement')];
await $('#converterFilterScriptUpload').dispatch('change'); assert.equal($('#converterFilterScript').value,source);
confirmation=true;
let opened=false; $('#converterFilterScriptUpload').files=[{name:'large.js',size:65537,arrayBuffer:async()=>{opened=true;}}];
await $('#converterFilterScriptUpload').dispatch('change'); assert.equal(opened,false); assert.equal($('#converterFilterScript').value,source);
$('#converterFilterScriptUpload').files=[{name:'bad.js',size:2,arrayBuffer:async()=>new Uint8Array([255,255]).buffer}];
await $('#converterFilterScriptUpload').dispatch('change'); assert.equal($('#converterFilterScript').value,source);
await inputValue('converterFilterScript','界'.repeat(21846)); await $('#executeConverter').click(); assert.equal(requestLog.length,0);
assert.equal(operationBusy,false); assert.equal($('#converterFilterScriptUpload').value,'');
''')

    def test_resources_scripts_and_sources_share_byte_count_and_json_budgets(self):
        self.run_js(r'''
await converterFixture(); requestLog.length=0;
converterResources=[{name:'base.yaml',content:'x'.repeat(1048500)}];
await inputValue('converterFilterScript','x'.repeat(80)); await $('#executeConverter').click(); assert.equal(requestLog.length,0);
converterResources=[]; await inputValue('converterFilterScript','');
await inputValue('converterSources',Array(32).fill(exampleSource).join('\n'));
await inputValue('converterPaste',syntheticText); await $('#executeConverter').click(); assert.equal(requestLog.length,0);
await inputValue('converterSources',''); await inputValue('converterPaste','"'.repeat(1048576));
await $('#executeConverter').click(); assert.equal(requestLog.length,0); assert.ok($('#notice').textContent.includes('JSON'));
assert.equal(operationBusy,false);
''')

    def test_failed_catalog_load_is_retryable_and_does_not_read_sources(self):
        self.run_js(r'''
routes.set('/api/converter/options',()=>response({...CONVERTER_SCHEMA,limits:{}}));
await $('#loadConverter').click(); assert.equal(converterSchema,null); assert.equal($('#loadConverter').disabled,false);
assert.ok($('#converterState').textContent.includes('失败'));
routes.set('/api/converter/options',()=>response(CONVERTER_SCHEMA)); await $('#loadConverter').click();
assert.equal(converterDirty(),false); assert.equal($('#converterFilterScript').disabled,false);
assert.deepEqual(requestLog.map(item=>item.path),['/api/converter/options','/api/converter/options']);
''')

    def test_no_implicit_sensitive_storage_or_source_fetch(self):
        for forbidden in ('localStorage', 'sessionStorage', 'indexedDB', 'console.', 'innerHTML', 'document.cookie'):
            self.assertNotIn(forbidden, self.module)
        self.assertNotIn('fetch(', self.module)
        self.assertIn('readonly autocomplete="off"',self.html)


if __name__ == '__main__':
    unittest.main()
