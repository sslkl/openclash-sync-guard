"""Synthetic-only interactive regression for converter tools/resources/archives.

Uses the actual HTML, app.js + converter.js and the existing Node DOM/async
harness. This is behavioral coverage, not native execution or visual acceptance.
"""
import unittest
import test_converter_frontend as fixture


class ConverterToolsFrontendTests(unittest.TestCase):
    run_js = fixture.ConverterFrontendTests.run_js

    @classmethod
    def setUpClass(cls):
        fixture.ConverterFrontendTests.setUpClass.__func__(cls)
        cls.app += r'''
const copied = [], downloads = [], revoked = [], downloadNames = [];
const navigator = {clipboard: {writeText: async text => {copied.push(text);}}};
URL.createObjectURL = blob => {downloads.push(blob); return 'blob:synthetic-' + downloads.length;};
URL.revokeObjectURL = url => revoked.push(url);
const originalElementClick = MiniElement.prototype.click;
MiniElement.prototype.click = function() {
  if (this.tagName === 'A') downloadNames.push(this.getAttribute('download'));
  return originalElementClick.call(this);
};
MiniElement.prototype.select = function() {this.selected = true;};
function toolResult(body) {
  return {...executionResult({form:{options:{target:body.operation}}}),
    content:'Synthetic result\n', bytes:converterBytes('Synthetic result\n'),
    summary:{source_count:1,asset_count:body.resources.length,network_executed:body.urls.length > 0,
      link_backend_used:false,router_changed:false,operation:body.operation}};
}
async function uploadResources(files) {$('#converterResourceUpload').files=files; await $('#converterResourceUpload').dispatch('change');}
async function importArchive(text) {$('#converterArchiveUpload').files=[syntheticFile('profile.json',text)]; await $('#converterArchiveUpload').dispatch('change');}
async function toolInput(tool, text='Synthetic input') {await inputValue('converter-'+tool+'-content',text);}
'''

    def test_markup_has_labels_accessible_states_and_non_submit_buttons(self):
        ids = [node['attrs']['id'] for node in self.page.elements if 'id' in node['attrs']]
        self.assertEqual(len(ids), len(set(ids)))
        labels = {node['attrs'].get('for') for node in self.page.elements if node['tag'] == 'label'}
        for node in self.page.elements:
            identifier = node['attrs'].get('id', '')
            if identifier.startswith('converter-') and node['tag'] in {'input', 'textarea', 'select'}:
                self.assertIn(identifier, labels)
                if node['tag'] != 'select' and node['attrs'].get('type') != 'file':
                    self.assertEqual(node['attrs'].get('autocomplete'), 'off')
                self.assertIn('disabled', node['attrs'])
            if identifier.startswith('converter-') and node['tag'] == 'button':
                self.assertEqual(node['attrs'].get('type'), 'button')
        for tool in ('ruleset', 'template', 'surge2clash'):
            state = next(n['attrs'] for n in self.page.elements if n['attrs'].get('id') == 'converter-' + tool + '-state')
            self.assertEqual(state['role'], 'status')
            self.assertEqual(state['aria-live'], 'polite')
        mount = next(n for n in self.page.elements if n.get('attrs', {}).get('id') == 'converterApplyMount')
        result_section = next(n for n in self.page.elements if n.get('attrs', {}).get('class') == 'custom-section converter-export')
        self.assertIn(mount, result_section['children'])
        self.assertEqual(mount['tag'], 'div')
        self.assertEqual(mount['children'], [])
        scripts = [n['attrs'] for n in self.page.elements if n['tag'] == 'script']
        converter_index = next(i for i, script in enumerate(scripts) if script.get('src') == '/converter.js')
        self.assertEqual(scripts[converter_index + 1].get('src'), '/converter_apply.js')
        self.assertIn('defer', scripts[converter_index + 1])
        self.assertNotIn('localStorage', self.module)
        self.assertNotIn('sessionStorage', self.module)
        self.assertNotIn('innerHTML', self.module)
        self.assertNotIn('fetch(', self.module)
        self.assertNotIn('eval(', self.module)

    def test_opening_tools_is_lazy_and_unavailable_engine_does_not_fake_success(self):
        self.run_js(r'''
assert.equal(requestLog.length,0); await $('#converterTools').dispatch('toggle'); assert.equal(requestLog.length,0);
CONVERTER_SCHEMA.execution.bridge_available=false; await $('#loadConverter').click();
for (const tool of Object.keys(CONVERTER_TOOLS)) {
  await toolInput(tool); assert.equal(converterToolElement(tool,'run').disabled,true);
  assert.equal(converterToolElement(tool,'content').disabled,false); assert.ok(converterToolElement(tool,'state').textContent.includes('不可用'));
}
assert.equal(requestLog.length,1); assert.equal(copied.length,0); assert.equal(downloads.length,0);
assert.equal(converterDirty(),true); await $('#clearConverter').click(); assert.equal(converterDirty(),false);
CONVERTER_SCHEMA.execution.bridge_available=true; CONVERTER_SCHEMA.execution.tools=['template'];
updateConverterControls(); renderConverterTool('ruleset'); await toolInput('ruleset');
assert.equal($('#converter-ruleset-run').disabled,true); assert.ok($('#converter-ruleset-state').textContent.includes('尚未声明'));
''')

    def test_all_rule_types_and_input_formats_follow_actual_tool_contract(self):
        self.run_js(r'''
await $('#loadConverter').click(); await toolInput('ruleset','DOMAIN,example.test');
await inputValue('converter-ruleset-urls','https://rules.example.test/a\nhttps://rules.example.test/a');
await inputValue('converter-ruleset-group','Synthetic'); requestLog.length=0;
routes.set('/api/converter/tool',body=>{
  assert.equal(body.operation,'ruleset'); assert.deepEqual(body.urls,['https://rules.example.test/a','https://rules.example.test/a']);
  assert.equal(body.options.group,'Synthetic'); assert.equal(body.content,'DOMAIN,example.test');
  assert.deepEqual(body.resources,[]); assert.ok(body.nonce); return response(toolResult(body));
});
for (let kind=1;kind<=6;kind++) {
  await inputValue('converter-ruleset-type',String(kind),'change'); await $('#converter-ruleset-run').click();
  const sent=requestLog.filter(item=>item.path==='/api/converter/tool').at(-1).body;
  assert.equal(sent.options.type,kind); assert.equal(converterToolExports.get('ruleset').current,true);
  assert.equal(converterToolExports.get('ruleset').extension,[3,4,6].includes(kind)?'yaml':'txt');
}
for (const format of ['surge','quanx','clash-domain','clash-ipcidr','clash-classic']) {
  await inputValue('converter-ruleset-input-format',format,'change'); await $('#converter-ruleset-run').click();
  assert.equal(requestLog.filter(item=>item.path==='/api/converter/tool').at(-1).body.options.input_format,format);
}
assert.equal(copied.length,0); assert.equal(downloads.length,0); assert.ok(requestLog.every(item=>item.path.startsWith('/api/')));
''')

    def test_template_and_surge_text_remote_and_resource_requests(self):
        self.run_js(r'''
await $('#loadConverter').click(); requestLog.length=0;
await uploadResources([syntheticFile('part.tpl','Local part')]);
await toolInput('template','{% include "asset:part.tpl" %} {{ request.title }}');
await inputValue('converter-template-variables','{"title":"<img src=x onerror=alert(1)>"}');
assert.equal(requestLog.length,0);
routes.set('/api/converter/tool',body=>response(toolResult(body)));
await $('#converter-template-run').click(); let body=requestLog.find(item=>item.path==='/api/converter/tool').body;
assert.deepEqual(body.options,{variables:{title:'<img src=x onerror=alert(1)>'}});
assert.deepEqual(body.resources,[{name:'part.tpl',content:'Local part'}]); assert.deepEqual(body.urls,[]);
assert.equal($('#converter-template-variables').querySelectorAll('img').length,0);
await inputValue('converter-surge2clash-urls','https://config.example.test/surge.conf'); await $('#converter-surge2clash-run').click();
body=requestLog.filter(item=>item.path==='/api/converter/tool').at(-1).body;
assert.deepEqual(body.options,{}); assert.equal(body.content,''); assert.equal(body.operation,'surge2clash');
assert.deepEqual(body.urls,['https://config.example.test/surge.conf']);
assert.equal(converterToolExports.get('surge2clash').extension,'yaml'); assert.equal(converterExport,null);
''')

    def test_tool_sources_validate_before_nonce_network_and_file_reads_are_local(self):
        self.run_js(r'''
await $('#loadConverter').click(); requestLog.length=0;
$('#converter-template-upload').files=[syntheticFile('test.tpl','Hello {{ request.title }}')];
await $('#converter-template-upload').dispatch('change'); assert.equal($('#converter-template-content').value,'Hello {{ request.title }}');
assert.equal(requestLog.length,0);
for (const tool of ['template','surge2clash']) {
  await toolInput(tool); await inputValue('converter-'+tool+'-urls','https://source.example.test/a');
  await converterToolElement(tool,'run').click(); assert.equal(requestLog.length,0);
  await toolInput(tool,''); await inputValue('converter-'+tool+'-urls','https://source.example.test/a\nhttps://source.example.test/b');
  await converterToolElement(tool,'run').click(); assert.equal(requestLog.length,0);
}
await toolInput('ruleset'); await inputValue('converter-ruleset-urls',Array(32).fill('https://source.example.test/a').join('\n'));
await $('#converter-ruleset-run').click(); assert.equal(requestLog.length,0);
for (const url of ['file:///etc/passwd','javascript:alert(1)','https://user:synthetic@example.test/a','https://example.test/a#b','https://example.test/%zz']) {
  await inputValue('converter-ruleset-urls',url); await $('#converter-ruleset-run').click(); assert.equal(requestLog.length,0);
}
let opened=false; $('#converter-template-upload').files=[{name:'huge.tpl',size:1048577,arrayBuffer:async()=>{opened=true;}}];
await $('#converter-template-upload').dispatch('change'); assert.equal(opened,false); assert.equal(operationBusy,false);
''')

    def test_template_variables_reject_shape_controls_reserved_and_duplicate_keys(self):
        self.run_js(r'''
await $('#loadConverter').click(); await toolInput('template'); requestLog.length=0;
const values=['[]','null','{"title":4}','{"title":{}}','{"path":"x"}','{"__proto__":{"polluted":true}}',
  '{"constructor":"x"}','{"prototype":"x"}','{"title":"a","title":"b"}','{"title":"a","\\u0074itle":"b"}',
  '{"bad key":"x"}','{"title":"bad\\nvalue"}','{"title":"\\ud800"}',JSON.stringify({title:'界'.repeat(1366)}),
  JSON.stringify(Object.fromEntries(Array.from({length:33},(_,i)=>['key'+i,'x'])))];
for (const text of values) {
  await inputValue('converter-template-variables',text); await $('#converter-template-run').click();
  assert.equal(requestLog.length,0); assert.equal(operationBusy,false); assert.equal(converterToolExports.has('template'),false);
}
assert.equal({}.polluted,undefined);
assert.deepEqual(converterVariables('{"title":"{\\"x\\":1,\\"x\\":2}","empty":""}'),{title:'{"x":1,"x":2}',empty:''});
''')

    def test_resources_are_atomic_controlled_and_disable_lossy_links(self):
        self.run_js(r'''
await converterFixture(); requestLog.length=0;
await uploadResources([syntheticFile('base.yaml','port: 7890')]);
assert.equal(converterResources.length,1); assert.equal($('#generateConverter').disabled,true);
await $('#converterForm').dispatch('submit'); assert.equal(requestLog.length,0);
for (const files of [
  [syntheticFile('../bad.txt','x')], [syntheticFile('.hidden','x')], [syntheticFile('含中文.txt','x')], [syntheticFile('a..b','x')],
  [syntheticFile('base.yaml','replacement')], [syntheticFile('same.txt','x'),syntheticFile('same.txt','x')],
  [syntheticFile('valid.txt','x'),{name:'bad.txt',size:1,arrayBuffer:async()=>new Uint8Array([255]).buffer}],
  Array.from({length:64},(_,i)=>syntheticFile('resource'+i,'x'))]) {
  await uploadResources(files); assert.deepEqual(converterResources,[{name:'base.yaml',content:'port: 7890'}]);
  assert.equal($('#converterResourceUpload').value,''); assert.equal(operationBusy,false);
}
let opened=false; await uploadResources([{name:'huge.txt',size:1048577,arrayBuffer:async()=>{opened=true;}}]); assert.equal(opened,false);
await inputValue('converterConfigContent','[custom]\nclash_rule_base=asset:base.yaml');
routes.set('/api/converter/execute',body=>{assert.deepEqual(body.resources,converterResources);return response(executionResult(body));});
await $('#executeConverter').click(); assert.equal(converterExport.current,true);
''')

    def test_resource_changes_invalidate_both_results_without_destroying_edits(self):
        self.run_js(r'''
await converterFixture(); await toolInput('ruleset');
routes.set('/api/converter/execute',body=>response(executionResult(body))); routes.set('/api/converter/tool',body=>response(toolResult(body)));
await $('#executeConverter').click(); await $('#converter-ruleset-run').click();
await inputValue('converterText',syntheticText+'# edited'); await inputValue('converter-ruleset-result','Tool edited');
await uploadResources([syntheticFile('rules.txt','DOMAIN,example.test')]);
assert.equal(converterExport.current,false); assert.equal(converterToolExports.get('ruleset').current,false);
assert.ok($('#converterText').value.endsWith('# edited')); assert.equal($('#converter-ruleset-result').value,'Tool edited');
const remove=$('#converterResources').querySelector('button'); confirmation=false; await remove.click(); assert.equal(converterResources.length,1);
confirmation=true; await remove.click(); assert.equal(converterResources.length,0);
await $('#converter-ruleset-restore').click(); assert.equal($('#converter-ruleset-result').value,'Synthetic result\n');
assert.equal(converterToolExports.get('ruleset').current,false);
await $('#clearConverter').click(); assert.equal(converterDirty(),false); assert.equal(converterToolExports.size,0);
assert.equal($('#converter-ruleset-download').disabled,true); assert.equal($('#parseConverter').disabled,true);
''')

    def test_tool_lock_covers_nonce_renewal_and_does_not_retry_lost_responses(self):
        self.run_js(r'''
await converterFixture(); await toolInput('template'); requestLog.length=0;
const request=deferred(), renewal=deferred(); let calls=0;
routes.set('/api/converter/tool',body=>{calls++;assert.equal(body.nonce,'token-1');return request.promise;});
routes.set('/api/bootstrap',()=>renewal.promise);
const task=$('#converter-template-run').click(); await waitTick();
for (const id of ['executeConverter','converterResourceUpload','converterArchiveUpload','exportConverterArchive','converterFilterScript','saveChain']) assert.equal($('#'+id).disabled,true);
await $('#converter-template-run').click(); assert.equal(calls,1);
request.resolve(response({ok:false,message:'Synthetic failure'},502)); await waitTick();
assert.equal(operationBusy,true); assert.equal($('#clearConverter').disabled,true);
renewal.resolve(response({ok:true,nonce:'token-renewed',mode:'live'})); await task;
assert.equal(operationBusy,false); assert.equal(nonce,'token-renewed'); assert.equal(calls,1);
assert.equal(converterToolExports.size,0); assert.ok($('#converter-template-state').textContent.includes('未成功'));
assert.equal($('#converterArchiveUpload').disabled,false);
''')

    def test_invalid_tool_evidence_and_failed_reconversion_keep_old_draft(self):
        self.run_js(r'''
await $('#loadConverter').click(); await toolInput('template');
routes.set('/api/converter/tool',body=>response(toolResult(body))); await $('#converter-template-run').click();
await inputValue('converter-template-result','Edited draft'); await toolInput('template','changed');
confirmation=false; requestLog.length=0; await $('#converter-template-run').click(); assert.equal(requestLog.length,0);
confirmation=true;
for (const mutation of [{target:'ruleset'}, {cleanup_confirmed:false}, {network:'bridge'}, {bytes:1}, {engine:'other'}, {unexpected:'x'},
  {router_changed:true}, {elapsed_ms:60001}, {summary:{source_count:1,asset_count:0,router_changed:false,link_backend_used:false,network_executed:false}}]) {
  routes.set('/api/converter/tool',body=>response({...toolResult(body),...mutation})); await $('#converter-template-run').click();
  assert.equal($('#converter-template-result').value,'Edited draft'); assert.equal(converterToolExports.get('template').current,false);
  assert.ok($('#converter-template-state').textContent.includes('未成功')); assert.equal(operationBusy,false);
}
assert.equal(requestLog.filter(item=>item.path==='/api/converter/tool').length,9);
''')

    def test_copy_download_restore_use_explicit_actions_and_snapshot_extension(self):
        self.run_js(r'''
await $('#loadConverter').click(); await toolInput('ruleset'); await inputValue('converter-ruleset-type','3','change');
routes.set('/api/converter/tool',body=>response(toolResult(body))); await $('#converter-ruleset-run').click();
assert.equal(copied.length,0); assert.equal(downloads.length,0);
await inputValue('converter-ruleset-type','1','change'); await inputValue('converter-ruleset-result','Edited result');
confirmation=false; await $('#converter-ruleset-download').click(); assert.equal(downloads.length,0);
confirmation=true; await $('#converter-ruleset-download').click(); assert.equal(downloadNames[0],'ruleset.yaml');
assert.equal(await downloads[0].text(),'Edited result');
for (const callback of timers.values()) callback(); assert.deepEqual(revoked,['blob:synthetic-1']);
const pending=deferred(); navigator.clipboard.writeText=text=>{copied.push(text);return pending.promise;};
const task=$('#converter-ruleset-copy').click(); assert.equal(operationBusy,true); assert.equal($('#clearConverter').disabled,true);
pending.resolve(); await task; assert.deepEqual(copied,['Edited result']); assert.equal(operationBusy,false);
navigator.clipboard.writeText=async()=>{throw Error('synthetic denied');}; await $('#converter-ruleset-copy').click();
assert.equal($('#converter-ruleset-result').selected,true); assert.equal(operationBusy,false);
await inputValue('converter-ruleset-result','bad\0text'); await $('#converter-ruleset-copy').click(); await $('#converter-ruleset-download').click();
assert.equal(downloads.length,1); assert.deepEqual(copied,['Edited result']);
''')

    def test_copy_link_and_main_result_hold_lock_and_select_only_after_unlock(self):
        self.run_js(r'''
MiniElement.prototype.select = function() {assert.equal(this.disabled,false); assert.equal(operationBusy,false); this.selected=true;};
await converterFixture(); routes.set('/api/converter/link',validLink); await $('#converterForm').dispatch('submit');
const before=requestLog.length, pending=deferred(); let attempts=0;
navigator.clipboard.writeText=()=>{attempts++;return pending.promise.then(()=>{throw Error('synthetic denied');});};
const task=$('#copyConverter').click(); assert.equal(operationBusy,true); assert.equal($('#saveChain').disabled,true);
await $('#copyConverter').click(); assert.equal(attempts,1); pending.resolve(); await task;
assert.equal($('#converterOutput').selected,true); assert.equal(operationBusy,false); assert.equal(requestLog.length,before);
routes.set('/api/converter/execute',body=>response(executionResult(body))); await $('#executeConverter').click();
navigator.clipboard.writeText=async()=>{throw Error('synthetic denied');}; await $('#copyConverterText').click();
assert.equal($('#converterText').selected,true); assert.equal(operationBusy,false); assert.equal(copied.length,0);
await toolInput('template'); routes.set('/api/converter/tool',body=>response(toolResult(body))); await $('#converter-template-run').click();
await $('#converter-template-copy').click(); assert.equal($('#converter-template-result').selected,true);
''')

    def test_archive_roundtrip_preserves_all_inputs_without_network_execution_or_html(self):
        self.run_js(r'''
await converterFixture();
await inputValue('converterTarget','surge','change'); const ver=converterOptionFields.get('ver').control; ver.value='5'; await ver.dispatch('input');
const sort=converterOptionFields.get('sort').control; sort.value='true'; await sort.dispatch('change');
await inputValue('converterPaste',syntheticText); await inputValue('converterConfigContent','[custom]\nclash_rule_base=asset:base.yaml');
await inputValue('converterFilterScript','function filter(node) { return true; }'); await inputValue('converterSortScript','function compare(a,b) { return 0; }');
$('#converterUpload').files=[syntheticFile('<img src=x>.yaml',syntheticText)]; await $('#converterUpload').dispatch('change');
await uploadResources([syntheticFile('base.yaml','port: 7890')]);
await toolInput('ruleset','DOMAIN,example.test'); await inputValue('converter-ruleset-type','6','change');
await toolInput('template','{{ request.title }}'); await inputValue('converter-template-variables','{"title":"<img src=x onerror=alert(1)>"}');
await inputValue('converter-surge2clash-urls','https://config.example.test/surge.conf');
await inputValue('converterImport','https://converter.example.test/sub?target=clash&url=synthetic');
const expected=converterArchive(); requestLog.length=0;
await $('#exportConverterArchive').click(); assert.equal(downloads.length,1); assert.equal(copied.length,0); assert.equal(requestLog.length,0);
const text=await downloads[0].text(); assert.deepEqual(JSON.parse(text),expected); assert.equal(downloadNames[0],'subscription-converter-profile-v1.json');
assert.equal(Object.hasOwn(JSON.parse(text),'result'),false); assert.equal(Object.hasOwn(JSON.parse(text),'nonce'),false);
await $('#clearConverter').click(); assert.equal(converterDirty(),false);
await importArchive(text); assert.deepEqual(converterArchive(),expected); assert.equal(requestLog.length,0); assert.equal(copied.length,0);
assert.equal(converterForm().options.ver,5); assert.equal(converterForm().options.scv,false); assert.equal(converterDirty(),true);
assert.equal($('#converterFiles').querySelectorAll('img').length,0); assert.equal($('#converter-template-variables').querySelectorAll('img').length,0);
assert.equal(converterExport,null); assert.equal(converterToolExports.size,0); assert.equal($('#converterArchiveUpload').value,'');
assert.equal($('#converterText').disabled,true); assert.equal($('#converter-template-download').disabled,true);
''')

    def test_archive_rejects_wrong_shapes_versions_and_poison_without_partial_apply(self):
        self.run_js(r'''
await converterFixture(); await toolInput('template','Hello');
routes.set('/api/converter/tool',body=>response(toolResult(body))); await $('#converter-template-run').click();
await inputValue('converter-template-result','Keep edited draft');
const original=converterArchive(), signature=JSON.stringify(original); requestLog.length=0;
const changes=[
 x=>{x.version=2;},x=>{x.version='1';},x=>{x.format='other';},x=>{x.unknown=true;},x=>{delete x.resources;},
 x=>{x.form=[];},x=>{x.form.profile='unknown';},x=>{x.form.sources=[];},x=>{x.form.backend='javascript:alert(1)';},
 x=>{x.form.options.udp='true';},x=>{x.form.options.token='not allowed';},x=>{x.form.options.target='unknown';},x=>{x.form.options.ver=5;},
 x=>{x.uploads=[{name:'x',content:7}];},x=>{x.uploads=[{name:'x',content:'x',bytes:1}];},x=>{x.paste=null;},
 x=>{x.resources=[{name:'../x',content:'x'}];},x=>{x.resources=[{name:'x',content:'x'},{name:'x',content:'x'}];},
 x=>{x.scripts.filter=false;},x=>{x.scripts.filter='x'.repeat(65537);},x=>{x.scripts.extra='x';},
 x=>{x.tools.template.variables='[]';},x=>{x.tools.template.variables='{"constructor":"x"}';},
 x=>{x.tools.ruleset.type=true;},x=>{x.tools.surge2clash.options={};},x=>{x.tools.ruleset.group='bad,group';},
 x=>{x.config_content='bad\0text';},x=>{x.import_link=7;},x=>{x.resources=[{name:'x',content:'x'.repeat(1048576)}];}
];
for (const change of changes) {
  const candidate=JSON.parse(signature); change(candidate); await importArchive(JSON.stringify(candidate));
  assert.equal(JSON.stringify(converterArchive()),signature); assert.equal($('#converter-template-result').value,'Keep edited draft');
  assert.equal(operationBusy,false); assert.equal($('#converterArchiveUpload').value,'');
  assert.ok($('#converterArchiveState').textContent.includes('未应用'));
}
for (const text of [signature.replace('"version":1','"version":2,"version":1'),signature.replace('"version":1','"version":1,"__proto__":{"polluted":true}'),
  '{"constructor":{"prototype":{"polluted":true}}}', 'null', '[]', '{broken']) {
  await importArchive(text); assert.equal(JSON.stringify(converterArchive()),signature); assert.equal({}.polluted,undefined);
}
assert.equal(requestLog.length,0); assert.equal(downloads.length,0); assert.equal(copied.length,0);
''')

    def test_archive_cancellation_oversize_and_failed_read_preserve_current_results(self):
        self.run_js(r'''
await converterFixture(); routes.set('/api/converter/execute',body=>response(executionResult(body))); await $('#executeConverter').click();
await inputValue('converterText',syntheticText+'# keep'); const signature=JSON.stringify(converterArchive()); requestLog.length=0;
confirmation=false; await $('#exportConverterArchive').click(); assert.equal(downloads.length,0);
const changed=JSON.parse(signature); changed.form.sources='https://changed.example.test/a'; await importArchive(JSON.stringify(changed));
assert.equal(JSON.stringify(converterArchive()),signature); assert.ok($('#converterText').value.endsWith('# keep'));
confirmation=true; let opened=false;
$('#converterArchiveUpload').files=[{name:'huge.json',size:8*1024*1024+1,arrayBuffer:async()=>{opened=true;}}];
await $('#converterArchiveUpload').dispatch('change'); assert.equal(opened,false);
$('#converterArchiveUpload').files=[{name:'bad.json',size:1,arrayBuffer:async()=>new Uint8Array([255]).buffer}];
await $('#converterArchiveUpload').dispatch('change'); assert.equal(JSON.stringify(converterArchive()),signature);
assert.ok($('#converterText').value.endsWith('# keep')); assert.equal(requestLog.length,0); assert.equal(operationBusy,false);
await importArchive(JSON.stringify(changed)); assert.equal(converterForm().sources,changed.form.sources);
assert.equal(converterExport,null); assert.equal($('#converterText').value,''); assert.equal(requestLog.length,0);
''')


if __name__ == '__main__':
    unittest.main()
