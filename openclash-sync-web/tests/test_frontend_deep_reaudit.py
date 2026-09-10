"""Deep front-end re-audit: actual JS, synthetic DOM/I/O, no backend import.

Real-browser/visual evidence is kept separately. The shared DOM harness models
only the APIs needed here; these tests do not claim layout or production QA.
"""
import unittest

import test_chain_frontend as fixture


class FrontendDeepReauditTests(unittest.TestCase):
    run_js = fixture.ChainFrontendTests.run_js

    @classmethod
    def setUpClass(cls):
        fixture.ChainFrontendTests.setUpClass.__func__(cls)
        for name in ('converter.js', 'converter_apply.js', 'converter_services.js'):
            cls.app += '\n' + (fixture.ROOT / 'static' / name).read_text()
        cls.app += r'''
const enabledFocus = MiniElement.prototype.focus;
MiniElement.prototype.focus = function () {if (!this.disabled) enabledFocus.call(this);};
window.location = {protocol:'http:'};
const deepSchema = {ok:true,backend:'https://converter.example.test/sub',
  clients:{clash:'Clash'},booleans:{},texts:{},integers:{},
  presets:[{id:'router_a',name:'Synthetic',options:{target:'clash'}}],
  limits:{sources:32,source_bytes:16384,link_bytes:65536,content_bytes:1048576,uploads:32},
  execution:{bridge_available:true,engine:'synthetic',tools:[],virtual_resources:true}};
async function deepChain() {
  await loadFixture([]);
  await inputValue('chainServer', 'exit.example.test');
  await inputValue('chainPort', '443');
}
function deepCustom() {
  switchPanel('custom');
  const row = addRule({type:'DOMAIN',value:'example.test',policy:'DIRECT'});
  customStateHash = {router_a:'a'.repeat(64),router_b:'b'.repeat(64)};
  customConfigHash = {router_a:'c'.repeat(64),router_b:'d'.repeat(64)};
  return row;
}
const deepCustomError = () => response({ok:false,message:'Synthetic invalid policy',errors:[
  {section:'rules',index:0,field:'policy',message:'Synthetic policy error'}]},400);
async function deepConverter() {
  routes.set('/api/converter/options', () => response(deepSchema));
  await $('#loadConverter').click();
  converterExport = {content:'proxies: []\n',target:'clash',sha256:'a'.repeat(64),current:true};
  $('#converterText').value = converterExport.content;
  updateConverterControls();
}
'''

    def test_chain_identical_pending_validation_is_single_flight(self):
        self.run_js(r'''
await deepChain();
const pending = deferred(); routes.set('/api/chain/validate', () => pending.promise);
const first = validateChain(), second = validateChain(), third = validateChain();
assert.equal(requestLog.filter(r => r.path === '/api/chain/validate').length, 1);
assert.equal($('#validateChain').getAttribute('aria-busy'), 'true');
pending.resolve(response({ok:true,message:'Synthetic valid'}));
assert.deepEqual(await Promise.all([first,second,third]), [true,true,true]);
assert.equal($('#validateChain').getAttribute('aria-busy'), 'false');
''')

    def test_chain_different_password_cannot_reuse_pending_validation(self):
        self.run_js(r'''
await deepChain(); await inputValue('chainPassword','synthetic-first');
const pending=deferred(); routes.set('/api/chain/validate', () => pending.promise);
const old=validateChain(); await inputValue('chainPassword','synthetic-second');
routes.set('/api/chain/validate', () => response({ok:false,message:'Synthetic current invalid'}));
assert.equal(await validateChain(),false);
pending.resolve(response({ok:true,message:'old success'})); assert.equal(await old,false);
const calls=requestLog.filter(r=>r.path==='/api/chain/validate');
assert.equal(calls.length,2); assert.equal(calls[0].signal.aborted,true);
assert.equal(chainIsValid,false); assert.ok(!$('#chainValidation').textContent.includes('old success'));
''')

    def test_chain_settled_results_are_never_cached(self):
        self.run_js(r'''
await deepChain(); assert.equal(await validateChain(),true); assert.equal(await validateChain(),true);
assert.equal(requestLog.filter(r=>r.path==='/api/chain/validate').length,2);
''')

    def test_chain_recheck_clears_old_valid_state_until_settlement(self):
        self.run_js(r'''
await deepChain(); await validateChain(); await inputValue('chainConfirm',true,'change');
assert.equal($('#saveChain').disabled,false);
const pending=deferred(); routes.set('/api/chain/validate',()=>pending.promise);
const running=validateChain();
assert.equal(chainIsValid,false); assert.equal($('#saveChain').disabled,true);
pending.resolve(response({ok:false,message:'Synthetic invalid'})); await running;
''')

    def test_chain_old_completion_does_not_clear_new_pending_indicator(self):
        self.run_js(r'''
await deepChain(); const first=deferred(), second=deferred(); let count=0;
routes.set('/api/chain/validate',()=>++count===1?first.promise:second.promise);
const old=validateChain(); await inputValue('chainPort','444'); const current=validateChain();
first.resolve(response({ok:true,message:'old'})); await old;
assert.equal($('#validateChain').getAttribute('aria-busy'),'true');
second.resolve(response({ok:true,message:'current'})); assert.equal(await current,true);
assert.equal($('#validateChain').getAttribute('aria-busy'),'false');
''')

    def test_chain_failed_request_releases_pending_and_allows_retry(self):
        self.run_js(r'''
await deepChain(); routes.set('/api/chain/validate',()=>{throw new Error('Synthetic unavailable')});
assert.equal(await validateChain(),false);
assert.equal($('#validateChain').getAttribute('aria-busy'),'false');
routes.set('/api/chain/validate',()=>response({ok:true,message:'retry'}));
assert.equal(await validateChain(),true);
assert.equal(requestLog.filter(r=>r.path==='/api/chain/validate').length,2);
''')

    def test_explicit_custom_check_focuses_first_editable_error_field(self):
        self.run_js(r'''
const row=deepCustom(); routes.set('/api/custom/validate',deepCustomError);
$('#validateCustom').focus(); await $('#validateCustom').click();
assert.ok(document.activeElement===row.querySelector('.rule-policy'));
assert.equal(row.querySelector('.rule-policy').getAttribute('aria-invalid'),'true');
routes.delete('/api/custom/validate'); await validateCustom();
assert.equal(row.querySelector('.rule-policy').getAttribute('aria-invalid'),null);
''')

    def test_background_custom_check_does_not_steal_focus(self):
        self.run_js(r'''
deepCustom(); routes.set('/api/custom/validate',deepCustomError); $('#routeValue').focus();
assert.equal(await validateCustom(),false); assert.ok(document.activeElement===$('#routeValue'));
''')

    def test_custom_check_merges_explicit_focus_into_background_request(self):
        self.run_js(r'''
const row=deepCustom(), pending=deferred(); routes.set('/api/custom/validate',()=>pending.promise);
const background=validateCustom(); $('#validateCustom').focus(); const explicit=$('#validateCustom').click();
assert.equal(requestLog.filter(r=>r.path==='/api/custom/validate').length,1);
pending.resolve(deepCustomError()); await Promise.all([background,explicit]);
assert.ok(document.activeElement===row.querySelector('.rule-policy'));
''')

    def test_custom_save_failure_focuses_only_after_unlock(self):
        self.run_js(r'''
const row=deepCustom(); await validateCustom(); await inputValue('customConfirm',true,'change');
const pending=deferred(); routes.set('/api/custom/validate',()=>pending.promise);
$('#saveCustom').focus(); const running=$('#saveCustom').click();
assert.equal(row.querySelector('.rule-policy').disabled,true);
pending.resolve(deepCustomError()); await running;
assert.equal(operationBusy,false); assert.ok(document.activeElement===row.querySelector('.rule-policy'));
assert.equal(requestLog.filter(r=>r.path==='/api/custom/apply').length,0);
''')

    def test_custom_failure_does_not_steal_focus_after_panel_navigation(self):
        self.run_js(r'''
deepCustom(); await validateCustom(); await inputValue('customConfirm',true,'change');
const pending=deferred(); routes.set('/api/custom/validate',()=>pending.promise);
const running=$('#saveCustom').click(); switchPanel('editor'); $('[data-panel="editor"]').focus();
pending.resolve(deepCustomError()); await running;
assert.ok(document.activeElement===$('[data-panel="editor"]'));
assert.equal(operationBusy,false);
''')

    def test_bulk_custom_errors_resolve_each_section_rows_once(self):
        self.run_js(r'''
deepCustom(); const errors=Array.from({length:300},()=>({section:'rules',index:0,field:'value',message:'Synthetic error'}));
let resolutions=0; const original=validationRows;
validationRows=function(section){resolutions++;return original(section);};
showCustomResult({ok:false,message:'Synthetic errors',errors});
assert.ok(resolutions<=2, 'Error rendering must not rescan all rows per error: '+resolutions);
assert.equal($('#ruleList .row-error').textContent,'Synthetic error');
''')

    def test_apply_unrelated_control_updates_do_not_recheck_large_text(self):
        self.run_js(r'''
await deepConverter(); $('#converterText').value='proxies: []\n#'+'x'.repeat(512*1024); updateConverterControls();
let largeChecks=0; const original=converterCheckText;
converterCheckText=function(text,...args){if(text.length>512*1024)largeChecks++;return original(text,...args);};
for(let i=0;i<8;i++)updateConverterControls();
assert.equal(largeChecks,0, 'Unchanged result must not be re-encoded for unrelated controls');
assert.equal($('#previewConverterApply').disabled,false);
''')

    def test_apply_cached_controls_invalidate_on_text_and_mode_changes(self):
        self.run_js(r'''
await deepConverter(); assert.equal($('#previewConverterApply').disabled,false);
$('#converterText').value=''; updateConverterControls(); assert.equal($('#previewConverterApply').disabled,true);
$('#converterText').value='proxies: []\n'; updateConverterControls(); assert.equal($('#previewConverterApply').disabled,false);
mode='unknown';updateConverterControls();assert.equal($('#previewConverterApply').disabled,true);
mode='live';updateConverterControls();assert.equal($('#previewConverterApply').disabled,false);
''')

    def test_apply_button_revalidates_even_if_cached_controls_are_enabled(self):
        self.run_js(r'''
await deepConverter(); assert.equal($('#previewConverterApply').disabled,false);
converterRequestBudget=()=>{throw new Error('Synthetic budget failure')};
await $('#previewConverterApply').click();
assert.equal(requestLog.filter(r=>r.path==='/api/converter/router-preview').length,0);
assert.equal($('#converterApplyState').getAttribute('data-state'),'error');
''')


if __name__ == '__main__':
    unittest.main()
