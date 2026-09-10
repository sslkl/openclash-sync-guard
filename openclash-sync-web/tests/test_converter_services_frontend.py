"""Real external-service JS on the shared synthetic HTML/async DOM harness."""
import unittest
import test_converter_frontend as fixture

class ServicesFrontendTests(unittest.TestCase):
    run_js=fixture.ConverterFrontendTests.run_js
    @classmethod
    def setUpClass(cls):
        fixture.ConverterFrontendTests.setUpClass.__func__(cls)
        cls.app += '\n' + (fixture.ROOT/'static/converter_services.js').read_text()
        cls.app += r'''
window.location={protocol:'http:'};
const servicePath='/api/converter/service';
const callsToService=()=>requestLog.filter(x=>x.path===servicePath);
const serviceState=()=>$('#converterService-state').textContent;
const service=key=>$('#converterService-'+key);
async function serviceFixture(action='gist_list') {
 await converterFixture();await inputValue('converterService-action',action,'change');
 if(action.startsWith('gist_'))await inputValue('converterService-token','synthetic_token_for_offline_only');
 requestLog.length=0;
}
async function confirmService() {
 await inputValue('converterService-confirm',true,'change');
 if(service('action').value.startsWith('gist_'))await inputValue('converterService-http',true,'change');
}
function serviceOK(body) {return response({ok:true,action:body.action,router_changed:false,
 ...(body.action==='gist_list'?{items:[],page:body.page,has_next:false}:body.action==='gist_get'?{gist:{id:'a'.repeat(32),public:false,filenames:['config.ini']},content:'[custom]\n',filename:'config.ini'}:body.action==='gist_delete'?{id:body.id,deleted:true}:body.action.startsWith('gist_')?{gist:{id:'a'.repeat(32),public:false,filenames:['config.ini']}}:{link:'https://short.example.test/a'})});}
'''

    def test_no_automatic_requests_and_controls_labels(self):
        self.run_js(r'''
assert.equal(callsToService().length,0);await $('#converterServicesWorkspace').dispatch('toggle');assert.equal(callsToService().length,0);
await serviceFixture();assert.equal(service('send').disabled,true);
for(const key of ['token','link','content','filename','action','api','confirm','http']) {
 const c=service(key);assert.ok(c);assert.equal(c.getAttribute('autocomplete'),'off');
 assert.ok($$('label').some(x=>x.getAttribute('for')===c.id));
}
assert.equal(service('token').type,'password');assert.equal(service('state').getAttribute('aria-live'),'polite');
''')

    def test_confirm_http_risk_and_input_changes_invalidate(self):
        self.run_js(r'''
await serviceFixture();routes.set(servicePath,serviceOK);
await inputValue('converterService-confirm',true,'change');assert.equal(service('send').disabled,true);
await inputValue('converterService-http',true,'change');assert.equal(service('send').disabled,false);
await inputValue('converterService-page','2');assert.equal(service('confirm').checked,false);assert.equal(service('http').checked,false);
await service('send').click();assert.equal(callsToService().length,0);
await confirmService();await service('send').click();assert.equal(callsToService().length,1);
const sent=callsToService()[0].body;assert.equal(sent.page,2);assert.equal(sent.confirm_external,true);assert.ok(sent.nonce);assert.ok(!('http' in sent));
assert.equal(service('token').value,'');assert.equal(service('confirm').checked,false);assert.equal(operationBusy,false);
''')

    def test_clear_and_archive_do_not_store_service_credentials(self):
        self.run_js(r'''
await serviceFixture();await inputValue('converterService-content','service-only-secret');assert.equal(converterDirty(),true);
const archive=JSON.stringify(converterArchive());assert.ok(!archive.includes('service-only-secret'));assert.ok(!archive.includes('synthetic_token_for_offline_only'));
window.confirm=()=>true;await service('clear').click();assert.equal(service('token').value,'');assert.equal(service('content').value,'');assert.equal(callsToService().length,0);
''')

    def test_cancel_never_sends_and_missing_input_keeps_result(self):
        self.run_js(r'''
await serviceFixture();routes.set(servicePath,serviceOK);await confirmService();window.confirm=()=>false;
await service('send').click();assert.equal(callsToService().length,0);assert.ok(serviceState().includes('取消'));assert.notEqual(service('token').value,'');
''')

    def test_page_lock_spans_nonce_renewal_and_prevents_duplicate(self):
        self.run_js(r'''
await serviceFixture();await confirmService();const wait=deferred();routes.set(servicePath,()=>wait.promise);
const first=service('send').click();await settle();assert.equal(operationBusy,true);assert.equal(service('token').disabled,true);
await service('send').click();assert.equal(callsToService().length,1);
const renewal=deferred();routes.set('/api/bootstrap',()=>renewal.promise);wait.resolve(serviceOK(callsToService()[0].body));await settle();
assert.equal(operationBusy,true);renewal.resolve(response({ok:true,nonce:'renewed',mode:'live'}));await first;
assert.equal(operationBusy,false);assert.equal(service('token').value,'');assert.equal(callsToService().length,1);
''')

    def test_write_response_loss_is_unknown_no_retry_no_sensitive_echo(self):
        self.run_js(r'''
await serviceFixture('gist_delete');await inputValue('converterService-id','a'.repeat(32));await confirmService();
routes.set(servicePath,()=>{throw new Error('synthetic-sensitive-message');});await service('send').click();
assert.equal(callsToService().length,1);assert.ok(serviceState().includes('可能已生效'));assert.ok(!serviceState().includes('synthetic-sensitive-message'));assert.equal(service('token').value,'');
''')

    def test_read_return_is_not_automatically_loaded_and_user_import_invalidates(self):
        self.run_js(r'''
await serviceFixture('gist_get');await inputValue('converterService-id','a'.repeat(32));await confirmService();routes.set(servicePath,serviceOK);
await service('send').click();assert.equal($('#converterConfigContent').value,'');assert.equal(service('result').value,'[custom]\n');assert.equal(service('importConfig').disabled,false);
await service('importConfig').click();assert.equal($('#converterConfigContent').value,'[custom]\n');assert.equal(callsToService().length,1);
assert.ok(!requestLog.some(x=>x.path.includes('router-apply')||x.path.endsWith('/execute')));
''')

    def test_shortening_does_not_forward_gist_credentials_or_files(self):
        self.run_js(r'''
await serviceFixture('shorten');await inputValue('converterService-link','http://192.0.2.20:25500/sub?target=clash&url=https%3A%2F%2Fexample.test%2Fs');
service('token').value='unrelated-token';service('content').value='unrelated-content';await confirmService();routes.set(servicePath,serviceOK);await service('send').click();
assert.equal(callsToService().length,1);const body=callsToService()[0].body;assert.ok(!('token' in body));assert.ok(!('content' in body));assert.equal(body.api,'https://suo.yt/short');
assert.equal(service('result').value,'https://short.example.test/a');
''')

    def test_https_does_not_require_http_risk_check(self):
        self.run_js(r'''
window.location.protocol='https:';await serviceFixture();await inputValue('converterService-confirm',true,'change');
assert.equal(service('send').disabled,false);assert.equal(service('http').parentNode.hidden,true);
''')

    def test_gist_import_clears_stale_catalog_only_after_confirmation(self):
        self.run_js(r'''
await serviceFixture('gist_get');
const preset = CONVERTER_SCHEMA.config_presets[0].items[0].url;
await inputValue('converterConfigPreset', preset, 'change');
await inputValue('converterService-id', 'a'.repeat(32)); await confirmService();
routes.set(servicePath, serviceOK); await service('send').click();
assert.equal($('#converterConfig').value, preset); assert.equal($('#converterConfigPreset').value, preset);
window.confirm = () => false; await service('importConfig').click();
assert.equal($('#converterConfig').value, preset); assert.equal($('#converterConfigPreset').value, preset);
assert.equal($('#converterConfigContent').value, '');
window.confirm = () => true; await service('importConfig').click();
assert.equal($('#converterConfig').value, ''); assert.equal($('#converterConfigPreset').value, '');
assert.equal($('#converterConfigContent').value, '[custom]\n');
assert.equal(callsToService().length, 1); assert.equal(converterResult, '');
assert.ok(!requestLog.some(item => item.path.includes('router-apply') || item.path.endsWith('/execute')));
''')
