"""Status freshness failures on the actual frontend with synthetic responses."""
import unittest
import test_chain_frontend as fixture


class StatusFrontendTests(unittest.TestCase):
    run_js = fixture.ChainFrontendTests.run_js

    @classmethod
    def setUpClass(cls):
        fixture.ChainFrontendTests.setUpClass.__func__(cls)
        cls.app += r'''
const statusOK = () => response({ok:true,targets:[{id:'router_a',name:'Synthetic',
  address:'192.0.2.1',active:'current.yaml',state:'OK'}]});
async function goodStatus() {
  routes.set('/api/status',statusOK);
  lastNodeHealth.router_a={maying:{passed:1,total:1},nexitally:{passed:2,total:2}};
  await refresh(); assert.ok($('#targetGrid').textContent.includes('current.yaml'));
}
function unknownStatus() {
  assert.ok($('#targetGrid').textContent.includes('UNKNOWN'));
  assert.ok(!$('#targetGrid').textContent.includes('current.yaml'));
  assert.deepEqual(lastNodeHealth,{});
}
'''

    def test_failed_readback_preserves_receipt_but_invalidates_old_status(self):
        self.run_js(r'''
await goodStatus(); notice('操作回执：已完成');
routes.set('/api/status',()=>{throw new Error('synthetic readback failure');});
assert.equal(await refresh(true),false); unknownStatus();
assert.equal($('#notice').textContent,'操作回执：已完成');
routes.set('/api/status',statusOK); assert.equal(await refresh(true),true);
assert.ok($('#targetGrid').textContent.includes('current.yaml'));
assert.ok(!$('#targetGrid').textContent.includes('Maying 1/1'));
''')

    def test_manual_refresh_failure_reports_error_and_bootstrap_failure_invalidates(self):
        self.run_js(r'''
await goodStatus(); routes.set('/api/status',()=>{throw new Error('synthetic unavailable');});
await refresh(); unknownStatus(); assert.ok($('#notice').textContent.includes('synthetic unavailable'));
await goodStatus(); routes.set('/api/bootstrap',()=>{throw new Error('bootstrap unavailable');});
assert.equal(await bootstrap(true,false),false); unknownStatus(); assert.equal(nonce,'');
''')

    def test_invalid_or_empty_status_never_reuses_old_cards(self):
        self.run_js(r'''
for (const data of [{ok:false,targets:[]},{ok:true,targets:null},{ok:true,targets:[null]},
  {ok:true,targets:[{id:'router_a'}]},{ok:true,targets:[]},
  {ok:true,targets:Array(2).fill({id:'router_a',name:'A',address:'192.0.2.1',active:'a',state:'OK'})}]) {
  await goodStatus(); routes.set('/api/status',()=>response(data));
  assert.equal(await refresh(true),false); unknownStatus();
}
''')

    def test_successful_status_escapes_remote_display_strings(self):
        self.run_js(r'''
routes.set('/api/status',()=>response({ok:true,targets:[{id:'router_a',name:'<script>x</script>',
 address:'192.0.2.1',active:'<img src=x>',state:'<svg onload=x>'}]}));
assert.equal(await refresh(),true);
assert.equal($('#targetGrid').querySelectorAll('script, img, svg').length,0);
assert.ok($('#targetGrid').innerHTML.includes('&lt;img'));
''')
