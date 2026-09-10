"""Resume audit regressions: real JS with synthetic-only DOM/I/O.

Disabled controls deliberately cannot receive focus, as in a real browser.
The browser/visual evidence is separate; this harness does not claim layout QA.
"""
import unittest

import test_chain_frontend as fixture


class FrontendAuditResumeTests(unittest.TestCase):
    run_js = fixture.ChainFrontendTests.run_js

    @classmethod
    def setUpClass(cls):
        fixture.ChainFrontendTests.setUpClass.__func__(cls)
        cls.app += r'''
const enabledFocus = MiniElement.prototype.focus;
MiniElement.prototype.focus = function () {if (!this.disabled) enabledFocus.call(this);};
const resumeText = 'first\nsecond\nthird';
async function resumeEditor() {
  switchPanel('editor');
  routes.set('/api/read', () => response({ok:true,sha256:'a'.repeat(64),content:resumeText}));
  await $('#readConfig').click();
  assert.equal($('#saveConfig').disabled, false);
}
function resumeManaged(kind, count = 3) {
  $('#ruleList').replaceChildren(); $('#filterList').replaceChildren();
  savedRules = []; savedFilters = [];
  const values = ['a.example.test','b.example.test','c.example.test','d.example.test'].slice(0,count);
  if (kind === 'rule') savedRules = values.map(value => ({type:'DOMAIN',value,policy:'DIRECT'}));
  else savedFilters = values.slice();
  renderManagedRules(); renderManagedFilters();
  customBaseline = JSON.stringify(collectCustom());
  const list = kind === 'rule' ? $('#managedRuleList') : $('#managedFilterList');
  const drafts = kind === 'rule' ? $('#ruleList') : $('#filterList');
  const field = kind === 'rule' ? '.rule-value' : '.filter-value';
  return {
    values,
    edit: value => list.querySelectorAll('.managed-item').find(row => row.querySelector('code').textContent.includes(value)).querySelector('.ghost').click(),
    cancel: value => drafts.querySelectorAll('.custom-row').find(row => row.querySelector(field).value === value).querySelector('.remove-row').click(),
    remove: value => list.querySelectorAll('.managed-item').find(row => row.querySelector('code').textContent.includes(value)).querySelector('.remove-row').click(),
    read: () => kind === 'rule' ? savedRules.map(rule => rule.value) : savedFilters.slice()
  };
}
'''

    def test_navigation_focus_scrolls_without_switching_panel_or_requesting(self):
        self.run_js(r'''
const active = $('.panel.active');
const scrolls = [];
for (const button of $$('.nav-item')) {
  button.scrollIntoView = options => scrolls.push({panel:button.dataset.panel,options});
}
for (const panel of ['editor','chain','custom']) {
  await $('.nav-item[data-panel="' + panel + '"]').dispatch('focus');
  assert.ok($('.panel.active') === active, 'focus alone must not select a panel');
}
assert.deepEqual(scrolls.map(item => item.panel), ['editor','chain','custom']);
assert.ok(scrolls.every(item => item.options.block === 'nearest' && item.options.inline === 'nearest'));
assert.equal(requestLog.length, 0, 'focus-only navigation must not request data');
''')

    def test_yaml_editor_disables_soft_wrap(self):
        control = next(node for node in self.page.elements if node['attrs'].get('id') == 'yamlEditor')
        self.assertEqual(control['attrs'].get('wrap'), 'off')

    def test_save_error_focus_waits_for_global_unlock(self):
        self.run_js(r'''
await resumeEditor();
routes.set('/api/validate', () => response({ok:false,message:'synthetic parse error',line:3,column:2}));
await $('#saveConfig').click();
assert.equal(operationBusy, false);
assert.equal(editor.disabled, false);
assert.ok(document.activeElement === editor);
assert.equal(editor.selectionStart, 14);
assert.equal($('#cursorPosition').textContent, '第 3 行，第 2 列');
assert.equal($('#saveConfig').disabled, true);
assert.equal(requestLog.filter(request => request.path === '/api/write').length, 0);
''')

    def test_error_focus_does_not_steal_focus_from_another_panel(self):
        self.run_js(r'''
await resumeEditor();
const pending = deferred(); routes.set('/api/validate', () => pending.promise);
const save = $('#saveConfig').click(); await settle();
const navigation = $('.nav-item[data-panel="custom"]');
navigation.focus(); await navigation.click();
pending.resolve(response({ok:false,message:'synthetic parse error',line:3,column:2})); await save;
assert.ok(document.activeElement === navigation);
assert.equal($('#custom').classList.contains('active'), true);
assert.equal(operationBusy, false);
''')

    def test_same_yaml_validation_is_single_flight_and_merges_focus(self):
        self.run_js(r'''
switchPanel('editor'); editor.value = resumeText; editorLines();
const pending = deferred(); routes.set('/api/validate', () => pending.promise);
const first = validate(false), second = validate(true), third = validate(true);
assert.equal(requestLog.filter(request => request.path === '/api/validate').length, 1);
assert.equal($('#validateYaml').getAttribute('aria-busy'), 'true');
pending.resolve(response({ok:false,message:'synthetic parse error',line:2,column:3}));
assert.deepEqual(await Promise.all([first,second,third]), [false,false,false]);
assert.ok(document.activeElement === editor);
assert.equal(editor.selectionStart, 8);
assert.equal($('#validateYaml').getAttribute('aria-busy'), 'false');
''')

    def test_yaml_validation_does_not_reuse_settled_result(self):
        self.run_js(r'''
editor.value = resumeText;
await validate(); await validate();
assert.equal(requestLog.filter(request => request.path === '/api/validate').length, 2);
''')

    def test_changed_yaml_supersedes_pending_without_releasing_new_busy_state(self):
        self.run_js(r'''
editor.value = 'first';
const first = deferred(), second = deferred(); let count = 0;
routes.set('/api/validate', () => ++count === 1 ? first.promise : second.promise);
const old = validate(true); editor.value = 'second'; await editor.dispatch('input');
const current = validate(false);
assert.equal(count, 2); assert.equal(requestLog.filter(r => r.path === '/api/validate')[0].signal.aborted, true);
first.resolve(response({ok:false,message:'old error',line:1,column:1})); await old;
assert.equal($('#validateYaml').getAttribute('aria-busy'), 'true');
second.resolve(response({ok:true,summary:{proxies:0,groups:0,rules:0}})); await current;
assert.equal(yamlIsValid, true); assert.equal($('#validateYaml').getAttribute('aria-busy'), 'false');
assert.ok(!$('#validationState').textContent.includes('old error'));
''')

    def test_yaml_binding_change_cannot_reuse_old_validation(self):
        self.run_js(r'''
editor.value = resumeText;
const pending = deferred(); routes.set('/api/validate', () => pending.promise);
const old = validate(); $('#editorTarget').value = 'router_b'; clearEditorBinding();
routes.set('/api/validate', () => response({ok:true,summary:{proxies:0,groups:0,rules:0}}));
await validate(); pending.resolve(response({ok:false,message:'old target',line:1,column:1})); await old;
assert.equal(requestLog.filter(r => r.path === '/api/validate').length, 2);
assert.equal(yamlIsValid, true); assert.equal($('#saveConfig').disabled, true);
''')

    def test_yaml_validation_failure_allows_explicit_retry(self):
        self.run_js(r'''
routes.set('/api/validate', () => {throw new Error('synthetic unavailable')});
assert.equal(await validate(true), false);
assert.equal($('#validateYaml').getAttribute('aria-busy'), 'false');
routes.set('/api/validate', () => response({ok:true,summary:{proxies:0,groups:0,rules:0}}));
assert.equal(await validate(), true);
assert.equal(requestLog.filter(r => r.path === '/api/validate').length, 2);
''')

    def test_custom_validation_is_single_flight_for_identical_draft(self):
        self.run_js(r'''
const pending = deferred(); let body;
routes.set('/api/custom/validate', value => {body=value; return pending.promise;});
const first = validateCustom(), second = validateCustom();
assert.equal(requestLog.filter(r => r.path === '/api/custom/validate').length, 1);
pending.resolve(response({ok:true,...body.customization,summary:{rules:0,fake_ip_filter:0}}));
assert.deepEqual(await Promise.all([first,second]), [true,true]);
assert.equal($('#validateCustom').getAttribute('aria-busy'), 'false');
''')

    def test_changed_custom_validation_supersedes_without_reusing_old_request(self):
        self.run_js(r'''
const pending = deferred(); routes.set('/api/custom/validate', () => pending.promise);
const old = validateCustom(); addFilter('example.test'); scheduleCustomValidation();
routes.set('/api/custom/validate', body => response({ok:true,...body.customization,summary:{rules:0,fake_ip_filter:1}}));
assert.equal(await validateCustom(), true);
pending.resolve(response({ok:false,message:'old draft'})); await old;
assert.equal(requestLog.filter(r => r.path === '/api/custom/validate').length, 2);
assert.equal(customIsValid, true); assert.equal($('#validateCustom').getAttribute('aria-busy'), 'false');
''')

    def test_custom_http_error_details_still_mark_each_draft_row(self):
        self.run_js(r'''
addRule({type:'DOMAIN',value:'a.example.test',policy:'DIRECT'});
addFilter('*.a.example.test');
routes.set('/api/custom/validate', () => response({ok:false,message:'synthetic conflict',errors:[
  {section:'rules',index:0,field:'value',message:'synthetic rule <detail>'},
  {section:'fake_ip_filter',index:0,field:'value',message:'synthetic filter detail'}
]}, 400));
assert.equal(await validateCustom(), false);
assert.equal($('#customValidation').textContent, 'synthetic conflict');
assert.equal($('#ruleList .row-error').textContent, 'synthetic rule <detail>');
assert.equal($('#filterList .row-error').textContent, 'synthetic filter detail');
assert.equal($('#ruleList .rule-row').classList.contains('invalid'), true);
assert.equal($('#filterList .filter-row').classList.contains('invalid'), true);
assert.equal($('#saveCustom').disabled, true);
routes.set('/api/custom/validate', () => response({ok:false,message:'synthetic malformed details',errors:{message:'not an array'}}, 400));
assert.equal(await validateCustom(), false);
assert.equal($('#customValidation').textContent, 'synthetic malformed details');
assert.equal($('#ruleList .row-error').textContent, '');
assert.equal($('#filterList .row-error').textContent, '');
assert.equal($('#ruleList .rule-row').classList.contains('invalid'), false);
''')

    def test_cancel_order_is_stable_for_rules_and_filters(self):
        self.run_js(r'''
for (const kind of ['rule','filter']) {
  for (const editOrder of [[0,1,2],[2,1,0],[1,0,2]]) {
    for (const cancelOrder of [[0,1,2],[2,1,0],[1,0,2]]) {
      const fixture = resumeManaged(kind);
      for (const index of editOrder) await fixture.edit(fixture.values[index]);
      for (const index of cancelOrder) await fixture.cancel(fixture.values[index]);
      assert.deepEqual(fixture.read(), fixture.values, kind + '/' + editOrder + '/' + cancelOrder);
      assert.equal(draftFlags().custom, false, 'cancelling must not manufacture an order-only draft');
    }
  }
}
assert.equal(requestLog.length, 0);
''')

    def test_large_managed_order_restore_uses_linear_rank_lookups(self):
        self.run_js(r'''
const items = Array.from({length:10000}, (_,index) => ({value:'synthetic-' + index}));
const original = items.slice(), restore = takeManagedEdit(items, 9999);
assert.ok(restore.order instanceof Map);
let lookups = 0;
const get = restore.order.get.bind(restore.order);
restore.order.get = value => {lookups++; return get(value);};
assert.equal(restoreManagedEdit(items, restore), 9999);
assert.deepEqual(items, original);
assert.equal(lookups, 9999);
''')

    def test_cancel_around_a_staged_delete_restores_relative_order_and_focus(self):
        self.run_js(r'''
for (const kind of ['rule','filter']) {
  const fixture = resumeManaged(kind, 4), [a,b,c,d] = fixture.values;
  await fixture.edit(b); await fixture.edit(d); await fixture.remove(a);
  await fixture.cancel(d); await fixture.cancel(b);
  assert.deepEqual(fixture.read(), [b,c,d]);
  assert.equal(document.activeElement.getAttribute('aria-label'), '编辑 ' + (kind === 'rule' ? 'DOMAIN,' + b + ',DIRECT' : b));
}
assert.equal(requestLog.length, 0);
''')


if __name__ == '__main__':
    unittest.main()
