"""Round-two state regressions; real JS, synthetic DOM/I/O, no live requests."""
import unittest

import test_frontend_audit_resume as custom_fixture
import test_converter_apply_frontend as converter_fixture


class CustomOrderRound2Tests(unittest.TestCase):
    run_js = custom_fixture.FrontendAuditResumeTests.run_js

    @classmethod
    def setUpClass(cls):
        custom_fixture.FrontendAuditResumeTests.setUpClass.__func__(cls)

    def test_opening_saved_rule_for_edit_preserves_payload_order_and_clean_state(self):
        self.run_js(r'''
const fixture = resumeManaged('rule');
const before = collectCustom();
await fixture.edit(fixture.values[0]);
assert.deepEqual(collectCustom(), before, 'opening an edit must not change rule precedence');
assert.equal(draftFlags().custom, false);
assert.deepEqual(validationRows('rules'), [$('#ruleList .rule-row'), null, null]);
assert.equal(requestLog.length, 0);
''')

    def test_edited_matcher_stays_in_its_original_precedence_slot(self):
        self.run_js(r'''
resumeManaged('rule');
savedRules = [
  {type:'DOMAIN-SUFFIX',value:'example.test',policy:'DIRECT'},
  {type:'DOMAIN',value:'api.example.test',policy:'REJECT'},
];
renderManagedRules(); customBaseline = JSON.stringify(collectCustom());
await $('#managedRuleList .ghost').click();
const row = $('#ruleList .rule-row');
row.querySelector('.rule-value').value = 'edited.example.test';
assert.deepEqual(collectCustom().rules, [
  {type:'DOMAIN-SUFFIX',value:'edited.example.test',policy:'DIRECT'},
  {type:'DOMAIN',value:'api.example.test',policy:'REJECT'},
]);
assert.equal(draftFlags().custom, true);
assert.deepEqual(validationRows('rules'), [row, null]);
showCustomResult({ok:false,message:'synthetic invalid',errors:[
  {section:'rules',index:0,field:'value',message:'first rule error'},
]});
assert.equal(row.querySelector('.row-error').textContent, 'first rule error');
assert.equal(row.querySelector('.rule-value').getAttribute('aria-invalid'), 'true');
await row.querySelector('.remove-row').click();
assert.equal(draftFlags().custom, false);
assert.equal(collectCustom().rules[0].value, 'example.test');
assert.equal(requestLog.length, 0);
''')

    def test_multi_edit_delete_reconciliation_and_new_rows_share_the_same_mapping(self):
        self.run_js(r'''
const fixture = resumeManaged('rule');
const [a,b,c] = fixture.values;
const reconciliation = {type:'DOMAIN',value:'reconcile.example.test',policy:'DIRECT'};
reconciliationRules = [reconciliation];
await fixture.edit(c); await fixture.edit(a); await fixture.remove(b);
const rows = $$('#ruleList .rule-row');
const fresh = addRule({type:'DOMAIN',value:'new.example.test',policy:'DIRECT'});
assert.deepEqual(collectCustom().rules.map(rule => rule.value), [a,c,reconciliation.value,'new.example.test']);
assert.deepEqual(validationRows('rules'), [rows[1],rows[0],null,fresh]);
await fixture.cancel(a);
assert.deepEqual(collectCustom().rules.map(rule => rule.value), [a,c,reconciliation.value,'new.example.test']);
assert.deepEqual(validationRows('rules'), [null,rows[0],null,fresh]);
assert.equal(requestLog.length, 0);
''')

    def test_filter_edits_do_not_manufacture_order_only_drafts(self):
        self.run_js(r'''
const fixture = resumeManaged('filter');
const before = collectCustom();
await fixture.edit(fixture.values[1]); await fixture.edit(fixture.values[0]);
const rows = $$('#filterList .filter-row');
assert.deepEqual(collectCustom(), before);
assert.equal(draftFlags().custom, false);
assert.deepEqual(validationRows('fake_ip_filter'), [rows[1],rows[0],null]);
rows[1].querySelector('.filter-value').value = '*.edited.example.test';
assert.deepEqual(collectCustom().fake_ip_filter, ['*.edited.example.test',fixture.values[1],fixture.values[2]]);
assert.equal(draftFlags().custom, true);
assert.equal(requestLog.length, 0);
''')


class ConverterPresetRound2Tests(unittest.TestCase):
    run_js = converter_fixture.ConverterApplyFrontendTests.run_js

    @classmethod
    def setUpClass(cls):
        converter_fixture.ConverterApplyFrontendTests.setUpClass.__func__(cls)

    def test_cancelled_preset_keeps_clean_form_and_makes_no_request(self):
        self.run_js(r'''
await $('#loadConverter').click();
const form = converterForm(), state = $('#converterState').textContent, count = requestLog.length;
assert.equal(converterDirty(), false);
window.confirm = () => false;
await inputValue('converterProfile','router_b','change');
assert.deepEqual(converterForm(), form);
assert.equal(converterDirty(), false);
assert.equal($('#converterState').textContent, state);
assert.equal(requestLog.length, count);
''')

    def test_cancelled_preset_keeps_generated_link_and_manual_selection(self):
        self.run_js(r'''
await converterFixture();
await inputValue('converterConfig','https://config.example.test/manual.ini');
routes.set('/api/converter/link', body => validLink(body));
await $('#converterForm').dispatch('submit');
assert.ok(converterResult);
const before = {form:converterForm(),signature:converterDraftSignature(),dirty:converterDirty(),
  link:converterResult,target:converterResultTarget,state:$('#converterState').textContent};
const count = requestLog.length;
window.confirm = () => false;
await inputValue('converterProfile','router_b','change');
assert.equal($('#converterProfile').value, 'manual');
assert.deepEqual(converterForm(), before.form);
assert.equal(converterDraftSignature(), before.signature);
assert.equal(converterDirty(), before.dirty);
assert.equal(converterResult, before.link);
assert.equal(converterResultTarget, before.target);
assert.equal($('#converterOutput').value, before.link);
assert.equal($('#converterState').textContent, before.state);
assert.equal($('#copyConverter').disabled, false);
assert.equal(requestLog.length, count);
''')

    def test_cancelled_preset_keeps_current_result_edited_text_and_preview_proof(self):
        self.run_js(r'''
await applyFixture();
await inputValue('converterText', syntheticText + '# edited\n');
await readyApply();
const form = converterForm(), signature = converterDraftSignature(), dirty = converterDirty();
const exported = JSON.stringify(converterExport), text = $('#converterText').value;
const preview = applyText(), summary = $('#converterApplySummary').textContent, count = requestLog.length;
window.confirm = () => false;
await inputValue('converterProfile','router_b','change');
assert.deepEqual(converterForm(), form);
assert.equal(converterDraftSignature(), signature); assert.equal(converterDirty(), dirty);
assert.equal(JSON.stringify(converterExport), exported);
assert.equal($('#converterText').value, text);
assert.equal(applyState(), 'ready'); assert.equal(applyText(), preview);
assert.equal($('#converterApplySummary').textContent, summary);
assert.equal($('#applyConverterResult').disabled, false);
assert.equal(requestLog.length, count); assert.equal(callsTo(routerApplyPath).length, 0);
''')

    def test_accepting_preset_still_replaces_options_and_invalidates_link(self):
        self.run_js(r'''
await converterFixture();
routes.set('/api/converter/link', body => validLink(body));
await $('#converterForm').dispatch('submit'); assert.ok(converterResult);
const count = requestLog.length; window.confirm = () => true;
await inputValue('converterProfile','router_b','change');
assert.equal(converterForm().profile, 'router_b');
assert.deepEqual(converterForm().options, CONVERTER_SCHEMA.presets.find(p=>p.id==='router_b').options);
assert.equal(converterResult, ''); assert.equal($('#copyConverter').disabled, true);
assert.equal(requestLog.length, count);
''')


if __name__ == '__main__':
    unittest.main()
