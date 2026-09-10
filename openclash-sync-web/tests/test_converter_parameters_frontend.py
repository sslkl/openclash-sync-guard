"""Synthetic frontend coverage for optional main-conversion template parameters.

Runs the real HTML/app.js/converter.js with the existing Node DOM/API fixture.
No browser, external requests, native converter or production credentials.
"""
import re
import unittest
import test_converter_frontend as fixture


class ConverterParametersFrontendTests(unittest.TestCase):
    run_js = fixture.ConverterFrontendTests.run_js

    @classmethod
    def setUpClass(cls):
        fixture.ConverterFrontendTests.setUpClass.__func__(cls)
        cls.css = (fixture.ROOT / 'static/app.css').read_text()
        cls.app += r'''
const downloads = [], downloadNames = [];
URL.createObjectURL = blob => {downloads.push(blob); return 'blob:synthetic';};
URL.revokeObjectURL = () => {};
const originalParameterClick = MiniElement.prototype.click;
MiniElement.prototype.click = function() {
  if (this.tagName === 'A') downloadNames.push(this.getAttribute('download'));
  return originalParameterClick.call(this);
};
MiniElement.prototype.setCustomValidity = function(message) {this.validationMessage = message;};
async function parameterInput(value) {await inputValue('converterParameters', JSON.stringify(value));}
async function importParameterArchive(text) {
  $('#converterArchiveUpload').files = [syntheticFile('parameters-v1.json', text)];
  await $('#converterArchiveUpload').dispatch('change');
}
'''

    def test_parameter_markup_and_local_layout_guards(self):
        nodes = {n['attrs']['id']: n for n in self.page.elements if 'id' in n['attrs']}
        self.assertEqual(len(nodes), sum('id' in n['attrs'] for n in self.page.elements))
        field = nodes['converterParameters']
        self.assertEqual(field['tag'], 'textarea')
        self.assertEqual(''.join(n.get('text', '') for n in field['children']), '{}')
        self.assertEqual(field['attrs']['autocomplete'], 'off')
        self.assertEqual(field['attrs']['spellcheck'], 'false')
        self.assertEqual(field['attrs']['aria-invalid'], 'false')
        self.assertIn('disabled', field['attrs'])
        self.assertTrue(any(n['tag'] == 'label' and n['attrs'].get('for') == 'converterParameters'
                            for n in self.page.elements))
        for identifier in field['attrs']['aria-describedby'].split():
            self.assertIn(identifier, nodes)
        state = nodes['converterParametersState']['attrs']
        self.assertEqual((state['role'], state['aria-live'], state['aria-atomic']), ('status', 'polite', 'true'))
        self.assertEqual(nodes['converterTarget']['attrs']['aria-describedby'], 'converterTargetHint')
        self.assertIn('hidden', nodes['converterTargetHint']['attrs'])
        for pattern in (r'\.badge\s*\{[^}]*white-space:\s*nowrap',
                        r'\.panel-head\s*\{[^}]*align-items:\s*flex-start',
                        r'#loadConverter\s*\{[^}]*align-self:\s*flex-start',
                        r'\.sidebar\s*\{[^}]*overflow-x:\s*auto',
                        r'\.nav-item\s*\{[^}]*white-space:\s*nowrap',
                        r'\[aria-invalid="true"\]:focus-visible',
                        r'#converterTargetHint\[hidden\]\s*\{display:none\}',
                        r'@media\s*\(max-width:\s*480px\)'):
            with self.subTest(pattern=pattern):
                self.assertRegex(self.css, re.compile(pattern))

    def test_empty_parameters_are_optional_and_edits_are_local(self):
        self.run_js(r'''
await converterFixture(); requestLog.length = 0;
assert.equal(converterParameterContract(converterSchema), converterSchema.parameters);
assert.equal(converterForm().parameters, undefined); assert.equal(converterHasLocal(), false);
for (const text of ['', '  \n\t ', '{}']) {
  await inputValue('converterParameters', text);
  assert.equal(Object.hasOwn(converterForm(), 'parameters'), false);
  assert.equal($('#converterParameters').getAttribute('aria-invalid'), 'false');
}
await parameterInput({title:'Synthetic', 'region.code':'HK', 'theme-color':'green', empty:''});
assert.equal(converterForm().parameters.title, 'Synthetic'); assert.equal(converterHasLocal(), false);
assert.equal($('#generateConverter').disabled, false); assert.equal($('#executeConverter').disabled, false);
assert.equal(converterForm().profile, 'manual'); assert.equal(converterDirty(), true);
assert.equal(requestLog.length, 0);
''')

    def test_names_and_object_count_boundaries(self):
        self.run_js(r'''
await converterFixture();
for (const key of ['a', 'Z'.repeat(64), 'custom.tag_1-2']) {
  assert.deepEqual(converterParameters(JSON.stringify({[key]:''})), {[key]:''});
}
for (const key of ['', 'a'.repeat(65), '1first', '_first', '-first', '.first', '中文', 'a b', 'a/b', 'a?b', 'a&b', 'title\n', 'title\r', 'title\u2028', 'title\u2029', 'a\ud800']) {
  assert.throws(() => converterParameters(JSON.stringify({[key]:'x'})), undefined, 'key rejected');
}
const full = Object.fromEntries(Array.from({length:32}, (_, i) => ['custom' + i, 'x']));
assert.equal(Object.keys(converterParameters(JSON.stringify(full))).length, 32);
assert.throws(() => converterParameters(JSON.stringify({...full, extra:'x'})));
for (const value of [null, [], '', 1, false, Object.create({inherited:'x'})]) assert.throws(() => converterValidateParameters(value));
''')

    def test_values_are_strings_with_utf8_control_and_unicode_limits(self):
        self.run_js(r'''
await converterFixture();
for (const value of ['', 'x'.repeat(4096), '文'.repeat(1365) + 'a', '😀'.repeat(1024), '&=+% 空格']) {
  assert.equal(converterParameters(JSON.stringify({title:value})).title, value);
}
for (const value of [null, 0, true, {}, [], 'x'.repeat(4097), '文'.repeat(1366), '😀'.repeat(1025), '\ud800', '\udfff']) {
  assert.throws(() => converterParameters(JSON.stringify({title:value})));
}
for (const code of [...Array.from({length:32}, (_, i) => i), ...Array.from({length:33}, (_, i) => i + 127)]) {
  assert.throws(() => converterParameters(JSON.stringify({title:'a' + String.fromCharCode(code) + 'b'})));
}
assert.equal(converterParameterBytes({title:'文', empty:''}), 13);
''')

    def test_reserved_fields_are_case_insensitive_and_catalog_driven(self):
        self.run_js(r'''
await converterFixture();
const reserved = new Set([...converterSchema.parameters.reserved, ...Object.keys(converterSchema.booleans),
  ...Object.keys(converterSchema.texts), ...Object.keys(converterSchema.integers),
  'target', 'url', 'path', 'token', 'upload', 'groups', 'ruleset', 'profile_data', 'constructor', 'prototype']);
for (const name of reserved) {
  for (const key of [name, name.toUpperCase(), name[0].toUpperCase() + name.slice(1)]) {
    assert.throws(() => converterValidateParameters({[key]:'synthetic'}), undefined, 'reserved: ' + key);
  }
}
assert.deepEqual(converterParameters('{"future_control":"x"}'), {future_control:'x'});
converterSchema.parameters.reserved.push('future_control');
assert.throws(() => converterParameters('{"FUTURE_CONTROL":"x"}'));
const form = converterForm(); form.options.unknown_custom = 'not a custom parameter';
assert.throws(() => converterValidateForm(form), /未知/);
''')

    def test_invalid_json_does_not_escape_input_dirty_or_control_events(self):
        self.run_js(r'''
await converterFixture(); requestLog.length = 0;
const bad = ['{', '{"title":"synthetic_private_fragment"', '[]', 'null', '{"title":1}',
  '{"title":"a","title":"b"}', '{"title":"a","ti\\u0074le":"b"}',
  '{"constructor":"x"}', '{"__proto__":{"polluted":true}}', '{"title":"a\\nb"}'];
for (const text of bad) {
  await inputValue('converterParameters', text);
  assert.equal($('#converterParameters').value, text);
  assert.equal($('#converterParameters').getAttribute('aria-invalid'), 'true');
  assert.ok($('#converterParameters').validationMessage);
  assert.ok($('#converterParametersState').textContent.includes('草稿已保留'));
  assert.ok(!$('#converterParametersState').textContent.includes('synthetic_private_fragment'));
  assert.doesNotThrow(updateConverterControls); assert.doesNotThrow(updateDraftNotice); assert.equal(converterDirty(), true);
  for (const id of ['generateConverter', 'validateConverter', 'executeConverter', 'exportConverterArchive']) assert.equal($('#' + id).disabled, true);
  // A programmatic submit must be rejected too, rather than relying on disabled buttons.
  await $('#converterForm').dispatch('submit');
  assert.equal(operationBusy, false); assert.equal($('#clearConverter').disabled, false);
  assert.equal($('#converterParameters').value, text);
}
assert.equal((await window.dispatch('beforeunload')).defaultPrevented, true);
assert.equal(requestLog.length, 0); assert.equal({}.polluted, undefined);
await parameterInput({title:'repaired'});
assert.equal($('#converterParameters').getAttribute('aria-invalid'), 'false');
assert.equal($('#converterParameters').validationMessage, ''); assert.equal($('#executeConverter').disabled, false);
''')

    def test_raw_parameter_json_is_bounded_without_losing_draft(self):
        self.run_js(r'''
await converterFixture(); requestLog.length = 0;
const text = '{' + ' '.repeat(converterSchema.limits.content_bytes) + '}';
await inputValue('converterParameters', text);
assert.equal($('#converterParameters').value, text); assert.equal(converterDirty(), true);
assert.equal($('#converterParameters').getAttribute('aria-invalid'), 'true');
assert.ok($('#converterParametersState').textContent.includes('字节')); assert.equal(requestLog.length, 0);
''')

    def test_same_parameter_values_go_to_link_validation_and_execution(self):
        self.run_js(r'''
await converterFixture();
const parameters = {title:'A & B=1 + 100% / 中文', 'region.code':'HK', empty:''};
await parameterInput(parameters); requestLog.length = 0;
routes.set('/api/converter/link', validLink);
routes.set('/api/converter/validate', () => response({ok:true, summary:{source_count:1, network_executed:false, router_changed:false}}));
routes.set('/api/converter/execute', body => response(executionResult(body)));
await $('#converterForm').dispatch('submit');
const url = new URL(converterResult);
for (const [key, value] of Object.entries(parameters)) assert.deepEqual(url.searchParams.getAll(key), [value]);
await $('#validateConverter').click(); await $('#executeConverter').click();
const sent = requestLog.filter(item => /^\/api\/converter\/(link|validate|execute)$/.test(item.path));
assert.deepEqual(sent.map(item => item.path), ['/api/converter/link', '/api/converter/validate', '/api/converter/execute']);
for (const item of sent) {
  assert.deepEqual(item.body.form.parameters, parameters); assert.match(item.body.nonce, /^token-\d+$/);
  for (const key of Object.keys(parameters)) assert.equal(Object.hasOwn(item.body.form.options, key), false);
}
assert.equal(converterExport.current, true);
assert.ok(requestLog.every(item => ['/api/bootstrap', ...sent.map(entry => entry.path)].includes(item.path)));
''')

    def test_link_response_must_preserve_each_custom_parameter_once(self):
        self.run_js(r'''
await converterFixture(); await parameterInput({title:'A&B = 中文'});
for (const mutate of [params => params.delete('title'), params => params.set('title', 'changed'), params => params.append('title', 'A&B = 中文')]) {
  routes.set('/api/converter/link', async body => {
    const result = await validLink(body).json(), url = new URL(result.link);
    mutate(url.searchParams); return response({...result, link:url.href});
  });
  await $('#converterForm').dispatch('submit');
  assert.equal(converterResult, ''); assert.equal($('#copyConverter').disabled, true);
  assert.ok($('#notice').textContent.includes('未完整保留')); assert.equal(operationBusy, false);
}
routes.set('/api/converter/link', validLink); await $('#converterForm').dispatch('submit');
assert.ok(converterResult); assert.equal($('#copyConverter').disabled, false);
''')

    def test_presets_restore_parameters_and_cancel_keeps_invalid_draft(self):
        self.run_js(r'''
await converterFixture(); await inputValue('converterPaste', 'keep local'); requestLog.length = 0;
const incomplete = '{"title":'; await inputValue('converterParameters', incomplete);
confirmation = false; await inputValue('converterProfile', 'router_b', 'change');
assert.equal($('#converterParameters').value, incomplete); assert.equal($('#converterProfile').value, 'manual');
confirmation = true; await inputValue('converterProfile', 'router_b', 'change');
assert.equal($('#converterParameters').value, '{}'); assert.equal($('#converterPaste').value, 'keep local');
assert.equal(converterForm().sources, exampleSource);
converterSchema.presets.find(item => item.id === 'router_a').parameters = {title:'Preset template'};
await inputValue('converterProfile', 'router_a', 'change'); assert.equal(converterForm().parameters.title, 'Preset template');
await $('#clearConverter').click(); assert.equal($('#converterParameters').value, '{}');
assert.equal(Object.hasOwn(converterForm(), 'parameters'), false); assert.equal(converterDirty(), false);
assert.equal(requestLog.length, 0);
''')

    def test_parse_restores_optional_parameters_without_extra_requests(self):
        self.run_js(r'''
await converterFixture(); requestLog.length = 0;
const parsed = {sources:[exampleSource, exampleSource], backend:converterSchema.backend, profile:'manual', options:{target:'clash'}, parameters:{title:'Parsed 中文'}};
routes.set('/api/converter/parse', () => response({ok:true, form:parsed}));
await inputValue('converterImport', 'https://converter.example.test/sub?title=synthetic'); await $('#parseConverter').click();
assert.deepEqual(converterForm().parameters, parsed.parameters);
assert.equal(converterForm().sources, exampleSource + '\n' + exampleSource); assert.equal($('#converterImport').value, '');
delete parsed.parameters;
await inputValue('converterImport', 'https://converter.example.test/sub?url=synthetic'); await $('#parseConverter').click();
assert.equal($('#converterParameters').value, '{}'); assert.equal(Object.hasOwn(converterForm(), 'parameters'), false);
assert.ok(requestLog.every(item => ['/api/converter/parse', '/api/bootstrap'].includes(item.path)));
''')

    def test_bad_parse_parameters_do_not_partially_clear_existing_drafts(self):
        self.run_js(r'''
await converterFixture(); routes.set('/api/converter/execute', body => response(executionResult(body)));
await $('#executeConverter').click(); await inputValue('converterText', 'keep edited result');
await inputValue('converterPaste', 'keep local'); await inputValue('converterParameters', '{"title":');
const signature = converterDraftSignature(), raw = $('#converterParameters').value;
routes.set('/api/converter/parse', () => response({ok:true, form:{sources:[exampleSource], options:{target:'clash'}, parameters:{TOKEN:'blocked'}}}));
await inputValue('converterImport', 'https://converter.example.test/sub?title=synthetic');
await $('#parseConverter').click();
assert.equal(converterDraftSignature(), signature); assert.equal($('#converterParameters').value, raw);
assert.equal($('#converterPaste').value, 'keep local'); assert.equal($('#converterText').value, 'keep edited result');
assert.ok($('#converterImport').value); assert.equal(operationBusy, false);
assert.throws(() => setConverterForm({options:{target:'surge'}, parameters:{Path:'blocked'}}));
assert.equal(converterDraftSignature(), signature);
''')

    def test_v1_archive_roundtrip_includes_only_nonempty_parameters(self):
        self.run_js(r'''
await converterFixture(); await parameterInput({title:'Local archive 中文', empty:''});
const expected = converterArchive(); requestLog.length = 0;
await $('#exportConverterArchive').click(); assert.equal(downloads.length, 1);
const text = await downloads[0].text(), archive = JSON.parse(text);
assert.deepEqual(archive, expected); assert.equal(archive.version, 1);
assert.deepEqual(archive.form.parameters, {title:'Local archive 中文', empty:''});
for (const key of ['result', 'content', 'nonce', 'converterExport']) assert.equal(Object.hasOwn(archive, key), false);
await $('#clearConverter').click(); await importParameterArchive(text);
assert.deepEqual(converterArchive(), expected); assert.equal(converterExport, null); assert.equal(converterToolExports.size, 0);
const legacy = JSON.parse(text); delete legacy.form.parameters;
await importParameterArchive(JSON.stringify(legacy));
assert.equal($('#converterParameters').value, '{}'); assert.equal(Object.hasOwn(converterArchive().form, 'parameters'), false);
assert.equal(converterArchive().version, 1); assert.equal(requestLog.length, 0);
''')

    def test_bad_archive_parameters_are_rejected_before_confirmation_or_apply(self):
        self.run_js(r'''
await converterFixture(); await parameterInput({title:'Keep input'});
routes.set('/api/converter/execute', body => response(executionResult(body)));
await $('#executeConverter').click(); await inputValue('converterText', 'Keep result draft');
const signature = JSON.stringify(converterArchive()), beforeConfirms = confirmations; requestLog.length = 0;
const many = Object.fromEntries(Array.from({length:33}, (_, i) => ['custom' + i, 'x']));
for (const value of [null, [], {title:42}, {PATH:'blocked'}, {title:'a\nb'}, {title:'\ud800'}, {title:'x'.repeat(4097)}, many]) {
  const candidate = JSON.parse(signature); candidate.form.parameters = value;
  await importParameterArchive(JSON.stringify(candidate));
  assert.equal(JSON.stringify(converterArchive()), signature); assert.equal($('#converterText').value, 'Keep result draft');
  assert.ok($('#converterArchiveState').textContent.includes('未应用')); assert.equal(operationBusy, false);
}
const duplicate = signature.replace('"parameters":{"title":"Keep input"}', '"parameters":{"title":"first","title":"last"}');
assert.notEqual(duplicate, signature); await importParameterArchive(duplicate);
const resultClaim = JSON.parse(signature); resultClaim.result = {current:true}; await importParameterArchive(JSON.stringify(resultClaim));
assert.equal(JSON.stringify(converterArchive()), signature); assert.equal(confirmations, beforeConfirms);
assert.equal(requestLog.length, 0); assert.equal(downloads.length, 0);
''')

    def test_parameter_edits_invalidate_results_but_preserve_downloadable_draft(self):
        self.run_js(r'''
await converterFixture(); routes.set('/api/converter/link', validLink);
await parameterInput({title:'first'}); await $('#converterForm').dispatch('submit'); assert.ok(converterResult);
await parameterInput({title:'second'}); assert.equal(converterResult, ''); assert.equal($('#converterOutput').value, '');
routes.set('/api/converter/execute', body => response(executionResult(body))); await $('#executeConverter').click();
assert.equal(converterExport.current, true); await inputValue('converterText', 'Manual edited result');
requestLog.length = 0; await inputValue('converterParameters', '{"title":');
assert.equal(converterExport.current, false); assert.equal($('#converterText').value, 'Manual edited result');
assert.equal($('#downloadConverter').disabled, false); assert.equal($('#executeConverter').disabled, true);
assert.doesNotThrow(converterFilename);
confirmation = false; await $('#downloadConverter').click(); assert.equal(downloads.length, 0);
confirmation = true; await $('#downloadConverter').click();
assert.equal(downloads.length, 1); assert.equal(await downloads[0].text(), 'Manual edited result');
assert.ok(downloadNames[0].endsWith('.yaml')); assert.equal($('#converterParameters').value, '{"title":');
assert.equal(requestLog.length, 0);
''')

    def test_parameter_key_and_value_bytes_share_main_input_budget(self):
        self.run_js(r'''
await converterFixture(); await parameterInput({title:'文'.repeat(1000), empty:''});
const draft = converterMainDraft(), size = converterParameterBytes(draft.form.parameters), limit = converterSchema.limits.content_bytes;
assert.equal(size, 3010); assert.equal(converterMainLocalBytes(draft), size);
draft.paste = 'x'.repeat(limit - size); assert.equal(converterMainLocalBytes(draft), limit);
assert.doesNotThrow(() => converterMainBudget(draft, [])); draft.paste += 'x';
assert.throws(() => converterMainBudget(draft, []), /1 MiB/);
draft.form.sources = 'ss://synthetic'; draft.paste = 'x'.repeat(limit - size - converterBytes(draft.form.sources));
assert.doesNotThrow(() => converterMainBudget(draft, []));
assert.throws(() => converterMainBudget(draft, [{name:'part.txt', content:'x'}]), /1 MiB/);
''')

    def test_file_preflight_counts_parameters_before_reading_any_file(self):
        self.run_js(r'''
await converterFixture(); await parameterInput({title:'x'.repeat(4096)}); requestLog.length = 0;
const size = converterParameterBytes(converterForm().parameters), limit = converterSchema.limits.content_bytes;
let reads = 0;
for (const id of ['converterUpload', 'converterConfigUpload', 'converterResourceUpload']) {
  $('#' + id).files = [{name:'synthetic.txt', size:limit - size + 1, arrayBuffer:async () => {reads++; throw Error('must not read');}}];
  await $('#' + id).dispatch('change'); assert.equal(reads, 0); assert.equal(operationBusy, false);
  assert.equal($('#' + id).value, '');
}
assert.equal(converterUploads.length, 0); assert.equal(converterResources.length, 0); assert.equal($('#converterConfigContent').value, '');
await inputValue('converterPaste', 'x'.repeat(limit - size));
$('#converterFilterScriptUpload').files = [{name:'filter.js', size:1, arrayBuffer:async () => {reads++; throw Error('must not read');}}];
await $('#converterFilterScriptUpload').dispatch('change'); assert.equal(reads, 0);
assert.equal($('#converterFilterScript').value, ''); assert.equal(requestLog.length, 0);
''')

    def test_request_budget_includes_parameters_json_escaping_and_nonce_room(self):
        self.run_js(r'''
await converterFixture(); await parameterInput({title:'\\'.repeat(4096)});
const form = converterForm(), wire = {form, uploads:['']};
const room = CONVERTER_REQUEST_BYTES - 4096 - converterBytes(JSON.stringify(wire));
wire.uploads[0] = 'x'.repeat(room); assert.equal(converterRequestBudget(wire), wire);
wire.uploads[0] += 'x'; assert.throws(() => converterRequestBudget(wire), /JSON/);
const size = converterParameterBytes(form.parameters);
await inputValue('converterPaste', '"'.repeat(converterSchema.limits.content_bytes - size));
assert.doesNotThrow(() => converterMainBudget(converterMainDraft(), []));
assert.throws(converterPayload, /JSON/); requestLog.length = 0;
await $('#executeConverter').click(); assert.equal(requestLog.length, 0); assert.equal(operationBusy, false);
assert.ok($('#notice').textContent.includes('JSON'));
''')

    def test_catalog_load_and_unrelated_page_locks_cover_parameter_field(self):
        self.run_js(r'''
const pending = deferred(); routes.set('/api/converter/options', () => pending.promise);
const loading = $('#loadConverter').click(); assert.equal(operationBusy, true); assert.equal($('#converterParameters').disabled, true);
pending.resolve(response(CONVERTER_SCHEMA)); await loading;
assert.equal($('#converterParameters').disabled, false); assert.equal(converterDirty(), false);
await inputValue('converterParameters', '{');
const later = deferred(), operation = runOperation('Synthetic read-only lock', () => later.promise);
assert.equal($('#converterParameters').disabled, true); assert.equal($('#saveChain').disabled, true);
later.resolve(); await operation;
assert.equal(operationBusy, false); assert.equal($('#converterParameters').disabled, false);
assert.equal($('#converterParameters').value, '{'); assert.equal($('#generateConverter').disabled, true);
assert.equal($('#clearConverter').disabled, false); assert.doesNotThrow(updateDraftNotice);
''')

    def test_old_catalog_and_v1_profiles_work_only_with_empty_parameters(self):
        self.run_js(r'''
delete CONVERTER_SCHEMA.parameters; await converterFixture();
assert.equal($('#converterParameters').disabled, true); assert.equal(converterForm().parameters, undefined);
assert.ok($('#converterParametersState').textContent.includes('尚未声明'));
const archive = converterArchive(); assert.doesNotThrow(() => converterValidateArchive(archive));
assert.throws(() => converterValidateParameters({title:'unsupported'}));
archive.form.parameters = {}; assert.doesNotThrow(() => converterValidateArchive(archive));
routes.set('/api/converter/link', validLink); await $('#converterForm').dispatch('submit'); assert.ok(converterResult);
await importParameterArchive(JSON.stringify(archive)); assert.equal($('#converterParameters').value, '{}');
''')

    def test_bad_parameter_catalog_is_retryable_and_declared_limits_are_used(self):
        self.run_js(r'''
const original = CONVERTER_SCHEMA.parameters;
for (const spec of [null, {...original, max:33}, {...original, max:0}, {...original, value_bytes:4097},
  {...original, value_bytes:0}, {...original, key_pattern:'.*'}, {...original, reserved:null}, {...original, reserved:['bad\n']}]) {
  routes.set('/api/converter/options', () => response({...CONVERTER_SCHEMA, parameters:spec}));
  await $('#loadConverter').click(); assert.equal(converterSchema, null); assert.equal(converterOptionFields.size, 0);
  assert.equal($('#loadConverter').disabled, false); assert.equal($('#converterParameters').disabled, true);
}
routes.set('/api/converter/options', () => response(CONVERTER_SCHEMA)); await $('#loadConverter').click();
converterSchema.parameters = {...original, max:1, value_bytes:3};
assert.deepEqual(converterParameters('{"title":"文"}'), {title:'文'});
assert.throws(() => converterParameters('{"title":"文a"}'));
assert.throws(() => converterParameters('{"title":"a","custom":"b"}'));
assert.ok(requestLog.every(item => item.path === '/api/converter/options'));
''')

    def test_template_reserved_names_use_the_same_case_and_key_guards(self):
        self.run_js(r'''
await converterFixture(); requestLog.length = 0;
for (const key of ['PATH', 'Path', 'Constructor', 'CONSTRUCTOR', 'Prototype', 'PROTOTYPE', 'title\n']) {
  assert.throws(() => converterVariables(JSON.stringify({[key]:'x'})));
}
assert.deepEqual(converterVariables('{"title":"😀"}'), {title:'😀'}); assert.equal(requestLog.length, 0);
''')

    def test_mellow_hint_follows_target_without_external_actions(self):
        self.run_js(r'''
await converterFixture(); requestLog.length = 0;
assert.equal($('#converterTargetHint').hidden, true);
await inputValue('converterTarget', 'mellow', 'change');
assert.equal($('#converterTargetHint').hidden, false);
assert.ok($('#converterTargetHint').textContent.includes('保守兼容子集'));
assert.ok($('#converterTargetHint').textContent.includes('HTTP 伪装、插件'));
assert.ok($('#converterTargetHint').textContent.includes('显式 Clash'));
await inputValue('converterTarget', 'clash', 'change'); assert.equal($('#converterTargetHint').hidden, true);
assert.equal(requestLog.length, 0);
''')


if __name__ == '__main__':
    unittest.main()
