"""Offline real-HTML/app/converter coverage for captured remote-config presets."""
import json
import unittest

import test_converter_frontend as fixture
from test_converter_presets import EXPECTED_CATALOG, c


class ConverterPresetsFrontendTests(unittest.TestCase):
    run_js = fixture.ConverterFrontendTests.run_js

    @classmethod
    def setUpClass(cls):
        fixture.ConverterFrontendTests.setUpClass.__func__(cls)
        links = {
            item['url']: c.validate({'profile': 'manual', 'sources': 'https://sub.example.test/a?token=synthetic',
                                    'options': dict(c.PRESET_OPTIONS, config=item['url'])}).link()
            for group in EXPECTED_CATALOG for item in group['items']
        }
        cls.app += '\nconst EXPECTED_CONFIG_CATALOG = ' + json.dumps(EXPECTED_CATALOG, ensure_ascii=False) + ';'
        cls.app += '\nconst PRESET_LINKS = ' + json.dumps(links) + ';'
        cls.app += r'''
const CONFIG_ITEMS = EXPECTED_CONFIG_CATALOG.flatMap(group => group.items);
async function chooseConfig(url) {await inputValue('converterConfigPreset', url, 'change');}
function presetLink(body) {return response({ok:true, link:PRESET_LINKS[body.form.options.config],
  summary:{source_count:1,network_executed:false,router_changed:false,warnings:[]}});}
async function importPresetArchive(data) {
  $('#converterArchiveUpload').files = [syntheticFile('legacy-v1.json', JSON.stringify(data))];
  await $('#converterArchiveUpload').dispatch('change');
}
'''

    def test_markup_keeps_manual_url_and_labels_the_initially_disabled_selector(self):
        nodes = {node['attrs']['id']: node for node in self.page.elements if 'id' in node['attrs']}
        self.assertEqual(len(nodes), sum('id' in node['attrs'] for node in self.page.elements))
        field = nodes['converterConfigPreset']
        self.assertEqual(field['tag'], 'select')
        self.assertIn('disabled', field['attrs'])
        self.assertIn(field['attrs']['aria-describedby'], nodes)
        self.assertTrue(any(node['tag'] == 'label' and node['attrs'].get('for') == 'converterConfigPreset'
                            for node in self.page.elements))
        self.assertEqual(nodes['converterConfig']['attrs']['type'], 'url')
        self.assertIn('disabled', nodes['converterConfig']['attrs'])

    def test_lazy_load_preserves_defaults_and_renders_exact_optgroups_without_selecting(self):
        self.run_js(r'''
assert.equal($('#converterConfigPreset').disabled, true); assert.equal(requestLog.length, 0);
await chooseConfig(CONFIG_ITEMS[0].url);
assert.equal($('#converterConfig').value, ''); assert.equal(requestLog.length, 0);
await $('#loadConverter').click();
const groups = $('#converterConfigPreset').querySelectorAll('optgroup');
assert.deepEqual(groups.map(group => ({name:group.getAttribute('label'), items:group.querySelectorAll('option').map(option => ({name:option.textContent,url:option.value}))})), EXPECTED_CONFIG_CATALOG);
assert.equal($('#converterConfigPreset').querySelectorAll('option').length, 12);
assert.equal($('#converterConfigPreset').value, ''); assert.equal($('#converterConfigPreset').disabled, false);
assert.equal(converterForm().options.config, undefined); assert.equal(converterForm().profile, 'router_a');
assert.equal(converterDirty(), false); assert.equal(converterForm().options.scv, false);
assert.deepEqual(requestLog.map(item => item.path), ['/api/converter/options']);
''')

    def test_eleven_selections_only_change_config_and_profile_and_mark_dirty_without_requests(self):
        self.run_js(r'''
await converterFixture(); requestLog.length = 0;
const initial = converterForm();
for (const item of CONFIG_ITEMS) {
  await chooseConfig(item.url);
  const actual = converterForm();
  assert.equal(actual.options.config, item.url); assert.equal(actual.profile, 'manual');
  assert.equal($('#converterConfigPreset').value, item.url); assert.equal(converterDirty(), true);
  delete actual.options.config; actual.profile = initial.profile;
  assert.deepEqual(actual, initial); assert.equal(requestLog.length, 0);
}
assert.equal(confirmations, 0);
''')

    def test_selection_invalidates_link_and_execution_but_preserves_edited_output(self):
        self.run_js(r'''
await converterFixture(); await chooseConfig(CONFIG_ITEMS[0].url);
routes.set('/api/converter/link', presetLink);
await $('#converterForm').dispatch('submit'); assert.ok(converterResult);
let count = requestLog.length; await chooseConfig(CONFIG_ITEMS[1].url);
assert.equal(requestLog.length, count); assert.equal(converterResult, ''); assert.equal($('#converterOutput').value, '');
assert.equal($('#copyConverter').disabled, true); assert.equal($('#installConverter').disabled, true);
routes.set('/api/converter/execute', body => response(executionResult(body)));
await $('#executeConverter').click(); assert.equal(converterExport.current, true);
await inputValue('converterText', syntheticText + '# edited\n');
count = requestLog.length; await chooseConfig(CONFIG_ITEMS[2].url);
assert.equal(requestLog.length, count); assert.equal(converterExport.current, false);
assert.equal($('#converterText').value, syntheticText + '# edited\n');
assert.ok($('#converterExportState').textContent.includes('旧结果'));
''')

    def test_manual_edit_and_custom_choice_preserve_url_and_exact_match_state(self):
        self.run_js(r'''
await converterFixture(); requestLog.length = 0;
await chooseConfig(CONFIG_ITEMS[0].url); await chooseConfig('');
assert.equal($('#converterConfigPreset').value, ''); assert.equal(converterForm().options.config, CONFIG_ITEMS[0].url);
await inputValue('converterConfig', 'https://config.example.test/manual.ini');
assert.equal($('#converterConfigPreset').value, ''); assert.equal(converterForm().options.config, 'https://config.example.test/manual.ini');
await inputValue('converterConfig', CONFIG_ITEMS[10].url);
assert.equal($('#converterConfigPreset').value, CONFIG_ITEMS[10].url);
await inputValue('converterConfig', CONFIG_ITEMS[10].url + '?custom=1');
assert.equal($('#converterConfigPreset').value, '');
await inputValue('converterConfig', '');
assert.equal($('#converterConfigPreset').value, ''); assert.equal(converterForm().options.config, undefined);
assert.equal(requestLog.length, 0);
''')

    def test_form_restore_matches_catalog_without_new_form_or_archive_fields(self):
        self.run_js(r'''
await converterFixture(); requestLog.length = 0;
for (const item of CONFIG_ITEMS) {
  const form = {profile:'manual', backend:CONVERTER_SCHEMA.backend, sources:exampleSource,
    options:{target:'surge',ver:5,udp:false,config:item.url}};
  setConverterForm(form);
  assert.equal($('#converterConfigPreset').value, item.url); assert.deepEqual(converterForm(), form);
  assert.equal(converterArchive().version, 1); assert.deepEqual(converterArchive().form, form);
}
setConverterForm({profile:'manual',sources:exampleSource,options:{target:'clash',config:'https://example.test/custom.ini'}});
assert.equal($('#converterConfigPreset').value, ''); assert.equal(converterForm().options.config, 'https://example.test/custom.ini');
assert.equal(requestLog.length, 0);
''')

    def test_legacy_v1_archive_upload_restores_known_and_custom_config_without_requests(self):
        self.run_js(r'''
await converterFixture(); const legacy = converterArchive(); delete legacy.form.parameters;
assert.equal(legacy.version, 1); requestLog.length = 0;
for (const url of [CONFIG_ITEMS[0].url, CONFIG_ITEMS[10].url, 'https://example.test/manual.ini']) {
  legacy.form.options.config = url;
  await importPresetArchive(legacy);
  assert.equal(converterForm().options.config, url);
  assert.equal($('#converterConfigPreset').value, CONFIG_ITEMS.some(item => item.url === url) ? url : '');
  assert.equal(converterExport, null); assert.equal(converterResult, '');
  assert.equal(Object.hasOwn(converterForm(), 'parameters'), false); assert.equal(requestLog.length, 0);
}
''')

    def test_parse_response_restores_named_or_custom_config_without_fetching_templates(self):
        self.run_js(r'''
await converterFixture();
for (const url of [CONFIG_ITEMS[2].url, CONFIG_ITEMS[9].url, 'https://example.test/custom.ini']) {
  routes.set('/api/converter/parse', () => response({ok:true, form:{profile:'manual',backend:CONVERTER_SCHEMA.backend,
    sources:[exampleSource],options:{target:'clash',config:url}}}));
  await inputValue('converterImport', 'https://example.test/sub?url=synthetic'); requestLog.length = 0;
  await $('#parseConverter').click();
  assert.equal(converterForm().options.config, url);
  assert.equal($('#converterConfigPreset').value, CONFIG_ITEMS.some(item => item.url === url) ? url : '');
  assert.equal(requestLog.filter(item => item.path === '/api/converter/parse').length, 1);
  assert.ok(requestLog.every(item => ['/api/converter/parse','/api/bootstrap'].includes(item.path)));
}
''')

    def test_each_preset_uses_identical_options_for_real_model_link_and_execute_request(self):
        self.run_js(r'''
await converterFixture(); let linkForm;
routes.set('/api/converter/link', body => {linkForm = body.form; return presetLink(body);});
routes.set('/api/converter/execute', body => {
  assert.deepEqual(body.form, linkForm); assert.equal(body.form.options.config, $('#converterConfigPreset').value);
  return response(executionResult(body));
});
for (const item of CONFIG_ITEMS) {
  let count = requestLog.length; await chooseConfig(item.url); assert.equal(requestLog.length, count);
  await $('#converterForm').dispatch('submit');
  const link = new URL(converterResult);
  assert.deepEqual(link.searchParams.getAll('config'), [item.url]); assert.equal(linkForm.options.config, item.url);
  await $('#executeConverter').click(); assert.equal(converterExport.current, true);
}
assert.equal(requestLog.filter(item => item.path === '/api/converter/link').length, 11);
assert.equal(requestLog.filter(item => item.path === '/api/converter/execute').length, 11);
assert.ok(requestLog.every(item => item.path.startsWith('/api/')));
''')

    def test_loading_and_page_wide_lock_prevent_selection_or_config_mutation(self):
        self.run_js(r'''
const loading = deferred(); routes.set('/api/converter/options', () => loading.promise);
const load = $('#loadConverter').click(); await waitTick();
assert.equal(operationBusy, true); assert.equal($('#converterConfigPreset').disabled, true);
let count = requestLog.length; await chooseConfig(CONFIG_ITEMS[0].url);
assert.equal($('#converterConfig').value, ''); assert.equal(requestLog.length, count);
loading.resolve(response(CONVERTER_SCHEMA)); await load;
await inputValue('converterSources', exampleSource); await chooseConfig(CONFIG_ITEMS[0].url);
const pending = deferred(); let body;
routes.set('/api/converter/execute', value => {body = value; return pending.promise;});
const task = $('#executeConverter').click(); await waitTick();
assert.equal(operationBusy, true); assert.equal($('#saveChain').disabled, true);
assert.equal($('#converterConfigPreset').disabled, true); assert.equal($('#converterConfig').disabled, true);
count = requestLog.length; await chooseConfig(CONFIG_ITEMS[1].url);
assert.equal(converterForm().options.config, CONFIG_ITEMS[0].url); assert.equal($('#converterConfigPreset').value, CONFIG_ITEMS[0].url);
assert.equal(requestLog.length, count); pending.resolve(response(executionResult(body))); await task;
assert.equal(operationBusy, false); assert.equal($('#converterConfigPreset').disabled, false);
$('#converterConfigPreset').disabled = true; count = requestLog.length;
await chooseConfig(CONFIG_ITEMS[2].url); assert.equal(converterForm().options.config, CONFIG_ITEMS[0].url);
assert.equal(requestLog.length, count); updateConverterControls();
const other = deferred(), otherTask = runOperation('synthetic other-page operation', () => other.promise);
await chooseConfig(CONFIG_ITEMS[3].url); assert.equal(converterForm().options.config, CONFIG_ITEMS[0].url);
other.resolve(); await otherTask; assert.equal($('#converterConfigPreset').disabled, false);
''')

    def test_missing_or_empty_legacy_catalog_keeps_manual_and_archive_paths_usable(self):
        for catalog in (None, []):
            with self.subTest(catalog=catalog):
                mutation = 'delete CONVERTER_SCHEMA.config_presets;' if catalog is None else 'CONVERTER_SCHEMA.config_presets = [];'
                self.run_js(mutation + r'''
await converterFixture(); requestLog.length = 0;
assert.equal($('#converterConfigPreset').disabled, true); assert.equal($('#converterConfig').disabled, false);
await inputValue('converterConfig', CONFIG_ITEMS[0].url);
assert.equal($('#converterConfigPreset').value, ''); assert.equal(converterForm().options.config, CONFIG_ITEMS[0].url);
const archive = converterArchive(); delete archive.form.parameters;
await importPresetArchive(archive);
assert.equal(converterForm().options.config, CONFIG_ITEMS[0].url); assert.equal($('#converterConfigPreset').disabled, true);
await chooseConfig(CONFIG_ITEMS[1].url); assert.equal(converterForm().options.config, CONFIG_ITEMS[0].url);
assert.equal(requestLog.length, 0);
''')

    def test_malformed_catalog_stays_unloaded_and_retry_does_not_duplicate_choices(self):
        self.run_js(r'''
for (const catalog of [null, {}, [{name:'group',items:[]}], [{name:'group',items:[{name:'invalid',url:'file:///test.ini'}]}],
  [{name:'group',items:[CONFIG_ITEMS[0],CONFIG_ITEMS[0]]}]]) {
  assert.throws(() => converterConfigPresetCatalog({...CONVERTER_SCHEMA,config_presets:catalog}));
}
routes.set('/api/converter/options', () => response({...CONVERTER_SCHEMA,config_presets:null}));
await $('#loadConverter').click(); assert.equal(converterSchema, null);
assert.equal($('#converterConfigPreset').disabled, true); assert.equal($('#converterConfigPreset').querySelectorAll('optgroup').length, 0);
routes.set('/api/converter/options', () => response(CONVERTER_SCHEMA));
await $('#loadConverter').click(); assert.equal($('#converterConfigPreset').querySelectorAll('optgroup').length, 3);
await inputValue('converterConfig', 'https://example.test/manual.ini'); const count = requestLog.length;
await loadConverter(); assert.equal(converterForm().options.config, 'https://example.test/manual.ini'); assert.equal(requestLog.length, count);
''')

    def test_subnet_confirm_cancel_and_clear_keep_existing_profile_behaviour(self):
        self.run_js(r'''
await converterFixture(); await chooseConfig(CONFIG_ITEMS[0].url); requestLog.length = 0;
confirmation = false; await inputValue('converterProfile','router_b','change');
assert.equal(converterForm().options.config, CONFIG_ITEMS[0].url); assert.equal($('#converterConfigPreset').value, CONFIG_ITEMS[0].url);
confirmation = true; await inputValue('converterProfile','router_b','change');
assert.equal(converterForm().profile,'router_b'); assert.equal(converterForm().options.config, undefined);
assert.equal($('#converterConfigPreset').value, ''); assert.equal(converterForm().sources, exampleSource);
await chooseConfig(CONFIG_ITEMS[1].url); await $('#clearConverter').click();
assert.equal($('#converterConfigPreset').value, ''); assert.equal(converterForm().options.config, undefined);
assert.equal(converterDirty(), false); assert.equal(requestLog.length, 0);
''')


if __name__ == '__main__':
    unittest.main()
