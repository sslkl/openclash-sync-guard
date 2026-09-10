"""Real frontend code in the shared Node DOM harness; synthetic I/O only.

These regressions cover observable interaction/focus state and DOM writes.
They do not claim browser layout, assistive-technology or production acceptance.
"""
import unittest

import test_chain_frontend as chain_fixture
import test_converter_frontend as converter_fixture


class EditorInteractionTests(unittest.TestCase):
    run_js = chain_fixture.ChainFrontendTests.run_js

    @classmethod
    def setUpClass(cls):
        chain_fixture.ChainFrontendTests.setUpClass.__func__(cls)

    def test_cursor_offsets_follow_empty_unicode_and_same_size_replacements(self):
        self.run_js(r'''
for (const text of ['', 'a\n', '\n\n', '中😀x\nβ\n', 'a\nbc', 'ab\nc']) {
  editor.value = text;
  editorLines();
  assert.equal($('#lineNumbers').textContent, Array.from({length:text.split('\n').length}, (_,i)=>i+1).join('\n'));
  for (let offset = 0; offset <= text.length; offset++) {
    editor.setSelectionRange(offset, offset);
    await editor.dispatch('keyup');
    const prefix = text.slice(0, offset).split('\n');
    assert.equal($('#cursorPosition').textContent, '第 ' + prefix.length + ' 行，第 ' + (prefix.at(-1).length + 1) + ' 列');
  }
}
// Replacing the value programmatically must not reuse an obsolete line index.
editor.value = 'a\nbc'; editor.setSelectionRange(2, 2); editorMeta();
assert.equal($('#cursorPosition').textContent, '第 2 行，第 1 列');
editor.value = 'ab\nc'; editorMeta();
assert.equal($('#cursorPosition').textContent, '第 1 行，第 3 列');
''')

    def test_selection_event_updates_cursor_without_keyup_or_click(self):
        self.run_js(r'''
editor.value = 'first\nsecond\nthird'; editorLines();
editor.setSelectionRange(8, 14); await editor.dispatch('select');
assert.equal($('#cursorPosition').textContent, '第 2 行，第 3 列');
assert.equal(requestLog.length, 0);
''')

    def test_validation_focus_updates_the_visible_cursor_immediately(self):
        self.run_js(r'''
editor.value = 'first\nsecond\nthird'; editor.setSelectionRange(0, 0); editorLines();
routes.set('/api/validate', () => response({ok:false,message:'Synthetic parse error',line:3,column:2}));
await $('#validateYaml').click();
assert.ok(document.activeElement === editor, 'validation must focus the editor');
assert.equal(editor.selectionStart, 14);
assert.equal($('#cursorPosition').textContent, '第 3 行，第 2 列');
assert.equal($('#saveConfig').disabled, true);
assert.equal(editor.value, 'first\nsecond\nthird');
''')

    def test_large_document_avoids_gutter_rewrites_when_line_count_is_unchanged(self):
        self.run_js(r'''
const gutter = $('#lineNumbers');
const descriptor = Object.getOwnPropertyDescriptor(MiniElement.prototype, 'textContent');
let writes = 0;
Object.defineProperty(gutter, 'textContent', {
  get() {return descriptor.get.call(this);},
  set(value) {writes++; descriptor.set.call(this, value);}
});
editor.value = 'name: synthetic-node\n'.repeat(20000);
editorLines();
const numbers = gutter.textContent;
assert.equal(numbers.split('\n').length, 20001);
writes = 0;
gutter.scrollTop = 80;
for (let i = 0; i < 40; i++) {
  editor.value = (i % 2 ? 'n' : 'N') + editor.value.slice(1);
  editor.setSelectionRange(editor.value.length, editor.value.length);
  await editor.dispatch('input');
}
assert.equal(writes, 0, 'same-line-count edits must not rebuild the entire gutter');
assert.equal(gutter.textContent, numbers);
assert.equal(gutter.scrollTop, 80);
assert.equal($('#cursorPosition').textContent, '第 20001 行，第 1 列');
editor.value += 'last\n'; await editor.dispatch('input');
assert.equal(writes, 1);
assert.equal(gutter.textContent.split('\n').length, 20002);
editor.value = ''; await editor.dispatch('input');
assert.equal(writes, 2); assert.equal(gutter.textContent, '1');
assert.equal(requestLog.length, 0);
''')

    def test_unchanged_cursor_events_do_not_rewrite_live_dom(self):
        self.run_js(r'''
editor.value = 'a\nb'; editor.setSelectionRange(2, 2); editorLines();
const label = $('#cursorPosition');
const descriptor = Object.getOwnPropertyDescriptor(MiniElement.prototype, 'textContent');
let writes = 0;
Object.defineProperty(label, 'textContent', {
  get() {return descriptor.get.call(this);},
  set(value) {writes++; descriptor.set.call(this, value);}
});
for (let i = 0; i < 30; i++) await editor.dispatch('keyup');
assert.equal(writes, 0);
editor.setSelectionRange(3, 3); await editor.dispatch('keyup');
assert.equal(writes, 1); assert.equal(label.textContent, '第 2 行，第 2 列');
''')


class ManagedListInteractionTests(unittest.TestCase):
    run_js = chain_fixture.ChainFrontendTests.run_js

    @classmethod
    def setUpClass(cls):
        chain_fixture.ChainFrontendTests.setUpClass.__func__(cls)
        cls.app += r'''
function managedFixture(kind) {
  const rule = kind === 'rule';
  const original = ['first.example.test', 'second.example.test', 'third.example.test']
    .map(value => rule ? {type:'DOMAIN',value,policy:'DIRECT'} : '*.' + value);
  if (rule) {savedRules = original.map(cloneRule); renderManagedRules();}
  else {savedFilters = [...original]; renderManagedFilters();}
  const list = $(rule ? '#managedRuleList' : '#managedFilterList');
  const details = $(rule ? '#managedRuleDetails' : '#managedFilterDetails');
  details.open = true;
  return {rule, original, list, details, drafts:$(rule ? '#ruleList' : '#filterList'),
    rowClass:rule ? '.rule-row' : '.filter-row', inputClass:rule ? '.rule-value' : '.filter-value',
    add:$(rule ? '#addRule' : '#addFilter'), values:()=>rule ? savedRules : savedFilters};
}
'''

    def test_edit_moves_focus_to_draft_and_cancel_returns_to_restored_item(self):
        for kind in ('rule', 'filter'):
            with self.subTest(kind=kind):
                self.run_js("const kind = " + repr(kind) + ";\n" + r'''
const state = managedFixture(kind);
const edit = state.list.querySelectorAll('.ghost')[1]; edit.focus(); await edit.click();
const draft = state.drafts.querySelector(state.rowClass), input = draft.querySelector(state.inputClass);
assert.ok(document.activeElement === input, 'editing removes the trigger, so focus must follow the editable draft');
input.value = 'changed.example.test'; await input.dispatch('input');
state.details.open = false;
const cancel = draft.querySelector('.remove-row'); cancel.focus(); await cancel.click();
assert.deepEqual(state.values(), state.original);
assert.equal(state.drafts.querySelector(state.rowClass), null);
assert.equal(state.details.open, true, 'the restored item must be visible before focusing it');
assert.ok(document.activeElement === state.list.querySelectorAll('.ghost')[1], 'cancel must focus the restored item');
assert.equal(requestLog.length, 0);
''')

    def test_saved_delete_focuses_neighbor_or_add_button_without_losing_other_items(self):
        for kind in ('rule', 'filter'):
            with self.subTest(kind=kind):
                self.run_js("const kind = " + repr(kind) + ";\n" + r'''
const state = managedFixture(kind), expected = [...state.original];
while (expected.length) {
  const index = Math.min(1, expected.length - 1);
  const button = state.list.querySelectorAll('.remove-row')[index]; button.focus(); await button.click();
  expected.splice(index, 1);
  assert.deepEqual(state.values(), expected);
  const buttons = state.list.querySelectorAll('.remove-row');
  assert.ok(document.activeElement === (buttons[Math.min(index, buttons.length - 1)] || state.add), 'delete must focus the next item or add button');
}
assert.equal(requestLog.length, 0);
''')

    def test_draft_delete_focuses_neighbor_or_add_button_and_preserves_remaining_drafts(self):
        for kind in ('rule', 'filter'):
            with self.subTest(kind=kind):
                self.run_js("const kind = " + repr(kind) + ";\n" + r'''
const state = managedFixture(kind);
const expected = ['one.example.test', 'two.example.test', 'three.example.test'];
for (const value of expected) {
  if (state.rule) addRule({type:'DOMAIN',value,policy:'DIRECT'}); else addFilter(value);
}
while (expected.length) {
  const index = Math.min(1, expected.length - 1), rows = state.drafts.querySelectorAll(state.rowClass);
  const button = rows[index].querySelector('.remove-row'); button.focus(); await button.click();
  expected.splice(index, 1);
  const remaining = state.drafts.querySelectorAll(state.rowClass);
  assert.deepEqual(remaining.map(row=>row.querySelector(state.inputClass).value), expected);
  const next = remaining[Math.min(index, remaining.length - 1)];
  assert.ok(document.activeElement === (next?.querySelector(state.inputClass) || state.add), 'draft delete must focus a surviving control');
  assert.deepEqual(state.values(), state.original);
}
assert.equal(requestLog.length, 0);
''')

    def test_managed_action_names_include_their_item_context(self):
        for kind in ('rule', 'filter'):
            with self.subTest(kind=kind):
                self.run_js("const kind = " + repr(kind) + ";\n" + r'''
const state = managedFixture(kind);
const rows = state.list.querySelectorAll('.managed-item');
for (let i = 0; i < rows.length; i++) {
  const identity = state.rule ? ruleIdentity(state.original[i]) : state.original[i];
  assert.equal(rows[i].querySelector('.ghost').getAttribute('aria-label'), '编辑 ' + identity);
  assert.equal(rows[i].querySelector('.remove-row').getAttribute('aria-label'), '暂存删除 ' + identity);
}
''')



class LargeNodeListInteractionTests(unittest.TestCase):
    run_js = chain_fixture.ChainFrontendTests.run_js

    @classmethod
    def setUpClass(cls):
        chain_fixture.ChainFrontendTests.setUpClass.__func__(cls)

    def test_large_catalog_keeps_every_node_and_allows_selecting_the_last_one(self):
        self.run_js(r'''
const catalog = fixtureRead([]);
catalog.nodes = Array.from({length:5000}, (_,i)=>({name:'Synthetic node '+i,type:'ss'}));
routes.set('/api/chain/read', () => response(catalog));
await $('#loadChain').click();
const options = $('#chainNode').querySelectorAll('option');
assert.equal(options.length, 5001); assert.equal(options[0].value, '');
assert.deepEqual(options.slice(1).map(option=>option.value), catalog.nodes.map(node=>node.name));
await inputValue('chainNode', catalog.nodes.at(-1).name, 'change');
assert.equal(selectedChainNode, catalog.nodes.at(-1).name);
assert.equal(chainReady(), true);
assert.equal(requestLog.filter(r=>r.path === '/api/chain/read').length, 1);
assert.equal(requestLog.some(r=>r.path === '/api/chain/apply'), false);
''')


class ConverterCatalogInteractionTests(unittest.TestCase):
    run_js = converter_fixture.ConverterFrontendTests.run_js

    @classmethod
    def setUpClass(cls):
        converter_fixture.ConverterFrontendTests.setUpClass.__func__(cls)
        # Include both wrappers to exercise the actual control-update stack.
        for module in ('converter_apply.js', 'converter_services.js'):
            cls.app += '\n' + (chain_fixture.ROOT / 'static' / module).read_text()

    def test_late_malformed_field_does_not_publish_a_partial_catalog_and_is_retryable(self):
        for field_type in ('texts', 'integers', 'tools'):
            with self.subTest(field_type=field_type):
                self.run_js("const fieldType = " + repr(field_type) + ";\n" + r'''
const original = new Map(['converterTarget','converterProfile','converterOptions','converterConfigPreset']
  .map(id => [id, $('#' + id).innerHTML]));
// Model a browser-restored local text field. A failed load must not clear it.
$('#converterImport').value = 'synthetic local draft';
const invalid = structuredClone(CONVERTER_SCHEMA);
if (['texts','integers'].includes(fieldType)) invalid[fieldType].broken = null;
else invalid.execution[fieldType] = {}; // Would otherwise throw during control unlock.
const pending = deferred(); routes.set('/api/converter/options', () => pending.promise);
const first = $('#loadConverter').click(), repeated = $('#loadConverter').click();
assert.equal(operationBusy, true); assert.equal($('#loadConverter').disabled, true);
pending.resolve(response(invalid)); await Promise.all([first, repeated]);
assert.equal(Boolean(converterSchema), false, 'failed catalog must not make the module ready');
assert.equal(converterOptionFields.size, 0);
assert.equal($('#loadConverter').disabled, false, 'the offered retry must remain reachable');
assert.equal($('#converterSources').disabled, true);
for (const [id, html] of original) assert.equal($('#' + id).innerHTML, html, 'no partial UI commit: ' + id);
assert.equal($('#converterImport').value, 'synthetic local draft');
assert.equal($('#converterState').classList.contains('bad'), true);
assert.equal(requestLog.filter(r=>r.path === '/api/converter/options').length, 1);
routes.set('/api/converter/options', () => response(CONVERTER_SCHEMA));
await $('#loadConverter').click();
assert.equal(Boolean(converterSchema), true); assert.equal(operationBusy, false);
assert.equal($('#converterSources').disabled, false); assert.equal($('#loadConverter').disabled, true);
assert.equal($('#converterTarget').querySelectorAll('option').length, Object.keys(CONVERTER_SCHEMA.clients).length);
assert.equal($('#converterProfile').querySelectorAll('option').length, CONVERTER_SCHEMA.presets.length + 1);
assert.equal(converterOptionFields.size, ['booleans','texts','integers'].reduce((n,k)=>n + Object.keys(CONVERTER_SCHEMA[k]).length,0));
assert.equal($('#converterState').classList.contains('bad'), false);
assert.equal(requestLog.filter(r=>r.path === '/api/converter/options').length, 2);
assert.equal(requestLog.some(r=>r.path.includes('execute') || r.path.includes('router-')), false);
''')


if __name__ == '__main__':
    unittest.main()
