"""Synthetic regressions for guidance, status freshness and allocation-free escaping."""
import unittest
from pathlib import Path
import test_chain_frontend as fixture

ROOT = Path(__file__).resolve().parents[1]


class GuidanceInteractionTests(unittest.TestCase):
    run_js = fixture.ChainFrontendTests.run_js

    @classmethod
    def setUpClass(cls):
        fixture.ChainFrontendTests.setUpClass.__func__(cls)

    def test_html_escaping_preserves_text_without_dom_allocations(self):
        self.run_js(r'''
const original = document.createElement; let allocations = 0;
document.createElement = (...args) => { allocations++; return original(...args); };
for (const input of ['', null, undefined, 0, true, 'simple', '中😀 & <script> "quote"', '&lt;x&gt;', "' < > & "]){
  const text = String(input);
  assert.equal(escapeHtml(input), text.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;'));
  assert.equal(escapeAttr(input), text.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;'));
}
assert.equal(allocations, 0, 'Escaping many nodes must not allocate detached DOM elements');
''')

    def test_status_read_time_clears_after_failure(self):
        self.run_js(r'''
routes.set('/api/status', () => response({ok:true, targets:[{id:'router_a',name:'Synthetic',address:'192.0.2.1',active:'current.yaml',state:'OK'}]}));
await refresh();
assert.ok($('#statusFreshness').textContent.includes('本页读取于'));
routes.set('/api/status', () => {throw new Error('Synthetic unavailable');});
await refresh(true);
assert.ok($('#statusFreshness').textContent.includes('未确认'));
assert.ok(!$('#statusFreshness').textContent.includes('本页读取于'));
''')

    def test_unknown_panel_does_not_hide_current_panel_or_drop_draft(self):
        self.run_js(r'''
editor.value = 'synthetic draft'; switchPanel('editor');
switchPanel('not-a-panel');
assert.ok($('#editor').classList.contains('active'));
assert.equal(editor.value, 'synthetic draft');
assert.equal(requestLog.length, 0);
''')

    def test_progressive_help_is_native_and_does_not_submit(self):
        html = (ROOT / 'static/index.html').read_text()
        parser = fixture.PageParser(html)
        help_nodes = [node for node in parser.elements if node['attrs'].get('id') == 'quickStartGuide']
        self.assertEqual(len(help_nodes), 1)
        self.assertEqual(help_nodes[0]['tag'], 'details')
        self.assertNotIn('open', help_nodes[0]['attrs'])
        for identifier in ('statusFreshness', 'updatesDetails', 'customHelp', 'chainHelp', 'converterHelp'):
            self.assertTrue(any(node['attrs'].get('id') == identifier for node in parser.elements), identifier)


if __name__ == '__main__':
    unittest.main()
