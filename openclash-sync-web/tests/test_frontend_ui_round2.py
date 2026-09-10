"""Offline HTML/accessibility/layout guards for the second UI improvement round.

Reads only public frontend source. No backend, browser profile, network, fixtures
with credentials, or generated files. These source constraints do not replace
real browser layout, keyboard or assistive-technology acceptance.
"""
from html.parser import HTMLParser
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
# Existing DOM IDs are integration contracts; new IDs may be added.
EXISTING_IDS = frozenset("""
modeText refreshStatus notice operationStatus draftNotice targetGrid updates custom loadCustom
configuredSummary configuredRules configuredFilters addRule managedRuleDetails managedRuleCount
managedRuleList ruleList routeValue checkRoute routeResult addFilter managedFilterDetails
managedFilterCount managedFilterList filterList customValidation customConfirm validateCustom
saveCustom chain chainHeading chainPreview chainPreviewHeading chainPreviewText chainTarget loadChain
chainReadState chainListHeading chainCount chainList chainForm chainFormHeading chainSelectionState
chainNode chainType chainPort chainServer chainEndpointHelp chainUsernameField chainUsername
chainPasswordField chainPassword chainPasswordHint chainKeepPassword chainKeepHint chainTlsField
chainTls chainSniField chainSni chainCipherField chainCipher chainValidation chainConfirm
validateChain saveChain removeChain resetChain chainTestHeading testChain chainTestResult converter
converterHeading loadConverter converterState converterForm converterProfile converterTarget
converterTargetHint converterSources converterLocal converterUpload converterFiles
clearConverterFiles converterPaste converterAdvanced converterBackend converterConfigPreset
converterConfigPresetHint converterConfig converterConfigUpload converterConfigContent
converterParameters converterParametersHint converterParametersState converterOptions
converterScripts converterFilterScriptUpload converterFilterScript converterSortScriptUpload
converterSortScript converterScriptHint executeConverter generateConverter validateConverter
clearConverter converterExecutionHint converterExportState converterText copyConverterText
downloadConverter restoreConverterText converterApplyMount converterServicesMount
converterResourceWorkspace converterResourceHint converterResourceUpload converterResources
clearConverterResources converterTools converter-ruleset converter-ruleset-upload
converter-ruleset-content converter-ruleset-urls converter-ruleset-input-format
converter-ruleset-type converter-ruleset-group converter-ruleset-run converter-ruleset-clear
converter-ruleset-state converter-ruleset-result converter-ruleset-copy converter-ruleset-download
converter-ruleset-restore converter-template converter-template-upload converter-template-content
converter-template-urls converter-template-variables converter-template-run converter-template-clear
converter-template-state converter-template-result converter-template-copy
converter-template-download converter-template-restore converter-surge2clash
converter-surge2clash-upload converter-surge2clash-content converter-surge2clash-urls
converter-surge2clash-run converter-surge2clash-clear converter-surge2clash-state
converter-surge2clash-result converter-surge2clash-copy converter-surge2clash-download
converter-surge2clash-restore converterArchiveWorkspace converterArchiveUpload exportConverterArchive
converterArchiveState converterImport parseConverter converterOutput copyConverter installConverter
editor editorTarget fileName readConfig lineNumbers yamlEditor editorLineHint validationState
cursorPosition fileHash validateYaml saveConfig rollback rollbackTarget rollbackPhrase rollbackButton
""".split())
PANELS = ("updates", "custom", "chain", "editor", "rollback", "converter")


class Markup(HTMLParser):
    VOID = frozenset("area base br col embed hr img input link meta param source track wbr".split())

    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self.root = {"tag": "document", "attrs": {}, "children": [], "parent": None}
        self.stack = [self.root]
        self.nodes, self.errors = [], []
        self.feed(source)
        self.close()
        if len(self.stack) != 1:
            self.errors.append("Unclosed tags")

    def handle_starttag(self, tag, attrs):
        if len(attrs) != len(dict(attrs)):
            self.errors.append("Duplicate attributes on " + tag)
        node = {"tag": tag, "attrs": dict(attrs), "children": [], "parent": self.stack[-1]}
        self.stack[-1]["children"].append(node)
        self.nodes.append(node)
        if tag not in self.VOID:
            self.stack.append(node)

    def handle_endtag(self, tag):
        if len(self.stack) == 1 or self.stack[-1]["tag"] != tag:
            self.errors.append("Mismatched closing tag " + tag)
        else:
            self.stack.pop()

    def handle_data(self, data):
        self.stack[-1]["children"].append(data)


def text(node):
    if isinstance(node, str):
        return node
    return "".join(text(child) for child in node["children"])


def css_rules(source, media=()):
    """Read this stylesheet's simple rule blocks, retaining media boundaries."""
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    cursor = 0
    while cursor < len(source):
        start = source.find("{", cursor)
        if start < 0:
            if source[cursor:].strip():
                raise ValueError("Trailing non-rule CSS")
            return
        header = source[cursor:start].strip()
        depth, end = 1, start + 1
        while end < len(source) and depth:
            depth += (source[end] == "{") - (source[end] == "}")
            end += 1
        if depth:
            raise ValueError("Unclosed CSS block")
        body = source[start + 1:end - 1]
        if header.startswith("@media"):
            yield from css_rules(body, media + (re.sub(r"\s+", "", header),))
        else:
            declarations = dict(part.strip().split(":", 1) for part in body.split(";") if ":" in part)
            declarations = {key.strip(): value.strip() for key, value in declarations.items()}
            for selector in header.split(","):
                yield selector.strip(), media, declarations
        cursor = end


def contrast(first, second):
    def luminance(value):
        rgb = [int(value[i:i + 2], 16) / 255 for i in (1, 3, 5)]
        linear = [v / 12.92 if v <= .04045 else ((v + .055) / 1.055) ** 2.4 for v in rgb]
        return sum(v * weight for v, weight in zip(linear, (.2126, .7152, .0722)))
    bright, dark = sorted((luminance(first), luminance(second)), reverse=True)
    return (bright + .05) / (dark + .05)


class FrontendUIRound2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (ROOT / "static/index.html").read_text(encoding="utf-8")
        cls.css = (ROOT / "static/app.css").read_text(encoding="utf-8")
        cls.page = Markup(cls.html)
        cls.ids = {n["attrs"]["id"]: n for n in cls.page.nodes if "id" in n["attrs"]}
        cls.rules = list(css_rules(cls.css))

    def properties(self, selector, media=None):
        result = {}
        context = () if media is None else (re.sub(r"\s+", "", "@media" + media),)
        for candidate, conditions, declarations in self.rules:
            if candidate == selector and conditions == context:
                result.update(declarations)
        self.assertTrue(result, (selector, context))
        return result

    def test_well_formed_markup_unique_ids_and_existing_hooks(self):
        self.assertEqual(self.page.errors, [])
        ids = [n["attrs"]["id"] for n in self.page.nodes if "id" in n["attrs"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(EXISTING_IDS.issubset(ids), EXISTING_IDS.difference(ids))
        self.assertEqual(next(n for n in self.page.nodes if n["tag"] == "html")["attrs"]["lang"], "zh-CN")

    def test_skip_link_has_a_focusable_main_target(self):
        skip = next(n for n in self.page.nodes if "skip-link" in n["attrs"].get("class", "").split())
        main = self.ids[skip["attrs"]["href"][1:]]
        self.assertEqual(main["tag"], "main")
        self.assertEqual(main["attrs"]["tabindex"], "-1")
        self.assertEqual(sum(n["tag"] == "main" for n in self.page.nodes), 1)
        self.assertEqual(sum(n["tag"] == "h1" for n in self.page.nodes), 1)
        self.assertEqual(self.properties(".skip-link:focus")["transform"], "translateY(0)")
        self.assertEqual(self.properties(".skip-link")["opacity"], "0")
        self.assertEqual(self.properties(".skip-link")["pointer-events"], "none")
        self.assertEqual(self.properties(".skip-link:focus")["opacity"], "1")
        self.assertEqual(self.properties(".skip-link:focus")["pointer-events"], "auto")

    def test_all_panels_keep_navigation_contract_and_named_headings(self):
        nav = [n for n in self.page.nodes if "data-panel" in n["attrs"]]
        self.assertEqual([n["attrs"]["data-panel"] for n in nav], list(PANELS))
        for item in nav:
            panel = self.ids[item["attrs"]["data-panel"]]
            self.assertEqual(item["attrs"]["aria-controls"], panel["attrs"]["id"])
            heading = self.ids[panel["attrs"]["aria-labelledby"]]
            self.assertEqual(heading["tag"], "h2")
            self.assertTrue(text(heading).strip())
        self.assertEqual(nav[0]["attrs"]["aria-current"], "page")
        self.assertEqual([p for p in PANELS if "active" in self.ids[p]["attrs"]["class"].split()], ["updates"])

    def test_accessibility_references_resolve_to_real_content(self):
        for node in self.page.nodes:
            for attr in ("aria-labelledby", "aria-describedby", "aria-controls", "for"):
                for identifier in node["attrs"].get(attr, "").split():
                    with self.subTest(id=node["attrs"].get("id"), attribute=attr, target=identifier):
                        self.assertIn(identifier, self.ids)
                        if attr in ("aria-labelledby", "aria-describedby"):
                            self.assertTrue(text(self.ids[identifier]).strip())

    def test_every_static_form_control_has_an_accessible_name(self):
        labels = {n["attrs"]["for"]: n for n in self.page.nodes if n["tag"] == "label" and "for" in n["attrs"]}
        for node in self.page.nodes:
            if node["tag"] not in ("input", "select", "textarea"):
                continue
            attrs, ancestor = node["attrs"], node["parent"]
            named = attrs.get("aria-label") or attrs.get("aria-labelledby")
            if attrs.get("id") in labels:
                named = named or text(labels[attrs["id"]]).strip()
            while ancestor:
                if ancestor["tag"] == "label":
                    named = named or text(ancestor).strip()
                ancestor = ancestor["parent"]
            self.assertTrue(named, attrs.get("id"))

    def test_details_and_buttons_retain_native_names(self):
        for node in self.page.nodes:
            if node["tag"] == "details":
                children = [c for c in node["children"] if isinstance(c, dict)]
                self.assertEqual(children[0]["tag"], "summary")
                self.assertTrue(text(children[0]).strip())
            if node["tag"] == "button":
                self.assertTrue(text(node).strip() or node["attrs"].get("aria-label"))
                self.assertNotIn("tabindex", node["attrs"])

    def test_update_actions_explain_writes_without_renaming_buttons(self):
        actions = {n["attrs"]["data-action"]: n for n in self.page.nodes if "data-action" in n["attrs"]}
        self.assertEqual(set(actions), {"stage-main", "update-maying", "update-nexitally"})
        for action, label in (("stage-main", "检查并更新"), ("update-maying", "更新 Maying"), ("update-nexitally", "更新 Nexitally")):
            self.assertEqual(text(actions[action]), label)
            self.assertIn("write-action", actions[action]["attrs"]["class"].split())
            self.assertIn("updatesWorkflow", actions[action]["attrs"]["aria-describedby"].split())
        self.assertIn("不是只读检查", text(self.ids["updatesWorkflow"]))
        self.assertIn("可能重启", self.html)

    def test_read_preview_write_and_restart_are_text_not_color_only(self):
        guide = next(n for n in self.page.nodes if n["attrs"].get("class") == "operation-guide")
        for label in ("读取", "预览 / 检查", "写入", "重启"):
            self.assertIn(label, text(guide))
        for identifier in ("validateCustom", "validateChain", "validateYaml", "executeConverter"):
            self.assertIn("preview-action", self.ids[identifier]["attrs"]["class"].split())
        for identifier in ("saveCustom", "saveChain", "saveConfig"):
            self.assertIn("write-action", self.ids[identifier]["attrs"]["class"].split())
        for phrase in ("所有写入都会", "失败时会自动恢复", "完成运行态验收后仅执行一次全节点 delay 检查"):
            self.assertNotIn(phrase, self.html)

    def test_initial_locks_and_confirmation_controls_are_not_weakened(self):
        for identifier in ("saveCustom", "saveConfig", "saveChain", "removeChain", "rollbackButton", "executeConverter", "downloadConverter"):
            self.assertIn("disabled", self.ids[identifier]["attrs"])
        for identifier in ("customConfirm", "chainConfirm"):
            self.assertEqual(self.ids[identifier]["attrs"]["type"], "checkbox")
            self.assertNotIn("checked", self.ids[identifier]["attrs"])
        self.assertEqual(self.ids["saveChain"]["attrs"]["type"], "submit")
        self.assertEqual(self.ids["generateConverter"]["attrs"]["type"], "submit")
        self.assertIn("确认回滚主配置", self.ids["rollbackPhrase"]["attrs"]["placeholder"])

    def test_settings_describe_impact_and_next_step(self):
        expected = {
            "chainType": ("chainProtocolHint", "协议"),
            "converterProfile": ("converterProfileHint", "核对"),
            "converterSources": ("converterSourceHint", "生成链接不代表"),
            "converterUpload": ("converterUploadHint", "才发送"),
            "converterBackend": ("converterBackendHint", "源凭据"),
            "converterConfig": ("converterConfigHint", "安全审计"),
            "fileName": ("editorFileHint", "重新读取"),
            "rollbackPhrase": ("rollbackPhraseHint", "核对返回结果"),
        }
        for identifier, (hint, phrase) in expected.items():
            self.assertIn(hint, self.ids[identifier]["attrs"]["aria-describedby"].split())
            self.assertIn(phrase, text(self.ids[hint]))
            self.assertNotIn("hidden", self.ids[hint]["attrs"])
        self.assertIn("保存不等于连通", text(self.ids["chainWorkflow"]))
        self.assertIn("下载到本机不等于写入路由器", text(self.ids["converterWorkflow"]))
        self.assertIn("文件写入不代表运行配置已更新", text(self.ids["editorWorkflow"]))
        self.assertIn("仍需核对恢复结果", text(self.ids["customImpact"]))

    def test_status_feedback_stays_polite_and_separate_from_settings(self):
        for identifier in ("notice", "operationStatus", "draftNotice", "customValidation", "validationState", "converterState"):
            self.assertEqual(self.ids[identifier]["attrs"]["role"], "status")
            self.assertEqual(self.ids[identifier]["attrs"]["aria-live"], "polite")
        self.assertEqual(self.ids["lineNumbers"]["attrs"]["aria-hidden"], "true")
        self.assertEqual(self.ids["yamlEditor"]["attrs"]["wrap"], "off")
        self.assertEqual(self.ids["yamlEditor"]["attrs"]["aria-describedby"], "editorLineHint")

    def test_no_extra_scripts_styles_or_inline_event_handlers(self):
        scripts = [n for n in self.page.nodes if n["tag"] == "script"]
        self.assertEqual([n["attrs"]["src"] for n in scripts], ["/app.js", "/converter.js", "/converter_apply.js", "/converter_services.js"])
        self.assertTrue(all("defer" in n["attrs"] and not text(n).strip() for n in scripts))
        self.assertEqual([n["attrs"]["href"] for n in self.page.nodes if n["tag"] == "link" and n["attrs"].get("rel") == "stylesheet"], ["/app.css"])
        self.assertNotIn("@import", self.css)
        for node in self.page.nodes:
            self.assertFalse(any(key.startswith("on") for key in node["attrs"]))

    def test_keyboard_focus_is_visible_including_dark_editor(self):
        for selector in ("button:focus-visible", "a:focus-visible", "summary:focus-visible", "input:focus-visible", "select:focus-visible", "textarea:focus-visible", "#converter textarea:focus-visible"):
            self.assertEqual(self.properties(selector)["outline"], "3px solid var(--focus-ring)")
            self.assertEqual(self.properties(selector)["outline-offset"], "3px")
        self.assertIn("outline", self.properties(".editor-shell:focus-within"))
        self.assertEqual(self.properties(".editor-shell textarea:focus-visible")["outline-offset"], "-4px")
        self.assertEqual(self.properties("#converter [aria-invalid=\"true\"]:focus-visible")["outline-color"], "var(--red)")

    def test_operation_guide_and_navigation_fit_narrow_layout(self):
        self.assertEqual(self.properties(".operation-steps")["grid-template-columns"], "repeat(4, minmax(0, 1fr))")
        narrow = "(max-width: 800px)"
        self.assertEqual(self.properties(".operation-steps", narrow)["grid-template-columns"], "repeat(2, minmax(0, 1fr))")
        self.assertEqual(self.properties(".sidebar", narrow)["grid-template-columns"], "repeat(3, minmax(0, 1fr))")
        self.assertEqual(self.properties(".nav-item", narrow)["white-space"], "normal")
        self.assertNotEqual(self.properties(".sidebar", narrow).get("overflow"), "hidden")

    def test_mobile_and_short_viewport_do_not_overlay_actions(self):
        for media in ("(max-width: 800px)", "(max-height: 600px)"):
            for selector in (".notice", ".custom-footer", ".editor-actions", ".converter-main-actions"):
                props = self.properties(selector, media)
                self.assertEqual(props["position"], "static")
                self.assertEqual((props["top"], props["bottom"]), ("auto", "auto"))
        self.assertIn("env(safe-area-inset-bottom, 0px)", self.properties("main", "(max-width: 480px)")["padding-bottom"])

    def test_touch_targets_inputs_and_action_groups_have_mobile_guards(self):
        for selector in ("button", ".hero > button", ".nav-item", "#loadConverter", ".converter-actions > button"):
            self.assertEqual(self.properties(selector)["min-height"], "44px")
        narrow = "(max-width: 480px)"
        for selector in ('input:not([type="checkbox"])', "select", "textarea", ".editor-shell textarea", ".line-numbers"):
            self.assertEqual(self.properties(selector, narrow)["font-size"], "16px")
        for selector in (".custom-footer > div:last-child", ".editor-actions", ".chain-actions"):
            self.assertEqual(self.properties(selector, narrow)["grid-template-columns"], "repeat(2, minmax(0, 1fr))")
        self.assertEqual(self.properties("#fileHash")["overflow-wrap"], "anywhere")
        for selector, _, props in self.rules:
            if selector in ("html", "body", "main"):
                self.assertNotIn(props.get("overflow-x"), ("hidden", "clip"))

    def test_muted_text_intent_tags_and_primary_writes_have_contrast(self):
        tokens = self.properties(":root")
        for background in ("#ffffff", tokens["--surface-subtle"]):
            self.assertGreaterEqual(contrast(tokens["--muted"], background), 4.5)
        self.assertGreaterEqual(contrast("#ffffff", tokens["--green2"]), 4.5)
        self.assertGreaterEqual(contrast(tokens["--focus-ring"], "#ffffff"), 3)
        for selector in (".intent-read", ".intent-preview", ".intent-write", ".intent-restart"):
            props = self.properties(selector)
            self.assertGreaterEqual(contrast(props["color"], props["background"]), 4.5)

    def test_reduced_motion_and_forced_colors_are_supported(self):
        reduced = self.properties("*", "(prefers-reduced-motion: reduce)")
        self.assertEqual(reduced["transition"], "none !important")
        self.assertEqual(reduced["animation"], "none !important")
        self.assertEqual(self.properties(".intent-tag", "(forced-colors: active)")["border"], "1px solid CanvasText")


if __name__ == "__main__":
    unittest.main()
