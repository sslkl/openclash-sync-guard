"""Offline system-theme and guidance contracts; standard library only.

Reads only public CSS/HTML, writes nothing, imports no application modules and
makes no requests. Contrast checks cover authored sRGB colors, not rasterized
text. This deliberately small CSS reader is not a browser/layout/a11y audit.
"""
from html.parser import HTMLParser
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
DARK = "@media(prefers-color-scheme:dark)"
# All IDs present before this theme change are integration hooks, not snapshots
# of changing content. Additional IDs are allowed.
EXISTING_IDS = frozenset("""
modeText mainContent workspaceHeading refreshStatus notice operationStatus draftNotice
targetGrid updates updatesHeading updatesWorkflow mainUpdateImpact mayingUpdateImpact nexitallyUpdateImpact
custom customHeading loadCustom customWorkflow configuredSummary configuredRules configuredFilters
addRule managedRuleDetails managedRuleCount managedRuleList ruleList routeValue checkRoute
routeResult addFilter managedFilterDetails managedFilterCount managedFilterList filterList customValidation
customImpact customConfirm validateCustom saveCustom chain chainHeading chainWorkflow
chainPreview chainPreviewHeading chainPreviewText chainTarget loadChain chainReadState chainListHeading
chainCount chainList chainForm chainFormHeading chainSelectionState chainNode chainType
chainProtocolHint chainPort chainServer chainEndpointHelp chainUsernameField chainUsername chainPasswordField
chainPassword chainPasswordHint chainKeepPassword chainKeepHint chainTlsField chainTls chainSniField
chainSni chainCipherField chainCipher chainValidation chainConfirm validateChain saveChain
removeChain resetChain chainTestHeading testChain chainTestResult converter converterHeading
loadConverter converterState converterWorkflow converterForm converterProfile converterProfileHint converterTarget
converterTargetHint converterSources converterSourceHint converterLocal converterUpload converterUploadHint converterFiles
clearConverterFiles converterPaste converterAdvanced converterBackend converterBackendHint converterConfigPreset converterConfigPresetHint
converterConfig converterConfigHint converterConfigUpload converterConfigContent converterParameters converterParametersHint converterParametersState
converterOptions converterScripts converterFilterScriptUpload converterFilterScript converterSortScriptUpload converterSortScript converterScriptHint
executeConverter generateConverter validateConverter clearConverter converterExecutionHint converterExportState converterText
copyConverterText downloadConverter restoreConverterText converterApplyMount converterServicesMount converterResourceWorkspace converterResourceHint
converterResourceUpload converterResources clearConverterResources converterTools converter-ruleset converter-ruleset-upload converter-ruleset-content
converter-ruleset-urls converter-ruleset-input-format converter-ruleset-type converter-ruleset-group converter-ruleset-run converter-ruleset-clear converter-ruleset-state
converter-ruleset-result converter-ruleset-copy converter-ruleset-download converter-ruleset-restore converter-template converter-template-upload converter-template-content
converter-template-urls converter-template-variables converter-template-run converter-template-clear converter-template-state converter-template-result converter-template-copy
converter-template-download converter-template-restore converter-surge2clash converter-surge2clash-upload converter-surge2clash-content converter-surge2clash-urls converter-surge2clash-run
converter-surge2clash-clear converter-surge2clash-state converter-surge2clash-result converter-surge2clash-copy converter-surge2clash-download converter-surge2clash-restore converterArchiveWorkspace
converterArchiveUpload exportConverterArchive converterArchiveState converterImport parseConverter converterOutput copyConverter
installConverter editor editorHeading editorWorkflow editorTarget fileName readConfig
editorFileHint lineNumbers yamlEditor editorLineHint validationState cursorPosition fileHash
validateYaml saveConfig rollback rollbackHeading rollbackImpact rollbackTarget rollbackPhrase
rollbackPhraseHint rollbackButton
""".split())


class Page(HTMLParser):
    VOID = frozenset("area base br col embed hr img input link meta param source track wbr".split())

    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self.root = {"tag": "document", "attrs": {}, "children": [], "parent": None}
        self.stack = [self.root]
        self.nodes, self.errors = [], []
        self.feed(source)
        self.close()
        if len(self.stack) != 1:
            self.errors.append("Unclosed HTML element")
        self.ids = {n["attrs"]["id"]: n for n in self.nodes if "id" in n["attrs"]}

    def handle_starttag(self, tag, attrs):
        if len(attrs) != len(dict(attrs)):
            self.errors.append("Duplicate attribute: " + tag)
        node = {"tag": tag, "attrs": dict(attrs), "children": [], "parent": self.stack[-1]}
        self.stack[-1]["children"].append(node)
        self.nodes.append(node)
        if tag not in self.VOID:
            self.stack.append(node)

    def handle_endtag(self, tag):
        if len(self.stack) == 1 or self.stack[-1]["tag"] != tag:
            self.errors.append("Mismatched closing tag: " + tag)
        else:
            self.stack.pop()

    def handle_data(self, value):
        self.stack[-1]["children"].append(value)


def text(node):
    return node if isinstance(node, str) else "".join(text(c) for c in node["children"])


def css_rules(source, context=()):
    """Parse this sheet's rule blocks and media boundaries without dependencies."""
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    cursor = 0
    while cursor < len(source):
        start = source.find("{", cursor)
        if start < 0:
            if source[cursor:].strip():
                raise ValueError("Trailing CSS outside a rule")
            return
        header = source[cursor:start].strip()
        depth, end = 1, start + 1
        while end < len(source) and depth:
            depth += (source[end] == "{") - (source[end] == "}")
            end += 1
        if depth:
            raise ValueError("Unclosed CSS rule")
        body = source[start + 1:end - 1]
        if header.startswith("@media"):
            yield from css_rules(body, context + (re.sub(r"\s+", "", header),))
        elif header.startswith("@"):
            raise ValueError("Unsupported at-rule: " + header)
        else:
            declarations = {}
            for declaration in body.split(";"):
                if declaration.strip():
                    name, value = declaration.split(":", 1)
                    declarations[name.strip()] = value.strip()
            for selector in header.split(","):
                yield selector.strip(), context, declarations
        cursor = end


def contrast(first, second):
    """WCAG relative luminance/contrast for authored, opaque sRGB hex colors."""
    def luminance(value):
        if not re.fullmatch(r"#[0-9a-fA-F]{6}", value):
            raise ValueError("Expected resolved six-digit hex color: " + value)
        channels = [int(value[i:i + 2], 16) / 255 for i in (1, 3, 5)]
        linear = [c / 12.92 if c <= .04045 else ((c + .055) / 1.055) ** 2.4 for c in channels]
        return sum(c * w for c, w in zip(linear, (.2126, .7152, .0722)))
    bright, dark = sorted((luminance(first), luminance(second)), reverse=True)
    return (bright + .05) / (dark + .05)


class SystemThemeFrontendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (ROOT / "static/index.html").read_text(encoding="utf-8")
        cls.css = (ROOT / "static/app.css").read_text(encoding="utf-8")
        cls.page = Page(cls.html)
        cls.rules = list(css_rules(cls.css))

    def declarations(self, selector, dark=False, context=None):
        """Exact authored selector, in source order; not a computed-style engine."""
        result = {}
        allowed = ((), (DARK,)) if dark else ((),)
        if context is not None:
            allowed = ((re.sub(r"\s+", "", "@media" + context),),)
        for candidate, media, declarations in self.rules:
            if candidate == selector and media in allowed:
                result.update(declarations)
        self.assertTrue(result, (selector, dark, context))
        return result

    def resolve(self, value, dark=False):
        tokens = self.declarations(":root", dark)
        for _ in range(len(tokens) + 1):
            if "var(" not in value:
                return value
            previous = value
            value = re.sub(r"var\((--[\w-]+)\)", lambda m: tokens[m[1]], value)
            if value == previous:
                break
        self.fail("Unresolved or cyclic CSS variable: " + value)

    def assert_contrast(self, foreground, background, dark=False, minimum=4.5):
        ratio = contrast(self.resolve(foreground, dark), self.resolve(background, dark))
        self.assertGreaterEqual(ratio, minimum, (dark, foreground, background, round(ratio, 3)))

    def visible_text(self, identifier):
        node = self.page.ids[identifier]
        current = node
        while current:
            self.assertNotIn("hidden", current["attrs"])
            self.assertNotEqual(current["attrs"].get("aria-hidden"), "true")
            self.assertNotIn("hidden", current["attrs"].get("class", "").split())
            current = current["parent"]
        return text(node)

    def test_meta_precedes_stylesheet_for_native_first_paint(self):
        metas = [n for n in self.page.nodes if n["tag"] == "meta" and n["attrs"].get("name") == "color-scheme"]
        self.assertEqual(len(metas), 1)
        self.assertEqual(metas[0]["attrs"]["content"], "light dark")
        self.assertEqual(metas[0]["parent"]["tag"], "head")
        css = next(n for n in self.page.nodes if n["tag"] == "link" and n["attrs"].get("rel") == "stylesheet")
        self.assertLess(self.page.nodes.index(metas[0]), self.page.nodes.index(css))
        self.assertNotIn("media", css["attrs"])
        for selector in ("html", "body"):
            self.assertEqual(self.declarations(selector)["background"], "var(--bg)")

    def test_system_media_owns_theme_without_runtime_toggle_or_storage(self):
        light = self.declarations(":root")
        dark = self.declarations(":root", True)
        self.assertEqual(light["color-scheme"], "light dark")
        self.assertEqual(dark["color-scheme"], "dark")
        required = "ink muted line bg panel surface-subtle surface-inset control-bg control-border green green2 blue red amber focus-ring primary-bg on-primary danger-bg on-danger button-bg button-ink button-hover disabled-bg disabled-ink disabled-border info-bg info-ink info-line success-bg success-ink success-line warning-bg warning-ink warning-line error-bg error-ink error-line selection-bg selection-ink".split()
        for name in required:
            with self.subTest(token=name):
                self.assertNotEqual(light["--" + name], dark["--" + name])
        self.assertTrue(any(selector == ":root" and media == (DARK,) for selector, media, _ in self.rules))
        for forbidden in ("data-theme", "localStorage", "sessionStorage", "matchMedia"):
            self.assertNotIn(forbidden, self.html + self.css)

    def test_all_variables_resolve_in_both_themes(self):
        for dark in (False, True):
            tokens = self.declarations(":root", dark)
            used = set(re.findall(r"var\((--[\w-]+)", self.css))
            self.assertFalse(used.difference(tokens), used.difference(tokens))
            for name in used:
                self.resolve("var(" + name + ")", dark)

    def test_surface_colors_are_tokenized_not_late_white_overrides(self):
        light_tags = {".intent-read", ".intent-preview", ".intent-write", ".intent-restart"}
        for selector, media, declarations in self.rules:
            if selector == ":root":
                continue
            if not media and selector in light_tags:
                # Keep the established light-label palette and its existing tests.
                self.assertTrue(self.declarations(selector, True)["background"].startswith("var("))
                continue
            for name, value in declarations.items():
                with self.subTest(selector=selector, property=name, media=media):
                    self.assertIsNone(re.search(r"#[0-9a-fA-F]{3,8}\b|rgba?\(", value))

    def test_readable_text_and_control_boundaries_in_both_themes(self):
        for dark in (False, True):
            for surface in ("bg", "panel", "surface-subtle", "surface-inset", "control-bg"):
                for foreground in ("ink", "muted"):
                    self.assert_contrast("var(--" + foreground + ")", "var(--" + surface + ")", dark)
            for background in ("var(--control-bg)", "var(--panel)"):
                self.assert_contrast("var(--control-border)", background, dark, 3)
            for foreground in ("var(--green)", "var(--green2)", "var(--blue)", "var(--red)", "var(--amber)"):
                self.assert_contrast(foreground, "var(--panel)", dark)
            self.assert_contrast("var(--button-ink)", "var(--button-hover)", dark)

    def test_semantic_messages_and_intent_labels_are_readable(self):
        for dark in (False, True):
            for semantic in ("info", "success", "warning", "error"):
                self.assert_contrast("var(--" + semantic + "-ink)", "var(--" + semantic + "-bg)", dark)
                self.assert_contrast("var(--" + semantic + "-line)", "var(--" + semantic + "-bg)", dark, 3)
            for selector in (".intent-read", ".intent-preview", ".intent-write", ".intent-restart", ".operation-status", ".draft-notice", ".warning", ".notice", ".notice.error"):
                props = self.declarations(selector, dark)
                self.assert_contrast(props["color"], props["background"], dark)
            for foreground in ("var(--green2)", "var(--red)", "var(--warning-ink)"):
                self.assert_contrast(foreground, "var(--surface-inset)", dark)

    def test_action_buttons_keep_separate_foreground_and_background_tokens(self):
        for dark in (False, True):
            for selector in ("button", ".primary", ".primary-card button", "button.write-action", "button.secondary-write", "button.preview-action", ".danger"):
                props = self.declarations(selector, dark)
                self.assert_contrast(props["color"], props["background"], dark)
            self.assertEqual(self.declarations("button.write-action")["background"], "var(--primary-bg)")
            self.assertEqual(self.declarations(".danger")["color"], "var(--on-danger)")

    def test_disabled_and_placeholder_text_do_not_disappear(self):
        selectors = ("button:disabled", "input:disabled", "select:disabled", "textarea:disabled", "#converter input:disabled", "#converter select:disabled", "#converter textarea:disabled", "#converter input[type=file]:disabled::file-selector-button")
        for dark in (False, True):
            for selector in selectors:
                props = self.declarations(selector, dark)
                self.assertEqual(props["opacity"], "1")
                self.assertEqual(props["cursor"], "not-allowed")
                self.assertEqual(props["-webkit-text-fill-color"], "var(--disabled-ink)")
                self.assert_contrast(props["color"], props["background"], dark)
            for selector in ("input::placeholder", "textarea::placeholder"):
                props = self.declarations(selector, dark)
                self.assertEqual(props["opacity"], "1")
                self.assert_contrast(props["color"], "var(--control-bg)", dark)

    def test_keyboard_focus_and_selection_remain_visible(self):
        for dark in (False, True):
            for selector in ("button:focus-visible", "a:focus-visible", "summary:focus-visible", "input:focus-visible", "select:focus-visible", "textarea:focus-visible", "#converter textarea:focus-visible"):
                props = self.declarations(selector, dark)
                self.assertEqual(props["outline"], "3px solid var(--focus-ring)")
                self.assertEqual(props["outline-offset"], "3px")
            for surface in ("bg", "panel", "control-bg"):
                self.assert_contrast("var(--focus-ring)", "var(--" + surface + ")", dark, 3)
            self.assert_contrast("var(--selection-ink)", "var(--selection-bg)", dark)
            self.assertEqual(self.declarations("::selection")["background"], "var(--selection-bg)")

    def test_editor_keeps_its_own_dark_palette_and_native_scheme(self):
        for dark in (False, True):
            self.assertEqual(self.declarations(".editor-shell", dark)["color-scheme"], "dark")
            for selector in (".editor-shell textarea", ".readonly-config pre", ".line-numbers", ".editor-shell textarea:disabled"):
                props = self.declarations(selector, dark)
                self.assert_contrast(props["color"], props["background"], dark)
            self.assert_contrast("var(--editor-muted)", "var(--editor-bg)", dark)
            self.assert_contrast("var(--editor-focus)", "var(--editor-bg)", dark, 3)
        self.assertEqual(self.declarations(".editor-shell textarea:focus-visible")["outline-offset"], "-4px")
        self.assertEqual(self.declarations(".editor-shell textarea")["caret-color"], "var(--editor-ink)")

    def test_dynamic_converter_surfaces_share_theme_tokens(self):
        for dark in (False, True):
            for selector in ("#converter textarea", "#converter details", "#converter .converter-tool", "#converter .converter-tool-result", "#converterText", "#converter input[type=file]", "#converter input[type=file]::file-selector-button", "#converterApplyWorkspace .converter-apply-summary>div", ".converter-service-meta"):
                props = self.declarations(selector, dark)
                self.assertTrue(props["background"].startswith("var("), selector)
                self.resolve(props["background"], dark)
            self.assertEqual(self.declarations('#converter [aria-invalid="true"]')["background"], "var(--error-bg)")
            for state in ("error", "stale"):
                self.assertEqual(self.declarations("#converterApplyState[data-state=" + state + "]")["color"], "var(--red)")
            for state in ("unknown", "unverified"):
                self.assertEqual(self.declarations("#converterApplyState[data-state=" + state + "]")["color"], "var(--warning-ink)")

    def test_navigation_tables_details_and_preview_are_theme_aware(self):
        for dark in (False, True):
            for selector in (".sidebar", ".nav-item.active", "table", "th", ".managed-items", ".managed-item", ".chain-item", ".chain-results-grid > div"):
                props = self.declarations(selector, dark)
                self.assertTrue(props["background"].startswith("var("), selector)
            self.assertEqual(self.declarations("summary")["min-height"], "44px")
            self.assertEqual(self.declarations(".nav-item.active")["box-shadow"], "inset 3px 0 0 var(--green2)")
            self.assertEqual(self.declarations("#converter details[open]>summary")["border-bottom"], "1px solid var(--line)")
            self.assert_contrast(self.declarations(".nav-item.active")["color"], self.declarations(".nav-item.active")["background"], dark)

    def test_original_ids_labels_and_action_hooks_survive(self):
        self.assertEqual(self.page.errors, [])
        ids = [n["attrs"]["id"] for n in self.page.nodes if "id" in n["attrs"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(EXISTING_IDS.issubset(ids), EXISTING_IDS.difference(ids))
        actions = {n["attrs"]["data-action"]: text(n) for n in self.page.nodes if "data-action" in n["attrs"]}
        self.assertEqual(actions, {"stage-main": "检查并更新", "update-maying": "更新 Maying", "update-nexitally": "更新 Nexitally"})
        panels = [n["attrs"]["data-panel"] for n in self.page.nodes if "data-panel" in n["attrs"]]
        self.assertEqual(panels, ["updates", "custom", "chain", "editor", "rollback", "converter"])
        for node in self.page.nodes:
            for attribute in ("aria-labelledby", "aria-describedby", "aria-controls", "for"):
                for identifier in node["attrs"].get(attribute, "").split():
                    self.assertIn(identifier, self.page.ids)

    def test_confirmation_and_initial_disabled_boundaries_survive(self):
        for identifier in ("customConfirm", "chainConfirm"):
            attrs = self.page.ids[identifier]["attrs"]
            self.assertEqual(attrs["type"], "checkbox")
            self.assertNotIn("checked", attrs)
        for identifier in ("saveCustom", "saveChain", "saveConfig", "rollbackButton", "executeConverter", "generateConverter", "downloadConverter", "installConverter"):
            self.assertIn("disabled", self.page.ids[identifier]["attrs"])
        self.assertEqual(self.page.ids["chainPassword"]["attrs"]["type"], "password")
        self.assertNotIn("value", self.page.ids["chainPassword"]["attrs"])
        self.assertIn("readonly", self.page.ids["converterOutput"]["attrs"])
        self.assertEqual(self.page.ids["yamlEditor"]["attrs"]["wrap"], "off")
        for identifier in ("converterApplyMount", "converterServicesMount"):
            self.assertFalse(self.page.ids[identifier]["children"])
        for identifier in ("notice", "operationStatus", "draftNotice", "converterState", "validationState"):
            self.assertEqual(self.page.ids[identifier]["attrs"]["aria-live"], "polite")

    def test_appearance_and_homepage_stop_conditions_are_visible(self):
        appearance = self.visible_text("appearanceNote")
        for phrase in ("外观随系统", "浅色 / 深色", "无需刷新"):
            self.assertIn(phrase, appearance)
        guide = self.visible_text("statusGuide")
        for phrase in ("先点“刷新状态”", "两个子网", "UNKNOWN", "不是正常或故障结论", "不要继续写入", "ACTIVE", "不是运行验收通过"):
            self.assertIn(phrase, guide)
        operation_guide = next(n for n in self.page.nodes if "operation-guide" in n["attrs"].get("class", "").split())
        self.assertIn("Stage（暂存）", text(operation_guide))
        self.assertIn("不代表生效", text(operation_guide))

    def test_panel_guidance_explains_sequence_results_and_stopping(self):
        required = {
            "updatesWorkflow": ("不是只读检查", "两边回执", "不要重复点击写入"),
            "customWorkflow": ("先读取", "冲突或摘要变化", "不要反复保存"),
            "chainWorkflow": ("只作用于所选子网", "保存不等于连通", "UNKNOWN", "不要当作链路可用"),
            "converterWorkflow": ("转换与应用分开", "下载到本机不等于写入路由器", "不要应用到路由器"),
            "editorWorkflow": ("先读取，再保存", "文件写入不代表运行配置已更新", "摘要不一致", "先停止保存"),
            "rollbackPhraseHint": ("目标子网", "运行态", "请不要继续"),
        }
        for identifier, phrases in required.items():
            value = self.visible_text(identifier)
            for phrase in phrases:
                self.assertIn(phrase, value)
        for phrase in ("不会切换 ACTIVE", "写入 UCI", "reload"):
            self.assertIn(phrase, self.visible_text("rollbackImpact"))

    def test_no_added_scripts_inline_handlers_or_remote_css_dependencies(self):
        scripts = [n for n in self.page.nodes if n["tag"] == "script"]
        self.assertEqual([n["attrs"].get("src") for n in scripts], ["/app.js", "/converter.js", "/converter_apply.js", "/converter_services.js"])
        for node in scripts:
            self.assertIn("defer", node["attrs"])
            self.assertFalse(text(node).strip())
        self.assertEqual([n["attrs"].get("href") for n in self.page.nodes if n["tag"] == "link" and n["attrs"].get("rel") == "stylesheet"], ["/app.css"])
        for node in self.page.nodes:
            self.assertNotEqual(node["tag"], "style")
            self.assertNotIn("style", node["attrs"])
            self.assertFalse(any(name.startswith("on") for name in node["attrs"]))
        self.assertNotIn("@import", self.css)
        self.assertNotRegex(self.css, r"url\s*\(")

    def test_forced_colors_and_reduced_motion_stay_supported(self):
        forced = "(forced-colors: active)"
        for selector in ("button:focus-visible", "input:focus-visible", "#converter textarea:focus-visible", ".editor-shell textarea:focus-visible"):
            self.assertEqual(self.declarations(selector, context=forced)["outline-color"], "Highlight")
        self.assertEqual(self.declarations("#converter input:disabled", context=forced)["color"], "GrayText")
        self.assertEqual(self.declarations("*", context="(prefers-reduced-motion: reduce)")["transition"], "none !important")
        self.assertNotIn("forced-color-adjust", self.css)


if __name__ == "__main__":
    unittest.main()
