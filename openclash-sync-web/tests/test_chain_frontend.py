#!/usr/bin/env python3
"""Offline DOM/async contract tests for the chain UI (not visual acceptance).

Runs the actual app.js using Node's standard library and a deliberately small
DOM fixture built from the actual HTML. No npm modules, router, credentials or
network requests are required. Set OPENCLASH_TEST_NODE if Node is not on PATH.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest
from html.parser import HTMLParser

ROOT = Path(__file__).resolve().parents[1]


class PageParser(HTMLParser):
    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self, html):
        super().__init__(convert_charrefs=True)
        self.root = {"tag": "document", "attrs": {}, "children": []}
        self.stack = [self.root]
        self.elements = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        node = {"tag": tag, "attrs": dict(attrs), "children": []}
        self.stack[-1]["children"].append(node)
        self.elements.append(node)
        if tag not in self.VOID:
            self.stack.append(node)

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, 0, -1):
            if self.stack[index]["tag"] == tag:
                self.stack = self.stack[:index]
                break

    def handle_data(self, data):
        self.stack[-1]["children"].append({"tag": "#text", "text": data})


HARNESS = r'''
const assert = require("node:assert/strict");
const encode = value => String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
const decode = value => value.replaceAll("&quot;", '"').replaceAll("&#39;", "'").replaceAll("&lt;", "<").replaceAll("&gt;", ">").replaceAll("&amp;", "&");
const voidTags = new Set(["INPUT", "BR", "IMG", "META", "LINK"]);
class MiniElement {
  constructor(tag, attrs = {}, text = "") {
    this.tagName = tag.toUpperCase(); this.attrs = {...attrs}; this.children = [];
    this.parentNode = null; this.listeners = new Map(); this._text = text;
    this._value = undefined; this.disabled = "disabled" in attrs; this.checked = "checked" in attrs;
    this.selectionStart = 0; this.scrollTop = 0; this.readOnly = false;
    this.classList = {
      contains: c => this.className.split(/\s+/).includes(c),
      toggle: (c, force) => {
        const found = this.classList.contains(c), set = force === undefined ? !found : force;
        this.className = [...new Set(this.className.split(/\s+/).filter(x => x && x !== c).concat(set ? [c] : []))].join(" ");
        return set;
      },
      add: c => this.classList.toggle(c, true), remove: c => this.classList.toggle(c, false)
    };
  }
  get id() { return this.attrs.id || ""; }
  get type() { return this.attrs.type || (this.tagName === "INPUT" ? "text" : ""); }
  set type(value) { this.attrs.type = value; }
  get className() { return this.attrs.class || ""; }
  set className(value) { this.attrs.class = value; }
  get dataset() { return Object.fromEntries(Object.entries(this.attrs).filter(([k]) => k.startsWith("data-")).map(([k, v]) => [k.slice(5), v])); }
  get value() {
    if (this._value !== undefined) return this._value;
    if (this.tagName === "SELECT") {
      const options = this.querySelectorAll("option");
      const selected = options.find(o => "selected" in o.attrs) || options[0];
      return selected ? selected.value : "";
    }
    return this.attrs.value || (this.tagName === "TEXTAREA" ? this.textContent : "");
  }
  set value(value) { this._value = String(value); }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(""); }
  set textContent(value) { this.replaceChildren(); this._text = String(value); }
  get innerHTML() { return encode(this._text) + this.children.map(child => child.outerHTML).join(""); }
  set innerHTML(value) {
    this.replaceChildren();
    const stack = [this];
    for (const match of String(value).matchAll(/<\/([\w-]+)\s*>|<([\w-]+)([^>]*)>|([^<]+)/g)) {
      if (match[1]) { if (stack.length > 1) stack.pop(); }
      else if (match[2]) {
        const attrs = {};
        for (const attr of match[3].matchAll(/([\w:-]+)(?:="([^"]*)"|='([^']*)')?/g)) attrs[attr[1]] = decode(attr[2] ?? attr[3] ?? "");
        const el = new MiniElement(match[2], attrs);
        stack.at(-1).append(el);
        if (!voidTags.has(el.tagName)) stack.push(el);
      } else if (match[4]) stack.at(-1).append(new MiniElement("#text", {}, decode(match[4])));
    }
  }
  get outerHTML() { return this.tagName === "#TEXT" ? encode(this._text) : `<${this.tagName.toLowerCase()}>${this.innerHTML}</${this.tagName.toLowerCase()}>`; }
  append(...children) {
    for (let child of children) {
      if (typeof child === "string") child = new MiniElement("#text", {}, child);
      child.remove(); child.parentNode = this; this.children.push(child);
    }
  }
  remove() {
    if (this.parentNode) this.parentNode.children = this.parentNode.children.filter(child => child !== this);
    this.parentNode = null;
  }
  replaceChildren(...children) {
    this.children.forEach(child => { child.parentNode = null; }); this.children = []; this._text = "";
    if (this.tagName === "SELECT") this._value = undefined;
    this.append(...children);
  }
  setAttribute(key, value) { this.attrs[key] = String(value); }
  removeAttribute(key) { delete this.attrs[key]; }
  getAttribute(key) { return this.attrs[key] ?? null; }
  addEventListener(type, callback) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(callback);
  }
  async dispatch(type, extra = {}) {
    const event = {target: this, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }, ...extra};
    await Promise.all((this.listeners.get(type) || []).map(callback => callback(event)));
    return event;
  }
  click() { return this.disabled ? Promise.resolve() : this.dispatch("click"); }
  focus() { document.activeElement = this; }
  setSelectionRange(start, end) { this.selectionStart = start; this.selectionEnd = end; }
  querySelectorAll(query) {
    const all = [];
    const walk = el => { for (const child of el.children) { all.push(child); walk(child); } };
    walk(this);
    return all.filter(el => query.split(",").some(part => matches(el, part.trim().split(/\s+/))));
  }
  querySelector(query) { return this.querySelectorAll(query)[0] || null; }
}
function simpleMatch(el, token) {
  if (!el) return false;
  const last = token.endsWith(":last-of-type"); token = token.replace(":last-of-type", "");
  const attr = token.match(/\[([^\]=]+)(?:="([^"]*)")?\]/);
  if (attr && (!(attr[1] in el.attrs) || (attr[2] !== undefined && el.attrs[attr[1]] !== attr[2]))) return false;
  token = token.replace(/\[[^\]]*\]/g, "");
  const id = token.match(/#([\w-]+)/), classes = [...token.matchAll(/\.([\w-]+)/g)];
  const tag = token.match(/^[\w-]+/);
  if (id && el.id !== id[1]) return false;
  if (tag && el.tagName !== tag[0].toUpperCase()) return false;
  if (classes.some(c => !el.classList.contains(c[1]))) return false;
  if (last && el.parentNode?.children.filter(child => child.tagName === el.tagName).at(-1) !== el) return false;
  return true;
}
function matches(el, tokens) {
  if (!simpleMatch(el, tokens.at(-1))) return false;
  let parent = el.parentNode;
  for (let index = tokens.length - 2; index >= 0; index--) {
    while (parent && !simpleMatch(parent, tokens[index])) parent = parent.parentNode;
    if (!parent) return false;
    parent = parent.parentNode;
  }
  return true;
}
function makeTree(node) {
  const el = new MiniElement(node.tag, node.attrs, node.text || "");
  for (const child of node.children || []) el.append(makeTree(child));
  return el;
}
const document = makeTree(PAGE_TREE);
document.createElement = tag => new MiniElement(tag);
const window = new MiniElement("window");
let confirmation = true, confirmations = 0;
window.confirm = () => { confirmations++; return confirmation; };
let timerId = 0; const timers = new Map();
function setTimeout(fn) { const id = ++timerId; timers.set(id, fn); return id; }
function clearTimeout(id) { timers.delete(id); }
const routes = new Map(), requestLog = [];
let nonceId = 0, fixtureMode = "live";
const response = (data, status = 200) => ({ok: status >= 200 && status < 300, json: async () => data});
async function fetch(path, options = {}) {
  const body = options.body === undefined ? undefined : JSON.parse(options.body);
  requestLog.push({path, body, signal: options.signal});
  if (routes.has(path)) return routes.get(path)(body, options);
  if (path === "/api/bootstrap") return response({ok: true, nonce: "token-" + ++nonceId, mode: fixtureMode});
  if (path === "/api/status") return response({ok: true, targets: []});
  if (path === "/api/chain/validate") return response({ok: true, message: "配置合法，尚未测试"});
  if (path === "/api/validate") return response({ok: true, summary: {proxies: 1, groups: 1, rules: 1}});
  if (path === "/api/custom/validate") return response({ok: true, ...body.customization, summary: {rules: body.customization.rules.length, fake_ip_filter: body.customization.fake_ip_filter.length}});
  throw new Error("Unexpected request: " + path);
}
const waitTick = () => new Promise(resolve => setImmediate(resolve));
async function settle() { for (let count = 0; count < 6; count++) await waitTick(); }
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return {promise, resolve}; }
const fixtureProfile = {node: "Node A", type: "http", server: "exit.example.test", port: 443,
  username: "example-user", tls: true, sni: "exit.example.test", cipher: "", has_password: true};
function fixtureRead(profiles = [fixtureProfile], target = "router_a") {
  return {ok: true, target, config_sha256: "a".repeat(64), state_sha256: "b".repeat(64),
    nodes: [{name: "Node A", type: "ss"}, {name: "Node B", type: "vmess"}], chains: profiles, message: "已读取"};
}
async function loadFixture(profiles = [fixtureProfile]) {
  routes.set("/api/chain/read", () => response(fixtureRead(profiles)));
  await $("#loadChain").click();
  assert.equal(chainReady(), true);
  selectChainNode("Node A");
}
async function inputValue(id, value, event = "input") {
  const el = $("#" + id);
  if (typeof value === "boolean") el.checked = value; else el.value = value;
  await el.dispatch(event);
}
'''


class ChainFrontendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (ROOT / "static/index.html").read_text()
        cls.app = (ROOT / "static/app.js").read_text()
        cls.css = (ROOT / "static/app.css").read_text()
        cls.page = PageParser(cls.html)
        cls.node = os.environ.get("OPENCLASH_TEST_NODE") or shutil.which("node")

    def run_js(self, body):
        if not self.node:
            self.skipTest("Node.js is required for executable offline frontend checks")
        source = "const PAGE_TREE = " + json.dumps(self.page.root, ensure_ascii=False) + ";\n"
        source += HARNESS + "\n" + self.app
        source += "\n(async () => { await settle(); assert.equal(operationBusy, false); requestLog.length = 0;\n"
        source += body + '\nawait settle(); process.stdout.write("PASS\\n"); })().catch(error => { process.stderr.write(error.stack + "\\n"); process.exitCode = 1; });\n'
        result = subprocess.run([self.node, "-"], input=source, text=True,
                                capture_output=True, timeout=20, cwd=ROOT, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "PASS")

    def test_html_has_unique_ids_and_explicit_chain_labels(self):
        ids = [node["attrs"]["id"] for node in self.page.elements if "id" in node["attrs"]]
        self.assertEqual(len(ids), len(set(ids)))
        labels = {node["attrs"].get("for") for node in self.page.elements if node["tag"] == "label"}
        fields = {"chainTarget", "chainNode", "chainType", "chainServer", "chainPort", "chainUsername",
                  "chainPassword", "chainTls", "chainSni", "chainCipher", "chainKeepPassword", "chainConfirm"}
        self.assertTrue(fields.issubset(labels))
        password = next(n["attrs"] for n in self.page.elements if n["attrs"].get("id") == "chainPassword")
        self.assertEqual(password["type"], "password")
        self.assertNotIn("value", password)
        self.assertEqual(password["autocomplete"], "new-password")
        for panel in ("updates", "custom", "editor", "rollback", "chain"):
            self.assertIn(panel, ids)
        self.assertIn("原节点 → 落地代理 → 网站", self.html)
        self.assertIn("不是裸 IP 转发", self.html)
        self.assertIn("chain-results-grid", self.css)
        self.assertIn("@media (max-width: 480px)", self.css)
        self.assertIn("button:focus-visible", self.css)

    def test_no_persistent_secret_storage_or_browser_logging(self):
        for forbidden in ("localStorage", "sessionStorage", "indexedDB", "console.", "document.cookie"):
            self.assertNotIn(forbidden, self.app)

    def test_initialization_and_operation_button_state(self):
        self.run_js(r'''
assert.equal($("#loadChain").disabled, false);
assert.equal($("#saveChain").disabled, true);
assert.equal($("#testChain").disabled, true);
assert.equal($("#chainPassword").disabled, true);
assert.equal(Object.values(draftFlags()).some(Boolean), false);
assert.equal($("#chainPreview").classList.contains("hidden"), true);
''')

    def test_one_lock_covers_nonce_read_and_followup_refresh(self):
        self.run_js(r'''
const pending = deferred();
routes.set("/api/chain/read", () => pending.promise);
const first = $("#loadChain").click();
assert.equal(operationBusy, true);
assert.equal($("#readConfig").disabled, true);
assert.equal($("#chainTarget").disabled, true);
assert.equal($("#checkRoute").disabled, true);
const duplicate = await runOperation("second", () => nonceRequest("/api/read", {target: "router_b"}));
assert.equal(duplicate, null);
assert.equal(requestLog.filter(r => r.path === "/api/read").length, 0);
pending.resolve(response(fixtureRead())); await first;
assert.equal(operationBusy, false);
assert.equal($("#loadChain").disabled, false);
assert.equal($("#readConfig").disabled, false);
assert.equal(requestLog.filter(r => r.path === "/api/bootstrap").length, 1);
assert.equal(nonce, "token-2");
''')

    def test_nonce_failure_releases_lock_and_rotates_without_retry(self):
        self.run_js(r'''
routes.set("/api/chain/read", () => response({ok: false, message: "synthetic error"}, 503));
await $("#loadChain").click();
assert.equal(operationBusy, false); assert.equal($("#loadChain").disabled, false);
assert.equal(requestLog.filter(r => r.path === "/api/chain/read").length, 1);
assert.equal(nonce, "token-2");
routes.set("/api/chain/read", () => response(fixtureRead()));
await $("#loadChain").click();
assert.equal(requestLog.filter(r => r.path === "/api/chain/read")[1].body.nonce, "token-2");
''')

    def test_yaml_validation_old_success_does_not_replace_new_failure(self):
        self.run_js(r'''
const first = deferred(), second = deferred(); let count = 0;
routes.set("/api/validate", () => ++count === 1 ? first.promise : second.promise);
editor.value = "first"; const a = validate();
await inputValue("yamlEditor", "second"); const b = validate();
second.resolve(response({ok: false, message: "new error", line: 1, column: 1})); await b;
first.resolve(response({ok: true, summary: {proxies: 99, groups: 99, rules: 99}})); await a;
assert.equal(yamlIsValid, false); assert.match($("#validationState").textContent, /new error/);
assert.equal($("#saveConfig").disabled, true);
assert.equal(requestLog[0].signal.aborted, true);
''')

    def test_custom_validation_old_failure_does_not_replace_new_success(self):
        self.run_js(r'''
const first = deferred(), second = deferred(); let count = 0;
routes.set("/api/custom/validate", () => ++count === 1 ? first.promise : second.promise);
savedFilters = ["old.example"]; const a = validateCustom();
savedFilters = ["new.example"]; scheduleCustomValidation(); const b = validateCustom();
second.resolve(response({ok: true, rules: [], fake_ip_filter: ["new.example"], summary: {rules: 0, fake_ip_filter: 1}})); await b;
first.resolve(response({ok: false, message: "old error", errors: [{section: "fake_ip_filter", index: 0, message: "stale"}]}, 422)); await a;
assert.equal(customIsValid, true); assert.match($("#customValidation").textContent, /检查通过/);
assert.doesNotMatch($("#notice").textContent, /old error/);
''')

    def test_custom_union_supplemental_and_conflict_behavior_preserved(self):
        self.run_js(r'''
savedRules = [{type: "DOMAIN", value: "saved.example", policy: "DIRECT"}];
reconciliationRules = [{type: "DOMAIN-SUFFIX", value: "one-sided.example", policy: "AI"}];
savedFilters = ["saved.lan"]; reconciliationFilters = ["one-sided.lan"];
supplementalRules = ["IP-CIDR,192.0.2.0/24,DIRECT,no-resolve"];
supplementalFilters = ["+.raw.example"];
const value = collectCustom();
assert.equal(value.rules.length, 2); assert.equal(value.fake_ip_filter.length, 2);
assert.equal(value.supplemental_rules[0], supplementalRules[0]);
unownedRulesByMatcher.set(ruleMatcher(savedRules[0]), ["DOMAIN,saved.example,AI"]);
const conflict = configuredDuplicateResult({ok: true, rules: value.rules, fake_ip_filter: value.fake_ip_filter});
assert.equal(conflict.ok, false); assert.match(conflict.errors[0].message, /内容不同/);
assert.match(routeLabel({mode: "PROXY", certainty: "EXACT", policy: "AI", reachability: "UNKNOWN"}), /UNKNOWN/);
assert.match(routeLabel({mode: "REJECT", certainty: "EXACT", policy: "REJECT"}), /已拦截/);
''')

    def test_managed_edit_cancel_restores_rules_and_filters(self):
        self.run_js(r'''
const original = {type: "DOMAIN", value: "saved.example", policy: "DIRECT"};
savedRules = [original]; savedFilters = ["printer.lan"];
renderManagedRules(); renderManagedFilters(); customBaseline = JSON.stringify(collectCustom());
await $("#managedRuleList .ghost").click();
assert.equal(savedRules.length, 0); assert.equal(document.querySelectorAll("#ruleList .rule-row").length, 1);
assert.equal($("#ruleList .rule-value").value, "saved.example");
assert.deepEqual(collectCustom().rules, [original]);
await $("#ruleList .remove-row").click();
assert.equal(savedRules[0], original); assert.equal(document.querySelectorAll("#ruleList .rule-row").length, 0);
assert.deepEqual(collectCustom().rules, [original]);
await $("#managedFilterList .ghost").click();
assert.equal(savedFilters.length, 0);
await $("#filterList .remove-row").click();
assert.deepEqual(savedFilters, ["printer.lan"]); assert.equal(draftFlags().custom, false);
''')

    def test_read_password_is_not_returned_to_form_and_keep_is_explicit(self):
        self.run_js(r'''
await loadFixture();
assert.equal($("#chainPassword").value, "");
assert.equal($("#chainKeepPassword").checked, false);
assert.equal($("#chainKeepPassword").disabled, false);
assert.equal(Object.hasOwn(chainProfiles[0], "password"), false);
assert.match($("#chainList").textContent, /不回显/);
await inputValue("chainKeepPassword", true, "change");
assert.equal(collectChain().keep_password, true);
assert.equal(localChainError(collectChain()), "");
assert.equal($("#chainPassword").disabled, true);
assert.equal(await validateChain(), true);
const validation = requestLog.find(r => r.path === "/api/chain/validate").body;
assert.equal(Object.hasOwn(validation, "nonce"), false);
assert.equal(validation.chain.password, "");
''')

    def test_sensitive_read_field_and_invalid_hash_are_rejected(self):
        self.run_js(r'''
assert.throws(() => publicChainRead(fixtureRead([{...fixtureProfile, password: "synthetic-secret"}]), "router_a"), /公开视图/);
assert.throws(() => publicChainRead({...fixtureRead(), state_sha256: "invalid"}, "router_a"), /摘要/);
assert.throws(() => publicChainRead(fixtureRead(), "router_b"), /摘要/);
assert.equal($("#chainPassword").value, "");
''')

    def test_identity_changes_disable_keep_password_for_all_fields(self):
        self.run_js(r'''
await loadFixture();
for (const [field, value, kind] of [["chainServer", "other.example.test", "input"], ["chainPort", "8443", "input"],
  ["chainUsername", "different-user", "input"], ["chainSni", "other.example.test", "input"],
  ["chainTls", false, "change"], ["chainType", "socks5", "change"]]) {
  fillChainForm("Node A"); await inputValue("chainKeepPassword", true, "change");
  await inputValue(field, value, kind);
  assert.equal($("#chainKeepPassword").checked, false, field);
  assert.equal($("#chainKeepPassword").disabled, true, field);
}
chainProfiles = [{...fixtureProfile, type: "ss", username: "", tls: false, sni: "", cipher: "aes-128-gcm"}];
fillChainForm("Node A"); await inputValue("chainKeepPassword", true, "change");
await inputValue("chainCipher", "aes-256-gcm", "change");
assert.equal($("#chainKeepPassword").disabled, true);
assert.equal($("#chainKeepPassword").checked, false);
''')

    def test_ss_fields_and_address_validation(self):
        self.run_js(r'''
await loadFixture([]);
await inputValue("chainType", "ss", "change");
await inputValue("chainServer", "exit.example.test"); await inputValue("chainPort", "8388");
assert.equal($("#chainUsernameField").classList.contains("hidden"), true);
assert.equal($("#chainSni").disabled, true);
assert.equal($("#chainCipherField").classList.contains("hidden"), false);
assert.match(localChainError(collectChain()), /密码/);
await inputValue("chainPassword", "synthetic-secret");
assert.equal(localChainError(collectChain()), "");
assert.deepEqual([...chainCiphers], ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"]);
await inputValue("chainServer", "https://user:password@proxy.example/subscribe");
const before = requestLog.length; assert.equal(await validateChain(), false);
assert.equal(requestLog.length, before); assert.doesNotMatch($("#chainValidation").textContent, /user:password/);
''')

    def test_chain_validation_ignores_old_password_response(self):
        self.run_js(r'''
await loadFixture();
const first = deferred(), second = deferred(); let count = 0;
routes.set("/api/chain/validate", () => ++count === 1 ? first.promise : second.promise);
await inputValue("chainPassword", "synthetic-old"); const a = validateChain();
await inputValue("chainPassword", "synthetic-new"); const b = validateChain();
second.resolve(response({ok: false, message: "new validation error"}, 422)); await b;
first.resolve(response({ok: true, message: "stale success"})); await a;
assert.equal(chainIsValid, false); assert.match($("#chainValidation").textContent, /new validation error/);
assert.doesNotMatch($("#chainValidation").textContent, /stale success/);
''')

    def test_apply_has_exact_target_hashes_and_clears_password_then_reads(self):
        self.run_js(r'''
await loadFixture([]);
await inputValue("chainType", "ss", "change");
await inputValue("chainServer", "exit.example.test"); await inputValue("chainPort", "8388");
await inputValue("chainPassword", "synthetic-secret");
await inputValue("chainConfirm", true, "change");
routes.set("/api/chain/apply", body => {
  assert.equal(body.target, "router_a"); assert.equal(body.operation, "upsert");
  assert.equal(body.expected_config_sha256, "a".repeat(64)); assert.equal(body.expected_state_sha256, "b".repeat(64));
  assert.deepEqual(Object.keys(body.chain).sort(), ["cipher", "keep_password", "node", "password", "port", "server", "sni", "tls", "type", "username"]);
  assert.equal(body.chain.password, "synthetic-secret"); assert.equal(body.chain.keep_password, false);
  const {password, keep_password, ...publicProfile} = body.chain;
  routes.set("/api/chain/read", () => response(fixtureRead([{...publicProfile, has_password: true}])));
  return response({ok: true, message: "applied"});
});
await $("#chainForm").dispatch("submit");
assert.equal($("#chainPassword").value, ""); assert.equal($("#chainKeepPassword").checked, false);
assert.equal(requestLog.filter(r => r.path === "/api/chain/read").length, 2);
assert.equal(chainProfiles[0].type, "ss"); assert.equal(draftFlags().chain, false);
assert.equal($("#testChain").disabled, false); assert.equal(operationBusy, false);
''')

    def test_failed_apply_clears_password_unlocks_and_requires_reread(self):
        self.run_js(r'''
await loadFixture(); await inputValue("chainPassword", "synthetic-secret");
await inputValue("chainConfirm", true, "change");
routes.set("/api/chain/apply", () => response({ok: false, message: "synthetic failure"}, 502));
await $("#chainForm").dispatch("submit");
assert.equal($("#chainPassword").value, ""); assert.equal(chainReady(), false);
assert.equal($("#loadChain").disabled, false); assert.equal($("#testChain").disabled, true);
assert.equal(operationBusy, false); assert.equal(requestLog.filter(r => r.path === "/api/chain/apply").length, 1);
''')

    def test_remove_sends_no_profile_or_password_and_reads_back(self):
        self.run_js(r'''
await loadFixture(); await inputValue("chainConfirm", true, "change");
routes.set("/api/chain/apply", body => {
  assert.equal(body.operation, "remove"); assert.equal(body.node, "Node A");
  assert.equal(body.target, "router_a"); assert.equal(Object.hasOwn(body, "chain"), false);
  assert.equal(Object.hasOwn(body, "password"), false);
  routes.set("/api/chain/read", () => response(fixtureRead([])));
  return response({ok: true, message: "removed"});
});
await $("#removeChain").click();
assert.equal(chainProfiles.length, 0); assert.equal($("#testChain").disabled, true);
assert.equal($("#removeChain").disabled, true); assert.equal($("#chainNode").value, "Node A");
''')

    def test_test_request_uses_saved_node_not_draft_or_arbitrary_probe(self):
        self.run_js(r'''
await loadFixture(); await inputValue("chainServer", "unsaved.example.test");
routes.set("/api/chain/test", body => {
  assert.deepEqual(Object.keys(body).sort(), ["node", "nonce", "target"]);
  assert.equal(body.node, "Node A"); assert.equal(body.target, "router_a");
  return response({ok: true, node: "Node A", configuration: "PASS", runtime: "UNKNOWN", upstream: "REACHABLE", chain: "REACHABLE", verdict: "UNKNOWN", message: "no attestation"});
});
await $("#testChain").click();
assert.match($("#chainTestResult").textContent, /UNKNOWN/);
assert.equal($("#chainServer").value, "unsaved.example.test"); assert.equal(draftFlags().chain, true);
''')

    def test_preview_and_incomplete_evidence_never_claim_chain_success(self):
        self.run_js(r'''
const complete = {node: "Node A", configuration: "PASS", runtime: "PASS", upstream: "REACHABLE", chain: "REACHABLE", verdict: "PASS", message: "fixture"};
renderChainTest(complete, "Node A", "preview");
assert.match($("#chainTestResult .chain-verdict").textContent, /UNKNOWN/);
assert.doesNotMatch($("#chainTestResult").textContent, /链式固定探针验证通过/);
renderChainTest({...complete, runtime: "UNKNOWN"}, "Node A", "live");
assert.match($("#chainTestResult .chain-verdict").textContent, /UNKNOWN/);
renderChainTest({...complete, chain: "UNREACHABLE"}, "Node A", "live");
assert.match($("#chainTestResult .chain-verdict").textContent, /FAIL/);
renderChainTest(complete, "Node A", "live");
assert.match($("#chainTestResult .chain-verdict").textContent, /PASS/);
assert.throws(() => renderChainTest({...complete, runtime: "maybe"}, "Node A", "live"), /UNKNOWN/);
''')

    def test_selection_and_target_changes_protect_dirty_drafts(self):
        self.run_js(r'''
await loadFixture();
assert.equal(confirmations, 0);
await inputValue("chainNode", "Node B", "change"); assert.equal(confirmations, 0);
await inputValue("chainServer", "draft.example.test"); confirmation = false;
await inputValue("chainNode", "Node A", "change");
assert.equal($("#chainNode").value, "Node B"); assert.equal($("#chainServer").value, "draft.example.test");
await inputValue("chainTarget", "router_b", "change");
assert.equal($("#chainTarget").value, "router_a");
selectChainNode("Node B"); assert.equal($("#chainServer").value, "draft.example.test");
const leaving = await window.dispatch("beforeunload");
assert.equal(leaving.defaultPrevented, true); assert.equal(leaving.returnValue, "");
confirmation = true; await $("#resetChain").click();
assert.equal(draftFlags().chain, false); assert.equal($("#chainServer").value, "");
''')

    def test_yaml_source_is_readonly_and_dirty_reload_can_be_cancelled(self):
        self.run_js(r'''
routes.set("/api/read", body => response({ok: true, content: "proxies: []", sha256: "c".repeat(64)}));
await inputValue("fileName", "ProviderBase.yaml"); await $("#readConfig").click();
assert.equal(editor.readOnly, true); assert.equal($("#saveConfig").disabled, true);
await inputValue("fileName", mainConfigName); await $("#readConfig").click();
assert.equal(editor.readOnly, false); assert.equal($("#saveConfig").disabled, false);
await inputValue("yamlEditor", "draft"); confirmation = false;
const reads = requestLog.filter(r => r.path === "/api/read").length;
await $("#readConfig").click();
assert.equal(requestLog.filter(r => r.path === "/api/read").length, reads);
assert.equal(editor.value, "draft"); assert.equal(draftFlags().editor, true);
''')


if __name__ == "__main__":
    unittest.main()
