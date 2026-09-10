"use strict";
// This panel only sends the user's current result after an explicit click. It
// neither reads the router editor nor refreshes/replaces any unsaved draft.
(() => {
  const mount = $("#converterApplyMount");
  if (!mount) return;
  const targets = new Map([["router_a", "路由器 A（router_a）"], ["router_b", "路由器 B（router_b）"]]);
  const sources = new Map([["main", ["converterText", "主转换的当前编辑结果"]],
    ["surge2clash", ["converter-surge2clash-result", "Surge → Clash 工具的当前编辑结果"]]]);
  const modes = new Map([["nodes", "仅追加节点"], ["merge", "保守合并节点、策略组与规则"]]);
  const counts = new Map([["nodes_added", "新增节点"], ["groups_added", "新增策略组"],
    ["rules_added", "新增规则"], ["group_members_added", "追加到已有组的成员"], ["final_rules_ignored", "忽略的 MATCH / FINAL 规则"]]);
  const safeErrors = new Map([
    ["REQUEST", "请求参数不符合契约。"], ["CONTENT", "仅支持 1 MiB 以内、无锚点和重复字段的 Clash/Mihomo YAML。"],
    ["BASELINE", "当前主配置结构无法安全合并。"], ["CONFLICT", "存在同名但内容不同的节点或策略组，请在结果中重命名。"],
    ["REFERENCE", "结果中有未知、循环或不可用的引用，请先调整。"],
    ["STALE_BASELINE", "主配置已变化，旧基线已失效。"], ["STALE_PREVIEW", "输入与服务端预览不一致，旧计划已失效。"]
  ]);
  const maxBytes = 1024 * 1024;
  let proof = null, observed = null, revision = 0, availableGroups = [];

  function element(tag, id = "", text = "", className = "") {
    const node = document.createElement(tag);
    if (id) node.setAttribute("id", id);
    if (text) node.textContent = text;
    if (className) node.className = className;
    return node;
  }
  const panel = element("details", "converterApplyWorkspace");
  panel.append(element("summary", "", "将编辑结果保守合并到单个路由器 · 先预览，再确认应用"));
  panel.append(element("p", "", "只接受 Clash/Mihomo YAML，使用下方所选来源的当前文本（含手动编辑）。预览会发送这份文本并读取目标主配置，但不写入或重启；不会自动请求、复制凭据或同步到另一子网。", "help"));
  panel.append(element("p", "", "保留目标的现有节点和网络设置；nodes 不导入新策略组/规则，merge 仅追加兼容内容并忽略传入的 MATCH/FINAL。同名冲突由后端拒绝，不会直接覆盖主配置。", "help"));
  const fields = element("div", "", "", "converter-grid");
  function select(id, label, entries) {
    const field = element("div"), control = element("select", id);
    const caption = element("label", "", label); caption.setAttribute("for", id);
    for (const [value, text] of entries) {
      const option = element("option", "", text); option.value = value; control.append(option);
    }
    field.append(caption, control); fields.append(field);
    return control;
  }
  const source = select("converterApplySource", "结果来源（使用当前编辑文本）", [...sources].map(([value, spec]) => [value, spec[1]]));
  const target = select("converterApplyTarget", "应用目标（仅此子网）", targets);
  const applyMode = select("converterApplyMode", "合并模式", modes);
  const group = select("converterApplyGroup", "可选：追加节点到目标已有策略组", [["", "不追加到已有组"]]);
  group.setAttribute("aria-describedby", "converterApplyGroupHint");
  panel.append(fields, element("p", "converterApplyGroupHint", "先不选组进行预览，以读取可用的已有组；选组后需再次点击预览。切换目标会清空组选择，不会自动读取。", "help"));
  const actions = element("div", "", "", "converter-actions");
  const previewButton = element("button", "previewConverterApply", "预览变更（不写入）", "ghost");
  const applyButton = element("button", "applyConverterResult", "确认应用到目标…", "primary");
  previewButton.type = "button"; applyButton.type = "button";
  actions.append(previewButton, applyButton); panel.append(actions);
  const state = element("p", "converterApplyState", "尚未预览。", "validation idle");
  state.setAttribute("role", "status"); state.setAttribute("aria-live", "polite");
  const summary = element("dl", "converterApplySummary", "", "converter-apply-summary");
  panel.append(state, summary); mount.append(panel);

  function setState(text, kind = "idle") {
    state.textContent = text; state.setAttribute("data-state", kind);
  }
  function clearProof() { proof = null; summary.replaceChildren(); }
  function setGroups(names, selected = "") {
    availableGroups = names;
    const options = [["", "不追加到已有组"], ...names.map(name => [name, name])].map(([value, text]) => {
      const option = element("option", "", text); option.value = value; return option;
    });
    group.replaceChildren(...options); group.value = selected;
  }
  function snapshot() {
    return {source: source.value, target: target.value, mode: applyMode.value, group: group.value,
      content: sources.has(source.value) ? $("#" + sources.get(source.value)[0]).value : "", live: mode === "live"};
  }
  function same(a, b) {
    return a && b && ["source", "target", "mode", "group", "content", "live"].every(key => a[key] === b[key]);
  }
  // Observe exact text as well as a monotonic revision: changing away and back
  // cannot resurrect a proof. The hook below also catches .value replacements.
  function observe() {
    let current = snapshot();
    if (observed && current.target !== observed.target) {
      setGroups([]); current = snapshot();
    }
    if (observed && !same(observed, current)) {
      const wasReady = Boolean(proof);
      revision++; clearProof();
      setState(wasReady ? "预览已失效：来源、目标、模式、组或输入已变化，请重新预览。" : "当前输入尚未预览；请先预览再应用。", wasReady ? "stale" : "idle");
    }
    observed = current;
    return current;
  }
  const payloadFor = s => ({target: s.target, content: s.content, mode: s.mode, group: s.group});
  function inputProblem(s) {
    if (!s.live) return mode === "preview"
      ? "当前为预览模式，未连接真实路由器，不能读取或应用目标配置。"
      : "连接状态 UNKNOWN，不能读取或应用目标配置；请刷新状态后重新预览。";
    if (!sources.has(s.source) || !targets.has(s.target) || !modes.has(s.mode)) return "来源、目标或模式无效，请重新选择。";
    try { converterCheckText(s.content, maxBytes, false); }
    catch { return "所选结果为空、不是有效 UTF-8 文本或超过 1 MiB；请先生成或修正 Clash/Mihomo YAML。"; }
    try { converterCheckText(s.group, 512, true, false); }
    catch { return "所选已有组名称无效，请重新预览。"; }
    if (s.group && !availableGroups.includes(s.group)) return "所选组不属于此次目标的已有组列表，请重新预览。";
    try { converterRequestBudget({...payloadFor(s), expected_sha256: "0".repeat(64), preview_sha256: "0".repeat(64)}); }
    catch { return "JSON 请求体接近 2 MiB 上限（转义字符也占空间），请减少结果文本。"; }
    return "";
  }
  let controlSnapshot = null, controlMode = "", controlGroups = null, controlProblem = "";
  function update() {
    const current = observe();
    // Button-state updates also run for unrelated form edits and lock changes.
    // Avoid re-encoding the same large result; click handlers still perform a
    // fresh inputProblem check before every preview/apply request.
    if (!same(controlSnapshot, current) || controlMode !== mode || controlGroups !== availableGroups) {
      controlProblem = inputProblem(current);
      controlSnapshot = current; controlMode = mode; controlGroups = availableGroups;
    }
    const problem = controlProblem;
    for (const control of [source, target, applyMode]) control.disabled = operationBusy;
    group.disabled = operationBusy || !availableGroups.length;
    previewButton.disabled = operationBusy || Boolean(problem);
    applyButton.disabled = operationBusy || Boolean(problem) || !proof;
    if (problem && !operationBusy && state.getAttribute("data-state") === "idle") setState(problem);
  }

  // WebCrypto is absent on some LAN HTTP origins. This bounded SHA-256 fallback
  // binds local input only; server-side SHA checks and nonce authentication remain
  // authoritative. It is run on button clicks, never on each editor keystroke.
  async function fingerprint(s) {
    const bytes = new TextEncoder().encode(JSON.stringify([s.source, s.target, s.mode, s.group, s.content]));
    if (globalThis.crypto?.subtle) {
      const hash = await globalThis.crypto.subtle.digest("SHA-256", bytes);
      return [...new Uint8Array(hash)].map(n => n.toString(16).padStart(2, "0")).join("");
    }
    const k = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
    const h = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
    const data = new Uint8Array(Math.ceil((bytes.length + 9) / 64) * 64), w = new Uint32Array(64);
    data.set(bytes); data[bytes.length] = 0x80;
    const view = new DataView(data.buffer);
    view.setUint32(data.length - 8, Math.floor(bytes.length / 0x20000000));
    view.setUint32(data.length - 4, (bytes.length * 8) >>> 0);
    const rotr = (value, n) => (value >>> n) | (value << (32 - n));
    for (let offset = 0; offset < data.length; offset += 64) {
      for (let i = 0; i < 16; i++) w[i] = view.getUint32(offset + i * 4);
      for (let i = 16; i < 64; i++) {
        const a = w[i - 15], b = w[i - 2];
        w[i] = w[i - 16] + (rotr(a, 7) ^ rotr(a, 18) ^ (a >>> 3)) + w[i - 7] + (rotr(b, 17) ^ rotr(b, 19) ^ (b >>> 10));
      }
      let [a,b,c,d,e,f,g,j] = h;
      for (let i = 0; i < 64; i++) {
        const t1 = (j + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + k[i] + w[i]) >>> 0;
        const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
        j = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      [a,b,c,d,e,f,g,j].forEach((value, i) => { h[i] += value; });
    }
    return [...h].map(n => n.toString(16).padStart(8, "0")).join("");
  }
  function stillCurrent(s, version) { return same(observe(), s) && revision === version; }
  async function authorize(s, version) {
    // The preflight is under the same global lock, before nonceRequest; it avoids
    // its initial status refresh and distinguishes "not sent" from a lost reply.
    if (!nonce && !await bootstrap(true, false)) {
      observe();
      clearProof(); setState("无法取得操作凭证：尚未发送本次请求。请检查登录/管理服务后重新预览。", "error"); return false;
    }
    if (!stillCurrent(s, version)) {
      clearProof(); setState("输入或连接状态已变化，本次请求未发送；请重新预览。", "stale"); return false;
    }
    return true;
  }
  const record = value => value && typeof value === "object" && !Array.isArray(value);
  function checkedPreview(data, s) {
    const stats = data?.summary;
    if (!record(data) || data.ok !== true || data.target !== s.target || !digestValid(data.expected_sha256)
        || !digestValid(data.sha256) || !record(stats) || stats.mode !== s.mode
        || stats.existing_nodes_preserved !== true || stats.network_settings_preserved !== true
        || stats.router_changed !== false || typeof stats.no_change !== "boolean"
        || !Array.isArray(data.groups) || data.groups.length > 10000) throw new Error("preview shape");
    const cleanCounts = {};
    for (const key of counts.keys()) {
      const value = stats[key];
      if (!Number.isSafeInteger(value) || value < 0 || value > 10000) throw new Error("preview count");
      cleanCounts[key] = value;
    }
    const unchanged = ["nodes_added", "groups_added", "rules_added", "group_members_added"].every(key => cleanCounts[key] === 0);
    if (stats.no_change !== unchanged || (data.sha256 === data.expected_sha256) !== unchanged
        || (s.mode === "nodes" && ["groups_added", "rules_added", "final_rules_ignored"].some(key => cleanCounts[key] !== 0))
        || (!s.group && cleanCounts.group_members_added !== 0)) throw new Error("preview invariants");
    for (const name of data.groups) {
      converterCheckText(name, 512, true, false);
      if (!name.length) throw new Error("preview group name");
    }
    if (new Set(data.groups).size !== data.groups.length || (s.group && !data.groups.includes(s.group))) throw new Error("preview groups");
    // Never retain or read data.content, raw messages, or the response object.
    return {baselineSha: data.expected_sha256, previewSha: data.sha256, counts: cleanCounts,
      noChange: unchanged, groups: data.groups.slice()};
  }
  function addSummary(label, value) {
    const row = element("div"); row.append(element("dt", "", label), element("dd", "", String(value))); summary.append(row);
  }
  function renderPreview(saved) {
    summary.replaceChildren();
    addSummary("目标", targets.get(saved.snapshot.target));
    addSummary("来源", sources.get(saved.snapshot.source)[1]);
    addSummary("模式", modes.get(saved.snapshot.mode));
    for (const [key, label] of counts) addSummary(label, saved.counts[key]);
    addSummary("基线 SHA-256", saved.baselineSha); addSummary("预览计划 SHA-256", saved.previewSha);
    addSummary("本页输入绑定 SHA-256（来源 / 目标 / 模式 / 组 / 文本）", saved.inputSha);
  }
  function failure(error, applying, s) {
    clearProof();
    const data = error?.data, known = record(data) && safeErrors.has(data.code);
    if (!applying || (known && data.router_changed === false)) {
      const reason = known ? data.code + "：" + safeErrors.get(data.code) : "认证、操作凭证或管理服务响应不可用。";
      setState((applying ? targets.get(s.target) + " 应用被拒绝。" : "预览失败。") + reason + "未执行写入；请重新预览。",
        known && data.code.startsWith("STALE_") ? "stale" : "error");
    } else {
      setState(targets.get(s.target) + " 应用结果 UNKNOWN：可能已写入或重启，不能认定已生效。不要重复应用；先核查目标状态，再重新预览。", "unknown");
    }
  }
  function showApplied(data, saved) {
    const s = saved.snapshot, label = targets.get(s.target);
    if (!record(data) || data.ok !== true || (data.target !== undefined && data.target !== s.target)
        || !digestValid(data.sha256)) throw new Error("apply evidence");
    if (data.no_change === true) {
      if (!saved.noChange || data.target !== s.target || data.sha256 !== saved.baselineSha
          || (data.service_restarted !== undefined && data.service_restarted !== false)
          || (data.runtime_verified !== undefined && data.runtime_verified !== false)) throw new Error("no-change evidence");
      setState(label + " 未变更：未执行写入或重启，本次未验证当前运行配置。旧预览已失效。", "unchanged");
    } else {
      if ((data.no_change !== undefined && data.no_change !== false) || !digestValid(data.state_sha256)
          || typeof data.service_restarted !== "boolean" || typeof data.runtime_verified !== "boolean"
          || (!data.service_restarted && data.runtime_verified)) throw new Error("runtime evidence");
      if (data.service_restarted && data.runtime_verified) {
        setState(label + "：后端报告 OpenClash 已受控重启且运行态验证通过。旧预览已失效；本页草稿未改动。", "success");
      } else if (data.service_restarted) {
        setState(label + "：后端报告已重启，但 runtime_verified=false，运行态 UNKNOWN，不能认定已生效。请核查目标状态后重新预览。", "unknown");
      } else {
        setState(label + "：已收到处理回执，但未重启且 runtime_verified=false；本次未验证当前运行配置，不能认定已生效。旧预览已失效。", "unverified");
      }
      addSummary("处理后定制状态 SHA-256", data.state_sha256);
    }
    addSummary("本次操作目标", label); addSummary("处理后主配置 SHA-256", data.sha256);
  }

  previewButton.addEventListener("click", () => runOperation("正在读取单个目标并预览合并（不写入、不重启）", async () => {
    const s = observe(), version = revision, problem = inputProblem(s);
    clearProof();
    if (problem) { setState(problem, "error"); return; }
    setState("正在校验当前输入并读取目标；尚未写入或重启。", "loading");
    try {
      const inputSha = await fingerprint(s);
      if (!await authorize(s, version)) return;
      const data = await nonceRequest("/api/converter/router-preview", payloadFor(s));
      if (!stillCurrent(s, version)) {
        setState("等待期间输入或连接状态已变化，返回的预览已丢弃；请重新预览。", "stale"); return;
      }
      let clean;
      try { clean = checkedPreview(data, s); }
      catch { setState("预览响应缺少可信的计数、保留标记或 SHA，已丢弃；未执行写入。请重新预览。", "error"); return; }
      setGroups(clean.groups, s.group);
      proof = {snapshot: s, revision: version, inputSha, baselineSha: clean.baselineSha,
        previewSha: clean.previewSha, counts: clean.counts, noChange: clean.noChange};
      renderPreview(proof);
      setState(clean.noChange ? "预览显示无新增变化；尚未应用，尚未验证运行态。可确认检查未变更，或调整输入后重新预览。"
        : "预览就绪：仅展示变更计数与 SHA，尚未写入或重启。确认应用前请核对目标；任何输入变化都需重新预览。", "ready");
    } catch (error) { failure(error, false, s); }
  }));
  applyButton.addEventListener("click", () => runOperation("正在确认并应用单个目标的合并，变化时将重启 OpenClash", async () => {
    const s = observe(), saved = proof, problem = inputProblem(s);
    if (problem || !saved) { clearProof(); setState(problem || "缺少有效预览，请先重新预览。", "stale"); return; }
    let sent = false;
    try {
      const inputSha = await fingerprint(s);
      if (!stillCurrent(saved.snapshot, saved.revision) || proof !== saved || inputSha !== saved.inputSha) {
        clearProof(); setState("输入与预览绑定不一致，请重新预览；未发送应用。", "stale"); return;
      }
      const confirmed = window.confirm("将向 " + targets.get(s.target) + " 应用当前预览（" + modes.get(s.mode) + "）。\n"
        + "若配置变化，将重启此目标的 OpenClash，可能短暂中断该子网网络/代理连接。另一子网不会同步更改。\n"
        + "若未变更则不会重启，也不会重新验证运行配置。是否继续？");
      if (!stillCurrent(saved.snapshot, saved.revision) || proof !== saved) {
        clearProof(); setState("确认期间输入已变化，未发送应用；请重新预览。", "stale"); return;
      }
      if (!confirmed) { setState("已取消应用，未发送请求；当前预览仍有效。", "ready"); return; }
      if (!await authorize(s, saved.revision)) return;
      // Consume local proof before POST, including on lost/failed responses. A new
      // preview is mandatory for every later attempt; never automatically retry.
      clearProof(); setState("已确认，正在请求目标事务；请勿重复操作或关闭页面。", "loading");
      sent = true;
      const data = await nonceRequest("/api/converter/router-apply", {...payloadFor(s),
        expected_sha256: saved.baselineSha, preview_sha256: saved.previewSha});
      observe(); showApplied(data, saved);
    } catch (error) {
      observe();
      if (sent) failure(error, true, s);
      else { clearProof(); setState("应用前校验未完成，本次应用尚未发送；请检查页面或连接后重新预览。", "error"); }
    } finally {
      if (sent) {
        // A failed/lost reply can still have changed the target. Expire bindings,
        // not drafts, and do not start additional reads after an apply.
        invalidateViews([s.target], "converter");
        unavailableStatus("已尝试应用转换结果，旧状态已失效；请手动刷新状态确认，草稿不会自动重载。");
      }
    }
  }));

  for (const control of [source, target, applyMode, group, ...[...sources.values()].map(spec => $("#" + spec[0]))]) {
    control.addEventListener("input", update); control.addEventListener("change", update);
  }
  // converter.js invokes this after edits, imports, clears, restores, conversions
  // and tools; app.js also invokes it after the full nonce/operation lock ends.
  const originalInvalidate = invalidateViews;
  invalidateViews = function (targets, source = "") {
    originalInvalidate(targets, source);
    if (source !== "converter" && targets.includes(target.value)) {
      revision++; clearProof();
      setState("目标配置可能已变化，旧预览已失效；请重新预览。当前编辑文本仍保留。", "stale");
      update();
    }
  };
  const originalUpdate = updateConverterControls;
  updateConverterControls = function (...args) { const result = originalUpdate.apply(this, args); update(); return result; };
  lockNewControls(); update();
})();
