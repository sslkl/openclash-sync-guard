"use strict";
const $ = (query) => document.querySelector(query);
const $$ = (query) => [...document.querySelectorAll(query)];
let nonce = "", mode = "preview";
let currentHash = "", currentTarget = "", currentName = "";
let validationTimer = null, customTimer = null;
let yamlRevision = 0, customRevision = 0, statusRevision = 0;
let yamlController = null, customController = null;
let yamlPending = null, customPending = null;
let yamlIsValid = false, customIsValid = false;
let editorBaseline = "", customBaseline = "";
let groups = ["DIRECT"], customStateHash = {}, customConfigHash = {};
let supplementalRules = [], supplementalFilters = [], savedRules = [], savedFilters = [];
let reconciliationRules = [], reconciliationFilters = [], lastNodeHealth = {};
let unownedRulesByMatcher = new Map(), managedRuleIdentities = new Set();
let unownedFiltersByKey = new Map(), managedFilters = new Set();
let operationBusy = false, operationControls = null, operationFocus = null;
const mainConfigName = "ProviderBase-ProviderSource.yaml";
const digestValid = (value) => typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
const notice = (text, error = false) => {
  const box = $("#notice");
  box.textContent = text;
  box.className = "notice" + (error ? " error" : "");
};
const clearNotice = () => {
  $("#notice").textContent = "";
  $("#notice").className = "notice hidden";
};

async function api(path, body, signal) {
  const options = {headers: {"Content-Type": "application/json"}, cache: "no-store"};
  if (body !== undefined) {
    options.method = "POST";
    options.body = JSON.stringify(body);
  }
  if (signal) options.signal = signal;
  const response = await fetch(path, options);
  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error("管理服务返回了无法识别的响应，请重新读取状态");
  }
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("管理服务响应格式无效");
  }
  if (!response.ok) {
    const error = new Error(data.message || "操作失败");
    error.details = data.errors || [];
    error.data = data;
    throw error;
  }
  return data;
}

async function bootstrap(preserveNotice = false, refreshTargets = true) {
  try {
    const data = await api("/api/bootstrap");
    if (data.ok !== true || typeof data.nonce !== "string" || !data.nonce) {
      throw new Error("管理服务未提供有效操作凭证");
    }
    nonce = data.nonce;
    mode = data.mode === "live" ? "live" : "preview";
    $("#modeText").textContent = mode === "live"
      ? "实时模式 · 已登录受控管理台" : "预览模式 · 尚未连接路由器";
    $("#chainPreview").classList.toggle("hidden", mode === "live");
    $("#chainPreviewHeading").textContent = "预览模式";
    $("#chainPreviewText").textContent = "本面板仅用于配置演示；没有连接真实路由器，测试不会标记为实时链路成功。";
    if (refreshTargets) await refresh(preserveNotice);
    return true;
  } catch (e) {
    nonce = "";
    mode = "unknown";
    unavailableStatus();
    invalidateViews(["router_a", "router_b"]);
    $("#chainPreview").classList.remove("hidden");
    $("#chainPreviewHeading").textContent = "连接状态 UNKNOWN";
    $("#chainPreviewText").textContent = "未能确认管理服务，旧结果不能代表当前链路；请刷新状态。";
    $("#modeText").textContent = "管理服务连接失败 · 请刷新状态";
    if(!preserveNotice)notice(e.message,true);
    return false;
  }
}

// One lock covers the complete operation, including validation, nonce renewal and read-back.
// No mutation is automatically retried: a lost response may already have committed remotely.
function lockNewControls() {
  if (!operationControls) return;
  $$("main button, main input, main select, main textarea").forEach((button) => {
    // Navigation only switches local panels; keep it available while mutations stay locked.
    if (button.classList.contains("nav-item")) return;
    if (!operationControls.has(button)) operationControls.set(button, button.disabled);
    button.disabled=true;
  });
}

async function runOperation(label, work) {
  if (operationBusy) {
    notice("已有操作正在进行，请等待完成后再试");
    return null;
  }
  operationBusy = true;
  operationControls = new Map();
  operationFocus = null;
  lockNewControls();
  $(".panels").setAttribute("aria-busy", "true");
  $("#operationStatus").className = "operation-status";
  $("#operationStatus").textContent = label + "；请等待完成，不要关闭页面。";
  try {
    return await work();
  } catch (e) {
    notice(e.message || "操作失败，请重新读取当前状态", true);
    return null;
  } finally {
    operationControls.forEach((disabled, control) => { control.disabled = disabled; });
    operationControls = null;
    operationBusy = false;
    $(".panels").setAttribute("aria-busy", "false");
    $("#operationStatus").className = "operation-status hidden";
    $("#operationStatus").textContent = "";
    updateEditorSaveState();
    updateCustomSaveState();
    updateChainControls();
    updateRollbackState();
    if (typeof updateConverterControls === "function") updateConverterControls();
    updateDraftNotice();
    const restoreFocus = operationFocus;
    operationFocus = null;
    restoreFocus?.();
  }
}

async function nonceRequest(path, extra = {}) {
  if (!operationBusy) throw new Error("操作未取得页面锁，请重试");
  if (!nonce && !await bootstrap(true)) {
    throw new Error("无法取得操作凭证；尚未发送操作，请刷新状态后重试");
  }
  const token = nonce;
  nonce = "";
  try {
    const data = await api(path, {...extra, nonce: token});
    if (data.ok !== true) {
      const error = new Error(data.message || "操作未完整完成，请重新读取");
      error.data = data;
      throw error;
    }
    return data;
  } finally {
    // Even rejected requests can consume the one-use nonce.
    await bootstrap(true,false);
  }
}

// A read can succeed just before its nonce renewal loses authentication. Keep
// drafts, but never rebuild current bindings or test proof after that failure.
function requireReadConnection() {
  if (mode === "unknown") {
    throw new Error("读取后管理连接未能确认（UNKNOWN），结果已丢弃；请刷新状态后重新读取");
  }
}

function draftFlags() {
  return {
    editor: $("#yamlEditor").value !== editorBaseline,
    custom: customBaseline !== "" && JSON.stringify(collectCustom()) !== customBaseline,
    chain: chainDraftSignature() !== chainBaseline,
    converter: typeof converterDirty === "function" && converterDirty()
  };
}

function updateDraftNotice() {
  const flags = draftFlags();
  const labels = Object.entries({editor: "YAML 配置", custom: "域名/IP 与 Fake-IP", chain: "链式代理", converter: "订阅转换"})
    .filter(([key]) => flags[key]).map(([, label]) => label);
  $("#draftNotice").className = "draft-notice" + (labels.length ? "" : " hidden");
  $("#draftNotice").textContent = labels.length
    ? "未保存草稿：" + labels.join("、") + "。切换面板会保留；重新读取或离开页面可能丢失。" : "";
}

function confirmDiscard(section) {
  return !draftFlags()[section] || window.confirm("此处有未保存草稿，继续会放弃它。是否继续？");
}

window.addEventListener("beforeunload", (event) => {
  if (operationBusy || Object.values(draftFlags()).some(Boolean)) {
    event.preventDefault();
    event.returnValue = "";
  }
});

function healthText(target){if(!Object.prototype.hasOwnProperty.call(lastNodeHealth,target))return "";const health=lastNodeHealth[target],m=health&&health.maying,n=health&&health.nexitally,valid=item=>item&&Number.isInteger(item.passed)&&Number.isInteger(item.total)&&item.passed>=0&&item.total>=0&&item.passed<=item.total;if(!valid(m)||!valid(n))return '<span class="node-health">节点检查：UNKNOWN</span>';return `<span class="node-health">Maying ${m.passed}/${m.total} · Nexitally ${n.passed}/${n.total}</span>`}
function unavailableStatus(message = "状态读取失败或响应无效，请刷新状态；此前的 ACTIVE 与节点检查结果已失效。") {
  statusRevision++;
  lastNodeHealth = {};
  $("#statusFreshness").textContent = "状态未确认 · 请重新读取";
  $("#targetGrid").innerHTML = `<article class="target-card" role="status"><div class="target-title"><span class="router-icon">?</span><div><strong>当前状态未确认</strong><small>${escapeHtml(message)}</small></div></div><span class="badge">UNKNOWN</span></article>`;
}

async function refresh(preserveNotice = false) {
  const revision = ++statusRevision;
  $("#statusFreshness").textContent = "正在读取当前状态…";
  try {
    const data = await api("/api/status");
    if (revision !== statusRevision) return false;
    if (data.ok !== true || !Array.isArray(data.targets) || data.targets.length > 16 ||
        data.targets.some(t => !t || ["id", "name", "address", "active", "state"].some(k => typeof t[k] !== "string")) ||
        new Set(data.targets.map(t => t.id)).size !== data.targets.length) {
      throw new Error("子网状态响应格式无效，请重新读取状态");
    }
    if (!data.targets.length) {
      unavailableStatus();
      return false;
    }
    $("#targetGrid").innerHTML = data.targets.map(t => `<article class="target-card"><div class="target-title"><span class="router-icon">网</span><div><strong>${escapeHtml(t.name)}</strong><small>${escapeHtml(t.address)} · ACTIVE（当前启用）：${escapeHtml(t.active)}</small>${healthText(t.id)}</div></div><span class="badge">${escapeHtml(t.state)}</span></article>`).join("");
    $("#statusFreshness").textContent = "本页读取于 " + new Date().toLocaleTimeString("zh-CN", {hour12: false});
    return true;
  } catch (e) {
    if (revision !== statusRevision) return false;
    unavailableStatus();
    if (!preserveNotice) notice(e.message, true);
    return false;
  }
}
// Escape text without allocating thousands of detached elements in large lists.
const HTML_ESCAPES = {"&": "&amp;", "<": "&lt;", ">": "&gt;"};
function escapeHtml(value) { return String(value).replace(/[&<>]/g, character => HTML_ESCAPES[character]); }
function escapeAttr(value) { return escapeHtml(value).replaceAll('"', "&quot;"); }
function policyLabel(name){return({DIRECT:"DIRECT（直连）",Proxies:"Proxies（代理总组）",AI:"AI（人工智能）","🎯Direct":"🎯Direct（直连组）","✈️Final":"✈️Final（最终匹配组）"})[name]||name}
function switchPanel(id) {
  const panels = $$(".panel");
  if (!panels.some(panel => panel.id === id)) return;
  $$(".nav-item").forEach((button) => {
    const active = button.dataset.panel === id;
    button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  });
  panels.forEach((panel) => panel.classList.toggle("active", panel.id === id));
  updateDraftNotice();
}
$$(".nav-item").forEach((button) => {
  button.addEventListener("click", () => switchPanel(button.dataset.panel));
  // Native focus may leave only a sliver visible in the narrow horizontal sidebar.
  button.addEventListener("focus", () => button.scrollIntoView({block: "nearest", inline: "nearest"}));
});
$("#refreshStatus").addEventListener("click", () => runOperation("正在刷新状态", async () => {
  clearNotice();
  lastNodeHealth = {};
  await bootstrap();
}));

// A write to one view also makes that target's hashes in the other views stale.
function invalidateViews(targets, source = "") {
  if (source !== "editor" && targets.includes(currentTarget)) clearEditorBinding();
  if (source !== "custom") invalidateCustomBinding();
  if (source !== "chain" && targets.includes(chainReadTarget)) invalidateChainBinding();
  $("#routeResult").replaceChildren();
}

async function mutate(path, extra = {}, source = "") {
  try {
    const data = await nonceRequest(path, extra);
    notice(data.message || "操作完成");
    return data;
  } catch (e) {
    notice(e.message, true);
    return null;
  } finally {
    invalidateViews(extra.target ? [extra.target] : ["router_a", "router_b"], source);
    await refresh(true);
  }
}
async function mutateTarget(path, target, extra = {}, source = "") {
  return mutate(path, {target, ...extra}, source);
}
function captureNodeHealth(data,reset=false){if(reset)for(const target of ["router_a","router_b"])lastNodeHealth[target]=null;for(const [target,result] of Object.entries((data&&data.results)||{})){if(result&&Object.prototype.hasOwnProperty.call(result,"node_health"))lastNodeHealth[target]=result.node_health||null}}
$$("[data-action]").forEach((button) => button.addEventListener("click", () =>
  runOperation("正在按顺序处理两个子网，主配置变化时可能需要 1–3 分钟", async () => {
    const paths = {"stage-main": "/api/stage-main", "update-maying": "/api/update-maying", "update-nexitally": "/api/update-nexitally"};
    const isMain = button.dataset.action === "stage-main";
    try {
      const data = await nonceRequest(paths[button.dataset.action]);
      captureNodeHealth(data,isMain);
      notice(data.message || "两个子网操作完成");
    } catch (e) {
      captureNodeHealth(e.data, isMain);
      notice(e.message, true);
    } finally {
      invalidateViews(["router_a", "router_b"]);
      await refresh(true);
    }
  })
));

// YAML editor: validation responses must match both the revision and the file binding.
const editor = $("#yamlEditor");
function editorBindingValid(){return Boolean(currentHash)&&currentTarget===$("#editorTarget").value&&currentName===$("#fileName").value&&currentName===mainConfigName}
function updateEditorSaveState() {
  $("#saveConfig").disabled = operationBusy || !yamlIsValid || !editorBindingValid();
}
function clearEditorBinding() {
  currentHash = "";
  currentTarget = "";
  currentName = "";
  yamlIsValid = false;
  yamlRevision++;
  yamlController?.abort();
  clearTimeout(validationTimer);
  $("#fileHash").textContent = "SHA-256：请重新读取";
  $("#validationState").className = "validation idle";
  $("#validationState").textContent = "目标、文件名或配置已变化，请重新读取当前文件";
  updateEditorSaveState();
  updateDraftNotice();
}
// Cache logical line starts, not split substrings, for repeated cursor moves.
// Recheck the value so programmatic reads/replacements cannot reuse stale offsets.
let editorIndexedText = null, editorLineStarts = [0], editorGutterCount = 0;
function indexEditorLines() {
  const text = editor.value;
  if (text !== editorIndexedText) {
    editorLineStarts = [0];
    for (let at = text.indexOf("\n"); at !== -1; at = text.indexOf("\n", at + 1)) editorLineStarts.push(at + 1);
    editorIndexedText = text;
  }
  return editorLineStarts;
}
function editorMeta() {
  const starts = indexEditorLines(), offset = Math.min(editor.selectionStart, editorIndexedText.length);
  let low = 0, high = starts.length;
  while (low + 1 < high) {
    const middle = Math.floor((low + high) / 2);
    if (starts[middle] <= offset) low = middle; else high = middle;
  }
  const label = $("#cursorPosition"), text = `第 ${low + 1} 行，第 ${offset - starts[low] + 1} 列`;
  if (label.textContent !== text) label.textContent = text;
}
function editorLines() {
  const count = indexEditorLines().length;
  if (count !== editorGutterCount) {
    $("#lineNumbers").textContent = Array.from({length: count}, (_, i) => i + 1).join("\n");
    editorGutterCount = count;
  }
  editorMeta();
}
function mark(result, focus = false) {
  const el = $("#validationState");
  yamlIsValid = result.ok === true;
  el.className = "validation " + (yamlIsValid ? "good" : "bad");
  el.textContent = yamlIsValid
    ? `检查通过 · ${result.summary.proxies} 节点 / ${result.summary.groups} 组 / ${result.summary.rules} 规则`
    : `${result.message}${result.line ? `（第 ${result.line} 行，第 ${result.column} 列）` : ""}`;
  updateEditorSaveState();
  if (focus && !yamlIsValid && result.line) {
    const lines = editor.value.split("\n");
    const pos = lines.slice(0, result.line - 1).reduce((n, line) => n + line.length + 1, 0) + Math.max(0, result.column - 1);
    // Disabled controls cannot receive focus; restore it only after unlocking
    // and only if the user has not navigated to another local panel.
    if (operationBusy && editor.disabled) {
      operationFocus = () => { if ($("#editor").classList.contains("active")) editor.focus(); };
    } else editor.focus();
    editor.setSelectionRange(pos, pos);
    editorMeta();
  }
}
async function validate(focus = false) {
  clearTimeout(validationTimer);
  const content = editor.value, target = $("#editorTarget").value, name = $("#fileName").value;
  // Reuse only an in-flight read for this exact revision/binding. Completed or
  // invalidated checks are never cached, and explicit focus requests are kept.
  if (yamlPending && yamlPending.revision === yamlRevision && !yamlPending.controller.signal.aborted
      && yamlPending.content === content && yamlPending.target === target && yamlPending.name === name) {
    yamlPending.focus ||= focus;
    return yamlPending.promise;
  }
  const revision = ++yamlRevision;
  yamlController?.abort();
  const controller = yamlController = new AbortController();
  const request = yamlPending = {revision, content, target, name, controller, focus};
  const fresh = () => revision === yamlRevision && content === editor.value
    && target === $("#editorTarget").value && name === $("#fileName").value;
  yamlIsValid = false;
  updateEditorSaveState();
  $("#validateYaml").setAttribute("aria-busy", "true");
  $("#validationState").className = "validation idle";
  $("#validationState").textContent = "正在检查…";
  request.promise = (async () => {
    try {
      const result = await api("/api/validate", {content}, controller.signal);
      if (!fresh()) return false;
      mark(result, request.focus);
      return result.ok === true;
    } catch (e) {
      if (!fresh() || e.name === "AbortError") return false;
      yamlIsValid = false;
      updateEditorSaveState();
      $("#validationState").className = "validation bad";
      $("#validationState").textContent = e.message;
      return false;
    } finally {
      if (yamlPending === request) {
        yamlPending = null;
        $("#validateYaml").setAttribute("aria-busy", "false");
      }
    }
  })();
  return request.promise;
}
editor.addEventListener("input", () => {
  editorLines();
  yamlRevision++;
  yamlController?.abort();
  yamlIsValid = false;
  updateEditorSaveState();
  updateDraftNotice();
  $("#validationState").className = "validation idle";
  $("#validationState").textContent = "正在检查…";
  clearTimeout(validationTimer);
  validationTimer = setTimeout(() => validate(), 450);
});
editor.addEventListener("click", editorMeta);
editor.addEventListener("keyup", editorMeta);
editor.addEventListener("select", editorMeta);
editor.addEventListener("scroll", () => { $("#lineNumbers").scrollTop = editor.scrollTop; });
$("#validateYaml").addEventListener("click", () => validate(true));
$("#editorTarget").addEventListener("change", clearEditorBinding);
$("#fileName").addEventListener("input", clearEditorBinding);
$("#readConfig").addEventListener("click", () => runOperation("正在读取受管配置", async () => {
  if (!confirmDiscard("editor")) return;
  const target = $("#editorTarget").value, name = $("#fileName").value;
  try {
    const data = await nonceRequest("/api/read", {target, name});
    requireReadConnection();
    if (!digestValid(data.sha256) || typeof data.content !== "string") throw new Error("配置内容或摘要格式无效");
    editor.value = data.content;
    editor.readOnly = name !== mainConfigName;
    editorBaseline = data.content;
    currentHash = data.sha256;
    currentTarget = target;
    currentName = name;
    $("#fileHash").textContent = "SHA-256：" + currentHash.slice(0, 16) + "…";
    editorLines();
    await validate();
    notice(name === mainConfigName ? (data.message || "配置读取成功") : "机场源文件已按只读模式加载；请使用对应的受控更新操作");
  } catch (e) {
    clearEditorBinding();
    notice(e.message, true);
  }
}));
$("#saveConfig").addEventListener("click", () => runOperation("正在校验并保存主配置", async () => {
  if (!editorBindingValid()) throw new Error("目标或文件名已变化，请重新读取当前文件");
  if (!await validate(true)) return;
  const content = editor.value;
  const saved = await mutateTarget("/api/write", currentTarget, {
    name: currentName, content, expected_sha256: currentHash
  }, "editor");
  if (saved && digestValid(saved.sha256)) {
    currentHash = saved.sha256;
    editorBaseline = content;
    $("#fileHash").textContent = "SHA-256：" + currentHash.slice(0, 16) + "…";
  } else {
    clearEditorBinding();
  }
}));
function updateRollbackState() {
  $("#rollbackButton").disabled = operationBusy || $("#rollbackPhrase").value !== "确认回滚主配置";
}
$("#rollbackPhrase").addEventListener("input", updateRollbackState);
$("#rollbackButton").addEventListener("click", () => runOperation("正在回滚主配置", async () => {
  if ($("#rollbackPhrase").value !== "确认回滚主配置") return;
  await mutateTarget("/api/rollback", $("#rollbackTarget").value, {confirmation: $("#rollbackPhrase").value});
  $("#rollbackPhrase").value = "";
}));

function policyOptions(selected){return groups.map(name=>`<option value="${escapeAttr(name)}"${name===selected?" selected":""}>${escapeHtml(policyLabel(name))}</option>`).join("")}
function cloneRule(rule){return{type:rule.type,value:rule.value,policy:rule.policy}}
// Keep the original relative order while multiple saved entries are in drafts.
// The snapshot belongs to the current array; a fresh read creates a new array.
const managedEditOrders = new WeakMap();
const managedDraftEdits = new WeakMap();
function takeManagedEdit(items, index) {
  if (!managedEditOrders.has(items)) {
    const order = new Map();
    items.forEach((value, rank) => { if (!order.has(value)) order.set(value, rank); });
    managedEditOrders.set(items, order);
  }
  const order = managedEditOrders.get(items), [value] = items.splice(index, 1);
  return {value, index: order.get(value), order};
}
function restoreManagedEdit(items, restore) {
  const next = items.findIndex(value => restore.order.get(value) > restore.index);
  const index = next < 0 ? items.length : next;
  items.splice(index, 0, restore.value);
  return index;
}
function updateDraftEmpty(list,selector,text){if(list.querySelector(selector))list.querySelector(".empty-draft")?.remove();else if(!list.querySelector(".empty-draft")){const empty=document.createElement("p");empty.className="empty-draft";empty.textContent=text;list.append(empty)}}
// Dynamic rows remove their trigger; keep keyboard focus on a surviving control.
function focusCustomRow(list, rowSelector, index, controlSelector, fallback) {
  const rows = list.querySelectorAll(rowSelector), row = rows[Math.min(index, rows.length - 1)];
  const control = row?.querySelector(controlSelector);
  if (control && list.parentNode?.tagName === "DETAILS") list.parentNode.open = true;
  (control || $(fallback)).focus();
}
function addRule(rule={type:"DOMAIN",value:"",policy:"DIRECT"},restore=null){const list=$("#ruleList"),row=document.createElement("div");row.className="custom-row rule-row"+(restore?" edit-row":"");if(restore)managedDraftEdits.set(row,restore);row.innerHTML=`<select class="rule-type" aria-label="规则类型"><option value="DOMAIN">DOMAIN（精确域名）</option><option value="DOMAIN-SUFFIX">DOMAIN-SUFFIX（域名后缀）</option><option value="IP-CIDR">IP-CIDR（IPv4 网段）</option><option value="IP-CIDR6">IP-CIDR6（IPv6 网段）</option></select><input class="rule-value" aria-label="域名或 IP"><select class="rule-policy" aria-label="分流策略">${policyOptions(rule.policy)}</select><button class="remove-row" aria-label="${restore?"取消编辑":"删除规则"}">${restore?"取消编辑":"删除"}</button><small class="row-error" role="alert"></small>`;const type=row.querySelector(".rule-type"),value=row.querySelector(".rule-value");type.value=rule.type;value.value=rule.value;const updateExample=()=>{value.placeholder={DOMAIN:"示例：api.example.com","DOMAIN-SUFFIX":"示例：example.com","IP-CIDR":"示例：198.51.100.0/24","IP-CIDR6":"示例：2001:db8::/32"}[type.value]};updateExample();type.addEventListener("change",updateExample);row.querySelector(".remove-row").addEventListener("click",()=>{let index=[...list.querySelectorAll(".rule-row")].indexOf(row);row.remove();if(restore){index=restoreManagedEdit(savedRules,restore);renderManagedRules()}updateDraftEmpty(list,".rule-row","暂无新增规则");scheduleCustomValidation();if(restore)focusCustomRow($("#managedRuleList"),".managed-item",index,".ghost","#addRule");else focusCustomRow(list,".rule-row",index,".rule-value","#addRule")});row.querySelectorAll("input,select").forEach(el=>{el.addEventListener("input",scheduleCustomValidation);el.addEventListener("change",scheduleCustomValidation)});list.append(row);updateDraftEmpty(list,".rule-row","暂无新增规则");return row}
function addFilter(value="",restore=null){const list=$("#filterList"),row=document.createElement("div");row.className="custom-row filter-row"+(restore?" edit-row":"");if(restore)managedDraftEdits.set(row,restore);row.innerHTML=`<input class="filter-value" aria-label="Fake-IP Filter 黑名单" placeholder="示例：*.example.com"><button class="remove-row" aria-label="${restore?"取消编辑":"删除黑名单"}">${restore?"取消编辑":"删除"}</button><small class="row-error" role="alert"></small>`;row.querySelector(".filter-value").value=value;row.querySelector(".remove-row").addEventListener("click",()=>{let index=[...list.querySelectorAll(".filter-row")].indexOf(row);row.remove();if(restore){index=restoreManagedEdit(savedFilters,restore);renderManagedFilters()}updateDraftEmpty(list,".filter-row","暂无新增条目");scheduleCustomValidation();if(restore)focusCustomRow($("#managedFilterList"),".managed-item",index,".ghost","#addFilter");else focusCustomRow(list,".filter-row",index,".filter-value","#addFilter")});const input=row.querySelector("input");input.addEventListener("input",scheduleCustomValidation);input.addEventListener("change",scheduleCustomValidation);list.append(row);updateDraftEmpty(list,".filter-row","暂无新增条目");return row}
function managedItem(text,onEdit,onRemove){const row=document.createElement("div");row.className="managed-item";const code=document.createElement("code");code.textContent=text;const actions=document.createElement("div");actions.className="managed-actions";const edit=document.createElement("button");edit.className="ghost";edit.textContent="编辑";edit.setAttribute("aria-label",`编辑 ${text}`);edit.addEventListener("click",onEdit);const remove=document.createElement("button");remove.className="remove-row";remove.textContent="暂存删除";remove.setAttribute("aria-label",`暂存删除 ${text}`);remove.addEventListener("click",onRemove);actions.append(edit,remove);row.append(code,actions);return row}
function renderManagedRules(){const list=$("#managedRuleList");list.replaceChildren();$("#managedRuleCount").textContent=`${savedRules.length} 条`;if(!savedRules.length){const empty=document.createElement("p");empty.className="empty-managed";empty.textContent="没有已保存的标准分流定制";list.append(empty);return}savedRules.forEach((rule,index)=>list.append(managedItem(ruleIdentity(rule),()=>{const restore=takeManagedEdit(savedRules,index);renderManagedRules();const row=addRule(cloneRule(restore.value),restore);scheduleCustomValidation();row.querySelector(".rule-value").focus()},()=>{savedRules.splice(index,1);renderManagedRules();scheduleCustomValidation();focusCustomRow(list,".managed-item",index,".remove-row","#addRule")})))}
function renderManagedFilters(){const list=$("#managedFilterList");list.replaceChildren();$("#managedFilterCount").textContent=`${savedFilters.length} 条`;if(!savedFilters.length){const empty=document.createElement("p");empty.className="empty-managed";empty.textContent="没有已保存的标准 Fake-IP Filter 定制";list.append(empty);return}savedFilters.forEach((value,index)=>list.append(managedItem(value,()=>{const restore=takeManagedEdit(savedFilters,index);renderManagedFilters();const row=addFilter(restore.value,restore);scheduleCustomValidation();row.querySelector(".filter-value").focus()},()=>{savedFilters.splice(index,1);renderManagedFilters();scheduleCustomValidation();focusCustomRow(list,".managed-item",index,".remove-row","#addFilter")})))}
// Use one ordering model for both submitted values and validation row indexes.
// An edit substitutes in its original slot; only newly added rows go at the end.
function managedEntries(items, reconciliation, rows, read, clone) {
  const order = managedEditOrders.get(items), ranked = new Map(), unranked = [], drafts = [];
  const place = (entry, rank) => {
    if (rank === undefined) unranked.push(entry);
    else {
      if (!ranked.has(rank)) ranked.set(rank, []);
      ranked.get(rank).push(entry);
    }
  };
  for (const item of items) place({value: clone(item), row: null}, order?.get(item));
  for (const row of rows) {
    const entry = {value: read(row), row}, restore = managedDraftEdits.get(row);
    if (restore && restore.order === order) place(entry, restore.index);
    else drafts.push(entry);
  }
  // Rank buckets keep even malformed duplicate values visible to validation,
  // rather than silently deduplicating them. Traversal is linear, not a sort.
  const ordered = order ? [...order.values()].flatMap(rank => ranked.get(rank) || []) : [];
  return [...ordered, ...unranked, ...reconciliation.map(value => ({value: clone(value), row: null})), ...drafts];
}
function customEntries(section) {
  if (section === "rules") return managedEntries(savedRules, reconciliationRules, $$('#ruleList .rule-row'),
    row => ({type: row.querySelector('.rule-type').value, value: row.querySelector('.rule-value').value,
      policy: row.querySelector('.rule-policy').value}), cloneRule);
  if (section === "fake_ip_filter") return managedEntries(savedFilters, reconciliationFilters, $$('#filterList .filter-row'),
    row => row.querySelector('.filter-value').value, value => value);
  return [];
}
function collectCustom() {
  return {rules: customEntries("rules").map(entry => entry.value),
    fake_ip_filter: customEntries("fake_ip_filter").map(entry => entry.value),
    supplemental_rules: [...supplementalRules], supplemental_fake_ip_filter: [...supplementalFilters]};
}
function validationRows(section) { return customEntries(section).map(entry => entry.row); }
function ruleMatcher(rule){if(typeof rule==="string"){const parts=rule.split(",");if(parts.length<2)return "";rule={type:parts[0],value:parts[1]}}const type=String(rule.type||"").toUpperCase(),value=String(rule.value||"").trim();return `${type}\0${type.startsWith("DOMAIN")?value.toLowerCase().replace(/\.$/,""):value}`}
function ruleIdentity(rule){return typeof rule==="string"?rule:`${rule.type},${rule.value},${rule.policy}`}
function filterKey(value){const raw=String(value||"").trim().toLowerCase(),prefix=raw.startsWith("*.")?"*.":raw.startsWith("+.")?"+.":"",domain=prefix?raw.slice(2):raw;return prefix+domain.replace(/\.$/,"")}
function configuredDuplicateResult(result){if(!result.ok)return result;const errors=[],current=collectCustom();result.rules.forEach(rule=>{const key=ruleMatcher(rule),identity=ruleIdentity(rule),matching=unownedRulesByMatcher.get(key)||[];if(matching.length&&!(managedRuleIdentities.has(identity)&&matching.every(item=>item===identity))){const index=current.rules.findIndex(item=>ruleMatcher(item)===key),conflict=matching.some(item=>item!==identity);errors.push({section:"rules",index,field:"value",message:conflict?"当前 OpenClash 非同步器配置中已有同匹配条件但内容不同的规则":"当前 OpenClash 配置中已存在相同规则，请勿重复增加"})}});result.fake_ip_filter.forEach(value=>{const key=filterKey(value),matching=unownedFiltersByKey.get(key)||[];if(matching.length&&!(managedFilters.has(key)&&matching.every(item=>item===value))){const index=current.fake_ip_filter.findIndex(item=>filterKey(item)===key),conflict=matching.some(item=>item!==value);errors.push({section:"fake_ip_filter",index,field:"value",message:conflict?"当前 OpenClash 非同步器配置中已有等价但格式不同的 Fake-IP Filter":"当前 OpenClash 配置中已存在相同 Fake-IP Filter，请勿重复增加"})}});return errors.length?{ok:false,message:`发现 ${errors.length} 个配置重复或冲突项`,errors}:result}
function clearCustomErrors() {
  $$(".custom-row").forEach(row => {
    row.classList.remove("invalid");
    row.querySelector(".row-error").textContent = "";
    row.querySelectorAll("input,select").forEach(control => control.removeAttribute("aria-invalid"));
  });
}
function updateCustomSaveState(){$("#saveCustom").disabled=operationBusy||!customIsValid||Object.keys(customStateHash).length!==2||Object.keys(customConfigHash).length!==2||!$("#customConfirm").checked}
function invalidateCustomBinding(message = "配置可能已变化，请重新读取两个子网（现有草稿仍保留）", state = "idle") {
  customStateHash = {};
  customConfigHash = {};
  customIsValid = false;
  customRevision++;
  customController?.abort();
  clearTimeout(customTimer);
  $("#customValidation").className = "validation " + state;
  $("#customValidation").textContent = message;
  updateCustomSaveState();
}
function showCustomResult(result, focus = false) {
  clearCustomErrors();
  const el = $("#customValidation");
  customIsValid = result.ok === true;
  updateCustomSaveState();
  if (customIsValid) {
    el.className = "validation good";
    el.textContent = `检查通过 · ${result.summary.rules} 条分流 / ${result.summary.fake_ip_filter} 条 Fake-IP 黑名单`;
    return true;
  }
  el.className = "validation bad";
  el.textContent = result.message;
  // Resolve each section once, not once per error (which rescans the full DOM).
  const rows = new Map();
  let firstInvalid = null;
  for (const error of Array.isArray(result.errors) ? result.errors : []) {
    if (!error || !Number.isInteger(error.index) || error.index < 0) continue;
    if (!rows.has(error.section)) rows.set(error.section, validationRows(error.section));
    const row = rows.get(error.section)[error.index];
    if (!row) continue;
    row.classList.add("invalid");
    row.querySelector(".row-error").textContent = error.message;
    const selector = error.section === "rules"
      ? error.field === "type" ? ".rule-type" : error.field === "policy" ? ".rule-policy" : ".rule-value"
      : ".filter-value";
    const control = row.querySelector(selector);
    control?.setAttribute("aria-invalid", "true");
    firstInvalid ||= control;
  }
  if (focus && firstInvalid) {
    const revision = customRevision;
    const focusError = () => {
      if (revision === customRevision && $("#custom").classList.contains("active")) firstInvalid.focus();
    };
    // Save checks run with inputs disabled; background checks never move focus.
    if (operationBusy && firstInvalid.disabled) operationFocus = focusError;
    else focusError();
  }
  return false;
}
async function validateCustom(focus = false) {
  clearTimeout(customTimer);
  focus = focus === true;
  const customization = collectCustom(), signature = JSON.stringify(customization);
  if (customPending && customPending.revision === customRevision && !customPending.controller.signal.aborted
      && customPending.signature === signature) {
    customPending.focus ||= focus;
    return customPending.promise;
  }
  const revision = ++customRevision;
  customController?.abort();
  const controller = customController = new AbortController();
  const request = customPending = {revision, signature, controller, focus};
  const fresh = () => revision === customRevision && signature === JSON.stringify(collectCustom());
  customIsValid = false;
  updateCustomSaveState();
  $("#validateCustom").setAttribute("aria-busy", "true");
  $("#customValidation").className = "validation idle";
  $("#customValidation").textContent = "正在检查…";
  request.promise = (async () => {
    try {
      const checked = await api("/api/custom/validate", {customization}, controller.signal);
      if (!fresh()) return false;
      return showCustomResult(configuredDuplicateResult(checked), request.focus);
    } catch (e) {
      if (!fresh() || e.name === "AbortError") return false;
      showCustomResult({ok: false, message: e.message, errors: Array.isArray(e.details) ? e.details : []}, request.focus);
      return false;
    } finally {
      if (customPending === request) {
        customPending = null;
        $("#validateCustom").setAttribute("aria-busy", "false");
      }
    }
  })();
  return request.promise;
}
function scheduleCustomValidation() {
  clearTimeout(customTimer);
  customRevision++;
  customController?.abort();
  customIsValid = false;
  updateCustomSaveState();
  updateDraftNotice();
  $("#customValidation").className = "validation idle";
  $("#customValidation").textContent = "正在检查…";
  customTimer = setTimeout(validateCustom, 350);
}
$("#addRule").addEventListener("click",()=>{addRule();scheduleCustomValidation();$("#ruleList .rule-row:last-of-type .rule-value")?.focus()});$("#addFilter").addEventListener("click",()=>{addFilter();scheduleCustomValidation();$("#filterList .filter-row:last-of-type .filter-value")?.focus()});$("#validateCustom").addEventListener("click",()=>validateCustom(true));
$("#customConfirm").addEventListener("change",updateCustomSaveState);
async function loadCustom(showNotice = true) {
  try {
    const data = await nonceRequest("/api/custom/read");
    requireReadConnection();
    const validHashes = (value) => value && Object.keys(value).length === 2
      && ["router_a", "router_b"].every((target) => digestValid(value[target]));
    if (!validHashes(data.state_sha256) || !validHashes(data.config_sha256)) {
      throw new Error("双子网定制状态或主配置摘要无效");
    }
    if (!["supplemental_rules", "supplemental_fake_ip_filter", "rules", "fake_ip_filter",
      "unowned_rule_matcher_overrides", "groups"].every((key) => Array.isArray(data[key]))) {
      throw new Error("双子网定制清单格式无效");
    }
    groups = ["DIRECT", ...data.groups.filter((name) => name !== "DIRECT")];
    customStateHash = data.state_sha256;
    customConfigHash = data.config_sha256;
    supplementalRules = [...data.supplemental_rules];
    supplementalFilters = [...data.supplemental_fake_ip_filter];
    savedRules=(data.editable_rules||data.rules).map(cloneRule);
    savedFilters = [...(data.editable_fake_ip_filter || data.fake_ip_filter)];
    reconciliationRules=(data.reconciliation_rules||[]).map(cloneRule);
    reconciliationFilters = [...(data.reconciliation_fake_ip_filter || [])];
    managedRuleIdentities = new Set(data.rules.map(ruleIdentity));
    managedFilters = new Set(data.fake_ip_filter.map(filterKey));
    unownedRulesByMatcher = new Map();
    const rawUnowned = data.unowned_configured_rules || [], matcherOverrides = new Map();
    data.unowned_rule_matcher_overrides.forEach((item) => {
      if (Array.isArray(item) && item.length === 3 && Number.isInteger(item[0]) && item[0] >= 0
          && item[0] < rawUnowned.length && typeof item[1] === "string" && typeof item[2] === "string") {
        matcherOverrides.set(item[0], `${item[1]}\0${item[2]}`);
      }
    });
    rawUnowned.forEach((item, index) => {
      const key = matcherOverrides.get(index)||ruleMatcher(item);
      if (key) {
        const values = unownedRulesByMatcher.get(key) || [];
        values.push(item);
        unownedRulesByMatcher.set(key, values);
      }
    });
    unownedFiltersByKey = new Map();
    (data.unowned_configured_fake_ip_filter || []).forEach((item) => {
      const key = filterKey(item), values = unownedFiltersByKey.get(key) || [];
      values.push(item);
      unownedFiltersByKey.set(key, values);
    });
    $("#ruleList").replaceChildren();
    $("#filterList").replaceChildren();
    updateDraftEmpty($("#ruleList"), ".rule-row", "暂无新增规则");
    updateDraftEmpty($("#filterList"), ".filter-row", "暂无新增条目");
    renderManagedRules();
    renderManagedFilters();
    $("#configuredRules").textContent = (data.configured_rules || []).join("\n");
    $("#configuredFilters").textContent = (data.configured_fake_ip_filter || []).join("\n");
    const c = data.configured_counts || {}, d = data.baseline_delta||{};
    const countPair = (a, b) => [a, b].every(Number.isInteger) ? a + b : "?";
    const safe = countPair(d.rules, d.fake_ip_filter);
    const exact = countPair(d.exact_rules, d.exact_fake_ip_filter);
    const unresolved = countPair(d.unresolved_rules, d.unresolved_fake_ip_filter);
    $("#configuredSummary").textContent = `路由器 A ${c.router_a?.rules ?? "?"} 条规则 / ${c.router_a?.fake_ip_filter ?? "?"} 条 Filter；路由器 B ${c.router_b?.rules ?? "?"} 条规则 / ${c.router_b?.fake_ip_filter ?? "?"} 条 Filter；只读并集 ${(data.configured_rules || []).length} / ${(data.configured_fake_ip_filter || []).length}；可补齐 ${safe} 条（完整原文 ${exact} 条）/ 超出页面范围 ${unresolved} 条`;
    $("#customConfirm").checked = false;
    customBaseline = JSON.stringify(collectCustom());
    lockNewControls();
    await validateCustom();
    if (showNotice) notice(data.message);
    return true;
  } catch (e) {
    invalidateCustomBinding("读取未成功，旧检查已失效；请重新读取两个子网（现有草稿仍保留）", "bad");
    notice(e.message + "；未保存草稿仍保留，请重新读取", true);
    return false;
  }
}
$("#loadCustom").addEventListener("click", () => runOperation("正在读取两个子网的定制并集", async () => {
  if (confirmDiscard("custom")) await loadCustom(true);
}));
$("#saveCustom").addEventListener("click", () => runOperation("正在预演并提交两个子网的定制", async () => {
  if (!$("#customConfirm").checked) throw new Error("请先确认主配置变化时会重启 OpenClash");
  if (Object.keys(customStateHash).length !== 2 || Object.keys(customConfigHash).length !== 2) {
    throw new Error("请先读取两个子网的当前定制，防止覆盖其他会话的修改");
  }
  if (!await validateCustom(true)) return;
  const saved = await mutate("/api/custom/apply", {
    customization: collectCustom(), expected_state_sha256: customStateHash,
    expected_config_sha256: customConfigHash
  }, "custom");
  if (saved) {
    const read = await loadCustom(false);
    notice(saved.message + (read ? "" : "；保存已返回成功，但重新读取失败，请再次读取确认"), !read);
  } else {
    $("#customConfirm").checked = false;
    invalidateCustomBinding("保存未完整完成，请重新读取两个子网的当前定制", "bad");
  }
}));

function routeLabel(result){if(result.mode==="UNKNOWN")return "缺少足够的运行上下文，结果 UNKNOWN";const contextual=result.certainty==="CONTEXTUAL",certainty=contextual?"上下文受限，存在源端口/进程/DNS/GEOIP 等例外":"精确匹配";if(result.mode==="REJECT")return `${contextual?"通常":""}已拦截 · 策略 ${result.policy} · ${certainty}`;const mode=result.mode==="DIRECT"?"直连":"代理",reachable=result.reachability==="REACHABLE"?"固定探针可达":result.reachability==="UNREACHABLE"?"固定探针不可达":"固定探针状态 UNKNOWN";return `${contextual?"通常":""}${mode} · ${reachable} · 策略 ${result.policy} · ${certainty}`}
$("#checkRoute").addEventListener("click", () => runOperation("正在判断两个子网并检查固定探针", async () => {
  const value = $("#routeValue").value.trim();
  $("#routeResult").replaceChildren();
  if (!value) throw new Error("请输入网址、域名或 IP");
  $("#routeResult").textContent = "正在判断当前输入；此前的判路结果已失效。";
  try {
    const data = await nonceRequest("/api/route-check", {value});
    requireReadConnection();
    $("#routeResult").innerHTML = Object.entries(data.results).map(([target, result]) =>
      `<article><strong>${target === "router_a" ? "路由器 A" : "路由器 B"}</strong> · ${escapeHtml(routeLabel(result))}</article>`
    ).join("");
    notice(data.message);
  } catch (e) {
    $("#routeResult").replaceChildren();
    notice(e.message, true);
  }
}));
$("#routeValue").addEventListener("input", () => $("#routeResult").replaceChildren());
$("#routeValue").addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    $("#checkRoute").click();
  }
});

// Single-target chain manager. Only public profiles are retained; passwords stay in
// the form/current request and are cleared after every attempted submission.
const chainFieldIds = {
  node: "chainNode", type: "chainType", server: "chainServer", port: "chainPort",
  username: "chainUsername", password: "chainPassword", tls: "chainTls",
  sni: "chainSni", cipher: "chainCipher", keep_password: "chainKeepPassword"
};
const chainCiphers = new Set(["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"]);
let chainReadTarget = "", chainSelectorTarget = $("#chainTarget").value;
let chainConfigHash = "", chainStateHash = "", chainNodes = [], chainProfiles = [];
let selectedChainNode = "", chainBaseline = "", chainIsValid = false;
let chainRevision = 0, chainTimer = null, chainController = null, chainPending = null;

function collectChain() {
  const type = $("#chainType").value;
  const tls = type !== "ss" && $("#chainTls").checked;
  return {
    node: $("#chainNode").value,
    type,
    server: $("#chainServer").value.trim(),
    port: Number($("#chainPort").value),
    username: type === "ss" ? "" : $("#chainUsername").value,
    password: $("#chainPassword").value,
    tls,
    sni: tls ? $("#chainSni").value.trim() : "",
    cipher: type === "ss" ? $("#chainCipher").value : "",
    keep_password: $("#chainKeepPassword").checked
  };
}

function chainIdentity(profile) {
  return JSON.stringify({
    node: profile.node, type: profile.type, server: profile.server, port: profile.port,
    username: profile.username || "", tls: profile.tls === true,
    sni: profile.sni || "", cipher: profile.cipher || ""
  });
}

function chainDraftSignature() {
  const chain = collectChain();
  // Dirty-state bookkeeping must not keep another copy of the password.
  return JSON.stringify({identity: chainIdentity(chain), keep: chain.keep_password,
    typedPassword: chain.password.length > 0});
}

function savedChain(node = $("#chainNode").value) {
  return chainProfiles.find((profile) => profile.node === node) || null;
}

function chainReady() {
  return chainReadTarget === $("#chainTarget").value
    && digestValid(chainConfigHash) && digestValid(chainStateHash);
}

function canKeepChainPassword(chain = collectChain()) {
  const saved = savedChain(chain.node);
  return chainReady() && Boolean(saved?.has_password)
    && chainIdentity(saved) === chainIdentity(chain);
}

function setChainValidation(message, state = "idle") {
  $("#chainValidation").className = "validation " + state;
  $("#chainValidation").textContent = message;
}

function updateChainControls() {
  const ready = chainReady(), selected = ready && Boolean($("#chainNode").value);
  const existing = selected && Boolean(savedChain());
  const isSS = $("#chainType").value === "ss";
  const tls = !isSS && $("#chainTls").checked;
  const keepAllowed = canKeepChainPassword();
  if (!keepAllowed) $("#chainKeepPassword").checked = false;
  $$("#chainForm input, #chainForm select").forEach((input) => {
    input.disabled = operationBusy || !ready;
  });
  $("#chainNode").disabled = operationBusy || !ready || !chainNodes.length;
  $("#chainUsernameField").classList.toggle("hidden", isSS);
  $("#chainTlsField").classList.toggle("hidden", isSS);
  $("#chainSniField").classList.toggle("hidden", !tls);
  $("#chainCipherField").classList.toggle("hidden", !isSS);
  $("#chainUsername").disabled = operationBusy || !ready || isSS;
  $("#chainTls").disabled = operationBusy || !ready || isSS;
  $("#chainSni").disabled = operationBusy || !ready || !tls;
  $("#chainCipher").disabled = operationBusy || !ready || !isSS;
  $("#chainKeepPassword").disabled = operationBusy || !selected || !keepAllowed;
  $("#chainPassword").disabled = operationBusy || !ready || $("#chainKeepPassword").checked;
  $("#chainPassword").required = isSS && !$("#chainKeepPassword").checked;
  $("#chainPasswordHint").textContent = savedChain()?.has_password
    ? "路由器已存有密码，但不会回显。填写新密码，或显式勾选保留；修改身份后不能复用旧密码。"
    : "没有可保留的密码。按代理服务要求填写；SS 必须提供密码。";
  $("#chainKeepHint").textContent = keepAllowed
    ? "身份未改变，可明确勾选保留已保存密码；不会把密码传回浏览器。"
    : "保留不可用：需要同一节点、协议、地址、端口、用户名、TLS/SNI 及加密方式，并已有保存的密码。";
  $("#validateChain").disabled = operationBusy || !selected;
  $("#saveChain").disabled = operationBusy || !selected || !chainIsValid
    || !$("#chainConfirm").checked || chainDraftSignature() === chainBaseline;
  $("#removeChain").disabled = operationBusy || !existing || !$("#chainConfirm").checked;
  $("#testChain").disabled = operationBusy || !existing;
  $("#resetChain").disabled = operationBusy || chainDraftSignature() === chainBaseline;
  $("#saveChain").textContent = existing ? "更新链式代理" : "应用链式代理";
  $("#chainFormHeading").textContent = existing ? "更新所选链路" : "新增链路";
}

function invalidateChainValidation(message = "配置已变化，等待检查…") {
  clearTimeout(chainTimer);
  chainController?.abort();
  chainPending = null;
  $("#validateChain").setAttribute("aria-busy", "false");
  chainRevision++;
  chainIsValid = false;
  setChainValidation(message);
}

function invalidateChainBinding() {
  chainConfigHash = "";
  chainStateHash = "";
  resetChainTest();
  invalidateChainValidation("配置可能已变化，请重新读取所选子网（草稿仍保留）");
  $("#chainReadState").textContent = "读取摘要已失效；再次读取前不能应用、取消或测试。";
  updateChainControls();
}

function localChainError(chain) {
  if (!chainReady()) return "请先读取当前子网的节点与链式配置";
  if (!chainNodes.some((node) => node.name === chain.node)) return "请选择当前子网中的原节点";
  if (!["socks5", "http", "ss"].includes(chain.type)) return "落地协议不支持";
  if (!chain.server || chain.server.length > 253 || /[\s\x00-\x1f\x7f/@?#<>\[\]\\]/.test(chain.server)) {
    return "落地地址必须是 IP 或域名，不能包含协议、路径、空格、凭据或订阅链接";
  }
  if (!Number.isInteger(chain.port) || chain.port < 1 || chain.port > 65535) return "端口必须是 1–65535 的整数";
  if (chain.username.length > 255 || /[\x00-\x1f\x7f]/.test(chain.username)) return "用户名格式无效";
  if (chain.password.length > 4096 || /[\x00-\x1f\x7f]/.test(chain.password)) return "密码长度或格式无效";
  if (chain.sni.length > 253 || /[\s\x00-\x1f\x7f/:@?#<>\[\]\\]/.test(chain.sni)) return "SNI 应为证书对应的域名";
  if (chain.type === "ss" && !chainCiphers.has(chain.cipher)) return "请选择受支持的 SS 加密方式";
  if (chain.keep_password && (!canKeepChainPassword(chain) || chain.password)) {
    return "代理身份已改变或填写了新密码，不能保留旧密码";
  }
  if ((chain.type === "ss" || chain.username) && !chain.password && !chain.keep_password) {
    return "请输入密码，或在身份未改变时明确选择保留已保存密码";
  }
  if (canKeepChainPassword(chain) && !chain.password && !chain.keep_password) {
    return "此链路已有密码，请填写新密码或明确勾选保留，避免误清空";
  }
  return "";
}

async function validateChain() {
  clearTimeout(chainTimer);
  const target = $("#chainTarget").value, chain = collectChain();
  const signature = chainDraftSignature();
  if (chainPending && chainPending.revision === chainRevision && !chainPending.controller.signal.aborted
      && chainPending.target === target && chainPending.signature === signature
      && chainPending.chain.password === chain.password) {
    chain.password = "";
    return chainPending.promise;
  }
  const revision = ++chainRevision;
  chainController?.abort();
  const controller = chainController = new AbortController();
  const fresh = () => revision === chainRevision && target === $("#chainTarget").value
    && signature === chainDraftSignature() && chain.password === $("#chainPassword").value;
  chainPending = null;
  chainIsValid = false;
  $("#validateChain").setAttribute("aria-busy", "false");
  const error = localChainError(chain);
  if (error) {
    chain.password = "";
    setChainValidation(error, "bad");
    updateChainControls();
    return false;
  }
  // Keep one reference to the existing request-local profile, never a password
  // signature/cache. A settled request is removed and its password cleared.
  const request = chainPending = {revision, target, signature, chain, controller};
  $("#validateChain").setAttribute("aria-busy", "true");
  setChainValidation("正在检查链式配置…");
  updateChainControls();
  request.promise = (async () => {
    try {
      const result = await api("/api/chain/validate", {chain}, controller.signal);
      if (!fresh()) return false;
      chainIsValid = result.ok === true;
      setChainValidation(result.message || (chainIsValid ? "链式配置检查通过；尚未执行链路测试" : "链式配置检查未通过"), chainIsValid ? "good" : "bad");
      updateChainControls();
      return chainIsValid;
    } catch (e) {
      if (!fresh() || e.name === "AbortError") return false;
      chainIsValid = false;
      setChainValidation(e.message, "bad");
      updateChainControls();
      return false;
    } finally {
      chain.password = "";
      if (chainPending === request) {
        chainPending = null;
        $("#validateChain").setAttribute("aria-busy", "false");
      }
    }
  })();
  return request.promise;
}

function scheduleChainValidation() {
  invalidateChainValidation();
  updateChainControls();
  updateDraftNotice();
  if (chainReady() && $("#chainNode").value) chainTimer = setTimeout(validateChain, 400);
}

function resetChainTest() {
  $("#chainTestResult").replaceChildren();
  const text = document.createElement("p");
  text.className = "help";
  text.textContent = "尚未测试所选已保存链路。无法确认的结果显示 UNKNOWN。";
  $("#chainTestResult").append(text);
}

function fillChainForm(node) {
  const profile = savedChain(node);
  selectedChainNode = node;
  $("#chainNode").value = node;
  $("#chainType").value = profile?.type || "socks5";
  $("#chainServer").value = profile?.server || "";
  $("#chainPort").value = profile ? String(profile.port) : "";
  $("#chainUsername").value = profile?.username || "";
  $("#chainPassword").value = "";
  $("#chainTls").checked = profile?.tls === true;
  $("#chainSni").value = profile?.sni || "";
  $("#chainCipher").value = profile?.cipher || "aes-128-gcm";
  $("#chainKeepPassword").checked = false;
  $("#chainConfirm").checked = false;
  chainBaseline = chainDraftSignature();
  $("#chainSelectionState").textContent = profile
    ? "此原节点已启用链式。修改后应用可更新；取消会恢复原节点。"
    : node ? "此原节点尚未启用链式。请提供真实可用的落地代理服务。" : "先选择原节点，再配置落地代理。";
  invalidateChainValidation(profile?.has_password
    ? "已读取链路；更新前需填写新密码或显式选择保留" : "请完善落地设置后检查配置");
  resetChainTest();
  updateChainControls();
  updateDraftNotice();
}

function selectChainNode(node) {
  // A select's value has already changed when its change event fires. Compare
  // against the old selection so merely choosing a node is not a dirty draft.
  $("#chainNode").value = selectedChainNode;
  if (!confirmDiscard("chain")) return;
  fillChainForm(node);
  $("#chainNode").focus();
}

function publicChainRead(data, target) {
  if (data.ok !== true || data.target !== target || !digestValid(data.config_sha256)
      || !digestValid(data.state_sha256) || !Array.isArray(data.nodes) || !Array.isArray(data.chains)) {
    throw new Error("链式配置响应或并发摘要格式无效");
  }
  const names = new Set();
  const nodes = data.nodes.map((node) => {
    if (!node || typeof node.name !== "string" || !node.name || typeof node.type !== "string" || names.has(node.name)) {
      throw new Error("原节点清单格式无效或存在重名");
    }
    names.add(node.name);
    return {name: node.name, type: node.type};
  });
  const chained = new Set();
  const profiles = data.chains.map((profile) => {
    if (!profile || !names.has(profile.node) || chained.has(profile.node)
        || !["socks5", "http", "ss"].includes(profile.type) || typeof profile.server !== "string"
        || !Number.isInteger(profile.port) || profile.port < 1 || profile.port > 65535
        || typeof profile.has_password !== "boolean"
        || Object.prototype.hasOwnProperty.call(profile, "password")
        || ["username", "sni", "cipher"].some((key) => profile[key] !== undefined && typeof profile[key] !== "string")
        || (profile.tls !== undefined && typeof profile.tls !== "boolean")) {
      throw new Error("链式配置公开视图格式无效；不会显示敏感字段");
    }
    chained.add(profile.node);
    return {
      node: profile.node, type: profile.type, server: profile.server, port: profile.port,
      username: profile.username || "", tls: profile.tls === true, sni: profile.sni || "",
      cipher: profile.cipher || "", has_password: profile.has_password
    };
  });
  return {nodes, profiles};
}

function renderChainList() {
  const list = $("#chainList");
  list.replaceChildren();
  $("#chainCount").textContent = `${chainProfiles.length} 条`;
  if (!chainProfiles.length) {
    const empty = document.createElement("p");
    empty.className = "empty-managed";
    empty.textContent = "此子网尚未启用链式代理。可在下方选择原节点并添加落地。";
    list.append(empty);
    return;
  }
  chainProfiles.forEach((profile) => {
    const row = document.createElement("article");
    row.className = "chain-item";
    const details = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = profile.node;
    const route = document.createElement("p");
    const protocol = profile.type === "http" && profile.tls ? "HTTPS" : profile.type.toUpperCase();
    const server = profile.server.includes(":") ? `[${profile.server}]` : profile.server;
    route.textContent = `原节点 → ${protocol} ${server}:${profile.port} → 网站`;
    const password = document.createElement("small");
    password.textContent = profile.has_password ? "密码已保存 · 不回显" : "没有已保存密码";
    details.append(title, route, password);
    const button = document.createElement("button");
    button.type = "button";
    button.className = "ghost";
    button.textContent = "选择链路";
    button.setAttribute("aria-label", `选择链路 ${profile.node}`);
    button.addEventListener("click", () => {
      if (!operationBusy) selectChainNode(profile.node);
    });
    row.append(details, button);
    list.append(row);
  });
  lockNewControls();
}

async function readChains(preferredNode = "", showNotice = true) {
  const target = $("#chainTarget").value;
  try {
    const data = await nonceRequest("/api/chain/read", {target});
    requireReadConnection();
    const publicData = publicChainRead(data, target);
    chainReadTarget = target;
    chainSelectorTarget = target;
    chainConfigHash = data.config_sha256;
    chainStateHash = data.state_sha256;
    chainNodes = publicData.nodes;
    chainProfiles = publicData.profiles;
    $("#chainNode").replaceChildren();
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = chainNodes.length ? "请选择原节点" : "此子网没有可用原节点";
    $("#chainNode").append(placeholder);
    const enabled = new Set(chainProfiles.map((profile) => profile.node));
    chainNodes.forEach((node) => {
      const option = document.createElement("option");
      option.value = node.name;
      option.textContent = `${node.name} · ${node.type}${enabled.has(node.name) ? " · 已启用链式" : ""}`;
      $("#chainNode").append(option);
    });
    renderChainList();
    fillChainForm(chainNodes.some((node) => node.name === preferredNode) ? preferredNode : "");
    $("#chainReadState").textContent = `${target === "router_a" ? "路由器 A" : "路由器 B"} · ${chainNodes.length} 个原节点 · 配置 ${chainConfigHash.slice(0, 12)}… · 状态 ${chainStateHash.slice(0, 12)}…`;
    if (showNotice) notice(data.message || "已读取所选子网的链式配置");
    return true;
  } catch (e) {
    invalidateChainBinding();
    notice(e.message + "；未保存草稿仍保留，请重新读取", true);
    return false;
  }
}

function renderChainTest(data, node, liveMode = mode) {
  if (data.node !== node || !["PASS", "FAIL"].includes(data.configuration)
      || !["PASS", "FAIL", "UNKNOWN"].includes(data.runtime)
      || !["REACHABLE", "UNREACHABLE", "UNKNOWN"].includes(data.upstream)
      || !["REACHABLE", "UNREACHABLE", "UNKNOWN"].includes(data.chain)
      || !["PASS", "FAIL", "UNKNOWN"].includes(data.verdict)) {
    throw new Error("链路测试响应格式无效，结果不能确认（UNKNOWN）");
  }
  const results = {...data};
  if (liveMode !== "live") {
    results.runtime = "UNKNOWN";
    results.upstream = "UNKNOWN";
    results.chain = "UNKNOWN";
    results.verdict = "UNKNOWN";
  } else {
    const failed = results.configuration === "FAIL" || results.runtime === "FAIL"
      || results.upstream === "UNREACHABLE" || results.chain === "UNREACHABLE";
    const proven = results.configuration === "PASS" && results.runtime === "PASS"
      && results.upstream === "REACHABLE" && results.chain === "REACHABLE";
    if (failed) results.verdict = "FAIL";
    else if (!proven && results.verdict === "PASS") results.verdict = "UNKNOWN";
  }
  const list = $("#chainTestResult");
  list.replaceChildren();
  const summary = document.createElement("p");
  summary.className = "chain-verdict " + (results.verdict === "PASS" ? "good" : results.verdict === "FAIL" ? "bad" : "unknown");
  summary.textContent = `${node} · ${results.verdict === "PASS" ? "链式固定探针验证通过" : results.verdict === "FAIL" ? "链式验证未通过" : "链式是否成功尚不能确认"} · ${results.verdict}`;
  list.append(summary);
  const grid = document.createElement("dl");
  grid.className = "chain-results-grid";
  for (const [key, label] of [["configuration", "配置定义"], ["runtime", "运行态链路"], ["upstream", "原节点固定探针"], ["chain", "完整链路固定探针"]]) {
    const entry = document.createElement("div");
    const term = document.createElement("dt"), value = document.createElement("dd");
    term.textContent = label;
    value.textContent = results[key];
    value.className = ["PASS", "REACHABLE"].includes(results[key]) ? "good"
      : ["FAIL", "UNREACHABLE"].includes(results[key]) ? "bad" : "unknown";
    entry.append(term, value);
    grid.append(entry);
  }
  const message = document.createElement("p");
  message.className = "help";
  message.textContent = liveMode === "live" ? (data.message || "测试已完成；仅代表所选已保存链路的固定探针结果。")
    : "预览模式没有实时链路证据；以上运行态与网络测试均为 UNKNOWN。";
  list.append(grid, message);
}

$("#loadChain").addEventListener("click", () => runOperation("正在读取所选子网的节点与链式配置", async () => {
  if (confirmDiscard("chain")) await readChains(selectedChainNode);
}));
$("#chainTarget").addEventListener("change", () => {
  if (!confirmDiscard("chain")) {
    $("#chainTarget").value = chainSelectorTarget;
    return;
  }
  chainSelectorTarget = $("#chainTarget").value;
  chainReadTarget = "";
  chainConfigHash = "";
  chainStateHash = "";
  chainNodes = [];
  chainProfiles = [];
  $("#chainNode").replaceChildren();
  $("#chainList").replaceChildren();
  $("#chainCount").textContent = "0 条";
  fillChainForm("");
  $("#chainReadState").textContent = "子网已切换，请先读取其节点与链式配置。";
});
$("#chainNode").addEventListener("change", () => selectChainNode($("#chainNode").value));
for (const [key, id] of Object.entries(chainFieldIds)) {
  if (key === "node") continue;
  const input = $("#" + id);
  const eventName = input.type === "checkbox" || input.tagName === "SELECT" ? "change" : "input";
  input.addEventListener(eventName, () => {
    if (key === "keep_password" && input.checked) $("#chainPassword").value = "";
    if (key === "password" && input.value) $("#chainKeepPassword").checked = false;
    if (key === "type") {
      $("#chainPassword").value = "";
      $("#chainKeepPassword").checked = false;
      if (input.value === "ss") {
        $("#chainUsername").value = "";
        $("#chainTls").checked = false;
      }
    }
    if (!$("#chainTls").checked) $("#chainSni").value = "";
    scheduleChainValidation();
  });
}
$("#chainConfirm").addEventListener("change", updateChainControls);
$("#validateChain").addEventListener("click", validateChain);
$("#resetChain").addEventListener("click", () => {
  if (confirmDiscard("chain")) fillChainForm(selectedChainNode);
});
$("#chainForm").addEventListener("submit", (event) => {
  event.preventDefault();
  return runOperation("正在预演并应用链式代理，配置变化时可能需要 1–3 分钟", async () => {
    if (!chainReady()) throw new Error("请先读取当前子网的链式配置");
    if (!$("#chainConfirm").checked) throw new Error("请先确认链式出口变化及可能的重启影响");
    if (!await validateChain()) return;
    const target = chainReadTarget, chain = collectChain(), node = chain.node;
    let applied = null;
    try {
      applied = await nonceRequest("/api/chain/apply", {
        target, operation: "upsert", expected_config_sha256: chainConfigHash,
        expected_state_sha256: chainStateHash, chain
      });
    } finally {
      chain.password = "";
      $("#chainPassword").value = "";
      $("#chainKeepPassword").checked = false;
      $("#chainConfirm").checked = false;
      invalidateChainValidation("提交尝试完成，密码输入已清空；请重新读取后确认状态");
      invalidateViews([target], "chain");
      if (!applied) invalidateChainBinding();
    }
    const read = await readChains(node, false);
    notice((applied.message || "链式设置已应用")
      + (read ? "；已重新读取。请执行固定探针测试确认链路。" : "；重新读取失败，当前状态需再次确认。"), !read);
    await refresh(true);
  });
});
$("#removeChain").addEventListener("click", () => runOperation("正在取消所选链式代理并恢复原节点", async () => {
  if (!chainReady() || !savedChain()) throw new Error("请先读取并选择已保存的链路");
  if (!$("#chainConfirm").checked) throw new Error("请先确认取消链式的出口变化及可能的重启影响");
  if (!confirmDiscard("chain")) return;
  const target = chainReadTarget, node = selectedChainNode;
  let removed = null;
  try {
    removed = await nonceRequest("/api/chain/apply", {
      target, operation: "remove", node,
      expected_config_sha256: chainConfigHash, expected_state_sha256: chainStateHash
    });
  } finally {
    $("#chainPassword").value = "";
    $("#chainKeepPassword").checked = false;
    $("#chainConfirm").checked = false;
    invalidateViews([target], "chain");
    if (!removed) invalidateChainBinding();
  }
  const read = await readChains(node, false);
  notice((removed.message || "所选链式已取消") + (read ? "；已重新读取原节点配置。" : "；重新读取失败，请再次读取确认。"), !read);
  await refresh(true);
}));
$("#testChain").addEventListener("click", () => runOperation("正在测试已保存的原节点与完整链路固定探针", async () => {
  if (!chainReady() || !savedChain()) throw new Error("请先读取并选择已保存的链路；草稿不能测试");
  const node = selectedChainNode, liveMode = mode;
  resetChainTest();
  $("#chainTestResult").textContent = "正在测试所选已保存链路；不会使用未保存草稿。";
  try {
    const data = await nonceRequest("/api/chain/test", {target: chainReadTarget, node});
    requireReadConnection();
    renderChainTest(data, node, liveMode);
    notice(liveMode === "live" ? "已返回分项链路测试结果；请查看 PASS / FAIL / UNKNOWN。" : "预览模式：未执行真实链路成功验证。");
  } catch (e) {
    $("#chainTestResult").textContent = "测试未完成 · UNKNOWN。" + e.message;
    throw e;
  }
}));

customBaseline = JSON.stringify(collectCustom());
chainBaseline = chainDraftSignature();
updateChainControls();
editorLines();
runOperation("正在连接管理服务", () => bootstrap());
