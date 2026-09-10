"use strict";
// Separate module, no persistent storage, automatic fetch of source URLs, or
// retries of credential-bearing requests. app.js owns the global operation lock.
let converterSchema = null, converterResult = "", converterResultTarget = "";
let converterBaseline = "", converterOptionFields = new Map();
let converterUploads = [], converterExport = null, converterResources = [];
let converterToolsBaseline = "";
// The change event sees the new DOM value; keep the last accepted selection.
let converterSelectedProfile = "manual";
const converterToolExports = new Map();
// Mirrors the current engine/server contract; remote expansion is checked again there.
const CONVERTER_MAX_FILES = 64, CONVERTER_SCRIPT_BYTES = 65536;
const CONVERTER_REQUEST_BYTES = 2 * 1024 * 1024, CONVERTER_ARCHIVE_BYTES = 8 * 1024 * 1024;
const CONVERTER_TOOLS = {
  ruleset: {label: "规则集转换", extension: "txt"},
  template: {label: "模板渲染", extension: "txt"},
  surge2clash: {label: "Surge → Clash", extension: "yaml"}
};
const converterBytes = value => new TextEncoder().encode(value).byteLength;
const CONVERTER_PARAMETER_PATTERN = "[A-Za-z][A-Za-z0-9_.-]{0,63}";
function converterParameterContract(schema) {
  if (!schema || !Object.hasOwn(schema, "parameters")) return null;
  const spec = schema.parameters;
  if (!converterRecord(spec) || !Number.isSafeInteger(spec.max) || spec.max < 1 || spec.max > 32
      || !Number.isSafeInteger(spec.value_bytes) || spec.value_bytes < 1 || spec.value_bytes > 4096
      || ![CONVERTER_PARAMETER_PATTERN, "^" + CONVERTER_PARAMETER_PATTERN + "$"].includes(spec.key_pattern)
      || !Array.isArray(spec.reserved) || !spec.reserved.every(key => typeof key === "string" && /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(key) && key.trim() === key)) throw new Error("自定义模板参数目录格式无效");
  return spec;
}
function converterValidateParameters(value, schema = converterSchema) {
  const spec = converterParameterContract(schema);
  if (!converterRecord(value) || Object.keys(value).length > (spec?.max || 0)) throw new Error("自定义模板参数须为 JSON 对象，且不能超过目录声明的项数");
  if (!spec) return value; // Older catalogs can still use empty v1 archives.
  const reserved = new Set([...spec.reserved, ...Object.keys(schema.booleans), ...Object.keys(schema.texts),
    ...Object.keys(schema.integers), "target", "config", "url", "path", "token", "upload", "groups", "ruleset", "profile_data",
    "constructor", "prototype", "__proto__"].map(key => key.toLowerCase()));
  const pattern = new RegExp("^(?:" + spec.key_pattern + ")$", "u");
  for (const [key, item] of Object.entries(value)) {
    converterCheckText(key, 64, false, false); // JS $ also matches before a final newline.
    if (!pattern.test(key) || reserved.has(key.toLowerCase())) throw new Error("自定义模板参数名无效或为保留字段；不能覆盖内建选项或底层控制项");
    converterCheckText(item, spec.value_bytes, true, false);
  }
  return value;
}
function converterParameters(text) {
  converterCheckText(text, converterSchema?.limits.content_bytes || 1024 * 1024);
  return converterValidateParameters(converterParseJSON(text.trim() || "{}"));
}
function converterParameterState() {
  try {return {value: converterParameters($("#converterParameters").value), error: ""};}
  catch (error) {return {value: null, error: error.message};}
}
function renderConverterParameters(state) {
  const control = $("#converterParameters"), status = $("#converterParametersState");
  control.setAttribute("aria-invalid", String(Boolean(state.error)));
  control.setCustomValidity?.(state.error);
  status.className = "validation " + (state.error ? "bad" : "idle");
  status.textContent = state.error ? state.error + "。草稿已保留；修正后才能生成链接、执行主转换或导出输入档案。"
    : !converterSchema?.parameters ? "后端尚未声明自定义模板参数能力；当前仅可使用空参数。"
    : Object.keys(state.value).length + " / " + converterSchema.parameters.max + " 项；只在主动生成链接、校验或执行主转换时随表单发送。";
}
function converterParameterBytes(parameters) {
  return Object.entries(parameters).reduce((sum, [key, value]) => sum + converterBytes(key) + converterBytes(value), 0);
}
// Optional directory: older backends and v1 input archives still use options.config.
function converterConfigPresetCatalog(schema) {
  if (!Object.hasOwn(schema, "config_presets")) return [];
  const catalog = schema.config_presets, names = new Set(), urls = new Set();
  if (!Array.isArray(catalog) || catalog.length > 16) throw new Error("远程配置预设目录格式无效");
  for (const group of catalog) {
    if (!converterExactKeys(group, ["name", "items"]) || !Array.isArray(group.items) || !group.items.length) throw new Error("远程配置预设分组无效");
    converterCheckText(group.name, 128, false, false);
    if (names.has(group.name)) throw new Error("远程配置预设分组重复");
    names.add(group.name);
    for (const item of group.items) {
      if (!converterExactKeys(item, ["name", "url"])) throw new Error("远程配置预设条目无效");
      converterCheckText(item.name, 128, false, false); converterCheckText(item.url, 16384, false, false);
      let url;
      try {url = new URL(item.url);} catch {throw new Error("远程配置预设 URL 无效");}
      if (!/^https?:\/\//.test(item.url) || !["http:", "https:"].includes(url.protocol) || !url.hostname
          || url.username || url.password || url.hash || /[\\\s|]/u.test(item.url) || /%(?![0-9a-fA-F]{2})/.test(item.url)
          || urls.has(item.url) || urls.size >= 128) throw new Error("远程配置预设 URL 无效或重复");
      urls.add(item.url);
    }
  }
  return catalog;
}
function syncConverterConfigPreset() {
  const value = $("#converterConfig").value;
  const matched = converterSchema?.config_presets?.some(group => group.items.some(item => item.url === value));
  $("#converterConfigPreset").value = matched ? value : "";
}
function renderConverterConfigPresets(catalog) {
  const control = $("#converterConfigPreset"), custom = document.createElement("option");
  custom.value = ""; custom.textContent = "自定义 / 手工输入"; control.replaceChildren(custom);
  for (const group of catalog) {
    const optgroup = document.createElement("optgroup"); optgroup.setAttribute("label", group.name);
    for (const item of group.items) {
      const option = document.createElement("option"); option.value = item.url; option.textContent = item.name; optgroup.append(option);
    }
    control.append(optgroup);
  }
  $("#converterConfigPresetHint").textContent = catalog.length
    ? "只填入下方 URL 草稿，不下载模板、不执行转换或应用；选择自定义保留当前 URL，可继续手工修改。"
    : "当前后端未提供模板目录；仍可在下方手工填写 URL，不会自动访问。";
  syncConverterConfigPreset();
}
function converterForm(includeParameters = true) {
  const options = {target: $("#converterTarget").value};
  if ($("#converterConfig").value) options.config = $("#converterConfig").value;
  for (const [key, {control, type}] of converterOptionFields) {
    if (control.value === "") continue;
    if (key === "ver" && options.target !== "surge") continue;
    options[key] = type === "boolean" ? control.value === "true" : type === "integer" ? Number(control.value) : control.value;
  }
  const form = {profile: $("#converterProfile").value, backend: $("#converterBackend").value,
    sources: $("#converterSources").value, options};
  if (includeParameters) {
    const parameters = converterParameters($("#converterParameters").value);
    if (Object.keys(parameters).length) form.parameters = parameters;
  }
  return form;
}
function converterDraftSignature() {
  // Preserve incomplete JSON exactly. Dirty/control events must never parse it
  // without catching errors, or a typing mistake could break the global lock.
  return JSON.stringify([converterForm(false), $("#converterParameters").value]);
}
function converterDirty() {
  return Boolean(converterSchema && (converterDraftSignature() !== converterBaseline || $("#converterImport").value
    || converterHasLocal() || JSON.stringify(converterToolDrafts()) !== converterToolsBaseline
    || [...converterToolExports].some(([tool, result]) => converterToolElement(tool, "result").value !== result.content) || (converterExport && $("#converterText").value !== converterExport.content)));
}
function updateConverterControls() {
  const ready = Boolean(converterSchema) && !operationBusy;
  const parameterState = converterParameterState(), parametersValid = !parameterState.error;
  renderConverterParameters(parameterState);
  $("#converterTargetHint").hidden = $("#converterTarget").value !== "mellow";
  $("#converterParameters").disabled = !ready || !converterSchema.parameters;
  $("#converterConfigPreset").disabled = !ready || !converterSchema.config_presets?.length;
  for (const id of ["converterProfile", "converterTarget", "converterSources", "converterBackend", "converterConfig", "converterImport", "clearConverter", "converterUpload", "converterConfigUpload", "converterPaste", "converterConfigContent"]) $("#" + id).disabled = !ready;
  for (const [key, {control}] of converterOptionFields) control.disabled = !ready || (key === "ver" && $("#converterTarget").value !== "surge");
  for (const id of ["generateConverter", "validateConverter"]) $("#" + id).disabled = !ready || !parametersValid || !$("#converterSources").value.trim() || converterHasLocal();
  $("#parseConverter").disabled = !ready || !$("#converterImport").value.trim();
  $("#copyConverter").disabled = !ready || !converterResult;
  $("#installConverter").disabled = !ready || !converterResult || !["clash", "clashr"].includes(converterResultTarget);
  $("#loadConverter").disabled = operationBusy || Boolean(converterSchema);
  $("#executeConverter").disabled = !ready || converterSchema.execution?.bridge_available !== true
    || !parametersValid || $("#converterTarget").value === "auto" || !converterHasSources();
  $("#clearConverterFiles").disabled = !ready || !converterUploads.length;
  $("#converterText").disabled = !ready || !converterExport;
  for (const id of ["copyConverterText", "downloadConverter"]) $("#" + id).disabled = !ready || !converterExport || !$("#converterText").value;
  $("#restoreConverterText").disabled = !ready || !converterExport || $("#converterText").value === converterExport.content;
  for (const id of ["converterFilterScript", "converterSortScript", "converterFilterScriptUpload", "converterSortScriptUpload", "converterArchiveUpload", "exportConverterArchive"]) $("#" + id).disabled = !ready;
  $("#exportConverterArchive").disabled = !ready || !parametersValid;
  $("#converterResourceUpload").disabled = !ready || converterSchema.execution?.virtual_resources !== true;
  for (const button of $("#converterResources").querySelectorAll("button")) button.disabled = !ready;
  $("#clearConverterResources").disabled = !ready || !converterResources.length;
  for (const tool of Object.keys(CONVERTER_TOOLS)) {
    const result = converterToolExports.get(tool), text = converterToolElement(tool, "result").value;
    for (const part of ["content", "urls", "upload", "clear"]) converterToolElement(tool, part).disabled = !ready;
    converterToolElement(tool, "run").disabled = !ready || converterSchema.execution?.bridge_available !== true
      || !converterSchema.execution?.tools?.includes(tool)
      || !(converterToolElement(tool, "content").value.trim() || converterToolElement(tool, "urls").value.trim());
    converterToolElement(tool, "result").disabled = !ready || !result;
    for (const part of ["copy", "download"]) converterToolElement(tool, part).disabled = !ready || !result || !text;
    converterToolElement(tool, "restore").disabled = !ready || !result || text === result.content;
  }
  for (const part of ["type", "input-format", "group"]) converterToolElement("ruleset", part).disabled = !ready;
  converterToolElement("template", "variables").disabled = !ready;
}
function invalidateConverter() {
  converterSelectedProfile = $("#converterProfile").value;
  converterResult = ""; converterResultTarget = ""; $("#converterOutput").value = "";
  $("#converterState").className = "validation idle";
  if (converterExport) {converterExport.current = false; renderConverterExport();}
  $("#converterState").textContent = "输入已调整，旧结果已失效；请重新转换或生成链接。编辑草稿会保留。";
  updateConverterControls(); updateDraftNotice();
}
function setConverterForm(form) {
  const parameters = converterValidateParameters(Object.hasOwn(form, "parameters") ? form.parameters : {});
  $("#converterParameters").value = JSON.stringify(parameters, null, 2);
  $("#converterProfile").value = form.profile || "manual";
  $("#converterTarget").value = form.options.target || "clash";
  $("#converterBackend").value = form.backend || converterSchema.backend;
  $("#converterConfig").value = form.options.config || "";
  syncConverterConfigPreset();
  $("#converterSources").value = Array.isArray(form.sources) ? form.sources.join("\n") : form.sources || "";
  for (const [key, {control}] of converterOptionFields) control.value = Object.prototype.hasOwnProperty.call(form.options, key) ? String(form.options[key]) : "";
  invalidateConverter();
}
function converterField(key, labelText, type, spec) {
  const wrapper = document.createElement("div"), label = document.createElement("label");
  const control = document.createElement(type === "boolean" ? "select" : "input");
  control.setAttribute("id", "converter-option-" + key);
  label.setAttribute("for", control.id); label.textContent = labelText;
  if (type === "boolean") {
    for (const [value, title] of [["", "继承后端"], ["true", "true · 开启"], ["false", "false · 关闭"]]) {
      const option = document.createElement("option"); option.value = value; option.textContent = title; control.append(option);
    }
  } else {
    control.type = type === "integer" ? "number" : "text";
    control.setAttribute("autocomplete", "off"); control.setAttribute("spellcheck", "false");
    if (type === "integer") {control.setAttribute("min", String(spec.min)); control.setAttribute("max", String(spec.max)); control.setAttribute("step", "1");}
    else control.setAttribute("maxlength", String(spec.max));
  }
  control.addEventListener(type === "boolean" ? "change" : "input", () => {
    $("#converterProfile").value = "manual"; invalidateConverter();
  });
  wrapper.append(label, control);
  return {wrapper, control, type};
}
async function loadConverter() {
  if (converterSchema) return;
  const data = await api("/api/converter/options");
  if (data.ok !== true || !Array.isArray(data.presets) || typeof data.backend !== "string"
      || !data.clients || !data.booleans || !data.texts || !data.integers
      || !["sources", "source_bytes", "link_bytes", "content_bytes", "uploads"].every(key => Number.isSafeInteger(data.limits?.[key]) && data.limits[key] > 0)
      || !data.presets.some(item => item.id === "router_a" && item.options?.target)) throw new Error("转换参数目录格式无效");
  // Control updates call includes(); malformed capability lists must fail before
  // publishing the catalog, not throw while the global operation lock unwinds.
  if (data.execution?.tools != null && !Array.isArray(data.execution.tools)) throw new Error("转换工具目录格式无效");
  converterParameterContract(data);
  const configPresets = converterConfigPresetCatalog(data);
  for (const profile of data.presets) converterValidateParameters(Object.hasOwn(profile, "parameters") ? profile.parameters : {}, data);
  // Build every advanced field off-DOM. A late malformed spec must leave both
  // the visible form and ready state untouched, so the offered retry works.
  const fields = new Map();
  for (const [key, label] of Object.entries(data.booleans)) fields.set(key, converterField(key, label, "boolean", {}));
  for (const [key, spec] of Object.entries(data.texts)) fields.set(key, converterField(key, spec.label, "text", spec));
  for (const [key, spec] of Object.entries(data.integers)) fields.set(key, converterField(key, key === "ver" ? "Surge 版本" : "更新间隔（秒）", "integer", spec));
  converterSchema = data;
  converterOptionFields = fields;
  renderConverterConfigPresets(configPresets);
  for (const [key, label] of Object.entries(data.clients)) {
    const option = document.createElement("option"); option.value = key; option.textContent = label; $("#converterTarget").append(option);
  }
  for (const profile of data.presets) {
    const option = document.createElement("option"); option.value = profile.id; option.textContent = profile.name; $("#converterProfile").append(option);
  }
  $("#converterOptions").replaceChildren(...[...fields.values()].map(field => field.wrapper));
  const preset = data.presets.find(item => item.id === "router_a");
  setConverterForm({backend: data.backend, sources: "", options: preset.options, profile: preset.id, parameters: preset.parameters || {}});
  converterBaseline = converterDraftSignature();
  converterToolsBaseline = JSON.stringify(converterToolDrafts());
  for (const tool of Object.keys(CONVERTER_TOOLS)) renderConverterTool(tool);
  $("#converterState").textContent = "已加载 A 参数预设。上传内容请使用实际转换；仅生成链接不会访问源。";
  $("#converterExecutionHint").textContent = data.execution?.bridge_available === true
    ? "实际转换：先从公网 80/443 受控取源，再使用断网容器转换。自定义后端只影响生成的链接；配置不会自动写入路由器。"
    : "当前是预览或执行器未接通，实际转换不可用；不会用模拟结果冒充转换成功。";
  lockNewControls(); updateDraftNotice();
}
$("#loadConverter").addEventListener("click", () => runOperation("正在加载转换参数目录", async () => {
  $("#converterState").textContent = "正在加载参数与工具能力目录；不会访问任何输入源。";
  try {await loadConverter();}
  catch (error) {
    $("#converterState").className = "validation bad";
    $("#converterState").textContent = "目录加载失败，转换尚未执行；请重试加载选项。";
    throw error;
  }
}));
$("#converterProfile").addEventListener("change", () => {
  const profile = converterSchema?.presets.find(item => item.id === $("#converterProfile").value);
  if (profile) {
    if (!window.confirm("使用此子网预设替换高级选项与自定义模板参数？源链接、上传内容和自定义配置文本保持不变，不会修改路由器。")) {
      $("#converterProfile").value = converterSelectedProfile; return;
    }
    setConverterForm({backend: $("#converterBackend").value, sources: $("#converterSources").value, options: profile.options, profile: profile.id, parameters: profile.parameters || {}});
  } else invalidateConverter();
});
$("#converterConfigPreset").addEventListener("change", () => {
  const control = $("#converterConfigPreset");
  if (!converterSchema || operationBusy || control.disabled) {syncConverterConfigPreset(); return;}
  const selected = converterSchema.config_presets?.flatMap(group => group.items).find(item => item.url === control.value);
  if (control.value && !selected) {syncConverterConfigPreset(); return;}
  // "Custom" only changes the editing mode; never erase a user's existing URL.
  if (selected) $("#converterConfig").value = selected.url;
  $("#converterProfile").value = "manual";
  invalidateConverter();
});
for (const id of ["converterSources", "converterBackend", "converterConfig", "converterTarget", "converterParameters"]) {
  $("#" + id).addEventListener(id === "converterTarget" ? "change" : "input", () => {
    if (id !== "converterSources") $("#converterProfile").value = "manual";
    if (id === "converterConfig") syncConverterConfigPreset();
    invalidateConverter();
  });
}
$("#converterImport").addEventListener("input", () => {updateConverterControls(); updateDraftNotice();});
async function converterSubmit(action) {
  invalidateConverter();
  $("#converterState").textContent = action === "link" ? "正在生成链接；尚未访问源或写入路由器。" : "正在校验参数；尚未访问源或写入路由器。";
  try {
    if (converterHasLocal()) throw new Error("已添加本地内容，不能生成会遗漏这些内容的链接；请使用实际转换或先移除本地内容。");
    const draft = converterMainDraft(), form = draft.form;
    converterMainBudget(draft, converterResources, true);
    const payload = converterRequestBudget({form});
    const result = await nonceRequest("/api/converter/" + action, payload);
    if (!result.summary || result.summary.network_executed !== false || result.summary.router_changed !== false) throw new Error("转换结果缺少操作范围证据");
    if (action === "link") {
      if (typeof result.link !== "string" || result.link.length > converterSchema.limits.link_bytes) throw new Error("生成链接格式无效");
      // Do not render as HTML, auto-navigate or auto-copy credential-bearing URLs.
      const url = new URL(result.link);
      if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.pathname !== "/sub" || url.hash
          || url.origin !== new URL(form.backend).origin || url.searchParams.get("target") !== form.options.target) throw new Error("生成链接格式无效");
      for (const [key, value] of Object.entries(form.parameters || {})) {
        if (url.searchParams.getAll(key).length !== 1 || url.searchParams.get(key) !== value) throw new Error("生成链接未完整保留自定义模板参数，未接受结果");
      }
      converterResult = result.link; converterResultTarget = form.options.target;
      $("#converterOutput").value = converterResult;
    }
    $("#converterState").className = "validation good";
    $("#converterState").textContent = `${action === "link" ? "链接已生成" : "参数校验通过"} · ${result.summary.source_count} 个源 · 未执行网络转换/路由器写入。`
      + (result.summary.warnings?.length ? " 警告：已开启跳过证书验证或后端额外源选项，请检查。" : "");
    notice("转换参数已处理。链接含源凭据，请勿公开；这不是实际转换或部署验收。");
  } catch (error) {
    $("#converterState").className = "validation bad";
    $("#converterState").textContent = "链接生成或参数校验未成功，旧链接已失效；未自动重试或写入路由器。";
    throw error;
  }
}
$("#converterForm").addEventListener("submit", (event) => {event.preventDefault(); return runOperation("正在生成转换链接（不访问源）", () => converterSubmit("link"));});
$("#validateConverter").addEventListener("click", () => runOperation("正在校验转换参数", () => converterSubmit("validate")));
$("#parseConverter").addEventListener("click", () => runOperation("正在解析转换链接（不访问链接）", async () => {
  if (!confirmDiscard("converter")) return;
  const result = await nonceRequest("/api/converter/parse", {link: $("#converterImport").value});
  if (!result.form || !Array.isArray(result.form.sources) || !result.form.options) throw new Error("解析结果格式无效");
  // Validate optional parameters before clearing any existing local drafts.
  converterValidateParameters(Object.hasOwn(result.form, "parameters") ? result.form.parameters : {});
  resetConverterLocal(); setConverterForm(result.form); $("#converterImport").value = "";
  $("#converterState").textContent = "链接已解析到表单；可继续修改。未访问源或修改任何路由器。";
}));
$("#clearConverter").addEventListener("click", () => {
  if (operationBusy || !window.confirm("清空本页全部源、上传内容、配置文本、解析输入及结果（包括编辑草稿）？")) return;
  resetConverterLocal(); resetConverterWorkspace(); converterExport = null; $("#converterText").value = ""; renderConverterExport();
  setConverterForm({backend: converterSchema.backend, sources: "", options: {target: "clash"}, profile: "manual"});
  $("#converterImport").value = ""; converterBaseline = converterDraftSignature(); updateConverterControls(); updateDraftNotice();
  $("#converterState").textContent = "本页敏感字段已清空。剪贴板及已导入客户端的内容不会被自动清除。";
});
$("#copyConverter").addEventListener("click", () => {
  if (operationBusy || !converterResult) return;
  return converterCopyText($("#converterOutput"), "正在复制转换链接", converterSchema.limits.link_bytes);
});
$("#installConverter").addEventListener("click", () => {
  if (operationBusy || !converterResult || !["clash", "clashr"].includes(converterResultTarget)) return;
  if (window.confirm("唤起本机 Clash 客户端并将链接交给它？客户端会联系所选后端，可能改变本机代理配置。")) {
    window.location.href = "clash://install-config?url=" + encodeURIComponent(converterResult);
  }
});

function converterHasLocal() {
  return Boolean(converterUploads.length || converterResources.length || $("#converterPaste").value || $("#converterConfigContent").value
    || $("#converterFilterScript").value || $("#converterSortScript").value);
}
function converterHasSources() {
  return Boolean($("#converterSources").value.trim() || converterUploads.length || $("#converterPaste").value.trim());
}
function renderConverterFiles() {
  const box = $("#converterFiles"); box.replaceChildren();
  if (!converterUploads.length) {box.textContent = "尚未选择文件"; return;}
  for (const file of converterUploads) {
    const line = document.createElement("p"); line.textContent = `${file.name} · ${file.bytes} 字节`; box.append(line);
  }
}
function resetConverterLocal() {
  converterUploads = [];
  for (const id of ["converterUpload", "converterConfigUpload", "converterPaste", "converterConfigContent", "converterFilterScript", "converterSortScript", "converterFilterScriptUpload", "converterSortScriptUpload"]) $("#" + id).value = "";
  renderConverterFiles();
}
function converterPayload() {
  const input = converterMainDraft();
  converterMainBudget(input, converterResources, true);
  if (input.config_content && input.form.options.config) throw new Error("远程配置 URL 与配置文本不能同时填写");
  if (input.scripts.sort && input.form.options.sort === false) throw new Error("排序脚本与显式 sort=false 冲突；请将排序改为开启或继承后端，或清空脚本");
  const uploads = input.uploads.map(file => file.content);
  if (input.paste) uploads.push(input.paste);
  return converterRequestBudget({form: input.form, uploads, config_content: input.config_content,
    resources: converterResources.map(({name, content}) => ({name, content})), scripts: input.scripts});
}
async function readConverterFiles(input, config = false) {
  try {
    const files = Array.from(input.files || []);
    if (!files.length) return;
    if (files.length + (config ? 0 : converterUploads.length) > (config ? 1 : converterSchema.limits.uploads)) throw new Error("文件数量超限");
    const draft = converterMainDraft();
    const other = converterMainLocalBytes(draft) - (config ? converterBytes(draft.config_content) : 0);
    converterFilePreflight(files, converterSchema.limits.content_bytes,
      other + converterResourceBytes(converterResources));
    if (config && draft.config_content && !window.confirm("用所选文件替换当前外部配置文本？")) return;
    const accepted = [];
    for (const file of files) accepted.push({name: String(file.name).slice(0, 200), content: await converterReadFile(file)});
    if (config) draft.config_content = accepted[0].content;
    else draft.uploads.push(...accepted);
    converterMainBudget(draft, converterResources);
    if (config) $("#converterConfigContent").value = draft.config_content;
    else converterUploads = draft.uploads.map(file => ({...file, bytes: converterBytes(file.content)}));
    renderConverterFiles(); invalidateConverter();
    $("#converterState").textContent = "文件已读入本页内存，尚未发送；点击实际转换才会处理。";
  } finally {input.value = "";}
}
$("#converterUpload").addEventListener("change", () => runOperation("正在本页读取订阅文件（不发送）", () => readConverterFiles($("#converterUpload"))));
$("#converterConfigUpload").addEventListener("change", () => runOperation("正在本页读取外部配置文件（不发送）", () => readConverterFiles($("#converterConfigUpload"), true)));
$("#clearConverterFiles").addEventListener("click", () => {
  if (operationBusy || !converterUploads.length || !window.confirm("移除本页已选订阅文件？不会删除磁盘文件。")) return;
  converterUploads = []; renderConverterFiles(); invalidateConverter();
});
for (const id of ["converterPaste", "converterConfigContent"]) $("#" + id).addEventListener("input", invalidateConverter);

function renderConverterExport() {
  const state = $("#converterExportState");
  if (!converterExport) {state.className = "validation idle"; state.textContent = "尚未执行转换。"; return;}
  const edited = $("#converterText").value !== converterExport.content;
  state.className = "validation " + (edited || !converterExport.current ? "idle" : "good");
  state.textContent = `${converterExport.target} · ${converterBytes($("#converterText").value)} 字节 · 未写入路由器。 `
    + (!converterExport.current ? "输入已变化，旧结果仅作为草稿保留。 " : "")
    + (edited ? "已手动修改，尚未重新校验；原始摘要不再代表当前内容。" : `原始结果 SHA-256：${converterExport.sha256}`);
}
function converterExecutionValid(result, target) {
  const expected = ["ok", "content", "sha256", "bytes", "target", "elapsed_ms", "engine", "isolated", "network", "router_changed", "cleanup_confirmed", "summary"];
  if (!result || typeof result !== "object" || Array.isArray(result)) return false;
  const summary = result.summary;
  return Object.keys(result).length === expected.length && expected.every(key => Object.hasOwn(result, key))
    && result.ok === true && result.target === target && result.engine === converterSchema.execution.engine
    && result.isolated === true && result.network === "none" && result.router_changed === false && result.cleanup_confirmed === true
    && typeof result.content === "string" && !result.content.includes("\0") && result.content.length > 0
    && Number.isInteger(result.bytes) && result.bytes === converterBytes(result.content) && result.bytes <= converterSchema.limits.content_bytes
    && digestValid(result.sha256) && Number.isInteger(result.elapsed_ms) && result.elapsed_ms >= 0 && result.elapsed_ms <= 60000
    && summary && summary.router_changed === false && summary.link_backend_used === false && typeof summary.network_executed === "boolean"
    && Number.isInteger(summary.source_count) && summary.source_count > 0 && summary.source_count <= converterSchema.limits.sources
    && Number.isInteger(summary.asset_count) && summary.asset_count >= 0 && summary.asset_count <= 64;
}
$("#executeConverter").addEventListener("click", () => runOperation("正在取源并执行隔离转换（不会写入路由器）", async () => {
  if (converterSchema.execution?.bridge_available !== true) throw new Error("当前没有真实隔离执行器");
  const payload = converterPayload();
  if (converterExport && $("#converterText").value !== converterExport.content && !window.confirm("重新转换将替换已编辑的结果草稿，是否继续？")) return;
  invalidateConverter();
  $("#converterState").textContent = "正在取源并隔离转换，请等待；已有结果仅作旧草稿保留。";
  try {
    const result = await nonceRequest("/api/converter/execute", payload);
    if (!converterExecutionValid(result, payload.form.options.target)) throw new Error("转换响应缺少有效内容或隔离/清理证据，未接受结果");
    converterExport = {target: result.target, content: result.content, sha256: result.sha256, current: true};
    $("#converterText").value = result.content; renderConverterExport();
    $("#converterState").className = "validation good";
    $("#converterState").textContent = `转换完成 · ${result.summary.source_count} 个源 · ${result.summary.asset_count} 个依赖 · 原生执行 ${result.elapsed_ms} ms · 容器清理已确认 · 未写入路由器。`;
    notice("实际转换完成。导出前请检查内容；子网主配置与链式设置没有变化。");
  } catch (error) {
    $("#converterState").className = "validation bad";
    $("#converterState").textContent = "转换未成功，未自动重试或写入路由器；已有内容仅保留为旧草稿。";
    throw error;
  }
}));
$("#converterText").addEventListener("input", () => {renderConverterExport(); updateConverterControls(); updateDraftNotice();});
$("#restoreConverterText").addEventListener("click", () => {
  if (operationBusy || !converterExport || !window.confirm("放弃手动修改并恢复本次生成内容？")) return;
  $("#converterText").value = converterExport.content; renderConverterExport(); updateConverterControls(); updateDraftNotice();
});
$("#copyConverterText").addEventListener("click", () => {
  if (operationBusy || !converterExport || !$("#converterText").value) return;
  return converterCopyText($("#converterText"), "正在复制所选转换内容");
});
function converterFilename() {
  const extensions = {clash: "yaml", clashr: "yaml", singbox: "json", sssub: "json"};
  // Never honor a path, hidden file or active HTML extension from a parameter.
  const title = String(converterForm(false).options.filename || "subscription").replace(/\.[^.]*$/, "").replace(/[^a-zA-Z0-9_\u3400-\u9fff-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 72) || "subscription";
  return title + "." + (extensions[converterExport.target] || "txt");
}
$("#downloadConverter").addEventListener("click", () => {
  if (operationBusy || !converterExport || !$("#converterText").value) return;
  const text = $("#converterText").value;
  if (converterBytes(text) > converterSchema.limits.content_bytes || text.includes("\0")) {notice("导出内容超过 1 MiB 或含 NUL 字符", true); return;}
  if ((!converterExport.current || text !== converterExport.content) && !window.confirm("下载的是旧参数结果或未经重新校验的编辑草稿，不是已验证的路由器配置。继续下载？")) return;
  converterDownload(text, converterFilename());
  notice("已发起下载。文件可能含凭据，请妥善保存；没有写入路由器。");
});

// Shared, request-local intake. These checks do not replace server validation.
function converterCheckText(value, maximum, empty = true, multiline = true) {
  if (typeof value !== "string" || value.includes("\0") || /[\ud800-\udfff]/u.test(value)
      || (!empty && !value.trim()) || (!multiline && /[\x00-\x1f\x7f-\x9f]/u.test(value))) throw new Error("输入必须为有效文本，不能含禁用控制字符或为空");
  const bytes = converterBytes(value);
  if (bytes > maximum) throw new Error("输入文本超过字节限制，请减少内容");
  return bytes;
}
function converterSourceLines(text) {
  converterCheckText(text, converterSchema.limits.link_bytes);
  return text.replace(/\r\n/g, "\n").split(/[\n|]/).map(line => line.trim()).filter(Boolean);
}
function converterMainDraft() {
  return {form: converterForm(), uploads: converterUploads.map(({name, content}) => ({name, content})),
    paste: $("#converterPaste").value, config_content: $("#converterConfigContent").value,
    scripts: {filter: $("#converterFilterScript").value, sort: $("#converterSortScript").value}};
}
function converterMainLocalBytes(draft) {
  return draft.uploads.reduce((sum, file) => sum + converterBytes(file.content), 0)
    + converterBytes(draft.paste) + converterBytes(draft.config_content)
    + converterBytes(draft.scripts.filter) + converterBytes(draft.scripts.sort)
    + converterParameterBytes(converterValidateParameters(draft.form.parameters || {}));
}
function converterResourceName(name) {
  return typeof name === "string" && /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/.test(name) && !name.includes("..");
}
function converterResourceBytes(resources) {
  if (!Array.isArray(resources) || resources.length > CONVERTER_MAX_FILES) throw new Error("资源文件最多 64 个");
  const names = new Set();
  return resources.reduce((sum, file) => {
    if (!converterExactKeys(file, ["name", "content"]) || !converterResourceName(file.name) || names.has(file.name)) throw new Error("资源名重复或不合法；请在本机重命名后重选：字母/数字开头，最多 64 位，仅字母、数字、_、-、.，不含 ..");
    names.add(file.name);
    return sum + converterCheckText(file.content, converterSchema.limits.content_bytes, false);
  }, 0);
}
function converterMainBudget(draft, resources, required = false) {
  const maximum = converterSchema.limits.content_bytes;
  const sources = converterSourceLines(draft.form.sources);
  if (draft.uploads.length + (draft.paste ? 1 : 0) > converterSchema.limits.uploads
      || sources.length + draft.uploads.length + (draft.paste ? 1 : 0) > converterSchema.limits.sources) throw new Error("链接、上传与粘贴合计最多 32 个源");
  if (required && !sources.length && !draft.uploads.length && !draft.paste.trim()) throw new Error("请填写源链接或订阅内容");
  let total = converterResourceBytes(resources) + converterParameterBytes(converterValidateParameters(draft.form.parameters || {}));
  for (const file of draft.uploads) total += converterCheckText(file.content, maximum, false);
  total += converterCheckText(draft.paste, maximum) + converterCheckText(draft.config_content, maximum);
  for (const text of Object.values(draft.scripts)) total += converterCheckText(text, CONVERTER_SCRIPT_BYTES);
  for (const source of sources) {
    converterCheckText(source, converterSchema.limits.source_bytes, false, false);
    if (!/^https?:\/\//.test(source)) total += converterBytes(source);
  }
  const fileCount = sources.length + draft.uploads.length + (draft.paste ? 1 : 0) + resources.length
    + (draft.config_content || draft.form.options.config ? 1 : 0) + Object.values(draft.scripts).filter(Boolean).length;
  if (fileCount > CONVERTER_MAX_FILES) throw new Error("源、资源、配置和脚本合计最多 64 个文件；远程展开另由后端检查");
  if (total > maximum) throw new Error("本次转换的本地输入与资源合计超过 1 MiB（含自定义参数、脚本与节点链接）");
}
function converterRequestBudget(payload) {
  // Reserve room for the single-use nonce, including after a bootstrap renewal.
  if (converterBytes(JSON.stringify(payload)) > CONVERTER_REQUEST_BYTES - 4096) throw new Error("JSON 请求体接近 2 MiB 上限（转义字符也占空间），请减少输入");
  return payload;
}
function converterFilePreflight(files, maximum, existing = 0) {
  if (files.some(file => !Number.isSafeInteger(file.size) || file.size <= 0 || file.size > maximum)
      || files.reduce((sum, file) => sum + file.size, existing) > maximum) throw new Error("文件为空或本地输入合计超过大小限制");
}
async function converterReadFile(file, maximum = converterSchema.limits.content_bytes) {
  converterFilePreflight([file], maximum);
  let text;
  try {text = new TextDecoder("utf-8", {fatal: true}).decode(await file.arrayBuffer());}
  catch {throw new Error("文件读取失败或不是有效 UTF-8 文本");}
  converterCheckText(text, maximum, false);
  return text;
}
function converterDownload(text, filename, type = "text/plain;charset=utf-8") {
  const url = URL.createObjectURL(new Blob([text], {type}));
  try {
    const anchor = document.createElement("a");
    anchor.setAttribute("href", url); anchor.setAttribute("download", filename); anchor.setAttribute("rel", "noopener");
    $("#converter").append(anchor); anchor.click(); anchor.remove();
  } finally {setTimeout(() => URL.revokeObjectURL(url), 1000);}
}
async function converterCopyText(control, label, maximum = converterSchema.limits.content_bytes) {
  const copied = await runOperation(label, async () => {
    converterCheckText(control.value, maximum, false);
    try {await navigator.clipboard.writeText(control.value); notice("内容已复制；剪贴板可能含凭据，请勿公开。"); return true;}
    catch {return false;}
  });
  // A disabled textarea cannot be focused/selected in a real browser. Keep the
  // lock through clipboard settlement, then offer manual copy after unlock.
  if (copied === false) {control.focus(); control.select(); notice("浏览器未允许复制，已选中内容，请手动复制。");}
}

function renderConverterResources() {
  const box = $("#converterResources"); box.replaceChildren();
  if (!converterResources.length) {box.textContent = "尚未添加资源。主转换与下方工具共用此列表。"; return;}
  for (const file of converterResources) {
    const row = document.createElement("div"), title = document.createElement("span"), button = document.createElement("button");
    row.className = "converter-resource-row";
    title.textContent = `asset:${file.name} · ${converterBytes(file.content)} 字节`;
    button.type = "button"; button.className = "ghost"; button.textContent = "移除";
    button.setAttribute("aria-label", "移除资源 " + file.name);
    button.addEventListener("click", () => {
      if (operationBusy || !window.confirm("移除此共享资源？引用它的主转换与工具需重新检查，不会删除磁盘文件。")) return;
      converterResources = converterResources.filter(item => item !== file);
      renderConverterResources(); invalidateConverterResources();
    });
    row.append(title, button); box.append(row);
  }
  lockNewControls();
}
function invalidateConverterResources() {
  invalidateConverter();
  for (const tool of Object.keys(CONVERTER_TOOLS)) invalidateConverterTool(tool);
}
function converterWorkspaceBudget(resources) {
  converterMainBudget(converterMainDraft(), resources);
  for (const [tool, draft] of Object.entries(converterToolDrafts())) converterToolBudget(tool, draft, resources);
}
$("#converterResourceUpload").addEventListener("change", () => runOperation("正在本页读取共享资源（不发送）", async () => {
  const input = $("#converterResourceUpload");
  try {
    const files = Array.from(input.files || []);
    if (!files.length) return;
    if (files.length + converterResources.length > CONVERTER_MAX_FILES) throw new Error("资源文件最多 64 个");
    const names = new Set(converterResources.map(file => file.name));
    for (const file of files) {
      if (!converterResourceName(file.name) || names.has(file.name)) throw new Error("资源名无效或重复，请先在本机重命名；只接受字母/数字开头的 1–64 位字母、数字、_、-、.，不含 ..");
      names.add(file.name);
    }
    const existing = converterResourceBytes(converterResources);
    const drafts = converterToolDrafts();
    const largestInput = Math.max(converterMainLocalBytes(converterMainDraft()),
      ...Object.values(drafts).map(draft => converterBytes(draft.content) + converterBytes(draft.variables || "")));
    converterFilePreflight(files, converterSchema.limits.content_bytes, existing + largestInput);
    const accepted = [];
    for (const file of files) accepted.push({name: file.name, content: await converterReadFile(file)});
    const candidate = [...converterResources, ...accepted];
    converterWorkspaceBudget(candidate);
    converterResources = candidate; renderConverterResources(); invalidateConverterResources();
    notice("资源已读入本页内存；点击主转换或工具的执行按钮才发送。请在文本中使用 asset:文件名 引用。");
  } finally {input.value = "";}
}));
$("#clearConverterResources").addEventListener("click", () => {
  if (operationBusy || !converterResources.length || !window.confirm("移除全部共享资源？各工具中的引用文本会保留，不会删除磁盘文件。")) return;
  converterResources = []; renderConverterResources(); invalidateConverterResources();
});
for (const [key, id] of [["filter", "converterFilterScript"], ["sort", "converterSortScript"]]) {
  $("#" + id).addEventListener("input", invalidateConverter);
  $("#" + id + "Upload").addEventListener("change", () => runOperation("正在本页读取脚本文本（不会执行）", async () => {
    const input = $("#" + id + "Upload");
    try {
      const files = Array.from(input.files || []);
      if (!files.length) return;
      if (files.length !== 1) throw new Error("每次只选择一个脚本文件");
      const draft = converterMainDraft();
      const other = converterMainLocalBytes(draft) - converterBytes(draft.scripts[key]) + converterResourceBytes(converterResources);
      converterFilePreflight(files, CONVERTER_SCRIPT_BYTES);
      converterFilePreflight(files, converterSchema.limits.content_bytes, other);
      if (draft.scripts[key] && !window.confirm("用文件替换当前脚本草稿？只读入文本，不会在浏览器执行。")) return;
      draft.scripts[key] = await converterReadFile(files[0], CONVERTER_SCRIPT_BYTES);
      converterMainBudget(draft, converterResources);
      $("#" + id).value = draft.scripts[key]; invalidateConverter();
      notice("脚本文本已读入本页内存，尚未发送或执行。");
    } finally {input.value = "";}
  }));
}

// Three independent tool drafts/results, one shared page-wide operation lock.
function converterToolElement(tool, part) {return $("#converter-" + tool + "-" + part);}
function converterToolDraft(tool) {
  const draft = {content: converterToolElement(tool, "content").value, urls: converterToolElement(tool, "urls").value};
  if (tool === "ruleset") {
    draft.type = Number(converterToolElement(tool, "type").value);
    draft.input_format = converterToolElement(tool, "input-format").value;
    draft.group = converterToolElement(tool, "group").value;
  } else if (tool === "template") draft.variables = converterToolElement(tool, "variables").value;
  return draft;
}
function converterToolDrafts() {return Object.fromEntries(Object.keys(CONVERTER_TOOLS).map(tool => [tool, converterToolDraft(tool)]));}
function converterToolDefaults(tool) {
  return {content: "", urls: "", ...(tool === "ruleset" ? {type: 1, input_format: "surge", group: "Proxy"} : tool === "template" ? {variables: "{}"} : {})};
}
function setConverterToolDraft(tool, draft) {
  for (const [key, value] of Object.entries(draft)) converterToolElement(tool, key === "input_format" ? "input-format" : key).value = String(value);
}
function converterSafeHTTP(text, backend = false) {
  converterCheckText(text, converterSchema.limits.source_bytes, false, false);
  let url;
  try {url = new URL(text);}
  catch {throw new Error("URL 格式无效");}
  if (!/^https?:\/\//.test(text) || !["http:", "https:"].includes(url.protocol) || !url.hostname || url.username || url.password || url.hash
      || /[\\\s|]/u.test(text) || /%(?![0-9a-fA-F]{2})/.test(text)
      || (backend && (!["", "/", "/sub"].includes(url.pathname) || url.search))) throw new Error("仅支持不含嵌入认证/片段的 HTTP(S) URL；后端须为 /sub 且无查询参数");
  return text;
}
function converterToolBudget(tool, draft, resources, required = false) {
  const urls = converterSourceLines(draft.urls);
  for (const url of urls) converterSafeHTTP(url);
  const count = urls.length + (draft.content ? 1 : 0);
  if (count > converterSchema.limits.sources || (required && (count < 1 || (tool !== "ruleset" && count !== 1)))) throw new Error(tool === "ruleset" ? "规则集请输入 1–32 个源；粘贴文本算一个源" : "模板与 Surge 工具只能有一个源：文本/文件或一个远程 URL，二选一");
  const bytes = converterCheckText(draft.content, converterSchema.limits.content_bytes)
    + converterResourceBytes(resources) + converterCheckText(draft.variables || "", 256 * 1024);
  if (bytes > converterSchema.limits.content_bytes) throw new Error("本工具文本、变量与共享资源合计超过 1 MiB");
  if (count + resources.length > CONVERTER_MAX_FILES) throw new Error("本工具源与资源合计最多 64 个文件；依赖展开另由后端校验");
  if (required && draft.content && !draft.content.trim()) throw new Error("工具内容不能仅包含空白");
  return urls;
}
function converterVariables(text) {
  converterCheckText(text, 256 * 1024);
  const variables = converterParseJSON(text.trim() || "{}");
  if (!converterRecord(variables) || Object.keys(variables).length > 32) throw new Error("模板变量须为最多 32 项的 JSON 对象，值只能是字符串");
  for (const [key, value] of Object.entries(variables)) {
    converterCheckText(key, 64, false, false);
    if (!/^[a-zA-Z][a-zA-Z0-9_.-]{0,63}$/.test(key) || ["path", "__proto__", "prototype", "constructor"].includes(key.toLowerCase())) throw new Error("模板变量名无效或为保留名称");
    converterCheckText(value, 4096, true, false);
  }
  return variables;
}
function converterToolOptions(tool, draft) {
  if (tool === "template") return {variables: converterVariables(draft.variables)};
  if (tool === "surge2clash") return {};
  if (!Number.isInteger(draft.type) || draft.type < 1 || draft.type > 6
      || !["surge", "quanx", "clash-domain", "clash-ipcidr", "clash-classic"].includes(draft.input_format)) throw new Error("规则类型或输入格式无效");
  converterCheckText(draft.group, 128, false, false);
  if (/[,|`]/.test(draft.group)) throw new Error("规则分组不能包含逗号、竖线或反引号");
  return {type: draft.type, input_format: draft.input_format, group: draft.group};
}
function converterToolPayload(tool) {
  const draft = converterToolDraft(tool);
  const urls = converterToolBudget(tool, draft, converterResources, true);
  return converterRequestBudget({operation: tool, content: draft.content, urls, options: converterToolOptions(tool, draft),
    resources: converterResources.map(({name, content}) => ({name, content}))});
}
function renderConverterTool(tool, status) {
  const state = converterToolElement(tool, "state"), result = converterToolExports.get(tool);
  state.className = "validation idle";
  if (status) {state.textContent = status; return;}
  if (!result) {
    state.textContent = !converterSchema ? "请先加载转换选项。" : converterSchema.execution?.bridge_available !== true ? "当前执行器不可用，可编辑本机草稿；不会模拟成功。"
      : !converterSchema.execution?.tools?.includes(tool) ? "后端尚未声明支持此工具，执行不可用。" : "尚未执行。文本/文件只在本页暂存，点击执行才取源并转换。";
    return;
  }
  const text = converterToolElement(tool, "result").value, edited = text !== result.content;
  state.className = "validation " + (result.current && !edited ? "good" : "idle");
  state.textContent = `${CONVERTER_TOOLS[tool].label} · ${converterBytes(text)} 字节 · 隔离环境清理已确认 · 未写入路由器。 `
    + (!result.current ? "输入或资源已变化，旧结果仅作草稿保留。 " : "")
    + (edited ? "已手动修改，未经重新校验，原摘要不代表当前内容。" : `原始结果 SHA-256：${result.sha256}`);
}
function invalidateConverterTool(tool) {
  const result = converterToolExports.get(tool);
  if (result) result.current = false;
  renderConverterTool(tool); updateConverterControls(); updateDraftNotice();
}
async function executeConverterTool(tool) {
  if (converterSchema.execution?.bridge_available !== true || !converterSchema.execution?.tools?.includes(tool)) throw new Error("当前工具或隔离执行器不可用");
  const payload = converterToolPayload(tool), previous = converterToolExports.get(tool);
  if (previous && converterToolElement(tool, "result").value !== previous.content && !window.confirm("重新执行会替换此工具的已编辑结果，是否继续？")) return;
  if (previous) previous.current = false;
  renderConverterTool(tool, "正在取源并隔离处理，请等待；旧草稿保留到新结果验证成功。");
  try {
    const result = await nonceRequest("/api/converter/tool", payload);
    if (!converterExecutionValid(result, tool) || result.summary.operation !== tool) throw new Error("工具响应缺少有效内容、操作类型或隔离/清理证据，未接受结果");
    converterToolExports.set(tool, {content: result.content, sha256: result.sha256, current: true,
      extension: tool === "ruleset" && [3, 4, 6].includes(payload.options.type) ? "yaml" : CONVERTER_TOOLS[tool].extension});
    converterToolElement(tool, "result").value = result.content; renderConverterTool(tool);
    notice("工具执行完成，未写入路由器。请检查结果；复制或下载必须由你明确点击。");
  } catch (error) {
    converterToolElement(tool, "state").className = "validation bad";
    converterToolElement(tool, "state").textContent = "工具执行未成功，未自动重试或写入路由器；已有结果仅保留为旧草稿。";
    throw error;
  }
}
for (const tool of Object.keys(CONVERTER_TOOLS)) {
  for (const part of ["content", "urls", ...(tool === "ruleset" ? ["type", "input-format", "group"] : tool === "template" ? ["variables"] : [])]) {
    converterToolElement(tool, part).addEventListener(["type", "input-format"].includes(part) ? "change" : "input", () => invalidateConverterTool(tool));
  }
  converterToolElement(tool, "run").addEventListener("click", () => runOperation("正在执行" + CONVERTER_TOOLS[tool].label + "（不会写入路由器）", () => executeConverterTool(tool)));
  converterToolElement(tool, "upload").addEventListener("change", () => runOperation("正在本页读取工具输入（不发送）", async () => {
    const input = converterToolElement(tool, "upload");
    try {
      const files = Array.from(input.files || []);
      if (!files.length) return;
      if (files.length !== 1) throw new Error("每次只选择一个工具输入文件；多个规则文件可添加到文本或使用多行 URL");
      const draft = converterToolDraft(tool);
      converterFilePreflight(files, converterSchema.limits.content_bytes, converterResourceBytes(converterResources) + converterBytes(draft.variables || ""));
      if (draft.content && !window.confirm("用所选文件替换此工具的当前文本草稿？远程 URL 不会清除。")) return;
      draft.content = await converterReadFile(files[0]); converterToolBudget(tool, draft, converterResources);
      converterToolElement(tool, "content").value = draft.content; invalidateConverterTool(tool);
      notice("文件已读入工具文本，尚未发送。模板/Surge 的文本与远程 URL 只能选择其一。");
    } finally {input.value = "";}
  }));
  converterToolElement(tool, "clear").addEventListener("click", () => {
    if (operationBusy || !window.confirm("清空此工具的输入、参数与结果草稿？共享资源及其他工具保持不变。")) return;
    setConverterToolDraft(tool, converterToolDefaults(tool)); converterToolElement(tool, "upload").value = "";
    converterToolExports.delete(tool); converterToolElement(tool, "result").value = "";
    renderConverterTool(tool); updateConverterControls(); updateDraftNotice();
  });
  converterToolElement(tool, "result").addEventListener("input", () => {renderConverterTool(tool); updateConverterControls(); updateDraftNotice();});
  converterToolElement(tool, "restore").addEventListener("click", () => {
    const result = converterToolExports.get(tool);
    if (operationBusy || !result || !window.confirm("放弃此工具结果的手动编辑，恢复原始生成内容？失效状态不会因此恢复。")) return;
    converterToolElement(tool, "result").value = result.content; renderConverterTool(tool); updateConverterControls(); updateDraftNotice();
  });
  converterToolElement(tool, "copy").addEventListener("click", () => {
    if (operationBusy || !converterToolExports.has(tool) || !converterToolElement(tool, "result").value) return;
    return converterCopyText(converterToolElement(tool, "result"), "正在复制所选工具内容");
  });
  converterToolElement(tool, "download").addEventListener("click", () => {
    const result = converterToolExports.get(tool), text = converterToolElement(tool, "result").value;
    if (operationBusy || !result || !text) return;
    try {
      converterCheckText(text, converterSchema.limits.content_bytes, false);
      if ((!result.current || text !== result.content) && !window.confirm("下载的是旧参数结果或未经重新校验的编辑草稿，不是已验证的路由器配置。继续？")) return;
      converterDownload(text, tool + "." + result.extension);
      notice("已发起工具结果下载，文件可能含凭据，请妥善保存；未写入路由器。");
    } catch (error) {notice(error.message, true);}
  });
}

// Versioned input-only local archives. No result claims or router state are imported.
function converterRecord(value) {return value !== null && typeof value === "object" && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));}
function converterExactKeys(value, keys) {return converterRecord(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));}
function converterParseJSON(text) {
  try {
    const value = JSON.parse(text, (key, item) => {
      if (["__proto__", "prototype", "constructor"].includes(key)) throw new Error("reserved");
      return item;
    });
    // JSON.parse has already checked syntax. Tokenize strings atomically so
    // repeated keys (including escaped spellings) cannot silently win last.
    const stack = [];
    for (const match of text.matchAll(/"(?:[^"\\]|\\.)*"|[{}\[\]:,]/g)) {
      const token = match[0], frame = stack.at(-1);
      if (token === "{" || token === "[") {
        if (stack.length >= 16) throw new Error("depth");
        stack.push(token === "{" ? {keys: new Set(), key: true} : null);
      } else if (token === "}" || token === "]") stack.pop();
      else if (token === "," && frame) frame.key = true;
      else if (token.startsWith('"') && frame?.key) {
        const key = JSON.parse(token);
        if (frame.keys.has(key)) throw new Error("duplicate");
        frame.keys.add(key); frame.key = false;
      }
    }
    return value;
  } catch {throw new Error("JSON 无效、过深、含重复键或保留属性名；不会应用任何内容");}
}
function converterValidateForm(form) {
  if (!(converterExactKeys(form, ["profile", "backend", "sources", "options"])
        || converterExactKeys(form, ["profile", "backend", "sources", "options", "parameters"])) || !converterRecord(form.options)) throw new Error("档案 form 形状无效");
  converterValidateParameters(Object.hasOwn(form, "parameters") ? form.parameters : {});
  if (!["manual", ...converterSchema.presets.map(item => item.id)].includes(form.profile)) throw new Error("档案预设无效");
  converterSafeHTTP(form.backend, true);
  const sources = converterSourceLines(form.sources);
  if (sources.length > converterSchema.limits.sources) throw new Error("档案源数量超限");
  for (const source of sources) converterCheckText(source, converterSchema.limits.source_bytes, false, false);
  if (!Object.hasOwn(form.options, "target") || typeof form.options.target !== "string" || !Object.hasOwn(converterSchema.clients, form.options.target)) throw new Error("档案目标客户端无效");
  for (const [key, value] of Object.entries(form.options)) {
    if (key === "target") continue;
    if (key === "config") {if (value !== "") converterSafeHTTP(value);}
    else if (Object.hasOwn(converterSchema.booleans, key)) {if (typeof value !== "boolean") throw new Error("档案布尔参数无效");}
    else if (Object.hasOwn(converterSchema.texts, key)) {
      converterCheckText(value, converterSchema.texts[key].max, true, false);
      if ((key === "rename" && /(?:^|\|)\s*(?:script|!!script):/i.test(value))
          || (key === "filename" && (/[\/\\:*?"<>|]/.test(value) || [".", ".."].includes(value)))) throw new Error("档案文本参数无效");
    } else if (Object.hasOwn(converterSchema.integers, key)) {
      const range = converterSchema.integers[key];
      if (!Number.isInteger(value) || value < range.min || value > range.max || (key === "ver" && form.options.target !== "surge")) throw new Error("档案整数参数无效");
    } else throw new Error("档案包含未知转换参数");
  }
}
function converterArchive() {
  return {format: "openclash-sync-converter", version: 1, ...converterMainDraft(), resources: converterResources.map(({name, content}) => ({name, content})),
    import_link: $("#converterImport").value, tools: converterToolDrafts()};
}
function converterValidateArchive(data) {
  if (!converterExactKeys(data, ["format", "version", "form", "uploads", "paste", "config_content", "scripts", "resources", "import_link", "tools"])
      || data.format !== "openclash-sync-converter" || data.version !== 1) throw new Error("档案格式、版本或顶层字段不受支持（仅接受 version=1）");
  converterValidateForm(data.form);
  if (!Array.isArray(data.uploads) || data.uploads.length > converterSchema.limits.uploads || !converterExactKeys(data.scripts, ["filter", "sort"])) throw new Error("档案上传或脚本形状无效");
  for (const file of data.uploads) {
    if (!converterExactKeys(file, ["name", "content"])) throw new Error("档案上传项形状无效");
    converterCheckText(file.name, 800, false, false);
    if (file.name.length > 200) throw new Error("档案文件名过长");
  }
  converterCheckText(data.import_link, converterSchema.limits.link_bytes, true, false);
  if (!converterExactKeys(data.tools, Object.keys(CONVERTER_TOOLS))) throw new Error("档案工具集合无效");
  converterMainBudget(data, data.resources);
  for (const tool of Object.keys(CONVERTER_TOOLS)) {
    const draft = data.tools[tool];
    if (!converterExactKeys(draft, Object.keys(converterToolDefaults(tool)))) throw new Error("档案工具字段形状无效");
    converterToolOptions(tool, draft); converterToolBudget(tool, draft, data.resources);
  }
  // Retain incomplete drafts, but never execute them as part of import/export.
  return data;
}
function resetConverterWorkspace() {
  converterResources = []; renderConverterResources(); converterToolExports.clear();
  for (const tool of Object.keys(CONVERTER_TOOLS)) {
    setConverterToolDraft(tool, converterToolDefaults(tool));
    for (const part of ["upload", "result"]) converterToolElement(tool, part).value = "";
    renderConverterTool(tool);
  }
  converterToolsBaseline = JSON.stringify(converterToolDrafts());
  $("#converterArchiveUpload").value = "";
  $("#converterArchiveState").className = "validation idle";
  $("#converterArchiveState").textContent = "输入档案未导入。导出为未加密 JSON，不含生成结果或路由器状态。";
}
function applyConverterArchive(data) {
  resetConverterLocal(); resetConverterWorkspace();
  converterUploads = data.uploads.map(file => ({name: file.name, content: file.content, bytes: converterBytes(file.content)}));
  converterResources = data.resources.map(({name, content}) => ({name, content}));
  $("#converterPaste").value = data.paste; $("#converterConfigContent").value = data.config_content;
  $("#converterFilterScript").value = data.scripts.filter; $("#converterSortScript").value = data.scripts.sort;
  $("#converterImport").value = data.import_link;
  for (const tool of Object.keys(CONVERTER_TOOLS)) setConverterToolDraft(tool, data.tools[tool]);
  converterExport = null; $("#converterText").value = ""; renderConverterExport();
  renderConverterFiles(); renderConverterResources(); setConverterForm(data.form);
  $("#converterState").textContent = "本机输入档案已恢复；结果已清除，未取源、未执行脚本、未写入路由器。";
}
$("#exportConverterArchive").addEventListener("click", () => runOperation("正在准备本机输入档案（不发送）", async () => {
  const text = JSON.stringify(converterValidateArchive(converterArchive()), null, 2);
  converterCheckText(text, CONVERTER_ARCHIVE_BYTES, false);
  if (!window.confirm("导出未加密的本机 JSON 档案？它包含源链接、上传文本、资源、配置、脚本、自定义参数与模板变量，可能包含密码或 token。请只保存在可信本机位置，不要公开；不包含生成结果。")) return;
  converterDownload(text, "subscription-converter-profile-v1.json", "application/json;charset=utf-8");
  $("#converterArchiveState").className = "validation good";
  $("#converterArchiveState").textContent = "已发起未加密档案下载（浏览器是否保存请自行确认）。未发送任何输入；结果编辑需单独下载。";
}));
$("#converterArchiveUpload").addEventListener("change", () => runOperation("正在校验本机输入档案（不发送）", async () => {
  const input = $("#converterArchiveUpload");
  try {
    const files = Array.from(input.files || []);
    if (!files.length) return;
    if (files.length !== 1) throw new Error("每次只导入一个 JSON 档案");
    const text = await converterReadFile(files[0], CONVERTER_ARCHIVE_BYTES);
    const data = converterValidateArchive(converterParseJSON(text));
    if (!window.confirm("档案已通过版本、形状和本地预算检查，但内容并未经安全审计。应用它会替换本页主转换、工具、共享资源及脚本，并清空所有结果草稿；档案可能含凭据。继续？")) return;
    applyConverterArchive(data);
    $("#converterArchiveState").className = "validation good";
    $("#converterArchiveState").textContent = "输入档案已导入本页内存；尚未发送、取源或执行。需要主动点击转换/工具按钮才会处理。";
  } catch (error) {
    $("#converterArchiveState").className = "validation bad";
    $("#converterArchiveState").textContent = "档案未应用；当前输入与结果草稿保持不变。请检查 JSON 版本、字段、文本及大小限制。";
    throw error;
  } finally {input.value = "";}
}));
