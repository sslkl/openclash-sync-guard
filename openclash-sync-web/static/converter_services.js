"use strict";
// Explicit third-party operations are separate from conversion/router mutation.
(() => {
  const mount = $("#converterServicesMount");
  if (!mount) return;
  const actions = new Map([["shorten", "生成短链（外发完整订阅链接）"], ["expand", "展开短链（只读重定向）"],
    ["gist_list", "列出我的 Gist"], ["gist_get", "读取指定 Gist 文件"], ["gist_create", "创建 Gist"],
    ["gist_update", "更新指定 Gist 文件"], ["gist_delete", "删除整个指定 Gist"]]);
  const mutations = new Set(["shorten", "gist_create", "gist_update", "gist_delete"]);
  const controls = new Map(), wrappers = new Map();
  let outputText = "", outputAction = "", outputCurrent = false;
  function el(tag, text = "", id = "") {
    const node = document.createElement(tag); if (text) node.textContent = text;
    if (id) node.setAttribute("id", id); return node;
  }
  const panel = el("details", "", "converterServicesWorkspace");
  panel.append(el("summary", "外部服务 · 短链与 Gist（每次单独确认）"));
  const help = el("p", "不会自动取源、上传或加载路由器配置。短链供应商会收到完整链接（可能包含订阅凭据）；Gist 即使设为非公开，持有链接的人仍可能访问。token 仅用于当次请求并在请求结束后清空，不写入输入档案。供应商写入超时可能已生效，不会自动重试。"); help.className = "help"; panel.append(help);
  const grid = el("div"); grid.className = "converter-grid";
  function field(key, label, type = "text", initial = "") {
    const box = el("div"), id = "converterService-" + key;
    const caption = el("label", label); caption.setAttribute("for", id);
    const node = el(type === "textarea" ? "textarea" : type === "select" ? "select" : "input", "", id);
    if (!["textarea", "select"].includes(type)) node.type = type;
    node.setAttribute("autocomplete", "off"); node.setAttribute("spellcheck", "false"); node.value = initial;
    if (type === "textarea") {node.setAttribute("rows", "5"); box.className = "converter-wide";}
    if (type === "number") {node.setAttribute("min", "1"); node.setAttribute("max", "100"); node.setAttribute("step", "1");}
    box.append(caption, node); grid.append(box); controls.set(key, node); wrappers.set(key, box); return node;
  }
  const action = field("action", "操作", "select");
  for (const [value, text] of actions) {const option = el("option", text); option.value = value; action.append(option);}
  action.value = "shorten";
  field("link", "订阅链接或短链（不会自动访问）", "textarea");
  field("api", "短链 API（HTTPS / 443；longUrl multipart 协议）", "text", "https://suo.yt/short");
  field("token", "当次 Gist token（只向 api.github.com 发送）", "password");
  field("page", "Gist 列表页码（每页最多 30 项）", "number", "1");
  field("id", "Gist ID（20–40 位小写十六进制）");
  field("filename", "Gist 文件名（无目录）", "text", "config.ini");
  field("description", "Gist 描述（最多 256 UTF-8 字节）");
  field("content", "本次外发的文件内容（请逐字检查）", "textarea");
  field("public", "创建为公开 Gist（默认关闭；非公开不等于私密）", "checkbox");
  field("confirm", "我确认本次第三方读取／外发的目标与内容", "checkbox");
  field("http", "我了解当前 HTTP 管理入口会明文传输 token；只在可信受控网络继续", "checkbox");
  panel.append(grid);
  const buttons = el("div"); buttons.className = "converter-actions";
  function button(id, text, callback) {
    const node = el("button", text, "converterService-" + id); node.type = "button"; node.className = "ghost";
    node.addEventListener("click", callback); buttons.append(node); return node;
  }
  const useLink = button("useLink", "填入已生成的订阅链接", () => {
    if (operationBusy || !converterResult || (get("link") && !window.confirm("替换外部服务面板中的链接草稿？尚不外发。"))) return;
    controls.get("link").value = converterResult; changed();
  });
  const useConfig = button("useConfig", "填入当前外部配置文本", () => copyInput($("#converterConfigContent").value));
  const useResult = button("useResult", "填入当前转换结果", () => copyInput($("#converterText").value));
  const send = button("send", "确认并执行所选外部操作…", () => runOperation("正在执行已确认的外部服务操作（不改路由器）", perform));
  send.className = "primary";
  button("clear", "清空本面板敏感内容", () => {
    if (operationBusy || !window.confirm("清空本面板的 token、链接、内容及结果？不会撤销供应商已完成的写入或清除剪贴板。")) return;
    reset(); updateConverterControls(); updateDraftNotice();
  });
  panel.append(buttons);
  const state = el("p", "尚未执行外部请求。", "converterService-state"); state.className = "validation idle";
  state.setAttribute("role", "status"); state.setAttribute("aria-live", "polite"); panel.append(state);
  const meta = el("pre", "", "converterService-meta"); meta.className = "converter-service-meta"; panel.append(meta);
  const resultLabel = el("label", "返回链接或指定文件内容（仅本页内存）"); resultLabel.setAttribute("for", "converterService-result");
  const result = el("textarea", "", "converterService-result"); result.setAttribute("rows", "6"); result.readOnly = true; result.setAttribute("autocomplete", "off"); result.setAttribute("spellcheck", "false");
  panel.append(resultLabel, result);
  const copy = button("copy", "复制返回文本", () => converterCopyText(result, "正在显式复制外部服务结果"));
  const importConfig = button("importConfig", "将已读文件填入外部配置文本", () => {
    if (operationBusy || !outputCurrent || outputAction !== "gist_get" || !outputText || !window.confirm("用刚读取的 Gist 文件替换主转换的外部配置文本，并清空外部配置 URL？尚不执行转换。")) return;
    $("#converterConfigContent").value = outputText; $("#converterConfig").value = "";
    syncConverterConfigPreset(); invalidateConverter();
    setState("已填入本页外部配置文本；未执行、取源或写入路由器。", "good");
  });
  mount.append(panel);
  const get = key => controls.get(key).value;
  const isGist = () => action.value.startsWith("gist_");
  const secure = () => window.location && window.location.protocol === "https:";
  function setState(text, kind = "idle") {state.textContent = text; state.className = "validation " + kind;}
  function copyInput(value) {
    if (operationBusy || !value || (get("content") && !window.confirm("替换本次外发内容草稿？尚不外发。"))) return;
    controls.get("content").value = value; changed();
  }
  function visibleKeys() {
    const specific = {shorten:["link","api"], expand:["link"], gist_list:["token","page"], gist_get:["token","id","filename"],
      gist_create:["token","filename","content","description","public"], gist_update:["token","id","filename","content"], gist_delete:["token","id"]};
    return new Set(["action", "confirm", ...specific[action.value], ...(isGist() && !secure() ? ["http"] : [])]);
  }
  function update() {
    const visible = visibleKeys(), ready = Boolean(converterSchema) && !operationBusy;
    for (const [key, control] of controls) {wrappers.get(key).hidden = !visible.has(key); control.disabled = !ready || !visible.has(key);}
    send.disabled = !ready || !controls.get("confirm").checked || (isGist() && !secure() && !controls.get("http").checked);
    useLink.disabled = !ready || !converterResult; useConfig.disabled = !ready || !$("#converterConfigContent").value;
    useResult.disabled = !ready || !$("#converterText").value;
    copy.disabled = !ready || !result.value; result.disabled = !ready || !result.value;
    importConfig.disabled = !ready || !outputCurrent || outputAction !== "gist_get" || !outputText;
    lockNewControls();
  }
  function changed(event) {
    if (!event || ![controls.get("confirm"), controls.get("http")].includes(event.target)) {
      controls.get("confirm").checked = false; controls.get("http").checked = false;
      outputCurrent = false;
      setState("输入已调整，请检查后重新确认；旧结果仅作参考，未自动请求。", "idle");
    }
    updateConverterControls(); updateDraftNotice();
  }
  for (const control of controls.values()) {control.addEventListener("input", changed); control.addEventListener("change", changed);}
  function draft() {return [...controls].some(([key, c]) => ["token","link","content","id","description"].includes(key) && Boolean(c.value));}
  function reset() {
    for (const key of ["token","link","content","id","description"]) controls.get(key).value = "";
    for (const key of ["confirm","http","public"]) controls.get(key).checked = false;
    outputText = outputAction = ""; outputCurrent = false; result.value = ""; meta.textContent = "";
    setState("本面板敏感内容已清空；未撤销第三方写入或清除剪贴板。");
  }
  function payload() {
    const data = {action: action.value, confirm_external: controls.get("confirm").checked};
    if (!data.confirm_external || (isGist() && !secure() && !controls.get("http").checked)) throw new Error("需要明确确认外部访问与传输风险，尚未发送。");
    for (const key of visibleKeys()) {
      if (["action","confirm","http"].includes(key)) continue;
      data[key] = key === "public" ? controls.get(key).checked : key === "page" ? Number(get(key)) : get(key);
    }
    if (data.content) converterCheckText(data.content, 1024 * 1024, false);
    if (data.token && !/^[A-Za-z0-9_-]{16,512}$/.test(data.token)) throw new Error("token 格式不符；尚未发送。");
    if (data.id && !/^[0-9a-f]{20,40}$/.test(data.id)) throw new Error("Gist ID 格式不符；尚未发送。");
    return converterRequestBudget(data);
  }
  function gistDescription(gist) {
    if (!gist || typeof gist.id !== "string" || typeof gist.public !== "boolean"
        || !Array.isArray(gist.filenames) || gist.filenames.some(name => typeof name !== "string")) {
      throw new Error("Gist 元数据格式无效。");
    }
    return `${gist.id} · ${gist.public ? "公开" : "非公开"} · ${gist.filenames.join(", ")}`;
  }
  function checkedOutput(value, requested) {
    if (value.action !== requested || value.router_changed !== false) throw new Error("返回的操作证据不完整。");
    let text = "", link = "", description = "";
    if (requested === "gist_list") {
      if (!Array.isArray(value.items) || typeof value.has_next !== "boolean") throw new Error("Gist 列表格式无效。");
      description = value.items.map(gistDescription).join("\n")
        + (value.has_next ? "\n可能还有下一页，请手动调整页码。" : "\n本页已列完。");
    } else if (requested === "gist_delete") {
      if (value.deleted !== true) throw new Error("删除结果证据不完整。");
      description = "指定 Gist 已删除。";
    } else if (requested.startsWith("gist_")) {
      description = gistDescription(value.gist);
      if (requested === "gist_get") {
        if (typeof value.content !== "string") throw new Error("返回的文件内容格式无效。");
        text = value.content;
      }
    } else {
      if (typeof value.link !== "string" || !value.link) throw new Error("返回的链接格式无效。");
      link = value.link;
    }
    return {text, link, description};
  }
  async function perform() {
    let sent = false, requested;
    try {
      const data = payload(); requested = data.action;
      const prompt = data.action === "gist_delete" ? "删除整个 Gist " + data.id + " 及其中所有文件？这不是只删除一个文件，也不会自动恢复。"
        : mutations.has(data.action) ? "将当前明确选定的链接／文件内容外发至 " + (isGist() ? "GitHub Gist" : "所填短链供应商") + (data.public ? "，并公开发布" : "") + "？请确认没有不该外发的凭据。" : "确认联系外部服务读取所选内容？不会自动执行返回内容。";
      if (!window.confirm(prompt)) {setState("已取消，未发送请求。"); return;}
      if (!nonce && !await bootstrap(true, false)) throw new Error("未取得操作凭证，尚未发送。");
      sent = true; outputCurrent = false; setState("请求已发送，请勿重复操作；写入超时可能已生效。", "idle");
      const value = await nonceRequest("/api/converter/service", data);
      // Validate the complete display shape before replacing any previous result.
      const clean = checkedOutput(value, requested);
      outputAction = requested; outputText = clean.text;
      result.value = clean.link || clean.text; meta.textContent = clean.description;
      outputCurrent = true;
      setState("外部操作已返回成功结果；未自动加载、执行返回内容或修改路由器。", "good");
    } catch (error) {
      const uncertain = sent && (mutations.has(requested) || error.data?.code === "SERVICE_UNCERTAIN");
      setState(uncertain ? "第三方写入结果无法确认，可能已生效。请先查询供应商／Gist 状态，不要直接重试；路由器未改动。"
        : sent ? "第三方读取未完成或响应无效；旧结果保留作参考，未自动重试或修改路由器。" : "本次请求未发送。请检查必填内容、确认项、大小和连接状态。", "bad");
    } finally {
      if (sent) controls.get("token").value = "";
      controls.get("confirm").checked = false; controls.get("http").checked = false;
      updateConverterControls(); updateDraftNotice();
    }
  }
  const previousUpdate = updateConverterControls;
  updateConverterControls = function (...args) {const result = previousUpdate.apply(this, args); update(); return result;};
  const previousDirty = converterDirty;
  converterDirty = function (...args) {return previousDirty.apply(this, args) || draft();};
  const previousReset = resetConverterWorkspace;
  resetConverterWorkspace = function (...args) {const result = previousReset.apply(this, args); reset(); return result;};
  lockNewControls(); update();
})();
