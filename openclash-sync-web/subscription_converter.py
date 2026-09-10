"""Memory-only Subscription Converter request model.

This module builds/parses URLs; it NEVER fetches one or applies router state.
Keep network execution separate: a syntactically valid URL is not SSRF approval.
The credential-bearing values are intentionally excluded from repr and errors.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import re
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

MAX_LINK = 65536
MAX_SOURCE = 16384
MAX_SOURCES = 32
DEFAULT_BACKEND = "http://192.0.2.20:25500/sub"
CLIENTS = {
    "clash": "Clash / Mihomo", "clashr": "ClashR", "singbox": "sing-box", "quan": "Quantumult",
    "quanx": "Quantumult X", "loon": "Loon", "mellow": "Mellow", "ss": "SS / Shadowrocket",
    "sssub": "SS SIP008", "ssd": "SSD", "ssr": "SSR", "surfboard": "Surfboard",
    "surge": "Surge", "trojan": "Trojan", "v2ray": "V2Ray", "mixed": "Mixed", "auto": "自动识别",
}
# All documented non-executing conversion flags are editable, including explicit
# false vs omitted (inherit). Never conflate these three states in the UI.
BOOL_OPTIONS = {
    "emoji": "Emoji 综合开关", "add_emoji": "添加 Emoji", "remove_emoji": "移除原 Emoji",
    "append_type": "添加节点类型", "append_info": "附加流量信息", "tfo": "TCP Fast Open",
    "udp": "UDP", "list": "仅节点列表 / Provider", "sort": "按名称排序",
    "script": "输出 Clash Script", "insert": "插入后端配置的额外订阅",
    "scv": "跳过节点 TLS 证书校验（有风险）", "fdn": "过滤客户端不支持的节点",
    "prepend": "额外订阅前置", "expand": "展开规则", "new_name": "使用 Clash 新字段名", "strict": "Surge 强制更新",
    "classic": "Clash classical 规则", "tls13": "TLS 1.3",
    "surge.doh": "Surge DoH 模板参数", "clash.doh": "Clash DoH 模板参数",
}
TEXT_OPTIONS = {
    "include": ("Include 节点正则", 1024), "exclude": ("Exclude 节点正则", 1024),
    "rename": ("重命名：匹配@替换，多个用 | 分隔", 4096), "group": ("订阅组名", 128),
    "ua": ("订阅 User-Agent", 256), "dev_id": ("Quantumult X 设备 ID", 256), "filename": ("导出文件名", 128),
}
INT_OPTIONS = {"ver": (2, 5), "interval": (1, 31536000)}
BLOCKED_OPTIONS = frozenset({"token", "upload", "upload_path", "filter_script", "sort_script"})
NODE_SCHEMES = frozenset({"ss", "ssr", "vmess", "vless", "trojan", "hysteria", "hysteria2", "hy2", "tuic", "anytls", "socks", "socks5", "http", "https", "snell", "wireguard", "tg"})
MAX_PARAMETERS = 32
MAX_PARAMETER_BYTES = 4096
PARAMETER_KEY_PATTERN = r"[A-Za-z][A-Za-z0-9_.-]{0,63}"
# The pinned engine passes unknown query fields to templates. Keep this separate
# from options, and block all engine/file/service controls case-insensitively.
RESERVED_PARAMETERS = frozenset(BOOL_OPTIONS) | frozenset(TEXT_OPTIONS) | frozenset(INT_OPTIONS) | frozenset('''target config url path token upload upload_path groups ruleset profile_data
filter_script sort_script filter_script_file sort_script_file name dev_id
operation variables parameters input_format type policy_sources include_primary
version files source_names body backend sources profile resources scripts uploads
config_content upload download total expire constructor prototype __proto__
__defineGetter__ __defineSetter__ __lookupGetter__ __lookupSetter__'''.lower().split())
CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\ud800-\udfff]")
BAD_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")
DOMAIN = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\Z", re.I)
PRESET_OPTIONS = {
    "target": "clash", "new_name": True, "emoji": True, "udp": True, "tfo": False,
    "fdn": True, "list": False, "scv": False, "sort": False,
}

# Display-only directory copied from the captured sub-web frontend (three groups).
# Choosing a URL does not fetch it or override either subnet parameter preset.
REMOTE_CONFIG_PRESETS = (
    ("universal", (
        ("No-Urltest", "https://cdn.jsdelivr.net/gh/SleepyHeeead/subconverter-config@master/remote-config/universal/no-urltest.ini"),
        ("Urltest", "https://cdn.jsdelivr.net/gh/SleepyHeeead/subconverter-config@master/remote-config/universal/urltest.ini"),
    )),
    ("customized", (
        ("Maying", "https://cdn.jsdelivr.net/gh/SleepyHeeead/subconverter-config@master/remote-config/customized/maying.ini"),
        ("Ytoo", "https://cdn.jsdelivr.net/gh/SleepyHeeead/subconverter-config@master/remote-config/customized/ytoo.ini"),
        ("FlowerCloud", "https://cdn.jsdelivr.net/gh/SleepyHeeead/subconverter-config@master/remote-config/customized/flowercloud.ini"),
        ("Nexitally", "https://cdn.jsdelivr.net/gh/SleepyHeeead/subconverter-config@master/remote-config/customized/nexitally.ini"),
        ("SoCloud", "https://cdn.jsdelivr.net/gh/SleepyHeeead/subconverter-config@master/remote-config/customized/socloud.ini"),
        ("ARK", "https://cdn.jsdelivr.net/gh/SleepyHeeead/subconverter-config@master/remote-config/customized/ark.ini"),
        ("ssrCloud", "https://cdn.jsdelivr.net/gh/SleepyHeeead/subconverter-config@master/remote-config/customized/ssrcloud.ini"),
    )),
    ("Special", (
        ("NeteaseUnblock(仅规则，No-Urltest)", "https://cdn.jsdelivr.net/gh/SleepyHeeead/subconverter-config@master/remote-config/special/netease.ini"),
        ("Basic(仅GEOIP CN + Final)", "https://cdn.jsdelivr.net/gh/SleepyHeeead/subconverter-config@master/remote-config/special/basic.ini"),
    )),
)


class ConverterError(ValueError):
    """Only predefined codes/messages; never interpolate the rejected input."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


MESSAGES = {
    "SERVICE_CONFIRM": "请明确确认本次第三方读取或外发；没有自动发送",
    "SERVICE_AUTH": "Gist token 格式无效；只接受当次输入，不读取或保存既有凭据",
    "SERVICE_RESULT": "第三方服务未返回预期结果；未加载内容或修改路由器",
    "SERVICE_UNCERTAIN": "第三方写入结果无法确认，可能已完成。请先查询第三方记录，不要直接重试；路由器未改动",
    "REQUEST": "转换请求结构无效或包含未知字段",
    "FETCH_ADDRESS": "禁止访问私网、环回、保留地址、云元数据或混合 DNS 结果",
    "FETCH_DNS": "源域名解析失败或超过解析时限",
    "FETCH_PORT": "在线取源仅允许 HTTP(S) 的 80/443 端口；内网来源请上传内容",
    "FETCH_REDIRECT": "重定向无效、循环或次数超限",
    "FETCH_DOWNGRADE": "禁止 HTTPS 重定向降级至 HTTP",
    "FETCH_TIMEOUT": "取源超过总时间预算",
    "FETCH_CONNECT": "取源连接失败、超时或 TLS 校验失败",
    "FETCH_STATUS": "源服务未返回成功响应",
    "FETCH_ENCODING": "源服务返回不支持的压缩编码，请上传解压后的文本",
    "FETCH_PROTOCOL": "源服务的 HTTP 响应结构不完整或存在歧义",
    "FETCH_SIZE": "源内容或合并任务超过大小预算",
    "SANDBOX": "隔离转换失败或超时；没有写入任何路由器",
    "SANDBOX_UNAVAILABLE": "隔离转换执行器尚未安装或当前不可用",
    "CONVERTER_BUSY": "已有转换任务正在运行，请稍后重试",
    "CONTENT": "订阅内容应为 UTF-8 文本，且不能含 NUL 或超过大小限制",
    "MELLOW_SOURCE": "Mellow 无法保真转换此输入；仅接受受支持的 Clash 节点或 SS / JSON VMess 分享链接，拒绝 HTTP 伪装、插件及其他丢失语义的字段",
    "RESULT": "转换器未返回有效结果",
    "CONFIG_FORMAT": "外部配置结构无效；支持 INI [custom]、YAML custom 与 TOML version=1",
    "SCRIPT_SORT": "填写排序脚本后需启用 sort 排序选项，或清空排序脚本",
    "SURGE_FORMAT": "Surge 配置含无效或无法无损转换的策略组、规则或引用；未返回缺项配置",
    "SURGE_POLICY_PATH": "当前策略来源的节点归属无法确认；请先展开 policy-path 节点后再转换",
    "TOML_UNAVAILABLE": "TOML 配置解析需要 Python 3.11 或更高版本",
    "CONFIG_CONFLICT": "远程配置 URL 和粘贴配置不能同时指定",
    "DEPENDENCIES": "模板依赖循环、过深、含本地路径或尚未展开的动态资源；请提供完整资源包",
    "EXECUTION_TARGET": "导出文件请指定目标客户端；auto 仅用于客户端订阅链接",
    "SANDBOX_CLEANUP": "转换已停止，但隔离环境清理未获确认；未写入路由器，请检查执行器",


    "TEXT": "参数应为有效文本，且不能含控制字符或超出长度限制",
    "BACKEND": "后端须为 HTTP(S) 的 /sub 地址，不能含认证、查询参数或片段",
    "URL": "URL 格式不受支持；禁止本地文件路径、控制字符和嵌入认证",
    "SOURCES": "请提供 1–32 条订阅或节点链接，每行一条或用 | 分隔",
    "SOURCE": "源格式不受支持；请使用 HTTP(S) 订阅或受支持的节点分享链接",
    "TARGET": "目标客户端无效，Surge 版本必须为 2–5",
    "OPTION": "转换参数无效；布尔选项必须为 true、false 或省略",
    "PARAMETERS": "自定义参数须为最多 32 项的 JSON 对象；参数名或值无效，或使用了保留字段",
    "UNSAFE_OPTION": "不允许透传后端 token、执行脚本、本地文件或 Gist 自动上传参数",
    "DUPLICATE": "转换链接包含重复参数；请消除歧义后重试",
    "ENCODING": "转换链接的百分号编码或 UTF-8 无效",
    "PROFILE": "子网预设无效；请选择 A、B 或手动模式",
    "LINK_SIZE": "生成的链接过长，请减少源或参数",
}


def failure(exc: ConverterError) -> dict:
    return {"ok": False, "code": exc.code, "message": MESSAGES.get(exc.code, MESSAGES["REQUEST"])}


def text(value: object, maximum: int, *, empty: bool = False) -> str:
    if not isinstance(value, str) or CONTROL.search(value) or (not value and not empty):
        raise ConverterError("TEXT")
    try:
        if len(value) > maximum or len(value.encode("utf-8")) > maximum:
            raise ConverterError("TEXT")
    except UnicodeError:
        raise ConverterError("TEXT") from None
    return value


def http_url(value: object, *, backend: bool = False) -> str:
    value = text(value, MAX_SOURCE)
    if any(char in value for char in ('\\', ' ', '|')) or BAD_PERCENT.search(value):
        raise ConverterError("URL")
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.fragment or parsed.port == 0 or parsed.netloc.endswith(":")):
            raise ValueError
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        try:
            ip = ipaddress.ip_address(host)
            host = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
            if "%" in host:
                raise ValueError
        except ValueError:
            # Bracketed authorities are IP literals, never DNS names. In
            # particular, do not reinterpret unsupported IPvFuture as a host.
            if parsed.netloc.startswith("[") or not DOMAIN.fullmatch(host):
                raise ValueError from None
        port = f":{parsed.port}" if parsed.port is not None else ""
        if backend and (parsed.path not in ("", "/", "/sub") or parsed.query):
            raise ValueError
        # HTTP request targets must be ASCII. Preserve delimiters and existing
        # percent escapes (including signed subscription query values), but
        # encode Unicode IRI path/query text once using UTF-8.
        path = "/sub" if backend else quote(parsed.path or "/", safe="/:@!$&'()*+,;=%")
        query = quote(parsed.query, safe="/?:@!$&'()*+,;=%")
        canonical = urlunsplit((parsed.scheme, host + port, path, query, ""))
        if len(canonical) > MAX_SOURCE:
            raise ValueError
        return canonical
    except (ValueError, UnicodeError):
        raise ConverterError("BACKEND" if backend else "URL") from None


def sources(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        if len(value) > MAX_LINK or len(value.encode("utf-8", errors="surrogatepass")) > MAX_LINK:
            raise ConverterError("LINK_SIZE")
        # LF/CRLF are separators, never trim embedded control characters.
        value = value.replace("\r\n", "\n").replace("\n", "|").split("|")
        value = [item.strip(" ") for item in value if item.strip(" ")]
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_SOURCES:
        raise ConverterError("SOURCES")
    result = []
    for item in value:
        item = text(item, MAX_SOURCE)
        if "|" in item or " " in item:
            raise ConverterError("SOURCE")
        try:
            scheme = urlsplit(item).scheme
        except ValueError:
            raise ConverterError("SOURCE") from None
        if scheme not in NODE_SCHEMES:
            raise ConverterError("SOURCE")
        if scheme in {"http", "https"}:
            item = http_url(item)
        elif not item.startswith(scheme + "://") or not item[len(scheme) + 3:]:
            raise ConverterError("SOURCE")
        if BAD_PERCENT.search(item):
            raise ConverterError("ENCODING")
        result.append(item)
    # Preserve order AND duplicates; silently dropping one could change semantics.
    if sum(len(item.encode()) for item in result) > MAX_LINK:
        raise ConverterError("LINK_SIZE")
    return tuple(result)


def options(value: object) -> dict:
    if not isinstance(value, dict) or len(value) > 48:
        raise ConverterError("OPTION")
    result = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ConverterError("OPTION")
        if key in BLOCKED_OPTIONS:
            raise ConverterError("UNSAFE_OPTION")
        if key in BOOL_OPTIONS:
            if type(item) is not bool:
                raise ConverterError("OPTION")
        elif key in TEXT_OPTIONS:
            item = text(item, TEXT_OPTIONS[key][1], empty=True)
            if key == "rename" and re.search(r"(?:^|\|)\s*(?:script|!!script):", item, re.I):
                raise ConverterError("UNSAFE_OPTION")
            if key == "filename" and (any(c in item for c in '/\\:*?"<>|') or item in {".", ".."}):
                raise ConverterError("OPTION")
        elif key in INT_OPTIONS:
            low, high = INT_OPTIONS[key]
            if type(item) is not int or not low <= item <= high:
                raise ConverterError("OPTION")
        elif key == "target":
            if not isinstance(item, str) or item not in CLIENTS:
                raise ConverterError("TARGET")
        elif key == "config":
            item = http_url(item) if item else text(item, MAX_SOURCE, empty=True)
        else:
            raise ConverterError("OPTION")
        result[key] = item
    if "target" not in result:
        result["target"] = "clash"
    if result["target"] == "surge" and "ver" not in result:
        result["ver"] = 4
    if "ver" in result and result["target"] != "surge":
        raise ConverterError("TARGET")
    return result


def parameters(value: object) -> dict:
    if not isinstance(value, dict) or len(value) > MAX_PARAMETERS:
        raise ConverterError("PARAMETERS")
    result = {}
    for key, item in value.items():
        if not isinstance(key, str) or not re.fullmatch(PARAMETER_KEY_PATTERN, key) or key.lower() in RESERVED_PARAMETERS:
            raise ConverterError("PARAMETERS")
        try:
            result[key] = text(item, MAX_PARAMETER_BYTES, empty=True)
        except ConverterError:
            raise ConverterError("PARAMETERS") from None
    return result


def parameter_bytes(values: dict) -> int:
    """Count validated template keys and values in the shared intake budget."""
    return sum(len(key.encode()) + len(value.encode()) for key, value in values.items())


@dataclass(frozen=True)
class ConversionRequest:
    backend: str = field(repr=False)
    sources: tuple[str, ...] = field(repr=False)
    options: dict = field(repr=False)
    profile: str = "manual"
    parameters: dict = field(default_factory=dict, repr=False)

    def public_form(self) -> dict:
        """Credential-bearing. Only an explicit authenticated parse may return it."""
        return {"backend": self.backend, "sources": list(self.sources),
                "options": dict(self.options), "profile": self.profile,
                **({"parameters": dict(self.parameters)} if self.parameters else {})}

    def link(self) -> str:
        params = {"target": self.options["target"], "url": "|".join(self.sources)}
        params.update({key: str(value).lower() if type(value) is bool else str(value)
                       for key, value in self.options.items() if key != "target"})
        params.update(parameters(self.parameters))
        result = self.backend + "?" + urlencode(params, encoding="utf-8", errors="strict")
        if len(result.encode()) > MAX_LINK:
            raise ConverterError("LINK_SIZE")
        return result

    def summary(self) -> dict:
        return {"source_count": len(self.sources), "target": self.options["target"],
                "profile": self.profile, "option_count": len(self.options),
                "parameter_count": len(self.parameters),
                "network_executed": False, "router_changed": False,
                "warnings": (["SCV_ENABLED"] if self.options.get("scv") else [])
                            + (["BACKEND_INSERT_ENABLED"] if self.options.get("insert") else [])}


def validate(value: object) -> ConversionRequest:
    if not isinstance(value, dict) or set(value) - {"backend", "sources", "options", "profile", "parameters"}:
        raise ConverterError("REQUEST")
    profile = value.get("profile", "manual")
    if not isinstance(profile, str) or profile not in {"manual", "router_a", "router_b"}:
        raise ConverterError("PROFILE")
    result = ConversionRequest(http_url(value.get("backend", DEFAULT_BACKEND), backend=True),
                               sources(value.get("sources")), options(value.get("options", {})), profile,
                               parameters(value.get("parameters", {})))
    result.link()  # Enforce the final encoded size, not only the unencoded input.
    return result


def parse_link(value: object) -> ConversionRequest:
    raw = text(value, MAX_LINK)
    if BAD_PERCENT.search(raw):
        raise ConverterError("ENCODING")
    try:
        parsed = urlsplit(raw)
        if parsed.fragment or parsed.path != "/sub":
            raise ConverterError("BACKEND")
        backend = http_url(urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", "")), backend=True)
        pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True,
                          max_num_fields=81, encoding="utf-8", errors="strict")
    except ConverterError:
        raise
    except (ValueError, UnicodeError):
        raise ConverterError("ENCODING") from None
    values = {}
    for key, item in pairs:
        if key in values:
            raise ConverterError("DUPLICATE")
        values[key] = item
    raw_sources = values.pop("url", None)
    custom = {}
    for key, item in list(values.items()):
        if key in BOOL_OPTIONS:
            if item not in {"true", "false"}:
                raise ConverterError("OPTION")
            values[key] = item == "true"
        elif key in INT_OPTIONS:
            if not re.fullmatch(r"[0-9]{1,8}", item):
                raise ConverterError("OPTION")
            values[key] = int(item)
        elif key not in TEXT_OPTIONS and key not in {"target", "config"}:
            custom[key] = values.pop(key)
    return validate({"backend": backend, "sources": raw_sources, "options": values, "parameters": custom})


def capabilities() -> dict:
    """Fresh copies: no request can mutate process-wide defaults."""
    return {"ok": True, "backend": DEFAULT_BACKEND, "clients": dict(CLIENTS),
            "booleans": dict(BOOL_OPTIONS), "texts": {k: {"label": v[0], "max": v[1]} for k, v in TEXT_OPTIONS.items()},
            "integers": {k: {"min": v[0], "max": v[1]} for k, v in INT_OPTIONS.items()},
            "presets": [{"id": key, "name": label, "options": dict(PRESET_OPTIONS)} for key, label in
                        (("router_a", "路由器 A · 保持现有转换参数"), ("router_b", "路由器 B · 保持现有转换参数"))],
            "config_presets": [{"name": group, "items": [{"name": name, "url": url} for name, url in items]}
                               for group, items in REMOTE_CONFIG_PRESETS],
            "parameters": {"max": MAX_PARAMETERS, "value_bytes": MAX_PARAMETER_BYTES,
                           "key_pattern": PARAMETER_KEY_PATTERN, "reserved": sorted(RESERVED_PARAMETERS)},
            "limits": {"sources": MAX_SOURCES, "source_bytes": MAX_SOURCE, "link_bytes": MAX_LINK,
                       "content_bytes": 1024 * 1024, "uploads": 32, "files": 64, "script_bytes": 65536, "request_bytes": 2 * 1024 * 1024},
            "execution": {"engine": "subconverter-0.9.1-36573b3-isolated", "network": "none",
                          "source_network": "public-pinned", "config_formats": ["ini", "yaml", "toml"],
                          "tools": ["ruleset", "template", "surge2clash"], "virtual_resources": True,
                          "services": ["shorten", "expand", "gist_list", "gist_get", "gist_create", "gist_update", "gist_delete"], "short_api": "https://suo.yt/short", "router_apply_available": True, "production_defaults_shared": False},
            "network_executed": False, "router_changed": False}
