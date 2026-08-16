# OpenClash Sync Guard

[English](README.md) · [详细部署门禁](docs/DEPLOYMENT.zh-CN.md) · [安全策略](SECURITY.md)

这是一个强调“失败即停止（fail closed）”和“只生成候选、不自动启用”的 OpenClash 同步工具集。它可在独立 worker 上完成订阅转换与校验，在两台路由器上分别生成 Candidate，并可选提供中文管理台。

最重要的边界：`ROUTER_STAGE=PASS` 只证明 Candidate 已生成、哈希一致且通过本机 Mihomo 语法检查；它不代表活动配置已切换、真实流量正常或已获得生产启用授权。本项目故意不提供自动启用 Candidate 的流程。

## 核心能力

- worker 在内存中处理订阅，固定来源主机哈希，禁止重定向，限制输入/YAML 结构，并输出不含凭据的 receipt。
- Ruby builder 使用安全 YAML 加载和资源预算，闭合校验代理、策略组、规则、DNS 与运行时漂移。
- 两台路由器使用独立密钥、独立 stage 目录和独立 Candidate，推荐严格串行：A 完成复核后再处理 B。
- 可选中文 Web 管理台使用 Digest SHA-256、请求体/JSON 深度限制、root-owned helper 和 SSH forced command。
- TOML 渲染器只替换白名单占位值，输出目录已存在时拒绝覆盖，并生成 `FILES` 与 `SHA256SUMS`。

## 先做离线验证

运行位置：本机 Mac 或 Linux 开发机。以下操作不会连接路由器，不会修改 OpenClash。

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r openclash-sync-web/requirements.txt
./tools/run_offline_checks.sh
```

预期最后看到：

```text
OFFLINE_CHECKS=PASS
LIVE_CHANGES=false
```

## 生成你自己的部署副本

`config.example.toml` 使用 RFC 5737 文档地址，无法访问真实设备；其中 Mihomo core SHA-256 也是故意无效的占位符。

```sh
cp config.example.toml config.local.toml
# 编辑 config.local.toml，替换每个字段；不要提交该文件。
python3 tools/render_config.py config.local.toml --output build/rendered
```

Linux 校验：

```sh
(cd build/rendered && sha256sum -c SHA256SUMS)
```

macOS 校验：

```sh
(cd build/rendered && shasum -a 256 -c SHA256SUMS)
```

渲染器只生成文件，不会 SSH、不会部署、不会重启服务。字段说明：

| 字段 | 含义与约束 |
| --- | --- |
| `target_a_id` / `target_b_id` | 两个不同的小写目标 ID |
| `target_a_host` / `target_b_host` | 两台路由器的不同 IPv4 地址 |
| `worker_host` | worker 的 IPv4 地址，不能与路由器相同 |
| `service_user` | worker 上已存在的无特权服务用户 |
| `main_config` / `base_config` / `source_config` | 三个不同的 OpenClash YAML 文件名 |
| `expected_core_sha256` | 当前路由器实际 Mihomo 可执行文件的 64 位小写 SHA-256 |
| `web_auth_user` | Web Digest 登录名 |
| `keychain_service` | macOS Keychain service 名称 |
| `allowed_networks` | Web 管理台允许的 CIDR，逗号分隔 |

## 使用前提

- worker：Python 3.12、PyYAML 6.0.2、OpenSSH；转换器默认只允许 `127.0.0.1:25500`。
- 可选 Web：systemd、`sudo`/`visudo`、`ss`，服务用户与组必须预先创建。
- 路由器：OpenWrt/ImmortalWrt、OpenClash、Ruby/Psych、Lua/LuCI、`jsonfilter`、`flock`、`curl`、`sha256sum`、Dropbear 工具。
- 当前 builder 带有 Maying/Nexitally 的文件名、地区组和业务组约束；换机场或规则集前必须改代码并补测试，不能只改显示名称。
- 路由器侧脚本兼容较旧 Dropbear；不要盲目加入仅新版本 OpenSSH/Dropbear 支持的参数。
- 安装器要求 `.ssh`/`authorized_keys`、helper、key、`known_hosts` 及目录链 owner/mode 闭合；host key 必须恰好一行 Ed25519。出现 HOLD 时先审计漂移，不能先删文件或放宽权限。

## 推荐顺序

1. 本机：跑完整离线测试并渲染专用副本。
2. worker：只读检查服务用户、转换器、SSH、Python/PyYAML；准备两把互不复用的路由器密钥授权。
3. 路由器 A：运行 capability audit；审查输出全部为 PASS 后再安装 stage client。
4. 路由器 A：生成 Candidate，核对 receipt、SHA-256、Mihomo 检查和 `ACTIVE_CHANGED=false`。
5. 路由器 B：重新执行同样流程，不能复用 A 的 Candidate 或把 A 的 PASS 推断为 B 的 PASS。
6. 可选 Web：单独评审 systemd、sudoers、监听地址、Digest 与 SSH forced-command 变更。
7. 生产启用：必须作为独立变更重新备份活动配置、设计回滚并单独审批；本仓库不自动执行。

更详细的命令运行位置、风险与回滚边界见 [docs/DEPLOYMENT.zh-CN.md](docs/DEPLOYMENT.zh-CN.md)。

若使用 TLS 反向代理，必须同时把外部 Host 加入 `OPENCLASH_WEB_ALLOWED_HOSTS`，并把精确的 `https://host[:port]` 加入 `OPENCLASH_WEB_ALLOWED_ORIGINS`；两者必须对应，禁止使用任意 Origin。

## 敏感信息规则

不得提交或粘贴到 Issue：订阅 URL、token、cookie、密码、HA1、私钥、真实 `known_hosts`、真实 YAML、真实拓扑或带认证 URL。测试中的 `example.invalid`、RFC 5737 地址和 `secret` 字符串均为不可用的合成样例。

## 审核状态

首个公开版于 2026-08-16 完成 129 项本地非监听测试，并以 GitHub Actions 运行包含 6 项 loopback HTTP/Digest 集成测试的 135 项完整门禁；ShellCheck、Bandit、pip-audit、Lua 解析、清单校验和敏感信息扫描也通过。只有最终标签指向的精确提交再次通过完整工作流后才创建发布标签。详见 [脱敏审核报告](docs/SECURITY-AUDIT-2026-08-16.md)。这不是第三方正式渗透测试。

## 许可证

MIT，见 [LICENSE](LICENSE)。
