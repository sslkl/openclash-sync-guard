# OpenClash Sync Guard

[English](README.md) · [部署门禁](docs/DEPLOYMENT.zh-CN.md) · [使用指南](docs/USER-GUIDE.zh-CN.md) · [AI 维护](docs/AI-HANDOFF.md) · [验证记录](docs/VALIDATION-2026-09-09.md) · [安全策略](SECURITY.md)

用于订阅归一化、逐路由器准备 OpenClash Candidate，以及可选中文 Web 操作台的 fail-closed 工具集。

**stage CLI 默认只准备 Candidate；扩展 Web 是单独的特权操作入口，获准的动作可以替换配置文件，部分操作可能重启 OpenClash。** 不要把所有 Web 按钮都理解成 stage-only。

> **2026-09-10：审计分支与附注标签已发布，跟进修复覆盖 Linux 认证夹具与可选 Mellow 跳过契约。** 本地回归和限定生产检查按下文记录；真实 GUI 验收仍未完成。
>
> **回归证据：** 已配置可选解析器的源码全量 `source-mellow-contract-full01` 为 905/905、无 skip。公开 CI 同配置 `public-mellow-contract-full02`：根测试 72/72，Web run 905 / skip 13（仅未配置 Mellow），`OFFLINE_CHECKS=PASS_WITH_SKIPS`，Mihomo PASS；已配置但缺失/损坏的解析器或缺少 Node 必须失败，不能跳过。该离线入口仍记录 `REAL_RUNTIME_SHAPE=NOT_RUN`、`NATIVE_PARSER_PROBES=NOT_RUN`。认证夹具要求 checkout 的祖先目录均不可被 group/world 写入，不要放在共享 `/tmp` 下，也不要修改系统 `/tmp` 权限或关闭生产认证检查来凑绿。
>
> **限制：** 已在 Safari 看到新版已登录的浅色页面；后续只读刷新被 Mac 锁屏阻止，完整交互与 macOS 真实外观切换仍为 PENDING。write-check 为 `SKIPPED`，`restore_drill=NOT_RUN`。离线 Chromium 43/43 不是生产 GUI 验收。
>
> **安全证据：** `public-mellow-contract-security01` 仍为 `PASS_WITH_SKIPS`：HIGH 0、已审阅 MEDIUM 15、保留 LOW 254，脚本内依赖查询跳过。独立公告查询仅对固定 PyYAML 6.0.2 返回未发现已知漏洞，保留两条泛化 warning。已审阅发现或公告查询无已知漏洞均不代表零风险。
>
> **封版与发布：** 初次[分支](https://github.com/sslkl/openclash-sync-guard/tree/codex/audit-ui-converter-release)与[附注标签](https://github.com/sslkl/openclash-sync-guard/tree/audit-ui-converter-20260910)已原子推送并读回，提交为 `7a9c015c39bf4d7e42114cf1092767f0ca49ab44`，`main` 未变。[初次 CI #13](https://github.com/sslkl/openclash-sync-guard/actions/runs/34447188599)暴露认证测试使用 Linux 共享 `/tmp` 的夹具问题，生产目录信任检查正确拒绝了该路径。跟进版本只把合成夹具移入可信 checkout，并新增可写祖先目录拒绝回归；生产认证逻辑不变。[CI #15](https://github.com/sslkl/openclash-sync-guard/actions/runs/34466931345)随后暴露三项可选解析器 skip 说明不一致，并非 Web 断言失败；现共用测试装饰器并新增三项真实夹具门禁回归，保持既有跳过策略，不改工作流或生产程序，旧标签不移动。后续结果查看[对应提交的 Actions](https://github.com/sslkl/openclash-sync-guard/actions?query=branch%3Acodex%2Faudit-ui-converter-release)及[验证记录](docs/VALIDATION-2026-09-09.md)，不把本地通过或 push 成功当成远端 CI 和完整生产验收。

## 核心能力

- 订阅 worker 与本地转换器：来源主机绑定、受限解析、归一化契约和脱敏回执。
- 路由器 Candidate builder：安全 YAML、结构预算、base 对规则/DNS 的所有权、UDP 来源标记，以及漂移/冲突时拒绝继续。
- 两个目标分别持有独立身份与 Candidate；先检查 A，再推进 B。
- 中文操作台：快速更新、分流/Fake-IP 定制、单层链式代理、配置查看/编辑、恢复与订阅转换。
- Digest SHA-256、精确 Host/Origin 与客户端网段门禁、固定 helper 动作、每端 forced-command 和事务校验。
- 严格闭合字段的 TOML 渲染器：生成新的私有部署副本，不就地改写公开源码。

```text
默认 stage：来源 → worker → 各端 Candidate → 人工复核门禁。
可选 Web：浏览器 → Web 服务 → 固定 helper → 路由器 agent → 事务。
转换：受控在线取源 → 断网受限执行器 → 结果/预览。
```

## 先看懂操作台

从原生折叠的**三步入门**开始：看两端状态 → 按目的选功能 → 检查后确认。六个导航入口带编号与用途，分级帮助用文字区分读取、预览/检查、写入、重启；不能只靠颜色判断风险。视口宽度 **≤600px** 时，导航按两列排列。

| 编号 | 页面入口 | 用途与关键边界 |
| --- | --- | --- |
| 01 | 快速更新 | 更新订阅与主配置；获准的写入可能重启 OpenClash。 |
| 02 | 域名/IP 与 Fake-IP | 编辑受管分流与 Fake-IP 条目；先读取、检查，再确认保存。 |
| 03 | 链式代理 | 为受支持的节点增加已有落地代理；应用、测试、取消是不同动作。 |
| 04 | 配置浏览与修改 | 读取、校验与编辑 YAML；保存主文件不等于运行态生效。 |
| 05 | 主配置回滚 | 恢复主文件；不是取消链式，也不是运行态恢复证明。 |
| 06 | 订阅转换 | 转换、导出订阅；生成链接、预览与单目标应用是不同动作。 |

- **外观随系统：** 界面随浏览器提供的系统浅色/深色偏好即时切换，不刷新、不清空草稿、不提交表单，也不重新读取设备。YAML 编辑区在两种主题下都固定深色，这是有意设计。
- **“本页读取于”是浏览器读取完成时间：** 成功读取状态后按浏览器本地时钟显示，不是服务器采样时间，也不证明状态此刻仍新鲜。读取失败后显示“状态未确认”；写入前应重新读取。
- **ACTIVE 表示所选配置路径，不是运行态/流量验收。** 遇到 `UNKNOWN` 或写入响应丢失，先核对当前状态与回执，再决定是否重试。逐项操作影响见[用户指南](docs/USER-GUIDE.zh-CN.md)。

## 公开示例拓扑

以下均为 RFC 5737 文档值，**不能直接拿来部署**；不代表任何真实使用者或供应商。

| 配置角色 | 公开示例 |
| --- | --- |
| 目标 A | `router_a` / `192.0.2.10` |
| 目标 B | `router_b` / `192.0.2.11` |
| worker / 服务账号 | `192.0.2.20` / `syncsvc` |
| 主配置 | `ProviderBase-ProviderSource.yaml` |
| base / source | `ProviderBase.yaml` / `ProviderSource.yaml` |
| 允许的客户端网段 | `192.0.2.0/24,127.0.0.0/8` |

以 [config.example.toml](config.example.toml) 为唯一配置字段入口，目标 ID、主机和配置角色不得混同。`expected_core_sha256` 故意保留无效占位符：必须填写已核实的目标 Mihomo 二进制摘要，不能编造，也不能使用 Web runtime ID 代替。

## 先做离线检查

运行位置：开发 Mac 或 Linux 工作站，**仅含公开源码、不含本地配置、凭据、私有渲染输出或备份的副本**。虚拟环境选择源码目录外尚不存在的路径。安装依赖可能访问软件源，需单独满足联网授权。

```sh
python3 -m venv ../openclash-checks-venv
. ../openclash-checks-venv/bin/activate
python -m pip install -r openclash-sync-web/requirements.txt
./tools/run_offline_checks.sh
```

基础环境包括 Python 3.12、锁定的 PyYAML、Ruby/Psych 和 Node.js。完整验证还需要相应 Lua、Mihomo、浏览器和安全工具；缺工具或跳过用例不是完整 PASS。测试可能创建临时文件、监听 loopback。覆盖范围及外部查询边界见[验证流程](docs/VALIDATION-2026-09-09.md)。

## 渲染自己的私有部署副本

公开源码检查完成后再创建被 Git 忽略的本地配置；仅在 `config.local.toml` 尚不存在时执行复制。在私有环境编辑，不打印或提交真实值。

```sh
cp config.example.toml config.local.toml
# 逐项编辑并核实 config.local.toml，再执行渲染。
python3 tools/render_config.py config.local.toml --output build/rendered
(cd build/rendered && sha256sum -c SHA256SUMS)
```

macOS 将校验命令换为 `shasum -a 256 -c SHA256SUMS`。渲染器拒绝覆盖已有输出；需要重做时另选新路径，不为重做而删除旧证据。有私有输入或输出后，不得未经单独读取授权对该目录执行全树打包/安全扫描。

渲染流程完整导出 converter 模块、PNG 标志和含许可/来源信息的 19 项 PyYAML vendor 文件；替换拓扑后**自动更新五个消费文件中的 runtime/sandbox 与 router/customizer 摘要绑定**：server、helper、路由器安装/更新器和保留调度安装器，再生成 `FILES` 与 `SHA256SUMS`。当前候选已通过合成拓扑渲染及独立字节/摘要绑定检查（`synthetic-render-final02`），本地 runtime 独立验证通过 31/31（`public-runtime-independent-final02`）。这些本地用户检查不代表生产 root owner 或祖先目录链验收。本地封版 ID 与门禁结果以交付回执为准；后续输入变化仍需重验。每次真实部署还须核验其实际文件字节、owner/mode 与目录链。缺文件、旧摘要、owner/mode 不符或独立验证失败均为部署 HOLD；不得绕过 pin 或手填一个“能通过”的摘要。checksum 相等仅证明所检查的完整性，不证明运行可用或安全验收通过。

渲染不会连接设备或安装服务。继续阅读[部署门禁](docs/DEPLOYMENT.zh-CN.md)，不要运行尚未渲染的示例安装器。

**旧入口已禁用：** `deploy_worker_lan_access.sh` 仅是无副作用兼容入口，返回 `HOLD=LEGACY_LAN_MIGRATOR_DISABLED`、退出码 `64`。它不在 renderer 的 operational 白名单中，不得换摘要来绕过完整 updater。worker Web 只用 `install_worker_web_console.sh` / `update_worker_web_console.sh`。

## 操作与证据边界

| 层次 | 可以说明 | 不能说明 |
| --- | --- | --- |
| stage CLI | Candidate/回执一致及已执行的 Mihomo 语法检查 | 活动配置、真实流量或激活许可 |
| Web 预览 | 与当前输入和目标基线绑定的计划 | 已写入或扩大操作授权 |
| 事务回执 | 回执记录的单端写入/恢复结果 | 两端原子提交或独立真实流量健康 |
| `no_change=true` | 本次没有配置写入/重启 | 运行态健康或业务端到端 PASS |
| GUI/合成测试 | 确实覆盖的交互场景 | 已认证真实 GUI 或所有浏览器/设备 |

- `ROUTER_STAGE=PASS` 不授权激活。source、Candidate、主配置、ACTIVE/UCI 指向、runtime、traffic 是不同层次。
- 双目标写入串行执行，不是分布式事务；B 失败不代表 A 没写或已自动撤销。
- preview proof 与 CAS（比较后交换）基线会因输入改变、漂移或认证失效而作废；必须重读/重预览，不能强制覆盖。
- 写请求丢失响应或结果为 `UNKNOWN` 时，先检查目标和回执，不重复提交；请求可能已经提交。
- 手工保存主配置、回滚主配置只更新静态文件，不自动 reload/restart；恢复会重放当前定制，并不隐含取消链式代理。

## 安全与功能限制

**HTTP 上的 Digest 不加密请求和响应正文。** 订阅、代理密码、token、配置内容仍是传输中的敏感数据。限制管理网访问；需要保密时使用经过审查的 TLS 入口或明确获准的现有加密隧道。Digest、CIDR、精确 Host/Origin、一次性写入授权各有用途，不能代替加密。旧 MD5 只是需明确安全审批的兼容例外，不是默认选项。

- `allowed_networks` 由离线渲染归一化为 IPv4 网段；拒绝默认路由、危险/保留网段、重复项及缺少 loopback 或 worker 覆盖，也拒绝 `service_user=root` 和全零 core 摘要。保留与预期网段集合相等的校验和精确 Host/Origin 门禁。不要用通配、扩大网段或关闭证书验证来绕过 403。本流程不修改 WAN 暴露或防火墙规则。
- 链式需要事先存在的落地代理，只支持受支持的静态节点与单层关系；探针不能证明所有网站、UDP、住宅或供应商身份。密码不回显，但运行配置和受保护备份必须保存必要凭据。
- 转换将受控在线取源与断网执行器分开。生成链接不等于取源，自定义后端 URL 不授权任意后端访问；应用必须基于新鲜、单目标、基线绑定的预览做保守合并。
- 短链、Gist、客户端导入、凭据/剪贴板读取等均需明确接收方、数据和具体操作授权；第三方只读请求也可能泄露敏感数据，Secret Gist 不是访问控制。
- 不公开真实配置、订阅地址、HA1、私钥、token、cookie、私有备份或已渲染拓扑。详见[安全策略](SECURITY.md)。

## 文档与状态

- [中文部署门禁](docs/DEPLOYMENT.zh-CN.md) / [English deployment](docs/DEPLOYMENT.md)
- [用户指南](docs/USER-GUIDE.zh-CN.md)：动作影响、确认、链式、转换与恢复
- [AI 维护手册](docs/AI-HANDOFF.md)：授权、代码边界、摘要绑定与证据纪律
- [当前验证记录](docs/VALIDATION-2026-09-09.md)：范围及尚未验证的层次
- [变更记录](CHANGELOG.md)、[历史脱敏审计](docs/SECURITY-AUDIT-2026-08-16.md)；历史结论不是当前副本验收

## 许可证

MIT，见 [LICENSE](LICENSE)。
