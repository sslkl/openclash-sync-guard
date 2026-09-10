# AI 维护手册

[README](../README.zh-CN.md) · [部署门禁](DEPLOYMENT.zh-CN.md) · [用户指南](USER-GUIDE.zh-CN.md) · [验证记录](VALIDATION-2026-09-09.md)

本文是公开源码的通用维护契约，不含私有环境、认证、备份或部署定位信息。最新源版本/公开副本、生产分层验收和发布状态以[验证记录](VALIDATION-2026-09-09.md)为准；不得把公开例子的离线 PASS 解释成任意私有部署可用，也不得用 HTTP/native 结果替代真实 GUI 或业务端到端验收。

## 1. 接手前先确定边界

1. 确认用户指定的仓库根、当前分支、工作区状态、独占写集和禁止读取项。多人协作时不回退、不清理、不暂存别人的改动。
2. 先读公开 README、当前验证记录和受影响源码，再说明拟改文件、理由与风险。普通代码授权不自动包含生产、发布或敏感信息操作。
3. 只读阶段不执行安装/更新/回滚 CLI，不修改文件、Git、服务、网络或定时任务。不要把语法检查实现为 import 特权 helper 或执行安装器。
4. 凭据、私有配置、环境文件、HA1、Keychain、SSH 私钥、真实订阅和敏感日志分别需要读取授权；“扫描时不打印匹配值”也不是读取许可。读取与输出授权不同。
5. 网络取源、第三方只读查询也可能外发数据；对方、数据与操作范围需明确。写入、公开、删除、重启或访问范围扩大时停止相关步骤，继续独立可做的工作。
6. 不递归委派；协作时保持不重叠写集，关键安全、生产和审批决定由负责集成的维护者亲自复核。
7. 使用 `PASS / FAIL / HOLD / UNKNOWN / NOT RUN`；缺证据不显示旧成功。局部验证不是完整回归，构建不是部署，HTTP/native 结果不代替已认证 GUI。

## 2. 公开代码地图

以下路径相对于此仓库，不依赖任何历史工作目录：

| 层次 | 主要入口 | 维护重点 |
| --- | --- | --- |
| stage worker | `openclash_worker.py`、归一化/契约模块 | 来源绑定、结构预算、UDP 来源、脱敏回执与 base 所有权 |
| stage router | `openclash_router_stage_builder.rb`、`openclash_router_stage_client.sh` | Candidate、stage 锁、静态校验与 ACTIVE/UCI 不变 |
| 主界面 | `openclash-sync-web/static/index.html`、`app.css`、`app.js` | 六面板、草稿、焦点、并发锁、逻辑行号与现有 DOM/action 契约 |
| 转换前端 | `openclash-sync-web/static/converter.js`、`converter_apply.js`、`converter_services.js` | 输入档案、proof 生命周期、单端合并与显式第三方动作 |
| Web API | `openclash-sync-web/server.py` | 精确 Host/Origin/CIDR、Digest、写入 nonce、HTTP framing/deadline 与串行目标 |
| 特权边界 | `openclash-sync-web/openclash_web_helper.py`、`openclash_web_forced_command.sh` | 固定动作/目标/argv、runtime pin、可信目录链、受控 SSH |
| 路由器事务 | `openclash-sync-web/openclash_web_router_agent.lua`、`openclash_customizer.rb`、`openclash_custom_transaction.sh`、`openclash_custom_rollback_guard.sh` | 稳定读取、CAS、所有权、备份、选择恢复与分层验收 |
| 转换核心 | `openclash-sync-web/subscription_converter.py`、`converter_fetch.py`、`converter_engine.py`、`converter_formats.py`、`converter_surge.py`、`converter_mellow.py`、`converter_apply.py` | SSRF/TLS/DNS pinning、格式保真、预算与保守合并 |
| 隔离/外部服务 | `openclash-sync-web/converter_sandbox.py`、`converter_services.py` | 已批准且固定的镜像、断网非 root 限额执行、显式外发 |
| 渲染/发布身份 | `tools/render_config.py`、`tools/release_bindings.py`、`openclash-sync-web/converter_runtime_bundle.py`、install/update 脚本 | 全资产覆盖、替换后自动绑定、摘要/owner/mode 与独立验证 |
| 安全策略门禁 | `tools/bandit_policy.py`、`tests/test_bandit_policy.py` | 全源含测试、MEDIUM 精确上下文复审、未知 MEDIUM、任何 HIGH 与陈旧例外拒绝，LOW 仅计数 |

表中同一 Web 行的短文件名位于该行标出的目录。stage 测试的父依赖是本仓库的 `openclash_worker.py`；不能回退到某个本机私有/历史路径。vendor 与测试工具应有明确、可移植的来源和版本，不静默借用全局环境。

## 3. 不可破坏的安全契约

### 请求与特权执行

- Host、Origin、客户端地址、Digest、一次性写入授权、正文/结构预算、连接 deadline 与并发上限各自独立；不能删一个来修测试或改善“内网体验”。
- `allowed_networks` 由严格离线配置渲染指定；保留与预期集合相等的 LAN 校验，禁止通配 Host/Origin、任意转发头信任和临时扩大网络。不得附带 WAN/防火墙更改。
- **HTTP Digest 不加密正文**；MD5 兼容是显式安全例外。测试只能使用合成认证，不读取真实密码/HA1 或绕过 TLS 校验。
- 拒绝仍有未消费正文的请求后正确关闭连接，防止残留正文被下一请求解析；测试替身应实现真实接口，不删除 deadline 迁就 FakeHandler。
- 保持字节、深度、节点、重复键、数值/布尔严格类型与序列化回读预算。解析失败不能回退到旧结果或另一个来源掩盖错误。
- helper 固定程序、action、target 和 argv，不把输入拼接成 shell；不继承未经控制的 SSH/curl 配置，保留 host-key、来源、owner/mode 和复制后字节检查。

### 配置与事务

- stage-only CLI 与扩展 Web apply 是不同许可。程序更新不能顺带更新订阅、apply 主配置、切 ACTIVE/UCI、选点或重启 OpenClash。
- source、Candidate、静态 main、ACTIVE/UCI、runtime、traffic 分层。`ROUTER_STAGE=PASS` 或 `no_change=true` 不等于运行态 PASS。
- 保留定制所有权、精确非规范原文、重复/冲突标记、rank/order 和 `no-resolve`。成员索引只能加速查找，不排序或接管外部条目。
- 两目标预检/写入串行且非原子；部分提交、CAS 漂移、UNKNOWN 和恢复失败必须分别报告。重试前先读回，不盲目重复写入。
- 主配置手工保存/回滚仅改静态文件，不自动 reload/restart；回滚重放当前定制，不能等同于取消链式或恢复流量。
- 恢复限定目标、可信备份、当前状态和兼容格式。PENDING/PREPARED、锁占用或漂移先诊断，不删锁、不伪造回执、不清证据。

### 链式、转换与第三方

- 链式仅支持受支持静态节点的单层关系；已有 dialer、动态 provider、内部节点暴露等限制不能绕过。凭据不回显但需在运行配置/受保护备份中保存。
- 固定原节点和完整链路探针仅证明其覆盖的协议/路径，不证明所有站点、UDP、运营商或住宅身份。
- 在线取源逐跳核对 authority、解析/连接地址、TLS 和响应 framing；拒绝私网/保留/metadata、混合 DNS、HTTPS 降级等 SSRF 路径。
- 高级脚本/转换执行器断网、非 root、固定镜像且有限额；不能声称整个流程无网络。自定义后端 URL 不授予任意后端访问。
- Mellow 仅保真受支持的 Shadowsocks/JSON VMess 子集；不支持就明确拒绝，不能静默丢节点或字段。
- 转换应用保留既有 DNS/TUN/监听/auth/provider/network，拒绝冲突/循环，使用单目标保守 merge 与 CAS。
- 短链/Gist/客户端导入必须显式指定接收方、数据和动作范围。Secret Gist 不是访问控制，删除涉及整个指定 Gist；超时先查状态再决定，不重复 POST。

## 4. 前端一致性与并发

- 外观由 CSS `prefers-color-scheme` 与语义色彩变量驱动，不创建主题存储、不刷新页面、不触发 API；YAML 编辑器两主题保持深色。新组件必须复用色彩变量，检查手机/短屏、焦点/禁用/错误对比度与系统减少动画/高对比偏好。
- 帮助折叠与导航属于本地交互，不能触发写入或让旧 proof 复活；动态状态时间明确标为浏览器本次读取时间，失败必须清除可信时间提示。
- 文本转义必须保持 `&`、`<`、`>` 与双引号属性上下文安全；避免为大量节点逐个创建临时 DOM。验收属性原文用 `getAttribute`，输入控件 `.value` 另受浏览器换行规范化约束。

- 保留已存在 DOM ID、data-*、事件入口和导航关系。界面美化不能截断节点列表；逻辑 YAML 行号不随软换行错位。
- 读取、草稿、预览、运行证明分开。编辑不变/取消不改变原顺序；拒绝预设切换不清空原输入与仍有效状态。
- preview proof 绑定 source、target、mode、group、当前结果正文和 baseline/plan 摘要。改动后作废，改回原值也不恢复；尝试发送 apply 后即按已消费处理，包括 UNKNOWN。
- 认证/连接失效使旧读取与 proof 作废；晚到响应不能恢复旧 PASS 或抢走已切换面板的焦点。重新登录不重放写入。
- 失败也应释放 busy；导航不取消在途请求。快速更新可能直接提交，不能假定所有写操作都有第二个确认框。
- 不用 localStorage/sessionStorage、URL 或控制台保存真实订阅、配置、token、密码。输入档案是未加密 JSON 草稿，不是运行证明或凭据保险箱。

## 5. 发布身份与可移植渲染

以 `config.example.toml` 为闭合 schema，保留两目标 RFC 5737 示例、`syncsvc` 和 ProviderBase/ProviderSource 角色。真实值仅放在获准的忽略配置中；禁止把主机私有路径写进源码/测试。拒绝 `service_user=root`、无效/全零 core 摘要；IPv4 allowlist 归一化后仍须覆盖 loopback 与 worker，拒绝默认路由、重复和危险/保留网段。

`tools/render_config.py` 通过 `tools/release_bindings.py` 在拓扑替换后自动绑定。operational 集合须完整导出 converter、PNG 标志和含许可/来源信息的 19 项 PyYAML vendor 文件。更改源码后重新渲染/绑定，不复制旧摘要。自动更新的消费文件严格为 `openclash-sync-web/` 下这五项：

| 文件 | 绑定对象 |
| --- | --- |
| `server.py` | converter runtime ID |
| `openclash_web_helper.py` | converter runtime ID 与 sandbox SHA-256 |
| `install_router_web_agent.sh` | 路由器 agent/customizer/事务资产 pin |
| `update_router_web_agent.sh` | 同一组路由器资产 pin |
| `install_router_backup_retention_schedule.sh` | customizer pin |

- `converter_runtime_bundle.py` 的规范 `FILES` 定义 runtime 身份输入；核对 `CONVERTER_RUNTIME_ID` 和 `CONVERTER_SANDBOX_SHA256`。目标 `expected_core_sha256`、runtime ID 与依赖元数据 `metadata.source_sha256` 是不同身份，不可互换。
- 路由器安装/更新器的 `expected_hash()`、保留安装器的 `expected_customizer` 必须对应替换后的资产。Lua 机场更新动作对应渲染后的 base/source YAML stem；既有 `maying_normalizer.py` 兼容算法和 converter-shape 限制仍在，不得因通用命名宣称适配所有供应商。
- **旧 `deploy_worker_lan_access.sh` 已禁用**：无副作用，`HOLD=LEGACY_LAN_MIGRATOR_DISABLED` / `LIVE_CHANGES=false` / exit `64`，不在 operational 白名单中。它的历史 V5-pair 迁移逻辑不能靠换 V6 摘要升级；禁止把它加入绑定集或替代完整 worker updater。
- 当前公开副本的合成渲染、自动绑定与 runtime 独立验收已通过；不同拓扑必须重新验证。构建退出成功不够：独立读取产物，验证规范相对路径、精确集合、普通文件、无符号链接、hash、owner/mode 与祖先目录。
- 本地 runtime CLI `verify` 默认 `owner=None`，不检查 owner 或祖先目录链。当前用户下的 `0444/0555` 也不代表真正不可变。生产 `publish(..., production=True)` 的 root-owner/目录链门禁必须独立满足，不能用本地 PASS 替代。
- `FILES` / `SHA256SUMS` 不自列/互列，不含凭据、raw 输入、备份、日志、数据库、环境目录或私有渲染产物。公开清单由集成维护者从完整白名单生成，不能用父工作区的全量 `git add` 代替。
- runtime 工具的构建、验证和安装职责分开；安装是目标写入，不是离线验证。发现权限漂移保留现场，不能 chmod 掩盖或削弱验证器。

## 6. 回归与证据

遵循[当前验证流程](VALIDATION-2026-09-09.md)：先冻结公开输入，再做最小红灯复现、修复、专项与受影响完整回归。工具/fixture 配置错误与产品 bug 分开记录。

- 根目录两份 worker 类测试是直接执行型脚本，各自运行且各自检查退出码；不能当 unittest 模块导入，否则首个 `SystemExit(0)` 会漏跑后续测试。`tests/` 与 Web 使用 discovery，记录 discovered/run/skipped，并拒绝数量不一致或异常退出。新增入口回归见 `tests/test_offline_checks.py`。
- 完整门禁覆盖 reconciler/worker 直接脚本、公开与 Web unittest、Ruby builder/customizer/chain、Lua agent/capture，以及显式配置的 Mihomo/Mellow 合成集成。当前各项数量、跳过项和时间只在验证记录中维护；wrapper 重复覆盖不累加，真实运行态/native probes 另行验收。
- Mellow 可选测试必须共用 `test_converter_mellow.requires_official_parser`。仅未配置 `OPENCLASH_TEST_MELLOW_PARSER` 可跳过，原因必须保留变量标识，供严格聚合器识别；已配置但缺失/损坏的解析器或缺少 Node 必须失败，不得再用 `shutil.which` 转成 skip。`tests/test_offline_checks.py` 直接装载真实 13 项用例，分别覆盖未配置、文件错误及缺 Node；不能放宽聚合器或工作流来凑绿。CI #15 的失败与本地两种依赖矩阵见验证记录。
- 语法检查用编译/AST 或 `--check`、`-c`、`-n` 等不执行安装动作的入口。不得把生产 smoke/acceptance CLI 当普通回归运行；import 纯校验函数也不代表访问过生产。
- 浏览器合成测试使用隔离 profile、合成 API/认证及受控离线资源，明确真实后端/外网是否参与。桌面、手机、低高度、键盘、焦点、长输入和错误状态分别复核。
- GUI 截图、HTTP/native、runtime 与真实业务端到端属于不同证据。没有已认证真实会话就标 `NOT RUN`，不复制凭据补齐指标。
- 安全工具保留实际退出码、告警与扫描范围；告警需分诊，不新增 suppression 只为减少数量。缺工具/skip 不计作完整 PASS，扫描通过不承诺零漏洞。
- Ruff 正确性门禁 `--isolated --no-cache --select E9,F,B023,PLW1510` 已本地实跑通过；完整规则扫描与选择性门禁分开记录，不能说全量 Ruff 无告警。本地 Ruff 与 CI 固定版本不同。[初次 CI #13](https://github.com/sslkl/openclash-sync-guard/actions/runs/34447188599)因 Linux 认证测试临时目录夹具失败，后续静态步骤当时未执行；错误栈已读取、夹具已修复。跟进结果以[对应提交的 Actions](https://github.com/sslkl/openclash-sync-guard/actions?query=branch%3Acodex%2Faudit-ui-converter-release)为准，不用本地通过覆盖远端失败，也不放宽门禁来凑绿。
- 认证测试必须在祖先目录均不可被 group/world 写入的可信 checkout 内运行；合成 HA1 夹具显式使用 checkout 下的私有临时目录。不要把整个 checkout 放在共享 `/tmp`，不要 chmod 系统 `/tmp`、跳过认证测试或放宽生产 `auth_directory_chain_ok()`。新增回归覆盖直接父目录和上层祖先的 `0720`、`0702`、`0777`、`01777`，确保 sticky bit 也不构成信任例外。
- Bandit 策略覆盖全部项目源码（含测试），使用 `--ignore-nosec`。MEDIUM 逐项按精确代码上下文复审；未知 MEDIUM、任何 HIGH 或陈旧例外必须失败，LOW 保留计数而非宣称已消除。行号移动不构成豁免，代码上下文改变须重新审阅，不能靠文件名、告警代码或总数相同凑绿。实际扫描范围/计数见验证记录。依赖公告检查与静态检查分开；本轮未查就标 `NOT RUN`，即使固定 PyYAML 查询通过也不覆盖镜像、宿主或固件。
- 扫描器 JSON 输出因合成 surrogate 等编码问题失败，是报告工具错误，不是“零告警”。保留可用 metadata 与失败状态，单独验证报告/策略的失败处理；不可把不完整 JSON 当成功扫描结果。
- 不对含私有配置或输出的目录执行全树扫描；公开测试副本和私有渲染副本分开。只读授权不因脱敏输出而扩大。
- 修改后检查输入是否漂移；源变了就重新绑定相关证据，不把前一份副本的统计复制过来。

## 7. 升级、恢复与交付

保留公开脚本命名：worker Web 的 `install_worker_web_console.sh` / `update_worker_web_console.sh`，每目标的 `install_router_web_agent.sh` / `update_router_web_agent.sh`；stage contract/assets 使用根目录对应 update/rollback 事务。不要重新用 first-install 覆盖已有系统。

升级前确认可信、可恢复且目标绑定的备份和兼容旧 runtime。降级到不识别链式状态的版本前，先用当前版本取消链式并独立验证恢复。恢复不能跨目标复用，不能只恢复文件却宣称运行态已恢复。

安装保留调度会写定时任务，清理会删除备份；必须另行批准。事务后清理警告与配置提交结果分开记录，不为了得到整齐报告删除失败现场。

交付包含：实际改动文件、授权边界、diff 摘要、执行过的检查及结果、剩余告警/UNKNOWN/NOT RUN、恢复条件。更新验证记录前核实最终公开源码与产物；没有外部写权限就停在本地交付；在获准的本地范围内封版提交，不等于远端提交或发布。不得未经授权 push、对外创建提交、合并或发布来补齐“完成”。正式外部写入另需精确目标、可见性、范围和授权。
