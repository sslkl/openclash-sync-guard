# 公开候选验证记录与复验流程

[README](../README.zh-CN.md) · [部署门禁](DEPLOYMENT.zh-CN.md) · [AI 维护](AI-HANDOFF.md)

## 1. 状态与证据范围

**2026-09-10：审计分支与附注标签已发布；初次 CI 暴露的 Linux 认证测试夹具问题已修复，生产认证逻辑不变。** 跟进源项目与公开副本独立 Web Python 全量各 905 项通过，公开必要本地离线门禁通过；真实 GUI 验收仍未完成。远端结果须读取对应提交的 CI，不能用本地通过覆盖；初次失败记录保留。部署比较、只读 HTTP、converter/native 和备份验收见第 7 节，不等于全部上线验收；发布身份见第 8 节。

每项结果只对应其受验代码、对象与时间；源项目与公开副本分别记录，不相加或互相替代。较早的全量、静态及渲染/runtime 构建仅作历史，最新结果在各节单列；此后输入变化仍须重验。依赖公告查询只覆盖固定依赖及查询时点，不扩大为全代码安全验收。生产 native 通过不改写本轮或较早离线日志中的 `NOT_RUN`，HTTP/native 结果不代替 GUI 或业务流量结论。原始输出及中间失败证据私有留存，公开摘要不包含工作区路径、真实设备标识、地址、凭据或生产摘要。

| 检查层 | 当前状态 | 实测范围与限制 |
| --- | --- | --- |
| 8 份公开 Markdown 的最终结构、链接、术语与脱敏 | 以联合 QC / 交付回执为准 | 联合文档检查与最终文档全树扫描分别记录；不预先声明通过 |
| 最终公开白名单、双层清单与 working/staged 门禁 | 以交付回执为准 | 对最终实际字节核对集合、摘要与授权范围；本地封版 ID 不在此预填 |
| 源项目跟进 Web Python 全量 | PASS | `source-ci-fixture-full02`：905 项，151.493 秒；采集 151.680996 秒 / exit 0，无 skip、无超时，退出后进程组为空 |
| 公开副本跟进 Web Python 全量 | PASS | `public-ci-fixture-full02`：905 项，154.125 秒；整套采集 158.369719 秒 / exit 0，无 skip、无超时，退出后进程组为空；不是借用源项目结果 |
| 最新 smoke 专项 | PASS | 源项目 / 公开副本各 9/9，新增 4 项回归；与全量分开记录、不相加 |
| 公开副本本地跟进全套及离线门禁 | PASS（本地） | 根 69 项，Lua agent/capture 147/14；五语言语法及必要本地离线门禁 PASS，LIVE_CHANGES=false；该入口 runtime-shape/native-parser probes 仍为 NOT_RUN |
| 合成拓扑渲染及自动摘要重绑定 | PASS（本地合成） | `synthetic-render-final02`：77 个文件、根/Web 清单成员 75/37；不是生产 root 目录链验收 |
| 本地 runtime 构建后独立验证 | PASS（本地合成） | `public-runtime-independent-final02`：31/31；12 文件与 manifest 合同，生产证据另列 |
| 选择性静态正确性/安全门禁 | PASS_WITH_SKIPS | `public-security-final03`：静态 PASS；脚本内依赖查询 SKIP，15 MEDIUM 已审阅、254 LOW 保留 |
| 固定 Python 依赖公告查询 | PASS（独立查询） | `public-dependency-advisory-final01`：PyYAML 6.0.2 未发现已知漏洞；保留两条 warning，不扩展到系统/原生镜像 |
| 隔离合成浏览器与视觉 | PASS（离线场景） | Chromium 43/43；主代理视觉复核 7 张截图，见第 6 节 |
| macOS 真实系统外观切换 | PENDING | 尚未执行；最近交互尝试受 Mac 锁屏阻止，合成媒体查询测试不替代此项 |
| 源项目已认证生产 GUI | PENDING | 已在 Safari 看到新版已登录的浅色页面；后续只读刷新被锁屏阻止，不能将页面可见或只读 HTTP 成功计为完整交互通过 |
| 本公开副本的已认证真实 GUI | NOT RUN | 公开副本使用示例拓扑，未部署到真实认证环境；不借用源项目页面证据 |
| 本公开副本的真实设备/业务流量/外部服务 | NOT RUN | 本副本仅有离线与合成验收；源项目的生产分层检查另列 |
| 本轮生产 worker 整组 updater | PASS（updater 回执） | 服务 ACTIVE/ENABLED，本轮重启服务、未改防火墙 |
| 本轮两路由器资产核对 | ALREADY_CURRENT_NO_WRITE | 受检资产与 source 一致，本轮没有路由器写入或重启 |
| 部署前后独立比较 | PASS | worker runtime/payload 精确一致；保护项及路由器受检状态保持本轮 pre 基线 |
| 生产只读 HTTP 验收 | PASS（限定范围） | 6/6 受管只读、28 个共同分组及认证/拒绝分支，见第 7 节 |
| HTTP write-check | SKIPPED | 不把只读或拒绝分支通过写成写入验收 |
| 生产 converter 验收 | PASS | 28/28，24.669 秒；无真实取源/路由器写入，执行器 network=none |
| 生产 native 验收 | PASS | 53/53；与离线 probes 的 NOT_RUN 分开记录 |
| 生产备份核验 | PASS（核验范围） | 8 个资产、COMMITTED 与旧 runtime 13 项通过；不是恢复演练 |
| 真实业务流量/外部服务 | NOT RUN | 本记录没有该层验收证据，不以 HTTP/converter/native 结果替代 |
| 真实恢复演练 | NOT RUN | restore_drill=NOT_RUN；更新时的服务重启不等于恢复演练 |
| GitHub 分支与附注标签写入/读回 | PASS（精确两个 refs） | 已原子推送并读回初次发布提交 `7a9c015c39bf4d7e42114cf1092767f0ca49ab44`；main 未变，根工作区未推送 |
| 初次发布 GitHub CI | FAIL（历史保留） | [分支 #13](https://github.com/sslkl/openclash-sync-guard/actions/runs/34447188599)与[标签 #14](https://github.com/sslkl/openclash-sync-guard/actions/runs/34447190614)失败；#13 错误栈确认 Linux 共享 TMPDIR 认证夹具问题，已只修复测试；跟进结果见[对应提交的 Actions](https://github.com/sslkl/openclash-sync-guard/actions?query=branch%3Acodex%2Faudit-ui-converter-release) |

`PASS` 只覆盖记录的对象和场景，`PASS_WITH_SKIPS` 不包含未执行的检查；`FAIL` 为可观察失败；`HOLD` 为门禁不满足；`PENDING` 为流程未完成；`UNKNOWN` 为无法确认；`NOT RUN` 表示本记录没有相应执行证据，`SKIPPED` 为该步骤被跳过。未知写入结果可能已提交，不能通过再次写入“验证”。本记录不承诺零漏洞。

## 2. 验证前固定输入

运行位置：开发 Mac 或 Linux 的隔离、公开源码副本，不是生产主机。

1. 确认源码根、公开基线、未提交改动和精确白名单；不回退他人的修改。
2. 先排除私有配置、环境文件、凭据、raw、备份与历史工作区，再检查全树。Git ignore 不是发布白名单。
3. 工具环境放在源码外；日志使用新位置和合成数据，不覆盖失败证据。不全局安装工具或读取真实配置来补齐测试。
4. 保留源码身份、工具版本、真实退出码、stdout/stderr 与漂移检查；公开记录不包含真实设备信息、私有账号/凭据、工作区路径或生产哈希。
5. 依赖、镜像、公告查询可能联网，先核对范围。本轮离线/静态 runner 阻止非 loopback 网络及生产命令；依赖公告查询在单独步骤执行，不是离线 PASS 的一部分。

## 3. 离线回归：初次发布基线与 CI 跟进结果

### 较早完整离线运行（smoke 修改前）

公开入口：`/bin/sh tools/run_offline_checks.sh`，证据标识 `public-comprehensive-final01`，真实 exit `0`，约 158.64 秒，`OFFLINE_CHECKS=PASS`、`LIVE_CHANGES=false`。源项目独立对照 `source-comprehensive-final02` exit `0`，约 154.38 秒。两轮均无超时、退出时进程组为空，已核对各自 stdout/stderr 与 result 中的摘要。这些结果仅对应上述两轮离线运行，早于最新 smoke 修改，不是当前全量复验或生产测试。

| 组别 | 实际结果 |
| --- | --- |
| 源项目 Web Python（独立对照） | run 900 / skipped 0 |
| reconciler 直接执行脚本 | 10/10 |
| worker 直接执行脚本 | 19/19 |
| 公开 unittest discovery | discovered 69 / run 69 / skipped 0 |
| 公开副本 Web unittest discovery | discovered 900 / run 900 / skipped 0 |
| Ruby builder / customizer / chain | 25/25、46/46、26/26 |
| Lua agent / capture | 147、14 场景通过 |
| 已配置的 Mihomo / Mellow 合成集成 | PASS / PASS |
| Python / Ruby / Lua / shell / JavaScript 语法 | 93 / 7 / 3 / 25 / 4 个文件通过 |
| 独立真实 runtime-shape / native-parser probes | `REAL_RUNTIME_SHAPE=NOT_RUN` / `NATIVE_PARSER_PROBES=NOT_RUN` |

这些是各入口的实际计数，不把 wrapper 内外重复的 Lua、前端等用例再次相加。配置的 parser 已执行，不允许可选 skip 掩盖失败；未配置的额外 runtime/native probes 不算通过。测试生产 smoke 模块的纯函数，不表示执行生产 CLI。

### 最新 smoke 修复与两份副本最终全量

主代理将 `production_smoke` 的旧标题硬编码判断改为与当前 `static/index.html` 字节级匹配，并新增 4 项回归；源项目与公开副本的 smoke 专项各 **9/9 PASS**。这是验收工具及专项测试的结果，不是 GUI 验收。

**初次发布前源项目全量：904 项 PASS（历史基线）。** 主代理核实 `source-comprehensive-final03` 的 RAW stderr 末尾为 `Ran 904 tests in 152.355s` / `OK`；采集耗时 **152.548408 秒**、exit `0`、无超时、退出后进程组为空。152.355 秒是测试套件报告时间，与整个采集过程的耗时分开记录。

**公开副本最终全套：PASS。** 主代理核实 `public-comprehensive-final02`：采集 **156.623771 秒**、exit `0`，RAW 未见 warning、traceback 或失败提示。该结果不借用源项目或专项结果。

| 最终公开入口 | 实际结果 |
| --- | --- |
| 根目录 Python | 69 项 / 2.366 秒 |
| Web Python | 904 项 / 152.447 秒 |
| Lua agent / capture | 147 / 14 场景通过 |
| 必要离线与整体离线门禁 | `REQUIRED_OFFLINE_CHECKS=PASS` / `OFFLINE_CHECKS=PASS` |
| 本次离线运行的 live change | `LIVE_CHANGES=false` |
| 额外 runtime-shape / native-parser probes | `REAL_RUNTIME_SHAPE=NOT_RUN` / `NATIVE_PARSER_PROBES=NOT_RUN` |

900 项属于上述 smoke 修改前的历史全量，不能继续用作当前最终计数；也不将两份副本、wrapper 内外或专项计数重复累加。最终离线 PASS 仍不包含未运行的额外 probes；第 7 节生产 native 是独立证据。

### 2026-09-10 CI 认证夹具可移植性修复

初次 Linux CI 的两个认证错误已在本机强制共享 TMPDIR 下精确复现。根因是测试使用默认临时目录，而生产 HA1 检查有意拒绝任一 group/world 可写祖先；macOS 默认临时目录掩盖了这一夹具假设。仅将两处合成夹具移入可信 checkout，新增直接父级及上层祖先分别为 `0720`、`0702`、`0777`、`01777` 的 8 个拒绝子案例，未改生产认证代码。checkout 也必须位于可信目录链；不要 chmod 系统 `/tmp`、跳过测试或弱化信任检查。

修复后在共享 TMPDIR 下，源项目/公开副本定向各 86 项通过；独立全量各 905 项通过，最新时间与采集范围见第 1 节。公开全套另有根 Python 69、Lua agent 147、capture 14 及五语言语法 PASS。`public-ci-fixture-security01` 静态复验为 PASS_WITH_SKIPS：Ruff 与 ShellCheck 通过，Bandit HIGH 0 / 已审阅 MEDIUM 15 / LOW 254、未知及陈旧审阅均为 0；该入口依赖查询仍跳过。最初本地跟进因未刷清单失败、源项目首次跟进因私有测试沙箱未允许新夹具目录失败，均保留原始记录；分别修正清单与测试 profile 后重跑，不属于生产权限放宽。

### 2026-09-10 格式边界修复

- `converter_formats`：非法输入类型统一为 `CONFIG_FORMAT`；TOML dump 只接受 mapping；TOML 头部正则不再跨空行回溯。
- `converter_surge`：拒绝非文本与无效 Unicode surrogate，保留 `policy` 文本的 256 UTF-8 字节上限，不放宽输入限制。
- `converter_mellow`：消除未闭合 section 头的回溯。

主代理提供的专项证据：[18 项新格式回归](../openclash-sync-web/tests/test_format_audit_20260910.py)在原代码上 RED、修复后 GREEN；专项测试切片 89/89、无 skip。这是独立专项结果，不与全量或其他专项重复累加。解析语义对照 TOML 18,556 个、Mellow 15,664 个样本无差异；只覆盖该样本集，不等于所有输入已证明等价。

| 合成微基准输入 | 修复前 | 修复后 |
| --- | --- | --- |
| TOML 头部路径，8,000 个空行 | 159.097 ms | 0.111 ms |
| Mellow 未闭合 section，512 个空格 | 38.944 ms | 0.006 ms |

以上是特定合成输入的解析路径耗时，不是整个服务、真实设备或端到端请求的倍数加速证明。

### 修复过的测试入口缺陷

两份根目录 legacy 测试脚本在顶层运行后会抛出 `SystemExit`。旧入口将它们一起作为 unittest 模块导入，第一份 `SystemExit(0)` 会导致第二份漏跑，仍可能输出整体 PASS。现在逐个独立执行、逐个检查 exit，并设置 `PYTHONOPTIMIZE=0` 防止继承优化选项关闭裸 assert。

unittest wrapper 拒绝异常退出，要求 discovered/run 一致。新增[入口回归](../tests/test_offline_checks.py) 15 项覆盖两脚本执行、首/次组失败、优化环境、discovery/named-module 退出差异、空发现、漏执行、断言失败与 required/optional parser skip，均在上述公开 unittest 中实际通过。

最初两条回归断言混同了 discovery 包装为 `_FailedTest` 与 named-module 直接传播异常的协议，修正测试判断后复验通过；早期失败保留，不记作产品代码失败。

### 公开数据脱敏回归

暂存前扫描发现私有地址规则遗漏 CGNAT。先使用合成主机地址及原始转义边界复现漏检（真实 exit 1），再将三个测试文件中的 7 处主机样例统一为明确合成值，扩展 RFC1918/CGNAT 数字边界检测。保留必要的网络语义边界，不改变产品逻辑或生产源码。

专项绿灯 5/5 通过，包括上下边界、范围外负例、原始转义前缀、secret shapes 与精确例外。仅允许 15 条经过复核的完整源码行 SHA 与精确命中次数；没有整文件或整个测试目录豁免。完整回归已覆盖 CGNAT 修改后的业务 fixture；最终发布扫描仍以最新实际字节为准。

补充扫描还发现测试类名中嵌入的旧设备标识被单词边界规则漏掉。先收紧规则并用现存类名复现失败（真实 exit 1），再改用通用 worker 测试类名，专项 exit 0。现有测试方法增加嵌入前缀/后缀、大小写与通用名称负例，不增加测试方法数量、不改变产品逻辑。

### 复现入口与工具

新环境示例（安装可能联网，执行前核对授权与来源）：

```sh
python3 -m venv ../openclash-checks-venv
. ../openclash-checks-venv/bin/activate
python -m pip install -r openclash-sync-web/requirements.txt
./tools/run_offline_checks.sh
```

前轮工具记录：Python 3.11.15、Ruby 2.6.10p210、Node 22.22.3、Lua 5.1.5、Ruff 0.16.6、Bandit 1.9.4、ShellCheck 0.11.0、pip-audit 2.10.1；CI 配置为 Python 3.12、Ruby 3.3、Node 22、Lua 5.1，固定开发依赖中的 Ruff 为 0.16.3。初次 CI #13 的认证夹具错误栈已读取，工具版本未逐项从远端日志核对；配置版本不是实际版本证据，本地结果不冒充远端结果。

测试可创建临时文件和 loopback listener；“offline”名称不是无副作用证明。安装器只做语法检查，不执行安装、启用或重启。

## 4. 静态安全与依赖实测

### 2026-09-10 最终静态复验

入口仍为 `/bin/sh tools/run_security_checks.sh`。主代理核实最新 `public-security-final03`：真实 exit `0`，耗时 **7.446792 秒**；`STATIC_SECURITY_CHECKS=PASS`，总结果仍为 `SECURITY_CHECKS=PASS_WITH_SKIPS`。后者保留脚本内依赖查询被跳过的事实，不表示所有安全层均已执行。

| 检查 | 最新结果与边界 |
| --- | --- |
| Ruff correctness | PASS；选择性正确性规则，不是全量 lint 无提示 |
| Bandit | 93 个 Python 文件；HIGH 0 / MEDIUM 15 / LOW 254 |
| MEDIUM 复核门禁 | 15 项逐条已审阅；`BANDIT_UNREVIEWED=0`、`BANDIT_STALE_REVIEWS=0`；`PASS_WITH_REVIEWED_FINDINGS` |
| ShellCheck | 25 个文件 PASS |
| 静态入口内的依赖步骤 | 跳过：`NETWORK_AUDIT_NOT_REQUESTED`；本轮另行完成的独立查询见下节，不改写该跳过记录 |

此前 `public-security-final01` 真实 exit `1`：`converter_formats.py` 的 B506 审阅上下文指纹过期，unreviewed/stale 各 1，门禁正确拒绝通过。主代理逐行复核仍为 `BoundedSafeLoader` → `yaml.SafeLoader`，仅精确刷新这一条 context 哈希，没有降低规则或豁免新 finding；随后 smoke 修改前的 `public-security-final02` 以 exit `0`、约 6.94 秒完成，结果为 `PASS_WITH_SKIPS`。该历史通过与最新 `final03` 分开记录；失败输出保留，不改记为 PASS。

15 项 MEDIUM 仍是需维护的已审阅发现，不是零风险；254 项 LOW 保留且未逐项消除。扫描文件数、发现数量或一次 exit 0 不能代替上下文复核，也不能证明没有未知漏洞。

### 2026-09-10 独立依赖公告查询

主代理核实 `public-dependency-advisory-final01`：使用现有隔离 audit-venv 和独立新 cache 查询公开公告，命令为 `pip-audit --no-deps --disable-pip --format json -r openclash-sync-web/requirements.txt`。采集 exit `0`、无超时、退出后进程组为空；RAW 结果为 PyYAML 6.0.2 `vulns: []`，并报告 `No known vulnerabilities found`。

RAW 保留两条泛化 warning，建议完整固定依赖哈希和使用 `pip-compile`；现有 requirements 已固定版本且带 hash，不把这些建议误写为实际缺失，也不宣称无 warning。这两条不是运行错误；该步骤未安装或升级依赖。查询只覆盖固定的 PyYAML 运行依赖在查询时的已知公告，不证明所有系统、原生镜像、供应链或未知漏洞均无风险。静态入口的 `public-security-final02` 及最新 `final03` 各自仍为 `PASS_WITH_SKIPS`；独立查询不改写其跳过记录，也不抹去首次静态未查公告的历史。

### 前轮静态与依赖记录（仅历史）

下列 90 个 Python 文件、253 LOW 和独立依赖查询属于较早快照，不是上述 93 文件复验的计数或新增查询结果。

实际入口：`/bin/sh tools/run_security_checks.sh`，`RUN_DEPENDENCY_AUDIT=0`。整合轮次 `public-static-security-final-cgnat-round02` 真实 exit `0`，约 7.60 秒，无超时，进程组已退出。

| 检查 | 实测结果与边界 |
| --- | --- |
| Ruff 正确性门禁 | `--isolated --no-cache --select E9,F,B023,PLW1510` 通过；不是全量规则无告警 |
| Bandit 策略 | 90 个项目 Python 文件（含测试）；0 HIGH / 15 MEDIUM / 253 LOW |
| 精确 MEDIUM 复核 | reviewed 15，unreviewed 0，stale reviews 0；`PASS_WITH_REVIEWED_FINDINGS` |
| Bandit policy 回归 | 15 项在公开 unittest 中实际执行通过 |
| ShellCheck | 25 个文件通过 |
| 静态 wrapper 的依赖步骤 | `SKIP: NETWORK_AUDIT_NOT_REQUESTED`，总体输出 `SECURITY_CHECKS=PASS_WITH_SKIPS` |
| 单独 pip-audit | 真实 exit 0；固定 PyYAML 6.0.2 的 `vulns: []` |

[Bandit 策略](../tools/bandit_policy.py)覆盖项目代码和测试、使用 `--ignore-nosec`，按精确上下文匹配 [15 项复核记录](../tools/bandit-reviewed.json)。未知 MEDIUM、任何 HIGH、陈旧例外或扫描错误必须失败。LOW 只计数，未逐项消除；例外不表示风险消失，数量相同不能替代上下文核验。

独立依赖命令：`python -B -m pip_audit --no-deps --disable-pip --require-hashes -r openclash-sync-web/requirements.txt --format json`。原始 WARNING 保留：`--no-deps` 与 `--require-hashes` 同用冗余、鼓励完整固定依赖哈希，以及建议 `pip-compile`。这只证明指定依赖在查询时未发现已知公告，不代表镜像、宿主、固件、供应链或未知漏洞均通过；后者 NOT RUN。

CGNAT fixture 变化曾使一条 B104 的精确上下文复核失效：静态入口正确返回 exit 1，unreviewed/stale 各 1。主代理重新检查该 `public_ip` 拒绝地址纯函数测试，确认没有监听或连接操作后，仅更新这条上下文摘要；随后上述静态整合轮恢复 reviewed 15、unreviewed/stale 均 0，没有扩大例外。

历史中间证据不覆盖或删除：完整 Ruff 曾 exit 1、203 项提示；Bandit 中间基线的 LOW 曾为 248、251。原 Bandit JSON 输出曾因合成 surrogate 在 LOW 报告中的编码错误崩溃，属于报告链路故障，不是“无发现”。该轮扫描成功不改变该历史失败，必须保留扫描错误和完整性门禁。

合成 Mihomo 入口为 `tools/run_mihomo_syntax_check.sh VERIFIED_MIHOMO_BINARY_PATH`，只生成合成 Candidate 并运行 `-t`，不是启动代理或验证实际 UDP/流量。维护者先独立核实二进制来源；脚本会清理自建临时目录，只读任务不能擅自执行。不得用真实输入或随意摘要冒充实际 core 验证。

## 5. 合成渲染、绑定与 runtime

**当前候选合成产物独立复验 PASS。** `synthetic-render-final02` 与 `public-runtime-independent-final02` 分别验证渲染输出和本地 runtime bundle；下列计数来自这两份最新报告，不沿用前轮具体字节数或摘要。本地封版 ID 与最终门禁结果以交付回执为准；报告后输入若变化须重验。第 7 节生产 runtime/payload 比对独立记录，不能由本地合成结果替代。

### 当前合成渲染结果

`synthetic-render-final02` 的独立报告为 PASS；检查对象为使用合成拓扑的本地产物：

- 总计 **77 个普通文件**；根清单列 75 项、Web 清单列 37 项，核对成员与逐文件摘要。
- 12 个 runtime payload 及其绑定已核对；10 个 router pins 与 retention customizer pin 通过。
- 19 个 vendor 文件与 PNG 标志共 20 个文件字节未改变。语法检查：Python 36、shell 21、Ruby 2、Lua 1、JavaScript 4。
- 本地 owner 为 uid 501。根及大多数产物目录为 0700；vendor 中间目录为 0755，受根 0700 保护；无 group/other writable。未为测试放宽权限，这不是生产 root-owner/祖先目录链验收。
- core 仅为合成 pin，没有真实 core 执行；`live_changes=false`。这些结果只证明本轮合成配置、文件与绑定协议，不是实际 core 或业务验收。

前轮检查器曾先误要求所有子目录 0700，再误把 installer 其他同名 case 当作 pin 分支；修正检查器后的第三版通过。两次历史失败保留，属于检查器断言问题，不写成本次 `final02` 的失败或产品缺陷。

### 当前本地 runtime bundle

`public-runtime-independent-final02` **31/31 PASS**：公开输入的构建与另一个进程执行的 CLI verify 均 exit `0`。独立核对 12 个 payload（9 Python + 3 JavaScript）与 manifest 合同，加 `SHA256SUMS` 共 13 个文件；文件 0444、nlink 1，bundle/static 目录 0555，锁 0600，版本父目录 0755，无 bundle 链接。12 个源文件及构建工具的摘要在构建前、构建后、verify 后稳定；不是只重复信任 build 输出。

**owner 与目录链限制：** 本地 uid/gid 为 **501/20**，不是 root。CLI `verify` 默认 `owner=None`，不强制 owner 或生产祖先目录链检查；不能把本地 root ownership 标为 PASS，0444/0555 也不代表真正不可变。生产 `publish(..., production=True)` 的 owner/目录链门禁必须独立满足，不能降低校验或 chmod 掩盖漂移。该本地验证没有执行真实转换、生产安装、网络/SSH/Docker/服务操作或真实 core。

### 维护时仍须保留的门禁

1. 闭合配置 schema、目标/主机/文件名区分、非 root 服务用户及有效非零 core pin；原样示例的无效摘要占位符应拒绝。
2. IPv4 allowlist 归一化、排序并拒绝重复网段，拒绝 IPv6、默认路由、危险范围，要求 loopback/worker 覆盖与精确 network-set equality。
3. 新输出目录、无符号链接/路径逃逸、完整普通文件集，不覆盖旧目录。vendor 与二进制资产不得执行拓扑文本替换。
4. 替换后只对[维护指南](AI-HANDOFF.md)中五个消费者自动重绑定。core/source/runtime 身份不同，不可互换，不继承旧公开或生产摘要。
5. 已禁用的 `deploy_worker_lan_access.sh` 不在 operational 集合或绑定集中；仅报告 `HOLD=LEGACY_LAN_MIGRATOR_DISABLED`、`LIVE_CHANGES=false`、exit 64，不能恢复旧 V5-pair 流程绕过正式 updater。
6. Lua 动作跟随渲染后的 base/source YAML stem；通用命名不代表供应商兼容算法适用于所有订阅。
7. 公开清单排除配置、日志、备份、数据库、环境和合成产物；输入变化后重验，不能复用旧字节的证明。

## 6. 浏览器与交互

### 2026-09-10 当前离线浏览器结果

证据标识 `theme-browser-comprehensive02`：真实 Chromium 中运行的离线合成场景 **43/43 PASS**，`blocked=[]`、`pageErrors=[]`。主代理已对 7 张截图完成视觉复核；本记录引用该复核结果，不将离线场景扩展为真实生产 GUI 验收。

本轮界面使用 CSS tokens / `prefers-color-scheme` 即时切换外观，不刷新或丢弃草稿；YAML 编辑器固定深色。新增原生折叠三步入门、六导航编号与用途、≤600px 两列导航、分级帮助与 `UNKNOWN`/ACTIVE 风险说明。“本页读取于”表示浏览器成功读取完成时间，不是服务器采样时间。`escapeHtml` 使用纯字符串转义，无效 panel ID 不切换面板。

**已认证生产 GUI 与 macOS 真实外观切换：PENDING。** 已通过 Safari 看到新版已登录的浅色页面，导航与引导可见；随后只读刷新动作被 Mac 锁屏阻止，完整交互与真实系统外观切换尚未执行。不将页面可见、旧状态展示或锁屏阻止记为验收通过或产品失败。离线浏览器可以验证被模拟的偏好与交互，不能证明操作系统真实切换、认证链路或所有设备均已验收；空错误列表也不是全链路安全或主动外联审计。

### 前轮 30 场景基线（仅历史）

前轮公开前端快照在 Chromium 149.0.7827.55 中完成 **30/30 场景通过、0 失败、0 跳过**。runner 真实 exit 0，约 8.25 秒，无超时，退出时进程组为空。使用 sandbox、新 profile、mock keychain、offline context 及全路由 mock；没有启动 HTTP server，没有连接真实后端、设备或第三方账号。

实际覆盖：六面板桌面/390px 导航和键盘可达性、skip link、草稿与取消保留、保存错误焦点/操作锁、重复验证单请求、晚到错误不抢焦点、规则/过滤器编辑顺序、长 YAML 行号与大节点列表、转换链接失效、预览与当前文本/目标/模式绑定、取消 apply 不提交、外部服务仅显式动作，以及低高度布局。其他 HTTP/API 回归中的 401/403、CAS/UNKNOWN、proof 消费或链式字段安全分支，不因此额外记为本次浏览器场景通过。

53 个 API 请求均为合成 mock；实际写入路由请求 0，unexpected/blocked 请求 0，page errors 0。3 条 console errors 均对应预设的 HTTP 400 失败场景，而非未处理页面异常。没有运行期端口采样或抓包，不能将此结果夸大为独立主动外联测试。

六份前端资产在执行前、快照、执行后和最终回读间逐文件摘要一致，PNG 标志未变。21 张截图的摘要均已回读核对；原执行者视觉复核 7 张，主代理另抽查桌面概览、手机保存错误焦点、手机合并预览及低高度转换器视口，未发现影响操作的遮挡、横向溢出或不可读的目标/计数/摘要。低高度只复核记录的当前视口，不宣称全页或全部浏览器/设备视觉通过。

**该离线基线不包含已认证真实 GUI 验收。** 当前生产验收进度见第 7 节；合成浏览器、HTTP/API、native 或其他环境的 Safari 会话不能替代。辅助技术、实体触控、加密隧道客户端等未单独执行时保持 NOT RUN，不复制凭据、读取 cookie 或绕过认证来补齐矩阵。

## 7. 真实系统与外部服务

### 本轮生产更新与独立验收（主代理核实摘要）

正式整组 worker updater 返回 PASS，报告服务 ACTIVE/ENABLED、监听就绪，`SERVICE_RESTARTED=true`、`FIREWALL_CHANGED=false`。两个路由器的受检资产与 source 一致，返回 `ALREADY_CURRENT_NO_WRITE`；本轮没有路由器写入或重启。实际监听地址、runtime 身份及备份位置保留在私有证据，不在公开记录展开。

以下按主代理核实的 `comprehensive-20260910/release` 证据组回填；原始记录私有留存，不公开真实设备地址、runtime 摘要或备份路径。

| 验收项 | 结果 | 范围与限制 |
| --- | --- | --- |
| 部署前后比较 | PASS | worker 新 runtime 身份与 payload 精确匹配；认证/密钥及 service/sudoers 保护项未变化；两路由器所有非动态字段、配置、进程、选点及 nft 结构均与本轮 pre 一致 |
| 只读 HTTP | PASS | SHA-256 与显式 legacy MD5 兼容验证、Host 421 拒绝、同源/安全响应头、6/6 受管只读项、28 个共同分组、验证与跨站拒绝分支；write-check=SKIPPED |
| HTTP converter | 28/28 PASS | 24.669 秒；无真实取源/路由器写入，执行器 network=none；验收前后相关容器数均为 0 |
| native | 53/53 PASS | 验收前后相关容器数均为 0；不代替真实业务流量验收 |
| 备份核验 | PASS | 8 个资产、COMMITTED 状态及旧 runtime 的 13 项通过；无 residue；restore_drill=NOT_RUN |

**比较基线是本轮部署前的新快照。** 路由器受检状态与 worker 保护项相对 pre 未变；worker runtime 已按正式 updater 更新并重启服务。这里不声称恢复了历史漂移，也不对跨轮差异作 cron 因果判断。legacy MD5 验证只是显式兼容例外，不改变 SHA-256 默认与传输保密边界。

生产 native 53/53 与第 3 节本轮及较早离线 probes 是不同入口，不能改写离线日志的 `NOT_RUN`。前后容器为 0 是边界时刻的计数，不等于过程中从未创建过临时容器。备份核验通过也不等于已执行恢复。

**剩余 GUI/macOS 验收：PENDING。** Safari 已显示新版已登录的浅色页面；后续只读刷新受 Mac 锁屏阻止，完整只读交互与真实系统外观切换仍未完成。write-check 保留 SKIPPED，restore_drill 保留 NOT_RUN；不把这些未完成项、真实取源或业务流量补写为通过。

### 后续限定只读复核

后续 worker 复核通过：6 项应用资产、13 项 runtime、pin、owner/mode、服务 active/running/enabled、限定监听、health 200 与 converter 容器残留 0；服务 PID/starttime 与部署后相同。两路由器各 5 项公开程序的摘要、root:root/0500、受信父目录链及核心 PID/starttime 也通过。本次未读取真实配置/认证内容、未写入或重启，不将程序复核扩大为再次验证配置、选点、真实业务流量或 GUI；精确采样时间及记录私有留存。

### 仍需遵守的验收边界

真实取源、apply、链式流量、重启/恢复、短链/Gist/客户端导入不属于本次公开候选离线验证。另行获准后，说明目标、敏感读取/外发、写入/删除、可信备份、风险与停止/恢复条件；先 A 后 B，不视为跨设备原子事务。

分别核对主文件、ACTIVE/UCI、runtime、选择、DNS 和必要真实流量。固定 TCP/HTTPS probe 不证明全部网站、UDP 或出口身份；主文件保存/回滚不自动加载运行态。UNKNOWN 时先读取状态与回执，不重复提交。

保留调度/清理与业务事务分别验收，不为补测试安装定时任务或删除恢复材料。未执行真实恢复时，不能用离线分支写成生产恢复 PASS。

## 8. 最终公开与发布门禁

公开交付须核对八份文档、当轮实际 payload 白名单、双层清单、摘要绑定与公开打包测试；最终文件数量以实际封版集合为准，不沿用前轮计数，不整体上传私有验证目录。文档回填后的全树扫描、working/staged 精确字节与双层清单门禁结果以交付回执为准，不在此预先声明成功。最终内容须在明确的敏感读取授权内完成独立逐字节清单核对与不输出匹配值的敏感审查；无输出不豁免读取授权。

公开源码与受验产物要关联，实际命令、版本、退出码、skip/告警与漂移结果须可复核。文档检查仅验证文字、链接和格式，不能排除应用漏洞。历史失败不删除，未运行项不补写通过。

原仓库 [sslkl/openclash-sync-guard](https://github.com/sslkl/openclash-sync-guard) 的[审计分支](https://github.com/sslkl/openclash-sync-guard/tree/codex/audit-ui-converter-release)与[附注标签](https://github.com/sslkl/openclash-sync-guard/tree/audit-ui-converter-20260910)已于 2026-09-10T06:52:17Z 经正常 Git 凭据助手原子推送。06:52:41Z 独立远端读回：分支与 tag peeled commit 均为 `7a9c015c39bf4d7e42114cf1092767f0ca49ab44`，annotated tag object 为 `fd84701c3ba3bcb7e0129dd33422797bec3706e5`；main 仍为 `bbe7de854778be30a60df85c8c479020c8926961`。早先认证失败属于历史诊断，不再作为当前发布阻塞；未提取浏览器 cookie 或向记录输出 token。

外部写入前仍须核对精确仓库、分支、可见性、文件范围和授权。初次只更新原公开项目的两个 refs，没有推送父工作区、强推、合并或改变 main。[初次 CI #13](https://github.com/sslkl/openclash-sync-guard/actions/runs/34447188599)在“Run complete offline regressions and five-language syntax checks”步骤 exit 1；该次后续 Mihomo synthetic Candidate 与静态安全步骤未执行。已读取错误栈，确认是 Linux 共享 TMPDIR 与严格祖先目录信任检查不兼容的测试夹具假设；修复与独立本地复验见第 3 节，不放宽生产安全要求。初次标签 CI #14 亦独立读回 failure，旧失败和旧标签保留。

初次发布已完成 push/远端读回，PR/合并未执行。CI 夹具修复已实现；后续提交的远端结果须查看[对应 SHA 的 Actions](https://github.com/sslkl/openclash-sync-guard/actions?query=branch%3Acodex%2Faudit-ui-converter-release)，不能沿用初次标签或本地 PASS。真实 GUI/macOS 检查仍待完成，不声明全部发布验收通过。后续代码、文档或清单变化按影响范围重验；保留 write-check=SKIPPED、restore_drill=NOT_RUN、静态入口依赖跳过与各轮离线 probes 的 NOT_RUN，独立依赖查询按第 4 节单列。
