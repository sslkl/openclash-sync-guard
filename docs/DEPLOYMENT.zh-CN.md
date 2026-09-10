# 部署门禁

[English](DEPLOYMENT.md) · [README](../README.zh-CN.md) · [用户指南](USER-GUIDE.zh-CN.md) · [验证记录](VALIDATION-2026-09-09.md)

本文将检查、私有渲染、获准安装、stage、Web 操作与恢复分开。**本地回归及合成包通过，不代表新的真实部署已验收或已经发布。** 部署前查看当前验证记录并完成目标专属门禁；旧发布或私有环境结果不能替代。

## 1. 范围与前提

公开示例保持为 `router_a` / `192.0.2.10`、`router_b` / `192.0.2.11`、worker `192.0.2.20` 和账号 `syncsvc`。配置角色为 `ProviderBase.yaml`、`ProviderSource.yaml` 和主配置 `ProviderBase-ProviderSource.yaml`。这些文档值必须经 [config.example.toml](../config.example.toml) 渲染替换，不要对安装器随意全局替换。

- 工作站：Python 3.12、锁定 PyYAML、Ruby/Psych、Node.js，以及验证矩阵要求的其他工具。
- worker：经审查的服务账号、OpenSSH、受支持的 Python/runtime 依赖和已批准的本地转换器。stage worker 预期转换器绑定 loopback `127.0.0.1:25500`；它与 Web 转换 sandbox 是不同入口。
- 路由器：带 OpenClash 的 OpenWrt/ImmortalWrt、已核实的 Mihomo、POSIX shell、Ruby/Psych、Lua/LuCI 模块、`jsonfilter`、`flock`、`curl` 和 Dropbear 工具。
- 更换上游前，用合成输入检查供应商/规则格式假设与转换形状契约。UDP 配置策略不证明上游能力或真实 UDP 流量。

**授权：** 凭据读取、取源联网、安装密钥/服务、重启、改变网络暴露、删除备份、公开发布分别授权。渲染或测试成功不授予这些权限。本指南不要求修改 WAN、防火墙、DHCP、系统 DNS、默认路由或 SSH 策略。

## 2. 工作站：先检查公开源码，再私有渲染

先在只含公开源码的副本完成[离线与安全验证流程](VALIDATION-2026-09-09.md)，环境目录放在源码之外。Git 忽略不等于允许读取；不要把本地配置、私有输出、凭据、原始输入或备份纳入全树扫描。

之后在私有准备副本中执行：

```sh
cp config.example.toml config.local.toml
# 私下逐项编辑，不打印或提交真实值。
python3 tools/render_config.py config.local.toml --output build/rendered
(cd build/rendered && sha256sum -c SHA256SUMS)
```

macOS 使用 `shasum -a 256 -c SHA256SUMS`。这些命令创建本地文件，不连接路由器或改变运行服务。已有本地配置时不要用复制命令覆盖。渲染器拒绝已有输出目录；另选尚不存在的路径，并保留既有证据。

必须检查：

1. 配置字段闭合，目标 ID/IPv4 主机/配置角色各自不同，`service_user` 不得为 `root`；`expected_core_sha256` 是独立核实的目标二进制摘要。示例占位符和全零摘要都必须校验失败。
2. `allowed_networks` 由离线渲染归一化并排序：接受 1–16 个 IPv4 网段，拒绝重复、默认路由和危险/保留网段，必须覆盖 loopback 与 `worker_host`。保留与预期网段集合相等的校验，不在运行时扩大列表来使安装通过。
3. operational 集合完整包含 converter 模块、PNG 标志和含许可/来源信息的 19 项 PyYAML vendor 文件；故意排除已禁用的 `deploy_worker_lan_access.sh`。
4. 渲染后自动更新 `openclash-sync-web/` 下五个文件的 pin：`server.py`、`openclash_web_helper.py`、`install_router_web_agent.sh`、`update_router_web_agent.sh`、`install_router_backup_retention_schedule.sh`。绑定的是 runtime/sandbox 与 router/customizer 身份，不包含旧 LAN 迁移器。再独立核对复制后字节、可信目录链和 owner/mode。当前合成包已独立检查；其他部署候选及目标 owner/目录链仍需另验，不能只看渲染退出 0。
5. Lua 机场更新动作映射到渲染后的 base/source YAML stem。通用角色名不解除既有 `maying_normalizer.py` 兼容算法与 converter-shape 契约，也不表示当前供应商选择或任意上游均可适配；适配需用合成输入验证。
6. `FILES`、`SHA256SUMS` 与预期集合一致；私有渲染产物不得进入公开归档或发布清单。

**风险：** 准备目录会包含私有拓扑，后续还可能含凭据。**恢复：** 保留源文件与已有输出，在授权内修正本地输入后渲染到新路径；不删除证据、不放宽摘要或权限门禁。

## 3. worker 与路由器：只读预检

worker 上检查账号/工具存在性、转换器监听及已批准的元数据。服务用户 SSH 目录应为 `0700`，`authorized_keys` 应为 `0600`，属主符合预期。检查元数据不授权读取密钥或认证文件。通过可信渠道核对主机 pin；连接失败不能成为接受新 host key 的理由。

每台路由器上，在审查脚本并按已批准的传输计划放好渲染资产后：

```sh
/bin/sh ./router-openclash-sync-capability-audit.sh
```

必须得到 `CAPABILITY_AUDIT=PASS`、工具/core 身份符合预期、活动选择未改变。可共享记录只保留脱敏结论，不公开真实路径、摘要、PID 或配置正文。缺工具、证据不可读、暴露不符或任何 HOLD 都停止该目标；审计本身不授权安装或激活。

## 4. stage 首次安装：一次一个目标

以下是**参数形状，不是无人值守部署脚本**。大写参数需替换成已审查的绝对路径、获准元数据和符合脚本格式的唯一部署 ID。只能使用已渲染资产。路由器私钥留在本端；传递其公钥用于授权，不等于获准读取私钥。

1. 路由器 A 的首次 client 安装会创建 stage 目录、独立 Dropbear Ed25519 身份与 worker 主机 pin 文件；不切 ACTIVE/UCI、不重启 OpenClash。
2. 在 worker 用该路由器产生的公钥执行 stage-worker 授权安装；它写入 worker 资产及服务用户受约束的公钥条目，不安装常驻 stage-worker 守护进程。
3. A 完成 stage 与复核后，才对 B 使用独立密钥和部署 ID 重复流程。

```text
# 路由器 A root shell：仅限首次安装
install_router_openclash_stage_client.sh router_a RENDERED_ASSETS_ABSOLUTE_DIR PINNED_WORKER_KNOWN_HOSTS_FILE
# worker root shell：授权 A 独立产生的公钥
install_openclash_worker.sh RENDERED_ASSETS_ABSOLUTE_DIR ROUTER_A_PUBLIC_KEY_FILE SOURCE_HOST_SHA256 router_a strict-v1 UNIQUE_DEPLOYMENT_ID
```

保留公开安装命名 `install_openclash_worker.sh` 与 `install_router_openclash_stage_client.sh`。第二目标用 `router_b` 和自己的值；不复用 A 的身份或回执。

**风险：** root 脚本创建文件/密钥并修改 SSH 授权。先审查影响和可恢复基线。已有安装根、已有 host-key 文件、符号链接、不是单行 Ed25519 pin、owner/mode 漂移、复制后不一致均为 HOLD，不要盲删或 chmod。

**恢复：** 安装失败可能触发事务回滚，但必须读回结果才能声称已恢复。已提交安装的撤销需审查 `uninstall_openclash_worker_key.sh` 或 `uninstall_router_openclash_stage_client.sh` 及本目标可信回执；卸载/删除另需批准，不能删掉仍被使用的 Candidate。

## 5. 已有 stage 安装：contract/资产更新

已有 publisher 不重复执行首次安装器。完成预检与授权后，使用相应更新事务：

```text
# worker root shell，从渲染资产目录调用
update_openclash_worker_contract.sh RENDERED_ASSETS_ABSOLUTE_DIR UNIQUE_DEPLOYMENT_ID
# 仅在核对当前状态后，恢复同一笔事务
rollback_openclash_worker_contract.sh SAME_DEPLOYMENT_ID
# 路由器 A root shell；A 验证后才轮到 B
update_router_openclash_stage_assets.sh router_a RENDERED_ASSETS_ABSOLUTE_DIR UNIQUE_TARGET_DEPLOYMENT_ID
rollback_router_openclash_stage_assets.sh router_a SAME_TARGET_DEPLOYMENT_ID
```

worker 更新先发布依赖/契约，最后发布 worker，并保留 SSH 授权与来源绑定；路由器更新持有 stage 锁，最后发布 client。事务要求相应 ACTIVE/UCI/core/服务基线不变，不是业务配置 apply。

私下记录精确目标与可信事务回执。遇到 `CURRENT_DRIFT`、`BACKUP_HASH`、`PENDING`、`PREPARED`、证据缺失或其他 HOLD 停止。恢复必须匹配目标、当前状态及兼容备份格式；不复用别端备份、不伪造 COMMITTED、不删锁、不覆盖漂移凑 PASS。

## 6. 生成并复核 Candidate

stage 会访问配置好的 worker/来源，可能读取敏感订阅输入，必须先取得该范围授权。先在路由器 A 使用公开安装路径：

```sh
/etc/openclash/publisher-v4/bin/openclash_router_stage_client.sh router_a
```

考虑 B 前必须同时满足：

- `ROUTER_STAGE=PASS`、worker/builder 决策成功、针对该 Candidate 的真实 Mihomo 语法 PASS。
- Candidate 与回执身份一致；有明确 UDP 来源说明，归一化策略不是运行态 UDP 证明。
- `ACTIVE_CHANGED=false`、`UCI_CHANGED=false`、`SERVICE_RESTARTED=false`。
- 无未解释警告、过期证据、超时、意外写入或部分事务歧义。

stage PASS 只证明准备层；CLI 不提供自动激活 Candidate 的流程。保留 HOLD 证据，不要为掩盖失败重复取源、删除 staging 或重启 OpenClash。

## 7. 可选 Web 部署：单独的特权变更

公开入口保持为 `openclash-sync-web/install_worker_web_console.sh`、`openclash-sync-web/update_worker_web_console.sh`，每台路由器另有 `install_router_web_agent.sh` / `update_router_web_agent.sh`。先核对当前接口、所需私有输入与渲染绑定；它们**不是**语法验证器。

**禁止使用旧 `deploy_worker_lan_access.sh` 安装或迁移。** 旧逻辑只接受 V5 pair，不能安装完整 V6。公开兼容入口现为无副作用的 `HOLD=LEGACY_LAN_MIGRATOR_DISABLED` / `LIVE_CHANGES=false`，退出码 `64`，并从渲染后的 operational 集合排除。不得给它换 V6 摘要、把 HOLD 当更新成功或绕过完整 updater；只在通过前检并获准后使用上述 worker 安装/更新入口。

- worker Web 安装/更新写入应用/runtime/服务/helper；安装可能写 sudoers、启用并启动 Web 服务，更新可能重启该服务。
- 路由器 agent 安装可能写 forced-command 与 authorized_keys；Web 身份及主机 pin 每端独立。
- helper、key、host-key 文件及所有可信祖先目录必须满足 root owner/mode 门禁；不能在失败后放宽。
- 凭据生成/轮换、`prepare_web_auth.py`、`copy-web-login.sh`、Keychain 和剪贴板访问另需明确授权；不把秘密打印或放进命令参数/历史。
- 备份保留安装会修改调度，清理会删除材料；它们不是普通验证步骤，必须另行批准。

**传输：** Digest 默认 SHA-256，旧 MD5 仅作经明确安全审批的兼容例外。**HTTP + Digest 不加密配置、订阅、token 或代理密码正文。** 限制管理网访问；在其他条件不能保证保密时，传敏感输入前批准经过审查的 TLS 入口或现有加密隧道。

保持 `OPENCLASH_WEB_ALLOWED_HOSTS`、`OPENCLASH_WEB_ALLOWED_ORIGINS` 精确匹配，并保留渲染网段相等校验。反向代理的外部 Host 与 HTTPS Origin 必须单独审查；不能信任任意转发头、通配 Origin 或关闭 TLS 验证。`openclash-sync-web/open-console-tunnel.sh` 只是可选连接辅助，不授权读取凭据或修改 SSH/网络策略。本流程不开放 WAN、不改防火墙。

## 8. 业务操作与恢复

| 动作 | 边界 |
| --- | --- |
| 快速更新主配置 | 候选/检查/备份/替换；内容变化可能触发受控 OpenClash 重启；不切 ACTIVE/UCI |
| 分流/Fake-IP/链式定制 | 明确目标绑定的事务；配置和运行态分层验证；双目标串行而非原子 |
| 手工保存主配置 / 回滚主配置 | 只替换静态文件，不自动 reload/restart；编辑器内 source/base 只读 |
| 转换应用 | 新鲜、一次性、单目标预览；保守合并与 CAS；不整体覆盖网络段 |
| 更新程序 | 不授权更新订阅、apply 主配置、改变选择或重启 OpenClash |

写入结果未知时，先查看目标与事务回执，不持旧 proof 再提交。恢复主配置备份会重放当前定制，不等于取消链式或恢复真实流量。降级到不识别链式状态的旧版本前，必须用当前链式取消流程并验证恢复。

保留每端可信备份与兼容 runtime，直到另行批准保留/清理策略。清理回执成功与配置事务成功是不同结论。

## 9. 激活与公开发布是附加门禁

计划切换活动配置时，另行确定目标、精确 Candidate 身份、可恢复的配置/选择基线、独立管理入口、断网/超时方案及明确批准。A 的 core、DNS、runtime、真实流量分别验证后，才考虑 B；不从静态 PASS 外推所有层。

公开发布只能包含已审查的公开白名单，且须通过当前源码回归、绑定/清单验证及已授权的敏感信息审查。不上传私有渲染目录、父工作区或历史私有证据。仓库、分支、可见性、最终暂存文件及写入授权另行确认；本文不宣称已经发布。
