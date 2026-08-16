# 详细部署门禁

本文把检查、修改、验证和生产启用分开。示例中的路径来自渲染后的 `build/rendered`，地址和账号必须来自你自己的 `config.local.toml`。

## 0. 本机：离线准备

```sh
./tools/run_offline_checks.sh
python3 tools/render_config.py config.local.toml --output build/rendered
(cd build/rendered && sha256sum -c SHA256SUMS)
```

预期：`OFFLINE_CHECKS=PASS`、`RENDER=PASS`、所有文件 checksum 为 `OK`、`LIVE_CHANGES=false`。

风险：无线上写入；`pip install` 可能访问软件源。渲染器拒绝覆盖已有输出。

回滚：删除你新建的 `build/rendered` 即可；不要删除其他目录。若要重新渲染，先确认该目录确实只包含本次生成物。

## 1. worker：只读检查

运行位置：worker Linux shell。先确认服务用户、Python、PyYAML、SSH 和本机转换器；不要在这一步复制密钥或写 `authorized_keys`。

```sh
id syncsvc
stat -c '%a:%U:%G' /home/syncsvc/.ssh /home/syncsvc/.ssh/authorized_keys
python3 --version
python3 -c 'import yaml; print(yaml.__version__)'
ss -ltn | grep '127.0.0.1:25500'
sshd -T 2>/dev/null | head
```

预期：用户存在；`.ssh` 为 `0700`、`authorized_keys` 为 `0600` 且均属于服务用户；Python 与 PyYAML 版本符合 README；转换器只绑定 loopback。`sshd -T` 不应输出任何私钥内容。

HOLD：用户不存在、转换器外网监听、版本不匹配、SSH 配置无法读取，均应停止。

## 2. 路由器：能力审计

运行位置：每台 OpenWrt/ImmortalWrt 路由器的 root shell。此脚本只读，但会核对活动配置路径、OpenClash 运行状态和 core 身份。

```sh
/bin/sh ./router-openclash-sync-capability-audit.sh
```

必须看到：

```text
CAPABILITY_AUDIT=PASS
```

同时保存脱敏后的 `CORE_SHA256`、core size、工具存在性和 `ACTIVE_UNCHANGED=true`。任一 `MISSING`、`HOLD` 或非零退出都应停止。

## 3. 安装 worker forced command

运行位置：worker root shell。脚本参数为：渲染资产目录、某一台路由器的公钥、订阅来源主机名的 SHA-256、目标 ID、归一化策略、唯一部署 ID。

```sh
./install_openclash_worker.sh \
  /absolute/path/to/rendered \
  /absolute/path/to/router-public-key \
  SOURCE_HOST_SHA256 \
  TARGET_ID \
  strict-v1 \
  DEPLOYMENT-ID
```

影响：写 `/opt/publisher-v4-openclash-worker`，备份并追加服务用户的 `authorized_keys`；不安装常驻 worker 服务。对第二台路由器必须使用另一把钥匙并再次执行。

风险：错误账号/公钥会影响 SSH 授权；脚本需要 root。执行前应另存 `authorized_keys` 的 mode、owner、SHA-256 和可恢复副本，不得在日志中打印键值。

回滚：失败时脚本内置事务回滚。已提交安装可用 `uninstall_openclash_worker_key.sh TARGET_ID`，但必须先审查该脚本找到的唯一 committed backup；不要在无法确认备份时强行清理。

## 4. 安装路由器 stage client

运行位置：目标路由器 root shell。

```sh
./install_router_openclash_stage_client.sh TARGET_ID /absolute/path/to/rendered /absolute/path/to/pinned-known-hosts
```

影响：创建 `/etc/openclash/publisher-v4`、生成该路由器独立 Dropbear Ed25519 私钥，并在原本不存在时创建 `/root/.ssh/known_hosts`。它不改活动配置、UCI 或服务。

风险：脚本会因安装根或 `known_hosts` 已存在、host key 不是恰好一行 Ed25519、owner/mode 漂移而 HOLD；不要为了绕过 HOLD 删除现有文件。先人工合并和复核，或调整方案。

回滚：失败时脚本回滚本次创建物。已提交安装的卸载需使用 `uninstall_router_openclash_stage_client.sh TARGET_ID`，执行前先保存 stage receipt 和确认 Candidate 未被生产流程引用。

## 5. 串行生成 Candidate

运行位置：先路由器 A，复核通过后才在路由器 B 执行。

```sh
/etc/openclash/publisher-v4/bin/openclash_router_stage_client.sh TARGET_ID
```

必须同时满足：

- `ROUTER_STAGE=PASS`
- worker receipt 为 `decision=PASS` 且不含 secret fields
- builder receipt 为 PASS
- Mihomo 语法检查 PASS
- Candidate SHA-256 与 receipt 一致
- `ACTIVE_CHANGED=false`
- `UCI_CHANGED=false`
- `SERVICE_RESTARTED=false`

HOLD：任何原因码都应保留脱敏状态和 committed stage 证据，不要直接重试、删除 stage 或重启 OpenClash。先解释具体门禁失败原因。

## 6. 可选 Web 管理台

这是独立的高风险部署，不属于 stage-only：安装脚本会写 `/opt`、`/etc/systemd/system`、`/etc/sudoers.d` 和路由器 `authorized_keys`，并启用/启动 systemd 服务。

部署前至少确认：

- 每台路由器使用独立 Web SSH key 和固定 host key；
- worker 上 helper、key、`known_hosts` 均为 root-owned、不可被普通用户写；
- helper、key、`known_hosts` 的每一级祖先目录也必须由 root 控制且不可组/全局写；
- Digest 默认只生成 SHA-256；仅在受信任内网且确实需要旧 Safari 时使用 `--enable-legacy-md5`；
- 监听和 `allowed_networks` 仅覆盖管理网；公网不可直连；
- 使用 TLS 反向代理时，外部 Host 与精确 HTTPS Origin 必须分别加入 `OPENCLASH_WEB_ALLOWED_HOSTS` 和 `OPENCLASH_WEB_ALLOWED_ORIGINS`，禁止通配；
- 预先记录 systemd、sudoers、应用目录和路由器 `authorized_keys` 的回滚副本。

推荐从管理 Mac 使用 `openclash-sync-web/open-console-tunnel.sh`，通过 `http://127.0.0.1:18088` 访问。不要把密码、HA1 或私钥复制进仓库、Issue 或普通日志。

## 7. 生产启用边界

本项目没有自动激活 Candidate 的命令。若你自行设计激活流程，必须单独完成：

1. 保存每台路由器当前活动 YAML、UCI 指针和服务状态的可恢复基线；
2. 固定要启用的 Candidate 路径与 SHA-256；
3. 明确切换命令、断网风险、管理回路和超时回滚；
4. 路由器 A 激活、DNS/核心/连通性/真实流量验证全部通过后，才考虑路由器 B；
5. 任何失败立即回滚到该路由器自己的基线，不复用另一台的备份。

Candidate PASS 不能替代上述审批和运行时证据。
