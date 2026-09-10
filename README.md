# OpenClash Sync Guard

[简体中文](README.zh-CN.md) · [Deployment](docs/DEPLOYMENT.md) · [中文使用指南](docs/USER-GUIDE.zh-CN.md) · [AI maintenance](docs/AI-HANDOFF.md) · [Validation record](docs/VALIDATION-2026-09-09.md) · [Security](SECURITY.md)

A fail-closed toolkit for normalizing subscription data, preparing per-router OpenClash Candidates, and operating an optional Chinese web console.

**The stage CLI prepares Candidates only. The extended web console is a separate privileged interface: approved actions can replace configuration files and, for some operations, restart OpenClash.** Do not treat every web action as stage-only.

> **2026-09-10: audited branch and annotated tag published; follow-up fixes cover Linux authentication fixtures and the optional Mellow skip contract.** Local regression and scoped production results are recorded below; production GUI acceptance remains incomplete.
>
> **Regression evidence:** `source-mellow-contract-full01` passed all 905 Web Python tests with the optional parser configured. The CI-equivalent public run, `public-mellow-contract-full02`, passed all 72 root tests and ran 905 Web tests with 13 explicit skips for the unconfigured optional Mellow parser: `OFFLINE_CHECKS=PASS_WITH_SKIPS`, Mihomo PASS. Missing/broken configured parsers or missing Node fail rather than skip. That offline entry still records `REAL_RUNTIME_SHAPE=NOT_RUN` and `NATIVE_PARSER_PROBES=NOT_RUN`. Keep authentication fixtures under trusted, non-group/world-writable checkout ancestors—not shared `/tmp`; do not chmod system `/tmp` or weaken production authentication checks.
>
> **Limits:** authenticated production GUI and real macOS appearance switching remain PENDING. The signed-in Safari light-theme page was observed; a later read-only refresh action was blocked by the Mac lock, so complete interaction and real appearance switching have not been accepted. Write-check is `SKIPPED`; `restore_drill=NOT_RUN`. Offline Chromium 43/43 is not production GUI acceptance.
>
> **Security evidence:** `public-mellow-contract-security01` remains `PASS_WITH_SKIPS`: 0 HIGH, 15 reviewed MEDIUM and 254 retained LOW; its embedded dependency query is skipped. A separate advisory query found no known vulnerabilities for pinned PyYAML 6.0.2 only, with two generic warnings retained. Reviewed findings and a clean advisory result are not zero-risk guarantees.
>
> **Release evidence:** The initial [branch](https://github.com/sslkl/openclash-sync-guard/tree/codex/audit-ui-converter-release) and [annotated tag](https://github.com/sslkl/openclash-sync-guard/tree/audit-ui-converter-20260910) were atomically pushed and read back at `7a9c015c39bf4d7e42114cf1092767f0ca49ab44`; `main` was unchanged. [Initial CI #13](https://github.com/sslkl/openclash-sync-guard/actions/runs/34447188599) exposed authentication fixtures using Linux’s shared `/tmp`, which the production trust check correctly rejects. The follow-up moves only synthetic fixtures into the trusted checkout and adds writable-ancestor rejection coverage; production authentication is unchanged. [CI #15](https://github.com/sslkl/openclash-sync-guard/actions/runs/34466931345) then exposed three inconsistent optional-parser skip messages, not Web assertion failures. A shared test decorator and three real-fixture gate regressions now enforce the existing skip policy without changing the workflow or production code. The old tag is not moved. Check the [commit-specific Actions results](https://github.com/sslkl/openclash-sync-guard/actions?query=branch%3Acodex%2Faudit-ui-converter-release) and [validation record](docs/VALIDATION-2026-09-09.md); local PASS or a successful push is not hosted CI or full production acceptance.

## Components

- A subscription worker and local converter with source-host pinning, bounded parsing, normalization contracts, and redacted receipts.
- A router Candidate builder with safe YAML loading, structural limits, base-owned rules/DNS, explicit UDP provenance, and fail-closed drift/conflict checks.
- Independent target identities and Candidates for two routers; review target A before proceeding to target B.
- A Chinese console for quick updates, routing/Fake-IP customization, single-layer chain proxies, configuration viewing/editing, recovery, and subscription conversion.
- Digest SHA-256 authentication, exact Host/Origin and client-network gates, fixed privileged-helper actions, per-router forced commands, and transaction checks.
- A closed-schema TOML renderer that produces a new private deployment copy rather than editing the public source in place.

```text
default stage CLI: source → worker → per-router Candidate → review gate
optional web:     browser → web service → fixed helper → router agent → transaction
conversion:       controlled online fetch → restricted offline executor → result/preview
```

## Find your way around the console

Start with the native collapsible **three-step guide**: read both targets → choose a function → check before confirming. Numbered navigation and layered help distinguish reading, preview/checking, writing, and restarting; color alone is not a risk indicator. At viewport widths of **600px or less**, navigation uses two columns.

| No. | On-screen label | Purpose / key boundary |
| --- | --- | --- |
| 01 | 快速更新 | Update subscriptions and the main configuration; approved writes may restart OpenClash. |
| 02 | 域名/IP 与 Fake-IP | Edit managed routing and Fake-IP entries; read, check, and confirm before saving. |
| 03 | 链式代理 | Add an existing landing proxy to a supported node; apply, test, and cancel are separate actions. |
| 04 | 配置浏览与修改 | Read, validate, and edit YAML; saving the main file does not activate it. |
| 05 | 主配置回滚 | Restore a main file; this is neither chain cancellation nor proof of runtime recovery. |
| 06 | 订阅转换 | Convert/export subscriptions; link generation, preview, and single-target apply are distinct. |

- **Appearance follows the system:** The interface updates immediately when the browser's system light/dark preference changes, without refreshing, clearing drafts, submitting forms, or re-reading devices. The YAML editor intentionally stays dark in both themes.
- **“本页读取于” is browser read-completion time:** it uses the browser's clock after a successful status read, not the server's sampling time or proof that the state is still fresh. A failed read shows “状态未确认”; re-read before writing.
- **ACTIVE is a selected configuration path, not runtime/traffic acceptance.** For `UNKNOWN` or a lost write response, inspect current state and the receipt before retrying. The [Chinese user guide](docs/USER-GUIDE.zh-CN.md) explains each action's effects.

## Public example topology

These are RFC 5737 documentation values, **not reachable deployment instructions**. The public configuration does not identify an operator or a real provider.

| Setting | Checked-in example |
| --- | --- |
| Target A | `router_a` at `192.0.2.10` |
| Target B | `router_b` at `192.0.2.11` |
| Worker / service account | `192.0.2.20` / `syncsvc` |
| Main configuration | `ProviderBase-ProviderSource.yaml` |
| Base / source | `ProviderBase.yaml` / `ProviderSource.yaml` |
| Allowed client networks | `192.0.2.0/24,127.0.0.0/8` |

Use [config.example.toml](config.example.toml) as the schema. Target IDs, hosts, and configuration roles must remain distinct. `expected_core_sha256` deliberately contains an invalid placeholder: supply the verified hash of your intended Mihomo binary, not an invented value or a web-runtime identity.

## Start with offline checks

Run on a development Mac or Linux workstation, in a **public-only source copy with no local configuration, credentials, rendered private output, or backups**. Use an unused environment path outside that checkout. Dependency installation may contact package indexes and needs its own network approval.

```sh
python3 -m venv ../openclash-checks-venv
. ../openclash-checks-venv/bin/activate
python -m pip install -r openclash-sync-web/requirements.txt
./tools/run_offline_checks.sh
```

The supported baseline includes Python 3.12, the pinned PyYAML requirement, Ruby/Psych, and Node.js. Full verification also needs the applicable Lua, Mihomo, browser, and security tools; missing dependencies or skipped cases are not a full PASS. Tests may use temporary files and loopback listeners. See the [validation procedure](docs/VALIDATION-2026-09-09.md) for coverage and external-query boundaries.

## Render a private deployment copy

After public-source checks, create an ignored local configuration and edit it privately. Run the copy step only if `config.local.toml` does not already exist. Do not print or commit its values.

```sh
cp config.example.toml config.local.toml
# Edit and verify every field in config.local.toml before rendering.
python3 tools/render_config.py config.local.toml --output build/rendered
(cd build/rendered && sha256sum -c SHA256SUMS)
```

On macOS use `shasum -a 256 -c SHA256SUMS` instead. The renderer refuses an existing output directory; choose a new destination rather than deleting old evidence. Once private inputs or output exist, do not run a whole-tree packaging/security scan over that directory without a separately approved read scope.

The render workflow exports converter modules, the PNG logo, and all 19 vendored PyYAML files, including license/provenance. After topology substitution it **automatically refreshes runtime/sandbox and router/customizer pins in five consuming files**: server, helper, router install/update scripts, and the retention installer. It then produces `FILES` and `SHA256SUMS`. Current candidate synthetic rendering and independent byte/pin checks passed (`synthetic-render-final02`); local runtime verification passed 31/31 (`public-runtime-independent-final02`). These local-user checks do not establish production root ownership or ancestor-chain acceptance. Refer to the delivery receipt for local sealing IDs and gate results; recheck any later input changes. Each deployment also requires verification of its own rendered bytes, ownership and directory chain. A missing asset, stale binding, wrong owner/mode, or failed independent verification is a deployment HOLD; do not bypass pins or manually substitute a convenient hash. A checksum match is an integrity check, not a runtime or security acceptance result.

Rendering neither connects to targets nor installs services. Continue with the [deployment gates](docs/DEPLOYMENT.md); do not execute unrendered example installers.

**Disabled legacy entry:** `deploy_worker_lan_access.sh` is a no-side-effect compatibility stub returning `HOLD=LEGACY_LAN_MIGRATOR_DISABLED` and exit `64`. It is excluded from the renderer's operational allowlist and must not be re-pinned to bypass the full updater. Use only `install_worker_web_console.sh` / `update_worker_web_console.sh` for the worker console.

## Operational boundaries

| Layer | What a result can establish | What it cannot establish |
| --- | --- | --- |
| Stage CLI | Candidate/receipt consistency and the stated Mihomo syntax check | Active configuration, traffic health, or permission to activate |
| Web preview | A plan bound to current inputs and target baseline | A completed write or permission for unrelated actions |
| Transaction receipt | The recorded target-local write/recovery result | Cross-router atomicity or independent live traffic health |
| `no_change=true` | No configuration write/restart for that operation | Runtime health or successful end-to-end traffic |
| GUI/synthetic tests | The particular interaction cases actually exercised | An authenticated live browser session or every browser/device |

- `ROUTER_STAGE=PASS` does not authorize activation. Source, Candidate, main file, ACTIVE/UCI selection, runtime, and traffic are separate layers.
- Two-target writes are serial, not a distributed transaction. A failure on B does not prove A was untouched or automatically rolled back.
- Preview proofs and compare-and-swap (CAS) baselines expire after input changes, drift, or authentication loss. Re-read and re-preview; do not force an overwrite.
- After `UNKNOWN` or a lost write response, inspect the target and receipt before retrying. A request may already have committed.
- Manual main-file save and main-file rollback are static-file operations, without automatic reload/restart. Recovery reapplies current customizations; it is not an implicit chain-proxy cancellation.

## Security and feature limits

**Digest over HTTP does not encrypt request or response bodies.** Subscriptions, proxy passwords, tokens, and configuration contents remain sensitive in transit. Restrict management access and use a reviewed TLS endpoint or an explicitly approved existing encrypted tunnel where confidentiality is needed. Digest, CIDR filtering, exact Host/Origin allowlists, and one-time write authorization serve different purposes; none replaces encryption. Legacy MD5 is an explicit compatibility/security exception, not the default.

- Render `allowed_networks` offline as normalized IPv4 networks. Default routes, unsafe/reserved networks, duplicate entries, and missing loopback or worker coverage are rejected; so are `service_user=root` and an all-zero core digest. Keep the exact configured network-set check and explicit Host/Origin checks; never work around a 403 with wildcards, broader networks, or disabled certificate validation. This workflow does not change WAN exposure or firewall rules.
- Chain proxies require an existing landing proxy and supported static nodes. They are single-layer; probes do not certify every site, UDP, or a residential/provider identity. Passwords are not echoed, but operational configurations and protected backups necessarily contain required credentials.
- Conversion separates controlled online fetching from a network-disabled executor. Link generation is not fetching; a custom backend URL is not permission to access an arbitrary backend. Apply uses a fresh, single-target, baseline-bound preview and conservative merge rules.
- Short links, Gist, client import, credential/clipboard access, and other external actions require explicit recipient/data/action authorization. A read-only third-party request can still disclose sensitive data. A secret Gist is not access control.
- Never include real configuration, subscription URLs, HA1 files, private keys, tokens, cookies, private backups, or rendered topology in a public release. See [SECURITY.md](SECURITY.md).

## Documentation and status

- [Deployment gates](docs/DEPLOYMENT.md) / [中文部署](docs/DEPLOYMENT.zh-CN.md)
- [中文用户指南](docs/USER-GUIDE.zh-CN.md): action effects, confirmation, chaining, conversion, and recovery
- [AI maintenance guide](docs/AI-HANDOFF.md): permissions, code boundaries, digest binding, and evidence discipline
- [Current validation record](docs/VALIDATION-2026-09-09.md): current scope and unverified layers
- [Changelog](CHANGELOG.md) and [historical sanitized audit](docs/SECURITY-AUDIT-2026-08-16.md); historical findings are not current-copy acceptance

## License

MIT. See [LICENSE](LICENSE).
