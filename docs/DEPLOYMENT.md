# Deployment gates

[简体中文](DEPLOYMENT.zh-CN.md) · [README](../README.md) · [User guide](USER-GUIDE.zh-CN.md) · [Validation](VALIDATION-2026-09-09.md)

This guide separates inspection, private rendering, authorized installation, staging, Web operations, and recovery. **Local regression and synthetic-package results do not certify a new deployment or publication.** Review the current validation record and complete target-specific gates before deployment; old release or private-system results are not substitutes.

## 1. Scope and prerequisites

The checked-in example remains `router_a` / `192.0.2.10`, `router_b` / `192.0.2.11`, and worker `192.0.2.20` with account `syncsvc`. The YAML roles are `ProviderBase.yaml`, `ProviderSource.yaml`, and main `ProviderBase-ProviderSource.yaml`. These documentation values must be replaced through [config.example.toml](../config.example.toml), not by ad hoc search/replace in installers.

- Workstation: Python 3.12, pinned PyYAML, Ruby/Psych, Node.js, and the additional tools required by the validation matrix.
- Worker: reviewed service account, OpenSSH, supported Python/runtime dependencies, and the approved local converter. The stage-worker converter is expected on loopback `127.0.0.1:25500`; this is distinct from the Web conversion sandbox.
- Router: OpenWrt/ImmortalWrt with OpenClash, a verified Mihomo binary, POSIX shell, Ruby/Psych, Lua/LuCI modules, `jsonfilter`, `flock`, `curl`, and Dropbear tools.
- Inspect provider/rule-format assumptions and the converter-shape contract with synthetic data before adapting an upstream. UDP configuration policy is not proof of upstream capability or real UDP traffic.

**Authorization:** reading credentials, contacting a source, installing keys/services, restarting, changing network exposure, deleting backups, and publishing are separate scopes. Rendering or a successful test does not grant any of them. This guide does not call for WAN, firewall, DHCP, system-DNS, default-route, or SSH-policy changes.

## 2. Workstation: public-only checks, then private rendering

First run the [offline and security verification procedure](VALIDATION-2026-09-09.md) in a public-only source copy. Keep environments outside it. Do not run broad scanners over local configuration, private render output, credentials, raw inputs, or backups merely because Git ignores them.

Only afterwards, in the private preparation copy:

```sh
cp config.example.toml config.local.toml
# Edit every field privately; do not commit or print the resulting values.
python3 tools/render_config.py config.local.toml --output build/rendered
(cd build/rendered && sha256sum -c SHA256SUMS)
```

Use `shasum -a 256 -c SHA256SUMS` on macOS. These commands create local files; they do not contact a router or change a running service. Do not replace an existing local config with the copy command. The renderer refuses an existing output directory: choose another unused destination and retain previous evidence.

Required checks:

1. Closed schema, distinct target IDs/IPv4 hosts/configuration roles, a non-root `service_user`, and a real, independently verified `expected_core_sha256`. Both the example placeholder and an all-zero digest must fail validation.
2. `allowed_networks` is normalized and sorted during offline rendering. It accepts 1–16 IPv4 networks, rejects duplicates, default routes and unsafe/reserved ranges, and must cover loopback and `worker_host`. Preserve the exact expected network-set equality gate; do not broaden it at runtime to make an installation pass.
3. The operational set includes converter modules, the PNG logo, and all 19 PyYAML vendor files with license/provenance. The disabled `deploy_worker_lan_access.sh` is deliberately excluded.
4. Rendering automatically refreshes pins in exactly five files: `server.py`, `openclash_web_helper.py`, `install_router_web_agent.sh`, `update_router_web_agent.sh`, and `install_router_backup_retention_schedule.sh` under `openclash-sync-web/`. These bind runtime/sandbox and router/customizer identities, not the old LAN migrator. Independently verify copied bytes, trusted directory chains, and owner/mode. The current synthetic package passed independent checks; renderer exit zero alone still cannot certify a different deployment candidate or its target ownership.
5. Lua provider-update actions map to the rendered base/source YAML stems. Generic role names do not remove the existing compatibility algorithms in `maying_normalizer.py` or the converter-shape contract; this is not a promise of compatibility with every upstream. Validate adaptations with synthetic inputs.
6. `FILES` and `SHA256SUMS` match the intended set. Keep private rendered artifacts out of public archives and release manifests.

**Risk:** private topology and later credentials can enter the preparation directory. **Recovery:** preserve the source and existing outputs, correct the local inputs within their authorized scope, and render to a new path; do not delete evidence or disable hash/permission gates.

## 3. Worker and routers: read-only preflight

On the worker, inspect account/tool availability, converter binding, and approved metadata only. The service account's SSH directory must be mode `0700` and `authorized_keys` mode `0600` with the expected owner. Inspecting metadata is not permission to read key material or credential files. Confirm the intended host-key pin through a trusted channel; do not accept a replacement key merely because a connection failed.

On each router, after reviewing and making the rendered audit script available under an approved transfer plan:

```sh
/bin/sh ./router-openclash-sync-capability-audit.sh
```

Require `CAPABILITY_AUDIT=PASS`, the expected tools/core identity, and unchanged active selection. Keep only a redacted summary in shareable records; do not publish real paths, hashes, process IDs, or configuration contents. Missing tools, unreadable evidence, unexpected exposure, or any HOLD stops that target. An audit is not permission to install or activate.

## 4. Fresh stage installation: one target at a time

The following are **argument signatures, not an unattended deployment script**. Uppercase arguments stand for reviewed absolute paths, approved metadata, and a unique deployment ID accepted by the script. Use the rendered assets. Keep each router's private key on that router; transferring its public key for authorization does not authorize reading the private key.

1. On router A, the first-install client creates the stage directory, that router's independent Dropbear Ed25519 identity, and the pinned worker host-key file. It does not switch ACTIVE/UCI or restart OpenClash.
2. On the worker, authorize the resulting router A public key with the stage-worker installer. It installs worker assets and a constrained key entry for the service account, not a persistent stage-worker daemon.
3. Stage and verify A before repeating this sequence for B with its own key and deployment ID.

```text
# Router A root shell: first installation only
install_router_openclash_stage_client.sh router_a RENDERED_ASSETS_ABSOLUTE_DIR PINNED_WORKER_KNOWN_HOSTS_FILE
# Worker root shell: authorize router A's independently generated public key
install_openclash_worker.sh RENDERED_ASSETS_ABSOLUTE_DIR ROUTER_A_PUBLIC_KEY_FILE SOURCE_HOST_SHA256 router_a strict-v1 UNIQUE_DEPLOYMENT_ID
```

The public installation names remain `install_openclash_worker.sh` and `install_router_openclash_stage_client.sh`. Use `router_b` and its own values for the second target; never reuse A's identity or receipt.

**Risk:** these root scripts create files/keys and change SSH authorization. Review scope and recoverable baselines first. Existing installation roots, existing host-key files, symlinks, non-single-line Ed25519 pins, owner/mode drift, or post-copy mismatch are HOLD conditions, not reasons to delete or chmod blindly.

**Recovery:** an installer may attempt transaction rollback on failure, but read back its result before declaring restoration. For a committed installation, review `uninstall_openclash_worker_key.sh` or `uninstall_router_openclash_stage_client.sh` and the target's trusted receipt; uninstall/deletion requires separate approval and must not remove a Candidate still in use.

## 5. Existing stage installations: contract/assets updates

Do not rerun first-install scripts against an existing publisher. Use the matching update transaction after inspection and approval:

```text
# Worker root shell, from the rendered asset directory
update_openclash_worker_contract.sh RENDERED_ASSETS_ABSOLUTE_DIR UNIQUE_DEPLOYMENT_ID
# Worker rollback, only for that transaction and after current-state checks
rollback_openclash_worker_contract.sh SAME_DEPLOYMENT_ID
# Router A root shell, then router B only after A is verified
update_router_openclash_stage_assets.sh router_a RENDERED_ASSETS_ABSOLUTE_DIR UNIQUE_TARGET_DEPLOYMENT_ID
rollback_router_openclash_stage_assets.sh router_a SAME_TARGET_DEPLOYMENT_ID
```

Worker update publishes dependencies/contracts before the worker and preserves SSH authorization/source binding. Router update holds the stage lock and publishes the client last. The transactions require the relevant active-selection/UCI/core/service baseline to remain unchanged; they are not business configuration apply operations.

Record the exact target and trusted transaction receipt privately. Stop on `CURRENT_DRIFT`, `BACKUP_HASH`, `PENDING`, `PREPARED`, missing evidence, or other HOLD. A rollback must match that target, current state, and compatible backup format. Never reuse another device's backup, fabricate a COMMITTED marker, delete a lock, or overwrite drift to obtain PASS.

## 6. Generate and review a Candidate

Running stage contacts the configured worker/source and may read sensitive subscription input. Obtain that scope first. On router A, using the installed public path:

```sh
/etc/openclash/publisher-v4/bin/openclash_router_stage_client.sh router_a
```

Require all of the following before considering B:

- `ROUTER_STAGE=PASS`, successful worker/builder decisions, and a real Mihomo syntax PASS for the Candidate.
- Matching Candidate/receipt identities and explicit UDP provenance; normalized policy does not prove runtime UDP.
- `ACTIVE_CHANGED=false`, `UCI_CHANGED=false`, and `SERVICE_RESTARTED=false`.
- No unresolved warnings, stale evidence, timeout, unexpected writes, or partial-transaction ambiguity.

Stage PASS proves only this preparation layer. The CLI provides no automatic Candidate activation workflow. Preserve HOLD evidence; do not repeat source fetches, remove staging, or restart OpenClash to hide a failure.

## 7. Optional Web deployment: separate privileged change

Public entry names remain `openclash-sync-web/install_worker_web_console.sh` and `openclash-sync-web/update_worker_web_console.sh`, with `install_router_web_agent.sh` / `update_router_web_agent.sh` for each router. Review their current interfaces, required private inputs, and rendered bindings; these scripts are **not** syntax-check commands.

**The legacy `deploy_worker_lan_access.sh` must not be used for installation or migration.** Its former V5-pair migration contract could not install a full V6 release. The public compatibility entry now performs no changes, reports `HOLD=LEGACY_LAN_MIGRATOR_DISABLED` and `LIVE_CHANGES=false`, and exits `64`. It is excluded from rendered operational assets. Do not change its pins to accept V6, treat the HOLD as a successful update, or work around the full updater. Use the worker install/update entries above after their preflight and approval.

- A worker-console install/update writes application/runtime/service/helper assets; installation can change sudoers and enable/start the console service, and an update can restart that service.
- Router-agent installation can write forced commands and authorized keys. Use independent per-target Web identities and pinned host keys.
- Helper, keys, host-key files, and every trusted parent directory must satisfy root ownership/mode checks. Do not weaken them after a failed validation.
- Credential generation/rotation, `prepare_web_auth.py`, `copy-web-login.sh`, Keychain, and clipboard access need explicit authorization; do not print secrets or put them in shell arguments/history.
- Backup-retention installation changes scheduling, and cleanup deletes material. Neither is an ordinary verification step; approve them separately.

**Transport:** Digest defaults to SHA-256; legacy MD5 is an explicit compatibility/security exception. **HTTP + Digest does not encrypt configuration, subscription, token, or proxy-password bodies.** Restrict management access and approve a reviewed TLS endpoint or existing encrypted tunnel before transmitting sensitive input where confidentiality is not otherwise established.

Keep `OPENCLASH_WEB_ALLOWED_HOSTS` and `OPENCLASH_WEB_ALLOWED_ORIGINS` exact, and preserve the rendered client-network equality check. A reverse proxy's external Host and HTTPS Origin must be explicitly reviewed; do not trust arbitrary forwarding headers, wildcard origins, or disable TLS verification. `openclash-sync-web/open-console-tunnel.sh` is an optional connection helper, not authorization to read credentials or alter SSH/network policy. This workflow does not open WAN access or change firewall rules.

## 8. Business actions and recovery

| Operation | Boundary |
| --- | --- |
| Quick main update | Candidate/check/backup/replace; content changes may trigger a controlled OpenClash restart; not an ACTIVE/UCI switch |
| Routing/Fake-IP/chain customization | Explicit target-bound transaction; verify configuration and runtime separately; two targets are serial, not atomic |
| Manual main save / main rollback | Static-file replacement without automatic reload/restart; editor source/base views are read-only |
| Conversion apply | Fresh, one-use, single-target preview; conservative merge and CAS; no wholesale network-section replacement |
| Program upgrade | Not permission to update subscriptions, apply main configuration, change selection, or restart OpenClash |

After an unknown write outcome, first inspect the target and transaction receipt. Do not submit again with a stale proof. Recovery of a main backup replays current customizations and is not equivalent to canceling a chain or restoring live traffic. Use the chain-cancellation workflow and verify restoration **before** downgrading to a version that cannot understand chain state.

Retain trustworthy per-target backups and compatible runtime versions until separately approved retention/cleanup. A successful cleanup receipt and a successful configuration transaction are different claims.

## 9. Activation and publication are additional gates

A proposed active-config switch needs its own target, exact Candidate identity, recoverable configuration/selection baseline, out-of-band access, outage/timeout plan, and explicit approval. Verify router A's core, DNS, runtime, and real traffic independently before considering B. Do not claim all layers from a static PASS.

Publish only a reviewed public allowlist after current-source regression, binding/manifest verification, and an authorized sensitive-data review. Do not upload the private render directory, a parent workspace, or historical private evidence. Confirm the repository, branch, visibility, final staged files, and write authorization separately; this document does not state that publication has occurred.
