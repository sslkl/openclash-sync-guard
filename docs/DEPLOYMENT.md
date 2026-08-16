# Deployment gates

The complete Chinese guide is available in [DEPLOYMENT.zh-CN.md](DEPLOYMENT.zh-CN.md). This page summarizes the non-negotiable gates.

1. Run `tools/run_offline_checks.sh` and render a private output with `tools/render_config.py` on a workstation.
2. Inspect the rendered manifest and every root script. Rendering is not deployment.
3. On the worker, verify the service account, local converter, Python/PyYAML, SSH host key, and the pinned subscription-host digest before changing files.
   The service account `.ssh` directory must be mode 0700 and `authorized_keys` mode 0600; the installer rejects symlinks and ownership drift.
4. Use independent router keys. Audit and stage target A before target B.
5. Require `CAPABILITY_AUDIT=PASS`, then require `ROUTER_STAGE=PASS`, matching hashes, a Mihomo syntax PASS, and all live-change flags set to `false`.
6. Treat the web console as a separate privileged deployment: it installs a systemd service, sudoers rule, router forced commands, and starts/restarts a service.
   A TLS reverse proxy requires matching explicit allowed Host and HTTPS Origin values; wildcard Origins are unsupported.
7. Candidate activation is intentionally absent and requires a separate backup, rollback plan, runtime validation, and approval.

Do not place secrets in this repository or command history. The example topology is non-routable and must be replaced in an ignored `config.local.toml`.
