# Contributing

Contributions are welcome when they preserve fail-closed behavior and the stage-only default.

1. Do not include real subscription URLs, credentials, private keys, raw YAML, device snapshots, or topology.
2. Add a synthetic regression test for every behavior change.
3. Run `./tools/run_offline_checks.sh` before opening a pull request.
4. Explain authorization effects explicitly: active config, UCI, service restart, scheduler, and firewall.
5. Keep provider-specific changes isolated and document their assumptions.

Changes that silently activate a Candidate, weaken SSH/Digest authentication, log converted credentials, or turn an unknown state into PASS will not be accepted.
