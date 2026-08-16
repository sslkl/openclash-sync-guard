# Sanitized security audit — 2026-08-16

Scope: the public source tree only. No router, VM, subscription endpoint, production credential, or live OpenClash service was contacted during this release audit.

## Fixed findings

| ID | Area | Resolution |
| --- | --- | --- |
| F-01 | YAML denial of service / object construction | Disabled aliases and classes, rejected anchors, and added node/depth/container/scalar budgets. |
| F-02 | IP literal DNS handling | IPv4, IPv6, and bracketed IPv6 literals no longer become hostname DNS-policy entries. |
| F-03 | Capability audit exit status | Missing capabilities, including Ruby `IPAddr`, now aggregate to `CAPABILITY_AUDIT=HOLD` and a non-zero exit. |
| F-04 | HTTP and Digest ambiguity | Rejected transfer encoding, duplicate singleton headers, missing/invalid/short bodies, deep payloads, and incomplete or duplicate Digest fields. |
| F-05 | Unbounded in-memory state | Bounded authentication-failure, operation-nonce, and replay-state tables and pruned stale entries. |
| F-06 | Privileged helper trust | Required root-controlled directory chains, publickey-only SSH, bounded output, and bounded helper-response structures. |
| F-07 | Router temporary files | Replaced predictable paths with root-private objects, validated owner/mode/type, and required two non-empty matching backup hashes. |
| F-08 | Customization fail-open paths | Required the complete static runtime rule block and fixed filter-only handling. |
| F-09 | Digest compatibility | SHA-256 is default; legacy MD5 HA1 generation now requires an explicit flag. |
| F-10 | Public packaging | Replaced real topology with RFC documentation addresses, added strict rendering, and repaired renamed entry points. |
| F-11 | Dependency baseline | Pinned PyYAML 6.0.2 and verified no known vulnerability with pip-audit at audit time. |
| F-12 | Installer trust | Validated service accounts, directory modes, ED25519 keys, exact host-key records, regular source assets, copied bytes, and target-bound uninstall receipts. |
| F-13 | Origin and interpreter environment | Added strict allowed-origin parsing and Host binding, documented TLS boundaries, and cleared Lua/Ruby/Bundler/loader environment in forced commands. |
| F-14 | Reconstructable release markers | Removed split-string private marker checks and synthetic RFC 1918 fixtures; the public verifier now uses generic workspace/device patterns and RFC 5737 documentation addresses only. |
| F-15 | Missing optional HTTP headers | Normalized `HTTPMessage.get_all()` missing values to an empty list so unauthenticated requests receive a Digest 401 challenge instead of an unhandled `TypeError`. |

## Verification performed

- 129 deterministic non-listener tests passed locally: worker 12, reconciler 10, router builder 17, customizer 22, web non-listener tests 58, renderer 5, public-packaging gates 5.
- GitHub Actions Offline CI passed the corrected 135-test source tree: reconciler 10, worker 12, renderer/public-packaging 10, web 64 (including six loopback HTTP/Digest tests), router builder 17, and customizer 22. The release tag is created only after the same workflow passes the final documentation/checksum commit.
- All shell files parsed with `sh -n`; ShellCheck warning-level gate passed.
- Python Bandit medium/high gate passed; critical Ruff syntax/name checks passed.
- Lua router agent parsed successfully; frontend JavaScript passed `node --check`.
- Dependency audit reported no known vulnerability for the pinned requirements at audit time.
- Public manifest and SHA-256 checks passed after a filename, credential-pattern, authenticated-URL, private-key, real-topology, and filesystem-path scan.

## Residual risks

- The router builder is intentionally provider/ruleset-specific. Unsupported group shapes must HOLD until code and tests are adapted.
- The optional web service is plain HTTP and must remain on a trusted management network, SSH tunnel, or reviewed TLS reverse proxy.
- Dropbear option support varies by router release; compatibility must be audited on each target.
- Offline PASS cannot prove a production core, network path, converter, DNS result, service restart, or rollback.
- This review was performed by the project maintainer workflow and is not an independent penetration test.
- Release decision: `AUDIT PASS`, with a fail-closed gate that permits `v1.0.0` only on the final commit whose Offline CI run passes all 135 tests.
