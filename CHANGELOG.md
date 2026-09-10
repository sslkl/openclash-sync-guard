# Changelog

## Unreleased

This section describes an unreleased public integration candidate, not a completed GitHub release or full production acceptance. Final source/public Web Python runs each passed 904 tests; the worker updater and scoped production checks also reported PASS. Authenticated GUI/macOS checks and GitHub publication remain pending. Refer to the delivery receipt for local sealing IDs and gate results; they are not predeclared here. See the [validation record](docs/VALIDATION-2026-09-09.md) for the 2026-09-10 evidence and its limits. Historical entries retain their original version labels and scope.

### 2026-09-10 candidate updates

- Follow system appearance immediately with CSS tokens and `prefers-color-scheme`, without a refresh, draft reset, or new device read. Keep the YAML editor intentionally dark.
- Add a native collapsible three-step guide, six numbered navigation entries with purposes, two-column navigation at widths up to 600px, and layered help for read/write/restart and `UNKNOWN`/ACTIVE boundaries.
- Define “本页读取于” as browser-local successful-read completion, not server sampling time. Use pure-string `escapeHtml` and ignore invalid panel IDs without changing the active panel.
- In `converter_formats`, normalize invalid input types to `CONFIG_FORMAT`, restrict TOML dumping to mappings, and prevent TOML header matching from backtracking across blank lines.
- In `converter_surge`, reject non-text input and invalid Unicode surrogates while retaining the 256-byte limit on UTF-8-encoded `policy` text. In `converter_mellow`, remove backtracking for unclosed section headers.
- Add 18 format regressions that fail on the original code and pass after repair; the focused test slice passes 89/89 with no skips. TOML/Mellow semantic comparisons show no differences in the recorded samples; parser microbenchmarks are not whole-service speedup claims.
- Preserve the earlier separate 900-test source/public Web Python passes and public offline checks PASS as evidence from before the latest smoke fix. Offline Chromium passed 43/43 scenarios with seven screenshots visually reviewed by the lead maintainer. The earlier offline run recorded `REAL_RUNTIME_SHAPE=NOT_RUN` and `NATIVE_PARSER_PROBES=NOT_RUN`; later production native acceptance does not rewrite those logs.
- Replace the stale hard-coded title check in `production_smoke` with byte-for-byte comparison against the current `static/index.html`, and add four regressions. Source/public smoke suites each pass 9/9. Final source/public Web Python runs (`source-comprehensive-final03` / `public-comprehensive-final02`) each pass 904 tests, in 152.355 / 152.447 seconds respectively. The public run also passes 69 root tests and Lua agent/capture scenarios 147/14, with `REQUIRED_OFFLINE_CHECKS=PASS`, `OFFLINE_CHECKS=PASS`, `LIVE_CHANGES=false` and capture exit 0. Its `REAL_RUNTIME_SHAPE=NOT_RUN` and `NATIVE_PARSER_PROBES=NOT_RUN` remain separate from production acceptance; counts from independent or overlapping entries are not added together.
- Preserve `public-security-final01` FAIL for one stale B506 review context. After the lead maintainer rechecked the unchanged `BoundedSafeLoader` → `yaml.SafeLoader` protection and refreshed only that context hash, `public-security-final02` exited 0 with `PASS_WITH_SKIPS`; no rule was weakened or new finding exempted.
- Record the latest `public-security-final03`: exit 0 in 7.446792 seconds, Ruff correctness PASS and ShellCheck 25 files PASS. Bandit scans 93 Python files: 0 HIGH, 15 reviewed MEDIUM and 254 retained LOW, with unreviewed/stale entries both 0. `STATIC_SECURITY_CHECKS=PASS`; `SECURITY_CHECKS=PASS_WITH_SKIPS` because the embedded dependency query is skipped. Reviewed findings are not zero risk.
- Record the separate `public-dependency-advisory-final01` query using a fresh cache: exit 0, no timeout, an empty process group on exit, and PyYAML 6.0.2 `vulns: []` / `No known vulnerabilities found`. Retain the two generic warnings recommending fully hashed requirements and `pip-compile`; the requirements already pin the version and include hashes. These are not runtime errors, and no dependency installation or upgrade occurred. This covers only the fixed PyYAML runtime dependency, not all systems, native images or unknown vulnerabilities, and does not rewrite the static run’s skipped step.
- Record `synthetic-render-final02` independent verification PASS: 77 files, root/Web manifest members 75/37, ten router pins, the retention pin and 12 runtime files checked; all 20 vendor/logo files are unchanged. Syntax and local modes pass within the recorded scope, without real-core execution or live changes.
- Record `public-runtime-independent-final02` 31/31 PASS: an independently checked 12-file-plus-manifest contract, files 0444/directories 0555, stable source hashes, and build plus separate-process verify exit 0. Local uid/gid 501/20 and CLI `owner=None` do not establish production root ownership or ancestor-chain acceptance.
- Record the production worker full updater returning PASS with service ACTIVE/ENABLED, `SERVICE_RESTARTED=true`, and `FIREWALL_CHANGED=false`. Both routers returned `ALREADY_CURRENT_NO_WRITE`, without router writes or restarts. Private endpoint, runtime, and backup identifiers are not published.
- Record post-deployment comparison PASS: the worker runtime/payload match the expected deployment, authentication/key/service/sudoers protections are unchanged, and both routers retain the checked non-dynamic fields, configuration, processes, selections and nft structure from this round's pre-deployment baseline. This is neither restoration of historical drift nor attribution of cross-round differences to cron.
- Record scoped production read-only HTTP PASS, converter 28/28 PASS, native 53/53 PASS, and backup verification PASS for eight assets, the `COMMITTED` state and 13 old-runtime entries. Converter/native checks each report zero related containers before and after; converter acceptance uses `network=none` without real-source fetching or router writes.
- Keep HTTP write-check `SKIPPED` and `restore_drill=NOT_RUN`. Authenticated production GUI and real macOS appearance switching remain PENDING because the operator Mac is locked; user unlock has been requested, with no automatic unlock attempted. GitHub push/PR/remote readback remain incomplete; no GitHub write has occurred.

### Earlier integration work in this unreleased candidate

- Extend the Chinese console with chain-proxy controls, bounded subscription conversion, single-target conservative merge previews, and explicit third-party actions.
- Document single-use preview proofs, target-bound CAS, authentication/late-response invalidation, two-target partial failures, and UNKNOWN write recovery.
- Clarify stage-only CLI versus privileged Web writes, static-file save/rollback versus runtime activation, and HTTP Digest without body encryption.
- Integrate converter-shape and base-owned rule/DNS contracts, explicit UDP provenance, and drift-bound worker/router asset update and rollback transactions.
- Retain the two-target RFC 5737 example configuration and public worker installer names. Export converter modules, the PNG logo, and 19 vendor files; automatically refresh runtime/sandbox and router/customizer pins in five consuming files after rendering. Earlier-snapshot synthetic rendering and independent binding checks remain historical; the current candidate final02 results are recorded above. Later input changes require rechecking, and each deployment still needs its own owner/runtime acceptance.
- Disable the legacy V5 LAN migrator with `HOLD=LEGACY_LAN_MIGRATOR_DISABLED` / exit `64`, exclude it from rendered operational assets, and require the full worker install/update workflow instead of re-pinning it to V6.
- Normalize IPv4 allowlists and reject default/unsafe/reserved networks, missing loopback/worker coverage, a root service account, and all-zero core digests. Map Lua source-update actions to rendered base/source YAML stems without relaxing the existing compatibility algorithms.
- Add public user, AI-maintenance, and validation guides without private deployment evidence or inherited test counts.
- Record earlier offline regressions, configured synthetic Mihomo/Mellow integrations, correctness lint, reviewed Bandit policy, and ShellCheck. Preserve skipped external-audit layers, retained LOW findings, and historical scanner failures; the latest results are recorded separately above.
- Fix an import-time successful exit that skipped the second legacy worker test script. Run the two scripts independently, reject unexpected unittest exits/count mismatches, and add 15 real-process regression cases for coverage and failure propagation.
- Fix synthetic IPv4 fixtures missed after raw escape prefixes, cover RFC 1918/CGNAT boundaries and out-of-range negatives, and retain exact line-hash/count review exceptions instead of broad fixture exemptions.
- Remove a legacy device identifier embedded in a test class name and cover embedded/case-insensitive device-marker rejection without changing product behavior.
- Preserve the earlier 30-scenario Chromium baseline, source/screenshot hash readback, and desktop/mobile/low-height review as historical evidence, not as acceptance of the updated frontend.
- These earlier integration entries do not establish authenticated-GUI acceptance, current production acceptance, or publication.

## 0.1.0 — 2026-08-16

- Initial sanitized public release.
- Added fail-closed subscription worker, router Candidate builder, stage client, and optional Chinese web console.
- Added YAML/JSON/input budgets, request framing checks, privileged-helper checks, bounded SSH output, safer router temporary files, and SHA-256-first Digest authentication.
- Added complete Digest/header parsing, root-owned directory-chain checks, single-line Ed25519 pinning, non-null double-hash backups, full runtime static-block verification, and explicit TLS Origin allowlisting.
- Added strict topology renderer, offline verification script, CI, deployment gates, security policy, and sanitized audit report.
- Replaced reconstructable private-marker fixtures and synthetic RFC 1918 addresses with generic checks and RFC 5737 documentation data.
- Fixed a missing optional-header crash that closed the first Digest challenge connection instead of returning HTTP 401.
- No automatic Candidate activation is included.
