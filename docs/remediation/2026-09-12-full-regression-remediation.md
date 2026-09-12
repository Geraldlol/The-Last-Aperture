# Full Regression Remediation Ledger

This file is the durable handoff for the repository-wide remediation that began on 2026-09-12. Read it before resuming after context compaction or handing work to another agent. Update it whenever a finding changes state, a validation result changes, or a commit lands.

## Objective

Repair every reproducible correctness, durability, security, packaging, CI, and runtime issue found in the full repository review. The work is complete only when the focused regressions and the full supported validation matrix pass, the shipped artifact has a unique version, the installed Codex and Claude skills resolve to the repaired tree, and remaining external runtime dependencies are either validated live or recorded with exact evidence.

## Repository state

- Repository: `C:\Users\geral\Red Team\last-aperture`
- Branch: `fix/full-regression-remediation`
- Base: `1fa73692e9b86cb30e11ebfd7d49f943da1eaf63`
- Base PR: `#8`
- Review source reconciled: `C:\Users\geral\.codex\attachments\4e191ac4-a3dc-47bc-9023-39ca5a1edad2\pasted-text.txt`
- Baseline full suite: 2,965 tests; 2,962 passed, 1 failed, 2 skipped.
- Baseline failure: authenticated campaign stop-marker publication race.
- GitHub main run: Node 24 failed the Ghidra Windows-path test; Node 20 failed that test and cancelled timer-dependent tests.

## Resume procedure

1. Read this ledger.
2. Run `git status --short --branch` and `git log --oneline -10`.
3. Inspect unchecked or `IN PROGRESS` findings and their named tests.
4. Run the smallest relevant test before editing, then add a failing regression and repair it.
5. Record the focused command and outcome here after each slice.
6. Do not claim completion until the full validation and release checklist at the end is checked.

Status values: `OPEN`, `IN PROGRESS`, `FIXED`, `VERIFIED`, `DEFERRED`.

## HTTP campaign and recon lifecycle

| ID | Status | Finding | Primary code | Required proof |
| --- | --- | --- | --- | --- |
| HTTP-01 | OPEN | Recover a recon run when its lock belongs to a dead process or is demonstrably stale. | `scripts/lib/http-recon-controller.mjs` | Dead-lock recovery and live-lock refusal tests. |
| HTTP-02 | OPEN | Preserve handled redirect semantics when an authenticated campaign ledger is reopened. | `scripts/lib/http-authed-campaign-ledger.mjs` | Reopen after handled redirect remains runnable. |
| HTTP-03 | OPEN | Publish campaign stop markers atomically and dispose runtimes if stop monitoring fails. | `scripts/lib/http-authed-campaign-ledger.mjs`, `scripts/lib/http-authed-campaign-runtime.mjs` | Repeated concurrency regression and full-suite stability. |
| HTTP-04 | OPEN | Make rooted recon finalization idempotent; a late stop must not corrupt an already valid bundle. | `scripts/lib/http-recon-controller.mjs` | Re-finalize and late-stop regressions. |
| HTTP-05 | OPEN | Mark recovery ambiguous only after durable pre-dispatch evidence, not after a merely queued/SENT state. | `scripts/lib/http-recon-controller.mjs` | Crash-before-dispatch is provably unsent. |
| HTTP-06 | OPEN | Publish recon reports atomically. | `scripts/lib/http-recon-controller.mjs` | Injected partial-write/failure recovery test. |
| HTTP-07 | OPEN | Preserve authenticated campaign and mutation rate-limit timing across reopen. | authenticated campaign and mutation controllers/ledgers | Reopen cannot dispatch earlier than the configured interval. |
| HTTP-08 | OPEN | Zero mutation response buffers on every early status and recovery path. | `scripts/lib/http-authed-mutation-controller.mjs` | Instrumented zeroization tests. |
| HTTP-09 | OPEN | Keep stop-watcher timers alive while callers are awaiting them. | `scripts/lib/http-recon-controller.mjs` | Node 20 lifecycle regression completes without cancellation. |

## Browser, HAR, bounty, and connector runtime

| ID | Status | Finding | Primary code | Required proof |
| --- | --- | --- | --- | --- |
| WEB-01 | OPEN | Remove credentials from query strings and structured/request bodies before persisting imported authz requests. | bounty authz request/controller | Bearer, password, CSRF, cookie-like field redaction tests. |
| WEB-02 | OPEN | Reject repeatedly encoded traversal and separator tokens consistently across engagement, route, HAR, and recon contracts. | engagement contracts/registry, `reverse-web-har.mjs`, recon contracts | `%252e%252e%252f` and deeper encodings rejected. |
| WEB-03 | OPEN | Bound HAR request bodies by actual decoded text/byte length; do not trust `postData.size`. | `scripts/lib/reverse-web-har.mjs` | Forged small metadata cannot admit an oversized body. |
| WEB-04 | OPEN | Bound injected-fetch cancellation; a hostile `reader.cancel()` cannot hang the observation. | `browser/http-authed-chrome/injected-fetch.mjs` | Never-resolving and rejecting cancel tests. |
| WEB-05 | OPEN | Include credential-provider and receiver execution in generated connector deadlines, and keep deadline timers live. | `scripts/templates/native-connector-runtime.mjs` | Provider/receiver timeout tests on supported Node versions. |
| WEB-06 | OPEN | Stream and bound crafted bounty responses; do not turn response-read failure into successful evidence. | bounty replay/scan controller | Oversize, stream failure, and cancellation regressions. |
| WEB-07 | OPEN | Detect state-changing routes as well as HTTP verbs before crafted dispatch. | bounty scan plan/controller | `GET /delete` and `GET /logout`-style routes cannot be classified non-mutating. |
| WEB-08 | OPEN | Passive scans must not claim full coverage without response evidence. | bounty scan controller/import | Request-only input yields partial or incomplete coverage. |

## Evidence acquisition and OCI

| ID | Status | Finding | Primary code | Required proof |
| --- | --- | --- | --- | --- |
| EVID-01 | OPEN | Bind provenance, coverage/status, confidence, evidence IDs, attestation, and ordered records into the evidence root. | `scripts/lib/evidence-bundle.mjs` | Metadata tampering invalidates verification. |
| EVID-02 | OPEN | Enforce manifest and per-payload byte limits before unbounded reads. | evidence bundle/schema | Oversize files fail without full-buffer allocation. |
| EVID-03 | OPEN | Refuse symlink/hardlink/reparse-point payload targets and publish payloads safely. | `scripts/lib/evidence-bundle.mjs` | Prelinked output cannot overwrite another file. |
| EVID-04 | OPEN | Cryptographically bind executable acquisition commands and immutable adapter identity to approved plans. | evidence acquire controller/adapters | Tampered persisted plan is rejected before execution. |
| EVID-05 | OPEN | Enforce command, object, stdout, stderr, and total-byte caps before side effects exceed policy. | evidence CLI runner and live/deployed adapters | `maxCommands=1` runs at most one command; stderr and produced objects count. |
| EVID-06 | OPEN | Finalize only executed, matching plans and bind adapter/class/root to the final bundle. | evidence acquire controller | PLANNED or mismatched runs cannot finalize. |
| EVID-07 | OPEN | Resolve registry credential references, avoid leaking secrets, and verify the requested digest. | image reference/registry adapter | Credential and digest mismatch tests. |
| EVID-08 | OPEN | Bound registry output while it is written. | registry adapter | Producer cannot create an unbounded OCI file. |
| EVID-09 | OPEN | Reject stateful SOQL clauses such as `FOR UPDATE`, `FOR VIEW`, and `FOR REFERENCE`. | evidence readonly allowlist | Clause regression matrix. |
| OCI-01 | OPEN | Bound gzip inflation and normalize the decoded outer archive exactly once. | `scripts/lib/oci-normalizer.mjs` | Compression-bomb limit and gzipped outer archive tests. |
| OCI-02 | OPEN | Accept normal tar names such as `./file` and size ordinary OCI layer members by policy rather than the generic 8 MiB entry cap. | OCI normalizer | Realistic OCI fixture normalizes. |
| OCI-03 | OPEN | Preserve repeated ordered layers instead of deduplicating by digest/name. | OCI normalizer | Repeated layer semantics remain ordered. |
| OCI-04 | OPEN | Treat directory entries correctly and support or reject PAX/GNU metadata explicitly without false orphan findings. | OCI normalizer | Directory and x/g/L/K fixture matrix. |

## Platform, CI, packaging, and installation

| ID | Status | Finding | Primary code | Required proof |
| --- | --- | --- | --- | --- |
| PLAT-01 | OPEN | Validate Windows Ghidra helper paths using Windows semantics on every host platform. | `scripts/lib/reverse-ghidra.mjs` | Node 20/24 Linux-compatible unit test. |
| CI-01 | OPEN | Run the supported matrix for pull requests, with concurrency and least required permissions. | `.github/workflows/lint-lenses.yml` | Workflow syntax plus green PR checks. |
| REL-01 | OPEN | Bump the package version and build a uniquely named uploadable artifact after all fixes. | `package.json`, version module, release artifact | Pack/verify, contents, size, SHA-256. |
| INST-01 | OPEN | Ensure the Codex and Claude skill installations resolve to the repaired package without duplicate skill discovery. | local skill links/layout | Both catalogs discover one canonical skill and invoke current files. |
| RUN-01 | VERIFIED | Execute a real Ghidra headless analysis through Last Aperture. | local Ghidra 12.1.2 | Completed with 106 observations against a copied Windows binary. |
| RUN-02 | OPEN | Install and validate a working Frida CLI/runtime. | local environment | Version check plus a harmless local attach/spawn smoke test. |
| RUN-03 | OPEN | Install/find Burp Suite and compile/load the Montoya extension against the real API. | local environment/extension | Real compile and Burp load evidence. |
| RUN-04 | OPEN | Record Docker/crane readiness for OCI live validation. | local environment | Docker daemon and/or crane smoke test. |

## Validation log

| Date/time (Kyiv) | Scope | Command/evidence | Result |
| --- | --- | --- | --- |
| 2026-09-12 baseline | Full Node suite | `npm.cmd test` | FAIL: 1 stop-marker race; 2 skipped. |
| 2026-09-12 baseline | Focused review suite | targeted Node tests | PASS: 808; 2 skipped. |
| 2026-09-12 baseline | Static/generated checks | lint, generators, benchmark/capability generation | PASS. |
| 2026-09-12 baseline | Python bounty conformance | Python test suite | PASS: 38/38. |
| 2026-09-12 baseline | Dependency audit | `npm audit --offline` | PASS: zero vulnerabilities. |

## Completion checklist

- [ ] Every finding above is `VERIFIED` or has an explicit, user-accepted external dependency.
- [ ] Focused regression suites pass on the local supported Node versions.
- [ ] `npm.cmd test` passes without failures or cancellations.
- [ ] Lint, generated-file checks, Python conformance, and dependency audit pass.
- [ ] GitHub pull-request checks run and pass.
- [ ] Version is unique and consistent in source and package metadata.
- [ ] Uploadable package is built and its SHA-256 is recorded.
- [ ] Codex and Claude installations resolve to the final committed tree.
- [ ] Commits are pushed and the reviewed pull request is merged.
