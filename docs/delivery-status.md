# Assessment improvement delivery status

## CI compatibility follow-up (2026-09-05)

The optional proxy-store test module no longer crashes Node 20 during import.
Its eight tests now report explicit unsupported-dependency skips when a runtime
older than Node 24 lacks `node:sqlite`; Node 24 still imports the module normally
and executes all eight unchanged test bodies. Missing SQLite or other import
errors on Node 24 remain failures. Production modules and CI gates are unchanged.

Verification: the original Node 20.20.2 import crash was reproduced, followed
by eight named skips and zero failures after the test-only correction. On Node
24.13.0 all eight tests pass with zero skips. Review confirmed that the Node 20
public support promise covers planning/manual ingestion, not this optional store.

This is a partial CI fix. Campaign-timeout failures remain unchanged, no full
suite or new GitHub run is claimed, and no changes have been pushed or merged.
The fixture portability fix described below is already in the local history.

## Passive-check slice (2026-09-05)

The next additive slice introduces a standalone, explicitly scoped JavaScript
TLS-pattern checker, fixed-text repair guidance, and synthetic evaluation.
See [passive source checks](passive-source-checks.md). This does not supply the
still-unavailable semantic provider/oracle or independently validated quality
measurement. Existing finding repair records and dependency-aware result reuse
remain open.

The post-merge Linux CI run
[33972298641](https://github.com/Geraldlol/red-team-audit/actions/runs/33972298641)
failed despite the earlier local Windows result below. The fixture builder now
normalizes gzip OS metadata; its 47 focused tests pass on Windows Node 20.20.2
and Node 24.13.0, including a simulated Unix/Windows-header regression. Actual
Linux CI confirmation is still pending.

Two Node 20 failures remain visible and unchanged: the optional proxy-ingest
suite imports unavailable `node:sqlite`, and campaign timeout tests can lose
their event-loop handles before pending promises settle. The latter is a real
runtime lifecycle assumption, not 52 independent assertion failures. No
test-only keepalive, hidden skip, campaign-runtime fix, push, or merge is
included in this slice. CI must not be described as green.

Verification for this slice:

- 53 distinct source-check, input-reader, CLI, evaluation, and capability tests
  pass on Windows Node 20.20.2 and Node 24.13.0. Following the final binding
  review, the 32 affected checker/CLI/evaluation tests were rerun successfully;
  the unchanged input-reader and registry checks had already passed.
- The 47 fixture/normalizer/evidence regressions pass on both Node versions.
- 27 adjacent readiness and release-wiring tests pass on Node 24.
- Lens lint and generated topic, benchmark, and capability drift checks pass.
- All 24 synthetic case expectations match, including 8 expected abstentions.
  The first run exposed a scalar-read classification bug; the checker was
  corrected without changing the corpus. These are now regression cases,
  not held-out accuracy evidence.
- Test-first regressions and the final code review also corrected Unicode
  path disagreement, loop/destructuring writes, assignment-based namespace
  escapes, and extra-rule precision accounting. No dependencies were added.

This is focused local verification, not a fresh full-suite or Linux CI pass.
The prior full-suite result below describes the earlier tree only.

## Preceding assessment-support slice

This pass adds reporting, measurement, and review handoffs across the six
recommendations. It does **not** complete all six recommendations or add a new
automated security analyzer. The table distinguishes implemented support from
the capabilities that remain open.

| Recommendation | Delivered in this pass | Remaining work |
|---|---|---|
| 1. Independently verified findings | `verdict` describes saved evidence, proof-job state, claimed verdicts, and unmet verification requirements. | A controller-authenticated semantic verifier. The report explicitly returns `semantic_verifier: NOT_AVAILABLE`; receipt presence and successful execution do not establish a vulnerability or verified fix. |
| 2. Honest accuracy measurement | Per-repeat scorecards, aggregate metric ranges, explicit assessment/abstention counts, primary-outcome binding, and bounded model/harness/corpus metadata. | An independently reviewed corpus and actual analysis measurements. Metadata is caller-declared; synthetic regression tests are not detection-quality results. |
| 3. Supported source-analysis integration | `review-template` creates an inert, packet-bound result template; `check-result` validates a completed submission without ingesting it. | A supported semantic analyzer/provider. A reviewer still supplies analysis; generated templates start at `NOT_PERFORMED` and contain intentionally invalid placeholders. |
| 4. Repair briefs and retesting | `repair-brief` projects saved source references, claim authority, acceptance requirements, and optional baseline/current links. | Structured, reviewed repair recommendations and linked patch/test evidence. The current recommendation is `UNKNOWN`; the command does not patch, execute retests, or verify fixes. |
| 5. Readiness and capability discovery | Static `doctor`, a dependency-free standalone doctor entry point, a shared capability registry, and generated capability documentation. | Runtime readiness remains a separate observation: static checks do not establish Docker daemon, image, worker, or target compatibility. |
| 6. Representative environments and deployment evidence | `doctor --bundle` explains likely environment gaps using recorded filenames and the capability registry. | Additional executable runtime profiles, browser and database-backed stack coverage, and trustworthy current deployment evidence. No new runtime is supported by this pass. |

See [assessment improvements](assessment-improvements.md) for commands and
interpretation, [public capabilities](capabilities.md) for generated release
support declarations, and [benchmark semantics](../benchmarks/README.md) for
measurement denominators and limits.

Verification of these additions exercises controller behavior with local
fixtures, synthetic records, schema checks, and generated-document drift
checks. Passing those checks establishes the tested software behavior; it does
not measure security-analysis effectiveness or independently verify a target.

## Local verification (2026-09-05)

- `npm.cmd test`: 2,610 tests passed, zero failures. One existing Windows
  unsafe-symlink assertion was unavailable because symlink creation was denied;
  its containing test passed and the runner reported zero skipped tests.
- Lens lint, generated topics, generated benchmark cases, generated capability
  documentation, and `git diff --check` passed.
- Synthetic CLI checks verified unchanged bundle bytes after inspection,
  accepted/rejected result preflight, and redacted parser/scope failures.
- The standalone doctor was checked through the installed Codex skill junction;
  its isolated regression test also passed without installed dependencies.

The review fixed provider-error disclosure in the new preflight command,
preserved literal inventory filenames in repair briefs, exposed recorded
triage/remediation claims in human output, and replaced locale-sensitive
doctor ordering with the canonical sorter. No dependencies were added. Live
targets and the optional Docker and dedicated HTTPS conformance commands were
not exercised in this pass. The default suite did run synthetic loopback HTTPS
tests.
