# Adversarial validation task list

## Task 1: Separate vulnerability proof from remediation

- [x] Acceptance: reproduced attack plus valid control is `CONFIRMED` without a patch.
- [x] Acceptance: optional patch result is reported independently.
- [x] Verify: `node --test test/proof-evidence.test.mjs test/report-sarif.test.mjs`.
- Files: `schemas/finding.schema.json`, `scripts/lib/proof-evidence.mjs`, focused tests.

## Task 2: Bound the repository proof runner

- [x] Acceptance: wall timeout terminates a hung child and marks the result inconclusive.
- [x] Acceptance: stdout/stderr are capped with an explicit truncation marker.
- [x] Acceptance: concrete replay evidence survives mirror cleanup.
- [x] Verify: `node --test test/proof-execution.test.mjs test/run-proof-command.test.mjs`.
- [x] Containment: public `audit run-proof` is disabled before bundle/config
  access until a controller-attested network-denied, credential-scrubbed sandbox
  with descendant termination is available.
- Files: `schemas/proof-config.schema.json`, proof execution/CLI, focused tests.

## Task 3: Define strategy-neutral live plan and operator authorization

- [x] Acceptance: schemas reject unknown, oversized, or incomplete plans and
  controller permits.
- [x] Acceptance: the accepted operator statement and controller permit bind
  exact canonical plan bytes, target, scope, and expiry.
- [x] Acceptance: plan drift or a caller-authored permit is refused.
- [x] Verify: focused plan, operator-ingress, and permit lifecycle tests.
- Files: plan/operator-authorization schemas, contract modules, focused tests.

## Task 4: Add governed scope expansion

- [x] Acceptance: an out-of-scope candidate emits an inert scope-expansion request.
- [x] Acceptance: only a new authenticated operator statement lets the
  controller create a predecessor-bound scope revision.
- [x] Acceptance: an approved scope delta does not approve a changed or undisclosed attack.
- [x] Verify: scope-request, scope-ledger, signature, and no-I/O escape tests.
- Files: scope request/revision schemas, approval kernel, focused tests.

## Task 5: Add graduated autonomy and safety preflight

- [x] Acceptance: autonomy profiles encode distinct operational-decision cadence
  and limits after the operator statement is accepted.
- [x] Acceptance: `L3_MAXIMUM_AUTHORIZED` refuses to start when any mandatory safety preflight is absent or unhealthy.
- [x] Acceptance: mandatory escalation triggers pause even a maximum-authority campaign.
- [x] Acceptance: L3 agents choose tactical subtargets and chains inside a broad
  controller-sealed operator-declared authorized-target predicate without additional prompts, checkpoint progress,
  and continue unrelated branches when one branch needs more scope.
- [x] Acceptance: a signed one-use `BREAK_GLASS` decision can waive only the
  hardcoded overridable controls, never scope, the current campaign receipt, finite budgets,
  revocation, or the operator kill switch.
- [x] Verify: autonomy, supervised checkpoints, fail-closed pause, kill-switch,
  control-plane-loss, and break-glass non-bypass tests.
- [ ] Product activation: wire controller-owned L3 preflight, durable ledger,
  checkpoint, adaptive proposal, and trusted transport providers into the
  public CLI. Until then the CLI refuses L3 before nonce consumption or I/O.
- Files: autonomy/break-glass schemas and kernels, preflight controller, focused tests.

## Task 6: Gate active live scanning

- [x] Acceptance: active scan planning performs no target I/O.
- [x] Acceptance: execution without a current exact controller permit performs
  zero target I/O.
- [x] Acceptance: approved actions are still checked by the bounty scope kernel.
- [x] Verify: scanner-controller and local-testbed tests. The existing bounty
  CLI intentionally has no route to inject approval authority or nonce storage,
  so crafted live scans currently refuse rather than execute.
- [x] Active routes: an exact bounded HTTPS action through `adversarial go` or
  `http-recon-v1`, plus fixed sealed `http-authed-v1` campaigns whose attempted
  actions and outcomes are recorded in the durable campaign ledger.
- [x] Containment: `audit run-proof`, `audit run-provider`, `audit run-remote`,
  transparency publication, every evidence-acquisition command, audit
  evidence-bundle import and source sealing, database-conformance run, `bounty recon run`, `bounty
  scan run`, `bounty authz run`, standalone authenticated-HTTP probes,
  discovery-derived action dispatch, and every OOB session command are
  disabled before process/target traffic (and before caller paths, sensitive
  artifacts, credentials, bundles, sessions, or state are read where relevant).
- [ ] Product activation: enumerate and migrate every network-capable legacy
  active-testing route to authenticated operator ingress and the
  controller-permit boundary.
- Files: scanner planner/controller, bounty CLI, focused tests.

## Task 7: Normalize and report active evidence

- [x] Acceptance: caller-asserted attack, control, target, authorization, limits, and
  replay digests appear in a record explicitly labeled unauthenticated and
  `CLAIMED_*`; the formatter cannot promote a finding.
- [x] Acceptance: the bounded public claim omits locator, header, body, and known
  private-capture fields and rejects test-supplied sensitive values. Generic
  secret discovery and protected raw-evidence custody remain open controller
  requirements.
- [x] Verify: standalone adversarial-evidence renderer and secret-leak tests.
- [ ] Integration: connect T4 evidence to the legacy T0-T3 finding/report path
  only after controller-signed execution attestations bind operator-statement
  receipt and permit consumption, prepared actions, observations, trusted
  oracle results, replay lineage, and an externally anchored ledger head.
- Files: evidence normalizer, report renderer/controller, focused tests.

## Task 8: Add fuzz strategy providers

- [x] Acceptance: structured Node properties retain seed, path, and concrete minimized value.
- [ ] Acceptance: coverage-guided provider is optional, pinned, isolated, and replayable.
- [x] Acceptance: coverage/sample exhaustion never clears a vulnerability class.
- [x] Verify: structured-provider conformance, bounded async, and vulnerable/clean semantics.
- Files: strategy registry, provider adapter(s), fixtures/tests, package/provider lock.

## Final checkpoint

- [x] `npm.cmd test -- --test-reporter=spec` passes (2,295/2,295; no skips).
- [x] `npm.cmd run test:adversarial` passes (199/199).
- [x] `npm.cmd run lint` passes.
- [x] `npm.cmd run gen` leaves generated files consistent.
- [x] Independent pre-PR findings were resolved with no remaining static/offline
  handoff blockers. Production activation blockers are recorded in the design,
  ADR, and CTO brief; public generic live/L3 remains fail-closed until they are
  resolved and reviewed.
