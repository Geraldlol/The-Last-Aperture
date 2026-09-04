# Implementation Plan: Adversarial validation engine

## Overview

Unify repository proof and authorized live testing behind a strategy-neutral
evidence contract. The first vertical delivery corrects proof semantics and
resource bounds, then binds the authenticated operator target/scope statement to
controller-issued technical permits for the existing live scanner, and finally
emits normalized report evidence. Fuzzing is delivered as a strategy adapter,
not a separate vulnerability lens.

## Architecture decisions

- Keep existing lenses/topics as the vulnerability taxonomy.
- Add strategy metadata and normalized attack/control observations.
- Accept the authenticated operator target/scope statement as the sole authority
  primitive and bind canonical plan bytes into controller-issued permits.
- Reuse the bounty scope kernel and transport instead of creating another egress
  path.
- Keep remediation separate from confirmation.

## Dependency graph

```text
proof/finding semantics + bounded process runner
                    |
strategy-neutral plan/evidence schemas
                    |
operator-statement binding + permit lifecycle tests
                    |
scope request + successor-scope ledger
                    |
graduated-autonomy campaign envelope + safety preflight
                    |
existing scanner plan/gate integration
                    |
normalized report output
                    |
fuzz-provider adapters and additional target transports
```

## Phases

### Phase 1: Executed proof truthfulness

- [x] Confirm an attack reproduction with a valid control without requiring a
  patch.
- [x] Track optional remediation independently.
- [x] Bound proof process time and output, and preserve a replay artifact.

### Checkpoint

- [x] Focused proof/evidence/schema tests pass.
- [x] Existing Critical/High proof gates still require T1/T2 executed evidence.

### Phase 2: Operator-controlled live execution

- [x] Define canonical live plan, operator-statement, and technical-permit
  contracts.
- [x] Prove exact target/plan/scope binding, expiry, drift refusal, and one-use
  consumption.
- [x] Add inert scope-expansion requests and predecessor-bound successor scopes.
- [x] Add `L1_ASSISTED`, `L2_SUPERVISED`, and `L3_MAXIMUM_AUTHORIZED` contracts;
  maximum authority remains disabled until every required safety control passes.
- [x] Split the scanner into plan and run; perform zero active I/O without an
  operator-authorized plan and matching controller permit.

### Checkpoint

- [x] Controller tests prove operator statement -> sealed plan -> controller
  permit -> scoped local-testbed attack.
- [x] Scope, role, rate, mutation, and redirect escape tests pass.
- [ ] Expose authenticated operator ingress and controller-owned permit state
  through the bounty CLI; its crafted live command currently refuses safely
  because those controller services are not deployed.

### Phase 3: Evidence and strategy breadth

- [x] Normalize caller-asserted live attack/control/replay fields into a
  standalone bounded, redacted claim record and Markdown renderer. It is
  explicitly unauthenticated and cannot promote a finding to T4.
- [x] Add the initial strategy-neutral runtime and built-in structured-fuzz adapter.
- [x] Add structured property fuzzing with deterministic minimized replay data.
- [ ] Add isolated coverage-guided and schema-driven API fuzz providers.
- [ ] Replace the standalone claim projection with authenticated T4 evidence,
  then connect it to the legacy report pipeline and adaptive campaign-ledger
  observations.

### Checkpoint

- [x] A vulnerable structured-fuzz fixture produces a minimized reproducer;
  caller-supplied adversarial assertions produce a separately tested redacted,
  non-promotable claim draft.
- [x] Full tests, adversarial tests, lens lint, generated registry, and focused
  documentation/contract checks pass.

## Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| A model can self-authorize | Critical | Only authenticated operator ingress creates authority; the controller seals the exact statement |
| Plan changes after authorization | Critical | Canonical JSON digest bound into the controller permit and rechecked before each action |
| Scope bypass through redirects or generated cases | Critical | Re-run the pure scope kernel on each concrete action before I/O |
| Agent request is mistaken for authority | Critical | Distinct request/decision schemas; only a new authenticated operator statement creates a controller-sealed successor scope |
| Maximum-authority mode becomes unbounded | Critical | Sealed action categories, mandatory escalations, health monitor, kill/failsafe, and fail-closed pause |
| Active proof harms production | High | Explicit risk class, finite budgets, health stop, kill state, mutation cleanup |
| Fuzzer hangs or floods evidence | High | Process, case, output, request, response, and wall-time bounds |
| Report leaks credentials/data | High | Public claim output omits locators, headers, bodies, and supplied sensitive values; controller-owned credential references and protected raw-evidence storage remain activation gates |
| Backward compatibility breaks historical bundles | Medium | Additive schema versions and fixtures for legacy read/report paths |

## Release gates still open

- Public L3 activation needs controller-owned preflight, checkpoint, adaptive
  proposal, durable-ledger, and trusted-transport providers.
- Generic live execution needs a reviewed transport/adapter contract and
  protected controller provisioning; callers cannot inject either today.
- Hard termination of a non-cooperative adapter needs worker/process isolation.
- T4 evidence needs authenticated controller attestations, independent replay
  lineage, protected custody, an external ledger anchor, and only then
  legacy-report/adaptive-ledger integration.
- Coverage-guided and schema-driven API providers remain later slices.
- Passkeys, a dashboard, multi-approver policies, and non-HTTP transports remain
  later milestones.
