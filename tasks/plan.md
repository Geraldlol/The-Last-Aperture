# Target-Only Autonomous Controller — Implementation Plan

## Objective

Accept one target, unleash a provider-neutral adversarial campaign, exhaust every applicable registered strategy, and return independently verifiable findings plus exact coverage gaps.

Source of truth: `docs/design/2026-09-15-target-only-autonomous-controller.md`.

## Product contract

- Runtime input: one target descriptor.
- Runtime action: Unleash.
- No local-repository prerequisite, attestation form, profile picker, route picker, output-path choice, or JSON editing.
- Codex, Claude, and later providers use one typed proposal protocol.
- Models explore and chain hypotheses; the controller alone binds targets, admits tools, executes effects, verifies proof, and records evidence.
- A finding never ends the campaign. Verified footholds expand the frontier until every reachable branch is terminal.

## Constraints

- Preserve existing route-registry, fixed-invocation, action-risk preflight,
  durable permit, Pause/Stop, recovery, output-binding, and append-only ledger guarantees.
- Keep deployment authority, credentials, effect limits, and retention policy outside target intake.
- Treat target responses and provider output as untrusted data.
- Do not silently widen destinations or let providers construct commands.
- Keep unsupported capabilities visible and fail-closed.
- Build test-first in small vertical slices on the isolated feature branch.

## Phase 1 — Target and campaign contracts

1. Map the existing HTTPS resolver, route registry, engagement scheduler, and adversarial proposer seams.
2. Add a target-only campaign-intent schema.
3. Add a deterministic campaign-plan schema with target, registry, policy, provider-protocol, route dispositions, budgets, gaps, and digest.
4. Add a provider-neutral campaign-proposal schema for hypotheses and typed tool actions.
5. Implement canonical planning from one HTTPS/API target.
6. Enumerate every registered route as ready, waiting, unavailable, or not applicable.
7. Add target binding, determinism, provider-injection, and false-proof tests.

## Phase 2 — First remote shot

1. Add `engage unleash <https-target>` with an app-owned run directory.
2. Load controller deployment policy and provider configuration without adding run-form fields.
3. Execute the existing bounded HTTPS reconnaissance route.
4. Convert verified reconnaissance into a sealed provider packet.
5. Accept evidence-linked provider hypotheses as candidates.
6. Expose progress, detection context, confirmation, Pause/Resume, rollback,
   Stop, findings, route inventory, and gaps from one verified snapshot.
7. Validate end to end against a deterministic synthetic HTTP target.

## Phase 3 — Autonomous web/API swarm

1. Add same-origin discovery of pages, scripts, forms, OpenAPI, GraphQL, and API routes.
2. Run specialized campaign agents in parallel: perimeter, identity, API, data, client, exploit verifier, and skeptic.
3. Let agents rank and chain hypotheses against a frozen typed tool registry.
4. Add machine-verifiable attack/control oracles, cleanup contracts, and replay records.
5. Continue from every verified foothold until the frontier is exhausted or every remaining branch has an explicit gap.
6. Evaluate known-positive and known-negative targets independently.

## Phase 4 — Point-Click-Shoot cockpit

1. Build the hosted campaign control plane and a narrow local bridge only where browser/device/process access requires it.
2. Implement target field, saved-target double-click, Unleash, live graph,
   frontier, proof levels, detection context, Pause/Resume, rollback, Stop,
   gaps, and exports.
3. Add snapshot-bound pagination and exact GUI/CLI classification parity.
4. Package the optional local bridge and verify artifacts from the exact release commit.

## Phase 5 — Any target

1. Add database endpoint and managed-database adapters.
2. Add cloud resource and estate adapters.
3. Add network-service adapters.
4. Add binary/process/device adapters through enrolled workers.
5. Add repair generation, controlled application, ordinary regression, security replay, and verified cleanup.
6. Add team tenancy, identity, retention, audit, and remote-worker isolation.

## Definition of done for Phase 1

- One HTTPS/API target produces one deterministic, schema-valid, digest-bound campaign plan.
- The plan contains one explicit disposition for every route in the frozen registry.
- Provider proposals cannot alter target, policy, registry, budgets, or proof state.
- Candidate findings must reference admitted evidence and remain candidates until an independent verifier promotes them.
- Existing commands and tests remain compatible.
