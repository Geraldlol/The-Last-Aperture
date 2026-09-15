# ADR 0029: Target-only autonomous controller

- Status: Accepted
- Date: 2026-09-15
- Extends: ADR 0028

## Context

The unified engagement controller already has durable scheduling, target binding, route registration, stop/recovery behavior, and evidence ledgers. Its public entry point still asks the operator for an attestation file, profile, output directory, route materials, and other controller concerns. The intended product accepts one target and autonomously drives an adversarial campaign through Codex, Claude, or another compatible reasoning provider.

## Decision

The Point-Click-Shoot runtime input will contain only a target descriptor. The controller will resolve it to an exact identity, load controller-owned deployment policy and credentials, freeze the applicable tool registry, and create a digest-bound campaign plan and coverage denominator. The controller will revalidate policy validity and revocation before each dispatch and after recovery; withdrawn authority stops new work and drives reconciliation and cleanup.

A provider-neutral campaign brain may generate competing hypotheses, prioritize work, and propose registered tool actions. Provider output remains inert until the controller validates its schema, target binding, tool ID, parameters, effect budget, prerequisites, and deadline. The controller constructs all invocations and independently verifies exploit claims.

The campaign will continue until the hypothesis frontier is quiescent or every remaining item has an explicit terminal gap. Discoveries may expand the versioned target graph and coverage denominator only when controller checks admit them inside the configured deployment policy. Recoverable branch failures do not stop independent work. Evidence-integrity failures, ambiguous mutation delivery, or uncertain cleanup halt new dispatch.

The first vertical slice targets a remote HTTPS website or API. It uses existing bounded reconnaissance, automatic run storage, and complete capability/gap inventory. It retains the provider-neutral proposal contract, while provider hypothesis execution remains a future route. Local-repository analysis is not a prerequisite.

## Consequences

- The normal run has one input and one action.
- Authorization forms, profiles, output paths, and route configuration disappear from the run flow.
- Engagement authority and effect limits become controller deployment concerns that targets and models cannot change.
- Reasoning agents can pursue attacker-style chains without becoming evidence or execution authorities.
- Completion can include explicit gaps; the controller does not promise universal vulnerability absence.
- New target families and tools plug into stable resolver, proposal, registry, proof, and coverage contracts.
- Existing route and ledger controls remain authoritative and backward-compatible.

## Rejected alternatives

### Put target interpretation and execution directly in a model prompt

This makes prompt injection, target drift, arbitrary command execution, and fabricated proof part of the controller boundary.

### Ask for authorization and profiles on every run

This violates the target-only product contract. Controller deployment policy supplies those limits without adding run-flow ceremony.

### Start with local repository analysis

The north star is a live target of any kind. The first slice must prove the remote target-only path.

### Treat a completed tool or confident provider response as proof

Neither establishes the tested invariant, control observation, exact target binding, cleanup, or reproducibility required for a verified exploit.
