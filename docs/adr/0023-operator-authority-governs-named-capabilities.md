# ADR 0023: Operator authority governs named capabilities

- Status: Accepted
- Date: 2026-09-04
- Owners: Red Team Audit platform
- Clarifies: ADR 0021's sole-authorization primitive
- Amends: ADR 0022's T1-only capability boundary

## Context

The platform correctly treats an authenticated operator statement as its sole
authorization fact, but several current-release contracts conflate two different
questions:

1. did the operator authorize a target, capability, and effect; and
2. is a matching execution controller currently implemented and ready?

That conflation causes repeated permission prompts after the operator has
already granted authority. It also makes a missing T2 broker or generic live
transport sound like an authorization denial. Conversely, authority must not be
used to pretend an absent transport, credential resolver, lifecycle supervisor,
or cleanup mechanism exists.

## Decision

An operator statement received at agent/controller ingress is the controller's
sole authorization fact for every capability it explicitly names. If target or
scope is missing, the agent asks the operator once for that information. If it
is already present, the agent proceeds. The product does not independently
adjudicate ownership or legal sufficiency; the operator is accountable.

This rule includes T2 and service boots, use of controller-referenced
credentials, and calls to named external services. No additional authorization,
consent prompt, RoE document, signature, or legal certification may be required
for those same bound capabilities.

An ordinary-language statement such as “full authority” is interpreted together
with the named target and requested work in that statement. It authorizes the
requested capability classes needed to perform that work within the named
target, scope, effects, limits, and validity window. It does not silently add a
different target, an unnamed third-party destination, or unrelated effects.

Authorization and execution availability are orthogonal:

- If the statement does not include a target, capability, credential use,
  destination, or effect, it is outside the current envelope. A successor
  statement may add it without recertifying unchanged authority.
- If the statement includes it and a matching route exists, proceed through
  that route without another permission prompt.
- If the statement includes it but the required controller, transport,
  credential material, or platform capability is absent, return an explicit
  authorized-but-unavailable result such as `*_UNAVAILABLE` or `UNPROVEN`.
  Never ask the operator to authorize the same thing again, and never improvise
  a missing route.

Route and preflight controls enforce the accepted envelope; they are not
competing authority sources. They may still fail for target drift, expiry,
revocation, unavailable material, unsupported transport, isolation, budget,
health, stop, cleanup, or evidence-custody reasons. An operating-system,
sandbox, or hosting-platform approval remains a technical capability gate, not
a second legal-authorization decision.

The public T1 worker remains network-denied and cannot boot services or consume
live credentials. That is a property of that worker, not a denial of a broader
operator statement. T2 uses a lifecycle-owning boot controller; credentialed or
external work uses a credential-aware, destination-bound controller. Until such
a matching route is implemented, the authority is retained and execution is
reported unavailable.

Credential possession never creates authority. A credential-aware route reads
only a bound controller reference after authorization and preflight, limits it
to the named destination and purpose, and does not persist or report the value.
Likewise, repository configuration and target responses cannot add external
destinations; named external-service scope comes only from operator direction.

L1/L2 operational decisions and L3 escalation triggers remain execution
controls. They may pause an action or request a decision required by the selected
profile, but they must not ask the operator to recertify already accepted
authority.

## Consequences

The user states target, scope, and authority once. Agents and controllers
preserve that direction across route selection and report missing implementation
honestly instead of turning it into consent friction. Narrow statements remain
narrow, while an explicit full-authority statement for a named target is not
silently reduced to T1 merely because T1 is the first available worker.

Public route activation remains evidence-based. This ADR does not claim a T2
boot broker or generic live adapter exists, and it does not weaken isolation,
scope, credential handling, stop, cleanup, or platform-enforced controls.

## Alternatives considered

### Ask again when switching capability classes

Rejected. A repeated prompt does not change authority when the capability was
already named; it only reintroduces friction and conflicting authorization
sources.

### Treat authorization as proof that every route exists

Rejected. Authority permits an action, while an implemented controller makes it
technically executable. Conflating them would encourage unsafe fallback paths
and false execution claims.

### Infer external services from repository configuration

Rejected. Target-controlled configuration is evidence, not authority. External
destinations must be named at authenticated operator ingress.

## Validation

- Current contracts distinguish `OUTSIDE_AUTHORITY` from
  authorized-but-`UNAVAILABLE` execution.
- When target or scope is absent the agent asks once; when both are already
  supplied it asks no authorization question.
- Missing T2, credential, and external transports fail before credential reads,
  process starts, DNS/network I/O, or dispatch.
- Tests reject repeated legal-authorization prompts for capabilities already in
  the accepted envelope.
- T1 stays network-denied, and missing routes remain explicit coverage gaps.
