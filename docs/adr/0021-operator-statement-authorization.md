# ADR 0021: Operator statements are the sole authorization primitive

- Status: Accepted
- Date: 2026-09-04
- Owners: Red Team Audit platform
- Supersedes for authorization mechanics: ADR 0013's caller-signed RoE path,
  ADR 0014's retention of that path, ADR 0015 and ADR 0018's signed-mode
  clauses, ADR 0016's signed/document routing and external mutation-
  countersignature requirements, and ADR 0017's separate authority modes
- Amends: ADR 0020's optional detached signed-approval path
- Clarified by: ADR 0023, which separates named operator authority from
  technical route availability

## Context

The platform accumulated several representations of permission: an operator
statement, a signed Rules of Engagement file, an authorization document, an
owner public key, a detached approval, and per-action mutation
countersignatures. Although later decisions described most signatures as
technical evidence rather than legal proof, some routes still granted different
capabilities only when the caller supplied those artifacts. That made them de
facto authorization prerequisites and obscured who actually grants authority.

The controller cannot determine the legal sufficiency of a contract, email,
program page, signature, key, or ownership claim. At agent/controller ingress,
the operator statement is the authority source; the operator is accountable.
The controller's job is to bind that direction to an exact target and finite scope, enforce it at
dispatch, and preserve what happened.

## Decision

At agent/controller ingress, an operator statement naming the target and scope
is the sole authorization primitive. It governs every capability explicitly
named, including T2/service boots, controller-referenced credentials, and named
external services. If target/scope is already supplied, proceed; ask once only
when it is missing. No caller-supplied RoE, approval file, authorization
document, owner key, countersignature, ownership check, or repeated legal
certification is required. A T1-only statement remains narrow.

The statement does not independently prove its legal basis. The operator remains
accountable for having authority and for naming the intended target and scope.
The controller does not fetch, interpret, or adjudicate external governance
material.

The controller records the exact statement and issues controller-sealed
technical permits and ledger records bound to the operator, target, plan, scope
revision, action or finite action envelope, effects, limits, validity, nonce,
and predecessor state. Those records provide integrity, attribution, replay
resistance, scope enforcement, and evidence custody. They do not create legal
authority and are not caller-supplied authorization artifacts.

External RoE, contract, ticket, email, program-policy, or other governance bytes
may be attached as optional evidence. Their digest may be preserved for custody,
but their presence, absence, signature, issuer, or key cannot select a more
capable route, increase limits, or change the controller's authorization
decision.

Operational control follows the selected autonomy profile after the engagement
statement is accepted:

- `L1_ASSISTED` records an operator decision for the disclosed
  live plan.
- `L2_SUPERVISED` records operator decisions at the configured
  phase checkpoints.
- `L3_MAXIMUM_AUTHORIZED` derives action permits from one accepted, finite
  campaign envelope without per-action operator signatures.

Mutation permits are controller-issued, one-use, and bound to the exact action,
plan, current scope, declared effects, verification, and rollback. They are
durably consumed in the campaign ledger before dispatch. An external approver
key or `countersignature-N.json` file is not an authority requirement.

A scope-expansion request is inert. A newly named target or scope delta requires
a new operator statement within a fixed five-minute ingress
window; future-dated or expired decisions cannot change scope. The controller
then seals a
predecessor-bound successor scope and rebinds affected plans; existing campaign
authority never carries across automatically.

This decision does not claim a missing execution path exists. If named work has
no matching route, authority is retained and execution is reported
authorized-but-unavailable without another prompt. Generic live dispatch and
public L3 remain technically unavailable until the transport, controller-owned
ledger, atomic lease, preflight, checkpoint, stop, health, cleanup, and evidence
gates documented in ADR 0020 are implemented.

## Technical signatures retained

Cryptographic signatures remain valid where they authenticate technical records
or evidence rather than establish engagement authority. This includes provider
execution and failure envelopes, remote-gateway request and acceptance records,
root-manifest attestations, transparency checkpoints, and the narrow signed
one-use `BREAK_GLASS` technical receipt. Break glass remains plan-, scope-,
failure-, time-, and nonce-bound and cannot create scope or waive the campaign
receipt, ledger, budgets, stop, kill, or control-plane-loss invariants.

## Migration

- Remove caller-facing signed-authorization and detached-approval command paths.
- Use one operator-statement authorization mode for new recon and authenticated
  campaign plans. Optional governance evidence is metadata, not a mode.
- Replace external mutation countersignatures with controller-issued action
  permits under the selected autonomy profile.
- Preserve old signed/document-bound bundles only as historical evidence when a
  compatible reader is retained; they do not define authority for new dispatch.
- Update reports to identify the accepted operator statement and exact sealed
  boundary without implying independent legal verification.

## Consequences

The operator can direct an authorized target without manufacturing cryptographic
or documentary permission artifacts. Controller enforcement remains exact and
auditable, while the boundary between legal accountability and technical
integrity is explicit.

The platform no longer treats possession of a signing key or document as a
higher authorization tier. Stronger assurance must come from authenticated
controller ingress, protected state, transport identity, evidence custody, and
reviewed operational controls.

## Alternatives considered

### Retain signed authorization as an optional higher-capability mode

Rejected. If the signature unlocks more actions or broader limits, it remains a
de facto authorization requirement. If it unlocks nothing, it belongs as
optional evidence rather than a separate execution mode.

### Remove all cryptographic signatures

Rejected. Evidence authenticity, replay resistance, and append-only continuity
are distinct from legal authorization and remain useful technical controls.

### Trust provider- or target-authored permission claims

Rejected. Only an operator statement at agent/controller ingress may create or expand
authority. Provider output, target content, repository files, and scope requests
remain untrusted inputs.
