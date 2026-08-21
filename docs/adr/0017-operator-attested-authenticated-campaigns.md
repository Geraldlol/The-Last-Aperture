# ADR 0017: Operator-attested authenticated campaigns

- Status: Accepted - implemented in v0.12.0
- Date: 2026-08-17
- Owners: Red Team Audit platform
- Amends: ADR 0016 authorization routing, runtime command names, and reporting
  nonclaims. ADR 0016 still governs transport, discovery, mutation, rollback,
  browser-session, evidence, and ledger mechanics.

## Context

ADR 0016 defined `OPERATOR_ATTESTED_AUTHED` as a lower-assurance type but its
initial released planner and runtime accepted only document-bound
`WRITTEN_AUTHORIZATION_AUTHED`. That made an authorization document a technical
prerequisite even when an operator already held permission under a bug-bounty or
security-testing engagement whose authorization was not supplied as a bounded
file.

Creating a synthetic "authorization document" would add no assurance. An
operator-entered authorizer name or program reference also does not prove vendor
permission, ownership, legal authority, scope coverage, or revocation status. The
controller needs a distinct route that records exactly what the operator attests,
keeps that lower assurance visible, and preserves every existing execution gate.

## Decision

### Distinct commands and evidence

The released lower-assurance route is selected only through:

- `plan-attested --attest-authorized`
- `validate-attested`
- `campaign-attested`

`plan-attested` requires the operator id, declared authorizer, authorization
reference, action deadline, cleanup deadline, exact HTTPS origin, path prefixes,
methods, test categories, environment, data class, ownership, permissions,
credential binding, and actions. Simple probes use `--seed-url`; full probe or
mutation plans use `--requests <absolute-requests.json>`. `--cleanup-not-after`
defaults to `--not-after` and never extends authority for new work. Planning
performs no network activity. It rejects
`--authorization-document`, `--document-issuer`, and `--document-issued-at`.
Validation also needs no credential or network access.

The sealed authorization uses mode `OPERATOR_ATTESTED_AUTHED`, the fixed statement
"I confirm that I am authorized by the asset owner to perform these exact bounded
authenticated HTTP actions.", and `independently_verified: false`. Planning emits
`red-team-audit/http-authed-attested-plan`; validation emits
`red-team-audit/http-authed-attested-validation`. Public summaries and campaign
ledger records bind the mode-specific authorization as
`authorization_binding_sha256`. They do not invent, emit, or persist an
`authorization_document_sha256` field for this route.

`authorization_binding_sha256` for the attested route is the SHA-256 of the
domain-separated canonical sealed authorization object. It detects later changes
to the recorded declaration; it does not prove that the declaration is true.

### Classification and authorization scope

The operator-attested route may represent operator-owned or third-party-owned,
production or non-production, and PHI/non-PHI/unknown target classifications.
Those classifications force the matching explicit permission booleans into the
sealed scope; they do not upgrade the assurance level. A target containing PHI
does not permit PHI test payloads: request identifiers and bodies remain synthetic
non-PHI, and the existing non-persistence boundary remains in force.

The operator must actually possess authorization for every declared action. The
CLI attestation records that claim; it neither creates permission nor fetches,
interprets, or verifies a vendor program, disclosure page, contract, email, or
other authorization source. The controller makes no claim about legal sufficiency
or whether the operator's declared scope matches external terms.

### Execution gates remain unchanged

`campaign-attested` requires the exact sealed scope, matching
`campaign_grant_sha256`, matching operator id, ordinary action window, and
`--confirm-authorization-current`. It rereads and revalidates the scope immediately
before every ordinary dispatch. After `validity.not_after`, it can only resume a
ledger-proven, approval-consumed mutation's rollback and rollback verification
before `validity.cleanup_not_after`; it cannot enqueue or send new work. That path
durably records `CLEANUP_SESSION_CONFIRMED`, never a new ordinary
`CAMPAIGN_SESSION_CONFIRMED`. There is no external revocation signal.

Discovery remains bounded by the sealed origin, path, method, category, synthetic
substitutions, and data-handling rules. Write-capable or body-bearing probes and
all mutation actions require explicit mutation permission. Mutations additionally
retain a pinned approver, fresh one-use countersignature,
before/after and sibling-context verification, inverse rollback, rollback
verification, immutable ledger sequencing, and no-retry treatment of ambiguous
delivery. An approver signature proves possession of the enrolled key. It does not verify the approver's identity or independence; it also does not verify vendor authorization.

The attested route supports the same sealed credential transports as the written
route. A Chrome active-tab scope keeps the browser-held session in Chrome and
requires one explicit extension attach per campaign. An exported credential may
instead use a sealed `env:` reference or redirected `--credential-stdin`.

### Reporting and nonclaims

Every attested plan, validation, campaign result, ledger, and report exposes
`OPERATOR_ATTESTED_AUTHED` and `independently_verified: false`. Reports state that:

- authorization is an operator declaration only;
- the named authorizer and reference were recorded but not independently checked;
- vendor/program permission, ownership, legal authority, external scope coverage,
  and revocation status were not verified;
- the authorization binding proves only that the same sealed declaration was used;
- no result is a legal opinion, vendor approval, compliance attestation, or claim
  that the target is clean, safe, or secure.

`WRITTEN_AUTHORIZATION_AUTHED` remains a separate document-bound route. It checks
the supplied document digest and the sealed permission extraction, but still does
not cryptographically verify issuer identity or judge legal sufficiency.

## Consequences

Positive: an authorized operator can run a durable, scope-bounded authenticated
bug-bounty campaign without manufacturing or repeatedly supplying a document that
the controller cannot authenticate. The selected assurance mode and its limits are
machine-visible throughout planning, execution, and reporting.

Cost: the controller cannot distinguish a truthful attestation from a false one.
The operator is responsible for retaining the real authorization and staying
inside it. Misstating authority is an operator/governance failure, not an assurance
provided by this software.

## ADR 0016 amendments

This ADR supersedes only these ADR 0016 statements:

- the routing matrix restriction that limited `OPERATOR_ATTESTED_AUTHED` to
  operator-owned, non-production, non-PHI work;
- the statements that production, PHI, third-party, or mutation classifications
  necessarily select written or externally signed authorization;
- the `campaign-written`/`validate-written`-only runtime wording; and
- the `(non-production only)` qualification in the operator-attested mutation
  discussion.

All ADR 0016 technical action, mutation, cleanup, browser, evidence-handling,
ledger, and uncertainty requirements remain in force.

## References

- ADR 0014: operator-attested HTTP reconnaissance
- ADR 0016: authenticated, scope-bounded active HTTP testing
- `schemas/http-authed-scope.schema.json`
