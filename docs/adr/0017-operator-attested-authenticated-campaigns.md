# ADR 0017: Operator-attested authenticated campaigns

- Status: Accepted - implemented in v0.12.0
- Date: 2026-08-17
- Owners: The Last Aperture platform
- Amends: ADR 0016 authorization routing, runtime command names, and reporting
  nonclaims. ADR 0016 still governs transport, discovery, mutation, rollback,
  browser-session, evidence, and ledger mechanics.
- Amended by: ADR 0021, which makes the operator statement the sole authority
  primitive and retires separate signed/document authority modes and external
  mutation countersignatures

> **Supersession notice (2026-09-04):** The operator-statement path and its
> nonclaims remain current. References below to separate written/signed authority
> modes, pinned approvers, or caller-supplied countersignatures are historical;
> optional governance bytes are evidence only and controller action permits
> carry technical integrity and replay state.

> **Release amendment (2026-09-04):** public fixed, already-sealed campaign
> execution is active through the authenticated controller. It uses a locally
> append-only, hash-chained ledger for every action, refuses adaptive discovery,
> and accepts at most 256 sealed actions. The packaged Chrome companion remains
> disabled; a separately supplied protocol-compatible companion may use the
> browser bridge. The `plan-attested` invocation is itself the explicit operator
> authorization statement; no repeat flag or legal-proof file is required.

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

- `plan-attested`
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
domain-separated canonical sealed authorization object. The controller accepts
the operator's explicit statement as its authorization fact. The digest detects
later changes and supplies technical integrity; it is not independent proof of
the operator's underlying legal authority.

### Classification and authorization scope

The operator-attested route may represent operator-owned or third-party-owned,
production or non-production, and PHI/non-PHI/unknown target classifications.
Those classifications force the matching explicit permission booleans into the
sealed scope; they do not upgrade the assurance level. A target containing PHI
does not permit PHI test payloads: request identifiers and bodies remain synthetic
non-PHI, and the existing non-persistence boundary remains in force.

The operator remains accountable for underlying authorization. The controller
does not demand or interpret a vendor program, disclosure page, contract, email,
or other legal-proof source after the explicit statement. It makes no independent
claim about legal sufficiency or whether the declared scope matches external terms.

### Execution and ledger gates

`campaign-attested` requires the exact sealed scope, matching
`campaign_grant_sha256`, matching operator id, ordinary action window, and an
explicit controller launch approval supplied by the live CLI invocation. It does
not ask for a repeated legal-attestation flag. It rereads and revalidates the scope
immediately before every ordinary dispatch. After `validity.not_after`, it can only resume a
ledger-proven, approval-consumed mutation's rollback and rollback verification
before `validity.cleanup_not_after`; it cannot enqueue or send new work. That path
durably records `CLEANUP_SESSION_CONFIRMED`, never a new ordinary
`CAMPAIGN_SESSION_CONFIRMED`. There is no external revocation signal.

The public route accepts only the fixed sealed request list, refuses a scope with
discovery enabled, and caps that list at 256 actions. The internal discovery
kernel remains bounded by the sealed origin, path, method, category, synthetic
substitutions, and data-handling rules but is not exposed by these commands.
Write-capable or body-bearing probes and all mutation actions require explicit
mutation permission. Mutations additionally
retain a pinned approver, fresh one-use countersignature,
before/after and sibling-context verification, inverse rollback, rollback
verification, locally append-only hash-chained ledger sequencing, and no-retry
treatment of ambiguous delivery. Detecting cross-restart rollback or
valid-prefix truncation requires the operator to retain the last trusted record
count and head digest outside the ledger directory and supply both on reopen;
the local chain alone cannot detect whole-ledger rollback to a valid prefix. An
approver signature proves possession of the enrolled key. It
does not verify the approver's identity or independence; it also does not verify
vendor authorization.

The attested route supports the same sealed credential transports as the written
route. With a separately supplied protocol-compatible companion, a Chrome
active-tab scope keeps the browser-held session in Chrome and requires one
explicit extension attach per campaign. That route relies on browser-managed DNS
rather than the native transport's all-answer validation and socket IP pinning.
An exported credential may instead use a sealed `env:` reference or redirected
`--credential-stdin`.

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

The separate `campaign-stop` command writes a grant/operator-bound out-of-band
request. A running campaign consumes it as `CAMPAIGN_STOPPED` before another
action is dispatched; it cannot retract bytes from a request already sent.

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
