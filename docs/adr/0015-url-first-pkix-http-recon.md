# ADR 0015: URL-first PKIX identity for operator-attested HTTP reconnaissance

- Status: Accepted for the v0.11 authorized-reconnaissance slice
- Date: 2026-08-04
- Owners: The Last Aperture platform
- Amends: ADR 0014 only for operator-attested TLS identity
- Amended by: ADR 0021 retires the separate signed authorization mode; this
  ADR's URL-first PKIX and optional SPKI-pin decision remains current

> **Current 0.14.1 execution status: active through the bounded controller.**
> Operator-directed `go` and the lower-level `run` route use the URL-first PKIX
> behavior in this ADR. Redirects remain terminal and every resolved destination
> must satisfy the public-address and sealed-identity checks.

> **Supersession notice (2026-09-04):** References below to an externally signed
> authority mode are historical. New authorization comes only from the
> authenticated operator target/scope statement.

## Context

ADR 0014 required an exact TLS SPKI SHA-256 before any network access. That
created a circular gate for ordinary public HTTPS targets: an operator often
needs a TLS connection to learn the current certificate identity, while the
controller refused that connection until the identity was already known.

Certificate discovery as a separate preflight would add an unplanned network
action and could bind a different connection from the one used for the probe.
Silently treating the first observed key as a persistent pin would also
misstate what was independently trusted.

## Decision

Operator-attested planning now needs only the exact HTTPS URL plus the existing
authorization declaration. `HEAD` is the default method. Planning remains
offline and seals one of two explicit TLS policies:

- `PKIX_HOSTNAME`: use the runtime-configured CA trust and normal hostname
  verification; no advance SPKI is supplied.
- `PKIX_HOSTNAME_AND_SPKI_PIN`: perform those same checks and additionally
  require the operator-supplied SPKI SHA-256.

During the action's own TLS handshake, the controller requires certificate
chain authorization and hostname validation, records the selected DNS address,
server name, certificate SHA-256, SPKI SHA-256, and verification mode, durably
commits that identity before request bytes are sent, and then performs the one
sealed action. There is no certificate-discovery request. An observed SPKI is
evidence for that connection, not a new trust pin.

The externally signed mode is unchanged. Its RoE, target-control proof, proof
fetch, and target action remain bound to the exact pre-supplied SPKI pin.

## Integrity and failure semantics

The scope and plan hashes bind the TLS policy. Bundle validation correlates the
pre-dispatch identity, sealed action, committed observation, and report. A TLS
mode change, pin injection or removal, hostname mismatch, untrusted chain,
unauthorized socket, or pinned-key mismatch fails closed. Once request bytes
may have left, missing or contradictory evidence remains
`OUTCOME_UNCERTAIN` and is never retried automatically.

## Consequences and rollback

An operator can point the controller at a normal public HTTPS URL without
first obtaining its certificate key hash. This removes the circular gate but
uses the runtime CA trust as the connection trust anchor, so it does not defend
against a compromised or incorrectly configured trusted CA. An independently
obtained pin remains available when that stronger binding is needed.

Rollback is mode-local: require `PKIX_HOSTNAME_AND_SPKI_PIN` for new
operator-attested plans. Signed-mode artifacts and evidence require no
migration.
