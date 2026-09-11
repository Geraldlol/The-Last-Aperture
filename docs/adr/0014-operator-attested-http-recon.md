# ADR 0014: Operator-attested authorization for one external HTTP action

- Status: Accepted for the v0.11 authorized-reconnaissance slice
- Date: 2026-08-04
- Owners: The Last Aperture platform
- Amends: ADR 0013; amended by ADR 0021, which retains operator-statement
  authority and retires the externally signed authorization mode
- Amended by: ADR 0015, which removes the mandatory advance SPKI pin from
  operator-attested planning

> **Current 0.13.0 execution status: active through the bounded controller.**
> `go <exact-https-url>` records the operator invocation as the authorization
> declaration and executes one sealed action without a second attestation step.
> The declaration is not independent proof of permission; exact-target and
> transport containment remain controller-enforced.

The inline-SPKI requirement below records the original decision. ADR 0015
supersedes that requirement with an explicit `PKIX_HOSTNAME` default while
retaining optional pinning. References below to a separate signed authority mode
are historical under ADR 0021.

> **Supersession notice (2026-09-04):** The authenticated operator statement is
> now the sole authorization primitive. Caller-supplied signed RoE, document,
> owner-key, and target-proof artifacts are not a second authority path.

## Context

ADR 0013 required a signed RoE JSON file, the authorization document bound by
that RoE, an independently pinned owner Ed25519 public key, and a live signed
target-control proof. That is the higher-assurance path, but it prevents an
operator from starting even a narrowly bounded external observation when an
asset owner has granted permission through an ordinary business channel and
has not provisioned those machine-verifiable artifacts.

Removing only the three file arguments would be incoherent: the owner key also
authenticates the live proof, the proof pins DNS continuity, and both are part
of observation and completion evidence. A no-file route therefore needs an
explicitly different authorization mode and must not inherit the signed mode's
claims.

[OWASP APTS scope enforcement](https://owasp.org/APTS/standard/1_Scope_Enforcement/)
requires machine-readable RoE authorization proof for conforming autonomous
testing. [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final) uses an
approved assessment plan and Rules of Engagement as its planning baseline.
Operator attestation is deliberately lower assurance and this project claims
conformance with neither source.

## Decision

Add `OPERATOR_ATTESTED` as the default `http-recon-v1` planning mode. It needs
no signed RoE, authorization-document, or owner-key path. The operator supplies
before planning:

- one exact credential-free public HTTPS URL and one `HEAD`, `GET`, or
  `OPTIONS` method;
- the exact target TLS SPKI SHA-256 inline;
- operator identity, the declared authorizer, and an authorization reference;
  and
- an explicit authorization attestation. `GET` also needs a separate
  safe-to-get acknowledgment.

The controller constructs and durably writes `attested-scope.json` without
network activity. It seals exactly one action, fixed controller limits, a
15-minute validity window, and the authorization declaration. `next`, `run`,
`finalize`, and `validate` need no external authority files for this mode.
Immediately before dispatch, `run` requires a fresh explicit confirmation that
authorization remains current and the same operator identity that created the
attestation.

The existing externally signed path remains available as `plan-signed`. Signed
runs continue to require and revalidate their external authorization document,
owner key, signed RoE, and live target-control proof.

## Preserved execution boundary

Both modes retain public-DNS filtering, TLS hostname validation, exact SPKI
pinning, fixed credential-free headers, no request body, one action at a time,
no redirects, no retries, hard time and byte limits, an out-of-band stop marker,
durable pre-dispatch evidence, and `OUTCOME_UNCERTAIN` for ambiguous delivery.
Target responses cannot add or alter actions.

Operator-attested mode is stricter in breadth: one plan contains exactly one
action and has zero target-proof requests. It still performs no exploitation,
authentication, crawling, fuzzing, mutation, brute force, or load testing.

## Evidence and claims

Every operator-attested observation records the authorization mode, operator,
local scope digest, and plan digest. Its report must state that:

- permission is an operator declaration only;
- no signed RoE, authorization document, independently pinned owner key,
  ownership proof, or live revocation signal was verified;
- local scope and event hashes are not independently tamper-proof unless their
  terminal digest is retained elsewhere; and
- repository coverage, vulnerability absence, legal authority, ownership, and
  APTS/NIST conformance are not claimed.

The result label remains bounded to the one sealed request denominator. It
cannot be imported into repository coverage or an exploitation tier.

## Consequences and rollback

This mode removes the three-path preflight and enables a minimal black-box
start, at the cost of cryptographic authorization and live revocation
assurance. The declared authorizer and reference improve auditability but do
not verify the declaration.

Rollback is mode-local: disable `OPERATOR_ATTESTED` planning and continue to
accept existing `EXTERNAL_SIGNED` bundles. No signed-mode contract or evidence
needs migration.
