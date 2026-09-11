# ADR 0004: Detached terminal root-manifest attestation

- Status: Accepted
- Date: 2026-07-30
- Owners: The Last Aperture platform
- Supersedes: the unsigned-root boundary in ADR 0001
- Extends: ADR 0001, ADR 0002, and ADR 0003

## Context

Every bundle artifact is write-once and SHA-256-hash-manifested by `run.json`.
That detects artifact changes only relative to the loaded manifest. An actor
who can rewrite the bundle can replace an artifact and its hash in `run.json`
together. Signed provider execution envelopes do not close this gap because
their public-key identity is also described by the mutable root.

`run.json` changes throughout an active audit. Embedding a signature in it and
re-signing every transition would require the root private key for `ingest`,
`ingest-batch`, `run-provider`, `abort`, and recovery paths. Portable Node
filesystem APIs also cannot atomically replace both a manifest and a detached
signature. A crash between those writes would leave an ambiguous active state.

The stable signing point is the existing terminal boundary. `COMPLETED`,
`COMPLETE_WITH_GAPS`, `ABORTED`, and `FAILED` runs are `FINALIZED` and immutable.

## Decision

### 1. Sign only terminal manifests

The controller exposes:

```text
last-aperture attest <bundle>
  --signing-key <external-ed25519-private.pem>
  --out <external-attestation.json>
```

`attest` first validates the run contract and every hash-manifested bundle
artifact. It refuses nonterminal runs. It then signs an attestation containing:

- the run ID, schema version, terminal state, and `FINALIZED` phase;
- the SHA-256 digest of the exact loaded `run.json` bytes;
- the Ed25519 public-key identity;
- the signing timestamp; and
- a format and protocol version.

The signature covers the canonical unsigned attestation with a fixed,
null-terminated protocol context. This domain separation prevents a signature
from the provider-receipt protocol from being replayed as a root attestation.

### 2. Keep both trust inputs outside mutable scope

The private signing key, detached attestation, and public verification key must
be outside both the run bundle and audited repository. The controller rejects
linked/reparse-point trust files, bounded-reads them, and rechecks their
canonical paths after reading.

Verification requires both:

```text
last-aperture validate <bundle>
  --root-attestation <external-attestation.json>
  --root-public-key <external-ed25519-public.pem>
```

`report` accepts the same pair. Supplying only one fails closed. Without the
pair, historical unsigned bundles remain validatable, but the CLI explicitly
labels their root authenticity `UNANCHORED`.

### 3. Make the artifact transparency-ready without claiming a log

The detached document is small, deterministic except for `signed_at`, and
binds the exact root digest. An operator can store it in immutable object
storage, a release record, a transparency service, or another independently
controlled system. Version 0.5 does not publish it or claim inclusion,
consistency, witness, revocation, or timestamp authority.

## Options rejected

### Embed and re-sign the active manifest

This gives every intermediate state a signature, but makes all mutations
dependent on an online root private key and introduces a non-atomic
manifest/signature update. It also expands key exposure into provider and
manual-ingest operations.

### Put the detached signature inside the bundle

This improves accidental-corruption detection but does not establish an
external trust root. An actor who replaces the bundle can replace the public
key, manifest, and signature together.

### Sign only the artifact map

This omits terminal state, findings, coverage, errors, store profiles, and
provider-attempt history. The exact `run.json` digest is the smaller and
stronger commitment.

### Require an external transparency service now

A service would add network, identity, availability, retention, and privacy
policy decisions. The detached contract is the portable prerequisite; service
publication can be added without changing the signed payload.

## Security invariants

1. Only a terminal `FINALIZED` run can be attested.
2. Bundle validation succeeds before the controller signs its root digest.
3. Ed25519 is the only accepted signing algorithm.
4. The signing key, verification key, and attestation are external to the
   target and bundle.
5. Verification binds the externally pinned key ID, signature, exact manifest
   bytes, run ID, schema version, state, and phase.
6. A missing external anchor is reported as `UNANCHORED`, never as authenticated.
7. The attestation does not claim trusted time, key revocation, or transparency
   inclusion.

## Failure modes

- A manifest byte changes: the digest binding fails before artifact validation
  can turn the replaced root into an authenticated result.
- The wrong public key is pinned: key identity fails before signature checking.
- The signature or signed metadata changes: Ed25519 verification fails.
- The output already exists: `attest` refuses overwrite.
- The output, key, or attestation is placed inside mutable scope: the command
  fails closed.
- Signing fails after finalization: the immutable run remains a valid but
  `UNANCHORED` bundle, and `attest` can be retried to a new absent output path.

## Verification

The implementation includes:

- schema and canonical-base64 validation;
- valid Ed25519 creation and verification;
- exact-byte manifest replacement tests;
- signature and key-substitution tests;
- active-run, non-Ed25519, partial-pin, and in-bundle-output rejection;
- anchored and unanchored CLI validation paths; and
- the full platform, lint, generation, and release gates.

## Rollback

The feature adds no field to `run.json` and does not change run schema 3.0.0.
Rolling back removes the `attest` command and anchored verification options;
all existing bundles remain readable. Detached attestations remain
independently verifiable by the versioned schema and signing algorithm.
