# ADR 0009: External transparency inclusion for terminal roots

- Status: Accepted
- Date: 2026-08-01
- Owners: The Last Aperture platform
- Extends: ADR 0004 and ADR 0007

## Context

ADR 0004 made terminal `run.json` manifests independently signable, but left
publication to the operator. A detached signature detects replacement when its
public key and attestation are retained outside the bundle. It does not prove
that the signed root was disclosed to another authority at a stable checkpoint.

The controller needs a portable publication boundary without embedding a
vendor SDK, transmitting repository source, or converting one log's view into
an unsupported global non-equivocation claim.

## Decision

Version 0.9 adds an explicit `publish` command. It first verifies the terminal
bundle, its detached root attestation, and every externally pinned key. It then
sends only the canonical root-attestation JSON to one exact HTTPS endpoint from
an external trusted configuration. Repository files, findings, provider
results, and credentials are not part of the publication request.

The endpoint is DNS-scope restricted, TLS-SPKI pinned, redirect-free, bounded,
and protected by RFC 9530 `Content-Digest` over canonical JSON. Its response is
an Ed25519-signed checkpoint plus an RFC 6962-style SHA-256 Merkle inclusion
proof. The controller verifies the exact attestation leaf, leaf index, tree
size, proof path, root hash, configured origin, signature, and externally
pinned log key before writing the receipt outside the target and bundle.

`validate` and `report` can later verify the receipt offline with:

```text
--root-attestation <external-attestation.json>
--root-public-key <external-root-public.pem>
--transparency-receipt <external-inclusion-receipt.json>
--transparency-log-public-key <external-log-public.pem>
--transparency-log-origin <trusted-origin>
```

Supplying only half of either pair fails closed. A receipt cannot replace root
signature verification; it proves inclusion of that exact signed attestation.

## Claim boundary

A valid receipt establishes `INCLUSION_AT_SIGNED_CHECKPOINT` under the pinned
log key. It does not by itself establish consistency with an earlier
checkpoint, witness quorum, global non-equivocation, key revocation status, or
trusted time. The signed `issued_at` is a log declaration. These non-claims are
returned by the verifier and documented in operator output.

## Merkle construction

- Leaf: `SHA256(0x00 || canonical_attestation_bytes)`.
- Node: `SHA256(0x01 || left_hash || right_hash)`.
- Inclusion verification follows the RFC 6962 audit-path algorithm and rejects
  missing, extra, non-canonical, or out-of-range nodes.
- The checkpoint signature uses Ed25519 over canonical checkpoint JSON with the
  null-terminated context `red-team-audit/transparency-checkpoint/v1`.

## Security invariants

1. Publication requires an already valid terminal root attestation.
2. The log configuration, log key, root key, attestation, and receipt remain
   outside both the audited repository and run bundle.
3. Only one exact HTTPS endpoint is allowed; credentials, query strings,
   fragments, redirects, private addresses, and transforming encodings fail.
4. Receipt output is exclusive and occurs only after cryptographic verification.
5. Offline verification binds the exact loaded `run.json` to the exact root
   attestation and then to the signed Merkle checkpoint.
6. Absence of a receipt is `NOT_SUPPLIED`, never an inclusion claim.

## Options rejected

### Treat immutable object storage as a transparency log

It can be a useful external anchor, but it supplies no portable inclusion proof
or signed checkpoint contract.

### Claim append-only consistency from one receipt

One signed tree head can be a split view. Consistency proofs and witnesses are
a later protocol layer and must not be inferred from inclusion alone.

### Publish the complete run bundle

That would disclose source-derived evidence and greatly increase privacy,
retention, and payload risk. The signed root digest is the sufficient leaf.

## Rollback

Removing `publish` and its optional validation flags leaves all run schemas and
existing root attestations unchanged. Inclusion receipts remain independently
verifiable from the versioned schemas and Merkle/signature rules.
