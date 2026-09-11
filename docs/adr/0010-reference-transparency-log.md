# ADR 0010: Stateful reference transparency log

- Status: Accepted
- Date: 2026-08-01
- Owners: The Last Aperture platform
- Extends: ADR 0009

## Context

ADR 0009 defined publication of a terminal root attestation to an external
`transparency-log-v1` endpoint and constrained the resulting claim to inclusion
at one signed checkpoint. Version 0.9 supplied the request, receipt, Merkle,
signature, HTTPS-client, and offline-verification contracts. Tests could
emulate the endpoint, but there was no durable implementation against which to
exercise restart, concurrency, crash boundaries, or exact HTTP conformance.

A useful reference implementation must demonstrate more than a cryptographic
receipt factory. It must preserve an append across process restart, serialize
concurrent writers, fail closed on state substitution, recover only
well-defined partial commits, and expose the exact protocol over HTTPS. At the
same time, a small local reference log must not be presented as a globally
consistent or production-complete transparency service.

## Decision

Add a stateful reference provider under
`providers/reference-transparency-log/`, split into three independently
testable layers:

1. `store.mjs` owns durable signed state, locking, recovery, Merkle construction,
   proof generation, and idempotency.
2. `handler.mjs` accepts a buffered Node-style request description without
   binding sockets. It validates exact HTTP semantics and canonical protocol
   bytes before calling the store, then verifies and canonicalizes the store's
   signed receipt.
3. `server.mjs` binds one exact HTTPS path, reads a bounded request body, maps
   request and internal failures to bounded error responses, and delegates all
   protocol decisions to the handler.

The split keeps filesystem and cryptographic behavior testable without a
network, while the HTTPS conformance suite exercises the same components across
a real TLS connection.

## External identity and placement

The reference log requires an externally provisioned Ed25519 private key, a
logical log origin, and an absolute dedicated state directory. It derives and
exposes the public key and `ed25519:<spki-sha256>` key ID. The private key is
kept in process for signing but is not written into state. Signed metadata binds
the first configured origin and key ID; reopening with another origin or key
fails closed.

TLS key and certificate material are also supplied externally as Node HTTPS
options. The adapter defaults to a TLS 1.2 minimum and allows the operator to
raise it to TLS 1.3, but not lower it. TLS identity is distinct from the
Ed25519 checkpoint identity. The controller independently pins the endpoint
certificate SPKI, log public key, and logical origin through its external
transparency configuration.

The state directory must remain outside the audited repository and every audit
bundle. The store rejects an explicit overlap and checks ancestors for a run
manifest. State files and directories must be real filesystem objects rather
than symlinks; persisted records must be bounded regular, non-symlink,
single-link files when loaded.

## Signed append-only state

A new state contains signed canonical `metadata.json`, an `entries/` directory,
and a `checkpoints/` directory. Entry and checkpoint names use a zero-based,
16-digit sequence number. Holes, unexpected names, duplicate content digests,
or more than one unmatched record fail closed.

Metadata binds:

- state schema and kind;
- logical origin and Ed25519 key ID;
- canonical creation time; and
- a random genesis nonce.

Each signed entry binds:

- its index and the SHA-256 digest of the previous entry file;
- the complete validated canonical publication request;
- the domain-separated Merkle leaf hash and decoded content size;
- acceptance time, origin, and signing identity.

Each signed internal checkpoint binds:

- the current tree size and RFC 6962-style Merkle root;
- the corresponding entry-file digest;
- the previous checkpoint-file digest; and
- commit time, origin, and signing identity.

Metadata, entries, and internal checkpoints use separate null-terminated
signature contexts. Internal checkpoints are implementation state, not the
public inclusion-receipt checkpoint. A successful `publish` creates the public
receipt with the protocol context from ADR 0009 and verifies that receipt again
at the handler boundary before returning it.

Merkle construction remains the protocol construction from ADR 0009:

- leaf: `SHA256(0x00 || canonical_attestation_bytes)`;
- node: `SHA256(0x01 || left_hash || right_hash)`; and
- odd-sized trees split at the largest power of two below the subtree size, as
  in RFC 6962.

## Commit, locking, and recovery

All state-changing work runs under an exclusive directory lock that is visible
across local processes. The lock has a canonical owner record containing a PID,
acquisition time, and random nonce. Acquisition and polling are bounded.
The implementation quarantines and removes a stale lock only if its owner is
dead, or if the lock remained ownerless past the stale threshold after a crash
before owner publication. The lock directory, owner bytes, and recognized
owner temporary must remain unchanged through recovery. An active, malformed,
or otherwise ambiguous owner is never stolen.

Before each append, the store reloads and validates the full durable state
under the lock. A distinct publication follows these stages; shared-state
checks and writes occur while that lock is held:

1. validate and clone the canonical request and exact attestation content;
2. enforce entry-count, request, entry, cumulative-byte, and clock bounds;
3. create and durably synchronize the next immutable signed entry;
4. compute the new Merkle root;
5. create and durably synchronize the next immutable signed internal
   checkpoint; and
6. update the in-memory view.

Files are created with exclusive temporary names, flushed, installed without
replacement, and followed by directory synchronization. Existing target bytes
must match exactly; an immutable-name conflict fails closed.

On reload, a recognized atomic temporary is removed only when it is either an
unpublished one-link orphan with no target or the exact second link to the
installed target inode. Multiple temporaries, different inodes, unsafe file
types, or unexpected link counts are contradictory state and fail closed.

Recovery recognizes only two durable shapes:

- equal entry and checkpoint counts form a complete state; or
- exactly one additional signed entry is a crash between the two durable
  writes, so the store reconstructs its deterministic checkpoint using the
  entry acceptance time.

A checkpoint already durable before a process failure is recovered by the next
full reload even if the former process did not update memory. Any larger count
difference, checkpoint without its entry, invalid signature, broken hash
chain, wrong Merkle root, identity drift, clock rollback, or unsafe file shape
is rejected. The store does not delete or heuristically repair contradictory
state.

These mechanics provide bounded recovery at the tested commit boundaries.
They do not claim durability beyond the guarantees of the host filesystem,
device, operating system, and deployment configuration.

## Idempotency

The durable content index is keyed by the request's attestation SHA-256 digest.
If the same digest maps to the same exact canonical content, publication does
not append another leaf. If the bytes differ, the operation fails as a digest
collision. The index is reconstructed and revalidated on restart, so the
behavior also applies across processes and restarts.

The HTTPS result is 201 for a newly created leaf and 200 for an idempotent
publication. An idempotent response can carry a new receipt for the original
leaf under the current tree size and root; idempotency means one leaf per exact
attestation, not permanently identical receipt bytes.

## HTTPS boundary and bounds

The adapter defaults to loopback, an ephemeral port, and `/v1/entries`. It
requires an externally supplied TLS configuration and accepts only the exact
configured path. The handler requires:

- `POST` and `application/json` without parameters;
- no content or transfer encoding;
- one canonical decimal content length matching the exact buffered body;
- `X-RTA-Protocol: transparency-log-v1`;
- the exact RFC 9530 SHA-256 `Content-Digest`; and
- canonical UTF-8 JSON conforming to the publication-request contract.

The adapter bounds raw header bytes and count and reconstructs headers from the
raw sequence so duplicate protected fields remain visible and are rejected.
These checks occur before mutation. The store independently validates the
request again. Response receipts are schema-checked and cryptographically
verified against the request attestation, configured origin, and store public
key. Success and error bodies are canonical, content-digested, explicitly
length-delimited, and marked `no-store`.

The HTTPS adapter, handler, and store each enforce their own request bounds.
The handler additionally bounds normalized headers, response bytes, and clock
skew. The store bounds entries, decoded entry bytes, canonical request bytes,
cumulative bytes, and lock timing. The effective bound is the lowest applicable
layer. Defaults and operator-facing composition are documented in the provider
README.

## Claim boundary and residual risks

The public receipt still proves only
`INCLUSION_AT_SIGNED_CHECKPOINT` for the exact submitted root-attestation bytes
under the pinned origin and Ed25519 key. It does not validate the audited run by
itself; the controller separately verifies the root attestation and run
manifest before publication and during offline validation.

The signed state detects many local modifications: record replacement,
insertion, holes, broken chains, invalid roots, unsafe file substitution, and
an incomplete entry/checkpoint sequence. It cannot detect restoration of the
**entire state directory** to an older, internally valid prefix. Detection of
that whole-state rollback requires a newer checkpoint retained outside the
directory or an independent witness/gossip system. The reference store does
not read or compare such an anchor during startup.

No broader claims are made for:

- checkpoint consistency proofs, gossip, witness quorum, or global
  non-equivocation;
- high availability, replication, failover, distributed consensus, or shared
  filesystem coordination;
- client authentication, authorization, tenant isolation, rate limiting, or
  Internet-facing abuse resistance;
- trusted time, key revocation, key rotation, HSM integration, or certificate
  lifecycle management;
- backups, retention, compaction, disaster recovery, monitoring, alerting, or
  unattended repair; or
- semantic validity of submitted audit content beyond the publication schema.

The default local lock is a single-state serialization mechanism, not a
distributed lock. Binding the HTTPS adapter to a public interface does not add
any of the missing production controls.

## Consequences

Positive:

- the controller can be tested against a real durable external state boundary
  with no mocked Merkle or signature operation;
- receipts remain verifiable after restart with the standard protocol
  verifier;
- exact duplicates do not inflate the tree;
- concurrent local processes cannot silently lose or reuse an index; and
- crash and tampering behavior is explicit and adversarially testable.

Costs and limitations:

- the Ed25519 signing key is online whenever the service publishes;
- append reloads and validates the full state, favoring auditability and a
  simple reference model over high throughput;
- the implementation creates an entry/checkpoint file pair per distinct leaf
  and provides no compaction;
- one local lock serializes all writers; and
- operators must supply the missing availability, access-control, observability,
  backup, TLS, and external-checkpoint controls.

## Options rejected

### Keep only an in-memory or mocked endpoint

That cannot establish restart persistence, process serialization, durable
idempotency, or crash-recovery behavior and leaves the client tested against a
weaker boundary than the documented protocol.

### Store transparency state inside the audit bundle

That would place the external disclosure authority inside the artifact whose
history it is intended to anchor and would make bundle replacement and log
replacement share one failure domain.

### Rewrite one mutable tree-state file

A compact mutable file makes torn writes and silent replacement harder to
distinguish. Immutable signed entries and checkpoints expose sequence and
commit boundaries directly, at the cost of more files and full reloads.

### Automatically repair every inconsistent state

Ambiguous repair can convert tampering or rollback into accepted history.
Recovery is therefore limited to one signed entry missing its deterministic
checkpoint; all other contradictions require operator investigation.

### Treat signed local chains as rollback protection

An attacker capable of restoring the complete directory can restore a valid
older prefix. Claiming rollback protection without an external latest
checkpoint or witness would exceed the evidence.

### Add clustering and witnesses to the reference provider

Replication, distributed consensus, consistency proofs, and witness gossip are
separate trust and operations layers. Combining them with this slice would
obscure the individual-inclusion claim and prevent the provider from remaining
a small conformance implementation.

## Validation

The reference slice is covered by:

- independently computed RFC 6962 roots and proofs across odd and even tree
  sizes;
- duplicate publication and restart identity tests;
- injected failures after durable entry and checkpoint writes;
- tampering, rollback evidence, unsafe-link, state-placement, clock, and bounds
  tests;
- active and stale lock tests plus parallel child-process appends;
- exact handler tests for method, encoding, content length, digest, canonical
  JSON, key/origin substitution, response bounds, and mutation ordering; and
- end-to-end HTTPS publication, restart, offline verification, malformed
  request rejection, and a real socket-truncated response followed by an
  idempotent retry.

## Rollback

The reference service can be stopped or removed without changing the
`transparency-log-v1` request, receipt, or verifier contracts. The controller
can publish to another conforming external log using the same protocol.

Preserve any reference-log state, signing key, public receipts, and externally
retained checkpoints needed for investigation or historical verification.
Removing the service does not revoke previously signed receipts, and deleting
the only external checkpoint copies would weaken rollback detection rather
than constitute a safe protocol rollback.
