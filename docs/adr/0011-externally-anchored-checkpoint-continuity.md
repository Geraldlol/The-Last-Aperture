# ADR 0011: Externally anchored checkpoint continuity

- Status: Accepted for the v0.10 build
- Date: 2026-08-01
- Owners: The Last Aperture platform
- Extends: ADR 0009 and ADR 0010

## Context

Version 0.9 can publish an exact detached root-manifest attestation and verify
its inclusion under one Ed25519-signed transparency-log checkpoint. The
durable reference log also detects holes, record replacement, broken chains,
and narrowly defined partial commits inside its current state directory.

Those controls do not establish that two checkpoints belong to one append-only
history. A log can present different signed roots to different clients, or its
entire state directory can be restored to an older internally valid prefix.
One inclusion receipt cannot distinguish either case. ADR 0010 therefore
limits the claim to `INCLUSION_AT_SIGNED_CHECKPOINT` and requires a checkpoint
retained outside the log state, or an independent witness, before making a
continuity claim.

The next trust step is client-verifiable continuity from an externally owned
checkpoint. It is not productionization of the reference service and it is not
yet witness gossip or quorum.

## Decision

Version 0.10 adds an additive checkpoint-consistency protocol and a
controller-owned external checkpoint journal.

The log exposes a separate exact endpoint:

```text
POST /v1/consistency
X-RTA-Protocol: transparency-log-consistency-v1
Content-Type: application/json
```

The controller can optionally compose that endpoint into publication with an
external checkpoint journal. The existing `POST /v1/entries` request and
inclusion-receipt contracts do not change. In particular, a prior checkpoint
is not inserted into the publication request and does not become part of the
Merkle leaf.

The consistency endpoint is read-only. It accepts canonical JSON containing
the exact positive `first_tree_size` and `second_tree_size`, and returns
canonical JSON containing freshly signed checkpoints for both historical
sizes and an RFC 6962-style Merkle consistency path. Both checkpoints bind:

- the same configured log origin and Ed25519 key ID;
- an independently verified log signature;
- a safe positive tree size; and
- the root hash for that exact size.

The handler confirms that both requested sizes exist in the durable history,
constructs the exact historical roots while holding the store lock, and signs
both public checkpoints before producing a proof. The older size must not
exceed the newer size. Equal sizes produce identical roots and an empty path.
The client compares the returned heads with its separately retained and newly
published checkpoints by origin, key ID, size, and root; issued-at declarations
and signatures may differ because each valid public checkpoint is freshly
signed.

The response is self-contained so it can be verified offline. The consistency
path itself does not need another signature: verification reconstructs both
already signed Merkle roots from the path. Request and response schemas remain
strict, bounded, and versioned.

## HTTPS boundary

`/v1/consistency` uses the transport invariants already applied to
`/v1/entries`:

- one exact HTTPS URL and path, with no query or fragment;
- public DNS resolution and TLS certificate SPKI pinning;
- no redirects, implicit credentials, proxy inheritance, content encoding, or
  transfer encoding;
- one canonical decimal `Content-Length` matching the exact bytes;
- an RFC 9530 SHA-256 `Content-Digest`;
- duplicate protected-header rejection;
- fatal UTF-8 decoding and exact canonical compact JSON; and
- bounded header, request, response, clock, and wall-time handling.

The endpoint uses `X-RTA-Protocol: transparency-log-consistency-v1` so a response
from the publication endpoint, a generic JSON service, or a future protocol
cannot be accepted by context confusion. Errors are bounded and canonical and
do not expose state paths or internal exceptions.

## Controller data flow

Checkpoint continuity is an optional higher-assurance publication flow:

1. Verify the terminal bundle and detached root attestation as before.
2. Publish the attestation and verify the returned inclusion receipt entirely
   in memory.
3. Open and fully validate the externally owned checkpoint journal.
4. Compare its current signed checkpoint with the receipt checkpoint.
5. Request and verify the required consistency proof over real HTTPS.
6. Durably advance the journal when the receipt checkpoint is newer.
7. Exclusively write the inclusion receipt only after the required continuity
   operation succeeds.

If the journal checkpoint is older, the proof runs from the journal head to
the receipt checkpoint and a new journal record is appended. If the sizes are
equal, the roots must match and no new record is needed. If another process has
already advanced the journal beyond the receipt checkpoint, the controller
uses an existing retained record for that checkpoint or idempotently republishes
the same entry to obtain a current head. It does not emit a receipt whose only
connecting proof was transient and unavailable to later offline verification,
and it never moves the journal backward.

An empty journal is never silently trusted on first contact. Initialization
requires the explicit `--initialize-transparency-checkpoint-journal` option in
addition to the journal path. It creates a baseline anchor from the already
verified inclusion receipt but does not retroactively establish continuity
with any earlier checkpoint.

There is no distributed transaction across the log and the journal. A log
append may be durable even when the consistency request or journal update
later fails. In that case the command fails closed, writes no higher-assurance
receipt output, does not advance the journal, and reports that publication may
have occurred while continuity was not established. Retrying is safe because
publication is idempotent.

## External anchor ownership

The checkpoint journal belongs to the controller/operator trust domain, not
the log. The log process must not receive its path or have authority to write
it. The journal directory must be absolute and outside:

- the audited target repository;
- every audit bundle;
- the transparency-log state directory; and
- any directory writable by the log service identity.

Operators should place it on separately controlled durable or immutable
storage and retain its latest record digest through a mechanism appropriate to
their threat model. A journal on the same rollback-capable volume and under the
same principal as the log is structurally valid but supplies no independent
rollback boundary.

The signed journal records pin the log origin and Ed25519 key ID. The exact
endpoint URLs and TLS SPKI digest remain in the independently supplied trusted
online configuration and are revalidated on every retrieval. Each immutable
sequential record binds its index, the SHA-256 digest of the
previous record, the previous and new signed checkpoints, and the verified
consistency path. It contains no repository source, findings, provider output,
credentials, or target path.

## Atomic advancement and recovery

One exclusive cross-process journal lock serializes validation and advancement.
Lock acquisition and every network operation are bounded. The controller
captures a validated head, fetches and verifies the proof without holding a
filesystem lock, then advances with an expected-head compare-and-swap. If the
head changed, it reloads and retries against the new exact predecessor rather
than overwriting another caller's advance.

Advancement creates one immutable record through an exclusive temporary file,
file synchronization, no-replace installation, directory synchronization, and
temporary-name removal. There is no mutable high-water pointer: the highest
fully validated sequential record is the head.

Recovery accepts only well-defined shapes:

- a crash before no-replace installation leaves no new journal record;
- a completely installed and synchronized next record is the new head even if
  the former process failed before returning; and
- a recognized temporary is removed only when its bytes and inode relationship
  prove it is the harmless residue of the interrupted install.

Holes, unexpected names, multiple temporaries, unsafe file types, changed lock
ownership, record replacement, a broken record chain, invalid checkpoint
signatures, or an invalid consistency proof fail closed. The controller does
not delete, rewrite, or guess around contradictory evidence. Concurrent callers
either observe the same head or reload after the preceding caller advances it;
no caller can overwrite or move the head backward.

These mechanics do not claim durability beyond the guarantees of the host
filesystem, device, operating system, and storage configuration.

## Offline verification and claims

`validate` and `report` can consume the externally pinned log key, origin,
inclusion receipt, and checkpoint journal without contacting the log. They:

1. verify the terminal run and detached root attestation;
2. verify inclusion at the receipt checkpoint;
3. verify journal metadata and every immutable record chain;
4. verify every log checkpoint signature; and
5. verify every consistency path needed to connect the trusted journal baseline
   to the receipt checkpoint or a later journal head.

Successful composition adds:

```text
consistency: CONSISTENT_WITH_EXTERNALLY_RETAINED_CHECKPOINT
```

Offline validation opens the journal without creating a lock, directory, or
file and without reconciling temporary residue. Any ambiguous residue fails
closed, so the operation can run against genuinely read-only media.

It preserves the separate inclusion claim. Without a supplied, valid journal,
the result remains `consistency: NOT_VERIFIED`; absence is never inferred as a
failure or a success.

The continuity claim means only that the exact signed checkpoint containing
the attestation is on one append-only Merkle history connected to the explicit
external baseline under the pinned log origin and key.

It does not establish:

- witness participation, witness independence, witness quorum, gossip, or
  global non-equivocation;
- agreement with checkpoints shown to other clients;
- detection when the log and the complete external journal are rolled back
  together and no later journal digest is retained elsewhere;
- trusted time, freshness, maximum merge delay, entry availability, or log
  monitoring;
- log-key rotation, compromise recovery, revocation, or HSM custody;
- semantic validity of the published audit, beyond the independently verified
  root attestation;
- authentication, authorization, tenant isolation, rate limiting, abuse
  resistance, high availability, replication, backup, or disaster recovery;
  or
- production readiness of the reference log or reference journal.

## Failure modes

- A checkpoint smaller than the external head is a rollback failure.
- Equal sizes with different roots are an equivocation failure.
- A larger checkpoint with no valid path from the external head is a fork or
  corrupt-proof failure.
- A key, origin, endpoint, or TLS-pin change is identity drift and requires an
  explicit migration; it is never accepted as ordinary advancement.
- An unavailable endpoint, timeout, truncated response, malformed body, or
  invalid signature leaves the journal unchanged and produces no continuity
  claim.
- Journal tampering, truncation relative to a separately retained head digest,
  unsafe filesystem substitution, or ambiguous crash residue fails closed.
- Whole-journal restoration to an older valid prefix remains locally
  undetectable when the caller supplies no newer independently retained head.

## Consequences

Positive:

- a relying party can verify append-only continuity across checkpoints without
  trusting the current log filesystem or contacting the log during validation;
- restoring only the log to an older valid prefix is detected against the
  external journal;
- split views that cross a client's retained history are detected;
- the publication leaf and receipt v1 contracts remain unchanged; and
- the same consistency primitive can support a later independent witness.

Costs and limitations:

- operators must own and protect a second durable state boundary;
- checkpoint advancement adds another bounded HTTPS exchange;
- journal validation and serialization add filesystem and concurrency work;
- a compromised log key can sign forks, although it still cannot make a fork
  consistent with an already retained checkpoint; and
- client-local continuity is not global non-equivocation.

## Alternatives rejected

### Put an optional prior checkpoint in `POST /v1/entries`

This would couple mutation, inclusion, and consistency, change strict
publication request bytes, complicate duplicate-publication semantics, and
create downgrade ambiguity when the optional field is omitted or ignored.
Controller orchestration gives one operator workflow while keeping the wire
contracts and Merkle leaf stable.

### Rely only on an external high-water mark at log startup

A startup guard can prevent one service instance from opening state older than
an independently supplied anchor, but it supplies no portable proof to clients
and commonly places the anchor in the same operator failure domain. Version
0.10 therefore includes it only as optional defense in depth: a reference store
opened with `trustedCheckpoint` or canonical `trustedCheckpointBytes` refuses
an older or conflicting local prefix on startup and every later reload. The
external journal and portable proof remain the continuity mechanism.

### Rewrite one mutable latest-checkpoint file

A single file makes torn replacement, concurrent lost updates, and rollback of
the high-water mark difficult to distinguish. Immutable chained records expose
the advancement and crash boundaries and permit full offline reconstruction.

### Add a witness or quorum now

An independent witness must own separate keys and durable per-log state,
atomically compare each checkpoint with its prior view, and return a
verifiable cosignature. Quorum policy also needs distinct identity, threshold,
availability, and operator-independence rules. Those are a separate trust and
operations slice. Calling the controller journal a witness would overstate its
independence.

### Productionize the reference log instead

Authentication, authorization, rate limiting, HSM integration, replication,
backups, observability, and certificate lifecycle are important deployment
controls, but none proves that two signed checkpoints share an append-only
history. They remain separate production work.

## Validation

The v0.10 slice is accepted only when tests establish all of the following:

- independently computed consistency proofs verify for every old/new size pair
  across bounded odd, even, and power-of-two trees;
- truncated, reordered, duplicated, and extra proof nodes fail, as do wrong
  roots, wrong sizes, same-size forks, key substitution, and origin
  substitution;
- exact HTTP tests reject duplicate protected headers, malformed lengths or
  digests, non-canonical JSON, oversized input, and truncated responses before
  any journal mutation;
- concurrent processes cannot lose an advance or move the journal backward;
- injected crashes at every durable-write boundary recover only the documented
  shapes;
- a real-TLS flow publishes at checkpoint M, retains M externally, appends
  through process restart to N, proves M to N, stops the service, and validates
  the result offline with no mocked hash or signature operation;
- restoring the log to a valid prefix below M fails without changing the
  journal;
- opening the reference store against that retained checkpoint also rejects
  an older or conflicting local prefix;
- extending a different branch beyond M fails consistency verification;
- failure after durable publication but before journal advancement is reported
  accurately and succeeds through an idempotent retry; and
- existing v0.9 publication and inclusion-only validation remain compatible.

## Rollback

The consistency endpoint, journal, and controller flags are additive. They can
be disabled or removed without changing `POST /v1/entries`, the Merkle leaf,
the root-attestation format, or existing inclusion receipts. Inclusion-only
validation then returns to `consistency: NOT_VERIFIED`.

Preserve every journal record, consistency artifact, signed checkpoint, log
key, and separately retained head digest needed for historical verification or
incident analysis. Removing software support does not invalidate those signed
artifacts. Deleting the only external anchors is not a safe rollback; it
weakens future rollback and fork detection.
