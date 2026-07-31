# ADR 0002: Sealed provider execution and controller-observed consumption

Date: 2026-07-29
Status: Accepted

## Context

Version 0.2 exports a bounded job packet and later accepts a packet-bound
provider result. The target is re-inventoried before dispatch and ingestion,
but the provider reads the live repository between those checks. A file can
therefore change, be read, and be restored without changing the final tree
digest. `examined_files` and producer identity are also provider declarations.

The next trust boundary must establish which planned bytes were made available
to one provider attempt without claiming that receipt, comprehension, or a
zero-finding result proves semantic correctness.

The Node.js Permission Model is not an isolation boundary for malicious code,
and Node's WASI implementation carries the same warning. The reference backend
therefore uses brokered content delivery plus an external OCI runtime. OCI
containers remain a shared-kernel trust boundary and are defense in depth, not
proof that arbitrary native provider code is harmless.

Primary sources:

- Node.js Permission Model:
  https://nodejs.org/api/permissions.html
- Node.js WASI security warning:
  https://nodejs.org/api/wasi.html
- OCI Linux runtime isolation:
  https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md
- Docker run controls:
  https://docs.docker.com/reference/cli/docker/container/run
- Docker seccomp:
  https://docs.docker.com/engine/security/seccomp/

## Decision

Version 0.3 adds a separate controller-owned provider execution path. The
existing `next` / `ingest` path remains available and is always labeled
`PROVIDER_DECLARED`.

### Sealed inputs

Runner-ready planning stores the exact already-inventoried text bytes in
deterministic, uncompressed, bounded shards outside the target repository. A
canonical index binds:

- the repository tree digest;
- an opaque file ID;
- the repository-relative path, byte count, and SHA-256 digest; and
- the shard digest, offset, and length.

Trusted lens and control files are sealed separately. JSON indexes never embed
source bytes or absolute host paths. The complete Rules of Engagement remains
controller-only; providers receive a path-free projection bound to its digest
and relative capabilities. The provider cannot mount or reopen the target
repository; the broker serves only bytes from verified sealed shards.

Source sealing is explicit because the bundle becomes a sensitive source
archive. Hash-only plans remain valid but cannot use the observed runner.

### Attempts and execution

Before launching a provider, the controller atomically persists a one-use
attempt lease bound to the run, job, packet, plan, source snapshot, provider
configuration (including the receipt-signing key ID), sandbox policy, nonce,
and expiry. Only the compare-and-swap winner may launch. Attempt events are
append-only. A failed or expired attempt remains visible; a retry receives a
new attempt ID and nonce. All evidence in one run must verify under the same
trusted key. Durable `RESULT_CAPTURED` and `VALIDATED` states resume without a
second provider launch.

The first backend is a digest-pinned OCI image launched through an explicitly
configured absolute runtime path. It uses no target or bundle mount, no
inherited provider environment, no network, a read-only root, a bounded tmpfs,
non-root identity, no Linux capabilities, no-new-privileges, the built-in
seccomp allowlist, private IPC, and CPU, memory, PID, file-descriptor, output,
and wall-time limits. Missing or unverifiable controls disable observed mode;
the controller never falls back to an ordinary child process.

Expired `STARTED` recovery records a signed failure before retry and requires
positive proof that the exact container is absent. An ambiguous create outcome
or unverifiable absence is signed as nonrecoverable and atomically closes the
run and its jobs, preventing another launch across uncertain container state.

### Broker and receipts

The provider receives a portable packet containing opaque snapshot IDs rather
than an absolute repository root. It requests one allowlisted file or control
artifact at a time over bounded JSON Lines stdio. For each request the
controller sends exact bytes plus a fresh challenge. The provider acknowledges
full byte consumption with:

```text
HMAC-SHA-256(
  challenge,
  "red-team-audit/provider-delivery/v1\0" ||
  job_id || "\0" || file_id || "\0" || size || "\0" || exact_bytes
)
```

The controller verifies the response and authors the receipt. The provider
cannot set attempt identity, execution authority, delivered paths, producer
configuration, sandbox claims, or receipt contents.

One write-once execution envelope contains the raw provider result and its
controller receipt. This avoids doubling the artifact count for thousands of
proof jobs and gives crash recovery one replayable captured unit.

Controller-observed failures use a separate write-once failure envelope. It
binds the structured failure, bounded stderr, and any partial controller receipt
to the same lease and signing key. It preserves delivery evidence without
granting a failed job coverage authority.

Execution and failure envelopes are signed with Ed25519 over compact,
recursively key-sorted UTF-8 JSON with one trailing newline and with the
`signature` member omitted. The key ID is SHA-256 of the DER SPKI public key.
An embedded key establishes self-consistency only; `validate` and `report`
accept an external public-key pin stored outside both target and bundle.

### Assurance vocabulary

Reports and machine output keep these statements separate:

- `PROVIDER_DECLARED`: provider claimed it examined a relative path.
- `CONTROLLER_DELIVERED`: controller sent the complete sealed bytes.
- `CONTROLLER_OBSERVED_CONSUMPTION`: the adapter produced the byte challenge
  response for the complete sealed bytes.
- `REMOTE_REQUEST_ACCEPTED`: reserved here for a trusted gateway accepting a
  particular request digest; implemented later by ADR 0007 and ADR 0008.
- `INDEPENDENTLY_PROVEN`: a separate proof oracle established the claim.

Consumption is not comprehension. None of the first four states means the
provider analyzed the file correctly, and zero findings is always
`NO_FINDINGS_REPORTED`, never "clean" or "safe".

Provider `examined_files` may contain only fully consumed snapshot files.
Missing consumption becomes an explicit gap. Observed fan-out findings that
quote source must use controller-verifiable snapshot byte spans and excerpt
hashes. The controller verifies those anchors against consumed sealed bytes;
unanchored free-form prose remains a provider claim.

## Consequences

Positive:

- Live-repository mutation and restore cannot change provider input.
- A provider cannot manufacture observed file coverage or its own receipt.
- Concurrent runners cannot both launch the same attempt.
- Captured output, receipt, limits, and retry history remain auditable.
- Historical v1 bundles and manual providers keep their original meaning.

Costs and residual risks:

- Runner-ready bundles contain source and require sensitive-artifact handling.
- Docker or another OCI implementation is an external prerequisite and part of
  the trusted computing base.
- A shared-kernel container is not a microVM. The initial backend is suitable
  for a trusted adapter handling hostile repository data, not an assertion that
  arbitrary hostile native images are perfectly contained.
- The acknowledgement proves possession/consumption sufficient to compute the
  response, not reasoning or model prompt inclusion.
- Remote model use requires a later credential-holding gateway that records the
  exact prompt/request transform; the sandbox receives no API credential or
  arbitrary egress.
- Receipt signatures establish controller identity only when the verifier pins
  the public key outside the mutable bundle. External freshness/transparency
  remains a separate milestone.

## Alternatives considered

- Re-read the live repository from a child: rejected because it retains the
  mutation/restore race and host authority.
- Read-only worktree or bind mount: rejected because it is live state and does
  not contain environment, network, processes, or resources.
- Node Permission Model, workers, or `node:vm`: rejected because they are not
  malicious-code security boundaries.
- Node `node:wasi`: rejected because Node explicitly says not to rely on it for
  untrusted-code sandboxing.
- Wasmtime component provider: promising second backend with a smaller
  capability surface, but it cannot run existing Node provider images.
- Ordinary Docker wrapper with the repository mounted read-only: rejected;
  brokered sealed bytes and verified effective controls are mandatory.

## Validation

- Deterministic snapshot pack/index round trips and tamper rejection.
- Mutation/restore, symlink/reparse, malformed UTF-8, and wrong-span tests.
- Concurrent lease, replay, expiry, duplicate result, and crash-boundary tests.
- Out-of-scope, partial, duplicate, reordered, and forged consumption tests.
- Host path/environment/network/process/write and resource-exhaustion probes.
- Effective OCI configuration inspection and orphan-container cleanup.
- Mixed declared/observed reporting and lifecycle authority tests.
- Full corpus, platform, generation, and Node 24 runner gates. Node 20 remains
  supported for manual static operation but cannot execute the observed runner.

## Rollback

Runner-ready plans are additive. Disabling or removing the runner leaves
hash-only planning, packet export, and manual ingestion intact. A v2 sealed run
must never be reinterpreted as an observed run by a v1 controller; unsupported
execution envelopes fail closed while their artifacts remain readable.
