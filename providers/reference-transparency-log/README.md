# Reference transparency log

This directory contains the stateful reference implementation of the
`transparency-log-v1` publication protocol and the optional
`transparency-log-consistency-v1` proof protocol. It is a conformance target
and a small deployable building block, not a hosted or production-complete
transparency service. The v0.10 consistency surface is additive: existing
v0.9 publication clients and configuration version `1.0.0` retain their
original inclusion-only behavior.

The implementation accepts only canonical root-attestation publication
requests, appends each distinct attestation to a durable RFC 6962-style Merkle
tree, and returns an Ed25519-signed inclusion receipt. When configured, it also
returns self-contained RFC 6962/9162 consistency proofs between two requested
committed tree sizes. Neither protocol transmits the audited repository,
findings, provider output, credentials, or target path.

## Components

- `store.mjs` owns signed append-only state, exclusive cross-process locking,
  restart validation, bounded recovery, Merkle roots, inclusion and
  consistency proofs, idempotency, and an optional externally supplied
  checkpoint high-water guard.
- `handler.mjs` provides socket-free publication and consistency HTTP protocol
  boundaries. Each validates the exact request bytes before calling the store
  and verifies the returned signed result before responding.
- `server.mjs` is a small HTTPS adapter for the exact publication endpoint and,
  when supplied a consistency handler, a distinct exact consistency endpoint.
  It buffers bounded bodies and passes Node-style request descriptions to the
  handlers.

## Required external material

The operator must provision the applicable material below outside the audited
repository and outside every audit bundle:

1. An Ed25519 log-signing private key. The same key and logical origin must be
   supplied whenever an existing state directory is opened. The store derives
   the public key and key ID but does not copy the private key into its state.
2. A TLS private key and certificate chain for the HTTPS adapter. These are
   separate from the transparency signing key and are passed as Node TLS
   options. The adapter defaults to TLS 1.2 and permits only TLS 1.2 or 1.3 as
   its configured minimum; it does not issue or rotate certificates.
3. An absolute, dedicated state-directory path. Do not place it below an audit
   bundle, use it as an audit bundle, or point it at a symlink.
4. Controller-side trusted configuration containing the exact publication
   HTTPS URL, logical origin, log public key, and TLS certificate SPKI SHA-256
   pin. Configuration schema `1.1.0` additionally requires a distinct exact
   HTTPS `consistency_url`; schema `1.0.0` deliberately forbids that field and
   remains inclusion-only. The service does not make those client trust
   decisions on the controller's behalf.
5. For optional cross-run continuity, an absolute, dedicated checkpoint-journal
   directory controlled by the audit controller and retained independently of
   the log state. Never place it below the log state, an audit bundle, or under
   a filesystem principal controlled by the log service. The journal stores
   signed origin/key-bound checkpoints and their consistency proofs. Endpoint
   URLs and TLS SPKI pins remain external trusted configuration and are checked
   again whenever the controller contacts the log; they are not journal
   metadata.

Protect the online log-signing key as a service credential. Anyone who obtains
it can create apparently valid state records, receipts, and signed
checkpoints. Opening existing state with a different origin or signing key
fails closed; intentional rotation requires a separately provisioned log
identity and state directory, followed by a coordinated controller trust
update.

## Programmatic composition

There is no implicit daemon or secret loader. A host application composes the
three components explicitly:

```js
import { readFile } from 'node:fs/promises'

import {
  createReferenceTransparencyConsistencyHandler,
  createReferenceTransparencyLogHandler,
} from './handler.mjs'
import { createReferenceTransparencyHttpsServer } from './server.mjs'
import { openReferenceTransparencyLogStore } from './store.mjs'

const trustedCheckpointBytes = process.env.RTA_LOG_TRUSTED_CHECKPOINT_PATH
  ? await readFile(process.env.RTA_LOG_TRUSTED_CHECKPOINT_PATH)
  : undefined

const store = await openReferenceTransparencyLogStore({
  directory: process.env.RTA_LOG_STATE_DIRECTORY,
  auditBundleDirectory: process.env.RTA_AUDIT_BUNDLE_DIRECTORY,
  origin: 'audit-log.example/v1',
  privateKeyBytes: await readFile(process.env.RTA_LOG_SIGNING_KEY_PATH),
  ...(trustedCheckpointBytes === undefined
    ? {}
    : { trustedCheckpointBytes }),
})

const handler = createReferenceTransparencyLogHandler({ store })
const consistencyHandler = createReferenceTransparencyConsistencyHandler({
  store,
})
const service = createReferenceTransparencyHttpsServer({
  handler,
  consistencyHandler,
  host: '127.0.0.1',
  port: 8443,
  path: '/v1/entries',
  consistencyPath: '/v1/consistency',
  tls: {
    key: await readFile(process.env.RTA_LOG_TLS_KEY_PATH),
    cert: await readFile(process.env.RTA_LOG_TLS_CERT_PATH),
    minVersion: 'TLSv1.2',
  },
})

const endpoint = await service.start()
console.log(endpoint.url)
console.log(endpoint.consistencyUrl)

// On shutdown:
await service.stop()
await store.close()
```

Every path supplied through the example environment variables must be
absolute. A real host must obtain secrets through its approved secret manager,
set restrictive filesystem permissions, configure certificate lifecycle
management, and keep the state on storage with durability semantics
appropriate to its threat model. The host, not the store, reads the optional
trusted-checkpoint file. That file must be an independently retained signed
checkpoint; the store neither discovers nor advances it.

## HTTPS contract

### Publication

The default publication endpoint is `POST /v1/entries`. The path is
configurable but is matched exactly; a query string or different path is
rejected. Requests must provide:

- `Content-Type: application/json` with no media-type parameters;
- one canonical decimal `Content-Length` equal to the exact body length;
- `Content-Digest` in the protocol's exact RFC 9530 SHA-256 form;
- `X-RTA-Protocol: transparency-log-v1`; and
- no `Content-Encoding` or `Transfer-Encoding`.

The HTTPS adapter preserves repeated raw headers for the handler, so duplicate
protected headers are rejected instead of being silently joined. It also
bounds raw header bytes and count before body processing.

The body must be valid UTF-8 and the exact canonical compact JSON, including
its trailing newline, for
`schemas/transparency-publish-request.schema.json`. Schema validation also
binds canonical base64 attestation bytes to `content_sha256`. All method,
header, length, digest, UTF-8, canonicalization, and schema checks finish before
the store is called.

A new leaf returns HTTP 201. Republishing an existing exact attestation returns
HTTP 200 without adding a leaf. Both success responses contain canonical JSON
for `schemas/transparency-inclusion-receipt.schema.json` and include exact
`Content-Length`, `Content-Digest`, `X-RTA-Protocol`, and
`Cache-Control: no-store` headers. The handler verifies the receipt's entry,
proof, origin, Ed25519 key, signature, and issue time before returning it.

### Consistency

Supplying `consistencyHandler` enables the distinct exact
`POST /v1/consistency` endpoint. A query string or any other path is rejected,
and the consistency path cannot equal the publication path. Requests use the
same exact `Content-Type`, `Content-Length`, `Content-Digest`, encoding, raw
header, canonical JSON, and bounded-body rules as publication, except that
`X-RTA-Protocol` must be `transparency-log-consistency-v1`.

The canonical request conforms to
`schemas/transparency-consistency-request.schema.json` and carries only the
ordered `first_tree_size` and `second_tree_size` (`1 <= first <= second`). It
does not carry caller-supplied checkpoint documents or roots. The endpoint is
read-only: under the store lock it fully reloads and validates committed state,
projects independently signed checkpoints for the exact requested historical
prefixes, and constructs the RFC 6962/9162 consistency path between them.

HTTP 200 returns canonical JSON for
`schemas/transparency-consistency-proof.schema.json`, containing
`first_checkpoint`, `second_checkpoint`, and `consistency_path`. Both
standalone checkpoints conform to
`schemas/transparency-signed-checkpoint.schema.json` and bind the origin, tree
size, root hash, issue time, Ed25519 algorithm, and key ID under the checkpoint
signature. The handler checks both signatures, origin/key identity, exact
requested sizes, issue-time ordering and skew, path shape, and Merkle relation
before returning the proof. Success responses declare
`X-RTA-Protocol: transparency-log-consistency-v1` and include exact
`Content-Length`, `Content-Digest`, and `Cache-Control: no-store` headers.

The proof follows RFC 6962/9162 semantics. Equal sizes are valid only for equal
roots and use an empty path. An exact-power-of-two first tree does not include
its first root as the first path node; non-power-of-two proofs include the
required seed node. Proofs with missing, extra, reordered, malformed, or
unused nodes fail closed.

Malformed input is rejected without publication or proof generation. The HTTPS
adapter emits bounded canonical error bodies: 404 for a different endpoint,
413 for a body that exceeds its read limit, 400 for rejected request contracts,
and 500 for store, receipt-generation, or proof-generation failures. Error
responses do not expose internal exception details.

The server binds to `127.0.0.1` and an ephemeral port by default. Binding it to
a reachable interface changes the exposure but does not add authentication,
authorization, client certificates, or rate limiting.

## Durable state

The state directory has this layout:

```text
<state-directory>/
  metadata.json
  entries/
    0000000000000000.entry.json
    0000000000000001.entry.json
    ...
  checkpoints/
    0000000000000000.checkpoint.json
    0000000000000001.checkpoint.json
    ...
```

Every file is canonical JSON. `metadata.json` binds the origin, Ed25519 key ID,
creation time, and a random genesis nonce under a domain-separated state
signature. Each entry is immutable and includes:

- its sequential index and the previous entry-file SHA-256 digest;
- the complete validated publication request;
- the domain-separated Merkle leaf hash and decoded content size;
- its acceptance time, origin, and signing identity; and
- a domain-separated Ed25519 state signature.

Each internal checkpoint binds the corresponding entry-file digest, previous
checkpoint-file digest, tree size, RFC 6962-style Merkle root, commit time,
origin, and signing identity under a separate state-signature context. These
internal state checkpoints are distinct from the public inclusion receipt,
whose checkpoint uses the protocol signature context defined in
`scripts/lib/transparency-log-contracts.mjs`.

New immutable files are created through an exclusive temporary file, file
flush, no-replace link, directory synchronization, and temporary-name removal.
An exclusive `.state.lock` directory serializes writers across local
processes. Lock acquisition is bounded. A stale lock is recovered only when
its recorded owner is dead, or when it remained ownerless past the stale
threshold after a crash before owner publication. The exact lock contents must
remain unchanged during quarantine and removal; malformed or ambiguous owners
fail closed.

On reload, a recognized atomic temporary is removed only if it is an
unpublished one-link orphan with no target, or the exact second hard link to
the installed target inode. Multiple temporaries, different inodes, unsafe
file types, and unexpected link counts are rejected rather than guessed
around.

On open and before append, the store reloads and validates the complete state:
canonical encoding, bounded regular non-symlink single-link files, sequential
indexes, signatures, origin/key identity, entry and checkpoint hash chains,
Merkle roots, decoded-byte limits, unique content digests, and nondecreasing
checkpoint times. Tampering, holes, unexpected files, identity drift, unsafe
file types, and impossible entry/checkpoint sequences fail closed.

Recovery is intentionally narrow:

- equal entry and checkpoint counts load normally;
- exactly one durable signed entry without its checkpoint is completed by
  creating the deterministic next signed checkpoint from that entry; and
- every other count mismatch or invalid record is rejected rather than
  deleted, rewritten, or guessed around.

A crash after a durable checkpoint but before in-memory completion is handled
by the next full reload. The store does not claim recovery from arbitrary
filesystem, hardware, or storage-controller behavior.

Consistency proof generation does not append or rewrite state. It takes the
same exclusive lock, reloads and verifies the complete committed state, checks
that both requested sizes identify ordered committed prefixes, computes their
exact historical roots and path, and signs the two public checkpoints. The
path is bounded to 64 SHA-256 nodes by the public proof contract.

### Optional startup high-water guard

`openReferenceTransparencyLogStore` accepts either a
`trustedCheckpoint` document or its exact canonical JSON bytes as
`trustedCheckpointBytes`, but never both. The host is responsible for loading
that independently retained artifact. Before accepting it, the store verifies
its schema, canonical bytes when bytes were supplied, Ed25519 signature,
origin, key identity, and bounded issue time against the configured store
identity.

Every full state load then enforces that checkpoint as a minimum trusted
prefix. A local tree smaller than the checkpoint fails with
`REFERENCE_TRANSPARENCY_EXTERNAL_CHECKPOINT_ROLLBACK`; a different local root
at the checkpoint's tree size fails with
`REFERENCE_TRANSPARENCY_EXTERNAL_CHECKPOINT_FORK`. A successful snapshot
includes `external_checkpoint.status: EXTENDS_EXTERNAL_CHECKPOINT` plus the
anchor digest, tree size, and root hash.

This is optional defense in depth, not controller continuity storage. The
store never writes, replaces, or advances the supplied checkpoint, so its
protection is only as current and independently durable as the host-provided
artifact. Omitting it preserves v0.9 startup behavior. The controller-owned
checkpoint journal described below remains the primary cross-run continuity
mechanism.

## Idempotency

The store indexes the attestation content digest. Republishing the same digest
and exact canonical content returns the original leaf index without creating a
second entry. A digest mapped to different exact content is rejected as a
collision. Idempotency survives restart because the index is reconstructed
from verified durable entries.

The returned receipt is not necessarily byte-for-byte identical to an earlier
receipt: after other leaves are appended, it contains an inclusion path under
the current tree, and its checkpoint issue declaration may be newer. The
idempotency guarantee is no duplicate leaf, not a permanently identical HTTP
response.

## Bounds

All layers enforce limits, and the lowest applicable limit wins. Important
defaults are:

| Layer | Limit | Default |
| --- | --- | ---: |
| HTTPS adapter | request body | 256 KiB |
| HTTPS adapter | request timeout | 30 seconds |
| HTTPS adapter | raw header bytes | 16 KiB |
| HTTPS adapter | raw header count | 64 |
| Handler | request body | 256 KiB |
| Handler | response body | 256 KiB |
| Handler | normalized header bytes | 16 KiB |
| Handler | normalized header count | 64 |
| Handler | signed-result clock skew | 0 ms |
| Store | entries | 1,000,000 |
| Store | decoded attestation bytes per entry | 256 KiB |
| Store | canonical publication-request bytes | 384 KiB |
| Store | cumulative decoded entry bytes | 1 GiB |
| Store | lock acquisition timeout | 10 seconds |
| Store | stale-lock age | 30 seconds |
| Store | lock polling interval | 10 ms |

Each option is validated against a hard range in its owning component. Raising
limits increases memory, startup-validation, disk, and denial-of-service risk;
the implementation performs no retention or compaction.

## External checkpoint journal operations

The checkpoint journal belongs to the audit controller, not this service. It
is an immutable, gap-free chain of canonical records named
`0000000000000000.checkpoint-journal.json`,
`0000000000000001.checkpoint-journal.json`, and so on, protected by a bounded
`.checkpoint-journal.lock`. Each record conforms to
`schemas/transparency-checkpoint-journal-record.schema.json` and binds its
sequence, predecessor-record digest, signed checkpoint, and, after the
baseline, the verified consistency proof from the prior exact checkpoint to
the new one.

Initialization is explicit. On the first journaled publication, pass both
`--transparency-checkpoint-journal <absolute-external-directory>` and
`--initialize-transparency-checkpoint-journal`. After verifying the audit
bundle, root attestation, TLS/SPKI-pinned publication response, and signed
checkpoint, the controller writes record zero with a null predecessor and
null proof. This establishes only a baseline; it does not retroactively prove
history or earn a continuity claim.

On later journaled publications, omit the initialization flag. The controller
reloads and verifies the complete external journal, publishes idempotently,
requests the exact old-to-new proof from the externally configured and
TLS/SPKI-pinned `consistency_url`, verifies both signed checkpoints and the
Merkle relation, then atomically advances the journal. Only a successful
post-baseline advance supports
`CONSISTENT_WITH_EXTERNALLY_RETAINED_CHECKPOINT`. `validate` and `report` can
consume the same external journal with `--transparency-checkpoint-journal` to
recheck the receipt and journal offline; they make no network request and open
the directory without creating a lock or reconciling crash residue. Keep
receipt outputs outside the journal directory so its strict inventory contains
only journal records.

Keep the journal, its backups, the trusted log configuration, and the log
public key under controller authority. The service must never receive the
journal directory or write its records. The journal intentionally does not
persist endpoint URLs or TLS SPKI pins: those remain separately managed trust
inputs and are re-pinned for every online request.

Publication and journal advancement are not a distributed transaction. A log
append can become durable before consistency retrieval or journal persistence
fails. In that case the controller emits no successful receipt output; retry
the same publication, which is idempotent, and complete proof verification and
journal advancement. Treat a changed journal head as concurrency, reload it,
and retry only after re-evaluating the exact requested checkpoint relation. If
the head advanced beyond an unretained receipt checkpoint, idempotently
republish to obtain a current checkpoint rather than discarding the only proof
needed for later offline verification.

For operation, restrict the signing key, TLS key, state directory, journal,
and trusted configuration to their intended filesystem principals. Back up
state and journal independently, test restoration against a retained
checkpoint, monitor endpoint failures and journal advancement, and coordinate
origin/key or TLS-pin rotation as an explicit trust migration. The reference
implementation does not automate those controls.

## Security and claim boundary

A valid inclusion response supports `INCLUSION_AT_SIGNED_CHECKPOINT` for the
exact root-attestation bytes under the configured log origin and Ed25519 key.
A verified consistency proof supports
`CONSISTENCY_BETWEEN_SIGNED_CHECKPOINTS` with
`VERIFIED_BETWEEN_SUPPLIED_CHECKPOINTS` for that exact signed pair. A verified
post-baseline external-journal advance additionally supports
`CONSISTENT_WITH_EXTERNALLY_RETAINED_CHECKPOINT`. The initial journal record
alone supports no continuity claim.

The controller separately verifies that the root attestation is valid and
binds the exact terminal run; the log does not turn arbitrary submitted bytes
into a valid audit result. Pairwise consistency proves an append-only relation
between the two supplied signed checkpoints, not that either checkpoint was
globally visible, newest, witnessed, or non-equivocating.

Without the optional `trustedCheckpoint`, signed local chains still cannot
detect restoration of the entire state directory to an older, internally
consistent prefix. The startup guard detects a local tree older than, or a
fork at, that independently supplied checkpoint. It does not advance itself,
detect rollback of both log state and the external artifact, or establish that
no newer independently retained checkpoint exists. The controller journal is
what advances the client-side high-water mark across runs.

The reference service also makes no claim of:

- gossip, witness quorum, cross-client comparison, or global non-equivocation;
- trusted time, key revocation, automated key rotation, or HSM custody;
- high availability, replication, failover, distributed locking, or safe use
  of a shared/network filesystem;
- client authentication, authorization, tenant isolation, abuse prevention,
  or rate limiting;
- backup consistency, retention, compaction, disaster recovery, or online
  repair; or
- production monitoring, alerting, certificate management, or service
  supervision.

Use the reference service to exercise and independently test the protocol. A
production transparency deployment must add these controls without broadening
the meaning of an individual inclusion receipt.

See [ADR 0009](../../docs/adr/0009-external-transparency-inclusion.md) for the
publication claim, [ADR 0010](../../docs/adr/0010-reference-transparency-log.md)
for the reference implementation, and
[ADR 0011](../../docs/adr/0011-externally-anchored-checkpoint-continuity.md)
for pairwise consistency and externally retained checkpoint continuity.

## Conformance gate

Run the stateful HTTPS gate with:

```powershell
npm.cmd run test:transparency:https
```

The gate uses a repository-owned test-only certificate and generated ephemeral
Ed25519 keys. It exercises publication and consistency through a real TLS
socket with the certificate SPKI pinned, explicitly initializes an external
journal baseline, advances that journal only after verifying an old-to-new
proof, restarts from the same external state, checks idempotent retry and the
optional trusted-checkpoint rollback guard, then stops the service and
validates the retained receipt and journal offline. The security-critical
path uses the real protocol, filesystem, hashing, signature, TLS, and offline
verification implementations rather than mocked cryptography or transport.
None of its key material is suitable for production.
