# Transparency publication and checkpoint-continuity protocols

> **Current release gate (2026-09-03):** Public `audit publish` is disabled
> before run, attestation, key, output, or configuration access. A caller-chosen
> HTTPS endpoint/SPKI/key is not independently enrolled log identity, and even a
> fixed canonical POST can trigger state on an arbitrary endpoint. The transport
> kernel also still needs an independent total wall-time deadline rather than
> only socket-inactivity timeout. The protocol below is retained for conformance
> testing, not current operational use.

Version 0.9 publishes one detached root-manifest attestation to a separately
operated HTTPS log. Version 0.10 preserves that request, Merkle leaf, and
inclusion receipt and adds an optional, read-only checkpoint-consistency
protocol plus a controller-owned external checkpoint journal. Neither protocol
carries repository source, findings, provider output, credentials, or a target
path.

## Trusted configuration

The external JSON configuration conforms to
`schemas/transparency-log-config.schema.json`.

- Schema `1.0.0` pins one exact publication `log_url`, a logical log origin,
  the absolute external Ed25519 log-public-key path, the TLS certificate SPKI
  SHA-256 digest, and request, response, and clock bounds. It remains valid for
  v0.9-compatible inclusion-only publication.
- Schema `1.1.0` requires a second, distinct exact HTTPS `consistency_url`.
  Both endpoints use the same configured origin, log key, TLS SPKI pin, and
  bounds. A `1.0.0` configuration cannot contain `consistency_url`, and a
  `1.1.0` configuration cannot omit it.

Both URLs must be exact HTTPS endpoints without credentials, query strings, or
fragments. The controller rejects a configuration, log key, journal, or other
trust input inside the audited target or run bundle.

## Inclusion publication (v0.9-compatible)

`publish` sends canonical compact JSON conforming to
`schemas/transparency-publish-request.schema.json`. The entry is the canonical
compact root-attestation JSON, encoded as canonical base64 and bound by its
plain SHA-256 digest. HTTP uses `POST`, `application/json`,
`X-RTA-Protocol: transparency-log-v1`, one exact `Content-Length`, and an RFC
9530 `Content-Digest`.

The endpoint must return HTTP 200 or 201 with the same media type and protocol
header, one canonical `Content-Length` matching the exact response bytes, and
a valid content digest. Redirects, transfer encodings, duplicate protected
headers, truncated responses, and content encodings are not accepted.

The canonical response conforms to
`schemas/transparency-inclusion-receipt.schema.json`. It contains:

- the attestation content digest and domain-separated Merkle leaf hash;
- the zero-based leaf index and bounded audit path;
- a checkpoint origin, tree size, root hash, issue declaration, and log key ID;
  and
- an Ed25519 signature over the domain-separated canonical checkpoint.

The verifier reconstructs the root with the RFC 6962/RFC 9162 audit-path
algorithm and requires the configured origin and externally pinned log key. A
successful inclusion-only result means `INCLUSION_AT_SIGNED_CHECKPOINT` and
returns `consistency: NOT_VERIFIED`. Version 0.10 does not put a previous
checkpoint in `POST /v1/entries`, alter the attestation leaf, or broaden this
standalone receipt claim.

## Standalone signed checkpoints

`schemas/transparency-signed-checkpoint.schema.json` projects the checkpoint
and signature from an inclusion receipt into a reusable trust artifact:

```json
{
  "schema_version": "1.0.0",
  "kind": "red-team-audit/transparency-signed-checkpoint",
  "checkpoint": {
    "origin": "audit-log.example/v1",
    "tree_size": 42,
    "root_hash": "<64 lowercase hexadecimal characters>",
    "issued_at": "2026-08-01T12:00:00.000Z",
    "signing": {
      "algorithm": "Ed25519",
      "key_id": "ed25519:<SPKI SHA-256>"
    }
  },
  "signature": "<canonical base64 Ed25519 signature>"
}
```

The signature uses the same domain-separated checkpoint context as an
inclusion receipt. `issued_at` is a log declaration, not trusted time. Every
continuity verifier independently checks each checkpoint signature, configured
origin, and externally pinned key before considering a Merkle path.

## Checkpoint consistency (v0.10)

The read-only endpoint is an exact `POST /v1/consistency` by default. It uses:

```text
Content-Type: application/json
X-RTA-Protocol: transparency-log-consistency-v1
Content-Length: <exact canonical body length>
Content-Digest: sha-256=:...:
```

The request conforms to
`schemas/transparency-consistency-request.schema.json` and names only the two
positive, ordered historical sizes:

```json
{
  "schema_version": "1.0.0",
  "protocol": "transparency-log-consistency-v1",
  "kind": "red-team-audit/transparency-consistency-request",
  "first_tree_size": 17,
  "second_tree_size": 42
}
```

The server resolves both exact roots from its fully validated durable history.
It does not accept caller-supplied roots as authority. A size outside the
committed history, or a range with `first_tree_size > second_tree_size`, is
rejected without changing log state.

The canonical response conforms to
`schemas/transparency-consistency-proof.schema.json`:

```json
{
  "schema_version": "1.0.0",
  "kind": "red-team-audit/transparency-consistency-proof",
  "first_checkpoint": { "<signed checkpoint>": "..." },
  "second_checkpoint": { "<signed checkpoint>": "..." },
  "consistency_path": ["<64-character lowercase SHA-256 digest>"]
}
```

`first_checkpoint` and `second_checkpoint` are complete standalone signed
checkpoint objects, not the abbreviated placeholder used above. The path has
at most 64 nodes and must have exactly the length required by the two sizes.
It is not separately signed: the verifier reconstructs both already signed
roots from the path.

The Merkle construction and proof semantics follow the RFC 6962/RFC 9162
history-tree algorithm:

- `1 <= first_tree_size <= second_tree_size`;
- equal sizes require identical roots and an empty path, producing relation
  `SAME_SIZE_SAME_ROOT`;
- different sizes require the unique minimal path proving the first tree is a
  prefix of the second, producing relation `APPEND_ONLY_EXTENSION`;
- when the first size is an exact power of two, its already trusted root is not
  redundantly carried as a path node; and
- missing, extra, reordered, non-canonical, or otherwise unused nodes fail
  verification.

A verified proof establishes only `CONSISTENCY_BETWEEN_SIGNED_CHECKPOINTS` and
reports `consistency: VERIFIED_BETWEEN_SUPPLIED_CHECKPOINTS`. By itself it does
not establish that either checkpoint is independently retained.

The consistency endpoint inherits the publication transport boundary: public
DNS resolution, TLS certificate SPKI pinning, no redirects or implicit
credentials, no transforming or transfer encoding, exact canonical JSON,
duplicate-header rejection, and bounded header, body, response, clock, and
wall-time handling. Its distinct protocol header prevents a publication
response from being accepted in the consistency context.

## External checkpoint journal

The optional journal turns pairwise proof verification into a client-retained
continuity history. It is an absolute external directory owned by the
controller/operator, not the log process. Keep it outside the target, every run
bundle, the log state directory, and any directory writable by the log service
identity. Inclusion-receipt outputs must also be outside the journal directory;
an unrelated file would make the strict journal inventory fail closed. A
journal on the same rollback-capable storage under the same
principal as the log does not provide an independent rollback boundary. The
journal persists only signed, origin/key-bound checkpoints and consistency
proofs. Endpoint URLs and TLS certificate SPKI pins remain separate trusted
configuration, are re-pinned whenever the controller contacts the log, and are
not journal metadata.

Journal records conform to
`schemas/transparency-checkpoint-journal-record.schema.json` and are immutable,
gap-free files named `0000000000000000.checkpoint-journal.json`,
`0000000000000001.checkpoint-journal.json`, and so on. Each record contains:

- `sequence`, matching its zero-based filename;
- `previous_record_sha256`, binding the exact prior canonical record bytes;
- `checkpoint`, the current standalone signed checkpoint; and
- `consistency_proof`, connecting the exact preceding checkpoint to the
  current one.

Record zero has null `previous_record_sha256` and null `consistency_proof`.
Every later record requires both fields, and the proof's first signed tree head
must match the preceding record checkpoint while its second signed tree head
must match the current record checkpoint. A `.checkpoint-journal.lock`
directory serializes local processes. Advancement uses immutable no-replace
publication and durable synchronization; holes, broken hashes, unexpected
files, ambiguous crash residue, unsafe filesystem objects, substituted
identities, or invalid proofs fail closed.

### Explicit initialization and advancement

An empty journal is never trusted implicitly. The first publication using a
journal must include `--initialize-transparency-checkpoint-journal`. Only after
the bundle, root attestation, publication response, and signed checkpoint have
been verified does the controller create record zero. Initialization anchors
that checkpoint for later comparisons; it does **not** establish continuity
with any pre-initialization history and does not earn the continuity claim.

On a later publication:

1. the controller verifies the bundle, root attestation, and inclusion receipt
   in memory;
2. it fully reloads and verifies the external journal under its lock;
3. it requests the required consistency proof over real HTTPS;
4. it verifies both signed checkpoints and the exact path;
5. it durably appends a journal record only when moving to a newer checkpoint;
   and
6. it exclusively writes the requested inclusion-receipt output only after the
   required continuity operation succeeds.

Equal-size, equal-root publication needs no journal advance. If a receipt is
older than a concurrently advanced journal head, an already retained receipt
checkpoint is verified from the journal. Otherwise the controller idempotently
republishes the same entry to obtain a current checkpoint; it never emits a
receipt whose only connecting proof would be discarded, and the journal is
never moved backward. A smaller checkpoint, same-size different
root, invalid path, identity drift, unavailable endpoint, timeout, malformed or
truncated response, or journal failure produces no continuity claim and no
higher-assurance receipt output. The log append may already be durable;
idempotent retry is therefore the recovery path.

The journal contains no source or audit evidence. Operators should retain the
latest journal record digest in another independently controlled location when
their threat model includes restoration of the complete journal directory to
an older valid prefix.

## Optional reference-log startup guard

The reference store can also receive one host-loaded external signed
checkpoint as `trustedCheckpoint` or its exact canonical bytes as
`trustedCheckpointBytes`, but not both. It verifies the checkpoint under the
configured origin and log key and then treats it as a minimum trusted prefix
on every full state load. A local tree below that size fails as
`REFERENCE_TRANSPARENCY_EXTERNAL_CHECKPOINT_ROLLBACK`; a different historical
root at that size fails as `REFERENCE_TRANSPARENCY_EXTERNAL_CHECKPOINT_FORK`.
A successful store snapshot reports
`external_checkpoint.status: EXTENDS_EXTERNAL_CHECKPOINT` with the anchor
digest, size, and root.

This optional guard is defense in depth for the log host, not a replacement
for client-retained continuity. The store does not read the controller journal
or any checkpoint path, and it never writes or advances the supplied anchor.
It cannot detect rollback of both the log state and the caller-supplied anchor,
and omission retains the v0.9 startup behavior.

## CLI

Inclusion-only publication remains unchanged and accepts a schema `1.0.0`
configuration:

```powershell
npm.cmd run audit -- publish <bundle> <external-log-config.json> `
  --root-attestation <external-root-attestation.json> `
  --root-public-key <external-root-public.pem> `
  --out <external-inclusion-receipt.json>
```

Initialize an external journal explicitly with a schema `1.1.0` configuration:

```powershell
npm.cmd run audit -- publish <bundle> <external-log-config-1.1.json> `
  --root-attestation <external-root-attestation.json> `
  --root-public-key <external-root-public.pem> `
  --transparency-checkpoint-journal <external-journal-directory> `
  --initialize-transparency-checkpoint-journal `
  --out <external-inclusion-receipt.json>
```

Omit the initialization flag for every subsequent continuity-enforced
publication:

```powershell
npm.cmd run audit -- publish <bundle> <external-log-config-1.1.json> `
  --root-attestation <external-root-attestation.json> `
  --root-public-key <external-root-public.pem> `
  --transparency-checkpoint-journal <external-journal-directory> `
  --out <external-inclusion-receipt.json>
```

Offline validation never contacts the log:

```powershell
npm.cmd run audit -- validate <bundle> `
  --root-attestation <external-root-attestation.json> `
  --root-public-key <external-root-public.pem> `
  --transparency-receipt <external-inclusion-receipt.json> `
  --transparency-log-public-key <external-log-public.pem> `
  --transparency-log-origin <trusted-origin> `
  --transparency-checkpoint-journal <external-journal-directory>
```

`report` accepts the same external verification inputs. Publication changes log
and journal state and must be explicitly authorized by the operator. Validation
and reporting open the journal in strict read-only mode: they create no lock,
directory, or file and do not reconcile or delete crash residue. Ambiguous
residue fails closed, which permits verification from read-only media.

## Claims and non-claims

After at least one verified journal advance connects the relevant receipt
checkpoint to the explicit external baseline, successful composition adds:

```text
consistency: CONSISTENT_WITH_EXTERNALLY_RETAINED_CHECKPOINT
```

This is separate from `INCLUSION_AT_SIGNED_CHECKPOINT`. It means only that the
exact signed checkpoint containing the attestation is on one append-only Merkle
history connected to that externally retained baseline under the pinned log
origin and key. Without a supplied valid journal, or for initialization alone,
consistency remains `NOT_VERIFIED`.

The result does not establish witness participation or independence, witness
quorum, gossip, global non-equivocation, agreement with checkpoints shown to
other clients, trusted time, freshness, maximum merge delay, entry
availability, revocation, key-compromise recovery, key rotation, or HSM
custody. It also cannot detect rollback of both the log and complete journal to
older mutually consistent prefixes unless a newer journal-head digest or
checkpoint is retained elsewhere.

The repository ships a durable reference implementation and a real-TLS,
restart, rollback, journal, and offline-validation conformance gate. It is
intentionally not a production service; see
[`providers/reference-transparency-log/README.md`](../providers/reference-transparency-log/README.md),
[ADR 0010](adr/0010-reference-transparency-log.md), and
[ADR 0011](adr/0011-externally-anchored-checkpoint-continuity.md).
