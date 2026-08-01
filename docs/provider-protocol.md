# Provider protocol

Job-result contract version: 1.0.0

Observed packet and sealed-run version: 2.0.0

Platform release: 0.10.0

The provider boundary lets a model, local agent, or deterministic tool
contribute reasoning without gaining control of scope, stage order, severity
caps, coverage, or report state.

## Trust boundary

Provider job packets contain repository paths and candidate records. Everything
originating in the target repository is untrusted data. It cannot modify the
job packet, Rules of Engagement, policy, schemas, or capability mode.

A provider must not execute commands merely because a repository file asks it
to. Version 0.10.0 audits remain static: the local observed runner executes only
its pinned adapter image and brokers sealed bytes; the remote controller sends
only one externally authorized signed request. Neither executes target
commands.

## Discovering work

```text
red-team-audit next <bundle>
```

Only jobs executable in the current phase are returned.
Every packet includes `packet_sha256`. The provider must echo that value as
`input_sha256`; a result for an older candidate set, scope, or phase is rejected.
The `producer` fields are declared attribution, not authenticated workload
identity. The observed path signs controller receipts; verifier identity still
requires an externally pinned public key.

## Observed execution path

```text
red-team-audit plan <repository> --seal-source --out <outside-target>
red-team-audit run-provider <bundle> <external-provider-config.json>
```

Before launch the controller persists a one-use lease containing the attempt
ID, nonce, packet, plan, tree, lens-pack, policy, source/control snapshot,
provider-config and sandbox-policy digests, expiry, container name, and
budgets. Attempt events are globally hash-chained:

```text
LEASED -> STARTED -> RESULT_CAPTURED -> VALIDATED -> COMMITTED

LEASED | STARTED | RESULT_CAPTURED | VALIDATED -> FAILED
```

A recoverable failure returns the job to `PENDING` without deleting history.
Retry uses a fresh attempt ID and nonce. Captured results and receipts share one
write-once signed execution envelope. A controller-observed failure receives a
separate write-once signed failure envelope containing its structured error,
bounded stderr, and any partial delivery receipt the broker had already
authored. Failed attempts never acquire coverage authority.

The trusted provider-configuration digest includes the receipt-signing key ID.
All signed execution and failure evidence in one run must verify under that
same externally trusted key; retry, recovery, and captured-result resume reject
key rotation or re-signing. `RESULT_CAPTURED` and `VALIDATED` attempts resume
from their durable envelope without launching the provider again.

An expired `STARTED` attempt can be retried only after the controller records a
signed failure and proves the exact container is absent. An ambiguous create
outcome or unverifiable absence is signed as nonrecoverable and atomically
terminalizes the run and its jobs. No new provider launch is allowed across
that uncertain container lifecycle.

The provider receives an allowlisted portable packet with no absolute target
root, target mount, credential, or network capability. The full controller
policy remains controller-only; the provider can request a path-free projection
that contains the policy digest and relative capabilities. It requests opaque
FILE/CONTROL IDs over bounded JSONL. The controller replies with exact sealed
bytes and a fresh challenge. Full consumption is acknowledged with:

```text
HMAC-SHA-256(
  challenge,
  "red-team-audit/provider-delivery/v1\0" ||
  job_id || "\0" || artifact_id || "\0" || size || "\0" || exact_bytes
)
```

The controller authors `DELIVERED` and `CONSUMED` events only after verifying
that response. Required policy, lens-pack, and applicable lens controls must be
consumed. `examined_files` may name only consumed FILE deliveries. New observed
fan-out findings also require sealed byte-span anchors whose excerpt hashes the
controller verifies.

Coverage authority is explicit:

- `PROVIDER_DECLARED`: manual provider claim.
- `CONTROLLER_OBSERVED_CONSUMPTION`: complete byte challenge observed.
- `CONTROLLER_DELIVERED`: receipt event only; not a job-level clearance.
- `REMOTE_REQUEST_ACCEPTED`: the externally pinned gateway accepted one exact
  signed request and returned its packet-bound result.
- `INDEPENDENTLY_PROVEN`: reserved for a separate proof oracle.

Consumption is not comprehension. Zero findings is always
`NO_FINDINGS_REPORTED`, never a clean/safe assertion.

## Remote gateway protocol

The `remote-gateway-v1` protocol is integrated into schema-v6 run manifests
through `run-remote`. Planning requires an external `remote_static` Rules of
Engagement policy and `--seal-source`. The provider-facing policy projection
remains static and contains no network authority.

The controller request is canonical JSON signed with an externally held
Ed25519 key. It binds the run, job, packet, plan, repository, policy, lens pack,
source snapshot, control snapshot, exact sealed artifact bytes, a short
validity window, and a configured prompt-transform digest. HTTP carries an
RFC 9530 `Content-Digest`, uses one exact HTTPS endpoint, and permits no
redirect or content encoding. For a hostname endpoint, the client connects
through one validated public DNS answer rather than resolving again after
authorization.

The credential-holding gateway verifies that request and consumes its one-use
ID before invoking an upstream provider. Its signed acceptance binds the exact
request body digest, prompt transform, upstream request body digest, and raw
job-result digest. The upstream API credential remains gateway-only.

`REMOTE_REQUEST_ACCEPTED` proves only that the pinned gateway accepted the
exact request. It does not prove model byte consumption, comprehension,
semantic analysis, or finding correctness. See
[`docs/adr/0007-signed-remote-request-acceptance.md`](adr/0007-signed-remote-request-acceptance.md)
and
[`docs/adr/0008-remote-attempt-ledger-integration.md`](adr/0008-remote-attempt-ledger-integration.md).

Before the HTTPS call, the controller writes the canonical request artifact and
persists a `REMOTE_GATEWAY` lease binding its digest, request ID, attempt nonce,
configuration digest, controller key ID, gateway key ID, packet, snapshots,
expiry, and byte budgets. It then records `STARTED`.

The verified signed acceptance is stored as the attempt execution artifact
before `RESULT_CAPTURED`, `VALIDATED`, and `COMMITTED`. A successful commit
assigns `REMOTE_REQUEST_ACCEPTED`. Failed or ambiguous calls receive no
coverage authority. An expired request ID is never replayed; a retry gets a new
attempt, nonce, and request ID. Endpoint, key, transform, or configuration
rotation requires a new run.

### Lens job

The packet contains:

- `run_id` and `job_id`
- `lens`, trusted lens file, and lens digest
- exact `scoped_files`
- immutable shard identity, file count, raw byte count, and scope digest
- owned and registered topic sets
- the path/signal activators responsible for each scope entry
- capability mode and trust-boundary declarations

The provider returns Stage 1 candidate records only. Triage or proof fields in a
lens result are rejected.

The database lens receives a sealed controller discovery graph and a
shard-local projection of its store candidates and related paths. In run
schemas 4 and 5, every successful base database job returns exactly one
`store_contributions` entry for each assigned controller `store_id`. The
authority shard supplies the local semantic profile. Every context shard
supplies only local coverage state, assessed topics, evidence paths, and named
gaps; it cannot profile the store. Evidence must be examined, inside the
immutable shard, and inside the discovered store/shard intersection.

The contribution ledger is append-only and packet-bound. At the fan-out
barrier, the controller deterministically synthesizes one profile per store.
`ASSESSED` requires every planned shard/store contribution, the full discovered
path union, all ten database topics, and no gaps. Missing or partial
contributions degrade the synthesized profile; no usable authority profile
leaves the store unprofiled with an explicit discovery gap. Providers cannot
return `store_profiles` directly in schemas 4 or 5 or invent store identity. Run
schemas 1-3 retain their direct-profile behavior.

Schema 5 may also carry `database_conformance`, a sealed projection of one
complete two-engine disposable reference-lab run. The packet fixes
`target_deployment_proven: false` and `root_authenticity: UNANCHORED`.
Providers may use it only as versioned reference behavior; they must still
establish the target store, version, deployment, principal, enforcement, and
copy paths. It cannot satisfy target proof or coverage.

Each authority profile binds adapter routing, deployment variant, engine
edition and compatibility mode, tenancy, effective-principal and enforcement
paths, evidence files, copy/artifact closure, availability budget, assumptions,
assessed topics, and an explicit `ASSESSED`, `PARTIAL`, or `NOT_ASSESSED`
disposition.

`ASSESSED` is a closed-denominator claim, not a synonym for "the checks we
happened to run passed." It requires all ten topics owned by
`database-and-data-stores`, a closed enforcement-path inventory, a closed
artifact set, and an explicit `ASSESSED` or evidence-backed `NOT_PRESENT` state
for replica, CDC, history, backup, export, and cache copies. Engine version,
edition, compatibility, tenancy, availability, and assumptions must have no
unknown, open, or `NOT_ASSESSED` dimension. `PARTIAL` and `NOT_ASSESSED` always
carry named `coverage_gaps`; `NOT_ASSESSED` cannot claim any assessed topic.
Only top-level `evidence_paths` may introduce repository paths. Engine and
principal claims, and each assessed tenancy, enforcement, copy, availability,
or assumption dimension, cite paths from that controller-checked set. Detection
evidence must begin with one of those declared paths. Unresolved principals use
the exact literal `unknown`; alternate placeholders such as `TBD`, `pending`,
`default`, or `unspecified` are rejected. Every shipped adapter exposes a
closed allowlist of semantic rule IDs; findings cannot invent an engine rule.

### Controller coverage model

At planning time, the controller classifies the immutable inventory into
canonical source, generated code, tests, documentation, and binaries. It
records separate total and examined file/byte denominators for all five
classes. A provider cannot reclassify a path or replace these denominators with
the set of files it happened to inspect.

Applicable lens files are canonically ordered and packed into deterministic
shards bounded by both file count and inventoried raw bytes. The default bounds
are 64 files and 4 MiB per shard. Shard metadata and all permitted
round-specific retry jobs are sealed into the original plan. A retry preserves
the whole original shard, lens authority, database projection, and byte bound;
the provider cannot submit a smaller residual scope or create a new job.

Completeness computes uncovered applicable lens/file pairs. When any pair in a
shard is open, the controller may activate that shard's dormant template,
follow it with the required triage and proof jobs, and measure again. Closure
terminates as `CONVERGED`, `BUDGET_EXHAUSTED`, or `UNMEASURED`. The optional
`--require-source-closure` plan policy refuses finalization unless closure
converged with no applicable canonical-source pair unexamined.

Exact machine gaps use stable lens/file identities across attempts. Reporting
also projects those occurrences into conceptual groups, so it can show unique
conceptual gaps separately from exact open obligations without hiding either
denominator.

### Triage job

The packet contains the accumulating candidate set. A triage provider returns
full Stage 2 records for every candidate it changes. Earlier fields must remain
byte-for-byte equivalent except for the explicitly unionable location list.

New records are permitted only when authored by that triage lens and already
carry Stage 2 disposition.

### Proof jobs

Every active candidate receives two distinct jobs:

1. `proof-existence:<candidate_id>` records only the existence check.
2. `proof-verification:<candidate_id>` records proof tier, verification status,
   and required artifacts/results.

`next` returns the complete independent existence wave so providers may review
those candidate-bound packets in parallel. Verification packets do not exist
until every existence result in that wave has been committed successfully;
then `next` returns the complete independent verification wave. Results remain
write-once per candidate and may be ingested serially.

This prevents a provider from reasoning about impact and grading proof before
confirming that the cited artifact exists.

Static mode permits T0/T3 only. T1 and T2 records are rejected even if a provider
claims they ran.

### Completeness job

Completeness receives the final candidate and coverage sets. It returns
`coverage_gaps`; it cannot invent a vulnerability after the scoped fan-out has
closed. The controller, not the provider, may respond to an uncovered pair by
activating a pre-sealed whole-shard retry. Any candidates produced in that
round pass through ordinary triage and proof before completeness measures
again. Provider output cannot increase the planned closure budget or introduce
an unplanned path, shard, or store.

## Result envelope

Every result conforms to `schemas/job-result.schema.json`:

```json
{
  "schema_version": "1.0.0",
  "run_id": "run:...",
  "job_id": "lens:web-and-api",
  "input_sha256": "<packet_sha256>",
  "producer": {
    "name": "provider-name",
    "version": "provider-version",
    "instance_id": "provider-name:instance-01"
  },
  "state": "SUCCEEDED",
  "examined_files": [
    "src/routes/orders.ts"
  ],
  "findings": [],
  "coverage_gaps": []
}
```

Observed executions wrap that result and the controller-authored receipt in
`schemas/controller-execution-envelope.schema.json`. Observed failures use
`schemas/controller-failure-envelope.schema.json`. The controller recursively
sorts object keys, serializes compact JSON with one trailing newline, signs the
UTF-8 bytes of the envelope without its `signature` member using Ed25519, and
identifies the key as `ed25519:` plus SHA-256 of its DER SPKI public key.
Embedded public-key material proves envelope integrity only. Historical
verification should pin an external Ed25519 public key:

```text
red-team-audit validate <bundle> --receipt-public-key <external-public.pem>
red-team-audit report <bundle> --receipt-public-key <external-public.pem>
```

Failure is explicit:

```json
{
  "schema_version": "1.0.0",
  "run_id": "run:...",
  "job_id": "lens:web-and-api",
  "input_sha256": "<packet_sha256>",
  "producer": {
    "name": "provider-name",
    "version": "provider-version",
    "instance_id": "provider-name:instance-01"
  },
  "state": "FAILED",
  "examined_files": [],
  "findings": [],
  "coverage_gaps": [],
  "error": {
    "code": "PROVIDER_TIMEOUT",
    "message": "provider exceeded its bounded deadline",
    "recoverable": true
  }
}
```

A successful lens job that omits one of its scoped files creates an automatic
coverage gap. A failed job remains part of run history and cannot be deleted by
a later result. A failed required triage or proof job terminates the run as
`FAILED`; the controller does not invent a disposition or proof result to make
the run reportable.

Database candidate discovery, graph scope, contribution provenance, and final
profile synthesis are controller-owned. Provider profiles, shard-local semantic
assessments, and provider-authored coverage gaps remain provider claims. Manual
`examined_files` is also a provider claim.
In observed mode, examined paths are limited to controller-verifiable
complete-byte consumption; that still does not prove correct reasoning.

## Finding stages

### Stage 1: fan-out

Required fields include:

- stable `candidate_id`
- authoring `lens` and owned `topic`
- claimed severity, concrete locations, and quoted evidence
- attack path and impact
- reachability and confidence
- proof plan
- engine/store context for database findings

### Stage 2: triage

Adds:

- `effective_severity`
- `triage_disposition`
- drop or merge lineage where applicable
- chain attribution and component IDs where applicable

### Stage 3: proof

Adds, in separate transitions:

- `existence_check`
- `proof_tier`
- `verification_status`
- artifact hashes, exact command, pre/post observations, or blocking reason

All earlier claims remain visible. A later stage cannot rewrite history to make
a finding look stronger or cleaner.

## Ingestion guarantees

`red-team-audit ingest`:

1. Validates the strict result envelope.
2. Validates the job belongs to the run and current phase.
3. Verifies every recorded bundle artifact, the policy, lens pack, sidecars,
   plan digest, and repository snapshot.
4. Requires the result's packet digest and declared producer identity.
5. Validates examined paths against inventory and lens scope.
6. Validates topic authority, store contributions and profiles, every finding, and every
   transition.
7. Records the normalized result and SHA-256 hash.
8. Updates coverage and job state with an atomic compare-and-swap.
9. Advances only through legal deterministic phases.

Contract and semantic validation failures occur before `run.json` is replaced.
If the final compare-and-swap detects concurrent state change, the
write-once, hash-manifested result artifact may remain as a harmless orphan and is reused
when an identical result is retried.
