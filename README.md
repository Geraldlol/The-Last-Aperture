# Red Team Audit

Red Team Audit is an evidence-first, agent-assisted source audit platform with
separate controllers for bounded HTTPS observation and operator-attested or
document-bound authenticated campaigns. Its
security lenses supply domain judgment; a deterministic Node.js control plane
owns inventory, activation, scope, state transitions, coverage accounting,
evidence lineage, and reporting. Manual providers declare which scoped files
and stores they examined. The optional sealed runner can prove byte consumption
and the optional remote gateway can prove acceptance of one signed provider
request; neither proves model comprehension. External HTTP reconnaissance has
its own authorization, action denominator, stop path, and nonclaims. It never
becomes repository coverage.

It is not another regex scanner. Agent and scanner output is provider evidence:
it is packet-bound, attributed, schema-checked, scope-checked, and capped before
it enters the run, but its factual accuracy still depends on proof and review.

## Current release

Version 0.12.0 adds authenticated HTTP campaigns to the v0.11
authorized-reconnaissance and v0.10 repository-audit foundation:

- A separate `http-authed-v1` protocol and `audit:http-authed` CLI. The released
  runtime has distinct lower-assurance `OPERATOR_ATTESTED_AUTHED` and
  document-bound `WRITTEN_AUTHORIZATION_AUTHED` routes. The former records an
  operator declaration only; it does not independently verify vendor/program
  permission, ownership, legal authority, external scope coverage, or revocation.
  The latter rechecks supplied document bytes and extracted permissions without
  verifying issuer identity or judging legal sufficiency.
- Canonical uppercase application methods explicitly admitted by the sealed
  scope, including body-bearing and write methods. Native transport refuses
  `CONNECT` and protocol upgrades; browser transport also refuses `TRACE`/`TRACK`.
- An immutable external campaign ledger with monotonic sequencing, no campaign
  action-count ceiling, no redirect or automatic retry, scope-bounded synthetic
  discovery, and immediate pre-send authorization revalidation.
- Declared mutations with credential preflight, before/after JSON observation,
  a fresh one-use Ed25519 countersignature, an always-on inverse rollback, and
  rollback verification. Ambiguous mutation or rollback delivery is never
  retried.
- Metadata-only durable results: credential values, request/response bodies,
  header values, arbitrary target-controlled header names, and rejected
  discovery values are not persisted. Operators must use synthetic non-PHI
  identifiers and bodies.

It retains the separately authorized `http-recon-v1` observation protocol:

- A separate `http-recon-v1` protocol with no repository, lens, closure, code
  coverage, or T0-T3 proof-tier claim.
- A default one-action operator-attested mode requiring no authorization files,
  plus an optional externally signed RoE mode with owner key, hash-bound
  document, and fresh target-control proof.
- Exact HTTPS `HEAD`, `GET`, or `OPTIONS` actions only, with schema-enforced hard
  caps, runtime CA and hostname validation, recorded certificate identity,
  concurrency one, durable stop, and explicit uncertain-delivery state.
- No redirects, retries, crawl, authentication, request bodies, retained normal
  response bodies, mutation, exploitation, fuzzing, or load generation.

- Hidden-aware, deterministic repository inventory with handle-bound file reads.
- SHA-256-hashed repository and lens-pack manifests.
- Exact lens activation with deterministic file-and-byte-bounded shards.
- Separate canonical-source, generated-code, test, documentation, and binary
  file/byte denominators.
- Hash-bound dormant retry templates and fixed-point completeness rounds.
- An opt-in `--require-source-closure` finalization gate.
- Controller-owned, provider-neutral database evidence graphs that close over
  clients, bindings, queries, migrations, roles, policies, privileged code,
  replication, CDC, backups, restores, exports, and snapshots.
- JSON Schema Draft 2020-12 finding, store-profile, store-contribution, run,
  RoE, job-result, and root-attestation contracts.
- Accumulating candidate state with immutable claims and checked transitions.
- Fail-closed coverage: unfinished work is never rendered as a clean audit.
- External read/write/execute/network policy decisions.
- Provider-neutral job packets and result ingestion.
- Packet/result binding and declared producer provenance.
- Opt-in exact-byte source and trusted-control snapshots with no live target mount.
- Durable, hash-chained, one-use provider attempts with retry history.
- A digest-pinned, no-network Docker stdio runner with bounded resources and
  verified effective isolation settings.
- Controller-authored byte-delivery/challenge receipts and externally keyed
  Ed25519 execution or structured failure envelopes.
- Detached, externally pinned Ed25519 attestations over exact terminal
  `run.json` bytes.
- Canonical publication of only that detached attestation to one DNS-restricted,
  TLS-SPKI-pinned HTTPS log endpoint.
- Offline-verifiable RFC 6962-style Merkle inclusion receipts under an
  externally pinned Ed25519 checkpoint key.
- A separate exact HTTPS consistency endpoint with RFC 6962/9162 append-only
  proofs between independently signed historical checkpoints.
- An immutable, hash-chained external checkpoint journal with explicit
  baseline initialization, compare-and-swap advancement, crash recovery, and
  offline verification.
- An optional reference-store high-water guard that rejects a local state
  rollback or fork relative to a supplied external checkpoint.
- A stateful reference HTTPS transparency log with signed immutable state,
  exclusive local-process locking, restart recovery, durable idempotency, and
  a dedicated real-TLS conformance gate.
- Separate `INCLUSION_AT_SIGNED_CHECKPOINT` and conditional
  `CONSISTENT_WITH_EXTERNALLY_RETAINED_CHECKPOINT` claims that preserve witness,
  global non-equivocation, revocation, and trusted-time non-claims.
- Separate `PROVIDER_DECLARED`, `CONTROLLER_OBSERVED_CONSUMPTION`, and
  `REMOTE_REQUEST_ACCEPTED` coverage authority in run, Markdown, lifecycle,
  and SARIF output.
- A `remote_static` Rules of Engagement mode that allows one exact
  policy-authorized HTTPS gateway while keeping provider packets read-only and
  credential-free.
- Canonical Ed25519 remote requests, SPKI-pinned HTTPS, RFC 9530 content
  digests, one-use request IDs, signed gateway acceptance receipts, and
  hash-chained schema-v6 attempt recovery.
- Separate existence and proof transitions.
- Per-store database adapter routing, shard-local contributions, and
  controller-synthesized coverage profiles.
- A standalone digest-pinned PostgreSQL 18.4/MySQL 8.4.10 conformance lab with
  eight authorization, session, stored-code, copy, backup, export, and
  migration-role scenarios.
- Content-addressed engine results with checkable transcripts, exact image and
  server identities, hard resource/wall-time bounds, stale-lock recovery, and
  verified container teardown.
- Optional schema-5/6 audit attachment of a complete reference-lab result,
  explicitly labeled `UNANCHORED` and `target_deployment_proven: false`.
- Read-only audit mode and an operator abort command.
- Markdown, JSON, and SARIF 2.1 output.
- Separate unique-file, lens/file-obligation, conceptual-gap, and raw-gap
  reporting with bounded samples.
- Baseline comparison that distinguishes `fixed` from `not-observed`.
- TP/FP/TN/FN, false-clear, severity, and repeated-run stability metrics.

The general dynamic T1/T2 target proof broker is not enabled. T2 retains its
historical meaning: a locally booted application reached only through
loopback. `http-recon-v1` is not T2 and cannot verify a repository finding.
Local static mode does not execute target code, follow target symlinks, or make
network calls. `remote_static` permits only the configured provider-gateway
request; it grants no network authority to repository content or a provider
packet. The local provider boundary runs a separately supplied trusted adapter
image against brokered sealed data; it neither mounts nor executes the target.

The standalone database lab is separate opt-in `LOCAL_DYNAMIC` execution of
controller-owned synthetic SQL. It never reads the audited target or target
credentials, and its reference-engine results never prove a target deployment.

Inventory is fail-closed and resource-bounded. Regular files are opened with
no-follow semantics where Node exposes them, verified with `fstat`, read and
hashed from that same handle, and verified again after the read. A changed
target, symlink/reparse traversal, quota breach, or unreadable path becomes an
explicit inventory error and coverage gap. Defaults are 2 MiB per text file,
100,000 inventory files, 256 MiB of aggregate file content, 200,000 total
traversal entries, and 64 directory levels. Directory enumeration is streamed
only up to the remaining traversal budget; if it crosses that budget, the
directory is rejected as a whole rather than inventorying a filesystem-order
dependent prefix. Callers embedding `inventoryRepository` may lower these
deterministic limits with `maxTextBytes`, `maxInventoryFiles`,
`maxInventoryBytes`, `maxTraversalEntries`, and `maxDirectoryDepth`; the
serialized inventory records the effective values. There is deliberately no
wall-clock traversal timeout because it would make the inventory and its digest
machine-load-dependent.

## Quick start

Requirements: Node.js 20 or newer for planning and manual `next`/`ingest`.
Observed provider execution requires Node.js 24 or newer and a local Docker
daemon. The full development test suite also requires Bash and ripgrep because
it executes selected shell probes directly from the audit lenses.

```powershell
npm.cmd install
npm.cmd test
npm.cmd run audit -- plan C:\path\to\repository --out C:\audit-runs
npm.cmd run audit -- plan C:\path\to\repository --out C:\audit-runs --require-source-closure
npm.cmd run audit -- plan C:\path\to\repository --out C:\audit-runs `
  --max-shard-files 64 --max-shard-bytes 4194304 --max-closure-rounds 3
```

### Authorized external HTTP reconnaissance

This path is separate from `npm.cmd run audit`. The default mode records an
operator declaration of asset-owner permission and seals one exact action. It
does not require a signed RoE, authorization-document, or public-key path:

```powershell
npm.cmd run audit:http-recon -- plan `
  --target-url https://target.example/exact-path `
  --operator-id <operator-id> `
  --authorized-by "asset owner name or role" `
  --authorization-reference "ticket, email, or conversation reference" `
  --attest-authorized `
  --out C:\audit-runs\http-recon-run-001

npm.cmd run audit:http-recon -- next `
  C:\audit-runs\http-recon-run-001

npm.cmd run audit:http-recon -- run `
  C:\audit-runs\http-recon-run-001 <action-id> `
  --operator-id <operator-id> `
  --rationale "authorized header and status observation" `
  --confirm-authorization-current
```

Planning is network-free and `HEAD` is the default method. No certificate
lookup or advance SPKI value is needed: execution validates the certificate
chain with the runtime-configured CA trust, validates the hostname, and records
the certificate and SPKI hashes from that same connection before dispatch. Add
`--tls-spki-sha256 <64-lowercase-hex>` only when an advance pin is available.
Operator-attested plans may also seal one reviewed controller-owned diagnostic
request-header profile with `--request-header-profile`; raw header names and
values remain unavailable. After planning, the CLI accepts no target, URL,
method, TLS policy, header profile,
credential, body, proof endpoint, retry, or limit override. Operator-attested
mode makes zero proof requests and may execute only its one sealed action.
`run` must use the operator ID that created the plan. Its permission claim is
not independently verified.
Stop immediately without needing a still-valid authorization artifact:

```powershell
npm.cmd run audit:http-recon -- stop `
  C:\audit-runs\http-recon-run-001 `
  --operator-id <operator-id> `
  --reason "operator stop"
```

Then `finalize` and `validate` using only the attested bundle; use
`report <bundle>` to locate the generated report. The optional higher-assurance
`plan-signed` command retains the signed RoE, authorization-document, owner-key,
and live-proof workflow. A complete run may say
`NO_FINDINGS_OBSERVED_IN_AUTHORIZED_PROBED_SURFACE`, never clean or safe. Every
report states that repository inventory, lens activation, source closure, and
code coverage are not applicable. See
[`docs/http-recon-protocol.md`](docs/http-recon-protocol.md) and
[`ADR 0014`](docs/adr/0014-operator-attested-http-recon.md), as amended by
[`ADR 0015`](docs/adr/0015-url-first-pkix-http-recon.md) and
[`ADR 0018`](docs/adr/0018-controller-governed-diagnostic-http-recon-headers.md).

### Authorized authenticated HTTP campaign

This path is separate from both repository proof and `http-recon-v1`. Choose one
authorization mode; commands never convert or fall back between them.

`plan-attested --attest-authorized` creates lower-assurance
`OPERATOR_ATTESTED_AUTHED` from the operator's explicit declaration and exact
scope. It is suitable only when the operator actually holds authorization, such
as an applicable bug-bounty or security-testing engagement. The controller does
not fetch or interpret that program, and does not independently verify
vendor/program permission, ownership, legal authority, external scope coverage,
or revocation. The declared authorizer and reference are audit fields, not proof
of vendor approval.

Planning is offline and requires no authorization document:

```powershell
npm.cmd run audit:http-authed -- plan-attested `
  --scope C:\trusted\scope.json `
  --engagement-id <engagement-id> --authorization-id <authorization-id> `
  --operator-id <operator-id> --authorized-by <declared-authorizer> `
  --authorization-reference <operator-held-reference> --attest-authorized `
  --not-before <timestamp> --not-after <timestamp> `
  --cleanup-not-after <timestamp> `
  --target-origin https://target.example --environment production `
  --data-class phi --ownership third_party_owned `
  --credential-browser --browser-extension-id <extension-id> `
  --path-prefix / --method HEAD --method GET --method OPTIONS `
  --test-category api_security --seed-url https://target.example/start `
  --enable-discovery --json
```

For simple probes, use repeatable `--seed-url`. For a complete probe/mutation
plan, replace the seed shortcuts with
`--requests C:\trusted\requests.json`; the bounded JSON array carries the full
declared action envelopes. `--cleanup-not-after` defaults to `--not-after`. A
later value extends only ledger-proven rollback and rollback verification, never
discovery, probes, or a new mutation.

The plan and validation expose `authorization_binding_sha256`,
`authorization_mode: OPERATOR_ATTESTED_AUTHED`, and
`independently_verified: false`. They do not invent a null or synthetic
`authorization_document_sha256`.

Use `plan-written` instead when supplying bounded authorization-document bytes.
`WRITTEN_AUTHORIZATION_AUTHED` binds the document digest, declared issuer/date,
and extracted permissions, but still does not cryptographically verify the issuer
or judge legal sufficiency. Its planner uses the same scope flags plus
`--authorization-document`, `--document-issuer`, and `--document-issued-at`.

For a rotating Chrome session, load the unpacked extension from
`browser/http-authed-chrome` into a dedicated testing profile and copy its
32-character ID from `chrome://extensions`. The extension has only `activeTab`,
`scripting`, and loopback-host access: it has no cookie, storage, debugger,
request-observer, broad target-host, or profile permission. Browser mode creates
`CHROME_ACTIVE_TAB_SESSION`; no cookie value or credential digest enters the
scope. It uses Chrome's PKIX/hostname validation and cannot be combined with
`--tls-spki-sha256`.

Probe-only plans need no per-mutation approver. Add `--mutation-authorized` plus
the approver public-key and enrollment flags shown by `--help` when the sealed
permissions include write-capable probes or declared reversible mutations. The
planner does not create synthetic bodies or countersignatures. Validate with the
matching command and retain the returned grant hash:

```powershell
npm.cmd run audit:http-authed -- validate-attested `
  --scope C:\trusted\scope.json `
  --json

npm.cmd run audit:http-authed -- validate-written `
  --scope C:\trusted\written-scope.json `
  --authorization-document C:\trusted\authorization.pdf `
  --json
```

Run the campaign with an absolute ledger outside the target; the runtime creates
the ledger when that path does not yet exist. Mutating actions also require an
absolute materials directory containing the declared synthetic bodies and
`countersignature-N.json` approvals:

```powershell
npm.cmd run audit:http-authed -- campaign-attested `
  --scope C:\trusted\scope.json `
  --campaign-grant-sha256 <hash-from-validation> `
  --ledger C:\trusted\campaign-ledger `
  --materials C:\trusted\campaign-materials `
  --operator-id <operator-id> `
  --confirm-authorization-current `
  --credential-browser `
  --json
```

For written mode, use `campaign-written` with the written scope and add
`--authorization-document`. An attested command rejects document flags, and a
written command rejects an attested scope.

Ordinary actions stop at `validity.not_after`. If a previously dispatched,
approval-consumed mutation remains incomplete, restarting the matching campaign
before `validity.cleanup_not_after` opens the existing ledger in cleanup-only
mode and can send only the sealed rollback and rollback-verification requests.
It writes `CLEANUP_SESSION_CONFIRMED` before cleanup dispatch, does not write a
new ordinary session confirmation, and never queues or sends new work.

The browser campaign prints a loopback port and one-time pairing capability. In
the exact logged-in target tab, open the companion, enter those values, select
**Load controller binding**, and verify the exact origin and full campaign grant.
Then select **Attach and start campaign**. That is one extension attach per
campaign. The companion automatically prepares and executes each
controller-authorized action; only emergency stop or detach remains manual. Chrome
applies the current session and processes normal cookie rotation on every sealed
same-origin request. Cookie and Authorization values never cross into the
controller, ledger, command output, or agent context. Origin, tab, document,
action-binding, or protocol drift fails closed, and ambiguous delivery is never
retried.

Sealed `env:NAME` and redirected `--credential-stdin` remain explicit fallbacks
for exported credentials. Stdin is read once per process and must match the
binding at live execution; it does not provide automatic rotation. Never put an
exported credential in chat, argv, or a file. Validation needs no credential.

Use synthetic non-PHI test data even when the target data class is PHI. Discovery
can enqueue only scope-valid
`GET`/`HEAD`/`OPTIONS` probes; it never synthesizes mutation envelopes. See
[`ADR 0016`](docs/adr/0016-authenticated-mutation-actions.md),
[`ADR 0017`](docs/adr/0017-operator-attested-authenticated-campaigns.md), and
[`schemas/http-authed-scope.schema.json`](schemas/http-authed-scope.schema.json).

### Disposable database conformance

The lab requires a trusted absolute Docker CLI path, a local Docker daemon, and
the two exact manifest images already present. Plan bundles outside the project
and audited target:

```powershell
npm.cmd run conformance:database -- plan C:\database-lab-runs\run-001
npm.cmd run conformance:database -- run C:\database-lab-runs\run-001 C:\trusted\database-lab-config.json
npm.cmd run conformance:database -- validate C:\database-lab-runs\run-001
```

The trusted configuration must satisfy
[`schemas/database-conformance-config.schema.json`](schemas/database-conformance-config.schema.json),
name an absolute Docker executable, set
`acknowledge_local_dynamic: true`, and provide bounded limits. If a controller
process dies, `conformance:database -- unlock <bundle>` removes only a parsed
dead-PID lock; the next run inspects and recovers only containers bearing the
exact run/engine labels.

A fully passing two-engine result can be attached as reference context when a
new static audit is planned:

```powershell
npm.cmd run audit -- plan C:\path\to\repository --out C:\audit-runs `
  --database-conformance C:\database-lab-runs\run-001
```

The controller copies and hashes a bounded evidence projection into the audit
bundle and seals it for database-lens jobs. Reports keep it in a separate
reference section. It does not change store coverage, finding proof tier,
verification status, or target deployment claims.

### Install the development checkout as a Codex skill

Link the whole repository, not only `skills/red-team-audit`, because the
canonical skill deliberately enters through the executable controller,
schemas, and package dependencies at the repository root:

```powershell
$skillDestination = Join-Path $env:USERPROFILE '.codex\skills\red-team-audit'
New-Item -ItemType Junction -Path $skillDestination -Target (Resolve-Path .)
```

The destination must not already exist. Codex discovers the skill on the next
turn. CLI entrypoint detection resolves the physical path, so commands invoked
through the junction execute normally.

The plan command writes a versioned bundle and prints `State: PLANNED`. A plan
is not an audit result and cannot be mistaken for one. `next`, `ingest`, and
`finalize` re-inventory the target and refuse to mix evidence if any in-scope
input changed after planning.

A custom `--out` must be outside the audited repository so creating the bundle
cannot change its own snapshot denominator. Omit `--out` to use the built-in
`.audit-runs` directory for a hash-only plan, which inventory excludes
explicitly. `--seal-source` always requires an output outside the target,
because that bundle is a sensitive exact-byte source archive.

Inspect the bounded jobs:

```powershell
npm.cmd run audit -- next C:\audit-runs\<run-directory>
```

A provider consumes one returned job packet and emits a job result satisfying
[`schemas/job-result.schema.json`](schemas/job-result.schema.json). Ingest it:

```powershell
npm.cmd run audit -- ingest C:\audit-runs\<run-directory> provider-result.json
```

Repeat `next` and `ingest` until the completeness job is finished, then:

```powershell
npm.cmd run audit -- finalize C:\audit-runs\<run-directory>
```

The final bundle contains `report.md`, `results.sarif`, hash-bound
`coverage.json`, raw normalized job results, inventory hashes, policy, and the
canonical `run.json`. `coverage-plan.json` is the immutable planning snapshot;
it is deliberately distinct from final coverage.

Anchor a terminal bundle with a signing key and output path kept outside both
the target and bundle:

```powershell
npm.cmd run audit -- attest C:\audit-runs\<run-directory> `
  --signing-key C:\trusted\root-private.pem `
  --out C:\trusted\attestations\<run-id>.json

npm.cmd run audit -- validate C:\audit-runs\<run-directory> `
  --root-attestation C:\trusted\attestations\<run-id>.json `
  --root-public-key C:\trusted\root-public.pem
```

The detached attestation binds the exact terminal `run.json` bytes, run
identity, state, phase, and externally pinned Ed25519 key. It can optionally be
published to a separately operated transparency log:

```powershell
npm.cmd run audit -- publish C:\audit-runs\<run-directory> `
  C:\trusted\transparency-log-config.json `
  --root-attestation C:\trusted\attestations\<run-id>.json `
  --root-public-key C:\trusted\root-public.pem `
  --transparency-checkpoint-journal C:\trusted\checkpoint-journal `
  --initialize-transparency-checkpoint-journal `
  --out C:\trusted\receipts\<run-id>.json

npm.cmd run audit -- validate C:\audit-runs\<run-directory> `
  --root-attestation C:\trusted\attestations\<run-id>.json `
  --root-public-key C:\trusted\root-public.pem `
  --transparency-receipt C:\trusted\receipts\<run-id>.json `
  --transparency-log-public-key C:\trusted\transparency-log-public.pem `
  --transparency-log-origin audit-log.example/v1 `
  --transparency-checkpoint-journal C:\trusted\checkpoint-journal
```

Publication still transmits only canonical root-attestation JSON. A verified
receipt proves inclusion at one signed checkpoint. With a version 1.1 log
configuration and an explicitly initialized external journal, later
publications additionally retrieve and retain an append-only consistency proof.
Offline validation verifies the complete retained chain without contacting the
log. This is client-local continuity, not witness quorum, global
non-equivocation, revocation status, or trusted time. See
[`docs/transparency-protocol.md`](docs/transparency-protocol.md).

The shipped reference implementation is a bounded conformance service, not a
production hosted log. It requires operator-supplied TLS material, an external
Ed25519 signing key, and a dedicated external state directory. Its signed
local chains detect holes, truncation, replacement, and contradictory tails.
Supplying the journal head as `trustedCheckpoint` (or canonical
`trustedCheckpointBytes`) also prevents startup against an older or conflicting
prefix. Without that external input, whole-directory restoration remains a
non-claim. Composition and non-claims
are documented in
[`providers/reference-transparency-log/README.md`](providers/reference-transparency-log/README.md).
Run its actual HTTPS/restart/offline-validation gate with:

```powershell
npm.cmd run test:transparency:https
```

The default fan-out bound is 64 files and 4 MiB of inventoried raw bytes per
job, with up to three closure rounds. `--max-shard-files`,
`--max-shard-bytes`, and `--max-closure-rounds` select different controller
bounds at planning time. Those values, every initial shard, and every dormant
retry template are committed into the plan; repository content and provider
output cannot raise them later.

### Controller-observed provider execution

Create a sensitive runner-ready bundle only when exact source-byte archiving is
acceptable:

```powershell
npm.cmd run audit -- plan C:\path\to\repository --out C:\audit-runs --seal-source
npm.cmd run audit -- run-provider C:\audit-runs\<run-directory> C:\trusted\provider-config.json
```

The provider configuration and Ed25519 private key must be outside both the
target and bundle. The image must be pinned by `sha256` digest and the Docker
runtime path must be absolute. `run-provider` persists a lease before launch,
serves only allowlisted sealed FILE/CONTROL capabilities over bounded JSONL,
and records one signed execution envelope. A retry gets a new attempt and
nonce; controller-observed failures retain a signed structured error, bounded
stderr, and any partial receipt without receiving coverage authority. Failed
attempts remain in the hash-chained event history. See
[`docs/provider-protocol.md`](docs/provider-protocol.md) and
[`schemas/provider-config.schema.json`](schemas/provider-config.schema.json).

### Signed remote gateway execution

Remote execution requires an external `remote_static` Rules of Engagement
policy whose network allowlist contains the exact gateway endpoint:

```powershell
npm.cmd run audit -- plan C:\path\to\repository `
  --out C:\audit-runs `
  --roe C:\trusted\remote-static-roe.json `
  --seal-source

npm.cmd run audit -- run-remote `
  C:\audit-runs\<run-directory> `
  C:\trusted\remote-gateway-config.json
```

The controller persists the exact canonical signed request and a schema-v6
lease before network I/O. The HTTPS client permits no redirect, pins one
validated public DNS answer for the connection, pins the
certificate SPKI and gateway Ed25519 key, verifies the response content digest,
and records the signed acceptance before committing the job result.

An expired or ambiguous attempt is retained as a recoverable failure. Its
request ID is never reused; retry creates a new attempt and signed request.
Configuration, endpoint, transform, or key rotation inside one run is rejected.
Source bytes leave the local machine only on this explicitly authorized path.
`REMOTE_REQUEST_ACCEPTED` proves request acceptance, not provider
comprehension, semantic correctness, or independent proof.

See [`docs/adr/0008-remote-attempt-ledger-integration.md`](docs/adr/0008-remote-attempt-ledger-integration.md)
and [`schemas/remote-gateway-config.schema.json`](schemas/remote-gateway-config.schema.json).

For historical verification, pin the controller identity with an Ed25519 public
key kept outside both target and bundle:

```powershell
npm.cmd run audit -- validate C:\audit-runs\<run-directory> `
  --receipt-public-key C:\trusted\receipt-public-key.pem
```

Stop a run at any time:

```powershell
npm.cmd run audit -- abort C:\audit-runs\<run-directory> --reason "operator safety stop"
```

This records an immutable `ABORTED` terminal state. It never authorizes target
execution. `run-provider` separately owns and removes its exact container.

If a CLI process exits while replacing `run.json`, its lock remains as evidence
instead of being guessed stale automatically. After confirming that no update is
running, use:

```powershell
npm.cmd run audit -- unlock C:\audit-runs\<run-directory>
```

`unlock` parses the recorded owner PID and refuses to remove the lock while that
process is alive. It also reclaims a recovery marker left by a crashed
dead-PID `unlock`. New lock and recovery records are published atomically only
after their content is durable. Under its scoped recovery lock, explicit
`unlock` may also remove a legacy malformed run lock only after two identical
reads; normal mutations continue to fail closed on that marker. Linked lock
files and malformed recovery ownership records are rejected. PID reuse fails
safe: if an unrelated live process has inherited the recorded PID, wait for it
to exit or independently verify the marker before manual recovery.

## Safety model

The repository and external target are untrusted data. A README, source
comment, `AGENTS.md`, generated file, HTTP response, DNS answer, or tool output
cannot:

- Change scope or capability mode.
- Grant file, command, credential, or network access.
- Edit the Rules of Engagement.
- Skip validation or completeness.
- Convert missing work into a clean result.

The policy kernel returns structured decisions but performs no I/O itself.
Manual dispatchers must additionally resolve symlinks and recheck real-path
containment immediately before access. The observed runner instead reads
verified sealed shards and never reopens the live target.

Provider result JSON is read through an 8 MiB bounded reader before parsing.
The result contract additionally caps one response at 65,536 examined paths and
4,096 findings, coverage gaps, store profiles, and store contributions. Bundle artifact reads and
generated result/report writes reject symbolic-link or reparse-point path
components and require canonical containment beneath the run directory. A run
manifest or individual bundle artifact is capped at 128 MiB; integrity
verification streams artifact hashes and accepts at most 16,384 artifacts and
512 MiB of aggregate artifact bytes per command. Planning and append operations
reserve against the same count and aggregate ceilings before writing, so a
successful controller operation cannot make its own bundle unreadable.
Planning applies the same per-artifact ceiling, so it cannot successfully emit
a bundle the CLI later refuses to read. These checks are against observed
filesystem state; use a bundle directory that a hostile local process cannot
concurrently replace (see `SECURITY.md`).

This architecture uses OWASP APTS 0.1.0 as a governance design baseline and
NIST SP 800-115 as a planning and authorization baseline. The project claims
conformance with neither. See
[`docs/adr/0001-executable-audit-platform.md`](docs/adr/0001-executable-audit-platform.md)
and [`ADR 0013`](docs/adr/0013-authorized-external-http-recon.md).
Operator-attested authorization is the lower-assurance exception documented in
[`ADR 0014`](docs/adr/0014-operator-attested-http-recon.md); its URL-first TLS
policy is documented in [`ADR 0015`](docs/adr/0015-url-first-pkix-http-recon.md).

## Repository audit run states

The separate HTTP-reconnaissance states and nonclaims are defined in
[`docs/http-recon-protocol.md`](docs/http-recon-protocol.md).

- `PLANNED`: inventory and jobs exist; no provider work is implied.
- `RUNNING`: at least one stage has begun.
- `COMPLETED`: all required protocol jobs succeeded with no declared coverage
  gap; its per-job authority still distinguishes provider declarations from
  controller-observed byte consumption, neither of which proves comprehension.
- `COMPLETE_WITH_GAPS`: work terminated honestly, with exclusions or gaps.
- `ABORTED`: an operator or policy control stopped the run.
- `FAILED`: required protocol work failed, or the control plane could not
  preserve a valid run.

Finding count never decides run state.

## Job protocol

The state machine is:

```text
RECON -> FANOUT -> TRIAGE
      -> PROOF existence -> PROOF verification
      -> PATCH (read-only/skipped by default)
      -> REPORT -> COMPLETENESS -> FINALIZED
```

Providers may add reasoning, but may not skip a stage. In particular, the
existence check must be committed before proof-tier or verification claims.

See [`docs/provider-protocol.md`](docs/provider-protocol.md) for the complete
record contract.

## Validation and quality gates

```powershell
npm.cmd test
npm.cmd run test:platform
npm.cmd run lint
npm.cmd run gen -- --check
npm.cmd run gen:benchmarks -- --check
```

Real-container conformance is a separate, fail-closed release gate. The host
controller still requires Node 24; the small protocol peer can use its separately
digest-pinned runtime. The CI-reviewed peer pin is shown below. Pass its
immutable local image ID—not a mutable tag:

```powershell
docker build `
  --file providers/reference-byte-consumer/Dockerfile.conformance `
  --build-arg NODE_IMAGE=node:22-bookworm@sha256:c601a46abb4d2ab80a9dc3da208d50d1122642d53f17a101926ace71e5a9bf1c `
  --tag red-team-audit-reference-byte-consumer:conformance `
  providers/reference-byte-consumer
$env:RTA_DOCKER_RUNTIME = (Get-Command docker.exe).Source
$env:RTA_PROVIDER_IMAGE = docker image inspect `
  --format '{{.Id}}' red-team-audit-reference-byte-consumer:conformance
npm.cmd run test:provider:docker
```

The gate refuses to run when either environment variable is absent. Its
in-container probes exercise root-filesystem and `/work` mount behavior,
network and host isolation, Linux privilege state, effective cgroup and
file-descriptor/PID limits, plus timeout cleanup. The reference peer proves
protocol and containment behavior only; it deliberately reports that no
semantic analysis occurred.

Benchmark input and configurable release gates are documented in
[`benchmarks/README.md`](benchmarks/README.md). Capability observations must
name and exactly match one normalized repeated run; the scorecard records that
binding so stability cannot be supplied from an unrelated evidence set.

```powershell
npm.cmd run audit -- benchmark evaluation.json `
  --thresholds benchmarks/thresholds.json `
  --out scorecard.json
```

The development profile currently requires all 64 committed vulnerable/clean
cases, zero clean-case findings, zero explicit false clears, zero invalid
records, and repeated-run stability measurements. Thresholds are versioned
configuration, not hidden product claims.

## Result lifecycle

Compare two validated runs:

```powershell
npm.cmd run audit -- compare baseline\run.json current\run.json
```

An absent finding is classified `fixed` only when the current run covers the
relevant file under the relevant lens, no attributable coverage gap can hide
it, and both runs use the same repository root, lens pack, and Rules of
Engagement. Database findings additionally require the same assessed store,
topic, adapter, engine/version/deployment semantics, and effective principal.
Otherwise the finding is `not-observed`; unrelated or differently governed runs
are explicitly non-comparable. Lifecycle output preserves whether that basis
was provider-declared or controller-observed byte consumption; neither is
independent semantic proof.

Historical bundles remain validatable and reportable from their own hashed
manifests after the installed lens pack advances. Without an externally pinned
root attestation they are explicitly `UNANCHORED`; with one, exact manifest
replacement is detected. Active `next`, `ingest`, and `finalize` operations
additionally require the installed trusted pack to match the planned pack; old
and new packs compare as explicitly non-comparable rather than making the
baseline unreadable.

## Coverage closure

Version 0.4 classifies the immutable inventory into five independent
denominators: canonical source, generated code, tests, documentation, and
binaries. Each denominator records total and examined files and raw bytes.
Canonical source never disappears into a combined percentage merely because a
repository contains large generated, test, or documentation trees.

For every active lens, the controller canonically sorts applicable files and
packs them into deterministic jobs bounded by both file count and bytes. A
single available text file larger than the configured byte bound is a planning
error. Shard identity is derived from its ordered scope rather than filesystem
enumeration order.

Completeness measures applicable lens/file pairs, not only unique paths. If a
pair remains uncovered, the controller may activate the already sealed dormant
retry template for its original bounded shard. It then repeats the required
triage, proof, and completeness work until the measurement reaches a fixed
point or the planned round budget is exhausted. Providers cannot create a new
scope, split an easier residual shard, or extend the retry budget. Exhausted or
unmeasured closure remains an explicit gap.

`--require-source-closure` turns that measurement into a finalization gate.
When enabled, the controller refuses to finalize unless closure converged and
every applicable canonical-source lens/file pair was examined. Without the
flag, an honest `COMPLETE_WITH_GAPS` result remains possible; zero findings
never overrides incomplete coverage.

Machine coverage retains one stable exact record per lens/file obligation.
Reports separately project open records into conceptual gap groups and show
both counts, with bounded examples. Repeated attempts do not multiply the
conceptual count, and a successful retry resolves the same exact obligation
without erasing its history.

## Database coverage

Database security is a first-class domain, not a PostgreSQL-only RLS checklist.
Each finding binds to one profiled store and engine adapter, the effective
principal path, the enforcement plane, and copy/lifecycle behavior. Unknown
engine, deployment, or principal semantics force the store to
`inventory-only / NOT_ASSESSED / UNPROVEN` and cap effective severity at
Medium. The run records coverage per store and assessed database topic; one
declared profile cannot cross-clear another store.

Before lens activation, the controller builds a bounded, deterministic,
secret-free database evidence graph. It follows strong manifest, import,
connection-token, infrastructure, query, migration, principal, policy, and
copy-artifact relationships within manifest-defined project roots. Connected
paths augment the database lens scope before sharding. Unconnected examples in
documentation, generated output, tests, and fixtures remain context-only.
Ambiguous engines, versions, deployments, and principals remain explicitly
unresolved; discovery does not invent semantic support or a clean verdict.

All 24 shipped engine/service adapters expose an allowlisted semantic rule
vocabulary. `ASSESSED` engine, principal, tenancy, enforcement, copy,
availability, and assumption claims must cite controller-inventoried evidence
paths; placeholder versions, principals, and invented semantic rule IDs fail
validation.

Run schemas 4 and 5 record one authenticated contribution for every successful base
database shard/store relationship. Only the authority shard may supply the
local semantic profile; context shards supply local topic, evidence, and gap
claims. At the fan-out barrier the controller deterministically synthesizes one
profile per discovered store. It reports `ASSESSED` only when every required
contribution closes its local paths and all ten database topics; missing or
partial contributions preserve a gap.

Version 0.7 ships the disposable multi-engine matrix for two-tenant
authorization, pooled-session reset, direct-table bypass, views and stored
code, CDC/history, backups, exports, and migration/runtime role separation.
The next database expansion is additional versioned engines and managed-service
variants after the v1 result and lifecycle contracts have operational history.

## Project boundaries

- Do not upload source, evidence, secrets, PII, or PHI by default.
- Do not run repository T1/T2 proof against production. Production HTTP actions
  require a separate `http-authed-v1` campaign and actual authorization; an
  operator attestation records a claim but does not verify it.
- Do not infer completeness from zero findings.
- Do not automatically apply patches; external mutation requires its declared
  reversible action and fresh countersignature.
- Do not claim unsupported frameworks or engines were assessed.
- Do not treat this tool as a compliance attestation or a replacement for a
  qualified penetration test.
