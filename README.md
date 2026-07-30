# Red Team Audit

Red Team Audit is an evidence-first, agent-assisted source audit platform. Its
security lenses supply domain judgment; a deterministic Node.js control plane
owns inventory, activation, scope, state transitions, coverage accounting,
evidence lineage, and reporting. Manual providers declare which scoped files
and stores they examined. The optional sealed runner can prove that its adapter
completed a byte challenge over exact planned bytes, but cannot prove the
provider understood or analyzed those bytes correctly.

It is not another regex scanner. Agent and scanner output is provider evidence:
it is packet-bound, attributed, schema-checked, scope-checked, and capped before
it enters the run, but its factual accuracy still depends on proof and review.

## Current release

Version 0.4.0 adds bounded, recursively measured coverage and controller-owned
database discovery to the sealed provider-execution foundation:

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
- JSON Schema Draft 2020-12 finding, store-profile, run, RoE, and job-result contracts.
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
- Separate `PROVIDER_DECLARED` and `CONTROLLER_OBSERVED_CONSUMPTION` coverage
  authority in run, Markdown, lifecycle, and SARIF output.
- Separate existence and proof transitions.
- Per-store database adapter routing and coverage profiles.
- Read-only audit mode and an operator abort command.
- Markdown, JSON, and SARIF 2.1 output.
- Separate unique-file, lens/file-obligation, conceptual-gap, and raw-gap
  reporting with bounded samples.
- Baseline comparison that distinguishes `fixed` from `not-observed`.
- TP/FP/TN/FN, false-clear, severity, and repeated-run stability metrics.

The dynamic T1/T2 proof broker is not enabled. Static mode does not execute
target code, follow target symlinks, or make network calls. The reference
provider boundary runs a separately supplied, trusted adapter image against
brokered sealed data; it does not mount or execute the target.

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

The repository under audit is untrusted data. A README, source comment,
`AGENTS.md`, generated file, HTTP response, or tool output cannot:

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
4,096 findings, coverage gaps, and store profiles. Bundle artifact reads and
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

This architecture is informed by OWASP APTS 0.1.0, but the project does not
claim APTS conformance. See
[`docs/adr/0001-executable-audit-platform.md`](docs/adr/0001-executable-audit-platform.md).

## Run states

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
manifests after the installed lens pack advances. Active `next`, `ingest`, and
`finalize` operations additionally require the installed trusted pack to match
the planned pack; old and new packs compare as explicitly non-comparable rather
than making the baseline unreadable.

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

Before lens activation, the 0.4 controller builds a bounded, deterministic,
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

The next database milestone is a disposable multi-engine conformance lab for
two-tenant authorization, pooled-session reset, direct-table bypass, views and
stored code, CDC/history, backups, exports, and migration/runtime role
separation.

## Project boundaries

- Do not upload source, evidence, secrets, PII, or PHI by default.
- Do not run dynamic proof against production.
- Do not infer completeness from zero findings.
- Do not automatically apply patches; mutation requires separate authorization.
- Do not claim unsupported frameworks or engines were assessed.
- Do not treat this tool as a compliance attestation or a replacement for a
  qualified penetration test.
