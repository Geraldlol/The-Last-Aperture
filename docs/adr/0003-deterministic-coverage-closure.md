# ADR 0003: Deterministic coverage closure and controller-owned database discovery

- Status: Accepted
- Date: 2026-07-29
- Owners: The Last Aperture platform
- Supersedes: none
- Extends: ADR 0001 and ADR 0002

## Context

The 0.3 execution protocol seals source bytes and records observed provider
consumption, but its analysis denominator is still too coarse:

- one activated lens produces one unbounded semantic job;
- coverage has one flat file count, so source, generated artifacts, tests,
  documentation, and binaries are indistinguishable;
- completeness is a terminal provider job instead of a fixed-point controller
  loop;
- database stores are declared by the database provider after activation, so a
  driver match can leave connection, query, migration, policy, role, and copy
  surfaces outside the immutable scope;
- repeated lens/file misses are rendered as if every occurrence were a unique
  conceptual gap.

Those properties allow a provider failure, context limit, or incomplete
activation rule to make the audit look more complete than the evidence permits.
They also make large repositories depend on provider context size rather than a
controller-enforced work bound.

## Decision

### 1. Classify every inventory entry before activation

The controller assigns exactly one stable category to every inventory entry:

1. `canonical-source`
2. `generated-code`
3. `tests`
4. `docs`
5. `binaries`

Classification is deterministic and conservative. Explicit binary content wins.
Explicit test conventions win next, followed by generated/vendor conventions
and documentation conventions. Ambiguous text defaults to
`canonical-source`; it never defaults out of source closure.

Coverage records file and byte totals, examined values, and unexamined values
for each category. The complete per-file inventory remains the authority behind
those aggregates.

### 2. Shard semantic lens work by files and raw bytes

Activated fan-out scopes are sorted by repository-relative path and greedily
packed with two controller limits:

- maximum files per shard; and
- maximum inventoried raw bytes per shard.

No shard may exceed either limit. A single available text file larger than the
byte limit is a planning error, not an oversized job. Each shard records a
stable scope digest, its bounds, file and byte counts, and its ordinal.

For compatibility, a lens with one shard may retain its historical job ID. A
multi-shard lens uses deterministic shard-qualified IDs. Identity comes from
the sealed scope and plan, never from provider output.

### 3. Seal retry templates during planning

Completeness may requeue an uncovered original shard, but it may not create an
unsealed provider scope at runtime. Planning therefore seals one retry sidecar
for every original shard and permitted closure round. A retry has the same
bounded files, bytes, lens digest, topic authority, and discovered database
projection as its parent shard.

The controller schedules a retry template only when at least one applicable
lens/file pair in that shard remains uncovered. Previously examined files may
be re-read; this is preferable to manufacturing a provider-controlled subset.

### 4. Make completeness a fixed-point protocol

Completeness has explicit controller state and history:

- `PENDING`
- `MEASURING`
- `REQUEUED`
- `CONVERGED`
- `BUDGET_EXHAUSTED`
- `UNMEASURED`

After each completeness measurement, the controller compares immutable
applicable lens/file pairs with accumulated per-lens examined paths.

- Zero uncovered pairs produces `CONVERGED`.
- Uncovered pairs with remaining rounds schedule the corresponding sealed retry
  shards.
- After retry fan-out, new candidates pass through round-specific triage and
  the ordinary existence and verification proof protocol before remeasurement.
- Exhausting the configured round budget produces `BUDGET_EXHAUSTED`; it is
  never relabelled convergence.
- A failed or unavailable measurement produces `UNMEASURED`.

The loop runs inside the completeness phase so run provenance and earlier phase
history remain monotonic. Closure-round jobs are explicitly marked and are the
only fan-out, triage, or proof jobs legal in that phase.

### 5. Add strict source closure as an opt-in finalization gate

`--require-source-closure` is persisted in the immutable plan. When enabled,
finalization fails unless:

- completeness is `CONVERGED`;
- every applicable `canonical-source` file is globally examined; and
- every applicable lens/file pair for canonical source is covered.

Without the flag, a bounded run may finalize honestly as
`COMPLETE_WITH_GAPS`, including `BUDGET_EXHAUSTED` or `UNMEASURED` closure.

### 6. Discover database surfaces in the controller

Before activation, the controller builds a bounded, deterministic database
evidence graph from inventoried text. It recognizes engine-specific and generic
client seeds across SQL, document, key-value, graph, wide-column, search,
warehouse, vector, embedded, cloud, and BaaS families.

Within the nearest manifest-defined project root, discovery follows seeds into:

- client and driver declarations;
- connections and credentials/configuration;
- queries, repositories, and ORM access;
- schemas and migrations;
- roles, grants, policies, rules, and tenant enforcement;
- replication, CDC, backup, restore, export, and snapshot paths.

Explicit relative references and shared bounded symbols add graph edges.
Project membership adds a conservative follow edge from a client seed to
database-shaped surfaces in the same project. Every evidence signal and edge is
controller-derived and path-bounded.

The discovered paths augment the database lens scope before sharding. A
discovered store is a denominator record, not a semantic adapter selection:
unknown versions, deployment variants, principals, or engine semantics remain
inventory-only until a provider supplies defensible evidence. Provider profiles
must bind to controller-discovered store IDs in the new run contract.

### 7. Separate exact gap occurrences from unique report groups

Exact machine coverage retains stable lens/file gaps. Reporting projects those
records into:

- unique conceptual gap groups; and
- exact lens/file occurrences.

The exact key excludes retry job identity, so repeated misses of the same
lens/path do not create new exact gaps. The conceptual projection groups
structured file misses by affected lens while retaining the exact lens/path
denominator separately. A later successful retry resolves the corresponding
lens/file gap without rewriting its occurrence history. Reports show aggregate
counts and bounded examples instead of dumping the full cross-product as unique
findings.

## Contract and compatibility

The new planner emits run schema `3.0.0` and platform version `0.4.0`. The
validator continues to accept 1.x and 2.x manifests. Existing 2.x runs preserve
their historical single-job and flat-coverage semantics; closure and discovery
requirements apply only when their new fields are present.

Provider dispatch remains backward compatible at the job-result boundary.
Shard, closure-round, category, and database-discovery metadata are
controller-supplied inputs. Providers cannot change them.

## Consequences

### Positive

- Work is reproducible and bounded independently of provider context windows.
- “Complete” means a measured fixed point, not merely that a final prompt ran.
- Strict mode can act as a source-coverage release gate.
- Database activation reaches security controls and data-copy paths beyond the
  first package or connection match, without assuming PostgreSQL or RLS.
- Human reports distinguish one systemic omission from thousands of affected
  lens/file pairs.

### Costs

- Planning writes more sidecars because retry authority is sealed in advance.
- A partial result can cause a whole bounded shard to be re-read.
- Coverage and transition validation become more stateful.
- Controller discovery is intentionally conservative and can create honest
  inventory-only stores that require provider resolution.

## Security invariants

1. Repository content never selects shard limits, retry budgets, closure policy,
   or adapter authority.
2. Every dispatched source path belongs to one immutable, byte-bounded sidecar.
3. A provider cannot add a path to its scope or mark a different shard covered.
4. Applicable denominators and database discovery are immutable after planning.
5. Coverage is monotonic; a path or lens/file pair cannot become unexamined.
6. `BUDGET_EXHAUSTED` and `UNMEASURED` always remain reportable gaps.
7. Strict source closure cannot be bypassed by reporting zero findings.

## Verification

The implementation must include:

- deterministic boundary tests for exact file and byte limits;
- permutation tests proving stable shard identity;
- multi-shard aggregation and partial-result retry tests;
- convergence, repeated-omission budget exhaustion, failed measurement, and
  new-finding closure-round lifecycle tests;
- category and byte-denominator fixtures, including ambiguous files defaulting
  to canonical source;
- strict finalization acceptance and rejection tests;
- non-PostgreSQL database projects covering connections, queries, migrations,
  roles/policies, and copy paths;
- database-profile binding across multiple shards;
- unique-versus-lens/file report projection tests;
- legacy 1.x/2.x validation tests and the full platform suite.

## Rollback

The 3.0 planner can be rolled back without mutating existing bundles because run
manifests, sidecars, and snapshots are immutable. A rollback may continue to
validate historical 3.0 artifacts, but must not reinterpret a
`BUDGET_EXHAUSTED` or `UNMEASURED` run as converged.
