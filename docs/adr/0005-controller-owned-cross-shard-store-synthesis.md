# ADR 0005: Controller-owned cross-shard store synthesis

- Status: Accepted
- Date: 2026-07-30
- Owners: Red Team Audit platform
- Extends: ADR 0001 and the run schema 3 database authority model

## Context

Database discovery can connect one store to source, configuration, policy, and
copy artifacts that do not fit in one bounded lens shard. Run schema 3 assigns
exactly one profile-authority shard from the candidate's first evidence path.
Other shards know that they are related to the store, but cannot return or
rewrite its profile.

That prevents a context shard from manufacturing a clearance. It also means a
legitimate cross-shard store can never become `ASSESSED`: the authority shard
cannot cite evidence outside its scope, while later related-shard results have
no append-only record that can affect the store profile.

Provider result authentication binds a result to one immutable dispatch packet.
It does not make provider judgment controller-owned. The controller can,
however, own the denominator, provenance checks, conservative merge rules, and
the exact point at which a final profile is materialized.

## Decision

### 1. Run schema 4 records append-only store contributions

Every successful base `database-and-data-stores` shard returns exactly one
contribution for each controller-assigned `database_store_id`.

A contribution declares:

- the discovered `store_id`;
- local `coverage_state`;
- database-owned topics assessed in that shard;
- evidence paths examined in that shard;
- explicit local coverage gaps; and
- on the one profile-authority shard only, a complete local store profile.

The controller derives the contribution's job ID, packet digest, coverage
authority, and `AUTHORITY` or `CONTEXT` role. Providers cannot set those
fields. Context shards cannot return a profile.

The controller accepts evidence only when it is in all three sets:

1. the immutable job scope;
2. the provider-declared examined paths; and
3. the controller-discovered component for that store.

An `ASSESSED` contribution must cover every store path assigned to that shard,
claim all ten database topics, and contain no gap. Partial and unassessed
contributions must preserve at least one gap.

### 2. The controller synthesizes once at the fan-out barrier

After all base lens jobs are terminal and before triage starts, the controller
materializes at most one final profile for each discovered store.

The synthesis denominator is the immutable set of base database shards whose
scope intersects the store. The controller requires:

- exactly one authenticated authority contribution;
- one authenticated contribution from every related base shard;
- no duplicate `(job_id, store_id)` pair;
- canonical union of contribution evidence paths; and
- complete coverage of the discovered store scope.

The authority contribution supplies store identity, adapter selection,
principal model, tenancy, enforcement, copy, availability, assumptions, and
other structured profile dimensions. Context contributions can widen evidence
and constrain the result, but cannot replace those dimensions.

No profile is materialized when the usable authority contribution is absent;
the controller-discovered store gap remains open. Otherwise, the final profile
is `ASSESSED` only when the authority profile and every
required contribution are `ASSESSED`, every contribution claims all database
topics, every discovered scope path is evidenced, and no contribution carries
a gap. Otherwise the controller degrades the result:

- `NOT_ASSESSED` if the authority profile is unassessed;
- `PARTIAL` for every other incomplete aggregation.

Assessed topics become the ordered intersection across required contributions.
Coverage gaps are a canonical bounded union of provider gaps and
controller-generated missing, duplicate, failed, or uncovered-contribution
reasons.

Providers cannot write `store_profiles` directly in run schema 4. The
controller-generated profile is append-only and its exact value is
recomputable from discovery, immutable job metadata, and the contribution
ledger.

### 3. Bound the aggregation

Planning fails before publication when the number of required
`(database job, store)` contributions exceeds the platform limit. Provider
results and the accumulated contribution ledger use the same finite
cardinality. Evidence, topic, and gap arrays retain their schema bounds.

Contribution and synthesis order is independent of provider completion order:
stores follow discovery order, jobs follow planned run order, topics follow the
database registry, evidence paths use canonical path order, and gaps use
canonical structural order.

### 4. Preserve historical semantics

Run schemas 1 through 3 remain readable and keep their existing direct
home-shard profile behavior. New plans use run schema 4 and the contribution
ledger. A schema 4 transition cannot use the legacy direct-profile path, and a
legacy run cannot acquire schema 4 contribution state.

Closure retries remain whole-shard coverage retries. They do not rewrite a
profile synthesized at the initial fan-out barrier. If a required base
contribution is failed or missing, the terminal result remains conservative and
the operator must start a new run after fixing the provider failure.

## Options rejected

### Let related shards append or replace the home profile

This creates multiple writers for one store identity and makes completion order
security-relevant. It also permits a narrow context shard to overwrite
principal, tenancy, adapter, or copy-path claims established elsewhere.

### Merge full profiles from every shard

Nested profile dimensions do not form one safe general-purpose merge lattice.
Conflicting principals, adapter routes, enforcement paths, or copy semantics
cannot be resolved by last-writer wins, union, or optimistic precedence.

### Let the home shard cite all discovered paths

That defeats bounded sharding and converts unexamined paths into apparent
evidence. Packet scope and examined-path binding must remain exact.

### Synthesize during each provider result transition

The resulting profile would depend on completion order and could be
optimistically materialized before the denominator is terminal. The fan-out
barrier gives the controller one deterministic aggregation point.

## Security invariants

1. Discovery owns store identity and the required shard denominator.
2. Every stored contribution is bound to one successful authenticated base
   database job.
3. Exactly one required shard has authority to supply structured profile
   dimensions.
4. Context shards never supply or rewrite a profile.
5. Contribution evidence is examined, shard-local, and inside the discovered
   store component.
6. Missing, failed, duplicate, partial, or gapped contributions cannot produce
   `ASSESSED`.
7. A final schema 4 store profile is exactly recomputable and provider
   completion order cannot change it.
8. Store profiles and contribution history are append-only.

## Verification

Tests cover:

- successful synthesis across a home shard and one or more context shards;
- contribution-order independence;
- missing, failed, partial, duplicate, extra-store, and out-of-scope evidence;
- context profile injection and authority omission;
- forged contribution provenance and forged synthesized profiles;
- the bounded contribution limit;
- schema 1-3 compatibility; and
- report and lifecycle behavior for synthesized store coverage.

## Rollback

Run schema 4 bundles remain readable by versions that implement this ADR.
Rolling back new planning requires emitting no new schema 4 runs; it does not
rewrite existing contribution ledgers or synthesized profiles.
