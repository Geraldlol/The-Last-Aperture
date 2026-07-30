# ADR: Engine-neutral database and data-store security lens

Date: 2026-07-28
Status: Core adapter/profile architecture implemented in 0.3.0;
controller-owned Phase 0 discovery implemented in 0.4.0

## Context

The audit suite inventories data stores in recon, checks application query
injection in `web-and-api`, and checks managed-service perimeter and backup
configuration in `cloud-and-iac`. It has no owner for database-native principals,
effective grants, tenant policies, privileged stored code, security migration
drift, replication/CDC visibility, restore-time security state or native audit
attribution.

A PostgreSQL/Supabase-only or RLS-only lens would create false confidence.
Equivalent-looking features have materially different read/write, bypass, role
composition, execution-context, replication, transaction, restore and audit
semantics. Some engines have no native per-record policy and require a deliberate
alternative isolation boundary.

## Decision

Add one owning `database-and-data-stores` fan-out lens with ten engine-neutral
topics. Keep its core thin: inventory, ownership, shared invariants, severity,
proof and coverage. Put mutable product semantics in versioned, primary-source
adapter references under `lenses/_database-adapters/`.

Phase 0 creates one controller-discovered stable candidate per physical or
logical store. Version 0.4 builds a bounded, deterministic, secret-free graph
before activation, follows clients through bindings, connections, queries,
migrations, roles, policies, privileged code, and copy artifacts, and assigns
each candidate and related path to a bounded database shard. Phase 1 profiles
each controller-issued `store_id`, loading the adapter contract and only the
selected adapter. The controller enforces immutable per-store profiles and
routes 24 shipped engine/service adapters through closed rule vocabularies. An
engine, version, edition or deployment that cannot be selected from repository
evidence uses `inventory-only` and is reported `NOT ASSESSED`; ambiguity can
never clear a candidate.

For every controller-discovered store candidate, the validated provider profile
records engine edition and compatibility, tenancy, effective-principal and
enforcement paths, copy/artifact closure, availability budget, assumptions,
and coverage gaps.
Engine, principal, tenancy, enforcement, copy, availability, and assumption
claims each carry explicit path references into the controller-checked
top-level evidence denominator. Detection evidence must begin with one of those
declared paths, optionally followed by a line/column locator and observation;
free-form attestations do not establish a store identity.
`ASSESSED` means the profile covers all ten database-owned topics, closes the
enforcement and artifact inventories, and records `ASSESSED` or
evidence-backed `NOT_PRESENT` for replica, CDC, history, backup, export, and
cache categories. Unknown, open, or `NOT_ASSESSED` dimensions force `PARTIAL`
or `NOT_ASSESSED` with a named gap. This closes the per-profile semantic
denominator; it does not let provider output redefine controller-owned store
identity or discovery scope.

Database candidate records add `store_context`, `principal_path`,
`enforcement_plane`, optional `copy_path`, and, for semantic claims,
`adapter_rule_id` plus a dated primary `semantic_source`.
Each of the 24 canonical product adapters declares an adapter-namespaced rule
anchor. The controller accepts only exact rule IDs parsed from the selected
adapter document, so a provider cannot mint a plausible-looking semantic rule
ID that has no reviewed oracle.

Every adapter rule is evaluated in both directions with inert vulnerable/clean
fixtures. Runtime confirmation additionally requires a direct native-client
two-subject test and the existing proof oracle. Catalog convergence, connection
pool reuse, CDC/history, restore and audit are independent proof dimensions.
Provider-result transitions consume at most one completed provider job, bind
finding/profile deltas to that job's kind and declared candidates, keep gap
history append-only, and require newly claimed profile evidence to have been
examined by the completing database job.

## Ownership boundaries

- `web-and-api`: caller-controlled query construction and endpoint authorization.
- `cloud-and-iac`: perimeter, managed control-plane IAM and managed feature flags.
- `crypto-and-key-management`: credentials, TLS, keys and cryptographic design.
- `privacy-and-data-protection`: lawful retention/deletion and final data grading.
- `llm-and-ai`: semantic retrieval authorization and embedding inheritance.
- `cicd-and-supply-chain`: driver/package provenance and deployment authority.
- `database-and-data-stores`: native data-plane semantics and copy behavior.

## Consequences

Positive:

- One finding owner for the database attack surface without duplicating existing
  lenses.
- No generic SQL or RLS verdict can be applied to an unknown engine.
- Managed variants and version-sensitive behavior remain explicit.
- Controller-discovered stores receive independent coverage and cannot
  cross-clear; unresolved graph components and unprofiled candidates remain
  explicit gaps.
- CDC, history, replicas, backups and restores become first-class attack paths.

Costs:

- Adapter maintenance follows vendor releases and deployment variants.
- Live semantic confirmation often needs a disposable engine and therefore T2
  approval.
- Full adapter breadth is incremental; unsupported engines remain visibly
  `NOT ASSESSED`.
- Catalog normalization and restore proofs are more work than grep-based checks.

## Alternatives considered

- Extend `web-and-api`: rejected because database-native principals, replication,
  restore and audit are not request-handler concerns.
- Extend `cloud-and-iac`: rejected because a managed resource flag does not model
  native data-plane policy or transaction behavior.
- Build a PostgreSQL/Supabase RLS lens: rejected because it encodes one product's
  mechanism as a universal requirement and misses most of the attack surface.
- Build one generic SQL/NoSQL checklist: rejected because role composition,
  deny precedence, definer behavior and copy semantics are not portable.

## Validation

1. Registry/lens lint and generated ownership artifacts pass.
2. Activation coverage assigns every activator exactly once and drift-checks it.
3. Every automated adapter rule shipped by the initial release has an inert
   vulnerable/clean fixture pair.
4. Each fixture evaluator asserts vulnerable=true and clean=false with the same
   detector; prose-only adapter guidance is never counted as automated coverage.
5. Schema contract tests assert the database fields, ambiguity cap and
   inventory-only prohibition in both directions. Store-profile tests also
   prove that one topic, duplicate topics, missing copy categories, open
   assumptions, unassessed dimensions, unresolved prose, unbound evidence, and
   non-version labels cannot produce `ASSESSED`.
6. Adapter corpus tests require at least one source-grounded, adapter-namespaced
   rule anchor for every canonical adapter and reject invented IDs.
7. Transition tests reject compound provider results, gap-history rewriting,
   and finding/profile deltas that are not bound to the completing job.
8. Full `npm test`, `npm run lint`, and `npm run gen -- --check` pass.

## Rollback

The feature is additive. Roll back by removing the owning lens, adapter subtree,
database fixtures/tests and schema extension, then regenerate `_topics.md` and
`ownership-overlap.md`. No runtime migration or external system is changed.
