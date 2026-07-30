# Database and data-store adapter contract

Contract version: `1`

Verified: `2026-07-29`

This file is a contract, not a lens. It owns no topics and emits no findings.
The `database-and-data-stores` lens supplies the threat families; an adapter
supplies the semantics of one identified engine and deployment. The split is
load-bearing: "deny wins", "the owner is subject to policy", "a view is a
security boundary", and even "the database authenticates users" are not
portable claims.

An adapter answers four questions:

1. Which product, version, edition, compatibility mode, and deployment is this?
2. Which security guarantees can that exact deployment express?
3. Which principals, operations, enforcement paths, and copy paths were
   actually assessed?
4. What behavior proves or disproves the claimed guarantee?

The adapter never turns product recognition into a clearance. A client library
is evidence that a store may exist; it is not evidence of a server version,
edition, configuration, or effective policy.

## One profile per protection domain

A `store_profile` describes one independently configured protection domain.
Create separate profiles when any of these differ:

- engine or compatibility mode;
- production versus local embedded storage;
- account, cluster, server, database, or file boundary;
- runtime principal or tenant-isolation mechanism;
- primary versus separately authorized replica, warehouse, search index, or
  analytics copy.

Do not collapse "the app uses SQL" into one profile when it writes PostgreSQL,
reads an Elasticsearch projection, and exports through a warehouse. A managed
service that exposes several APIs also gets one profile per API whose
authorization semantics differ.

## Required `store_profile`

Every activated adapter receives the following validated record. A required
field may contain `unknown` only when the profile is `PARTIAL` or
`NOT_ASSESSED` and names the resulting gap. Never put a password, token, private
endpoint, or full credential-bearing connection string in the record.

```yaml
store_profile:
  store_context:
    store_id: orders-primary
    family: relational
    engine: postgresql
    engine_version: "16.3"
    deployment_variant: self-managed
    adapter_id: postgresql
    detection_evidence:
      - docker-compose.yml:19 postgres:16.3
    confidence: high
  engine_edition: community
  compatibility_mode: native
  engine_evidence_paths:
    - docker-compose.yml
  principal_evidence_paths:
    - deploy/roles.yml
    - config/database.yml
  tenancy:
    model: shared-table
    tenant_attribute: tenant_id
    claimed_guarantee: database-enforced
    evidence: tenant_id policy is declared in the bounded migration
    evidence_paths:
      - migrations/0042-tenant-policy.sql
  principal_path:
    authenticated_principal: application-user
    session_principal: app_runtime
    effective_principal: app_runtime
    owner_or_definer: db_owner
    bypass_capabilities: []
  evidence_paths:
    - migrations/0042-tenant-policy.sql
    - docker-compose.yml
    - ops/backup.yml
    - config/database.yml
    - deploy/roles.yml
    - src/store.ts
  enforcement_paths:
    inventory_closed: true
    paths:
      - name: primary-sql
        state: ASSESSED
        evidence: native policy is declared in the bounded migration
        evidence_paths:
          - migrations/0042-tenant-policy.sql
      - name: stored-routines
        state: NOT_PRESENT
        evidence: no stored routine exists in the closed migration set
        evidence_paths:
          - migrations/0042-tenant-policy.sql
  copy_artifact_closure:
    artifact_set_closed: true
    closure_basis: recon closed every configured store and copy declaration path
    evidence_paths:
      - config/database.yml
      - ops/backup.yml
      - src/store.ts
    categories:
      replica:
        state: NOT_PRESENT
        evidence: no replica is configured in the bounded store configuration
        evidence_paths: [config/database.yml]
      cdc:
        state: NOT_PRESENT
        evidence: no change stream is configured in the bounded store paths
        evidence_paths: [config/database.yml, src/store.ts]
      history:
        state: NOT_PRESENT
        evidence: no history store is declared in the bounded store paths
        evidence_paths: [config/database.yml, src/store.ts]
      backup:
        state: ASSESSED
        evidence: bounded backup workflow and destination controls are declared
        evidence_paths: [ops/backup.yml]
      export:
        state: NOT_PRESENT
        evidence: no export path is reachable from the bounded store code
        evidence_paths: [src/store.ts]
      cache:
        state: NOT_PRESENT
        evidence: no data cache is configured in the bounded store paths
        evidence_paths: [config/database.yml, src/store.ts]
  availability_budget:
    state: ASSESSED
    description: queries are limited to 500 ms and 20 concurrent requests per tenant
    evidence: bounded limits are declared in config/database.yml
    evidence_paths:
      - config/database.yml
  assumptions:
    - statement: runtime and migrator credentials are distinct
      status: VALIDATED
      evidence: distinct role bindings are declared in deploy/roles.yml
      evidence_paths:
        - deploy/roles.yml
  coverage_state: ASSESSED
  assessed_topics:
    - database-audit-identity-and-coverage
    - database-backup-restore-and-clone-security
    - database-integrity-transactions-and-concurrency
    - database-lifecycle-and-copy-propagation
    - database-migration-security-drift
    - database-native-authorization-and-tenant-isolation
    - database-principal-and-role-boundaries
    - database-privileged-code-and-execution-context
    - database-replication-cdc-history-and-sharing
    - database-resource-governance-and-availability
  coverage_gaps: []
```

### Field rules

- `store_context.store_id` is stable across reruns and does not contain a
  hostname. The whole `store_context` is projected unchanged into every Stage-1
  candidate for this store.
- `store_context.family` and `store_context.engine` use the adapter's canonical
  identifiers. A package version for a driver is not an engine version. An
  `ASSESSED` engine version contains a concrete numeric release marker;
  moving labels and prose such as `latest`, `default`, or `stable release` do
  not establish version semantics.
- `engine_edition`, `store_context.deployment_variant`, and
  `compatibility_mode` remain separate. A cloud product name does not prove
  parity with a boxed engine, and a compatibility level does not prove a server
  version.
- `evidence_paths` is the profile's bounded evidence set.
  `copy_artifact_closure.artifact_set_closed` may be `true` only when the set
  covers every repository location in which a relevant copy or control could
  be declared and the adapter can interpret each relevant format.
- `store_context.detection_evidence[]` begins with an exact top-level
  `evidence_paths` entry, optionally followed by a line/column locator and an
  observation. Free-form claims such as `trust me` are invalid.
- Every positive or absence-bearing nested dimension carries both an evidence
  summary and `evidence_paths`. Every nested path must be a member of the
  top-level evidence denominator that the controller checked against inventory,
  job scope, and examined files.
- `tenancy.claimed_guarantee` is one of `database-enforced`,
  `application-enforced`, `topology-enforced`, `single-tenant`, or `unknown`.
  This is a claim to test, not a conclusion.
- `principal_path` records the authenticated, session, effective, owner/definer,
  and bypass path. Symbolic names are sufficient; a collision between roles is
  important evidence. Unresolved tokens remain unresolved even when embedded
  in prose: `unknown effective principal`, `TBD role`, `pending`, `default`,
  and `unspecified` are invalid, and canonical `unknown` prevents `ASSESSED`.
- Every enforcement path and each of `replica`, `cdc`, `history`, `backup`,
  `export`, and `cache` has state `ASSESSED`, `NOT_PRESENT`, or
  `NOT_ASSESSED`. `NOT_PRESENT` requires evidence; `NOT_ASSESSED` requires a
  reason and prevents an overall `ASSESSED` disposition.
- `availability_budget` records whether the bounded workload model was
  assessed, its concrete description, and its evidence or blocking reason.
- Assumptions are `VALIDATED`, `INVALIDATED`, or `OPEN`; an open assumption
  prevents `ASSESSED` and must surface in `coverage_gaps`.
- `ASSESSED` is exact: all ten database-owned topics, closed enforcement and
  artifact inventories, no unknown/open/`NOT_ASSESSED` dimension, and no
  coverage gap. `PARTIAL` and `NOT_ASSESSED` require at least one named gap;
  `NOT_ASSESSED` carries no assessed topics.

## Required Stage-1 `store_context`

`store_profile` is the validated per-store assessment envelope above.
`store_context` is its small, immutable routing projection into every database
candidate finding. Its shape is owned by `_schema.md`; adapters must not replace
it with a private context shape:

```yaml
store_context:
  store_id: orders-primary
  family: relational
  engine: postgresql
  engine_version: "16.3"
  deployment_variant: self-managed
  adapter_id: postgresql
  detection_evidence:
    - docker-compose.yml:19 postgres:16.3
  confidence: high
```

`store_id`, `family`, `engine`, `engine_version`, `deployment_variant`,
`adapter_id`, `detection_evidence[]`, and `confidence` are required.
`engine_version` is an established version or the literal `unknown`;
`confidence` is `high`, `medium`, or `low`. Detection evidence is repository
location plus observed value, never a credential.

Capability mode, artifact closure, assessed/unassessed operations, local-target
provenance, assumptions, and ownership handoffs remain profile/proof/coverage
metadata. They do not get hidden inside `store_context`.
`copy_artifact_closure.artifact_set_closed` is true only when discovery
explicitly proves closure; the adapter never infers closure from a large file
count.

## Canonical adapter routing

The dispatcher uses the exact `adapter_id` values below. Several product
branches intentionally share a file while keeping distinct IDs; the file must
select the branch named by `engine` and `deployment_variant`.

| Canonical `adapter_id` | Adapter file |
|---|---|
| `postgresql` | `postgresql-and-supabase.md` |
| `sqlserver` | `sqlserver-and-azure-sql.md` |
| `mysql` | `mysql.md` |
| `mariadb` | `mariadb.md` |
| `oracle` | `oracle.md` |
| `sqlite` | `sqlite.md` |
| `mongodb` | `mongodb.md` |
| `redis` | `redis-and-valkey.md` |
| `valkey` | `redis-and-valkey.md` |
| `firestore` | `firestore.md` |
| `dynamodb` | `dynamodb.md` |
| `elasticsearch` | `elasticsearch-and-opensearch.md` |
| `opensearch` | `elasticsearch-and-opensearch.md` |
| `cassandra` | `cassandra-and-scylla.md` |
| `scylla` | `cassandra-and-scylla.md` |
| `neo4j` | `neo4j.md` |
| `pinecone` | `vector-stores.md` |
| `qdrant` | `vector-stores.md` |
| `weaviate` | `vector-stores.md` |
| `milvus` | `vector-stores.md` |
| `snowflake` | `warehouses.md` |
| `bigquery` | `warehouses.md` |
| `redshift` | `warehouses.md` |
| `databricks` | `warehouses.md` |
| `inventory-only` | no product adapter; load `contract.md` only |

An unlisted engine selects `inventory-only`. Do not manufacture an adapter ID
from a package name or silently route a compatible service to its upstream
engine.

## Capability enum

Each adapter declares every canonical capability below using exactly one value:

| Value | Meaning |
|---|---|
| `NATIVE` | The identified deployment has a dedicated engine primitive for the guarantee. |
| `COMPOSABLE` | The guarantee can be built from native primitives, but only if every named precondition is true. |
| `EXTERNAL_ONLY` | The engine cannot enforce the guarantee itself; a process, filesystem, proxy, application, or topology boundary must do it. |
| `UNSUPPORTED` | The identified deployment cannot express the guarantee in scope. |
| `UNKNOWN` | Version, edition, provider behavior, or configuration ambiguity prevents classification. |

These values describe product capability, not audit outcome. `UNSUPPORTED` is
not automatically a vulnerability. It becomes actionable only when the system
claims or requires the guarantee and no tested alternative supplies it.

Every adapter declares these canonical capabilities:

| Capability ID | Guarantee being classified |
|---|---|
| `principal-authentication` | Distinct callers can be authenticated at the store boundary. |
| `role-and-object-grants` | Operations can be granted by principal and resource. |
| `record-read-authorization` | Individual records can be filtered or denied on reads. |
| `record-write-authorization` | Inserts, updates, re-keying, upserts, and deletes can be constrained per record. |
| `column-or-property-authorization` | Sensitive fields can be denied independently of the enclosing object. |
| `tenant-session-context` | A trusted, request-scoped tenant/actor value can participate in policy. |
| `stored-code-execution-context` | Stored code has explicit invoker/definer or equivalent authority semantics. |
| `schema-integrity` | Constraints or validation can enforce stored-data shape and relationships. |
| `transactional-integrity` | Multi-operation invariants can be protected with documented concurrency semantics. |
| `resource-governance` | Work can be bounded by time, memory, concurrency, or workload class. |
| `replication-cdc-authorization` | Replication/change feeds can independently restrict principals and data. |
| `history-authorization` | Temporal/history data has an independently assessable authorization boundary. |
| `backup-policy-portability` | A supported backup/restore path preserves security policy and principals. |
| `security-audit` | Security-relevant data operations can be attributed and protected as audit evidence. |
| `policy-catalog-introspection` | Effective policy inputs can be enumerated from supported metadata. |

An adapter may add namespaced capabilities, but it may not rename or omit a
canonical one.

## Coverage states

Capability and coverage are separate axes:

| Coverage state | Meaning |
|---|---|
| `COVERED` | All declared artifacts and behavior required by the rule were assessed. |
| `PARTIAL` | Named subpaths or operations were assessed and the omissions are listed. |
| `INVENTORY_ONLY` | The store or feature was detected, but the adapter has no sound actionable evaluation for it. |
| `NOT_ASSESSED` | Required discriminators, artifacts, capability, or permitted proof are absent. |
| `NOT_APPLICABLE` | The rule's precondition is demonstrably false for this profile. |

`INVENTORY_ONLY` and `NOT_ASSESSED` are never rendered as pass, clean, secure,
or no findings. They appear in `Coverage` with the exact missing discriminator
or operation.

### Ambiguity is fail-closed

- A driver, ORM dialect, port number, filename extension, or environment
  variable name alone activates inventory only.
- If two engines remain plausible, create both candidate identities, record the
  conflict, and mark all engine-semantic rules `NOT_ASSESSED`.
- If the engine is known but the version or edition is not, evaluate only rules
  whose semantics do not cross that gate. Mark gated rules `NOT_ASSESSED`.
- If a managed service emulates another engine, use the managed adapter or an
  explicitly supported deployment variant. Do not silently apply the upstream
  adapter.
- If committed migrations disagree with a pinned container or generated schema,
  do not choose the more convenient signal. Record the conflict.
- Unknown live grants, policy state, feature licensing, or drift are open
  questions. Static absence is not a clearance.

## Stable rule IDs

Adapter rules use:

```text
db.<threat-family>.<adapter-id>.<semantic-name>
```

Examples:

```text
db.authorization.postgresql.rls-policy-completeness
db.execution.mysql.definer-context
db.integrity.sqlite.foreign-keys-per-connection
```

Rules:

1. IDs are lowercase ASCII, dot-separated, and contain no version, severity,
   path, line number, or sequence number.
2. The adapter ID is the canonical ID declared by the adapter, not a marketing
   alias.
3. A compatible refinement keeps the ID. A changed oracle, protected resource,
   or security meaning gets a new ID and a `supersedes` link.
4. The rule ID is not the candidate finding ID. `_schema.md` still derives
   `candidate_id` from topic, normalized primary location, and title.
5. Provider-specific behavior gets a provider-qualified semantic name under
   the engine adapter, or a distinct adapter if the authorization model is no
   longer engine-compatible.
6. A semantic rule ID is valid only when that exact ID is declared as a rule
   anchor in the selected adapter document. Every one of the 24 canonical
   product adapters declares at least one adapter-namespaced rule anchor;
   syntactically plausible but invented IDs are rejected.

Every rule result carries `rule_id`, `adapter_id`, `capability_value`,
`coverage_state`, `evidence`, `assumptions`, `unassessed_paths`, and, when it
becomes a finding, the complete candidate-finding contract.

## Enforcement-path inventory

For every protected collection, map at least:

- primary native query protocol;
- application ORM/repository path;
- direct runtime-principal access;
- views, stored procedures, functions, triggers, jobs, and extensions;
- administrative console or query tool;
- migration and schema-owner path;
- bulk load/import and export;
- analytics, reporting, materialized views, and search/vector projection;
- replica/read endpoint;
- CDC, change stream, binlog/WAL/redo, or event subscription;
- temporal/history/flashback path;
- backup, snapshot, clone, point-in-time restore, and lower-environment restore.

An authorization result on the ORM path says nothing about direct SQL, CDC,
backup, or history. Record each path independently.

## Copy-path inventory

At minimum, ask whether each of these exists and who can read it:

- physical and logical backups;
- snapshots, clones, forks, and restored test environments;
- transaction logs, WAL, binlogs, redo, archive logs, and journal files;
- replicas and delayed replicas;
- CDC/change streams and event sinks;
- exports, dumps, bulk unloads, and local analyst extracts;
- materialized views, indexes, caches, warehouses, and vector stores;
- temporary files, spill files, crash dumps, and deleted-page remnants.

The adapter owns native security semantics and whether policy survives the
copy. Cloud exposure, encryption configuration, key custody, lawful retention,
and semantic retrieval authorization remain with their owning lenses.

## Version, edition, and deployment gates

Every adapter includes:

- canonical `adapter_id`;
- `verified_on`;
- supported engine/version range, if established;
- edition or licensed-option gates;
- self-managed, managed, BaaS, and compatibility-mode differences;
- official sources supporting each mutable semantic claim.

Detection precedence is:

1. committed output produced by the server or engine;
2. an exact pinned server image/package;
3. provider resource configuration with an exact engine declaration;
4. migration-generator metadata;
5. SQL dialect;
6. driver or ORM package.

A lower-precedence signal never overrides a conflicting higher-precedence one.
`latest`, `current`, an unpinned image, and a provider's rolling service version
all yield an unknown exact version.

## Conformance matrix

Every adapter fixture supplies at least two tenants, `TENANT_A` and `TENANT_B`,
and distinct values from `_harness.md`'s canary set. It defines these actors:

- unauthenticated or no-credential actor, where meaningful;
- tenant-A runtime actor;
- tenant-B runtime actor;
- shared pooled runtime actor with tenant A then tenant B context;
- reporting/read-only actor;
- migrator/schema owner;
- replication/CDC actor;
- backup/restore actor;
- administrator/bypass control.

For each enforcement and copy path, populate this matrix. `expected` is
`ALLOW`, `DENY`, `EMPTY`, `MASKED`, or `NOT_APPLICABLE`; do not accept "query
succeeded" as the oracle.

| Operation | Own tenant | Foreign tenant | Side effect asserted | Audit asserted |
|---|---:|---:|---|---|
| read one by known identifier | ALLOW | DENY or EMPTY | none | actor, target, outcome |
| list/query | ALLOW | EMPTY | result contains no foreign canary | actor, scope, outcome |
| aggregate/count/statistics | ALLOW | DENY or tenant-only | no inference from foreign rows | actor, operation, outcome |
| insert | ALLOW | DENY | no foreign row created | actor, target, denial |
| update non-tenant field | ALLOW | DENY | foreign row unchanged | actor, target, denial |
| mutate tenant key | DENY unless explicit transfer workflow | DENY | ownership unchanged | actor, before/after |
| upsert/merge/batch | ALLOW | DENY | no partial foreign effects | actor, batch outcome |
| delete | ALLOW | DENY | foreign row remains | actor, target, denial |
| execute stored code | declared | declared | authority and writes match contract | invoker and effective actor |
| read metadata/history/CDC | declared | declared | no alternate-path disclosure | subscriber and scope |
| export/backup/restore | declared | declared | policy and principals preserved or deliberately rebuilt | operator and artifact |

Also run:

- an unset, null, malformed, stale, and attacker-supplied tenant context;
- pool return and reuse in the opposite tenant order;
- direct native access using the deployed runtime principal;
- a fresh migration, upgrade migration, rollback path, and restored copy;
- policy-owner/admin controls proving the harness can see protected rows;
- a fixture self-check proving that the foreign canary exists before asserting
  it is absent.

## Proof and reporting rules

- Static sweeps are candidate discovery. A matching keyword is not a finding.
- A static absence rule requires closed artifact scope, format-aware parsing,
  and both vulnerable and clean fixtures. Otherwise it is `NOT_ASSESSED`.
- T1 is allowed only when the repository's own test runner already starts the
  ephemeral store. Starting a database, container, emulator, or local service
  is T2 and requires the user's local-dynamic consent.
- All dynamic destinations are loopback. Never connect to a hostname found in a
  connection string or provider configuration.
- Use disposable data and bounded operations. Do not use `DROP`, `TRUNCATE`,
  mass mutation, or a production-shaped credential.
- Assert the authorization decision and persisted side effect, not an error
  string or log line.
- A restore proof must compare policy catalogs, principals, grants, stored code,
  and audit configuration as well as application rows.
- An edition-gated feature that cannot be started locally remains
  `NOT_ASSESSED`; a syntactically plausible fixture does not prove it.

## Core ownership boundary

Adapters collect native facts and hand off conclusions outside their domain:

- query construction and SQL/NoSQL injection -> `web-and-api`;
- cloud network exposure, managed backup retention, snapshot sharing, and
  encryption-at-rest switches -> `cloud-and-iac`;
- TLS implementation and key custody -> `crypto-and-key-management`;
- lawful retention, erasure periods, and cross-border legality ->
  `privacy-and-data-protection`;
- application workflow atomicity and business invariants -> `business-logic`;
- semantic retrieval authorization and embedding/vector meaning -> `llm-and-ai`;
- dependency CVEs and extension/package provenance ->
  `cicd-and-supply-chain`.

The database lens still records the aggravating native fact and the handoff. It
does not duplicate the finding.
