# Apache Cassandra and ScyllaDB adapter

Adapter ID: `cassandra`, `scylla`

Deployment variants: `cassandra-self-managed`, `cassandra-managed`,
`scylla-self-managed`, `scylla-enterprise`, `scylla-cloud`

Verified: `2026-07-28`

This adapter shares CQL-shaped tests while keeping Apache Cassandra, ScyllaDB
Open Source/Enterprise/Cloud, Astra, Amazon Keyspaces, and other compatible
services as distinct versioned deployment variants. It applies through
`database-and-data-stores` and owns no topics.

## Detect and profile

Activate on Cassandra/Scylla drivers, `cassandra.yaml`, `scylla.yaml`, CQL
migrations, keyspace/table definitions, `nodetool`, Scylla REST/Manager config,
or managed compatible resources. Record:

- engine/provider, exact version, edition, topology/datacenters/racks, snitch,
  replication strategy/factor, and managed compatibility limits;
- native CQL, JMX, internode, Scylla REST, maintenance socket, Prometheus,
  Manager/agent, Alternator, and administrative endpoints;
- runtime, analytics, migration, repair, backup, CDC, JMX/operations, and
  monitoring principals;
- keyspace/table/materialized-view/index/function resources, partition-key
  tenant unit, consistency levels, TTL/tombstone policy, snapshots/SSTables,
  CDC logs, and downstream copies.

Do not infer Cassandra defaults or features for a managed CQL service or
ScyllaDB. Unknown compatibility is `NOT ASSESSED`.

Emit the contract's required `store_context`: `store_id`, `family`, `engine`,
`engine_version`, `deployment_variant`, `adapter_id`, `detection_evidence[]`,
and `confidence`. Keep `data_classes`, `tenant_unit`, `enforcement_plane`,
`principal_paths[]`, and `copy_paths[]` in the full store profile.

## Capability declaration

| Capability ID | Cassandra | ScyllaDB | Conditions |
|---|---|---|---|
| `principal-authentication` | `NATIVE` | `NATIVE` | A real authenticator must replace AllowAll on every node. |
| `role-and-object-grants` | `NATIVE` | `NATIVE` | Roles and hierarchical keyspace/table/function grants with product-specific admin endpoints. |
| `record-read-authorization` | `UNSUPPORTED` | `UNSUPPORTED` | No general native partition/row read policy inside a shared table. |
| `record-write-authorization` | `UNSUPPORTED` | `UNSUPPORTED` | No general native partition/row write predicate. |
| `column-or-property-authorization` | `UNKNOWN` | `UNKNOWN` | Cassandra masking permissions and Scylla/managed parity are version/edition sensitive. |
| `tenant-session-context` | `EXTERNAL_ONLY` | `EXTERNAL_ONLY` | A trusted application must bind tenant partition keys. |
| `stored-code-execution-context` | `NATIVE` | `NATIVE` | Function execution privileges/UDF settings, with no portable definer model. |
| `schema-integrity` | `COMPOSABLE` | `COMPOSABLE` | Types/primary keys plus application/LWT invariants; no foreign-key/check model. |
| `transactional-integrity` | `COMPOSABLE` | `COMPOSABLE` | Batches/LWT provide bounded primitives, not relational multi-partition transactions. |
| `resource-governance` | `COMPOSABLE` | `COMPOSABLE` | Guardrails/timeouts/service levels plus partition/query/application bounds. |
| `replication-cdc-authorization` | `COMPOSABLE` | `COMPOSABLE` | Internode/CDC/raw-file paths require separate transport/filesystem principals. |
| `history-authorization` | `UNSUPPORTED` | `UNSUPPORTED` | No general queryable temporal-history authorization. |
| `backup-policy-portability` | `COMPOSABLE` | `COMPOSABLE` | SSTable/snapshot restore plus system-auth, configuration, functions and audit comparison. |
| `security-audit` | `NATIVE` | `UNKNOWN` | Cassandra 4+ audit logging; Scylla capability is edition/version/deployment gated. |
| `policy-catalog-introspection` | `NATIVE` | `NATIVE` | Roles/grants/schema/config are inspectable, with node/config drift checked separately. |

## Resource and tenant model

Cassandra authorization resources are hierarchical: all keyspaces -> keyspace
-> table; all functions -> keyspace -> function; all roles -> role; and,
where supported, JMX MBeans. Permissions granted above a resource flow
downward. ScyllaDB has similar CQL roles but must be evaluated against its own
version and endpoint set.

Native authorization is generally keyspace/table/function granularity, not
per-row partition-key authorization. Keyspace/table-per-tenant can use native
grants. Tenants sharing a table and partitioned by `tenant_id` normally rely on
application query construction. Materialized views and secondary/search
indexes can introduce different query keys and copies.

## Effective privilege semantics

On Apache Cassandra, `AllowAllAuthenticator`/`AllowAllAuthorizer` provide no
meaningful client authn/authz; the shipped default authorizer performs no
checks. Confirm `PasswordAuthenticator` or another intended authenticator and
`CassandraAuthorizer` (or a reviewed custom implementation) consistently on
every node. Authentication alone is insufficient if internode or JMX
interfaces remain unprotected.

Resolve direct and transitively granted roles, superuser status, resource
hierarchy inheritance, automatic creator permissions, permission/credential/
role cache staleness, and `AUTHORIZE`/role-management capabilities. Cassandra
authorization is allowlist-oriented after a real authorizer is enabled; do not
invent row-level deny semantics.

For ScyllaDB, resolve login/superuser roles, recursively granted roles,
keyspace/table permissions, service-level attachments, and maintenance/admin
paths using the deployed version. A transient authentication migration mode is
not an acceptable indefinite production state.

Route network/TLS and managed IAM perimeter candidates to `cloud-and-iac` or
crypto; this adapter proves reachable CQL/JMX/admin consequences.

## Native versus application-only authorization

Label each path:

- `native-table` or `native-keyspace`: database role grants constrain the
  whole resource;
- `application-only`: shared table requires a tenant partition predicate;
- `hybrid`: native table scope plus application partition ownership;
- `none` or `unknown`.

For shared tables, prove that every SELECT/INSERT/UPDATE/DELETE and batch binds
the authenticated tenant into the full partition key and cannot mutate it.
`ALLOW FILTERING`, token/range scans, raw CQL, materialized views, indexes,
analytics connectors, and maintenance tools must not bypass the boundary.

CQL string injection belongs to `web-and-api`. This adapter owns native
capability and partition-boundary consequences, not duplicate injection
findings.

## Alternate paths and privileged execution

Exercise:

- point/range/token SELECT, paging, prepared/unprepared CQL, secondary/custom
  indexes, materialized views, aggregation, and every supported query API;
- INSERT/UPDATE/DELETE, counters, TTL/timestamp writes, logged/unlogged batches,
  lightweight transactions, and schema changes;
- CDC raw logs/consumers, Spark/analytics, SSTable tools/loader, `COPY`,
  snapshots, incremental backup, repair, commitlog/archive restore, and
  replacement/bootstrap nodes;
- JMX/MBeans, `nodetool`, Scylla REST/maintenance socket/Manager, Alternator,
  custom authenticators/authorizers, triggers, UDFs/UDAs, and plugins.

Review `CREATE FUNCTION`/`EXECUTE`, scripted UDF enablement, trigger jars,
custom index code, MBean execution/modification, `AUTHORIZE`, schema,
truncate/drop, snapshot/restore, repair, and topology changes as privileged
execution/admin surfaces.

## Integrity, consistency, and availability

Record consistency level per security-relevant operation, replication factor,
read repair/repair cadence, hinted handoff, speculative retry, lightweight
transaction use, batch semantics, timestamps, and conflict resolution.
Logged batches provide atomicity for a batch, not general transaction isolation;
lightweight transactions have different cost/availability tradeoffs.

Attack:

- stale authorization/revocation caches and weak-consistency authorization
  decisions stored in application tables;
- timestamp manipulation, last-write-wins anomalies, lost updates, counter
  misuse, partial cross-partition workflows, and retry/idempotency errors;
- unbounded partitions/rows, `ALLOW FILTERING`, range/tombstone scans, giant
  batches, hot partitions, wide rows, high-cardinality materialized views,
  secondary-index fan-out, and paging/result amplification;
- tombstone/compaction storms, repair backlog, disk/commitlog pressure, CDC
  backpressure, overloaded consistency levels, and auth-table under-replication.

Prove security-critical invariants under the deployed consistency/failure
model; do not label tunable consistency as universally strong or eventual.

## CDC, replicas, SSTables, snapshots, and restore

CDC logs, commitlogs, hints, SSTables, snapshots, incremental backups, repair
streams, bootstrap/decommission/replacement transfers, analytics connectors,
and object-storage backups are bulk-copy surfaces. Raw files bypass CQL
authorization. Scope host/object access and backup/repair identities
independently.

Restore proof must re-establish authenticators/authorizers on every node,
system-auth replication and role state, permissions caches, JMX/admin
protection, audit configuration, schema/UDF/trigger state, topology, and
service levels before client traffic. Test a replacement node and rolling
upgrade; mixed node configuration can create a bypass.

## Audit and attribution

Apache Cassandra audit logging can capture successful/failed CQL and
authentication events, but its filters, per-node deployment, bounded queue/
disk behavior, and exclusions must be inspected. Prepared-statement executions
do not log bound values. Cassandra audit logging does not cover
`cassandra.yaml` edits or every `nodetool` operation.

Version-gate ScyllaDB auditing and its destination/category support. Full query
logging, ordinary server logs, metrics, and managed-provider control-plane logs
are not automatically equivalent to a durable security audit.

For allowed and denied cross-tenant attempts, prove authenticated CQL identity,
source, keyspace/table/function, action/category, result, node coverage, and
end-user correlation. Protect audit disks/sinks from truncation, tampering, and
backpressure loss.

## Deletion, TTL, and copies

Deletes and TTL expiry create tombstones. Physical data can remain in SSTables,
snapshots, backups, commitlogs, hints, CDC, repair streams, replicas, and
downstream sinks until compaction and retention processes complete. Verify
`gc_grace`, repair cadence, tombstone resurrection risk, TTL default/override,
materialized-view/index convergence, and snapshot cleanup.

Legal erasure/retention decisions belong to `privacy-and-data-protection`; this
adapter supplies the actual replica/tombstone/copy lifecycle.

## Unsupported or unproven guarantees

Do not claim:

- row/partition authorization inside a shared table from native grants;
- meaningful security from authentication with `AllowAllAuthorizer`;
- deny precedence that the engine does not implement;
- relational transaction/isolation semantics from batches;
- immediate revocation despite permission/role caches;
- immediate physical erase from a tombstone;
- audit coverage for config/JMX/`nodetool` merely because CQL audit is enabled;
- Cassandra/Scylla/managed-CQL behavioral equivalence.

## Rule anchors

- `db.authorization.cassandra.role-and-keyspace-boundary` evaluates the
  authenticated role's transitive grants, keyspace/table permissions, and
  network/topology path together; it cannot clear on an `AUTHORIZE` statement
  or role name alone.
- `db.authorization.scylla.role-and-keyspace-boundary` applies the same
  boundary to ScyllaDB while keeping Scylla-specific authentication,
  authorization-cache, and deployment behavior distinct.

## Static discovery sweeps

| Evidence | Review |
|---|---|
| `cassandra.yaml`/`scylla.yaml` | authenticator/authorizer on all nodes, caches, UDFs, audit, CDC, consistency and admin endpoints |
| CQL role/grant migrations | superusers, recursive roles, `ALL KEYSPACES`, `ALL FUNCTIONS`, `AUTHORIZE`, schema/truncate/drop and creator grants |
| schema CQL | partition tenant key, owner immutability, materialized views/indexes, TTL, compaction, replication |
| driver config | principal separation, default consistency, prepared statements, paging, retries/idempotency, raw CQL |
| queries/batches/LWT | full partition binding, token scans/`ALLOW FILTERING`, timestamp/TTL control, cross-partition invariants |
| JMX/nodetool/REST/Manager | alternate administration and data-copy capabilities |
| CDC/backup/repair tooling | raw-copy authorization, sinks, restore security state, snapshot cleanup |
| audit config | every node, include/exclude filters, bounded queue/disk behavior and CQL-only limitations |

## Proof and conformance matrix

Use tenants A/B in a shared table plus separate keyspaces/tables, an A runtime
role, migration/repair/backup/JMX roles, and superuser control:

| Path | Required negative proof |
|---|---|
| point/range/token/index/MV query | A cannot retrieve or infer B |
| insert/update/delete/timestamp/TTL | A cannot create for B, mutate tenant key, overwrite/delete B, or control B expiry |
| batch/LWT/retry | cross-tenant elements fail and declared atomic/idempotent behavior holds |
| UDF/trigger/custom index | runtime role cannot gain privileged execution |
| JMX/nodetool/REST/SSTable | data-plane role cannot use alternate admin/raw paths |
| CDC/backup/repair/snapshot | bulk copies and consumers are separately authorized |
| cache/revocation/rolling node | removed grants converge within the declared bound; no mixed-node bypass |
| failure/repair/restore | tenant denial and integrity survive failover/rebuild/restore |
| audit | allowed/denied CQL is attributable and known non-CQL gaps are explicit |
| availability | partition/tombstone/batch/CDC attack is bounded |

## Known false positives

- `AllowAllAuthorizer` in a disconnected development fixture is not production
  exposure when release/deployment evidence excludes it; preserve the evidence.
- A keyspace-wide grant can be least privilege for a single-purpose service;
  inspect future tables and creator/migration paths.
- Weak consistency is not automatically a defect; connect it to a security or
  integrity decision that requires fresher semantics.
- Shared-table application isolation can be acceptable when an unbypassable
  service boundary and exhaustive alternate-path tests pass.
- Lack of bound values in Cassandra prepared-statement audit logs is a
  documented limitation, not proof that no query was audited.

## Fixture concept

Build separate version-pinned Cassandra and Scylla clusters with auth, two
nodes, tenants A/B, a shared partitioned table, separate keyspaces, a
materialized view/index, UDF, TTL/tombstones, CDC, snapshots, and audit. The
vulnerable variant retains AllowAll authorization or broad inherited grants,
allows raw shared-table CQL, exposes JMX/admin, and under-bounds partitions.
The clean variant enables product-correct authz on every node, scopes native
resources, proves application partition enforcement where required, separates
admin/copy roles, and documents audit/deletion bounds. Re-run after revocation,
rolling restart, replacement-node/bootstrap, repair, and restore.

## Official sources

Verified 2026-07-28:

- https://cassandra.apache.org/doc/latest/cassandra/managing/operating/security.html
- https://cassandra.apache.org/doc/latest/cassandra/developing/cql/security.html
- https://cassandra.apache.org/doc/latest/cassandra/managing/operating/auditlogging.html
- https://cassandra.apache.org/doc/latest/cassandra/managing/configuration/cass_yaml_file.html
- https://docs.scylladb.com/manual/stable/operating-scylla/security/
- https://docs.scylladb.com/manual/stable/operating-scylla/security/security-checklist.html
- https://docs.scylladb.com/manual/stable/operating-scylla/security/authentication.html
- https://docs.scylladb.com/manual/stable/operating-scylla/security/rbac-usecase.html
