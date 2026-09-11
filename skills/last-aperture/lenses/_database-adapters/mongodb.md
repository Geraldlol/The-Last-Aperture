# MongoDB adapter

Adapter ID: `mongodb`

Deployment variants: `mongodb-self-managed`, `mongodb-atlas`, `mongodb-managed`

Verified: `2026-07-28`

This adapter applies MongoDB-specific semantics to the `database-and-data-stores`
lens. It is not a standalone lens and owns no topics. Do not treat MongoDB as
generic JSON storage: deployment mode, server version, edition, topology, and
the identity used by each path materially change the result.

## Detect and profile

Activate on a confirmed MongoDB signal such as `mongodb://` or
`mongodb+srv://`, an official MongoDB driver, `mongod.conf`, Atlas
configuration, `db.createUser`, `db.createRole`, or MongoDB migration scripts.
Do not activate solely on BSON/object-id libraries.

Record:

- server version and compatibility version; Community, Enterprise, Atlas, or
  another managed service;
- standalone, replica set, or sharded cluster, including every `mongos`,
  config server, and shard;
- databases and collections, validators, views, indexes, time-series
  collections, GridFS buckets, and Atlas Search/Vector Search indexes;
- application, migration, operations, backup, analytics, connector, search,
  and change-stream identities and their credential sources;
- whether clients connect through one service identity or propagate a
  separately attributable principal.

If the exact version, edition, or managed-service feature set cannot be
established, mark feature-dependent checks `NOT ASSESSED`; do not borrow current
Atlas or Enterprise guarantees.

Emit the contract's required `store_context`: `store_id`, `family`, `engine`,
`engine_version`, `deployment_variant`, `adapter_id`, `detection_evidence[]`,
and `confidence`. Keep `data_classes`, `tenant_unit`, `enforcement_plane`,
`principal_paths[]`, and `copy_paths[]` in the full store profile.

## Capability declaration

| Capability ID | Value | Conditions |
|---|---|---|
| `principal-authentication` | `NATIVE` | Access control and the selected authentication mechanism must be enabled on the complete topology. |
| `role-and-object-grants` | `NATIVE` | Roles grant actions on cluster, database, and collection resources. |
| `record-read-authorization` | `UNSUPPORTED` | No general native document predicate; isolate by database/collection or prove an external boundary. |
| `record-write-authorization` | `UNSUPPORTED` | No general native per-document write predicate. |
| `column-or-property-authorization` | `COMPOSABLE` | Read-only projection/redaction views plus denial of backing-collection access; not general field-level DML policy. |
| `tenant-session-context` | `EXTERNAL_ONLY` | A trusted application/router must bind tenant identity for shared collections. |
| `stored-code-execution-context` | `NATIVE` | Server expressions execute under the invoking operation's authority; managed triggers/functions are separate principals. |
| `schema-integrity` | `NATIVE` | Validators and indexes, subject to validation action/level and bypass privilege. |
| `transactional-integrity` | `NATIVE` | Multi-document transactions require a supported replica-set/sharded deployment and matching concerns. |
| `resource-governance` | `COMPOSABLE` | Engine limits, topology, quotas and application bounds must be combined. |
| `replication-cdc-authorization` | `COMPOSABLE` | Change-stream scope/actions plus separately secured replicas, oplog and pre-images. |
| `history-authorization` | `COMPOSABLE` | Change-stream pre-images/oplog windows are independently privileged but are not a general temporal-policy system. |
| `backup-policy-portability` | `COMPOSABLE` | Data, users/roles, validators, audit and topology require explicit tool-specific restore coverage. |
| `security-audit` | `UNKNOWN` | Enterprise/Atlas tier and successful-authorization logging must be established. |
| `policy-catalog-introspection` | `NATIVE` | Users, roles, privileges, collection options, indexes and parameters are inspectable with sufficient privilege. |

## Resource and tenant model

The native authorization hierarchy is deployment -> database -> collection and
cluster resources/actions. Roles may inherit other roles. MongoDB has no
general native document predicate equivalent to SQL row-level security.
Database-per-tenant and collection-per-tenant designs can use native resource
grants. A shared collection with `tenantId` is application-enforced unless a
separate, demonstrably unbypassable enforcement layer exists.

Inventory the tenant unit independently for the primary collection, `$lookup`
targets, GridFS files/chunks, search indexes, change streams, exports, and
backups. A tenant field in a schema or index is not an authorization control.

## Effective privilege semantics

Compute effective privileges from direct roles plus recursively inherited
roles and all scoped resources/actions. Roles add privileges; a narrower role
does not subtract privileges granted by another role. Inspect
`rolesInfo` with inherited privileges in a proof environment when possible.

Treat `root`, `__system`, `readWriteAnyDatabase`, `dbAdminAnyDatabase`,
`userAdminAnyDatabase`, `clusterAdmin`, `restore`, `backup`, `directShardOperations`,
role-management actions, and wildcard resources as privileged. Include Atlas
database users, workload identity mappings, custom roles, and project access;
Atlas control-plane roles do not by themselves prove data-plane least
privilege.

Self-managed MongoDB does not enable access control by default. Verify
`security.authorization: enabled` (or the equivalent authenticated cluster
configuration) on every node and router. Route network reachability to
`cloud-and-iac`; this adapter decides what a reachable authenticated or
unauthenticated client can do.

## Native versus application-only authorization

For every read and mutation, label enforcement:

- `native`: a least-privileged MongoDB role prevents access to the database or
  collection;
- `application-only`: code supplies a tenant predicate or chooses a tenant
  namespace while the database identity can access other tenants;
- `hybrid`: native collection/database grants plus application document
  predicates;
- `none` or `unknown`.

For application-only isolation, prove tenant binding for `find`, `findOne`,
`aggregate`, count/distinct, bulk operations, upserts, `findOneAnd*`, replace,
delete, transactions, and every repository escape hatch. Do not promote static
presence of `{tenantId: ...}` to a pass.

Generic operator/query injection, unsafe object merging into a query, and
untrusted `$where` construction belong to `web-and-api`. This adapter may cite
them as a bypass path but must not file a duplicate.

## Alternate read and write paths

Exercise direct driver access and:

- aggregation stages, especially `$lookup`, `$graphLookup`, `$unionWith`,
  `$facet`, `$out`, and `$merge`;
- views and direct access to their backing collections;
- count, distinct, map-reduce where supported, GridFS, Atlas Data API,
  Atlas Search/Vector Search, BI/SQL connectors, and online archives;
- change streams at collection, database, and deployment scope, including
  pre/post images and resume tokens;
- bulk write, transaction, retryable-write, import/export, restore, and
  direct-shard paths;
- secondaries, hidden/delayed members, analytics nodes, snapshots, and copied
  lower environments.

A policy proved through an ODM is not proved until raw driver access available
to the same credential fails closed.

## Executable and administrative surfaces

Review server-side JavaScript (`$where`, `$function`, `$accumulator`,
map-reduce), validators containing expressions, triggers/functions in managed
adjacent services, custom authentication/authorization modules, and automation
agents. Record whether `security.javascriptEnabled` is needed. Inspect
privileges for role/user administration, `setParameter`, `setFeatureCompatibilityVersion`,
profiling, log rotation, replication, sharding, schema changes, index creation,
and audit-filter changes.

Stored JavaScript risk belongs here when MongoDB executes trusted stored or
configured code with elevated reach. Injection caused by untrusted application
input remains with `web-and-api`.

## Integrity, consistency, and availability

Inspect collection validators, `validationLevel`, `validationAction`, unique
and partial indexes, write concern, read concern, read preference, retry
semantics, transaction boundaries, and idempotency. Schema validation rejects
newly invalid writes by default but may be partial, warn-only, bypassed by
privileged callers, or leave historical invalid documents.

Attack:

- stale secondary reads and authorization decisions based on stale data;
- lost or duplicated effects across retryable operations and application
  retries;
- missing transaction boundaries around cross-collection invariants;
- unbounded aggregation, regex, `$lookup`, `$graphLookup`, sort, cursor,
  change-stream, and result-size work;
- connection-pool, transaction, disk, index-build, change-stream pre-image,
  and profiler exhaustion;
- shard-key hotspots, jumbo chunks, and unbounded tenant cardinality.

Do not claim serializable behavior or cross-document integrity without a proof
that matches the deployed topology and read/write concerns.

## Replication, CDC, snapshots, and restore

Change streams are an independent data-read surface. Grant only the required
scope and test event payloads, pre/post images, resume behavior, and tenant
filtering. Inventory the oplog, `config.system.preimages`, search/analytics
sync, connectors, Atlas triggers, snapshots, continuous backup, exports, and
restore automation.

Prove that a restored deployment re-enables authorization, recreates users and
custom roles intentionally, preserves validators/indexes, restores audit
configuration where promised, and is not exposed before hardening completes.
Test every `mongod` and `mongos`; a partially configured sharded deployment is
not a pass.

## Audit and attribution

MongoDB Enterprise and qualifying Atlas tiers provide database auditing; do not
assume the feature exists in Community or every Atlas tier. Audit all routers
and data/config nodes required by the topology. Successful CRUD authorization
checks require `auditAuthorizationSuccess: true`; the default can otherwise
record only failures. Review filters for excluded users, namespaces, actions,
truncation, and internal operations.

For a successful and denied cross-tenant attempt, prove capture of authenticated
database principal, source, action, namespace, result, and a correlation value
to the end-user actor. A pooled application credential without trustworthy
actor propagation is an attribution gap even when `mongod` logging works.
Route log-sink retention and cloud control-plane coverage to the owning
observability/cloud topic.

## Deletion, TTL, and copies

TTL deletion is asynchronous and driven by a background task; expired
documents can remain readable after expiration. Verify the indexed field type,
partial-filter behavior, time-series behavior, primary/replica propagation,
and backlog under load. Explicitly cascade application-owned nested references,
GridFS chunks, search/vector copies, change-stream pre-images, exports, and
downstream connectors. Backups and snapshots remain separate copies.

The legal sufficiency of retention/deletion belongs to
`privacy-and-data-protection`; this adapter supplies the technical propagation
and residual-copy evidence.

## Unsupported or unproven guarantees

Do not claim any of the following without versioned proof:

- native per-document tenant authorization in a shared collection;
- deny precedence across roles;
- complete successful CRUD audit coverage by default;
- immediate TTL deletion;
- replica or search-index freshness;
- restore of security state merely because data restored;
- Atlas/Enterprise features in Community or a lower Atlas tier.

Absence of native document authorization is not itself a finding. Require an
explicit isolation architecture and attack it.

## Rule anchors

- `db.authorization.mongodb.additive-role-boundary` computes the authenticated
  user's effective built-in and custom role union across database, collection,
  view, aggregation, change-stream, and administrative paths. A narrow custom
  role cannot clear broader inherited privileges.

## Static discovery sweeps

| Evidence | Review |
|---|---|
| `mongod.conf`, Helm, Compose, operators | `security.authorization`, authentication, JavaScript, audit, bind/listener, TLS handoff, replication and sharding consistency |
| `db.createUser`, `db.updateUser`, `db.createRole`, `grantRolesToUser` | wildcard and `AnyDatabase` roles, role inheritance, admin/backup/restore separation |
| `createCollection`, `collMod`, migrations | validators, validation action/level, indexes, tenant field and immutable ownership fields |
| driver/ODM initialization | credential identity, direct/native escape hatches, read/write concern, read preference, pool separation |
| `.watch`, `$changeStream`, connectors | stream scope, filters, pre/post images, sink authorization and retention |
| `$where`, `$function`, `$accumulator`, map-reduce | privileged executable code; route untrusted query construction to `web-and-api` |
| TTL indexes and delete jobs | coverage, async window, cascades, derived copies and restore behavior |

Static sweeps produce candidates, never a configuration pass.

## Proof and conformance matrix

Use tenants A and B, an A-scoped runtime principal, a migrator, and an
operations control. At minimum execute:

| Path | Required negative proof |
|---|---|
| get/find/list/count/distinct/aggregate | A cannot observe B through direct or inferred results |
| insert/upsert/replace/update | A cannot create for B, change ownership to B, or mutate B |
| delete/bulk/transaction | A cannot delete B or smuggle a cross-tenant operation into a batch |
| `$lookup`/`$unionWith`/view/search/GridFS | alternate namespace cannot disclose B |
| change stream/pre-image | A cannot subscribe to or recover B events |
| role/user/schema/index/admin command | runtime principal is denied |
| secondary/failover/restore | the same tests remain denied after topology change |
| audit | allowed and denied attempts are attributable without leaking secrets |
| TTL/delete | primary and all enumerated copies converge within the declared bound |

## Known false positives

- A development-only unauthenticated container is not a production finding
  when deployment evidence proves it is unreachable and excluded from release;
  keep the reachability evidence.
- A broad migrator role is not a runtime-privilege finding when credentials,
  workload identity, and invocation paths are demonstrably separated.
- Missing document-native enforcement is not a defect for database- or
  collection-per-tenant designs whose native grants and alternate paths pass.
- A tenant predicate inside a shared repository is neither a pass nor a
  finding until bypass reachability is established.
- Do not report an Enterprise audit feature as disabled on Community; report
  the unsupported guarantee and assess the compensating design.

## Fixture concept

Create a replica-set fixture with `tenant_a` and `tenant_b` documents,
application and migration users, a backing collection/view, GridFS content,
change stream, validator, TTL index, and one aggregation join. The vulnerable
variant disables authorization or grants `readWriteAnyDatabase`, trusts an
optional tenant filter, allows ownership mutation, and omits successful audit
events. The clean variant enables auth, uses scoped roles or an explicitly
tested application boundary, makes ownership immutable, scopes every alternate
path, and produces attributable audit evidence. Re-run after a replica
failover and restore.

## Official sources

Verified 2026-07-28:

- https://www.mongodb.com/docs/manual/core/authorization/
- https://www.mongodb.com/docs/manual/core/schema-validation/
- https://www.mongodb.com/docs/manual/changestreams/
- https://www.mongodb.com/docs/manual/core/index-ttl/
- https://www.mongodb.com/docs/manual/tutorial/configure-auditing/
- https://www.mongodb.com/docs/manual/reference/audit-message/mongo/
