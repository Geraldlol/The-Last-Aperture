# Neo4j adapter

Adapter ID: `neo4j`

Deployment variants: `neo4j-community`, `neo4j-enterprise`, `neo4j-aura`

Verified: `2026-07-28`

This adapter covers Neo4j Community/Enterprise and Aura deployment variants.
It does not generalize Neo4j semantics to every Cypher-compatible graph store.
It applies through `database-and-data-stores` and owns no topics.

## Detect and profile

Activate on `neo4j://`, `neo4j+s://`, Bolt drivers, Neo4j images/config, Cypher
migrations, `SHOW ... PRIVILEGES`, Aura resources, APOC/GDS dependencies, or
Neo4j admin tooling. Record:

- exact version/Cypher version, Community or Enterprise, Aura tier, standalone
  or cluster, databases/aliases/composite/fabric/sharded features, and enabled
  plugins;
- Bolt, HTTP, Browser, Query API, admin/import, backup, CDC, monitoring, and
  extension endpoints;
- runtime, read-only analytics, migration, procedure, ETL/import, backup,
  CDC/connector, monitoring, and security-admin principals;
- graph/database/label/relationship/property tenant unit, enforcement plane,
  transaction metadata, replicas/backups/exports, and derived graph/vector
  copies.

Version- and edition-gate subgraph/property authorization, ABAC, procedure
privileges, CDC, query/audit logging, clustering, online backup, and Aura
controls. Unknown feature support is `NOT ASSESSED`.

Emit the contract's required `store_context`: `store_id`, `family`, `engine`,
`engine_version`, `deployment_variant`, `adapter_id`, `detection_evidence[]`,
and `confidence`. Keep `data_classes`, `tenant_unit`, `enforcement_plane`,
`principal_paths[]`, and `copy_paths[]` in the full store profile.

## Capability declaration

Edition-gated `NATIVE` values become `UNKNOWN` until Enterprise/Aura tier and
version are established; unsupported Community profiles must say so.

| Capability ID | Value | Conditions |
|---|---|---|
| `principal-authentication` | `NATIVE` | Native/external providers with auth enabled. |
| `role-and-object-grants` | `NATIVE` | Database/DBMS/graph/procedure privileges; granularity is edition-sensitive. |
| `record-read-authorization` | `NATIVE` | Enterprise/Aura subgraph and property-based read/traverse privileges. |
| `record-write-authorization` | `COMPOSABLE` | Enterprise label/type/property write privileges can compose a boundary, but property-based read rules are not a universal write predicate. |
| `column-or-property-authorization` | `NATIVE` | Enterprise property read rules; topology/inference remains separate. |
| `tenant-session-context` | `COMPOSABLE` | Role/ABAC claims and property policy, version-gated and dependent on trusted attributes. |
| `stored-code-execution-context` | `NATIVE` | Procedure/function execute and boosted-execute semantics are explicit. |
| `schema-integrity` | `NATIVE` | Version/edition-supported uniqueness, key, existence and type constraints. |
| `transactional-integrity` | `NATIVE` | Graph/schema operations use ACID transactions; cluster causality requires bookmarks. |
| `resource-governance` | `NATIVE` | Transaction time/concurrency/memory/query/job controls, which must be configured. |
| `replication-cdc-authorization` | `COMPOSABLE` | Cluster/CDC/connectors plus independently protected raw/copy paths. |
| `history-authorization` | `UNSUPPORTED` | Core has no general end-user temporal-history policy plane. |
| `backup-policy-portability` | `COMPOSABLE` | Backup/restore must compare system auth, privileges, aliases, procedures, config and logs. |
| `security-audit` | `COMPOSABLE` | Security log plus query/transaction metadata; successful data-operation coverage is configuration-sensitive. |
| `policy-catalog-introspection` | `NATIVE` | `SHOW ... PRIVILEGES AS COMMANDS`, users/roles, databases, aliases and config. |

## Resource and tenant model

Model DBMS -> database/alias/composite graph -> labels/relationship types ->
nodes/relationships -> properties, plus procedures/functions/settings. Tenant
isolation may be database-per-tenant, label/type subgraph, property-based
subgraph, or application query predicates.

Community authorization capabilities are not Enterprise subgraph access
control. A tenant property or label is not a native boundary until applicable
`GRANT`/`DENY` privileges are effective for the real principal and all graph
elements/paths. Inventory unlabeled nodes, untyped/general relationships,
missing properties, system database, aliases, and composite/federated graphs.

## Effective privilege semantics

Resolve users, external identity mappings, all assigned roles, built-in roles,
home/default database, graph/database/DBMS privileges, grants, denies, revokes,
role-management privileges, and procedure/function execution. Use `SHOW USER
... PRIVILEGES`/`SHOW ROLE ... PRIVILEGES AS COMMANDS` against the deployed
version where authorized.

Neo4j supports explicit `GRANT` and `DENY`, but property-based rules have
special semantics: a `DENY` condition that cannot be evaluated can fail open
when a broader grant exists. Missing properties are therefore an attack case,
not only dirty data. A user who can modify the property used by a policy can
alter authorization; make policy inputs immutable to that user.

Treat `admin`, DBMS/database management, user/role/privilege management,
`ALL DBMS PRIVILEGES`, alias/composite management, backup/import, settings,
transaction termination, `EXECUTE BOOSTED`, unrestricted procedures/functions,
and unrestricted graph `MATCH`/`WRITE` as privileged.

## Native versus application-only authorization

Label every path:

- `native-database`: database/alias grants isolate the tenant;
- `native-subgraph`: edition/version-supported label/type/property privileges
  constrain graph elements;
- `application-only`: Cypher adds tenant labels/properties/predicates while the
  database identity can traverse other tenants;
- `hybrid`, `none`, or `unknown`.

Separate `TRAVERSE` from `READ`/`MATCH` and write privileges. Hiding a property
does not necessarily hide topology, counts, paths, or existence. Test create,
delete, label/type/property mutation, and relationship endpoints separately
from reads.

Cypher injection from untrusted string construction belongs to `web-and-api`.
This adapter owns privilege composition, boosted procedure execution, and the
resulting graph boundary consequence.

## Alternate paths and privileged execution

Exercise:

- node/relationship/property reads, pattern existence, counts, aggregations,
  variable-length paths, shortest paths, subqueries, unions, optional matches,
  indexes/full-text/vector indexes, and graph algorithms;
- create/merge/set/remove/delete/detach delete, label/property/relationship
  mutation, constraints/schema, `LOAD CSV`, import, and batched transactions;
- Bolt, HTTP/Query API, Browser, Bloom, ETL/connectors, APOC, GDS, custom
  procedures/functions, CDC, Kafka, backup/restore, dump/load, and aliases/
  composite/federated graph routes.

Review allowlisted/unrestricted procedures, APOC file/network/import/export and
dynamic Cypher, Java extensions, plugins, `LOAD CSV`, external URLs, and
`EXECUTE BOOSTED`. Boosted execution may use privileges beyond the caller; it
must be allowlisted by exact procedure/function and attacked as an authority
boundary. Route network SSRF from untrusted URL inputs to `web-and-api`, while
this adapter owns the database execution grant.

## Integrity, consistency, and availability

Neo4j graph/schema operations run in ACID transactions. Review uniqueness, key,
existence, type and relationship constraints available to the deployed
edition/version; application-only checks are raceable unless transactionally
enforced. Validate retries/idempotency and bookmarks/causal consistency for
cluster reads.

Attack:

- missing/changed authorization property, unexpected labels, multi-label nodes,
  cross-tenant relationships, relationship endpoint smuggling, and `MERGE`
  matching an existing B node;
- variable-length traversal, path explosion, Cartesian products, regex,
  unbounded collect/aggregation, GDS/APOC jobs, full-text/vector queries, large
  transactions, and import;
- lock contention/deadlocks, memory-heavy modifications, transaction leaks,
  plan/cache abuse, page-cache pressure, connection exhaustion, and unbounded
  concurrent transactions.

Set and prove query/transaction timeouts, memory limits, concurrent transaction
limits, result bounds, and procedure/job controls. The documented default
transaction timeout can be disabled; do not assume it is protective.

## CDC, clustering, backups, and restore

Inventory cluster secondaries/read replicas, CDC/change identifiers,
connectors, APOC/Kafka exports, dumps, online backups, snapshots, import files,
and lower environments. Each bypasses or replays a different layer of graph
authorization. Raw store/backup access bypasses Cypher privileges.

Restore proof must re-establish users/external auth, roles/privileges, default
database and aliases, policy properties/constraints, plugins/procedures and
allowlists, CDC positions, logging, and cluster topology before use. Test
failover, restored aliases/composites, and a rolling upgrade for security-state
equivalence.

## Audit and attribution

The security log records authentication, administration commands against
`system`, and authorization failures when auth is enabled. Query logging is a
separate facility and can expose literals/parameters. Verify edition/version,
success/failure coverage, thresholds, rotation, redaction/obfuscation,
transaction metadata, cluster-node collection, and whether query logging is
appropriate for sensitive data.

For allowed and denied cross-tenant attempts, prove database user, source,
database/alias, query/action class, outcome, and an end-user correlation value.
Use driver transaction metadata for attribution where trustworthy, but do not
let callers forge privileged audit identity. Security logs alone do not prove
every successful graph read/write was recorded.

## Deletion, lifecycle, and copies

Test node/relationship/property deletion, required `DETACH DELETE` behavior,
cross-tenant relationships, full-text/vector index convergence, CDC/connectors,
transaction logs, replicas, dumps/backups, exports, and derived stores.
Deleting a tenant root node does not cascade arbitrary graph reachability.

Semantic graph-RAG retrieval authorization, poisoning, and embedding/model
leakage belong to `llm-and-ai`. This adapter supplies native graph privilege,
vector-index data-plane, and technical deletion evidence. Legal retention
belongs to `privacy-and-data-protection`.

## Unsupported or unproven guarantees

Do not claim:

- Enterprise/Aura subgraph or property controls in Community;
- fail-closed property `DENY` when the property is absent/uncomparable;
- tenant isolation from a label/property predicate supplied only by code;
- topology secrecy from field/property masking alone;
- caller-limited execution for `EXECUTE BOOSTED`;
- complete successful data audit coverage from `security.log`;
- cascading graph deletion, CDC deletion, or backup erasure;
- causal/cluster freshness without bookmarks and deployed-mode proof.

## Rule anchors

- `db.authorization.neo4j.graph-privilege-boundary` evaluates the effective
  role union for graph/database privileges, label/type/property traversal,
  procedure execution, impersonation, and administrative paths. One label
  restriction cannot clear unrestricted traversal or a privileged procedure.

## Static discovery sweeps

| Evidence | Review |
|---|---|
| `neo4j.conf`, Helm/Compose/Aura config | version/edition, auth, default DB, procedures, import/network, transaction/resource limits, logs |
| Cypher grants/migrations | broad built-ins, graph/database wildcard, grants+denies, home DB, policy property, write/traverse/read split |
| `SHOW ... PRIVILEGES AS COMMANDS` captures | effective roles, evaluated temporal/property expressions, boosted execute, drift |
| query repositories | tenant binding on every node/relationship, raw Cypher, `MERGE`, optional/union/subquery/path escapes |
| schema migrations | constraints, immutable policy properties, unlabeled/missing-property handling, indexes |
| APOC/GDS/custom plugins | boosted execution, filesystem/network/import/export, dynamic Cypher and job limits |
| CDC/connectors/backup/import | bulk access, destinations, restore security state and deletion propagation |
| logging config | security/query coverage, success/denial, redaction, metadata and cluster collection |

## Proof and conformance matrix

Use A/B nodes, A-only and cross-tenant relationships, missing/mutable policy
properties, multi-label nodes, an A principal, writer, procedure role,
migrator, and admin control:

| Path | Required negative proof |
|---|---|
| node/property/relationship reads | A cannot read B data |
| traverse/count/path/aggregate/index | A cannot infer forbidden B topology/data beyond declared leakage |
| missing/changed policy property | policy fails according to the intended secure state; A cannot edit its input |
| create/merge/set/remove/delete | A cannot attach to, relabel, retenant, overwrite, or delete B |
| relationship endpoints | A cannot create a cross-boundary edge or reach B through it |
| APOC/GDS/custom/boosted procedure | execution cannot expand caller authority unexpectedly |
| alias/composite/HTTP/Bolt/Browser | alternate endpoint or graph name cannot bypass |
| CDC/backup/export/restore | copied paths are separately authorized and preserve deletion scope |
| failover/rolling upgrade | effective privileges remain equivalent |
| audit | allowed and denied activity is attributable without leaking literals |
| availability | path/Cartesian/job/transaction attacks are bounded |

## Known false positives

- A broad traversal grant may be required for a public topology while
  properties remain protected; validate the declared inference model.
- A database-per-tenant design need not use property controls if aliases,
  procedure paths, backups, and database grants pass.
- `EXECUTE BOOSTED` can be intentional for a narrow audited encapsulation;
  prove exact allowlist, inputs, output, and side effects before accepting it.
- A missing transaction timeout in a development profile is not production
  exposure when deployment evidence proves a protective override.
- A property-based `GRANT` may safely exclude missing properties; do not
  transpose the documented fail-open `DENY` caveat to every rule shape.

## Fixture concept

Use a version-pinned Neo4j Enterprise fixture and a Community negative-capability
profile. Create A/B subgraphs, missing/mutable classification properties,
cross-tenant relationships, labels, constraints, full-text/vector indexes, a
boosted custom procedure, CDC/export, cluster failover, and backup/restore. The
vulnerable policy relies on a fail-open property deny and lets users edit the
property or call a boosted procedure. The clean policy uses a supported native
boundary or database separation, immutable policy inputs, least-privilege
execute grants, bounded queries, and attributable logs.

## Official sources

Verified 2026-07-28:

- https://neo4j.com/docs/operations-manual/current/authentication-authorization/
- https://neo4j.com/docs/operations-manual/current/authentication-authorization/manage-privileges/
- https://neo4j.com/docs/operations-manual/current/authentication-authorization/property-based-access-control/
- https://neo4j.com/docs/operations-manual/current/authentication-authorization/manage-execute-permissions/
- https://neo4j.com/docs/operations-manual/current/database-internals/transaction-management/
- https://neo4j.com/docs/operations-manual/current/monitoring/logging/
