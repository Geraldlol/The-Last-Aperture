# Vector-store adapter family

Adapter ID: `pinecone`, `qdrant`, `weaviate`, `milvus`

Deployment variants: `pinecone-serverless`, `qdrant-self-managed`,
`qdrant-cloud`, `weaviate-self-managed`, `weaviate-cloud`,
`milvus-self-managed`, `zilliz-cloud`

Verified: `2026-07-28`

This adapter covers the storage/data-plane semantics of Pinecone, Qdrant,
Weaviate, and Milvus first, with an explicit extension point for other vector
stores. It does not turn all vector products into one fictional authorization
model. Semantic RAG threats remain with `llm-and-ai`.

## Detect and profile

Activate only after identifying an engine through an official client,
endpoint, image/config, collection/index migration, or managed resource.
Record exact engine, server/API version, cloud/self-hosted deployment, plan or
edition, region/topology, modules, and authentication mode.

Inventory:

- organization/project/cluster/instance/database/index/collection/namespace/
  tenant/partition/shard and record/point/object hierarchy as applicable;
- embedding model/dimension/metric only to identify incompatible copies and
  index rebuild paths, not to evaluate model quality here;
- application search/write, ingest, embedding, delete, backup, migration,
  analytics, and administrative principals;
- metadata/payload tenant key, native tenant unit, API-key/RBAC enforcement
  plane, replicas, snapshots/backups, bulk exports/imports, and downstream
  retrieval services.

Unknown engine/version/plan semantics are `NOT ASSESSED`. “Vector database”
alone is insufficient activation evidence.

Emit the contract's required `store_context`: `store_id`, `family`, `engine`,
`engine_version`, `deployment_variant`, `adapter_id`, `detection_evidence[]`,
and `confidence`. Keep `data_classes`, `tenant_unit`, `enforcement_plane`,
`principal_paths[]`, and `copy_paths[]` in the full store profile.

## Capability declaration

These are branch defaults after product recognition. Plan/version gates can
downgrade a cell to `UNKNOWN`; an external tenant router never upgrades a
native capability.

| Capability ID | Pinecone | Qdrant | Weaviate | Milvus |
|---|---|---|---|---|
| `principal-authentication` | `NATIVE` | `NATIVE` | `NATIVE` | `NATIVE` |
| `role-and-object-grants` | `COMPOSABLE` | `NATIVE` | `NATIVE` | `NATIVE` |
| `record-read-authorization` | `UNSUPPORTED` | `UNSUPPORTED` | `COMPOSABLE` | `UNSUPPORTED` |
| `record-write-authorization` | `UNSUPPORTED` | `UNSUPPORTED` | `COMPOSABLE` | `UNSUPPORTED` |
| `column-or-property-authorization` | `UNSUPPORTED` | `UNSUPPORTED` | `UNSUPPORTED` | `UNSUPPORTED` |
| `tenant-session-context` | `EXTERNAL_ONLY` | `EXTERNAL_ONLY` | `COMPOSABLE` | `EXTERNAL_ONLY` |
| `stored-code-execution-context` | `EXTERNAL_ONLY` | `UNSUPPORTED` | `EXTERNAL_ONLY` | `UNSUPPORTED` |
| `schema-integrity` | `COMPOSABLE` | `COMPOSABLE` | `NATIVE` | `NATIVE` |
| `transactional-integrity` | `UNSUPPORTED` | `UNSUPPORTED` | `UNSUPPORTED` | `UNSUPPORTED` |
| `resource-governance` | `NATIVE` | `COMPOSABLE` | `COMPOSABLE` | `COMPOSABLE` |
| `replication-cdc-authorization` | `UNKNOWN` | `EXTERNAL_ONLY` | `COMPOSABLE` | `COMPOSABLE` |
| `history-authorization` | `UNSUPPORTED` | `UNSUPPORTED` | `UNSUPPORTED` | `UNSUPPORTED` |
| `backup-policy-portability` | `COMPOSABLE` | `COMPOSABLE` | `COMPOSABLE` | `COMPOSABLE` |
| `security-audit` | `UNKNOWN` | `UNKNOWN` | `NATIVE` | `UNKNOWN` |
| `policy-catalog-introspection` | `COMPOSABLE` | `NATIVE` | `NATIVE` | `NATIVE` |

`record-*-authorization: COMPOSABLE` for Weaviate refers only to a correctly
enabled native multi-tenant collection plus tenant-scoped RBAC in a supporting
version. It does not mean arbitrary object predicates. Pinecone namespaces,
Qdrant collections, and Milvus databases/collections are stronger resource
units that can still supply tenant isolation even though general record-policy
capability is `UNSUPPORTED`.

## Engine-specific hierarchy and authorization

| Engine | Resource/tenant unit | Authorization facts the evaluator must encode |
|---|---|---|
| Pinecone serverless | organization/project -> index -> namespace -> record | Project roles/API keys control data/control planes. Pinecone recommends one namespace per tenant; data operations target a namespace. Metadata filters in one namespace are application-level isolation, not a substitute for namespace separation when strict tenant isolation is required. |
| Qdrant | instance/cluster -> collection -> shard -> point/payload | Self-hosted starts unsecured unless configured. Admin/read-only keys and version-gated granular JWT access can scope read/write to collections; payload filters remain application-only unless the exact JWT-RBAC claim demonstrably enforces them. Internal cluster port protection is separate. |
| Weaviate | cluster -> collection -> tenant -> object/property | Authentication may allow anonymous access in self-hosted defaults. Version-gated RBAC can scope collection/tenant/data operations. Multi-tenancy must be enabled on the collection and the tenant selected for every applicable operation. |
| Milvus | instance -> database -> collection -> partition/partition key -> entity | Authentication requires `authorizationEnabled`; change the documented default `root:Milvus`. RBAC supports database/collection tenancy, while official guidance says partition and partition-key tenancy do not have RBAC support. Those modes need application enforcement or a stronger boundary. |

Do not infer negative/deny precedence, role union, tenant wildcard behavior, or
control/data-plane separation across vendors. Query the running effective
roles/keys where the product supports it.

## Native versus application-only authorization

Label each operation:

- `native-namespace`, `native-collection`, `native-tenant`, or
  `native-database` when the engine independently enforces that unit;
- `application-metadata-filter` when code adds a tenant payload/metadata
  predicate while its credential can omit it;
- `application-router` when a trusted service chooses the tenant unit with a
  broad credential;
- `hybrid`, `none`, or `unknown`.

Metadata or payload filtering can improve search relevance/performance without
being an authorization control. Prove `query/search`, fetch/get, list/scroll,
recommend/discover, update/upsert, delete, batch/import, and collection/index
administration independently. Namespace/tenant selection must be server-bound
to authenticated context, not accepted raw from a caller.

Semantic authorization of which source chunks a user should retrieve,
cross-document inference, poisoning, prompt injection, embedding inversion,
model-context exfiltration, and RAG answer leakage belong to `llm-and-ai`.
This adapter owns native storage credentials, tenant scope, alternate data
paths, resource exhaustion, and technical copy/deletion behavior.

Generic query/filter injection belongs to `web-and-api`.

## Alternate paths and privileged surfaces

Exercise:

- similarity, hybrid, sparse, keyword/filter-only, recommendation, grouping,
  aggregation/count, fetch/get, list/scroll, and direct ID access;
- query with no tenant selector, empty/default namespace, wildcard/all-tenant
  calls, wrong-case/encoded tenant identifiers, cross-collection/index APIs,
  and batch/multi-query;
- upsert/update metadata or payload, ownership/tenant mutation, delete by ID,
  delete by filter, delete all/namespace/collection, and bulk import/export;
- replicas/read nodes, snapshots/backups, restores, collection aliases,
  tenant offload/cold states, shard movement, index rebuilds, and managed
  console/API paths.

Review admin API keys, control-plane project roles, collection/index creation
and deletion, RBAC/user management, snapshot/restore URLs, modules/plugins,
inference/vectorizer/generative modules, webhook/connectors, strict-mode/
resource settings, and internal cluster APIs. Module calls that reach external
models or URLs are separate authority paths.

## Integrity, consistency, and availability

Record each product's write/read consistency, acknowledgement, replica
behavior, index freshness, ordering, and backup point. Approximate nearest
neighbor search is not an integrity failure by itself, but security filters
must not be approximate or post-filtered in a way that exposes candidates.

Attack:

- stale deletes/updates, replica/index lag, overwrite-by-ID, cross-tenant ID
  collision, missing payload fields, mutable tenant fields, partial batches,
  and dimension/model/schema drift;
- extreme `top_k`/limit, broad filters, huge metadata/payload, high-dimensional
  vectors, hybrid fan-out, unindexed payload filters, sparse-vector
  cardinality, batch upserts, collection/namespace/tenant explosion, and index
  rebuilds;
- adversarial hot tenants/noisy neighbors, replica/shard movement, snapshot
  creation, offload/reactivation, external inference cost, and unbounded result
  inclusion of vector/payload values.

Use native strict/rate/quota controls when available, plus application limits.
Qdrant self-hosted strict mode and managed defaults, for example, must be
distinguished by version/deployment.

## Replicas, snapshots, backups, and restore

Inventory every Pinecone backup/restored index, Qdrant snapshot/shard transfer,
Weaviate backup/export/offloaded tenant, Milvus object storage/backup, replica,
bulk import, and analytics/search copy. Backup authorization and data-plane
authorization are different; a backup can expose every tenant.

Restore proof must recreate API keys/roles/users separately where required,
tenant/namespace mapping, payload indexes, collection aliases, strict/rate
limits, audit settings, and delete/offboarding state before clients connect.
Weaviate documentation, for example, states RBAC roles/users are not restored
by default and has version-specific multi-tenant backup behavior.

## Audit and attribution

Feature-gate audit:

- Pinecone plan/project audit events and API-key/control-plane coverage;
- Qdrant Cloud/self-hosted versioned audit configuration;
- Weaviate automatic authorization decision logs when RBAC is enabled;
- Milvus/Zilliz deployment-specific audit support.

Ordinary request logs, metrics, and billing are not automatically a durable
successful data audit. Prove allowed and denied query/fetch/upsert/delete/
backup/admin calls include database principal/key ID, resource and tenant unit
where available, action, result, source/correlation, and end-user actor. Never
log raw embeddings, payloads, prompts, source chunks, or API keys to improve
attribution.

## Deletion, TTL, and derived copies

Do not assume a universal TTL. Detect a product/version-supported expiry
feature or require explicit delete/offboarding. Test record/point/object
deletion, delete-by-filter, namespace/tenant/collection deletion, replicas,
snapshot/backup retention, offloaded/cold tenants, caches, and asynchronous
index convergence.

Technical deletion propagation into embedding/vector stores that mirror a
source is inventoried here, but `llm-and-ai` owns the semantic derived-store
inheritance/deletion finding and `privacy-and-data-protection` owns legal
retention. Deduplicate on the owning topic.

## Unsupported or unproven guarantees

Do not claim:

- a universal row-policy, role-composition, audit, TTL, transaction, or
  consistency model across vector stores;
- tenant authorization from metadata filtering alone;
- namespace/tenant isolation when a broad key accepts a caller-controlled
  namespace/tenant;
- Milvus RBAC at partition or partition-key tenant levels;
- production authentication from a local embedded/in-memory client;
- backup restoration of users/roles/API keys;
- immediate deletion from replicas, indexes, offloaded storage, or backups;
- semantic RAG safety from storage isolation tests.

## Rule anchors

- `db.authorization.pinecone.namespace-metadata-boundary` evaluates project,
  index, namespace, metadata-filter, API-key, and administrative paths; a
  namespace supplied by the client is not an authorization boundary by itself.
- `db.authorization.qdrant.payload-filter-boundary` evaluates collection,
  shard, payload-filter, API-key, snapshot, and administrative paths.
- `db.authorization.weaviate.tenant-object-boundary` evaluates tenant status,
  collection/object permissions, filters, cross-reference traversal, backup,
  and administrative paths.
- `db.authorization.milvus.rbac-collection-boundary` evaluates database,
  collection/partition, RBAC privilege-group, alias, backup, and administrative
  paths.

## Static discovery sweeps

| Evidence | Review |
|---|---|
| client and endpoint initialization | engine/version, local versus cloud, broad/admin key use, TLS handoff, one key across runtime/admin/ingest |
| index/collection schema | tenant unit, mutable/missing metadata, namespaces/tenants/partitions, payload indexes, model/dimension drift |
| every query API | native scope versus caller filter, default namespace, fetch/list/count/scroll, result/vector/payload limits |
| every mutation API | cross-tenant IDs, ownership changes, filter deletes, delete-all, partial batch/idempotency |
| auth/RBAC config | anonymous/default auth, resource wildcards, control/data plane, version/plan support |
| strict/rate/resource settings | broad filters, top-k, batches, collection/tenant count, external inference calls |
| snapshots/backups/offload | bulk authorization, role restoration, tenant inclusion, delete propagation |
| RAG framework integration | only storage scope here; route retrieval/prompt/model findings to `llm-and-ai` |

## Proof and conformance matrix

For each engine, use A/B data, an A-scoped native principal when supported, the
actual broad application principal, ingest/delete roles, and an admin control:

| Path | Required negative proof |
|---|---|
| search/hybrid/recommend/filter-only | A cannot retrieve or infer B from results/counts |
| fetch/list/scroll/direct ID | alternate reads cannot bypass search filter |
| upsert/update/batch | A cannot create for B, collide with B ID, or mutate tenant ownership |
| delete by ID/filter/all | A cannot delete B or expand delete scope |
| empty/default/wrong tenant unit | request fails closed rather than selecting shared/global data |
| admin/RBAC/index/collection | runtime principal cannot create/drop/export/restore or mint access |
| replica/snapshot/backup/restore/offload | copies preserve declared authorization and deletion state |
| consistency | read-after-write/delete behavior stays within declared security bounds |
| audit | allowed/denied operations are attributable without sensitive vector/payload logging |
| availability/cost | broad-filter/top-k/batch/index-build attack is bounded |

## Known false positives

- One namespace/collection per tenant can be sufficient even when per-record
  policies do not exist, provided keys/routing/admin/copies pass.
- A broad server key is not automatically a finding when an unbypassable
  service boundary supplies tenant scope and raw access is unavailable to
  users; keep blast-radius evidence.
- Approximate result variance is not a security defect unless it violates an
  authorization or integrity invariant.
- Anonymous access in a local development fixture is not production exposure
  when deployment evidence excludes it.
- Metadata filtering is not native auth, but its use is not itself defective
  when a stronger independent boundary exists.

## Fixture concept

Maintain one conformance manifest and separate version-pinned fixtures for
Pinecone (isolated test project), Qdrant, Weaviate, and Milvus. Each holds A/B
records with overlapping IDs, a missing/mutable tenant field, hybrid and direct
ID paths, bulk mutation/delete, snapshot/backup, and an admin role. Vulnerable
variants use one broad key plus caller metadata filters/default namespaces,
permit anonymous/default admin access, and omit limits. Clean variants use the
strongest supported native tenant unit or a behaviorally proved service
boundary, separate principals, bounded operations, copy inventory, and
attributable audit. Never treat one engine passing as evidence for another.

## Official sources

Verified 2026-07-28:

- https://docs.pinecone.io/guides/index-data/implement-multitenancy
- https://docs.pinecone.io/guides/production/security-overview
- https://docs.pinecone.io/guides/index-data/data-modeling
- https://qdrant.tech/documentation/operations/security/
- https://qdrant.tech/documentation/tutorials/multiple-partitions/
- https://qdrant.tech/documentation/tutorials-operations/create-snapshot/
- https://docs.weaviate.io/deploy/configuration/authentication
- https://docs.weaviate.io/deploy/configuration/configuring-rbac
- https://docs.weaviate.io/deploy/configuration/backups
- https://milvus.io/docs/authenticate.md
- https://milvus.io/docs/multi_tenancy.md
- https://milvus.io/docs/users_and_roles.md
- https://milvus.io/docs/single-instance-backup-and-restore.md
