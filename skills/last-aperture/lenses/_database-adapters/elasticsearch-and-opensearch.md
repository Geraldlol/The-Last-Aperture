# Elasticsearch and OpenSearch adapter

Adapter ID: `elasticsearch`, `opensearch`

Deployment variants: `elasticsearch-self-managed`, `elastic-cloud`,
`elastic-serverless`, `opensearch-self-managed`, `amazon-opensearch-service`,
`opensearch-serverless`

Verified: `2026-07-28`

This adapter has separate versioned branches for Elasticsearch and OpenSearch.
Shared API ancestry is not permission-semantic equivalence. It applies through
`database-and-data-stores` and owns no topics.

## Detect and profile

Activate on official clients, `_search`/`_bulk` endpoints, Elasticsearch/
OpenSearch images and Helm charts, index templates/mappings, Elastic roles, or
OpenSearch Security plugin files. Record:

- product, exact version/build, license/subscription, self-managed/Elastic
  Cloud/Amazon OpenSearch Service/other provider, serverless versus cluster;
- node/collection topology, data streams, indexes/aliases, templates,
  pipelines, transforms, search applications, security plugin/realm, and
  cross-cluster relationships;
- application, ingest, search-only, dashboard, transform, connector,
  replication, snapshot, migration, and security-administration principals;
- tenant unit (deployment, index, alias, document field, dashboard tenant),
  enforcement plane, and all snapshot/CCR/CCS/export/derived paths.

Feature-gate document/field security, audit, anonymous access, API keys, remote
clusters, and provider IAM by product, version, deployment and subscription.
Unknowns are `NOT ASSESSED`.

Emit the contract's required `store_context`: `store_id`, `family`, `engine`,
`engine_version`, `deployment_variant`, `adapter_id`, `detection_evidence[]`,
and `confidence`. Keep `data_classes`, `tenant_unit`, `enforcement_plane`,
`principal_paths[]`, and `copy_paths[]` in the full store profile.

## Capability declaration

Values below are product branches; exact license/provider/version can downgrade
a value to `UNKNOWN` or `UNSUPPORTED`.

| Capability ID | Elasticsearch | OpenSearch | Conditions |
|---|---|---|---|
| `principal-authentication` | `NATIVE` | `NATIVE` | Security feature/plugin or provider authentication enabled. |
| `role-and-object-grants` | `NATIVE` | `NATIVE` | Cluster/index/action privileges; provider IAM is an additional plane. |
| `record-read-authorization` | `NATIVE` | `NATIVE` | Licensed/versioned DLS for read paths; role composition differs. |
| `record-write-authorization` | `UNSUPPORTED` | `UNSUPPORTED` | DLS does not supply per-document write enforcement; isolate writers by index/service. |
| `column-or-property-authorization` | `NATIVE` | `NATIVE` | FLS for reads; not field-level write policy. |
| `tenant-session-context` | `COMPOSABLE` | `COMPOSABLE` | Templated DLS/user attributes with trusted identity mapping. |
| `stored-code-execution-context` | `COMPOSABLE` | `COMPOSABLE` | Script contexts/privileges plus trusted pipelines/plugins; no portable definer model. |
| `schema-integrity` | `COMPOSABLE` | `COMPOSABLE` | Mappings/templates with dynamic/coercion/ignore settings; no relational constraints. |
| `transactional-integrity` | `UNSUPPORTED` | `UNSUPPORTED` | No general multi-document transaction invariant. |
| `resource-governance` | `NATIVE` | `NATIVE` | Circuit breakers, task/query limits and workload controls, deployment-sensitive. |
| `replication-cdc-authorization` | `COMPOSABLE` | `COMPOSABLE` | CCR/remote credentials and copies; DLS/FLS limitations require separate boundaries. |
| `history-authorization` | `COMPOSABLE` | `COMPOSABLE` | Snapshots/translogs/backing indexes are alternate copies, not a uniform temporal policy. |
| `backup-policy-portability` | `COMPOSABLE` | `COMPOSABLE` | Snapshot restore requires explicit security-index/role/template/audit comparison. |
| `security-audit` | `UNKNOWN` | `NATIVE` | Elastic is subscription/config gated; OpenSearch audit exists but is disabled by default. |
| `policy-catalog-introspection` | `NATIVE` | `NATIVE` | Security APIs/config, roles, mappings, indexes, aliases and cluster settings. |

## Resource and tenant model

Model cluster/deployment -> data stream/index/alias -> document -> field, plus
Dashboards/Kibana saved-object spaces/tenants. A dashboard tenant or Kibana
Space is not an index/document authorization boundary. An alias with a filter
is not a security boundary if the same principal can address the backing index.

Tenant designs may use separate deployments, indexes/data streams, or native
document-level security (DLS). Metadata filters sent by an application are
application-only. Record hidden/system indexes, rollover generations,
templates, and newly created indexes that wildcard roles will match.

## Effective privilege semantics

### Elasticsearch

Resolve realm/role mappings, API key descriptors, role inheritance/composition,
cluster privileges, index patterns, restricted indexes, remote-cluster
privileges, DLS queries, and field-level security (FLS). Permissions from
multiple roles are unions. For one index, Elasticsearch combines DLS role
queries with OR and FLS field grants into a union; an unrestricted role can
remove the intended restriction. DLS/FLS is intended for read-only users.

### OpenSearch

Resolve authentication backends, backend roles, users, role mappings, action
groups, cluster/index permissions, tenants, DLS/FLS, and the precise
`plugins.security.dfm_empty_overrides_all` behavior. OpenSearch combines DLS
queries with OR, but its empty-DLS interaction and FLS composition differ from
Elasticsearch and can be configuration/version-sensitive. Do not reuse the
Elastic evaluator.

Route AWS domain/resource IAM, network policies, and general cloud roles to
`cloud-and-iac`; this adapter evaluates the resulting OpenSearch data actions.

## Native versus application-only authorization

Label each search/mutation path:

- `native-dls-fls`: versioned engine security constrains documents/fields;
- `native-index`: role/API key restricts whole indexes/data streams;
- `application-only`: alias or query filter supplied by trusted code;
- `hybrid`, `none`, or `unknown`.

OpenSearch DLS and FLS restrict reads, not writes. Elasticsearch documents DLS/
FLS for read-only accounts. Never grant writes to a supposedly tenant-scoped
DLS/FLS user without a separate write proof. A writer may modify or delete a
document it cannot read.

Query-string/DSL/SQL/PPL injection belongs to `web-and-api`. This adapter owns
dangerous script/plugin capability, policy composition, and the demonstrated
document/field consequence.

## Alternate paths and privileged execution

Exercise:

- `_get`, `_mget`, `_search`, `_msearch`, async search, scroll, point-in-time,
  SQL/ES|QL/PPL, terms enumeration, suggest, vector/kNN search, aggregations,
  highlighting, stored fields, doc values, source filtering, and explain;
- aliases, data streams, backing indexes, wildcards, multi-target syntax,
  cross-cluster search, Dashboards/Kibana saved searches, and direct API access;
- index/bulk/update/delete, `_update_by_query`, `_delete_by_query`, reindex,
  transforms, ingest pipelines, connectors, rollups/downsampling, and scripts;
- snapshots/repositories/restore, CCR, searchable snapshots, remote clusters,
  exports, and lower environments.

Review inline/stored Painless or OpenSearch scripts, ingest processors,
mustache templates, plugins/modules, snapshot repository registration,
security REST APIs, cluster settings, destructive actions, reroute, and script
contexts. Dashboard read-only UI settings do not constrain direct APIs.

## Integrity, consistency, and availability

Review dynamic mappings, coercion, `ignore_malformed`, index templates,
optimistic concurrency (`if_seq_no`/`if_primary_term`), refresh semantics,
replica acknowledgement, external versions, and bulk partial-failure handling.
Search visibility after a write is not immediate merely because the write was
acknowledged.

Attack:

- inference through counts, aggregations, scoring, term statistics, timing,
  error messages, highlights, and fields used by DLS;
- wildcard/regex/fuzzy/script queries, deep pagination, large `size`/`top_hits`,
  aggregation bucket explosion, high-dimensional kNN, stored fields/source,
  fielddata, scroll/PIT leaks, and multi-search amplification;
- mapping explosion, oversharding, unbounded tenant/index creation, bulk
  request pressure, expensive scripts/pipelines, snapshot/restore IO, and
  circuit-breaker exhaustion.

Limits must cover direct APIs, Dashboards, async jobs, transforms, remote
search, and vector endpoints.

## Replication, snapshots, restore, and derived copies

Inventory replicas, CCR, cross-cluster search credentials, remote reindex,
transforms, connectors, searchable snapshots, repositories, exports, and
downstream analytics. Elasticsearch cross-cluster replication does not support
DLS/FLS on replication privileges; use separate least-privilege remote
credentials and treat replicated indexes as independently governed.

Restore proof must validate renamed/index patterns, aliases, templates,
security state inclusion/exclusion, role mappings, API keys, audit settings,
ILM/ISM, pipelines, and system-index handling before opening restored indexes.
A snapshot repository is a bulk data-read/write and code/configuration-adjacent
surface, not only disaster recovery.

## Audit and attribution

Elasticsearch audit logging and OpenSearch Security audit logging are
feature/configuration dependent. OpenSearch audit logging is disabled by
default. For Elasticsearch, verify subscription and enablement on every node
or serverless/project surface. Review event include/exclude settings, ignored
users, success/read/write coverage, request bodies, sensitive header
redaction, rollover, and whether storing audit logs in the protected cluster
creates a tampering/availability dependency.

Prove allowed and denied cross-tenant calls record effective user/API key,
realm/backend roles where appropriate, origin, action, resolved indexes,
outcome, and end-user correlation without logging sensitive query payloads.

## Deletion, lifecycle, and copies

Inspect ILM/ISM transitions, rollover aliases, delete phases, data-stream
backing indexes, soft deletes/translog, snapshots/searchable snapshots,
replicas, transforms, connector destinations, caches, and restored clusters.
Deleting one alias, document, or current index is not proof that historical
generations and snapshots disappeared.

Semantic RAG authorization, retrieval poisoning, embedding inversion, and
model-context leakage belong to `llm-and-ai`. This adapter supplies native
index/document policy and copy/deletion evidence without duplicating those
findings. Legal retention belongs to `privacy-and-data-protection`.

## Unsupported or unproven guarantees

Do not claim:

- that a filtered alias or application query is native authorization;
- write isolation from DLS/FLS alone;
- deny precedence across additive Elastic roles;
- identical Elastic and OpenSearch DLS/FLS composition;
- that dashboard tenant/space permissions secure backing indexes;
- DLS/FLS propagation through every CCR, transform, snapshot, or remote path;
- audit coverage by default or without license/provider verification;
- immediate search visibility or deletion from snapshots.

## Rule anchors

- `db.authorization.elasticsearch.document-level-security-boundary` evaluates
  the effective role union, index aliases, DLS/FLS query semantics, templates,
  and alternate search/export paths; the presence of one DLS clause is not a
  clearance.
- `db.authorization.opensearch.document-level-security-boundary` applies the
  same outcome boundary using OpenSearch role mapping, security-plugin, tenant,
  index-pattern, and service-specific semantics.

## Static discovery sweeps

| Evidence | Review |
|---|---|
| images/Helm/config | product/version/license, security plugin, anonymous access, realms/backends, audit, scripts, remote clusters |
| Elastic roles/API keys | cluster/index wildcards, restricted indexes, additive role DLS OR/FLS union, write grants, remote privileges |
| OpenSearch roles/mappings | backend-role expansion, action groups, DLS OR, empty-DLS setting, FLS composition, security REST admin |
| aliases/templates/data streams | filter mistaken for security, new-index wildcard drift, backing-index direct access |
| query clients | raw endpoints, multi-target/wildcards, missing tenant filters, aggregation/count/inference and result limits |
| scripts/pipelines/plugins | executable/admin scope; route untrusted DSL/string construction to `web-and-api` |
| CCR/CCS/transforms/connectors | remote credentials, DLS/FLS limitations, destinations and end-user attribution |
| snapshot/ILM/ISM | repository privilege, restore security state, lifecycle gaps, historical copies |

## Proof and conformance matrix

Use tenants A/B in the same index plus separate indexes, an A search principal,
an A writer, a broad secondary role, ingest/transform/replication principals,
and an admin control:

| Path | Required negative proof |
|---|---|
| get/mget/search/msearch/SQL/PPL/vector | A cannot retrieve B by any read API |
| counts/aggs/suggest/highlight/explain | A cannot infer protected B data beyond the declared leakage model |
| added broad role/empty DLS | composition does not silently widen the intended boundary |
| index/bulk/update/delete/reindex | a scoped reader cannot write; scoped writer cannot mutate B |
| alias/backing index/wildcard/data stream | direct naming cannot bypass the tenant boundary |
| script/pipeline/plugin/security API | runtime identities cannot gain privileged execution/admin |
| CCR/CCS/transform/snapshot/restore | copied/remote paths preserve declared scope |
| failover/rollover/new index | roles and templates do not drift open |
| audit | allowed and denied calls resolve actor and concrete indexes |
| availability | representative aggregation/regex/kNN/bulk attack is bounded |

## Known false positives

- A broad ingest writer can be intentional when isolated from untrusted callers
  and unable to search; test overwrite/delete and pipeline abuse separately.
- DLS/FLS absence is not a defect for index-per-tenant designs whose wildcard,
  rollover, alias, snapshot, and remote paths pass.
- A filtered alias may be defense in depth; do not call it native enforcement,
  but do not report it as a defect if an independent native boundary holds.
- OpenSearch empty-DLS behavior must be read from the deployed setting/version,
  not inferred from Elasticsearch docs.
- Audit disabled in an unsupported subscription is an unsupported guarantee,
  not the same candidate as misconfigured available auditing.

## Fixture concept

Create separate version-pinned Elasticsearch and OpenSearch fixtures with A/B
documents, sensitive fields, separate indexes, alias, data stream/rollover,
DLS/FLS roles, a deliberately broad second role, write role, stored script,
transform, snapshot repository, and audit sink. Vulnerable variants trust alias
filters, combine a restricted role with broad access, grant writes under DLS,
and omit audit/resource limits. Clean variants use index isolation or correctly
composed read-only DLS/FLS, separate writers, constrained scripts, and tested
copy paths. Never use one product's expected results for the other.

## Official sources

Verified 2026-07-28:

- https://www.elastic.co/docs/deploy-manage/users-roles/cluster-or-deployment-auth/controlling-access-at-document-field-level
- https://www.elastic.co/docs/deploy-manage/users-roles/cluster-or-deployment-auth/role-structure
- https://www.elastic.co/docs/deploy-manage/security/limitations
- https://www.elastic.co/docs/reference/elasticsearch/configuration-reference/auding-settings
- https://docs.opensearch.org/latest/security/access-control/document-level-security/
- https://docs.opensearch.org/latest/security/access-control/field-level-security/
- https://docs.opensearch.org/latest/security/access-control/users-roles/
- https://docs.opensearch.org/latest/security/audit-logs/index/
