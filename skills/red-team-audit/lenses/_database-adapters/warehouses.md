# Warehouse and lakehouse adapter family

Adapter ID: `snowflake`, `bigquery`, `redshift`, `databricks`

Deployment variants: `snowflake-managed`, `bigquery-managed`,
`redshift-provisioned`, `redshift-serverless`, `databricks-unity-catalog`

Verified: `2026-07-28`

This adapter initially profiles Snowflake, BigQuery, Amazon Redshift, and
Databricks Unity Catalog. It treats them as distinct engines whose SQL-like
surfaces, role composition, sharing, history, and compute controls differ. It
applies through `database-and-data-stores` and owns no topics.

## Detect and profile

Activate on official clients/connectors, warehouse SQL dialect/config,
Terraform/provider resources, dbt profiles/models, grants/policies, scheduled
queries/jobs, notebooks, catalog resources, shares, or native audit exports.
Record:

- provider, account/project/workspace, exact feature/version/runtime/edition,
  Region, catalog/metastore, warehouse/compute mode, and federated/external
  storage;
- organization/account/project/catalog/database/schema/dataset/table/view/
  volume/share hierarchy as the engine defines it;
- interactive analyst, BI, application, ETL/ELT, dbt, notebook/job, service,
  policy owner, data-sharing, replication, backup/restore, and admin principals;
- tenant unit, row/column/masking policy, role/group/tag inputs, materialized
  copies, time travel/history, clones, shares, exports, stages/object storage,
  external tables, clean rooms, and ML/search/vector destinations.

An edition-gated feature that is unavailable or whose enablement is unknown is
`NOT ASSESSED`, not a failed or passed row-policy check.

Emit the contract's required `store_context`: `store_id`, `family`, `engine`,
`engine_version`, `deployment_variant`, `adapter_id`, `detection_evidence[]`,
and `confidence`. Keep `data_classes`, `tenant_unit`, `enforcement_plane`,
`principal_paths[]`, and `copy_paths[]` in the full store profile.

## Capability declaration

| Capability ID | Snowflake | BigQuery | Redshift | Databricks |
|---|---|---|---|---|
| `principal-authentication` | `NATIVE` | `NATIVE` | `NATIVE` | `NATIVE` |
| `role-and-object-grants` | `NATIVE` | `NATIVE` | `NATIVE` | `NATIVE` |
| `record-read-authorization` | `NATIVE` | `NATIVE` | `NATIVE` | `NATIVE` |
| `record-write-authorization` | `COMPOSABLE` | `COMPOSABLE` | `COMPOSABLE` | `COMPOSABLE` |
| `column-or-property-authorization` | `NATIVE` | `NATIVE` | `NATIVE` | `NATIVE` |
| `tenant-session-context` | `NATIVE` | `NATIVE` | `NATIVE` | `NATIVE` |
| `stored-code-execution-context` | `NATIVE` | `NATIVE` | `NATIVE` | `NATIVE` |
| `schema-integrity` | `COMPOSABLE` | `COMPOSABLE` | `COMPOSABLE` | `NATIVE` |
| `transactional-integrity` | `NATIVE` | `COMPOSABLE` | `NATIVE` | `COMPOSABLE` |
| `resource-governance` | `NATIVE` | `NATIVE` | `NATIVE` | `NATIVE` |
| `replication-cdc-authorization` | `COMPOSABLE` | `COMPOSABLE` | `COMPOSABLE` | `COMPOSABLE` |
| `history-authorization` | `COMPOSABLE` | `NATIVE` | `UNKNOWN` | `COMPOSABLE` |
| `backup-policy-portability` | `COMPOSABLE` | `COMPOSABLE` | `COMPOSABLE` | `COMPOSABLE` |
| `security-audit` | `NATIVE` | `NATIVE` | `NATIVE` | `NATIVE` |
| `policy-catalog-introspection` | `NATIVE` | `NATIVE` | `NATIVE` | `NATIVE` |

`NATIVE` means the identified product can express the primitive, not that the
profile configured it. Row/write and history semantics remain subject to the
documented edition/runtime/access-path limitations below.

## Engine-specific privilege semantics

| Engine | Hierarchy and effective access hazards |
|---|---|
| Snowflake | Organization/account -> database -> schema -> objects, with account/database roles, hierarchy, ownership, future grants, secondary-role behavior, secure objects, shares and reader accounts. Row access policies are Enterprise Edition; they filter reads and selected rows for update/delete/merge but do not prevent insert or update/delete of visible rows. Role/session functions behave differently across shares. |
| BigQuery | Organization/folder/project -> dataset -> table/view/model/routine, plus IAM, authorized datasets/views/routines, policy tags, row access policies and reservations. Multiple row policies grant qualifying rows; separate tables are stronger where row counts/existence are sensitive. Project/dataset roles and authorized views can widen access. |
| Redshift | AWS account/namespace/workgroup/cluster -> database -> schema -> relation, with IAM/control plane plus database users/groups/roles, inherited privileges, scoped permissions, datashares and external schemas. RLS applies to SELECT/UPDATE/DELETE but not INSERT, COPY, or ALTER TABLE APPEND; superuser/IGNORE RLS paths require explicit review. |
| Databricks | Account/metastore -> catalog -> schema -> table/view/volume/function/model, with account/workspace groups, service principals, privilege inheritance, workspace bindings, storage credentials/external locations and compute modes. Unity Catalog row filters/column masks are SQL UDF based; tag-driven ABAC has runtime/compute/feature requirements and table filters have clone/time-travel/AI Search limitations. |

Resolve direct and inherited roles/groups, ownership, future/default/scoped
grants, service-principal impersonation, share/recipient privileges, policy
owners/UDF execution, and bypass/admin roles. Do not assume deny precedence;
many warehouse role systems primarily accumulate grants.

Route generic cloud IAM, object-storage buckets, networks, KMS, and control-plane
logging to `cloud-and-iac`/crypto. This adapter proves the warehouse data-plane
consequence and access through external locations/stages.

## Native versus application-only authorization

Label every access path:

- `native-row-column`: versioned row policy plus column policy/mask;
- `native-object`: table/view/dataset/schema/catalog grants or separate tenant
  object;
- `authorized-view/share`: native encapsulation with documented limitations;
- `application-only`: BI/app/dbt SQL injects a tenant filter under a broad
  service principal;
- `hybrid`, `none`, or `unknown`.

Test select and inference separately from insert, update, merge, delete, copy/
load/unload, clone, share, export, ML/search/index, and history access. RLS is
not a universal write policy. A masking policy can hide values without hiding
counts, grouping, joins, statistics, timing, or the underlying object from a
broader role.

SQL/query injection belongs to `web-and-api`. This adapter owns policy/UDF
execution context, alternate warehouse interfaces, and privilege consequence.

## Alternate paths and privileged execution

Exercise:

- tables, secure/ordinary/authorized/dynamic/materialized/late-binding views,
  external/Iceberg/federated tables, cached/result/history/time-travel reads,
  metadata/information schema, BI semantic layers, notebooks, JDBC/ODBC,
  REST/query APIs, and direct object-storage access;
- insert/copy/load/write streams, update/merge/delete/truncate, CTAS, temp/
  transient tables, materializations, dbt jobs, UDFs/procedures, scheduled
  queries, and notebook/job compute;
- exports/unloads/stages, clones, fail-safe/time travel, snapshots, replication/
  failover, datashares/marketplaces/Delta Sharing/clean rooms, cross-account/
  project shares, ML models, search/vector indexes, and downstream extracts.

Review owner/definer/execution context for functions, procedures, row-policy
UDFs, remote/external functions, Python/Java/Scala runtimes, notebook libraries,
COPY credentials, external connections, storage credentials, network access,
and task/job owners. Privileged code can both bypass a policy and exfiltrate
through an external destination.

## Integrity, consistency, and availability

Review constraints and whether they are enforced versus informational,
transaction boundaries, merge/upsert uniqueness, streaming/ingestion
deduplication, materialized-view refresh, result caching, replica/share
consistency, and policy/tag propagation. Do not assume OLTP constraints or
transaction isolation from SQL syntax.

Attack:

- stale mapping/entitlement tables, role/session-context confusion, shared
  connection pools, policy-owner bypass, missing tenant tags, and copied tables
  created without policy attachment;
- counts, query duration, errors, explain plans, statistics, joins, grouping,
  sampling, ML training/prediction, exports, and metadata inference;
- unbounded scans/joins/recursive queries/UDFs, Cartesian products, warehouse
  auto-scaling, query concurrency, materialization/clone storms, notebook jobs,
  external-function fan-out, and denial-of-wallet;
- one tenant monopolizing shared compute or causing spill/storage/queue
  exhaustion.

Prove query timeouts, statement/slot/warehouse quotas, resource monitors,
workload management, per-user/tenant budgets, result/export limits, and
kill/cancellation paths.

## Sharing, history, replication, backup, and restore

Inventory:

- Snowflake shares/reader accounts, listings, clones, Time Travel/Fail-safe,
  replication/failover groups, streams/dynamic tables and external stages;
- BigQuery authorized views/datasets, snapshots/clones, time travel, exports,
  transfers, Analytics Hub, external tables and cross-project jobs;
- Redshift datashares, snapshots/restores, cross-Region sharing, UNLOAD/COPY,
  Spectrum/external schemas and zero-ETL integrations;
- Databricks Delta Sharing, clean rooms, shallow/deep clones, version history,
  external locations/volumes, table sharing, lineage, jobs and checkpoints.

For every restored/cloned/copied table, prove grants, policies/masks/tags,
policy UDFs/mapping tables, ownership, audit, network/external connections, and
share membership are present before access. A data copy can silently drop its
policy association. A “live share” is still an independent authorization and
egress path.

## Audit and attribution

Version-gate and validate:

- Snowflake query/access history, login history, grants/policy references, and
  sharing/administrative events with documented latency/edition;
- BigQuery Cloud Audit Logs for data access, jobs, policies, authorized views,
  exports and impersonation;
- Redshift database connection/user/user-activity logging, CloudTrail
  management/datashare events, and the separate
  `enable_user_activity_logging` requirement;
- Databricks audit logs/system tables (`system.access.audit`), lineage, account
  versus workspace scope, regional coverage, retention, and preview status.

For allowed and denied cross-tenant queries and exports, prove original/effective
principal, active role/group, service/job/notebook, object and share, policy
context, action/query ID, result, and end-user correlation. Protect logs from
query text/secrets and from the same admins they are meant to audit.

## Deletion, retention, and copies

Warehouse deletion includes current tables plus time travel/history/fail-safe,
clones, snapshots, result caches, materialized/dynamic tables, streams/
checkpoints, shares, exports, external object storage, notebooks, local BI
extracts, ML/search/vector copies, and replicas. Record the technical retention
window and whether a clone/share prevents or merely references deletion.

Semantic RAG/search/model threats belong to `llm-and-ai`; legal retention and
erasure sufficiency belong to `privacy-and-data-protection`. This adapter
supplies policy and copy propagation evidence.

## Unsupported or unproven guarantees

Do not claim:

- universal RLS/write enforcement across warehouses;
- that a view, mask, or BI filter prevents inference or direct-table access;
- deny precedence across accumulated warehouse roles;
- policy continuity through CTAS, clone, restore, share, external table, ML,
  or search/index paths without engine-specific proof;
- immediate revocation where caches/tokens/shares propagate asynchronously;
- complete audit coverage or freshness merely because a history table exists;
- enforced relational constraints in analytical engines;
- legal erasure from a logical delete while history/clones/exports remain.

## Rule anchors

- `db.authorization.snowflake.row-access-policy-boundary` evaluates active and
  secondary roles, ownership, row-access and masking policies, secure views,
  shares, clones, and task/procedure execution paths.
- `db.authorization.bigquery.row-access-policy-boundary` evaluates the caller's
  IAM grants, row-access policies, authorized views/datasets, routines, jobs,
  exports, and service-agent paths.
- `db.authorization.redshift.rls-policy-boundary` evaluates effective roles,
  RLS attachment and bypass authority, views, stored procedures, UNLOAD/COPY,
  data sharing, and administrative paths.
- `db.authorization.databricks.row-filter-boundary` evaluates Unity Catalog
  privileges, row filters, column masks, views, function execution, external
  locations, shares, and compute identity paths.

## Static discovery sweeps

| Evidence | Review |
|---|---|
| Terraform/provider/dbt grants | hierarchy, owner/future/default/scoped grants, wildcards, role inheritance, new-object drift |
| row/mask/tag policies | edition/compute support, mapping-table/UDF owner, session-role function, missing tags, attachment coverage |
| views/materializations/CTAS | authorized/secure semantics, backing-table access, copied-policy attachment, owner/definer context |
| service/BI/notebook/dbt clients | active role, pooled identity, application-only filters, raw SQL/export paths, attribution |
| UDF/procedure/task/job code | privileged runtime, external destinations, libraries, credentials and resource bounds |
| shares/external tables/stages | recipient/consumer access, storage credentials, copy/export, cross-account/project scope |
| clone/backup/replication | policy/grant/tag recreation, history and pre-traffic restore gate |
| audit configuration | data versus admin events, success/denial/export coverage, Regions/accounts, latency/retention |

## Proof and conformance matrix

Use A/B rows, sensitive columns, an A analyst, pooled BI/app principal, loader/
writer, policy owner, share consumer, job/notebook, and admin control:

| Path | Required negative proof |
|---|---|
| select/view/materialized/history | A cannot read B current or historical data |
| count/group/join/statistics/explain | A cannot infer B beyond the declared leakage model |
| insert/copy/update/merge/delete | A cannot create for B, retenant, mutate/delete B, or bypass a read-only policy |
| CTAS/temp/clone/materialize | derived table does not drop required grants/policies/tags |
| UDF/procedure/task/notebook | execution context cannot bypass/exfiltrate unexpectedly |
| share/export/stage/external table | consumer or bulk path is limited to declared objects/rows/columns |
| replica/failover/restore | equivalent policy state exists before access |
| secondary role/group/session pool | activating another grant cannot widen A unexpectedly |
| audit | query/export/admin attempts are attributable to human/service/end user |
| availability/cost | scan/join/UDF/concurrency/materialization attack is bounded |

## Known false positives

- Separate table/dataset/schema/catalog per tenant can be stronger than RLS;
  do not require a row policy when native object grants and copy paths pass.
- A warehouse owner/admin bypass may be necessary; evaluate separation,
  just-in-time access, and audit instead of demanding it obey ordinary policy.
- An informational constraint is not automatically a finding unless code relies
  on it for security/integrity as if enforced.
- A row-count side channel should be graded against data sensitivity and
  attacker query capability, not reported mechanically.
- Audit/history latency is not absence when documented and within the declared
  detection objective; verify the bound.

## Fixture concept

Maintain a common conformance dataset and isolated engine fixtures/projects for
Snowflake, BigQuery, Redshift, and Databricks. Include A/B rows, sensitive
columns, mapping table, row/mask policy, ordinary and authorized/secure views,
writer/loader, pooled BI role, UDF/task/job, share/export, clone/history, and
audit. Vulnerable variants use app/BI filters, broad secondary roles, policy
only on the base read path, and copies without policy. Clean variants use the
engine's strongest appropriate object/row boundary, separate writers and
policy owners, secure copy/share workflows, resource limits, and attributable
audit. Tests must encode each engine's different write and composition rules.

## Official sources

Verified 2026-07-28:

- https://docs.snowflake.com/en/user-guide/security-access-control-overview
- https://docs.snowflake.com/en/user-guide/security-row-intro
- https://docs.snowflake.com/en/user-guide/access-history
- https://docs.snowflake.com/en/user-guide/data-sharing-intro
- https://cloud.google.com/bigquery/docs/row-level-security-intro
- https://cloud.google.com/bigquery/docs/authorized-views
- https://cloud.google.com/bigquery/docs/reference/auditlogs
- https://docs.aws.amazon.com/redshift/latest/dg/t_rls.html
- https://docs.aws.amazon.com/redshift/latest/dg/t_rls_usage.html
- https://docs.aws.amazon.com/redshift/latest/dg/datashare-overview.html
- https://docs.aws.amazon.com/redshift/latest/mgmt/db-auditing.html
- https://docs.databricks.com/aws/en/data-governance/unity-catalog/access-control
- https://docs.databricks.com/aws/en/data-governance/unity-catalog/filters-and-masks
- https://docs.databricks.com/aws/en/data-governance/unity-catalog/abac/requirements
- https://docs.databricks.com/aws/en/admin/system-tables/audit-logs
