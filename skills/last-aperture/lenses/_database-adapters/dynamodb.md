# Amazon DynamoDB adapter

Adapter ID: `dynamodb`

Deployment variants: `dynamodb-aws`, `dynamodb-local`,
`dynamodb-compatible-managed`

Verified: `2026-07-28`

This adapter covers DynamoDB tables, indexes, streams, global tables, backups,
and common adjacent access paths. It applies through
`database-and-data-stores`, owns no topics, and does not replace the
`cloud-and-iac` lens's general AWS IAM or perimeter analysis.

## Detect and profile

Activate on DynamoDB SDK clients, table/index/stream ARNs, CloudFormation/CDK/
Terraform resources, DynamoDB Toolbox/Enhanced Client models, PartiQL calls,
DAX, local emulator configuration, or migration/bootstrap code. Record:

- account, Region, partition, table ARN, billing/capacity mode, table class,
  deletion protection, PITR, TTL, streams, GSIs/LSIs, replicas, and global-table
  consistency mode;
- AWS commercial/GovCloud/local or compatible implementation and exact
  feature/version assumptions;
- runtime role/session, web-identity user, Lambda role, migration, backup/
  restore, analytics/export, stream consumer, DAX, and operator principals;
- table, item primary key, tenant partition, index projections, stream images,
  exports, backups, global replicas, and downstream copies.

Local DynamoDB is a functional fixture, not proof of IAM, CloudTrail, global
tables, PITR, or production consistency semantics. If the AWS account/Region,
policy inputs, or managed feature state is unavailable, mark the gated rule
`NOT ASSESSED`.

Emit the contract's required `store_context`: `store_id`, `family`, `engine`,
`engine_version`, `deployment_variant`, `adapter_id`, `detection_evidence[]`,
and `confidence`. Keep `data_classes`, `tenant_unit`, `enforcement_plane`,
`principal_paths[]`, and `copy_paths[]` in the full store profile.

## Capability declaration

| Capability ID | Value | Conditions |
|---|---|---|
| `principal-authentication` | `NATIVE` | AWS IAM/STS signs and authenticates requests. |
| `role-and-object-grants` | `NATIVE` | Identity/resource policies and table/index/stream resources, subject to full IAM evaluation. |
| `record-read-authorization` | `NATIVE` | `dynamodb:LeadingKeys` can constrain item partitions when correctly applied to every action/key. |
| `record-write-authorization` | `NATIVE` | Leading-key/attribute conditions can constrain writes, batches and transactions when complete. |
| `column-or-property-authorization` | `NATIVE` | Top-level `dynamodb:Attributes` plus `Select`/`ReturnValues` conditions. |
| `tenant-session-context` | `COMPOSABLE` | STS/web-identity/session attributes can feed conditions; trust and substitution must be proved. |
| `stored-code-execution-context` | `EXTERNAL_ONLY` | DynamoDB has no stored-code runtime; Lambda/AppSync/jobs are external principals. |
| `schema-integrity` | `COMPOSABLE` | Key/index schemas, conditions and application validation; non-key document shape remains flexible. |
| `transactional-integrity` | `NATIVE` | DynamoDB transactions and conditional writes with documented limits. |
| `resource-governance` | `NATIVE` | Capacity modes/quotas and bounded service operations, supplemented by application cost controls. |
| `replication-cdc-authorization` | `NATIVE` | Streams and global-table service paths have separately assessable IAM/service roles. |
| `history-authorization` | `COMPOSABLE` | PITR/backups/Streams are separately authorized but not a general record-history query plane. |
| `backup-policy-portability` | `COMPOSABLE` | Restore creates a new table; tags, policies, streams and controls require rebuilding. |
| `security-audit` | `NATIVE` | CloudTrail supports management/data events; data selectors are not on by default. |
| `policy-catalog-introspection` | `NATIVE` | IAM/resource policies, table/index/stream/backup configuration and CloudTrail state are queryable. |

## Resource and tenant model

The native resource hierarchy relevant here is account/Region -> table ->
index/stream/backup/export, with IAM actions and condition keys controlling
requests. The application tenant unit is commonly a table, partition-key
prefix/value, or item attribute. A `tenantId` attribute that is neither in the
leading partition key nor enforced by an independent boundary is
application-only.

Inventory every alternate key schema. A GSI may project sensitive attributes
and use a different leading key, so a table policy that assumes the base
partition shape can be incomplete. Treat global-table replicas and restored
tables as distinct resource ARNs.

## Effective privilege semantics

Compute effective access using identity policies, resource-based table
policies, permissions boundaries, session policies, SCPs/RCPs, VPC endpoint
policies, service-linked roles, resource tags/ABAC, and explicit denies. Include
role assumption and service-account/web-identity claim substitution. Defer the
generic IAM candidate to `cloud-and-iac`; attach this adapter's concrete item,
index, stream, export, or restore consequence as evidence.

For fine-grained access, evaluate:

- `dynamodb:LeadingKeys` with the required `ForAllValues` set operator,
  including every batch/transaction key;
- `dynamodb:Attributes` plus `dynamodb:Select` and `dynamodb:ReturnValues` so a
  caller cannot request omitted attributes through a different action;
- exact `Action` and `Resource` coverage for table plus `/index/*`, stream,
  backup, export, and restored resources;
- tag/ABAC behavior on backups and restores; native DynamoDB backups do not
  preserve tags on a restored table.

Do not infer deny behavior from one policy document; use IAM policy evaluation
and, where authorized, a real assumed-role denial proof.

## Native versus application-only authorization

Label each path:

- `native-iam-item`: IAM conditions bind allowed leading keys/attributes;
- `native-resource`: table/index/stream resource scoping only;
- `application-only`: a broad role supplies `KeyConditionExpression`, filter,
  or tenant key in code;
- `hybrid`, `none`, or `unknown`.

`FilterExpression` is not an authorization boundary: DynamoDB reads candidate
items before applying it, it consumes capacity, and a caller with the same
credential can omit it. Prefer a tenant value in the partition key plus
`LeadingKeys`, or a stronger table/account boundary, when a native per-tenant
principal is feasible.

PartiQL/Expression construction from untrusted input belongs to `web-and-api`.
This adapter owns the capability and key-condition bypass consequence, not a
duplicate injection finding.

## Alternate paths and administrative surfaces

Exercise:

- `GetItem`, `BatchGetItem`, `Query`, `Scan`, PartiQL read, transactional read,
  pagination, projection, and all GSIs/LSIs;
- put/update/delete, condition expressions, upsert semantics, batch writes,
  transactions, PartiQL mutations, and `ReturnValues`;
- Streams/GetRecords, Lambda/event-source mappings, DAX, AppSync, export to S3,
  import from S3, PITR/on-demand/AWS Backup, and global-table replicas;
- table/index/stream/policy/TTL/PITR/capacity changes, restore, export, replica
  management, and `iam:PassRole` involved in adjacent services.

Treat `Scan`, wildcard table/index ARNs, `ExportTableToPointInTime`,
`RestoreTable*`, `PutResourcePolicy`, `UpdateTable`, `UpdateContinuousBackups`,
global-table changes, and stream access as privileged even when the principal
cannot call `GetItem`.

## Integrity, consistency, and availability

Review conditional writes, idempotency tokens, transactions, item and
transaction size limits, uniqueness patterns, and version attributes. DynamoDB
provides read-committed isolation; eventual reads are default. Strongly
consistent reads are available only on tables and LSIs, not GSIs or Streams.
Global tables require their configured MREC/MRSC semantics to be recorded, not
an assumed universal guarantee.

Attack:

- stale GSI, stream, DAX, or MREC authorization/uniqueness decisions;
- missing conditions on update/delete and overwrite-by-`PutItem`;
- cross-tenant items hidden in a batch/transaction;
- hot tenant/partition keys, unbounded scans, pagination omission, large
  projections/items, retry storms, and expensive transactional/strong reads;
- GSI write throttling, stream consumer lag, DAX staleness, on-demand/account
  quotas, and denial-of-wallet through high-volume reads/writes/exports.

Application filters that hide an item after a read do not prevent capacity or
timing side channels.

## Streams, replicas, export, backup, and restore

Streams expose keys plus configured old/new images and are eventually
consistent. Scope stream consumers, Lambda destinations, dead-letter paths,
event replays, and retention independently. A consumer role can become a bulk
reader even if it has no table read action.

Inventory every global replica, export bucket/object, PITR/on-demand/AWS Backup
recovery point, imported/restored table, and DAX cluster. Restore creates a new
table/ARN. Prove resource policies, tags, IAM references, alarms, streams, TTL,
PITR, encryption handoff, and deletion protection are deliberately recreated
before the restored table receives traffic. Native backup restores do not
preserve tags, so tag-based authorization can silently change.

## Audit and attribution

CloudTrail records management events, but DynamoDB item operations and Streams
reads are data events that require explicit selectors; data events are not
logged by default on trails/event stores. TTL service deletions are not
DynamoDB CloudTrail data-plane events. Verify coverage for classic API and
PartiQL, table and stream resource types, read and write, every Region, and
service-initiated-event filtering.

For allowed and denied cross-tenant attempts, prove assumed-role/session
identity, source, table/index/stream, action, outcome, and end-user correlation.
Web-identity sessions should carry a stable attributable subject without
placing sensitive tokens in logs.

## Deletion, TTL, and copies

TTL expiry is asynchronous and expired items can remain readable until
deleted. Verify the TTL attribute is an epoch-seconds Number, is enabled on the
correct table, cannot be removed or extended by an unauthorized caller, and
that stream/replica behavior is expected. Global replicas, Streams consumers,
DAX, exports, backups/PITR, S3 destinations, search/analytics sinks, and
restored tables retain separate copies.

The legal retention judgement belongs to `privacy-and-data-protection`; supply
the actual expiry and propagation evidence here.

## Unsupported or unproven guarantees

Do not claim:

- that an item `FilterExpression` is authorization;
- strong reads from GSIs or Streams;
- universal strong consistency across global tables;
- that base-table leading-key conditions automatically secure differently
  keyed indexes;
- CloudTrail data-event coverage by default;
- tag/ABAC continuity after native backup restore;
- immediate TTL erasure or TTL CloudTrail attribution;
- IAM equivalence from DynamoDB Local.

Absence of item-level IAM is not automatically a finding when table-per-tenant
or a tested service boundary is the declared isolation design.

## Rule anchors

- `db.authorization.dynamodb.leading-keys-boundary` evaluates the effective IAM
  identity, all applicable allow and deny policy layers, the exact operation
  and index path, and `dynamodb:LeadingKeys`/attribute conditions. A condition
  on one call shape cannot clear unbounded scans, indexes, streams, exports, or
  administrative paths.

## Static discovery sweeps

| Evidence | Review |
|---|---|
| CloudFormation/CDK/Terraform | table/index ARNs, resource policies, PITR, TTL, streams, global replicas, capacity, deletion protection |
| IAM JSON | wildcard actions/resources, `LeadingKeys` + `ForAllValues`, `Attributes`, `Select`, `ReturnValues`, index/stream/export/restore coverage |
| key builders/models | tenant in partition key, delimiter ambiguity, owner mutation, GSI alternate keys, conditional writes |
| `Query`/`Scan`/PartiQL | application-only filters, pagination, projections, result/capacity bounds; route injection to `web-and-api` |
| batch/transaction calls | every key constrained, conditions, failure/idempotency behavior |
| Streams/Lambda/DAX/AppSync | consumer identity, image exposure, destinations, caches, replays |
| backup/export/import/restore | new ARN, tags/policies, S3 access, control recreation and pre-traffic gate |
| CloudTrail selectors | DynamoDB table and stream data events, Regions, reads/writes, retention and attribution |

## Proof and conformance matrix

Use tenants A/B, an A-scoped principal/session, broad application service role,
stream consumer, migration role, and admin control:

| Path | Required negative proof |
|---|---|
| Get/BatchGet/Query/Scan/PartiQL | A cannot read or infer B through base table or any index |
| Put/Update/Delete/ReturnValues | A cannot create for B, change tenant key, mutate/delete B, or receive B's old value |
| batch/transaction | one B key causes denial/atomic failure as declared |
| GSI/LSI/DAX | alternate key/cache cannot bypass the tenant boundary |
| Streams/Lambda replay | A consumer cannot obtain unauthorized images |
| export/backup/restore/global replica | bulk and restored paths preserve declared authorization |
| table/policy/TTL/PITR admin | runtime principal is denied security-changing actions |
| consistency | stale paths cannot authorize a forbidden business action |
| audit | allowed and denied item/stream actions are captured and attributable |
| availability | representative scan/hot-key/retry attack meets declared limits |

## Known false positives

- A wildcard index ARN can be appropriate for a role that legitimately queries
  every index on one scoped table; evaluate item conditions and new-index drift.
- A broad Lambda role is not a tenant-isolation defect if the function is the
  unbypassable trusted enforcement plane and behavioral tests pass; retain its
  blast radius.
- An eventually consistent read is not a finding unless the application uses
  freshness for a security or integrity decision it cannot safely retry.
- A disabled TTL is not a defect for data without an expiry requirement.
- Resource-based policy absence is not a defect when identity policies and
  organization controls establish the intended boundary.

## Fixture concept

Provision an isolated table with tenants A/B, a base composite key, a
differently keyed GSI, stream old/new images, TTL, PITR, and CloudTrail data
selectors. The vulnerable policy omits `ForAllValues`, constrains only the base
table, relies on a filter, allows broad `ReturnValues`, and logs only management
events. The clean policy binds leading keys and attributes across all required
actions/resources, constrains alternate paths, and uses conditions for writes.
Exercise DynamoDB Local for fast logic tests and a disposable AWS account for
IAM, CloudTrail, Streams, backup/restore, and consistency proof.

## Official sources

Verified 2026-07-28:

- https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/specifying-conditions.html
- https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.ReadConsistency.html
- https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.CoreComponents.html
- https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/TTL.html
- https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Streams.html
- https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Backup-and-Restore.html
- https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/logging-using-cloudtrail.html
