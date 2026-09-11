# Cloud Firestore adapter

Adapter ID: `firestore`

Deployment variants: `firestore-native`, `firestore-enterprise`,
`firestore-emulator`

Verified: `2026-07-28`

This adapter covers Cloud Firestore Native/Standard/Enterprise modes as
identified by the repository and deployment evidence. It does not cover
Realtime Database rules. It applies through `database-and-data-stores` and owns
no topics.

## Detect and profile

Activate on `firebase-admin` or Firestore client libraries, `firestore.rules`,
`firestore.indexes.json`, `firebase.json`, Firestore Terraform/gcloud
resources, emulator configuration, or canonical Firestore resource names.
Record:

- project, database ID, location, edition/mode, point-in-time recovery, backup,
  clone, TTL, and CMEK settings where applicable;
- web/mobile SDK, server SDK, REST/RPC, Admin SDK, Cloud Functions/Eventarc,
  import/export, Dataflow, extension, and analytics paths;
- Firebase Auth/App Check principals versus Google IAM service accounts and
  workload identities;
- ruleset release/version, emulator use, collection groups, listeners/offline
  persistence, indexes, and every derived copy.

An emulator result is supporting evidence only. Re-run critical rules against
the deployed ruleset or mark production semantics `NOT ASSESSED`.

Emit the contract's required `store_context`: `store_id`, `family`, `engine`,
`engine_version`, `deployment_variant`, `adapter_id`, `detection_evidence[]`,
and `confidence`. Keep `data_classes`, `tenant_unit`, `enforcement_plane`,
`principal_paths[]`, and `copy_paths[]` in the full store profile.

## Capability declaration

| Capability ID | Value | Conditions |
|---|---|---|
| `principal-authentication` | `NATIVE` | Firebase Auth/App Check context for client SDKs; Google IAM identity for server paths. |
| `role-and-object-grants` | `NATIVE` | IAM grants database/project resources; Security Rules authorize client document paths. |
| `record-read-authorization` | `COMPOSABLE` | Native client Rules are document-aware; server SDKs bypass them and need IAM/application closure. |
| `record-write-authorization` | `COMPOSABLE` | Rules can validate client creates/updates/deletes; server paths need separate enforcement. |
| `column-or-property-authorization` | `COMPOSABLE` | Rules can validate changed fields but cannot return a field-masked document; split sensitive documents. |
| `tenant-session-context` | `COMPOSABLE` | Auth claims/path bindings are native to Rules; server identities need trusted application context. |
| `stored-code-execution-context` | `EXTERNAL_ONLY` | Functions, extensions and triggers execute as external service principals. |
| `schema-integrity` | `COMPOSABLE` | Rules validate client writes; server writes bypass Rules. |
| `transactional-integrity` | `NATIVE` | Transactions/batches are atomic with documented retry and contention semantics. |
| `resource-governance` | `COMPOSABLE` | Service quotas, Rules query constraints, indexes and application/budget bounds. |
| `replication-cdc-authorization` | `COMPOSABLE` | Listeners use Rules; triggers/events use independently authorized service identities. |
| `history-authorization` | `COMPOSABLE` | PITR/backup/history are separately controlled through Google Cloud IAM, not client Rules. |
| `backup-policy-portability` | `COMPOSABLE` | Documents, Rules, IAM, indexes, TTL, triggers and audit must be compared separately. |
| `security-audit` | `NATIVE` | Cloud Audit Logs support exists; Data Access enablement/coverage must be proved. |
| `policy-catalog-introspection` | `COMPOSABLE` | Deployed Rules/IAM/index/TTL state can be enumerated but require separate planes. |

## Resource and tenant model

The data hierarchy is project -> database -> alternating collection/document
paths, with collection-group queries spanning identically named collections.
Tenant isolation may be database-, collection-, path-, or field-based. Record
the actual unit separately for nested subcollections, collection groups,
exports, listeners, and server-side processing.

Mobile/web requests are authorized by Security Rules. Server client libraries
and privileged REST/RPC use IAM and bypass Firestore Security Rules. Therefore
“rules protect this collection” is never sufficient until every access path is
classified.

## Effective privilege semantics

For client rules, evaluate the deployed ruleset as a whole. Overlapping
`match` statements are not deny-overrides: access is allowed if any applicable
`allow` expression is true. Resolve recursive wildcards using the declared
rules version. Separate `get` from `list`, and `create`, `update`, and `delete`;
`read` or `write` shorthand deliberately combines operations.

For server paths, compute Google IAM effective access including project,
folder, and organization inheritance, groups, service-account impersonation,
conditional bindings, and deny/organization policies. Route generic IAM
analysis to `cloud-and-iac`, while this adapter proves Firestore data-plane
actions and tenant consequences.

Never treat Firebase Auth claims, App Check, or client rules as constraints on
an Admin SDK/service-account request.

## Native versus application-only authorization

Label each path:

- `native-rules`: Firebase Auth/App Check context evaluated by Firestore Rules;
- `native-iam`: Google IAM authorizes a server identity at supported resource
  granularity;
- `application-only`: a broad server identity relies on code to select tenant
  paths or predicates;
- `hybrid`, `none`, or `unknown`.

Rules can enforce path/field ownership and validate data for client calls.
They are not query filters: a query whose potential result set can include
forbidden documents fails entirely. The application query must carry
constraints that the rules can prove.

For application-only server access, attack raw Admin SDK handles, converters,
bulk writers, transactions, jobs, functions, import/export, and test utilities.
Generic injection into APIs or query builders belongs to `web-and-api`.

## Alternate paths and administrative surfaces

Exercise:

- single get, list/query, collection-group query, aggregation query, listener,
  offline cache/bundle, and REST/RPC variants;
- set/create/update with and without merge, transforms, batch/bulk writes,
  transactions, recursive delete, and delete;
- Admin SDK/server libraries, Cloud Functions and Eventarc triggers,
  extensions, scheduled jobs, exports/imports, backups/clones, PITR, and lower
  environments;
- rules/index deployment, IAM changes, database creation/deletion, TTL
  configuration, and service-account impersonation.

Test that field allowlists use `diff().affectedKeys()` or equivalent logic and
that a caller cannot create or mutate ownership/role/tenant fields. Rules
helper reads have per-request limits; a design that fails closed only by
exceeding the limit is not robust.

## Integrity, consistency, and availability

Firestore transactions and batched writes are atomic when correctly used.
Transactions can retry, so callbacks must be idempotent and side-effect-free.
Inspect `getAfter()` rules for multi-document invariants, server/client
concurrency mode, contention, write hotspots, and retries.

Attack:

- document-ID/path confusion and orphaned nested subcollections;
- partial updates, merge writes, transforms, and tenant/owner-field mutation;
- high fan-out indexes, sequential IDs/timestamps, hot documents, unbounded
  listeners, collection-group queries, aggregation queries, and recursive
  rules reads;
- large batches, retry-amplified side effects, export/restore cost, and
  unbounded billed reads/writes.

Resource abuse and denial-of-wallet findings live here when caused by database
access shape; general cloud budgets/quotas remain with `cloud-and-iac`.

## Replication, events, backups, and restore

Inventory snapshot listeners, triggers, extensions, ETL/export pipelines,
backups, PITR, clones, and cross-project transfers as alternate copies. A
trigger runs under its service identity, not the client rules context; validate
event provenance, idempotency, and destination authorization.

Restore/clone proof must show the destination project/database IAM, ruleset,
indexes, TTL policies, triggers, App Check assumptions, and network/perimeter
controls before use. Do not infer that restoring documents restores rules or
IAM.

## Audit and attribution

Classify Cloud Audit Logs by Admin Activity and Data Access, and verify actual
coverage for document reads/writes, rules/IAM changes, exports, restores, and
service-account impersonation. Data Access logs can require explicit
enablement and incur cost. Firebase rules evaluation and App Check telemetry do
not replace a durable application actor audit trail.

For allowed and denied cross-tenant attempts, prove principal, service-account
delegation chain where available, resource/database, method, result, and an
end-user correlation value. A single server service account otherwise
attributes every customer action to the same principal.

## Deletion, TTL, and copies

Deleting a document does not delete its subcollections. Firestore TTL deletion
is not instantaneous (typically within 24 hours), is not transactional across
documents, and also does not delete subcollections. Expired documents remain
queryable until processed.

Offboarding must enumerate nested subcollections, collection groups, listener
caches, exports, backups/PITR/clones, search/vector/analytics destinations, and
trigger-created copies. Route legal retention conclusions to
`privacy-and-data-protection`; this adapter supplies observed deletion bounds.

## Unsupported or unproven guarantees

Do not claim:

- that Security Rules constrain Admin/server SDKs;
- that rules filter a query result after execution;
- deny precedence between overlapping `match` blocks;
- cascading document deletion;
- immediate or transactional TTL erasure;
- production equivalence from emulator-only tests;
- restored rules/IAM merely because documents, indexes, or backups exist;
- end-user attribution from a pooled service account without propagation.

## Rule anchors

- `db.authorization.firestore.rules-query-boundary` evaluates the deployed
  ruleset for the exact authenticated principal, document path, query
  constraints, read/write operation, and Admin SDK bypass path. A rule that
  filters an individual document cannot clear a query the rules engine cannot
  prove safe.

## Static discovery sweeps

| Evidence | Review |
|---|---|
| `firestore.rules` | catch-all allows, auth-only rules, overlapping matches, recursive wildcards/version, get/list split, create/update/delete split |
| rule conditions | path tenant binding, immutable owner/tenant/role fields, field allowlists, `getAfter`, custom-claim trust, rule access-call limits |
| `firebase.json`, deploy workflows | correct project/database/rules target, emulator-only configuration, drift and privileged deploy identity |
| client query code | constraints matching rules, collection-group scope, listeners/aggregations, caller-controlled paths |
| `firebase-admin`, server SDKs, REST/RPC | rule bypass, IAM principal, application-only isolation, raw handles, bulk/export paths |
| indexes/TTL config | sensitive projected fields, hotspots, TTL gaps, subcollection cascades |
| functions/triggers/extensions | service identity, recursion/idempotency, alternate writes and downstream copies |

## Proof and conformance matrix

Use authenticated clients for tenants A/B, an unauthenticated client, the real
server identity, and an administrative control:

| Path | Required negative proof |
|---|---|
| get and list/query | A cannot read B; an overbroad query fails, not partially filters |
| collection-group/aggregation/listener | alternate read forms cannot observe B |
| create/set/merge/update/transform | A cannot create for B or change tenant/owner/role |
| batch/transaction/delete | one forbidden operation fails atomically as declared; A cannot delete B |
| Admin/server SDK | rules bypass is acknowledged and application/IAM boundary blocks B |
| trigger/export/backup/clone | copied data and invocation identities preserve declared scope |
| deploy/restore | correct rules, IAM, indexes, TTL, and audit are active before traffic |
| audit | allowed and denied attempts are attributable to service and end user |
| TTL/offboarding | parent, subcollections, derived stores, and declared copies converge |

Run client-rule cases in the emulator for fast iteration, then run a bounded
production-semantics canary against an isolated project/database when
authorized.

## Known false positives

- A broad server identity is not automatically a finding when it is isolated
  behind an unbypassable service boundary whose tenant tests pass; record the
  residual blast radius.
- `allow read: if request.auth != null` may be intentional for a genuinely
  user-global collection; validate classification before reporting it.
- A catch-all deny does not repair an overlapping allow, but its presence is
  not itself a defect.
- Test-mode rules in a file are not production exposure if deployment evidence
  proves another version is active; report drift/unknown when the active
  release cannot be established.
- App Check mitigates non-genuine clients; it is not user authorization.

## Fixture concept

Build an emulator fixture with two tenant path trees, nested subcollections, a
collection-group query, mutable owner field, batched write, listener, Admin SDK
job, trigger, and TTL field. The vulnerable rules use auth-only/catch-all
allows, omit field immutability, and assume parent deletion cascades. The clean
variant separates get/list and write operations, binds paths and immutable
fields, validates atomic invariants, and explicitly protects the Admin path.
Add deployment assertions for the ruleset hash, IAM identity, logging, and
offboarding inventory.

## Official sources

Verified 2026-07-28:

- https://firebase.google.com/docs/firestore/security/overview
- https://firebase.google.com/docs/firestore/security/rules-query
- https://firebase.google.com/docs/firestore/security/rules-structure
- https://firebase.google.com/docs/firestore/security/rules-conditions
- https://firebase.google.com/docs/firestore/manage-data/transactions
- https://firebase.google.com/docs/firestore/transaction-data-contention
- https://firebase.google.com/docs/firestore/data-model
- https://firebase.google.com/docs/firestore/ttl
- https://cloud.google.com/firestore/native/docs/audit-logging
