# PostgreSQL and Supabase adapter

Adapter ID: `postgresql`

Deployment variants: `postgresql-self-managed`, `postgresql-managed`,
`supabase`

Verified: `2026-07-28`

This adapter covers PostgreSQL semantics. Supabase is a deployment variant, not
a synonym: its exposed schemas, API roles, JWT helpers, dashboard defaults, and
service-role path add enforcement routes that plain PostgreSQL does not have.
PostgREST used outside Supabase receives a separate profile unless its role and
JWT mapping are proved equivalent.

## Engine, version, and deployment detection

Strong signals:

- exact `postgres:<version>` image, server package, or committed output from
  `server_version`/`server_version_num`;
- PostgreSQL provider configuration naming an engine version;
- `PG_VERSION` from a repository-owned data image;
- PostgreSQL catalog queries or dialect features in migrations.

Supabase signals:

- `supabase/config.toml`, `supabase/migrations/`, or Supabase CLI project files;
- `@supabase/supabase-js` plus a Supabase project configuration;
- `auth.uid()`, `auth.jwt()`, `anon`, `authenticated`, `service_role`, or
  Supabase schema conventions in migrations.

Weak signals such as `pg`, `psycopg`, `asyncpg`, JDBC, Npgsql, Prisma's
`provider = "postgresql"`, or a `DATABASE_URL` activate inventory only. They do
not establish the server version, deployment, exposed schema, or Supabase use.
An unpinned `postgres:latest` has `engine_version.precision: unknown`.

RLS exists in PostgreSQL 9.5 and later. Version-gated behavior such as
security-invoker views or logical-replication row filters is `NOT_ASSESSED`
until the deployed major version is established. A Supabase marketing product
version is not a PostgreSQL server version.

## Capability declaration

| Capability ID | Value | Conditions |
|---|---|---|
| `principal-authentication` | `NATIVE` | PostgreSQL roles; managed identity/auth proxies are additional deployment paths. |
| `role-and-object-grants` | `NATIVE` | Database, schema, relation, sequence, routine, type, and column privileges plus role membership. |
| `record-read-authorization` | `NATIVE` | RLS enabled with complete `SELECT`/`ALL` policies on every protected relation. |
| `record-write-authorization` | `NATIVE` | Command policies and correct `USING`/`WITH CHECK`; tenant-key mutation is tested separately. |
| `column-or-property-authorization` | `NATIVE` | Column grants and safe views; neither is row masking by itself. |
| `tenant-session-context` | `COMPOSABLE` | Trusted transaction-local GUC or verified JWT helper; unset and pool-reuse behavior must fail closed. |
| `stored-code-execution-context` | `NATIVE` | `SECURITY INVOKER`/`SECURITY DEFINER`, ownership, routine grants, and `search_path`. |
| `schema-integrity` | `NATIVE` | Constraints, domains, generated columns, and triggers; constraint state is inspected. |
| `transactional-integrity` | `NATIVE` | Transactions, row/table/advisory locks, and selectable isolation levels. |
| `resource-governance` | `COMPOSABLE` | Timeouts, role/database connection limits, memory settings, and provider quotas. |
| `replication-cdc-authorization` | `COMPOSABLE` | Replication roles, publications, version-gated row filters/column lists, and subscriber access all assessed. |
| `history-authorization` | `EXTERNAL_ONLY` | Core PostgreSQL has no general temporal authorization primitive; history tables/extensions need independent policy. |
| `backup-policy-portability` | `COMPOSABLE` | Relation policy can be dumped, but cluster roles and other globals require a separate supported path. |
| `security-audit` | `COMPOSABLE` | Core logging plus pgaudit/provider facilities and protected collection; configuration is deployment-specific. |
| `policy-catalog-introspection` | `NATIVE` | `pg_policy`, `pg_policies`, `pg_roles`, ACL catalogs, publications, routines, and event triggers. |

## Principal and grant model

PostgreSQL roles are both users and groups. Compute effective authority from:

- `LOGIN`, `SUPERUSER`, `BYPASSRLS`, `CREATEDB`, `CREATEROLE`, `REPLICATION`,
  role membership, inheritance, and `SET ROLE`;
- database `CONNECT`/`TEMP`, schema `USAGE`/`CREATE`, relation and column ACLs,
  sequence privileges, routine `EXECUTE`, and ownership;
- grants to `PUBLIC`;
- default privileges for the role that actually creates future objects;
- managed-service reserved roles and identity/proxy layers.

Do not read only explicit grants on a table. Schema creation authority, object
ownership, default privileges, inherited membership, routine execution, and an
owner-capable migration role can each expand the graph. Runtime, migrator,
owner, replication, backup, and human-query roles should be distinct. If they
are not, record the collision.

Supabase adds `anon`, `authenticated`, `service_role`, dashboard/CLI
administrators, and PostgREST role switching. Map each API key type to the
database role it can become. Never copy or decode a live key merely to populate
the profile.

## Native authorization and tenant controls

RLS is default-deny only after `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` and
only for actors subject to it. Policies are command- and role-specific:

- `USING` controls which existing rows are visible for read, update, and
  delete;
- `WITH CHECK` controls rows introduced by insert or update;
- permissive policies combine with `OR`; restrictive policies combine with
  `AND`;
- table owners normally bypass RLS; `FORCE ROW LEVEL SECURITY` makes an owner
  subject in ordinary operation, but never constrains a superuser or a role
  with `BYPASSRLS`;
- RLS applies per relation. Direct access to a partition, history table,
  materialized view, or copied relation is a separate path.

`db.authorization.postgresql.rls-policy-completeness` requires all protected
relations and operations to be mapped. `db.authorization.postgresql.rls-bypass`
computes whether any deployed runtime/reporting path can become owner,
superuser, or `BYPASSRLS`.

A custom setting such as `app.tenant_id` is untrusted unless only a trusted
entry point can set it. Establish it inside every transaction with
transaction-local scope, reject unset/null/malformed values, and prove a pooled
connection cannot retain the previous tenant. A session GUC is context, not
authorization by itself.

For Supabase:

- RLS must be enabled on every table in an exposed schema. A table created by
  raw SQL or migration must not be assumed to inherit dashboard defaults.
- `service_role` bypasses RLS and must never be a browser/mobile/runtime-user
  credential.
- `auth.uid()` is null for an unauthenticated request; the policy must make the
  intended unauthenticated outcome explicit.
- authorization claims must not come from user-editable JWT metadata.
- views are a separate path. On supported PostgreSQL versions,
  `security_invoker = true` can make a view check the caller's permissions and
  policies; otherwise the adapter verifies ownership, grants, and underlying
  policy rather than assuming the view is filtered.

Column grants and views can compose a field boundary only when the caller lacks
base-table access and cannot invoke another definer routine that returns the
field.

## Bypasses and alternate paths

Inventory and test:

- superusers, `BYPASSRLS`, relation owners, owner-capable role membership, and
  `SET ROLE`;
- `SECURITY DEFINER` routines, unsafe views, event triggers, extensions,
  foreign data wrappers, and untrusted procedural languages;
- `COPY`, large objects, materialized views, generated exports, and direct
  partition access;
- logical/physical replication, publications, replication slots, WAL access,
  backups, and restored copies;
- Supabase `service_role`, administrative API, SQL editor, exposed schemas, and
  Edge Functions holding privileged credentials;
- referential-integrity checks and error/timing behavior that can disclose the
  existence of otherwise invisible values.

The ability to alter/disable policy is an administrative bypass even if ordinary
queries are filtered. Report the reachable runtime path, not the mere existence
of an administrator.

## Stored code and execution context

Functions and procedures execute as invoker unless declared `SECURITY DEFINER`.
For every definer routine:

- identify the owner and its effective roles;
- revoke unintended `PUBLIC EXECUTE` and grant only the intended callers;
- pin `search_path` to trusted schemas and put `pg_temp` last or exclude it;
- schema-qualify security-sensitive objects and operators;
- reject dynamic object-name construction or hand injection to `web-and-api`;
- prove every returned row and write is authorized for the invoker;
- inspect nested definer calls, triggers, event triggers, language handlers, and
  extensions.

Only superusers can mark a function `LEAKPROOF`; treat a custom leakproof
function in a policy path as high-risk evidence requiring behavioral proof.
Routine ownership changes and `CREATE OR REPLACE` migrations are security
changes, not implementation detail.

Rule anchors:

- `db.execution.postgresql.security-definer-authority`
- `db.execution.postgresql.security-definer-search-path`
- `db.authorization.postgresql.routine-execute-grants`

## Migration and security drift

Diff the effective catalogs after a fresh install, every supported upgrade
path, rollback, and restore. Look for:

- a new exposed table without RLS or without policies for all used commands;
- `DISABLE ROW LEVEL SECURITY`, removed `FORCE`, broadened policy roles, or a
  permissive policy that ORs around a restrictive intent;
- a tenant column becoming nullable, mutable, or absent from a uniqueness key;
- a partition, view, materialized view, function, or replica created without
  equivalent controls;
- runtime ownership or broad default privileges introduced by the migration
  runner;
- definer owner/search-path changes;
- Supabase schema exposure or API grants changing independently of policy.

SQL text order matters: a migration that grants API access before enabling RLS
has an exposure window when deployed non-atomically. A static migration scan
cannot prove deployed drift; it reports configuration-as-written and lists live
catalog comparison as unassessed.

Rule anchors:

- `db.migration.postgresql.new-relation-policy-drift`
- `db.migration.postgresql.runtime-ddl-separation`

## Transactions, concurrency, and integrity

Inventory primary keys, tenant-qualified unique constraints, foreign keys,
checks, exclusion constraints, deferred constraints, triggers, and isolation
assumptions. Verify:

- cross-tenant identifiers cannot collide where the application assumes global
  uniqueness, and globally unique identifiers do not accidentally authorize;
- a tenant key cannot be changed through update, upsert, writable view, bulk
  copy, or definer routine;
- read-check-write workflows use a transaction and an appropriate lock or
  isolation level;
- retry behavior does not replay a mutation under stale tenant context;
- constraints and triggers behave identically through direct SQL and API paths.

PostgreSQL's default `READ COMMITTED` does not make a multi-statement business
invariant atomic. The database adapter records isolation and constraint facts;
the business-logic lens owns workflow conclusions.

## CDC, replication, and history

Map physical replicas, logical publications/subscriptions, replication slots,
provider CDC, audit/event pipelines, and any application history tables.
Logical publication row filters and column lists are version- and
operation-sensitive; they are data-selection controls, not subscriber
authorization. Verify initial synchronization as well as ongoing changes,
updates that move rows into/out of a filter, partition publication behavior,
and subscriber grants.

RLS on the primary is not proof that WAL, a replication slot, a subscriber
table, a temporal extension, or an audit sink is tenant-filtered. A
replication-capable principal and a runtime principal are separate actors in the
conformance matrix.

Application history tables are ordinary relations. Their owners, grants, RLS
state, policies, triggers, and alternate readers must be closed independently
from the current-state table.

Rule anchors:

- `db.copy.postgresql.replication-policy-gap`
- `db.history.postgresql.audit-table-closure`

## Backup and restore

Identify physical backup, `pg_dump`, `pg_dumpall`, provider snapshots, PITR,
and clone workflows. A relation dump can carry table policy definitions, but a
single-database dump does not by itself preserve cluster-global roles and
tablespaces. Verify the documented companion path rather than assuming grants
will resolve after restore.

The restore oracle compares:

- owners, role memberships, attributes, ACLs, and default privileges;
- RLS enable/force flags and policy definitions;
- routines, owners, `prosecdef`, configuration, event triggers, and extensions;
- publications/subscriptions and audit/logging configuration;
- data canaries and all copy-path readers.

TDE/storage encryption, snapshot sharing, retention, and key restore remain
cloud/crypto/privacy findings.

Tenant-scoped client export must execute under the tenant's effective
principal and policy. Server-side `COPY ... TO file` and broader export roles
are separate privileged paths; a filtered application query does not constrain
them automatically.

Rule anchors:

- `db.restore.postgresql.global-principal-gap`
- `db.copy.postgresql.export-rls-boundary`

## Audit and attribution

Core statement/connection logging is configurable and can be too broad, too
narrow, or unsafe for sensitive parameters. pgaudit and provider audit products
add coverage but remain deployment-specific. Establish:

- successful and denied reads/writes/admin changes that must be recorded;
- session user, current/effective role, application actor, tenant, target,
  operation, and outcome;
- whether a pooled service identity erases end-user attribution;
- who can disable, alter, read, or delete audit output;
- whether definer routines and replication activity preserve both invoker and
  effective authority.

Logging every statement is not automatically a clean result: it can leak
secrets or personal data and can still omit object-level audit semantics.

## Availability and resource governance

Assess `statement_timeout`, `lock_timeout`,
`idle_in_transaction_session_timeout`, role/database connection limits,
pool bounds, `work_mem`, temp-file limits, autovacuum health, and managed
provider quotas. Exercise bounded adversarial forms:

- unindexed tenant-policy predicates and per-row policy functions;
- expensive aggregates, regexes, recursive CTEs, JSON operations, sorts, and
  spill;
- lock queues, idle transactions, connection exhaustion, and replication-slot
  WAL retention;
- extension, trigger, and definer-function amplification.

The absence of one suggested knob is not a finding without a reachable
untrusted workload and a stated availability budget.

## Unsupported guarantees and NOT ASSESSED cases

- RLS cannot constrain superusers or `BYPASSRLS`, and ordinary table ownership
  bypasses it unless forced.
- Core PostgreSQL does not provide a universal, immutable end-user audit trail
  or general temporal-history authorization layer.
- A policy on the primary does not automatically protect backups, WAL,
  subscribers, exported files, views, materialized views, or derived stores.
- A Supabase `service_role` request is not made safe by table RLS.
- A custom GUC or JWT claim is not trustworthy merely because a policy reads
  it.
- Native column grants are not dynamic data masking.

When the system needs one of these guarantees, require and test an explicit
alternative. Do not file "PostgreSQL lacks X" without the unmet system claim.

## Static discovery sweeps

Every hit is a candidate to read. Every command includes an explicit path:

```bash
rg -n --hidden 'CREATE\s+TABLE|ALTER\s+TABLE|CREATE\s+(MATERIALIZED\s+)?VIEW|CREATE\s+POLICY' .
rg -n --hidden 'ENABLE\s+ROW\s+LEVEL\s+SECURITY|DISABLE\s+ROW\s+LEVEL\s+SECURITY|FORCE\s+ROW\s+LEVEL\s+SECURITY|NO\s+FORCE\s+ROW\s+LEVEL\s+SECURITY' .
rg -n --hidden 'USING\s*\(|WITH\s+CHECK\s*\(|AS\s+(PERMISSIVE|RESTRICTIVE)|TO\s+(PUBLIC|anon|authenticated|service_role)' .
rg -n --hidden 'SUPERUSER|BYPASSRLS|SET\s+ROLE|ALTER\s+(TABLE|FUNCTION|PROCEDURE).*\s+OWNER\s+TO' .
rg -n --hidden 'SECURITY\s+DEFINER|SECURITY\s+INVOKER|SET\s+search_path|GRANT\s+EXECUTE|REVOKE\s+EXECUTE' .
rg -n --hidden 'current_setting\s*\(|set_config\s*\(|SET\s+LOCAL|auth\.uid\s*\(|auth\.jwt\s*\(' .
rg -n --hidden 'service_role|SUPABASE_SERVICE_ROLE|supabaseAdmin|exposed_schemas|extra_search_path' .
rg -n --hidden 'CREATE\s+PUBLICATION|CREATE\s+SUBSCRIPTION|REPLICATION\s+SLOT|pg_dump|pg_dumpall|pg_basebackup' .
rg -n --hidden 'statement_timeout|lock_timeout|idle_in_transaction_session_timeout|work_mem|max_connections|CONNECTION\s+LIMIT' .
```

Do not grep for `CREATE TABLE` and conclude RLS is absent. Pair parsed relation
creation with later alterations and final catalog state. Generated migrations,
conditional SQL, extensions, and provider-side state remain named gaps.

## Proof and conformance recipe

Use the contract matrix with a repository-started ephemeral PostgreSQL at T1,
or a user-approved loopback instance at T2.

1. Record `server_version_num`, deployment variant, role attributes,
   memberships, relation owners/ACLs, RLS flags, policies, routines,
   publications, and audit settings.
2. Seed tenant-A and tenant-B canaries plus a harness-control row. Confirm the
   administrator can see both before testing absence.
3. Connect as the exact runtime role. Test select-by-id, list, aggregate,
   insert, update, tenant-key update, upsert, delete, `COPY`, view, function,
   direct partition, and materialized/history paths.
4. Run unset/null/forged context cases. Borrow one pooled connection as A,
   return it, then borrow it as B; repeat in the opposite order and after a
   failed transaction.
5. Exercise owner, `BYPASSRLS`, definer, Supabase anonymous/authenticated, and
   service-role controls only with synthetic local credentials.
6. Compare a fresh migration, supported upgrade, and repository-owned restored
   dump. If the test runner does not already perform backup/restore, leave that
   path `NOT_ASSESSED` rather than starting tooling silently.
7. Assert rows, side effects, and audit records. Do not assert only an exception
   string.

Useful catalog anchors include `pg_roles`, `pg_auth_members`, `pg_class`,
`pg_namespace`, `pg_policy`/`pg_policies`, `information_schema` privilege
views, `pg_proc`, `pg_publication`, and `pg_event_trigger`.

## Known false positives

- A table is staging, migration bookkeeping, or provably single-tenant and not
  reachable by a tenant runtime role.
- RLS appears after `CREATE TABLE` in a later migration and the final parsed
  state enables it before any deployment grants access.
- An apparent owner is a `NOLOGIN` migration role the runtime cannot inherit or
  become.
- `SECURITY DEFINER` is deliberately narrow, has pinned trusted resolution,
  constrained `EXECUTE`, and a two-principal behavioral fixture.
- `service_role` occurs only in a server-only migration/administration path;
  verify bundling and call reachability before filing.
- An RLS policy omits `WITH CHECK` because the intended `USING` expression is
  validly reused; test write behavior rather than filing on syntax alone.
- A custom GUC uses `set_config(..., true)` instead of literal `SET LOCAL`; both
  are transaction-local patterns when used correctly.
- A relation is protected by physical database/schema isolation with direct
  grants that make record RLS not applicable. Prove the topology boundary.

## Fixture concepts

### Vulnerable

`V-PG-001`: shared-table tenancy with correct read policy but no write check;
runtime owns the table; a pooled connection uses session-scoped tenant context;
a `SECURITY DEFINER` export has mutable `search_path`; a new table is exposed
without RLS; service-role code is bundled into a client path; publication and
restored dump expose both tenant canaries.

Expected rule anchors:

- `db.authorization.postgresql.rls-policy-completeness`
- `db.authorization.postgresql.rls-bypass`
- `db.authorization.postgresql.tenant-context-lifecycle`
- `db.execution.postgresql.security-definer-search-path`
- `db.migration.postgresql.new-relation-policy-drift`
- `db.copy.postgresql.replication-policy-gap`
- `db.restore.postgresql.global-principal-gap`

### Clean

`C-PG-001`: distinct `NOLOGIN` owner/migrator and least-privileged runtime;
RLS enabled and forced where appropriate; complete read/write policies;
transaction-local trusted tenant context; tenant key immutable; constrained
definer routine with safe resolution; no client service role; explicit
publication contract; dump plus globals restore; actor-aware audit; bounded
timeouts. The same matrix must show own-tenant success and foreign-tenant
failure.

## Official sources

All links verified `2026-07-28`:

- [PostgreSQL row security policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [PostgreSQL privileges](https://www.postgresql.org/docs/current/ddl-priv.html)
- [PostgreSQL `CREATE POLICY`](https://www.postgresql.org/docs/current/sql-createpolicy.html)
- [PostgreSQL `CREATE FUNCTION`](https://www.postgresql.org/docs/current/sql-createfunction.html)
- [PostgreSQL function security](https://www.postgresql.org/docs/current/perm-functions.html)
- [PostgreSQL logical replication row filters](https://www.postgresql.org/docs/current/logical-replication-row-filter.html)
- [PostgreSQL `pg_dump`](https://www.postgresql.org/docs/current/app-pgdump.html)
- [PostgreSQL `pg_dumpall`](https://www.postgresql.org/docs/current/app-pg-dumpall.html)
- [PostgreSQL error reporting and logging](https://www.postgresql.org/docs/current/runtime-config-logging.html)
- [Supabase row-level security](https://supabase.com/docs/guides/database/postgres/row-level-security)
- [Supabase database roles](https://supabase.com/docs/guides/database/postgres/roles)
- [Supabase pgaudit extension](https://supabase.com/docs/guides/database/extensions/pgaudit)
