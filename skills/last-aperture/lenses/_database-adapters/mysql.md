# MySQL adapter

Adapter ID: `mysql`

Deployment variants: `mysql-self-managed`, `mysql-managed`

Verified: `2026-07-28`

This adapter covers Oracle MySQL, not MariaDB, Percona Server, TiDB, Vitess, or
a provider's partially compatible wire protocol. Those products receive their
own adapter/profile. MySQL has no general native row-policy engine: tenant
isolation can be composed from accounts, schemas, views/routines, and removal
of base-table access, or enforced outside the engine. The adapter must never
translate "no `CREATE POLICY`" into a vulnerability by itself.

## Engine, version, edition, and deployment detection

Strong signals:

- pinned `mysql:<version>` images or exact Oracle MySQL server packages;
- committed `SELECT VERSION()`/server metadata;
- provider configuration naming MySQL and an exact engine version;
- `mysqld --version`, `mysql_upgrade`/data-dictionary metadata, or
  MySQL-specific grants and DDL.

`mysql2`, Connector/J, Connector/Python, Go's MySQL driver, an ORM dialect, port
3306, or `MYSQL_URL` is weak evidence and activates inventory only. MariaDB can
present a MySQL-compatible protocol; distinguish the server product before
applying role, privilege, audit, replication, JSON, or DDL semantics.

Record MySQL major/minor, Community versus Enterprise, managed provider/SKU,
storage engines in use, `sql_mode`, and relevant server variables. This adapter
supports MySQL 8.0+ semantics when the exact feature gate is established.
Older versions and unknown forks are `NOT_ASSESSED`, not approximated.

## Capability declaration

| Capability ID | Value | Conditions |
|---|---|---|
| `principal-authentication` | `NATIVE` | MySQL accounts are `user`@`host` identities with authentication plugins. |
| `role-and-object-grants` | `NATIVE` | MySQL 8 roles plus static/dynamic privileges at global, schema, table, column, routine, and proxy scopes. |
| `record-read-authorization` | `COMPOSABLE` | Separate accounts/schemas or predicate views with no base-table access; no native row-policy catalog. |
| `record-write-authorization` | `COMPOSABLE` | Updatable views with `WITH CHECK OPTION` and/or constrained routines; every DML path must be closed. |
| `column-or-property-authorization` | `NATIVE` | Column privileges and constrained views. |
| `tenant-session-context` | `EXTERNAL_ONLY` | User/session variables are caller-mutable; use distinct authenticated accounts or an external trusted context boundary. |
| `stored-code-execution-context` | `NATIVE` | `DEFINER`, `SQL SECURITY`, routine/view grants, triggers, and events. |
| `schema-integrity` | `NATIVE` | Storage-engine- and version-sensitive keys, foreign keys, checks, generated columns, and triggers. |
| `transactional-integrity` | `NATIVE` | Transactional storage engine required; DDL and nontransactional tables have different semantics. |
| `resource-governance` | `COMPOSABLE` | Account limits, resource groups, execution/lock limits, pool bounds, and provider quotas. |
| `replication-cdc-authorization` | `COMPOSABLE` | Replication accounts/privileges and filters plus independently secured replicas/binlogs. |
| `history-authorization` | `UNSUPPORTED` | Core MySQL has no general temporal-history authorization primitive. |
| `backup-policy-portability` | `COMPOSABLE` | Dump/physical tools preserve different object sets; users, grants, definers, routines, events, and plugins require explicit coverage. |
| `security-audit` | `UNKNOWN` | Enterprise Audit, managed-service audit plugins, or external collection; edition/provider must be known. |
| `policy-catalog-introspection` | `NATIVE` | Grant tables, `INFORMATION_SCHEMA`, `performance_schema`, roles, routines, views, triggers, events, replication, and variables. |

## Principal and grant model

Compute effective authority from:

- exact `user`@`host` account matching and authentication plugin;
- directly granted static privileges, dynamic privileges, active/default roles,
  mandatory roles, and role-to-role grants;
- global, schema, table, column, routine, and proxy scopes;
- object ownership/`DEFINER` context, default roles of definers, and the
  `activate_all_roles_on_login` setting;
- administrative privileges such as `CREATE USER`, `ROLE_ADMIN`,
  `SYSTEM_USER`, `SYSTEM_VARIABLES_ADMIN`, definer-setting privileges,
  `FILE`, `PROCESS`, backup, replication, connection, and plugin/component
  administration.

MySQL privileges are additive; there is no general SQL `DENY` that a generic
evaluator can apply after grants. When `partial_revokes` is enabled, schema-level
partial revokes add a narrower restriction that must be expanded from the grant
tables/`SHOW GRANTS`; they are not a portable deny rule. A role being granted
does not prove it is active. Record `CURRENT_ROLE()`/default-role semantics for
runtime and for stored objects.

`'app'@'localhost'` and `'app'@'%'` are different accounts. Do not normalize
away the host component or infer deployed network trust from it; network
exposure belongs to cloud/IaC.

## Native authorization and tenant controls

MySQL does not have PostgreSQL/SQL Server-style native RLS. Supported
compositions are:

1. one authenticated database account/schema/database per tenant, with no
   cross-tenant grants;
2. a view per allowed slice, where the runtime has privileges on the view but
   not the base table;
3. a constrained routine API, where runtime has `EXECUTE` but no direct base
   DML;
4. application-enforced predicates, explicitly labelled `EXTERNAL_ONLY`.

A predicate view is a security boundary only if:

- its `SQL SECURITY` and definer/invoker semantics are deliberate;
- the caller cannot query the base table or another broader view/routine;
- every required read, aggregate, insert, update, tenant-key change, upsert,
  delete, bulk, and export path is covered;
- writes through an updatable view use the required `CASCADED` or `LOCAL`
  `WITH CHECK OPTION`, and the nested-view behavior is tested;
- the tenant identity comes from an authenticated account or external trusted
  boundary, not a caller-set `@tenant_id`.

Rule anchors:

- `db.authorization.mysql.no-native-row-policy`
- `db.authorization.mysql.view-base-table-closure`
- `db.authorization.mysql.view-write-check`
- `db.authorization.mysql.caller-mutable-tenant-context`

Absence of native RLS is inventory. File a finding only when the architecture
claims database-enforced record isolation and neither a complete native
composition nor a proved external boundary supplies it.

## Bypasses and alternate paths

Inventory and test:

- global/schema/base-table grants, broad roles, `PROXY`, definers, and ability
  to grant roles or choose/alter definers;
- `FILE`, `SELECT ... INTO OUTFILE`, `LOAD DATA`, `LOAD_FILE`, local-infile
  client behavior, and secure-file restrictions;
- stored routines, views, triggers, scheduled events, plugins, components, and
  user-defined functions;
- binlogs, relay logs, replicas, clone/backup tools, general/slow logs,
  `performance_schema`, and provider exports;
- federated tables, storage-engine plugins, partition access, temporary tables,
  and administrative metadata;
- direct native access using the same shared application account.

Replication filters and view predicates are not equivalent controls. A source
binlog or backup can contain rows a filtered replica/view never exposes.

## Stored code and execution context

Views and stored routines declare `SQL SECURITY DEFINER` or `INVOKER`; a
missing definer is assigned at creation, and definer context can carry that
account's default/activated roles under version-specific rules. Triggers and
events execute in definer context. Orphaned definers can make objects fail or
preserve an unintended authority relationship after account changes.

For every stored object:

- record explicit/effective definer, SQL security mode, caller grants, default
  roles, and downstream objects;
- minimize the definer's privileges and avoid a system-administrative definer;
- prove base-table access is not reachable through a broader routine/view;
- inspect dynamic SQL, file/network-capable UDFs/plugins, event scheduling, and
  binary-log effects;
- verify dump/restore and migration do not rewrite the definer to the deployment
  administrator.

Rule anchors:

- `db.execution.mysql.definer-context`
- `db.execution.mysql.trigger-event-definer`
- `db.execution.mysql.orphan-definer`

SQL injection inside application-built SQL remains `web-and-api`; the
privileged stored-object context that magnifies it is recorded here.

## Migration and security drift

Compare grants and metadata after fresh install, upgrade, rollback, and restore:

- a new base table is granted to runtime while old tables were view/routine
  only;
- a view loses its predicate or `WITH CHECK OPTION`, changes `SQL SECURITY`, or
  is recreated under a more privileged definer;
- broad schema/global grants or default roles are added;
- a role is granted but not made active, or a mandatory role silently changes
  authority;
- a storage engine changes from InnoDB to nontransactional behavior;
- `sql_mode`, check-constraint support, FK enforcement, event scheduler,
  local-infile, plugin loading, or binary-log settings change;
- dumps omit routines/events or restore orphan/high-privilege definers.

Do not infer final state from a single `GRANT`/`REVOKE` line. Resolve all
migrations in order and distinguish MySQL from MariaDB syntax and variables.

Rule anchor:

- `db.migration.mysql.runtime-ddl-separation`

## Transactions, concurrency, and integrity

Record storage engine for every protected table. InnoDB supplies transactions
and foreign keys; a nontransactional engine invalidates rollback assumptions.
Check:

- primary/unique keys include the tenant dimension where the model requires it;
- foreign keys and checks exist and are enforced for the identified version and
  engine;
- older MySQL versions that parsed but did not enforce `CHECK` are not treated
  as protected;
- autocommit and implicit-commit DDL do not split a security migration;
- isolation/locking (`SELECT ... FOR UPDATE`, gap/next-key locks, deadlock
  retry) matches the claimed invariant;
- tenant-key mutation through views, triggers, upserts, `REPLACE`, and bulk
  operations cannot cross ownership.

Application workflow conclusions remain with business logic.

## CDC, replication, and history

Map binary log format/retention, replication source and applier accounts,
replicas, relay logs, GTIDs, filters, managed CDC connectors, and any
application audit/history tables. Verify:

- the replication account has only the required current privileges;
- source binlog, relay log, replica, and downstream connector each have an
  independent reader boundary;
- initial snapshot and ongoing changes apply the same data-selection contract;
- statement/row/mixed format and trigger behavior do not invalidate the
  selection or attribution claim;
- replication filters are not represented as access control for readers of the
  source log.

Core MySQL has no general temporal-table authorization surface. Application
history and audit tables are ordinary tables and require the same view/grant
closure as current data.

Rule anchors:

- `db.copy.mysql.binlog-reader-boundary`
- `db.history.mysql.application-history-closure`

## Backup and restore

Map `mysqldump`, MySQL Shell dump/load, physical backup, clone plugin, provider
snapshot/PITR, and replica promotion. `mysqldump` includes triggers by default,
while routines and events require explicit options; account/grant preservation
is a separate concern from dumping application schemas.

The restore oracle compares:

- accounts, authentication plugins, role graph, active/default/mandatory roles,
  global/schema/table/column/routine grants, and proxies;
- definers and `SQL SECURITY` for views/routines plus triggers/events;
- storage engines, constraints, `sql_mode`, plugins/components, and scheduled
  event state;
- replication/CDC and audit configuration;
- application canaries and every restored copy path.

Do not run a provider restore or connect to a managed instance under this skill.
Use repository-owned local fixtures or report the path `NOT_ASSESSED`.

Tenant-scoped client export must use a constrained view or routine. `FILE`,
`SELECT ... INTO OUTFILE`, `LOAD_FILE`, dump accounts, and unrestricted base
table reads remain separate export paths.

Rule anchors:

- `db.restore.mysql.dump-object-coverage`
- `db.copy.mysql.export-boundary`

## Audit and attribution

MySQL Enterprise Audit, managed-service audit plugins, and community/plugin
options have different event models and availability. The general query log,
slow log, binary log, and `performance_schema` are not automatically a complete
or tamper-resistant security audit.

Establish:

- authenticated account, active roles, application actor/tenant when a shared
  account is used, object, operation, and outcome;
- coverage of reads, denied operations, privilege/role/definer changes,
  backup/restore, replication, and plugin administration;
- who can change audit policy, unload a plugin, rotate/delete targets, or alter
  clocks;
- whether definer routines record invoker and effective definer;
- parameter/data minimization so audit does not become a secret/PII copy.

If edition/provider is unknown, audit coverage is `NOT_ASSESSED`.

## Availability and resource governance

Assess per-account resource limits, `max_connections`, thread/pool limits,
execution/lock timeouts, Resource Groups where available, temp/disk limits,
replica lag, provider quotas, and cancellation behavior. `MAX_EXECUTION_TIME`
has operation-specific limits and is not a universal statement timeout.

Use bounded tests for:

- unindexed predicate views and tenant columns;
- regex/JSON/full-text/spatial work, recursive CTEs, sorts, temp tables, and
  large packets/results;
- metadata locks, long transactions, deadlocks, connection/pool exhaustion,
  and event-scheduler overlap;
- binlog/relay growth, replica lag, and audit-log amplification;
- stored routines, triggers, UDFs, and plugins that amplify one request.

The absence of a suggested variable is not a finding without a reachable
untrusted path and availability requirement.

## Unsupported guarantees and NOT ASSESSED cases

- MySQL has no general native record-policy/RLS catalog.
- There is no protected custom per-request tenant context equivalent to an
  authenticated principal; caller-set session/user variables are forgeable by
  that connection.
- Grants are additive; a generic explicit-deny policy cannot be modelled.
- View/routine isolation fails if runtime retains base-table or broader
  stored-object access.
- Core MySQL has no universal native history authorization.
- Community and managed deployments do not all provide the same security audit
  plugin or event coverage.
- View predicates do not automatically protect binlogs, replicas, dumps,
  exports, logs, or restored copies.

Require a tested alternative when the architecture claims one of these
guarantees. Product absence by itself is not a finding.

## Static discovery sweeps

Every hit is a candidate to read:

```bash
rg -n --hidden 'CREATE\s+(OR\s+REPLACE\s+)?VIEW|SQL\s+SECURITY\s+(DEFINER|INVOKER)|WITH\s+(CASCADED|LOCAL\s+)?CHECK\s+OPTION' .
rg -n --hidden 'CREATE\s+(PROCEDURE|FUNCTION|TRIGGER|EVENT)|DEFINER\s*=|ALTER\s+DEFINER' .
rg -n --hidden 'GRANT\s+.*ON\s+\*\.\*|GRANT\s+.*ON\s+[^ ]+\.\*|GRANT\s+.*TO|SET\s+DEFAULT\s+ROLE|SET\s+ROLE|mandatory_roles' .
rg -n --hidden 'FILE|PROCESS|SYSTEM_USER|SYSTEM_VARIABLES_ADMIN|SET_ANY_DEFINER|SET_USER_ID|ROLE_ADMIN|PROXY\s+ON' .
rg -n --hidden '@tenant|@user|SET\s+@|CURRENT_USER\s*\(|USER\s*\(|CURRENT_ROLE\s*\(' .
rg -n --hidden 'ENGINE\s*=\s*(MyISAM|MEMORY|CSV|ARCHIVE)|FOREIGN\s+KEY|CHECK\s*\(|sql_mode|FOREIGN_KEY_CHECKS' .
rg -n --hidden 'local_infile|LOAD\s+DATA|INTO\s+OUTFILE|LOAD_FILE\s*\(|plugin_load|INSTALL\s+(PLUGIN|COMPONENT)' .
rg -n --hidden 'log_bin|binlog_format|replicate_(do|ignore|wild)|CHANGE\s+REPLICATION\s+SOURCE|START\s+REPLICA' .
rg -n --hidden 'mysqldump|mysqlpump|util\.dump|clone\s+instance|--routines|--events|--triggers' .
rg -n --hidden 'audit_log|server_audit|general_log|slow_query_log|max_execution_time|max_connections|max_user_connections' .
```

Resolve final grants, role activation, nested-view check options, definers,
storage engines, and version gates. A keyword hit is never the finding.

## Proof and conformance recipe

Use a repository-started ephemeral Oracle MySQL at T1. An accepted authenticated
operator statement naming the target, scope, and T2 loopback launch is authority
without another prompt. Execute it only through a matching implemented
controller; otherwise record `UNPROVEN` with the technical transport gap. Do not
substitute MariaDB because it accepts similar SQL.

1. Record version/comment, edition/provider, storage engines, `sql_mode`,
   accounts/auth plugins, effective grants/roles, definers, views/routines,
   constraints, replication, plugins, and audit/resource variables.
2. Seed tenant-A/B canaries and prove an administrative control sees both.
3. Connect as the exact runtime account. Test base tables, every view/routine,
   read-by-id, list, aggregate, insert, update, tenant-key mutation, upsert,
   `REPLACE`, delete, bulk, export, trigger, and event paths.
4. Try unset/forged caller session variables and direct native SQL. If the
   design uses per-tenant accounts, repeat with both accounts and host forms.
5. Exercise invoker/definer, active/default-role, base-table, replication, and
   backup controls using only disposable local data.
6. Compare fresh/upgrade/rollback and repository-owned dump/restore catalogs,
   including routines/events/definers and grants.
7. Assert persistent side effects and audit entries, not only MySQL error codes.

Catalog anchors include `mysql.user`, `mysql.db`, role edges/default roles,
`INFORMATION_SCHEMA.USER_PRIVILEGES`, schema/table/column/routine privilege
views, `INFORMATION_SCHEMA.VIEWS`, routines, triggers, events, constraints,
`performance_schema`, replication tables, and server variables. Access to
grant tables itself may be restricted; record an unavailable catalog as
`NOT_ASSESSED`.

## Known false positives

- A shared table is provably single-tenant or isolated by a separate
  schema/account with no cross-grants; native row policy is not required.
- A predicate view is paired with revoked base-table access and a complete
  two-tenant read/write proof.
- A definer is a narrow `ACCOUNT LOCK`/non-login-style administrative account
  with least privilege and constrained caller grants; prove actual semantics.
- A role appears granted but is intentionally inactive for runtime, or appears
  only in a migration/test fixture.
- `WITH CHECK OPTION` is inherited through a nested view as intended; resolve
  `LOCAL`/`CASCADED` semantics rather than matching text.
- A non-InnoDB table is a disposable cache/staging artifact with no
  transactional or relational guarantee; classify it instead of assuming
  impact.
- Audit plugin names differ on a managed service. Mark the provider path
  unassessed until its official event model is selected.
- `@tenant_id` occurs in a test, diagnostic script, or as an input immediately
  validated against a distinct authenticated database account.

## Fixture concepts

### Vulnerable

`V-MYSQL-001`: shared account with caller-set `@tenant_id`; predicate view but
runtime can read base table; updatable view lacks check option; high-privilege
definer trigger/event; role exists but is not default; MyISAM table breaks
rollback; dump omits routines/events/accounts; replica/binlog exposes both
tenants; general log is claimed as complete audit.

Expected rule anchors:

- `db.authorization.mysql.caller-mutable-tenant-context`
- `db.authorization.mysql.view-base-table-closure`
- `db.authorization.mysql.view-write-check`
- `db.execution.mysql.definer-context`
- `db.integrity.mysql.storage-engine-guarantee`
- `db.restore.mysql.dump-object-coverage`
- `db.audit.mysql.audit-capability-claim`

### Clean

`C-MYSQL-001`: distinct least-privileged authenticated tenant/runtime accounts
or a clearly external trust boundary; no base-table access; complete constrained
views/routines and write checks; explicit low-privilege definers; active/default
roles verified; InnoDB constraints and concurrency proof; separately secured
replication/backup; edition-correct audit; resource bounds. The matrix proves
own-tenant allow and foreign-tenant deny/empty.

## Official sources

All links verified `2026-07-28`:

- [MySQL access control and account management](https://dev.mysql.com/doc/refman/8.4/en/access-control.html)
- [MySQL roles](https://dev.mysql.com/doc/refman/8.4/en/roles.html)
- [MySQL privileges](https://dev.mysql.com/doc/refman/8.4/en/privileges-provided.html)
- [MySQL stored-object access control](https://dev.mysql.com/doc/refman/8.4/en/stored-objects-security.html)
- [MySQL view `WITH CHECK OPTION`](https://dev.mysql.com/doc/refman/8.4/en/view-check-option.html)
- [MySQL internal locking and transaction model](https://dev.mysql.com/doc/refman/8.4/en/internal-locking.html)
- [MySQL InnoDB transaction model](https://dev.mysql.com/doc/refman/8.4/en/innodb-transaction-model.html)
- [MySQL CHECK constraints](https://dev.mysql.com/doc/refman/8.4/en/create-table-check-constraints.html)
- [MySQL replication security](https://dev.mysql.com/doc/refman/8.4/en/replication-security.html)
- [MySQL `mysqldump`](https://dev.mysql.com/doc/refman/8.4/en/mysqldump.html)
- [MySQL Enterprise Audit](https://dev.mysql.com/doc/refman/8.4/en/audit-log.html)
- [MySQL Resource Groups](https://dev.mysql.com/doc/refman/8.4/en/resource-groups.html)
