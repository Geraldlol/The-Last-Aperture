# MariaDB adapter

Adapter ID: `mariadb`

Deployment variants: `mariadb-self-managed`, `mariadb-managed`,
`mariadb-galera`

Verified: `2026-07-28`

This adapter covers MariaDB Server. It does not inherit MySQL semantics merely
because both speak a similar protocol. Roles, privileges, definers, temporal
tables, resource controls, audit plugins, replication, storage engines, and
version gates have diverged. MySQL, Percona, Amazon Aurora MySQL, and other
compatible products select their own adapter or `inventory-only`.

## Engine, version, edition, and deployment detection

Strong signals:

- pinned `mariadb:<version>`/MariaDB Server packages or committed
  `SELECT VERSION()` output containing the product identity;
- `mariadb-install-db`, `mariadb-upgrade`, `mariadb-backup`,
  `mariadb-dump`, `mariadbd`, or MariaDB-specific configuration;
- provider configuration naming MariaDB and an exact engine version;
- MariaDB-only DDL, system-versioning, role, Galera, or audit variables.

MySQL/MariaDB drivers, an ORM `mysql` dialect, port 3306, and generic SQL are
weak signals. They activate inventory only. Record exact version, Community or
Enterprise/provider distribution, storage engines, Galera/standard replication
topology, `sql_mode`, authentication plugins, and enabled plugins.

Version gates are material: `PUBLIC` role/grants, dynamic privileges, role
definers, temporal features, privilege names, backup behavior, and system
variables vary by MariaDB release. Unknown versions remain `NOT_ASSESSED` for
gated rules.

## Capability declaration

| Capability ID | Value | Conditions |
|---|---|---|
| `principal-authentication` | `NATIVE` | `user`@`host` accounts and MariaDB authentication plugins. |
| `role-and-object-grants` | `NATIVE` | Version-sensitive roles and global/database/table/column/routine privileges; `PUBLIC` is version-gated. |
| `record-read-authorization` | `COMPOSABLE` | Separate accounts/databases or predicate views with base-table access removed; no general native RLS. |
| `record-write-authorization` | `COMPOSABLE` | Updatable checked views and constrained routines; all DML paths must be closed. |
| `column-or-property-authorization` | `NATIVE` | Column privileges and constrained views. |
| `tenant-session-context` | `EXTERNAL_ONLY` | Caller-set session/user variables are not a protected tenant identity. |
| `stored-code-execution-context` | `NATIVE` | Definer/invoker routines and views, role definers, triggers, and events. |
| `schema-integrity` | `NATIVE` | Version/storage-engine-sensitive constraints, keys, generated columns, and triggers. |
| `transactional-integrity` | `NATIVE` | Only for the identified transactional storage engine and topology. |
| `resource-governance` | `COMPOSABLE` | Account resource options, statement time, connections, thread pools, and provider controls. |
| `replication-cdc-authorization` | `COMPOSABLE` | Standard/multi-source/Galera/binlog paths require independent accounts and filters. |
| `history-authorization` | `COMPOSABLE` | System-versioned tables are native, but historical query/grant/view paths must be assessed separately. |
| `backup-policy-portability` | `COMPOSABLE` | `mariadb-backup`, dump, Galera SST, and provider snapshots preserve different state. |
| `security-audit` | `COMPOSABLE` | MariaDB Audit Plugin/provider audit plus protected configuration and destination. |
| `policy-catalog-introspection` | `NATIVE` | Grant tables, roles, information schema, stored objects, plugins, temporal, replication, and variables. |

## Principal and grant model

Compute authority from:

- exact `user`@`host` accounts and authentication plugins;
- direct privileges, granted roles, default/current role, nested roles, role
  administration, `GRANT OPTION`, and version-gated `PUBLIC` grants;
- global, database, table, column, routine, and proxy scopes;
- definers including version-supported `CURRENT_ROLE`, routine/view
  `SQL SECURITY`, triggers, and events;
- high-impact privileges for user/role/definer administration, file access,
  process visibility, replication, backup, plugin/UDF/server administration,
  and connection/session control.

A granted role is not necessarily active. A global grant applies to future
objects; a table review cannot see it. `PUBLIC`, where supported, reaches every
server user and must be expanded explicitly.

Do not parse MariaDB privileges with a MySQL static/dynamic-privilege list.
Unknown privilege syntax on a new version is `NOT_ASSESSED`.

## Native authorization and tenant controls

MariaDB has no general native record-policy/RLS engine. A record guarantee may
be composed from:

- one authenticated account/database per tenant with no cross-grants;
- predicate views whose callers lack base-table access;
- a constrained routine API with only `EXECUTE` exposed;
- an external application/topology boundary, labelled `EXTERNAL_ONLY`.

For view/routine isolation, verify:

- explicit `SQL SECURITY` and least-privileged definer;
- complete base-table, alternate-view, routine, trigger, event, and export
  closure;
- `WITH CHECK OPTION` and nested-view behavior for writes;
- read, aggregate, insert, update, tenant-key mutation, replace/upsert, delete,
  and bulk paths;
- tenant identity derives from an authenticated database account or proved
  external boundary, not `@tenant_id`.

Rule anchors:

- `db.authorization.mariadb.no-native-row-policy`
- `db.authorization.mariadb.view-base-table-closure`
- `db.authorization.mariadb.view-write-check`
- `db.authorization.mariadb.caller-mutable-tenant-context`

Missing RLS syntax is not a finding. A claimed database-enforced guarantee with
no complete composition is.

## Bypasses and alternate paths

Inventory and test:

- global/database/base-table grants, active/default/nested roles, `PUBLIC`,
  proxying, grant/admin authority, and definer-setting privileges;
- `FILE`, file import/export, UDFs, plugins, user-defined storage engines, and
  administrative sockets;
- views, routines, triggers, scheduled events, sequences, and packages where
  supported;
- binlog/relay logs, standard/multi-source replication, Galera IST/SST,
  MaxScale/proxy paths, backups, dumps, logs, and provider exports;
- `skip-grant-tables`, unix-socket authentication, anonymous/default accounts,
  and recovery configuration;
- system-versioned history queried with `FOR SYSTEM_TIME`;
- direct native access by the shared application account.

Replication filters are selection/operations settings, not authorization for
the source binlog or a reader with broader replica grants.

## Stored code and execution context

Views and stored routines can run as definer or invoker. MariaDB versions may
allow a role as definer (`CURRENT_ROLE`), which intentionally uses role rather
than user privileges. Triggers and events use definer authority. For each
object:

- capture explicit/effective definer, current/default role behavior, caller
  grants, and downstream objects;
- minimize the definer and constrain `EXECUTE`/view grants;
- test nested routine/view chains and dynamic SQL;
- inspect event scheduler, trigger side effects, file/UDF/plugin access, and
  replication behavior;
- detect orphaned definers and migration/dump rewrites.

Rule anchors:

- `db.execution.mariadb.definer-context`
- `db.execution.mariadb.role-definer-semantics`
- `db.execution.mariadb.trigger-event-definer`
- `db.execution.mariadb.orphan-definer`

Do not assume MySQL's role activation or definer privilege names apply.

## Migration and security drift

Compare catalogs after fresh, upgrade, rollback, and restore paths:

- runtime gains a global/database/base-table grant that bypasses views;
- views lose predicates/check options or change definer/security mode;
- new tables/history partitions/routines/events lack the established boundary;
- role activation, nesting, `PUBLIC` grants, authentication plugins, or
  definers change across a version upgrade;
- storage engine, `sql_mode`, constraint enforcement, Galera settings,
  replication filters, event scheduler, audit plugin, or resource limits drift;
- system-versioned history is altered, dropped, or exposed differently;
- dump/restore omits grants, routines, events, temporal definitions, or plugins.

Generated/MySQL-compatible migrations are not proof they ran on MariaDB.
Resolve the final state under the detected version.

## Transactions, concurrency, and integrity

Record storage engine for every protected relation and the topology that
commits it. Verify:

- keys, tenant-qualified uniqueness, FKs/checks, generated columns, triggers,
  and enforcement state under the exact engine/version;
- rollback behavior when transactional and nontransactional tables mix;
- implicit DDL commits and autocommit during security migrations;
- isolation/locking, deadlock retry, and Galera certification/conflict behavior
  for the claimed invariant;
- tenant-key mutation through views, triggers, `REPLACE`, upsert, bulk, and
  system-versioned paths;
- retry does not reuse stale actor/tenant context.

The adapter records engine facts; cross-service business invariants remain with
business logic.

## CDC, replication, and history

Map binlogs, relay logs, standard and multi-source replication, replication
filters, Galera write sets/IST/SST, MaxScale/binlog routers, CDC connectors, and
system-versioned/application history.

System-versioned tables expose historical rows through `FOR SYSTEM_TIME`
queries, including `ALL`. Test history under the runtime/reporting account and
through views, backups, replicas, and restore. History is not an immutable
security audit merely because it is system-versioned.

For every replication path, verify initial copy, ongoing events, filters,
replication/monitoring accounts, source log readers, replica readers, promotion,
and conflict/error behavior. A filtered replica does not protect the source
binlog.

## Backup and restore

Map logical `mariadb-dump`, physical `mariadb-backup`, filesystem/provider
snapshots, PITR/binlogs, Galera SST, and replica-based backup. Physical backups
must be prepared before restore; a file copy or unprepared successful command
is not a consistency proof. Logical backups do not include server
configuration/log files.

Compare restored:

- accounts, authentication plugins, roles/defaults/`PUBLIC`, grants, and
  definers;
- views, routines, triggers, events, packages, temporal definitions/history,
  storage engines, and constraints;
- plugins/UDFs, audit settings, replication/Galera state, and resource limits;
- canary data plus policy behavior for every actor and copy path.

Encryption, snapshot sharing, retention, and key custody remain with their
owning lenses.

## Audit and attribution

The MariaDB Audit Plugin or a managed-provider equivalent must be installed,
enabled, configured, and protected; its presence in a package is not audit
coverage. Establish:

- event classes and filters for successful/failed data access, grants/roles,
  definers, plugins, replication, backup, and administration;
- authenticated account, current role, application actor/tenant for shared
  identities, definer/effective authority, object, action, and outcome;
- destination, rotation, loss/failure behavior, and principals that can alter
  or unload audit;
- Galera/proxy/replica node coverage and clock/node identity;
- parameter minimization so logs do not create a sensitive-data copy.

General/slow/binary logs are not automatically a complete security audit.

## Availability and resource governance

Assess per-account `MAX_*` limits (including version-supported statement time),
`max_statement_time`, connections, thread pools, query/lock timeouts, temp/disk
limits, provider quotas, Galera flow control, replication lag, history growth,
and audit growth.

Use bounded tests for:

- unindexed predicate views, regex/JSON/full-text/spatial work, recursive CTEs,
  sorts, temp tables, and large packets/results;
- metadata locks, long transactions, deadlocks, pool exhaustion, and mixed
  storage-engine stalls;
- Galera certification conflicts/flow control, SST pressure, binlog/relay lag,
  and system-versioned history expansion;
- event/trigger/UDF/plugin amplification.

A missing knob is not a finding without a reachable workload and availability
requirement.

## Unsupported guarantees and NOT ASSESSED cases

- MariaDB has no general native RLS/record-policy catalog.
- Caller-set session/user variables are not a protected tenant identity.
- View/routine isolation is defeated by base-table or broader object grants.
- System-versioned history is queryable data, not an immutable end-user audit.
- Primary view predicates do not automatically protect binlogs, Galera
  transfers, replicas, dumps, history, logs, or restored copies.
- Version, `PUBLIC` support, role-definer semantics, plugin availability, or
  managed-service behavior that cannot be identified is `NOT_ASSESSED`.
- MySQL test results do not clear MariaDB behavior.

An unsupported primitive becomes a finding only when a required system
guarantee has no tested alternative.

## Static discovery sweeps

Every hit is a candidate to read:

```bash
rg -n --hidden 'mariadb|mariadbd|mariadb-backup|mariadb-dump|galera|wsrep_' .
rg -n --hidden 'CREATE\s+(OR\s+REPLACE\s+)?VIEW|SQL\s+SECURITY\s+(DEFINER|INVOKER)|WITH\s+(CASCADED|LOCAL\s+)?CHECK\s+OPTION' .
rg -n --hidden 'CREATE\s+(PROCEDURE|FUNCTION|TRIGGER|EVENT|PACKAGE)|DEFINER\s*=|CURRENT_ROLE' .
rg -n --hidden 'GRANT\s+.*ON\s+\*\.\*|GRANT\s+.*TO\s+PUBLIC|SET\s+DEFAULT\s+ROLE|SET\s+ROLE|WITH\s+ADMIN\s+OPTION' .
rg -n --hidden 'FILE|PROCESS|SUPER|READ_ONLY\s+ADMIN|BINLOG\s+REPLAY|REPLICATION|PROXY\s+ON|GRANT\s+OPTION' .
rg -n --hidden '@tenant|@user|SET\s+@|CURRENT_USER\s*\(|CURRENT_ROLE\s*\(' .
rg -n --hidden 'WITH\s+SYSTEM\s+VERSIONING|FOR\s+SYSTEM_TIME|system_versioning_|secure_timestamp' .
rg -n --hidden 'ENGINE\s*=\s*(MyISAM|Aria|MEMORY|CONNECT)|FOREIGN\s+KEY|CHECK\s*\(|sql_mode|FOREIGN_KEY_CHECKS' .
rg -n --hidden 'log_bin|binlog_format|replicate_(do|ignore|wild)|CHANGE\s+MASTER|CHANGE\s+REPLICATION|wsrep_sst' .
rg -n --hidden 'server_audit|plugin_load|INSTALL\s+(SONAME|PLUGIN)|max_statement_time|MAX_STATEMENT_TIME|MAX_USER_CONNECTIONS' .
```

Resolve version gates, final grants/role activation, nested views, definers,
storage engines, plugins, and topology. Static discovery alone never clears a
store.

## Proof and conformance recipe

Use a repository-started ephemeral MariaDB at T1 or a user-approved loopback
instance at T2. Do not substitute MySQL.

1. Record product/version, provider, engines, topology/Galera, `sql_mode`,
   accounts/plugins, effective grants/roles/`PUBLIC`, definers, views/routines,
   temporal metadata, replication, audit plugins, and resource variables.
2. Seed tenant-A/B canaries and verify an administrator control sees both.
3. As the exact runtime account, test base table and every view/routine:
   read-by-id, list, aggregate, insert, update, tenant-key mutation, upsert,
   `REPLACE`, delete, bulk, export, trigger, event, and `FOR SYSTEM_TIME ALL`.
4. Try unset/forged caller variables and direct SQL. Where per-tenant accounts
   enforce isolation, test both users and all relevant role states.
5. Exercise invoker/definer/role-definer, `PUBLIC`, replication, Galera,
   history, backup, and audit controls with bounded disposable data.
6. Compare fresh/upgrade/rollback and repository-owned dump/physical restore,
   including prepare step, grants, definers, events, history, and plugins.
7. Assert persisted side effects and audit events, not only errors.

Catalog anchors include MariaDB grant tables, role-mapping/default-role tables,
`INFORMATION_SCHEMA` privilege/view/routine/trigger/event/constraint tables,
plugins, system-versioning metadata, replication status/tables, and variables.
If the fixture principal cannot enumerate required metadata, record the leg
`NOT_ASSESSED`.

## Known false positives

- A store is single-tenant or uses a proved separate-account/database boundary;
  native row policy is not required.
- Runtime has only a complete checked view/routine surface and no base-table or
  broader role/`PUBLIC` access; a two-tenant proof confirms it.
- A role/definer name is present but inactive/unreachable under the detected
  version.
- A role definer is intentionally narrow and its effective privileges are
  proved; do not treat MariaDB's supported syntax as MySQL drift.
- System versioning is used for product history with separately tested
  authorization, not claimed as audit.
- A nontransactional table is a disposable cache with no transaction claim;
  record the boundary rather than inventing impact.
- Audit uses a provider-specific MariaDB plugin/event model; select that
  deployment branch before filing.
- Vulnerable-looking SQL exists only in negative fixtures or generated vendor
  dumps that are not deployed.

## Fixture concepts

### Vulnerable

`V-MARIADB-001`: caller-set tenant variable; checked view but base table granted
through active `PUBLIC`; high-privilege role definer; trigger/event with broad
authority; mixed nontransactional table; `FOR SYSTEM_TIME ALL` exposes foreign
history; Galera SST/binlog reader is shared; physical backup is not prepared;
audit plugin installed but disabled.

Expected rule anchors:

- `db.authorization.mariadb.caller-mutable-tenant-context`
- `db.authorization.mariadb.view-base-table-closure`
- `db.execution.mariadb.role-definer-semantics`
- `db.integrity.mariadb.storage-engine-guarantee`
- `db.copy.mariadb.temporal-replication-policy-gap`
- `db.restore.mariadb.physical-backup-preparation`
- `db.audit.mariadb.plugin-state-coverage`

### Clean

`C-MARIADB-001`: exact version branch; separate least-privileged accounts and
roles; no `PUBLIC`/base-table bypass; complete checked views/routines; narrow
explicit definers; transactional constraints and Galera behavior tested;
history independently authorized; replication/backup identities separate;
prepared restore is policy-equivalent; enabled actor-aware audit and bounded
resources. Own-tenant allow and foreign-tenant deny/empty both pass.

## Official sources

All links verified `2026-07-28`:

- [MariaDB user account management](https://mariadb.com/docs/server/security/user-account-management)
- [MariaDB `GRANT`](https://mariadb.com/docs/server/reference/sql-statements/account-management-sql-statements/grant)
- [MariaDB roles overview](https://mariadb.com/docs/server/security/user-account-management/roles/roles_overview)
- [MariaDB `CREATE VIEW`](https://mariadb.com/docs/server/server-usage/views/create-view)
- [MariaDB stored routine privileges](https://mariadb.com/docs/server/server-usage/stored-routines/stored-functions/stored-routine-privileges)
- [MariaDB system-versioned tables](https://mariadb.com/docs/server/reference/sql-structure/temporal-tables/system-versioned-tables)
- [MariaDB replication filters](https://mariadb.com/docs/server/ha-and-performance/standard-replication/replication-filters)
- [MariaDB backup and restore overview](https://mariadb.com/docs/server/server-usage/backup-and-restore/backup-and-restore-overview)
- [MariaDB Audit Plugin](https://mariadb.com/docs/server/reference/plugins/mariadb-audit-plugin)
- [MariaDB account resource limits](https://mariadb.com/docs/server/reference/sql-statements/account-management-sql-statements/grant#resource-limit-options)
- [MariaDB `max_statement_time`](https://mariadb.com/docs/server/ha-and-performance/optimization-and-tuning/query-optimizations/aborting-statements)
