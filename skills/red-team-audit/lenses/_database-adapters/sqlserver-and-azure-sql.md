# SQL Server and Azure SQL adapter

Adapter ID: `sqlserver`

Deployment variants: `sqlserver-self-managed`, `azure-sql-database`,
`azure-sql-managed-instance`

Verified: `2026-07-28`

This adapter covers the SQL Server Database Engine, Azure SQL Database, and
Azure SQL Managed Instance where the deployment variant is known. Azure
Synapse, Microsoft Fabric SQL surfaces, and third-party T-SQL compatibility
layers activate inventory only: their row-policy, audit, administrative, and
write-predicate behavior is not interchangeable with SQL Server.

## Engine, version, edition, and deployment detection

Strong signals:

- a pinned SQL Server container/image or exact server package;
- committed output from `SERVERPROPERTY('ProductVersion')`,
  `SERVERPROPERTY('Edition')`, and `SERVERPROPERTY('EngineEdition')`;
- an Azure resource whose type and SKU distinguish SQL Database from Managed
  Instance;
- a DACPAC/database project with a declared target platform;
- T-SQL catalogs or engine-specific DDL such as `CREATE SECURITY POLICY`.

`mssql`, JDBC, ODBC, Entity Framework's SQL Server provider, Dapper, a `.bak`
filename, or a connection-string key activates inventory only. A database
compatibility level is recorded separately and is not treated as the engine
version or edition.

Row-Level Security was introduced in SQL Server 2016 (13.x). The adapter marks
RLS rules `NOT_ASSESSED` for older or unknown server generations. Features such
as Resource Governor, SQL Server Audit targets, CLR, Agent, cross-database
behavior, and Entra authentication are deployment/edition-sensitive and must
not be inferred from T-SQL syntax.

## Capability declaration

| Capability ID | Value | Conditions |
|---|---|---|
| `principal-authentication` | `NATIVE` | Server logins/contained users or Azure SQL/Entra identities; deployment path must be identified. |
| `role-and-object-grants` | `NATIVE` | Server/database roles and securable hierarchy with grant, deny, ownership, impersonation, and certificates. |
| `record-read-authorization` | `NATIVE` | Enabled security policy with schema-bound filter predicates. |
| `record-write-authorization` | `NATIVE` | Block predicates plus update/delete behavior; not all T-SQL-compatible products support block predicates. |
| `column-or-property-authorization` | `NATIVE` | Column permissions; Dynamic Data Masking is not authorization. |
| `tenant-session-context` | `NATIVE` | `SESSION_CONTEXT`, but the setter and connection-pool lifecycle remain part of the trusted computing base. |
| `stored-code-execution-context` | `NATIVE` | `EXECUTE AS`, ownership chaining, module signing, and object ownership. |
| `schema-integrity` | `NATIVE` | Constraints, indexes, triggers, computed columns, and schema binding. |
| `transactional-integrity` | `NATIVE` | Transactions, locking, row-versioning, and selectable isolation levels. |
| `resource-governance` | `COMPOSABLE` | Timeouts, workload/resource controls, query hints, connection limits, and Azure service limits differ by deployment. |
| `replication-cdc-authorization` | `COMPOSABLE` | Replication/CDC/Change Tracking principals and artifacts are independent paths. |
| `history-authorization` | `COMPOSABLE` | Temporal history and ledger/history objects require explicit grants and policy testing. |
| `backup-policy-portability` | `COMPOSABLE` | Database security objects can restore, while server logins, credentials, keys, jobs, and external identities may not. |
| `security-audit` | `NATIVE` | SQL Server Audit/database audit specifications; available targets and Azure routing vary. |
| `policy-catalog-introspection` | `NATIVE` | `sys.database_permissions`, principals, role members, security policies/predicates, modules, audits, CDC, and temporal catalogs. |

## Principal and grant model

Build the effective graph from:

- server logins, contained database users, external/Entra users and service
  principals, certificates/asymmetric keys, application roles, and proxy paths;
- fixed and user-defined server/database roles;
- `GRANT`, `DENY`, `REVOKE`, `CONTROL`, `IMPERSONATE`, `TAKE OWNERSHIP`,
  `ALTER ANY ...`, and ownership at server/database/schema/object levels;
- module signatures and `EXECUTE AS`;
- SQL Agent proxies, linked-server mappings, credentials, and managed identities
  when present.

Do not implement a generic "deny always wins" shortcut. SQL Server evaluates a
securable hierarchy, ownership, fixed roles, impersonation, and documented
column-permission exceptions. Enumerate the effective path with catalogs and
behavior. Membership in `sysadmin`, `db_owner`, `db_securityadmin`,
`db_ddladmin`, or a role with policy/module alteration is a bypass or policy
administration path even when table grants look narrow.

Runtime, migrator, database owner, reporting, CDC, backup, Agent, and human
support identities are separate profile roles. Azure SQL Database has no
ordinary server-level security surface equivalent to boxed SQL Server; do not
invent one.

## Native authorization and tenant controls

SQL Server RLS uses a schema-bound inline table-valued function attached by a
security policy:

- filter predicates remove rows from `SELECT`, `UPDATE`, and `DELETE`
  visibility;
- block predicates reject disallowed writes at the supported `BEFORE`/`AFTER`
  operation points;
- the policy must be `STATE = ON`;
- read filtering does not prove insert, tenant-key update, `MERGE`, bulk, or
  delete behavior;
- predicate function permissions and schema binding have special semantics and
  must be assessed with the policy, not as an ordinary view.

Rule anchors:

- `db.authorization.sqlserver.security-policy-state`
- `db.authorization.sqlserver.filter-block-completeness`
- `db.authorization.sqlserver.security-policy-bypass`
- `db.authorization.sqlserver.tenant-context-lifecycle`

For a shared middle-tier login, `SESSION_CONTEXT` can carry a user/tenant ID.
The application must derive it from authenticated state, set it on every
checkout before protected work, and handle null, conversion failure, failed
transactions, retries, and pool return. `@read_only = 1` prevents later changes
for that logical connection but does not make an initially attacker-controlled
value trustworthy. Direct access by the shared login can choose any context
unless another boundary constrains who may issue native SQL.

Column permissions can protect fields. Dynamic Data Masking changes query
presentation for some users; it is not a substitute for `DENY SELECT`, and
users with broader permissions or inference queries may recover information.

## Bypasses and alternate paths

Inventory and test:

- `sysadmin`, database owner/`dbo`, fixed roles, `CONTROL`, `IMPERSONATE`,
  ownership changes, and permission to alter security policies/functions;
- policy `STATE = OFF`, disabled predicates, overly broad predicate branches,
  and a runtime principal that can set arbitrary trusted context;
- ownership chains, `EXECUTE AS OWNER`, certificate-signed modules, dynamic
  SQL, cross-database ownership chaining, and `TRUSTWORTHY`;
- linked servers, external tables, CLR, SQL Agent, Service Broker, external
  scripts, `xp_cmdshell`, OLE automation, bulk operations, and import/export;
- temporal history, CDC tables/functions, Change Tracking, replication,
  readable secondaries, Query Store/statistics/metadata, backups, and restored
  databases;
- Azure data-plane versus control-plane administrators and diagnostic/export
  destinations.

Microsoft documents error-based inference and statistics caveats for RLS.
Behavioral tests therefore include aggregate, divide/error, metadata, and
statistics paths available to the actual runtime/reporting roles.

## Stored code and execution context

Modules can execute as `CALLER`, `SELF`, `OWNER`, a named database user, or a
login where supported. Ownership chaining skips downstream permission checks
for same-owner objects referenced statically; dynamic SQL starts a new
permission check and does not simply inherit the static chain.

For each procedure, function, trigger, view, assembly, Agent job, and signed
module:

- record owner, declared execution context, signatures, caller grants, and
  downstream objects;
- inspect `IMPERSONATE`, `AUTHENTICATE`, `TRUSTWORTHY`, cross-database chaining,
  and database-owner login;
- prove dynamic SQL and nested module behavior under the least-privileged
  caller;
- test that tenant context cannot be replaced or omitted inside the module;
- identify server-capable features such as CLR `UNSAFE`, external scripts,
  linked servers, Agent proxies, and `xp_cmdshell`.

Prefer a narrowly certificate-signed module over making the database
`TRUSTWORTHY` or granting broad ownership/impersonation. That is a design
preference, not a finding until a reachable escalation path is shown.

Rule anchors:

- `db.execution.sqlserver.execute-as-authority`
- `db.execution.sqlserver.ownership-chain-expansion`
- `db.execution.sqlserver.trustworthy-cross-database`

## Migration and security drift

Compare catalogs after fresh deployment, every supported upgrade/rollback, and
restore. Look for:

- a protected table with no security predicate or only a filter/no required
  block predicate;
- `ALTER SECURITY POLICY ... WITH (STATE = OFF)`, dropped predicates, or
  predicate target changes;
- new partition/history/staging tables, synonyms, views, or external tables
  outside the policy;
- a tenant column made nullable/mutable or removed from a unique key;
- a DACPAC publish profile dropping/recreating users, grants, signatures, audit
  specs, or policy objects;
- owner changes and migration grants that make runtime `dbo`/owner;
- database compatibility, containment, or trustworthy/chaining changes.

Text order alone cannot establish final DACPAC state. Parse the model or compare
the repository-owned deployed catalog. Live Azure drift remains an open
question, never a static clearance.

## Transactions, concurrency, and integrity

Inventory keys, tenant-qualified unique indexes, foreign/check constraints,
triggers, indexed/computed columns, constraint trust state, isolation settings,
and row-versioning. `WITH NOCHECK`, disabled/untrusted constraints, and a
successful migration are not equivalent to validated existing data.

Exercise:

- read-check-write under the declared isolation level;
- tenant-key updates through `UPDATE`, `MERGE`, triggers, views, and procedures;
- race pairs under `READ COMMITTED`, snapshot/RCSI, repeatable read, and
  serializable where the design relies on them;
- partial failure and retry for batch/`MERGE`;
- deadlock retry with actor/tenant context re-established.

The adapter records engine guarantees. Cross-service workflow atomicity remains
business logic.

## CDC, replication, and history

Treat each as a new read surface:

- transactional/snapshot/merge replication and distribution databases;
- CDC capture instances, change tables, functions, gating roles, and cleanup;
- Change Tracking metadata and version-retention behavior;
- system-versioned temporal current/history tables and `FOR SYSTEM_TIME`;
- readable availability replicas, geo-replicas, export/BACPAC, and ETL.

RLS on the source table is not proof that a CDC change table, temporal history
table, distributor, secondary, or exported copy applies the same predicate.
Test its exact principal and query path. In Synapse/Fabric variants that lack
the same block-predicate behavior, this adapter reports `NOT_ASSESSED`.

## Backup and restore

Map native backup/restore, copy-only backups, log backups, BACPAC/DACPAC,
Azure automated backup/PITR, geo-restore, database copy, and clone workflows.
Compare:

- database users, roles, grants/denies, ownership, policies and predicate
  functions, signatures, assemblies, and audit specs;
- server logins/SIDs, credentials, Agent jobs/proxies, linked servers, server
  audits, endpoints, and certificates that are outside a database backup;
- external/Entra identities and managed-service administrators;
- database master keys, TDE/Always Encrypted dependencies, without duplicating
  crypto/cloud ownership.

A restored database user can be orphaned from its login. A successful row-count
restore is therefore not a security restore.

## Audit and attribution

SQL Server Audit connects a server audit target to server and/or database audit
specifications. Azure SQL adds platform routing and service-specific controls.
Verify:

- enabled audit/specification state and the actual action groups/actions;
- target protection, retention handoff, and principals able to alter/disable
  audit;
- configured failure behavior and what occurs if the target is unavailable;
- successful and denied data access, policy/admin changes, backup/restore, and
  impersonation;
- original login, database user, session-context application actor/tenant,
  effective execution context, target, and outcome.

Extended Events, Query Store, application logs, and Azure Activity logs are not
automatically substitutes for data-plane security audit. A shared SQL login
without protected application identity provides service attribution, not
end-user attribution.

Rule anchors:

- `db.audit.sqlserver.audit-specification-coverage`
- `db.audit.sqlserver.pooled-actor-attribution`
- `db.audit.sqlserver.audit-administration`

## Availability and resource governance

Deployment-sensitive controls include Resource Governor, workload groups,
Azure service objectives/resource limits, query/lock timeouts, connection-pool
bounds, `MAXDOP`, memory-grant controls, deadlock priority, and application
cancellation. Query Store observes; it does not by itself cap work.

Use bounded tests for:

- expensive predicate functions, scans, regex/JSON/spatial operations,
  aggregates, recursive queries, and memory grants;
- blocking, deadlocks, long transactions, tempdb pressure, and pool exhaustion;
- CDC/temporal/history growth, version store pressure, Agent job overlap, and
  replica lag;
- error-based probes that amplify RLS inference.

Do not file "Resource Governor absent" on Azure SQL or an edition that uses
different service governance. Establish the reachable workload and budget.

## Unsupported guarantees and NOT ASSESSED cases

- Dynamic Data Masking is not a field-authorization boundary.
- A filter predicate does not supply all required write blocking.
- A policy administrator, `sysadmin`, or other alter-capable principal cannot
  be constrained by a policy it can disable.
- `SESSION_CONTEXT` does not authenticate an end user and cannot make a forged
  initial value trustworthy.
- RLS does not automatically secure CDC, temporal history, replication,
  statistics/error side channels, export, or backup copies.
- A database backup cannot by itself promise to restore server-scoped logins,
  jobs, credentials, endpoints, audits, or external identity configuration.
- SQL Server/Azure SQL semantics do not clear Synapse or Fabric variants.

An unsupported capability is actionable only when the system requires or
claims it and no proved external alternative exists.

## Static discovery sweeps

Every hit is a candidate to read:

```bash
rg -n --hidden 'CREATE\s+SECURITY\s+POLICY|ALTER\s+SECURITY\s+POLICY|CREATE\s+FUNCTION.*RETURNS\s+TABLE' .
rg -n --hidden 'FILTER\s+PREDICATE|BLOCK\s+PREDICATE|STATE\s*=\s*(ON|OFF)|SCHEMABINDING' .
rg -n --hidden 'SESSION_CONTEXT\s*\(|sp_set_session_context|@read_only' .
rg -n --hidden 'EXECUTE\s+AS|REVERT|AUTHENTICATE|IMPERSONATE|ADD\s+SIGNATURE|CERTIFICATE' .
rg -n --hidden 'TRUSTWORTHY|DB_CHAINING|cross\s+db\s+ownership\s+chaining|xp_cmdshell|EXTERNAL\s+ACCESS|UNSAFE' .
rg -n --hidden 'GRANT\s+CONTROL|DENY\s+|db_owner|db_securityadmin|db_ddladmin|sysadmin' .
rg -n --hidden 'SYSTEM_VERSIONING|HISTORY_TABLE|FOR\s+SYSTEM_TIME|CHANGE_TRACKING|sys\.sp_cdc_|cdc\.' .
rg -n --hidden 'CREATE\s+(SERVER\s+)?AUDIT|AUDIT\s+SPECIFICATION|ON_FAILURE|is_state_enabled' .
rg -n --hidden 'CREATE\s+LOGIN|CREATE\s+USER|FROM\s+EXTERNAL\s+PROVIDER|CREATE\s+ROLE|ALTER\s+AUTHORIZATION' .
rg -n --hidden 'BACKUP\s+(DATABASE|LOG)|RESTORE\s+DATABASE|SqlPackage|\.dacpac|\.bacpac' .
```

Do not infer final policy state from one migration fragment. Resolve `CREATE`,
`ALTER`, DACPAC model state, deployment variables, and target platform. Dynamic
SQL and live Azure settings remain named gaps.

## Proof and conformance recipe

Use the contract matrix against a repository-started ephemeral SQL Server at
T1 or a user-approved loopback engine at T2. Azure-only behavior that cannot be
reproduced locally is `NOT_ASSESSED`, not emulated as boxed SQL Server.

1. Record product version, edition, engine edition, compatibility level,
   containment, principals/roles, effective permissions, owners, policy state,
   predicates, modules/signatures, temporal/CDC, and audit catalogs.
2. Seed two tenant canaries and verify an administrator control sees both.
3. As the exact runtime user, test select-by-id, list, aggregate/error,
   insert, update, tenant-key mutation, `MERGE`, batch, delete, view, stored
   module, temporal/history, CDC, and permitted metadata.
4. Test null/forged `SESSION_CONTEXT`, set it read-only, return the connection to
   the pool, and borrow as the opposite tenant in both orders and after error.
5. Exercise caller/owner/module-signed controls and prove dynamic SQL's actual
   downstream permissions. Keep server-capable features disabled unless the
   repository already owns a safe fixture.
6. Compare fresh/upgrade/rollback catalogs and a repository-owned restored
   copy, including server-scoped omissions.
7. Assert persisted rows and audit entries, not only T-SQL error text.

Catalog anchors include `sys.server_principals`, `sys.database_principals`,
`sys.server_role_members`, `sys.database_role_members`,
`sys.server_permissions`, `sys.database_permissions`, `sys.objects`,
`sys.sql_modules`, `sys.security_policies`, `sys.security_predicates`,
`sys.tables`, `sys.periods`, CDC catalogs, and audit catalogs/functions.

## Known false positives

- A predicate is defined in one project file and attached/enabled in the final
  DACPAC model or a later migration before access is granted.
- A named `dbo`/owner identity is deployment-only and unreachable by runtime;
  establish role and impersonation edges before filing.
- `EXECUTE AS OWNER` or module signing deliberately exposes one narrow
  operation, and the two-principal proof shows no authority expansion.
- `SESSION_CONTEXT` is set through a trusted middleware from authenticated
  state on every checkout and direct native access is prevented by a separate
  proved boundary.
- Temporal/CDC is disabled or the table is demonstrably single-tenant; mark the
  operation not applicable rather than missing.
- Dynamic Data Masking is present for accidental-display reduction while
  column permissions still enforce the real boundary.
- Resource Governor is unavailable or irrelevant to the identified deployment,
  and equivalent provider/workload limits are tested.
- A `DENY` or broad role name appears only in a negative migration/test fixture.

## Fixture concepts

### Vulnerable

`V-MSSQL-001`: enabled filter predicate but no insert block predicate; mutable
tenant session context; runtime membership in `db_owner`; policy left
`STATE = OFF` after an upgrade; `EXECUTE AS OWNER` procedure using dynamic SQL;
foreign tenant in temporal/CDC data; audit spec misses selects and can be
disabled by runtime; restored contained users do not match server login paths.

Expected rule anchors:

- `db.authorization.sqlserver.filter-block-completeness`
- `db.authorization.sqlserver.tenant-context-lifecycle`
- `db.authorization.sqlserver.security-policy-bypass`
- `db.execution.sqlserver.execute-as-authority`
- `db.copy.sqlserver.temporal-cdc-policy-gap`
- `db.audit.sqlserver.audit-specification-coverage`
- `db.restore.sqlserver.server-principal-gap`

### Clean

`C-MSSQL-001`: separate owner/migrator/runtime users; enabled filter and required
block predicates; immutable trusted context lifecycle; no runtime policy-alter
or owner path; narrowly signed module; tenant key denied and behaviorally
tested; temporal/CDC separately authorized; audit records original and
effective actor; restored database plus server dependencies compare cleanly;
bounded workload controls. Own-tenant allow and foreign-tenant deny/empty must
both pass.

## Official sources

All links verified `2026-07-28`:

- [SQL Server Row-Level Security](https://learn.microsoft.com/en-us/sql/relational-databases/security/row-level-security?view=sql-server-ver17)
- [SQL Server permissions hierarchy](https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-hierarchy-database-engine?view=sql-server-ver17)
- [`EXECUTE AS`](https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-clause-transact-sql?view=sql-server-ver17)
- [`sp_set_session_context`](https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-set-session-context-transact-sql?view=sql-server-ver17)
- [Ownership chains](https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#ownership-chains)
- [Dynamic Data Masking](https://learn.microsoft.com/en-us/sql/relational-databases/security/dynamic-data-masking?view=sql-server-ver17)
- [Temporal table security](https://learn.microsoft.com/en-us/sql/relational-databases/tables/temporal-table-security?view=sql-server-ver17)
- [Change Data Capture administration](https://learn.microsoft.com/en-us/sql/relational-databases/track-changes/administer-and-monitor-change-data-capture-sql-server?view=sql-server-ver17)
- [SQL Server Audit](https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver17)
- [Azure SQL auditing](https://learn.microsoft.com/en-us/azure/azure-sql/database/auditing-overview?view=azuresql)
- [Troubleshoot orphaned users](https://learn.microsoft.com/en-us/sql/sql-server/failover-clusters/troubleshoot-orphaned-users-sql-server?view=sql-server-ver17)
- [Resource Governor](https://learn.microsoft.com/en-us/sql/relational-databases/resource-governor/resource-governor?view=sql-server-ver17)
