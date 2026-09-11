# Oracle Database adapter

Adapter ID: `oracle`

Deployment variants: `oracle-self-managed`, `oracle-rac`,
`oracle-autonomous-database`, `oracle-managed`

Verified: `2026-07-28`

This adapter covers Oracle Database only when version, edition, CDB/PDB scope,
and licensed/enabled security options are identified. Oracle-compatible
products, client libraries, and SQL dialects select `inventory-only`. Virtual
Private Database (VPD), Oracle Label Security (OLS), Database Vault, Real
Application Security (RAS), Data Redaction, and Autonomous Database are
different capabilities; their names are not interchangeable.

## Engine, version, edition, and deployment detection

Strong signals:

- a pinned Oracle Database Free/Enterprise image or exact server installation
  metadata;
- committed output from `V$VERSION`, `PRODUCT_COMPONENT_VERSION`,
  `V$OPTION`, `DBA_REGISTRY`, or `CDB_REGISTRY`;
- an Oracle cloud resource that identifies Autonomous/database service,
  workload, version, and edition/options;
- SQL*Plus/SQLcl migrations using Oracle catalog/package APIs such as
  `DBMS_RLS`, `DBMS_FGA`, application contexts, or PL/SQL packages.

`ojdbc`, `oracledb`, OCI clients, TNS syntax, Prisma/ORM providers, `.dmp`, or
PL/SQL-like source is weak evidence. Record exact release/update, edition,
license/options, CDB root/PDB, RAC/Data Guard/Autonomous/provider topology, and
compatibility settings.

`DBMS_RLS` VPD is Enterprise Edition-only in current Oracle documentation.
OLS, Database Vault, RAS, advanced audit/export, Flashback, Resource Manager,
and managed-service capabilities have their own gates. If edition/option or PDB
scope is unknown, the dependent rule is `NOT_ASSESSED`.

## Capability declaration

| Capability ID | Value | Conditions |
|---|---|---|
| `principal-authentication` | `NATIVE` | Local/common/external/global/proxy users and optional RAS application users; deployment must be known. |
| `role-and-object-grants` | `NATIVE` | System/object privileges, roles, `PUBLIC`, common/local scope, proxy, secure application roles, and administrative privilege. |
| `record-read-authorization` | `UNKNOWN` | `NATIVE` with licensed/enabled VPD/OLS/RAS; otherwise views/topology/external enforcement. |
| `record-write-authorization` | `UNKNOWN` | VPD statement types and `update_check`, OLS/RAS; exact option and policy required. |
| `column-or-property-authorization` | `NATIVE` | Column privileges and views; column VPD/redaction are option/semantic-sensitive and not equivalent. |
| `tenant-session-context` | `NATIVE` | Secure application contexts set by a trusted package; `CLIENT_IDENTIFIER` alone is not trusted authorization. |
| `stored-code-execution-context` | `NATIVE` | Definer/invoker rights, `INHERIT PRIVILEGES`, roles granted to program units, triggers, Java, and external jobs. |
| `schema-integrity` | `NATIVE` | Constraints and validation/trust state, triggers, virtual columns, and types. |
| `transactional-integrity` | `NATIVE` | Transactions, locking, selectable isolation, savepoints, and distributed transactions. |
| `resource-governance` | `NATIVE` | Database Resource Manager/profiles when configured; Autonomous/provider behavior differs. |
| `replication-cdc-authorization` | `COMPOSABLE` | Data Guard, redo/LogMiner, GoldenGate/XStream, materialized views, and subscribers each need authorization. |
| `history-authorization` | `COMPOSABLE` | Flashback/undo, Flashback Data Archive, temporal/application history, and audit are separate read paths. |
| `backup-policy-portability` | `COMPOSABLE` | RMAN, Data Pump, PDB clone, and provider restore preserve different database/external state. |
| `security-audit` | `NATIVE` | Unified Auditing and FGA, with version/mode/policy and destination operations assessed. |
| `policy-catalog-introspection` | `NATIVE` | DBA/CDB views for users, roles, grants, RLS, contexts, program units, audit, resource, history, and replication. |

For a known edition without VPD/OLS/RAS, record authorization capability as
`COMPOSABLE` or `EXTERNAL_ONLY` according to the proved design. Do not leave
`UNKNOWN` after the discriminator is established.

## Principal and grant model

Build effective authority from:

- common/local users and roles, PDB/root scope, externally/globally identified
  users, proxy users, RAS application users, and database links;
- object and system privileges, `ANY` privileges, `ADMIN OPTION`,
  `GRANT OPTION`, `PUBLIC`, default/enabled/secure application roles, and roles
  granted to program units;
- schema ownership (a user owns its schema), definer/invoker program units,
  `INHERIT PRIVILEGES`/`INHERIT ANY PRIVILEGES`, and code-based access control;
- `SYSDBA`, `SYSOPER`, `SYSBACKUP`, `SYSDG`, `SYSKM`, `SYSRAC`, `DBA`,
  `EXEMPT ACCESS POLICY`, audit, Data Pump, scheduler, Java, external-job, and
  database-link capabilities;
- Database Vault realms/command rules and OLS/RAS roles where enabled.

Do not reduce Oracle to schema grants. Common grants with `CONTAINER=ALL`, an
`ANY` privilege, `PUBLIC`, proxy connection, definer routine, or database link
can add paths invisible in the table ACL.

Runtime, schema owner/migrator, PDB administrator, CDB administrator, reporting,
replication, backup, audit, scheduler, and human support are separate actors.

## Native authorization and tenant controls

VPD associates a PL/SQL policy function with a table, view, or synonym through
`DBMS_RLS`. The function returns a predicate added at parse time. Assess:

- policy enabled state, object and policy group, statement types, policy type,
  namespace/attribute, relevant columns, and `update_check`;
- `SELECT`, `INSERT`, `UPDATE`, `DELETE`, index/direct/bulk, view, synonym,
  partition, and stored-code paths;
- dynamic/context-sensitive versus static/shared policy caching;
- null/unset/malformed application context;
- zero-length predicate behavior: Oracle documents it as no restriction;
- column-relevant policy behavior. `ALL_ROWS` masks selected sensitive columns
  with null for supported selects; it is not ordinary row filtering or a
  write-control;
- `SYS` and `EXEMPT ACCESS POLICY` bypass.

Rule anchors:

- `db.authorization.oracle.vpd-policy-completeness`
- `db.authorization.oracle.vpd-zero-length-predicate`
- `db.authorization.oracle.vpd-cache-context-scope`
- `db.authorization.oracle.vpd-bypass`
- `db.authorization.oracle.secure-application-context`

A secure application context names a trusted package that sets values. Test
that runtime cannot call or spoof the setter for another tenant. Values from
`DBMS_SESSION.SET_IDENTIFIER`/`CLIENT_IDENTIFIER` improve attribution but are
not authorization unless a trusted boundary binds them to the authenticated
actor.

OLS labels, RAS ACL/data-security policies, and Database Vault realms have
their own catalogs and bypasses. If detected, use the option-specific branch;
do not translate them into VPD rules. Data Redaction reduces returned
presentation under defined conditions but is not a substitute for object/column
authorization.

Without a licensed native policy, a view/routine/per-schema/per-PDB design can
be `COMPOSABLE`; direct base-object and alternate-path access must be removed
and behaviorally tested.

## Bypasses and alternate paths

Inventory and test:

- `SYS`, administrative privilege connections, `DBA`, `ANY` privileges,
  `EXEMPT ACCESS POLICY`, policy/package alteration, and database/PDB ownership;
- definer units, invoker units with inheritance, program-unit roles, views and
  `BEQUEATH`, triggers, schedulers/jobs, Java, external procedures, libraries,
  directories, database links, and external tables;
- direct path/bulk/Data Pump operations, materialized views, result caches,
  synonyms, partitions, and editioned objects;
- redo/archive logs, LogMiner, GoldenGate/XStream, Data Guard standbys,
  replicas, RMAN, Data Pump, PDB clones/refreshable clones, and Autonomous
  exports;
- Flashback Query, Flashback Data Archive, undo/history tables, recycle bin,
  unified/FGA audit, and diagnostics;
- Database Vault/OLS/RAS administrative bypass paths where enabled.

A realm or VPD policy does not prove a redo reader, backup operator, Data Pump
user, database link, history reader, or restored clone sees the same scope.

## Stored code and execution context

PL/SQL program units default to definer's rights. `AUTHID CURRENT_USER` selects
invoker rights. Definer-rights code relies on directly granted owner
privileges, while invoker-rights code can use the invoker's privileges/roles
subject to call-chain and `INHERIT [ANY] PRIVILEGES` rules. Triggers execute
with definer authority.

For every package/procedure/function/trigger/view/scheduler job/Java or external
unit:

- record owner, `AUTHID`, `BEQUEATH`, program-unit roles, caller `EXECUTE`,
  inheritance grants, direct owner grants, and downstream objects;
- schema-qualify references and inspect invoker-dependent name resolution;
- test dynamic SQL, database links, directories/files, Java permissions,
  external procedures/jobs, autonomous transactions, and nested call chains;
- prove the routine cannot set another tenant's secure context or return/write
  foreign rows;
- compare invalid/recompiled/editioned objects and owner/grant drift.

Rule anchors:

- `db.execution.oracle.definer-rights-authority`
- `db.execution.oracle.invoker-inherit-privileges`
- `db.execution.oracle.external-code-path`
- `db.execution.oracle.secure-context-setter`

## Migration and security drift

Compare dictionary state after fresh install, supported upgrade/rollback, PDB
plug/clone, and restore:

- new objects lack VPD/OLS/RAS/realm policy or are created in the wrong policy
  group/PDB;
- `DBMS_RLS.ENABLE_POLICY` disables a policy, statement types/update check
  narrow, or static/shared caching no longer matches context behavior;
- a policy function returns empty predicate on null/error path;
- secure application context changes trusted package, or runtime gains setter
  execution;
- owner, `AUTHID`, `BEQUEATH`, program-unit roles, direct grants, inheritance,
  `PUBLIC`, `ANY`, common/local scope, or proxy grants change;
- constraints become disabled, `NOVALIDATE`, `RELY`, or deferrable in a way the
  invariant did not expect;
- audit policy enablement, Resource Manager plan, Database Vault/OLS/RAS option,
  link/directory/scheduler/Java, redo/history, or backup settings drift.

PL/SQL calls may be conditional and idempotent; a text hit is not final state.
Autonomous/provider console drift remains unassessed without committed
evidence.

## Transactions, concurrency, and integrity

Record keys, tenant-qualified uniqueness, FK/check constraints, enabled and
validated/rely state, deferrability, triggers, indexes, and isolation.
Exercise:

- read-check-write at `READ COMMITTED`, `SERIALIZABLE`, or read-only semantics
  actually selected;
- `SELECT ... FOR UPDATE`, deadlock/serialization retry, and context reset;
- tenant-key mutation through DML, `MERGE`, views, packages, triggers, direct
  path, and bulk APIs;
- implicit DDL commits during migration;
- autonomous transactions that persist an audit/data side effect when the
  caller transaction rolls back;
- distributed transactions/database links and partial failure where used.

Oracle transaction support does not prove an application workflow chose the
right boundary; the latter remains business logic.

## CDC, replication, and history

Map:

- online/archived redo, LogMiner, XStream, GoldenGate extract/trails/replicat;
- Data Guard physical/logical standby and Active Data Guard readers;
- materialized views/logs, database links, AQ/streaming connectors, and exports;
- Flashback Query, undo, Flashback Data Archive, recycle bin, and application
  history;
- RAC instances and PDB clones/refreshable copies.

Verify initial load and ongoing change, each operator/subscriber credential,
trail/log/standby reader, promotion/failover, and policy on the destination.
VPD/OLS/RAS on a source table is not assumed to filter redo, trails, standby
administrators, materialized copies, or Flashback history.

## Backup and restore

Map RMAN physical backup, control/SPFILE/password and recovery artifacts as
applicable, archive logs, Data Pump schema/full/table export, transportable
tablespaces, PDB clone/unplug/plug, Autonomous/provider backup/PITR, and standby
promotion.

The restore oracle compares:

- common/local users/roles, direct/system/object grants, `PUBLIC`, proxies,
  administrative privilege paths, and external identities;
- VPD policy/groups/functions, application contexts/trusted packages,
  OLS/RAS/Database Vault state, and bypass privileges;
- owners, `AUTHID`, `BEQUEATH`, program-unit roles, Java/external/scheduler
  objects, links, directories, and credentials;
- constraints, audit policies/mode, Resource Manager, history/replication, and
  canary behavior;
- wallets/keystores and provider identity dependencies as a crypto/cloud
  handoff, not a duplicate finding.

Data Pump include/exclude scope and privileges are not equivalent to RMAN.
Restoring rows successfully does not prove a security-equivalent database.

## Audit and attribution

Unified Auditing and Fine-Grained Auditing are native but policy-driven. Verify:

- unified mode/version, enabled policies, actions/privileges/objects,
  `WHENEVER SUCCESSFUL`/`NOT SUCCESSFUL`, users/roles/context conditions, and
  PDB/common scope;
- FGA predicates/columns/handlers and VPD predicate capture where required;
- database user, proxy/application/end-user identity, client identifier,
  effective definer, PDB/service, object/action/outcome, and transaction;
- mandatory/admin/policy changes, backup/export, replication, scheduler,
  Database Vault/OLS/RAS, and denied access;
- `AUDIT_ADMIN`/`AUDIT_VIEWER`, purge/archive controls, destination loss, and
  tamper authority;
- sensitive bind/SQL text minimization.

A pooled service account with caller-set client identifier is not reliable
end-user attribution until the application binding and reset are tested.

## Availability and resource governance

Assess active CDB/PDB Database Resource Manager plans, consumer-group mapping,
profiles/session limits, services, statement cancellation/call timeouts,
parallelism, temp/undo, PGA, queueing, provider service limits, and pool bounds.
Resource Manager exists but is not active merely because a plan was created.

Use bounded tests for:

- expensive VPD policy functions, per-row PL/SQL, regex/JSON/XML/spatial,
  recursive/hierarchical queries, sorts, parallel work, and temp spill;
- locks, long transactions, deadlocks, session/pool exhaustion, scheduler
  overlap, and autonomous work;
- undo/Flashback/redo/archive/GoldenGate/Data Guard lag and audit growth;
- PDB/noisy-neighbor and RAC/failover behavior under the declared budget.

Missing Resource Manager configuration is not a finding without a reachable
workload and requirement.

## Unsupported guarantees and NOT ASSESSED cases

- `DBMS_RLS` VPD is not available in every Oracle edition; an unknown edition
  or licensed option is `NOT_ASSESSED`.
- VPD does not constrain `SYS` or a user with `EXEMPT ACCESS POLICY`.
- A zero-length VPD predicate means no restriction; it is not fail-closed.
- `CLIENT_IDENTIFIER`, ordinary application context, or a setter callable by
  runtime does not authenticate a tenant.
- Data Redaction is not object/column authorization; system-versioned/Flashback
  data is not an immutable end-user audit.
- VPD/OLS/RAS policy on a source does not automatically protect redo,
  GoldenGate trails, standbys, history, Data Pump/RMAN, links, or clones.
- Without Database Vault or an equivalent external separation, a sufficiently
  privileged database administrator can change native policy.
- Autonomous/provider-only behavior that cannot be reproduced or established
  from committed artifacts remains `NOT_ASSESSED`.

An unavailable option is actionable only when a required guarantee lacks a
tested view/schema/PDB/application/topology alternative.

## Static discovery sweeps

Every hit is a candidate to read:

```bash
rg -n --hidden 'DBMS_RLS\.(ADD_POLICY|ENABLE_POLICY|DROP_POLICY|ADD_GROUPED_POLICY)|EXEMPT\s+ACCESS\s+POLICY' .
rg -n --hidden 'CREATE\s+CONTEXT|USING\s+[A-Za-z0-9_$#]+|DBMS_SESSION\.(SET_CONTEXT|SET_IDENTIFIER)|SYS_CONTEXT\s*\(' .
rg -n --hidden 'AUTHID\s+(DEFINER|CURRENT_USER)|BEQUEATH\s+(DEFINER|CURRENT_USER)|INHERIT\s+(ANY\s+)?PRIVILEGES' .
rg -n --hidden 'GRANT\s+.*\s+TO\s+PUBLIC|GRANT\s+.*ANY|WITH\s+(ADMIN|GRANT)\s+OPTION|CONTAINER\s*=\s*(ALL|CURRENT)' .
rg -n --hidden 'CREATE\s+(DATABASE\s+LINK|DIRECTORY|LIBRARY|JAVA|JOB)|DBMS_SCHEDULER|PRAGMA\s+AUTONOMOUS_TRANSACTION' .
rg -n --hidden 'DBMS_REDACT|SA_SYSDBA|LBACSYS|DVSYS|DBMS_MACADM|XS_SECURITY_CLASS|XS_ACL' .
rg -n --hidden 'ENABLE\s+NOVALIDATE|DISABLE\s+NOVALIDATE|\bRELY\b|DEFERRABLE|SET\s+CONSTRAINTS' .
rg -n --hidden 'FLASHBACK|FOR\s+SYSTEM_TIME|DBMS_FLASHBACK|DBMS_LOGMNR|GOLDENGATE|XSTREAM|MATERIALIZED\s+VIEW\s+LOG' .
rg -n --hidden 'CREATE\s+AUDIT\s+POLICY|AUDIT\s+POLICY|DBMS_FGA\.ADD_POLICY|UNIFIED_AUDIT_TRAIL|AUDIT_TRAIL' .
rg -n --hidden 'DBMS_RESOURCE_MANAGER|RESOURCE_MANAGER_PLAN|CREATE\s+PROFILE|SESSIONS_PER_USER|CPU_PER_' .
rg -n --hidden 'expdp|impdp|DBMS_DATAPUMP|rman|BACKUP\s+DATABASE|RECOVER\s+DATABASE|CREATE\s+PLUGGABLE\s+DATABASE' .
```

Resolve PL/SQL calls, version/edition/options, final dictionary state, CDB/PDB
scope, roles and direct grants. Static text never proves an enabled policy.

## Proof and conformance recipe

Use a repository-started disposable Oracle fixture at T1. An accepted
authenticated operator statement naming the target, scope, and T2 loopback
launch is authority without another prompt. Execute it only through a matching
implemented controller; otherwise record `UNPROVEN` with the technical transport
gap. Never infer an Autonomous/managed database destination from configuration.
If the required edition/option is unavailable locally, keep that behavior
`NOT_ASSESSED`.

1. Record exact version/edition/options, CDB/PDB/service, users/roles/grants,
   administrative/bypass privileges, VPD/contexts, program units, constraints,
   history/replication, audit, and resource catalogs.
2. Seed tenant-A/B canaries and prove an administrative control sees both.
3. As the exact runtime principal, test read-by-id, list, aggregate/error,
   insert, update, tenant-key mutation, `MERGE`, delete, view/synonym/package,
   bulk/direct, partition, Flashback/history, link, and permitted metadata.
4. Test null/empty/forged secure context; same pooled session A then B and B
   then A; failed call/retry; trusted setter invocation; VPD static/shared cache.
5. Exercise invoker/definer, inheritance, program-unit role, `PUBLIC`/`ANY`,
   owner/admin, `EXEMPT ACCESS POLICY`, audit, backup, and replication controls
   using bounded synthetic data.
6. Compare fresh/upgrade/rollback/PDB clone and repository-owned RMAN/Data Pump
   restore state where the existing runner supports it.
7. Assert persisted rows and audit records with original/effective actor, not
   only ORA error text.

Catalog anchors include `CDB_`/`DBA_USERS`, roles/role privileges,
system/table/column privileges, policies/policy groups/contexts, procedures/
arguments/source, triggers, constraints, audit policies/enabled policies/
unified trail, resource plans/groups, Flashback archives, database links,
directories, scheduler, and option/registry views. Missing dictionary access is
an explicit unassessed leg.

## Known false positives

- A protected object is in a provably single-tenant PDB/schema with no
  cross-principal path; VPD is not required by name.
- VPD is created through a package/helper and final dictionary comparison shows
  it enabled with complete statement/update behavior.
- A definer package is deliberately narrow, owner privileges are direct and
  least, caller execute is constrained, and two-principal proof passes.
- `CLIENT_IDENTIFIER` is used only for attribution while authorization uses a
  secure trusted context or distinct database principal.
- `SYS`/administrative bypass exists but is not reachable from the application;
  inventory it without inventing runtime reachability.
- Data Redaction supplements real column/object grants rather than replacing
  them.
- `NOVALIDATE` is a deliberate migration state followed by validation before
  access is granted; resolve final state.
- VPD/OLS/Database Vault/RAS syntax is present only in a licensed-option
  compatibility script not deployed to the profiled store.

## Fixture concepts

### Vulnerable

`V-ORACLE-001`: shared runtime can call tenant context setter; VPD function
returns empty predicate on null and is incorrectly shared-static; no
`update_check`; runtime inherits `EXEMPT ACCESS POLICY`; high-privilege definer
package/database link; constraint is `NOVALIDATE`; Flashback/GoldenGate/Data
Pump exposes both tenants; unified audit policy exists but is not enabled;
restored PDB loses policy group/context binding.

Expected rule anchors:

- `db.authorization.oracle.vpd-zero-length-predicate`
- `db.authorization.oracle.vpd-cache-context-scope`
- `db.authorization.oracle.secure-application-context`
- `db.authorization.oracle.vpd-bypass`
- `db.execution.oracle.definer-rights-authority`
- `db.copy.oracle.flashback-replication-policy-gap`
- `db.audit.oracle.unified-policy-enablement`

### Clean

`C-ORACLE-001`: exact Enterprise/options branch; distinct runtime/migrator/
owner/admin identities; complete enabled VPD with trusted secure context and
write check; no runtime bypass; constrained invoker/definer/inheritance paths;
validated tenant-aware constraints; history/redo/backup independently secured;
PDB/RMAN/Data Pump restore is policy-equivalent; unified audit preserves
original/effective actor; active bounded Resource Manager plan. Both
own-tenant allow and foreign-tenant deny/empty pass.

## Official sources

All links verified `2026-07-28`:

- [Oracle `DBMS_RLS` and VPD semantics](https://docs.oracle.com/en/database/oracle/oracle-database/26/arpls/DBMS_RLS.html)
- [Oracle Virtual Private Database](https://docs.oracle.com/en/database/oracle/oracle-database/26/dbseg/using-oracle-vpd-to-control-data-access.html)
- [Definer's and invoker's rights](https://docs.oracle.com/en/database/oracle/oracle-database/26/dbseg/managing-security-for-definers-rights-and-invokers-rights.html)
- [Oracle application contexts](https://docs.oracle.com/en/database/oracle/oracle-database/26/dbseg/using-application-contexts-to-retrieve-user-information.html)
- [Oracle Database Vault](https://docs.oracle.com/en/database/oracle/oracle-database/26/dvadm/)
- [Oracle Label Security](https://docs.oracle.com/en/database/oracle/oracle-database/26/olsag/)
- [Introduction to Unified Auditing](https://docs.oracle.com/en/database/oracle/oracle-database/26/dbseg/introduction-to-auditing.html)
- [Creating custom unified audit policies](https://docs.oracle.com/en/database/oracle/oracle-database/26/dbseg/creating-custom-unified-audit-policies.html)
- [Oracle Flashback Data Archive](https://docs.oracle.com/en/database/oracle/oracle-database/26/adfns/flashback.html)
- [Oracle Data Pump overview](https://docs.oracle.com/en/database/oracle/oracle-database/26/sutil/oracle-data-pump-overview.html)
- [RMAN backup concepts](https://docs.oracle.com/en/database/oracle/oracle-database/26/bradv/rman-backup-concepts.html)
- [Oracle Database Resource Manager](https://docs.oracle.com/en/database/oracle/oracle-database/26/admin/managing-resources-with-oracle-database-resource-manager.html)
