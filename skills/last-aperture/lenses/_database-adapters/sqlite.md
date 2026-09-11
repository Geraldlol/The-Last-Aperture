# SQLite adapter

Adapter ID: `sqlite`

Deployment variants: `sqlite-embedded`, `sqlite-file`,
`sqlite-in-memory`

Verified: `2026-07-28`

SQLite is an embedded library and file format, not a database server with users,
roles, grants, RLS, a protected audit service, or a network control plane. Its
security principal is normally the process/OS identity that can open the file.
Application authentication, filesystem permissions, process sandboxing, and
per-connection callbacks are therefore part of the enforcement plane. SQLCipher
and provider-specific encrypted/replicated SQLite products select a separate
variant or `inventory-only`; they are not assumed to be SQLite core features.

## Engine, version, and deployment detection

Strong signals:

- an exact bundled/runtime SQLite library version or committed
  `sqlite_version()` output;
- a pinned native SQLite package/build configuration;
- `PRAGMA`/C API use plus a schema and connection code that establishes SQLite;
- ORM configuration explicitly selecting SQLite, when paired with the runtime
  binding used in deployment.

`sqlite3`, `better-sqlite3`, Python's `sqlite3`, Android/iOS wrappers, a `.db`
or `.sqlite` filename, or SQLite-flavored DDL alone does not establish the
runtime library version or compile options. The database file-format header is
not the engine version. Record:

- exact runtime version and `PRAGMA compile_options`;
- in-memory, temporary, on-disk, URI, immutable/read-only, or bundled seed file;
- process/container/mobile/desktop/server deployment and all filesystem paths;
- WAL/rollback journal, shared-cache, VFS, extensions, virtual tables, custom
  functions, serialization/backup, and encryption wrapper;
- every process/OS identity and copied/synced file path.

Version-gated features include STRICT tables, defensive/trusted-schema APIs,
limits, WAL fixes, and pragma behavior. An unknown runtime or wrapper remains
`NOT_ASSESSED` for gated claims.

## Capability declaration

| Capability ID | Value | Conditions |
|---|---|---|
| `principal-authentication` | `EXTERNAL_ONLY` | SQLite authenticates no users; process/OS/application identity is external. |
| `role-and-object-grants` | `UNSUPPORTED` | No persistent users, roles, or object ACL catalog exists in SQLite core. |
| `record-read-authorization` | `EXTERNAL_ONLY` | Application predicates, separate files/processes, or a connection authorizer; any direct file-capable connection is a bypass. |
| `record-write-authorization` | `EXTERNAL_ONLY` | Same boundary plus application logic/triggers; no native per-principal record policy. |
| `column-or-property-authorization` | `COMPOSABLE` | `sqlite3_set_authorizer()` can deny/NULL column reads per connection, but identity and direct-file closure are external. |
| `tenant-session-context` | `EXTERNAL_ONLY` | Application state only; no protected authenticated session context. |
| `stored-code-execution-context` | `UNSUPPORTED` | Triggers/views/UDFs run with the connection/process authority; no definer/invoker privilege separation. |
| `schema-integrity` | `NATIVE` | Keys/checks/STRICT/triggers plus per-connection foreign-key and pragma state. |
| `transactional-integrity` | `NATIVE` | SQLite transactions and locking; concurrency/journal mode and filesystem support matter. |
| `resource-governance` | `COMPOSABLE` | `sqlite3_limit`, progress/interrupt, heap/page limits, busy handling, and process limits. |
| `replication-cdc-authorization` | `UNSUPPORTED` | Core SQLite has no authenticated replication/CDC service. |
| `history-authorization` | `UNSUPPORTED` | Core SQLite has no temporal/history authorization primitive. |
| `backup-policy-portability` | `EXTERNAL_ONLY` | Backup API/VACUUM/file copies copy database content, not external filesystem/process policy. |
| `security-audit` | `EXTERNAL_ONLY` | Trace/update/authorizer/application logs are connection/process controls and can be bypassed by another file-capable process. |
| `policy-catalog-introspection` | `COMPOSABLE` | Schema, pragmas, compile options, and connection setup are inspectable; effective OS/application policy is external. |

## Principal and grant model

There is no SQLite account, role, `GRANT`, owner, or administrator inside the
file. Model:

- authenticated application user;
- application process identity and sandbox/container;
- OS user/group and directory/file ACL;
- code that can obtain an existing connection or open a new one;
- code that can read/copy/replace the main file, `-wal`, `-shm`, rollback
  journal, temp files, backups, or bundled seed;
- sync/backup/indexer/analytics processes and mobile/desktop user;
- extension, virtual-table, VFS, and custom-function code running in-process.

An application "read-only role" is an application role, not a SQLite
principal. A connection opened `SQLITE_OPEN_READONLY` is a useful capability
boundary only if that code cannot open a second writable connection and the OS
path is appropriately constrained. `PRAGMA query_only` is connection-local and
mutable by that same connection; it is not a persistent grant.

## Native authorization and tenant controls

SQLite has no native record policy. Supported designs include:

1. one file per tenant with filesystem/process capability separation;
2. one process/service per trust domain that mediates all access;
3. shared-file application predicates, explicitly `EXTERNAL_ONLY`;
4. a per-connection `sqlite3_set_authorizer()` that limits statements/objects,
   combined with an externally authenticated actor and closure of all other
   file/connection paths.

The authorizer runs while statements are prepared, is disabled by default, only
one callback can be installed per connection, and a later call replaces it. It
can deny operations or substitute null for a column read; it does not evaluate
a record's values as row policy. It must remain installed through possible
reprepare and on every connection.

Views/triggers are not independent principal boundaries: any unrestricted
connection can query the base table or change the schema. Separate-file tenancy
fails if `ATTACH` or ordinary file APIs can open another tenant's path.

Rule anchors:

- `db.authorization.sqlite.no-native-principal-policy`
- `db.authorization.sqlite.authorizer-every-connection`
- `db.authorization.sqlite.direct-file-closure`
- `db.authorization.sqlite.attach-cross-tenant`
- `db.authorization.sqlite.query-only-not-a-grant`

Missing RLS is inventory, not a finding. File the unmet guarantee and failed
external boundary.

## Bypasses and alternate paths

Inventory and test:

- every new/pooled connection, direct file API, backup/serialize/deserialize
  API, CLI/tooling, ORM escape hatch, and test/debug console;
- `ATTACH`, URI filenames, temp databases/files, shared cache, VFS aliases,
  symlinks/reparse points, and mobile/cloud file sync;
- main database, `-wal`, `-shm`, rollback/super-journal, temp/spill, backup,
  crash copy, bundled seed, and exported dump;
- `PRAGMA writable_schema`, `trusted_schema`, `query_only`,
  `ignore_check_constraints`, `foreign_keys`, journal/synchronous/locking
  modes, and unknown/typo pragmas;
- loadable extensions, virtual tables, FTS, custom functions/collations,
  triggers/views, and side-effecting UDFs;
- file replacement/rollback to an older valid database and deleted-page/WAL
  remnants.

SQLite officially recommends treating a database file writable by another
security domain as untrusted. A valid file can contain a hostile schema even
when SQL input is parameterized.

## Stored code and execution context

SQLite has no stored procedure role or definer/invoker authority. Schema
objects such as triggers, views, generated expressions, indexes, and virtual
tables execute through the current connection, while custom functions,
extensions, VFSes, and virtual-table modules execute with process authority.

For files of uncertain provenance:

- set `SQLITE_DBCONFIG_TRUSTED_SCHEMA` false or `PRAGMA trusted_schema=OFF` on
  every connection as early as possible;
- mark side-effecting functions `SQLITE_DIRECTONLY` and virtual tables
  `SQLITE_VTAB_DIRECTONLY`;
- enable `SQLITE_DBCONFIG_DEFENSIVE`;
- disable triggers/views if genuinely unused;
- keep extension loading disabled or allowlist exact built artifacts;
- run integrity/quick checks according to the risk and availability budget.

Rule anchors:

- `db.execution.sqlite.untrusted-schema`
- `db.execution.sqlite.extension-loading`
- `db.execution.sqlite.side-effecting-udf`
- `db.execution.sqlite.defensive-mode`

Injection into application SQL remains `web-and-api`; the process-authority and
hostile-database-file amplification belongs here.

## Migration and security drift

Compare fresh, upgraded, downgraded/rollback, and restored schema plus
connection initialization:

- `PRAGMA foreign_keys=ON`, trusted-schema/defensive/authorizer/limits are
  missing on one connection factory or run too late;
- an unknown or misspelled pragma is silently ignored;
- table-rebuild migrations lose keys, checks, FKs, triggers, indexes, STRICT,
  generated columns, or tenant predicates;
- `PRAGMA user_version` advances without schema/policy equivalence;
- an upgrade changes journal/synchronous/locking/secure-delete/temp behavior or
  runtime compile options;
- a tenant file path becomes user-controlled, shared, attachable, synced, or
  broadly readable;
- extension/UDF/virtual-table registration broadens;
- a backup/seed replaces a newer schema or omits WAL content.

Pragmas are connection-, database-, or compile-time scoped depending on the
specific setting. Never generalize one connection's value to all.

## Transactions, concurrency, and integrity

Verify:

- `PRAGMA foreign_keys=ON` on every connection and `foreign_key_check` after
  migration/restore; do not rely on historical default-off behavior changing;
- check constraints are not disabled, types/STRICT behavior matches the
  declared version, and tenant uniqueness is encoded where required;
- `BEGIN DEFERRED`/`IMMEDIATE`/`EXCLUSIVE`, busy handling, lock upgrade, and
  retry semantics match the workflow;
- single-writer contention and WAL/read snapshot behavior cannot cause stale
  authorization or duplicate/partial work;
- `journal_mode`, `synchronous`, filesystem/VFS locking and durability match
  the stated guarantee;
- a failed transaction/retry re-establishes application actor/tenant state.

SQLite serializes writes; that does not make a multi-process application
authorization check atomic unless the check and write share the correct
transaction. Business workflow conclusions remain outside this adapter.

## CDC, replication, and history

Core SQLite has no authenticated CDC, replication, or temporal service. WAL and
rollback journals are recovery artifacts, not authorized change feeds.
Application update/preupdate hooks, session extension/change sets, file sync,
mobile replication products, triggers, and history tables are separate
application/product paths.

For each detected path, inventory:

- initial snapshot and ongoing change semantics;
- process/file/service principal;
- conflict resolution and stale/offline writes;
- foreign-tenant filtering;
- tombstone/deletion and restored-copy behavior;
- audit attribution and tamper authority.

If a third-party replicated SQLite product is not covered by a selected
adapter, report `NOT_ASSESSED`; core SQLite behavior cannot clear it.

## Backup and restore

Map the Online Backup API, `VACUUM INTO`, `sqlite3 .backup`/`.dump`, filesystem
copy, volume snapshot, application sync, OS/mobile backup, and bundled seed.
For WAL mode, a raw copy that omits required WAL state is not a consistency
proof. A backup copies database content; it does not automatically preserve or
recreate OS ACLs, sandbox entitlements, file ownership, secure storage, or
application authorization configuration.

The restore oracle compares:

- schema SQL, constraints, triggers/views/indexes/STRICT, application/user
  version, and integrity/FK checks;
- connection setup for foreign keys, authorizer, trusted schema, defensive
  mode, extensions, limits, journal/synchronous settings;
- file/directory ACL and process/sandbox paths;
- main/WAL/journal data canaries, deleted-page remnants, and every replica/sync
  path;
- application actor/tenant behavior after restore.

Secure deletion, storage encryption, mobile backup exclusion, retention, and
key custody are handed to their owning lenses.

## Audit and attribution

SQLite core has no protected server audit. `sqlite3_trace_v2`, update/preupdate
hooks, authorizer callbacks, triggers, and application logs observe only the
connections/processes that install or execute them. Another file-capable
process can bypass or alter them.

A claimed audit must establish:

- authenticated application actor, process/OS identity, tenant, connection,
  target, operation, outcome, and transaction;
- read as well as write/denial coverage where required;
- coverage across every connection factory, CLI/tool, background process,
  restore/sync, and direct-file path;
- append/remote protection and loss behavior outside the SQLite file;
- parameter/data minimization.

An audit table in the same writable file is ordinary mutable data, not a
tamper-resistant trail.

## Availability and resource governance

SQLite's official defensive guidance for untrusted SQL includes lowering
`sqlite3_limit()` values, using a progress handler/interrupt, heap and allocation
limits, and bounding attached databases. Also assess max page count, cache/temp
settings, busy timeout/cancellation, pool/connections, WAL checkpoints/growth,
long readers, disk/full behavior, and OS process quotas.

Use bounded tests for:

- recursive CTEs, expression/trigger depth, compound selects, variables,
  LIKE/regex/FTS/JSON, large blobs/rows/results, sorts, and temp spill;
- lock contention, long readers, busy retry loops, WAL growth/checkpoint
  starvation, and file descriptor exhaustion;
- corrupt/hostile file parsing only through safe committed fixtures;
- trigger/UDF/virtual-table/extension amplification.

Do not file every default limit as a vulnerability. Tie the gap to accepted
untrusted SQL/file input and an availability budget.

## Unsupported guarantees and NOT ASSESSED cases

- SQLite core has no user authentication, roles, grants, RLS, protected tenant
  context, definer/invoker separation, native CDC/replication/history, or
  tamper-resistant security audit.
- `PRAGMA query_only`, a view, trigger, or authorizer callback is not a
  persistent per-user grant and does not survive a new unrestricted connection.
- File-per-tenant isolation is not enforced when the process can open/attach
  every file.
- Database backups do not carry external filesystem/process/sandbox policy.
- WAL/journal/history/audit tables are data copies and can expose deleted or
  foreign values.
- SQLCipher/encrypted wrappers, mobile sync, distributed SQLite products, and
  unknown VFS/extension behavior are `NOT_ASSESSED` without their own adapter
  and version.
- An unknown runtime version or compile option cannot be cleared by a package
  version.

Unsupported native capability is not itself a finding. A required guarantee
with no tested external enforcement path is.

## Static discovery sweeps

Every hit is a candidate to read:

```bash
rg -n --hidden 'provider\s*=\s*"sqlite"|better-sqlite3|node:sqlite|sqlite3|pysqlite|Microsoft\.Data\.Sqlite|RoomDatabase' .
rg -n --hidden 'sqlite_version\s*\(|PRAGMA\s+compile_options|SQLITE_VERSION|SQLITE_SOURCE_ID' .
rg -n --hidden 'PRAGMA\s+(foreign_keys|trusted_schema|query_only|writable_schema|ignore_check_constraints|journal_mode|synchronous|locking_mode|secure_delete)' .
rg -n --hidden 'sqlite3_db_config|SQLITE_DBCONFIG_(DEFENSIVE|TRUSTED_SCHEMA|ENABLE_TRIGGER|ENABLE_VIEW)' .
rg -n --hidden 'sqlite3_set_authorizer|SQLITE_(DENY|IGNORE|OK)|sqlite3_trace_v2|sqlite3_(preupdate|update)_hook' .
rg -n --hidden 'sqlite3_create_function|SQLITE_DIRECTONLY|sqlite3_create_module|SQLITE_VTAB_DIRECTONLY|load_extension|enable_load_extension' .
rg -n --hidden '\bATTACH\b|\bDETACH\b|SQLITE_LIMIT_ATTACH|mode=(ro|rw|rwc|memory)|immutable=1' .
rg -n --hidden 'CREATE\s+(TRIGGER|VIEW|VIRTUAL\s+TABLE)|WITHOUT\s+ROWID|\bSTRICT\b|FOREIGN\s+KEY|CHECK\s*\(' .
rg -n --hidden 'sqlite3_backup|VACUUM\s+INTO|\.backup|\.dump|-wal|-shm|journal' .
rg -n --hidden 'sqlite3_limit|progress_handler|sqlite3_progress_handler|sqlite3_interrupt|max_page_count|busy_timeout|busy_handler' .
```

Separate production code from tests/generated/vendor sources, resolve every
connection factory and runtime version, and inspect values rather than mere
pragma names. Unknown pragmas can be silently ignored.

## Proof and conformance recipe

Use the repository's existing SQLite test path at T1. A new process/service is
T2. An accepted authenticated operator statement naming the target, scope, and
launch is authority without another prompt. Execute it only through a matching
implemented controller; otherwise record `UNPROVEN` with the technical transport
gap. All files remain disposable and inside the proof worktree/temp directory.

1. Record runtime/source ID, compile options, database list, schema, pragmas,
   connection flags, authorizer/config callbacks, functions/modules/extensions,
   and exact main/WAL/journal paths.
2. Seed tenant-A/B canaries and prove an unrestricted harness control can see
   both.
3. Exercise every connection factory as its application actor: read-by-id,
   list, aggregate, insert, update, tenant-key mutation, upsert, delete,
   schema/pragma, view/trigger/UDF, backup, and permitted metadata.
4. Open a second connection that intentionally lacks initialization; test
   authorizer, foreign keys, trusted schema, defensive mode, query-only, and
   limits. The self-check must prove the second path reached the fixture.
5. For file-per-tenant designs, use distinct disposable paths/process
   identities already supported by the runner and attempt benign `ATTACH`/
   ordinary open of the other tenant. Do not change real user ACLs.
6. Exercise pool reuse, failed transaction/retry, WAL reader/writer contention,
   progress cancellation, backup plus restore, and missing-WAL negative fixture.
7. Assert rows/file copies and application/audit records, not just SQLite result
   codes.

Catalog anchors include `sqlite_schema`, `pragma_database_list`,
`pragma_compile_options`, table/index/FK/check metadata, runtime pragma values,
and connection initialization code. External OS/app policy evidence belongs in
the profile and proof manifest.

## Known false positives

- SQLite is a local single-user cache with no confidentiality/tenant/audit claim
  and contains no sensitive data; classify the boundary rather than requiring
  server controls.
- File-per-tenant access is enforced by distinct process/OS capabilities and a
  proof shows other tenant files cannot be opened or attached.
- `PRAGMA foreign_keys=ON` is centralized in a connection factory that every
  path uses; verify the closed factory set and runtime value.
- An authorizer callback is registered in wrapper code rather than near each
  query, and every connection/reprepare path is covered by tests.
- Extension loading appears only in a build/test tool and is disabled in the
  deployed runtime.
- `trusted_schema=ON` is acceptable for a repository-owned file with no
  side-effecting custom function/module and no cross-domain writer; state the
  established provenance.
- WAL/journal filenames in ignore/cleanup rules do not prove they are exposed
  or omitted from backup.
- A non-STRICT table deliberately uses SQLite affinity and explicit checks;
  STRICT is not required by name.

## Fixture concepts

### Vulnerable

`V-SQLITE-001`: shared multi-tenant file with application-only filter missing
on one path; second connection lacks authorizer/foreign keys/trusted-schema
hardening; caller can `ATTACH` another tenant file; `query_only` is claimed as a
role; side-effecting UDF is schema-callable; unbounded recursive query; raw WAL
copy omitted from backup; audit trigger can be bypassed by a direct connection.

Expected rule anchors:

- `db.authorization.sqlite.authorizer-every-connection`
- `db.authorization.sqlite.attach-cross-tenant`
- `db.authorization.sqlite.query-only-not-a-grant`
- `db.integrity.sqlite.foreign-keys-per-connection`
- `db.execution.sqlite.untrusted-schema`
- `db.availability.sqlite.untrusted-input-limits`
- `db.restore.sqlite.wal-copy-consistency`
- `db.audit.sqlite.direct-file-bypass`

### Clean

`C-SQLITE-001`: declared external enforcement; distinct file/process
capabilities or complete service mediation; every connection has foreign keys,
authorizer where needed, defensive/trusted-schema settings and limits;
extensions closed; validated constraints; bounded WAL/locking behavior;
consistent Backup API restore plus external ACL recreation; actor-aware audit
outside the writable file. Own-tenant operations pass and foreign-file/direct
paths fail.

## Official sources

All links verified `2026-07-28`:

- [SQLite defense against malicious SQL and database files](https://sqlite.org/security.html)
- [SQLite authorizer callback](https://sqlite.org/c3ref/set_authorizer.html)
- [SQLite database configuration options](https://sqlite.org/c3ref/c_dbconfig_defensive.html)
- [SQLite run-time limits](https://sqlite.org/c3ref/limit.html)
- [SQLite PRAGMA reference](https://sqlite.org/pragma.html)
- [SQLite foreign key support](https://sqlite.org/foreignkeys.html)
- [SQLite STRICT tables](https://sqlite.org/stricttables.html)
- [SQLite transactions](https://sqlite.org/lang_transaction.html)
- [SQLite isolation](https://sqlite.org/isolation.html)
- [SQLite write-ahead logging](https://sqlite.org/wal.html)
- [SQLite Online Backup API](https://sqlite.org/backup.html)
- [SQLite loadable extensions](https://sqlite.org/loadext.html)
