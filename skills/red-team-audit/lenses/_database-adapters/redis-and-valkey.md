# Redis and Valkey adapter

Adapter ID: `redis`, `valkey`

Deployment variants: `redis-self-managed`, `redis-managed`, `redis-enterprise`,
`valkey-self-managed`, `valkey-managed`

Verified: `2026-07-28`

This adapter covers Redis Open Source and Valkey without pretending that the
two products, their managed services, modules, or versions are interchangeable.
It applies through the `database-and-data-stores` lens and owns no topics.

## Detect and profile

Activate on `redis://`/`rediss://`, RESP clients, Redis or Valkey images,
`redis.conf`, `valkey.conf`, ACL files, Sentinel/Cluster configuration, or
managed-cache resources. Record:

- product, exact version, distribution/license, managed provider, modules, and
  whether it is a cache, durable store, queue/stream, session store, or lock;
- standalone, Sentinel, Cluster, replica, proxy, and active-active topology,
  including client, cluster bus, Sentinel, admin, and module endpoints;
- runtime, read-only, publisher/subscriber, replication, Sentinel, backup, and
  administrative identities;
- numbered logical databases, key patterns, hash tags, streams, channels,
  scripts/functions, modules, persistence, eviction, and backup paths.

Version-gate ACL syntax, module command categories, sharded Pub/Sub, functions,
granular managed-service RBAC, audit facilities, and multi-region behavior. An
unknown product or version is `NOT ASSESSED`, not “Redis-compatible pass.”

Emit the contract's required `store_context`: `store_id`, `family`, `engine`,
`engine_version`, `deployment_variant`, `adapter_id`, `detection_evidence[]`,
and `confidence`. Keep `data_classes`, `tenant_unit`, `enforcement_plane`,
`principal_paths[]`, and `copy_paths[]` in the full store profile.

## Capability declaration

The branch column is the baseline for versioned Redis Open Source/Valkey. A
managed or Enterprise service can override only with provider evidence.

| Capability ID | Redis | Valkey | Conditions |
|---|---|---|---|
| `principal-authentication` | `NATIVE` | `NATIVE` | ACL-capable version and authentication configured; default/no-auth deployments do not satisfy it. |
| `role-and-object-grants` | `COMPOSABLE` | `COMPOSABLE` | ACL users constrain commands, key patterns and channels; there is no general role hierarchy. |
| `record-read-authorization` | `COMPOSABLE` | `COMPOSABLE` | Key-pattern ACLs can isolate whole keys, not records inside a value. |
| `record-write-authorization` | `COMPOSABLE` | `COMPOSABLE` | Key write patterns plus command grants; verify scripts/modules. |
| `column-or-property-authorization` | `UNSUPPORTED` | `UNSUPPORTED` | No native field/property policy inside hashes, JSON, streams or module values. |
| `tenant-session-context` | `EXTERNAL_ONLY` | `EXTERNAL_ONLY` | Bind a principal/keyspace per tenant outside the engine. |
| `stored-code-execution-context` | `NATIVE` | `NATIVE` | Script/function/module command and key checks are version/module sensitive. |
| `schema-integrity` | `UNSUPPORTED` | `UNSUPPORTED` | Core stores do not enforce application value schemas. |
| `transactional-integrity` | `COMPOSABLE` | `COMPOSABLE` | Atomic serialization and WATCH/Lua are available; no rollback after runtime command errors. |
| `resource-governance` | `COMPOSABLE` | `COMPOSABLE` | ACLs, maxmemory, timeouts, client/output limits and workload bounds. |
| `replication-cdc-authorization` | `COMPOSABLE` | `COMPOSABLE` | Dedicated replica/Sentinel ACLs and protected replication channels; no row-filtered CDC. |
| `history-authorization` | `UNSUPPORTED` | `UNSUPPORTED` | Core has no queryable temporal-history policy plane. |
| `backup-policy-portability` | `COMPOSABLE` | `COMPOSABLE` | RDB/AOF restores require separate ACL/config/module validation. |
| `security-audit` | `UNKNOWN` | `UNKNOWN` | OSS ACL LOG is not full audit; managed/Enterprise capability is deployment-specific. |
| `policy-catalog-introspection` | `NATIVE` | `NATIVE` | Running ACL/config/module/topology state can be enumerated with privilege. |

## Resource and tenant model

Open-source ACLs primarily constrain commands, key patterns, and Pub/Sub
channel patterns for a user. Redis and older Valkey releases do not make a
numbered database selected with `SELECT` a tenant boundary. Valkey 9.1 adds
version-gated ACL database permissions (`db=`, `alldbs`, `resetdbs`); prove
the running version and effective ACL rather than applying that guarantee to
Redis or older Valkey. Cluster supports only database zero. A tenant key prefix
or hash tag is application-defined unless the effective ACL independently
restricts it.

Model tenant units separately for keys, channels, streams/consumer groups,
search indexes, JSON paths, time-series keys, module-owned data, persistence
files, and replicas. A cache used only for derived data still inherits the
sensitivity and authorization boundary of its source.

## Effective privilege semantics

Resolve the final ACL for each user, including `on`/`off`, passwords/nopass,
command/category grants and removals, key read/write patterns, channel
patterns, selectors, and later ACL mutations. Rule order and repeated
`ACL SETUSER` calls matter; inspect the running `ACL GETUSER` result rather
than interpreting one line in isolation.

The common Redis default user state `on nopass ~* &* +@all`, and an unhardened
Valkey deployment with no authentication, are full access for any reachable
client. Treat `+@all`, `+@admin`, `+@dangerous`, unrestricted keys/channels,
`CONFIG`, `ACL`, `MODULE`, `DEBUG`, replication, shutdown, persistence, and
cluster-management commands as privileged. Inspect module commands explicitly;
category assumptions can drift when modules or versions change.

Route listener exposure, firewalling, private endpoints, and managed-service
IAM to `cloud-and-iac`. This adapter proves the data-plane consequence.

## Native versus application-only authorization

Label each boundary:

- `native`: an authenticated ACL user is restricted to required commands,
  keys, and channels;
- `application-only`: one broad credential relies on prefix construction or
  code filters;
- `hybrid`: ACL pattern plus application ownership checks;
- `none` or `unknown`.

For application-only designs, attack every command-building helper, raw client,
pipeline, transaction, script, module API, key scan, Pub/Sub path, and
background worker. A correct prefix in one wrapper is not proof.

Command/protocol injection and unsafe construction of Lua or query strings from
untrusted input belong to `web-and-api`. This adapter owns dangerous capability
grants and stored/script execution configuration, not duplicate injection
findings.

## Alternate paths and privileged execution

Exercise `GET`/`MGET`, `SCAN`, `KEYS`, hashes/JSON/search, streams, Pub/Sub,
keyspace notifications, blocking commands, pipelines, `MULTI`/`EXEC`,
`WATCH`, Lua `EVAL`/`EVALSHA`, functions, and every loaded module.

Inventory `DUMP`/`RESTORE`, `MIGRATE`, replication/PSYNC, Sentinel, Cluster,
RDB/AOF, managed exports, and replicas. Review `CONFIG`, `ACL`, `MODULE`,
`SCRIPT`, `FUNCTION`, `DEBUG`, `MONITOR`, `CLIENT`, `SHUTDOWN`, `FLUSH*`,
failover, and cluster commands. A read-only application user should not acquire
write or administration indirectly through a script/function/module.

## Integrity, consistency, and availability

Redis/Valkey transactions serialize queued commands but do not provide
relational rollback semantics for runtime command errors. Prove `WATCH`
conflict handling, idempotency, distributed-lock ownership/token checks, script
atomicity, and Cluster same-slot requirements rather than calling
`MULTI`/`EXEC` “ACID.”

Model asynchronous replication and the selected durability mode: no
persistence, RDB, AOF policy, or both. `WAIT` and minimum-replica settings
reduce some loss windows but are not universal consistency guarantees. Test
failover, restart, partial writes to AOF, and a primary restarted empty while
replicas synchronize.

Attack:

- unbounded `KEYS`, scans, wildcard search, Lua/functions, module queries,
  large values, batches, streams, consumer-group backlog, and output buffers;
- memory exhaustion, eviction of security/session/lock keys, maxmemory policy,
  persistence forks/rewrites, disk exhaustion, hot hash slots, and connection
  exhaustion;
- blocking operations, long transactions/scripts, Pub/Sub fan-out, and
  cardinality amplification.

Resource limits must protect every protocol endpoint and workload class.

## Replication, persistence, snapshots, and restore

Treat replicas, RDB files, AOF segments, diskless replication streams, cluster
migrations, managed snapshots, and exports as independent bulk-copy surfaces.
Replication/Sentinel users need narrowly documented ACLs; do not reuse the
runtime or administrative credential.

Restore proof must validate ACL users/config, module set, persistence settings,
key TTLs, tenant key patterns, replica authentication, and exposure before
clients reconnect. A data-only RDB/AOF restore does not prove security-state
equivalence.

## Audit and attribution

Open-source `ACL LOG` is a bounded log of authentication failures and ACL
violations, not a durable audit trail of successful reads and writes.
`MONITOR`, slow logs, command statistics, and keyspace notifications are not
substitutes for a tamper-resistant per-actor audit log. Managed/Enterprise
audit features must be edition- and provider-gated.

Prove successful and denied sensitive operations carry database identity,
source, command class/key scope where safely possible, outcome, and an
end-user correlation value. Never enable value/argument logging that exposes
session tokens or secrets merely to satisfy audit coverage.

## Deletion, expiry, and copies

Expiration is asynchronous: keys may be removed through passive access or
active expiry, and replica/persistence/backup copies have separate lifetimes.
Verify every tenant key actually receives a TTL, refresh cannot make it
immortal unexpectedly, eviction is not mistaken for deletion, stream entries
and consumer metadata are trimmed, and search/module indexes converge.

Test explicit offboarding with a bounded key inventory; never rely on an
unbounded production `KEYS` command. Route legal retention conclusions to
`privacy-and-data-protection`.

## Unsupported or unproven guarantees

Do not claim:

- per-record authorization inside a shared value, hash, stream, or JSON
  document;
- isolation from numbered logical databases without a versioned database-ACL
  proof (for example, Valkey 9.1+);
- durable successful-operation auditing from `ACL LOG`;
- rollback of earlier commands after an `EXEC` runtime error;
- synchronous no-loss replication or failover;
- immediate physical erasure from RDB/AOF, replicas, or backups;
- identical Redis, Valkey, module, Enterprise, and managed-provider semantics.

Absence of native value-level authorization is a design input, not an automatic
finding. Attack the declared keyspace or instance isolation.

## Rule anchors

- `db.authorization.redis.acl-key-command-boundary` evaluates the selected ACL
  user, command/category grants, key and channel patterns, module commands,
  authentication path, and reachable administrative interfaces together.
- `db.authorization.valkey.acl-key-command-boundary` applies the same boundary
  to Valkey while requiring Valkey-specific command/module and deployment
  semantics rather than inheriting a Redis version assumption.

## Static discovery sweeps

| Evidence | Review |
|---|---|
| `redis.conf`, `valkey.conf`, Helm/Compose | product/version, auth, `aclfile`, default user, bind/protected mode handoff, TLS handoff, persistence, maxmemory, dangerous renames/ACLs |
| ACL files and `ACL SETUSER` | `nopass`, `~*`, `&*`, `+@all`, admin/dangerous/scripting/module grants, selectors, replica/Sentinel users |
| client factories | one broad URL, DB-number “isolation,” runtime/admin credential reuse, TLS and pool identity |
| key helpers | user-controlled prefixes, delimiter ambiguity, wildcard characters, tenant ownership mutation, missing TTL |
| `EVAL`, `FCALL`, modules | stored execution and undeclared commands; route untrusted construction to `web-and-api` |
| persistence/replication config | AOF/RDB loss window, replica auth/read exposure, failover, empty-primary restart |
| stream/PubSub/search calls | channel and consumer isolation, backlog, alternate enumeration and result limits |

## Proof and conformance matrix

With tenants A/B, A-scoped read and write users, a publisher/subscriber, and an
admin control, execute:

| Path | Required negative proof |
|---|---|
| GET/MGET/SCAN and module search | A cannot enumerate, infer, or read B |
| SET/MSET/hash/JSON/stream writes | A cannot create, overwrite, rename, or move B |
| DEL/UNLINK/expiry/flush | A cannot delete B or disable B expiry |
| Pub/Sub and keyspace notifications | A cannot subscribe/publish outside allowed channels |
| pipeline/MULTI/Lua/function/module | batching or execution cannot escape ACL scope |
| CONFIG/ACL/MODULE/DEBUG/replication | runtime user is denied administrative amplification |
| replica/failover/restart/restore | denial and declared durability survive topology changes |
| audit | allowed/denied operation is attributable at the promised coverage |
| availability | declared limits stop a representative scan/script/value/fan-out attack |

## Known false positives

- A deliberately ephemeral cache may disable persistence; verify that loss
  cannot break authorization, uniqueness, money, locking, or revocation before
  accepting it.
- A broad local-development default is not a production finding when release
  configuration and reachability are independently excluded.
- One instance per tenant can be valid even with broad per-instance ACLs if
  provisioning, routing, backups, and administrative access preserve that
  boundary.
- Command renaming alone is not evidence of authorization, and absence of
  renaming is not a finding when ACLs correctly deny the command.
- A managed-service control must be judged against its exact provider/version,
  not self-hosted defaults.

## Fixture concept

Run separate version-pinned Redis and Valkey fixtures with tenant-prefixed
keys, hashes, streams, channels, a Lua function, a replica, RDB+AOF, and scoped
users. The vulnerable variant leaves the default user broad, trusts prefix
helpers, grants scripting/admin categories, omits resource limits, and treats
`ACL LOG` as full audit. The clean variant disables the default user, uses
separate least-privilege users and patterns, constrains scripts/modules and
resources, and documents durability/audit limitations. Repeat after failover,
restart, and restore.

## Official sources

Verified 2026-07-28:

- https://redis.io/docs/latest/operate/oss_and_stack/management/security/
- https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/
- https://redis.io/docs/latest/commands/acl-log/
- https://redis.io/docs/latest/operate/oss_and_stack/management/replication/
- https://valkey.io/topics/security/
- https://valkey.io/topics/acl/
- https://valkey.io/topics/transactions/
- https://valkey.io/topics/replication/
- https://valkey.io/topics/persistence/
