---
name: database-and-data-stores
title: Database and data-store security
runs_in: fanout
activates_on:
  paths:
    - '**/*.sql'
    - '**/migrations/**'
    - '**/migrate/**'
    - '**/*.prisma'
    - '**/drizzle.config.*'
    - '**/knexfile.*'
    - '**/ormconfig.*'
    - '**/alembic.ini'
    - '**/flyway.conf'
    - '**/liquibase*.xml'
    - '**/liquibase*.yaml'
    - '**/liquibase*.yml'
    - '**/liquibase*.json'
    - '**/liquibase*.properties'
    - '**/supabase/migrations/**'
    - '**/firestore.rules'
    - '**/firebase.json'
    - '**/mongod.conf'
    - '**/users.acl'
    - '**/redis.conf'
    - '**/elasticsearch.yml'
    - '**/opensearch.yml'
    - '**/cassandra.yaml'
    - '**/neo4j.conf'
    - '**/*.cql'
    - '**/*snapshot*.sh'
    - '**/*snapshot*.ps1'
    - '**/*snapshot*.sql'
    - '**/*backup*.sh'
    - '**/*backup*.ps1'
    - '**/*backup*.sql'
    - '**/*restore*.sh'
    - '**/*restore*.ps1'
    - '**/*restore*.sql'
    - '**/*replication*.conf'
    - '**/*replication*.cnf'
    - '**/*replication*.ini'
    - '**/*replication*.yaml'
    - '**/*replication*.yml'
    - '**/*replication*.json'
    - '**/*replication*.sql'
    - '**/*cdc*.sql'
    - '**/*cdc*.yaml'
    - '**/*cdc*.yml'
    - '**/*cdc*.json'
    - '**/*cdc*.conf'
    - '**/.env'
    - '**/.env.*'
    - '**/local.settings.json'
    - '**/local.settings.*.json'
    - '**/appsettings.json'
    - '**/appsettings.*.json'
  signals:
    - '@prisma/client'
    - 'drizzle-orm'
    - '"knex":'
    - '"sequelize":'
    - '"typeorm":'
    - 'sqlalchemy'
    - 'django.db'
    - 'ActiveRecord::Base'
    - '"pg":'
    - '"postgres":'
    - '@supabase/supabase-js'
    - 'Npgsql'
    - 'Microsoft.Data.SqlClient'
    - '"mssql":'
    - '"mysql2":'
    - '"mariadb":'
    - '"oracledb":'
    - '"sqlite3":'
    - 'better-sqlite3'
    - '"mongodb":'
    - '"mongoose":'
    - '"redis":'
    - '"ioredis":'
    - '@google-cloud/firestore'
    - 'firebase-admin'
    - '@aws-sdk/client-dynamodb'
    - 'DynamoDBClient'
    - '@elastic/elasticsearch'
    - '@opensearch-project/opensearch'
    - 'cassandra-driver'
    - 'neo4j-driver'
    - 'pinecone'
    - 'qdrant'
    - 'weaviate'
    - 'milvus'
    - 'snowflake-sdk'
    - '@google-cloud/bigquery'
    - 'CREATE POLICY'
    - 'ROW LEVEL SECURITY'
    - 'SECURITY DEFINER'
    - 'SQL SECURITY DEFINER'
    - 'CREATE SECURITY POLICY'
    - 'DBMS_RLS'
    - 'dynamodb:LeadingKeys'
    - 'allow read'
    - 'ACL SETUSER'
    - 'document_level_security'
    - 'ChangeStream'
    - 'CREATE PUBLICATION'
    - 'CHANGE_TRACKING'
    - 'CREATE AUDIT'
    - 'EXECUTE AS'
    - 'AUTHID CURRENT_USER'
    - 'SQL SECURITY INVOKER'
    - 'BYPASSRLS'
    - 'EXEMPT ACCESS POLICY'
    - 'FORCE ROW LEVEL SECURITY'
    - '@valkey/valkey-glide'
    - 'scylla-driver'
    - '@aws-sdk/client-redshift-data'
    - 'redshift_connector'
    - '@databricks/sql'
    - 'databricks-sql-connector'
    - 'psycopg'
    - 'pymongo'
    - 'redis=='
    - 'from redis'
    - 'import redis'
    - 'snowflake-connector-python'
    - 'github.com/jackc/pgx'
    - 'database/sql'
    - 'github.com/lib/pq'
    - 'github.com/go-sql-driver/mysql'
    - 'go.mongodb.org/mongo-driver'
    - 'github.com/redis/go-redis'
    - 'modernc.org/sqlite'
    - 'org.postgresql'
    - 'mysql-connector-j'
    - 'org.mariadb.jdbc'
    - 'com.microsoft.sqlserver'
    - 'com.oracle.database.jdbc'
    - 'sqlite-jdbc'
    - 'mongodb-driver-sync'
    - 'redis.clients'
    - 'io.lettuce'
    - 'com.datastax.oss'
    - 'org.neo4j.driver'
    - 'net.snowflake'
    - 'org.elasticsearch.client'
    - 'org.opensearch.client'
    - 'google-cloud-bigquery'
    - 'redshift-jdbc'
    - 'databricks-jdbc'
    - 'jdbc:postgresql:'
    - 'jdbc:mysql:'
    - 'jdbc:sqlserver:'
    - 'jdbc:oracle:'
    - 'jdbc:sqlite:'
    - 'postgres://'
    - 'postgresql://'
    - 'mongodb://'
    - 'mongodb+srv://'
    - 'redis://'
    - 'rediss://'
    - 'mysql://'
    - 'mariadb://'
    - 'sqlserver://'
    - 'sslmode='
    - 'Data Source='
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: not-consumed
    deployed-state:
      state: consumed
      may_conclude: [drift-from-source, runtime-misconfiguration]
    live-runtime:
      state: consumed
      may_conclude: [runtime-misconfiguration, sensitive-data-at-rest]
owns:
  - database-principal-and-role-boundaries
  - database-native-authorization-and-tenant-isolation
  - database-privileged-code-and-execution-context
  - database-integrity-transactions-and-concurrency
  - database-resource-governance-and-availability
  - database-migration-security-drift
  - database-replication-cdc-history-and-sharing
  - database-backup-restore-and-clone-security
  - database-audit-identity-and-coverage
  - database-lifecycle-and-copy-propagation
defers:
  injection-sql-nosql-orm: web-and-api
  authz-object-level: web-and-api
  authz-property-level: web-and-api
  authz-function-level: web-and-api
  tenant-isolation-enforcement: web-and-api
  race-conditions-and-toctou: web-and-api
  rate-limiting-and-request-quotas: web-and-api
  network-exposure-and-segmentation: cloud-and-iac
  iam-policy-and-privilege-scope: cloud-and-iac
  encryption-at-rest-configuration: cloud-and-iac
  backup-and-replica-configuration: cloud-and-iac
  resource-tls-enforcement-flags: cloud-and-iac
  control-plane-audit-logging: cloud-and-iac
  hardcoded-credentials-and-key-material: crypto-and-key-management
  tls-and-certificate-validation: crypto-and-key-management
  key-separation-derivation-and-destruction: crypto-and-key-management
  retention-lawfulness-and-deletion-completeness: privacy-and-data-protection
  pii-inventory-and-data-map: privacy-and-data-protection
  derived-store-data-inheritance: llm-and-ai
  rag-retrieval-authorization: llm-and-ai
  model-artifact-provenance: llm-and-ai
  package-dependency-cves: cicd-and-supply-chain
  dependency-eol-and-abandonment: cicd-and-supply-chain
  dependency-pinning-and-lockfiles: cicd-and-supply-chain
  phi-access-audit-controls: hipaa-and-phi
  phi-severity-uplift: hipaa-and-phi
frameworks:
  - owasp-database-security
  - owasp-nosql-security
  - cis-benchmarks
  - cwe
  - stride
severity_floor: low
---

## Scope

This lens audits the security semantics of databases and data stores. It owns the
native data plane: principals and grants, record/document/item/field/subgraph
authorization, privileged stored code, transactional and consistency behavior,
resource governance, migration drift, replication and change feeds, native
backup/restore behavior, audit attribution, and deletion propagation.

It is deliberately not a generic SQL checklist and it is not organized around
row-level security. RLS is one authorization mechanism in some engines. Other
stores use security policies, views, database-per-tenant isolation, IAM
conditions, document rules, key prefixes, document/field security, graph
privileges, namespaces, or application-only enforcement. A control that does
not exist in an engine cannot be required by name.

### The dispatcher rule

The core lens is always paired with
`lenses/_database-adapters/contract.md` and only the adapters selected by the
store profile. The adapter is the semantic authority for a version and
deployment variant. The core supplies shared invariants, ownership, severity,
and proof discipline; it contains no universal claim about policy composition,
administrator bypass, transaction rollback, replication, or audit.

In the current provider-owned discovery step, the provider must declare a stable
profile for every store it detects. Its immutable routing projection is:

```yaml
store_context:
  store_id: orders-primary
  family: relational
  engine: postgresql
  engine_version: "16"
  deployment_variant: self-managed
  adapter_id: postgresql
  detection_evidence:
    - package.json:31 @prisma/client
    - docker-compose.yml:19 postgres:16
  confidence: high
```

The complete profile and its closed coverage denominator are defined by
`lenses/_database-adapters/contract.md` and
`schemas/store-profile.schema.json`.

An explicit provider, driver or service image is stronger evidence than dialect
syntax. Dialect syntax is stronger than a filename. `.sql` alone never selects
an adapter. Conflicting evidence stays conflicting and selects
`inventory-only`; an unknown engine, version, edition or deployment is reported
as **NOT ASSESSED**, never cleared by a generic detector.

Within the current repository-level database job, treat each `store_id` as an
independent assessment: return one `store_profiles` entry per detected store,
bind every finding to exactly one profile and never merge clearance evidence
between stores. A safe token or policy found for one store cannot clear another.
Controller-owned discovery and one-job-per-store dispatch are target protocol
work, not behavior supplied by this version. Generated dumps, vendored
migrations and test schemas are inventory until an execution path establishes
that they create or change a deployed store.

### Owns

| Topic | What that means here |
|---|---|
| `database-principal-and-role-boundaries` | Runtime, migrator, owner, administrator, analyst, support, replicator, CDC, backup and audit identities; role expansion and activation; delegation and bypass authority. |
| `database-native-authorization-and-tenant-isolation` | Native grants and policies from instance/account down to row, item, field, label, path, namespace or key prefix, including direct-client and alternate-path bypasses. |
| `database-privileged-code-and-execution-context` | Views, procedures, functions, triggers, events, scripts, extensions, modules and imports that run with owner, definer, invoker, boosted or signed authority. |
| `database-integrity-transactions-and-concurrency` | Schema validation, constraints, isolation, consistency, optimistic concurrency, stale replicas and partial-write behavior as implemented by the store. |
| `database-resource-governance-and-availability` | Query cost, scans, aggregations, graph traversals, regexes, scripts, connection pools, locks, hot partitions, memory, disk, eviction and quotas. |
| `database-migration-security-drift` | Fresh, upgraded, rolled-back and restored catalogs converging on the same grants, policies, signatures, contexts, triggers and audit settings. |
| `database-replication-cdc-history-and-sharing` | Replicas, CDC, change streams, temporal/history tables, global tables, cross-cluster replication, shares and exports as independent read/copy authorities. |
| `database-backup-restore-and-clone-security` | Native backup consistency, restore-time security state, clone authority and post-restore policy convergence. |
| `database-audit-identity-and-coverage` | Successful and failed data-plane access, original and effective actors, object/action/outcome coverage, tamper authority and dropped-event behavior. |
| `database-lifecycle-and-copy-propagation` | TTL, tombstones, soft deletion, indexes, caches, streams, replicas and restored copies preserving or frustrating an established deletion requirement. |

### Does not own

- **web-and-api** owns caller-controlled SQL/NoSQL/ORM query construction and
  endpoint-level object/function/property authorization. A handler missing its
  tenant predicate is `tenant-isolation-enforcement`; a correct handler defeated
  by a database owner, definer object or native policy gap is this lens.
- **cloud-and-iac** owns network perimeter, managed-service control-plane IAM,
  public endpoints, managed encryption/backup/replica flags and control-plane
  logs. This lens owns native data-plane grants and what a replica, CDC reader or
  restore can actually read.
- **crypto-and-key-management** owns TLS, primitives, keys and application or
  column encryption correctness. "Encrypted" never clears authorization.
- **privacy-and-data-protection** owns whether retention and deletion are lawful
  and complete. This lens supplies evidence about copies, TTL, tombstones and
  restores.
- **llm-and-ai** owns semantic retrieval authorization, candidate-set filtering,
  embedding inheritance and poisoning. This lens owns the vector store's
  principals, namespaces, collections, backups and control plane.
- **cicd-and-supply-chain** owns driver CVEs, version pinning and who may run a
  deployment. This lens owns the security state produced by the migration.
- **hipaa-and-phi** owns HIPAA sufficiency, minimum necessary and severity
  uplift. This lens establishes whether the database audit records the needed
  actor and operation.
- **business logic** owns the product invariant. This lens owns whether the
  selected constraint, transaction and isolation mechanism enforces it.

### What a repository cannot establish

State these as assumptions or contingent facts, not findings or clearances:

- The exact managed-service edition and enabled licensed features when no
  deployment artifact records them.
- Live role membership, temporary elevation, federated group membership and
  break-glass use.
- The deployed catalog when migrations can be skipped, reordered or edited
  outside this checkout.
- Runtime connection-pool reset behavior until the real pool is exercised.
- Whether every replica, stream consumer, backup destination, BI tool or clone
  is represented in the repository.
- Audit retention, export health and dropped-event behavior without the running
  service.
- Data distribution, cardinality, partition hot spots and real query cost.
- Whether a backup is restorable and security-equivalent until it is restored.

Use `_schema.md`'s `contingent_fact` and `contingent_query` for one live fact.
Do not invent a second uncertainty model.

## Activation coverage

Activation selects a store for profiling, not a verdict. Every family remains
PARTIAL until its adapter, version and deployment are established.

| Activation family | Status | Actionable body anchor | Evidence or limit |
|---|---|---|---|
| Generic SQL, ORM and migration surfaces | PARTIAL | `database-principal-and-role-boundaries` | A provider profile and adapter are required; generic syntax cannot establish engine semantics |
| PostgreSQL and Supabase surfaces | PARTIAL | `database-native-authorization-and-tenant-isolation` | The PostgreSQL/Supabase adapter covers native policy semantics; deployed roles and service-key paths still need proof |
| SQL Server and Azure SQL surfaces | PARTIAL | `database-native-authorization-and-tenant-isolation` | The SQL Server adapter separates filter, block, CDC, temporal and execution-context behavior |
| MySQL, MariaDB, Oracle and SQLite surfaces | PARTIAL | `database-privileged-code-and-execution-context` | Separate adapters prevent definer, role, VPD and embedded-engine semantics from being collapsed |
| Firestore and BaaS rule surfaces | PARTIAL | `database-native-authorization-and-tenant-isolation` | Rules, query shape and server-SDK bypass require the Firestore adapter plus IAM evidence |
| MongoDB document-store surfaces | PARTIAL | `database-principal-and-role-boundaries` | Native roles are evaluated with source collections, views, change streams and server-side scripting |
| Redis and Valkey key-value surfaces | PARTIAL | `database-principal-and-role-boundaries` | ACL key, channel and command scopes are covered; value-level policy is unsupported |
| Elasticsearch and OpenSearch surfaces | PARTIAL | `database-native-authorization-and-tenant-isolation` | Vendor-specific effective-role, alias, script, snapshot and replication semantics remain separate |
| DynamoDB item-policy surfaces | PARTIAL | `database-native-authorization-and-tenant-isolation` | LeadingKeys, attributes, batch, transaction, PartiQL, stream and index paths require one condition matrix |
| Cassandra, Scylla and graph surfaces | PARTIAL | `database-integrity-transactions-and-concurrency` | Wide-column and graph adapters cover their native units; shared-row tenancy may remain application-only |
| Vector and warehouse surfaces | PARTIAL | `database-lifecycle-and-copy-propagation` | Control-plane tenancy and copy behavior are assessed; semantic retrieval remains in llm-and-ai |
| Backup, restore, replication and CDC artifacts | PARTIAL | `database-replication-cdc-history-and-sharing` | A named copy path is inventoried; consistency and authority require the selected engine adapter |
| Connection strings and application settings | PARTIAL | `database-principal-and-role-boundaries` | Host, transport mode and connecting principal are established; engine version is not, so adapter selection still needs a declared version |

## Checklist

Work per `store_id`, in order. Item 0 selects the adapter and creates the
denominator. Items 1-10 file findings. A store with no selected adapter receives
inventory and NOT ASSESSED coverage; it never receives a clean result.

### 0. Profile every store and copy path

Start with repository traversal. Every command carries `--hidden`; a database
credential or migration under a dot-directory is otherwise pruned before globs
are applied. Exclude dependency, generated and fixture trees only after recording
them as exclusions.

```bash
# schema, migration, policy and stored-code inputs
rg --files --hidden \
  --glob '**/*.sql' --glob '**/*.cql' --glob '**/*.prisma' \
  --glob '**/migrations/**' --glob '**/migrate/**' \
  --glob '**/firestore.rules' --glob '**/users.acl' \
  --glob '**/mongod.conf' --glob '**/redis.conf' \
  --glob '**/elasticsearch.yml' --glob '**/opensearch.yml' \
  --glob '**/cassandra.yaml' --glob '**/neo4j.conf' .

# provider and driver evidence; use manifests to disambiguate generic source
rg -n --hidden \
  '@prisma/client|drizzle-orm|"pg":|"postgres":|@supabase/supabase-js|Npgsql|Microsoft\.Data\.SqlClient|"mssql":|"mysql2":|"mariadb":|"oracledb":|"mongodb":|"redis":|@google-cloud/firestore|@aws-sdk/client-dynamodb|@elastic/elasticsearch|@opensearch-project/opensearch|cassandra-driver|neo4j-driver' \
  --glob '**/package.json' --glob '**/*.csproj' --glob '**/requirements*.txt' \
  --glob '**/pyproject.toml' --glob '**/pom.xml' --glob '**/build.gradle*' .

# native policy, privilege and execution-context signals
rg -n --hidden -i \
  'CREATE\s+(SECURITY\s+)?POLICY|ROW\s+LEVEL\s+SECURITY|FORCE\s+ROW\s+LEVEL|BYPASSRLS|SECURITY\s+(DEFINER|INVOKER)|SQL\s+SECURITY|AUTHID\s+(DEFINER|CURRENT_USER)|EXECUTE\s+AS|EXEMPT\s+ACCESS\s+POLICY|ACL\s+SETUSER|dynamodb:LeadingKeys|allow\s+(get|list|read|create|update|delete)' .

# independent copy paths
rg -n --hidden -i \
  'CREATE\s+PUBLICATION|logical\s+replication|change\s+data\s+capture|change\s+tracking|ChangeStream|watch\(|global\s+table|cross.cluster\s+replication|snapshot|backup|restore|dump|temporal|history\s+table|point.in.time|export' .
```

For each store, record:

1. Engine, exact version band, edition/deployment, adapter and evidence.
2. Sensitive data and tenant/resource unit.
3. Application, migrator, owner/admin, support/analyst, CDC/replicator,
   backup/restore and audit principals.
4. Enforcement plane: application, database, cloud IAM, filesystem or unknown.
5. Primary, replica, CDC/history, backup/clone, index/cache and export paths.
6. Every direct client path, including browser/mobile BaaS clients, admin SDKs,
   BI/reporting tools and maintenance scripts.
7. Whether the adapter can test each required capability, or explicitly cannot.

Load `lenses/_database-adapters/contract.md`, then the selected adapter. Never
load an adapter merely because another store in the repository uses that engine.

### 1. Principal and role boundaries (`database-principal-and-role-boundaries`)

Expand effective authority, not just declared role names.

- Separate runtime, migration, ownership/admin, analytics, support, CDC,
  replication, backup/restore and monitoring identities. The application
  runtime must not own the database, create principals, alter policies, load
  modules, manage replication, read backups or disable audit.
- Resolve inherited roles, default/current role activation, group/federated
  membership, grants with delegation/admin options, ownership, signatures and
  engine bypass privileges. Adapters define whether grants union, deny, override
  or depend on activation order.
- Record the full principal tuple. A username alone may omit host, database,
  tenant, authentication source, session role, assumed identity or certificate.
- Trace credential provenance without printing a credential: workload identity,
  short-lived token, secret reference, connection URI or embedded literal. Route
  a literal credential to crypto; retain the excessive database authority here.
- For pooled middle tiers, distinguish authenticated, session, effective,
  owner/definer and end-user identities. Shared service identity without a
  trusted end-user context is not record attribution.
- Treat database owner, superuser, system administrator, service/admin key,
  backup operator and CDC reader as separate attacker starting points.

```detector
match: |
  CREATE ROLE app_runtime LOGIN;
  ALTER ROLE app_runtime WITH SUPERUSER BYPASSRLS;
  GRANT ALL PRIVILEGES ON DATABASE app TO app_runtime;
nomatch: |
  CREATE ROLE app_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
  CREATE ROLE app_migrator NOLOGIN;
  GRANT SELECT, INSERT, UPDATE, DELETE ON app.orders TO app_runtime;
```

The detector is a candidate shape, not a cross-engine parser. The adapter must
confirm what each keyword means for the selected engine and version.

### 2. Native authorization and tenant isolation (`database-native-authorization-and-tenant-isolation`)

Define the invariant without naming a feature:

> A server-derived principal and tenant may perform only the allowed operation
> on the allowed resource; missing or malformed tenant context fails closed; no
> alternate native path returns or mutates another tenant's data.

Then test the engine's actual mechanism.

- State the tenant unit: database/account, schema/keyspace, table/collection,
  partition key, row/item/document, field/property, graph label/subgraph,
  namespace or key prefix. If enforcement is application-only, say so and test
  direct native clients as the privileged control.
- Enumerate read-exact, list/query, aggregate, create, update, tenant-key
  transition, upsert, delete, bulk/batch, transaction and watch/change-stream
  separately. Read filtering does not imply write blocking.
- Derive tenant context on the server or from a verified identity. Never accept
  a caller-selected namespace, database, collection, index, partition prefix,
  session variable or policy role as authority.
- Make tenant ownership fields immutable after create, or enforce old and new
  images. Null or missing policy attributes must fail closed.
- Deny direct base-object access where a secure view, procedure, alias or API is
  the intended boundary. Test source collections, tables, indices and aliases.
- Expand every effective role. A restrictive role plus an unrestricted role is
  assessed according to the adapter's composition semantics, never intuition.
- Test owners, administrators, bypass principals, service/admin SDKs, backup and
  CDC identities. Their ability to bypass may be intended; accidental assignment
  to application paths is the finding.
- Where the engine lacks the required granularity, require and test an explicit
  alternative: separate account/database/schema/collection/index/namespace,
  distinct principal, fixed view/procedure, partition-key invariant, or
  application-only enforcement. Absence of a named RLS feature is not itself a
  finding.

```detector
match: |
  CREATE TABLE app.orders (tenant_id text, order_id text);
  ALTER TABLE app.orders ENABLE ROW LEVEL SECURITY;
  GRANT SELECT, INSERT, UPDATE, DELETE ON app.orders TO app_runtime;
nomatch: |
  CREATE TABLE app.orders (tenant_id text NOT NULL, order_id text);
  ALTER TABLE app.orders ENABLE ROW LEVEL SECURITY;
  ALTER TABLE app.orders FORCE ROW LEVEL SECURITY;
  CREATE POLICY orders_tenant ON app.orders USING (tenant_id = current_setting('app.tenant')) WITH CHECK (tenant_id = current_setting('app.tenant'));
```

The match demonstrates the incomplete-control shape: enabling a mechanism with
no policy and no write check. It does not declare this syntax universal.

### 3. Privileged code and execution context (`database-privileged-code-and-execution-context`)

Inventory views, routines, procedures, functions, triggers, events, jobs,
scripts, UDFs, extensions, modules, plugins, import/export features and external
links.

- Record creator/owner/definer, execution context, active roles, name resolution,
  search path, signature/certificate, caller permissions and reachable objects.
- Default definer behavior is version- and engine-specific. A privileged
  definition omitted from source can be inherited from the migration runner.
- Prefer invoker context where it preserves the required behavior. Where
  elevation is intentional, use a locked least-privileged owner/definer or a
  narrowly signed module, fixed object references and strict parameter
  validation.
- Revoke direct access to protected base objects. A secure wrapper beside a
  direct grant is not a boundary.
- Trace dynamic query or Cypher construction to web-and-api for injection while
  keeping the elevated execution context here.
- Treat caller-provided scripts, JavaScript/Lua bodies, expressions, map/reduce,
  boosted graph procedures, extension/module load and database-to-OS/file/network
  features as code execution or administrative capabilities.
- Check orphan/stale definers, inherited privileges, public execute grants,
  unsafe search paths and migration operations that drop signatures or recreate
  objects under a stronger owner.

```detector
match: |
  CREATE DEFINER = 'admin'@'%' PROCEDURE app.export_all()
  SQL SECURITY DEFINER
  BEGIN SELECT * FROM app.customers; END;
  GRANT EXECUTE ON PROCEDURE app.export_all TO 'app_runtime'@'%';
nomatch: |
  CREATE DEFINER = 'app_exporter'@'localhost' PROCEDURE app.export_tenant(IN p_tenant varchar(64))
  SQL SECURITY DEFINER
  BEGIN SELECT customer_id FROM app.customers WHERE tenant_id = p_tenant; END;
  GRANT EXECUTE ON PROCEDURE app.export_tenant TO 'app_runtime'@'10.%';
```

### 4. Integrity, transactions and concurrency (`database-integrity-transactions-and-concurrency`)

The database must preserve the security-relevant invariant under its real
consistency model.

- Identify which validations are database-enforced: non-null, type/schema,
  uniqueness, foreign keys, checks, immutability, ownership and valid-state
  transitions. Application validation alone has every alternate writer as a
  bypass.
- Read engine and storage-engine transaction semantics before reasoning about
  rollback. DDL, multi-document operations, scripts and external side effects
  may have different atomicity.
- Test two sessions for lost update, write skew, stale authorization, duplicate
  redemption, double spend and tenant-key races. File the product invariant with
  business logic; file the incorrect isolation/constraint mechanism here.
- Include batch, bulk, retry, upsert and partial-failure behavior. A transaction
  API does not establish that every operation joined it.
- Treat replica lag and eventual consistency as authorization inputs when a
  stale read can re-enable a revoked identity, resurrect an object, overspend a
  limit or expose recently deleted data.
- Verify schema validators apply to existing and new data, every write concern
  is checked, and conflicts are not swallowed as success.

### 5. Resource governance and availability (`database-resource-governance-and-availability`)

Evaluate cost at the store, not only request rate at the API.

- Bound scans, result rows, page size, aggregation buckets, regex complexity,
  graph depth/path expansion, joins, sort memory, vector `top_k`, script runtime,
  change-stream backlog and export size.
- Require connection, statement/query, lock and transaction timeouts; bounded
  pools and queues; cancellation; and per-tenant cost controls where one tenant
  can consume shared capacity.
- Check index support for authorization predicates and common bounded queries.
  A correct policy that forces an unindexed full scan can be an availability
  vulnerability.
- Model hot partition/key/tenant behavior, cache stampedes, eviction of security
  state, unbounded key cardinality, memory/disk high-water marks and CDC/audit
  queues that can fill the store.
- Split ordinary data commands from scripting, schema, reindex, flush, snapshot,
  restore, replication and administrative commands. Application principals
  should not hold the latter.
- Use synthetic bounded explain/plans or local fixtures. Never run a destructive
  or unbounded load proof against a shared store.

### 6. Migration security drift (`database-migration-security-drift`)

A final migration file is not the deployed catalog. Compare four paths:

1. Fresh creation from zero.
2. Upgrade from the oldest supported release.
3. Rollback and re-apply where rollback is supported.
4. Restore or clone followed by current migrations.

For each, introspect and normalize principals, role memberships, direct grants,
owners/definers, row/document/field policies, protected object set, functions and
triggers, signatures, extensions/modules, contexts, replication objects and
audit configuration. The sets must converge.

- New tables, partitions, collections, indexes, history tables and tenant types
  must inherit or receive the intended security control.
- `CREATE OR REPLACE`, `ALTER`, drop/recreate and ownership changes can preserve
  stale grants or remove signatures, policies and audit associations.
- A migration runner with owner/admin authority can stamp that authority onto
  definer objects even after its own grant is removed.
- A policy temporarily disabled for a backfill must be re-enabled on every exit,
  including errors and interrupted deployments.
- Seed/default roles and bootstrap users must not survive into production.
- Store expected normalized catalog snapshots as test artifacts. A text grep of
  migration files cannot prove convergence.

```detector
match: |
  ALTER TABLE app.orders DISABLE ROW LEVEL SECURITY;
  UPDATE app.orders SET normalized = true;
nomatch: |
  BEGIN;
  ALTER TABLE app.orders DISABLE ROW LEVEL SECURITY;
  UPDATE app.orders SET normalized = true;
  ALTER TABLE app.orders ENABLE ROW LEVEL SECURITY;
  COMMIT;
```

The nomatch is only a static candidate clearance. The migration proof still
introspects the final catalog and exercises interruption behavior.

### 7. Replication, CDC, history and sharing (`database-replication-cdc-history-and-sharing`)

Every copy path is a separate authorization boundary:

- Capture: what rows/items/documents, old/new images, keys, schema and metadata
  enter the stream or history store?
- Filter: where is tenant/record filtering applied, under which identity, and
  what operations bypass it?
- Transport: which principal and channel can read or redirect the copy?
- Apply: which identity writes the destination, and are its grants checked?
- Destination: do source policies, grants, labels, masks, deletion and audit
  semantics exist there independently?

Inventory logical/physical replication, CDC, change tracking/streams, temporal
history, global tables, cross-cluster replication, indexers, ETL, warehouse/BI
shares and export jobs. Test them using cross-tenant canaries. A primary query
returning tenant A only says nothing about a CDC role that returns A and B.

Treat replication slots/log retention, change-stream pre/post images, trail
files, dead-letter queues and local CDC segments as data stores with their own
availability and lifecycle behavior.

### 8. Backup, restore and clone security (`database-backup-restore-and-clone-security`)

Cloud configuration owns whether managed backups are enabled and encrypted.
This lens asks whether the native backup is consistent and whether restore
reconstructs a security-equivalent system.

- Identify the snapshot/backup principal, included databases/collections,
  consistency point, transaction/WAL/oplog requirements and restore identity.
- Record whether users, roles, grants, policies, audit state, keys, extensions,
  scripts, security indices and tenant metadata are included, excluded or
  separately restored.
- Restrict list/read/restore/clone/export authority separately from ordinary
  application access. Restore-from-URL and remote reindex are outbound-fetch
  capabilities as well as restore operations.
- Restore into a disposable local destination and compare normalized catalog
  state plus synthetic tenant markers. A backup command returning zero is not a
  restore test.
- Require post-restore reconciliation before exposure: current migrations,
  security catalog, revoked identities, deletion ledger and audit forwarding.
- Treat lower-environment clones and analyst extracts as copies; route their
  lawful purpose and retention to privacy.

### 9. Audit identity and coverage (`database-audit-identity-and-coverage`)

Prove the audit trail rather than inferring it from an installed feature.

- Successful and failed data-plane reads/writes, bulk/export, stored-code
  execution, schema/security changes, login failures, privilege changes,
  replication/CDC and backup/restore each need an explicit disposition.
- Record original/authenticated, session and effective/definer identities,
  application end user/tenant, action, target, outcome, row/byte count where
  safe, timestamp and correlation identifier. Do not log secrets or full
  sensitive query parameters to obtain attribution.
- A pooled application's shared database username is not the acting human.
  Verify a trusted context or correlation path reaches the audit sink and is
  cleared on pool return.
- Determine whether "success" means authorization succeeded or the operation
  completed. Include per-item outcomes for bulk operations where the engine
  reports them separately.
- Test audit filters, successful-event inclusion, node/coordinator coverage,
  dropped-event/blocking behavior, queue/disk exhaustion and restart/failover.
- Separate the authority to administer or purge audit from the authority being
  audited, and export to a tamper-separated destination where supported.

### 10. Lifecycle and copy propagation (`database-lifecycle-and-copy-propagation`)

Start from a deletion or expiry requirement established by privacy or product
policy; do not invent the deadline here.

- Trace delete, soft delete, TTL, tombstone, compaction/vacuum, index/cache
  removal, stream events, replicas, search/vector/analytics copies, snapshots,
  restores and replays.
- Distinguish logical invisibility from physical removal. A tombstone or expired
  item may remain in storage, backups, streams or eventually consistent reads.
- Verify restored data re-applies deletions that happened after the backup.
- Check TTL is enabled on the right field/unit, cannot be caller-extended without
  authority, and has monitored lag/failure behavior.
- Make secondary-store ingestion and deletion idempotent. A dropped delete event
  must be detected and repairable by reconciliation.
- Report unsupported guarantees explicitly. Do not promise immediate deletion
  from an engine that offers eventual convergence.

## Severity calibration

These are impact grades before `_schema.md` applies reachability and proof caps.

| Finding | Claimed impact severity | Establishing artifact |
|---|---|---|
| Untrusted or ordinary application principal can execute database-to-OS/network code, load a module, or gain owner/system authority | Critical | Exact privilege plus a reachable native operation or privileged module path |
| Cross-tenant or cross-customer bulk read/write through a native policy, direct base object, service/admin client, CDC, replica, snapshot or restore path | Critical | Two-subject attack showing another tenant's marker or a static path with reachability still capped pending proof |
| Unauthenticated native store permits sensitive read/write or administrative commands | Critical | Deployed/default auth state plus a reachable data path; network exposure itself remains cloud-and-iac |
| Runtime application identity owns the store or can alter principals, policies, audit, replication or backup authority | High; Critical when a reachable path yields mass exfiltration or system execution | Effective-principal expansion and reachable application connection |
| Tenant write escape, including changing an ownership key, inserting another tenant's item or bypassing a write predicate | High | Old/new image or create proof under the ordinary tenant principal |
| Privileged definer/boosted/signed routine exposes operations beyond its intended contract | High | Execution context, caller grant and concrete overreach |
| Migration, restore or failover drops or disables a security invariant | High | Normalized catalog diff plus affected operation; Medium while the deployed path is unknown |
| CDC, stream, history, replica, backup or export identity has unnecessary bulk-read authority | High | Copy-path principal and cross-boundary marker |
| Audit omits or misattributes successful sensitive data access or security administration | High for regulated/high-value stores; Medium otherwise | Valid audit probe naming missing actor/action/outcome |
| Authenticated tenant can exhaust shared database capacity with one ordinary request | High where it denies all tenants; Medium where bounded to its own quota | Safe bounded cost proof or query plan |
| Security-relevant transaction/consistency choice permits duplicate or stale authorization behavior | High when it changes money/authority or crosses tenants; Medium otherwise | Two-session or stale-replica proof |
| Incomplete deletion propagation after a valid requirement is established | Severity inherited from privacy/data classification, capped by evidence | Copy map plus observable surviving record |
| Version/edition is unknown and a required semantic cannot be assessed | Info coverage gap, not a vulnerability | Store profile with conflicting or missing evidence |

Never report High or Critical from a dialect grep. T0, T3, UNPROVEN,
INCONCLUSIVE and unresolved reachability remain capped by `_schema.md`.

## Known false positives

1. **"This engine has no RLS."** Not a finding. Establish the required
   granularity and evaluate deliberate database/schema/collection/partition/view
   or application enforcement.
2. **"RLS is enabled, therefore the store is safe."** Read and write operations,
   policy state, owner/bypass behavior, direct paths, history and CDC are
   separate.
3. **"An administrator can bypass policy."** Intended administrative capability
   is not a finding by itself. Accidental assignment, application reachability,
   no separation or no audit is.
4. **"A definer or elevated object exists."** Elevation is often the point. A
   view, routine, trigger or boosted procedure needs excess authority, unsafe
   inputs/name resolution, a broad caller grant or direct base bypass.
5. **"A restrictive role exists."** Expand all effective roles and adapter
   composition. One broad role may dominate, union, or activate differently.
6. **"A DENY exists."** Deny precedence and missing-attribute behavior differ by
   engine, scope and operation.
7. **"The database is encrypted."** Encryption does not establish authentication,
   authorization, integrity, audit or deletion.
8. **"A backup command exists."** It does not establish consistency,
   restorability, protected storage or security-state convergence.
9. **"The replica is read-only."** Read-only can still mean complete
   exfiltration; it says nothing about who may connect or what policies apply.
10. **"Redis database numbers isolate tenants."** Logical database selection is
    not an ACL boundary. Evaluate keys, channels and commands.
11. **"A Firestore query omits a tenant predicate."** Rules are not filters; the
    adapter must determine whether the query is rejected, while server/admin
    clients use a separate enforcement path.
12. **"A filtered search alias protects an index."** An alias is a query
    convenience unless the selected engine's native security control enforces
    it and direct index access is denied.
13. **"SQLite lacks database users."** It is an embedded file store. Assess
    filesystem/process trust, query construction elsewhere, concurrency, backup
    and integrity rather than inventing server roles.
14. **"The migration contains the final policy."** Only ordered execution and
    catalog introspection establish deployed state.
15. **"The connection string names an administrator."** A username-shaped token
    is a candidate; aliases, local test containers and managed identity may
    resolve differently. Confirm the profile without printing a secret.
16. **Fixtures, examples, vendor dumps and generated schemas.** They do not
    establish a deployed store until an execution path includes them. Still
    exclude them explicitly from the assessed denominator.

## Proof recipes

All proofs inherit `_harness.md`'s hard rails. Never point a database proof at a
shared, production, cloud or credential-bearing endpoint. Use a disposable local
engine/container/emulator supplied by the repository, synthetic markers and a
dedicated security-test directory. Starting an engine the repository does not
already start is T2 and requires approval.

### P1 - Adapter fixture pair (T1)

Every adapter rule that ships as an automated detector has a vulnerable and
clean fixture. Run the same local detector against both and assert:

```text
detect(vulnerable) == 1
detect(clean) == 0
```

Also assert that an incorrect or ambiguous adapter never clears either fixture.
A parser test proves detection logic, not live engine semantics; it cannot by
itself confirm a High or Critical runtime finding.

### P2 - Two-subject direct-client matrix (T1 or T2)

Create tenant A and tenant B, an ordinary principal for each, a privileged
control and unmistakable synthetic markers. Exercise the native client directly:

```text
get, list/query, aggregate
create, update, tenant-key transition, upsert, delete
batch/bulk, transaction
view/alias/base object
stored code/script
watch/CDC/history/replica
snapshot/restore
```

Each denial must be the expected authorization failure, not an empty query caused
by bad setup. Prove the path was reached and make the privileged control retrieve
the B marker so the test demonstrates sensitivity.

### P3 - Pool-context reset (T1)

With a pool size of one, set tenant A context, return the connection, borrow it as
tenant B before setting context, and attempt both read and write. Missing context
must fail closed; B must never observe A. Repeat after error/rollback and
cancellation paths. Where the engine can make context immutable/read-only for
the transaction, assert that too.

### P4 - Catalog convergence (T1)

Build fresh, upgrade, rollback/re-apply and restore states. Normalize adapter
catalog queries into sorted JSON and compare principals, memberships, grants,
owners/definers, policies, protected objects, signatures, modules/extensions,
replication and audit state. A changed expected snapshot receives review; it is
not automatically accepted.

### P5 - Copy-path canary (T1 or T2)

Insert A and B markers, then consume CDC/history/replica/export using the
ordinary application identity and the dedicated copy identity. Assert exact
visibility, old/new image handling, deletion propagation and audit events.
Exercise the documented adapter exception, not a generic stream mock.

### P6 - Restore security equivalence (T2)

Back up the disposable store, revoke one identity and delete one marker, restore
to a new local destination, apply the reconciliation hook, then compare normalized
security state and data expectations. The restored endpoint remains isolated
until the comparison passes.

### P7 - Audit attribution and tamper separation (T1 or T2)

Perform one successful and one denied read/write, one privileged-module call,
one grant/policy change and one copy operation. Assert original and effective
actors, tenant/correlation, target, operation and outcome. Then use the ordinary
principal to alter or purge audit; it must fail. A log line from the application
does not substitute for the native data-plane event.

### P8 - Safe availability bounds (T1)

Use a tiny synthetic data set and explain/query-plan APIs, injected clocks and
counting fakes. Assert page/result/top-k/depth limits, timeouts, pool limits,
per-tenant quota and cancellation without generating material load. Never prove
availability by attempting exhaustion.

### Coverage output

The report includes one row per store:

| Store ID | Engine/version/deployment | Adapter | Enforcement | Copy paths | Assessed capabilities | Gaps |
|---|---|---|---|---|---|---|

Capability cells are only **COVERED**, **PARTIAL** or **NOT ASSESSED**. COVERED
requires an exact adapter/version source, a both-direction fixture for every
applicable automated rule, direct two-subject proof for behavioral authorization
claims and no unsupported path relevant to the claim. The per-store row is
mandatory even when the lens produces no findings.
