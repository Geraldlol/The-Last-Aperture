import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import {
  DATABASE_DISCOVERY_KIND,
  DATABASE_DISCOVERY_SCHEMA_VERSION,
  DatabaseDiscoveryValidationError,
  discoverDatabaseGraph,
  serializeDatabaseDiscovery,
  validateDatabaseDiscovery,
} from '../scripts/lib/database-discovery.mjs'

const schema = JSON.parse(readFileSync(
  fileURLToPath(new URL('../schemas/database-discovery.schema.json', import.meta.url)),
  'utf8',
))
const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  validateFormats: false,
})
const validateSchema = ajv.compile(schema)

function text(path, content) {
  return {
    path,
    kind: 'text',
    size: Buffer.byteLength(content),
    content,
  }
}

function binary(path, size = 12) {
  return { path, kind: 'binary', size }
}

function reverseCopy(values) {
  return [...values].reverse().map((value) => ({ ...value }))
}

function nodeSubtypes(graph) {
  return new Set(graph.nodes.map((node) => node.subtype))
}

test('database discovery is deterministic, canonical, schema-valid, and input-order neutral', () => {
  const inventory = [
    text('package.json', JSON.stringify({
      dependencies: { pg: '8.13.1' },
    }, null, 2)),
    text('src/db.ts', `
      import { Pool } from 'pg'
      const pool = new Pool({ connectionString: process.env.DATABASE_URL })
      export const load = () => pool.query('SELECT id FROM accounts')
    `),
    text('src/not-database.ts', 'export const answer = 42'),
    binary('assets/logo.png'),
  ]

  const first = discoverDatabaseGraph(inventory)
  const second = discoverDatabaseGraph(reverseCopy(inventory))

  assert.deepEqual(first, second)
  assert.equal(first.schema_version, DATABASE_DISCOVERY_SCHEMA_VERSION)
  assert.equal(first.kind, DATABASE_DISCOVERY_KIND)
  assert.match(first.digest, /^sha256:[a-f0-9]{64}$/)
  assert.deepEqual(validateDatabaseDiscovery(first), { valid: true, errors: [] })
  assert.equal(validateSchema(first), true, JSON.stringify(validateSchema.errors))
  assert.equal(serializeDatabaseDiscovery(first), serializeDatabaseDiscovery(second))
  assert.equal(serializeDatabaseDiscovery(first).endsWith('\n'), true)
  assert.equal(first.store_candidates.length, 1)
  assert.deepEqual(first.store_candidates[0].engine_candidates, ['postgresql'])
  assert.equal(
    first.path_scope.find((item) => item.path === 'assets/logo.png').reasons[0].code,
    'non-text-entry',
  )
  assert.equal(
    first.path_scope.find((item) => item.path === 'src/not-database.ts').reasons[0].code,
    'no-database-evidence',
  )
})

test('enterprise-scale mixed-case inventory retains exact canonical path_scope order', () => {
  const rootPaths = [
    'AUDIT_REPORT.md',
    'CLAUDE.md',
    'DEPLOYMENT_GUIDE.md',
    'PLATFORM_MIGRATION_REFERENCE.md',
    'README.md',
    'SERVICE_CATALOG.md',
    'SYSTEM_GUIDE.md',
  ]
  const frontendPaths = Array.from(
    { length: 512 },
    (_, index) =>
      `frontend-app/dist/chunk-${String(index).padStart(4, '0')}.js`,
  )
  const servicePaths = Array.from(
    { length: 8_192 },
    (_, index) =>
      `services/core/src/modules/Module${String(index).padStart(4, '0')}.ts`,
  )
  const expectedPaths = [
    ...rootPaths,
    ...frontendPaths,
    ...servicePaths,
  ]
  assert.equal(expectedPaths.length, 8_711)

  const graph = discoverDatabaseGraph(
    [...expectedPaths].reverse().map((path) => binary(path)),
  )
  const scopedPaths = graph.path_scope.map(({ path }) => path)

  assert.deepEqual(scopedPaths, expectedPaths)
  assert.equal(new Set(scopedPaths).size, expectedPaths.length)
  assert.equal(graph.stats.inventory_entries, expectedPaths.length)
})

test('controller path identities are preserved without whitespace normalization', () => {
  const inventory = [
    {
      path: ' db-client.ts',
      kind: 'text',
      size: 24,
      content: 'export const first = true\n',
    },
    {
      path: 'db-client.ts ',
      kind: 'text',
      size: 25,
      content: 'export const second = true\n',
    },
  ]
  const first = discoverDatabaseGraph(inventory)
  const reversed = discoverDatabaseGraph([...inventory].reverse())

  assert.deepEqual(first, reversed)
  assert.deepEqual(
    first.path_scope.map(({ path }) => path),
    [' db-client.ts', 'db-client.ts '],
  )
})

test('client dependency and infrastructure API versions never become server versions', () => {
  const graph = discoverDatabaseGraph([
    text('scheduler-app/package.json', JSON.stringify({
      dependencies: { pg: '99.77.55' },
    })),
    text('scheduler-app/infra/postgres.bicep', `
      resource postgresServer 'Microsoft.DBforPostgreSQL/flexibleServers@2099-12-31-preview' = {
        name: 'scheduler-database'
        properties: {
          version: '16'
        }
      }
      output databaseUrl string = 'provided-at-runtime'
    `),
  ])

  assert.equal(graph.store_candidates.length, 1)
  assert.deepEqual(graph.store_candidates[0].engine_candidates, ['postgresql'])
  assert.deepEqual(graph.store_candidates[0].engine_version_candidates, ['16'])
  const serialized = serializeDatabaseDiscovery(graph)
  assert.doesNotMatch(serialized, /99\.77\.55/)
  assert.doesNotMatch(serialized, /2099-12-31-preview/)
  assert.match(serialized, /"engine_version_candidates": \[\s+"16"/)
})

test('local Redis and Azure Redis resources remain separate protection domains', () => {
  const graph = discoverDatabaseGraph([
    text('scheduler-app/docker-compose.yml', `
      services:
        redis:
          image: redis:7-alpine
    `),
    text('scheduler-app/infra/modules/redis.bicep', `
      resource redis 'Microsoft.Cache/redis@2024-03-01' = {
        name: 'audit-fixture-redis'
        properties: {
          enableNonSslPort: false
        }
      }
    `),
    text('scheduler-app/infra/prod.arm.json', JSON.stringify({
      resources: [
        {
          type: 'Microsoft.Cache/redisEnterprise',
          name: 'audit-fixture-managed-redis',
        },
      ],
    })),
  ])

  assert.equal(graph.store_candidates.length, 3)
  assert.deepEqual(
    graph.store_candidates
      .map((candidate) => candidate.deployment_candidates[0])
      .sort(),
    ['azure-cache-for-redis', 'azure-managed-redis', 'container'],
  )
  assert.equal(
    graph.store_candidates.every((candidate) =>
      candidate.engine_candidates.length === 1
      && candidate.engine_candidates[0] === 'redis'),
    true,
  )
  assert.equal(
    new Set(graph.store_candidates.map((candidate) => candidate.store_id)).size,
    3,
  )
})

test('unconnected docs, tests, fixtures, generated files, and DSN literals remain context-only', () => {
  const graph = discoverDatabaseGraph([
    text('README.md', `
      Example only: postgres://example_admin:do-not-copy@example.invalid/sample
      Set DATABASE_URL before starting.
    `),
    text('test/db.test.ts', `
      import { Pool } from 'pg'
      new Pool({ connectionString: process.env.DATABASE_URL })
    `),
    text('fixtures/schema.sql', `
      CREATE TABLE example_only (id bigint);
      ALTER TABLE example_only ENABLE ROW LEVEL SECURITY;
    `),
    text('package-lock.json', JSON.stringify({
      packages: {
        'node_modules/pg': { version: '8.99.0' },
      },
    })),
    text('src/math.ts', 'export const add = (a, b) => a + b'),
  ])

  assert.equal(graph.store_candidates.length, 0)
  for (const path of ['README.md', 'test/db.test.ts', 'fixtures/schema.sql']) {
    const scope = graph.path_scope.find((item) => item.path === path)
    assert.equal(scope.state, 'context-only')
    assert.equal(
      graph.nodes.filter((node) => node.evidence.some((item) => item.path === path))
        .every((node) => node.context_only),
      true,
    )
  }
  assert.equal(
    graph.path_scope.find((item) => item.path === 'package-lock.json').state,
    'out-of-scope',
  )
  assert.equal(
    graph.unresolved.filter((item) => item.type === 'context-only-evidence').length,
    3,
  )
  const serialized = serializeDatabaseDiscovery(graph)
  assert.doesNotMatch(serialized, /example_admin/)
  assert.doesNotMatch(serialized, /do-not-copy/)
  assert.doesNotMatch(serialized, /example\.invalid/)
  assert.doesNotMatch(serialized, /postgres:\/\//)
  assert.doesNotMatch(serialized, /8\.99\.0/)
})

test('browser caches, generic query clients, and service connection strings do not invent a database', () => {
  const graph = discoverDatabaseGraph([
    text('src/web-client.ts', `
      export async function loadGraph(client, request) {
        const cached = await caches.match(request)
        return cached ?? client.query({ query: 'CurrentViewer' })
      }
      export const serviceConnection = process.env.CONNECTION_STRING
    `),
  ])

  assert.equal(graph.store_candidates.length, 0)
  assert.equal(nodeSubtypes(graph).has('query-path'), false)
  assert.equal(nodeSubtypes(graph).has('cache'), false)
  assert.equal(
    graph.unresolved.some((item) => item.type === 'ambiguous-connection-config'),
    true,
  )
})

test('generic save calls and permission denials do not block a real PostgreSQL adapter candidate', () => {
  const graph = discoverDatabaseGraph([
    text('package.json', JSON.stringify({
      dependencies: { pg: '8.13.1' },
    })),
    text('src/index.ts', `
      import { Pool } from 'pg'
      import { initializeSchema } from './store/pgAdapter'
      import { saveSession } from './store/sessionStores'
      import './accessPolicy'
      const pool = new Pool({
        connectionString: process.env.CONNECTION_STRING,
      })
      export const start = async () => {
        await initializeSchema(pool)
        await saveSession(pool, 'runtime-session')
        return pool.query('SELECT 1')
      }
    `),
    text('src/store/pgAdapter.ts', `
      export const initializeSchema = pool =>
        pool.query('CREATE TABLE IF NOT EXISTS sessions (id text primary key)')
    `),
    text('src/store/sessionStores.ts', `
      export const saveSession = (repository, id) => {
        repository.save({ id })
        return repository.query('INSERT INTO sessions (id) VALUES ($1)', [id])
      }
    `),
    text('src/accessPolicy.ts', `
      export function assertRuntimeBoundary(denied) {
        if (!denied) throw new Error('The runtime permission boundary must deny access')
      }
    `),
  ])

  assert.equal(graph.store_candidates.length, 1)
  const [store] = graph.store_candidates
  assert.deepEqual(store.engine_candidates, ['postgresql'])
  for (const path of [
    'package.json',
    'src/index.ts',
    'src/store/pgAdapter.ts',
    'src/store/sessionStores.ts',
  ]) {
    assert.equal(store.scope_paths.includes(path), true, `${path} should be in store scope`)
  }
  assert.equal(
    graph.nodes.some((node) =>
      node.evidence.some((item) =>
        item.signature_id === 'copy.redis-persistence'
        || item.signature_id === 'artifact.security.neo4j-privilege')),
    false,
  )
  assert.equal(
    graph.unresolved.some((item) => item.type === 'ambiguous-binding-target'),
    false,
  )
})

test('a runtime better-sqlite3 open promotes an embedded SQLite store without infrastructure', () => {
  const graph = discoverDatabaseGraph([
    text('package.json', JSON.stringify({
      dependencies: { 'better-sqlite3': '12.11.1' },
    })),
    text('scripts/read-cookies.mjs', `
      import SqliteDatabase from 'better-sqlite3'
      import { resolve } from 'node:path'
      const databasePath = resolve('runtime/cookies.sqlite')
      const db = new SqliteDatabase(databasePath, { readonly: true })
      export const cookies = () => db.prepare(
        'SELECT host_key, name FROM cookies'
      ).all()
    `),
  ])

  assert.deepEqual(graph, discoverDatabaseGraph(reverseCopy([
    text('package.json', JSON.stringify({
      dependencies: { 'better-sqlite3': '12.11.1' },
    })),
    text('scripts/read-cookies.mjs', `
      import SqliteDatabase from 'better-sqlite3'
      import { resolve } from 'node:path'
      const databasePath = resolve('runtime/cookies.sqlite')
      const db = new SqliteDatabase(databasePath, { readonly: true })
      export const cookies = () => db.prepare(
        'SELECT host_key, name FROM cookies'
      ).all()
    `),
  ])))
  assert.equal(graph.store_candidates.length, 1)
  const [store] = graph.store_candidates
  assert.deepEqual(store.engine_candidates, ['sqlite'])
  assert.deepEqual(store.deployment_candidates, ['sqlite-embedded'])
  assert.equal(store.confidence, 'high')
  assert.deepEqual(store.scope_paths, [
    'package.json',
    'scripts/read-cookies.mjs',
  ])
  assert.equal(
    store.open_reasons.includes('connection-binding-unresolved'),
    false,
  )
  const signatureIds = new Set(store.node_ids.flatMap((nodeId) =>
    graph.nodes
      .find((node) => node.node_id === nodeId)
      ?.evidence.map((item) => item.signature_id) ?? []))
  assert.equal(signatureIds.has('resource.runtime.sqlite-open'), true)
  assert.equal(signatureIds.has('binding.runtime.sqlite-open'), true)
  assert.deepEqual(validateDatabaseDiscovery(graph), { valid: true, errors: [] })
})

test('an exact production import promotes an otherwise context-classified file', () => {
  const graph = discoverDatabaseGraph([
    text('package.json', JSON.stringify({ dependencies: { pg: '8.0.0' } })),
    text('src/db.ts', `
      import { Pool } from 'pg'
      import { databaseUrl } from '../fixtures/runtime-config'
      export const pool = new Pool({ connectionString: databaseUrl })
    `),
    text('fixtures/runtime-config.ts', `
      export const databaseUrl = process.env.DATABASE_URL
    `),
  ])

  const fixtureScope = graph.path_scope.find((item) =>
    item.path === 'fixtures/runtime-config.ts')
  assert.equal(fixtureScope.state, 'in-scope')
  assert.equal(
    fixtureScope.reasons.some((reason) => reason.code === 'exact-relative-import'),
    true,
  )
  assert.equal(
    graph.nodes
      .filter((node) =>
        node.evidence.some((item) => item.path === 'fixtures/runtime-config.ts'))
      .every((node) => node.context_only === false),
    true,
  )
  assert.equal(graph.store_candidates.length, 1)
})

test('Bicep to DATABASE_URL to Pool evidence resolves as one store graph', () => {
  const inventory = [
    text('scheduler-app/package.json', JSON.stringify({
      dependencies: { pg: '8.13.1' },
    })),
    text('scheduler-app/infra/main.bicep', `
      module postgres './modules/postgres.bicep' = {
        name: 'postgres'
      }
      module apps './modules/apps.bicep' = {
        name: 'apps'
        params: {
          databaseUrl: postgres.outputs.databaseUrl
        }
      }
    `),
    text('scheduler-app/infra/modules/postgres.bicep', `
      resource postgresServer 'Microsoft.DBforPostgreSQL/flexibleServers@2023-12-01-preview' = {
        name: 'audit-fixture-postgres'
        properties: {
          version: '16'
          backup: {
            backupRetentionDays: 14
            geoRedundantBackup: 'Enabled'
          }
          replicaCount: 1
        }
      }
      output databaseUrl string = 'assembled-by-deployment'
    `),
    text('scheduler-app/infra/modules/apps.bicep', `
      param databaseUrl string
      resource api 'Microsoft.App/containerApps@2024-03-01' = {
        name: 'scheduler-api'
        properties: {
          template: {
            containers: [{
              env: [{
                name: 'DATABASE_URL'
                secretRef: 'database-url'
              }]
            }]
          }
        }
      }
    `),
    text('scheduler-app/service/src/db.ts', `
      import { Pool } from 'pg'
      const pool = new Pool({
        connectionString: process.env.DATABASE_URL,
      })
      export const nextMeeting = () => pool.query(
        'SELECT id FROM meetings WHERE tenant_id = $1'
      )
    `),
    text('scheduler-app/service/migrations/001-security.sql', `
      CREATE ROLE scheduler_runtime;
      GRANT SELECT ON meetings TO scheduler_runtime;
      ALTER TABLE meetings ENABLE ROW LEVEL SECURITY;
      CREATE POLICY tenant_meetings ON meetings USING (tenant_id = current_setting('app.tenant'));
      CREATE FUNCTION next_meeting() RETURNS bigint SECURITY DEFINER LANGUAGE SQL
        AS 'SELECT 1';
      CREATE PUBLICATION scheduler_cdc FOR TABLE meetings;
      COPY meetings TO STDOUT;
      CREATE MATERIALIZED VIEW meeting_counts AS SELECT count(*) FROM meetings;
    `),
  ]

  const graph = discoverDatabaseGraph(inventory)

  assert.equal(graph.store_candidates.length, 1)
  const [store] = graph.store_candidates
  assert.equal(store.confidence, 'high')
  assert.deepEqual(store.engine_candidates, ['postgresql'])
  assert.deepEqual(store.engine_version_candidates, ['16'])
  for (const path of [
    'scheduler-app/infra/main.bicep',
    'scheduler-app/infra/modules/postgres.bicep',
    'scheduler-app/infra/modules/apps.bicep',
    'scheduler-app/service/src/db.ts',
  ]) {
    assert.equal(store.scope_paths.includes(path), true, `${path} should be in store scope`)
  }
  assert.equal(
    graph.edges.some((edge) => edge.relation === 'EXACT_RELATIVE_IMPORT'),
    true,
  )
  assert.equal(
    graph.edges.some((edge) => edge.relation === 'EXACT_CONFIG_TOKEN'),
    true,
  )
  assert.equal(
    graph.edges.some((edge) => edge.relation === 'USES_BINDING'),
    true,
  )
  assert.equal(
    graph.edges.some((edge) => edge.relation === 'TARGETS_STORE'),
    true,
  )
  const subtypes = nodeSubtypes(graph)
  for (const subtype of [
    'query-path',
    'schema-or-migration',
    'principal-or-grant',
    'row-authorization-policy',
    'execution-context',
    'replica',
    'cdc',
    'backup',
    'export',
    'cache',
  ]) {
    assert.equal(subtypes.has(subtype), true, `missing ${subtype}`)
  }
  assert.doesNotMatch(serializeDatabaseDiscovery(graph), /2023-12-01-preview/)
})

test('provider-neutral server properties are accepted while generic service connection strings stay unresolved', () => {
  const graph = discoverDatabaseGraph([
    text('orders/infra/database.tf', `
      resource "aws_db_instance" "orders" {
        engine = "mysql"
        engine_version = "8.0.36"
      }
    `),
    text('messaging/config.ts', `
      export const connectionString = process.env.CONNECTION_STRING
    `),
  ])

  assert.equal(graph.store_candidates.length, 1)
  assert.deepEqual(graph.store_candidates[0].engine_candidates, ['mysql'])
  assert.deepEqual(graph.store_candidates[0].engine_version_candidates, ['8.0.36'])
  assert.equal(
    graph.unresolved.some((item) => item.type === 'ambiguous-connection-config'),
    true,
  )
  assert.equal(
    graph.store_candidates.some((candidate) =>
      candidate.evidence_paths.includes('messaging/config.ts')),
    false,
  )
})

test('direct Python, Go, Java, and Rust client manifests produce typed client evidence only', () => {
  const graph = discoverDatabaseGraph([
    text('python/requirements.txt', `
      redis==5.2.1
      snowflake-connector-python==3.12.4
    `),
    text('go/go.mod', `
      module example.test/data
      require github.com/jackc/pgx/v5 v5.7.2
    `),
    text('java/pom.xml', `
      <dependency>
        <groupId>com.mysql</groupId>
        <artifactId>mysql-connector-j</artifactId>
        <version>8.4.0</version>
      </dependency>
    `),
    text('rust/Cargo.toml', `
      [dependencies]
      rusqlite = "0.32.1"
    `),
  ])

  const clientEngines = new Set(
    graph.nodes
      .filter((node) => node.kind === 'client')
      .flatMap((node) => node.engine_candidates),
  )
  for (const engine of ['redis', 'snowflake', 'postgresql', 'mysql', 'sqlite']) {
    assert.equal(clientEngines.has(engine), true, `missing ${engine} client evidence`)
  }
  assert.equal(graph.store_candidates.length, 0)
  assert.equal(
    graph.unresolved.every((item) =>
      item.type === 'client-without-connection-binding'),
    true,
  )
  const serialized = serializeDatabaseDiscovery(graph)
  for (const clientVersion of ['5.2.1', '3.12.4', '5.7.2', '8.4.0', '0.32.1']) {
    assert.doesNotMatch(serialized, new RegExp(clientVersion.replaceAll('.', '\\.')))
  }
})

test('privileged managed-database bindings are typed without leaking their values', () => {
  const graph = discoverDatabaseGraph([
    text('package.json', JSON.stringify({
      dependencies: { '@supabase/supabase-js': '2.99.0' },
    })),
    text('src/admin.ts', `
      import { createClient } from '@supabase/supabase-js'
      const privileged = createClient(
        process.env.SUPABASE_URL,
        process.env.SUPABASE_SERVICE_ROLE_KEY,
      )
      export const bypassRole = 'BYPASSRLS'
    `),
    text('.env.example', `
      SUPABASE_URL=https://project-ref.supabase.co
      SUPABASE_SERVICE_ROLE_KEY=example-secret-that-must-not-escape
    `),
  ])

  assert.equal(
    graph.nodes.some((node) =>
      node.subtype === 'credential-binding'
      && node.engine_candidates.includes('postgresql')),
    true,
  )
  assert.equal(nodeSubtypes(graph).has('row-authorization-policy'), true)
  assert.equal(
    graph.store_candidates.some((candidate) =>
      candidate.deployment_candidates.includes('supabase')),
    true,
  )
  const serialized = serializeDatabaseDiscovery(graph)
  assert.doesNotMatch(serialized, /example-secret-that-must-not-escape/)
  assert.doesNotMatch(serialized, /project-ref\.supabase\.co/)
})

test('nearest manifest roots isolate identical connection tokens in sibling services', () => {
  const inventory = [
    text('package.json', JSON.stringify({
      private: true,
      workspaces: ['services/*'],
    })),
    text('services/mysql/package.json', JSON.stringify({
      dependencies: { mysql2: '3.0.0' },
    })),
    text('services/mysql/src/db.ts', `
      import mysql from 'mysql2'
      const db = mysql.createConnection(process.env.DATABASE_URL)
      export const ping = () => db.query('SELECT 1')
    `),
    text('services/mysql/infra/database.yml', 'image: mysql:8.4'),
    text('services/mongo/package.json', JSON.stringify({
      dependencies: { mongodb: '6.0.0' },
    })),
    text('services/mongo/src/db.ts', `
      import { MongoClient } from 'mongodb'
      const db = new MongoClient(process.env.DATABASE_URL)
      export const connect = () => db.connect()
    `),
    text('services/mongo/infra/database.yml', 'image: mongodb:7.0'),
  ]

  const graph = discoverDatabaseGraph(inventory)
  const permuted = discoverDatabaseGraph(reverseCopy(inventory))

  assert.deepEqual(graph, permuted)
  assert.equal(graph.store_candidates.length, 2)
  const mysql = graph.store_candidates.find((candidate) =>
    candidate.engine_candidates.includes('mysql'))
  const mongodb = graph.store_candidates.find((candidate) =>
    candidate.engine_candidates.includes('mongodb'))
  assert.ok(mysql)
  assert.ok(mongodb)
  assert.deepEqual(mysql.engine_version_candidates, ['8.4'])
  assert.deepEqual(mongodb.engine_version_candidates, ['7.0'])
  assert.equal(
    mysql.scope_paths.every((path) => path.startsWith('services/mysql/')),
    true,
  )
  assert.equal(
    mongodb.scope_paths.every((path) => path.startsWith('services/mongo/')),
    true,
  )
  assert.equal(
    graph.edges.some((edge) => {
      const from = graph.nodes.find((node) => node.node_id === edge.from_node_id)
      const to = graph.nodes.find((node) => node.node_id === edge.to_node_id)
      return edge.relation === 'EXACT_CONFIG_TOKEN'
        && from?.component_root !== to?.component_root
    }),
    false,
  )
  assert.doesNotMatch(serializeDatabaseDiscovery(graph), /postgresql/)
})

test('same-project closure joins a non-PostgreSQL store to security and copy artifacts', () => {
  const inventory = [
    text('orders/package.json', JSON.stringify({
      dependencies: { mssql: '11.0.0' },
    })),
    text('orders/infra/database.tf', `
      resource "aws_db_instance" "orders" {
        engine = "sqlserver-se"
        engine_version = "16.00.4145.4.v1"
      }
    `),
    text('orders/src/db.ts', `
      import sql from 'mssql'
      const pool = sql.connect(process.env.SQLSERVER_URL)
      export const listOrders = () => pool.query('SELECT id FROM orders')
    `),
    text('orders/migrations/001-security.sql', `
      CREATE TABLE orders (id int, tenant_id int);
      CREATE ROLE orders_reader;
      GRANT SELECT ON orders TO orders_reader;
      CREATE SECURITY POLICY tenant_orders
        ADD FILTER PREDICATE dbo.fn_tenant(tenant_id) ON dbo.orders;
      EXECUTE AS USER = 'runtime';
      -- change data capture
      BACKUP DATABASE orders TO DISK = 'runtime-path';
    `),
  ]

  const graph = discoverDatabaseGraph(inventory)
  assert.deepEqual(graph, discoverDatabaseGraph(reverseCopy(inventory)))
  assert.equal(graph.store_candidates.length, 1)
  const [store] = graph.store_candidates
  assert.deepEqual(store.engine_candidates, ['sqlserver'])
  assert.deepEqual(store.engine_version_candidates, ['16.00.4145.4.v1'])
  assert.deepEqual(store.scope_paths, [
    'orders/infra/database.tf',
    'orders/migrations/001-security.sql',
    'orders/package.json',
    'orders/src/db.ts',
  ])
  const storeSubtypes = new Set(store.node_ids.map((nodeId) =>
    graph.nodes.find((node) => node.node_id === nodeId)?.subtype))
  for (const subtype of [
    'query-path',
    'schema-or-migration',
    'principal-or-grant',
    'row-authorization-policy',
    'execution-context',
    'cdc',
    'backup',
  ]) {
    assert.equal(storeSubtypes.has(subtype), true, `store is missing ${subtype}`)
  }
  assert.equal(
    graph.unresolved.some((item) =>
      item.path === 'orders/migrations/001-security.sql'),
    false,
  )
  assert.equal(
    graph.edges.some((edge) => edge.relation === 'USES_BINDING'),
    true,
  )
  assert.equal(
    graph.edges.filter((edge) => edge.relation === 'APPLIES_TO_STORE').length >= 7,
    true,
  )
  assert.deepEqual(validateDatabaseDiscovery(graph), { valid: true, errors: [] })
})

test('SQL and policy artifacts are typed evidence but do not invent an engine or store', () => {
  const graph = discoverDatabaseGraph([
    text('db/migrations/001.sql', `
      CREATE TABLE invoices (id integer);
      CREATE ROLE billing_reader;
      GRANT SELECT ON invoices TO billing_reader;
      CREATE POLICY invoice_tenant ON invoices USING (tenant_id = current_user);
      ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
      CREATE FUNCTION invoice_count() RETURNS integer SECURITY DEFINER
        AS 'SELECT count(*) FROM invoices';
    `),
  ])

  assert.equal(graph.store_candidates.length, 0)
  assert.equal(
    graph.unresolved.some((item) => item.type === 'database-artifact-without-store'),
    true,
  )
  assert.equal(
    graph.nodes
      .filter((node) => ['artifact', 'principal', 'copy'].includes(node.kind))
      .every((node) => node.engine_candidates.length === 0),
    true,
  )
})

test('fixed-point, graph-node, graph-edge, and strong-token fanout caps emit explicit gaps', () => {
  assert.throws(
    () => discoverDatabaseGraph([], { maxNodes: 0 }),
    /maxNodes must be a safe integer/,
  )
  const chain = discoverDatabaseGraph([
    text('src/root.ts', `
      import './a'
      export const databaseUrl = process.env.DATABASE_URL
    `),
    text('src/a.ts', "import './b'"),
    text('src/b.ts', "import './c'"),
    text('src/c.ts', 'export const leaf = true'),
  ], { maxRounds: 1 })
  assert.equal(
    chain.gaps.some((gap) => gap.code === 'fixed-point-round-cap'),
    true,
  )
  const relationCapped = discoverDatabaseGraph([
    text('src/root.ts', `
      import './a'
      export const databaseUrl = process.env.DATABASE_URL
    `),
    text('src/a.ts', "import './b'"),
    text('src/b.ts', "import './c'"),
    text('src/c.ts', 'export const leaf = true'),
  ], { maxEdges: 1 })
  assert.equal(
    relationCapped.gaps.some((gap) => gap.code === 'path-relation-cap'),
    true,
  )

  const capped = discoverDatabaseGraph([
    text('src/db.ts', `
      import { Pool } from 'pg'
      const pool = new Pool({ connectionString: process.env.DATABASE_URL })
      pool.query('SELECT 1')
    `),
  ], { maxNodes: 2, maxEdges: 1 })
  assert.equal(capped.gaps.some((gap) => gap.code === 'graph-node-cap'), true)
  assert.equal(validateDatabaseDiscovery(capped).valid, true)

  const edgeCapped = discoverDatabaseGraph([
    text('src/db.ts', `
      import { Pool } from 'pg'
      const pool = new Pool({ connectionString: process.env.DATABASE_URL })
      pool.query('SELECT 1')
    `),
  ], { maxEdges: 1 })
  assert.equal(edgeCapped.gaps.some((gap) => gap.code === 'graph-edge-cap'), true)
  assert.equal(validateDatabaseDiscovery(edgeCapped).valid, true)

  const fanout = discoverDatabaseGraph([
    text('a/db.ts', 'export const a = process.env.DATABASE_URL'),
    text('a/worker.ts', 'export const b = process.env.DATABASE_URL'),
    text('a/jobs.ts', 'export const c = process.env.DATABASE_URL'),
  ], { maxTokenFanout: 2 })
  assert.equal(fanout.gaps.some((gap) => gap.code === 'token-fanout-cap'), true)
})

test('hard resource ceilings reject oversized options and inventory before discovery work', () => {
  for (const [options, expected] of [
    [{ maxNodes: 50_001 }, /maxNodes must be a safe integer between 1 and 50000/],
    [{ maxEdges: 100_001 }, /maxEdges must be a safe integer between 1 and 100000/],
    [{ maxRounds: 65 }, /maxRounds must be a safe integer between 1 and 64/],
    [
      { maxTokenFanout: 1_025 },
      /maxTokenFanout must be a safe integer between 2 and 1024/,
    ],
  ]) {
    assert.throws(() => discoverDatabaseGraph([], options), expected)
  }

  assert.throws(
    () => discoverDatabaseGraph(new Array(100_001)),
    /inventory must contain at most 100000 entries/,
  )

  const oversizedText = 'x'.repeat((16 * 1024 * 1024) + 1)
  assert.throws(
    () => discoverDatabaseGraph([
      {
        path: 'src/oversized.txt',
        kind: 'text',
        size: 1,
        content: oversizedText,
      },
    ]),
    /inventory entry 0 content exceeds 16777216 bytes/,
  )

  const maximumSizedText = 'x'.repeat(16 * 1024 * 1024)
  assert.throws(
    () => discoverDatabaseGraph(Array.from(
      { length: 33 },
      (_, index) => ({
        path: `src/chunk-${index}.txt`,
        kind: 'text',
        size: maximumSizedText.length,
        content: maximumSizedText,
      }),
    )),
    /inventory text exceeds 536870912 bytes/,
  )
})

test('validation and serialization reject tampering and credential-bearing output', () => {
  const graph = discoverDatabaseGraph([
    text('analytics/app.ts', 'export const app = true'),
    text('src/db.ts', 'export const databaseUrl = process.env.DATABASE_URL'),
  ])
  const reorderedScope = structuredClone(graph)
  reorderedScope.path_scope.reverse()
  assert.equal(
    validateDatabaseDiscovery(reorderedScope).errors.some((error) =>
      error === 'path_scope paths must be in strict canonical order'),
    true,
  )

  const tamperedDigest = structuredClone(graph)
  tamperedDigest.stats.node_count += 1
  assert.equal(validateDatabaseDiscovery(tamperedDigest).valid, false)
  assert.throws(
    () => serializeDatabaseDiscovery(tamperedDigest),
    DatabaseDiscoveryValidationError,
  )

  const leaked = structuredClone(graph)
  leaked.nodes[0].label = 'postgres://admin:password@example.invalid/db'
  leaked.digest = ''
  assert.equal(
    validateDatabaseDiscovery(leaked).errors.some((error) =>
      error.includes('credential-bearing URI')),
    true,
  )

  const smuggled = structuredClone(graph)
  smuggled.raw_connection_string = 'opaque-root-secret'
  smuggled.nodes[0].raw_secret = 'opaque-node-secret'
  const smuggledValidation = validateDatabaseDiscovery(smuggled)
  assert.equal(smuggledValidation.valid, false)
  assert.equal(
    smuggledValidation.errors.some((error) =>
      error === 'schema/ must NOT have additional properties'),
    true,
  )
  assert.equal(
    smuggledValidation.errors.some((error) =>
      error === 'schema/nodes/0 must NOT have additional properties'),
    true,
  )
  assert.throws(
    () => serializeDatabaseDiscovery(smuggled),
    (error) => {
      assert.ok(error instanceof DatabaseDiscoveryValidationError)
      assert.doesNotMatch(error.message, /opaque-(?:root|node)-secret/)
      return true
    },
  )

  const oversizedDeclaredLimit = structuredClone(graph)
  oversizedDeclaredLimit.limits.max_nodes = 50_001
  assert.equal(
    validateDatabaseDiscovery(oversizedDeclaredLimit).errors.some((error) =>
      error === 'schema/limits/max_nodes must be <= 50000'),
    true,
  )
})

test('MongoDB, Redis, DynamoDB, and Firestore follow client to binding to query, policy, and copy evidence', () => {
  const inventory = [
    text('services/mongo/package.json', JSON.stringify({
      dependencies: { mongodb: '6.8.0' },
    })),
    text('services/mongo/src/store.ts', `
      import { MongoClient } from 'mongodb'
      const ignoredExampleSecret = 'family-secret-must-not-escape'
      const mongo = new MongoClient(process.env.MONGODB_URI)
      const orders = mongo.db('app').collection('orders')
      export const list = tenant => orders.find({ tenant }).toArray()
    `),
    text('services/mongo/security.js', `
      db.createRole({ role: 'tenantReader', privileges: [], roles: [] })
      MongoClient changeStream collection.watch()
      mongodump --archive=runtime-path
    `),
    text('services/redis/package.json', JSON.stringify({
      dependencies: { ioredis: '5.4.1' },
    })),
    text('services/redis/src/store.ts', `
      import Redis from 'ioredis'
      const redisClient = new Redis(process.env.REDIS_URL)
      export const load = tenant => redisClient.hget('tenant-cache', tenant)
    `),
    text('services/redis/redis.conf', `
      ACL SETUSER tenant-reader on +hget ~tenant:*
      replicaof redis-primary 6379
      appendonly yes
    `),
    text('services/dynamo/package.json', JSON.stringify({
      dependencies: { '@aws-sdk/client-dynamodb': '3.620.0' },
    })),
    text('services/dynamo/src/store.ts', `
      import { DynamoDBClient, QueryCommand } from '@aws-sdk/client-dynamodb'
      const client = new DynamoDBClient({ region: process.env.DYNAMODB_REGION })
      export const list = tenant => client.send(new QueryCommand({
        TableName: process.env.DYNAMODB_TABLE,
        KeyConditionExpression: 'tenant = :tenant',
      }))
    `),
    text('services/dynamo/iam-and-copy.json', `
      dynamodb:Query
      dynamodb:LeadingKeys
      StreamEnabled
      StreamViewType
      PointInTimeRecoveryEnabled
      ExportTableToPointInTime
    `),
    text('services/firestore/package.json', JSON.stringify({
      dependencies: { 'firebase-admin': '12.3.1' },
    })),
    text('services/firestore/src/store.ts', `
      import { getFirestore } from 'firebase-admin/firestore'
      const firestore = getFirestore(process.env.FIRESTORE_PROJECT)
      export const list = tenant =>
        firestore.collection('orders').where('tenant', '==', tenant).get()
    `),
    text('services/firestore/firestore.rules', `
      service cloud.firestore {
        match /databases/{database}/documents {
          match /orders/{order} {
            allow read: if request.auth.uid == resource.data.tenant;
          }
        }
      }
    `),
    text('services/firestore/backup.sh', 'gcloud firestore export runtime-bucket'),
  ]

  const graph = discoverDatabaseGraph(inventory)
  assert.deepEqual(graph, discoverDatabaseGraph(reverseCopy(inventory)))
  assert.deepEqual(validateDatabaseDiscovery(graph), { valid: true, errors: [] })
  assert.equal(validateSchema(graph), true, JSON.stringify(validateSchema.errors))

  const expected = {
    mongodb: [
      'artifact.query.mongodb',
      'artifact.security.mongodb-role',
      'copy.mongodb-change-stream',
      'copy.mongodb-backup',
    ],
    redis: [
      'artifact.query.redis',
      'artifact.security.redis-acl',
      'copy.redis-replica',
      'copy.redis-persistence',
    ],
    dynamodb: [
      'artifact.query.dynamodb',
      'artifact.security.dynamodb-iam',
      'artifact.security.dynamodb-leading-keys',
      'copy.dynamodb-stream',
      'copy.dynamodb-backup',
      'copy.dynamodb-export',
    ],
    firestore: [
      'artifact.query.firestore',
      'artifact.security.firestore-rules',
      'copy.firestore-export',
    ],
  }

  assert.equal(graph.store_candidates.length, 4)
  for (const [engine, signatures] of Object.entries(expected)) {
    const store = graph.store_candidates.find((candidate) =>
      candidate.engine_candidates.length === 1
      && candidate.engine_candidates[0] === engine)
    assert.ok(store, `missing ${engine} store`)
    const signatureIds = new Set(store.node_ids.flatMap((nodeId) =>
      graph.nodes
        .find((node) => node.node_id === nodeId)
        ?.evidence.map((item) => item.signature_id) ?? []))
    for (const signatureId of signatures) {
      assert.equal(
        signatureIds.has(signatureId),
        true,
        `${engine} is missing ${signatureId}; found ${[...signatureIds].join(', ')}; graph has ${
          graph.nodes
            .filter((node) => node.evidence.some((item) => item.signature_id === signatureId))
            .map((node) => `${node.component_root}:${node.context_only}`)
            .join(', ')
        }`,
      )
    }
    const serviceDirectory = {
      mongodb: 'mongo',
      dynamodb: 'dynamo',
    }[engine] ?? engine
    assert.equal(
      store.scope_paths.every((repositoryPath) =>
        repositoryPath.startsWith(`services/${serviceDirectory}/`)),
      true,
      `${engine} crossed a sibling manifest root`,
    )
  }
  assert.equal(
    graph.edges.filter((edge) => edge.relation === 'USES_BINDING').length >= 4,
    true,
  )
  assert.equal(
    graph.edges.filter((edge) => edge.relation === 'APPLIES_TO_STORE').length >= 12,
    true,
  )
  assert.doesNotMatch(
    serializeDatabaseDiscovery(graph),
    /family-secret-must-not-escape/,
  )
})

test('generic AWS SDK and Cosmos declarations do not invent DynamoDB or MongoDB engines', () => {
  const graph = discoverDatabaseGraph([
    text('services/files/package.json', JSON.stringify({
      dependencies: { 'aws-sdk': '2.1692.0' },
    })),
    text('services/files/src/storage.ts', `
      import AWS from 'aws-sdk'
      export const files = new AWS.S3({ region: process.env.AWS_REGION })
    `),
    text('services/cosmos/infra/main.bicep', `
      resource account 'Microsoft.DocumentDB/databaseAccounts@2024-05-15' = {
        name: 'generic-account'
        kind: 'GlobalDocumentDB'
      }
    `),
  ])

  assert.equal(
    graph.store_candidates.some((candidate) =>
      candidate.engine_candidates.includes('dynamodb')
      || candidate.engine_candidates.includes('mongodb')),
    false,
  )
  assert.equal(
    graph.nodes
      .filter((node) =>
        node.evidence.some((item) =>
          item.signature_id === 'client.node.aws-sdk-generic'
          || item.signature_id === 'resource.azure.cosmos-db'))
      .every((node) => node.engine_candidates.length === 0),
    true,
  )
})

test('search, graph, wide-column, warehouse, and vector clients retain engine-specific evidence', () => {
  const services = [
    {
      root: 'elasticsearch',
      dependency: '@elastic/elasticsearch',
      source: `
        import { Client } from '@elastic/elasticsearch'
        const elasticsearchClient = new Client({
          node: process.env.ELASTICSEARCH_URL,
          auth: { apiKey: process.env.ELASTICSEARCH_API_KEY },
        })
        export const search = body => elasticsearchClient.search({ body })
      `,
      control: 'xpack.security _security/role _snapshot/runtime',
      signatures: [
        'artifact.query.elasticsearch',
        'artifact.security.elasticsearch-role',
        'copy.elasticsearch-snapshot',
      ],
    },
    {
      root: 'opensearch',
      dependency: '@opensearch-project/opensearch',
      source: `
        import { Client } from '@opensearch-project/opensearch'
        const openSearch = new Client({
          node: process.env.OPENSEARCH_ENDPOINT,
          auth: { apiKey: process.env.OPENSEARCH_API_KEY },
        })
        export const search = body => openSearch.search({ body })
      `,
      control: 'plugins.security _plugins/_security _snapshot/runtime',
      signatures: [
        'artifact.query.opensearch',
        'artifact.security.opensearch-role',
        'copy.opensearch-snapshot',
      ],
    },
    {
      root: 'neo4j',
      dependency: 'neo4j-driver',
      source: `
        import neo4j from 'neo4j-driver'
        const driver = neo4j.driver(
          process.env.NEO4J_URI,
          neo4j.auth.basic(process.env.NEO4J_USER, process.env.NEO4J_PASSWORD),
        )
        export const graph = () => driver.session().run('MATCH (n) RETURN n')
      `,
      control: 'GRANT MATCH ON GRAPH app TO tenant_reader; neo4j-admin database backup app',
      signatures: [
        'artifact.query.neo4j',
        'artifact.security.neo4j-privilege',
        'copy.neo4j-backup',
      ],
    },
    {
      root: 'cassandra',
      dependency: 'cassandra-driver',
      source: `
        import cassandra from 'cassandra-driver'
        const client = new cassandra.Client({
          contactPoints: process.env.CASSANDRA_HOSTS,
          keyspace: process.env.CASSANDRA_KEYSPACE,
        })
        export const rows = () => client.execute('SELECT * FROM orders')
      `,
      control: `
        Cassandra GRANT SELECT ON KEYSPACE app TO tenant_reader;
        NetworkTopologyStrategy replication_factor nodetool snapshot
      `,
      signatures: [
        'artifact.query.cassandra',
        'artifact.security.cassandra-role',
        'copy.cassandra-replication',
        'copy.cassandra-snapshot',
      ],
    },
    {
      root: 'bigquery',
      dependency: '@google-cloud/bigquery',
      source: `
        import { BigQuery } from '@google-cloud/bigquery'
        const bigquery = new BigQuery({ projectId: process.env.BIGQUERY_PROJECT })
        export const rows = () => bigquery.query({ query: 'SELECT 1' })
      `,
      control: `
        roles/bigquery.dataViewer bigquery.tables.getData
        CREATE ROW ACCESS POLICY tenant_filter ON app.orders
          FILTER USING (tenant = SESSION_USER());
        EXPORT DATA OPTIONS(uri='runtime-path') AS SELECT 1;
      `,
      signatures: [
        'artifact.query.bigquery',
        'artifact.security.bigquery-iam',
        'artifact.security.bigquery-row-access-policy',
        'copy.bigquery-export',
      ],
    },
    {
      root: 'snowflake',
      dependency: 'snowflake-sdk',
      source: `
        import snowflake from 'snowflake-sdk'
        const connection = snowflake.createConnection({
          account: process.env.SNOWFLAKE_ACCOUNT,
          database: process.env.SNOWFLAKE_DATABASE,
        })
        export const rows = () => connection.execute({ sqlText: 'SELECT 1' })
      `,
      control: `
        snowflake GRANT USAGE ON WAREHOUSE app TO ROLE tenant_reader;
        CREATE MASKING POLICY tenant_mask AS (value string) RETURNS string -> value;
        COPY INTO @runtime_stage FROM app.orders;
      `,
      signatures: [
        'artifact.query.snowflake',
        'artifact.security.snowflake-role',
        'artifact.security.snowflake-policy',
        'copy.snowflake-export-or-clone',
      ],
    },
    {
      root: 'pinecone',
      dependency: '@pinecone-database/pinecone',
      source: `
        import { Pinecone } from '@pinecone-database/pinecone'
        const pinecone = new Pinecone({ apiKey: process.env.PINECONE_API_KEY })
        const index = pinecone.index(process.env.PINECONE_INDEX)
        export const nearest = vector => index.query({ vector })
        Pinecone createSnapshot
      `,
      signatures: ['artifact.query.pinecone', 'copy.pinecone-snapshot'],
    },
    {
      root: 'qdrant',
      dependency: '@qdrant/js-client-rest',
      source: `
        import { QdrantClient } from '@qdrant/js-client-rest'
        const qdrant = new QdrantClient({
          url: process.env.QDRANT_URL,
          apiKey: process.env.QDRANT_API_KEY,
        })
        export const nearest = vector => qdrant.search('items', { vector })
        QdrantClient snapshot_collection
      `,
      signatures: ['artifact.query.qdrant', 'copy.qdrant-snapshot'],
    },
    {
      root: 'weaviate',
      dependency: 'weaviate-ts-client',
      source: `
        import weaviate from 'weaviate-ts-client'
        const client = weaviate.client({
          scheme: 'https',
          host: process.env.WEAVIATE_URL,
          apiKey: process.env.WEAVIATE_API_KEY,
        })
        export const nearest = vector =>
          client.graphql.get().nearVector({ vector }).withClassName(
            process.env.WEAVIATE_CLASS,
          )
        weaviate createSnapshot
      `,
      signatures: ['artifact.query.weaviate', 'copy.weaviate-backup'],
    },
  ]
  const inventory = services.flatMap((service) => [
    text(`services/${service.root}/package.json`, JSON.stringify({
      dependencies: { [service.dependency]: '1.0.0' },
    })),
    text(`services/${service.root}/src/store.ts`, service.source),
    ...(service.control
      ? [text(`services/${service.root}/security-and-copy.conf`, service.control)]
      : []),
  ])

  const graph = discoverDatabaseGraph(inventory)
  assert.deepEqual(graph, discoverDatabaseGraph(reverseCopy(inventory)))
  assert.deepEqual(validateDatabaseDiscovery(graph), { valid: true, errors: [] })
  assert.equal(
    graph.store_candidates.length,
    services.length,
    `found engines ${graph.store_candidates
      .map((candidate) => candidate.engine_candidates.join('+'))
      .join(', ')}; unresolved ${graph.unresolved
      .filter((item) => item.path?.startsWith('services/neo4j/'))
      .map((item) => `${item.type}:${item.reasons.join('+')}`)
      .join(', ')}`,
  )

  for (const service of services) {
    const store = graph.store_candidates.find((candidate) =>
      candidate.engine_candidates.length === 1
      && candidate.engine_candidates[0] === service.root)
    assert.ok(store, `missing ${service.root} candidate`)
    assert.equal(
      store.scope_paths.every((repositoryPath) =>
        repositoryPath.startsWith(`services/${service.root}/`)),
      true,
      `${service.root} crossed a sibling manifest root`,
    )
    const signatureIds = new Set(store.node_ids.flatMap((nodeId) =>
      graph.nodes
        .find((node) => node.node_id === nodeId)
        ?.evidence.map((item) => item.signature_id) ?? []))
    for (const signatureId of service.signatures) {
      assert.equal(
        signatureIds.has(signatureId),
        true,
        `${service.root} is missing ${signatureId}; found ${[...signatureIds].join(', ')}`,
      )
    }
  }
})
