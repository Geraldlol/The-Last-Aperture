import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  buildActivationPlan,
  loadLenses,
} from '../scripts/lib/activation.mjs'
import { discoverDatabaseGraph } from '../scripts/lib/database-discovery.mjs'

const lenses = await loadLenses('skills/red-team-audit/lenses')

function databaseActivation(path, content) {
  const inventory = {
    entries: [{
      path,
      kind: 'text',
      content,
      examined: true,
    }],
    errors: [],
    excluded: [],
  }
  return buildActivationPlan(lenses, inventory).jobs.find(
    ({ lens }) => lens === 'database-and-data-stores',
  )
}

const ECOSYSTEM_PROBES = [
  {
    label: 'Python psycopg2 requirement',
    path: 'requirements.txt',
    content: 'psycopg2-binary==2.9.10',
    signal: 'psycopg',
  },
  {
    label: 'Python PyMongo requirement',
    path: 'pyproject.toml',
    content: 'pymongo = "^4.10.1"',
    signal: 'pymongo',
  },
  {
    label: 'Python Redis requirement',
    path: 'requirements.txt',
    content: 'redis==5.2.1',
    signal: 'redis==',
  },
  {
    label: 'Python Snowflake connector',
    path: 'requirements.txt',
    content: 'snowflake-connector-python==3.12.4',
    signal: 'snowflake-connector-python',
  },
  {
    label: 'Go pgx module',
    path: 'go.mod',
    content: 'require github.com/jackc/pgx/v5 v5.7.2',
    signal: 'github.com/jackc/pgx',
  },
  {
    label: 'Go database/sql import',
    path: 'internal/store/database.go',
    content: 'import "database/sql"\nimport _ "github.com/lib/pq"',
    signal: 'database/sql',
  },
  {
    label: 'Go MySQL driver module',
    path: 'go.mod',
    content: 'require github.com/go-sql-driver/mysql v1.9.0',
    signal: 'github.com/go-sql-driver/mysql',
  },
  {
    label: 'Java PostgreSQL JDBC dependency',
    path: 'pom.xml',
    content: '<groupId>org.postgresql</groupId><artifactId>postgresql</artifactId>',
    signal: 'org.postgresql',
  },
  {
    label: 'Java MySQL JDBC dependency',
    path: 'build.gradle.kts',
    content: 'runtimeOnly("com.mysql:mysql-connector-j:8.4.0")',
    signal: 'mysql-connector-j',
  },
  {
    label: 'Java SQL Server JDBC URL',
    path: 'application.properties',
    content: 'spring.datasource.url=jdbc:sqlserver://db.internal:1433;databaseName=orders',
    signal: 'jdbc:sqlserver:',
  },
]

test('common Python, Go, and Java database dependencies activate the database lens', () => {
  for (const probe of ECOSYSTEM_PROBES) {
    const job = databaseActivation(probe.path, probe.content)
    assert.equal(job.activated, true, `${probe.label} did not activate the database lens`)
    assert.ok(
      job.matches.some(({ signal_activators: signals }) => signals.includes(probe.signal)),
      `${probe.label} did not preserve ${JSON.stringify(probe.signal)} as activation evidence`,
    )
  }
})

test('controller discovery closes exact database imports before lens sharding', () => {
  const entries = [
    {
      path: 'package.json',
      kind: 'text',
      content: '{"dependencies":{"pg":"8.13.1"}}',
      examined: true,
    },
    {
      path: 'src/db.ts',
      kind: 'text',
      content: [
        "import { Pool } from 'pg'",
        "import { endpoint } from './runtime-config'",
        'export const pool = new Pool({ connectionString: endpoint })',
      ].join('\n'),
      examined: true,
    },
    {
      path: 'src/runtime-config.ts',
      kind: 'text',
      content: 'export const endpoint = process.env.PRIMARY_STORE_ENDPOINT',
      examined: true,
    },
  ].map((entry) => ({
    ...entry,
    size: Buffer.byteLength(entry.content),
  }))
  const inventory = { entries, errors: [], excluded: [] }
  const databaseDiscovery = discoverDatabaseGraph(inventory)
  const withoutDiscovery = buildActivationPlan(lenses, inventory)
  const withDiscovery = buildActivationPlan(lenses, inventory, {
    databaseDiscovery,
    shardPolicy: { maxFiles: 2, maxBytes: 1024 * 1024 },
  })
  const scoped = withDiscovery.jobs
    .filter(({ lens, activated }) =>
      lens === 'database-and-data-stores' && activated)
    .flatMap(({ scoped_files: scopedFiles }) => scopedFiles)

  assert.equal(
    withoutDiscovery.jobs
      .filter(({ lens }) => lens === 'database-and-data-stores')
      .flatMap(({ scoped_files: scopedFiles }) => scopedFiles)
      .includes('src/runtime-config.ts'),
    false,
  )
  assert.ok(scoped.includes('src/runtime-config.ts'))
  assert.equal(new Set(scoped).size, scoped.length)
  assert.ok(withDiscovery.jobs
    .filter(({ lens, activated }) =>
      lens === 'database-and-data-stores' && activated)
    .every(({ shard }) => shard.file_count <= 2))
})
