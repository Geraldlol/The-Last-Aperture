import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const ADAPTER_DIRECTORY = new URL(
  '../skills/red-team-audit/lenses/_database-adapters/',
  import.meta.url,
)
const ADAPTER_PATH = fileURLToPath(ADAPTER_DIRECTORY)

const ADAPTERS = new Map([
  ['postgresql-and-supabase.md', ['postgresql']],
  ['sqlserver-and-azure-sql.md', ['sqlserver']],
  ['mysql.md', ['mysql']],
  ['mariadb.md', ['mariadb']],
  ['oracle.md', ['oracle']],
  ['sqlite.md', ['sqlite']],
  ['mongodb.md', ['mongodb']],
  ['redis-and-valkey.md', ['redis', 'valkey']],
  ['firestore.md', ['firestore']],
  ['dynamodb.md', ['dynamodb']],
  ['elasticsearch-and-opensearch.md', ['elasticsearch', 'opensearch']],
  ['cassandra-and-scylla.md', ['cassandra', 'scylla']],
  ['neo4j.md', ['neo4j']],
  ['vector-stores.md', ['pinecone', 'qdrant', 'weaviate', 'milvus']],
  ['warehouses.md', ['snowflake', 'bigquery', 'redshift', 'databricks']],
])

const CAPABILITIES = [
  'principal-authentication',
  'role-and-object-grants',
  'record-read-authorization',
  'record-write-authorization',
  'column-or-property-authorization',
  'tenant-session-context',
  'stored-code-execution-context',
  'schema-integrity',
  'transactional-integrity',
  'resource-governance',
  'replication-cdc-authorization',
  'history-authorization',
  'backup-policy-portability',
  'security-audit',
  'policy-catalog-introspection',
]

const CAPABILITY_VALUES = [
  'NATIVE',
  'COMPOSABLE',
  'EXTERNAL_ONLY',
  'UNSUPPORTED',
  'UNKNOWN',
]

const readCorpus = () => Object.fromEntries([
  ['contract.md', readFileSync(new URL('contract.md', ADAPTER_DIRECTORY), 'utf8')],
  ...[...ADAPTERS].map(([file]) => [
    file,
    readFileSync(new URL(file, ADAPTER_DIRECTORY), 'utf8'),
  ]),
])

const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

function adapterIds(text) {
  const line = /^Adapter IDs?:\s*(.+)$/m.exec(text)?.[1] ?? ''
  return [...line.matchAll(/`([^`]+)`/g)].map((match) => match[1])
}

function routes(contract) {
  return new Map(
    [...contract.matchAll(/^\|\s*`([^`]+)`\s*\|\s*`([^`]+\.md)`\s*\|$/gm)]
      .map((match) => [match[1], match[2]]),
  )
}

function capabilityRows(text) {
  const heading = '## Capability declaration'
  const start = text.indexOf(heading)
  if (start < 0) return new Map()
  const remainder = text.slice(start + heading.length)
  const nextHeading = remainder.search(/\r?\n## /)
  const section = nextHeading < 0 ? remainder : remainder.slice(0, nextHeading)
  return new Map(
    section
      .split(/\r?\n/)
      .map((line) => /^\|\s*`([^`]+)`\s*\|(.+)\|\s*$/.exec(line))
      .filter(Boolean)
      .map((match) => [match[1], match[2]]),
  )
}

export function validateAdapterCorpus(corpus) {
  const errors = []
  const contract = corpus['contract.md'] ?? ''
  const routing = routes(contract)

  const actualFiles = Object.keys(corpus).sort()
  const expectedFiles = ['contract.md', ...ADAPTERS.keys()].sort()
  if (JSON.stringify(actualFiles) !== JSON.stringify(expectedFiles)) {
    errors.push('adapter file set differs from the contract-checked set')
  }

  for (const capability of CAPABILITIES) {
    const definition = new RegExp(`^\\| \`${escapeRegex(capability)}\` \\|`, 'm')
    if (!definition.test(contract)) {
      errors.push(`contract: missing capability ${capability}`)
    }
  }
  for (const value of CAPABILITY_VALUES) {
    const definition = new RegExp(`^\\| \`${value}\` \\|`, 'm')
    if (!definition.test(contract)) {
      errors.push(`contract: missing capability value ${value}`)
    }
  }
  if (!/An unlisted engine selects `inventory-only`/.test(contract)) {
    errors.push('contract: unlisted engines must select inventory-only')
  }
  if (!/`INVENTORY_ONLY` and `NOT_ASSESSED` are never rendered as pass, clean,\s*secure,/m.test(contract)) {
    errors.push('contract: incomplete coverage must never render as clean')
  }

  const seenIds = new Map()
  for (const [file, expectedIds] of ADAPTERS) {
    const text = corpus[file] ?? ''
    if (!text) {
      errors.push(`${file}: missing`)
      continue
    }

    const ids = adapterIds(text)
    if (JSON.stringify(ids) !== JSON.stringify(expectedIds)) {
      errors.push(`${file}: adapter IDs are ${ids.join(', ') || 'missing'}`)
    }
    if (!/^Deployment variants:/m.test(text)) {
      errors.push(`${file}: missing deployment variants`)
    }
    if (!/^Verified: `\d{4}-\d{2}-\d{2}`$/m.test(text)) {
      errors.push(`${file}: missing dated verification`)
    }
    if (!/\bNOT ASSESSED\b/.test(text)) {
      errors.push(`${file}: missing NOT ASSESSED behavior`)
    }
    if (!/^## Static (?:discovery )?sweeps?$/m.test(text)) {
      errors.push(`${file}: missing static discovery sweeps`)
    }
    if (!/^## Proof(?: and conformance)?(?: matrix| recipe)?$/m.test(text)) {
      errors.push(`${file}: missing proof/conformance section`)
    }
    if (!/^## Known false positives$/m.test(text)) {
      errors.push(`${file}: missing false-positive controls`)
    }
    if (!/^## Fixture concepts?$/m.test(text)) {
      errors.push(`${file}: missing fixture concept`)
    }
    if (!/^## Official (?:semantic )?sources$/m.test(text)) {
      errors.push(`${file}: missing official sources`)
    }
    if ((text.match(/https:\/\//g) ?? []).length < 3) {
      errors.push(`${file}: fewer than three primary-source links`)
    }

    const rows = capabilityRows(text)
    for (const capability of CAPABILITIES) {
      const row = rows.get(capability)
      if (!row) {
        errors.push(`${file}: missing capability ${capability}`)
        continue
      }
      if (!CAPABILITY_VALUES.some((value) => row.includes(`\`${value}\``))) {
        errors.push(`${file}: capability ${capability} has no contract value`)
      }
    }
    for (const capability of rows.keys()) {
      if (!CAPABILITIES.includes(capability)) {
        errors.push(`${file}: unknown canonical capability ${capability}`)
      }
    }

    for (const id of ids) {
      if (seenIds.has(id)) {
        errors.push(`${file}: adapter ID ${id} also declared by ${seenIds.get(id)}`)
      }
      seenIds.set(id, file)
      if (routing.get(id) !== file) {
        errors.push(`${file}: adapter ID ${id} is not routed to this file`)
      }
      const rulePattern = new RegExp(
        `\\bdb\\.[a-z0-9-]+\\.${escapeRegex(id)}\\.[a-z0-9][a-z0-9.-]*\\b`,
      )
      if (!rulePattern.test(text)) {
        errors.push(`${file}: adapter ID ${id} has no allowlisted semantic rule anchor`)
      }
    }
  }

  for (const [id, file] of routing) {
    if (seenIds.get(id) !== file) {
      errors.push(`contract: route ${id} -> ${file} has no matching adapter metadata`)
    }
  }

  return errors
}

test('database adapters satisfy the shared semantic contract', () => {
  const diskFiles = readdirSync(ADAPTER_PATH)
    .filter((file) => file.endsWith('.md'))
    .sort()
  assert.deepEqual(diskFiles, ['contract.md', ...ADAPTERS.keys()].sort())

  const errors = validateAdapterCorpus(readCorpus())
  assert.deepEqual(errors, [])
})

test('adapter contract checks fire on semantic and routing drift', () => {
  const corpus = readCorpus()
  const postgres = corpus['postgresql-and-supabase.md']
  const mutations = [
    [
      'capability',
      {
        ...corpus,
        'postgresql-and-supabase.md': postgres.replace(
          /^\| `record-write-authorization` \|.*\r?\n/m,
          '',
        ),
      },
    ],
    [
      'adapter ID',
      {
        ...corpus,
        'vector-stores.md': corpus['vector-stores.md'].replace(
          '`pinecone`',
          '`vector-compatible`',
        ),
      },
    ],
    [
      'route',
      {
        ...corpus,
        'contract.md': corpus['contract.md'].replace(
          /^\| `pinecone` \| `vector-stores\.md` \|\r?\n/m,
          '',
        ),
      },
    ],
    [
      'NOT ASSESSED',
      {
        ...corpus,
        'postgresql-and-supabase.md': postgres.replaceAll('NOT ASSESSED', 'UNCHECKED'),
      },
    ],
  ]

  for (const [name, mutation] of mutations) {
    assert.ok(
      validateAdapterCorpus(mutation).length > 0,
      `removing ${name} produced no violation`,
    )
  }
})

test('an empty adapter corpus cannot pass vacuously', () => {
  assert.ok(validateAdapterCorpus({}).length > ADAPTERS.size)
})
