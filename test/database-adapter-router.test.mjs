import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

import {
  assertValidDatabaseAdapterManifest,
  databaseAdapterManifest,
  getDatabaseAdapterDefinition,
  knownDatabaseAdapterIds,
  knownDatabaseDeploymentVariants,
  routeDatabaseAdapter,
  validateDatabaseAdapterManifest,
  validateDatabaseSemanticMetadata,
} from '../scripts/lib/database-adapters.mjs'

const ADAPTER_DIRECTORY = new URL(
  '../skills/red-team-audit/lenses/_database-adapters/',
  import.meta.url,
)

function validProfile(overrides = {}) {
  return {
    store_id: 'orders-primary',
    family: 'relational',
    engine: 'postgresql',
    engine_version: '16.3',
    deployment_variant: 'postgresql-self-managed',
    adapter_id: 'postgresql',
    detection_evidence: ['compose.yml:19 postgres:16.3'],
    confidence: 'high',
    ...overrides,
  }
}

function mutableManifest() {
  return structuredClone(databaseAdapterManifest)
}

function documentedHeaderValues(file, heading) {
  const text = readFileSync(new URL(file, ADAPTER_DIRECTORY), 'utf8')
  const header = text.slice(0, text.indexOf('\n\nVerified:'))
  const start = header.indexOf(`${heading}:`)
  if (start < 0) return []
  const remainder = header.slice(start)
  const end = remainder.search(/\r?\n\r?\n/)
  const field = end < 0 ? remainder : remainder.slice(0, end)
  return [...field.matchAll(/`([^`]+)`/g)].map((match) => match[1])
}

test('manifest is valid and exposes the full documented engine set', () => {
  assert.deepEqual(validateDatabaseAdapterManifest(databaseAdapterManifest), {
    valid: true,
    errors: [],
  })
  assert.equal(knownDatabaseAdapterIds.length, 24)
  assert.equal(new Set(knownDatabaseAdapterIds).size, knownDatabaseAdapterIds.length)
  assert.ok(knownDatabaseDeploymentVariants.length > knownDatabaseAdapterIds.length)
  assert.equal(getDatabaseAdapterDefinition('postgresql').adapter_file,
    'postgresql-and-supabase.md')
  assert.equal(getDatabaseAdapterDefinition('inventory-only'), null)
})

test('manifest adapter IDs and canonical variants stay in lockstep with adapter docs', () => {
  const idsByFile = new Map()
  const variantsByFile = new Map()

  for (const adapter of databaseAdapterManifest.adapters) {
    if (!idsByFile.has(adapter.adapter_file)) {
      idsByFile.set(adapter.adapter_file,
        documentedHeaderValues(adapter.adapter_file, 'Adapter ID'))
      variantsByFile.set(adapter.adapter_file,
        documentedHeaderValues(adapter.adapter_file, 'Deployment variants'))
    }
    assert.ok(
      idsByFile.get(adapter.adapter_file).includes(adapter.adapter_id),
      `${adapter.adapter_id} is missing from ${adapter.adapter_file}`,
    )
    for (const { id } of adapter.deployment_variants) {
      assert.ok(
        variantsByFile.get(adapter.adapter_file).includes(id),
        `${id} is missing from ${adapter.adapter_file}`,
      )
    }
    const text = readFileSync(new URL(adapter.adapter_file, ADAPTER_DIRECTORY), 'utf8')
    const documentedHosts = new Set(
      [...text.matchAll(/https:\/\/[^\s<>()`]+/g)].map((match) =>
        new URL(match[0].replace(/[.,;:]+$/, '')).hostname.toLowerCase()),
    )
    for (const host of adapter.semantic_source_hosts) {
      assert.ok(
        documentedHosts.has(host),
        `${adapter.adapter_id} trusts uncited semantic source host ${host}`,
      )
    }
  }
})

test('high-confidence exact selection routes but never grants proof or clearance', () => {
  const result = routeDatabaseAdapter(validProfile())

  assert.deepEqual(result, {
    adapter_id: 'postgresql',
    adapter_file: 'postgresql-and-supabase.md',
    selection_status: 'SELECTED',
    coverage_state: 'ROUTED',
    verification_status: null,
    effective_severity_cap: null,
    can_clear: false,
    can_confirm: false,
    engine: 'postgresql',
    engine_version: '16.3',
    deployment_variant: 'postgresql-self-managed',
    reasons: [],
  })
  assert.ok(Object.isFrozen(result))
})

test('engine and engine-scoped deployment aliases normalize deterministically', () => {
  const result = routeDatabaseAdapter(validProfile({
    engine: 'postgres',
    deployment_variant: 'self-managed',
  }))

  assert.equal(result.selection_status, 'SELECTED')
  assert.equal(result.engine, 'postgresql')
  assert.equal(result.deployment_variant, 'postgresql-self-managed')
  assert.deepEqual(result.reasons.map(({ code }) => code), [
    'engine-alias-normalized',
    'deployment-variant-alias-normalized',
  ])
})

test('unknown engines force inventory-only, NOT_ASSESSED, and UNPROVEN', () => {
  const result = routeDatabaseAdapter(validProfile({
    engine: 'cockroachdb',
    deployment_variant: 'cockroach-cloud',
    adapter_id: undefined,
  }))

  assert.equal(result.adapter_id, 'inventory-only')
  assert.equal(result.selection_status, 'INVENTORY_ONLY')
  assert.equal(result.coverage_state, 'NOT_ASSESSED')
  assert.equal(result.verification_status, 'UNPROVEN')
  assert.equal(result.effective_severity_cap, 'Medium')
  assert.equal(result.can_clear, false)
  assert.equal(result.can_confirm, false)
  assert.ok(result.reasons.some(({ code }) => code === 'unknown-engine'))
})

for (const confidence of ['medium', 'low']) {
  test(`${confidence} confidence forces conservative inventory-only routing`, () => {
    const result = routeDatabaseAdapter(validProfile({ confidence }))
    assert.equal(result.adapter_id, 'inventory-only')
    assert.equal(result.verification_status, 'UNPROVEN')
    assert.ok(result.reasons.some(
      ({ code }) => code === 'insufficient-detection-confidence'))
  })
}

test('unknown versions and deployment variants force conservative routing', () => {
  for (const profile of [
    validProfile({ engine_version: 'unknown' }),
    validProfile({ deployment_variant: 'unknown' }),
    validProfile({ deployment_variant: 'postgresql-compatible-mystery' }),
  ]) {
    const result = routeDatabaseAdapter(profile)
    assert.equal(result.adapter_id, 'inventory-only')
    assert.equal(result.verification_status, 'UNPROVEN')
  }
})

test('moving labels and unknown-ish placeholders cannot establish routing semantics', () => {
  for (const engineVersion of [
    'latest',
    'current',
    'unspecified',
    'unknown-ish',
    'pending-release',
    'TBD',
    'managed',
    'banana',
  ]) {
    const result = routeDatabaseAdapter(validProfile({ engine_version: engineVersion }))
    assert.equal(result.adapter_id, 'inventory-only', engineVersion)
    assert.ok(result.reasons.some(
      ({ code }) => code === 'unresolved-engine-version'), engineVersion)
  }

  for (const deploymentVariant of [
    'latest',
    'unspecified',
    'unknown-ish',
    'managed',
  ]) {
    const result = routeDatabaseAdapter(validProfile({ deployment_variant: deploymentVariant }))
    assert.equal(result.adapter_id, 'inventory-only', deploymentVariant)
    assert.ok(result.reasons.some(
      ({ code }) => code === 'unresolved-deployment-variant'), deploymentVariant)
  }

  const canonicalManaged = routeDatabaseAdapter(validProfile({
    deployment_variant: 'postgresql-managed',
  }))
  assert.equal(canonicalManaged.selection_status, 'SELECTED')
})

test('missing evidence, adapter conflicts, and profile-shape drift fail closed', () => {
  const cases = [
    validProfile({ detection_evidence: [] }),
    validProfile({ adapter_id: 'mysql' }),
    { ...validProfile(), deployment: 'postgresql-self-managed' },
  ]
  const expectedCodes = [
    'invalid-detection-evidence',
    'adapter-engine-conflict',
    'unsupported-profile-field',
  ]

  cases.forEach((profile, index) => {
    const result = routeDatabaseAdapter(profile)
    assert.equal(result.adapter_id, 'inventory-only')
    assert.ok(result.reasons.some(({ code }) => code === expectedCodes[index]))
  })
})

test('version-sensitive semantic metadata requires matching rule and dated HTTPS source', () => {
  const valid = validateDatabaseSemanticMetadata({
    adapter_id: 'postgresql',
    semantic_sensitivity: 'version-sensitive',
    adapter_rule_id: 'db.authorization.postgresql.rls-bypass',
    semantic_source: {
      url: 'https://www.postgresql.org/docs/16/ddl-rowsecurity.html',
      verified_on: '2026-07-28',
    },
  }, { asOf: '2026-07-28' })
  assert.deepEqual(valid, { valid: true, errors: [] })

  const missing = validateDatabaseSemanticMetadata({
    adapter_id: 'postgresql',
    semantic_sensitivity: 'version-sensitive',
  }, { asOf: '2026-07-28' })
  assert.equal(missing.valid, false)
  assert.deepEqual(missing.errors.map(({ code }) => code), [
    'missing-adapter-rule-id',
    'missing-semantic-source',
  ])
})

test('semantic metadata rejects adapter mismatch, insecure URLs, and impossible dates', () => {
  const result = validateDatabaseSemanticMetadata({
    adapter_id: 'postgresql',
    semantic_sensitivity: 'deployment-sensitive',
    adapter_rule_id: 'db.authorization.mysql.row-filter',
    semantic_source: {
      url: 'http://example.test/docs',
      verified_on: '2026-02-30',
    },
  }, { asOf: '2026-07-28' })

  assert.equal(result.valid, false)
  assert.deepEqual(result.errors.map(({ code }) => code), [
    'adapter-rule-mismatch',
    'invalid-semantic-source-url',
    'invalid-semantic-source-date',
  ])

  const untrustedHost = validateDatabaseSemanticMetadata({
    adapter_id: 'postgresql',
    semantic_sensitivity: 'stable',
    adapter_rule_id: 'db.authorization.postgresql.rls-bypass',
    semantic_source: {
      url: 'https://attacker.invalid/copied-docs',
      verified_on: '2026-07-28',
    },
  }, { asOf: '2026-07-28' })
  assert.equal(untrustedHost.valid, false)
  assert.ok(untrustedHost.errors.some(
    ({ code }) => code === 'untrusted-semantic-source-host',
  ))
})

test('semantic source trust is scoped to the selected engine', () => {
  const metadata = {
    adapter_id: 'postgresql',
    semantic_sensitivity: 'version-sensitive',
    adapter_rule_id: 'db.authorization.postgresql.rls-bypass',
    semantic_source: {
      url: 'https://www.postgresql.org/docs/16/ddl-rowsecurity.html',
      verified_on: '2026-07-28',
    },
  }
  assert.deepEqual(
    validateDatabaseSemanticMetadata(metadata, { asOf: '2026-07-28' }),
    { valid: true, errors: [] },
  )

  const crossEngine = validateDatabaseSemanticMetadata({
    ...metadata,
    semantic_source: {
      ...metadata.semantic_source,
      url: 'https://dev.mysql.com/doc/refman/8.4/en/grant.html',
    },
  }, { asOf: '2026-07-28' })
  assert.equal(crossEngine.valid, false)
  assert.ok(crossEngine.errors.some(
    ({ code }) => code === 'untrusted-semantic-source-host',
  ))
})

test('every routed adapter uses its allowlisted rule vocabulary', () => {
  const selectedIds = []
  for (const adapter of databaseAdapterManifest.adapters) {
    const routedAdapter = routeDatabaseAdapter(validProfile({
      store_id: `${adapter.adapter_id}-primary`,
      engine: adapter.engine,
      engine_version: '1.0',
      deployment_variant: adapter.deployment_variants[0].id,
      adapter_id: adapter.adapter_id,
      detection_evidence: [
        `config/${adapter.adapter_id}.yml:1 declares ${adapter.engine} 1.0`,
      ],
    }))
    assert.equal(
      routedAdapter.selection_status,
      'SELECTED',
      `${adapter.adapter_id}: ${JSON.stringify(routedAdapter.reasons)}`,
    )
    assert.equal(routedAdapter.adapter_id, adapter.adapter_id)
    selectedIds.push(routedAdapter.adapter_id)
  }
  assert.deepEqual(selectedIds, knownDatabaseAdapterIds)

  const routed = routeDatabaseAdapter(validProfile({
    engine: 'firestore',
    engine_version: '2026-07-28',
    deployment_variant: 'native',
    adapter_id: 'firestore',
  }))
  assert.equal(routed.selection_status, 'SELECTED')

  const invented = validateDatabaseSemanticMetadata({
    adapter_id: 'firestore',
    semantic_sensitivity: 'version-sensitive',
    adapter_rule_id: 'db.authorization.firestore.i-made-this-up',
    semantic_source: {
      url: 'https://firebase.google.com/docs/firestore/security/get-started',
      verified_on: '2026-07-28',
    },
  }, { asOf: '2026-07-28' })
  assert.equal(invented.valid, false)
  assert.ok(invented.errors.some(
    ({ code }) => code === 'undeclared-adapter-rule-id',
  ))

  const allowlisted = validateDatabaseSemanticMetadata({
    adapter_id: 'firestore',
    semantic_sensitivity: 'version-sensitive',
    adapter_rule_id: 'db.authorization.firestore.rules-query-boundary',
    semantic_source: {
      url: 'https://firebase.google.com/docs/firestore/security/rules-query',
      verified_on: '2026-07-28',
    },
  }, { asOf: '2026-07-28' })
  assert.deepEqual(allowlisted, { valid: true, errors: [] })
})

test('declared adapter rule catalogs reject invented semantic rule IDs', () => {
  const result = validateDatabaseSemanticMetadata({
    adapter_id: 'postgresql',
    semantic_sensitivity: 'version-sensitive',
    adapter_rule_id: 'db.imaginary.postgresql.this-rule-does-not-exist',
    semantic_source: {
      url: 'https://www.postgresql.org/docs/16/ddl-rowsecurity.html',
      verified_on: '2026-07-28',
    },
  }, { asOf: '2026-07-28' })

  assert.equal(result.valid, false)
  assert.ok(result.errors.some(
    ({ code }) => code === 'undeclared-adapter-rule-id',
  ))
})

test('inventory-only can never validate semantic clearance metadata', () => {
  const result = validateDatabaseSemanticMetadata({
    adapter_id: 'inventory-only',
    semantic_sensitivity: 'stable',
  }, { asOf: '2026-07-28' })

  assert.equal(result.valid, false)
  assert.equal(result.errors[0].code, 'semantic-adapter-not-selected')
})

test('manifest validation prevents a permissive fallback and identifier collisions', () => {
  const unsafeFallback = mutableManifest()
  unsafeFallback.fallback.can_clear = true
  assert.ok(validateDatabaseAdapterManifest(unsafeFallback).errors.includes(
    'fallback.can_clear must be false',
  ))

  const duplicateEngine = mutableManifest()
  duplicateEngine.adapters[1].engine_aliases.push('postgresql')
  assert.ok(validateDatabaseAdapterManifest(duplicateEngine).errors.some(
    (error) => error.includes('reuses engine name or alias "postgresql"'),
  ))

  const missingSourceHosts = mutableManifest()
  missingSourceHosts.adapters[0].semantic_source_hosts = []
  assert.ok(validateDatabaseAdapterManifest(missingSourceHosts).errors.some(
    (error) => error.includes('semantic_source_hosts must be a non-empty array'),
  ))

  const malformedSourceHost = mutableManifest()
  malformedSourceHost.adapters[0].semantic_source_hosts = ['https://www.postgresql.org']
  assert.ok(validateDatabaseAdapterManifest(malformedSourceHost).errors.some(
    (error) => error.includes('must be a lowercase hostname'),
  ))

  assert.throws(
    () => assertValidDatabaseAdapterManifest(unsafeFallback),
    /fallback\.can_clear must be false/,
  )
})
