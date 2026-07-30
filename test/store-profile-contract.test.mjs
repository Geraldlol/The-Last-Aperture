import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import Ajv2020 from 'ajv/dist/2020.js'
import {
  findingSchema,
  storeProfileSchema,
} from '../scripts/lib/contracts.mjs'

const DATABASE_TOPICS = [
  'database-audit-identity-and-coverage',
  'database-backup-restore-and-clone-security',
  'database-integrity-transactions-and-concurrency',
  'database-lifecycle-and-copy-propagation',
  'database-migration-security-drift',
  'database-native-authorization-and-tenant-isolation',
  'database-principal-and-role-boundaries',
  'database-privileged-code-and-execution-context',
  'database-replication-cdc-history-and-sharing',
  'database-resource-governance-and-availability',
]

const topicRegistry = readFileSync(
  new URL('../skills/red-team-audit/lenses/_topics.md', import.meta.url),
  'utf8',
)
const registeredDatabaseTopics = topicRegistry
  .match(/## database-and-data-stores\r?\n\r?\n(?<topics>(?:- .+\r?\n)+)/)
  ?.groups?.topics
  .trim()
  .split(/\r?\n/)
  .map((line) => line.slice(2))

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})
ajv.addSchema(findingSchema)
const validateStoreProfile = ajv.compile(storeProfileSchema)

function completeAssessedProfile() {
  const evidencePaths = ['db/policies.sql']
  return {
    store_context: {
      store_id: 'orders-primary',
      family: 'relational',
      engine: 'postgresql',
      engine_version: '16.3',
      deployment_variant: 'self-managed',
      adapter_id: 'postgresql',
      detection_evidence: ['db/policies.sql:1 declares PostgreSQL 16.3'],
      confidence: 'high',
    },
    engine_edition: 'community',
    compatibility_mode: 'native',
    engine_evidence_paths: evidencePaths,
    principal_evidence_paths: evidencePaths,
    tenancy: {
      model: 'shared-table',
      tenant_attribute: 'tenant_id',
      claimed_guarantee: 'database-enforced',
      evidence: 'The tenant_id policy is declared in the bounded evidence set.',
      evidence_paths: evidencePaths,
    },
    principal_path: {
      authenticated_principal: 'application user',
      session_principal: 'orders_runtime',
      effective_principal: 'orders_runtime',
      owner_or_definer: 'orders_owner',
      bypass_capabilities: [],
    },
    evidence_paths: evidencePaths,
    enforcement_paths: {
      inventory_closed: true,
      paths: [{
        name: 'primary-sql',
        state: 'ASSESSED',
        evidence: 'The primary SQL policy is declared in the bounded evidence set.',
        evidence_paths: evidencePaths,
      }],
    },
    copy_artifact_closure: {
      artifact_set_closed: true,
      closure_basis: 'The scoped SQL file is the complete store artifact set.',
      evidence_paths: evidencePaths,
      categories: Object.fromEntries(
        ['replica', 'cdc', 'history', 'backup', 'export', 'cache'].map((category) => [
          category,
          {
            state: 'NOT_PRESENT',
            evidence: `${category} configuration is absent from the bounded evidence set.`,
            evidence_paths: evidencePaths,
          },
        ]),
      ),
    },
    availability_budget: {
      state: 'ASSESSED',
      description: 'Queries are limited to 500 ms and 20 concurrent requests per tenant.',
      evidence: 'The bounded limits are declared in the scoped SQL configuration.',
      evidence_paths: evidencePaths,
    },
    assumptions: [{
      statement: 'The deployed runtime and migration principals are distinct.',
      status: 'VALIDATED',
      evidence: 'Distinct role declarations are present in the bounded evidence set.',
      evidence_paths: evidencePaths,
    }],
    coverage_state: 'ASSESSED',
    assessed_topics: DATABASE_TOPICS,
    coverage_gaps: [],
  }
}

function assertInvalid(profile, message) {
  assert.equal(validateStoreProfile(profile), false, message)
}

test('the store denominator is locked to the generated database topic registry', () => {
  assert.deepEqual(registeredDatabaseTopics, DATABASE_TOPICS)
  assert.deepEqual(
    storeProfileSchema.properties.assessed_topics.items.enum,
    DATABASE_TOPICS,
  )
  assert.equal(new Set(DATABASE_TOPICS).size, 10)
})

test('ASSESSED is a closed claim over all ten database-owned topics', () => {
  const profile = completeAssessedProfile()
  assert.equal(
    validateStoreProfile(profile),
    true,
    JSON.stringify(validateStoreProfile.errors, null, 2),
  )

  const oneTopic = structuredClone(profile)
  oneTopic.assessed_topics = ['database-native-authorization-and-tenant-isolation']
  assertInvalid(oneTopic, 'one assessed topic must not clear the whole store')

  const duplicateTopic = structuredClone(profile)
  duplicateTopic.assessed_topics[9] = duplicateTopic.assessed_topics[0]
  assertInvalid(duplicateTopic, 'duplicate topics must not pad the denominator')

  const inventedTopic = structuredClone(profile)
  inventedTopic.coverage_state = 'PARTIAL'
  inventedTopic.assessed_topics = ['database-invented-clearance']
  inventedTopic.coverage_gaps = [{ area: 'topic', reason: 'coverage is incomplete' }]
  assertInvalid(inventedTopic, 'only database-owned registry topics are accepted')
})

test('every store profile records the engine, tenancy, enforcement, copy, budget, and assumptions dimensions', () => {
  for (const field of [
    'engine_edition',
    'compatibility_mode',
    'engine_evidence_paths',
    'principal_evidence_paths',
    'tenancy',
    'enforcement_paths',
    'copy_artifact_closure',
    'availability_budget',
    'assumptions',
  ]) {
    const profile = completeAssessedProfile()
    delete profile[field]
    assertInvalid(profile, `${field} must be explicit`)
  }

  for (const category of ['replica', 'cdc', 'history', 'backup', 'export', 'cache']) {
    const profile = completeAssessedProfile()
    delete profile.copy_artifact_closure.categories[category]
    assertInvalid(profile, `${category} copy state must be explicit`)
  }

  const unboundDimension = completeAssessedProfile()
  delete unboundDimension.copy_artifact_closure.categories.replica.evidence_paths
  assertInvalid(unboundDimension, 'assessed dimensions require machine-checkable evidence paths')
})

test('ASSESSED rejects open or NOT_ASSESSED dimensions', () => {
  const mutations = [
    ['unknown engine version', (profile) => {
      profile.store_context.engine_version = 'unknown'
    }],
    ['moving engine version', (profile) => {
      profile.store_context.engine_version = 'latest'
    }],
    ['non-version engine label', (profile) => {
      profile.store_context.engine_version = 'banana'
    }],
    ['unknown engine edition', (profile) => {
      profile.engine_edition = 'unknown'
    }],
    ['default engine edition', (profile) => {
      profile.engine_edition = 'default'
    }],
    ['embedded unresolved engine edition', (profile) => {
      profile.engine_edition = 'unknown edition'
    }],
    ['abbreviated unresolved engine edition', (profile) => {
      profile.engine_edition = 'N/A'
    }],
    ['unknown compatibility mode', (profile) => {
      profile.compatibility_mode = 'unknown'
    }],
    ['unresolved compatibility mode', (profile) => {
      profile.compatibility_mode = 'Unresolved'
    }],
    ['embedded unresolved compatibility mode', (profile) => {
      profile.compatibility_mode = 'TBD mode'
    }],
    ['prose unresolved compatibility mode', (profile) => {
      profile.compatibility_mode = 'not determined'
    }],
    ['unknown tenancy model', (profile) => {
      profile.tenancy.model = 'unknown'
    }],
    ['unknown tenant attribute', (profile) => {
      profile.tenancy.tenant_attribute = 'unknown'
    }],
    ['unknown tenancy guarantee', (profile) => {
      profile.tenancy.claimed_guarantee = 'unknown'
    }],
    ['unresolved effective principal', (profile) => {
      profile.principal_path.effective_principal = 'TBD'
    }],
    ['embedded unresolved effective principal', (profile) => {
      profile.principal_path.effective_principal = 'unknown effective principal'
    }],
    ['non-descriptor effective principal', (profile) => {
      profile.principal_path.effective_principal = '??'
    }],
    ['non-evidence assertion', (profile) => {
      profile.tenancy.evidence = 'x'
    }],
    ['missing engine evidence binding', (profile) => {
      delete profile.engine_evidence_paths
    }],
    ['unresolved bypass capability', (profile) => {
      profile.principal_path.bypass_capabilities = ['unspecified']
    }],
    ['open enforcement inventory', (profile) => {
      profile.enforcement_paths.inventory_closed = false
    }],
    ['unassessed enforcement path', (profile) => {
      profile.enforcement_paths.paths[0] = {
        name: 'primary-sql',
        state: 'NOT_ASSESSED',
        reason: 'native policy catalog was unavailable',
      }
    }],
    ['open artifact set', (profile) => {
      profile.copy_artifact_closure.artifact_set_closed = false
    }],
    ['unassessed copy category', (profile) => {
      profile.copy_artifact_closure.categories.cdc = {
        state: 'NOT_ASSESSED',
        reason: 'change-stream consumers were not inventoried',
      }
    }],
    ['unassessed availability budget', (profile) => {
      profile.availability_budget = {
        state: 'NOT_ASSESSED',
        description: 'No bounded workload model was supplied.',
        reason: 'production limits are external to the repository',
      }
    }],
    ['open assumption', (profile) => {
      profile.assumptions[0] = {
        statement: 'The deployed runtime and migration principals are distinct.',
        status: 'OPEN',
        reason: 'deployment bindings were not supplied',
      }
    }],
  ]

  for (const [label, mutate] of mutations) {
    const profile = completeAssessedProfile()
    mutate(profile)
    assertInvalid(profile, `${label} must prevent ASSESSED`)
  }
})

test('PARTIAL and NOT_ASSESSED carry gaps instead of silently clearing open work', () => {
  const partial = completeAssessedProfile()
  partial.coverage_state = 'PARTIAL'
  partial.assessed_topics = [
    'database-native-authorization-and-tenant-isolation',
  ]
  partial.principal_path.effective_principal = 'unknown'
  partial.enforcement_paths.inventory_closed = false
  partial.enforcement_paths.paths[0] = {
    name: 'primary-sql',
    state: 'NOT_ASSESSED',
    reason: 'native policy catalog was unavailable',
  }
  partial.copy_artifact_closure.artifact_set_closed = false
  partial.copy_artifact_closure.categories.cdc = {
    state: 'NOT_ASSESSED',
    reason: 'change-stream consumers were not inventoried',
  }
  partial.availability_budget = {
    state: 'NOT_ASSESSED',
    description: 'No bounded workload model was supplied.',
    reason: 'production limits are external to the repository',
  }
  partial.assumptions[0] = {
    statement: 'The deployed runtime and migration principals are distinct.',
    status: 'OPEN',
    reason: 'deployment bindings were not supplied',
  }
  partial.coverage_gaps = [{
    area: 'store-denominator',
    reason: 'enforcement, CDC, availability, and deployment bindings remain open',
  }]
  assert.equal(
    validateStoreProfile(partial),
    true,
    JSON.stringify(validateStoreProfile.errors, null, 2),
  )

  const silentPartial = structuredClone(partial)
  silentPartial.coverage_gaps = []
  assertInvalid(silentPartial, 'PARTIAL requires a named gap')

  const notAssessed = structuredClone(partial)
  notAssessed.coverage_state = 'NOT_ASSESSED'
  notAssessed.assessed_topics = []
  assert.equal(
    validateStoreProfile(notAssessed),
    true,
    JSON.stringify(validateStoreProfile.errors, null, 2),
  )

  const silentNotAssessed = structuredClone(notAssessed)
  silentNotAssessed.coverage_gaps = []
  assertInvalid(silentNotAssessed, 'NOT_ASSESSED requires a named gap')

  const contradictoryNotAssessed = structuredClone(notAssessed)
  contradictoryNotAssessed.assessed_topics = [
    'database-native-authorization-and-tenant-isolation',
  ]
  assertInvalid(
    contradictoryNotAssessed,
    'NOT_ASSESSED cannot claim assessed topics',
  )
})
