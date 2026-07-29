import assert from 'node:assert/strict'
import {
  mkdir,
  mkdtemp,
  rm,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  after,
  before,
  test,
} from 'node:test'

import {
  applyJobResult,
  beginJob,
  prepareJobStart,
} from '../scripts/lib/job-protocol.mjs'
import {
  validateRun,
  validateRunTransition,
} from '../scripts/lib/contracts.mjs'
import { createRunPlan } from '../scripts/lib/run-engine.mjs'

const PACKET_SHA256 = 'a'.repeat(64)
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
let fixtureRoot
let plan

function inventoryOnlyProfile(storeId, evidencePath) {
  return {
    store_context: {
      store_id: storeId,
      family: 'relational',
      engine: 'postgresql',
      engine_version: 'unknown',
      deployment_variant: 'unknown',
      adapter_id: 'inventory-only',
      detection_evidence: [`${evidencePath}:1 belongs to the discovered store component`],
      confidence: 'high',
    },
    engine_edition: 'unknown',
    compatibility_mode: 'unknown',
    engine_evidence_paths: [evidencePath],
    principal_evidence_paths: [evidencePath],
    tenancy: {
      model: 'unknown',
      tenant_attribute: 'unknown',
      claimed_guarantee: 'unknown',
      evidence: 'The bounded shard does not establish tenancy semantics.',
      evidence_paths: [evidencePath],
    },
    principal_path: {
      authenticated_principal: 'unknown',
      session_principal: 'unknown',
      effective_principal: 'unknown',
      owner_or_definer: 'unknown',
      bypass_capabilities: [],
    },
    evidence_paths: [evidencePath],
    enforcement_paths: {
      inventory_closed: false,
      paths: [{
        name: 'runtime',
        state: 'NOT_ASSESSED',
        reason: 'Runtime enforcement was not assessed.',
      }],
    },
    copy_artifact_closure: {
      artifact_set_closed: false,
      closure_basis: 'Copy artifacts were not enumerated.',
      evidence_paths: [evidencePath],
      categories: Object.fromEntries(
        ['replica', 'cdc', 'history', 'backup', 'export', 'cache']
          .map((category) => [
            category,
            {
              state: 'NOT_ASSESSED',
              reason: `${category} was not assessed`,
            },
          ]),
      ),
    },
    availability_budget: {
      state: 'NOT_ASSESSED',
      description: 'No bounded availability objective was established.',
      reason: 'Availability was not assessed.',
    },
    assumptions: [],
    coverage_state: 'NOT_ASSESSED',
    assessed_topics: [],
    coverage_gaps: [{
      area: 'store semantics',
      reason: 'The store remains inventory only.',
    }],
  }
}

function providerResult(run, jobId, evidencePath, profile) {
  return {
    schema_version: '1.0.0',
    run_id: run.run_id,
    job_id: jobId,
    input_sha256: PACKET_SHA256,
    producer: {
      name: 'database-shard-authority-test',
      version: '1.0.0',
      instance_id: 'database-shard-authority-test:instance-1',
    },
    state: 'SUCCEEDED',
    examined_files: [evidencePath],
    findings: [],
    coverage_gaps: [],
    store_profiles: profile ? [profile] : [],
  }
}

function postgresProfile(storeId, evidencePath, coverageState = 'PARTIAL') {
  const evidencePaths = [evidencePath]
  return {
    store_context: {
      store_id: storeId,
      family: 'relational',
      engine: 'postgresql',
      engine_version: '16.3',
      deployment_variant: 'self-managed',
      adapter_id: 'postgresql',
      detection_evidence: [
        `${evidencePath}:1 declares the bounded PostgreSQL store surface`,
      ],
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
      evidence: 'The bounded evidence declares a tenant isolation policy.',
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
        evidence: 'The primary SQL enforcement path was inspected.',
        evidence_paths: evidencePaths,
      }],
    },
    copy_artifact_closure: {
      artifact_set_closed: true,
      closure_basis: 'The bounded evidence declares each known copy category.',
      evidence_paths: evidencePaths,
      categories: Object.fromEntries(
        ['replica', 'cdc', 'history', 'backup', 'export', 'cache']
          .map((category) => [
            category,
            {
              state: 'NOT_PRESENT',
              evidence: `${category} configuration is absent from bounded evidence.`,
              evidence_paths: evidencePaths,
            },
          ]),
      ),
    },
    availability_budget: {
      state: 'ASSESSED',
      description: 'Queries are limited to a bounded per-tenant budget.',
      evidence: 'The bounded evidence declares the workload budget.',
      evidence_paths: evidencePaths,
    },
    assumptions: [{
      statement: 'The runtime and migration principals remain distinct.',
      status: 'VALIDATED',
      evidence: 'The bounded evidence declares distinct principals.',
      evidence_paths: evidencePaths,
    }],
    coverage_state: coverageState,
    assessed_topics: DATABASE_TOPICS,
    coverage_gaps: coverageState === 'ASSESSED'
      ? []
      : [{
          area: 'cross-shard store closure',
          reason: 'Other discovered store paths are assigned to related shards.',
        }],
  }
}

function initialDatabaseSidecars() {
  return plan.jobSidecars.filter((sidecar) =>
    sidecar.kind === 'LENS'
    && sidecar.lens === 'database-and-data-stores'
    && sidecar.closure_round === undefined)
}

function homeAndRelated() {
  const initial = initialDatabaseSidecars()
  const home = initial.find(
    (sidecar) => sidecar.profile_authority_store_ids?.length > 0,
  )
  assert.ok(home, 'expected one database shard to own a discovered store profile')
  const storeId = home.profile_authority_store_ids[0]
  const related = initial.find((sidecar) =>
    sidecar.database_store_ids?.includes(storeId)
    && !sidecar.profile_authority_store_ids?.includes(storeId))
  assert.ok(related, 'expected the discovered component to cross a non-home shard')
  return { home, related, storeId }
}

before(async () => {
  fixtureRoot = await mkdtemp(join(tmpdir(), 'red-team-db-shard-authority-'))
  const repository = join(fixtureRoot, 'repository')
  await mkdir(join(repository, 'src'), { recursive: true })
  await Promise.all([
    writeFile(
      join(repository, 'package.json'),
      '{"name":"db-shard-authority","dependencies":{"pg":"8.16.3"}}\n',
    ),
    writeFile(
      join(repository, 'src', 'db.ts'),
      [
        "import { Pool } from 'pg'",
        "import { databaseUrl } from './runtime-config'",
        'export const pool = new Pool({ connectionString: databaseUrl })',
        '',
      ].join('\n'),
    ),
    writeFile(
      join(repository, 'src', 'runtime-config.ts'),
      'export const databaseUrl = process.env.DATABASE_URL\n',
    ),
  ])
  plan = await createRunPlan({
    targetRoot: repository,
    lensDirectory: join(process.cwd(), 'skills', 'red-team-audit', 'lenses'),
    createdAt: new Date('2026-07-29T20:00:00.000Z'),
    maxClosureRounds: 2,
    shardOptions: {
      maxFiles: 1,
      maxBytes: 1024 * 1024,
    },
  })
})

after(async () => {
  if (fixtureRoot) await rm(fixtureRoot, { recursive: true, force: true })
})

test('database profile authority stays on the home shard and its sealed retries', () => {
  const initial = plan.jobSidecars.filter((sidecar) =>
    sidecar.kind === 'LENS'
    && sidecar.lens === 'database-and-data-stores'
    && sidecar.closure_round === undefined)
  const home = initial.find(
    (sidecar) => sidecar.database_discovery?.store_candidates?.length > 0,
  )
  assert.ok(home, 'expected one database shard to own a discovered store profile')
  const storeId = home.database_discovery.store_candidates[0].store_id
  const related = initial.find((sidecar) =>
    sidecar.database_discovery?.related_store_ids?.includes(storeId)
    && !sidecar.database_discovery.store_candidates
      .some(({ store_id: candidateId }) => candidateId === storeId))
  assert.ok(related, 'expected the discovered component to cross a non-home shard')

  const retries = plan.jobSidecars.filter((sidecar) =>
    sidecar.kind === 'LENS'
    && sidecar.parent_job_id === home.job_id)
  assert.equal(retries.length, 2)
  assert.ok(retries.every((sidecar) =>
    sidecar.database_discovery.store_candidates
      .some(({ store_id: candidateId }) => candidateId === storeId)))
})

test('a related database shard cannot profile a store owned by its home shard', () => {
  const initial = plan.jobSidecars.filter((sidecar) =>
    sidecar.kind === 'LENS'
    && sidecar.lens === 'database-and-data-stores'
    && sidecar.closure_round === undefined)
  const home = initial.find(
    (sidecar) => sidecar.database_discovery?.store_candidates?.length > 0,
  )
  const storeId = home.database_discovery.store_candidates[0].store_id
  const related = initial.find((sidecar) =>
    sidecar.database_discovery?.related_store_ids?.includes(storeId)
    && !sidecar.database_discovery.store_candidates
      .some(({ store_id: candidateId }) => candidateId === storeId))
  assert.ok(related)

  const run = structuredClone(plan.run)
  run.state = 'RUNNING'
  run.phase = 'FANOUT'
  run.jobs.find(({ job_id: jobId }) => jobId === related.job_id).state = 'RUNNING'
  const evidencePath = related.scoped_files[0]

  assert.throws(
    () => applyJobResult(
      run,
      providerResult(
        run,
        related.job_id,
        evidencePath,
        inventoryOnlyProfile(storeId, evidencePath),
      ),
      {
        sidecar: related,
        expectedPacketSha256: PACKET_SHA256,
      },
    ),
    /store profile .* is not assigned to this database shard/,
  )
})

test('v3 contracts recompute database shard metadata and seal retry authority', () => {
  const untouched = validateRun(plan.run)
  assert.equal(
    untouched.valid,
    true,
    JSON.stringify(untouched.errors, null, 2),
  )

  const { home, related, storeId } = homeAndRelated()
  const baseAuthorityJobs = plan.run.jobs.filter((job) =>
    job.kind === 'LENS'
    && job.lens === 'database-and-data-stores'
    && job.closure_round === undefined
    && job.profile_authority_store_ids?.includes(storeId))
  assert.equal(baseAuthorityJobs.length, 1)
  assert.equal(baseAuthorityJobs[0].job_id, home.job_id)

  const forgedRelated = structuredClone(plan.run)
  forgedRelated.jobs.find(
    ({ job_id: jobId }) => jobId === related.job_id,
  ).database_store_ids = []
  assert.ok(
    validateRun(forgedRelated).errors.some(
      ({ code }) => code === 'DATABASE_JOB_STORE_METADATA_MISMATCH',
    ),
  )

  const forgedAuthority = structuredClone(plan.run)
  forgedAuthority.jobs.find(
    ({ job_id: jobId }) => jobId === home.job_id,
  ).profile_authority_store_ids = []
  const authorityCodes = new Set(
    validateRun(forgedAuthority).errors.map(({ code }) => code),
  )
  assert.ok(authorityCodes.has('DATABASE_JOB_AUTHORITY_METADATA_MISMATCH'))
  assert.ok(authorityCodes.has('DATABASE_PROFILE_AUTHORITY_COUNT_INVALID'))

  const forgedRetry = structuredClone(plan.run)
  const retry = forgedRetry.jobs.find((job) =>
    job.kind === 'LENS'
    && job.parent_job_id === home.job_id
    && job.closure_round === 1)
  assert.ok(retry)
  retry.profile_authority_store_ids = []
  assert.ok(
    validateRun(forgedRetry).errors.some(
      ({ code }) => code === 'DATABASE_RETRY_STORE_METADATA_MISMATCH',
    ),
  )
})

test('database store and authority arrays are immutable transition identity', () => {
  const { related } = homeAndRelated()
  const next = structuredClone(plan.run)
  next.jobs.find(
    ({ job_id: jobId }) => jobId === related.job_id,
  ).database_store_ids = []

  const validation = validateRunTransition(plan.run, next)
  assert.equal(validation.valid, false)
  assert.ok(validation.errors.some(
    ({ code }) => code === 'JOB_IDENTITY_CHANGED',
  ))
})

test('context shards wait for the base authority job to terminate', () => {
  const { home, related } = homeAndRelated()
  assert.throws(
    () => prepareJobStart(plan.run, related.job_id),
    new RegExp(
      `database context job .* must wait for profile authority job ${home.job_id}`,
    ),
  )

  const authorityStarted = prepareJobStart(plan.run, home.job_id)
  assert.equal(
    authorityStarted.jobs.find(
      ({ job_id: jobId }) => jobId === home.job_id,
    ).state,
    'RUNNING',
  )

  let run = beginJob(plan.run, home.job_id)
  run = applyJobResult(
    run,
    providerResult(run, home.job_id, home.scoped_files[0]),
    {
      sidecar: home,
      expectedPacketSha256: PACKET_SHA256,
    },
  )
  const contextStarted = prepareJobStart(run, related.job_id)
  assert.equal(
    contextStarted.jobs.find(
      ({ job_id: jobId }) => jobId === related.job_id,
    ).state,
    'RUNNING',
  )
})

test('a home shard may record partial coverage but cannot clear a cross-shard store', () => {
  const { home, storeId } = homeAndRelated()
  const evidencePath = home.scoped_files[0]
  let run = beginJob(plan.run, home.job_id)

  assert.throws(
    () => applyJobResult(
      run,
      providerResult(
        run,
        home.job_id,
        evidencePath,
        postgresProfile(storeId, evidencePath, 'ASSESSED'),
      ),
      {
        sidecar: home,
        expectedPacketSha256: PACKET_SHA256,
      },
    ),
    /cannot be ASSESSED from a shard that does not contain its complete discovered scope/,
  )

  run = applyJobResult(
    run,
    providerResult(
      run,
      home.job_id,
      evidencePath,
      postgresProfile(storeId, evidencePath, 'PARTIAL'),
    ),
    {
      sidecar: home,
      expectedPacketSha256: PACKET_SHA256,
    },
  )
  assert.equal(run.store_profiles.length, 1)
  assert.equal(run.store_profiles[0].coverage_state, 'PARTIAL')
})

test('the transition contract rejects a profile appended by a related shard', () => {
  const { home, related, storeId } = homeAndRelated()
  let run = beginJob(plan.run, home.job_id)
  run = applyJobResult(
    run,
    providerResult(run, home.job_id, home.scoped_files[0]),
    {
      sidecar: home,
      expectedPacketSha256: PACKET_SHA256,
    },
  )
  const previous = beginJob(run, related.job_id)
  const next = structuredClone(previous)
  Object.assign(
    next.jobs.find(({ job_id: jobId }) => jobId === related.job_id),
    {
      state: 'SUCCEEDED',
      input_sha256: PACKET_SHA256,
      producer: {
        name: 'database-shard-authority-test',
        version: '1.0.0',
        instance_id: 'database-shard-authority-test:instance-1',
      },
      coverage_authority: 'PROVIDER_DECLARED',
    },
  )
  next.store_profiles.push(
    inventoryOnlyProfile(storeId, related.scoped_files[0]),
  )

  const validation = validateRunTransition(previous, next)
  const codes = new Set(validation.errors.map(({ code }) => code))
  assert.equal(validation.valid, false)
  assert.ok(codes.has('STORE_PROFILE_NOT_JOB_AUTHORIZED'))
})
