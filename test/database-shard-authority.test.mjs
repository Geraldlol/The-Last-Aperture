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
  advanceRun,
  applyJobResult,
  beginJob,
  prepareJobStart,
} from '../scripts/lib/job-protocol.mjs'
import {
  validateRun,
  validateRunTransition,
} from '../scripts/lib/contracts.mjs'
import { createRunPlan } from '../scripts/lib/run-engine.mjs'
import { synthesizeStoreProfiles } from '../scripts/lib/store-synthesis.mjs'

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

function contextContribution(storeId, evidencePath, coverageState = 'NOT_ASSESSED') {
  return {
    store_id: storeId,
    coverage_state: coverageState,
    assessed_topics: coverageState === 'ASSESSED' ? DATABASE_TOPICS : [],
    evidence_paths: [evidencePath],
    coverage_gaps: coverageState === 'ASSESSED'
      ? []
      : [{
          area: 'shard-local store semantics',
          reason: 'This shard contribution remains unassessed.',
        }],
  }
}

function databaseFinding(profile, evidencePath) {
  return {
    candidate_id: 'database-native-authorization:7c41ab02',
    lens: 'database-and-data-stores',
    topic: 'database-native-authorization-and-tenant-isolation',
    title: 'Runtime role reads rows outside its tenant',
    claimed_impact_severity: 'Medium',
    location: [`${evidencePath}:1`],
    evidence: 'The bounded evidence binds one runtime role to every tenant row.',
    attack: 'Reuse the runtime connection to select another tenant row.',
    impact: 'Cross-tenant read through the shared runtime principal.',
    reachable_from: 'the application connection pool',
    confidence: 'High',
    proof_plan:
      'Assert the tenant policy is enabled; fixture pair is a schema with the policy and one without.',
    store_context: profile.store_context,
    principal_path: profile.principal_path,
    enforcement_plane: 'database',
    semantic_sensitivity: 'version-sensitive',
    adapter_rule_id: 'db.authorization.postgresql.rls-bypass',
    semantic_source: {
      url: 'https://www.postgresql.org/docs/16/ddl-rowsecurity.html',
      verified_on: '2026-07-28',
    },
  }
}

function providerResult(
  run,
  jobId,
  evidencePath,
  profile,
  explicitContribution,
) {
  const sidecar = plan.jobSidecars.find(
    ({ job_id: candidateJobId }) => candidateJobId === jobId,
  )
  const storeId = sidecar?.database_store_ids?.[0]
  const isAuthority = sidecar?.profile_authority_store_ids?.includes(storeId)
  const contribution = explicitContribution ?? (
    storeId === undefined
      ? undefined
      : isAuthority
        ? {
            store_id: storeId,
            profile: profile ?? inventoryOnlyProfile(storeId, evidencePath),
          }
        : profile
          ? { store_id: storeId, profile }
          : contextContribution(storeId, evidencePath)
  )
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
    topic_assessments: (sidecar?.topic_obligations ?? []).map((topic) => ({
      topic,
      disposition: 'examined-clean',
      reason: 'The database fixture assessed this topic in the bounded shard.',
      evidence: ['The fixture provider completed its bounded database topic check.'],
      evidence_paths: [evidencePath],
    })),
    store_contributions: contribution ? [contribution] : [],
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
    /context contribution .* cannot supply or rewrite a store profile/,
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

test('an authority shard records a local contribution without materializing a profile early', () => {
  const { home, storeId } = homeAndRelated()
  const evidencePath = home.scoped_files[0]
  let run = beginJob(plan.run, home.job_id)

  run = applyJobResult(
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
  )
  assert.equal(run.store_profiles.length, 0)
  assert.equal(run.store_contributions.length, 1)
  assert.equal(
    run.store_contributions[0].contribution.profile.coverage_state,
    'ASSESSED',
  )
})

test('an authority shard reports a finding against the store it profiles', () => {
  // Synthesis is deferred until every base lens job is terminal, but findings
  // arrive during FANOUT. A database finding must therefore bind to the
  // contribution that will become the profile, not to the materialized list.
  const { home, storeId } = homeAndRelated()
  const evidencePath = home.scoped_files[0]
  let run = beginJob(plan.run, home.job_id)

  const profile = postgresProfile(storeId, evidencePath, 'ASSESSED')
  const result = providerResult(run, home.job_id, evidencePath, profile)
  result.findings = [databaseFinding(profile, evidencePath)]
  result.topic_assessments = result.topic_assessments.map((assessment) =>
    assessment.topic === result.findings[0].topic
      ? {
          topic: assessment.topic,
          disposition: 'finding',
          reason: 'The database fixture reported a finding for this topic.',
          finding_ids: [result.findings[0].candidate_id],
        }
      : assessment)

  run = applyJobResult(run, result, {
    sidecar: home,
    expectedPacketSha256: PACKET_SHA256,
  })

  assert.equal(run.phase, 'FANOUT')
  assert.equal(run.store_profiles.length, 0)
  assert.equal(run.findings.length, 1)
  assert.equal(run.findings[0].store_context.store_id, storeId)
})

test('a finding citing a store no shard profiles is still refused', () => {
  const { home, storeId } = homeAndRelated()
  const evidencePath = home.scoped_files[0]
  const run = beginJob(plan.run, home.job_id)

  const profile = postgresProfile(storeId, evidencePath, 'ASSESSED')
  const stray = databaseFinding(profile, evidencePath)
  stray.store_context = {
    ...stray.store_context,
    store_id: 'store-never-discovered',
  }
  const result = providerResult(run, home.job_id, evidencePath, profile)
  result.findings = [stray]
  result.topic_assessments = result.topic_assessments.map((assessment) =>
    assessment.topic === stray.topic
      ? {
          topic: assessment.topic,
          disposition: 'finding',
          reason: 'The database fixture reported a finding for this topic.',
          finding_ids: [stray.candidate_id],
        }
      : assessment)

  assert.throws(
    () => applyJobResult(run, result, {
      sidecar: home,
      expectedPacketSha256: PACKET_SHA256,
    }),
    /references an unprofiled store/,
  )
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
  assert.ok(codes.has('STORE_PROFILE_DELTA_NOT_SYNTHESIZED'))
})

test('controller synthesis closes a cross-shard store only after every authenticated contribution', () => {
  const { home, storeId } = homeAndRelated()
  const databaseSidecars = initialDatabaseSidecars().filter(
    (sidecar) => sidecar.database_store_ids?.includes(storeId),
  )
  let run = structuredClone(plan.run)
  for (const job of run.jobs) {
    if (
      job.kind === 'LENS'
      && job.closure_round === undefined
      && job.lens !== 'database-and-data-stores'
    ) {
      job.state = 'SKIPPED'
      job.reason = 'test isolates database synthesis'
    }
  }

  const ordered = [
    home,
    ...databaseSidecars.filter(({ job_id: jobId }) => jobId !== home.job_id),
  ]
  for (const sidecar of ordered) {
    const evidencePath = sidecar.scoped_files[0]
    run = beginJob(run, sidecar.job_id)
    const contribution = sidecar.profile_authority_store_ids.includes(storeId)
      ? {
          store_id: storeId,
          profile: postgresProfile(storeId, evidencePath, 'ASSESSED'),
        }
      : contextContribution(storeId, evidencePath, 'ASSESSED')
    run = applyJobResult(
      run,
      providerResult(
        run,
        sidecar.job_id,
        evidencePath,
        undefined,
        contribution,
      ),
      {
        sidecar,
        expectedPacketSha256: PACKET_SHA256,
      },
    )
  }

  const reversed = structuredClone(run)
  reversed.store_contributions.reverse()
  assert.deepEqual(
    synthesizeStoreProfiles(run),
    synthesizeStoreProfiles(reversed),
  )
  const advanced = advanceRun(run)
  assert.equal(advanced.advanced, true)
  assert.equal(advanced.run.phase, 'TRIAGE')
  assert.equal(advanced.run.store_profiles.length, 1)
  assert.equal(advanced.run.store_profiles[0].coverage_state, 'ASSESSED')
  assert.deepEqual(
    advanced.run.store_profiles[0].evidence_paths,
    plan.run.database_discovery.store_candidates
      .find(({ store_id: candidateId }) => candidateId === storeId)
      .scope_paths,
  )
})

test('one partial context contribution conservatively degrades synthesized coverage', () => {
  const { home, storeId } = homeAndRelated()
  const databaseSidecars = initialDatabaseSidecars().filter(
    (sidecar) => sidecar.database_store_ids?.includes(storeId),
  )
  let run = structuredClone(plan.run)
  for (const job of run.jobs) {
    if (
      job.kind === 'LENS'
      && job.closure_round === undefined
      && job.lens !== 'database-and-data-stores'
    ) {
      job.state = 'SKIPPED'
      job.reason = 'test isolates database synthesis'
    }
  }

  const contexts = databaseSidecars.filter(
    ({ job_id: jobId }) => jobId !== home.job_id,
  )
  for (const [index, sidecar] of [home, ...contexts].entries()) {
    const evidencePath = sidecar.scoped_files[0]
    run = beginJob(run, sidecar.job_id)
    const contribution = sidecar.job_id === home.job_id
      ? {
          store_id: storeId,
          profile: postgresProfile(storeId, evidencePath, 'ASSESSED'),
        }
      : contextContribution(
          storeId,
          evidencePath,
          index === 1 ? 'PARTIAL' : 'ASSESSED',
        )
    run = applyJobResult(
      run,
      providerResult(
        run,
        sidecar.job_id,
        evidencePath,
        undefined,
        contribution,
      ),
      {
        sidecar,
        expectedPacketSha256: PACKET_SHA256,
      },
    )
  }

  const advanced = advanceRun(run).run
  assert.equal(advanced.store_profiles[0].coverage_state, 'PARTIAL')
  assert.ok(advanced.store_profiles[0].coverage_gaps.some(
    ({ area }) => area === 'shard-local store semantics',
  ))
})

test('forged contribution provenance and evidence fail standalone validation', () => {
  const { home, storeId } = homeAndRelated()
  const evidencePath = home.scoped_files[0]
  let run = beginJob(plan.run, home.job_id)
  run = applyJobResult(
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
  )

  const forgedDigest = structuredClone(run)
  forgedDigest.store_contributions[0].input_sha256 = 'b'.repeat(64)
  assert.ok(validateRun(forgedDigest).errors.some(
    ({ code }) => code === 'STORE_CONTRIBUTION_PROVENANCE_INVALID',
  ))

  const forgedEvidence = structuredClone(run)
  forgedEvidence.store_contributions[0]
    .contribution.profile.evidence_paths = ['src/runtime-config.ts']
  assert.ok(validateRun(forgedEvidence).errors.some(
    ({ code }) => code === 'STORE_CONTRIBUTION_EVIDENCE_OUTSIDE_SHARD',
  ))

  const forgedDetectionBinding = structuredClone(run)
  forgedDetectionBinding.store_contributions[0]
    .contribution.profile.store_context.detection_evidence = [
      `${evidencePath}: missing line binding`,
    ]
  assert.ok(validateRun(forgedDetectionBinding).errors.some(
    ({ code }) => code === 'DATABASE_PROFILE_UNBOUND_DETECTION_EVIDENCE',
  ))

  const forgedAdapter = structuredClone(run)
  forgedAdapter.store_contributions[0]
    .contribution.profile.store_context.adapter_id = 'inventory-only'
  assert.ok(validateRun(forgedAdapter).errors.some(
    ({ code }) => code === 'DATABASE_PROFILE_ROUTE_UNASSESSED',
  ))
})

test('legacy schema 3 retains direct home-shard profile behavior', () => {
  const { home, storeId } = homeAndRelated()
  const evidencePath = home.scoped_files[0]
  const legacy = structuredClone(plan.run)
  legacy.schema_version = '3.0.0'
  delete legacy.store_contributions
  let run = beginJob(legacy, home.job_id)
  run = applyJobResult(
    run,
    {
      ...providerResult(
        run,
        home.job_id,
        evidencePath,
        postgresProfile(storeId, evidencePath, 'PARTIAL'),
      ),
      store_profiles: [
        postgresProfile(storeId, evidencePath, 'PARTIAL'),
      ],
      store_contributions: [],
    },
    {
      sidecar: home,
      expectedPacketSha256: PACKET_SHA256,
    },
  )
  assert.equal(run.store_profiles.length, 1)
  assert.equal(run.store_profiles[0].coverage_state, 'PARTIAL')
})
