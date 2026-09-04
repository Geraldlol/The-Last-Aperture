import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  advanceRun,
  applyJobResult as applyProtocolJobResult,
  assertValidJobResult,
  beginJob,
  buildFinalizedRun,
  createProofJobComparator,
  validateJobResult,
} from '../scripts/lib/job-protocol.mjs'
import { pendingJobsForCurrentPhase } from '../scripts/audit.mjs'
import { validateRun } from '../scripts/lib/contracts.mjs'

const SHA_A = 'a'.repeat(64)
const SHA_B = 'b'.repeat(64)
const SHA_C = 'c'.repeat(64)

function stageOne(overrides = {}) {
  return {
    candidate_id: 'authz-object-level:a3f19c2e',
    lens: 'web-and-api',
    topic: 'authz-object-level',
    title: 'Invoice route loads another tenant by identifier',
    claimed_impact_severity: 'High',
    location: ['src/routes/invoices.ts:88'],
    cwe: 'CWE-639',
    evidence: 'const invoice = await repo.findById(req.params.id)',
    attack: 'GET /api/invoices/8814 while authenticated to another tenant',
    impact: 'Reads another tenant invoice and billing address',
    reachable_from: 'GET /api/invoices/:id',
    confidence: 'High',
    proof_plan: 'Request subject A invoice as subject B and assert refusal plus marker absence',
    ...overrides,
  }
}

function triaged(overrides = {}) {
  return {
    ...stageOne(),
    effective_severity: 'Medium',
    triage_disposition: 'queued',
    ...overrides,
  }
}

function staticProof(overrides = {}) {
  return {
    ...triaged(),
    existence_check: {
      status: 'located',
      method: 'read src/routes/invoices.ts:88 and compare the quoted evidence verbatim',
    },
    proof_tier: 'T0',
    verification_status: 'UNPROVEN',
    blocking_reason: 'static mode cannot execute the two-subject harness',
    ...overrides,
  }
}

function withExistence(overrides = {}) {
  return {
    ...triaged(),
    existence_check: {
      status: 'located',
      method: 'read src/routes/invoices.ts:88 and compare the quoted evidence verbatim',
    },
    ...overrides,
  }
}

function plannedRun() {
  return {
    schema_version: '1.0.0',
    run_id: 'run:20260728:jobprotocol',
    state: 'PLANNED',
    phase: 'RECON',
    capability_mode: 'STATIC',
    created_at: '2026-07-28T20:00:00Z',
    tool: {
      name: 'red-team-audit',
      version: '0.2.0',
      corpus_sha256: SHA_C,
    },
    plan_digest: SHA_A,
    policy_digest: SHA_B,
    lens_pack_digest: SHA_C,
    repository: {
      root: 'C:/workspace/example',
      tree_digest: SHA_A,
      dirty: 'unknown',
    },
    scope: {
      included_paths: ['src/routes/invoices.ts'],
      excluded_paths: [],
    },
    activated_lenses: ['web-and-api', 'business-logic', 'completeness'],
    jobs: [
      {
        job_id: 'lens:web-and-api',
        kind: 'LENS',
        lens: 'web-and-api',
        state: 'PENDING',
      },
      {
        job_id: 'triage:business-logic',
        kind: 'TRIAGE',
        lens: 'business-logic',
        state: 'PENDING',
      },
      {
        job_id: 'completeness:completeness',
        kind: 'COMPLETENESS',
        lens: 'completeness',
        state: 'PENDING',
      },
    ],
    coverage: {
      inventory: ['src/routes/invoices.ts'],
      examined: [],
      unexamined: [{
        path: 'src/routes/invoices.ts',
        reason: 'audit job has not run',
      }],
      lenses: [
        { lens: 'web-and-api', status: 'NOT_ASSESSED', examined_paths: [], reason: 'audit job has not run' },
        { lens: 'business-logic', status: 'NOT_ASSESSED', examined_paths: [], reason: 'audit job has not run' },
        { lens: 'completeness', status: 'NOT_ASSESSED', examined_paths: [], reason: 'audit job has not run' },
      ],
      gaps: [],
    },
    store_profiles: [],
    findings: [],
    errors: [],
    artifacts: {},
  }
}

function jobResult(run, jobId, overrides = {}) {
  return {
    schema_version: '1.0.0',
    run_id: run.run_id,
    job_id: jobId,
    input_sha256: SHA_A,
    producer: {
      name: 'unit-test-provider',
      version: '1.0.0',
      instance_id: 'unit-test-provider:instance-1',
    },
    state: 'SUCCEEDED',
    examined_files: [],
    findings: [],
    coverage_gaps: [],
    ...overrides,
  }
}

function applyJobResult(run, result, options = {}) {
  return applyProtocolJobResult(run, result, {
    ...options,
    expectedPacketSha256: SHA_A,
  })
}

function failedJobResult(run, jobId, message = 'provider exceeded its bounded job deadline') {
  return jobResult(run, jobId, {
    state: 'FAILED',
    error: {
      code: 'PROVIDER_TIMEOUT',
      message,
      recoverable: true,
    },
  })
}

function runToProof() {
  let run = beginJob(plannedRun(), 'lens:web-and-api')
  run = applyJobResult(run, jobResult(run, 'lens:web-and-api', {
    examined_files: ['src/routes/invoices.ts'],
    findings: [stageOne()],
  }), { sidecar: lensSidecar })
  ;({ run } = advanceRun(run))
  run = beginJob(run, 'triage:business-logic')
  run = applyJobResult(run, jobResult(run, 'triage:business-logic', {
    findings: [triaged()],
  }))
  ;({ run } = advanceRun(run))
  return run
}

function runManyToProof(count) {
  const stageOneFindings = Array.from({ length: count }, (_, index) => stageOne({
    candidate_id: `authz-object-level:wave-${String(index + 1).padStart(2, '0')}`,
    title: `Candidate-bound proof wave finding ${index + 1}`,
  }))
  const triagedFindings = stageOneFindings.map((finding) => ({
    ...finding,
    effective_severity: 'Medium',
    triage_disposition: 'queued',
  }))

  let run = beginJob(plannedRun(), 'lens:web-and-api')
  run = applyJobResult(run, jobResult(run, 'lens:web-and-api', {
    examined_files: ['src/routes/invoices.ts'],
    findings: stageOneFindings,
  }), { sidecar: lensSidecar })
  ;({ run } = advanceRun(run))
  run = beginJob(run, 'triage:business-logic')
  run = applyJobResult(run, jobResult(run, 'triage:business-logic', {
    findings: triagedFindings,
  }))
  ;({ run } = advanceRun(run))
  return { run, triagedFindings }
}

function addExistence(finding) {
  return {
    ...finding,
    existence_check: {
      status: 'located',
      method: `read ${finding.location[0]} and compare the quoted evidence verbatim`,
    },
  }
}

const lensSidecar = {
  job_id: 'lens:web-and-api',
  scoped_files: ['src/routes/invoices.ts'],
  owned_topics: ['authz-object-level'],
  known_topics: ['authz-object-level'],
}

const databasePrincipal = {
  authenticated_principal: 'application user',
  session_principal: 'orders_runtime',
  effective_principal: 'orders_runtime',
  owner_or_definer: 'orders_owner',
  bypass_capabilities: [],
}

const databaseStore = {
  store_id: 'orders-primary',
  family: 'relational',
  engine: 'postgresql',
  engine_version: '16',
  deployment_variant: 'self-managed',
  adapter_id: 'postgresql',
  detection_evidence: ['db/policies.sql:1 declares PostgreSQL 16'],
  confidence: 'high',
}

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

function databaseStageOne() {
  return stageOne({
    candidate_id: 'database-native-authorization:4ba01c9f',
    lens: 'database-and-data-stores',
    topic: 'database-native-authorization-and-tenant-isolation',
    title: 'Runtime role bypasses the tenant policy',
    location: ['db/policies.sql:41'],
    evidence: 'ALTER TABLE invoices DISABLE ROW LEVEL SECURITY;',
    attack: 'Query another tenant invoice through the deployed runtime role',
    impact: 'Reads tenant invoices across the isolation boundary',
    reachable_from: 'POST /graphql',
    proof_plan: 'Exercise two principals against an isolated PostgreSQL database',
    store_context: databaseStore,
    principal_path: databasePrincipal,
    enforcement_plane: 'database',
    semantic_sensitivity: 'version-sensitive',
    adapter_rule_id: 'db.authorization.postgresql.rls-bypass',
    semantic_source: {
      url: 'https://www.postgresql.org/docs/16/ddl-rowsecurity.html',
      verified_on: '2026-07-28',
    },
  })
}

function databasePlannedRun() {
  const run = plannedRun()
  run.activated_lenses[0] = 'database-and-data-stores'
  run.jobs[0] = {
    job_id: 'lens:database-and-data-stores',
    kind: 'LENS',
    lens: 'database-and-data-stores',
    state: 'PENDING',
  }
  run.coverage.inventory = ['db/policies.sql']
  run.coverage.unexamined = [{
    path: 'db/policies.sql',
    reason: 'audit job has not run',
  }]
  run.coverage.lenses[0] = {
    lens: 'database-and-data-stores',
    status: 'NOT_ASSESSED',
    examined_paths: [],
    reason: 'audit job has not run',
  }
  run.store_profiles = []
  return run
}

const databaseSidecar = {
  job_id: 'lens:database-and-data-stores',
  scoped_files: ['db/policies.sql'],
  owned_topics: DATABASE_TOPICS,
  known_topics: DATABASE_TOPICS,
}

test('job result schema is strict and fail-closed', () => {
  const value = jobResult(plannedRun(), 'lens:web-and-api')
  assert.equal(validateJobResult(value).valid, true)
  assert.equal(validateJobResult({ ...value, surprise: true }).valid, false)
  const { input_sha256: _inputSha256, ...withoutInputDigest } = value
  const { producer: _producer, ...withoutProducer } = value
  assert.equal(validateJobResult(withoutInputDigest).valid, false)
  assert.equal(validateJobResult(withoutProducer).valid, false)
  assert.throws(
    () => assertValidJobResult({ ...value, findings: [stageOne(), stageOne()] }),
    /duplicate candidate_id/,
  )
})

test('job result acceptance is bound to the controller-derived dispatch digest', () => {
  const run = beginJob(plannedRun(), 'lens:web-and-api')
  const value = jobResult(run, 'lens:web-and-api')

  assert.throws(
    () => applyProtocolJobResult(run, value, { sidecar: lensSidecar }),
    /requires the controller-derived expectedPacketSha256/,
  )
  assert.throws(
    () => applyProtocolJobResult(run, value, {
      expectedPacketSha256: SHA_B,
      sidecar: lensSidecar,
    }),
    /not bound to the expected dispatch packet/,
  )

  const accepted = applyProtocolJobResult(run, value, {
    expectedPacketSha256: SHA_A.toUpperCase(),
    sidecar: lensSidecar,
  })
  assert.equal(accepted.jobs[0].state, 'SUCCEEDED')
  assert.equal(accepted.jobs[0].input_sha256, SHA_A)
})

test('initial fan-out still rejects an existing candidate_id collision', () => {
  const planned = plannedRun()
  planned.findings = [stageOne()]
  const run = beginJob(planned, 'lens:web-and-api')

  assert.throws(
    () => applyJobResult(run, jobResult(run, 'lens:web-and-api', {
      examined_files: ['src/routes/invoices.ts'],
      findings: [stageOne()],
    }), { sidecar: lensSidecar }),
    /candidate_id collision during fan-out/,
  )
})

test('database fan-out inventories each store and binds findings to its immutable profile', () => {
  let run = beginJob(databasePlannedRun(), 'lens:database-and-data-stores')
  const profile = {
    store_context: databaseStore,
    engine_edition: 'community',
    compatibility_mode: 'native',
    engine_evidence_paths: ['db/policies.sql'],
    principal_evidence_paths: ['db/policies.sql'],
    tenancy: {
      model: 'shared-table',
      tenant_attribute: 'tenant_id',
      claimed_guarantee: 'database-enforced',
      evidence: 'The tenant_id policy is declared in the bounded evidence set.',
      evidence_paths: ['db/policies.sql'],
    },
    principal_path: databasePrincipal,
    evidence_paths: ['db/policies.sql'],
    enforcement_paths: {
      inventory_closed: true,
      paths: [{
        name: 'primary-sql',
        state: 'ASSESSED',
        evidence: 'The primary SQL policy is declared in the bounded evidence set.',
        evidence_paths: ['db/policies.sql'],
      }],
    },
    copy_artifact_closure: {
      artifact_set_closed: true,
      closure_basis: 'The scoped SQL file is the complete store artifact set.',
      evidence_paths: ['db/policies.sql'],
      categories: Object.fromEntries(
        ['replica', 'cdc', 'history', 'backup', 'export', 'cache'].map((category) => [
          category,
          {
            state: 'NOT_PRESENT',
            evidence: `${category} configuration is absent from the bounded evidence set.`,
            evidence_paths: ['db/policies.sql'],
          },
        ]),
      ),
    },
    availability_budget: {
      state: 'ASSESSED',
      description: 'Queries are limited to 500 ms and 20 concurrent requests per tenant.',
      evidence: 'The bounded limits are declared in the scoped SQL configuration.',
      evidence_paths: ['db/policies.sql'],
    },
    assumptions: [{
      statement: 'The deployed runtime and migration principals are distinct.',
      status: 'VALIDATED',
      evidence: 'Distinct role declarations are present in the bounded evidence set.',
      evidence_paths: ['db/policies.sql'],
    }],
    coverage_state: 'ASSESSED',
    assessed_topics: DATABASE_TOPICS,
    coverage_gaps: [],
  }
  run = applyJobResult(run, jobResult(run, 'lens:database-and-data-stores', {
    examined_files: ['db/policies.sql'],
    store_profiles: [profile],
    findings: [databaseStageOne()],
  }), { sidecar: databaseSidecar })

  assert.equal(run.store_profiles.length, 1)
  assert.equal(run.store_profiles[0].store_context.store_id, 'orders-primary')
  assert.equal(run.findings[0].store_context.store_id, 'orders-primary')

  let missing = beginJob(databasePlannedRun(), 'lens:database-and-data-stores')
  assert.throws(
    () => applyJobResult(missing, jobResult(missing, 'lens:database-and-data-stores', {
      examined_files: ['db/policies.sql'],
      findings: [databaseStageOne()],
    }), { sidecar: databaseSidecar }),
    /must inventory every detected store/,
  )
})

test('hashed sidecar authority enforces topic ownership and zero-owner attribution', () => {
  let owningRun = beginJob(plannedRun(), 'lens:web-and-api')
  assert.throws(
    () => applyJobResult(owningRun, jobResult(owningRun, 'lens:web-and-api', {
      examined_files: ['src/routes/invoices.ts'],
      findings: [stageOne({ topic: 'csrf' })],
    }), { sidecar: lensSidecar }),
    /does not own topic csrf/,
  )

  const crossCuttingRun = plannedRun()
  crossCuttingRun.activated_lenses[0] = 'ai-generated-code'
  crossCuttingRun.jobs[0] = {
    job_id: 'lens:ai-generated-code',
    kind: 'LENS',
    lens: 'ai-generated-code',
    state: 'PENDING',
  }
  crossCuttingRun.coverage.lenses[0].lens = 'ai-generated-code'
  let started = beginJob(crossCuttingRun, 'lens:ai-generated-code')
  started = applyJobResult(started, jobResult(started, 'lens:ai-generated-code', {
    examined_files: ['src/routes/invoices.ts'],
    findings: [stageOne({
      candidate_id: 'authz-object-level:crosscutting',
      lens: 'ai-generated-code',
      raised_by: 'ai-generated-code',
    })],
  }), {
    sidecar: {
      job_id: 'lens:ai-generated-code',
      scoped_files: ['src/routes/invoices.ts'],
      owned_topics: [],
      known_topics: ['authz-object-level'],
    },
  })
  assert.equal(started.findings[0].raised_by, 'ai-generated-code')
})

test('proof priority promotes every component of a high-impact attack chain', () => {
  const run = {
    findings: [
      triaged({
        candidate_id: 'component:medium',
        claimed_impact_severity: 'Medium',
        effective_severity: 'Medium',
      }),
      triaged({
        candidate_id: 'standalone:high',
        claimed_impact_severity: 'High',
        effective_severity: 'High',
      }),
      triaged({
        candidate_id: 'chain:critical',
        claimed_impact_severity: 'Medium',
        effective_severity: 'Critical',
        triage_disposition: 'elevated',
        raised_by: 'attack-chaining',
        component_finding_ids: ['component:medium', 'chain:critical'],
      }),
    ],
  }
  const component = {
    job_id: 'proof-existence:component:medium',
    candidate_ids: ['component:medium'],
  }
  const standalone = {
    job_id: 'proof-existence:standalone:high',
    candidate_ids: ['standalone:high'],
  }
  assert.ok(createProofJobComparator(run)(component, standalone) < 0)
})

test('a reachability-capped Critical outranks an ordinary High in the proof queue', () => {
  const run = {
    findings: [
      triaged({
        candidate_id: 'authz-object-level:ordinary-high',
        claimed_impact_severity: 'High',
        effective_severity: 'High',
      }),
      triaged({
        candidate_id: 'authz-object-level:capped-critical',
        claimed_impact_severity: 'Critical',
        effective_severity: 'Medium',
        reachable_from: 'unknown',
      }),
      triaged({
        candidate_id: 'authz-object-level:contingent-critical',
        claimed_impact_severity: 'Critical',
        effective_severity: 'Medium',
        reachable_from: 'contingent:POST /api/exports',
        contingent_fact: 'the guest permission set is assigned to at least one user',
        contingent_query: 'SELECT COUNT(*) FROM PermissionSetAssignment WHERE PermissionSetId = :id',
      }),
    ],
  }
  const compare = createProofJobComparator(run)
  const ordered = run.findings
    .map(({ candidate_id: candidateId }) => ({
      job_id: `proof-existence:${candidateId}`,
      candidate_ids: [candidateId],
    }))
    .sort(compare)

  assert.deepEqual(
    ordered.map(({ candidate_ids: candidateIds }) => candidateIds[0]),
    [
      'authz-object-level:contingent-critical',
      'authz-object-level:capped-critical',
      'authz-object-level:ordinary-high',
    ],
    'claimed Critical outranks claimed High even when the reachability gate capped it to Medium',
  )
})

test('the dispatched proof queue puts a reachability-capped Critical ahead of an ordinary High', () => {
  const cappedCritical = {
    candidate_id: 'authz-object-level:zz-capped-critical',
    claimed_impact_severity: 'Critical',
    reachable_from: 'unknown',
    title: 'Unreachable-path candidate whose claimed impact is Critical',
  }
  const ordinaryHigh = {
    candidate_id: 'authz-object-level:aa-ordinary-high',
    claimed_impact_severity: 'High',
    title: 'Traced candidate whose claimed impact is High',
  }
  const stageOneFindings = [cappedCritical, ordinaryHigh].map((overrides) =>
    stageOne(overrides))

  let run = beginJob(plannedRun(), 'lens:web-and-api')
  run = applyJobResult(run, jobResult(run, 'lens:web-and-api', {
    examined_files: ['src/routes/invoices.ts'],
    findings: stageOneFindings,
  }), { sidecar: lensSidecar })
  ;({ run } = advanceRun(run))
  run = beginJob(run, 'triage:business-logic')
  run = applyJobResult(run, jobResult(run, 'triage:business-logic', {
    findings: stageOneFindings.map((finding) => ({
      ...finding,
      effective_severity: finding.reachable_from === 'unknown' ? 'Medium' : 'High',
      triage_disposition: 'queued',
    })),
  }))
  ;({ run } = advanceRun(run))

  assert.equal(validateRun(run).valid, true)
  assert.deepEqual(
    pendingJobsForCurrentPhase(run).map(({ job_id: jobId }) => jobId),
    [
      'proof-existence:authz-object-level:zz-capped-critical',
      'proof-existence:authz-object-level:aa-ordinary-high',
    ],
    'an operator stopping early under budget must reach the capped Critical first',
  )
})

test('proof selection indexes 4,096 findings once and preserves deterministic priority', () => {
  const source = Array.from({ length: 4096 }, (_, index) => triaged({
    candidate_id: `component:${String(index).padStart(4, '0')}`,
    claimed_impact_severity: 'Medium',
    effective_severity: 'Medium',
  }))
  source.push(triaged({
    candidate_id: 'chain:critical',
    claimed_impact_severity: 'Medium',
    effective_severity: 'Critical',
    triage_disposition: 'elevated',
    raised_by: 'attack-chaining',
    component_finding_ids: ['component:4095', 'chain:critical'],
  }))
  let iterations = 0
  const findings = new Proxy(source, {
    get(target, property, receiver) {
      if (property === Symbol.iterator) {
        return function * boundedFindingIterator() {
          iterations += 1
          if (iterations > 1) {
            throw new Error('proof selection repeatedly rescanned the finding array')
          }
          yield * target
        }
      }
      return Reflect.get(target, property, receiver)
    },
  })
  const jobs = source
    .slice(0, 4096)
    .map((finding) => ({
      job_id: `proof-existence:${finding.candidate_id}`,
      candidate_ids: [finding.candidate_id],
    }))
    .reverse()

  const ordered = jobs.sort(createProofJobComparator({ findings }))
  assert.equal(ordered[0].candidate_ids[0], 'component:4095')
  assert.equal(iterations, 1)
})

test('N findings dispatch as candidate-bound proof waves with a global existence barrier', () => {
  const count = 7
  let { run, triagedFindings } = runManyToProof(count)
  const existenceJobs = run.jobs.filter(({ job_id: jobId }) =>
    jobId.startsWith('proof-existence:'))

  assert.equal(existenceJobs.length, count)
  assert.ok(existenceJobs.every(({ state }) => state === 'PENDING'))
  assert.deepEqual(
    existenceJobs.map(({ candidate_ids: candidateIds }) => candidateIds),
    triagedFindings.map(({ candidate_id: candidateId }) => [candidateId]),
  )
  assert.deepEqual(
    pendingJobsForCurrentPhase(run).map(({ job_id: jobId }) => jobId),
    existenceJobs.map(({ job_id: jobId }) => jobId),
    'next must expose the complete independent existence wave',
  )

  const forged = structuredClone(run)
  const forgedCandidateId = triagedFindings[0].candidate_id
  const forgedVerificationId = `proof-verification:${forgedCandidateId}`
  forged.jobs.push({
    job_id: forgedVerificationId,
    kind: 'PROOF',
    state: 'PENDING',
    candidate_ids: [forgedCandidateId],
  })
  assert.ok(validateRun(forged).errors.some(
    ({ code }) => code === 'PROOF_VERIFICATION_BEFORE_EXISTENCE_WAVE',
  ))
  assert.throws(
    () => beginJob(forged, forgedVerificationId),
    /must wait for every existence result in its proof wave to commit/,
  )

  for (const finding of [...triagedFindings].reverse()) {
    const jobId = `proof-existence:${finding.candidate_id}`
    run = beginJob(run, jobId)
    run = applyJobResult(run, jobResult(run, jobId, {
      findings: [addExistence(finding)],
    }))
    const advanced = advanceRun(run)
    run = advanced.run
    const unfinishedExistence = run.jobs.some((job) =>
      job.job_id.startsWith('proof-existence:') && job.state !== 'SUCCEEDED')
    if (unfinishedExistence) {
      assert.equal(advanced.advanced, false)
      assert.equal(
        run.jobs.some(({ job_id: candidateJobId }) =>
          candidateJobId.startsWith('proof-verification:')),
        false,
      )
    } else {
      assert.equal(advanced.advanced, true)
    }
  }

  const verificationJobs = run.jobs.filter(({ job_id: jobId }) =>
    jobId.startsWith('proof-verification:'))
  assert.equal(verificationJobs.length, count)
  assert.ok(verificationJobs.every(({ state }) => state === 'PENDING'))
  assert.deepEqual(
    verificationJobs.map(({ candidate_ids: candidateIds }) => candidateIds),
    triagedFindings.map(({ candidate_id: candidateId }) => [candidateId]),
  )
  assert.deepEqual(
    pendingJobsForCurrentPhase(run).map(({ job_id: jobId }) => jobId),
    verificationJobs.map(({ job_id: jobId }) => jobId),
    'next must expose the complete independent verification wave',
  )

  const lastVerification = verificationJobs.at(-1)
  assert.doesNotThrow(() => beginJob(run, lastVerification.job_id))
})

test('an unauthenticated provider drop cannot remove a candidate from proof scheduling', () => {
  let run = beginJob(plannedRun(), 'lens:web-and-api')
  run = applyJobResult(run, jobResult(run, 'lens:web-and-api', {
    examined_files: ['src/routes/invoices.ts'],
    findings: [stageOne()],
  }), { sidecar: lensSidecar })
  ;({ run } = advanceRun(run))
  run = beginJob(run, 'triage:business-logic')
  run = applyJobResult(run, jobResult(run, 'triage:business-logic', {
    findings: [triaged({
      triage_disposition: 'dropped',
      drop_reason: 'provider claims the route is unreachable',
    })],
  }))
  ;({ run } = advanceRun(run))

  assert.equal(run.findings[0].triage_authority, 'UNAUTHENTICATED_PROVIDER_ASSERTION')
  assert.ok(run.jobs.some(({ job_id: jobId, state }) =>
    jobId === 'proof-existence:authz-object-level:a3f19c2e'
    && state === 'PENDING'))
})

test('one failed existence result fails an N-finding proof wave before verification', () => {
  let { run } = runManyToProof(5)
  const failed = run.jobs.filter(({ job_id: jobId }) =>
    jobId.startsWith('proof-existence:'))[2]
  run = beginJob(run, failed.job_id)
  run = applyJobResult(run, failedJobResult(run, failed.job_id))
  run = advanceRun(run).run

  assert.equal(run.state, 'FAILED')
  assert.equal(run.phase, 'FINALIZED')
  assert.equal(
    run.jobs.some(({ job_id: jobId }) =>
      jobId.startsWith('proof-verification:')),
    false,
  )
  assert.ok(run.jobs
    .filter(({ job_id: jobId }) => jobId.startsWith('proof-existence:'))
    .every(({ state }) => ['FAILED', 'SKIPPED'].includes(state)))
})

test('full provider-neutral state machine reaches a validated static final report', () => {
  let run = plannedRun()

  run = beginJob(run, 'lens:web-and-api')
  assert.equal(run.state, 'RUNNING')
  assert.equal(run.phase, 'FANOUT')
  run = applyJobResult(run, jobResult(run, 'lens:web-and-api', {
    examined_files: ['src/routes/invoices.ts'],
    findings: [stageOne()],
  }), { sidecar: lensSidecar })
  assert.equal(run.coverage.examined[0], 'src/routes/invoices.ts')
  assert.equal(run.findings.length, 1)

  ;({ run } = advanceRun(run))
  assert.equal(run.phase, 'TRIAGE')
  run = beginJob(run, 'triage:business-logic')
  run = applyJobResult(run, jobResult(run, 'triage:business-logic', {
    findings: [triaged()],
  }))

  ;({ run } = advanceRun(run))
  assert.equal(run.phase, 'PROOF')
  assert.ok(run.jobs.some(
    ({ job_id }) => job_id === 'proof-existence:authz-object-level:a3f19c2e',
  ))
  run = beginJob(run, 'proof-existence:authz-object-level:a3f19c2e')
  run = applyJobResult(run, jobResult(
    run,
    'proof-existence:authz-object-level:a3f19c2e',
    { findings: [withExistence()] },
  ))
  ;({ run } = advanceRun(run))
  assert.equal(run.phase, 'PROOF')
  assert.ok(run.jobs.some(
    ({ job_id }) => job_id === 'proof-verification:authz-object-level:a3f19c2e',
  ))
  run = beginJob(run, 'proof-verification:authz-object-level:a3f19c2e')
  run = applyJobResult(run, jobResult(run, 'proof-verification:authz-object-level:a3f19c2e', {
    findings: [staticProof()],
  }))
  assert.equal(
    run.findings[0].verification_authority,
    'UNAUTHENTICATED_PROVIDER_ASSERTION',
  )

  ;({ run } = advanceRun(run))
  assert.equal(run.phase, 'PATCH')
  assert.equal(run.jobs.find(({ kind }) => kind === 'PATCH').state, 'SKIPPED')
  ;({ run } = advanceRun(run))
  assert.equal(run.phase, 'REPORT')
  ;({ run } = advanceRun(run))
  assert.equal(run.phase, 'COMPLETENESS')

  run = beginJob(run, 'completeness:completeness')
  run = applyJobResult(run, jobResult(run, 'completeness:completeness'))
  const finalized = buildFinalizedRun(run, {
    completedAt: new Date('2026-07-28T20:10:00Z'),
  })
  assert.equal(finalized.run.state, 'COMPLETED')
  assert.equal(finalized.run.phase, 'FINALIZED')
  assert.equal(finalized.run.jobs.find(({ kind }) => kind === 'REPORT').state, 'SUCCEEDED')
  assert.match(finalized.report, /Invoice route loads/)
  assert.match(finalized.sarif, /authz-object-level/)
  assert.deepEqual(JSON.parse(finalized.coverage), finalized.run.coverage)
  assert.equal(finalized.run.artifacts.coverage.path, 'coverage.json')
  assert.equal(Object.isFrozen(finalized.run), true)
})

test('a lens cannot smuggle proof fields into fan-out', () => {
  let run = beginJob(plannedRun(), 'lens:web-and-api')
  assert.throws(
    () => applyJobResult(run, jobResult(run, 'lens:web-and-api', {
      examined_files: ['src/routes/invoices.ts'],
      findings: [staticProof()],
    }), { sidecar: lensSidecar }),
    /Stage 3 fields but Stage 1 was required/,
  )
})

test('out-of-scope reads and silently skipped scoped files cannot clear coverage', () => {
  let run = beginJob(plannedRun(), 'lens:web-and-api')
  assert.throws(
    () => applyJobResult(run, jobResult(run, 'lens:web-and-api', {
      examined_files: ['secrets/outside.txt'],
    }), { sidecar: lensSidecar }),
    /outside inventory/,
  )

  run = applyJobResult(run, jobResult(run, 'lens:web-and-api'), {
    sidecar: lensSidecar,
  })
  assert.equal(run.coverage.unexamined.length, 1)
  assert.ok(run.coverage.gaps.some(({ reason }) => /did not report/.test(reason)))
})

test('a failed job is preserved as structured run evidence', () => {
  let run = beginJob(plannedRun(), 'lens:web-and-api')
  run = applyJobResult(run, jobResult(run, 'lens:web-and-api', {
    state: 'FAILED',
    error: {
      code: 'PROVIDER_TIMEOUT',
      message: 'provider exceeded its bounded job deadline',
      recoverable: true,
    },
  }), { sidecar: lensSidecar })
  assert.equal(run.jobs[0].state, 'FAILED')
  assert.equal(run.coverage.lenses[0].status, 'FAILED')
  assert.equal(run.errors[0].code, 'PROVIDER_TIMEOUT')
})

test('a required triage failure terminates FAILED without inventing a disposition', () => {
  let run = beginJob(plannedRun(), 'lens:web-and-api')
  run = applyJobResult(run, jobResult(run, 'lens:web-and-api', {
    examined_files: ['src/routes/invoices.ts'],
    findings: [stageOne()],
  }), { sidecar: lensSidecar })
  ;({ run } = advanceRun(run))

  run = beginJob(run, 'triage:business-logic')
  run = applyJobResult(run, failedJobResult(run, 'triage:business-logic'))
  const providerError = structuredClone(run.errors[0])
  const result = advanceRun(run)
  run = result.run

  assert.equal(result.advanced, true)
  assert.equal(run.state, 'FAILED')
  assert.equal(run.phase, 'FINALIZED')
  assert.equal(Number.isNaN(Date.parse(run.completed_at)), false)
  assert.deepEqual(run.errors[0], providerError)
  assert.equal(run.errors[1].code, 'REQUIRED_TRIAGE_JOB_FAILED')
  assert.equal(run.errors[1].recoverable, false)
  assert.equal(run.findings[0].triage_disposition, undefined)
  assert.equal(
    run.jobs.find(({ job_id }) => job_id === 'completeness:completeness').state,
    'SKIPPED',
  )
  assert.equal(run.jobs.every(({ state }) =>
    ['SUCCEEDED', 'SKIPPED', 'FAILED'].includes(state)), true)
  assert.deepEqual(advanceRun(run), { advanced: false, run })
})

test('a failed existence proof terminates FAILED before verification is scheduled', () => {
  let run = runToProof()
  const jobId = `proof-existence:${stageOne().candidate_id}`
  run = beginJob(run, jobId)
  run = applyJobResult(run, failedJobResult(run, jobId))
  const providerError = structuredClone(run.errors[0])
  run = advanceRun(run).run

  assert.equal(run.state, 'FAILED')
  assert.equal(run.phase, 'FINALIZED')
  assert.deepEqual(run.errors[0], providerError)
  assert.equal(run.errors[1].code, 'REQUIRED_PROOF_JOB_FAILED')
  assert.equal(run.findings[0].existence_check, undefined)
  assert.equal(
    run.jobs.some(({ job_id }) => job_id.startsWith('proof-verification:')),
    false,
  )
  assert.equal(
    run.jobs.find(({ job_id }) => job_id === 'completeness:completeness').state,
    'SKIPPED',
  )
})

test('a failed verification proof preserves existence evidence and terminates FAILED', () => {
  let run = runToProof()
  const candidateId = stageOne().candidate_id
  const existenceJobId = `proof-existence:${candidateId}`
  run = beginJob(run, existenceJobId)
  run = applyJobResult(run, jobResult(run, existenceJobId, {
    findings: [withExistence()],
  }))
  ;({ run } = advanceRun(run))

  const verificationJobId = `proof-verification:${candidateId}`
  run = beginJob(run, verificationJobId)
  run = applyJobResult(run, failedJobResult(run, verificationJobId))
  const existenceEvidence = structuredClone(run.findings[0].existence_check)
  run = advanceRun(run).run

  assert.equal(run.state, 'FAILED')
  assert.equal(run.phase, 'FINALIZED')
  assert.deepEqual(run.findings[0].existence_check, existenceEvidence)
  assert.equal(run.findings[0].verification_status, undefined)
  assert.equal(run.errors.at(-1).code, 'REQUIRED_PROOF_JOB_FAILED')
  assert.equal(run.jobs.some(({ kind }) => kind === 'PATCH'), false)
})

test('a verification proof cannot consume its job without recording a decision', () => {
  let run = runToProof()
  const candidateId = stageOne().candidate_id
  const existenceJobId = `proof-existence:${candidateId}`
  run = beginJob(run, existenceJobId)
  run = applyJobResult(run, jobResult(run, existenceJobId, {
    findings: [withExistence()],
  }))
  ;({ run } = advanceRun(run))

  const verificationJobId = `proof-verification:${candidateId}`
  run = beginJob(run, verificationJobId)
  assert.throws(
    () => applyJobResult(run, jobResult(run, verificationJobId, {
      findings: [withExistence()],
    })),
    /must add proof_tier and verification_status/,
  )
  assert.equal(
    run.jobs.find(({ job_id: jobId }) => jobId === verificationJobId).state,
    'RUNNING',
  )
  assert.equal(run.findings[0].verification_status, undefined)
})

test('a provider cannot self-assign verification authority', () => {
  let run = runToProof()
  const candidateId = stageOne().candidate_id
  const existenceJobId = `proof-existence:${candidateId}`
  run = beginJob(run, existenceJobId)
  run = applyJobResult(run, jobResult(run, existenceJobId, {
    findings: [withExistence()],
  }))
  ;({ run } = advanceRun(run))

  const verificationJobId = `proof-verification:${candidateId}`
  run = beginJob(run, verificationJobId)
  assert.throws(
    () => applyJobResult(run, jobResult(run, verificationJobId, {
      findings: [staticProof({
        verification_status: 'CONFIRMED',
        verification_authority: 'UNAUTHENTICATED_PROVIDER_ASSERTION',
      })],
    })),
    /providers cannot supply or change .*verification_authority/,
  )
  assert.equal(run.findings[0].verification_status, undefined)
})

const INVENTORY_ENTRIES = [{
  path: 'src/routes/invoices.ts',
  kind: 'text',
  content: 'import x\nconst invoice = await repo.findById(req.params.id)\n',
  sha256: null,
}]

test('applyJobResult records existence verdicts once inventory entries are supplied', () => {
  const verified = stageOne({
    quotes: [{
      path: 'src/routes/invoices.ts',
      line: 2,
      text: 'const invoice = await repo.findById(req.params.id)',
    }],
  })
  const unverified = stageOne({
    candidate_id: 'authz-object-level:fabricated',
    quotes: [{
      path: 'src/routes/invoices.ts',
      line: 2,
      text: 'this text was never in the file',
    }],
  })

  let run = beginJob(plannedRun(), 'lens:web-and-api')
  run = applyJobResult(run, jobResult(run, 'lens:web-and-api', {
    examined_files: ['src/routes/invoices.ts'],
    findings: [verified, unverified],
  }), {
    sidecar: lensSidecar,
    inventoryEntries: INVENTORY_ENTRIES,
    deferTransitionValidation: true,
  })

  assert.equal(run.existence_verifications.length, 2)
  const byCandidate = new Map(
    run.existence_verifications.map((row) => [row.candidate_id, row]),
  )
  assert.equal(byCandidate.get(verified.candidate_id).outcome, 'VERIFIED')
  assert.equal(byCandidate.get(unverified.candidate_id).outcome, 'UNVERIFIED')
  assert.deepEqual(
    run.existence_verifications.map((row) => row.candidate_id),
    [...byCandidate.keys()].sort(),
    'existence_verifications must be sorted by candidate_id',
  )
})

test('independent proof-existence jobs accumulate existence verdicts without clobbering siblings', () => {
  let { run, triagedFindings } = runManyToProof(2)
  const [first, second] = triagedFindings
  const jobIdFirst = `proof-existence:${first.candidate_id}`
  const jobIdSecond = `proof-existence:${second.candidate_id}`

  // Both existence jobs are begun before either result is applied: applyJobResult's
  // deferTransitionValidation:true (used below, purely to isolate this accumulation
  // behavior from the separately-tested v7-schema-version gate — see
  // test/existence-schema-version.test.mjs) only skips the *next* applyJobResult
  // transition's own schema check, not a later, non-deferred beginJob's. Starting a
  // second existence job while a sibling is already RUNNING is valid: independent
  // proof-existence jobs form one wave and assertProofWaveReady only blocks an
  // existence job once its wave's verification jobs have been scheduled.
  run = beginJob(run, jobIdFirst)
  run = beginJob(run, jobIdSecond)

  run = applyJobResult(run, jobResult(run, jobIdFirst, {
    findings: [addExistence(first)],
  }), { inventoryEntries: INVENTORY_ENTRIES, deferTransitionValidation: true })

  assert.equal(run.existence_verifications.length, 1)
  assert.equal(run.existence_verifications[0].candidate_id, first.candidate_id)
  assert.equal(run.existence_verifications[0].outcome, 'NOT_APPLICABLE')

  run = applyJobResult(run, jobResult(run, jobIdSecond, {
    findings: [addExistence(second)],
  }), { inventoryEntries: INVENTORY_ENTRIES, deferTransitionValidation: true })

  assert.equal(
    run.existence_verifications.length, 2,
    'the first candidate verdict must survive the second job result',
  )
  assert.deepEqual(
    run.existence_verifications.map((row) => row.candidate_id).sort(),
    [first.candidate_id, second.candidate_id].sort(),
  )
})
