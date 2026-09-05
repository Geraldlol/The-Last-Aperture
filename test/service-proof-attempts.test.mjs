import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  classifyServiceProofAttemptRecovery,
  commitServiceProofAttempt,
  failProviderAttempt,
  failServiceProofAttempt,
  hashAttemptEvent,
  leaseServiceProofAttempt,
  markServiceProofAttemptStarted,
  recordServiceProofResultCaptured,
  recordServiceProofResultValidated,
  recoverExpiredServiceProofAttempt,
} from '../scripts/lib/attempts.mjs'
import { validateRun } from '../scripts/lib/contracts.mjs'
import { buildCategoryDenominators } from '../scripts/lib/coverage-model.mjs'
import { discoverDatabaseGraph } from '../scripts/lib/database-discovery.mjs'

const SHA_A = 'a'.repeat(64)
const SHA_B = 'b'.repeat(64)
const SHA_C = 'c'.repeat(64)
const SHA_D = 'd'.repeat(64)
const SHA_E = 'e'.repeat(64)
const SHA_F = 'f'.repeat(64)

function findingFixture(overrides = {}) {
  return {
    candidate_id: 'candidate:service-proof',
    lens: 'web-and-api',
    topic: 'authz-object-level',
    title: 'Service route accepts another tenant identifier',
    claimed_impact_severity: 'High',
    location: ['src/app.mjs:1'],
    cwe: 'CWE-639',
    evidence: 'const record = await repository.findById(request.id)',
    attack: 'Request another tenant record through the loopback service',
    impact: 'Reads another tenant record',
    reachable_from: 'POST /records',
    confidence: 'High',
    proof_plan: 'Boot the sealed service and compare attack and control probes',
    effective_severity: 'High',
    triage_disposition: 'queued',
    existence_check: {
      status: 'located',
      method: 'matched the cited source in the sealed snapshot',
    },
    ...overrides,
  }
}

function runFixture() {
  return {
    schema_version: '7.0.0',
    run_id: 'run:service-proof-attempt-contract',
    state: 'RUNNING',
    phase: 'PROOF',
    capability_mode: 'LOCAL_DYNAMIC',
    created_at: '2026-09-04T10:00:00Z',
    tool: {
      name: 'red-team-audit',
      version: '0.3.0',
      corpus_sha256: SHA_F,
    },
    plan_digest: SHA_A,
    policy_digest: SHA_B,
    lens_pack_digest: SHA_C,
    repository: {
      root: 'C:/workspace/example',
      tree_digest: SHA_D,
      dirty: 'unknown',
    },
    scope: {
      included_paths: ['src'],
      excluded_paths: [],
    },
    activated_lenses: ['web-and-api'],
    jobs: [{
      job_id: 'proof-verification:candidate:service-proof',
      kind: 'PROOF',
      state: 'PENDING',
      candidate_ids: ['candidate:service-proof'],
    }, {
      job_id: 'proof-existence:candidate:service-proof',
      kind: 'PROOF',
      state: 'SUCCEEDED',
      candidate_ids: ['candidate:service-proof'],
      input_sha256: SHA_A,
      producer: {
        name: 'red-team-audit-proof-controller',
        version: '0.3.0',
        instance_id: 'run-proof:controller',
      },
      coverage_authority: 'PROVIDER_DECLARED',
    }],
    coverage: {
      model_version: '2.0.0',
      policy: {
        require_source_closure: false,
        max_shard_files: 64,
        max_shard_bytes: 4_194_304,
        max_requeue_rounds: 3,
      },
      inventory: [],
      inventory_records: [],
      examined: [],
      unexamined: [],
      lenses: [{
        lens: 'web-and-api',
        status: 'NOT_ASSESSED',
        applicable_paths: [],
        examined_paths: [],
        reason: 'awaiting service proof execution',
      }],
      gaps: [],
      denominators: buildCategoryDenominators([], []),
      shards: [],
      resolved_gap_ids: [],
      closure: {
        required_source_closure: false,
        max_rounds: 3,
        round: 0,
        status: 'PENDING',
        history: [],
      },
    },
    database_discovery: discoverDatabaseGraph([]),
    evidence_declarations: {},
    evidence_bundles: [],
    evidence_coverage: {
      cells: [],
      bundle_coverage: [],
      summary: {
        cell_count: 0,
        bundle_count: 0,
        unreached_class_count: 0,
        unreached_classes: [],
        not_assessed_cell_count: 0,
        inventory_only_cell_count: 0,
      },
    },
    store_contributions: [],
    store_profiles: [],
    findings: [findingFixture()],
    errors: [],
    artifacts: {
      source_index: {
        path: 'snapshots/source.index.json',
        sha256: SHA_A,
      },
      control_index: {
        path: 'snapshots/control.index.json',
        sha256: SHA_B,
      },
    },
    source_snapshot: {
      kind: 'SOURCE',
      index_artifact_key: 'source_index',
      root_sha256: SHA_C,
      available_files: 1,
      available_bytes: 19,
    },
    control_snapshot: {
      kind: 'CONTROL',
      index_artifact_key: 'control_index',
      root_sha256: SHA_D,
      available_files: 2,
      available_bytes: 100,
    },
    attempt_events: [],
  }
}

const SERVICE_CONTAINER_NAMES = Object.freeze({
  attack: 'rta-proof-service-attack-test-0001',
  control: 'rta-proof-service-control-test-0001',
})

const SERVICE_SESSION_BUDGET = Object.freeze({
  attack_controller_wall_clock_ms: 120_000,
  control_controller_wall_clock_ms: 120_000,
  capture_grace_ms: 30_000,
  controller_wall_clock_ms: 270_000,
})

function lease(run = runFixture(), overrides = {}) {
  return leaseServiceProofAttempt(
    run,
    'proof-verification:candidate:service-proof',
    {
    attempt_id: 'attempt:service-proof-0001',
    occurred_at: '2026-09-04T10:00:01Z',
    nonce: SHA_E,
    packet_sha256: SHA_A,
    proof_config_sha256: SHA_B,
    proof_worker_config_sha256: SHA_C,
    service_container_names: SERVICE_CONTAINER_NAMES,
    service_session_budget: SERVICE_SESSION_BUDGET,
      ...overrides,
    },
  )
}

test('service-proof lease durably binds both exact containers, configs, provenance, and two-session budget', () => {
  const leased = lease()
  const event = leased.attempt_events[0]

  assert.equal(validateRun(leased).valid, true)
  assert.equal(leased.jobs[0].state, 'RUNNING')
  assert.equal(event.backend, 'SERVICE_PROOF_CONTAINER')
  assert.deepEqual(event.service_container_names, SERVICE_CONTAINER_NAMES)
  assert.deepEqual(event.service_session_budget, SERVICE_SESSION_BUDGET)
  assert.equal(event.proof_config_sha256, SHA_B)
  assert.equal(event.proof_worker_config_sha256, SHA_C)
  assert.equal(event.packet_sha256, SHA_A)
  assert.equal(event.source_snapshot_sha256, SHA_C)
  assert.equal(event.control_snapshot_sha256, SHA_D)
  assert.equal(event.policy_sha256, SHA_B)
  assert.equal(event.expires_at, '2026-09-04T10:04:31.000Z')
})

test('service-proof leases reject ambiguous containers and budgets that understate controller time', () => {
  assert.throws(
    () => lease(runFixture(), {
      service_container_names: {
        attack: SERVICE_CONTAINER_NAMES.attack,
        control: SERVICE_CONTAINER_NAMES.attack,
      },
    }),
    /attack and control container names must be distinct/,
  )
  assert.throws(
    () => lease(runFixture(), {
      service_session_budget: {
        ...SERVICE_SESSION_BUDGET,
        controller_wall_clock_ms: 240_000,
      },
    }),
    /controller_wall_clock_ms must equal attack, control, and capture budgets/,
  )
  assert.throws(
    () => lease(runFixture(), {
      expires_at: '2026-09-04T10:04:30.999Z',
    }),
    /expires_at must equal the complete service-proof controller budget/,
  )
  assert.throws(
    () => lease(runFixture(), {
      expires_at: '2026-09-04T10:04:31.001Z',
    }),
    /expires_at must equal the complete service-proof controller budget/,
  )
})

test('expired LEASED service proofs recover without Docker cleanup and permit a fresh lease', () => {
  const leased = lease()
  assert.equal(
    classifyServiceProofAttemptRecovery(leased, 'attempt:service-proof-0001', {
      now: '2026-09-04T10:04:30.999Z',
    }).status,
    'ACTIVE_UNEXPIRED',
  )

  const classification = classifyServiceProofAttemptRecovery(
    leased,
    'attempt:service-proof-0001',
    { now: '2026-09-04T10:04:31Z' },
  )
  assert.equal(classification.status, 'EXPIRED_LEASED')
  assert.equal(classification.cleanup_required, false)
  assert.deepEqual(classification.service_container_names, SERVICE_CONTAINER_NAMES)

  const recovered = recoverExpiredServiceProofAttempt(
    leased,
    'attempt:service-proof-0001',
    { occurred_at: '2026-09-04T10:04:31Z' },
  )
  assert.equal(recovered.jobs[0].state, 'PENDING')
  assert.equal(recovered.attempt_events.at(-1).event, 'FAILED')
  assert.equal(recovered.attempt_events.at(-1).recoverable, true)

  const retried = lease(recovered, {
    attempt_id: 'attempt:service-proof-0002',
    occurred_at: '2026-09-04T10:04:32Z',
    nonce: SHA_F,
    service_container_names: {
      attack: 'rta-proof-service-attack-test-0002',
      control: 'rta-proof-service-control-test-0002',
    },
  })
  assert.equal(retried.attempt_events.at(-1).attempt_id, 'attempt:service-proof-0002')
})

test('expired STARTED recovery requires verification of both bound names and fails closed on ambiguity', () => {
  const started = markServiceProofAttemptStarted(
    lease(),
    'attempt:service-proof-0001',
    { occurred_at: '2026-09-04T10:00:02Z' },
  )
  const classification = classifyServiceProofAttemptRecovery(
    started,
    'attempt:service-proof-0001',
    { now: '2026-09-04T10:04:31Z' },
  )
  assert.equal(classification.status, 'EXPIRED_STARTED')
  assert.equal(classification.cleanup_required, true)
  assert.deepEqual(classification.service_container_names, SERVICE_CONTAINER_NAMES)

  assert.throws(
    () => recoverExpiredServiceProofAttempt(
      started,
      'attempt:service-proof-0001',
      { occurred_at: '2026-09-04T10:04:31Z' },
    ),
    /cleanup_verified must be a boolean/,
  )
  assert.throws(
    () => recoverExpiredServiceProofAttempt(
      started,
      'attempt:service-proof-0001',
      {
        occurred_at: '2026-09-04T10:04:31Z',
        cleanup_verified: true,
        service_container_names: {
          attack: SERVICE_CONTAINER_NAMES.attack,
          control: 'rta-proof-service-wrong-control',
        },
      },
    ),
    /cleanup must bind the exact leased service container names/,
  )

  const recoverable = recoverExpiredServiceProofAttempt(
    started,
    'attempt:service-proof-0001',
    {
      occurred_at: '2026-09-04T10:04:31Z',
      cleanup_verified: true,
      service_container_names: SERVICE_CONTAINER_NAMES,
    },
  )
  assert.equal(recoverable.jobs[0].state, 'PENDING')
  assert.equal(recoverable.attempt_events.at(-1).recoverable, true)
  assert.equal(recoverable.attempt_events.at(-1).cleanup_verified, true)
  assert.deepEqual(
    recoverable.attempt_events.at(-1).service_container_names,
    SERVICE_CONTAINER_NAMES,
  )

  const ambiguous = recoverExpiredServiceProofAttempt(
    started,
    'attempt:service-proof-0001',
    {
      occurred_at: '2026-09-04T10:04:31Z',
      cleanup_verified: false,
      service_container_names: SERVICE_CONTAINER_NAMES,
    },
  )
  assert.equal(ambiguous.jobs[0].state, 'FAILED')
  assert.equal(ambiguous.attempt_events.at(-1).recoverable, false)
  assert.equal(ambiguous.attempt_events.at(-1).cleanup_verified, false)
  assert.deepEqual(
    ambiguous.attempt_events.at(-1).service_container_names,
    SERVICE_CONTAINER_NAMES,
  )
})

test('captured service-proof results are resumable and commit without a second launch', () => {
  const started = markServiceProofAttemptStarted(
    lease(),
    'attempt:service-proof-0001',
    { occurred_at: '2026-09-04T10:00:02Z' },
  )
  const captured = recordServiceProofResultCaptured(
    started,
    'attempt:service-proof-0001',
    {
      occurred_at: '2026-09-04T10:00:03Z',
      execution_artifact_key: 'execution_service_proof_0001',
      execution_artifact: {
        path: 'proofs/service-proof-0001.json',
        sha256: SHA_E,
      },
      receipt_sha256: SHA_E,
    },
  )
  const recovery = classifyServiceProofAttemptRecovery(
    captured,
    'attempt:service-proof-0001',
    { now: '2026-09-05T10:00:00Z' },
  )
  assert.equal(recovery.status, 'RESUMABLE')
  assert.equal(recovery.cleanup_required, false)

  const validated = recordServiceProofResultValidated(
    captured,
    'attempt:service-proof-0001',
    { occurred_at: '2026-09-04T10:00:04Z' },
  )
  const candidate = structuredClone(validated)
  candidate.jobs[0] = {
    ...candidate.jobs[0],
    state: 'SUCCEEDED',
    input_sha256: SHA_A,
    producer: {
      name: 'red-team-audit-service-proof-controller',
      version: '0.3.0',
      instance_id: 'run-service-proof:controller',
    },
  }
  candidate.findings[0] = {
    ...candidate.findings[0],
    proof_tier: 'T1',
    verification_status: 'CONFIRMED',
    artifact: {
      path: 'proofs/service-proof-0001.json',
      sha256: SHA_E,
    },
    command: 'node test/security/attack.mjs',
    pre_result: {
      assertion: 'attack reproduced and the control remained clean',
      path_reached: 'sealed loopback service route handled both probes',
      control: 'control probe exited successfully',
      control_status: 'passed',
    },
    post_result: {
      status: 'passed',
      regressions: 'service-proof protocol fixture completed',
    },
  }
  const committed = commitServiceProofAttempt(
    validated,
    candidate,
    'attempt:service-proof-0001',
    { occurred_at: '2026-09-04T10:00:05Z' },
  )

  assert.equal(validateRun(committed).valid, true)
  assert.equal(committed.attempt_events.at(-1).event, 'COMMITTED')
  assert.equal(committed.jobs[0].attempt_id, 'attempt:service-proof-0001')
  assert.equal(committed.jobs[0].coverage_authority, 'CONTROLLER_OBSERVED_CONSUMPTION')
})

test('service-proof leases reject non-verification jobs and multi-candidate jobs', () => {
  const wrongKind = runFixture()
  wrongKind.jobs.push({
    job_id: 'proof-other:candidate:wrong-service-proof',
    kind: 'PROOF',
    state: 'PENDING',
    candidate_ids: ['candidate:service-proof'],
  })
  assert.throws(
    () => leaseServiceProofAttempt(
      wrongKind,
      'proof-other:candidate:wrong-service-proof',
      {
      packet_sha256: SHA_A,
      },
    ),
    /not a proof-verification PROOF job/,
  )
  assert.throws(
    () => leaseServiceProofAttempt(
      runFixture(),
      'proof-existence:candidate:service-proof',
      { packet_sha256: SHA_A },
    ),
    /not a proof-verification PROOF job/,
  )

  const multipleCandidates = runFixture()
  for (const job of multipleCandidates.jobs) {
    job.candidate_ids = ['candidate:service-proof', 'candidate:other']
  }
  multipleCandidates.findings.push(findingFixture({
    candidate_id: 'candidate:other',
  }))
  assert.throws(
    () => lease(multipleCandidates),
    /must name exactly one candidate/,
  )
})

test('service-proof capture requires the receipt to be its execution artifact', () => {
  const started = markServiceProofAttemptStarted(
    lease(),
    'attempt:service-proof-0001',
    { occurred_at: '2026-09-04T10:00:02Z' },
  )
  assert.throws(
    () => recordServiceProofResultCaptured(
      started,
      'attempt:service-proof-0001',
      {
        occurred_at: '2026-09-04T10:00:03Z',
        execution_artifact_key: 'execution_service_proof_0001',
        execution_artifact: {
          path: 'proofs/service-proof-0001.json',
          sha256: SHA_E,
        },
        receipt_sha256: SHA_F,
      },
    ),
    /receipt_sha256 must equal execution_artifact.sha256/,
  )
})

test('ordinary and generic failure APIs cannot make a service-proof attempt retryable', () => {
  const started = markServiceProofAttemptStarted(
    lease(),
    'attempt:service-proof-0001',
    { occurred_at: '2026-09-04T10:00:02Z' },
  )
  assert.throws(
    () => failServiceProofAttempt(started, 'attempt:service-proof-0001', {
      occurred_at: '2026-09-04T10:00:03Z',
      reason: 'controller interrupted',
      recoverable: true,
    }),
    /ordinary service-proof failures are terminal-only/,
  )
  assert.throws(
    () => failServiceProofAttempt(started, 'attempt:service-proof-0001', {
      occurred_at: '2026-09-04T10:00:03Z',
      reason: 'controller interrupted after claimed cleanup',
      recoverable: true,
      cleanup_verified: true,
      service_container_names: SERVICE_CONTAINER_NAMES,
    }),
    /ordinary service-proof failures are terminal-only/,
  )
  assert.throws(
    () => failProviderAttempt(started, 'attempt:service-proof-0001', {
      occurred_at: '2026-09-04T10:00:03Z',
      reason: 'generic retry bypass',
      recoverable: true,
    }),
    /generic provider failure cannot mutate a service-proof attempt/,
  )

  const failed = failServiceProofAttempt(
    started,
    'attempt:service-proof-0001',
    {
      occurred_at: '2026-09-04T10:00:03Z',
      reason: 'ordinary terminal service failure',
    },
  )
  assert.equal(failed.jobs[0].state, 'FAILED')
  assert.equal(failed.attempt_events.at(-1).recoverable, false)
})

test('service-proof failures cannot discard captured or validated results', () => {
  const started = markServiceProofAttemptStarted(
    lease(),
    'attempt:service-proof-0001',
    { occurred_at: '2026-09-04T10:00:02Z' },
  )
  const captured = recordServiceProofResultCaptured(
    started,
    'attempt:service-proof-0001',
    {
      occurred_at: '2026-09-04T10:00:03Z',
      execution_artifact_key: 'execution_service_proof_0001',
      execution_artifact: {
        path: 'proofs/service-proof-0001.json',
        sha256: SHA_E,
      },
      receipt_sha256: SHA_E,
    },
  )
  for (const run of [
    captured,
    recordServiceProofResultValidated(
      captured,
      'attempt:service-proof-0001',
      { occurred_at: '2026-09-04T10:00:04Z' },
    ),
  ]) {
    assert.throws(
      () => failServiceProofAttempt(run, 'attempt:service-proof-0001', {
        occurred_at: '2026-09-04T10:00:05Z',
        reason: 'discard captured result',
        recoverable: false,
      }),
      /captured service-proof results are resume-only/,
    )
  }
})

test('semantic validation rejects forged early, unbound, or captured-state service retries', () => {
  const started = markServiceProofAttemptStarted(
    lease(),
    'attempt:service-proof-0001',
    { occurred_at: '2026-09-04T10:00:02Z' },
  )
  const recovered = recoverExpiredServiceProofAttempt(
    started,
    'attempt:service-proof-0001',
    {
      occurred_at: '2026-09-04T10:04:31Z',
      reason: 'expired service recovery',
      recoverable: true,
      cleanup_verified: true,
      service_container_names: SERVICE_CONTAINER_NAMES,
    },
  )

  const early = structuredClone(recovered)
  early.attempt_events.at(-1).occurred_at = '2026-09-04T10:04:30.999Z'
  early.attempt_events.at(-1).event_sha256 = hashAttemptEvent(
    early.attempt_events.at(-1),
  )
  const earlyValidation = validateRun(early)
  assert.equal(earlyValidation.valid, false)
  assert.equal(earlyValidation.errors.some(
    ({ code }) => code === 'SERVICE_PROOF_RECOVERY_BEFORE_EXPIRY',
  ), true)

  const wrongNames = structuredClone(recovered)
  wrongNames.attempt_events.at(-1).service_container_names.control =
    'rta-proof-service-wrong-control'
  wrongNames.attempt_events.at(-1).event_sha256 = hashAttemptEvent(
    wrongNames.attempt_events.at(-1),
  )
  const wrongNamesValidation = validateRun(wrongNames)
  assert.equal(wrongNamesValidation.valid, false)
  assert.equal(wrongNamesValidation.errors.some(
    ({ code }) => code === 'SERVICE_PROOF_RECOVERY_CONTAINER_NAMES_MISMATCH',
  ), true)

  const noCleanup = structuredClone(recovered)
  delete noCleanup.attempt_events.at(-1).cleanup_verified
  noCleanup.attempt_events.at(-1).event_sha256 = hashAttemptEvent(
    noCleanup.attempt_events.at(-1),
  )
  const noCleanupValidation = validateRun(noCleanup)
  assert.equal(noCleanupValidation.valid, false)
  assert.equal(noCleanupValidation.errors.some(
    ({ code }) => code === 'SERVICE_PROOF_RETRY_WITHOUT_VERIFIED_CLEANUP',
  ), true)

  const captured = recordServiceProofResultCaptured(
    started,
    'attempt:service-proof-0001',
    {
      occurred_at: '2026-09-04T10:00:03Z',
      execution_artifact_key: 'execution_service_proof_0001',
      execution_artifact: {
        path: 'proofs/service-proof-0001.json',
        sha256: SHA_E,
      },
      receipt_sha256: SHA_E,
    },
  )
  const forgedCapturedFailure = structuredClone(captured)
  const failedEvent = {
    sequence: forgedCapturedFailure.attempt_events.length + 1,
    attempt_id: 'attempt:service-proof-0001',
    job_id: 'proof-verification:candidate:service-proof',
    event: 'FAILED',
    occurred_at: '2026-09-04T10:04:31Z',
    reason: 'discard captured result',
    recoverable: true,
    cleanup_verified: true,
    service_container_names: structuredClone(SERVICE_CONTAINER_NAMES),
    previous_event_sha256: forgedCapturedFailure.attempt_events.at(-1).event_sha256,
  }
  failedEvent.event_sha256 = hashAttemptEvent(failedEvent)
  forgedCapturedFailure.attempt_events.push(failedEvent)
  forgedCapturedFailure.jobs[0].state = 'PENDING'
  const capturedFailureValidation = validateRun(forgedCapturedFailure)
  assert.equal(capturedFailureValidation.valid, false)
  assert.equal(capturedFailureValidation.errors.some(
    ({ code }) => code === 'SERVICE_PROOF_CAPTURED_RESULT_MUST_RESUME',
  ), true)
})

test('service-proof attempt backend is exclusive to v7 manifests', () => {
  const legacy = runFixture()
  legacy.schema_version = '6.0.0'
  assert.equal(validateRun(legacy).valid, true)
  assert.throws(
    () => lease(legacy),
    /Observed service-proof attempts require a v7 run/,
  )

  const forged = lease()
  forged.schema_version = '6.0.0'
  const validation = validateRun(forged)
  assert.equal(validation.valid, false)
  assert.equal(validation.errors.some(
    ({ code }) => code === 'SERVICE_PROOF_BACKEND_REQUIRES_V7',
  ), true)
})

test('schema rejects incomplete or cross-backend service-proof leases', () => {
  const missingName = structuredClone(lease())
  delete missingName.attempt_events[0].service_container_names.control
  missingName.attempt_events[0].event_sha256 = hashAttemptEvent(
    missingName.attempt_events[0],
  )
  const missingNameValidation = validateRun(missingName)
  assert.equal(missingNameValidation.valid, false)
  assert.equal(
    missingNameValidation.errors.some(({ code }) => code === 'SCHEMA_REQUIRED'),
    true,
  )
  assert.equal(
    missingNameValidation.errors.some(({ code }) =>
      code === 'ATTEMPT_EVENT_HASH_MISMATCH'),
    false,
  )

  const crossBackend = structuredClone(lease())
  crossBackend.attempt_events[0].container_name = 'rta-provider-container'
  crossBackend.attempt_events[0].event_sha256 = hashAttemptEvent(
    crossBackend.attempt_events[0],
  )
  const crossBackendValidation = validateRun(crossBackend)
  assert.equal(crossBackendValidation.valid, false)
  assert.equal(
    crossBackendValidation.errors.some(({ code }) => code.startsWith('SCHEMA_')),
    true,
  )
  assert.equal(
    crossBackendValidation.errors.some(({ code }) =>
      code === 'ATTEMPT_EVENT_HASH_MISMATCH'),
    false,
  )
})

test('service-proof helpers reject semantically forged budget bindings after rehashing', () => {
  const forged = structuredClone(lease())
  forged.attempt_events[0].service_session_budget.controller_wall_clock_ms -= 1
  forged.attempt_events[0].event_sha256 = hashAttemptEvent(forged.attempt_events[0])

  assert.throws(
    () => classifyServiceProofAttemptRecovery(
      forged,
      'attempt:service-proof-0001',
      { now: '2026-09-04T10:00:02Z' },
    ),
    /controller budget must equal both sessions plus capture grace|controller_wall_clock_ms must equal attack, control, and capture budgets/,
  )
})
