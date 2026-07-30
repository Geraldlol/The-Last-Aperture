import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  classifyProviderAttemptRecovery,
  commitProviderAttempt,
  failProviderAttempt,
  findActiveAttempt,
  hashAttemptEvent,
  leaseProviderAttempt,
  markProviderAttemptStarted,
  recordProviderResultCaptured,
  recordProviderResultValidated,
  recoverExpiredProviderAttempt,
} from '../scripts/lib/attempts.mjs'
import {
  validateRun,
  validateRunTransition,
} from '../scripts/lib/contracts.mjs'

const SHA_A = 'a'.repeat(64)
const SHA_B = 'b'.repeat(64)
const SHA_C = 'c'.repeat(64)
const SHA_D = 'd'.repeat(64)
const SHA_E = 'e'.repeat(64)
const SHA_F = 'f'.repeat(64)

function v2Run(overrides = {}) {
  return {
    schema_version: '2.0.0',
    run_id: 'run:attempt-contract',
    state: 'RUNNING',
    phase: 'FANOUT',
    capability_mode: 'STATIC',
    created_at: '2026-07-29T10:00:00Z',
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
      job_id: 'lens:web-and-api',
      kind: 'LENS',
      lens: 'web-and-api',
      state: 'PENDING',
    }],
    coverage: {
      inventory: ['src/app.mjs'],
      examined: [],
      unexamined: [{
        path: 'src/app.mjs',
        reason: 'awaiting provider execution',
      }],
      lenses: [{
        lens: 'web-and-api',
        status: 'NOT_ASSESSED',
        examined_paths: [],
        reason: 'awaiting provider execution',
      }],
      gaps: [],
    },
    store_profiles: [],
    findings: [],
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
    ...overrides,
  }
}

function lease(run, overrides = {}) {
  return leaseProviderAttempt(run, 'lens:web-and-api', {
    attempt_id: 'attempt:test-0001',
    occurred_at: '2026-07-29T10:00:01Z',
    expires_at: '2026-07-29T10:01:01Z',
    nonce: SHA_E,
    packet_sha256: SHA_A,
    provider_config_sha256: SHA_B,
    sandbox_policy_sha256: SHA_C,
    container_name: 'rta-attempt-test-0001',
    budgets: {
      wall_clock_ms: 30_000,
      max_requests: 10,
      max_bytes: 1024,
    },
    ...overrides,
  })
}

function rehashAttemptEvents(run) {
  let previousEventSha256 = null
  for (const [index, event] of run.attempt_events.entries()) {
    event.sequence = index + 1
    event.previous_event_sha256 = previousEventSha256
    event.event_sha256 = hashAttemptEvent(event)
    previousEventSha256 = event.event_sha256
  }
  return run
}

function capturedRun() {
  const leased = lease(v2Run())
  const started = markProviderAttemptStarted(leased, 'attempt:test-0001', {
    occurred_at: '2026-07-29T10:00:02Z',
  })
  return recordProviderResultCaptured(started, 'attempt:test-0001', {
    occurred_at: '2026-07-29T10:00:03Z',
    execution_artifact_key: 'execution_attempt_test_0001',
    execution_artifact: {
      path: 'executions/attempt-test-0001.json',
      sha256: SHA_E,
    },
    receipt_sha256: SHA_F,
  })
}

test('attempt helpers persist a hash-chained lease through observed commit', () => {
  const captured = capturedRun()
  const validated = recordProviderResultValidated(captured, 'attempt:test-0001', {
    occurred_at: '2026-07-29T10:00:04Z',
  })
  const candidate = structuredClone(validated)
  const job = candidate.jobs[0]
  job.state = 'SUCCEEDED'
  job.input_sha256 = SHA_A
  job.producer = {
    name: 'reference-provider',
    version: '1.0.0',
    instance_id: 'provider:test',
  }
  job.candidate_ids = []
  candidate.coverage.lenses[0] = {
    lens: 'web-and-api',
    status: 'RAN',
    examined_paths: [],
  }
  const committed = commitProviderAttempt(
    validated,
    candidate,
    'attempt:test-0001',
    { occurred_at: '2026-07-29T10:00:05Z' },
  )

  assert.equal(validateRun(committed).valid, true)
  assert.equal(committed.attempt_events.at(-1).event, 'COMMITTED')
  assert.equal(
    committed.jobs[0].coverage_authority,
    'CONTROLLER_OBSERVED_CONSUMPTION',
  )
  assert.equal(committed.jobs[0].receipt_sha256, SHA_F)
  assert.equal(findActiveAttempt(committed, 'lens:web-and-api'), null)
})

test('event content, order, sequence, and previous hashes are tamper evident', () => {
  const run = lease(v2Run())
  const changed = structuredClone(run)
  changed.attempt_events[0].nonce = SHA_A
  assert.ok(
    validateRun(changed).errors.some(({ code }) =>
      code === 'ATTEMPT_EVENT_HASH_MISMATCH'),
  )

  const wrongSequence = structuredClone(run)
  wrongSequence.attempt_events[0].sequence = 2
  wrongSequence.attempt_events[0].event_sha256 =
    hashAttemptEvent(wrongSequence.attempt_events[0])
  assert.ok(
    validateRun(wrongSequence).errors.some(({ code }) =>
      code === 'ATTEMPT_EVENT_SEQUENCE_BROKEN'),
  )

  const started = markProviderAttemptStarted(run, 'attempt:test-0001', {
    occurred_at: '2026-07-29T10:00:02Z',
  })
  const broken = structuredClone(started)
  broken.attempt_events[1].previous_event_sha256 = SHA_F
  broken.attempt_events[1].event_sha256 =
    hashAttemptEvent(broken.attempt_events[1])
  assert.ok(
    validateRun(broken).errors.some(({ code }) =>
      code === 'ATTEMPT_EVENT_CHAIN_BROKEN'),
  )
})

test('a recoverable failure preserves history and permits a fresh one-use lease', () => {
  const first = markProviderAttemptStarted(
    lease(v2Run()),
    'attempt:test-0001',
    { occurred_at: '2026-07-29T10:00:02Z' },
  )
  const failed = failProviderAttempt(first, 'attempt:test-0001', {
    occurred_at: '2026-07-29T10:00:03Z',
    reason: 'provider exceeded its wall-clock budget',
    recoverable: true,
  })
  assert.equal(failed.jobs[0].state, 'PENDING')
  assert.equal(failed.attempt_events.at(-1).event, 'FAILED')
  assert.equal(findActiveAttempt(failed, 'lens:web-and-api'), null)

  const retried = lease(failed, {
    attempt_id: 'attempt:test-0002',
    occurred_at: '2026-07-29T10:00:04Z',
    expires_at: '2026-07-29T10:01:04Z',
    nonce: SHA_F,
    container_name: 'rta-attempt-test-0002',
  })
  assert.equal(retried.attempt_events.length, 4)
  assert.equal(retried.attempt_events[2].event, 'FAILED')
  assert.equal(retried.attempt_events[3].attempt_id, 'attempt:test-0002')
})

test('invalid and expired leases cannot START', () => {
  assert.throws(
    () => lease(v2Run(), {
      expires_at: '2026-07-29T10:00:01Z',
    }),
    /expires_at must be strictly after occurred_at/,
  )
  assert.throws(
    () => lease(v2Run(), {
      occurred_at: '2026-02-31T10:00:01Z',
    }),
    /semantically valid timestamp/,
  )

  const leased = lease(v2Run())
  assert.throws(
    () => markProviderAttemptStarted(leased, 'attempt:test-0001', {
      occurred_at: leased.attempt_events[0].expires_at,
    }),
    /lease expired.*refusing STARTED/,
  )
  assert.equal(leased.attempt_events.length, 1)

  const forged = structuredClone(leased)
  forged.attempt_events.push({
    sequence: 2,
    attempt_id: 'attempt:test-0001',
    job_id: 'lens:web-and-api',
    event: 'STARTED',
    occurred_at: leased.attempt_events[0].expires_at,
    previous_event_sha256: leased.attempt_events[0].event_sha256,
  })
  rehashAttemptEvents(forged)
  assert.ok(
    validateRun(forged).errors.some(({ code }) =>
      code === 'ATTEMPT_START_OUTSIDE_LEASE'),
  )
})

test('attempt event timestamps are semantically valid and never move backward', () => {
  const leased = lease(v2Run())
  const started = markProviderAttemptStarted(leased, 'attempt:test-0001', {
    occurred_at: '2026-07-29T10:00:02Z',
  })
  assert.throws(
    () => failProviderAttempt(started, 'attempt:test-0001', {
      occurred_at: '2026-07-29T10:00:01.500Z',
      reason: 'clock moved backward',
    }),
    /Run transition validation failed/,
  )

  const reversed = structuredClone(started)
  reversed.attempt_events[1].occurred_at = '2026-07-29T09:59:59Z'
  rehashAttemptEvents(reversed)
  assert.ok(
    validateRun(reversed).errors.some(({ code }) =>
      code === 'ATTEMPT_EVENT_TIME_REVERSED'),
  )

  const invalid = structuredClone(started)
  invalid.attempt_events[1].occurred_at = '2026-02-31T10:00:02Z'
  rehashAttemptEvents(invalid)
  assert.ok(
    validateRun(invalid).errors.some(({ code }) =>
      code === 'ATTEMPT_EVENT_TIME_INVALID'),
  )
})

test('unexpired attempts cannot be stolen and expired recovery is explicit', () => {
  const leased = lease(v2Run())
  assert.equal(
    classifyProviderAttemptRecovery(leased, 'attempt:test-0001', {
      now: '2026-07-29T10:01:00.999Z',
    }).status,
    'ACTIVE_UNEXPIRED',
  )
  assert.throws(
    () => recoverExpiredProviderAttempt(leased, 'attempt:test-0001', {
      occurred_at: '2026-07-29T10:01:00.999Z',
    }),
    /ACTIVE_UNEXPIRED/,
  )

  assert.equal(
    classifyProviderAttemptRecovery(leased, 'attempt:test-0001', {
      now: '2026-07-29T10:01:01Z',
    }).status,
    'ACTIVE_EXPIRED',
  )
  const recovered = recoverExpiredProviderAttempt(
    leased,
    'attempt:test-0001',
    { occurred_at: '2026-07-29T10:01:01Z' },
  )
  assert.equal(recovered.jobs[0].state, 'PENDING')
  assert.deepEqual(
    recovered.attempt_events.map(({ event }) => event),
    ['LEASED', 'FAILED'],
  )

  const retried = lease(recovered, {
    attempt_id: 'attempt:test-0002',
    occurred_at: '2026-07-29T10:01:02Z',
    expires_at: '2026-07-29T10:02:02Z',
    nonce: SHA_F,
    container_name: 'rta-attempt-test-0002',
  })
  assert.equal(retried.attempt_events.at(-1).attempt_id, 'attempt:test-0002')
})

test('standalone run validation rejects retry after a non-recoverable failure', () => {
  const started = markProviderAttemptStarted(
    lease(v2Run()),
    'attempt:test-0001',
    { occurred_at: '2026-07-29T10:00:02Z' },
  )
  const recovered = failProviderAttempt(started, 'attempt:test-0001', {
    occurred_at: '2026-07-29T10:00:03Z',
    reason: 'recoverable fixture failure',
    recoverable: true,
  })
  const retried = lease(recovered, {
    attempt_id: 'attempt:test-0002',
    occurred_at: '2026-07-29T10:00:04Z',
    expires_at: '2026-07-29T10:01:04Z',
    nonce: SHA_F,
    container_name: 'rta-attempt-test-0002',
  })
  const forged = structuredClone(retried)
  forged.attempt_events[2].recoverable = false
  rehashAttemptEvents(forged)
  assert.ok(
    validateRun(forged).errors.some(({ code }) =>
      code === 'ATTEMPT_RETRY_WITHOUT_RECOVERABLE_FAILURE'),
  )
})

test('elapsed time alone cannot replace an active attempt with a fresh lease', () => {
  const leased = lease(v2Run())
  const forged = structuredClone(leased)
  forged.attempt_events.push({
    ...structuredClone(leased.attempt_events[0]),
    sequence: 2,
    attempt_id: 'attempt:test-0002',
    occurred_at: '2026-07-29T10:01:02Z',
    expires_at: '2026-07-29T10:02:02Z',
    nonce: SHA_F,
    container_name: 'rta-attempt-test-0002',
    previous_event_sha256: leased.attempt_events[0].event_sha256,
  })
  rehashAttemptEvents(forged)
  const codes = new Set(validateRun(forged).errors.map(({ code }) => code))
  assert.equal(codes.has('CONCURRENT_JOB_ATTEMPTS'), true)
  assert.equal(codes.has('ATTEMPT_RETRY_WITHOUT_RECOVERABLE_FAILURE'), true)
})

test('replay, duplicate starts, and concurrent leases fail closed', () => {
  const leased = lease(v2Run())
  assert.throws(
    () => leaseProviderAttempt(leased, 'lens:web-and-api', {
      attempt_id: 'attempt:test-0002',
    }),
    /only PENDING jobs|already has an active attempt/,
  )
  const started = markProviderAttemptStarted(leased, 'attempt:test-0001', {
    occurred_at: '2026-07-29T10:00:02Z',
  })
  assert.throws(
    () => markProviderAttemptStarted(started, 'attempt:test-0001'),
    /expected LEASED/,
  )
  assert.throws(
    () => failProviderAttempt(
      failProviderAttempt(started, 'attempt:test-0001', {
        reason: 'first terminal result',
      }),
      'attempt:test-0001',
      { reason: 'replayed terminal result' },
    ),
    /already terminal/,
  )
})

test('provider-declared jobs cannot smuggle controller receipt provenance', () => {
  const run = v2Run()
  run.jobs[0] = {
    ...run.jobs[0],
    state: 'SUCCEEDED',
    input_sha256: SHA_A,
    producer: {
      name: 'manual-provider',
      version: '1.0.0',
      instance_id: 'provider:manual',
    },
    candidate_ids: [],
    coverage_authority: 'PROVIDER_DECLARED',
    attempt_id: 'attempt:forged',
    receipt_sha256: SHA_E,
    execution_artifact_key: 'source_index',
  }
  run.coverage.lenses[0] = {
    lens: 'web-and-api',
    status: 'RAN',
    examined_paths: [],
  }
  assert.ok(
    validateRun(run).errors.some(({ code }) =>
      code === 'DECLARED_COVERAGE_RECEIPT_SMUGGLING'),
  )
})

test('manual provider-declared v2 jobs remain valid without attempt history', () => {
  const run = v2Run()
  run.jobs[0] = {
    ...run.jobs[0],
    state: 'SUCCEEDED',
    input_sha256: SHA_A,
    producer: {
      name: 'manual-provider',
      version: '1.0.0',
      instance_id: 'provider:manual',
    },
    candidate_ids: [],
    coverage_authority: 'PROVIDER_DECLARED',
  }
  run.coverage.lenses[0] = {
    lens: 'web-and-api',
    status: 'RAN',
    examined_paths: [],
  }
  assert.equal(validateRun(run).valid, true)
})

test('observed coverage requires a matching commit and execution artifact', () => {
  const run = v2Run()
  run.jobs[0] = {
    ...run.jobs[0],
    state: 'SUCCEEDED',
    input_sha256: SHA_A,
    producer: {
      name: 'provider',
      version: '1.0.0',
      instance_id: 'provider:forged',
    },
    candidate_ids: [],
    coverage_authority: 'CONTROLLER_OBSERVED_CONSUMPTION',
    attempt_id: 'attempt:missing',
    receipt_sha256: SHA_E,
    execution_artifact_key: 'missing_execution',
  }
  run.coverage.lenses[0] = {
    lens: 'web-and-api',
    status: 'RAN',
    examined_paths: [],
  }
  const codes = new Set(validateRun(run).errors.map(({ code }) => code))
  assert.equal(codes.has('OBSERVED_COVERAGE_ATTEMPT_MISSING'), true)
  assert.equal(codes.has('OBSERVED_COVERAGE_ARTIFACT_MISSING'), true)
})

test('sealed snapshots must have the right kind and an existing index artifact', () => {
  const run = v2Run()
  run.source_snapshot.kind = 'CONTROL'
  run.control_snapshot.index_artifact_key = 'missing_control_index'
  const codes = new Set(validateRun(run).errors.map(({ code }) => code))
  assert.equal(codes.has('SEALED_SNAPSHOT_KIND_MISMATCH'), true)
  assert.equal(codes.has('SEALED_SNAPSHOT_INDEX_MISSING'), true)
})

test('generic transitions cannot rewind RUNNING jobs without a failed attempt', () => {
  const previous = lease(v2Run())
  const next = structuredClone(previous)
  next.jobs[0].state = 'PENDING'
  const validation = validateRunTransition(previous, next)
  assert.equal(validation.valid, false)
  assert.ok(
    validation.errors.some(({ code }) =>
      code === 'JOB_RETRY_WITHOUT_RECOVERABLE_FAILURE'),
  )
})
