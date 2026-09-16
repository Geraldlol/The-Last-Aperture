import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import test from 'node:test'

import { digestUnleashValue } from '../scripts/lib/unleash-contracts.mjs'
import {
  UNLEASH_SWARM_DEFAULT_LIMITS,
  createUnleashRoleRequest,
  createUnleashRoleResponseCapture,
  createUnleashSwarmBasis,
  decodeUnleashRoleResponseCapture,
} from '../scripts/lib/unleash-swarm-contracts.mjs'
import {
  UNLEASH_SWARM_ATTEMPT_LEDGER_STATE_FILE,
  UnleashSwarmLedgerError,
  appendUnleashSwarmAttemptEvent,
  assertValidUnleashSwarmAttemptEvent,
  assertValidUnleashSwarmAttemptLedgerState,
  classifyUnleashSwarmAttemptRecovery,
  initializeUnleashSwarmAttemptLedger,
  reconcileUnleashSwarmAttemptLedger,
  recoverUnleashSwarmAttemptLedger,
  unleashSwarmAttemptEventFilename,
} from '../scripts/lib/unleash-swarm-ledger.mjs'

const SHA = Object.freeze(Object.fromEntries(
  'abcdefghijklmnop'.split('').map((letter, index) => [
    letter,
    '0123456789abcdef'[index].repeat(64),
  ]),
))

function basis(limitOverrides = {}) {
  return createUnleashSwarmBasis({
    recordedAt: '2026-09-15T14:00:00.000Z',
    campaignId: `campaign:sha256:${SHA.a}`,
    campaignStateRevision: 2,
    campaignStateSha256: SHA.b,
    planSha256: SHA.c,
    targetId: `target:sha256:${SHA.d}`,
    registrySha256: SHA.e,
    providerProfileSha256: SHA.f,
    evidencePacketSha256: SHA.g,
    completionReceiptSha256: SHA.h,
    limits: {
      ...structuredClone(UNLEASH_SWARM_DEFAULT_LIMITS),
      ...limitOverrides,
    },
  })
}

function request(swarmBasis = basis()) {
  return createUnleashRoleRequest({
    basis: swarmBasis,
    round: 1,
    roleId: 'attacker:perimeter',
    inputFrontierSha256: SHA.i,
    inputChallengeSetSha256: SHA.j,
    evidenceRefs: [`evidence:sha256:${SHA.k}`],
    allowedToolIds: ['tool:https-recon'],
    artifacts: [{
      artifact_id: `artifact:sha256:${SHA.l}`,
      kind: 'EVIDENCE',
      logical_name: 'verified-https-recon.json',
      sha256: SHA.k,
      size: 128,
    }],
  })
}

function adapterIdentity() {
  return {
    adapter_id: 'adapter:fixture-provider',
    adapter_version: '1.0.0',
    adapter_config_sha256: SHA.m,
  }
}

function attemptLimits() {
  return {
    wall_time_ms: 60_000,
    max_response_bytes: 262_144,
    max_frame_bytes: 65_536,
    max_frames: 64,
  }
}

function capture(
  roleRequest,
  bytes = Buffer.from('{"invalid":"semantics"}', 'utf8'),
  options = {},
) {
  const responseSha256 = createHash('sha256').update(bytes).digest('hex')
  return createUnleashRoleResponseCapture({
    request: roleRequest,
    adapterId: adapterIdentity().adapter_id,
    adapterVersion: adapterIdentity().adapter_version,
    adapterConfigSha256: options.adapterConfigSha256 ?? adapterIdentity().adapter_config_sha256,
    capturedAt: options.capturedAt ?? '2026-09-15T14:00:03.000Z',
    responseBytes: bytes,
    transportReceipt: {
      schema_version: '1.0.0',
      kind: 'last-aperture/unleash-provider-transport-receipt',
      adapter_id: adapterIdentity().adapter_id,
      adapter_version: adapterIdentity().adapter_version,
      adapter_config_sha256: adapterIdentity().adapter_config_sha256,
      request_id: roleRequest.request_id,
      request_sha256: roleRequest.request_sha256,
      response_sha256: responseSha256,
      scope: 'TRANSPORT_ONLY',
      semantic_analysis_proven: false,
    },
  })
}

function fakeStorage() {
  const files = new Map()
  const copy = (value) => structuredClone(value)
  return {
    files,
    storage: Object.freeze({
      async writeImmutableJson(filename, value) {
        if (files.has(filename)) {
          const error = new Error('exists')
          error.code = 'UNLEASH_STORAGE_FILE_EXISTS'
          throw error
        }
        files.set(filename, copy(value))
      },
      async replaceMutableJson(filename, value) {
        files.set(filename, copy(value))
      },
      async readJson(filename) {
        if (!files.has(filename)) {
          const error = new Error('missing')
          error.code = 'UNLEASH_STORAGE_FILE_NOT_FOUND'
          throw error
        }
        return copy(files.get(filename))
      },
      async listJsonFilenames() {
        return [...files.keys()].sort()
      },
    }),
  }
}

function rejectsCode(code) {
  return (error) => error instanceof UnleashSwarmLedgerError && error.code === code
}

async function append(storage, swarmBasis, roleRequest, state, occurredAt, payload) {
  return appendUnleashSwarmAttemptEvent({
    basis: swarmBasis,
    attemptId: `attempt:sha256:${SHA.n}`,
    request: roleRequest,
    adapterIdentity: adapterIdentity(),
    state,
    occurredAt,
    payload,
  }, { storage })
}

test('durably advances LEASED through COMMITTED with self-digested append-only records', async () => {
  const swarmBasis = basis()
  const roleRequest = request(swarmBasis)
  const retained = fakeStorage()
  await initializeUnleashSwarmAttemptLedger({
    basis: swarmBasis,
    initializedAt: '2026-09-15T14:00:00.000Z',
  }, { storage: retained.storage })

  await append(retained.storage, swarmBasis, roleRequest, 'LEASED', '2026-09-15T14:00:01.000Z', {
    expires_at: '2026-09-15T14:01:01.000Z',
    limits: attemptLimits(),
  })
  await append(retained.storage, swarmBasis, roleRequest, 'STARTED', '2026-09-15T14:00:02.000Z', {})
  const captured = capture(roleRequest)
  await append(retained.storage, swarmBasis, roleRequest, 'CAPTURED', '2026-09-15T14:00:03.000Z', {
    capture: captured,
  })
  await append(retained.storage, swarmBasis, roleRequest, 'VALIDATED', '2026-09-15T14:00:04.000Z', {
    capture_sha256: captured.capture_sha256,
    response_sha256: captured.response_sha256,
    validated_response_sha256: SHA.o,
  })
  const recovered = await append(retained.storage, swarmBasis, roleRequest, 'COMMITTED', '2026-09-15T14:00:05.000Z', {
    merge_sha256: SHA.p,
  })

  assert.equal(recovered.event_count, 5)
  assert.equal(recovered.attempt_count, 1)
  assert.equal(recovered.attempts[0].state, 'COMMITTED')
  assert.equal(recovered.reconciliation, 'CURRENT')
  assert.deepEqual(recovered.events.map(({ state }) => state), [
    'LEASED', 'STARTED', 'CAPTURED', 'VALIDATED', 'COMMITTED',
  ])
  for (const [index, event] of recovered.events.entries()) {
    assert.equal(assertValidUnleashSwarmAttemptEvent(event, {
      basis: swarmBasis,
      previousEvent: index === 0 ? null : recovered.events[index - 1],
      previousAttemptEvent: index === 0 ? null : recovered.events[index - 1],
      leaseEvent: index === 0 ? null : recovered.events[0],
      request: roleRequest,
    }), event)
    const { record_sha256: _digest, ...unsigned } = event
    assert.equal(event.record_sha256, digestUnleashValue(unsigned))
    assert.equal(retained.files.has(unleashSwarmAttemptEventFilename(index + 1)), true)
  }
  assert.equal(
    assertValidUnleashSwarmAttemptLedgerState(
      retained.files.get(UNLEASH_SWARM_ATTEMPT_LEDGER_STATE_FILE),
      { basis: swarmBasis, ledger: recovered },
    ),
    retained.files.get(UNLEASH_SWARM_ATTEMPT_LEDGER_STATE_FILE),
  )
})

test('classifies STARTED as ambiguous and refuses a new attempt for the same request', async () => {
  const swarmBasis = basis()
  const roleRequest = request(swarmBasis)
  const retained = fakeStorage()
  await initializeUnleashSwarmAttemptLedger({
    basis: swarmBasis,
    initializedAt: '2026-09-15T14:00:00.000Z',
  }, { storage: retained.storage })
  await append(retained.storage, swarmBasis, roleRequest, 'LEASED', '2026-09-15T14:00:01.000Z', {
    expires_at: '2026-09-15T14:01:01.000Z',
    limits: attemptLimits(),
  })
  const started = await append(
    retained.storage,
    swarmBasis,
    roleRequest,
    'STARTED',
    '2026-09-15T14:00:02.000Z',
    {},
  )

  assert.deepEqual(classifyUnleashSwarmAttemptRecovery({
    ledger: started,
    attemptId: `attempt:sha256:${SHA.n}`,
  }), {
    attempt_id: `attempt:sha256:${SHA.n}`,
    request_id: roleRequest.request_id,
    state: 'STARTED',
    recovery: 'AMBIGUOUS_NO_REPLAY',
    auto_replay: false,
    resume_local: false,
  })
  const failed = await append(
    retained.storage,
    swarmBasis,
    roleRequest,
    'FAILED',
    '2026-09-15T14:00:03.000Z',
    {
      reason_code: 'TRANSPORT_ABORTED',
      phase: 'STARTED',
      delivery: 'AMBIGUOUS',
      detail_sha256: SHA.p,
    },
  )
  assert.equal(failed.attempts[0].failure.delivery, 'AMBIGUOUS')
  assert.equal(classifyUnleashSwarmAttemptRecovery({
    ledger: failed,
    attemptId: `attempt:sha256:${SHA.n}`,
  }).recovery, 'TERMINAL')
  await assert.rejects(
    appendUnleashSwarmAttemptEvent({
      basis: swarmBasis,
      attemptId: `attempt:sha256:${SHA.o}`,
      request: roleRequest,
      adapterIdentity: adapterIdentity(),
      state: 'LEASED',
      occurredAt: '2026-09-15T14:00:04.000Z',
      payload: {
        expires_at: '2026-09-15T14:01:04.000Z',
        limits: attemptLimits(),
      },
    }, { storage: retained.storage }),
    rejectsCode('UNLEASH_SWARM_ATTEMPT_REPLAY_AMBIGUOUS'),
  )
})

test('enforces the sealed provider-call count even when a lease failed before dispatch', async () => {
  const swarmBasis = basis({
    max_provider_calls: 1,
    max_parallel_provider_calls: 1,
  })
  const roleRequest = request(swarmBasis)
  const retained = fakeStorage()
  await initializeUnleashSwarmAttemptLedger({
    basis: swarmBasis,
    initializedAt: '2026-09-15T14:00:00.000Z',
  }, { storage: retained.storage })
  await append(retained.storage, swarmBasis, roleRequest, 'LEASED', '2026-09-15T14:00:01.000Z', {
    expires_at: '2026-09-15T14:01:01.000Z',
    limits: attemptLimits(),
  })
  await append(retained.storage, swarmBasis, roleRequest, 'FAILED', '2026-09-15T14:00:02.000Z', {
    reason_code: 'ABORTED_BEFORE_START',
    phase: 'LEASED',
    delivery: 'NOT_STARTED',
    detail_sha256: SHA.p,
  })
  await assert.rejects(
    appendUnleashSwarmAttemptEvent({
      basis: swarmBasis,
      attemptId: `attempt:sha256:${SHA.o}`,
      request: roleRequest,
      adapterIdentity: adapterIdentity(),
      state: 'LEASED',
      occurredAt: '2026-09-15T14:00:03.000Z',
      payload: {
        expires_at: '2026-09-15T14:01:03.000Z',
        limits: attemptLimits(),
      },
    }, { storage: retained.storage }),
    rejectsCode('UNLEASH_SWARM_ATTEMPT_LIMIT'),
  )
})

test('retains CAPTURED bytes before semantic parsing and resumes validation locally', async () => {
  const swarmBasis = basis()
  const roleRequest = request(swarmBasis)
  const retained = fakeStorage()
  await initializeUnleashSwarmAttemptLedger({
    basis: swarmBasis,
    initializedAt: '2026-09-15T14:00:00.000Z',
  }, { storage: retained.storage })
  await append(retained.storage, swarmBasis, roleRequest, 'LEASED', '2026-09-15T14:00:01.000Z', {
    expires_at: '2026-09-15T14:01:01.000Z',
    limits: attemptLimits(),
  })
  await append(retained.storage, swarmBasis, roleRequest, 'STARTED', '2026-09-15T14:00:02.000Z', {})
  const invalidSemanticCapture = capture(roleRequest, Buffer.from('not-json', 'utf8'))
  const captured = await append(
    retained.storage,
    swarmBasis,
    roleRequest,
    'CAPTURED',
    '2026-09-15T14:00:03.000Z',
    { capture: invalidSemanticCapture },
  )

  assert.equal(captured.attempts[0].capture.capture_sha256, invalidSemanticCapture.capture_sha256)
  assert.deepEqual(classifyUnleashSwarmAttemptRecovery({
    ledger: captured,
    attemptId: `attempt:sha256:${SHA.n}`,
  }).recovery, 'RESUME_LOCAL_VALIDATION')
  assert.throws(
    () => decodeUnleashRoleResponseCapture(invalidSemanticCapture, {
      request: roleRequest,
      knownCandidateIds: [],
    }),
    (error) => error?.code === 'UNLEASH_SWARM_RESPONSE_INVALID',
  )
  assert.equal(retained.files.has(unleashSwarmAttemptEventFilename(3)), true)
})

test('rejects response capture completed after the durable lease expired', async () => {
  const swarmBasis = basis()
  const roleRequest = request(swarmBasis)
  const retained = fakeStorage()
  await initializeUnleashSwarmAttemptLedger({
    basis: swarmBasis,
    initializedAt: '2026-09-15T14:00:00.000Z',
  }, { storage: retained.storage })
  const shortLimits = { ...attemptLimits(), wall_time_ms: 1_000 }
  await append(retained.storage, swarmBasis, roleRequest, 'LEASED', '2026-09-15T14:00:01.000Z', {
    expires_at: '2026-09-15T14:00:02.000Z',
    limits: shortLimits,
  })
  await append(retained.storage, swarmBasis, roleRequest, 'STARTED', '2026-09-15T14:00:01.500Z', {})
  const lateCapture = capture(
    roleRequest,
    Buffer.from('{}', 'utf8'),
    { capturedAt: '2026-09-15T14:00:02.001Z' },
  )
  await assert.rejects(
    append(
      retained.storage,
      swarmBasis,
      roleRequest,
      'CAPTURED',
      '2026-09-15T14:00:02.001Z',
      { capture: lateCapture },
    ),
    rejectsCode('UNLEASH_SWARM_LEDGER_CAPTURE_INVALID'),
  )
  assert.equal(retained.files.has(unleashSwarmAttemptEventFilename(3)), false)
})

test('repairs a head left behind a durable event and detects gaps or rolled-back tails', async () => {
  const swarmBasis = basis()
  const roleRequest = request(swarmBasis)
  const retained = fakeStorage()
  await initializeUnleashSwarmAttemptLedger({
    basis: swarmBasis,
    initializedAt: '2026-09-15T14:00:00.000Z',
  }, { storage: retained.storage })
  await append(retained.storage, swarmBasis, roleRequest, 'LEASED', '2026-09-15T14:00:01.000Z', {
    expires_at: '2026-09-15T14:01:01.000Z',
    limits: attemptLimits(),
  })
  const oneEventState = structuredClone(retained.files.get(UNLEASH_SWARM_ATTEMPT_LEDGER_STATE_FILE))
  await append(retained.storage, swarmBasis, roleRequest, 'STARTED', '2026-09-15T14:00:02.000Z', {})
  retained.files.set(UNLEASH_SWARM_ATTEMPT_LEDGER_STATE_FILE, oneEventState)

  const repairable = await recoverUnleashSwarmAttemptLedger(
    { basis: swarmBasis },
    { storage: retained.storage },
  )
  assert.equal(repairable.reconciliation, 'REPAIR_REQUIRED')
  const repaired = await reconcileUnleashSwarmAttemptLedger({
    basis: swarmBasis,
    updatedAt: '2026-09-15T14:00:03.000Z',
  }, { storage: retained.storage })
  assert.equal(repaired.reconciliation, 'CURRENT')
  assert.equal(repaired.event_count, 2)

  retained.files.delete(unleashSwarmAttemptEventFilename(1))
  await assert.rejects(
    recoverUnleashSwarmAttemptLedger({ basis: swarmBasis }, { storage: retained.storage }),
    rejectsCode('UNLEASH_SWARM_LEDGER_GAP'),
  )

  retained.files.set(
    unleashSwarmAttemptEventFilename(1),
    structuredClone(repaired.events[0]),
  )
  retained.files.delete(unleashSwarmAttemptEventFilename(2))
  await assert.rejects(
    recoverUnleashSwarmAttemptLedger({ basis: swarmBasis }, { storage: retained.storage }),
    rejectsCode('UNLEASH_SWARM_LEDGER_ROLLBACK'),
  )
})

test('rejects computed event input without invoking its accessor', async () => {
  const swarmBasis = basis()
  const roleRequest = request(swarmBasis)
  const retained = fakeStorage()
  await initializeUnleashSwarmAttemptLedger({
    basis: swarmBasis,
    initializedAt: '2026-09-15T14:00:00.000Z',
  }, { storage: retained.storage })
  let getterCalls = 0
  const input = {
    basis: swarmBasis,
    attemptId: `attempt:sha256:${SHA.n}`,
    request: roleRequest,
    adapterIdentity: adapterIdentity(),
    state: 'LEASED',
    occurredAt: '2026-09-15T14:00:01.000Z',
    payload: {
      expires_at: '2026-09-15T14:01:01.000Z',
      limits: attemptLimits(),
    },
  }
  Object.defineProperty(input, 'state', {
    enumerable: true,
    get() {
      getterCalls += 1
      throw new Error('must not execute')
    },
  })

  await assert.rejects(
    appendUnleashSwarmAttemptEvent(input, { storage: retained.storage }),
    rejectsCode('UNLEASH_SWARM_LEDGER_INPUT_INVALID'),
  )
  assert.equal(getterCalls, 0)
})
