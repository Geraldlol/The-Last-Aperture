import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  acknowledgeUnleashCampaignPause,
  readUnleashCampaignPauseControl,
  requestUnleashCampaignPause,
  requestUnleashLocalRollback,
} from '../scripts/lib/unleash-campaign-pause.mjs'
import { digestUnleashValue } from '../scripts/lib/unleash-contracts.mjs'

const SHA_A = 'a'.repeat(64)
const SHA_B = 'b'.repeat(64)
const SHA_C = 'c'.repeat(64)
const SHA_D = 'd'.repeat(64)
const SHA_E = 'e'.repeat(64)
const OWNER_ID = `swarm-owner:sha256:${'f'.repeat(64)}`

function campaign() {
  return {
    plan: {
      plan_sha256: SHA_A,
      policy_id: 'policy:fixture',
      policy_sha256: SHA_B,
      target: { target_id: `target:sha256:${SHA_C}` },
      authority: { revocation: { check_id: `revocation:sha256:${SHA_D}` } },
    },
    state: {
      schema_version: '2.0.0',
      campaign_id: `campaign:sha256:${SHA_E}`,
      status: 'SWARMING',
    },
  }
}

function memoryStorage(initial = {}) {
  const records = new Map(
    Object.entries(initial).map(([filename, value]) => [filename, structuredClone(value)]),
  )
  const writes = []
  return {
    records,
    writes,
    async listJsonFilenames() {
      return [...records.keys()]
    },
    async readJson(filename) {
      if (!records.has(filename)) {
        const error = new Error(`missing fixture record: ${filename}`)
        error.code = 'UNLEASH_STORAGE_FILE_MISSING'
        throw error
      }
      return structuredClone(records.get(filename))
    },
    async writeImmutableJson(filename, value) {
      if (records.has(filename)) {
        const error = new Error(`immutable fixture record exists: ${filename}`)
        error.code = 'UNLEASH_STORAGE_FILE_EXISTS'
        throw error
      }
      records.set(filename, structuredClone(value))
      writes.push({ filename, value: structuredClone(value) })
    },
  }
}

function fixedNow(iso) {
  return () => new Date(iso)
}

function fixedRandom(hex) {
  return (length) => {
    assert.equal(length, 16)
    return Buffer.from(hex, 'hex')
  }
}

function seedAcknowledgedPauseHistory(storage, plan, state, count) {
  const expected = {
    campaign_id: state.campaign_id,
    plan_sha256: plan.plan_sha256,
    policy_id: plan.policy_id,
    policy_sha256: plan.policy_sha256,
    target_id: plan.target.target_id,
    revocation_check_id: plan.authority.revocation.check_id,
  }
  for (let requestIndex = 1; requestIndex <= count; requestIndex += 1) {
    const pauseId = `pause:sha256:${digestUnleashValue({
      ...expected,
      request_index: requestIndex,
    })}`
    const requestUnsigned = {
      schema_version: '1.0.0',
      kind: 'last-aperture/unleash-pause-request',
      ...expected,
      pause_id: pauseId,
      nonce: requestIndex.toString(16).padStart(32, '0'),
      request_index: requestIndex,
      requested_at: '2026-09-16T13:00:00.000Z',
      reason: `Seeded bounded Pause cycle ${requestIndex}.`,
    }
    const request = {
      ...requestUnsigned,
      request_sha256: digestUnleashValue(requestUnsigned),
    }
    const suffix = pauseId.slice('pause:sha256:'.length)
    storage.records.set(`campaign-pause-request-${suffix}.json`, request)

    const acknowledgementUnsigned = {
      schema_version: '1.0.0',
      kind: 'last-aperture/unleash-pause-resume',
      ...expected,
      pause_id: pauseId,
      request_sha256: request.request_sha256,
      owner_id: OWNER_ID,
      resumed_at: '2026-09-16T13:00:01.000Z',
    }
    storage.records.set(`campaign-pause-resume-${suffix}.json`, {
      ...acknowledgementUnsigned,
      ack_sha256: digestUnleashValue(acknowledgementUnsigned),
    })
  }
}

test('records immutable Pause and owner-bound Resume cycles without rewriting prior artifacts', async () => {
  const { plan, state } = campaign()
  const storage = memoryStorage()
  const initial = await readUnleashCampaignPauseControl({ storage, plan, state })
  assert.deepEqual(initial, {
    state: 'RUNNING',
    dispatch_open: true,
    request_count: 0,
    acknowledgement_count: 0,
    rollback_request_count: 0,
    active_requests: [],
    requests: [],
    acknowledgements: [],
    rollbacks: [],
  })

  const paused = await requestUnleashCampaignPause(
    { storage, plan, state, reason: 'Operator is reviewing a detection warning.' },
    {
      now: fixedNow('2026-09-16T10:00:00.000Z'),
      randomBytes: fixedRandom('00112233445566778899aabbccddeeff'),
    },
  )
  assert.equal(paused.state, 'PAUSED')
  assert.equal(paused.dispatch_open, false)
  assert.equal(paused.request_count, 1)
  assert.equal(paused.active_requests.length, 1)
  assert.equal(Object.isFrozen(paused), true)
  assert.equal(Object.isFrozen(paused.active_requests[0]), true)

  const firstRequest = structuredClone(paused.requests[0])
  const idempotent = await requestUnleashCampaignPause(
    { storage, plan, state, reason: 'A second reason cannot replace the active Pause.' },
    {
      now: fixedNow('2026-09-16T10:00:01.000Z'),
      randomBytes: fixedRandom('11112222333344445555666677778888'),
    },
  )
  assert.equal(idempotent.request_count, 1)
  assert.equal(storage.writes.length, 1)
  assert.deepEqual(idempotent.requests[0], firstRequest)

  const resumed = await acknowledgeUnleashCampaignPause(
    { storage, plan, state, ownerId: OWNER_ID },
    { now: fixedNow('2026-09-16T10:01:00.000Z') },
  )
  assert.equal(resumed.state, 'RUNNING')
  assert.equal(resumed.dispatch_open, true)
  assert.equal(resumed.acknowledgement_count, 1)
  assert.equal(resumed.acknowledgements[0].owner_id, OWNER_ID)
  assert.equal(resumed.acknowledgements[0].request_sha256, firstRequest.request_sha256)

  const pausedAgain = await requestUnleashCampaignPause(
    { storage, plan, state, reason: 'Operator requested a second bounded Pause.' },
    {
      now: fixedNow('2026-09-16T10:02:00.000Z'),
      randomBytes: fixedRandom('ffeeddccbbaa99887766554433221100'),
    },
  )
  assert.equal(pausedAgain.state, 'PAUSED')
  assert.equal(pausedAgain.request_count, 2)
  assert.equal(pausedAgain.acknowledgement_count, 1)
  assert.notEqual(pausedAgain.requests[1].pause_id, firstRequest.pause_id)

  const resumedAgain = await acknowledgeUnleashCampaignPause(
    { storage, plan, state, ownerId: OWNER_ID },
    { now: fixedNow('2026-09-16T10:03:00.000Z') },
  )
  assert.equal(resumedAgain.state, 'RUNNING')
  assert.equal(resumedAgain.request_count, 2)
  assert.equal(resumedAgain.acknowledgement_count, 2)
  assert.equal(storage.writes.length, 4)
  assert.deepEqual(resumedAgain.requests[0], firstRequest)
})

test('local rollback stays bound to one active Pause and never claims target-side reversal', async () => {
  const { plan, state } = campaign()
  const storage = memoryStorage()
  await requestUnleashCampaignPause(
    { storage, plan, state, reason: 'Stop future dispatch before local rollback.' },
    {
      now: fixedNow('2026-09-16T11:00:00.000Z'),
      randomBytes: fixedRandom('abcdefabcdefabcdefabcdefabcdefab'),
    },
  )
  const rolledBack = await requestUnleashLocalRollback(
    { storage, plan, state, reason: 'Discard undispatched and inert proposed work.' },
    { now: fixedNow('2026-09-16T11:01:00.000Z') },
  )
  assert.equal(rolledBack.state, 'PAUSED')
  assert.equal(rolledBack.rollback_request_count, 1)
  assert.equal(rolledBack.rollbacks[0].pause_id, rolledBack.active_requests[0].pause_id)
  assert.deepEqual(rolledBack.rollbacks[0].scope, ['NOT_YET_DISPATCHED', 'PROPOSED_INERT'])
  assert.equal(rolledBack.rollbacks[0].target_side_effects_reversed, false)

  const writesBeforeRetry = storage.writes.length
  const retried = await requestUnleashLocalRollback(
    { storage, plan, state, reason: 'A retry cannot replace the immutable rollback record.' },
    { now: fixedNow('2026-09-16T11:02:00.000Z') },
  )
  assert.equal(retried.rollback_request_count, 1)
  assert.equal(storage.writes.length, writesBeforeRetry)
})

test('rejects request and rollback tampering even when artifacts retain their original filenames', async () => {
  const { plan, state } = campaign()

  const requestStorage = memoryStorage()
  const paused = await requestUnleashCampaignPause(
    { storage: requestStorage, plan, state, reason: 'Preserve this signed operator reason.' },
    {
      now: fixedNow('2026-09-16T12:00:00.000Z'),
      randomBytes: fixedRandom('1234567890abcdef1234567890abcdef'),
    },
  )
  const requestFilename = requestStorage.writes[0].filename
  const changedRequest = structuredClone(paused.requests[0])
  changedRequest.reason = 'Tampered operator reason.'
  requestStorage.records.set(requestFilename, changedRequest)
  await assert.rejects(
    readUnleashCampaignPauseControl({ storage: requestStorage, plan, state }),
    { code: 'UNLEASH_PAUSE_REQUEST_INVALID' },
  )

  const rollbackStorage = memoryStorage()
  await requestUnleashCampaignPause(
    { storage: rollbackStorage, plan, state, reason: 'Pause for rollback claim validation.' },
    {
      now: fixedNow('2026-09-16T12:10:00.000Z'),
      randomBytes: fixedRandom('fedcba0987654321fedcba0987654321'),
    },
  )
  await requestUnleashLocalRollback(
    { storage: rollbackStorage, plan, state, reason: 'Rollback only local undispatched work.' },
    { now: fixedNow('2026-09-16T12:11:00.000Z') },
  )
  const rollbackFilename = rollbackStorage.writes.at(-1).filename
  const changedRollback = structuredClone(rollbackStorage.records.get(rollbackFilename))
  changedRollback.target_side_effects_reversed = true
  rollbackStorage.records.set(rollbackFilename, changedRollback)
  await assert.rejects(
    readUnleashCampaignPauseControl({ storage: rollbackStorage, plan, state }),
    { code: 'UNLEASH_ROLLBACK_REQUEST_INVALID' },
  )
})

test('rejects orphan Pause acknowledgements and rollback records', async () => {
  const { plan, state } = campaign()
  for (const filename of [
    `campaign-pause-resume-${SHA_A}.json`,
    `campaign-rollback-request-${SHA_B}.json`,
  ]) {
    const storage = memoryStorage({ [filename]: { forged: true } })
    await assert.rejects(
      readUnleashCampaignPauseControl({ storage, plan, state }),
      {
        code: 'UNLEASH_PAUSE_INVENTORY_INVALID',
        message: `pause control contains an orphan artifact: ${filename}`,
      },
    )
  }
})

test('rejects every Pause operation for protocol-v1 campaign state', async () => {
  const { plan, state } = campaign()
  state.schema_version = '1.0.0'
  const storage = memoryStorage()
  for (const operation of [
    () => readUnleashCampaignPauseControl({ storage, plan, state }),
    () => requestUnleashCampaignPause({ storage, plan, state, reason: 'Unsupported.' }),
    () => acknowledgeUnleashCampaignPause({ storage, plan, state, ownerId: OWNER_ID }),
    () => requestUnleashLocalRollback({ storage, plan, state, reason: 'Unsupported rollback.' }),
  ]) {
    await assert.rejects(operation(), { code: 'UNLEASH_PAUSE_PROTOCOL_UNSUPPORTED' })
  }
})

test('caps Pause history before request 1025 and serializes concurrent boundary writers', async () => {
  const { plan, state } = campaign()
  const storage = memoryStorage()
  const now = fixedNow('2026-09-16T14:00:00.000Z')
  const randomBytes = fixedRandom('00112233445566778899aabbccddeeff')
  seedAcknowledgedPauseHistory(storage, plan, state, 1023)

  const writesBeforeBoundary = storage.writes.length
  await Promise.all([
    requestUnleashCampaignPause(
      { storage, plan, state, reason: 'First concurrent boundary request.' },
      { now, randomBytes },
    ),
    requestUnleashCampaignPause(
      { storage, plan, state, reason: 'Second concurrent boundary request.' },
      { now, randomBytes },
    ),
  ])

  const atLimit = await readUnleashCampaignPauseControl({ storage, plan, state })
  assert.equal(atLimit.request_count, 1024)
  assert.equal(atLimit.active_requests.length, 1)
  assert.equal(storage.writes.length, writesBeforeBoundary + 1)

  await acknowledgeUnleashCampaignPause(
    { storage, plan, state, ownerId: OWNER_ID },
    { now },
  )
  const writesAtLimit = storage.writes.length
  await assert.rejects(
    requestUnleashCampaignPause(
      { storage, plan, state, reason: 'This would be request 1025.' },
      { now, randomBytes },
    ),
    { code: 'UNLEASH_PAUSE_LIMIT' },
  )
  assert.equal(storage.writes.length, writesAtLimit)

  const retained = await readUnleashCampaignPauseControl({ storage, plan, state })
  assert.equal(retained.state, 'RUNNING')
  assert.equal(retained.dispatch_open, true)
  assert.equal(retained.request_count, 1024)
  assert.equal(retained.acknowledgement_count, 1024)
})
