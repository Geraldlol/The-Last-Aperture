import { randomBytes as systemRandomBytes } from 'node:crypto'

import { digestUnleashValue } from './unleash-contracts.mjs'

export const UNLEASH_PAUSE_REQUEST_FILE = /^campaign-pause-request-([a-f0-9]{64})\.json$/u
export const UNLEASH_PAUSE_ACK_FILE = /^campaign-pause-resume-([a-f0-9]{64})\.json$/u
export const UNLEASH_ROLLBACK_REQUEST_FILE = /^campaign-rollback-request-([a-f0-9]{64})\.json$/u

const SHA256 = /^[a-f0-9]{64}$/u
const PAUSE_ID = /^pause:sha256:[a-f0-9]{64}$/u
const OWNER_ID = /^swarm-owner:sha256:[a-f0-9]{64}$/u
const TERMINAL = new Set(['COMPLETE', 'COMPLETE_WITH_GAPS', 'STOPPED', 'OUTCOME_UNCERTAIN', 'FAILED'])
const MAX_PAUSE_REQUESTS = 1024

export class UnleashCampaignPauseError extends Error {
  constructor(code, message, { cause } = {}) {
    super(message, cause === undefined ? undefined : { cause })
    this.name = 'UnleashCampaignPauseError'
    this.code = code
  }
}

function fail(code, message, options) {
  throw new UnleashCampaignPauseError(code, message, options)
}

function exact(value, fields) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && [Object.prototype, null].includes(Object.getPrototypeOf(value))
    && Object.keys(value).toSorted().join(',') === [...fields].toSorted().join(',')
}

function frozen(value) {
  const copy = structuredClone(value)
  const stack = [copy]
  while (stack.length > 0) {
    const current = stack.pop()
    if (current === null || typeof current !== 'object' || Object.isFrozen(current)) continue
    for (const child of Object.values(current)) stack.push(child)
    Object.freeze(current)
  }
  return copy
}

function timestamp(now) {
  if (typeof now !== 'function') fail('UNLEASH_PAUSE_TIME_INVALID', 'pause control requires a clock function')
  const value = now()
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    fail('UNLEASH_PAUSE_TIME_INVALID', 'pause control clock must return a valid Date')
  }
  return value.toISOString()
}

function bindings(plan, state) {
  if (
    plan === null
    || typeof plan !== 'object'
    || state === null
    || typeof state !== 'object'
    || state.schema_version !== '2.0.0'
  ) fail('UNLEASH_PAUSE_PROTOCOL_UNSUPPORTED', 'durable Pause is available only for protocol-v2 campaigns')
  return {
    campaign_id: state.campaign_id,
    plan_sha256: plan.plan_sha256,
    policy_id: plan.policy_id,
    policy_sha256: plan.policy_sha256,
    target_id: plan.target.target_id,
    revocation_check_id: plan.authority.revocation.check_id,
  }
}

function assertBound(record, expected) {
  return record.campaign_id === expected.campaign_id
    && record.plan_sha256 === expected.plan_sha256
    && record.policy_id === expected.policy_id
    && record.policy_sha256 === expected.policy_sha256
    && record.target_id === expected.target_id
    && record.revocation_check_id === expected.revocation_check_id
}

function canonicalTime(value) {
  const parsed = new Date(value)
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === value
}

function assertRequest(value, expected, filename) {
  if (
    !exact(value, [
      'schema_version', 'kind', 'campaign_id', 'plan_sha256', 'policy_id',
      'policy_sha256', 'target_id', 'revocation_check_id', 'pause_id', 'nonce',
      'request_index', 'requested_at', 'reason', 'request_sha256',
    ])
    || value.schema_version !== '1.0.0'
    || value.kind !== 'last-aperture/unleash-pause-request'
    || !assertBound(value, expected)
    || !PAUSE_ID.test(value.pause_id ?? '')
    || !/^[a-f0-9]{32}$/u.test(value.nonce ?? '')
    || !Number.isSafeInteger(value.request_index)
    || value.request_index < 1
    || value.request_index > MAX_PAUSE_REQUESTS
    || !canonicalTime(value.requested_at)
    || typeof value.reason !== 'string'
    || value.reason.length < 1
    || value.reason.length > 1024
    || /[\u0000-\u001f\u007f]/u.test(value.reason)
    || !SHA256.test(value.request_sha256 ?? '')
  ) fail('UNLEASH_PAUSE_REQUEST_INVALID', 'pause request is malformed or belongs to another campaign')
  const { request_sha256: requestSha256, ...unsigned } = value
  const suffix = value.pause_id.slice('pause:sha256:'.length)
  if (
    requestSha256 !== digestUnleashValue(unsigned)
    || value.pause_id !== `pause:sha256:${digestUnleashValue({
      ...expected,
      request_index: value.request_index,
    })}`
    || filename !== `campaign-pause-request-${suffix}.json`
  ) fail('UNLEASH_PAUSE_REQUEST_INVALID', 'pause request digest or filename binding changed')
  return frozen(value)
}

function assertAck(value, expected, request, filename) {
  if (
    !exact(value, [
      'schema_version', 'kind', 'campaign_id', 'plan_sha256', 'policy_id',
      'policy_sha256', 'target_id', 'revocation_check_id', 'pause_id',
      'request_sha256', 'owner_id', 'resumed_at', 'ack_sha256',
    ])
    || value.schema_version !== '1.0.0'
    || value.kind !== 'last-aperture/unleash-pause-resume'
    || !assertBound(value, expected)
    || value.pause_id !== request.pause_id
    || value.request_sha256 !== request.request_sha256
    || !OWNER_ID.test(value.owner_id ?? '')
    || !canonicalTime(value.resumed_at)
    || !SHA256.test(value.ack_sha256 ?? '')
  ) fail('UNLEASH_PAUSE_ACK_INVALID', 'pause resume acknowledgement is malformed or rebound')
  const { ack_sha256: ackSha256, ...unsigned } = value
  const suffix = request.pause_id.slice('pause:sha256:'.length)
  if (
    ackSha256 !== digestUnleashValue(unsigned)
    || filename !== `campaign-pause-resume-${suffix}.json`
  ) fail('UNLEASH_PAUSE_ACK_INVALID', 'pause acknowledgement digest or filename binding changed')
  return frozen(value)
}

function assertRollback(value, expected, request, filename) {
  if (
    !exact(value, [
      'schema_version', 'kind', 'campaign_id', 'plan_sha256', 'policy_id',
      'policy_sha256', 'target_id', 'revocation_check_id', 'pause_id',
      'request_sha256', 'requested_at', 'reason', 'scope',
      'target_side_effects_reversed', 'rollback_sha256',
    ])
    || value.schema_version !== '1.0.0'
    || value.kind !== 'last-aperture/unleash-local-rollback-request'
    || !assertBound(value, expected)
    || value.pause_id !== request.pause_id
    || value.request_sha256 !== request.request_sha256
    || !canonicalTime(value.requested_at)
    || typeof value.reason !== 'string'
    || value.reason.length < 8
    || value.reason.length > 1024
    || /[\u0000-\u001f\u007f]/u.test(value.reason)
    || JSON.stringify(value.scope) !== JSON.stringify(['NOT_YET_DISPATCHED', 'PROPOSED_INERT'])
    || value.target_side_effects_reversed !== false
    || !SHA256.test(value.rollback_sha256 ?? '')
  ) fail('UNLEASH_ROLLBACK_REQUEST_INVALID', 'local rollback request is malformed or rebound')
  const { rollback_sha256: rollbackSha256, ...unsigned } = value
  const suffix = request.pause_id.slice('pause:sha256:'.length)
  if (
    rollbackSha256 !== digestUnleashValue(unsigned)
    || filename !== `campaign-rollback-request-${suffix}.json`
  ) fail('UNLEASH_ROLLBACK_REQUEST_INVALID', 'local rollback digest or filename binding changed')
  return frozen(value)
}

function assertStorage(storage) {
  if (
    storage === null
    || typeof storage !== 'object'
    || typeof storage.listJsonFilenames !== 'function'
    || typeof storage.readJson !== 'function'
    || typeof storage.writeImmutableJson !== 'function'
  ) fail('UNLEASH_PAUSE_STORAGE_INVALID', 'pause control requires campaign storage')
}

export async function readUnleashCampaignPauseControl({ storage, plan, state } = {}) {
  assertStorage(storage)
  const expected = bindings(plan, state)
  const filenames = await storage.listJsonFilenames()
  const requestFiles = filenames.filter((name) => UNLEASH_PAUSE_REQUEST_FILE.test(name)).toSorted()
  if (requestFiles.length > MAX_PAUSE_REQUESTS) fail('UNLEASH_PAUSE_LIMIT', 'campaign pause control exceeds its bounded event limit')
  const requests = []
  const acknowledgements = []
  const rollbacks = []
  for (const filename of requestFiles) {
    requests.push(assertRequest(await storage.readJson(filename), expected, filename))
  }
  requests.sort((left, right) => left.request_index - right.request_index)
  if (requests.some(({ request_index: requestIndex }, index) => requestIndex !== index + 1)) {
    fail('UNLEASH_PAUSE_INVENTORY_INVALID', 'campaign pause request sequence is not contiguous')
  }
  for (const request of requests) {
    const suffix = request.pause_id.slice('pause:sha256:'.length)
    const ackFilename = `campaign-pause-resume-${suffix}.json`
    if (filenames.includes(ackFilename)) {
      acknowledgements.push(assertAck(
        await storage.readJson(ackFilename), expected, request, ackFilename,
      ))
    }
    const rollbackFilename = `campaign-rollback-request-${suffix}.json`
    if (filenames.includes(rollbackFilename)) {
      rollbacks.push(assertRollback(
        await storage.readJson(rollbackFilename), expected, request, rollbackFilename,
      ))
    }
  }
  const knownSuffixes = new Set(requests.map(({ pause_id: pauseId }) => pauseId.slice('pause:sha256:'.length)))
  const orphan = filenames.find((name) => {
    const ack = UNLEASH_PAUSE_ACK_FILE.exec(name)
    const rollback = UNLEASH_ROLLBACK_REQUEST_FILE.exec(name)
    return (ack !== null && !knownSuffixes.has(ack[1]))
      || (rollback !== null && !knownSuffixes.has(rollback[1]))
  })
  if (orphan !== undefined) fail('UNLEASH_PAUSE_INVENTORY_INVALID', `pause control contains an orphan artifact: ${orphan}`)
  const acknowledged = new Set(acknowledgements.map(({ pause_id: pauseId }) => pauseId))
  const active = requests.filter(({ pause_id: pauseId }) => !acknowledged.has(pauseId))
  return frozen({
    state: TERMINAL.has(state.status) ? 'SETTLED' : active.length > 0 ? 'PAUSED' : 'RUNNING',
    dispatch_open: !TERMINAL.has(state.status) && active.length === 0,
    request_count: requests.length,
    acknowledgement_count: acknowledgements.length,
    rollback_request_count: rollbacks.length,
    active_requests: active,
    requests,
    acknowledgements,
    rollbacks,
  })
}

export async function requestUnleashCampaignPause({ storage, plan, state, reason } = {}, {
  now = () => new Date(),
  randomBytes = systemRandomBytes,
} = {}) {
  const current = await readUnleashCampaignPauseControl({ storage, plan, state })
  if (TERMINAL.has(state.status) || current.active_requests.length > 0) return current
  if (current.request_count >= MAX_PAUSE_REQUESTS) {
    fail('UNLEASH_PAUSE_LIMIT', 'campaign pause control reached its bounded event limit')
  }
  if (
    typeof reason !== 'string'
    || reason.length < 1
    || reason.length > 1024
    || /[\u0000-\u001f\u007f]/u.test(reason)
  ) fail('UNLEASH_PAUSE_REASON_INVALID', 'pause reason must be one bounded human-readable string')
  if (typeof randomBytes !== 'function') fail('UNLEASH_PAUSE_RANDOM_INVALID', 'pause control requires a random source')
  const bytes = randomBytes(16)
  if (!Buffer.isBuffer(bytes) || bytes.length !== 16) {
    fail('UNLEASH_PAUSE_RANDOM_INVALID', 'pause random source must return exactly 16 bytes')
  }
  const expected = bindings(plan, state)
  const requestIndex = current.request_count + 1
  const base = {
    ...expected,
    nonce: bytes.toString('hex'),
    requested_at: timestamp(now),
    reason,
  }
  const pauseId = `pause:sha256:${digestUnleashValue({
    ...expected,
    request_index: requestIndex,
  })}`
  const unsigned = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-pause-request',
    ...expected,
    pause_id: pauseId,
    nonce: base.nonce,
    request_index: requestIndex,
    requested_at: base.requested_at,
    reason,
  }
  const request = { ...unsigned, request_sha256: digestUnleashValue(unsigned) }
  const filename = `campaign-pause-request-${pauseId.slice('pause:sha256:'.length)}.json`
  assertRequest(request, expected, filename)
  try {
    await storage.writeImmutableJson(filename, request)
  } catch (cause) {
    if (cause?.code !== 'UNLEASH_STORAGE_FILE_EXISTS') throw cause
  }
  return readUnleashCampaignPauseControl({ storage, plan, state })
}

export async function acknowledgeUnleashCampaignPause({ storage, plan, state, ownerId } = {}, {
  now = () => new Date(),
} = {}) {
  if (!OWNER_ID.test(ownerId ?? '')) fail('UNLEASH_PAUSE_OWNER_INVALID', 'pause Resume requires the exact swarm owner ID')
  const current = await readUnleashCampaignPauseControl({ storage, plan, state })
  const expected = bindings(plan, state)
  for (const request of current.active_requests) {
    const suffix = request.pause_id.slice('pause:sha256:'.length)
    const filename = `campaign-pause-resume-${suffix}.json`
    const unsigned = {
      schema_version: '1.0.0',
      kind: 'last-aperture/unleash-pause-resume',
      ...expected,
      pause_id: request.pause_id,
      request_sha256: request.request_sha256,
      owner_id: ownerId,
      resumed_at: timestamp(now),
    }
    const ack = { ...unsigned, ack_sha256: digestUnleashValue(unsigned) }
    try {
      await storage.writeImmutableJson(filename, ack)
    } catch (cause) {
      if (cause?.code !== 'UNLEASH_STORAGE_FILE_EXISTS') throw cause
      assertAck(await storage.readJson(filename), expected, request, filename)
    }
  }
  return readUnleashCampaignPauseControl({ storage, plan, state })
}

export async function requestUnleashLocalRollback({ storage, plan, state, reason } = {}, {
  now = () => new Date(),
} = {}) {
  const current = await readUnleashCampaignPauseControl({ storage, plan, state })
  const request = current.active_requests.at(-1)
  if (request === undefined || TERMINAL.has(state.status)) {
    fail('UNLEASH_ROLLBACK_REQUIRES_PAUSE', 'bounded local rollback requires one active Pause')
  }
  const expected = bindings(plan, state)
  const suffix = request.pause_id.slice('pause:sha256:'.length)
  const filename = `campaign-rollback-request-${suffix}.json`
  if (current.rollbacks.some(({ pause_id: pauseId }) => pauseId === request.pause_id)) return current
  const unsigned = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-local-rollback-request',
    ...expected,
    pause_id: request.pause_id,
    request_sha256: request.request_sha256,
    requested_at: timestamp(now),
    reason,
    scope: ['NOT_YET_DISPATCHED', 'PROPOSED_INERT'],
    target_side_effects_reversed: false,
  }
  const rollback = { ...unsigned, rollback_sha256: digestUnleashValue(unsigned) }
  assertRollback(rollback, expected, request, filename)
  await storage.writeImmutableJson(filename, rollback)
  return readUnleashCampaignPauseControl({ storage, plan, state })
}
