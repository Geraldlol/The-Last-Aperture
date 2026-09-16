import {
  assertValidUnleashRoleRequest,
  assertValidUnleashRoleResponseCapture,
  assertValidUnleashSwarmBasis,
} from './unleash-swarm-contracts.mjs'
import { digestUnleashValue } from './unleash-contracts.mjs'
import { canonicalUnleashCampaignJson } from './unleash-campaign-storage.mjs'
import {
  UNLEASH_REASONING_ADAPTER_MAX_LIMITS,
  assertValidUnleashReasoningAdapterIdentity,
} from './unleash-reasoning-adapter.mjs'

const SHA256 = /^[a-f0-9]{64}$/u
const ATTEMPT_ID = /^attempt:sha256:[a-f0-9]{64}$/u
const REASON_CODE = /^[A-Z][A-Z0-9_]{2,127}$/u
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u
const EVENT_FILENAME = /^swarm-attempt-event-([0-9]{6})\.json$/u
const EVENT_FIELDS = [
  'schema_version',
  'kind',
  'sequence',
  'previous_record_sha256',
  'basis_sha256',
  'campaign_id',
  'attempt_id',
  'request_id',
  'request_sha256',
  'round',
  'role_id',
  'adapter_identity',
  'request',
  'state',
  'occurred_at',
  'payload',
  'record_sha256',
]
const APPEND_FIELDS = [
  'basis',
  'attemptId',
  'request',
  'adapterIdentity',
  'state',
  'occurredAt',
  'payload',
]
const EVENT_CONTEXT_FIELDS = [
  'basis',
  'previousEvent',
  'previousAttemptEvent',
  'leaseEvent',
  'request',
]
const STATE_FIELDS = [
  'schema_version',
  'kind',
  'basis_sha256',
  'campaign_id',
  'event_count',
  'attempt_count',
  'response_bytes',
  'head_record_sha256',
  'ledger_sha256',
  'updated_at',
  'state_sha256',
]
const STATES = new Set(['LEASED', 'STARTED', 'CAPTURED', 'VALIDATED', 'COMMITTED', 'FAILED'])
const TERMINAL_STATES = new Set(['COMMITTED', 'FAILED'])
const TRANSITIONS = Object.freeze({
  LEASED: new Set(['STARTED', 'FAILED']),
  STARTED: new Set(['CAPTURED', 'FAILED']),
  CAPTURED: new Set(['VALIDATED', 'FAILED']),
  VALIDATED: new Set(['COMMITTED', 'FAILED']),
})
const trustedLedgers = new WeakSet()

export const UNLEASH_SWARM_ATTEMPT_LEDGER_STATE_FILE = 'swarm-attempt-ledger-state.json'
export const UNLEASH_SWARM_ATTEMPT_MAX_EVENTS_PER_ATTEMPT = 5

export class UnleashSwarmLedgerError extends Error {
  constructor(code, message, { cause } = {}) {
    super(message, cause === undefined ? undefined : { cause })
    this.name = 'UnleashSwarmLedgerError'
    this.code = code
  }
}

function fail(code, message, cause) {
  throw new UnleashSwarmLedgerError(code, message, { cause })
}

function exactDataRecord(value, fields) {
  let prototype
  let descriptors
  try {
    prototype = Object.getPrototypeOf(value)
    descriptors = Object.getOwnPropertyDescriptors(value)
  } catch {
    return null
  }
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || ![Object.prototype, null].includes(prototype)
  ) return null
  const keys = Reflect.ownKeys(descriptors)
  if (
    keys.length !== fields.length
    || keys.some((key) => typeof key !== 'string'
      || !fields.includes(key)
      || descriptors[key].enumerable !== true
      || !Object.hasOwn(descriptors[key], 'value'))
  ) return null
  return Object.fromEntries(fields.map((field) => [field, descriptors[field].value]))
}

function inputRecord(value, fields, message) {
  const record = exactDataRecord(value, fields)
  if (record === null) fail('UNLEASH_SWARM_LEDGER_INPUT_INVALID', message)
  return record
}

function deeplyFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const nested of Object.values(value)) deeplyFreeze(nested)
  return Object.freeze(value)
}

function safeJsonSnapshot(value, label, code = 'UNLEASH_SWARM_LEDGER_VALUE_INVALID') {
  try {
    return deeplyFreeze(JSON.parse(canonicalUnleashCampaignJson(value)))
  } catch (cause) {
    fail(code, `${label} must be bounded getter-free canonical plain JSON`, cause)
  }
}

function canonicalTimestamp(value, label) {
  if (
    typeof value !== 'string'
    || !TIMESTAMP.test(value)
    || !Number.isFinite(Date.parse(value))
    || new Date(value).toISOString() !== value
  ) fail('UNLEASH_SWARM_LEDGER_TIME_INVALID', `${label} must be one canonical UTC timestamp`)
  return value
}

function assertSha256(value, label) {
  if (typeof value !== 'string' || !SHA256.test(value)) {
    fail('UNLEASH_SWARM_LEDGER_BINDING_INVALID', `${label} must be a lowercase SHA-256 digest`)
  }
}

function digestWithout(value, field) {
  const unsigned = { ...value }
  delete unsigned[field]
  return digestUnleashValue(unsigned)
}

function sameJson(left, right) {
  return digestUnleashValue(left) === digestUnleashValue(right)
}

function assertStorage(value) {
  const fields = ['writeImmutableJson', 'replaceMutableJson', 'readJson', 'listJsonFilenames']
  const storage = exactDataRecord(value, fields)
  if (storage === null || fields.some((field) => typeof storage[field] !== 'function')) {
    fail('UNLEASH_SWARM_LEDGER_STORAGE_INVALID', 'swarm ledger storage is invalid')
  }
  return storage
}

function dependencies(value) {
  const retained = inputRecord(value, ['storage'], 'swarm ledger dependencies must contain exact storage')
  return { storage: assertStorage(retained.storage) }
}

function snapshotBasis(value) {
  const basis = safeJsonSnapshot(value, 'swarm basis')
  try {
    assertValidUnleashSwarmBasis(basis)
  } catch (cause) {
    fail('UNLEASH_SWARM_LEDGER_BASIS_INVALID', 'swarm ledger basis is invalid', cause)
  }
  return basis
}

function snapshotRequest(value, basis) {
  const request = safeJsonSnapshot(value, 'role request')
  try {
    assertValidUnleashRoleRequest(request, { basis })
  } catch (cause) {
    fail('UNLEASH_SWARM_LEDGER_REQUEST_INVALID', 'swarm ledger request is invalid', cause)
  }
  return request
}

function snapshotAdapterIdentity(value) {
  const identity = safeJsonSnapshot(value, 'reasoning adapter identity')
  try {
    assertValidUnleashReasoningAdapterIdentity(identity)
  } catch (cause) {
    fail('UNLEASH_SWARM_LEDGER_ADAPTER_INVALID', 'swarm ledger adapter identity is invalid', cause)
  }
  return identity
}

function assertAttemptLimits(value, request) {
  const limits = exactDataRecord(value, [
    'wall_time_ms', 'max_response_bytes', 'max_frame_bytes', 'max_frames',
  ])
  if (limits === null) fail('UNLEASH_SWARM_LEDGER_PAYLOAD_INVALID', 'attempt limits are not exact')
  for (const [field, maximum] of Object.entries({
    wall_time_ms: UNLEASH_REASONING_ADAPTER_MAX_LIMITS.wall_time_ms,
    max_response_bytes: UNLEASH_REASONING_ADAPTER_MAX_LIMITS.max_response_bytes,
    max_frame_bytes: UNLEASH_REASONING_ADAPTER_MAX_LIMITS.max_frame_bytes,
    max_frames: UNLEASH_REASONING_ADAPTER_MAX_LIMITS.max_frames,
  })) {
    if (!Number.isSafeInteger(limits[field]) || limits[field] < 1 || limits[field] > maximum) {
      fail('UNLEASH_SWARM_LEDGER_PAYLOAD_INVALID', `attempt ${field} is outside its bound`)
    }
  }
  if (
    limits.max_frame_bytes > limits.max_response_bytes
    || limits.max_response_bytes > request.limits.max_response_bytes
  ) fail('UNLEASH_SWARM_LEDGER_PAYLOAD_INVALID', 'attempt limits exceed the exact role request')
  return limits
}

function assertPayload(event, previousAttemptEvent, leaseEvent, request) {
  const payload = event.payload
  if (event.state === 'LEASED') {
    const lease = exactDataRecord(payload, ['expires_at', 'limits'])
    if (lease === null) fail('UNLEASH_SWARM_LEDGER_PAYLOAD_INVALID', 'LEASED payload is invalid')
    canonicalTimestamp(lease.expires_at, 'lease expires_at')
    const limits = assertAttemptLimits(lease.limits, request)
    if (Date.parse(lease.expires_at) !== Date.parse(event.occurred_at) + limits.wall_time_ms) {
      fail('UNLEASH_SWARM_LEDGER_TIME_INVALID', 'lease expiry must equal its exact wall-time budget')
    }
    return
  }
  if (event.state === 'STARTED') {
    if (exactDataRecord(payload, []) === null) {
      fail('UNLEASH_SWARM_LEDGER_PAYLOAD_INVALID', 'STARTED payload must be empty')
    }
    if (Date.parse(event.occurred_at) >= Date.parse(previousAttemptEvent.payload.expires_at)) {
      fail('UNLEASH_SWARM_LEDGER_TIME_INVALID', 'attempt cannot start after its lease expired')
    }
    return
  }
  if (event.state === 'CAPTURED') {
    const captured = exactDataRecord(payload, ['capture'])
    if (captured === null) fail('UNLEASH_SWARM_LEDGER_PAYLOAD_INVALID', 'CAPTURED payload is invalid')
    try {
      assertValidUnleashRoleResponseCapture(captured.capture, { request })
    } catch (cause) {
      fail('UNLEASH_SWARM_LEDGER_CAPTURE_INVALID', 'CAPTURED payload is not an exact response capture', cause)
    }
    if (
      captured.capture.adapter_id !== event.adapter_identity.adapter_id
      || captured.capture.adapter_version !== event.adapter_identity.adapter_version
      || captured.capture.adapter_config_sha256 !== event.adapter_identity.adapter_config_sha256
      || Date.parse(captured.capture.captured_at) < Date.parse(previousAttemptEvent.occurred_at)
      || Date.parse(captured.capture.captured_at) > Date.parse(event.occurred_at)
      || Date.parse(captured.capture.captured_at) > Date.parse(leaseEvent.payload.expires_at)
      || captured.capture.response_bytes > leaseEvent.payload.limits.max_response_bytes
    ) fail('UNLEASH_SWARM_LEDGER_CAPTURE_INVALID', 'response capture differs from the attempt binding or time')
    return
  }
  if (event.state === 'VALIDATED') {
    const validated = exactDataRecord(payload, [
      'capture_sha256', 'response_sha256', 'validated_response_sha256',
    ])
    if (validated === null) fail('UNLEASH_SWARM_LEDGER_PAYLOAD_INVALID', 'VALIDATED payload is invalid')
    for (const field of ['capture_sha256', 'response_sha256', 'validated_response_sha256']) {
      assertSha256(validated[field], `VALIDATED ${field}`)
    }
    const capture = previousAttemptEvent.payload.capture
    if (
      validated.capture_sha256 !== capture.capture_sha256
      || validated.response_sha256 !== capture.response_sha256
    ) fail('UNLEASH_SWARM_LEDGER_CAPTURE_INVALID', 'VALIDATED payload differs from retained captured bytes')
    return
  }
  if (event.state === 'COMMITTED') {
    const committed = exactDataRecord(payload, ['merge_sha256'])
    if (committed === null) fail('UNLEASH_SWARM_LEDGER_PAYLOAD_INVALID', 'COMMITTED payload is invalid')
    assertSha256(committed.merge_sha256, 'COMMITTED merge_sha256')
    return
  }
  const failed = exactDataRecord(payload, ['reason_code', 'phase', 'delivery', 'detail_sha256'])
  if (
    failed === null
    || typeof failed.reason_code !== 'string'
    || !REASON_CODE.test(failed.reason_code)
    || !['LEASED', 'STARTED', 'CAPTURED', 'VALIDATED'].includes(failed.phase)
    || !['NOT_STARTED', 'AMBIGUOUS', 'CAPTURED'].includes(failed.delivery)
  ) fail('UNLEASH_SWARM_LEDGER_PAYLOAD_INVALID', 'FAILED payload is invalid')
  assertSha256(failed.detail_sha256, 'FAILED detail_sha256')
  const expectedDelivery = previousAttemptEvent.state === 'LEASED'
    ? 'NOT_STARTED'
    : previousAttemptEvent.state === 'STARTED'
      ? 'AMBIGUOUS'
      : 'CAPTURED'
  if (failed.phase !== previousAttemptEvent.state || failed.delivery !== expectedDelivery) {
    fail('UNLEASH_SWARM_LEDGER_PAYLOAD_INVALID', 'FAILED payload understates its prior delivery state')
  }
}

export function unleashSwarmAttemptEventFilename(sequence) {
  if (!Number.isSafeInteger(sequence) || sequence < 1 || sequence > 999_999) {
    fail('UNLEASH_SWARM_LEDGER_SEQUENCE_INVALID', 'swarm attempt event sequence is invalid')
  }
  return `swarm-attempt-event-${String(sequence).padStart(6, '0')}.json`
}

export function assertValidUnleashSwarmAttemptEvent(value, context) {
  const retained = inputRecord(context, EVENT_CONTEXT_FIELDS, 'event validation context is invalid')
  const basis = snapshotBasis(retained.basis)
  const request = snapshotRequest(retained.request, basis)
  const event = safeJsonSnapshot(value, 'swarm attempt event')
  if (exactDataRecord(event, EVENT_FIELDS) === null) {
    fail('UNLEASH_SWARM_LEDGER_EVENT_INVALID', 'swarm attempt event contains missing or unknown fields')
  }
  canonicalTimestamp(event.occurred_at, 'event occurred_at')
  if (
    event.schema_version !== '1.0.0'
    || event.kind !== 'last-aperture/unleash-swarm-attempt-event'
    || !Number.isSafeInteger(event.sequence)
    || event.sequence < 1
    || event.sequence > basis.limits.max_provider_calls * UNLEASH_SWARM_ATTEMPT_MAX_EVENTS_PER_ATTEMPT
    || event.basis_sha256 !== basis.basis_sha256
    || event.campaign_id !== basis.campaign_id
    || typeof event.attempt_id !== 'string'
    || !ATTEMPT_ID.test(event.attempt_id)
    || event.request_id !== request.request_id
    || event.request_sha256 !== request.request_sha256
    || event.round !== request.round
    || event.role_id !== request.role_id
    || !STATES.has(event.state)
    || event.record_sha256 !== digestWithout(event, 'record_sha256')
    || !sameJson(event.request, request)
  ) fail('UNLEASH_SWARM_LEDGER_EVENT_INVALID', 'swarm attempt event identity, binding, or digest is invalid')
  const identity = snapshotAdapterIdentity(event.adapter_identity)
  if (!sameJson(identity, event.adapter_identity)) {
    fail('UNLEASH_SWARM_LEDGER_ADAPTER_INVALID', 'swarm attempt adapter identity changed')
  }
  if (Date.parse(event.occurred_at) < Date.parse(basis.recorded_at)) {
    fail('UNLEASH_SWARM_LEDGER_TIME_INVALID', 'swarm attempt event predates its basis')
  }

  const previousEvent = retained.previousEvent === null
    ? null
    : safeJsonSnapshot(retained.previousEvent, 'previous swarm attempt event')
  if (
    (previousEvent === null && (event.sequence !== 1 || event.previous_record_sha256 !== null))
    || (previousEvent !== null && (
      event.sequence !== previousEvent.sequence + 1
      || event.previous_record_sha256 !== previousEvent.record_sha256
      || previousEvent.record_sha256 !== digestWithout(previousEvent, 'record_sha256')
      || Date.parse(event.occurred_at) < Date.parse(previousEvent.occurred_at)
    ))
  ) fail('UNLEASH_SWARM_LEDGER_CHAIN_INVALID', 'swarm attempt event does not extend the exact global chain')

  const previousAttemptEvent = retained.previousAttemptEvent === null
    ? null
    : safeJsonSnapshot(retained.previousAttemptEvent, 'previous attempt event')
  const leaseEvent = retained.leaseEvent === null
    ? null
    : safeJsonSnapshot(retained.leaseEvent, 'attempt lease event')
  if (event.state === 'LEASED') {
    if (previousAttemptEvent !== null || leaseEvent !== null) {
      fail('UNLEASH_SWARM_LEDGER_TRANSITION_INVALID', 'LEASED must start a new attempt')
    }
  } else if (
    previousAttemptEvent === null
    || leaseEvent === null
    || leaseEvent.state !== 'LEASED'
    || leaseEvent.attempt_id !== event.attempt_id
    || leaseEvent.request_sha256 !== event.request_sha256
    || !sameJson(leaseEvent.adapter_identity, event.adapter_identity)
    || previousAttemptEvent.attempt_id !== event.attempt_id
    || previousAttemptEvent.request_sha256 !== event.request_sha256
    || !sameJson(previousAttemptEvent.adapter_identity, event.adapter_identity)
    || !TRANSITIONS[previousAttemptEvent.state]?.has(event.state)
    || Date.parse(event.occurred_at) < Date.parse(previousAttemptEvent.occurred_at)
  ) fail('UNLEASH_SWARM_LEDGER_TRANSITION_INVALID', 'swarm attempt state transition is invalid')
  assertPayload(event, previousAttemptEvent, leaseEvent, request)
  return value
}

function ledgerDigest(basis, events) {
  return digestUnleashValue({
    basis_sha256: basis.basis_sha256,
    event_record_sha256s: events.map(({ record_sha256: digest }) => digest),
  })
}

function projectAttempts(basis, events) {
  const attempts = new Map()
  let responseBytes = 0
  for (const event of events) {
    let attempt = attempts.get(event.attempt_id)
    if (event.state === 'LEASED') {
      if (attempt !== undefined) {
        fail('UNLEASH_SWARM_LEDGER_TRANSITION_INVALID', 'swarm attempt was leased more than once')
      }
      const sameRequest = [...attempts.values()]
        .filter((candidate) => candidate.request_id === event.request_id)
      if (sameRequest.some((candidate) => (
        candidate.state !== 'FAILED' || candidate.failure?.delivery !== 'NOT_STARTED'
      ))) {
        fail(
          sameRequest.some((candidate) => (
            candidate.state === 'STARTED' || candidate.failure?.delivery === 'AMBIGUOUS'
          ))
            ? 'UNLEASH_SWARM_ATTEMPT_REPLAY_AMBIGUOUS'
            : 'UNLEASH_SWARM_ATTEMPT_REPLAY_FORBIDDEN',
          'retained events replay the same role request after possible provider delivery',
        )
      }
      if (attempts.size >= basis.limits.max_provider_calls) {
        fail('UNLEASH_SWARM_ATTEMPT_LIMIT', 'retained attempts exceed the sealed provider-call budget')
      }
      attempt = {
        attempt_id: event.attempt_id,
        request_id: event.request_id,
        request_sha256: event.request_sha256,
        round: event.round,
        role_id: event.role_id,
        adapter_identity: structuredClone(event.adapter_identity),
        state: 'LEASED',
        lease_sequence: event.sequence,
        leased_at: event.occurred_at,
        expires_at: event.payload.expires_at,
        limits: structuredClone(event.payload.limits),
        capture: null,
        validated_response_sha256: null,
        merge_sha256: null,
        failure: null,
      }
      attempts.set(event.attempt_id, attempt)
      continue
    }
    if (event.state === 'CAPTURED') {
      if (event.payload.capture.response_bytes > attempt.limits.max_response_bytes) {
        fail('UNLEASH_SWARM_LEDGER_RESPONSE_LIMIT', 'captured response exceeds its attempt byte limit')
      }
      attempt.capture = structuredClone(event.payload.capture)
      responseBytes += event.payload.capture.response_bytes
    } else if (event.state === 'VALIDATED') {
      attempt.validated_response_sha256 = event.payload.validated_response_sha256
    } else if (event.state === 'COMMITTED') {
      attempt.merge_sha256 = event.payload.merge_sha256
    } else if (event.state === 'FAILED') {
      attempt.failure = structuredClone(event.payload)
    }
    attempt.state = event.state
  }
  if (responseBytes > basis.limits.max_total_response_bytes) {
    fail('UNLEASH_SWARM_LEDGER_RESPONSE_LIMIT', 'retained response captures exceed the swarm byte budget')
  }
  return {
    attempts: [...attempts.values()].sort((left, right) => left.lease_sequence - right.lease_sequence),
    responseBytes,
  }
}

function createLedger(basis, events, reconciliation) {
  const projected = projectAttempts(basis, events)
  const ledger = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-swarm-attempt-ledger',
    basis_sha256: basis.basis_sha256,
    campaign_id: basis.campaign_id,
    event_count: events.length,
    attempt_count: projected.attempts.length,
    response_bytes: projected.responseBytes,
    head_record_sha256: events.at(-1)?.record_sha256 ?? null,
    events: structuredClone(events),
    attempts: projected.attempts,
    ledger_sha256: ledgerDigest(basis, events),
    reconciliation,
  }
  const frozen = deeplyFreeze(ledger)
  trustedLedgers.add(frozen)
  return frozen
}

function assertTrustedLedger(value, basis = undefined) {
  if (
    value === null
    || typeof value !== 'object'
    || !trustedLedgers.has(value)
    || value.kind !== 'last-aperture/unleash-swarm-attempt-ledger'
    || value.schema_version !== '1.0.0'
    || value.event_count !== value.events.length
    || value.attempt_count !== value.attempts.length
    || value.head_record_sha256 !== (value.events.at(-1)?.record_sha256 ?? null)
    || (basis !== undefined && (
      value.basis_sha256 !== basis.basis_sha256
      || value.campaign_id !== basis.campaign_id
      || value.ledger_sha256 !== ledgerDigest(basis, value.events)
    ))
  ) fail('UNLEASH_SWARM_LEDGER_INVALID', 'swarm attempt ledger is not an authenticated recovered projection')
  return value
}

function stateBody(basis, ledger, updatedAt) {
  const unsigned = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-swarm-attempt-ledger-state',
    basis_sha256: basis.basis_sha256,
    campaign_id: basis.campaign_id,
    event_count: ledger.event_count,
    attempt_count: ledger.attempt_count,
    response_bytes: ledger.response_bytes,
    head_record_sha256: ledger.head_record_sha256,
    ledger_sha256: ledger.ledger_sha256,
    updated_at: canonicalTimestamp(updatedAt, 'ledger state updated_at'),
  }
  return deeplyFreeze({ ...unsigned, state_sha256: digestUnleashValue(unsigned) })
}

export function createUnleashSwarmAttemptLedgerState(value) {
  const input = inputRecord(value, ['basis', 'ledger', 'updatedAt'], 'ledger state input is invalid')
  const basis = snapshotBasis(input.basis)
  const ledger = assertTrustedLedger(input.ledger, basis)
  if (
    ledger.basis_sha256 !== basis.basis_sha256
    || ledger.campaign_id !== basis.campaign_id
    || ledger.ledger_sha256 !== ledgerDigest(basis, ledger.events)
  ) fail('UNLEASH_SWARM_LEDGER_STATE_INVALID', 'ledger state input differs from its basis or event chain')
  const state = stateBody(basis, ledger, input.updatedAt)
  assertValidUnleashSwarmAttemptLedgerState(state, { basis, ledger })
  return state
}

function assertStateBase(value, basis) {
  const state = safeJsonSnapshot(value, 'swarm attempt ledger state')
  if (exactDataRecord(state, STATE_FIELDS) === null) {
    fail('UNLEASH_SWARM_LEDGER_STATE_INVALID', 'swarm attempt ledger state contains missing or unknown fields')
  }
  canonicalTimestamp(state.updated_at, 'ledger state updated_at')
  if (
    state.schema_version !== '1.0.0'
    || state.kind !== 'last-aperture/unleash-swarm-attempt-ledger-state'
    || state.basis_sha256 !== basis.basis_sha256
    || state.campaign_id !== basis.campaign_id
    || !Number.isSafeInteger(state.event_count)
    || state.event_count < 0
    || state.event_count > basis.limits.max_provider_calls * UNLEASH_SWARM_ATTEMPT_MAX_EVENTS_PER_ATTEMPT
    || !Number.isSafeInteger(state.attempt_count)
    || state.attempt_count < 0
    || state.attempt_count > basis.limits.max_provider_calls
    || !Number.isSafeInteger(state.response_bytes)
    || state.response_bytes < 0
    || state.response_bytes > basis.limits.max_total_response_bytes
    || (state.event_count === 0 ? state.head_record_sha256 !== null : !SHA256.test(state.head_record_sha256 ?? ''))
    || !SHA256.test(state.ledger_sha256 ?? '')
    || state.state_sha256 !== digestWithout(state, 'state_sha256')
    || Date.parse(state.updated_at) < Date.parse(basis.recorded_at)
  ) fail('UNLEASH_SWARM_LEDGER_STATE_INVALID', 'swarm attempt ledger state identity, counts, or digest is invalid')
  return state
}

export function assertValidUnleashSwarmAttemptLedgerState(value, context) {
  const retained = inputRecord(context, ['basis', 'ledger'], 'ledger state validation context is invalid')
  const basis = snapshotBasis(retained.basis)
  const ledger = assertTrustedLedger(retained.ledger, basis)
  const state = assertStateBase(value, basis)
  if (
    state.event_count !== ledger.event_count
    || state.attempt_count !== ledger.attempt_count
    || state.response_bytes !== ledger.response_bytes
    || state.head_record_sha256 !== ledger.head_record_sha256
    || state.ledger_sha256 !== ledger.ledger_sha256
  ) fail('UNLEASH_SWARM_LEDGER_STATE_INVALID', 'ledger state differs from the recovered event chain')
  const lastOccurredAt = ledger.events.at(-1)?.occurred_at ?? basis.recorded_at
  if (Date.parse(state.updated_at) < Date.parse(lastOccurredAt)) {
    fail('UNLEASH_SWARM_LEDGER_TIME_INVALID', 'ledger state predates its recovered event chain')
  }
  return value
}

function eventFilenames(filenames) {
  const malformed = filenames.find((filename) => (
    filename.startsWith('swarm-attempt-')
    && filename !== UNLEASH_SWARM_ATTEMPT_LEDGER_STATE_FILE
    && !EVENT_FILENAME.test(filename)
  ))
  if (malformed !== undefined) {
    fail('UNLEASH_SWARM_LEDGER_ENTRY_INVALID', 'campaign storage contains a malformed swarm attempt entry')
  }
  const events = filenames.filter((filename) => EVENT_FILENAME.test(filename)).sort()
  for (const [index, filename] of events.entries()) {
    const observed = Number(EVENT_FILENAME.exec(filename)[1])
    if (observed !== index + 1) {
      fail('UNLEASH_SWARM_LEDGER_GAP', 'swarm attempt ledger contains a missing or displaced event')
    }
  }
  return events
}

function sameStringArray(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index])
}

function compareStateToChain(state, basis, events) {
  if (state.event_count > events.length) {
    fail('UNLEASH_SWARM_LEDGER_ROLLBACK', 'retained swarm ledger head is ahead of its event files')
  }
  const prefix = events.slice(0, state.event_count)
  const prefixLedger = createLedger(basis, prefix, 'CURRENT')
  if (
    state.attempt_count !== prefixLedger.attempt_count
    || state.response_bytes !== prefixLedger.response_bytes
    || state.head_record_sha256 !== prefixLedger.head_record_sha256
    || state.ledger_sha256 !== prefixLedger.ledger_sha256
  ) fail('UNLEASH_SWARM_LEDGER_ROLLBACK', 'retained swarm ledger head does not bind the surviving event prefix')
  const prefixOccurredAt = prefix.at(-1)?.occurred_at ?? basis.recorded_at
  if (Date.parse(state.updated_at) < Date.parse(prefixOccurredAt)) {
    fail('UNLEASH_SWARM_LEDGER_ROLLBACK', 'retained swarm ledger head predates its claimed event prefix')
  }
  return state.event_count === events.length ? 'CURRENT' : 'REPAIR_REQUIRED'
}

export async function recoverUnleashSwarmAttemptLedger(value, dependencyValues) {
  const input = inputRecord(value, ['basis'], 'swarm ledger recovery input is invalid')
  const basis = snapshotBasis(input.basis)
  const { storage } = dependencies(dependencyValues)
  const filenamesBefore = await storage.listJsonFilenames()
  const eventsBefore = eventFilenames([...filenamesBefore])
  if (!filenamesBefore.includes(UNLEASH_SWARM_ATTEMPT_LEDGER_STATE_FILE)) {
    fail('UNLEASH_SWARM_LEDGER_STATE_MISSING', 'swarm attempt ledger state is missing')
  }
  if (eventsBefore.length > basis.limits.max_provider_calls * UNLEASH_SWARM_ATTEMPT_MAX_EVENTS_PER_ATTEMPT) {
    fail('UNLEASH_SWARM_LEDGER_EVENT_LIMIT', 'swarm attempt ledger exceeds its event bound')
  }
  const stateBeforeValue = await storage.readJson(UNLEASH_SWARM_ATTEMPT_LEDGER_STATE_FILE)
  const eventValues = []
  for (const filename of eventsBefore) eventValues.push(await storage.readJson(filename))
  const confirmedEventValues = []
  for (const filename of eventsBefore) confirmedEventValues.push(await storage.readJson(filename))
  const stateAfterValue = await storage.readJson(UNLEASH_SWARM_ATTEMPT_LEDGER_STATE_FILE)
  const filenamesAfter = await storage.listJsonFilenames()
  const eventsAfter = eventFilenames([...filenamesAfter])
  if (
    !sameStringArray(eventsBefore, eventsAfter)
    || digestUnleashValue(stateBeforeValue) !== digestUnleashValue(stateAfterValue)
    || eventValues.some((event, index) => !sameJson(event, confirmedEventValues[index]))
  ) fail('UNLEASH_SWARM_LEDGER_CHANGED', 'swarm attempt ledger changed during recovery')

  const state = assertStateBase(stateAfterValue, basis)
  const events = []
  const lastByAttempt = new Map()
  const leaseByAttempt = new Map()
  for (const eventValue of eventValues) {
    const candidate = safeJsonSnapshot(eventValue, 'swarm attempt event')
    const previousEvent = events.at(-1) ?? null
    const previousAttemptEvent = lastByAttempt.get(candidate.attempt_id) ?? null
    const leaseEvent = leaseByAttempt.get(candidate.attempt_id) ?? null
    assertValidUnleashSwarmAttemptEvent(candidate, {
      basis,
      previousEvent,
      previousAttemptEvent,
      leaseEvent,
      request: candidate.request,
    })
    events.push(candidate)
    lastByAttempt.set(candidate.attempt_id, candidate)
    if (candidate.state === 'LEASED') leaseByAttempt.set(candidate.attempt_id, candidate)
  }
  const reconciliation = compareStateToChain(state, basis, events)
  const ledger = createLedger(basis, events, reconciliation)
  if (reconciliation === 'CURRENT') {
    assertValidUnleashSwarmAttemptLedgerState(state, { basis, ledger })
  }
  return ledger
}

export async function initializeUnleashSwarmAttemptLedger(value, dependencyValues) {
  const input = inputRecord(value, ['basis', 'initializedAt'], 'swarm ledger initialization input is invalid')
  const basis = snapshotBasis(input.basis)
  const initializedAt = canonicalTimestamp(input.initializedAt, 'ledger initializedAt')
  if (Date.parse(initializedAt) < Date.parse(basis.recorded_at)) {
    fail('UNLEASH_SWARM_LEDGER_TIME_INVALID', 'ledger initialization predates its swarm basis')
  }
  const deps = dependencies(dependencyValues)
  const filenames = await deps.storage.listJsonFilenames()
  if (filenames.includes(UNLEASH_SWARM_ATTEMPT_LEDGER_STATE_FILE)) {
    return recoverUnleashSwarmAttemptLedger({ basis }, deps)
  }
  if (eventFilenames([...filenames]).length > 0) {
    fail('UNLEASH_SWARM_LEDGER_STATE_MISSING', 'event files exist without the initialized ledger state')
  }
  const empty = createLedger(basis, [], 'CURRENT')
  await deps.storage.replaceMutableJson(
    UNLEASH_SWARM_ATTEMPT_LEDGER_STATE_FILE,
    stateBody(basis, empty, initializedAt),
  )
  return recoverUnleashSwarmAttemptLedger({ basis }, deps)
}

export async function reconcileUnleashSwarmAttemptLedger(value, dependencyValues) {
  const input = inputRecord(value, ['basis', 'updatedAt'], 'swarm ledger reconciliation input is invalid')
  const basis = snapshotBasis(input.basis)
  const updatedAt = canonicalTimestamp(input.updatedAt, 'ledger updatedAt')
  const deps = dependencies(dependencyValues)
  const ledger = await recoverUnleashSwarmAttemptLedger({ basis }, deps)
  if (ledger.reconciliation === 'CURRENT') return ledger
  const lastOccurredAt = ledger.events.at(-1)?.occurred_at ?? basis.recorded_at
  if (Date.parse(updatedAt) < Date.parse(lastOccurredAt)) {
    fail('UNLEASH_SWARM_LEDGER_TIME_INVALID', 'reconciled ledger state predates its event chain')
  }
  await deps.storage.replaceMutableJson(
    UNLEASH_SWARM_ATTEMPT_LEDGER_STATE_FILE,
    stateBody(basis, ledger, updatedAt),
  )
  return recoverUnleashSwarmAttemptLedger({ basis }, deps)
}

function assertRequestCanLease(ledger, basis, attemptId, request) {
  if (ledger.attempts.some((attempt) => attempt.attempt_id === attemptId)) {
    fail('UNLEASH_SWARM_ATTEMPT_DUPLICATE', 'swarm attempt ID already exists')
  }
  const prior = ledger.attempts.filter((attempt) => attempt.request_id === request.request_id)
  if (prior.some((attempt) => (
    attempt.state !== 'FAILED' || attempt.failure?.delivery !== 'NOT_STARTED'
  ))) {
    fail(
      prior.some((attempt) => attempt.state === 'STARTED' || attempt.failure?.delivery === 'AMBIGUOUS')
        ? 'UNLEASH_SWARM_ATTEMPT_REPLAY_AMBIGUOUS'
        : 'UNLEASH_SWARM_ATTEMPT_REPLAY_FORBIDDEN',
      'the same role request may not be replayed after possible provider delivery',
    )
  }
  if (ledger.attempt_count >= basis.limits.max_provider_calls) {
    fail('UNLEASH_SWARM_ATTEMPT_LIMIT', 'swarm attempt count exceeds the sealed provider-call budget')
  }
}

function createEvent({ basis, ledger, attemptId, request, adapterIdentity, state, occurredAt, payload }) {
  const previousEvent = ledger.events.at(-1) ?? null
  const previousAttemptEvent = [...ledger.events].reverse()
    .find((event) => event.attempt_id === attemptId) ?? null
  const leaseEvent = ledger.events
    .find((event) => event.attempt_id === attemptId && event.state === 'LEASED') ?? null
  const unsigned = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-swarm-attempt-event',
    sequence: ledger.event_count + 1,
    previous_record_sha256: previousEvent?.record_sha256 ?? null,
    basis_sha256: basis.basis_sha256,
    campaign_id: basis.campaign_id,
    attempt_id: attemptId,
    request_id: request.request_id,
    request_sha256: request.request_sha256,
    round: request.round,
    role_id: request.role_id,
    adapter_identity: structuredClone(adapterIdentity),
    request: structuredClone(request),
    state,
    occurred_at: occurredAt,
    payload: structuredClone(payload),
  }
  const event = deeplyFreeze({ ...unsigned, record_sha256: digestUnleashValue(unsigned) })
  assertValidUnleashSwarmAttemptEvent(event, {
    basis,
    previousEvent,
    previousAttemptEvent,
    leaseEvent,
    request,
  })
  return event
}

export async function appendUnleashSwarmAttemptEvent(value, dependencyValues) {
  const retained = inputRecord(value, APPEND_FIELDS, 'swarm attempt append input is invalid')
  const basis = snapshotBasis(retained.basis)
  const request = snapshotRequest(retained.request, basis)
  const adapterIdentity = snapshotAdapterIdentity(retained.adapterIdentity)
  const state = retained.state
  if (typeof state !== 'string' || !STATES.has(state)) {
    fail('UNLEASH_SWARM_LEDGER_INPUT_INVALID', 'swarm attempt state is invalid')
  }
  const occurredAt = canonicalTimestamp(retained.occurredAt, 'event occurredAt')
  const payload = safeJsonSnapshot(retained.payload, 'swarm attempt payload')
  const deps = dependencies(dependencyValues)
  let ledger = await recoverUnleashSwarmAttemptLedger({ basis }, deps)
  if (ledger.reconciliation === 'REPAIR_REQUIRED') {
    ledger = await reconcileUnleashSwarmAttemptLedger({ basis, updatedAt: occurredAt }, deps)
  }

  const attemptId = retained.attemptId
  if (typeof attemptId !== 'string' || !ATTEMPT_ID.test(attemptId)) {
    fail('UNLEASH_SWARM_LEDGER_INPUT_INVALID', 'swarm attempt ID is invalid')
  }
  const existing = ledger.attempts.find((attempt) => attempt.attempt_id === attemptId)
  if (state === 'LEASED') {
    assertRequestCanLease(ledger, basis, attemptId, request)
  } else if (
    existing === undefined
    || existing.request_sha256 !== request.request_sha256
    || !sameJson(existing.adapter_identity, adapterIdentity)
  ) fail('UNLEASH_SWARM_LEDGER_TRANSITION_INVALID', 'swarm attempt continuation differs from its lease')

  const event = createEvent({
    basis,
    ledger,
    attemptId,
    request,
    adapterIdentity,
    state,
    occurredAt,
    payload,
  })
  const filename = unleashSwarmAttemptEventFilename(event.sequence)
  try {
    await deps.storage.writeImmutableJson(filename, event)
  } catch (cause) {
    fail(
      cause?.code === 'UNLEASH_STORAGE_FILE_EXISTS'
        ? 'UNLEASH_SWARM_LEDGER_CONCURRENT_APPEND'
        : 'UNLEASH_SWARM_LEDGER_WRITE_FAILED',
      'swarm attempt event could not be appended immutably',
      cause,
    )
  }
  const nextLedger = createLedger(basis, [...ledger.events, event], 'CURRENT')
  await deps.storage.replaceMutableJson(
    UNLEASH_SWARM_ATTEMPT_LEDGER_STATE_FILE,
    stateBody(basis, nextLedger, occurredAt),
  )
  const recovered = await recoverUnleashSwarmAttemptLedger({ basis }, deps)
  if (
    recovered.reconciliation !== 'CURRENT'
    || recovered.head_record_sha256 !== event.record_sha256
  ) fail('UNLEASH_SWARM_LEDGER_WRITE_FAILED', 'appended swarm event did not become the verified ledger head')
  return recovered
}

export function classifyUnleashSwarmAttemptRecovery(value) {
  const input = inputRecord(value, ['ledger', 'attemptId'], 'attempt recovery input is invalid')
  const ledger = assertTrustedLedger(input.ledger)
  const attempt = ledger.attempts?.find((candidate) => candidate.attempt_id === input.attemptId)
  if (attempt === undefined) fail('UNLEASH_SWARM_ATTEMPT_UNKNOWN', 'swarm attempt does not exist')
  const classification = {
    LEASED: ['READY_TO_START', false, false],
    STARTED: ['AMBIGUOUS_NO_REPLAY', false, false],
    CAPTURED: ['RESUME_LOCAL_VALIDATION', false, true],
    VALIDATED: ['RESUME_LOCAL_COMMIT', false, true],
    COMMITTED: ['TERMINAL', false, false],
    FAILED: ['TERMINAL', false, false],
  }[attempt.state]
  if (classification === undefined) fail('UNLEASH_SWARM_LEDGER_EVENT_INVALID', 'swarm attempt has an unknown state')
  return deeplyFreeze({
    attempt_id: attempt.attempt_id,
    request_id: attempt.request_id,
    state: attempt.state,
    recovery: classification[0],
    auto_replay: classification[1],
    resume_local: classification[2],
  })
}
