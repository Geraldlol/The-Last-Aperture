import { createHash } from 'node:crypto'

import {
  assertSelfBoundUnleashPlan,
  digestUnleashValue,
} from './unleash-contracts.mjs'
import { canonicalUnleashCampaignJson } from './unleash-campaign-storage.mjs'
import { readVerifiedUnleashReconProviderArtifact } from './unleash-recon-evidence.mjs'
import {
  UNLEASH_SWARM_PROTOCOL_VERSION,
  assertValidUnleashSwarmBasis,
  createUnleashRoleRequest,
  createUnleashRoleResponseCapture,
  decodeUnleashRoleResponseCapture,
} from './unleash-swarm-contracts.mjs'
import {
  assertValidUnleashSwarmMerge,
  evaluateUnleashSwarmTermination,
  mergeUnleashSwarmResponses,
} from './unleash-swarm-merge.mjs'
import {
  UNLEASH_REASONING_ADAPTER_MAX_LIMITS,
  assertValidUnleashReasoningAdapterIdentity,
  captureUnleashReasoningResponse,
} from './unleash-reasoning-adapter.mjs'
import {
  appendUnleashSwarmAttemptEvent,
  initializeUnleashSwarmAttemptLedger,
  reconcileUnleashSwarmAttemptLedger,
  recoverUnleashSwarmAttemptLedger,
} from './unleash-swarm-ledger.mjs'

const INPUT_FIELDS = [
  'basis',
  'plan',
  'bundle',
  'reconCompletion',
  'providerProfile',
  'adapters',
]
const DEPENDENCY_FIELDS = [
  'storage',
  'readVerifiedRecon',
  'now',
  'signal',
  'stopRequested',
  'pauseRequested',
  'authorityAvailable',
  'deadlineExceeded',
  'assertExclusiveOwner',
]
const STORAGE_METHODS = [
  'writeImmutableJson',
  'replaceMutableJson',
  'readJson',
  'listJsonFilenames',
]
const ADAPTER_ASSIGNMENT_FIELDS = ['roleId', 'adapter']
const PROFILE_FIELDS = [
  'schema_version',
  'protocol_version',
  'proposal_kind',
  'role_set_id',
  'role_set_sha256',
  'roles',
  'limits',
  'assignments',
  'trust',
]
const PROFILE_ASSIGNMENT_FIELDS = [
  'role_id',
  'adapter_id',
  'adapter_version',
  'adapter_config_sha256',
  'availability',
  'reason_code',
]
const MERGE_FILENAME = /^swarm-merge-r([0-9]{2})-(attack|review)\.json$/u
const REASON_CODE = /^[A-Z][A-Z0-9_]{2,159}$/u
const MERGE_RESPONSE_REJECTIONS = new Map([
  ['UNLEASH_SWARM_MERGE_ARTIFACT_BUDGET_EXCEEDED', 'MERGE_ARTIFACT_BUDGET_EXCEEDED'],
  ['UNLEASH_SWARM_MERGE_LIMIT', 'MERGE_AGGREGATE_LIMIT_EXCEEDED'],
  ['UNLEASH_SWARM_PROVENANCE_LIMIT', 'MERGE_AGGREGATE_LIMIT_EXCEEDED'],
])
const MERGE_RESPONSE_REJECTION_REASONS = new Set(MERGE_RESPONSE_REJECTIONS.values())

export const UNLEASH_SWARM_BASIS_FILE = 'swarm-basis.json'

export class UnleashSwarmControllerError extends Error {
  constructor(code, message, { cause } = {}) {
    super(message, cause === undefined ? undefined : { cause })
    this.name = 'UnleashSwarmControllerError'
    this.code = code
  }
}

export class UnleashSwarmPause extends Error {
  constructor(message = 'The swarm paused before further provider dispatch.') {
    super(message)
    this.name = 'UnleashSwarmPause'
    this.code = 'UNLEASH_SWARM_PAUSED'
  }
}

function fail(code, message, cause) {
  throw new UnleashSwarmControllerError(code, message, { cause })
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

function exactOptionalRecord(value, allowedFields) {
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
  if (keys.some((key) => typeof key !== 'string'
    || !allowedFields.includes(key)
    || descriptors[key].enumerable !== true
    || !Object.hasOwn(descriptors[key], 'value'))) return null
  return Object.fromEntries(keys.map((key) => [key, descriptors[key].value]))
}

function deeplyFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const nested of Object.values(value)) deeplyFreeze(nested)
  return Object.freeze(value)
}

function safeJsonSnapshot(value, label) {
  try {
    return deeplyFreeze(JSON.parse(canonicalUnleashCampaignJson(value)))
  } catch (cause) {
    fail('UNLEASH_SWARM_CONTROLLER_VALUE_INVALID', `${label} must be bounded getter-free canonical JSON`, cause)
  }
}

function sameJson(left, right) {
  return digestUnleashValue(left) === digestUnleashValue(right)
}

function snapshotStorage(value) {
  let descriptors
  try {
    descriptors = Object.getOwnPropertyDescriptors(value)
  } catch (cause) {
    fail('UNLEASH_SWARM_CONTROLLER_STORAGE_INVALID', 'campaign storage could not be inspected safely', cause)
  }
  if (value === null || typeof value !== 'object') {
    fail('UNLEASH_SWARM_CONTROLLER_STORAGE_INVALID', 'campaign storage is required')
  }
  const methods = {}
  for (const field of STORAGE_METHODS) {
    const descriptor = descriptors[field]
    if (
      descriptor === undefined
      || descriptor.enumerable !== true
      || !Object.hasOwn(descriptor, 'value')
      || typeof descriptor.value !== 'function'
    ) fail('UNLEASH_SWARM_CONTROLLER_STORAGE_INVALID', `campaign storage is missing ${field}`)
    methods[field] = descriptor.value
  }
  return Object.freeze(methods)
}

function snapshotProviderProfile(value, basis, plan) {
  const profile = safeJsonSnapshot(value, 'provider profile')
  if (exactDataRecord(profile, PROFILE_FIELDS) === null) {
    fail('UNLEASH_SWARM_PROVIDER_PROFILE_INVALID', 'provider profile has missing or unknown fields')
  }
  if (
    profile.schema_version !== '1.0.0'
    || profile.protocol_version !== UNLEASH_SWARM_PROTOCOL_VERSION
    || profile.proposal_kind !== 'last-aperture/unleash-proposal'
    || profile.role_set_id !== basis.role_set_id
    || profile.role_set_sha256 !== basis.role_set_sha256
    || !sameJson(profile.roles, basis.roles)
    || !sameJson(profile.limits, basis.limits)
    || digestUnleashValue(profile) !== basis.provider_profile_sha256
    || plan.provider_sha256 !== basis.provider_profile_sha256
    || profile.trust?.provider_has_target_authority !== false
    || profile.trust?.provider_has_execution_authority !== false
    || profile.trust?.provider_output_is_proposal_only !== true
    || profile.trust?.provider_may_declare_proof !== false
    || !Array.isArray(profile.assignments)
    || profile.assignments.length !== basis.roles.length
  ) fail('UNLEASH_SWARM_PROVIDER_PROFILE_INVALID', 'provider profile differs from its plan or sealed swarm basis')
  const roleIds = basis.roles.map(({ role_id: roleId }) => roleId)
  for (const [index, assignment] of profile.assignments.entries()) {
    if (
      exactDataRecord(assignment, PROFILE_ASSIGNMENT_FIELDS) === null
      || assignment.role_id !== roleIds[index]
      || !['AVAILABLE', 'UNAVAILABLE'].includes(assignment.availability)
      || (assignment.availability === 'AVAILABLE' && (
        assignment.adapter_id === null
        || assignment.adapter_version === null
        || assignment.adapter_config_sha256 === null
        || assignment.reason_code !== null
      ))
      || (assignment.availability === 'UNAVAILABLE' && (
        assignment.adapter_id !== null
        || assignment.adapter_version !== null
        || assignment.adapter_config_sha256 !== null
        || !REASON_CODE.test(assignment.reason_code ?? '')
      ))
    ) fail('UNLEASH_SWARM_PROVIDER_PROFILE_INVALID', 'provider profile assignment is invalid or out of order')
    if (assignment.availability === 'AVAILABLE') {
      try {
        assertValidUnleashReasoningAdapterIdentity({
          adapter_id: assignment.adapter_id,
          adapter_version: assignment.adapter_version,
          adapter_config_sha256: assignment.adapter_config_sha256,
        })
      } catch (cause) {
        fail('UNLEASH_SWARM_PROVIDER_PROFILE_INVALID', 'provider profile adapter identity is invalid', cause)
      }
    }
  }
  return profile
}

function snapshotAdapters(value) {
  let descriptors
  try {
    descriptors = Object.getOwnPropertyDescriptors(value)
  } catch (cause) {
    fail('UNLEASH_SWARM_ADAPTER_ASSIGNMENTS_INVALID', 'adapter assignments could not be inspected safely', cause)
  }
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    fail('UNLEASH_SWARM_ADAPTER_ASSIGNMENTS_INVALID', 'adapter assignments must be one plain dense array')
  }
  const keys = Reflect.ownKeys(descriptors).filter((key) => key !== 'length')
  if (
    keys.length !== value.length
    || keys.some((key, index) => key !== String(index)
      || descriptors[key].enumerable !== true
      || !Object.hasOwn(descriptors[key], 'value'))
  ) fail('UNLEASH_SWARM_ADAPTER_ASSIGNMENTS_INVALID', 'adapter assignments must be one plain dense array')
  const byRole = new Map()
  for (const key of keys) {
    const item = exactDataRecord(descriptors[key].value, ADAPTER_ASSIGNMENT_FIELDS)
    if (item === null || typeof item.roleId !== 'string' || byRole.has(item.roleId)) {
      fail('UNLEASH_SWARM_ADAPTER_ASSIGNMENTS_INVALID', 'adapter assignment contains invalid or duplicate role data')
    }
    let adapterDescriptors
    try {
      adapterDescriptors = Object.getOwnPropertyDescriptors(item.adapter)
    } catch (cause) {
      fail('UNLEASH_SWARM_ADAPTER_ASSIGNMENTS_INVALID', 'reasoning adapter could not be inspected safely', cause)
    }
    if (
      item.adapter === null
      || typeof item.adapter !== 'object'
      || Reflect.ownKeys(adapterDescriptors).length !== 2
      || !Object.hasOwn(adapterDescriptors.identity ?? {}, 'value')
      || !Object.hasOwn(adapterDescriptors.invoke ?? {}, 'value')
      || typeof adapterDescriptors.invoke.value !== 'function'
    ) fail('UNLEASH_SWARM_ADAPTER_ASSIGNMENTS_INVALID', 'reasoning adapter has an invalid shape')
    try {
      assertValidUnleashReasoningAdapterIdentity(adapterDescriptors.identity.value)
    } catch (cause) {
      fail('UNLEASH_SWARM_ADAPTER_ASSIGNMENTS_INVALID', 'reasoning adapter identity is invalid', cause)
    }
    byRole.set(item.roleId, item.adapter)
  }
  return byRole
}

function dependenciesFor(value = {}) {
  const retained = exactOptionalRecord(value, DEPENDENCY_FIELDS)
  if (retained === null || retained.storage === undefined) {
    fail('UNLEASH_SWARM_CONTROLLER_DEPENDENCIES_INVALID', 'controller dependencies contain unknown, computed, or missing data')
  }
  const now = retained.now ?? (() => new Date())
  if (typeof now !== 'function') fail('UNLEASH_SWARM_CONTROLLER_DEPENDENCIES_INVALID', 'now must be a function')
  if (retained.readVerifiedRecon !== undefined && typeof retained.readVerifiedRecon !== 'function') {
    fail('UNLEASH_SWARM_CONTROLLER_DEPENDENCIES_INVALID', 'readVerifiedRecon must be a function')
  }
  if (retained.signal !== undefined && !(retained.signal instanceof AbortSignal)) {
    fail('UNLEASH_SWARM_CONTROLLER_DEPENDENCIES_INVALID', 'signal must be an AbortSignal')
  }
  if (retained.assertExclusiveOwner !== undefined && typeof retained.assertExclusiveOwner !== 'function') {
    fail('UNLEASH_SWARM_CONTROLLER_DEPENDENCIES_INVALID', 'assertExclusiveOwner must be a function')
  }
  for (const field of ['stopRequested', 'pauseRequested', 'authorityAvailable', 'deadlineExceeded']) {
    if (
      retained[field] !== undefined
      && typeof retained[field] !== 'boolean'
      && typeof retained[field] !== 'function'
    ) {
      fail('UNLEASH_SWARM_CONTROLLER_DEPENDENCIES_INVALID', `${field} must be boolean or a gate function`)
    }
  }
  return {
    storage: snapshotStorage(retained.storage),
    readVerifiedRecon: retained.readVerifiedRecon,
    now,
    signal: retained.signal,
    stopRequested: retained.stopRequested ?? false,
    pauseRequested: retained.pauseRequested ?? false,
    authorityAvailable: retained.authorityAvailable ?? true,
    deadlineExceeded: retained.deadlineExceeded ?? false,
    assertExclusiveOwner: retained.assertExclusiveOwner ?? (async () => true),
  }
}

async function sampleGate(value, fallback) {
  if (typeof value === 'boolean') return { value, failed: false }
  try {
    const observed = await value()
    return typeof observed === 'boolean'
      ? { value: observed, failed: false }
      : { value: fallback, failed: true }
  } catch {
    return { value: fallback, failed: true }
  }
}

async function sampleControllerGates(context) {
  const [stop, pause, authority, deadline] = await Promise.all([
    sampleGate(context.stopRequested, true),
    sampleGate(context.pauseRequested, true),
    sampleGate(context.authorityAvailable, false),
    sampleGate(context.deadlineExceeded, true),
  ])
  context.gateFailed ||= stop.failed || pause.failed || authority.failed || deadline.failed
  context.stopObserved ||= stop.value || context.signal?.aborted === true
  context.pauseObserved ||= pause.value
  context.authorityLost ||= !authority.value || context.gateFailed
  context.deadlineObserved ||= deadline.value
  return deeplyFreeze({
    stopRequested: context.stopObserved,
    pauseRequested: context.pauseObserved,
    authorityAvailable: !context.authorityLost,
    deadlineExceeded: context.deadlineObserved,
    failed: context.gateFailed,
  })
}

function closedGateReason(gates) {
  return gates.failed
    ? 'CONTROLLER_GATE_CHECK_FAILED'
    : gates.stopRequested
      ? 'STOP_REQUESTED'
      : !gates.authorityAvailable
        ? 'AUTHORITY_UNAVAILABLE'
        : gates.deadlineExceeded
          ? 'DEADLINE'
          : null
}

function sampleNow(now) {
  let value
  try {
    value = now()
  } catch (cause) {
    fail('UNLEASH_SWARM_CONTROLLER_TIME_INVALID', 'controller clock failed', cause)
  }
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    fail('UNLEASH_SWARM_CONTROLLER_TIME_INVALID', 'controller clock must return a valid Date')
  }
  return value.toISOString()
}

function mergeFilename(round, wave) {
  return `swarm-merge-r${String(round).padStart(2, '0')}-${wave.toLowerCase()}.json`
}

export function unleashSwarmMergeFilename(round, wave) {
  if (!Number.isSafeInteger(round) || round < 1 || round > 99 || !['ATTACK', 'REVIEW'].includes(wave)) {
    fail('UNLEASH_SWARM_MERGE_FILENAME_INVALID', 'swarm merge filename input is invalid')
  }
  return mergeFilename(round, wave)
}

async function writeOrVerifyImmutable(storage, filename, value, verifier) {
  const filenames = await storage.listJsonFilenames()
  if (!filenames.includes(filename)) {
    try {
      await storage.writeImmutableJson(filename, value)
    } catch (cause) {
      if (cause?.code !== 'UNLEASH_STORAGE_FILE_EXISTS') {
        fail('UNLEASH_SWARM_ARTIFACT_WRITE_FAILED', `could not publish immutable ${filename}`, cause)
      }
    }
  }
  let first
  let second
  try {
    first = await storage.readJson(filename)
    second = await storage.readJson(filename)
    verifier(first)
    verifier(second)
  } catch (cause) {
    if (cause instanceof UnleashSwarmControllerError) throw cause
    fail('UNLEASH_SWARM_ARTIFACT_INVALID', `immutable ${filename} is invalid`, cause)
  }
  if (!sameJson(first, second) || !sameJson(first, value)) {
    fail('UNLEASH_SWARM_ARTIFACT_CHANGED', `immutable ${filename} changed or differs from the expected artifact`)
  }
  return value
}

async function retainBasis(storage, basis) {
  return writeOrVerifyImmutable(
    storage,
    UNLEASH_SWARM_BASIS_FILE,
    basis,
    assertValidUnleashSwarmBasis,
  )
}

async function inspectMergeInventory(storage, basis) {
  const filenames = await storage.listJsonFilenames()
  const malformed = filenames.find((filename) => (
    filename.startsWith('swarm-merge-') && !MERGE_FILENAME.test(filename)
  ))
  if (malformed !== undefined) {
    fail('UNLEASH_SWARM_MERGE_INVENTORY_INVALID', 'campaign storage contains a malformed swarm merge artifact')
  }
  const retained = filenames.filter((filename) => MERGE_FILENAME.test(filename)).sort()
  const present = new Set(retained)
  for (const filename of retained) {
    const match = MERGE_FILENAME.exec(filename)
    const round = Number(match[1])
    const wave = match[2]
    if (
      round < 1
      || round > basis.limits.max_rounds
      || (wave === 'review' && !present.has(mergeFilename(round, 'ATTACK')))
      || (round > 1 && !present.has(mergeFilename(round - 1, 'REVIEW')))
    ) fail('UNLEASH_SWARM_MERGE_INVENTORY_INVALID', 'swarm merge artifact sequence is incomplete or exceeds the sealed rounds')
  }
  return present
}

function adapterIdentityFor(assignment) {
  return deeplyFreeze({
    adapter_id: assignment.adapter_id,
    adapter_version: assignment.adapter_version,
    adapter_config_sha256: assignment.adapter_config_sha256,
  })
}

function adapterMatches(adapter, identity) {
  if (adapter === undefined) return false
  try {
    return sameJson(adapter.identity, identity)
  } catch {
    return false
  }
}

function controlArtifact(basis, round, wave, merge) {
  const document = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-swarm-control',
    basis_sha256: basis.basis_sha256,
    round,
    wave,
    input_frontier_sha256: merge.frontier_sha256,
    input_challenge_set_sha256: merge.challenge_set_sha256,
    merge,
  }
  const bytes = Buffer.from(canonicalUnleashCampaignJson(document), 'utf8')
  const sha256 = createHash('sha256').update(bytes).digest('hex')
  const artifactId = `artifact:sha256:${sha256}`
  return {
    artifact: {
      artifact_id: artifactId,
      kind: 'CONTROL',
      logical_name: `swarm/control-r${String(round).padStart(2, '0')}-${wave.toLowerCase()}.json`,
      sha256,
      size: bytes.length,
    },
    payload: {
      artifact_id: artifactId,
      media_type: 'application/json',
      sha256,
      size: bytes.length,
      bytes,
    },
  }
}

function gap(round, roleId, state, reasonCode, requestId) {
  return deeplyFreeze({
    round,
    role_id: roleId,
    state,
    reason_code: REASON_CODE.test(reasonCode ?? '') ? reasonCode : 'UNCLASSIFIED_PROVIDER_FAILURE',
    request_id: requestId,
  })
}

function failureDetail(reasonCode, phase, request) {
  return digestUnleashValue({
    reason_code: REASON_CODE.test(reasonCode ?? '') ? reasonCode : 'UNCLASSIFIED_PROVIDER_FAILURE',
    phase,
    request_sha256: request.request_sha256,
  })
}

function attemptId(basis, request, adapterIdentity, ordinal) {
  return `attempt:sha256:${digestUnleashValue({
    basis_sha256: basis.basis_sha256,
    request_sha256: request.request_sha256,
    adapter_identity: adapterIdentity,
    ordinal,
  })}`
}

function attemptLimits(basis, maxResponseBytes = basis.limits.max_response_bytes_per_call) {
  const responseBytes = Math.max(1, Math.min(
    maxResponseBytes,
    basis.limits.max_response_bytes_per_call,
    UNLEASH_REASONING_ADAPTER_MAX_LIMITS.max_response_bytes,
  ))
  return deeplyFreeze({
    wall_time_ms: Math.min(
      basis.limits.wall_time_ms_per_call,
      UNLEASH_REASONING_ADAPTER_MAX_LIMITS.wall_time_ms,
    ),
    max_response_bytes: responseBytes,
    max_frame_bytes: Math.min(responseBytes, UNLEASH_REASONING_ADAPTER_MAX_LIMITS.max_frame_bytes),
    max_frames: UNLEASH_REASONING_ADAPTER_MAX_LIMITS.max_frames,
  })
}

function providerCallsStarted(ledger) {
  return ledger.events.filter(({ state }) => state === 'STARTED').length
}

function providerCallsStartedThrough(ledger, round) {
  return ledger.events.filter((event) => event.round <= round && event.state === 'STARTED').length
}

function responseBytesThrough(ledger, round) {
  return ledger.events
    .filter((event) => event.round <= round && event.state === 'CAPTURED')
    .reduce((total, event) => total + event.payload.capture.response_bytes, 0)
}

function unreservedResponseBytes(basis, ledger) {
  const reserved = ledger.attempts
    .filter(({ state }) => ['LEASED', 'STARTED'].includes(state))
    .reduce((total, attempt) => total + attempt.limits.max_response_bytes, 0)
  return Math.max(0, basis.limits.max_total_response_bytes - ledger.response_bytes - reserved)
}

function latestAttemptFor(ledger, requestId) {
  return [...ledger.attempts].reverse().find(({ request_id: candidate }) => candidate === requestId) ?? null
}

function requestForAttempt(ledger, attempt) {
  const event = ledger.events.find(({ attempt_id: attemptId }) => attemptId === attempt.attempt_id)
  if (event === undefined) {
    fail('UNLEASH_SWARM_ATTEMPT_INTEGRITY_FAILED', 'attempt has no retained lease request')
  }
  return event.request
}

function responseForAttempt(attempt, request, knownCandidateIds) {
  if (attempt.capture === null) {
    fail('UNLEASH_SWARM_ATTEMPT_INTEGRITY_FAILED', 'validated or committed attempt has no durable capture')
  }
  const response = decodeUnleashRoleResponseCapture(attempt.capture, {
    request,
    knownCandidateIds,
  })
  if (
    attempt.validated_response_sha256 !== null
    && attempt.validated_response_sha256 !== digestUnleashValue(response)
  ) fail('UNLEASH_SWARM_ATTEMPT_INTEGRITY_FAILED', 'validated response digest differs from its durable capture')
  return response
}

async function appendEvent(context, attempt, state, payload) {
  const occurredAt = sampleNow(context.now)
  const request = requestForAttempt(context.ledger, attempt)
  context.ledger = await appendUnleashSwarmAttemptEvent({
    basis: context.basis,
    attemptId: attempt.attempt_id,
    request,
    adapterIdentity: attempt.adapter_identity,
    state,
    occurredAt,
    payload,
  }, { storage: context.storage })
  return context.ledger
}

async function leaseAttempt(context, spec, identity, limits) {
  const occurredAt = sampleNow(context.now)
  const id = attemptId(context.basis, spec.request, identity, context.ledger.attempt_count + 1)
  const expiresAt = new Date(Date.parse(occurredAt) + limits.wall_time_ms).toISOString()
  context.ledger = await appendUnleashSwarmAttemptEvent({
    basis: context.basis,
    attemptId: id,
    request: spec.request,
    adapterIdentity: identity,
    state: 'LEASED',
    occurredAt,
    payload: { expires_at: expiresAt, limits },
  }, { storage: context.storage })
  return latestAttemptFor(context.ledger, spec.request.request_id)
}

async function failAttempt(context, attempt, reasonCode) {
  if (attempt.state === 'FAILED') return attempt
  if (attempt.state === 'COMMITTED') {
    fail('UNLEASH_SWARM_ATTEMPT_INTEGRITY_FAILED', 'committed attempts cannot be failed')
  }
  const phase = attempt.state
  const delivery = phase === 'LEASED' ? 'NOT_STARTED' : phase === 'STARTED' ? 'AMBIGUOUS' : 'CAPTURED'
  const request = requestForAttempt(context.ledger, attempt)
  await appendEvent(context, attempt, 'FAILED', {
    reason_code: REASON_CODE.test(reasonCode ?? '') ? reasonCode : 'UNCLASSIFIED_PROVIDER_FAILURE',
    phase,
    delivery,
    detail_sha256: failureDetail(reasonCode, phase, request),
  })
  return latestAttemptFor(context.ledger, attempt.request_id)
}

async function recordNotStartedGap(context, spec, identity, reasonCode) {
  let attempt = latestAttemptFor(context.ledger, spec.request.request_id)
  if (attempt === null && context.ledger.attempt_count < context.basis.limits.max_provider_calls) {
    attempt = await leaseAttempt(context, spec, identity, attemptLimits(context.basis, 1))
  }
  if (attempt?.state === 'LEASED') attempt = await failAttempt(context, attempt, reasonCode)
  return gap(spec.round, spec.role.role_id, 'FAILED_CLOSED', reasonCode, spec.request.request_id)
}

async function prepareAttempt(context, spec, sealedMerge, maxResponseBytes) {
  let gates = await sampleControllerGates(context)
  if (gates.pauseRequested && !gates.failed && !gates.stopRequested) {
    throw new UnleashSwarmPause()
  }
  const assignment = spec.assignment
  if (assignment.availability === 'UNAVAILABLE') {
    return { gap: gap(spec.round, spec.role.role_id, 'UNAVAILABLE', assignment.reason_code, spec.request.request_id) }
  }
  const identity = adapterIdentityFor(assignment)
  let attempt = latestAttemptFor(context.ledger, spec.request.request_id)
  if (attempt !== null && !sameJson(attempt.adapter_identity, identity)) {
    fail('UNLEASH_SWARM_ATTEMPT_INTEGRITY_FAILED', 'durable attempt adapter identity differs from the sealed assignment')
  }
  if (attempt?.state === 'STARTED') {
    attempt = await failAttempt(context, attempt, 'AMBIGUOUS_PROVIDER_DELIVERY')
  }
  if (attempt?.state === 'FAILED') {
    return { gap: gap(spec.round, spec.role.role_id, 'FAILED_CLOSED', attempt.failure.reason_code, spec.request.request_id) }
  }
  if (['CAPTURED', 'VALIDATED', 'COMMITTED'].includes(attempt?.state)) return { attempt }
  if (sealedMerge !== null) {
    if (attempt?.state === 'LEASED') {
      attempt = await failAttempt(context, attempt, 'MERGE_ALREADY_SEALED')
      return { gap: gap(spec.round, spec.role.role_id, 'FAILED_CLOSED', 'MERGE_ALREADY_SEALED', spec.request.request_id) }
    }
    if (context.ledger.attempt_count >= context.basis.limits.max_provider_calls) {
      return { gap: gap(spec.round, spec.role.role_id, 'INCONCLUSIVE', 'MAX_PROVIDER_CALLS', spec.request.request_id) }
    }
    fail('UNLEASH_SWARM_MERGE_INTEGRITY_FAILED', 'sealed merge has no durable outcome for an available assigned role')
  }
  if (gates.failed) {
    return { gap: await recordNotStartedGap(context, spec, identity, 'CONTROLLER_GATE_CHECK_FAILED') }
  }
  if (gates.stopRequested) {
    return { gap: await recordNotStartedGap(context, spec, identity, 'STOP_REQUESTED') }
  }
  if (!gates.authorityAvailable) {
    return { gap: await recordNotStartedGap(context, spec, identity, 'AUTHORITY_UNAVAILABLE') }
  }
  if (gates.deadlineExceeded) {
    return { gap: await recordNotStartedGap(context, spec, identity, 'DEADLINE') }
  }
  const adapter = context.adapters.get(spec.role.role_id)
  if (!adapterMatches(adapter, identity)) {
    const reason = adapter === undefined
      ? 'REASONING_ADAPTER_UNAVAILABLE'
      : 'REASONING_ADAPTER_IDENTITY_MISMATCH'
    return { gap: await recordNotStartedGap(context, spec, identity, reason) }
  }
  if (attempt === null) {
    if (context.ledger.attempt_count >= context.basis.limits.max_provider_calls) {
      return { gap: gap(spec.round, spec.role.role_id, 'INCONCLUSIVE', 'MAX_PROVIDER_CALLS', spec.request.request_id) }
    }
    const remainingBytes = Math.min(
      maxResponseBytes,
      unreservedResponseBytes(context.basis, context.ledger),
    )
    if (remainingBytes < 1) {
      return { gap: gap(spec.round, spec.role.role_id, 'INCONCLUSIVE', 'MAX_RESPONSE_BYTES', spec.request.request_id) }
    }
    attempt = await leaseAttempt(context, spec, identity, attemptLimits(context.basis, remainingBytes))
  }
  if (attempt.state !== 'LEASED') {
    fail('UNLEASH_SWARM_ATTEMPT_INTEGRITY_FAILED', 'attempt cannot enter provider dispatch from its retained state')
  }
  if (Date.parse(sampleNow(context.now)) >= Date.parse(attempt.expires_at)) {
    attempt = await failAttempt(context, attempt, 'PROVIDER_LEASE_EXPIRED')
    return { gap: gap(spec.round, spec.role.role_id, 'FAILED_CLOSED', 'PROVIDER_LEASE_EXPIRED', spec.request.request_id) }
  }
  gates = await sampleControllerGates(context)
  if (gates.pauseRequested && !gates.failed && !gates.stopRequested) {
    throw new UnleashSwarmPause()
  }
  if (gates.failed) {
    attempt = await failAttempt(context, attempt, 'CONTROLLER_GATE_CHECK_FAILED')
    return { gap: gap(spec.round, spec.role.role_id, 'FAILED_CLOSED', 'CONTROLLER_GATE_CHECK_FAILED', spec.request.request_id) }
  }
  if (gates.stopRequested || !gates.authorityAvailable || gates.deadlineExceeded) {
    const reason = gates.stopRequested
      ? 'STOP_REQUESTED'
      : !gates.authorityAvailable
        ? 'AUTHORITY_UNAVAILABLE'
        : 'DEADLINE'
    attempt = await failAttempt(context, attempt, reason)
    return { gap: gap(spec.round, spec.role.role_id, 'FAILED_CLOSED', reason, spec.request.request_id) }
  }
  return { attempt, adapter }
}

function serializedMutations() {
  let tail = Promise.resolve()
  return (operation) => {
    const pending = tail.then(operation, operation)
    tail = pending.catch(() => {})
    return pending
  }
}

async function dispatchAttempt(context, prepared, spec, artifacts, mutate) {
  const { adapter } = prepared
  const dispatch = await mutate(async () => {
    let attempt = latestAttemptFor(context.ledger, spec.request.request_id)
    if (attempt?.state !== 'LEASED') {
      fail('UNLEASH_SWARM_ATTEMPT_INTEGRITY_FAILED', 'provider dispatch requires one retained leased attempt')
    }
    if (Date.parse(sampleNow(context.now)) >= Date.parse(attempt.expires_at)) {
      await failAttempt(context, attempt, 'PROVIDER_LEASE_EXPIRED')
      return null
    }
    const gates = await sampleControllerGates(context)
    if (gates.pauseRequested && !gates.failed && !gates.stopRequested) {
      throw new UnleashSwarmPause()
    }
    const reason = closedGateReason(gates)
    if (reason !== null) {
      await failAttempt(context, attempt, reason)
      return null
    }
    if (await context.assertExclusiveOwner() !== true) {
      fail('UNLEASH_SWARM_OWNER_SUPERSEDED', 'exclusive swarm owner changed before provider dispatch publication')
    }
    await appendEvent(context, attempt, 'STARTED', {})
    attempt = latestAttemptFor(context.ledger, spec.request.request_id)
    if (await context.assertExclusiveOwner() !== true) {
      fail('UNLEASH_SWARM_OWNER_SUPERSEDED', 'exclusive swarm owner changed immediately before provider dispatch')
    }
    const finalGates = await sampleControllerGates(context)
    if (finalGates.pauseRequested && !finalGates.failed && !finalGates.stopRequested) {
      await failAttempt(context, attempt, 'PAUSE_AFTER_START_AMBIGUOUS')
      throw new UnleashSwarmPause()
    }
    const finalReason = closedGateReason(finalGates)
    if (finalReason !== null) {
      await failAttempt(context, attempt, finalReason)
      return null
    }
    const response = captureUnleashReasoningResponse({
      adapter,
      basis: context.basis,
      request: spec.request,
      artifactPayloads: artifacts,
      limits: attempt.limits,
      ...(context.signal === undefined ? {} : { signal: context.signal }),
    })
    // The adapter invocation is scheduled by the capture boundary. Yield once
    // while retaining the dispatch mutation so it begins before another queued
    // gate can observe a terminal condition.
    await Promise.resolve()
    return { attempt, response }
  })
  if (dispatch === null) return
  const { attempt, response } = dispatch
  try {
    const raw = await response
    await mutate(async () => {
      const capturedAt = sampleNow(context.now)
      if (Date.parse(capturedAt) > Date.parse(attempt.expires_at)) {
        const current = latestAttemptFor(context.ledger, spec.request.request_id)
        await failAttempt(context, current, 'PROVIDER_LEASE_EXPIRED')
        return
      }
      const capture = createUnleashRoleResponseCapture({
        request: spec.request,
        adapterId: attempt.adapter_identity.adapter_id,
        adapterVersion: attempt.adapter_identity.adapter_version,
        adapterConfigSha256: attempt.adapter_identity.adapter_config_sha256,
        capturedAt,
        responseBytes: raw.responseBytes,
        transportReceipt: raw.transportReceipt,
      })
      const occurredAt = sampleNow(context.now)
      context.ledger = await appendUnleashSwarmAttemptEvent({
        basis: context.basis,
        attemptId: attempt.attempt_id,
        request: spec.request,
        adapterIdentity: attempt.adapter_identity,
        state: 'CAPTURED',
        occurredAt,
        payload: { capture },
      }, { storage: context.storage })
    })
  } catch (cause) {
    await mutate(async () => {
      const current = latestAttemptFor(context.ledger, spec.request.request_id)
      if (current?.state === 'STARTED') {
        await failAttempt(context, current, cause?.code ?? 'PROVIDER_TRANSPORT_FAILED')
      }
    })
  }
}

async function inspectAttemptResponse(context, spec) {
  let attempt = latestAttemptFor(context.ledger, spec.request.request_id)
  if (attempt === null) return { response: null, gap: null }
  const retainedMergeRejection = attempt.state === 'FAILED'
    && MERGE_RESPONSE_REJECTION_REASONS.has(attempt.failure.reason_code)
  if (['CAPTURED', 'VALIDATED', 'COMMITTED'].includes(attempt.state) || retainedMergeRejection) {
    try {
      return {
        attempt,
        response: responseForAttempt(attempt, spec.request, spec.knownCandidateIds),
        gap: null,
      }
    } catch (cause) {
      if (attempt.state !== 'CAPTURED') {
        fail(
          'UNLEASH_SWARM_ATTEMPT_INTEGRITY_FAILED',
          'a retained semantic response no longer decodes from its exact captured bytes',
          cause,
        )
      }
      attempt = await failAttempt(context, attempt, cause?.code ?? 'PROVIDER_RESPONSE_INVALID')
      return {
        attempt,
        response: null,
        gap: gap(spec.round, spec.role.role_id, 'FAILED_CLOSED', attempt.failure.reason_code, spec.request.request_id),
      }
    }
  }
  if (attempt.state === 'FAILED') {
    return {
      attempt,
      response: null,
      gap: gap(spec.round, spec.role.role_id, 'FAILED_CLOSED', attempt.failure.reason_code, spec.request.request_id),
    }
  }
  fail('UNLEASH_SWARM_ATTEMPT_INTEGRITY_FAILED', 'wave ended with a nonterminal provider attempt')
}

async function foldWaveResponses(context, specs, round, previousMerge) {
  const responses = []
  const gaps = []
  let merge = mergeUnleashSwarmResponses({
    basis: context.basis,
    round,
    previous: previousMerge,
    responses,
  })
  for (const spec of [...specs].sort((left, right) => left.role.order - right.role.order)) {
    const outcome = await inspectAttemptResponse(context, spec)
    if (outcome.gap !== null) gaps.push(outcome.gap)
    if (outcome.response === null) continue
    let prospective
    let rejectionReason = null
    try {
      prospective = mergeUnleashSwarmResponses({
        basis: context.basis,
        round,
        previous: previousMerge,
        responses: [...responses, outcome.response],
      })
    } catch (cause) {
      rejectionReason = MERGE_RESPONSE_REJECTIONS.get(cause?.code) ?? null
      if (rejectionReason === null) throw cause
    }
    if (rejectionReason !== null) {
      if (['VALIDATED', 'COMMITTED'].includes(outcome.attempt.state)) {
        fail(
          'UNLEASH_SWARM_MERGE_INTEGRITY_FAILED',
          'a retained validated response exceeds the deterministic aggregate merge boundary',
        )
      }
      let attempt = outcome.attempt
      if (attempt.state === 'FAILED') {
        if (attempt.failure.reason_code !== rejectionReason) {
          fail(
            'UNLEASH_SWARM_MERGE_INTEGRITY_FAILED',
            'a retained merge-rejected response differs from deterministic replay',
          )
        }
      } else {
        attempt = await failAttempt(context, attempt, rejectionReason)
      }
      gaps.push(gap(
        spec.round,
        spec.role.role_id,
        'FAILED_CLOSED',
        rejectionReason,
        spec.request.request_id,
      ))
      continue
    }
    if (outcome.attempt.state === 'FAILED') {
      fail(
        'UNLEASH_SWARM_MERGE_INTEGRITY_FAILED',
        'a retained merge-rejected response now fits deterministic replay',
      )
    }
    if (outcome.attempt.state === 'CAPTURED') {
      await appendEvent(context, outcome.attempt, 'VALIDATED', {
        capture_sha256: outcome.attempt.capture.capture_sha256,
        response_sha256: outcome.attempt.capture.response_sha256,
        validated_response_sha256: digestUnleashValue(outcome.response),
      })
    }
    responses.push(outcome.response)
    merge = prospective
  }
  return { merge, gaps }
}

async function commitWaveAttempts(context, specs, merge) {
  for (const spec of specs) {
    const attempt = latestAttemptFor(context.ledger, spec.request.request_id)
    if (attempt?.state === 'VALIDATED') {
      await appendEvent(context, attempt, 'COMMITTED', { merge_sha256: merge.merge_sha256 })
      continue
    }
    if (attempt?.state === 'COMMITTED' && attempt.merge_sha256 !== merge.merge_sha256) {
      fail('UNLEASH_SWARM_MERGE_INTEGRITY_FAILED', 'committed attempt points at a different immutable wave merge')
    }
  }
}

async function readExistingMerge(storage, filename, basis) {
  const first = await storage.readJson(filename)
  const second = await storage.readJson(filename)
  try {
    assertValidUnleashSwarmMerge(first, { basis })
    assertValidUnleashSwarmMerge(second, { basis })
  } catch (cause) {
    fail('UNLEASH_SWARM_MERGE_INTEGRITY_FAILED', `retained ${filename} is invalid`, cause)
  }
  if (!sameJson(first, second)) {
    fail('UNLEASH_SWARM_MERGE_INTEGRITY_FAILED', `retained ${filename} changed while it was read`)
  }
  return first
}

async function runWave(context, round, wave, previousMerge, inputMerge, evidence, inventory) {
  const filename = mergeFilename(round, wave)
  const sealedMerge = inventory.has(filename)
    ? await readExistingMerge(context.storage, filename, context.basis)
    : null
  const control = controlArtifact(context.basis, round, wave, inputMerge)
  const roles = context.basis.roles.filter(({ wave: roleWave }) => roleWave === wave)
  const assignmentByRole = new Map(context.profile.assignments.map((item) => [item.role_id, item]))
  const readyToolIds = context.plan.route_dispositions
    .filter(({ disposition }) => disposition === 'READY')
    .map(({ tool_id: toolId }) => toolId)
    .sort()
  const specs = roles.map((role) => ({
    round,
    role,
    assignment: assignmentByRole.get(role.role_id),
    knownCandidateIds: inputMerge.candidates.map(({ candidate_id: candidateId }) => candidateId),
    request: createUnleashRoleRequest({
      basis: context.basis,
      round,
      roleId: role.role_id,
      inputFrontierSha256: inputMerge.frontier_sha256,
      inputChallengeSetSha256: inputMerge.challenge_set_sha256,
      evidenceRefs: [`evidence:sha256:${evidence.artifact.sha256}`],
      allowedToolIds: readyToolIds,
      artifacts: [evidence.artifact, control.artifact],
    }),
  }))
  for (const spec of specs) {
    context.requestBindings.set(spec.request.request_id, {
      request_sha256: spec.request.request_sha256,
      assignment: spec.assignment,
    })
  }
  const gaps = []
  const parallel = context.basis.limits.max_parallel_provider_calls
  for (let offset = 0; offset < specs.length; offset += parallel) {
    const chunk = specs.slice(offset, offset + parallel)
    await sampleControllerGates(context)
    const prepared = []
    for (const [index, spec] of chunk.entries()) {
      const remainingSlots = chunk.length - index
      const maxResponseBytes = Math.floor(
        unreservedResponseBytes(context.basis, context.ledger) / remainingSlots,
      )
      const outcome = await prepareAttempt(context, spec, sealedMerge, maxResponseBytes)
      if (outcome.gap !== undefined) gaps.push(outcome.gap)
      if (outcome.adapter !== undefined) prepared.push({ outcome, spec })
    }
    const mutate = serializedMutations()
    const settlements = await Promise.allSettled(prepared.map(({ outcome, spec }) => dispatchAttempt(
      context,
      outcome,
      spec,
      [evidence.payload, control.payload],
      mutate,
    )))
    const failure = settlements.find(({ status, reason }) => (
      status === 'rejected' && reason?.code !== 'UNLEASH_SWARM_PAUSED'
    ))
    if (failure?.status === 'rejected') throw failure.reason
    if (settlements.some(({ status, reason }) => (
      status === 'rejected' && reason?.code === 'UNLEASH_SWARM_PAUSED'
    ))) throw new UnleashSwarmPause()
  }

  const folded = await foldWaveResponses(context, specs, round, previousMerge)
  gaps.push(...folded.gaps)
  const derived = folded.merge
  const merge = sealedMerge === null
    ? await writeOrVerifyImmutable(
        context.storage,
        filename,
        derived,
        (value) => assertValidUnleashSwarmMerge(value, { basis: context.basis }),
      )
    : sealedMerge
  if (!sameJson(merge, derived)) {
    fail('UNLEASH_SWARM_MERGE_INTEGRITY_FAILED', `retained ${filename} differs from deterministic response replay`)
  }
  inventory.add(filename)
  await commitWaveAttempts(context, specs, merge)
  const finalGates = await sampleControllerGates(context)
  if (finalGates.pauseRequested && !finalGates.failed && !finalGates.stopRequested) {
    throw new UnleashSwarmPause()
  }
  return { merge, gaps }
}

function deduplicateGaps(values) {
  const byDigest = new Map()
  for (const value of values) byDigest.set(digestUnleashValue(value), value)
  return deeplyFreeze([...byDigest.entries()]
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    .map(([, value]) => value))
}

function terminalControlGap(termination, roundsCompleted) {
  if (termination.decision === 'QUIESCENT') return null
  const state = termination.decision === 'STOPPED'
    ? 'STOPPED'
    : termination.decision === 'POLICY_BLOCKED'
      ? 'FAILED_CLOSED'
      : 'INCONCLUSIVE'
  return gap(roundsCompleted, null, state, termination.reason, null)
}

function assertLedgerCoveredByRun(context, ledger, roundsCompleted) {
  for (const attempt of ledger.attempts) {
    const binding = context.requestBindings.get(attempt.request_id)
    if (
      binding === undefined
      || attempt.round > roundsCompleted
      || binding.request_sha256 !== attempt.request_sha256
      || binding.assignment.availability !== 'AVAILABLE'
      || !sameJson(attempt.adapter_identity, adapterIdentityFor(binding.assignment))
    ) fail('UNLEASH_SWARM_ATTEMPT_INTEGRITY_FAILED', 'attempt ledger contains an outcome outside the exact processed role requests')
  }
}

/**
 * Runs the bounded reasoning frontier through deterministic ATTACK and REVIEW
 * waves. It deliberately stops before candidate admission and completion
 * sealing; the campaign controller owns those two authority transitions.
 */
export async function runUnleashSwarmController(value, dependencyValues = {}) {
  const input = exactDataRecord(value, INPUT_FIELDS)
  if (input === null || typeof input.bundle !== 'string' || input.bundle.length < 1) {
    fail('UNLEASH_SWARM_CONTROLLER_INPUT_INVALID', 'swarm controller input must contain the exact required fields')
  }
  const dependencies = dependenciesFor(dependencyValues)
  const basis = safeJsonSnapshot(input.basis, 'swarm basis')
  try {
    assertValidUnleashSwarmBasis(basis)
  } catch (cause) {
    fail('UNLEASH_SWARM_CONTROLLER_BASIS_INVALID', 'swarm basis is invalid', cause)
  }
  const plan = safeJsonSnapshot(input.plan, 'unleash plan')
  try {
    assertSelfBoundUnleashPlan(plan)
  } catch (cause) {
    fail('UNLEASH_SWARM_CONTROLLER_PLAN_INVALID', 'unleash plan is invalid', cause)
  }
  if (
    plan.plan_sha256 !== basis.plan_sha256
    || plan.target.target_id !== basis.target_id
    || plan.registry_sha256 !== basis.registry_sha256
    || plan.provider_protocol_version !== UNLEASH_SWARM_PROTOCOL_VERSION
  ) fail('UNLEASH_SWARM_CONTROLLER_PLAN_INVALID', 'unleash plan differs from the sealed swarm basis')
  const profile = snapshotProviderProfile(input.providerProfile, basis, plan)
  const adapters = snapshotAdapters(input.adapters)
  if ([...adapters.keys()].some((roleId) => !basis.roles.some(({ role_id: id }) => id === roleId))) {
    fail('UNLEASH_SWARM_ADAPTER_ASSIGNMENTS_INVALID', 'adapter assignment names a role outside the sealed role set')
  }
  const reconCompletion = safeJsonSnapshot(input.reconCompletion, 'recon completion')
  if (
    reconCompletion.evidence_packet?.packet_sha256 !== basis.evidence_packet_sha256
    || reconCompletion.completion_receipt?.completion_receipt_sha256 !== basis.completion_receipt_sha256
  ) fail('UNLEASH_SWARM_CONTROLLER_EVIDENCE_INVALID', 'recon completion differs from the evidence bindings in the swarm basis')
  const evidence = await readVerifiedUnleashReconProviderArtifact({
    bundle: input.bundle,
    plan,
    completion: reconCompletion,
  }, dependencies.readVerifiedRecon === undefined
    ? {}
    : { readVerifiedRecon: dependencies.readVerifiedRecon })
  const retainedEvidence = {
    artifact: safeJsonSnapshot(evidence.artifact, 'verified recon artifact'),
    payload: {
      artifact_id: evidence.payload.artifact_id,
      media_type: evidence.payload.media_type,
      sha256: evidence.payload.sha256,
      size: evidence.payload.size,
      bytes: Buffer.from(evidence.payload.bytes),
    },
  }
  await retainBasis(dependencies.storage, basis)
  const inventory = await inspectMergeInventory(dependencies.storage, basis)
  let ledger = await initializeUnleashSwarmAttemptLedger({
    basis,
    initializedAt: sampleNow(dependencies.now),
  }, { storage: dependencies.storage })
  if (ledger.reconciliation === 'REPAIR_REQUIRED') {
    ledger = await reconcileUnleashSwarmAttemptLedger({
      basis,
      updatedAt: sampleNow(dependencies.now),
    }, { storage: dependencies.storage })
  }
  if (ledger.reconciliation !== 'CURRENT') {
    fail('UNLEASH_SWARM_ATTEMPT_INTEGRITY_FAILED', 'swarm attempt ledger requires reconciliation before dispatch')
  }
  const context = {
    basis,
    plan,
    profile,
    adapters,
    storage: dependencies.storage,
    now: dependencies.now,
    signal: dependencies.signal,
    stopRequested: dependencies.stopRequested,
    pauseRequested: dependencies.pauseRequested,
    authorityAvailable: dependencies.authorityAvailable,
    deadlineExceeded: dependencies.deadlineExceeded,
    assertExclusiveOwner: dependencies.assertExclusiveOwner,
    ledger,
    requestBindings: new Map(),
    gateFailed: ledger.attempts.some(({ failure }) => failure?.reason_code === 'CONTROLLER_GATE_CHECK_FAILED'),
    stopObserved: ledger.attempts.some(({ failure }) => (
      ['STOP_REQUESTED', 'UNLEASH_REASONING_ABORTED'].includes(failure?.reason_code)
    )),
    pauseObserved: false,
    authorityLost: ledger.attempts.some(({ failure }) => failure?.reason_code === 'AUTHORITY_UNAVAILABLE'),
    deadlineObserved: ledger.attempts.some(({ failure }) => failure?.reason_code === 'DEADLINE'),
  }
  const initial = mergeUnleashSwarmResponses({ basis, round: 1, previous: null, responses: [] })
  let previous = null
  let inputMerge = initial
  const allGaps = []
  let finalMerge = initial
  let termination = null
  let roundsCompleted = 0

  for (let round = 1; round <= basis.limits.max_rounds; round += 1) {
    const beforeFrontierSha256 = inputMerge.frontier_sha256
    const beforeChallengeSetSha256 = inputMerge.challenge_set_sha256
    const attack = await runWave(context, round, 'ATTACK', previous, inputMerge, retainedEvidence, inventory)
    allGaps.push(...attack.gaps)
    const review = await runWave(context, round, 'REVIEW', attack.merge, attack.merge, retainedEvidence, inventory)
    allGaps.push(...review.gaps)
    finalMerge = review.merge
    roundsCompleted = round
    context.ledger = await recoverUnleashSwarmAttemptLedger({ basis }, { storage: dependencies.storage })
    const pendingAttemptCount = context.ledger.attempts.filter(({ round: attemptRound, state }) => (
      attemptRound <= round && !['COMMITTED', 'FAILED'].includes(state)
    )).length
    const terminalGates = await sampleControllerGates(context)
    termination = evaluateUnleashSwarmTermination({
      beforeFrontierSha256,
      beforeChallengeSetSha256,
      after: finalMerge,
      roundsCompleted,
      providerCallsStarted: providerCallsStartedThrough(context.ledger, round),
      responseBytes: responseBytesThrough(context.ledger, round),
      pendingAttemptCount,
      stopRequested: terminalGates.stopRequested,
      authorityAvailable: terminalGates.failed ? false : terminalGates.authorityAvailable,
      deadlineExceeded: terminalGates.deadlineExceeded,
      basis,
    })
    if (termination.terminal) break
    previous = finalMerge
    inputMerge = finalMerge
  }
  if (termination === null || !termination.terminal) {
    fail('UNLEASH_SWARM_TERMINATION_FAILED', 'bounded swarm ended without one terminal decision')
  }
  const controlGap = terminalControlGap(termination, roundsCompleted)
  if (controlGap !== null) allGaps.push(controlGap)
  const futureMerge = [...inventory].find((filename) => {
    const match = MERGE_FILENAME.exec(filename)
    return match !== null && Number(match[1]) > roundsCompleted
  })
  if (futureMerge !== undefined) {
    fail('UNLEASH_SWARM_MERGE_INTEGRITY_FAILED', 'retained merge artifacts continue after the terminal round')
  }
  ledger = await recoverUnleashSwarmAttemptLedger({ basis }, { storage: dependencies.storage })
  assertLedgerCoveredByRun(context, ledger, roundsCompleted)
  const usage = deeplyFreeze({
    rounds_completed: roundsCompleted,
    provider_calls_started: providerCallsStarted(ledger),
    response_bytes: ledger.response_bytes,
  })
  return deeplyFreeze({
    basis,
    merge: finalMerge,
    termination,
    usage,
    gaps: deduplicateGaps(allGaps),
    ledger,
  })
}
