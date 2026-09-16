import {
  UNLEASH_CANDIDATE_FRONTIER_STATE_FILE,
  assertValidUnleashCandidateAdmissionV2,
  assertValidUnleashCandidateFrontierStateV2,
  createUnleashCandidateAdmissionV2,
  previewUnleashCandidateFrontierAppendV2,
  reconcileUnleashCandidateFrontierStateV2,
  recoverUnleashCandidateFrontierV2,
} from './unleash-candidate-frontier.mjs'
import {
  appendUnleashCampaignState,
  assertValidUnleashCampaignState,
  nextUnleashCampaignState,
  recoverUnleashCampaignState,
} from './unleash-campaign-state.mjs'
import { canonicalUnleashCampaignJson } from './unleash-campaign-storage.mjs'
import { digestUnleashValue } from './unleash-contracts.mjs'
import {
  assertValidUnleashSwarmBasis,
  assertValidUnleashSwarmCompletion,
  createUnleashSwarmCompletion,
} from './unleash-swarm-contracts.mjs'
import { assertValidUnleashSwarmMerge } from './unleash-swarm-merge.mjs'
import { recoverUnleashSwarmAttemptLedger } from './unleash-swarm-ledger.mjs'

const INPUT_FIELDS = [
  'plan',
  'registry',
  'provider',
  'basisState',
  'campaignState',
  'evidencePacket',
  'completion',
  'swarmBasis',
  'swarmMerge',
  'swarmLedger',
  'termination',
  'usage',
  'gaps',
  'stopReason',
]
const DEPENDENCY_FIELDS = ['storage', 'now']
const STORAGE_METHODS = [
  'writeImmutableJson',
  'replaceMutableJson',
  'readJson',
  'listJsonFilenames',
]
const TERMINAL_CAMPAIGN_STATUSES = new Set(['COMPLETE', 'COMPLETE_WITH_GAPS', 'STOPPED'])
const MAX_JSON_FILES = 10_000

export const UNLEASH_SWARM_COMPLETION_FILE = 'swarm-completion.json'

export class UnleashSwarmSealError extends Error {
  constructor(code, message, { cause } = {}) {
    super(message, cause === undefined ? undefined : { cause })
    this.name = 'UnleashSwarmSealError'
    this.code = code
  }
}

function fail(code, message, cause) {
  throw new UnleashSwarmSealError(code, message, { cause })
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

function exactOptionalDataRecord(value, allowedFields) {
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
  for (const child of Object.values(value)) deeplyFreeze(child)
  return Object.freeze(value)
}

function safeJsonSnapshot(value, label) {
  try {
    return deeplyFreeze(JSON.parse(canonicalUnleashCampaignJson(value)))
  } catch (cause) {
    fail('UNLEASH_SWARM_SEAL_VALUE_INVALID', `${label} must be bounded getter-free canonical JSON`, cause)
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
    fail('UNLEASH_SWARM_SEAL_STORAGE_INVALID', 'campaign storage could not be inspected safely', cause)
  }
  if (value === null || typeof value !== 'object') {
    fail('UNLEASH_SWARM_SEAL_STORAGE_INVALID', 'campaign storage is required')
  }
  const methods = {}
  for (const field of STORAGE_METHODS) {
    const descriptor = descriptors[field]
    if (
      descriptor === undefined
      || descriptor.enumerable !== true
      || !Object.hasOwn(descriptor, 'value')
      || typeof descriptor.value !== 'function'
    ) fail('UNLEASH_SWARM_SEAL_STORAGE_INVALID', `campaign storage is missing ${field}`)
    methods[field] = descriptor.value
  }
  return Object.freeze(methods)
}

function dependenciesFor(value = {}) {
  const retained = exactOptionalDataRecord(value, DEPENDENCY_FIELDS)
  if (retained === null || retained.storage === undefined) {
    fail('UNLEASH_SWARM_SEAL_DEPENDENCIES_INVALID', 'seal dependencies contain unknown, computed, or missing data')
  }
  if (retained.now !== undefined && typeof retained.now !== 'function') {
    fail('UNLEASH_SWARM_SEAL_DEPENDENCIES_INVALID', 'seal clock must be a function')
  }
  return {
    storage: snapshotStorage(retained.storage),
    now: retained.now ?? (() => new Date()),
  }
}

function sampleNow(now) {
  let value
  try {
    value = now()
  } catch (cause) {
    fail('UNLEASH_SWARM_SEAL_TIME_INVALID', 'seal clock failed', cause)
  }
  if (!(value instanceof Date) || !Number.isFinite(Date.prototype.getTime.call(value))) {
    fail('UNLEASH_SWARM_SEAL_TIME_INVALID', 'seal clock must return one valid Date')
  }
  return new Date(Date.prototype.getTime.call(value))
}

function monotonicDate(now, ...timestamps) {
  const sampled = sampleNow(now)
  const floor = Math.max(
    sampled.getTime(),
    ...timestamps.filter((value) => value !== null && value !== undefined).map((value) => Date.parse(value)),
  )
  if (!Number.isFinite(floor)) fail('UNLEASH_SWARM_SEAL_TIME_INVALID', 'seal timestamp floor is invalid')
  return new Date(floor)
}

function assertStopReason(termination, stopReason) {
  const validString = typeof stopReason === 'string'
    && stopReason.length >= 1
    && stopReason.length <= 1024
    && !/[\u0000-\u001f\u007f]/u.test(stopReason)
  if (termination.decision === 'STOPPED') {
    if (!validString) {
      fail('UNLEASH_SWARM_SEAL_STOP_REASON_INVALID', 'STOPPED swarm termination requires one bounded stop reason')
    }
  } else if (stopReason !== null) {
    fail('UNLEASH_SWARM_SEAL_STOP_REASON_INVALID', 'non-STOPPED swarm termination cannot carry a stop reason')
  }
}

function assertTerminalControlGap(termination, gaps) {
  if (!['POLICY_BLOCKED', 'BUDGET_EXHAUSTED'].includes(termination.decision)) return
  const state = termination.decision === 'POLICY_BLOCKED' ? 'FAILED_CLOSED' : 'INCONCLUSIVE'
  if (
    !Array.isArray(gaps)
    || !gaps.some((entry) => (
      entry?.role_id === null
      && entry?.request_id === null
      && entry?.state === state
      && entry?.reason_code === termination.reason
    ))
  ) {
    fail(
      'UNLEASH_SWARM_SEAL_INPUT_INVALID',
      `${termination.decision} swarm termination requires its explicit terminal control gap`,
    )
  }
}

async function inventory(storage) {
  const value = safeJsonSnapshot(await storage.listJsonFilenames(), 'campaign JSON inventory')
  if (
    !Array.isArray(value)
    || value.length > MAX_JSON_FILES
    || value.some((filename) => typeof filename !== 'string')
    || new Set(value).size !== value.length
  ) fail('UNLEASH_SWARM_SEAL_STORAGE_INVALID', 'campaign JSON inventory is invalid')
  return value
}

async function readStableOptional(storage, filename) {
  const before = await inventory(storage)
  if (!before.includes(filename)) {
    const after = await inventory(storage)
    if (!sameJson(before, after)) {
      fail('UNLEASH_SWARM_SEAL_STORAGE_CHANGED', `campaign inventory changed while ${filename} absence was checked`)
    }
    return null
  }
  let first
  let second
  try {
    first = safeJsonSnapshot(await storage.readJson(filename), filename)
    second = safeJsonSnapshot(await storage.readJson(filename), filename)
  } catch (cause) {
    fail('UNLEASH_SWARM_SEAL_STORAGE_CHANGED', `retained ${filename} could not be read twice`, cause)
  }
  const after = await inventory(storage)
  if (!sameJson(before, after) || !sameJson(first, second)) {
    fail('UNLEASH_SWARM_SEAL_STORAGE_CHANGED', `retained ${filename} changed while it was verified`)
  }
  return first
}

async function replaceAndVerifyMutable(storage, filename, value, verifier) {
  let writeError
  try {
    await storage.replaceMutableJson(filename, value)
  } catch (cause) {
    writeError = cause
  }
  const retained = await readStableOptional(storage, filename)
  if (retained === null) {
    fail('UNLEASH_SWARM_SEAL_MUTABLE_WRITE_FAILED', `mutable ${filename} was not retained`, writeError)
  }
  try {
    verifier(retained)
  } catch (cause) {
    fail('UNLEASH_SWARM_SEAL_MUTABLE_INVALID', `mutable ${filename} failed exact validation`, cause)
  }
  if (!sameJson(retained, value)) {
    fail('UNLEASH_SWARM_SEAL_MUTABLE_CHANGED', `mutable ${filename} differs from the required projection`, writeError)
  }
  return retained
}

function candidateContext(input, campaignState, swarmCompletion) {
  return {
    plan: input.plan,
    registry: input.registry,
    provider: input.provider,
    basisState: input.basisState,
    campaignState,
    evidencePacket: input.evidencePacket,
    completion: input.completion,
    swarmBasis: input.swarmBasis,
    swarmMerge: input.swarmMerge,
    swarmCompletion,
  }
}

function candidateRecoveryInput(input, storage, campaignState, swarmCompletion) {
  return {
    storage,
    ...candidateContext(input, campaignState, swarmCompletion),
  }
}

async function ensureFinalAdmission(input, storage, now, { allowCreate }) {
  const context = candidateContext(input, input.campaignState, null)
  let frontier = await recoverUnleashCandidateFrontierV2({ storage, ...context })
  if (frontier.proposal_count === 0) {
    if (!allowCreate) {
      fail('UNLEASH_SWARM_SEAL_ADMISSION_MISSING', 'immutable swarm completion cannot precede its final proposal admission')
    }
    const admission = createUnleashCandidateAdmissionV2({
      ...context,
      previousAdmission: null,
      proposal: input.swarmMerge.proposal,
      sequence: 1,
      recordedAt: monotonicDate(
        now,
        input.campaignState.updated_at,
        input.swarmBasis.recorded_at,
        input.evidencePacket.created_at,
      ),
    })
    previewUnleashCandidateFrontierAppendV2({
      frontier,
      admission,
      campaignState: input.campaignState,
      swarmMerge: input.swarmMerge,
      swarmCompletion: null,
    })
    let writeError
    try {
      await storage.writeImmutableJson('candidate-admission-000001.json', admission)
    } catch (cause) {
      writeError = cause
    }
    try {
      frontier = await recoverUnleashCandidateFrontierV2({ storage, ...context })
    } catch (cause) {
      fail('UNLEASH_SWARM_SEAL_ADMISSION_WRITE_FAILED', 'final swarm proposal admission was not proven durable', writeError ?? cause)
    }
    if (frontier.proposal_count !== 1 || frontier.head_admission_sha256 !== admission.admission_sha256) {
      fail('UNLEASH_SWARM_SEAL_ADMISSION_CHANGED', 'retained final swarm proposal admission differs from the expected admission', writeError)
    }
  }
  if (frontier.proposal_count !== 1) {
    fail('UNLEASH_SWARM_SEAL_ADMISSION_INVALID', 'swarm sealing requires exactly one final merged proposal admission')
  }
  const admission = await readStableOptional(storage, 'candidate-admission-000001.json')
  if (admission === null) fail('UNLEASH_SWARM_SEAL_ADMISSION_INVALID', 'final merged proposal admission is missing')
  try {
    assertValidUnleashCandidateAdmissionV2(admission, { ...context, previousAdmission: null })
  } catch (cause) {
    fail('UNLEASH_SWARM_SEAL_ADMISSION_INVALID', 'final merged proposal admission failed exact validation', cause)
  }
  if (admission.admission_sha256 !== frontier.head_admission_sha256) {
    fail('UNLEASH_SWARM_SEAL_ADMISSION_CHANGED', 'candidate frontier head differs from its immutable final admission')
  }
  return { frontier, admission }
}

async function reconcileFrontierState(input, storage, campaignState, swarmCompletion, frontier, now) {
  const context = {
    frontier,
    basisState: input.basisState,
    campaignState,
    swarmBasis: input.swarmBasis,
    swarmMerge: input.swarmMerge,
    swarmCompletion,
  }
  const retainedState = await readStableOptional(storage, UNLEASH_CANDIDATE_FRONTIER_STATE_FILE)
  const reconciliation = reconcileUnleashCandidateFrontierStateV2({
    ...context,
    retainedState,
    recordedAt: monotonicDate(
      now,
      input.swarmBasis.recorded_at,
      campaignState.updated_at,
      swarmCompletion?.completed_at,
      retainedState?.updated_at,
    ),
  })
  if (reconciliation.status === 'CURRENT') return reconciliation.frontier_state
  return replaceAndVerifyMutable(
    storage,
    UNLEASH_CANDIDATE_FRONTIER_STATE_FILE,
    reconciliation.frontier_state,
    (value) => assertValidUnleashCandidateFrontierStateV2(value, context),
  )
}

function expectedCompletion(input, completedAt) {
  return createUnleashSwarmCompletion({
    basis: input.swarmBasis,
    completedAt,
    termination: input.termination,
    merge: input.swarmMerge,
    attemptLedger: {
      event_count: input.swarmLedger.event_count,
      attempt_count: input.swarmLedger.attempt_count,
      response_bytes: input.swarmLedger.response_bytes,
      head_record_sha256: input.swarmLedger.head_record_sha256,
      ledger_sha256: input.swarmLedger.ledger_sha256,
    },
    gaps: input.gaps,
    usage: input.usage,
  })
}

function verifyCompletionResult(input, retained) {
  try {
    assertValidUnleashSwarmCompletion(retained, { basis: input.swarmBasis })
  } catch (cause) {
    fail('UNLEASH_SWARM_SEAL_COMPLETION_INVALID', 'retained swarm completion failed exact validation', cause)
  }
  if (input.swarmLedger.events.some(({ occurred_at: occurredAt }) => (
    Date.parse(occurredAt) > Date.parse(retained.completed_at)
  ))) {
    fail('UNLEASH_SWARM_SEAL_COMPLETION_INVALID', 'swarm completion predates its exact attempt ledger')
  }
  let expected
  try {
    expected = expectedCompletion(input, retained.completed_at)
  } catch (cause) {
    fail('UNLEASH_SWARM_SEAL_COMPLETION_INVALID', 'retained swarm completion differs from the terminal swarm result', cause)
  }
  if (!sameJson(retained, expected)) {
    fail('UNLEASH_SWARM_SEAL_COMPLETION_CHANGED', 'retained swarm completion differs from the terminal swarm result')
  }
  return retained
}

function verifyCompletion(input, retained, admission) {
  verifyCompletionResult(input, retained)
  if (Date.parse(retained.completed_at) < Date.parse(admission.recorded_at)) {
    fail('UNLEASH_SWARM_SEAL_COMPLETION_CHANGED', 'retained swarm completion predates its final proposal admission')
  }
  return retained
}

async function ensureCompletion(input, storage, admission, now, { create }) {
  let retained = await readStableOptional(storage, UNLEASH_SWARM_COMPLETION_FILE)
  if (retained !== null) return verifyCompletion(input, retained, admission)
  if (!create) {
    fail('UNLEASH_SWARM_SEAL_COMPLETION_MISSING', 'terminal campaign state requires its prior immutable swarm completion')
  }
  const completion = expectedCompletion(
    input,
    monotonicDate(
      now,
      input.swarmBasis.recorded_at,
      input.campaignState.updated_at,
      admission.recorded_at,
      ...input.swarmLedger.events.map(({ occurred_at: occurredAt }) => occurredAt),
    ).toISOString(),
  )
  let writeError
  try {
    await storage.writeImmutableJson(UNLEASH_SWARM_COMPLETION_FILE, completion)
  } catch (cause) {
    writeError = cause
  }
  retained = await readStableOptional(storage, UNLEASH_SWARM_COMPLETION_FILE)
  if (retained === null) {
    fail('UNLEASH_SWARM_SEAL_COMPLETION_WRITE_FAILED', 'immutable swarm completion was not retained', writeError)
  }
  return verifyCompletion(input, retained, admission)
}

function terminalStatus(campaignState, swarmCompletion) {
  if (swarmCompletion.status === 'STOPPED') return 'STOPPED'
  if (swarmCompletion.status !== 'QUIESCENT') return 'COMPLETE_WITH_GAPS'
  return campaignState.gap_count + swarmCompletion.gaps.length === 0
    ? 'COMPLETE'
    : 'COMPLETE_WITH_GAPS'
}

function assertTerminalState(input, state, swarmCompletion, frontier) {
  assertValidUnleashCampaignState(state)
  const expectedStatus = terminalStatus(state, swarmCompletion)
  if (
    state.status !== expectedStatus
    || state.swarm_completion_sha256 !== swarmCompletion.completion_sha256
    || state.candidate_frontier_sha256 !== frontier.frontier_sha256
    || state.candidate_frontier_head_sha256 !== frontier.head_admission_sha256
    || state.swarm_gap_count !== swarmCompletion.gaps.length
    || state.stop_reason !== input.stopReason
    || Date.parse(state.updated_at) < Date.parse(swarmCompletion.completed_at)
  ) fail('UNLEASH_SWARM_SEAL_CAMPAIGN_CHANGED', 'terminal campaign state differs from its swarm completion and candidate frontier')
  return state
}

async function appendTerminalState(input, storage, swarmCompletion, frontier, now) {
  const status = terminalStatus(input.campaignState, swarmCompletion)
  const next = nextUnleashCampaignState(input.campaignState, {
    status,
    swarm_completion_sha256: swarmCompletion.completion_sha256,
    candidate_frontier_sha256: frontier.frontier_sha256,
    candidate_frontier_head_sha256: frontier.head_admission_sha256,
    swarm_gap_count: swarmCompletion.gaps.length,
    stop_reason: input.stopReason,
  }, monotonicDate(
    now,
    input.campaignState.updated_at,
    swarmCompletion.completed_at,
  ).toISOString())

  let lastError
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      return await appendUnleashCampaignState({
        storage,
        previousState: input.campaignState,
        nextState: next,
      })
    } catch (cause) {
      lastError = cause
    }
    let recovered
    try {
      recovered = await recoverUnleashCampaignState({ storage })
    } catch (cause) {
      fail('UNLEASH_SWARM_SEAL_CAMPAIGN_RECOVERY_FAILED', 'campaign state could not be reconciled after terminal publication', cause)
    }
    if (sameJson(recovered.state, next)) return next
    if (!sameJson(recovered.state, input.campaignState)) {
      fail('UNLEASH_SWARM_SEAL_CAMPAIGN_CHANGED', 'campaign head changed during terminal publication', lastError)
    }
  }
  fail('UNLEASH_SWARM_SEAL_CAMPAIGN_WRITE_FAILED', 'terminal campaign event was not proven durable', lastError)
}

function snapshotInput(value) {
  const retained = exactDataRecord(value, INPUT_FIELDS)
  if (retained === null) {
    fail('UNLEASH_SWARM_SEAL_INPUT_INVALID', 'seal input must contain exact data fields')
  }
  const snapshot = Object.fromEntries(INPUT_FIELDS
    .filter((field) => field !== 'stopReason')
    .map((field) => [field, safeJsonSnapshot(retained[field], `seal ${field}`)]))
  snapshot.stopReason = retained.stopReason
  assertStopReason(snapshot.termination, snapshot.stopReason)
  assertTerminalControlGap(snapshot.termination, snapshot.gaps)
  try {
    assertValidUnleashCampaignState(snapshot.basisState)
    assertValidUnleashCampaignState(snapshot.campaignState)
    assertValidUnleashSwarmBasis(snapshot.swarmBasis)
    assertValidUnleashSwarmMerge(snapshot.swarmMerge, { basis: snapshot.swarmBasis })
  } catch (cause) {
    fail('UNLEASH_SWARM_SEAL_INPUT_INVALID', 'seal input contains an invalid campaign or swarm artifact', cause)
  }
  if (
    snapshot.basisState.schema_version !== '2.0.0'
    || snapshot.basisState.status !== 'RUNNING'
    || snapshot.campaignState.schema_version !== '2.0.0'
    || !['SWARMING', ...TERMINAL_CAMPAIGN_STATUSES].includes(snapshot.campaignState.status)
    || snapshot.termination.terminal !== true
    || snapshot.swarmMerge.basis_sha256 !== snapshot.swarmBasis.basis_sha256
  ) fail('UNLEASH_SWARM_SEAL_INPUT_INVALID', 'seal input is not one terminal protocol-v2 swarm result')
  return deeplyFreeze(snapshot)
}

async function verifyCampaignChain(input, storage) {
  const recovered = await recoverUnleashCampaignState({ storage })
  if (!sameJson(recovered.state, input.campaignState)) {
    fail('UNLEASH_SWARM_SEAL_CAMPAIGN_CHANGED', 'supplied campaign state is not the exact recovered campaign head')
  }
  const retainedBasis = recovered.states[input.basisState.revision - 1]
  if (retainedBasis === undefined || !sameJson(retainedBasis, input.basisState)) {
    fail('UNLEASH_SWARM_SEAL_BASIS_CHANGED', 'supplied swarm basis state is not its exact immutable campaign revision')
  }
  return { ...input, basisState: retainedBasis, campaignState: recovered.state }
}

async function verifyAttemptLedger(input, storage) {
  const ledgerStorage = {
    writeImmutableJson: storage.writeImmutableJson,
    replaceMutableJson: storage.replaceMutableJson,
    readJson: storage.readJson,
    listJsonFilenames: storage.listJsonFilenames,
  }
  let recovered
  try {
    recovered = await recoverUnleashSwarmAttemptLedger(
      { basis: input.swarmBasis },
      { storage: ledgerStorage },
    )
  } catch (cause) {
    fail('UNLEASH_SWARM_SEAL_LEDGER_INVALID', 'swarm attempt ledger could not be recovered exactly', cause)
  }
  if (
    recovered.reconciliation !== 'CURRENT'
    || !sameJson(recovered, input.swarmLedger)
    || recovered.events.filter(({ state }) => state === 'STARTED').length
      !== input.usage.provider_calls_started
    || recovered.response_bytes !== input.usage.response_bytes
    || recovered.attempts.some(({ state }) => !['COMMITTED', 'FAILED'].includes(state))
  ) fail(
    'UNLEASH_SWARM_SEAL_LEDGER_INVALID',
    'swarm completion input differs from its exact current terminal attempt ledger',
  )
  const assignmentByRole = new Map(input.provider.assignments.map((assignment) => [
    assignment.role_id,
    assignment,
  ]))
  for (const attempt of recovered.attempts) {
    const assignment = assignmentByRole.get(attempt.role_id)
    if (
      attempt.round > input.usage.rounds_completed
      || assignment?.availability !== 'AVAILABLE'
      || attempt.adapter_identity.adapter_id !== assignment.adapter_id
      || attempt.adapter_identity.adapter_version !== assignment.adapter_version
      || attempt.adapter_identity.adapter_config_sha256 !== assignment.adapter_config_sha256
    ) fail(
      'UNLEASH_SWARM_SEAL_LEDGER_INVALID',
      'swarm attempt differs from its terminal round or sealed available adapter assignment',
    )
    if (attempt.state === 'FAILED' && !input.gaps.some((gap) => (
      gap.round === attempt.round
      && gap.role_id === attempt.role_id
      && gap.state === 'FAILED_CLOSED'
      && gap.reason_code === attempt.failure.reason_code
      && gap.request_id === attempt.request_id
    ))) fail(
      'UNLEASH_SWARM_SEAL_LEDGER_INVALID',
      'failed swarm attempt has no exact terminal gap',
    )
  }
  return { ...input, swarmLedger: recovered }
}

/**
 * Publishes the final merged proposal and seals one protocol-v2 swarm into the
 * campaign chain. Every restart window is recovered from durable artifacts;
 * provider work is never replayed here.
 */
export async function sealUnleashSwarmCampaign(value, dependencyValues = {}) {
  const supplied = snapshotInput(value)
  const dependencies = dependenciesFor(dependencyValues)
  const campaignInput = await verifyCampaignChain(supplied, dependencies.storage)
  const input = await verifyAttemptLedger(campaignInput, dependencies.storage)

  if (input.campaignState.status === 'SWARMING') {
    const priorCompletion = await readStableOptional(
      dependencies.storage,
      UNLEASH_SWARM_COMPLETION_FILE,
    )
    if (priorCompletion !== null) verifyCompletionResult(input, priorCompletion)
    const { frontier, admission } = await ensureFinalAdmission(
      input,
      dependencies.storage,
      dependencies.now,
      { allowCreate: priorCompletion === null },
    )
    await reconcileFrontierState(
      input,
      dependencies.storage,
      input.campaignState,
      null,
      frontier,
      dependencies.now,
    )
    const swarmCompletion = await ensureCompletion(
      input,
      dependencies.storage,
      admission,
      dependencies.now,
      { create: true },
    )
    const campaignState = await appendTerminalState(
      input,
      dependencies.storage,
      swarmCompletion,
      frontier,
      dependencies.now,
    )
    const sealedFrontier = await recoverUnleashCandidateFrontierV2(
      candidateRecoveryInput(input, dependencies.storage, campaignState, swarmCompletion),
    )
    if (!sameJson(sealedFrontier, frontier)) {
      fail('UNLEASH_SWARM_SEAL_FRONTIER_CHANGED', 'candidate frontier changed while its campaign state was sealed')
    }
    assertTerminalState(input, campaignState, swarmCompletion, sealedFrontier)
    const frontierState = await reconcileFrontierState(
      input,
      dependencies.storage,
      campaignState,
      swarmCompletion,
      sealedFrontier,
      dependencies.now,
    )
    return deeplyFreeze({ campaignState, frontier: sealedFrontier, frontierState, swarmCompletion })
  }

  const provisionalCompletion = await readStableOptional(
    dependencies.storage,
    UNLEASH_SWARM_COMPLETION_FILE,
  )
  if (provisionalCompletion === null) {
    fail('UNLEASH_SWARM_SEAL_COMPLETION_MISSING', 'terminal campaign head has no immutable swarm completion')
  }
  const provisionalContext = candidateContext(input, input.campaignState, provisionalCompletion)
  const frontier = await recoverUnleashCandidateFrontierV2({
    storage: dependencies.storage,
    ...provisionalContext,
  })
  const admission = await readStableOptional(dependencies.storage, 'candidate-admission-000001.json')
  if (admission === null) fail('UNLEASH_SWARM_SEAL_ADMISSION_INVALID', 'terminal campaign head has no final admission')
  try {
    assertValidUnleashCandidateAdmissionV2(admission, { ...provisionalContext, previousAdmission: null })
  } catch (cause) {
    fail('UNLEASH_SWARM_SEAL_ADMISSION_INVALID', 'terminal final admission failed exact validation', cause)
  }
  const swarmCompletion = await ensureCompletion(
    input,
    dependencies.storage,
    admission,
    dependencies.now,
    { create: false },
  )
  assertTerminalState(input, input.campaignState, swarmCompletion, frontier)
  const frontierState = await reconcileFrontierState(
    input,
    dependencies.storage,
    input.campaignState,
    swarmCompletion,
    frontier,
    dependencies.now,
  )
  return deeplyFreeze({
    campaignState: input.campaignState,
    frontier,
    frontierState,
    swarmCompletion,
  })
}
