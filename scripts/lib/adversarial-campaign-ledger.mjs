import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from 'node:fs'
import { createHash } from 'node:crypto'
import { dirname, isAbsolute, resolve } from 'node:path'
import { TextDecoder } from 'node:util'
import { stableJson } from './run-engine.mjs'

const ZERO_SHA256 = '0'.repeat(64)
const RECORD_NAME = /^(\d{12})\.json$/
const SHA256 = /^[a-f0-9]{64}$/
const ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{2,159}$/
const QUALIFICATION_CONTRACT_VERSION = '1.1.0'
const AUTHORIZATION_RECEIPT_FIELDS = Object.freeze([
  'authority_basis',
  'authorization_id',
  'authorization_reference',
  'authorization_sha256',
  'autonomy_profile',
  'declared_at',
  'engagement_id',
  'expires_at',
  'kind',
  'operator_id',
  'plan_sha256',
  'risk_class',
  'schema_version',
  'scope_revision_sha256',
  'status',
  'target_sha256',
])
const AUTHORIZATION_RISK_CLASSES = new Set([
  'READ_ONLY',
  'STATE_CHANGE',
  'SENSITIVE_DATA',
  'AVAILABILITY_IMPACT',
  'IRREVERSIBLE_CHANGE',
  'PERSISTENCE',
  'LATERAL_MOVEMENT',
])
const AUTHORIZATION_AUTONOMY_PROFILES = new Set([
  'L1_ASSISTED',
  'L2_SUPERVISED',
  'L3_MAXIMUM_AUTHORIZED',
])
const QUALIFICATION_EVENT_TYPES = Object.freeze([
  'CAMPAIGN_STARTED',
  'CAMPAIGN_RESUMED',
  'ACTION_PROPOSED',
  'ACTION_CLASSIFIED',
  'ACTION_CONSIDERED',
  'ACTION_SKIPPED',
  'SCOPE_DECISION_RECORDED',
  'SCOPE_REQUEST_QUEUED',
  'ACTION_PREFLIGHT_RECORDED',
  'ACTION_BOUNDARY_DECIDED',
  'CHECKPOINT_QUEUED',
  'CHECKPOINT_ACKNOWLEDGED',
  'ACTION_PRE_DISPATCH',
  'ACTION_SEND_PERMITTED',
  'ACTION_DISPATCH_SETTLED',
  'ACTION_OBSERVATION',
  'ACTION_DISPATCH_CANCELLED',
  'CAMPAIGN_STOP_RECORDED',
  'ACTION_CLEANUP_OUTCOME',
  'CAMPAIGN_TERMINAL',
])

export class AdversarialCampaignLedgerError extends Error {
  constructor(code, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'AdversarialCampaignLedgerError'
    this.code = code
  }
}

function ledgerError(code, message, options) {
  return new AdversarialCampaignLedgerError(code, message, options)
}

function assertPlainJson(root, label) {
  const activeAncestors = new WeakSet()
  const stack = [{ value: root, depth: 0 }]
  let nodes = 0
  while (stack.length > 0) {
    const { value, depth, exit } = stack.pop()
    if (exit) {
      activeAncestors.delete(value)
      continue
    }
    nodes += 1
    if (nodes > 20_000 || depth > 32) {
      throw ledgerError('ADVERSARIAL_LEDGER_VALUE_TOO_LARGE', `${label} exceeds JSON depth or node limits`)
    }
    if (value === null || typeof value === 'string' || typeof value === 'boolean') continue
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) {
        throw ledgerError('ADVERSARIAL_LEDGER_VALUE_INVALID', `${label} contains a non-finite number`)
      }
      continue
    }
    if (typeof value !== 'object' || activeAncestors.has(value)) {
      throw ledgerError('ADVERSARIAL_LEDGER_VALUE_INVALID', `${label} contains non-JSON data or a cycle`)
    }
    const isArray = Array.isArray(value)
    const prototype = Object.getPrototypeOf(value)
    if ((!isArray && prototype !== Object.prototype && prototype !== null)
      || (isArray && prototype !== Array.prototype)
      || Object.getOwnPropertySymbols(value).length > 0) {
      throw ledgerError('ADVERSARIAL_LEDGER_VALUE_INVALID', `${label} must contain only plain JSON values`)
    }
    activeAncestors.add(value)
    stack.push({ value, depth, exit: true })
    for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
      if (isArray && key === 'length') continue
      if (!descriptor.enumerable || 'get' in descriptor || 'set' in descriptor) {
        throw ledgerError('ADVERSARIAL_LEDGER_VALUE_INVALID', `${label} contains hidden or accessor state`)
      }
      stack.push({ value: descriptor.value, depth: depth + 1 })
    }
  }
}

function canonicalSnapshot(value, label, maxBytes = 32 * 1024 * 1024) {
  let rendered
  let snapshot
  try {
    assertPlainJson(value, label)
    rendered = stableJson(value, 0)
    if (Buffer.byteLength(rendered, 'utf8') > maxBytes) {
      throw ledgerError('ADVERSARIAL_LEDGER_VALUE_TOO_LARGE', `${label} exceeds its byte limit`)
    }
    snapshot = JSON.parse(rendered)
  } catch (error) {
    if (error instanceof AdversarialCampaignLedgerError) throw error
    throw ledgerError('ADVERSARIAL_LEDGER_VALUE_INVALID', `${label} must be finite plain JSON`, { cause: error })
  }
  if (stableJson(snapshot, 0) !== rendered) {
    throw ledgerError('ADVERSARIAL_LEDGER_VALUE_INVALID', `${label} is not stable canonical JSON`)
  }
  return snapshot
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function digestJson(value) {
  const rendered = stableJson(value, 0)
  return sha256(Buffer.from(rendered.endsWith('\n') ? rendered.slice(0, -1) : rendered, 'utf8'))
}

const qualificationDigestJson = digestJson

function exactSha256(value, label) {
  if (typeof value !== 'string' || !SHA256.test(value)) {
    throw ledgerError('ADVERSARIAL_LEDGER_BINDING_INVALID', `${label} must be a SHA-256 digest`)
  }
  return value
}

function isCanonicalTimestamp(value) {
  if (typeof value !== 'string') return false
  const parsed = Date.parse(value)
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value
}

function assertAuthorizationReceipt(receipt, binding, startedAt) {
  if (binding.authorization_id === null) {
    if (receipt !== null) {
      throw ledgerError(
        'ADVERSARIAL_LEDGER_EVENT_INVALID',
        'campaign start cannot carry authorization without an authorization-bound ledger',
      )
    }
    return
  }
  const keys = receipt === null || typeof receipt !== 'object' || Array.isArray(receipt)
    ? []
    : Object.keys(receipt).sort()
  const declaredAt = Date.parse(receipt?.declared_at)
  const expiresAt = Date.parse(receipt?.expires_at)
  const campaignStartedAt = Date.parse(startedAt)
  if (
    keys.length !== AUTHORIZATION_RECEIPT_FIELDS.length
    || !keys.every((key, index) => key === AUTHORIZATION_RECEIPT_FIELDS[index])
    || receipt.schema_version !== '1.0.0'
    || receipt.kind !== 'red-team-audit/adversarial-authorization-receipt'
    || receipt.status !== 'CONTROLLER_VERIFIED'
    || receipt.authority_basis !== 'OPERATOR_DECLARATION_ACCEPTED_AS_FACT'
    || receipt.authorization_id !== binding.authorization_id
    || receipt.authorization_reference !== receipt.authorization_id
    || typeof receipt.authorization_id !== 'string'
    || receipt.authorization_id.length < 3
    || receipt.authorization_id.length > 1024
    || !ID.test(receipt.operator_id ?? '')
    || !ID.test(receipt.engagement_id ?? '')
    || receipt.authorization_sha256 !== binding.authorization_sha256
    || receipt.plan_sha256 !== binding.plan_sha256
    || receipt.scope_revision_sha256 !== binding.scope_revision_sha256
    || !SHA256.test(receipt.target_sha256 ?? '')
    || !AUTHORIZATION_RISK_CLASSES.has(receipt.risk_class)
    || !AUTHORIZATION_AUTONOMY_PROFILES.has(receipt.autonomy_profile)
    || !isCanonicalTimestamp(receipt.declared_at)
    || !isCanonicalTimestamp(receipt.expires_at)
    || !isCanonicalTimestamp(startedAt)
    || expiresAt <= declaredAt
    || campaignStartedAt < declaredAt
    || campaignStartedAt >= expiresAt
  ) {
    throw ledgerError(
      'ADVERSARIAL_LEDGER_EVENT_INVALID',
      'campaign start authorization receipt is incomplete, inconsistent, or outside its execution window',
    )
  }
}

function normalizeBinding(value) {
  const binding = canonicalSnapshot(value, 'campaign ledger binding', 4 * 1024)
  const keys = Object.keys(binding).sort()
  const expected = ['authorization_id', 'authorization_sha256', 'plan_sha256', 'scope_revision_sha256']
  if (stableJson(keys, 0) !== stableJson(expected, 0)) {
    throw ledgerError('ADVERSARIAL_LEDGER_BINDING_INVALID', 'campaign ledger binding has unexpected fields')
  }
  exactSha256(binding.plan_sha256, 'plan_sha256')
  exactSha256(binding.scope_revision_sha256, 'scope_revision_sha256')
  if (binding.authorization_id === null) {
    if (binding.authorization_sha256 !== null) {
      throw ledgerError('ADVERSARIAL_LEDGER_BINDING_INVALID', 'authorization digest requires an authorization id')
    }
  } else {
    if (typeof binding.authorization_id !== 'string' || binding.authorization_id.length < 3) {
      throw ledgerError('ADVERSARIAL_LEDGER_BINDING_INVALID', 'authorization_id is invalid')
    }
    exactSha256(binding.authorization_sha256, 'authorization_sha256')
  }
  return Object.freeze(binding)
}

function syncDirectoryEntry(directory) {
  if (process.platform === 'win32') return
  const descriptor = openSync(directory, 'r')
  try {
    fsyncSync(descriptor)
  } finally {
    closeSync(descriptor)
  }
}

function blankProjection(binding) {
  return {
    binding,
    records: [],
    headSha256: ZERO_SHA256,
    started: false,
    authorizationReceipt: null,
    preflight: null,
    qualificationReceipt: null,
    breakGlassOverrideSha256: null,
    startedAt: null,
    considered: 0,
    dispatched: 0,
    aggregateOutputBytes: 0,
    elapsedMs: 0,
    resumeCount: 0,
    exactIndex: 0,
    actionIds: new Set(),
    pausedBranches: new Set(),
    scopeRequests: [],
    observations: [],
    observationRecords: [],
    pendingConsideration: null,
    pendingDispatch: null,
    pendingExactScopeRequest: null,
    pendingCheckpoint: null,
    actionQualifications: new Map(),
    pendingActionQualification: null,
    qualificationRecords: [],
    stopRecords: [],
    pendingStop: null,
    cleanupOutcomes: [],
    pendingCleanupOutcome: null,
    terminalResult: null,
  }
}

function qualificationRequired(projection) {
  return projection.qualificationReceipt !== null
}

function exactActionBinding(event, projection) {
  const pending = projection.pendingDispatch ?? projection.pendingConsideration
  if (
    pending === null
    || pending.action_id !== event.action_id
    || pending.action_sha256 !== event.action_sha256
  ) {
    throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'qualification record does not bind the current action')
  }
  return pending
}

function qualificationFor(projection, actionId) {
  const qualification = projection.actionQualifications.get(actionId)
  if (!qualification) {
    throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'action has no durable proposal qualification')
  }
  return qualification
}

function validateReasonCodes(value) {
  if (
    !Array.isArray(value)
    || value.length > 64
    || value.some((reason) => typeof reason !== 'string' || reason.length < 1 || reason.length > 256)
  ) {
    throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'reason_codes must be a bounded string array')
  }
}

function isDispatchRecoveryObservation(observation, actionSha256, settlement) {
  if (
    observation === null
    || typeof observation !== 'object'
    || Array.isArray(observation)
    || observation.schema_version !== '1.0.0'
    || observation.kind !== 'red-team-audit/adversarial-dispatch-recovery-observation'
    || observation.status !== 'ERROR'
    || observation.action_sha256 !== actionSha256
    || observation.output_bytes !== 0
    || observation.settlement_outcome !== settlement?.outcome
    || observation.source_observation_sha256 !== settlement?.observation_sha256
    || stableJson(observation.escalation_triggers, 0)
      !== stableJson(['AMBIGUOUS_AUTHORIZATION_OR_CLEANUP'], 0)
  ) {
    return false
  }
  try {
    validateReasonCodes(observation.reason_codes)
  } catch {
    return false
  }
  return observation.reason_codes.length > 0
}

function positiveCount(value, label) {
  if (!Number.isInteger(value) || value < 0) {
    throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', `${label} must be a non-negative integer`)
  }
  return value
}

function elapsed(value) {
  const result = positiveCount(value, 'elapsed_ms')
  if (!Number.isSafeInteger(result)) {
    throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'elapsed_ms exceeds the safe integer range')
  }
  return result
}

function assertMutable(projection) {
  if (!projection.started) {
    throw ledgerError('ADVERSARIAL_LEDGER_NOT_STARTED', 'campaign ledger has not started')
  }
  if (projection.terminalResult !== null) {
    throw ledgerError('ADVERSARIAL_LEDGER_TERMINAL', 'campaign ledger is terminal')
  }
}

function applyEvent(projection, event) {
  if (event.type === 'CAMPAIGN_STARTED') {
    if (projection.started || projection.records.length !== 0) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'campaign can start exactly once')
    }
    const receipt = event.authorization_receipt
    const qualificationReceipt = event.qualification_receipt ?? null
    assertAuthorizationReceipt(receipt, projection.binding, event.started_at)
    if (qualificationReceipt !== null && (
      qualificationReceipt?.schema_version !== '1.0.0'
      || qualificationReceipt.kind !== 'red-team-audit/adversarial-ledger-qualification-receipt'
      || qualificationReceipt.status !== 'QUALIFIED'
      || qualificationReceipt.contract_version !== QUALIFICATION_CONTRACT_VERSION
      || qualificationReceipt.binding_sha256 !== qualificationDigestJson(projection.binding)
      || !SHA256.test(qualificationReceipt.requirements_sha256 ?? '')
    )) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'campaign ledger qualification receipt is invalid')
    }
    projection.started = true
    projection.authorizationReceipt = event.authorization_receipt
    projection.preflight = event.preflight
    projection.qualificationReceipt = qualificationReceipt
    projection.breakGlassOverrideSha256 = event.break_glass_override_sha256
    projection.startedAt = event.started_at
    if (qualificationReceipt !== null) {
      projection.qualificationRecords.push(structuredClone(event))
    }
    return
  }
  assertMutable(projection)
  if (
    projection.pendingStop !== null
    && ![
      'ACTION_CLASSIFIED',
      'ACTION_SKIPPED',
      'ACTION_DISPATCH_SETTLED',
      'ACTION_DISPATCH_CANCELLED',
      'ACTION_OBSERVATION',
      'ACTION_CLEANUP_OUTCOME',
      'CAMPAIGN_TERMINAL',
    ].includes(event.type)
  ) {
    throw ledgerError('ADVERSARIAL_LEDGER_STOPPED', 'campaign has a durable stop awaiting terminal recovery')
  }
  if (event.type === 'CAMPAIGN_RESUMED') {
    if (
      event.resume_count !== projection.resumeCount + 1
      || Number.isNaN(Date.parse(event.resumed_at))
      || new Date(event.resumed_at).toISOString() !== event.resumed_at
    ) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'campaign resume record is invalid or non-monotonic')
    }
    projection.resumeCount = event.resume_count
    if (qualificationRequired(projection)) {
      projection.qualificationRecords.push(structuredClone(event))
    }
    return
  }
  if (event.type === 'ACTION_PROPOSED') {
    if (
      !qualificationRequired(projection)
      || typeof event.action_id !== 'string'
      || event.action_id.length < 3
      || !['SEALED', 'ADAPTIVE'].includes(event.source)
      || !['baseline', 'control', 'attack', 'verification', 'cleanup'].includes(event.purpose)
      || typeof event.branch_id !== 'string'
      || event.branch_id.length < 3
      || projection.actionQualifications.has(event.action_id)
      || projection.pendingActionQualification !== null
      || projection.pendingConsideration !== null
      || projection.pendingDispatch !== null
      || projection.pendingCleanupOutcome !== null
    ) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'action proposal qualification is invalid or replayed')
    }
    exactSha256(event.proposal_sha256, 'proposal_sha256')
    positiveCount(event.next_exact_index, 'next_exact_index')
    if (
      event.next_exact_index < projection.exactIndex
      || event.next_exact_index > projection.exactIndex + 1
      || (event.source === 'ADAPTIVE' && event.next_exact_index !== projection.exactIndex)
      || (event.source === 'SEALED' && event.next_exact_index !== projection.exactIndex + 1)
    ) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'action proposal exact-index binding is invalid')
    }
    const qualification = {
      action_id: event.action_id,
      proposal_sha256: event.proposal_sha256,
      purpose: event.purpose,
      source: event.source,
      branch_id: event.branch_id,
      next_exact_index: event.next_exact_index,
      action_sha256: null,
      classification: null,
      scope_decisions: [],
      preflights: [],
      boundary: null,
      send_permit_sha256: null,
      settlement: null,
      observation_sha256: null,
      cleanup_outcome_sha256: null,
    }
    projection.actionQualifications.set(event.action_id, qualification)
    projection.pendingActionQualification = qualification
    projection.qualificationRecords.push(structuredClone(event))
    projection.elapsedMs = Math.max(projection.elapsedMs, elapsed(event.elapsed_ms))
    return
  }
  if (event.type === 'ACTION_CLASSIFIED') {
    if (!qualificationRequired(projection)) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'classification qualification requires an attested ledger contract')
    }
    const qualification = qualificationFor(projection, event.action_id)
    if (
      projection.pendingActionQualification !== qualification
      || qualification.classification !== null
      || event.proposal_sha256 !== qualification.proposal_sha256
      || event.receipt_sha256 !== digestJson(event.receipt)
      || event.receipt?.action_id !== event.action_id
      || event.receipt.proposal_sha256 !== event.proposal_sha256
      || event.receipt.action_sha256 !== event.action_sha256
      || !['CLASSIFIED', 'SKIPPED', 'FAILED'].includes(event.receipt.status)
    ) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'action classification receipt is stale or invalid')
    }
    exactSha256(event.action_sha256, 'action_sha256')
    if (event.receipt.status === 'CLASSIFIED') {
      for (const field of [
        'classification_sha256',
        'candidate_facts_sha256',
        'resolved_target_sha256',
        'effect_classification_sha256',
      ]) exactSha256(event.receipt[field], field)
      if (
        typeof event.receipt.risk_class !== 'string'
        || typeof event.receipt.strategy_family !== 'string'
        || event.receipt.reason_code !== null
      ) {
        throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'classified action receipt is incomplete')
      }
    } else if (
      event.receipt.classification_sha256 !== null
      || typeof event.receipt.reason_code !== 'string'
      || event.receipt.reason_code.length < 1
    ) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'skipped classification receipt is invalid')
    }
    qualification.action_sha256 = event.action_sha256
    qualification.classification = structuredClone(event.receipt)
    projection.qualificationRecords.push(structuredClone(event))
    projection.elapsedMs = Math.max(projection.elapsedMs, elapsed(event.elapsed_ms))
    return
  }
  if (event.type === 'ACTION_CONSIDERED') {
    if (
      event.considered_actions !== projection.considered + 1
      || event.exact_index < projection.exactIndex
      || projection.actionIds.has(event.action_id)
      || projection.pendingConsideration !== null
      || projection.pendingDispatch !== null
      || projection.pendingExactScopeRequest !== null
    ) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'action consideration is non-monotonic or replayed')
    }
    exactSha256(event.action_sha256, 'action_sha256')
    if (qualificationRequired(projection)) {
      const qualification = qualificationFor(projection, event.action_id)
      if (
        projection.pendingActionQualification !== qualification
        || qualification.classification === null
        || qualification.action_sha256 !== event.action_sha256
        || qualification.branch_id !== event.branch_id
        || qualification.next_exact_index !== event.exact_index
      ) {
        throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'considered action lacks its exact classification qualification')
      }
      projection.pendingActionQualification = null
    }
    projection.considered = event.considered_actions
    projection.exactIndex = event.exact_index
    projection.actionIds.add(event.action_id)
    projection.pendingConsideration = {
      action_id: event.action_id,
      action_sha256: event.action_sha256,
      branch_id: event.branch_id,
    }
    if (qualificationRequired(projection)) {
      projection.qualificationRecords.push(structuredClone(event))
    }
    projection.elapsedMs = Math.max(projection.elapsedMs, elapsed(event.elapsed_ms))
    return
  }
  if (event.type === 'SCOPE_DECISION_RECORDED') {
    if (!qualificationRequired(projection)) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'scope qualification requires an attested ledger contract')
    }
    const pending = exactActionBinding(event, projection)
    const qualification = qualificationFor(projection, event.action_id)
    if (
      pending.branch_id !== event.branch_id
      || !['INITIAL', 'PRE_SEND_RECHECK'].includes(event.stage)
      || qualification.scope_decisions.some(({ stage }) => stage === event.stage)
      || event.receipt_sha256 !== digestJson(event.receipt)
      || event.receipt?.stage !== event.stage
      || event.receipt.action_sha256 !== event.action_sha256
      || !['ALLOW', 'DENY', 'ERROR'].includes(event.receipt.status)
    ) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'scope decision receipt is invalid or not action-bound')
    }
    validateReasonCodes(event.receipt.reason_codes)
    for (const field of [
      'classification_sha256',
      'candidate_facts_sha256',
      'resolved_target_sha256',
      'effect_classification_sha256',
      'scope_revision_sha256',
      'decision_sha256',
    ]) exactSha256(event.receipt[field], field)
    if (
      event.receipt.classification_sha256 !== qualification.classification?.classification_sha256
      || event.receipt.candidate_facts_sha256 !== qualification.classification?.candidate_facts_sha256
      || event.receipt.resolved_target_sha256 !== qualification.classification?.resolved_target_sha256
      || event.receipt.effect_classification_sha256
        !== qualification.classification?.effect_classification_sha256
      || event.receipt.scope_revision_sha256 !== projection.binding.scope_revision_sha256
    ) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'scope decision drifted from the classified action or bound scope')
    }
    if (
      event.receipt.status === 'ALLOW'
      && !SHA256.test(event.receipt.authorization_sha256 ?? '')
    ) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'allowed scope decision lacks its authorization digest')
    }
    if (event.stage === 'INITIAL' && projection.pendingConsideration === null) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'initial scope decision occurred outside consideration')
    }
    if (event.stage === 'PRE_SEND_RECHECK' && projection.pendingDispatch === null) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'scope recheck occurred before durable send intent')
    }
    qualification.scope_decisions.push(structuredClone(event.receipt))
    if (event.stage === 'INITIAL' && event.receipt.status === 'DENY') {
      projection.pausedBranches.add(event.branch_id)
    }
    projection.qualificationRecords.push(structuredClone(event))
    projection.elapsedMs = Math.max(projection.elapsedMs, elapsed(event.elapsed_ms))
    return
  }
  if (event.type === 'ACTION_PREFLIGHT_RECORDED') {
    if (!qualificationRequired(projection)) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'preflight qualification requires an attested ledger contract')
    }
    const pending = exactActionBinding(event, projection)
    const qualification = qualificationFor(projection, event.action_id)
    if (
      pending.branch_id !== event.branch_id
      || !['PRE_BOUNDARY', 'PRE_SEND_RECHECK'].includes(event.stage)
      || qualification.preflights.some(({ stage }) => stage === event.stage)
      || event.receipt_sha256 !== digestJson(event.receipt)
      || event.receipt?.stage !== event.stage
      || event.receipt.action_sha256 !== event.action_sha256
      || !['PASS', 'DENY', 'ERROR'].includes(event.receipt.status)
    ) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'per-action preflight receipt is invalid or stale')
    }
    validateReasonCodes(event.receipt.reason_codes)
    if (event.receipt.runtime_preflight_sha256 !== null) {
      exactSha256(event.receipt.runtime_preflight_sha256, 'runtime_preflight_sha256')
    }
    if (event.receipt.authorization_state_sha256 !== null) {
      exactSha256(event.receipt.authorization_state_sha256, 'authorization_state_sha256')
    }
    if (event.stage === 'PRE_BOUNDARY' && projection.pendingConsideration === null) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'boundary preflight occurred outside consideration')
    }
    if (event.stage === 'PRE_SEND_RECHECK' && projection.pendingDispatch === null) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'send preflight occurred before durable send intent')
    }
    qualification.preflights.push(structuredClone(event.receipt))
    projection.qualificationRecords.push(structuredClone(event))
    projection.elapsedMs = Math.max(projection.elapsedMs, elapsed(event.elapsed_ms))
    return
  }
  if (event.type === 'ACTION_BOUNDARY_DECIDED') {
    if (!qualificationRequired(projection)) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'boundary qualification requires an attested ledger contract')
    }
    const pending = exactActionBinding(event, projection)
    const qualification = qualificationFor(projection, event.action_id)
    if (
      projection.pendingConsideration === null
      || pending.branch_id !== event.branch_id
      || qualification.boundary !== null
      || event.receipt_sha256 !== digestJson(event.receipt)
      || event.receipt?.action_sha256 !== event.action_sha256
      || !['ALLOW', 'DENY'].includes(event.receipt.status)
    ) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'campaign boundary decision is invalid or stale')
    }
    validateReasonCodes(event.receipt.reason_codes)
    exactSha256(event.receipt.boundary_sha256, 'boundary_sha256')
    qualification.boundary = structuredClone(event.receipt)
    if (event.receipt.status === 'DENY') projection.pausedBranches.add(event.branch_id)
    projection.qualificationRecords.push(structuredClone(event))
    projection.elapsedMs = Math.max(projection.elapsedMs, elapsed(event.elapsed_ms))
    return
  }
  if (event.type === 'ACTION_PRE_DISPATCH') {
    const considered = projection.pendingConsideration
    if (
      projection.pendingDispatch !== null
      || considered === null
      || considered.action_id !== event.action_id
      || considered.action_sha256 !== event.action_sha256
      || considered.branch_id !== event.branch_id
      || !projection.actionIds.has(event.action_id)
      || event.dispatched_actions !== projection.dispatched + 1
    ) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'pre-dispatch record is stale or concurrent')
    }
    exactSha256(event.action_sha256, 'action_sha256')
    if (qualificationRequired(projection)) {
      const qualification = qualificationFor(projection, event.action_id)
      const initialScope = qualification.scope_decisions.find(({ stage }) => stage === 'INITIAL')
      const preflight = qualification.preflights.find(({ stage }) => stage === 'PRE_BOUNDARY')
      if (
        initialScope?.status !== 'ALLOW'
        || preflight?.status !== 'PASS'
        || qualification.boundary?.status !== 'ALLOW'
      ) {
        throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'send intent lacks allowed scope, preflight, or boundary qualification')
      }
    }
    projection.pendingDispatch = {
      action_id: event.action_id,
      action_sha256: event.action_sha256,
      branch_id: event.branch_id,
      purpose: qualificationRequired(projection)
        ? qualificationFor(projection, event.action_id).purpose
        : null,
      send_permit_sha256: null,
      settlement: null,
    }
    projection.pendingConsideration = null
    projection.dispatched = event.dispatched_actions
    if (qualificationRequired(projection)) {
      projection.qualificationRecords.push(structuredClone(event))
    }
    projection.elapsedMs = Math.max(projection.elapsedMs, elapsed(event.elapsed_ms))
    return
  }
  if (event.type === 'ACTION_SEND_PERMITTED') {
    if (!qualificationRequired(projection)) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'send permit requires an attested ledger contract')
    }
    const pending = exactActionBinding(event, projection)
    const qualification = qualificationFor(projection, event.action_id)
    const scopeRecheck = qualification.scope_decisions.find(({ stage }) => stage === 'PRE_SEND_RECHECK')
    const preflightRecheck = qualification.preflights.find(({ stage }) => stage === 'PRE_SEND_RECHECK')
    const initialScope = qualification.scope_decisions.find(({ stage }) => stage === 'INITIAL')
    const boundaryPreflight = qualification.preflights.find(({ stage }) => stage === 'PRE_BOUNDARY')
    const permitFields = [
      'action_sha256',
      'boundary_receipt_sha256',
      'classification_sha256',
      'effect_classification_sha256',
      'initial_scope_receipt_sha256',
      'kind',
      'max_action_time_ms',
      'max_output_bytes',
      'pre_boundary_receipt_sha256',
      'pre_send_receipt_sha256',
      'resolved_target_sha256',
      'schema_version',
      'scope_recheck_receipt_sha256',
    ]
    if (
      projection.pendingDispatch === null
      || pending.branch_id !== event.branch_id
      || qualification.send_permit_sha256 !== null
      || scopeRecheck?.status !== 'ALLOW'
      || preflightRecheck?.status !== 'PASS'
      || event.permit_sha256 !== digestJson(event.permit)
      || event.permit?.action_sha256 !== event.action_sha256
      || stableJson(Object.keys(event.permit).sort(), 0) !== stableJson(permitFields, 0)
      || event.permit.schema_version !== '1.0.0'
      || event.permit.kind !== 'red-team-audit/adversarial-action-send-permit'
      || event.permit.classification_sha256 !== qualification.classification?.classification_sha256
      || event.permit.initial_scope_receipt_sha256 !== digestJson(initialScope)
      || event.permit.pre_boundary_receipt_sha256 !== digestJson(boundaryPreflight)
      || event.permit.boundary_receipt_sha256 !== digestJson(qualification.boundary)
      || event.permit.scope_recheck_receipt_sha256 !== digestJson(scopeRecheck)
      || event.permit.pre_send_receipt_sha256 !== digestJson(preflightRecheck)
      || event.permit.resolved_target_sha256 !== qualification.classification?.resolved_target_sha256
      || event.permit.effect_classification_sha256
        !== qualification.classification?.effect_classification_sha256
      || !Number.isSafeInteger(event.permit.max_output_bytes)
      || event.permit.max_output_bytes < 1
      || !Number.isSafeInteger(event.permit.max_action_time_ms)
      || event.permit.max_action_time_ms < 1
    ) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'send permit is incomplete or not bound to current qualifications')
    }
    qualification.send_permit_sha256 = event.permit_sha256
    projection.pendingDispatch.send_permit_sha256 = event.permit_sha256
    projection.qualificationRecords.push(structuredClone(event))
    projection.elapsedMs = Math.max(projection.elapsedMs, elapsed(event.elapsed_ms))
    return
  }
  if (event.type === 'ACTION_DISPATCH_SETTLED') {
    const pending = exactActionBinding(event, projection)
    const qualification = qualificationRequired(projection)
      ? qualificationFor(projection, event.action_id)
      : null
    const expectedSendPermitSha256 = qualification?.send_permit_sha256
      ?? pending.send_permit_sha256
      ?? null
    if (
      projection.pendingDispatch === null
      || pending.branch_id !== event.branch_id
      || pending.settlement !== null
      || (qualification !== null && qualification.settlement !== null)
      || event.receipt_sha256 !== digestJson(event.receipt)
      || event.receipt?.action_sha256 !== event.action_sha256
      || event.receipt.send_permit_sha256 !== expectedSendPermitSha256
      || !['RETURNED', 'AMBIGUOUS', 'CANCELLED_BEFORE_SEND'].includes(event.receipt.outcome)
      || typeof event.receipt.request_may_have_been_sent !== 'boolean'
    ) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'dispatch settlement is incomplete or stale')
    }
    validateReasonCodes(event.receipt.reason_codes)
    if (event.receipt.outcome === 'RETURNED') {
      exactSha256(event.receipt.observation_sha256, 'observation_sha256')
      if (
        event.receipt.reason_codes.length !== 0
        || event.receipt.request_may_have_been_sent !== true
      ) {
        throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'returned dispatch settlement cannot carry failure reasons')
      }
    } else {
      if (event.receipt.outcome === 'AMBIGUOUS' && event.receipt.observation_sha256 !== null) {
        exactSha256(event.receipt.observation_sha256, 'observation_sha256')
      }
      if (
        event.receipt.reason_codes.length === 0
        || (event.receipt.outcome === 'AMBIGUOUS'
          && event.receipt.request_may_have_been_sent !== true)
        || (event.receipt.outcome === 'CANCELLED_BEFORE_SEND'
          && (event.receipt.request_may_have_been_sent !== false
            || event.receipt.observation_sha256 !== null))
      ) {
        throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'non-returned dispatch settlement has invalid send certainty or reasons')
      }
    }
    pending.settlement = structuredClone(event.receipt)
    if (qualification !== null) qualification.settlement = structuredClone(event.receipt)
    if (event.receipt.outcome === 'CANCELLED_BEFORE_SEND') {
      projection.pendingDispatch = null
      projection.dispatched -= 1
    }
    if (qualification !== null) projection.qualificationRecords.push(structuredClone(event))
    projection.elapsedMs = Math.max(projection.elapsedMs, elapsed(event.elapsed_ms))
    return
  }
  if (event.type === 'ACTION_OBSERVATION') {
    const pending = projection.pendingDispatch
    if (
      pending === null
      || pending.action_id !== event.action_id
      || pending.action_sha256 !== event.action_sha256
      || event.observation_sha256 !== digestJson(event.observation)
      || event.aggregate_output_bytes
        !== projection.aggregateOutputBytes + event.accounted_output_bytes
    ) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'observation does not settle the exact pending dispatch')
    }
    positiveCount(event.accounted_output_bytes, 'accounted_output_bytes')
    positiveCount(event.aggregate_output_bytes, 'aggregate_output_bytes')
    const settlement = pending.settlement
    if (settlement !== null) {
      const directlyBound = ['RETURNED', 'AMBIGUOUS'].includes(settlement.outcome)
        && settlement.observation_sha256 === event.observation_sha256
      const recoveredBound = ['RETURNED', 'AMBIGUOUS'].includes(settlement.outcome)
        && isDispatchRecoveryObservation(event.observation, event.action_sha256, settlement)
      if (
        !directlyBound
        && !recoveredBound
      ) {
        throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'observation lacks its exact dispatch settlement')
      }
    }
    if (qualificationRequired(projection)) {
      const qualification = qualificationFor(projection, event.action_id)
      if (settlement === null) {
        throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'observation lacks its exact dispatch settlement')
      }
      qualification.observation_sha256 = event.observation_sha256
      if (qualification.purpose === 'cleanup') {
        projection.pendingCleanupOutcome = {
          action_id: event.action_id,
          action_sha256: event.action_sha256,
          observation_sha256: event.observation_sha256,
        }
      }
      projection.qualificationRecords.push(structuredClone(event))
    }
    projection.pendingDispatch = null
    projection.aggregateOutputBytes = event.aggregate_output_bytes
    projection.observations.push(event.observation)
    projection.observationRecords.push({
      action_id: event.action_id,
      action_sha256: event.action_sha256,
      branch_id: event.branch_id,
      observation_sha256: event.observation_sha256,
      accounted_output_bytes: event.accounted_output_bytes,
      aggregate_output_bytes: event.aggregate_output_bytes,
      pause_branch: event.pause_branch === true,
      observation: event.observation,
    })
    if (event.pause_branch === true) projection.pausedBranches.add(event.branch_id)
    projection.elapsedMs = Math.max(projection.elapsedMs, elapsed(event.elapsed_ms))
    return
  }
  if (event.type === 'ACTION_DISPATCH_CANCELLED') {
    const pending = projection.pendingDispatch
    if (
      pending === null
      || pending.action_id !== event.action_id
      || pending.action_sha256 !== event.action_sha256
      || !Array.isArray(event.reason_codes)
      || event.reason_codes.length === 0
      || event.reason_codes.some((reason) => typeof reason !== 'string')
    ) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'dispatch cancellation does not settle the exact send permit')
    }
    if (qualificationRequired(projection)) {
      const qualification = qualificationFor(projection, event.action_id)
      if (qualification.send_permit_sha256 !== null) {
        throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'a granted send permit cannot be rewritten as pre-send cancellation')
      }
      projection.qualificationRecords.push(structuredClone(event))
    }
    projection.pendingDispatch = null
    projection.dispatched -= 1
    projection.elapsedMs = Math.max(projection.elapsedMs, elapsed(event.elapsed_ms))
    return
  }
  if (event.type === 'CAMPAIGN_STOP_RECORDED') {
    if (
      !qualificationRequired(projection)
      || event.receipt_sha256 !== digestJson(event.receipt)
      || typeof event.receipt?.status !== 'string'
      || event.receipt.status.length < 1
    ) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'campaign stop receipt is invalid')
    }
    validateReasonCodes(event.receipt.reason_codes)
    exactSha256(event.receipt.stop_reasons_sha256, 'stop_reasons_sha256')
    if (
      !Array.isArray(event.receipt.stop_reasons)
      || event.receipt.stop_reasons_sha256 !== digestJson(event.receipt.stop_reasons)
    ) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'campaign stop reasons do not match their digest')
    }
    projection.stopRecords.push(structuredClone(event.receipt))
    projection.pendingStop = structuredClone(event.receipt)
    projection.qualificationRecords.push(structuredClone(event))
    projection.elapsedMs = Math.max(projection.elapsedMs, elapsed(event.elapsed_ms))
    return
  }
  if (event.type === 'ACTION_CLEANUP_OUTCOME') {
    if (!qualificationRequired(projection)) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'cleanup qualification requires an attested ledger contract')
    }
    const qualification = qualificationFor(projection, event.action_id)
    const pending = projection.pendingCleanupOutcome
    if (
      pending === null
      || pending.action_id !== event.action_id
      || pending.action_sha256 !== event.action_sha256
      || event.receipt_sha256 !== digestJson(event.receipt)
      || event.receipt?.action_sha256 !== event.action_sha256
      || event.receipt.observation_sha256 !== pending.observation_sha256
      || !['VERIFIED', 'FAILED', 'INCONCLUSIVE'].includes(event.receipt.status)
    ) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'cleanup outcome does not bind the observed cleanup action')
    }
    exactSha256(event.receipt.observation_sha256, 'observation_sha256')
    qualification.cleanup_outcome_sha256 = event.receipt_sha256
    projection.cleanupOutcomes.push(structuredClone(event.receipt))
    projection.qualificationRecords.push(structuredClone(event))
    projection.pendingCleanupOutcome = null
    projection.elapsedMs = Math.max(projection.elapsedMs, elapsed(event.elapsed_ms))
    return
  }
  if (event.type === 'SCOPE_REQUEST_QUEUED') {
    const considered = projection.pendingConsideration
    exactSha256(event.action_sha256, 'action_sha256')
    if (
      considered === null
      || considered.action_id !== event.action_id
      || considered.action_sha256 !== event.action_sha256
      || considered.branch_id !== event.branch_id
      || typeof event.continue_campaign !== 'boolean'
      || event.request_sha256 !== digestJson(event.request)
    ) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'scope request digest does not match')
    }
    projection.pendingConsideration = null
    if (!event.continue_campaign) {
      projection.pendingExactScopeRequest = {
        action_id: event.action_id,
        action_sha256: event.action_sha256,
        branch_id: event.branch_id,
        request: event.request,
      }
    }
    projection.pausedBranches.add(event.branch_id)
    projection.scopeRequests.push(event.request)
    if (qualificationRequired(projection)) {
      projection.qualificationRecords.push(structuredClone(event))
    }
    projection.elapsedMs = Math.max(projection.elapsedMs, elapsed(event.elapsed_ms))
    return
  }
  if (event.type === 'ACTION_SKIPPED') {
    const considered = projection.pendingConsideration
    const qualification = projection.pendingActionQualification
    const skipsUnconsideredQualification = considered === null
      && qualification !== null
      && qualification.action_id === event.action_id
      && qualification.action_sha256 === event.action_sha256
      && qualification.classification !== null
      && qualification.branch_id === event.branch_id
    if (
      (
        !skipsUnconsideredQualification
        && (
          considered === null
          || considered.action_id !== event.action_id
          || considered.action_sha256 !== event.action_sha256
          || considered.branch_id !== event.branch_id
        )
      )
      || typeof event.reason !== 'string'
      || event.reason.length === 0
    ) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'skipped action does not settle the pending consideration')
    }
    projection.pendingConsideration = null
    if (skipsUnconsideredQualification) projection.pendingActionQualification = null
    if (qualificationRequired(projection)) {
      projection.qualificationRecords.push(structuredClone(event))
    }
    projection.elapsedMs = Math.max(projection.elapsedMs, elapsed(event.elapsed_ms))
    return
  }
  if (event.type === 'CHECKPOINT_QUEUED') {
    if (
      projection.pendingDispatch !== null
      || projection.pendingConsideration !== null
      || projection.pendingCheckpoint !== null
      || event.checkpoint_sha256 !== digestJson(event.checkpoint)
    ) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'checkpoint is already pending or has an invalid digest')
    }
    projection.pendingCheckpoint = event.checkpoint
    if (qualificationRequired(projection)) {
      projection.qualificationRecords.push(structuredClone(event))
    }
    projection.elapsedMs = Math.max(projection.elapsedMs, elapsed(event.elapsed_ms))
    return
  }
  if (event.type === 'CHECKPOINT_ACKNOWLEDGED') {
    if (
      projection.pendingCheckpoint === null
      || event.checkpoint_sha256 !== digestJson(projection.pendingCheckpoint)
      || event.decision_sha256 !== digestJson(event.decision)
      || event.decision?.decision !== 'CONTINUE'
      || event.decision.plan_sha256 !== projection.binding.plan_sha256
      || event.decision.authorization_id !== projection.binding.authorization_id
      || event.decision.scope_revision_sha256 !== projection.binding.scope_revision_sha256
      || event.decision.actions_used !== projection.pendingCheckpoint.actions_used
    ) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'checkpoint acknowledgement is stale')
    }
    projection.pendingCheckpoint = null
    if (qualificationRequired(projection)) {
      projection.qualificationRecords.push(structuredClone(event))
    }
    projection.elapsedMs = Math.max(projection.elapsedMs, elapsed(event.elapsed_ms))
    return
  }
  if (event.type === 'CAMPAIGN_TERMINAL') {
    if (projection.pendingDispatch !== null) {
      throw ledgerError(
        'ADVERSARIAL_LEDGER_EVENT_INVALID',
        'an unsettled dispatch cannot be hidden by a terminal campaign record',
      )
    }
    if (event.result_sha256 !== digestJson(event.result)) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'terminal result digest does not match')
    }
    if (qualificationRequired(projection)) {
      if (projection.pendingActionQualification !== null) {
        throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'terminal campaign would hide an unfinished action qualification')
      }
      if (projection.pendingConsideration !== null) {
        throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'terminal campaign would hide an unsettled considered action')
      }
      if (projection.pendingCleanupOutcome !== null) {
        throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'terminal campaign would hide an unqualified cleanup outcome')
      }
      if (Array.isArray(event.result.stop_reasons) && event.result.stop_reasons.length > 0) {
        const stop = projection.stopRecords.at(-1)
        if (
          stop?.status !== event.result.status
          || stop.stop_reasons_sha256 !== digestJson(event.result.stop_reasons)
        ) {
          throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'terminal stop was not qualified by the campaign ledger')
        }
      }
    }
    if (event.result.plan_sha256 !== projection.binding.plan_sha256) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'terminal result is not bound to this plan')
    }
    if (
      event.result.considered_actions !== projection.considered
      || event.result.dispatched_actions !== projection.dispatched
      || event.result.aggregate_output_bytes !== projection.aggregateOutputBytes
      || event.result.paused_branch_count !== projection.pausedBranches.size
      || event.result.scope_request_count !== projection.scopeRequests.length
      || event.result.observation_count !== projection.observations.length
    ) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'terminal result accounting does not match campaign state')
    }
    projection.terminalResult = event.result
    projection.pendingStop = null
    if (qualificationRequired(projection)) {
      projection.qualificationRecords.push(structuredClone(event))
    }
    projection.elapsedMs = Math.max(projection.elapsedMs, elapsed(event.elapsed_ms))
    return
  }
  throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', `unsupported campaign ledger event ${event.type}`)
}

function loadProjection(directory, binding) {
  const projection = blankProjection(binding)
  const names = readdirSync(directory)
  const records = names.map((name) => {
    const match = RECORD_NAME.exec(name)
    if (!match) {
      throw ledgerError('ADVERSARIAL_LEDGER_DIRECTORY_UNSAFE', `unexpected campaign ledger entry ${JSON.stringify(name)}`)
    }
    return { name, sequence: Number(match[1]) }
  }).sort((left, right) => left.sequence - right.sequence)
  for (let index = 0; index < records.length; index += 1) {
    const expectedSequence = index + 1
    const entry = records[index]
    if (entry.sequence !== expectedSequence) {
      throw ledgerError('ADVERSARIAL_LEDGER_SEQUENCE_INVALID', 'campaign ledger has a missing or duplicate sequence')
    }
    const bytes = readFileSync(resolve(directory, entry.name))
    let record
    try {
      const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
      record = JSON.parse(text)
    } catch (error) {
      throw ledgerError('ADVERSARIAL_LEDGER_RECORD_INVALID', 'campaign ledger record is invalid JSON', { cause: error })
    }
    if (!bytes.equals(Buffer.from(stableJson(record, 0), 'utf8'))) {
      throw ledgerError('ADVERSARIAL_LEDGER_RECORD_NONCANONICAL', 'campaign ledger record is not canonical')
    }
    if (
      record.schema_version !== '1.0.0'
      || record.kind !== 'red-team-audit/adversarial-campaign-ledger-record'
      || record.sequence !== expectedSequence
      || stableJson(record.binding, 0) !== stableJson(binding, 0)
      || record.previous_sha256 !== projection.headSha256
    ) {
      throw ledgerError('ADVERSARIAL_LEDGER_CHAIN_INVALID', 'campaign ledger record binding or predecessor is invalid')
    }
    applyEvent(projection, canonicalSnapshot(record.event, 'campaign ledger event'))
    projection.records.push(record)
    projection.headSha256 = sha256(bytes)
  }
  return projection
}

function publicSnapshot(projection) {
  return {
    fresh: projection.records.length === 0,
    started: projection.started,
    terminal: projection.terminalResult !== null,
    terminal_result: projection.terminalResult === null ? null : structuredClone(projection.terminalResult),
    record_count: projection.records.length,
    head_sha256: projection.headSha256,
    authorization_receipt: projection.authorizationReceipt === null
      ? null
      : structuredClone(projection.authorizationReceipt),
    preflight: projection.preflight === null ? null : structuredClone(projection.preflight),
    qualification_receipt: projection.qualificationReceipt === null
      ? null
      : structuredClone(projection.qualificationReceipt),
    break_glass_override_sha256: projection.breakGlassOverrideSha256,
    considered_actions: projection.considered,
    dispatched_actions: projection.dispatched,
    aggregate_output_bytes: projection.aggregateOutputBytes,
    elapsed_ms: projection.elapsedMs,
    resume_count: projection.resumeCount,
    exact_index: projection.exactIndex,
    action_ids: [...projection.actionIds],
    paused_branches: [...projection.pausedBranches].sort(),
    scope_requests: structuredClone(projection.scopeRequests),
    observations: structuredClone(projection.observations),
    observation_records: structuredClone(projection.observationRecords),
    pending_consideration: projection.pendingConsideration === null
      ? null
      : structuredClone(projection.pendingConsideration),
    pending_dispatch: projection.pendingDispatch === null ? null : structuredClone(projection.pendingDispatch),
    pending_exact_scope_request: projection.pendingExactScopeRequest === null
      ? null
      : structuredClone(projection.pendingExactScopeRequest),
    pending_checkpoint: projection.pendingCheckpoint === null ? null : structuredClone(projection.pendingCheckpoint),
    pending_action_qualification: projection.pendingActionQualification === null
      ? null
      : structuredClone(projection.pendingActionQualification),
    qualification_records: structuredClone(projection.qualificationRecords),
    stop_records: structuredClone(projection.stopRecords),
    pending_stop: projection.pendingStop === null ? null : structuredClone(projection.pendingStop),
    cleanup_outcomes: structuredClone(projection.cleanupOutcomes),
    pending_cleanup_outcome: projection.pendingCleanupOutcome === null
      ? null
      : structuredClone(projection.pendingCleanupOutcome),
  }
}

export class AdversarialCampaignLedger {
  constructor({ directory, binding, fsyncFile, fsyncDirectory }) {
    this.directory = directory
    this.binding = binding
    this._fsyncFile = fsyncFile
    this._fsyncDirectory = fsyncDirectory
    this._projection = loadProjection(directory, binding)
    this._failedClosed = false
  }

  snapshot() {
    return publicSnapshot(this._projection)
  }

  assertBinding(binding) {
    const normalized = normalizeBinding(binding)
    if (stableJson(normalized, 0) !== stableJson(this.binding, 0)) {
      throw ledgerError('ADVERSARIAL_LEDGER_BINDING_MISMATCH', 'runtime authority does not match campaign ledger binding')
    }
    return this.snapshot()
  }

  assertQualificationContract(requirements) {
    const safeRequirements = canonicalSnapshot(
      requirements,
      'campaign ledger qualification requirements',
      64 * 1024,
    )
    const expectedFields = [
      'binding_sha256',
      'contract_version',
      'kind',
      'required_event_types',
      'schema_version',
    ]
    if (
      stableJson(Object.keys(safeRequirements).sort(), 0) !== stableJson(expectedFields, 0)
      || safeRequirements.schema_version !== '1.0.0'
      || safeRequirements.kind !== 'red-team-audit/adversarial-ledger-qualification-requirements'
      || safeRequirements.contract_version !== QUALIFICATION_CONTRACT_VERSION
      || safeRequirements.binding_sha256 !== qualificationDigestJson(this.binding)
      || stableJson(safeRequirements.required_event_types, 0) !== stableJson(QUALIFICATION_EVENT_TYPES, 0)
    ) {
      throw ledgerError(
        'ADVERSARIAL_LEDGER_QUALIFICATION_UNSUPPORTED',
        'campaign ledger cannot attest the requested lifecycle qualification contract',
      )
    }
    return Object.freeze({
      schema_version: '1.0.0',
      kind: 'red-team-audit/adversarial-ledger-qualification-receipt',
      status: 'QUALIFIED',
      contract_version: QUALIFICATION_CONTRACT_VERSION,
      binding_sha256: safeRequirements.binding_sha256,
      requirements_sha256: qualificationDigestJson(safeRequirements),
    })
  }

  async _append(event) {
    if (this._failedClosed) {
      throw ledgerError('ADVERSARIAL_LEDGER_FAILED_CLOSED', 'campaign ledger must be reopened after an append failure')
    }
    const snapshot = canonicalSnapshot(event, 'campaign ledger event')
    const sequence = this._projection.records.length + 1
    const record = {
      schema_version: '1.0.0',
      kind: 'red-team-audit/adversarial-campaign-ledger-record',
      sequence,
      previous_sha256: this._projection.headSha256,
      binding: structuredClone(this.binding),
      event: snapshot,
    }
    const bytes = Buffer.from(stableJson(record, 0), 'utf8')
    const name = `${String(sequence).padStart(12, '0')}.json`
    const path = resolve(this.directory, name)
    if (!path.startsWith(`${this.directory}\\`) && !path.startsWith(`${this.directory}/`)) {
      throw ledgerError('ADVERSARIAL_LEDGER_PATH_UNSAFE', 'campaign ledger record escaped its directory')
    }
    applyEvent(this._projection, snapshot)
    let descriptor = null
    try {
      descriptor = openSync(path, 'wx', 0o600)
      writeFileSync(descriptor, bytes)
      this._fsyncFile(descriptor)
      closeSync(descriptor)
      descriptor = null
      this._fsyncDirectory(this.directory)
    } catch (error) {
      this._failedClosed = true
      try {
        this._projection = loadProjection(this.directory, this.binding)
      } catch {
        // Preserve the original append failure. Any partial record remains a
        // durable fail-closed condition that a fresh open will reject.
      }
      throw ledgerError('ADVERSARIAL_LEDGER_APPEND_FAILED', 'campaign ledger append failed closed', { cause: error })
    } finally {
      if (descriptor !== null) closeSync(descriptor)
    }
    this._projection.records.push(record)
    this._projection.headSha256 = sha256(bytes)
    return this.snapshot()
  }

  start({ authorizationReceipt, preflight, qualificationReceipt = null, breakGlassOverrideSha256, startedAt }) {
    if (this._failedClosed) {
      throw ledgerError('ADVERSARIAL_LEDGER_FAILED_CLOSED', 'campaign ledger must be reopened after an append failure')
    }
    if (this._projection.records.length !== 0) {
      throw ledgerError('ADVERSARIAL_LEDGER_ALREADY_STARTED', 'campaign ledger already started')
    }
    if (Number.isNaN(Date.parse(startedAt))) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'campaign start timestamp is invalid')
    }
    if (breakGlassOverrideSha256 !== null) exactSha256(breakGlassOverrideSha256, 'break_glass_override_sha256')
    return this._append({
      type: 'CAMPAIGN_STARTED',
      authorization_receipt: canonicalSnapshot(
        authorizationReceipt,
        'authorization receipt',
        64 * 1024,
      ),
      preflight: canonicalSnapshot(preflight, 'preflight receipt', 256 * 1024),
      qualification_receipt: qualificationReceipt === null
        ? null
        : canonicalSnapshot(qualificationReceipt, 'ledger qualification receipt', 64 * 1024),
      break_glass_override_sha256: breakGlassOverrideSha256,
      started_at: new Date(startedAt).toISOString(),
    })
  }

  recordResume({ resumedAt }) {
    if (Number.isNaN(Date.parse(resumedAt))) {
      throw ledgerError('ADVERSARIAL_LEDGER_EVENT_INVALID', 'campaign resume timestamp is invalid')
    }
    return this._append({
      type: 'CAMPAIGN_RESUMED',
      resume_count: this._projection.resumeCount + 1,
      resumed_at: new Date(resumedAt).toISOString(),
    })
  }

  recordActionProposed({
    actionId, proposalSha256, source, purpose, branchId, nextExactIndex, elapsedMs,
  }) {
    return this._append({
      type: 'ACTION_PROPOSED', action_id: actionId, proposal_sha256: proposalSha256,
      source, purpose, branch_id: branchId, next_exact_index: nextExactIndex,
      elapsed_ms: elapsedMs,
    })
  }

  recordActionClassified({ actionId, proposalSha256, actionSha256, receipt, elapsedMs }) {
    const safeReceipt = canonicalSnapshot(receipt, 'action classification receipt', 64 * 1024)
    return this._append({
      type: 'ACTION_CLASSIFIED', action_id: actionId, proposal_sha256: proposalSha256,
      action_sha256: actionSha256, receipt: safeReceipt,
      receipt_sha256: digestJson(safeReceipt), elapsed_ms: elapsedMs,
    })
  }

  recordActionConsidered({ actionId, actionSha256, branchId, exactIndex, consideredActions, elapsedMs }) {
    return this._append({
      type: 'ACTION_CONSIDERED', action_id: actionId, action_sha256: actionSha256,
      branch_id: branchId, exact_index: exactIndex, considered_actions: consideredActions,
      elapsed_ms: elapsedMs,
    })
  }

  recordScopeDecision({ actionId, actionSha256, branchId, stage, receipt, elapsedMs }) {
    const safeReceipt = canonicalSnapshot(receipt, 'scope decision receipt', 64 * 1024)
    return this._append({
      type: 'SCOPE_DECISION_RECORDED', action_id: actionId, action_sha256: actionSha256,
      branch_id: branchId, stage, receipt: safeReceipt,
      receipt_sha256: digestJson(safeReceipt), elapsed_ms: elapsedMs,
    })
  }

  recordActionPreflight({ actionId, actionSha256, branchId, stage, receipt, elapsedMs }) {
    const safeReceipt = canonicalSnapshot(receipt, 'per-action preflight receipt', 64 * 1024)
    return this._append({
      type: 'ACTION_PREFLIGHT_RECORDED', action_id: actionId, action_sha256: actionSha256,
      branch_id: branchId, stage, receipt: safeReceipt,
      receipt_sha256: digestJson(safeReceipt), elapsed_ms: elapsedMs,
    })
  }

  recordBoundaryDecision({ actionId, actionSha256, branchId, receipt, elapsedMs }) {
    const safeReceipt = canonicalSnapshot(receipt, 'campaign boundary receipt', 64 * 1024)
    return this._append({
      type: 'ACTION_BOUNDARY_DECIDED', action_id: actionId, action_sha256: actionSha256,
      branch_id: branchId, receipt: safeReceipt,
      receipt_sha256: digestJson(safeReceipt), elapsed_ms: elapsedMs,
    })
  }

  recordPreDispatch({ actionId, actionSha256, branchId, dispatchedActions, elapsedMs }) {
    return this._append({
      type: 'ACTION_PRE_DISPATCH', action_id: actionId, action_sha256: actionSha256,
      branch_id: branchId, dispatched_actions: dispatchedActions, elapsed_ms: elapsedMs,
    })
  }

  recordSendPermit({ actionId, actionSha256, branchId, permit, elapsedMs }) {
    const safePermit = canonicalSnapshot(permit, 'action send permit', 64 * 1024)
    return this._append({
      type: 'ACTION_SEND_PERMITTED', action_id: actionId, action_sha256: actionSha256,
      branch_id: branchId, permit: safePermit, permit_sha256: digestJson(safePermit),
      elapsed_ms: elapsedMs,
    })
  }

  recordDispatchSettlement({ actionId, actionSha256, branchId, receipt, elapsedMs }) {
    const safeReceipt = canonicalSnapshot(receipt, 'dispatch settlement receipt', 64 * 1024)
    return this._append({
      type: 'ACTION_DISPATCH_SETTLED', action_id: actionId, action_sha256: actionSha256,
      branch_id: branchId, receipt: safeReceipt,
      receipt_sha256: digestJson(safeReceipt), elapsed_ms: elapsedMs,
    })
  }

  recordObservation({
    actionId, actionSha256, branchId, observation, accountedOutputBytes,
    aggregateOutputBytes, pauseBranch, elapsedMs,
  }) {
    const safeObservation = canonicalSnapshot(observation, 'action observation')
    return this._append({
      type: 'ACTION_OBSERVATION', action_id: actionId, action_sha256: actionSha256,
      branch_id: branchId, observation: safeObservation,
      observation_sha256: digestJson(safeObservation),
      accounted_output_bytes: accountedOutputBytes,
      aggregate_output_bytes: aggregateOutputBytes,
      pause_branch: pauseBranch === true,
      elapsed_ms: elapsedMs,
    })
  }

  recordDispatchCancelled({ actionId, actionSha256, reasonCodes, elapsedMs }) {
    return this._append({
      type: 'ACTION_DISPATCH_CANCELLED', action_id: actionId,
      action_sha256: actionSha256, reason_codes: [...reasonCodes], elapsed_ms: elapsedMs,
    })
  }

  recordActionSkipped({ actionId, actionSha256, branchId, reason, elapsedMs }) {
    return this._append({
      type: 'ACTION_SKIPPED', action_id: actionId, action_sha256: actionSha256,
      branch_id: branchId, reason, elapsed_ms: elapsedMs,
    })
  }

  recordScopeRequest({
    actionId, actionSha256, branchId, request, continueCampaign, elapsedMs,
  }) {
    const safeRequest = canonicalSnapshot(request, 'scope request', 256 * 1024)
    return this._append({
      type: 'SCOPE_REQUEST_QUEUED', action_id: actionId, action_sha256: actionSha256,
      branch_id: branchId, request: safeRequest, request_sha256: digestJson(safeRequest),
      continue_campaign: continueCampaign,
      elapsed_ms: elapsedMs,
    })
  }

  recordCheckpointQueued({ checkpoint, elapsedMs }) {
    const safeCheckpoint = canonicalSnapshot(checkpoint, 'checkpoint', 256 * 1024)
    return this._append({
      type: 'CHECKPOINT_QUEUED', checkpoint: safeCheckpoint,
      checkpoint_sha256: digestJson(safeCheckpoint), elapsed_ms: elapsedMs,
    })
  }

  recordCheckpointAcknowledged({ checkpoint, decision, elapsedMs }) {
    const safeCheckpoint = canonicalSnapshot(checkpoint, 'checkpoint', 256 * 1024)
    const safeDecision = canonicalSnapshot(decision, 'checkpoint decision', 256 * 1024)
    return this._append({
      type: 'CHECKPOINT_ACKNOWLEDGED', checkpoint_sha256: digestJson(safeCheckpoint),
      decision: safeDecision, decision_sha256: digestJson(safeDecision), elapsed_ms: elapsedMs,
    })
  }

  recordCampaignStop({ receipt, elapsedMs }) {
    const safeReceipt = canonicalSnapshot(receipt, 'campaign stop receipt', 64 * 1024)
    return this._append({
      type: 'CAMPAIGN_STOP_RECORDED', receipt: safeReceipt,
      receipt_sha256: digestJson(safeReceipt), elapsed_ms: elapsedMs,
    })
  }

  recordCleanupOutcome({ actionId, actionSha256, receipt, elapsedMs }) {
    const safeReceipt = canonicalSnapshot(receipt, 'cleanup outcome receipt', 64 * 1024)
    return this._append({
      type: 'ACTION_CLEANUP_OUTCOME', action_id: actionId, action_sha256: actionSha256,
      receipt: safeReceipt, receipt_sha256: digestJson(safeReceipt), elapsed_ms: elapsedMs,
    })
  }

  recordTerminal({ result, elapsedMs }) {
    const safeResult = canonicalSnapshot(result, 'terminal campaign result')
    return this._append({
      type: 'CAMPAIGN_TERMINAL', result: safeResult,
      result_sha256: digestJson(safeResult), elapsed_ms: elapsedMs,
    })
  }
}

export async function openAdversarialCampaignLedger({
  directory,
  binding,
  fsyncFile = fsyncSync,
  fsyncDirectory = syncDirectoryEntry,
} = {}) {
  if (typeof directory !== 'string' || !isAbsolute(directory)) {
    throw ledgerError('ADVERSARIAL_LEDGER_DIRECTORY_INVALID', 'campaign ledger directory must be absolute')
  }
  if (typeof fsyncFile !== 'function' || typeof fsyncDirectory !== 'function') {
    throw ledgerError('ADVERSARIAL_LEDGER_DURABILITY_INVALID', 'campaign ledger requires durability functions')
  }
  const root = resolve(directory)
  const parent = dirname(root)
  if (!existsSync(parent)) {
    throw ledgerError('ADVERSARIAL_LEDGER_DIRECTORY_INVALID', 'campaign ledger parent must be pre-provisioned')
  }
  let created = false
  try {
    mkdirSync(root, { recursive: false, mode: 0o700 })
    created = true
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error
  }
  if (created) fsyncDirectory(parent)
  return new AdversarialCampaignLedger({
    directory: root,
    binding: normalizeBinding(binding),
    fsyncFile,
    fsyncDirectory,
  })
}
