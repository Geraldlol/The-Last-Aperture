import { createHash } from 'node:crypto'
import { performance } from 'node:perf_hooks'
import {
  ADVERSARIAL_EFFECTS,
  L3_MANDATORY_ESCALATION_TRIGGERS,
  L3_PREFLIGHT_FLAGS,
  L3_PROHIBITED_EFFECTS,
  assertValidAdversarialPlan,
  digestAdversarialCandidateFacts,
  digestAdversarialPlan,
  digestAdversarialTacticalAction,
  evaluateL3CampaignBoundary,
  evaluateAdversarialEffectRisk,
} from './adversarial-validation-contracts.mjs'
import {
  evaluateL3PreflightWithBreakGlass,
  isBreakGlassControlWaivableForPlan,
} from './adversarial-break-glass-contracts.mjs'
import { assertValidAdversarialScopeRequest } from './adversarial-scope-contracts.mjs'
import { verifyOperatorAuthorizationReceipt } from './operator-authorization.mjs'
import { stableJson } from './run-engine.mjs'

const GLOBAL_ESCALATION_TRIGGERS = new Set([
  'OPERATOR_STOP',
  'CONTROL_PLANE_LOSS',
])
const ADVERSARIAL_TARGET_KIND_SET = new Set(['repository', 'local_service', 'live'])
const CAMPAIGN_LEDGER_OBSERVATION_MAX_BYTES = 16 * 1024 * 1024
const OPERATOR_AUTHORIZATION_START_GRACE_MS = 5 * 60 * 1000
const L3_LEDGER_QUALIFICATION_CONTRACT_VERSION = '1.1.0'
const L3_LEDGER_QUALIFICATION_EVENT_TYPES = Object.freeze([
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
const L3_LEDGER_QUALIFICATION_METHODS = Object.freeze([
  'assertQualificationContract',
  'recordActionProposed',
  'recordActionClassified',
  'recordScopeDecision',
  'recordActionPreflight',
  'recordBoundaryDecision',
  'recordSendPermit',
  'recordDispatchSettlement',
  'recordCampaignStop',
  'recordCleanupOutcome',
])
const AGENT_VISIBLE_OBSERVATION_STATUS_SET = new Set([
  'OBSERVED',
  'COUNTEREXAMPLE_OBSERVED',
  'NO_COUNTEREXAMPLE_OBSERVED',
  'NO_FINDING',
  'INCONCLUSIVE',
  'FAILED',
  'ERROR',
])

export class AdversarialRuntimeError extends Error {
  constructor(code, message, details = [], options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'AdversarialRuntimeError'
    this.code = code
    this.details = details
  }
}

function fail(code, message, details = [], options = {}) {
  throw new AdversarialRuntimeError(code, message, details, options)
}

function isLiteralLoopbackHostname(hostname) {
  if (hostname === '[::1]') return true
  const octets = hostname.split('.')
  return octets.length === 4
    && octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255)
    && Number(octets[0]) === 127
}

function assertRuntimeTargetSemantics(target) {
  if (target.kind === 'repository') {
    if (!target.locator.startsWith('repository://')) {
      fail(
        'ADVERSARIAL_REPOSITORY_TARGET_INVALID',
        'repository execution requires a repository:// target locator',
      )
    }
    return
  }
  if (target.kind !== 'local_service') return
  let url
  try {
    url = new URL(target.locator)
  } catch {
    url = null
  }
  if (
    !url
    || !['http:', 'https:'].includes(url.protocol)
    || !isLiteralLoopbackHostname(url.hostname)
    || url.username !== ''
    || url.password !== ''
  ) {
    fail(
      'ADVERSARIAL_LOCAL_SERVICE_TARGET_INVALID',
      'local-service execution requires a literal loopback HTTP(S) locator without credentials',
    )
  }
}

function canonicalJson(value) {
  const rendered = stableJson(value, 0)
  return rendered.endsWith('\n') ? rendered.slice(0, -1) : rendered
}

function deepFreeze(value, seen = new WeakSet()) {
  if (value === null || typeof value !== 'object' || seen.has(value)) return value
  seen.add(value)
  for (const child of Object.values(value)) deepFreeze(child, seen)
  return Object.freeze(value)
}

function snapshotJsonDocument(value, label, maxBytes = 1024 * 1024) {
  assertPlainJson(value, label)
  let rendered
  let snapshot
  try {
    rendered = canonicalJson(value)
    if (Buffer.byteLength(rendered, 'utf8') > maxBytes) {
      fail('ADVERSARIAL_RUNTIME_JSON_LIMIT', `${label} exceeds its canonical byte limit`)
    }
    snapshot = JSON.parse(rendered)
  } catch (cause) {
    if (cause instanceof AdversarialRuntimeError) throw cause
    fail('ADVERSARIAL_RUNTIME_JSON_INVALID', `${label} could not be snapshotted`, [], { cause })
  }
  assertPlainJson(snapshot, `${label} snapshot`)
  if (canonicalJson(snapshot) !== rendered) {
    fail('ADVERSARIAL_RUNTIME_JSON_UNSTABLE', `${label} changed while it was being snapshotted`)
  }
  return deepFreeze(snapshot)
}

function jsonBytes(value, label) {
  assertPlainJson(value, label)
  try {
    return Buffer.byteLength(canonicalJson(value), 'utf8')
  } catch (cause) {
    fail('ADVERSARIAL_RUNTIME_JSON_INVALID', `${label} is not canonical JSON`, [], { cause })
  }
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
      fail('ADVERSARIAL_RUNTIME_JSON_LIMIT', `${label} exceeds JSON depth or node limits`)
    }
    if (value === null || typeof value === 'string' || typeof value === 'boolean') continue
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) {
        fail('ADVERSARIAL_RUNTIME_JSON_INVALID', `${label} contains a non-finite number`)
      }
      continue
    }
    if (typeof value !== 'object') {
      fail('ADVERSARIAL_RUNTIME_JSON_INVALID', `${label} contains non-JSON data`)
    }
    if (activeAncestors.has(value)) {
      fail('ADVERSARIAL_RUNTIME_JSON_INVALID', `${label} contains a cycle`)
    }
    activeAncestors.add(value)
    stack.push({ value, depth, exit: true })
    const isArray = Array.isArray(value)
    const prototype = Object.getPrototypeOf(value)
    if ((!isArray && prototype !== Object.prototype && prototype !== null)
      || (isArray && prototype !== Array.prototype)) {
      fail('ADVERSARIAL_RUNTIME_JSON_INVALID', `${label} must contain only plain JSON objects and arrays`)
    }
    if (Object.getOwnPropertySymbols(value).length > 0) {
      fail('ADVERSARIAL_RUNTIME_JSON_INVALID', `${label} contains a symbol-keyed property`)
    }
    const descriptors = Object.getOwnPropertyDescriptors(value)
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (isArray && key === 'length') continue
      if (!descriptor.enumerable || 'get' in descriptor || 'set' in descriptor) {
        fail('ADVERSARIAL_RUNTIME_JSON_INVALID', `${label} contains a hidden or accessor property`)
      }
      stack.push({ value: descriptor.value, depth: depth + 1 })
    }
  }
}

function timestamp(value, label) {
  const parsed = value instanceof Date ? new Date(value.valueOf()) : new Date(value)
  if (Number.isNaN(parsed.valueOf())) {
    fail('ADVERSARIAL_RUNTIME_TIME_INVALID', `${label} must be a real timestamp`)
  }
  return parsed.valueOf()
}

function normalizeScopeDecision(value, expected) {
  try {
    value = snapshotJsonDocument(value, 'scope decision', 256 * 1024)
  } catch {
    return {
      allowed: false,
      decision: 'ERROR',
      reason: 'scope decision is not a bounded canonical JSON document',
    }
  }
  const expectedFields = [
    'action_sha256',
    'authorization_id',
    'candidate_facts_sha256',
    'effect_classification',
    'plan_sha256',
    'risk_class',
    'scope_revision_sha256',
    'status',
    'target',
  ]
  const actualFields = value && typeof value === 'object' && !Array.isArray(value)
    ? Object.keys(value).sort()
    : []
  if (
    actualFields.length !== expectedFields.length
    || actualFields.some((field, index) => field !== expectedFields[index])
  ) {
    return {
      allowed: false,
      decision: 'ERROR',
      reason: 'scope decision does not satisfy the exact controller response shape',
    }
  }
  if (
    value.plan_sha256 !== expected.planSha256
    || value.authorization_id !== expected.authorizationId
    || value.scope_revision_sha256 !== expected.scopeRevisionSha256
    || value.action_sha256 !== expected.actionSha256
    || value.candidate_facts_sha256 !== expected.candidateFactsSha256
    || value.risk_class !== expected.riskClass
    || value.target === null
    || typeof value.target !== 'object'
    || Array.isArray(value.target)
    || canonicalJson(value.target) !== canonicalJson(expected.target)
    || value.effect_classification?.complete !== true
    || !Array.isArray(value.effect_classification?.effects)
    || canonicalJson(value.effect_classification?.effects) !== canonicalJson(expected.effects)
  ) {
    return {
      allowed: false,
      reason: 'scope decision does not bind the exact current action, classification, target, risk, and scope revision',
      decision: 'ERROR',
    }
  }
  if (value.status !== 'AUTHORIZED') {
    return {
      allowed: false,
      reason: 'scope decision denied the exact current action',
      decision: 'DENIED',
    }
  }
  return { allowed: true, decision: 'AUTHORIZED', controllerAuthorization: value }
}

function assertControllerClassification(value, plan, { enforceL3ProhibitedEffects = false } = {}) {
  const classification = snapshotJsonDocument(
    value,
    'controller action classification',
    Math.min(plan.limits.max_input_bytes, 256 * 1024),
  )
  const allowedFields = new Set([
    'candidate_context',
    'resolved_target',
    'anticipated_effects',
    'strategy_family',
  ])
  for (const field of Object.keys(classification)) {
    if (!allowedFields.has(field)) {
      fail('ADVERSARIAL_CLASSIFICATION_INVALID', `controller classification contains unknown field ${field}`)
    }
  }
  if (
    classification.candidate_context === null
    || typeof classification.candidate_context !== 'object'
    || Array.isArray(classification.candidate_context)
    || !Array.isArray(classification.anticipated_effects)
    || classification.resolved_target === null
    || typeof classification.resolved_target !== 'object'
    || Array.isArray(classification.resolved_target)
    || typeof classification.strategy_family !== 'string'
    || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{2,159}$/.test(classification.strategy_family)
  ) {
    fail(
      'ADVERSARIAL_CLASSIFICATION_INVALID',
      'controller classification must provide a resolved target, candidate_context, and anticipated_effects',
    )
  }
  const targetFields = Object.keys(classification.resolved_target).sort()
  if (
    canonicalJson(targetFields) !== canonicalJson(['identity_sha256', 'kind', 'locator', 'target_id'])
    || !ADVERSARIAL_TARGET_KIND_SET.has(classification.resolved_target.kind)
    || typeof classification.resolved_target.target_id !== 'string'
    || typeof classification.resolved_target.locator !== 'string'
    || !/^[a-f0-9]{64}$/.test(classification.resolved_target.identity_sha256 ?? '')
  ) {
    fail('ADVERSARIAL_CLASSIFICATION_INVALID', 'resolved target classification is invalid')
  }
  if (
    classification.anticipated_effects.some((effect) => typeof effect !== 'string')
    || new Set(classification.anticipated_effects).size !== classification.anticipated_effects.length
  ) {
    fail('ADVERSARIAL_CLASSIFICATION_INVALID', 'anticipated effects must be unique string identifiers')
  }
  const unknownEffects = classification.anticipated_effects
    .filter((effect) => !ADVERSARIAL_EFFECTS.includes(effect))
  if (unknownEffects.length > 0) {
    fail(
      'ADVERSARIAL_EFFECT_UNKNOWN',
      'anticipated effects must use the closed controller-owned effect taxonomy',
      unknownEffects.sort(),
    )
  }
  const prohibited = enforceL3ProhibitedEffects
    ? classification.anticipated_effects.filter((effect) => L3_PROHIBITED_EFFECTS.includes(effect))
    : []
  if (prohibited.length > 0) {
    fail(
      'ADVERSARIAL_PROHIBITED_EFFECT',
      'controller classified the action with a prohibited campaign effect',
      prohibited,
    )
  }
  const effectRisk = evaluateAdversarialEffectRisk(
    plan.risk_class,
    classification.anticipated_effects,
  )
  if (!effectRisk.valid) {
    fail(
      'ADVERSARIAL_EFFECT_RISK_UNDERCLASSIFIED',
      `plan risk ${plan.risk_class} is below required ${effectRisk.minimum_risk_class}`,
      effectRisk,
    )
  }
  return classification
}

function governedL3Action(action, classification, adaptive) {
  if (adaptive) {
    if (classification.strategy_family !== action.strategy_family) {
      fail(
        'ADVERSARIAL_CLASSIFICATION_INVALID',
        'controller strategy classification does not match the adaptive action',
      )
    }
    return action
  }
  return snapshotJsonDocument({
    ...structuredClone(action),
    branch_id: 'branch:sealed-actions',
    chain_depth: 1,
    strategy_family: classification.strategy_family,
  }, 'governed sealed L3 action', 32 * 1024 * 1024)
}

function assertTacticalAction(action, plan) {
  if (action === null || typeof action !== 'object' || Array.isArray(action)) {
    fail('ADVERSARIAL_TACTICAL_ACTION_INVALID', 'tactical action must be an object')
  }
  assertPlainJson(action, 'tactical action')
  const allowedFields = new Set([
    'action_id',
    'branch_id',
    'chain_depth',
    'purpose',
    'action_category',
    'operation',
    'strategy_family',
    'parameters',
  ])
  for (const field of Object.keys(action)) {
    if (!allowedFields.has(field)) {
      fail('ADVERSARIAL_TACTICAL_ACTION_INVALID', `tactical action contains unknown field ${field}`)
    }
  }
  const idPattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]{2,159}$/
  for (const field of ['action_id', 'branch_id', 'action_category', 'operation', 'strategy_family']) {
    if (typeof action[field] !== 'string' || !idPattern.test(action[field])) {
      fail('ADVERSARIAL_TACTICAL_ACTION_INVALID', `tactical action ${field} is invalid`)
    }
  }
  if (!['baseline', 'control', 'attack', 'verification', 'cleanup'].includes(action.purpose)) {
    fail('ADVERSARIAL_TACTICAL_ACTION_INVALID', 'tactical action purpose is invalid')
  }
  if (!Number.isInteger(action.chain_depth) || action.chain_depth < 1) {
    fail('ADVERSARIAL_TACTICAL_ACTION_INVALID', 'tactical action chain_depth must be positive')
  }
  if (
    action.parameters === null
    || typeof action.parameters !== 'object'
    || Array.isArray(action.parameters)
  ) {
    fail('ADVERSARIAL_TACTICAL_ACTION_INVALID', 'tactical action parameters must be an object')
  }
  if (jsonBytes(action.parameters, 'tactical action parameters') > plan.limits.max_input_bytes) {
    fail('ADVERSARIAL_TACTICAL_INPUT_LIMIT', 'tactical action parameters exceed max_input_bytes')
  }
  if (jsonBytes(action, 'tactical action') > plan.limits.max_input_bytes * 2) {
    fail('ADVERSARIAL_TACTICAL_INPUT_LIMIT', 'tactical action exceeds its bounded input envelope')
  }
  return action
}

async function readPreflight(source) {
  const value = typeof source === 'function' ? await source() : source
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {}
  return snapshotJsonDocument(value, 'runtime preflight', 256 * 1024)
}

function runtimePreflightFailures(plan, runtimePreflight, preflight) {
  const waived = preflight.waived_controls
  const failed = L3_PREFLIGHT_FLAGS.filter((flag) => runtimePreflight?.[flag] !== true)
  const nonOverridable = failed.filter((flag) =>
    !isBreakGlassControlWaivableForPlan(plan, flag))
  if (nonOverridable.length > 0) {
    return nonOverridable.map((flag) => `NON_OVERRIDABLE_RUNTIME_PREFLIGHT:${flag}`)
  }
  const reasons = failed
    .filter((flag) => !waived.includes(flag))
    .map((flag) => `RUNTIME_PREFLIGHT_NOT_READY:${flag}`)
  if (preflight.mode === 'BREAK_GLASS') {
    for (const declared of preflight.failed_controls ?? []) {
      if (runtimePreflight?.[declared.control] === true) {
        reasons.push(`BREAK_GLASS_FAILURE_CONDITION_CHANGED:${declared.control}`)
        continue
      }
      const current = runtimePreflight?.control_observations?.[declared.control]
      if (
        current?.status !== declared.status
        || current?.observation_sha256 !== declared.observation_sha256
      ) {
        reasons.push(`BREAK_GLASS_FAILURE_EVIDENCE_CHANGED:${declared.control}`)
      }
    }
  }
  return reasons
}

function effectiveRuntimePreflight(runtimePreflight, waived) {
  const result = { ...runtimePreflight }
  for (const flag of waived) result[flag] = true
  return result
}

function effectiveLimits(plan, preflight) {
  if (preflight.mode !== 'BREAK_GLASS') return { ...plan.limits }
  return {
    ...plan.limits,
    ...preflight.effective_limits,
  }
}

function dispatchWithTimeout(dispatch, action, context, timeoutMs, campaignSignal) {
  const controller = new AbortController()
  let timer
  let campaignAbortListener
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const error = new AdversarialRuntimeError(
        'ADVERSARIAL_ACTION_TIMEOUT',
        `action ${action.action_id} exceeded max_action_time_ms`,
      )
      controller.abort(error)
      reject(error)
    }, timeoutMs)
    timer.unref?.()
  })
  const campaignAbort = campaignSignal === undefined
    ? null
    : new Promise((_, reject) => {
      campaignAbortListener = () => {
        const error = new AdversarialRuntimeError(
          'ADVERSARIAL_CAMPAIGN_ABORTED',
          'operator kill aborted the in-flight adversarial action',
        )
        controller.abort(error)
        reject(error)
      }
      if (campaignSignal.aborted) campaignAbortListener()
      else campaignSignal.addEventListener('abort', campaignAbortListener, { once: true })
    })
  const operation = Promise.resolve().then(() => {
    if (controller.signal.aborted || campaignSignal?.aborted === true) {
      throw controller.signal.reason ?? new AdversarialRuntimeError(
        'ADVERSARIAL_CAMPAIGN_ABORTED',
        'operator kill aborted the adversarial action before dispatch',
      )
    }
    return dispatch(
      structuredClone(action),
      { ...context, signal: controller.signal },
    )
  })
  const racers = campaignAbort === null ? [operation, timeout] : [operation, timeout, campaignAbort]
  return Promise.race(racers).finally(() => {
    clearTimeout(timer)
    if (campaignAbortListener !== undefined) {
      campaignSignal.removeEventListener('abort', campaignAbortListener)
    }
  })
}

function delayWithSignal(milliseconds, signal) {
  return new Promise((resolve) => {
    let timer
    const onAbort = () => {
      clearTimeout(timer)
      resolve(false)
    }
    if (signal?.aborted === true) {
      resolve(false)
      return
    }
    timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort)
      resolve(true)
    }, milliseconds)
    signal?.addEventListener('abort', onAbort, { once: true })
  })
}

function scopeExpansionCandidate(action, refusal) {
  return deepFreeze({
    kind: 'red-team-audit/adversarial-scope-expansion-candidate',
    disposition: 'QUEUE_SCOPE_EXPANSION_REQUEST',
    reason: refusal.reason ?? refusal.reasons?.join(', ') ?? 'action is outside current authority',
    action: {
      action_id: action.action_id,
      branch_id: action.branch_id ?? 'branch:exact-plan',
      purpose: action.purpose,
      action_category: action.action_category,
      operation: action.operation,
      strategy_family: action.strategy_family ?? null,
      parameters_sha256: digestJson(action.parameters),
    },
  })
}

function emitScopeRequest(scopeRequestBuilder, action, refusal, context) {
  const candidate = scopeExpansionCandidate(action, refusal)
  let proposed
  try {
    proposed = scopeRequestBuilder(
      structuredClone(candidate),
      deepFreeze(structuredClone(context)),
    )
  } catch (cause) {
    fail(
      'ADVERSARIAL_SCOPE_REQUEST_BUILD_FAILED',
      'the formal scope-request builder failed closed',
      [],
      { cause },
    )
  }
  if (proposed && typeof proposed.then === 'function') {
    fail(
      'ADVERSARIAL_SCOPE_REQUEST_BUILDER_INVALID',
      'the formal scope-request builder must be synchronous and inert',
    )
  }
  const request = snapshotJsonDocument(proposed, 'formal scope expansion request', 256 * 1024)
  try {
    assertValidAdversarialScopeRequest(request)
  } catch (cause) {
    fail(
      'ADVERSARIAL_SCOPE_REQUEST_INVALID',
      'the proposed scope expansion does not satisfy the formal inert request contract',
      [],
      { cause },
    )
  }
  if (
    request.engagement_id !== context.plan.engagement_id
    || request.base_scope.sha256 !== context.scope_revision_sha256
    || request.attack_plan_sha256 !== context.plan_sha256
    || !request.discovery_evidence.some(({ sha256 }) => sha256 === context.action_sha256)
  ) {
    fail(
      'ADVERSARIAL_SCOPE_REQUEST_BINDING_INVALID',
      'scope request must bind the current engagement, scope, attack plan, and blocked action evidence',
    )
  }
  return request
}

function digestJson(value) {
  return createHash('sha256')
    .update(Buffer.from(canonicalJson(value), 'utf8'))
    .digest('hex')
}

function normalizedOperatorAuthorizationReceipt({ plan, planSha256, receipt, now }) {
  const verified = verifyOperatorAuthorizationReceipt({
    value: receipt,
    planSha256,
    scopeRevisionSha256: plan.scope_revision_sha256,
    target: plan.target,
    fail(code, message) {
      fail(`ADVERSARIAL_OPERATOR_AUTHORIZATION_${code}`, message)
    },
  })
  const declaredAt = Date.parse(verified.declared_at)
  const currentTime = timestamp(now, 'now')
  const expiresAt = declaredAt + OPERATOR_AUTHORIZATION_START_GRACE_MS + plan.limits.max_wall_time_ms
  if (declaredAt > currentTime) {
    fail(
      'ADVERSARIAL_OPERATOR_AUTHORIZATION_TIME_FUTURE',
      'operator authorization receipt cannot be future-dated',
    )
  }
  if (currentTime >= expiresAt) {
    fail(
      'ADVERSARIAL_OPERATOR_AUTHORIZATION_EXPIRED',
      'operator authorization receipt is outside its plan-derived execution window',
    )
  }
  return deepFreeze({
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-authorization-receipt',
    status: 'CONTROLLER_VERIFIED',
    authorization_id: verified.authorization_reference,
    authorization_reference: verified.authorization_reference,
    authorization_sha256: verified.authorization_sha256,
    authority_basis: verified.authority_basis,
    operator_id: verified.operator_id,
    plan_sha256: verified.plan_sha256,
    engagement_id: plan.engagement_id,
    scope_revision_sha256: verified.scope_revision_sha256,
    target_sha256: verified.target_sha256,
    risk_class: plan.risk_class,
    autonomy_profile: plan.autonomy_profile,
    declared_at: verified.declared_at,
    expires_at: new Date(expiresAt).toISOString(),
  })
}

async function readCurrentAuthorizationControl({
  authorizationReceipt,
  isAuthorizationRevoked,
  isOperatorStopRequested,
}) {
  let stopRequested
  try {
    stopRequested = await isOperatorStopRequested(
      Object.freeze({ ...authorizationReceipt }),
    )
  } catch {
    return {
      allowed: false,
      status: 'PAUSED_AUTHORIZATION',
      reason: 'OPERATOR_STOP_CHECK_FAILED',
    }
  }
  if (typeof stopRequested !== 'boolean') {
    return {
      allowed: false,
      status: 'PAUSED_AUTHORIZATION',
      reason: 'OPERATOR_STOP_CHECK_INVALID',
    }
  }
  if (stopRequested) {
    return { allowed: false, status: 'ABORTED', reason: 'OPERATOR_STOP' }
  }

  let revoked
  try {
    revoked = await isAuthorizationRevoked(Object.freeze({ ...authorizationReceipt }))
  } catch {
    return {
      allowed: false,
      status: 'PAUSED_AUTHORIZATION',
      reason: 'AUTHORIZATION_REVOCATION_CHECK_FAILED',
    }
  }
  if (typeof revoked !== 'boolean') {
    return {
      allowed: false,
      status: 'PAUSED_AUTHORIZATION',
      reason: 'AUTHORIZATION_REVOCATION_CHECK_INVALID',
    }
  }
  if (revoked) {
    return {
      allowed: false,
      status: 'PAUSED_AUTHORIZATION',
      reason: 'AUTHORIZATION_REVOKED',
    }
  }
  return {
    allowed: true,
    currentAuthorization: Object.freeze({
      status: 'CURRENT',
      authorization_id: authorizationReceipt.authorization_id,
      plan_sha256: authorizationReceipt.plan_sha256,
      revoked: false,
      scope_revision_sha256: authorizationReceipt.scope_revision_sha256,
      stop_requested: false,
    }),
  }
}

function boundedReasonCodes(reasons, fallback = 'UNSPECIFIED') {
  const source = Array.isArray(reasons) ? reasons : []
  const bounded = source.slice(0, 64).map((reason) => {
    if (typeof reason !== 'string' || reason.length < 1) return fallback
    return reason.length <= 256 ? reason : `${reason.slice(0, 184)}:sha256:${digestJson(reason)}`
  })
  return bounded.length > 0 ? [...new Set(bounded)] : []
}

function dispatchRecoveryObservation({
  actionSha256,
  settlementOutcome,
  sourceObservationSha256 = null,
  reasons,
}) {
  return deepFreeze({
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-dispatch-recovery-observation',
    status: 'ERROR',
    action_sha256: actionSha256,
    output_bytes: 0,
    escalation_triggers: ['AMBIGUOUS_AUTHORIZATION_OR_CLEANUP'],
    settlement_outcome: settlementOutcome,
    source_observation_sha256: sourceObservationSha256,
    reason_codes: boundedReasonCodes(reasons, 'DISPATCH_OUTCOME_UNAVAILABLE'),
  })
}

function scopeQualificationReceipt({
  stage,
  actionSha256,
  classificationSha256,
  candidateFactsSha256,
  resolvedTarget,
  effects,
  scopeRevisionSha256,
  decision,
}) {
  const decisionRecord = decision.allowed
    ? decision.controllerAuthorization
    : { decision: decision.decision ?? 'DENIED', reason: decision.reason ?? 'SCOPE_DENIED' }
  return deepFreeze({
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-scope-qualification-receipt',
    stage,
    status: decision.allowed ? 'ALLOW' : decision.decision === 'ERROR' ? 'ERROR' : 'DENY',
    action_sha256: actionSha256,
    classification_sha256: classificationSha256,
    candidate_facts_sha256: candidateFactsSha256,
    resolved_target_sha256: digestJson(resolvedTarget),
    effect_classification_sha256: digestJson({ complete: true, effects }),
    scope_revision_sha256: scopeRevisionSha256,
    decision_sha256: digestJson(decisionRecord),
    authorization_sha256: decision.allowed ? digestJson(decision.controllerAuthorization) : null,
    reason_codes: decision.allowed ? [] : boundedReasonCodes([decision.reason], 'SCOPE_DENIED'),
  })
}

function preflightQualificationReceipt({
  stage,
  actionSha256,
  status,
  runtimePreflight,
  currentAuthorization,
  reasons = [],
}) {
  return deepFreeze({
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-action-preflight-receipt',
    stage,
    status,
    action_sha256: actionSha256,
    runtime_preflight_sha256: runtimePreflight === null ? null : digestJson(runtimePreflight),
    authorization_state_sha256: currentAuthorization === null
      ? null
      : digestJson(currentAuthorization),
    reason_codes: boundedReasonCodes(reasons, 'PREFLIGHT_DENIED'),
  })
}

function effectiveObservationTriggers(observation) {
  if (!Array.isArray(observation?.escalation_triggers)) {
    return ['AMBIGUOUS_AUTHORIZATION_OR_CLEANUP']
  }
  const known = observation.escalation_triggers.filter((trigger) =>
    typeof trigger === 'string' && L3_MANDATORY_ESCALATION_TRIGGERS.includes(trigger))
  const containsUnknown = known.length !== observation.escalation_triggers.length
  return [...new Set(containsUnknown
    ? [...known, 'AMBIGUOUS_AUTHORIZATION_OR_CLEANUP']
    : known)]
}

function agentObservationReceipt({
  actionId,
  actionSha256,
  branchId,
  observation,
  observationSha256 = digestJson(observation),
  accountedOutputBytes,
}) {
  return deepFreeze({
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-agent-observation-receipt',
    action_id: actionId,
    action_sha256: actionSha256,
    branch_id: branchId,
    observation_sha256: observationSha256,
    status: AGENT_VISIBLE_OBSERVATION_STATUS_SET.has(observation?.status)
      ? observation.status
      : 'UNCLASSIFIED',
    accounted_output_bytes: Number.isSafeInteger(accountedOutputBytes) && accountedOutputBytes >= 0
      ? accountedOutputBytes
      : null,
    escalation_triggers: effectiveObservationTriggers(observation),
  })
}

function terminalResult(state, status, extras = {}) {
  return {
    status,
    plan_sha256: state.planSha256,
    authorization_receipt: state.authorizationReceipt,
    preflight_mode: state.preflight.mode,
    waived_preflight_controls: [...state.preflight.waived_controls],
    considered_actions: state.considered,
    dispatched_actions: state.dispatched,
    aggregate_output_bytes: state.aggregateOutputBytes,
    paused_branches: [...state.pausedBranches].sort(),
    scope_requests: [...state.scopeRequests],
    observations: [...state.observations],
    agent_observation_receipts: [...state.observationReceipts],
    ...extras,
  }
}

function durableTerminalResult(result) {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-campaign-terminal-summary',
    status: result.status,
    plan_sha256: result.plan_sha256,
    authorization_receipt: result.authorization_receipt,
    preflight_mode: result.preflight_mode,
    waived_preflight_controls: result.waived_preflight_controls,
    considered_actions: result.considered_actions,
    dispatched_actions: result.dispatched_actions,
    aggregate_output_bytes: result.aggregate_output_bytes,
    paused_branch_count: result.paused_branches.length,
    scope_request_count: result.scope_requests.length,
    observation_count: result.observations.length,
    ...(Array.isArray(result.stop_reasons)
      ? { stop_reasons: structuredClone(result.stop_reasons) }
      : {}),
  }
}

function observationReceiptsFromLedgerSnapshot(snapshot) {
  return (snapshot?.observation_records ?? []).map((record) =>
    agentObservationReceipt({
      actionId: record.action_id,
      actionSha256: record.action_sha256,
      branchId: record.branch_id,
      observation: record.observation,
      observationSha256: record.observation_sha256,
      accountedOutputBytes: record.accounted_output_bytes,
    }))
}

function hydrateDurableTerminalResult(result, snapshot) {
  if (result?.kind !== 'red-team-audit/adversarial-campaign-terminal-summary') return result
  const {
    paused_branch_count: _pausedBranchCount,
    scope_request_count: _scopeRequestCount,
    observation_count: _observationCount,
    ...summary
  } = result
  return {
    ...summary,
    paused_branches: structuredClone(snapshot.paused_branches),
    scope_requests: structuredClone(snapshot.scope_requests),
    observations: structuredClone(snapshot.observations),
    agent_observation_receipts: observationReceiptsFromLedgerSnapshot(snapshot),
  }
}

function ledgerMetadata(snapshot) {
  return {
    record_count: snapshot.record_count,
    head_sha256: snapshot.head_sha256,
    terminal: snapshot.terminal,
    pending_dispatch: snapshot.pending_dispatch === null
      ? null
      : {
          action_id: snapshot.pending_dispatch.action_id,
          action_sha256: snapshot.pending_dispatch.action_sha256,
          branch_id: snapshot.pending_dispatch.branch_id,
        },
  }
}

function withLedgerMetadata(result, snapshot) {
  return {
    ...structuredClone(result),
    campaign_ledger: ledgerMetadata(snapshot),
  }
}

function assertCampaignLedger(value, { requireL3Qualification = false } = {}) {
  if (value === undefined || value === null) return null
  const methods = [
    'assertBinding',
    'snapshot',
    'start',
    'recordResume',
    'recordActionConsidered',
    'recordActionSkipped',
    'recordPreDispatch',
    'recordDispatchSettlement',
    'recordDispatchCancelled',
    'recordObservation',
    'recordScopeRequest',
    'recordCheckpointQueued',
    'recordCheckpointAcknowledged',
    'recordTerminal',
  ]
  if (methods.some((method) => typeof value[method] !== 'function')) {
    fail(
      'ADVERSARIAL_CAMPAIGN_LEDGER_INVALID',
      'campaign ledger does not implement the required durable controller interface',
    )
  }
  if (
    requireL3Qualification
    && L3_LEDGER_QUALIFICATION_METHODS.some((method) => typeof value[method] !== 'function')
  ) {
    fail(
      'ADVERSARIAL_L3_LEDGER_QUALIFICATION_REQUIRED',
      'maximum-authority execution requires a ledger that durably qualifies every proposal, classification, scope and preflight decision, send, settlement, stop, cleanup, and terminal outcome',
    )
  }
  return value
}

async function assertL3LedgerQualification(ledger, binding) {
  const requirements = deepFreeze({
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-ledger-qualification-requirements',
    contract_version: L3_LEDGER_QUALIFICATION_CONTRACT_VERSION,
    binding_sha256: digestJson(binding),
    required_event_types: [...L3_LEDGER_QUALIFICATION_EVENT_TYPES],
  })
  let receipt
  try {
    receipt = snapshotJsonDocument(
      await ledger.assertQualificationContract(structuredClone(requirements)),
      'campaign ledger qualification receipt',
      64 * 1024,
    )
  } catch (cause) {
    if (cause instanceof AdversarialRuntimeError) throw cause
    fail(
      'ADVERSARIAL_L3_LEDGER_QUALIFICATION_REQUIRED',
      'maximum-authority campaign ledger qualification failed closed',
      [],
      { cause },
    )
  }
  const expectedFields = [
    'binding_sha256',
    'contract_version',
    'kind',
    'requirements_sha256',
    'schema_version',
    'status',
  ]
  if (
    canonicalJson(Object.keys(receipt).sort()) !== canonicalJson(expectedFields)
    || receipt.schema_version !== '1.0.0'
    || receipt.kind !== 'red-team-audit/adversarial-ledger-qualification-receipt'
    || receipt.status !== 'QUALIFIED'
    || receipt.contract_version !== L3_LEDGER_QUALIFICATION_CONTRACT_VERSION
    || receipt.binding_sha256 !== requirements.binding_sha256
    || receipt.requirements_sha256 !== digestJson(requirements)
  ) {
    fail(
      'ADVERSARIAL_L3_LEDGER_QUALIFICATION_REQUIRED',
      'maximum-authority campaign ledger did not attest the complete qualification contract',
    )
  }
  return receipt
}

/**
 * Execute an exact or maximum-authority adversarial plan through controller-owned
 * gates. `dispatch` is the only target-I/O seam and is never invoked before live
 * authorization, current-scope, runtime-preflight, and per-action limit checks pass.
 */
export async function executeAdversarialCampaign(options) {
  const {
    plan: inputPlan,
    operatorAuthorizationReceipt: inputOperatorAuthorizationReceipt,
    now = new Date(),
    clock: legacyClock,
    wallClock: inputWallClock,
    monotonicClock: inputMonotonicClock,
    runtimePreflight,
    breakGlassOverride: inputBreakGlassOverride,
    breakGlassPinnedKey,
    breakGlassNonceStore,
    scopeAuthorize,
    dispatch,
    proposeNextAction,
    classifyAction,
    scopeRequestBuilder,
    scopeRequestSink,
    checkpoint,
    isAuthorizationRevoked,
    isOperatorStopRequested,
    campaignLedger: inputCampaignLedger,
    trustedCampaignLedger: inputTrustedCampaignLedger,
    signal: campaignSignal,
  } = options ?? {}

  // `clock` remains a compatibility hook for deterministic callers. Production
  // controllers must leave it unset (or pass both explicit clocks) so civil-time
  // validity and elapsed-budget accounting cannot fail in the same way.
  const wallClock = inputWallClock ?? legacyClock ?? (() => Date.now())
  const monotonicClock = inputMonotonicClock ?? legacyClock ?? (() => performance.now())
  if (typeof wallClock !== 'function' || typeof monotonicClock !== 'function') {
    fail(
      'ADVERSARIAL_RUNTIME_CLOCK_REQUIRED',
      'runtime wall and monotonic clocks must be controller-owned functions',
    )
  }

  const plan = snapshotJsonDocument(inputPlan, 'adversarial plan')
  assertValidAdversarialPlan(plan)
  assertRuntimeTargetSemantics(plan.target)
  if (plan.generator !== undefined) {
    fail(
      'ADVERSARIAL_GENERATOR_UNSUPPORTED',
      'this runtime does not execute sealed generator plans until a controller-owned generator provider is enrolled',
    )
  }
  const operatorAuthorizationReceipt = inputOperatorAuthorizationReceipt === null
    || inputOperatorAuthorizationReceipt === undefined
    ? inputOperatorAuthorizationReceipt
    : snapshotJsonDocument(
        inputOperatorAuthorizationReceipt,
        'operator authorization receipt',
        64 * 1024,
      )
  const breakGlassOverride = inputBreakGlassOverride === null || inputBreakGlassOverride === undefined
    ? inputBreakGlassOverride
    : snapshotJsonDocument(inputBreakGlassOverride, 'break-glass override', 64 * 1024)
  if (typeof dispatch !== 'function') {
    fail('ADVERSARIAL_DISPATCH_REQUIRED', 'a controller-owned dispatch adapter is required')
  }
  const isLive = plan.target.kind === 'live'
  const requiresAuthorization = isLive || plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED'
  const requiresScopeGate = isLive || plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED'
  const requiresClassification = isLive || plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED'
  if (
    requiresAuthorization
    && (operatorAuthorizationReceipt === null || operatorAuthorizationReceipt === undefined)
  ) {
    fail(
      'ADVERSARIAL_LIVE_AUTHORIZATION_REQUIRED',
      'live crafted testing and maximum-authority campaigns require a controller-verified operator authorization receipt',
    )
  }
  if (
    !Array.isArray(plan.actions)
    && !(plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED' && typeof proposeNextAction === 'function')
  ) {
    fail(
      'ADVERSARIAL_EXECUTION_SHAPE_EMPTY',
      'execution requires exact actions or an enrolled L3 tactical proposer',
    )
  }
  if (requiresScopeGate && typeof scopeAuthorize !== 'function') {
    fail('ADVERSARIAL_SCOPE_GATE_REQUIRED', 'live and maximum-authority execution require a concrete-action scope gate')
  }
  const authorizationRevocationCheck = isAuthorizationRevoked
  const operatorStopCheck = isOperatorStopRequested
  if (requiresAuthorization && typeof authorizationRevocationCheck !== 'function') {
    fail(
      'ADVERSARIAL_REVOCATION_GATE_REQUIRED',
      'live execution requires a fail-closed current-authorization revocation gate',
    )
  }
  if (requiresAuthorization && typeof operatorStopCheck !== 'function') {
    fail(
      'ADVERSARIAL_OPERATOR_STOP_GATE_REQUIRED',
      'live execution requires a fail-closed controller operator-stop gate',
    )
  }
  if (requiresClassification && typeof classifyAction !== 'function') {
    fail(
      'ADVERSARIAL_CLASSIFIER_REQUIRED',
      'live and maximum-authority execution require a controller-owned destination and effect classifier',
    )
  }
  if (plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED' && typeof checkpoint !== 'function') {
    fail(
      'ADVERSARIAL_CHECKPOINT_REQUIRED',
      'maximum-authority execution requires an acknowledged checkpoint sink',
    )
  }
  if (
    isLive
    && plan.autonomy_profile === 'L2_SUPERVISED'
    && typeof checkpoint !== 'function'
  ) {
    fail(
      'ADVERSARIAL_SUPERVISION_REQUIRED',
      'supervised live execution requires an acknowledged checkpoint sink',
    )
  }
  if (
    requiresScopeGate
    && typeof scopeRequestBuilder !== 'function'
  ) {
    fail(
      'ADVERSARIAL_SCOPE_REQUEST_BUILDER_REQUIRED',
      'live and maximum-authority execution require a controller-owned formal scope-request builder',
    )
  }

  const planSha256 = digestAdversarialPlan(plan)
  const verifiedOperatorAuthorizationReceipt = requiresAuthorization
    ? normalizedOperatorAuthorizationReceipt({
        plan,
        planSha256,
        receipt: operatorAuthorizationReceipt,
        now,
      })
    : null
  if (requiresAuthorization && inputCampaignLedger !== null && inputCampaignLedger !== undefined) {
    fail(
      'ADVERSARIAL_AUTHORIZATION_BOUND_LEDGER_UNTRUSTED',
      'authorization-bound campaigns require a controller-trusted ledger for campaign lease and durable qualification writes',
    )
  }
  if (requiresAuthorization && (inputTrustedCampaignLedger === null || inputTrustedCampaignLedger === undefined)) {
    fail(
      'ADVERSARIAL_TRUSTED_CAMPAIGN_LEDGER_REQUIRED',
      'authorization-bound execution requires a controller-owned append-only campaign ledger before target I/O',
    )
  }
  if (!requiresAuthorization && inputTrustedCampaignLedger !== null && inputTrustedCampaignLedger !== undefined) {
    fail(
      'ADVERSARIAL_TRUSTED_CAMPAIGN_LEDGER_UNEXPECTED',
      'controller-trusted campaign ledger authority is reserved for authorization-bound execution',
    )
  }
  const campaignLedger = assertCampaignLedger(
    requiresAuthorization ? inputTrustedCampaignLedger : inputCampaignLedger,
    { requireL3Qualification: plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED' },
  )
  const ledgerBinding = {
    plan_sha256: planSha256,
    authorization_id: requiresAuthorization
      ? verifiedOperatorAuthorizationReceipt.authorization_id
      : null,
    authorization_sha256: requiresAuthorization
      ? verifiedOperatorAuthorizationReceipt.authorization_sha256
      : null,
    scope_revision_sha256: plan.scope_revision_sha256,
  }
  let ledgerSnapshot = campaignLedger === null
    ? null
    : await campaignLedger.assertBinding(ledgerBinding)
  if (
    requiresAuthorization
    && ledgerSnapshot?.started
    && canonicalJson(ledgerSnapshot.authorization_receipt)
      !== canonicalJson(verifiedOperatorAuthorizationReceipt)
  ) {
    fail(
      'ADVERSARIAL_LEDGER_AUTHORIZATION_RECEIPT_MISMATCH',
      'persisted campaign authorization receipt differs from the current controller-verified receipt',
    )
  }
  const ledgerQualificationReceipt = plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED'
    ? await assertL3LedgerQualification(campaignLedger, ledgerBinding)
    : null
  if (
    plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED'
    && ledgerSnapshot?.started
    && canonicalJson(ledgerSnapshot.qualification_receipt) !== canonicalJson(ledgerQualificationReceipt)
  ) {
    fail(
      'ADVERSARIAL_L3_LEDGER_QUALIFICATION_REQUIRED',
      'maximum-authority campaign ledger was started under a stale or different lifecycle qualification contract',
    )
  }
  if (ledgerSnapshot?.terminal) {
    return withLedgerMetadata(
      hydrateDurableTerminalResult(ledgerSnapshot.terminal_result, ledgerSnapshot),
      ledgerSnapshot,
    )
  }
  const settleInterruptedDispatch = async (snapshot, reasonCode) => {
    const pending = snapshot?.pending_dispatch
    if (pending === null || pending === undefined) return snapshot

    const actionRecords = snapshot.qualification_records ?? []
    const sendPermitRecord = [...actionRecords].reverse().find((record) =>
      record.type === 'ACTION_SEND_PERMITTED'
      && record.action_id === pending.action_id
      && record.action_sha256 === pending.action_sha256)
    const settlementRecord = [...actionRecords].reverse().find((record) =>
      record.type === 'ACTION_DISPATCH_SETTLED'
      && record.action_id === pending.action_id
      && record.action_sha256 === pending.action_sha256)
    const proposalRecord = [...actionRecords].reverse().find((record) =>
      record.type === 'ACTION_PROPOSED'
      && record.action_id === pending.action_id)
    const sendPermitSha256 = pending.send_permit_sha256
      ?? sendPermitRecord?.permit_sha256
      ?? null
    let settlement = pending.settlement ?? settlementRecord?.receipt ?? null
    let current = snapshot

    if (settlement === null) {
      if (plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED' && sendPermitSha256 === null) {
        return campaignLedger.recordDispatchCancelled({
          actionId: pending.action_id,
          actionSha256: pending.action_sha256,
          reasonCodes: [reasonCode],
          elapsedMs: current.elapsed_ms,
        })
      }
      const observation = dispatchRecoveryObservation({
        actionSha256: pending.action_sha256,
        settlementOutcome: 'AMBIGUOUS',
        reasons: [reasonCode],
      })
      const observationSha256 = digestJson(observation)
      settlement = {
        schema_version: '1.0.0',
        kind: 'red-team-audit/adversarial-dispatch-settlement-receipt',
        action_sha256: pending.action_sha256,
        send_permit_sha256: sendPermitSha256,
        outcome: 'AMBIGUOUS',
        request_may_have_been_sent: true,
        observation_sha256: observationSha256,
        reason_codes: [reasonCode],
      }
      current = await campaignLedger.recordDispatchSettlement({
        actionId: pending.action_id,
        actionSha256: pending.action_sha256,
        branchId: pending.branch_id,
        receipt: settlement,
        elapsedMs: current.elapsed_ms,
      })
      current = await campaignLedger.recordObservation({
        actionId: pending.action_id,
        actionSha256: pending.action_sha256,
        branchId: pending.branch_id,
        observation,
        accountedOutputBytes: 0,
        aggregateOutputBytes: current.aggregate_output_bytes,
        pauseBranch: true,
        elapsedMs: current.elapsed_ms,
      })
    } else {
      const observation = dispatchRecoveryObservation({
        actionSha256: pending.action_sha256,
        settlementOutcome: settlement.outcome,
        sourceObservationSha256: settlement.observation_sha256,
        reasons: [reasonCode],
      })
      current = await campaignLedger.recordObservation({
        actionId: pending.action_id,
        actionSha256: pending.action_sha256,
        branchId: pending.branch_id,
        observation,
        accountedOutputBytes: 0,
        aggregateOutputBytes: current.aggregate_output_bytes,
        pauseBranch: true,
        elapsedMs: current.elapsed_ms,
      })
    }

    const purpose = pending.purpose
      ?? proposalRecord?.purpose
      ?? plan.actions?.find(({ action_id: actionId }) => actionId === pending.action_id)?.purpose
      ?? null
    if (plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED' && purpose === 'cleanup') {
      const observed = current.observation_records.at(-1)
      current = await campaignLedger.recordCleanupOutcome({
        actionId: pending.action_id,
        actionSha256: pending.action_sha256,
        receipt: {
          schema_version: '1.0.0',
          kind: 'red-team-audit/adversarial-cleanup-outcome-receipt',
          action_sha256: pending.action_sha256,
          observation_sha256: observed.observation_sha256,
          status: 'INCONCLUSIVE',
        },
        elapsedMs: current.elapsed_ms,
      })
    }
    return current
  }
  const settleStoppedL3QualificationTails = async (snapshot, reasonCode) => {
    let current = await settleInterruptedDispatch(snapshot, reasonCode)
    let pendingQualification = current.pending_action_qualification
    if (pendingQualification !== null && pendingQualification !== undefined) {
      const actionSha256 = pendingQualification.action_sha256
        ?? pendingQualification.proposal_sha256
      if (pendingQualification.classification === null) {
        current = await campaignLedger.recordActionClassified({
          actionId: pendingQualification.action_id,
          proposalSha256: pendingQualification.proposal_sha256,
          actionSha256,
          receipt: {
            schema_version: '1.0.0',
            kind: 'red-team-audit/adversarial-action-classification-receipt',
            status: 'FAILED',
            action_id: pendingQualification.action_id,
            proposal_sha256: pendingQualification.proposal_sha256,
            action_sha256: actionSha256,
            classification_sha256: null,
            reason_code: reasonCode,
          },
          elapsedMs: current.elapsed_ms,
        })
        pendingQualification = current.pending_action_qualification
      }
      current = await campaignLedger.recordActionSkipped({
        actionId: pendingQualification.action_id,
        actionSha256: pendingQualification.action_sha256,
        branchId: pendingQualification.branch_id,
        reason: reasonCode,
        elapsedMs: current.elapsed_ms,
      })
    }
    if (current.pending_consideration !== null && current.pending_consideration !== undefined) {
      current = await campaignLedger.recordActionSkipped({
        actionId: current.pending_consideration.action_id,
        actionSha256: current.pending_consideration.action_sha256,
        branchId: current.pending_consideration.branch_id,
        reason: reasonCode,
        elapsedMs: current.elapsed_ms,
      })
    }
    if (current.pending_cleanup_outcome !== null && current.pending_cleanup_outcome !== undefined) {
      const cleanup = current.pending_cleanup_outcome
      current = await campaignLedger.recordCleanupOutcome({
        actionId: cleanup.action_id,
        actionSha256: cleanup.action_sha256,
        receipt: {
          schema_version: '1.0.0',
          kind: 'red-team-audit/adversarial-cleanup-outcome-receipt',
          action_sha256: cleanup.action_sha256,
          observation_sha256: cleanup.observation_sha256,
          status: 'INCONCLUSIVE',
        },
        elapsedMs: current.elapsed_ms,
      })
    }
    return current
  }
  if (ledgerSnapshot?.pending_stop) {
    if (plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED') {
      ledgerSnapshot = await settleStoppedL3QualificationTails(
        ledgerSnapshot,
        'CAMPAIGN_INTERRUPTED_DURING_QUALIFICATION',
      )
    }
    const stoppedState = {
      planSha256,
      authorizationReceipt: ledgerSnapshot.authorization_receipt,
      preflight: ledgerSnapshot.preflight,
      considered: ledgerSnapshot.considered_actions,
      dispatched: ledgerSnapshot.dispatched_actions,
      aggregateOutputBytes: ledgerSnapshot.aggregate_output_bytes,
      pausedBranches: new Set(ledgerSnapshot.paused_branches),
      scopeRequests: structuredClone(ledgerSnapshot.scope_requests),
      observations: structuredClone(ledgerSnapshot.observations),
      observationReceipts: observationReceiptsFromLedgerSnapshot(ledgerSnapshot),
    }
    const stoppedResult = terminalResult(stoppedState, ledgerSnapshot.pending_stop.status, {
      stop_reasons: structuredClone(ledgerSnapshot.pending_stop.stop_reasons),
    })
    if (
      ledgerSnapshot.pending_dispatch === null
      && ledgerSnapshot.pending_action_qualification === null
      && ledgerSnapshot.pending_cleanup_outcome === null
    ) {
      ledgerSnapshot = await campaignLedger.recordTerminal({
        result: durableTerminalResult(stoppedResult),
        elapsedMs: ledgerSnapshot.elapsed_ms,
      })
    }
    return withLedgerMetadata(stoppedResult, ledgerSnapshot)
  }
  const latestAcknowledgedCheckpointActions = Array.isArray(ledgerSnapshot?.qualification_records)
    ? ledgerSnapshot.qualification_records.reduce((latest, event) => (
        event.type === 'CHECKPOINT_ACKNOWLEDGED'
        && Number.isSafeInteger(event.decision?.actions_used)
          ? Math.max(latest, event.decision.actions_used)
          : latest
      ), -1)
    : -1
  const durableProposalSources = new Map(
    (ledgerSnapshot?.qualification_records ?? [])
      .filter(({ type }) => type === 'ACTION_PROPOSED')
      .map((event) => [event.action_id, event.source]),
  )
  let durableObservationStop = null
  for (const record of ledgerSnapshot?.observation_records ?? []) {
    const triggers = effectiveObservationTriggers(record.observation)
    const globalTrigger = triggers.find((trigger) => GLOBAL_ESCALATION_TRIGGERS.has(trigger))
    if (globalTrigger !== undefined) {
      durableObservationStop = { status: 'PAUSED_SAFETY', reason: globalTrigger }
      break
    }
    if (
      durableObservationStop === null
      && durableProposalSources.get(record.action_id) === 'SEALED'
      && triggers.length > 0
    ) {
      durableObservationStop = { status: 'PAUSED_ESCALATION', reason: triggers[0] }
    }
  }
  const missedMandatoryCheckpoint = plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED'
    && ledgerSnapshot?.started === true
    && ledgerSnapshot.considered_actions > 0
    && ledgerSnapshot.considered_actions
      % plan.campaign_envelope.checkpoint_policy.interval_actions === 0
    && latestAcknowledgedCheckpointActions !== ledgerSnapshot.considered_actions
  const l3RecoveredInterruption = plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED'
    ? ledgerSnapshot?.pending_dispatch
      ? { status: 'PAUSED_SAFETY', reason: 'AMBIGUOUS_IN_FLIGHT_DISPATCH' }
      : durableObservationStop !== null
        ? durableObservationStop
        : ledgerSnapshot?.pending_cleanup_outcome
          ? { status: 'PAUSED_SAFETY', reason: 'INTERRUPTED_CLEANUP_QUALIFICATION' }
          : ledgerSnapshot?.pending_action_qualification
            ? { status: 'PAUSED_SAFETY', reason: 'INTERRUPTED_ACTION_QUALIFICATION' }
            : ledgerSnapshot?.pending_exact_scope_request
              ? { status: 'PAUSED_SCOPE', reason: 'PENDING_EXACT_SCOPE_REQUEST' }
              : ledgerSnapshot?.pending_consideration
                ? { status: 'PAUSED_SAFETY', reason: 'AMBIGUOUS_POST_CONSIDERATION' }
                : missedMandatoryCheckpoint
                  ? { status: 'PAUSED_CHECKPOINT', reason: 'MISSED_MANDATORY_CHECKPOINT' }
                  : ledgerSnapshot?.started === true
                    ? { status: 'PAUSED_SAFETY', reason: 'L3_CAMPAIGN_REENTRY_UNSUPPORTED' }
                    : null
    : null
  if (l3RecoveredInterruption !== null) {
    const stopReasons = [l3RecoveredInterruption.reason]
    ledgerSnapshot = await campaignLedger.recordCampaignStop({
      receipt: {
        schema_version: '1.0.0',
        kind: 'red-team-audit/adversarial-campaign-stop-receipt',
        status: l3RecoveredInterruption.status,
        reason_codes: [...stopReasons],
        stop_reasons: structuredClone(stopReasons),
        stop_reasons_sha256: digestJson(stopReasons),
      },
      elapsedMs: ledgerSnapshot.elapsed_ms,
    })
    ledgerSnapshot = await settleStoppedL3QualificationTails(
      ledgerSnapshot,
      l3RecoveredInterruption.reason,
    )
    const recoveredState = {
      planSha256,
      authorizationReceipt: ledgerSnapshot.authorization_receipt,
      preflight: ledgerSnapshot.preflight,
      considered: ledgerSnapshot.considered_actions,
      dispatched: ledgerSnapshot.dispatched_actions,
      aggregateOutputBytes: ledgerSnapshot.aggregate_output_bytes,
      pausedBranches: new Set(ledgerSnapshot.paused_branches),
      scopeRequests: structuredClone(ledgerSnapshot.scope_requests),
      observations: structuredClone(ledgerSnapshot.observations),
      observationReceipts: observationReceiptsFromLedgerSnapshot(ledgerSnapshot),
    }
    const result = terminalResult(recoveredState, l3RecoveredInterruption.status, {
      stop_reasons: stopReasons,
    })
    if (
      ledgerSnapshot.pending_dispatch === null
      && ledgerSnapshot.pending_action_qualification === null
      && ledgerSnapshot.pending_cleanup_outcome === null
    ) {
      ledgerSnapshot = await campaignLedger.recordTerminal({
        result: durableTerminalResult(result),
        elapsedMs: ledgerSnapshot.elapsed_ms,
      })
    }
    return withLedgerMetadata(result, ledgerSnapshot)
  }
  const authorizationReceipt = verifiedOperatorAuthorizationReceipt

  let initialRuntimePreflight = {}
  let preflight = { allowed: true, reasons: [], mode: 'NOT_REQUIRED', waived_controls: [] }
  if (plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED') {
    initialRuntimePreflight = await readPreflight(runtimePreflight)
    preflight = evaluateL3PreflightWithBreakGlass({
      plan,
      authorizationReceipt,
      runtimePreflight: initialRuntimePreflight,
      override: breakGlassOverride,
      pinnedKey: breakGlassPinnedKey,
      now,
      nonceStore: breakGlassNonceStore,
    })
    if (!preflight.allowed) {
      fail('ADVERSARIAL_L3_PREFLIGHT_FAILED', 'maximum-authority runtime preflight failed', preflight.reasons)
    }
  }

  if (ledgerSnapshot?.started) {
    ledgerSnapshot = await campaignLedger.recordResume({
      resumedAt: new Date(timestamp(now, 'now')).toISOString(),
    })
  }
  const recoveredInterruption = ledgerSnapshot?.pending_dispatch
    ? { status: 'PAUSED_SAFETY', reason: 'AMBIGUOUS_IN_FLIGHT_DISPATCH' }
    : ledgerSnapshot?.pending_exact_scope_request
      ? { status: 'PAUSED_SCOPE', reason: 'PENDING_EXACT_SCOPE_REQUEST' }
      : ledgerSnapshot?.pending_consideration
        ? { status: 'PAUSED_SAFETY', reason: 'AMBIGUOUS_POST_CONSIDERATION' }
        : null
  if (recoveredInterruption !== null) {
    if (ledgerSnapshot.pending_dispatch !== null) {
      ledgerSnapshot = await settleInterruptedDispatch(
        ledgerSnapshot,
        recoveredInterruption.reason,
      )
    }
    const recoveredState = {
      planSha256,
      authorizationReceipt: ledgerSnapshot.authorization_receipt,
      preflight: ledgerSnapshot.preflight,
      considered: ledgerSnapshot.considered_actions,
      dispatched: ledgerSnapshot.dispatched_actions,
      aggregateOutputBytes: ledgerSnapshot.aggregate_output_bytes,
      pausedBranches: new Set(ledgerSnapshot.paused_branches),
      scopeRequests: structuredClone(ledgerSnapshot.scope_requests),
      observations: structuredClone(ledgerSnapshot.observations),
      observationReceipts: observationReceiptsFromLedgerSnapshot(ledgerSnapshot),
    }
    const result = terminalResult(recoveredState, recoveredInterruption.status, {
      stop_reasons: [recoveredInterruption.reason],
    })
    if (plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED') {
      ledgerSnapshot = await campaignLedger.recordCampaignStop({
        receipt: {
          schema_version: '1.0.0',
          kind: 'red-team-audit/adversarial-campaign-stop-receipt',
          status: result.status,
          reason_codes: [...result.stop_reasons],
          stop_reasons: structuredClone(result.stop_reasons),
          stop_reasons_sha256: digestJson(result.stop_reasons),
        },
        elapsedMs: ledgerSnapshot.elapsed_ms,
      })
    }
    if (ledgerSnapshot.pending_dispatch === null) {
      ledgerSnapshot = await campaignLedger.recordTerminal({
        result: durableTerminalResult(result),
        elapsedMs: ledgerSnapshot.elapsed_ms,
      })
    }
    return withLedgerMetadata(result, ledgerSnapshot)
  }

  const runLimits = effectiveLimits(plan, preflight)
  timestamp(now, 'now')
  let lastWallTime = null
  let lastMonotonicTime = null
  let clockFailureReason = null
  const sampleRuntimeTime = () => {
    if (clockFailureReason !== null) {
      return Object.freeze({ valid: false, reason: clockFailureReason })
    }
    let wallTime
    let monotonicTime
    try {
      wallTime = wallClock()
      monotonicTime = monotonicClock()
    } catch {
      clockFailureReason = 'RUNTIME_CLOCK_INVALID'
      return Object.freeze({ valid: false, reason: clockFailureReason })
    }
    if (!Number.isFinite(wallTime) || !Number.isFinite(monotonicTime)) {
      clockFailureReason = 'RUNTIME_CLOCK_INVALID'
      return Object.freeze({ valid: false, reason: clockFailureReason })
    }
    if (lastWallTime !== null && wallTime < lastWallTime) {
      clockFailureReason = 'RUNTIME_WALL_CLOCK_REGRESSION'
      return Object.freeze({ valid: false, reason: clockFailureReason })
    }
    if (lastMonotonicTime !== null && monotonicTime < lastMonotonicTime) {
      clockFailureReason = 'RUNTIME_MONOTONIC_CLOCK_REGRESSION'
      return Object.freeze({ valid: false, reason: clockFailureReason })
    }
    lastWallTime = wallTime
    lastMonotonicTime = monotonicTime
    return Object.freeze({ valid: true, wallTime, monotonicTime })
  }
  const startedTime = sampleRuntimeTime()
  if (!startedTime.valid) {
    fail(
      'ADVERSARIAL_RUNTIME_CLOCK_INVALID',
      'runtime wall and monotonic clocks must return finite nondecreasing millisecond values',
      [startedTime.reason],
    )
  }
  const startedAt = startedTime.monotonicTime
  if (campaignLedger !== null && !ledgerSnapshot.started) {
    ledgerSnapshot = await campaignLedger.start({
      authorizationReceipt,
      preflight,
      qualificationReceipt: ledgerQualificationReceipt,
      breakGlassOverrideSha256: breakGlassOverride === null || breakGlassOverride === undefined
        ? null
        : digestJson(breakGlassOverride),
      startedAt: new Date(timestamp(now, 'now')).toISOString(),
    })
  }
  const state = {
    planSha256,
    authorizationReceipt,
    preflight,
    considered: ledgerSnapshot?.considered_actions ?? 0,
    dispatched: ledgerSnapshot?.dispatched_actions ?? 0,
    aggregateOutputBytes: ledgerSnapshot?.aggregate_output_bytes ?? 0,
    pausedBranches: new Set(ledgerSnapshot?.paused_branches ?? []),
    scopeRequests: structuredClone(ledgerSnapshot?.scope_requests ?? []),
    observations: structuredClone(ledgerSnapshot?.observations ?? []),
    observationReceipts: observationReceiptsFromLedgerSnapshot(ledgerSnapshot),
    actionIds: new Set(ledgerSnapshot?.action_ids ?? []),
    baseElapsedMs: ledgerSnapshot?.elapsed_ms ?? 0,
  }
  const exactQueue = Array.isArray(plan.actions) ? plan.actions.map((action) => structuredClone(action)) : []
  let exactIndex = ledgerSnapshot?.exact_index ?? 0
  let supervisedPhase = exactIndex > 0
    ? exactQueue[exactIndex - 1]?.purpose ?? null
    : null
  const campaignMaxActions = plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED'
    ? Math.min(runLimits.max_actions, plan.campaign_envelope.max_actions)
    : runLimits.max_actions

  const elapsedAt = (monotonicTime) => state.baseElapsedMs + (monotonicTime - startedAt)
  const elapsedAtSample = (runtimeTime) => runtimeTime?.valid
    ? elapsedAt(runtimeTime.monotonicTime)
    : state.baseElapsedMs + Math.max(0, (lastMonotonicTime ?? startedAt) - startedAt)
  const finish = async (status, extras = {}, runtimeTime = sampleRuntimeTime()) => {
    const effectiveStatus = runtimeTime?.valid === false ? 'PAUSED_SAFETY' : status
    const effectiveExtras = runtimeTime?.valid === false
      ? {
          ...extras,
          stop_reasons: [...new Set([
            runtimeTime.reason,
            ...(Array.isArray(extras.stop_reasons) ? extras.stop_reasons : []),
          ])],
        }
      : extras
    const result = terminalResult(state, effectiveStatus, effectiveExtras)
    if (campaignLedger === null) return result
    if (
      plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED'
      && Array.isArray(result.stop_reasons)
      && result.stop_reasons.length > 0
    ) {
      await campaignLedger.recordCampaignStop({
        receipt: {
          schema_version: '1.0.0',
          kind: 'red-team-audit/adversarial-campaign-stop-receipt',
          status: result.status,
          reason_codes: boundedReasonCodes(result.stop_reasons, 'CAMPAIGN_STOPPED'),
          stop_reasons: structuredClone(result.stop_reasons),
          stop_reasons_sha256: digestJson(result.stop_reasons),
        },
        elapsedMs: elapsedAtSample(runtimeTime),
      })
    }
    if (plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED') {
      const pendingConsideration = campaignLedger.snapshot().pending_consideration
      if (pendingConsideration !== null && pendingConsideration !== undefined) {
        await campaignLedger.recordActionSkipped({
          actionId: pendingConsideration.action_id,
          actionSha256: pendingConsideration.action_sha256,
          branchId: pendingConsideration.branch_id,
          reason: boundedReasonCodes(
            result.stop_reasons,
            'CAMPAIGN_STOPPED_BEFORE_ACTION_DISPATCH',
          )[0] ?? 'CAMPAIGN_STOPPED_BEFORE_ACTION_DISPATCH',
          elapsedMs: elapsedAtSample(runtimeTime),
        })
      }
    }
    const snapshot = await campaignLedger.recordTerminal({
      result: durableTerminalResult(result),
      elapsedMs: elapsedAtSample(runtimeTime),
    })
    return withLedgerMetadata(result, snapshot)
  }
  const pauseWithoutTerminalizing = async (status, extras = {}) => {
    const result = terminalResult(state, status, extras)
    if (campaignLedger === null) return result
    if (
      plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED'
      && Array.isArray(result.stop_reasons)
      && result.stop_reasons.length > 0
    ) {
      await campaignLedger.recordCampaignStop({
        receipt: {
          schema_version: '1.0.0',
          kind: 'red-team-audit/adversarial-campaign-stop-receipt',
          status: result.status,
          reason_codes: boundedReasonCodes(result.stop_reasons, 'CAMPAIGN_PAUSED'),
          stop_reasons: structuredClone(result.stop_reasons),
          stop_reasons_sha256: digestJson(result.stop_reasons),
        },
        elapsedMs: elapsedAtSample(sampleRuntimeTime()),
      })
    }
    return withLedgerMetadata(result, campaignLedger.snapshot())
  }

  const resumeCount = ledgerSnapshot?.resume_count ?? 0
  if (
    plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED'
    && resumeCount > plan.campaign_envelope.checkpoint_policy.max_resume_count
  ) {
    return finish('LIMIT_EXHAUSTED', {
      stop_reasons: ['CAMPAIGN_RESUME_BUDGET_EXHAUSTED'],
    }, startedTime)
  }

  if (campaignSignal?.aborted === true) {
    return finish('ABORTED', { stop_reasons: ['CAMPAIGN_ABORTED'] }, startedTime)
  }
  if (ledgerSnapshot?.pending_checkpoint !== null && ledgerSnapshot?.pending_checkpoint !== undefined) {
    const pendingCheckpoint = ledgerSnapshot.pending_checkpoint
    let checkpointDecision
    try {
      checkpointDecision = await checkpoint(Object.freeze(structuredClone(pendingCheckpoint)))
    } catch {
      return pauseWithoutTerminalizing('PAUSED_CHECKPOINT', {
        stop_reasons: ['CHECKPOINT_SINK_FAILED'],
        pending_checkpoint: pendingCheckpoint,
      })
    }
    if (
      checkpointDecision?.decision !== 'CONTINUE'
      || checkpointDecision.plan_sha256 !== state.planSha256
      || checkpointDecision.authorization_id !== (authorizationReceipt?.authorization_id ?? null)
      || checkpointDecision.scope_revision_sha256 !== plan.scope_revision_sha256
      || checkpointDecision.actions_used !== state.considered
      || (
        pendingCheckpoint.kind === 'red-team-audit/adversarial-supervised-phase-checkpoint'
        && (
          checkpointDecision.next_phase !== pendingCheckpoint.next_phase
          || checkpointDecision.next_action_sha256 !== pendingCheckpoint.next_action_sha256
        )
      )
    ) {
      return pauseWithoutTerminalizing('PAUSED_CHECKPOINT', {
        stop_reasons: ['CHECKPOINT_NOT_ACKNOWLEDGED'],
        pending_checkpoint: pendingCheckpoint,
      })
    }
    await campaignLedger.recordCheckpointAcknowledged({
      checkpoint: pendingCheckpoint,
      decision: checkpointDecision,
      elapsedMs: elapsedAtSample(sampleRuntimeTime()),
    })
    if (pendingCheckpoint.kind === 'red-team-audit/adversarial-supervised-phase-checkpoint') {
      supervisedPhase = pendingCheckpoint.next_phase
    }
  }

  while (state.considered < campaignMaxActions) {
    const currentTime = sampleRuntimeTime()
    if (!currentTime.valid) {
      return finish('PAUSED_SAFETY', { stop_reasons: [currentTime.reason] }, currentTime)
    }
    if (elapsedAt(currentTime.monotonicTime) >= runLimits.max_wall_time_ms) {
      return finish('LIMIT_EXHAUSTED', { stop_reasons: ['MAX_WALL_TIME_EXHAUSTED'] }, currentTime)
    }
    if (campaignSignal?.aborted === true) {
      return finish('ABORTED', { stop_reasons: ['CAMPAIGN_ABORTED'] }, currentTime)
    }
    if (state.aggregateOutputBytes >= runLimits.max_aggregate_output_bytes) {
      return finish('LIMIT_EXHAUSTED', {
        stop_reasons: ['MAX_AGGREGATE_OUTPUT_EXHAUSTED'],
      }, currentTime)
    }
    let currentAuthorization = null
    if (requiresAuthorization) {
      if (currentTime.wallTime >= Date.parse(authorizationReceipt.expires_at)) {
        return finish(
          'PAUSED_AUTHORIZATION',
          { stop_reasons: ['AUTHORIZATION_EXPIRED'] },
          currentTime,
        )
      }
      const authorizationControl = await readCurrentAuthorizationControl({
        authorizationReceipt,
        isAuthorizationRevoked: authorizationRevocationCheck,
        isOperatorStopRequested: operatorStopCheck,
      })
      if (!authorizationControl.allowed) {
        return finish(
          authorizationControl.status,
          { stop_reasons: [authorizationControl.reason] },
          currentTime,
        )
      }
      currentAuthorization = authorizationControl.currentAuthorization
    }

    let currentRuntimePreflight = initialRuntimePreflight

    let action
    let adaptive = false
    let exact = false
    if (exactIndex < exactQueue.length) {
      action = exactQueue[exactIndex]
      exact = true
    } else if (plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED' && typeof proposeNextAction === 'function') {
      try {
        action = await proposeNextAction(Object.freeze({
          considered_actions: state.considered,
          dispatched_actions: state.dispatched,
          remaining_actions: campaignMaxActions - state.considered,
          paused_branches: [...state.pausedBranches],
          observation_receipts: structuredClone(state.observationReceipts),
          scope_requests: structuredClone(state.scopeRequests),
        }))
      } catch (error) {
        await finish('PAUSED_SAFETY', { stop_reasons: ['ACTION_PROPOSER_FAILED'] })
        throw error
      }
      adaptive = true
    } else {
      action = undefined
    }
    if (action === null || action === undefined) break

    try {
      action = snapshotJsonDocument(
        action,
        'controller-owned action snapshot',
        Math.min(plan.limits.max_input_bytes * 2, 32 * 1024 * 1024),
      )
      if (adaptive) assertTacticalAction(action, plan)
    } catch (error) {
      if (plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED') {
        await finish('PAUSED_SAFETY', { stop_reasons: ['TACTICAL_ACTION_INVALID'] })
      }
      throw error
    }
    const proposalSha256 = digestJson(action)
    const proposalBranchId = exact
      ? plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED'
        ? 'branch:sealed-actions'
        : 'branch:exact-plan'
      : action.branch_id
    let boundaryQualificationReceipt = null
    if (
      plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED'
      && state.actionIds.has(action.action_id)
    ) {
      await finish('PAUSED_SAFETY', { stop_reasons: ['ACTION_ID_REPLAYED'] })
      fail('ADVERSARIAL_ACTION_REPLAY', `action id ${action.action_id} was proposed more than once`)
    }
    if (plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED') {
      await campaignLedger.recordActionProposed({
        actionId: action.action_id,
        proposalSha256,
        source: exact ? 'SEALED' : 'ADAPTIVE',
        purpose: action.purpose,
        branchId: proposalBranchId,
        nextExactIndex: exactIndex + (exact ? 1 : 0),
        elapsedMs: elapsedAtSample(sampleRuntimeTime()),
      })
    }

    if (
      exact
      && isLive
      && plan.autonomy_profile === 'L2_SUPERVISED'
      && supervisedPhase !== action.purpose
    ) {
      const checkpointRecord = Object.freeze({
        schema_version: '1.0.0',
        kind: 'red-team-audit/adversarial-supervised-phase-checkpoint',
        plan_sha256: state.planSha256,
        authorization_id: authorizationReceipt?.authorization_id ?? null,
        scope_revision_sha256: plan.scope_revision_sha256,
        actions_used: state.considered,
        next_phase: action.purpose,
        next_action_sha256: digestJson(action),
      })
      if (campaignLedger !== null) {
        await campaignLedger.recordCheckpointQueued({
          checkpoint: checkpointRecord,
          elapsedMs: elapsedAtSample(sampleRuntimeTime()),
        })
      }
      let checkpointDecision
      try {
        checkpointDecision = await checkpoint(checkpointRecord)
      } catch {
        return pauseWithoutTerminalizing('PAUSED_CHECKPOINT', {
          stop_reasons: ['CHECKPOINT_SINK_FAILED'],
          pending_checkpoint: checkpointRecord,
        })
      }
      if (
        checkpointDecision?.decision !== 'CONTINUE'
        || checkpointDecision.plan_sha256 !== state.planSha256
        || checkpointDecision.authorization_id !== (authorizationReceipt?.authorization_id ?? null)
        || checkpointDecision.scope_revision_sha256 !== plan.scope_revision_sha256
        || checkpointDecision.actions_used !== state.considered
        || checkpointDecision.next_phase !== checkpointRecord.next_phase
        || checkpointDecision.next_action_sha256 !== checkpointRecord.next_action_sha256
      ) {
        return pauseWithoutTerminalizing('PAUSED_CHECKPOINT', {
          stop_reasons: ['CHECKPOINT_NOT_ACKNOWLEDGED'],
          pending_checkpoint: checkpointRecord,
        })
      }
      if (campaignLedger !== null) {
        await campaignLedger.recordCheckpointAcknowledged({
          checkpoint: checkpointRecord,
          decision: checkpointDecision,
          elapsedMs: elapsedAtSample(sampleRuntimeTime()),
        })
      }
      supervisedPhase = action.purpose
    }
    if (exact) exactIndex += 1

    let branchId = proposalBranchId
    let boundary = { allowed: true, checkpoint_due: false }
    if (adaptive) {
      if (state.actionIds.has(action.action_id)) {
        fail('ADVERSARIAL_ACTION_REPLAY', `action id ${action.action_id} was proposed more than once`)
      }
      state.actionIds.add(action.action_id)
      branchId = action.branch_id
      if (state.pausedBranches.has(branchId)) {
        const skippedActionSha256 = digestAdversarialTacticalAction(action)
        state.considered += 1
        if (campaignLedger !== null) {
          await campaignLedger.recordActionClassified({
            actionId: action.action_id,
            proposalSha256,
            actionSha256: skippedActionSha256,
            receipt: {
              schema_version: '1.0.0',
              kind: 'red-team-audit/adversarial-action-classification-receipt',
              status: 'SKIPPED',
              action_id: action.action_id,
              proposal_sha256: proposalSha256,
              action_sha256: skippedActionSha256,
              classification_sha256: null,
              reason_code: 'BRANCH_ALREADY_PAUSED',
            },
            elapsedMs: elapsedAtSample(sampleRuntimeTime()),
          })
          await campaignLedger.recordActionConsidered({
            actionId: action.action_id,
            actionSha256: skippedActionSha256,
            branchId,
            exactIndex,
            consideredActions: state.considered,
            elapsedMs: elapsedAtSample(sampleRuntimeTime()),
          })
          await campaignLedger.recordActionSkipped({
            actionId: action.action_id,
            actionSha256: skippedActionSha256,
            branchId,
            reason: 'BRANCH_ALREADY_PAUSED',
            elapsedMs: elapsedAtSample(sampleRuntimeTime()),
          })
        }
        continue
      }
    } else {
      if (state.actionIds.has(action.action_id)) {
        fail('ADVERSARIAL_ACTION_REPLAY', `action id ${action.action_id} was proposed more than once`)
      }
      state.actionIds.add(action.action_id)
      if (jsonBytes(action.parameters, 'exact action parameters') > runLimits.max_input_bytes) {
        fail('ADVERSARIAL_ACTION_INPUT_LIMIT', 'exact action parameters exceed max_input_bytes')
      }
    }

    let classification
    try {
      classification = requiresClassification
        ? assertControllerClassification(
          await classifyAction(
            structuredClone(action),
            Object.freeze({
              plan_sha256: state.planSha256,
              scope_revision_sha256: plan.scope_revision_sha256,
              authority_root_target: structuredClone(plan.target),
              risk_class: plan.risk_class,
            }),
          ),
          plan,
          { enforceL3ProhibitedEffects: plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED' },
        )
        : deepFreeze({
          candidate_context: {},
          resolved_target: structuredClone(plan.target),
          anticipated_effects: [],
        })
    } catch (error) {
      if (plan.autonomy_profile !== 'L3_MAXIMUM_AUTHORIZED') throw error
      const failedActionSha256 = adaptive
        ? digestAdversarialTacticalAction(action)
        : proposalSha256
      const reasonCode = typeof error?.code === 'string' && error.code.length > 0
        ? error.code
        : 'ACTION_CLASSIFICATION_FAILED'
      state.considered += 1
      await campaignLedger.recordActionClassified({
        actionId: action.action_id,
        proposalSha256,
        actionSha256: failedActionSha256,
        receipt: {
          schema_version: '1.0.0',
          kind: 'red-team-audit/adversarial-action-classification-receipt',
          status: 'FAILED',
          action_id: action.action_id,
          proposal_sha256: proposalSha256,
          action_sha256: failedActionSha256,
          classification_sha256: null,
          reason_code: reasonCode,
        },
        elapsedMs: elapsedAtSample(sampleRuntimeTime()),
      })
      await campaignLedger.recordActionConsidered({
        actionId: action.action_id,
        actionSha256: failedActionSha256,
        branchId,
        exactIndex,
        consideredActions: state.considered,
        elapsedMs: elapsedAtSample(sampleRuntimeTime()),
      })
      await finish('PAUSED_SAFETY', { stop_reasons: [reasonCode] })
      throw error
    }
    const boundaryAction = plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED'
      ? governedL3Action(action, classification, adaptive)
      : action
    const actionSha256 = plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED'
      ? digestAdversarialTacticalAction(boundaryAction)
      : digestJson(action)
    const candidateFactsSha256 = digestAdversarialCandidateFacts(
      classification.candidate_context,
    )
    const classificationSha256 = digestJson(classification)

    state.considered += 1
    if (campaignLedger !== null) {
      if (plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED') {
        await campaignLedger.recordActionClassified({
          actionId: boundaryAction.action_id,
          proposalSha256,
          actionSha256,
          receipt: {
            schema_version: '1.0.0',
            kind: 'red-team-audit/adversarial-action-classification-receipt',
            status: 'CLASSIFIED',
            action_id: boundaryAction.action_id,
            proposal_sha256: proposalSha256,
            action_sha256: actionSha256,
            classification_sha256: classificationSha256,
            candidate_facts_sha256: candidateFactsSha256,
            resolved_target_sha256: digestJson(classification.resolved_target),
            effect_classification_sha256: digestJson({
              complete: true,
              effects: classification.anticipated_effects,
            }),
            risk_class: plan.risk_class,
            strategy_family: classification.strategy_family,
            reason_code: null,
          },
          elapsedMs: elapsedAtSample(sampleRuntimeTime()),
        })
      }
      await campaignLedger.recordActionConsidered({
        actionId: boundaryAction.action_id,
        actionSha256,
        branchId,
        exactIndex,
        consideredActions: state.considered,
        elapsedMs: elapsedAtSample(sampleRuntimeTime()),
      })
    }
    let controllerAuthorization = null
    let scopeContext = null
    let initialScopeQualificationReceipt = null
    const scopeDecisionExpectation = requiresScopeGate
      ? Object.freeze({
          planSha256: state.planSha256,
          authorizationId: authorizationReceipt.authorization_id,
          scopeRevisionSha256: plan.scope_revision_sha256,
          actionSha256,
          candidateFactsSha256,
          target: classification.resolved_target,
          riskClass: plan.risk_class,
          effects: classification.anticipated_effects,
        })
      : null
    if (requiresScopeGate) {
      scopeContext = Object.freeze({
        plan: structuredClone(plan),
        authorization_receipt: structuredClone(authorizationReceipt),
        action_sha256: actionSha256,
        candidate_facts_sha256: candidateFactsSha256,
        resolved_target: structuredClone(classification.resolved_target),
        risk_class: plan.risk_class,
        effect_classification: {
          complete: true,
          effects: [...classification.anticipated_effects],
        },
      })
      let rawScopeDecision
      let scopeDecision
      let scopeAuthorizationError = null
      try {
        rawScopeDecision = await scopeAuthorize(structuredClone(boundaryAction), scopeContext)
        scopeDecision = normalizeScopeDecision(
          rawScopeDecision,
          scopeDecisionExpectation,
        )
      } catch (error) {
        if (plan.autonomy_profile !== 'L3_MAXIMUM_AUTHORIZED') throw error
        scopeAuthorizationError = error
        scopeDecision = {
          allowed: false,
          decision: 'ERROR',
          reason: 'SCOPE_AUTHORIZATION_FAILED',
        }
      }
      if (plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED') {
        initialScopeQualificationReceipt = scopeQualificationReceipt({
          stage: 'INITIAL',
          actionSha256,
          classificationSha256,
          candidateFactsSha256,
          resolvedTarget: classification.resolved_target,
          effects: classification.anticipated_effects,
          scopeRevisionSha256: plan.scope_revision_sha256,
          decision: scopeDecision,
        })
        await campaignLedger.recordScopeDecision({
          actionId: boundaryAction.action_id,
          actionSha256,
          branchId,
          stage: 'INITIAL',
          receipt: initialScopeQualificationReceipt,
          elapsedMs: elapsedAtSample(sampleRuntimeTime()),
        })
      }
      if (scopeAuthorizationError !== null) {
        await finish('PAUSED_SCOPE', { stop_reasons: ['SCOPE_AUTHORIZATION_FAILED'] })
        throw scopeAuthorizationError
      }
      if (
        plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED'
        && scopeDecision.decision === 'ERROR'
      ) {
        return finish('PAUSED_SCOPE', { stop_reasons: ['SCOPE_DECISION_INVALID'] })
      }
      if (!scopeDecision.allowed) {
        state.pausedBranches.add(branchId)
        let scopeRequest
        try {
          scopeRequest = emitScopeRequest(
            scopeRequestBuilder,
            boundaryAction,
            scopeDecision,
            {
              plan: structuredClone(plan),
              plan_sha256: state.planSha256,
              scope_revision_sha256: plan.scope_revision_sha256,
              action_id: boundaryAction.action_id,
              action_sha256: actionSha256,
              candidate_facts_sha256: candidateFactsSha256,
              classification_sha256: classificationSha256,
              resolved_target: structuredClone(classification.resolved_target),
              risk_class: plan.risk_class,
              strategy_family: boundaryAction.strategy_family ?? classification.strategy_family ?? null,
              anticipated_effects: [...classification.anticipated_effects],
            },
          )
        } catch (error) {
          if (plan.autonomy_profile !== 'L3_MAXIMUM_AUTHORIZED') throw error
          const reasonCode = typeof error?.code === 'string' && error.code.length > 0
            ? error.code
            : 'SCOPE_REQUEST_BUILD_FAILED'
          await finish('PAUSED_SCOPE', { stop_reasons: [reasonCode] })
          throw error
        }
        if (campaignLedger !== null) {
          await campaignLedger.recordScopeRequest({
            actionId: boundaryAction.action_id,
            actionSha256,
            branchId,
            request: scopeRequest,
            continueCampaign: adaptive,
            elapsedMs: elapsedAtSample(sampleRuntimeTime()),
          })
        }
        state.scopeRequests.push(scopeRequest)
        if (typeof scopeRequestSink === 'function') {
          try {
            await scopeRequestSink(scopeRequest)
          } catch (error) {
            if (plan.autonomy_profile !== 'L3_MAXIMUM_AUTHORIZED') throw error
            await finish('PAUSED_SCOPE', { stop_reasons: ['SCOPE_REQUEST_SINK_FAILED'] })
            throw error
          }
        }
        if (adaptive) continue
        return finish('PAUSED_SCOPE', { stop_reasons: [scopeDecision.reason] })
      }
      controllerAuthorization = scopeDecision.controllerAuthorization
    }

    let boundaryPreflightQualificationReceipt = null
    const qualifyL3Preflight = async (stage, status, runtimeState, reasons = []) => {
      if (plan.autonomy_profile !== 'L3_MAXIMUM_AUTHORIZED') return null
      const receipt = preflightQualificationReceipt({
        stage,
        actionSha256,
        status,
        runtimePreflight: runtimeState,
        currentAuthorization,
        reasons,
      })
      await campaignLedger.recordActionPreflight({
        actionId: boundaryAction.action_id,
        actionSha256,
        branchId,
        stage,
        receipt,
        elapsedMs: elapsedAtSample(sampleRuntimeTime()),
      })
      return receipt
    }

    // Proposal, classification, scope, and ledger callbacks are untrusted
    // latency boundaries. Authority is checked here, again before the durable
    // permit, and finally after that permit immediately before target dispatch.
    if (requiresAuthorization) {
      const authorizationControl = await readCurrentAuthorizationControl({
        authorizationReceipt,
        isAuthorizationRevoked: authorizationRevocationCheck,
        isOperatorStopRequested: operatorStopCheck,
      })
      if (!authorizationControl.allowed) {
        await qualifyL3Preflight(
          'PRE_BOUNDARY',
          authorizationControl.status === 'ABORTED' ? 'DENY' : 'ERROR',
          currentRuntimePreflight,
          [authorizationControl.reason],
        )
        return finish(authorizationControl.status, {
          stop_reasons: [authorizationControl.reason],
        })
      }
      currentAuthorization = authorizationControl.currentAuthorization
    }
    if (plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED') {
      try {
        currentRuntimePreflight = await readPreflight(runtimePreflight)
      } catch {
        await qualifyL3Preflight(
          'PRE_BOUNDARY',
          'ERROR',
          null,
          ['CONTROL_PLANE_LOSS'],
        )
        return finish('PAUSED_SAFETY', { stop_reasons: ['CONTROL_PLANE_LOSS'] })
      }
    }
    const preDispatchTime = sampleRuntimeTime()
    if (!preDispatchTime.valid) {
      await qualifyL3Preflight('PRE_BOUNDARY', 'DENY', currentRuntimePreflight, [preDispatchTime.reason])
      return finish('PAUSED_SAFETY', { stop_reasons: [preDispatchTime.reason] }, preDispatchTime)
    }
    if (elapsedAt(preDispatchTime.monotonicTime) >= runLimits.max_wall_time_ms) {
      await qualifyL3Preflight(
        'PRE_BOUNDARY',
        'DENY',
        currentRuntimePreflight,
        ['MAX_WALL_TIME_EXHAUSTED'],
      )
      return finish('LIMIT_EXHAUSTED', { stop_reasons: ['MAX_WALL_TIME_EXHAUSTED'] }, preDispatchTime)
    }
    if (campaignSignal?.aborted === true) {
      await qualifyL3Preflight('PRE_BOUNDARY', 'DENY', currentRuntimePreflight, ['CAMPAIGN_ABORTED'])
      return finish('ABORTED', { stop_reasons: ['CAMPAIGN_ABORTED'] }, preDispatchTime)
    }
    if (
      requiresAuthorization
      && preDispatchTime.wallTime >= Date.parse(authorizationReceipt.expires_at)
    ) {
      await qualifyL3Preflight(
        'PRE_BOUNDARY',
        'DENY',
        currentRuntimePreflight,
        ['AUTHORIZATION_EXPIRED'],
      )
      return finish(
        'PAUSED_AUTHORIZATION',
        { stop_reasons: ['AUTHORIZATION_EXPIRED'] },
        preDispatchTime,
      )
    }
    if (requiresAuthorization) {
      currentAuthorization = Object.freeze({
        status: 'CURRENT',
        authorization_id: authorizationReceipt.authorization_id,
        plan_sha256: state.planSha256,
        revoked: false,
        scope_revision_sha256: plan.scope_revision_sha256,
        stop_requested: false,
      })
    }
    if (plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED') {
      const failures = runtimePreflightFailures(plan, currentRuntimePreflight, preflight)
      if (
        preflight.mode === 'BREAK_GLASS'
        && preDispatchTime.wallTime >= Date.parse(breakGlassOverride.expires_at)
      ) {
        failures.push('BREAK_GLASS_EXPIRED')
      }
      if (failures.length > 0) {
        boundaryPreflightQualificationReceipt = await qualifyL3Preflight(
          'PRE_BOUNDARY',
          'DENY',
          currentRuntimePreflight,
          failures,
        )
        return finish('PAUSED_SAFETY', { stop_reasons: failures }, preDispatchTime)
      }
      boundaryPreflightQualificationReceipt = await qualifyL3Preflight(
        'PRE_BOUNDARY',
        'PASS',
        currentRuntimePreflight,
      )
    }

    if (plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED') {
      boundary = evaluateL3CampaignBoundary({
        plan,
        runtimePreflight: effectiveRuntimePreflight(
          currentRuntimePreflight,
          preflight.waived_controls,
        ),
        action: boundaryAction,
        controllerCandidateContext: classification.candidate_context,
        authorizationReceipt,
        currentAuthorization,
        controllerAuthorization,
        now: new Date(preDispatchTime.wallTime),
        actionsUsed: state.considered - 1,
        resumeCount,
      })
      boundaryQualificationReceipt = deepFreeze({
        schema_version: '1.0.0',
        kind: 'red-team-audit/adversarial-campaign-boundary-receipt',
        status: boundary.allowed ? 'ALLOW' : 'DENY',
        action_sha256: actionSha256,
        boundary_sha256: digestJson(boundary),
        reason_codes: boundary.allowed
          ? []
          : boundedReasonCodes(boundary.reasons, 'CAMPAIGN_BOUNDARY_REFUSED'),
      })
      await campaignLedger.recordBoundaryDecision({
        actionId: boundaryAction.action_id,
        actionSha256,
        branchId,
        receipt: boundaryQualificationReceipt,
        elapsedMs: elapsedAtSample(sampleRuntimeTime()),
      })
      if (!boundary.allowed) {
        state.pausedBranches.add(branchId)
        if (boundary.disposition === 'QUEUE_SCOPE_EXPANSION_REQUEST') {
          let scopeRequest
          try {
            scopeRequest = emitScopeRequest(
              scopeRequestBuilder,
              boundaryAction,
              boundary,
              {
                plan: structuredClone(plan),
                plan_sha256: state.planSha256,
                scope_revision_sha256: plan.scope_revision_sha256,
                action_id: boundaryAction.action_id,
                action_sha256: actionSha256,
                candidate_facts_sha256: candidateFactsSha256,
                classification_sha256: classificationSha256,
                resolved_target: structuredClone(classification.resolved_target),
                risk_class: plan.risk_class,
                strategy_family: boundaryAction.strategy_family ?? classification.strategy_family ?? null,
                anticipated_effects: [...classification.anticipated_effects],
              },
            )
          } catch (error) {
            const reasonCode = typeof error?.code === 'string' && error.code.length > 0
              ? error.code
              : 'SCOPE_REQUEST_BUILD_FAILED'
            await finish('PAUSED_SCOPE', { stop_reasons: [reasonCode] })
            throw error
          }
          if (campaignLedger !== null) {
            await campaignLedger.recordScopeRequest({
              actionId: boundaryAction.action_id,
              actionSha256,
              branchId,
              request: scopeRequest,
              continueCampaign: adaptive,
              elapsedMs: elapsedAtSample(sampleRuntimeTime()),
            })
          }
          state.scopeRequests.push(scopeRequest)
          if (typeof scopeRequestSink === 'function') {
            try {
              await scopeRequestSink(scopeRequest)
            } catch (error) {
              await finish('PAUSED_SCOPE', { stop_reasons: ['SCOPE_REQUEST_SINK_FAILED'] })
              throw error
            }
          }
          if (adaptive) continue
          return finish('PAUSED_SCOPE', {
            stop_reasons: boundary.reasons ?? ['CAMPAIGN_BOUNDARY_REFUSED'],
          })
        }
        return finish('PAUSED_SAFETY', {
          stop_reasons: boundary.reasons ?? ['CAMPAIGN_BOUNDARY_REFUSED'],
        })
      }
    }

    const remainingAggregateOutputBytes =
      runLimits.max_aggregate_output_bytes - state.aggregateOutputBytes
    const effectiveOutputBytes = Math.min(
      runLimits.max_output_bytes,
      remainingAggregateOutputBytes,
      campaignLedger === null
        ? Number.MAX_SAFE_INTEGER
        : CAMPAIGN_LEDGER_OBSERVATION_MAX_BYTES,
    )
    state.dispatched += 1
    const cancelUndispatched = async (
      status,
      reasonCodes,
      cancellationTime = sampleRuntimeTime(),
    ) => {
      if (campaignLedger !== null) {
        await campaignLedger.recordDispatchCancelled({
          actionId: boundaryAction.action_id,
          actionSha256,
          reasonCodes,
          elapsedMs: elapsedAtSample(cancellationTime),
        })
      }
      state.dispatched -= 1
      return finish(
        status,
        { stop_reasons: reasonCodes },
        cancellationTime,
      )
    }
    if (campaignLedger !== null) {
      await campaignLedger.recordPreDispatch({
        actionId: boundaryAction.action_id,
        actionSha256,
        branchId,
        dispatchedActions: state.dispatched,
        elapsedMs: elapsedAt(preDispatchTime.monotonicTime),
      })
    }

    let postPermitStatus = null
    let postPermitReasons = []
    let preSendScopeQualificationReceipt = null
    if (requiresScopeGate) {
      let rawScopeDecision
      let currentScopeDecision
      try {
        rawScopeDecision = await scopeAuthorize(structuredClone(boundaryAction), scopeContext)
        currentScopeDecision = normalizeScopeDecision(
          rawScopeDecision,
          scopeDecisionExpectation,
        )
        if (!currentScopeDecision.allowed) {
          postPermitStatus = 'PAUSED_SCOPE'
          postPermitReasons = [currentScopeDecision.decision === 'ERROR'
            ? 'SCOPE_DECISION_INVALID'
            : currentScopeDecision.reason]
        }
      } catch {
        currentScopeDecision = {
          allowed: false,
          decision: 'ERROR',
          reason: 'SCOPE_REAUTHORIZATION_FAILED',
        }
        postPermitStatus = 'PAUSED_SCOPE'
        postPermitReasons = ['SCOPE_REAUTHORIZATION_FAILED']
      }
      if (plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED') {
        preSendScopeQualificationReceipt = scopeQualificationReceipt({
          stage: 'PRE_SEND_RECHECK',
          actionSha256,
          classificationSha256,
          candidateFactsSha256,
          resolvedTarget: classification.resolved_target,
          effects: classification.anticipated_effects,
          scopeRevisionSha256: plan.scope_revision_sha256,
          decision: currentScopeDecision,
        })
        await campaignLedger.recordScopeDecision({
          actionId: boundaryAction.action_id,
          actionSha256,
          branchId,
          stage: 'PRE_SEND_RECHECK',
          receipt: preSendScopeQualificationReceipt,
          elapsedMs: elapsedAtSample(sampleRuntimeTime()),
        })
      }
    }
    if (postPermitStatus === null && requiresAuthorization) {
      const authorizationControl = await readCurrentAuthorizationControl({
        authorizationReceipt,
        isAuthorizationRevoked: authorizationRevocationCheck,
        isOperatorStopRequested: operatorStopCheck,
      })
      if (!authorizationControl.allowed) {
        postPermitStatus = authorizationControl.status
        postPermitReasons.push(authorizationControl.reason)
      } else {
        currentAuthorization = authorizationControl.currentAuthorization
      }
    }
    let postPermitPreflight = currentRuntimePreflight
    if (postPermitStatus === null && plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED') {
      try {
        postPermitPreflight = await readPreflight(runtimePreflight)
      } catch {
        postPermitStatus = 'PAUSED_SAFETY'
        postPermitReasons.push('CONTROL_PLANE_LOSS')
      }
    }
    const permitDispatchTime = sampleRuntimeTime()
    if (!permitDispatchTime.valid) {
      postPermitStatus = 'PAUSED_SAFETY'
      postPermitReasons = [permitDispatchTime.reason]
    } else if (elapsedAt(permitDispatchTime.monotonicTime) >= runLimits.max_wall_time_ms) {
      postPermitStatus = 'LIMIT_EXHAUSTED'
      postPermitReasons = ['MAX_WALL_TIME_EXHAUSTED']
    } else if (campaignSignal?.aborted === true) {
      postPermitStatus = 'ABORTED'
      postPermitReasons = ['CAMPAIGN_ABORTED']
    } else if (
      requiresAuthorization
      && permitDispatchTime.wallTime >= Date.parse(authorizationReceipt.expires_at)
    ) {
      postPermitStatus = 'PAUSED_AUTHORIZATION'
      postPermitReasons = ['AUTHORIZATION_EXPIRED']
    } else if (postPermitStatus === null && plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED') {
      const failures = runtimePreflightFailures(plan, postPermitPreflight, preflight)
      if (
        preflight.mode === 'BREAK_GLASS'
        && permitDispatchTime.wallTime >= Date.parse(breakGlassOverride.expires_at)
      ) {
        failures.push('BREAK_GLASS_EXPIRED')
      }
      if (failures.length > 0) {
        postPermitStatus = 'PAUSED_SAFETY'
        postPermitReasons = failures
      }
    }
    let preSendPreflightQualificationReceipt = null
    if (plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED') {
      preSendPreflightQualificationReceipt = await qualifyL3Preflight(
        'PRE_SEND_RECHECK',
        postPermitStatus === null ? 'PASS' : 'DENY',
        postPermitPreflight,
        postPermitReasons,
      )
    }
    if (postPermitStatus !== null) {
      return cancelUndispatched(postPermitStatus, postPermitReasons, permitDispatchTime)
    }
    const dispatchTime = sampleRuntimeTime()
    if (!dispatchTime.valid) {
      return cancelUndispatched('PAUSED_SAFETY', [dispatchTime.reason], dispatchTime)
    }
    const dispatchDeadlines = [
      runLimits.max_action_time_ms,
      runLimits.max_wall_time_ms - elapsedAt(dispatchTime.monotonicTime),
    ]
    if (requiresAuthorization) {
      dispatchDeadlines.push(Date.parse(authorizationReceipt.expires_at) - dispatchTime.wallTime)
    }
    if (preflight.mode === 'BREAK_GLASS') {
      dispatchDeadlines.push(Date.parse(breakGlassOverride.expires_at) - dispatchTime.wallTime)
    }
    const effectiveActionTimeoutMs = Math.floor(Math.min(...dispatchDeadlines))
    if (effectiveActionTimeoutMs < 1) {
      if (
        requiresAuthorization
        && dispatchTime.wallTime >= Date.parse(authorizationReceipt.expires_at)
      ) {
        return cancelUndispatched(
          'PAUSED_AUTHORIZATION',
          ['AUTHORIZATION_EXPIRED'],
          dispatchTime,
        )
      }
      if (
        preflight.mode === 'BREAK_GLASS'
        && dispatchTime.wallTime >= Date.parse(breakGlassOverride.expires_at)
      ) {
        return cancelUndispatched('PAUSED_SAFETY', ['BREAK_GLASS_EXPIRED'], dispatchTime)
      }
      return cancelUndispatched('LIMIT_EXHAUSTED', ['MAX_WALL_TIME_EXHAUSTED'], dispatchTime)
    }
    let sendPermitSha256 = null
    if (plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED') {
      const sendPermit = deepFreeze({
        schema_version: '1.0.0',
        kind: 'red-team-audit/adversarial-action-send-permit',
        action_sha256: actionSha256,
        classification_sha256: classificationSha256,
        initial_scope_receipt_sha256: digestJson(initialScopeQualificationReceipt),
        pre_boundary_receipt_sha256: digestJson(boundaryPreflightQualificationReceipt),
        boundary_receipt_sha256: digestJson(boundaryQualificationReceipt),
        scope_recheck_receipt_sha256: digestJson(preSendScopeQualificationReceipt),
        pre_send_receipt_sha256: digestJson(preSendPreflightQualificationReceipt),
        resolved_target_sha256: digestJson(classification.resolved_target),
        effect_classification_sha256: digestJson({
          complete: true,
          effects: classification.anticipated_effects,
        }),
        max_output_bytes: effectiveOutputBytes,
        max_action_time_ms: effectiveActionTimeoutMs,
      })
      sendPermitSha256 = digestJson(sendPermit)
      await campaignLedger.recordSendPermit({
        actionId: boundaryAction.action_id,
        actionSha256,
        branchId,
        permit: sendPermit,
        elapsedMs: elapsedAtSample(dispatchTime),
      })
      let cancelledStatus = null
      let cancelledReasons = []
      // The durable permit append is itself an await boundary. Refresh every
      // mutable authority source after it; any denial settles the permit as an
      // explicit non-send before the dispatcher can observe the action.
      if (requiresScopeGate) {
        try {
          const finalScopeDecision = normalizeScopeDecision(
            await scopeAuthorize(structuredClone(boundaryAction), scopeContext),
            scopeDecisionExpectation,
          )
          if (!finalScopeDecision.allowed) {
            cancelledStatus = 'PAUSED_SCOPE'
            cancelledReasons = [finalScopeDecision.decision === 'ERROR'
              ? 'SCOPE_DECISION_INVALID_AFTER_SEND_PERMIT'
              : 'SCOPE_DENIED_AFTER_SEND_PERMIT']
          }
        } catch {
          cancelledStatus = 'PAUSED_SCOPE'
          cancelledReasons = ['SCOPE_REAUTHORIZATION_FAILED_AFTER_SEND_PERMIT']
        }
      }
      if (cancelledStatus === null && requiresAuthorization) {
        const finalAuthorizationControl = await readCurrentAuthorizationControl({
          authorizationReceipt,
          isAuthorizationRevoked: authorizationRevocationCheck,
          isOperatorStopRequested: operatorStopCheck,
        })
        if (!finalAuthorizationControl.allowed) {
          cancelledStatus = finalAuthorizationControl.status
          cancelledReasons = [finalAuthorizationControl.reason]
        } else {
          currentAuthorization = finalAuthorizationControl.currentAuthorization
        }
      }
      // Stop and revocation checks are asynchronous and may coincide with an
      // append-only scope change. Fence the exact action against the scope head
      // once more after those awaits so a withdrawal cannot be hidden in the
      // gap between the first post-permit scope check and transport dispatch.
      if (cancelledStatus === null && requiresScopeGate) {
        try {
          const postAuthorizationScopeDecision = normalizeScopeDecision(
            await scopeAuthorize(structuredClone(boundaryAction), scopeContext),
            scopeDecisionExpectation,
          )
          if (!postAuthorizationScopeDecision.allowed) {
            cancelledStatus = 'PAUSED_SCOPE'
            cancelledReasons = [postAuthorizationScopeDecision.decision === 'ERROR'
              ? 'SCOPE_DECISION_INVALID_AFTER_AUTHORIZATION_RECHECK'
              : 'SCOPE_DENIED_AFTER_AUTHORIZATION_RECHECK']
          }
        } catch {
          cancelledStatus = 'PAUSED_SCOPE'
          cancelledReasons = ['SCOPE_REAUTHORIZATION_FAILED_AFTER_AUTHORIZATION_RECHECK']
        }
      }
      const postPermitTime = sampleRuntimeTime()
      if (!postPermitTime.valid) {
        cancelledStatus = 'PAUSED_SAFETY'
        cancelledReasons = [postPermitTime.reason]
      } else if (campaignSignal?.aborted === true) {
        cancelledStatus = 'ABORTED'
        cancelledReasons = ['CAMPAIGN_ABORTED_AFTER_SEND_PERMIT']
      } else if (elapsedAt(postPermitTime.monotonicTime) >= runLimits.max_wall_time_ms) {
        cancelledStatus = 'LIMIT_EXHAUSTED'
        cancelledReasons = ['MAX_WALL_TIME_EXHAUSTED_AFTER_SEND_PERMIT']
      } else if (
        requiresAuthorization
        && postPermitTime.wallTime >= Date.parse(authorizationReceipt.expires_at)
      ) {
        cancelledStatus = 'PAUSED_AUTHORIZATION'
        cancelledReasons = ['AUTHORIZATION_EXPIRED_AFTER_SEND_PERMIT']
      } else if (
        preflight.mode === 'BREAK_GLASS'
        && postPermitTime.wallTime >= Date.parse(breakGlassOverride.expires_at)
      ) {
        cancelledStatus = 'PAUSED_SAFETY'
        cancelledReasons = ['BREAK_GLASS_EXPIRED_AFTER_SEND_PERMIT']
      }
      if (cancelledStatus !== null) {
        await campaignLedger.recordDispatchSettlement({
          actionId: boundaryAction.action_id,
          actionSha256,
          branchId,
          receipt: {
            schema_version: '1.0.0',
            kind: 'red-team-audit/adversarial-dispatch-settlement-receipt',
            action_sha256: actionSha256,
            send_permit_sha256: sendPermitSha256,
            outcome: 'CANCELLED_BEFORE_SEND',
            request_may_have_been_sent: false,
            observation_sha256: null,
            reason_codes: cancelledReasons,
          },
          elapsedMs: elapsedAtSample(postPermitTime),
        })
        state.dispatched -= 1
        return finish(cancelledStatus, { stop_reasons: cancelledReasons }, postPermitTime)
      }
    }
    const persistDispatchObservation = async ({
      observation,
      settlementOutcome,
      settlementReasons,
      accountedOutputBytes,
      pauseBranch,
      cleanupStatus = null,
    }) => {
      const observationSha256 = digestJson(observation)
      const nextAggregateOutputBytes = state.aggregateOutputBytes + accountedOutputBytes
      if (campaignLedger !== null) {
        await campaignLedger.recordDispatchSettlement({
          actionId: boundaryAction.action_id,
          actionSha256,
          branchId,
          receipt: {
            schema_version: '1.0.0',
            kind: 'red-team-audit/adversarial-dispatch-settlement-receipt',
            action_sha256: actionSha256,
            send_permit_sha256: sendPermitSha256,
            outcome: settlementOutcome,
            request_may_have_been_sent: true,
            observation_sha256: observationSha256,
            reason_codes: boundedReasonCodes(settlementReasons, 'DISPATCH_OUTCOME_UNAVAILABLE'),
          },
          elapsedMs: elapsedAtSample(sampleRuntimeTime()),
        })
        await campaignLedger.recordObservation({
          actionId: boundaryAction.action_id,
          actionSha256,
          branchId,
          observation,
          accountedOutputBytes,
          aggregateOutputBytes: nextAggregateOutputBytes,
          pauseBranch,
          elapsedMs: elapsedAtSample(sampleRuntimeTime()),
        })
        if (
          plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED'
          && boundaryAction.purpose === 'cleanup'
        ) {
          const effectiveCleanupStatus = cleanupStatus ?? (
            observation.cleanup_verified === true
            && effectiveObservationTriggers(observation).length === 0
              ? 'VERIFIED'
              : observation.cleanup_verified === false
                || ['FAILED', 'ERROR'].includes(observation.status)
                ? 'FAILED'
                : 'INCONCLUSIVE'
          )
          await campaignLedger.recordCleanupOutcome({
            actionId: boundaryAction.action_id,
            actionSha256,
            receipt: {
              schema_version: '1.0.0',
              kind: 'red-team-audit/adversarial-cleanup-outcome-receipt',
              action_sha256: actionSha256,
              observation_sha256: observationSha256,
              status: effectiveCleanupStatus,
            },
            elapsedMs: elapsedAtSample(sampleRuntimeTime()),
          })
        }
      }
      state.aggregateOutputBytes = nextAggregateOutputBytes
      state.observations.push(observation)
      state.observationReceipts.push(agentObservationReceipt({
        actionId: boundaryAction.action_id,
        actionSha256,
        branchId,
        observation,
        accountedOutputBytes,
      }))
      if (pauseBranch) state.pausedBranches.add(branchId)
      return observationSha256
    }
    let rawObservation
    try {
      rawObservation = await dispatchWithTimeout(
        dispatch,
        boundaryAction,
        {
          plan: structuredClone(plan),
          authorization_receipt: authorizationReceipt
            ? structuredClone(authorizationReceipt)
            : null,
          preflight_mode: preflight.mode,
          action_sha256: actionSha256,
          classification_sha256: classificationSha256,
          send_permit_sha256: sendPermitSha256,
          max_output_bytes: effectiveOutputBytes,
          remaining_aggregate_output_bytes: remainingAggregateOutputBytes,
          controller_wall_time_ms: dispatchTime.wallTime,
          controller_monotonic_time_ms: dispatchTime.monotonicTime,
        },
        effectiveActionTimeoutMs,
        campaignSignal,
      )
    } catch (error) {
      const settlementReason = error?.code === 'ADVERSARIAL_CAMPAIGN_ABORTED'
        || campaignSignal?.aborted === true
        ? 'ABORT_REQUESTED_DISPATCH_AMBIGUOUS'
        : error?.code === 'ADVERSARIAL_ACTION_TIMEOUT'
          ? 'ACTION_DISPATCH_TIMEOUT_AMBIGUOUS'
          : 'ACTION_DISPATCH_ABORTED_AMBIGUOUS'
      if (campaignLedger !== null) {
        const observation = dispatchRecoveryObservation({
          actionSha256,
          settlementOutcome: 'AMBIGUOUS',
          reasons: [settlementReason],
        })
        await persistDispatchObservation({
          observation,
          settlementOutcome: 'AMBIGUOUS',
          settlementReasons: [settlementReason],
          accountedOutputBytes: 0,
          pauseBranch: true,
          cleanupStatus: 'INCONCLUSIVE',
        })
        return finish('PAUSED_SAFETY', { stop_reasons: [settlementReason] })
      }
      if (error?.code === 'ADVERSARIAL_CAMPAIGN_ABORTED' || campaignSignal?.aborted === true) {
        return pauseWithoutTerminalizing('PAUSED_SAFETY', {
          stop_reasons: [settlementReason],
        })
      }
      throw error
    }
    let observation
    try {
      observation = snapshotJsonDocument(
        rawObservation,
        'action observation',
        effectiveOutputBytes,
      )
    } catch (error) {
      const observationReason = error?.code === 'ADVERSARIAL_RUNTIME_JSON_LIMIT'
        ? 'ACTION_OBSERVATION_DOCUMENT_TOO_LARGE'
        : 'ACTION_OBSERVATION_INVALID'
      if (campaignLedger !== null) {
        const observation = dispatchRecoveryObservation({
          actionSha256,
          settlementOutcome: 'AMBIGUOUS',
          reasons: [observationReason],
        })
        await persistDispatchObservation({
          observation,
          settlementOutcome: 'AMBIGUOUS',
          settlementReasons: [observationReason],
          accountedOutputBytes: 0,
          pauseBranch: true,
          cleanupStatus: 'INCONCLUSIVE',
        })
        return finish('PAUSED_SAFETY', { stop_reasons: [observationReason] })
      }
      if (error?.code === 'ADVERSARIAL_RUNTIME_JSON_LIMIT') {
        return pauseWithoutTerminalizing('PAUSED_SAFETY', {
          stop_reasons: [observationReason],
        })
      }
      throw error
    }
    const observationDocumentBytes = jsonBytes(observation, 'action observation')
    if (
      !Number.isInteger(observation?.output_bytes)
      || observation.output_bytes < 0
      || observation.output_bytes > effectiveOutputBytes
    ) {
      if (campaignLedger !== null) {
        await persistDispatchObservation({
          observation,
          settlementOutcome: 'RETURNED',
          settlementReasons: [],
          accountedOutputBytes: observationDocumentBytes,
          pauseBranch: true,
          cleanupStatus: 'INCONCLUSIVE',
        })
        return finish('PAUSED_SAFETY', {
          stop_reasons: ['ACTION_OUTPUT_LIMIT_OR_ACCOUNTING_INVALID'],
        })
      }
      return pauseWithoutTerminalizing('PAUSED_SAFETY', {
        stop_reasons: ['ACTION_OUTPUT_LIMIT_OR_ACCOUNTING_INVALID'],
      })
    }
    const accountedOutputBytes = Math.max(
      observation.output_bytes,
      observationDocumentBytes,
    )
    const effectiveTriggers = effectiveObservationTriggers(observation)
    const pauseBranch = effectiveTriggers.length > 0
    await persistDispatchObservation({
      observation,
      settlementOutcome: 'RETURNED',
      settlementReasons: [],
      accountedOutputBytes,
      pauseBranch,
    })
    if (state.aggregateOutputBytes >= runLimits.max_aggregate_output_bytes) {
      return finish('LIMIT_EXHAUSTED', {
        stop_reasons: ['MAX_AGGREGATE_OUTPUT_EXHAUSTED'],
      })
    }

    if (effectiveTriggers.some((trigger) => GLOBAL_ESCALATION_TRIGGERS.has(trigger))) {
      return finish('PAUSED_SAFETY', { stop_reasons: effectiveTriggers })
    }
    if (effectiveTriggers.length > 0) {
      state.pausedBranches.add(branchId)
      if (!adaptive) {
        return finish('PAUSED_ESCALATION', { stop_reasons: effectiveTriggers })
      }
    }

    const checkpointDue = plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED'
      && state.considered % plan.campaign_envelope.checkpoint_policy.interval_actions === 0
    if (checkpointDue) {
      let checkpointDecision
      const checkpointRecord = Object.freeze({
        schema_version: '1.0.0',
        kind: 'red-team-audit/adversarial-runtime-checkpoint',
        plan_sha256: state.planSha256,
        authorization_id: authorizationReceipt?.authorization_id ?? null,
        scope_revision_sha256: plan.scope_revision_sha256,
        actions_used: state.considered,
        dispatched_actions: state.dispatched,
        aggregate_output_bytes: state.aggregateOutputBytes,
        paused_branches: [...state.pausedBranches].sort(),
      })
      if (campaignLedger !== null) {
        await campaignLedger.recordCheckpointQueued({
          checkpoint: checkpointRecord,
          elapsedMs: elapsedAtSample(sampleRuntimeTime()),
        })
      }
      try {
        checkpointDecision = await checkpoint(checkpointRecord)
      } catch {
        return pauseWithoutTerminalizing('PAUSED_CHECKPOINT', {
          stop_reasons: ['CHECKPOINT_SINK_FAILED'],
          pending_checkpoint: checkpointRecord,
        })
      }
      if (
        checkpointDecision?.decision !== 'CONTINUE'
        || checkpointDecision.plan_sha256 !== state.planSha256
        || checkpointDecision.authorization_id !== (authorizationReceipt?.authorization_id ?? null)
        || checkpointDecision.scope_revision_sha256 !== plan.scope_revision_sha256
        || checkpointDecision.actions_used !== state.considered
      ) {
        return pauseWithoutTerminalizing('PAUSED_CHECKPOINT', {
          stop_reasons: ['CHECKPOINT_NOT_ACKNOWLEDGED'],
          pending_checkpoint: checkpointRecord,
        })
      }
      if (campaignLedger !== null) {
        await campaignLedger.recordCheckpointAcknowledged({
          checkpoint: checkpointRecord,
          decision: checkpointDecision,
          elapsedMs: elapsedAtSample(sampleRuntimeTime()),
        })
      }
    }
    if (runLimits.min_action_interval_ms > 0) {
      const elapsed = await delayWithSignal(runLimits.min_action_interval_ms, campaignSignal)
      if (!elapsed) {
        return finish('ABORTED', { stop_reasons: ['CAMPAIGN_ABORTED'] })
      }
    }
  }

  if (state.considered >= campaignMaxActions) {
    return finish('LIMIT_EXHAUSTED', { stop_reasons: ['MAX_ACTIONS_EXHAUSTED'] })
  }
  return finish(
    state.pausedBranches.size > 0 ? 'COMPLETED_WITH_BLOCKED_BRANCHES' : 'COMPLETED',
  )
}
