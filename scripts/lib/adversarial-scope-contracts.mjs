import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import { compareCanonicalStrings } from './canonical-order.mjs'

const REQUEST_SCHEMA_URL = new URL(
  '../../schemas/adversarial-scope-request.schema.json',
  import.meta.url,
)
const REVISION_SCHEMA_URL = new URL(
  '../../schemas/adversarial-scope-revision.schema.json',
  import.meta.url,
)
export const OPERATOR_SCOPE_DECISION_STATEMENT = 'I confirm this exact scope decision.'
const OPERATOR_AUTHORITY_BASIS = 'OPERATOR_DECLARATION_ACCEPTED_AS_FACT'
const MAX_SCOPE_DECISION_AGE_MS = 5 * 60 * 1000
const DELTA_CATEGORIES = Object.freeze([
  'targets',
  'paths',
  'methods',
  'strategy_families',
  'data_classes',
  'impact_permissions',
  'limits',
  'validity',
])

export const adversarialScopeRequestSchema = JSON.parse(
  readFileSync(fileURLToPath(REQUEST_SCHEMA_URL), 'utf8'),
)
export const adversarialScopeRevisionSchema = JSON.parse(
  readFileSync(fileURLToPath(REVISION_SCHEMA_URL), 'utf8'),
)

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})
ajv.addSchema(adversarialScopeRequestSchema)
ajv.addSchema(adversarialScopeRevisionSchema)
const validateRequestSchema = ajv.getSchema(adversarialScopeRequestSchema.$id)
const validateRevisionSchema = ajv.getSchema(adversarialScopeRevisionSchema.$id)
const validateDeltaSchema = ajv.compile({
  $ref: `${adversarialScopeRequestSchema.$id}#/$defs/scopeDelta`,
})
const validateDecisionSchema = ajv.compile({
  $ref: `${adversarialScopeRevisionSchema.$id}#/$defs/operatorDecision`,
})

export class AdversarialScopeContractError extends Error {
  constructor(code, message, details = [], options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'AdversarialScopeContractError'
    this.code = code
    this.details = details
  }
}

function contractError(code, message, details = [], options = {}) {
  return new AdversarialScopeContractError(code, message, details, options)
}

function normalizeAjvErrors(errors = []) {
  return errors.map((error) => ({
    code: `SCHEMA_${String(error.keyword).toUpperCase()}`,
    keyword: error.keyword,
    instancePath: error.instancePath || '/',
    message: error.message ?? 'schema validation failed',
    params: error.params,
  }))
}

function assertSchema(validate, value, code, label) {
  if (!validate(value)) {
    throw contractError(
      code,
      `${label} violates its JSON schema`,
      normalizeAjvErrors(validate.errors),
    )
  }
  return value
}

function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex')
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue)
  if (value === null || typeof value !== 'object') return value
  return Object.fromEntries(
    Object.keys(value)
      .sort(compareCanonicalStrings)
      .map((key) => [key, stableValue(value[key])]),
  )
}

function canonicalJson(value) {
  return JSON.stringify(stableValue(value))
}

function canonicalCompare(left, right) {
  return compareCanonicalStrings(canonicalJson(left), canonicalJson(right))
}

function deepFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const entry of Object.values(value)) deepFreeze(entry)
  return Object.freeze(value)
}

function exactTimestamp(value, label) {
  const parsed = Date.parse(value)
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw contractError(
      'ADVERSARIAL_SCOPE_TIME_INVALID',
      `${label} must be a real canonical UTC millisecond timestamp`,
    )
  }
  return parsed
}

function controllerTime(value) {
  const parsed = value instanceof Date ? value.valueOf() : Date.parse(value)
  if (!Number.isFinite(parsed)) {
    throw contractError(
      'ADVERSARIAL_SCOPE_TIME_INVALID',
      'scope decision requires a real controller ingress time',
    )
  }
  return parsed
}

function canonicalDelta(delta) {
  assertSchema(
    validateDeltaSchema,
    delta,
    'ADVERSARIAL_SCOPE_DELTA_SCHEMA_INVALID',
    'scope delta',
  )
  const normalized = structuredClone(delta)
  for (const category of DELTA_CATEGORIES) {
    normalized[category].add.sort(canonicalCompare)
    normalized[category].remove.sort(canonicalCompare)
  }
  return normalized
}

function identityFor(category, entry) {
  if (category === 'targets') return entry.target_id
  if (category === 'paths') return `${entry.target_id}\0${entry.path}`
  if (category === 'limits') return entry.limit_id
  return canonicalJson(entry)
}

function assertNoDuplicateIdentities(category, side, entries) {
  const seen = new Set()
  for (const entry of entries) {
    const identity = identityFor(category, entry)
    if (seen.has(identity)) {
      throw contractError(
        'ADVERSARIAL_SCOPE_DELTA_DUPLICATE',
        `${category}.${side} contains duplicate identity ${JSON.stringify(identity)}`,
      )
    }
    seen.add(identity)
  }
}

function assertValidDelta(delta) {
  const normalized = canonicalDelta(delta)
  let changes = 0
  for (const category of DELTA_CATEGORIES) {
    const { add, remove } = normalized[category]
    changes += add.length + remove.length
    assertNoDuplicateIdentities(category, 'add', add)
    assertNoDuplicateIdentities(category, 'remove', remove)
    const removed = new Set(remove.map((entry) => canonicalJson(entry)))
    const overlap = add.find((entry) => removed.has(canonicalJson(entry)))
    if (overlap !== undefined) {
      throw contractError(
        'ADVERSARIAL_SCOPE_DELTA_OVERLAP',
        `${category} cannot add and remove the same exact value`,
      )
    }
  }
  if (changes === 0) {
    throw contractError(
      'ADVERSARIAL_SCOPE_DELTA_EMPTY',
      'a scope expansion request must contain at least one exact change',
    )
  }
  for (const side of ['add', 'remove']) {
    for (const window of normalized.validity[side]) {
      const notBefore = exactTimestamp(window.not_before, `delta.validity.${side}.not_before`)
      const notAfter = exactTimestamp(window.not_after, `delta.validity.${side}.not_after`)
      if (notAfter <= notBefore) {
        throw contractError(
          'ADVERSARIAL_SCOPE_VALIDITY_INVALID',
          `delta.validity.${side} requires not_after later than not_before`,
        )
      }
    }
  }
  return normalized
}

export function adversarialScopeDeltaDigest(delta) {
  return sha256Hex(canonicalJson(assertValidDelta(delta)))
}

function canonicalRequestDocument(request) {
  const document = structuredClone(request)
  document.delta = assertValidDelta(document.delta)
  if (Array.isArray(document.discovery_evidence)) {
    document.discovery_evidence.sort(canonicalCompare)
  }
  return document
}

function canonicalRequestMaterial(request) {
  const material = canonicalRequestDocument(request)
  delete material.request_sha256
  return material
}

export function adversarialScopeRequestDigest(request) {
  return sha256Hex(canonicalJson(canonicalRequestMaterial(request)))
}

function assertUniqueEvidence(records) {
  const ids = new Set()
  for (const record of records) {
    if (ids.has(record.evidence_id)) {
      throw contractError(
        'ADVERSARIAL_SCOPE_EVIDENCE_DUPLICATE',
        `discovery evidence id ${JSON.stringify(record.evidence_id)} is duplicated`,
      )
    }
    ids.add(record.evidence_id)
  }
}

export function assertValidAdversarialScopeRequest(request) {
  assertSchema(
    validateRequestSchema,
    request,
    'ADVERSARIAL_SCOPE_REQUEST_SCHEMA_INVALID',
    'adversarial scope request',
  )
  exactTimestamp(request.requested_at, 'request.requested_at')
  assertUniqueEvidence(request.discovery_evidence)
  const expectedDeltaDigest = adversarialScopeDeltaDigest(request.delta)
  if (request.delta_sha256 !== expectedDeltaDigest) {
    throw contractError(
      'ADVERSARIAL_SCOPE_DELTA_DIGEST_MISMATCH',
      'request delta_sha256 does not match the exact canonical delta',
    )
  }
  const expectedRequestDigest = adversarialScopeRequestDigest(request)
  if (request.request_sha256 !== expectedRequestDigest) {
    throw contractError(
      'ADVERSARIAL_SCOPE_REQUEST_DIGEST_MISMATCH',
      'request_sha256 does not match the canonical request',
    )
  }
  return request
}

/** Canonical JSON text suitable for write-once persistence. */
export function canonicalAdversarialScopeRequest(request) {
  assertValidAdversarialScopeRequest(request)
  return canonicalJson(canonicalRequestDocument(request))
}

/**
 * Creates inert data only. All timestamps, predecessor identity, evidence and
 * desired authority are caller-supplied; this function performs no target,
 * filesystem, clock, credential, or network I/O.
 */
export function createAdversarialScopeRequest(options) {
  const {
    requestId,
    engagementId,
    requestedAt,
    baseScopeRevision,
    baseScopeSha256,
    delta,
    rationale,
    blockedObjective,
    discoveryEvidence,
    expectedRisk,
    sideEffects,
    cleanupPlan,
    eligibleActionPlan,
    attackPlanSha256,
  } = options ?? {}
  const normalizedDelta = assertValidDelta(delta)
  const request = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-scope-request',
    request_id: requestId,
    engagement_id: engagementId,
    requested_at: requestedAt,
    base_scope: {
      revision: baseScopeRevision,
      sha256: baseScopeSha256,
    },
    delta: normalizedDelta,
    delta_sha256: adversarialScopeDeltaDigest(normalizedDelta),
    rationale,
    blocked_objective: blockedObjective,
    discovery_evidence: Array.isArray(discoveryEvidence)
      ? structuredClone(discoveryEvidence).sort(canonicalCompare)
      : discoveryEvidence,
    expected_risk: expectedRisk,
    side_effects: sideEffects,
    cleanup_plan: cleanupPlan,
    eligible_action_plan: eligibleActionPlan,
    ...(attackPlanSha256 === undefined
      ? {}
      : { attack_plan_sha256: attackPlanSha256 }),
  }
  request.request_sha256 = adversarialScopeRequestDigest(request)
  assertValidAdversarialScopeRequest(request)
  return deepFreeze(request)
}

function exactDeltaEqual(left, right) {
  return canonicalJson(assertValidDelta(left)) === canonicalJson(assertValidDelta(right))
}

function assertStrictNarrowing(requested, approved) {
  const requestedDelta = assertValidDelta(requested)
  const approvedDelta = assertValidDelta(approved)
  if (exactDeltaEqual(requestedDelta, approvedDelta)) {
    throw contractError(
      'ADVERSARIAL_SCOPE_NARROWING_INVALID',
      'NARROW must approve a strict subset; use APPROVE for the exact request',
    )
  }
  for (const category of DELTA_CATEGORIES) {
    for (const side of ['add', 'remove']) {
      const requestedValues = new Set(
        requestedDelta[category][side].map((entry) => canonicalJson(entry)),
      )
      for (const entry of approvedDelta[category][side]) {
        if (!requestedValues.has(canonicalJson(entry))) {
          throw contractError(
            'ADVERSARIAL_SCOPE_NARROWING_INVALID',
            `NARROW introduced an unrequested ${category}.${side} value`,
          )
        }
      }
    }
  }
  return approvedDelta
}

function assertDecisionSemantics(request, decision) {
  if (
    decision.request_id !== request.request_id
    || decision.request_sha256 !== request.request_sha256
    || decision.base_scope_revision !== request.base_scope.revision
    || decision.base_scope_sha256 !== request.base_scope.sha256
  ) {
    throw contractError(
      'ADVERSARIAL_SCOPE_DECISION_BINDING_MISMATCH',
      'operator decision is not bound to the exact request and predecessor scope',
    )
  }
  const requestedAt = exactTimestamp(request.requested_at, 'request.requested_at')
  const decidedAt = exactTimestamp(decision.decided_at, 'decision.decided_at')
  const validUntil = exactTimestamp(decision.valid_until, 'decision.valid_until')
  if (decidedAt < requestedAt) {
    throw contractError(
      'ADVERSARIAL_SCOPE_TIME_INVALID',
      'operator decision cannot predate the scope request',
    )
  }
  if (validUntil !== decidedAt + MAX_SCOPE_DECISION_AGE_MS) {
    throw contractError(
      'ADVERSARIAL_SCOPE_DECISION_WINDOW_INVALID',
      'operator scope decisions have one fixed five-minute controller-ingress window',
    )
  }
  const accepts = ['APPROVE', 'NARROW'].includes(decision.disposition)
  if (!accepts) return decision

  const expectedDeltaDigest = adversarialScopeDeltaDigest(decision.approved_delta)
  if (decision.approved_delta_sha256 !== expectedDeltaDigest) {
    throw contractError(
      'ADVERSARIAL_SCOPE_DELTA_DIGEST_MISMATCH',
      'approved_delta_sha256 does not match the canonical approved delta',
    )
  }
  if (decision.disposition === 'APPROVE') {
    if (!exactDeltaEqual(request.delta, decision.approved_delta)) {
      throw contractError(
        'ADVERSARIAL_SCOPE_DECISION_DELTA_MISMATCH',
        'APPROVE must retain the exact requested delta; edited deltas use NARROW',
      )
    }
    if (decision.attack_plan_sha256 !== request.attack_plan_sha256) {
      throw contractError(
        'ADVERSARIAL_SCOPE_ATTACK_PLAN_BINDING_MISMATCH',
        'operator decision cannot authorize a changed or undisclosed attack plan',
      )
    }
  } else {
    assertStrictNarrowing(request.delta, decision.approved_delta)
    if (request.attack_plan_sha256 === undefined) {
      if (decision.attack_plan_sha256 !== undefined) {
        throw contractError(
          'ADVERSARIAL_SCOPE_ATTACK_PLAN_BINDING_MISMATCH',
          'a narrowed scope cannot introduce an attack plan absent from the request',
        )
      }
    } else if (
      decision.attack_plan_sha256 === undefined
      || decision.attack_plan_sha256 === request.attack_plan_sha256
    ) {
      throw contractError(
        'ADVERSARIAL_SCOPE_ATTACK_PLAN_REBIND_REQUIRED',
        'an operator-edited scope delta requires a newly bound attack plan digest',
      )
    }
  }
  return decision
}

function assertDecisionCurrent(decision, now) {
  const current = controllerTime(now)
  const decidedAt = exactTimestamp(decision.decided_at, 'decision.decided_at')
  const validUntil = exactTimestamp(decision.valid_until, 'decision.valid_until')
  if (decidedAt > current) {
    throw contractError(
      'ADVERSARIAL_SCOPE_DECISION_FUTURE',
      'operator scope decision cannot be future-dated at controller ingress',
    )
  }
  if (current >= validUntil) {
    throw contractError(
      'ADVERSARIAL_SCOPE_DECISION_EXPIRED',
      'operator scope decision expired before the scope revision was resolved or appended',
    )
  }
  return decision
}

/**
 * Creates the controller record for an operator's exact scope decision. The
 * authenticated controller ingress, not a caller-supplied signing key, is the
 * authority boundary. Canonical digests keep the decision bound to the request,
 * predecessor, approved delta, and disclosed attack plan.
 */
export function createAdversarialScopeDecision(options) {
  const {
    decisionId,
    request,
    disposition,
    rationale,
    decidedAt,
    now = new Date(),
    operatorId,
    authorizationReference,
    statement = OPERATOR_SCOPE_DECISION_STATEMENT,
    approvedDelta,
    attackPlanSha256,
  } = options ?? {}
  assertValidAdversarialScopeRequest(request)
  const decidedAtEpoch = exactTimestamp(decidedAt, 'decision.decided_at')
  const accepts = ['APPROVE', 'NARROW'].includes(disposition)
  let effectiveDelta
  let effectiveAttackPlan
  if (disposition === 'APPROVE') {
    effectiveDelta = assertValidDelta(approvedDelta ?? request.delta)
    effectiveAttackPlan = attackPlanSha256 ?? request.attack_plan_sha256
  } else if (disposition === 'NARROW') {
    if (approvedDelta === undefined) {
      throw contractError(
        'ADVERSARIAL_SCOPE_NARROWING_INVALID',
        'NARROW requires the exact approved subset delta',
      )
    }
    effectiveDelta = assertValidDelta(approvedDelta)
    effectiveAttackPlan = attackPlanSha256
  } else if (approvedDelta !== undefined || attackPlanSha256 !== undefined) {
    throw contractError(
      'ADVERSARIAL_SCOPE_DECISION_FIELDS_INVALID',
      'DENY and DEFER cannot carry approved scope or attack-plan authority',
    )
  }

  const decision = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-scope-decision',
    decision_id: decisionId,
    request_id: request.request_id,
    request_sha256: request.request_sha256,
    base_scope_revision: request.base_scope.revision,
    base_scope_sha256: request.base_scope.sha256,
    disposition,
    rationale,
    decided_at: decidedAt,
    valid_until: new Date(decidedAtEpoch + MAX_SCOPE_DECISION_AGE_MS).toISOString(),
    operator_id: operatorId,
    authorization_reference: authorizationReference,
    statement,
    authority_basis: OPERATOR_AUTHORITY_BASIS,
    ...(accepts
      ? {
          approved_delta: effectiveDelta,
          approved_delta_sha256: adversarialScopeDeltaDigest(effectiveDelta),
        }
      : {}),
    ...(effectiveAttackPlan === undefined
      ? {}
      : { attack_plan_sha256: effectiveAttackPlan }),
  }
  assertSchema(
    validateDecisionSchema,
    decision,
    'ADVERSARIAL_SCOPE_DECISION_SCHEMA_INVALID',
    'adversarial scope decision',
  )
  assertDecisionSemantics(request, decision)
  assertDecisionCurrent(decision, now)
  return deepFreeze(decision)
}

export function verifyAdversarialScopeDecision({ request, decision, now } = {}) {
  assertValidAdversarialScopeRequest(request)
  assertSchema(
    validateDecisionSchema,
    decision,
    'ADVERSARIAL_SCOPE_DECISION_SCHEMA_INVALID',
    'adversarial scope decision',
  )
  if (
    decision.statement !== OPERATOR_SCOPE_DECISION_STATEMENT
    || decision.authority_basis !== OPERATOR_AUTHORITY_BASIS
  ) {
    throw contractError(
      'ADVERSARIAL_SCOPE_OPERATOR_DECISION_INVALID',
      'scope decision must contain the exact affirmative controller statement and authority basis',
    )
  }
  assertDecisionSemantics(request, decision)
  if (now !== undefined) assertDecisionCurrent(decision, now)
  return decision
}

/** Canonical JSON text for a controller-qualified operator decision. */
export function canonicalAdversarialScopeDecision(decision, { request } = {}) {
  verifyAdversarialScopeDecision({ request, decision })
  const document = structuredClone(decision)
  if (document.approved_delta !== undefined) {
    document.approved_delta = assertValidDelta(document.approved_delta)
  }
  return canonicalJson(document)
}

function canonicalRevisionDocument(revision) {
  const document = structuredClone(revision)
  if (document.operator_decision?.approved_delta !== undefined) {
    document.operator_decision.approved_delta = assertValidDelta(
      document.operator_decision.approved_delta,
    )
  }
  return document
}

function canonicalRevisionMaterial(revision) {
  const material = canonicalRevisionDocument(revision)
  delete material.scope_sha256
  return material
}

export function adversarialScopeRevisionDigest(revision) {
  return sha256Hex(canonicalJson(canonicalRevisionMaterial(revision)))
}

export function assertValidAdversarialScopeRevision(
  revision,
  { request } = {},
) {
  assertSchema(
    validateRevisionSchema,
    revision,
    'ADVERSARIAL_SCOPE_REVISION_SCHEMA_INVALID',
    'adversarial scope revision',
  )
  const expectedDigest = adversarialScopeRevisionDigest(revision)
  if (revision.scope_sha256 !== expectedDigest) {
    throw contractError(
      'ADVERSARIAL_SCOPE_REVISION_DIGEST_MISMATCH',
      'scope_sha256 does not match the canonical successor revision',
    )
  }
  assertValidAdversarialScopeRequest(request)
  verifyAdversarialScopeDecision({
    request,
    decision: revision.operator_decision,
  })
  if (!['APPROVE', 'NARROW'].includes(revision.operator_decision.disposition)) {
    throw contractError(
      'ADVERSARIAL_SCOPE_REVISION_DECISION_INVALID',
      'only APPROVE or NARROW may create a successor scope revision',
    )
  }
  if (
    revision.engagement_id !== request.engagement_id
    || revision.scope_revision !== request.base_scope.revision + 1
    || revision.previous_scope_sha256 !== request.base_scope.sha256
    || revision.request_id !== request.request_id
    || revision.request_sha256 !== request.request_sha256
    || revision.attack_plan_sha256 !== revision.operator_decision.attack_plan_sha256
  ) {
    throw contractError(
      'ADVERSARIAL_SCOPE_REVISION_BINDING_MISMATCH',
      'successor revision is not exactly predecessor, request, decision, and attack-plan bound',
    )
  }
  return revision
}

/** Canonical JSON text for a controller-qualified successor revision. */
export function canonicalAdversarialScopeRevision(
  revision,
  { request } = {},
) {
  assertValidAdversarialScopeRevision(revision, { request })
  return canonicalJson(canonicalRevisionDocument(revision))
}

/**
 * Re-checks the live append head immediately before a caller persists a
 * successor. This function is pure; the caller owns atomic compare-and-append.
 */
export function assertAdversarialScopeSuccessorAppend({
  currentScope,
  request,
  successorRevision,
  now = new Date(),
} = {}) {
  assertValidAdversarialScopeRequest(request)
  if (
    !currentScope
    || currentScope.revision !== request.base_scope.revision
    || currentScope.sha256 !== request.base_scope.sha256
  ) {
    throw contractError(
      'ADVERSARIAL_SCOPE_PREDECESSOR_MISMATCH',
      'scope request is stale or does not match the current append-only scope head',
    )
  }
  assertValidAdversarialScopeRevision(successorRevision, { request })
  assertDecisionCurrent(successorRevision.operator_decision, now)
  return successorRevision
}

export function resolveAdversarialScopeRequest({ request, decision, now = new Date() } = {}) {
  verifyAdversarialScopeDecision({ request, decision, now })
  if (['DENY', 'DEFER'].includes(decision.disposition)) {
    return deepFreeze({ disposition: decision.disposition, decision, revision: null })
  }
  const revision = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-scope-revision',
    engagement_id: request.engagement_id,
    scope_revision: request.base_scope.revision + 1,
    previous_scope_sha256: request.base_scope.sha256,
    request_id: request.request_id,
    request_sha256: request.request_sha256,
    operator_decision: structuredClone(decision),
    ...(decision.attack_plan_sha256 === undefined
      ? {}
      : { attack_plan_sha256: decision.attack_plan_sha256 }),
  }
  revision.scope_sha256 = adversarialScopeRevisionDigest(revision)
  assertValidAdversarialScopeRevision(revision, { request })
  return deepFreeze({
    disposition: decision.disposition,
    decision,
    revision,
  })
}
