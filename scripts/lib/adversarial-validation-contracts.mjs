import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import { stableJson } from './run-engine.mjs'

const PLAN_SCHEMA_URL = new URL(
  '../../schemas/adversarial-plan.schema.json',
  import.meta.url,
)
const MAX_PLAN_BYTES = 1024 * 1024
const MAX_JSON_DEPTH = 32
const MAX_JSON_NODES = 20_000

export const ADVERSARIAL_TARGET_KINDS = Object.freeze([
  'repository',
  'local_service',
  'live',
])

export const AUTONOMY_PROFILES = Object.freeze([
  'L1_ASSISTED',
  'L2_SUPERVISED',
  'L3_MAXIMUM_AUTHORIZED',
])

export const ADVERSARIAL_RISK_CLASSES = Object.freeze([
  'READ_ONLY',
  'STATE_CHANGE',
  'SENSITIVE_DATA',
  'AVAILABILITY_IMPACT',
  'IRREVERSIBLE_CHANGE',
  'PERSISTENCE',
  'LATERAL_MOVEMENT',
])

export const ADVERSARIAL_EFFECTS = Object.freeze([
  'READ_ONLY_OBSERVATION',
  'STATE_CHANGE',
  'SENSITIVE_DATA_ACCESS',
  'AVAILABILITY_IMPACT',
  'IRREVERSIBLE_CHANGE',
  'PERSISTENCE',
  'LATERAL_MOVEMENT',
  'SCOPE_EXPANSION',
  'UNEXPECTED_SENSITIVE_DATA_ACCESS',
  'THIRD_PARTY_ACCESS',
  'EVIDENCE_DESTRUCTION',
  'UNPLANNED_LATERAL_MOVEMENT',
  'RESOURCE_EXHAUSTION',
])

const ADVERSARIAL_RISK_CLASS_RANK = Object.freeze({
  READ_ONLY: 0,
  STATE_CHANGE: 1,
  SENSITIVE_DATA: 2,
  AVAILABILITY_IMPACT: 3,
  IRREVERSIBLE_CHANGE: 4,
  PERSISTENCE: 5,
  LATERAL_MOVEMENT: 6,
})

const ADVERSARIAL_EFFECT_MINIMUM_RISK_CLASS = Object.freeze({
  READ_ONLY_OBSERVATION: 'READ_ONLY',
  STATE_CHANGE: 'STATE_CHANGE',
  SENSITIVE_DATA_ACCESS: 'SENSITIVE_DATA',
  AVAILABILITY_IMPACT: 'AVAILABILITY_IMPACT',
  IRREVERSIBLE_CHANGE: 'IRREVERSIBLE_CHANGE',
  PERSISTENCE: 'PERSISTENCE',
  LATERAL_MOVEMENT: 'LATERAL_MOVEMENT',
  SCOPE_EXPANSION: 'LATERAL_MOVEMENT',
  UNEXPECTED_SENSITIVE_DATA_ACCESS: 'SENSITIVE_DATA',
  THIRD_PARTY_ACCESS: 'SENSITIVE_DATA',
  EVIDENCE_DESTRUCTION: 'IRREVERSIBLE_CHANGE',
  UNPLANNED_LATERAL_MOVEMENT: 'LATERAL_MOVEMENT',
  RESOURCE_EXHAUSTION: 'AVAILABILITY_IMPACT',
})

export function evaluateAdversarialEffectRisk(riskClass, effects) {
  if (!Object.hasOwn(ADVERSARIAL_RISK_CLASS_RANK, riskClass) || !Array.isArray(effects)) {
    return { valid: false, code: 'EFFECT_RISK_INPUT_INVALID' }
  }
  const unknownEffects = effects
    .filter((effect) => !ADVERSARIAL_EFFECTS.includes(effect))
    .sort()
  if (unknownEffects.length > 0) {
    return {
      valid: false,
      code: 'UNKNOWN_EFFECT_CLASSIFIED',
      unknown_effects: unknownEffects,
    }
  }
  let minimumRiskClass = 'READ_ONLY'
  for (const effect of effects) {
    const candidate = ADVERSARIAL_EFFECT_MINIMUM_RISK_CLASS[effect]
    if (
      ADVERSARIAL_RISK_CLASS_RANK[candidate]
      > ADVERSARIAL_RISK_CLASS_RANK[minimumRiskClass]
    ) minimumRiskClass = candidate
  }
  if (
    ADVERSARIAL_RISK_CLASS_RANK[riskClass]
    < ADVERSARIAL_RISK_CLASS_RANK[minimumRiskClass]
  ) {
    return {
      valid: false,
      code: 'EFFECT_RISK_UNDERCLASSIFIED',
      minimum_risk_class: minimumRiskClass,
    }
  }
  return { valid: true, minimum_risk_class: minimumRiskClass }
}

export const L3_PREFLIGHT_FLAGS = Object.freeze([
  'external_scope_enforcement',
  'impact_classification',
  'finite_budgets',
  'target_health_monitoring',
  'append_only_evidence_capture',
  'operator_kill_switch',
  'control_plane_loss_failsafe',
  'credential_isolation',
  'cleanup_or_rollback',
])

export const L3_MANDATORY_ESCALATION_TRIGGERS = Object.freeze([
  'SCOPE_OR_AUTHORITY_CHANGE',
  'UNEXPECTED_SENSITIVE_OR_THIRD_PARTY_DATA',
  'TARGET_HEALTH_DEGRADATION',
  'LOCKOUT_OR_RESOURCE_EXHAUSTION',
  'IRREVERSIBLE_OR_PERSISTENCE_EFFECT',
  'UNPLANNED_LATERAL_MOVEMENT',
  'OPERATOR_STOP',
  'CONTROL_PLANE_LOSS',
  'AMBIGUOUS_AUTHORIZATION_OR_CLEANUP',
])

export const L3_PROHIBITED_EFFECTS = Object.freeze([
  'SCOPE_EXPANSION',
  'UNEXPECTED_SENSITIVE_DATA_ACCESS',
  'THIRD_PARTY_ACCESS',
  'IRREVERSIBLE_CHANGE',
  'PERSISTENCE',
  'EVIDENCE_DESTRUCTION',
  'UNPLANNED_LATERAL_MOVEMENT',
  'RESOURCE_EXHAUSTION',
])

// BREAK_GLASS may never waive controls that define authority, attribution,
// containment, evidence custody, or operator control. The verifier
// intentionally accepts no unsigned override flag.
export const L3_NON_OVERRIDABLE_PREFLIGHT_FLAGS = Object.freeze([
  'external_scope_enforcement',
  'impact_classification',
  'finite_budgets',
  'append_only_evidence_capture',
  'operator_kill_switch',
  'control_plane_loss_failsafe',
  'credential_isolation',
])

export const BREAK_GLASS_NON_OVERRIDABLE_INVARIANTS = Object.freeze([
  'SCOPE_AND_LEGAL_AUTHORIZATION',
  'EXACT_PLAN_BINDING',
  'FINITE_BUDGETS',
  'IMPACT_CLASSIFICATION',
  'APPEND_ONLY_EVIDENCE_CUSTODY',
  'CREDENTIAL_ISOLATION',
  'OPERATOR_KILL_SWITCH',
  'CONTROL_PLANE_LOSS_FAILSAFE',
  'CURRENT_AUTHORIZATION_AND_REVOCATION',
])

export const adversarialPlanSchema = JSON.parse(
  readFileSync(fileURLToPath(PLAN_SCHEMA_URL), 'utf8'),
)

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})
ajv.addSchema(adversarialPlanSchema)
const validatePlanSchema = ajv.getSchema(adversarialPlanSchema.$id)

export class AdversarialValidationContractError extends Error {
  constructor(code, message, details = [], options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'AdversarialValidationContractError'
    this.code = code
    this.details = details
  }
}

function contractError(code, message, details = [], options = {}) {
  return new AdversarialValidationContractError(code, message, details, options)
}

function issue(code, message, instancePath = '/', params = {}) {
  return { code, message, instancePath, params }
}

function normalizeAjvErrors(errors = []) {
  return errors.map((error) => ({
    keyword: error.keyword,
    code: `SCHEMA_${String(error.keyword).toUpperCase()}`,
    instancePath: error.instancePath || '/',
    message: error.message ?? 'schema validation failed',
    params: error.params,
  }))
}

function inspectJsonValue(root) {
  const errors = []
  const activeAncestors = new WeakSet()
  const stack = [{ value: root, path: '/', depth: 0 }]
  let nodes = 0

  while (stack.length > 0) {
    const { value, path, depth, exit } = stack.pop()
    if (exit) {
      activeAncestors.delete(value)
      continue
    }
    nodes += 1
    if (nodes > MAX_JSON_NODES) {
      errors.push(issue(
        'JSON_NODE_LIMIT',
        `JSON value exceeds the ${MAX_JSON_NODES} node contract limit`,
        path,
      ))
      break
    }
    if (depth > MAX_JSON_DEPTH) {
      errors.push(issue(
        'JSON_DEPTH_LIMIT',
        `JSON value exceeds the ${MAX_JSON_DEPTH} level contract limit`,
        path,
      ))
      continue
    }
    if (value === null || typeof value === 'string' || typeof value === 'boolean') {
      continue
    }
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) {
        errors.push(issue('JSON_NUMBER_INVALID', 'JSON numbers must be finite', path))
      }
      continue
    }
    if (typeof value !== 'object') {
      errors.push(issue(
        'JSON_TYPE_INVALID',
        `value of type ${typeof value} is not JSON data`,
        path,
      ))
      continue
    }
    if (activeAncestors.has(value)) {
      errors.push(issue('JSON_CYCLE', 'cyclic values are not canonical JSON', path))
      continue
    }
    activeAncestors.add(value)
    stack.push({ value, path, depth, exit: true })

    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) {
        errors.push(issue(
          'JSON_ARRAY_PROTOTYPE_INVALID',
          'only ordinary JSON arrays may be canonicalized',
          path,
        ))
      }
      if (Object.getOwnPropertySymbols(value).length > 0) {
        errors.push(issue(
          'JSON_SYMBOL_KEY_INVALID',
          'symbol-keyed array data cannot be represented in canonical JSON',
          path,
        ))
      }
      const keys = Object.keys(value)
      if (value.length > MAX_JSON_NODES) {
        errors.push(issue(
          'JSON_ARRAY_LIMIT',
          `JSON array exceeds the ${MAX_JSON_NODES} element contract limit`,
          path,
        ))
      } else if (keys.length !== value.length) {
        errors.push(issue(
          'JSON_ARRAY_SHAPE_INVALID',
          'canonical JSON arrays cannot contain holes or named properties',
          path,
        ))
      }
      for (const key of keys) {
        if (!/^(?:0|[1-9]\d*)$/.test(key) || Number(key) >= value.length) {
          errors.push(issue(
            'JSON_ARRAY_PROPERTY_INVALID',
            'canonical JSON arrays cannot contain named properties',
            `${path === '/' ? '' : path}/${key}`,
          ))
        }
      }
    } else {
      const prototype = Object.getPrototypeOf(value)
      if (prototype !== Object.prototype && prototype !== null) {
        errors.push(issue(
          'JSON_OBJECT_INVALID',
          'only plain JSON objects may be canonicalized',
          path,
        ))
        continue
      }
      if (Object.getOwnPropertySymbols(value).length > 0) {
        errors.push(issue(
          'JSON_SYMBOL_KEY_INVALID',
          'symbol-keyed data cannot be represented in canonical JSON',
          path,
        ))
      }
    }

    const descriptors = Object.getOwnPropertyDescriptors(value)
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (Array.isArray(value) && key === 'length') continue
      const childPath = path === '/' ? `/${key}` : `${path}/${key}`
      if (!descriptor.enumerable || 'get' in descriptor || 'set' in descriptor) {
        errors.push(issue(
          'JSON_PROPERTY_INVALID',
          'canonical JSON accepts enumerable data properties only',
          childPath,
        ))
        continue
      }
      stack.push({ value: descriptor.value, path: childPath, depth: depth + 1 })
    }
  }

  return errors
}

function canonicalJson(value) {
  const rendered = stableJson(value, 0)
  return rendered.endsWith('\n') ? rendered.slice(0, -1) : rendered
}

function canonicalByteLength(value) {
  return Buffer.byteLength(canonicalJson(value), 'utf8')
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function validateResourceEnvelope(value, maxBytes, label) {
  const errors = inspectJsonValue(value)
  if (errors.length > 0) return errors
  let bytes
  try {
    bytes = canonicalByteLength(value)
  } catch (error) {
    return [issue(
      'CANONICAL_JSON_INVALID',
      `${label} cannot be encoded as canonical JSON: ${error.message}`,
    )]
  }
  if (bytes > maxBytes) {
    errors.push(issue(
      'DOCUMENT_SIZE_LIMIT',
      `${label} exceeds the ${maxBytes} byte canonical JSON limit`,
      '/',
      { bytes, maxBytes },
    ))
  }
  return errors
}

function planSemanticErrors(plan) {
  const errors = []
  if (plan.limits.max_action_time_ms > plan.limits.max_wall_time_ms) {
    errors.push(issue(
      'PLAN_ACTION_TIME_EXCEEDS_WALL_TIME',
      'max_action_time_ms cannot exceed max_wall_time_ms',
      '/limits/max_action_time_ms',
    ))
  }
  if (plan.limits.max_output_bytes > plan.limits.max_aggregate_output_bytes) {
    errors.push(issue(
      'PLAN_OUTPUT_EXCEEDS_AGGREGATE',
      'max_output_bytes cannot exceed max_aggregate_output_bytes',
      '/limits/max_output_bytes',
    ))
  }

  if (Array.isArray(plan.actions)) {
    if (plan.actions.length > plan.limits.max_actions) {
      errors.push(issue(
        'PLAN_ACTION_BUDGET_EXCEEDED',
        'exact action count exceeds limits.max_actions',
        '/actions',
      ))
    }
    const actionIds = new Set()
    const purposes = new Set()
    plan.actions.forEach((action, index) => {
      if (actionIds.has(action.action_id)) {
        errors.push(issue(
          'PLAN_ACTION_ID_DUPLICATE',
          'action_id values must be unique within a plan',
          `/actions/${index}/action_id`,
        ))
      }
      actionIds.add(action.action_id)
      purposes.add(action.purpose)
      if (canonicalByteLength(action.parameters) > plan.limits.max_input_bytes) {
        errors.push(issue(
          'PLAN_ACTION_INPUT_BUDGET_EXCEEDED',
          'canonical action parameters exceed limits.max_input_bytes',
          `/actions/${index}/parameters`,
        ))
      }
    })
    if (plan.target.kind === 'live') {
      for (const purpose of ['control', 'attack']) {
        if (!purposes.has(purpose)) {
          errors.push(issue(
            'PLAN_PROOF_ACTION_MISSING',
            `live exact actions must include a ${purpose} action`,
            '/actions',
            { purpose },
          ))
        }
      }
    }
  }

  if (plan.generator) {
    if (plan.generator.max_cases > plan.limits.max_actions) {
      errors.push(issue(
        'PLAN_GENERATOR_CASE_BUDGET_EXCEEDED',
        'generator.max_cases exceeds limits.max_actions',
        '/generator/max_cases',
      ))
    }
    if (plan.generator.max_case_bytes > plan.limits.max_input_bytes) {
      errors.push(issue(
        'PLAN_GENERATOR_INPUT_BUDGET_EXCEEDED',
        'generator.max_case_bytes exceeds limits.max_input_bytes',
        '/generator/max_case_bytes',
      ))
    }
  }

  if (plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED') {
    for (const flag of L3_PREFLIGHT_FLAGS) {
      if (plan.preflight?.[flag] !== true) {
        errors.push(issue(
          'PLAN_L3_PREFLIGHT_REQUIRED',
          `L3_MAXIMUM_AUTHORIZED requires preflight.${flag} to be true`,
          `/preflight/${flag}`,
          { flag },
        ))
      }
    }
    const envelope = plan.campaign_envelope
    if (envelope) {
      if (envelope.max_actions > plan.limits.max_actions) {
        errors.push(issue(
          'PLAN_L3_ACTION_BUDGET_EXCEEDED',
          'campaign_envelope.max_actions exceeds limits.max_actions',
          '/campaign_envelope/max_actions',
        ))
      }
      if (envelope.max_chain_depth > envelope.max_actions) {
        errors.push(issue(
          'PLAN_L3_CHAIN_DEPTH_EXCEEDED',
          'campaign_envelope.max_chain_depth cannot exceed its max_actions',
          '/campaign_envelope/max_chain_depth',
        ))
      }
      if (envelope.checkpoint_policy.interval_actions > envelope.max_actions) {
        errors.push(issue(
          'PLAN_L3_CHECKPOINT_INTERVAL_EXCEEDED',
          'checkpoint interval cannot exceed campaign_envelope.max_actions',
          '/campaign_envelope/checkpoint_policy/interval_actions',
        ))
      }
      if (Array.isArray(plan.actions) && plan.actions.length > envelope.max_actions) {
        errors.push(issue(
          'PLAN_L3_EXACT_ACTION_BUDGET_EXCEEDED',
          'exact L3 action count exceeds campaign_envelope.max_actions',
          '/actions',
        ))
      }
      if (plan.generator && plan.generator.max_cases > envelope.max_actions) {
        errors.push(issue(
          'PLAN_L3_GENERATOR_BUDGET_EXCEEDED',
          'L3 generator.max_cases exceeds campaign_envelope.max_actions',
          '/generator/max_cases',
        ))
      }
      const allowedOperations = new Set(envelope.allowed_operations)
      const allowedCategories = new Set(envelope.allowed_action_categories)
      const allowedStrategies = new Set(envelope.allowed_strategy_families)
      const sealedActions = Array.isArray(plan.actions)
        ? plan.actions
        : plan.generator
          ? [plan.generator.template]
          : []
      sealedActions.forEach((action, index) => {
        if (!allowedOperations.has(action.operation)) {
          errors.push(issue(
            'PLAN_L3_OPERATION_OUTSIDE_ENVELOPE',
            'sealed action operation is outside the L3 campaign envelope',
            `/actions/${index}/operation`,
          ))
        }
        if (!allowedCategories.has(action.action_category)) {
          errors.push(issue(
            'PLAN_L3_CATEGORY_OUTSIDE_ENVELOPE',
            'sealed action category is outside the L3 campaign envelope',
            `/actions/${index}/action_category`,
          ))
        }
      })
      const ruleIds = new Set()
      envelope.decision_rules.forEach((rule, index) => {
        if (ruleIds.has(rule.rule_id)) {
          errors.push(issue(
            'PLAN_L3_RULE_ID_DUPLICATE',
            'campaign decision rule identifiers must be unique',
            `/campaign_envelope/decision_rules/${index}/rule_id`,
          ))
        }
        ruleIds.add(rule.rule_id)
        for (const operation of rule.authorize.operations) {
          if (!allowedOperations.has(operation)) {
            errors.push(issue(
              'PLAN_L3_RULE_OPERATION_OUTSIDE_ENVELOPE',
              'decision rule operation is outside allowed_operations',
              `/campaign_envelope/decision_rules/${index}/authorize/operations`,
            ))
          }
        }
        for (const category of rule.authorize.action_categories) {
          if (!allowedCategories.has(category)) {
            errors.push(issue(
              'PLAN_L3_RULE_CATEGORY_OUTSIDE_ENVELOPE',
              'decision rule category is outside allowed_action_categories',
              `/campaign_envelope/decision_rules/${index}/authorize/action_categories`,
            ))
          }
        }
        for (const strategy of rule.authorize.strategy_families) {
          if (!allowedStrategies.has(strategy)) {
            errors.push(issue(
              'PLAN_L3_RULE_STRATEGY_OUTSIDE_ENVELOPE',
              'decision rule strategy family is outside allowed_strategy_families',
              `/campaign_envelope/decision_rules/${index}/authorize/strategy_families`,
            ))
          }
        }
      })
    }
  }
  return errors
}

function isCanonicalTimestamp(value) {
  if (typeof value !== 'string') return false
  const parsed = Date.parse(value)
  return !Number.isNaN(parsed) && new Date(parsed).toISOString() === value
}

function currentTime(now) {
  const value = now instanceof Date ? now.getTime() : Date.parse(now)
  if (!Number.isFinite(value)) throw new TypeError('now must be a valid timestamp')
  return value
}

function validationResult(resourceErrors, validateSchema, value, semanticValidator) {
  if (resourceErrors.length > 0) return { valid: false, errors: resourceErrors }
  if (!validateSchema(value)) {
    return { valid: false, errors: normalizeAjvErrors(validateSchema.errors) }
  }
  const semanticErrors = semanticValidator(value)
  return { valid: semanticErrors.length === 0, errors: semanticErrors }
}

export function validateAdversarialPlan(value) {
  return validationResult(
    validateResourceEnvelope(value, MAX_PLAN_BYTES, 'adversarial plan'),
    validatePlanSchema,
    value,
    planSemanticErrors,
  )
}

export function assertValidAdversarialPlan(value) {
  const result = validateAdversarialPlan(value)
  if (!result.valid) {
    throw contractError(
      'ADVERSARIAL_PLAN_INVALID',
      'adversarial plan violates its schema or bounded execution invariants',
      result.errors,
    )
  }
  return value
}

export function canonicalAdversarialPlan(plan) {
  assertValidAdversarialPlan(plan)
  return canonicalJson(plan)
}

export function digestAdversarialPlan(plan) {
  return sha256(Buffer.from(canonicalAdversarialPlan(plan), 'utf8'))
}

export const adversarialPlanDigest = digestAdversarialPlan

const TACTICAL_ACTION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{2,159}$/

function assertCanonicalJsonObject(value, code, label) {
  const errors = inspectJsonValue(value)
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || errors.length > 0
  ) {
    throw contractError(code, `${label} must be a plain canonical JSON object`, errors)
  }
}

export function digestAdversarialTacticalAction(action) {
  assertCanonicalJsonObject(
    action,
    'ADVERSARIAL_TACTICAL_ACTION_INVALID',
    'tactical action',
  )
  for (const field of [
    'action_id',
    'branch_id',
    'action_category',
    'operation',
    'strategy_family',
  ]) {
    if (typeof action[field] !== 'string' || !TACTICAL_ACTION_ID_PATTERN.test(action[field])) {
      throw contractError(
        'ADVERSARIAL_TACTICAL_ACTION_INVALID',
        `tactical action ${field} is invalid`,
      )
    }
  }
  if (!Number.isInteger(action.chain_depth) || action.chain_depth < 1) {
    throw contractError(
      'ADVERSARIAL_TACTICAL_ACTION_INVALID',
      'tactical action chain_depth must be a positive integer',
    )
  }
  if (
    action.parameters === null
    || typeof action.parameters !== 'object'
    || Array.isArray(action.parameters)
  ) {
    throw contractError(
      'ADVERSARIAL_TACTICAL_ACTION_INVALID',
      'tactical action parameters must be a canonical JSON object',
    )
  }
  return sha256(Buffer.from(canonicalJson(action), 'utf8'))
}

export function digestAdversarialCandidateFacts(candidateFacts) {
  assertCanonicalJsonObject(
    candidateFacts,
    'ADVERSARIAL_CANDIDATE_FACTS_INVALID',
    'controller-derived candidate facts',
  )
  return sha256(Buffer.from(canonicalJson(candidateFacts), 'utf8'))
}

export function evaluateL3RuntimePreflight({ plan, runtimePreflight }) {
  const reasons = []
  if (plan?.autonomy_profile !== 'L3_MAXIMUM_AUTHORIZED') {
    return { allowed: false, reasons: ['L3_PROFILE_REQUIRED'] }
  }
  for (const flag of L3_PREFLIGHT_FLAGS) {
    if (plan.preflight?.[flag] !== true) {
      reasons.push(`SEALED_PREFLIGHT_NOT_READY:${flag}`)
    }
    if (runtimePreflight?.[flag] !== true) {
      reasons.push(`RUNTIME_PREFLIGHT_NOT_READY:${flag}`)
    }
  }
  return { allowed: reasons.length === 0, reasons }
}

function jsonPointerValue(value, pointer) {
  const segments = pointer
    .slice(1)
    .split('/')
    .map((segment) => segment.replaceAll('~1', '/').replaceAll('~0', '~'))
  let current = value
  for (const segment of segments) {
    if (current === null || typeof current !== 'object' || !Object.hasOwn(current, segment)) {
      return undefined
    }
    current = current[segment]
  }
  return current
}

function sameJson(left, right) {
  if (left === undefined || right === undefined) return left === right
  return canonicalJson(left) === canonicalJson(right)
}

function conditionMatches(condition, plan, candidateContext) {
  const actual = condition.field.startsWith('/candidate/')
    ? jsonPointerValue({ candidate: candidateContext }, condition.field)
    : jsonPointerValue(plan, condition.field)
  if (actual === undefined) return false
  switch (condition.operator) {
    case 'equals':
      return sameJson(actual, condition.value)
    case 'not_equals':
      return !sameJson(actual, condition.value)
    case 'in':
      return Array.isArray(condition.value)
        && condition.value.some((candidate) => sameJson(actual, candidate))
    case 'not_in':
      return Array.isArray(condition.value)
        && !condition.value.some((candidate) => sameJson(actual, candidate))
    case 'less_than_or_equal':
      return typeof actual === 'number'
        && typeof condition.value === 'number'
        && actual <= condition.value
    case 'greater_than_or_equal':
      return typeof actual === 'number'
        && typeof condition.value === 'number'
        && actual >= condition.value
    default:
      return false
  }
}

function campaignRefusal(code, details = {}) {
  return { allowed: false, reasons: [code], ...details }
}

function scopeExpansionRefusal(code) {
  return campaignRefusal(code, {
    disposition: 'QUEUE_SCOPE_EXPANSION_REQUEST',
    campaign_may_continue: true,
  })
}

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
const CURRENT_AUTHORIZATION_FIELDS = Object.freeze([
  'authorization_id',
  'plan_sha256',
  'revoked',
  'scope_revision_sha256',
  'status',
  'stop_requested',
])
const CONTROLLER_AUTHORIZATION_FIELDS = Object.freeze([
  'action_sha256',
  'authorization_id',
  'candidate_facts_sha256',
  'effect_classification',
  'plan_sha256',
  'risk_class',
  'scope_revision_sha256',
  'status',
  'target',
])

function isExactJsonRecord(value, fields) {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || inspectJsonValue(value).length > 0
  ) return false
  const keys = Object.keys(value).sort()
  return keys.length === fields.length && keys.every((key, index) => key === fields[index])
}

function validateCurrentL3Authorization({
  plan,
  planSha256,
  authorizationReceipt,
  currentAuthorization,
  now,
}) {
  if (
    !isExactJsonRecord(authorizationReceipt, AUTHORIZATION_RECEIPT_FIELDS)
    || authorizationReceipt.schema_version !== '1.0.0'
    || authorizationReceipt.kind !== 'red-team-audit/adversarial-authorization-receipt'
    || authorizationReceipt.status !== 'CONTROLLER_VERIFIED'
    || authorizationReceipt.plan_sha256 !== planSha256
    || authorizationReceipt.engagement_id !== plan.engagement_id
    || authorizationReceipt.scope_revision_sha256 !== plan.scope_revision_sha256
    || authorizationReceipt.risk_class !== plan.risk_class
    || authorizationReceipt.autonomy_profile !== plan.autonomy_profile
    || !/^[a-f0-9]{64}$/.test(authorizationReceipt.authorization_sha256 ?? '')
    || !/^[a-f0-9]{64}$/.test(authorizationReceipt.target_sha256 ?? '')
    || !isCanonicalTimestamp(authorizationReceipt.declared_at)
    || !isCanonicalTimestamp(authorizationReceipt.expires_at)
  ) return campaignRefusal('VERIFIED_AUTHORIZATION_RECEIPT_REQUIRED')

  let at
  try {
    at = currentTime(now)
  } catch {
    return campaignRefusal('CURRENT_AUTHORIZATION_REQUIRED')
  }
  if (at >= Date.parse(authorizationReceipt.expires_at)) {
    return campaignRefusal('CURRENT_AUTHORIZATION_REQUIRED')
  }
  if (
    !isExactJsonRecord(currentAuthorization, CURRENT_AUTHORIZATION_FIELDS)
    || currentAuthorization.status !== 'CURRENT'
    || currentAuthorization.authorization_id !== authorizationReceipt.authorization_id
    || currentAuthorization.plan_sha256 !== planSha256
    || currentAuthorization.revoked !== false
    || currentAuthorization.scope_revision_sha256 !== plan.scope_revision_sha256
    || currentAuthorization.stop_requested !== false
  ) return campaignRefusal('CURRENT_AUTHORIZATION_REQUIRED')
  return null
}

function validateControllerAuthorization({
  plan,
  planSha256,
  actionSha256,
  candidateFactsSha256,
  authorizationReceipt,
  controllerAuthorization,
}) {
  if (!isExactJsonRecord(controllerAuthorization, CONTROLLER_AUTHORIZATION_FIELDS)) {
    return campaignRefusal('CONTROLLER_AUTHORIZATION_REQUIRED')
  }
  if (
    controllerAuthorization.status !== 'AUTHORIZED'
    || controllerAuthorization.plan_sha256 !== planSha256
    || controllerAuthorization.authorization_id !== authorizationReceipt.authorization_id
    || controllerAuthorization.scope_revision_sha256 !== plan.scope_revision_sha256
  ) return campaignRefusal('CONTROLLER_AUTHORIZATION_BINDING_MISMATCH')
  if (controllerAuthorization.action_sha256 !== actionSha256) {
    return campaignRefusal('CONTROLLER_ACTION_BINDING_MISMATCH')
  }
  if (controllerAuthorization.candidate_facts_sha256 !== candidateFactsSha256) {
    return campaignRefusal('CONTROLLER_CANDIDATE_FACTS_MISMATCH')
  }
  const target = controllerAuthorization.target
  if (
    !isExactJsonRecord(target, ['identity_sha256', 'kind', 'locator', 'target_id'])
    || target.kind !== plan.target.kind
    || !TACTICAL_ACTION_ID_PATTERN.test(target.target_id ?? '')
    || typeof target.locator !== 'string'
    || target.locator.length < 1
    || target.locator.length > 2048
    || /[\u0000-\u0020\u007f]/.test(target.locator)
    || !/^[a-f0-9]{64}$/.test(target.identity_sha256 ?? '')
  ) return campaignRefusal('CONTROLLER_TARGET_BINDING_INVALID')
  if (controllerAuthorization.risk_class !== plan.risk_class) {
    return campaignRefusal('CONTROLLER_RISK_CLASS_MISMATCH')
  }
  const classification = controllerAuthorization.effect_classification
  if (
    !isExactJsonRecord(classification, ['complete', 'effects'])
    || classification.complete !== true
    || !Array.isArray(classification.effects)
    || classification.effects.length > 64
    || new Set(classification.effects).size !== classification.effects.length
    || classification.effects.some((effect) =>
      typeof effect !== 'string' || !TACTICAL_ACTION_ID_PATTERN.test(effect))
  ) return campaignRefusal('CONTROLLER_EFFECT_CLASSIFICATION_REQUIRED')
  const prohibited = classification.effects
    .filter((effect) => L3_PROHIBITED_EFFECTS.includes(effect))
    .sort()
  if (prohibited.length > 0) {
    return campaignRefusal('PROHIBITED_EFFECT_CLASSIFIED', {
      prohibited_effects: prohibited,
    })
  }
  const effectRisk = evaluateAdversarialEffectRisk(
    plan.risk_class,
    classification.effects,
  )
  if (!effectRisk.valid) {
    return campaignRefusal(effectRisk.code, {
      ...(effectRisk.unknown_effects
        ? { unknown_effects: effectRisk.unknown_effects }
        : {}),
      ...(effectRisk.minimum_risk_class
        ? { minimum_risk_class: effectRisk.minimum_risk_class }
        : {}),
    })
  }
  return null
}

export function evaluateL3CampaignBoundary({
  plan,
  runtimePreflight,
  action,
  controllerCandidateContext,
  authorizationReceipt,
  currentAuthorization,
  controllerAuthorization,
  now,
  actionsUsed,
  resumeCount = 0,
  activeEscalationTriggers = [],
}) {
  assertValidAdversarialPlan(plan)
  const preflight = evaluateL3RuntimePreflight({ plan, runtimePreflight })
  if (!preflight.allowed) return preflight

  if (action === undefined) return campaignRefusal('CONTROLLER_ACTION_REQUIRED')
  if (controllerCandidateContext === undefined) {
    return campaignRefusal('CONTROLLER_CANDIDATE_FACTS_REQUIRED')
  }
  let actionSha256
  let candidateFactsSha256
  try {
    actionSha256 = digestAdversarialTacticalAction(action)
    candidateFactsSha256 = digestAdversarialCandidateFacts(controllerCandidateContext)
  } catch (error) {
    return campaignRefusal(error.code ?? 'CONTROLLER_INPUT_INVALID')
  }
  const planSha256 = digestAdversarialPlan(plan)
  const authorizationRefusal = validateCurrentL3Authorization({
    plan,
    planSha256,
    authorizationReceipt,
    currentAuthorization,
    now,
  })
  if (authorizationRefusal) return authorizationRefusal
  const controllerRefusal = validateControllerAuthorization({
    plan,
    planSha256,
    actionSha256,
    candidateFactsSha256,
    authorizationReceipt,
    controllerAuthorization,
  })
  if (controllerRefusal) return controllerRefusal

  const operation = action.operation
  const actionCategory = action.action_category
  const strategyFamily = action.strategy_family
  const candidateContext = controllerCandidateContext
  const chainDepth = action.chain_depth

  if (!Array.isArray(activeEscalationTriggers)) {
    return campaignRefusal('ESCALATION_TRIGGER_SET_INVALID')
  }
  if (activeEscalationTriggers.length > 0) {
    return campaignRefusal('MANDATORY_ESCALATION_ACTIVE', {
      active_escalation_triggers: [...activeEscalationTriggers],
    })
  }

  const envelope = plan.campaign_envelope
  if (inspectJsonValue(candidateContext).length > 0) {
    return campaignRefusal('CANDIDATE_CONTEXT_INVALID')
  }
  if (!Number.isInteger(actionsUsed) || actionsUsed < 0) {
    return campaignRefusal('ACTION_COUNT_INVALID')
  }
  if (!Number.isInteger(chainDepth) || chainDepth < 1) {
    return campaignRefusal('CHAIN_DEPTH_INVALID')
  }
  if (!Number.isInteger(resumeCount) || resumeCount < 0) {
    return campaignRefusal('RESUME_COUNT_INVALID')
  }
  if (resumeCount > envelope.checkpoint_policy.max_resume_count) {
    return campaignRefusal('CAMPAIGN_RESUME_BUDGET_EXHAUSTED')
  }
  if (actionsUsed >= envelope.max_actions) {
    return campaignRefusal('CAMPAIGN_ACTION_BUDGET_EXHAUSTED')
  }
  if (chainDepth > envelope.max_chain_depth) {
    return campaignRefusal('CAMPAIGN_CHAIN_DEPTH_EXCEEDED')
  }
  if (!envelope.allowed_operations.includes(operation)) {
    return scopeExpansionRefusal('OPERATION_OUTSIDE_CAMPAIGN_ENVELOPE')
  }
  if (!envelope.allowed_action_categories.includes(actionCategory)) {
    return scopeExpansionRefusal('ACTION_CATEGORY_OUTSIDE_CAMPAIGN_ENVELOPE')
  }
  if (!envelope.allowed_strategy_families.includes(strategyFamily)) {
    return scopeExpansionRefusal('STRATEGY_FAMILY_OUTSIDE_CAMPAIGN_ENVELOPE')
  }
  if (!envelope.applicability_conditions.every((condition) =>
    conditionMatches(condition, plan, candidateContext))) {
    return scopeExpansionRefusal('CAMPAIGN_NOT_APPLICABLE')
  }

  const decisionRule = envelope.decision_rules.find((rule) =>
    rule.when_all.every((condition) => conditionMatches(condition, plan, candidateContext))
    && rule.authorize.operations.includes(operation)
    && rule.authorize.action_categories.includes(actionCategory)
    && rule.authorize.strategy_families.includes(strategyFamily))
  if (!decisionRule) {
    return scopeExpansionRefusal('NO_CAMPAIGN_DECISION_RULE_AUTHORIZES_ACTION')
  }
  return {
    allowed: true,
    reasons: [],
    action_sha256: actionSha256,
    candidate_facts_sha256: candidateFactsSha256,
    resolved_target: structuredClone(controllerAuthorization.target),
    classified_effects: [...controllerAuthorization.effect_classification.effects],
    decision_rule_id: decisionRule.rule_id,
    remaining_actions: envelope.max_actions - actionsUsed - 1,
    max_chain_depth: envelope.max_chain_depth,
    checkpoint_due:
      (actionsUsed + 1) % envelope.checkpoint_policy.interval_actions === 0,
    resume_count: resumeCount,
  }
}
