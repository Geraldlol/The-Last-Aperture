import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import {
  assertValidAdversarialPlan,
  digestAdversarialPlan,
} from './adversarial-validation-contracts.mjs'
import { stableJson } from './run-engine.mjs'

const SCOPE_SCHEMA_URL = new URL(
  '../../schemas/adversarial-current-scope.schema.json',
  import.meta.url,
)
const MAX_SCOPE_BYTES = 1024 * 1024

export const adversarialCurrentScopeSchema = JSON.parse(
  readFileSync(fileURLToPath(SCOPE_SCHEMA_URL), 'utf8'),
)

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})
const validateScopeSchema = ajv.compile(adversarialCurrentScopeSchema)

export class AdversarialCliContractError extends Error {
  constructor(code, message, details = [], options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'AdversarialCliContractError'
    this.code = code
    this.details = details
  }
}

function fail(code, message, details = [], options = {}) {
  throw new AdversarialCliContractError(code, message, details, options)
}

function canonicalJson(value) {
  const rendered = stableJson(value, 0)
  return rendered.endsWith('\n') ? rendered.slice(0, -1) : rendered
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function jsonEnvelopeErrors(root) {
  const errors = []
  const active = new WeakSet()
  const stack = [{ value: root, path: '/', depth: 0 }]
  let nodes = 0
  while (stack.length > 0) {
    const { value, path, depth, exit } = stack.pop()
    if (exit) {
      active.delete(value)
      continue
    }
    nodes += 1
    if (nodes > 20_000 || depth > 32) {
      errors.push({ code: 'JSON_LIMIT', instancePath: path, message: 'JSON depth or node limit exceeded' })
      break
    }
    if (value === null || typeof value === 'string' || typeof value === 'boolean') continue
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) errors.push({ code: 'JSON_NUMBER', instancePath: path, message: 'number must be finite' })
      continue
    }
    if (typeof value !== 'object') {
      errors.push({ code: 'JSON_TYPE', instancePath: path, message: 'value is not JSON data' })
      continue
    }
    if (active.has(value)) {
      errors.push({ code: 'JSON_CYCLE', instancePath: path, message: 'cyclic value is not JSON data' })
      continue
    }
    active.add(value)
    stack.push({ value, path, depth, exit: true })
    const isArray = Array.isArray(value)
    const prototype = Object.getPrototypeOf(value)
    if ((isArray && prototype !== Array.prototype)
      || (!isArray && prototype !== Object.prototype && prototype !== null)) {
      errors.push({ code: 'JSON_PROTOTYPE', instancePath: path, message: 'only ordinary JSON objects and arrays are accepted' })
      continue
    }
    if (isArray) {
      const keys = Object.keys(value)
      if (
        keys.length !== value.length
        || keys.some((key) => !/^(?:0|[1-9]\d*)$/.test(key) || Number(key) >= value.length)
      ) {
        errors.push({ code: 'JSON_ARRAY_SHAPE', instancePath: path, message: 'arrays cannot contain holes or named properties' })
      }
    }
    if (Object.getOwnPropertySymbols(value).length > 0) {
      errors.push({ code: 'JSON_SYMBOL', instancePath: path, message: 'symbol properties are not JSON data' })
    }
    for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
      if (isArray && key === 'length') continue
      const childPath = path === '/' ? `/${key}` : `${path}/${key}`
      if (!descriptor.enumerable || 'get' in descriptor || 'set' in descriptor) {
        errors.push({ code: 'JSON_PROPERTY', instancePath: childPath, message: 'only enumerable data properties are accepted' })
        continue
      }
      stack.push({ value: descriptor.value, path: childPath, depth: depth + 1 })
    }
  }
  if (errors.length === 0) {
    try {
      if (Buffer.byteLength(canonicalJson(root), 'utf8') > MAX_SCOPE_BYTES) {
        errors.push({ code: 'DOCUMENT_SIZE_LIMIT', instancePath: '/', message: 'scope exceeds its canonical byte limit' })
      }
    } catch (error) {
      errors.push({ code: 'CANONICAL_JSON_INVALID', instancePath: '/', message: error.message })
    }
  }
  return errors
}

function normalizeAjvErrors(errors = []) {
  return errors.map((error) => ({
    code: `SCHEMA_${String(error.keyword).toUpperCase()}`,
    instancePath: error.instancePath || '/',
    message: error.message ?? 'schema validation failed',
    params: error.params,
  }))
}

function canonicalTimestamp(value) {
  if (typeof value !== 'string') return false
  const parsed = Date.parse(value)
  return !Number.isNaN(parsed) && new Date(parsed).toISOString() === value
}

function scopeSemanticErrors(scope) {
  const errors = []
  if (!canonicalTimestamp(scope.validity.not_before)) {
    errors.push({ code: 'SCOPE_NOT_BEFORE_INVALID', instancePath: '/validity/not_before', message: 'not_before must be canonical UTC' })
  }
  if (!canonicalTimestamp(scope.validity.not_after)) {
    errors.push({ code: 'SCOPE_NOT_AFTER_INVALID', instancePath: '/validity/not_after', message: 'not_after must be canonical UTC' })
  }
  if (errors.length === 0 && Date.parse(scope.validity.not_before) >= Date.parse(scope.validity.not_after)) {
    errors.push({ code: 'SCOPE_WINDOW_INVALID', instancePath: '/validity', message: 'not_after must be later than not_before' })
  }
  const targetIds = new Set()
  for (const [index, target] of scope.targets.entries()) {
    if (targetIds.has(target.target_id)) {
      errors.push({ code: 'SCOPE_TARGET_ID_DUPLICATE', instancePath: `/targets/${index}/target_id`, message: 'target_id values must be unique' })
    }
    targetIds.add(target.target_id)
    if (target.kind === 'repository' && !target.locator.startsWith('repository://')) {
      errors.push({
        code: 'SCOPE_REPOSITORY_LOCATOR_INVALID',
        instancePath: `/targets/${index}/locator`,
        message: 'repository targets require a repository:// locator',
      })
    }
    if (target.kind === 'local_service') {
      let url
      try {
        url = new URL(target.locator)
      } catch {
        url = null
      }
      if (
        !url
        || !['http:', 'https:'].includes(url.protocol)
        || !['127.0.0.1', '[::1]'].includes(url.hostname)
        || url.username !== ''
        || url.password !== ''
      ) {
        errors.push({
          code: 'SCOPE_LOCAL_SERVICE_LOCATOR_INVALID',
          instancePath: `/targets/${index}/locator`,
          message: 'local-service targets require a literal loopback HTTP(S) locator without credentials',
        })
      }
    }
    if (target.kind === 'live') {
      let url
      try {
        url = new URL(target.locator)
      } catch {
        url = null
      }
      if (
        !url
        || !['http:', 'https:'].includes(url.protocol)
        || url.hostname.length === 0
        || url.username !== ''
        || url.password !== ''
      ) {
        errors.push({
          code: 'SCOPE_LIVE_LOCATOR_INVALID',
          instancePath: `/targets/${index}/locator`,
          message: 'live targets require an absolute HTTP(S) locator without embedded credentials',
        })
      }
    }
  }
  return errors
}

export function validateAdversarialCurrentScope(value) {
  const envelopeErrors = jsonEnvelopeErrors(value)
  if (envelopeErrors.length > 0) return { valid: false, errors: envelopeErrors }
  if (!validateScopeSchema(value)) {
    return { valid: false, errors: normalizeAjvErrors(validateScopeSchema.errors) }
  }
  const errors = scopeSemanticErrors(value)
  return { valid: errors.length === 0, errors }
}

export function assertValidAdversarialCurrentScope(value) {
  const result = validateAdversarialCurrentScope(value)
  if (!result.valid) {
    fail(
      'ADVERSARIAL_CURRENT_SCOPE_INVALID',
      'current adversarial scope violates its schema or validity invariants',
      result.errors,
    )
  }
  return value
}

export function canonicalAdversarialCurrentScope(scope) {
  assertValidAdversarialCurrentScope(scope)
  return canonicalJson(scope)
}

export function digestAdversarialCurrentScope(scope) {
  return sha256(Buffer.from(canonicalAdversarialCurrentScope(scope), 'utf8'))
}

function cloneCanonical(value) {
  return JSON.parse(canonicalJson(value))
}

export function sealAdversarialPlan({ draft, currentScope } = {}) {
  assertValidAdversarialCurrentScope(currentScope)
  if (draft === null || typeof draft !== 'object' || Array.isArray(draft)) {
    fail('ADVERSARIAL_PLAN_DRAFT_INVALID', 'plan draft must be a JSON object')
  }
  const draftErrors = jsonEnvelopeErrors(draft)
  if (draftErrors.length > 0) {
    fail('ADVERSARIAL_PLAN_DRAFT_INVALID', 'plan draft must contain only canonical JSON data', draftErrors)
  }
  for (const derived of ['schema_version', 'kind', 'scope_revision_sha256']) {
    if (Object.hasOwn(draft, derived)) {
      fail('ADVERSARIAL_PLAN_DRAFT_DERIVED_FIELD', `plan draft must omit derived field ${derived}`)
    }
  }
  const plan = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-plan',
    ...cloneCanonical(draft),
    scope_revision_sha256: digestAdversarialCurrentScope(currentScope),
  }
  assertValidAdversarialPlan(plan)
  if (plan.engagement_id !== currentScope.engagement_id) {
    fail('ADVERSARIAL_ENGAGEMENT_MISMATCH', 'plan and current scope must name the same engagement')
  }
  const reasons = outsideScopeReasons(plan, currentScope)
  if (reasons.length > 0) {
    fail(
      'ADVERSARIAL_PLAN_OUTSIDE_CURRENT_SCOPE',
      'plan draft requests authority outside the current scope',
      reasons,
    )
  }
  return plan
}

function equalJson(left, right) {
  return canonicalJson(left) === canonicalJson(right)
}

function outsideScopeReasons(plan, scope) {
  const reasons = []
  if (plan.engagement_id !== scope.engagement_id) reasons.push('ENGAGEMENT_NOT_AUTHORIZED')
  if (!scope.targets.some((target) => equalJson(target, plan.target))) reasons.push('TARGET_NOT_AUTHORIZED')
  if (!scope.allowed_risk_classes.includes(plan.risk_class)) reasons.push('RISK_CLASS_NOT_AUTHORIZED')
  if (!scope.allowed_autonomy_profiles.includes(plan.autonomy_profile)) reasons.push('AUTONOMY_PROFILE_NOT_AUTHORIZED')
  if (!scope.allowed_strategy_ids.includes(plan.strategy_id)) reasons.push('STRATEGY_NOT_AUTHORIZED')

  const actionShapes = Array.isArray(plan.actions)
    ? plan.actions
    : plan.generator
      ? [plan.generator.template]
      : []
  for (const action of actionShapes) {
    if (!scope.allowed_operations.includes(action.operation)) reasons.push('OPERATION_NOT_AUTHORIZED')
    if (!scope.allowed_action_categories.includes(action.action_category)) reasons.push('ACTION_CATEGORY_NOT_AUTHORIZED')
  }
  if (plan.campaign_envelope) {
    for (const operation of plan.campaign_envelope.allowed_operations) {
      if (!scope.allowed_operations.includes(operation)) reasons.push('CAMPAIGN_OPERATION_NOT_AUTHORIZED')
    }
    for (const category of plan.campaign_envelope.allowed_action_categories) {
      if (!scope.allowed_action_categories.includes(category)) reasons.push('CAMPAIGN_CATEGORY_NOT_AUTHORIZED')
    }
    for (const strategy of plan.campaign_envelope.allowed_strategy_families) {
      if (!scope.allowed_strategy_families.includes(strategy)) reasons.push('CAMPAIGN_STRATEGY_FAMILY_NOT_AUTHORIZED')
    }
  }
  return [...new Set(reasons)]
}

export function assertPlanWithinCurrentScope({ plan, currentScope, now = new Date() } = {}) {
  assertValidAdversarialPlan(plan)
  assertValidAdversarialCurrentScope(currentScope)
  if (plan.scope_revision_sha256 !== digestAdversarialCurrentScope(currentScope)) {
    fail(
      'ADVERSARIAL_SCOPE_BINDING_MISMATCH',
      'plan does not bind the exact current scope document',
    )
  }
  const currentTime = new Date(now)
  if (Number.isNaN(currentTime.valueOf())) {
    fail('ADVERSARIAL_CURRENT_SCOPE_TIME_INVALID', 'scope authorization requires a real current time')
  }
  if (currentTime < new Date(currentScope.validity.not_before)) {
    fail('ADVERSARIAL_CURRENT_SCOPE_NOT_YET_VALID', 'current scope is not yet valid')
  }
  if (currentTime >= new Date(currentScope.validity.not_after)) {
    fail('ADVERSARIAL_CURRENT_SCOPE_EXPIRED', 'current scope has expired')
  }
  const reasons = outsideScopeReasons(plan, currentScope)
  if (reasons.length > 0) {
    fail(
      'ADVERSARIAL_PLAN_OUTSIDE_CURRENT_SCOPE',
      'plan requests authority outside the current scope',
      reasons,
    )
  }
  return Object.freeze({
    status: 'CURRENT_SCOPE_AUTHORIZED',
    scope_id: currentScope.scope_id,
    scope_revision_sha256: plan.scope_revision_sha256,
    engagement_id: plan.engagement_id,
    plan_sha256: digestAdversarialPlan(plan),
  })
}

export function inspectAdversarialPlan({ plan, currentScope } = {}) {
  assertValidAdversarialPlan(plan)
  const inspection = {
    valid: true,
    plan_sha256: digestAdversarialPlan(plan),
    plan_id: plan.plan_id,
    engagement_id: plan.engagement_id,
    scope_revision_sha256: plan.scope_revision_sha256,
    target: cloneCanonical(plan.target),
    risk_class: plan.risk_class,
    autonomy_profile: plan.autonomy_profile,
    strategy_id: plan.strategy_id,
    action_count: Array.isArray(plan.actions) ? plan.actions.length : plan.generator?.max_cases ?? 0,
    execution_shape: Array.isArray(plan.actions) ? 'EXACT_ACTIONS' : plan.generator ? 'DETERMINISTIC_GENERATOR' : 'ADAPTIVE_L3',
  }
  if (currentScope !== undefined) {
    assertValidAdversarialCurrentScope(currentScope)
    inspection.scope_binding = plan.scope_revision_sha256 === digestAdversarialCurrentScope(currentScope)
      ? 'CURRENT_SCOPE_MATCH'
      : 'CURRENT_SCOPE_MISMATCH'
    inspection.scope_authority = outsideScopeReasons(plan, currentScope).length === 0
      ? 'WITHIN_CURRENT_SCOPE'
      : 'OUTSIDE_CURRENT_SCOPE'
  }
  return Object.freeze(inspection)
}
