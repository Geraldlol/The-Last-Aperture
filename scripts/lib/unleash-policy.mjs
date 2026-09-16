import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import Ajv2020 from 'ajv/dist/2020.js'

import { digestUnleashValue } from './unleash-contracts.mjs'

const POLICY_SCHEMA_URL = new URL('../../schemas/unleash-deployment-policy.schema.json', import.meta.url)
export const unleashDeploymentPolicySchema = JSON.parse(
  readFileSync(fileURLToPath(POLICY_SCHEMA_URL), 'utf8'),
)

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})
const validatePolicySchema = ajv.compile(unleashDeploymentPolicySchema)

const POLICY_FIELDS = [
  'schema_version',
  'kind',
  'policy_id',
  'valid_from',
  'valid_until',
  'allowed_origins',
  'allowed_target_families',
  'allowed_effects',
  'budgets',
  'detection',
  'credential_references',
  'revocation',
]
const LEGACY_POLICY_FIELDS = POLICY_FIELDS.filter((field) => field !== 'detection')
const DETECTION_FIELDS = [
  'noise_profile',
  'target_environment',
  'risk_tolerance',
  'confirmation_mode',
]
export const DEFAULT_UNLEASH_DETECTION_POLICY = Object.freeze({
  noise_profile: 'AUTO',
  target_environment: 'UNKNOWN',
  risk_tolerance: 'UNSPECIFIED',
  confirmation_mode: 'REQUIRED',
})
const TARGET_FIELDS = ['family', 'canonical_locator', 'target_id', 'supplied_sha256']
const ALLOWED_EFFECTS = new Set([
  'OBSERVE',
  'PROBE',
  'AUTHENTICATED_REQUEST',
  'MUTATE_REVERSIBLE',
  'EXECUTE_PROOF',
  'EXFILTRATE_CANARY',
  'PUBLISH_EVIDENCE',
])

export class UnleashPolicyError extends Error {
  constructor(code, message, details = []) {
    super(message)
    this.name = 'UnleashPolicyError'
    this.code = code
    this.details = details
  }
}

function fail(code, message, details = []) {
  throw new UnleashPolicyError(code, message, details)
}

function hasExactKeys(value, fields) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.keys(value).toSorted().join(',') === [...fields].toSorted().join(',')
}

function deeplyFrozenCopy(value) {
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

function canonicalTimestamp(value, label) {
  const milliseconds = Date.parse(value)
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    fail('UNLEASH_POLICY_TIME_INVALID', `${label} must be a canonical UTC millisecond timestamp`)
  }
  return milliseconds
}

function canonicalOrigin(value) {
  if (
    typeof value !== 'string'
    || value.length > 2048
    || value.includes('\\')
    || value.includes('*')
    || /[\u0000-\u0020\u007f]/u.test(value)
  ) fail('UNLEASH_POLICY_ORIGIN_INVALID', 'allowed origin must be one exact HTTPS origin')
  let url
  try { url = new URL(value) } catch {
    fail('UNLEASH_POLICY_ORIGIN_INVALID', 'allowed origin must be one exact HTTPS origin')
  }
  if (
    url.protocol !== 'https:'
    || url.hostname.length === 0
    || url.hostname.endsWith('.')
    || url.username.length > 0
    || url.password.length > 0
    || (url.pathname !== '/' && url.pathname !== '')
    || url.search.length > 0
    || url.hash.length > 0
  ) fail('UNLEASH_POLICY_ORIGIN_INVALID', 'allowed origin must be one credential-free HTTPS origin without path, query, or fragment')
  return url.origin
}

function normalizePolicy(value) {
  const legacy = hasExactKeys(value, LEGACY_POLICY_FIELDS)
  if (!legacy && !hasExactKeys(value, POLICY_FIELDS)) {
    fail('UNLEASH_POLICY_SCHEMA_INVALID', 'deployment policy contains missing or unknown fields')
  }
  const candidate = structuredClone(legacy
    ? { ...value, detection: DEFAULT_UNLEASH_DETECTION_POLICY }
    : value)
  if (!validatePolicySchema(candidate)) {
    fail('UNLEASH_POLICY_SCHEMA_INVALID', 'deployment policy violates its schema', validatePolicySchema.errors ?? [])
  }
  if (!hasExactKeys(candidate.budgets, [
    'max_actions', 'max_parallel_actions', 'max_duration_ms', 'max_response_bytes',
  ])) fail('UNLEASH_POLICY_BUDGET_INVALID', 'deployment policy budgets contain missing or unknown fields')
  if (!hasExactKeys(candidate.revocation, ['check_id', 'fail_mode'])) {
    fail('UNLEASH_POLICY_REVOCATION_INVALID', 'deployment policy revocation record contains missing or unknown fields')
  }
  if (!hasExactKeys(candidate.detection, DETECTION_FIELDS)) {
    fail('UNLEASH_POLICY_DETECTION_INVALID', 'deployment policy detection settings contain missing or unknown fields')
  }
  const validFrom = canonicalTimestamp(candidate.valid_from, 'valid_from')
  const validUntil = canonicalTimestamp(candidate.valid_until, 'valid_until')
  if (validFrom >= validUntil) {
    fail('UNLEASH_POLICY_TIME_INVALID', 'deployment policy validity window must be non-empty and increasing')
  }
  candidate.allowed_origins = candidate.allowed_origins.map(canonicalOrigin).toSorted()
  if (new Set(candidate.allowed_origins).size !== candidate.allowed_origins.length) {
    fail('UNLEASH_POLICY_ORIGIN_INVALID', 'allowed origins must remain unique after canonicalization')
  }
  candidate.allowed_target_families = [...candidate.allowed_target_families].toSorted()
  candidate.allowed_effects = [...candidate.allowed_effects].toSorted()
  candidate.credential_references = [...candidate.credential_references].toSorted()
  return candidate
}

export function createUnleashDeploymentPolicy(value) {
  return deeplyFrozenCopy(normalizePolicy(value))
}

function assertCreatedPolicy(value) {
  const normalized = normalizePolicy(value)
  const expected = JSON.stringify(normalized)
  if (JSON.stringify(value) !== expected) {
    fail('UNLEASH_POLICY_NOT_CANONICAL', 'deployment policy must use its canonical frozen representation')
  }
  return value
}

export function selectUnleashDetectionProfile(policy) {
  assertCreatedPolicy(policy)
  const configured = policy.detection.noise_profile
  if (configured !== 'AUTO') {
    return deeplyFrozenCopy({
      configured_profile: configured,
      operational_profile: configured.toLowerCase(),
      selection_reason: 'CONTROLLER_POLICY_EXPLICIT',
    })
  }
  const aggressive = policy.detection.target_environment === 'LAB'
    && policy.detection.risk_tolerance === 'HIGH'
  const cautious = policy.detection.target_environment === 'PRODUCTION'
    || policy.detection.risk_tolerance === 'LOW'
  return deeplyFrozenCopy({
    configured_profile: 'AUTO',
    operational_profile: aggressive ? 'aggressive' : cautious ? 'cautious' : 'balanced',
    selection_reason: aggressive
      ? 'AUTO_LAB_HIGH_TOLERANCE'
      : cautious
        ? 'AUTO_PRODUCTION_OR_LOW_TOLERANCE'
        : policy.detection.target_environment === 'UNKNOWN'
          ? 'AUTO_UNKNOWN_POSTURE_BALANCED'
          : 'AUTO_PRE_PRODUCTION_MODERATE_TOLERANCE',
  })
}

export function resolveUnleashDetectionPolicyBinding(policy, policySha256) {
  assertCreatedPolicy(policy)
  if (typeof policySha256 !== 'string' || !/^[a-f0-9]{64}$/u.test(policySha256)) {
    fail('UNLEASH_POLICY_BINDING_INVALID', 'retained policy digest must be one SHA-256 value')
  }
  const fullPolicySha256 = digestUnleashValue(policy)
  if (policySha256 === fullPolicySha256) {
    return deeplyFrozenCopy({
      binding: 'DETECTION_POLICY_BOUND',
      policy_sha256: policySha256,
      detection: policy.detection,
      selection: selectUnleashDetectionProfile(policy),
    })
  }
  const { detection: ignoredDetection, ...legacyPolicy } = policy
  const legacyPolicySha256 = digestUnleashValue(legacyPolicy)
  if (policySha256 !== legacyPolicySha256) {
    fail('UNLEASH_POLICY_PLAN_DRIFT', 'deployment policy no longer matches the retained campaign plan')
  }
  const automaticPolicy = createUnleashDeploymentPolicy({
    ...legacyPolicy,
    detection: DEFAULT_UNLEASH_DETECTION_POLICY,
  })
  return deeplyFrozenCopy({
    binding: 'LEGACY_POLICY_DEFAULTED',
    policy_sha256: policySha256,
    detection: DEFAULT_UNLEASH_DETECTION_POLICY,
    selection: selectUnleashDetectionProfile(automaticPolicy),
  })
}

function canonicalTarget(value) {
  if (!hasExactKeys(value, TARGET_FIELDS)) {
    fail('UNLEASH_POLICY_TARGET_INVALID', 'target contains missing or controller-owned policy fields')
  }
  if (
    value.family !== 'https'
    || typeof value.canonical_locator !== 'string'
    || typeof value.target_id !== 'string'
    || typeof value.supplied_sha256 !== 'string'
  ) fail('UNLEASH_POLICY_TARGET_INVALID', 'target identity is invalid')
  let url
  try { url = new URL(value.canonical_locator) } catch {
    fail('UNLEASH_POLICY_TARGET_INVALID', 'target locator is invalid')
  }
  if (
    url.protocol !== 'https:'
    || url.username.length > 0
    || url.password.length > 0
    || url.search.length > 0
    || url.hash.length > 0
    || url.href !== value.canonical_locator
    || url.hostname.endsWith('.')
  ) fail('UNLEASH_POLICY_TARGET_INVALID', 'target locator is not canonical HTTPS')
  const expectedTargetId = `target:sha256:${digestUnleashValue({
    canonical_locator: value.canonical_locator,
    family: value.family,
  })}`
  if (value.target_id !== expectedTargetId || !/^[a-f0-9]{64}$/u.test(value.supplied_sha256)) {
    fail('UNLEASH_POLICY_TARGET_INVALID', 'target digest does not bind the canonical locator')
  }
  return { target: value, origin: url.origin }
}

function admissionTime(value) {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    fail('UNLEASH_POLICY_TIME_INVALID', 'policy admission requires a valid current Date')
  }
  return value.getTime()
}

export function assertPolicyAllowsTarget(policy, targetValue, {
  now,
  isRevoked,
  effect,
} = {}) {
  assertCreatedPolicy(policy)
  const { target, origin } = canonicalTarget(targetValue)
  const current = admissionTime(now)
  if (current < Date.parse(policy.valid_from) || current >= Date.parse(policy.valid_until)) {
    fail('UNLEASH_POLICY_NOT_CURRENT', 'deployment policy is not current at action admission')
  }
  if (!policy.allowed_target_families.includes(target.family)) {
    fail('UNLEASH_POLICY_TARGET_BLOCKED', `target family ${target.family} is not allowed by deployment policy`)
  }
  if (!policy.allowed_origins.includes(origin)) {
    fail('UNLEASH_POLICY_TARGET_BLOCKED', `target origin ${origin} is not allowed by deployment policy`)
  }
  if (typeof effect !== 'string' || !ALLOWED_EFFECTS.has(effect)) {
    fail('UNLEASH_POLICY_EFFECT_INVALID', 'action admission requires one recognized effect')
  }
  if (!policy.allowed_effects.includes(effect)) {
    fail('UNLEASH_POLICY_EFFECT_BLOCKED', `effect ${effect} is not allowed by deployment policy`)
  }
  if (typeof isRevoked !== 'function') {
    fail('UNLEASH_POLICY_REVOCATION_UNAVAILABLE', 'fail-closed revocation checker is required for every admission')
  }
  let revoked
  try {
    revoked = isRevoked(Object.freeze({
      check_id: policy.revocation.check_id,
      policy_id: policy.policy_id,
      target_id: target.target_id,
      checked_at: now.toISOString(),
    }))
  } catch (cause) {
    fail('UNLEASH_POLICY_REVOCATION_UNAVAILABLE', `revocation check failed closed: ${cause?.message ?? 'unknown error'}`)
  }
  if (typeof revoked !== 'boolean') {
    fail('UNLEASH_POLICY_REVOCATION_UNAVAILABLE', 'revocation checker must return one boolean result')
  }
  if (revoked) fail('UNLEASH_POLICY_REVOKED', 'deployment policy has been revoked')
  return targetValue
}

export function projectUnleashPolicy(policy) {
  assertCreatedPolicy(policy)
  return deeplyFrozenCopy({
    ...structuredClone(policy),
    policy_sha256: digestUnleashValue(policy),
  })
}
