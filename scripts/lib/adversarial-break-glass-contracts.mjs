import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as signBytes,
  verify as verifyBytes,
} from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import {
  L3_PREFLIGHT_FLAGS,
  L3_NON_OVERRIDABLE_PREFLIGHT_FLAGS,
  assertValidAdversarialPlan,
  digestAdversarialPlan,
} from './adversarial-validation-contracts.mjs'
import { OPERATOR_AUTHORITY_BASIS } from './operator-authorization.mjs'
import { stableJson } from './run-engine.mjs'

const SCHEMA_URL = new URL('../../schemas/adversarial-break-glass.schema.json', import.meta.url)
const SIGNATURE_CONTEXT = Buffer.from('red-team-audit/adversarial-break-glass/v1\0', 'utf8')
const NONCE_CONTEXT = Buffer.from('red-team-audit/adversarial-break-glass-nonce/v1\0', 'utf8')
const MAX_DOCUMENT_BYTES = 64 * 1024
const MAX_WINDOW_MS = 15 * 60 * 1000

export const BREAK_GLASS_NON_OVERRIDABLE_PREFLIGHT_FLAGS =
  L3_NON_OVERRIDABLE_PREFLIGHT_FLAGS

export const BREAK_GLASS_WAIVABLE_PREFLIGHT_FLAGS = Object.freeze([
  'target_health_monitoring',
  'cleanup_or_rollback',
])

const BREAK_GLASS_LIMIT_REDUCTION_DIVISOR = 4
const BREAK_GLASS_MAX_ACTIONS = 10
const BREAK_GLASS_MAX_WALL_TIME_MS = 5 * 60 * 1000
const BREAK_GLASS_MAX_AGGREGATE_OUTPUT_BYTES = 1024 * 1024

export const adversarialBreakGlassSchema = JSON.parse(
  readFileSync(fileURLToPath(SCHEMA_URL), 'utf8'),
)

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})
const validateSchema = ajv.compile(adversarialBreakGlassSchema)

export class AdversarialBreakGlassContractError extends Error {
  constructor(code, message, details = [], options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'AdversarialBreakGlassContractError'
    this.code = code
    this.details = details
  }
}

function fail(code, message, details = [], options = {}) {
  throw new AdversarialBreakGlassContractError(code, message, details, options)
}

function canonicalJson(value) {
  const rendered = stableJson(value, 0)
  return rendered.endsWith('\n') ? rendered.slice(0, -1) : rendered
}

function digestBytes(value) {
  return createHash('sha256').update(value).digest('hex')
}

function digestJson(value) {
  return digestBytes(Buffer.from(canonicalJson(value), 'utf8'))
}

function withoutSignature(value) {
  const { signature: _signature, ...unsigned } = value
  return unsigned
}

function signingBytes(value) {
  return Buffer.concat([
    SIGNATURE_CONTEXT,
    Buffer.from(canonicalJson(withoutSignature(value)), 'utf8'),
  ])
}

function canonicalTimestamp(value, label) {
  const parsed = value instanceof Date ? new Date(value.valueOf()) : new Date(value)
  if (Number.isNaN(parsed.valueOf())) {
    fail('BREAK_GLASS_TIME_INVALID', `${label} must be a real timestamp`)
  }
  return parsed.toISOString()
}

function isCanonicalTimestamp(value) {
  if (typeof value !== 'string') return false
  const parsed = Date.parse(value)
  return !Number.isNaN(parsed) && new Date(parsed).toISOString() === value
}

function asPrivateKey(value) {
  let key
  try {
    key = value?.type === 'private' ? value : createPrivateKey(value)
  } catch (cause) {
    fail('BREAK_GLASS_PRIVATE_KEY_INVALID', 'break-glass signing key is invalid', [], { cause })
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    fail('BREAK_GLASS_KEY_TYPE_INVALID', 'break-glass signing key must be Ed25519')
  }
  return key
}

function asPublicKey(value) {
  let key
  try {
    key = value?.type === 'public' ? value : createPublicKey(value)
  } catch (cause) {
    fail('BREAK_GLASS_PUBLIC_KEY_INVALID', 'pinned break-glass public key is invalid', [], { cause })
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    fail('BREAK_GLASS_KEY_TYPE_INVALID', 'pinned break-glass key must be Ed25519')
  }
  return key
}

function keyIdentity(publicKey) {
  const spki = publicKey.export({ type: 'spki', format: 'der' })
  return `ed25519:${digestBytes(spki)}`
}

function normalizeAjvErrors(errors = []) {
  return errors.map((error) => ({
    keyword: error.keyword,
    instancePath: error.instancePath || '/',
    message: error.message ?? 'schema validation failed',
    params: error.params,
  }))
}

function inspectJsonValue(root) {
  const errors = []
  const active = new WeakSet()
  const stack = [{ value: root, path: '/', depth: 0, exit: false }]
  let nodes = 0
  while (stack.length > 0) {
    const item = stack.pop()
    if (item.exit) {
      active.delete(item.value)
      continue
    }
    const { value, path, depth } = item
    nodes += 1
    if (nodes > 20_000 || depth > 32) {
      errors.push({ code: 'BREAK_GLASS_JSON_LIMIT', message: 'JSON depth or node limit exceeded', instancePath: path })
      continue
    }
    if (value === null || typeof value === 'string' || typeof value === 'boolean') continue
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) {
        errors.push({ code: 'BREAK_GLASS_JSON_NUMBER_INVALID', message: 'JSON numbers must be finite', instancePath: path })
      }
      continue
    }
    if (typeof value !== 'object') {
      errors.push({ code: 'BREAK_GLASS_JSON_TYPE_INVALID', message: 'non-JSON value', instancePath: path })
      continue
    }
    if (active.has(value)) {
      errors.push({ code: 'BREAK_GLASS_JSON_CYCLE', message: 'cyclic JSON value', instancePath: path })
      continue
    }
    active.add(value)
    stack.push({ value, path, depth, exit: true })
    const isArray = Array.isArray(value)
    const prototype = Object.getPrototypeOf(value)
    if ((isArray && prototype !== Array.prototype)
      || (!isArray && prototype !== Object.prototype && prototype !== null)) {
      errors.push({ code: 'BREAK_GLASS_JSON_PROTOTYPE_INVALID', message: 'only plain JSON containers are accepted', instancePath: path })
      continue
    }
    if (Object.getOwnPropertySymbols(value).length > 0) {
      errors.push({ code: 'BREAK_GLASS_JSON_SYMBOL_INVALID', message: 'symbol-keyed data is not canonical JSON', instancePath: path })
    }
    const keys = Object.keys(value)
    if (isArray) {
      if (keys.length !== value.length || keys.some((key) => !/^(?:0|[1-9]\d*)$/.test(key))) {
        errors.push({ code: 'BREAK_GLASS_JSON_ARRAY_INVALID', message: 'arrays cannot contain holes or named properties', instancePath: path })
      }
    }
    const descriptors = Object.getOwnPropertyDescriptors(value)
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (isArray && key === 'length') continue
      if (!descriptor.enumerable || 'get' in descriptor || 'set' in descriptor) {
        errors.push({ code: 'BREAK_GLASS_JSON_PROPERTY_INVALID', message: 'hidden and accessor properties are forbidden', instancePath: `${path}/${key}` })
        continue
      }
      stack.push({ value: descriptor.value, path: `${path}/${key}`, depth: depth + 1, exit: false })
    }
  }
  return errors
}

function semanticErrors(value) {
  const errors = []
  const add = (code, message, instancePath) => errors.push({ code, message, instancePath })
  if (!isCanonicalTimestamp(value.issued_at)) {
    add('BREAK_GLASS_ISSUED_AT_INVALID', 'issued_at must be a real canonical UTC timestamp', '/issued_at')
  }
  if (!isCanonicalTimestamp(value.expires_at)) {
    add('BREAK_GLASS_EXPIRES_AT_INVALID', 'expires_at must be a real canonical UTC timestamp', '/expires_at')
  }
  if (isCanonicalTimestamp(value.issued_at) && isCanonicalTimestamp(value.expires_at)) {
    const windowMs = Date.parse(value.expires_at) - Date.parse(value.issued_at)
    if (windowMs <= 0) {
      add('BREAK_GLASS_WINDOW_INVALID', 'expires_at must be later than issued_at', '/expires_at')
    } else if (windowMs > MAX_WINDOW_MS) {
      add('BREAK_GLASS_WINDOW_TOO_LONG', 'break-glass validity cannot exceed 15 minutes', '/expires_at')
    }
  }
  const failed = value.failed_controls?.map((entry) => entry.control) ?? []
  const waived = value.waived_controls ?? []
  if (new Set(failed).size !== failed.length) {
    add('BREAK_GLASS_CONTROL_DUPLICATE', 'failed controls must be unique', '/failed_controls')
  }
  const sortedFailed = [...failed].sort()
  const sortedWaived = [...waived].sort()
  if (canonicalJson(sortedFailed) !== canonicalJson(sortedWaived)) {
    add(
      'BREAK_GLASS_CONTROL_DISCLOSURE_MISMATCH',
      'waived_controls must exactly equal the disclosed failed_controls',
      '/waived_controls',
    )
  }
  if (canonicalJson(waived) !== canonicalJson(sortedWaived)) {
    add('BREAK_GLASS_CONTROL_ORDER_INVALID', 'waived_controls must be sorted canonically', '/waived_controls')
  }
  if (typeof value.signature === 'string') {
    const decoded = Buffer.from(value.signature, 'base64')
    if (decoded.length !== 64 || decoded.toString('base64') !== value.signature) {
      add('BREAK_GLASS_SIGNATURE_ENCODING_INVALID', 'signature must be canonical Ed25519 base64', '/signature')
    }
  }
  return errors
}

export function validateAdversarialBreakGlassOverride(value) {
  const jsonErrors = inspectJsonValue(value)
  if (jsonErrors.length > 0) return { valid: false, errors: jsonErrors }
  let bytes = Number.POSITIVE_INFINITY
  try {
    bytes = Buffer.byteLength(canonicalJson(value), 'utf8')
  } catch (error) {
    return {
      valid: false,
      errors: [{ code: 'BREAK_GLASS_CANONICAL_JSON_INVALID', message: error.message, instancePath: '/' }],
    }
  }
  if (bytes > MAX_DOCUMENT_BYTES) {
    return {
      valid: false,
      errors: [{
        code: 'BREAK_GLASS_DOCUMENT_TOO_LARGE',
        message: `break-glass document exceeds ${MAX_DOCUMENT_BYTES} bytes`,
        instancePath: '/',
      }],
    }
  }
  if (!validateSchema(value)) {
    return { valid: false, errors: normalizeAjvErrors(validateSchema.errors) }
  }
  const errors = semanticErrors(value)
  return { valid: errors.length === 0, errors }
}

export function assertValidAdversarialBreakGlassOverride(value) {
  const result = validateAdversarialBreakGlassOverride(value)
  if (!result.valid) {
    fail(
      result.errors[0]?.code ?? 'BREAK_GLASS_INVALID',
      'break-glass override violates its schema or semantic invariants',
      result.errors,
    )
  }
  return value
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

function assertAuthorizationReceipt(plan, authorizationReceipt) {
  assertValidAdversarialPlan(plan)
  const planDigest = digestAdversarialPlan(plan)
  const jsonErrors = inspectJsonValue(authorizationReceipt)
  const fields = jsonErrors.length === 0
    && authorizationReceipt !== null
    && typeof authorizationReceipt === 'object'
    && !Array.isArray(authorizationReceipt)
    ? Object.keys(authorizationReceipt).sort()
    : []
  if (
    jsonErrors.length > 0
    || canonicalJson(fields) !== canonicalJson(AUTHORIZATION_RECEIPT_FIELDS)
    || authorizationReceipt?.schema_version !== '1.0.0'
    || authorizationReceipt.kind !== 'red-team-audit/adversarial-authorization-receipt'
    || authorizationReceipt.status !== 'CONTROLLER_VERIFIED'
    || authorizationReceipt.authority_basis !== OPERATOR_AUTHORITY_BASIS
    || authorizationReceipt.authorization_id !== authorizationReceipt.authorization_reference
    || !/^[a-f0-9]{64}$/.test(authorizationReceipt.authorization_sha256 ?? '')
    || !/^[a-f0-9]{64}$/.test(authorizationReceipt.target_sha256 ?? '')
    || authorizationReceipt.target_sha256 !== digestJson(plan.target)
    || authorizationReceipt.plan_sha256 !== planDigest
    || authorizationReceipt.engagement_id !== plan.engagement_id
    || authorizationReceipt.scope_revision_sha256 !== plan.scope_revision_sha256
    || authorizationReceipt.risk_class !== plan.risk_class
    || authorizationReceipt.autonomy_profile !== plan.autonomy_profile
    || !isCanonicalTimestamp(authorizationReceipt.declared_at)
    || !isCanonicalTimestamp(authorizationReceipt.expires_at)
    || Date.parse(authorizationReceipt.expires_at) <= Date.parse(authorizationReceipt.declared_at)
  ) {
    fail(
      'BREAK_GLASS_AUTHORIZATION_MISMATCH',
      'controller authorization receipt is not bound to the exact L3 plan, target, and scope',
    )
  }
  return planDigest
}

function assertLiveL3AuthorizationBinding(plan, authorizationReceipt) {
  if (plan.autonomy_profile !== 'L3_MAXIMUM_AUTHORIZED') {
    fail('BREAK_GLASS_L3_REQUIRED', 'L3 preflight requires an L3_MAXIMUM_AUTHORIZED plan')
  }
  if (plan.target.kind !== 'live') {
    fail(
      'BREAK_GLASS_L3_LIVE_REQUIRED',
      'break-glass applies only to live L3_MAXIMUM_AUTHORIZED plans',
    )
  }
  return assertAuthorizationReceipt(plan, authorizationReceipt)
}

export function isBreakGlassControlWaivableForPlan(plan, control) {
  return plan?.risk_class === 'READ_ONLY'
    && BREAK_GLASS_WAIVABLE_PREFLIGHT_FLAGS.includes(control)
}

function assertFailedControls(plan, failedControls) {
  if (!Array.isArray(failedControls) || failedControls.length === 0) {
    fail('BREAK_GLASS_FAILED_CONTROL_REQUIRED', 'at least one failed preflight control is required')
  }
  for (const entry of failedControls) {
    if (BREAK_GLASS_NON_OVERRIDABLE_PREFLIGHT_FLAGS.includes(entry?.control)) {
      fail(
        'BREAK_GLASS_CONTROL_NON_OVERRIDABLE',
        `preflight.${entry.control} is hardcoded non-waivable`,
      )
    }
    if (!BREAK_GLASS_WAIVABLE_PREFLIGHT_FLAGS.includes(entry?.control)) {
      fail('BREAK_GLASS_CONTROL_UNKNOWN', `preflight.${entry?.control} is not waivable`)
    }
    if (!isBreakGlassControlWaivableForPlan(plan, entry.control)) {
      fail(
        'BREAK_GLASS_CONTROL_RISK_INCOMPATIBLE',
        `preflight.${entry.control} may be waived only for a READ_ONLY plan`,
      )
    }
  }
}

function runtimeControlEvidence(runtimePreflight, control) {
  const evidence = runtimePreflight?.control_observations?.[control]
  if (
    evidence === null
    || typeof evidence !== 'object'
    || Array.isArray(evidence)
  ) return null
  return evidence
}

function exactFailureEvidenceReasons(runtimePreflight, failedControls) {
  const reasons = []
  for (const declared of failedControls) {
    const observed = runtimeControlEvidence(runtimePreflight, declared.control)
    if (!observed) {
      reasons.push(`BREAK_GLASS_FAILURE_EVIDENCE_MISSING:${declared.control}`)
      continue
    }
    if (
      observed.status !== declared.status
      || observed.observation_sha256 !== declared.observation_sha256
    ) {
      reasons.push(`BREAK_GLASS_FAILURE_EVIDENCE_CHANGED:${declared.control}`)
    }
  }
  return reasons
}

function normalizedCompensatingLimits(plan, limits) {
  const fields = [
    [
      'max_actions',
      Math.min(plan.limits.max_actions, plan.campaign_envelope?.max_actions ?? plan.limits.max_actions),
    ],
    ['max_wall_time_ms', plan.limits.max_wall_time_ms],
    ['max_aggregate_output_bytes', plan.limits.max_aggregate_output_bytes],
    ['max_concurrency', plan.limits.max_concurrency],
  ]
  for (const [field, approved] of fields) {
    const proposed = limits?.[field]
    if (!Number.isInteger(proposed) || proposed < 1) {
      fail('BREAK_GLASS_LIMIT_INVALID', `compensating_limits.${field} must be a positive integer`)
    }
    if (proposed > approved) {
      fail('BREAK_GLASS_LIMIT_EXPANSION', `break glass cannot expand approved ${field}`)
    }
  }

  const approved = Object.fromEntries(fields)
  const materialCaps = {
    max_actions: Math.min(
      BREAK_GLASS_MAX_ACTIONS,
      Math.max(1, Math.floor(approved.max_actions / BREAK_GLASS_LIMIT_REDUCTION_DIVISOR)),
    ),
    max_wall_time_ms: Math.min(
      BREAK_GLASS_MAX_WALL_TIME_MS,
      Math.max(1, Math.floor(approved.max_wall_time_ms / BREAK_GLASS_LIMIT_REDUCTION_DIVISOR)),
    ),
    max_aggregate_output_bytes: Math.min(
      BREAK_GLASS_MAX_AGGREGATE_OUTPUT_BYTES,
      Math.max(
        1,
        Math.floor(
          approved.max_aggregate_output_bytes / BREAK_GLASS_LIMIT_REDUCTION_DIVISOR,
        ),
      ),
    ),
    max_concurrency: 1,
  }
  const insufficient = Object.entries(materialCaps)
    .filter(([field, maximum]) => limits[field] > maximum)
    .map(([field]) => field)
  if (insufficient.length > 0) {
    fail(
      'BREAK_GLASS_LIMIT_NOT_MATERIAL',
      `break-glass limits are not materially reduced: ${insufficient.join(', ')}`,
    )
  }
  if (fields.every(([field, approvedLimit]) => limits[field] === approvedLimit)) {
    fail(
      'BREAK_GLASS_LIMIT_NOT_COMPENSATING',
      'break-glass must reduce at least one approved limit',
    )
  }
  return Object.fromEntries(fields.map(([field]) => [field, limits[field]]))
}

export function createAdversarialBreakGlassOverride({
  plan,
  authorizationReceipt,
  overrideId,
  failedControls,
  rationale,
  incidentReference,
  compensatingLimits,
  issuedAt,
  expiresAt,
  nonce,
  approver,
  privateKey,
}) {
  const planDigest = assertLiveL3AuthorizationBinding(plan, authorizationReceipt)
  assertFailedControls(plan, failedControls)
  const issued = canonicalTimestamp(issuedAt, 'issuedAt')
  const expires = canonicalTimestamp(expiresAt, 'expiresAt')
  const windowMs = Date.parse(expires) - Date.parse(issued)
  if (windowMs <= 0) {
    fail('BREAK_GLASS_WINDOW_INVALID', 'expiresAt must be later than issuedAt')
  }
  if (windowMs > MAX_WINDOW_MS) {
    fail('BREAK_GLASS_WINDOW_TOO_LONG', 'break-glass validity cannot exceed 15 minutes')
  }
  if (
    Date.parse(issued) < Date.parse(authorizationReceipt.declared_at)
    || Date.parse(expires) > Date.parse(authorizationReceipt.expires_at)
  ) {
    fail(
      'BREAK_GLASS_AUTHORIZATION_WINDOW_MISMATCH',
      'break-glass window must fit inside the controller authorization window',
    )
  }
  const limits = normalizedCompensatingLimits(plan, compensatingLimits)
  const signingKey = asPrivateKey(privateKey)
  const publicKey = createPublicKey(signingKey)
  const keyId = keyIdentity(publicKey)
  const failed = failedControls
    .map((entry) => ({
      control: entry.control,
      status: entry.status,
      observation_sha256: entry.observation_sha256,
    }))
    .sort((left, right) => (left.control < right.control ? -1 : left.control > right.control ? 1 : 0))
  const unsigned = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-break-glass',
    override_id: overrideId,
    engagement_id: plan.engagement_id,
    scope_revision_sha256: plan.scope_revision_sha256,
    plan_sha256: planDigest,
    authorization_id: authorizationReceipt.authorization_id,
    authorization_sha256: authorizationReceipt.authorization_sha256,
    failed_controls: failed,
    waived_controls: failed.map((entry) => entry.control),
    rationale,
    incident_reference: incidentReference,
    compensating_limits: limits,
    issued_at: issued,
    expires_at: expires,
    nonce,
    approver,
    signing: {
      algorithm: 'Ed25519',
      key_id: keyId,
      delegation: 'break_glass',
    },
  }
  const value = {
    ...unsigned,
    signature: signBytes(null, signingBytes(unsigned), signingKey).toString('base64'),
  }
  assertValidAdversarialBreakGlassOverride(value)
  return deepFreeze(value)
}

function deepFreeze(value, seen = new WeakSet()) {
  if (value === null || typeof value !== 'object' || seen.has(value)) return value
  seen.add(value)
  for (const child of Object.values(value)) deepFreeze(child, seen)
  return Object.freeze(value)
}

function assertPinnedAuthority(pinnedKey, override) {
  if (!pinnedKey || typeof pinnedKey !== 'object') {
    fail('BREAK_GLASS_PINNED_KEY_REQUIRED', 'a pinned break-glass authority is required')
  }
  if (!Array.isArray(pinnedKey.delegations) || !pinnedKey.delegations.includes('break_glass')) {
    fail('BREAK_GLASS_DELEGATION_REQUIRED', 'pinned authority lacks break_glass delegation')
  }
  if (pinnedKey.approver_id !== override.approver.id) {
    fail('BREAK_GLASS_APPROVER_ID_MISMATCH', 'break-glass approver id does not match the pinned authority')
  }
  if (pinnedKey.approver_role !== override.approver.role) {
    fail('BREAK_GLASS_ROLE_MISMATCH', 'break-glass approver role does not match the pinned authority')
  }
  const publicKey = asPublicKey(pinnedKey.public_key)
  const observedKeyId = keyIdentity(publicKey)
  if (pinnedKey.key_id !== observedKeyId || override.signing.key_id !== observedKeyId) {
    fail('BREAK_GLASS_KEY_ID_MISMATCH', 'break-glass key id does not match the pinned public key')
  }
  return publicKey
}

export function verifyAdversarialBreakGlassOverride({
  plan,
  authorizationReceipt,
  override,
  pinnedKey,
  now,
  nonceStore,
}) {
  assertValidAdversarialPlan(plan)
  const planDigest = digestAdversarialPlan(plan)
  assertValidAdversarialBreakGlassOverride(override)
  if (
    override.plan_sha256 !== planDigest
    || override.engagement_id !== plan.engagement_id
    || override.scope_revision_sha256 !== plan.scope_revision_sha256
  ) {
    fail('BREAK_GLASS_PLAN_MISMATCH', 'break-glass override does not match the exact plan and scope')
  }
  assertLiveL3AuthorizationBinding(plan, authorizationReceipt)
  if (
    override.authorization_id !== authorizationReceipt.authorization_id
    || override.authorization_sha256 !== authorizationReceipt.authorization_sha256
  ) {
    fail(
      'BREAK_GLASS_AUTHORIZATION_MISMATCH',
      'break-glass override does not match the exact controller authorization receipt',
    )
  }
  if (
    Date.parse(override.issued_at) < Date.parse(authorizationReceipt.declared_at)
    || Date.parse(override.expires_at) > Date.parse(authorizationReceipt.expires_at)
  ) {
    fail(
      'BREAK_GLASS_AUTHORIZATION_WINDOW_MISMATCH',
      'break-glass window lies outside controller authorization',
    )
  }
  normalizedCompensatingLimits(plan, override.compensating_limits)
  assertFailedControls(plan, override.failed_controls)
  const publicKey = assertPinnedAuthority(pinnedKey, override)
  const signature = Buffer.from(override.signature, 'base64')
  if (!verifyBytes(null, signingBytes(override), publicKey, signature)) {
    fail('BREAK_GLASS_SIGNATURE_INVALID', 'break-glass signature verification failed')
  }
  const at = Date.parse(canonicalTimestamp(now, 'now'))
  if (at < Date.parse(override.issued_at)) {
    fail('BREAK_GLASS_NOT_YET_VALID', 'break-glass override is not yet valid')
  }
  if (at >= Date.parse(override.expires_at)) {
    fail('BREAK_GLASS_EXPIRED', 'break-glass override has expired')
  }
  if (!nonceStore || typeof nonceStore.consume !== 'function') {
    fail('BREAK_GLASS_NONCE_STORE_REQUIRED', 'a durable one-use break-glass nonce store is required')
  }
  const nonceSha256 = digestBytes(Buffer.concat([
    NONCE_CONTEXT,
    Buffer.from(override.nonce, 'utf8'),
  ]))
  if (nonceStore.consume({
    nonce_sha256: nonceSha256,
    override_id: override.override_id,
    plan_sha256: planDigest,
  }) !== true) {
    fail('BREAK_GLASS_REPLAY', 'break-glass nonce was already consumed or could not be reserved')
  }
  return deepFreeze({
    status: 'VERIFIED_AND_CONSUMED',
    override_id: override.override_id,
    plan_sha256: planDigest,
    authorization_id: authorizationReceipt.authorization_id,
    authorization_sha256: authorizationReceipt.authorization_sha256,
    scope_revision_sha256: plan.scope_revision_sha256,
    key_id: override.signing.key_id,
    nonce_sha256: nonceSha256,
    waived_controls: [...override.waived_controls],
    failed_controls: override.failed_controls.map((entry) => ({ ...entry })),
    issued_at: override.issued_at,
    expires_at: override.expires_at,
  })
}

export function evaluateL3PreflightWithBreakGlass({
  plan,
  authorizationReceipt,
  runtimePreflight,
  override,
  pinnedKey,
  now,
  nonceStore,
}) {
  try {
    assertAuthorizationReceipt(plan, authorizationReceipt)
  } catch (error) {
    return { allowed: false, reasons: [error.code ?? 'BREAK_GLASS_PLAN_INVALID'] }
  }
  const failed = L3_PREFLIGHT_FLAGS.filter((flag) => runtimePreflight?.[flag] !== true)
  if (failed.length === 0) {
    return { allowed: true, reasons: [], mode: 'NORMAL', waived_controls: [] }
  }
  const nonOverridable = failed.filter((flag) =>
    !isBreakGlassControlWaivableForPlan(plan, flag))
  if (nonOverridable.length > 0) {
    return {
      allowed: false,
      reasons: nonOverridable.map((flag) => `NON_OVERRIDABLE_RUNTIME_PREFLIGHT:${flag}`),
    }
  }
  if (!override || typeof override !== 'object' || Array.isArray(override)) {
    return { allowed: false, reasons: ['BREAK_GLASS_OVERRIDE_REQUIRED'] }
  }
  const overrideValidation = validateAdversarialBreakGlassOverride(override)
  if (!overrideValidation.valid) {
    return {
      allowed: false,
      reasons: ['BREAK_GLASS_INVALID:BREAK_GLASS_CONTRACT_INVALID'],
    }
  }
  const waived = Array.isArray(override.waived_controls) ? override.waived_controls : []
  const unwaived = failed.filter((flag) => !waived.includes(flag))
  const notFailed = waived.filter((flag) => !failed.includes(flag))
  if (unwaived.length > 0 || notFailed.length > 0) {
    return {
      allowed: false,
      reasons: [
        ...unwaived.map((flag) => `UNWAIVED_RUNTIME_PREFLIGHT:${flag}`),
        ...notFailed.map((flag) => `WAIVER_CONTROL_NOT_FAILED:${flag}`),
      ],
    }
  }
  const evidenceReasons = exactFailureEvidenceReasons(
    runtimePreflight,
    override.failed_controls ?? [],
  )
  if (evidenceReasons.length > 0) {
    return { allowed: false, reasons: evidenceReasons }
  }
  let receipt
  try {
    receipt = verifyAdversarialBreakGlassOverride({
      plan,
      authorizationReceipt,
      override,
      pinnedKey,
      now,
      nonceStore,
    })
  } catch (error) {
    return {
      allowed: false,
      reasons: [`BREAK_GLASS_INVALID:${error.code ?? 'UNKNOWN'}`],
    }
  }
  return {
    allowed: true,
    reasons: [],
    mode: 'BREAK_GLASS',
    waived_controls: [...receipt.waived_controls],
    effective_limits: { ...override.compensating_limits },
    failed_controls: receipt.failed_controls.map((entry) => ({ ...entry })),
    override_receipt: receipt,
  }
}
