import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { isIP } from 'node:net'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import { stableJson } from './run-engine.mjs'
import {
  createHttpReconRequestHeaderDescriptor,
  resolveHttpReconRequestHeaders,
} from './http-recon-request-headers.mjs'

const ATTESTED_SCOPE_SCHEMA_URL = new URL(
  '../../schemas/http-recon-attested-scope.schema.json',
  import.meta.url,
)
const RUN_SCHEMA_URL = new URL('../../schemas/http-recon-run.schema.json', import.meta.url)
const OBSERVATION_SCHEMA_URL = new URL(
  '../../schemas/http-recon-observation.schema.json',
  import.meta.url,
)
export const OPERATOR_ATTESTED_AUTHORIZATION_STATEMENT =
  'I confirm that I am authorized to perform this exact bounded HTTP reconnaissance action.'

export const OPERATOR_ATTESTED_LIMITS = Object.freeze({
  max_probe_requests: 1,
  max_target_proof_requests: 0,
  max_target_proof_response_bytes: 0,
  request_timeout_ms: 10_000,
  max_response_bytes: 1_048_576,
  max_aggregate_response_bytes: 1_048_576,
  max_wall_time_ms: 900_000,
  min_interval_ms: 1_000,
  concurrency: 1,
})

export const httpReconAttestedScopeSchema = JSON.parse(
  readFileSync(fileURLToPath(ATTESTED_SCOPE_SCHEMA_URL), 'utf8'),
)
export const httpReconRunSchema = JSON.parse(
  readFileSync(fileURLToPath(RUN_SCHEMA_URL), 'utf8'),
)
export const httpReconObservationSchema = JSON.parse(
  readFileSync(fileURLToPath(OBSERVATION_SCHEMA_URL), 'utf8'),
)

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})
for (const schema of [
  httpReconAttestedScopeSchema,
  httpReconRunSchema,
  httpReconObservationSchema,
]) {
  ajv.addSchema(schema)
}
const validateAttestedScopeSchema = ajv.getSchema(httpReconAttestedScopeSchema.$id)
const validateRunSchema = ajv.getSchema(httpReconRunSchema.$id)
const validateObservationSchema = ajv.getSchema(httpReconObservationSchema.$id)

export class HttpReconContractError extends Error {
  constructor(code, message, details = [], options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'HttpReconContractError'
    this.code = code
    this.details = details
  }
}

function contractError(code, message, details, options) {
  return new HttpReconContractError(code, message, details, options)
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

function assertSchema(validate, value, label) {
  if (!validate(value)) {
    throw contractError(
      'HTTP_RECON_SCHEMA_INVALID',
      `${label} violates its JSON schema`,
      normalizeAjvErrors(validate.errors),
    )
  }
  return value
}

export function canonicalJson(value) {
  const rendered = stableJson(value, 0)
  return rendered.endsWith('\n') ? rendered.slice(0, -1) : rendered
}

export function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex')
}

function parseExactTimestamp(value, label) {
  const timestamp = Date.parse(value)
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    throw contractError(
      'HTTP_RECON_TIME_INVALID',
      `${label} must be a real canonical UTC millisecond timestamp`,
    )
  }
  return timestamp
}

function ambiguousEncodedPath(value) {
  let current = value
  for (let pass = 0; pass < 8; pass += 1) {
    if (/%(?:2e|2f|5c)/iu.test(current)) return true
    if (!current.includes('%')) return false
    let decoded
    try { decoded = decodeURIComponent(current) } catch { return true }
    if (decoded === current) return false
    current = decoded
  }
  return current.includes('%')
}

function assertNoAmbiguousPath(url, label) {
  if (
    url.pathname.includes('\\')
    || ambiguousEncodedPath(url.pathname)
    || url.pathname.split('/').some((part) => part === '.' || part === '..')
  ) {
    throw contractError(
      'HTTP_RECON_URL_AMBIGUOUS',
      `${label} contains an ambiguous path encoding`,
    )
  }
}

function parseExactHttpsUrl(value, label, { originOnly = false } = {}) {
  let url
  try {
    url = new URL(value)
  } catch (error) {
    throw contractError(
      'HTTP_RECON_URL_INVALID',
      `${label} is not a valid URL`,
      [],
      { cause: error },
    )
  }
  if (
    url.protocol !== 'https:'
    || url.username !== ''
    || url.password !== ''
    || url.hash !== ''
    || url.search !== ''
    || isIP(url.hostname) !== 0
    || url.hostname.endsWith('.')
    || url.hostname.includes('*')
  ) {
    throw contractError(
      'HTTP_RECON_URL_SCOPE_INVALID',
      `${label} must be one credential-free, non-IP HTTPS URL without query or fragment`,
    )
  }
  if (originOnly) {
    if (value !== url.origin || url.pathname !== '/') {
      throw contractError(
        'HTTP_RECON_ORIGIN_NOT_CANONICAL',
        `${label} must be an exact canonical HTTPS origin without a trailing slash`,
      )
    }
  } else if (value !== url.href) {
    throw contractError(
      'HTTP_RECON_URL_NOT_CANONICAL',
      `${label} must equal its canonical URL serialization`,
    )
  }
  assertNoAmbiguousPath(url, label)
  return url
}

function assertAttestedScopeSemantics(
  scope,
  { now, requireCurrentValidity = true } = {},
) {
  const targetOrigin = parseExactHttpsUrl(
    scope.target.origin,
    'target.origin',
    { originOnly: true },
  )
  const requestUrl = parseExactHttpsUrl(scope.requests[0].url, 'requests[0].url')
  if (scope.requests[0].request_headers !== undefined) {
    try {
      resolveHttpReconRequestHeaders({
        descriptor: scope.requests[0].request_headers,
        method: scope.requests[0].method,
      })
    } catch (cause) {
      throw contractError(
        'HTTP_RECON_HEADER_DESCRIPTOR_INVALID',
        'operator-attested diagnostic request-header descriptor is invalid',
        [],
        { cause },
      )
    }
  }
  if (requestUrl.origin !== targetOrigin.origin) {
    throw contractError(
      'HTTP_RECON_ACTION_ORIGIN_MISMATCH',
      'the attested action must use the exact attested target origin',
    )
  }
  const notBefore = parseExactTimestamp(
    scope.validity.not_before,
    'validity.not_before',
  )
  const notAfter = parseExactTimestamp(
    scope.validity.not_after,
    'validity.not_after',
  )
  const attestedAt = parseExactTimestamp(
    scope.authorization.attested_at,
    'authorization.attested_at',
  )
  if (
    attestedAt !== notBefore
    || notBefore >= notAfter
    || notAfter - notBefore !== OPERATOR_ATTESTED_LIMITS.max_wall_time_ms
  ) {
    throw contractError(
      'HTTP_RECON_VALIDITY_WINDOW_INVALID',
      'operator-attested validity must begin at attestation and use the fixed 15-minute window',
    )
  }
  if (requireCurrentValidity) {
    const current = now instanceof Date ? now.getTime() : new Date(now).getTime()
    if (!Number.isFinite(current)) {
      throw contractError('HTTP_RECON_TIME_INVALID', 'verification time is invalid')
    }
    if (current < notBefore) {
      throw contractError(
        'HTTP_RECON_AUTHORIZATION_NOT_YET_VALID',
        `operator attestation is not valid before ${scope.validity.not_before}`,
      )
    }
    if (current >= notAfter) {
      throw contractError(
        'HTTP_RECON_AUTHORIZATION_EXPIRED',
        `operator attestation expired at ${scope.validity.not_after}`,
      )
    }
  }
  return scope
}

export function validateOperatorAttestedHttpReconScope(value) {
  const valid = validateAttestedScopeSchema(value)
  return {
    valid,
    errors: valid ? [] : normalizeAjvErrors(validateAttestedScopeSchema.errors),
  }
}

export function assertValidOperatorAttestedHttpReconScope(value, options = {}) {
  assertSchema(
    validateAttestedScopeSchema,
    value,
    'operator-attested HTTP-recon scope',
  )
  return assertAttestedScopeSemantics(value, options)
}

export function createOperatorAttestedHttpReconScope({
  engagementId,
  authorizationId,
  targetUrl,
  tlsSpkiSha256,
  method = 'HEAD',
  safeToGet = false,
  requestHeaderProfile,
  operatorId,
  authorizedBy,
  authorizationReference,
  environment = 'production',
  now = new Date(),
}) {
  const normalizedMethod = typeof method === 'string' ? method.toUpperCase() : method
  if (
    (normalizedMethod === 'GET' && safeToGet !== true)
    || (normalizedMethod !== 'GET' && safeToGet === true)
  ) {
    throw contractError(
      'HTTP_RECON_GET_ACKNOWLEDGMENT_INVALID',
      'safe-to-get acknowledgment is required only for an attested GET action',
    )
  }
  const parsedTarget = parseExactHttpsUrl(targetUrl, 'targetUrl')
  const attestedAt = new Date(now).toISOString()
  const request = {
    method: normalizedMethod,
    url: parsedTarget.href,
    ...(requestHeaderProfile === undefined
      ? {}
      : {
          request_headers: createHttpReconRequestHeaderDescriptor({
            profile: requestHeaderProfile,
            method: normalizedMethod,
          }),
        }),
    ...(normalizedMethod === 'GET' ? { safe_to_get: safeToGet } : {}),
  }
  const scope = {
    schema_version: requestHeaderProfile === undefined ? '1.0.0' : '1.1.0',
    kind: 'red-team-audit/http-recon-attested-scope',
    engagement_id: engagementId,
    environment,
    authorization: {
      mode: 'OPERATOR_ATTESTED',
      authorization_id: authorizationId,
      statement: OPERATOR_ATTESTED_AUTHORIZATION_STATEMENT,
      operator_id: operatorId,
      authorized_by: authorizedBy,
      authorization_reference: authorizationReference,
      attested_at: attestedAt,
      independently_verified: false,
    },
    target: {
      origin: parsedTarget.origin,
      tls: tlsSpkiSha256 === undefined
        ? { mode: 'PKIX_HOSTNAME' }
        : {
            mode: 'PKIX_HOSTNAME_AND_SPKI_PIN',
            spki_sha256: tlsSpkiSha256,
          },
    },
    validity: {
      not_before: attestedAt,
      not_after: new Date(
        Date.parse(attestedAt) + OPERATOR_ATTESTED_LIMITS.max_wall_time_ms,
      ).toISOString(),
    },
    limits: structuredClone(OPERATOR_ATTESTED_LIMITS),
    stop_conditions: [
      'AUTHORIZATION_WITHDRAWN',
      'EMERGENCY_STOP_REQUESTED',
      'AUTHORIZATION_WINDOW_CLOSED',
      'TARGET_IDENTITY_CHANGED',
      'LIMIT_REACHED',
      'UNEXPECTED_SIDE_EFFECT',
    ],
    requests: [request],
  }
  return assertValidOperatorAttestedHttpReconScope(scope, {
    now: new Date(attestedAt),
  })
}

export function buildOperatorAttestedHttpReconPlan(scope) {
  assertValidOperatorAttestedHttpReconScope(scope, {
    requireCurrentValidity: false,
  })
  const request = scope.requests[0]
  const projection = {
    sequence: 1,
    method: request.method,
    url: request.url,
    ...(request.request_headers === undefined
      ? {}
      : { request_headers: structuredClone(request.request_headers) }),
    safe_to_get: request.method === 'GET',
  }
  const actions = [{
    action_id: `http-recon-action:${sha256Hex(canonicalJson(projection))}`,
    ...projection,
  }]
  const plan = {
    schema_version: scope.schema_version,
    kind: 'red-team-audit/http-recon-plan',
    authorization_mode: 'OPERATOR_ATTESTED',
    engagement_id: scope.engagement_id,
    authorization: structuredClone(scope.authorization),
    target: structuredClone(scope.target),
    validity: structuredClone(scope.validity),
    limits: structuredClone(scope.limits),
    actions,
  }
  return {
    plan,
    actions,
    plan_sha256: sha256Hex(canonicalJson(plan)),
    scope_sha256: sha256Hex(canonicalJson(scope)),
  }
}

export function validateHttpReconRun(value) {
  const valid = validateRunSchema(value)
  return { valid, errors: valid ? [] : normalizeAjvErrors(validateRunSchema.errors) }
}

function assertActionState(action) {
  const hasLease = action.leased_at !== null
  const hasSent = action.sent_at !== null
  const hasCompleted = action.completed_at !== null
  const hasObservation = action.observation_path !== null
    && action.observation_sha256 !== null
  const hasError = action.error !== null
  const valid = {
    PENDING: action.attempt_count === 0
      && !hasLease && !hasSent && !hasCompleted && !hasObservation && !hasError,
    LEASED: action.attempt_count === 1
      && hasLease && !hasSent && !hasCompleted && !hasObservation && !hasError,
    SENT: action.attempt_count === 1
      && hasLease && hasSent && !hasCompleted && !hasObservation && !hasError,
    COMMITTED: action.attempt_count === 1
      && hasLease && hasSent && hasCompleted && hasObservation && !hasError,
    FAILED: action.attempt_count === 1
      && hasLease && hasCompleted && !hasObservation && hasError,
    DELIVERY_AMBIGUOUS: action.attempt_count === 1
      && hasLease && hasSent && hasCompleted && !hasObservation && hasError,
  }[action.state]
  if (!valid) {
    throw contractError(
      'HTTP_RECON_ACTION_STATE_INVALID',
      `action ${action.action_id} fields do not match state ${action.state}`,
    )
  }
}

export function assertValidHttpReconRun(value) {
  assertSchema(validateRunSchema, value, 'authorized HTTP-recon run')
  if (
    value.authorization.mode !== 'OPERATOR_ATTESTED'
    || value.actions.length !== 1
    || value.limits.max_probe_requests !== 1
    || value.limits.max_target_proof_requests !== 0
    || value.limits.max_target_proof_response_bytes !== 0
    || value.budget.proof_requests_used !== 0
    || value.authorization.attested_at !== value.authorization.valid_from
    || !['PKIX_HOSTNAME', 'PKIX_HOSTNAME_AND_SPKI_PIN'].includes(
      value.target.tls?.mode,
    )
  ) {
    throw contractError(
      'HTTP_RECON_ATTESTED_MODE_INVALID',
      'HTTP reconnaissance requires one operator-attested action, an explicit PKIX TLS policy, and zero target-proof budget',
    )
  }
  if (Date.parse(value.updated_at) < Date.parse(value.created_at)) {
    throw contractError(
      'HTTP_RECON_RUN_TIME_INVALID',
      'run updated_at cannot precede created_at',
    )
  }
  const actionIds = new Set()
  for (const [index, action] of value.actions.entries()) {
    if (action.sequence !== index + 1 || actionIds.has(action.action_id)) {
      throw contractError(
      'HTTP_RECON_ACTION_ORDER_INVALID',
      'run actions must have unique IDs in contiguous sealed sequence order',
      )
    }
    actionIds.add(action.action_id)
    assertActionState(action)
  }
  if (
    value.budget.proof_requests_used > value.limits.max_target_proof_requests
    || value.budget.probe_requests_used > value.limits.max_probe_requests
    || value.budget.response_bytes_used > value.limits.max_aggregate_response_bytes
  ) {
    throw contractError(
      'HTTP_RECON_BUDGET_INVALID',
      'run budget exceeds the sealed hard limits',
    )
  }
  if (
    value.state === 'PLANNED'
    && value.actions.some(({ state }) => state !== 'PENDING')
  ) {
    throw contractError(
      'HTTP_RECON_RUN_STATE_INVALID',
      'PLANNED run cannot contain attempted actions',
    )
  }
  if (
    value.state === 'PROBE_PLAN_COMPLETE'
    && value.actions.some(({ state }) => state !== 'COMMITTED')
  ) {
    throw contractError(
      'HTTP_RECON_RUN_STATE_INVALID',
      'PROBE_PLAN_COMPLETE requires every sealed action to be committed',
    )
  }
  if (value.state === 'STOPPED' && value.stop === null) {
    throw contractError(
      'HTTP_RECON_RUN_STATE_INVALID',
      'STOPPED run requires stop evidence',
    )
  }
  if (
    value.state === 'OUTCOME_UNCERTAIN'
    && !value.actions.some(({ state }) => state === 'DELIVERY_AMBIGUOUS')
  ) {
    throw contractError(
      'HTTP_RECON_RUN_STATE_INVALID',
      'OUTCOME_UNCERTAIN requires a delivery-ambiguous action',
    )
  }
  return value
}

export function validateHttpReconObservation(value) {
  const valid = validateObservationSchema(value)
  return {
    valid,
    errors: valid ? [] : normalizeAjvErrors(validateObservationSchema.errors),
  }
}

export function assertValidHttpReconObservation(value) {
  assertSchema(
    validateObservationSchema,
    value,
    'authorized HTTP-recon observation',
  )
  parseExactHttpsUrl(value.url, 'observation.url')
  if (
    value.body.truncated
    && value.body.digest_scope !== 'captured-prefix'
  ) {
    throw contractError(
      'HTTP_RECON_OBSERVATION_BODY_INVALID',
      'truncated observation body must use captured-prefix digest scope',
    )
  }
  return value
}
