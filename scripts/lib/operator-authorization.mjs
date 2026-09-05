import { createHash } from 'node:crypto'

import { stableJson } from './run-engine.mjs'

export const OPERATOR_AUTHORIZATION_KIND = 'red-team-audit/operator-authorization'
export const OPERATOR_AUTHORIZATION_STATUS = 'OPERATOR_ASSERTED_AUTHORIZED'
export const OPERATOR_AUTHORITY_BASIS = 'OPERATOR_DECLARATION_ACCEPTED_AS_FACT'
export const OPERATOR_CAMPAIGN_AUTHORIZATION_STATEMENT =
  'I confirm I am authorized to execute this exact bounded campaign.'
export const OPERATOR_HTTPS_AUTHORIZATION_STATEMENT =
  'I confirm I am authorized to test this exact HTTPS target.'

const COMMON_FIELDS = Object.freeze([
  'authorization_reference',
  'declared_at',
  'kind',
  'operator_id',
  'schema_version',
  'statement',
  'status',
  'target',
])
const BOUND_FIELDS = Object.freeze([
  ...COMMON_FIELDS,
  'plan_sha256',
  'scope_revision_sha256',
])
const RECEIPT_FIELDS = Object.freeze([
  ...BOUND_FIELDS,
  'authority_basis',
  'target_sha256',
  'authorization_sha256',
])
const SHA256_PATTERN = /^[a-f0-9]{64}$/
const OPERATOR_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{2,159}$/
const MAX_INGRESS_AGE_MS = 5 * 60 * 1000

function canonical(value) {
  return stableJson(value, 0).trimEnd()
}

export function digestOperatorAuthorizationValue(value) {
  return createHash('sha256').update(canonical(value)).digest('hex')
}

function exactFields(value, fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const actual = Object.keys(value).sort()
  const expected = [...fields].sort()
  return actual.length === expected.length
    && actual.every((field, index) => field === expected[index])
}

function isCanonicalTimestamp(value) {
  if (typeof value !== 'string') return false
  const parsed = Date.parse(value)
  return !Number.isNaN(parsed) && new Date(parsed).toISOString() === value
}

function validHumanText(value, { min = 1, max = 4096 } = {}) {
  return typeof value === 'string'
    && value.length >= min
    && value.length <= max
    && value.trim() === value
    && !/[\u0000-\u001f\u007f]/.test(value)
}

function assertCommon(value, fields, fail) {
  if (!exactFields(value, fields)) {
    fail('SHAPE_INVALID', 'operator authorization must be one exact bounded record')
  }
  if (
    value.schema_version !== '1.0.0'
    || value.kind !== OPERATOR_AUTHORIZATION_KIND
    || value.status !== OPERATOR_AUTHORIZATION_STATUS
    || !OPERATOR_ID_PATTERN.test(value.operator_id ?? '')
    || !isCanonicalTimestamp(value.declared_at)
    || !validHumanText(value.authorization_reference, { min: 3, max: 1024 })
    || !validHumanText(value.statement, { min: 3 })
  ) {
    fail('SHAPE_INVALID', 'operator authorization contains invalid identity, time, or statement fields')
  }
  if (Buffer.byteLength(canonical(value), 'utf8') > 8 * 1024) {
    fail('SIZE_LIMIT', 'operator authorization exceeds the 8 KiB controller limit')
  }
}

function expectedStatement(target) {
  return target?.kind === 'https_url'
    ? OPERATOR_HTTPS_AUTHORIZATION_STATEMENT
    : OPERATOR_CAMPAIGN_AUTHORIZATION_STATEMENT
}

function assertIngressTime(value, { now, notBefore, notAfter, fail }) {
  const current = now instanceof Date ? now.valueOf() : Date.parse(now)
  const declaredAt = Date.parse(value.declared_at)
  if (!Number.isFinite(current)) {
    fail('TIME_INVALID', 'operator authorization requires a real controller ingress time')
  }
  if (declaredAt > current) {
    fail('TIME_FUTURE', 'operator authorization cannot be future-dated')
  }
  if (current - declaredAt > MAX_INGRESS_AGE_MS) {
    fail('TIME_STALE', 'operator authorization must be declared within five minutes of controller ingress')
  }
  if (notBefore !== undefined && declaredAt < Date.parse(notBefore)) {
    fail('TIME_OUTSIDE_SCOPE', 'operator authorization predates the current scope window')
  }
  if (notAfter !== undefined && declaredAt >= Date.parse(notAfter)) {
    fail('TIME_OUTSIDE_SCOPE', 'operator authorization falls outside the current scope window')
  }
}

function verifyBoundOperatorAuthorizationRecord({
  value,
  planSha256,
  scopeRevisionSha256,
  target,
  fail,
}) {
  assertCommon(value, BOUND_FIELDS, fail)
  if (value.statement !== expectedStatement(target)) {
    fail('STATEMENT_INVALID', 'operator authorization must use the exact affirmative statement for its target kind')
  }
  if (!SHA256_PATTERN.test(value.plan_sha256 ?? '') || value.plan_sha256 !== planSha256) {
    fail('PLAN_MISMATCH', 'operator authorization does not bind the exact canonical plan')
  }
  if (
    !SHA256_PATTERN.test(value.scope_revision_sha256 ?? '')
    || value.scope_revision_sha256 !== scopeRevisionSha256
  ) {
    fail('SCOPE_MISMATCH', 'operator authorization does not bind the current scope revision')
  }
  if (canonical(value.target) !== canonical(target)) {
    fail('TARGET_MISMATCH', 'operator authorization does not bind the exact plan target')
  }
  const authorization = structuredClone(value)
  return Object.freeze({
    ...authorization,
    authority_basis: OPERATOR_AUTHORITY_BASIS,
    target_sha256: digestOperatorAuthorizationValue(target),
    authorization_sha256: digestOperatorAuthorizationValue(authorization),
  })
}

export function verifyBoundOperatorAuthorization({
  value,
  planSha256,
  scopeRevisionSha256,
  target,
  now,
  notBefore,
  notAfter,
  fail,
}) {
  const receipt = verifyBoundOperatorAuthorizationRecord({
    value,
    planSha256,
    scopeRevisionSha256,
    target,
    fail,
  })
  assertIngressTime(value, { now, notBefore, notAfter, fail })
  return receipt
}

function canonicalHttpsUrl(value, fail) {
  let parsed
  try {
    parsed = new URL(value)
  } catch {
    fail('TARGET_MISMATCH', 'operator authorization target must be an exact HTTPS URL')
  }
  if (
    parsed.protocol !== 'https:'
    || parsed.username !== ''
    || parsed.password !== ''
    || parsed.hash !== ''
  ) {
    fail('TARGET_MISMATCH', 'operator authorization target must be an exact HTTPS URL without credentials or fragment')
  }
  return parsed.href
}

export function verifyPrePlanHttpsOperatorAuthorization({ value, targetUrl, now, fail }) {
  if (
    value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && (
      Object.hasOwn(value, 'plan_sha256')
      || Object.hasOwn(value, 'scope_revision_sha256')
    )
  ) {
    fail(
      'DERIVED_FIELD_FORBIDDEN',
      'pre-plan operator authorization cannot supply controller-derived plan or scope digests',
    )
  }
  assertCommon(value, COMMON_FIELDS, fail)
  if (!exactFields(value.target, ['kind', 'url']) || value.target.kind !== 'https_url') {
    fail('TARGET_MISMATCH', 'operator authorization must bind one exact HTTPS URL target')
  }
  if (value.statement !== OPERATOR_HTTPS_AUTHORIZATION_STATEMENT) {
    fail('STATEMENT_INVALID', 'operator authorization must use the exact affirmative HTTPS-target statement')
  }
  assertIngressTime(value, { now, fail })
  const expectedUrl = canonicalHttpsUrl(targetUrl, fail)
  const authorizedUrl = canonicalHttpsUrl(value.target.url, fail)
  if (authorizedUrl !== expectedUrl) {
    fail('TARGET_MISMATCH', 'operator authorization target differs from the requested HTTPS target')
  }
  return Object.freeze({
    ...structuredClone(value),
    target: Object.freeze({ kind: 'https_url', url: expectedUrl }),
  })
}

export function bindPrePlanOperatorAuthorization({ value, planSha256, scopeRevisionSha256 }) {
  const authorization = Object.freeze({
    ...structuredClone(value),
    plan_sha256: planSha256,
    scope_revision_sha256: scopeRevisionSha256,
  })
  return Object.freeze({
    ...authorization,
    authority_basis: OPERATOR_AUTHORITY_BASIS,
    target_sha256: digestOperatorAuthorizationValue(authorization.target),
    authorization_sha256: digestOperatorAuthorizationValue(authorization),
  })
}

export function verifyOperatorAuthorizationReceipt({
  value,
  planSha256,
  scopeRevisionSha256,
  target,
  fail,
}) {
  if (!exactFields(value, RECEIPT_FIELDS)) {
    fail('RECEIPT_INVALID', 'operator authorization receipt must be one exact bounded record')
  }
  const authorization = Object.fromEntries(
    BOUND_FIELDS.map((field) => [field, structuredClone(value[field])]),
  )
  const expected = verifyBoundOperatorAuthorizationRecord({
    value: authorization,
    planSha256,
    scopeRevisionSha256,
    target,
    fail,
  })
  if (canonical(value) !== canonical(expected)) {
    fail('RECEIPT_INVALID', 'operator authorization receipt digest or authority basis is invalid')
  }
  return Object.freeze(structuredClone(value))
}
