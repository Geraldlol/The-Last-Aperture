import { createHash } from 'node:crypto'

import {
  EngagementContractError,
  assertSha256,
  assertSupportedEngagementCredentialReferences,
  assertValidEngagementAuthority,
  assertValidEngagementManifest,
  canonicalEngagementAuthority,
  canonicalEngagementIntake,
  canonicalEngagementJson,
  canonicalEngagementManifest,
  canonicalEngagementTarget,
  digestEngagementManifest,
  digestEngagementIntake,
  digestEngagementTarget,
} from './engagement-contracts.mjs'
import {
  ENGAGEMENT_AUTHORIZED_CAPABILITIES,
  ENGAGEMENT_AUTHORIZED_EFFECTS,
  engagementAuthorizationProfile,
} from './engagement-authority-profiles.mjs'

const ROUTE_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{2,159}$/
export { ENGAGEMENT_AUTHORIZED_CAPABILITIES, ENGAGEMENT_AUTHORIZED_EFFECTS }
const ROUTE_GRANT_FIELDS = Object.freeze([
  'schema_version',
  'kind',
  'engagement_id',
  'route_id',
  'authority_sha256',
  'target_sha256',
  'manifest_sha256',
  'plan_sha256',
  'invocation_sha256',
  'authorization_profile',
  'scope_mode',
  'autonomy_profile',
  'capabilities',
  'effects',
])

function fail(code, message, details = []) {
  throw new EngagementContractError(code, message, details)
}

function sha256Bytes(value) {
  return createHash('sha256').update(value).digest('hex')
}

function exactObject(value, fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) return false
  const actual = Object.keys(value).sort()
  const expected = [...fields].sort()
  return actual.length === expected.length && actual.every((field, index) => field === expected[index])
}

function frozenCopy(value) {
  const copy = structuredClone(value)
  const stack = [copy]
  while (stack.length > 0) {
    const current = stack.pop()
    if (current === null || typeof current !== 'object' || Object.isFrozen(current)) continue
    for (const nested of Object.values(current)) stack.push(nested)
    Object.freeze(current)
  }
  return copy
}

export function digestEngagementAuthority(value) {
  return sha256Bytes(canonicalEngagementAuthority(value))
}

export function createEngagementAuthority({
  engagementId,
  operatorId,
  declaredAt,
  statement,
  objective,
  target,
  authorizationProfile,
  credentialReferences = [],
}) {
  canonicalEngagementTarget(target)
  if (!Array.isArray(credentialReferences)) {
    fail('ENGAGEMENT_REFERENCE_INVALID', 'credentialReferences must be an array of names')
  }
  if (new Set(credentialReferences).size !== credentialReferences.length) {
    fail('ENGAGEMENT_REFERENCE_INVALID', 'credentialReferences cannot contain duplicates')
  }
  assertSupportedEngagementCredentialReferences(credentialReferences)
  const profile = engagementAuthorizationProfile(authorizationProfile)
  if (profile === undefined) {
    fail('ENGAGEMENT_AUTHORIZATION_PROFILE_INVALID', 'engagement authorization profile is unknown')
  }
  const authority = {
    schema_version: '1.0.0',
    kind: 'last-aperture/engagement-authority',
    engagement_id: engagementId,
    operator_id: operatorId,
    declared_at: declaredAt,
    statement,
    statement_sha256: typeof statement === 'string'
      ? sha256Bytes(Buffer.from(statement, 'utf8'))
      : '',
    objective,
    authorization_profile: authorizationProfile,
    target: structuredClone(target),
    target_sha256: digestEngagementTarget(target),
    scope_mode: profile.scope_mode,
    autonomy_profile: profile.autonomy_profile,
    credential_references: [...credentialReferences].sort(),
    capabilities: [...profile.capabilities],
    effects: [...profile.effects],
  }
  assertValidEngagementAuthority(authority)
  return frozenCopy(authority)
}

export function verifyEngagementAuthority(value, {
  expectedEngagementId,
  expectedTarget,
} = {}) {
  assertValidEngagementAuthority(value)
  const expectedStatementSha256 = sha256Bytes(Buffer.from(value.statement, 'utf8'))
  if (value.statement_sha256 !== expectedStatementSha256) {
    fail('ENGAGEMENT_AUTHORITY_STATEMENT_DRIFT', 'engagement authority statement digest is invalid')
  }
  const expectedTargetSha256 = digestEngagementTarget(value.target)
  if (value.target_sha256 !== expectedTargetSha256) {
    fail('ENGAGEMENT_AUTHORITY_TARGET_DRIFT', 'engagement authority target digest is invalid')
  }
  if (expectedEngagementId !== undefined && value.engagement_id !== expectedEngagementId) {
    fail('ENGAGEMENT_AUTHORITY_ENGAGEMENT_MISMATCH', 'engagement authority binds a different engagement')
  }
  if (
    expectedTarget !== undefined
    && canonicalEngagementTarget(value.target) !== canonicalEngagementTarget(expectedTarget)
  ) {
    fail('ENGAGEMENT_AUTHORITY_TARGET_MISMATCH', 'engagement authority binds a different normalized target')
  }
  return frozenCopy(value)
}

export function createEngagementManifest({
  platformVersion,
  engagementId,
  createdAt,
  objective,
  target,
  intake,
  authority,
  routeRegistryVersion,
}) {
  const verifiedAuthority = verifyEngagementAuthority(authority, {
    expectedEngagementId: engagementId,
    expectedTarget: target,
  })
  const intakeSha256 = digestEngagementIntake(intake)
  if (
    intake.operator_id !== verifiedAuthority.operator_id
    || intake.declared_at !== verifiedAuthority.declared_at
    || intake.statement !== verifiedAuthority.statement
    || intake.objective !== verifiedAuthority.objective
    || intake.authorization_profile !== verifiedAuthority.authorization_profile
    || canonicalEngagementJson(intake.capabilities) !== canonicalEngagementJson(verifiedAuthority.capabilities)
    || canonicalEngagementJson(intake.effects) !== canonicalEngagementJson(verifiedAuthority.effects)
    || canonicalEngagementTarget(intake.target) !== canonicalEngagementTarget(verifiedAuthority.target)
    || canonicalEngagementJson(intake.credential_references)
      !== canonicalEngagementJson(verifiedAuthority.credential_references)
  ) {
    fail('ENGAGEMENT_MANIFEST_INTAKE_MISMATCH', 'engagement intake differs from durable authority')
  }
  if (objective !== verifiedAuthority.objective) {
    fail('ENGAGEMENT_MANIFEST_OBJECTIVE_MISMATCH', 'engagement manifest objective differs from durable authority')
  }
  if (Date.parse(createdAt) < Date.parse(verifiedAuthority.declared_at)) {
    fail('ENGAGEMENT_MANIFEST_TIME_INVALID', 'engagement manifest cannot predate its authority')
  }
  const manifest = {
    schema_version: '1.0.0',
    kind: 'last-aperture/engagement-manifest',
    platform_version: platformVersion,
    engagement_id: engagementId,
    created_at: createdAt,
    objective,
    target: structuredClone(target),
    target_sha256: verifiedAuthority.target_sha256,
    intake_sha256: intakeSha256,
    authority_sha256: digestEngagementAuthority(verifiedAuthority),
    route_registry_version: routeRegistryVersion,
    ledger: {
      format: 'CANONICAL_JSON_DIRECTORY_SHA256_CHAIN',
      schema_version: '1.0.0',
    },
  }
  assertValidEngagementManifest(manifest)
  return frozenCopy(manifest)
}

export function verifyEngagementManifest(value, { authority, intake } = {}) {
  assertValidEngagementManifest(value)
  if (value.target_sha256 !== digestEngagementTarget(value.target)) {
    fail('ENGAGEMENT_MANIFEST_TARGET_DRIFT', 'engagement manifest target digest is invalid')
  }
  if (authority !== undefined) {
    const verifiedAuthority = verifyEngagementAuthority(authority, {
      expectedEngagementId: value.engagement_id,
      expectedTarget: value.target,
    })
    if (value.authority_sha256 !== digestEngagementAuthority(verifiedAuthority)) {
      fail('ENGAGEMENT_MANIFEST_AUTHORITY_DRIFT', 'engagement manifest authority digest is invalid')
    }
    if (value.objective !== verifiedAuthority.objective) {
      fail('ENGAGEMENT_MANIFEST_OBJECTIVE_MISMATCH', 'engagement manifest objective differs from durable authority')
    }
  } else {
    assertSha256(value.authority_sha256, 'manifest authority_sha256')
  }
  if (intake !== undefined) {
    canonicalEngagementIntake(intake)
    if (value.intake_sha256 !== digestEngagementIntake(intake)) {
      fail('ENGAGEMENT_MANIFEST_INTAKE_DRIFT', 'engagement manifest intake digest is invalid')
    }
  } else {
    assertSha256(value.intake_sha256, 'manifest intake_sha256')
  }
  return frozenCopy(value)
}

export function deriveEngagementRouteGrant({
  manifest,
  authority,
  routeId,
  planSha256,
  invocationSha256,
}) {
  if (authority === undefined) {
    fail('ENGAGEMENT_ROUTE_GRANT_AUTHORITY_REQUIRED', 'route grant derivation requires durable authority')
  }
  const verifiedAuthority = verifyEngagementAuthority(authority, {
    expectedEngagementId: manifest?.engagement_id,
    expectedTarget: manifest?.target,
  })
  const verifiedManifest = verifyEngagementManifest(manifest, { authority: verifiedAuthority })
  if (typeof routeId !== 'string' || !ROUTE_ID.test(routeId)) {
    fail('ENGAGEMENT_ROUTE_ID_INVALID', 'routeId must be one bounded route identifier')
  }
  if (!verifiedAuthority.capabilities.includes(routeId)) {
    fail('ENGAGEMENT_ROUTE_CAPABILITY_NOT_GRANTED', 'routeId is outside the durable authority capabilities')
  }
  assertSha256(planSha256, 'route grant plan_sha256')
  assertSha256(invocationSha256, 'route grant invocation_sha256')
  const grant = {
    schema_version: '1.0.0',
    kind: 'last-aperture/engagement-route-grant',
    engagement_id: verifiedManifest.engagement_id,
    route_id: routeId,
    authority_sha256: verifiedManifest.authority_sha256,
    target_sha256: verifiedManifest.target_sha256,
    manifest_sha256: digestEngagementManifest(verifiedManifest),
    plan_sha256: planSha256,
    invocation_sha256: invocationSha256,
    authorization_profile: verifiedAuthority.authorization_profile,
    scope_mode: verifiedAuthority.scope_mode,
    autonomy_profile: verifiedAuthority.autonomy_profile,
    capabilities: [...verifiedAuthority.capabilities],
    effects: [...verifiedAuthority.effects],
  }
  return frozenCopy(grant)
}

export function verifyEngagementRouteGrant(value, {
  manifest,
  authority,
  routeId,
  planSha256,
  invocationSha256,
} = {}) {
  if (!exactObject(value, ROUTE_GRANT_FIELDS)) {
    fail('ENGAGEMENT_ROUTE_GRANT_INVALID', 'route grant must contain one exact authority binding')
  }
  if (authority === undefined) {
    fail('ENGAGEMENT_ROUTE_GRANT_AUTHORITY_REQUIRED', 'route grant verification requires durable authority')
  }
  const verifiedAuthority = verifyEngagementAuthority(authority, {
    expectedEngagementId: manifest?.engagement_id,
    expectedTarget: manifest?.target,
  })
  const verifiedManifest = verifyEngagementManifest(manifest, { authority: verifiedAuthority })
  if (
    value.schema_version !== '1.0.0'
    || value.kind !== 'last-aperture/engagement-route-grant'
    || !ROUTE_ID.test(value.route_id ?? '')
    || !verifiedAuthority.capabilities.includes(value.route_id)
    || (routeId !== undefined && value.route_id !== routeId)
    || value.engagement_id !== verifiedManifest.engagement_id
    || value.authority_sha256 !== verifiedManifest.authority_sha256
    || value.target_sha256 !== verifiedManifest.target_sha256
    || value.manifest_sha256 !== digestEngagementManifest(verifiedManifest)
    || value.plan_sha256 !== planSha256
    || value.invocation_sha256 !== invocationSha256
    || !/^[a-f0-9]{64}$/.test(value.plan_sha256 ?? '')
    || !/^[a-f0-9]{64}$/.test(value.invocation_sha256 ?? '')
    || value.authorization_profile !== verifiedAuthority.authorization_profile
    || value.scope_mode !== verifiedAuthority.scope_mode
    || value.autonomy_profile !== verifiedAuthority.autonomy_profile
    || canonicalEngagementJson(value.capabilities) !== canonicalEngagementJson(verifiedAuthority.capabilities)
    || canonicalEngagementJson(value.effects) !== canonicalEngagementJson(verifiedAuthority.effects)
  ) {
    fail('ENGAGEMENT_ROUTE_GRANT_INVALID', 'route grant does not match the durable authority and target binding')
  }
  return frozenCopy(value)
}

export function canonicalEngagementRouteGrant(value, options) {
  return canonicalEngagementJson(verifyEngagementRouteGrant(value, options))
}

export function digestEngagementRouteGrant(value, options) {
  return sha256Bytes(canonicalEngagementRouteGrant(value, options))
}

export { canonicalEngagementManifest }
