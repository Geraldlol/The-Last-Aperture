import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { test } from 'node:test'

import {
  assertValidEngagementAuthority,
  assertValidEngagementManifest,
  canonicalEngagementManifest,
  digestEngagementManifest,
} from '../scripts/lib/engagement-contracts.mjs'
import {
  ENGAGEMENT_AUTHORIZED_CAPABILITIES,
  ENGAGEMENT_AUTHORIZED_EFFECTS,
  createEngagementAuthority,
  createEngagementManifest,
  deriveEngagementRouteGrant,
  digestEngagementAuthority,
  verifyEngagementAuthority,
  verifyEngagementManifest,
  verifyEngagementRouteGrant,
} from '../scripts/lib/engagement-authorization.mjs'

const DECLARED_AT = '2026-09-11T09:00:00.000Z'
const TARGET = Object.freeze({
  kind: 'https',
  locator: 'https://app.example/internal',
})
const PLAN_SHA256 = 'c'.repeat(64)
const INVOCATION_SHA256 = 'd'.repeat(64)

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function authority(overrides = {}) {
  return createEngagementAuthority({
    engagementId: 'engagement:unified-authority-test',
    operatorId: 'operator:workspace-owner',
    declaredAt: DECLARED_AT,
    statement: 'I have full authority for https://app.example/internal.\nUse every useful Last Aperture capability — Codex and Claude may continue the same work.',
    objective: 'Assess the application and reconstruct its internal interactions.',
    target: TARGET,
    authorizationProfile: 'full',
    credentialReferences: ['browser-session:primary', 'vault:portal-test-user'],
    ...overrides,
  })
}

function intake(operatorAuthority) {
  return {
    schema_version: '1.0.0',
    kind: 'last-aperture/engagement-intake',
    operator_id: operatorAuthority.operator_id,
    declared_at: operatorAuthority.declared_at,
    statement: operatorAuthority.statement,
    objective: operatorAuthority.objective,
    authorization_profile: operatorAuthority.authorization_profile,
    capabilities: [...operatorAuthority.capabilities],
    effects: [...operatorAuthority.effects],
    target: structuredClone(operatorAuthority.target),
    credential_references: [...operatorAuthority.credential_references],
    inputs: [],
  }
}

test('one bounded natural-language statement is preserved exactly and grants the full named target', () => {
  const value = authority()

  assert.equal(
    value.statement,
    'I have full authority for https://app.example/internal.\nUse every useful Last Aperture capability — Codex and Claude may continue the same work.',
  )
  assert.equal(value.statement_sha256, sha256(Buffer.from(value.statement, 'utf8')))
  assert.equal(value.scope_mode, 'FULL_TARGET_AUTHORITY')
  assert.equal(value.autonomy_profile, 'L3_MAXIMUM_AUTHORIZED')
  assert.equal(value.authorization_profile, 'full')
  assert.deepEqual(value.capabilities, ENGAGEMENT_AUTHORIZED_CAPABILITIES)
  assert.deepEqual(value.effects, ENGAGEMENT_AUTHORIZED_EFFECTS)
  assert.deepEqual(value.credential_references, [
    'browser-session:primary',
    'vault:portal-test-user',
  ])
  assert.equal(value.target_sha256, sha256('{"kind":"https","locator":"https://app.example/internal"}'))
  assert.equal(Object.isFrozen(value.target), true)
  assert.equal(Object.isFrozen(value.capabilities), true)
  assert.equal(Object.isFrozen(value.credential_references), true)
  assert.doesNotThrow(() => assertValidEngagementAuthority(value))
})

test('authority verification on resume has no five-minute or repeated-attestation freshness rule', () => {
  const value = authority()
  const originalDigest = digestEngagementAuthority(value)

  const resumed = verifyEngagementAuthority(value, {
    expectedEngagementId: value.engagement_id,
    expectedTarget: TARGET,
    now: new Date('2036-09-11T09:00:00.000Z'),
  })

  assert.equal(digestEngagementAuthority(resumed), originalDigest)
  assert.equal(resumed.declared_at, DECLARED_AT)
  assert.equal(resumed.statement, value.statement)
})

test('authority verification rejects statement, target, and fixed full-authority drift', () => {
  const cases = [
    (value) => { value.statement = `${value.statement} changed` },
    (value) => { value.statement_sha256 = '0'.repeat(64) },
    (value) => { value.target.locator = 'https://other.example/' },
    (value) => { value.target_sha256 = '0'.repeat(64) },
    (value) => { value.capabilities = ['http-recon'] },
    (value) => { value.effects = [] },
    (value) => { value.scope_mode = 'PARTIAL' },
  ]

  for (const mutate of cases) {
    const changed = structuredClone(authority())
    mutate(changed)
    assert.throws(() => verifyEngagementAuthority(changed), /authority|statement|target|schema|scope|capabilit|effect/i)
  }
})

test('ordinary statements are bounded UTF-8 data rather than one magic sentence', () => {
  for (const statement of [
    'Authorized for a full assessment. Break this named test application and map its private endpoints.',
    'My team authorizes this target; Codex and Claude have full freedom for this engagement.',
    'Дозволяю повну перевірку названої системи.',
  ]) {
    assert.equal(authority({ statement }).statement, statement)
  }

  for (const statement of [
    'Please review this application.',
    'I am not authorized to assess this target.',
    'Proceed without permission.',
  ]) {
    assert.throws(() => authority({ statement }), /authoriz|permission|authority/i)
  }

  for (const statement of [
    '',
    ' \n\t ',
    'contains\u0000nul',
    '\ud800',
    'x'.repeat(8 * 1024 + 1),
  ]) {
    assert.throws(() => authority({ statement }), /statement|UTF-8|bounded|size|schema/i)
  }
})

test('a restrictive statement cannot be expanded into the full machine profile', () => {
  assert.throws(
    () => authority({
      statement: 'I am authorized for T1 read-only review; no network or runtime attachment.',
    }),
    (error) => error.code === 'ENGAGEMENT_AUTHORIZATION_PROFILE_CONTRADICTED',
  )

  const restricted = authority({
    statement: 'I am authorized for T1 read-only repository review.',
    authorizationProfile: 'repository-read',
  })
  assert.deepEqual(restricted.capabilities, ['repository-audit', 'repository-agent-work'])
  assert.equal(restricted.effects.some((effect) => effect.startsWith('SEND_')), false)
  assert.equal(restricted.effects.includes('ATTACH_AUTHORIZED_RUNTIME'), false)

  for (const [authorizationProfile, statement] of [
    ['web', 'I am authorized for this read-only web review with no network requests.'],
    ['reverse', 'I am authorized for this read-only reverse review with no runtime attachment.'],
  ]) {
    assert.throws(
      () => authority({
        statement,
        authorizationProfile,
      }),
      (error) => error.code === 'ENGAGEMENT_AUTHORIZATION_PROFILE_CONTRADICTED',
    )
  }

  assert.doesNotThrow(() => authority({
    statement: 'I am authorized for this offline review with no network access.',
    authorizationProfile: 'offline',
  }))
  assert.doesNotThrow(() => authority({
    statement: 'I am authorized for web requests, but no runtime attachment.',
    authorizationProfile: 'web',
  }))
  assert.doesNotThrow(() => authority({
    statement: 'I am authorized for local runtime tracing without network requests.',
    authorizationProfile: 'reverse',
  }))
})

test('immutable manifest binds authority and target without runtime status', () => {
  const operatorAuthority = authority()
  const manifest = createEngagementManifest({
    platformVersion: '0.14.0',
    engagementId: operatorAuthority.engagement_id,
    createdAt: '2026-09-11T09:00:01.000Z',
    objective: operatorAuthority.objective,
    target: TARGET,
    intake: intake(operatorAuthority),
    authority: operatorAuthority,
    routeRegistryVersion: '1.0.0',
  })

  assert.doesNotThrow(() => assertValidEngagementManifest(manifest))
  assert.equal(manifest.authority_sha256, digestEngagementAuthority(operatorAuthority))
  assert.equal(manifest.target_sha256, operatorAuthority.target_sha256)
  assert.match(manifest.intake_sha256, /^[a-f0-9]{64}$/)
  assert.deepEqual(manifest.ledger, {
    format: 'CANONICAL_JSON_DIRECTORY_SHA256_CHAIN',
    schema_version: '1.0.0',
  })
  assert.equal(Object.hasOwn(manifest, 'status'), false)
  assert.equal(Object.hasOwn(manifest, 'routes'), false)
  assert.equal(Object.isFrozen(manifest.target), true)
  assert.equal(Object.isFrozen(manifest.ledger), true)
  assert.equal(canonicalEngagementManifest(manifest).endsWith('\n'), false)
  assert.match(digestEngagementManifest(manifest), /^[a-f0-9]{64}$/)
  assert.doesNotThrow(() => verifyEngagementManifest(manifest, {
    authority: operatorAuthority,
    intake: intake(operatorAuthority),
  }))
})

test('route grants are derived from the durable authority binding without another statement', () => {
  const operatorAuthority = authority()
  const manifest = createEngagementManifest({
    platformVersion: '0.14.0',
    engagementId: operatorAuthority.engagement_id,
    createdAt: '2026-09-11T09:00:01.000Z',
    objective: operatorAuthority.objective,
    target: TARGET,
    intake: intake(operatorAuthority),
    authority: operatorAuthority,
    routeRegistryVersion: '1.0.0',
  })

  const first = deriveEngagementRouteGrant({
    manifest, authority: operatorAuthority, routeId: 'ghidra-analysis',
    planSha256: PLAN_SHA256, invocationSha256: INVOCATION_SHA256,
  })
  const second = deriveEngagementRouteGrant({
    manifest, authority: operatorAuthority, routeId: 'frida-trace',
    planSha256: PLAN_SHA256, invocationSha256: INVOCATION_SHA256,
  })

  for (const grant of [first, second]) {
    assert.equal(grant.engagement_id, operatorAuthority.engagement_id)
    assert.equal(grant.authority_sha256, digestEngagementAuthority(operatorAuthority))
    assert.equal(grant.target_sha256, operatorAuthority.target_sha256)
    assert.equal(grant.manifest_sha256, digestEngagementManifest(manifest))
    assert.equal(grant.plan_sha256, PLAN_SHA256)
    assert.equal(grant.invocation_sha256, INVOCATION_SHA256)
    assert.equal(Object.hasOwn(grant, 'statement'), false)
    assert.equal(Object.hasOwn(grant, 'declared_at'), false)
    assert.doesNotThrow(() => verifyEngagementRouteGrant(grant, {
      manifest, authority: operatorAuthority, routeId: grant.route_id,
      planSha256: PLAN_SHA256, invocationSha256: INVOCATION_SHA256,
    }))
  }

  const forged = { ...first, target_sha256: 'f'.repeat(64) }
  assert.throws(
    () => verifyEngagementRouteGrant(forged, {
      manifest, authority: operatorAuthority, routeId: first.route_id,
      planSha256: PLAN_SHA256, invocationSha256: INVOCATION_SHA256,
    }),
    /route grant|target|binding/i,
  )

  assert.throws(
    () => deriveEngagementRouteGrant({
      manifest, routeId: 'missing-authority',
      planSha256: PLAN_SHA256, invocationSha256: INVOCATION_SHA256,
    }),
    /authority/i,
  )

  const webAuthority = authority({
    statement: 'I am authorized to assess this web target.',
    authorizationProfile: 'web',
  })
  const webManifest = createEngagementManifest({
    platformVersion: '0.14.0',
    engagementId: webAuthority.engagement_id,
    createdAt: '2026-09-11T09:00:01.000Z',
    objective: webAuthority.objective,
    target: TARGET,
    intake: intake(webAuthority),
    authority: webAuthority,
    routeRegistryVersion: '1.2.0',
  })
  assert.throws(
    () => deriveEngagementRouteGrant({
      manifest: webManifest,
      authority: webAuthority,
      routeId: 'ghidra-analysis',
      planSha256: PLAN_SHA256,
      invocationSha256: INVOCATION_SHA256,
    }),
    (error) => error.code === 'ENGAGEMENT_ROUTE_CAPABILITY_NOT_GRANTED',
  )

  const webGrant = deriveEngagementRouteGrant({
    manifest: webManifest,
    authority: webAuthority,
    routeId: 'https-recon',
    planSha256: PLAN_SHA256,
    invocationSha256: INVOCATION_SHA256,
  })
  assert.throws(
    () => verifyEngagementRouteGrant({ ...webGrant, route_id: 'ghidra-analysis' }, {
      manifest: webManifest,
      authority: webAuthority,
      planSha256: PLAN_SHA256,
      invocationSha256: INVOCATION_SHA256,
    }),
    (error) => error.code === 'ENGAGEMENT_ROUTE_GRANT_INVALID',
  )
})
