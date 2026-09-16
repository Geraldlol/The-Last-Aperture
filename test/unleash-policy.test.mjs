import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { test } from 'node:test'

import { digestUnleashValue } from '../scripts/lib/unleash-contracts.mjs'

import {
  DEFAULT_UNLEASH_DETECTION_POLICY,
  assertPolicyAllowsTarget,
  createUnleashDeploymentPolicy,
  projectUnleashPolicy,
  resolveUnleashDetectionPolicyBinding,
  selectUnleashDetectionProfile,
} from '../scripts/lib/unleash-policy.mjs'

const VALID_FROM = '2026-09-15T09:00:00.000Z'
const VALID_UNTIL = '2026-09-15T10:00:00.000Z'
const NOW = new Date('2026-09-15T09:30:00.000Z')

function policyInput() {
  return {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-deployment-policy',
    policy_id: 'policy:unit-test',
    valid_from: VALID_FROM,
    valid_until: VALID_UNTIL,
    allowed_origins: ['https://example.test'],
    allowed_target_families: ['https'],
    allowed_effects: ['OBSERVE'],
    budgets: {
      max_actions: 20,
      max_parallel_actions: 2,
      max_duration_ms: 60_000,
      max_response_bytes: 1_048_576,
    },
    credential_references: ['credential:browser:primary'],
    revocation: { check_id: 'revocation:unit-test', fail_mode: 'CLOSED' },
  }
}

function sha256(value) {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex')
}

function target(locator = 'https://example.test/') {
  const canonicalLocator = new URL(locator).href
  return {
    family: 'https',
    canonical_locator: canonicalLocator,
    target_id: `target:sha256:${sha256({ canonical_locator: canonicalLocator, family: 'https' })}`,
    supplied_sha256: sha256(locator),
  }
}

function checkOptions(overrides = {}) {
  return { now: NOW, isRevoked: () => false, effect: 'OBSERVE', ...overrides }
}

test('canonicalizes an HTTPS origin and accepts only its exact origin', () => {
  const input = policyInput()
  input.allowed_origins = ['https://EXAMPLE.test:443/']
  const policy = createUnleashDeploymentPolicy(input)
  const projection = projectUnleashPolicy(policy)

  assert.deepEqual(projection.allowed_origins, ['https://example.test'])
  assert.doesNotThrow(() => assertPolicyAllowsTarget(policy, target(), checkOptions()))
  assert.doesNotThrow(() => assertPolicyAllowsTarget(
    policy, target('https://example.test/docs'), checkOptions(),
  ))

  for (const locator of [
    'https://example.test:444/',
    'https://api.example.test/',
    'https://example.test.other.test/',
    'https://notexample.test/',
    'https://example.test./',
    'http://example.test/',
  ]) {
    assert.throws(() => assertPolicyAllowsTarget(policy, target(locator), checkOptions()), locator)
  }
})

test('rejects wildcard, userinfo, path, query, fragment, and redirect-shaped origins', () => {
  for (const origin of [
    '*', 'https://*.example.test', 'https://example.test*',
    'http://example.test', 'https://example.test/path',
    'https://example.test?next=https://other.test',
    'https://example.test#fragment', 'https://example.test@other.test',
    'https://example.test\\@other.test',
  ]) {
    const input = policyInput()
    input.allowed_origins = [origin]
    assert.throws(() => createUnleashDeploymentPolicy(input), origin)
  }
  for (const origins of [[], ['https://example.test', 'https://example.test']]) {
    assert.throws(() => createUnleashDeploymentPolicy({ ...policyInput(), allowed_origins: origins }))
  }
})

test('a previously allowed source origin does not authorize a redirect destination', () => {
  const policy = createUnleashDeploymentPolicy(policyInput())
  assert.doesNotThrow(() => assertPolicyAllowsTarget(policy, target(), checkOptions()))
  assert.throws(() => assertPolicyAllowsTarget(policy, target('https://other.test/'), checkOptions()))

  const forged = { ...target(), canonical_locator: 'https://other.test/' }
  assert.throws(() => assertPolicyAllowsTarget(policy, forged, checkOptions()))
})

test('checks the current validity window at admission, including exact boundaries', () => {
  const policy = createUnleashDeploymentPolicy(policyInput())
  for (const instant of [VALID_FROM, '2026-09-15T09:59:59.999Z']) {
    assert.doesNotThrow(() => assertPolicyAllowsTarget(
      policy, target(), checkOptions({ now: new Date(instant) }),
    ))
  }
  for (const instant of ['2026-09-15T08:59:59.999Z', VALID_UNTIL, '2026-09-16T09:30:00.000Z']) {
    assert.throws(() => assertPolicyAllowsTarget(
      policy, target(), checkOptions({ now: new Date(instant) }),
    ), instant)
  }
  assert.throws(() => assertPolicyAllowsTarget(
    policy, target(), checkOptions({ now: new Date(Number.NaN) }),
  ))
})

test('rejects absent, invalid, empty, or reversed validity windows', () => {
  for (const change of [
    { valid_from: undefined }, { valid_until: undefined },
    { valid_from: 'not-a-time' }, { valid_until: '2026-02-30T10:00:00.000Z' },
    { valid_from: VALID_UNTIL }, { valid_until: VALID_FROM },
    { valid_from: '2026-09-16T09:00:00.000Z' },
  ]) {
    assert.throws(() => createUnleashDeploymentPolicy({ ...policyInput(), ...change }))
  }
})

test('checks revocation again for every admission and fails after withdrawal', () => {
  const policy = createUnleashDeploymentPolicy(policyInput())
  let revoked = false
  let checks = 0
  const options = checkOptions({ isRevoked: () => { checks += 1; return revoked } })

  assert.doesNotThrow(() => assertPolicyAllowsTarget(policy, target(), options))
  assert.doesNotThrow(() => assertPolicyAllowsTarget(policy, target(), options))
  assert.equal(checks, 2)
  revoked = true
  assert.throws(() => assertPolicyAllowsTarget(policy, target(), options))
  assert.equal(checks, 3)
})

test('fails closed when the revocation check is missing, unavailable, or indeterminate', () => {
  const policy = createUnleashDeploymentPolicy(policyInput())
  for (const isRevoked of [undefined, null, false, () => undefined, () => null, () => 'false', () => ({ revoked: false })]) {
    assert.throws(() => assertPolicyAllowsTarget(policy, target(), checkOptions({ isRevoked })))
  }
  assert.throws(() => assertPolicyAllowsTarget(policy, target(), checkOptions({
    isRevoked: () => { throw new Error('revocation source unavailable') },
  })))
  assert.throws(() => createUnleashDeploymentPolicy({
    ...policyInput(), revocation: { check_id: 'revocation:unit-test', fail_mode: 'OPEN' },
  }))
})

test('requires explicit bounded effect and target-family allowlists', () => {
  for (const change of [
    { allowed_effects: [] }, { allowed_effects: ['*'] },
    { allowed_effects: ['OBSERVE', 'OBSERVE'] },
    { allowed_effects: ['OBSERVE', 'PROVIDER_DEFINED_EFFECT'] },
    { allowed_target_families: [] }, { allowed_target_families: ['*'] },
    { allowed_target_families: ['https', 'https'] },
  ]) {
    assert.throws(() => createUnleashDeploymentPolicy({ ...policyInput(), ...change }))
  }
  const policy = createUnleashDeploymentPolicy(policyInput())
  assert.throws(() => assertPolicyAllowsTarget(policy, { ...target(), family: 'database' }, checkOptions()))
})

test('defaults to a context-selected automatic detection policy and rejects evasion profiles', () => {
  const policy = createUnleashDeploymentPolicy(policyInput())
  assert.deepEqual(policy.detection, DEFAULT_UNLEASH_DETECTION_POLICY)

  for (const noiseProfile of ['STEALTH', 'STEALTHY', 'EVASIVE', 'BYPASS']) {
    assert.throws(() => createUnleashDeploymentPolicy({
      ...policyInput(),
      detection: {
        ...DEFAULT_UNLEASH_DETECTION_POLICY,
        noise_profile: noiseProfile,
      },
    }), noiseProfile)
  }
})

test('accepts only exact controller-owned detection settings', () => {
  const configured = createUnleashDeploymentPolicy({
    ...policyInput(),
    detection: {
      noise_profile: 'BALANCED',
      target_environment: 'PRE_PRODUCTION',
      risk_tolerance: 'MODERATE',
      confirmation_mode: 'REQUIRED',
    },
  })
  assert.equal(configured.detection.noise_profile, 'BALANCED')
  assert.equal(Object.isFrozen(configured.detection), true)

  for (const detection of [
    null,
    {},
    { ...DEFAULT_UNLEASH_DETECTION_POLICY, confirmation_mode: 'OPTIONAL' },
    { ...DEFAULT_UNLEASH_DETECTION_POLICY, target_environment: 'MYSTERY' },
    { ...DEFAULT_UNLEASH_DETECTION_POLICY, risk_tolerance: 'UNBOUNDED' },
    { ...DEFAULT_UNLEASH_DETECTION_POLICY, extra: true },
  ]) {
    assert.throws(() => createUnleashDeploymentPolicy({ ...policyInput(), detection }))
  }
})

test('selects an explicit or automatic operational profile from immutable target posture', () => {
  const automatic = selectUnleashDetectionProfile(
    createUnleashDeploymentPolicy(policyInput()),
  )
  assert.deepEqual(automatic, {
    configured_profile: 'AUTO',
    operational_profile: 'balanced',
    selection_reason: 'AUTO_UNKNOWN_POSTURE_BALANCED',
  })

  const cases = [
    [{ noise_profile: 'AGGRESSIVE' }, 'aggressive', 'CONTROLLER_POLICY_EXPLICIT'],
    [{ noise_profile: 'BALANCED' }, 'balanced', 'CONTROLLER_POLICY_EXPLICIT'],
    [{ noise_profile: 'CAUTIOUS' }, 'cautious', 'CONTROLLER_POLICY_EXPLICIT'],
    [{ target_environment: 'LAB', risk_tolerance: 'HIGH' }, 'aggressive', 'AUTO_LAB_HIGH_TOLERANCE'],
    [{ target_environment: 'PRE_PRODUCTION', risk_tolerance: 'MODERATE' }, 'balanced', 'AUTO_PRE_PRODUCTION_MODERATE_TOLERANCE'],
  ]
  for (const [overrides, operationalProfile, selectionReason] of cases) {
    const policy = createUnleashDeploymentPolicy({
      ...policyInput(),
      detection: { ...DEFAULT_UNLEASH_DETECTION_POLICY, ...overrides },
    })
    assert.deepEqual(selectUnleashDetectionProfile(policy), {
      configured_profile: policy.detection.noise_profile,
      operational_profile: operationalProfile,
      selection_reason: selectionReason,
    })
  }
})

test('binds new detection policy digests and defaults legacy campaign digests automatically', () => {
  const explicit = createUnleashDeploymentPolicy({
    ...policyInput(),
    detection: {
      noise_profile: 'AGGRESSIVE',
      target_environment: 'LAB',
      risk_tolerance: 'HIGH',
      confirmation_mode: 'REQUIRED',
    },
  })
  const current = resolveUnleashDetectionPolicyBinding(
    explicit,
    projectUnleashPolicy(explicit).policy_sha256,
  )
  assert.equal(current.binding, 'DETECTION_POLICY_BOUND')
  assert.equal(current.selection.operational_profile, 'aggressive')

  const { detection: ignoredDetection, ...legacyPolicy } = explicit
  const legacy = resolveUnleashDetectionPolicyBinding(
    explicit,
    digestUnleashValue(legacyPolicy),
  )
  assert.equal(legacy.binding, 'LEGACY_POLICY_DEFAULTED')
  assert.equal(legacy.selection.operational_profile, 'balanced')
  assert.equal(legacy.detection.target_environment, 'UNKNOWN')
  assert.throws(
    () => resolveUnleashDetectionPolicyBinding(explicit, '0'.repeat(64)),
    (error) => error?.code === 'UNLEASH_POLICY_PLAN_DRIFT',
  )
})

test('requires one declared allowed effect for every action admission', () => {
  const policy = createUnleashDeploymentPolicy(policyInput())
  assert.doesNotThrow(() => assertPolicyAllowsTarget(
    policy, target(), checkOptions({ effect: 'OBSERVE' }),
  ))
  for (const effect of [undefined, null, '', 'PROBE', 'EXECUTE_PROOF', 'PROVIDER_DEFINED_EFFECT']) {
    assert.throws(() => assertPolicyAllowsTarget(
      policy, target(), checkOptions({ effect }),
    ))
  }
})

test('rejects missing, noninteger, nonfinite, zero, negative, and oversized budgets', () => {
  const maxima = {
    max_actions: 1_000_000,
    max_parallel_actions: 1024,
    max_duration_ms: 604_800_000,
    max_response_bytes: 1_073_741_824,
  }
  for (const [field, maximum] of Object.entries(maxima)) {
    for (const value of [undefined, 0, -1, 1.5, Number.NaN, Infinity, '1', maximum + 1]) {
      const input = policyInput()
      input.budgets[field] = value
      assert.throws(() => createUnleashDeploymentPolicy(input), `${field} must reject ${String(value)}`)
    }
  }
  const input = policyInput()
  input.budgets.provider_limit = 1
  assert.throws(() => createUnleashDeploymentPolicy(input))
})

test('detaches and freezes policy state so caller-owned input cannot broaden it', () => {
  const input = policyInput()
  const policy = createUnleashDeploymentPolicy(input)
  const before = projectUnleashPolicy(policy)
  const saved = structuredClone(before)
  input.allowed_origins.push('https://other.test')
  input.allowed_effects.push('PROVIDER_DEFINED_EFFECT')
  input.budgets.max_actions = 999_999
  input.revocation.fail_mode = 'OPEN'

  assert.deepEqual(projectUnleashPolicy(policy), saved)
  assert.throws(() => assertPolicyAllowsTarget(policy, target('https://other.test/'), checkOptions()))
  assert.equal(Object.isFrozen(policy), true)
  assert.equal(Object.isFrozen(policy.allowed_origins), true)
  assert.equal(Object.isFrozen(policy.budgets), true)
  assert.throws(() => { policy.allowed_origins.push('https://other.test') }, TypeError)
})

test('rejects target-supplied policy, effects, budgets, credentials, and redirect authority', () => {
  const policy = createUnleashDeploymentPolicy(policyInput())
  const before = structuredClone(projectUnleashPolicy(policy))
  for (const change of [
    { policy: policyInput() }, { allowed_origins: ['https://other.test'] },
    { allowed_effects: ['OBSERVE'] }, { budgets: { max_actions: 999_999 } },
    { credential_references: ['credential:browser:other'] },
    { redirect_to: 'https://other.test' },
  ]) {
    assert.throws(() => assertPolicyAllowsTarget(policy, { ...target(), ...change }, checkOptions()))
    assert.deepEqual(projectUnleashPolicy(policy), before)
  }
})

test('projects only public policy fields, opaque credential references, and a stable digest', () => {
  const input = policyInput()
  const first = projectUnleashPolicy(createUnleashDeploymentPolicy(input))
  const second = projectUnleashPolicy(createUnleashDeploymentPolicy(structuredClone(input)))

  assert.deepEqual(second, first)
  assert.match(first.policy_sha256, /^[a-f0-9]{64}$/)
  assert.deepEqual(first.credential_references, ['credential:browser:primary'])
  assert.deepEqual(first.budgets, input.budgets)
  assert.equal(first.valid_from, VALID_FROM)
  assert.equal(first.valid_until, VALID_UNTIL)
  assert.deepEqual(
    Object.keys(first).sort(),
    [...Object.keys(input), 'detection', 'policy_sha256'].sort(),
  )

  const changed = policyInput()
  changed.credential_references = ['credential:browser:secondary']
  assert.notEqual(projectUnleashPolicy(createUnleashDeploymentPolicy(changed)).policy_sha256, first.policy_sha256)
})

test('refuses credential values instead of accepting and later redacting them', () => {
  const canary = 'synthetic-unit-test-value-not-a-credential'
  for (const change of [
    { credential_value: canary }, { credentials: { token: canary } },
    { credential_references: [{ reference: 'credential:browser:primary', value: canary }] },
    { credential_references: [`Bearer ${canary}`] },
  ]) {
    assert.throws(() => createUnleashDeploymentPolicy({ ...policyInput(), ...change }))
  }
  const input = policyInput()
  input.revocation.credential_value = canary
  assert.throws(() => createUnleashDeploymentPolicy(input))
  const policy = createUnleashDeploymentPolicy(policyInput())
  assert.equal(JSON.stringify(projectUnleashPolicy(policy)).includes(canary), false)
})
