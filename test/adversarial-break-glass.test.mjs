import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync } from 'node:crypto'
import {
  L3_MANDATORY_ESCALATION_TRIGGERS,
  L3_PREFLIGHT_FLAGS,
  L3_PROHIBITED_EFFECTS,
  digestAdversarialPlan,
} from '../scripts/lib/adversarial-validation-contracts.mjs'
import {
  OPERATOR_AUTHORIZATION_KIND,
  OPERATOR_AUTHORIZATION_STATUS,
  OPERATOR_CAMPAIGN_AUTHORIZATION_STATEMENT,
  verifyBoundOperatorAuthorization,
} from '../scripts/lib/operator-authorization.mjs'
import {
  BREAK_GLASS_NON_OVERRIDABLE_PREFLIGHT_FLAGS,
  BREAK_GLASS_WAIVABLE_PREFLIGHT_FLAGS,
  AdversarialBreakGlassContractError,
  createAdversarialBreakGlassOverride,
  evaluateL3PreflightWithBreakGlass,
  validateAdversarialBreakGlassOverride,
  verifyAdversarialBreakGlassOverride,
} from '../scripts/lib/adversarial-break-glass-contracts.mjs'

const SHA_B = 'b'.repeat(64)
const SHA_C = 'c'.repeat(64)
const SHA_D = 'd'.repeat(64)

function maximumPlan() {
  const applicability = { field: '/target/kind', operator: 'equals', value: 'live' }
  const preflight = Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true]))
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-plan',
    plan_id: 'plan:maximum-authorized-001',
    engagement_id: 'engagement:estate-001',
    scope_revision_sha256: SHA_B,
    candidate_id: 'candidate:adaptive-campaign-001',
    target: {
      kind: 'live',
      target_id: 'target:authorized-estate',
      locator: 'https://example.test',
      identity_sha256: SHA_C,
    },
    strategy_id: 'campaign.adaptive/multi-strategy-v1',
    risk_class: 'READ_ONLY',
    autonomy_profile: 'L3_MAXIMUM_AUTHORIZED',
    attack: {
      id: 'attack:adaptive-chain',
      description: 'Select and chain bounded adversarial actions inside the signed estate envelope.',
      expected_observation: 'A security invariant is violated under a reproducible action chain.',
    },
    control: {
      id: 'control:campaign-baseline',
      description: 'Run matched controls for each promoted vulnerability hypothesis.',
      expected_observation: 'The harness and expected authorized behavior remain valid.',
    },
    oracle: {
      id: 'oracle:campaign-evidence',
      confirmation_condition: 'A minimized attack reproduces while its matched control remains valid.',
      inconclusive_condition: 'The control fails, scope is ambiguous, or impact attribution is incomplete.',
    },
    limits: {
      max_actions: 20,
      max_wall_time_ms: 600_000,
      max_action_time_ms: 30_000,
      max_input_bytes: 65_536,
      max_output_bytes: 65_536,
      max_aggregate_output_bytes: 1_048_576,
      max_concurrency: 2,
      min_action_interval_ms: 100,
    },
    actions: [
      {
        action_id: 'action:control-001',
        purpose: 'control',
        action_category: 'http.control',
        operation: 'http.request',
        parameters: { method: 'GET', url: 'https://example.test/health' },
      },
      {
        action_id: 'action:attack-001',
        purpose: 'attack',
        action_category: 'http.adversarial',
        operation: 'http.request',
        parameters: { method: 'GET', url: 'https://example.test/synthetic-test' },
      },
    ],
    preflight,
    campaign_envelope: {
      envelope_id: 'campaign:estate-001',
      allowed_operations: ['http.request'],
      allowed_action_categories: ['http.control', 'http.adversarial'],
      allowed_strategy_families: ['multi-strategy-testing'],
      applicability_conditions: [applicability],
      decision_rules: [{
        rule_id: 'rule:authorized-live-http',
        when_all: [applicability],
        authorize: {
          operations: ['http.request'],
          action_categories: ['http.control', 'http.adversarial'],
          strategy_families: ['multi-strategy-testing'],
        },
      }],
      max_actions: 20,
      max_chain_depth: 8,
      checkpoint_policy: {
        interval_actions: 2,
        max_resume_count: 10,
        require_current_authorization: true,
        require_runtime_preflight: true,
      },
      mandatory_escalation_triggers: [...L3_MANDATORY_ESCALATION_TRIGGERS],
      prohibited_effects: [...L3_PROHIBITED_EFFECTS],
    },
  }
}

function keyFixture({
  approverId = 'operator:security-executive',
  role = 'SECURITY_EXECUTIVE',
  delegations = ['break_glass'],
} = {}) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  const spki = publicKey.export({ type: 'spki', format: 'der' })
  const keyId = `ed25519:${createHash('sha256').update(spki).digest('hex')}`
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' })
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' })
  return {
    privateKey: privateKeyPem,
    publicKey: publicKeyPem,
    pinnedKey: {
      key_id: keyId,
      public_key: publicKeyPem,
      approver_id: approverId,
      approver_role: role,
      delegations,
    },
  }
}

function authorizationReceiptFor(plan, overrides = {}) {
  const verified = verifyBoundOperatorAuthorization({
    value: {
      schema_version: '1.0.0',
      kind: OPERATOR_AUTHORIZATION_KIND,
      status: OPERATOR_AUTHORIZATION_STATUS,
      operator_id: 'operator:owner',
      authorization_reference: 'authorization:maximum-authorized-001',
      statement: OPERATOR_CAMPAIGN_AUTHORIZATION_STATEMENT,
      declared_at: '2026-09-03T10:00:00.000Z',
      target: structuredClone(plan.target),
      plan_sha256: digestAdversarialPlan(plan),
      scope_revision_sha256: plan.scope_revision_sha256,
    },
    planSha256: digestAdversarialPlan(plan),
    scopeRevisionSha256: plan.scope_revision_sha256,
    target: plan.target,
    now: '2026-09-03T10:05:00.000Z',
    fail(code, message) {
      const error = new Error(message)
      error.code = code
      throw error
    },
  })
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-authorization-receipt',
    status: 'CONTROLLER_VERIFIED',
    authorization_id: verified.authorization_reference,
    authorization_reference: verified.authorization_reference,
    authorization_sha256: verified.authorization_sha256,
    authority_basis: verified.authority_basis,
    operator_id: verified.operator_id,
    plan_sha256: verified.plan_sha256,
    engagement_id: plan.engagement_id,
    scope_revision_sha256: verified.scope_revision_sha256,
    target_sha256: verified.target_sha256,
    risk_class: plan.risk_class,
    autonomy_profile: plan.autonomy_profile,
    declared_at: verified.declared_at,
    expires_at: '2026-09-03T10:15:00.000Z',
    ...overrides,
  }
}

function nonceStore() {
  const used = new Set()
  return {
    consume({ nonce_sha256: digest }) {
      if (used.has(digest)) return false
      used.add(digest)
      return true
    },
  }
}

function overrideFor(plan, authorizationReceipt, key, overrides = {}) {
  return createAdversarialBreakGlassOverride({
    plan,
    authorizationReceipt,
    overrideId: 'break-glass:estate-001',
    failedControls: [{
      control: 'target_health_monitoring',
      status: 'UNAVAILABLE',
      observation_sha256: SHA_D,
    }],
    rationale: 'The isolated exercise network has no compatible health telemetry endpoint.',
    incidentReference: 'change:SEC-2026-0903',
    compensatingLimits: {
      max_actions: 2,
      max_wall_time_ms: 60_000,
      max_aggregate_output_bytes: 131_072,
      max_concurrency: 1,
    },
    issuedAt: '2026-09-03T10:04:00.000Z',
    expiresAt: '2026-09-03T10:14:00.000Z',
    nonce: 'BREAK_GLASS_NONCE_0001',
    approver: { id: 'operator:security-executive', role: 'SECURITY_EXECUTIVE' },
    privateKey: key.privateKey,
    ...overrides,
  })
}

test('a signed short-lived override waives only its named runtime preflight failure', () => {
  const plan = maximumPlan()
  const authorizationReceipt = authorizationReceiptFor(plan)
  const key = keyFixture()
  const override = overrideFor(plan, authorizationReceipt, key)
  assert.equal(validateAdversarialBreakGlassOverride(override).valid, true)
  assert.equal(override.authorization_id, authorizationReceipt.authorization_id)
  assert.equal(override.authorization_sha256, authorizationReceipt.authorization_sha256)
  assert.equal(Object.hasOwn(override, 'approval_id'), false)
  assert.equal(Object.hasOwn(override, 'approval_sha256'), false)

  const runtimePreflight = Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true]))
  runtimePreflight.target_health_monitoring = false
  runtimePreflight.control_observations = {
    target_health_monitoring: {
      status: 'UNAVAILABLE',
      observation_sha256: SHA_D,
    },
  }
  const result = evaluateL3PreflightWithBreakGlass({
    plan,
    authorizationReceipt,
    runtimePreflight,
    override,
    pinnedKey: key.pinnedKey,
    now: '2026-09-03T10:05:00.000Z',
    nonceStore: nonceStore(),
  })

  assert.equal(result.allowed, true)
  assert.equal(result.mode, 'BREAK_GLASS')
  assert.deepEqual(result.waived_controls, ['target_health_monitoring'])
  assert.deepEqual(result.effective_limits, override.compensating_limits)
  assert.equal(result.override_receipt.plan_sha256, digestAdversarialPlan(plan))
})

test('there is no unsigned boolean, password, or environment-style preflight bypass', () => {
  const plan = maximumPlan()
  const authorizationReceipt = authorizationReceiptFor(plan)
  const runtimePreflight = Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true]))
  runtimePreflight.target_health_monitoring = false
  runtimePreflight.control_observations = {
    target_health_monitoring: {
      status: 'UNAVAILABLE',
      observation_sha256: SHA_D,
    },
  }
  for (const override of [true, 'BREAK_GLASS', { override: true }, { token: 'BREAK_GLASS' }]) {
    const result = evaluateL3PreflightWithBreakGlass({
      plan,
      authorizationReceipt,
      runtimePreflight,
      override,
      now: '2026-09-03T10:05:00.000Z',
    })
    assert.equal(result.allowed, false)
    assert.match(
      result.reasons.join(' '),
      /BREAK_GLASS_OVERRIDE_REQUIRED|BREAK_GLASS_INVALID/,
    )
  }
})

test('authority, impact, evidence, credentials, and operator controls are hardcoded non-waivable', () => {
  assert.deepEqual(BREAK_GLASS_NON_OVERRIDABLE_PREFLIGHT_FLAGS, [
    'external_scope_enforcement',
    'impact_classification',
    'finite_budgets',
    'append_only_evidence_capture',
    'operator_kill_switch',
    'control_plane_loss_failsafe',
    'credential_isolation',
  ])
  assert.deepEqual(BREAK_GLASS_WAIVABLE_PREFLIGHT_FLAGS, [
    'target_health_monitoring',
    'cleanup_or_rollback',
  ])

  const plan = maximumPlan()
  const authorizationReceipt = authorizationReceiptFor(plan)
  const key = keyFixture()
  for (const control of BREAK_GLASS_NON_OVERRIDABLE_PREFLIGHT_FLAGS) {
    assert.throws(
      () => overrideFor(plan, authorizationReceipt, key, {
        failedControls: [{ control, status: 'UNAVAILABLE', observation_sha256: SHA_D }],
      }),
      (error) => error instanceof AdversarialBreakGlassContractError
        && error.code === 'BREAK_GLASS_CONTROL_NON_OVERRIDABLE',
      control,
    )
  }
})

test('compensating limits may only narrow the already approved plan limits', () => {
  const plan = maximumPlan()
  const authorizationReceipt = authorizationReceiptFor(plan)
  const key = keyFixture()
  assert.throws(
    () => overrideFor(plan, authorizationReceipt, key, {
      compensatingLimits: {
        max_actions: plan.limits.max_actions + 1,
        max_wall_time_ms: 60_000,
        max_aggregate_output_bytes: 131_072,
        max_concurrency: 1,
      },
    }),
    (error) => error.code === 'BREAK_GLASS_LIMIT_EXPANSION',
  )
  assert.throws(
    () => overrideFor(plan, authorizationReceipt, key, {
      compensatingLimits: {
        max_actions: plan.limits.max_actions,
        max_wall_time_ms: plan.limits.max_wall_time_ms,
        max_aggregate_output_bytes: plan.limits.max_aggregate_output_bytes,
        max_concurrency: plan.limits.max_concurrency,
      },
    }),
    (error) => error.code === 'BREAK_GLASS_LIMIT_NOT_MATERIAL',
  )

  assert.throws(
    () => overrideFor(plan, authorizationReceipt, key, {
      compensatingLimits: {
        max_actions: plan.limits.max_actions - 1,
        max_wall_time_ms: plan.limits.max_wall_time_ms - 1,
        max_aggregate_output_bytes: plan.limits.max_aggregate_output_bytes - 1,
        max_concurrency: 1,
      },
    }),
    (error) => error.code === 'BREAK_GLASS_LIMIT_NOT_MATERIAL',
    'one-unit reductions are not material compensation',
  )
})

test('operational waivers are refused for every non-read-only plan', () => {
  for (const riskClass of [
    'STATE_CHANGE',
    'SENSITIVE_DATA',
    'AVAILABILITY_IMPACT',
    'IRREVERSIBLE_CHANGE',
    'PERSISTENCE',
    'LATERAL_MOVEMENT',
  ]) {
    const plan = maximumPlan()
    plan.risk_class = riskClass
    const authorizationReceipt = authorizationReceiptFor(plan)
    const key = keyFixture()
    assert.throws(
      () => overrideFor(plan, authorizationReceipt, key),
      (error) => error.code === 'BREAK_GLASS_CONTROL_RISK_INCOMPATIBLE',
      riskClass,
    )
  }
})

test('break glass cannot claim more actions than the authorized campaign envelope', () => {
  const plan = maximumPlan()
  plan.campaign_envelope.max_actions = 4
  plan.campaign_envelope.max_chain_depth = 4
  const authorizationReceipt = authorizationReceiptFor(plan)
  const key = keyFixture()
  assert.throws(
    () => overrideFor(plan, authorizationReceipt, key, {
      compensatingLimits: {
        max_actions: 5,
        max_wall_time_ms: 60_000,
        max_aggregate_output_bytes: 131_072,
        max_concurrency: 1,
      },
    }),
    (error) => error.code === 'BREAK_GLASS_LIMIT_EXPANSION',
  )
})

test('tampering, plan drift, expiry, missing delegation, and replay fail closed', () => {
  const plan = maximumPlan()
  const authorizationReceipt = authorizationReceiptFor(plan)
  const key = keyFixture()
  const override = overrideFor(plan, authorizationReceipt, key)

  const tampered = structuredClone(override)
  tampered.rationale += ' Changed after signing.'
  assert.throws(
    () => verifyAdversarialBreakGlassOverride({
      plan, authorizationReceipt,
      override: tampered, pinnedKey: key.pinnedKey,
      now: '2026-09-03T10:05:00.000Z', nonceStore: nonceStore(),
    }),
    (error) => error.code === 'BREAK_GLASS_SIGNATURE_INVALID',
  )

  const drifted = structuredClone(plan)
  drifted.target.locator = 'https://other.example.test'
  assert.throws(
    () => verifyAdversarialBreakGlassOverride({
      plan: drifted, authorizationReceipt,
      override, pinnedKey: key.pinnedKey,
      now: '2026-09-03T10:05:00.000Z', nonceStore: nonceStore(),
    }),
    (error) => error.code === 'BREAK_GLASS_PLAN_MISMATCH',
  )

  assert.throws(
    () => verifyAdversarialBreakGlassOverride({
      plan, authorizationReceipt,
      override, pinnedKey: key.pinnedKey,
      now: override.expires_at, nonceStore: nonceStore(),
    }),
    (error) => error.code === 'BREAK_GLASS_EXPIRED',
  )

  assert.throws(
    () => verifyAdversarialBreakGlassOverride({
      plan, authorizationReceipt,
      override,
      pinnedKey: { ...key.pinnedKey, delegations: ['attack_plan'] },
      now: '2026-09-03T10:05:00.000Z', nonceStore: nonceStore(),
    }),
    (error) => error.code === 'BREAK_GLASS_DELEGATION_REQUIRED',
  )

  const store = nonceStore()
  verifyAdversarialBreakGlassOverride({
    plan, authorizationReceipt,
    override, pinnedKey: key.pinnedKey,
    now: '2026-09-03T10:05:00.000Z', nonceStore: store,
  })
  assert.throws(
    () => verifyAdversarialBreakGlassOverride({
      plan, authorizationReceipt,
      override, pinnedKey: key.pinnedKey,
      now: '2026-09-03T10:05:00.000Z', nonceStore: store,
    }),
    (error) => error.code === 'BREAK_GLASS_REPLAY',
  )
})

test('the override is short-lived and must exactly disclose every waived failure', () => {
  const plan = maximumPlan()
  const authorizationReceipt = authorizationReceiptFor(plan)
  const key = keyFixture()
  assert.throws(
    () => overrideFor(plan, authorizationReceipt, key, {
      expiresAt: '2026-09-03T10:19:00.001Z',
    }),
    (error) => error.code === 'BREAK_GLASS_WINDOW_TOO_LONG',
  )

  const runtimePreflight = Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true]))
  runtimePreflight.target_health_monitoring = false
  runtimePreflight.credential_isolation = false
  runtimePreflight.control_observations = {
    target_health_monitoring: {
      status: 'UNAVAILABLE',
      observation_sha256: SHA_D,
    },
    credential_isolation: {
      status: 'FAILED',
      observation_sha256: SHA_C,
    },
  }
  const result = evaluateL3PreflightWithBreakGlass({
    plan,
    authorizationReceipt,
    runtimePreflight,
    override: overrideFor(plan, authorizationReceipt, key),
    pinnedKey: key.pinnedKey,
    now: '2026-09-03T10:05:00.000Z',
    nonceStore: nonceStore(),
  })
  assert.equal(result.allowed, false)
  assert.ok(result.reasons.includes('NON_OVERRIDABLE_RUNTIME_PREFLIGHT:credential_isolation'))
})

test('break glass binds the signed status and observation for each failed control', () => {
  const plan = maximumPlan()
  const authorizationReceipt = authorizationReceiptFor(plan)
  const key = keyFixture()
  const runtimePreflight = Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true]))
  runtimePreflight.target_health_monitoring = false
  runtimePreflight.control_observations = {
    target_health_monitoring: {
      status: 'DEGRADED',
      observation_sha256: SHA_C,
    },
  }
  const result = evaluateL3PreflightWithBreakGlass({
    plan,
    authorizationReceipt,
    runtimePreflight,
    override: overrideFor(plan, authorizationReceipt, key),
    pinnedKey: key.pinnedKey,
    now: '2026-09-03T10:05:00.000Z',
    nonceStore: nonceStore(),
  })
  assert.equal(result.allowed, false)
  assert.deepEqual(result.reasons, [
    'BREAK_GLASS_FAILURE_EVIDENCE_CHANGED:target_health_monitoring',
  ])
})

test('array subclasses, hidden properties, and unsigned symbols cannot affect override authority', () => {
  const plan = maximumPlan()
  const authorizationReceipt = authorizationReceiptFor(plan)
  const key = keyFixture()
  const valid = overrideFor(plan, authorizationReceipt, key)

  class LyingArray extends Array {
    includes() { return true }
    map() { return [] }
  }
  const subclassed = structuredClone(valid)
  subclassed.waived_controls = new LyingArray(...subclassed.waived_controls)
  assert.equal(validateAdversarialBreakGlassOverride(subclassed).valid, false)

  const symbolled = structuredClone(valid)
  symbolled.failed_controls[Symbol('unsigned waiver')] = 'operator_kill_switch'
  assert.equal(validateAdversarialBreakGlassOverride(symbolled).valid, false)

  const hidden = structuredClone(valid)
  Object.defineProperty(hidden.failed_controls, 'bypass', { value: true })
  assert.equal(validateAdversarialBreakGlassOverride(hidden).valid, false)
})

test('a controller authorization receipt cannot be laundered across plan, target, or scope bindings', () => {
  const plan = maximumPlan()
  const authorizationReceipt = authorizationReceiptFor(plan)
  const key = keyFixture()
  const override = overrideFor(plan, authorizationReceipt, key)

  for (const forgedReceipt of [
    { ...authorizationReceipt, plan_sha256: '0'.repeat(64) },
    { ...authorizationReceipt, target_sha256: '0'.repeat(64) },
    { ...authorizationReceipt, scope_revision_sha256: '0'.repeat(64) },
    { ...authorizationReceipt, authorization_sha256: '0'.repeat(64) },
  ]) {
    assert.throws(
      () => verifyAdversarialBreakGlassOverride({
        plan,
        authorizationReceipt: forgedReceipt,
        override,
        pinnedKey: key.pinnedKey,
        now: '2026-09-03T10:05:00.000Z',
        nonceStore: nonceStore(),
      }),
      (error) => error.code === 'BREAK_GLASS_AUTHORIZATION_MISMATCH',
    )
  }
})

test('healthy L3 preflight still requires the exact controller-verified authorization receipt', () => {
  const plan = maximumPlan()
  const authorizationReceipt = authorizationReceiptFor(plan)
  const runtimePreflight = Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true]))

  const missing = evaluateL3PreflightWithBreakGlass({
    plan,
    runtimePreflight,
    now: '2026-09-03T10:05:00.000Z',
  })
  assert.equal(missing.allowed, false)
  assert.deepEqual(missing.reasons, ['BREAK_GLASS_AUTHORIZATION_MISMATCH'])

  const legacyReceipt = { ...authorizationReceipt, approval_sha256: '0'.repeat(64) }
  const forged = evaluateL3PreflightWithBreakGlass({
    plan,
    authorizationReceipt: legacyReceipt,
    runtimePreflight,
    now: '2026-09-03T10:05:00.000Z',
  })
  assert.equal(forged.allowed, false)
  assert.deepEqual(forged.reasons, ['BREAK_GLASS_AUTHORIZATION_MISMATCH'])

  const healthy = evaluateL3PreflightWithBreakGlass({
    plan,
    authorizationReceipt,
    runtimePreflight,
    now: '2026-09-03T10:05:00.000Z',
  })
  assert.deepEqual(healthy, {
    allowed: true,
    reasons: [],
    mode: 'NORMAL',
    waived_controls: [],
  })
})

test('break-glass authority is pinned to the exact approver identity', () => {
  const plan = maximumPlan()
  const authorizationReceipt = authorizationReceiptFor(plan)
  const key = keyFixture()
  const override = overrideFor(plan, authorizationReceipt, key)

  assert.throws(
    () => verifyAdversarialBreakGlassOverride({
      plan,
      authorizationReceipt,
      override,
      pinnedKey: { ...key.pinnedKey, approver_id: 'operator:different' },
      now: '2026-09-03T10:05:00.000Z',
      nonceStore: nonceStore(),
    }),
    (error) => error.code === 'BREAK_GLASS_APPROVER_ID_MISMATCH',
  )
})
