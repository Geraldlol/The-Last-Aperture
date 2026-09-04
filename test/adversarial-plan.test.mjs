import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  BREAK_GLASS_NON_OVERRIDABLE_INVARIANTS,
  L3_PREFLIGHT_FLAGS,
  L3_MANDATORY_ESCALATION_TRIGGERS,
  L3_NON_OVERRIDABLE_PREFLIGHT_FLAGS,
  L3_PROHIBITED_EFFECTS,
  assertValidAdversarialPlan,
  canonicalAdversarialPlan,
  digestAdversarialCandidateFacts,
  digestAdversarialPlan,
  digestAdversarialTacticalAction,
  evaluateL3CampaignBoundary,
  evaluateL3RuntimePreflight,
  validateAdversarialPlan,
} from '../scripts/lib/adversarial-validation-contracts.mjs'

const SHA_B = 'b'.repeat(64)
const SHA_C = 'c'.repeat(64)
const SHA_D = 'd'.repeat(64)

function livePlan(overrides = {}) {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-plan',
    plan_id: 'plan:tenant-boundary-001',
    engagement_id: 'engagement:acme-2026-09',
    scope_revision_sha256: SHA_B,
    candidate_id: 'candidate:authz-object-level-001',
    target: {
      kind: 'live',
      target_id: 'target:api.example.test',
      locator: 'https://api.example.test',
      identity_sha256: SHA_C,
    },
    strategy_id: 'custom.authz/replay-v2',
    risk_class: 'STATE_CHANGE',
    autonomy_profile: 'L1_ASSISTED',
    attack: {
      id: 'attack:cross-tenant-read',
      description: 'Replay the authorized request with a different tenant object identifier.',
      expected_observation: 'The other tenant object is returned.',
    },
    control: {
      id: 'control:owned-object-read',
      description: 'Request an object owned by the synthetic test principal.',
      expected_observation: 'The owned synthetic object is returned.',
    },
    oracle: {
      id: 'oracle:tenant-object-disclosure',
      confirmation_condition: 'Attack returns the marked foreign object while the control validates the harness.',
      inconclusive_condition: 'The control fails or the response cannot be attributed to the requested object.',
    },
    limits: {
      max_actions: 4,
      max_wall_time_ms: 30_000,
      max_action_time_ms: 5_000,
      max_input_bytes: 4_096,
      max_output_bytes: 16_384,
      max_aggregate_output_bytes: 65_536,
      max_concurrency: 1,
      min_action_interval_ms: 100,
    },
    actions: [
      {
        action_id: 'action:control-001',
        purpose: 'control',
        action_category: 'authorization.control',
        operation: 'http.request',
        parameters: {
          method: 'GET',
          url: 'https://api.example.test/objects/SYNTHETIC_OWNED_OBJECT',
        },
      },
      {
        action_id: 'action:attack-001',
        purpose: 'attack',
        action_category: 'authorization.replay',
        operation: 'http.request',
        parameters: {
          method: 'GET',
          url: 'https://api.example.test/objects/SYNTHETIC_FOREIGN_OBJECT',
        },
      },
    ],
    ...overrides,
  }
}

function campaignEnvelope() {
  const liveCondition = {
    field: '/candidate/target_kind',
    operator: 'equals',
    value: 'live',
  }
  return {
    envelope_id: 'campaign:tenant-boundary-001',
    allowed_operations: ['http.request'],
    allowed_action_categories: ['authorization.control', 'authorization.replay'],
    allowed_strategy_families: ['authorization-testing'],
    applicability_conditions: [liveCondition],
    decision_rules: [
      {
        rule_id: 'rule:bounded-live-http',
        when_all: [liveCondition],
        authorize: {
          operations: ['http.request'],
          action_categories: ['authorization.control', 'authorization.replay'],
          strategy_families: ['authorization-testing'],
        },
      },
    ],
    max_actions: 4,
    max_chain_depth: 2,
    checkpoint_policy: {
      interval_actions: 2,
      max_resume_count: 3,
      require_current_authorization: true,
      require_runtime_preflight: true,
    },
    mandatory_escalation_triggers: [...L3_MANDATORY_ESCALATION_TRIGGERS],
    prohibited_effects: [...L3_PROHIBITED_EFFECTS],
  }
}

function controllerBoundaryInputs(planValue, runtimePreflight, overrides = {}) {
  const action = {
    action_id: 'action:adaptive-001',
    branch_id: 'branch:tenant-boundary',
    chain_depth: 1,
    purpose: 'attack',
    action_category: 'authorization.replay',
    operation: 'http.request',
    strategy_family: 'authorization-testing',
    parameters: { method: 'GET', path: '/objects/SYNTHETIC_FOREIGN_OBJECT' },
    ...(overrides.action ?? {}),
  }
  const controllerCandidateContext = overrides.controllerCandidateContext
    ?? { target_kind: 'live' }
  const planSha256 = digestAdversarialPlan(planValue)
  const authorizationReceipt = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-authorization-receipt',
    status: 'CONTROLLER_VERIFIED',
    authorization_id: 'authorization:l3-001',
    authorization_reference: 'authorization:l3-001',
    authorization_sha256: SHA_D,
    authority_basis: 'OPERATOR_DECLARATION_ACCEPTED_AS_FACT',
    plan_sha256: planSha256,
    engagement_id: planValue.engagement_id,
    scope_revision_sha256: planValue.scope_revision_sha256,
    target_sha256: SHA_C,
    operator_id: 'operator:owner',
    risk_class: planValue.risk_class,
    autonomy_profile: planValue.autonomy_profile,
    declared_at: '2026-09-03T10:00:00.000Z',
    expires_at: '2026-09-03T10:15:00.000Z',
    ...(overrides.authorizationReceipt ?? {}),
  }
  const currentAuthorization = {
    status: 'CURRENT',
    authorization_id: authorizationReceipt.authorization_id,
    plan_sha256: planSha256,
    revoked: false,
    scope_revision_sha256: planValue.scope_revision_sha256,
    stop_requested: false,
    ...(overrides.currentAuthorization ?? {}),
  }
  const controllerAuthorization = {
    status: 'AUTHORIZED',
    plan_sha256: planSha256,
    authorization_id: authorizationReceipt.authorization_id,
    scope_revision_sha256: planValue.scope_revision_sha256,
    action_sha256: digestAdversarialTacticalAction(action),
    candidate_facts_sha256: digestAdversarialCandidateFacts(controllerCandidateContext),
    target: structuredClone(planValue.target),
    risk_class: planValue.risk_class,
    effect_classification: {
      complete: true,
      effects: [],
    },
    ...(overrides.controllerAuthorization ?? {}),
  }
  return {
    plan: planValue,
    runtimePreflight,
    action,
    controllerCandidateContext,
    authorizationReceipt,
    currentAuthorization,
    controllerAuthorization,
    now: '2026-09-03T10:05:00.000Z',
    actionsUsed: overrides.actionsUsed ?? 0,
    chainDepth: overrides.chainDepth ?? action.chain_depth,
    resumeCount: overrides.resumeCount ?? 0,
    activeEscalationTriggers: overrides.activeEscalationTriggers ?? [],
  }
}

function deterministicGenerator() {
  return {
    generator_id: 'generator:fast-check-state-model',
    algorithm: 'fast-check',
    version: '4.3.0',
    generator_sha256: SHA_D,
    deterministic: true,
    seed: '424242',
    max_cases: 4,
    max_case_bytes: 1_024,
    insertion_points: ['request.object_id'],
    purposes: ['control', 'attack'],
    template: {
      action_category: 'authorization.replay',
      operation: 'http.request',
      parameters: { method: 'GET', path_template: '/objects/{request.object_id}' },
    },
  }
}

test('strategy-neutral plans accept repository, local_service, and live targets', () => {
  for (const kind of ['repository', 'local_service', 'live']) {
    const plan = livePlan({
      target: {
        ...livePlan().target,
        kind,
        locator: kind === 'repository' ? 'repository://disposable-mirror' : livePlan().target.locator,
      },
    })
    assert.equal(validateAdversarialPlan(plan).valid, true, kind)
    assert.equal(assertValidAdversarialPlan(plan), plan)
  }

  assert.equal(livePlan().strategy_id, 'custom.authz/replay-v2')
})

test('canonical plan bytes and digest depend on content, not object insertion order', () => {
  const plan = livePlan()
  const reordered = Object.fromEntries(Object.entries(plan).reverse())
  reordered.target = Object.fromEntries(Object.entries(plan.target).reverse())
  reordered.limits = Object.fromEntries(Object.entries(plan.limits).reverse())
  reordered.actions = plan.actions.map((action) =>
    Object.fromEntries(Object.entries(action).reverse()))

  assert.equal(canonicalAdversarialPlan(plan), canonicalAdversarialPlan(reordered))
  assert.equal(digestAdversarialPlan(plan), digestAdversarialPlan(reordered))
  assert.match(digestAdversarialPlan(plan), /^[a-f0-9]{64}$/)

  const changed = structuredClone(plan)
  changed.actions[1].parameters.url += '?variant=1'
  assert.notEqual(digestAdversarialPlan(changed), digestAdversarialPlan(plan))
})

test('a live plan requires either finite exact actions or one bounded deterministic generator', () => {
  const absent = livePlan()
  delete absent.actions
  assert.equal(validateAdversarialPlan(absent).valid, false)

  const both = livePlan({ generator: deterministicGenerator() })
  assert.equal(validateAdversarialPlan(both).valid, false)

  const empty = livePlan({ actions: [] })
  assert.equal(validateAdversarialPlan(empty).valid, false)

  const generated = livePlan({ generator: deterministicGenerator() })
  delete generated.actions
  assert.equal(validateAdversarialPlan(generated).valid, true)

  for (const missing of ['deterministic', 'seed', 'max_cases', 'max_case_bytes', 'generator_sha256']) {
    const invalidGenerator = deterministicGenerator()
    delete invalidGenerator[missing]
    const invalid = livePlan({ generator: invalidGenerator })
    delete invalid.actions
    assert.equal(validateAdversarialPlan(invalid).valid, false, missing)
  }

  const unbounded = livePlan({ generator: deterministicGenerator() })
  delete unbounded.actions
  unbounded.generator.max_cases = unbounded.limits.max_actions + 1
  assert.equal(validateAdversarialPlan(unbounded).valid, false)
})

test('plans reject unknown fields, oversized content, unsafe strategy IDs, and invalid action sets', () => {
  assert.equal(validateAdversarialPlan(livePlan({ surprise: true })).valid, false)

  const oversized = livePlan()
  oversized.attack.description = 'x'.repeat(4_097)
  assert.equal(validateAdversarialPlan(oversized).valid, false)

  assert.equal(
    validateAdversarialPlan(livePlan({ strategy_id: 'shell; rm -rf workspace' })).valid,
    false,
  )

  const duplicate = livePlan()
  duplicate.actions[1].action_id = duplicate.actions[0].action_id
  assert.equal(validateAdversarialPlan(duplicate).valid, false)

  const overBudget = livePlan()
  overBudget.limits.max_actions = 1
  assert.equal(validateAdversarialPlan(overBudget).valid, false)

  const missingControl = livePlan({
    actions: livePlan().actions.filter((action) => action.purpose !== 'control'),
  })
  assert.equal(validateAdversarialPlan(missingControl).valid, false)

  const arrayProperty = livePlan()
  arrayProperty.actions.unhashed_metadata = 'must-not-be-dropped-by-canonical-json'
  assert.equal(validateAdversarialPlan(arrayProperty).valid, false)

  class AdversarialArray extends Array {
    includes() { return true }
    map(callback) { return super.map((value, index) => index === 0 ? value : callback(value, index, this)) }
  }
  const subclassed = livePlan()
  subclassed.actions = new AdversarialArray(...subclassed.actions)
  assert.equal(validateAdversarialPlan(subclassed).valid, false)

  const symbolProperty = livePlan()
  symbolProperty.actions[Symbol('unsigned authority')] = true
  assert.equal(validateAdversarialPlan(symbolProperty).valid, false)
})

test('L3_MAXIMUM_AUTHORIZED requires a bounded adaptive envelope and healthy runtime preflight', () => {
  assert.equal(validateAdversarialPlan(livePlan({ autonomy_profile: 'L1_ASSISTED' })).valid, true)
  assert.equal(validateAdversarialPlan(livePlan({ autonomy_profile: 'L2_SUPERVISED' })).valid, true)
  assert.equal(validateAdversarialPlan(livePlan({ autonomy_profile: 'L3_MAXIMUM_AUTHORIZED' })).valid, false)

  const allReady = Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true]))
  const ready = livePlan({
    autonomy_profile: 'L3_MAXIMUM_AUTHORIZED',
    preflight: allReady,
    campaign_envelope: campaignEnvelope(),
  })
  assert.deepEqual(validateAdversarialPlan(ready), { valid: true, errors: [] })

  const envelopeOnly = structuredClone(ready)
  delete envelopeOnly.actions
  assert.deepEqual(
    validateAdversarialPlan(envelopeOnly),
    { valid: true, errors: [] },
    'an L3 campaign envelope is bounded executable authority without preselected tactics',
  )

  const supervisedWithoutExecution = livePlan({ autonomy_profile: 'L2_SUPERVISED' })
  delete supervisedWithoutExecution.actions
  assert.equal(validateAdversarialPlan(supervisedWithoutExecution).valid, false)

  const unhealthy = structuredClone(ready)
  unhealthy.preflight.operator_kill_switch = false
  assert.equal(validateAdversarialPlan(unhealthy).valid, false)
  assert.throws(
    () => assertValidAdversarialPlan(unhealthy),
    /L3_MAXIMUM_AUTHORIZED|schema|preflight/i,
  )

  const unknown = structuredClone(ready)
  unknown.preflight.provider_self_approval = true
  assert.equal(validateAdversarialPlan(unknown).valid, false)

  const noEnvelope = structuredClone(ready)
  delete noEnvelope.campaign_envelope
  assert.equal(validateAdversarialPlan(noEnvelope).valid, false)

  const missingEscalation = structuredClone(ready)
  missingEscalation.campaign_envelope.mandatory_escalation_triggers.pop()
  assert.equal(validateAdversarialPlan(missingEscalation).valid, false)

  const excessiveEnvelope = structuredClone(ready)
  excessiveEnvelope.campaign_envelope.max_actions = ready.limits.max_actions + 1
  assert.equal(validateAdversarialPlan(excessiveEnvelope).valid, false)

  const excessiveExactSeeds = structuredClone(ready)
  excessiveExactSeeds.campaign_envelope.max_actions = 1
  excessiveExactSeeds.campaign_envelope.max_chain_depth = 1
  excessiveExactSeeds.campaign_envelope.checkpoint_policy.interval_actions = 1
  assert.equal(
    validateAdversarialPlan(excessiveExactSeeds).valid,
    false,
    'exact L3 seeds cannot exceed the campaign action cap',
  )

  const excessiveGenerator = structuredClone(ready)
  delete excessiveGenerator.actions
  excessiveGenerator.generator = deterministicGenerator()
  excessiveGenerator.campaign_envelope.max_actions = 2
  excessiveGenerator.campaign_envelope.max_chain_depth = 2
  excessiveGenerator.campaign_envelope.checkpoint_policy.interval_actions = 2
  assert.equal(
    validateAdversarialPlan(excessiveGenerator).valid,
    false,
    'deterministic L3 cases cannot exceed the campaign action cap',
  )

  assert.deepEqual(
    evaluateL3RuntimePreflight({ plan: ready, runtimePreflight: allReady }),
    { allowed: true, reasons: [] },
  )
  assert.equal(evaluateL3RuntimePreflight({
    plan: ready,
    runtimePreflight: { ...allReady, target_health_monitoring: false },
    breakGlass: true,
  }).allowed, false)
  assert.deepEqual(BREAK_GLASS_NON_OVERRIDABLE_INVARIANTS, [
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
  assert.equal(
    L3_NON_OVERRIDABLE_PREFLIGHT_FLAGS.includes('control_plane_loss_failsafe'),
    true,
  )

  assert.equal(evaluateL3CampaignBoundary(
    controllerBoundaryInputs(ready, allReady),
  ).allowed, true)
  assert.equal(evaluateL3CampaignBoundary(controllerBoundaryInputs(ready, allReady, {
    activeEscalationTriggers: ['TARGET_HEALTH_DEGRADATION'],
  })).allowed, false)
  assert.deepEqual(evaluateL3CampaignBoundary(controllerBoundaryInputs(ready, allReady, {
    action: { operation: 'process.spawn' },
  })), {
    allowed: false,
    reasons: ['OPERATION_OUTSIDE_CAMPAIGN_ENVELOPE'],
    disposition: 'QUEUE_SCOPE_EXPANSION_REQUEST',
    campaign_may_continue: true,
  })

  const checkpoint = evaluateL3CampaignBoundary(controllerBoundaryInputs(ready, allReady, {
    actionsUsed: 1,
  }))
  assert.equal(checkpoint.allowed, true)
  assert.equal(checkpoint.checkpoint_due, true)

  const missingFactPlan = structuredClone(ready)
  missingFactPlan.campaign_envelope.applicability_conditions[0].operator = 'not_equals'
  missingFactPlan.campaign_envelope.applicability_conditions[0].value = 'repository'
  missingFactPlan.campaign_envelope.decision_rules[0].when_all[0].operator = 'not_equals'
  missingFactPlan.campaign_envelope.decision_rules[0].when_all[0].value = 'repository'
  assert.equal(evaluateL3CampaignBoundary(controllerBoundaryInputs(
    missingFactPlan,
    allReady,
    { controllerCandidateContext: {} },
  )).allowed, false, 'missing predicate facts must fail closed even for not_equals')
})

test('L3 boundary binds the exact controller-authorized action, target facts, effects, and current authorization', () => {
  const allReady = Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true]))
  const ready = livePlan({
    autonomy_profile: 'L3_MAXIMUM_AUTHORIZED',
    preflight: allReady,
    campaign_envelope: campaignEnvelope(),
  })

  const actionDrift = controllerBoundaryInputs(ready, allReady)
  actionDrift.action.parameters.path = '/objects/DIFFERENT_AFTER_AUTHORIZATION'
  assert.deepEqual(evaluateL3CampaignBoundary(actionDrift), {
    allowed: false,
    reasons: ['CONTROLLER_ACTION_BINDING_MISMATCH'],
  })

  const factDrift = controllerBoundaryInputs(ready, allReady)
  factDrift.controllerCandidateContext.target_kind = 'repository'
  assert.deepEqual(evaluateL3CampaignBoundary(factDrift), {
    allowed: false,
    reasons: ['CONTROLLER_CANDIDATE_FACTS_MISMATCH'],
  })

  const prohibited = controllerBoundaryInputs(ready, allReady, {
    controllerAuthorization: {
      effect_classification: {
        complete: true,
        effects: ['PERSISTENCE'],
      },
    },
  })
  assert.deepEqual(evaluateL3CampaignBoundary(prohibited), {
    allowed: false,
    reasons: ['PROHIBITED_EFFECT_CLASSIFIED'],
    prohibited_effects: ['PERSISTENCE'],
  })

  const unknownEffect = controllerBoundaryInputs(ready, allReady, {
    controllerAuthorization: {
      effect_classification: {
        complete: true,
        effects: ['delete.records'],
      },
    },
  })
  assert.deepEqual(evaluateL3CampaignBoundary(unknownEffect), {
    allowed: false,
    reasons: ['UNKNOWN_EFFECT_CLASSIFIED'],
    unknown_effects: ['delete.records'],
  })

  const underclassified = controllerBoundaryInputs(ready, allReady, {
    controllerAuthorization: {
      effect_classification: {
        complete: true,
        effects: ['AVAILABILITY_IMPACT'],
      },
    },
  })
  assert.deepEqual(evaluateL3CampaignBoundary(underclassified), {
    allowed: false,
    reasons: ['EFFECT_RISK_UNDERCLASSIFIED'],
    minimum_risk_class: 'AVAILABILITY_IMPACT',
  })

  const incompleteEffects = controllerBoundaryInputs(ready, allReady, {
    controllerAuthorization: {
      effect_classification: { complete: false, effects: [] },
    },
  })
  assert.deepEqual(evaluateL3CampaignBoundary(incompleteEffects), {
    allowed: false,
    reasons: ['CONTROLLER_EFFECT_CLASSIFICATION_REQUIRED'],
  })

  const wrongTargetKind = controllerBoundaryInputs(ready, allReady, {
    controllerAuthorization: {
      target: {
        ...ready.target,
        kind: 'repository',
      },
    },
  })
  assert.deepEqual(evaluateL3CampaignBoundary(wrongTargetKind), {
    allowed: false,
    reasons: ['CONTROLLER_TARGET_BINDING_INVALID'],
  })

  const stale = controllerBoundaryInputs(ready, allReady, {
    currentAuthorization: { status: 'REVOKED' },
  })
  assert.deepEqual(evaluateL3CampaignBoundary(stale), {
    allowed: false,
    reasons: ['CURRENT_AUTHORIZATION_REQUIRED'],
  })

  const expired = controllerBoundaryInputs(ready, allReady, {
    authorizationReceipt: { expires_at: '2026-09-03T10:05:00.000Z' },
  })
  assert.deepEqual(evaluateL3CampaignBoundary(expired), {
    allowed: false,
    reasons: ['CURRENT_AUTHORIZATION_REQUIRED'],
  })

  const legacyLooseInputs = evaluateL3CampaignBoundary({
    plan: ready,
    runtimePreflight: allReady,
    operation: 'http.request',
    actionCategory: 'authorization.replay',
    strategyFamily: 'authorization-testing',
    candidateContext: { target_kind: 'live' },
    actionsUsed: 0,
    chainDepth: 1,
  })
  assert.equal(legacyLooseInputs.allowed, false)
  assert.match(legacyLooseInputs.reasons.join(' '), /CONTROLLER.*REQUIRED/)
})
