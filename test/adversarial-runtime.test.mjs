import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  L3_MANDATORY_ESCALATION_TRIGGERS,
  L3_PREFLIGHT_FLAGS,
  L3_PROHIBITED_EFFECTS,
  digestAdversarialPlan,
} from '../scripts/lib/adversarial-validation-contracts.mjs'
import { executeAdversarialCampaign } from '../scripts/lib/adversarial-runtime.mjs'
import { createAdversarialBreakGlassOverride } from '../scripts/lib/adversarial-break-glass-contracts.mjs'
import { createAdversarialScopeRequest } from '../scripts/lib/adversarial-scope-contracts.mjs'
import { openAdversarialCampaignLedger } from '../scripts/lib/adversarial-campaign-ledger.mjs'
import {
  OPERATOR_AUTHORIZATION_KIND,
  OPERATOR_AUTHORIZATION_STATUS,
  OPERATOR_CAMPAIGN_AUTHORIZATION_STATEMENT,
  verifyBoundOperatorAuthorization,
} from '../scripts/lib/operator-authorization.mjs'
import { stableJson } from '../scripts/lib/run-engine.mjs'

const SHA_B = 'b'.repeat(64)
const SHA_C = 'c'.repeat(64)
const SHA_D = 'd'.repeat(64)

function keys() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })
  return { privateKey, publicKey }
}

function limits(overrides = {}) {
  return {
    max_actions: 8,
    max_wall_time_ms: 60_000,
    max_action_time_ms: 5_000,
    max_input_bytes: 4_096,
    max_output_bytes: 16_384,
    max_aggregate_output_bytes: 65_536,
    max_concurrency: 1,
    min_action_interval_ms: 0,
    ...overrides,
  }
}

function exactPlan({ targetKind = 'live', overrides = {} } = {}) {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-plan',
    plan_id: 'plan:exact-runtime-001',
    engagement_id: 'engagement:runtime-001',
    scope_revision_sha256: SHA_B,
    candidate_id: 'candidate:runtime-001',
    target: {
      kind: targetKind,
      target_id: 'target:runtime-testbed',
      locator: targetKind === 'repository'
        ? 'repository://disposable-mirror'
        : 'https://127.0.0.1:9443',
      identity_sha256: SHA_C,
    },
    strategy_id: 'custom.runtime/exact-v1',
    risk_class: 'READ_ONLY',
    autonomy_profile: 'L1_ASSISTED',
    attack: {
      id: 'attack:runtime',
      description: 'Exercise the planted synthetic invariant failure.',
      expected_observation: 'The synthetic forbidden marker is returned.',
    },
    control: {
      id: 'control:runtime',
      description: 'Exercise the authorized synthetic control.',
      expected_observation: 'The authorized marker is returned.',
    },
    oracle: {
      id: 'oracle:runtime',
      confirmation_condition: 'Attack returns the forbidden marker while control remains valid.',
      inconclusive_condition: 'Control or attribution fails.',
    },
    limits: limits(),
    actions: [
      {
        action_id: 'action:control-001',
        purpose: 'control',
        action_category: 'http.control',
        operation: 'http.request',
        parameters: { method: 'GET', url: 'https://127.0.0.1:9443/owned' },
      },
      {
        action_id: 'action:attack-001',
        purpose: 'attack',
        action_category: 'http.authorization',
        operation: 'http.request',
        parameters: { method: 'GET', url: 'https://127.0.0.1:9443/foreign' },
      },
    ],
    ...overrides,
  }
}

function maximumPlan(overrides = {}) {
  const condition = { field: '/target/kind', operator: 'equals', value: 'live' }
  const plan = exactPlan({
    overrides: {
      plan_id: 'plan:break-their-bones-001',
      strategy_id: 'campaign.adaptive/multi-strategy-v1',
      risk_class: 'STATE_CHANGE',
      autonomy_profile: 'L3_MAXIMUM_AUTHORIZED',
      limits: limits({ max_actions: 6 }),
      preflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
      campaign_envelope: {
        envelope_id: 'campaign:break-their-bones-001',
        allowed_operations: ['http.request', 'fuzzer.case'],
        allowed_action_categories: ['http.control', 'http.authorization', 'input.fuzz'],
        allowed_strategy_families: ['authorization-testing', 'structured-fuzzing'],
        applicability_conditions: [condition],
        decision_rules: [{
          rule_id: 'rule:authorized-estate',
          when_all: [condition],
          authorize: {
            operations: ['http.request', 'fuzzer.case'],
            action_categories: ['http.control', 'http.authorization', 'input.fuzz'],
            strategy_families: ['authorization-testing', 'structured-fuzzing'],
          },
        }],
        max_actions: 6,
        max_chain_depth: 4,
        checkpoint_policy: {
          interval_actions: 2,
          max_resume_count: 3,
          require_current_authorization: true,
          require_runtime_preflight: true,
        },
        mandatory_escalation_triggers: [...L3_MANDATORY_ESCALATION_TRIGGERS],
        prohibited_effects: [...L3_PROHIBITED_EFFECTS],
      },
      ...overrides,
    },
  })
  delete plan.actions
  return plan
}

function operatorAuthorizationFor(plan, overrides = {}) {
  const value = {
    schema_version: '1.0.0',
    kind: OPERATOR_AUTHORIZATION_KIND,
    status: OPERATOR_AUTHORIZATION_STATUS,
    operator_id: 'operator:owner',
    authorization_reference: 'authorization:runtime-operator-001',
    statement: OPERATOR_CAMPAIGN_AUTHORIZATION_STATEMENT,
    declared_at: '2026-09-03T10:05:00.000Z',
    target: structuredClone(plan.target),
    plan_sha256: digestAdversarialPlan(plan),
    scope_revision_sha256: plan.scope_revision_sha256,
    ...overrides,
  }
  return verifyBoundOperatorAuthorization({
    value,
    planSha256: digestAdversarialPlan(plan),
    scopeRevisionSha256: plan.scope_revision_sha256,
    target: plan.target,
    now: new Date('2026-09-03T10:05:00.000Z'),
    fail(code, message) {
      const error = new Error(message)
      error.code = code
      throw error
    },
  })
}

function campaignAuthorizationReceiptFor(plan) {
  const receipt = operatorAuthorizationFor(plan)
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-authorization-receipt',
    status: 'CONTROLLER_VERIFIED',
    authorization_id: receipt.authorization_reference,
    authorization_reference: receipt.authorization_reference,
    authorization_sha256: receipt.authorization_sha256,
    authority_basis: receipt.authority_basis,
    operator_id: receipt.operator_id,
    plan_sha256: receipt.plan_sha256,
    engagement_id: plan.engagement_id,
    scope_revision_sha256: receipt.scope_revision_sha256,
    target_sha256: receipt.target_sha256,
    risk_class: plan.risk_class,
    autonomy_profile: plan.autonomy_profile,
    declared_at: receipt.declared_at,
    expires_at: new Date(
      Date.parse(receipt.declared_at) + (5 * 60 * 1000) + plan.limits.max_wall_time_ms,
    ).toISOString(),
  }
}

function oneUseStore() {
  const consumed = new Set()
  return {
    consume(record) {
      if (consumed.has(record.nonce_sha256)) return false
      consumed.add(record.nonce_sha256)
      return true
    },
  }
}

function digestJson(value) {
  const rendered = stableJson(value, 0)
  const canonical = rendered.endsWith('\n') ? rendered.slice(0, -1) : rendered
  return createHash('sha256').update(Buffer.from(canonical, 'utf8')).digest('hex')
}

async function trustedFileLedger(t, plan) {
  const root = await mkdtemp(join(tmpdir(), 'adversarial-runtime-ledger-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const directory = join(root, 'records')
  const authorization = operatorAuthorizationFor(plan)
  const binding = {
    plan_sha256: digestAdversarialPlan(plan),
    authorization_id: authorization.authorization_reference,
    authorization_sha256: authorization.authorization_sha256,
    scope_revision_sha256: plan.scope_revision_sha256,
  }
  return {
    directory,
    binding,
    ledger: await openAdversarialCampaignLedger({ directory, binding }),
  }
}

function interceptLedgerMethod(ledger, methodName, replacement) {
  return new Proxy(ledger, {
    get(target, property) {
      if (property === methodName) return replacement
      const value = Reflect.get(target, property, target)
      return typeof value === 'function' ? value.bind(target) : value
    },
  })
}

function callerSuppliedStartedLedger(snapshot = {}) {
  const methods = [
    'start',
    'recordResume',
    'recordActionConsidered',
    'recordActionSkipped',
    'recordPreDispatch',
    'recordDispatchSettlement',
    'recordDispatchCancelled',
    'recordObservation',
    'recordScopeRequest',
    'recordCheckpointQueued',
    'recordCheckpointAcknowledged',
    'recordTerminal',
  ]
  const ledger = Object.fromEntries(methods.map((method) => [method, async () => {
    throw new Error(`unexpected ${method}`)
  }]))
  ledger.assertBinding = async () => ({
    started: true,
    terminal: false,
    ...snapshot,
  })
  ledger.snapshot = () => ({ started: true, terminal: false, ...snapshot })
  return ledger
}

function trustedControllerLedger() {
  const events = []
  const state = {
    started: false,
    terminal: false,
    terminal_result: null,
    record_count: 0,
    head_sha256: '0'.repeat(64),
    authorization_receipt: null,
    preflight: null,
    qualification_receipt: null,
    break_glass_override_sha256: null,
    considered_actions: 0,
    dispatched_actions: 0,
    aggregate_output_bytes: 0,
    elapsed_ms: 0,
    resume_count: 0,
    exact_index: 0,
    action_ids: [],
    paused_branches: [],
    scope_requests: [],
    observations: [],
    observation_records: [],
    pending_consideration: null,
    pending_dispatch: null,
    pending_exact_scope_request: null,
    pending_checkpoint: null,
  }
  const snapshot = () => structuredClone({ fresh: state.record_count === 0, ...state })
  const append = (type, value = {}) => {
    events.push(structuredClone({ type, ...value }))
    state.record_count += 1
    state.head_sha256 = createHash('sha256')
      .update(JSON.stringify(events.at(-1)))
      .digest('hex')
    state.elapsed_ms = Math.max(state.elapsed_ms, value.elapsedMs ?? 0)
    return snapshot()
  }
  return {
    events,
    assertBinding: async () => snapshot(),
    assertQualificationContract: async (requirements) => ({
      schema_version: '1.0.0',
      kind: 'red-team-audit/adversarial-ledger-qualification-receipt',
      status: 'QUALIFIED',
      contract_version: requirements.contract_version,
      binding_sha256: requirements.binding_sha256,
      requirements_sha256: digestJson(requirements),
    }),
    snapshot,
    start: async (value) => {
      state.started = true
      state.authorization_receipt = structuredClone(value.authorizationReceipt)
      state.preflight = structuredClone(value.preflight)
      state.qualification_receipt = structuredClone(value.qualificationReceipt)
      state.break_glass_override_sha256 = value.breakGlassOverrideSha256
      return append('CAMPAIGN_STARTED', value)
    },
    recordResume: async (value) => {
      state.resume_count += 1
      return append('CAMPAIGN_RESUMED', value)
    },
    recordActionConsidered: async (value) => {
      state.considered_actions = value.consideredActions
      state.exact_index = value.exactIndex
      state.action_ids.push(value.actionId)
      state.pending_consideration = {
        action_id: value.actionId,
        action_sha256: value.actionSha256,
        branch_id: value.branchId,
      }
      return append('ACTION_CONSIDERED', value)
    },
    recordActionProposed: async (value) => append('ACTION_PROPOSED', value),
    recordActionClassified: async (value) => append('ACTION_CLASSIFIED', value),
    recordScopeDecision: async (value) => append('SCOPE_DECISION_RECORDED', value),
    recordActionPreflight: async (value) => append('ACTION_PREFLIGHT_RECORDED', value),
    recordBoundaryDecision: async (value) => append('ACTION_BOUNDARY_DECIDED', value),
    recordActionSkipped: async (value) => {
      state.pending_consideration = null
      return append('ACTION_SKIPPED', value)
    },
    recordPreDispatch: async (value) => {
      state.pending_consideration = null
      state.dispatched_actions = value.dispatchedActions
      state.pending_dispatch = {
        action_id: value.actionId,
        action_sha256: value.actionSha256,
        branch_id: value.branchId,
        send_permit_sha256: null,
        settlement: null,
      }
      return append('ACTION_PRE_DISPATCH', value)
    },
    recordSendPermit: async (value) => {
      state.pending_dispatch.send_permit_sha256 = digestJson(value.permit)
      return append('ACTION_SEND_PERMITTED', value)
    },
    recordDispatchSettlement: async (value) => {
      state.pending_dispatch.settlement = structuredClone(value.receipt)
      if (value.receipt.outcome === 'CANCELLED_BEFORE_SEND') {
        state.pending_dispatch = null
        state.dispatched_actions -= 1
      }
      return append('ACTION_DISPATCH_SETTLED', value)
    },
    recordDispatchCancelled: async (value) => {
      state.pending_dispatch = null
      state.dispatched_actions -= 1
      return append('ACTION_DISPATCH_CANCELLED', value)
    },
    recordObservation: async (value) => {
      state.pending_dispatch = null
      state.aggregate_output_bytes = value.aggregateOutputBytes
      state.observations.push(structuredClone(value.observation))
      state.observation_records.push({
        action_id: value.actionId,
        action_sha256: value.actionSha256,
        branch_id: value.branchId,
        observation_sha256: createHash('sha256')
          .update(JSON.stringify(value.observation))
          .digest('hex'),
      })
      if (value.pauseBranch && !state.paused_branches.includes(value.branchId)) {
        state.paused_branches.push(value.branchId)
      }
      return append('ACTION_OBSERVATION', value)
    },
    recordScopeRequest: async (value) => {
      state.pending_consideration = null
      state.scope_requests.push(structuredClone(value.request))
      if (!value.continueCampaign) {
        state.pending_exact_scope_request = {
          action_id: value.actionId,
          action_sha256: value.actionSha256,
          branch_id: value.branchId,
        }
      }
      return append('SCOPE_REQUEST_QUEUED', value)
    },
    recordCheckpointQueued: async (value) => {
      state.pending_checkpoint = structuredClone(value.checkpoint)
      return append('CHECKPOINT_QUEUED', value)
    },
    recordCheckpointAcknowledged: async (value) => {
      state.pending_checkpoint = null
      return append('CHECKPOINT_ACKNOWLEDGED', value)
    },
    recordCampaignStop: async (value) => append('CAMPAIGN_STOP_RECORDED', value),
    recordCleanupOutcome: async (value) => append('ACTION_CLEANUP_OUTCOME', value),
    recordTerminal: async (value) => {
      state.terminal = true
      state.terminal_result = structuredClone(value.result)
      return append('CAMPAIGN_TERMINAL', value)
    },
  }
}

function allowScope(action, context) {
  return {
    status: 'AUTHORIZED',
    plan_sha256: context.authorization_receipt.plan_sha256,
    authorization_id: context.authorization_receipt.authorization_id,
    scope_revision_sha256: SHA_B,
    action_sha256: context.action_sha256,
    candidate_facts_sha256: context.candidate_facts_sha256,
    target: context.resolved_target,
    risk_class: context.risk_class,
    effect_classification: context.effect_classification,
  }
}

function buildFormalScopeRequest(_candidate, context) {
  return createAdversarialScopeRequest({
    requestId: `scope-request:${context.action_sha256.slice(0, 16)}`,
    engagementId: context.plan.engagement_id,
    requestedAt: '2026-09-03T10:05:00.000Z',
    baseScopeRevision: 1,
    baseScopeSha256: context.scope_revision_sha256,
    delta: {
      targets: { add: [], remove: [] },
      paths: { add: [], remove: [] },
      methods: { add: [], remove: [] },
      strategy_families: {
        add: [context.strategy_family ?? 'runtime-expansion'],
        remove: [],
      },
      data_classes: { add: [], remove: [] },
      impact_permissions: { add: [], remove: [] },
      limits: { add: [], remove: [] },
      validity: { add: [], remove: [] },
    },
    rationale: 'The candidate requires authority outside the current operator-stated campaign envelope.',
    blockedObjective: `Validate ${context.action_id} without crossing the current boundary.`,
    discoveryEvidence: [{
      evidence_id: 'candidate-action',
      sha256: context.action_sha256,
    }],
    expectedRisk: `The requested action carries ${context.risk_class} risk.`,
    sideEffects: 'Only the effects disclosed by the candidate action would become eligible.',
    cleanupPlan: 'Use the cleanup action bound into the successor plan when state changes occur.',
    eligibleActionPlan: `Replan action ${context.action_id} under a new operator scope statement.`,
    attackPlanSha256: context.plan_sha256,
  })
}

function runtimeOptions(plan, overrides = {}) {
  const requiresAuthorization = plan.target.kind === 'live'
    || plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED'
  return {
    plan,
    operatorAuthorizationReceipt: requiresAuthorization
      ? operatorAuthorizationFor(plan)
      : undefined,
    trustedCampaignLedger: (plan.target.kind === 'live'
      || plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED')
      ? trustedControllerLedger()
      : undefined,
    now: new Date('2026-09-03T10:05:00.000Z'),
    clock: () => Date.parse('2026-09-03T10:05:00.000Z'),
    scopeAuthorize: async (action, context) => allowScope(action, context),
    isAuthorizationRevoked: async () => false,
    isOperatorStopRequested: async () => false,
    classifyAction: async (action) => ({
      candidate_context: { target_kind: plan.target.kind },
      resolved_target: structuredClone(plan.target),
      anticipated_effects: [],
      strategy_family: action.strategy_family
        ?? plan.campaign_envelope?.allowed_strategy_families?.[0]
        ?? 'authorization-testing',
    }),
    checkpoint: async (state) => ({
      decision: 'CONTINUE',
      plan_sha256: state.plan_sha256,
      authorization_id: state.authorization_id,
      scope_revision_sha256: state.scope_revision_sha256,
      actions_used: state.actions_used,
      ...(state.next_phase === undefined ? {} : { next_phase: state.next_phase }),
      ...(state.next_action_sha256 === undefined
        ? {}
        : { next_action_sha256: state.next_action_sha256 }),
    }),
    scopeRequestBuilder: buildFormalScopeRequest,
    dispatch: async (action) => ({
      action_id: action.action_id,
      status: 'OBSERVED',
      output_bytes: 32,
      escalation_triggers: [],
    }),
    ...overrides,
  }
}

function tacticalAction(id, overrides = {}) {
  return {
    action_id: `action:${id}`,
    branch_id: `branch:${id}`,
    chain_depth: 1,
    purpose: 'attack',
    action_category: 'http.authorization',
    operation: 'http.request',
    strategy_family: 'authorization-testing',
    parameters: { method: 'GET', url: `https://127.0.0.1:9443/${id}` },
    ...overrides,
  }
}

test('a controller-verified operator authorization receipt starts live execution without a signing key', async () => {
  const plan = exactPlan()
  const operatorAuthorizationReceipt = operatorAuthorizationFor(plan)
  const trustedCampaignLedger = trustedControllerLedger()
  let dispatches = 0

  const result = await executeAdversarialCampaign({
    ...runtimeOptions(plan),
    operatorAuthorizationReceipt,
    trustedCampaignLedger,
    isAuthorizationRevoked: async () => false,
    isOperatorStopRequested: async () => false,
    dispatch: async (action) => {
      dispatches += 1
      return {
        action_id: action.action_id,
        status: 'OBSERVED',
        output_bytes: 32,
        escalation_triggers: [],
      }
    },
  })

  assert.equal(result.status, 'COMPLETED')
  assert.equal(dispatches, 2)
  assert.equal(result.authorization_receipt.status, 'CONTROLLER_VERIFIED')
  assert.equal(
    result.authorization_receipt.authorization_sha256,
    operatorAuthorizationReceipt.authorization_sha256,
  )
  const started = trustedCampaignLedger.events.find(({ type }) => type === 'CAMPAIGN_STARTED')
  assert.equal(started.authorizationReceipt.authorization_id, 'authorization:runtime-operator-001')
})

test('live execution rejects a drifted persisted authorization receipt before resume or dispatch', async (t) => {
  const plan = exactPlan()
  const file = await trustedFileLedger(t, plan)
  const persistedReceipt = {
    ...campaignAuthorizationReceiptFor(plan),
    operator_id: 'operator:different',
  }
  await file.ledger.start({
    authorizationReceipt: persistedReceipt,
    preflight: { allowed: true, reasons: [], mode: 'NOT_REQUIRED', waived_controls: [] },
    qualificationReceipt: null,
    breakGlassOverrideSha256: null,
    startedAt: '2026-09-03T10:05:00.000Z',
  })
  let dispatches = 0

  await assert.rejects(
    () => executeAdversarialCampaign(runtimeOptions(plan, {
      trustedCampaignLedger: file.ledger,
      dispatch: async () => {
        dispatches += 1
        return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
      },
    })),
    (error) => error.code === 'ADVERSARIAL_LEDGER_AUTHORIZATION_RECEIPT_MISMATCH',
  )
  assert.equal(dispatches, 0)
  assert.equal(file.ledger.snapshot().record_count, 1, 'receipt drift must fail before resume')
})

test('live execution rejects a drifted persisted authorization receipt before terminal hydration', async (t) => {
  const plan = exactPlan()
  const file = await trustedFileLedger(t, plan)
  const persistedReceipt = {
    ...campaignAuthorizationReceiptFor(plan),
    operator_id: 'operator:different',
  }
  await file.ledger.start({
    authorizationReceipt: persistedReceipt,
    preflight: { allowed: true, reasons: [], mode: 'NOT_REQUIRED', waived_controls: [] },
    qualificationReceipt: null,
    breakGlassOverrideSha256: null,
    startedAt: '2026-09-03T10:05:00.000Z',
  })
  await file.ledger.recordTerminal({
    result: {
      schema_version: '1.0.0',
      kind: 'red-team-audit/adversarial-campaign-terminal-summary',
      status: 'COMPLETED',
      plan_sha256: digestAdversarialPlan(plan),
      authorization_receipt: persistedReceipt,
      preflight_mode: 'NOT_REQUIRED',
      waived_preflight_controls: [],
      considered_actions: 0,
      dispatched_actions: 0,
      aggregate_output_bytes: 0,
      paused_branch_count: 0,
      scope_request_count: 0,
      observation_count: 0,
    },
    elapsedMs: 0,
  })

  await assert.rejects(
    () => executeAdversarialCampaign(runtimeOptions(plan, {
      trustedCampaignLedger: file.ledger,
      dispatch: async () => { throw new Error('terminal hydration must not dispatch') },
    })),
    (error) => error.code === 'ADVERSARIAL_LEDGER_AUTHORIZATION_RECEIPT_MISMATCH',
  )
})

test('operator authorization remains bound to the exact plan target and plan-derived time window', async () => {
  const plan = exactPlan()
  const targetDrift = structuredClone(operatorAuthorizationFor(plan))
  targetDrift.target.locator = 'https://127.0.0.1:9443/different-target'
  let dispatches = 0

  await assert.rejects(
    () => executeAdversarialCampaign({
      ...runtimeOptions(plan),
      operatorAuthorizationReceipt: targetDrift,
      isAuthorizationRevoked: async () => false,
      isOperatorStopRequested: async () => false,
      dispatch: async () => { dispatches += 1; return {} },
    }),
    (error) => error.code === 'ADVERSARIAL_OPERATOR_AUTHORIZATION_TARGET_MISMATCH',
  )

  await assert.rejects(
    () => executeAdversarialCampaign({
      ...runtimeOptions(plan),
      operatorAuthorizationReceipt: operatorAuthorizationFor(plan),
      now: new Date('2026-09-03T10:12:00.000Z'),
      clock: () => Date.parse('2026-09-03T10:12:00.000Z'),
      isAuthorizationRevoked: async () => false,
      isOperatorStopRequested: async () => false,
      dispatch: async () => { dispatches += 1; return {} },
    }),
    (error) => error.code === 'ADVERSARIAL_OPERATOR_AUTHORIZATION_EXPIRED',
  )
  assert.equal(dispatches, 0)
})

test('operator stop and current revocation callbacks fail closed before live dispatch', async () => {
  const missingStopPlan = exactPlan()
  await assert.rejects(
    () => executeAdversarialCampaign({
      ...runtimeOptions(missingStopPlan),
      operatorAuthorizationReceipt: operatorAuthorizationFor(missingStopPlan),
      isAuthorizationRevoked: async () => false,
      isOperatorStopRequested: undefined,
    }),
    (error) => error.code === 'ADVERSARIAL_OPERATOR_STOP_GATE_REQUIRED',
  )

  for (const scenario of [
    {
      expectedStatus: 'ABORTED',
      expectedReason: 'OPERATOR_STOP',
      isAuthorizationRevoked: async () => false,
      isOperatorStopRequested: async () => true,
    },
    {
      expectedStatus: 'PAUSED_AUTHORIZATION',
      expectedReason: 'AUTHORIZATION_REVOKED',
      isAuthorizationRevoked: async () => true,
      isOperatorStopRequested: async () => false,
    },
  ]) {
    const plan = exactPlan()
    let dispatches = 0
    const result = await executeAdversarialCampaign({
      ...runtimeOptions(plan),
      operatorAuthorizationReceipt: operatorAuthorizationFor(plan),
      isAuthorizationRevoked: scenario.isAuthorizationRevoked,
      isOperatorStopRequested: scenario.isOperatorStopRequested,
      dispatch: async () => { dispatches += 1; return {} },
    })
    assert.equal(result.status, scenario.expectedStatus)
    assert.deepEqual(result.stop_reasons, [scenario.expectedReason])
    assert.equal(dispatches, 0)
  }
})

test('a live crafted plan without exact current authorization performs zero dispatch', async () => {
  const plan = exactPlan()
  let scopeChecks = 0
  let dispatches = 0
  await assert.rejects(
    () => executeAdversarialCampaign({
      ...runtimeOptions(plan),
      operatorAuthorizationReceipt: undefined,
      scopeAuthorize: async (action, context) => { scopeChecks += 1; return allowScope(action, context) },
      dispatch: async () => { dispatches += 1; return {} },
    }),
    (error) => error.code === 'ADVERSARIAL_LIVE_AUTHORIZATION_REQUIRED',
  )
  assert.equal(scopeChecks, 0)
  assert.equal(dispatches, 0)
})


test('every live plan requires controller-owned destination/effect classification and scope-request construction', async () => {
  const plan = exactPlan()
  let dispatches = 0
  await assert.rejects(
    () => executeAdversarialCampaign(runtimeOptions(plan, {
      classifyAction: undefined,
      dispatch: async () => { dispatches += 1; return {} },
    })),
    (error) => error.code === 'ADVERSARIAL_CLASSIFIER_REQUIRED',
  )
  await assert.rejects(
    () => executeAdversarialCampaign(runtimeOptions(plan, {
      scopeRequestBuilder: undefined,
      dispatch: async () => { dispatches += 1; return {} },
    })),
    (error) => error.code === 'ADVERSARIAL_SCOPE_REQUEST_BUILDER_REQUIRED',
  )
  assert.equal(dispatches, 0)
})

test('an authorized live plan dispatches only its exact actions after a fresh scope check', async () => {
  const plan = exactPlan()
  const scoped = []
  const dispatched = []
  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    scopeAuthorize: async (action, context) => { scoped.push(action.action_id); return allowScope(action, context) },
    dispatch: async (action) => {
      dispatched.push(structuredClone(action))
      return { action_id: action.action_id, status: 'OBSERVED', output_bytes: 10, escalation_triggers: [] }
    },
  }))

  assert.equal(result.status, 'COMPLETED')
  assert.deepEqual(scoped, plan.actions.flatMap((action) => [action.action_id, action.action_id]))
  assert.deepEqual(dispatched, plan.actions)
  assert.equal(result.authorization_receipt.plan_sha256, digestAdversarialPlan(plan))
})

test('authorization-bound campaigns refuse a caller-supplied ledger before touching it', async () => {
  const plan = exactPlan()
  let dispatches = 0
  await assert.rejects(
    () => executeAdversarialCampaign(runtimeOptions(plan, {
      campaignLedger: callerSuppliedStartedLedger({
        terminal: true,
        terminal_result: { status: 'COMPLETED' },
      }),
      dispatch: async () => {
        dispatches += 1
        return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
      },
    })),
    (error) => error.code === 'ADVERSARIAL_AUTHORIZATION_BOUND_LEDGER_UNTRUSTED',
  )
  assert.equal(dispatches, 0)
})

test('authorization-bound campaigns require a trusted controller ledger before dispatch', async () => {
  const plan = maximumPlan()
  let dispatches = 0
  await assert.rejects(
    () => executeAdversarialCampaign(runtimeOptions(plan, {
      trustedCampaignLedger: undefined,
      runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
      proposeNextAction: async () => tacticalAction('must-not-run'),
      dispatch: async () => {
        dispatches += 1
        return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
      },
    })),
    (error) => error.code === 'ADVERSARIAL_TRUSTED_CAMPAIGN_LEDGER_REQUIRED',
  )
  assert.equal(dispatches, 0)
})

test('L3 rejects a trusted ledger without complete lifecycle qualification before dispatch', async () => {
  const plan = maximumPlan()
  const campaignLedger = trustedControllerLedger()
  let dispatches = 0
  delete campaignLedger.recordActionProposed

  await assert.rejects(
    () => executeAdversarialCampaign(runtimeOptions(plan, {
      trustedCampaignLedger: campaignLedger,
      runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
      proposeNextAction: async () => tacticalAction('must-not-be-proposed'),
      dispatch: async () => {
        dispatches += 1
        return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
      },
    })),
    (error) => error.code === 'ADVERSARIAL_L3_LEDGER_QUALIFICATION_REQUIRED',
  )
  assert.equal(dispatches, 0)
})

test('a trusted-ledger pre-dispatch append failure causes zero target dispatch', async () => {
  const plan = maximumPlan()
  const campaignLedger = trustedControllerLedger()
  const appendFailure = new Error('synthetic trusted-ledger pre-dispatch append failure')
  let appendAttempts = 0
  let dispatches = 0
  campaignLedger.recordPreDispatch = async () => {
    appendAttempts += 1
    throw appendFailure
  }

  await assert.rejects(
    () => executeAdversarialCampaign(runtimeOptions(plan, {
      trustedCampaignLedger: campaignLedger,
      runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
      proposeNextAction: async () => tacticalAction('ledger-append-failure'),
      dispatch: async () => {
        dispatches += 1
        return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
      },
    })),
    (error) => error === appendFailure,
  )
  assert.equal(appendAttempts, 1)
  assert.equal(dispatches, 0)
})

test('operator stop during the durable send-permit append cancels before target I/O', async () => {
  const plan = maximumPlan()
  const campaignLedger = trustedControllerLedger()
  const controller = new AbortController()
  const recordSendPermit = campaignLedger.recordSendPermit
  let proposals = 0
  let dispatches = 0
  campaignLedger.recordSendPermit = async (value) => {
    const snapshot = await recordSendPermit(value)
    controller.abort(new Error('operator stop after durable permit'))
    return snapshot
  }

  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    trustedCampaignLedger: campaignLedger,
    signal: controller.signal,
    runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
    proposeNextAction: async () => {
      proposals += 1
      return proposals === 1 ? tacticalAction('post-permit-stop') : null
    },
    dispatch: async () => {
      dispatches += 1
      return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
    },
  }))

  assert.equal(result.status, 'ABORTED')
  assert.equal(dispatches, 0)
  assert.deepEqual(campaignLedger.events.slice(-4).map(({ type }) => type), [
    'ACTION_SEND_PERMITTED',
    'ACTION_DISPATCH_SETTLED',
    'CAMPAIGN_STOP_RECORDED',
    'CAMPAIGN_TERMINAL',
  ])
  assert.equal(campaignLedger.events.at(-3).receipt.outcome, 'CANCELLED_BEFORE_SEND')
  assert.equal(campaignLedger.events.at(-3).receipt.request_may_have_been_sent, false)
})

test('scope withdrawal after the durable send permit is rechecked and settled before target I/O', async () => {
  const plan = maximumPlan()
  const campaignLedger = trustedControllerLedger()
  let proposals = 0
  let dispatches = 0

  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    trustedCampaignLedger: campaignLedger,
    runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
    proposeNextAction: async () => {
      proposals += 1
      return proposals === 1 ? tacticalAction('post-permit-scope-withdrawal') : null
    },
    scopeAuthorize: async (action, context) => {
      const decision = allowScope(action, context)
      return campaignLedger.events.at(-1)?.type === 'ACTION_SEND_PERMITTED'
        ? { ...decision, status: 'DENIED' }
        : decision
    },
    dispatch: async () => {
      dispatches += 1
      return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
    },
  }))

  assert.equal(result.status, 'PAUSED_SCOPE')
  assert.equal(dispatches, 0)
  const settlement = campaignLedger.events.findLast(({ type }) => type === 'ACTION_DISPATCH_SETTLED')
  assert.equal(settlement.receipt.outcome, 'CANCELLED_BEFORE_SEND')
  assert.equal(settlement.receipt.request_may_have_been_sent, false)
  assert.ok(settlement.receipt.reason_codes.includes('SCOPE_DENIED_AFTER_SEND_PERMIT'))
})

test('operator stop raised during the final scope await cancels the durable permit before target I/O', async () => {
  const plan = maximumPlan()
  const campaignLedger = trustedControllerLedger()
  let proposals = 0
  let stopRequested = false
  let dispatches = 0

  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    trustedCampaignLedger: campaignLedger,
    runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
    proposeNextAction: async () => {
      proposals += 1
      return proposals === 1 ? tacticalAction('post-permit-operator-stop') : null
    },
    scopeAuthorize: async (action, context) => {
      if (campaignLedger.events.at(-1)?.type === 'ACTION_SEND_PERMITTED') {
        stopRequested = true
      }
      return allowScope(action, context)
    },
    isOperatorStopRequested: async () => stopRequested,
    dispatch: async () => {
      dispatches += 1
      return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
    },
  }))

  assert.equal(result.status, 'ABORTED')
  assert.deepEqual(result.stop_reasons, ['OPERATOR_STOP'])
  assert.equal(dispatches, 0)
  const settlement = campaignLedger.events.findLast(({ type }) => type === 'ACTION_DISPATCH_SETTLED')
  assert.equal(settlement.receipt.outcome, 'CANCELLED_BEFORE_SEND')
  assert.equal(settlement.receipt.request_may_have_been_sent, false)
  assert.deepEqual(settlement.receipt.reason_codes, ['OPERATOR_STOP'])
})

test('scope withdrawal during the post-permit stop check is rechecked before target I/O', async () => {
  const plan = maximumPlan()
  const campaignLedger = trustedControllerLedger()
  let proposals = 0
  let scopeAllowed = true
  let dispatches = 0

  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    trustedCampaignLedger: campaignLedger,
    runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
    proposeNextAction: async () => {
      proposals += 1
      return proposals === 1 ? tacticalAction('scope-withdrawn-during-stop-check') : null
    },
    scopeAuthorize: async (action, context) => {
      const decision = allowScope(action, context)
      return scopeAllowed ? decision : { ...decision, status: 'DENIED' }
    },
    isOperatorStopRequested: async () => {
      if (campaignLedger.events.at(-1)?.type === 'ACTION_SEND_PERMITTED') {
        scopeAllowed = false
      }
      return false
    },
    dispatch: async () => {
      dispatches += 1
      return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
    },
  }))

  assert.equal(result.status, 'PAUSED_SCOPE')
  assert.equal(dispatches, 0)
  const settlement = campaignLedger.events.findLast(({ type }) => type === 'ACTION_DISPATCH_SETTLED')
  assert.equal(settlement.receipt.outcome, 'CANCELLED_BEFORE_SEND')
  assert.equal(settlement.receipt.request_may_have_been_sent, false)
  assert.ok(settlement.receipt.reason_codes.includes('SCOPE_DENIED_AFTER_AUTHORIZATION_RECHECK'))
})

test('revocation raised during the last authority await cancels the durable permit before target I/O', async () => {
  const plan = maximumPlan()
  const campaignLedger = trustedControllerLedger()
  let proposals = 0
  let revoked = false
  let dispatches = 0

  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    trustedCampaignLedger: campaignLedger,
    runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
    proposeNextAction: async () => {
      proposals += 1
      return proposals === 1 ? tacticalAction('post-permit-revocation') : null
    },
    isAuthorizationRevoked: async () => {
      if (campaignLedger.events.at(-1)?.type === 'ACTION_SEND_PERMITTED') revoked = true
      await Promise.resolve()
      return revoked
    },
    dispatch: async () => {
      dispatches += 1
      return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
    },
  }))

  assert.equal(result.status, 'PAUSED_AUTHORIZATION')
  assert.deepEqual(result.stop_reasons, ['AUTHORIZATION_REVOKED'])
  assert.equal(dispatches, 0)
  const settlement = campaignLedger.events.findLast(({ type }) => type === 'ACTION_DISPATCH_SETTLED')
  assert.equal(settlement.receipt.outcome, 'CANCELLED_BEFORE_SEND')
  assert.equal(settlement.receipt.request_may_have_been_sent, false)
  assert.deepEqual(settlement.receipt.reason_codes, ['AUTHORIZATION_REVOKED'])
})

test('L3 classifier failure is durably qualified and stopped before target I/O', async () => {
  const plan = maximumPlan()
  const campaignLedger = trustedControllerLedger()
  const classifierFailure = new Error('synthetic classifier failure')
  let dispatches = 0

  await assert.rejects(
    () => executeAdversarialCampaign(runtimeOptions(plan, {
      trustedCampaignLedger: campaignLedger,
      runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
      proposeNextAction: async () => tacticalAction('classifier-failure'),
      classifyAction: async () => { throw classifierFailure },
      dispatch: async () => {
        dispatches += 1
        return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
      },
    })),
    (error) => error === classifierFailure,
  )
  assert.equal(dispatches, 0)
  assert.deepEqual(campaignLedger.events.slice(-5).map(({ type }) => type), [
    'ACTION_CLASSIFIED',
    'ACTION_CONSIDERED',
    'CAMPAIGN_STOP_RECORDED',
    'ACTION_SKIPPED',
    'CAMPAIGN_TERMINAL',
  ])
  assert.equal(campaignLedger.events.at(-5).receipt.status, 'FAILED')
})

test('L3 initial scope callback failure is durably denied and stopped before target I/O', async () => {
  const plan = maximumPlan()
  const campaignLedger = trustedControllerLedger()
  const scopeFailure = new Error('synthetic scope controller failure')
  let dispatches = 0

  await assert.rejects(
    () => executeAdversarialCampaign(runtimeOptions(plan, {
      trustedCampaignLedger: campaignLedger,
      runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
      proposeNextAction: async () => tacticalAction('scope-failure'),
      scopeAuthorize: async () => { throw scopeFailure },
      dispatch: async () => {
        dispatches += 1
        return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
      },
    })),
    (error) => error === scopeFailure,
  )
  assert.equal(dispatches, 0)
  assert.deepEqual(campaignLedger.events.slice(-4).map(({ type }) => type), [
    'SCOPE_DECISION_RECORDED',
    'CAMPAIGN_STOP_RECORDED',
    'ACTION_SKIPPED',
    'CAMPAIGN_TERMINAL',
  ])
  assert.equal(campaignLedger.events.at(-4).receipt.status, 'ERROR')
})

test('L3 proposer failure is durably stopped before target I/O', async () => {
  const plan = maximumPlan()
  const campaignLedger = trustedControllerLedger()
  const proposerFailure = new Error('synthetic action proposer failure')
  let dispatches = 0

  await assert.rejects(
    () => executeAdversarialCampaign(runtimeOptions(plan, {
      trustedCampaignLedger: campaignLedger,
      runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
      proposeNextAction: async () => { throw proposerFailure },
      dispatch: async () => {
        dispatches += 1
        return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
      },
    })),
    (error) => error === proposerFailure,
  )
  assert.equal(dispatches, 0)
  assert.deepEqual(campaignLedger.events.slice(-2).map(({ type }) => type), [
    'CAMPAIGN_STOP_RECORDED',
    'CAMPAIGN_TERMINAL',
  ])
  assert.deepEqual(campaignLedger.events.at(-2).receipt.reason_codes, [
    'ACTION_PROPOSER_FAILED',
  ])
})

test('L3 scope-request builder and sink failures are durably stopped before target I/O', async () => {
  const plan = maximumPlan()
  const deniedScope = async (action, context) => ({
    ...allowScope(action, context),
    status: 'DENIED',
  })
  let dispatches = 0

  const builderLedger = trustedControllerLedger()
  await assert.rejects(
    () => executeAdversarialCampaign(runtimeOptions(plan, {
        trustedCampaignLedger: builderLedger,
        runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
        proposeNextAction: async () => tacticalAction('scope-builder-failure'),
        scopeAuthorize: deniedScope,
        scopeRequestBuilder: () => { throw new Error('synthetic builder failure') },
        dispatch: async () => { dispatches += 1; return {} },
      })),
    (error) => error.code === 'ADVERSARIAL_SCOPE_REQUEST_BUILD_FAILED',
  )
  assert.deepEqual(builderLedger.events.slice(-4).map(({ type }) => type), [
    'SCOPE_DECISION_RECORDED',
    'CAMPAIGN_STOP_RECORDED',
    'ACTION_SKIPPED',
    'CAMPAIGN_TERMINAL',
  ])

  const sinkLedger = trustedControllerLedger()
  const sinkFailure = new Error('synthetic scope-request sink failure')
  const sinkPlan = maximumPlan({ plan_id: 'plan:break-their-bones-scope-sink' })
  await assert.rejects(
    () => executeAdversarialCampaign(runtimeOptions(sinkPlan, {
        trustedCampaignLedger: sinkLedger,
        runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
        proposeNextAction: async () => tacticalAction('scope-sink-failure'),
        scopeAuthorize: deniedScope,
        scopeRequestSink: async () => { throw sinkFailure },
        dispatch: async () => { dispatches += 1; return {} },
      })),
    (error) => error === sinkFailure,
  )
  assert.equal(dispatches, 0)
  assert.deepEqual(sinkLedger.events.slice(-3).map(({ type }) => type), [
    'SCOPE_REQUEST_QUEUED',
    'CAMPAIGN_STOP_RECORDED',
    'CAMPAIGN_TERMINAL',
  ])
  assert.deepEqual(sinkLedger.events.at(-2).receipt.reason_codes, [
    'SCOPE_REQUEST_SINK_FAILED',
  ])
})

test('malformed L3 scope returns are durably qualified and stopped at both action gates', async () => {
  let dispatches = 0

  const initialPlan = maximumPlan({ plan_id: 'plan:invalid-initial-scope-return' })
  const initialLedger = trustedControllerLedger()
  const initialResult = await executeAdversarialCampaign(runtimeOptions(initialPlan, {
      trustedCampaignLedger: initialLedger,
      runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
      proposeNextAction: async () => tacticalAction('invalid-initial-scope-return'),
      scopeAuthorize: async () => ({ status: 'AUTHORIZED' }),
      dispatch: async () => { dispatches += 1; return {} },
    }))
  assert.equal(initialResult.status, 'PAUSED_SCOPE')
  assert.equal(dispatches, 0)
  assert.deepEqual(initialLedger.events.slice(-4).map(({ type }) => type), [
    'SCOPE_DECISION_RECORDED',
    'CAMPAIGN_STOP_RECORDED',
    'ACTION_SKIPPED',
    'CAMPAIGN_TERMINAL',
  ])
  assert.equal(initialLedger.events.at(-4).receipt.status, 'ERROR')

  const recheckPlan = maximumPlan({ plan_id: 'plan:invalid-scope-recheck-return' })
  const recheckLedger = trustedControllerLedger()
  let scopeChecks = 0
  const recheckResult = await executeAdversarialCampaign(runtimeOptions(recheckPlan, {
      trustedCampaignLedger: recheckLedger,
      runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
      proposeNextAction: async () => tacticalAction('invalid-scope-recheck-return'),
      scopeAuthorize: async (action, context) => {
        scopeChecks += 1
        return scopeChecks === 1 ? allowScope(action, context) : { status: 'AUTHORIZED' }
      },
      dispatch: async () => { dispatches += 1; return {} },
    }))
  assert.equal(recheckResult.status, 'PAUSED_SCOPE')
  assert.equal(scopeChecks, 2)
  assert.equal(dispatches, 0)
  assert.deepEqual(recheckLedger.events.slice(-5).map(({ type }) => type), [
    'SCOPE_DECISION_RECORDED',
    'ACTION_PREFLIGHT_RECORDED',
    'ACTION_DISPATCH_CANCELLED',
    'CAMPAIGN_STOP_RECORDED',
    'CAMPAIGN_TERMINAL',
  ])
  assert.equal(recheckLedger.events.at(-5).receipt.status, 'ERROR')
  assert.deepEqual(recheckLedger.events.at(-2).receipt.reason_codes, [
    'SCOPE_DECISION_INVALID',
  ])
})

test('L3 recovers a crash after proposal as a failed classification and stopped action', async (t) => {
  const plan = maximumPlan({ plan_id: 'plan:proposal-crash-recovery' })
  const file = await trustedFileLedger(t, plan)
  const crash = new Error('synthetic crash after proposal append')
  const crashingLedger = interceptLedgerMethod(
    file.ledger,
    'recordActionClassified',
    async () => { throw crash },
  )

  await assert.rejects(
    () => executeAdversarialCampaign(runtimeOptions(plan, {
      trustedCampaignLedger: crashingLedger,
      runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
      proposeNextAction: async () => tacticalAction('proposal-crash-recovery'),
    })),
    (error) => error === crash,
  )
  assert.equal(file.ledger.snapshot().pending_action_qualification.action_id, 'action:proposal-crash-recovery')

  const reopened = await openAdversarialCampaignLedger({
    directory: file.directory,
    binding: file.binding,
  })
  let dispatches = 0
  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    trustedCampaignLedger: reopened,
    proposeNextAction: async () => { throw new Error('recovery cannot propose') },
    dispatch: async () => { dispatches += 1; return {} },
  }))
  assert.equal(result.status, 'PAUSED_SAFETY')
  assert.equal(dispatches, 0)
  const snapshot = reopened.snapshot()
  assert.equal(snapshot.terminal, true)
  assert.equal(snapshot.pending_action_qualification, null)
  assert.deepEqual(snapshot.qualification_records.slice(-4).map(({ type }) => type), [
    'CAMPAIGN_STOP_RECORDED',
    'ACTION_CLASSIFIED',
    'ACTION_SKIPPED',
    'CAMPAIGN_TERMINAL',
  ])
  assert.equal(snapshot.qualification_records.at(-3).receipt.status, 'FAILED')
})

test('L3 recovers a crash before cleanup qualification with a bound inconclusive outcome', async (t) => {
  const plan = maximumPlan({ plan_id: 'plan:cleanup-crash-recovery' })
  const file = await trustedFileLedger(t, plan)
  const crash = new Error('synthetic crash before cleanup outcome append')
  const crashingLedger = interceptLedgerMethod(
    file.ledger,
    'recordCleanupOutcome',
    async () => { throw crash },
  )
  let proposals = 0
  let dispatches = 0

  await assert.rejects(
    () => executeAdversarialCampaign(runtimeOptions(plan, {
      trustedCampaignLedger: crashingLedger,
      runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
      proposeNextAction: async () => (++proposals === 1
        ? tacticalAction('cleanup-crash-recovery', { purpose: 'cleanup' })
        : null),
      dispatch: async () => {
        dispatches += 1
        return {
          status: 'OBSERVED',
          output_bytes: 1,
          escalation_triggers: [],
          cleanup_verified: true,
        }
      },
    })),
    (error) => error === crash,
  )
  assert.equal(dispatches, 1)
  assert.equal(file.ledger.snapshot().pending_cleanup_outcome.action_id, 'action:cleanup-crash-recovery')

  const reopened = await openAdversarialCampaignLedger({
    directory: file.directory,
    binding: file.binding,
  })
  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    trustedCampaignLedger: reopened,
    proposeNextAction: async () => { throw new Error('recovery cannot propose') },
    dispatch: async () => { dispatches += 1; return {} },
  }))
  assert.equal(result.status, 'PAUSED_SAFETY')
  assert.equal(dispatches, 1)
  const snapshot = reopened.snapshot()
  assert.equal(snapshot.terminal, true)
  assert.equal(snapshot.pending_cleanup_outcome, null)
  assert.equal(snapshot.cleanup_outcomes.at(-1).status, 'INCONCLUSIVE')
  assert.deepEqual(snapshot.qualification_records.slice(-3).map(({ type }) => type), [
    'CAMPAIGN_STOP_RECORDED',
    'ACTION_CLEANUP_OUTCOME',
    'CAMPAIGN_TERMINAL',
  ])
})

test('L3 recovers a crash after RETURNED settlement without leaving a pending dispatch', async (t) => {
  const plan = maximumPlan({ plan_id: 'plan:return-settlement-crash-recovery' })
  const file = await trustedFileLedger(t, plan)
  const crash = new Error('synthetic crash after returned settlement')
  const crashingLedger = interceptLedgerMethod(
    file.ledger,
    'recordObservation',
    async () => { throw crash },
  )
  let proposals = 0
  let dispatches = 0

  await assert.rejects(
    () => executeAdversarialCampaign(runtimeOptions(plan, {
      trustedCampaignLedger: crashingLedger,
      runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
      proposeNextAction: async () => (++proposals === 1
        ? tacticalAction('returned-cleanup-crash', { purpose: 'cleanup' })
        : null),
      dispatch: async () => {
        dispatches += 1
        return {
          status: 'OBSERVED',
          output_bytes: 1,
          escalation_triggers: [],
          cleanup_verified: true,
        }
      },
    })),
    (error) => error === crash,
  )
  const crashed = file.ledger.snapshot()
  assert.equal(dispatches, 1)
  assert.equal(crashed.pending_dispatch.action_id, 'action:returned-cleanup-crash')
  assert.equal(crashed.qualification_records.at(-1).type, 'ACTION_DISPATCH_SETTLED')
  assert.equal(crashed.qualification_records.at(-1).receipt.outcome, 'RETURNED')

  const reopened = await openAdversarialCampaignLedger({
    directory: file.directory,
    binding: file.binding,
  })
  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    trustedCampaignLedger: reopened,
    proposeNextAction: async () => { throw new Error('recovery cannot propose') },
    dispatch: async () => { dispatches += 1; return {} },
  }))

  assert.equal(result.status, 'PAUSED_SAFETY')
  assert.equal(dispatches, 1)
  const snapshot = reopened.snapshot()
  assert.equal(snapshot.terminal, true)
  assert.equal(snapshot.pending_dispatch, null)
  assert.equal(snapshot.pending_cleanup_outcome, null)
  assert.equal(snapshot.cleanup_outcomes.at(-1).status, 'INCONCLUSIVE')
  assert.equal(
    snapshot.observations.at(-1).kind,
    'red-team-audit/adversarial-dispatch-recovery-observation',
  )
  assert.deepEqual(snapshot.qualification_records.slice(-4).map(({ type }) => type), [
    'CAMPAIGN_STOP_RECORDED',
    'ACTION_OBSERVATION',
    'ACTION_CLEANUP_OUTCOME',
    'CAMPAIGN_TERMINAL',
  ])
})

test('L3 terminally qualifies cleanup dispatch failures and malformed returns', async (t) => {
  const cases = [
    {
      name: 'transport error',
      dispatch: async () => { throw new Error('synthetic transport failure') },
    },
    {
      name: 'timeout',
      maxActionTimeMs: 10,
      dispatch: async (_action, { signal }) => new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(signal.reason), { once: true })
      }),
    },
    {
      name: 'malformed return',
      dispatch: async () => ({ status: 'OBSERVED', output_bytes: 0, invalid: 1n }),
    },
  ]

  for (const [index, failureCase] of cases.entries()) {
    await t.test(failureCase.name, async (t) => {
      const plan = maximumPlan({
        plan_id: `plan:cleanup-dispatch-failure-${index}`,
        limits: limits({ max_action_time_ms: failureCase.maxActionTimeMs ?? 5_000 }),
      })
      const file = await trustedFileLedger(t, plan)
      let proposals = 0
      const result = await executeAdversarialCampaign(runtimeOptions(plan, {
        trustedCampaignLedger: file.ledger,
        runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
        proposeNextAction: async () => (++proposals === 1
          ? tacticalAction(`cleanup-dispatch-failure-${index}`, { purpose: 'cleanup' })
          : null),
        dispatch: failureCase.dispatch,
      }))

      assert.equal(result.status, 'PAUSED_SAFETY')
      const snapshot = file.ledger.snapshot()
      assert.equal(snapshot.terminal, true)
      assert.equal(snapshot.pending_dispatch, null)
      assert.equal(snapshot.pending_cleanup_outcome, null)
      assert.equal(snapshot.cleanup_outcomes.at(-1).status, 'INCONCLUSIVE')
      assert.equal(
        snapshot.observations.at(-1).kind,
        'red-team-audit/adversarial-dispatch-recovery-observation',
      )
      assert.deepEqual(snapshot.qualification_records.slice(-5).map(({ type }) => type), [
        'ACTION_DISPATCH_SETTLED',
        'ACTION_OBSERVATION',
        'ACTION_CLEANUP_OUTCOME',
        'CAMPAIGN_STOP_RECORDED',
        'CAMPAIGN_TERMINAL',
      ])
    })
  }
})

test('L3 persists a returned cleanup observation with invalid accounting before stopping', async (t) => {
  const plan = maximumPlan({ plan_id: 'plan:cleanup-invalid-output-accounting' })
  const file = await trustedFileLedger(t, plan)
  let proposals = 0
  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    trustedCampaignLedger: file.ledger,
    runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
    proposeNextAction: async () => (++proposals === 1
      ? tacticalAction('cleanup-invalid-output', { purpose: 'cleanup' })
      : null),
    dispatch: async () => ({
      status: 'OBSERVED',
      output_bytes: plan.limits.max_output_bytes + 1,
      escalation_triggers: [],
      cleanup_verified: true,
    }),
  }))

  assert.equal(result.status, 'PAUSED_SAFETY')
  assert.deepEqual(result.stop_reasons, ['ACTION_OUTPUT_LIMIT_OR_ACCOUNTING_INVALID'])
  const snapshot = file.ledger.snapshot()
  assert.equal(snapshot.terminal, true)
  assert.equal(snapshot.pending_dispatch, null)
  assert.equal(snapshot.pending_cleanup_outcome, null)
  assert.equal(snapshot.observations.at(-1).output_bytes, plan.limits.max_output_bytes + 1)
  assert.equal(snapshot.cleanup_outcomes.at(-1).status, 'INCONCLUSIVE')
  assert.deepEqual(snapshot.qualification_records.slice(-5).map(({ type }) => type), [
    'ACTION_DISPATCH_SETTLED',
    'ACTION_OBSERVATION',
    'ACTION_CLEANUP_OUTCOME',
    'CAMPAIGN_STOP_RECORDED',
    'CAMPAIGN_TERMINAL',
  ])
})

test('L3 infers a missed durable checkpoint after a crash before the queue append', async (t) => {
  const plan = maximumPlan({ plan_id: 'plan:checkpoint-crash-recovery' })
  const file = await trustedFileLedger(t, plan)
  const crash = new Error('synthetic crash before checkpoint queue append')
  const crashingLedger = interceptLedgerMethod(
    file.ledger,
    'recordCheckpointQueued',
    async () => { throw crash },
  )
  const actions = [tacticalAction('checkpoint-one'), tacticalAction('checkpoint-two')]
  let dispatches = 0

  await assert.rejects(
    () => executeAdversarialCampaign(runtimeOptions(plan, {
      trustedCampaignLedger: crashingLedger,
      runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
      proposeNextAction: async () => actions.shift() ?? null,
      dispatch: async () => {
        dispatches += 1
        return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
      },
    })),
    (error) => error === crash,
  )
  assert.equal(dispatches, 2)
  assert.equal(file.ledger.snapshot().pending_checkpoint, null)
  assert.equal(file.ledger.snapshot().considered_actions, 2)

  const reopened = await openAdversarialCampaignLedger({
    directory: file.directory,
    binding: file.binding,
  })
  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    trustedCampaignLedger: reopened,
    proposeNextAction: async () => { throw new Error('recovery cannot propose') },
    dispatch: async () => { dispatches += 1; return {} },
  }))
  assert.equal(result.status, 'PAUSED_CHECKPOINT')
  assert.deepEqual(result.stop_reasons, ['MISSED_MANDATORY_CHECKPOINT'])
  assert.equal(dispatches, 2)
  assert.equal(reopened.snapshot().terminal, true)
})

test('L3 derives global and sealed-action stops from durable crash-tail observations', async (t) => {
  const cases = [
    {
      name: 'global',
      trigger: 'OPERATOR_STOP',
      expectedStatus: 'PAUSED_SAFETY',
      configurePlan(plan) {
        return plan
      },
      propose: async () => tacticalAction('durable-global-stop'),
    },
    {
      name: 'sealed',
      trigger: 'UNEXPECTED_SENSITIVE_OR_THIRD_PARTY_DATA',
      expectedStatus: 'PAUSED_ESCALATION',
      configurePlan(plan) {
        plan.actions = exactPlan().actions
        return plan
      },
      propose: undefined,
    },
  ]

  for (const scenario of cases) {
    const plan = scenario.configurePlan(maximumPlan({
      plan_id: `plan:observation-crash-${scenario.name}`,
    }))
    const file = await trustedFileLedger(t, plan)
    const crash = new Error(`synthetic ${scenario.name} crash after observation append`)
    const durableRecordObservation = file.ledger.recordObservation.bind(file.ledger)
    const crashingLedger = interceptLedgerMethod(
      file.ledger,
      'recordObservation',
      async (value) => {
        await durableRecordObservation(value)
        throw crash
      },
    )
    let dispatches = 0
    await assert.rejects(
      () => executeAdversarialCampaign(runtimeOptions(plan, {
        trustedCampaignLedger: crashingLedger,
        runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
        ...(scenario.propose === undefined ? {} : { proposeNextAction: scenario.propose }),
        dispatch: async () => {
          dispatches += 1
          return {
            status: 'OBSERVED',
            output_bytes: 1,
            escalation_triggers: [scenario.trigger],
          }
        },
      })),
      (error) => error === crash,
    )
    assert.equal(dispatches, 1)

    const reopened = await openAdversarialCampaignLedger({
      directory: file.directory,
      binding: file.binding,
    })
    const result = await executeAdversarialCampaign(runtimeOptions(plan, {
      trustedCampaignLedger: reopened,
      ...(scenario.propose === undefined
        ? {}
        : { proposeNextAction: async () => { throw new Error('recovery cannot propose') } }),
      dispatch: async () => { dispatches += 1; return {} },
    }))
    assert.equal(result.status, scenario.expectedStatus)
    assert.deepEqual(result.stop_reasons, [scenario.trigger])
    assert.equal(dispatches, 1)
    assert.equal(reopened.snapshot().terminal, true)
  }
})

test('scope withdrawal at final reauthorization cancels the committed action before target I/O', async () => {
  const plan = exactPlan()
  let scopeChecks = 0
  let dispatches = 0
  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    scopeAuthorize: async (action, context) => {
      scopeChecks += 1
      return {
        ...allowScope(action, context),
        status: scopeChecks === 1 ? 'AUTHORIZED' : 'DENIED',
      }
    },
    dispatch: async () => {
      dispatches += 1
      return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
    },
  }))

  assert.equal(result.status, 'PAUSED_SCOPE')
  assert.equal(scopeChecks, 2)
  assert.equal(dispatches, 0)
})

test('L2 supervised live plans require an acknowledged checkpoint at each action phase', async () => {
  const plan = exactPlan({ overrides: { autonomy_profile: 'L2_SUPERVISED' } })
  const checkpoints = []
  const dispatched = []
  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    checkpoint: async (record) => {
      checkpoints.push(structuredClone(record))
      return {
        decision: 'CONTINUE',
        plan_sha256: record.plan_sha256,
        authorization_id: record.authorization_id,
        scope_revision_sha256: record.scope_revision_sha256,
        actions_used: record.actions_used,
        next_phase: record.next_phase,
        next_action_sha256: record.next_action_sha256,
      }
    },
    dispatch: async (action) => {
      dispatched.push(action.action_id)
      return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
    },
  }))

  assert.equal(result.status, 'COMPLETED')
  assert.deepEqual(dispatched, ['action:control-001', 'action:attack-001'])
  assert.deepEqual(checkpoints.map(({ next_phase: phase }) => phase), ['control', 'attack'])
  assert.ok(checkpoints.every(({ kind }) => kind === 'red-team-audit/adversarial-supervised-phase-checkpoint'))
})

test('L2 supervised live execution performs zero dispatch without its phase checkpoint sink', async () => {
  const plan = exactPlan({ overrides: { autonomy_profile: 'L2_SUPERVISED' } })
  let dispatches = 0
  await assert.rejects(
    () => executeAdversarialCampaign(runtimeOptions(plan, {
      checkpoint: undefined,
      dispatch: async () => { dispatches += 1; return {} },
    })),
    (error) => error.code === 'ADVERSARIAL_SUPERVISION_REQUIRED',
  )
  assert.equal(dispatches, 0)
})

test('repository and disposable local-service plans do not consume a live authorization', async () => {
  for (const targetKind of ['repository', 'local_service']) {
    const plan = exactPlan({ targetKind })
    let dispatches = 0
    const result = await executeAdversarialCampaign({
      ...runtimeOptions(plan),
      scopeAuthorize: undefined,
      dispatch: async () => {
        dispatches += 1
        return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
      },
    })
    assert.equal(result.status, 'COMPLETED', targetKind)
    assert.equal(dispatches, 2, targetKind)
    assert.equal(result.authorization_receipt, null)
  }
})

test('local and repository execution labels cannot disguise remote target locators', async () => {
  for (const [targetKind, locator, code] of [
    ['local_service', 'https://example.com', 'ADVERSARIAL_LOCAL_SERVICE_TARGET_INVALID'],
    ['repository', 'file:///tmp/disguised', 'ADVERSARIAL_REPOSITORY_TARGET_INVALID'],
  ]) {
    const plan = exactPlan({ targetKind })
    plan.target.locator = locator
    let dispatches = 0
    await assert.rejects(
      () => executeAdversarialCampaign({
        ...runtimeOptions(plan),
        scopeAuthorize: undefined,
        dispatch: async () => { dispatches += 1; return {} },
      }),
      (error) => error.code === code,
    )
    assert.equal(dispatches, 0)
  }
})

test('a non-L3 plan with no actions cannot report a zero-work completion', async () => {
  const plan = exactPlan({ targetKind: 'repository' })
  delete plan.actions
  let dispatches = 0
  await assert.rejects(
    () => executeAdversarialCampaign({
      ...runtimeOptions(plan),
      scopeAuthorize: undefined,
      dispatch: async () => { dispatches += 1; return {} },
    }),
    (error) => error.code === 'ADVERSARIAL_EXECUTION_SHAPE_EMPTY',
  )
  assert.equal(dispatches, 0)
})

test('runtime refuses a valid but unwired generator plan instead of reporting false completion', async () => {
  const plan = exactPlan({ targetKind: 'repository' })
  delete plan.actions
  plan.generator = {
    generator_id: 'generator:runtime-unwired',
    algorithm: 'fast-check',
    version: '4.9.0',
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
  let dispatches = 0
  await assert.rejects(
    () => executeAdversarialCampaign({
      ...runtimeOptions(plan),
      scopeAuthorize: undefined,
      dispatch: async () => { dispatches += 1; return {} },
    }),
    (error) => error.code === 'ADVERSARIAL_GENERATOR_UNSUPPORTED',
  )
  assert.equal(dispatches, 0)
})

test('Break Their Bones autonomously chooses tactical scope and checkpoints inside its envelope', async () => {
  const plan = maximumPlan()
  const queue = [
    tacticalAction('authz'),
    tacticalAction('fuzz', {
      branch_id: 'branch:authz',
      chain_depth: 2,
      action_category: 'input.fuzz',
      operation: 'fuzzer.case',
      strategy_family: 'structured-fuzzing',
    }),
  ]
  const checkpoints = []
  const campaignLedger = trustedControllerLedger()
  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    trustedCampaignLedger: campaignLedger,
    runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
    proposeNextAction: async () => queue.shift() ?? null,
    checkpoint: async (state) => {
      checkpoints.push(structuredClone(state))
      return {
        decision: 'CONTINUE',
        plan_sha256: state.plan_sha256,
        authorization_id: state.authorization_id,
        scope_revision_sha256: state.scope_revision_sha256,
        actions_used: state.actions_used,
      }
    },
  }))

  assert.equal(result.status, 'COMPLETED')
  assert.equal(result.dispatched_actions, 2)
  assert.equal(result.preflight_mode, 'NORMAL')
  assert.equal(checkpoints.length, 1)
  assert.equal(checkpoints[0].actions_used, 2)
  assert.deepEqual(campaignLedger.events.map(({ type }) => type), [
    'CAMPAIGN_STARTED',
    'ACTION_PROPOSED',
    'ACTION_CLASSIFIED',
    'ACTION_CONSIDERED',
    'SCOPE_DECISION_RECORDED',
    'ACTION_PREFLIGHT_RECORDED',
    'ACTION_BOUNDARY_DECIDED',
    'ACTION_PRE_DISPATCH',
    'SCOPE_DECISION_RECORDED',
    'ACTION_PREFLIGHT_RECORDED',
    'ACTION_SEND_PERMITTED',
    'ACTION_DISPATCH_SETTLED',
    'ACTION_OBSERVATION',
    'ACTION_PROPOSED',
    'ACTION_CLASSIFIED',
    'ACTION_CONSIDERED',
    'SCOPE_DECISION_RECORDED',
    'ACTION_PREFLIGHT_RECORDED',
    'ACTION_BOUNDARY_DECIDED',
    'ACTION_PRE_DISPATCH',
    'SCOPE_DECISION_RECORDED',
    'ACTION_PREFLIGHT_RECORDED',
    'ACTION_SEND_PERMITTED',
    'ACTION_DISPATCH_SETTLED',
    'ACTION_OBSERVATION',
    'CHECKPOINT_QUEUED',
    'CHECKPOINT_ACKNOWLEDGED',
    'CAMPAIGN_TERMINAL',
  ])
})

test('Break Their Bones qualifies cleanup separately before the terminal outcome', async () => {
  const plan = maximumPlan()
  const campaignLedger = trustedControllerLedger()
  let proposals = 0
  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    trustedCampaignLedger: campaignLedger,
    runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
    proposeNextAction: async () => {
      proposals += 1
      return proposals === 1 ? tacticalAction('cleanup', { purpose: 'cleanup' }) : null
    },
    dispatch: async (action) => ({
      action_id: action.action_id,
      status: 'OBSERVED',
      cleanup_verified: true,
      output_bytes: 32,
      escalation_triggers: [],
    }),
  }))

  assert.equal(result.status, 'COMPLETED')
  assert.deepEqual(campaignLedger.events.slice(-3).map(({ type }) => type), [
    'ACTION_OBSERVATION',
    'ACTION_CLEANUP_OUTCOME',
    'CAMPAIGN_TERMINAL',
  ])
  assert.equal(campaignLedger.events.at(-2).receipt.status, 'VERIFIED')
})

test('adaptive planning receives bounded receipts rather than raw target observations', async () => {
  const plan = maximumPlan()
  const secret = 'SYNTHETIC_PRIVATE_RESPONSE_TOKEN_7f89'
  let proposals = 0
  let secondContext
  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
    proposeNextAction: async (context) => {
      proposals += 1
      if (proposals === 1) return tacticalAction('redacted-feedback')
      secondContext = structuredClone(context)
      return null
    },
    dispatch: async () => ({
      status: 'OBSERVED',
      output_bytes: 32,
      evidence: secret,
      escalation_triggers: [],
    }),
  }))

  assert.equal(result.status, 'COMPLETED')
  assert.equal(Object.hasOwn(secondContext, 'observations'), false)
  assert.equal(JSON.stringify(secondContext).includes(secret), false)
  assert.equal(secondContext.observation_receipts.length, 1)
  assert.equal(secondContext.observation_receipts[0].status, 'OBSERVED')
  assert.match(secondContext.observation_receipts[0].observation_sha256, /^[a-f0-9]{64}$/)
  assert.equal(result.observations[0].evidence, secret)
})

test('an exact L3 dispatch receives the same governed action bytes that scope and boundary authorized', async () => {
  const plan = maximumPlan()
  plan.actions = exactPlan().actions
  const authorized = []
  const dispatched = []
  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
    scopeAuthorize: async (action, context) => {
      authorized.push(structuredClone(action))
      return allowScope(action, context)
    },
    dispatch: async (action) => {
      dispatched.push(structuredClone(action))
      return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
    },
  }))

  assert.equal(result.status, 'COMPLETED')
  assert.deepEqual(
    authorized,
    dispatched.flatMap((action) => [action, action, action, action]),
    'each L3 action is scope-bound initially, before and after the permit, and after async authorization checks',
  )
  assert.deepEqual(dispatched.map(({ branch_id: branch }) => branch), [
    'branch:sealed-actions',
    'branch:sealed-actions',
  ])
  assert.ok(dispatched.every(({ chain_depth: depth }) => depth === 1))
  assert.ok(dispatched.every(({ strategy_family: family }) => family === 'authorization-testing'))
})

test('an out-of-envelope tactical lead queues a scope request and other branches continue', async () => {
  const plan = maximumPlan()
  const queue = [
    tacticalAction('outside', {
      operation: 'cloud.control-plane',
      action_category: 'cloud.iam',
      strategy_family: 'cloud-privilege-testing',
    }),
    tacticalAction('inside'),
  ]
  const requests = []
  const dispatched = []
  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
    proposeNextAction: async () => queue.shift() ?? null,
    scopeRequestSink: async (request) => requests.push(request),
    dispatch: async (action) => {
      dispatched.push(action.action_id)
      return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
    },
  }))

  assert.equal(result.status, 'COMPLETED_WITH_BLOCKED_BRANCHES')
  assert.deepEqual(dispatched, ['action:inside'])
  assert.equal(requests.length, 1)
  assert.equal(requests[0].kind, 'red-team-audit/adversarial-scope-request')
  assert.equal(requests[0].attack_plan_sha256, digestAdversarialPlan(plan))
  assert.equal(
    requests[0].discovery_evidence.some(({ sha256 }) => sha256.length === 64),
    true,
  )
})

test('maximum-authority execution requires a formal scope-request builder before target I/O', async () => {
  const plan = maximumPlan()
  let dispatches = 0
  await assert.rejects(
    () => executeAdversarialCampaign(runtimeOptions(plan, {
      scopeRequestBuilder: undefined,
      runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
      proposeNextAction: async () => tacticalAction('outside-without-builder', {
        operation: 'cloud.control-plane',
        action_category: 'cloud.iam',
        strategy_family: 'cloud-privilege-testing',
      }),
      dispatch: async () => { dispatches += 1; return {} },
    })),
    (error) => error.code === 'ADVERSARIAL_SCOPE_REQUEST_BUILDER_REQUIRED',
  )
  assert.equal(dispatches, 0)
})

test('a mandatory escalation pauses its branch while unrelated work can finish', async () => {
  const plan = maximumPlan()
  const queue = [
    tacticalAction('sensitive'),
    tacticalAction('same-branch', { branch_id: 'branch:sensitive', chain_depth: 2 }),
    tacticalAction('independent'),
  ]
  const dispatched = []
  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
    proposeNextAction: async () => queue.shift() ?? null,
    dispatch: async (action) => {
      dispatched.push(action.action_id)
      return {
        status: 'OBSERVED',
        output_bytes: 1,
        escalation_triggers: action.action_id === 'action:sensitive'
          ? ['UNEXPECTED_SENSITIVE_OR_THIRD_PARTY_DATA']
          : [],
      }
    },
  }))

  assert.equal(result.status, 'COMPLETED_WITH_BLOCKED_BRANCHES')
  assert.deepEqual(dispatched, ['action:sensitive', 'action:independent'])
  assert.deepEqual(result.paused_branches, ['branch:sensitive'])
})

test('a dynamic kill-switch failure stops all further dispatch and cannot be broken-glass waived', async () => {
  const plan = maximumPlan()
  const queue = [tacticalAction('one'), tacticalAction('two')]
  let preflightReads = 0
  let dispatches = 0
  const ready = Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true]))
  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    runtimePreflight: () => {
      preflightReads += 1
      return preflightReads < 5 ? ready : { ...ready, operator_kill_switch: false }
    },
    proposeNextAction: async () => queue.shift() ?? null,
    dispatch: async () => {
      dispatches += 1
      return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
    },
  }))
  assert.equal(result.status, 'PAUSED_SAFETY')
  assert.equal(dispatches, 1)
  assert.ok(result.stop_reasons.includes('NON_OVERRIDABLE_RUNTIME_PREFLIGHT:operator_kill_switch'))
})

test('a separately signed break-glass artifact binds the operator authorization receipt', async () => {
  const plan = maximumPlan({
    risk_class: 'READ_ONLY',
    limits: limits({ max_actions: 2 }),
  })
  plan.campaign_envelope.max_actions = 2
  plan.campaign_envelope.max_chain_depth = 2
  const authorizationReceipt = campaignAuthorizationReceiptFor(plan)
  const breakGlassKey = keys()
  const { createHash, createPublicKey } = await import('node:crypto')
  const publicObject = createPublicKey(breakGlassKey.publicKey)
  const keyId = `ed25519:${createHash('sha256')
    .update(publicObject.export({ type: 'spki', format: 'der' })).digest('hex')}`
  const override = createAdversarialBreakGlassOverride({
    plan,
    authorizationReceipt,
    overrideId: 'break-glass:runtime-001',
    failedControls: [{
      control: 'target_health_monitoring',
      status: 'UNAVAILABLE',
      observation_sha256: SHA_D,
    }],
    rationale: 'The isolated target does not expose the ordinary health telemetry adapter.',
    incidentReference: 'change:runtime-001',
    compensatingLimits: {
      max_actions: 1,
      max_wall_time_ms: 15_000,
      max_aggregate_output_bytes: 8_192,
      max_concurrency: 1,
    },
    issuedAt: '2026-09-03T10:05:00.000Z',
    expiresAt: '2026-09-03T10:10:00.000Z',
    nonce: 'BREAK_GLASS_RUNTIME_NONCE_001',
    approver: { id: 'operator:executive', role: 'SECURITY_EXECUTIVE' },
    privateKey: breakGlassKey.privateKey,
  })
  const ready = Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true]))
  ready.target_health_monitoring = false
  ready.control_observations = {
    target_health_monitoring: {
      status: 'UNAVAILABLE',
      observation_sha256: SHA_D,
    },
  }
  const queue = [tacticalAction('break-glass')]
  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    runtimePreflight: ready,
    proposeNextAction: async () => queue.shift() ?? null,
    breakGlassOverride: override,
    breakGlassPinnedKey: {
      key_id: keyId,
      public_key: breakGlassKey.publicKey,
      approver_id: 'operator:executive',
      approver_role: 'SECURITY_EXECUTIVE',
      delegations: ['break_glass'],
    },
    breakGlassNonceStore: oneUseStore(),
  }))
  assert.equal(result.status, 'LIMIT_EXHAUSTED')
  assert.equal(result.preflight_mode, 'BREAK_GLASS')
  assert.deepEqual(result.waived_preflight_controls, ['target_health_monitoring'])
  assert.equal(result.dispatched_actions, 1)
})

test('adaptive actions reject unknown fields and duplicate action identities before replay', async () => {
  const plan = maximumPlan()
  const unknownLedger = trustedControllerLedger()
  let dispatches = 0
  const unknown = tacticalAction('unknown', { provider_bypass: true })
  await assert.rejects(
    () => executeAdversarialCampaign(runtimeOptions(plan, {
      trustedCampaignLedger: unknownLedger,
      runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
      proposeNextAction: async () => unknown,
      dispatch: async () => { dispatches += 1; return {} },
    })),
    (error) => error.code === 'ADVERSARIAL_TACTICAL_ACTION_INVALID',
  )
  assert.equal(dispatches, 0)
  assert.deepEqual(unknownLedger.events.slice(-2).map(({ type }) => type), [
    'CAMPAIGN_STOP_RECORDED',
    'CAMPAIGN_TERMINAL',
  ])
  assert.equal(unknownLedger.events.some(({ type }) => type === 'ACTION_PROPOSED'), false)

  const replayPlan = maximumPlan({ plan_id: 'plan:break-their-bones-replay' })
  const repeated = tacticalAction('repeat')
  const replayLedger = trustedControllerLedger()
  let proposals = 0
  await assert.rejects(
    () => executeAdversarialCampaign(runtimeOptions(replayPlan, {
      trustedCampaignLedger: replayLedger,
      runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
      proposeNextAction: async () => (++proposals <= 2 ? repeated : null),
      dispatch: async () => {
        dispatches += 1
        return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
      },
    })),
    (error) => error.code === 'ADVERSARIAL_ACTION_REPLAY',
  )
  assert.equal(proposals, 2)
  assert.deepEqual(replayLedger.events.slice(-2).map(({ type }) => type), [
    'CAMPAIGN_STOP_RECORDED',
    'CAMPAIGN_TERMINAL',
  ])
  assert.equal(
    replayLedger.events.filter(({ type }) => type === 'ACTION_PROPOSED').length,
    1,
  )
})

test('scope revision drift blocks the concrete action before dispatch', async () => {
  const plan = exactPlan()
  let dispatches = 0
  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    scopeAuthorize: async (action, context) => ({
      ...allowScope(action, context),
      scope_revision_sha256: 'e'.repeat(64),
    }),
    dispatch: async () => { dispatches += 1; return {} },
  }))
  assert.equal(result.status, 'PAUSED_SCOPE')
  assert.equal(dispatches, 0)
  assert.match(result.stop_reasons.join(' '), /exact current action.*scope revision/i)
})

test('action timeout propagates an abort signal to the trusted transport', async () => {
  const plan = exactPlan({
    targetKind: 'local_service',
    overrides: { limits: limits({ max_action_time_ms: 10 }) },
  })
  let aborted = false
  await assert.rejects(
    () => executeAdversarialCampaign({
      ...runtimeOptions(plan),
      scopeAuthorize: undefined,
      dispatch: async (_action, { signal }) => new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => {
          aborted = true
          reject(signal.reason)
        }, { once: true })
      }),
    }),
    (error) => error.code === 'ADVERSARIAL_ACTION_TIMEOUT',
  )
  assert.equal(aborted, true)
})

test('dispatch timeout cannot exceed the remaining authorized campaign wall budget', async () => {
  const plan = exactPlan({
    targetKind: 'local_service',
    overrides: {
      limits: limits({ max_action_time_ms: 140, max_wall_time_ms: 150 }),
    },
  })
  const startedAt = Date.now()
  let dispatches = 0
  await assert.rejects(
    () => executeAdversarialCampaign({
      ...runtimeOptions(plan),
      scopeAuthorize: undefined,
      clock: () => Date.now(),
      dispatch: async (_action, { signal }) => new Promise((resolve, reject) => {
        signal.addEventListener('abort', () => reject(signal.reason), { once: true })
        dispatches += 1
        if (dispatches === 1) setTimeout(() => resolve({
          status: 'OBSERVED', output_bytes: 1, escalation_triggers: [],
        }), 100)
      }),
    }),
    (error) => error.code === 'ADVERSARIAL_ACTION_TIMEOUT',
  )
  assert.ok(Date.now() - startedAt < 210)
})

test('operator kill signals a cooperative transport but reports termination as ambiguous', async () => {
  const plan = exactPlan({
    targetKind: 'local_service',
    overrides: { limits: limits({ max_action_time_ms: 1_000 }) },
  })
  const campaign = new AbortController()
  let transportAborted = false
  const pending = executeAdversarialCampaign({
    ...runtimeOptions(plan),
    scopeAuthorize: undefined,
    signal: campaign.signal,
    dispatch: async (_action, { signal }) => new Promise((_resolve, reject) => {
      signal.addEventListener('abort', () => {
        transportAborted = true
        reject(signal.reason)
      }, { once: true })
      setImmediate(() => campaign.abort(new Error('operator kill')))
    }),
  })

  const result = await pending
  assert.equal(result.status, 'PAUSED_SAFETY')
  assert.deepEqual(result.stop_reasons, ['ABORT_REQUESTED_DISPATCH_AMBIGUOUS'])
  assert.equal(transportAborted, true)
})

test('plan-defined minimum action interval is enforced by the runtime scheduler', async () => {
  const plan = exactPlan({
    targetKind: 'local_service',
    overrides: { limits: limits({ min_action_interval_ms: 30 }) },
  })
  const dispatchTimes = []
  const result = await executeAdversarialCampaign({
    ...runtimeOptions(plan),
    scopeAuthorize: undefined,
    dispatch: async () => {
      dispatchTimes.push(Date.now())
      return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
    },
  })
  assert.equal(result.status, 'COMPLETED')
  assert.equal(dispatchTimes.length, 2)
  assert.ok(dispatchTimes[1] - dispatchTimes[0] >= 25)
})

test('invalid or oversized observation accounting stops the campaign', async () => {
  const plan = exactPlan({ targetKind: 'local_service' })
  const result = await executeAdversarialCampaign({
    ...runtimeOptions(plan),
    scopeAuthorize: undefined,
    dispatch: async () => ({
      status: 'OBSERVED',
      output_bytes: plan.limits.max_output_bytes + 1,
      escalation_triggers: [],
    }),
  })
  assert.equal(result.status, 'PAUSED_SAFETY')
  assert.equal(result.dispatched_actions, 1)
  assert.ok(result.stop_reasons.includes('ACTION_OUTPUT_LIMIT_OR_ACCOUNTING_INVALID'))
})

test('aggregate output accounts for canonical evidence when an adapter lies with zero bytes', async () => {
  const plan = exactPlan({
    targetKind: 'local_service',
    overrides: {
      limits: limits({
        max_output_bytes: 1_024,
        max_aggregate_output_bytes: 2_000,
      }),
    },
  })
  const result = await executeAdversarialCampaign({
    ...runtimeOptions(plan),
    scopeAuthorize: undefined,
    dispatch: async () => ({
      status: 'OBSERVED',
      output_bytes: 0,
      evidence: 'x'.repeat(800),
      escalation_triggers: [],
    }),
  })
  assert.equal(result.status, 'COMPLETED')
  assert.ok(result.aggregate_output_bytes > 1_600)
  assert.ok(result.aggregate_output_bytes < plan.limits.max_aggregate_output_bytes)
})

test('dispatch receives a shrinking output cap and cannot overrun the aggregate budget', async () => {
  const plan = exactPlan({
    targetKind: 'local_service',
    overrides: {
      limits: limits({
        max_output_bytes: 1_024,
        max_aggregate_output_bytes: 1_500,
      }),
    },
  })
  const caps = []
  const result = await executeAdversarialCampaign({
    ...runtimeOptions(plan),
    scopeAuthorize: undefined,
    dispatch: async (_action, context) => {
      caps.push(context.max_output_bytes)
      return {
        status: 'OBSERVED',
        output_bytes: context.max_output_bytes,
        escalation_triggers: [],
      }
    },
  })

  assert.equal(result.status, 'LIMIT_EXHAUSTED')
  assert.deepEqual(caps, [1_024, 476])
  assert.equal(result.aggregate_output_bytes, plan.limits.max_aggregate_output_bytes)
  assert.ok(result.stop_reasons.includes('MAX_AGGREGATE_OUTPUT_EXHAUSTED'))
})

test('live execution requires revocation checking and fails closed when that check breaks', async () => {
  const plan = exactPlan()
  let dispatches = 0
  await assert.rejects(
    () => executeAdversarialCampaign(runtimeOptions(plan, {
      isAuthorizationRevoked: undefined,
      dispatch: async () => { dispatches += 1; return {} },
    })),
    (error) => error.code === 'ADVERSARIAL_REVOCATION_GATE_REQUIRED',
  )
  assert.equal(dispatches, 0)

  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    isAuthorizationRevoked: async () => { throw new Error('revocation store offline') },
    dispatch: async () => { dispatches += 1; return {} },
  }))
  assert.equal(result.status, 'PAUSED_AUTHORIZATION')
  assert.deepEqual(result.stop_reasons, ['AUTHORIZATION_REVOCATION_CHECK_FAILED'])
  assert.equal(dispatches, 0)
})

test('controller snapshots defeat post-verification plan and action mutation', async () => {
  const plan = exactPlan()
  const expectedActions = structuredClone(plan.actions)
  const dispatched = []
  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    scopeAuthorize: async (action, context) => {
      plan.actions[1].parameters.url = 'https://attacker.invalid/mutated-plan'
      action.parameters.url = 'https://attacker.invalid/mutated-action'
      return allowScope(action, context)
    },
    dispatch: async (action) => {
      dispatched.push(structuredClone(action))
      return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
    },
  }))
  assert.equal(result.status, 'COMPLETED')
  assert.deepEqual(dispatched, expectedActions)
})

test('scope authorization must bind the exact action and controller classification', async () => {
  const plan = exactPlan()
  let dispatches = 0
  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    scopeAuthorize: async (action, context) => ({
      ...allowScope(action, context),
      action_sha256: '0'.repeat(64),
    }),
    dispatch: async () => { dispatches += 1; return {} },
  }))
  assert.equal(result.status, 'PAUSED_SCOPE')
  assert.equal(dispatches, 0)
})

test('controller-classified prohibited effects never reach live scope or dispatch', async () => {
  const plan = maximumPlan()
  let scopeChecks = 0
  let dispatches = 0
  await assert.rejects(
    () => executeAdversarialCampaign(runtimeOptions(plan, {
      runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
      proposeNextAction: async () => tacticalAction('persistence'),
      classifyAction: async () => ({
        candidate_context: { target_kind: 'live' },
        resolved_target: structuredClone(plan.target),
        anticipated_effects: ['PERSISTENCE'],
        strategy_family: 'authorization-testing',
      }),
      scopeAuthorize: async () => { scopeChecks += 1; return {} },
      dispatch: async () => { dispatches += 1; return {} },
    })),
    (error) => error.code === 'ADVERSARIAL_PROHIBITED_EFFECT',
  )
  assert.equal(scopeChecks, 0)
  assert.equal(dispatches, 0)
})

test('unknown and under-classified effects fail before scope or dispatch', async () => {
  for (const anticipatedEffects of [['delete.records'], ['AVAILABILITY_IMPACT']]) {
    const plan = maximumPlan({ risk_class: 'READ_ONLY' })
    let scopeChecks = 0
    let dispatches = 0
    await assert.rejects(
      () => executeAdversarialCampaign(runtimeOptions(plan, {
        runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
        proposeNextAction: async () => tacticalAction(`effect-${scopeChecks}-${dispatches}`),
        classifyAction: async () => ({
          candidate_context: { target_kind: 'live' },
          resolved_target: structuredClone(plan.target),
          anticipated_effects: anticipatedEffects,
          strategy_family: 'authorization-testing',
        }),
        scopeAuthorize: async () => { scopeChecks += 1; return {} },
        dispatch: async () => { dispatches += 1; return {} },
      })),
      (error) => ['ADVERSARIAL_EFFECT_UNKNOWN', 'ADVERSARIAL_EFFECT_RISK_UNDERCLASSIFIED']
        .includes(error.code),
    )
    assert.equal(scopeChecks, 0)
    assert.equal(dispatches, 0)
  }
})

test('mandatory checkpoints pause when their exact continuation is not acknowledged', async () => {
  const plan = maximumPlan()
  const queue = [tacticalAction('checkpoint-one'), tacticalAction('checkpoint-two'), tacticalAction('checkpoint-three')]
  let dispatches = 0
  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
    proposeNextAction: async () => queue.shift() ?? null,
    checkpoint: async () => undefined,
    dispatch: async () => {
      dispatches += 1
      return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
    },
  }))
  assert.equal(result.status, 'PAUSED_CHECKPOINT')
  assert.deepEqual(result.stop_reasons, ['CHECKPOINT_NOT_ACKNOWLEDGED'])
  assert.equal(dispatches, 2)
})

test('maximum-authority repository campaigns still require current authorization and scope currency', async () => {
  const plan = maximumPlan({
    target: {
      kind: 'repository',
      target_id: 'target:repository-mirror',
      locator: 'repository://disposable-mirror',
      identity_sha256: SHA_C,
    },
  })
  plan.campaign_envelope.applicability_conditions[0].value = 'repository'
  plan.campaign_envelope.decision_rules[0].when_all[0].value = 'repository'
  let dispatches = 0
  await assert.rejects(
    () => executeAdversarialCampaign({
      ...runtimeOptions(plan),
      operatorAuthorizationReceipt: undefined,
      dispatch: async () => { dispatches += 1; return {} },
    }),
    (error) => error.code === 'ADVERSARIAL_LIVE_AUTHORIZATION_REQUIRED',
  )
  assert.equal(dispatches, 0)

  const queue = [tacticalAction('repository', {
    operation: 'fuzzer.case',
    action_category: 'input.fuzz',
    strategy_family: 'structured-fuzzing',
    parameters: { fixture: 'disposable-mirror' },
  })]
  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
    proposeNextAction: async () => queue.shift() ?? null,
    classifyAction: async () => ({
      candidate_context: { target_kind: 'repository' },
      resolved_target: structuredClone(plan.target),
      anticipated_effects: [],
      strategy_family: 'structured-fuzzing',
    }),
    dispatch: async () => {
      dispatches += 1
      return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
    },
  }))
  assert.equal(result.status, 'COMPLETED')
  assert.equal(dispatches, 1)
})

test('sealed L3 actions pass the same candidate, scope, effect, and authorization boundary', async () => {
  const envelopePlan = maximumPlan()
  const plan = exactPlan({
    overrides: {
      plan_id: 'plan:sealed-l3-boundary-001',
      strategy_id: 'campaign.adaptive/multi-strategy-v1',
      risk_class: 'STATE_CHANGE',
      autonomy_profile: 'L3_MAXIMUM_AUTHORIZED',
      limits: limits({ max_actions: 6 }),
      preflight: structuredClone(envelopePlan.preflight),
      campaign_envelope: structuredClone(envelopePlan.campaign_envelope),
    },
  })
  let scopeChecks = 0
  let dispatches = 0
  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    runtimePreflight: Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true])),
    classifyAction: async () => ({
      candidate_context: { target_kind: 'repository' },
      resolved_target: {
        kind: 'repository',
        target_id: 'target:wrong-kind',
        locator: 'repository://wrong-kind',
        identity_sha256: plan.target.identity_sha256,
      },
      anticipated_effects: [],
      strategy_family: 'authorization-testing',
    }),
    scopeAuthorize: async (action, context) => {
      scopeChecks += 1
      return allowScope(action, context)
    },
    dispatch: async () => {
      dispatches += 1
      return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
    },
  }))
  assert.equal(result.status, 'PAUSED_SAFETY')
  assert.ok(result.stop_reasons.includes('CONTROLLER_TARGET_BINDING_INVALID'))
  assert.equal(scopeChecks, 1)
  assert.equal(dispatches, 0)
})

test('authorization expiry during an awaited scope decision blocks the exact action before dispatch', async () => {
  const plan = exactPlan()
  let currentTime = Date.parse('2026-09-03T10:05:00.000Z')
  let dispatches = 0
  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    wallClock: () => currentTime,
    monotonicClock: () => 0,
    scopeAuthorize: async (action, context) => {
      currentTime = Date.parse('2026-09-03T10:11:00.000Z')
      return allowScope(action, context)
    },
    dispatch: async () => {
      dispatches += 1
      return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
    },
  }))
  assert.equal(result.status, 'PAUSED_AUTHORIZATION')
  assert.deepEqual(result.stop_reasons, ['AUTHORIZATION_EXPIRED'])
  assert.equal(dispatches, 0)
})

test('a backwards wall-clock jump pauses before target dispatch', async () => {
  const plan = exactPlan()
  let wallTime = Date.parse('2026-09-03T10:05:00.000Z')
  let monotonicTime = 1_000
  let dispatches = 0
  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    wallClock: () => wallTime,
    monotonicClock: () => monotonicTime,
    scopeAuthorize: async (action, context) => {
      wallTime -= 1
      monotonicTime += 1
      return allowScope(action, context)
    },
    dispatch: async () => {
      dispatches += 1
      return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
    },
  }))
  assert.equal(result.status, 'PAUSED_SAFETY')
  assert.deepEqual(result.stop_reasons, ['RUNTIME_WALL_CLOCK_REGRESSION'])
  assert.equal(dispatches, 0)
})

test('a backwards monotonic-clock jump pauses before target dispatch', async () => {
  const plan = exactPlan()
  const wallTime = Date.parse('2026-09-03T10:05:00.000Z')
  let monotonicTime = 1_000
  let dispatches = 0
  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    wallClock: () => wallTime,
    monotonicClock: () => monotonicTime,
    scopeAuthorize: async (action, context) => {
      monotonicTime -= 1
      return allowScope(action, context)
    },
    dispatch: async () => {
      dispatches += 1
      return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
    },
  }))
  assert.equal(result.status, 'PAUSED_SAFETY')
  assert.deepEqual(result.stop_reasons, ['RUNTIME_MONOTONIC_CLOCK_REGRESSION'])
  assert.equal(dispatches, 0)
})

test('authorization revocation during an awaited scope decision is rechecked before dispatch', async () => {
  const plan = exactPlan()
  let revoked = false
  let dispatches = 0
  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    isAuthorizationRevoked: async () => revoked,
    scopeAuthorize: async (action, context) => {
      revoked = true
      return allowScope(action, context)
    },
    dispatch: async () => {
      dispatches += 1
      return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
    },
  }))
  assert.equal(result.status, 'PAUSED_AUTHORIZATION')
  assert.deepEqual(result.stop_reasons, ['AUTHORIZATION_REVOKED'])
  assert.equal(dispatches, 0)
})

test('L3 control-plane loss during awaited action gates is rechecked before dispatch', async () => {
  const plan = maximumPlan()
  const ready = Object.fromEntries(L3_PREFLIGHT_FLAGS.map((flag) => [flag, true]))
  let preflight = ready
  let dispatches = 0
  const campaignLedger = trustedControllerLedger()
  const result = await executeAdversarialCampaign(runtimeOptions(plan, {
    trustedCampaignLedger: campaignLedger,
    runtimePreflight: () => preflight,
    proposeNextAction: async () => tacticalAction('toctou-preflight'),
    scopeAuthorize: async (action, context) => {
      preflight = { ...ready, control_plane_loss_failsafe: false }
      return allowScope(action, context)
    },
    dispatch: async () => {
      dispatches += 1
      return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
    },
  }))
  assert.equal(result.status, 'PAUSED_SAFETY')
  assert.ok(result.stop_reasons.includes('NON_OVERRIDABLE_RUNTIME_PREFLIGHT:control_plane_loss_failsafe'))
  assert.equal(dispatches, 0)
  assert.deepEqual(campaignLedger.events.slice(-4).map(({ type }) => type), [
    'ACTION_PREFLIGHT_RECORDED',
    'CAMPAIGN_STOP_RECORDED',
    'ACTION_SKIPPED',
    'CAMPAIGN_TERMINAL',
  ])
  assert.equal(
    campaignLedger.events.at(-3).receipt.stop_reasons_sha256,
    digestJson(result.stop_reasons),
  )
})
