import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, readdir, writeFile } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  digestAdversarialPlan,
} from '../scripts/lib/adversarial-validation-contracts.mjs'
import { executeAdversarialCampaign } from '../scripts/lib/adversarial-runtime.mjs'
import {
  openAdversarialCampaignLedger,
} from '../scripts/lib/adversarial-campaign-ledger.mjs'
import { stableJson } from '../scripts/lib/run-engine.mjs'

const SHA_B = 'b'.repeat(64)
const SHA_C = 'c'.repeat(64)
const QUALIFICATION_EVENTS = [
  'CAMPAIGN_STARTED',
  'CAMPAIGN_RESUMED',
  'ACTION_PROPOSED',
  'ACTION_CLASSIFIED',
  'ACTION_CONSIDERED',
  'ACTION_SKIPPED',
  'SCOPE_DECISION_RECORDED',
  'SCOPE_REQUEST_QUEUED',
  'ACTION_PREFLIGHT_RECORDED',
  'ACTION_BOUNDARY_DECIDED',
  'CHECKPOINT_QUEUED',
  'CHECKPOINT_ACKNOWLEDGED',
  'ACTION_PRE_DISPATCH',
  'ACTION_SEND_PERMITTED',
  'ACTION_DISPATCH_SETTLED',
  'ACTION_OBSERVATION',
  'ACTION_DISPATCH_CANCELLED',
  'CAMPAIGN_STOP_RECORDED',
  'ACTION_CLEANUP_OUTCOME',
  'CAMPAIGN_TERMINAL',
]

function digestJson(value) {
  const rendered = stableJson(value, 0)
  const canonical = rendered.endsWith('\n') ? rendered.slice(0, -1) : rendered
  return createHash('sha256').update(Buffer.from(canonical, 'utf8')).digest('hex')
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

function localPlan() {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-plan',
    plan_id: 'plan:ledger-runtime-001',
    engagement_id: 'engagement:ledger-runtime-001',
    scope_revision_sha256: SHA_B,
    candidate_id: 'candidate:ledger-runtime-001',
    target: {
      kind: 'local_service',
      target_id: 'target:ledger-testbed',
      locator: 'https://127.0.0.1:9443',
      identity_sha256: SHA_C,
    },
    strategy_id: 'custom.runtime/ledger-v1',
    risk_class: 'READ_ONLY',
    autonomy_profile: 'L1_ASSISTED',
    attack: {
      id: 'attack:ledger',
      description: 'Exercise a synthetic local invariant failure.',
      expected_observation: 'The synthetic forbidden marker is returned.',
    },
    control: {
      id: 'control:ledger',
      description: 'Exercise the synthetic local control.',
      expected_observation: 'The authorized marker is returned.',
    },
    oracle: {
      id: 'oracle:ledger',
      confirmation_condition: 'Attack and control observations remain attributable.',
      inconclusive_condition: 'Control or attribution fails.',
    },
    limits: limits(),
    actions: [
      {
        action_id: 'action:ledger-control',
        purpose: 'control',
        action_category: 'http.control',
        operation: 'http.request',
        parameters: { method: 'GET', url: 'https://127.0.0.1:9443/owned' },
      },
      {
        action_id: 'action:ledger-attack',
        purpose: 'attack',
        action_category: 'http.authorization',
        operation: 'http.request',
        parameters: { method: 'GET', url: 'https://127.0.0.1:9443/foreign' },
      },
    ],
  }
}

function binding(plan) {
  return {
    plan_sha256: digestAdversarialPlan(plan),
    authorization_id: null,
    authorization_sha256: null,
    scope_revision_sha256: plan.scope_revision_sha256,
  }
}

async function ledgerDirectory(t) {
  const directory = await mkdtemp(join(tmpdir(), 'adversarial-ledger-'))
  t.after(async () => {
    const { rm } = await import('node:fs/promises')
    await rm(directory, { recursive: true, force: true })
  })
  return join(directory, 'records')
}

function replaceFirstReplacementCharacterWithMalformedUtf8(bytes) {
  const replacement = Buffer.from('\uFFFD', 'utf8')
  const index = bytes.indexOf(replacement)
  assert.notEqual(index, -1, 'fixture must contain a replacement character')
  return Buffer.concat([
    bytes.subarray(0, index),
    Buffer.from([0xff]),
    bytes.subarray(index + replacement.length),
  ])
}

function qualificationRequirements(ledgerBinding) {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-ledger-qualification-requirements',
    contract_version: '1.1.0',
    binding_sha256: digestJson(ledgerBinding),
    required_event_types: [...QUALIFICATION_EVENTS],
  }
}

function operatorAuthorizationReceipt(plan, overrides = {}) {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-authorization-receipt',
    status: 'CONTROLLER_VERIFIED',
    authorization_id: 'authorization:ledger-001',
    authorization_reference: 'authorization:ledger-001',
    authorization_sha256: 'd'.repeat(64),
    authority_basis: 'OPERATOR_DECLARATION_ACCEPTED_AS_FACT',
    operator_id: 'operator:ledger-owner',
    plan_sha256: digestAdversarialPlan(plan),
    engagement_id: plan.engagement_id,
    scope_revision_sha256: plan.scope_revision_sha256,
    target_sha256: digestJson(plan.target),
    risk_class: plan.risk_class,
    autonomy_profile: plan.autonomy_profile,
    declared_at: '2026-09-03T10:05:00.000Z',
    expires_at: '2026-09-03T10:11:00.000Z',
    ...overrides,
  }
}

test('campaign ledger binds and projects controller authorization fields without approval aliases', async (t) => {
  const plan = localPlan()
  const authorizationReceipt = operatorAuthorizationReceipt(plan)
  const ledgerBinding = {
    plan_sha256: authorizationReceipt.plan_sha256,
    authorization_id: authorizationReceipt.authorization_id,
    authorization_sha256: authorizationReceipt.authorization_sha256,
    scope_revision_sha256: authorizationReceipt.scope_revision_sha256,
  }
  const directory = await ledgerDirectory(t)
  const ledger = await openAdversarialCampaignLedger({ directory, binding: ledgerBinding })
  await ledger.start({
    authorizationReceipt,
    preflight: { allowed: true, reasons: [], mode: 'NOT_REQUIRED', waived_controls: [] },
    breakGlassOverrideSha256: null,
    startedAt: '2026-09-03T10:05:00.000Z',
  })

  const snapshot = ledger.snapshot()
  assert.deepEqual(snapshot.authorization_receipt, authorizationReceipt)
  assert.equal(Object.hasOwn(snapshot, 'approval_receipt'), false)
  const record = JSON.parse(await readFile(join(directory, '000000000001.json'), 'utf8'))
  assert.deepEqual(record.binding, ledgerBinding)
  assert.equal(Object.hasOwn(record.event, 'approval_receipt'), false)

  const legacyDirectory = await ledgerDirectory(t)
  await assert.rejects(
    () => openAdversarialCampaignLedger({
      directory: legacyDirectory,
      binding: {
        plan_sha256: authorizationReceipt.plan_sha256,
        approval_id: authorizationReceipt.authorization_id,
        approval_sha256: authorizationReceipt.authorization_sha256,
        scope_revision_sha256: authorizationReceipt.scope_revision_sha256,
      },
    }),
    (error) => error.code === 'ADVERSARIAL_LEDGER_BINDING_INVALID',
  )
})

test('campaign ledger rejects incomplete or internally inconsistent normalized authorization receipts', async (t) => {
  const plan = localPlan()
  const validReceipt = operatorAuthorizationReceipt(plan)
  const ledgerBinding = {
    plan_sha256: validReceipt.plan_sha256,
    authorization_id: validReceipt.authorization_id,
    authorization_sha256: validReceipt.authorization_sha256,
    scope_revision_sha256: validReceipt.scope_revision_sha256,
  }
  const withoutTargetDigest = structuredClone(validReceipt)
  delete withoutTargetDigest.target_sha256
  const cases = [
    withoutTargetDigest,
    { ...validReceipt, legacy_approval_id: 'approval:retired' },
    { ...validReceipt, authorization_reference: 'authorization:different' },
    { ...validReceipt, expires_at: validReceipt.declared_at },
    { ...validReceipt, risk_class: 'UNKNOWN' },
  ]

  for (const authorizationReceipt of cases) {
    const directory = await ledgerDirectory(t)
    const ledger = await openAdversarialCampaignLedger({ directory, binding: ledgerBinding })
    await assert.rejects(
      () => ledger.start({
        authorizationReceipt,
        preflight: { allowed: true, reasons: [], mode: 'NOT_REQUIRED', waived_controls: [] },
        breakGlassOverrideSha256: null,
        startedAt: '2026-09-03T10:05:00.000Z',
      }),
      (error) => error.code === 'ADVERSARIAL_LEDGER_EVENT_INVALID',
    )
  }
})

test('qualified file ledger persists every L3 action decision through cleanup and terminal outcome', async (t) => {
  const plan = localPlan()
  const ledgerBinding = binding(plan)
  const directory = await ledgerDirectory(t)
  const ledger = await openAdversarialCampaignLedger({ directory, binding: ledgerBinding })
  const requirements = qualificationRequirements(ledgerBinding)
  const qualificationReceipt = ledger.assertQualificationContract(requirements)
  assert.equal(qualificationReceipt.status, 'QUALIFIED')
  assert.equal(qualificationReceipt.requirements_sha256, digestJson(requirements))

  const actionId = 'action:qualified-cleanup'
  const branchId = 'branch:qualified-cleanup'
  const proposalSha256 = '1'.repeat(64)
  const actionSha256 = '2'.repeat(64)
  const classificationSha256 = '3'.repeat(64)
  const candidateFactsSha256 = '4'.repeat(64)
  const resolvedTargetSha256 = '5'.repeat(64)
  const effectClassificationSha256 = '6'.repeat(64)
  const scopeRevisionSha256 = plan.scope_revision_sha256
  const scopeReceipt = (stage) => ({
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-scope-qualification-receipt',
    stage,
    status: 'ALLOW',
    action_sha256: actionSha256,
    classification_sha256: classificationSha256,
    candidate_facts_sha256: candidateFactsSha256,
    resolved_target_sha256: resolvedTargetSha256,
    effect_classification_sha256: effectClassificationSha256,
    scope_revision_sha256: scopeRevisionSha256,
    decision_sha256: '7'.repeat(64),
    authorization_sha256: '8'.repeat(64),
    reason_codes: [],
  })
  const preflightReceipt = (stage) => ({
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-action-preflight-receipt',
    stage,
    status: 'PASS',
    action_sha256: actionSha256,
    runtime_preflight_sha256: '9'.repeat(64),
    authorization_state_sha256: 'a'.repeat(64),
    reason_codes: [],
  })

  await ledger.start({
    authorizationReceipt: null,
    preflight: { allowed: true, reasons: [], mode: 'NORMAL', waived_controls: [] },
    qualificationReceipt,
    breakGlassOverrideSha256: null,
    startedAt: '2026-09-03T10:05:00.000Z',
  })
  await ledger.recordActionProposed({
    actionId, proposalSha256, source: 'ADAPTIVE', purpose: 'cleanup',
    branchId, nextExactIndex: 0, elapsedMs: 1,
  })
  await ledger.recordActionClassified({
    actionId,
    proposalSha256,
    actionSha256,
    receipt: {
      schema_version: '1.0.0',
      kind: 'red-team-audit/adversarial-action-classification-receipt',
      status: 'CLASSIFIED',
      action_id: actionId,
      proposal_sha256: proposalSha256,
      action_sha256: actionSha256,
      classification_sha256: classificationSha256,
      candidate_facts_sha256: candidateFactsSha256,
      resolved_target_sha256: resolvedTargetSha256,
      effect_classification_sha256: effectClassificationSha256,
      risk_class: 'READ_ONLY',
      strategy_family: 'cleanup-validation',
      reason_code: null,
    },
    elapsedMs: 2,
  })
  await ledger.recordActionConsidered({
    actionId, actionSha256, branchId, exactIndex: 0, consideredActions: 1, elapsedMs: 3,
  })
  await assert.rejects(
    () => ledger.recordPreDispatch({
      actionId, actionSha256, branchId, dispatchedActions: 1, elapsedMs: 4,
    }),
    (error) => error.code === 'ADVERSARIAL_LEDGER_EVENT_INVALID'
      && /scope, preflight, or boundary qualification/i.test(error.message),
  )
  await ledger.recordScopeDecision({
    actionId, actionSha256, branchId, stage: 'INITIAL', receipt: scopeReceipt('INITIAL'), elapsedMs: 4,
  })
  await ledger.recordActionPreflight({
    actionId, actionSha256, branchId, stage: 'PRE_BOUNDARY',
    receipt: preflightReceipt('PRE_BOUNDARY'), elapsedMs: 5,
  })
  const boundaryReceipt = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-campaign-boundary-receipt',
    status: 'ALLOW',
    action_sha256: actionSha256,
    boundary_sha256: 'b'.repeat(64),
    reason_codes: [],
  }
  await ledger.recordBoundaryDecision({
    actionId,
    actionSha256,
    branchId,
    receipt: boundaryReceipt,
    elapsedMs: 6,
  })
  await ledger.recordPreDispatch({
    actionId, actionSha256, branchId, dispatchedActions: 1, elapsedMs: 7,
  })
  await ledger.recordScopeDecision({
    actionId, actionSha256, branchId, stage: 'PRE_SEND_RECHECK',
    receipt: scopeReceipt('PRE_SEND_RECHECK'), elapsedMs: 8,
  })
  await ledger.recordActionPreflight({
    actionId, actionSha256, branchId, stage: 'PRE_SEND_RECHECK',
    receipt: preflightReceipt('PRE_SEND_RECHECK'), elapsedMs: 9,
  })
  const permit = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-action-send-permit',
    action_sha256: actionSha256,
    classification_sha256: classificationSha256,
    initial_scope_receipt_sha256: digestJson(scopeReceipt('INITIAL')),
    pre_boundary_receipt_sha256: digestJson(preflightReceipt('PRE_BOUNDARY')),
    boundary_receipt_sha256: digestJson(boundaryReceipt),
    scope_recheck_receipt_sha256: digestJson(scopeReceipt('PRE_SEND_RECHECK')),
    pre_send_receipt_sha256: digestJson(preflightReceipt('PRE_SEND_RECHECK')),
    resolved_target_sha256: resolvedTargetSha256,
    effect_classification_sha256: effectClassificationSha256,
    max_output_bytes: 1024,
    max_action_time_ms: 1000,
  }
  await ledger.recordSendPermit({ actionId, actionSha256, branchId, permit, elapsedMs: 10 })
  const observation = { status: 'OBSERVED', output_bytes: 10, escalation_triggers: [] }
  await ledger.recordDispatchSettlement({
    actionId,
    actionSha256,
    branchId,
    receipt: {
      action_sha256: actionSha256,
      send_permit_sha256: digestJson(permit),
      outcome: 'RETURNED',
      request_may_have_been_sent: true,
      observation_sha256: digestJson(observation),
      reason_codes: [],
    },
    elapsedMs: 11,
  })
  await ledger.recordObservation({
    actionId,
    actionSha256,
    branchId,
    observation,
    accountedOutputBytes: 10,
    aggregateOutputBytes: 10,
    pauseBranch: false,
    elapsedMs: 12,
  })
  await ledger.recordCleanupOutcome({
    actionId,
    actionSha256,
    receipt: {
      action_sha256: actionSha256,
      observation_sha256: digestJson(observation),
      status: 'INCONCLUSIVE',
    },
    elapsedMs: 13,
  })
  await ledger.recordTerminal({
    result: {
      schema_version: '1.0.0',
      kind: 'red-team-audit/adversarial-campaign-terminal-summary',
      status: 'COMPLETED',
      plan_sha256: ledgerBinding.plan_sha256,
      considered_actions: 1,
      dispatched_actions: 1,
      aggregate_output_bytes: 10,
      paused_branch_count: 0,
      scope_request_count: 0,
      observation_count: 1,
    },
    elapsedMs: 14,
  })

  const reopened = await openAdversarialCampaignLedger({ directory, binding: ledgerBinding })
  const snapshot = reopened.snapshot()
  assert.equal(snapshot.terminal, true)
  assert.equal(snapshot.qualification_receipt.status, 'QUALIFIED')
  assert.deepEqual(snapshot.qualification_records.map(({ type }) => type), [
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
    'ACTION_CLEANUP_OUTCOME',
    'CAMPAIGN_TERMINAL',
  ])
  assert.equal(snapshot.cleanup_outcomes[0].status, 'INCONCLUSIVE')
  assert.equal(snapshot.pending_cleanup_outcome, null)
})

test('a durable campaign stop is recovered to terminal state without resume or dispatch', async (t) => {
  const plan = localPlan()
  const ledgerBinding = binding(plan)
  const directory = await ledgerDirectory(t)
  const ledger = await openAdversarialCampaignLedger({ directory, binding: ledgerBinding })
  const qualificationReceipt = ledger.assertQualificationContract(
    qualificationRequirements(ledgerBinding),
  )
  const stopReasons = ['CAMPAIGN_ABORTED_AFTER_SEND_PERMIT']
  await ledger.start({
    authorizationReceipt: null,
    preflight: { allowed: true, reasons: [], mode: 'NORMAL', waived_controls: [] },
    qualificationReceipt,
    breakGlassOverrideSha256: null,
    startedAt: '2026-09-03T10:05:00.000Z',
  })
  await ledger.recordCampaignStop({
    receipt: {
      schema_version: '1.0.0',
      kind: 'red-team-audit/adversarial-campaign-stop-receipt',
      status: 'ABORTED',
      reason_codes: stopReasons,
      stop_reasons: stopReasons,
      stop_reasons_sha256: digestJson(stopReasons),
    },
    elapsedMs: 1,
  })

  const reopened = await openAdversarialCampaignLedger({ directory, binding: ledgerBinding })
  let dispatches = 0
  const result = await executeAdversarialCampaign({
    plan,
    campaignLedger: reopened,
    dispatch: async () => {
      dispatches += 1
      return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
    },
  })

  assert.equal(dispatches, 0)
  assert.equal(result.status, 'ABORTED')
  assert.deepEqual(result.stop_reasons, stopReasons)
  assert.equal(result.campaign_ledger.terminal, true)
  assert.equal(reopened.snapshot().pending_stop, null)
  const records = await readdir(directory)
  assert.equal(records.length, 3)
})

test('file campaign ledger persists a canonical bound hash chain and terminal package', async (t) => {
  const plan = localPlan()
  const directory = await ledgerDirectory(t)
  const ledger = await openAdversarialCampaignLedger({ directory, binding: binding(plan) })
  await ledger.start({
    authorizationReceipt: null,
    preflight: { allowed: true, reasons: [], mode: 'NOT_REQUIRED', waived_controls: [] },
    breakGlassOverrideSha256: null,
    startedAt: '2026-09-03T10:05:00.000Z',
  })
  await ledger.recordActionConsidered({
    actionId: plan.actions[0].action_id,
    actionSha256: '1'.repeat(64),
    branchId: 'branch:exact-plan',
    exactIndex: 1,
    consideredActions: 1,
    elapsedMs: 1,
  })
  await ledger.recordPreDispatch({
    actionId: plan.actions[0].action_id,
    actionSha256: '1'.repeat(64),
    branchId: 'branch:exact-plan',
    dispatchedActions: 1,
    elapsedMs: 2,
  })
  const observation = { status: 'OBSERVED', output_bytes: 8, escalation_triggers: [] }
  await ledger.recordObservation({
    actionId: plan.actions[0].action_id,
    actionSha256: '1'.repeat(64),
    branchId: 'branch:exact-plan',
    observation,
    accountedOutputBytes: 64,
    aggregateOutputBytes: 64,
    pauseBranch: false,
    elapsedMs: 3,
  })
  const result = {
    status: 'COMPLETED',
    plan_sha256: binding(plan).plan_sha256,
    authorization_receipt: null,
    preflight_mode: 'NOT_REQUIRED',
    waived_preflight_controls: [],
    considered_actions: 1,
    dispatched_actions: 1,
    aggregate_output_bytes: 64,
    paused_branch_count: 0,
    scope_request_count: 0,
    observation_count: 1,
    paused_branches: [],
    scope_requests: [],
    observations: [observation],
  }
  await ledger.recordTerminal({ result, elapsedMs: 4 })

  const recordNames = (await readdir(directory)).sort()
  assert.equal(recordNames.length, 5)
  const records = await Promise.all(recordNames.map(async (name) =>
    JSON.parse(await readFile(join(directory, name), 'utf8'))))
  assert.ok(records.every((record) => assert.deepEqual(record.binding, binding(plan)) === undefined))
  assert.equal(records[0].previous_sha256, '0'.repeat(64))
  assert.equal(records.at(-1).event.result_sha256.length, 64)

  const reopened = await openAdversarialCampaignLedger({ directory, binding: binding(plan) })
  const snapshot = reopened.snapshot()
  assert.equal(snapshot.terminal, true)
  assert.deepEqual(snapshot.terminal_result, result)
  assert.equal(snapshot.observation_records[0].action_id, plan.actions[0].action_id)
  assert.equal(snapshot.observation_records[0].action_sha256, '1'.repeat(64))
  assert.equal(snapshot.observation_records[0].observation_sha256.length, 64)
  assert.deepEqual(snapshot.observation_records[0].observation, observation)
  await assert.rejects(
    () => reopened.recordActionConsidered({
      actionId: 'action:after-terminal',
      actionSha256: '2'.repeat(64),
      branchId: 'branch:exact-plan',
      exactIndex: 2,
      consideredActions: 2,
      elapsedMs: 5,
    }),
    /terminal/i,
  )
})

test('ledger reopen rejects malformed UTF-8 that aliases canonical record text', async (t) => {
  const plan = localPlan()
  const directory = await ledgerDirectory(t)
  const ledger = await openAdversarialCampaignLedger({ directory, binding: binding(plan) })
  await ledger.start({
    authorizationReceipt: null,
    preflight: {
      allowed: false,
      reasons: ['synthetic replacement \uFFFD reason'],
      mode: 'NOT_REQUIRED',
      waived_controls: [],
    },
    breakGlassOverrideSha256: null,
    startedAt: '2026-09-03T10:05:00.000Z',
  })
  const recordPath = join(directory, '000000000001.json')
  const canonicalBytes = await readFile(recordPath)
  await writeFile(recordPath, replaceFirstReplacementCharacterWithMalformedUtf8(canonicalBytes))

  await assert.rejects(
    () => openAdversarialCampaignLedger({ directory, binding: binding(plan) }),
    (error) => error.code === 'ADVERSARIAL_LEDGER_RECORD_INVALID',
  )
})

test('reopening an ambiguous pre-dispatch action settles it and terminally fails closed', async (t) => {
  const plan = localPlan()
  const directory = await ledgerDirectory(t)
  const ledger = await openAdversarialCampaignLedger({ directory, binding: binding(plan) })
  await ledger.start({
    authorizationReceipt: null,
    preflight: { allowed: true, reasons: [], mode: 'NOT_REQUIRED', waived_controls: [] },
    breakGlassOverrideSha256: null,
    startedAt: '2026-09-03T10:05:00.000Z',
  })
  await ledger.recordActionConsidered({
    actionId: plan.actions[0].action_id,
    actionSha256: '1'.repeat(64),
    branchId: 'branch:exact-plan',
    exactIndex: 1,
    consideredActions: 1,
    elapsedMs: 1,
  })
  await ledger.recordPreDispatch({
    actionId: plan.actions[0].action_id,
    actionSha256: '1'.repeat(64),
    branchId: 'branch:exact-plan',
    dispatchedActions: 1,
    elapsedMs: 2,
  })

  const reopened = await openAdversarialCampaignLedger({ directory, binding: binding(plan) })
  let dispatches = 0
  const result = await executeAdversarialCampaign({
    plan,
    campaignLedger: reopened,
    now: new Date('2026-09-03T10:05:05.000Z'),
    clock: () => Date.parse('2026-09-03T10:05:05.000Z'),
    dispatch: async () => {
      dispatches += 1
      return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
    },
  })
  assert.equal(dispatches, 0)
  assert.equal(result.status, 'PAUSED_SAFETY')
  assert.deepEqual(result.stop_reasons, ['AMBIGUOUS_IN_FLIGHT_DISPATCH'])
  assert.equal(result.campaign_ledger.pending_dispatch, null)
  assert.equal(reopened.snapshot().terminal, true)
  assert.equal(
    reopened.snapshot().observations.at(-1).kind,
    'red-team-audit/adversarial-dispatch-recovery-observation',
  )
})

test('a timed-out dispatch is durably settled and terminal across reopen', async (t) => {
  const plan = localPlan()
  plan.limits.max_action_time_ms = 10
  const directory = await ledgerDirectory(t)
  const ledger = await openAdversarialCampaignLedger({ directory, binding: binding(plan) })
  let aborted = false
  const result = await executeAdversarialCampaign({
    plan,
    campaignLedger: ledger,
    now: new Date('2026-09-03T10:05:00.000Z'),
    clock: () => Date.now(),
    dispatch: async (_action, { signal }) => new Promise((_resolve, reject) => {
      signal.addEventListener('abort', () => {
        aborted = true
        reject(signal.reason)
      }, { once: true })
    }),
  })

  assert.equal(aborted, true)
  assert.equal(result.status, 'PAUSED_SAFETY')
  assert.deepEqual(result.stop_reasons, ['ACTION_DISPATCH_TIMEOUT_AMBIGUOUS'])
  assert.equal(result.campaign_ledger.terminal, true)
  assert.equal(result.campaign_ledger.pending_dispatch, null)

  const reopened = await openAdversarialCampaignLedger({ directory, binding: binding(plan) })
  let redispatches = 0
  const recovered = await executeAdversarialCampaign({
    plan,
    campaignLedger: reopened,
    now: new Date('2026-09-03T10:05:01.000Z'),
    clock: () => Date.now(),
    dispatch: async () => {
      redispatches += 1
      return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
    },
  })
  assert.equal(redispatches, 0)
  assert.equal(recovered.status, 'PAUSED_SAFETY')
  assert.deepEqual(recovered.stop_reasons, ['ACTION_DISPATCH_TIMEOUT_AMBIGUOUS'])
  assert.equal(recovered.campaign_ledger.terminal, true)
  assert.equal(recovered.campaign_ledger.pending_dispatch, null)
})

test('reopening after consideration but before a send permit cannot skip the exact action', async (t) => {
  const plan = localPlan()
  const directory = await ledgerDirectory(t)
  const ledger = await openAdversarialCampaignLedger({ directory, binding: binding(plan) })
  await ledger.start({
    authorizationReceipt: null,
    preflight: { allowed: true, reasons: [], mode: 'NOT_REQUIRED', waived_controls: [] },
    breakGlassOverrideSha256: null,
    startedAt: '2026-09-03T10:05:00.000Z',
  })
  await ledger.recordActionConsidered({
    actionId: plan.actions[0].action_id,
    actionSha256: '1'.repeat(64),
    branchId: 'branch:exact-plan',
    exactIndex: 1,
    consideredActions: 1,
    elapsedMs: 1,
  })

  const reopened = await openAdversarialCampaignLedger({ directory, binding: binding(plan) })
  let dispatches = 0
  const result = await executeAdversarialCampaign({
    plan,
    campaignLedger: reopened,
    now: new Date('2026-09-03T10:05:01.000Z'),
    clock: () => Date.parse('2026-09-03T10:05:01.000Z'),
    dispatch: async () => {
      dispatches += 1
      return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
    },
  })
  assert.equal(dispatches, 0)
  assert.equal(result.status, 'PAUSED_SAFETY')
  assert.deepEqual(result.stop_reasons, ['AMBIGUOUS_POST_CONSIDERATION'])
})

test('reopening after an exact scope request cannot continue into the next action', async (t) => {
  const plan = localPlan()
  const directory = await ledgerDirectory(t)
  const ledger = await openAdversarialCampaignLedger({ directory, binding: binding(plan) })
  await ledger.start({
    authorizationReceipt: null,
    preflight: { allowed: true, reasons: [], mode: 'NOT_REQUIRED', waived_controls: [] },
    breakGlassOverrideSha256: null,
    startedAt: '2026-09-03T10:05:00.000Z',
  })
  await ledger.recordActionConsidered({
    actionId: plan.actions[0].action_id,
    actionSha256: '1'.repeat(64),
    branchId: 'branch:exact-plan',
    exactIndex: 1,
    consideredActions: 1,
    elapsedMs: 1,
  })
  const request = {
    kind: 'red-team-audit/adversarial-scope-expansion-candidate',
    disposition: 'QUEUE_SCOPE_EXPANSION_REQUEST',
    reason: 'outside current authority',
    action: {
      action_id: plan.actions[0].action_id,
      branch_id: 'branch:exact-plan',
      purpose: 'control',
      action_category: 'http.control',
      operation: 'http.request',
      strategy_family: null,
      parameters_sha256: '4'.repeat(64),
    },
  }
  await ledger.recordScopeRequest({
    actionId: plan.actions[0].action_id,
    actionSha256: '1'.repeat(64),
    branchId: 'branch:exact-plan',
    request,
    continueCampaign: false,
    elapsedMs: 2,
  })

  const reopened = await openAdversarialCampaignLedger({ directory, binding: binding(plan) })
  let dispatches = 0
  const result = await executeAdversarialCampaign({
    plan,
    campaignLedger: reopened,
    now: new Date('2026-09-03T10:05:01.000Z'),
    clock: () => Date.parse('2026-09-03T10:05:01.000Z'),
    dispatch: async () => {
      dispatches += 1
      return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
    },
  })
  assert.equal(dispatches, 0)
  assert.equal(result.status, 'PAUSED_SCOPE')
  assert.deepEqual(result.stop_reasons, ['PENDING_EXACT_SCOPE_REQUEST'])
})

test('resume count is append-only and survives reopening', async (t) => {
  const plan = localPlan()
  const directory = await ledgerDirectory(t)
  const ledger = await openAdversarialCampaignLedger({ directory, binding: binding(plan) })
  await ledger.start({
    authorizationReceipt: null,
    preflight: { allowed: true, reasons: [], mode: 'NOT_REQUIRED', waived_controls: [] },
    breakGlassOverrideSha256: null,
    startedAt: '2026-09-03T10:05:00.000Z',
  })
  await ledger.recordResume({ resumedAt: '2026-09-03T10:05:01.000Z' })
  const reopened = await openAdversarialCampaignLedger({ directory, binding: binding(plan) })
  assert.equal(reopened.snapshot().resume_count, 1)
  await reopened.recordResume({ resumedAt: '2026-09-03T10:05:02.000Z' })
  assert.equal(reopened.snapshot().resume_count, 2)
})

test('runtime fsyncs the send permit before dispatch and resumes only settled actions', async (t) => {
  const plan = localPlan()
  const directory = await ledgerDirectory(t)
  const ledger = await openAdversarialCampaignLedger({ directory, binding: binding(plan) })
  const observedDispatches = []
  let failAfterFirstObservation = true
  const throwingLedger = new Proxy(ledger, {
    get(target, property, receiver) {
      if (property !== 'recordObservation') return Reflect.get(target, property, receiver)
      return async (value) => {
        const result = await target.recordObservation(value)
        if (failAfterFirstObservation) {
          failAfterFirstObservation = false
          throw new Error('simulated process loss after durable observation')
        }
        return result
      }
    },
  })
  await assert.rejects(
    () => executeAdversarialCampaign({
      plan,
      campaignLedger: throwingLedger,
      now: new Date('2026-09-03T10:05:00.000Z'),
      clock: () => Date.parse('2026-09-03T10:05:00.000Z'),
      dispatch: async (action) => {
        const snapshot = ledger.snapshot()
        assert.equal(snapshot.pending_dispatch.action_id, action.action_id)
        observedDispatches.push(action.action_id)
        return { action_id: action.action_id, status: 'OBSERVED', output_bytes: 8, escalation_triggers: [] }
      },
    }),
    /simulated process loss/,
  )

  const reopened = await openAdversarialCampaignLedger({ directory, binding: binding(plan) })
  const result = await executeAdversarialCampaign({
    plan,
    campaignLedger: reopened,
    now: new Date('2026-09-03T10:05:01.000Z'),
    clock: () => Date.parse('2026-09-03T10:05:01.000Z'),
    dispatch: async (action) => {
      observedDispatches.push(action.action_id)
      return { action_id: action.action_id, status: 'OBSERVED', output_bytes: 8, escalation_triggers: [] }
    },
  })
  assert.deepEqual(observedDispatches, ['action:ledger-control', 'action:ledger-attack'])
  assert.equal(result.status, 'COMPLETED')
  assert.equal(result.considered_actions, 2)
  assert.equal(result.observations.length, 2)
  assert.equal(result.campaign_ledger.terminal, true)
  const durable = reopened.snapshot().terminal_result
  assert.equal(durable.kind, 'red-team-audit/adversarial-campaign-terminal-summary')
  assert.equal(Object.hasOwn(durable, 'observations'), false)

  const hydrated = await executeAdversarialCampaign({
    plan,
    campaignLedger: reopened,
    now: new Date('2026-09-03T10:05:02.000Z'),
    clock: () => Date.parse('2026-09-03T10:05:02.000Z'),
    dispatch: async () => { throw new Error('terminal campaigns cannot dispatch') },
  })
  assert.equal(hydrated.status, 'COMPLETED')
  assert.equal(hydrated.observations.length, 2)
  assert.equal(hydrated.agent_observation_receipts.length, 2)
})

test('queued scope requests and pending checkpoints survive reopening', async (t) => {
  const plan = localPlan()
  const directory = await ledgerDirectory(t)
  const ledger = await openAdversarialCampaignLedger({ directory, binding: binding(plan) })
  await ledger.start({
    authorizationReceipt: null,
    preflight: { allowed: true, reasons: [], mode: 'NOT_REQUIRED', waived_controls: [] },
    breakGlassOverrideSha256: null,
    startedAt: '2026-09-03T10:05:00.000Z',
  })
  const request = {
    kind: 'red-team-audit/adversarial-scope-expansion-candidate',
    disposition: 'QUEUE_SCOPE_EXPANSION_REQUEST',
    reason: 'outside current authority',
    action: {
      action_id: 'action:scope',
      branch_id: 'branch:scope',
      purpose: 'attack',
      action_category: 'cloud.iam',
      operation: 'cloud.control-plane',
      strategy_family: 'cloud-privilege-testing',
      parameters_sha256: '4'.repeat(64),
    },
  }
  await ledger.recordActionConsidered({
    actionId: 'action:scope',
    actionSha256: '5'.repeat(64),
    branchId: 'branch:scope',
    exactIndex: 0,
    consideredActions: 1,
    elapsedMs: 1,
  })
  await ledger.recordScopeRequest({
    actionId: 'action:scope',
    actionSha256: '5'.repeat(64),
    branchId: 'branch:scope',
    request,
    continueCampaign: true,
    elapsedMs: 2,
  })
  const checkpoint = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-runtime-checkpoint',
    plan_sha256: binding(plan).plan_sha256,
    authorization_id: null,
    scope_revision_sha256: plan.scope_revision_sha256,
    actions_used: 1,
    dispatched_actions: 0,
    aggregate_output_bytes: 0,
    paused_branches: ['branch:scope'],
  }
  await ledger.recordCheckpointQueued({ checkpoint, elapsedMs: 3 })

  const reopened = await openAdversarialCampaignLedger({ directory, binding: binding(plan) })
  const snapshot = reopened.snapshot()
  assert.deepEqual(snapshot.scope_requests, [request])
  assert.deepEqual(snapshot.paused_branches, ['branch:scope'])
  assert.deepEqual(snapshot.pending_checkpoint, checkpoint)
})

test('authority loss after the fsynced send permit cancels it before dispatch', async (t) => {
  const plan = localPlan()
  const directory = await ledgerDirectory(t)
  const ledger = await openAdversarialCampaignLedger({ directory, binding: binding(plan) })
  const campaign = new AbortController()
  const abortingLedger = new Proxy(ledger, {
    get(target, property, receiver) {
      if (property !== 'recordPreDispatch') return Reflect.get(target, property, receiver)
      return async (value) => {
        const result = await target.recordPreDispatch(value)
        campaign.abort(new Error('operator stop after durable permit'))
        return result
      }
    },
  })
  let dispatches = 0
  const result = await executeAdversarialCampaign({
    plan,
    campaignLedger: abortingLedger,
    signal: campaign.signal,
    now: new Date('2026-09-03T10:05:00.000Z'),
    clock: () => Date.parse('2026-09-03T10:05:00.000Z'),
    dispatch: async () => {
      dispatches += 1
      return { status: 'OBSERVED', output_bytes: 1, escalation_triggers: [] }
    },
  })
  assert.equal(dispatches, 0)
  assert.equal(result.status, 'ABORTED')
  assert.deepEqual(result.stop_reasons, ['CAMPAIGN_ABORTED'])
  const snapshot = ledger.snapshot()
  assert.equal(snapshot.pending_dispatch, null)
  assert.equal(snapshot.dispatched_actions, 0)
  assert.equal(snapshot.terminal, true)
})

test('an append durability failure poisons that handle and requires a verified reopen', async (t) => {
  const plan = localPlan()
  const directory = await ledgerDirectory(t)
  const ledger = await openAdversarialCampaignLedger({
    directory,
    binding: binding(plan),
    fsyncFile: () => { throw new Error('simulated FlushFileBuffers failure') },
    fsyncDirectory: () => {},
  })
  const start = {
    authorizationReceipt: null,
    preflight: { allowed: true, reasons: [], mode: 'NOT_REQUIRED', waived_controls: [] },
    breakGlassOverrideSha256: null,
    startedAt: '2026-09-03T10:05:00.000Z',
  }
  await assert.rejects(() => ledger.start(start), /append failed closed/i)
  assert.throws(() => ledger.start(start), /must be reopened/i)

  const reopened = await openAdversarialCampaignLedger({ directory, binding: binding(plan) })
  assert.equal(reopened.snapshot().started, true)
  assert.equal(reopened.snapshot().record_count, 1)
})

test('an existing ledger cannot be reopened under a different plan or scope binding', async (t) => {
  const plan = localPlan()
  const directory = await ledgerDirectory(t)
  const ledger = await openAdversarialCampaignLedger({ directory, binding: binding(plan) })
  await ledger.start({
    authorizationReceipt: null,
    preflight: { allowed: true, reasons: [], mode: 'NOT_REQUIRED', waived_controls: [] },
    breakGlassOverrideSha256: null,
    startedAt: '2026-09-03T10:05:00.000Z',
  })
  await assert.rejects(
    () => openAdversarialCampaignLedger({
      directory,
      binding: { ...binding(plan), scope_revision_sha256: 'd'.repeat(64) },
    }),
    /binding|chain/i,
  )
})
