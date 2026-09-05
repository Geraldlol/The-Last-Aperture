import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  digestAdversarialPlan,
} from '../scripts/lib/adversarial-validation-contracts.mjs'
import {
  digestAdversarialOracleContract,
  normalizeAdversarialEvidence,
  renderAdversarialEvidenceMarkdown,
  validateAdversarialEvidence,
} from '../scripts/lib/adversarial-evidence.mjs'
import { digestOperatorAuthorizationValue } from '../scripts/lib/operator-authorization.mjs'

const SHA_B = 'b'.repeat(64)
const SHA_C = 'c'.repeat(64)
const SECRET = 'Bearer live-production-secret-token'
const RESPONSE_BODY = '{"patient":"Ada","diagnosis":"private"}'

function plan(targetKind = 'live') {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-plan',
    plan_id: 'plan:active-evidence-001',
    engagement_id: 'engagement:active-evidence-001',
    scope_revision_sha256: SHA_B,
    candidate_id: 'candidate:active-evidence-001',
    target: {
      kind: targetKind,
      target_id: 'target:authorized-api',
      locator: targetKind === 'repository'
        ? 'repository://disposable-mirror'
        : 'https://api.example.test/orders',
      identity_sha256: SHA_C,
    },
    strategy_id: 'custom.authorization/paired-oracle-v1',
    risk_class: 'SENSITIVE_DATA',
    autonomy_profile: 'L1_ASSISTED',
    attack: {
      id: 'attack:cross-tenant-read',
      description: 'Request a foreign tenant object.',
      expected_observation: 'The foreign marker is observed.',
    },
    control: {
      id: 'control:owner-read',
      description: 'Request an owned tenant object.',
      expected_observation: 'The owner marker is observed.',
    },
    oracle: {
      id: 'oracle:paired-tenant',
      confirmation_condition: 'The attack reproduces while the paired control remains valid.',
      inconclusive_condition: 'The control, target binding, or attribution is invalid.',
    },
    limits: {
      max_actions: 4,
      max_wall_time_ms: 60_000,
      max_action_time_ms: 5_000,
      max_input_bytes: 4_096,
      max_output_bytes: 16_384,
      max_aggregate_output_bytes: 65_536,
      max_concurrency: 1,
      min_action_interval_ms: 0,
    },
    actions: [
      {
        action_id: 'action:control-001',
        purpose: 'control',
        action_category: 'http.control',
        operation: 'http.request',
        parameters: {
          method: 'GET',
          url: 'https://api.example.test/orders/owned',
          headers: { authorization: SECRET },
        },
      },
      {
        action_id: 'action:attack-001',
        purpose: 'attack',
        action_category: 'http.authorization',
        operation: 'http.request',
        parameters: {
          method: 'GET',
          url: 'https://api.example.test/orders/foreign',
          headers: { authorization: SECRET },
        },
      },
    ],
  }
}

function authorizationReceipt(planValue) {
  return {
    status: 'CONTROLLER_VERIFIED',
    authorization_id: 'authorization:active-evidence-001',
    authorization_reference: 'authorization:active-evidence-001',
    authorization_sha256: 'a'.repeat(64),
    operator_id: 'operator:engagement-owner',
    plan_sha256: digestAdversarialPlan(planValue),
    engagement_id: planValue.engagement_id,
    scope_revision_sha256: planValue.scope_revision_sha256,
    target_sha256: digestOperatorAuthorizationValue(planValue.target),
    authority_basis: 'OPERATOR_DECLARATION_ACCEPTED_AS_FACT',
    risk_class: planValue.risk_class,
    autonomy_profile: planValue.autonomy_profile,
  }
}

function observation(marker) {
  return {
    status: 'OBSERVED',
    output_bytes: Buffer.byteLength(RESPONSE_BODY),
    escalation_triggers: [],
    private_capture: {
      request_headers: {
        authorization: SECRET,
        cookie: 'sid=credential-cookie-value',
      },
      response_headers: { 'set-cookie': 'session=new-secret-value' },
      response_body: `${RESPONSE_BODY}:${marker}`,
    },
  }
}

function evaluation(planValue, action, result, observationIndex) {
  return {
    observation_index: observationIndex,
    action: structuredClone(action),
    oracle_id: planValue.oracle.id,
    target_identity_sha256: planValue.target.identity_sha256,
    oracle_contract_sha256: digestAdversarialOracleContract(planValue),
    result,
  }
}

function execution(planValue, executionId, {
  attackResult = 'ATTACK_REPRODUCED',
  controlResult = 'CONTROL_VALID',
  authorization = authorizationReceipt(planValue),
  status = 'COMPLETED',
} = {}) {
  return {
    execution_id: executionId,
    oracle_evaluations: [
      evaluation(planValue, planValue.actions[0], controlResult, 0),
      evaluation(planValue, planValue.actions[1], attackResult, 1),
    ],
    runtime_result: {
      status,
      plan_sha256: digestAdversarialPlan(planValue),
      authorization_receipt: authorization,
      considered_actions: 2,
      dispatched_actions: 2,
      aggregate_output_bytes: 1_024,
      paused_branches: [],
      scope_requests: [],
      observations: [
        observation(`${executionId}:control`),
        observation(`${executionId}:attack`),
      ],
    },
  }
}

function normalized(targetKind = 'live', overrides = {}) {
  const planValue = plan(targetKind)
  return normalizeAdversarialEvidence({
    plan: planValue,
    primary: execution(planValue, 'execution:primary-001'),
    replay: execution(planValue, 'execution:replay-001'),
    ...overrides,
  })
}

test('caller-asserted paired attack/control and replay create a bounded claimed-confirmed record', () => {
  const evidence = normalized()

  assert.equal(evidence.finding.verification_status, 'CLAIMED_CONFIRMED')
  assert.equal(evidence.finding.proof_tier, 'T4')
  assert.equal(evidence.authorization.mode, 'CLAIMED_OPERATOR_AUTHORIZATION')
  assert.equal(validateAdversarialEvidence(evidence).valid, true)
  assert.equal(Object.isFrozen(evidence), true)
  for (const name of [
    'attack_sha256',
    'control_sha256',
    'target_sha256',
    'authorization_sha256',
    'limits_sha256',
    'replay_sha256',
  ]) {
    assert.match(evidence.digests[name], /^[a-f0-9]{64}$/, name)
  }
  assert.equal(evidence.execution.primary.status, 'CLAIMED_COMPLETED')
  assert.equal(evidence.oracle.primary.attack.result, 'CLAIMED_ATTACK_REPRODUCED')
  assert.equal(evidence.oracle.primary.control.result, 'CLAIMED_CONTROL_VALID')
  assert.equal(evidence.oracle.replay.status, 'CLAIMED_REPRODUCED_WITH_VALID_CONTROL')
  for (const result of [
    evidence.execution.primary.status,
    evidence.execution.replay.status,
    evidence.oracle.primary.attack.result,
    evidence.oracle.primary.control.result,
    evidence.oracle.replay.status,
    evidence.oracle.replay.attack.result,
    evidence.oracle.replay.control.result,
  ]) {
    assert.match(result, /^CLAIMED_/, result)
  }
})

test('normalized evidence and its public Markdown omit credentials, locators, and response bodies', () => {
  const evidence = normalized()
  const serialized = JSON.stringify(evidence)
  const markdown = renderAdversarialEvidenceMarkdown(evidence, {
    sensitiveValues: [SECRET, RESPONSE_BODY, 'credential-cookie-value', 'new-secret-value', 'locator-secret'],
  })

  for (const forbidden of [
    SECRET,
    RESPONSE_BODY,
    'credential-cookie-value',
    'new-secret-value',
    'locator-secret',
    'response_body',
    'request_headers',
    'private_capture',
  ]) {
    assert.equal(serialized.includes(forbidden), false, `normalized evidence leaked ${forbidden}`)
    assert.equal(markdown.includes(forbidden), false, `Markdown leaked ${forbidden}`)
  }
  assert.match(markdown, /Attack digest: `[a-f0-9]{64}`/)
  assert.match(markdown, /Control digest: `[a-f0-9]{64}`/)
  assert.match(markdown, /Replay digest: `[a-f0-9]{64}`/)
})

test('an absent or invalid control can never confirm a vulnerability', () => {
  const planValue = plan()
  const missing = execution(planValue, 'execution:primary-001')
  missing.oracle_evaluations = missing.oracle_evaluations
    .filter(({ action }) => action.purpose === 'attack')
  const missingEvidence = normalizeAdversarialEvidence({
    plan: planValue,
    primary: missing,
    replay: execution(planValue, 'execution:replay-001'),
  })
  assert.equal(missingEvidence.finding.verification_status, 'INCONCLUSIVE')
  assert.match(missingEvidence.finding.reason, /control/i)

  const invalidEvidence = normalizeAdversarialEvidence({
    plan: planValue,
    primary: execution(planValue, 'execution:primary-001', {
      controlResult: 'CONTROL_INVALID',
    }),
    replay: execution(planValue, 'execution:replay-001'),
  })
  assert.equal(invalidEvidence.finding.verification_status, 'INCONCLUSIVE')
  assert.match(invalidEvidence.finding.reason, /control/i)
})

test('a reproduced primary observation without a fresh bound replay stays inconclusive', () => {
  const planValue = plan()
  const absent = normalizeAdversarialEvidence({
    plan: planValue,
    primary: execution(planValue, 'execution:primary-001'),
    replay: null,
  })
  assert.equal(absent.finding.verification_status, 'INCONCLUSIVE')
  assert.match(absent.finding.reason, /replay/i)
  assert.match(absent.digests.replay_sha256, /^[a-f0-9]{64}$/)

  const mismatched = execution(planValue, 'execution:replay-001')
  mismatched.oracle_evaluations[1].action.parameters.url += '?drifted=1'
  assert.throws(
    () => normalizeAdversarialEvidence({
      plan: planValue,
      primary: execution(planValue, 'execution:primary-001'),
      replay: mismatched,
    }),
    (error) => error.code === 'ADVERSARIAL_EVIDENCE_ACTION_BINDING_MISMATCH',
  )
})

test('a stable non-reproduction is not promoted to confirmation', () => {
  const planValue = plan()
  const evidence = normalizeAdversarialEvidence({
    plan: planValue,
    primary: execution(planValue, 'execution:primary-001', {
      attackResult: 'ATTACK_NOT_REPRODUCED',
    }),
    replay: execution(planValue, 'execution:replay-001', {
      attackResult: 'ATTACK_NOT_REPRODUCED',
    }),
  })
  assert.equal(evidence.finding.verification_status, 'CLAIMED_NOT_REPRODUCED')
  assert.match(evidence.finding.reason, /not reproduce/i)
})

test('a live evidence claim requires an exactly bound operator authorization receipt', () => {
  const planValue = plan()
  assert.throws(
    () => normalizeAdversarialEvidence({
      plan: planValue,
      primary: execution(planValue, 'execution:primary-001', { authorization: null }),
      replay: execution(planValue, 'execution:replay-001', { authorization: null }),
    }),
    (error) => error.code === 'ADVERSARIAL_EVIDENCE_AUTHORIZATION_REQUIRED',
  )

  const wrong = authorizationReceipt(planValue)
  wrong.scope_revision_sha256 = '9'.repeat(64)
  assert.throws(
    () => normalizeAdversarialEvidence({
      plan: planValue,
      primary: execution(planValue, 'execution:primary-001', { authorization: wrong }),
      replay: execution(planValue, 'execution:replay-001'),
    }),
    (error) => error.code === 'ADVERSARIAL_EVIDENCE_AUTHORIZATION_BINDING_MISMATCH',
  )
})

test('an adapter cannot substitute a different oracle contract', () => {
  const planValue = plan()
  const primary = execution(planValue, 'execution:primary-001')
  primary.oracle_evaluations[1].oracle_contract_sha256 = '9'.repeat(64)
  assert.throws(
    () => normalizeAdversarialEvidence({
      plan: planValue,
      primary,
      replay: execution(planValue, 'execution:replay-001'),
    }),
    (error) => error.code === 'ADVERSARIAL_EVIDENCE_ORACLE_BINDING_MISMATCH',
  )
})

test('a repository evidence claim records a deterministic not-required authorization digest', () => {
  const planValue = plan('repository')
  const evidence = normalizeAdversarialEvidence({
    plan: planValue,
    primary: execution(planValue, 'execution:primary-001', { authorization: null }),
    replay: execution(planValue, 'execution:replay-001', { authorization: null }),
  })
  assert.equal(evidence.authorization.mode, 'CLAIMED_AUTHORIZATION_NOT_REQUIRED')
  assert.equal(evidence.finding.proof_tier, 'T1')
  assert.match(evidence.digests.authorization_sha256, /^[a-f0-9]{64}$/)
})

test('plan/result drift and oversized private captures are rejected before public output exists', () => {
  const planValue = plan()
  const drifted = execution(planValue, 'execution:primary-001')
  drifted.runtime_result.plan_sha256 = '9'.repeat(64)
  assert.throws(
    () => normalizeAdversarialEvidence({
      plan: planValue,
      primary: drifted,
      replay: execution(planValue, 'execution:replay-001'),
    }),
    (error) => error.code === 'ADVERSARIAL_EVIDENCE_PLAN_BINDING_MISMATCH',
  )

  const oversized = execution(planValue, 'execution:primary-001')
  oversized.runtime_result.observations[0].private_capture.response_body = 'x'.repeat(
    planValue.limits.max_output_bytes + 1,
  )
  assert.throws(
    () => normalizeAdversarialEvidence({
      plan: planValue,
      primary: oversized,
      replay: execution(planValue, 'execution:replay-001'),
    }),
    (error) => error.code === 'ADVERSARIAL_EVIDENCE_OBSERVATION_TOO_LARGE',
  )
})

test('oracle observations cannot outnumber controller-recorded dispatches', () => {
  const planValue = plan()
  const fabricated = execution(planValue, 'execution:primary-001')
  fabricated.runtime_result.dispatched_actions = 0
  assert.throws(
    () => normalizeAdversarialEvidence({
      plan: planValue,
      primary: fabricated,
      replay: execution(planValue, 'execution:replay-001'),
    }),
    (error) => error.code === 'ADVERSARIAL_EVIDENCE_RUNTIME_ACCOUNTING_INVALID',
  )
})

test('target-controlled verdict text cannot replace a controller oracle evaluation', () => {
  const planValue = plan()
  const primary = execution(planValue, 'execution:primary-001')
  primary.oracle_evaluations = []
  primary.runtime_result.observations[0].oracle_result = 'CONTROL_VALID'
  primary.runtime_result.observations[1].oracle_result = 'ATTACK_REPRODUCED'
  const evidence = normalizeAdversarialEvidence({
    plan: planValue,
    primary,
    replay: execution(planValue, 'execution:replay-001'),
  })
  assert.equal(evidence.finding.verification_status, 'INCONCLUSIVE')
  assert.match(evidence.finding.reason, /control/i)
})

test('the public schema and renderer reject post-normalization raw-data injection', () => {
  const injected = structuredClone(normalized())
  injected.private_capture = { response_body: RESPONSE_BODY, authorization: SECRET }
  assert.equal(validateAdversarialEvidence(injected).valid, false)
  assert.throws(
    () => renderAdversarialEvidenceMarkdown(injected),
    (error) => error.code === 'ADVERSARIAL_EVIDENCE_INVALID',
  )
})
