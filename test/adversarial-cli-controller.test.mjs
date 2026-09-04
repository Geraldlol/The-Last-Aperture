import { createServer } from 'node:http'
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  digestAdversarialPlan,
  L3_MANDATORY_ESCALATION_TRIGGERS,
  L3_PREFLIGHT_FLAGS,
  L3_PROHIBITED_EFFECTS,
} from '../scripts/lib/adversarial-validation-contracts.mjs'
import {
  AdversarialCliControllerError,
  executeEnrolledAdversarialCampaign,
  inspectControllerEnrollment,
} from '../scripts/lib/adversarial-cli-controller.mjs'
import {
  digestAdversarialCurrentScope,
  sealAdversarialPlan,
} from '../scripts/lib/adversarial-cli-contracts.mjs'
import { stableJson } from '../scripts/lib/run-engine.mjs'

const SHA_A = 'a'.repeat(64)
const NOW = '2026-09-03T10:00:00.000Z'

function canonical(value) {
  return stableJson(value, 0).trimEnd()
}

function replaceFirstReplacementCharacterWithMalformedUtf8(text) {
  const bytes = Buffer.from(text, 'utf8')
  const replacement = Buffer.from('\uFFFD', 'utf8')
  const index = bytes.indexOf(replacement)
  assert.notEqual(index, -1, 'fixture must contain a replacement character')
  return Buffer.concat([
    bytes.subarray(0, index),
    Buffer.from([0xff]),
    bytes.subarray(index + replacement.length),
  ])
}

function scope(
  targetKind = 'repository',
  autonomyProfile = 'L2_SUPERVISED',
  targetLocator,
) {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-current-scope',
    scope_id: 'scope:cli-enrollment',
    engagement_id: 'engagement:cli-enrollment',
    targets: [{
      kind: targetKind,
      target_id: `target:${targetKind}`,
      locator: targetLocator ?? (targetKind === 'repository'
        ? 'repository://disposable-mirror'
        : targetKind === 'local_service'
          ? 'http://127.0.0.1:43123'
          : 'https://authorized.example.test'),
      identity_sha256: SHA_A,
    }],
    allowed_risk_classes: ['READ_ONLY'],
    allowed_autonomy_profiles: [autonomyProfile],
    allowed_strategy_ids: ['structured-fuzz/v1'],
    allowed_operations: ['fuzz.structured'],
    allowed_action_categories: ['fuzz.property'],
    allowed_strategy_families: ['structured-fuzz'],
    validity: {
      not_before: '2026-09-03T09:00:00.000Z',
      not_after: '2026-09-03T11:00:00.000Z',
    },
  }
}

function planDraft(currentScope) {
  const fuzzAction = {
    action_id: 'action:structured-fuzz',
    purpose: 'attack',
    action_category: 'fuzz.property',
    operation: 'fuzz.structured',
    parameters: {
      seed: 424242,
      num_runs: 100,
      timeout_ms: 1_000,
      max_counterexample_bytes: 4_096,
      arbitrary: { kind: 'integer', min: -100, max: 100 },
      property: { kind: 'integer-less-than', value: 10 },
    },
  }
  const actions = currentScope.targets[0].kind === 'live'
    ? [
        {
          ...structuredClone(fuzzAction),
          action_id: 'action:structured-fuzz-control',
          purpose: 'control',
        },
        fuzzAction,
      ]
    : [fuzzAction]
  const autonomyProfile = currentScope.allowed_autonomy_profiles[0]
  const draft = {
    plan_id: 'plan:cli-enrollment',
    engagement_id: currentScope.engagement_id,
    candidate_id: 'candidate:structured-fuzz',
    target: currentScope.targets[0],
    strategy_id: 'structured-fuzz/v1',
    risk_class: 'READ_ONLY',
    autonomy_profile: autonomyProfile,
    attack: {
      id: 'attack:integer-boundary',
      description: 'Search for a property counterexample.',
      expected_observation: 'A minimized counterexample is recorded.',
    },
    control: {
      id: 'control:integer-boundary',
      description: 'Exercise the same deterministic generator.',
      expected_observation: 'The harness returns a structured result.',
    },
    oracle: {
      id: 'oracle:boolean-property',
      confirmation_condition: 'The property returns false.',
      inconclusive_condition: 'The bounded harness cannot complete.',
    },
    limits: {
      max_actions: actions.length,
      max_wall_time_ms: 5_000,
      max_action_time_ms: 2_000,
      max_input_bytes: 16_384,
      max_output_bytes: 65_536,
      max_aggregate_output_bytes: 65_536,
      max_concurrency: 1,
      min_action_interval_ms: 0,
    },
    actions,
  }
  if (autonomyProfile === 'L3_MAXIMUM_AUTHORIZED') {
    const targetKindCondition = {
      field: '/target/kind',
      operator: 'equals',
      value: currentScope.targets[0].kind,
    }
    draft.preflight = Object.fromEntries(
      L3_PREFLIGHT_FLAGS.map((flag) => [flag, true]),
    )
    draft.campaign_envelope = {
      envelope_id: 'campaign:cli-l3-refusal',
      allowed_operations: ['fuzz.structured'],
      allowed_action_categories: ['fuzz.property'],
      allowed_strategy_families: ['structured-fuzz'],
      applicability_conditions: [targetKindCondition],
      decision_rules: [{
        rule_id: 'rule:exact-target-kind',
        when_all: [targetKindCondition],
        authorize: {
          operations: ['fuzz.structured'],
          action_categories: ['fuzz.property'],
          strategy_families: ['structured-fuzz'],
        },
      }],
      max_actions: actions.length,
      max_chain_depth: 1,
      checkpoint_policy: {
        interval_actions: 1,
        max_resume_count: 0,
        require_current_authorization: true,
        require_runtime_preflight: true,
      },
      mandatory_escalation_triggers: [...L3_MANDATORY_ESCALATION_TRIGGERS],
      prohibited_effects: [...L3_PROHIBITED_EFFECTS],
    }
  }
  return draft
}

function provisionEnrollment({
  targetKind = 'repository',
  targetLocator,
  autonomyProfile = 'L2_SUPERVISED',
} = {}) {
  const controllerRoot = mkdtempSync(join(tmpdir(), 'rta-adversarial-controller-'))
  const enrollmentId = 'enrollment-cli-test'
  const enrollmentDirectory = join(controllerRoot, 'enrollments', enrollmentId)
  mkdirSync(enrollmentDirectory, { recursive: true })

  const currentScope = scope(targetKind, autonomyProfile, targetLocator)
  const manifest = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-controller-enrollment',
    enrollment_id: enrollmentId,
    engagement_id: currentScope.engagement_id,
    status: 'ACTIVE',
    scope_sha256: digestAdversarialCurrentScope(currentScope),
    allowed_adapters: ['structured-fuzz/v1'],
  }
  for (const [name, value] of [
    ['manifest.json', manifest],
    ['scope.json', currentScope],
  ]) {
    writeFileSync(join(enrollmentDirectory, name), canonical(value), 'utf8')
  }
  const plan = sealAdversarialPlan({ draft: planDraft(currentScope), currentScope })
  return {
    controllerRoot,
    enrollmentDirectory,
    enrollmentId,
    plan,
  }
}

function operatorAuthorization(plan, overrides = {}) {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/operator-authorization',
    status: 'OPERATOR_ASSERTED_AUTHORIZED',
    operator_id: 'operator:security-lead',
    declared_at: NOW,
    authorization_reference: 'operator-directive:cli-controller-test',
    statement: 'I confirm I am authorized to execute this exact bounded campaign.',
    plan_sha256: digestAdversarialPlan(plan),
    scope_revision_sha256: plan.scope_revision_sha256,
    target: structuredClone(plan.target),
    ...overrides,
  }
}

test('controller enrollment owns only current scope and adapter policy', () => {
  const fixture = provisionEnrollment()
  const status = inspectControllerEnrollment({
    trustedControllerRoot: fixture.controllerRoot,
    enrollmentId: fixture.enrollmentId,
    now: NOW,
  })
  assert.equal(status.status, 'ACTIVE')
  assert.equal(status.scope_status, 'CURRENT')
  assert.deepEqual(status.allowed_adapters, ['structured-fuzz/v1'])
  assert.equal('authority_sha256' in status, false)
  assert.equal('revocation_status' in status, false)
  assert.deepEqual(
    readdirSync(fixture.enrollmentDirectory).sort(),
    ['manifest.json', 'scope.json'],
  )
})

test('operator-authorized repository execution uses the built-in structured fuzzer', async () => {
  const fixture = provisionEnrollment()
  const clock = () => Date.parse(NOW)
  const result = await executeEnrolledAdversarialCampaign({
    trustedControllerRoot: fixture.controllerRoot,
    enrollmentId: fixture.enrollmentId,
    plan: fixture.plan,
    operatorAuthorization: operatorAuthorization(fixture.plan),
    now: NOW,
    clock,
  })
  assert.equal(result.status, 'LIMIT_EXHAUSTED')
  assert.equal(result.authorization_mode, 'CONTROLLER_OPERATOR_ATTESTED')
  assert.equal(result.operator_authorization_receipt.status, 'OPERATOR_ASSERTED_AUTHORIZED')
  assert.equal('approval_receipt' in result, false)
  assert.equal(result.observations.length, 1)
  assert.equal(result.observations[0].kind, 'red-team-audit/structured-fuzz-observation')
  assert.equal(result.observations[0].result.status, 'COUNTEREXAMPLE_OBSERVED')
  assert.equal(readdirSync(fixture.enrollmentDirectory).includes('approval-nonces'), false)
})

test('dispatch fails closed if the enrolled adapter manifest changes after authorization', async () => {
  const fixture = provisionEnrollment()
  let changed = false
  const clock = () => {
    if (!changed) {
      changed = true
      const path = join(fixture.enrollmentDirectory, 'manifest.json')
      const manifest = JSON.parse(readFileSync(path, 'utf8'))
      manifest.allowed_adapters = ['disabled-adapter/v1']
      writeFileSync(path, canonical(manifest), 'utf8')
    }
    return Date.parse(NOW)
  }

  await assert.rejects(
    () => executeEnrolledAdversarialCampaign({
      trustedControllerRoot: fixture.controllerRoot,
      enrollmentId: fixture.enrollmentId,
      plan: fixture.plan,
      operatorAuthorization: operatorAuthorization(fixture.plan),
      now: NOW,
      clock,
    }),
    (error) => error instanceof AdversarialCliControllerError
      && error.code === 'ADVERSARIAL_ENROLLMENT_CHANGED',
  )
})

test('built-in registry refuses generic live target I/O under operator authorization', async () => {
  const fixture = provisionEnrollment({ targetKind: 'live' })
  await assert.rejects(
    () => executeEnrolledAdversarialCampaign({
      trustedControllerRoot: fixture.controllerRoot,
      enrollmentId: fixture.enrollmentId,
      plan: fixture.plan,
      operatorAuthorization: operatorAuthorization(fixture.plan),
      now: NOW,
      clock: () => Date.parse(NOW),
    }),
    (error) => error instanceof AdversarialCliControllerError
      && error.code === 'ADVERSARIAL_LIVE_ADAPTER_UNAVAILABLE',
  )
  assert.equal(
    readdirSync(fixture.enrollmentDirectory).includes('approval-nonces'),
    false,
  )
})

test('public repository and local-service L3 execution refuses before target I/O', async (t) => {
  let localServiceRequests = 0
  const server = createServer((_request, response) => {
    localServiceRequests += 1
    response.writeHead(204)
    response.end()
  })
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  t.after(() => new Promise((resolve) => server.close(resolve)))
  const address = server.address()
  assert.ok(address && typeof address === 'object')

  for (const [targetKind, targetLocator] of [
    ['repository', 'repository://must-not-be-opened'],
    ['local_service', `http://127.0.0.1:${address.port}/must-not-be-requested`],
  ]) {
    const fixture = provisionEnrollment({
      targetKind,
      targetLocator,
      autonomyProfile: 'L3_MAXIMUM_AUTHORIZED',
    })
    await assert.rejects(
      () => executeEnrolledAdversarialCampaign({
        trustedControllerRoot: fixture.controllerRoot,
        enrollmentId: fixture.enrollmentId,
        plan: fixture.plan,
        operatorAuthorization: operatorAuthorization(fixture.plan),
        now: NOW,
        clock: () => Date.parse(NOW),
      }),
      (error) => error instanceof AdversarialCliControllerError
        && error.code === 'ADVERSARIAL_L3_CLI_CONTROL_PLANE_UNAVAILABLE',
      targetKind,
    )
    assert.equal(
      readdirSync(fixture.enrollmentDirectory).includes('approval-nonces'),
      false,
      `${targetKind} refusal must precede nonce-store creation`,
    )
  }
  assert.equal(localServiceRequests, 0)
})

test('tampering with enrolled scope fails before dispatch', async () => {
  const fixture = provisionEnrollment()
  writeFileSync(join(fixture.enrollmentDirectory, 'scope.json'), '{}', 'utf8')
  await assert.rejects(
    () => executeEnrolledAdversarialCampaign({
      trustedControllerRoot: fixture.controllerRoot,
      enrollmentId: fixture.enrollmentId,
      plan: fixture.plan,
      operatorAuthorization: operatorAuthorization(fixture.plan),
      now: NOW,
      clock: () => Date.parse(NOW),
    }),
    /enrollment|scope|digest|invalid/i,
  )
})

test('retired signed approval input is rejected before enrollment reads', async () => {
  const fixture = provisionEnrollment()
  await assert.rejects(
    () => executeEnrolledAdversarialCampaign({
      trustedControllerRoot: join(fixture.controllerRoot, 'must-not-be-read'),
      enrollmentId: fixture.enrollmentId,
      plan: fixture.plan,
      approval: { kind: 'legacy-signed-approval' },
      now: NOW,
      clock: () => Date.parse(NOW),
    }),
    (error) => error instanceof AdversarialCliControllerError
      && error.code === 'ADVERSARIAL_SIGNED_APPROVAL_RETIRED',
  )
})

test('controller requires an operator statement before enrollment reads', async () => {
  const fixture = provisionEnrollment()
  await assert.rejects(
    () => executeEnrolledAdversarialCampaign({
      trustedControllerRoot: join(fixture.controllerRoot, 'must-not-be-read'),
      enrollmentId: fixture.enrollmentId,
      plan: fixture.plan,
      now: NOW,
      clock: () => Date.parse(NOW),
    }),
    (error) => error instanceof AdversarialCliControllerError
      && error.code === 'ADVERSARIAL_AUTHORIZATION_REQUIRED',
  )
})

test('controller artifacts reject malformed UTF-8 that aliases canonical JSON text', () => {
  const fixture = provisionEnrollment()
  const manifestPath = join(fixture.enrollmentDirectory, 'manifest.json')
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
  manifest.allowed_adapters = ['structured-fuzz/\uFFFD']
  writeFileSync(
    manifestPath,
    replaceFirstReplacementCharacterWithMalformedUtf8(canonical(manifest)),
  )

  assert.throws(
    () => inspectControllerEnrollment({
      trustedControllerRoot: fixture.controllerRoot,
      enrollmentId: fixture.enrollmentId,
      now: NOW,
    }),
    (error) => error instanceof AdversarialCliControllerError
      && error.code === 'ADVERSARIAL_CONTROLLER_ARTIFACT_INVALID',
  )
})
