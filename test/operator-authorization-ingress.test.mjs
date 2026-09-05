import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  writeFileSync,
} from 'node:fs'
import {
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import { main as adversarialMain } from '../scripts/adversarial.mjs'
import { main as httpAuthedMain } from '../scripts/http-authed.mjs'
import { main as httpReconMain } from '../scripts/http-recon.mjs'
import {
  digestAdversarialCurrentScope,
  sealAdversarialPlan,
} from '../scripts/lib/adversarial-cli-contracts.mjs'
import {
  AdversarialCliControllerError,
  executeEnrolledAdversarialCampaign,
} from '../scripts/lib/adversarial-cli-controller.mjs'
import {
  canonicalAdversarialPlan,
  digestAdversarialPlan,
  L3_MANDATORY_ESCALATION_TRIGGERS,
  L3_PREFLIGHT_FLAGS,
  L3_PROHIBITED_EFFECTS,
} from '../scripts/lib/adversarial-validation-contracts.mjs'
import {
  finalizeHttpReconBundle,
  goOperatorAttestedHttpRecon,
  nextHttpReconAction,
  planOperatorAttestedHttpReconBundle,
  requestHttpReconStop,
  runHttpReconAction,
} from '../scripts/lib/http-recon-controller.mjs'
import { planHttpAuthedAttestedScope } from '../scripts/lib/http-authed-planner.mjs'
import { stableJson } from '../scripts/lib/run-engine.mjs'

const NOW = '2026-09-03T10:00:00.000Z'
const SHA_A = 'a'.repeat(64)

function canonical(value) {
  return stableJson(value, 0).trimEnd()
}

function digest(value) {
  return createHash('sha256').update(canonical(value)).digest('hex')
}

function currentScope({
  targetKind = 'repository',
  autonomyProfile = 'L2_SUPERVISED',
} = {}) {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-current-scope',
    scope_id: 'scope:operator-authorization-ingress',
    engagement_id: 'engagement:operator-authorization-ingress',
    targets: [{
      kind: targetKind,
      target_id: `target:${targetKind}:operator-authorization-ingress`,
      locator: targetKind === 'live'
        ? 'https://authorized.example.test/exact'
        : 'repository://disposable-mirror/operator-authorization-ingress',
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

function planDraft(scope) {
  const action = {
    action_id: 'action:operator-authorization-ingress',
    purpose: 'attack',
    action_category: 'fuzz.property',
    operation: 'fuzz.structured',
    parameters: {
      seed: 424242,
      num_runs: 10,
      timeout_ms: 1_000,
      max_counterexample_bytes: 4_096,
      arbitrary: { kind: 'integer', min: -10, max: 10 },
      property: { kind: 'integer-less-than', value: 5 },
    },
  }
  const actions = scope.targets[0].kind === 'live'
    ? [{ ...structuredClone(action), action_id: 'action:operator-authorization-control', purpose: 'control' }, action]
    : [action]
  const draft = {
    plan_id: 'plan:operator-authorization-ingress',
    engagement_id: scope.engagement_id,
    candidate_id: 'candidate:operator-authorization-ingress',
    target: scope.targets[0],
    strategy_id: 'structured-fuzz/v1',
    risk_class: 'READ_ONLY',
    autonomy_profile: scope.allowed_autonomy_profiles[0],
    attack: {
      id: 'attack:operator-authorization-ingress',
      description: 'Exercise one bounded controller-owned property.',
      expected_observation: 'A bounded structured observation is returned.',
    },
    control: {
      id: 'control:operator-authorization-ingress',
      description: 'Use the same deterministic controller-owned harness.',
      expected_observation: 'The bounded harness remains available.',
    },
    oracle: {
      id: 'oracle:operator-authorization-ingress',
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
  if (draft.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED') {
    const targetCondition = {
      field: '/target/kind',
      operator: 'equals',
      value: scope.targets[0].kind,
    }
    draft.preflight = Object.fromEntries(
      L3_PREFLIGHT_FLAGS.map((flag) => [flag, true]),
    )
    draft.campaign_envelope = {
      envelope_id: 'campaign:operator-authorization-ingress',
      allowed_operations: ['fuzz.structured'],
      allowed_action_categories: ['fuzz.property'],
      allowed_strategy_families: ['structured-fuzz'],
      applicability_conditions: [targetCondition],
      decision_rules: [{
        rule_id: 'rule:exact-target-kind',
        when_all: [targetCondition],
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

function provisionEnrollment(options = {}) {
  const controllerRoot = mkdtempSync(join(tmpdir(), 'rta-operator-authorization-controller-'))
  const enrollmentId = 'enrollment-operator-authorization-ingress'
  const enrollmentDirectory = join(controllerRoot, 'enrollments', enrollmentId)
  mkdirSync(enrollmentDirectory, { recursive: true })

  const scope = currentScope(options)
  const manifest = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-controller-enrollment',
    enrollment_id: enrollmentId,
    engagement_id: scope.engagement_id,
    status: 'ACTIVE',
    scope_sha256: digestAdversarialCurrentScope(scope),
    allowed_adapters: ['structured-fuzz/v1'],
  }
  for (const [name, value] of [
    ['manifest.json', manifest],
    ['scope.json', scope],
  ]) {
    writeFileSync(join(enrollmentDirectory, name), canonical(value), 'utf8')
  }

  const plan = sealAdversarialPlan({ draft: planDraft(scope), currentScope: scope })
  return {
    controllerRoot,
    enrollmentDirectory,
    enrollmentId,
    plan,
    scope,
  }
}

function operatorAuthorization(plan, overrides = {}) {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/operator-authorization',
    status: 'OPERATOR_ASSERTED_AUTHORIZED',
    operator_id: 'operator:local-security-owner',
    declared_at: NOW,
    authorization_reference: 'operator-directive:test-session-001',
    statement: 'I confirm I am authorized to execute this exact bounded campaign.',
    plan_sha256: digestAdversarialPlan(plan),
    scope_revision_sha256: plan.scope_revision_sha256,
    target: structuredClone(plan.target),
    ...overrides,
  }
}

function assertNoNonceStore(fixture) {
  assert.equal(
    readdirSync(fixture.enrollmentDirectory).includes('approval-nonces'),
    false,
    'operator-attested execution must never create a legacy approval nonce store',
  )
}

test('execute CLI creates one exact operator authorization at ingress', async () => {
  const fixture = provisionEnrollment()
  const root = mkdtempSync(join(tmpdir(), 'rta-operator-authorization-cli-'))
  const planPath = join(root, 'plan.json')
  writeFileSync(planPath, canonicalAdversarialPlan(fixture.plan), 'utf8')
  const sentinel = new Error('stop after operator authorization ingress')
  let received

  await assert.rejects(
    adversarialMain([
      'execute',
      planPath,
      '--enrollment',
      fixture.enrollmentId,
    ], {
      now: () => new Date(NOW),
      executeCampaign: async (input) => {
        received = input
        throw sentinel
      },
    }),
    (error) => error === sentinel,
  )

  assert.equal('approval' in received, false)
  assert.deepEqual(Object.keys(received.operatorAuthorization).sort(), [
    'authorization_reference',
    'declared_at',
    'kind',
    'operator_id',
    'plan_sha256',
    'schema_version',
    'scope_revision_sha256',
    'statement',
    'status',
    'target',
  ])
  assert.equal(received.operatorAuthorization.status, 'OPERATOR_ASSERTED_AUTHORIZED')
  assert.match(received.operatorAuthorization.operator_id, /^local:/)
  assert.equal(received.operatorAuthorization.declared_at, NOW)
  assert.equal(received.operatorAuthorization.plan_sha256, digestAdversarialPlan(fixture.plan))
  assert.equal(
    received.operatorAuthorization.scope_revision_sha256,
    fixture.plan.scope_revision_sha256,
  )
  assert.deepEqual(received.operatorAuthorization.target, fixture.plan.target)
  assert.match(received.operatorAuthorization.authorization_reference, /^operator-directive:/)
  assert.match(received.operatorAuthorization.statement, /authorized/i)
  assert.equal('authorization_document' in received.operatorAuthorization, false)
  assert.equal('legal_proof' in received.operatorAuthorization, false)
})

test('controller accepts an exact operator declaration as fact and returns its bounded receipt', async () => {
  const fixture = provisionEnrollment()
  const authorization = operatorAuthorization(fixture.plan)
  const result = await executeEnrolledAdversarialCampaign({
    trustedControllerRoot: fixture.controllerRoot,
    enrollmentId: fixture.enrollmentId,
    plan: fixture.plan,
    operatorAuthorization: authorization,
    now: NOW,
    clock: () => Date.parse(NOW),
  })

  assert.equal(result.authorization_mode, 'CONTROLLER_OPERATOR_ATTESTED')
  assert.deepEqual(result.operator_authorization_receipt, {
    ...authorization,
    authority_basis: 'OPERATOR_DECLARATION_ACCEPTED_AS_FACT',
    target_sha256: digest(fixture.plan.target),
    authorization_sha256: digest(authorization),
  })
  assert.equal('approval_receipt' in result, false)
  assertNoNonceStore(fixture)

  const rendered = canonical(result.operator_authorization_receipt)
  assert.ok(Buffer.byteLength(rendered, 'utf8') <= 8 * 1024)
  assert.doesNotMatch(rendered, /private[_-]?key|credential|cookie|bearer/i)
})

test('operator declaration enrollment requires only its manifest and exact scope', async () => {
  const fixture = provisionEnrollment()
  assert.deepEqual(
    readdirSync(fixture.enrollmentDirectory).sort(),
    ['manifest.json', 'scope.json'],
  )

  const result = await executeEnrolledAdversarialCampaign({
    trustedControllerRoot: fixture.controllerRoot,
    enrollmentId: fixture.enrollmentId,
    plan: fixture.plan,
    operatorAuthorization: operatorAuthorization(fixture.plan),
    now: NOW,
    clock: () => Date.parse(NOW),
  })

  assert.equal(result.authorization_mode, 'CONTROLLER_OPERATOR_ATTESTED')
  assert.equal(result.operator_authorization_receipt.status, 'OPERATOR_ASSERTED_AUTHORIZED')
  assertNoNonceStore(fixture)
})

test('operator authorization evidence must be affirmative, current, canonical, and bounded', async (t) => {
  const cases = [
    {
      name: 'contradictory-statement',
      code: 'ADVERSARIAL_OPERATOR_AUTHORIZATION_STATEMENT_INVALID',
      overrides: { statement: 'I am explicitly not authorized.' },
    },
    {
      name: 'stale-time',
      code: 'ADVERSARIAL_OPERATOR_AUTHORIZATION_TIME_STALE',
      overrides: { declared_at: '2026-09-03T09:54:59.999Z' },
    },
    {
      name: 'future-time',
      code: 'ADVERSARIAL_OPERATOR_AUTHORIZATION_TIME_FUTURE',
      overrides: { declared_at: '2026-09-03T10:00:00.001Z' },
    },
    {
      name: 'whitespace-reference',
      code: 'ADVERSARIAL_OPERATOR_AUTHORIZATION_SHAPE_INVALID',
      overrides: { authorization_reference: ' operator-directive:test-session-001 ' },
    },
    {
      name: 'oversized-reference',
      code: 'ADVERSARIAL_OPERATOR_AUTHORIZATION_SHAPE_INVALID',
      overrides: { authorization_reference: `operator-directive:${'x'.repeat(1100)}` },
    },
    {
      name: 'extra-field',
      code: 'ADVERSARIAL_OPERATOR_AUTHORIZATION_SHAPE_INVALID',
      overrides: { legal_proof: 'not accepted at this ingress' },
    },
  ]

  for (const scenario of cases) {
    await t.test(scenario.name, async () => {
      const fixture = provisionEnrollment()
      await assert.rejects(
        executeEnrolledAdversarialCampaign({
          trustedControllerRoot: fixture.controllerRoot,
          enrollmentId: fixture.enrollmentId,
          plan: fixture.plan,
          operatorAuthorization: operatorAuthorization(fixture.plan, scenario.overrides),
          now: NOW,
          clock: () => Date.parse(NOW),
        }),
        (error) => error instanceof AdversarialCliControllerError
          && error.code === scenario.code,
      )
      assertNoNonceStore(fixture)
    })
  }
})

test('controller snapshots the exact plan before authorization and dispatch', async () => {
  const fixture = provisionEnrollment()
  const callerPlan = structuredClone(fixture.plan)
  const originalPlanSha256 = digestAdversarialPlan(callerPlan)
  const authorization = operatorAuthorization(callerPlan)
  const execution = executeEnrolledAdversarialCampaign({
    trustedControllerRoot: fixture.controllerRoot,
    enrollmentId: fixture.enrollmentId,
    plan: callerPlan,
    operatorAuthorization: authorization,
    now: NOW,
    clock: () => Date.parse(NOW),
  })

  callerPlan.target.locator = 'repository://mutated-after-controller-ingress'
  callerPlan.actions[0].parameters.seed += 1
  const result = await execution

  assert.equal(result.plan_sha256, originalPlanSha256)
  assert.equal(result.operator_authorization_receipt.plan_sha256, originalPlanSha256)
  assert.deepEqual(result.operator_authorization_receipt.target, authorization.target)
})

test('controller rejects retired signed approval input before enrollment reads or dispatch', async () => {
  const fixture = provisionEnrollment()
  await assert.rejects(
    executeEnrolledAdversarialCampaign({
      trustedControllerRoot: join(tmpdir(), 'must-not-read-legacy-signed-enrollment'),
      enrollmentId: fixture.enrollmentId,
      plan: fixture.plan,
      approval: { kind: 'legacy-signed-approval' },
      now: NOW,
      clock: () => Date.parse(NOW),
    }),
    (error) => error instanceof AdversarialCliControllerError
      && error.code === 'ADVERSARIAL_SIGNED_APPROVAL_RETIRED',
  )
  assertNoNonceStore(fixture)
})

test('operator declaration plan, scope, and target drift fail before controller state or dispatch', async (t) => {
  const cases = [
    {
      name: 'plan',
      code: 'ADVERSARIAL_OPERATOR_AUTHORIZATION_PLAN_MISMATCH',
      mutate: (authorization) => { authorization.plan_sha256 = 'b'.repeat(64) },
    },
    {
      name: 'scope',
      code: 'ADVERSARIAL_OPERATOR_AUTHORIZATION_SCOPE_MISMATCH',
      mutate: (authorization) => { authorization.scope_revision_sha256 = 'c'.repeat(64) },
    },
    {
      name: 'target',
      code: 'ADVERSARIAL_OPERATOR_AUTHORIZATION_TARGET_MISMATCH',
      mutate: (authorization) => { authorization.target.locator = 'repository://different-target' },
    },
  ]

  for (const scenario of cases) {
    await t.test(scenario.name, async () => {
      const fixture = provisionEnrollment()
      const authorization = operatorAuthorization(fixture.plan)
      scenario.mutate(authorization)
      await assert.rejects(
        executeEnrolledAdversarialCampaign({
          trustedControllerRoot: fixture.controllerRoot,
          enrollmentId: fixture.enrollmentId,
          plan: fixture.plan,
          operatorAuthorization: authorization,
          now: NOW,
          clock: () => Date.parse(NOW),
        }),
        (error) => error instanceof AdversarialCliControllerError
          && error.code === scenario.code,
      )
      assertNoNonceStore(fixture)
    })
  }
})

test('verified operator declaration is accepted as authority before unavailable live or L3 routes fail closed', async (t) => {
  for (const options of [
    {
      targetKind: 'live',
      autonomyProfile: 'L2_SUPERVISED',
      code: 'ADVERSARIAL_LIVE_ADAPTER_UNAVAILABLE',
      technicalGap: /no trusted transport\/provider adapter is enrolled/i,
      noRepeat: /reauthorization cannot activate a missing route/i,
    },
    {
      targetKind: 'repository',
      autonomyProfile: 'L3_MAXIMUM_AUTHORIZED',
      code: 'ADVERSARIAL_L3_CLI_CONTROL_PLANE_UNAVAILABLE',
      technicalGap: /controller-owned live preflight.*trusted append-only campaign ledger.*durable checkpoint services/i,
      noRepeat: /reauthorization cannot activate missing controller services/i,
    },
  ]) {
    await t.test(`${options.targetKind}-${options.autonomyProfile}`, async () => {
      const fixture = provisionEnrollment(options)
      await assert.rejects(
        executeEnrolledAdversarialCampaign({
          trustedControllerRoot: fixture.controllerRoot,
          enrollmentId: fixture.enrollmentId,
          plan: fixture.plan,
          operatorAuthorization: operatorAuthorization(fixture.plan),
          now: NOW,
          clock: () => Date.parse(NOW),
        }),
        (error) => {
          assert.ok(error instanceof AdversarialCliControllerError)
          assert.equal(error.code, options.code)
          assert.match(error.message, /verified operator statement was accepted as the authority fact/i)
          assert.match(error.message, /technically unavailable/i)
          assert.match(error.message, options.technicalGap)
          assert.match(error.message, options.noRepeat)
          return true
        },
      )
      assertNoNonceStore(fixture)
    })
  }
})

function reconOperatorAuthorization(targetUrl, overrides = {}) {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/operator-authorization',
    status: 'OPERATOR_ASSERTED_AUTHORIZED',
    operator_id: 'operator:local-security-owner',
    declared_at: '2026-08-04T12:00:00.000Z',
    authorization_reference: 'operator-directive:recon-test-001',
    statement: 'I confirm I am authorized to test this exact HTTPS target.',
    target: { kind: 'https_url', url: targetUrl },
    ...overrides,
  }
}

test('HTTPS go CLI hands the controller one pre-plan authorization declaration', async () => {
  const targetUrl = 'https://target.example/exact?case=one'
  const sentinel = new Error('stop after HTTPS authorization ingress')
  let received
  await assert.rejects(
    adversarialMain(['go', targetUrl], {
      now: () => new Date('2026-08-04T12:00:00.000Z'),
      goTarget: async (input) => {
        received = input
        throw sentinel
      },
    }),
    (error) => error === sentinel,
  )

  assert.equal(received.targetUrl, targetUrl)
  assert.equal('attestationConfirmed' in received, false)
  assert.equal('executionApproved' in received, false)
  assert.deepEqual(Object.keys(received.operatorAuthorization).sort(), [
    'authorization_reference',
    'declared_at',
    'kind',
    'operator_id',
    'schema_version',
    'statement',
    'status',
    'target',
  ])
  assert.equal(received.operatorAuthorization.status, 'OPERATOR_ASSERTED_AUTHORIZED')
  assert.match(received.operatorAuthorization.operator_id, /^local:/)
  assert.equal(
    received.operatorAuthorization.declared_at,
    '2026-08-04T12:00:00.000Z',
  )
  assert.deepEqual(received.operatorAuthorization.target, {
    kind: 'https_url',
    url: targetUrl,
  })
  assert.equal('plan_sha256' in received.operatorAuthorization, false)
  assert.equal('scope_revision_sha256' in received.operatorAuthorization, false)
})

test('HTTPS go accepts one pre-plan declaration, persists its derived bindings, and honors stop', async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'rta-recon-operator-authorization-'))
  t.after(() => rm(parent, { recursive: true, force: true }))
  const out = join(parent, 'bundle')
  const targetUrl = 'https://target.example/exact'
  const now = () => new Date('2026-08-04T12:00:00.000Z')
  let probes = 0

  const result = await goOperatorAttestedHttpRecon({
    targetUrl,
    operatorAuthorization: reconOperatorAuthorization(targetUrl),
    out,
    now,
    randomBytesImpl: (size) => Buffer.alloc(size, 7),
    onPlanned: async ({ bundle }) => {
      await requestHttpReconStop({
        bundle,
        operatorId: 'operator:local-security-owner',
        reason: 'operator stop must remain authoritative',
        now,
      })
    },
    runImpl: (input) => runHttpReconAction({
      ...input,
      probeImpl: async () => {
        probes += 1
        throw new Error('stopped go must perform zero target I/O')
      },
      fetchProofImpl: async () => {
        throw new Error('operator-attested go must not fetch proof authority')
      },
    }),
    finalizeImpl: finalizeHttpReconBundle,
  })

  assert.equal(result.state, 'STOPPED')
  assert.equal(probes, 0)
  const run = JSON.parse(await readFile(join(out, 'run.json'), 'utf8'))
  const scope = JSON.parse(await readFile(join(out, 'attested-scope.json'), 'utf8'))
  const events = (await readFile(join(out, 'events.jsonl'), 'utf8'))
    .trimEnd()
    .split('\n')
    .map((line) => JSON.parse(line))
  assert.equal(run.actions.length, 1)
  assert.equal(run.actions[0].url, targetUrl)
  assert.equal(scope.authorization.operator_id, 'operator:local-security-owner')
  assert.equal(scope.authorization.independently_verified, false)
  const planCreated = events.find(({ type }) => type === 'PLAN_CREATED')
  assert.equal(planCreated.details.action_count, 1)
  assert.equal(planCreated.details.operator_id, 'operator:local-security-owner')
  assert.equal(planCreated.details.plan_sha256, run.plan_sha256)
  assert.equal(planCreated.details.scope_sha256, run.authorization.scope_sha256)
  assert.equal(planCreated.details.independently_verified, false)
})

test('recon rejects a locally rehashed operator receipt before action selection', async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'rta-recon-receipt-tamper-'))
  t.after(() => rm(parent, { recursive: true, force: true }))
  const out = join(parent, 'bundle')
  const targetUrl = 'https://target.example/exact'
  const now = () => new Date('2026-08-04T12:00:00.000Z')
  await planOperatorAttestedHttpReconBundle({
    targetUrl,
    operatorAuthorization: reconOperatorAuthorization(targetUrl),
    out,
    now,
    randomBytesImpl: (size) => Buffer.alloc(size, 9),
  })

  const eventPath = join(out, 'events.jsonl')
  const runPath = join(out, 'run.json')
  const record = JSON.parse((await readFile(eventPath, 'utf8')).trim())
  record.details.operator_authorization_receipt.authorization_sha256 = 'f'.repeat(64)
  const { record_sha256: _oldDigest, ...unsigned } = record
  record.record_sha256 = digest(unsigned)
  const run = JSON.parse(await readFile(runPath, 'utf8'))
  run.event_chain.last_sha256 = record.record_sha256
  await writeFile(eventPath, stableJson(record, 0), 'utf8')
  await writeFile(runPath, stableJson(run), 'utf8')

  await assert.rejects(
    nextHttpReconAction({ bundle: out, now }),
    (error) => error.code === 'HTTP_RECON_OPERATOR_AUTHORIZATION_RECEIPT_INVALID',
  )
})

test('HTTPS go rejects declaration target drift and caller-supplied derived bindings before planning', async (t) => {
  const cases = [
    reconOperatorAuthorization('https://different.example/exact'),
    reconOperatorAuthorization('https://target.example/exact', {
      plan_sha256: 'd'.repeat(64),
    }),
    reconOperatorAuthorization('https://target.example/exact', {
      scope_revision_sha256: 'e'.repeat(64),
    }),
  ]

  for (const [index, authorization] of cases.entries()) {
    await t.test(String(index), async () => {
      let plans = 0
      await assert.rejects(
        goOperatorAttestedHttpRecon({
          targetUrl: 'https://target.example/exact',
          operatorAuthorization: authorization,
          now: () => new Date('2026-08-04T12:00:00.000Z'),
          out: join(tmpdir(), `must-not-plan-${index}`),
          planImpl: async () => { plans += 1 },
        }),
        (error) => [
          'HTTP_RECON_OPERATOR_AUTHORIZATION_TARGET_MISMATCH',
          'HTTP_RECON_OPERATOR_AUTHORIZATION_DERIVED_FIELD_FORBIDDEN',
        ].includes(error.code),
      )
      assert.equal(plans, 0)
    })
  }
})

test('live recon controllers reject legacy booleans instead of treating them as authorization', async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'rta-recon-legacy-boolean-'))
  t.after(() => rm(parent, { recursive: true, force: true }))
  let plans = 0

  await assert.rejects(
    planOperatorAttestedHttpReconBundle({
      targetUrl: 'https://target.example/exact',
      operatorId: 'operator:recon-owner',
      authorizedBy: 'Authenticated recon owner',
      authorizationReference: 'operator-directive:legacy-plan',
      attestationConfirmed: true,
      out: join(parent, 'plan-must-not-exist'),
    }),
    (error) => error.code === 'HTTP_RECON_AUTHORIZATION_ATTESTATION_REQUIRED',
  )
  await assert.rejects(
    goOperatorAttestedHttpRecon({
      targetUrl: 'https://target.example/exact',
      operatorId: 'operator:recon-owner',
      executionApproved: true,
      out: join(parent, 'go-must-not-exist'),
      planImpl: async () => { plans += 1 },
    }),
    (error) => error.code === 'HTTP_RECON_LIVE_EXECUTION_AUTHORIZATION_REQUIRED',
  )
  assert.equal(plans, 0)
})

test('live recon rejects noncanonical authorization evidence before planning', async (t) => {
  const cases = [
    {
      code: 'HTTP_RECON_OPERATOR_AUTHORIZATION_STATEMENT_INVALID',
      overrides: { statement: 'I am explicitly not authorized.' },
    },
    {
      code: 'HTTP_RECON_OPERATOR_AUTHORIZATION_SHAPE_INVALID',
      overrides: { authorization_reference: ' operator-directive:recon-test-001 ' },
    },
    {
      code: 'HTTP_RECON_OPERATOR_AUTHORIZATION_TIME_STALE',
      overrides: { declared_at: '2026-08-04T11:54:59.999Z' },
    },
    {
      code: 'HTTP_RECON_OPERATOR_AUTHORIZATION_TIME_FUTURE',
      overrides: { declared_at: '2026-08-04T12:00:00.001Z' },
    },
  ]

  for (const [index, scenario] of cases.entries()) {
    await t.test(String(index), async () => {
      let plans = 0
      await assert.rejects(
        goOperatorAttestedHttpRecon({
          targetUrl: 'https://target.example/exact',
          operatorAuthorization: reconOperatorAuthorization(
            'https://target.example/exact',
            scenario.overrides,
          ),
          now: () => new Date('2026-08-04T12:00:00.000Z'),
          out: join(tmpdir(), `must-not-plan-noncanonical-${index}`),
          planImpl: async () => { plans += 1 },
        }),
        (error) => error.code === scenario.code,
      )
      assert.equal(plans, 0)
    })
  }
})

test('public http-recon plan invocation supplies one declaration without --attest-authorized', async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'rta-recon-plan-ingress-'))
  t.after(() => rm(parent, { recursive: true, force: true }))
  const out = join(parent, 'bundle')
  const result = spawnSync(process.execPath, [
    'scripts/http-recon.mjs',
    'plan',
    '--target-url', 'https://target.example/exact-plan',
    '--operator-id', 'operator:recon-owner',
    '--authorized-by', 'Authenticated recon owner',
    '--authorization-reference', 'operator-directive:recon-plan-001',
    '--out', out,
    '--json',
  ], {
    cwd: process.cwd(),
    encoding: 'utf8',
    shell: false,
    windowsHide: true,
  })

  assert.equal(result.status, 0, result.stderr)
  const summary = JSON.parse(result.stdout)
  assert.equal(summary.authorization_mode, 'OPERATOR_ATTESTED')
  assert.equal(summary.action_count, 1)
  const run = JSON.parse(await readFile(join(out, 'run.json'), 'utf8'))
  const records = (await readFile(join(out, 'events.jsonl'), 'utf8'))
    .trimEnd()
    .split('\n')
    .map((line) => JSON.parse(line))
  const receipt = records.find(({ type }) => type === 'PLAN_CREATED')
    ?.details?.operator_authorization_receipt
  assert.equal(receipt.status, 'OPERATOR_ASSERTED_AUTHORIZED')
  assert.equal(receipt.operator_id, 'operator:recon-owner')
  assert.equal(receipt.plan_sha256, run.plan_sha256)
  assert.equal(receipt.scope_revision_sha256, run.authorization.scope_sha256)
  assert.deepEqual(receipt.target, {
    kind: 'https_url',
    url: 'https://target.example/exact-plan',
  })
  assert.equal('authorization_document' in receipt, false)
  assert.equal('legal_proof' in receipt, false)
})

test('direct http-recon planner omission still refuses before creating a bundle', async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'rta-recon-direct-plan-ingress-'))
  t.after(() => rm(parent, { recursive: true, force: true }))
  const out = join(parent, 'must-not-exist')
  await assert.rejects(
    planOperatorAttestedHttpReconBundle({
      targetUrl: 'https://target.example/exact',
      operatorId: 'operator:recon-owner',
      authorizedBy: 'Authenticated recon owner',
      authorizationReference: 'operator-directive:recon-direct-plan-001',
      out,
    }),
    (error) => error.code === 'HTTP_RECON_AUTHORIZATION_ATTESTATION_REQUIRED',
  )
})

test('public http-recon run invocation does not inject repeat authorization', async () => {
  const sentinel = new Error('stop after public run authorization ingress')
  let received
  await assert.rejects(
    httpReconMain([
      'run',
      'synthetic-bundle-not-read-by-stub',
      'action:synthetic-not-sent',
      '--operator-id', 'operator:recon-owner',
      '--rationale', 'execute the already sealed authorized action',
    ], {
      runAction: async (input) => {
        received = input
        throw sentinel
      },
    }),
    (error) => error === sentinel,
  )
  assert.equal('authorizationConfirmed' in received, false)
  assert.equal(received.operatorId, 'operator:recon-owner')
  assert.equal(received.actionId, 'action:synthetic-not-sent')
  assert.equal('authorizationDocumentPath' in received, false)
  assert.equal('ownerPublicKeyPath' in received, false)
})

test('direct http-recon run reaches the transport boundary without repeat authorization', async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'rta-recon-direct-run-ingress-'))
  t.after(() => rm(parent, { recursive: true, force: true }))
  const targetUrl = 'https://target.example/exact'
  const out = join(parent, 'bundle')
  const now = () => new Date('2026-08-04T12:00:00.000Z')
  const planned = await planOperatorAttestedHttpReconBundle({
    targetUrl,
    operatorAuthorization: reconOperatorAuthorization(targetUrl),
    authorizedBy: 'Authenticated recon owner',
    out,
    now,
    randomBytesImpl: (size) => Buffer.alloc(size, 8),
  })
  const sentinel = new Error('stop at the synthetic transport boundary')
  let probes = 0
  await assert.rejects(
    runHttpReconAction({
      bundle: out,
      actionId: planned.run.actions[0].action_id,
      operatorId: 'operator:local-security-owner',
      rationale: 'execute the already sealed authorized action',
      now,
      probeImpl: async () => {
        probes += 1
        throw sentinel
      },
      fetchProofImpl: async () => { throw new Error('must not fetch authority proof') },
    }),
    (error) => error === sentinel,
  )
  assert.equal(probes, 1)
})

function httpAuthedPlanArguments(scopePath) {
  return [
    'plan-attested',
    '--scope', scopePath,
    '--engagement-id', 'operator-ingress-http-authed',
    '--authorization-id', 'operator-ingress-http-authed-authorization',
    '--operator-id', 'operator:http-authed-owner',
    '--authorized-by', 'Authenticated HTTP campaign owner',
    '--authorization-reference', 'operator-directive:http-authed-plan-001',
    '--not-before', '2026-08-17T09:00:00.000Z',
    '--not-after', '2026-08-17T11:00:00.000Z',
    '--target-origin', 'https://bounty.example.test',
    '--environment', 'production',
    '--data-class', 'phi',
    '--ownership', 'third_party_owned',
    '--credential-stdin',
    '--credential-kind', 'cookie',
    '--path-prefix', '/authorized',
    '--method', 'GET',
    '--test-category', 'api_security',
    '--seed-url', 'https://bounty.example.test/authorized/non-phi-seed',
    '--seed-test-category', 'api_security',
    '--min-interval-ms', '0',
    '--json',
  ]
}

test('public http-authed plan-attested invocation supplies its declaration without a repeat flag', async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'rta-http-authed-plan-ingress-'))
  t.after(() => rm(parent, { recursive: true, force: true }))
  const scopePath = join(parent, 'scope.json')
  let output = ''
  let credentialReads = 0
  let transportCalls = 0
  await httpAuthedMain(httpAuthedPlanArguments(scopePath), {
    clock: () => new Date('2026-08-17T10:00:00.000Z'),
    env: {},
    credentialInput: Symbol('sealed stdin credential'),
    credentialStdinReader: async () => {
      credentialReads += 1
      return Buffer.from('__Host-rta=SYNTHETIC_OPERATOR_INGRESS', 'ascii')
    },
    transport: async () => { transportCalls += 1 },
    write: (value) => { output += value },
  })

  assert.equal(credentialReads, 1)
  assert.equal(transportCalls, 0)
  const summary = JSON.parse(output)
  assert.equal(summary.authorization_mode, 'OPERATOR_ATTESTED_AUTHED')
  assert.equal(summary.independently_verified, false)
  assert.equal('authorization_document_sha256' in summary, false)
  const scope = JSON.parse(await readFile(scopePath, 'utf8'))
  assert.equal(scope.authorization.operator_id, 'operator:http-authed-owner')
  assert.equal(scope.authorization.independently_verified, false)
  assert.match(scope.authorization.statement, /authorized/i)
  assert.deepEqual(scope.authorization.authorized_scope.origins, [
    'https://bounty.example.test',
  ])
})

test('direct http-authed planner omission still requires explicit operator authority', async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'rta-http-authed-direct-plan-ingress-'))
  t.after(() => rm(parent, { recursive: true, force: true }))
  await assert.rejects(
    planHttpAuthedAttestedScope({
      outputPath: join(parent, 'must-not-exist.json'),
      authorization: {},
    }, {
      clock: () => new Date('2026-08-17T10:00:00.000Z'),
      env: {},
    }),
    (error) => error.code === 'HTTP_AUTHED_PLAN_ATTESTATION_REQUIRED',
  )
})

test('http-authed public commands expose only operator-statement authorization', async () => {
  let requestPlanReads = 0
  let transportCalls = 0
  let help = ''
  await httpAuthedMain(['--help'], { write: (value) => { help += value } })
  assert.doesNotMatch(help, /plan-written|validate-written|campaign-written/i)
  assert.doesNotMatch(help, /authorization-document|approver-public-key|countersignature/i)

  await assert.rejects(
    httpAuthedMain([
      'plan-written',
      '--scope', 'must-not-exist.json',
      '--authorization-document', 'must-not-read.txt',
    ], {
      requestPlanLstat: async () => { requestPlanReads += 1 },
      transport: async () => { transportCalls += 1 },
      write: () => {},
    }),
    /supported http-authed command/i,
  )
  assert.equal(requestPlanReads, 0)
  assert.equal(transportCalls, 0)
})
