import assert from 'node:assert/strict'
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import {
  openHttpAuthedCampaignLedger,
  requestHttpAuthedCampaignStop,
} from '../scripts/lib/http-authed-campaign-ledger.mjs'
import {
  canonicalJson,
  sha256Hex,
  verifyHttpAuthedAuthorization,
} from '../scripts/lib/http-authed-contracts.mjs'
import {
  recoverDeclaredHttpAuthedMutation,
  runDeclaredHttpAuthedMutation,
  verifyTransientHttpAuthedJsonObservation,
} from '../scripts/lib/http-authed-mutation-controller.mjs'
import { attestedScope } from './helpers/http-authed-fixtures.mjs'

const NOW = new Date('2026-08-16T12:00:00.000Z')
const OPERATOR_ID = 'example-security-operator'
const CREDENTIAL = Buffer.from('SYNTHETIC_SECRET_CREDENTIAL_VALUE')
const MUTATION_BODY = Buffer.alloc(64, 0x78)
const ROLLBACK_BODY = Buffer.alloc(64, 0x79)
const SECRET_RESPONSE = 'SYNTHETIC_SECRET_RESPONSE_BODY_VALUE'
const SECRET_HEADER = 'SYNTHETIC_SECRET_HEADER_VALUE'
const SECRET_HEADER_NAME = 'x-synthetic-patient-identifier-54321'

async function campaign(t, suffix, { configureScope, faultInjector } = {}) {
  const scope = attestedScope({ actionCount: 1 })
  scope.limits.min_interval_ms = 0
  scope.credential.binding_sha256 = sha256Hex(CREDENTIAL)
  scope.requests[0].request_body.sha256 = sha256Hex(MUTATION_BODY)
  scope.requests[0].request_body.byte_length = MUTATION_BODY.length
  scope.requests[0].rollback.request_body.sha256 = sha256Hex(ROLLBACK_BODY)
  scope.requests[0].rollback.request_body.byte_length = ROLLBACK_BODY.length
  configureScope?.(scope)
  const verified = verifyHttpAuthedAuthorization({
    scope,
    now: NOW,
  })
  const parent = await mkdtemp(join(tmpdir(), `rta-http-authed-mutation-${suffix}-`))
  const ledger = await openHttpAuthedCampaignLedger({
    directory: join(parent, 'ledger'),
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
    independentlyVerified: scope.authorization.independently_verified,
    operatorId: OPERATOR_ID,
    initialize: true,
    now: () => NOW,
    limits: { lockTimeoutMs: 100, staleLockMs: 1, lockPollMs: 1 },
    faultInjector,
  })
  t.after(async () => {
    await ledger.close()
    await rm(parent, { recursive: true, force: true })
  })
  return {
    scope,
    action: scope.requests[0],
    ledger,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
  }
}

function observationVerifier(overrides = {}) {
  const results = {
    BEFORE_READ: { valueMatch: true, contextMatch: true, contextToken: 'TRANSIENT_CONTEXT' },
    AFTER_READ: { valueMatch: true, contextMatch: true },
    ROLLBACK_VERIFY: { valueMatch: true, contextMatch: true },
    ...overrides,
  }
  return async ({ phase }) => results[phase]
}

function successfulTransport(calls, additions = {}) {
  return async (request) => {
    calls.push({ phase: request.phase, method: request.method })
    await request.beforeSend()
    return {
      status: request.phase === 'MUTATION' ? 201 : 200,
      responseBytes: 97,
      responseHeaderNames: ['content-type', 'set-cookie', SECRET_HEADER_NAME],
      responseHeaderValues: ['application/json', SECRET_HEADER],
      body: SECRET_RESPONSE,
      ...additions,
    }
  }
}

function runOptions(campaignState, additions = {}) {
  return {
    ...campaignState,
    operatorId: OPERATOR_ID,
    credentialValue: CREDENTIAL,
    requestBodyBytes: MUTATION_BODY,
    rollbackBodyBytes: ROLLBACK_BODY,
    now: () => NOW,
    verifyObservation: observationVerifier(),
    ...additions,
  }
}

function canonicalValueDigest(value) {
  return sha256Hex(Buffer.from(canonicalJson(value), 'utf8'))
}

async function interruptedMutation(t, suffix) {
  const state = await campaign(t, suffix, {
    configureScope(scope) {
      scope.validity.cleanup_not_after = '2026-08-16T12:10:00.000Z'
    },
  })
  await state.ledger.enqueueCandidate({
    candidateDraft: state.action,
    provenance: 'SEALED_PLAN',
  })
  const lease = await state.ledger.leaseAction({
    candidateDraft: state.action,
    operatorId: OPERATOR_ID,
  })
  for (const phase of ['CREDENTIAL_PREFLIGHT', 'BEFORE_READ']) {
    await state.ledger.markPreDispatch({
      actionId: lease.actionId,
      leaseId: lease.leaseId,
      phase,
      requestBindingSha256: sha256Hex(Buffer.from(`synthetic-${phase}`)),
    })
    await state.ledger.markOutcome({
      actionId: lease.actionId,
      leaseId: lease.leaseId,
      phase,
      outcome: 'SETTLED',
      responseMetadata: {
        status: 200,
        bytes: 0,
        headerNames: ['content-type'],
        requestMayHaveBeenSent: true,
      },
    })
    if (phase === 'BEFORE_READ') {
      await state.ledger.recordVerification({
        actionId: lease.actionId,
        leaseId: lease.leaseId,
        phase,
        valueMatch: true,
        contextMatch: true,
      })
    }
  }
  await state.ledger.consumeAuthorization({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    nonce: `synthetic-${suffix}-authorization-nonce-0001`,
    dispatchPermitSha256: 'a'.repeat(64),
  })
  await state.ledger.markPreDispatch({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'MUTATION',
    requestBindingSha256: 'b'.repeat(64),
  })
  await state.ledger.markOutcome({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'MUTATION',
    outcome: 'FAILED',
    responseMetadata: {
      status: null,
      bytes: 0,
      headerNames: [],
      requestMayHaveBeenSent: true,
    },
  })
  await state.ledger.stopCampaign('INTERRUPTED_MUTATION_CLEANUP_REQUIRED')
  return { state, lease }
}

test('transient JSON observation verifies one pointer and detects undeclared context drift', () => {
  const beforeBody = Buffer.from(JSON.stringify({
    synthetic_marker: 'before',
    stable_sibling: 'stable',
    transient_sensitive_value: 'SYNTHETIC_PHI_SENTINEL',
  }))
  const afterBody = Buffer.from(JSON.stringify({
    synthetic_marker: 'after',
    stable_sibling: 'stable',
    transient_sensitive_value: 'SYNTHETIC_PHI_SENTINEL',
  }))
  const driftedBody = Buffer.from(JSON.stringify({
    synthetic_marker: 'after',
    stable_sibling: 'changed',
    transient_sensitive_value: 'SYNTHETIC_PHI_SENTINEL',
  }))
  const observation = { format: 'JSON', json_pointer: '/synthetic_marker' }
  const before = verifyTransientHttpAuthedJsonObservation({
    response: { body: beforeBody },
    observation,
    expectedDigest: canonicalValueDigest('before'),
  })
  const after = verifyTransientHttpAuthedJsonObservation({
    response: { body: afterBody },
    observation,
    expectedDigest: canonicalValueDigest('after'),
    baselineContextToken: before.contextToken,
  })
  const drifted = verifyTransientHttpAuthedJsonObservation({
    response: { body: driftedBody },
    observation,
    expectedDigest: canonicalValueDigest('after'),
    baselineContextToken: before.contextToken,
  })

  assert.deepEqual(
    { valueMatch: before.valueMatch, contextMatch: before.contextMatch },
    { valueMatch: true, contextMatch: true },
  )
  assert.equal(after.valueMatch, true)
  assert.equal(after.contextMatch, true)
  assert.equal(drifted.valueMatch, true)
  assert.equal(drifted.contextMatch, false)
  assert.doesNotMatch(JSON.stringify({ before, after, drifted }), /SYNTHETIC_PHI_SENTINEL/)
})

test('declared mutation verifies before and after, rolls back once, and verifies cleanup', async (t) => {
  const state = await campaign(t, 'happy')
  const calls = []
  const result = await runDeclaredHttpAuthedMutation(runOptions(state, {
    transport: successfulTransport(calls),
  }))

  assert.deepEqual(calls, [
    { phase: 'CREDENTIAL_PREFLIGHT', method: 'GET' },
    { phase: 'BEFORE_READ', method: 'GET' },
    { phase: 'MUTATION', method: 'POST' },
    { phase: 'AFTER_READ', method: 'GET' },
    { phase: 'ROLLBACK', method: 'PATCH' },
    { phase: 'ROLLBACK_VERIFY', method: 'GET' },
  ])
  assert.equal(result.outcome, 'MUTATION_VERIFIED_ROLLBACK_VERIFIED')
  assert.deepEqual(result.verification, {
    before: true,
    after: true,
    rollback: true,
  })
  assert.equal(state.ledger.actionState(result.action.action_id).terminal, true)
  assert.equal(
    state.ledger.actionState(result.action.action_id).outcome,
    'MUTATION_VERIFIED_ROLLBACK_VERIFIED',
  )

  const rendered = JSON.stringify(result)
  assert.doesNotMatch(rendered, new RegExp(SECRET_RESPONSE))
  assert.doesNotMatch(rendered, new RegExp(SECRET_HEADER))
  assert.doesNotMatch(rendered, /patient-identifier-54321/)
  assert.doesNotMatch(rendered, /SYNTHETIC_SECRET_CREDENTIAL_VALUE/)
  assert.doesNotMatch(rendered, /SYNTHETIC_SECRET_COUNTERSIGNATURE_VALUE/)
  assert.doesNotMatch(rendered, /SYNTHETIC_SECURITY_TEST_RECORD|SYNTHETIC_SECURITY_TEST_PAYLOAD/)
  assert.deepEqual(result.responses.MUTATION.header_names, ['content-type', 'set-cookie', 'other'])

  const recordNames = (await readdir(state.ledger.directory))
    .filter((name) => name.endsWith('.http-authed-campaign.json'))
    .sort()
  const recordTexts = await Promise.all(recordNames.map((name) =>
    readFile(join(state.ledger.directory, name), 'utf8')))
  const records = recordTexts.map((text) => JSON.parse(text))
  assert.deepEqual(
    records.filter(({ event }) => event.type === 'REQUEST_PRE_DISPATCH')
      .map(({ event }) => event.phase),
    [
      'CREDENTIAL_PREFLIGHT', 'BEFORE_READ', 'MUTATION', 'AFTER_READ',
      'ROLLBACK', 'ROLLBACK_VERIFY',
    ],
  )
  assert.deepEqual(
    records.filter(({ event }) => event.type === 'VERIFICATION_RECORDED')
      .map(({ event }) => event.phase),
    ['BEFORE_READ', 'AFTER_READ', 'ROLLBACK_VERIFY'],
  )
  const durableText = recordTexts.join('\n')
  assert.doesNotMatch(durableText, new RegExp(SECRET_RESPONSE))
  assert.doesNotMatch(durableText, new RegExp(SECRET_HEADER))
  assert.doesNotMatch(durableText, /SYNTHETIC_SECRET_CREDENTIAL_VALUE/)
})

test('an applied mutation keeps cleanup authority when the action window closes mid-run', async (t) => {
  const state = await campaign(t, 'cross-action-deadline', {
    configureScope(scope) {
      scope.validity.cleanup_not_after = '2026-08-16T12:10:00.000Z'
    },
  })
  const calls = []
  let current = NOW
  const result = await runDeclaredHttpAuthedMutation(runOptions(state, {
    now: () => current,
    transport: async (request) => {
      calls.push(request.phase)
      await request.beforeSend()
      if (request.phase === 'MUTATION') {
        current = new Date('2026-08-16T12:05:00.000Z')
      }
      return {
        status: request.phase === 'MUTATION' ? 201 : 200,
        responseBytes: 0,
        responseHeaderNames: ['content-type'],
      }
    },
  }))

  assert.deepEqual(calls, [
    'CREDENTIAL_PREFLIGHT',
    'BEFORE_READ',
    'MUTATION',
    'AFTER_READ',
    'ROLLBACK',
    'ROLLBACK_VERIFY',
  ])
  assert.equal(result.outcome, 'MUTATION_VERIFIED_ROLLBACK_VERIFIED')
})

test('declared mutation can use the transient JSON verifier with ephemeral transport bodies', async (t) => {
  const state = await campaign(t, 'transient-e2e', {
    configureScope(scope) {
      scope.requests[0].expected_mutation.before_digest = canonicalValueDigest('BEFORE_VALUE_SENTINEL')
      scope.requests[0].expected_mutation.after_digest = canonicalValueDigest('AFTER_VALUE_SENTINEL')
      scope.requests[0].rollback.expected_after_digest = canonicalValueDigest('BEFORE_VALUE_SENTINEL')
    },
  })
  const bodies = {
    BEFORE_READ: Buffer.from('{"synthetic_marker":"BEFORE_VALUE_SENTINEL","stable":"BODY_CONTEXT_SENTINEL"}'),
    AFTER_READ: Buffer.from('{"synthetic_marker":"AFTER_VALUE_SENTINEL","stable":"BODY_CONTEXT_SENTINEL"}'),
    ROLLBACK_VERIFY: Buffer.from('{"synthetic_marker":"BEFORE_VALUE_SENTINEL","stable":"BODY_CONTEXT_SENTINEL"}'),
  }
  const result = await runDeclaredHttpAuthedMutation(runOptions(state, {
    verifyObservation: undefined,
    transport: async (request) => {
      await request.beforeSend()
      return {
        status: request.phase === 'MUTATION' ? 201 : 200,
        responseBytes: bodies[request.phase]?.length ?? 0,
        responseHeaderNames: ['content-type'],
        body: bodies[request.phase] ?? Buffer.alloc(0),
      }
    },
  }))

  assert.equal(result.outcome, 'MUTATION_VERIFIED_ROLLBACK_VERIFIED')
  assert.deepEqual(result.verification, { before: true, after: true, rollback: true })
  assert.doesNotMatch(
    JSON.stringify(result),
    /synthetic_marker|BODY_CONTEXT_SENTINEL|BEFORE_VALUE_SENTINEL|AFTER_VALUE_SENTINEL/,
  )
})

test('declared mutation derives and consumes a campaign-bound controller permit', async (t) => {
  const state = await campaign(t, 'controller-dispatch-permit')
  const calls = []
  const result = await runDeclaredHttpAuthedMutation(runOptions(state, {
    transport: successfulTransport(calls),
  }))

  assert.equal(result.outcome, 'MUTATION_VERIFIED_ROLLBACK_VERIFIED')
  assert.equal(calls.filter(({ phase }) => phase === 'MUTATION').length, 1)
  const actionState = state.ledger.actionState(result.action.action_id)
  assert.equal(actionState.authorization_consumed, true)
  const records = await Promise.all(
    (await readdir(state.ledger.directory))
      .filter((name) => name.endsWith('.json'))
      .map((name) => readFile(join(state.ledger.directory, name), 'utf8')),
  )
  const ledgerText = records.join('\n')
  assert.match(ledgerText, /AUTHORIZATION_CONSUMED/)
  assert.match(ledgerText, /dispatch_permit_sha256/)
  assert.doesNotMatch(ledgerText, /countersignature/i)
})

test('before-state mismatch terminalizes without dispatching a mutation', async (t) => {
  const state = await campaign(t, 'before-mismatch')
  const calls = []
  const result = await runDeclaredHttpAuthedMutation(runOptions(state, {
    transport: successfulTransport(calls),
    verifyObservation: observationVerifier({
      BEFORE_READ: { valueMatch: false, contextMatch: true },
    }),
  }))

  assert.deepEqual(calls, [
    { phase: 'CREDENTIAL_PREFLIGHT', method: 'GET' },
    { phase: 'BEFORE_READ', method: 'GET' },
  ])
  assert.equal(result.outcome, 'FAILED_BEFORE_MUTATION')
  assert.equal(result.verification.before, false)
  assert.equal(state.ledger.actionState(result.action.action_id).outcome, 'FAILED_BEFORE_MUTATION')
})

test('before-state observer failure is ledgered and never reported as a mismatch', async (t) => {
  const state = await campaign(t, 'before-observer-failure')
  const calls = []
  const result = await runDeclaredHttpAuthedMutation(runOptions(state, {
    transport: successfulTransport(calls),
    verifyObservation: async ({ phase }) => {
      if (phase === 'BEFORE_READ') {
        throw new Error('SYNTHETIC_SENSITIVE_OBSERVER_FAILURE_DETAIL')
      }
      return { valueMatch: true, contextMatch: true }
    },
  }))
  const action = state.ledger.actionState(result.action.action_id)
  const renderedRecords = (await Promise.all(
    (await readdir(state.ledger.directory))
      .filter((name) => name.endsWith('.http-authed-campaign.json'))
      .map((name) => readFile(join(state.ledger.directory, name), 'utf8')),
  )).join('\n')

  assert.deepEqual(calls, [
    { phase: 'CREDENTIAL_PREFLIGHT', method: 'GET' },
    { phase: 'BEFORE_READ', method: 'GET' },
  ])
  assert.equal(result.schema_version, '1.1.0')
  assert.deepEqual(result.verification_failures, [{
    phase: 'BEFORE_READ',
    reason_code: 'TRANSIENT_OBSERVATION_FAILED',
  }])
  assert.equal(result.terminal_reason_code, 'BEFORE_OBSERVATION_FAILED')
  assert.equal(result.outcome, 'FAILED_BEFORE_MUTATION')
  assert.equal(action.terminal_reason_code, 'BEFORE_OBSERVATION_FAILED')
  assert.deepEqual(action.last_verification, {
    failed: true,
    reason_code: 'TRANSIENT_OBSERVATION_FAILED',
  })
  assert.match(renderedRecords, /"type"\s*:\s*"VERIFICATION_FAILED"/)
  assert.doesNotMatch(renderedRecords, /SYNTHETIC_SENSITIVE_OBSERVER_FAILURE_DETAIL/)
})

test('an out-of-band operator stop after the before-read prevents mutation dispatch', async (t) => {
  const state = await campaign(t, 'stop-before-mutation')
  const sent = []
  const result = await runDeclaredHttpAuthedMutation(runOptions(state, {
    transport: async (request) => {
      await request.beforeSend()
      sent.push(request.phase)
      if (request.phase === 'BEFORE_READ') {
        await requestHttpAuthedCampaignStop({
          directory: state.ledger.directory,
          campaignGrantSha256: state.expectedCampaignGrantSha256,
          operatorId: OPERATOR_ID,
          now: () => NOW,
        })
      }
      return {
        status: request.phase === 'MUTATION' ? 201 : 200,
        responseBytes: 0,
        responseHeaderNames: ['content-type'],
        body: Buffer.from('{}'),
      }
    },
  }))

  assert.deepEqual(sent, ['CREDENTIAL_PREFLIGHT', 'BEFORE_READ'])
  assert.equal(result.outcome, 'FAILED_BEFORE_SEND')
  assert.equal(state.ledger.snapshot().stopped, true)
  assert.equal(state.ledger.actionState(result.action.action_id).authorization_consumed, false)
})

test('a stop committed with mutation pre-dispatch is settled before the write sends', async (t) => {
  const state = await campaign(t, 'stop-with-mutation-pre-dispatch')
  const durablePreDispatch = state.ledger.markPreDispatch.bind(state.ledger)
  state.ledger.markPreDispatch = async (input) => {
    const result = await durablePreDispatch(input)
    if (input.phase === 'MUTATION') {
      await requestHttpAuthedCampaignStop({
        directory: state.ledger.directory,
        campaignGrantSha256: state.expectedCampaignGrantSha256,
        operatorId: OPERATOR_ID,
        now: () => NOW,
      })
    }
    return result
  }
  const sent = []
  const result = await runDeclaredHttpAuthedMutation(runOptions(state, {
    transport: async (request) => {
      await request.beforeSend()
      sent.push(request.phase)
      return {
        status: request.phase === 'MUTATION' ? 201 : 200,
        responseBytes: 0,
        responseHeaderNames: ['content-type'],
        body: Buffer.from('{}'),
      }
    },
  }))
  const action = state.ledger.actionState(result.action.action_id)

  assert.deepEqual(sent, ['CREDENTIAL_PREFLIGHT', 'BEFORE_READ'])
  assert.equal(result.outcome, 'FAILED_BEFORE_SEND')
  assert.equal(state.ledger.snapshot().stopped, true)
  assert.equal(action.authorization_consumed, true)
  assert.equal(action.phase_outcomes.MUTATION.outcome, 'FAILED')
  assert.equal(action.phase_outcomes.MUTATION.request_may_have_been_sent, false)
})

test('an operator stop after mutation dispatch is recorded while cleanup still completes', async (t) => {
  const state = await campaign(t, 'stop-after-mutation')
  const sent = []
  const result = await runDeclaredHttpAuthedMutation(runOptions(state, {
    transport: async (request) => {
      await request.beforeSend()
      sent.push(request.phase)
      if (request.phase === 'MUTATION') {
        await requestHttpAuthedCampaignStop({
          directory: state.ledger.directory,
          campaignGrantSha256: state.expectedCampaignGrantSha256,
          operatorId: OPERATOR_ID,
          now: () => NOW,
        })
      }
      return {
        status: request.phase === 'MUTATION' ? 201 : 200,
        responseBytes: 0,
        responseHeaderNames: ['content-type'],
        body: Buffer.from('{}'),
      }
    },
  }))

  assert.deepEqual(sent, [
    'CREDENTIAL_PREFLIGHT', 'BEFORE_READ', 'MUTATION', 'AFTER_READ',
    'ROLLBACK', 'ROLLBACK_VERIFY',
  ])
  assert.equal(result.outcome, 'MUTATION_VERIFIED_ROLLBACK_VERIFIED')
  assert.equal(state.ledger.snapshot().stopped, true)
})

test('credential preflight failure prevents reads and mutation dispatch', async (t) => {
  const state = await campaign(t, 'credential-preflight')
  const calls = []
  const result = await runDeclaredHttpAuthedMutation(runOptions(state, {
    transport: async (request) => {
      calls.push(request.phase)
      await request.beforeSend()
      return {
        status: 401,
        responseBytes: 0,
        responseHeaderNames: ['content-type'],
      }
    },
  }))

  assert.deepEqual(calls, ['CREDENTIAL_PREFLIGHT'])
  assert.equal(result.outcome, 'FAILED_BEFORE_MUTATION')
  assert.equal(result.responses.CREDENTIAL_PREFLIGHT.status, 401)
})

test('an undeclared before-read status blocks mutation even if the observer would match', async (t) => {
  const state = await campaign(t, 'before-status')
  const calls = []
  const result = await runDeclaredHttpAuthedMutation(runOptions(state, {
    transport: async (request) => {
      calls.push(request.phase)
      await request.beforeSend()
      return {
        status: request.phase === 'CREDENTIAL_PREFLIGHT' ? 200 : 404,
        responseBytes: 0,
        responseHeaderNames: ['content-type'],
      }
    },
  }))

  assert.deepEqual(calls, ['CREDENTIAL_PREFLIGHT', 'BEFORE_READ'])
  assert.equal(result.outcome, 'FAILED_BEFORE_MUTATION')
  assert.equal(result.verification.before, false)
})

test('mutation refuses to start when the authorization window cannot cover cleanup', async (t) => {
  const state = await campaign(t, 'cleanup-window', {
    configureScope(scope) {
      scope.limits.min_interval_ms = 0
      scope.validity.not_after = '2026-08-16T12:00:30.000Z'
      scope.validity.cleanup_not_after = scope.validity.not_after
    },
  })
  const sent = []
  const result = await runDeclaredHttpAuthedMutation(runOptions(state, {
    transport: async (request) => {
      await request.beforeSend()
      sent.push(request.phase)
      return {
        status: 200,
        responseBytes: 0,
        responseHeaderNames: ['content-type'],
      }
    },
  }))

  assert.deepEqual(sent, ['CREDENTIAL_PREFLIGHT', 'BEFORE_READ'])
  assert.equal(result.outcome, 'FAILED_BEFORE_SEND')
  assert.equal(state.ledger.actionState(result.action.action_id).authorization_consumed, false)
})

test('a sealed cleanup extension can cover settlement near the action deadline', async (t) => {
  const state = await campaign(t, 'extended-cleanup-window', {
    configureScope(scope) {
      scope.limits.min_interval_ms = 0
      scope.validity.cleanup_not_after = '2026-08-16T12:10:00.000Z'
    },
  })
  const calls = []
  const result = await runDeclaredHttpAuthedMutation(runOptions(state, {
    now: () => new Date('2026-08-16T12:03:50.000Z'),
    transport: successfulTransport(calls),
  }))

  assert.equal(result.outcome, 'MUTATION_VERIFIED_ROLLBACK_VERIFIED')
  assert.deepEqual(calls.map(({ phase }) => phase), [
    'CREDENTIAL_PREFLIGHT',
    'BEFORE_READ',
    'MUTATION',
    'AFTER_READ',
    'ROLLBACK',
    'ROLLBACK_VERIFY',
  ])
})

test('cleanup authorization does not permit a new mutation at the action deadline', async (t) => {
  const state = await campaign(t, 'cleanup-new-mutation-blocked', {
    configureScope(scope) {
      scope.validity.cleanup_not_after = '2026-08-16T12:10:00.000Z'
    },
  })
  const sent = []

  await assert.rejects(
    runDeclaredHttpAuthedMutation(runOptions(state, {
      now: () => new Date(state.scope.validity.not_after),
      transport: async (request) => {
        await request.beforeSend()
        sent.push(request.phase)
        return { status: 200, responseBytes: 0, responseHeaderNames: [] }
      },
    })),
    (error) => error.code === 'HTTP_AUTHED_MUTATION_AUTHORIZATION_REJECTED'
      && error.cause?.code === 'HTTP_AUTHED_AUTHORIZATION_EXPIRED',
  )

  assert.deepEqual(sent, [])
  assert.equal(state.ledger.snapshot().queued_actions, 0)
  assert.equal(state.ledger.snapshot().next_action_sequence, 1)
})

test('an ambiguous mutation is not retried and enters its sealed idempotent cleanup path', async (t) => {
  const state = await campaign(t, 'mutation-ambiguous')
  const calls = []
  const transport = async (request) => {
    calls.push(request.phase)
    await request.beforeSend()
    if (request.phase === 'MUTATION') {
      const error = new Error(`transport failed ${SECRET_RESPONSE}`)
      error.request_may_have_been_sent = true
      throw error
    }
    return { status: 200, responseBytes: 1, responseHeaderNames: [] }
  }

  const result = await runDeclaredHttpAuthedMutation(runOptions(state, {
    transport,
    verifyObservation: observationVerifier({
      AFTER_READ: { valueMatch: false, contextMatch: false },
    }),
  }))

  assert.deepEqual(calls, [
    'CREDENTIAL_PREFLIGHT', 'BEFORE_READ', 'MUTATION', 'AFTER_READ',
    'ROLLBACK', 'ROLLBACK_VERIFY',
  ])
  assert.equal(result.outcome, 'ROLLBACK_VERIFIED_AFTER_FAILURE')
  assert.equal(calls.filter((phase) => phase === 'MUTATION').length, 1)
  assert.equal(calls.filter((phase) => phase === 'ROLLBACK').length, 1)
  assert.doesNotMatch(JSON.stringify(result), new RegExp(SECRET_RESPONSE))
})

test('a mutation response stop status survives verified rollback', async (t) => {
  const state = await campaign(t, 'mutation-status-stop')
  const calls = []
  const result = await runDeclaredHttpAuthedMutation(runOptions(state, {
    transport: async (request) => {
      calls.push(request.phase)
      await request.beforeSend()
      return {
        status: request.phase === 'MUTATION' ? 500 : 200,
        responseBytes: 0,
        responseHeaderNames: [],
        body: Buffer.from('{}'),
      }
    },
  }))

  assert.deepEqual(calls, [
    'CREDENTIAL_PREFLIGHT', 'BEFORE_READ', 'MUTATION', 'AFTER_READ',
    'ROLLBACK', 'ROLLBACK_VERIFY',
  ])
  assert.equal(result.outcome, 'ROLLBACK_VERIFIED_AFTER_FAILURE')
  assert.equal(result.stop_reason, 'TARGET_HEALTH_DEGRADED')
})

for (const status of [304, 305, 306]) {
  test(`non-redirect HTTP status ${status} does not set a mutation stop reason`, async (t) => {
    const state = await campaign(t, `mutation-non-redirect-${status}`)
    const calls = []
    const result = await runDeclaredHttpAuthedMutation(runOptions(state, {
      transport: async (request) => {
        calls.push(request.phase)
        await request.beforeSend()
        return {
          status: request.phase === 'MUTATION' ? status : 200,
          responseBytes: 0,
          responseHeaderNames: [],
          body: Buffer.from('{}'),
        }
      },
    }))

    assert.deepEqual(calls, [
      'CREDENTIAL_PREFLIGHT', 'BEFORE_READ', 'MUTATION', 'AFTER_READ',
      'ROLLBACK', 'ROLLBACK_VERIFY',
    ])
    assert.equal(result.outcome, 'ROLLBACK_VERIFIED_AFTER_FAILURE')
    assert.equal(result.stop_reason, null)
  })
}

test('a linked mutation settlement append fault still completes rollback without replaying the write', async (t) => {
  let injected = false
  const state = await campaign(t, 'linked-settlement-fault', {
    faultInjector: async (phase, details) => {
      if (!injected && phase === 'after-record-linked' && details.sequence === 10) {
        injected = true
        throw new Error('synthetic linked mutation settlement fault')
      }
    },
  })
  const calls = []

  const result = await runDeclaredHttpAuthedMutation(runOptions(state, {
    transport: successfulTransport(calls),
  }))

  assert.equal(injected, true)
  assert.deepEqual(calls.map(({ phase }) => phase), [
    'CREDENTIAL_PREFLIGHT', 'BEFORE_READ', 'MUTATION', 'AFTER_READ',
    'ROLLBACK', 'ROLLBACK_VERIFY',
  ])
  assert.equal(calls.filter(({ phase }) => phase === 'MUTATION').length, 1)
  assert.equal(result.outcome, 'MUTATION_VERIFIED_ROLLBACK_VERIFIED')
  assert.equal(state.ledger.actionState(result.action.action_id).terminal, true)
})

test('an unreconciled mutation settlement append fault erases its transient response and still cleans up', async (t) => {
  let injected = 0
  const state = await campaign(t, 'unreconciled-settlement-fault', {
    faultInjector: async (phase, details) => {
      if (
        injected < 2
        && phase === 'after-temporary-durable'
        && details.sequence === 10
      ) {
        injected += 1
        throw new Error('synthetic pre-link mutation settlement fault')
      }
    },
  })
  const calls = []
  let mutationResponseBody
  const result = await runDeclaredHttpAuthedMutation(runOptions(state, {
    transport: async (request) => {
      calls.push(request.phase)
      await request.beforeSend()
      const body = Buffer.alloc(32, 0x73)
      if (request.phase === 'MUTATION') mutationResponseBody = body
      return {
        status: request.phase === 'MUTATION' ? 201 : 200,
        responseBytes: body.length,
        responseHeaderNames: [],
        body,
      }
    },
  }))

  assert.equal(injected, 2)
  assert.equal(calls.filter((phase) => phase === 'MUTATION').length, 1)
  assert.equal(calls.filter((phase) => phase === 'ROLLBACK').length, 1)
  assert.equal(calls.filter((phase) => phase === 'ROLLBACK_VERIFY').length, 1)
  assert.equal(result.outcome, 'ROLLBACK_VERIFIED_AFTER_FAILURE')
  assert.equal(mutationResponseBody.every((byte) => byte === 0), true)
})

for (const boundary of [
  {
    label: 'durable mutation settlement',
    faultPhase: 'after-record-durable',
    recordSequence: 10,
  },
  {
    label: 'after-state verification',
    faultPhase: 'after-temporary-durable',
    recordSequence: 13,
  },
  {
    label: 'rollback pre-dispatch',
    faultPhase: 'after-record-linked',
    recordSequence: 14,
  },
  {
    label: 'rollback settlement',
    faultPhase: 'after-record-durable',
    recordSequence: 15,
  },
  {
    label: 'rollback verification pre-dispatch',
    faultPhase: 'after-record-linked',
    recordSequence: 16,
  },
  {
    label: 'rollback verification settlement',
    faultPhase: 'after-record-durable',
    recordSequence: 17,
  },
  {
    label: 'rollback verification decision',
    faultPhase: 'after-temporary-durable',
    recordSequence: 18,
  },
  {
    label: 'terminal outcome',
    faultPhase: 'after-temporary-durable',
    recordSequence: 19,
  },
]) {
  test(`${boundary.label} append fault preserves verified cleanup and exact-once mutation`, async (t) => {
    let injected = false
    const state = await campaign(t, `append-boundary-${boundary.recordSequence}`, {
      faultInjector: async (phase, details) => {
        if (
          !injected
          && phase === boundary.faultPhase
          && details.sequence === boundary.recordSequence
        ) {
          injected = true
          throw new Error(`synthetic ${boundary.label} append fault`)
        }
      },
    })
    const calls = []

    const result = await runDeclaredHttpAuthedMutation(runOptions(state, {
      transport: successfulTransport(calls),
    }))

    assert.equal(injected, true)
    assert.equal(calls.filter(({ phase }) => phase === 'MUTATION').length, 1)
    assert.equal(calls.filter(({ phase }) => phase === 'ROLLBACK').length, 1)
    assert.equal(calls.filter(({ phase }) => phase === 'ROLLBACK_VERIFY').length, 1)
    assert.equal(result.outcome, 'MUTATION_VERIFIED_ROLLBACK_VERIFIED')
    const ledgerState = state.ledger.actionState(result.action.action_id)
    assert.equal(ledgerState.terminal, true)
    assert.equal(ledgerState.outcome, 'MUTATION_VERIFIED_ROLLBACK_VERIFIED')
  })
}

test('restart after rollback pre-dispatch never repeats the rollback request', async (t) => {
  const state = await campaign(t, 'restart-after-rollback-pre-dispatch')
  await state.ledger.enqueueCandidate({
    candidateDraft: state.action,
    provenance: 'SEALED_PLAN',
  })
  const lease = await state.ledger.leaseAction({
    candidateDraft: state.action,
    operatorId: OPERATOR_ID,
  })
  const settle = async (phase, status) => {
    await state.ledger.markPreDispatch({
      actionId: lease.actionId,
      leaseId: lease.leaseId,
      phase,
      requestBindingSha256: sha256Hex(Buffer.from(`restart-${phase}`)),
    })
    await state.ledger.markOutcome({
      actionId: lease.actionId,
      leaseId: lease.leaseId,
      phase,
      outcome: 'SETTLED',
      responseMetadata: {
        status,
        bytes: 0,
        headerNames: [],
        requestMayHaveBeenSent: true,
      },
    })
  }
  await settle('CREDENTIAL_PREFLIGHT', 200)
  await settle('BEFORE_READ', 200)
  await state.ledger.recordVerification({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'BEFORE_READ',
    valueMatch: true,
    contextMatch: true,
  })
  await state.ledger.consumeAuthorization({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    nonce: 'synthetic-restart-after-rollback-nonce-0001',
    dispatchPermitSha256: 'a'.repeat(64),
  })
  await settle('MUTATION', 201)
  await settle('AFTER_READ', 200)
  await state.ledger.recordVerification({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'AFTER_READ',
    valueMatch: true,
    contextMatch: true,
  })
  await state.ledger.markPreDispatch({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'ROLLBACK',
    requestBindingSha256: 'e'.repeat(64),
  })
  const directory = state.ledger.directory
  await state.ledger.close()

  const reopened = await openHttpAuthedCampaignLedger({
    directory,
    campaignGrantSha256: state.expectedCampaignGrantSha256,
    authorizationBindingSha256: state.ledger.authorizationBindingSha256,
    authorizationMode: state.ledger.authorizationMode,
    independentlyVerified: state.ledger.independentlyVerified,
    operatorId: OPERATOR_ID,
    initialize: false,
    now: () => NOW,
  })
  const sent = []
  const result = await recoverDeclaredHttpAuthedMutation({
    ledger: reopened,
    scope: state.scope,
    action: lease.allocatedAction,
    existingLease: lease,
    expectedCampaignGrantSha256: state.expectedCampaignGrantSha256,
    credentialValue: CREDENTIAL,
    rollbackBodyBytes: ROLLBACK_BODY,
    now: () => NOW,
    verifyObservation: observationVerifier(),
    transport: async (request) => {
      await request.beforeSend()
      sent.push(request.phase)
      return {
        status: 200,
        responseBytes: 0,
        responseHeaderNames: [],
        body: Buffer.from('{}'),
      }
    },
  })
  await reopened.close()

  assert.deepEqual(sent, ['ROLLBACK_VERIFY'])
  assert.equal(result.outcome, 'ROLLBACK_RECOVERED_CONTEXT_UNVERIFIED')
})

test('restart after a durable mutation settlement recovers cleanup without a second mutation', async (t) => {
  let injected = false
  const state = await campaign(t, 'restart-after-durable-settlement', {
    faultInjector: async (phase, details) => {
      if (!injected && phase === 'after-record-linked' && details.sequence === 10) {
        injected = true
        throw new Error('synthetic crash-tail append fault')
      }
    },
  })
  await state.ledger.enqueueCandidate({
    candidateDraft: state.action,
    provenance: 'SEALED_PLAN',
  })
  const lease = await state.ledger.leaseAction({
    candidateDraft: state.action,
    operatorId: OPERATOR_ID,
  })
  for (const phase of ['CREDENTIAL_PREFLIGHT', 'BEFORE_READ']) {
    await state.ledger.markPreDispatch({
      actionId: lease.actionId,
      leaseId: lease.leaseId,
      phase,
      requestBindingSha256: sha256Hex(Buffer.from(`synthetic-${phase}`)),
    })
    await state.ledger.markOutcome({
      actionId: lease.actionId,
      leaseId: lease.leaseId,
      phase,
      outcome: 'SETTLED',
      responseMetadata: {
        status: 200,
        bytes: 0,
        headerNames: [],
        requestMayHaveBeenSent: true,
      },
    })
    if (phase === 'BEFORE_READ') {
      await state.ledger.recordVerification({
        actionId: lease.actionId,
        leaseId: lease.leaseId,
        phase,
        valueMatch: true,
        contextMatch: true,
      })
    }
  }
  await state.ledger.consumeAuthorization({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    nonce: 'synthetic-restart-after-settlement-nonce-0001',
    dispatchPermitSha256: 'a'.repeat(64),
  })
  await state.ledger.markPreDispatch({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'MUTATION',
    requestBindingSha256: 'b'.repeat(64),
  })
  await state.ledger.markOutcome({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'MUTATION',
    outcome: 'SETTLED',
    responseMetadata: {
      status: 201,
      bytes: 0,
      headerNames: [],
      requestMayHaveBeenSent: true,
    },
  })
  assert.equal(injected, true)
  const directory = state.ledger.directory
  await state.ledger.close()

  const reopened = await openHttpAuthedCampaignLedger({
    directory,
    campaignGrantSha256: state.expectedCampaignGrantSha256,
    authorizationBindingSha256: state.ledger.authorizationBindingSha256,
    authorizationMode: state.ledger.authorizationMode,
    independentlyVerified: state.ledger.independentlyVerified,
    operatorId: OPERATOR_ID,
    initialize: false,
    now: () => NOW,
  })
  const sent = []
  const result = await recoverDeclaredHttpAuthedMutation({
    ledger: reopened,
    scope: state.scope,
    action: lease.allocatedAction,
    existingLease: lease,
    expectedCampaignGrantSha256: state.expectedCampaignGrantSha256,
    credentialValue: CREDENTIAL,
    rollbackBodyBytes: ROLLBACK_BODY,
    now: () => NOW,
    verifyObservation: observationVerifier(),
    transport: async (request) => {
      await request.beforeSend()
      sent.push(request.phase)
      return {
        status: 200,
        responseBytes: 0,
        responseHeaderNames: [],
        body: Buffer.from('{}'),
      }
    },
  })
  await reopened.close()

  assert.deepEqual(sent, ['ROLLBACK', 'ROLLBACK_VERIFY'])
  assert.equal(sent.includes('MUTATION'), false)
  assert.equal(result.outcome, 'ROLLBACK_RECOVERED_CONTEXT_UNVERIFIED')
})

test('an interrupted durable mutation resumes cleanup only and never resends the write', async (t) => {
  const state = await campaign(t, 'recovery-cleanup')
  await state.ledger.enqueueCandidate({
    candidateDraft: state.action,
    provenance: 'SEALED_PLAN',
  })
  const lease = await state.ledger.leaseAction({
    candidateDraft: state.action,
    operatorId: OPERATOR_ID,
  })
  for (const phase of ['CREDENTIAL_PREFLIGHT', 'BEFORE_READ']) {
    await state.ledger.markPreDispatch({
      actionId: lease.actionId,
      leaseId: lease.leaseId,
      phase,
      requestBindingSha256: sha256Hex(Buffer.from(`synthetic-${phase}`)),
    })
    await state.ledger.markOutcome({
      actionId: lease.actionId,
      leaseId: lease.leaseId,
      phase,
      outcome: 'SETTLED',
      responseMetadata: {
        status: 200,
        bytes: 0,
        headerNames: ['content-type'],
        requestMayHaveBeenSent: true,
      },
    })
    if (phase === 'BEFORE_READ') {
      await state.ledger.recordVerification({
        actionId: lease.actionId,
        leaseId: lease.leaseId,
        phase,
        valueMatch: true,
        contextMatch: true,
      })
    }
  }
  await state.ledger.consumeAuthorization({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    nonce: 'synthetic-recovery-authorization-nonce-0001',
    dispatchPermitSha256: 'a'.repeat(64),
  })
  await state.ledger.markPreDispatch({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'MUTATION',
    requestBindingSha256: 'b'.repeat(64),
  })
  await state.ledger.markOutcome({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'MUTATION',
    outcome: 'FAILED',
    responseMetadata: {
      status: null,
      bytes: 0,
      headerNames: [],
      requestMayHaveBeenSent: true,
    },
  })
  await state.ledger.stopCampaign('INTERRUPTED_MUTATION_CLEANUP_REQUIRED')

  const calls = []
  const result = await recoverDeclaredHttpAuthedMutation({
    ledger: state.ledger,
    scope: state.scope,
    action: lease.allocatedAction,
    existingLease: lease,
    expectedCampaignGrantSha256: state.expectedCampaignGrantSha256,
    credentialValue: CREDENTIAL,
    rollbackBodyBytes: ROLLBACK_BODY,
    now: () => NOW,
    verifyObservation: observationVerifier(),
    transport: async (request) => {
      await request.beforeSend()
      calls.push(request.phase)
      return {
        status: 200,
        responseBytes: 0,
        responseHeaderNames: ['content-type'],
        body: Buffer.from('{}'),
      }
    },
  })

  assert.deepEqual(calls, ['ROLLBACK', 'ROLLBACK_VERIFY'])
  assert.equal(result.outcome, 'ROLLBACK_RECOVERED_CONTEXT_UNVERIFIED')
  assert.equal(result.verification.rollback_value, true)
  assert.equal(result.verification.sibling_context, false)
  assert.equal(state.ledger.actionState(lease.actionId).terminal, true)
})

test('cleanup observer failure is durably distinguished from rollback mismatch', async (t) => {
  const { state, lease } = await interruptedMutation(t, 'cleanup-observer-failure')
  const sent = []
  const result = await recoverDeclaredHttpAuthedMutation({
    ledger: state.ledger,
    scope: state.scope,
    action: lease.allocatedAction,
    existingLease: lease,
    expectedCampaignGrantSha256: state.expectedCampaignGrantSha256,
    credentialValue: CREDENTIAL,
    rollbackBodyBytes: ROLLBACK_BODY,
    now: () => NOW,
    verifyObservation: async () => {
      throw new Error('SYNTHETIC_PRIVATE_RECOVERY_OBSERVER_DETAIL')
    },
    transport: async (request) => {
      await request.beforeSend()
      sent.push(request.phase)
      return {
        status: 200,
        responseBytes: 0,
        responseHeaderNames: ['content-type'],
        body: Buffer.from('{}'),
      }
    },
  })
  const action = state.ledger.actionState(lease.actionId)

  assert.deepEqual(sent, ['ROLLBACK', 'ROLLBACK_VERIFY'])
  assert.equal(result.schema_version, '1.1.0')
  assert.deepEqual(result.verification_failures, [{
    phase: 'ROLLBACK_VERIFY',
    reason_code: 'TRANSIENT_OBSERVATION_FAILED',
  }])
  assert.equal(result.terminal_reason_code, 'RECOVERY_OBSERVATION_FAILED')
  assert.equal(result.outcome, 'MANUAL_INTERVENTION_REQUIRED')
  assert.equal(action.terminal_reason_code, 'RECOVERY_OBSERVATION_FAILED')
  assert.deepEqual(action.last_verification, {
    failed: true,
    reason_code: 'TRANSIENT_OBSERVATION_FAILED',
  })
  assert.doesNotMatch(
    JSON.stringify(action),
    /SYNTHETIC_PRIVATE_RECOVERY_OBSERVER_DETAIL/,
  )
})

test('ledger-proven interrupted mutation can recover after action expiry until cleanup expiry', async (t) => {
  const { state, lease } = await interruptedMutation(t, 'post-expiry-recovery')
  const sent = []
  const nextActionSequence = state.ledger.snapshot().next_action_sequence

  const result = await recoverDeclaredHttpAuthedMutation({
    ledger: state.ledger,
    scope: state.scope,
    action: lease.allocatedAction,
    existingLease: lease,
    expectedCampaignGrantSha256: state.expectedCampaignGrantSha256,
    credentialValue: CREDENTIAL,
    rollbackBodyBytes: ROLLBACK_BODY,
    now: () => new Date('2026-08-16T12:05:00.000Z'),
    verifyObservation: observationVerifier(),
    transport: async (request) => {
      await request.beforeSend()
      sent.push(request.phase)
      return {
        status: 200,
        responseBytes: 0,
        responseHeaderNames: ['content-type'],
        body: Buffer.from('{}'),
      }
    },
  })

  assert.deepEqual(sent, ['ROLLBACK', 'ROLLBACK_VERIFY'])
  assert.equal(sent.includes('MUTATION'), false)
  assert.equal(state.ledger.snapshot().next_action_sequence, nextActionSequence)
  assert.equal(result.outcome, 'ROLLBACK_RECOVERED_CONTEXT_UNVERIFIED')
})

test('cleanup recovery sends nothing at or after cleanup_not_after', async (t) => {
  const { state, lease } = await interruptedMutation(t, 'cleanup-expired')
  const sent = []

  await recoverDeclaredHttpAuthedMutation({
    ledger: state.ledger,
    scope: state.scope,
    action: lease.allocatedAction,
    existingLease: lease,
    expectedCampaignGrantSha256: state.expectedCampaignGrantSha256,
    credentialValue: CREDENTIAL,
    rollbackBodyBytes: ROLLBACK_BODY,
    now: () => new Date(state.scope.validity.cleanup_not_after),
    verifyObservation: observationVerifier(),
    transport: async (request) => {
      await request.beforeSend()
      sent.push(request.phase)
      return {
        status: 200,
        responseBytes: 0,
        responseHeaderNames: [],
        body: Buffer.from('{}'),
      }
    },
  }).catch(() => undefined)

  assert.deepEqual(sent, [])
  assert.equal(state.ledger.snapshot().next_action_sequence, 2)
})

test('an ambiguous mutation is not retried when a safe read proves rollback is required', async (t) => {
  const state = await campaign(t, 'mutation-ambiguous-observed')
  const calls = []
  const transport = async (request) => {
    calls.push(request.phase)
    await request.beforeSend()
    if (request.phase === 'MUTATION') {
      const error = new Error('mutation response was lost')
      error.request_may_have_been_sent = true
      throw error
    }
    return { status: 200, responseBytes: 1, responseHeaderNames: [] }
  }

  const result = await runDeclaredHttpAuthedMutation(runOptions(state, { transport }))

  assert.equal(calls.filter((phase) => phase === 'MUTATION').length, 1)
  assert.equal(calls.filter((phase) => phase === 'AFTER_READ').length, 1)
  assert.equal(calls.filter((phase) => phase === 'ROLLBACK').length, 1)
  assert.equal(calls.filter((phase) => phase === 'ROLLBACK_VERIFY').length, 1)
  assert.equal(result.outcome, 'ROLLBACK_VERIFIED_AFTER_FAILURE')
})

test('after-state mismatch still performs one rollback and records verified cleanup', async (t) => {
  const state = await campaign(t, 'after-mismatch')
  const calls = []
  const result = await runDeclaredHttpAuthedMutation(runOptions(state, {
    transport: successfulTransport(calls),
    verifyObservation: observationVerifier({
      AFTER_READ: { valueMatch: false, contextMatch: false },
    }),
  }))

  assert.equal(calls.filter(({ phase }) => phase === 'MUTATION').length, 1)
  assert.equal(calls.filter(({ phase }) => phase === 'ROLLBACK').length, 1)
  assert.equal(result.outcome, 'ROLLBACK_VERIFIED_AFTER_FAILURE')
  assert.equal(result.verification.after, false)
  assert.equal(result.verification.rollback, true)
})

test('an ambiguous rollback is attempted once and requires manual intervention', async (t) => {
  const state = await campaign(t, 'rollback-ambiguous')
  const calls = []
  const transport = async (request) => {
    calls.push(request.phase)
    await request.beforeSend()
    if (request.phase === 'ROLLBACK') {
      const error = new Error(`rollback failed ${SECRET_HEADER}`)
      error.request_may_have_been_sent = true
      throw error
    }
    return { status: 200, responseBytes: 1, responseHeaderNames: [] }
  }

  const result = await runDeclaredHttpAuthedMutation(runOptions(state, {
    transport,
    verifyObservation: observationVerifier({
      ROLLBACK_VERIFY: { valueMatch: false, contextMatch: false },
    }),
  }))

  assert.equal(calls.filter((phase) => phase === 'MUTATION').length, 1)
  assert.equal(calls.filter((phase) => phase === 'ROLLBACK').length, 1)
  assert.equal(calls.filter((phase) => phase === 'ROLLBACK_VERIFY').length, 1)
  assert.equal(result.outcome, 'MANUAL_INTERVENTION_REQUIRED')
  assert.doesNotMatch(JSON.stringify(result), new RegExp(SECRET_HEADER))
})

test('an ambiguous rollback is not retried when a safe read verifies restored state', async (t) => {
  const state = await campaign(t, 'rollback-ambiguous-verified')
  const calls = []
  const transport = async (request) => {
    calls.push(request.phase)
    await request.beforeSend()
    if (request.phase === 'ROLLBACK') {
      const error = new Error('rollback response was lost')
      error.request_may_have_been_sent = true
      throw error
    }
    return { status: 200, responseBytes: 1, responseHeaderNames: [] }
  }

  const result = await runDeclaredHttpAuthedMutation(runOptions(state, { transport }))

  assert.equal(calls.filter((phase) => phase === 'ROLLBACK').length, 1)
  assert.equal(calls.filter((phase) => phase === 'ROLLBACK_VERIFY').length, 1)
  assert.equal(result.outcome, 'ROLLBACK_VERIFIED_AFTER_FAILURE')
  assert.equal(result.verification.rollback, true)
})
