import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import { openHttpAuthedCampaignLedger } from '../scripts/lib/http-authed-campaign-ledger.mjs'
import { runHttpAuthedCampaign } from '../scripts/lib/http-authed-campaign-controller.mjs'
import { runDeclaredHttpAuthedMutation } from '../scripts/lib/http-authed-mutation-controller.mjs'
import {
  sha256Hex,
  verifyHttpAuthedWrittenAuthorization,
} from '../scripts/lib/http-authed-contracts.mjs'
import {
  AUTHORIZATION_DOCUMENT,
  writtenScope,
} from './helpers/http-authed-fixtures.mjs'

const NOW = new Date('2026-08-16T12:00:00.000Z')
const CREDENTIAL = Buffer.from('synthetic-campaign-credential')
const MUTATION_BODY = Buffer.alloc(64, 0x61)
const ROLLBACK_BODY = Buffer.alloc(64, 0x62)

function campaignScope() {
  const scope = writtenScope({ actionCount: 1 })
  scope.limits.min_interval_ms = 0
  const origin = scope.target.origin
  scope.authorization.authorized_scope.path_prefixes = ['/approved']
  scope.liveness.credential_preflight.url = `${origin}/approved/whoami`
  scope.requests = [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'GET',
    url: `${origin}/approved/node-0`,
    expected_effect: 'none',
  }]
  scope.discovery = {
    enabled: true,
    origin,
    path_prefixes: ['/approved'],
    sources: ['location_header'],
    candidate_methods: ['GET'],
    test_category: 'api_security',
    synthetic_query_values: {},
    synthetic_path_values: {},
    max_response_bytes: scope.limits.max_response_bytes,
  }
  return scope
}

test('campaign durably drains discovered probes beyond the old 64-action gate and replays none', async (t) => {
  const scope = campaignScope()
  const verified = verifyHttpAuthedWrittenAuthorization({
    scope,
    documentBytes: AUTHORIZATION_DOCUMENT,
    now: NOW,
  })
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-campaign-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const ledgerDirectory = join(root, 'ledger')
  let sends = 0
  const seenSequences = []
  const executeProbe = async ({ action, beforeSend }) => {
    await beforeSend()
    sends += 1
    seenSequences.push(action.sequence)
    const current = Number(/node-(\d+)$/.exec(new URL(action.url).pathname)?.[1])
    return {
      response: { status: 200, bytes: 0, header_names: ['location'] },
      discoveryInput: {
        headers: current < 70
          ? [{ name: 'location', value: `/approved/node-${current + 1}` }]
          : [],
        bodyChunks: [],
      },
    }
  }

  const ledger = await openHttpAuthedCampaignLedger({
    directory: ledgerDirectory,
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationDocumentSha256: sha256Hex(AUTHORIZATION_DOCUMENT),
    operatorId: scope.authorization.operator_id,
    initialize: true,
    now: () => NOW,
  })
  const result = await runHttpAuthedCampaign({
    scope,
    documentBytes: AUTHORIZATION_DOCUMENT,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    authorizationConfirmed: true,
    ledger,
    now: () => NOW,
    reauthorize: async ({ action }) => verifyHttpAuthedWrittenAuthorization({
      scope,
      documentBytes: AUTHORIZATION_DOCUMENT,
      now: NOW,
    }) && action,
    executeProbe,
  })
  await ledger.close()

  assert.equal(sends, 71)
  assert.equal(result.actions.completed, 71)
  assert.equal(result.actions.discovered, 70)
  assert.deepEqual(seenSequences, Array.from({ length: 71 }, (_, index) => index + 1))
  assert.doesNotMatch(JSON.stringify(result), /peerstar-test|approved|node-/i)

  const reopened = await openHttpAuthedCampaignLedger({
    directory: ledgerDirectory,
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationDocumentSha256: sha256Hex(AUTHORIZATION_DOCUMENT),
    operatorId: scope.authorization.operator_id,
    now: () => NOW,
  })
  const replay = await runHttpAuthedCampaign({
    scope,
    documentBytes: AUTHORIZATION_DOCUMENT,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    authorizationConfirmed: true,
    ledger: reopened,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe,
  })
  await reopened.close()
  assert.equal(sends, 71)
  assert.equal(replay.actions.completed, 0)
  assert.equal(replay.actions.already_terminal, 1)
})

test('an ambiguous probe delivery stops the campaign before the next action', async (t) => {
  const scope = campaignScope()
  delete scope.discovery
  scope.requests.push({
    ...scope.requests[0],
    sequence: 2,
    url: `${scope.target.origin}/approved/node-1`,
  })
  const verified = verifyHttpAuthedWrittenAuthorization({
    scope,
    documentBytes: AUTHORIZATION_DOCUMENT,
    now: NOW,
  })
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-probe-uncertain-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const ledger = await openHttpAuthedCampaignLedger({
    directory: join(root, 'ledger'),
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationDocumentSha256: verified.authorizationDocumentSha256,
    operatorId: scope.authorization.operator_id,
    initialize: true,
    now: () => NOW,
  })
  let sends = 0
  const result = await runHttpAuthedCampaign({
    scope,
    documentBytes: AUTHORIZATION_DOCUMENT,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    authorizationConfirmed: true,
    ledger,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe: async ({ beforeSend }) => {
      await beforeSend()
      sends += 1
      const error = new Error('synthetic delivery boundary loss')
      error.request_may_have_been_sent = true
      throw error
    },
  })
  const snapshot = ledger.snapshot()
  await ledger.close()

  assert.equal(sends, 1)
  assert.equal(result.actions.uncertain, 1)
  assert.equal(snapshot.stopped, true)
  assert.equal(snapshot.queued_actions, 1)
})

test('settled JSON-shape observation failure terminalizes once and continues independent probes', async (t) => {
  const scope = campaignScope()
  delete scope.discovery
  scope.schema_version = '1.2.0'
  scope.response_observation = {
    mode: 'ASPNET_D_JSON_SHAPE_ONLY',
    max_depth: 4,
    safe_key_names: ['records'],
  }
  scope.requests.push({
    ...scope.requests[0],
    sequence: 2,
    url: `${scope.target.origin}/approved/node-1`,
  })
  const verified = verifyHttpAuthedWrittenAuthorization({
    scope,
    documentBytes: AUTHORIZATION_DOCUMENT,
    now: NOW,
  })
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-observation-failed-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const ledgerDirectory = join(root, 'ledger')
  const ledger = await openHttpAuthedCampaignLedger({
    directory: ledgerDirectory,
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationDocumentSha256: verified.authorizationDocumentSha256,
    operatorId: scope.authorization.operator_id,
    initialize: true,
    now: () => NOW,
  })
  let sends = 0
  const executeProbe = async ({ beforeSend }) => {
    await beforeSend()
    sends += 1
    return sends === 1
      ? {
          response: {
            status: 500,
            header_names: ['content-type', 'x-synthetic-subject-8675309'],
            response_byte_bucket: 'LE_4_KIB',
            failure_stage_code: 'JSON_SHAPE_OBSERVATION',
          },
        }
      : { response: { status: 204, bytes: 0, header_names: [] } }
  }
  const result = await runHttpAuthedCampaign({
    scope,
    documentBytes: AUTHORIZATION_DOCUMENT,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    authorizationConfirmed: true,
    ledger,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe,
  })
  const snapshot = ledger.snapshot()
  await ledger.close()

  assert.equal(sends, 2)
  assert.equal(result.schema_version, '1.3.0')
  assert.deepEqual(result.actions, {
    completed: 1,
    discovered: 0,
    duplicates: 0,
    rejected: 0,
    failed: 1,
    uncertain: 0,
    already_terminal: 0,
  })
  assert.equal(snapshot.stopped, false)
  assert.equal(snapshot.queued_actions, 0)
  assert.equal(snapshot.terminal_actions, 2)
  assert.deepEqual(result.observation_failures, [{
    action_sequence: 1,
    method: 'GET',
    status: 500,
    header_names: ['content-type', 'other'],
    response_byte_bucket: 'LE_4_KIB',
    failure_stage_code: 'JSON_SHAPE_OBSERVATION',
  }])
  const rendered = JSON.stringify(result)
  assert.doesNotMatch(rendered, /8675309|exact_bytes|cause|error_text/i)

  const reopened = await openHttpAuthedCampaignLedger({
    directory: ledgerDirectory,
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationDocumentSha256: verified.authorizationDocumentSha256,
    operatorId: scope.authorization.operator_id,
    now: () => NOW,
  })
  const replay = await runHttpAuthedCampaign({
    scope,
    documentBytes: AUTHORIZATION_DOCUMENT,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    authorizationConfirmed: true,
    ledger: reopened,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe,
  })
  await reopened.close()
  assert.equal(sends, 2)
  assert.equal(replay.actions.already_terminal, 2)
  assert.equal(replay.observation_failures, undefined)
})

test('campaign executes a declared mutation through its existing durable lease', async (t) => {
  const scope = writtenScope({ actionCount: 1 })
  scope.limits.min_interval_ms = 0
  scope.credential.binding_sha256 = sha256Hex(CREDENTIAL)
  scope.requests[0].request_body.sha256 = sha256Hex(MUTATION_BODY)
  scope.requests[0].rollback.request_body.sha256 = sha256Hex(ROLLBACK_BODY)
  const verified = verifyHttpAuthedWrittenAuthorization({
    scope,
    documentBytes: AUTHORIZATION_DOCUMENT,
    now: NOW,
  })
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-campaign-mutate-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const ledger = await openHttpAuthedCampaignLedger({
    directory: join(root, 'ledger'),
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationDocumentSha256: verified.authorizationDocumentSha256,
    operatorId: scope.authorization.operator_id,
    initialize: true,
    now: () => NOW,
  })
  const phases = []
  const result = await runHttpAuthedCampaign({
    scope,
    documentBytes: AUTHORIZATION_DOCUMENT,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    authorizationConfirmed: true,
    ledger,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe: async () => { throw new Error('probe executor must not run') },
    executeMutation: ({ action, lease }) => runDeclaredHttpAuthedMutation({
      ledger,
      scope,
      action,
      existingLease: lease,
      documentBytes: AUTHORIZATION_DOCUMENT,
      expectedCampaignGrantSha256: verified.campaignGrantSha256,
      operatorId: scope.authorization.operator_id,
      countersignature: {
        nonce: 'synthetic-campaign-mutation-nonce-0001',
        at: NOW.toISOString(),
      },
      credentialValue: CREDENTIAL,
      requestBodyBytes: MUTATION_BODY,
      rollbackBodyBytes: ROLLBACK_BODY,
      now: () => NOW,
      verifyCountersignature: async () => ({ keyId: scope.approver.key_id }),
      verifyObservation: async ({ phase }) => ({
        valueMatch: true,
        contextMatch: true,
        ...(phase === 'BEFORE_READ' ? { contextToken: 'TRANSIENT_CONTEXT' } : {}),
      }),
      transport: async (request) => {
        phases.push(request.phase)
        await request.beforeSend()
        return {
          status: request.phase === 'MUTATION' ? 201 : 200,
          responseBytes: 0,
          responseHeaderNames: ['content-type'],
          body: Buffer.from('{}'),
        }
      },
    }),
  })
  await ledger.close()

  assert.deepEqual(phases, [
    'CREDENTIAL_PREFLIGHT', 'BEFORE_READ', 'MUTATION', 'AFTER_READ',
    'ROLLBACK', 'ROLLBACK_VERIFY',
  ])
  assert.equal(result.actions.completed, 1)
  assert.equal(result.actions.failed, 0)
  assert.equal(result.ledger.terminal_actions, 1)
  assert.doesNotMatch(JSON.stringify(result), /security-test-resource|credential|nonce/i)
})

test('a failed mutation cleanup durably stops the campaign before the next action', async (t) => {
  const scope = writtenScope({ actionCount: 2 })
  scope.limits.min_interval_ms = 0
  const verified = verifyHttpAuthedWrittenAuthorization({
    scope,
    documentBytes: AUTHORIZATION_DOCUMENT,
    now: NOW,
  })
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-campaign-stop-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const ledger = await openHttpAuthedCampaignLedger({
    directory: join(root, 'ledger'),
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationDocumentSha256: verified.authorizationDocumentSha256,
    operatorId: scope.authorization.operator_id,
    initialize: true,
    now: () => NOW,
  })
  let mutationCalls = 0
  const result = await runHttpAuthedCampaign({
    scope,
    documentBytes: AUTHORIZATION_DOCUMENT,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    authorizationConfirmed: true,
    ledger,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe: async () => { throw new Error('probe executor must not run') },
    executeMutation: async ({ lease }) => {
      mutationCalls += 1
      await ledger.terminalizeAction({
        actionId: lease.actionId,
        leaseId: lease.leaseId,
        outcome: 'MANUAL_INTERVENTION_REQUIRED',
        reasonCode: 'ROLLBACK_VERIFICATION_MISMATCH',
      })
      return { outcome: 'MANUAL_INTERVENTION_REQUIRED' }
    },
  })
  const snapshot = ledger.snapshot()
  await ledger.close()

  assert.equal(mutationCalls, 1)
  assert.equal(result.actions.uncertain, 1)
  assert.equal(snapshot.stopped, true)
  assert.equal(snapshot.queued_actions, 1)
})
