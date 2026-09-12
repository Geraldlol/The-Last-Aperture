import assert from 'node:assert/strict'
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import {
  openHttpAuthedCampaignLedger,
  readHttpAuthedCampaignProjection,
  requestHttpAuthedCampaignStop,
} from '../scripts/lib/http-authed-campaign-ledger.mjs'
import { runHttpAuthedCampaign } from '../scripts/lib/http-authed-campaign-controller.mjs'
import {
  recoverDeclaredHttpAuthedMutation,
  runDeclaredHttpAuthedMutation,
} from '../scripts/lib/http-authed-mutation-controller.mjs'
import {
  sha256Hex,
  verifyHttpAuthedAuthorization,
} from '../scripts/lib/http-authed-contracts.mjs'
import {
  attestedScope,
} from './helpers/http-authed-fixtures.mjs'

const NOW = new Date('2026-08-16T12:00:00.000Z')
const CREDENTIAL = Buffer.from('synthetic-campaign-credential')
const MUTATION_BODY = Buffer.alloc(64, 0x61)
const ROLLBACK_BODY = Buffer.alloc(64, 0x62)

function campaignScope() {
  const scope = attestedScope({ actionCount: 1 })
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

test('campaign uses sealed authority without repeat authorization and replays no completed probes', async (t) => {
  const scope = campaignScope()
  const verified = verifyHttpAuthedAuthorization({
    scope,
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
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
    operatorId: scope.authorization.operator_id,
    initialize: true,
    now: () => NOW,
  })
  const result = await runHttpAuthedCampaign({
    scope,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    ledger,
    now: () => NOW,
    reauthorize: async ({ action }) => verifyHttpAuthedAuthorization({
      scope,
      now: NOW,
    }) && action,
    executeProbe,
  })
  await ledger.close()

  assert.equal(sends, 71)
  assert.equal(result.actions.completed, 71)
  assert.equal(result.actions.discovered, 70)
  assert.deepEqual(seenSequences, Array.from({ length: 71 }, (_, index) => index + 1))
  assert.doesNotMatch(JSON.stringify(result), /app\.example\.test|approved|node-/i)

  const reopened = await openHttpAuthedCampaignLedger({
    directory: ledgerDirectory,
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
    operatorId: scope.authorization.operator_id,
    now: () => NOW,
  })
  const replay = await runHttpAuthedCampaign({
    scope,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
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

test('campaign minimum interval survives ledger close and reopen', async (t) => {
  const scope = campaignScope()
  delete scope.discovery
  scope.limits.min_interval_ms = 1_000
  scope.requests.push({
    ...scope.requests[0],
    sequence: 2,
    url: `${scope.target.origin}/approved/node-1`,
  })
  const verified = verifyHttpAuthedAuthorization({ scope, now: NOW })
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-rate-reopen-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const ledgerDirectory = join(root, 'ledger')
  const open = (initialize = false) => openHttpAuthedCampaignLedger({
    directory: ledgerDirectory,
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
    operatorId: scope.authorization.operator_id,
    initialize,
    now: () => NOW,
  })
  const first = await open(true)
  let sends = 0
  await assert.rejects(runHttpAuthedCampaign({
    scope,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    ledger: first,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe: async ({ beforeSend }) => {
      await beforeSend()
      sends += 1
      return { response: { status: 200, bytes: 0, header_names: [] } }
    },
    wait: async () => { throw new Error('synthetic process interruption during rate wait') },
  }), /synthetic process interruption/)
  await first.close()
  assert.equal(sends, 1)

  const reopened = await open()
  const waits = []
  await runHttpAuthedCampaign({
    scope,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    ledger: reopened,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe: async ({ beforeSend }) => {
      await beforeSend()
      sends += 1
      return { response: { status: 200, bytes: 0, header_names: [] } }
    },
    wait: async (milliseconds) => { waits.push(milliseconds) },
  })
  await reopened.close()
  assert.equal(sends, 2)
  assert.deepEqual(waits, [1_000])
})

test('campaign follows an accepted same-origin Location from a settled redirect', async (t) => {
  const scope = campaignScope()
  scope.limits.max_actions = 4
  const verified = verifyHttpAuthedAuthorization({ scope, now: NOW })
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-redirect-discovery-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const ledgerDirectory = join(root, 'ledger')
  const ledger = await openHttpAuthedCampaignLedger({
    directory: ledgerDirectory,
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
    operatorId: scope.authorization.operator_id,
    initialize: true,
    now: () => NOW,
  })
  const paths = []
  const result = await runHttpAuthedCampaign({
    scope,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    ledger,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe: async ({ action, beforeSend }) => {
      await beforeSend()
      const path = new URL(action.url).pathname
      paths.push(path)
      return path.endsWith('node-0')
        ? {
            response: { status: 302, bytes: 0, header_names: ['location'] },
            discoveryInput: {
              headers: [{ name: 'location', value: '/approved/node-1' }],
              bodyChunks: [],
            },
          }
        : { response: { status: 200, bytes: 0, header_names: [] }, discoveryInput: { headers: [], bodyChunks: [] } }
    },
  })
  const snapshot = ledger.snapshot()
  await ledger.close()

  assert.deepEqual(paths, ['/approved/node-0', '/approved/node-1'])
  assert.equal(result.actions.completed, 2)
  assert.equal(result.actions.discovered, 1)
  assert.equal(snapshot.stopped, false)

  const reopened = await openHttpAuthedCampaignLedger({
    directory: ledgerDirectory,
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
    operatorId: scope.authorization.operator_id,
    now: () => NOW,
  })
  const replay = await runHttpAuthedCampaign({
    scope,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    ledger: reopened,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe: async () => { throw new Error('terminal redirect chain must not replay') },
  })
  assert.equal(reopened.snapshot().stopped, false)
  assert.equal(replay.actions.completed, 0)
  await reopened.close()
})

test('a failed redirect disposition cannot rewrite a settled request as failed before send', async (t) => {
  const scope = campaignScope()
  scope.limits.max_actions = 2
  const verified = verifyHttpAuthedAuthorization({ scope, now: NOW })
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-redirect-disposition-failure-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const ledgerDirectory = join(root, 'ledger')
  const ledgerOptions = {
    directory: ledgerDirectory,
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
    operatorId: scope.authorization.operator_id,
    now: () => NOW,
  }
  const ledger = await openHttpAuthedCampaignLedger({ ...ledgerOptions, initialize: true })
  ledger.recordHandledResponseStop = async () => {
    throw new Error('synthetic response-stop disposition persistence failure')
  }
  let sends = 0
  const result = await runHttpAuthedCampaign({
    scope,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    ledger,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe: async ({ beforeSend }) => {
      await beforeSend()
      sends += 1
      return {
        response: { status: 302, bytes: 0, header_names: ['location'] },
        discoveryInput: {
          headers: [{ name: 'location', value: '/approved/node-1' }],
          bodyChunks: [],
        },
      }
    },
  })
  assert.equal(sends, 1)
  assert.equal(result.actions.completed, 1)
  assert.equal(result.actions.failed, 0)
  assert.equal(ledger.snapshot().stopped, true)
  assert.equal(ledger.snapshot().stop_reason, 'UNEXPECTED_REDIRECT')
  await ledger.close()

  const projection = await readHttpAuthedCampaignProjection(ledgerOptions)
  const reopened = await openHttpAuthedCampaignLedger(ledgerOptions)
  assert.equal(projection.actions[0].phase_outcomes.PROBE.status, 302)
  assert.equal(projection.actions[0].outcome, 'PROBE_COMPLETED')
  assert.notEqual(projection.actions[0].outcome, 'FAILED_BEFORE_SEND')
  assert.equal(projection.actions[1].outcome, 'CAMPAIGN_STOPPED')
  assert.equal(projection.stopped, true)
  assert.equal(projection.stop_reason, 'UNEXPECTED_REDIRECT')
  assert.equal(
    reopened.actionState(projection.actions[0].action_id).outcome,
    projection.actions[0].outcome,
  )
  assert.equal(
    reopened.actionState(projection.actions[1].action_id).outcome,
    projection.actions[1].outcome,
  )
  await reopened.close()
})

test('a discovered append that throws after durability is terminal in both live and reopened state', async (t) => {
  const scope = campaignScope()
  scope.limits.max_actions = 2
  const verified = verifyHttpAuthedAuthorization({ scope, now: NOW })
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-durable-discovery-failure-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const ledgerDirectory = join(root, 'ledger')
  const ledgerOptions = {
    directory: ledgerDirectory,
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
    operatorId: scope.authorization.operator_id,
    now: () => NOW,
  }
  const ledger = await openHttpAuthedCampaignLedger({ ...ledgerOptions, initialize: true })
  const enqueueCandidate = ledger.enqueueCandidate.bind(ledger)
  ledger.enqueueCandidate = async (options) => {
    const result = await enqueueCandidate(options)
    if (options.provenance === 'DISCOVERED') {
      throw new Error('synthetic failure after durable discovered append')
    }
    return result
  }
  let sends = 0
  await runHttpAuthedCampaign({
    scope,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    ledger,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe: async ({ beforeSend }) => {
      await beforeSend()
      sends += 1
      return {
        response: { status: 302, bytes: 0, header_names: ['location'] },
        discoveryInput: {
          headers: [{ name: 'location', value: '/approved/node-1' }],
          bodyChunks: [],
        },
      }
    },
  })
  assert.equal(sends, 1)
  assert.equal(ledger.snapshot().queued_actions, 0)
  assert.equal(ledger.snapshot().terminal_actions, 2)
  await ledger.close()

  const projection = await readHttpAuthedCampaignProjection(ledgerOptions)
  assert.equal(projection.actions.length, 2)
  assert.equal(projection.actions[0].outcome, 'PROBE_COMPLETED')
  assert.equal(projection.actions[1].outcome, 'CAMPAIGN_STOPPED')
  assert.equal(
    projection.actions[1].terminal_reason_code,
    'POST_SETTLEMENT_PROCESSING_FAILED',
  )
  const reopened = await openHttpAuthedCampaignLedger(ledgerOptions)
  assert.equal(reopened.snapshot().queued_actions, 0)
  assert.equal(reopened.snapshot().terminal_actions, 2)
  await reopened.close()
})

test('redirect continuation survives an unrelated candidate exhausting the total action budget', async (t) => {
  const scope = campaignScope()
  scope.limits.max_actions = 2
  scope.discovery.sources = ['link_header', 'location_header']
  const verified = verifyHttpAuthedAuthorization({ scope, now: NOW })
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-redirect-mixed-budget-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const ledger = await openHttpAuthedCampaignLedger({
    directory: join(root, 'ledger'),
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
    operatorId: scope.authorization.operator_id,
    initialize: true,
    now: () => NOW,
  })
  const paths = []
  const result = await runHttpAuthedCampaign({
    scope,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    ledger,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe: async ({ action, beforeSend }) => {
      await beforeSend()
      const path = new URL(action.url).pathname
      paths.push(path)
      return path.endsWith('node-0')
        ? {
            response: { status: 302, bytes: 0, header_names: ['link', 'location'] },
            discoveryInput: {
              headers: [
                { name: 'location', value: '/approved/node-1' },
                { name: 'link', value: '</approved/unrelated>; rel="next"' },
              ],
              bodyChunks: [],
            },
          }
        : { response: { status: 200, bytes: 0, header_names: [] }, discoveryInput: { headers: [], bodyChunks: [] } }
    },
  })
  const snapshot = ledger.snapshot()
  await ledger.close()

  assert.deepEqual(paths, ['/approved/node-0', '/approved/node-1'])
  assert.equal(result.actions.completed, 2)
  assert.equal(result.actions.discovered, 1)
  assert.equal(result.actions.rejected, 1)
  assert.equal(snapshot.stopped, false)
})

test('a Location rejected by the per-response candidate budget stops as LIMIT_REACHED', async (t) => {
  const scope = campaignScope()
  scope.limits.max_actions = 3
  scope.discovery.sources = ['link_header', 'location_header']
  scope.discovery.max_candidates = 1
  const verified = verifyHttpAuthedAuthorization({ scope, now: NOW })
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-redirect-candidate-budget-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const ledger = await openHttpAuthedCampaignLedger({
    directory: join(root, 'ledger'),
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
    operatorId: scope.authorization.operator_id,
    initialize: true,
    now: () => NOW,
  })
  const paths = []
  const result = await runHttpAuthedCampaign({
    scope,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    ledger,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe: async ({ action, beforeSend }) => {
      await beforeSend()
      paths.push(new URL(action.url).pathname)
      return {
        response: { status: 302, bytes: 0, header_names: ['link', 'location'] },
        discoveryInput: {
          headers: [
            { name: 'link', value: '</approved/unrelated>; rel="next"' },
            { name: 'location', value: '/approved/redirect' },
          ],
          bodyChunks: [],
        },
      }
    },
  })
  const snapshot = ledger.snapshot()
  await ledger.close()

  assert.deepEqual(paths, ['/approved/node-0'])
  assert.equal(result.actions.completed, 1)
  assert.equal(result.actions.discovered, 1)
  assert.equal(result.actions.rejected, 1)
  assert.equal(snapshot.stopped, true)
  assert.equal(snapshot.stop_reason, 'LIMIT_REACHED')
})

test('a Location deduplicated against a Link remains a live redirect continuation', async (t) => {
  const scope = campaignScope()
  scope.limits.max_actions = 3
  scope.discovery.sources = ['link_header', 'location_header']
  const verified = verifyHttpAuthedAuthorization({ scope, now: NOW })
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-redirect-local-dedup-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const ledger = await openHttpAuthedCampaignLedger({
    directory: join(root, 'ledger'),
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
    operatorId: scope.authorization.operator_id,
    initialize: true,
    now: () => NOW,
  })
  const paths = []
  const result = await runHttpAuthedCampaign({
    scope,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    ledger,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe: async ({ action, beforeSend }) => {
      await beforeSend()
      const path = new URL(action.url).pathname
      paths.push(path)
      return path.endsWith('node-0')
        ? {
            response: { status: 302, bytes: 0, header_names: ['link', 'location'] },
            discoveryInput: {
              headers: [
                { name: 'link', value: '</approved/node-1>; rel="next"' },
                { name: 'location', value: '/approved/node-1' },
              ],
              bodyChunks: [],
            },
          }
        : { response: { status: 200, bytes: 0, header_names: [] }, discoveryInput: { headers: [], bodyChunks: [] } }
    },
  })
  const snapshot = ledger.snapshot()
  await ledger.close()

  assert.deepEqual(paths, ['/approved/node-0', '/approved/node-1'])
  assert.equal(result.actions.completed, 2)
  assert.equal(result.actions.discovered, 1)
  assert.equal(result.actions.duplicates, 1)
  assert.equal(snapshot.stopped, false)
})

test('a Location already queued by the sealed plan remains live at the total action budget', async (t) => {
  const scope = campaignScope()
  scope.requests.push({
    ...scope.requests[0],
    sequence: 2,
    url: `${scope.target.origin}/approved/node-1`,
  })
  scope.limits.max_actions = 2
  const verified = verifyHttpAuthedAuthorization({ scope, now: NOW })
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-redirect-queued-budget-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const ledger = await openHttpAuthedCampaignLedger({
    directory: join(root, 'ledger'),
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
    operatorId: scope.authorization.operator_id,
    initialize: true,
    now: () => NOW,
  })
  const paths = []
  const result = await runHttpAuthedCampaign({
    scope,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    ledger,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe: async ({ action, beforeSend }) => {
      await beforeSend()
      const path = new URL(action.url).pathname
      paths.push(path)
      return path.endsWith('node-0')
        ? {
            response: { status: 302, bytes: 0, header_names: ['location'] },
            discoveryInput: {
              headers: [{ name: 'location', value: '/approved/node-1' }],
              bodyChunks: [],
            },
          }
        : { response: { status: 200, bytes: 0, header_names: [] }, discoveryInput: { headers: [], bodyChunks: [] } }
    },
  })
  const snapshot = ledger.snapshot()
  await ledger.close()

  assert.deepEqual(paths, ['/approved/node-0', '/approved/node-1'])
  assert.equal(result.actions.completed, 2)
  assert.equal(result.actions.discovered, 0)
  assert.equal(result.actions.duplicates, 1)
  assert.equal(result.actions.rejected, 0)
  assert.equal(snapshot.stopped, false)
})

test('same-open resume reuses a durable private discovered candidate at the total action budget', async (t) => {
  const scope = campaignScope()
  scope.limits.max_actions = 2
  const verified = verifyHttpAuthedAuthorization({ scope, now: NOW })
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-redirect-resume-budget-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const ledger = await openHttpAuthedCampaignLedger({
    directory: join(root, 'ledger'),
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
    operatorId: scope.authorization.operator_id,
    initialize: true,
    now: () => NOW,
  })
  await ledger.enqueueCandidate({
    candidateDraft: {
      kind: 'probe',
      test_category: 'api_security',
      method: 'GET',
      url: `${scope.target.origin}/approved/node-1`,
      expected_effect: 'none',
    },
    provenance: 'DISCOVERED',
  })
  const paths = []
  const result = await runHttpAuthedCampaign({
    scope,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    ledger,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe: async ({ action, beforeSend }) => {
      await beforeSend()
      const path = new URL(action.url).pathname
      paths.push(path)
      return path.endsWith('node-0')
        ? {
            response: { status: 302, bytes: 0, header_names: ['location'] },
            discoveryInput: {
              headers: [{ name: 'location', value: '/approved/node-1' }],
              bodyChunks: [],
            },
          }
        : { response: { status: 200, bytes: 0, header_names: [] }, discoveryInput: { headers: [], bodyChunks: [] } }
    },
  })
  const snapshot = ledger.snapshot()
  await ledger.close()

  assert.deepEqual(paths, ['/approved/node-0', '/approved/node-1'])
  assert.equal(result.actions.completed, 2)
  assert.equal(result.actions.discovered, 0)
  assert.equal(result.actions.duplicates, 1)
  assert.equal(result.actions.rejected, 0)
  assert.equal(snapshot.next_action_sequence, 3)
  assert.equal(snapshot.stopped, false)
})

test('redirect cycle through a terminal candidate preserves the unexpected redirect stop', async (t) => {
  const scope = campaignScope()
  scope.limits.max_actions = 4
  const verified = verifyHttpAuthedAuthorization({ scope, now: NOW })
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-redirect-cycle-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const ledger = await openHttpAuthedCampaignLedger({
    directory: join(root, 'ledger'),
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
    operatorId: scope.authorization.operator_id,
    initialize: true,
    now: () => NOW,
  })
  const paths = []
  const result = await runHttpAuthedCampaign({
    scope,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    ledger,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe: async ({ action, beforeSend }) => {
      await beforeSend()
      const path = new URL(action.url).pathname
      paths.push(path)
      return {
        response: { status: 302, bytes: 0, header_names: ['location'] },
        discoveryInput: {
          headers: [{
            name: 'location',
            value: path.endsWith('node-0') ? '/approved/node-1' : '/approved/node-0',
          }],
          bodyChunks: [],
        },
      }
    },
  })
  const snapshot = ledger.snapshot()
  await ledger.close()

  assert.deepEqual(paths, ['/approved/node-0', '/approved/node-1'])
  assert.equal(result.actions.completed, 2)
  assert.equal(result.actions.duplicates, 1)
  assert.equal(result.actions.already_terminal, 1)
  assert.equal(snapshot.stopped, true)
  assert.equal(snapshot.stop_reason, 'UNEXPECTED_REDIRECT')
})

test('campaign stops at the sealed discovery depth without dispatching beyond it', async (t) => {
  const scope = campaignScope()
  scope.limits.max_actions = 10
  scope.discovery.max_depth = 1
  const verified = verifyHttpAuthedAuthorization({ scope, now: NOW })
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-depth-budget-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const ledger = await openHttpAuthedCampaignLedger({
    directory: join(root, 'ledger'),
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
    operatorId: scope.authorization.operator_id,
    initialize: true,
    now: () => NOW,
  })
  let sends = 0
  const result = await runHttpAuthedCampaign({
    scope,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    ledger,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe: async ({ action, beforeSend }) => {
      await beforeSend()
      sends += 1
      const current = Number(/node-(\d+)$/.exec(new URL(action.url).pathname)?.[1])
      return {
        response: { status: 302, bytes: 0, header_names: ['location'] },
        discoveryInput: {
          headers: [{ name: 'location', value: `/approved/node-${current + 1}` }],
          bodyChunks: [],
        },
      }
    },
  })
  const snapshot = ledger.snapshot()
  await ledger.close()

  assert.equal(sends, 2)
  assert.equal(result.actions.discovered, 1)
  assert.equal(result.actions.rejected, 1)
  assert.equal(snapshot.stop_reason, 'LIMIT_REACHED')
})

test('campaign stops at the sealed total action budget', async (t) => {
  const scope = campaignScope()
  scope.limits.max_actions = 2
  const verified = verifyHttpAuthedAuthorization({ scope, now: NOW })
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-action-budget-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const ledger = await openHttpAuthedCampaignLedger({
    directory: join(root, 'ledger'),
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
    operatorId: scope.authorization.operator_id,
    initialize: true,
    now: () => NOW,
  })
  let sends = 0
  const result = await runHttpAuthedCampaign({
    scope,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    ledger,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe: async ({ action, beforeSend }) => {
      await beforeSend()
      sends += 1
      const current = Number(/node-(\d+)$/.exec(new URL(action.url).pathname)?.[1])
      return {
        response: { status: 302, bytes: 0, header_names: ['location'] },
        discoveryInput: {
          headers: [{ name: 'location', value: `/approved/node-${current + 1}` }],
          bodyChunks: [],
        },
      }
    },
  })
  const snapshot = ledger.snapshot()
  await ledger.close()

  assert.equal(sends, 2)
  assert.equal(result.actions.discovered, 1)
  assert.equal(result.actions.rejected, 1)
  assert.equal(snapshot.stop_reason, 'LIMIT_REACHED')
})

test('an ambiguous probe delivery stops the campaign before the next action', async (t) => {
  const scope = campaignScope()
  delete scope.discovery
  scope.requests.push({
    ...scope.requests[0],
    sequence: 2,
    url: `${scope.target.origin}/approved/node-1`,
  })
  const verified = verifyHttpAuthedAuthorization({
    scope,
    now: NOW,
  })
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-probe-uncertain-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const ledger = await openHttpAuthedCampaignLedger({
    directory: join(root, 'ledger'),
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
    operatorId: scope.authorization.operator_id,
    initialize: true,
    now: () => NOW,
  })
  let sends = 0
  const result = await runHttpAuthedCampaign({
    scope,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
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

test('a stop committed with probe pre-dispatch is settled before the transport sends', async (t) => {
  const scope = campaignScope()
  delete scope.discovery
  const verified = verifyHttpAuthedAuthorization({
    scope,
    now: NOW,
  })
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-probe-stop-race-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const ledgerDirectory = join(root, 'ledger')
  const ledger = await openHttpAuthedCampaignLedger({
    directory: ledgerDirectory,
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
    operatorId: scope.authorization.operator_id,
    initialize: true,
    now: () => NOW,
  })
  const durablePreDispatch = ledger.markPreDispatch.bind(ledger)
  let actionId
  ledger.markPreDispatch = async (input) => {
    const result = await durablePreDispatch(input)
    actionId = input.actionId
    await requestHttpAuthedCampaignStop({
      directory: ledgerDirectory,
      campaignGrantSha256: verified.campaignGrantSha256,
      operatorId: scope.authorization.operator_id,
      now: () => NOW,
    })
    return result
  }
  let sends = 0

  const result = await runHttpAuthedCampaign({
    scope,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    ledger,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe: async ({ beforeSend }) => {
      await beforeSend()
      sends += 1
      return { response: { status: 204, bytes: 0, header_names: [] } }
    },
  })
  const state = ledger.actionState(actionId)
  const snapshot = ledger.snapshot()
  await ledger.close()

  assert.equal(sends, 0)
  assert.equal(result.actions.failed, 1)
  assert.equal(snapshot.stopped, true)
  assert.equal(snapshot.stop_reason, 'OPERATOR_REQUESTED')
  assert.equal(state.outcome, 'FAILED_BEFORE_SEND')
  assert.equal(state.phase_outcomes.PROBE.outcome, 'FAILED')
  assert.equal(state.phase_outcomes.PROBE.request_may_have_been_sent, false)
})

test('settled JSON-shape observation failure still honors its response stop status', async (t) => {
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
  const verified = verifyHttpAuthedAuthorization({
    scope,
    now: NOW,
  })
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-observation-failed-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const ledgerDirectory = join(root, 'ledger')
  const ledger = await openHttpAuthedCampaignLedger({
    directory: ledgerDirectory,
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
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
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    ledger,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe,
  })
  const snapshot = ledger.snapshot()
  await ledger.close()

  assert.equal(sends, 1)
  assert.equal(result.schema_version, '1.3.0')
  assert.deepEqual(result.actions, {
    completed: 0,
    discovered: 0,
    duplicates: 0,
    rejected: 0,
    failed: 1,
    uncertain: 0,
    already_terminal: 0,
  })
  assert.equal(snapshot.stopped, true)
  assert.equal(snapshot.stop_reason, 'TARGET_HEALTH_DEGRADED')
  assert.equal(snapshot.queued_actions, 1)
  assert.equal(snapshot.terminal_actions, 1)
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
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
    operatorId: scope.authorization.operator_id,
    now: () => NOW,
  })
  const replay = await runHttpAuthedCampaign({
    scope,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    ledger: reopened,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe,
  })
  await reopened.close()
  assert.equal(sends, 1)
  assert.equal(replay.actions.already_terminal, 0)
  assert.equal(replay.observation_failures, undefined)
})

test('recovery after a durable observation-failure stop does not double-count completion', async (t) => {
  const scope = campaignScope()
  delete scope.discovery
  scope.schema_version = '1.2.0'
  scope.response_observation = {
    mode: 'ASPNET_D_JSON_SHAPE_ONLY',
    max_depth: 4,
    safe_key_names: ['records'],
  }
  const verified = verifyHttpAuthedAuthorization({ scope, now: NOW })
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-observation-stop-recovery-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const ledger = await openHttpAuthedCampaignLedger({
    directory: join(root, 'ledger'),
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
    operatorId: scope.authorization.operator_id,
    initialize: true,
    now: () => NOW,
  })
  const durableStopCampaign = ledger.stopCampaign.bind(ledger)
  let injected = false
  ledger.stopCampaign = async (reasonCode) => {
    const result = await durableStopCampaign(reasonCode)
    if (!injected) {
      injected = true
      throw new Error('synthetic failure after durable stop append')
    }
    return result
  }

  const result = await runHttpAuthedCampaign({
    scope,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    ledger,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe: async ({ beforeSend }) => {
      await beforeSend()
      return {
        response: {
          status: 500,
          header_names: ['content-type'],
          response_byte_bucket: 'LE_4_KIB',
          failure_stage_code: 'JSON_SHAPE_OBSERVATION',
        },
      }
    },
  })
  await ledger.close()

  assert.equal(injected, true)
  assert.equal(result.actions.failed, 1)
  assert.equal(result.actions.completed, 0)
})

test('a durably settled observation failure recovers as failed when its append reports late', async (t) => {
  const scope = campaignScope()
  delete scope.discovery
  scope.schema_version = '1.2.0'
  scope.response_observation = {
    mode: 'ASPNET_D_JSON_SHAPE_ONLY',
    max_depth: 4,
    safe_key_names: ['records'],
  }
  const verified = verifyHttpAuthedAuthorization({ scope, now: NOW })
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-observation-settlement-recovery-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const ledger = await openHttpAuthedCampaignLedger({
    directory: join(root, 'ledger'),
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
    operatorId: scope.authorization.operator_id,
    initialize: true,
    now: () => NOW,
  })
  const durableMarkOutcome = ledger.markOutcome.bind(ledger)
  let injected = false
  ledger.markOutcome = async (input) => {
    const result = await durableMarkOutcome(input)
    if (input.phase === 'PROBE' && input.responseMetadata.failureStageCode !== undefined && !injected) {
      injected = true
      throw new Error('synthetic failure after durable observation settlement')
    }
    return result
  }

  const result = await runHttpAuthedCampaign({
    scope,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    ledger,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe: async ({ beforeSend }) => {
      await beforeSend()
      return {
        response: {
          status: 500,
          header_names: ['content-type'],
          response_byte_bucket: 'LE_4_KIB',
          failure_stage_code: 'JSON_SHAPE_OBSERVATION',
        },
      }
    },
  })
  const snapshot = ledger.snapshot()
  await ledger.close()

  assert.equal(injected, true)
  assert.equal(result.actions.failed, 1)
  assert.equal(result.actions.completed, 0)
  assert.equal(result.observation_failures?.length, 1)
  assert.equal(snapshot.stop_reason, 'TARGET_HEALTH_DEGRADED')
})

test('campaign erases discovery response chunks when settlement reports a late failure', async (t) => {
  const scope = campaignScope()
  const verified = verifyHttpAuthedAuthorization({ scope, now: NOW })
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-discovery-erasure-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const ledger = await openHttpAuthedCampaignLedger({
    directory: join(root, 'ledger'),
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
    operatorId: scope.authorization.operator_id,
    initialize: true,
    now: () => NOW,
  })
  const durableMarkOutcome = ledger.markOutcome.bind(ledger)
  let injected = false
  ledger.markOutcome = async (input) => {
    const result = await durableMarkOutcome(input)
    if (input.phase === 'PROBE' && input.outcome === 'SETTLED' && !injected) {
      injected = true
      throw new Error('synthetic failure after durable settlement')
    }
    return result
  }
  const retainedChunk = Buffer.from('transient-discovery-response')

  const result = await runHttpAuthedCampaign({
    scope,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    ledger,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe: async ({ beforeSend }) => {
      await beforeSend()
      return {
        response: { status: 200, bytes: retainedChunk.length, header_names: [] },
        discoveryInput: { headers: [], bodyChunks: [retainedChunk] },
      }
    },
  })
  await ledger.close()

  assert.equal(injected, true)
  assert.equal(result.actions.completed, 1)
  assert.equal(retainedChunk.every((byte) => byte === 0), true)
})

test('campaign executes a declared mutation through its existing durable lease', async (t) => {
  const scope = attestedScope({ actionCount: 1 })
  scope.limits.min_interval_ms = 0
  scope.credential.binding_sha256 = sha256Hex(CREDENTIAL)
  scope.requests[0].request_body.sha256 = sha256Hex(MUTATION_BODY)
  scope.requests[0].rollback.request_body.sha256 = sha256Hex(ROLLBACK_BODY)
  const verified = verifyHttpAuthedAuthorization({
    scope,
    now: NOW,
  })
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-campaign-mutate-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const ledger = await openHttpAuthedCampaignLedger({
    directory: join(root, 'ledger'),
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
    operatorId: scope.authorization.operator_id,
    initialize: true,
    now: () => NOW,
  })
  const phases = []
  const result = await runHttpAuthedCampaign({
    scope,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    ledger,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe: async () => { throw new Error('probe executor must not run') },
    executeMutation: ({ action, lease }) => runDeclaredHttpAuthedMutation({
      ledger,
      scope,
      action,
      existingLease: lease,
      expectedCampaignGrantSha256: verified.campaignGrantSha256,
      operatorId: scope.authorization.operator_id,
      credentialValue: CREDENTIAL,
      requestBodyBytes: MUTATION_BODY,
      rollbackBodyBytes: ROLLBACK_BODY,
      now: () => NOW,
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
  const ledgerRecords = await Promise.all(
    (await readdir(ledger.directory))
      .filter((name) => name.endsWith('.json'))
      .sort()
      .map(async (name) => JSON.parse(await readFile(join(ledger.directory, name), 'utf8'))),
  )
  await ledger.close()

  assert.deepEqual(phases, [
    'CREDENTIAL_PREFLIGHT', 'BEFORE_READ', 'MUTATION', 'AFTER_READ',
    'ROLLBACK', 'ROLLBACK_VERIFY',
  ])
  assert.equal(result.actions.completed, 1)
  assert.equal(result.actions.failed, 0)
  assert.equal(result.ledger.terminal_actions, 1)
  const authorizationConsumed = ledgerRecords.find(
    ({ event }) => event.type === 'AUTHORIZATION_CONSUMED',
  )
  assert.match(authorizationConsumed.event.dispatch_permit_sha256, /^[a-f0-9]{64}$/)
  assert.equal(ledgerRecords.some(({ event }) => event.type === 'APPROVAL_CONSUMED'), false)
  assert.doesNotMatch(JSON.stringify(result), /security-test-resource|credential|nonce/i)
})

test('a failed mutation cleanup durably stops the campaign before the next action', async (t) => {
  const scope = attestedScope({ actionCount: 2 })
  scope.limits.min_interval_ms = 0
  const verified = verifyHttpAuthedAuthorization({
    scope,
    now: NOW,
  })
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-campaign-stop-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const ledger = await openHttpAuthedCampaignLedger({
    directory: join(root, 'ledger'),
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
    operatorId: scope.authorization.operator_id,
    initialize: true,
    now: () => NOW,
  })
  let mutationCalls = 0
  const result = await runHttpAuthedCampaign({
    scope,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
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

test('a post-write executor failure enters cleanup recovery without replaying the mutation', async (t) => {
  const scope = attestedScope({ actionCount: 1 })
  scope.limits.min_interval_ms = 0
  scope.credential.binding_sha256 = sha256Hex(CREDENTIAL)
  scope.requests[0].request_body.sha256 = sha256Hex(MUTATION_BODY)
  scope.requests[0].rollback.request_body.sha256 = sha256Hex(ROLLBACK_BODY)
  const verified = verifyHttpAuthedAuthorization({
    scope,
    now: NOW,
  })
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-post-write-recovery-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const ledger = await openHttpAuthedCampaignLedger({
    directory: join(root, 'ledger'),
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
    operatorId: scope.authorization.operator_id,
    initialize: true,
    now: () => NOW,
  })
  let mutationExecutions = 0
  let mutationActionId
  const recoveryPhases = []
  const result = await runHttpAuthedCampaign({
    scope,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    ledger,
    now: () => NOW,
    reauthorize: async ({ action }) => action,
    executeProbe: async () => { throw new Error('probe executor must not run') },
    executeMutation: async ({ lease }) => {
      mutationExecutions += 1
      mutationActionId = lease.actionId
      for (const phase of ['CREDENTIAL_PREFLIGHT', 'BEFORE_READ']) {
        await ledger.markPreDispatch({
          actionId: lease.actionId,
          leaseId: lease.leaseId,
          phase,
          requestBindingSha256: sha256Hex(Buffer.from(`synthetic-${phase}`)),
        })
        await ledger.markOutcome({
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
          await ledger.recordVerification({
            actionId: lease.actionId,
            leaseId: lease.leaseId,
            phase,
            valueMatch: true,
            contextMatch: true,
          })
        }
      }
      await ledger.consumeAuthorization({
        actionId: lease.actionId,
        leaseId: lease.leaseId,
        nonce: 'synthetic-post-write-controller-authorization-nonce-0001',
        dispatchPermitSha256: 'a'.repeat(64),
      })
      await ledger.markPreDispatch({
        actionId: lease.actionId,
        leaseId: lease.leaseId,
        phase: 'MUTATION',
        requestBindingSha256: 'b'.repeat(64),
      })
      await ledger.markOutcome({
        actionId: lease.actionId,
        leaseId: lease.leaseId,
        phase: 'MUTATION',
        outcome: 'SETTLED',
        responseMetadata: {
          status: 500,
          bytes: 0,
          headerNames: [],
          requestMayHaveBeenSent: true,
        },
      })
      throw new Error('synthetic executor failure after the write settlement')
    },
    executeMutationRecovery: ({ action, lease }) => recoverDeclaredHttpAuthedMutation({
      ledger,
      scope,
      action,
      existingLease: lease,
      expectedCampaignGrantSha256: verified.campaignGrantSha256,
      credentialValue: CREDENTIAL,
      rollbackBodyBytes: ROLLBACK_BODY,
      now: () => NOW,
      verifyObservation: async () => ({ valueMatch: true, contextMatch: false }),
      transport: async (request) => {
        await request.beforeSend()
        recoveryPhases.push(request.phase)
        return {
          status: 200,
          responseBytes: 0,
          responseHeaderNames: [],
          body: Buffer.from('{}'),
        }
      },
    }),
  })
  const actionState = ledger.actionState(mutationActionId)
  const snapshot = ledger.snapshot()
  await ledger.close()

  assert.equal(mutationExecutions, 1)
  assert.deepEqual(recoveryPhases, ['ROLLBACK', 'ROLLBACK_VERIFY'])
  assert.equal(result.actions.uncertain, 1)
  assert.equal(snapshot.stopped, true)
  assert.equal(snapshot.stop_reason, 'TARGET_HEALTH_DEGRADED')
  assert.equal(snapshot.terminal_actions, 1)
  assert.equal(actionState.authorization_consumed, true)
  assert.equal(actionState.outcome, 'ROLLBACK_RECOVERED_CONTEXT_UNVERIFIED')
})

for (const status of [304, 305, 306]) {
  test(`non-redirect HTTP status ${status} does not stop remaining sealed probes`, async (t) => {
    const scope = campaignScope()
    delete scope.discovery
    scope.requests.push({
      ...scope.requests[0],
      sequence: 2,
      url: `${scope.target.origin}/approved/node-1`,
    })
    const verified = verifyHttpAuthedAuthorization({ scope, now: NOW })
    const root = await mkdtemp(join(tmpdir(), `rta-http-authed-non-redirect-${status}-`))
    t.after(() => rm(root, { recursive: true, force: true }))
    const ledger = await openHttpAuthedCampaignLedger({
      directory: join(root, 'ledger'),
      campaignGrantSha256: verified.campaignGrantSha256,
      authorizationBindingSha256: verified.authorizationBindingSha256,
      authorizationMode: scope.authorization.mode,
      operatorId: scope.authorization.operator_id,
      initialize: true,
      now: () => NOW,
    })
    let sends = 0

    const result = await runHttpAuthedCampaign({
      scope,
      expectedCampaignGrantSha256: verified.campaignGrantSha256,
      operatorId: scope.authorization.operator_id,
      ledger,
      now: () => NOW,
      reauthorize: async ({ action }) => action,
      executeProbe: async ({ beforeSend }) => {
        await beforeSend()
        sends += 1
        return {
          response: {
            status: sends === 1 ? status : 204,
            bytes: 0,
            header_names: [],
          },
        }
      },
    })
    const snapshot = ledger.snapshot()
    await ledger.close()

    assert.equal(sends, 2)
    assert.equal(result.actions.completed, 2)
    assert.equal(snapshot.stopped, false)
    assert.equal(snapshot.stop_reason, null)
  })
}

for (const [status, expectedStopReason] of [
  [401, 'CREDENTIAL_INVALID'],
  [403, 'CREDENTIAL_INVALID'],
  [429, 'LIMIT_REACHED'],
  [302, 'UNEXPECTED_REDIRECT'],
  [500, 'TARGET_HEALTH_DEGRADED'],
]) {
  test(`mutation status ${status} preserves campaign stop reason ${expectedStopReason}`, async (t) => {
    const scope = attestedScope({ actionCount: 2 })
    scope.limits.min_interval_ms = 0
    scope.credential.binding_sha256 = sha256Hex(CREDENTIAL)
    for (const action of scope.requests) {
      action.request_body.sha256 = sha256Hex(MUTATION_BODY)
      action.rollback.request_body.sha256 = sha256Hex(ROLLBACK_BODY)
    }
    const verified = verifyHttpAuthedAuthorization({
      scope,
      now: NOW,
    })
    const root = await mkdtemp(join(tmpdir(), `rta-http-authed-mutation-status-${status}-`))
    t.after(() => rm(root, { recursive: true, force: true }))
    const ledger = await openHttpAuthedCampaignLedger({
      directory: join(root, 'ledger'),
      campaignGrantSha256: verified.campaignGrantSha256,
      authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
      operatorId: scope.authorization.operator_id,
      initialize: true,
      now: () => NOW,
    })
    let mutationExecutions = 0
    let mutationResult
    const result = await runHttpAuthedCampaign({
      scope,
      expectedCampaignGrantSha256: verified.campaignGrantSha256,
      operatorId: scope.authorization.operator_id,
      ledger,
      now: () => NOW,
      reauthorize: async ({ action }) => action,
      executeProbe: async () => { throw new Error('probe executor must not run') },
      executeMutation: async ({ action, lease }) => {
        mutationExecutions += 1
        mutationResult = await runDeclaredHttpAuthedMutation({
          ledger,
          scope,
          action,
          existingLease: lease,
          expectedCampaignGrantSha256: verified.campaignGrantSha256,
          operatorId: scope.authorization.operator_id,
          credentialValue: CREDENTIAL,
          requestBodyBytes: MUTATION_BODY,
          rollbackBodyBytes: ROLLBACK_BODY,
          now: () => NOW,
          verifyObservation: async () => ({ valueMatch: true, contextMatch: true }),
          transport: async (request) => {
            await request.beforeSend()
            return {
              status,
              responseBytes: 0,
              responseHeaderNames: [],
              body: Buffer.from('{}'),
            }
          },
        })
        return mutationResult
      },
    })
    const snapshot = ledger.snapshot()
    await ledger.close()

    assert.equal(mutationExecutions, 1)
    assert.equal(mutationResult.stop_reason, expectedStopReason)
    assert.equal(result.ledger.stop_reason, expectedStopReason)
    assert.equal(snapshot.stop_reason, expectedStopReason)
    assert.equal(snapshot.terminal_actions, 1)
    assert.equal(snapshot.queued_actions, 1)
  })
}
