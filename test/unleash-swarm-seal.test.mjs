import assert from 'node:assert/strict'
import { resolve } from 'node:path'
import test from 'node:test'

import {
  appendUnleashCampaignState,
  nextUnleashCampaignState,
  recoverUnleashCampaignState,
} from '../scripts/lib/unleash-campaign-state.mjs'
import { createUnleashPlan, digestUnleashValue } from '../scripts/lib/unleash-contracts.mjs'
import { createUnleashDeploymentPolicy } from '../scripts/lib/unleash-policy.mjs'
import { createVerifiedReconCompletion } from '../scripts/lib/unleash-recon-evidence.mjs'
import { createDefaultUnleashPlannerDependencies } from '../scripts/lib/unleash-registry.mjs'
import {
  UNLEASH_SWARM_DEFAULT_LIMITS,
  createUnleashSwarmBasis,
} from '../scripts/lib/unleash-swarm-contracts.mjs'
import {
  evaluateUnleashSwarmTermination,
  mergeUnleashSwarmResponses,
} from '../scripts/lib/unleash-swarm-merge.mjs'
import { initializeUnleashSwarmAttemptLedger } from '../scripts/lib/unleash-swarm-ledger.mjs'
import {
  UNLEASH_SWARM_COMPLETION_FILE,
  UnleashSwarmSealError,
  sealUnleashSwarmCampaign,
} from '../scripts/lib/unleash-swarm-seal.mjs'

const TARGET = 'https://example.test/'
const RUN_DIRECTORY = resolve('C:/synthetic/LastAperture/campaigns/campaign-0123456789abcdef01234567')

function memoryStorage() {
  const files = new Map()
  const operations = []
  let blocker = () => false
  return {
    files,
    operations,
    blockWhen(predicate) { blocker = predicate },
    unblock() { blocker = () => false },
    async writeImmutableJson(filename, value) {
      operations.push({ method: 'immutable', filename, value: structuredClone(value) })
      if (blocker('immutable', filename, value)) {
        throw Object.assign(new Error('synthetic blocked immutable write'), { code: 'SYNTHETIC_WRITE_BLOCKED' })
      }
      if (files.has(filename)) {
        throw Object.assign(new Error('exists'), { code: 'UNLEASH_STORAGE_FILE_EXISTS' })
      }
      files.set(filename, structuredClone(value))
      return filename
    },
    async replaceMutableJson(filename, value) {
      operations.push({ method: 'mutable', filename, value: structuredClone(value) })
      if (blocker('mutable', filename, value)) {
        throw Object.assign(new Error('synthetic blocked mutable write'), { code: 'SYNTHETIC_WRITE_BLOCKED' })
      }
      files.set(filename, structuredClone(value))
      return filename
    },
    async readJson(filename) {
      if (!files.has(filename)) {
        throw Object.assign(new Error('missing'), { code: 'UNLEASH_STORAGE_FILE_NOT_FOUND' })
      }
      return structuredClone(files.get(filename))
    },
    async listJsonFilenames() {
      return [...files.keys()].sort()
    },
  }
}

function deploymentPolicy() {
  return createUnleashDeploymentPolicy({
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-deployment-policy',
    policy_id: 'policy:swarm-seal-test',
    valid_from: '2026-09-15T09:00:00.000Z',
    valid_until: '2026-09-15T10:00:00.000Z',
    allowed_origins: ['https://example.test'],
    allowed_target_families: ['https'],
    allowed_effects: ['OBSERVE'],
    budgets: {
      max_actions: 4,
      max_parallel_actions: 1,
      max_duration_ms: 900_000,
      max_response_bytes: 1_048_576,
    },
    credential_references: [],
    revocation: { check_id: 'revocation:swarm-seal-test', fail_mode: 'CLOSED' },
  })
}

function routeCounts(plan) {
  const counts = {
    total: plan.route_dispositions.length,
    ready: 0,
    waiting: 0,
    unavailable: 0,
    not_applicable: 0,
    blocked: 0,
  }
  for (const route of plan.route_dispositions) {
    if (route.disposition === 'READY') counts.ready += 1
    else if (['WAITING_FOR_MATERIAL', 'WAITING_FOR_DEPENDENCY'].includes(route.disposition)) counts.waiting += 1
    else if (route.disposition === 'UNAVAILABLE') counts.unavailable += 1
    else if (route.disposition === 'NOT_APPLICABLE') counts.not_applicable += 1
    else if (route.disposition === 'BLOCKED_BY_POLICY') counts.blocked += 1
  }
  return counts
}

function clock(start = Date.parse('2026-09-15T09:32:00.000Z')) {
  let current = start
  return () => {
    const sampled = new Date(current)
    current += 1_000
    return sampled
  }
}

async function fixture({ stopped = false } = {}) {
  const storage = memoryStorage()
  const planner = createDefaultUnleashPlannerDependencies({ policy: deploymentPolicy() })
  const plan = createUnleashPlan({ target: TARGET }, planner)
  const authority = {
    admitted_at: '2026-09-15T09:15:00.000Z',
    effect: 'OBSERVE',
    mode: 'CONTROLLER_DEPLOYMENT_POLICY',
    policy_id: plan.policy_id,
    policy_sha256: plan.policy_sha256,
    revocation_check_id: plan.authority.revocation.check_id,
    target_id: plan.target.target_id,
  }
  const verified = {
    schema_version: '1.0.0',
    kind: 'last-aperture/verified-http-recon-evidence',
    run: {
      state: 'PROBE_PLAN_COMPLETE',
      run_id: 'run:swarm-seal-fixture',
      plan_sha256: '5'.repeat(64),
      authorization: structuredClone(authority),
      target: { origin: new URL(TARGET).origin },
      actions: [{ method: 'HEAD', url: TARGET, safe_to_get: false }],
      event_chain: { count: 3, last_sha256: '7'.repeat(64) },
    },
    observations: [{ authority: structuredClone(authority), method: 'HEAD', url: TARGET }],
  }
  const completion = await createVerifiedReconCompletion({
    bundle: resolve(RUN_DIRECTORY, 'recon'),
    plan,
  }, {
    now: () => new Date('2026-09-15T09:30:00.000Z'),
    readVerifiedRecon: async () => structuredClone(verified),
  })
  const counts = routeCounts(plan)
  const stateBase = {
    schema_version: '2.0.0',
    kind: 'last-aperture/unleash-state',
    campaign_id: `campaign:sha256:${'4'.repeat(64)}`,
    run_directory: RUN_DIRECTORY,
    plan_sha256: plan.plan_sha256,
    target: structuredClone(plan.target),
    completed_routes: [],
    route_counts: counts,
    gap_count: counts.waiting + counts.unavailable + counts.blocked,
    recon_bundle: resolve(RUN_DIRECTORY, 'recon'),
    evidence_packet_path: null,
    evidence_packet_sha256: null,
    completion_receipt_sha256: null,
    stop_reason: null,
    failure: null,
    swarm_basis_sha256: null,
    swarm_completion_sha256: null,
    candidate_frontier_sha256: null,
    candidate_frontier_head_sha256: null,
    swarm_gap_count: 0,
  }
  const planned = await appendUnleashCampaignState({
    storage,
    nextState: {
      ...structuredClone(stateBase),
      revision: 1,
      updated_at: '2026-09-15T09:28:00.000Z',
      status: 'PLANNED',
    },
  })
  const running = await appendUnleashCampaignState({
    storage,
    previousState: planned,
    nextState: nextUnleashCampaignState(planned, { status: 'RUNNING' }, '2026-09-15T09:29:00.000Z'),
  })
  const swarmBasis = createUnleashSwarmBasis({
    recordedAt: '2026-09-15T09:31:00.000Z',
    campaignId: running.campaign_id,
    campaignStateRevision: running.revision,
    campaignStateSha256: digestUnleashValue(running),
    planSha256: plan.plan_sha256,
    targetId: plan.target.target_id,
    registrySha256: digestUnleashValue(planner.registry),
    providerProfileSha256: digestUnleashValue(planner.provider),
    evidencePacketSha256: completion.evidence_packet.packet_sha256,
    completionReceiptSha256: completion.completion_receipt.completion_receipt_sha256,
    limits: structuredClone(UNLEASH_SWARM_DEFAULT_LIMITS),
  })
  const swarming = await appendUnleashCampaignState({
    storage,
    previousState: running,
    nextState: nextUnleashCampaignState(running, {
      status: 'SWARMING',
      completed_routes: [completion.completion_receipt.route_id],
      evidence_packet_path: resolve(RUN_DIRECTORY, 'evidence-packet.json'),
      evidence_packet_sha256: completion.evidence_packet.packet_sha256,
      completion_receipt_sha256: completion.completion_receipt.completion_receipt_sha256,
      swarm_basis_sha256: swarmBasis.basis_sha256,
    }, swarmBasis.recorded_at),
  })
  const swarmMerge = mergeUnleashSwarmResponses({
    basis: swarmBasis,
    round: 1,
    previous: null,
    responses: [],
  })
  const swarmLedger = await initializeUnleashSwarmAttemptLedger({
    basis: swarmBasis,
    initializedAt: swarmBasis.recorded_at,
  }, {
    storage: {
      writeImmutableJson: storage.writeImmutableJson.bind(storage),
      replaceMutableJson: storage.replaceMutableJson.bind(storage),
      readJson: storage.readJson.bind(storage),
      listJsonFilenames: storage.listJsonFilenames.bind(storage),
    },
  })
  const termination = evaluateUnleashSwarmTermination({
    beforeFrontierSha256: swarmMerge.frontier_sha256,
    beforeChallengeSetSha256: swarmMerge.challenge_set_sha256,
    after: swarmMerge,
    roundsCompleted: 1,
    providerCallsStarted: 0,
    responseBytes: 0,
    pendingAttemptCount: 0,
    stopRequested: stopped,
    authorityAvailable: true,
    deadlineExceeded: false,
    basis: swarmBasis,
  })
  return {
    storage,
    input: {
      plan,
      registry: planner.registry,
      provider: planner.provider,
      basisState: running,
      campaignState: swarming,
      evidencePacket: completion.evidence_packet,
      completion,
      swarmBasis,
      swarmMerge,
      swarmLedger,
      termination,
      usage: { rounds_completed: 1, provider_calls_started: 0, response_bytes: 0 },
      gaps: [{
        round: 1,
        role_id: 'attacker:perimeter',
        state: stopped ? 'STOPPED' : 'UNAVAILABLE',
        reason_code: stopped ? 'STOP_REQUESTED' : 'REASONING_ADAPTER_UNAVAILABLE',
        request_id: null,
      }],
      stopReason: stopped ? 'Operator requested stop.' : null,
    },
  }
}

function seal(input, storage, now = clock()) {
  return sealUnleashSwarmCampaign(input, { storage, now })
}

function rejectsCode(code) {
  return (error) => error instanceof UnleashSwarmSealError && error.code === code
}

test('seals admission, completion, campaign, and frontier in order and idempotently repairs stale mutable heads', async () => {
  const { input, storage } = await fixture()
  const start = storage.operations.length
  const result = await seal(input, storage)
  const sealOperations = storage.operations.slice(start)

  assert.equal(result.campaignState.status, 'COMPLETE_WITH_GAPS')
  assert.equal(result.frontier.proposal_count, 1)
  assert.equal(result.frontier.candidate_count, 0)
  assert.equal(result.frontierState.swarm_completion_sha256, result.swarmCompletion.completion_sha256)
  assert.equal(result.campaignState.candidate_frontier_sha256, result.frontier.frontier_sha256)
  assert.equal(result.campaignState.swarm_gap_count, 1)
  const admissionIndex = sealOperations.findIndex(({ filename }) => filename === 'candidate-admission-000001.json')
  const unsealedStateIndex = sealOperations.findIndex(({ filename, value }) => (
    filename === 'candidate-frontier-state.json' && value.swarm_completion_sha256 === null
  ))
  const completionIndex = sealOperations.findIndex(({ filename }) => filename === UNLEASH_SWARM_COMPLETION_FILE)
  const terminalEventIndex = sealOperations.findIndex(({ filename }) => filename === 'campaign-event-000004.json')
  const sealedStateIndex = sealOperations.findIndex(({ filename, value }) => (
    filename === 'candidate-frontier-state.json' && value.swarm_completion_sha256 !== null
  ))
  assert.ok(admissionIndex < unsealedStateIndex)
  assert.ok(unsealedStateIndex < completionIndex)
  assert.ok(completionIndex < terminalEventIndex)
  assert.ok(terminalEventIndex < sealedStateIndex)

  const unsealedState = sealOperations[unsealedStateIndex].value
  storage.files.set('campaign-state.json', structuredClone(input.campaignState))
  storage.files.set('candidate-frontier-state.json', structuredClone(unsealedState))
  const immutableBefore = storage.operations.filter(({ method }) => method === 'immutable').length
  const repaired = await seal({ ...input, campaignState: result.campaignState }, storage, clock(Date.parse('2026-09-15T09:40:00.000Z')))
  const immutableAfter = storage.operations.filter(({ method }) => method === 'immutable').length

  assert.equal(immutableAfter, immutableBefore)
  assert.deepEqual(repaired.campaignState, result.campaignState)
  assert.equal(repaired.frontierState.swarm_completion_sha256, result.swarmCompletion.completion_sha256)
  assert.deepEqual(storage.files.get('campaign-state.json'), result.campaignState)
})

test('resumes when the final admission exists but its mutable frontier projection was not published', async () => {
  const { input, storage } = await fixture()
  storage.blockWhen((method, filename) => method === 'mutable' && filename === 'candidate-frontier-state.json')

  await assert.rejects(
    seal(input, storage),
    rejectsCode('UNLEASH_SWARM_SEAL_MUTABLE_WRITE_FAILED'),
  )
  assert.equal(storage.files.has('candidate-admission-000001.json'), true)
  assert.equal(storage.files.has(UNLEASH_SWARM_COMPLETION_FILE), false)

  storage.unblock()
  const result = await seal(input, storage, clock(Date.parse('2026-09-15T09:35:00.000Z')))
  assert.equal(result.frontier.proposal_count, 1)
  assert.equal(result.campaignState.status, 'COMPLETE_WITH_GAPS')
})

test('reuses immutable completion after terminal event publication was interrupted', async () => {
  const { input, storage } = await fixture()
  storage.blockWhen((method, filename) => method === 'immutable' && filename === 'campaign-event-000004.json')

  await assert.rejects(
    seal(input, storage),
    rejectsCode('UNLEASH_SWARM_SEAL_CAMPAIGN_WRITE_FAILED'),
  )
  assert.equal(storage.files.has(UNLEASH_SWARM_COMPLETION_FILE), true)
  assert.equal((await recoverUnleashCampaignState({ storage })).state.status, 'SWARMING')
  const completionWrites = storage.operations.filter(({ filename }) => filename === UNLEASH_SWARM_COMPLETION_FILE).length

  storage.unblock()
  const result = await seal(input, storage, clock(Date.parse('2026-09-15T09:38:00.000Z')))
  assert.equal(result.campaignState.status, 'COMPLETE_WITH_GAPS')
  assert.equal(storage.operations.filter(({ filename }) => filename === UNLEASH_SWARM_COMPLETION_FILE).length, completionWrites)
})

test('repairs the sealed frontier state after the terminal campaign event is already durable', async () => {
  const { input, storage } = await fixture()
  storage.blockWhen((method, filename, value) => (
    method === 'mutable'
    && filename === 'candidate-frontier-state.json'
    && value.swarm_completion_sha256 !== null
  ))

  await assert.rejects(
    seal(input, storage),
    rejectsCode('UNLEASH_SWARM_SEAL_MUTABLE_INVALID'),
  )
  const recovered = await recoverUnleashCampaignState({ storage })
  assert.equal(recovered.state.status, 'COMPLETE_WITH_GAPS')
  assert.equal(storage.files.get('candidate-frontier-state.json').swarm_completion_sha256, null)

  storage.unblock()
  const result = await seal(
    { ...input, campaignState: recovered.state },
    storage,
    clock(Date.parse('2026-09-15T09:40:00.000Z')),
  )
  assert.equal(result.frontierState.swarm_completion_sha256, result.swarmCompletion.completion_sha256)
  assert.deepEqual(result.campaignState, recovered.state)
})

test('requires terminal control gaps and never maps budget exhaustion to COMPLETE', async () => {
  const { input, storage } = await fixture()
  const termination = {
    decision: 'BUDGET_EXHAUSTED',
    reason: 'DEADLINE',
    stable: true,
    terminal: true,
  }
  await assert.rejects(
    seal({ ...input, termination, gaps: [] }, storage),
    rejectsCode('UNLEASH_SWARM_SEAL_INPUT_INVALID'),
  )

  const result = await seal({
    ...input,
    termination,
    gaps: [{
      round: 1,
      role_id: null,
      state: 'INCONCLUSIVE',
      reason_code: 'DEADLINE',
      request_id: null,
    }],
  }, storage)
  assert.equal(result.swarmCompletion.status, 'BUDGET_EXHAUSTED')
  assert.equal(result.campaignState.status, 'COMPLETE_WITH_GAPS')
  assert.equal(result.campaignState.swarm_gap_count, 1)
})

test('maps only a STOPPED swarm decision to a stopped campaign and rejects computed ingress', async () => {
  const { input, storage } = await fixture({ stopped: true })
  const result = await seal(input, storage)
  assert.equal(result.swarmCompletion.status, 'STOPPED')
  assert.equal(result.campaignState.status, 'STOPPED')
  assert.equal(result.campaignState.stop_reason, input.stopReason)

  let calls = 0
  const computed = { ...input }
  Object.defineProperty(computed, 'gaps', {
    enumerable: true,
    get() {
      calls += 1
      throw new Error('must not execute')
    },
  })
  await assert.rejects(
    sealUnleashSwarmCampaign(computed, { storage, now: clock() }),
    rejectsCode('UNLEASH_SWARM_SEAL_INPUT_INVALID'),
  )
  assert.equal(calls, 0)
})
