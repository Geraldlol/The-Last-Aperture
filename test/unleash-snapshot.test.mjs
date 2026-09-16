import assert from 'node:assert/strict'
import { resolve } from 'node:path'
import test from 'node:test'

import {
  createUnleashPlan,
  digestUnleashValue,
} from '../scripts/lib/unleash-contracts.mjs'
import { createDefaultUnleashPlannerDependencies } from '../scripts/lib/unleash-registry.mjs'
import {
  UNLEASH_SWARM_DEFAULT_LIMITS,
  createUnleashSwarmBasis,
  createUnleashSwarmCompletion,
} from '../scripts/lib/unleash-swarm-contracts.mjs'
import { mergeUnleashSwarmResponses } from '../scripts/lib/unleash-swarm-merge.mjs'
import {
  assertValidUnleashCampaignSnapshot,
  createUnleashCampaignSnapshot,
} from '../scripts/lib/unleash-snapshot.mjs'

const CAPTURED_AT = '2026-09-15T12:00:03.000Z'
const V2_CAPTURED_AT = '2026-09-15T12:00:05.000Z'
const CAMPAIGN_ID = `campaign:sha256:${'a'.repeat(64)}`
const EVIDENCE_REF = `evidence:sha256:${'b'.repeat(64)}`

function deploymentPolicy() {
  return {
    schema_version: '1.0.0',
    policy_id: 'deployment-policy:snapshot-test',
    valid_from: '2026-09-15T00:00:00.000Z',
    valid_until: '2026-09-16T00:00:00.000Z',
    allowed_origins: ['https://example.test'],
    allowed_target_families: ['https'],
    allowed_effects: ['OBSERVE'],
    budgets: {
      max_actions: 64,
      max_parallel_actions: 4,
      max_duration_ms: 300_000,
      max_response_bytes: 1_048_576,
    },
    revocation: { check_id: 'revocation:snapshot-test', fail_mode: 'CLOSED' },
  }
}

function digestRecord(value, digestField) {
  const { [digestField]: _omitted, ...unsigned } = value
  return { ...value, [digestField]: digestUnleashValue(unsigned) }
}

function event(previous, state) {
  return {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-campaign-event',
    revision: state.revision,
    recorded_at: state.updated_at,
    previous_state_sha256: previous === null ? null : digestUnleashValue(previous),
    state_sha256: digestUnleashValue(state),
    state: structuredClone(state),
  }
}

function fixture({ terminal = true, stopped = false } = {}) {
  const dependencies = createDefaultUnleashPlannerDependencies({ policy: deploymentPolicy() })
  const plan = createUnleashPlan({ target: 'https://example.test/' }, dependencies)
  const routeCounts = {
    total: plan.route_dispositions.length,
    ready: plan.route_dispositions.filter(({ disposition }) => disposition === 'READY').length,
    waiting: plan.route_dispositions.filter(({ disposition }) => (
      disposition === 'WAITING_FOR_MATERIAL' || disposition === 'WAITING_FOR_DEPENDENCY'
    )).length,
    unavailable: plan.route_dispositions.filter(({ disposition }) => disposition === 'UNAVAILABLE').length,
    not_applicable: plan.route_dispositions.filter(({ disposition }) => disposition === 'NOT_APPLICABLE').length,
    blocked: plan.route_dispositions.filter(({ disposition }) => disposition === 'BLOCKED_BY_POLICY').length,
  }
  const runDirectory = resolve('snapshot-campaign-fixture')
  const base = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-state',
    campaign_id: CAMPAIGN_ID,
    run_directory: runDirectory,
    plan_sha256: plan.plan_sha256,
    target: structuredClone(plan.target),
    completed_routes: [],
    route_counts: routeCounts,
    gap_count: routeCounts.waiting + routeCounts.unavailable + routeCounts.blocked,
    recon_bundle: resolve(runDirectory, 'recon'),
    evidence_packet_path: null,
    evidence_packet_sha256: null,
    completion_receipt_sha256: null,
    stop_reason: null,
    failure: null,
  }
  const planned = {
    ...structuredClone(base),
    revision: 1,
    updated_at: '2026-09-15T12:00:00.000Z',
    status: 'PLANNED',
  }
  const running = {
    ...structuredClone(base),
    revision: 2,
    updated_at: '2026-09-15T12:00:01.000Z',
    status: 'RUNNING',
  }
  let state = running
  let states = [planned, running]
  if (terminal) {
    state = stopped
      ? {
          ...structuredClone(base),
          revision: 3,
          updated_at: '2026-09-15T12:00:02.000Z',
          status: 'STOPPED',
          stop_reason: 'operator requested stop',
        }
      : {
          ...structuredClone(base),
          revision: 3,
          updated_at: '2026-09-15T12:00:02.000Z',
          status: 'COMPLETE_WITH_GAPS',
          completed_routes: ['https-recon'],
          evidence_packet_path: resolve(runDirectory, 'evidence-packet.json'),
          evidence_packet_sha256: 'c'.repeat(64),
          completion_receipt_sha256: 'd'.repeat(64),
        }
    states = [planned, running, state]
  }
  const stateEvents = states.map((item, index) => event(states[index - 1] ?? null, item))

  const candidate = digestRecord({
    candidate_id: 'candidate:header-disclosure',
    state: 'CANDIDATE',
    candidate_sha256: '0'.repeat(64),
    proposal_id: 'proposal:fixture',
    proposal_sha256: 'e'.repeat(64),
    admission_sha256: 'f'.repeat(64),
    title: 'Potential version disclosure',
    hypothesis: 'A response header may expose exact component versions.',
    invariant: 'Production responses should not expose unnecessary exact component versions.',
    provider_confidence: 'MEDIUM',
    evidence_refs: [EVIDENCE_REF],
    competing_explanations: ['The disclosed token may be a compatibility marker.'],
    proposed_action_ids: ['action:inspect-header'],
  }, 'candidate_sha256')
  const action = digestRecord({
    action_id: 'action:inspect-header',
    state: 'PROPOSED_INERT',
    action_sha256: '0'.repeat(64),
    candidate_id: candidate.candidate_id,
    proposal_id: candidate.proposal_id,
    proposal_sha256: candidate.proposal_sha256,
    admission_sha256: candidate.admission_sha256,
    tool_id: 'tool:https-recon',
    evidence_refs: [EVIDENCE_REF],
    parameters: { method: 'HEAD' },
    expected_observation: 'Confirm whether the exact version token is stable.',
    executable: false,
  }, 'action_sha256')
  const includeCandidates = state.status === 'COMPLETE_WITH_GAPS'
  const frontier = digestRecord({
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-candidate-frontier',
    campaign_id: CAMPAIGN_ID,
    plan_sha256: plan.plan_sha256,
    target_id: plan.target.target_id,
    campaign_state_revision: state.revision,
    campaign_state_sha256: digestUnleashValue(state),
    evidence_packet_sha256: state.evidence_packet_sha256,
    completion_receipt_sha256: state.completion_receipt_sha256,
    proposal_count: includeCandidates ? 1 : 0,
    candidate_count: includeCandidates ? 1 : 0,
    proposed_action_count: includeCandidates ? 1 : 0,
    head_admission_sha256: includeCandidates ? 'f'.repeat(64) : null,
    candidates: includeCandidates ? [candidate] : [],
    actions: includeCandidates ? [action] : [],
    frontier_sha256: '0'.repeat(64),
  }, 'frontier_sha256')
  return { plan, state, stateEvents, registry: dependencies.registry, frontier }
}

function roleResponse({ basis, plan, roleId, roleKind, wave, proposal, challenges }) {
  const requestId = `request:sha256:${digestUnleashValue({ roleId, wave })}`
  return {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-role-response',
    request_id: requestId,
    request_sha256: digestUnleashValue({ requestId, basis: basis.basis_sha256 }),
    basis_sha256: basis.basis_sha256,
    plan_sha256: plan.plan_sha256,
    round: 1,
    role_id: roleId,
    role_kind: roleKind,
    wave,
    proposal,
    challenges,
  }
}

function swarmMerge(basis, plan) {
  const attacker = roleResponse({
    basis,
    plan,
    roleId: 'attacker:perimeter',
    roleKind: 'ATTACKER',
    wave: 'ATTACK',
    proposal: {
      schema_version: '1.0.0',
      kind: 'last-aperture/unleash-proposal',
      proposal_id: 'proposal:provider-perimeter',
      plan_sha256: plan.plan_sha256,
      provider_protocol_version: '2.0.0',
      candidates: [{
        candidate_id: 'candidate:provider-header',
        title: 'Potential version disclosure',
        hypothesis: 'A response header may expose exact component versions.',
        invariant: 'Production responses should not expose unnecessary exact component versions.',
        confidence: 'MEDIUM',
        evidence_refs: [EVIDENCE_REF],
        competing_explanations: ['The disclosed token may be a compatibility marker.'],
      }],
      actions: [{
        action_id: 'action:provider-inspect-header',
        candidate_id: 'candidate:provider-header',
        tool_id: 'tool:https-recon',
        evidence_refs: [EVIDENCE_REF],
        parameters: { method: 'HEAD' },
        expected_observation: 'Confirm whether the exact version token is stable.',
      }],
    },
    challenges: [],
  })
  const attackMerge = mergeUnleashSwarmResponses({ basis, round: 1, previous: null, responses: [attacker] })
  const reviewer = roleResponse({
    basis,
    plan,
    roleId: 'reviewer:skeptic',
    roleKind: 'REVIEWER',
    wave: 'REVIEW',
    proposal: {
      schema_version: '1.0.0',
      kind: 'last-aperture/unleash-proposal',
      proposal_id: 'proposal:provider-skeptic',
      plan_sha256: plan.plan_sha256,
      provider_protocol_version: '2.0.0',
      candidates: [],
      actions: [],
    },
    challenges: [{
      challenge_id: 'challenge:provider-header-evidence',
      candidate_id: attackMerge.candidates[0].candidate_id,
      disposition: 'INSUFFICIENT_EVIDENCE',
      reason: 'One response does not establish whether the header is stable across the deployment.',
      evidence_refs: [EVIDENCE_REF],
      competing_explanations: ['An edge cache may have synthesized the observed header.'],
    }],
  })
  return mergeUnleashSwarmResponses({
    basis,
    round: 1,
    previous: attackMerge,
    responses: [reviewer],
  })
}

function frontierV2({ basisState, plan, swarmBasis, merge, admitted }) {
  const admissionSha256 = admitted ? 'f'.repeat(64) : null
  const proposalSha256 = digestUnleashValue(merge.proposal)
  const candidates = admitted
    ? merge.candidates.map((candidate) => digestRecord({
        candidate_id: candidate.candidate_id,
        state: candidate.state,
        candidate_sha256: '0'.repeat(64),
        proposal_id: merge.proposal.proposal_id,
        proposal_sha256: proposalSha256,
        admission_sha256: admissionSha256,
        title: candidate.title,
        hypothesis: candidate.hypothesis,
        invariant: candidate.invariant,
        provider_confidence: candidate.provider_confidence,
        evidence_refs: [...candidate.evidence_refs],
        competing_explanations: [...candidate.competing_explanations],
        proposed_action_ids: [...candidate.proposed_action_ids],
      }, 'candidate_sha256'))
    : []
  const actions = admitted
    ? merge.actions.map((action) => digestRecord({
        action_id: action.action_id,
        state: action.state,
        action_sha256: '0'.repeat(64),
        candidate_id: action.candidate_id,
        proposal_id: merge.proposal.proposal_id,
        proposal_sha256: proposalSha256,
        admission_sha256: admissionSha256,
        tool_id: action.tool_id,
        evidence_refs: [...action.evidence_refs],
        parameters: structuredClone(action.parameters),
        expected_observation: action.expected_observation,
        executable: action.executable,
      }, 'action_sha256'))
    : []
  return digestRecord({
    schema_version: '2.0.0',
    kind: 'last-aperture/unleash-candidate-frontier',
    campaign_id: basisState.campaign_id,
    plan_sha256: plan.plan_sha256,
    target_id: plan.target.target_id,
    campaign_state_revision: basisState.revision,
    campaign_state_sha256: digestUnleashValue(basisState),
    evidence_packet_sha256: swarmBasis.evidence_packet_sha256,
    completion_receipt_sha256: swarmBasis.completion_receipt_sha256,
    proposal_count: admitted ? 1 : 0,
    candidate_count: candidates.length,
    proposed_action_count: actions.length,
    head_admission_sha256: admissionSha256,
    candidates,
    actions,
    swarm_basis_sha256: swarmBasis.basis_sha256,
    swarm_merge_sha256: merge.merge_sha256,
    frontier_sha256: '0'.repeat(64),
  }, 'frontier_sha256')
}

function fixtureV2({ sealed = true, stopped = false } = {}) {
  const dependencies = createDefaultUnleashPlannerDependencies({ policy: deploymentPolicy() })
  const plan = createUnleashPlan({ target: 'https://example.test/' }, dependencies)
  const routeCounts = {
    total: plan.route_dispositions.length,
    ready: plan.route_dispositions.filter(({ disposition }) => disposition === 'READY').length,
    waiting: plan.route_dispositions.filter(({ disposition }) => (
      disposition === 'WAITING_FOR_MATERIAL' || disposition === 'WAITING_FOR_DEPENDENCY'
    )).length,
    unavailable: plan.route_dispositions.filter(({ disposition }) => disposition === 'UNAVAILABLE').length,
    not_applicable: plan.route_dispositions.filter(({ disposition }) => disposition === 'NOT_APPLICABLE').length,
    blocked: plan.route_dispositions.filter(({ disposition }) => disposition === 'BLOCKED_BY_POLICY').length,
  }
  const runDirectory = resolve('snapshot-campaign-v2-fixture')
  const base = {
    schema_version: '2.0.0',
    kind: 'last-aperture/unleash-state',
    campaign_id: CAMPAIGN_ID,
    run_directory: runDirectory,
    plan_sha256: plan.plan_sha256,
    target: structuredClone(plan.target),
    route_counts: routeCounts,
    gap_count: routeCounts.waiting + routeCounts.unavailable + routeCounts.blocked,
    recon_bundle: resolve(runDirectory, 'recon'),
    stop_reason: null,
    failure: null,
    swarm_completion_sha256: null,
    candidate_frontier_sha256: null,
    candidate_frontier_head_sha256: null,
    swarm_gap_count: 0,
  }
  const planned = {
    ...structuredClone(base),
    revision: 1,
    updated_at: '2026-09-15T12:00:00.000Z',
    status: 'PLANNED',
    completed_routes: [],
    evidence_packet_path: null,
    evidence_packet_sha256: null,
    completion_receipt_sha256: null,
    swarm_basis_sha256: null,
  }
  const basisState = {
    ...structuredClone(planned),
    revision: 2,
    updated_at: '2026-09-15T12:00:01.000Z',
    status: 'RUNNING',
  }
  const swarmBasis = createUnleashSwarmBasis({
    recordedAt: '2026-09-15T12:00:02.000Z',
    campaignId: CAMPAIGN_ID,
    campaignStateRevision: basisState.revision,
    campaignStateSha256: digestUnleashValue(basisState),
    planSha256: plan.plan_sha256,
    targetId: plan.target.target_id,
    registrySha256: plan.registry_sha256,
    providerProfileSha256: plan.provider_sha256,
    evidencePacketSha256: 'c'.repeat(64),
    completionReceiptSha256: 'd'.repeat(64),
    limits: structuredClone(UNLEASH_SWARM_DEFAULT_LIMITS),
  })
  const swarming = {
    ...structuredClone(base),
    revision: 3,
    updated_at: swarmBasis.recorded_at,
    status: 'SWARMING',
    completed_routes: ['https-recon'],
    evidence_packet_path: resolve(runDirectory, 'evidence-packet.json'),
    evidence_packet_sha256: swarmBasis.evidence_packet_sha256,
    completion_receipt_sha256: swarmBasis.completion_receipt_sha256,
    swarm_basis_sha256: swarmBasis.basis_sha256,
  }
  const merge = swarmMerge(swarmBasis, plan)
  const frontier = sealed
    ? frontierV2({ basisState, plan, swarmBasis, merge, admitted: true })
    : null
  const swarmCompletion = sealed
    ? createUnleashSwarmCompletion({
        basis: swarmBasis,
        merge,
        termination: stopped
          ? { decision: 'STOPPED', reason: 'STOP_REQUESTED', stable: false, terminal: true }
          : { decision: 'BUDGET_EXHAUSTED', reason: 'DEADLINE', stable: false, terminal: true },
        completedAt: '2026-09-15T12:00:04.000Z',
        attemptLedger: {
          event_count: 4,
          attempt_count: 2,
          response_bytes: 512,
          head_record_sha256: 'e'.repeat(64),
          ledger_sha256: 'f'.repeat(64),
        },
        gaps: [{
          round: 1,
          role_id: stopped ? 'attacker:identity' : null,
          state: stopped ? 'STOPPED' : 'INCONCLUSIVE',
          reason_code: stopped ? 'STOP_REQUESTED' : 'DEADLINE',
          request_id: null,
        }],
        usage: { rounds_completed: 1, provider_calls_started: 2, response_bytes: 512 },
      })
    : null
  const state = sealed
    ? {
        ...structuredClone(swarming),
        revision: 4,
        updated_at: swarmCompletion.completed_at,
        status: stopped ? 'STOPPED' : 'COMPLETE_WITH_GAPS',
        stop_reason: stopped ? 'operator requested stop' : null,
        swarm_completion_sha256: swarmCompletion.completion_sha256,
        candidate_frontier_sha256: frontier.frontier_sha256,
        candidate_frontier_head_sha256: frontier.head_admission_sha256,
        swarm_gap_count: swarmCompletion.gaps.length,
      }
    : swarming
  const states = sealed ? [planned, basisState, swarming, state] : [planned, basisState, swarming]
  return {
    plan,
    registry: dependencies.registry,
    state,
    stateEvents: states.map((item, index) => event(states[index - 1] ?? null, item)),
    frontier,
    basisState,
    swarmBasis,
    swarmMerge: merge,
    swarmCompletion,
  }
}

function fixtureV2BeforeSwarm(status = 'PLANNED') {
  const source = fixtureV2({ sealed: false })
  const planned = structuredClone(source.stateEvents[0].state)
  const running = structuredClone(source.stateEvents[1].state)
  let states
  if (status === 'PLANNED') states = [planned]
  else if (status === 'RUNNING') states = [planned, running]
  else {
    const state = {
      ...structuredClone(running),
      revision: 3,
      updated_at: '2026-09-15T12:00:02.000Z',
      status,
      ...(status === 'STOPPED'
        ? { stop_reason: 'operator requested stop' }
        : {
            failure: {
              code: 'UNLEASH_RECON_FAILED',
              message: 'Reconnaissance ended before a swarm basis was created.',
            },
          }),
    }
    states = [planned, running, state]
  }
  return {
    plan: source.plan,
    registry: source.registry,
    state: states.at(-1),
    stateEvents: states.map((item, index) => event(states[index - 1] ?? null, item)),
    frontier: null,
    basisState: null,
    swarmBasis: null,
    swarmMerge: null,
    swarmCompletion: null,
  }
}

test('builds one immutable self-digested view of progress, routes, gaps, candidates, findings, timeline, and controls', () => {
  const input = fixture()
  const snapshot = createUnleashCampaignSnapshot({ ...input, capturedAt: CAPTURED_AT })

  assert.equal(snapshot.kind, 'last-aperture/unleash-campaign-snapshot')
  assert.equal(snapshot.campaign_id, CAMPAIGN_ID)
  assert.equal(snapshot.status, 'COMPLETE_WITH_GAPS')
  assert.equal(snapshot.routes.count, input.registry.routes.length)
  assert.equal(snapshot.routes.items.find(({ route_id: id }) => id === 'https-recon').completed, true)
  assert.equal(snapshot.gaps.count, snapshot.progress.current_gap_count)
  assert.equal(snapshot.progress.plan_gap_count, input.state.gap_count)
  assert.deepEqual(snapshot.candidates.state_counts, { CANDIDATE: 1 })
  assert.equal(snapshot.candidates.items[0].state, 'CANDIDATE')
  assert.deepEqual(snapshot.findings, {
    count: 0,
    source_status: 'NO_VERIFIED_RECORDS',
    clearance: 'NOT_ESTABLISHED',
    sha256: digestUnleashValue([]),
    items: [],
  })
  assert.deepEqual(snapshot.timeline.items.map(({ revision }) => revision), [1, 2, 3])
  assert.deepEqual(snapshot.controls, {
    stop: { enabled: false, state: 'SETTLED', reason: null },
    resume: { enabled: false, mode: 'NO_OP', authority_check: 'NOT_APPLICABLE' },
  })
  assert.equal(snapshot.trust.absence_of_vulnerabilities, 'NOT_ESTABLISHED')
  assert.equal(snapshot.bindings.state_sha256, digestUnleashValue(input.state))
  assert.equal(snapshot.bindings.candidate_frontier_sha256, input.frontier.frontier_sha256)
  assert.equal(snapshot.bindings.candidate_frontier_head_sha256, input.frontier.head_admission_sha256)
  const { snapshot_sha256: _digest, ...unsigned } = snapshot
  assert.equal(snapshot.snapshot_sha256, digestUnleashValue(unsigned))
  assert.equal(assertValidUnleashCampaignSnapshot(snapshot), snapshot)
  assert.equal(Object.isFrozen(snapshot), true)
  assert.equal(Object.isFrozen(snapshot.routes.items), true)
  assert.equal(Object.isFrozen(snapshot.candidates.items[0]), true)
})

test('projects an active protocol-v2 swarm without promoting its live frontier to findings', () => {
  const input = fixtureV2({ sealed: false })
  const snapshot = createUnleashCampaignSnapshot({ ...input, capturedAt: V2_CAPTURED_AT })

  assert.equal(snapshot.schema_version, '2.0.0')
  assert.equal(snapshot.status, 'SWARMING')
  assert.equal(snapshot.swarm.phase, 'SWARMING')
  assert.equal(snapshot.swarm.terminal_status, null)
  assert.equal(snapshot.swarm.terminal_reason, null)
  assert.equal(snapshot.swarm.usage, null)
  assert.equal(snapshot.swarm.limits.max_merge_json_bytes, 262_144)
  assert.equal(snapshot.swarm.hypotheses.count, 1)
  assert.equal(snapshot.swarm.proposed_actions.count, 1)
  assert.equal(snapshot.swarm.proposed_actions.items[0].state, 'PROPOSED_INERT')
  assert.equal(snapshot.swarm.proposed_actions.items[0].executable, false)
  assert.equal(snapshot.swarm.challenges.count, 1)
  assert.deepEqual(snapshot.swarm.gaps, {
    state_count: 0,
    sealed: false,
    count: 0,
    sha256: digestUnleashValue([]),
    items: [],
  })
  assert.equal(snapshot.candidates.count, 0)
  assert.equal(snapshot.findings.count, 0)
  assert.equal(snapshot.findings.clearance, 'NOT_ESTABLISHED')
  assert.equal(snapshot.bindings.basis_state_sha256, digestUnleashValue(input.basisState))
  assert.equal(snapshot.bindings.swarm_basis_sha256, input.swarmBasis.basis_sha256)
  assert.equal(snapshot.bindings.swarm_merge_sha256, input.swarmMerge.merge_sha256)
  assert.equal(snapshot.bindings.swarm_completion_sha256, null)
  assert.equal(assertValidUnleashCampaignSnapshot(snapshot), snapshot)

  const invalidActionContract = structuredClone(snapshot)
  invalidActionContract.swarm.proposed_actions.items[0].parameters = {}
  assert.throws(
    () => assertValidUnleashCampaignSnapshot(invalidActionContract),
    { code: 'UNLEASH_SNAPSHOT_SCHEMA_INVALID' },
  )
})

test('binds durable Pause and bounded local rollback state into a self-digested protocol-v2 snapshot', () => {
  const input = fixtureV2({ sealed: false })
  const campaignControl = {
    pause: {
      state: 'PAUSED',
      dispatch_open: false,
      reason: 'operator requested pause',
      request_count: 2,
      acknowledgement_count: 1,
    },
    rollback: {
      enabled: true,
      state: 'REQUESTED',
      request_count: 1,
      scope: ['NOT_YET_DISPATCHED', 'PROPOSED_INERT'],
      target_side_effects_reversed: false,
    },
  }
  const snapshot = createUnleashCampaignSnapshot({
    ...input,
    campaignControl,
    capturedAt: V2_CAPTURED_AT,
  })
  assert.deepEqual(snapshot.pause, campaignControl.pause)
  assert.deepEqual(snapshot.rollback, campaignControl.rollback)
  assert.equal(Object.isFrozen(snapshot.pause), true)
  assert.equal(assertValidUnleashCampaignSnapshot(snapshot), snapshot)

  const invalid = structuredClone(campaignControl)
  invalid.rollback.target_side_effects_reversed = true
  assert.throws(
    () => createUnleashCampaignSnapshot({
      ...input,
      campaignControl: invalid,
      capturedAt: V2_CAPTURED_AT,
    }),
    { code: 'UNLEASH_SNAPSHOT_CONTROL_INVALID' },
  )
})

test('projects protocol-v2 pre-basis lifecycle and recon failure states as NOT_STARTED', () => {
  for (const status of ['PLANNED', 'RUNNING', 'FAILED', 'STOPPED']) {
    const input = fixtureV2BeforeSwarm(status)
    const snapshot = createUnleashCampaignSnapshot({ ...input, capturedAt: V2_CAPTURED_AT })

    assert.equal(snapshot.status, status)
    assert.equal(snapshot.swarm.phase, 'NOT_STARTED')
    assert.equal(snapshot.swarm.basis_sha256, null)
    assert.equal(snapshot.swarm.limits, null)
    assert.equal(snapshot.swarm.hypotheses, null)
    assert.equal(snapshot.swarm.proposed_actions, null)
    assert.equal(snapshot.swarm.challenges, null)
    assert.equal(snapshot.swarm.gaps, null)
    assert.equal(snapshot.bindings.basis_state_sha256, null)
    assert.equal(snapshot.bindings.swarm_merge_sha256, null)
    assert.equal(snapshot.bindings.candidate_frontier_sha256, null)
    assert.equal(snapshot.progress.candidate_count, 0)
    assert.equal(snapshot.findings.count, 0)
    assert.equal(snapshot.findings.clearance, 'NOT_ESTABLISHED')
    assert.equal(assertValidUnleashCampaignSnapshot(snapshot), snapshot)
  }
})

test('projects an immutable basis publication crash window without mutating campaign state', () => {
  const input = fixtureV2({ sealed: false })
  input.state = structuredClone(input.basisState)
  input.stateEvents = input.stateEvents.slice(0, input.basisState.revision)
  input.swarmMerge = null
  input.frontier = null
  input.swarmCompletion = null
  const snapshot = createUnleashCampaignSnapshot({ ...input, capturedAt: V2_CAPTURED_AT })

  assert.equal(snapshot.status, 'RUNNING')
  assert.equal(snapshot.swarm_basis_sha256, null)
  assert.equal(snapshot.swarm.phase, 'BASIS_READY')
  assert.equal(snapshot.swarm.basis_sha256, input.swarmBasis.basis_sha256)
  assert.equal(snapshot.bindings.swarm_basis_sha256, input.swarmBasis.basis_sha256)
  assert.equal(snapshot.swarm.merge_sha256, null)
  assert.equal(snapshot.swarm.hypotheses.count, 0)
  assert.equal(snapshot.findings.count, 0)
  assert.equal(assertValidUnleashCampaignSnapshot(snapshot), snapshot)
})

test('projects SWARMING immediately after basis admission with empty live views', () => {
  const input = fixtureV2({ sealed: false })
  input.swarmMerge = null
  const snapshot = createUnleashCampaignSnapshot({ ...input, capturedAt: V2_CAPTURED_AT })

  assert.equal(snapshot.swarm.phase, 'SWARMING')
  assert.equal(snapshot.swarm.round, null)
  assert.equal(snapshot.swarm.merge_sha256, null)
  assert.deepEqual(snapshot.swarm.hypotheses, {
    count: 0,
    sha256: digestUnleashValue([]),
    items: [],
  })
  assert.deepEqual(snapshot.swarm.proposed_actions, {
    count: 0,
    sha256: digestUnleashValue([]),
    items: [],
  })
  assert.equal(snapshot.bindings.swarm_frontier_sha256, null)
  assert.equal(snapshot.bindings.swarm_hypothesis_view_sha256, digestUnleashValue([]))
  assert.equal(snapshot.candidates.count, 0)
  assert.equal(snapshot.findings.count, 0)
  assert.equal(assertValidUnleashCampaignSnapshot(snapshot), snapshot)
})

test('projects merged and admitted recovery-required swarm heads without promoting findings', () => {
  for (const admitted of [false, true]) {
    const input = fixtureV2({ sealed: false })
    if (admitted) {
      input.frontier = frontierV2({
        basisState: input.basisState,
        plan: input.plan,
        swarmBasis: input.swarmBasis,
        merge: input.swarmMerge,
        admitted: true,
      })
    }
    const previous = input.state
    input.state = {
      ...structuredClone(previous),
      revision: previous.revision + 1,
      updated_at: '2026-09-15T12:00:03.000Z',
      status: 'RECONCILIATION_REQUIRED',
      failure: {
        code: 'UNLEASH_SWARM_PUBLICATION_INCOMPLETE',
        message: 'Synthetic interrupted swarm publication.',
      },
    }
    input.stateEvents.push(event(previous, input.state))
    const snapshot = createUnleashCampaignSnapshot({ ...input, capturedAt: V2_CAPTURED_AT })

    assert.equal(snapshot.status, 'RECONCILIATION_REQUIRED')
    assert.equal(snapshot.swarm.phase, 'SWARMING')
    assert.equal(snapshot.swarm.merge_sha256, input.swarmMerge.merge_sha256)
    assert.equal(snapshot.candidates.count, admitted ? input.swarmMerge.candidate_count : 0)
    assert.equal(snapshot.findings.count, 0)
    assert.equal(snapshot.controls.resume.mode, 'RECOVER')
    assert.equal(assertValidUnleashCampaignSnapshot(snapshot), snapshot)
  }
})

test('rejects every partial protocol-v2 swarm artifact context', () => {
  const active = fixtureV2({ sealed: false })
  const cases = [
    { ...active, basisState: null },
    { ...active, swarmBasis: null },
    { ...active, swarmMerge: null, frontier: frontierV2({
      basisState: active.basisState,
      plan: active.plan,
      swarmBasis: active.swarmBasis,
      merge: active.swarmMerge,
      admitted: true,
    }) },
    { ...active, swarmCompletion: fixtureV2().swarmCompletion },
  ]
  for (const input of cases) {
    assert.throws(
      () => createUnleashCampaignSnapshot({ ...input, capturedAt: V2_CAPTURED_AT }),
      (error) => error?.code === 'UNLEASH_SNAPSHOT_SWARM_PARTIAL'
        || error?.code === 'UNLEASH_SNAPSHOT_SWARM_INVALID',
    )
  }
})

test('projects a sealed protocol-v2 swarm with exact usage, termination, challenges, gaps, and frontier bindings', () => {
  const input = fixtureV2()
  const snapshot = createUnleashCampaignSnapshot({ ...input, capturedAt: V2_CAPTURED_AT })

  assert.equal(snapshot.status, 'COMPLETE_WITH_GAPS')
  assert.equal(snapshot.swarm.phase, 'SEALED')
  assert.equal(snapshot.swarm.terminal_status, 'BUDGET_EXHAUSTED')
  assert.equal(snapshot.swarm.terminal_reason, 'DEADLINE')
  assert.deepEqual(snapshot.swarm.usage, {
    rounds_completed: 1,
    provider_calls_started: 2,
    response_bytes: 512,
  })
  assert.equal(snapshot.swarm.gaps.sealed, true)
  assert.equal(snapshot.swarm.gaps.count, 1)
  assert.equal(snapshot.swarm.gaps.items[0].reason_code, 'DEADLINE')
  assert.equal(snapshot.swarm.challenges.items[0].candidate_id, snapshot.swarm.hypotheses.items[0].candidate_id)
  assert.equal(snapshot.candidates.count, snapshot.swarm.hypotheses.count)
  assert.equal(snapshot.progress.current_gap_count, snapshot.gaps.count + snapshot.swarm.gaps.state_count)
  assert.equal(snapshot.bindings.candidate_frontier_sha256, input.frontier.frontier_sha256)
  assert.equal(snapshot.bindings.swarm_completion_sha256, input.swarmCompletion.completion_sha256)
  assert.equal(snapshot.bindings.swarm_frontier_sha256, input.swarmMerge.frontier_sha256)
  assert.equal(snapshot.bindings.swarm_challenge_set_sha256, input.swarmMerge.challenge_set_sha256)
  assert.equal(snapshot.findings.count, 0)
  assert.equal(snapshot.progress.assessment_clearance, 'NOT_ESTABLISHED')
  assert.equal(Object.isFrozen(snapshot.swarm.proposed_actions.items[0]), true)
  assert.equal(assertValidUnleashCampaignSnapshot(snapshot), snapshot)
})

test('keeps an exactly sealed stopped swarm distinct from a completed campaign', () => {
  const input = fixtureV2({ stopped: true })
  const snapshot = createUnleashCampaignSnapshot({ ...input, capturedAt: V2_CAPTURED_AT })

  assert.equal(snapshot.status, 'STOPPED')
  assert.equal(snapshot.swarm.phase, 'SEALED')
  assert.equal(snapshot.swarm.terminal_status, 'STOPPED')
  assert.equal(snapshot.swarm.terminal_reason, 'STOP_REQUESTED')
  assert.equal(snapshot.swarm.gaps.items[0].state, 'STOPPED')
  assert.deepEqual(snapshot.controls, {
    stop: { enabled: false, state: 'SETTLED', reason: 'operator requested stop' },
    resume: { enabled: false, mode: 'NO_OP', authority_check: 'NOT_APPLICABLE' },
  })
  assert.equal(assertValidUnleashCampaignSnapshot(snapshot), snapshot)
})

test('rejects protocol-v2 mixed swarm heads and self-consistent action promotion', () => {
  const input = fixtureV2()
  const frontier = digestRecord({
    ...structuredClone(input.frontier),
    swarm_merge_sha256: '0'.repeat(64),
  }, 'frontier_sha256')
  assert.throws(
    () => createUnleashCampaignSnapshot({ ...input, frontier, capturedAt: V2_CAPTURED_AT }),
    (error) => error?.code === 'UNLEASH_SNAPSHOT_SWARM_SEAL_INVALID'
      || error?.code === 'UNLEASH_SNAPSHOT_FRONTIER_INVALID',
  )

  const snapshot = structuredClone(createUnleashCampaignSnapshot({ ...input, capturedAt: V2_CAPTURED_AT }))
  snapshot.swarm.proposed_actions.items[0].executable = true
  snapshot.swarm.proposed_actions.sha256 = digestUnleashValue(snapshot.swarm.proposed_actions.items)
  snapshot.bindings.swarm_action_view_sha256 = snapshot.swarm.proposed_actions.sha256
  snapshot.snapshot_sha256 = digestRecord(snapshot, 'snapshot_sha256').snapshot_sha256
  assert.throws(
    () => assertValidUnleashCampaignSnapshot(snapshot),
    (error) => error?.code === 'UNLEASH_SNAPSHOT_SCHEMA_INVALID',
  )
})

test('projects actionable controls without loading authority and never treats a provider candidate as a finding', () => {
  const input = fixture({ terminal: false })
  const snapshot = createUnleashCampaignSnapshot({ ...input, capturedAt: CAPTURED_AT })

  assert.deepEqual(snapshot.controls, {
    stop: { enabled: true, state: 'AVAILABLE', reason: null },
    resume: { enabled: true, mode: 'CONTINUE', authority_check: 'REQUIRED_AT_EXECUTION' },
  })
  assert.equal(snapshot.progress.route_open, input.state.route_counts.ready)
  assert.equal(snapshot.candidates.count, 0)
  assert.equal(snapshot.findings.count, 0)
  assert.equal(snapshot.progress.assessment_clearance, 'NOT_ESTABLISHED')
})

test('adds an explicit runtime gap when a ready route terminates without verified completion', () => {
  const input = fixture({ stopped: true })
  const snapshot = createUnleashCampaignSnapshot({ ...input, capturedAt: CAPTURED_AT })
  const runtime = snapshot.gaps.items.filter(({ source }) => source === 'RUNTIME')

  assert.deepEqual(runtime.map(({ route_id: routeId }) => routeId), ['https-recon'])
  assert.equal(runtime[0].gap_state, 'STOPPED')
  assert.equal(runtime[0].reason_code, 'CAMPAIGN_STOPPED_BEFORE_ROUTE_COMPLETION')
  assert.equal(snapshot.progress.route_open, 0)
  assert.equal(snapshot.progress.current_gap_count, input.state.gap_count + 1)
  assert.deepEqual(snapshot.controls, {
    stop: { enabled: false, state: 'SETTLED', reason: 'operator requested stop' },
    resume: { enabled: false, mode: 'NO_OP', authority_check: 'NOT_APPLICABLE' },
  })
})

test('distinguishes durable stop reconciliation from general recovery', () => {
  const base = fixture({ terminal: false })
  const stoppingState = {
    ...structuredClone(base.state),
    revision: 3,
    updated_at: '2026-09-15T12:00:02.000Z',
    status: 'STOP_REQUESTED',
    stop_reason: 'operator requested stop',
  }
  const stoppingFrontier = digestRecord({
    ...structuredClone(base.frontier),
    campaign_state_revision: stoppingState.revision,
    campaign_state_sha256: digestUnleashValue(stoppingState),
  }, 'frontier_sha256')
  const stopping = createUnleashCampaignSnapshot({
    ...base,
    state: stoppingState,
    stateEvents: [...base.stateEvents, event(base.state, stoppingState)],
    frontier: stoppingFrontier,
    capturedAt: CAPTURED_AT,
  })
  assert.deepEqual(stopping.controls, {
    stop: { enabled: true, state: 'REQUESTED', reason: 'operator requested stop' },
    resume: { enabled: true, mode: 'STOP_RECONCILIATION_ONLY', authority_check: 'NOT_APPLICABLE' },
  })

  const recoveringState = {
    ...structuredClone(base.state),
    revision: 3,
    updated_at: '2026-09-15T12:00:02.000Z',
    status: 'RECONCILIATION_REQUIRED',
    failure: {
      code: 'UNLEASH_RECON_RECOVERY_INCOMPLETE',
      message: 'Retained reconnaissance requires reconciliation before another action.',
    },
  }
  const recoveringFrontier = digestRecord({
    ...structuredClone(base.frontier),
    campaign_state_revision: recoveringState.revision,
    campaign_state_sha256: digestUnleashValue(recoveringState),
  }, 'frontier_sha256')
  const recovering = createUnleashCampaignSnapshot({
    ...base,
    state: recoveringState,
    stateEvents: [...base.stateEvents, event(base.state, recoveringState)],
    frontier: recoveringFrontier,
    capturedAt: CAPTURED_AT,
  })
  assert.deepEqual(recovering.controls, {
    stop: { enabled: true, state: 'AVAILABLE', reason: null },
    resume: { enabled: true, mode: 'RECOVER', authority_check: 'REQUIRED_AT_EXECUTION' },
  })
  assert.equal(recovering.gaps.items.some(({ gap_state: state }) => state === 'RECONCILIATION_REQUIRED'), true)
})

test('rejects mixed heads, forged registries, provider proof promotion, and unexpected controller inputs', () => {
  const input = fixture()
  const mixedEvents = structuredClone(input.stateEvents)
  mixedEvents.at(-1).state_sha256 = '0'.repeat(64)
  assert.throws(
    () => createUnleashCampaignSnapshot({ ...input, stateEvents: mixedEvents, capturedAt: CAPTURED_AT }),
    (error) => error?.code === 'UNLEASH_SNAPSHOT_EVENT_INVALID',
  )

  const registry = structuredClone(input.registry)
  registry.routes[0].required_effect = 'EXECUTE_PROOF'
  assert.throws(
    () => createUnleashCampaignSnapshot({ ...input, registry, capturedAt: CAPTURED_AT }),
    (error) => error?.code === 'UNLEASH_SNAPSHOT_REGISTRY_DRIFT',
  )

  const frontier = structuredClone(input.frontier)
  frontier.candidates[0].state = 'AUTHENTICATED_VERIFIED'
  frontier.candidates[0] = digestRecord(frontier.candidates[0], 'candidate_sha256')
  frontier.frontier_sha256 = digestRecord(frontier, 'frontier_sha256').frontier_sha256
  assert.throws(
    () => createUnleashCampaignSnapshot({ ...input, frontier, capturedAt: CAPTURED_AT }),
    (error) => error?.code === 'UNLEASH_SNAPSHOT_FRONTIER_INVALID',
  )

  assert.throws(
    () => createUnleashCampaignSnapshot({ ...input, capturedAt: CAPTURED_AT, policy: deploymentPolicy() }),
    (error) => error?.code === 'UNLEASH_SNAPSHOT_INPUT_INVALID',
  )
})

test('the public verifier rejects a tampered or self-consistently overstated snapshot', () => {
  const input = fixture()
  const snapshot = createUnleashCampaignSnapshot({ ...input, capturedAt: CAPTURED_AT })
  const tampered = structuredClone(snapshot)
  tampered.findings.clearance = 'ESTABLISHED'
  tampered.snapshot_sha256 = digestRecord(tampered, 'snapshot_sha256').snapshot_sha256

  assert.throws(
    () => assertValidUnleashCampaignSnapshot(tampered),
    (error) => error?.code === 'UNLEASH_SNAPSHOT_SCHEMA_INVALID',
  )
})

test('rejects computed builder input without invoking its accessor', () => {
  const input = { ...fixture(), capturedAt: CAPTURED_AT }
  let getterCalls = 0
  Object.defineProperty(input, 'plan', {
    enumerable: true,
    get() {
      getterCalls += 1
      throw new Error('snapshot builder invoked hostile computed input')
    },
  })

  assert.throws(
    () => createUnleashCampaignSnapshot(input),
    (error) => error?.code === 'UNLEASH_SNAPSHOT_INPUT_INVALID',
  )
  assert.equal(getterCalls, 0)
})

test('rejects a computed public snapshot without invoking its accessor', () => {
  const snapshot = structuredClone(createUnleashCampaignSnapshot({
    ...fixture(),
    capturedAt: CAPTURED_AT,
  }))
  let getterCalls = 0
  Object.defineProperty(snapshot, 'status', {
    enumerable: true,
    get() {
      getterCalls += 1
      throw new Error('snapshot verifier invoked hostile computed state')
    },
  })

  assert.throws(
    () => assertValidUnleashCampaignSnapshot(snapshot),
    (error) => error?.code === 'UNLEASH_SNAPSHOT_VALUE_INVALID',
  )
  assert.equal(getterCalls, 0)
})
