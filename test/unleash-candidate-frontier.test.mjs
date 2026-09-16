import assert from 'node:assert/strict'
import { resolve } from 'node:path'
import test from 'node:test'

import {
  UnleashCandidateFrontierError,
  UNLEASH_CANDIDATE_FRONTIER_STATE_FILE,
  assertValidUnleashCandidateAdmission,
  assertValidUnleashCandidateAdmissionV2,
  assertValidUnleashCandidateFrontierState,
  assertValidUnleashCandidateFrontierStateV2,
  createUnleashCandidateAdmission,
  createUnleashCandidateAdmissionV2,
  createUnleashCandidateFrontierState,
  createUnleashCandidateFrontierStateV2,
  createEmptyUnleashCandidateFrontier,
  createEmptyUnleashCandidateFrontierV2,
  getUnleashCandidateFrontierAdmissionReferences,
  previewUnleashCandidateFrontierAppend,
  previewUnleashCandidateFrontierAppendV2,
  reconcileUnleashCandidateFrontierState,
  reconcileUnleashCandidateFrontierStateV2,
  recoverUnleashCandidateFrontier,
  recoverUnleashCandidateFrontierV2,
  snapshotUnleashProviderProposal,
} from '../scripts/lib/unleash-candidate-frontier.mjs'
import { createUnleashPlan, digestUnleashValue } from '../scripts/lib/unleash-contracts.mjs'
import { createUnleashDeploymentPolicy } from '../scripts/lib/unleash-policy.mjs'
import { createVerifiedReconCompletion } from '../scripts/lib/unleash-recon-evidence.mjs'
import { createDefaultUnleashPlannerDependencies } from '../scripts/lib/unleash-registry.mjs'
import {
  UNLEASH_SWARM_DEFAULT_LIMITS,
  createUnleashRoleRequest,
  createUnleashSwarmBasis,
} from '../scripts/lib/unleash-swarm-contracts.mjs'
import { mergeUnleashSwarmResponses } from '../scripts/lib/unleash-swarm-merge.mjs'

const TARGET = 'https://example.test/'
const OBSERVED_AT = '2026-09-15T09:30:00.000Z'
const ADMITTED_AT = '2026-09-15T09:31:00.000Z'
const RUN_DIRECTORY = resolve('C:/synthetic/LastAperture/campaigns/campaign-0123456789abcdef01234567')
const V1_PROVIDER = Object.freeze({
  protocol_version: '1.0.0',
  proposal_kind: 'last-aperture/unleash-proposal',
})

function deploymentPolicy() {
  return createUnleashDeploymentPolicy({
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-deployment-policy',
    policy_id: 'policy:candidate-frontier-test',
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
    revocation: { check_id: 'revocation:candidate-frontier-test', fail_mode: 'CLOSED' },
  })
}

function routeCounts(plan) {
  const counts = { total: plan.route_dispositions.length, ready: 0, waiting: 0, unavailable: 0, not_applicable: 0, blocked: 0 }
  for (const route of plan.route_dispositions) {
    if (route.disposition === 'READY') counts.ready += 1
    else if (['WAITING_FOR_MATERIAL', 'WAITING_FOR_DEPENDENCY'].includes(route.disposition)) counts.waiting += 1
    else if (route.disposition === 'UNAVAILABLE') counts.unavailable += 1
    else if (route.disposition === 'NOT_APPLICABLE') counts.not_applicable += 1
    else if (route.disposition === 'BLOCKED_BY_POLICY') counts.blocked += 1
  }
  return counts
}

async function campaignArtifacts() {
  const policy = deploymentPolicy()
  const planner = createDefaultUnleashPlannerDependencies({ policy, provider: V1_PROVIDER })
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
      run_id: 'run:candidate-frontier-fixture',
      plan_sha256: '6'.repeat(64),
      authorization: structuredClone(authority),
      target: { origin: new URL(TARGET).origin },
      actions: [{ method: 'HEAD', url: TARGET, safe_to_get: false }],
      event_chain: { count: 3, last_sha256: '8'.repeat(64) },
    },
    observations: [{ authority: structuredClone(authority), method: 'HEAD', url: TARGET }],
  }
  const completion = await createVerifiedReconCompletion({ bundle: resolve(RUN_DIRECTORY, 'recon'), plan }, {
    now: () => new Date(OBSERVED_AT),
    readVerifiedRecon: async () => structuredClone(verified),
  })
  const counts = routeCounts(plan)
  const campaignState = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-state',
    revision: 3,
    updated_at: OBSERVED_AT,
    campaign_id: `campaign:sha256:${'3'.repeat(64)}`,
    status: counts.waiting + counts.unavailable + counts.blocked === 0 ? 'COMPLETE' : 'COMPLETE_WITH_GAPS',
    run_directory: RUN_DIRECTORY,
    plan_sha256: plan.plan_sha256,
    target: structuredClone(plan.target),
    completed_routes: ['https-recon'],
    route_counts: counts,
    gap_count: counts.waiting + counts.unavailable + counts.blocked,
    recon_bundle: resolve(RUN_DIRECTORY, 'recon'),
    evidence_packet_path: resolve(RUN_DIRECTORY, 'evidence-packet.json'),
    evidence_packet_sha256: completion.evidence_packet.packet_sha256,
    completion_receipt_sha256: completion.completion_receipt.completion_receipt_sha256,
    stop_reason: null,
    failure: null,
  }
  return {
    plan,
    registry: planner.registry,
    provider: planner.provider,
    campaignState,
    evidencePacket: completion.evidence_packet,
    completion,
  }
}

async function campaignArtifactsV2() {
  const policy = deploymentPolicy()
  const planner = createDefaultUnleashPlannerDependencies({ policy })
  const plan = createUnleashPlan({ target: TARGET }, planner)
  assert.equal(plan.provider_protocol_version, '2.0.0')
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
      run_id: 'run:candidate-frontier-v2-fixture',
      plan_sha256: '5'.repeat(64),
      authorization: structuredClone(authority),
      target: { origin: new URL(TARGET).origin },
      actions: [{ method: 'HEAD', url: TARGET, safe_to_get: false }],
      event_chain: { count: 3, last_sha256: '7'.repeat(64) },
    },
    observations: [{ authority: structuredClone(authority), method: 'HEAD', url: TARGET }],
  }
  const completion = await createVerifiedReconCompletion({ bundle: resolve(RUN_DIRECTORY, 'recon'), plan }, {
    now: () => new Date(OBSERVED_AT),
    readVerifiedRecon: async () => structuredClone(verified),
  })
  const counts = routeCounts(plan)
  const base = {
    kind: 'last-aperture/unleash-state',
    campaign_id: `campaign:sha256:${'4'.repeat(64)}`,
    run_directory: RUN_DIRECTORY,
    plan_sha256: plan.plan_sha256,
    target: structuredClone(plan.target),
    route_counts: counts,
    gap_count: counts.waiting + counts.unavailable + counts.blocked,
    recon_bundle: resolve(RUN_DIRECTORY, 'recon'),
    stop_reason: null,
    failure: null,
    swarm_completion_sha256: null,
    candidate_frontier_sha256: null,
    candidate_frontier_head_sha256: null,
    swarm_gap_count: 0,
  }
  const basisState = {
    ...structuredClone(base),
    schema_version: '2.0.0',
    revision: 2,
    updated_at: '2026-09-15T09:20:00.000Z',
    status: 'RUNNING',
    completed_routes: [],
    evidence_packet_path: null,
    evidence_packet_sha256: null,
    completion_receipt_sha256: null,
    swarm_basis_sha256: null,
  }
  const swarmBasis = createUnleashSwarmBasis({
    recordedAt: '2026-09-15T09:30:30.000Z',
    campaignId: basisState.campaign_id,
    campaignStateRevision: basisState.revision,
    campaignStateSha256: digestUnleashValue(basisState),
    planSha256: plan.plan_sha256,
    targetId: plan.target.target_id,
    registrySha256: digestUnleashValue(planner.registry),
    providerProfileSha256: digestUnleashValue(planner.provider),
    evidencePacketSha256: completion.evidence_packet.packet_sha256,
    completionReceiptSha256: completion.completion_receipt.completion_receipt_sha256,
    limits: structuredClone(UNLEASH_SWARM_DEFAULT_LIMITS),
  })
  const evidenceRef = completion.evidence_packet.sources[0].evidence_ref
  const evidenceSha256 = evidenceRef.split(':').at(-1)
  const roleRequest = createUnleashRoleRequest({
    basis: swarmBasis,
    round: 1,
    roleId: 'attacker:perimeter',
    inputFrontierSha256: digestUnleashValue({ candidates: [], actions: [] }),
    inputChallengeSetSha256: digestUnleashValue([]),
    evidenceRefs: [evidenceRef],
    allowedToolIds: ['tool:https-recon'],
    artifacts: [{
      artifact_id: `artifact:sha256:${evidenceSha256}`,
      kind: 'EVIDENCE',
      logical_name: 'verified-recon-evidence.json',
      sha256: evidenceSha256,
      size: 128,
    }],
  })
  const roleResponse = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-role-response',
    request_id: roleRequest.request_id,
    request_sha256: roleRequest.request_sha256,
    basis_sha256: roleRequest.basis_sha256,
    plan_sha256: roleRequest.plan_sha256,
    round: roleRequest.round,
    role_id: roleRequest.role_id,
    role_kind: roleRequest.role_kind,
    wave: roleRequest.wave,
    proposal: {
      schema_version: '1.0.0',
      kind: 'last-aperture/unleash-proposal',
      proposal_id: 'proposal:candidate-frontier-v2-source',
      plan_sha256: plan.plan_sha256,
      provider_protocol_version: '2.0.0',
      candidates: [{
        candidate_id: 'candidate:candidate-frontier-v2-source',
        title: 'Candidate hypothesis from the final swarm merge',
        hypothesis: 'The observed service metadata may indicate a security invariant worth testing.',
        invariant: 'Untrusted input must not change a security-sensitive destination.',
        confidence: 'MEDIUM',
        evidence_refs: [evidenceRef],
        competing_explanations: ['The observed behavior may be an intentional bounded redirect.'],
      }],
      actions: [{
        action_id: 'action:candidate-frontier-v2-source',
        candidate_id: 'candidate:candidate-frontier-v2-source',
        tool_id: 'tool:https-recon',
        evidence_refs: [evidenceRef],
        parameters: { method: 'HEAD' },
        expected_observation: 'A bounded HEAD observation associated with the candidate.',
      }],
    },
    challenges: [],
  }
  const swarmMerge = mergeUnleashSwarmResponses({
    basis: swarmBasis,
    round: 1,
    previous: null,
    responses: [roleResponse],
  })
  const campaignState = {
    ...structuredClone(base),
    schema_version: '2.0.0',
    revision: 3,
    updated_at: swarmBasis.recorded_at,
    status: 'SWARMING',
    completed_routes: [completion.completion_receipt.route_id],
    evidence_packet_path: resolve(RUN_DIRECTORY, 'evidence-packet.json'),
    evidence_packet_sha256: completion.evidence_packet.packet_sha256,
    completion_receipt_sha256: completion.completion_receipt.completion_receipt_sha256,
    swarm_basis_sha256: swarmBasis.basis_sha256,
  }
  return {
    plan,
    registry: planner.registry,
    provider: planner.provider,
    basisState,
    campaignState,
    evidencePacket: completion.evidence_packet,
    completion,
    swarmBasis,
    swarmMerge,
    swarmCompletion: null,
  }
}

function sealedArtifactsV2(artifacts, frontier, completedAt = '2026-09-15T09:35:00.000Z') {
  const unsignedCompletion = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-swarm-completion',
    completed_at: completedAt,
    basis_sha256: artifacts.swarmBasis.basis_sha256,
    campaign_id: artifacts.basisState.campaign_id,
    plan_sha256: artifacts.plan.plan_sha256,
    status: 'QUIESCENT',
    reason: 'FRONTIER_STABLE',
    merge_sha256: artifacts.swarmMerge.merge_sha256,
    frontier_sha256: artifacts.swarmMerge.frontier_sha256,
    challenge_set_sha256: artifacts.swarmMerge.challenge_set_sha256,
    candidate_count: artifacts.swarmMerge.candidate_count,
    proposed_action_count: artifacts.swarmMerge.proposed_action_count,
    challenge_count: artifacts.swarmMerge.challenge_count,
    attempt_ledger: {
      event_count: 4,
      attempt_count: 1,
      head_record_sha256: 'e'.repeat(64),
      ledger_sha256: 'f'.repeat(64),
    },
    usage: { rounds_completed: 1, provider_calls_started: 1, response_bytes: 128 },
    gaps: [],
  }
  const swarmCompletion = {
    ...unsignedCompletion,
    completion_sha256: digestUnleashValue(unsignedCompletion),
  }
  const campaignState = {
    ...structuredClone(artifacts.campaignState),
    revision: artifacts.campaignState.revision + 1,
    updated_at: completedAt,
    status: artifacts.campaignState.gap_count === 0 ? 'COMPLETE' : 'COMPLETE_WITH_GAPS',
    swarm_completion_sha256: swarmCompletion.completion_sha256,
    candidate_frontier_sha256: frontier.frontier_sha256,
    candidate_frontier_head_sha256: frontier.head_admission_sha256,
    swarm_gap_count: 0,
  }
  return { ...artifacts, campaignState, swarmCompletion }
}

function stoppedSealedArtifactsV2(artifacts, frontier) {
  const sealed = sealedArtifactsV2(artifacts, frontier)
  const unsignedCompletion = {
    ...structuredClone(sealed.swarmCompletion),
    status: 'STOPPED',
    reason: 'STOP_REQUESTED',
  }
  delete unsignedCompletion.completion_sha256
  const swarmCompletion = {
    ...unsignedCompletion,
    completion_sha256: digestUnleashValue(unsignedCompletion),
  }
  const campaignState = {
    ...structuredClone(sealed.campaignState),
    status: 'STOPPED',
    stop_reason: 'Operator requested stop.',
    swarm_completion_sha256: swarmCompletion.completion_sha256,
  }
  return { ...sealed, campaignState, swarmCompletion }
}

function proposal(artifacts, suffix = '001') {
  const evidenceRef = artifacts.evidencePacket.sources[0].evidence_ref
  const candidateId = `candidate:test-${suffix}`
  return {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-proposal',
    proposal_id: `proposal:test-${suffix}`,
    plan_sha256: artifacts.plan.plan_sha256,
    provider_protocol_version: artifacts.plan.provider_protocol_version,
    candidates: [{
      candidate_id: candidateId,
      title: `Candidate hypothesis ${suffix}`,
      hypothesis: 'The observed service metadata may indicate a security invariant worth testing.',
      invariant: 'Untrusted input must not change a security-sensitive destination.',
      confidence: 'MEDIUM',
      evidence_refs: [evidenceRef],
      competing_explanations: ['The observed behavior may be an intentional bounded redirect.'],
    }],
    actions: [{
      action_id: `action:test-${suffix}`,
      candidate_id: candidateId,
      tool_id: 'tool:https-recon',
      evidence_refs: [evidenceRef],
      parameters: { method: 'HEAD' },
      expected_observation: 'A bounded HEAD observation associated with the candidate.',
    }],
  }
}

function largeProposal(artifacts, suffix, candidateCount = 60) {
  const value = proposal(artifacts, suffix)
  value.candidates = Array.from({ length: candidateCount }, (_, index) => ({
    ...structuredClone(value.candidates[0]),
    candidate_id: `candidate:large-${suffix}-${String(index).padStart(3, '0')}`,
    title: 't'.repeat(4096),
    hypothesis: 'h'.repeat(4096),
    invariant: 'i'.repeat(4096),
  }))
  value.actions = []
  return value
}

function context(artifacts, previousAdmission = null) {
  return { ...artifacts, previousAdmission }
}

function createAdmission(artifacts, candidateProposal, sequence = 1, previousAdmission = null, time = ADMITTED_AT) {
  return createUnleashCandidateAdmission({
    ...context(artifacts, previousAdmission),
    proposal: candidateProposal,
    sequence,
    recordedAt: new Date(time),
  })
}

function contextV2(artifacts, previousAdmission = null) {
  return {
    plan: artifacts.plan,
    registry: artifacts.registry,
    provider: artifacts.provider,
    basisState: artifacts.basisState,
    campaignState: artifacts.campaignState,
    evidencePacket: artifacts.evidencePacket,
    completion: artifacts.completion,
    swarmBasis: artifacts.swarmBasis,
    swarmMerge: artifacts.swarmMerge,
    swarmCompletion: artifacts.swarmCompletion,
    previousAdmission,
  }
}

function createAdmissionV2(artifacts, candidateProposal, sequence = 1, previousAdmission = null, time = ADMITTED_AT) {
  return createUnleashCandidateAdmissionV2({
    ...contextV2(artifacts, previousAdmission),
    proposal: candidateProposal,
    sequence,
    recordedAt: new Date(time),
  })
}

function recoveryInputV2(artifacts, storage) {
  const { previousAdmission: _previous, ...context } = contextV2(artifacts)
  return { storage, ...context }
}

function frontierStateContextV2(artifacts, frontier) {
  return {
    frontier,
    basisState: artifacts.basisState,
    campaignState: artifacts.campaignState,
    swarmBasis: artifacts.swarmBasis,
    swarmMerge: artifacts.swarmMerge,
    swarmCompletion: artifacts.swarmCompletion,
  }
}

function memoryStorage(baseFilenames = []) {
  const files = new Map()
  return {
    files,
    readJson: async (filename) => {
      if (!files.has(filename)) throw Object.assign(new Error('missing'), { code: 'UNLEASH_STORAGE_FILE_NOT_FOUND' })
      return structuredClone(files.get(filename))
    },
    listJsonFilenames: async () => Object.freeze([...baseFilenames, ...files.keys()].sort()),
  }
}

function rejectsFrontierCode(code) {
  return (error) => error instanceof UnleashCandidateFrontierError && error.code === code
}

test('creates one exact candidate-only admission and projects provider actions as inert data', async () => {
  const artifacts = await campaignArtifacts()
  const candidateProposal = proposal(artifacts)
  const admission = createAdmission(artifacts, candidateProposal)

  assert.equal(assertValidUnleashCandidateAdmission(admission, context(artifacts)), admission)
  assert.equal(Object.isFrozen(admission), true)
  assert.equal(Object.isFrozen(admission.proposal.candidates[0]), true)
  assert.equal(admission.disposition.candidate_state, 'CANDIDATE')
  assert.equal(admission.disposition.semantic_authority, 'NONE')
  assert.equal(admission.disposition.proof_authority, 'NONE')
  assert.equal(admission.disposition.actions_executable, false)
  assert.equal(admission.proposal_sha256, digestUnleashValue(candidateProposal))
  const { admission_sha256: admissionSha256, ...unsignedAdmission } = admission
  assert.equal(admissionSha256, digestUnleashValue(unsignedAdmission))

  const storage = memoryStorage(['campaign-plan.json', 'campaign-state.json'])
  storage.files.set('candidate-admission-000001.json', admission)
  const frontier = await recoverUnleashCandidateFrontier({ storage, ...artifacts })

  assert.equal(frontier.proposal_count, 1)
  assert.equal(frontier.candidate_count, 1)
  assert.equal(frontier.proposed_action_count, 1)
  assert.equal(frontier.head_admission_sha256, admission.admission_sha256)
  assert.equal(frontier.candidates[0].state, 'CANDIDATE')
  assert.equal(frontier.candidates[0].provider_confidence, 'MEDIUM')
  assert.deepEqual(frontier.candidates[0].proposed_action_ids, ['action:test-001'])
  assert.equal(frontier.actions[0].state, 'PROPOSED_INERT')
  assert.equal(frontier.actions[0].executable, false)
  const { candidate_sha256: candidateSha256, ...unsignedCandidate } = frontier.candidates[0]
  const { action_sha256: actionSha256, ...unsignedAction } = frontier.actions[0]
  const { frontier_sha256: frontierSha256, ...unsignedFrontier } = frontier
  assert.equal(candidateSha256, digestUnleashValue(unsignedCandidate))
  assert.equal(actionSha256, digestUnleashValue(unsignedAction))
  assert.equal(frontierSha256, digestUnleashValue(unsignedFrontier))
  assert.equal(Object.isFrozen(frontier), true)
  assert.equal(Object.isFrozen(frontier.actions[0].parameters), true)
})

test('creates the same self-bound empty frontier shape for a non-complete campaign', async () => {
  const artifacts = await campaignArtifacts()
  const campaignState = structuredClone(artifacts.campaignState)
  campaignState.revision = 2
  campaignState.status = 'RUNNING'
  campaignState.completed_routes = []
  campaignState.evidence_packet_path = null
  campaignState.evidence_packet_sha256 = null
  campaignState.completion_receipt_sha256 = null
  const frontier = createEmptyUnleashCandidateFrontier({
    plan: artifacts.plan,
    campaignState,
  })

  assert.deepEqual(Object.keys(frontier).sort(), [
    'actions',
    'campaign_id',
    'campaign_state_revision',
    'campaign_state_sha256',
    'candidate_count',
    'candidates',
    'completion_receipt_sha256',
    'evidence_packet_sha256',
    'frontier_sha256',
    'head_admission_sha256',
    'kind',
    'plan_sha256',
    'proposal_count',
    'proposed_action_count',
    'schema_version',
    'target_id',
  ].sort())
  assert.equal(frontier.evidence_packet_sha256, null)
  assert.equal(frontier.completion_receipt_sha256, null)
  assert.equal(frontier.head_admission_sha256, null)
  assert.equal(frontier.candidate_count, 0)
  assert.deepEqual(frontier.candidates, [])
  const { frontier_sha256: frontierSha256, ...unsigned } = frontier
  assert.equal(frontierSha256, digestUnleashValue(unsigned))
  assert.equal(Object.isFrozen(frontier), true)

  assert.throws(
    () => createEmptyUnleashCandidateFrontier({ plan: artifacts.plan, campaignState: artifacts.campaignState }),
    rejectsFrontierCode('UNLEASH_CANDIDATE_CAMPAIGN_COMPLETE'),
  )
  const drifted = structuredClone(campaignState)
  drifted.route_counts.ready += 1
  drifted.route_counts.not_applicable -= 1
  assert.throws(
    () => createEmptyUnleashCandidateFrontier({ plan: artifacts.plan, campaignState: drifted }),
    rejectsFrontierCode('UNLEASH_CANDIDATE_CAMPAIGN_DRIFT'),
  )
})

test('admits only exact plan-bound proposals whose evidence exists in the retained packet', async () => {
  const artifacts = await campaignArtifacts()
  for (const mutate of [
    (value) => { value.plan_sha256 = '0'.repeat(64) },
    (value) => { value.provider_protocol_version = '2.0.0' },
    (value) => { value.candidates[0].evidence_refs = [`evidence:sha256:${'0'.repeat(64)}`] },
    (value) => { value.candidates[0].proof_state = 'AUTHENTICATED_VERIFIED' },
  ]) {
    const candidateProposal = proposal(artifacts)
    mutate(candidateProposal)
    assert.throws(() => createAdmission(artifacts, candidateProposal))
  }

  const driftedState = structuredClone(artifacts.campaignState)
  driftedState.evidence_packet_sha256 = '0'.repeat(64)
  assert.throws(
    () => createAdmission({ ...artifacts, campaignState: driftedState }, proposal(artifacts)),
    /campaign|evidence|state/i,
  )

  const driftedCounts = structuredClone(artifacts.campaignState)
  driftedCounts.route_counts.ready += 1
  driftedCounts.route_counts.not_applicable -= 1
  assert.throws(
    () => createAdmission({ ...artifacts, campaignState: driftedCounts }, proposal(artifacts)),
    rejectsFrontierCode('UNLEASH_CANDIDATE_CAMPAIGN_DRIFT'),
  )

  const running = structuredClone(artifacts.campaignState)
  running.status = 'RUNNING'
  running.completed_routes = []
  running.evidence_packet_path = null
  running.evidence_packet_sha256 = null
  running.completion_receipt_sha256 = null
  assert.throws(
    () => createAdmission({ ...artifacts, campaignState: running }, proposal(artifacts)),
    rejectsFrontierCode('UNLEASH_CANDIDATE_CAMPAIGN_NOT_COMPLETE'),
  )
})

test('rejects computed proposal data without invoking the accessor and bounds durable admission bytes', async () => {
  const artifacts = await campaignArtifacts()
  const computed = proposal(artifacts)
  let getterCalls = 0
  Object.defineProperty(computed.candidates[0], 'title', {
    enumerable: true,
    get: () => { getterCalls += 1; return 'computed title' },
  })
  assert.throws(() => createAdmission(artifacts, computed))
  assert.equal(getterCalls, 0)

  const source = proposal(artifacts, 'snapshot')
  const snapshot = snapshotUnleashProviderProposal(source)
  source.candidates[0].title = 'mutated after snapshot'
  assert.equal(snapshot.candidates[0].title, 'Candidate hypothesis snapshot')
  assert.equal(Object.isFrozen(snapshot), true)
  assert.equal(Object.isFrozen(snapshot.candidates[0]), true)

  const oversized = proposal(artifacts)
  oversized.candidates = Array.from({ length: 300 }, (_, index) => ({
    ...structuredClone(oversized.candidates[0]),
    candidate_id: `candidate:oversized-${String(index).padStart(3, '0')}`,
    hypothesis: 'x'.repeat(4096),
  }))
  oversized.actions = []
  assert.throws(
    () => createAdmission(artifacts, oversized),
    rejectsFrontierCode('UNLEASH_CANDIDATE_VALUE_INVALID'),
  )
})

test('recovers a contiguous multi-proposal chain with deterministic global ordering', async () => {
  const artifacts = await campaignArtifacts()
  const first = createAdmission(artifacts, proposal(artifacts, 'z'))
  const second = createAdmission(artifacts, proposal(artifacts, 'a'), 2, first, '2026-09-15T09:32:00.000Z')
  const storage = memoryStorage()
  storage.files.set('candidate-admission-000002.json', second)
  storage.files.set('candidate-admission-000001.json', first)

  const frontier = await recoverUnleashCandidateFrontier({ storage, ...artifacts })

  assert.equal(frontier.proposal_count, 2)
  assert.equal(frontier.candidate_count, 2)
  assert.deepEqual(frontier.candidates.map(({ candidate_id: id }) => id), ['candidate:test-a', 'candidate:test-z'])
  assert.deepEqual(frontier.actions.map(({ action_id: id }) => id), ['action:test-a', 'action:test-z'])
  assert.equal(frontier.head_admission_sha256, second.admission_sha256)
})

test('fails closed when a concurrent admission changes the recovered inventory', async () => {
  const artifacts = await campaignArtifacts()
  const first = createAdmission(artifacts, proposal(artifacts, '001'))
  let inventories = 0
  const storage = {
    readJson: async () => structuredClone(first),
    listJsonFilenames: async () => {
      inventories += 1
      return inventories === 1
        ? ['candidate-admission-000001.json']
        : ['candidate-admission-000001.json', 'candidate-admission-000002.json']
    },
  }
  await assert.rejects(
    recoverUnleashCandidateFrontier({ storage, ...artifacts }),
    rejectsFrontierCode('UNLEASH_CANDIDATE_FRONTIER_CHANGED'),
  )
})

test('fails closed when a same-name admission is replaced during recovery', async () => {
  const artifacts = await campaignArtifacts()
  const first = createAdmission(artifacts, proposal(artifacts, 'first'))
  const replacement = createAdmission(artifacts, proposal(artifacts, 'replacement'))
  let reads = 0
  const storage = {
    readJson: async () => {
      reads += 1
      return structuredClone(reads === 1 ? first : replacement)
    },
    listJsonFilenames: async () => ['candidate-admission-000001.json'],
  }
  await assert.rejects(
    recoverUnleashCandidateFrontier({ storage, ...artifacts }),
    rejectsFrontierCode('UNLEASH_CANDIDATE_FRONTIER_CHANGED'),
  )
})

test('rechecks admission bytes after the final inventory snapshot', async () => {
  const artifacts = await campaignArtifacts()
  const first = createAdmission(artifacts, proposal(artifacts, 'first'))
  const replacement = createAdmission(artifacts, proposal(artifacts, 'replacement'))
  let current = first
  let inventories = 0
  const storage = {
    readJson: async () => structuredClone(current),
    listJsonFilenames: async () => {
      inventories += 1
      if (inventories === 3) current = replacement
      return ['candidate-admission-000001.json']
    },
  }
  await assert.rejects(
    recoverUnleashCandidateFrontier({ storage, ...artifacts }),
    rejectsFrontierCode('UNLEASH_CANDIDATE_FRONTIER_CHANGED'),
  )
})

test('snapshots retained context before storage can mutate caller-owned artifacts', async () => {
  const artifacts = structuredClone(await campaignArtifacts())
  const originalCampaignId = artifacts.campaignState.campaign_id
  let inventories = 0
  const storage = {
    readJson: async () => { throw new Error('unexpected read') },
    listJsonFilenames: async () => {
      inventories += 1
      if (inventories === 1) {
        artifacts.campaignState.campaign_id = `campaign:sha256:${'9'.repeat(64)}`
        artifacts.plan.target.display = 'mutated after recovery began'
      }
      return []
    },
  }
  const frontier = await recoverUnleashCandidateFrontier({ storage, ...artifacts })
  assert.equal(frontier.campaign_id, originalCampaignId)
  assert.notEqual(artifacts.campaignState.campaign_id, originalCampaignId)
})

test('fully validates a preceding admission before extending its digest', async () => {
  const artifacts = await campaignArtifacts()
  const first = createAdmission(artifacts, proposal(artifacts, '001'))
  const invalidPrevious = structuredClone(first)
  invalidPrevious.proposal.candidates[0].evidence_refs = [`evidence:sha256:${'0'.repeat(64)}`]
  invalidPrevious.proposal_sha256 = digestUnleashValue(invalidPrevious.proposal)
  delete invalidPrevious.admission_sha256
  invalidPrevious.admission_sha256 = digestUnleashValue(invalidPrevious)

  assert.throws(
    () => createAdmission(
      artifacts,
      proposal(artifacts, '002'),
      2,
      invalidPrevious,
      '2026-09-15T09:32:00.000Z',
    ),
    /evidence/i,
  )

  const forgedRoot = structuredClone(first)
  forgedRoot.previous_admission_sha256 = '0'.repeat(64)
  delete forgedRoot.admission_sha256
  forgedRoot.admission_sha256 = digestUnleashValue(forgedRoot)
  assert.throws(
    () => createAdmission(
      artifacts,
      proposal(artifacts, '003'),
      2,
      forgedRoot,
      '2026-09-15T09:32:00.000Z',
    ),
    rejectsFrontierCode('UNLEASH_CANDIDATE_CHAIN_INVALID'),
  )
})

test('rejects computed and over-bound campaign inventories without invoking entries', async () => {
  const artifacts = await campaignArtifacts()
  let getterCalls = 0
  const computed = []
  Object.defineProperty(computed, '0', {
    enumerable: true,
    get: () => { getterCalls += 1; return 'candidate-admission-000001.json' },
  })
  await assert.rejects(
    recoverUnleashCandidateFrontier({
      storage: { readJson: async () => ({}), listJsonFilenames: async () => computed },
      ...artifacts,
    }),
    rejectsFrontierCode('UNLEASH_CANDIDATE_INVENTORY_INVALID'),
  )
  assert.equal(getterCalls, 0)

  await assert.rejects(
    recoverUnleashCandidateFrontier({
      storage: {
        readJson: async () => ({}),
        listJsonFilenames: async () => Array.from({ length: 10_001 }, (_, index) => `unrelated-${index}.json`),
      },
      ...artifacts,
    }),
    rejectsFrontierCode('UNLEASH_CANDIDATE_INVENTORY_INVALID'),
  )
})

test('previews the exact recovery projection before publishing an admission', async () => {
  const artifacts = await campaignArtifacts()
  const storage = memoryStorage()
  const emptyFrontier = await recoverUnleashCandidateFrontier({ storage, ...artifacts })
  const admission = createAdmission(artifacts, proposal(artifacts, 'preview'))
  const preview = previewUnleashCandidateFrontierAppend({ frontier: emptyFrontier, admission })

  storage.files.set('candidate-admission-000001.json', admission)
  const recovered = await recoverUnleashCandidateFrontier({ storage, ...artifacts })
  assert.deepEqual(preview, recovered)
})

test('preview retains empty proposal identity and accepts only context-validated admissions', async () => {
  const artifacts = await campaignArtifacts()
  const emptyFrontier = await recoverUnleashCandidateFrontier({ storage: memoryStorage(), ...artifacts })
  const empty = proposal(artifacts, 'empty-identity')
  empty.candidates = []
  empty.actions = []
  const first = createAdmission(artifacts, empty)
  const firstFrontier = previewUnleashCandidateFrontierAppend({ frontier: emptyFrontier, admission: first })
  assert.deepEqual(
    getUnleashCandidateFrontierAdmissionReferences({ frontier: firstFrontier }).map((reference) => ({
      sequence: reference.sequence,
      proposal_id: reference.proposal_id,
      admission_sha256: reference.admission_sha256,
    })),
    [{ sequence: 1, proposal_id: empty.proposal_id, admission_sha256: first.admission_sha256 }],
  )
  const repeated = proposal(artifacts, 'second')
  repeated.proposal_id = empty.proposal_id
  const second = createAdmission(
    artifacts,
    repeated,
    2,
    first,
    '2026-09-15T09:32:00.000Z',
  )
  assert.throws(
    () => previewUnleashCandidateFrontierAppend({ frontier: firstFrontier, admission: second }),
    rejectsFrontierCode('UNLEASH_CANDIDATE_PROPOSAL_COLLISION'),
  )

  const altered = structuredClone(second)
  altered.provider_sha256 = '0'.repeat(64)
  delete altered.admission_sha256
  altered.admission_sha256 = digestUnleashValue(altered)
  assert.throws(
    () => previewUnleashCandidateFrontierAppend({ frontier: firstFrontier, admission: altered }),
    rejectsFrontierCode('UNLEASH_CANDIDATE_ADMISSION_PROVENANCE_MISSING'),
  )
})

test('a recovered campaign head authorizes only its exact reread predecessor', async () => {
  const artifacts = await campaignArtifacts()
  const first = createAdmission(artifacts, proposal(artifacts, '001'))
  const second = createAdmission(artifacts, proposal(artifacts, '002'), 2, first, '2026-09-15T09:32:00.000Z')
  const storage = memoryStorage()
  storage.files.set('candidate-admission-000001.json', first)
  storage.files.set('candidate-admission-000002.json', second)
  await recoverUnleashCandidateFrontier({ storage, ...artifacts })
  assert.doesNotThrow(() => createAdmission(
    artifacts,
    proposal(artifacts, '003'),
    3,
    structuredClone(second),
    '2026-09-15T09:33:00.000Z',
  ))
  const unrelated = createAdmission(artifacts, proposal(artifacts, 'fork-root'))
  const forkHead = createAdmission(
    artifacts,
    proposal(artifacts, 'fork-head'),
    2,
    unrelated,
    '2026-09-15T09:32:00.000Z',
  )
  assert.throws(
    () => createAdmission(
      artifacts,
      proposal(artifacts, '004'),
      3,
      forkHead,
      '2026-09-15T09:33:00.000Z',
    ),
    rejectsFrontierCode('UNLEASH_CANDIDATE_CHAIN_INVALID'),
  )
})

test('rejects a valid admission before publication when its cumulative projection exceeds canonical bytes', async () => {
  const artifacts = await campaignArtifacts()
  const storage = memoryStorage()
  let frontier = await recoverUnleashCandidateFrontier({ storage, ...artifacts })
  let previous = null
  for (let sequence = 1; sequence <= 3; sequence += 1) {
    const admission = createAdmission(
      artifacts,
      largeProposal(artifacts, String(sequence)),
      sequence,
      previous,
      `2026-09-15T09:3${sequence}:00.000Z`,
    )
    if (sequence < 3) {
      frontier = previewUnleashCandidateFrontierAppend({ frontier, admission })
      storage.files.set(`candidate-admission-${String(sequence).padStart(6, '0')}.json`, admission)
      frontier = await recoverUnleashCandidateFrontier({ storage, ...artifacts })
    } else {
      assert.throws(
        () => previewUnleashCandidateFrontierAppend({ frontier, admission }),
        rejectsFrontierCode('UNLEASH_CANDIDATE_FRONTIER_BOUNDS'),
      )
    }
    previous = admission
  }
})

test('retains and reconciles a self-bound frontier head to detect truncation', async () => {
  const artifacts = await campaignArtifacts()
  assert.equal(UNLEASH_CANDIDATE_FRONTIER_STATE_FILE, 'candidate-frontier-state.json')
  const storage = memoryStorage()
  const emptyFrontier = await recoverUnleashCandidateFrontier({ storage, ...artifacts })
  const first = createAdmission(artifacts, proposal(artifacts, '001'))
  const firstFrontier = previewUnleashCandidateFrontierAppend({ frontier: emptyFrontier, admission: first })
  const firstState = createUnleashCandidateFrontierState({
    frontier: firstFrontier,
    campaignState: artifacts.campaignState,
    recordedAt: new Date('2026-09-15T09:32:00.000Z'),
  })
  assert.equal(
    assertValidUnleashCandidateFrontierState(firstState, {
      frontier: firstFrontier,
      campaignState: artifacts.campaignState,
    }),
    firstState,
  )
  assert.equal(reconcileUnleashCandidateFrontierState({
    frontier: firstFrontier,
    retainedState: null,
    campaignState: artifacts.campaignState,
    recordedAt: new Date('2026-09-15T09:32:00.000Z'),
  }).status, 'PUBLICATION_REQUIRED')
  assert.equal(reconcileUnleashCandidateFrontierState({
    frontier: firstFrontier,
    retainedState: firstState,
    campaignState: artifacts.campaignState,
    recordedAt: new Date('2026-09-15T09:32:00.000Z'),
  }).status, 'CURRENT')

  const second = createAdmission(
    artifacts,
    proposal(artifacts, '002'),
    2,
    first,
    '2026-09-15T09:33:00.000Z',
  )
  const secondFrontier = previewUnleashCandidateFrontierAppend({ frontier: firstFrontier, admission: second })
  const repaired = reconcileUnleashCandidateFrontierState({
    frontier: secondFrontier,
    retainedState: firstState,
    campaignState: artifacts.campaignState,
    recordedAt: new Date('2026-09-15T09:34:00.000Z'),
  })
  assert.equal(repaired.status, 'REPAIR_REQUIRED')
  assert.equal(repaired.frontier_state.head_admission_sha256, second.admission_sha256)

  const forkFirst = createAdmission(artifacts, proposal(artifacts, 'fork-first'))
  const forkFirstFrontier = previewUnleashCandidateFrontierAppend({ frontier: emptyFrontier, admission: forkFirst })
  const forkSecond = createAdmission(
    artifacts,
    proposal(artifacts, 'fork-second'),
    2,
    forkFirst,
    '2026-09-15T09:33:00.000Z',
  )
  const forkFrontier = previewUnleashCandidateFrontierAppend({ frontier: forkFirstFrontier, admission: forkSecond })
  assert.throws(
    () => reconcileUnleashCandidateFrontierState({
      frontier: forkFrontier,
      retainedState: firstState,
      campaignState: artifacts.campaignState,
      recordedAt: new Date('2026-09-15T09:34:00.000Z'),
    }),
    rejectsFrontierCode('UNLEASH_CANDIDATE_FRONTIER_ANCESTRY_INVALID'),
  )

  await assert.rejects(
    async () => reconcileUnleashCandidateFrontierState({
      frontier: firstFrontier,
      retainedState: repaired.frontier_state,
      campaignState: artifacts.campaignState,
      recordedAt: new Date('2026-09-15T09:35:00.000Z'),
    }),
    rejectsFrontierCode('UNLEASH_CANDIDATE_FRONTIER_TRUNCATED'),
  )
  const forged = structuredClone(firstState)
  forged.head_admission_sha256 = '0'.repeat(64)
  delete forged.frontier_state_sha256
  forged.frontier_state_sha256 = digestUnleashValue(forged)
  assert.throws(
    () => reconcileUnleashCandidateFrontierState({
      frontier: firstFrontier,
      retainedState: forged,
      campaignState: artifacts.campaignState,
      recordedAt: new Date('2026-09-15T09:35:00.000Z'),
    }),
    rejectsFrontierCode('UNLEASH_CANDIDATE_FRONTIER_STATE_MISMATCH'),
  )
  assert.equal(reconcileUnleashCandidateFrontierState({
    frontier: emptyFrontier,
    retainedState: null,
    campaignState: artifacts.campaignState,
    recordedAt: new Date('2026-09-15T09:32:00.000Z'),
  }).status, 'CURRENT')
})

test('rejects chain gaps, tampering, rollback, and global proposal/candidate/action collisions', async () => {
  const artifacts = await campaignArtifacts()
  const first = createAdmission(artifacts, proposal(artifacts, '001'))

  {
    const storage = memoryStorage()
    storage.files.set('candidate-admission-000002.json', first)
    await assert.rejects(
      recoverUnleashCandidateFrontier({ storage, ...artifacts }),
      rejectsFrontierCode('UNLEASH_CANDIDATE_CHAIN_GAP'),
    )
  }
  {
    const storage = memoryStorage()
    const changed = structuredClone(first)
    changed.proposal.candidates[0].title = 'tampered'
    storage.files.set('candidate-admission-000001.json', changed)
    await assert.rejects(recoverUnleashCandidateFrontier({ storage, ...artifacts }))
  }
  {
    const duplicateProposal = proposal(artifacts, '002')
    duplicateProposal.proposal_id = first.proposal_id
    const second = createAdmission(artifacts, duplicateProposal, 2, first, '2026-09-15T09:32:00.000Z')
    const storage = memoryStorage()
    storage.files.set('candidate-admission-000001.json', first)
    storage.files.set('candidate-admission-000002.json', second)
    await assert.rejects(
      recoverUnleashCandidateFrontier({ storage, ...artifacts }),
      rejectsFrontierCode('UNLEASH_CANDIDATE_PROPOSAL_COLLISION'),
    )
  }
  for (const collision of ['candidate', 'action']) {
    const secondProposal = proposal(artifacts, '002')
    if (collision === 'candidate') secondProposal.candidates[0].candidate_id = first.proposal.candidates[0].candidate_id
    else secondProposal.actions[0].action_id = first.proposal.actions[0].action_id
    if (collision === 'candidate') secondProposal.actions[0].candidate_id = secondProposal.candidates[0].candidate_id
    const second = createAdmission(artifacts, secondProposal, 2, first, '2026-09-15T09:32:00.000Z')
    const storage = memoryStorage()
    storage.files.set('candidate-admission-000001.json', first)
    storage.files.set('candidate-admission-000002.json', second)
    await assert.rejects(
      recoverUnleashCandidateFrontier({ storage, ...artifacts }),
      rejectsFrontierCode(collision === 'candidate' ? 'UNLEASH_CANDIDATE_ID_COLLISION' : 'UNLEASH_CANDIDATE_ACTION_COLLISION'),
    )
  }
})

test('retains an empty provider proposal without claiming a clean result or a finding', async () => {
  const artifacts = await campaignArtifacts()
  const empty = proposal(artifacts, 'empty')
  empty.candidates = []
  empty.actions = []
  const admission = createAdmission(artifacts, empty)
  const storage = memoryStorage()
  storage.files.set('candidate-admission-000001.json', admission)

  const frontier = await recoverUnleashCandidateFrontier({ storage, ...artifacts })

  assert.equal(frontier.proposal_count, 1)
  assert.equal(frontier.candidate_count, 0)
  assert.equal(frontier.proposed_action_count, 0)
  assert.deepEqual(frontier.candidates, [])
  assert.deepEqual(frontier.actions, [])
  assert.equal(artifacts.campaignState.status, 'COMPLETE_WITH_GAPS')
  assert.ok(artifacts.campaignState.gap_count > 0)
})

test('protocol v2 admits candidate-only proposals during SWARMING against the immutable basis state', async () => {
  const artifacts = await campaignArtifactsV2()
  const { previousAdmission: _previous, ...emptyContext } = contextV2(artifacts)
  const emptyFrontier = createEmptyUnleashCandidateFrontierV2(emptyContext)
  const admission = createAdmissionV2(artifacts, artifacts.swarmMerge.proposal)

  assert.equal(assertValidUnleashCandidateAdmissionV2(admission, contextV2(artifacts)), admission)
  assert.equal(admission.schema_version, '2.0.0')
  assert.equal(admission.swarm_basis_sha256, artifacts.swarmBasis.basis_sha256)
  assert.equal(admission.swarm_merge_sha256, artifacts.swarmMerge.merge_sha256)
  assert.equal(admission.campaign_state_revision, artifacts.basisState.revision)
  assert.equal(admission.campaign_state_sha256, digestUnleashValue(artifacts.basisState))
  assert.notEqual(admission.campaign_state_revision, artifacts.campaignState.revision)
  assert.equal(admission.disposition.candidate_state, 'CANDIDATE')
  assert.equal(admission.disposition.actions_executable, false)

  const preview = previewUnleashCandidateFrontierAppendV2({
    frontier: emptyFrontier,
    admission,
    campaignState: artifacts.campaignState,
    swarmMerge: artifacts.swarmMerge,
    swarmCompletion: null,
  })
  assert.equal(preview.schema_version, '2.0.0')
  assert.equal(preview.swarm_basis_sha256, artifacts.swarmBasis.basis_sha256)
  assert.equal(preview.swarm_merge_sha256, artifacts.swarmMerge.merge_sha256)
  assert.equal(preview.candidates[0].state, 'CANDIDATE')
  assert.equal(preview.actions[0].state, 'PROPOSED_INERT')
  assert.throws(
    () => createAdmissionV2(artifacts, proposal(artifacts, 'not-the-final-merge')),
    rejectsFrontierCode('UNLEASH_CANDIDATE_V2_FINAL_MERGE_DRIFT'),
  )

  const storage = memoryStorage()
  storage.files.set('candidate-admission-000001.json', admission)
  const recovered = await recoverUnleashCandidateFrontierV2(recoveryInputV2(artifacts, storage))
  assert.deepEqual(recovered, preview)
  assert.throws(
    () => assertValidUnleashCandidateAdmission(admission, {
      plan: artifacts.plan,
      registry: artifacts.registry,
      provider: artifacts.provider,
      campaignState: artifacts.campaignState,
      evidencePacket: artifacts.evidencePacket,
      completion: artifacts.completion,
      previousAdmission: null,
    }),
    rejectsFrontierCode('UNLEASH_CANDIDATE_PROTOCOL_INVALID'),
  )
})

test('protocol-v2 frontier identity remains on its basis when the unsealed campaign enters recovery', async () => {
  const artifacts = await campaignArtifactsV2()
  const admission = createAdmissionV2(artifacts, artifacts.swarmMerge.proposal)
  const storage = memoryStorage()
  storage.files.set('candidate-admission-000001.json', admission)
  const first = await recoverUnleashCandidateFrontierV2(recoveryInputV2(artifacts, storage))
  const advancedState = {
    ...structuredClone(artifacts.campaignState),
    revision: artifacts.campaignState.revision + 1,
    updated_at: '2026-09-15T09:32:00.000Z',
    status: 'RECONCILIATION_REQUIRED',
    failure: {
      code: 'UNLEASH_SWARM_PUBLICATION_INCOMPLETE',
      message: 'Synthetic interrupted swarm publication.',
    },
  }
  const advanced = { ...artifacts, campaignState: advancedState }
  const second = await recoverUnleashCandidateFrontierV2(recoveryInputV2(advanced, storage))

  assert.equal(second.frontier_sha256, first.frontier_sha256)
  assert.equal(second.campaign_state_revision, artifacts.basisState.revision)
  assert.equal(second.campaign_state_sha256, digestUnleashValue(artifacts.basisState))
  assert.notEqual(second.campaign_state_revision, advancedState.revision)

  const drifted = structuredClone(artifacts)
  drifted.swarmBasis.campaign_state_sha256 = '0'.repeat(64)
  const { basis_sha256: _basisSha, ...unsignedBasis } = drifted.swarmBasis
  drifted.swarmBasis.basis_sha256 = digestUnleashValue(unsignedBasis)
  drifted.campaignState.swarm_basis_sha256 = drifted.swarmBasis.basis_sha256
  assert.throws(
    () => createAdmissionV2(drifted, drifted.swarmMerge.proposal),
    /basis|binding|swarm/i,
  )
})

test('protocol-v2 completion seals frontier recovery and frontier-state reconciliation', async () => {
  const artifacts = await campaignArtifactsV2()
  const first = createAdmissionV2(artifacts, artifacts.swarmMerge.proposal)
  const storage = memoryStorage()
  storage.files.set('candidate-admission-000001.json', first)
  const frontier = await recoverUnleashCandidateFrontierV2(recoveryInputV2(artifacts, storage))
  const unsealedContext = frontierStateContextV2(artifacts, frontier)
  const unsealedState = createUnleashCandidateFrontierStateV2({
    ...unsealedContext,
    recordedAt: new Date('2026-09-15T09:33:00.000Z'),
  })
  assert.equal(unsealedState.swarm_completion_sha256, null)
  assert.equal(
    assertValidUnleashCandidateFrontierStateV2(unsealedState, unsealedContext),
    unsealedState,
  )

  assert.throws(
    () => createAdmissionV2(
      artifacts,
      artifacts.swarmMerge.proposal,
      2,
      first,
      '2026-09-15T09:34:00.000Z',
    ),
    rejectsFrontierCode('UNLEASH_CANDIDATE_V2_FINAL_ALREADY_ADMITTED'),
  )
  const sealedArtifacts = sealedArtifactsV2(artifacts, frontier)
  const sealedFrontier = await recoverUnleashCandidateFrontierV2(
    recoveryInputV2(sealedArtifacts, storage),
  )
  assert.equal(sealedFrontier.frontier_sha256, frontier.frontier_sha256)
  assert.throws(
    () => createAdmissionV2(
      sealedArtifacts,
      sealedArtifacts.swarmMerge.proposal,
      2,
      first,
      '2026-09-15T09:36:00.000Z',
    ),
    rejectsFrontierCode('UNLEASH_CANDIDATE_SWARM_SEALED'),
  )
  assert.throws(
    () => previewUnleashCandidateFrontierAppendV2({
      frontier: sealedFrontier,
      admission: first,
      campaignState: sealedArtifacts.campaignState,
      swarmMerge: sealedArtifacts.swarmMerge,
      swarmCompletion: sealedArtifacts.swarmCompletion,
    }),
    rejectsFrontierCode('UNLEASH_CANDIDATE_SWARM_SEALED'),
  )

  const sealedContext = frontierStateContextV2(sealedArtifacts, sealedFrontier)
  const reconciliation = reconcileUnleashCandidateFrontierStateV2({
    ...sealedContext,
    retainedState: unsealedState,
    recordedAt: new Date('2026-09-15T09:35:00.000Z'),
  })
  assert.equal(reconciliation.status, 'SEAL_REQUIRED')
  assert.equal(
    reconciliation.frontier_state.swarm_completion_sha256,
    sealedArtifacts.swarmCompletion.completion_sha256,
  )
  assert.equal(
    assertValidUnleashCandidateFrontierStateV2(reconciliation.frontier_state, sealedContext),
    reconciliation.frontier_state,
  )
  assert.equal(reconcileUnleashCandidateFrontierStateV2({
    ...sealedContext,
    retainedState: reconciliation.frontier_state,
    recordedAt: new Date('2026-09-15T09:35:00.000Z'),
  }).status, 'CURRENT')

  const late = structuredClone(first)
  late.recorded_at = '2026-09-15T09:36:00.000Z'
  delete late.admission_sha256
  late.admission_sha256 = digestUnleashValue(late)
  storage.files.set('candidate-admission-000001.json', late)
  await assert.rejects(
    recoverUnleashCandidateFrontierV2(recoveryInputV2(sealedArtifacts, storage)),
    rejectsFrontierCode('UNLEASH_CANDIDATE_TIME_INVALID'),
  )
})

test('protocol-v2 refuses to seal without its one final merged proposal admission', async () => {
  const artifacts = await campaignArtifactsV2()
  const { previousAdmission: _previous, ...emptyContext } = contextV2(artifacts)
  const emptyFrontier = createEmptyUnleashCandidateFrontierV2(emptyContext)
  const sealedArtifacts = sealedArtifactsV2(artifacts, emptyFrontier)

  await assert.rejects(
    recoverUnleashCandidateFrontierV2(recoveryInputV2(sealedArtifacts, memoryStorage())),
    rejectsFrontierCode('UNLEASH_CANDIDATE_V2_FINAL_MISSING'),
  )
})

test('protocol-v2 accepts an exact STOPPED completion after the final merge admission', async () => {
  const artifacts = await campaignArtifactsV2()
  const admission = createAdmissionV2(artifacts, artifacts.swarmMerge.proposal)
  const storage = memoryStorage()
  storage.files.set('candidate-admission-000001.json', admission)
  const frontier = await recoverUnleashCandidateFrontierV2(recoveryInputV2(artifacts, storage))
  const stopped = stoppedSealedArtifactsV2(artifacts, frontier)

  const sealedFrontier = await recoverUnleashCandidateFrontierV2(recoveryInputV2(stopped, storage))
  assert.equal(sealedFrontier.frontier_sha256, frontier.frontier_sha256)
  assert.equal(stopped.campaignState.status, 'STOPPED')
  assert.equal(stopped.swarmCompletion.status, 'STOPPED')
  assert.equal(createUnleashCandidateFrontierStateV2({
    ...frontierStateContextV2(stopped, sealedFrontier),
    recordedAt: new Date(stopped.swarmCompletion.completed_at),
  }).swarm_completion_sha256, stopped.swarmCompletion.completion_sha256)
})
