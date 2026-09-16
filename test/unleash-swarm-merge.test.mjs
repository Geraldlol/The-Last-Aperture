import assert from 'node:assert/strict'
import test from 'node:test'

import { digestUnleashValue } from '../scripts/lib/unleash-contracts.mjs'
import {
  UNLEASH_SWARM_DEFAULT_LIMITS,
  assertValidUnleashRoleResponse,
  createUnleashRoleRequest,
  createUnleashSwarmBasis,
} from '../scripts/lib/unleash-swarm-contracts.mjs'
import {
  assertValidUnleashSwarmMerge,
  evaluateUnleashSwarmTermination,
  mergeUnleashSwarmResponses,
} from '../scripts/lib/unleash-swarm-merge.mjs'

const SHA = Object.freeze(Object.fromEntries(
  'abcdefghijklmnop'.split('').map((letter, index) => [letter, index.toString(16).repeat(64)]),
))
const EVIDENCE_REF = `evidence:sha256:${SHA.h}`

function basis(limitOverrides = {}) {
  return createUnleashSwarmBasis({
    recordedAt: '2026-09-15T14:00:00.000Z',
    campaignId: `campaign:sha256:${SHA.a}`,
    campaignStateRevision: 2,
    campaignStateSha256: SHA.b,
    planSha256: SHA.c,
    targetId: `target:sha256:${SHA.d}`,
    registrySha256: SHA.e,
    providerProfileSha256: SHA.f,
    evidencePacketSha256: SHA.g,
    completionReceiptSha256: SHA.i,
    limits: {
      ...structuredClone(UNLEASH_SWARM_DEFAULT_LIMITS),
      ...limitOverrides,
    },
  })
}

test('binds the merge artifact byte ceiling into requests and rejects oversized canonical merges', () => {
  const swarmBasis = basis({ max_merge_json_bytes: 4096 })
  const roleRequest = requestFor(swarmBasis, 'attacker:perimeter', 1)
  const response = attackResponse(roleRequest, {
    candidateId: 'candidate:large-source-id',
    actionId: 'action:large-source-id',
    confidence: 'MEDIUM',
    title: 'x'.repeat(4096),
    explanation: 'The long title is synthetic test data.',
  })

  assert.equal(UNLEASH_SWARM_DEFAULT_LIMITS.max_merge_json_bytes, 262_144)
  assert.equal(roleRequest.limits.max_merge_json_bytes, 4096)
  assertValidUnleashRoleResponse(response, { request: roleRequest, knownCandidateIds: [] })
  assert.throws(
    () => mergeUnleashSwarmResponses({
      basis: swarmBasis,
      round: 1,
      previous: null,
      responses: [response],
    }),
    { code: 'UNLEASH_SWARM_MERGE_ARTIFACT_BUDGET_EXCEEDED' },
  )

  assert.throws(
    () => mergeUnleashSwarmResponses({
      basis: swarmBasis,
      round: 1,
      previous: null,
      responses: Array.from({ length: 5 }, () => ({ padding: 'z'.repeat(250_000) })),
    }),
    { code: 'UNLEASH_SWARM_MERGE_ARTIFACT_BUDGET_EXCEEDED' },
  )
})

function requestFor(swarmBasis, roleId, round, frontierSha256 = SHA.j, challengeSha256 = SHA.k) {
  return createUnleashRoleRequest({
    basis: swarmBasis,
    round,
    roleId,
    inputFrontierSha256: frontierSha256,
    inputChallengeSetSha256: challengeSha256,
    evidenceRefs: [EVIDENCE_REF],
    allowedToolIds: ['tool:https-recon'],
    artifacts: [{
      artifact_id: `artifact:sha256:${SHA.l}`,
      kind: 'EVIDENCE',
      logical_name: 'verified-https-recon.json',
      sha256: SHA.h,
      size: 128,
    }],
  })
}

function attackResponse(roleRequest, { candidateId, actionId, confidence, title, explanation }) {
  return {
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
      proposal_id: `proposal:${roleRequest.role_id.replace(':', '-')}`,
      plan_sha256: roleRequest.plan_sha256,
      provider_protocol_version: '2.0.0',
      candidates: [{
        candidate_id: candidateId,
        title,
        hypothesis: 'The verified response may disclose a stable implementation version.',
        invariant: 'Production responses should not expose unnecessary exact implementation versions.',
        confidence,
        evidence_refs: [EVIDENCE_REF],
        competing_explanations: [explanation],
      }],
      actions: [{
        action_id: actionId,
        candidate_id: candidateId,
        tool_id: 'tool:https-recon',
        evidence_refs: [EVIDENCE_REF],
        parameters: { method: 'HEAD' },
        expected_observation: 'A repeated controller observation distinguishes a stable disclosure.',
      }],
    },
    challenges: [],
  }
}

test('merges duplicate hypotheses and actions deterministically regardless of response completion order', () => {
  const swarmBasis = basis()
  const perimeterRequest = requestFor(swarmBasis, 'attacker:perimeter', 1)
  const apiRequest = requestFor(swarmBasis, 'attacker:api', 1)
  const perimeter = attackResponse(perimeterRequest, {
    candidateId: 'candidate:perimeter-source-id',
    actionId: 'action:perimeter-source-id',
    confidence: 'HIGH',
    title: 'Potential implementation disclosure',
    explanation: 'The token may be an edge compatibility marker.',
  })
  const api = attackResponse(apiRequest, {
    candidateId: 'candidate:api-source-id',
    actionId: 'action:api-source-id',
    confidence: 'LOW',
    title: 'Implementation version may be exposed',
    explanation: 'The token may be synthetic.',
  })
  assertValidUnleashRoleResponse(perimeter, { request: perimeterRequest, knownCandidateIds: [] })
  assertValidUnleashRoleResponse(api, { request: apiRequest, knownCandidateIds: [] })

  const forward = mergeUnleashSwarmResponses({
    basis: swarmBasis,
    round: 1,
    previous: null,
    responses: [perimeter, api],
  })
  const reverse = mergeUnleashSwarmResponses({
    basis: swarmBasis,
    round: 1,
    previous: null,
    responses: [api, perimeter],
  })

  assert.deepEqual(reverse, forward)
  assert.equal(assertValidUnleashSwarmMerge(forward, { basis: swarmBasis }), forward)
  assert.equal(forward.candidate_count, 1)
  assert.equal(forward.proposed_action_count, 1)
  assert.match(forward.candidates[0].candidate_id, /^candidate:sha256:[a-f0-9]{64}$/u)
  assert.equal(forward.candidates[0].state, 'CANDIDATE')
  assert.equal(forward.candidates[0].provider_confidence, 'LOW')
  assert.deepEqual(forward.candidates[0].competing_explanations, [
    'The token may be an edge compatibility marker.',
    'The token may be synthetic.',
  ])
  assert.match(forward.actions[0].action_id, /^action:sha256:[a-f0-9]{64}$/u)
  assert.equal(forward.actions[0].state, 'PROPOSED_INERT')
  assert.equal(forward.actions[0].executable, false)
  assert.equal(forward.actions[0].candidate_id, forward.candidates[0].candidate_id)
  assert.equal(forward.provenance.candidates[0].source_refs.length, 2)
  assert.equal(forward.provenance.actions[0].source_refs.length, 2)

  const invalidActionContract = structuredClone(forward)
  invalidActionContract.actions[0].parameters = {}
  assert.throws(
    () => assertValidUnleashSwarmMerge(invalidActionContract, { basis: swarmBasis }),
    { code: 'UNLEASH_SWARM_SCHEMA_INVALID' },
  )
})

test('merges reviewer challenges without deleting or promoting a candidate', () => {
  const swarmBasis = basis()
  const attackerRequest = requestFor(swarmBasis, 'attacker:perimeter', 1)
  const attacked = mergeUnleashSwarmResponses({
    basis: swarmBasis,
    round: 1,
    previous: null,
    responses: [attackResponse(attackerRequest, {
      candidateId: 'candidate:source',
      actionId: 'action:source',
      confidence: 'MEDIUM',
      title: 'Potential implementation disclosure',
      explanation: 'The token may be synthetic.',
    })],
  })
  const canonicalCandidateId = attacked.candidates[0].candidate_id
  const skepticRequest = requestFor(
    swarmBasis,
    'reviewer:skeptic',
    1,
    attacked.frontier_sha256,
    attacked.challenge_set_sha256,
  )
  const skepticResponse = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-role-response',
    request_id: skepticRequest.request_id,
    request_sha256: skepticRequest.request_sha256,
    basis_sha256: skepticRequest.basis_sha256,
    plan_sha256: skepticRequest.plan_sha256,
    round: skepticRequest.round,
    role_id: skepticRequest.role_id,
    role_kind: skepticRequest.role_kind,
    wave: skepticRequest.wave,
    proposal: {
      schema_version: '1.0.0',
      kind: 'last-aperture/unleash-proposal',
      proposal_id: 'proposal:skeptic',
      plan_sha256: skepticRequest.plan_sha256,
      provider_protocol_version: '2.0.0',
      candidates: [],
      actions: [],
    },
    challenges: [{
      challenge_id: 'challenge:provider-local-id',
      candidate_id: canonicalCandidateId,
      disposition: 'INSUFFICIENT_EVIDENCE',
      reason: 'One bounded HEAD observation cannot establish route-wide behavior.',
      evidence_refs: [EVIDENCE_REF],
      competing_explanations: ['A downstream route may remove the token.'],
    }],
  }
  assertValidUnleashRoleResponse(skepticResponse, {
    request: skepticRequest,
    knownCandidateIds: [canonicalCandidateId],
  })

  const reviewed = mergeUnleashSwarmResponses({
    basis: swarmBasis,
    round: 1,
    previous: attacked,
    responses: [skepticResponse],
  })

  assert.equal(reviewed.candidate_count, 1)
  assert.equal(reviewed.candidates[0].state, 'CANDIDATE')
  assert.equal(reviewed.challenge_count, 1)
  assert.match(reviewed.challenges[0].challenge_id, /^challenge:sha256:[a-f0-9]{64}$/u)
  assert.equal(reviewed.challenges[0].candidate_id, canonicalCandidateId)
  assert.equal(Object.hasOwn(reviewed.candidates[0], 'proof'), false)
  assert.equal(Object.hasOwn(reviewed.candidates[0], 'verified'), false)
})

test('evaluates stable quiescence before deterministic round and usage limits', () => {
  const swarmBasis = basis()
  const empty = mergeUnleashSwarmResponses({
    basis: swarmBasis,
    round: 1,
    previous: null,
    responses: [],
  })
  const common = {
    beforeFrontierSha256: empty.frontier_sha256,
    beforeChallengeSetSha256: empty.challenge_set_sha256,
    after: empty,
    roundsCompleted: 2,
    providerCallsStarted: swarmBasis.limits.max_provider_calls,
    responseBytes: swarmBasis.limits.max_total_response_bytes,
    pendingAttemptCount: 0,
    stopRequested: false,
    authorityAvailable: true,
    deadlineExceeded: false,
    basis: swarmBasis,
  }

  assert.deepEqual(evaluateUnleashSwarmTermination(common), {
    decision: 'QUIESCENT',
    reason: 'FRONTIER_STABLE',
    stable: true,
    terminal: true,
  })
  assert.deepEqual(evaluateUnleashSwarmTermination({
    ...common,
    beforeFrontierSha256: SHA.m,
  }), {
    decision: 'BUDGET_EXHAUSTED',
    reason: 'MAX_ROUNDS',
    stable: false,
    terminal: true,
  })
  assert.deepEqual(evaluateUnleashSwarmTermination({
    ...common,
    stopRequested: true,
  }), {
    decision: 'STOPPED',
    reason: 'STOP_REQUESTED',
    stable: true,
    terminal: true,
  })
})

test('does not declare quiescence while a provider attempt remains pending', () => {
  const swarmBasis = basis()
  const empty = mergeUnleashSwarmResponses({
    basis: swarmBasis,
    round: 1,
    previous: null,
    responses: [],
  })
  assert.deepEqual(evaluateUnleashSwarmTermination({
    beforeFrontierSha256: empty.frontier_sha256,
    beforeChallengeSetSha256: empty.challenge_set_sha256,
    after: empty,
    roundsCompleted: 1,
    providerCallsStarted: 7,
    responseBytes: 0,
    pendingAttemptCount: 1,
    stopRequested: false,
    authorityAvailable: true,
    deadlineExceeded: false,
    basis: swarmBasis,
  }), {
    decision: 'CONTINUE',
    reason: 'ATTEMPTS_PENDING',
    stable: true,
    terminal: false,
  })
})

test('retains provenance across rounds without making provenance growth disturb quiescence', () => {
  const swarmBasis = basis()
  const firstRequest = requestFor(swarmBasis, 'attacker:perimeter', 1)
  const firstResponse = attackResponse(firstRequest, {
    candidateId: 'candidate:round-one',
    actionId: 'action:round-one',
    confidence: 'MEDIUM',
    title: 'Potential implementation disclosure',
    explanation: 'The token may be synthetic.',
  })
  const first = mergeUnleashSwarmResponses({
    basis: swarmBasis,
    round: 1,
    previous: null,
    responses: [firstResponse],
  })
  const secondRequest = requestFor(
    swarmBasis,
    'attacker:api',
    2,
    first.frontier_sha256,
    first.challenge_set_sha256,
  )
  const secondResponse = attackResponse(secondRequest, {
    candidateId: 'candidate:round-two',
    actionId: 'action:round-two',
    confidence: 'MEDIUM',
    title: 'Potential implementation disclosure',
    explanation: 'The token may be synthetic.',
  })
  const second = mergeUnleashSwarmResponses({
    basis: swarmBasis,
    round: 2,
    previous: first,
    responses: [secondResponse],
  })

  assert.equal(second.frontier_sha256, first.frontier_sha256)
  assert.equal(second.challenge_set_sha256, first.challenge_set_sha256)
  assert.equal(second.provenance.candidates[0].source_refs.length, 2)
  assert.equal(second.provenance.actions[0].source_refs.length, 2)
  assert.deepEqual(second.delta, {
    new_candidate_count: 0,
    changed_candidate_count: 0,
    new_action_count: 0,
    changed_action_count: 0,
    new_challenge_count: 0,
    changed_challenge_count: 0,
  })
})

test('rejects recomputed tampering and computed merge input without invoking accessors', () => {
  const swarmBasis = basis()
  const merged = mergeUnleashSwarmResponses({
    basis: swarmBasis,
    round: 1,
    previous: null,
    responses: [],
  })
  const tamperedUnsigned = {
    ...merged,
    frontier_sha256: SHA.m,
  }
  delete tamperedUnsigned.merge_sha256
  const tampered = {
    ...tamperedUnsigned,
    merge_sha256: digestUnleashValue(tamperedUnsigned),
  }
  assert.throws(
    () => assertValidUnleashSwarmMerge(tampered, { basis: swarmBasis }),
    (error) => error?.code === 'UNLEASH_SWARM_MERGE_DRIFT',
  )

  let calls = 0
  const input = {
    basis: swarmBasis,
    round: 1,
    previous: null,
  }
  Object.defineProperty(input, 'responses', {
    enumerable: true,
    get() {
      calls += 1
      throw new Error('must not execute')
    },
  })
  assert.throws(
    () => mergeUnleashSwarmResponses(input),
    (error) => error?.code === 'UNLEASH_SWARM_INPUT_INVALID',
  )
  assert.equal(calls, 0)

  const nested = {
    basis: swarmBasis,
    round: 1,
    previous: null,
    responses: [],
  }
  Object.defineProperty(nested.responses, '0', {
    enumerable: true,
    get() {
      calls += 1
      throw new Error('must not execute')
    },
  })
  nested.responses.length = 1
  assert.throws(
    () => mergeUnleashSwarmResponses(nested),
    (error) => error?.code === 'UNLEASH_SWARM_VALUE_INVALID',
  )
  assert.equal(calls, 0)
})

test('evaluates every controller terminal condition with fixed precedence', () => {
  const swarmBasis = basis()
  const empty = mergeUnleashSwarmResponses({
    basis: swarmBasis,
    round: 1,
    previous: null,
    responses: [],
  })
  const changed = {
    beforeFrontierSha256: SHA.m,
    beforeChallengeSetSha256: empty.challenge_set_sha256,
    after: empty,
    roundsCompleted: 1,
    providerCallsStarted: 1,
    responseBytes: 1,
    pendingAttemptCount: 0,
    stopRequested: false,
    authorityAvailable: true,
    deadlineExceeded: false,
    basis: swarmBasis,
  }
  assert.equal(evaluateUnleashSwarmTermination({ ...changed, authorityAvailable: false }).decision, 'POLICY_BLOCKED')
  assert.equal(evaluateUnleashSwarmTermination({ ...changed, deadlineExceeded: true }).reason, 'DEADLINE')
  assert.equal(evaluateUnleashSwarmTermination({
    ...changed,
    providerCallsStarted: swarmBasis.limits.max_provider_calls,
  }).reason, 'MAX_PROVIDER_CALLS')
  assert.equal(evaluateUnleashSwarmTermination({
    ...changed,
    responseBytes: swarmBasis.limits.max_total_response_bytes,
  }).reason, 'MAX_RESPONSE_BYTES')
  assert.deepEqual(evaluateUnleashSwarmTermination(changed), {
    decision: 'CONTINUE',
    reason: 'FRONTIER_CHANGED',
    stable: false,
    terminal: false,
  })

  let calls = 0
  const computed = { ...changed }
  Object.defineProperty(computed, 'after', {
    enumerable: true,
    get() {
      calls += 1
      throw new Error('must not execute')
    },
  })
  assert.throws(
    () => evaluateUnleashSwarmTermination(computed),
    (error) => error?.code === 'UNLEASH_SWARM_INPUT_INVALID',
  )
  assert.equal(calls, 0)
})
