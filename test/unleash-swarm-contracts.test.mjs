import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import test from 'node:test'

import { digestUnleashValue } from '../scripts/lib/unleash-contracts.mjs'
import {
  UNLEASH_SWARM_DEFAULT_LIMITS,
  assertValidUnleashRoleRequest,
  assertValidUnleashRoleResponse,
  assertValidUnleashRoleResponseCapture,
  assertValidUnleashSwarmBasis,
  assertValidUnleashSwarmCompletion,
  createUnleashRoleRequest,
  createUnleashRoleResponseCapture,
  createUnleashSwarmBasis,
  createUnleashSwarmCompletion,
  decodeUnleashRoleResponseCapture,
} from '../scripts/lib/unleash-swarm-contracts.mjs'
import {
  evaluateUnleashSwarmTermination,
  mergeUnleashSwarmResponses,
} from '../scripts/lib/unleash-swarm-merge.mjs'

const SHA = Object.freeze(Object.fromEntries(
  'abcdefghijklmnop'.split('').map((letter, index) => [letter, index.toString(16).repeat(64)]),
))
const EVIDENCE_REF = `evidence:sha256:${SHA.h}`

function attemptLedgerBinding(usage) {
  const attemptCount = Math.max(
    usage.provider_calls_started,
    usage.response_bytes > 0 ? 1 : 0,
  )
  const eventCount = attemptCount === 0 ? 0 : attemptCount * 2
  return {
    event_count: eventCount,
    attempt_count: attemptCount,
    response_bytes: usage.response_bytes,
    head_record_sha256: eventCount === 0 ? null : SHA.m,
    ledger_sha256: SHA.n,
  }
}

function basis() {
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
    limits: structuredClone(UNLEASH_SWARM_DEFAULT_LIMITS),
  })
}

function request(roleId = 'attacker:perimeter', round = 1, overrides = {}) {
  return createUnleashRoleRequest({
    basis: basis(),
    round,
    roleId,
    inputFrontierSha256: SHA.j,
    inputChallengeSetSha256: SHA.k,
    evidenceRefs: [EVIDENCE_REF],
    allowedToolIds: ['tool:https-recon'],
    artifacts: [{
      artifact_id: `artifact:sha256:${SHA.l}`,
      kind: 'EVIDENCE',
      logical_name: 'verified-https-recon.json',
      sha256: SHA.h,
      size: 128,
    }],
    ...overrides,
  })
}

function emptyProposal(planSha256 = SHA.c, proposalId = 'proposal:fixture') {
  return {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-proposal',
    proposal_id: proposalId,
    plan_sha256: planSha256,
    provider_protocol_version: '2.0.0',
    candidates: [],
    actions: [],
  }
}

function response(boundRequest, overrides = {}) {
  return {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-role-response',
    request_id: boundRequest.request_id,
    request_sha256: boundRequest.request_sha256,
    basis_sha256: boundRequest.basis_sha256,
    plan_sha256: boundRequest.plan_sha256,
    round: boundRequest.round,
    role_id: boundRequest.role_id,
    role_kind: boundRequest.role_kind,
    wave: boundRequest.wave,
    proposal: emptyProposal(boundRequest.plan_sha256),
    challenges: [],
    ...overrides,
  }
}

function actionResponse(boundRequest, {
  toolId = 'tool:https-recon',
  parameters = { method: 'HEAD' },
} = {}) {
  const candidateId = 'candidate:action-contract-fixture'
  return response(boundRequest, {
    proposal: {
      ...emptyProposal(boundRequest.plan_sha256),
      candidates: [{
        candidate_id: candidateId,
        title: 'Potential implementation disclosure',
        hypothesis: 'The verified response may disclose a stable implementation version.',
        invariant: 'Production responses should not expose unnecessary implementation details.',
        confidence: 'LOW',
        evidence_refs: [EVIDENCE_REF],
        competing_explanations: ['The header may have been injected by an intermediary.'],
      }],
      actions: [{
        action_id: 'action:action-contract-fixture',
        candidate_id: candidateId,
        tool_id: toolId,
        evidence_refs: [EVIDENCE_REF],
        parameters,
        expected_observation: 'A bounded HEAD request repeats the verified observation.',
      }],
    },
  })
}

function captureResponse(boundRequest, providerResponse) {
  const responseBytes = Buffer.from(JSON.stringify(providerResponse), 'utf8')
  const responseSha256 = createHash('sha256').update(responseBytes).digest('hex')
  return createUnleashRoleResponseCapture({
    request: boundRequest,
    adapterId: 'adapter:fixture-provider',
    adapterVersion: '1.0.0',
    adapterConfigSha256: SHA.n,
    capturedAt: '2026-09-15T14:00:01.000Z',
    responseBytes,
    transportReceipt: {
      schema_version: '1.0.0',
      kind: 'last-aperture/unleash-provider-transport-receipt',
      adapter_id: 'adapter:fixture-provider',
      adapter_version: '1.0.0',
      adapter_config_sha256: SHA.n,
      request_id: boundRequest.request_id,
      request_sha256: boundRequest.request_sha256,
      response_sha256: responseSha256,
      scope: 'TRANSPORT_ONLY',
      semantic_analysis_proven: false,
    },
  })
}

function rejectsCode(code) {
  return (error) => error?.code === code
}

test('creates immutable self-bound swarm basis and role request records', () => {
  const swarmBasis = basis()
  const roleRequest = request()

  assert.equal(assertValidUnleashSwarmBasis(swarmBasis), swarmBasis)
  assert.equal(assertValidUnleashRoleRequest(roleRequest, { basis: swarmBasis }), roleRequest)
  assert.equal(Object.isFrozen(swarmBasis), true)
  assert.equal(Object.isFrozen(swarmBasis.roles), true)
  assert.equal(Object.isFrozen(roleRequest), true)
  assert.equal(swarmBasis.limits.max_merge_json_bytes, 262_144)
  assert.equal(roleRequest.limits.max_merge_json_bytes, 262_144)
  assert.deepEqual(swarmBasis.roles.map(({ role_id: id }) => id), [
    'attacker:perimeter',
    'attacker:identity',
    'attacker:api',
    'attacker:data',
    'attacker:client',
    'reviewer:exploit-falsifier',
    'reviewer:skeptic',
  ])
  assert.equal(roleRequest.request_id, `request:sha256:${digestUnleashValue({
    basis_sha256: swarmBasis.basis_sha256,
    round: 1,
    role_id: 'attacker:perimeter',
    input_frontier_sha256: SHA.j,
    input_challenge_set_sha256: SHA.k,
  })}`)
  const { basis_sha256: _basisDigest, ...unsignedBasis } = swarmBasis
  const { request_sha256: _requestDigest, ...unsignedRequest } = roleRequest
  assert.equal(swarmBasis.basis_sha256, digestUnleashValue(unsignedBasis))
  assert.equal(roleRequest.request_sha256, digestUnleashValue(unsignedRequest))
})

test('rejects computed builder input without invoking its accessor', () => {
  let calls = 0
  const input = {
    recordedAt: '2026-09-15T14:00:00.000Z',
    campaignId: `campaign:sha256:${SHA.a}`,
    campaignStateRevision: 2,
    campaignStateSha256: SHA.b,
    targetId: `target:sha256:${SHA.d}`,
    registrySha256: SHA.e,
    providerProfileSha256: SHA.f,
    evidencePacketSha256: SHA.g,
    completionReceiptSha256: SHA.i,
    limits: structuredClone(UNLEASH_SWARM_DEFAULT_LIMITS),
  }
  Object.defineProperty(input, 'planSha256', {
    enumerable: true,
    get() {
      calls += 1
      throw new Error('must not execute')
    },
  })

  assert.throws(() => createUnleashSwarmBasis(input), rejectsCode('UNLEASH_SWARM_INPUT_INVALID'))
  assert.equal(calls, 0)

  const requestInput = {
    basis: basis(),
    round: 1,
    roleId: 'attacker:perimeter',
    inputFrontierSha256: SHA.j,
    inputChallengeSetSha256: SHA.k,
    evidenceRefs: [EVIDENCE_REF],
    allowedToolIds: ['tool:https-recon'],
    artifacts: [],
  }
  Object.defineProperty(requestInput.artifacts, '0', {
    enumerable: true,
    get() {
      calls += 1
      throw new Error('must not execute')
    },
  })
  requestInput.artifacts.length = 1
  assert.throws(() => createUnleashRoleRequest(requestInput), rejectsCode('UNLEASH_SWARM_VALUE_INVALID'))
  assert.equal(calls, 0)
})

test('binds provider response to the exact role request and forbids proof fields', () => {
  const roleRequest = request()
  const providerResponse = response(roleRequest)
  assert.equal(
    assertValidUnleashRoleResponse(providerResponse, {
      request: roleRequest,
      knownCandidateIds: [],
    }),
    providerResponse,
  )

  assert.throws(
    () => assertValidUnleashRoleResponse({ ...providerResponse, proof: 'VERIFIED' }, {
      request: roleRequest,
      knownCandidateIds: [],
    }),
    rejectsCode('UNLEASH_SWARM_SCHEMA_INVALID'),
  )
  assert.throws(
    () => assertValidUnleashRoleResponse({ ...providerResponse, request_sha256: SHA.m }, {
      request: roleRequest,
      knownCandidateIds: [],
    }),
    rejectsCode('UNLEASH_SWARM_RESPONSE_BINDING_DRIFT'),
  )

  let calls = 0
  const computed = { ...providerResponse }
  Object.defineProperty(computed, 'proposal', {
    enumerable: true,
    get() {
      calls += 1
      throw new Error('must not execute')
    },
  })
  assert.throws(
    () => assertValidUnleashRoleResponse(computed, {
      request: roleRequest,
      knownCandidateIds: [],
    }),
    rejectsCode('UNLEASH_SWARM_VALUE_INVALID'),
  )
  assert.equal(calls, 0)
})

test('enforces the exact current protocol action contract through captured responses', () => {
  const roleRequest = request()
  const exact = actionResponse(roleRequest)
  assert.equal(assertValidUnleashRoleResponse(exact, {
    request: roleRequest,
    knownCandidateIds: [],
  }), exact)

  const missingMethod = actionResponse(roleRequest, { parameters: {} })
  assert.throws(
    () => assertValidUnleashRoleResponse(missingMethod, {
      request: roleRequest,
      knownCandidateIds: [],
    }),
    rejectsCode('UNLEASH_SWARM_SCHEMA_INVALID'),
  )
  const unsupportedTool = actionResponse(roleRequest, {
    toolId: 'tool:future-provider-action',
    parameters: {},
  })
  assert.throws(
    () => assertValidUnleashRoleResponse(unsupportedTool, {
      request: roleRequest,
      knownCandidateIds: [],
    }),
    rejectsCode('UNLEASH_SWARM_ACTION_CONTRACT_UNSUPPORTED'),
  )

  const captured = captureResponse(roleRequest, missingMethod)
  assert.throws(
    () => decodeUnleashRoleResponseCapture(captured, {
      request: roleRequest,
      knownCandidateIds: [],
    }),
    rejectsCode('UNLEASH_SWARM_SCHEMA_INVALID'),
  )
})

test('captures exact response bytes before interpretation with transport-only trust', () => {
  const roleRequest = request()
  const providerResponse = response(roleRequest)
  const responseBytes = Buffer.from(JSON.stringify(providerResponse), 'utf8')
  const responseSha256 = createHash('sha256').update(responseBytes).digest('hex')
  const transportReceipt = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-provider-transport-receipt',
    adapter_id: 'adapter:fixture-provider',
    adapter_version: '1.0.0',
    adapter_config_sha256: SHA.n,
    request_id: roleRequest.request_id,
    request_sha256: roleRequest.request_sha256,
    response_sha256: responseSha256,
    scope: 'TRANSPORT_ONLY',
    semantic_analysis_proven: false,
  }
  const capture = createUnleashRoleResponseCapture({
    request: roleRequest,
    adapterId: 'adapter:fixture-provider',
    adapterVersion: '1.0.0',
    adapterConfigSha256: SHA.n,
    capturedAt: '2026-09-15T14:00:01.000Z',
    responseBytes,
    transportReceipt,
  })

  assert.equal(assertValidUnleashRoleResponseCapture(capture, { request: roleRequest }), capture)
  assert.equal(capture.content_base64, responseBytes.toString('base64'))
  assert.equal(capture.response_sha256, responseSha256)
  assert.equal(capture.transport_receipt_scope, 'TRANSPORT_ONLY')
  assert.equal(capture.semantic_analysis_proven, false)
  assert.equal(Object.isFrozen(capture.transport_receipt), true)
  const { capture_sha256: _captureDigest, ...unsigned } = capture
  assert.equal(capture.capture_sha256, digestUnleashValue(unsigned))

  assert.throws(
    () => assertValidUnleashRoleResponseCapture({ ...capture, response_bytes: capture.response_bytes + 1 }, {
      request: roleRequest,
    }),
    rejectsCode('UNLEASH_SWARM_CAPTURE_INVALID'),
  )
  assert.throws(
    () => createUnleashRoleResponseCapture({
      request: roleRequest,
      adapterId: 'adapter:fixture-provider',
      adapterVersion: '1.0.0',
      adapterConfigSha256: SHA.o,
      capturedAt: '2026-09-15T14:00:01.000Z',
      responseBytes,
      transportReceipt,
    }),
    rejectsCode('UNLEASH_SWARM_TRANSPORT_RECEIPT_INVALID'),
  )
})

test('rejects malformed UTF-8 even when the exact captured bytes and transport receipt agree', () => {
  const roleRequest = request()
  const providerResponse = response(roleRequest, {
    proposal: {
      ...emptyProposal(roleRequest.plan_sha256),
      candidates: [{
        candidate_id: 'candidate:malformed-utf8',
        title: 'candidate title',
        hypothesis: 'The verified response may disclose a stable implementation version.',
        invariant: 'Production responses should not expose unnecessary implementation details.',
        confidence: 'LOW',
        evidence_refs: [EVIDENCE_REF],
        competing_explanations: ['The header may have been injected by an intermediary.'],
      }],
    },
  })
  const responseBytes = Buffer.from(JSON.stringify(providerResponse), 'utf8')
  const titleOffset = responseBytes.indexOf(Buffer.from('candidate title', 'utf8'))
  assert.notEqual(titleOffset, -1)
  responseBytes[titleOffset] = 0x80
  const responseSha256 = createHash('sha256').update(responseBytes).digest('hex')
  const capture = createUnleashRoleResponseCapture({
    request: roleRequest,
    adapterId: 'adapter:fixture-provider',
    adapterVersion: '1.0.0',
    adapterConfigSha256: SHA.n,
    capturedAt: '2026-09-15T14:00:01.000Z',
    responseBytes,
    transportReceipt: {
      schema_version: '1.0.0',
      kind: 'last-aperture/unleash-provider-transport-receipt',
      adapter_id: 'adapter:fixture-provider',
      adapter_version: '1.0.0',
      adapter_config_sha256: SHA.n,
      request_id: roleRequest.request_id,
      request_sha256: roleRequest.request_sha256,
      response_sha256: responseSha256,
      scope: 'TRANSPORT_ONLY',
      semantic_analysis_proven: false,
    },
  })

  assert.throws(
    () => decodeUnleashRoleResponseCapture(capture, {
      request: roleRequest,
      knownCandidateIds: [],
    }),
    rejectsCode('UNLEASH_SWARM_RESPONSE_INVALID'),
  )
})

test('creates a self-bound completion from one terminal decision', () => {
  const swarmBasis = basis()
  const merged = mergeUnleashSwarmResponses({
    basis: swarmBasis,
    round: 1,
    previous: null,
    responses: [],
  })
  const termination = evaluateUnleashSwarmTermination({
    beforeFrontierSha256: merged.frontier_sha256,
    beforeChallengeSetSha256: merged.challenge_set_sha256,
    after: merged,
    roundsCompleted: 1,
    providerCallsStarted: 7,
    responseBytes: 1024,
    pendingAttemptCount: 0,
    stopRequested: false,
    authorityAvailable: true,
    deadlineExceeded: false,
    basis: swarmBasis,
  })
  const usage = {
    rounds_completed: 1,
    provider_calls_started: 7,
    response_bytes: 1024,
  }
  const completion = createUnleashSwarmCompletion({
    basis: swarmBasis,
    completedAt: '2026-09-15T14:00:02.000Z',
    termination,
    merge: merged,
    attemptLedger: attemptLedgerBinding(usage),
    gaps: [],
    usage,
  })

  assert.equal(completion.status, 'QUIESCENT')
  assert.equal(completion.reason, 'FRONTIER_STABLE')
  assert.deepEqual(completion.attempt_ledger, {
    event_count: 14,
    attempt_count: 7,
    head_record_sha256: SHA.m,
    ledger_sha256: SHA.n,
  })
  assert.equal(assertValidUnleashSwarmCompletion(completion, { basis: swarmBasis }), completion)
  assert.equal(Object.isFrozen(completion), true)
  const { completion_sha256: _digest, ...unsigned } = completion
  assert.equal(completion.completion_sha256, digestUnleashValue(unsigned))
})

test('enforces exact terminal decision, reason, and stability tuples in builders and validators', () => {
  const swarmBasis = basis()
  const merged = mergeUnleashSwarmResponses({
    basis: swarmBasis,
    round: 1,
    previous: null,
    responses: [],
  })
  const usageFor = (termination) => ({
    rounds_completed: termination.reason === 'MAX_ROUNDS'
      ? swarmBasis.limits.max_rounds
      : 1,
    provider_calls_started: termination.reason === 'MAX_PROVIDER_CALLS'
      ? swarmBasis.limits.max_provider_calls
      : 0,
    response_bytes: termination.reason === 'MAX_RESPONSE_BYTES'
      ? swarmBasis.limits.max_total_response_bytes
      : 0,
  })
  const inputFor = (termination, usage = usageFor(termination)) => ({
    basis: swarmBasis,
    completedAt: '2026-09-15T14:00:02.000Z',
    termination,
    merge: merged,
    attemptLedger: attemptLedgerBinding(usage),
    gaps: [],
    usage,
  })
  const accepted = [
    { decision: 'QUIESCENT', reason: 'FRONTIER_STABLE', stable: true, terminal: true },
    { decision: 'BUDGET_EXHAUSTED', reason: 'MAX_ROUNDS', stable: false, terminal: true },
    { decision: 'BUDGET_EXHAUSTED', reason: 'MAX_PROVIDER_CALLS', stable: false, terminal: true },
    { decision: 'BUDGET_EXHAUSTED', reason: 'MAX_RESPONSE_BYTES', stable: false, terminal: true },
    { decision: 'BUDGET_EXHAUSTED', reason: 'DEADLINE', stable: true, terminal: true },
    { decision: 'BUDGET_EXHAUSTED', reason: 'DEADLINE', stable: false, terminal: true },
    { decision: 'STOPPED', reason: 'STOP_REQUESTED', stable: true, terminal: true },
    { decision: 'STOPPED', reason: 'STOP_REQUESTED', stable: false, terminal: true },
    { decision: 'POLICY_BLOCKED', reason: 'AUTHORITY_UNAVAILABLE', stable: true, terminal: true },
    { decision: 'POLICY_BLOCKED', reason: 'AUTHORITY_UNAVAILABLE', stable: false, terminal: true },
  ]
  for (const termination of accepted) {
    const completion = createUnleashSwarmCompletion(inputFor(termination))
    assert.equal(completion.status, termination.decision)
    assert.equal(completion.reason, termination.reason)
  }

  const rejected = [
    { decision: 'QUIESCENT', reason: 'AUTHORITY_UNAVAILABLE', stable: false, terminal: true },
    { decision: 'QUIESCENT', reason: 'FRONTIER_STABLE', stable: false, terminal: true },
    { decision: 'BUDGET_EXHAUSTED', reason: 'MAX_ROUNDS', stable: true, terminal: true },
    { decision: 'POLICY_BLOCKED', reason: 'STOP_REQUESTED', stable: true, terminal: true },
  ]
  for (const termination of rejected) {
    assert.throws(
      () => createUnleashSwarmCompletion(inputFor(termination)),
      rejectsCode('UNLEASH_SWARM_SCHEMA_INVALID'),
    )
  }

  for (const termination of accepted.slice(1, 4)) {
    assert.throws(
      () => createUnleashSwarmCompletion(inputFor(termination, {
        rounds_completed: 1,
        provider_calls_started: 0,
        response_bytes: 0,
      })),
      rejectsCode('UNLEASH_SWARM_USAGE_INVALID'),
    )
  }

  const completion = createUnleashSwarmCompletion(inputFor(accepted[0]))
  const { completion_sha256: _digest, ...unsigned } = completion
  const contradictory = {
    ...unsigned,
    reason: 'AUTHORITY_UNAVAILABLE',
  }
  contradictory.completion_sha256 = digestUnleashValue(contradictory)
  assert.throws(
    () => assertValidUnleashSwarmCompletion(contradictory, { basis: swarmBasis }),
    rejectsCode('UNLEASH_SWARM_SCHEMA_INVALID'),
  )


  const maxRoundsCompletion = createUnleashSwarmCompletion(inputFor(accepted[1]))
  const { completion_sha256: _maxRoundsDigest, ...maxRoundsUnsigned } = maxRoundsCompletion
  const earlyExhaustion = {
    ...maxRoundsUnsigned,
    usage: { ...maxRoundsUnsigned.usage, rounds_completed: 1 },
  }
  earlyExhaustion.completion_sha256 = digestUnleashValue(earlyExhaustion)
  assert.throws(
    () => assertValidUnleashSwarmCompletion(earlyExhaustion, { basis: swarmBasis }),
    rejectsCode('UNLEASH_SWARM_COMPLETION_BINDING_DRIFT'),
  )
})
