import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import test from 'node:test'

import {
  createUnleashPlan,
  digestUnleashValue,
} from '../scripts/lib/unleash-contracts.mjs'
import { canonicalUnleashCampaignJson } from '../scripts/lib/unleash-campaign-storage.mjs'
import { createUnleashDeploymentPolicy } from '../scripts/lib/unleash-policy.mjs'
import { createUnleashProviderProfile } from '../scripts/lib/unleash-provider-profile.mjs'
import {
  createDefaultUnleashPlannerDependencies,
} from '../scripts/lib/unleash-registry.mjs'
import { createUnleashReasoningAdapter } from '../scripts/lib/unleash-reasoning-adapter.mjs'
import { createVerifiedReconCompletion } from '../scripts/lib/unleash-recon-evidence.mjs'
import {
  UNLEASH_SWARM_ROLE_SET,
  createUnleashSwarmBasis,
} from '../scripts/lib/unleash-swarm-contracts.mjs'
import {
  UnleashSwarmControllerError,
  runUnleashSwarmController,
} from '../scripts/lib/unleash-swarm-controller.mjs'
import {
  appendUnleashSwarmAttemptEvent,
  recoverUnleashSwarmAttemptLedger,
} from '../scripts/lib/unleash-swarm-ledger.mjs'

const OBSERVED_AT = new Date('2026-09-15T12:30:00.000Z')
const RECON_PLAN_SHA256 = 'b'.repeat(64)
const RECON_EVENT_SHA256 = 'd'.repeat(64)

function digestText(value) {
  return createHash('sha256').update(value).digest('hex')
}

function identity(label) {
  return {
    adapter_id: `adapter:${label}`,
    adapter_version: '1.0.0',
    adapter_config_sha256: digestText(`config:${label}`),
  }
}

function deploymentPolicy() {
  return createUnleashDeploymentPolicy({
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-deployment-policy',
    policy_id: 'policy:swarm-controller-test',
    valid_from: '2026-09-15T12:00:00.000Z',
    valid_until: '2026-09-15T13:00:00.000Z',
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
    revocation: { check_id: 'revocation:swarm-controller-test', fail_mode: 'CLOSED' },
  })
}

function verifiedRecon(plan) {
  const authority = {
    mode: 'CONTROLLER_DEPLOYMENT_POLICY',
    policy_id: plan.policy_id,
    policy_sha256: plan.policy_sha256,
    target_id: plan.target.target_id,
    effect: 'OBSERVE',
    admitted_at: OBSERVED_AT.toISOString(),
    revocation_check_id: plan.authority.revocation.check_id,
  }
  return {
    schema_version: '1.0.0',
    kind: 'last-aperture/verified-http-recon-evidence',
    run: {
      run_id: 'http-recon-run:swarm-controller-fixture',
      plan_sha256: RECON_PLAN_SHA256,
      state: 'PROBE_PLAN_COMPLETE',
      authorization: authority,
      event_chain: { count: 3, last_sha256: RECON_EVENT_SHA256 },
      target: { origin: 'https://example.test', tls: { mode: 'PKIX_HOSTNAME' } },
      actions: [{ method: 'HEAD', url: 'https://example.test/', safe_to_get: false }],
    },
    observations: [{
      authority: structuredClone(authority),
      method: 'HEAD',
      url: 'https://example.test/',
      status_code: 200,
      response_headers: [{ name: 'content-type' }],
    }],
  }
}

function clock(start = '2026-09-15T12:30:00.100Z') {
  let milliseconds = Date.parse(start)
  return () => {
    const value = new Date(milliseconds)
    milliseconds += 1
    return value
  }
}

function memoryStorage() {
  const files = new Map()
  let shouldReject = () => false
  const copy = (value) => JSON.parse(JSON.stringify(value))
  const storage = Object.freeze({
    async writeImmutableJson(filename, value) {
      if (shouldReject(filename, value)) {
        const error = new Error(`synthetic publication interruption for ${filename}`)
        error.code = 'EIO'
        throw error
      }
      if (files.has(filename)) {
        const error = new Error(`immutable file exists: ${filename}`)
        error.code = 'UNLEASH_STORAGE_FILE_EXISTS'
        throw error
      }
      files.set(filename, copy(value))
      return copy(value)
    },
    async replaceMutableJson(filename, value) {
      if (shouldReject(filename, value)) {
        const error = new Error(`synthetic replacement interruption for ${filename}`)
        error.code = 'EIO'
        throw error
      }
      files.set(filename, copy(value))
      return copy(value)
    },
    async readJson(filename) {
      if (!files.has(filename)) {
        const error = new Error(`file missing: ${filename}`)
        error.code = 'ENOENT'
        throw error
      }
      return copy(files.get(filename))
    },
    async listJsonFilenames() {
      return [...files.keys()].sort()
    },
  })
  return {
    storage,
    files,
    rejectWhen(predicate) { shouldReject = predicate },
  }
}

async function campaignFixture({ profileAssignments, adapters, limitOverrides = {} }) {
  const defaultProfile = createUnleashProviderProfile({ assignments: profileAssignments })
  const providerProfile = Object.keys(limitOverrides).length === 0
    ? defaultProfile
    : {
        ...structuredClone(defaultProfile),
        limits: {
          ...structuredClone(defaultProfile.limits),
          ...limitOverrides,
        },
      }
  const plan = createUnleashPlan(
    { target: 'https://example.test/' },
    createDefaultUnleashPlannerDependencies({
      policy: deploymentPolicy(),
      provider: providerProfile,
    }),
  )
  const verified = verifiedRecon(plan)
  const reconCompletion = await createVerifiedReconCompletion({
    bundle: 'controller-owned/recon',
    plan,
  }, {
    now: () => new Date(OBSERVED_AT),
    readVerifiedRecon: async () => structuredClone(verified),
  })
  const basis = createUnleashSwarmBasis({
    recordedAt: OBSERVED_AT.toISOString(),
    campaignId: `campaign:sha256:${digestText('swarm-controller-campaign')}`,
    campaignStateRevision: 2,
    campaignStateSha256: digestText('swarming-state'),
    planSha256: plan.plan_sha256,
    targetId: plan.target.target_id,
    registrySha256: plan.registry_sha256,
    providerProfileSha256: digestUnleashValue(providerProfile),
    evidencePacketSha256: reconCompletion.evidence_packet.packet_sha256,
    completionReceiptSha256: reconCompletion.completion_receipt.completion_receipt_sha256,
    limits: structuredClone(providerProfile.limits),
  })
  return {
    input: {
      basis,
      plan,
      bundle: 'controller-owned/recon',
      reconCompletion,
      providerProfile,
      adapters,
    },
    readVerifiedRecon: async () => structuredClone(verified),
  }
}

function providerResponse(request, control) {
  const evidenceRef = request.evidence_refs[0]
  const isDuplicateAttacker = ['attacker:perimeter', 'attacker:api'].includes(request.role_id)
  const candidates = isDuplicateAttacker
    ? [{
        candidate_id: `candidate:${request.role_id.replaceAll(':', '-')}`,
        title: request.role_id === 'attacker:perimeter'
          ? 'Potential implementation disclosure'
          : 'Implementation version may be exposed',
        hypothesis: 'The verified response may disclose a stable implementation version.',
        invariant: 'Production responses should not expose unnecessary exact implementation versions.',
        confidence: request.role_id === 'attacker:perimeter' ? 'HIGH' : 'LOW',
        evidence_refs: [evidenceRef],
        competing_explanations: [request.role_id === 'attacker:perimeter'
          ? 'The token may be an edge compatibility marker.'
          : 'The token may be synthetic.'],
      }]
    : []
  const challengedCandidate = control.merge.candidates[0]?.candidate_id
  const challenges = request.role_id === 'reviewer:skeptic' && challengedCandidate !== undefined
    ? [{
        challenge_id: `challenge:provider-r${request.round}`,
        candidate_id: challengedCandidate,
        disposition: 'INSUFFICIENT_EVIDENCE',
        reason: 'One bounded observation cannot establish route-wide behavior.',
        evidence_refs: [evidenceRef],
        competing_explanations: ['A downstream route may remove the token.'],
      }]
    : []
  return {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-role-response',
    request_id: request.request_id,
    request_sha256: request.request_sha256,
    basis_sha256: request.basis_sha256,
    plan_sha256: request.plan_sha256,
    round: request.round,
    role_id: request.role_id,
    role_kind: request.role_kind,
    wave: request.wave,
    proposal: {
      schema_version: '1.0.0',
      kind: 'last-aperture/unleash-proposal',
      proposal_id: `proposal:${request.role_id.replaceAll(':', '-')}:r${request.round}`,
      plan_sha256: request.plan_sha256,
      provider_protocol_version: '2.0.0',
      candidates,
      actions: [],
    },
    challenges,
  }
}

function responseAdapter(adapterIdentity, metrics = undefined) {
  const firstAttackRoles = new Set([
    'attacker:perimeter',
    'attacker:identity',
    'attacker:api',
    'attacker:data',
  ])
  let releaseFirstAttack
  const firstAttackBarrier = new Promise((resolve) => { releaseFirstAttack = resolve })
  let firstAttackWaiting = 0
  return createUnleashReasoningAdapter({
    identity: adapterIdentity,
    async invoke(envelope) {
      if (metrics !== undefined) {
        metrics.calls += 1
        metrics.active += 1
        metrics.maxActive = Math.max(metrics.maxActive, metrics.active)
      }
      try {
        if (
          metrics !== undefined
          && envelope.request.round === 1
          && firstAttackRoles.has(envelope.request.role_id)
        ) {
          firstAttackWaiting += 1
          if (firstAttackWaiting === 4) releaseFirstAttack()
          await firstAttackBarrier
        }
        const controlManifest = envelope.request.artifacts.find(({ kind }) => kind === 'CONTROL')
        const controlPayload = envelope.artifact_payloads.find(
          ({ artifact_id: artifactId }) => artifactId === controlManifest.artifact_id,
        )
        const control = JSON.parse(Buffer.from(controlPayload.content_base64, 'base64').toString('utf8'))
        return Buffer.from(JSON.stringify(providerResponse(envelope.request, control)), 'utf8')
      } finally {
        if (metrics !== undefined) metrics.active -= 1
      }
    },
  })
}

function emptyResponseAdapter(adapterIdentity) {
  return createUnleashReasoningAdapter({
    identity: adapterIdentity,
    async invoke(envelope) {
      const response = providerResponse(envelope.request, { merge: { candidates: [] } })
      response.proposal.candidates = []
      response.challenges = []
      return Buffer.from(JSON.stringify(response), 'utf8')
    },
  })
}

function syntheticCandidate(request, label, {
  textSize = 0,
  identityLabel = label,
  explanations = [],
} = {}) {
  const padding = 'x'.repeat(textSize)
  return {
    candidate_id: `candidate:${label}`,
    title: `Candidate ${label}`,
    hypothesis: `Hypothesis ${identityLabel}${padding}`,
    invariant: `Invariant ${identityLabel}${padding}`,
    confidence: 'MEDIUM',
    evidence_refs: [request.evidence_refs[0]],
    competing_explanations: explanations,
  }
}

function candidatesFor(request, count, prefix, options = {}) {
  return Array.from({ length: count }, (_, index) => syntheticCandidate(
    request,
    `${prefix}-${String(index).padStart(3, '0')}`,
    options,
  ))
}

function aggregateResponseAdapter(adapterIdentity, candidateFactory, metrics = { calls: 0 }) {
  return createUnleashReasoningAdapter({
    identity: adapterIdentity,
    async invoke({ request }) {
      metrics.calls += 1
      const response = providerResponse(request, { merge: { candidates: [] } })
      response.proposal.candidates = request.round === 1
        ? candidateFactory(request)
        : []
      response.proposal.actions = []
      response.challenges = []
      return Buffer.from(JSON.stringify(response), 'utf8')
    },
  })
}

function assignedSwarm(adapterIdentity, adapter) {
  return {
    profileAssignments: UNLEASH_SWARM_ROLE_SET.roles.map(({ role_id: roleId }) => ({
      roleId,
      adapterIdentity,
    })),
    adapters: UNLEASH_SWARM_ROLE_SET.roles.map(({ role_id: roleId }) => ({ roleId, adapter })),
  }
}

function dependencies(storageFixture, fixture, now = clock(), overrides = {}) {
  return {
    storage: storageFixture.storage,
    readVerifiedRecon: fixture.readVerifiedRecon,
    now,
    signal: undefined,
    stopRequested: false,
    authorityAvailable: true,
    deadlineExceeded: false,
    ...overrides,
  }
}

test('runs four attackers concurrently, merges two waves deterministically, and replays no provider after recovery', async () => {
  const sharedIdentity = identity('full-swarm')
  const metrics = { calls: 0, active: 0, maxActive: 0 }
  const adapter = responseAdapter(sharedIdentity, metrics)
  const assignments = UNLEASH_SWARM_ROLE_SET.roles.map(({ role_id: roleId }) => ({
    roleId,
    adapterIdentity: sharedIdentity,
  }))
  const adapters = UNLEASH_SWARM_ROLE_SET.roles.map(({ role_id: roleId }) => ({ roleId, adapter }))
  const fixture = await campaignFixture({ profileAssignments: assignments, adapters })
  const retained = memoryStorage()
  const first = await runUnleashSwarmController(
    fixture.input,
    dependencies(retained, fixture),
  )

  assert.equal(metrics.calls, 14)
  assert.equal(metrics.maxActive, 4)
  assert.equal(first.termination.decision, 'QUIESCENT')
  assert.equal(first.termination.reason, 'FRONTIER_STABLE')
  assert.equal(first.usage.rounds_completed, 2)
  assert.equal(first.usage.provider_calls_started, 14)
  assert.equal(first.merge.candidate_count, 1)
  assert.equal(first.merge.challenge_count, 1)
  assert.equal(first.merge.candidates[0].state, 'CANDIDATE')
  assert.equal(first.gaps.length, 0)
  assert.equal(retained.files.has('swarm-basis.json'), true)
  assert.equal(retained.files.has('swarm-merge-r01-attack.json'), true)
  assert.equal(retained.files.has('swarm-merge-r01-review.json'), true)
  assert.equal(retained.files.has('swarm-merge-r02-attack.json'), true)
  assert.equal(retained.files.has('swarm-merge-r02-review.json'), true)
  assert.equal(retained.files.has('swarm-completion.json'), false)

  const callsBeforeRecovery = metrics.calls
  const recovered = await runUnleashSwarmController(
    fixture.input,
    dependencies(retained, fixture, clock('2026-09-15T12:31:00.000Z')),
  )
  assert.equal(metrics.calls, callsBeforeRecovery)
  assert.deepEqual(recovered.merge, first.merge)
  assert.deepEqual(recovered.termination, first.termination)
  assert.deepEqual(recovered.usage, first.usage)
  assert.deepEqual(recovered.gaps, first.gaps)
})

test('rejects one oversized response atomically, accepts a later small role, and recovers at the CAPTURED boundary', async () => {
  const adapterIdentity = identity('merge-byte-fold')
  const metrics = { calls: 0 }
  const adapter = aggregateResponseAdapter(adapterIdentity, (request) => {
    if (request.role_id === 'attacker:perimeter') {
      return candidatesFor(request, 25, 'byte-first', { textSize: 2000 })
    }
    if (request.role_id === 'attacker:identity') {
      return candidatesFor(request, 25, 'byte-rejected', { textSize: 2000 })
    }
    if (request.role_id === 'attacker:api') {
      return candidatesFor(request, 1, 'byte-later-small')
    }
    return []
  }, metrics)
  const fixture = await campaignFixture(assignedSwarm(adapterIdentity, adapter))
  const retained = memoryStorage()
  retained.rejectWhen((filename, value) => (
    filename.startsWith('swarm-attempt-event-')
    && value.state === 'FAILED'
    && value.payload.reason_code === 'MERGE_ARTIFACT_BUDGET_EXCEEDED'
  ))

  await assert.rejects(
    runUnleashSwarmController(fixture.input, dependencies(retained, fixture)),
    /attempt event|publication|append|write/i,
  )
  assert.equal(metrics.calls, 5)
  retained.rejectWhen(() => false)

  const result = await runUnleashSwarmController(
    fixture.input,
    dependencies(retained, fixture, clock('2026-09-15T12:31:00.000Z')),
  )
  assert.equal(metrics.calls, 14)
  assert.equal(result.termination.decision, 'QUIESCENT')
  assert.equal(result.merge.candidate_count, 26)
  assert.equal(result.merge.candidates.some(({ title }) => title.includes('byte-rejected')), false)
  const mergeBytes = Buffer.byteLength(canonicalUnleashCampaignJson(result.merge), 'utf8')
  assert.ok(mergeBytes > 200_000)
  assert.ok(mergeBytes <= 262_144)
  assert.equal(retained.files.has('swarm-merge-r01-review.json'), true)
  assert.equal(retained.files.has('swarm-merge-r02-attack.json'), true)
  assert.equal(retained.files.has('swarm-merge-r02-review.json'), true)
  assert.ok(result.gaps.some((entry) => (
    entry.round === 1
    && entry.role_id === 'attacker:identity'
    && entry.reason_code === 'MERGE_ARTIFACT_BUDGET_EXCEEDED'
  )))
  assert.equal(result.ledger.attempts.find((attempt) => (
    attempt.round === 1 && attempt.role_id === 'attacker:identity'
  )).state, 'FAILED')
  assert.equal(result.ledger.attempts.find((attempt) => (
    attempt.round === 1 && attempt.role_id === 'attacker:api'
  )).state, 'COMMITTED')

  const callsBeforeRecovery = metrics.calls
  const recovered = await runUnleashSwarmController(
    fixture.input,
    dependencies(retained, fixture, clock('2026-09-15T12:32:00.000Z')),
  )
  assert.equal(metrics.calls, callsBeforeRecovery)
  assert.deepEqual(recovered.merge, result.merge)
  assert.deepEqual(recovered.gaps, result.gaps)
})

test('fails recovery integrity when a byte-overflowing response was already VALIDATED or COMMITTED', async () => {
  const adapterIdentity = identity('merge-byte-invalid-retained')
  const adapter = aggregateResponseAdapter(adapterIdentity, (request) => {
    if (request.role_id === 'attacker:perimeter') {
      return candidatesFor(request, 25, 'retained-first', { textSize: 2000 })
    }
    if (request.role_id === 'attacker:identity') {
      return candidatesFor(request, 25, 'retained-overflow', { textSize: 2000 })
    }
    return []
  })
  const fixture = await campaignFixture(assignedSwarm(adapterIdentity, adapter))
  const retained = memoryStorage()
  retained.rejectWhen((filename, value) => (
    filename.startsWith('swarm-attempt-event-')
    && value.state === 'FAILED'
    && value.payload.reason_code === 'MERGE_ARTIFACT_BUDGET_EXCEEDED'
  ))
  await assert.rejects(
    runUnleashSwarmController(fixture.input, dependencies(retained, fixture)),
    /attempt event|publication|append|write/i,
  )
  retained.rejectWhen(() => false)

  let ledger = await recoverUnleashSwarmAttemptLedger(
    { basis: fixture.input.basis },
    { storage: retained.storage },
  )
  const overflowAttempt = ledger.attempts.find((attempt) => (
    attempt.round === 1 && attempt.role_id === 'attacker:identity'
  ))
  const lease = ledger.events.find(({ attempt_id: attemptId }) => attemptId === overflowAttempt.attempt_id)
  const response = JSON.parse(Buffer.from(
    overflowAttempt.capture.content_base64,
    'base64',
  ).toString('utf8'))
  ledger = await appendUnleashSwarmAttemptEvent({
    basis: fixture.input.basis,
    attemptId: overflowAttempt.attempt_id,
    request: lease.request,
    adapterIdentity: overflowAttempt.adapter_identity,
    state: 'VALIDATED',
    occurredAt: '2026-09-15T12:30:30.000Z',
    payload: {
      capture_sha256: overflowAttempt.capture.capture_sha256,
      response_sha256: overflowAttempt.capture.response_sha256,
      validated_response_sha256: digestUnleashValue(response),
    },
  }, { storage: retained.storage })
  await assert.rejects(
    runUnleashSwarmController(
      fixture.input,
      dependencies(retained, fixture, clock('2026-09-15T12:31:00.000Z')),
    ),
    { code: 'UNLEASH_SWARM_MERGE_INTEGRITY_FAILED' },
  )

  const validatedAttempt = ledger.attempts.find(({ attempt_id: attemptId }) => (
    attemptId === overflowAttempt.attempt_id
  ))
  await appendUnleashSwarmAttemptEvent({
    basis: fixture.input.basis,
    attemptId: validatedAttempt.attempt_id,
    request: lease.request,
    adapterIdentity: validatedAttempt.adapter_identity,
    state: 'COMMITTED',
    occurredAt: '2026-09-15T12:30:31.000Z',
    payload: { merge_sha256: 'a'.repeat(64) },
  }, { storage: retained.storage })
  await assert.rejects(
    runUnleashSwarmController(
      fixture.input,
      dependencies(retained, fixture, clock('2026-09-15T12:32:00.000Z')),
    ),
    { code: 'UNLEASH_SWARM_MERGE_INTEGRITY_FAILED' },
  )
})

test('folds global candidate overflow into a gap and still accepts the next role', async () => {
  const adapterIdentity = identity('merge-count-fold')
  const adapter = aggregateResponseAdapter(adapterIdentity, (request) => {
    if (request.role_id === 'attacker:perimeter') {
      return candidatesFor(request, 6, 'count-first')
    }
    if (request.role_id === 'attacker:identity') {
      return candidatesFor(request, 6, 'count-rejected')
    }
    if (request.role_id === 'attacker:api') {
      return candidatesFor(request, 1, 'count-later-small')
    }
    return []
  })
  const fixture = await campaignFixture({
    ...assignedSwarm(adapterIdentity, adapter),
    limitOverrides: { max_rounds: 1, max_candidates: 10 },
  })
  const result = await runUnleashSwarmController(
    fixture.input,
    dependencies(memoryStorage(), fixture),
  )

  assert.equal(result.merge.candidate_count, 7)
  assert.equal(result.merge.candidates.some(({ title }) => title.includes('count-rejected')), false)
  assert.ok(result.gaps.some((entry) => (
    entry.round === 1
    && entry.role_id === 'attacker:identity'
    && entry.reason_code === 'MERGE_AGGREGATE_LIMIT_EXCEEDED'
  )))
  assert.ok(result.merge.candidates.some(({ title }) => title.includes('count-later-small')))
})

test('rejects an aggregate explanation union over 64 without excluding a later role', async () => {
  const adapterIdentity = identity('merge-explanation-fold')
  const adapter = aggregateResponseAdapter(adapterIdentity, (request) => {
    if (request.role_id === 'attacker:perimeter') {
      return [syntheticCandidate(request, 'explanation-first', {
        identityLabel: 'shared-explanation-candidate',
        explanations: Array.from({ length: 40 }, (_, index) => `First explanation ${index}`),
      })]
    }
    if (request.role_id === 'attacker:identity') {
      return [syntheticCandidate(request, 'explanation-rejected', {
        identityLabel: 'shared-explanation-candidate',
        explanations: Array.from({ length: 40 }, (_, index) => `Second explanation ${index}`),
      })]
    }
    if (request.role_id === 'attacker:api') {
      return candidatesFor(request, 1, 'explanation-later-small')
    }
    return []
  })
  const fixture = await campaignFixture({
    ...assignedSwarm(adapterIdentity, adapter),
    limitOverrides: { max_rounds: 1 },
  })
  const result = await runUnleashSwarmController(
    fixture.input,
    dependencies(memoryStorage(), fixture),
  )

  assert.equal(result.merge.candidate_count, 2)
  assert.ok(result.gaps.some((entry) => (
    entry.round === 1
    && entry.role_id === 'attacker:identity'
    && entry.reason_code === 'MERGE_AGGREGATE_LIMIT_EXCEEDED'
  )))
  assert.ok(result.merge.candidates.some(({ title }) => title.includes('explanation-later-small')))
})

test('turns every unavailable or identity-mismatched role into an explicit gap while peers continue', async () => {
  const expectedIdentity = identity('expected-perimeter')
  let unexpectedInvocations = 0
  const wrongAdapter = createUnleashReasoningAdapter({
    identity: identity('wrong-perimeter'),
    invoke: async () => {
      unexpectedInvocations += 1
      return Buffer.from('{}')
    },
  })
  const fixture = await campaignFixture({
    profileAssignments: [{ roleId: 'attacker:perimeter', adapterIdentity: expectedIdentity }],
    adapters: [{ roleId: 'attacker:perimeter', adapter: wrongAdapter }],
  })
  const retained = memoryStorage()
  const result = await runUnleashSwarmController(
    fixture.input,
    dependencies(retained, fixture),
  )

  assert.equal(unexpectedInvocations, 0)
  assert.equal(result.termination.decision, 'QUIESCENT')
  assert.equal(result.usage.provider_calls_started, 0)
  assert.equal(result.gaps.length, 7)
  assert.equal(new Set(result.gaps.map(({ role_id: roleId }) => roleId)).size, 7)
  assert.equal(
    result.gaps.find(({ role_id: roleId }) => roleId === 'attacker:perimeter').reason_code,
    'REASONING_ADAPTER_IDENTITY_MISMATCH',
  )
  assert.equal(
    result.gaps.filter(({ reason_code: reasonCode }) => reasonCode === 'REASONING_ADAPTER_UNAVAILABLE').length,
    6,
  )
  assert.equal(result.ledger.attempts[0].state, 'FAILED')
  assert.equal(result.ledger.attempts[0].failure.delivery, 'NOT_STARTED')
})

test('never replays STARTED delivery and resumes CAPTURED bytes through local validation', async (t) => {
  const adapterIdentity = identity('recoverable-perimeter')

  await t.test('STARTED becomes an ambiguous terminal gap without a second provider call', async () => {
    let calls = 0
    const adapter = emptyResponseAdapter(adapterIdentity)
    const countedAdapter = createUnleashReasoningAdapter({
      identity: adapterIdentity,
      async invoke(envelope, context) {
        calls += 1
        return adapter.invoke(envelope, context)
      },
    })
    const fixture = await campaignFixture({
      profileAssignments: [{ roleId: 'attacker:perimeter', adapterIdentity }],
      adapters: [{ roleId: 'attacker:perimeter', adapter: countedAdapter }],
    })
    const retained = memoryStorage()
    retained.rejectWhen((filename, value) => (
      filename.startsWith('swarm-attempt-event-')
      && ['CAPTURED', 'FAILED'].includes(value.state)
    ))
    await assert.rejects(
      runUnleashSwarmController(fixture.input, dependencies(retained, fixture)),
      /swarm attempt event|publication|append|write/i,
    )
    assert.equal(calls, 1)
    retained.rejectWhen(() => false)

    const recovered = await runUnleashSwarmController(
      fixture.input,
      dependencies(retained, fixture, clock('2026-09-15T12:31:00.000Z')),
    )
    assert.equal(calls, 1)
    assert.equal(
      recovered.gaps.find(({ role_id: roleId }) => roleId === 'attacker:perimeter').reason_code,
      'AMBIGUOUS_PROVIDER_DELIVERY',
    )
    assert.equal(
      recovered.ledger.attempts.find(({ role_id: roleId }) => roleId === 'attacker:perimeter').state,
      'FAILED',
    )
  })

  await t.test('CAPTURED resumes locally and commits without a second provider call', async () => {
    let calls = 0
    const adapter = emptyResponseAdapter(adapterIdentity)
    const countedAdapter = createUnleashReasoningAdapter({
      identity: adapterIdentity,
      async invoke(envelope, context) {
        calls += 1
        return adapter.invoke(envelope, context)
      },
    })
    const fixture = await campaignFixture({
      profileAssignments: [{ roleId: 'attacker:perimeter', adapterIdentity }],
      adapters: [{ roleId: 'attacker:perimeter', adapter: countedAdapter }],
    })
    const retained = memoryStorage()
    retained.rejectWhen((filename, value) => (
      filename.startsWith('swarm-attempt-event-') && value.state === 'VALIDATED'
    ))
    await assert.rejects(
      runUnleashSwarmController(fixture.input, dependencies(retained, fixture)),
      /swarm attempt event|publication|append|write/i,
    )
    assert.equal(calls, 1)
    retained.rejectWhen(() => false)

    const recovered = await runUnleashSwarmController(
      fixture.input,
      dependencies(retained, fixture, clock('2026-09-15T12:31:00.000Z')),
    )
    assert.equal(calls, 1)
    assert.equal(recovered.merge.candidate_count, 0)
    assert.equal(recovered.termination.decision, 'QUIESCENT')
    assert.equal(
      recovered.ledger.attempts.find(({ role_id: roleId }) => roleId === 'attacker:perimeter').state,
      'COMMITTED',
    )
  })
})

test('samples asynchronous authority gates again before later provider starts', async () => {
  const sharedIdentity = identity('gate-sampling')
  let calls = 0
  const adapter = createUnleashReasoningAdapter({
    identity: sharedIdentity,
    async invoke(envelope) {
      calls += 1
      return Buffer.from(JSON.stringify(providerResponse(envelope.request, {
        merge: { candidates: [] },
      })), 'utf8')
    },
  })
  const fixture = await campaignFixture({
    profileAssignments: UNLEASH_SWARM_ROLE_SET.roles.map(({ role_id: roleId }) => ({
      roleId,
      adapterIdentity: sharedIdentity,
    })),
    adapters: UNLEASH_SWARM_ROLE_SET.roles.map(({ role_id: roleId }) => ({ roleId, adapter })),
  })
  const retained = memoryStorage()
  let authorityChecks = 0
  const result = await runUnleashSwarmController(fixture.input, dependencies(
    retained,
    fixture,
    clock(),
    {
      authorityAvailable: async () => {
        authorityChecks += 1
        return authorityChecks !== 12
      },
    },
  ))

  assert.ok(authorityChecks > calls)
  assert.ok(calls < 7)
  assert.equal(result.termination.decision, 'POLICY_BLOCKED')
  assert.ok(result.gaps.some(({ reason_code: reasonCode }) => reasonCode === 'AUTHORITY_UNAVAILABLE'))
  assert.ok(result.gaps.some((entry) => (
    entry.role_id === null
    && entry.request_id === null
    && entry.state === 'FAILED_CLOSED'
    && entry.reason_code === 'AUTHORITY_UNAVAILABLE'
  )))
})

test('rechecks sticky terminal gates before each queued STARTED record and provider invocation', async (t) => {
  const cases = [
    {
      name: 'stop',
      field: 'stopRequested',
      observed(check) { return check === 4 },
      decision: 'STOPPED',
      reason: 'STOP_REQUESTED',
      state: 'STOPPED',
    },
    {
      name: 'authority',
      field: 'authorityAvailable',
      observed(check) { return check !== 4 },
      decision: 'POLICY_BLOCKED',
      reason: 'AUTHORITY_UNAVAILABLE',
      state: 'FAILED_CLOSED',
    },
    {
      name: 'deadline',
      field: 'deadlineExceeded',
      observed(check) { return check === 4 },
      decision: 'BUDGET_EXHAUSTED',
      reason: 'DEADLINE',
      state: 'INCONCLUSIVE',
    },
  ]
  for (const scenario of cases) {
    await t.test(scenario.name, async () => {
      const sharedIdentity = identity(`queued-gate-${scenario.name}`)
      const baseAdapter = emptyResponseAdapter(sharedIdentity)
      let calls = 0
      const adapter = createUnleashReasoningAdapter({
        identity: sharedIdentity,
        async invoke(envelope, context) {
          calls += 1
          return baseAdapter.invoke(envelope, context)
        },
      })
      const fixture = await campaignFixture({
        profileAssignments: UNLEASH_SWARM_ROLE_SET.roles.map(({ role_id: roleId }) => ({
          roleId,
          adapterIdentity: sharedIdentity,
        })),
        adapters: UNLEASH_SWARM_ROLE_SET.roles.map(({ role_id: roleId }) => ({ roleId, adapter })),
      })
      const retained = memoryStorage()
      let checks = 0
      const result = await runUnleashSwarmController(fixture.input, dependencies(
        retained,
        fixture,
        clock(),
        {
          [scenario.field]: async () => {
            checks += 1
            return scenario.observed(checks)
          },
        },
      ))

      assert.equal(calls, 0)
      assert.ok(checks >= 4)
      assert.equal(result.termination.decision, scenario.decision)
      assert.equal(result.termination.reason, scenario.reason)
      assert.ok(result.gaps.some((entry) => (
        entry.role_id === null
        && entry.request_id === null
        && entry.state === scenario.state
        && entry.reason_code === scenario.reason
      )))
      assert.equal(result.ledger.events.some(({ state }) => state === 'STARTED'), false)
    })
  }
})

test('does not invoke a provider when Stop becomes observable during STARTED publication', async () => {
  const sharedIdentity = identity('started-publication-stop')
  const baseAdapter = emptyResponseAdapter(sharedIdentity)
  let calls = 0
  const adapter = createUnleashReasoningAdapter({
    identity: sharedIdentity,
    async invoke(envelope, context) {
      calls += 1
      return baseAdapter.invoke(envelope, context)
    },
  })
  const fixture = await campaignFixture({
    profileAssignments: UNLEASH_SWARM_ROLE_SET.roles.map(({ role_id: roleId }) => ({
      roleId,
      adapterIdentity: sharedIdentity,
    })),
    adapters: UNLEASH_SWARM_ROLE_SET.roles.map(({ role_id: roleId }) => ({ roleId, adapter })),
  })
  const retained = memoryStorage()
  let stopRequested = false
  const storage = Object.freeze({
    async writeImmutableJson(filename, value) {
      const written = await retained.storage.writeImmutableJson(filename, value)
      if (filename.startsWith('swarm-attempt-event-') && value.state === 'STARTED') {
        stopRequested = true
      }
      return written
    },
    replaceMutableJson: retained.storage.replaceMutableJson,
    readJson: retained.storage.readJson,
    listJsonFilenames: retained.storage.listJsonFilenames,
  })
  const hooked = { ...retained, storage }
  const result = await runUnleashSwarmController(fixture.input, dependencies(
    hooked,
    fixture,
    clock(),
    { stopRequested: () => stopRequested },
  ))

  assert.equal(calls, 0)
  assert.equal(result.termination.decision, 'STOPPED')
  assert.equal(result.ledger.events.filter(({ state }) => state === 'STARTED').length, 1)
  const startedAttempt = result.ledger.attempts.find(({ state }) => state === 'FAILED')
  assert.equal(startedAttempt.failure.reason_code, 'STOP_REQUESTED')
  assert.equal(startedAttempt.failure.delivery, 'AMBIGUOUS')
})

test('resamples Stop after exclusive-owner validation and before provider invocation', async () => {
  const sharedIdentity = identity('owner-validation-stop')
  const baseAdapter = emptyResponseAdapter(sharedIdentity)
  let calls = 0
  const adapter = createUnleashReasoningAdapter({
    identity: sharedIdentity,
    async invoke(envelope, context) {
      calls += 1
      return baseAdapter.invoke(envelope, context)
    },
  })
  const fixture = await campaignFixture({
    profileAssignments: UNLEASH_SWARM_ROLE_SET.roles.map(({ role_id: roleId }) => ({
      roleId,
      adapterIdentity: sharedIdentity,
    })),
    adapters: UNLEASH_SWARM_ROLE_SET.roles.map(({ role_id: roleId }) => ({ roleId, adapter })),
  })
  const retained = memoryStorage()
  let stopRequested = false
  let ownerChecks = 0
  const result = await runUnleashSwarmController(fixture.input, dependencies(
    retained,
    fixture,
    clock(),
    {
      stopRequested: () => stopRequested,
      assertExclusiveOwner: async () => {
        ownerChecks += 1
        if (ownerChecks === 2) stopRequested = true
        return true
      },
    },
  ))

  assert.equal(calls, 0)
  assert.equal(ownerChecks, 2)
  assert.equal(result.termination.decision, 'STOPPED')
  assert.equal(result.ledger.events.filter(({ state }) => state === 'STARTED').length, 1)
  const startedAttempt = result.ledger.attempts.find(({ state }) => state === 'FAILED')
  assert.equal(startedAttempt.failure.reason_code, 'STOP_REQUESTED')
  assert.equal(startedAttempt.failure.delivery, 'AMBIGUOUS')
})

test('a superseded exclusive owner exits after STARTED without invoking or appending a terminal outcome', async () => {
  const sharedIdentity = identity('started-publication-owner')
  const baseAdapter = emptyResponseAdapter(sharedIdentity)
  let calls = 0
  const adapter = createUnleashReasoningAdapter({
    identity: sharedIdentity,
    async invoke(envelope, context) {
      calls += 1
      return baseAdapter.invoke(envelope, context)
    },
  })
  const fixture = await campaignFixture({
    profileAssignments: UNLEASH_SWARM_ROLE_SET.roles.map(({ role_id: roleId }) => ({
      roleId,
      adapterIdentity: sharedIdentity,
    })),
    adapters: UNLEASH_SWARM_ROLE_SET.roles.map(({ role_id: roleId }) => ({ roleId, adapter })),
  })
  const retained = memoryStorage()
  let ownerCurrent = true
  const storage = Object.freeze({
    async writeImmutableJson(filename, value) {
      const written = await retained.storage.writeImmutableJson(filename, value)
      if (filename.startsWith('swarm-attempt-event-') && value.state === 'STARTED') {
        ownerCurrent = false
      }
      return written
    },
    replaceMutableJson: retained.storage.replaceMutableJson,
    readJson: retained.storage.readJson,
    listJsonFilenames: retained.storage.listJsonFilenames,
  })
  const hooked = { ...retained, storage }

  await assert.rejects(
    runUnleashSwarmController(fixture.input, dependencies(
      hooked,
      fixture,
      clock(),
      { assertExclusiveOwner: () => ownerCurrent },
    )),
    { code: 'UNLEASH_SWARM_OWNER_SUPERSEDED' },
  )
  assert.equal(calls, 0)
  const eventNames = await retained.storage.listJsonFilenames()
  const events = await Promise.all(eventNames
    .filter((filename) => filename.startsWith('swarm-attempt-event-'))
    .map((filename) => retained.storage.readJson(filename)))
  assert.equal(events.filter(({ state }) => state === 'STARTED').length, 1)
  assert.equal(events.some(({ state }) => ['CAPTURED', 'VALIDATED', 'COMMITTED', 'FAILED'].includes(state)), false)
})

test('records a terminal deadline control gap after otherwise successful stable waves', async () => {
  const sharedIdentity = identity('terminal-deadline')
  const baseAdapter = emptyResponseAdapter(sharedIdentity)
  let calls = 0
  const adapter = createUnleashReasoningAdapter({
    identity: sharedIdentity,
    async invoke(envelope, context) {
      calls += 1
      return baseAdapter.invoke(envelope, context)
    },
  })
  const fixture = await campaignFixture({
    profileAssignments: UNLEASH_SWARM_ROLE_SET.roles.map(({ role_id: roleId }) => ({
      roleId,
      adapterIdentity: sharedIdentity,
    })),
    adapters: UNLEASH_SWARM_ROLE_SET.roles.map(({ role_id: roleId }) => ({ roleId, adapter })),
  })
  const retained = memoryStorage()
  const result = await runUnleashSwarmController(fixture.input, dependencies(
    retained,
    fixture,
    clock(),
    { deadlineExceeded: () => calls >= 7 },
  ))

  assert.equal(calls, 7)
  assert.deepEqual(result.termination, {
    decision: 'BUDGET_EXHAUSTED',
    reason: 'DEADLINE',
    stable: true,
    terminal: true,
  })
  assert.equal(result.gaps.length, 1)
  assert.equal(result.gaps[0].role_id, null)
  assert.equal(result.gaps[0].request_id, null)
  assert.equal(result.gaps[0].state, 'INCONCLUSIVE')
  assert.equal(result.gaps[0].reason_code, 'DEADLINE')
})

test('rejects computed controller input and a valid basis rebound to other recon evidence', async () => {
  const fixture = await campaignFixture({ profileAssignments: [], adapters: [] })
  const retained = memoryStorage()
  let getterCalls = 0
  const computed = { ...fixture.input }
  Object.defineProperty(computed, 'basis', {
    enumerable: true,
    get() {
      getterCalls += 1
      throw new Error('must not execute')
    },
  })
  await assert.rejects(
    runUnleashSwarmController(computed, dependencies(retained, fixture)),
    (error) => error instanceof UnleashSwarmControllerError
      && error.code === 'UNLEASH_SWARM_CONTROLLER_INPUT_INVALID',
  )
  assert.equal(getterCalls, 0)

  const original = fixture.input.basis
  const rebound = createUnleashSwarmBasis({
    recordedAt: original.recorded_at,
    campaignId: original.campaign_id,
    campaignStateRevision: original.campaign_state_revision,
    campaignStateSha256: original.campaign_state_sha256,
    planSha256: original.plan_sha256,
    targetId: original.target_id,
    registrySha256: original.registry_sha256,
    providerProfileSha256: original.provider_profile_sha256,
    evidencePacketSha256: digestText('other-evidence-packet'),
    completionReceiptSha256: original.completion_receipt_sha256,
    limits: structuredClone(original.limits),
  })
  await assert.rejects(
    runUnleashSwarmController(
      { ...fixture.input, basis: rebound },
      dependencies(memoryStorage(), fixture),
    ),
    (error) => error instanceof UnleashSwarmControllerError
      && error.code === 'UNLEASH_SWARM_CONTROLLER_EVIDENCE_INVALID',
  )
})
