import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { test } from 'node:test'

import {
  assertValidUnleashReconCompletion,
  createVerifiedReconCompletion,
  createVerifiedReconEvidencePacket,
  verifyUnleashReconCompletion,
} from '../scripts/lib/unleash-recon-evidence.mjs'
import {
  assertExactUnleashHttpsReconExecutionContract,
  createUnleashPlan,
  digestUnleashHttpsReconExecutionContract,
  digestUnleashValue,
  getUnleashHttpsReconExecutionContract,
} from '../scripts/lib/unleash-contracts.mjs'
import { createUnleashEvidencePacket } from '../scripts/lib/unleash-evidence-packet.mjs'
import { createUnleashDeploymentPolicy } from '../scripts/lib/unleash-policy.mjs'
import { createDefaultUnleashPlannerDependencies } from '../scripts/lib/unleash-registry.mjs'

const RECON_PLAN_SHA256 = 'b'.repeat(64)
const EVENT_SHA256 = 'd'.repeat(64)
const NOW = new Date('2026-09-15T12:30:00.000Z')
const DEPLOYMENT_POLICY = createUnleashDeploymentPolicy({
  schema_version: '1.0.0',
  kind: 'last-aperture/unleash-deployment-policy',
  policy_id: 'policy:recon-evidence-test',
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
  revocation: { check_id: 'revocation:recon-evidence-test', fail_mode: 'CLOSED' },
})
const PLAN = createUnleashPlan(
  { target: 'https://example.test/' },
  createDefaultUnleashPlannerDependencies({ policy: DEPLOYMENT_POLICY }),
)
const UNLEASH_PLAN_SHA256 = PLAN.plan_sha256

function controllerAuthority(overrides = {}) {
  return {
    mode: 'CONTROLLER_DEPLOYMENT_POLICY',
    policy_id: PLAN.policy_id,
    policy_sha256: PLAN.policy_sha256,
    target_id: PLAN.target.target_id,
    effect: 'OBSERVE',
    admitted_at: NOW.toISOString(),
    revocation_check_id: PLAN.authority.revocation.check_id,
    ...overrides,
  }
}

function verifiedRecon(overrides = {}) {
  const authority = controllerAuthority()
  return {
    schema_version: '1.0.0',
    kind: 'last-aperture/verified-http-recon-evidence',
    run: {
      run_id: 'http-recon-run:fixture',
      plan_sha256: RECON_PLAN_SHA256,
      state: 'PROBE_PLAN_COMPLETE',
      authorization: authority,
      event_chain: { count: 3, last_sha256: EVENT_SHA256 },
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
    ...overrides,
  }
}

async function verifiedCompletion(verified = verifiedRecon(), dependencies = {}) {
  return createVerifiedReconCompletion({
    bundle: 'controller-owned/recon',
    plan: PLAN,
  }, {
    now: () => new Date(NOW),
    readVerifiedRecon: async () => structuredClone(verified),
    ...dependencies,
  })
}

function resealCompletionReceipt(completion) {
  const receipt = completion.completion_receipt
  receipt.authority_sha256 = digestUnleashValue(receipt.authority)
  const { completion_receipt_sha256: ignored, ...unsigned } = receipt
  receipt.completion_receipt_sha256 = digestUnleashValue(unsigned)
}

test('re-verifies finalized recon and emits one metadata-only packet', async () => {
  const calls = []
  const verified = verifiedRecon()
  const packet = await createVerifiedReconEvidencePacket({
    bundle: 'controller-owned/recon',
    plan: PLAN,
  }, {
    now: () => new Date(NOW),
    readVerifiedRecon: async (input) => {
      calls.push(input)
      return structuredClone(verified)
    },
  })

  assert.equal(calls.length, 2)
  assert.deepEqual(calls, [
    { bundle: 'controller-owned/recon', now: calls[0].now },
    { bundle: 'controller-owned/recon', now: calls[1].now },
  ])
  assert.equal(typeof calls[0].now, 'function')
  assert.equal(packet.plan_sha256, UNLEASH_PLAN_SHA256)
  assert.equal(packet.sources.length, 1)
  assert.equal(packet.sources[0].verifier_id, 'verifier:last-aperture-http-recon')
  assert.equal(packet.sources[0].media_type, 'application/json')
  assert.equal(packet.redaction.payload_values_included, false)
  assert.equal(packet.trust.semantic_authority, 'NONE')
  assert.equal(packet.trust.input_authentication, 'LOCALLY_HASH_CHAIN_VERIFIED')
  const serialized = JSON.stringify(packet)
  assert.equal(serialized.includes('https://example.test/'), false)
  assert.equal(serialized.includes('content-type'), false)
})

test('emits one typed completion receipt bound to the exact route execution and verified run', async () => {
  const verified = verifiedRecon()
  const completion = await verifiedCompletion(verified)
  const receipt = completion.completion_receipt
  const source = completion.evidence_packet.sources[0]

  assert.equal(receipt.route_id, 'https-recon')
  assert.equal(receipt.tool_id, 'tool:https-recon')
  assert.equal(receipt.execution_contract_sha256, digestUnleashHttpsReconExecutionContract())
  assert.equal(receipt.adapter_id, 'adapter:last-aperture-http-recon')
  assert.equal(receipt.verifier_id, 'verifier:last-aperture-http-recon')
  assert.equal(receipt.recon_run_id, verified.run.run_id)
  assert.equal(receipt.recon_plan_sha256, verified.run.plan_sha256)
  assert.equal(receipt.recon_event_count, verified.run.event_chain.count)
  assert.equal(receipt.recon_event_head_sha256, verified.run.event_chain.last_sha256)
  assert.equal(receipt.unleash_plan_sha256, PLAN.plan_sha256)
  assert.equal(receipt.unleash_registry_sha256, PLAN.registry_sha256)
  assert.equal(receipt.target_id, PLAN.target.target_id)
  assert.equal(receipt.target_url, PLAN.target.canonical_locator)
  assert.equal(receipt.policy_id, PLAN.policy_id)
  assert.equal(receipt.policy_sha256, PLAN.policy_sha256)
  assert.deepEqual(receipt.authority, controllerAuthority())
  assert.equal(receipt.authority_sha256, digestUnleashValue(controllerAuthority()))
  assert.equal(Object.hasOwn(receipt.authority, 'operator_id'), false)
  assert.equal(Object.hasOwn(receipt.authority, 'authorization_reference'), false)
  assert.equal(receipt.evidence_ref, source.evidence_ref)
  assert.equal(receipt.evidence_receipt_sha256, source.receipt_sha256)
  assert.equal(receipt.observed_at, NOW.toISOString())
  assert.doesNotThrow(() => assertValidUnleashReconCompletion(completion, { plan: PLAN }))
  await assert.doesNotReject(() => verifyUnleashReconCompletion({
    bundle: 'controller-owned/recon',
    plan: PLAN,
    completion,
  }, {
    readVerifiedRecon: async () => structuredClone(verified),
  }))
})

test('rejects every resealed route, adapter, verifier, run, plan, event, target, policy, and evidence rebind', async () => {
  const verified = verifiedRecon()
  const original = await verifiedCompletion(verified)
  const mutations = [
    (receipt) => { receipt.route_id = 'bounty-recon' },
    (receipt) => { receipt.tool_id = 'tool:bounty-recon' },
    (receipt) => { receipt.execution_contract_sha256 = 'e'.repeat(64) },
    (receipt) => { receipt.adapter_id = 'adapter:last-aperture:other' },
    (receipt) => { receipt.verifier_id = 'verifier:last-aperture-other' },
    (receipt) => { receipt.recon_run_id = 'http-recon-run:other' },
    (receipt) => { receipt.recon_plan_sha256 = 'e'.repeat(64) },
    (receipt) => { receipt.recon_event_count += 1 },
    (receipt) => { receipt.recon_event_head_sha256 = 'e'.repeat(64) },
    (receipt) => { receipt.unleash_plan_sha256 = 'e'.repeat(64) },
    (receipt) => { receipt.unleash_registry_sha256 = 'e'.repeat(64) },
    (receipt) => { receipt.target_id = `target:sha256:${'e'.repeat(64)}` },
    (receipt) => { receipt.target_url = 'https://other.example.test/' },
    (receipt) => { receipt.policy_id = 'policy:other' },
    (receipt) => { receipt.policy_sha256 = 'e'.repeat(64) },
    (receipt) => { receipt.authority.mode = 'OPERATOR_ATTESTED' },
    (receipt) => { receipt.authority.policy_id = 'policy:other' },
    (receipt) => { receipt.authority.policy_sha256 = 'e'.repeat(64) },
    (receipt) => { receipt.authority.target_id = `target:sha256:${'e'.repeat(64)}` },
    (receipt) => { receipt.authority.effect = 'PROBE' },
    (receipt) => { receipt.authority.admitted_at = '2026-09-15T11:59:59.999Z' },
    (receipt) => { receipt.authority.revocation_check_id = 'revocation:other' },
    (receipt) => { receipt.evidence_ref = `evidence:sha256:${'e'.repeat(64)}` },
    (receipt) => { receipt.evidence_receipt_sha256 = 'e'.repeat(64) },
  ]

  for (const mutate of mutations) {
    const completion = structuredClone(original)
    mutate(completion.completion_receipt)
    resealCompletionReceipt(completion)
    await assert.rejects(() => verifyUnleashReconCompletion({
      bundle: 'controller-owned/recon',
      plan: PLAN,
      completion,
    }, {
      readVerifiedRecon: async () => structuredClone(verified),
    }), /completion|receipt|schema|route|verifier|contract|plan|target|policy|evidence/i)
  }
})

test('rejects execution-contract drift and evidence-packet builders that bypass enrollment', async () => {
  const exactContract = getUnleashHttpsReconExecutionContract()
  assert.doesNotThrow(() => assertExactUnleashHttpsReconExecutionContract(exactContract))
  const alteredContract = structuredClone(exactContract)
  alteredContract.limits.max_probe_requests += 1
  assert.throws(
    () => assertExactUnleashHttpsReconExecutionContract(alteredContract),
    /execution contract|adapter/i,
  )

  await assert.rejects(() => verifiedCompletion(verifiedRecon(), {
    createEvidencePacket: async (input, options) => createUnleashEvidencePacket(input, {
      ...options,
      verifierId: 'verifier:last-aperture-other',
      verifyEvidence: (request) => ({
        authenticated: true,
        verifier_id: 'verifier:last-aperture-other',
        plan_sha256: request.plan_sha256,
        evidence_ref: request.evidence_ref,
        content_sha256: request.content_sha256,
        receipt_sha256: request.receipt_sha256,
      }),
    }),
  }), /bypassed|enrolled verifier|completion/i)
})

test('fails closed when the authenticated recon changes between projection and verification', async () => {
  let calls = 0
  await assert.rejects(() => createVerifiedReconEvidencePacket({
    bundle: 'controller-owned/recon',
    plan: PLAN,
  }, {
    now: () => new Date(NOW),
    readVerifiedRecon: async () => {
      calls += 1
      return calls === 1
        ? verifiedRecon()
        : verifiedRecon({ observations: [{ method: 'HEAD', status_code: 503 }] })
    },
  }))
  assert.equal(calls, 2)
})

test('rejects malformed verified recon before constructing a packet', async () => {
  for (const verified of [
    null,
    {},
    verifiedRecon({ kind: 'provider-asserted-recon' }),
    verifiedRecon({ observations: [] }),
    verifiedRecon({ run: { ...verifiedRecon().run, state: 'PLANNED' } }),
  ]) {
    let calls = 0
    await assert.rejects(() => createVerifiedReconEvidencePacket({
      bundle: 'controller-owned/recon',
      plan: PLAN,
    }, {
      now: () => new Date(NOW),
      readVerifiedRecon: async () => { calls += 1; return verified },
    }))
    assert.equal(calls, 1)
  }
})

test('binds the evidence reference to the canonical verified recon bytes', async () => {
  const verified = verifiedRecon()
  const packet = await createVerifiedReconEvidencePacket({
    bundle: 'controller-owned/recon',
    plan: PLAN,
  }, {
    now: () => new Date(NOW),
    readVerifiedRecon: async () => structuredClone(verified),
  })
  assert.match(packet.sources[0].evidence_ref, /^evidence:sha256:[a-f0-9]{64}$/u)
  assert.equal(
    packet.sources[0].source_sha256,
    packet.sources[0].evidence_ref.slice('evidence:sha256:'.length),
  )
  assert.notEqual(packet.sources[0].source_sha256, createHash('sha256').update('{}').digest('hex'))
})

test('rejects recon whose target, exact controller authority, or sealed action differs from the unleash plan', async () => {
  for (const mutate of [
    (value) => { value.run.target.origin = 'https://other.example.test' },
    (value) => { value.run.authorization.policy_sha256 = 'f'.repeat(64) },
    (value) => { value.run.authorization.target_id = `target:sha256:${'f'.repeat(64)}` },
    (value) => { value.run.authorization.revocation_check_id = 'revocation:other' },
    (value) => { value.run.authorization.admitted_at = '2026-09-15T13:00:00.000Z' },
    (value) => { value.observations[0].authority.policy_sha256 = 'f'.repeat(64) },
    (value) => { value.run.actions[0].url = 'https://other.example.test/' },
    (value) => { value.run.actions[0].method = 'GET' },
    (value) => { value.run.actions[0].request_headers = [] },
    (value) => { value.observations[0].url = 'https://other.example.test/' },
  ]) {
    const verified = verifiedRecon()
    mutate(verified)
    await assert.rejects(() => createVerifiedReconEvidencePacket({
      bundle: 'controller-owned/recon',
      plan: PLAN,
    }, {
      now: () => new Date(NOW),
      readVerifiedRecon: async () => structuredClone(verified),
    }), /target|policy|action|plan|bind/i)
  }
})
