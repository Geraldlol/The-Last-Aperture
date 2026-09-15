import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import Ajv2020 from 'ajv/dist/2020.js'

import {
  assertValidUnleashEvidencePacket,
  createUnleashEvidencePacket,
  UNLEASH_EVIDENCE_LIMITS,
} from '../scripts/lib/unleash-evidence-packet.mjs'

const PLAN = 'a'.repeat(64)
const VERIFIER = 'verifier:offline-unit-test'
const NOW = new Date('2026-09-15T12:00:00.000Z')
const sha256 = (text) => createHash('sha256').update(text, 'utf8').digest('hex')

function evidence(content = 'synthetic private source value', receipt = 'synthetic detached receipt') {
  return {
    evidence_ref: `evidence:sha256:${sha256(content)}`,
    media_type: 'text/plain',
    content,
    receipt,
  }
}

function verified(request) {
  return {
    authenticated: true,
    verifier_id: VERIFIER,
    plan_sha256: request.plan_sha256,
    evidence_ref: request.evidence_ref,
    content_sha256: request.content_sha256,
    receipt_sha256: request.receipt_sha256,
  }
}

function options(overrides = {}) {
  return { now: NOW, verifierId: VERIFIER, verifyEvidence: verified, ...overrides }
}

test('authenticates supplied text before producing a metadata-only packet', async () => {
  const source = evidence()
  const requests = []
  const packet = await createUnleashEvidencePacket({ plan_sha256: PLAN, evidence: [source] }, options({
    verifyEvidence: async (request) => {
      requests.push(request)
      assert.equal(Object.isFrozen(request), true)
      assert.equal(request.content, source.content)
      assert.equal(request.receipt, source.receipt)
      return verified(request)
    },
  }))

  assert.equal(requests.length, 1)
  assert.equal(packet.plan_sha256, PLAN)
  assert.equal(packet.created_at, NOW.toISOString())
  assert.equal(packet.sources[0].source_sha256, sha256(source.content))
  assert.equal(packet.sources[0].source_bytes, Buffer.byteLength(source.content))
  assert.equal(packet.sources[0].receipt_sha256, sha256(source.receipt))
  assert.equal(packet.sources[0].verifier_id, VERIFIER)
  assert.equal(packet.redaction.mode, 'METADATA_ONLY')
  assert.equal(packet.redaction.payload_values_included, false)
  assert.equal(packet.trust.packet_authenticity, 'UNANCHORED')
  assert.equal(packet.trust.semantic_authority, 'NONE')
  assert.equal(JSON.stringify(packet).includes(source.content), false)
  assert.equal(JSON.stringify(packet).includes(source.receipt), false)
  assert.equal(Object.isFrozen(packet), true)
  assert.equal(Object.isFrozen(packet.sources[0]), true)
  assert.doesNotThrow(() => assertValidUnleashEvidencePacket(packet))

  const schema = JSON.parse(readFileSync(new URL('../schemas/unleash-evidence-packet.schema.json', import.meta.url), 'utf8'))
  const validate = new Ajv2020({ strict: true, allErrors: true }).compile(schema)
  assert.equal(validate(packet), true, JSON.stringify(validate.errors))
})

test('omits all content values rather than relying on secret-pattern recognition', async () => {
  const content = JSON.stringify({
    arbitrary_field: 'unique-private-canary-123',
    nested: { password: 'synthetic-password', participant: 'synthetic-person' },
  })
  const source = { ...evidence(content), media_type: 'application/json' }
  const packet = await createUnleashEvidencePacket({ plan_sha256: PLAN, evidence: [source] }, options())
  const serialized = JSON.stringify(packet)
  for (const marker of ['unique-private-canary-123', 'synthetic-password', 'synthetic-person', 'arbitrary_field']) {
    assert.equal(serialized.includes(marker), false)
  }
})

test('binds packet digests to the plan and source metadata deterministically', async () => {
  const input = { plan_sha256: PLAN, evidence: [evidence('second'), evidence('first')] }
  const first = await createUnleashEvidencePacket(input, options())
  const reordered = await createUnleashEvidencePacket({ ...input, evidence: [...input.evidence].reverse() }, options())
  assert.deepEqual(reordered, first)
  assert.match(first.packet_sha256, /^[a-f0-9]{64}$/)
  const otherPlan = await createUnleashEvidencePacket({ ...input, plan_sha256: 'b'.repeat(64) }, options())
  assert.notEqual(otherPlan.packet_sha256, first.packet_sha256)
  const changed = structuredClone(first)
  changed.sources[0].source_bytes += 1
  assert.throws(() => assertValidUnleashEvidencePacket(changed))
})

test('rejects source digest mismatch and duplicate evidence before calling the verifier', async () => {
  let calls = 0
  const deps = options({ verifyEvidence: (request) => { calls += 1; return verified(request) } })
  const source = evidence()
  for (const sources of [
    [{ ...source, content: 'changed after signing' }],
    [source, structuredClone(source)],
    [source, { ...evidence('other'), evidence_ref: 'evidence:sha256:not-a-digest' }],
  ]) {
    await assert.rejects(() => createUnleashEvidencePacket({ plan_sha256: PLAN, evidence: sources }, deps))
  }
  assert.equal(calls, 0)
})

test('rejects unbounded or unsupported input before calling the verifier', async () => {
  let calls = 0
  const deps = options({ verifyEvidence: (request) => { calls += 1; return verified(request) } })
  for (const input of [
    { plan_sha256: PLAN, evidence: [] },
    { plan_sha256: PLAN, evidence: [evidence()], target: 'untrusted extra field' },
    { plan_sha256: PLAN, evidence: [{ ...evidence(), filename: '/private/path' }] },
    { plan_sha256: PLAN, evidence: [{ ...evidence(), media_type: 'application/octet-stream' }] },
    { plan_sha256: PLAN, evidence: [evidence('x'.repeat(UNLEASH_EVIDENCE_LIMITS.max_source_bytes + 1))] },
    { plan_sha256: PLAN, evidence: [evidence('text', 'r'.repeat(UNLEASH_EVIDENCE_LIMITS.max_receipt_bytes + 1))] },
    { plan_sha256: PLAN, evidence: Array.from({ length: UNLEASH_EVIDENCE_LIMITS.max_items + 1 }, (_, index) => evidence(String(index))) },
  ]) {
    await assert.rejects(() => createUnleashEvidencePacket(input, deps))
  }
  assert.equal(calls, 0)
})

test('enforces cumulative source and receipt limits before any verification', async () => {
  let calls = 0
  const deps = options({ verifyEvidence: (request) => { calls += 1; return verified(request) } })
  const manySources = Array.from({ length: 5 }, (_, index) => evidence(String(index).repeat(UNLEASH_EVIDENCE_LIMITS.max_source_bytes)))
  const manyReceipts = Array.from({ length: 5 }, (_, index) => evidence(String(index), 'r'.repeat(UNLEASH_EVIDENCE_LIMITS.max_receipt_bytes)))
  await assert.rejects(() => createUnleashEvidencePacket({ plan_sha256: PLAN, evidence: manySources }, deps))
  await assert.rejects(() => createUnleashEvidencePacket({ plan_sha256: PLAN, evidence: manyReceipts }, deps))
  assert.equal(calls, 0)
})

test('fails closed for absent, unauthenticated, malformed, or misbound verifier results', async () => {
  const input = { plan_sha256: PLAN, evidence: [evidence()] }
  for (const verifyEvidence of [
    undefined, () => true, () => null,
    (request) => ({ ...verified(request), authenticated: false }),
    (request) => ({ ...verified(request), verifier_id: 'verifier:untrusted' }),
    (request) => ({ ...verified(request), plan_sha256: 'b'.repeat(64) }),
    (request) => ({ ...verified(request), content_sha256: 'b'.repeat(64) }),
    (request) => ({ ...verified(request), receipt_sha256: 'b'.repeat(64) }),
    (request) => ({ ...verified(request), evidence_ref: `evidence:sha256:${'b'.repeat(64)}` }),
    (request) => ({ ...verified(request), proof_state: 'VERIFIED' }),
  ]) {
    await assert.rejects(() => createUnleashEvidencePacket(input, options({ verifyEvidence })))
  }
})

test('sanitizes synchronous and asynchronous verifier failures', async () => {
  const marker = 'synthetic-private-verifier-error'
  for (const verifyEvidence of [
    () => { throw new Error(marker) },
    async () => { throw new Error(marker) },
  ]) {
    await assert.rejects(
      () => createUnleashEvidencePacket({ plan_sha256: PLAN, evidence: [evidence()] }, options({ verifyEvidence })),
      (error) => error.name === 'UnleashEvidencePacketError'
        && !String(error.stack).includes(marker) && error.cause === undefined,
    )
  }
})

test('times out an unsettled verifier and signals cancellation without returning a packet', async () => {
  let signal
  await assert.rejects(
    () => createUnleashEvidencePacket({ plan_sha256: PLAN, evidence: [evidence()] }, options({
      verificationTimeoutMs: 20,
      verifyEvidence: (request) => { signal = request.signal; return new Promise(() => {}) },
    })),
    (error) => error.code === 'UNLEASH_EVIDENCE_VERIFICATION_TIMEOUT',
  )
  assert.equal(signal.aborted, true)
})

test('snapshots every input before awaiting authentication', async () => {
  const second = evidence('original second source')
  const input = { plan_sha256: PLAN, evidence: [evidence('first source'), second] }
  const observed = []
  const packet = await createUnleashEvidencePacket(input, options({
    verifyEvidence: async (request) => {
      observed.push(request.content)
      input.plan_sha256 = 'b'.repeat(64)
      second.content = 'caller replacement'
      return verified(request)
    },
  }))
  assert.equal(packet.plan_sha256, PLAN)
  assert.deepEqual(observed.sort(), ['first source', 'original second source'].sort())
})

test('rejects accessors without invoking caller-controlled getters', async () => {
  let reads = 0
  const source = evidence()
  Object.defineProperty(source, 'content', { enumerable: true, get() { reads += 1; return 'getter data' } })
  await assert.rejects(() => createUnleashEvidencePacket({ plan_sha256: PLAN, evidence: [source] }, options()))
  assert.equal(reads, 0)
})

test('packet validation rejects payload injection and false authenticity or semantic claims', async () => {
  const packet = await createUnleashEvidencePacket({ plan_sha256: PLAN, evidence: [evidence()] }, options())
  for (const mutate of [
    (value) => { value.sources[0].content = 'injected content' },
    (value) => { value.trust.packet_authenticity = 'AUTHENTICATED' },
    (value) => { value.trust.semantic_authority = 'VERIFIED' },
    (value) => { value.redaction.payload_values_included = true },
  ]) {
    const changed = structuredClone(packet)
    mutate(changed)
    assert.throws(() => assertValidUnleashEvidencePacket(changed))
  }
})

test('rejects observation times that cannot satisfy the packet timestamp schema', async () => {
  for (const now of [new Date(Number.NaN), new Date('+010000-01-01T00:00:00.000Z')]) {
    await assert.rejects(() => createUnleashEvidencePacket(
      { plan_sha256: PLAN, evidence: [evidence()] }, options({ now }),
    ))
  }
})
