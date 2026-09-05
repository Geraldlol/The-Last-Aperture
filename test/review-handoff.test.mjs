import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildReviewTemplate } from '../scripts/lib/review-handoff.mjs'
import { validateJobResult } from '../scripts/lib/job-protocol.mjs'

function packet(overrides = {}) {
  return {
    kind: 'LENS',
    run_id: 'run:review:001',
    job_id: 'lens:web-and-api:001',
    lens: 'web-and-api',
    packet_sha256: 'a'.repeat(64),
    scoped_files: ['src/orders.js'],
    topic_obligations: ['authz-object-level', 'authz-function-level'],
    ...overrides,
  }
}

test('review template is bound to its packet and cannot be ingested as completed analysis', () => {
  const input = packet()
  const before = structuredClone(input)
  const handoff = buildReviewTemplate(input)
  assert.equal(handoff.analysis_status, 'NOT_PERFORMED')
  assert.equal(handoff.input.packet_sha256, input.packet_sha256)
  assert.equal(handoff.result_template.input_sha256, input.packet_sha256)
  assert.equal(handoff.result_template.run_id, input.run_id)
  assert.equal(handoff.result_template.job_id, input.job_id)
  assert.equal(handoff.result_template.state, null)
  assert.deepEqual(handoff.result_template.producer, { name: null, version: null, instance_id: null })
  assert.equal(validateJobResult(handoff.result_template).valid, false)
  assert.deepEqual(input, before)
})

test('every topic starts as not assessed with an explicit matching coverage gap', () => {
  const input = packet()
  const result = buildReviewTemplate(input).result_template
  assert.deepEqual(result.findings, [])
  assert.deepEqual(result.examined_files, [])
  assert.deepEqual(result.topic_assessments.map(({ topic }) => topic), input.topic_obligations)
  const gapAreas = new Set(result.coverage_gaps.map(({ area }) => area))
  assert.ok(result.topic_assessments.every((entry) => (
    entry.disposition === 'not-assessed'
    && entry.coverage_gap_areas.every((area) => gapAreas.has(area))
  )))
  // Populating metadata does not erase the retained not-assessed gaps.
  result.state = 'SUCCEEDED'
  result.producer = { name: 'synthetic-reviewer', version: '1.0.0', instance_id: 'test:reviewer:001' }
  assert.equal(validateJobResult(result).valid, true)
  assert.equal(result.topic_assessments[0].disposition, 'not-assessed')
})

test('review handoff projects metadata without provider instructions, finding narratives or source payloads', () => {
  const privateValue = 'SYNTHETIC_PRIVATE_CONTENT_SENTINEL'
  const input = packet({
    instructions: [privateValue],
    source: privateValue,
    raw_bytes: privateValue,
    findings: [{ evidence: privateValue, attack: privateValue }],
    authorization: privateValue,
  })
  const handoff = buildReviewTemplate(input)
  assert.ok(!JSON.stringify(handoff).includes(privateValue))
  assert.ok(handoff.instructions.every((entry) => !entry.includes(privateValue)))
  assert.deepEqual(handoff.input.source_path_examples, ['src/orders.js'])
})

test('review handoff explicitly samples paths and does not invent topics for a zero-owner lens', () => {
  const paths = Array.from({ length: 25 }, (_, index) => `src/file-${index}.js`)
  const handoff = buildReviewTemplate(packet({ scoped_files: paths, topic_obligations: [] }))
  assert.equal(handoff.input.source_file_count, 25)
  assert.equal(handoff.input.source_path_examples.length, 20)
  assert.equal(handoff.input.omitted_source_path_count, 5)
  assert.equal(Object.hasOwn(handoff.result_template, 'topic_assessments'), false)
  assert.equal(handoff.analysis_status, 'NOT_PERFORMED')
})

test('review handoff rejects a proof job or a missing controller-bound packet digest', () => {
  assert.throws(() => buildReviewTemplate(packet({ kind: 'PROOF' })), /LENS jobs only/)
  assert.throws(() => buildReviewTemplate(packet({ packet_sha256: undefined })), /controller-bound packet digest/)
  assert.throws(() => buildReviewTemplate(packet({ packet_sha256: 'untrusted' })), /controller-bound packet digest/)
})
