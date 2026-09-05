import test from 'node:test'
import assert from 'node:assert/strict'
import {
  assertValidBenchmarkInput,
  benchmarkInputSchema,
  bindBenchmarkPrimaryRun,
  bindBenchmarkPrimaryOutcomes,
} from '../scripts/lib/benchmark-contracts.mjs'

test('benchmark input schema requires one bounded primary repeated-run envelope', () => {
  assert.equal(
    benchmarkInputSchema.$schema,
    'https://json-schema.org/draft/2020-12/schema',
  )
  assert.doesNotThrow(() => assertValidBenchmarkInput({
    primary_run_id: 'repeat:1',
    observedFindings: [],
    caseOutcomes: [],
    repeatedRuns: [{ run_id: 'repeat:1', findings: [] }],
  }))
  assert.throws(
    () => assertValidBenchmarkInput({
      observedFindings: [],
      repeatedRuns: [{ run_id: 'repeat:1', findings: [] }],
    }),
    /requires primary_run_id/,
  )
  assert.throws(
    () => assertValidBenchmarkInput({
      primary_run_id: 'repeat:1',
      observedFindings: [],
      repeatedRuns: Array.from({ length: 65 }, (_, index) => ({
        run_id: `repeat:${index}`,
        findings: [],
      })),
    }),
    /must NOT have more than 64 items/,
  )
})

test('primary benchmark evidence binds to one exact normalized repeated run', () => {
  const first = {
    case_id: 'V-001',
    candidate_id: 'candidate:first',
    topic: 'authz-object-level',
  }
  const second = {
    case_id: 'V-002',
    candidate_id: 'candidate:second',
    topic: 'injection-sql-nosql-orm',
  }
  const binding = bindBenchmarkPrimaryRun(
    ' repeat:primary ',
    [first, second],
    [{
      run_id: 'repeat:primary',
      findings: [second, first],
    }],
  )
  assert.deepEqual(
    {
      run_id: binding.run_id,
      normalized_finding_count: binding.normalized_finding_count,
      bound_to_repeated_run: binding.bound_to_repeated_run,
    },
    {
      run_id: 'repeat:primary',
      normalized_finding_count: 2,
      bound_to_repeated_run: true,
    },
  )
  assert.match(binding.normalized_finding_set_sha256, /^[a-f0-9]{64}$/)

  assert.throws(
    () => bindBenchmarkPrimaryRun(
      'repeat:primary',
      [first],
      [{ run_id: 'repeat:primary', findings: [second] }],
    ),
    /must exactly match repeated run "repeat:primary"/,
  )
  assert.throws(
    () => bindBenchmarkPrimaryRun(
      'repeat:missing',
      [first],
      [{ run_id: 'repeat:other', findings: [first] }],
    ),
    /must identify exactly one repeated run/,
  )
})

const benchmarkEnvelope = () => ({
  primary_run_id: 'repeat:1',
  observedFindings: [],
  repeatedRuns: [{ run_id: 'repeat:1', findings: [] }],
})
const measurementMetadata = () => ({
  model: { name: 'synthetic-test-model', version: '2026-09-05', configuration_sha256: 'a'.repeat(64) },
  harness: { name: 'synthetic-harness', version: '1.0.0' },
  corpus: { name: 'development-regression-fixtures', version: '1' },
})

test('optional measurement metadata records bounded descriptive versions', () => {
  const envelope = benchmarkEnvelope()
  envelope.measurement = measurementMetadata()
  envelope.repeatedRuns[0].caseOutcomes = [{ case_id: 'C-001', verdict: 'clear' }]
  assert.equal(assertValidBenchmarkInput(envelope), envelope)
  assert.doesNotThrow(() => assertValidBenchmarkInput(benchmarkEnvelope()))
})

test('measurement metadata rejects unsupported claims, missing versions, and unbounded fields', () => {
  const variants = [
    { ...measurementMetadata(), verified_accuracy: 1 },
    { ...measurementMetadata(), model: { name: 'model' } },
    { ...measurementMetadata(), corpus: { name: 'corpus', version: 'x'.repeat(161) } },
    { ...measurementMetadata(), harness: { name: ' ', version: '1' } },
    { ...measurementMetadata(), model: { name: 'model\nclaimed', version: '1' } },
    { ...measurementMetadata(), corpus: { name: 'corpus', version: '1', independently_reviewed: true } },
    { ...measurementMetadata(), model: { name: 'model', version: '1', configuration_sha256: 'fake' } },
  ]
  for (const measurement of variants) {
    assert.throws(() => assertValidBenchmarkInput({ ...benchmarkEnvelope(), measurement }), /contract validation failed/)
  }
})

test('repeat outcomes are bounded and cannot supply schema-invalid counts', () => {
  for (const run of [
    { run_id: 'repeat:1', findings: [], schemaInvalidCount: 0 },
    { run_id: 'repeat:1', findings: [], caseOutcomes: [{ case_id: 'C-001', verdict: 'probably_clear' }] },
    { run_id: 'repeat:1', findings: [], caseOutcomes: [{ case_id: 'C-001', verdict: 'clear', trusted: true }] },
    { run_id: 'repeat:1', findings: [], caseOutcomes: Array(4097).fill({ case_id: 'C-001', verdict: 'clear' }) },
  ]) {
    assert.throws(() => assertValidBenchmarkInput({ ...benchmarkEnvelope(), repeatedRuns: [run] }), /contract validation failed/)
  }
})

test('legacy primary outcomes bind only to the primary repeat without mutating input', () => {
  const runs = [{ run_id: 'repeat:1', findings: [] }, { run_id: 'repeat:2', findings: [] }]
  const outcomes = [{ case_id: 'C-001', verdict: 'clear' }]
  const bound = bindBenchmarkPrimaryOutcomes(' repeat:1 ', outcomes, runs)
  assert.deepEqual(bound.caseOutcomes, outcomes)
  assert.deepEqual(bound.repeatedRuns[0].caseOutcomes, outcomes)
  assert.equal(bound.repeatedRuns[1].caseOutcomes, undefined)
  assert.equal(runs[0].caseOutcomes, undefined)
})

test('primary outcomes accept equivalent sets and reject conflicting final verdicts', () => {
  const outcomes = [{ case_id: 'C-001', verdict: 'clear' }, { case_id: 'V-001', verdict: 'incomplete' }]
  const runs = [{ run_id: 'repeat:1', findings: [], caseOutcomes: [...outcomes].reverse() }]
  assert.deepEqual(bindBenchmarkPrimaryOutcomes('repeat:1', outcomes, runs).caseOutcomes, outcomes)
  assert.deepEqual(bindBenchmarkPrimaryOutcomes('repeat:1', undefined, runs).caseOutcomes, outcomes)
  assert.throws(
    () => bindBenchmarkPrimaryOutcomes('repeat:1', [], runs),
    /must exactly match repeated run/,
  )
  assert.throws(
    () => bindBenchmarkPrimaryOutcomes('repeat:missing', [], runs),
    /must identify exactly one repeated run/,
  )
  assert.throws(
    () => bindBenchmarkPrimaryOutcomes('repeat:1', [outcomes[0], outcomes[0]], runs),
    /duplicate/,
  )
})
