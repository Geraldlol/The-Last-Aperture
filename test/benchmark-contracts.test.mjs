import test from 'node:test'
import assert from 'node:assert/strict'
import {
  assertValidBenchmarkInput,
  benchmarkInputSchema,
  bindBenchmarkPrimaryRun,
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
