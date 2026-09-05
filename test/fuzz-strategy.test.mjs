import { test } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import {
  FuzzStrategyError,
  generateStructuredFuzzCases,
  replayStructuredFuzz,
  runStructuredFuzz,
} from '../scripts/lib/fuzz-strategy.mjs'

test('structured fuzzing shrinks and records a deterministic counterexample', async () => {
  const result = await runStructuredFuzz({
    executionDomain: 'repository',
    arbitrary: fc.integer({ min: -1_000, max: 1_000 }),
    property: (value) => value < 10,
    seed: 424_242,
    numRuns: 200,
    timeoutMs: 5_000,
    maxCounterexampleBytes: 4_096,
  })

  assert.equal(result.status, 'COUNTEREXAMPLE_OBSERVED')
  assert.equal(result.provider.name, 'fast-check')
  assert.equal(result.provider.version, '4.9.0')
  assert.equal(result.reproducer.seed, 424_242)
  assert.equal(typeof result.reproducer.counterexample_path, 'string')
  assert.equal(result.reproducer.concrete_arguments.length, 1)
  assert.equal(result.reproducer.concrete_arguments[0] >= 10, true)
  assert.equal(result.non_clearance, true)

  const replay = await replayStructuredFuzz({
    priorResult: result,
    executionDomain: 'repository',
    arbitrary: fc.integer({ min: -1_000, max: 1_000 }),
    property: (value) => value < 10,
    timeoutMs: 5_000,
    maxCounterexampleBytes: 4_096,
  })
  assert.equal(replay.status, 'COUNTEREXAMPLE_OBSERVED')
  assert.deepEqual(
    replay.reproducer.concrete_arguments,
    result.reproducer.concrete_arguments,
  )
})

test('a completed sample is explicitly not a security clearance', async () => {
  const result = await runStructuredFuzz({
    executionDomain: 'local_service',
    arbitrary: fc.jsonValue(),
    property: () => true,
    seed: 7,
    numRuns: 25,
    timeoutMs: 5_000,
    maxCounterexampleBytes: 4_096,
  })
  assert.equal(result.status, 'NO_COUNTEREXAMPLE_OBSERVED')
  assert.equal(result.non_clearance, true)
  assert.match(result.statement, /does not establish absence/i)
})

test('async properties are supported and interrupted campaigns are inconclusive', async () => {
  const asyncFailure = await runStructuredFuzz({
    executionDomain: 'repository',
    arbitrary: fc.integer({ min: 0, max: 100 }),
    property: async (value) => value < 3,
    asyncProperty: true,
    seed: 99,
    numRuns: 100,
    timeoutMs: 5_000,
    maxCounterexampleBytes: 4_096,
  })
  assert.equal(asyncFailure.status, 'COUNTEREXAMPLE_OBSERVED')

  const interrupted = await runStructuredFuzz({
    executionDomain: 'repository',
    arbitrary: fc.constant(null),
    property: async () => {
      await new Promise((resolve) => setTimeout(resolve, 5))
      return true
    },
    asyncProperty: true,
    seed: 1,
    numRuns: 1_000,
    timeoutMs: 1,
    maxCounterexampleBytes: 4_096,
  })
  assert.equal(interrupted.status, 'INCONCLUSIVE')
  assert.equal(interrupted.interrupted, true)
  assert.equal(interrupted.non_clearance, true)
})

test('harness exceptions and non-boolean returns are inconclusive, not findings', async () => {
  for (const property of [
    () => { throw new Error('fixture setup failed') },
    () => 'truthy-but-invalid',
  ]) {
    const result = await runStructuredFuzz({
      executionDomain: 'repository',
      arbitrary: fc.constant({ fixture: true }),
      property,
      seed: 5,
      numRuns: 1,
      timeoutMs: 5_000,
      maxCounterexampleBytes: 4_096,
    })
    assert.equal(result.status, 'INCONCLUSIVE')
    assert.match(result.statement, /harness/i)
    assert.equal('stack' in (result.harness_error ?? {}), false)
  }
})

test('an async property that never settles is bounded by the campaign deadline', async () => {
  const started = Date.now()
  const result = await runStructuredFuzz({
    executionDomain: 'repository',
    arbitrary: fc.constant(null),
    property: async () => new Promise(() => {}),
    asyncProperty: true,
    seed: 11,
    numRuns: 1,
    timeoutMs: 20,
    maxCounterexampleBytes: 4_096,
  })
  assert.equal(result.status, 'INCONCLUSIVE')
  assert.equal(result.interrupted, true)
  assert.ok(Date.now() - started < 1_000)
})

test('oversized minimized inputs are inconclusive without leaking the payload', async () => {
  const secretMarker = 'SENSITIVE_MARKER_'.repeat(100)
  const result = await runStructuredFuzz({
    executionDomain: 'repository',
    arbitrary: fc.constant({ payload: secretMarker }),
    property: () => false,
    seed: 3,
    numRuns: 1,
    timeoutMs: 5_000,
    maxCounterexampleBytes: 64,
  })
  assert.equal(result.status, 'INCONCLUSIVE')
  assert.equal(result.reproducer.counterexample_omitted, true)
  assert.equal('concrete_arguments' in result.reproducer, false)
  assert.doesNotMatch(JSON.stringify(result), /SENSITIVE_MARKER/)
})

test('limits and execution domains fail closed', async () => {
  const base = {
    executionDomain: 'repository',
    arbitrary: fc.integer(),
    property: () => true,
    seed: 1,
    numRuns: 10,
    timeoutMs: 100,
    maxCounterexampleBytes: 1_024,
  }
  for (const invalid of [
    { numRuns: Infinity },
    { timeoutMs: 0 },
    { maxCounterexampleBytes: 32 },
    { executionDomain: 'live' },
  ]) {
    await assert.rejects(
      () => runStructuredFuzz({ ...base, ...invalid }),
      (error) => error instanceof FuzzStrategyError,
    )
  }
})

test('pure deterministic case generation feeds live cases into the governed runtime', () => {
  const first = generateStructuredFuzzCases({
    arbitrary: fc.record({ id: fc.integer({ min: 0, max: 100 }) }),
    seed: 123,
    numCases: 5,
    maxCaseBytes: 1_024,
  })
  const second = generateStructuredFuzzCases({
    arbitrary: fc.record({ id: fc.integer({ min: 0, max: 100 }) }),
    seed: 123,
    numCases: 5,
    maxCaseBytes: 1_024,
  })
  assert.deepEqual(first, second)
  assert.equal(first.length, 5)
  assert.equal(first.every((entry) => /^[a-f0-9]{64}$/.test(entry.value_sha256)), true)
  assert.equal(first.every((entry) => entry.route === 'ADVERSARIAL_RUNTIME_REQUIRED'), true)
})
