import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import {
  assertFixtureSelectorsExist,
  extractBenchmarkCases,
  renderBenchmarkCases,
} from '../scripts/gen-benchmark-cases.mjs'

const manifest = readFileSync('fixtures/EXPECTED.md', 'utf8')
const ownership = readFileSync('fixtures/OWNERSHIP.tsv', 'utf8')
const committed = readFileSync('benchmarks/cases.json', 'utf8')
const cases = extractBenchmarkCases(manifest, ownership)

test('benchmark ground truth stays generated from the fixture manifest', () => {
  assert.equal(renderBenchmarkCases(cases), committed)
  assert.equal(assertFixtureSelectorsExist(cases), cases)
})

test('benchmark ground truth has the complete vulnerable and clean denominator', () => {
  assert.equal(cases.length, 64)
  assert.equal(cases.filter(({ expectation }) => expectation === 'vulnerable').length, 22)
  assert.equal(cases.filter(({ expectation }) => expectation === 'clean').length, 42)
  assert.ok(cases.filter(({ expectation }) => expectation === 'vulnerable').every(
    ({ topic, lens, expected_severity }) =>
      topic !== 'clean-canary' &&
      typeof lens === 'string' &&
      ['Critical', 'High', 'Medium', 'Low'].includes(expected_severity),
  ))
  assert.ok(cases.filter(({ expectation }) => expectation === 'clean').every(
    ({ topic, expected_severity }) => topic === 'clean-canary' && expected_severity === undefined,
  ))
  assert.ok(cases.every(
    ({ fixture_selectors: selectors }) =>
      Array.isArray(selectors) && selectors.length > 0,
  ))
})

test('benchmark generation rejects fixture selectors that do not exist', () => {
  const invalidOwnership = ownership.replace(
    'V-001\tvulnerable/order_notes_route.ts',
    'V-001\tvulnerable/does-not-exist.ts',
  )
  const invalid = extractBenchmarkCases(manifest, invalidOwnership)
  assert.throws(
    () => assertFixtureSelectorsExist(invalid),
    /V-001 fixture selector matches no path/,
  )
})
