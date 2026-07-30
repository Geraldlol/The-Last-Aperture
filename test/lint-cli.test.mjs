import { test } from 'node:test'
import assert from 'node:assert/strict'
import { runLint } from '../scripts/lint-lenses.mjs'

test('a clean corpus produces no violations', () => {
  const { violations, counts } = runLint({
    lensDir: 'test/samples/corpus-ok',
    topicsFile: 'test/samples/corpus-ok/_topics.md',
    ledgerFile: 'test/samples/ledger-ok.tsv',
  })
  assert.deepEqual(violations, [])
  assert.equal(counts.lenses, 2)
  assert.equal(counts.slugs, 2)
})

test('a clean corpus reports detector coverage as observations, never as violations', () => {
  const { violations, observations, counts } = runLint({
    lensDir: 'test/samples/corpus-ok',
    topicsFile: 'test/samples/corpus-ok/_topics.md',
    ledgerFile: 'test/samples/ledger-ok.tsv',
  })
  assert.deepEqual(violations, [])
  assert.equal(observations.length, counts.lenses)
  for (const o of observations) {
    assert.equal(typeof o.lens, 'string')
    assert.equal(typeof o.literals, 'number')
    assert.equal(typeof o.detectors, 'number')
  }
})

test('a colliding corpus reports the cross-lens R1 collision on jwt-jws-and-jwks-verification', () => {
  const { violations } = runLint({
    lensDir: 'test/samples/corpus-bad',
    topicsFile: 'test/samples/corpus-bad/_topics.md',
    ledgerFile: 'test/samples/ledger-ok.tsv',
  })
  assert.ok(
    violations.some(
      (v) =>
        v.rule === 'R1' &&
        v.lenses.includes('crypto-and-key-management') &&
        v.lenses.includes('web-sample')
    )
  )
})

test('a colliding corpus separately reports web-sample owning and deferring the same slug', () => {
  const { violations } = runLint({
    lensDir: 'test/samples/corpus-bad',
    topicsFile: 'test/samples/corpus-bad/_topics.md',
    ledgerFile: 'test/samples/ledger-ok.tsv',
  })
  assert.ok(
    violations.some(
      (v) => v.rule === 'R1' && v.lenses.length === 1 && v.lenses[0] === 'web-sample' && /owns and defers/i.test(v.message)
    )
  )
})

test('a colliding corpus reports R2 for a slug owned in frontmatter but missing from _topics.md', () => {
  const { violations } = runLint({
    lensDir: 'test/samples/corpus-bad',
    topicsFile: 'test/samples/corpus-bad/_topics.md',
    ledgerFile: 'test/samples/ledger-ok.tsv',
  })
  assert.ok(
    violations.some((v) => v.rule === 'R2' && v.slug === 'csrf' && /missing from _topics\.md/.test(v.message))
  )
})

test('a colliding corpus reports R2 for a slug in _topics.md owned by no lens', () => {
  const { violations } = runLint({
    lensDir: 'test/samples/corpus-bad',
    topicsFile: 'test/samples/corpus-bad/_topics.md',
    ledgerFile: 'test/samples/ledger-ok.tsv',
  })
  assert.ok(
    violations.some((v) => v.rule === 'R2' && v.slug === 'orphan-topic' && /owned by no lens/.test(v.message))
  )
})

test('a colliding corpus reports R8 for a body claim on another lens\'s slug', () => {
  // Wiring proof, taken through the real read-parse-lint path rather than a
  // synthetic lens object: crypto's Checklist heads an item with `csrf`, which
  // web-sample claims in its own Owns table and crypto does not defer.
  const { violations } = runLint({
    lensDir: 'test/samples/corpus-bad',
    topicsFile: 'test/samples/corpus-bad/_topics.md',
    ledgerFile: 'test/samples/ledger-ok.tsv',
  })
  assert.ok(
    violations.some(
      (v) => v.rule === 'R8' && v.slug === 'csrf' && v.lenses[0] === 'crypto-and-key-management' && /no defers entry/.test(v.message)
    )
  )
})

test('ledger violations surface through the same channel', () => {
  const { violations } = runLint({
    lensDir: 'test/samples/corpus-ok',
    topicsFile: 'test/samples/corpus-ok/_topics.md',
    ledgerFile: 'test/samples/ledger-bad.tsv',
  })
  assert.ok(violations.some((v) => v.rule === 'LEDGER'))
})

test('files starting with an underscore are not treated as lenses', () => {
  const { counts } = runLint({
    lensDir: 'test/samples/corpus-ok',
    topicsFile: 'test/samples/corpus-ok/_topics.md',
    ledgerFile: 'test/samples/ledger-ok.tsv',
  })
  assert.equal(counts.lenses, 2)
})

test('a missing lens directory is reported as a violation rather than thrown', () => {
  const { violations, counts } = runLint({
    lensDir: 'test/samples/corpus-does-not-exist',
    topicsFile: 'test/samples/corpus-does-not-exist/_topics.md',
    ledgerFile: 'test/samples/ledger-ok.tsv',
  })
  assert.equal(counts.lenses, 0)
  assert.equal(counts.slugs, 0)
  assert.ok(violations.some((v) => v.rule === 'FATAL'))
})

test('a malformed lens file surfaces a PARSE violation naming the offending file', () => {
  const { violations } = runLint({
    lensDir: 'test/samples/corpus-parse-error',
    topicsFile: 'test/samples/corpus-parse-error/_topics.md',
    ledgerFile: 'test/samples/ledger-ok.tsv',
  })
  assert.ok(violations.some((v) => v.rule === 'PARSE' && /malformed\.md/.test(v.message)))
})

test('a malformed lens file does not abort processing of the valid lens beside it', () => {
  const { violations, counts } = runLint({
    lensDir: 'test/samples/corpus-parse-error',
    topicsFile: 'test/samples/corpus-parse-error/_topics.md',
    ledgerFile: 'test/samples/ledger-ok.tsv',
  })
  // Both files were read and parsed — the malformed one did not crash the loop
  // or evict its valid sibling from the run.
  assert.equal(counts.lenses, 2)
  assert.equal(counts.slugs, 1)
  assert.ok(!violations.some((v) => v.lenses.includes('parse-error-sample')))
})
