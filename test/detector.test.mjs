import { test } from 'node:test'
import assert from 'node:assert/strict'
import { checkDetectors, detectorCoverage } from '../scripts/lib/registry.mjs'

const withDetectors = (name, detectors, sections = { Checklist: 'x' }) => ({
  name, frontmatter: { name, runs_in: 'fanout' }, sections, detectors, errors: [],
})

test('a detector with both directions passes', () => {
  const v = checkDetectors([withDetectors('web', [{ match: 'app.post(x)', nomatch: 'app.post(x, csrf)', line: 10 }])])
  assert.deepEqual(v, [])
})

test('R7 flags a detector missing nomatch', () => {
  const v = checkDetectors([withDetectors('web', [{ match: 'app.post(x)', nomatch: null, line: 10 }])])
  assert.equal(v.length, 1)
  assert.match(v[0].message, /nomatch/)
})

test('R7 flags a detector missing match', () => {
  const v = checkDetectors([withDetectors('web', [{ match: null, nomatch: 'safe', line: 10 }])])
  assert.ok(v.some((x) => /match/.test(x.message)))
})

test('R7 flags identical match and nomatch as non-discriminating', () => {
  const v = checkDetectors([withDetectors('web', [{ match: 'same', nomatch: 'same', line: 10 }])])
  assert.ok(v.some((x) => /identical/i.test(x.message)))
})

test('R7 flags a domain lens with a Checklist and no detectors at all', () => {
  const v = checkDetectors([withDetectors('web', [], { Checklist: 'look for things' })])
  assert.ok(v.some((x) => /no detector/i.test(x.message)))
})

test('R7 exempts a lens with no Checklist section', () => {
  const v = checkDetectors([withDetectors('completeness', [], { Scope: 'reads findings' })])
  assert.deepEqual(v, [])
})

test('detectorCoverage counts distinct backticked literals and detectors', () => {
  const cov = detectorCoverage([withDetectors('web', [{ match: 'x', nomatch: 'y', line: 1 }], { Checklist: 'look for `foo` and `bar` and `baz`' })])
  assert.equal(cov.length, 1)
  assert.deepEqual(cov[0], { lens: 'web', literals: 3, detectors: 1 })
})

test('detectorCoverage omits lenses with no Checklist section', () => {
  const cov = detectorCoverage([withDetectors('completeness', [{ match: 'x', nomatch: 'y', line: 1 }], { Scope: 'reads findings' })])
  assert.deepEqual(cov, [])
})

test('detectorCoverage counts repeated literals only once', () => {
  const cov = detectorCoverage([withDetectors('web', [{ match: 'x', nomatch: 'y', line: 1 }], { Checklist: 'look for `foo` and also `foo`' })])
  assert.equal(cov.length, 1)
  assert.equal(cov[0].literals, 1)
})

test('detectorCoverage includes lenses with zero literals', () => {
  const cov = detectorCoverage([withDetectors('web', [{ match: 'x', nomatch: 'y', line: 1 }], { Checklist: 'look for things without backticks' })])
  assert.equal(cov.length, 1)
  assert.deepEqual(cov[0], { lens: 'web', literals: 0, detectors: 1 })
})

test('detectorCoverage does not count backtick spans inside a fenced example', () => {
  const checklist = [
    'Look for `realTarget` in the handler.',
    '',
    '```',
    'Sample report contains `fake1` and `fake2` and `fake3`',
    '```',
  ].join('\n')
  const cov = detectorCoverage([withDetectors('web', [{ match: 'x', nomatch: 'y', line: 1 }], { Checklist: checklist })])
  assert.equal(cov.length, 1)
  assert.equal(cov[0].literals, 1)
})

test('detectorCoverage still counts backtick spans that are outside any fenced block', () => {
  const checklist = [
    '```',
    'Sample report contains `fake1`',
    '```',
    '',
    'Look for `realTarget` and `anotherReal`.',
  ].join('\n')
  const cov = detectorCoverage([withDetectors('web', [{ match: 'x', nomatch: 'y', line: 1 }], { Checklist: checklist })])
  assert.equal(cov.length, 1)
  assert.equal(cov[0].literals, 2)
})
