import { test } from 'node:test'
import assert from 'node:assert/strict'
import { checkOrthography } from '../scripts/lib/orthography.mjs'
import { checkShapes } from '../scripts/lib/registry.mjs'

test('R5 flags British -isation spellings', () => {
  const v = checkOrthography(['rag-retrieval-authorization', 'payment-page-script-authorisation'])
  assert.equal(v.length, 1)
  assert.equal(v[0].slug, 'payment-page-script-authorisation')
  assert.match(v[0].message, /authorization/)
})

test('R5 flags -isation and -yse forms', () => {
  assert.equal(checkOrthography(['collection-side-minimisation']).length, 1)
  assert.equal(checkOrthography(['traffic-analyse-gap']).length, 1)
})

test('R5 accepts a clean American slug set', () => {
  assert.deepEqual(checkOrthography(['deserialization-and-xxe', 'csrf', 'tenant-isolation-enforcement']), [])
})

const l = (name, fm) => ({
  name,
  frontmatter: { name, title: name, frameworks: [], severity_floor: 'low', ...fm },
  sections: {},
  detectors: [],
  errors: [],
})

test('R6 accepts the three valid shapes', () => {
  const v = checkShapes([
    l('web', { runs_in: 'fanout', activates_on: { paths: ['a'], signals: [] }, owns: ['csrf'], defers: {} }),
    l('ai-generated-code', { runs_in: 'fanout', always_active: true, activates_on: { paths: [], signals: [] }, owns: [], defers: {} }),
    l('completeness', { runs_in: 'triage', activates_on: { paths: [], signals: [] }, owns: [], defers: {} }),
  ])
  assert.deepEqual(v, [])
})

test('R6 flags a triage lens that owns slugs', () => {
  const v = checkShapes([l('completeness', { runs_in: 'triage', activates_on: { paths: [], signals: [] }, owns: ['csrf'], defers: {} })])
  assert.ok(v.some((x) => /triage.*owns/i.test(x.message)))
})

test('R6 flags a triage lens with a non-empty activates_on', () => {
  const v = checkShapes([l('completeness', { runs_in: 'triage', activates_on: { paths: ['**/*'], signals: [] }, owns: [], defers: {} })])
  assert.ok(v.some((x) => /activates_on/i.test(x.message)))
})

test('R6 flags always_active combined with runs_in triage', () => {
  const v = checkShapes([l('x', { runs_in: 'triage', always_active: true, activates_on: { paths: [], signals: [] }, owns: [], defers: {} })])
  assert.ok(v.some((x) => /always_active/i.test(x.message)))
})

test('R6 flags an always-on lens that owns slugs', () => {
  const v = checkShapes([l('x', { runs_in: 'fanout', always_active: true, activates_on: { paths: [], signals: [] }, owns: ['csrf'], defers: {} })])
  assert.ok(v.some((x) => /always_active.*owns/i.test(x.message)))
})

test('R6 flags a domain lens with an empty activates_on', () => {
  const v = checkShapes([l('web', { runs_in: 'fanout', activates_on: { paths: [], signals: [] }, owns: ['csrf'], defers: {} })])
  assert.ok(v.some((x) => /must match something/i.test(x.message)))
})

test('R6 flags missing required keys', () => {
  const v = checkShapes([l('web', { runs_in: 'fanout' })])
  assert.ok(v.some((x) => /missing/i.test(x.message)))
})

test('R6 flags an unknown runs_in value', () => {
  const v = checkShapes([l('web', { runs_in: 'sometimes', activates_on: { paths: [], signals: [] }, owns: [], defers: {} })])
  assert.ok(v.some((x) => /runs_in/i.test(x.message)))
})

test('R6 flags each of the eight required keys individually', () => {
  const valid = {
    runs_in: 'fanout',
    activates_on: { paths: ['a'], signals: [] },
    owns: ['csrf'],
    defers: {},
  }
  for (const key of ['name', 'title', 'frameworks', 'severity_floor', 'runs_in', 'activates_on', 'owns', 'defers']) {
    const v = checkShapes([l('web', { ...valid, [key]: undefined })])
    assert.ok(
      v.some((x) => x.message.includes(`"${key}"`)),
      `omitting ${key} should be flagged, but it was not`
    )
  }
})
