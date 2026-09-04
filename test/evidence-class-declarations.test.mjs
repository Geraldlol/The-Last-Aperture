import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { parseLens } from '../scripts/lib/frontmatter.mjs'
import { checkEvidenceClasses, lensEvidenceDeclarations } from '../scripts/lib/registry.mjs'
import { EVIDENCE_CLASS_ORDER } from '../scripts/lib/evidence-classes.mjs'

const LENS_DIR = 'skills/red-team-audit/lenses'

function corpus() {
  return readdirSync(LENS_DIR)
    .filter((file) => file.endsWith('.md') && !file.startsWith('_'))
    .sort()
    .map((file) => parseLens(readFileSync(join(LENS_DIR, file), 'utf8'), file))
}

const declare = (name, evidenceClasses, extra = {}) => ({
  name,
  frontmatter: {
    name,
    runs_in: 'fanout',
    owns: ['x'],
    defers: {},
    activates_on: { paths: ['**/*.ts'], evidence_classes: evidenceClasses },
    ...extra,
  },
  sections: {},
  detectors: [],
  errors: [],
})

const ALL_NOT_CONSUMED = Object.fromEntries(
  EVIDENCE_CLASS_ORDER.map((evidenceClass) => [evidenceClass, { state: 'not-consumed' }]),
)

test('every canonical lens declares all four evidence classes', () => {
  const lenses = corpus()
  assert.equal(lenses.length, 19)
  assert.deepEqual(checkEvidenceClasses(lenses), [])
  for (const lens of lenses) {
    const declared = lens.frontmatter.activates_on?.evidence_classes ?? {}
    assert.deepEqual(
      Object.keys(declared).sort(),
      [...EVIDENCE_CLASS_ORDER].sort(),
      `${lens.frontmatter.name} must declare every canonical class`,
    )
  }
})

test('threat-modeling is advisory and consumes nothing', () => {
  const lens = corpus().find((l) => l.frontmatter.name === 'threat-modeling')
  const declared = lens.frontmatter.activates_on.evidence_classes
  for (const evidenceClass of EVIDENCE_CLASS_ORDER) {
    assert.equal(declared[evidenceClass].state, 'not-consumed')
  }
})

test('cloud-and-iac can conclude about images and deployed state, not runtime', () => {
  const declared = corpus()
    .find((l) => l.frontmatter.name === 'cloud-and-iac')
    .frontmatter.activates_on.evidence_classes
  assert.deepEqual(declared['built-artifact'].artifact_kinds, ['oci-image'])
  assert.deepEqual(declared['built-artifact'].may_conclude, [
    'secret-present-in-artifact',
    'unexpected-artifact-content',
  ])
  assert.equal(declared['live-runtime'].state, 'not-consumed')
})

test('mobile-app-security claims apk and ipa, never oci-image', () => {
  const declared = corpus()
    .find((l) => l.frontmatter.name === 'mobile-app-security')
    .frontmatter.activates_on.evidence_classes
  assert.deepEqual(declared['built-artifact'].artifact_kinds, ['apk', 'ipa'])
})

test('R9 rejects an omitted class', () => {
  const { 'live-runtime': _omitted, ...partial } = ALL_NOT_CONSUMED
  const violations = checkEvidenceClasses([declare('web', partial)])
  assert.equal(violations.length, 1)
  assert.equal(violations[0].rule, 'R9')
  assert.match(violations[0].message, /live-runtime/)
})

test('R9 rejects a missing declaration block outright', () => {
  const lens = declare('web', undefined)
  delete lens.frontmatter.activates_on.evidence_classes
  assert.ok(checkEvidenceClasses([lens]).some((v) => /evidence_classes/.test(v.message)))
})

test('R9 rejects an unknown class, state, kind or claim', () => {
  assert.ok(checkEvidenceClasses([
    declare('web', { ...ALL_NOT_CONSUMED, exploitation: { state: 'consumed' } }),
  ]).some((v) => /exploitation/.test(v.message)))

  assert.ok(checkEvidenceClasses([
    declare('web', { ...ALL_NOT_CONSUMED, source: { state: 'maybe' } }),
  ]).some((v) => /state/.test(v.message)))

  assert.ok(checkEvidenceClasses([declare('web', {
    ...ALL_NOT_CONSUMED,
    'built-artifact': {
      state: 'consumed',
      artifact_kinds: ['docker-image'],
      may_conclude: ['secret-present-in-artifact'],
    },
  })]).some((v) => /docker-image/.test(v.message)))

  assert.ok(checkEvidenceClasses([declare('web', {
    ...ALL_NOT_CONSUMED,
    'deployed-state': { state: 'consumed', may_conclude: ['looks-bad'] },
  })]).some((v) => /looks-bad/.test(v.message)))
})

test('R9 requires artifact_kinds exactly when built-artifact is consumed', () => {
  assert.ok(checkEvidenceClasses([declare('web', {
    ...ALL_NOT_CONSUMED,
    'built-artifact': { state: 'consumed', may_conclude: ['secret-present-in-artifact'] },
  })]).some((v) => /artifact_kinds/.test(v.message)))

  assert.ok(checkEvidenceClasses([declare('web', {
    ...ALL_NOT_CONSUMED,
    'built-artifact': { state: 'not-consumed', artifact_kinds: ['oci-image'] },
  })]).some((v) => /artifact_kinds/.test(v.message)))
})

test('R9 requires may_conclude for a consumed non-source class and exempts source', () => {
  assert.deepEqual(
    checkEvidenceClasses([declare('web', { ...ALL_NOT_CONSUMED, source: { state: 'consumed' } })]),
    [],
  )
  assert.ok(checkEvidenceClasses([declare('web', {
    ...ALL_NOT_CONSUMED,
    'live-runtime': { state: 'consumed' },
  })]).some((v) => /may_conclude/.test(v.message)))
})

test('lensEvidenceDeclarations exposes the corpus as a lookup', () => {
  const declarations = lensEvidenceDeclarations(corpus())
  assert.equal(declarations.size, 19)
  assert.equal(declarations.get('cloud-and-iac')['built-artifact'].state, 'consumed')
  assert.equal(declarations.get('threat-modeling')['built-artifact'].state, 'not-consumed')
  assert.equal(declarations.get('no-such-lens'), undefined)
})
