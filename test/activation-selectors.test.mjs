import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { signalActivatorMatches } from '../scripts/lib/activation.mjs'
import { parseLens } from '../scripts/lib/frontmatter.mjs'
import { checkShapes } from '../scripts/lib/registry.mjs'

const LENS_DIR = 'skills/last-aperture/lenses'

function lensWithSignals(signals) {
  return {
    name: 'typed-signals',
    frontmatter: {
      name: 'typed-signals',
      title: 'Typed signals',
      runs_in: 'fanout',
      activates_on: { paths: [], signals },
      owns: ['typed-signals'],
      defers: {},
      frameworks: [],
      severity_floor: 'low',
    },
    sections: {},
    detectors: [],
    errors: [],
  }
}

test('any_of signal selectors match each alternative without requiring dead compound prose', () => {
  const selector = { any_of: ['syft', 'trivy', 'grype'] }

  assert.equal(signalActivatorMatches(selector, 'run syft packages dir:/workspace'), true)
  assert.equal(signalActivatorMatches(selector, 'trivy image app:latest'), true)
  assert.equal(signalActivatorMatches(selector, 'grype registry:example/app:latest'), true)
  assert.equal(signalActivatorMatches(selector, 'run the approved scanner'), false)
})

test('plain literal signal selectors retain identifier-boundary behavior', () => {
  assert.equal(signalActivatorMatches('expo', 'export const sdk = "expo"'), true)
  assert.equal(signalActivatorMatches('expo', 'EXPORT DATABASE'), false)
})

test('R6 accepts bounded any_of selectors and rejects unsupported regex selectors', () => {
  assert.deepEqual(checkShapes([lensWithSignals([{ any_of: ['syft', 'trivy'] }])]), [])

  const violations = checkShapes([
    lensWithSignals([{ regex: '(a+)+$' }]),
  ])
  assert.ok(violations.some(({ message }) => /unknown signal selector key "regex"/.test(message)))
})

test('R6 rejects malformed or unbounded signal selectors', () => {
  const cases = [
    { selector: '', message: /non-empty trimmed string/ },
    { selector: ' untrimmed', message: /non-empty trimmed string/ },
    { selector: { any_of: ['only-one'] }, message: /between 2 and 32/ },
    { selector: { any_of: ['same', 'same'] }, message: /must not contain duplicates/ },
    { selector: { any_of: ['ok', 'x'.repeat(257)] }, message: /at most 256 characters/ },
    { selector: { any_of: ['ok', { any_of: ['nested', 'selector'] }] }, message: /atomic literal/ },
    { selector: { any_of: ['ok', 'other'], extra: true }, message: /exactly one "any_of" key/ },
    { selector: 'syft / trivy', message: /any_of instead of slash-separated prose/ },
  ]

  for (const { selector, message } of cases) {
    const violations = checkShapes([lensWithSignals([selector])])
    assert.ok(
      violations.some((violation) => message.test(violation.message)),
      `${JSON.stringify(selector)} should fail with ${message}`,
    )
  }
})

test('runtime matching fails closed for a selector that bypassed lens lint', () => {
  assert.throws(
    () => signalActivatorMatches({ regex: '.*' }, 'untrusted repository content'),
    /invalid signal selector.*unknown signal selector key "regex"/,
  )
})

test('R6 requires paths and signals to be arrays of their declared selector type', () => {
  const badSignals = lensWithSignals('syft')
  const badPaths = lensWithSignals([])
  badPaths.frontmatter.activates_on.paths = [{ any_of: ['**/*.js', '**/*.ts'] }]

  assert.ok(checkShapes([badSignals]).some(({ message }) => /signals must be an array/.test(message)))
  assert.ok(checkShapes([badPaths]).some(({ message }) => /path selector.*string/.test(message)))
})

test('every repository any_of selector has positive alternatives and a negative control', () => {
  const selectors = readdirSync(LENS_DIR)
    .filter((file) => file.endsWith('.md') && !file.startsWith('_'))
    .flatMap((file) => {
      const parsed = parseLens(readFileSync(join(LENS_DIR, file), 'utf8'), file)
      return (parsed.frontmatter.activates_on?.signals ?? [])
        .filter((selector) => typeof selector === 'object' && selector !== null)
        .map((selector) => ({ file, selector }))
    })

  assert.ok(selectors.length > 0, 'compound signal inventories must use typed selectors')
  for (const { file, selector } of selectors) {
    for (const literal of selector.any_of) {
      assert.equal(
        signalActivatorMatches(selector, literal),
        true,
        `${file}: ${JSON.stringify(selector)} must match alternative ${JSON.stringify(literal)}`,
      )
    }
    assert.equal(
      signalActivatorMatches(selector, '__red_team_unrelated_negative_control__'),
      false,
      `${file}: ${JSON.stringify(selector)} must discriminate an unrelated file`,
    )
  }
})
