import { test } from 'node:test'
import assert from 'node:assert/strict'
import { loadLenses, pathActivatorMatches } from '../scripts/lib/activation.mjs'

test('a single-alternative brace matches exactly what the bare pattern matches', () => {
  // A lens declaring `src/**/*.{ts}` used to match nothing at all, so it reported
  // as NOT_TRIGGERED — a silently disabled lens presented as inapplicable.
  assert.equal(pathActivatorMatches('src/**/*.{ts}', 'src/a/b.ts'), true)
  assert.equal(pathActivatorMatches('src/**/*.ts', 'src/a/b.ts'), true)
  assert.equal(pathActivatorMatches('src/**/*.{ts,js}', 'src/a/b.ts'), true)
  assert.equal(pathActivatorMatches('src/**/*.{ts}', 'src/a/b.js'), false)
  assert.equal(pathActivatorMatches('{Dockerfile}', 'Dockerfile'), true)
})

test('multiple and nested brace groups keep expanding', () => {
  assert.equal(pathActivatorMatches('a/{b}/{c}/e.txt', 'a/b/c/e.txt'), true)
  assert.equal(pathActivatorMatches('a/{b,{c,d}}/e.txt', 'a/b/e.txt'), true)
  assert.equal(pathActivatorMatches('a/{b,{c,d}}/e.txt', 'a/d/e.txt'), true)
  assert.equal(pathActivatorMatches('a/{b,{c,d}}/e.txt', 'a/e/e.txt'), false)
  assert.equal(pathActivatorMatches('**/*.{y,ya}ml', 'ci/pipeline.yaml'), true)
  assert.equal(pathActivatorMatches('**/*.{y,ya}ml', 'ci/pipeline.yml'), true)
})

test('an unmatched brace stays a literal instead of leaking regex syntax', () => {
  assert.equal(pathActivatorMatches('src/{ts', 'src/{ts'), true)
  assert.equal(pathActivatorMatches('src/}ts', 'src/}ts'), true)
  assert.equal(pathActivatorMatches('src/{ts', 'src/ts'), false)
})

test('no shipped lens declares a brace pattern this expansion cannot resolve', async () => {
  const lenses = await loadLenses('skills/last-aperture/lenses')
  const declared = lenses.flatMap((lens) => lens.frontmatter.activates_on?.paths ?? [])
  assert.ok(declared.length > 0, 'expected the lens corpus to declare path activators')
  for (const pattern of declared) {
    assert.equal(
      (pattern.match(/\{/g) ?? []).length,
      (pattern.match(/\}/g) ?? []).length,
      `${pattern}: unbalanced brace; expansion cannot resolve it and it would match literally`,
    )
  }
})
