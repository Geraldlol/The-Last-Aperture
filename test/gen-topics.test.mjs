import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { renderTopics, renderOverlap } from '../scripts/gen-topics.mjs'
import { parseTopicsFile } from '../scripts/lint-lenses.mjs'

const slugs = new Map([
  ['csrf', 'web-sample'],
  ['jwt-jws-and-jwks-verification', 'crypto-and-key-management'],
])

test('module is importable when process.argv[1] is undefined', async () => {
  const saved = process.argv[1]
  process.argv[1] = undefined
  try {
    // Cache-busting query forces re-evaluation of the module's top level,
    // which is where the unsafe guard used to throw.
    const fresh = await import('../scripts/gen-topics.mjs?argv-undefined')
    const out = fresh.renderTopics(new Map([['csrf', 'web']]))
    assert.match(out, /csrf/)
  } finally {
    process.argv[1] = saved
  }
})

test('renderTopics output round-trips through parseTopicsFile', () => {
  assert.deepEqual([...parseTopicsFile(renderTopics(slugs))].sort(), [...slugs].sort())
})

test('renderTopics reproduces the committed sample byte-for-byte', () => {
  assert.equal(renderTopics(slugs), readFileSync('test/samples/corpus-ok/_topics.md', 'utf8'))
})

test('renderTopics is deterministic and sorted', () => {
  const reversed = new Map([...slugs].reverse())
  assert.equal(renderTopics(slugs), renderTopics(reversed))
})

test('renderOverlap emits exactly one row per slug', () => {
  const lenses = [
    { frontmatter: { name: 'web-sample', owns: ['csrf'], defers: {} } },
    { frontmatter: { name: 'crypto-and-key-management', owns: ['jwt-jws-and-jwks-verification'], defers: { csrf: 'web-sample' } } },
  ]
  const rows = renderOverlap(lenses, slugs).split('\n').filter((l) => l.startsWith('| `'))
  assert.equal(rows.length, slugs.size)
  assert.ok(rows.some((r) => r.includes('`csrf`') && r.includes('crypto-and-key-management')))
})
