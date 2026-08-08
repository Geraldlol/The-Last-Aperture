import { test } from 'node:test'
import assert from 'node:assert/strict'
import { matchQuote, normalizeQuote } from '../scripts/lib/existence-matcher.mjs'

const FILE = [
  'resource pg "Microsoft.DBforPostgreSQL" = {',
  '  properties: {',
  "    publicNetworkAccess: 'Enabled'",
  '  }',
  '}',
].join('\n')

test('an exact quote at the claimed line is LOCATED', () => {
  const r = matchQuote(FILE, "    publicNetworkAccess: 'Enabled'", 3)
  assert.equal(r.outcome, 'LOCATED')
  assert.equal(r.foundLine, 3)
  assert.equal(r.matchCount, 1)
})

test('a re-indented quote is still LOCATED', () => {
  const r = matchQuote(FILE, "publicNetworkAccess: 'Enabled'", 3)
  assert.equal(r.outcome, 'LOCATED')
  assert.equal(r.foundLine, 3)
})

test('a tab-indented quote matches a space-indented file', () => {
  const r = matchQuote(FILE, "\t\tpublicNetworkAccess: 'Enabled'", 3)
  assert.equal(r.outcome, 'LOCATED')
})

test('correct content at the wrong line is LOCATED_OFF_LINE', () => {
  const r = matchQuote(FILE, "publicNetworkAccess: 'Enabled'", 27)
  assert.equal(r.outcome, 'LOCATED_OFF_LINE')
  assert.equal(r.foundLine, 3)
})

test('fabricated content is NOT_LOCATED', () => {
  const r = matchQuote(FILE, "publicNetworkAccess: 'Disabled'", 3)
  assert.equal(r.outcome, 'NOT_LOCATED')
  assert.equal(r.foundLine, null)
})

test('a multi-line quote must match contiguously', () => {
  const good = matchQuote(FILE, "properties: {\npublicNetworkAccess: 'Enabled'", 2)
  assert.equal(good.outcome, 'LOCATED')
  const bad = matchQuote(FILE, "properties: {\n}", 2)
  assert.equal(bad.outcome, 'NOT_LOCATED')
})

test('CRLF in the file matches an LF quote', () => {
  const crlf = FILE.replaceAll('\n', '\r\n')
  assert.equal(matchQuote(crlf, "publicNetworkAccess: 'Enabled'", 3).outcome, 'LOCATED')
})

test('CR-only line endings are handled', () => {
  const cr = FILE.replaceAll('\n', '\r')
  assert.equal(matchQuote(cr, "publicNetworkAccess: 'Enabled'", 3).outcome, 'LOCATED')
})

test('byte offsets bracket the matched text', () => {
  const r = matchQuote(FILE, "publicNetworkAccess: 'Enabled'", 3)
  const bytes = Buffer.from(FILE, 'utf8').subarray(r.startByte, r.endByte)
  assert.equal(bytes.toString('utf8'), "publicNetworkAccess: 'Enabled'")
})

test('byte offsets are correct after a non-ASCII line', () => {
  const content = ['// café — note', 'const x = 1'].join('\n')
  const r = matchQuote(content, 'const x = 1', 2)
  const bytes = Buffer.from(content, 'utf8').subarray(r.startByte, r.endByte)
  assert.equal(bytes.toString('utf8'), 'const x = 1')
})

test('CRLF byte offsets are correct', () => {
  const crlf = FILE.replaceAll('\n', '\r\n')
  const r = matchQuote(crlf, "publicNetworkAccess: 'Enabled'", 3)
  const bytes = Buffer.from(crlf, 'utf8').subarray(r.startByte, r.endByte)
  assert.equal(bytes.toString('utf8'), "publicNetworkAccess: 'Enabled'")
})

test('a multi-line byte span covers both lines including the terminator', () => {
  const r = matchQuote(FILE, "properties: {\npublicNetworkAccess: 'Enabled'", 2)
  const bytes = Buffer.from(FILE, 'utf8').subarray(r.startByte, r.endByte)
  assert.equal(bytes.toString('utf8'), "properties: {\n    publicNetworkAccess: 'Enabled'")
})

test('the nearest occurrence to the claimed line wins and matchCount reports all', () => {
  const repeated = ['a', 'dup', 'b', 'dup', 'c'].join('\n')
  const r = matchQuote(repeated, 'dup', 4)
  assert.equal(r.foundLine, 4)
  assert.equal(r.matchCount, 2)
})

test('a quote that normalizes to nothing never matches', () => {
  assert.deepEqual(normalizeQuote('   \n\t\n  '), [])
  assert.equal(matchQuote(FILE, '   \n  ', 1).outcome, 'NOT_LOCATED')
})

test('NOT_LOCATED returns the full documented tuple', () => {
  const r = matchQuote(FILE, "publicNetworkAccess: 'Disabled'", 3)
  assert.deepEqual(r, {
    outcome: 'NOT_LOCATED',
    foundLine: null,
    matchCount: 0,
    startByte: null,
    endByte: null,
  })
})

test('LOCATED_OFF_LINE returns the full documented tuple', () => {
  const r = matchQuote(FILE, "publicNetworkAccess: 'Enabled'", 27)
  assert.equal(r.outcome, 'LOCATED_OFF_LINE')
  assert.equal(r.foundLine, 3)
  assert.equal(r.matchCount, 1)
  assert.equal(typeof r.startByte, 'number')
  assert.equal(typeof r.endByte, 'number')
  assert.ok(r.endByte > r.startByte)
})

import { searchAbsence } from '../scripts/lib/existence-matcher.mjs'

const ENTRIES = [
  { path: 'src/a.cls', kind: 'text', content: 'void f() {}\nBoolean ok = constantTimeEquals(x, y);' },
  { path: 'src/b.cls', kind: 'text', content: 'void g() {}' },
  { path: 'docs/n.md', kind: 'text', content: 'mentions ConstantTimeEquals here' },
  { path: 'bin/blob.png', kind: 'binary', content: null },
]

test('an absence that holds reports ABSENCE_HOLDS', () => {
  const r = searchAbsence(ENTRIES, {
    pattern: 'notPresentAnywhere', kind: 'literal', scope: ['src'],
  })
  assert.equal(r.outcome, 'ABSENCE_HOLDS')
  assert.equal(r.matchCount, 0)
  assert.equal(r.searchedFiles, 2)
})

test('a contradicted absence names where', () => {
  const r = searchAbsence(ENTRIES, {
    pattern: 'constantTimeEquals', kind: 'literal', scope: ['src'],
  })
  assert.equal(r.outcome, 'ABSENCE_CONTRADICTED')
  assert.equal(r.matchCount, 1)
  assert.deepEqual(r.hits, [{ path: 'src/a.cls', line: 2 }])
})

test('scope restricts the search', () => {
  const r = searchAbsence(ENTRIES, {
    pattern: 'constantTimeEquals', kind: 'literal', scope: ['src/b.cls'],
  })
  assert.equal(r.outcome, 'ABSENCE_HOLDS')
  assert.equal(r.searchedFiles, 1)
})

test('literal_ci matches a differently cased occurrence', () => {
  const sensitive = searchAbsence(ENTRIES, {
    pattern: 'constanttimeequals', kind: 'literal', scope: ['docs'],
  })
  assert.equal(sensitive.outcome, 'ABSENCE_HOLDS')
  const insensitive = searchAbsence(ENTRIES, {
    pattern: 'constanttimeequals', kind: 'literal_ci', scope: ['docs'],
  })
  assert.equal(insensitive.outcome, 'ABSENCE_CONTRADICTED')
})

test('a scope matching no inventory entry is UNCHECKABLE, never HOLDS', () => {
  const r = searchAbsence(ENTRIES, {
    pattern: 'anything', kind: 'literal', scope: ['src/typo-does-not-exist'],
  })
  assert.equal(r.outcome, 'ABSENCE_UNCHECKABLE')
  assert.equal(r.searchedFiles, 0)
})

test('a scope of only binary entries is UNCHECKABLE', () => {
  const r = searchAbsence(ENTRIES, {
    pattern: 'anything', kind: 'literal', scope: ['bin'],
  })
  assert.equal(r.outcome, 'ABSENCE_UNCHECKABLE')
  assert.equal(r.searchedFiles, 0)
})

test('a scope prefix does not leak into a sibling directory', () => {
  const entries = [{ path: 'srcx/a.ts', kind: 'text', content: 'boom' }]
  const r = searchAbsence(entries, {
    pattern: 'boom', kind: 'literal', scope: ['src'],
  })
  assert.equal(r.outcome, 'ABSENCE_UNCHECKABLE')
})

test('literal_ci folds the needle as well as the haystack', () => {
  const r = searchAbsence(ENTRIES, {
    pattern: 'CONSTANTTIMEEQUALS', kind: 'literal_ci', scope: ['docs'],
  })
  assert.equal(r.outcome, 'ABSENCE_CONTRADICTED')
  assert.equal(r.matchCount, 1)
})

test('literal does not fold either side', () => {
  const r = searchAbsence(ENTRIES, {
    pattern: 'CONSTANTTIMEEQUALS', kind: 'literal', scope: ['docs'],
  })
  assert.equal(r.outcome, 'ABSENCE_HOLDS')
  assert.equal(r.matchCount, 0)
})

test('matchCount counts matching lines, not occurrences within a line', () => {
  const entries = [{ path: 'src/x.ts', kind: 'text', content: 'dup and dup again\nclean line' }]
  const r = searchAbsence(entries, { pattern: 'dup', kind: 'literal', scope: ['src'] })
  assert.equal(r.matchCount, 1)
  assert.deepEqual(r.hits, [{ path: 'src/x.ts', line: 1 }])
})

test('hits truncate at 16 while matchCount keeps the full total', () => {
  const content = Array.from({ length: 20 }, (_, i) => `line ${i} has needle here`).join('\n')
  const entries = [{ path: 'src/many.ts', kind: 'text', content }]
  const r = searchAbsence(entries, { pattern: 'needle', kind: 'literal', scope: ['src'] })
  assert.equal(r.matchCount, 20)
  assert.equal(r.hits.length, 16)
  assert.deepEqual(r.hits[0], { path: 'src/many.ts', line: 1 })
  assert.deepEqual(r.hits[15], { path: 'src/many.ts', line: 16 })
})
