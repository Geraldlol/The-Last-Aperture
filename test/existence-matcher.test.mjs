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
