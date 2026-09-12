import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import Ajv2020 from 'ajv/dist/2020.js'
import { verifyRepositorySnapshot } from '../scripts/audit.mjs'
import { indexEntriesByPath, verifyFindingExistence } from '../scripts/lib/existence-matcher.mjs'
import { runSchema } from '../scripts/lib/contracts.mjs'

test('verifyRepositorySnapshot is exported for inventory reuse', () => {
  assert.equal(typeof verifyRepositorySnapshot, 'function')
})

const ENTRIES = [{
  path: 'src/routes/invoices.ts',
  kind: 'text',
  content: 'import x\nconst invoice = await repo.findById(req.params.id)\n',
  sha256: null,
}]

function withQuote(line, text) {
  return {
    candidate_id: 'c:1',
    quotes: [{ path: 'src/routes/invoices.ts', line, text }],
  }
}

test('a correct quote yields VERIFIED', () => {
  const v = verifyFindingExistence(
    withQuote(2, 'const invoice = await repo.findById(req.params.id)'), ENTRIES)
  assert.equal(v.outcome, 'VERIFIED')
  assert.equal(v.quote_results[0].outcome, 'LOCATED')
})

test('a correct quote at a wrong line yields DRIFTED', () => {
  const v = verifyFindingExistence(
    withQuote(88, 'const invoice = await repo.findById(req.params.id)'), ENTRIES)
  assert.equal(v.outcome, 'DRIFTED')
  assert.equal(v.quote_results[0].found_line, 2)
})

test('a fabricated quote yields UNVERIFIED', () => {
  const v = verifyFindingExistence(
    withQuote(2, 'const invoice = await repo.findByTenant(req.params.id)'), ENTRIES)
  assert.equal(v.outcome, 'UNVERIFIED')
})

test('a quote naming a path outside inventory yields UNVERIFIED', () => {
  const v = verifyFindingExistence({
    candidate_id: 'c:2',
    quotes: [{ path: 'src/does-not-exist.ts', line: 1, text: 'x' }],
  }, ENTRIES)
  assert.equal(v.outcome, 'UNVERIFIED')
  assert.equal(v.quote_results[0].outcome, 'NOT_LOCATED')
})

test('a finding with no claims yields NOT_APPLICABLE', () => {
  const v = verifyFindingExistence({ candidate_id: 'c:3' }, ENTRIES)
  assert.equal(v.outcome, 'NOT_APPLICABLE')
})

test('an uncheckable absence makes the finding UNVERIFIED', () => {
  const v = verifyFindingExistence({
    candidate_id: 'c:4',
    absence_claims: [{ pattern: 'x', kind: 'literal', scope: ['no/such/dir'] }],
  }, ENTRIES)
  assert.equal(v.absence_results[0].outcome, 'ABSENCE_UNCHECKABLE')
  assert.equal(v.outcome, 'UNVERIFIED')
})

test('a verdict never carries absolutePath even when inventory entries have one', () => {
  const entries = [{
    ...ENTRIES[0],
    absolutePath: 'C:\\Users\\example-operator\\secret-checkout\\src\\routes\\invoices.ts',
  }]
  const v = verifyFindingExistence(
    withQuote(2, 'const invoice = await repo.findById(req.params.id)'), entries)
  assert.equal('absolutePath' in v, false)
  assert.ok(v.quote_results.every((result) => !('absolutePath' in result)))
  assert.equal(JSON.stringify(v).includes('secret-checkout'), false)
})

test('a matching digest keeps the anchor and reports the excerpt sha256', () => {
  const content = ENTRIES[0].content
  const sha256 = createHash('sha256').update(Buffer.from(content, 'utf8')).digest('hex')
  const entries = [{ ...ENTRIES[0], sha256 }]
  const v = verifyFindingExistence(
    withQuote(2, 'const invoice = await repo.findById(req.params.id)'), entries)
  assert.equal(v.quote_results[0].anchor_state, 'ANCHORED')
  assert.equal(typeof v.quote_results[0].start_byte, 'number')
  assert.equal(typeof v.quote_results[0].end_byte, 'number')
  assert.match(v.quote_results[0].excerpt_sha256, /^[a-f0-9]{64}$/)
})

test('a byte-mismatched digest withholds the anchor but keeps the match outcome', () => {
  // The recorded sha256 does not match sha256(Buffer.from(content, 'utf8')), simulating
  // a file whose original bytes were not valid UTF-8 (the decoder already replaced the
  // invalid bytes with U+FFFD, so re-encoding cannot round-trip to the original digest).
  const entries = [{ ...ENTRIES[0], sha256: 'f'.repeat(64) }]
  const v = verifyFindingExistence(
    withQuote(2, 'const invoice = await repo.findById(req.params.id)'), entries)
  assert.equal(v.outcome, 'VERIFIED')
  assert.equal(v.quote_results[0].outcome, 'LOCATED')
  assert.equal(v.quote_results[0].anchor_state, 'ANCHOR_UNAVAILABLE')
  assert.equal(v.quote_results[0].start_byte, null)
  assert.equal(v.quote_results[0].end_byte, null)
  assert.equal(v.quote_results[0].excerpt_sha256, null)
})

test('indexEntriesByPath builds a lookup usable as the optional third argument', () => {
  const byPath = indexEntriesByPath(ENTRIES)
  assert.equal(byPath.get('src/routes/invoices.ts'), ENTRIES[0])
  const v = verifyFindingExistence(
    withQuote(2, 'const invoice = await repo.findById(req.params.id)'), ENTRIES, byPath)
  assert.equal(v.outcome, 'VERIFIED')
})

const validateExistenceVerification = new Ajv2020({ strict: true }).compile({
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  ...runSchema.$defs.existenceVerification,
})

test('every verdict shape produced here matches the schema existenceVerification definition', () => {
  const matchedSha256 = createHash('sha256')
    .update(Buffer.from(ENTRIES[0].content, 'utf8'))
    .digest('hex')
  const samples = [
    verifyFindingExistence(
      withQuote(2, 'const invoice = await repo.findById(req.params.id)'), ENTRIES),
    verifyFindingExistence(
      withQuote(88, 'const invoice = await repo.findById(req.params.id)'), ENTRIES),
    verifyFindingExistence(
      withQuote(2, 'const invoice = await repo.findByTenant(req.params.id)'), ENTRIES),
    verifyFindingExistence({
      candidate_id: 'c:5',
      quotes: [{ path: 'src/does-not-exist.ts', line: 1, text: 'x' }],
    }, ENTRIES),
    verifyFindingExistence({ candidate_id: 'c:6' }, ENTRIES),
    verifyFindingExistence({
      candidate_id: 'c:7',
      absence_claims: [{ pattern: 'x', kind: 'literal', scope: ['no/such/dir'] }],
    }, ENTRIES),
    verifyFindingExistence({
      candidate_id: 'c:8',
      absence_claims: [{ pattern: 'findById', kind: 'literal', scope: ['src'] }],
    }, ENTRIES),
    verifyFindingExistence(
      withQuote(2, 'const invoice = await repo.findById(req.params.id)'),
      [{ ...ENTRIES[0], sha256: matchedSha256 }],
    ),
    verifyFindingExistence(
      withQuote(2, 'const invoice = await repo.findById(req.params.id)'),
      [{ ...ENTRIES[0], sha256: 'f'.repeat(64) }],
    ),
  ]
  for (const sample of samples) {
    const valid = validateExistenceVerification(sample)
    assert.ok(valid, JSON.stringify(validateExistenceVerification.errors))
  }
})
