import { test } from 'node:test'
import assert from 'node:assert/strict'
import { scanResidue, parseTerms } from '../scripts/scan-residue.mjs'

// PLACEHOLDER TERMS ONLY. The real employer / tenant / product / person names
// are supplied at the shell via RESIDUE_TERMS and must never be written into a
// tracked file — putting the strings being scanned for inside the thing being
// scanned would poison the scan. 'acmehealth' and 'zephyr' are inventions.

test('finds a banned term and reports its line', () => {
  const hits = scanResidue('line one\nsomething AcmeHealth here\n', ['acmehealth'])
  assert.equal(hits.length, 1)
  assert.equal(hits[0].line, 2)
  assert.equal(hits[0].term, 'acmehealth')
})

test('matching is case-insensitive', () => {
  assert.equal(scanResidue('ACMEHEALTH\n', ['acmehealth']).length, 1)
  assert.equal(scanResidue('acmehealth\n', ['AcmeHealth']).length, 1)
})

test('clean text produces no hits', () => {
  assert.deepEqual(scanResidue('generic security guidance\n', ['acmehealth']), [])
})

test('a term appearing twice on one line reports once per line', () => {
  assert.equal(scanResidue('acmehealth and acmehealth\n', ['acmehealth']).length, 1)
})

test('two different terms on the same line each report', () => {
  const hits = scanResidue('acmehealth ships zephyr\n', ['acmehealth', 'zephyr'])
  assert.equal(hits.length, 2)
  assert.deepEqual(hits.map((h) => h.term).sort(), ['acmehealth', 'zephyr'])
  assert.deepEqual(hits.map((h) => h.line), [1, 1])
})

test('line numbers are correct under CRLF endings', () => {
  const hits = scanResidue('a\r\nb\r\nacmehealth\r\n', ['acmehealth'])
  assert.equal(hits.length, 1)
  assert.equal(hits[0].line, 3)
})

test('a term embedded in a longer word still hits', () => {
  // Substring matching is deliberate: acmehealthcare-internal must not slip
  // through a word-boundary regex.
  assert.equal(scanResidue('see acmehealthcare-internal\n', ['acmehealth']).length, 1)
})

test('an empty term list finds nothing rather than matching everything', () => {
  // '' is a substring of every line. A blank entry must not turn the scanner
  // into a universal match, and must not turn it into a universal PASS either —
  // the CLI treats an empty list as a configuration error, not as clean.
  assert.deepEqual(scanResidue('anything at all\n', []), [])
  assert.deepEqual(scanResidue('anything at all\n', ['', '  ']), [])
})

test('parseTerms splits, trims, drops blanks and de-duplicates case-insensitively', () => {
  assert.deepEqual(parseTerms(' acmehealth , zephyr ,, AcmeHealth '), ['acmehealth', 'zephyr'])
  assert.deepEqual(parseTerms(''), [])
  assert.deepEqual(parseTerms(undefined), [])
})
