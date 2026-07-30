import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { parseLedger } from '../scripts/lib/ledger.mjs'

test('a complete ledger produces no violations', () => {
  const { rows, violations } = parseLedger(readFileSync('test/samples/ledger-ok.tsv', 'utf8'))
  assert.equal(rows.length, 3)
  assert.deepEqual(violations, [])
  assert.equal(rows[0].disposition, 'moved')
})

test('an unknown disposition is a violation', () => {
  const { violations } = parseLedger(readFileSync('test/samples/ledger-bad.tsv', 'utf8'))
  assert.ok(violations.some((v) => /pending/.test(v.message)))
})

test('a row with no evidence is a violation', () => {
  const { violations } = parseLedger('source\tdestination\tdisposition\tevidence\na\tb\tpreserved\t\n')
  assert.ok(violations.some((v) => /evidence/i.test(v.message)))
})

test('intentionally_removed is accepted as a disposition', () => {
  const { violations } = parseLedger('source\tdestination\tdisposition\tevidence\na\t—\tintentionally_removed\te1\n')
  assert.deepEqual(violations, [])
})

test('a wrong column count is a violation, not a crash', () => {
  const { violations } = parseLedger('source\tdestination\tdisposition\tevidence\na\tb\n')
  assert.ok(violations.some((v) => /columns/i.test(v.message)))
})

test('an empty ledger with only a header is a violation', () => {
  const { violations } = parseLedger('source\tdestination\tdisposition\tevidence\n')
  assert.ok(violations.some((v) => /no rows/i.test(v.message)))
})

test('line numbers survive blank lines', () => {
  const { violations } = parseLedger('source\tdestination\tdisposition\tevidence\n\na\tb\tunknown_disp\te1\n')
  assert.ok(violations.some((v) => /line 3/.test(v.message)), 'violation should reference physical line 3')
})
