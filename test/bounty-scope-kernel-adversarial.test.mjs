import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { decideScope } from '../scripts/lib/bounty-scope-kernel.mjs'

const CASES_URL = new URL('../fixtures/bounty/scope-kernel-cases.json', import.meta.url)
const suite = JSON.parse(readFileSync(CASES_URL, 'utf8'))

test('fixture suite is well formed', () => {
  assert.equal(suite.kind, 'red-team-audit/bounty-scope-kernel-cases')
  assert.ok(suite.cases.length >= 35)
  const ids = suite.cases.map((entry) => entry.case_id)
  assert.equal(new Set(ids).size, ids.length, 'case ids must be unique')
})

for (const entry of suite.cases) {
  test(`scope kernel case: ${entry.case_id}`, () => {
    const result = decideScope(suite.scope, entry.candidate)
    assert.equal(result.decision, entry.expect, `${entry.candidate} decision`)
    assert.equal(result.reason, entry.expect_reason, `${entry.candidate} reason`)
  })
}

test('no case in the suite reaches ALLOW by default', () => {
  const emptyScope = { scope_rules: { allow: [], deny: [] } }
  for (const entry of suite.cases) {
    assert.equal(decideScope(emptyScope, entry.candidate).decision, 'DENY', entry.case_id)
  }
})
