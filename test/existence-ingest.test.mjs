import { test } from 'node:test'
import assert from 'node:assert/strict'
import { verifyRepositorySnapshot } from '../scripts/audit.mjs'

test('verifyRepositorySnapshot is exported for inventory reuse', () => {
  assert.equal(typeof verifyRepositorySnapshot, 'function')
})
