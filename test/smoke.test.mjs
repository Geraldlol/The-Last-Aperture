import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parse } from 'yaml'

test('yaml devDependency is installed and parses nested maps', () => {
  const parsed = parse('a:\n  b: [1, 2]\n')
  assert.deepEqual(parsed, { a: { b: [1, 2] } })
})
