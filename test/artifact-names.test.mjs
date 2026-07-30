import test from 'node:test'
import assert from 'node:assert/strict'
import {
  artifactKeyToken,
  artifactToken,
} from '../scripts/lib/artifact-names.mjs'

test('artifact names remain injective after slug normalization and truncation', () => {
  assert.notEqual(artifactToken('proof:a/b'), artifactToken('proof:a?b'))
  assert.notEqual(
    artifactToken(`proof:${'a'.repeat(200)}:left`),
    artifactToken(`proof:${'a'.repeat(200)}:right`),
  )
  assert.match(artifactToken('proof:a/b'), /^[A-Za-z0-9._-]+$/)
})

test('artifact keys satisfy the run artifact property-name contract', () => {
  const key = `result_${artifactKeyToken('proof:a.b/c').toLowerCase()}`
  assert.match(key, /^[a-z][a-z0-9_-]*$/)
})
