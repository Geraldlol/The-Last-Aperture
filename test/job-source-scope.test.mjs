import { test } from 'node:test'
import assert from 'node:assert/strict'
import { sourcePathsForJob } from '../scripts/lib/job-source-scope.mjs'

const sourceIndex = {
  files: [
    { path: 'src/routes/orders.ts' },
    { path: 'src/services/orders.ts' },
  ],
}

test('business-logic triage receives its sealed source scope', () => {
  assert.deepEqual(sourcePathsForJob(
    { findings: [] },
    { kind: 'TRIAGE', lens: 'business-logic' },
    { scoped_files: ['src/services/orders.ts', 'src/routes/orders.ts'] },
    sourceIndex,
  ), [
    'src/routes/orders.ts',
    'src/services/orders.ts',
  ])
})

test('attack chaining receives component locations while completeness receives no source', () => {
  const run = {
    findings: [{
      candidate_id: 'candidate:web:orders',
      location: ['src/routes/orders.ts:8'],
    }],
  }
  assert.deepEqual(sourcePathsForJob(
    run,
    { kind: 'TRIAGE', lens: 'attack-chaining' },
    { scoped_files: [] },
    sourceIndex,
  ), ['src/routes/orders.ts'])
  assert.deepEqual(sourcePathsForJob(
    run,
    { kind: 'COMPLETENESS', lens: 'completeness' },
    { scoped_files: ['src/routes/orders.ts'] },
    sourceIndex,
  ), [])
})

test('proof source scope follows only known component locations', () => {
  assert.deepEqual(sourcePathsForJob(
    {
      findings: [{
        candidate_id: 'candidate:web:orders',
        location: ['src/services/orders.ts:18:4', 'outside.ts:1'],
      }],
    },
    { kind: 'PROOF', candidate_ids: ['candidate:web:orders'] },
    { scoped_files: [] },
    sourceIndex,
  ), ['src/services/orders.ts'])
})
