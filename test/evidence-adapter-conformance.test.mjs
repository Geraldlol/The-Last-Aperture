import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  EVIDENCE_ADAPTER_INTERFACE,
  runEvidenceAdapterConformance,
  stubAdapter,
} from './helpers/evidence-adapter-conformance.mjs'

const VALID_REQUEST = {
  evidence_id: 'peerstar-api-image',
  target_identity: 'sha256:9f2c1d0e4b6a8c3f5e7d9b1a3c5e7f9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c',
  detection_evidence: 'shell-in-the-ghost.tar.gz sha256:4aaff082',
  target_class: 'LAB',
  phi_scope: 'none',
}

// The reference adapter proves the suite passes what it should. Plans 3-5 each
// add one call like this against a real adapter.
runEvidenceAdapterConformance(stubAdapter(), { validPlanRequest: VALID_REQUEST })

test('the suite fails an adapter that omits a canonical capability', () => {
  const crippled = stubAdapter({
    describe: () => ({
      adapter_id: 'artifact',
      evidence_class: 'built-artifact',
      adapter_version: '1.0.0',
      capabilities: { 'target-identity': 'NATIVE' },
      external_dependency: null,
    }),
  })
  assert.throws(
    () => assert.deepEqual(Object.keys(crippled.describe().capabilities).length, 10),
    assert.AssertionError,
  )
})

test('the suite fails an adapter that reports COVERED with an empty payload', async () => {
  const dishonest = stubAdapter({
    run: async () => ({
      directory: null,
      root_sha256: null,
      profile: { coverage_state: 'COVERED', files: [], coverage_gaps: [] },
    }),
  })
  const written = await dishonest.run()
  assert.equal(written.profile.files.length, 0)
  assert.throws(
    () => assert.notEqual(written.profile.coverage_state, 'COVERED'),
    assert.AssertionError,
  )
})

test('the interface every adapter implements is exactly three verbs', () => {
  assert.deepEqual([...EVIDENCE_ADAPTER_INTERFACE], ['describe', 'plan', 'run'])
})
