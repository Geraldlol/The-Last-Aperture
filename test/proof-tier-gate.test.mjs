import { test } from 'node:test'
import assert from 'node:assert/strict'
import { validateFinding } from '../scripts/lib/contracts.mjs'

function finding(overrides = {}) {
  return {
    candidate_id: 'cand:web:001',
    lens: 'web-and-api',
    topic: 'authz-object-level',
    title: 'Tenant object loads without an ownership check',
    claimed_impact_severity: 'Critical',
    effective_severity: 'Critical',
    location: ['src/orders.js:42'],
    evidence: 'return Orders.findById(req.params.id)',
    reachable_from: 'GET /orders/:id',
    proof_tier: 'T1',
    verification_status: 'CONFIRMED',
    ...overrides,
  }
}

const codes = (record) => validateFinding(record).errors.map((error) => error.code)

test('T3 evidence no longer caps effective severity', () => {
  assert.equal(codes(finding({ proof_tier: 'T3' })).includes('PROOF_TIER_CAP'), false)
})

test('T0 evidence still caps effective severity at Medium', () => {
  assert.equal(codes(finding({ proof_tier: 'T0' })).includes('PROOF_TIER_CAP'), true)
})

test('T1 and T2 evidence do not cap effective severity', () => {
  for (const tier of ['T1', 'T2']) {
    assert.equal(codes(finding({ proof_tier: tier })).includes('PROOF_TIER_CAP'), false)
  }
})

test('unresolved reachability still caps regardless of tier', () => {
  const codesFor = codes(finding({ proof_tier: 'T1', reachable_from: 'unknown' }))
  assert.equal(codesFor.includes('REACHABILITY_CAP'), true)
})
