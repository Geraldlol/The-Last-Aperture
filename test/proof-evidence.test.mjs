import { test } from 'node:test'
import assert from 'node:assert/strict'
import { proofEvidence } from '../scripts/lib/proof-evidence.mjs'
import { validateFinding } from '../scripts/lib/contracts.mjs'

const config = {
  job_id: 'proof-verification:cand:web:001',
  proof_files: [{ path: 'test/security/authz.test.mjs', contents: 'a\n' }],
  command: { program: 'npm', args: ['test'] },
  destination_guard: { installed: true, path: 'test/security/harness/destinations.py' },
}
const context = { ruleSixApplicable: true }
const fail = { code: 1, stdout: 'expected 403, received 200 containing CANARY-A', stderr: '' }
const pass = { code: 0, stdout: 'all tests passed', stderr: '' }
const outcome = (demonstration, remediation) => ({ demonstration, remediation, ownedPaths: [] })

test('demonstration plus a passing remediation confirms at T1', () => {
  const e = proofEvidence(outcome(fail, pass), config, context)
  assert.equal(e.proof_tier, 'T1')
  assert.equal(e.verification_status, 'CONFIRMED')
  assert.equal(e.post_result.status, 'passed')
  assert.ok(e.pre_result.assertion)
  assert.ok(e.pre_result.path_reached)
  assert.ok(e.pre_result.control)
  assert.match(e.artifact.sha256, /^[a-f0-9]{64}$/)
  assert.equal(e.command, 'npm test')
})

test('a demonstration with no patch rests at UNPROVEN with a blocking reason', () => {
  const e = proofEvidence(outcome(fail, null), config, context)
  assert.equal(e.verification_status, 'UNPROVEN')
  assert.ok(e.blocking_reason)
  assert.equal(e.post_result, undefined)
})

test('a demonstration that does not fire is NOT_REPRODUCED with a reason', () => {
  const e = proofEvidence(outcome(pass, null), config, context)
  assert.equal(e.verification_status, 'NOT_REPRODUCED')
  assert.ok(e.reason)
})

test('a patch that leaves the suite red does not confirm', () => {
  const e = proofEvidence(outcome(fail, fail), config, context)
  assert.notEqual(e.verification_status, 'CONFIRMED')
  assert.equal(e.post_result.status, 'failed')
  assert.ok(e.reason)
})

test('an unmonitored run is recorded in the evidence', () => {
  const e = proofEvidence(
    outcome(fail, pass),
    { ...config, destination_guard: { installed: false } },
    context,
  )
  assert.match(JSON.stringify(e), /unmonitored/i)
})

test('rule six not applicable is recorded', () => {
  const e = proofEvidence(outcome(fail, pass), config, { ruleSixApplicable: false })
  assert.match(JSON.stringify(e), /previous revision/i)
})

function findingWith(evidence) {
  return {
    candidate_id: 'cand:web:001',
    lens: 'web-and-api',
    topic: 'authz-object-level',
    title: 'Tenant object loads without an ownership check',
    claimed_impact_severity: 'Critical',
    effective_severity: 'Critical',
    location: ['src/orders.js:42'],
    evidence: 'return Orders.findById(req.params.id)',
    attack: 'Request another tenant order identifier.',
    impact: 'An authenticated tenant can read another tenant order.',
    reachable_from: 'GET /orders/:id',
    confidence: 'High',
    proof_plan: 'Two-subject authorization oracle under the project runner.',
    triage_disposition: 'queued',
    existence_check: { status: 'located', method: 'read src/orders.js:42' },
    ...evidence,
  }
}

test('a confirmed evidence block satisfies the finding contract at Critical', () => {
  const e = proofEvidence(outcome(fail, pass), config, context)
  const result = validateFinding(findingWith(e))
  assert.equal(result.valid, true, JSON.stringify(result.errors))
})

test('an unproven evidence block is contract-valid but capped at Medium', () => {
  const e = proofEvidence(outcome(fail, null), config, context)
  const critical = validateFinding(findingWith(e))
  assert.equal(
    critical.errors.some(({ code }) => code === 'PROOF_TIER_CAP' || code === 'VERIFICATION_CAP'),
    true,
    'UNPROVEN must not carry Critical effective severity',
  )
  const capped = validateFinding(findingWith({ ...e, effective_severity: 'Medium' }))
  assert.equal(capped.valid, true, JSON.stringify(capped.errors))
})
