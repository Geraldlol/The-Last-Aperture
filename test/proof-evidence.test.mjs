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
const v2Config = {
  ...config,
  schema_version: '2.0.0',
  oracle: {
    id: 'oracle:exit-differential',
    attack_exit_codes: [17],
    control_exit_codes: [0],
  },
}
const outcome = (demonstration, remediation, control) => ({
  demonstration,
  remediation,
  ...(control === undefined ? {} : { control }),
  ownedPaths: [],
})

test('demonstration plus a passing remediation confirms at T1', () => {
  const e = proofEvidence(outcome(fail, pass), config, context)
  assert.equal(e.proof_tier, 'T1')
  assert.equal(e.verification_status, 'CONFIRMED')
  assert.equal(e.post_result.status, 'passed')
  assert.equal(e.remediation.status, 'FIX_VERIFIED')
  assert.ok(e.remediation.detail)
  assert.ok(e.pre_result.assertion)
  assert.ok(e.pre_result.path_reached)
  assert.ok(e.pre_result.control)
  assert.match(e.artifact.sha256, /^[a-f0-9]{64}$/)
  assert.equal(e.command, 'controller-sealed T1 proof command')
})

test('a reproduced attack with a passing explicit control confirms without a patch', () => {
  const e = proofEvidence(outcome(fail, null, pass), config, context)
  assert.equal(e.verification_status, 'CONFIRMED')
  assert.equal(e.pre_result.control_status, 'passed')
  assert.match(e.pre_result.control, /all tests passed/)
  assert.deepEqual(e.remediation, {
    status: 'NOT_ATTEMPTED',
    detail: 'no candidate patch was supplied',
  })
  assert.equal(e.post_result, undefined)
})

test('a reproduced attack without an explicit control or passing legacy patch stays UNPROVEN', () => {
  const e = proofEvidence(outcome(fail, null), config, context)
  assert.equal(e.verification_status, 'UNPROVEN')
  assert.match(e.blocking_reason, /control/i)
  assert.equal(e.remediation.status, 'NOT_ATTEMPTED')
})

test('an omitted patch result is treated as not attempted', () => {
  const e = proofEvidence({ demonstration: fail, ownedPaths: [] }, config, context)
  assert.equal(e.verification_status, 'UNPROVEN')
  assert.equal(e.remediation.status, 'NOT_ATTEMPTED')
})

test('a demonstration that does not fire is NOT_REPRODUCED with a reason', () => {
  const e = proofEvidence(outcome(pass, null), config, context)
  assert.equal(e.verification_status, 'NOT_REPRODUCED')
  assert.ok(e.reason)
})

test('a timed-out demonstration is inconclusive rather than a reproduced attack', () => {
  const timedOut = {
    code: 124,
    signal: 'SIGTERM',
    stdout: '',
    stderr: 'terminated after the proof wall limit',
    timed_out: true,
  }
  const e = proofEvidence(outcome(timedOut, null, pass), config, context)
  assert.equal(e.verification_status, 'INCONCLUSIVE')
  assert.match(e.reason, /timed out/i)
  assert.equal(e.pre_result, undefined)
})

test('a v2 proof accepts only the exact signed oracle exit classes', () => {
  const expectedAttack = { code: 17, stdout: 'reproduced', stderr: '' }
  assert.equal(
    proofEvidence(outcome(expectedAttack, null, pass), v2Config, context).verification_status,
    'CONFIRMED',
  )

  const unexpectedExit = { code: 2, stdout: '', stderr: 'harness crashed' }
  const inconclusive = proofEvidence(outcome(unexpectedExit, null, pass), v2Config, context)
  assert.equal(inconclusive.verification_status, 'INCONCLUSIVE')
  assert.match(inconclusive.reason, /not declared by the v2 oracle/i)

  const noAttack = proofEvidence(outcome(pass, null, pass), v2Config, context)
  assert.equal(noAttack.verification_status, 'NOT_REPRODUCED')
})

test('a failed patch does not downgrade an attack confirmed by an explicit control', () => {
  const e = proofEvidence(outcome(fail, fail, pass), config, context)
  assert.equal(e.verification_status, 'CONFIRMED')
  assert.deepEqual(e.remediation, {
    status: 'FIX_FAILED',
    detail: 'expected 403, received 200 containing CANARY-A',
  })
  assert.equal(e.post_result, undefined)
})

test('a failed explicit control makes the proof inconclusive', () => {
  const e = proofEvidence(outcome(fail, null, fail), config, context)
  assert.equal(e.verification_status, 'INCONCLUSIVE')
  assert.equal(e.pre_result.control_status, 'failed')
  assert.match(e.reason, /control/i)
  assert.equal(e.remediation.status, 'NOT_ATTEMPTED')
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

test('a control-confirmed evidence block without a patch satisfies the finding contract', () => {
  const e = proofEvidence(outcome(fail, null, pass), config, context)
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
