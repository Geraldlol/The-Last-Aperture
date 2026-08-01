import assert from 'node:assert/strict'
import test from 'node:test'
import { validateFinding, validateRun } from '../scripts/lib/contracts.mjs'

function completedRun({ closureStatus, examinedPaths }) {
  return {
    schema_version: '3.0.0',
    state: 'COMPLETED',
    jobs: [],
    errors: [],
    findings: [],
    store_profiles: [],
    coverage: {
      inventory: [],
      examined: [],
      unexamined: [],
      gaps: [],
      resolved_gap_ids: [],
      lenses: [{
        lens: 'web-and-api',
        status: 'RAN',
        applicable_paths: ['src/routes/invoices.ts'],
        examined_paths: examinedPaths,
      }],
      closure: {
        status: closureStatus,
        round: 0,
        max_rounds: 3,
      },
    },
  }
}

function runCodes(run) {
  return new Set(validateRun(run).errors.map(({ code }) => code))
}

function provenFinding(overrides = {}) {
  return {
    candidate_id: 'authz-object-level:a3f19c2e',
    lens: 'web-and-api',
    topic: 'authz-object-level',
    title: 'Invoice route loads another tenant by identifier',
    claimed_impact_severity: 'High',
    location: ['src/routes/invoices.ts:88'],
    evidence: 'const invoice = await repo.findById(req.params.id)',
    attack: 'GET /api/invoices/8814 while authenticated to another tenant',
    impact: 'Reads another tenant invoice and billing address',
    reachable_from: 'GET /api/invoices/:id',
    confidence: 'High',
    proof_plan: 'Request subject A invoice as subject B and assert refusal plus marker absence',
    effective_severity: 'High',
    triage_disposition: 'queued',
    existence_check: {
      status: 'located',
      method: 'read src/routes/invoices.ts:88 and compare the quoted evidence verbatim',
    },
    proof_tier: 'T1',
    verification_status: 'CONFIRMED',
    artifact: {
      path: 'proofs/invoices.test.ts',
      sha256: 'a'.repeat(64),
    },
    command: 'npm test -- proofs/invoices.test.ts',
    pre_result: {
      assertion: 'subject B reads subject A invoice',
      path_reached: 'src/routes/invoices.ts:88',
      control: 'no tenant predicate on the query',
    },
    post_result: {
      status: 'passed',
      regressions: 'none observed in the repository test suite',
    },
    ...overrides,
  }
}

function nested(depth) {
  let value = 'leaf'
  for (let index = 0; index < depth; index += 1) value = { level: value }
  return value
}

test('a COMPLETED run cannot hide open lens/file obligations', () => {
  assert.ok(
    runCodes(completedRun({
      closureStatus: 'CONVERGED',
      examinedPaths: [],
    })).has('FALSE_COMPLETE_STATE'),
    'an open lens/file obligation must force COMPLETE_WITH_GAPS',
  )
})

test('a COMPLETED run cannot hide a non-converged closure', () => {
  for (const closureStatus of ['BUDGET_EXHAUSTED', 'UNMEASURED']) {
    assert.ok(
      runCodes(completedRun({
        closureStatus,
        examinedPaths: ['src/routes/invoices.ts'],
      })).has('FALSE_COMPLETE_STATE'),
      `closure ${closureStatus} must force COMPLETE_WITH_GAPS`,
    )
  }
})

test('a converged run with no open obligation is still allowed to be COMPLETED', () => {
  assert.equal(
    runCodes(completedRun({
      closureStatus: 'CONVERGED',
      examinedPaths: ['src/routes/invoices.ts'],
    })).has('FALSE_COMPLETE_STATE'),
    false,
  )
})

test('proof pre/post state carries real evidence within its bounds', () => {
  const validation = validateFinding(provenFinding({
    pre_result: {
      assertion: 'subject B reads subject A invoice',
      path_reached: 'src/routes/invoices.ts:88',
      control: 'no tenant predicate on the query',
      detail: 'the response body carried the marker',
      response: {
        status: 200,
        headers: { 'content-type': 'application/json' },
        markers: ['tenant-a-marker', 'invoice-8814'],
      },
    },
  }))

  assert.equal(
    validation.valid,
    true,
    `structured proof evidence must survive:\n${JSON.stringify(validation.errors, null, 2)}`,
  )
})

test('proof pre/post state is bounded in breadth and in depth', () => {
  const wide = Object.fromEntries(
    Array.from({ length: 128 }, (_, index) => [`extra_${index}`, 'value']),
  )
  assert.equal(
    validateFinding(provenFinding({
      pre_result: {
        assertion: 'subject B reads subject A invoice',
        path_reached: 'src/routes/invoices.ts:88',
        control: 'no tenant predicate on the query',
        ...wide,
      },
    })).valid,
    false,
    'an unbounded property count must be rejected before it reaches the attested manifest',
  )

  assert.equal(
    validateFinding(provenFinding({
      post_result: {
        status: 'passed',
        regressions: 'none observed in the repository test suite',
        trace: nested(64),
      },
    })).valid,
    false,
    'unbounded nesting must be rejected before it reaches deepFreeze and cloneJson',
  )
})
