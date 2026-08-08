import assert from 'node:assert/strict'
import test from 'node:test'
import { validateFinding } from '../scripts/lib/contracts.mjs'
import { createProofJobComparator } from '../scripts/lib/job-protocol.mjs'

function stageOne(overrides = {}) {
  return {
    candidate_id: 'authz-object-level:a3f19c2e',
    lens: 'web-and-api',
    topic: 'authz-object-level',
    title: 'Invoice route loads another tenant by identifier',
    claimed_impact_severity: 'Critical',
    location: ['src/routes/invoices.ts:88'],
    evidence: 'const invoice = await repo.findById(req.params.id)',
    attack: 'GET /api/invoices/8814 while authenticated to another tenant',
    impact: 'Reads another tenant invoice and billing address',
    reachable_from: 'GET /api/invoices/:id',
    confidence: 'High',
    proof_plan: 'Request subject A invoice as subject B and assert refusal plus marker absence',
    ...overrides,
  }
}

function codes(record, options) {
  return new Set(validateFinding(record, options).errors.map(({ code }) => code))
}

function pointers(record) {
  return new Set(validateFinding(record).errors.map(({ instancePath }) => instancePath))
}

test('reachable_from accepts exactly the three specified forms', () => {
  for (const reachability of [
    'GET /api/invoices/:id',
    'src/app.js exported module',
    'unknown',
  ]) {
    const validation = validateFinding(stageOne({ reachable_from: reachability }))
    assert.equal(
      validation.valid,
      true,
      `${reachability} must be accepted:\n${JSON.stringify(validation.errors, null, 2)}`,
    )
  }

  const contingent = validateFinding(stageOne({
    reachable_from: 'contingent:POST /api/exports',
    contingent_fact: 'the guest permission set is assigned to at least one user',
    contingent_query: 'SELECT COUNT(*) FROM PermissionSetAssignment WHERE PermissionSetId = :id',
  }))
  assert.equal(
    contingent.valid,
    true,
    `the contingent form must be accepted:\n${JSON.stringify(contingent.errors, null, 2)}`,
  )
})

test('a contingent near-miss cannot skip the contingency disclosure', () => {
  const record = stageOne({
    reachable_from: 'contingent on FEATURE_X being enabled',
    effective_severity: 'Critical',
    triage_disposition: 'queued',
  })

  assert.equal(
    validateFinding(record).valid,
    false,
    'a contingent: near-miss must be rejected rather than bypassing contingent_fact and contingent_query',
  )
  assert.ok(pointers(record).has('/reachable_from'))
  assert.ok(
    codes(record).has('REACHABILITY_CAP'),
    'the runtime cap must read a contingent near-miss as unresolved reachability',
  )
})

test('an unknown near-miss cannot carry an uncapped effective severity', () => {
  const record = stageOne({
    reachable_from: 'Unknown — no caller traced',
    effective_severity: 'Critical',
    triage_disposition: 'queued',
  })

  assert.equal(
    validateFinding(record).valid,
    false,
    'an unknown near-miss must be rejected rather than bypassing the Medium cap',
  )
  assert.ok(pointers(record).has('/reachable_from'))
  assert.ok(
    codes(record).has('REACHABILITY_CAP'),
    'the runtime cap must read an unknown near-miss as unresolved reachability',
  )
})

test('the contingent form still requires the fact and the query it waits on', () => {
  const record = stageOne({ reachable_from: 'contingent:POST /api/exports' })
  const validation = validateFinding(record)

  assert.equal(validation.valid, false)
  assert.ok(
    validation.errors.some(({ params }) =>
      params?.missingProperty === 'contingent_fact'),
  )
  assert.ok(
    validation.errors.some(({ params }) =>
      params?.missingProperty === 'contingent_query'),
  )
})

test('an unresolved-reachability near-miss cannot outrank a traced path in the proof queue', () => {
  const run = {
    findings: [
      {
        candidate_id: 'authz-object-level:near-miss-unknown',
        claimed_impact_severity: 'Critical',
        effective_severity: 'Medium',
        reachable_from: 'Unknown — no caller traced',
      },
      {
        candidate_id: 'authz-object-level:traced',
        claimed_impact_severity: 'Critical',
        effective_severity: 'Critical',
        reachable_from: 'GET /api/invoices/:id',
      },
    ],
  }
  const ordered = run.findings
    .map(({ candidate_id: candidateId }) => ({
      job_id: `proof-existence:${candidateId}`,
      candidate_ids: [candidateId],
    }))
    .sort(createProofJobComparator(run))

  assert.deepEqual(
    ordered.map(({ candidate_ids: candidateIds }) => candidateIds[0]),
    ['authz-object-level:traced', 'authz-object-level:near-miss-unknown'],
  )
})

test('unresolved reachability is not grounds for dropping a claimed Critical or High', () => {
  for (const reachability of ['unknown', 'contingent:POST /api/exports']) {
    for (const dropReason of [
      'no entry point reaches this code',
      'unreachable from any traced caller',
      'reachability could not be established',
      'dead code',
    ]) {
      const record = stageOne({
        reachable_from: reachability,
        ...(reachability.startsWith('contingent:')
          ? {
              contingent_fact: 'the guest permission set is assigned to at least one user',
              contingent_query: 'SELECT COUNT(*) FROM PermissionSetAssignment',
            }
          : {}),
        effective_severity: 'Medium',
        triage_disposition: 'dropped',
        drop_reason: dropReason,
      })

      assert.ok(
        codes(record).has('REACHABILITY_DROP'),
        `${reachability} dropped for "${dropReason}" must stay in the proof queue`,
      )
    }
  }
})

test('a capped candidate is still droppable and mergeable on other grounds', () => {
  const droppedOnOtherGrounds = stageOne({
    reachable_from: 'unknown',
    effective_severity: 'Medium',
    triage_disposition: 'dropped',
    drop_reason: 'the framework binder rejects the identifier before the handler runs; listed in this lens Known false positives',
  })
  const merged = stageOne({
    reachable_from: 'unknown',
    effective_severity: 'Medium',
    triage_disposition: 'merged',
    merged_into_candidate_id: 'authz-object-level:b7c2d1f0',
  })
  const informationalGap = stageOne({
    candidate_id: 'coverage-gap:entry-point-unassessed',
    claimed_impact_severity: 'Info',
    reachable_from: 'unknown',
    effective_severity: 'Info',
    triage_disposition: 'dropped',
    drop_reason: 'entry point POST /api/exports appears in no record reachable_from',
  })

  for (const record of [droppedOnOtherGrounds, merged, informationalGap]) {
    const validation = validateFinding(record)
    assert.equal(
      validation.valid,
      true,
      `a legitimate disposition must survive:\n${JSON.stringify(validation.errors, null, 2)}`,
    )
  }
})

test('a capped candidate cannot be dropped without stating grounds', () => {
  const record = stageOne({
    reachable_from: 'unknown',
    effective_severity: 'Medium',
    triage_disposition: 'dropped',
  })

  assert.ok(codes(record).has('REACHABILITY_DROP'))
})
