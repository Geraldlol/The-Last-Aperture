import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  buildVerdictAssessment,
  renderVerdictAssessment,
} from '../scripts/lib/verdict-assessment.mjs'

function finding(overrides = {}) {
  return {
    candidate_id: 'cand:verdict:001',
    lens: 'web-and-api',
    topic: 'authz-object-level',
    title: 'Synthetic finding',
    claimed_impact_severity: 'High',
    location: ['src/orders.js:42'],
    evidence: 'Synthetic recorded evidence',
    impact: 'Synthetic claimed impact',
    verification_status: 'UNPROVEN',
    proof_tier: 'T0',
    ...overrides,
  }
}

function run(overrides = {}) {
  return { run_id: 'run:verdict:001', findings: [finding()], jobs: [], ...overrides }
}

test('verdict assessment retains unauthenticated negative, triage and remediation claims without mutating history', () => {
  const saved = run({ findings: [finding({
    verification_status: 'DISPROVED',
    verification_authority: 'UNAUTHENTICATED_PROVIDER_ASSERTION',
    triage_disposition: 'dropped',
    triage_authority: 'UNAUTHENTICATED_PROVIDER_ASSERTION',
    remediation: { status: 'FIX_VERIFIED', detail: 'Synthetic claim' },
  })] })
  const before = structuredClone(saved)
  const assessment = buildVerdictAssessment(saved)
  const [item] = assessment.findings
  assert.equal(assessment.semantic_verifier, 'NOT_AVAILABLE')
  assert.equal(item.verification, 'CLAIMED_DISPROVED')
  assert.equal(item.triage, 'CLAIMED_DROPPED')
  assert.equal(item.remediation, 'CLAIMED_FIX_VERIFIED')
  assert.equal(item.retained, true)
  assert.equal(item.semantic_verification_authenticated, false)
  assert.deepEqual(saved, before)
})

test('recorded source anchors, receipt references and completed proof jobs never authenticate a semantic conclusion', () => {
  const saved = run({
    findings: [finding({
      verification_status: 'CONFIRMED', proof_tier: 'T2',
      source_anchors: [{ file_id: `file_${'a'.repeat(64)}` }],
    })],
    jobs: [{
      job_id: 'proof-verification:cand:verdict:001', kind: 'PROOF', state: 'SUCCEEDED',
      candidate_ids: ['cand:verdict:001'], receipt_sha256: 'a'.repeat(64),
    }],
  })
  const [item] = buildVerdictAssessment(saved).findings
  assert.equal(item.verification, 'CLAIMED_CONFIRMED')
  assert.equal(item.source_anchor_count, 1)
  assert.equal(item.proof_jobs[0].receipt_reference_recorded, true)
  assert.equal(item.semantic_verification_authenticated, false)
  assert.ok(item.unmet_requirements.includes('AUTHENTICATED_SEMANTIC_VERIFIER_UNAVAILABLE'))
})

test('verdict output omits raw evidence, PHI, credentials, proof payloads and provider narrative', () => {
  const privateValue = 'SYNTHETIC_PRIVATE_CONTENT_SENTINEL'
  const saved = run({
    findings: [finding({
      title: privateValue, impact: privateValue, evidence: privateValue,
      attack: privateValue, command: privateValue, proof_plan: privateValue,
      remediation: { status: 'FIX_FAILED', detail: privateValue },
      evidence_context: { target_identity: privateValue, detection_evidence: [privateValue] },
    })],
    jobs: [{
      job_id: 'proof-verification:cand:verdict:001', kind: 'PROOF', state: 'FAILED',
      candidate_ids: ['cand:verdict:001'], reason: privateValue,
    }],
  })
  const assessment = buildVerdictAssessment(saved)
  assert.ok(!JSON.stringify(assessment).includes(privateValue))
  assert.ok(!renderVerdictAssessment(assessment).includes(privateValue))
  assert.ok(assessment.findings[0].unmet_requirements.includes('PROOF_JOB_FAILED'))
})

test('verdict assessment bounds finding and proof-job detail without hiding incomplete work', () => {
  const saved = run({
    findings: Array.from({ length: 103 }, (_, index) => finding({
      candidate_id: `cand:verdict:${String(index).padStart(3, '0')}`,
    })),
    jobs: Array.from({ length: 22 }, (_, index) => ({
      job_id: `proof-verification:synthetic:${index}`, kind: 'PROOF',
      state: index === 21 ? 'PENDING' : 'SUCCEEDED', candidate_ids: ['cand:verdict:000'],
    })),
  })
  const assessment = buildVerdictAssessment(saved)
  assert.equal(assessment.findings_total, 103)
  assert.equal(assessment.findings.length, 100)
  assert.equal(assessment.omitted_findings, 3)
  const [item] = assessment.findings
  assert.equal(item.proof_jobs.length, 20)
  assert.equal(item.omitted_proof_jobs, 2)
  assert.ok(item.unmet_requirements.includes('PROOF_WORK_INCOMPLETE'))
  assert.equal(buildVerdictAssessment(saved, { candidateId: 'cand:verdict:102' }).findings[0].candidate_id, 'cand:verdict:102')
  assert.throws(() => buildVerdictAssessment(saved, { candidateId: 'cand:verdict:absent' }), /candidate not found/)
})

test('human verdict output exposes claimed triage and remediation and neutralizes terminal controls', () => {
  const saved = run({ findings: [finding({
    triage_disposition: 'merged', remediation: { status: 'FIX_VERIFIED', detail: 'Synthetic claim' },
  })] })
  const assessment = buildVerdictAssessment(saved)
  assessment.run_id = 'run:verdict:001\u001b[31m\nFORGED LINE'
  const output = renderVerdictAssessment(assessment)
  assert.ok(output.includes('Triage: CLAIMED_MERGED'))
  assert.ok(output.includes('Remediation: CLAIMED_FIX_VERIFIED'))
  assert.ok(!output.includes('\u001b'))
  assert.ok(!output.includes('\nFORGED LINE'))
  assert.ok(output.includes('\\u001B'))
})
