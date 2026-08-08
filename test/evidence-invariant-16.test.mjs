import { test } from 'node:test'
import assert from 'node:assert/strict'
import { evidenceConflicts, validateFinding } from '../scripts/lib/contracts.mjs'

const DECLARATIONS = new Map([
  ['cloud-and-iac', {
    source: { state: 'consumed' },
    'built-artifact': {
      state: 'consumed',
      artifact_kinds: ['oci-image'],
      may_conclude: ['secret-present-in-artifact', 'unexpected-artifact-content'],
    },
    'deployed-state': { state: 'consumed', may_conclude: ['drift-from-source'] },
    'live-runtime': { state: 'not-consumed' },
  }],
  ['web-and-api', {
    source: { state: 'consumed' },
    'built-artifact': { state: 'not-consumed' },
    'deployed-state': { state: 'consumed', may_conclude: ['runtime-misconfiguration'] },
    'live-runtime': { state: 'consumed', may_conclude: ['runtime-misconfiguration'] },
  }],
])

const COVERED = new Map([['cloud-and-iac\0container-image-content\0built-artifact', 'COVERED']])

function record(overrides = {}) {
  return {
    candidate_id: 'container-image-content:5c1a7f30',
    lens: 'cloud-and-iac',
    topic: 'container-image-content',
    title: 'Deleted build secret is readable below the whiteout',
    claimed_impact_severity: 'High',
    location: ['peerstar-api-image:layer/02/secret.txt'],
    evidence: 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI',
    attack: 'extract layer 02 and read secret.txt',
    impact: 'Recovers a deployment credential',
    reachable_from: 'anyone who can pull the image',
    confidence: 'High',
    proof_plan: 'Read the quoted bytes from the sealed bundle',
    evidence_claim: 'secret-present-in-artifact',
    evidence_context: {
      evidence_id: 'peerstar-api-image',
      evidence_class: 'built-artifact',
      adapter_id: 'artifact',
      target_identity: 'sha256:9f2c',
      acquisition_mode: 'offline-export',
      acquired_on: '2026-08-08T14:22:10Z',
      detection_evidence: ['image.tar sha256:4aaff082'],
      confidence: 'high',
    },
    ...overrides,
  }
}

test('a declared class with covered evidence validates', () => {
  const validation = validateFinding(record(), {
    evidence: { declarations: DECLARATIONS, coverage: COVERED },
  })
  assert.deepEqual(validation.errors, [])
})

test('omitting the evidence context leaves today behaviour untouched', () => {
  assert.deepEqual(validateFinding(record()).errors, [])
})

test('a lens cannot conclude from a class it declares not-consumed', () => {
  const validation = validateFinding(
    record({ lens: 'web-and-api', topic: 'authz-object-level' }),
    { evidence: { declarations: DECLARATIONS, coverage: COVERED } },
  )
  assert.ok(validation.errors.some((e) => e.code === 'EVIDENCE_CLASS_NOT_CONSUMED'))
})

test('a claim outside may_conclude is malformed', () => {
  const validation = validateFinding(
    record({ evidence_claim: 'sensitive-data-at-rest' }),
    { evidence: { declarations: DECLARATIONS, coverage: COVERED } },
  )
  assert.ok(validation.errors.some((e) => e.code === 'EVIDENCE_CLAIM_OUT_OF_BOUNDS'))
})

test('a claim on NOT_ASSESSED coverage is UNPROVEN and capped at Medium', () => {
  const coverage = new Map([
    ['cloud-and-iac\0container-image-content\0built-artifact', 'NOT_ASSESSED'],
  ])
  const errors = validateFinding(
    record({ effective_severity: 'High', triage_disposition: 'queued', verification_status: 'CONFIRMED' }),
    { evidence: { declarations: DECLARATIONS, coverage } },
  ).errors
  assert.ok(errors.some((e) => e.code === 'EVIDENCE_COVERAGE_UNPROVEN'))
  assert.ok(errors.some((e) => e.code === 'EVIDENCE_COVERAGE_SEVERITY_CAP'))
})

test('INVENTORY_ONLY caps identically to NOT_ASSESSED', () => {
  const coverage = new Map([
    ['cloud-and-iac\0container-image-content\0built-artifact', 'INVENTORY_ONLY'],
  ])
  const errors = validateFinding(
    record({ effective_severity: 'Critical', triage_disposition: 'queued' }),
    { evidence: { declarations: DECLARATIONS, coverage } },
  ).errors
  assert.ok(errors.some((e) => e.code === 'EVIDENCE_COVERAGE_SEVERITY_CAP'))
})

test('an unknown lens in the declaration set is a violation, not a pass', () => {
  const validation = validateFinding(record({ lens: 'no-such-lens' }), {
    evidence: { declarations: DECLARATIONS, coverage: COVERED },
  })
  assert.ok(validation.errors.some((e) => e.code === 'EVIDENCE_LENS_UNDECLARED'))
})

test('the higher-precedence class prevails and the conflict is recorded', () => {
  const sourceClaim = {
    candidate_id: 'container-image-content:aaaa1111',
    lens: 'cloud-and-iac',
    topic: 'container-image-content',
    location: ['Dockerfile:14'],
  }
  const artifactClaim = {
    candidate_id: 'container-image-content:5c1a7f30',
    lens: 'cloud-and-iac',
    topic: 'container-image-content',
    location: ['peerstar-api-image:layer/02/secret.txt'],
    evidence_context: { evidence_class: 'built-artifact' },
  }
  const conflicts = evidenceConflicts([sourceClaim, artifactClaim])
  assert.equal(conflicts.length, 1)
  assert.equal(conflicts[0].prevailing_class, 'built-artifact')
  assert.equal(conflicts[0].superseded_class, 'source')
  assert.equal(conflicts[0].prevailing_candidate_id, 'container-image-content:5c1a7f30')
})

test('two records in the same class are not a precedence conflict', () => {
  const conflicts = evidenceConflicts([
    { candidate_id: 'a', lens: 'web-and-api', topic: 't', location: ['a.ts:1'] },
    { candidate_id: 'b', lens: 'web-and-api', topic: 't', location: ['b.ts:2'] },
  ])
  assert.deepEqual(conflicts, [])
})
