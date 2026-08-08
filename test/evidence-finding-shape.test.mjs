import { test } from 'node:test'
import assert from 'node:assert/strict'
import { validateFinding } from '../scripts/lib/contracts.mjs'

function stageOne(overrides = {}) {
  return {
    candidate_id: 'container-image-content:5c1a7f30',
    lens: 'cloud-and-iac',
    topic: 'container-image-content',
    title: 'Deleted build secret is still readable in the layer below the whiteout',
    claimed_impact_severity: 'High',
    location: ['peerstar-api-image:layer/02/secret.txt'],
    evidence: 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI',
    attack: 'docker save the image, extract layer 02, read secret.txt',
    impact: 'Recovers a deployment credential the Dockerfile claims to have removed',
    reachable_from: 'anyone who can pull the image',
    confidence: 'High',
    proof_plan: 'Extract layer 02 from the sealed bundle and read the quoted bytes',
    evidence_claim: 'secret-present-in-artifact',
    evidence_context: {
      evidence_id: 'peerstar-api-image',
      evidence_class: 'built-artifact',
      adapter_id: 'artifact',
      target_identity: 'sha256:9f2c1d0e4b6a8c3f5e7d9b1a3c5e7f9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c',
      acquisition_mode: 'offline-export',
      acquired_on: '2026-08-08T14:22:10Z',
      detection_evidence: ['shell-in-the-ghost.tar.gz sha256:4aaff082'],
      confidence: 'high',
    },
    ...overrides,
  }
}

test('an evidence-qualified finding validates', () => {
  const validation = validateFinding(stageOne())
  assert.deepEqual(validation.errors, [])
  assert.equal(validation.valid, true)
})

test('the repository location form is unchanged', () => {
  const validation = validateFinding(stageOne({
    location: ['src/routes/invoices.ts:88'],
    evidence_claim: undefined,
    evidence_context: undefined,
    lens: 'web-and-api',
    topic: 'authz-object-level',
    candidate_id: 'authz-object-level:a3f19c2e',
  }))
  assert.deepEqual(validation.errors, [])
})

test('the two location forms are disjoint', () => {
  // A repository path can never be read as an evidence id.
  assert.equal(validateFinding(stageOne({ location: ['src/app.ts:12'] })).valid, false)
  // A bare line number can never be read as a locator.
  assert.equal(validateFinding(stageOne({ location: ['peerstar-api-image:88'] })).valid, false)
})

test('an evidence-qualified location without evidence_context is malformed', () => {
  const validation = validateFinding(stageOne({ evidence_context: undefined }))
  assert.equal(validation.valid, false)
  assert.ok(validation.errors.some((e) => e.code === 'EVIDENCE_CONTEXT_REQUIRED'))
})

test('evidence_context whose id does not match the location prefix is malformed', () => {
  const validation = validateFinding(stageOne({
    location: ['prod-cluster:v1/Namespace/sidecars'],
  }))
  assert.equal(validation.valid, false)
  assert.ok(validation.errors.some((e) => e.code === 'EVIDENCE_ID_MISMATCH'))
})

test('evidence_context requires evidence_claim and vice versa', () => {
  assert.ok(
    validateFinding(stageOne({ evidence_claim: undefined }))
      .errors.some((e) => e.code === 'EVIDENCE_CLAIM_REQUIRED'),
  )
  assert.ok(
    validateFinding(stageOne({
      location: ['src/main.ts:4'],
      evidence_context: undefined,
    })).errors.some((e) => e.code === 'EVIDENCE_CLAIM_WITHOUT_CONTEXT'),
  )
})

test('evidence_claim must be a canonical claim kind', () => {
  assert.equal(validateFinding(stageOne({ evidence_claim: 'looks-bad' })).valid, false)
})

test('a source-class evidence_context is refused; source needs no bundle', () => {
  const context = { ...stageOne().evidence_context, evidence_class: 'source' }
  const validation = validateFinding(stageOne({ evidence_context: context }))
  assert.equal(validation.valid, false)
  assert.ok(validation.errors.some((e) => e.code === 'EVIDENCE_CLASS_NOT_ACQUIRED'))
})

test('mixing repository and evidence locations in one record is refused', () => {
  const validation = validateFinding(stageOne({
    location: ['peerstar-api-image:layer/02/secret.txt', 'Dockerfile:14'],
  }))
  assert.equal(validation.valid, false)
  assert.ok(validation.errors.some((e) => e.code === 'MIXED_LOCATION_CLASSES'))
})
