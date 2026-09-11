import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  EVIDENCE_BUNDLE_SCHEMA_VERSION,
  EVIDENCE_CONTRACT_VERSION,
  EvidenceContractValidationError,
  assertValidEvidenceProfile,
  evidenceBundleSchema,
  validateEvidenceProfile,
} from '../scripts/lib/evidence-contracts.mjs'
import {
  EVIDENCE_ARTIFACT_KINDS,
  EVIDENCE_CLASS_ORDER,
  EVIDENCE_COVERAGE_STATES,
} from '../scripts/lib/evidence-classes.mjs'

function profile(overrides = {}) {
  return {
    schema: EVIDENCE_BUNDLE_SCHEMA_VERSION,
    evidence_context: {
      evidence_id: 'sample-api-image',
      evidence_class: 'built-artifact',
      adapter_id: 'artifact',
      target_identity: 'sha256:9f2c1d0e4b6a8c3f5e7d9b1a3c5e7f9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c',
      acquisition_mode: 'offline-export',
      acquired_on: '2026-08-08T14:22:10Z',
      detection_evidence: ['shell-in-the-ghost.tar.gz sha256:4aaff082'],
      confidence: 'high',
    },
    target_class: 'LAB',
    phi_scope: 'none',
    phi_bearing: false,
    adapter_version: '1.0.0',
    contract_version: EVIDENCE_CONTRACT_VERSION,
    coverage_state: 'COVERED',
    artifact_kind: 'oci-image',
    files: [
      {
        path: 'payload/layers/02/entries.json',
        sha256: '6c1f0a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f',
        size: 4096,
      },
    ],
    attestation: null,
    coverage_gaps: [],
    ...overrides,
  }
}

test('the reference profile validates', () => {
  const validation = validateEvidenceProfile(profile())
  assert.deepEqual(validation.errors, [])
  assert.equal(validation.valid, true)
})

test('the schema enums are the registry enums, not a private copy', () => {
  const context = evidenceBundleSchema.$defs.evidenceContext.properties
  assert.deepEqual(context.evidence_class.enum, [...EVIDENCE_CLASS_ORDER])
  assert.deepEqual(
    evidenceBundleSchema.properties.coverage_state.enum,
    [...EVIDENCE_COVERAGE_STATES],
  )
  assert.deepEqual(
    evidenceBundleSchema.properties.artifact_kind.enum,
    [...EVIDENCE_ARTIFACT_KINDS],
  )
})

test('every evidence_context field is required', () => {
  for (const field of [
    'evidence_id',
    'evidence_class',
    'adapter_id',
    'target_identity',
    'acquisition_mode',
    'acquired_on',
    'detection_evidence',
    'confidence',
  ]) {
    const candidate = profile()
    delete candidate.evidence_context[field]
    assert.equal(
      validateEvidenceProfile(candidate).valid,
      false,
      `${field} must be required`,
    )
  }
})

test('an unknown property is rejected rather than carried', () => {
  assert.equal(validateEvidenceProfile(profile({ notes: 'extra' })).valid, false)
  const candidate = profile()
  candidate.evidence_context.hostname = 'api.internal'
  assert.equal(validateEvidenceProfile(candidate).valid, false)
})

test('COVERED with an empty payload is rejected by the contract itself', () => {
  const validation = validateEvidenceProfile(profile({ files: [] }))
  assert.equal(validation.valid, false)
  assert.ok(validation.errors.some((error) => error.code === 'EMPTY_COVERED_PAYLOAD'))
})

test('a non-clearing coverage state requires a named gap', () => {
  const validation = validateEvidenceProfile(
    profile({ coverage_state: 'NOT_ASSESSED', files: [], coverage_gaps: [] }),
  )
  assert.equal(validation.valid, false)
  assert.ok(validation.errors.some((error) => error.code === 'UNNAMED_COVERAGE_GAP'))

  const named = validateEvidenceProfile(profile({
    coverage_state: 'NOT_ASSESSED',
    files: [],
    coverage_gaps: [{ area: 'registry', reason: 'crane is not installed on PATH' }],
  }))
  assert.deepEqual(named.errors, [])
})

test('artifact_kind is required for built-artifact and forbidden elsewhere', () => {
  const missing = profile()
  delete missing.artifact_kind
  assert.ok(
    validateEvidenceProfile(missing).errors
      .some((error) => error.code === 'ARTIFACT_KIND_REQUIRED'),
  )

  const context = { ...profile().evidence_context, evidence_class: 'deployed-state', adapter_id: 'deployed' }
  assert.ok(
    validateEvidenceProfile(profile({ evidence_context: context })).errors
      .some((error) => error.code === 'ARTIFACT_KIND_NOT_APPLICABLE'),
  )
})

test('a credential value anywhere in the profile is refused', () => {
  const candidate = profile()
  candidate.evidence_context.detection_evidence = [
    'docker login -u ci -p hunter2 registry.internal',
  ]
  const validation = validateEvidenceProfile(candidate)
  assert.equal(validation.valid, false)
  assert.ok(validation.errors.some((error) => error.code === 'CREDENTIAL_VALUE_PRESENT'))
})

test('phi_bearing content requires a declared phi scope that permits it', () => {
  const validation = validateEvidenceProfile(
    profile({ phi_scope: 'none', phi_bearing: true }),
  )
  assert.equal(validation.valid, false)
  assert.ok(validation.errors.some((error) => error.code === 'PHI_SCOPE_CONTRADICTION'))
})

test('assertValidEvidenceProfile throws with the failing pointers attached', () => {
  assert.throws(
    () => assertValidEvidenceProfile(profile({ files: [] })),
    (error) => error instanceof EvidenceContractValidationError
      && error.errors.some((detail) => detail.code === 'EMPTY_COVERED_PAYLOAD'),
  )
  assert.equal(assertValidEvidenceProfile(profile()).phi_bearing, false)
})
