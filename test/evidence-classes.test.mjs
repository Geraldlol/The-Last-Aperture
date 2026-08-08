import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  EVIDENCE_ARTIFACT_KINDS,
  EVIDENCE_CLAIM_KINDS,
  EVIDENCE_CLASSES,
  EVIDENCE_CLASS_ORDER,
  EVIDENCE_COVERAGE_STATES,
  assertEvidenceClass,
  compareEvidenceClassPrecedence,
  evidenceClassAuthorizationFloor,
  evidenceClassPrecedence,
  evidenceCoverageStateClears,
  higherPrecedenceEvidenceClass,
  isEvidenceArtifactKind,
  isEvidenceClaimKind,
  isEvidenceClass,
  isEvidenceCoverageState,
  normalizeEvidenceId,
} from '../scripts/lib/evidence-classes.mjs'

test('the four canonical classes are ordered by ascending precedence', () => {
  assert.deepEqual(EVIDENCE_CLASS_ORDER, [
    'source',
    'built-artifact',
    'deployed-state',
    'live-runtime',
  ])
  assert.equal(evidenceClassPrecedence(EVIDENCE_CLASSES.SOURCE), 1)
  assert.equal(evidenceClassPrecedence(EVIDENCE_CLASSES.LIVE_RUNTIME), 4)
})

test('a built artifact outranks the source that claims to produce it', () => {
  assert.ok(compareEvidenceClassPrecedence('source', 'built-artifact') < 0)
  assert.equal(higherPrecedenceEvidenceClass('source', 'built-artifact'), 'built-artifact')
  assert.equal(higherPrecedenceEvidenceClass('live-runtime', 'deployed-state'), 'live-runtime')
  assert.equal(higherPrecedenceEvidenceClass('source', 'source'), 'source')
})

test('an unknown class is rejected rather than defaulted', () => {
  assert.equal(isEvidenceClass('exploitation'), false)
  assert.throws(() => assertEvidenceClass('exploitation'), TypeError)
  assert.throws(() => evidenceClassPrecedence('exploitation'), TypeError)
})

test('the coverage-state vocabulary is the database contract vocabulary, unchanged', () => {
  assert.deepEqual(EVIDENCE_COVERAGE_STATES, [
    'COVERED',
    'PARTIAL',
    'INVENTORY_ONLY',
    'NOT_ASSESSED',
    'NOT_APPLICABLE',
  ])
  assert.ok(isEvidenceCoverageState('INVENTORY_ONLY'))
  assert.equal(isEvidenceCoverageState('ASSESSED'), false)
})

test('INVENTORY_ONLY and NOT_ASSESSED never clear', () => {
  assert.equal(evidenceCoverageStateClears('COVERED'), true)
  assert.equal(evidenceCoverageStateClears('PARTIAL'), true)
  assert.equal(evidenceCoverageStateClears('NOT_APPLICABLE'), true)
  assert.equal(evidenceCoverageStateClears('INVENTORY_ONLY'), false)
  assert.equal(evidenceCoverageStateClears('NOT_ASSESSED'), false)
})

test('artifact kinds and claim kinds are closed canonical sets', () => {
  assert.deepEqual(EVIDENCE_ARTIFACT_KINDS, [
    'apk',
    'dist-bundle',
    'ipa',
    'jar',
    'oci-image',
  ])
  assert.ok(isEvidenceArtifactKind('oci-image'))
  assert.equal(isEvidenceArtifactKind('docker-image'), false)
  assert.deepEqual(EVIDENCE_CLAIM_KINDS, [
    'drift-from-source',
    'runtime-misconfiguration',
    'secret-present-in-artifact',
    'sensitive-data-at-rest',
    'unexpected-artifact-content',
    'vulnerable-component-present',
  ])
  assert.ok(isEvidenceClaimKind('secret-present-in-artifact'))
  assert.equal(isEvidenceClaimKind('looks-bad'), false)
})

test('the authorization floor rises with precedence and no adapter may go below it', () => {
  assert.deepEqual(evidenceClassAuthorizationFloor('source'), {
    attestation: false,
    credential_ref: false,
    target_class: false,
    operator_identity: false,
    impact_counters: false,
    kill_switch: false,
  })
  assert.deepEqual(evidenceClassAuthorizationFloor('built-artifact'), {
    attestation: false,
    credential_ref: false,
    target_class: false,
    operator_identity: false,
    impact_counters: false,
    kill_switch: false,
  })
  assert.deepEqual(evidenceClassAuthorizationFloor('deployed-state'), {
    attestation: true,
    credential_ref: false,
    target_class: true,
    operator_identity: true,
    impact_counters: true,
    kill_switch: true,
  })
  assert.deepEqual(evidenceClassAuthorizationFloor('live-runtime'), {
    attestation: true,
    credential_ref: false,
    target_class: true,
    operator_identity: true,
    impact_counters: true,
    kill_switch: true,
  })
})

test('an evidence id is a stable handle and never carries a hostname', () => {
  assert.equal(normalizeEvidenceId('peerstar-api-image'), 'peerstar-api-image')
  assert.equal(normalizeEvidenceId('  prod-cluster  '), 'prod-cluster')
  assert.throws(() => normalizeEvidenceId('api.peerstar.internal'), TypeError)
  assert.throws(() => normalizeEvidenceId('localhost'), TypeError)
  assert.throws(() => normalizeEvidenceId('10.0.0.4'), TypeError)
  assert.throws(() => normalizeEvidenceId('Peerstar-API'), TypeError)
  assert.throws(() => normalizeEvidenceId('-leading-dash'), TypeError)
  assert.throws(() => normalizeEvidenceId(''), TypeError)
  assert.throws(() => normalizeEvidenceId('a'.repeat(65)), TypeError)
})
