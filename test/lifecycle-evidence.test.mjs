import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  compareRuns,
  coverageSupportsResolution,
} from '../scripts/lib/lifecycle.mjs'

const EVIDENCE_LOCATION = 'sample-api-image:layer/02/secret.txt'
const SOURCE_LOCATION = 'Dockerfile'

function artifactFinding() {
  return {
    candidate_id: 'container-image-content:5c1a7f30',
    lens: 'cloud-and-iac',
    topic: 'container-image-content',
    title: 'Deleted build secret remains readable in an image layer',
    claimed_impact_severity: 'High',
    location: [EVIDENCE_LOCATION],
    evidence: 'AWS_SECRET_ACCESS_KEY remains in layer 02',
    attack: 'Extract layer 02 from the image and read secret.txt.',
    impact: 'An image reader can recover a deployment credential.',
    reachable_from: 'anyone who can pull the image',
    confidence: 'High',
    proof_plan: 'Extract the sealed image layer and read the cited bytes.',
    evidence_claim: 'secret-present-in-artifact',
    evidence_context: {
      evidence_id: 'sample-api-image',
      evidence_class: 'built-artifact',
      adapter_id: 'artifact',
      target_identity: `sha256:${'9'.repeat(64)}`,
      acquisition_mode: 'offline-export',
      acquired_on: '2026-08-08T14:22:10Z',
      detection_evidence: [`image.tar sha256:${'4'.repeat(64)}`],
      confidence: 'high',
    },
  }
}

function artifactBundle(overrides = {}) {
  return {
    evidence_id: 'sample-api-image',
    evidence_class: 'built-artifact',
    adapter_id: 'artifact',
    artifact_kind: 'oci-image',
    coverage_state: 'COVERED',
    phi_bearing: false,
    root_sha256: 'e'.repeat(64),
    ...overrides,
  }
}

function evidenceCoverage(state, bundleCount) {
  return {
    cells: [{
      lens: 'cloud-and-iac',
      topic: 'container-image-content',
      evidence_class: 'built-artifact',
      state,
      reason: state === 'COVERED'
        ? 'sample-api-image was assessed'
        : 'no built-artifact evidence was acquired for this run',
    }],
    summary: {
      cell_count: 1,
      bundle_count: bundleCount,
      unreached_class_count: state === 'COVERED' ? 0 : 1,
      unreached_classes: state === 'COVERED' ? [] : ['built-artifact'],
      not_assessed_cell_count: state === 'NOT_ASSESSED' ? 1 : 0,
      inventory_only_cell_count: state === 'INVENTORY_ONLY' ? 1 : 0,
    },
  }
}

function artifactRun(overrides = {}) {
  return {
    run_id: 'run:artifact:baseline',
    state: 'COMPLETED',
    capability_mode: 'STATIC',
    repository: {
      root: 'C:\\repo',
      tree_digest: 'a'.repeat(64),
    },
    coverage: {
      inventory: [SOURCE_LOCATION],
      examined: [SOURCE_LOCATION],
      unexamined: [],
      lenses: [{
        lens: 'cloud-and-iac',
        status: 'RAN',
        examined_paths: [SOURCE_LOCATION],
      }],
      gaps: [],
    },
    findings: [artifactFinding()],
    jobs: [{
      job_id: 'lens:cloud-and-iac',
      kind: 'LENS',
      lens: 'cloud-and-iac',
      state: 'SUCCEEDED',
      coverage_authority: 'PROVIDER_DECLARED',
    }],
    evidence_bundles: [artifactBundle()],
    evidence_coverage: evidenceCoverage('COVERED', 1),
    errors: [],
    policy_digest: 'b'.repeat(64),
    lens_pack_digest: 'c'.repeat(64),
    plan_digest: 'd'.repeat(64),
    tool: { version: '0.12.0' },
    ...overrides,
  }
}

test('an evidence finding cannot be claimed fixed when the current class was not acquired', () => {
  const baseline = artifactRun()
  const current = artifactRun({
    run_id: 'run:artifact:not-acquired',
    findings: [],
    evidence_bundles: [],
    evidence_coverage: evidenceCoverage('NOT_ASSESSED', 0),
  })

  assert.equal(coverageSupportsResolution(current, artifactFinding(), baseline), false)
  assert.equal(compareRuns(baseline, current).counts['not-observed'], 1)
  assert.equal(compareRuns(baseline, current).counts['claimed-fixed'], 0)
})

test('an evidence finding cannot be cleared by a covered cell for a different acquisition', () => {
  const baseline = artifactRun()
  const current = artifactRun({
    run_id: 'run:artifact:different-acquisition',
    findings: [],
    evidence_bundles: [artifactBundle({ evidence_id: 'different-image' })],
    evidence_coverage: evidenceCoverage('COVERED', 1),
  })

  assert.equal(coverageSupportsResolution(current, artifactFinding(), baseline), false)
  assert.equal(compareRuns(baseline, current).counts['not-observed'], 1)
})

test('a built-artifact finding cannot be cleared by a different artifact kind', () => {
  const baseline = artifactRun()
  const current = artifactRun({
    run_id: 'run:artifact:different-kind',
    findings: [],
    evidence_bundles: [artifactBundle({ artifact_kind: 'firmware-image' })],
    evidence_coverage: evidenceCoverage('COVERED', 1),
  })

  assert.equal(coverageSupportsResolution(current, artifactFinding(), baseline), false)
  assert.equal(compareRuns(baseline, current).counts['not-observed'], 1)
})

test('built-artifact resolution fails closed without baseline artifact identity', () => {
  const current = artifactRun({
    run_id: 'run:artifact:no-baseline-identity',
    findings: [],
  })

  assert.equal(coverageSupportsResolution(current, artifactFinding()), false)
})

test('matching covered evidence permits the existing unauthenticated absence claim', () => {
  const baseline = artifactRun()
  const current = artifactRun({
    run_id: 'run:artifact:covered',
    findings: [],
    evidence_bundles: [artifactBundle({ root_sha256: 'f'.repeat(64) })],
    evidence_coverage: evidenceCoverage('COVERED', 1),
  })

  assert.equal(coverageSupportsResolution(current, artifactFinding(), baseline), true)
  assert.equal(compareRuns(baseline, current).counts['claimed-fixed'], 1)
  assert.equal(compareRuns(baseline, current).counts.fixed, 0)
})
