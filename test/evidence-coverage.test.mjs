import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  acquiredEvidenceHasGaps,
  buildEvidenceCoverage,
  evidenceCoverageIndex,
} from '../scripts/lib/evidence-coverage.mjs'

const LENSES = [
  {
    frontmatter: {
      name: 'cloud-and-iac',
      owns: ['container-image-content', 'iac-secrets'],
      activates_on: {
        evidence_classes: {
          source: { state: 'consumed' },
          'built-artifact': {
            state: 'consumed',
            artifact_kinds: ['oci-image'],
            may_conclude: ['secret-present-in-artifact'],
          },
          'deployed-state': { state: 'consumed', may_conclude: ['drift-from-source'] },
          'live-runtime': { state: 'not-consumed' },
        },
      },
    },
  },
  {
    frontmatter: {
      name: 'mobile-app-security',
      owns: ['mobile-storage'],
      activates_on: {
        evidence_classes: {
          source: { state: 'consumed' },
          'built-artifact': {
            state: 'consumed',
            artifact_kinds: ['apk', 'ipa'],
            may_conclude: ['secret-present-in-artifact'],
          },
          'deployed-state': { state: 'not-consumed' },
          'live-runtime': { state: 'not-consumed' },
        },
      },
    },
  },
]

const cell = (coverage, lens, topic, evidenceClass) => coverage.cells.find(
  (entry) => entry.lens === lens
    && entry.topic === topic
    && entry.evidence_class === evidenceClass,
)

test('with no bundle, every consumed non-source class is NOT_ASSESSED with a reason', () => {
  const coverage = buildEvidenceCoverage({
    lenses: LENSES,
    activatedLenses: ['cloud-and-iac'],
    bundles: [],
  })
  const artifact = cell(coverage, 'cloud-and-iac', 'container-image-content', 'built-artifact')
  assert.equal(artifact.state, 'NOT_ASSESSED')
  assert.match(artifact.reason, /no built-artifact evidence was acquired/)
  assert.equal(
    cell(coverage, 'cloud-and-iac', 'container-image-content', 'deployed-state').state,
    'NOT_ASSESSED',
  )
})

test('source is COVERED for an activated lens and the repository needs no bundle', () => {
  const coverage = buildEvidenceCoverage({
    lenses: LENSES,
    activatedLenses: ['cloud-and-iac'],
    bundles: [],
  })
  assert.equal(cell(coverage, 'cloud-and-iac', 'iac-secrets', 'source').state, 'COVERED')
})

test('a not-consumed class is NOT_APPLICABLE, never NOT_ASSESSED', () => {
  const coverage = buildEvidenceCoverage({
    lenses: LENSES,
    activatedLenses: ['cloud-and-iac'],
    bundles: [],
  })
  const runtime = cell(coverage, 'cloud-and-iac', 'container-image-content', 'live-runtime')
  assert.equal(runtime.state, 'NOT_APPLICABLE')
  assert.match(runtime.reason, /nothing to say/)
})

test('an inactive lens contributes NOT_APPLICABLE across the board', () => {
  const coverage = buildEvidenceCoverage({
    lenses: LENSES,
    activatedLenses: ['cloud-and-iac'],
    bundles: [],
  })
  for (const evidenceClass of ['source', 'built-artifact', 'deployed-state', 'live-runtime']) {
    assert.equal(
      cell(coverage, 'mobile-app-security', 'mobile-storage', evidenceClass).state,
      'NOT_APPLICABLE',
    )
  }
})

test('a supplied bundle carries its own coverage state into the matrix', () => {
  const coverage = buildEvidenceCoverage({
    lenses: LENSES,
    activatedLenses: ['cloud-and-iac'],
    bundles: [{
      evidence_id: 'peerstar-api-image',
      evidence_class: 'built-artifact',
      artifact_kind: 'oci-image',
      coverage_state: 'PARTIAL',
      root_sha256: 'a'.repeat(64),
    }],
  })
  const artifact = cell(coverage, 'cloud-and-iac', 'container-image-content', 'built-artifact')
  assert.equal(artifact.state, 'PARTIAL')
  assert.match(artifact.reason, /peerstar-api-image/)
})

test('missing controller analysis state cannot produce non-source COVERED', () => {
  const coverage = buildEvidenceCoverage({
    lenses: LENSES,
    activatedLenses: ['cloud-and-iac'],
    bundles: [{
      evidence_id: 'unproven-image-analysis',
      evidence_class: 'built-artifact',
      artifact_kind: 'oci-image',
      coverage_state: 'COVERED',
      root_sha256: '8'.repeat(64),
    }],
  })
  const artifact = cell(
    coverage,
    'cloud-and-iac',
    'container-image-content',
    'built-artifact',
  )

  assert.equal(artifact.state, 'PARTIAL')
  assert.match(artifact.reason, /controller analysis state is missing/)
  assert.equal(coverage.bundle_coverage[0].state, 'PARTIAL')
})

test('an acquired class without supported provider delivery remains NOT_ASSESSED', () => {
  const coverage = buildEvidenceCoverage({
    lenses: LENSES,
    activatedLenses: ['cloud-and-iac'],
    bundles: [{
      evidence_id: 'prod-cluster',
      evidence_class: 'deployed-state',
      coverage_state: 'COVERED',
      root_sha256: 'c'.repeat(64),
      analysis_state: 'NOT_ASSESSED',
      analysis_reason: 'provider evidence-byte delivery is not implemented',
    }],
  })
  const deployed = cell(
    coverage,
    'cloud-and-iac',
    'container-image-content',
    'deployed-state',
  )
  assert.equal(deployed.state, 'NOT_ASSESSED')
  assert.match(deployed.reason, /provider evidence-byte delivery/i)
  assert.ok(coverage.summary.unreached_classes.includes('deployed-state'))
})

test('an artifact kind no activated lens declares is INVENTORY_ONLY, never silence', () => {
  const coverage = buildEvidenceCoverage({
    lenses: LENSES,
    activatedLenses: ['cloud-and-iac'],
    bundles: [{
      evidence_id: 'peerstar-mobile',
      evidence_class: 'built-artifact',
      artifact_kind: 'apk',
      coverage_state: 'COVERED',
      root_sha256: 'b'.repeat(64),
    }],
  })
  const artifact = cell(coverage, 'cloud-and-iac', 'container-image-content', 'built-artifact')
  assert.equal(artifact.state, 'INVENTORY_ONLY')
  assert.match(artifact.reason, /apk/)
})

test('the summary counts the classes an audit could not reach', () => {
  const coverage = buildEvidenceCoverage({
    lenses: LENSES,
    activatedLenses: ['cloud-and-iac'],
    bundles: [],
  })
  assert.equal(coverage.summary.unreached_class_count, 2)
  assert.deepEqual(coverage.summary.unreached_classes, ['built-artifact', 'deployed-state'])
  assert.equal(coverage.summary.bundle_count, 0)
})

test('the index is keyed for the finding validator', () => {
  const index = evidenceCoverageIndex(buildEvidenceCoverage({
    lenses: LENSES,
    activatedLenses: ['cloud-and-iac'],
    bundles: [],
  }))
  assert.equal(
    index.get('cloud-and-iac\0container-image-content\0built-artifact'),
    'NOT_ASSESSED',
  )
})

test('cells are canonically ordered so the run digest is stable', () => {
  const first = buildEvidenceCoverage({ lenses: LENSES, activatedLenses: ['cloud-and-iac'], bundles: [] })
  const second = buildEvidenceCoverage({
    lenses: [...LENSES].reverse(),
    activatedLenses: ['cloud-and-iac'],
    bundles: [],
  })
  assert.deepEqual(first.cells, second.cells)
})

test('only attached evidence with non-clear audit coverage forces a final gap', () => {
  const base = {
    evidence_bundles: [],
    evidence_coverage: {
      cells: [{
        lens: 'cloud-and-iac',
        topic: 'container-image-content',
        evidence_class: 'deployed-state',
        state: 'NOT_ASSESSED',
        reason: 'no deployed-state evidence was acquired',
      }],
    },
  }
  assert.equal(acquiredEvidenceHasGaps(base), false)

  const attachedUnsupported = structuredClone(base)
  attachedUnsupported.evidence_bundles.push({
    evidence_class: 'deployed-state',
  })
  assert.equal(acquiredEvidenceHasGaps(attachedUnsupported), true)

  const attachedTruncated = {
    evidence_bundles: [{ evidence_class: 'built-artifact' }],
    evidence_coverage: {
      cells: [{
        lens: 'cloud-and-iac',
        topic: 'container-image-content',
        evidence_class: 'built-artifact',
        state: 'PARTIAL',
        reason: 'the OCI locator index was truncated',
      }],
    },
  }
  assert.equal(acquiredEvidenceHasGaps(attachedTruncated), true)
})

test('every acquired bundle has controller-owned delivery coverage, even with no consumer', () => {
  const bundles = ['model-bundle', 'sbom', 'vex'].map((artifactKind, index) => ({
    evidence_id: `portable-${artifactKind}`,
    evidence_class: 'built-artifact',
    artifact_kind: artifactKind,
    adapter_id: 'artifact',
    coverage_state: 'COVERED',
    root_sha256: String(index + 1).repeat(64),
    analysis_state: 'NOT_ASSESSED',
    analysis_reason: 'no supported complete locator index is available',
  }))
  const coverage = buildEvidenceCoverage({
    lenses: LENSES,
    activatedLenses: ['cloud-and-iac'],
    bundles,
  })

  assert.deepEqual(
    coverage.bundle_coverage.map((record) => ({
      evidence_id: record.evidence_id,
      artifact_kind: record.artifact_kind,
      state: record.state,
      consumer_lenses: record.consumer_lenses,
    })),
    [
      {
        evidence_id: 'portable-model-bundle',
        artifact_kind: 'model-bundle',
        state: 'INVENTORY_ONLY',
        consumer_lenses: [],
      },
      {
        evidence_id: 'portable-sbom',
        artifact_kind: 'sbom',
        state: 'INVENTORY_ONLY',
        consumer_lenses: [],
      },
      {
        evidence_id: 'portable-vex',
        artifact_kind: 'vex',
        state: 'INVENTORY_ONLY',
        consumer_lenses: [],
      },
    ],
  )
  assert.ok(coverage.bundle_coverage.every(({ reason }) =>
    /no lens declares/i.test(reason)))
  assert.equal(acquiredEvidenceHasGaps({
    evidence_bundles: bundles,
    evidence_coverage: coverage,
  }), true)
})

test('positive-only controller analysis stays PARTIAL after delivery', () => {
  const coverage = buildEvidenceCoverage({
    lenses: LENSES,
    activatedLenses: ['cloud-and-iac'],
    bundles: [{
      evidence_id: 'peerstar-api-image',
      evidence_class: 'built-artifact',
      artifact_kind: 'oci-image',
      adapter_id: 'artifact',
      coverage_state: 'COVERED',
      root_sha256: 'a'.repeat(64),
      analysis_state: 'READY',
      analysis_reason: 'controller analysis completed',
    }],
  })

  assert.deepEqual(coverage.bundle_coverage, [{
    evidence_id: 'peerstar-api-image',
    evidence_class: 'built-artifact',
    artifact_kind: 'oci-image',
    root_sha256: 'a'.repeat(64),
    state: 'PARTIAL',
    consumer_lenses: ['cloud-and-iac'],
    reason: 'controller analysis completed; current controller analysis is positive-only, '
      + 'not exhaustive; delivered to cloud-and-iac',
  }])
  assert.equal(acquiredEvidenceHasGaps({
    evidence_bundles: [{ evidence_class: 'built-artifact' }],
    evidence_coverage: coverage,
  }), true)
})

test('NOT_APPLICABLE on an acquired bundle is non-clear bundle coverage', () => {
  const bundle = {
    evidence_id: 'misclassified-image',
    evidence_class: 'built-artifact',
    artifact_kind: 'oci-image',
    adapter_id: 'artifact',
    coverage_state: 'NOT_APPLICABLE',
    root_sha256: 'f'.repeat(64),
    analysis_state: 'READY',
    analysis_reason: 'controller analysis completed',
  }
  const coverage = buildEvidenceCoverage({
    lenses: LENSES,
    activatedLenses: ['cloud-and-iac'],
    bundles: [bundle],
  })

  assert.equal(coverage.bundle_coverage[0].state, 'NOT_ASSESSED')
  assert.match(coverage.bundle_coverage[0].reason, /cannot have NOT_APPLICABLE/)
  assert.equal(
    cell(coverage, 'cloud-and-iac', 'container-image-content', 'built-artifact').state,
    'NOT_ASSESSED',
  )
  assert.equal(acquiredEvidenceHasGaps({
    evidence_bundles: [bundle],
    evidence_coverage: coverage,
  }), true)
})

test('one delivery cannot cover two active declared consumers', () => {
  const peerLens = {
    frontmatter: {
      name: 'container-security',
      owns: ['container-image-peer-review'],
      activates_on: {
        evidence_classes: {
          source: { state: 'not-consumed' },
          'built-artifact': {
            state: 'consumed',
            artifact_kinds: ['oci-image'],
          },
          'deployed-state': { state: 'not-consumed' },
          'live-runtime': { state: 'not-consumed' },
        },
      },
    },
  }
  const bundle = {
    evidence_id: 'shared-image',
    evidence_class: 'built-artifact',
    artifact_kind: 'oci-image',
    coverage_state: 'COVERED',
    root_sha256: '7'.repeat(64),
    analysis_state: 'READY',
    analysis_reason: 'controller analysis completed',
  }
  const coverage = buildEvidenceCoverage({
    lenses: [...LENSES, peerLens],
    activatedLenses: ['cloud-and-iac', 'container-security'],
    bundles: [bundle],
    jobs: [{
      lens: 'cloud-and-iac',
      evidence: [{ evidence_context: { evidence_id: bundle.evidence_id } }],
    }],
  })

  assert.deepEqual(coverage.bundle_coverage[0].consumer_lenses, ['cloud-and-iac'])
  assert.equal(coverage.bundle_coverage[0].state, 'NOT_ASSESSED')
  assert.match(coverage.bundle_coverage[0].reason, /missing container-security/)
  assert.equal(
    cell(coverage, 'cloud-and-iac', 'container-image-content', 'built-artifact').state,
    'PARTIAL',
  )
  assert.equal(
    cell(
      coverage,
      'container-security',
      'container-image-peer-review',
      'built-artifact',
    ).state,
    'NOT_ASSESSED',
  )
})
