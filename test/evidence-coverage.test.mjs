import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
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
