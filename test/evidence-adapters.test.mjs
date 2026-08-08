import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import {
  EVIDENCE_ADAPTER_MANIFEST_URL,
  declaredEvidenceRuleAnchors,
  evidenceAdapterIds,
  evidenceAdapterManifest,
  evidenceRuleIdErrors,
  resolveEvidenceAdapter,
} from '../scripts/lib/evidence-adapters.mjs'
import {
  EVIDENCE_CLAIM_KINDS,
  EVIDENCE_CLASS_ORDER,
  evidenceClassAuthorizationFloor,
} from '../scripts/lib/evidence-classes.mjs'

const CONTRACT_PATH = fileURLToPath(
  new URL('../skills/red-team-audit/lenses/_evidence-adapters/contract.md', import.meta.url),
)

test('four adapters plus the inventory-only fallback are declared', () => {
  assert.deepEqual(evidenceAdapterIds(), [
    'artifact',
    'deployed',
    'inventory-only',
    'registry',
    'runtime',
  ])
})

test('each adapter routes to its class and its own document', () => {
  assert.equal(resolveEvidenceAdapter('artifact').evidence_class, 'built-artifact')
  assert.equal(resolveEvidenceAdapter('registry').evidence_class, 'built-artifact')
  assert.equal(resolveEvidenceAdapter('deployed').evidence_class, 'deployed-state')
  assert.equal(resolveEvidenceAdapter('runtime').evidence_class, 'live-runtime')
  assert.equal(resolveEvidenceAdapter('artifact').selection_status, 'SELECTED')
})

test('an unlisted acquisition target selects inventory-only rather than an invented adapter', () => {
  const decision = resolveEvidenceAdapter('helm-chart-museum')
  assert.equal(decision.adapter_id, 'inventory-only')
  assert.equal(decision.selection_status, 'INVENTORY_ONLY')
  assert.equal(decision.adapter_file, 'contract.md')
})

test('no adapter declares authorization below its class floor', () => {
  for (const adapterId of evidenceAdapterIds()) {
    const adapter = resolveEvidenceAdapter(adapterId)
    if (adapter.selection_status !== 'SELECTED') continue
    const floor = evidenceClassAuthorizationFloor(adapter.evidence_class)
    for (const [requirement, required] of Object.entries(floor)) {
      if (!required) continue
      assert.equal(
        adapter.authorization[requirement],
        true,
        `${adapterId} must require ${requirement}`,
      )
    }
  }
})

test('registry acquisition requires a sealed credential reference and attestation', () => {
  const registry = resolveEvidenceAdapter('registry')
  assert.equal(registry.authorization.credential_ref, true)
  assert.equal(registry.authorization.attestation, true)
  assert.equal(resolveEvidenceAdapter('artifact').authorization.attestation, false)
})

test('rule IDs follow the ev namespace and reject a version, severity or line number', () => {
  assert.deepEqual(
    evidenceRuleIdErrors('ev.built-artifact.oci.whiteout-named-file-with-content', {
      adapterId: 'oci',
    }),
    [],
  )
  assert.ok(evidenceRuleIdErrors('db.authorization.postgresql.rls', { adapterId: 'oci' }).length)
  assert.ok(evidenceRuleIdErrors('ev.built-artifact.oci.rule-v2', { adapterId: 'oci' }).length)
  assert.ok(evidenceRuleIdErrors('ev.built-artifact.oci.High-Severity', { adapterId: 'oci' }).length)
  assert.ok(evidenceRuleIdErrors('ev.exploitation.oci.pop-shell', { adapterId: 'oci' }).length)
  assert.ok(
    evidenceRuleIdErrors('ev.built-artifact.registry.thing', { adapterId: 'oci' }).length,
    'the adapter segment must be the selected adapter',
  )
})

test('the contract document declares the canonical vocabulary it claims to own', () => {
  const contract = readFileSync(CONTRACT_PATH, 'utf8')
  for (const evidenceClass of EVIDENCE_CLASS_ORDER) {
    assert.ok(contract.includes(`\`${evidenceClass}\``), `contract must name ${evidenceClass}`)
  }
  for (const claim of EVIDENCE_CLAIM_KINDS) {
    assert.ok(contract.includes(`\`${claim}\``), `contract must name ${claim}`)
  }
  assert.ok(contract.includes('Contract version: `1`'))
  assert.match(contract, /Verified: `\d{4}-\d{2}-\d{2}`/)
})

test('a rule anchor is recognised only where the contract declares it', () => {
  const anchors = declaredEvidenceRuleAnchors(readFileSync(CONTRACT_PATH, 'utf8'))
  assert.equal(anchors.has('ev.built-artifact.oci.whiteout-named-file-with-content'), false)
  assert.ok(
    declaredEvidenceRuleAnchors('### `ev.built-artifact.oci.blob-unreferenced-by-manifest`\n')
      .has('ev.built-artifact.oci.blob-unreferenced-by-manifest'),
  )
})

const ARTIFACT_DOC = fileURLToPath(
  new URL('../skills/red-team-audit/lenses/_evidence-adapters/artifact.md', import.meta.url),
)

test('the artifact adapter document declares its five rule anchors', () => {
  const anchors = declaredEvidenceRuleAnchors(readFileSync(ARTIFACT_DOC, 'utf8'))
  assert.deepEqual([...anchors].sort(), [
    'ev.built-artifact.oci.blob-unreferenced-by-manifest',
    'ev.built-artifact.oci.recursive-encoded-payload',
    'ev.built-artifact.oci.secret-in-config-history',
    'ev.built-artifact.oci.sibling-size-mtime-outlier',
    'ev.built-artifact.oci.whiteout-named-file-with-content',
  ])
})

test('every declared anchor is a well-formed rule ID for this adapter', () => {
  for (const anchor of declaredEvidenceRuleAnchors(readFileSync(ARTIFACT_DOC, 'utf8'))) {
    assert.deepEqual(evidenceRuleIdErrors(anchor, { adapterId: 'oci' }), [], anchor)
  }
})

test('the adapter document names every locator form the resolver supports', () => {
  const doc = readFileSync(ARTIFACT_DOC, 'utf8')
  assert.match(doc, /layer\/NN\//)
  assert.match(doc, /config\/history\[N\]/)
  assert.match(doc, /orphan\//)
})

test('the manifest file is the one the module reads', () => {
  const onDisk = JSON.parse(readFileSync(fileURLToPath(EVIDENCE_ADAPTER_MANIFEST_URL), 'utf8'))
  assert.deepEqual(onDisk, evidenceAdapterManifest)
})
