import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createRunPlan } from '../scripts/lib/run-engine.mjs'
import { renderMarkdownReport } from '../scripts/lib/report.mjs'
import { writeEvidenceBundle } from '../scripts/lib/evidence-bundle.mjs'

const CLEARANCE_LANGUAGE = /\b(?:no findings|clean|secure|passed|no issues)\b/i

async function repositoryWithADockerfile() {
  const root = await mkdtemp(join(tmpdir(), 'rta-false-clearance-'))
  await mkdir(join(root, 'deploy'), { recursive: true })
  await writeFile(
    join(root, 'Dockerfile'),
    'FROM node:20-alpine\nCOPY secret.txt /secret.txt\nRUN rm /secret.txt\n',
    'utf8',
  )
  await writeFile(join(root, 'deploy', 'app.yaml'), 'kind: Deployment\n', 'utf8')
  return root
}

test('an audit with no evidence bundle reports built-artifact as NOT_ASSESSED with a reason', async () => {
  const plan = await createRunPlan({ targetRoot: await repositoryWithADockerfile() })
  const cells = plan.run.evidence_coverage.cells.filter(
    (cell) => cell.lens === 'cloud-and-iac' && cell.evidence_class === 'built-artifact',
  )
  assert.ok(cells.length > 0, 'cloud-and-iac must contribute built-artifact cells')
  for (const cell of cells) {
    assert.equal(cell.state, 'NOT_ASSESSED')
    assert.match(cell.reason, /no built-artifact evidence was acquired/)
  }
  assert.ok(plan.run.evidence_coverage.summary.unreached_classes.includes('built-artifact'))
})

test('the report never renders an unreached class as clean', async () => {
  const plan = await createRunPlan({ targetRoot: await repositoryWithADockerfile() })
  const report = renderMarkdownReport(plan.run)
  const section = report.slice(report.indexOf('### Evidence-class coverage'))
  const table = section.slice(0, section.indexOf('\n\n', section.indexOf('|---')))
  for (const line of table.split('\n')) {
    if (!line.includes('NOT_ASSESSED') && !line.includes('INVENTORY_ONLY')) continue
    assert.equal(
      CLEARANCE_LANGUAGE.test(line),
      false,
      `an unassessed class must not read as a clearance: ${line}`,
    )
  }
  assert.match(section, /not a clearance/)
})

test('the Dockerfile whiteout case is the one this encodes', async () => {
  // COPY secret.txt / RUN rm /secret.txt reads as a removal in source and is
  // not one in the image. Before this matrix existed the run said nothing at
  // all about the image, and saying nothing is what read as clearance.
  const plan = await createRunPlan({ targetRoot: await repositoryWithADockerfile() })
  assert.ok(plan.run.activated_lenses.includes('cloud-and-iac'))
  assert.equal(plan.run.evidence_coverage.summary.bundle_count, 0)
  assert.ok(plan.run.evidence_coverage.summary.not_assessed_cell_count > 0)
})

test('supplying a covering bundle lifts exactly the class it covers', async () => {
  const bundleDirectory = join(await mkdtemp(join(tmpdir(), 'rta-ev-')), 'ev')
  const bundle = await writeEvidenceBundle({
    directory: bundleDirectory,
    profile: {
      schema: 'evidence-bundle-v1',
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
      target_class: 'LAB',
      phi_scope: 'none',
      phi_bearing: false,
      adapter_version: '1.0.0',
      contract_version: 1,
      coverage_state: 'COVERED',
      artifact_kind: 'oci-image',
      attestation: null,
      coverage_gaps: [],
    },
    payload: [{ path: 'layers/02/entries.json', bytes: Buffer.from('[]', 'utf8') }],
  })

  const plan = await createRunPlan({
    targetRoot: await repositoryWithADockerfile(),
    evidenceBundles: [{
      evidence_id: 'peerstar-api-image',
      evidence_class: 'built-artifact',
      adapter_id: 'artifact',
      artifact_kind: 'oci-image',
      coverage_state: 'COVERED',
      phi_bearing: false,
      root_sha256: bundle.root_sha256,
    }],
  })

  const artifact = plan.run.evidence_coverage.cells.filter(
    (cell) => cell.lens === 'cloud-and-iac' && cell.evidence_class === 'built-artifact',
  )
  for (const cell of artifact) assert.equal(cell.state, 'COVERED')

  // deployed-state was not supplied and must stay unreached.
  assert.ok(plan.run.evidence_coverage.summary.unreached_classes.includes('deployed-state'))
  assert.equal(
    plan.run.evidence_coverage.summary.unreached_classes.includes('built-artifact'),
    false,
  )
})
