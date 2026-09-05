import assert from 'node:assert/strict'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { validateRun } from '../scripts/lib/contracts.mjs'
import { acquiredEvidenceHasGaps } from '../scripts/lib/evidence-coverage.mjs'
import { renderMarkdownReport, renderSarif } from '../scripts/lib/report.mjs'
import { createRunPlan } from '../scripts/lib/run-engine.mjs'

function portableBundle(artifactKind, index) {
  const evidenceId = `portable-${artifactKind}`
  return {
    evidence_id: evidenceId,
    evidence_class: 'built-artifact',
    adapter_id: 'artifact',
    artifact_kind: artifactKind,
    coverage_state: 'COVERED',
    phi_bearing: false,
    root_sha256: String(index + 1).repeat(64),
    evidence_context: {
      evidence_id: evidenceId,
      evidence_class: 'built-artifact',
      adapter_id: 'artifact',
      target_identity: `sha256:${String(index + 4).repeat(64)}`,
      acquisition_mode: 'offline-export',
      acquired_on: '2026-09-04T12:00:00Z',
      detection_evidence: [`portable ${artifactKind} supplied by the operator`],
      confidence: 'high',
    },
  }
}

test('portable model, SBOM, and VEX bundles cannot disappear in a minimal repository', async () => {
  const repository = await mkdtemp(join(tmpdir(), 'rta-unconsumed-evidence-'))
  await writeFile(join(repository, 'README.txt'), 'minimal repository\n', 'utf8')
  const plan = await createRunPlan({
    targetRoot: repository,
    evidenceBundles: [
      portableBundle('model-bundle', 0),
      portableBundle('sbom', 1),
      portableBundle('vex', 2),
    ],
  })

  assert.deepEqual(
    plan.run.evidence_coverage.bundle_coverage.map(
      ({ evidence_id: evidenceId, state, consumer_lenses: consumers }) => ({
        evidence_id: evidenceId,
        state,
        consumers,
      }),
    ),
    [
      { evidence_id: 'portable-model-bundle', state: 'INVENTORY_ONLY', consumers: [] },
      { evidence_id: 'portable-sbom', state: 'INVENTORY_ONLY', consumers: [] },
      { evidence_id: 'portable-vex', state: 'INVENTORY_ONLY', consumers: [] },
    ],
  )
  assert.ok(plan.run.jobs.every(({ evidence_ids: evidenceIds = [] }) =>
    evidenceIds.length === 0))
  assert.equal(acquiredEvidenceHasGaps(plan.run), true)

  const markdown = renderMarkdownReport(plan.run)
  for (const evidenceId of [
    'portable-model-bundle',
    'portable-sbom',
    'portable-vex',
  ]) {
    assert.match(markdown, new RegExp(evidenceId))
  }
  const notifications = renderSarif(plan.run)
    .runs[0].invocations[0].toolExecutionNotifications ?? []
  assert.equal(notifications.filter(({ descriptor }) =>
    descriptor.id.startsWith('evidence-bundle-not-assessed/')).length, 3)

  assert.equal(validateRun(plan.run).valid, true)
  const omittedCoverage = structuredClone(plan.run)
  delete omittedCoverage.evidence_coverage.bundle_coverage
  assert.ok(validateRun(omittedCoverage).errors.some(
    ({ code }) => code === 'EVIDENCE_BUNDLE_COVERAGE_REQUIRED',
  ))

  const falseCoverage = structuredClone(plan.run)
  falseCoverage.evidence_coverage.bundle_coverage[0].state = 'COVERED'
  assert.ok(validateRun(falseCoverage).errors.some(
    ({ code }) => code === 'UNDELIVERED_EVIDENCE_MARKED_COVERED',
  ))

  const partialDelivery = structuredClone(plan.run)
  const activeConsumerLenses = [...new Set(partialDelivery.jobs
    .filter((job) =>
      job.kind === 'LENS'
      && job.closure_round === undefined)
    .map(({ lens }) => lens))]
    .slice(0, 2)
  assert.equal(activeConsumerLenses.length, 2)
  partialDelivery.activated_lenses = [...new Set([
    ...partialDelivery.activated_lenses,
    ...activeConsumerLenses,
  ])]
  const evidenceId = partialDelivery.evidence_bundles[0].evidence_id
  for (const lens of activeConsumerLenses) {
    partialDelivery.evidence_declarations[lens]['built-artifact'] = {
      state: 'consumed',
      artifact_kinds: ['model-bundle'],
    }
  }
  const deliveredJob = partialDelivery.jobs.find((job) =>
    job.kind === 'LENS'
    && job.closure_round === undefined
    && job.lens === activeConsumerLenses[0])
  deliveredJob.evidence_ids = [
    ...new Set([...(deliveredJob.evidence_ids ?? []), evidenceId]),
  ]
  partialDelivery.evidence_coverage.bundle_coverage[0].consumer_lenses = [
    activeConsumerLenses[0],
  ]
  partialDelivery.evidence_coverage.bundle_coverage[0].state = 'NOT_ASSESSED'
  assert.ok(validateRun(partialDelivery).errors.some(
    ({ code, message }) =>
      code === 'EVIDENCE_BUNDLE_DELIVERY_INCOMPLETE'
      && message.includes(activeConsumerLenses[1]),
  ))
})
