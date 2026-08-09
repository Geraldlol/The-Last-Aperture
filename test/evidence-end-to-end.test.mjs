import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createArtifactAdapter } from '../scripts/lib/evidence-adapters/artifact.mjs'
import { createRunPlan } from '../scripts/lib/run-engine.mjs'
import { renderMarkdownReport } from '../scripts/lib/report.mjs'
import { assertValidFinding, validateFinding } from '../scripts/lib/contracts.mjs'

const adapter = createArtifactAdapter({ clock: () => '2026-08-08T14:22:10Z' })

async function acquiredImage() {
  const out = join(await mkdtemp(join(tmpdir(), 'rta-e2e-')), 'ev')
  const planned = await adapter.plan({
    evidence_id: 'peerstar-api-image',
    source_path: 'test/fixtures/evidence/vulnerable-image.tar',
    target_class: 'LAB',
    phi_scope: 'none',
  })
  const written = await adapter.run(planned, { out })
  return {
    evidence_id: 'peerstar-api-image',
    evidence_class: 'built-artifact',
    adapter_id: 'artifact',
    artifact_kind: 'oci-image',
    coverage_state: 'COVERED',
    phi_bearing: false,
    root_sha256: written.root_sha256,
    directory: written.directory,
  }
}

async function repository() {
  const root = await mkdtemp(join(tmpdir(), 'rta-e2e-repo-'))
  await writeFile(
    join(root, 'Dockerfile'),
    'FROM node:20-alpine\nCOPY secret.txt /secret.txt\nRUN rm /secret.txt\n',
    'utf8',
  )
  return root
}

// The finding an auditor writes from what the packet hands them: the whiteout
// impostor, cited by its locator, asserting a claim cloud-and-iac declares.
function whiteoutFinding(overrides = {}) {
  return {
    candidate_id: 'container-image-content:5c1a7f30',
    lens: 'cloud-and-iac',
    topic: 'container-image-content',
    title: 'A file named as a whiteout carries content in the upper layer',
    claimed_impact_severity: 'High',
    location: ['peerstar-api-image:layer/01/.wh.audit-log.txt'],
    evidence: 'not actually a whiteout',
    attack: 'Extract layer 01 and read the entry the whiteout convention hides',
    impact: 'Content the image presents as deleted is readable',
    reachable_from: 'anyone who can pull the image',
    confidence: 'High',
    proof_plan: 'Read the entry from the sealed bundle at the cited locator',
    evidence_claim: 'unexpected-artifact-content',
    evidence_context: {
      evidence_id: 'peerstar-api-image',
      evidence_class: 'built-artifact',
      adapter_id: 'artifact',
      target_identity: 'sha256:9f2c',
      acquisition_mode: 'offline-export',
      acquired_on: '2026-08-08T14:22:10Z',
      detection_evidence: ['vulnerable-image.tar sha256:bcea0007'],
      confidence: 'high',
    },
    ...overrides,
  }
}

async function plannedRun() {
  return createRunPlan({
    targetRoot: await repository(),
    evidenceBundles: [await acquiredImage()],
  })
}

test('the run records the declarations ingest needs to enforce invariant 16', async () => {
  const { run } = await plannedRun()
  const declared = run.evidence_declarations['cloud-and-iac']
  assert.equal(declared['built-artifact'].state, 'consumed')
  assert.deepEqual(declared['built-artifact'].may_conclude, [
    'secret-present-in-artifact',
    'unexpected-artifact-content',
  ])
  // Without this the enforcement has no inputs and silently passes everything.
  assert.equal(run.evidence_declarations['threat-modeling']['built-artifact'].state, 'not-consumed')
})

test('a well-formed evidence finding passes the enforced contract', async () => {
  const { run } = await plannedRun()
  const evidence = {
    declarations: new Map(Object.entries(run.evidence_declarations)),
    coverage: new Map(run.evidence_coverage.cells.map((cell) => [
      `${cell.lens}\0${cell.topic}\0${cell.evidence_class}`,
      cell.state,
    ])),
  }
  assert.deepEqual(validateFinding(whiteoutFinding(), { evidence }).errors, [])
  assert.doesNotThrow(() => assertValidFinding(whiteoutFinding(), { stage: 1, evidence }))
})

test('the enforced contract rejects a claim the lens may not make', async () => {
  const { run } = await plannedRun()
  const evidence = {
    declarations: new Map(Object.entries(run.evidence_declarations)),
    coverage: new Map(run.evidence_coverage.cells.map((cell) => [
      `${cell.lens}\0${cell.topic}\0${cell.evidence_class}`,
      cell.state,
    ])),
  }
  const errors = validateFinding(
    whiteoutFinding({ evidence_claim: 'sensitive-data-at-rest' }),
    { evidence },
  ).errors
  assert.ok(errors.some((error) => error.code === 'EVIDENCE_CLAIM_OUT_OF_BOUNDS'))
})

test('the enforced contract rejects a lens concluding from a class it does not consume', async () => {
  const { run } = await plannedRun()
  const evidence = {
    declarations: new Map(Object.entries(run.evidence_declarations)),
    coverage: new Map(),
  }
  const errors = validateFinding(
    whiteoutFinding({ lens: 'threat-modeling', topic: 'threat-model-completeness' }),
    { evidence },
  ).errors
  assert.ok(errors.some((error) => error.code === 'EVIDENCE_CLASS_NOT_CONSUMED'))
})

test('a claim resting on unacquired coverage is capped, not reported at High', async () => {
  const { run } = await plannedRun()
  const evidence = {
    declarations: new Map(Object.entries(run.evidence_declarations)),
    // The same finding, in a run where that class was never acquired.
    coverage: new Map([
      ['cloud-and-iac\0container-image-content\0built-artifact', 'NOT_ASSESSED'],
    ]),
  }
  const errors = validateFinding(
    whiteoutFinding({
      effective_severity: 'High',
      triage_disposition: 'queued',
      verification_status: 'CONFIRMED',
    }),
    { evidence },
  ).errors
  assert.ok(errors.some((error) => error.code === 'EVIDENCE_COVERAGE_SEVERITY_CAP'))
  assert.ok(errors.some((error) => error.code === 'EVIDENCE_COVERAGE_UNPROVEN'))
})

test('the whole chain holds: acquire, attach, activate, cite, report', async () => {
  const bundle = await acquiredImage()
  const { run } = await createRunPlan({
    targetRoot: await repository(),
    evidenceBundles: [bundle],
  })

  // Acquired and attached.
  assert.equal(run.evidence_bundles[0].evidence_id, 'peerstar-api-image')
  assert.equal(run.evidence_bundles[0].coverage_state, 'COVERED')

  // Handed to a lens that declared it can read it.
  const job = run.jobs.find((entry) =>
    entry.lens === 'cloud-and-iac' && (entry.evidence_ids ?? []).length > 0)
  assert.ok(job, 'cloud-and-iac must receive the image')
  assert.deepEqual(job.evidence_ids, ['peerstar-api-image'])

  // Coverage lifted for the class supplied, and honest about the one that was not.
  const artifactCells = run.evidence_coverage.cells.filter((cell) =>
    cell.lens === 'cloud-and-iac' && cell.evidence_class === 'built-artifact')
  assert.ok(artifactCells.every(({ state }) => state === 'COVERED'))
  assert.ok(run.evidence_coverage.summary.unreached_classes.includes('deployed-state'))

  // A finding citing that evidence validates under the enforced contract.
  const evidence = {
    declarations: new Map(Object.entries(run.evidence_declarations)),
    coverage: new Map(run.evidence_coverage.cells.map((cell) => [
      `${cell.lens}\0${cell.topic}\0${cell.evidence_class}`,
      cell.state,
    ])),
  }
  assert.deepEqual(validateFinding(whiteoutFinding(), { evidence }).errors, [])

  // And the report shows the acquired evidence rather than a blind spot.
  const report = renderMarkdownReport({ ...run, findings: [whiteoutFinding()] })
  const section = report.slice(report.indexOf('### Evidence-class coverage'))
  assert.match(section, /peerstar-api-image/)
  assert.match(section, /deployed-state.*NOT_ASSESSED|NOT_ASSESSED.*deployed-state/s)
})

test('the sealed packet a provider receives carries the evidence, not just the run', async () => {
  const bundle = await acquiredImage()
  const plan = await createRunPlan({
    targetRoot: await repository(),
    evidenceBundles: [bundle],
  })
  const job = plan.run.jobs.find((entry) =>
    entry.lens === 'cloud-and-iac' && (entry.evidence_ids ?? []).length > 0)
  const sidecar = plan.jobSidecars.find((entry) => entry.job_id === job.job_id)

  // The sidecar is what `next` hands a provider. Carrying evidence on the
  // activation job and the run job alone left the lens unable to see it, which
  // is the entire point of having acquired it.
  assert.ok(Array.isArray(sidecar.evidence), 'the sealed packet must carry the evidence')
  const [evidence] = sidecar.evidence
  assert.equal(evidence.evidence_context.evidence_id, 'peerstar-api-image')
  assert.deepEqual(evidence.may_conclude, [
    'secret-present-in-artifact',
    'unexpected-artifact-content',
  ])

  // The discriminator the motivating incident turned on, in the packet: an
  // entry named as a whiteout that carries content.
  const impostor = evidence.entries.find(({ path }) => path === '.wh.audit-log.txt')
  assert.equal(impostor.locator, 'layer/01/.wh.audit-log.txt')
  assert.equal(impostor.whiteout, false)
  assert.ok(impostor.size > 0)
  const genuine = evidence.entries.find(({ path }) => path === '.wh.build-secret.txt')
  assert.equal(genuine.whiteout, true)
  assert.equal(genuine.size, 0)
})
