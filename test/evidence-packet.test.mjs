import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createArtifactAdapter } from '../scripts/lib/evidence-adapters/artifact.mjs'
import { createRunPlan } from '../scripts/lib/run-engine.mjs'
import { evidenceForLens, readEvidenceIndex } from '../scripts/lib/evidence-packet.mjs'

const adapter = createArtifactAdapter({ clock: () => '2026-08-08T14:22:10Z' })

async function acquiredImage(evidenceId = 'peerstar-api-image') {
  const out = join(await mkdtemp(join(tmpdir(), 'rta-packet-')), 'ev')
  const planned = await adapter.plan({
    evidence_id: evidenceId,
    source_path: 'test/fixtures/evidence/vulnerable-image.tar',
    target_class: 'LAB',
    phi_scope: 'none',
  })
  const written = await adapter.run(planned, { out })
  return {
    evidence_id: evidenceId,
    evidence_class: 'built-artifact',
    adapter_id: 'artifact',
    artifact_kind: 'oci-image',
    coverage_state: 'COVERED',
    phi_bearing: false,
    root_sha256: written.root_sha256,
    directory: written.directory,
  }
}

async function repositoryWithADockerfile() {
  const root = await mkdtemp(join(tmpdir(), 'rta-packet-repo-'))
  await mkdir(join(root, 'deploy'), { recursive: true })
  await writeFile(
    join(root, 'Dockerfile'),
    'FROM node:20-alpine\nCOPY secret.txt /secret.txt\nRUN rm /secret.txt\n',
    'utf8',
  )
  return root
}

test('the entry index carries what a lens reasons over, keyed by locator', async () => {
  const bundle = await acquiredImage()
  const index = await readEvidenceIndex(bundle.directory)
  assert.equal(index.unreadable, false)
  assert.equal(index.layers.length, 2)

  const whiteout = index.entries.find(({ path }) => path === '.wh.build-secret.txt')
  const impostor = index.entries.find(({ path }) => path === '.wh.audit-log.txt')
  assert.equal(whiteout.whiteout, true)
  assert.equal(impostor.whiteout, false)
  // The locator is the exact string a finding cites, so a lens never has to
  // construct one.
  assert.equal(whiteout.locator, 'layer/01/.wh.build-secret.txt')
  const secret = index.entries.find(({ path }) => path === 'build-secret.txt')
  assert.equal(secret.locator, 'layer/00/build-secret.txt')
  assert.equal(secret.mode, 0o600)
})

test('truncation is reported rather than silently narrowing the denominator', async () => {
  const bundle = await acquiredImage()
  const index = await readEvidenceIndex(bundle.directory, { maxEntriesPerBundle: 3 })
  assert.equal(index.entries.length, 3)
  assert.ok(index.truncated > 0)
})

test('a lens is handed a bundle only where it declares the class and kind', async () => {
  const bundle = { ...(await acquiredImage()), evidence_context: { evidence_id: 'peerstar-api-image' } }
  const declarations = new Map([
    ['cloud-and-iac', {
      'built-artifact': {
        state: 'consumed',
        artifact_kinds: ['oci-image'],
        may_conclude: ['secret-present-in-artifact'],
      },
    }],
    ['mobile-app-security', {
      'built-artifact': {
        state: 'consumed',
        artifact_kinds: ['apk', 'ipa'],
        may_conclude: ['secret-present-in-artifact'],
      },
    }],
    ['threat-modeling', { 'built-artifact': { state: 'not-consumed' } }],
  ])

  assert.equal(evidenceForLens('cloud-and-iac', declarations, [bundle]).length, 1)
  // Declares built-artifact, but has no rule for an oci-image. Handing it one
  // and leaving it to improvise is what INVENTORY_ONLY records instead.
  assert.equal(evidenceForLens('mobile-app-security', declarations, [bundle]).length, 0)
  assert.equal(evidenceForLens('threat-modeling', declarations, [bundle]).length, 0)
  assert.equal(evidenceForLens('no-such-lens', declarations, [bundle]).length, 0)
})

test('the packet carries may_conclude, so a lens knows what it may assert', async () => {
  const bundle = { ...(await acquiredImage()), evidence_context: { evidence_id: 'peerstar-api-image' } }
  const declarations = new Map([['cloud-and-iac', {
    'built-artifact': {
      state: 'consumed',
      artifact_kinds: ['oci-image'],
      may_conclude: ['secret-present-in-artifact', 'unexpected-artifact-content'],
    },
  }]])
  const [evidence] = evidenceForLens('cloud-and-iac', declarations, [bundle])
  assert.deepEqual(evidence.may_conclude, [
    'secret-present-in-artifact',
    'unexpected-artifact-content',
  ])
})

test('a planned run hands the image to exactly the lenses that declare its kind', async () => {
  const bundle = await acquiredImage()
  const plan = await createRunPlan({
    targetRoot: await repositoryWithADockerfile(),
    evidenceBundles: [bundle],
  })

  const withEvidence = plan.run.jobs.filter((job) => (job.evidence_ids ?? []).length > 0)
  const lenses = [...new Set(withEvidence.map(({ lens }) => lens))].sort()
  // The four lenses that declare oci-image in artifact_kinds, and no others.
  assert.deepEqual(lenses, [
    'cicd-and-supply-chain',
    'cloud-and-iac',
    'crypto-and-key-management',
    'hipaa-and-phi',
  ])
  // The discriminating cases: declares built-artifact but only apk/ipa, and
  // declares nothing at all.
  assert.equal(lenses.includes('mobile-app-security'), false)
  assert.equal(lenses.includes('threat-modeling'), false)
  assert.deepEqual(withEvidence[0].evidence_ids, ['peerstar-api-image'])
})

test('the local bundle directory never enters run.json', async () => {
  const bundle = await acquiredImage()
  const plan = await createRunPlan({
    targetRoot: await repositoryWithADockerfile(),
    evidenceBundles: [bundle],
  })
  // run.json is portable and attested; an absolute local path in it would be
  // neither.
  assert.equal(JSON.stringify(plan.run).includes(bundle.directory.replaceAll('\\', '\\\\')), false)
  assert.equal(Object.hasOwn(plan.run.evidence_bundles[0], 'directory'), false)
  assert.equal(plan.run.evidence_bundles[0].root_sha256, bundle.root_sha256)
})

test('evidence alone activates a lens whose repository globs matched nothing', async () => {
  const empty = await mkdtemp(join(tmpdir(), 'rta-packet-empty-'))
  await writeFile(join(empty, 'notes.txt'), 'no infrastructure here\n', 'utf8')
  const plan = await createRunPlan({
    targetRoot: empty,
    evidenceBundles: [await acquiredImage()],
  })
  const cloudJobs = plan.run.jobs.filter((job) => job.lens === 'cloud-and-iac')
  assert.ok(cloudJobs.some((job) => (job.evidence_ids ?? []).length > 0))
  // An image acquired for a lens whose globs matched nothing is still evidence
  // that lens owns; skipping it would recreate the silence this dimension
  // exists to remove.
  assert.ok(cloudJobs.some((job) => job.state === 'PENDING'))
})
