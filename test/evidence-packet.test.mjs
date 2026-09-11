import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createArtifactAdapter } from '../scripts/lib/evidence-adapters/artifact.mjs'
import { writeEvidenceBundle } from '../scripts/lib/evidence-bundle.mjs'
import { createRunPlan } from '../scripts/lib/run-engine.mjs'
import { evidenceForLens, readEvidenceIndex } from '../scripts/lib/evidence-packet.mjs'

const adapter = createArtifactAdapter({ clock: () => '2026-08-08T14:22:10Z' })

async function acquiredImage(evidenceId = 'sample-api-image') {
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
    evidence_context: written.profile.evidence_context,
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
  assert.equal(index.rule_analysis.controller_evaluated, true)
  assert.equal(index.rule_analysis.raw_evidence_bytes_delivered, false)
  assert.deepEqual(index.rule_analysis.evaluated_rule_ids, [
    'ev.built-artifact.oci.blob-unreferenced-by-manifest',
    'ev.built-artifact.oci.recursive-encoded-payload',
    'ev.built-artifact.oci.secret-in-config-history',
    'ev.built-artifact.oci.sibling-size-mtime-outlier',
    'ev.built-artifact.oci.whiteout-named-file-with-content',
  ])

  const orphan = index.entries.find(({ kind }) => kind === 'orphan')
  assert.match(orphan.locator, /^orphan\/sha256:/)
  assert.ok(orphan.matched_rule_ids.includes(
    'ev.built-artifact.oci.blob-unreferenced-by-manifest',
  ))

  const history = index.entries.find(({ kind, matched_rule_ids: ruleIds }) =>
    kind === 'config-history'
    && ruleIds.includes('ev.built-artifact.oci.secret-in-config-history'))
  assert.match(history.locator, /^config\/history\[\d+\]$/)
  assert.equal(history.credential_material_detected, true)

  const recursive = index.entries.find(({ matched_rule_ids: ruleIds }) =>
    ruleIds.includes('ev.built-artifact.oci.recursive-encoded-payload'))
  assert.equal(recursive.content_captured, true)
})

test('truncation is reported rather than silently narrowing the denominator', async () => {
  const bundle = await acquiredImage()
  const index = await readEvidenceIndex(bundle.directory, { maxEntriesPerBundle: 3 })
  assert.equal(index.entries.length, 3)
  assert.ok(index.truncated > 0)
})

test('the packet entry cap must remain a finite positive bound', async () => {
  const bundle = await acquiredImage()
  for (const maxEntriesPerBundle of [0, -1, Number.POSITIVE_INFINITY, 1.5]) {
    await assert.rejects(
      () => readEvidenceIndex(bundle.directory, { maxEntriesPerBundle }),
      /positive safe integer/i,
    )
  }
})

test('truncation cannot manufacture a sibling outlier from an ambiguous full baseline', async () => {
  const directory = join(await mkdtemp(join(tmpdir(), 'rta-packet-siblings-')), 'ev')
  const entries = [
    ...Array.from({ length: 4 }, (_, index) => ({
      path: `app/a-${index}.bin`,
      mode: 0o644,
      size: 100,
      mtime: 1,
      type: 'file',
      link_target: '',
      sha256: 'a'.repeat(64),
      whiteout: false,
    })),
    ...Array.from({ length: 4 }, (_, index) => ({
      path: `app/b-${index}.bin`,
      mode: 0o644,
      size: 200,
      mtime: 2,
      type: 'file',
      link_target: '',
      sha256: 'b'.repeat(64),
      whiteout: false,
    })),
  ]
  const written = await writeEvidenceBundle({
    directory,
    profile: {
      schema: 'evidence-bundle-v1',
      evidence_context: {
        evidence_id: 'ambiguous-siblings',
        evidence_class: 'built-artifact',
        adapter_id: 'artifact',
        target_identity: `sha256:${'c'.repeat(64)}`,
        acquisition_mode: 'offline-export',
        acquired_on: '2026-08-08T14:22:10Z',
        detection_evidence: ['synthetic ambiguous sibling baseline'],
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
    payload: [
      {
        path: 'normalized.json',
        bytes: Buffer.from(JSON.stringify({
          format: 'oci-layout',
          config_digest: null,
          diff_ids: [],
          layers: [{
            index: 0,
            directory: '00',
            digest: `sha256:${'d'.repeat(64)}`,
            media_type: 'application/vnd.oci.image.layer.v1.tar',
            entry_count: entries.length,
          }],
          gaps: [],
        })),
      },
      { path: 'config/history.json', bytes: Buffer.from('[]') },
      { path: 'orphan-blobs.json', bytes: Buffer.from('[]') },
      { path: 'layers/00/entries.json', bytes: Buffer.from(JSON.stringify(entries)) },
    ],
  })
  const index = await readEvidenceIndex(written.directory, { maxEntriesPerBundle: 5 })
  assert.equal(index.truncated, 3)
  assert.equal(index.entries.length, 5)
  assert.ok(index.entries.every(({ matched_rule_ids: ids }) =>
    !ids.includes('ev.built-artifact.oci.sibling-size-mtime-outlier')))

  const [authority] = evidenceForLens(
    'cloud-and-iac',
    new Map([['cloud-and-iac', {
      'built-artifact': {
        state: 'consumed',
        artifact_kinds: ['oci-image'],
        may_conclude: ['unexpected-artifact-content'],
      },
    }]]),
    [{
      evidence_context: written.profile.evidence_context,
      artifact_kind: 'oci-image',
      evidence_class: 'built-artifact',
      root_sha256: written.root_sha256,
      index,
    }],
  )
  assert.deepEqual(authority.required_matches, [])
})

test('a lens is handed a bundle only where it declares the class and kind', async () => {
  const bundle = await acquiredImage()
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
  const bundle = await acquiredImage()
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
  assert.deepEqual(withEvidence[0].evidence_ids, ['sample-api-image'])

  const requiredCounts = Object.fromEntries(lenses.map((lens) => {
    const sidecar = plan.jobSidecars.find((candidate) =>
      candidate.lens === lens && candidate.evidence?.length > 0)
    return [lens, sidecar.evidence[0].required_matches.length]
  }))
  assert.deepEqual(requiredCounts, {
    'cicd-and-supply-chain': 0,
    'cloud-and-iac': 4,
    'crypto-and-key-management': 1,
    'hipaa-and-phi': 0,
  })
})

test('bundle-global evidence obligations are delivered once when source is sharded', async () => {
  const root = await repositoryWithADockerfile()
  await writeFile(join(root, 'deploy', 'one.tf'), 'resource "x" "one" {}\n', 'utf8')
  await writeFile(join(root, 'deploy', 'two.tf'), 'resource "x" "two" {}\n', 'utf8')
  const plan = await createRunPlan({
    targetRoot: root,
    evidenceBundles: [await acquiredImage()],
    shardOptions: { maxFiles: 1, maxBytes: 1024 * 1024 },
  })
  const cloudJobs = plan.run.jobs.filter(
    ({ lens, closure_round: round }) => lens === 'cloud-and-iac' && round === undefined,
  )
  assert.ok(cloudJobs.length > 1)
  const [evidenceParent] = cloudJobs.filter(
    ({ evidence_ids: evidenceIds = [] }) => evidenceIds.length > 0,
  )
  assert.equal(
    cloudJobs.filter(({ evidence_ids: evidenceIds = [] }) => evidenceIds.length > 0).length,
    1,
  )
  assert.equal(
    plan.jobSidecars.filter(({ lens, evidence, closure_round: round }) =>
      lens === 'cloud-and-iac' && round === undefined && evidence?.length > 0).length,
    1,
  )
  const retryCarriers = plan.jobSidecars.filter(
    ({ parent_job_id: parentId }) => parentId === evidenceParent.job_id,
  )
  assert.ok(retryCarriers.length > 0)
  assert.ok(retryCarriers.every(({ evidence }) => evidence?.length === 1))
  assert.ok(plan.jobSidecars
    .filter(({ lens, parent_job_id: parentId }) =>
      lens === 'cloud-and-iac'
      && parentId !== undefined
      && parentId !== evidenceParent.job_id)
    .every(({ evidence }) => evidence === undefined))
})

test('the sealed control snapshot delivers shared lens contracts and adapters', async () => {
  const plan = await createRunPlan({
    targetRoot: await repositoryWithADockerfile(),
  })
  const paths = new Set(plan.sealedSnapshots.control.index.files.map(({ path }) => path))

  for (const required of [
    'lenses/_schema.md',
    'lenses/_harness.md',
    'lenses/_topics.md',
  ]) {
    assert.equal(paths.has(required), true, `${required} was not sealed for providers`)
  }
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

test('planning rejects duplicate evidence identities before emitting an ambiguous run', async () => {
  const first = await acquiredImage()
  const second = await acquiredImage()
  await assert.rejects(
    createRunPlan({
      targetRoot: await repositoryWithADockerfile(),
      evidenceBundles: [first, second],
    }),
    /evidence_id must be unique within a run: sample-api-image/,
  )

  const { directory: _directory, ...portableDuplicate } = structuredClone(second)
  await assert.rejects(
    createRunPlan({
      targetRoot: await repositoryWithADockerfile(),
      evidenceBundles: [first, portableDuplicate],
    }),
    /evidence_id must be unique within a run: sample-api-image/,
  )
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
