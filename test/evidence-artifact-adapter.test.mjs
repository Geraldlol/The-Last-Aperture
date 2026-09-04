import { test } from 'node:test'
import assert from 'node:assert/strict'
import { copyFile, mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createArtifactAdapter } from '../scripts/lib/evidence-adapters/artifact.mjs'
import { readEvidencePayloadFile, verifyEvidenceBundle } from '../scripts/lib/evidence-bundle.mjs'
import { runEvidenceAdapterConformance } from './helpers/evidence-adapter-conformance.mjs'

const FIXTURE = 'test/fixtures/evidence/vulnerable-image.tar'
const adapter = createArtifactAdapter({ clock: () => '2026-08-08T14:22:10Z' })

const REQUEST = {
  evidence_id: 'peerstar-api-image',
  source_path: FIXTURE,
  target_class: 'LAB',
  phi_scope: 'none',
}

// The shared suite, unmodified, against the first real adapter.
runEvidenceAdapterConformance(adapter, { validPlanRequest: REQUEST })

async function acquired() {
  const out = join(await mkdtemp(join(tmpdir(), 'rta-artifact-')), 'ev')
  const planned = await adapter.plan(REQUEST)
  return adapter.run(planned, { out })
}

test('plan seals the target identity by hashing the supplied bytes', async () => {
  const planned = await adapter.plan(REQUEST)
  const bytes = await readFile(FIXTURE)
  assert.match(planned.evidence_context_seed.target_identity, /^sha256:[0-9a-f]{64}$/)
  assert.deepEqual(planned.source_integrity, {
    algorithm: 'sha256',
    sha256: planned.evidence_context_seed.target_identity.slice('sha256:'.length),
    size_bytes: bytes.length,
  })
  assert.equal(planned.evidence_context_seed.acquisition_mode, 'offline-export')
  assert.equal(planned.evidence_context_seed.adapter_id, 'artifact')
  assert.ok(bytes.length > 0)
})

test('plan performs no acquisition and refuses a missing source', async () => {
  await assert.rejects(
    () => adapter.plan({ ...REQUEST, source_path: 'no/such/image.tar' }),
    /not found|ENOENT/i,
  )
})

test('plan refuses remote/device-style paths and sources above its byte cap', async () => {
  await assert.rejects(
    () => adapter.plan({ ...REQUEST, source_path: '\\\\host\\share\\artifact.tar' }),
    (error) => error?.code === 'ARTIFACT_SOURCE_REMOTE_PATH_REFUSED',
  )

  const capped = createArtifactAdapter({ limits: { maxSourceBytes: 8 } })
  await assert.rejects(
    () => capped.plan(REQUEST),
    (error) => error?.code === 'ARTIFACT_SOURCE_TOO_LARGE',
  )
})

test('run rejects a same-size source swap before normalization or evidence output', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'rta-artifact-swap-'))
  const source = join(directory, 'image.tar')
  const out = join(directory, 'evidence')
  await copyFile(FIXTURE, source)
  const planned = await adapter.plan({ ...REQUEST, source_path: source })
  const swapped = Buffer.from(await readFile(source))
  swapped[0] ^= 0xff
  await writeFile(source, swapped)

  await assert.rejects(
    () => adapter.run(planned, { out }),
    (error) => error?.code === 'ARTIFACT_SOURCE_CHANGED_SINCE_PLAN',
  )
  await assert.rejects(() => readFile(join(out, 'manifest.json')), /ENOENT/)
})

test('run writes a verifiable bundle with the layer index in manifest order', async () => {
  const written = await acquired()
  assert.deepEqual((await verifyEvidenceBundle(written.directory)).errors, [])
  assert.equal(written.profile.artifact_kind, 'oci-image')
  assert.equal(written.profile.coverage_state, 'COVERED')

  const normalized = JSON.parse(
    (await readEvidencePayloadFile(written.directory, 'payload/normalized.json')).toString('utf8'),
  )
  assert.equal(normalized.format, 'oci-layout')
  assert.deepEqual(normalized.layers.map(({ index }) => index), [0, 1])
})

test('an entry is addressable by the locator a finding will cite', async () => {
  const written = await acquired()
  const bytes = await readEvidencePayloadFile(
    written.directory,
    'payload/layers/00/content/var/lib/db/sbom/zsh-5.9r7.spdx.json',
  )
  assert.match(bytes.toString('utf8'), /"blob"/)
})

test('per-layer entry listings carry mode, size, mtime and the whiteout verdict', async () => {
  const written = await acquired()
  const entries = JSON.parse(
    (await readEvidencePayloadFile(written.directory, 'payload/layers/01/entries.json'))
      .toString('utf8'),
  )
  const real = entries.find(({ path }) => path === '.wh.build-secret.txt')
  const impostor = entries.find(({ path }) => path === '.wh.audit-log.txt')
  assert.equal(real.whiteout, true)
  assert.equal(real.mode, 0o600)
  assert.equal(impostor.whiteout, false)
})

test('the config history and orphan blobs are carried, not summarised away', async () => {
  const written = await acquired()
  const history = JSON.parse(
    (await readEvidencePayloadFile(written.directory, 'payload/config/history.json'))
      .toString('utf8'),
  )
  assert.equal(history.length, 3)
  const orphans = JSON.parse(
    (await readEvidencePayloadFile(written.directory, 'payload/orphan-blobs.json'))
      .toString('utf8'),
  )
  assert.equal(orphans.length, 1)
})

test('the clean fixture yields COVERED with no gaps', async () => {
  const out = join(await mkdtemp(join(tmpdir(), 'rta-artifact-')), 'ev')
  const planned = await adapter.plan({
    ...REQUEST,
    evidence_id: 'clean-image',
    source_path: 'test/fixtures/evidence/clean-image.tar',
  })
  const written = await adapter.run(planned, { out })
  assert.equal(written.profile.coverage_state, 'COVERED')
  assert.deepEqual(written.profile.coverage_gaps, [])
})

test('an entry above the content cap is listed but not captured, and the omission is named', async () => {
  const capped = createArtifactAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    limits: { maxCapturedEntryBytes: 8 },
  })
  const out = join(await mkdtemp(join(tmpdir(), 'rta-artifact-')), 'ev')
  const planned = await capped.plan(REQUEST)
  const written = await capped.run(planned, { out })
  assert.equal(written.profile.coverage_state, 'PARTIAL')
  assert.ok(written.profile.coverage_gaps.some(({ reason }) => /content cap/i.test(reason)))
})

test('an archive that is neither format is NOT_ASSESSED with a named gap', async () => {
  const out = join(await mkdtemp(join(tmpdir(), 'rta-artifact-')), 'ev')
  const planned = await adapter.plan({
    ...REQUEST,
    evidence_id: 'not-an-image',
    source_path: 'test/fixtures/evidence/not-an-image.txt',
  })
  const written = await adapter.run(planned, { out })
  assert.equal(written.profile.coverage_state, 'NOT_ASSESSED')
  assert.ok(written.profile.coverage_gaps.some(({ reason }) => /neither an OCI layout/i.test(reason)))
})

test('two runs of one sealed plan produce the same bundle root', async () => {
  const first = await acquired()
  const second = await acquired()
  assert.equal(first.root_sha256, second.root_sha256)
})
