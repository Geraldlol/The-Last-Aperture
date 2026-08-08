import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  EvidenceBundleError,
  evidenceBundleRootDigest,
  loadEvidenceBundle,
  readEvidenceBundle,
  readEvidencePayloadFile,
  verifyEvidenceBundle,
  writeEvidenceBundle,
} from '../scripts/lib/evidence-bundle.mjs'

const PAYLOAD = [
  { path: 'layers/02/entries.json', bytes: Buffer.from('[{"name":"var/lib/db"}]', 'utf8') },
  { path: 'config/history.json', bytes: Buffer.from('["RUN rm /secret.txt"]', 'utf8') },
]

function baseProfile() {
  return {
    schema: 'evidence-bundle-v1',
    evidence_context: {
      evidence_id: 'peerstar-api-image',
      evidence_class: 'built-artifact',
      adapter_id: 'artifact',
      target_identity: 'sha256:9f2c1d0e4b6a8c3f5e7d9b1a3c5e7f9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c',
      acquisition_mode: 'offline-export',
      acquired_on: '2026-08-08T14:22:10Z',
      detection_evidence: ['shell-in-the-ghost.tar.gz sha256:4aaff082'],
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
  }
}

async function sealedBundle() {
  const directory = join(await mkdtemp(join(tmpdir(), 'rta-evidence-')), 'ev')
  const written = await writeEvidenceBundle({
    directory,
    profile: baseProfile(),
    payload: PAYLOAD,
  })
  return { directory, written }
}

test('writing a bundle content-addresses every payload file', async () => {
  const { directory, written } = await sealedBundle()
  assert.equal(written.directory, directory)
  assert.match(written.root_sha256, /^[0-9a-f]{64}$/)
  assert.deepEqual(
    written.profile.files.map(({ path }) => path),
    ['payload/config/history.json', 'payload/layers/02/entries.json'],
  )
  for (const file of written.profile.files) {
    assert.match(file.sha256, /^[0-9a-f]{64}$/)
    assert.ok(file.size > 0)
  }
})

test('the root digest depends only on path, hash and size, in canonical order', () => {
  const files = [
    { path: 'payload/b.json', sha256: 'b'.repeat(64), size: 2 },
    { path: 'payload/a.json', sha256: 'a'.repeat(64), size: 1 },
  ]
  assert.equal(
    evidenceBundleRootDigest(files),
    evidenceBundleRootDigest([...files].reverse()),
  )
  assert.notEqual(
    evidenceBundleRootDigest(files),
    evidenceBundleRootDigest([{ ...files[0], size: 3 }, files[1]]),
  )
})

test('a sealed bundle round-trips through read and verify', async () => {
  const { directory, written } = await sealedBundle()
  const read = await readEvidenceBundle(directory)
  assert.equal(read.root_sha256, written.root_sha256)
  assert.equal(read.evidence_context.evidence_id, 'peerstar-api-image')
  assert.equal(read.evidence_context.evidence_class, 'built-artifact')

  const verification = await verifyEvidenceBundle(directory)
  assert.deepEqual(verification.errors, [])
  assert.equal(verification.valid, true)

  const bytes = await readEvidencePayloadFile(directory, 'payload/config/history.json')
  assert.equal(bytes.toString('utf8'), '["RUN rm /secret.txt"]')
})

test('one mutated payload byte fails verification and refuses to load', async () => {
  const { directory } = await sealedBundle()
  await writeFile(join(directory, 'payload', 'config', 'history.json'), '["RUN rm /secreT.txt"]')

  const verification = await verifyEvidenceBundle(directory)
  assert.equal(verification.valid, false)
  assert.ok(verification.errors.some((error) => error.code === 'PAYLOAD_DIGEST_MISMATCH'))

  await assert.rejects(
    () => loadEvidenceBundle(directory),
    (error) => error instanceof EvidenceBundleError
      && error.code === 'EVIDENCE_BUNDLE_INVALID',
  )
})

test('a tampered manifest root digest is refused', async () => {
  const { directory } = await sealedBundle()
  const manifestPath = join(directory, 'manifest.json')
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'))
  manifest.root_sha256 = '0'.repeat(64)
  await writeFile(manifestPath, JSON.stringify(manifest))

  const verification = await verifyEvidenceBundle(directory)
  assert.ok(verification.errors.some((error) => error.code === 'ROOT_DIGEST_MISMATCH'))
  await assert.rejects(() => loadEvidenceBundle(directory), EvidenceBundleError)
})

test('a payload file listed in the manifest but absent on disk is refused', async () => {
  const { directory } = await sealedBundle()
  const manifestPath = join(directory, 'manifest.json')
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'))
  manifest.profile.files.push({
    path: 'payload/ghost.json',
    sha256: 'c'.repeat(64),
    size: 3,
  })
  manifest.root_sha256 = evidenceBundleRootDigest(manifest.profile.files)
  await writeFile(manifestPath, JSON.stringify(manifest))

  const verification = await verifyEvidenceBundle(directory)
  assert.ok(verification.errors.some((error) => error.code === 'PAYLOAD_FILE_MISSING'))
})

test('a payload file on disk that the manifest never listed is refused', async () => {
  const { directory } = await sealedBundle()
  await writeFile(join(directory, 'payload', 'smuggled.json'), '{}')
  const verification = await verifyEvidenceBundle(directory)
  assert.ok(verification.errors.some((error) => error.code === 'UNDECLARED_PAYLOAD_FILE'))
})

test('a payload path escaping the bundle is refused at write time', async () => {
  const directory = join(await mkdtemp(join(tmpdir(), 'rta-evidence-')), 'ev')
  await assert.rejects(
    () => writeEvidenceBundle({
      directory,
      profile: baseProfile(),
      payload: [{ path: '../escape.json', bytes: Buffer.from('{}') }],
    }),
    EvidenceBundleError,
  )
})

test('loadEvidenceBundle returns the immutable routing projection', async () => {
  const { directory, written } = await sealedBundle()
  const loaded = await loadEvidenceBundle(directory)
  assert.equal(loaded.root_sha256, written.root_sha256)
  assert.deepEqual(Object.keys(loaded.evidence_context).sort(), [
    'acquired_on',
    'acquisition_mode',
    'adapter_id',
    'confidence',
    'detection_evidence',
    'evidence_class',
    'evidence_id',
    'target_identity',
  ])
  assert.throws(() => {
    loaded.evidence_context.evidence_id = 'mutated'
  }, TypeError)
})
