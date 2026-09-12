import { test } from 'node:test'
import assert from 'node:assert/strict'
import { writeFileSync } from 'node:fs'
import { access, copyFile, link, mkdir, mkdtemp, readFile, readdir, rm, symlink, truncate, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
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
      evidence_id: 'sample-api-image',
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
  const manifest = JSON.parse(await readFile(join(directory, 'manifest.json'), 'utf8'))
  assert.equal(manifest.schema, 'evidence-bundle-manifest-v2')
  assert.equal(manifest.root_algorithm, 'sha256-canonical-profile-v2')
})

test('a committed legacy file-tuple bundle verifies for migration but cannot load unbound metadata', async () => {
  const directory = join(resolve('test/fixtures/compat/evidence-bundle-v1'))
  const verification = await verifyEvidenceBundle(directory)
  assert.equal(verification.valid, true)
  assert.equal(verification.root_algorithm, 'sha256-file-tuples-v1')
  await assert.rejects(
    () => loadEvidenceBundle(directory),
    (error) => error?.code === 'EVIDENCE_BUNDLE_MIGRATION_REQUIRED',
  )
})

test('the root digest binds canonical profile metadata and ordered file records', () => {
  const files = [
    { path: 'payload/a.json', sha256: 'a'.repeat(64), size: 1 },
    { path: 'payload/b.json', sha256: 'b'.repeat(64), size: 2 },
  ]
  const profile = { ...baseProfile(), files }
  assert.equal(
    evidenceBundleRootDigest(profile),
    evidenceBundleRootDigest({ files, ...baseProfile() }),
  )
  assert.notEqual(
    evidenceBundleRootDigest(profile),
    evidenceBundleRootDigest({ ...profile, coverage_state: 'PARTIAL', coverage_gaps: [{ area: 'x', reason: 'y' }] }),
  )
  assert.notEqual(
    evidenceBundleRootDigest(profile),
    evidenceBundleRootDigest({ ...profile, files: [...files].reverse() }),
  )
})

test('a sealed bundle round-trips through read and verify', async () => {
  const { directory, written } = await sealedBundle()
  const read = await readEvidenceBundle(directory)
  assert.equal(read.root_sha256, written.root_sha256)
  assert.equal(read.evidence_context.evidence_id, 'sample-api-image')
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

test('manifest metadata tampering invalidates the retained bundle root', async () => {
  const { directory, written } = await sealedBundle()
  const manifestPath = join(directory, 'manifest.json')
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'))
  manifest.profile.evidence_context.evidence_id = 'forged-image'
  manifest.profile.evidence_context.confidence = 'low'
  await writeFile(manifestPath, JSON.stringify(manifest))

  const verification = await verifyEvidenceBundle(directory)
  assert.equal(verification.root_sha256, evidenceBundleRootDigest(manifest.profile))
  assert.notEqual(verification.root_sha256, written.root_sha256)
  assert.ok(verification.errors.some((error) => error.code === 'ROOT_DIGEST_MISMATCH'))
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
  manifest.root_sha256 = evidenceBundleRootDigest(manifest.profile)
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

test('portable payload aliases are rejected before any bundle output is published', async () => {
  for (const paths of [
    ['A.txt', 'a.txt'],
    ['name.txt', 'name.txt.'],
    ['safe.txt:stream'],
    ['CON'],
    ['dir/aux.json'],
    ['same.txt', 'same.txt'],
    ['leaf', 'leaf/child.txt'],
  ]) {
    const directory = join(await mkdtemp(join(tmpdir(), 'rta-evidence-portable-')), 'ev')
    await assert.rejects(
      () => writeEvidenceBundle({
        directory,
        profile: baseProfile(),
        payload: paths.map((path) => ({ path, bytes: Buffer.from(path) })),
      }),
      (error) => error instanceof EvidenceBundleError
        && error.code === 'EVIDENCE_PAYLOAD_PATH_INVALID',
    )
    await assert.rejects(() => access(directory))
  }
})

test('a failed publication leaves no partial payload and cleans its staged tree', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'rta-evidence-stage-failure-'))
  const directory = join(parent, 'ev')
  await mkdir(directory)
  await writeFile(join(directory, 'manifest.json'), 'preexisting')
  await assert.rejects(
    () => writeEvidenceBundle({ directory, profile: baseProfile(), payload: PAYLOAD }),
    (error) => error instanceof EvidenceBundleError
      && error.code === 'EVIDENCE_BUNDLE_OUTPUT_UNSAFE',
  )
  assert.equal(await readFile(join(directory, 'manifest.json'), 'utf8'), 'preexisting')
  await assert.rejects(() => access(join(directory, 'payload')))
  assert.deepEqual((await readdir(parent)).filter((name) => name.includes('.evidence-')), [])
})

test('an absent output below a linked ancestor is refused before directories are created', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-evidence-linked-ancestor-'))
  const outside = join(root, 'outside')
  const linked = join(root, 'linked')
  await mkdir(outside)
  try {
    await symlink(outside, linked, process.platform === 'win32' ? 'junction' : 'dir')
  } catch (error) {
    return t.skip(`directory links unavailable: ${error.code}`)
  }
  await assert.rejects(
    () => writeEvidenceBundle({
      directory: join(linked, 'new', 'ev'),
      profile: baseProfile(),
      payload: PAYLOAD,
    }),
    (error) => error instanceof EvidenceBundleError
      && error.code === 'EVIDENCE_BUNDLE_OUTPUT_UNSAFE',
  )
  await assert.rejects(() => access(join(outside, 'new')))
})

test('a malformed profile is reported invalid rather than throwing during root derivation', async () => {
  const directory = join(await mkdtemp(join(tmpdir(), 'rta-evidence-malformed-')), 'ev')
  await mkdir(directory, { recursive: true })
  await writeFile(join(directory, 'manifest.json'), JSON.stringify({
    schema: 'evidence-bundle-manifest-v2',
    root_algorithm: 'sha256-canonical-profile-v2',
    profile: 'invalid',
    root_sha256: '0'.repeat(64),
  }))
  const verification = await verifyEvidenceBundle(directory)
  assert.equal(verification.valid, false)
  assert.ok(verification.errors.length > 0)
})

test('a linked payload root is rejected during verification', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-evidence-junction-'))
  const source = join(root, 'source')
  const directory = join(root, 'ev')
  await mkdir(source)
  await mkdir(directory)
  await writeFile(join(source, 'legacy.txt'), 'legacy evidence\n')
  try {
    await symlink(source, join(directory, 'payload'), process.platform === 'win32' ? 'junction' : 'dir')
  } catch (error) {
    return t.skip(`directory links unavailable: ${error.code}`)
  }
  const legacyManifest = await readFile(resolve('test/fixtures/compat/evidence-bundle-v1/manifest.json'))
  await writeFile(join(directory, 'manifest.json'), legacyManifest)
  const verification = await verifyEvidenceBundle(directory)
  assert.equal(verification.valid, false)
  assert.ok(verification.errors.some(({ code }) => code === 'EVIDENCE_BUNDLE_SYMLINK'))
})

test('a linked nested payload ancestor is rejected by verification and direct reads', async (t) => {
  const { directory } = await sealedBundle()
  const outside = join(await mkdtemp(join(tmpdir(), 'rta-evidence-nested-junction-')), 'outside')
  await mkdir(outside)
  await copyFile(
    join(directory, 'payload', 'layers', '02', 'entries.json'),
    join(outside, 'entries.json'),
  )
  await rm(join(directory, 'payload', 'layers', '02'), { recursive: true })
  try {
    await symlink(
      outside,
      join(directory, 'payload', 'layers', '02'),
      process.platform === 'win32' ? 'junction' : 'dir',
    )
  } catch (error) {
    return t.skip(`directory links unavailable: ${error.code}`)
  }
  const verification = await verifyEvidenceBundle(directory)
  assert.equal(verification.valid, false)
  assert.ok(verification.errors.some(({ code }) => /SYMLINK|UNSAFE/.test(code)))
  await assert.rejects(
    () => readEvidencePayloadFile(directory, 'payload/layers/02/entries.json'),
    (error) => /SYMLINK|UNSAFE/.test(error?.code ?? ''),
  )
})

test('a prelinked payload cannot overwrite a file outside the bundle', async () => {
  const root = await mkdtemp(join(tmpdir(), 'rta-evidence-hardlink-'))
  const directory = join(root, 'ev')
  const outside = join(root, 'outside.txt')
  await mkdir(join(directory, 'payload', 'config'), { recursive: true })
  await writeFile(outside, 'unchanged')
  await link(outside, join(directory, 'payload', 'config', 'history.json'))

  await assert.rejects(
    () => writeEvidenceBundle({ directory, profile: baseProfile(), payload: PAYLOAD }),
    (error) => error instanceof EvidenceBundleError
      && error.code === 'EVIDENCE_BUNDLE_OUTPUT_UNSAFE',
  )
  assert.equal(await readFile(outside, 'utf8'), 'unchanged')
})

test('oversize manifest and payload files are refused from metadata before reading', async () => {
  const { directory } = await sealedBundle()
  await truncate(join(directory, 'manifest.json'), 4 * 1024 * 1024 + 1)
  const manifestVerification = await verifyEvidenceBundle(directory)
  assert.ok(manifestVerification.errors.some(
    (error) => error.code === 'EVIDENCE_BUNDLE_MANIFEST_TOO_LARGE',
  ))

  const second = await sealedBundle()
  await truncate(join(second.directory, 'payload', 'config', 'history.json'), 128 * 1024 * 1024 + 1)
  const payloadVerification = await verifyEvidenceBundle(second.directory)
  assert.ok(payloadVerification.errors.some(
    (error) => error.code === 'PAYLOAD_FILE_TOO_LARGE',
  ))
})

test('bundle creation refuses an oversized generated manifest before publishing output', async () => {
  const directory = join(await mkdtemp(join(tmpdir(), 'rta-evidence-manifest-cap-')), 'ev')
  const payload = Array.from({ length: 5000 }, (_, index) => ({
    path: `large/${String(index).padStart(5, '0')}-${'a'.repeat(900)}.json`,
    bytes: Buffer.alloc(0),
  }))
  await assert.rejects(
    () => writeEvidenceBundle({ directory, profile: baseProfile(), payload }),
    (error) => error instanceof EvidenceBundleError
      && error.code === 'EVIDENCE_BUNDLE_MANIFEST_TOO_LARGE',
  )
  await assert.rejects(() => access(directory))
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
  assert.throws(() => {
    loaded.evidence_context.detection_evidence.push('mutated')
  }, TypeError)
  assert.throws(() => {
    loaded.profile.coverage_gaps.push({ area: 'forged', reason: 'mutable' })
  }, TypeError)
  assert.throws(() => {
    loaded.profile.target_class = 'PROD'
  }, TypeError)
  assert.equal(loaded.profile.evidence_context, loaded.evidence_context)
})

test('loadEvidenceBundle returns the manifest snapshot it actually verified', async () => {
  const { directory, written } = await sealedBundle()
  const manifestPath = join(directory, 'manifest.json')
  const replacement = JSON.parse(await readFile(manifestPath, 'utf8'))
  replacement.profile.evidence_context.evidence_id = 'replacement-after-verification'
  replacement.root_sha256 = evidenceBundleRootDigest(replacement.profile)

  const originalParse = JSON.parse
  let replaced = false
  JSON.parse = (text, reviver) => {
    const parsed = originalParse(text, reviver)
    if (!replaced
      && parsed?.schema === 'evidence-bundle-manifest-v2'
      && parsed?.root_sha256 === written.root_sha256) {
      replaced = true
      writeFileSync(manifestPath, JSON.stringify(replacement))
    }
    return parsed
  }
  try {
    const loaded = await loadEvidenceBundle(directory)
    assert.equal(replaced, true)
    assert.equal(loaded.root_sha256, written.root_sha256)
    assert.equal(loaded.evidence_context.evidence_id, 'sample-api-image')
  } finally {
    JSON.parse = originalParse
  }

  const onDisk = JSON.parse(await readFile(manifestPath, 'utf8'))
  assert.equal(onDisk.root_sha256, replacement.root_sha256)
  assert.equal(onDisk.profile.evidence_context.evidence_id, 'replacement-after-verification')
})
