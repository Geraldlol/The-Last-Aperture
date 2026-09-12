import { test } from 'node:test'
import assert from 'node:assert/strict'
import { gzipSync } from 'node:zlib'
import { createHash, randomBytes } from 'node:crypto'
import { access, mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  buildArtifactPayload,
  createArtifactAdapter,
} from '../scripts/lib/evidence-adapters/artifact.mjs'
import { readEvidenceIndex } from '../scripts/lib/evidence-packet.mjs'
import {
  DEFAULT_NORMALIZER_LIMITS,
  normalizeOciArchive,
  normalizeOciLayout,
  readTarEntries,
  readTarEntryBytes,
} from '../scripts/lib/oci-normalizer.mjs'

function writeBase256(header, offset, length, input) {
  let value = BigInt(input)
  header.fill(0, offset, offset + length)
  for (let index = offset + length - 1; index > offset; index -= 1) {
    header[index] = Number(value & 0xffn)
    value >>= 8n
  }
  assert.ok(value <= 0x7fn, 'test base-256 value must fit the requested field')
  header[offset] = 0x80 | Number(value)
}

function tarHeader({
  name,
  size,
  mode = 0o644,
  mtime = 1754661730,
  type = '0',
  linkname = '',
  base256Size = false,
  base256Mtime = false,
}) {
  const header = Buffer.alloc(512)
  header.write(name, 0, 100, 'utf8')
  header.write(`${mode.toString(8).padStart(7, '0')}\0`, 100, 8, 'ascii')
  header.write('0000000\0', 108, 8, 'ascii')
  header.write('0000000\0', 116, 8, 'ascii')
  if (base256Size) writeBase256(header, 124, 12, size)
  else header.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 12, 'ascii')
  if (base256Mtime) writeBase256(header, 136, 12, mtime)
  else header.write(`${mtime.toString(8).padStart(11, '0')}\0`, 136, 12, 'ascii')
  header.write('        ', 148, 8, 'ascii')
  header.write(type, 156, 1, 'ascii')
  header.write(linkname, 157, 100, 'utf8')
  header.write('ustar\0', 257, 6, 'ascii')
  header.write('00', 263, 2, 'ascii')
  let checksum = 0
  for (const byte of header) checksum += byte
  header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii')
  return header
}

// Content may be a Buffer: a gzipped layer blob is binary, and re-encoding it
// through a JS string would corrupt every byte above 0x7F.
function tar(entries) {
  const blocks = []
  for (const entry of entries) {
    const content = Buffer.isBuffer(entry.content)
      ? entry.content
      : Buffer.from(entry.content ?? '', 'utf8')
    blocks.push(tarHeader({ ...entry, size: content.length }))
    if (content.length > 0) {
      const padded = Buffer.alloc(Math.ceil(content.length / 512) * 512)
      content.copy(padded)
      blocks.push(padded)
    }
  }
  blocks.push(Buffer.alloc(1024))
  return Buffer.concat(blocks)
}

function appendTarEntryBeforeTerminator(archive, entry) {
  const encodedEntry = tar([entry]).subarray(0, -1024)
  return Buffer.concat([archive.subarray(0, -1024), encodedEntry, Buffer.alloc(1024)])
}

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')

test('a tar archive round-trips through the entry reader', () => {
  const archive = tar([
    { name: 'etc/passwd', content: 'root:x:0:0\n', mode: 0o644 },
    { name: 'usr/local/bin/', content: '', type: '5', mode: 0o755 },
    { name: 'bin/sh', content: '', type: '2', linkname: '/bin/busybox' },
  ])
  const entries = readTarEntries(archive, DEFAULT_NORMALIZER_LIMITS)
  assert.deepEqual(entries.map(({ path }) => path), ['etc/passwd', 'usr/local/bin/', 'bin/sh'])
  assert.equal(entries[0].mode, 0o644)
  assert.equal(entries[0].size, 11)
  assert.equal(entries[0].mtime, 1754661730)
  assert.equal(entries[0].type, 'file')
  assert.equal(entries[1].type, 'directory')
  assert.equal(entries[2].type, 'symlink')
  assert.equal(entries[2].link_target, '/bin/busybox')
  assert.equal(readTarEntryBytes(archive, entries[0]).toString('utf8'), 'root:x:0:0\n')
})

test('the entry reader accepts GNU base-256 numeric fields before enforcing bounds', () => {
  const mtime = 1754661730
  const archive = tar([{
    name: 'app.bin',
    content: 'x',
    mtime,
    base256Mtime: true,
  }])
  assert.equal(readTarEntries(archive, DEFAULT_NORMALIZER_LIMITS)[0].mtime, mtime)

  const eightGibibytes = 8 * 1024 * 1024 * 1024
  const declaredLargeEntry = Buffer.concat([
    tarHeader({ name: 'layer.tar', size: eightGibibytes, base256Size: true }),
    Buffer.alloc(1024),
  ])
  assert.throws(
    () => readTarEntries(declaredLargeEntry, DEFAULT_NORMALIZER_LIMITS),
    /above the bounded limit/i,
  )
})

test('the entry reader refuses a path that escapes the archive root', () => {
  const archive = tar([{ name: '../../etc/shadow', content: 'x' }])
  assert.throws(() => readTarEntries(archive, DEFAULT_NORMALIZER_LIMITS), /escape/i)
})

test('the entry reader rejects a header whose integrity checksum is invalid', () => {
  const archive = tar([{ name: 'app.bin', content: 'x' }])
  archive[0] ^= 0x01
  assert.throws(
    () => readTarEntries(archive, DEFAULT_NORMALIZER_LIMITS),
    /checksum mismatch/i,
  )
})

test('the entry reader accepts zero record padding but rejects data or partial bytes after its terminator', () => {
  const archive = tar([{ name: 'app.bin', content: 'x' }])
  assert.equal(
    readTarEntries(Buffer.concat([archive, Buffer.alloc(1024)]), DEFAULT_NORMALIZER_LIMITS).length,
    1,
  )

  const nonzeroBlock = Buffer.alloc(512)
  nonzeroBlock[17] = 1
  assert.throws(
    () => readTarEntries(Buffer.concat([archive, nonzeroBlock]), DEFAULT_NORMALIZER_LIMITS),
    /nonzero data after the tar terminator/i,
  )
  assert.throws(
    () => readTarEntries(Buffer.concat([archive, Buffer.alloc(1)]), DEFAULT_NORMALIZER_LIMITS),
    /partial trailing block after the tar terminator/i,
  )

  const withoutTerminator = archive.subarray(0, archive.length - 1024)
  assert.throws(
    () => readTarEntries(Buffer.concat([withoutTerminator, Buffer.from([1])]), DEFAULT_NORMALIZER_LIMITS),
    /partial trailing block without a complete tar header/i,
  )
  assert.throws(
    () => readTarEntries(Buffer.from([1]), DEFAULT_NORMALIZER_LIMITS),
    /partial trailing block without a complete tar header/i,
  )
})

test('a file cannot use a directory-shaped tar path', () => {
  assert.throws(
    () => readTarEntries(tar([{ name: 'not-a-directory/', content: 'x' }]), DEFAULT_NORMALIZER_LIMITS),
    /non-directory entry.*directory-shaped path/i,
  )
})

test('a directory tar entry must have a directory-shaped path and zero content bytes', () => {
  assert.throws(
    () => readTarEntries(tar([{ name: 'not-shaped', content: '', type: '5' }]), DEFAULT_NORMALIZER_LIMITS),
    /directory entry.*non-directory-shaped path/i,
  )
  assert.throws(
    () => readTarEntries(tar([{ name: 'shaped/', content: 'x', type: '5' }]), DEFAULT_NORMALIZER_LIMITS),
    /directory entry carries 1 content byte/i,
  )
})

test('the entry reader halts at its bounded limits rather than exhausting memory', () => {
  const archive = tar([
    { name: 'a', content: 'x'.repeat(4096) },
    { name: 'b', content: 'y' },
  ])
  assert.throws(
    () => readTarEntries(archive, { ...DEFAULT_NORMALIZER_LIMITS, maxEntries: 1 }),
    /entr(?:y|ies)/i,
  )
  assert.throws(
    () => readTarEntries(archive, { ...DEFAULT_NORMALIZER_LIMITS, maxEntryBytes: 1024 }),
    /bytes/i,
  )
})

test('gzip expansion is bounded before an outer archive can inflate without limit', () => {
  const compressed = gzipSync(Buffer.alloc(16 * 1024))
  const normalized = normalizeOciLayout(compressed, {
    ...DEFAULT_NORMALIZER_LIMITS,
    maxArchiveBytes: 1024,
  })
  assert.equal(normalized.format, 'unknown')
  assert.match(normalized.gaps[0].reason, /bounded limit.*1024 bytes/i)
})

test('normalizer and artifact limits reject non-finite or fractional caps before reading bytes', () => {
  assert.throws(
    () => normalizeOciArchive(Buffer.alloc(0), { ...DEFAULT_NORMALIZER_LIMITS, maxInflatedBytes: Number.NaN }),
    /maxInflatedBytes.*positive safe integer/i,
  )
  assert.throws(
    () => readTarEntries(Buffer.alloc(0), { ...DEFAULT_NORMALIZER_LIMITS, maxEntries: Number.POSITIVE_INFINITY }),
    /maxEntries.*positive safe integer/i,
  )
  assert.throws(
    () => createArtifactAdapter({ limits: { maxCapturedBytes: Number.POSITIVE_INFINITY } }),
    /maxCapturedBytes.*positive safe integer/i,
  )
  assert.throws(
    () => createArtifactAdapter({ limits: { maxCapturedEntryBytes: 1.5 } }),
    /maxCapturedEntryBytes.*positive safe integer/i,
  )
})

test('tar paths with a conventional leading dot segment normalize to one canonical path', () => {
  const archive = tar([
    { name: './file.txt', content: 'x' },
    { name: './directory/', content: '', type: '5' },
  ])
  assert.deepEqual(
    readTarEntries(archive, DEFAULT_NORMALIZER_LIMITS).map(({ path }) => path),
    ['file.txt', 'directory/'],
  )
})

test('unsupported PAX and GNU metadata extensions are rejected explicitly', () => {
  for (const type of ['x', 'g', 'L', 'K']) {
    assert.throws(
      () => readTarEntries(tar([{ name: 'metadata', content: 'path=value\n', type }]), DEFAULT_NORMALIZER_LIMITS),
      /unsupported tar metadata extension/i,
    )
  }
})

function ociLayout({
  layers,
  historyEntry = 'RUN rm /secret.txt',
  orphan = null,
  corruptLayer = false,
  rawLayerBlobs = false,
  history,
  diffIds,
}) {
  const blobs = new Map()
  const put = (bytes) => {
    const digest = `sha256:${sha256(bytes)}`
    blobs.set(digest, bytes)
    return digest
  }
  const layerDescriptors = layers.map((entries) => {
    // A blob that opens with the gzip magic and carries garbage after it is
    // deterministically undecompressable, which is what the gap case needs.
    const compressed = corruptLayer
      ? Buffer.concat([Buffer.from([0x1f, 0x8b, 0x08, 0x00]), Buffer.alloc(64, 0xab)])
      : rawLayerBlobs
        ? Buffer.from(entries)
      : gzipSync(Buffer.isBuffer(entries) ? entries : tar(entries))
    return {
      mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip',
      digest: put(compressed),
      size: compressed.length,
    }
  })
  const config = Buffer.from(JSON.stringify({
    architecture: 'amd64',
    os: 'linux',
    history: history ?? [{ created_by: 'FROM alpine' }, { created_by: historyEntry }],
    rootfs: { type: 'layers', diff_ids: diffIds ?? layerDescriptors.map(({ digest }) => digest) },
  }), 'utf8')
  const configDigest = put(config)
  const manifest = Buffer.from(JSON.stringify({
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    config: { mediaType: 'application/vnd.oci.image.config.v1+json', digest: configDigest, size: config.length },
    layers: layerDescriptors,
  }), 'utf8')
  const manifestDigest = put(manifest)
  if (orphan) put(Buffer.from(orphan, 'utf8'))
  const index = Buffer.from(JSON.stringify({
    schemaVersion: 2,
    manifests: [{
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
      digest: manifestDigest,
      size: manifest.length,
    }],
  }), 'utf8')

  const files = [
    { name: 'oci-layout', content: JSON.stringify({ imageLayoutVersion: '1.0.0' }) },
    { name: 'index.json', content: index },
  ]
  for (const [digest, bytes] of blobs) {
    files.push({ name: `blobs/sha256/${digest.slice(7)}`, content: bytes })
  }
  return tar(files)
}

function multiPlatformOciLayout({ nested = false, nestedFirst = false, digestlessLayer = false } = {}) {
  const blobs = new Map()
  const put = (bytes) => {
    const digest = `sha256:${sha256(bytes)}`
    blobs.set(digest, bytes)
    return digest
  }
  const platforms = ['amd64', 'arm64']
  const manifests = platforms.map((architecture, platformIndex) => {
    const layer = gzipSync(tar([{
      name: `app/${architecture}.txt`,
      content: `${architecture}-payload`,
    }]))
    const layerDescriptor = {
      mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip',
      digest: put(layer),
      size: layer.length,
    }
    const config = Buffer.from(JSON.stringify({
      architecture,
      os: 'linux',
      history: [{ created_by: `BUILD ${architecture}` }],
      rootfs: { type: 'layers', diff_ids: [layerDescriptor.digest] },
    }))
    const configDigest = put(config)
    const imageManifest = Buffer.from(JSON.stringify({
      schemaVersion: 2,
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
      config: {
        mediaType: 'application/vnd.oci.image.config.v1+json',
        digest: configDigest,
        size: config.length,
      },
      layers: [
        layerDescriptor,
        ...(digestlessLayer && platformIndex === 0
          ? [{ mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip', size: 12 }]
          : []),
      ],
    }))
    return {
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
      digest: put(imageManifest),
      size: imageManifest.length,
      platform: { architecture, os: 'linux' },
    }
  })
  let topManifests = manifests
  if (nested || nestedFirst) {
    const nestedIndex = Buffer.from(JSON.stringify({
      schemaVersion: 2,
      mediaType: 'application/vnd.oci.image.index.v1+json',
      manifests: nestedFirst ? [manifests[0]] : manifests,
    }))
    const nestedDescriptor = {
      mediaType: 'application/vnd.oci.image.index.v1+json',
      digest: put(nestedIndex),
      size: nestedIndex.length,
    }
    topManifests = nestedFirst ? [nestedDescriptor, manifests[1]] : [nestedDescriptor]
  }
  const files = [
    { name: 'oci-layout', content: JSON.stringify({ imageLayoutVersion: '1.0.0' }) },
    { name: 'index.json', content: JSON.stringify({ schemaVersion: 2, manifests: topManifests }) },
  ]
  for (const [digest, bytes] of blobs) {
    files.push({ name: `blobs/sha256/${digest.slice(7)}`, content: bytes })
  }
  return tar(files)
}

function withRepeatedTopManifest(layout, mutate = (descriptor) => descriptor) {
  const entries = readTarEntries(layout, DEFAULT_NORMALIZER_LIMITS)
  return tar(entries.map((entry) => {
    let content = Buffer.from(readTarEntryBytes(layout, entry))
    if (entry.path === 'index.json') {
      const index = JSON.parse(content.toString('utf8'))
      index.manifests.push(mutate({ ...index.manifests[0] }))
      content = Buffer.from(JSON.stringify(index), 'utf8')
    }
    return { name: entry.path, content }
  }))
}

async function assertArtifactNormalizationIsGapped(archive, label, expectedError) {
  const normalized = normalizeOciLayout(archive, DEFAULT_NORMALIZER_LIMITS)
  assert.equal(normalized.format, 'unknown')
  assert.deepEqual(normalized.layers, [])
  assert.ok(normalized.gaps.some(({ reason }) => expectedError.test(reason)))

  const directory = await mkdtemp(join(tmpdir(), `rta-oci-${label}-`))
  const source = join(directory, 'image.tar')
  const output = join(directory, 'evidence')
  await writeFile(source, archive)
  const adapter = createArtifactAdapter({ clock: () => '2026-08-08T14:22:10Z' })
  const planned = await adapter.plan({
    evidence_id: label,
    source_path: source,
    target_class: 'LAB',
    phi_scope: 'none',
  })
  const written = await adapter.run(planned, { out: output })
  assert.equal(written.profile.coverage_state, 'NOT_ASSESSED')
  assert.ok(written.profile.coverage_gaps.some(({ reason }) => expectedError.test(reason)))

  const index = await readEvidenceIndex(output)
  assert.equal(index.unreadable, false)
  assert.deepEqual(index.entries, [])
}

test('a duplicate authoritative index.json becomes a gap before last-wins lookup', async () => {
  const layout = ociLayout({
    layers: [[{ name: '.wh.looks-deleted', content: 'still present' }]],
  })
  const poisoned = appendTarEntryBeforeTerminator(layout, {
    name: 'index.json',
    content: JSON.stringify({ schemaVersion: 2, manifests: [] }),
  })

  await assertArtifactNormalizationIsGapped(
    poisoned,
    'duplicate-index',
    /duplicate normalized path: index\.json/i,
  )
})

test('nonzero and partial outer OCI trailers become gaps without mandatory matches', async () => {
  const layout = ociLayout({
    layers: [[{ name: '.wh.looks-deleted', content: 'still present' }]],
  })
  const nonzeroBlock = Buffer.alloc(512)
  nonzeroBlock[17] = 1
  await assertArtifactNormalizationIsGapped(
    Buffer.concat([layout, nonzeroBlock]),
    'nonzero-trailer',
    /nonzero data after the tar terminator/i,
  )
  await assertArtifactNormalizationIsGapped(
    Buffer.concat([layout, Buffer.alloc(1)]),
    'partial-trailer',
    /partial trailing block after the tar terminator/i,
  )

  const withoutTerminator = layout.subarray(0, layout.length - 1024)
  await assertArtifactNormalizationIsGapped(
    Buffer.concat([withoutTerminator, Buffer.from([1])]),
    'unterminated-partial-trailer',
    /partial trailing block without a complete tar header/i,
  )
})

test('layers are normalized in manifest order, which is what makes "below" mean anything', () => {
  const layout = ociLayout({
    layers: [
      [{ name: 'secret.txt', content: 'AKIA_FIXTURE_NOT_A_REAL_KEY' }],
      [{ name: '.wh.secret.txt', content: '', mode: 0o600 }],
    ],
  })
  const normalized = normalizeOciLayout(layout, DEFAULT_NORMALIZER_LIMITS)
  assert.equal(normalized.format, 'oci-layout')
  assert.equal(normalized.layers.length, 2)
  assert.deepEqual(normalized.layers.map(({ index }) => index), [0, 1])
  assert.equal(normalized.layers[0].entries[0].path, 'secret.txt')
  assert.equal(normalized.layers[1].entries[0].path, '.wh.secret.txt')
})

test('repeated OCI layer descriptors remain repeated in their exact manifest order', () => {
  const entries = [{ name: 'same.txt', content: 'same' }]
  const normalized = normalizeOciLayout(
    ociLayout({ layers: [entries, entries] }),
    DEFAULT_NORMALIZER_LIMITS,
  )
  assert.equal(normalized.layers.length, 2)
  assert.deepEqual(normalized.layers.map(({ index }) => index), [0, 1])
  assert.equal(normalized.layers[0].digest, normalized.layers[1].digest)
})

test('repeated OCI manifest descriptors preserve their layer occurrences in index order', () => {
  const result = normalizeOciArchive(
    withRepeatedTopManifest(ociLayout({ layers: [[{ name: 'same.txt', content: 'same' }]] })),
    DEFAULT_NORMALIZER_LIMITS,
  )
  const { normalized } = result
  assert.equal(normalized.layers.length, 2)
  assert.deepEqual(normalized.layers.map(({ index }) => index), [0, 1])
  assert.equal(normalized.layers[0].digest, normalized.layers[1].digest)
  assert.equal(result.resource_usage.verified_blob_cache_entries, 3)
})

test('each repeated OCI manifest descriptor is validated before digest caching', () => {
  const normalized = normalizeOciLayout(
    withRepeatedTopManifest(
      ociLayout({ layers: [[{ name: 'same.txt', content: 'same' }]] }),
      (descriptor) => ({ ...descriptor, size: descriptor.size + 1 }),
    ),
    DEFAULT_NORMALIZER_LIMITS,
  )
  assert.equal(normalized.layers.length, 1)
  assert.ok(normalized.gaps.some(({ reason }) => /declares.*bytes.*blob has/i.test(reason)))
  assert.deepEqual(normalized.orphan_blobs, [])
})

test('repeated layer content consumes the aggregate inflation budget once through the digest cache', () => {
  const entries = [{ name: 'same.txt', content: 'same' }]
  const decodedLayer = tar(entries)
  const layout = ociLayout({ layers: [entries, entries] })
  const result = normalizeOciArchive(layout, {
    ...DEFAULT_NORMALIZER_LIMITS,
    maxInflatedBytes: layout.length + decodedLayer.length,
  })
  assert.equal(result.normalized.layers.length, 2)
  assert.deepEqual(result.normalized.layers.map(({ index }) => index), [0, 1])
  assert.equal(result.resource_usage.inflated_bytes, layout.length + decodedLayer.length)
  assert.equal(result.resource_usage.decoded_layer_cache_entries, 1)
})

test('repeated layer metadata stops before crossing the aggregate projected-entry budget', () => {
  const entries = Array.from({ length: 10 }, (_, index) => ({
    name: `entry-${index}.txt`, content: String(index),
  }))
  const layout = ociLayout({ layers: [entries, entries] })
  const outerEntries = readTarEntries(layout, DEFAULT_NORMALIZER_LIMITS).length
  const result = normalizeOciArchive(layout, {
    ...DEFAULT_NORMALIZER_LIMITS,
    maxEntries: outerEntries + entries.length,
  })
  assert.equal(result.normalized.layers.length, 2)
  assert.equal(result.normalized.layers[0].entries.length, entries.length)
  assert.equal(result.normalized.layers[1].entries.length, outerEntries)
  assert.equal(result.resource_usage.projected_entries, outerEntries + entries.length)
  assert.ok(result.normalized.gaps.some(({ reason }) => /aggregate projected-entry limit/i.test(reason)))
})

test('serialized layer metadata retains an ordered prefix within its aggregate byte cap', () => {
  const archive = ociLayout({ layers: [[
    { name: 'control-\u0001-\u0002.txt', content: 'one' },
    { name: 'second.txt', content: 'two' },
  ]] })
  const baseline = normalizeOciArchive(archive, DEFAULT_NORMALIZER_LIMITS)
  const first = baseline.normalized.layers[0].entries[0]
  const maxProjectedBytes = Buffer.byteLength(JSON.stringify(first), 'utf8')
  const result = normalizeOciArchive(archive, {
    ...DEFAULT_NORMALIZER_LIMITS,
    maxProjectedBytes,
  })
  assert.deepEqual(result.normalized.layers[0].entries.map(({ path }) => path), ['control-\u0001-\u0002.txt'])
  assert.equal(result.resource_usage.projected_entries, 1)
  assert.equal(result.resource_usage.projected_bytes, maxProjectedBytes)
  assert.ok(result.normalized.gaps.some(({ reason }) => /projected-entry limits.*serialized bytes/i.test(reason)))
  const built = buildArtifactPayload(
    result.archive,
    result.normalized,
    { ...DEFAULT_NORMALIZER_LIMITS, maxProjectedBytes },
    result.resource_budget,
  )
  const entriesPayload = built.payload.find(({ path }) => path.endsWith('/entries.json'))
  assert.equal(entriesPayload.bytes.length, maxProjectedBytes + 2)
  assert.deepEqual(JSON.parse(entriesPayload.bytes).map(({ path }) => path), ['control-\u0001-\u0002.txt'])
  assert.equal(
    built.payload.some(({ path }) => path.endsWith('/content/second.txt')),
    false,
  )
})

test('unique layers stop before crossing the campaign aggregate inflation budget', () => {
  const first = [{ name: 'one.txt', content: 'one' }]
  const second = [{ name: 'two.txt', content: 'two' }]
  const layout = ociLayout({ layers: [first, second] })
  const result = normalizeOciArchive(layout, {
    ...DEFAULT_NORMALIZER_LIMITS,
    maxInflatedBytes: layout.length + tar(first).length,
  })
  assert.equal(result.normalized.layers.length, 1)
  assert.ok(result.normalized.gaps.some(({ reason }) => /aggregate.*inflation|inflated.*limit/i.test(reason)))
})

test('unique layers stop before crossing the aggregate tar-entry budget', () => {
  const layout = ociLayout({
    layers: [
      [{ name: 'one.txt', content: 'one' }],
      [{ name: 'two.txt', content: 'two' }],
    ],
  })
  const outerEntries = readTarEntries(layout, DEFAULT_NORMALIZER_LIMITS).length
  const result = normalizeOciArchive(layout, {
    ...DEFAULT_NORMALIZER_LIMITS,
    maxEntries: outerEntries + 1,
  })
  assert.equal(result.normalized.layers.length, 1)
  assert.equal(result.resource_usage.parsed_entries, outerEntries + 1)
  assert.ok(result.normalized.gaps.some(({ reason }) => /aggregate tar-entry limit/i.test(reason)))
})

test('entries parsed before corrupt layer trailers still consume the campaign entry budget', () => {
  const corruptAfterTwo = (prefix) => {
    const archive = tar([
      { name: `${prefix}-one`, content: '1' },
      { name: `${prefix}-two`, content: '2' },
      { name: `${prefix}-corrupt`, content: '3' },
    ])
    const last = readTarEntries(archive, DEFAULT_NORMALIZER_LIMITS).at(-1)
    archive[last.offset - 512] ^= 1
    return archive
  }
  const layout = ociLayout({ layers: [corruptAfterTwo('a'), corruptAfterTwo('b')] })
  const outerEntries = readTarEntries(layout, DEFAULT_NORMALIZER_LIMITS).length
  const result = normalizeOciArchive(layout, {
    ...DEFAULT_NORMALIZER_LIMITS,
    maxEntries: outerEntries + 3,
  })
  assert.equal(result.resource_usage.parsed_entries, outerEntries + 3)
  assert.equal(result.normalized.layers.length, 0)
  assert.ok(result.normalized.gaps.some(({ reason }) => /aggregate tar-entry limit/i.test(reason)))
})

test('a failed gzip decode conservatively exhausts the remaining campaign inflation budget', () => {
  const badGzip = (byte) => {
    const compressed = gzipSync(Buffer.alloc(4096, byte))
    compressed[compressed.length - 1] ^= 1
    return compressed
  }
  const layout = ociLayout({
    layers: [badGzip(0x61), badGzip(0x62)],
    rawLayerBlobs: true,
  })
  const maxInflatedBytes = layout.length + 1024
  const result = normalizeOciArchive(layout, {
    ...DEFAULT_NORMALIZER_LIMITS,
    maxInflatedBytes,
  })
  assert.equal(result.resource_usage.inflated_bytes, maxInflatedBytes)
  assert.equal(result.normalized.layers.length, 0)
  assert.ok(result.normalized.gaps.some(({ reason }) => /aggregate inflation limit/i.test(reason)))
})

test('artifact payload capture reuses the verified outer tar index without reparsing it', () => {
  const layout = ociLayout({ layers: [[{ name: 'captured.txt', content: 'captured' }]] })
  const result = normalizeOciArchive(layout, DEFAULT_NORMALIZER_LIMITS)
  const parsedBeforeCapture = result.resource_budget.parsedEntries
  result.archive[0] ^= 1 // invalidate only an outer header checksum after the verified parse
  const built = buildArtifactPayload(
    result.archive,
    result.normalized,
    undefined,
    result.resource_budget,
  )
  assert.equal(result.resource_budget.parsedEntries, parsedBeforeCapture)
  assert.equal(
    built.payload.find(({ path }) => path.endsWith('/content/captured.txt')).bytes.toString('utf8'),
    'captured',
  )
})

test('a layer blob and its files use the image byte policy rather than the JSON metadata cap', () => {
  const layout = ociLayout({
    layers: [[{ name: 'large.bin', content: randomBytes(16 * 1024) }]],
  })
  const normalized = normalizeOciLayout(layout, {
    ...DEFAULT_NORMALIZER_LIMITS,
    maxEntryBytes: 1024,
    maxTotalBytes: 128 * 1024,
  })
  assert.equal(normalized.layers.length, 1)
  assert.equal(normalized.layers[0].entries[0].size, 16 * 1024)
})

test('a real whiteout and a file merely named like one are distinguishable', () => {
  const layout = ociLayout({
    layers: [[
      { name: '.wh.deleted', content: '', mode: 0o600 },
      { name: '.wh.impostor', content: 'still here', mode: 0o664 },
    ]],
  })
  const [entries] = normalizeOciLayout(layout, DEFAULT_NORMALIZER_LIMITS)
    .layers.map(({ entries: e }) => e)
  const real = entries.find(({ path }) => path === '.wh.deleted')
  const impostor = entries.find(({ path }) => path === '.wh.impostor')
  assert.equal(real.whiteout, true)
  assert.equal(real.size, 0)
  assert.equal(impostor.whiteout, false)
  assert.ok(impostor.size > 0)
})

test('the image config history is carried through addressably', () => {
  const layout = ociLayout({ layers: [[{ name: 'a', content: 'a' }]] })
  const normalized = normalizeOciLayout(layout, DEFAULT_NORMALIZER_LIMITS)
  assert.equal(normalized.config.history.length, 2)
  assert.equal(normalized.config.history[1].created_by, 'RUN rm /secret.txt')
  assert.equal(normalized.config.diff_ids.length, 1)
})

test('OCI history and diff-id projection obey aggregate item and serialized-byte limits', () => {
  const history = Array.from({ length: 200_000 }, () => null)
  const diffIds = Array.from({ length: 200_000 }, () => 'sha256:metadata')
  const archive = ociLayout({ layers: [], history, diffIds })
  const result = normalizeOciArchive(archive, {
    ...DEFAULT_NORMALIZER_LIMITS,
    maxMetadataItems: 4,
    maxMetadataBytes: 14,
  })
  assert.equal(result.normalized.config.history.length, 3)
  assert.equal(result.normalized.config.diff_ids.length, 0)
  assert.equal(result.resource_usage.metadata_items, 3)
  assert.equal(result.resource_usage.metadata_bytes, 14)
  assert.equal(
    result.normalized.gaps.filter(({ area }) => area === 'image configuration metadata').length,
    1,
  )
  const built = buildArtifactPayload(
    result.archive,
    result.normalized,
    { ...DEFAULT_NORMALIZER_LIMITS, maxMetadataItems: 4, maxMetadataBytes: 14 },
    result.resource_budget,
  )
  const durable = JSON.parse(built.payload.find(({ path }) => path === 'normalized.json').bytes)
  assert.equal(durable.resource_usage.metadata_items, 3)
  assert.equal(durable.resource_usage.metadata_bytes, 14)
})

test('docker history and diff-id projection stop without spreading attacker-cardinality arrays', () => {
  const history = Array.from({ length: 200_000 }, () => null)
  const diffIds = Array.from({ length: 200_000 }, () => 'sha256:metadata')
  const archive = tar([
    { name: 'manifest.json', content: JSON.stringify([{ Config: 'config.json', Layers: [] }]) },
    { name: 'config.json', content: JSON.stringify({ history, rootfs: { diff_ids: diffIds } }) },
  ])
  const result = normalizeOciArchive(archive, {
    ...DEFAULT_NORMALIZER_LIMITS,
    maxMetadataItems: 5,
    maxMetadataBytes: 24,
  })
  assert.equal(result.normalized.config.history.length, 5)
  assert.equal(result.normalized.config.diff_ids.length, 0)
  assert.equal(result.resource_usage.metadata_items, 5)
  assert.equal(result.resource_usage.metadata_bytes, 24)
  assert.equal(
    result.normalized.gaps.filter(({ area }) => area === 'image configuration metadata').length,
    1,
  )
})

test('a blob no manifest references is reported, not dropped', () => {
  const layout = ociLayout({
    layers: [[{ name: 'a', content: 'a' }]],
    orphan: 'unreferenced payload',
  })
  const normalized = normalizeOciLayout(layout, DEFAULT_NORMALIZER_LIMITS)
  assert.equal(normalized.orphan_blobs.length, 1)
  assert.ok(normalized.orphan_blobs[0].size > 0)
})

test('a directory shaped like a blob path is not reported as an orphan blob', () => {
  const layout = ociLayout({ layers: [[{ name: 'a', content: 'a' }]] })
  const directory = appendTarEntryBeforeTerminator(layout, {
    name: `blobs/sha256/${'a'.repeat(64)}/`,
    content: '',
    type: '5',
  })
  assert.deepEqual(normalizeOciLayout(directory, DEFAULT_NORMALIZER_LIMITS).orphan_blobs, [])
})

test('an OCI descriptor cannot treat a content-bearing directory record as its blob', () => {
  const layout = ociLayout({ layers: [[{ name: 'a', content: 'a' }]] })
  const entries = readTarEntries(layout, DEFAULT_NORMALIZER_LIMITS)
  const index = JSON.parse(readTarEntryBytes(
    layout,
    entries.find(({ path }) => path === 'index.json'),
  ).toString('utf8'))
  const manifestPath = `blobs/sha256/${index.manifests[0].digest.slice('sha256:'.length)}`
  const forged = tar(entries.map((entry) => ({
    name: entry.path,
    content: Buffer.from(readTarEntryBytes(layout, entry)),
    ...(entry.path === manifestPath ? { type: '5' } : {}),
  })))
  const normalized = normalizeOciLayout(forged, DEFAULT_NORMALIZER_LIMITS)
  assert.equal(normalized.format, 'unknown')
  assert.deepEqual(normalized.layers, [])
  assert.ok(normalized.gaps.some(({ reason }) => /directory entry/i.test(reason)))
})

test('a corrupt OCI index cannot manufacture orphan-blob findings', () => {
  const layout = Buffer.from(ociLayout({
    layers: [[{ name: 'a', content: 'a' }]],
    orphan: 'unreferenced payload',
  }))
  const indexEntry = readTarEntries(layout, DEFAULT_NORMALIZER_LIMITS)
    .find(({ path }) => path === 'index.json')
  layout[indexEntry.offset] = 0xff

  const normalized = normalizeOciLayout(layout, DEFAULT_NORMALIZER_LIMITS)
  assert.ok(normalized.gaps.some(({ area }) => area === 'index.json'))
  assert.deepEqual(normalized.orphan_blobs, [])
})

test('every entry carries mode, size, mtime and a content hash', () => {
  const layout = ociLayout({ layers: [[{ name: 'app.js', content: 'console.log(1)', mode: 0o755 }]] })
  const [entry] = normalizeOciLayout(layout, DEFAULT_NORMALIZER_LIMITS).layers[0].entries
  assert.equal(entry.mode, 0o755)
  assert.equal(entry.size, 14)
  assert.equal(typeof entry.mtime, 'number')
  assert.match(entry.sha256, /^[0-9a-f]{64}$/)
})

test('an unreadable layer is a named gap, never a silent drop', () => {
  const layout = ociLayout({ layers: [[{ name: 'a', content: 'a' }]], corruptLayer: true })
  const normalized = normalizeOciLayout(layout, DEFAULT_NORMALIZER_LIMITS)
  assert.equal(normalized.layers.length, 0)
  assert.ok(normalized.gaps.length > 0)
  assert.match(normalized.gaps[0].reason, /decompress|pars|read/i)
})

test('a layer entry whose declared bytes are truncated cannot become a mandatory match', async () => {
  const truncatedLayer = tarHeader({ name: 'app/outlier', size: 200 })
  assert.throws(
    () => readTarEntries(truncatedLayer, DEFAULT_NORMALIZER_LIMITS),
    /beyond the available archive payload/i,
  )
  const archive = ociLayout({ layers: [truncatedLayer] })
  const normalized = normalizeOciLayout(archive, DEFAULT_NORMALIZER_LIMITS)
  assert.equal(normalized.layers.length, 0)
  assert.ok(normalized.gaps.some(({ reason }) => /beyond the available archive payload/i.test(reason)))

  const directory = await mkdtemp(join(tmpdir(), 'rta-oci-truncated-layer-'))
  const source = join(directory, 'image.tar')
  await writeFile(source, archive)
  const adapter = createArtifactAdapter({ clock: () => '2026-08-08T14:22:10Z' })
  const planned = await adapter.plan({
    evidence_id: 'truncated-layer',
    source_path: source,
    target_class: 'LAB',
    phi_scope: 'none',
  })
  const acquired = await adapter.run(planned, { out: join(directory, 'evidence') })
  assert.equal(acquired.profile.coverage_state, 'NOT_ASSESSED')
  const index = await readEvidenceIndex(acquired.directory)
  assert.equal(index.entries.some(({ kind }) => kind === 'layer-entry'), false)
  assert.ok(index.entries.every(({ matched_rule_ids: ruleIds }) => ruleIds.length === 0))
})

test('a docker save tarball is recognised as its own format', () => {
  const archive = tar([
    { name: 'manifest.json', content: JSON.stringify([{ Config: 'c.json', Layers: ['l/layer.tar'] }]) },
    { name: 'c.json', content: JSON.stringify({ history: [], rootfs: { diff_ids: [] } }) },
    { name: 'l/layer.tar', content: tar([{ name: 'x', content: 'x' }]) },
  ])
  const normalized = normalizeOciLayout(archive, DEFAULT_NORMALIZER_LIMITS)
  assert.equal(normalized.format, 'docker-archive')
  assert.equal(normalized.layers.length, 1)
})

test('repeated docker layer paths remain repeated in manifest order', () => {
  const layer = tar([{ name: 'x', content: 'x' }])
  const archive = tar([
    { name: 'manifest.json', content: JSON.stringify([{ Config: 'c.json', Layers: ['l/layer.tar', 'l/layer.tar'] }]) },
    { name: 'c.json', content: JSON.stringify({ history: [], rootfs: { diff_ids: [] } }) },
    { name: 'l/layer.tar', content: layer },
  ])
  const result = normalizeOciArchive(archive, DEFAULT_NORMALIZER_LIMITS)
  assert.equal(result.normalized.layers.length, 2)
  assert.equal(result.normalized.layers[0].digest, result.normalized.layers[1].digest)
  assert.equal(result.resource_usage.verified_blob_cache_entries, 1)
})

test('a gzip-compressed outer OCI archive is decoded once for normalization and payload capture', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'rta-oci-outer-gzip-'))
  const source = join(directory, 'image.tar.gz')
  await writeFile(source, gzipSync(ociLayout({ layers: [[{ name: 'app.txt', content: 'captured' }]] })))
  const adapter = createArtifactAdapter({ clock: () => '2026-08-08T14:22:10Z' })
  const acquired = await adapter.run(await adapter.plan({
    evidence_id: 'outer-gzip',
    source_path: source,
    target_class: 'LAB',
    phi_scope: 'none',
  }), { out: join(directory, 'evidence') })
  assert.equal(acquired.profile.coverage_state, 'COVERED')
  assert.equal(
    await readFile(join(acquired.directory, 'payload', 'layers', '00', 'content', 'app.txt'), 'utf8'),
    'captured',
  )
})

test('artifact content capture stops before the aggregate capture budget is exceeded', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'rta-oci-capture-cap-'))
  const source = join(directory, 'image.tar')
  await writeFile(source, ociLayout({ layers: [[
    { name: 'first.txt', content: '1234' },
    { name: 'second.txt', content: '5678' },
  ]] }))
  const adapter = createArtifactAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    limits: { maxCapturedBytes: 4 },
  })
  const acquired = await adapter.run(await adapter.plan({
    evidence_id: 'capture-cap', source_path: source, target_class: 'LAB', phi_scope: 'none',
  }), { out: join(directory, 'evidence') })
  assert.equal(acquired.profile.coverage_state, 'PARTIAL')
  assert.equal(
    await readFile(join(acquired.directory, 'payload', 'layers', '00', 'content', 'first.txt'), 'utf8'),
    '1234',
  )
  await assert.rejects(() => access(join(acquired.directory, 'payload', 'layers', '00', 'content', 'second.txt')))
  assert.ok(acquired.profile.coverage_gaps.some(({ reason }) => /aggregate.*capture|capture.*budget/i.test(reason)))
  const normalized = JSON.parse(await readFile(join(acquired.directory, 'payload', 'normalized.json'), 'utf8'))
  assert.ok(normalized.gaps.some(({ reason }) => /aggregate.*capture|capture.*budget/i.test(reason)))
  assert.equal(normalized.resource_usage.captured_bytes, 4)
  assert.ok(normalized.resource_usage.inflated_bytes > 0)
})

test('artifact content capture bounds payload file cardinality before manifest publication', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'rta-oci-capture-files-'))
  const source = join(directory, 'image.tar')
  await writeFile(source, ociLayout({ layers: [[
    { name: 'first.txt', content: '1' },
    { name: 'second.txt', content: '2' },
    { name: 'third.txt', content: '3' },
  ]] }))
  const adapter = createArtifactAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    limits: { maxCapturedFiles: 1 },
  })
  const acquired = await adapter.run(await adapter.plan({
    evidence_id: 'capture-files', source_path: source, target_class: 'LAB', phi_scope: 'none',
  }), { out: join(directory, 'evidence') })
  assert.equal(acquired.profile.coverage_state, 'PARTIAL')
  assert.equal(
    acquired.profile.files.filter(({ path }) => path.includes('/content/')).length,
    1,
  )
  assert.ok(acquired.profile.coverage_gaps.some(({ reason }) => /file-count limit of 1/i.test(reason)))
  const normalized = JSON.parse(await readFile(
    join(acquired.directory, 'payload', 'normalized.json'),
    'utf8',
  ))
  assert.equal(normalized.resource_usage.captured_files, 1)
})

test('nonportable and colliding layer names stay listed while optional content capture is gapped', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'rta-oci-portable-paths-'))
  const source = join(directory, 'image.tar')
  const layer = tar([
    { name: 'safe.txt', content: 'safe' },
    { name: 'CON', content: 'reserved' },
    { name: 'stream:ads', content: 'ads' },
    { name: 'trailing.', content: 'dot' },
    { name: 'Case.txt', content: 'first' },
    { name: 'case.txt', content: 'collision' },
  ])
  await writeFile(source, tar([
    { name: 'manifest.json', content: JSON.stringify([{ Config: 'config.json', Layers: ['layer.tar'] }]) },
    { name: 'config.json', content: JSON.stringify({ history: [], rootfs: { diff_ids: [] } }) },
    { name: 'layer.tar', content: layer },
  ]))
  const adapter = createArtifactAdapter({ clock: () => '2026-08-08T14:22:10Z' })
  const acquired = await adapter.run(await adapter.plan({
    evidence_id: 'portable-paths', source_path: source, target_class: 'LAB', phi_scope: 'none',
  }), { out: join(directory, 'evidence') })
  assert.equal(acquired.profile.coverage_state, 'PARTIAL')
  const listed = JSON.parse(await readFile(
    join(acquired.directory, 'payload', 'layers', '00', 'entries.json'),
    'utf8',
  ))
  assert.deepEqual(listed.map(({ path }) => path), [
    'safe.txt', 'CON', 'stream:ads', 'trailing.', 'Case.txt', 'case.txt',
  ])
  const published = acquired.profile.files.map(({ path }) => path)
  assert.ok(published.includes('payload/layers/00/content/safe.txt'))
  assert.ok(published.includes('payload/layers/00/content/Case.txt'))
  assert.equal(published.some((path) => /\/(?:CON|stream:ads|trailing\.|case\.txt)$/.test(path)), false)
  assert.ok(acquired.profile.coverage_gaps.some(({ reason }) => /not portable/i.test(reason)))
  assert.ok(acquired.profile.coverage_gaps.some(({ reason }) => /collides/i.test(reason)))
})

test('every platform manifest and nested index is traversed without false orphan blobs', () => {
  for (const nested of [false, true]) {
    const normalized = normalizeOciLayout(
      multiPlatformOciLayout({ nested }),
      DEFAULT_NORMALIZER_LIMITS,
    )
    assert.equal(normalized.layers.length, 2)
    assert.deepEqual(
      normalized.config.history.map(({ created_by: command }) => command),
      ['BUILD amd64', 'BUILD arm64'],
    )
    assert.deepEqual(normalized.orphan_blobs, [])
    assert.deepEqual(normalized.gaps, [])
  }
})

test('nested OCI indexes preserve depth-first descriptor occurrence order', () => {
  const normalized = normalizeOciLayout(
    multiPlatformOciLayout({ nestedFirst: true }),
    DEFAULT_NORMALIZER_LIMITS,
  )
  assert.deepEqual(
    normalized.config.history.map(({ created_by: command }) => command),
    ['BUILD amd64', 'BUILD arm64'],
  )
  assert.deepEqual(
    normalized.layers.map(({ entries }) => entries[0].path),
    ['app/amd64.txt', 'app/arm64.txt'],
  )
})

test('OCI blob paths do not substitute for content-address verification', () => {
  const layout = Buffer.from(multiPlatformOciLayout())
  const blob = readTarEntries(layout, DEFAULT_NORMALIZER_LIMITS)
    .find(({ path }) => path.startsWith('blobs/sha256/'))
  layout[blob.offset] ^= 0xff

  const normalized = normalizeOciLayout(layout, DEFAULT_NORMALIZER_LIMITS)
  assert.ok(normalized.gaps.some(({ reason }) => /does not match.*sha256 digest/i.test(reason)))
  assert.ok(normalized.layers.length < 2)
  assert.deepEqual(normalized.orphan_blobs, [])
})

test('the manifest traversal cap is explicit and suppresses incomplete orphan classification', () => {
  const normalized = normalizeOciLayout(multiPlatformOciLayout(), {
    ...DEFAULT_NORMALIZER_LIMITS,
    maxManifests: 1,
  })
  assert.equal(normalized.layers.length, 1)
  assert.deepEqual(normalized.orphan_blobs, [])
  assert.ok(normalized.gaps.some(({ area, reason }) =>
    area === 'manifests' && /bounded limit/i.test(reason)))
})

test('a huge malformed top descriptor array is inspected only to its aggregate cap', () => {
  const layout = ociLayout({ layers: [] })
  const entries = readTarEntries(layout, DEFAULT_NORMALIZER_LIMITS)
  const archive = tar(entries.map((entry) => ({
    name: entry.path,
    content: entry.path === 'index.json'
      ? JSON.stringify({ schemaVersion: 2, manifests: Array.from({ length: 200_000 }, () => null) })
      : Buffer.from(readTarEntryBytes(layout, entry)),
  })))
  const normalized = normalizeOciLayout(archive, {
    ...DEFAULT_NORMALIZER_LIMITS,
    maxManifests: 4,
  })
  assert.deepEqual(normalized.top_level_digests, [])
  assert.deepEqual(normalized.orphan_blobs, [])
  assert.equal(normalized.gaps.filter(({ reason }) => /index descriptor has no digest/i.test(reason)).length, 4)
  assert.equal(normalized.gaps.filter(({ reason }) => /199996 manifest descriptor/i.test(reason)).length, 1)
})

test('invalid OCI layer occurrences consume the same aggregate cap as valid descriptors', () => {
  const blobs = new Map()
  const put = (value) => {
    const bytes = Buffer.from(JSON.stringify(value))
    const digest = `sha256:${sha256(bytes)}`
    blobs.set(digest, bytes)
    return { digest, size: bytes.length }
  }
  const config = put({ history: [], rootfs: { diff_ids: [] } })
  const manifests = []
  for (let image = 0; image < 2; image += 1) {
    manifests.push({
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
      ...put({
        schemaVersion: 2,
        config,
        layers: Array.from({ length: 200 }, () => null),
      }),
    })
  }
  const archive = tar([
    { name: 'oci-layout', content: JSON.stringify({ imageLayoutVersion: '1.0.0' }) },
    { name: 'index.json', content: JSON.stringify({ schemaVersion: 2, manifests }) },
    ...[...blobs].map(([digest, content]) => ({
      name: `blobs/sha256/${digest.slice(7)}`,
      content,
    })),
  ])
  const normalized = normalizeOciLayout(archive, {
    ...DEFAULT_NORMALIZER_LIMITS,
    maxLayers: 4,
  })
  assert.equal(normalized.gaps.filter(({ reason }) => /layer descriptor with no digest/i.test(reason)).length, 4)
  assert.equal(normalized.gaps.filter(({ reason }) => /396 ordered layer occurrence/i.test(reason)).length, 1)
})

test('invalid docker layer occurrences consume the same aggregate cap as valid paths', () => {
  const archive = tar([
    {
      name: 'manifest.json',
      content: JSON.stringify([
        { Config: 'one.json', Layers: Array.from({ length: 200 }, () => null) },
        { Config: 'two.json', Layers: Array.from({ length: 200 }, () => null) },
      ]),
    },
    { name: 'one.json', content: JSON.stringify({ history: [], rootfs: { diff_ids: [] } }) },
    { name: 'two.json', content: JSON.stringify({ history: [], rootfs: { diff_ids: [] } }) },
  ])
  const normalized = normalizeOciLayout(archive, {
    ...DEFAULT_NORMALIZER_LIMITS,
    maxLayers: 4,
  })
  assert.equal(normalized.gaps.filter(({ reason }) => /layer with no path/i.test(reason)).length, 4)
  assert.equal(normalized.gaps.filter(({ reason }) => /396 ordered layer occurrence/i.test(reason)).length, 1)
})

test('a mixed valid and digestless OCI layer is a named PARTIAL acquisition gap', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'rta-oci-malformed-'))
  const source = join(directory, 'image.tar')
  await writeFile(source, multiPlatformOciLayout({ digestlessLayer: true }))
  const adapter = createArtifactAdapter({ clock: () => '2026-08-08T14:22:10Z' })
  const planned = await adapter.plan({
    evidence_id: 'malformed-multi-platform',
    source_path: source,
    target_class: 'LAB',
    phi_scope: 'none',
  })
  const acquired = await adapter.run(planned, { out: join(directory, 'evidence') })
  assert.equal(acquired.profile.coverage_state, 'PARTIAL')
  assert.ok(acquired.profile.coverage_gaps.some(({ reason }) => /no digest/i.test(reason)))
})

test('every image in a docker-save archive contributes config history and layers', () => {
  const archive = tar([
    {
      name: 'manifest.json',
      content: JSON.stringify([
        { Config: 'amd64.json', Layers: ['amd64/layer.tar'] },
        { Config: 'arm64.json', Layers: ['arm64/layer.tar'] },
      ]),
    },
    {
      name: 'amd64.json',
      content: JSON.stringify({
        history: [{ created_by: 'BUILD amd64' }],
        rootfs: { diff_ids: ['sha256:amd64'] },
      }),
    },
    {
      name: 'arm64.json',
      content: JSON.stringify({
        history: [{ created_by: 'BUILD arm64' }],
        rootfs: { diff_ids: ['sha256:arm64'] },
      }),
    },
    { name: 'amd64/layer.tar', content: tar([{ name: 'amd64', content: 'a' }]) },
    { name: 'arm64/layer.tar', content: tar([{ name: 'arm64', content: 'b' }]) },
  ])
  const normalized = normalizeOciLayout(archive, DEFAULT_NORMALIZER_LIMITS)
  assert.equal(normalized.layers.length, 2)
  assert.deepEqual(
    normalized.config.history.map(({ created_by: command }) => command),
    ['BUILD amd64', 'BUILD arm64'],
  )
  assert.deepEqual(normalized.gaps, [])
})

test('the docker-save image cap is explicit rather than silently selecting image zero', () => {
  const archive = tar([
    {
      name: 'manifest.json',
      content: JSON.stringify([
        { Config: 'one.json', Layers: ['one.tar'] },
        { Config: 'two.json', Layers: ['two.tar'] },
      ]),
    },
    { name: 'one.json', content: JSON.stringify({ history: [], rootfs: { diff_ids: [] } }) },
    { name: 'two.json', content: JSON.stringify({ history: [], rootfs: { diff_ids: [] } }) },
    { name: 'one.tar', content: tar([{ name: 'one', content: '1' }]) },
    { name: 'two.tar', content: tar([{ name: 'two', content: '2' }]) },
  ])
  const normalized = normalizeOciLayout(archive, {
    ...DEFAULT_NORMALIZER_LIMITS,
    maxManifests: 1,
  })
  assert.equal(normalized.layers.length, 1)
  assert.ok(normalized.gaps.some(({ area, reason }) =>
    area === 'manifests' && /bounded limit/i.test(reason)))
})
