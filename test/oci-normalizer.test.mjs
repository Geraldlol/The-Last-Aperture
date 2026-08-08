import { test } from 'node:test'
import assert from 'node:assert/strict'
import { gzipSync } from 'node:zlib'
import { createHash } from 'node:crypto'
import {
  DEFAULT_NORMALIZER_LIMITS,
  normalizeOciLayout,
  readTarEntries,
  readTarEntryBytes,
} from '../scripts/lib/oci-normalizer.mjs'

function tarHeader({ name, size, mode = 0o644, mtime = 1754661730, type = '0', linkname = '' }) {
  const header = Buffer.alloc(512)
  header.write(name, 0, 100, 'utf8')
  header.write(`${mode.toString(8).padStart(7, '0')}\0`, 100, 8, 'ascii')
  header.write('0000000\0', 108, 8, 'ascii')
  header.write('0000000\0', 116, 8, 'ascii')
  header.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 12, 'ascii')
  header.write(`${mtime.toString(8).padStart(11, '0')}\0`, 136, 12, 'ascii')
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

test('the entry reader refuses a path that escapes the archive root', () => {
  const archive = tar([{ name: '../../etc/shadow', content: 'x' }])
  assert.throws(() => readTarEntries(archive, DEFAULT_NORMALIZER_LIMITS), /escape/i)
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

function ociLayout({ layers, historyEntry = 'RUN rm /secret.txt', orphan = null, corruptLayer = false }) {
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
      : gzipSync(tar(entries))
    return {
      mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip',
      digest: put(compressed),
      size: compressed.length,
    }
  })
  const config = Buffer.from(JSON.stringify({
    architecture: 'amd64',
    os: 'linux',
    history: [{ created_by: 'FROM alpine' }, { created_by: historyEntry }],
    rootfs: { type: 'layers', diff_ids: layerDescriptors.map(({ digest }) => digest) },
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

test('a blob no manifest references is reported, not dropped', () => {
  const layout = ociLayout({
    layers: [[{ name: 'a', content: 'a' }]],
    orphan: 'unreferenced payload',
  })
  const normalized = normalizeOciLayout(layout, DEFAULT_NORMALIZER_LIMITS)
  assert.equal(normalized.orphan_blobs.length, 1)
  assert.ok(normalized.orphan_blobs[0].size > 0)
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
