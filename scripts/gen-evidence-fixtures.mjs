#!/usr/bin/env node
import { createHash } from 'node:crypto'
import { mkdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { gzipSync } from 'node:zlib'
import { isMainModule } from './lib/main-module.mjs'
import { terminalSafeText } from './lib/terminal-text.mjs'

// Deterministic: every timestamp is a constant, so a rebuilt fixture is
// byte-identical and the drift test means something. Date.now() would make the
// committed bytes unreproducible.
const BASE_MTIME = 1754661730
const SECRET = (name) => `FIXTURE-NOT-A-REAL-SECRET-${name}`

function tarHeader({ name, size, mode = 0o644, mtime = BASE_MTIME, type = '0', linkname = '' }) {
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

function ociLayout({ layerEntrySets, history, orphan }) {
  const blobs = []
  const put = (bytes) => {
    const digest = `sha256:${sha256(bytes)}`
    blobs.push({ digest, bytes })
    return digest
  }
  const layerDescriptors = layerEntrySets.map((entries) => {
    // Fix both variable gzip header fields: mtime and the compressor's host OS.
    // RFC 1952 reserves 255 for an unspecified OS; this metadata byte is outside
    // the compressed data and its CRC, so payload and decompression are unchanged.
    const compressed = gzipSync(tar(entries), { level: 9, mtime: 0 })
    compressed[9] = 255
    return {
      mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip',
      digest: put(compressed),
      size: compressed.length,
    }
  })
  const config = Buffer.from(JSON.stringify({
    architecture: 'amd64',
    os: 'linux',
    history,
    rootfs: { type: 'layers', diff_ids: layerDescriptors.map(({ digest }) => digest) },
  }), 'utf8')
  const configDigest = put(config)
  const manifest = Buffer.from(JSON.stringify({
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    config: {
      mediaType: 'application/vnd.oci.image.config.v1+json',
      digest: configDigest,
      size: config.length,
    },
    layers: layerDescriptors,
  }), 'utf8')
  const manifestDigest = put(manifest)
  if (orphan !== undefined) put(Buffer.from(orphan, 'utf8'))
  const index = Buffer.from(JSON.stringify({
    schemaVersion: 2,
    manifests: [{
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
      digest: manifestDigest,
      size: manifest.length,
    }],
  }), 'utf8')

  return tar([
    { name: 'oci-layout', content: JSON.stringify({ imageLayoutVersion: '1.0.0' }) },
    { name: 'index.json', content: index },
    ...blobs.map(({ digest, bytes }) => ({
      name: `blobs/sha256/${digest.slice(7)}`,
      content: bytes,
    })),
  ])
}

// Five uniform SBOM siblings; in the vulnerable image exactly one deviates in
// both size and mtime, which is the pattern a human reads as cleanup noise.
function sbomSiblings({ outlier }) {
  const uniform = JSON.stringify({ spdxVersion: 'SPDX-2.3', name: 'pkg' })
  const names = ['busybox-1.36', 'musl-1.2', 'openssl-3.1', 'zlib-1.3', 'zsh-5.9r7']
  return names.map((name) => {
    const isOutlier = outlier && name === 'zsh-5.9r7'
    // Pattern 4 lives inside the outlier: base64 of base64 of the planted string.
    const inner = Buffer.from(SECRET('recursive-payload'), 'utf8').toString('base64')
    const payload = Buffer.from(inner, 'utf8').toString('base64')
    return {
      name: `var/lib/db/sbom/${name}.spdx.json`,
      content: isOutlier ? JSON.stringify({ spdxVersion: 'SPDX-2.3', name, blob: payload }) : uniform,
      mtime: isOutlier ? BASE_MTIME + 8371 : BASE_MTIME,
      mode: 0o644,
    }
  })
}

export async function buildEvidenceFixtures(outDirectory) {
  await mkdir(outDirectory, { recursive: true })

  const vulnerable = ociLayout({
    layerEntrySets: [
      [
        { name: 'build-secret.txt', content: SECRET('layer-below-whiteout'), mode: 0o600 },
        { name: 'audit-log.txt', content: 'startup ok\n', mode: 0o664 },
        ...sbomSiblings({ outlier: true }),
      ],
      [
        { name: '.wh.build-secret.txt', content: '', mode: 0o600 },
        { name: '.wh.audit-log.txt', content: 'not actually a whiteout\n', mode: 0o664 },
      ],
    ],
    history: [
      { created_by: 'FROM alpine:3.19' },
      { created_by: `RUN export DEPLOY_TOKEN=${SECRET('config-history')} && ./deploy.sh` },
      { created_by: 'RUN rm /build-secret.txt' },
    ],
    orphan: 'unreferenced blob content',
  })

  const clean = ociLayout({
    layerEntrySets: [
      [
        { name: 'audit-log.txt', content: 'startup ok\n', mode: 0o664 },
        ...sbomSiblings({ outlier: false }),
      ],
    ],
    history: [
      { created_by: 'FROM alpine:3.19' },
      { created_by: 'RUN ./deploy.sh' },
    ],
  })

  const paths = {
    vulnerable: join(outDirectory, 'vulnerable-image.tar'),
    clean: join(outDirectory, 'clean-image.tar'),
  }
  await writeFile(paths.vulnerable, vulnerable)
  await writeFile(paths.clean, clean)
  return paths
}

if (isMainModule(import.meta.url)) {
  const out = process.argv[2] ?? 'test/fixtures/evidence'
  const written = await buildEvidenceFixtures(out)
  for (const [name, path] of Object.entries(written)) {
    console.log(`${terminalSafeText(name, 128)}: ${terminalSafeText(path)}`)
  }
}
