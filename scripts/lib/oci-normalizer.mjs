import { createHash } from 'node:crypto'
import { gunzipSync } from 'node:zlib'
import { compareCanonicalStrings } from './canonical-order.mjs'

export const DEFAULT_NORMALIZER_LIMITS = Object.freeze({
  maxEntries: 200000,
  maxEntryBytes: 8 * 1024 * 1024,
  maxTotalBytes: 512 * 1024 * 1024,
  maxLayers: 256,
})

const BLOCK = 512
const TYPE_BY_FLAG = new Map([
  ['0', 'file'],
  ['\0', 'file'],
  ['1', 'hardlink'],
  ['2', 'symlink'],
  ['5', 'directory'],
])

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function readString(block, offset, length) {
  const slice = block.subarray(offset, offset + length)
  const end = slice.indexOf(0)
  return slice.subarray(0, end === -1 ? slice.length : end).toString('utf8')
}

function readOctal(block, offset, length) {
  const text = readString(block, offset, length).trim()
  if (text === '') return 0
  const value = Number.parseInt(text, 8)
  return Number.isFinite(value) ? value : 0
}

// An archive is untrusted input. A path that escapes its own root would let a
// normalized bundle name a file outside the bundle, and every later locator
// resolves through these paths.
function assertContainedPath(path) {
  const normalized = path.replaceAll('\\', '/')
  const segments = normalized.split('/')
  if (
    normalized.startsWith('/')
    || /^[A-Za-z]:/.test(normalized)
    || segments.includes('..')
  ) {
    throw new RangeError(`archive entry path would escape the archive root: ${path}`)
  }
  return normalized
}

export function readTarEntries(buffer, limits = DEFAULT_NORMALIZER_LIMITS) {
  const entries = []
  let offset = 0
  let totalBytes = 0
  while (offset + BLOCK <= buffer.length) {
    const header = buffer.subarray(offset, offset + BLOCK)
    if (header.every((byte) => byte === 0)) break

    const prefix = readString(header, 345, 155)
    const name = readString(header, 0, 100)
    const path = assertContainedPath(prefix ? `${prefix}/${name}` : name)
    const size = readOctal(header, 124, 12)

    if (entries.length + 1 > limits.maxEntries) {
      throw new RangeError(`archive exceeds the bounded limit of ${limits.maxEntries} entries`)
    }
    if (size > limits.maxEntryBytes) {
      throw new RangeError(
        `archive entry ${path} is ${size} bytes, above the bounded limit of `
        + `${limits.maxEntryBytes} bytes`,
      )
    }
    totalBytes += size
    if (totalBytes > limits.maxTotalBytes) {
      throw new RangeError(`archive exceeds the bounded limit of ${limits.maxTotalBytes} bytes`)
    }

    const flag = String.fromCharCode(header[156])
    entries.push({
      path,
      mode: readOctal(header, 100, 8) & 0o7777,
      size,
      mtime: readOctal(header, 136, 12),
      type: TYPE_BY_FLAG.get(flag) ?? 'other',
      link_target: readString(header, 157, 100),
      offset: offset + BLOCK,
    })
    offset += BLOCK + Math.ceil(size / BLOCK) * BLOCK
  }
  return entries
}

export function readTarEntryBytes(buffer, entry) {
  return buffer.subarray(entry.offset, entry.offset + entry.size)
}

function decompressIfGzipped(bytes) {
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) return gunzipSync(bytes)
  return bytes
}

// An OCI whiteout is a 0-byte entry named .wh.<name>. A file merely named
// .wh.something that carries content is not a whiteout; it is a file hiding
// behind the convention, and distinguishing the two is exactly what a
// source-only audit cannot do.
function isWhiteout(entry) {
  return entry.type === 'file'
    && entry.size === 0
    && entry.path.split('/').at(-1).startsWith('.wh.')
}

export function normalizeLayerEntries(bytes, limits = DEFAULT_NORMALIZER_LIMITS) {
  const archive = decompressIfGzipped(bytes)
  return readTarEntries(archive, limits).map((entry) => ({
    path: entry.path,
    mode: entry.mode,
    size: entry.size,
    mtime: entry.mtime,
    type: entry.type,
    link_target: entry.link_target,
    sha256: entry.type === 'file' ? sha256(readTarEntryBytes(archive, entry)) : null,
    whiteout: isWhiteout(entry),
  }))
}

/**
 * The decompressed bytes of one layer blob, or null when it cannot be read.
 * Returning null rather than throwing keeps one bad layer from discarding the
 * rest of the image.
 */
export function layerContentBytes(archive, layer, byPath) {
  const suffix = String(layer.digest).replace(/^sha256:/, '')
  const entry = byPath.get(`blobs/sha256/${suffix}`) ?? byPath.get(layer.source_path)
  if (!entry) return null
  try {
    return decompressIfGzipped(readTarEntryBytes(archive, entry))
  } catch {
    return null
  }
}

function parseJsonEntry(archive, entry, label, gaps) {
  if (!entry) {
    gaps.push({ area: label, reason: `could not read ${label}: it is absent from the archive` })
    return null
  }
  try {
    return JSON.parse(readTarEntryBytes(archive, entry).toString('utf8'))
  } catch (error) {
    gaps.push({ area: label, reason: `could not parse ${label}: ${error.message}` })
    return null
  }
}

function normalizeOci(archive, byPath, limits, gaps) {
  const index = parseJsonEntry(archive, byPath.get('index.json'), 'index.json', gaps)
  const referenced = new Set()
  const blobEntry = (digest) => {
    referenced.add(digest)
    return byPath.get(`blobs/sha256/${String(digest).replace(/^sha256:/, '')}`)
  }

  const manifestDescriptor = index?.manifests?.[0]
  const manifestEntry = manifestDescriptor && blobEntry(manifestDescriptor.digest)
  const manifest = manifestEntry
    ? parseJsonEntry(archive, manifestEntry, 'image manifest', gaps)
    : null
  if (!manifest) {
    gaps.push({ area: 'manifest', reason: 'the layout declares no readable image manifest' })
  }

  const configEntry = manifest?.config?.digest && blobEntry(manifest.config.digest)
  const configJson = configEntry
    ? parseJsonEntry(archive, configEntry, 'image config', gaps)
    : null

  const descriptors = (manifest?.layers ?? []).slice(0, limits.maxLayers)
  if ((manifest?.layers ?? []).length > limits.maxLayers) {
    gaps.push({
      area: 'layers',
      reason: `image declares ${manifest.layers.length} layers, above the bounded limit of `
        + `${limits.maxLayers}; the remainder was not read`,
    })
  }

  const layers = []
  for (const [index_, descriptor] of descriptors.entries()) {
    const entry = blobEntry(descriptor.digest)
    if (!entry) {
      gaps.push({ area: `layer ${index_}`, reason: `blob ${descriptor.digest} is absent from the layout` })
      continue
    }
    let entries
    try {
      entries = normalizeLayerEntries(readTarEntryBytes(archive, entry), limits)
    } catch (error) {
      gaps.push({ area: `layer ${index_}`, reason: `could not decompress or read layer: ${error.message}` })
      continue
    }
    layers.push({
      index: index_,
      digest: descriptor.digest,
      source_path: `blobs/sha256/${String(descriptor.digest).replace(/^sha256:/, '')}`,
      media_type: descriptor.mediaType ?? null,
      entry_count: entries.length,
      entries,
    })
  }

  const orphans = []
  for (const [path, entry] of byPath) {
    if (!path.startsWith('blobs/sha256/')) continue
    if (referenced.has(`sha256:${path.slice('blobs/sha256/'.length)}`)) continue
    orphans.push({ digest: `sha256:${path.slice('blobs/sha256/'.length)}`, size: entry.size })
  }
  orphans.sort((left, right) => compareCanonicalStrings(left.digest, right.digest))

  return {
    format: 'oci-layout',
    config: {
      digest: manifest?.config?.digest ?? null,
      history: configJson?.history ?? [],
      diff_ids: configJson?.rootfs?.diff_ids ?? [],
    },
    layers,
    orphan_blobs: orphans,
    gaps,
  }
}

function normalizeDockerArchive(archive, byPath, limits, gaps) {
  const manifest = parseJsonEntry(archive, byPath.get('manifest.json'), 'manifest.json', gaps)
  const image = Array.isArray(manifest) ? manifest[0] : null
  const configEntry = image?.Config && byPath.get(image.Config)
  const configJson = configEntry
    ? parseJsonEntry(archive, configEntry, 'image config', gaps)
    : null

  const layers = []
  for (const [index_, layerPath] of (image?.Layers ?? []).slice(0, limits.maxLayers).entries()) {
    const entry = byPath.get(layerPath)
    if (!entry) {
      gaps.push({ area: `layer ${index_}`, reason: `${layerPath} is absent from the archive` })
      continue
    }
    let entries
    try {
      entries = normalizeLayerEntries(readTarEntryBytes(archive, entry), limits)
    } catch (error) {
      gaps.push({ area: `layer ${index_}`, reason: `could not decompress or read layer: ${error.message}` })
      continue
    }
    layers.push({
      index: index_,
      digest: `sha256:${sha256(readTarEntryBytes(archive, entry))}`,
      source_path: layerPath,
      media_type: 'application/vnd.docker.image.rootfs.diff.tar',
      entry_count: entries.length,
      entries,
    })
  }

  return {
    format: 'docker-archive',
    config: {
      digest: null,
      history: configJson?.history ?? [],
      diff_ids: configJson?.rootfs?.diff_ids ?? [],
    },
    layers,
    orphan_blobs: [],
    gaps,
  }
}

/**
 * Converts an OCI layout or docker-save tarball into something the packet
 * model can scope and a provider can read. Providers cannot run tar, so
 * without this `next` has nothing to hand them.
 *
 * Ambiguity is fail-closed: an archive that looks like neither format yields
 * no layers and a named gap, never a confident empty result.
 */
export function normalizeOciLayout(buffer, limits = DEFAULT_NORMALIZER_LIMITS) {
  const gaps = []
  const archive = decompressIfGzipped(buffer)
  const entries = readTarEntries(archive, limits)
  const byPath = new Map(entries.map((entry) => [entry.path, entry]))

  if (byPath.has('index.json') && byPath.has('oci-layout')) {
    return normalizeOci(archive, byPath, limits, gaps)
  }
  if (byPath.has('manifest.json')) {
    return normalizeDockerArchive(archive, byPath, limits, gaps)
  }
  gaps.push({
    area: 'format',
    reason: 'the archive is neither an OCI layout nor a docker-save tarball; '
      + 'no layer structure could be read',
  })
  return { format: 'unknown', config: { digest: null, history: [], diff_ids: [] }, layers: [], orphan_blobs: [], gaps }
}
