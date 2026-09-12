import { createHash } from 'node:crypto'
import { gunzipSync } from 'node:zlib'
import { compareCanonicalStrings } from './canonical-order.mjs'

export const DEFAULT_NORMALIZER_LIMITS = Object.freeze({
  maxEntries: 200000,
  maxEntryBytes: 8 * 1024 * 1024,
  maxTotalBytes: 512 * 1024 * 1024,
  maxManifests: 64,
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
  if (!/^[0-7]+$/.test(text)) {
    throw new RangeError(`tar header contains an unsupported octal value: ${text}`)
  }
  const value = Number.parseInt(text, 8)
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`tar header octal value is outside the safe integer range: ${text}`)
  }
  return value
}

function readTarNumber(block, offset, length, { allowNegative = false } = {}) {
  const field = block.subarray(offset, offset + length)
  if ((field[0] & 0x80) === 0) return readOctal(block, offset, length)

  // GNU/POSIX tar uses 0x80 plus an unsigned big-endian payload for positive
  // base-256 values and 0xff plus a two's-complement payload for negatives.
  // Size fields remain non-negative; mtimes may validly predate the epoch.
  if (field[0] !== 0x80 && field[0] !== 0xff) {
    throw new RangeError('tar header contains an unsupported base-256 value')
  }
  let value = 0n
  for (const byte of field.subarray(1)) value = (value << 8n) | BigInt(byte)
  if (field[0] === 0xff) value -= 1n << BigInt((length - 1) * 8)
  if ((!allowNegative && value < 0n)
    || value < BigInt(Number.MIN_SAFE_INTEGER)
    || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new RangeError('tar header base-256 value is outside the supported safe integer range')
  }
  return Number(value)
}

function assertTarHeaderChecksum(header) {
  const expected = readOctal(header, 148, 8)
  let actual = 0
  for (let index = 0; index < header.length; index += 1) {
    actual += index >= 148 && index < 156 ? 0x20 : header[index]
  }
  if (actual !== expected) {
    throw new RangeError(`tar header checksum mismatch: declared ${expected}, calculated ${actual}`)
  }
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
  const seenPaths = new Set()
  let offset = 0
  let totalBytes = 0
  while (offset + BLOCK <= buffer.length) {
    const header = buffer.subarray(offset, offset + BLOCK)
    if (header.every((byte) => byte === 0)) {
      const trailing = buffer.subarray(offset)
      if (trailing.length % BLOCK !== 0) {
        throw new RangeError('archive contains a partial trailing block after the tar terminator')
      }
      if (trailing.some((byte) => byte !== 0)) {
        throw new RangeError('archive contains nonzero data after the tar terminator')
      }
      offset = buffer.length
      break
    }
    assertTarHeaderChecksum(header)

    const prefix = readString(header, 345, 155)
    const name = readString(header, 0, 100)
    const path = assertContainedPath(prefix ? `${prefix}/${name}` : name)
    const size = readTarNumber(header, 124, 12)

    if (seenPaths.has(path)) {
      throw new RangeError(`archive contains duplicate normalized path: ${path}`)
    }
    seenPaths.add(path)

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
    const contentOffset = offset + BLOCK
    const paddedEnd = contentOffset + Math.ceil(size / BLOCK) * BLOCK
    if (contentOffset + size > buffer.length || paddedEnd > buffer.length) {
      throw new RangeError(
        `archive entry ${path} declares ${size} bytes beyond the available archive payload`,
      )
    }
    entries.push({
      path,
      mode: readOctal(header, 100, 8) & 0o7777,
      size,
      mtime: readTarNumber(header, 136, 12, { allowNegative: true }),
      type: TYPE_BY_FLAG.get(flag) ?? 'other',
      link_target: readString(header, 157, 100),
      offset: contentOffset,
    })
    offset = paddedEnd
  }
  if (entries.length > 0 && offset !== buffer.length) {
    throw new RangeError('archive contains a partial trailing block without a complete tar header')
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
  const resolveBlob = (descriptor, area) => {
    const digest = descriptor?.digest
    const match = /^sha256:([0-9a-f]{64})$/.exec(String(digest ?? ''))
    if (!match) {
      gaps.push({ area, reason: `${area} has no supported canonical sha256 digest` })
      return null
    }
    const path = `blobs/sha256/${match[1]}`
    const entry = byPath.get(path)
    if (!entry) {
      gaps.push({ area, reason: `blob ${digest} is absent from the layout` })
      return null
    }
    if (!Number.isSafeInteger(descriptor.size) || descriptor.size < 0) {
      gaps.push({ area, reason: `descriptor ${digest} has no valid byte size` })
      return null
    }
    if (descriptor.size !== entry.size) {
      gaps.push({
        area,
        reason: `descriptor ${digest} declares ${descriptor.size} bytes but the blob has ${entry.size}`,
      })
      return null
    }
    const actualDigest = sha256(readTarEntryBytes(archive, entry))
    if (actualDigest !== match[1]) {
      gaps.push({
        area,
        reason: `blob ${digest} content does not match its declared sha256 digest`,
      })
      return null
    }
    return entry
  }
  const descriptors = Array.isArray(index?.manifests) ? index.manifests : []
  if (descriptors.length === 0) {
    gaps.push({ area: 'manifest', reason: 'the layout declares no image manifest descriptor' })
  }
  const queue = []
  // Absence of references is meaningful only when index.json itself supplied
  // a valid descriptor list. A corrupt index does not turn every blob in the
  // archive into a proven orphan.
  let referenceGraphComplete = index !== null
    && typeof index === 'object'
    && !Array.isArray(index)
    && Array.isArray(index.manifests)
  for (const descriptor of descriptors) {
    if (typeof descriptor?.digest !== 'string') {
      referenceGraphComplete = false
      gaps.push({ area: 'manifest', reason: 'an index descriptor has no digest' })
      continue
    }
    referenced.add(descriptor.digest)
    queue.push(descriptor)
  }
  const imageManifests = []
  const visitedDescriptors = new Set()
  let traversedDescriptors = 0
  let skippedDescriptors = 0
  while (queue.length > 0) {
    const descriptor = queue.shift()
    if (visitedDescriptors.has(descriptor.digest)) continue
    visitedDescriptors.add(descriptor.digest)
    if (traversedDescriptors >= limits.maxManifests) {
      skippedDescriptors += 1
      referenceGraphComplete = false
      continue
    }
    traversedDescriptors += 1
    const entry = resolveBlob(descriptor, `manifest ${descriptor.digest}`)
    const document = entry
      ? parseJsonEntry(archive, entry, `manifest ${descriptor.digest}`, gaps)
      : null
    if (!document) {
      referenceGraphComplete = false
      continue
    }
    if (Array.isArray(document.manifests)) {
      for (const child of document.manifests) {
        if (typeof child?.digest !== 'string') {
          referenceGraphComplete = false
          gaps.push({ area: 'manifest', reason: 'a nested index descriptor has no digest' })
          continue
        }
        referenced.add(child.digest)
        queue.push(child)
      }
      continue
    }
    if (!Array.isArray(document.layers) || typeof document.config?.digest !== 'string') {
      referenceGraphComplete = false
      gaps.push({
        area: 'manifest',
        reason: `blob ${descriptor.digest} is neither an image manifest nor an image index`,
      })
      continue
    }
    referenced.add(document.config.digest)
    for (const layer of document.layers) {
      if (typeof layer?.digest === 'string') referenced.add(layer.digest)
      else {
        referenceGraphComplete = false
        gaps.push({
          area: 'manifest',
          reason: `image manifest ${descriptor.digest} contains a layer descriptor with no digest`,
        })
      }
    }
    imageManifests.push(document)
  }
  if (skippedDescriptors > 0) {
    gaps.push({
      area: 'manifests',
      reason: `${skippedDescriptors} manifest descriptor(s) exceeded the bounded limit of `
        + `${limits.maxManifests}; their reference graphs were not read`,
    })
  }
  if (imageManifests.length === 0) {
    gaps.push({ area: 'manifest', reason: 'the layout declares no readable image manifest' })
  }

  const histories = []
  const diffIds = []
  const configDigests = []
  const seenConfigs = new Set()
  for (const manifest of imageManifests) {
    const digest = manifest.config.digest
    const entry = resolveBlob(manifest.config, `image config ${digest}`)
    if (seenConfigs.has(digest)) {
      if (!entry) referenceGraphComplete = false
      continue
    }
    seenConfigs.add(digest)
    configDigests.push(digest)
    const config = entry
      ? parseJsonEntry(archive, entry, `image config ${digest}`, gaps)
      : null
    if (!entry) referenceGraphComplete = false
    if (Array.isArray(config?.history)) histories.push(...config.history)
    if (Array.isArray(config?.rootfs?.diff_ids)) diffIds.push(...config.rootfs.diff_ids)
  }

  const layerDescriptors = []
  const seenLayers = new Set()
  for (const manifest of imageManifests) {
    for (const descriptor of manifest.layers) {
      if (typeof descriptor?.digest !== 'string') continue
      if (seenLayers.has(descriptor.digest)) {
        if (!resolveBlob(descriptor, `layer descriptor ${descriptor.digest}`)) {
          referenceGraphComplete = false
        }
        continue
      }
      seenLayers.add(descriptor.digest)
      layerDescriptors.push(descriptor)
    }
  }
  const selectedLayers = layerDescriptors.slice(0, limits.maxLayers)
  if (layerDescriptors.length > limits.maxLayers) {
    gaps.push({
      area: 'layers',
      reason: `image set declares ${layerDescriptors.length} unique layers, above the bounded limit of `
        + `${limits.maxLayers}; the remainder was not read`,
    })
  }

  const layers = []
  for (const [index_, descriptor] of selectedLayers.entries()) {
    const entry = resolveBlob(descriptor, `layer ${index_}`)
    if (!entry) {
      referenceGraphComplete = false
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
  if (referenceGraphComplete) {
    for (const [path, entry] of byPath) {
      if (!path.startsWith('blobs/sha256/')) continue
      if (referenced.has(`sha256:${path.slice('blobs/sha256/'.length)}`)) continue
      orphans.push({ digest: `sha256:${path.slice('blobs/sha256/'.length)}`, size: entry.size })
    }
  }
  orphans.sort((left, right) => compareCanonicalStrings(left.digest, right.digest))

  return {
    format: 'oci-layout',
    config: {
      digest: configDigests.length === 1 ? configDigests[0] : null,
      history: histories,
      diff_ids: diffIds,
    },
    layers,
    orphan_blobs: orphans,
    gaps,
  }
}

function normalizeDockerArchive(archive, byPath, limits, gaps) {
  const manifest = parseJsonEntry(archive, byPath.get('manifest.json'), 'manifest.json', gaps)
  const images = Array.isArray(manifest) ? manifest : []
  if (images.length === 0) {
    gaps.push({ area: 'manifests', reason: 'the docker archive declares no image' })
  }
  const selectedImages = images.slice(0, limits.maxManifests)
  if (images.length > limits.maxManifests) {
    gaps.push({
      area: 'manifests',
      reason: `${images.length - limits.maxManifests} image manifest(s) exceeded the bounded `
        + `limit of ${limits.maxManifests} and were not read`,
    })
  }

  const histories = []
  const diffIds = []
  const seenConfigs = new Set()
  for (const [imageIndex, image] of selectedImages.entries()) {
    if (typeof image?.Config !== 'string') {
      gaps.push({
        area: `image ${imageIndex} config`,
        reason: `docker image manifest ${imageIndex} has no config path`,
      })
      continue
    }
    if (seenConfigs.has(image.Config)) continue
    seenConfigs.add(image.Config)
    const configEntry = byPath.get(image.Config)
    if (!configEntry) {
      gaps.push({
        area: `image ${imageIndex} config`,
        reason: `${image.Config} is absent from the archive`,
      })
      continue
    }
    const configJson = parseJsonEntry(
      archive,
      configEntry,
      `image config ${image.Config}`,
      gaps,
    )
    if (Array.isArray(configJson?.history)) histories.push(...configJson.history)
    if (Array.isArray(configJson?.rootfs?.diff_ids)) diffIds.push(...configJson.rootfs.diff_ids)
  }

  const layerPaths = []
  const seenLayerPaths = new Set()
  for (const [imageIndex, image] of selectedImages.entries()) {
    if (!Array.isArray(image?.Layers)) {
      gaps.push({
        area: `image ${imageIndex} layers`,
        reason: `docker image manifest ${imageIndex} has no layer list`,
      })
      continue
    }
    for (const layerPath of image.Layers) {
      if (typeof layerPath !== 'string') {
        gaps.push({
          area: `image ${imageIndex} layers`,
          reason: `docker image manifest ${imageIndex} contains a layer with no path`,
        })
        continue
      }
      if (seenLayerPaths.has(layerPath)) continue
      seenLayerPaths.add(layerPath)
      layerPaths.push(layerPath)
    }
  }
  const selectedLayerPaths = layerPaths.slice(0, limits.maxLayers)
  if (layerPaths.length > limits.maxLayers) {
    gaps.push({
      area: 'layers',
      reason: `image set declares ${layerPaths.length} unique layers, above the bounded limit of `
        + `${limits.maxLayers}; the remainder was not read`,
    })
  }

  const layers = []
  for (const [index_, layerPath] of selectedLayerPaths.entries()) {
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
      history: histories,
      diff_ids: diffIds,
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
  const effectiveLimits = { ...DEFAULT_NORMALIZER_LIMITS, ...limits }
  for (const name of Object.keys(DEFAULT_NORMALIZER_LIMITS)) {
    if (!Number.isSafeInteger(effectiveLimits[name]) || effectiveLimits[name] < 1) {
      throw new RangeError(`${name} must be a positive safe integer`)
    }
  }
  const gaps = []
  const unreadable = (area, error) => ({
    format: 'unknown',
    config: { digest: null, history: [], diff_ids: [] },
    layers: [],
    orphan_blobs: [],
    gaps: [{ area, reason: `could not read ${area}: ${error?.message ?? String(error)}` }],
  })
  let archive
  try {
    archive = decompressIfGzipped(buffer)
  } catch (error) {
    return unreadable('outer archive compression', error)
  }
  let entries
  try {
    entries = readTarEntries(archive, effectiveLimits)
  } catch (error) {
    return unreadable('outer archive', error)
  }
  const byPath = new Map(entries.map((entry) => [entry.path, entry]))

  if (byPath.has('index.json') && byPath.has('oci-layout')) {
    return normalizeOci(archive, byPath, effectiveLimits, gaps)
  }
  if (byPath.has('manifest.json')) {
    return normalizeDockerArchive(archive, byPath, effectiveLimits, gaps)
  }
  gaps.push({
    area: 'format',
    reason: 'the archive is neither an OCI layout nor a docker-save tarball; '
      + 'no layer structure could be read',
  })
  return { format: 'unknown', config: { digest: null, history: [], diff_ids: [] }, layers: [], orphan_blobs: [], gaps }
}
