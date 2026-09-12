import { createHash } from 'node:crypto'
import { gunzipSync } from 'node:zlib'
import { compareCanonicalStrings } from './canonical-order.mjs'

export const DEFAULT_NORMALIZER_LIMITS = Object.freeze({
  maxEntries: 200000,
  maxProjectedBytes: 64 * 1024 * 1024,
  maxEntryBytes: 8 * 1024 * 1024,
  maxTotalBytes: 512 * 1024 * 1024,
  maxArchiveBytes: 768 * 1024 * 1024,
  maxInflatedBytes: 1024 * 1024 * 1024,
  maxManifests: 64,
  maxLayers: 256,
  maxMetadataItems: 200000,
  maxMetadataBytes: 64 * 1024 * 1024,
})

export function validateNormalizerLimits(limits = {}) {
  const effective = { ...DEFAULT_NORMALIZER_LIMITS, ...limits }
  for (const name of Object.keys(DEFAULT_NORMALIZER_LIMITS)) {
    if (!Number.isSafeInteger(effective[name]) || effective[name] < 1) {
      throw new RangeError(`${name} must be a positive safe integer`)
    }
  }
  return effective
}

const BLOCK = 512
const TYPE_BY_FLAG = new Map([
  ['0', 'file'],
  ['\0', 'file'],
  ['1', 'hardlink'],
  ['2', 'symlink'],
  ['5', 'directory'],
  ['x', 'pax-local-header'],
  ['g', 'pax-global-header'],
  ['L', 'gnu-long-name'],
  ['K', 'gnu-long-link'],
])

const UNSUPPORTED_METADATA_FLAGS = new Set(['x', 'g', 'L', 'K'])

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function createResourceBudget(limits) {
  return {
    inflatedBytes: 0,
    capturedBytes: 0,
    capturedFiles: 0,
    parsedEntries: 0,
    projectedEntries: 0,
    projectedBytes: 0,
    metadataItems: 0,
    metadataBytes: 0,
    metadataLimitOmitted: 0,
    metadataGap: null,
    metadataSerializationGap: null,
    layerCache: new Map(),
    verifiedBlobDigests: new Map(),
    outerEntries: null,
    outerByPath: null,
    consumeInflated(bytes, label) {
      if (!Number.isSafeInteger(bytes) || bytes < 0
        || bytes > limits.maxInflatedBytes - this.inflatedBytes) {
        throw new RangeError(
          `${label} would cross the aggregate inflation limit of ${limits.maxInflatedBytes} bytes`,
        )
      }
      this.inflatedBytes += bytes
    },
    exhaustInflated() {
      this.inflatedBytes = limits.maxInflatedBytes
    },
    consumeEntries(entries, label) {
      if (!Number.isSafeInteger(entries) || entries < 0
        || entries > limits.maxEntries - this.parsedEntries) {
        throw new RangeError(
          `${label} would cross the aggregate tar-entry limit of ${limits.maxEntries}`,
        )
      }
      this.parsedEntries += entries
    },
    projectEntries(entries) {
      const accepted = []
      while (accepted.length < entries.length && this.projectedEntries < limits.maxEntries) {
        const serialized = JSON.stringify(entries[accepted.length])
        const bytes = Buffer.byteLength(serialized, 'utf8') + (accepted.length === 0 ? 0 : 1)
        if (bytes > limits.maxProjectedBytes - this.projectedBytes) break
        accepted.push(entries[accepted.length])
        this.projectedEntries += 1
        this.projectedBytes += bytes
      }
      return accepted
    },
    appendMetadata(target, values, area, gaps) {
      let accepted = 0
      let serializationFailed = false
      while (accepted < values.length && this.metadataItems < limits.maxMetadataItems) {
        let serialized
        try {
          serialized = JSON.stringify(values[accepted])
        } catch {
          serializationFailed = true
          break
        }
        if (serialized === undefined) {
          serializationFailed = true
          break
        }
        const bytes = Buffer.byteLength(serialized, 'utf8') + (target.length === 0 ? 0 : 1)
        if (bytes > limits.maxMetadataBytes - this.metadataBytes) break
        target.push(values[accepted])
        this.metadataItems += 1
        this.metadataBytes += bytes
        accepted += 1
      }
      if (accepted < values.length) {
        if (serializationFailed) {
          if (this.metadataSerializationGap === null) {
            this.metadataSerializationGap = {
              area: 'image configuration metadata',
              reason: `metadata beginning in ${area} could not be projected by bounded JSON serialization`,
            }
            gaps.push(this.metadataSerializationGap)
          }
        } else {
          this.metadataLimitOmitted += values.length - accepted
          if (this.metadataGap === null) {
            this.metadataGap = { area: 'image configuration metadata', reason: '' }
            gaps.push(this.metadataGap)
          }
          this.metadataGap.reason = `${this.metadataLimitOmitted} metadata item(s), beginning in ${area}, were omitted before the aggregate limits of ${limits.maxMetadataItems} items and ${limits.maxMetadataBytes} serialized bytes were crossed`
        }
      }
    },
  }
}

function writeTarOctal(header, offset, length, value) {
  const text = value.toString(8)
  if (text.length > length - 1) throw new RangeError('tar value does not fit its header field')
  header.write(`${text.padStart(length - 1, '0')}\0`, offset, length, 'ascii')
}

function ustarPath(path) {
  if (Buffer.byteLength(path, 'utf8') <= 100) return { name: path, prefix: '' }
  for (let index = path.lastIndexOf('/'); index > 0; index = path.lastIndexOf('/', index - 1)) {
    const prefix = path.slice(0, index)
    const name = path.slice(index + 1)
    if (Buffer.byteLength(prefix, 'utf8') <= 155 && Buffer.byteLength(name, 'utf8') <= 100) {
      return { name, prefix }
    }
  }
  throw new RangeError(`tar path does not fit the ustar name fields: ${path}`)
}

export function createTarArchive(files, { maxBytes = Number.MAX_SAFE_INTEGER } = {}) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new RangeError('tar archive maxBytes must be a non-negative safe integer')
  }
  const prepared = []
  const seen = new Set()
  let totalArchiveBytes = BLOCK * 2
  if (totalArchiveBytes > maxBytes) {
    throw new RangeError(`tar archive would exceed the bounded limit of ${maxBytes} bytes`)
  }
  for (const file of files) {
    const path = assertContainedPath(file.path)
    if (seen.has(path)) throw new RangeError(`archive contains duplicate normalized path: ${path}`)
    seen.add(path)
    const bytes = Buffer.isBuffer(file.bytes) ? file.bytes : Buffer.from(file.bytes ?? '')
    const { name, prefix } = ustarPath(path)
    const paddedBytes = Math.ceil(bytes.length / BLOCK) * BLOCK
    const requiredBytes = BLOCK + paddedBytes
    if (requiredBytes > maxBytes - totalArchiveBytes) {
      throw new RangeError(`tar archive would exceed the bounded limit of ${maxBytes} bytes`)
    }
    totalArchiveBytes += requiredBytes
    prepared.push({ bytes, name, prefix })
  }

  // Allocate once, only after the exact padded size is proven within policy.
  // This avoids constructing per-entry padded copies and then a second concat
  // allocation for an archive that will immediately be rejected as oversized.
  const archive = Buffer.alloc(totalArchiveBytes)
  let offset = 0
  for (const { bytes, name, prefix } of prepared) {
    const header = archive.subarray(offset, offset + BLOCK)
    header.write(name, 0, 100, 'utf8')
    writeTarOctal(header, 100, 8, 0o644)
    writeTarOctal(header, 108, 8, 0)
    writeTarOctal(header, 116, 8, 0)
    writeTarOctal(header, 124, 12, bytes.length)
    writeTarOctal(header, 136, 12, 0)
    header.write('        ', 148, 8, 'ascii')
    header.write('0', 156, 1, 'ascii')
    header.write('ustar\0', 257, 6, 'ascii')
    header.write('00', 263, 2, 'ascii')
    if (prefix) header.write(prefix, 345, 155, 'utf8')
    let checksum = 0
    for (const byte of header) checksum += byte
    header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii')
    bytes.copy(archive, offset + BLOCK)
    offset += BLOCK + Math.ceil(bytes.length / BLOCK) * BLOCK
  }
  return archive
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
  const trailingSlash = normalized.endsWith('/')
  const canonical = segments.filter((segment) => segment !== '' && segment !== '.').join('/')
  if (canonical === '') return '.'
  return trailingSlash ? `${canonical}/` : canonical
}

export function readTarEntries(buffer, limits = DEFAULT_NORMALIZER_LIMITS, options = {}) {
  limits = validateNormalizerLimits(limits)
  const maxEntryBytes = options.maxEntryBytes ?? limits.maxEntryBytes
  if (!Number.isSafeInteger(maxEntryBytes) || maxEntryBytes < 1) {
    throw new RangeError('maxEntryBytes must be a positive safe integer')
  }
  if (options.consumeEntry !== undefined && typeof options.consumeEntry !== 'function') {
    throw new TypeError('consumeEntry must be a function')
  }
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
    // Debit parser work as soon as a non-terminator header passes integrity.
    // A later malformed header/path/size must not erase work already spent on
    // earlier entries in this archive.
    options.consumeEntry?.()

    const prefix = readString(header, 345, 155)
    const name = readString(header, 0, 100)
    const path = assertContainedPath(prefix ? `${prefix}/${name}` : name)
    const size = readTarNumber(header, 124, 12)
    const flag = String.fromCharCode(header[156])
    const type = TYPE_BY_FLAG.get(flag) ?? 'other'

    if (UNSUPPORTED_METADATA_FLAGS.has(flag)) {
      throw new RangeError(
        `archive uses unsupported tar metadata extension ${TYPE_BY_FLAG.get(flag)} at ${path}`,
      )
    }
    if (type !== 'directory' && (path === '.' || path.endsWith('/'))) {
      throw new RangeError(`archive non-directory entry has a directory-shaped path: ${path}`)
    }
    if (type === 'directory' && path !== '.' && !path.endsWith('/')) {
      throw new RangeError(`archive directory entry has a non-directory-shaped path: ${path}`)
    }
    if (type === 'directory' && size !== 0) {
      throw new RangeError(`archive directory entry carries ${size} content bytes at ${path}`)
    }

    if (seenPaths.has(path)) {
      throw new RangeError(`archive contains duplicate normalized path: ${path}`)
    }
    seenPaths.add(path)

    if (entries.length + 1 > limits.maxEntries) {
      throw new RangeError(`archive exceeds the bounded limit of ${limits.maxEntries} entries`)
    }
    if (size > maxEntryBytes) {
      throw new RangeError(
        `archive entry ${path} is ${size} bytes, above the bounded limit of `
        + `${maxEntryBytes} bytes`,
      )
    }
    if (size > limits.maxTotalBytes - totalBytes) {
      throw new RangeError(`archive exceeds the bounded limit of ${limits.maxTotalBytes} bytes`)
    }
    totalBytes += size

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
      type,
      link_target: readString(header, 157, 100),
      offset: contentOffset,
    })
    offset = paddedEnd
  }
  if (offset !== buffer.length) {
    throw new RangeError('archive contains a partial trailing block without a complete tar header')
  }
  return entries
}

export function readTarEntryBytes(buffer, entry) {
  return buffer.subarray(entry.offset, entry.offset + entry.size)
}

function decompressIfGzipped(bytes, limits, resources, label = 'archive') {
  if (bytes.length > limits.maxArchiveBytes) {
    throw new RangeError(
      `archive is ${bytes.length} bytes, above the bounded limit of ${limits.maxArchiveBytes} bytes`,
    )
  }
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
    const remaining = limits.maxInflatedBytes - resources.inflatedBytes
    try {
      if (remaining < 1) {
        throw new RangeError(
          `${label} would cross the aggregate inflation limit of ${limits.maxInflatedBytes} bytes`,
        )
      }
      const decoded = gunzipSync(bytes, { maxOutputLength: Math.min(limits.maxArchiveBytes, remaining) })
      resources.consumeInflated(decoded.length, label)
      return decoded
    } catch (error) {
      // gunzipSync exposes no exact produced-byte count when it rejects. Treat
      // the remaining campaign budget as spent so many distinct corrupt gzip
      // members cannot each consume the same unrecorded decompression work.
      resources.exhaustInflated()
      if (error?.code === 'ERR_BUFFER_TOO_LARGE') {
        if (remaining < limits.maxArchiveBytes) {
          throw new RangeError(
            `${label} would cross the aggregate inflation limit of ${limits.maxInflatedBytes} bytes`,
          )
        }
        throw new RangeError(
          `decompressed archive exceeds the bounded limit of ${limits.maxArchiveBytes} bytes`,
        )
      }
      throw error
    }
  }
  resources.consumeInflated(bytes.length, label)
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

function decodeLayer(bytes, limits, resources, label) {
  const archive = decompressIfGzipped(bytes, limits, resources, label)
  const remainingEntries = limits.maxEntries - resources.parsedEntries
  if (remainingEntries < 1) {
    throw new RangeError(`${label} would cross the aggregate tar-entry limit of ${limits.maxEntries}`)
  }
  const tarEntries = readTarEntries(
    archive,
    limits,
    {
      maxEntryBytes: limits.maxTotalBytes,
      consumeEntry: () => resources.consumeEntries(1, label),
    },
  )
  const entries = tarEntries.map((entry) => ({
    path: entry.path,
    mode: entry.mode,
    size: entry.size,
    mtime: entry.mtime,
    type: entry.type,
    link_target: entry.link_target,
    sha256: entry.type === 'file' ? sha256(readTarEntryBytes(archive, entry)) : null,
    whiteout: isWhiteout(entry),
  }))
  return { bytes: archive, tarEntries, entries }
}

export function normalizeLayerEntries(bytes, limits = DEFAULT_NORMALIZER_LIMITS) {
  const effectiveLimits = validateNormalizerLimits(limits)
  const resources = createResourceBudget(effectiveLimits)
  return decodeLayer(bytes, effectiveLimits, resources, 'layer').entries
}

/**
 * The decompressed bytes of one layer blob, or null when it cannot be read.
 * Returning null rather than throwing keeps one bad layer from discarding the
 * rest of the image.
 */
export function layerContentBytes(
  archive,
  layer,
  byPath,
  limits = DEFAULT_NORMALIZER_LIMITS,
  resources,
) {
  const effectiveLimits = validateNormalizerLimits(limits)
  resources ??= createResourceBudget(effectiveLimits)
  const cached = resources.layerCache.get(layer.digest)
  if (cached) return cached.error ? null : cached.bytes
  const suffix = String(layer.digest).replace(/^sha256:/, '')
  const entry = byPath.get(`blobs/sha256/${suffix}`) ?? byPath.get(layer.source_path)
  if (!entry || entry.type !== 'file') return null
  try {
    const bytes = decompressIfGzipped(
      readTarEntryBytes(archive, entry),
      effectiveLimits,
      resources,
      `layer ${layer.digest}`,
    )
    resources.layerCache.set(layer.digest, { bytes })
    return bytes
  } catch (error) {
    resources.layerCache.set(layer.digest, { error })
    return null
  }
}

function parseJsonEntry(archive, entry, label, gaps, limits) {
  if (!entry) {
    gaps.push({ area: label, reason: `could not read ${label}: it is absent from the archive` })
    return null
  }
  if (entry.type !== 'file') {
    gaps.push({ area: label, reason: `could not read ${label}: its tar entry is not a regular file` })
    return null
  }
  if (entry.size > limits.maxEntryBytes) {
    gaps.push({
      area: label,
      reason: `${label} is ${entry.size} bytes, above the bounded JSON limit of ${limits.maxEntryBytes} bytes`,
    })
    return null
  }
  try {
    return JSON.parse(readTarEntryBytes(archive, entry).toString('utf8'))
  } catch (error) {
    gaps.push({ area: label, reason: `could not parse ${label}: ${error.message}` })
    return null
  }
}

function normalizeOci(archive, byPath, limits, gaps, resources) {
  const index = parseJsonEntry(archive, byPath.get('index.json'), 'index.json', gaps, limits)
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
    if (entry.type !== 'file') {
      gaps.push({ area, reason: `blob ${digest} is not stored as a regular file` })
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
    let actualDigest = resources.verifiedBlobDigests.get(path)
    if (actualDigest === undefined) {
      actualDigest = sha256(readTarEntryBytes(archive, entry))
      resources.verifiedBlobDigests.set(path, actualDigest)
    }
    if (actualDigest !== match[1]) {
      gaps.push({
        area,
        reason: `blob ${digest} content does not match its declared sha256 digest`,
      })
      return null
    }
    return entry
  }
  const declaredDescriptors = Array.isArray(index?.manifests) ? index.manifests : []
  const descriptors = declaredDescriptors.slice(0, limits.maxManifests)
  if (descriptors.length === 0) {
    gaps.push({ area: 'manifest', reason: 'the layout declares no image manifest descriptor' })
  }
  const stack = []
  let skippedDescriptors = declaredDescriptors.length - descriptors.length
  let inspectedDescriptors = descriptors.length
  // Absence of references is meaningful only when index.json itself supplied
  // a valid descriptor list. A corrupt index does not turn every blob in the
  // archive into a proven orphan.
  let referenceGraphComplete = index !== null
    && typeof index === 'object'
    && !Array.isArray(index)
    && Array.isArray(index.manifests)
    && skippedDescriptors === 0
  for (const descriptor of descriptors) {
    if (typeof descriptor?.digest !== 'string') {
      referenceGraphComplete = false
      gaps.push({ area: 'manifest', reason: 'an index descriptor has no digest' })
      continue
    }
    referenced.add(descriptor.digest)
    stack.unshift(descriptor)
  }
  const imageManifests = []
  const layerDescriptors = []
  let skippedLayerDescriptors = 0
  let inspectedLayerDescriptors = 0
  let traversedDescriptors = 0
  while (stack.length > 0) {
    if (traversedDescriptors >= limits.maxManifests) {
      skippedDescriptors += stack.length
      referenceGraphComplete = false
      break
    }
    const descriptor = stack.pop()
    traversedDescriptors += 1
    const entry = resolveBlob(descriptor, `manifest ${descriptor.digest}`)
    const document = entry
      ? parseJsonEntry(archive, entry, `manifest ${descriptor.digest}`, gaps, limits)
      : null
    if (!document) {
      referenceGraphComplete = false
      continue
    }
    if (Array.isArray(document.manifests)) {
      const remaining = Math.max(0, limits.maxManifests - inspectedDescriptors)
      const selectedChildren = document.manifests.slice(0, remaining)
      inspectedDescriptors += selectedChildren.length
      skippedDescriptors += document.manifests.length - selectedChildren.length
      if (selectedChildren.length < document.manifests.length) referenceGraphComplete = false
      for (const child of selectedChildren.reverse()) {
        if (typeof child?.digest !== 'string') {
          referenceGraphComplete = false
          gaps.push({ area: 'manifest', reason: 'a nested index descriptor has no digest' })
          continue
        }
        referenced.add(child.digest)
        stack.push(child)
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
    const remainingLayers = Math.max(0, limits.maxLayers - inspectedLayerDescriptors)
    const selectedManifestLayers = document.layers.slice(0, remainingLayers)
    inspectedLayerDescriptors += selectedManifestLayers.length
    skippedLayerDescriptors += document.layers.length - selectedManifestLayers.length
    if (selectedManifestLayers.length < document.layers.length) referenceGraphComplete = false
    for (const layer of selectedManifestLayers) {
      if (typeof layer?.digest === 'string') referenced.add(layer.digest)
      else {
        referenceGraphComplete = false
        gaps.push({
          area: 'manifest',
          reason: `image manifest ${descriptor.digest} contains a layer descriptor with no digest`,
        })
      }
      if (typeof layer?.digest === 'string') layerDescriptors.push(layer)
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
      ? parseJsonEntry(archive, entry, `image config ${digest}`, gaps, limits)
      : null
    if (!entry) referenceGraphComplete = false
    if (Array.isArray(config?.history)) {
      resources.appendMetadata(histories, config.history, `image config ${digest} history`, gaps)
    }
    if (Array.isArray(config?.rootfs?.diff_ids)) {
      resources.appendMetadata(diffIds, config.rootfs.diff_ids, `image config ${digest} diff_ids`, gaps)
    }
  }

  const selectedLayers = layerDescriptors
  if (skippedLayerDescriptors > 0) {
    gaps.push({
      area: 'layers',
      reason: `${skippedLayerDescriptors} ordered layer occurrence(s) exceeded the bounded limit of `
        + `${limits.maxLayers} and were not read`,
    })
  }

  const layers = []
  for (const [index_, descriptor] of selectedLayers.entries()) {
    const entry = resolveBlob(descriptor, `layer ${index_}`)
    if (!entry) {
      referenceGraphComplete = false
      continue
    }
    let decoded = resources.layerCache.get(descriptor.digest)
    if (!decoded) {
      try {
        decoded = decodeLayer(
          readTarEntryBytes(archive, entry),
          limits,
          resources,
          `layer ${descriptor.digest}`,
        )
      } catch (error) {
        decoded = { error }
      }
      resources.layerCache.set(descriptor.digest, decoded)
    }
    if (decoded.error) {
      const error = decoded.error
      gaps.push({ area: `layer ${index_}`, reason: `could not decompress or read layer: ${error.message}` })
      continue
    }
    const projectedEntries = resources.projectEntries(decoded.entries)
    if (projectedEntries.length < decoded.entries.length) {
      gaps.push({
        area: `layer ${index_}`,
        reason: `${decoded.entries.length - projectedEntries.length} entry metadata record(s) were omitted before the aggregate projected-entry limits of ${limits.maxEntries} records and ${limits.maxProjectedBytes} serialized bytes were crossed`,
      })
    }
    layers.push({
      index: index_,
      digest: descriptor.digest,
      source_path: `blobs/sha256/${String(descriptor.digest).replace(/^sha256:/, '')}`,
      media_type: descriptor.mediaType ?? null,
      entry_count: projectedEntries.length,
      entries: projectedEntries,
    })
  }

  const orphans = []
  if (referenceGraphComplete) {
    for (const [path, entry] of byPath) {
      if (entry.type !== 'file' || !/^blobs\/sha256\/[0-9a-f]{64}$/.test(path)) continue
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
    top_level_digests: descriptors
      .map((descriptor) => descriptor?.digest)
      .filter((digest) => /^sha256:[0-9a-f]{64}$/.test(String(digest))),
    layers,
    orphan_blobs: orphans,
    gaps,
  }
}

function normalizeDockerArchive(archive, byPath, limits, gaps, resources) {
  const manifest = parseJsonEntry(
    archive,
    byPath.get('manifest.json'),
    'manifest.json',
    gaps,
    limits,
  )
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
      limits,
    )
    if (Array.isArray(configJson?.history)) {
      resources.appendMetadata(histories, configJson.history, `image config ${image.Config} history`, gaps)
    }
    if (Array.isArray(configJson?.rootfs?.diff_ids)) {
      resources.appendMetadata(diffIds, configJson.rootfs.diff_ids, `image config ${image.Config} diff_ids`, gaps)
    }
  }

  const layerPaths = []
  let skippedLayerPaths = 0
  let inspectedLayerPaths = 0
  for (const [imageIndex, image] of selectedImages.entries()) {
    if (!Array.isArray(image?.Layers)) {
      gaps.push({
        area: `image ${imageIndex} layers`,
        reason: `docker image manifest ${imageIndex} has no layer list`,
      })
      continue
    }
    const remainingLayers = Math.max(0, limits.maxLayers - inspectedLayerPaths)
    const selectedImageLayers = image.Layers.slice(0, remainingLayers)
    inspectedLayerPaths += selectedImageLayers.length
    skippedLayerPaths += image.Layers.length - selectedImageLayers.length
    for (const layerPath of selectedImageLayers) {
      if (typeof layerPath !== 'string') {
        gaps.push({
          area: `image ${imageIndex} layers`,
          reason: `docker image manifest ${imageIndex} contains a layer with no path`,
        })
        continue
      }
      layerPaths.push(layerPath)
    }
  }
  const selectedLayerPaths = layerPaths
  if (skippedLayerPaths > 0) {
    gaps.push({
      area: 'layers',
      reason: `${skippedLayerPaths} ordered layer occurrence(s) exceeded the bounded limit of `
        + `${limits.maxLayers} and were not read`,
    })
  }

  const layers = []
  for (const [index_, layerPath] of selectedLayerPaths.entries()) {
    const entry = byPath.get(layerPath)
    if (!entry) {
      gaps.push({ area: `layer ${index_}`, reason: `${layerPath} is absent from the archive` })
      continue
    }
    if (entry.type !== 'file') {
      gaps.push({ area: `layer ${index_}`, reason: `${layerPath} is not stored as a regular file` })
      continue
    }
    const raw = readTarEntryBytes(archive, entry)
    let rawDigest = resources.verifiedBlobDigests.get(layerPath)
    if (rawDigest === undefined) {
      rawDigest = sha256(raw)
      resources.verifiedBlobDigests.set(layerPath, rawDigest)
    }
    const digest = `sha256:${rawDigest}`
    let decoded = resources.layerCache.get(digest)
    if (!decoded) {
      try {
        decoded = decodeLayer(raw, limits, resources, `layer ${digest}`)
      } catch (error) {
        decoded = { error }
      }
      resources.layerCache.set(digest, decoded)
    }
    if (decoded.error) {
      const error = decoded.error
      gaps.push({ area: `layer ${index_}`, reason: `could not decompress or read layer: ${error.message}` })
      continue
    }
    const projectedEntries = resources.projectEntries(decoded.entries)
    if (projectedEntries.length < decoded.entries.length) {
      gaps.push({
        area: `layer ${index_}`,
        reason: `${decoded.entries.length - projectedEntries.length} entry metadata record(s) were omitted before the aggregate projected-entry limits of ${limits.maxEntries} records and ${limits.maxProjectedBytes} serialized bytes were crossed`,
      })
    }
    layers.push({
      index: index_,
      digest,
      source_path: layerPath,
      media_type: 'application/vnd.docker.image.rootfs.diff.tar',
      entry_count: projectedEntries.length,
      entries: projectedEntries,
    })
  }

  return {
    format: 'docker-archive',
    config: {
      digest: null,
      history: histories,
      diff_ids: diffIds,
    },
    top_level_digests: [],
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
export function normalizeOciArchive(buffer, limits = DEFAULT_NORMALIZER_LIMITS) {
  const effectiveLimits = validateNormalizerLimits(limits)
  const resources = createResourceBudget(effectiveLimits)
  const result = (archive, normalized) => ({
    archive,
    normalized,
    resource_budget: resources,
    resource_usage: {
      inflated_bytes: resources.inflatedBytes,
      parsed_entries: resources.parsedEntries,
      projected_entries: resources.projectedEntries,
      projected_bytes: resources.projectedBytes,
      metadata_items: resources.metadataItems,
      metadata_bytes: resources.metadataBytes,
      decoded_layer_cache_entries: resources.layerCache.size,
      verified_blob_cache_entries: resources.verifiedBlobDigests.size,
    },
  })
  const gaps = []
  const unreadable = (area, error) => ({
    format: 'unknown',
    config: { digest: null, history: [], diff_ids: [] },
    top_level_digests: [],
    layers: [],
    orphan_blobs: [],
    gaps: [{ area, reason: `could not read ${area}: ${error?.message ?? String(error)}` }],
  })
  let archive
  try {
    archive = decompressIfGzipped(buffer, effectiveLimits, resources, 'outer archive')
  } catch (error) {
    return result(null, unreadable('outer archive compression', error))
  }
  let entries
  try {
    entries = readTarEntries(archive, effectiveLimits, {
      maxEntryBytes: effectiveLimits.maxTotalBytes,
      consumeEntry: () => resources.consumeEntries(1, 'outer archive'),
    })
  } catch (error) {
    return result(archive, unreadable('outer archive', error))
  }
  const byPath = new Map(entries.map((entry) => [entry.path, entry]))
  resources.outerEntries = entries
  resources.outerByPath = byPath

  if (byPath.get('index.json')?.type === 'file' && byPath.get('oci-layout')?.type === 'file') {
    return result(archive, normalizeOci(archive, byPath, effectiveLimits, gaps, resources))
  }
  if (byPath.get('manifest.json')?.type === 'file') {
    return result(archive, normalizeDockerArchive(archive, byPath, effectiveLimits, gaps, resources))
  }
  gaps.push({
    area: 'format',
    reason: 'the archive is neither an OCI layout nor a docker-save tarball; '
      + 'no layer structure could be read',
  })
  return result(archive, {
      format: 'unknown',
      config: { digest: null, history: [], diff_ids: [] },
      top_level_digests: [],
      layers: [],
      orphan_blobs: [],
      gaps,
  })
}

export function normalizeOciLayout(buffer, limits = DEFAULT_NORMALIZER_LIMITS) {
  return normalizeOciArchive(buffer, limits).normalized
}
