import { createHash } from 'node:crypto'

export const SEALED_SNAPSHOT_SCHEMA_VERSION = '1.0.0'
export const MAX_SEALED_SHARD_BYTES = 64 * 1024 * 1024

const SHA256_PATTERN = /^[a-f0-9]{64}$/
const FILE_ID_PATTERN = /^file_[a-f0-9]{64}$/
const SHARD_ID_PATTERN = /^shard_[0-9]{6}$/
const SNAPSHOT_KINDS = new Set(['source', 'control', 'lens'])
const MAX_INDEX_FILES = 100_000
const MAX_INDEX_SHARDS = 100_000

export class SealedSnapshotError extends Error {
  constructor(code, message, details = {}) {
    super(message)
    this.name = 'SealedSnapshotError'
    this.code = code
    this.details = details
  }
}

function fail(code, message, details = {}) {
  throw new SealedSnapshotError(code, message, details)
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function compareCanonicalStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue)
  if (value === null || typeof value !== 'object') return value
  return Object.fromEntries(
    Object.keys(value)
      .sort(compareCanonicalStrings)
      .map((key) => [key, stableValue(value[key])]),
  )
}

export function serializeSealedSnapshotIndex(index) {
  return `${JSON.stringify(stableValue(index), null, 2)}\n`
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

function requirePlainObject(value, label) {
  if (!isPlainObject(value)) fail('INDEX_SHAPE_INVALID', `${label} must be a plain object`)
}

function requireExactKeys(value, expected, label) {
  const actual = Object.keys(value).sort(compareCanonicalStrings)
  const wanted = [...expected].sort(compareCanonicalStrings)
  if (
    actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])
  ) {
    fail(
      'INDEX_KEYS_INVALID',
      `${label} must contain exactly: ${wanted.join(', ')}`,
      { actual, expected: wanted },
    )
  }
}

function requireSafeSize(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail('SIZE_INVALID', `${label} must be a non-negative safe integer`)
  }
  return value
}

function normalizeSha256(value, label) {
  if (typeof value !== 'string' || !/^[a-fA-F0-9]{64}$/.test(value)) {
    fail('SHA256_INVALID', `${label} must be a 64-character SHA-256 digest`)
  }
  return value.toLowerCase()
}

function requireCanonicalSha256(value, label) {
  if (typeof value !== 'string' || !SHA256_PATTERN.test(value)) {
    fail('SHA256_INVALID', `${label} must be a lowercase SHA-256 digest`)
  }
  return value
}

function canonicalRelativePath(value, label) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > 16_384
    || value.includes('\0')
    || value.includes('\\')
    || value.startsWith('/')
    || /^[A-Za-z]:/.test(value)
  ) {
    fail('PATH_INVALID', `${label} must be a canonical POSIX repository-relative path`)
  }
  const segments = value.split('/')
  if (
    segments.some((segment) =>
      segment.length === 0
      || segment === '.'
      || segment === '..')
  ) {
    fail('PATH_INVALID', `${label} contains an empty, current, or parent segment`)
  }
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index)
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1)
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        fail('PATH_INVALID', `${label} contains an unpaired Unicode surrogate`)
      }
      index += 1
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      fail('PATH_INVALID', `${label} contains an unpaired Unicode surrogate`)
    }
  }
  return value
}

function normalizeKind(value, label) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > 128
    || /[\u0000-\u001f\u007f]/.test(value)
  ) {
    fail('KIND_INVALID', `${label} must be a non-empty bounded string`)
  }
  return value
}

function normalizeSnapshotKind(value) {
  if (!SNAPSHOT_KINDS.has(value)) {
    fail('SNAPSHOT_KIND_INVALID', 'snapshot kind must be source, control, or lens')
  }
  return value
}

function normalizeMaxShardBytes(value) {
  if (
    !Number.isSafeInteger(value)
    || value <= 0
    || value > MAX_SEALED_SHARD_BYTES
  ) {
    fail(
      'SHARD_LIMIT_INVALID',
      `maxShardBytes must be between 1 and ${MAX_SEALED_SHARD_BYTES}`,
    )
  }
  return value
}

function opaqueFileId(snapshotKind, path) {
  return `file_${sha256(`red-team-audit:sealed-file:v1\0${snapshotKind}\0${path}`)}`
}

function fileManifestDigest(files) {
  return sha256(JSON.stringify(files.map(({ path, kind, size, sha256: digest }) => [
    path,
    kind,
    size,
    digest,
  ])))
}

function normalizeSourceEntries(inventory) {
  if (!isPlainObject(inventory)) {
    fail('INVENTORY_INVALID', 'source snapshot requires an inventory object')
  }
  if (!Array.isArray(inventory.entries)) {
    fail('INVENTORY_INVALID', 'source inventory entries must be an array')
  }
  if (inventory.entries.length > MAX_INDEX_FILES) {
    fail('FILE_LIMIT_EXCEEDED', `source inventory exceeds ${MAX_INDEX_FILES} entries`)
  }

  const normalized = inventory.entries.map((entry, index) => {
    if (!isPlainObject(entry)) {
      fail('INVENTORY_ENTRY_INVALID', `inventory entry ${index} must be an object`)
    }
    const path = canonicalRelativePath(entry.path, `inventory entry ${index} path`)
    const kind = normalizeKind(entry.kind, `inventory entry ${path} kind`)
    const size = requireSafeSize(entry.size, `inventory entry ${path} size`)
    const digest = normalizeSha256(entry.sha256, `inventory entry ${path} sha256`)

    if (kind !== 'text') {
      return { path, kind, size, sha256: digest, bytes: null }
    }
    if (typeof entry.content !== 'string') {
      fail(
        'TEXT_CONTENT_UNAVAILABLE',
        `text inventory entry ${path} does not carry verified UTF-8 content`,
      )
    }
    const bytes = Buffer.from(entry.content, 'utf8')
    if (bytes.length !== size || sha256(bytes) !== digest) {
      fail(
        'UTF8_ROUNDTRIP_MISMATCH',
        `text inventory entry ${path} does not round-trip to its inventoried bytes`,
        {
          expected_size: size,
          actual_size: bytes.length,
          expected_sha256: digest,
          actual_sha256: sha256(bytes),
        },
      )
    }
    return { path, kind, size, sha256: digest, bytes }
  })

  normalized.sort((left, right) => compareCanonicalStrings(left.path, right.path))
  rejectDuplicatePaths(normalized)
  return normalized
}

function normalizeControlEntry(entry, index) {
  let path
  let bytes
  if (Array.isArray(entry)) {
    if (entry.length !== 2) {
      fail('CONTROL_ENTRY_INVALID', `control entry ${index} tuple must contain path and Buffer`)
    }
    ;[path, bytes] = entry
  } else if (isPlainObject(entry)) {
    path = entry.path
    bytes = entry.bytes
  } else {
    fail('CONTROL_ENTRY_INVALID', `control entry ${index} must be a path/Buffer entry`)
  }
  const normalizedPath = canonicalRelativePath(path, `control entry ${index} path`)
  if (!Buffer.isBuffer(bytes)) {
    fail('CONTROL_ENTRY_INVALID', `control entry ${normalizedPath} bytes must be a Buffer`)
  }
  const copy = Buffer.from(bytes)
  return {
    path: normalizedPath,
    kind: 'text',
    size: copy.length,
    sha256: sha256(copy),
    bytes: copy,
  }
}

function normalizeControlEntries(entries) {
  if (!Array.isArray(entries)) {
    fail('CONTROL_ENTRIES_INVALID', 'control snapshot entries must be an array')
  }
  if (entries.length > MAX_INDEX_FILES) {
    fail('FILE_LIMIT_EXCEEDED', `control snapshot exceeds ${MAX_INDEX_FILES} entries`)
  }
  const normalized = entries.map(normalizeControlEntry)
    .sort((left, right) => compareCanonicalStrings(left.path, right.path))
  rejectDuplicatePaths(normalized)
  return normalized
}

function rejectDuplicatePaths(entries) {
  for (let index = 1; index < entries.length; index += 1) {
    if (entries[index - 1].path === entries[index].path) {
      fail('DUPLICATE_PATH', `snapshot path is duplicated: ${entries[index].path}`)
    }
  }
}

function packSnapshot(snapshotKind, sourceTreeDigest, normalizedEntries, maxShardBytes) {
  const files = []
  const shards = []
  let current

  function startShard() {
    const shardId = `shard_${String(shards.length).padStart(6, '0')}`
    current = {
      shard_id: shardId,
      chunks: [],
      size: 0,
    }
    shards.push(current)
  }

  for (const entry of normalizedEntries) {
    const base = {
      file_id: opaqueFileId(snapshotKind, entry.path),
      path: entry.path,
      kind: entry.kind,
      size: entry.size,
      sha256: entry.sha256,
    }
    if (entry.bytes === null) {
      files.push({
        ...base,
        availability: 'UNAVAILABLE',
        unavailable_reason: 'non-text',
      })
      continue
    }
    if (entry.bytes.length > maxShardBytes) {
      fail(
        'FILE_EXCEEDS_SHARD_LIMIT',
        `snapshot file ${entry.path} exceeds the ${maxShardBytes}-byte shard limit`,
      )
    }
    if (
      current === undefined
      || (current.size > 0 && current.size + entry.bytes.length > maxShardBytes)
    ) {
      startShard()
    }
    const offset = current.size
    current.chunks.push(entry.bytes)
    current.size += entry.bytes.length
    files.push({
      ...base,
      availability: 'AVAILABLE',
      shard: current.shard_id,
      offset,
      length: entry.bytes.length,
    })
  }

  const emittedShards = shards.map((shard) => {
    const bytes = Buffer.concat(shard.chunks, shard.size)
    return Object.freeze({
      shard_id: shard.shard_id,
      size: bytes.length,
      sha256: sha256(bytes),
      bytes,
    })
  })
  const shardIndex = emittedShards.map(({ bytes: _bytes, ...shard }) => shard)
  const index = {
    schema_version: SEALED_SNAPSHOT_SCHEMA_VERSION,
    snapshot_kind: snapshotKind,
    source_tree_digest: sourceTreeDigest,
    file_manifest_sha256: fileManifestDigest(files),
    shard_encoding: 'raw',
    compression: 'none',
    max_shard_bytes: maxShardBytes,
    files,
    shards: shardIndex,
  }
  const validatedIndex = assertValidSealedSnapshotIndex(index)
  return Object.freeze({
    index: validatedIndex,
    indexBytes: Buffer.from(serializeSealedSnapshotIndex(validatedIndex), 'utf8'),
    shards: Object.freeze(emittedShards),
  })
}

export function buildSealedSourceSnapshot(inventory, options = {}) {
  const sourceTreeDigest = normalizeSha256(
    inventory?.treeDigest,
    'source inventory treeDigest',
  )
  const maxShardBytes = normalizeMaxShardBytes(
    options.maxShardBytes ?? MAX_SEALED_SHARD_BYTES,
  )
  return packSnapshot(
    'source',
    sourceTreeDigest,
    normalizeSourceEntries(inventory),
    maxShardBytes,
  )
}

export function buildSealedControlSnapshot(entries, options = {}) {
  const snapshotKind = normalizeSnapshotKind(options.snapshotKind ?? 'control')
  if (snapshotKind === 'source') {
    fail('SNAPSHOT_KIND_INVALID', 'control snapshot builder cannot create a source snapshot')
  }
  const normalizedEntries = normalizeControlEntries(entries)
  const sourceTreeDigest = fileManifestDigest(normalizedEntries)
  const maxShardBytes = normalizeMaxShardBytes(
    options.maxShardBytes ?? MAX_SEALED_SHARD_BYTES,
  )
  return packSnapshot(
    snapshotKind,
    sourceTreeDigest,
    normalizedEntries,
    maxShardBytes,
  )
}

function cloneJson(value) {
  try {
    return JSON.parse(JSON.stringify(value))
  } catch (error) {
    fail('INDEX_JSON_INVALID', `sealed snapshot index is not JSON-compatible: ${error.message}`)
  }
}

function deepFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const child of Object.values(value)) deepFreeze(child)
  return Object.freeze(value)
}

function parseIndexInput(value) {
  if (Buffer.isBuffer(value)) {
    try {
      return JSON.parse(value.toString('utf8'))
    } catch (error) {
      fail('INDEX_JSON_INVALID', `sealed snapshot index JSON is invalid: ${error.message}`)
    }
  }
  if (typeof value === 'string') {
    try {
      return JSON.parse(value)
    } catch (error) {
      fail('INDEX_JSON_INVALID', `sealed snapshot index JSON is invalid: ${error.message}`)
    }
  }
  return cloneJson(value)
}

export function assertValidSealedSnapshotIndex(value) {
  const index = parseIndexInput(value)
  requirePlainObject(index, 'sealed snapshot index')
  requireExactKeys(index, [
    'schema_version',
    'snapshot_kind',
    'source_tree_digest',
    'file_manifest_sha256',
    'shard_encoding',
    'compression',
    'max_shard_bytes',
    'files',
    'shards',
  ], 'sealed snapshot index')
  if (index.schema_version !== SEALED_SNAPSHOT_SCHEMA_VERSION) {
    fail(
      'SCHEMA_VERSION_UNSUPPORTED',
      `sealed snapshot schema must be ${SEALED_SNAPSHOT_SCHEMA_VERSION}`,
    )
  }
  normalizeSnapshotKind(index.snapshot_kind)
  requireCanonicalSha256(index.source_tree_digest, 'source_tree_digest')
  requireCanonicalSha256(index.file_manifest_sha256, 'file_manifest_sha256')
  if (index.shard_encoding !== 'raw' || index.compression !== 'none') {
    fail('SHARD_ENCODING_UNSUPPORTED', 'sealed snapshot shards must be raw and uncompressed')
  }
  normalizeMaxShardBytes(index.max_shard_bytes)
  if (!Array.isArray(index.files) || index.files.length > MAX_INDEX_FILES) {
    fail('FILE_LIMIT_EXCEEDED', `sealed snapshot files must not exceed ${MAX_INDEX_FILES}`)
  }
  if (!Array.isArray(index.shards) || index.shards.length > MAX_INDEX_SHARDS) {
    fail('SHARD_LIMIT_EXCEEDED', `sealed snapshot shards must not exceed ${MAX_INDEX_SHARDS}`)
  }

  const shardById = new Map()
  index.shards.forEach((shard, shardIndex) => {
    requirePlainObject(shard, `shard ${shardIndex}`)
    requireExactKeys(shard, ['shard_id', 'size', 'sha256'], `shard ${shardIndex}`)
    const expectedId = `shard_${String(shardIndex).padStart(6, '0')}`
    if (
      typeof shard.shard_id !== 'string'
      || !SHARD_ID_PATTERN.test(shard.shard_id)
      || shard.shard_id !== expectedId
    ) {
      fail('SHARD_ID_INVALID', `shard ${shardIndex} must use id ${expectedId}`)
    }
    requireSafeSize(shard.size, `shard ${shard.shard_id} size`)
    if (shard.size > index.max_shard_bytes || shard.size > MAX_SEALED_SHARD_BYTES) {
      fail('SHARD_SIZE_EXCEEDED', `shard ${shard.shard_id} exceeds its declared limit`)
    }
    requireCanonicalSha256(shard.sha256, `shard ${shard.shard_id} sha256`)
    shardById.set(shard.shard_id, shard)
  })

  let priorPath
  let lastShardNumber = -1
  const shardCursors = new Map(index.shards.map(({ shard_id: shardId }) => [shardId, 0]))
  const shardReferences = new Map(index.shards.map(({ shard_id: shardId }) => [shardId, 0]))
  const fileIds = new Set()
  index.files.forEach((file, fileIndex) => {
    requirePlainObject(file, `file ${fileIndex}`)
    const commonKeys = [
      'file_id',
      'path',
      'kind',
      'size',
      'sha256',
      'availability',
    ]
    const available = file.availability === 'AVAILABLE'
    const unavailable = file.availability === 'UNAVAILABLE'
    if (!available && !unavailable) {
      fail('AVAILABILITY_INVALID', `file ${fileIndex} has an unsupported availability`)
    }
    requireExactKeys(
      file,
      available
        ? [...commonKeys, 'shard', 'offset', 'length']
        : [...commonKeys, 'unavailable_reason'],
      `file ${fileIndex}`,
    )
    const path = canonicalRelativePath(file.path, `file ${fileIndex} path`)
    const kind = normalizeKind(file.kind, `file ${path} kind`)
    if (priorPath !== undefined && compareCanonicalStrings(priorPath, path) >= 0) {
      fail('FILE_ORDER_INVALID', 'sealed snapshot files must be strictly path-sorted')
    }
    priorPath = path
    if (
      typeof file.file_id !== 'string'
      || !FILE_ID_PATTERN.test(file.file_id)
      || file.file_id !== opaqueFileId(index.snapshot_kind, path)
    ) {
      fail('FILE_ID_INVALID', `file ${path} has an invalid opaque file_id`)
    }
    if (fileIds.has(file.file_id)) {
      fail('DUPLICATE_FILE_ID', `file_id is duplicated: ${file.file_id}`)
    }
    fileIds.add(file.file_id)
    requireSafeSize(file.size, `file ${path} size`)
    requireCanonicalSha256(file.sha256, `file ${path} sha256`)

    if (available) {
      if (kind !== 'text') {
        fail('NON_TEXT_AVAILABLE', `non-text file ${path} cannot expose snapshot bytes`)
      }
      if (
        typeof file.shard !== 'string'
        || !SHARD_ID_PATTERN.test(file.shard)
        || !shardById.has(file.shard)
      ) {
        fail('SHARD_REFERENCE_INVALID', `file ${path} references an unknown shard`)
      }
      requireSafeSize(file.offset, `file ${path} offset`)
      requireSafeSize(file.length, `file ${path} length`)
      if (file.length !== file.size) {
        fail('FILE_LENGTH_MISMATCH', `file ${path} length must equal its exact size`)
      }
      const shardNumber = Number(file.shard.slice('shard_'.length))
      if (shardNumber < lastShardNumber) {
        fail('SHARD_ORDER_INVALID', 'available files cannot return to an earlier shard')
      }
      lastShardNumber = shardNumber
      const expectedOffset = shardCursors.get(file.shard)
      if (file.offset !== expectedOffset) {
        fail(
          'SHARD_LAYOUT_INVALID',
          `file ${path} must begin at contiguous offset ${expectedOffset}`,
        )
      }
      const end = file.offset + file.length
      if (!Number.isSafeInteger(end) || end > shardById.get(file.shard).size) {
        fail('SHARD_RANGE_INVALID', `file ${path} exceeds shard ${file.shard}`)
      }
      shardCursors.set(file.shard, end)
      shardReferences.set(file.shard, shardReferences.get(file.shard) + 1)
    } else {
      if (kind === 'text') {
        fail('TEXT_UNAVAILABLE', `text file ${path} must have sealed bytes`)
      }
      if (file.unavailable_reason !== 'non-text') {
        fail('UNAVAILABLE_REASON_INVALID', `file ${path} must use non-text reason`)
      }
    }
  })

  if (fileManifestDigest(index.files) !== index.file_manifest_sha256) {
    fail('FILE_MANIFEST_DIGEST_MISMATCH', 'file manifest digest does not match the index')
  }
  for (const shard of index.shards) {
    if (shardReferences.get(shard.shard_id) === 0) {
      fail('UNREFERENCED_SHARD', `shard ${shard.shard_id} has no file records`)
    }
    if (shardCursors.get(shard.shard_id) !== shard.size) {
      fail('SHARD_LAYOUT_INVALID', `shard ${shard.shard_id} contains unindexed bytes`)
    }
  }
  return deepFreeze(index)
}

export function parseSealedSnapshotIndex(value) {
  return assertValidSealedSnapshotIndex(value)
}

async function shardBytesFrom(source, shard, shardCount, { allowDirectBuffer = false } = {}) {
  let value
  if (Buffer.isBuffer(source)) {
    if (!allowDirectBuffer && shardCount !== 1) {
      fail('SHARD_SOURCE_AMBIGUOUS', 'a direct Buffer can verify only a one-shard snapshot')
    }
    value = source
  } else if (typeof source === 'function') {
    value = await source(shard.shard_id, Object.freeze({ ...shard }))
  } else if (source instanceof Map) {
    value = source.get(shard.shard_id)
  } else if (Array.isArray(source)) {
    value = source.find((entry) => entry?.shard_id === shard.shard_id)?.bytes
  } else {
    fail(
      'SHARD_SOURCE_INVALID',
      'shard source must be a Buffer, callback, Map, or emitted shard array',
    )
  }
  if (!Buffer.isBuffer(value)) {
    fail('SHARD_BYTES_INVALID', `shard source did not return a Buffer for ${shard.shard_id}`)
  }
  if (value.length !== shard.size || sha256(value) !== shard.sha256) {
    fail(
      'SHARD_DIGEST_MISMATCH',
      `verified bytes for ${shard.shard_id} do not match its index record`,
      {
        expected_size: shard.size,
        actual_size: value.length,
        expected_sha256: shard.sha256,
        actual_sha256: sha256(value),
      },
    )
  }
  return value
}

export async function verifySealedSnapshot(indexInput, shardSource) {
  const index = parseSealedSnapshotIndex(indexInput)
  const shardBytes = new Map()
  for (const shard of index.shards) {
    shardBytes.set(
      shard.shard_id,
      await shardBytesFrom(shardSource, shard, index.shards.length),
    )
  }
  let availableFiles = 0
  for (const file of index.files) {
    if (file.availability !== 'AVAILABLE') continue
    availableFiles += 1
    const bytes = shardBytes.get(file.shard).subarray(
      file.offset,
      file.offset + file.length,
    )
    if (bytes.length !== file.size || sha256(bytes) !== file.sha256) {
      fail('FILE_DIGEST_MISMATCH', `sealed bytes for ${file.file_id} do not match the index`)
    }
  }
  return deepFreeze({
    valid: true,
    snapshot_kind: index.snapshot_kind,
    source_tree_digest: index.source_tree_digest,
    files: index.files.length,
    available_files: availableFiles,
    unavailable_files: index.files.length - availableFiles,
    shards: index.shards.length,
  })
}

export async function readSealedSnapshotFile(indexInput, fileId, shardSource) {
  const index = parseSealedSnapshotIndex(indexInput)
  if (typeof fileId !== 'string' || !FILE_ID_PATTERN.test(fileId)) {
    fail('FILE_ID_INVALID', 'sealed snapshot reads require an opaque file_id')
  }
  const file = index.files.find(({ file_id: candidate }) => candidate === fileId)
  if (file === undefined) {
    fail('FILE_NOT_FOUND', `sealed snapshot file is unknown: ${fileId}`)
  }
  if (file.availability !== 'AVAILABLE') {
    fail(
      'CONTENT_UNAVAILABLE',
      `sealed snapshot bytes are unavailable for non-text file ${fileId}`,
      { kind: file.kind },
    )
  }
  const shard = index.shards.find(({ shard_id: shardId }) => shardId === file.shard)
  const bytes = await shardBytesFrom(
    shardSource,
    shard,
    index.shards.length,
    { allowDirectBuffer: true },
  )
  const content = bytes.subarray(file.offset, file.offset + file.length)
  if (content.length !== file.size || sha256(content) !== file.sha256) {
    fail('FILE_DIGEST_MISMATCH', `sealed bytes for ${fileId} do not match the index`)
  }
  return Buffer.from(content)
}
