import { createHash } from 'node:crypto'
import { compareCanonicalStrings } from './canonical-order.mjs'

export const DEFAULT_WORK_SHARD_MAX_FILES = 64
export const DEFAULT_WORK_SHARD_MAX_BYTES = 4 * 1024 * 1024
export const MAX_WORK_SHARD_FILES = 100_000
export const MAX_WORK_SHARD_BYTES = 512 * 1024 * 1024
export const MAX_WORK_SHARDS = 9_999

export const DEFAULT_WORK_SHARD_LIMITS = Object.freeze({
  maxFiles: DEFAULT_WORK_SHARD_MAX_FILES,
  maxBytes: DEFAULT_WORK_SHARD_MAX_BYTES,
})

const SHA256_PATTERN = /^[a-f0-9]{64}$/
const JOB_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]+$/
const LIMIT_KEYS = new Set(['maxFiles', 'maxBytes'])
const RETRY_OPTION_KEYS = new Set(['parentJobId', 'lens', 'closureRound'])

export class WorkShardError extends Error {
  constructor(code, message, details = {}) {
    super(message)
    this.name = 'WorkShardError'
    this.code = code
    this.details = details
  }
}

function fail(code, message, details = {}) {
  throw new WorkShardError(code, message, details)
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

function requirePlainObject(value, label, code = 'SHAPE_INVALID') {
  if (!isPlainObject(value)) fail(code, `${label} must be a plain object`)
}

function rejectUnknownKeys(value, allowed, label, code) {
  const unknown = Object.keys(value)
    .filter((key) => !allowed.has(key))
    .sort(compareCanonicalStrings)
  if (unknown.length > 0) {
    fail(code, `${label} contains unsupported keys: ${unknown.join(', ')}`, { unknown })
  }
}

function requireIntegerInRange(value, minimum, maximum, label, code) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(code, `${label} must be an integer between ${minimum} and ${maximum}`, {
      actual: value,
      minimum,
      maximum,
    })
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
    fail(
      'WORK_FILE_PATH_INVALID',
      `${label} must be a canonical POSIX repository-relative path`,
    )
  }
  const segments = value.split('/')
  if (
    segments.some((segment) =>
      segment.length === 0
      || segment === '.'
      || segment === '..')
  ) {
    fail(
      'WORK_FILE_PATH_INVALID',
      `${label} contains an empty, current, or parent segment`,
    )
  }
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index)
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1)
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        fail('WORK_FILE_PATH_INVALID', `${label} contains an unpaired Unicode surrogate`)
      }
      index += 1
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      fail('WORK_FILE_PATH_INVALID', `${label} contains an unpaired Unicode surrogate`)
    }
  }
  return value
}

function normalizeOptionalSha256(value, label) {
  if (value === undefined) return null
  if (typeof value !== 'string' || !/^[a-fA-F0-9]{64}$/.test(value)) {
    fail('WORK_FILE_SHA256_INVALID', `${label} must be a 64-character SHA-256 digest`)
  }
  return value.toLowerCase()
}

function normalizeWorkFiles(files) {
  if (!Array.isArray(files)) {
    fail('WORK_FILES_INVALID', 'work files must be an array')
  }
  if (files.length > MAX_WORK_SHARD_FILES) {
    fail(
      'WORK_FILE_LIMIT_EXCEEDED',
      `work scope exceeds ${MAX_WORK_SHARD_FILES} files`,
      { actual: files.length, maximum: MAX_WORK_SHARD_FILES },
    )
  }

  const normalized = files.map((file, index) => {
    requirePlainObject(file, `work file ${index}`, 'WORK_FILE_INVALID')
    const path = canonicalRelativePath(file.path, `work file ${index} path`)
    if (!Number.isSafeInteger(file.size) || file.size < 0) {
      fail(
        'WORK_FILE_SIZE_INVALID',
        `work file ${path} size must be a non-negative safe integer`,
      )
    }
    return Object.freeze({
      path,
      size: file.size,
      sha256: normalizeOptionalSha256(file.sha256, `work file ${path} sha256`),
    })
  })

  normalized.sort((left, right) => compareCanonicalStrings(left.path, right.path))
  for (let index = 1; index < normalized.length; index += 1) {
    if (normalized[index - 1].path === normalized[index].path) {
      fail(
        'WORK_FILE_DUPLICATE',
        `work scope contains duplicate path ${normalized[index].path}`,
      )
    }
  }
  return normalized
}

function digestNormalizedWorkScope(files) {
  const material = files.map(({ path, size, sha256: digest }) => [
    path,
    size,
    digest,
  ])
  return sha256(`red-team-audit:work-scope:v1\0${JSON.stringify(material)}`)
}

function normalizeSha256(value, label) {
  if (typeof value !== 'string' || !/^[a-fA-F0-9]{64}$/.test(value)) {
    fail('WORK_SCOPE_SHA256_INVALID', `${label} must be a 64-character SHA-256 digest`)
  }
  return value.toLowerCase()
}

export function validateWorkShardLimits(limits = {}) {
  requirePlainObject(limits, 'work shard limits', 'WORK_SHARD_LIMITS_INVALID')
  rejectUnknownKeys(
    limits,
    LIMIT_KEYS,
    'work shard limits',
    'WORK_SHARD_LIMITS_INVALID',
  )
  const maxFiles = requireIntegerInRange(
    limits.maxFiles ?? DEFAULT_WORK_SHARD_MAX_FILES,
    1,
    MAX_WORK_SHARD_FILES,
    'maxFiles',
    'WORK_SHARD_LIMITS_INVALID',
  )
  const maxBytes = requireIntegerInRange(
    limits.maxBytes ?? DEFAULT_WORK_SHARD_MAX_BYTES,
    1,
    MAX_WORK_SHARD_BYTES,
    'maxBytes',
    'WORK_SHARD_LIMITS_INVALID',
  )
  return Object.freeze({ maxFiles, maxBytes })
}

export function digestWorkScope(files) {
  return digestNormalizedWorkScope(normalizeWorkFiles(files))
}

export function workShardId(index, scopeSha256) {
  const ordinal = requireIntegerInRange(
    index,
    1,
    MAX_WORK_SHARDS,
    'work shard index',
    'WORK_SHARD_INDEX_INVALID',
  )
  const digest = normalizeSha256(scopeSha256, 'work shard scopeSha256')
  return `shard-${String(ordinal).padStart(4, '0')}-${digest.slice(0, 12)}`
}

export function packWorkShards(files, limits = {}) {
  const { maxFiles, maxBytes } = validateWorkShardLimits(limits)
  const normalized = normalizeWorkFiles(files)
  if (normalized.length === 0) return Object.freeze([])

  const buckets = []
  let current
  for (const file of normalized) {
    if (file.size > maxBytes) {
      fail(
        'WORK_FILE_EXCEEDS_SHARD_BYTE_LIMIT',
        `work file ${file.path} exceeds the ${maxBytes}-byte shard limit`,
        { path: file.path, size: file.size, maxBytes },
      )
    }
    if (
      current === undefined
      || current.files.length >= maxFiles
      || current.byteCount + file.size > maxBytes
    ) {
      current = { files: [], byteCount: 0 }
      buckets.push(current)
    }
    current.files.push(file)
    current.byteCount += file.size
  }

  if (buckets.length > MAX_WORK_SHARDS) {
    fail(
      'WORK_SHARD_COUNT_EXCEEDED',
      `work scope requires ${buckets.length} shards; the maximum is ${MAX_WORK_SHARDS}`,
      { actual: buckets.length, maximum: MAX_WORK_SHARDS },
    )
  }

  const count = buckets.length
  return Object.freeze(buckets.map((bucket, offset) => {
    const index = offset + 1
    const scopeSha256 = digestNormalizedWorkScope(bucket.files)
    const shard = Object.freeze({
      shard_id: workShardId(index, scopeSha256),
      index,
      count,
      file_count: bucket.files.length,
      byte_count: bucket.byteCount,
      max_files: maxFiles,
      max_bytes: maxBytes,
      scope_sha256: scopeSha256,
    })
    return Object.freeze({
      scoped_files: Object.freeze(bucket.files.map(({ path }) => path)),
      shard,
    })
  }))
}

function normalizeJobId(value, label) {
  if (
    typeof value !== 'string'
    || value.length < 3
    || value.length > 160
    || !JOB_ID_PATTERN.test(value)
  ) {
    fail(
      'RETRY_JOB_ID_INVALID',
      `${label} must be a 3-160 character controller job ID`,
    )
  }
  return value
}

function normalizeLens(value) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > 128
    || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value)
  ) {
    fail('RETRY_LENS_INVALID', 'retry lens must be a bounded controller lens name')
  }
  return value
}

function normalizePackedShard(value) {
  requirePlainObject(value, 'packed work shard', 'PACKED_WORK_SHARD_INVALID')
  if (!Array.isArray(value.scoped_files) || value.scoped_files.length === 0) {
    fail(
      'PACKED_WORK_SHARD_INVALID',
      'packed work shard must contain at least one scoped file',
    )
  }
  const scopedFiles = value.scoped_files.map((path, index) =>
    canonicalRelativePath(path, `packed work shard scoped_files[${index}]`))
  for (let index = 1; index < scopedFiles.length; index += 1) {
    if (compareCanonicalStrings(scopedFiles[index - 1], scopedFiles[index]) >= 0) {
      fail(
        'PACKED_WORK_SHARD_INVALID',
        'packed work shard scoped_files must be unique and canonically sorted',
      )
    }
  }

  const metadata = value.shard
  requirePlainObject(metadata, 'packed work shard metadata', 'PACKED_WORK_SHARD_INVALID')
  const index = requireIntegerInRange(
    metadata.index,
    1,
    MAX_WORK_SHARDS,
    'packed work shard index',
    'PACKED_WORK_SHARD_INVALID',
  )
  const count = requireIntegerInRange(
    metadata.count,
    index,
    MAX_WORK_SHARDS,
    'packed work shard count',
    'PACKED_WORK_SHARD_INVALID',
  )
  const limits = validateWorkShardLimits({
    maxFiles: metadata.max_files,
    maxBytes: metadata.max_bytes,
  })
  const fileCount = requireIntegerInRange(
    metadata.file_count,
    1,
    limits.maxFiles,
    'packed work shard file_count',
    'PACKED_WORK_SHARD_INVALID',
  )
  const byteCount = requireIntegerInRange(
    metadata.byte_count,
    0,
    limits.maxBytes,
    'packed work shard byte_count',
    'PACKED_WORK_SHARD_INVALID',
  )
  if (fileCount !== scopedFiles.length) {
    fail(
      'PACKED_WORK_SHARD_INVALID',
      'packed work shard file_count does not match scoped_files',
    )
  }
  const scopeSha256 = normalizeSha256(
    metadata.scope_sha256,
    'packed work shard scope_sha256',
  )
  const shardId = workShardId(index, scopeSha256)
  if (metadata.shard_id !== shardId) {
    fail(
      'PACKED_WORK_SHARD_INVALID',
      'packed work shard ID does not match its index and scope digest',
      { actual: metadata.shard_id, expected: shardId },
    )
  }

  return Object.freeze({
    scoped_files: Object.freeze([...scopedFiles]),
    shard: Object.freeze({
      shard_id: shardId,
      index,
      count,
      file_count: fileCount,
      byte_count: byteCount,
      max_files: limits.maxFiles,
      max_bytes: limits.maxBytes,
      scope_sha256: scopeSha256,
    }),
  })
}

export function buildRetryJobTemplate(workShard, options = {}) {
  requirePlainObject(options, 'retry job options', 'RETRY_OPTIONS_INVALID')
  rejectUnknownKeys(
    options,
    RETRY_OPTION_KEYS,
    'retry job options',
    'RETRY_OPTIONS_INVALID',
  )
  const parentJobId = normalizeJobId(options.parentJobId, 'parentJobId')
  const lens = normalizeLens(options.lens)
  const closureRound = requireIntegerInRange(
    options.closureRound,
    1,
    32,
    'closureRound',
    'RETRY_ROUND_INVALID',
  )
  const packed = normalizePackedShard(workShard)
  const identitySha256 = sha256(
    `red-team-audit:work-shard-retry:v1\0${JSON.stringify([
      parentJobId,
      lens,
      closureRound,
      packed.shard.shard_id,
      packed.shard.scope_sha256,
    ])}`,
  )
  const jobId = [
    'closure',
    String(closureRound).padStart(2, '0'),
    packed.shard.shard_id,
    identitySha256.slice(0, 12),
  ].join(':')

  return Object.freeze({
    job_id: jobId,
    kind: 'LENS',
    state: 'PENDING',
    lens,
    closure_round: closureRound,
    parent_job_id: parentJobId,
    scoped_files: packed.scoped_files,
    shard: packed.shard,
  })
}
