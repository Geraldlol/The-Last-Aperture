import { createHash } from 'node:crypto'
import { constants as FS_CONSTANTS } from 'node:fs'
import { lstat, open, opendir, realpath } from 'node:fs/promises'
import { isAbsolute, join, parse, relative, resolve, sep } from 'node:path'
import { TextDecoder } from 'node:util'

import { compareCanonicalStrings } from './canonical-order.mjs'
import { assertLocalFilesystemEndpoint } from './filesystem-endpoint.mjs'

export const ENGAGEMENT_OUTPUT_BINDING_SCHEMA_VERSION = '1.0.0'
export const ENGAGEMENT_OUTPUT_BINDING_KIND = 'last-aperture/engagement-output-binding'
export const DEFAULT_ENGAGEMENT_OUTPUT_LIMITS = Object.freeze({
  maximumEntries: 50_000,
  maximumTotalBytes: 2 * 1024 * 1024 * 1024,
})

const MAXIMUM_ENTRIES = DEFAULT_ENGAGEMENT_OUTPUT_LIMITS.maximumEntries
const MAXIMUM_TOTAL_BYTES = DEFAULT_ENGAGEMENT_OUTPUT_LIMITS.maximumTotalBytes
const MAXIMUM_DEPTH = 64
const MAXIMUM_PATH_BYTES = 4096
const MAXIMUM_SEGMENT_BYTES = 255
const READ_BUFFER_BYTES = 1024 * 1024
const SHA256 = /^[a-f0-9]{64}$/u
const WINDOWS_RESERVED_NAME = /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$/iu
const BINDING_FIELDS = Object.freeze([
  'schema_version',
  'kind',
  'root_relative_path',
  'root_kind',
  'limits',
  'entry_count',
  'total_size_bytes',
  'entries',
  'tree_sha256',
])
const ENTRY_FIELDS = Object.freeze(['relative_path', 'entry_kind', 'size_bytes', 'sha256'])
const LIMIT_FIELDS = Object.freeze(['maximum_entries', 'maximum_total_bytes'])
const decoder = new TextDecoder('utf-8', { fatal: true })

export class EngagementOutputBindingError extends Error {
  constructor(code, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'EngagementOutputBindingError'
    this.code = code
  }
}

function fail(code, message, options) {
  throw new EngagementOutputBindingError(code, message, options)
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
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

function canonicalBytes(value) {
  return Buffer.from(JSON.stringify(stableValue(value)), 'utf8')
}

function deeplyFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const nested of Object.values(value)) deeplyFreeze(nested)
  return Object.freeze(value)
}

function canonicalCopy(value) {
  return deeplyFreeze(JSON.parse(canonicalBytes(value).toString('utf8')))
}

function exactPlainObject(value, fields, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail('ENGAGEMENT_OUTPUT_BINDING_INVALID', `${label} must be a plain object`)
  }
  let prototype
  let descriptors
  try {
    prototype = Object.getPrototypeOf(value)
    descriptors = Object.getOwnPropertyDescriptors(value)
  } catch (cause) {
    fail('ENGAGEMENT_OUTPUT_BINDING_INVALID', `${label} cannot be inspected safely`, { cause })
  }
  if (
    (prototype !== Object.prototype && prototype !== null)
    || Object.getOwnPropertySymbols(value).length > 0
  ) {
    fail('ENGAGEMENT_OUTPUT_BINDING_INVALID', `${label} must contain only plain JSON state`)
  }
  const actual = Object.keys(descriptors).sort(compareCanonicalStrings)
  const expected = [...fields].sort(compareCanonicalStrings)
  if (
    actual.length !== expected.length
    || actual.some((field, index) => field !== expected[index])
  ) {
    fail('ENGAGEMENT_OUTPUT_BINDING_INVALID', `${label} contains missing or unexpected fields`)
  }
  for (const field of actual) {
    const descriptor = descriptors[field]
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      fail('ENGAGEMENT_OUTPUT_BINDING_INVALID', `${label} contains hidden or computed state`)
    }
  }
  return value
}

function exactPlainArray(value, label) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    fail('ENGAGEMENT_OUTPUT_BINDING_INVALID', `${label} must be a plain array`)
  }
  if (!Number.isSafeInteger(value.length) || value.length > MAXIMUM_ENTRIES) {
    fail('ENGAGEMENT_OUTPUT_BINDING_INVALID', `${label} exceeds the maximum entry count`)
  }
  const descriptors = Object.getOwnPropertyDescriptors(value)
  const actualKeys = Object.keys(descriptors).filter((key) => key !== 'length')
  if (
    actualKeys.length !== value.length
    || actualKeys.some((key, index) => key !== String(index))
  ) {
    fail('ENGAGEMENT_OUTPUT_BINDING_INVALID', `${label} must be dense and contain no extra fields`)
  }
  for (const key of actualKeys) {
    const descriptor = descriptors[key]
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      fail('ENGAGEMENT_OUTPUT_BINDING_INVALID', `${label} contains hidden or computed state`)
    }
  }
  return value
}

function normalizeLimit(value, fallback, hardMaximum, label) {
  const normalized = value ?? fallback
  if (!Number.isSafeInteger(normalized) || normalized < 1 || normalized > hardMaximum) {
    fail(
      'ENGAGEMENT_OUTPUT_LIMIT_INVALID',
      `${label} must be a positive safe integer no greater than ${hardMaximum}`,
    )
  }
  return normalized
}

function normalizeLimits(value = {}) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail('ENGAGEMENT_OUTPUT_LIMIT_INVALID', 'engagement output limits must be an object')
  }
  const allowed = new Set(['maximumEntries', 'maximumTotalBytes'])
  if (Object.keys(value).some((key) => !allowed.has(key))) {
    fail('ENGAGEMENT_OUTPUT_LIMIT_INVALID', 'engagement output limits contain an unexpected field')
  }
  return Object.freeze({
    maximumEntries: normalizeLimit(
      value.maximumEntries,
      DEFAULT_ENGAGEMENT_OUTPUT_LIMITS.maximumEntries,
      MAXIMUM_ENTRIES,
      'maximumEntries',
    ),
    maximumTotalBytes: normalizeLimit(
      value.maximumTotalBytes,
      DEFAULT_ENGAGEMENT_OUTPUT_LIMITS.maximumTotalBytes,
      MAXIMUM_TOTAL_BYTES,
      'maximumTotalBytes',
    ),
  })
}

function assertSafePathSegment(value, label) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value === '.'
    || value === '..'
    || value !== value.normalize('NFC')
    || value.includes('\ufffd')
    || Buffer.byteLength(value, 'utf8') > MAXIMUM_SEGMENT_BYTES
    || /[\\/\u0000-\u001f\u007f<>:"|?*]/u.test(value)
    || /[. ]$/u.test(value)
    || WINDOWS_RESERVED_NAME.test(value)
  ) {
    fail('ENGAGEMENT_OUTPUT_PATH_UNSAFE', `${label} contains a non-canonical or unsafe path segment`)
  }
  return value
}

function canonicalRelativePath(value, label = 'engagement output relative path') {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value === '.'
    || value.includes('\\')
    || value.startsWith('/')
    || value.endsWith('/')
    || isAbsolute(value)
    || Buffer.byteLength(value, 'utf8') > MAXIMUM_PATH_BYTES
  ) {
    fail('ENGAGEMENT_OUTPUT_PATH_UNSAFE', `${label} must be one canonical route-relative path`)
  }
  const segments = value.split('/')
  if (segments.length > MAXIMUM_DEPTH) {
    fail('ENGAGEMENT_OUTPUT_LIMIT_EXCEEDED', `${label} exceeds the maximum path depth`)
  }
  for (const segment of segments) assertSafePathSegment(segment, label)
  return segments.join('/')
}

function samePath(left, right) {
  const normalizedLeft = resolve(left)
  const normalizedRight = resolve(right)
  return process.platform === 'win32'
    ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
    : normalizedLeft === normalizedRight
}

function sameMetadata(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs
    && left.birthtimeNs === right.birthtimeNs
    && left.nlink === right.nlink
}

async function canonicalRealpath(path, label) {
  let canonical
  try {
    canonical = await realpath(path)
  } catch (cause) {
    fail('ENGAGEMENT_OUTPUT_PATH_UNSAFE', `${label} cannot be resolved safely`, { cause })
  }
  assertLocalFilesystemEndpoint(canonical, label)
  if (!samePath(path, canonical)) {
    fail('ENGAGEMENT_OUTPUT_PATH_UNSAFE', `${label} is a symbolic link, junction, or path alias`)
  }
  return canonical
}

async function lstatSafe(path, label) {
  try {
    return await lstat(path, { bigint: true })
  } catch (cause) {
    fail('ENGAGEMENT_OUTPUT_PATH_UNSAFE', `${label} is unavailable or cannot be inspected`, { cause })
  }
}

async function inspectRouteDirectory(routeDirectory) {
  assertLocalFilesystemEndpoint(routeDirectory, 'engagement route directory')
  if (
    typeof routeDirectory !== 'string'
    || !isAbsolute(routeDirectory)
    || resolve(routeDirectory) !== routeDirectory
  ) {
    fail(
      'ENGAGEMENT_OUTPUT_PATH_UNSAFE',
      'engagement route directory must be a canonical absolute local path',
    )
  }
  const filesystemRoot = parse(routeDirectory).root
  if (samePath(routeDirectory, filesystemRoot)) {
    fail('ENGAGEMENT_OUTPUT_PATH_UNSAFE', 'engagement route directory cannot be a filesystem root')
  }
  const rootMetadata = await lstatSafe(filesystemRoot, 'local filesystem root')
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) {
    fail('ENGAGEMENT_OUTPUT_PATH_UNSAFE', 'local filesystem root is linked or is not a directory')
  }
  let current = filesystemRoot
  const parts = relative(filesystemRoot, routeDirectory).split(/[\\/]/u).filter(Boolean)
  for (const [index, part] of parts.entries()) {
    current = join(current, part)
    const metadata = await lstatSafe(current, 'engagement route directory')
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
      fail(
        'ENGAGEMENT_OUTPUT_PATH_UNSAFE',
        index === parts.length - 1
          ? 'engagement route directory must be a non-link directory'
          : 'engagement route directory crosses a symbolic link or non-directory ancestor',
      )
    }
  }
  const metadata = await lstatSafe(routeDirectory, 'engagement route directory')
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    fail('ENGAGEMENT_OUTPUT_PATH_UNSAFE', 'engagement route directory must be a non-link directory')
  }
  const canonical = await canonicalRealpath(routeDirectory, 'engagement route directory')
  return { canonical, metadata }
}

async function inspectOutputAncestors(routeDirectory, canonicalRouteDirectory, relativePath) {
  const observed = []
  let current = routeDirectory
  const segments = relativePath.split('/')
  for (const [index, segment] of segments.entries()) {
    current = join(current, segment)
    const metadata = await lstatSafe(current, 'engagement route output')
    if (metadata.isSymbolicLink()) {
      fail('ENGAGEMENT_OUTPUT_PATH_UNSAFE', 'engagement route output crosses a symbolic link or junction')
    }
    if (index < segments.length - 1 && !metadata.isDirectory()) {
      fail('ENGAGEMENT_OUTPUT_PATH_UNSAFE', 'engagement route output crosses a non-directory ancestor')
    }
    if (index < segments.length - 1) observed.push({ path: current, metadata })
  }
  const canonical = await canonicalRealpath(current, 'engagement route output')
  const canonicalRelative = relative(canonicalRouteDirectory, canonical).split(/[\\/]/u).join('/')
  if (canonicalRelative !== relativePath) {
    fail('ENGAGEMENT_OUTPUT_PATH_UNSAFE', 'engagement route output path does not use its exact filesystem name')
  }
  return { outputPath: current, observed }
}

function reserveEntry(state) {
  state.entryCount += 1
  if (state.entryCount > state.limits.maximumEntries) {
    fail(
      'ENGAGEMENT_OUTPUT_LIMIT_EXCEEDED',
      `engagement route output exceeds ${state.limits.maximumEntries} entries`,
    )
  }
}

function reserveBytes(state, size) {
  if (size < 0n || size > BigInt(Number.MAX_SAFE_INTEGER)) {
    fail('ENGAGEMENT_OUTPUT_LIMIT_EXCEEDED', 'engagement route output contains an unsupported file size')
  }
  const next = BigInt(state.totalBytes) + size
  if (next > BigInt(state.limits.maximumTotalBytes)) {
    fail(
      'ENGAGEMENT_OUTPUT_LIMIT_EXCEEDED',
      `engagement route output exceeds ${state.limits.maximumTotalBytes} bytes`,
    )
  }
  state.totalBytes = Number(next)
}

async function assertNodeStillStable(path, expected, label) {
  const current = await lstatSafe(path, label)
  if (current.isSymbolicLink() || !sameMetadata(expected, current)) {
    fail('ENGAGEMENT_OUTPUT_CHANGED', `${label} changed while its output binding was created`)
  }
  await canonicalRealpath(path, label)
}

async function hashRegularFile(path, endpoint, state) {
  if (!endpoint.isFile() || endpoint.isSymbolicLink() || endpoint.nlink !== 1n) {
    fail(
      'ENGAGEMENT_OUTPUT_ENTRY_UNSAFE',
      'engagement route output must contain only regular single-link files and directories',
    )
  }
  if (endpoint.size > BigInt(state.limits.maximumTotalBytes)) {
    fail('ENGAGEMENT_OUTPUT_LIMIT_EXCEEDED', 'engagement route output file exceeds the byte limit')
  }
  const flags = FS_CONSTANTS.O_RDONLY
    | (FS_CONSTANTS.O_NOFOLLOW ?? 0)
    | (FS_CONSTANTS.O_NONBLOCK ?? 0)
  let handle
  try {
    handle = await open(path, flags)
    const heldBefore = await handle.stat({ bigint: true })
    if (
      !heldBefore.isFile()
      || heldBefore.isSymbolicLink()
      || heldBefore.nlink !== 1n
      || !sameMetadata(endpoint, heldBefore)
    ) {
      fail('ENGAGEMENT_OUTPUT_CHANGED', 'engagement route output file changed before hashing')
    }
    reserveBytes(state, heldBefore.size)
    const hash = createHash('sha256')
    const buffer = Buffer.allocUnsafe(READ_BUFFER_BYTES)
    let position = 0n
    while (position < heldBefore.size) {
      const remaining = heldBefore.size - position
      const wanted = Number(remaining > BigInt(buffer.length) ? BigInt(buffer.length) : remaining)
      const { bytesRead } = await handle.read(buffer, 0, wanted, Number(position))
      if (bytesRead === 0) break
      hash.update(buffer.subarray(0, bytesRead))
      position += BigInt(bytesRead)
    }
    const heldAfter = await handle.stat({ bigint: true })
    const endpointAfter = await lstatSafe(path, 'engagement route output file')
    if (
      position !== heldBefore.size
      || !sameMetadata(heldBefore, heldAfter)
      || endpointAfter.isSymbolicLink()
      || !sameMetadata(heldBefore, endpointAfter)
    ) {
      fail('ENGAGEMENT_OUTPUT_CHANGED', 'engagement route output file changed while hashing')
    }
    await canonicalRealpath(path, 'engagement route output file')
    state.observed.push({ path, metadata: heldAfter, label: 'engagement route output file' })
    return { size: Number(position), sha256: hash.digest('hex') }
  } catch (cause) {
    if (cause instanceof EngagementOutputBindingError) throw cause
    fail('ENGAGEMENT_OUTPUT_PATH_UNSAFE', 'engagement route output file could not be opened safely', { cause })
  } finally {
    await handle?.close()
  }
}

function directoryDigest(children) {
  return sha256(canonicalBytes({
    kind: 'directory',
    children: children.map(({ name, entry_kind: entryKind, size_bytes: sizeBytes, sha256: digest }) => ({
      name,
      entry_kind: entryKind,
      size_bytes: sizeBytes,
      sha256: digest,
    })),
  }))
}

async function readDirectoryNames(path, state) {
  let directory
  const names = []
  try {
    directory = await opendir(path, { encoding: 'buffer', bufferSize: 32 })
    while (true) {
      const entry = await directory.read()
      if (entry === null) break
      reserveEntry(state)
      if (entry.isSymbolicLink()) {
        fail('ENGAGEMENT_OUTPUT_ENTRY_UNSAFE', 'engagement route output contains a symbolic link or junction')
      }
      names.push(entry.name)
    }
  } catch (cause) {
    if (cause instanceof EngagementOutputBindingError) throw cause
    fail('ENGAGEMENT_OUTPUT_PATH_UNSAFE', 'engagement route output directory cannot be read safely', { cause })
  } finally {
    try { await directory?.close() } catch (cause) {
      if (cause?.code !== 'ERR_DIR_CLOSED') {
        fail('ENGAGEMENT_OUTPUT_PATH_UNSAFE', 'engagement route output directory could not be closed safely', { cause })
      }
    }
  }
  const decoded = names.map((name) => {
    try {
      return decoder.decode(name)
    } catch (cause) {
      fail('ENGAGEMENT_OUTPUT_PATH_UNSAFE', 'engagement route output contains a non-UTF-8 filename', { cause })
    }
  })
  for (const name of decoded) assertSafePathSegment(name, 'engagement route output filename')
  decoded.sort(compareCanonicalStrings)
  if (decoded.some((name, index) => index > 0 && name === decoded[index - 1])) {
    fail('ENGAGEMENT_OUTPUT_PATH_UNSAFE', 'engagement route output contains an ambiguous duplicate filename')
  }
  return decoded
}

async function scanNode(path, relativePath, state, depth) {
  if (depth > MAXIMUM_DEPTH || Buffer.byteLength(relativePath, 'utf8') > MAXIMUM_PATH_BYTES) {
    fail('ENGAGEMENT_OUTPUT_LIMIT_EXCEEDED', 'engagement route output exceeds path bounds')
  }
  const before = await lstatSafe(path, 'engagement route output entry')
  if (before.isSymbolicLink()) {
    fail('ENGAGEMENT_OUTPUT_ENTRY_UNSAFE', 'engagement route output contains a symbolic link or junction')
  }
  await canonicalRealpath(path, 'engagement route output entry')
  if (before.isFile()) {
    const file = await hashRegularFile(path, before, state)
    const entry = {
      relative_path: relativePath,
      entry_kind: 'file',
      size_bytes: file.size,
      sha256: file.sha256,
    }
    state.entries.push(entry)
    return { ...entry, name: relativePath.split('/').at(-1) }
  }
  if (!before.isDirectory()) {
    fail(
      'ENGAGEMENT_OUTPUT_ENTRY_UNSAFE',
      'engagement route output contains a socket, device, pipe, or other non-regular entry',
    )
  }
  const names = await readDirectoryNames(path, state)
  const children = []
  for (const name of names) {
    children.push(await scanNode(join(path, name), `${relativePath}/${name}`, state, depth + 1))
  }
  await assertNodeStillStable(path, before, 'engagement route output directory')
  state.observed.push({ path, metadata: before, label: 'engagement route output directory' })
  const size = children.reduce((total, child) => total + child.size_bytes, 0)
  const entry = {
    relative_path: relativePath,
    entry_kind: 'directory',
    size_bytes: size,
    sha256: directoryDigest(children),
  }
  state.entries.push(entry)
  return { ...entry, name: relativePath.split('/').at(-1) }
}

async function scanOutput(routeDirectory, relativePath, limits) {
  const route = await inspectRouteDirectory(routeDirectory)
  const { outputPath, observed: ancestors } = await inspectOutputAncestors(
    routeDirectory,
    route.canonical,
    relativePath,
  )
  const containment = relative(routeDirectory, outputPath)
  if (
    containment.length === 0
    || containment === '..'
    || containment.startsWith(`..${sep}`)
    || isAbsolute(containment)
  ) {
    fail('ENGAGEMENT_OUTPUT_PATH_UNSAFE', 'engagement route output must stay inside its route directory')
  }
  const state = { entries: [], observed: [], entryCount: 0, totalBytes: 0, limits }
  reserveEntry(state)
  const root = await scanNode(outputPath, relativePath, state, relativePath.split('/').length)
  for (const observed of [...ancestors, ...state.observed]) {
    await assertNodeStillStable(observed.path, observed.metadata, observed.label ?? 'output ancestor')
  }
  await assertNodeStillStable(routeDirectory, route.metadata, 'engagement route directory')
  state.entries.sort((left, right) => compareCanonicalStrings(left.relative_path, right.relative_path))
  return { root, entries: state.entries, entryCount: state.entryCount, totalBytes: state.totalBytes }
}

function validatePersistedLimits(value) {
  exactPlainObject(value, LIMIT_FIELDS, 'engagement output binding limits')
  return normalizeLimits({
    maximumEntries: value.maximum_entries,
    maximumTotalBytes: value.maximum_total_bytes,
  })
}

function parentRelativePath(path) {
  const offset = path.lastIndexOf('/')
  return offset === -1 ? null : path.slice(0, offset)
}

function validateEntry(value, index, limits) {
  exactPlainObject(value, ENTRY_FIELDS, `engagement output binding entry ${index}`)
  const relativePath = canonicalRelativePath(value.relative_path, `engagement output binding entry ${index}`)
  if (value.entry_kind !== 'file' && value.entry_kind !== 'directory') {
    fail('ENGAGEMENT_OUTPUT_BINDING_INVALID', `engagement output binding entry ${index} has an invalid kind`)
  }
  if (
    !Number.isSafeInteger(value.size_bytes)
    || value.size_bytes < 0
    || value.size_bytes > limits.maximumTotalBytes
  ) {
    fail('ENGAGEMENT_OUTPUT_BINDING_INVALID', `engagement output binding entry ${index} has an invalid size`)
  }
  if (typeof value.sha256 !== 'string' || !SHA256.test(value.sha256)) {
    fail('ENGAGEMENT_OUTPUT_BINDING_INVALID', `engagement output binding entry ${index} has an invalid digest`)
  }
  return { ...value, relative_path: relativePath }
}

function treeProjection(binding) {
  const { tree_sha256: _treeSha256, limits: _limits, ...projection } = binding
  return projection
}

function assertCoherentTree(binding) {
  const byPath = new Map(binding.entries.map((entry) => [entry.relative_path, entry]))
  if (byPath.size !== binding.entries.length) {
    fail('ENGAGEMENT_OUTPUT_BINDING_INVALID', 'engagement output binding contains duplicate paths')
  }
  const root = byPath.get(binding.root_relative_path)
  if (root === undefined || root.entry_kind !== binding.root_kind) {
    fail('ENGAGEMENT_OUTPUT_BINDING_INVALID', 'engagement output binding root entry is missing or inconsistent')
  }
  const children = new Map()
  for (const entry of binding.entries) {
    if (
      entry.relative_path !== binding.root_relative_path
      && !entry.relative_path.startsWith(`${binding.root_relative_path}/`)
    ) {
      fail('ENGAGEMENT_OUTPUT_BINDING_INVALID', 'engagement output binding entry escapes its declared root')
    }
    if (entry.relative_path === binding.root_relative_path) continue
    const parentPath = parentRelativePath(entry.relative_path)
    const parent = byPath.get(parentPath)
    if (parent?.entry_kind !== 'directory') {
      fail('ENGAGEMENT_OUTPUT_BINDING_INVALID', 'engagement output binding has a missing or non-directory parent')
    }
    const siblings = children.get(parentPath) ?? []
    siblings.push({ ...entry, name: entry.relative_path.slice(parentPath.length + 1) })
    children.set(parentPath, siblings)
  }
  const directories = binding.entries
    .filter((entry) => entry.entry_kind === 'directory')
    .sort((left, right) => right.relative_path.split('/').length - left.relative_path.split('/').length)
  for (const directory of directories) {
    const immediate = (children.get(directory.relative_path) ?? [])
      .sort((left, right) => compareCanonicalStrings(left.name, right.name))
    const size = immediate.reduce((total, child) => total + child.size_bytes, 0)
    if (directory.size_bytes !== size || directory.sha256 !== directoryDigest(immediate)) {
      fail('ENGAGEMENT_OUTPUT_BINDING_INVALID', 'engagement output binding directory digest is inconsistent')
    }
  }
  if (binding.total_size_bytes !== root.size_bytes) {
    fail('ENGAGEMENT_OUTPUT_BINDING_INVALID', 'engagement output binding total does not match its root')
  }
}

function assertValidBinding(value) {
  exactPlainObject(value, BINDING_FIELDS, 'engagement output binding')
  if (
    value.schema_version !== ENGAGEMENT_OUTPUT_BINDING_SCHEMA_VERSION
    || value.kind !== ENGAGEMENT_OUTPUT_BINDING_KIND
  ) {
    fail('ENGAGEMENT_OUTPUT_BINDING_INVALID', 'engagement output binding identity is unsupported')
  }
  const rootRelativePath = canonicalRelativePath(value.root_relative_path, 'engagement output binding root')
  if (value.root_kind !== 'file' && value.root_kind !== 'directory') {
    fail('ENGAGEMENT_OUTPUT_BINDING_INVALID', 'engagement output binding root kind is invalid')
  }
  const limits = validatePersistedLimits(value.limits)
  exactPlainArray(value.entries, 'engagement output binding entries')
  if (value.entries.length < 1 || value.entries.length > limits.maximumEntries) {
    fail('ENGAGEMENT_OUTPUT_BINDING_INVALID', 'engagement output binding entry count exceeds its limits')
  }
  const entries = value.entries.map((entry, index) => validateEntry(entry, index, limits))
  if (
    !Number.isSafeInteger(value.entry_count)
    || value.entry_count !== entries.length
    || !Number.isSafeInteger(value.total_size_bytes)
    || value.total_size_bytes < 0
    || value.total_size_bytes > limits.maximumTotalBytes
  ) {
    fail('ENGAGEMENT_OUTPUT_BINDING_INVALID', 'engagement output binding totals are invalid')
  }
  for (let index = 1; index < entries.length; index += 1) {
    if (compareCanonicalStrings(entries[index - 1].relative_path, entries[index].relative_path) >= 0) {
      fail('ENGAGEMENT_OUTPUT_BINDING_INVALID', 'engagement output binding entries are not canonically ordered')
    }
  }
  if (typeof value.tree_sha256 !== 'string' || !SHA256.test(value.tree_sha256)) {
    fail('ENGAGEMENT_OUTPUT_BINDING_INVALID', 'engagement output binding tree digest is invalid')
  }
  const normalized = {
    ...value,
    root_relative_path: rootRelativePath,
    entries,
  }
  assertCoherentTree(normalized)
  if (sha256(canonicalBytes(treeProjection(normalized))) !== value.tree_sha256) {
    fail('ENGAGEMENT_OUTPUT_BINDING_INVALID', 'engagement output binding tree digest does not match its manifest')
  }
  return normalized
}

/**
 * Hash one completed file or directory tree below an engagement route directory.
 * The returned object contains no timestamps or host-specific absolute paths.
 */
export async function bindEngagementOutput({ routeDirectory, relativePath, limits: rawLimits } = {}) {
  const normalizedRelativePath = canonicalRelativePath(relativePath)
  const limits = normalizeLimits(rawLimits)
  const scanned = await scanOutput(routeDirectory, normalizedRelativePath, limits)
  const projection = {
    schema_version: ENGAGEMENT_OUTPUT_BINDING_SCHEMA_VERSION,
    kind: ENGAGEMENT_OUTPUT_BINDING_KIND,
    root_relative_path: normalizedRelativePath,
    root_kind: scanned.root.entry_kind,
    limits: {
      maximum_entries: limits.maximumEntries,
      maximum_total_bytes: limits.maximumTotalBytes,
    },
    entry_count: scanned.entryCount,
    total_size_bytes: scanned.totalBytes,
    entries: scanned.entries,
  }
  const binding = { ...projection, tree_sha256: sha256(canonicalBytes(treeProjection(projection))) }
  assertValidBinding(binding)
  return canonicalCopy(binding)
}

/** Verify both a binding's internal structure and the current route output bytes. */
export async function verifyEngagementOutputBinding({ routeDirectory, binding } = {}) {
  const expected = canonicalCopy(assertValidBinding(binding))
  let actual
  try {
    actual = await bindEngagementOutput({
      routeDirectory,
      relativePath: expected.root_relative_path,
      limits: {
        maximumEntries: expected.limits.maximum_entries,
        maximumTotalBytes: expected.limits.maximum_total_bytes,
      },
    })
  } catch (cause) {
    if (cause?.code === 'ENGAGEMENT_OUTPUT_BINDING_INVALID') throw cause
    fail(
      'ENGAGEMENT_OUTPUT_BINDING_MISMATCH',
      'engagement route output cannot be verified against its persisted binding',
      { cause },
    )
  }
  if (!canonicalBytes(actual).equals(canonicalBytes(expected))) {
    fail(
      'ENGAGEMENT_OUTPUT_BINDING_MISMATCH',
      'engagement route output differs from its persisted binding',
    )
  }
  return expected
}

/** Return a digest suitable for binding this manifest into a route result or ledger record. */
export function digestEngagementOutputBinding(binding) {
  return sha256(canonicalBytes(assertValidBinding(binding)))
}

/** Serialize a validated binding for create-only persistence. */
export function canonicalEngagementOutputBinding(binding) {
  return `${canonicalBytes(assertValidBinding(binding)).toString('utf8')}\n`
}
