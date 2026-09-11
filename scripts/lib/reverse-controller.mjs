import { createHash, randomBytes } from 'node:crypto'
import { constants } from 'node:fs'
import {
  lstat,
  mkdir,
  open,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises'
import {
  dirname,
  extname,
  isAbsolute,
  join,
  parse,
  relative,
  resolve,
} from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  canonicalReverseEvidence,
  FRIDA_REVERSE_PROFILE,
  GHIDRA_GENERIC_PATH_SEGMENTS,
  GHIDRA_REVERSE_PROFILE,
} from './reverse-contracts.mjs'
import {
  buildFridaArguments,
  buildFridaTracePlanArguments,
  digestFridaTracePlan,
  FRIDA_V2_AGENT_PATH,
  FRIDA_V2_PROFILE_ID,
  parseFridaTracePlanOutput,
  runFridaTrace,
  runFridaTracePlan,
  assertValidFridaTracePlan,
} from './reverse-frida.mjs'
import {
  GHIDRA_WINDOWS_AGENT_MANIFEST_PATH,
  GHIDRA_WINDOWS_AGENT_SOURCE_PATH,
  assertSupportedGhidraLauncher,
  buildGhidraArguments,
  prepareWindowsGhidraCompatibilityAgent,
  runGhidraHeadless,
} from './reverse-ghidra.mjs'
import { isWindowsBatchLauncher } from './reverse-process.mjs'
import {
  buildNativeInteractionContract,
  canonicalNativeInteractionContract,
  digestNativeInteractionContract,
} from './reverse-protocol.mjs'
import {
  canonicalWebSessionEvidence,
  digestWebSessionEvidence,
  importWebHarEvidence,
} from './reverse-web-har.mjs'
import { importBurpHttpItemsEvidence } from './reverse-web-burp.mjs'
import { assertLocalFilesystemEndpoint } from './filesystem-endpoint.mjs'
import { compareCanonicalStrings } from './canonical-order.mjs'
import { stableJson } from './run-engine.mjs'

const MAX_JSON_INPUT_BYTES = 64 * 1024 * 1024
const MAX_PROTOCOL_INPUT_BYTES = 128 * 1024 * 1024
const MAX_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024
const MAX_OUTPUT_BYTES = 16 * 1024 * 1024
const MAX_OBSERVATIONS = 10_000
const GHIDRA_ANALYSIS_SECONDS = 300
const GHIDRA_TIMEOUT_MS = 360_000
const FRIDA_DURATION_SECONDS = 5
const FRIDA_MAX_EVENTS = 1_000
const FRIDA_TIMEOUT_MS = 8_000
const ARTIFACT_KINDS = new Set(['firmware-image', 'native-executable', 'shared-library'])
const OPEN_READ_FLAGS = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/u
const GHIDRA_EXPORTER_PATH = fileURLToPath(
  new URL('../ghidra/LastApertureExport.java', import.meta.url),
)
const FRIDA_AGENT_PATH = fileURLToPath(
  new URL('../frida/native-call-trace-v1.js', import.meta.url),
)
const FRIDA_PLAN_MAX_BYTES = 1024 * 1024

function fail(code, message, cause) {
  const error = new Error(message, cause ? { cause } : undefined)
  error.name = 'ReverseControllerError'
  error.code = code
  throw error
}

function localAbsolutePath(value, label) {
  assertLocalFilesystemEndpoint(value, label)
  if (
    typeof value !== 'string'
    || value.length < 1
    || value.length > 4096
    || value.trim() !== value
    || CONTROL.test(value)
    || !isAbsolute(value)
  ) fail('REVERSE_PATH_INVALID', `${label} must be an absolute local filesystem path`)
  const absolute = resolve(value)
  assertLocalFilesystemEndpoint(absolute, label)
  return absolute
}

function pathKey(value) {
  return process.platform === 'win32' ? value.toLowerCase() : value
}

function equalPath(left, right) {
  return pathKey(left) === pathKey(right)
}

function inside(parent, child) {
  const result = relative(parent, child)
  return result !== '' && result !== '..' && !result.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) && !isAbsolute(result)
}

function sameFile(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs
    && left.nlink === right.nlink
}

function regularSingleLink(metadata) {
  return metadata.isFile()
    && !metadata.isSymbolicLink()
    && (metadata.nlink === 1 || metadata.nlink === 1n)
}

async function checkedExistingPath(path, kind, { maximumBytes = Number.MAX_SAFE_INTEGER } = {}) {
  const absolute = localAbsolutePath(path, `${kind} path`)
  const filesystemRoot = parse(absolute).root
  let current = filesystemRoot
  let metadata = await lstat(current, { bigint: true })
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    fail('REVERSE_PATH_UNSAFE', `${kind} path has a linked or non-directory filesystem root`)
  }
  const parts = relative(filesystemRoot, absolute).split(/[\\/]/u).filter(Boolean)
  for (const [index, part] of parts.entries()) {
    current = join(current, part)
    metadata = await lstat(current, { bigint: true })
    if (metadata.isSymbolicLink()) fail('REVERSE_PATH_UNSAFE', `${kind} path contains a symbolic link or junction`)
    if (index < parts.length - 1 && !metadata.isDirectory()) {
      fail('REVERSE_PATH_UNSAFE', `${kind} path has a non-directory ancestor`)
    }
  }
  if (kind === 'directory') {
    if (!metadata.isDirectory()) fail('REVERSE_PATH_UNSAFE', `${kind} path must be a directory`)
  } else {
    if (!regularSingleLink(metadata)) fail('REVERSE_PATH_UNSAFE', `${kind} path must be one regular unlinked file`)
    if (metadata.size < 1n || metadata.size > BigInt(maximumBytes)) {
      fail('REVERSE_INPUT_SIZE_INVALID', `${kind} file is empty or exceeds its byte limit`)
    }
  }
  const canonical = await realpath(absolute)
  assertLocalFilesystemEndpoint(canonical, `${kind} path`)
  if (!equalPath(canonical, absolute)) fail('REVERSE_PATH_UNSAFE', `${kind} path is not canonical`)
  return { path: absolute, metadata }
}

async function checkedDirectory(path) {
  return (await checkedExistingPath(path, 'directory')).path
}

async function readStableFile(path, maximumBytes) {
  const endpoint = await checkedExistingPath(path, 'input', { maximumBytes })
  let handle
  try {
    handle = await open(endpoint.path, OPEN_READ_FLAGS)
    const heldBefore = await handle.stat({ bigint: true })
    if (!regularSingleLink(heldBefore) || !sameFile(endpoint.metadata, heldBefore)) {
      fail('REVERSE_INPUT_CHANGED', 'input identity changed before it was read')
    }
    const length = Number(heldBefore.size)
    const bytes = Buffer.alloc(length + 1)
    let offset = 0
    while (offset < bytes.length) {
      const result = await handle.read(bytes, offset, bytes.length - offset, offset)
      if (result.bytesRead === 0) break
      offset += result.bytesRead
    }
    const heldAfter = await handle.stat({ bigint: true })
    const endpointAfter = await checkedExistingPath(endpoint.path, 'input', { maximumBytes })
    if (
      offset !== length
      || !sameFile(heldBefore, heldAfter)
      || !sameFile(heldBefore, endpointAfter.metadata)
    ) fail('REVERSE_INPUT_CHANGED', 'input identity or content length changed while it was read')
    return bytes.subarray(0, offset)
  } finally {
    await handle?.close()
  }
}

async function hashStableFile(path, maximumBytes = MAX_ARTIFACT_BYTES) {
  const endpoint = await checkedExistingPath(path, 'artifact', { maximumBytes })
  let handle
  try {
    handle = await open(endpoint.path, OPEN_READ_FLAGS)
    const heldBefore = await handle.stat({ bigint: true })
    if (!regularSingleLink(heldBefore) || !sameFile(endpoint.metadata, heldBefore)) {
      fail('REVERSE_ARTIFACT_CHANGED', 'artifact identity changed before hashing')
    }
    const digest = createHash('sha256')
    const buffer = Buffer.allocUnsafe(1024 * 1024)
    let position = 0
    while (position < Number(heldBefore.size)) {
      const wanted = Math.min(buffer.length, Number(heldBefore.size) - position)
      const { bytesRead } = await handle.read(buffer, 0, wanted, position)
      if (bytesRead === 0) break
      digest.update(buffer.subarray(0, bytesRead))
      position += bytesRead
    }
    const heldAfter = await handle.stat({ bigint: true })
    const endpointAfter = await checkedExistingPath(endpoint.path, 'artifact', { maximumBytes })
    if (
      position !== Number(heldBefore.size)
      || !sameFile(heldBefore, heldAfter)
      || !sameFile(heldBefore, endpointAfter.metadata)
    ) fail('REVERSE_ARTIFACT_CHANGED', 'artifact identity or content length changed while hashing')
    return { sha256: digest.digest('hex'), size: Number(heldBefore.size) }
  } finally {
    await handle?.close()
  }
}

function sameHash(left, right) {
  return left.sha256 === right.sha256 && left.size === right.size
}

async function assertToolFilesUnchanged(files) {
  let observed
  try {
    observed = await Promise.all(files.map(({ path, maximumBytes }) => (
      hashStableFile(path, maximumBytes)
    )))
  } catch (error) {
    fail('REVERSE_TOOL_RECHECK_FAILED', 'a fixed tool file could not be revalidated', error)
  }
  if (observed.some((hash, index) => !sameHash(hash, files[index].expected))) {
    fail('REVERSE_TOOL_CHANGED', 'a fixed tool file changed around execution')
  }
}

function decodeJson(bytes, label) {
  let text
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    fail('REVERSE_JSON_INVALID', `${label} must contain valid UTF-8 JSON`)
  }
  try {
    return JSON.parse(text)
  } catch {
    fail('REVERSE_JSON_INVALID', `${label} must contain valid JSON`)
  }
}

async function readJson(path, label, maximumBytes = MAX_JSON_INPUT_BYTES) {
  return decodeJson(await readStableFile(localAbsolutePath(path, label), maximumBytes), label)
}

async function assertOutputAbsent(path, label) {
  const absolute = localAbsolutePath(path, label)
  const parent = dirname(absolute)
  if (equalPath(parent, absolute)) fail('REVERSE_OUTPUT_INVALID', `${label} cannot be a filesystem root`)
  await checkedDirectory(parent)
  try {
    await lstat(absolute)
  } catch (error) {
    if (error?.code === 'ENOENT') return absolute
    throw error
  }
  fail('REVERSE_OUTPUT_EXISTS', `${label} already exists; refusing to overwrite it`)
}

async function exclusiveWrite(path, content) {
  try {
    await writeFile(path, content, { encoding: 'utf8', flag: 'wx', mode: 0o600 })
  } catch (error) {
    if (error?.code === 'EEXIST') fail('REVERSE_OUTPUT_EXISTS', `output already exists; refusing to overwrite: ${path}`)
    throw error
  }
}

async function outputDirectoryCandidate(path, labRoot) {
  const absolute = await assertOutputAbsent(path, 'output directory')
  if (labRoot && (equalPath(labRoot, absolute) || inside(labRoot, absolute))) {
    fail('REVERSE_OUTPUT_IN_LAB', 'output directory must be outside the executable lab root')
  }
  return absolute
}

async function createOutputDirectory(absolute) {
  try {
    await mkdir(absolute, { recursive: false, mode: 0o700 })
  } catch (error) {
    if (error?.code === 'EEXIST') fail('REVERSE_OUTPUT_EXISTS', 'output directory already exists; refusing to overwrite it')
    throw error
  }
  let metadata
  try {
    metadata = await lstat(absolute, { bigint: true })
    const canonical = await realpath(absolute)
    if (!metadata.isDirectory() || metadata.isSymbolicLink() || !equalPath(canonical, absolute)) {
      fail('REVERSE_OUTPUT_INVALID', 'new output directory identity could not be verified')
    }
    return metadata
  } catch (error) {
    if (metadata && await cleanupOwnedOutputDirectory(absolute, metadata)) throw error
    fail(
      'REVERSE_OUTPUT_SETUP_CLEANUP_FAILED',
      'new output directory verification failed and safe cleanup was not confirmed',
      error,
    )
  }
}

function sameDirectoryIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino
}

async function cleanupOwnedOutputDirectory(absolute, expectedMetadata) {
  try {
    const metadata = await lstat(absolute, { bigint: true })
    const canonical = await realpath(absolute)
    if (
      !metadata.isDirectory()
      || metadata.isSymbolicLink()
      || !sameDirectoryIdentity(metadata, expectedMetadata)
      || !equalPath(canonical, absolute)
    ) return false
    await rm(absolute, { recursive: true, force: false })
    try {
      await lstat(absolute)
    } catch (error) {
      if (error?.code === 'ENOENT') return true
      throw error
    }
    return false
  } catch (error) {
    return error?.code === 'ENOENT'
  }
}

async function initializeOutputDirectory(absolute, initialize) {
  const metadata = await createOutputDirectory(absolute)
  try {
    await initialize()
  } catch (error) {
    const cleaned = await cleanupOwnedOutputDirectory(absolute, metadata)
    if (!cleaned) {
      fail(
        'REVERSE_OUTPUT_SETUP_CLEANUP_FAILED',
        'output setup failed and the controller could not safely remove its new directory',
        error,
      )
    }
    throw error
  }
}

function validateRelativeArtifactPath(value) {
  if (
    typeof value !== 'string'
    || value.length < 1
    || value.length > 2048
    || value.trim() !== value
    || CONTROL.test(value)
    || isAbsolute(value)
  ) fail('REVERSE_BINARY_INVALID', 'binary must be one contained relative path')
  const parts = value.split(/[\\/]/u)
  if (parts.some((part) => part.length === 0 || part === '.' || part === '..' || part.includes(':'))) {
    fail('REVERSE_BINARY_INVALID', 'binary must be one contained relative path without traversal')
  }
  return { parts, canonical: parts.join('/') }
}

async function resolveArtifact(labRootValue, binaryValue) {
  const labRoot = await checkedDirectory(localAbsolutePath(labRootValue, 'lab root'))
  const relativeArtifact = validateRelativeArtifactPath(binaryValue)
  const requested = resolve(labRoot, ...relativeArtifact.parts)
  if (!inside(labRoot, requested)) fail('REVERSE_BINARY_INVALID', 'binary must remain contained beneath the lab root')
  const endpoint = await checkedExistingPath(requested, 'artifact', { maximumBytes: MAX_ARTIFACT_BYTES })
  if (!inside(labRoot, endpoint.path)) fail('REVERSE_BINARY_INVALID', 'binary must remain contained beneath the lab root')
  return { labRoot, path: endpoint.path, relativePath: relativeArtifact.canonical }
}

async function verifyTool(path, label) {
  return (await checkedExistingPath(localAbsolutePath(path, label), 'tool', {
    maximumBytes: MAX_ARTIFACT_BYTES,
  })).path
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function toolComponent(role, name, hash) {
  return {
    role,
    name,
    sha256: hash.sha256,
    size_bytes: hash.size,
  }
}

function mergeToolComponents(...groups) {
  const byRole = new Map()
  for (const component of groups.flat()) {
    if (byRole.has(component.role)) {
      fail('REVERSE_TOOL_PROVENANCE_INVALID', `duplicate fixed tool component role: ${component.role}`)
    }
    byRole.set(component.role, component)
  }
  return [...byRole.values()].sort((left, right) => (
    compareCanonicalStrings(left.role, right.role)
  ))
}

function canonicalTimestamp(value) {
  const date = value instanceof Date ? value : new Date(value)
  if (Number.isNaN(date.getTime())) fail('REVERSE_CLOCK_INVALID', 'controller clock returned an invalid date')
  return date.toISOString()
}

function newRunId() {
  return `reverse:${randomBytes(16).toString('hex')}`
}

async function copyArtifact(source, destination, expected) {
  const endpoint = await checkedExistingPath(source, 'artifact', { maximumBytes: MAX_ARTIFACT_BYTES })
  let sourceHandle
  let destinationHandle
  try {
    sourceHandle = await open(endpoint.path, OPEN_READ_FLAGS)
    const heldBefore = await sourceHandle.stat({ bigint: true })
    if (!regularSingleLink(heldBefore) || !sameFile(endpoint.metadata, heldBefore)) {
      fail('REVERSE_ARTIFACT_CHANGED', 'artifact identity changed before staging')
    }
    destinationHandle = await open(destination, 'wx', 0o600)
    const digest = createHash('sha256')
    const buffer = Buffer.allocUnsafe(1024 * 1024)
    let position = 0
    while (position < Number(heldBefore.size)) {
      const wanted = Math.min(buffer.length, Number(heldBefore.size) - position)
      const { bytesRead } = await sourceHandle.read(buffer, 0, wanted, position)
      if (bytesRead === 0) break
      digest.update(buffer.subarray(0, bytesRead))
      let written = 0
      while (written < bytesRead) {
        const result = await destinationHandle.write(buffer, written, bytesRead - written, position + written)
        if (result.bytesWritten < 1) fail('REVERSE_STAGE_FAILED', 'staged artifact write made no progress')
        written += result.bytesWritten
      }
      position += bytesRead
    }
    await destinationHandle.sync()
    const heldAfter = await sourceHandle.stat({ bigint: true })
    const endpointAfter = await checkedExistingPath(endpoint.path, 'artifact', { maximumBytes: MAX_ARTIFACT_BYTES })
    const observed = digest.digest('hex')
    if (
      position !== expected.size
      || observed !== expected.sha256
      || !sameFile(heldBefore, heldAfter)
      || !sameFile(heldBefore, endpointAfter.metadata)
    ) fail('REVERSE_ARTIFACT_CHANGED', 'artifact changed while it was staged')
  } finally {
    await destinationHandle?.close()
    await sourceHandle?.close()
  }
}

async function assertOwnedWorkIdentity(outputDirectory, workDirectory, identity, workName = '.work') {
  const expected = resolve(outputDirectory, workName)
  if (!equalPath(expected, workDirectory) || !inside(outputDirectory, workDirectory)) {
    fail('REVERSE_CLEANUP_REFUSED', 'controller refused to clean an unowned working directory')
  }
  let canonical
  let metadata
  try {
    canonical = await realpath(workDirectory)
    metadata = await lstat(workDirectory, { bigint: true })
  } catch (error) {
    fail('REVERSE_WORK_IDENTITY_CHANGED', 'controller working directory is absent or unreadable', error)
  }
  if (
    !equalPath(canonical, expected)
    || metadata.isSymbolicLink()
    || !metadata.isDirectory()
    || (identity !== undefined && !sameDirectoryIdentity(metadata, identity))
  ) {
    fail('REVERSE_WORK_IDENTITY_CHANGED', 'controller working directory identity changed')
  }
  return metadata
}

async function cleanupOwnedWork(outputDirectory, workDirectory, identity, workName = '.work') {
  try {
    await assertOwnedWorkIdentity(outputDirectory, workDirectory, identity, workName)
    await rm(workDirectory, { recursive: true, force: false })
    try {
      await lstat(workDirectory)
    } catch (error) {
      if (error?.code === 'ENOENT') return true
      throw error
    }
    return false
  } catch {
    return false
  }
}

async function inspectGhidraLogs(paths, maximumBytes) {
  let total = 0n
  for (const path of paths) {
    let metadata
    try {
      metadata = await lstat(path, { bigint: true })
    } catch (error) {
      if (error?.code === 'ENOENT') continue
      return { integrityFailed: true, limitExceeded: false }
    }
    if (!regularSingleLink(metadata)) return { integrityFailed: true, limitExceeded: false }
    total += metadata.size
    if (total > BigInt(maximumBytes)) return { integrityFailed: false, limitExceeded: true }
  }
  return { integrityFailed: false, limitExceeded: false }
}

function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function exact(value, fields) {
  if (!plain(value)) return false
  const actual = Object.keys(value).sort()
  const expected = [...fields].sort()
  return actual.length === expected.length && actual.every((item, index) => item === expected[index])
}

function boundedObservationText(value) {
  return typeof value === 'string' && value.length >= 1 && value.length <= 512 && !CONTROL.test(value)
}

const GHIDRA_OFFSET = /^0x(?:0|[1-9a-f][0-9a-f]*)$/u
const GHIDRA_QUERY_NAME = /^[A-Za-z][A-Za-z0-9._~-]{0,63}$/u
const GHIDRA_NETWORK_APIS = new Set([
  'POSIX_CONNECT', 'POSIX_GETADDRINFO', 'POSIX_RECV', 'POSIX_SEND', 'POSIX_SOCKET',
  'LIBCURL_EASY_GETINFO', 'LIBCURL_EASY_INIT', 'LIBCURL_EASY_PERFORM',
  'LIBCURL_EASY_SETOPT', 'LIBCURL_HEADER_APPEND', 'OPENSSL_CONNECT', 'OPENSSL_READ',
  'OPENSSL_SET_SERVER_NAME', 'OPENSSL_VERIFY_RESULT', 'OPENSSL_WRITE',
  'WINHTTP_CONNECT', 'WINHTTP_OPEN', 'WINHTTP_OPEN_REQUEST', 'WINHTTP_QUERY_HEADERS',
  'WINHTTP_RECEIVE_RESPONSE', 'WINHTTP_SEND_REQUEST', 'WINHTTP_SET_CREDENTIALS',
  'WINHTTP_SET_OPTION', 'WININET_CONNECT', 'WININET_GET_COOKIE', 'WININET_OPEN',
  'WININET_OPEN_REQUEST', 'WININET_QUERY_INFO', 'WININET_READ', 'WININET_SEND_REQUEST',
  'WININET_SET_COOKIE', 'WINDOWS_CREDENTIAL_READ',
  'WINDOWS_SSPI_ACQUIRE_CREDENTIALS', 'WINDOWS_SSPI_INITIALIZE_CONTEXT',
])
const GHIDRA_AUTH_HINTS = new Set([
  'API_KEY_IDENTIFIER', 'AUTHORIZATION_HEADER_NAME', 'BASIC_SCHEME', 'BEARER_SCHEME',
  'COOKIE_HEADER_NAME', 'CSRF_IDENTIFIER', 'OAUTH_ACCESS_TOKEN_PARAMETER',
  'OAUTH_CLIENT_CREDENTIALS', 'OAUTH_FLOW', 'OAUTH_PKCE',
  'OAUTH_REFRESH_TOKEN_PARAMETER', 'OPENID_CONNECT', 'PASSWORD_FIELD_IDENTIFIER',
  'SAML_FLOW', 'SESSION_IDENTIFIER', 'SET_COOKIE_HEADER_NAME',
  'URL_USERINFO_CREDENTIALS', 'USERNAME_FIELD_IDENTIFIER',
  'WWW_AUTHENTICATE_HEADER_NAME',
])
const GHIDRA_STRUCTURAL_SEGMENTS = new Set(GHIDRA_GENERIC_PATH_SEGMENTS)

function nonNegativeInteger(value, maximum = Number.MAX_SAFE_INTEGER) {
  return Number.isSafeInteger(value) && value >= 0 && value <= maximum
}

function uniqueStrings(values, predicate, maximum) {
  return Array.isArray(values)
    && values.length <= maximum
    && new Set(values).size === values.length
    && values.every(predicate)
}

function canonicalGhidraPath(value) {
  if (typeof value !== 'string' || !value.startsWith('/') || value.length > 512 || CONTROL.test(value)) return false
  const segments = value.split('/')
  if (segments.length > 34) return false
  return segments.every((segment, index) => {
    if (index === 0 || segment === '') return true
    if (segment === '{...}') return index === segments.length - 1
    if (['{hex}', '{integer}', '{segment}', '{uuid}', '{value}'].includes(segment)) return true
    return /^v[0-9]+$/iu.test(segment) || GHIDRA_STRUCTURAL_SEGMENTS.has(segment.toLowerCase())
  })
}

function canonicalGhidraOrigin(item) {
  if (!['http', 'https'].includes(item.scheme) || !boundedObservationText(item.origin) || !boundedObservationText(item.host)) return false
  let parsed
  try { parsed = new URL(item.origin) } catch { return false }
  const normalizedHost = parsed.hostname.replace(/^\[|\]$/gu, '').toLowerCase()
  const effectivePort = parsed.port === '' ? (item.scheme === 'https' ? 443 : 80) : Number(parsed.port)
  return parsed.protocol === `${item.scheme}:`
    && parsed.origin === item.origin
    && parsed.pathname === '/'
    && !parsed.username
    && !parsed.password
    && normalizedHost === item.host.toLowerCase()
    && effectivePort === item.port
}

function ghidraObservations(value, artifactHash) {
  if (!exact(value, ['analysis_status', 'auth_hints', 'coverage', 'endpoint_observations', 'functions', 'kind', 'network_imports', 'profile_id', 'program', 'protocol_coverage', 'schema_version', 'target_execution'])) {
    fail('GHIDRA_EXPORT_INVALID', 'Ghidra fixed exporter returned an invalid document')
  }
  const protocolFields = [
    'auth_hint_candidates', 'auth_hint_limit', 'auth_hints_truncated',
    'emitted_auth_hints', 'emitted_endpoints', 'emitted_network_imports',
    'endpoint_candidates', 'endpoint_limit', 'endpoints_truncated',
    'external_function_scan_truncated', 'external_functions_scanned',
    'matching_network_imports', 'network_import_limit', 'network_imports_truncated',
    'references_per_import_limit', 'string_record_limit', 'string_records_scanned',
    'string_scan_truncated', 'string_values_scanned', 'truncated_string_values',
  ]
  if (
    value.schema_version !== '1.0.0'
    || value.kind !== 'red-team-audit/ghidra-static-export'
    || value.profile_id !== GHIDRA_REVERSE_PROFILE
    || value.analysis_status !== 'OBSERVATIONS_ONLY'
    || value.target_execution !== 'NOT_PERFORMED'
    || !exact(value.program, ['compiler_spec_id', 'executable_format', 'executable_sha256', 'image_base', 'language_id', 'maximum_address', 'minimum_address'])
    || !exact(value.coverage, ['available_functions', 'emitted_functions', 'function_limit', 'truncated'])
    || !exact(value.protocol_coverage, protocolFields)
    || !Array.isArray(value.functions)
    || value.functions.length > 20_000
    || !Array.isArray(value.network_imports)
    || value.network_imports.length > 512
    || !Array.isArray(value.endpoint_observations)
    || value.endpoint_observations.length > 512
    || !Array.isArray(value.auth_hints)
    || value.auth_hints.length > 512
  ) fail('GHIDRA_EXPORT_INVALID', 'Ghidra fixed exporter returned an invalid document')
  const programStrings = Object.values(value.program)
  if (
    programStrings.some((item) => !boundedObservationText(item))
    || !/^[a-f0-9]{64}$/u.test(value.program.executable_sha256)
    || value.program.executable_sha256 !== artifactHash
    || value.coverage.function_limit !== 20_000
    || !Number.isSafeInteger(value.coverage.available_functions)
    || !Number.isSafeInteger(value.coverage.emitted_functions)
    || value.coverage.available_functions < 0
    || value.coverage.emitted_functions < 0
    || value.coverage.emitted_functions !== value.functions.length
    || value.coverage.available_functions < value.coverage.emitted_functions
    || typeof value.coverage.truncated !== 'boolean'
  ) fail('GHIDRA_EXPORT_INVALID', 'Ghidra fixed exporter output does not match the staged artifact or declared coverage')
  for (const item of value.functions) {
    if (
      !exact(item, ['body_address_count', 'entry_point', 'external', 'name', 'thunk'])
      || !boundedObservationText(item.entry_point)
      || !boundedObservationText(item.name)
      || typeof item.external !== 'boolean'
      || typeof item.thunk !== 'boolean'
      || !Number.isSafeInteger(item.body_address_count)
      || item.body_address_count < 0
    ) fail('GHIDRA_EXPORT_INVALID', 'Ghidra fixed exporter returned an invalid function observation')
  }
  for (const item of value.network_imports) {
    if (
      !exact(item, ['api', 'callsite_offsets', 'references', 'references_scanned', 'references_truncated'])
      || !GHIDRA_NETWORK_APIS.has(item.api)
      || !uniqueStrings(item.callsite_offsets, (offset) => GHIDRA_OFFSET.test(offset), 128)
      || !Array.isArray(item.references)
      || item.references.length > 128
      || !nonNegativeInteger(item.references_scanned, 4_096)
      || typeof item.references_truncated !== 'boolean'
    ) fail('GHIDRA_EXPORT_INVALID', 'Ghidra fixed exporter returned an invalid network-import observation')
    const referenceKeys = new Set()
    for (const reference of item.references) {
      if (
        !exact(reference, ['from_offset', 'kind'])
        || !GHIDRA_OFFSET.test(reference.from_offset ?? '')
        || !['CALL', 'DATA', 'OTHER'].includes(reference.kind)
        || referenceKeys.has(`${reference.kind}:${reference.from_offset}`)
      ) fail('GHIDRA_EXPORT_INVALID', 'Ghidra fixed exporter returned an invalid network reference')
      referenceKeys.add(`${reference.kind}:${reference.from_offset}`)
    }
    const callsites = item.references.filter(({ kind }) => kind === 'CALL').map(({ from_offset: offset }) => offset)
    if (JSON.stringify(callsites) !== JSON.stringify(item.callsite_offsets) || item.references.length > item.references_scanned) {
      fail('GHIDRA_EXPORT_INVALID', 'Ghidra call-site metadata does not match its bounded references')
    }
  }
  for (const item of value.endpoint_observations) {
    if (
      !exact(item, ['candidate_truncated', 'host', 'origin', 'path_template', 'path_truncated', 'path_values_redacted', 'port', 'query_names', 'query_names_truncated', 'scheme', 'source_offsets', 'userinfo_present'])
      || !canonicalGhidraOrigin(item)
      || !canonicalGhidraPath(item.path_template)
      || !uniqueStrings(item.query_names, (name) => GHIDRA_QUERY_NAME.test(name), 32)
      || !uniqueStrings(item.source_offsets, (offset) => GHIDRA_OFFSET.test(offset), 16)
      || !['candidate_truncated', 'path_truncated', 'path_values_redacted', 'query_names_truncated', 'userinfo_present'].every((field) => typeof item[field] === 'boolean')
    ) fail('GHIDRA_EXPORT_INVALID', 'Ghidra fixed exporter returned an invalid endpoint observation')
  }
  for (const item of value.auth_hints) {
    if (
      !exact(item, ['hint', 'source_offset'])
      || !GHIDRA_AUTH_HINTS.has(item.hint)
      || !(item.source_offset === 'UNMAPPED' || GHIDRA_OFFSET.test(item.source_offset ?? ''))
    ) fail('GHIDRA_EXPORT_INVALID', 'Ghidra fixed exporter returned an invalid authentication hint')
  }
  const coverage = value.protocol_coverage
  const countFields = [
    'auth_hint_candidates', 'emitted_auth_hints', 'emitted_endpoints',
    'emitted_network_imports', 'endpoint_candidates', 'external_functions_scanned',
    'matching_network_imports', 'string_records_scanned', 'string_values_scanned',
    'truncated_string_values',
  ]
  if (
    coverage.network_import_limit !== 512
    || coverage.references_per_import_limit !== 128
    || coverage.string_record_limit !== 100_000
    || coverage.endpoint_limit !== 512
    || coverage.auth_hint_limit !== 512
    || countFields.some((field) => !nonNegativeInteger(coverage[field], 2_000_000))
    || !nonNegativeInteger(coverage.external_functions_scanned, 100_000)
    || !nonNegativeInteger(coverage.string_records_scanned, 100_000)
    || !nonNegativeInteger(coverage.string_values_scanned, 100_000)
    || !nonNegativeInteger(coverage.truncated_string_values, 100_000)
    || !nonNegativeInteger(coverage.emitted_network_imports, 512)
    || !nonNegativeInteger(coverage.emitted_endpoints, 512)
    || !nonNegativeInteger(coverage.emitted_auth_hints, 512)
    || !['auth_hints_truncated', 'endpoints_truncated', 'external_function_scan_truncated', 'network_imports_truncated', 'string_scan_truncated'].every((field) => typeof coverage[field] === 'boolean')
    || coverage.emitted_network_imports !== value.network_imports.length
    || coverage.emitted_endpoints !== value.endpoint_observations.length
    || coverage.emitted_auth_hints !== value.auth_hints.length
    || coverage.matching_network_imports < coverage.emitted_network_imports
    || coverage.string_values_scanned > coverage.string_records_scanned
    || coverage.truncated_string_values > coverage.string_values_scanned
    || (coverage.external_function_scan_truncated && !coverage.network_imports_truncated)
    || (coverage.matching_network_imports > coverage.emitted_network_imports && !coverage.network_imports_truncated)
    || ((coverage.string_scan_truncated || coverage.truncated_string_values > 0) && (!coverage.endpoints_truncated || !coverage.auth_hints_truncated))
  ) fail('GHIDRA_EXPORT_INVALID', 'Ghidra protocol coverage does not match its observations')
  const summary = {
    type: 'program-summary',
    ...value.program,
    available_functions: value.coverage.available_functions,
    emitted_functions: value.coverage.emitted_functions,
    truncated: value.coverage.truncated,
  }
  const protocolSummary = { type: 'protocol-summary', ...coverage }
  const networkImports = value.network_imports.map((item) => ({ type: 'network-import', ...item }))
  const endpoints = value.endpoint_observations.map((item) => ({ type: 'static-endpoint', ...item }))
  const authHints = value.auth_hints.map((item) => ({ type: 'auth-hint', ...item }))
  const fixedObservations = [summary, protocolSummary, ...networkImports, ...endpoints, ...authHints]
  const room = MAX_OBSERVATIONS - fixedObservations.length
  if (room < 0) fail('GHIDRA_EXPORT_INVALID', 'Ghidra protocol observations exceed the evidence limit')
  const functions = value.functions.slice(0, room).map((item) => ({ type: 'function', ...item }))
  return {
    observations: [...fixedObservations, ...functions],
    truncated: value.coverage.truncated
      || value.functions.length > room
      || coverage.network_imports_truncated
      || coverage.string_scan_truncated
      || coverage.endpoints_truncated
      || coverage.auth_hints_truncated,
  }
}

function fridaObservations(result, { frameNonce, moduleName, symbolName }) {
  if (!exact(result, [
    'complete', 'events', 'ignored_lines', 'observation_window_ms', 'process_exit_code',
    'profile_id', 'ready', 'stderr_bytes', 'trace_events', 'truncated',
  ]) || result.profile_id !== FRIDA_REVERSE_PROFILE || result.ready !== true || result.complete !== true) {
    fail('FRIDA_OUTPUT_INVALID', 'Frida fixed runner returned an invalid result')
  }
  if (
    !Number.isSafeInteger(result.trace_events)
    || result.trace_events < 0
    || result.trace_events > FRIDA_MAX_EVENTS
    || typeof result.truncated !== 'boolean'
    || !Number.isSafeInteger(result.ignored_lines)
    || result.ignored_lines < 0
    || !Number.isSafeInteger(result.stderr_bytes)
    || result.stderr_bytes < 0
    || result.stderr_bytes > MAX_OUTPUT_BYTES
    || result.process_exit_code !== 0
    || !exact(result.observation_window_ms, ['end', 'start'])
    || !Number.isSafeInteger(result.observation_window_ms.start)
    || !Number.isSafeInteger(result.observation_window_ms.end)
    || result.observation_window_ms.start < 0
    || result.observation_window_ms.end < result.observation_window_ms.start
    || !Array.isArray(result.events)
    || result.events.length !== result.trace_events + 2
  ) fail('FRIDA_OUTPUT_INVALID', 'Frida fixed runner result metadata is inconsistent')
  const ready = result.events[0]
  const complete = result.events.at(-1)
  if (
    ready?.event !== 'ready'
    || ready.frame_nonce !== frameNonce
    || ready.module_name !== moduleName
    || ready.symbol_name !== symbolName
    || ready.observed_at_ms !== result.observation_window_ms.start
    || complete?.event !== 'complete'
    || complete.frame_nonce !== frameNonce
    || complete.observed_at_ms !== result.observation_window_ms.end
    || complete.events_emitted !== result.trace_events
    || complete.truncated !== result.truncated
    || result.events.some((event) => event?.frame_nonce !== frameNonce)
  ) fail('FRIDA_OUTPUT_INVALID', 'Frida fixed runner frames do not match the requested trace')
  return result.events
}

function fridaV2Observations(result, { plan, artifactSha256, frameNonce, maxOutputBytes }) {
  if (!exact(result, [
    'capture_attempts', 'capture_failures', 'capture_truncations',
    'captured_payload_bytes', 'complete',
    'events', 'hooks_ready', 'ignored_lines', 'observation_window_ms',
    'process_exit_code', 'profile_id', 'session_ready', 'stderr_bytes',
    'termination_confirmed', 'trace_events', 'truncated',
  ]) || result.profile_id !== FRIDA_V2_PROFILE_ID
    || result.session_ready !== true
    || result.complete !== true
    || result.termination_confirmed !== true
    || result.process_exit_code !== 0
    || !Number.isSafeInteger(result.ignored_lines) || result.ignored_lines < 0
    || !Number.isSafeInteger(result.stderr_bytes) || result.stderr_bytes < 0
    || result.stderr_bytes > maxOutputBytes
    || !Array.isArray(result.events)) {
    fail('FRIDA_OUTPUT_INVALID', 'Frida typed runner returned an invalid result')
  }
  const framed = result.events.map((event) => (
    `[last-aperture:frida] ${JSON.stringify(event)}`
  )).join('\n')
  const verified = parseFridaTracePlanOutput(framed, {
    plan,
    artifactSha256,
    expectedFrameNonce: frameNonce,
    maxBytes: maxOutputBytes,
  })
  if (verified.hooks_ready !== result.hooks_ready
    || verified.trace_events !== result.trace_events
    || verified.capture_attempts !== result.capture_attempts
    || verified.capture_failures !== result.capture_failures
    || verified.capture_truncations !== result.capture_truncations
    || verified.captured_payload_bytes !== result.captured_payload_bytes
    || verified.truncated !== result.truncated
    || stableJson(verified.observation_window_ms, 0) !== stableJson(result.observation_window_ms, 0)
    || stableJson(verified.events, 0) !== stableJson(result.events, 0)) {
    fail('FRIDA_OUTPUT_INVALID', 'Frida typed runner metadata does not match its verified frames')
  }
  return result.events
}

function fixedGap(code, message) {
  return { code, message }
}

function reverseIntent({
  runId,
  engine,
  profileId,
  artifact,
  invocationSha256,
  startedAt,
  limits,
  targetExecution,
}) {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/reverse-intent',
    run_id: runId,
    engine,
    profile_id: profileId,
    started_at: startedAt,
    artifact,
    tool_invocation_sha256: invocationSha256,
    limits,
    target_execution: targetExecution ?? (engine === 'ghidra' ? 'NOT_PERFORMED' : 'LOCAL_LAB_SPAWN'),
    applied_to_audit_bundle: false,
  }
}

function resultSummary(outputPath, evidence) {
  return {
    status: evidence.status,
    output_path: outputPath,
    evidence_path: join(outputPath, 'evidence.json'),
    run_id: evidence.run_id,
    engine: evidence.engine,
    observations: evidence.observations.length,
  }
}

export async function importHarFile({ harPath, targetOrigins, pathLiterals = [], outPath } = {}) {
  if (!Array.isArray(targetOrigins) || targetOrigins.length < 1 || targetOrigins.length > 32) {
    fail('REVERSE_ORIGINS_INVALID', 'web HAR import requires one to 32 target origins')
  }
  const inputPath = localAbsolutePath(harPath, 'HAR input')
  const outputPath = await assertOutputAbsent(outPath, 'web evidence output')
  if (equalPath(inputPath, outputPath)) fail('REVERSE_OUTPUT_INVALID', 'web evidence output must differ from the HAR input')
  const bytes = await readStableFile(inputPath, MAX_JSON_INPUT_BYTES)
  const evidence = importWebHarEvidence(decodeJson(bytes, 'HAR input'), {
    sourceSha256: sha256(bytes),
    targetOrigins,
    pathLiterals,
  })
  await exclusiveWrite(outputPath, canonicalWebSessionEvidence(evidence))
  return {
    status: 'SUCCEEDED',
    output_path: outputPath,
    digest: digestWebSessionEvidence(evidence),
    entries: evidence.entries.length,
    skipped: evidence.skipped,
  }
}

export async function importBurpFile({ burpPath, targetOrigins, pathLiterals = [], outPath } = {}) {
  if (!Array.isArray(targetOrigins) || targetOrigins.length < 1 || targetOrigins.length > 32) {
    fail('REVERSE_ORIGINS_INVALID', 'web Burp XML import requires one to 32 target origins')
  }
  const inputPath = localAbsolutePath(burpPath, 'Burp XML input')
  const outputPath = await assertOutputAbsent(outPath, 'web evidence output')
  if (equalPath(inputPath, outputPath)) fail('REVERSE_OUTPUT_INVALID', 'web evidence output must differ from the Burp XML input')
  const bytes = await readStableFile(inputPath, MAX_JSON_INPUT_BYTES)
  const evidence = importBurpHttpItemsEvidence(bytes, {
    sourceSha256: sha256(bytes),
    targetOrigins,
    pathLiterals,
  })
  await exclusiveWrite(outputPath, canonicalWebSessionEvidence(evidence))
  return {
    status: 'SUCCEEDED',
    output_path: outputPath,
    digest: digestWebSessionEvidence(evidence),
    entries: evidence.entries.length,
    skipped: evidence.skipped,
  }
}

function distinctAbsolutePaths(values, label, minimum, maximum) {
  if (!Array.isArray(values) || values.length < minimum || values.length > maximum) {
    fail('REVERSE_EVIDENCE_INPUT_INVALID', `${label} requires ${minimum} through ${maximum} files`)
  }
  const result = values.map((value) => localAbsolutePath(value, label))
  if (new Set(result.map(pathKey)).size !== result.length) {
    fail('REVERSE_EVIDENCE_INPUT_INVALID', `${label} contains a duplicate file`)
  }
  return result
}

async function readProtocolEvidence(webPaths, reversePaths) {
  const inputs = [
    ...webPaths.map((path) => ({ path, label: 'web evidence input', kind: 'web' })),
    ...reversePaths.map((path) => ({ path, label: 'reverse evidence input', kind: 'reverse' })),
  ]
  let declaredBytes = 0n
  for (const input of inputs) {
    const endpoint = await checkedExistingPath(input.path, 'input', {
      maximumBytes: MAX_JSON_INPUT_BYTES,
    })
    declaredBytes += endpoint.metadata.size
    if (declaredBytes > BigInt(MAX_PROTOCOL_INPUT_BYTES)) {
      fail(
        'REVERSE_EVIDENCE_INPUT_SIZE_INVALID',
        'combined protocol evidence inputs exceed the 128 MiB cumulative byte limit',
      )
    }
  }

  const webSessionEvidence = []
  const reverseEvidence = []
  let observedBytes = 0
  for (const input of inputs) {
    const bytes = await readStableFile(input.path, MAX_JSON_INPUT_BYTES)
    observedBytes += bytes.length
    if (observedBytes > MAX_PROTOCOL_INPUT_BYTES) {
      fail(
        'REVERSE_EVIDENCE_INPUT_SIZE_INVALID',
        'combined protocol evidence inputs exceed the 128 MiB cumulative byte limit',
      )
    }
    const document = decodeJson(bytes, input.label)
    if (input.kind === 'web') webSessionEvidence.push(document)
    else reverseEvidence.push(document)
  }
  return { webSessionEvidence, reverseEvidence }
}

export async function buildProtocolContractFile({
  webEvidencePaths,
  reverseEvidencePaths = [],
  outPath,
  generatedAt,
} = {}) {
  const webPaths = distinctAbsolutePaths(webEvidencePaths, 'web evidence input', 1, 32)
  const reversePaths = distinctAbsolutePaths(reverseEvidencePaths, 'reverse evidence input', 0, 64)
  const outputPath = await assertOutputAbsent(outPath, 'protocol contract output')
  if ([...webPaths, ...reversePaths].some((path) => equalPath(path, outputPath))) {
    fail('REVERSE_OUTPUT_INVALID', 'protocol contract output must differ from every evidence input')
  }
  const { webSessionEvidence, reverseEvidence } = await readProtocolEvidence(webPaths, reversePaths)
  const contract = buildNativeInteractionContract({
    webSessionEvidence,
    reverseEvidence,
    ...(generatedAt === undefined ? {} : { generatedAt }),
  })
  await exclusiveWrite(outputPath, canonicalNativeInteractionContract(contract))
  return {
    status: 'SUCCEEDED',
    output_path: outputPath,
    digest: digestNativeInteractionContract(contract),
    endpoints: contract.endpoints.length,
    auth_flows: contract.auth_flows.length,
    generated_client_status: contract.generated_client_status,
  }
}

export async function analyzeGhidraArtifact({
  labRoot: labRootValue,
  binary,
  artifactKind,
  ghidraPath: ghidraPathValue,
  outPath,
  now = () => new Date(),
  runGhidra = runGhidraHeadless,
} = {}) {
  if (!ARTIFACT_KINDS.has(artifactKind)) fail('REVERSE_ARTIFACT_KIND_INVALID', 'artifact kind is unsupported')
  if (typeof runGhidra !== 'function') fail('REVERSE_RUNNER_INVALID', 'Ghidra runner must be a function')
  const artifact = await resolveArtifact(labRootValue, binary)
  const ghidraPath = await verifyTool(ghidraPathValue, 'Ghidra launcher')
  assertSupportedGhidraLauncher(ghidraPath)
  const usesWindowsCompatibilityAgent = process.platform === 'win32'
    && isWindowsBatchLauncher(ghidraPath)
  const scriptDirectory = await checkedDirectory(dirname(GHIDRA_EXPORTER_PATH))
  await checkedExistingPath(GHIDRA_EXPORTER_PATH, 'tool', { maximumBytes: 1024 * 1024 })
  if (usesWindowsCompatibilityAgent) {
    await checkedExistingPath(GHIDRA_WINDOWS_AGENT_SOURCE_PATH, 'tool', { maximumBytes: 256 * 1024 })
    await checkedExistingPath(GHIDRA_WINDOWS_AGENT_MANIFEST_PATH, 'tool', { maximumBytes: 16 * 1024 })
  }
  const outputPath = await outputDirectoryCandidate(outPath, artifact.labRoot)
  const before = await hashStableFile(artifact.path)
  const launcherHash = await hashStableFile(ghidraPath)
  const exporterHash = await hashStableFile(GHIDRA_EXPORTER_PATH, 1024 * 1024)
  const agentSourceHash = usesWindowsCompatibilityAgent
    ? await hashStableFile(GHIDRA_WINDOWS_AGENT_SOURCE_PATH, 256 * 1024)
    : undefined
  const agentManifestHash = usesWindowsCompatibilityAgent
    ? await hashStableFile(GHIDRA_WINDOWS_AGENT_MANIFEST_PATH, 16 * 1024)
    : undefined
  const fixedToolFiles = [
    { path: ghidraPath, maximumBytes: MAX_ARTIFACT_BYTES, expected: launcherHash },
    { path: GHIDRA_EXPORTER_PATH, maximumBytes: 1024 * 1024, expected: exporterHash },
    ...(usesWindowsCompatibilityAgent ? [
      { path: GHIDRA_WINDOWS_AGENT_SOURCE_PATH, maximumBytes: 256 * 1024, expected: agentSourceHash },
      { path: GHIDRA_WINDOWS_AGENT_MANIFEST_PATH, maximumBytes: 16 * 1024, expected: agentManifestHash },
    ] : []),
  ]
  const baseToolComponents = [
    toolComponent('ghidra-launcher', 'Ghidra headless launcher', launcherHash),
    toolComponent('fixed-exporter', 'LastApertureExport.java', exporterHash),
    ...(usesWindowsCompatibilityAgent ? [
      toolComponent('windows-agent-source', 'GhidraBundleLocationAgent.java.source', agentSourceHash),
      toolComponent('windows-agent-manifest', 'GhidraBundleLocationAgent.mf', agentManifestHash),
    ] : []),
  ]
  const runId = newRunId()
  const startedAt = canonicalTimestamp(now())
  // Ghidra rejects a project path when any path component begins with '.'.
  const workPath = join(outputPath, 'work')
  const projectPath = join(workPath, 'project')
  const stagedPath = join(workPath, `target${extname(artifact.path)}`)
  const exportPath = join(workPath, 'ghidra-export.json')
  const logPath = join(workPath, 'ghidra.log')
  const scriptLogPath = join(workPath, 'ghidra-script.log')
  const args = buildGhidraArguments({
    projectDirectory: projectPath,
    projectName: `last-aperture-${runId.slice('reverse:'.length)}`,
    stagedBinary: stagedPath,
    scriptDirectory,
    exportPath,
    logPath,
    scriptLogPath,
    timeoutSeconds: GHIDRA_ANALYSIS_SECONDS,
    maxCpu: 1,
  })
  const limits = {
    timeout_ms: GHIDRA_TIMEOUT_MS,
    max_output_bytes: MAX_OUTPUT_BYTES,
    max_observations: MAX_OBSERVATIONS,
  }
  let workIdentity
  let invocationSha256
  let toolComponents = mergeToolComponents(baseToolComponents)
  let windowsCompatibilityAgent
  let runnerTimeoutMs = GHIDRA_TIMEOUT_MS
  let runnerOutputBytes = MAX_OUTPUT_BYTES
  const preparationDeadline = Date.now() + GHIDRA_TIMEOUT_MS
  await initializeOutputDirectory(outputPath, async () => {
    await mkdir(workPath, { recursive: false, mode: 0o700 })
    await mkdir(projectPath, { recursive: false, mode: 0o700 })
    workIdentity = await assertOwnedWorkIdentity(outputPath, workPath, undefined, 'work')
    if (usesWindowsCompatibilityAgent && runGhidra === runGhidraHeadless) {
      windowsCompatibilityAgent = await prepareWindowsGhidraCompatibilityAgent({
        cwd: workPath,
        deadline: preparationDeadline,
        outputBudget: MAX_OUTPUT_BYTES,
      })
      runnerTimeoutMs = preparationDeadline - Date.now()
      runnerOutputBytes = windowsCompatibilityAgent.remainingOutput
      if (runnerTimeoutMs < 1 || runnerOutputBytes < 1) {
        fail('GHIDRA_LIMIT_EXHAUSTED', 'the fixed Ghidra preparation exhausted its limits before intent sealing')
      }
      fixedToolFiles.push(...windowsCompatibilityAgent.files.map((file) => ({
        path: file.path,
        maximumBytes: MAX_ARTIFACT_BYTES,
        expected: file.expected,
      })))
      toolComponents = mergeToolComponents(baseToolComponents, windowsCompatibilityAgent.provenance)
    }
    invocationSha256 = sha256(stableJson({
      profile_id: GHIDRA_REVERSE_PROFILE,
      args,
      components: toolComponents,
    }, 0))
    await exclusiveWrite(join(outputPath, 'intent.json'), stableJson(reverseIntent({
      runId,
      engine: 'ghidra',
      profileId: GHIDRA_REVERSE_PROFILE,
      artifact: { kind: artifactKind, path: artifact.relativePath, sha256: before.sha256, size_bytes: before.size },
      invocationSha256,
      startedAt,
      limits,
    })))
    workIdentity = await assertOwnedWorkIdentity(outputPath, workPath, workIdentity, 'work')
  })

  let status = 'FAILED'
  let observations = []
  const gaps = [
    fixedGap('STATIC_ANALYSIS_ONLY', 'Ghidra observations describe the staged artifact without executing it or proving application behavior.'),
    fixedGap(
      'TOOL_VERSION_UNRECORDED',
      usesWindowsCompatibilityAgent
        ? 'The launcher, exporter, and active compatibility-agent toolchain bytes are digest-bound, but this profile does not execute a separate version probe; tool.version remains null.'
        : 'The launcher and exporter bytes are digest-bound, but this profile does not execute a separate version probe; tool.version remains null.',
    ),
  ]
  let processResult
  let toolInvocationStarted = false
  try {
    await copyArtifact(artifact.path, stagedPath, before)
    await assertOwnedWorkIdentity(outputPath, workPath, workIdentity, 'work')
    await assertToolFilesUnchanged(fixedToolFiles)
    toolInvocationStarted = true
    let runnerError
    try {
      processResult = await runGhidra({
        launcherPath: ghidraPath,
        args,
        cwd: workPath,
        timeoutMs: runnerTimeoutMs,
        maxOutputBytes: runnerOutputBytes,
        ...(windowsCompatibilityAgent === undefined ? {} : { windowsCompatibilityAgent }),
      })
    } catch (error) {
      runnerError = error
    }
    await assertToolFilesUnchanged(fixedToolFiles)
    await assertOwnedWorkIdentity(outputPath, workPath, workIdentity, 'work')
    if (runnerError) throw runnerError
    if (windowsCompatibilityAgent !== undefined
      && stableJson(processResult?.tool_components ?? null, 0)
        !== stableJson(windowsCompatibilityAgent.provenance, 0)) {
      fail('REVERSE_TOOL_PROVENANCE_INVALID', 'the Ghidra runner did not return its sealed compatibility-agent provenance')
    }
    const logState = await inspectGhidraLogs([logPath, scriptLogPath], MAX_OUTPUT_BYTES)
    processResult = {
      ...processResult,
      log_limit_exceeded: processResult?.log_limit_exceeded === true || logState.limitExceeded,
      log_integrity_failed: processResult?.log_integrity_failed === true || logState.integrityFailed,
    }
    if (
      !plain(processResult)
      || processResult.code !== 0
      || processResult.spawn_error === true
      || processResult.timed_out === true
      || processResult.output_limit_exceeded === true
      || processResult.log_limit_exceeded === true
      || processResult.log_integrity_failed === true
      || processResult.termination_confirmed !== true
    ) {
      gaps.push(fixedGap('GHIDRA_PROCESS_FAILED', 'The fixed Ghidra process did not complete successfully; no static observations were accepted.'))
      if (processResult?.log_limit_exceeded === true) {
        gaps.push(fixedGap('GHIDRA_LOG_LIMIT_EXCEEDED', 'The combined Ghidra diagnostic logs exceeded their byte limit, so the process was terminated and no observations were accepted.'))
      }
      if (processResult?.log_integrity_failed === true) {
        gaps.push(fixedGap('GHIDRA_LOG_INTEGRITY_FAILED', 'A Ghidra diagnostic log was not a regular controller-owned file, so the process was terminated and no observations were accepted.'))
      }
      if (processResult?.termination_confirmed !== true) {
        gaps.push(fixedGap('GHIDRA_TERMINATION_UNCONFIRMED', 'Ghidra process termination was not confirmed, so controller scratch was preserved to avoid racing a live process.'))
      }
    } else {
      const parsed = ghidraObservations(await readJson(exportPath, 'Ghidra export', MAX_OUTPUT_BYTES), before.sha256)
      observations = parsed.observations
      status = parsed.truncated ? 'PARTIAL' : 'SUCCEEDED'
      if (parsed.truncated) gaps.push(fixedGap('GHIDRA_OBSERVATIONS_TRUNCATED', 'The fixed exporter or evidence contract observation limit truncated the function inventory.'))
    }
  } catch (error) {
    if (error?.code === 'REVERSE_TOOL_CHANGED') {
      gaps.push(fixedGap('TOOL_CHANGED', 'A digest-bound Ghidra launcher, exporter, build tool, or compatibility agent changed around execution, so all observations were discarded.'))
    } else if (error?.code === 'REVERSE_TOOL_RECHECK_FAILED') {
      gaps.push(fixedGap('TOOL_RECHECK_FAILED', 'A digest-bound Ghidra launcher, exporter, build tool, or compatibility agent could not be revalidated around execution, so all observations were discarded.'))
    } else if (error?.code === 'REVERSE_WORK_IDENTITY_CHANGED') {
      gaps.push(fixedGap('WORK_IDENTITY_CHANGED', 'The controller-owned Ghidra working directory was absent or replaced, so all observations were discarded and cleanup could not be verified.'))
    } else {
      gaps.push(fixedGap('GHIDRA_EXECUTION_FAILED', 'Ghidra execution or fixed export validation failed; no success is claimed.'))
    }
    status = 'FAILED'
    observations = []
  }

  if (
    toolInvocationStarted
    && processResult?.termination_confirmed !== true
    && !gaps.some(({ code }) => code === 'GHIDRA_TERMINATION_UNCONFIRMED')
  ) {
    gaps.push(fixedGap('GHIDRA_TERMINATION_UNCONFIRMED', 'Ghidra process termination was not confirmed, so controller scratch was preserved to avoid racing a live process.'))
  }

  let after
  try {
    after = await hashStableFile(artifact.path)
    if (after.sha256 !== before.sha256 || after.size !== before.size) {
      status = 'FAILED'
      observations = []
      gaps.push(fixedGap('TARGET_CHANGED', 'The source artifact changed during analysis, so its observations were discarded.'))
    }
  } catch {
    status = 'FAILED'
    observations = []
    gaps.push(fixedGap('TARGET_RECHECK_FAILED', 'The source artifact could not be revalidated after analysis.'))
  }
  const terminationSafe = !toolInvocationStarted || processResult?.termination_confirmed === true
  const cleanupVerified = terminationSafe
    ? await cleanupOwnedWork(outputPath, workPath, workIdentity, 'work')
    : false
  if (!cleanupVerified) {
    if (status === 'SUCCEEDED') status = 'PARTIAL'
    gaps.push(fixedGap('CLEANUP_UNVERIFIED', 'The controller could not verify removal of its staged artifact and Ghidra scratch project.'))
  }
  const evidence = {
    schema_version: '1.1.0',
    kind: 'red-team-audit/reverse-evidence',
    protocol: 'reverse-evidence-v1',
    run_id: runId,
    engine: 'ghidra',
    profile_id: GHIDRA_REVERSE_PROFILE,
    started_at: startedAt,
    finished_at: canonicalTimestamp(now()),
    artifact: { kind: artifactKind, path: artifact.relativePath, sha256: before.sha256, size_bytes: before.size },
    tool: {
      name: 'Ghidra',
      version: null,
      invocation_sha256: invocationSha256,
      components: toolComponents,
    },
    limits,
    status,
    target_execution: 'NOT_PERFORMED',
    security_verdict: 'NOT_ASSESSED',
    applied_to_audit_bundle: false,
    observations,
    gaps,
    cleanup: { attempted: terminationSafe, verified: cleanupVerified },
  }
  await exclusiveWrite(join(outputPath, 'evidence.json'), canonicalReverseEvidence(evidence))
  return resultSummary(outputPath, evidence)
}

export async function traceFridaArtifact({
  labRoot: labRootValue,
  binary,
  fridaPath: fridaPathValue,
  moduleName,
  symbolName,
  outPath,
  now = () => new Date(),
  runFrida = runFridaTrace,
} = {}) {
  if (typeof runFrida !== 'function') fail('REVERSE_RUNNER_INVALID', 'Frida runner must be a function')
  const artifact = await resolveArtifact(labRootValue, binary)
  const fridaPath = await verifyTool(fridaPathValue, 'Frida executable')
  await checkedExistingPath(FRIDA_AGENT_PATH, 'tool', { maximumBytes: 1024 * 1024 })
  const runId = newRunId()
  const startedAt = canonicalTimestamp(now())
  const before = await hashStableFile(artifact.path)
  const frameNonce = randomBytes(32).toString('hex')
  const args = buildFridaArguments({
    binaryPath: artifact.path,
    agentPath: FRIDA_AGENT_PATH,
    moduleName,
    symbolName,
    durationSeconds: FRIDA_DURATION_SECONDS,
    maxEvents: FRIDA_MAX_EVENTS,
    frameNonce,
  })
  const executableHash = await hashStableFile(fridaPath)
  const agentHash = await hashStableFile(FRIDA_AGENT_PATH, 1024 * 1024)
  const fixedToolFiles = [
    { path: fridaPath, maximumBytes: MAX_ARTIFACT_BYTES, expected: executableHash },
    { path: FRIDA_AGENT_PATH, maximumBytes: 1024 * 1024, expected: agentHash },
  ]
  const invocationSha256 = sha256(stableJson({
    profile_id: FRIDA_REVERSE_PROFILE,
    args,
    executable_sha256: executableHash.sha256,
    agent_sha256: agentHash.sha256,
  }, 0))
  const limits = {
    timeout_ms: FRIDA_TIMEOUT_MS,
    max_output_bytes: MAX_OUTPUT_BYTES,
    max_observations: FRIDA_MAX_EVENTS + 2,
  }
  const outputPath = await outputDirectoryCandidate(outPath, artifact.labRoot)
  await initializeOutputDirectory(outputPath, async () => {
    await exclusiveWrite(join(outputPath, 'intent.json'), stableJson(reverseIntent({
      runId,
      engine: 'frida',
      profileId: FRIDA_REVERSE_PROFILE,
      artifact: { kind: 'native-executable', path: artifact.relativePath, sha256: before.sha256, size_bytes: before.size },
      invocationSha256,
      startedAt,
      limits,
    })))
  })

  let status = 'FAILED'
  let observations = []
  let cleanupVerified = false
  let toolInvocationStarted = false
  const gaps = [
    fixedGap('LOCAL_LAB_SPAWN_ONLY', 'Frida spawned only the exact executable beneath the local lab root with the bundled fixed agent.'),
    fixedGap('CALL_METADATA_ONLY', 'The fixed Frida profile records call timing and thread metadata without reading arguments, return values, or process memory.'),
    fixedGap('TOOL_VERSION_UNRECORDED', 'The Frida executable and agent bytes are digest-bound, but this profile does not execute a separate version probe; tool.version remains null.'),
  ]
  try {
    await assertToolFilesUnchanged(fixedToolFiles)
    toolInvocationStarted = true
    let result
    let runnerError
    try {
      result = await runFrida({
        fridaPath,
        args,
        cwd: artifact.labRoot,
        timeoutMs: FRIDA_TIMEOUT_MS,
        maxOutputBytes: MAX_OUTPUT_BYTES,
      })
    } catch (error) {
      runnerError = error
    }
    await assertToolFilesUnchanged(fixedToolFiles)
    if (runnerError) throw runnerError
    observations = fridaObservations(result, { frameNonce, moduleName, symbolName })
    cleanupVerified = true
    status = result.truncated === true ? 'PARTIAL' : 'SUCCEEDED'
    if (result.truncated === true) gaps.push(fixedGap('FRIDA_OBSERVATIONS_TRUNCATED', 'The fixed Frida event limit truncated the runtime trace.'))
  } catch (error) {
    if (error?.code === 'REVERSE_TOOL_CHANGED') {
      gaps.push(fixedGap('TOOL_CHANGED', 'The Frida executable or bundled agent changed around execution, so all observations were discarded.'))
    } else if (error?.code === 'REVERSE_TOOL_RECHECK_FAILED') {
      gaps.push(fixedGap('TOOL_RECHECK_FAILED', 'The Frida executable or bundled agent could not be revalidated around execution, so all observations were discarded.'))
    } else if (error?.code === 'FRIDA_TERMINATION_UNCONFIRMED') {
      gaps.push(fixedGap('FRIDA_TERMINATION_UNCONFIRMED', 'Frida process-tree termination could not be confirmed, so no runtime observations were accepted.'))
    } else {
      gaps.push(fixedGap('FRIDA_EXECUTION_FAILED', 'Frida execution or fixed output validation failed; no success is claimed.'))
    }
    status = 'FAILED'
    observations = []
  }
  try {
    const after = await hashStableFile(artifact.path)
    if (after.sha256 !== before.sha256 || after.size !== before.size) {
      status = 'FAILED'
      observations = []
      gaps.push(fixedGap('TARGET_CHANGED', 'The executable changed during tracing, so its observations were discarded.'))
    }
  } catch {
    status = 'FAILED'
    observations = []
    gaps.push(fixedGap('TARGET_RECHECK_FAILED', 'The executable could not be revalidated after tracing.'))
  }
  if (toolInvocationStarted && !cleanupVerified) gaps.push(fixedGap('CLEANUP_UNVERIFIED', 'The controller could not verify fixed-agent completion and Frida process exit.'))
  const evidence = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/reverse-evidence',
    protocol: 'reverse-evidence-v1',
    run_id: runId,
    engine: 'frida',
    profile_id: FRIDA_REVERSE_PROFILE,
    started_at: startedAt,
    finished_at: canonicalTimestamp(now()),
    artifact: { kind: 'native-executable', path: artifact.relativePath, sha256: before.sha256, size_bytes: before.size },
    tool: { name: 'Frida', version: null, invocation_sha256: invocationSha256 },
    limits,
    status,
    target_execution: 'LOCAL_LAB_SPAWN',
    security_verdict: 'NOT_ASSESSED',
    applied_to_audit_bundle: false,
    observations,
    gaps,
    cleanup: { attempted: toolInvocationStarted, verified: cleanupVerified },
  }
  await exclusiveWrite(join(outputPath, 'evidence.json'), canonicalReverseEvidence(evidence))
  return resultSummary(outputPath, evidence)
}

function targetExecutionForFridaPlan(mode) {
  if (mode === 'local-spawn') return 'LOCAL_LAB_SPAWN'
  if (mode.startsWith('local-')) return 'LOCAL_PROCESS_ATTACH'
  if (mode.startsWith('usb-')) return 'USB_DEVICE_ATTACH'
  return 'DEVICE_ID_ATTACH'
}

async function assertPlanFileUnchanged(path, expected) {
  let observed
  try {
    observed = await hashStableFile(path, FRIDA_PLAN_MAX_BYTES)
  } catch (error) {
    fail('REVERSE_PLAN_RECHECK_FAILED', 'the Frida trace plan could not be revalidated', error)
  }
  if (!sameHash(observed, expected)) {
    fail('REVERSE_PLAN_CHANGED', 'the Frida trace plan changed around execution')
  }
}

export async function traceFridaPlanFile({
  planPath: planPathValue,
  fridaPath: fridaPathValue,
  outPath,
  now = () => new Date(),
  runFrida = runFridaTracePlan,
} = {}) {
  if (typeof runFrida !== 'function') fail('REVERSE_RUNNER_INVALID', 'Frida runner must be a function')
  const planPath = localAbsolutePath(planPathValue, 'Frida trace plan')
  const planBytes = await readStableFile(planPath, FRIDA_PLAN_MAX_BYTES)
  const plan = decodeJson(planBytes, 'Frida trace plan')
  try {
    assertValidFridaTracePlan(plan)
  } catch (error) {
    fail('REVERSE_PLAN_INVALID', 'Frida trace plan failed strict validation', error)
  }
  const planFileHash = {
    sha256: sha256(planBytes),
    size: planBytes.length,
  }
  await assertPlanFileUnchanged(planPath, planFileHash)
  const artifact = await resolveArtifact(plan.artifact.lab_root, plan.artifact.path)
  const fridaPath = await verifyTool(fridaPathValue, 'Frida executable')
  await checkedExistingPath(FRIDA_V2_AGENT_PATH, 'tool', { maximumBytes: 1024 * 1024 })
  const outputPath = await outputDirectoryCandidate(outPath, artifact.labRoot)
  if (equalPath(planPath, outputPath) || inside(outputPath, planPath)) {
    fail('REVERSE_OUTPUT_INVALID', 'Frida evidence output must not contain the trace plan input')
  }

  const runId = newRunId()
  const startedAt = canonicalTimestamp(now())
  const before = await hashStableFile(artifact.path)
  const executableHash = await hashStableFile(fridaPath)
  const agentHash = await hashStableFile(FRIDA_V2_AGENT_PATH, 1024 * 1024)
  const fixedToolFiles = [
    { path: fridaPath, maximumBytes: MAX_ARTIFACT_BYTES, expected: executableHash },
    { path: FRIDA_V2_AGENT_PATH, maximumBytes: 1024 * 1024, expected: agentHash },
  ]
  const frameNonce = randomBytes(32).toString('hex')
  const planSha256 = digestFridaTracePlan(plan)
  const args = buildFridaTracePlanArguments({
    plan,
    artifactPath: artifact.path,
    artifactSha256: before.sha256,
    agentPath: FRIDA_V2_AGENT_PATH,
    frameNonce,
  })
  const targetExecution = targetExecutionForFridaPlan(plan.target.mode)
  const timeoutMs = (plan.limits.duration_seconds + 3) * 1000
  const limits = {
    timeout_ms: timeoutMs,
    max_output_bytes: MAX_OUTPUT_BYTES,
    max_observations: plan.limits.max_events + plan.hooks.length + 2,
  }
  const invocationSha256 = sha256(stableJson({
    profile_id: FRIDA_V2_PROFILE_ID,
    plan_sha256: planSha256,
    artifact_sha256: before.sha256,
    args,
    executable_sha256: executableHash.sha256,
    agent_sha256: agentHash.sha256,
  }, 0))
  const artifactEvidence = {
    kind: plan.artifact.kind,
    path: artifact.relativePath,
    sha256: before.sha256,
    size_bytes: before.size,
  }
  await initializeOutputDirectory(outputPath, async () => {
    await exclusiveWrite(join(outputPath, 'intent.json'), stableJson(reverseIntent({
      runId,
      engine: 'frida',
      profileId: FRIDA_V2_PROFILE_ID,
      artifact: artifactEvidence,
      invocationSha256,
      startedAt,
      limits,
      targetExecution,
    })))
  })

  let status = 'FAILED'
  let observations = []
  let cleanupVerified = false
  let toolInvocationStarted = false
  const gaps = [
    fixedGap('DECLARED_CAPTURE_SCOPE_ONLY', 'The typed Frida profile records only the exact hooks and bounded typed captures declared in the plan; it does not infer behavior outside that scope.'),
    fixedGap('TOOL_VERSION_UNRECORDED', 'The Frida executable and bundled agent bytes are digest-bound, but this profile does not execute a separate version probe; tool.version remains null.'),
  ]
  if (targetExecution !== 'LOCAL_LAB_SPAWN') {
    gaps.push(fixedGap(
      'RUNTIME_ARTIFACT_IDENTITY_UNVERIFIED',
      'The trace is bound to the operator-supplied local artifact copy and target selector, but the profile does not prove that the attached runtime loaded those exact bytes.',
    ))
  }
  try {
    await assertPlanFileUnchanged(planPath, planFileHash)
    await assertToolFilesUnchanged(fixedToolFiles)
    toolInvocationStarted = true
    let result
    let runnerError
    try {
      result = await runFrida({
        fridaPath,
        args,
        plan,
        artifactPath: artifact.path,
        artifactSha256: before.sha256,
        cwd: artifact.labRoot,
        timeoutMs,
        maxOutputBytes: MAX_OUTPUT_BYTES,
      })
    } catch (error) {
      runnerError = error
    }
    await assertToolFilesUnchanged(fixedToolFiles)
    await assertPlanFileUnchanged(planPath, planFileHash)
    if (runnerError) throw runnerError
    observations = fridaV2Observations(result, {
      plan,
      artifactSha256: before.sha256,
      frameNonce,
      maxOutputBytes: MAX_OUTPUT_BYTES,
    })
    cleanupVerified = true
    status = result.truncated === true
      || result.capture_failures > 0
      || result.capture_truncations > 0
      || targetExecution !== 'LOCAL_LAB_SPAWN'
      ? 'PARTIAL'
      : 'SUCCEEDED'
    if (result.truncated === true) {
      gaps.push(fixedGap('FRIDA_OBSERVATIONS_TRUNCATED', 'The typed Frida event limit or an incomplete active call truncated the runtime trace.'))
    }
    if (result.capture_failures > 0) {
      gaps.push(fixedGap('FRIDA_CAPTURE_READ_FAILED', 'One or more declared typed captures failed; individual outcomes identify the failed capture without exposing an error string.'))
    }
    if (result.capture_truncations > 0) {
      gaps.push(fixedGap('FRIDA_CAPTURE_TRUNCATED', 'One or more typed captures reached a declared, readable-range, frame, or session byte boundary; each outcome records its truncation reason.'))
    }
    if (result.trace_events === 0) {
      gaps.push(fixedGap('NO_CALLS_OBSERVED', 'All declared hooks were installed, but no matching calls were observed during the bounded trace window.'))
    }
  } catch (error) {
    if (error?.code === 'REVERSE_PLAN_CHANGED') {
      gaps.push(fixedGap('PLAN_CHANGED', 'The Frida trace plan changed around execution, so all observations were discarded.'))
    } else if (error?.code === 'REVERSE_PLAN_RECHECK_FAILED') {
      gaps.push(fixedGap('PLAN_RECHECK_FAILED', 'The Frida trace plan could not be revalidated around execution, so all observations were discarded.'))
    } else if (error?.code === 'REVERSE_TOOL_CHANGED') {
      gaps.push(fixedGap('TOOL_CHANGED', 'The Frida executable or bundled agent changed around execution, so all observations were discarded.'))
    } else if (error?.code === 'REVERSE_TOOL_RECHECK_FAILED') {
      gaps.push(fixedGap('TOOL_RECHECK_FAILED', 'The Frida executable or bundled agent could not be revalidated around execution, so all observations were discarded.'))
    } else if (error?.code === 'FRIDA_TERMINATION_UNCONFIRMED') {
      gaps.push(fixedGap('FRIDA_TERMINATION_UNCONFIRMED', 'Frida process-tree termination could not be confirmed, so no runtime observations were accepted.'))
    } else {
      gaps.push(fixedGap('FRIDA_EXECUTION_FAILED', 'Frida execution or typed output validation failed; no success is claimed.'))
    }
    status = 'FAILED'
    observations = []
  }
  try {
    const after = await hashStableFile(artifact.path)
    if (!sameHash(after, before)) {
      status = 'FAILED'
      observations = []
      gaps.push(fixedGap('TARGET_CHANGED', 'The local artifact copy changed during tracing, so its observations were discarded.'))
    }
  } catch {
    status = 'FAILED'
    observations = []
    gaps.push(fixedGap('TARGET_RECHECK_FAILED', 'The local artifact copy could not be revalidated after tracing.'))
  }
  if (toolInvocationStarted && !cleanupVerified) {
    gaps.push(fixedGap('CLEANUP_UNVERIFIED', 'The controller could not verify fixed-agent detach and Frida process exit.'))
  }
  const evidence = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/reverse-evidence',
    protocol: 'reverse-evidence-v1',
    run_id: runId,
    engine: 'frida',
    profile_id: FRIDA_V2_PROFILE_ID,
    started_at: startedAt,
    finished_at: canonicalTimestamp(now()),
    artifact: artifactEvidence,
    tool: { name: 'Frida', version: null, invocation_sha256: invocationSha256 },
    limits,
    status,
    target_execution: targetExecution,
    security_verdict: 'NOT_ASSESSED',
    applied_to_audit_bundle: false,
    observations,
    gaps,
    cleanup: { attempted: toolInvocationStarted, verified: cleanupVerified },
  }
  await exclusiveWrite(join(outputPath, 'evidence.json'), canonicalReverseEvidence(evidence))
  return resultSummary(outputPath, evidence)
}
