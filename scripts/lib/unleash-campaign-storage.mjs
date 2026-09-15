import { randomBytes } from 'node:crypto'
import { constants as fsConstants } from 'node:fs'
import {
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  rename,
  unlink,
} from 'node:fs/promises'
import { homedir } from 'node:os'
import {
  isAbsolute,
  join,
  parse,
  posix,
  relative,
  resolve,
  win32,
} from 'node:path'
import { TextDecoder } from 'node:util'

import { compareCanonicalStrings } from './canonical-order.mjs'
import {
  publishFileCreateOnlyDurably,
  replaceFileDurably,
  syncRecoverableDirectoryChange,
} from './durable-file-publication.mjs'
import { assertLocalFilesystemEndpoint } from './filesystem-endpoint.mjs'
import { assertUnleashPrivateEndpoint } from './unleash-policy-loader.mjs'

export const MAX_UNLEASH_CAMPAIGN_JSON_BYTES = 1024 * 1024

export function defaultUnleashCampaignRunsRoot({
  platform = process.platform,
  localAppData = process.env.LOCALAPPDATA,
  home = homedir(),
} = {}) {
  const paths = platform === 'win32' ? win32 : posix
  const base = platform === 'win32'
    ? (typeof localAppData === 'string' && paths.isAbsolute(localAppData)
        ? localAppData
        : paths.join(home, 'AppData', 'Local'))
    : paths.join(home, '.local', 'share')
  return paths.join(paths.resolve(base), 'LastAperture', 'campaigns')
}

const MAX_JSON_DEPTH = 64
const MAX_JSON_NODES = 100_000
const CAMPAIGN_DIRECTORY_PATTERN = /^campaign-[a-f0-9]{24}$/u
const JSON_FILENAME_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*\.json$/u
const WINDOWS_RESERVED_NAME = /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$/iu
const OWNED_TEMP_PATTERN = /^\.([a-z0-9]+(?:-[a-z0-9]+)*\.json)\.([1-9][0-9]{0,15})\.([a-f0-9]{32})\.tmp$/u
const RECOVERY_TEMP_PATTERN = /^\.campaign-recovery\.([1-9][0-9]{0,15})\.([a-f0-9]{32})\.tmp$/u
const CREATE_ONLY_FLAGS = fsConstants.O_WRONLY
  | fsConstants.O_CREAT
  | fsConstants.O_EXCL
  | (fsConstants.O_NOFOLLOW ?? 0)
const READ_ONLY_FLAGS = fsConstants.O_RDONLY
  | (fsConstants.O_NOFOLLOW ?? 0)
  | (fsConstants.O_NONBLOCK ?? 0)
const utf8Decoder = new TextDecoder('utf-8', { fatal: true })

export class UnleashCampaignStorageError extends Error {
  constructor(code, message, { cause } = {}) {
    super(message, cause === undefined ? undefined : { cause })
    this.name = 'UnleashCampaignStorageError'
    this.code = code
  }
}

function fail(code, message, cause) {
  throw new UnleashCampaignStorageError(code, message, { cause })
}

function samePath(left, right) {
  const normalizedLeft = resolve(left)
  const normalizedRight = resolve(right)
  return process.platform === 'win32'
    ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
    : normalizedLeft === normalizedRight
}

function sameDirectoryIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.birthtimeNs === right.birthtimeNs
}

function sameFileMetadata(left, right) {
  return sameDirectoryIdentity(left, right)
    && left.mode === right.mode
    && left.nlink === right.nlink
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs
}

function assertLexicalRoot(value) {
  if (
    typeof value !== 'string'
    || value.length < 1
    || value.length > 4096
    || /[\u0000-\u001f\u007f]/u.test(value)
    || !isAbsolute(value)
  ) fail('UNLEASH_STORAGE_ROOT_INVALID', 'campaign storage root must be one absolute local path')
  try {
    assertLocalFilesystemEndpoint(value, 'campaign storage root')
  } catch (cause) {
    fail('UNLEASH_STORAGE_ROOT_INVALID', 'campaign storage root must be one absolute local path', cause)
  }
  if (resolve(value) !== value || samePath(value, parse(value).root)) {
    fail('UNLEASH_STORAGE_ROOT_INVALID', 'campaign storage root must be canonical and cannot be a filesystem root')
  }
  if (process.platform === 'win32' && /:/u.test(value.slice(2))) {
    fail('UNLEASH_STORAGE_ROOT_INVALID', 'campaign storage root cannot address an alternate data stream')
  }
  if (process.platform === 'win32') {
    const base = resolve(defaultUnleashCampaignRunsRoot(), '..', '..')
    const fromAppData = relative(base, value)
    const segments = fromAppData.split(/[\\/]/u).filter(Boolean)
    if (
      fromAppData === ''
      || fromAppData === '..'
      || fromAppData.startsWith(`..${parse(value).root === '/' ? '/' : '\\'}`)
      || isAbsolute(fromAppData)
      || segments.length < 2
      || segments.at(-2)?.toLowerCase() !== 'lastaperture'
      || segments.at(-1)?.toLowerCase() !== 'campaigns'
    ) {
      fail('UNLEASH_STORAGE_ROOT_INVALID', 'Windows campaign storage must be an app-owned LastAperture directory below LocalAppData')
    }
  }
  return value
}

async function inspectDirectoryPath(path, { requirePrivateRoot = false } = {}) {
  const filesystemRoot = parse(path).root
  let current = filesystemRoot
  let metadata
  try {
    metadata = await lstat(current, { bigint: true })
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      fail('UNLEASH_STORAGE_ROOT_UNSAFE', 'local filesystem root is linked or is not a directory')
    }
    for (const part of relative(filesystemRoot, path).split(/[\\/]/u).filter(Boolean)) {
      current = join(current, part)
      metadata = await lstat(current, { bigint: true })
      if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
        fail('UNLEASH_STORAGE_ROOT_UNSAFE', 'campaign storage cannot cross a link, junction, or non-directory')
      }
    }
    const canonical = await realpath(path)
    if (!samePath(canonical, path)) {
      fail('UNLEASH_STORAGE_ROOT_UNSAFE', 'campaign storage path is an alias instead of its canonical location')
    }
    if (requirePrivateRoot && process.platform !== 'win32') {
      const effectiveUid = typeof process.getuid === 'function' ? BigInt(process.getuid()) : null
      if (
        (effectiveUid !== null && metadata.uid !== effectiveUid)
        || (metadata.mode & 0o077n) !== 0n
      ) {
        fail('UNLEASH_STORAGE_ROOT_UNSAFE', 'campaign storage root must be owned by this account and private')
      }
    }
    return { canonical, metadata }
  } catch (cause) {
    if (cause instanceof UnleashCampaignStorageError) throw cause
    fail('UNLEASH_STORAGE_ROOT_UNSAFE', 'campaign storage path is unavailable or unsafe', cause)
  }
}

async function assertPrivateStorageEndpoint(path, expectedKind) {
  try {
    return await assertUnleashPrivateEndpoint(path, expectedKind)
  } catch (cause) {
    fail(
      'UNLEASH_STORAGE_AUTHORITY_UNSAFE',
      'campaign storage authority is unavailable or permits an untrusted writer',
      cause,
    )
  }
}

function assertCampaignDirectoryName(value) {
  if (typeof value !== 'string' || !CAMPAIGN_DIRECTORY_PATTERN.test(value)) {
    fail('UNLEASH_CAMPAIGN_NAME_INVALID', 'campaign directory must be campaign- followed by 24 lowercase hexadecimal characters')
  }
  return value
}

function assertJsonFilename(value) {
  if (
    typeof value !== 'string'
    || value.length > 128
    || value !== value.normalize('NFC')
    || !JSON_FILENAME_PATTERN.test(value)
    || WINDOWS_RESERVED_NAME.test(value)
  ) fail('UNLEASH_STORAGE_FILENAME_INVALID', 'campaign JSON filename must be one canonical lowercase path segment')
  return value
}

function reserveJsonBytes(state, bytes) {
  state.bytes += bytes
  if (state.bytes > MAX_UNLEASH_CAMPAIGN_JSON_BYTES) {
    fail('UNLEASH_STORAGE_JSON_BOUNDS', 'campaign JSON exceeds its byte bound')
  }
}

function dataDescriptor(value, key) {
  let descriptor
  try {
    descriptor = Object.getOwnPropertyDescriptor(value, key)
  } catch (cause) {
    fail('UNLEASH_STORAGE_JSON_INVALID', 'campaign JSON property cannot be inspected safely', cause)
  }
  if (descriptor === undefined || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
    fail('UNLEASH_STORAGE_JSON_INVALID', 'campaign JSON cannot contain hidden or computed state')
  }
  return descriptor
}

function normalizeJson(value, state, depth = 0) {
  state.nodes += 1
  if (state.nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH) {
    fail('UNLEASH_STORAGE_JSON_BOUNDS', 'campaign JSON exceeds its structure bounds')
  }
  if (value === null) {
    reserveJsonBytes(state, 4)
    return value
  }
  if (typeof value === 'boolean') {
    reserveJsonBytes(state, value ? 4 : 5)
    return value
  }
  if (typeof value === 'string') {
    const encoded = JSON.stringify(value)
    if (Buffer.byteLength(encoded, 'utf8') > MAX_UNLEASH_CAMPAIGN_JSON_BYTES) {
      fail('UNLEASH_STORAGE_JSON_BOUNDS', 'campaign JSON exceeds its byte bound')
    }
    reserveJsonBytes(state, Buffer.byteLength(encoded, 'utf8'))
    return value
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('UNLEASH_STORAGE_JSON_INVALID', 'campaign JSON numbers must be finite')
    const normalized = Object.is(value, -0) ? 0 : value
    reserveJsonBytes(state, Buffer.byteLength(JSON.stringify(normalized), 'utf8'))
    return normalized
  }
  if (typeof value !== 'object') {
    fail('UNLEASH_STORAGE_JSON_INVALID', 'campaign state must contain only plain JSON values')
  }
  if (state.seen.has(value)) {
    fail('UNLEASH_STORAGE_JSON_INVALID', 'campaign JSON cannot contain cycles or repeated object references')
  }
  state.seen.add(value)

  let ownKeys
  let prototype
  try {
    prototype = Object.getPrototypeOf(value)
    if (Array.isArray(value) && (!Number.isSafeInteger(value.length) || value.length > MAX_JSON_NODES)) {
      fail('UNLEASH_STORAGE_JSON_BOUNDS', 'campaign JSON array exceeds its structure bounds')
    }
    ownKeys = Reflect.ownKeys(value)
  } catch (cause) {
    if (cause instanceof UnleashCampaignStorageError) throw cause
    fail('UNLEASH_STORAGE_JSON_INVALID', 'campaign JSON cannot be inspected safely', cause)
  }
  if (ownKeys.length > MAX_JSON_NODES + 1) {
    fail('UNLEASH_STORAGE_JSON_BOUNDS', 'campaign JSON object exceeds its structure bounds')
  }
  if (ownKeys.some((key) => typeof key === 'symbol')) {
    fail('UNLEASH_STORAGE_JSON_INVALID', 'campaign JSON cannot contain symbol-keyed state')
  }

  if (Array.isArray(value)) {
    if (prototype !== Array.prototype || !Number.isSafeInteger(value.length)) {
      fail('UNLEASH_STORAGE_JSON_INVALID', 'campaign JSON arrays must be plain and dense')
    }
    const keys = ownKeys.filter((key) => key !== 'length')
    if (keys.length !== value.length || keys.some((key, index) => key !== String(index))) {
      fail('UNLEASH_STORAGE_JSON_INVALID', 'campaign JSON arrays must be dense and contain no extra fields')
    }
    reserveJsonBytes(state, 2 + Math.max(0, keys.length - 1))
    return keys.map((key) => {
      const descriptor = dataDescriptor(value, key)
      return normalizeJson(descriptor.value, state, depth + 1)
    })
  }

  if (prototype !== Object.prototype && prototype !== null) {
    fail('UNLEASH_STORAGE_JSON_INVALID', 'campaign JSON objects must be plain')
  }
  const keys = ownKeys.sort(compareCanonicalStrings)
  const normalized = Object.create(null)
  reserveJsonBytes(state, 2 + Math.max(0, keys.length - 1))
  for (const key of keys) {
    const descriptor = dataDescriptor(value, key)
    const encodedKey = JSON.stringify(key)
    if (Buffer.byteLength(encodedKey, 'utf8') > MAX_UNLEASH_CAMPAIGN_JSON_BYTES) {
      fail('UNLEASH_STORAGE_JSON_BOUNDS', 'campaign JSON exceeds its byte bound')
    }
    reserveJsonBytes(state, Buffer.byteLength(encodedKey, 'utf8') + 1)
    normalized[key] = normalizeJson(descriptor.value, state, depth + 1)
  }
  return normalized
}

export function canonicalUnleashCampaignJson(value) {
  const normalized = normalizeJson(value, { bytes: 1, nodes: 0, seen: new WeakSet() })
  let json
  try {
    json = `${JSON.stringify(normalized)}\n`
  } catch (cause) {
    fail('UNLEASH_STORAGE_JSON_INVALID', 'campaign JSON could not be serialized canonically', cause)
  }
  if (Buffer.byteLength(json, 'utf8') > MAX_UNLEASH_CAMPAIGN_JSON_BYTES) {
    fail('UNLEASH_STORAGE_JSON_BOUNDS', 'campaign JSON exceeds its byte bound')
  }
  return json
}

async function inspectRegularFile(path) {
  try {
    const metadata = await lstat(path, { bigint: true })
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1n) {
      fail('UNLEASH_STORAGE_FILE_UNSAFE', 'campaign JSON destination must be one regular single-link file')
    }
    const canonical = await realpath(path)
    if (!samePath(canonical, path)) {
      fail('UNLEASH_STORAGE_FILE_UNSAFE', 'campaign JSON destination must use its canonical path')
    }
    await assertPrivateStorageEndpoint(canonical, 'file')
    return { canonical, metadata }
  } catch (cause) {
    if (cause instanceof UnleashCampaignStorageError) throw cause
    if (cause?.code === 'ENOENT') return null
    fail('UNLEASH_STORAGE_FILE_UNSAFE', 'campaign JSON destination cannot be inspected safely', cause)
  }
}

async function verifyPublishedFile(path, expectedBytes) {
  let handle
  try {
    const endpoint = await inspectRegularFile(path)
    if (endpoint === null) fail('UNLEASH_STORAGE_WRITE_FAILED', 'campaign JSON was not published')
    handle = await open(path, READ_ONLY_FLAGS)
    const before = await handle.stat({ bigint: true })
    if (
      !before.isFile()
      || before.nlink !== 1n
      || before.size !== BigInt(expectedBytes.length)
      || !sameFileMetadata(before, endpoint.metadata)
    ) {
      fail('UNLEASH_STORAGE_CHANGED', 'campaign JSON changed before verification')
    }
    const actualBytes = Buffer.alloc(expectedBytes.length)
    let offset = 0
    while (offset < actualBytes.length) {
      const { bytesRead } = await handle.read(
        actualBytes,
        offset,
        actualBytes.length - offset,
        offset,
      )
      if (bytesRead === 0) break
      offset += bytesRead
    }
    const after = await handle.stat({ bigint: true })
    const endpointAfter = await inspectRegularFile(path)
    if (
      endpointAfter === null
      || offset !== actualBytes.length
      || !sameFileMetadata(before, after)
      || !sameFileMetadata(after, endpointAfter.metadata)
      || !actualBytes.equals(expectedBytes)
    ) fail('UNLEASH_STORAGE_CHANGED', 'campaign JSON changed while it was verified')
    return endpointAfter.canonical
  } catch (cause) {
    if (cause instanceof UnleashCampaignStorageError) throw cause
    fail('UNLEASH_STORAGE_WRITE_FAILED', 'campaign JSON could not be verified', cause)
  } finally {
    await handle?.close()
  }
}

function deeplyFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const nested of Object.values(value)) deeplyFreeze(nested)
  return Object.freeze(value)
}

async function readCanonicalJsonFile(path) {
  let handle
  try {
    const endpoint = await inspectRegularFile(path)
    if (endpoint === null) fail('UNLEASH_STORAGE_FILE_NOT_FOUND', 'campaign JSON file does not exist')
    if (endpoint.metadata.size < 1n || endpoint.metadata.size > BigInt(MAX_UNLEASH_CAMPAIGN_JSON_BYTES)) {
      fail('UNLEASH_STORAGE_JSON_BOUNDS', 'campaign JSON file exceeds its byte bound')
    }
    handle = await open(path, READ_ONLY_FLAGS)
    const before = await handle.stat({ bigint: true })
    if (!before.isFile() || before.nlink !== 1n || !sameFileMetadata(before, endpoint.metadata)) {
      fail('UNLEASH_STORAGE_CHANGED', 'campaign JSON changed before it was read')
    }
    const bytes = Buffer.alloc(Number(before.size))
    let offset = 0
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset)
      if (bytesRead === 0) break
      offset += bytesRead
    }
    const after = await handle.stat({ bigint: true })
    const endpointAfter = await inspectRegularFile(path)
    if (
      offset !== bytes.length
      || endpointAfter === null
      || !sameFileMetadata(before, after)
      || !sameFileMetadata(after, endpointAfter.metadata)
    ) fail('UNLEASH_STORAGE_CHANGED', 'campaign JSON changed while it was read')
    let parsed
    try {
      parsed = JSON.parse(utf8Decoder.decode(bytes))
    } catch (cause) {
      fail('UNLEASH_STORAGE_JSON_INVALID', 'campaign JSON is not valid bounded UTF-8 JSON', cause)
    }
    const canonical = Buffer.from(canonicalUnleashCampaignJson(parsed), 'utf8')
    if (!canonical.equals(bytes)) {
      fail('UNLEASH_STORAGE_JSON_NONCANONICAL', 'campaign JSON bytes are not in canonical form')
    }
    return deeplyFreeze(parsed)
  } catch (cause) {
    if (cause instanceof UnleashCampaignStorageError) throw cause
    fail('UNLEASH_STORAGE_READ_FAILED', 'campaign JSON could not be read safely', cause)
  } finally {
    await handle?.close()
  }
}

async function createTemporaryFile(campaignDirectory, filename, bytes) {
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const token = randomBytes(16).toString('hex')
    const path = join(campaignDirectory, `.${filename}.${process.pid}.${token}.tmp`)
    let handle
    try {
      handle = await open(path, CREATE_ONLY_FLAGS, 0o600)
      await handle.writeFile(bytes)
      await handle.sync()
      return path
    } catch (cause) {
      if (cause?.code !== 'EEXIST') {
        fail('UNLEASH_STORAGE_WRITE_FAILED', 'mutable campaign JSON staging failed', cause)
      }
    } finally {
      await handle?.close()
    }
  }
  fail('UNLEASH_STORAGE_WRITE_FAILED', 'mutable campaign JSON staging exhausted collision retries')
}

function processIsAlive(pid) {
  try {
    process.kill(pid, 0)
    return true
  } catch (cause) {
    return cause?.code !== 'ESRCH'
  }
}

async function quarantineAndRemoveStaleTemporary(campaignDirectory, name) {
  const path = join(campaignDirectory, name)
  const before = await inspectRegularFile(path)
  if (before === null) fail('UNLEASH_STORAGE_CHANGED', 'temporary campaign publication disappeared')
  const quarantine = join(
    campaignDirectory,
    `.campaign-recovery.${process.pid}.${randomBytes(16).toString('hex')}.tmp`,
  )
  try {
    await rename(path, quarantine)
    const after = await inspectRegularFile(quarantine)
    if (
      after === null
      || before.metadata.dev !== after.metadata.dev
      || before.metadata.ino !== after.metadata.ino
      || before.metadata.size !== after.metadata.size
      || before.metadata.nlink !== after.metadata.nlink
    ) fail('UNLEASH_STORAGE_CHANGED', 'temporary campaign publication changed during identity-bound quarantine')
    await unlink(quarantine)
    await syncRecoverableDirectoryChange(campaignDirectory)
  } catch (cause) {
    if (cause instanceof UnleashCampaignStorageError) throw cause
    fail('UNLEASH_STORAGE_CHANGED', 'stale campaign publication could not be removed safely', cause)
  }
}

async function recoverStaleTemporaryPublications(campaignDirectory) {
  let entries
  try {
    entries = await readdir(campaignDirectory, { withFileTypes: true })
  } catch (cause) {
    fail('UNLEASH_STORAGE_READ_FAILED', 'campaign directory could not be inspected for recovery', cause)
  }
  if (entries.length > 10_000) {
    fail('UNLEASH_STORAGE_ENTRY_UNSAFE', 'campaign directory exceeds its recovery entry bound')
  }
  for (const entry of entries) {
    const owned = entry.name.match(OWNED_TEMP_PATTERN)
    const recovery = entry.name.match(RECOVERY_TEMP_PATTERN)
    if (owned === null && recovery === null) continue
    const ownerPid = Number(owned !== null ? owned[2] : recovery[1])
    if (!Number.isSafeInteger(ownerPid) || ownerPid < 1 || processIsAlive(ownerPid)) {
      fail('UNLEASH_STORAGE_TEMP_RESIDUE', 'campaign directory contains a live or unverifiable temporary publication')
    }
    await quarantineAndRemoveStaleTemporary(campaignDirectory, entry.name)
  }
}

async function cleanupTemporary(path) {
  if (path === null) return
  try {
    const endpoint = await inspectRegularFile(path)
    if (endpoint !== null) await unlink(endpoint.canonical)
  } catch {}
}

async function initializeUnleashCampaignStorage(
  { runsRoot, campaignDirectory } = {},
  { createCampaign, publishCreateOnly, replaceFile },
) {
  const requestedRoot = assertLexicalRoot(runsRoot)
  const directoryName = assertCampaignDirectoryName(campaignDirectory)
  const inspectedRoot = await inspectDirectoryPath(requestedRoot, { requirePrivateRoot: true })
  await assertPrivateStorageEndpoint(inspectedRoot.canonical, 'directory')
  const campaignPath = join(inspectedRoot.canonical, directoryName)
  if (createCampaign) {
    try {
      await mkdir(campaignPath, { recursive: false, mode: 0o700 })
    } catch (cause) {
      if (cause?.code === 'EEXIST') fail('UNLEASH_CAMPAIGN_EXISTS', 'campaign directory already exists', cause)
      fail('UNLEASH_STORAGE_WRITE_FAILED', 'campaign directory could not be created', cause)
    }
  }
  const rootAfterCreate = await inspectDirectoryPath(inspectedRoot.canonical, { requirePrivateRoot: true })
  await assertPrivateStorageEndpoint(rootAfterCreate.canonical, 'directory')
  let inspectedCampaign
  try {
    inspectedCampaign = await inspectDirectoryPath(campaignPath, { requirePrivateRoot: true })
    await assertPrivateStorageEndpoint(inspectedCampaign.canonical, 'directory')
  } catch (cause) {
    if (!createCampaign && cause?.cause?.code === 'ENOENT') {
      fail('UNLEASH_CAMPAIGN_NOT_FOUND', 'campaign directory does not exist', cause)
    }
    throw cause
  }
  if (!sameDirectoryIdentity(inspectedRoot.metadata, rootAfterCreate.metadata)) {
    fail('UNLEASH_STORAGE_CHANGED', 'campaign storage root changed during campaign creation')
  }
  if (createCampaign) {
    try {
      await syncRecoverableDirectoryChange(inspectedRoot.canonical)
    } catch (cause) {
      fail(
        'UNLEASH_STORAGE_COMMIT_AMBIGUOUS',
        'campaign directory exists but its durable publication is unconfirmed',
        cause,
      )
    }
  }

  const assertStorageStable = async () => {
    try {
      const currentRoot = await inspectDirectoryPath(inspectedRoot.canonical, { requirePrivateRoot: true })
      const currentCampaign = await inspectDirectoryPath(
        inspectedCampaign.canonical,
        { requirePrivateRoot: true },
      )
      await assertPrivateStorageEndpoint(currentRoot.canonical, 'directory')
      await assertPrivateStorageEndpoint(currentCampaign.canonical, 'directory')
      if (
        !sameDirectoryIdentity(inspectedRoot.metadata, currentRoot.metadata)
        || !sameDirectoryIdentity(inspectedCampaign.metadata, currentCampaign.metadata)
      ) fail('UNLEASH_STORAGE_CHANGED', 'campaign storage identity changed after creation')
      return currentCampaign.canonical
    } catch (cause) {
      if (cause instanceof UnleashCampaignStorageError && cause.code === 'UNLEASH_STORAGE_CHANGED') throw cause
      fail('UNLEASH_STORAGE_CHANGED', 'campaign storage became unavailable or unsafe', cause)
    }
  }

  const writeImmutableJsonImpl = async (filename, value) => {
    const safeFilename = assertJsonFilename(filename)
    const bytes = Buffer.from(canonicalUnleashCampaignJson(value), 'utf8')
    const stableCampaign = await assertStorageStable()
    const destination = join(stableCampaign, safeFilename)
    if (await inspectRegularFile(destination) !== null) {
      fail('UNLEASH_STORAGE_FILE_EXISTS', 'immutable campaign JSON already exists')
    }
    let temporary = null
    try {
      temporary = await createTemporaryFile(stableCampaign, safeFilename, bytes)
      if (await inspectRegularFile(temporary) === null) {
        fail('UNLEASH_STORAGE_WRITE_FAILED', 'immutable campaign JSON staging disappeared')
      }
      await assertStorageStable()
      if (await inspectRegularFile(destination) !== null) {
        fail('UNLEASH_STORAGE_FILE_EXISTS', 'immutable campaign JSON already exists')
      }
      await publishCreateOnly(temporary, destination)
      temporary = null
      await assertStorageStable()
      return await verifyPublishedFile(destination, bytes)
    } catch (cause) {
      if (cause instanceof UnleashCampaignStorageError) throw cause
      if (cause?.code === 'EEXIST') {
        fail('UNLEASH_STORAGE_FILE_EXISTS', 'immutable campaign JSON already exists', cause)
      }
      try {
        await assertStorageStable()
        if (await inspectRegularFile(destination) === null) {
          fail('UNLEASH_STORAGE_WRITE_FAILED', 'immutable campaign JSON was not published', cause)
        }
        return await verifyPublishedFile(destination, bytes)
      } catch (reconciliationCause) {
        if (reconciliationCause?.code === 'UNLEASH_STORAGE_WRITE_FAILED') throw reconciliationCause
        fail(
          'UNLEASH_STORAGE_COMMIT_AMBIGUOUS',
          'immutable campaign JSON publication has an ambiguous commit result',
          reconciliationCause,
        )
      }
    } finally {
      await cleanupTemporary(temporary)
    }
  }

  const replaceMutableJsonImpl = async (filename, value) => {
    const safeFilename = assertJsonFilename(filename)
    const bytes = Buffer.from(canonicalUnleashCampaignJson(value), 'utf8')
    const stableCampaign = await assertStorageStable()
    const destination = join(stableCampaign, safeFilename)
    const destinationBefore = await inspectRegularFile(destination)
    let temporary = null
    try {
      temporary = await createTemporaryFile(stableCampaign, safeFilename, bytes)
      if (await inspectRegularFile(temporary) === null) {
        fail('UNLEASH_STORAGE_WRITE_FAILED', 'mutable campaign JSON staging disappeared')
      }
      await assertStorageStable()
      const destinationBeforeRename = await inspectRegularFile(destination)
      if (
        (destinationBefore === null) !== (destinationBeforeRename === null)
        || (
          destinationBefore !== null
          && !sameFileMetadata(destinationBefore.metadata, destinationBeforeRename.metadata)
        )
      ) fail('UNLEASH_STORAGE_CHANGED', 'mutable campaign JSON changed while its replacement was staged')
      await replaceFile(temporary, destination)
      temporary = null
      await syncRecoverableDirectoryChange(stableCampaign)
      await assertStorageStable()
      return await verifyPublishedFile(destination, bytes)
    } catch (cause) {
      if (cause instanceof UnleashCampaignStorageError) throw cause
      try {
        await assertStorageStable()
        const destinationAfterFailure = await inspectRegularFile(destination)
        if (destinationAfterFailure === null) {
          if (destinationBefore === null) {
            fail('UNLEASH_STORAGE_WRITE_FAILED', 'mutable campaign JSON was not published', cause)
          }
          fail(
            'UNLEASH_STORAGE_COMMIT_AMBIGUOUS',
            'mutable campaign JSON disappeared during an ambiguous commit',
            cause,
          )
        }
        try {
          return await verifyPublishedFile(destination, bytes)
        } catch (verificationCause) {
          if (
            destinationBefore !== null
            && sameFileMetadata(destinationBefore.metadata, destinationAfterFailure.metadata)
          ) {
            fail('UNLEASH_STORAGE_WRITE_FAILED', 'mutable campaign JSON replacement did not commit', cause)
          }
          fail(
            'UNLEASH_STORAGE_COMMIT_AMBIGUOUS',
            'mutable campaign JSON replacement has an ambiguous commit result',
            verificationCause,
          )
        }
      } catch (reconciliationCause) {
        if (
          reconciliationCause instanceof UnleashCampaignStorageError
          && [
            'UNLEASH_STORAGE_WRITE_FAILED',
            'UNLEASH_STORAGE_COMMIT_AMBIGUOUS',
          ].includes(reconciliationCause.code)
        ) throw reconciliationCause
        fail(
          'UNLEASH_STORAGE_COMMIT_AMBIGUOUS',
          'mutable campaign JSON replacement could not be reconciled',
          reconciliationCause,
        )
      }
    } finally {
      await cleanupTemporary(temporary)
    }
  }

  const readJsonImpl = async (filename) => {
    const safeFilename = assertJsonFilename(filename)
    const stableCampaign = await assertStorageStable()
    const value = await readCanonicalJsonFile(join(stableCampaign, safeFilename))
    await assertStorageStable()
    return value
  }

  const listJsonFilenamesImpl = async () => {
    const stableCampaign = await assertStorageStable()
    await recoverStaleTemporaryPublications(stableCampaign)
    const campaignBefore = await inspectDirectoryPath(stableCampaign, { requirePrivateRoot: true })
    let entries
    try {
      entries = await readdir(stableCampaign, { withFileTypes: true })
    } catch (cause) {
      fail('UNLEASH_STORAGE_READ_FAILED', 'campaign directory could not be listed safely', cause)
    }
    const filenames = []
    const observed = []
    for (const entry of entries) {
      const name = entry.name
      if (/^\..+\.tmp$/u.test(name)) {
        fail('UNLEASH_STORAGE_TEMP_RESIDUE', 'campaign directory contains an unfinished temporary publication')
      }
      const path = join(stableCampaign, name)
      if (name.endsWith('.json')) {
        assertJsonFilename(name)
        const endpoint = await inspectRegularFile(path)
        if (endpoint === null) fail('UNLEASH_STORAGE_CHANGED', 'campaign JSON disappeared while listing')
        observed.push({ kind: 'file', path, metadata: endpoint.metadata })
        filenames.push(name)
        continue
      }
      if (entry.isDirectory() && /^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(name)) {
        const endpoint = await inspectDirectoryPath(path, { requirePrivateRoot: true })
        await assertPrivateStorageEndpoint(endpoint.canonical, 'directory')
        observed.push({ kind: 'directory', path, metadata: endpoint.metadata })
        continue
      }
      fail('UNLEASH_STORAGE_ENTRY_UNSAFE', 'campaign directory contains an unknown or unsafe entry')
    }
    for (const item of observed) {
      const current = item.kind === 'file'
        ? await inspectRegularFile(item.path)
        : await inspectDirectoryPath(item.path)
      if (current === null || !sameFileMetadata(item.metadata, current.metadata)) {
        fail('UNLEASH_STORAGE_CHANGED', 'campaign directory entry changed while listing')
      }
    }
    const campaignAfter = await inspectDirectoryPath(stableCampaign, { requirePrivateRoot: true })
    if (!sameFileMetadata(campaignBefore.metadata, campaignAfter.metadata)) {
      fail('UNLEASH_STORAGE_CHANGED', 'campaign directory changed while listing')
    }
    await assertStorageStable()
    return Object.freeze(filenames.sort(compareCanonicalStrings))
  }

  let accessTail = Promise.resolve()
  const serializeAccess = (operation) => {
    const pending = accessTail.then(operation, operation)
    accessTail = pending.catch(() => {})
    return pending
  }
  const writeImmutableJson = (filename, value) => serializeAccess(
    () => writeImmutableJsonImpl(filename, value),
  )
  const replaceMutableJson = (filename, value) => serializeAccess(
    () => replaceMutableJsonImpl(filename, value),
  )
  const readJson = (filename) => serializeAccess(() => readJsonImpl(filename))
  const listJsonFilenames = () => serializeAccess(() => listJsonFilenamesImpl())

  return Object.freeze({
    runs_root: inspectedRoot.canonical,
    campaign_directory: inspectedCampaign.canonical,
    writeImmutableJson,
    replaceMutableJson,
    readJson,
    listJsonFilenames,
  })
}

function publicationDependencies(dependencies = {}) {
  if (dependencies === null || typeof dependencies !== 'object' || Array.isArray(dependencies)) {
    fail('UNLEASH_STORAGE_DEPENDENCIES_INVALID', 'campaign storage dependencies must be an object')
  }
  if (Object.keys(dependencies).some((key) => !['publishCreateOnly', 'replaceFile'].includes(key))) {
    fail('UNLEASH_STORAGE_DEPENDENCIES_INVALID', 'campaign storage dependencies contain an unexpected field')
  }
  const publishCreateOnly = dependencies.publishCreateOnly ?? publishFileCreateOnlyDurably
  const replaceFile = dependencies.replaceFile ?? replaceFileDurably
  if (typeof publishCreateOnly !== 'function' || typeof replaceFile !== 'function') {
    fail('UNLEASH_STORAGE_DEPENDENCIES_INVALID', 'campaign storage publication dependencies must be functions')
  }
  return { publishCreateOnly, replaceFile }
}

export async function createUnleashCampaignStorage(options, dependencies) {
  return initializeUnleashCampaignStorage(options, {
    createCampaign: true,
    ...publicationDependencies(dependencies),
  })
}

export async function openUnleashCampaignStorage(options, dependencies) {
  return initializeUnleashCampaignStorage(options, {
    createCampaign: false,
    ...publicationDependencies(dependencies),
  })
}
