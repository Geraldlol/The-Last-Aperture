import { constants as fsConstants } from 'node:fs'
import {
  createHash,
  randomBytes,
  sign as signBytes,
  verify as verifyBytes,
} from 'node:crypto'
import {
  access,
  link,
  lstat,
  mkdir,
  open,
  opendir,
  readFile,
  realpath,
  rename,
  rm,
  rmdir,
  unlink,
} from 'node:fs/promises'
import {
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
} from 'node:path'

import {
  assertValidTransparencyConsistencyRequest,
  assertValidTransparencyPublishRequest,
  canonicalAttestationBytes,
  createTransparencyConsistencyProof,
  createTransparencyInclusionReceipt,
  createTransparencySignedCheckpoint,
  parseTransparencyPrivateKey,
  transparencyLeafHash,
  transparencyNodeHash,
  verifyTransparencyConsistencyProof,
  verifyTransparencySignedCheckpoint,
} from '../../scripts/lib/transparency-log-contracts.mjs'
import { stableJson } from '../../scripts/lib/run-engine.mjs'

const STATE_SCHEMA_VERSION = '1.0.0'
const STATE_KIND = 'red-team-audit/reference-transparency-log-state'
const ENTRY_KIND = 'red-team-audit/reference-transparency-log-entry'
const CHECKPOINT_KIND = 'red-team-audit/reference-transparency-log-checkpoint'
const SIGNING_ALGORITHM = 'Ed25519'
const METADATA_FILE = 'metadata.json'
const ENTRY_DIRECTORY = 'entries'
const CHECKPOINT_DIRECTORY = 'checkpoints'
const LOCK_DIRECTORY = '.state.lock'
const LOCK_OWNER_FILE = 'owner.json'
const EMPTY_ROOT = createHash('sha256').update(Buffer.alloc(0)).digest('hex')
const DIGEST = /^[a-f0-9]{64}$/
const KEY_ID = /^ed25519:[a-f0-9]{64}$/
const ORIGIN = /^[A-Za-z0-9][A-Za-z0-9._:/-]+$/
const INDEX_NAME = /^(\d{16})\.(entry|checkpoint)\.json$/
const TEMPORARY_NAME = /^\.(\d{16})\.(entry|checkpoint)\.json\.tmp-\d+-[a-f0-9]{24}$/
const METADATA_TEMPORARY_NAME = /^\.metadata\.json\.tmp-\d+-[a-f0-9]{24}$/
const LOCK_OWNER_TEMPORARY_NAME = /^\.owner\.json\.tmp-\d+-[a-f0-9]{24}$/
const MAX_TRUSTED_CHECKPOINT_BYTES = 64 * 1024
const OPEN_READ_ONLY_NO_FOLLOW = fsConstants.O_RDONLY
  | (typeof fsConstants.O_NOFOLLOW === 'number' ? fsConstants.O_NOFOLLOW : 0)
const METADATA_CONTEXT = Buffer.from(
  'red-team-audit/reference-transparency-log/metadata/v1\0',
  'utf8',
)
const ENTRY_CONTEXT = Buffer.from(
  'red-team-audit/reference-transparency-log/entry/v1\0',
  'utf8',
)
const CHECKPOINT_CONTEXT = Buffer.from(
  'red-team-audit/reference-transparency-log/checkpoint/v1\0',
  'utf8',
)

export const DEFAULT_REFERENCE_TRANSPARENCY_LOG_LIMITS = Object.freeze({
  maxEntries: 1_000_000,
  maxEntryBytes: 256 * 1024,
  maxRequestBytes: 384 * 1024,
  maxTotalEntryBytes: 1024 * 1024 * 1024,
  lockTimeoutMs: 10_000,
  staleLockMs: 30_000,
  lockPollMs: 10,
})

export class ReferenceTransparencyLogStoreError extends Error {
  constructor(code, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'ReferenceTransparencyLogStoreError'
    this.code = code
    if (options.details !== undefined) this.details = options.details
  }
}

function storeError(code, message, options) {
  return new ReferenceTransparencyLogStoreError(code, message, options)
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function canonicalBytes(value) {
  return Buffer.from(stableJson(value, 0), 'utf8')
}

function parseTrustedCheckpoint(options) {
  const hasDocument = options.trustedCheckpoint !== undefined
  const hasBytes = options.trustedCheckpointBytes !== undefined
  if (hasDocument && hasBytes) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_TRUSTED_CHECKPOINT_AMBIGUOUS',
      'supply trustedCheckpoint or trustedCheckpointBytes, not both',
    )
  }
  if (!hasDocument && !hasBytes) return null
  let document
  let bytes
  if (hasBytes) {
    bytes = Buffer.from(options.trustedCheckpointBytes)
    if (bytes.length === 0 || bytes.length > MAX_TRUSTED_CHECKPOINT_BYTES) {
      throw storeError(
        'REFERENCE_TRANSPARENCY_TRUSTED_CHECKPOINT_INVALID',
        'trusted checkpoint bytes are empty or exceed the bounded artifact size',
      )
    }
    try {
      document = JSON.parse(bytes.toString('utf8'))
    } catch (error) {
      throw storeError(
        'REFERENCE_TRANSPARENCY_TRUSTED_CHECKPOINT_INVALID',
        `trusted checkpoint is not valid JSON: ${error.message}`,
      )
    }
    const canonical = canonicalBytes(document)
    if (!canonical.equals(bytes)) {
      throw storeError(
        'REFERENCE_TRANSPARENCY_TRUSTED_CHECKPOINT_INVALID',
        'trusted checkpoint must use canonical JSON bytes',
      )
    }
  } else {
    try {
      document = structuredClone(options.trustedCheckpoint)
      bytes = canonicalBytes(document)
    } catch (error) {
      throw storeError(
        'REFERENCE_TRANSPARENCY_TRUSTED_CHECKPOINT_INVALID',
        `trusted checkpoint cannot be cloned and canonicalized: ${error.message}`,
      )
    }
  }
  return Object.freeze({
    document: Object.freeze(document),
    sha256: sha256(bytes),
  })
}

function unsigned(document) {
  const { signature: _signature, ...rest } = document
  return rest
}

function signingPayload(context, document) {
  return Buffer.concat([context, canonicalBytes(unsigned(document))])
}

function signDocument(context, document, privateKey) {
  return {
    ...document,
    signature: signBytes(
      null,
      signingPayload(context, document),
      privateKey,
    ).toString('base64'),
  }
}

function assertSignedDocument(context, document, publicKey, label) {
  const signature = Buffer.from(document?.signature ?? '', 'base64')
  if (
    signature.length !== 64
    || signature.toString('base64') !== document?.signature
    || !verifyBytes(
      null,
      signingPayload(context, document),
      publicKey,
      signature,
    )
  ) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_STATE_SIGNATURE_INVALID',
      `${label} does not have a valid canonical state signature`,
    )
  }
}

function normalizeInstant(value, label) {
  const supplied = typeof value === 'function' ? value() : value
  const instant = supplied instanceof Date ? supplied : new Date(supplied)
  if (!Number.isFinite(instant.getTime())) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_CLOCK_INVALID',
      `${label} must be a valid instant`,
    )
  }
  return instant
}

function canonicalTimestamp(value, label) {
  if (typeof value !== 'string') {
    throw storeError(
      'REFERENCE_TRANSPARENCY_STATE_INVALID',
      `${label} must be a canonical timestamp`,
    )
  }
  const instant = normalizeInstant(value, label)
  if (instant.toISOString() !== value) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_STATE_INVALID',
      `${label} must be a canonical timestamp`,
    )
  }
  return instant.getTime()
}

function integerLimit(value, fallback, name, minimum, maximum) {
  const selected = value ?? fallback
  if (
    !Number.isSafeInteger(selected)
    || selected < minimum
    || selected > maximum
  ) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_LIMIT_INVALID',
      `${name} must be an integer between ${minimum} and ${maximum}`,
    )
  }
  return selected
}

function limitValue(limits, camel, snake) {
  return limits?.[camel] ?? limits?.[snake]
}

function normalizeLimits(limits = {}) {
  if (limits === null || typeof limits !== 'object' || Array.isArray(limits)) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_LIMIT_INVALID',
      'reference transparency log limits must be an object',
    )
  }
  return Object.freeze({
    maxEntries: integerLimit(
      limitValue(limits, 'maxEntries', 'max_entries'),
      DEFAULT_REFERENCE_TRANSPARENCY_LOG_LIMITS.maxEntries,
      'maxEntries',
      1,
      10_000_000,
    ),
    maxEntryBytes: integerLimit(
      limitValue(limits, 'maxEntryBytes', 'max_entry_bytes'),
      DEFAULT_REFERENCE_TRANSPARENCY_LOG_LIMITS.maxEntryBytes,
      'maxEntryBytes',
      1,
      16 * 1024 * 1024,
    ),
    maxRequestBytes: integerLimit(
      limitValue(limits, 'maxRequestBytes', 'max_request_bytes'),
      DEFAULT_REFERENCE_TRANSPARENCY_LOG_LIMITS.maxRequestBytes,
      'maxRequestBytes',
      256,
      32 * 1024 * 1024,
    ),
    maxTotalEntryBytes: integerLimit(
      limitValue(limits, 'maxTotalEntryBytes', 'max_total_entry_bytes'),
      DEFAULT_REFERENCE_TRANSPARENCY_LOG_LIMITS.maxTotalEntryBytes,
      'maxTotalEntryBytes',
      1,
      1024 * 1024 * 1024 * 1024,
    ),
    lockTimeoutMs: integerLimit(
      limitValue(limits, 'lockTimeoutMs', 'lock_timeout_ms'),
      DEFAULT_REFERENCE_TRANSPARENCY_LOG_LIMITS.lockTimeoutMs,
      'lockTimeoutMs',
      1,
      300_000,
    ),
    staleLockMs: integerLimit(
      limitValue(limits, 'staleLockMs', 'stale_lock_ms'),
      DEFAULT_REFERENCE_TRANSPARENCY_LOG_LIMITS.staleLockMs,
      'staleLockMs',
      1,
      24 * 60 * 60 * 1000,
    ),
    lockPollMs: integerLimit(
      limitValue(limits, 'lockPollMs', 'lock_poll_ms'),
      DEFAULT_REFERENCE_TRANSPARENCY_LOG_LIMITS.lockPollMs,
      'lockPollMs',
      1,
      1_000,
    ),
  })
}

function isWithin(parent, child) {
  const path = relative(resolve(parent), resolve(child))
  return path === '' || (!path.startsWith('..') && !isAbsolute(path))
}

function comparablePath(path) {
  const normalized = resolve(path)
  return process.platform === 'win32' ? normalized.toLowerCase() : normalized
}

async function assertNoLinkedAncestor(requestedPath) {
  let candidate = resolve(requestedPath)
  let info
  for (;;) {
    try {
      info = await lstat(candidate)
      break
    } catch (error) {
      if (error.code !== 'ENOENT') throw error
      const parent = dirname(candidate)
      if (parent === candidate) throw error
      candidate = parent
    }
  }
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_STATE_PATH_ALIAS',
      'transparency state path cannot traverse a symlink or junction ancestor',
    )
  }
  const canonical = await realpath(candidate)
  if (comparablePath(candidate) !== comparablePath(canonical)) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_STATE_PATH_ALIAS',
      'transparency state path cannot traverse a symlink or junction ancestor',
    )
  }
}

async function pathExists(path) {
  try {
    await access(path)
    return true
  } catch (error) {
    if (error.code === 'ENOENT') return false
    throw error
  }
}

async function boundedDirectoryNames(path, maximum, label) {
  const directory = await opendir(path)
  const names = []
  try {
    for await (const entry of directory) {
      names.push(entry.name)
      if (names.length > maximum) {
        throw storeError(
          'REFERENCE_TRANSPARENCY_DIRECTORY_ENTRY_LIMIT',
          `${label} exceeds its ${maximum}-entry directory limit`,
        )
      }
    }
  } finally {
    await directory.close().catch((error) => {
      if (error.code !== 'ERR_DIR_CLOSED') throw error
    })
  }
  return names
}

async function assertOutsideAuditBundle(directory, auditBundleDirectory) {
  if (auditBundleDirectory !== undefined) {
    if (
      typeof auditBundleDirectory !== 'string'
      || auditBundleDirectory.length === 0
    ) {
      throw storeError(
        'REFERENCE_TRANSPARENCY_STATE_PATH_INVALID',
        'auditBundleDirectory must be a non-empty path when supplied',
      )
    }
    const bundle = resolve(auditBundleDirectory)
    if (isWithin(bundle, directory) || isWithin(directory, bundle)) {
      throw storeError(
        'REFERENCE_TRANSPARENCY_STATE_INSIDE_AUDIT_BUNDLE',
        'transparency log state must be separate from every audit bundle',
      )
    }
  }

  let candidate = directory
  for (;;) {
    const runPath = join(candidate, 'run.json')
    if (await pathExists(runPath)) {
      let run
      try {
        const info = await lstat(runPath)
        if (info.isFile() && !info.isSymbolicLink() && info.size <= 2 * 1024 * 1024) {
          run = JSON.parse(await readFile(runPath, 'utf8'))
        }
      } catch {
        // An unrelated or malformed run.json is not enough to label an ancestor.
      }
      if (
        run !== null
        && typeof run === 'object'
        && typeof run.run_id === 'string'
        && typeof run.phase === 'string'
        && typeof run.state === 'string'
      ) {
        throw storeError(
          'REFERENCE_TRANSPARENCY_STATE_INSIDE_AUDIT_BUNDLE',
          'transparency log state must be stored outside the audit bundle',
        )
      }
    }
    const parent = dirname(candidate)
    if (parent === candidate) break
    candidate = parent
  }
}

async function syncDirectory(path) {
  let handle
  try {
    handle = await open(path, fsConstants.O_RDONLY)
    await handle.sync()
  } catch (error) {
    if (!['EINVAL', 'EISDIR', 'ENOTSUP', 'EPERM'].includes(error.code)) {
      throw error
    }
  } finally {
    await handle?.close()
  }
}

async function atomicCreate(path, bytes) {
  const target = resolve(path)
  const parent = dirname(target)
  const temporary = join(
    parent,
    `.${target.slice(parent.length + 1)}.tmp-${process.pid}-${randomBytes(12).toString('hex')}`,
  )
  let handle
  try {
    handle = await open(temporary, 'wx', 0o600)
    await handle.writeFile(bytes)
    await handle.sync()
    await handle.close()
    handle = undefined
    await link(temporary, target)
    await syncDirectory(parent)
  } catch (error) {
    await handle?.close().catch(() => {})
    await rm(temporary, { force: true }).catch(() => {})
    throw error
  }
  await unlink(temporary)
  await syncDirectory(parent)
}

async function createCanonicalFile(path, document) {
  const bytes = canonicalBytes(document)
  try {
    await atomicCreate(path, bytes)
  } catch (error) {
    if (error.code !== 'EEXIST') throw error
    const existing = await readBoundedRegularFile(
      path,
      bytes.length,
      `existing ${path}`,
    )
    if (!existing.equals(bytes)) {
      throw storeError(
        'REFERENCE_TRANSPARENCY_IMMUTABLE_FILE_CONFLICT',
        `immutable transparency state file already exists with different bytes: ${path}`,
      )
    }
  }
  return bytes
}

async function readBoundedRegularFile(
  path,
  maximumBytes,
  label,
  { allowedLinkCounts = [1] } = {},
) {
  const info = await lstat(path)
  if (
    !info.isFile()
    || info.isSymbolicLink()
    || (
      typeof info.nlink === 'number'
      && !allowedLinkCounts.includes(info.nlink)
    )
  ) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_STATE_FILE_UNSAFE',
      `${label} must be a regular non-symlink file with an expected link count`,
    )
  }
  if (info.size > maximumBytes) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_STATE_FILE_TOO_LARGE',
      `${label} exceeds its ${maximumBytes}-byte limit`,
    )
  }
  const handle = await open(path, OPEN_READ_ONLY_NO_FOLLOW)
  try {
    const before = await handle.stat()
    const bytes = await handle.readFile()
    const after = await handle.stat()
    if (
      before.size !== after.size
      || before.mtimeMs !== after.mtimeMs
      || before.ino !== after.ino
      || bytes.length !== after.size
    ) {
      throw storeError(
        'REFERENCE_TRANSPARENCY_STATE_FILE_CHANGED',
        `${label} changed while it was being read`,
      )
    }
    return bytes
  } finally {
    await handle.close()
  }
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino
}

function assertRegularAtomicFile(info, label) {
  if (!info.isFile() || info.isSymbolicLink()) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_ATOMIC_TEMP_UNSAFE',
      `${label} must be a regular non-symlink file`,
    )
  }
}

async function reconcileAtomicTemporary(
  directory,
  targetName,
  temporaryName,
  label,
) {
  const targetPath = join(directory, targetName)
  const temporaryPath = join(directory, temporaryName)
  const temporaryInfo = await lstat(temporaryPath)
  assertRegularAtomicFile(temporaryInfo, `${label} temporary file`)

  let targetInfo
  try {
    targetInfo = await lstat(targetPath)
  } catch (error) {
    if (error.code !== 'ENOENT') throw error
  }
  if (targetInfo === undefined) {
    if (temporaryInfo.nlink !== 1) {
      throw storeError(
        'REFERENCE_TRANSPARENCY_ATOMIC_TEMP_CONFLICT',
        `${label} uncommitted temporary file has an unexpected link count`,
      )
    }
    await unlink(temporaryPath)
    await syncDirectory(directory)
    return { committed: false }
  }

  assertRegularAtomicFile(targetInfo, `${label} target file`)
  if (
    temporaryInfo.nlink !== 2
    || targetInfo.nlink !== 2
    || !sameFileIdentity(temporaryInfo, targetInfo)
  ) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_ATOMIC_TEMP_CONFLICT',
      `${label} target and temporary file are not the same two-link durable inode`,
    )
  }
  await unlink(temporaryPath)
  await syncDirectory(directory)
  const reconciled = await lstat(targetPath)
  assertRegularAtomicFile(reconciled, `${label} reconciled target file`)
  if (reconciled.nlink !== 1) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_ATOMIC_TEMP_CONFLICT',
      `${label} target did not return to one link after reconciliation`,
    )
  }
  return { committed: true }
}

async function reconcileNamedAtomicTemporary(
  directory,
  targetName,
  pattern,
  label,
) {
  const names = await boundedDirectoryNames(directory, 64, label)
  const temporaryNames = names.filter((name) => pattern.test(name))
  if (temporaryNames.length > 1) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_ATOMIC_TEMP_CONFLICT',
      `${label} has multiple pending temporary files`,
    )
  }
  if (temporaryNames.length === 1) {
    await reconcileAtomicTemporary(
      directory,
      targetName,
      temporaryNames[0],
      label,
    )
  }
}

async function reconcileStateTemporaries(directory, kind, maximum) {
  await assertStateDirectory(directory, `${kind} directory`)
  const names = await boundedDirectoryNames(
    directory,
    maximum + 16,
    `${kind} directory`,
  )
  const byTarget = new Map()
  for (const name of names) {
    const match = TEMPORARY_NAME.exec(name)
    if (match?.[2] !== kind) continue
    const targetName = `${match[1]}.${kind}.json`
    const prior = byTarget.get(targetName)
    if (prior !== undefined) {
      throw storeError(
        'REFERENCE_TRANSPARENCY_ATOMIC_TEMP_CONFLICT',
        `${kind} ${match[1]} has multiple pending temporary files`,
      )
    }
    byTarget.set(targetName, name)
  }
  for (const [targetName, temporaryName] of byTarget) {
    await reconcileAtomicTemporary(
      directory,
      targetName,
      temporaryName,
      `${kind} ${targetName.slice(0, 16)}`,
    )
  }
}

async function readCanonicalDocument(path, maximumBytes, label) {
  const bytes = await readBoundedRegularFile(path, maximumBytes, label)
  let document
  try {
    document = JSON.parse(bytes.toString('utf8'))
  } catch (error) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_STATE_JSON_INVALID',
      `${label} is not valid JSON`,
      { cause: error },
    )
  }
  if (!canonicalBytes(document).equals(bytes)) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_STATE_NONCANONICAL',
      `${label} is not canonical JSON`,
    )
  }
  return { bytes, document }
}

function sleep(milliseconds) {
  return new Promise((resolveSleep) => setTimeout(resolveSleep, milliseconds))
}

function processIsAlive(pid) {
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    return error.code !== 'ESRCH'
  }
}

function validLockOwner(value) {
  return value !== null
    && typeof value === 'object'
    && value.schema_version === STATE_SCHEMA_VERSION
    && Number.isSafeInteger(value.pid)
    && value.pid > 0
    && typeof value.acquired_at === 'string'
    && /^[a-f0-9]{32}$/.test(value.nonce ?? '')
}

async function inspectLock(lockPath) {
  const before = await lstat(lockPath)
  if (!before.isDirectory() || before.isSymbolicLink()) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_LOCK_UNSAFE',
      'transparency state lock must be a real directory',
    )
  }
  const names = await boundedDirectoryNames(lockPath, 3, 'state lock')
  const temporaryNames = names.filter((name) =>
    LOCK_OWNER_TEMPORARY_NAME.test(name))
  if (
    names.some((name) =>
      name !== LOCK_OWNER_FILE && !LOCK_OWNER_TEMPORARY_NAME.test(name))
    || temporaryNames.length > 1
    || names.length > 2
  ) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_LOCK_UNSAFE',
      'transparency state lock contains unexpected files',
    )
  }
  const ownerPath = join(lockPath, LOCK_OWNER_FILE)
  const hasOwner = names.includes(LOCK_OWNER_FILE)
  let ownerInfo
  let temporaryInfo
  if (temporaryNames.length === 1) {
    temporaryInfo = await lstat(join(lockPath, temporaryNames[0]))
    assertRegularAtomicFile(temporaryInfo, 'lock owner temporary file')
  }
  if (!hasOwner) {
    if (temporaryInfo !== undefined && temporaryInfo.nlink !== 1) {
      throw storeError(
        'REFERENCE_TRANSPARENCY_LOCK_CHANGED',
        'lock owner publication changed during inspection',
      )
    }
    const after = await lstat(lockPath)
    if (
      !sameFileIdentity(before, after)
      || before.mtimeMs !== after.mtimeMs
    ) {
      throw storeError(
        'REFERENCE_TRANSPARENCY_LOCK_CHANGED',
        'transparency state lock changed during inspection',
      )
    }
    return {
      info: before,
      owner: null,
      observed: null,
      ageReference: before.mtimeMs,
      missingOwner: true,
      temporaryName: temporaryNames[0] ?? null,
    }
  }

  ownerInfo = await lstat(ownerPath)
  assertRegularAtomicFile(ownerInfo, 'lock owner')
  if (ownerInfo.nlink === 1) {
    if (temporaryInfo !== undefined) {
      throw storeError(
        'REFERENCE_TRANSPARENCY_LOCK_UNSAFE',
        'lock owner has an unrelated pending temporary file',
      )
    }
  } else if (
    ownerInfo.nlink !== 2
    || temporaryInfo === undefined
    || temporaryInfo.nlink !== 2
    || !sameFileIdentity(ownerInfo, temporaryInfo)
  ) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_LOCK_UNSAFE',
      'lock owner hard-link state is not an exact atomic publication pair',
    )
  }
  const observed = await readBoundedRegularFile(
    ownerPath,
    4096,
    'lock owner',
    { allowedLinkCounts: [1, 2] },
  )
  let owner
  try {
    owner = JSON.parse(observed.toString('utf8'))
  } catch {
    owner = null
  }
  const after = await lstat(lockPath)
  if (
    !sameFileIdentity(before, after)
    || before.mtimeMs !== after.mtimeMs
  ) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_LOCK_CHANGED',
      'transparency state lock changed during inspection',
    )
  }
  const acquiredAt = validLockOwner(owner)
    ? Date.parse(owner.acquired_at)
    : Number.NaN
  return {
    info: before,
    owner,
    observed,
    ageReference: Number.isFinite(acquiredAt) ? acquiredAt : before.mtimeMs,
    temporaryName: temporaryNames[0] ?? null,
  }
}

async function removeRenamedLock(path, inspected) {
  const current = await inspectLock(path)
  if (
    !sameFileIdentity(current.info, inspected.info)
    || current.info.mtimeMs !== inspected.info.mtimeMs
    || (
      current.observed === null
        ? inspected.observed !== null
        : inspected.observed === null
          || !current.observed.equals(inspected.observed)
    )
  ) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_LOCK_CHANGED',
      'transparency state lock changed during recovery',
    )
  }
  if (current.temporaryName !== null) {
    await unlink(join(path, current.temporaryName))
  }
  if (current.observed !== null) {
    await unlink(join(path, LOCK_OWNER_FILE))
  }
  await syncDirectory(path)
  await removeEmptyLockDirectory(path)
  await syncDirectory(dirname(path))
}

async function removeEmptyLockDirectory(path) {
  const deadline = Date.now() + 2_000
  for (;;) {
    try {
      await rmdir(path)
      return
    } catch (error) {
      if (
        !['EACCES', 'EBUSY', 'EPERM'].includes(error.code)
        || Date.now() >= deadline
      ) {
        throw error
      }
      await sleep(2)
    }
  }
}

async function renameLockDirectory(source, destination) {
  const deadline = Date.now() + 2_000
  for (;;) {
    try {
      await rename(source, destination)
      return
    } catch (error) {
      if (
        !['EACCES', 'EBUSY', 'EPERM'].includes(error.code)
        || Date.now() >= deadline
      ) {
        throw error
      }
      await sleep(2)
    }
  }
}

async function recoverStaleLock(lockPath, inspected) {
  const quarantine = `${lockPath}.stale-${process.pid}-${randomBytes(12).toString('hex')}`
  try {
    await renameLockDirectory(lockPath, quarantine)
  } catch (error) {
    if (['ENOENT', 'EEXIST'].includes(error.code)) return false
    throw error
  }
  try {
    await removeRenamedLock(quarantine, inspected)
  } catch (error) {
    try {
      await renameLockDirectory(quarantine, lockPath)
    } catch (restoreError) {
      throw new AggregateError(
        [error, restoreError],
        'stale transparency lock changed and could not be restored safely',
      )
    }
    throw error
  }
  return true
}

async function acquireLock(directory, limits) {
  const lockPath = join(directory, LOCK_DIRECTORY)
  const deadline = Date.now() + limits.lockTimeoutMs
  let nextInspectionAt = 0
  let lastOwnerAlive = true
  let unsafeStateObservedAt = null
  for (;;) {
    try {
      await mkdir(lockPath, { recursive: false, mode: 0o700 })
      const owner = {
        schema_version: STATE_SCHEMA_VERSION,
        pid: process.pid,
        acquired_at: new Date().toISOString(),
        nonce: randomBytes(16).toString('hex'),
      }
      const content = canonicalBytes(owner)
      try {
        await atomicCreate(join(lockPath, LOCK_OWNER_FILE), content)
        await syncDirectory(lockPath)
      } catch (error) {
        let cleanupError
        try {
          const inspected = await inspectLock(lockPath)
          const failedPath = `${lockPath}.failed-${process.pid}-${owner.nonce}`
          await renameLockDirectory(lockPath, failedPath)
          await removeRenamedLock(failedPath, inspected)
        } catch (candidateCleanupError) {
          cleanupError = candidateCleanupError
        }
        if (cleanupError) {
          throw new AggregateError(
            [error, cleanupError],
            'lock owner creation failed and its exact state could not be removed safely',
          )
        }
        throw error
      }
      return { path: lockPath, owner, content }
    } catch (error) {
      if (error.code !== 'EEXIST') throw error
    }

    const beforeInspection = Date.now()
    if (beforeInspection < nextInspectionAt) {
      if (beforeInspection >= deadline) {
        throw storeError(
          'REFERENCE_TRANSPARENCY_LOCK_TIMEOUT',
          lastOwnerAlive
            ? 'timed out waiting for an active transparency state lock'
            : 'timed out waiting to recover the transparency state lock',
        )
      }
      const baseDelay = Math.min(
        Math.max(limits.lockPollMs, 2),
        Math.max(1, deadline - beforeInspection),
      )
      await sleep(baseDelay + (randomBytes(1)[0] % 7))
      continue
    }

    let inspected
    try {
      inspected = await inspectLock(lockPath)
    } catch (error) {
      if (
        error.code === 'ENOENT'
        || error.code === 'REFERENCE_TRANSPARENCY_LOCK_CHANGED'
      ) {
        continue
      }
      if (error.code === 'REFERENCE_TRANSPARENCY_LOCK_UNSAFE') {
        unsafeStateObservedAt ??= Date.now()
        if (
          Date.now() < deadline
          && Date.now() - unsafeStateObservedAt < 100
        ) {
          await sleep(5)
          continue
        }
      }
      throw error
    }
    unsafeStateObservedAt = null
    const age = Date.now() - inspected.ageReference
    const ownerAlive = inspected.missingOwner
      ? false
      : validLockOwner(inspected.owner)
        ? processIsAlive(inspected.owner.pid)
        : true
    lastOwnerAlive = ownerAlive
    if (age >= limits.staleLockMs && !ownerAlive) {
      if (await recoverStaleLock(lockPath, inspected)) continue
    }
    if (Date.now() >= deadline) {
      throw storeError(
        'REFERENCE_TRANSPARENCY_LOCK_TIMEOUT',
        ownerAlive
          ? 'timed out waiting for an active transparency state lock'
          : 'timed out waiting to recover the transparency state lock',
        {
          details: validLockOwner(inspected.owner)
            ? { pid: inspected.owner.pid }
            : undefined,
        },
      )
    }
    nextInspectionAt = Math.min(
      deadline,
      Date.now() + Math.max(50, limits.lockPollMs * 8),
    )
    await sleep(Math.min(limits.lockPollMs, Math.max(1, deadline - Date.now())))
  }
}

async function releaseLock(lock) {
  const inspected = await inspectLock(lock.path)
  if (
    inspected.observed === null
    || !inspected.observed.equals(lock.content)
  ) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_LOCK_CHANGED',
      'transparency state lock changed while held',
    )
  }
  const releasePath = `${lock.path}.release-${process.pid}-${lock.owner.nonce}`
  await renameLockDirectory(lock.path, releasePath)
  await removeRenamedLock(releasePath, inspected)
}

async function withLock(store, operation) {
  const lock = await acquireLock(store.directory, store.limits)
  let result
  let operationError
  try {
    result = await operation()
  } catch (error) {
    operationError = error
  }
  try {
    await releaseLock(lock)
  } catch (releaseError) {
    if (operationError) {
      throw new AggregateError(
        [operationError, releaseError],
        'transparency state operation failed and its lock could not be released safely',
      )
    }
    throw releaseError
  }
  if (operationError) throw operationError
  return result
}

function largestPowerOfTwoBelow(size) {
  let power = 1
  while (power * 2 < size) power *= 2
  return power
}

function merkleRootRange(leaves, start, size, cache) {
  const key = `${start}:${size}`
  const cached = cache.get(key)
  if (cached !== undefined) return cached
  let root
  if (size === 0) {
    root = EMPTY_ROOT
  } else if (size === 1) {
    root = leaves[start]
  } else {
    const split = largestPowerOfTwoBelow(size)
    root = transparencyNodeHash(
      merkleRootRange(leaves, start, split, cache),
      merkleRootRange(leaves, start + split, size - split, cache),
    )
  }
  cache.set(key, root)
  return root
}

export function referenceTransparencyMerkleRoot(leaves) {
  if (!Array.isArray(leaves) || leaves.some((leaf) => !DIGEST.test(leaf ?? ''))) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_LEAVES_INVALID',
      'Merkle leaves must be lowercase SHA-256 digests',
    )
  }
  return merkleRootRange(leaves, 0, leaves.length, new Map())
}

function enforceTrustedCheckpoint(store, state) {
  const trusted = store._trustedCheckpoint
  if (trusted === null) return
  const checkpoint = trusted.document.checkpoint
  if (state.leaves.length < checkpoint.tree_size) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_EXTERNAL_CHECKPOINT_ROLLBACK',
      'local transparency state is older than the externally trusted checkpoint',
      {
        details: {
          trusted_tree_size: checkpoint.tree_size,
          local_tree_size: state.leaves.length,
        },
      },
    )
  }
  const historicalRoot = merkleRootRange(
    state.leaves,
    0,
    checkpoint.tree_size,
    new Map(),
  )
  if (historicalRoot !== checkpoint.root_hash) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_EXTERNAL_CHECKPOINT_FORK',
      'local transparency state does not extend the externally trusted checkpoint',
      {
        details: {
          trusted_tree_size: checkpoint.tree_size,
          trusted_root_hash: checkpoint.root_hash,
          local_root_hash: historicalRoot,
        },
      },
    )
  }
}

function inclusionPathRange(leaves, start, size, relativeIndex, cache) {
  if (size === 1) return []
  const split = largestPowerOfTwoBelow(size)
  if (relativeIndex < split) {
    return [
      ...inclusionPathRange(leaves, start, split, relativeIndex, cache),
      merkleRootRange(leaves, start + split, size - split, cache),
    ]
  }
  return [
    ...inclusionPathRange(
      leaves,
      start + split,
      size - split,
      relativeIndex - split,
      cache,
    ),
    merkleRootRange(leaves, start, split, cache),
  ]
}

export function referenceTransparencyInclusionPath(leaves, leafIndex) {
  if (!Array.isArray(leaves) || leaves.some((leaf) => !DIGEST.test(leaf ?? ''))) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_LEAVES_INVALID',
      'Merkle leaves must be lowercase SHA-256 digests',
    )
  }
  if (
    leaves.length === 0
    || !Number.isSafeInteger(leafIndex)
    || leafIndex < 0
    || leafIndex >= leaves.length
  ) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_LEAF_INDEX_INVALID',
      'leafIndex must identify one leaf in the Merkle tree',
    )
  }
  return inclusionPathRange(
    leaves,
    0,
    leaves.length,
    leafIndex,
    new Map(),
  )
}

function consistencyPathRange(
  leaves,
  start,
  firstSize,
  secondSize,
  complete,
  cache,
) {
  if (firstSize === secondSize) {
    return complete
      ? []
      : [merkleRootRange(leaves, start, secondSize, cache)]
  }
  const split = largestPowerOfTwoBelow(secondSize)
  if (firstSize <= split) {
    return [
      ...consistencyPathRange(
        leaves,
        start,
        firstSize,
        split,
        complete,
        cache,
      ),
      merkleRootRange(
        leaves,
        start + split,
        secondSize - split,
        cache,
      ),
    ]
  }
  return [
    ...consistencyPathRange(
      leaves,
      start + split,
      firstSize - split,
      secondSize - split,
      false,
      cache,
    ),
    merkleRootRange(leaves, start, split, cache),
  ]
}

/**
 * Returns the unique minimal RFC 6962 / RFC 9162 consistency path proving
 * that the first tree is a prefix of the second tree. Hashing is shared with
 * the public transparency contract; callers receive no mutable store state.
 */
export function referenceTransparencyConsistencyPath(
  leaves,
  firstSize,
  secondSize,
) {
  if (!Array.isArray(leaves) || leaves.some((leaf) => !DIGEST.test(leaf ?? ''))) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_LEAVES_INVALID',
      'Merkle leaves must be lowercase SHA-256 digests',
    )
  }
  if (
    !Number.isSafeInteger(firstSize)
    || !Number.isSafeInteger(secondSize)
    || firstSize < 1
    || secondSize < firstSize
    || secondSize > leaves.length
  ) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_CONSISTENCY_RANGE_INVALID',
      'consistency sizes must identify ordered, non-empty committed tree prefixes',
    )
  }
  if (firstSize === secondSize) return []
  return consistencyPathRange(
    leaves,
    0,
    firstSize,
    secondSize,
    true,
    new Map(),
  )
}

function stateIndexName(index, kind) {
  return `${String(index).padStart(16, '0')}.${kind}.json`
}

function assertExactKeys(document, keys, label) {
  if (
    document === null
    || typeof document !== 'object'
    || Array.isArray(document)
    || Object.keys(document).sort().join('\0') !== [...keys].sort().join('\0')
  ) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_STATE_INVALID',
      `${label} has an invalid field set`,
    )
  }
}

function assertIdentityFields(document, store, label) {
  if (
    document.origin !== store.origin
    || document.signing?.algorithm !== SIGNING_ALGORITHM
    || document.signing?.key_id !== store.keyId
  ) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_IDENTITY_DRIFT',
      `${label} does not match the configured transparency log origin and signing key`,
    )
  }
}

function validateMetadata(document, store) {
  assertExactKeys(document, [
    'schema_version',
    'kind',
    'origin',
    'signing',
    'created_at',
    'genesis_nonce',
    'signature',
  ], 'transparency state metadata')
  if (
    document.schema_version !== STATE_SCHEMA_VERSION
    || document.kind !== STATE_KIND
    || !/^[a-f0-9]{32}$/.test(document.genesis_nonce ?? '')
  ) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_STATE_INVALID',
      'transparency state metadata has invalid fixed fields',
    )
  }
  canonicalTimestamp(document.created_at, 'metadata created_at')
  assertIdentityFields(document, store, 'transparency state metadata')
  assertSignedDocument(
    METADATA_CONTEXT,
    document,
    store._key.publicKey,
    'transparency state metadata',
  )
}

function validateEntry(document, store, index, previousEntrySha256) {
  assertExactKeys(document, [
    'schema_version',
    'kind',
    'index',
    'origin',
    'signing',
    'previous_entry_sha256',
    'accepted_at',
    'request',
    'leaf_hash',
    'content_bytes',
    'signature',
  ], `entry ${index}`)
  if (
    document.schema_version !== STATE_SCHEMA_VERSION
    || document.kind !== ENTRY_KIND
    || document.index !== index
    || document.previous_entry_sha256 !== previousEntrySha256
    || !DIGEST.test(document.leaf_hash ?? '')
    || !Number.isSafeInteger(document.content_bytes)
    || document.content_bytes < 1
  ) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_STATE_INVALID',
      `entry ${index} has invalid fixed or chain fields`,
    )
  }
  canonicalTimestamp(document.accepted_at, `entry ${index} accepted_at`)
  assertIdentityFields(document, store, `entry ${index}`)
  assertSignedDocument(
    ENTRY_CONTEXT,
    document,
    store._key.publicKey,
    `entry ${index}`,
  )
  try {
    assertValidTransparencyPublishRequest(document.request)
  } catch (error) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_STATE_REQUEST_INVALID',
      `entry ${index} contains an invalid publication request`,
      { cause: error },
    )
  }
  const content = Buffer.from(document.request.entry.content_base64, 'base64')
  if (
    document.content_bytes !== content.length
    || document.leaf_hash !== transparencyLeafHash(content)
  ) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_STATE_ENTRY_MISMATCH',
      `entry ${index} does not bind its exact request content`,
    )
  }
  return content
}

function validateCheckpoint(
  document,
  store,
  index,
  entrySha256,
  previousCheckpointSha256,
  expectedRoot,
) {
  assertExactKeys(document, [
    'schema_version',
    'kind',
    'origin',
    'signing',
    'tree_size',
    'root_hash',
    'entry_sha256',
    'previous_checkpoint_sha256',
    'committed_at',
    'signature',
  ], `checkpoint ${index + 1}`)
  if (
    document.schema_version !== STATE_SCHEMA_VERSION
    || document.kind !== CHECKPOINT_KIND
    || document.tree_size !== index + 1
    || document.root_hash !== expectedRoot
    || document.entry_sha256 !== entrySha256
    || document.previous_checkpoint_sha256 !== previousCheckpointSha256
  ) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_STATE_ROLLBACK_OR_TAMPERING',
      `checkpoint ${index + 1} does not match the append-only state`,
    )
  }
  canonicalTimestamp(document.committed_at, `checkpoint ${index + 1} committed_at`)
  assertIdentityFields(document, store, `checkpoint ${index + 1}`)
  assertSignedDocument(
    CHECKPOINT_CONTEXT,
    document,
    store._key.publicKey,
    `checkpoint ${index + 1}`,
  )
}

function createCheckpoint(store, {
  index,
  rootHash,
  entrySha256,
  previousCheckpointSha256,
  committedAt,
}) {
  return signDocument(CHECKPOINT_CONTEXT, {
    schema_version: STATE_SCHEMA_VERSION,
    kind: CHECKPOINT_KIND,
    origin: store.origin,
    signing: {
      algorithm: SIGNING_ALGORITHM,
      key_id: store.keyId,
    },
    tree_size: index + 1,
    root_hash: rootHash,
    entry_sha256: entrySha256,
    previous_checkpoint_sha256: previousCheckpointSha256,
    committed_at: committedAt,
  }, store._key.key)
}

async function assertStateDirectory(path, label) {
  const info = await lstat(path)
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_STATE_DIRECTORY_UNSAFE',
      `${label} must be a real non-symlink directory`,
    )
  }
}

async function indexedStateFiles(path, kind, maximum) {
  await assertStateDirectory(path, `${kind} directory`)
  const names = await boundedDirectoryNames(
    path,
    maximum + 16,
    `${kind} directory`,
  )
  const indexed = []
  for (const name of names) {
    const match = INDEX_NAME.exec(name)
    if (match?.[2] === kind) {
      indexed.push({ name, index: Number(match[1]) })
      continue
    }
    throw storeError(
      'REFERENCE_TRANSPARENCY_STATE_UNEXPECTED_FILE',
      `${kind} directory contains unexpected state file ${JSON.stringify(name)}`,
    )
  }
  indexed.sort((left, right) => left.index - right.index)
  indexed.forEach(({ index }, position) => {
    if (index !== position) {
      throw storeError(
        'REFERENCE_TRANSPARENCY_STATE_HOLE',
        `${kind} state has a missing or non-sequential index at ${position}`,
      )
    }
  })
  return indexed
}

function emptyState() {
  return {
    entries: [],
    entryBytes: [],
    leaves: [],
    contentIndex: new Map(),
    totalEntryBytes: 0,
    rootHash: EMPTY_ROOT,
    lastEntrySha256: null,
    lastCheckpointSha256: null,
    lastCommittedAt: null,
  }
}

async function loadState(store, { recover = true } = {}) {
  const entryDirectory = join(store.directory, ENTRY_DIRECTORY)
  const checkpointDirectory = join(store.directory, CHECKPOINT_DIRECTORY)
  await reconcileStateTemporaries(
    entryDirectory,
    'entry',
    store.limits.maxEntries,
  )
  await reconcileStateTemporaries(
    checkpointDirectory,
    'checkpoint',
    store.limits.maxEntries,
  )
  const entryFiles = await indexedStateFiles(
    entryDirectory,
    'entry',
    store.limits.maxEntries,
  )
  const checkpointFiles = await indexedStateFiles(
    checkpointDirectory,
    'checkpoint',
    store.limits.maxEntries,
  )
  if (entryFiles.length > store.limits.maxEntries) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_STATE_ENTRY_LIMIT',
      'persisted transparency state exceeds maxEntries',
    )
  }
  if (
    checkpointFiles.length > entryFiles.length
    || entryFiles.length - checkpointFiles.length > 1
  ) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_STATE_ROLLBACK_OR_TAMPERING',
      'transparency state has an impossible entry/checkpoint sequence',
    )
  }

  const state = emptyState()
  const rootCache = new Map()
  for (const { index, name } of entryFiles) {
    const maximumRecordBytes = store.limits.maxRequestBytes + 64 * 1024
    const loaded = await readCanonicalDocument(
      join(entryDirectory, name),
      maximumRecordBytes,
      `entry ${index}`,
    )
    const content = validateEntry(
      loaded.document,
      store,
      index,
      state.lastEntrySha256,
    )
    if (content.length > store.limits.maxEntryBytes) {
      throw storeError(
        'REFERENCE_TRANSPARENCY_STATE_ENTRY_BYTES_LIMIT',
        `persisted entry ${index} exceeds maxEntryBytes`,
      )
    }
    state.totalEntryBytes += content.length
    if (state.totalEntryBytes > store.limits.maxTotalEntryBytes) {
      throw storeError(
        'REFERENCE_TRANSPARENCY_STATE_TOTAL_BYTES_LIMIT',
        'persisted transparency entries exceed maxTotalEntryBytes',
      )
    }
    const contentDigest = loaded.document.request.entry.content_sha256
    if (state.contentIndex.has(contentDigest)) {
      throw storeError(
        'REFERENCE_TRANSPARENCY_STATE_DUPLICATE_ENTRY',
        `persisted state contains duplicate content digest ${contentDigest}`,
      )
    }
    state.contentIndex.set(contentDigest, index)
    state.entries.push(loaded.document)
    state.entryBytes.push(loaded.bytes)
    state.leaves.push(loaded.document.leaf_hash)
    state.lastEntrySha256 = sha256(loaded.bytes)

    if (index < checkpointFiles.length) {
      const checkpointLoaded = await readCanonicalDocument(
        join(checkpointDirectory, checkpointFiles[index].name),
        16 * 1024,
        `checkpoint ${index + 1}`,
      )
      const expectedRoot = merkleRootRange(
        state.leaves,
        0,
        state.leaves.length,
        rootCache,
      )
      validateCheckpoint(
        checkpointLoaded.document,
        store,
        index,
        state.lastEntrySha256,
        state.lastCheckpointSha256,
        expectedRoot,
      )
      const committedAt = canonicalTimestamp(
        checkpointLoaded.document.committed_at,
        `checkpoint ${index + 1} committed_at`,
      )
      if (state.lastCommittedAt !== null && committedAt < state.lastCommittedAt) {
        throw storeError(
          'REFERENCE_TRANSPARENCY_STATE_CLOCK_ROLLBACK',
          `checkpoint ${index + 1} moves committed_at backward`,
        )
      }
      state.lastCommittedAt = committedAt
      state.lastCheckpointSha256 = sha256(checkpointLoaded.bytes)
    }
  }

  state.rootHash = referenceTransparencyMerkleRoot(state.leaves)
  if (entryFiles.length === checkpointFiles.length + 1) {
    if (!recover) {
      throw storeError(
        'REFERENCE_TRANSPARENCY_STATE_RECOVERY_REQUIRED',
        'transparency state contains one durable uncheckpointed entry',
      )
    }
    const index = entryFiles.length - 1
    const entry = state.entries[index]
    const checkpoint = createCheckpoint(store, {
      index,
      rootHash: state.rootHash,
      entrySha256: state.lastEntrySha256,
      previousCheckpointSha256: state.lastCheckpointSha256,
      committedAt: entry.accepted_at,
    })
    const checkpointBytes = await createCanonicalFile(
      join(checkpointDirectory, stateIndexName(index, 'checkpoint')),
      checkpoint,
    )
    state.lastCheckpointSha256 = sha256(checkpointBytes)
    state.lastCommittedAt = Date.parse(checkpoint.committed_at)
  }
  enforceTrustedCheckpoint(store, state)
  return state
}

function snapshotFrom(store, state) {
  return {
    schema_version: STATE_SCHEMA_VERSION,
    kind: STATE_KIND,
    state_directory: store.directory,
    origin: store.origin,
    signing: {
      algorithm: SIGNING_ALGORITHM,
      key_id: store.keyId,
    },
    tree_size: state.leaves.length,
    root_hash: state.rootHash,
    total_entry_bytes: state.totalEntryBytes,
    last_entry_sha256: state.lastEntrySha256,
    last_checkpoint_sha256: state.lastCheckpointSha256,
    ...(store._trustedCheckpoint === null
      ? {}
      : {
          external_checkpoint: {
            status: 'EXTENDS_EXTERNAL_CHECKPOINT',
            checkpoint_sha256: store._trustedCheckpoint.sha256,
            tree_size: store._trustedCheckpoint.document.checkpoint.tree_size,
            root_hash: store._trustedCheckpoint.document.checkpoint.root_hash,
          },
        }),
  }
}

function parseRequest(request, limits) {
  let canonical
  try {
    assertValidTransparencyPublishRequest(request)
    canonical = canonicalBytes(request)
  } catch (error) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_REQUEST_INVALID',
      'reference transparency log received an invalid publication request',
      { cause: error },
    )
  }
  if (canonical.length > limits.maxRequestBytes) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_REQUEST_BYTES_LIMIT',
      'transparency publication request exceeds maxRequestBytes',
    )
  }
  const content = Buffer.from(request.entry.content_base64, 'base64')
  if (content.length > limits.maxEntryBytes) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_ENTRY_BYTES_LIMIT',
      'transparency publication content exceeds maxEntryBytes',
    )
  }
  let attestation
  try {
    attestation = JSON.parse(content.toString('utf8'))
  } catch (error) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_REQUEST_INVALID',
      'transparency publication content is not JSON',
      { cause: error },
    )
  }
  return {
    request: structuredClone(request),
    canonical,
    content,
    attestation,
    contentDigest: request.entry.content_sha256,
    leafHash: transparencyLeafHash(content),
  }
}

function requestFromAppendInput(input) {
  if (
    input !== null
    && typeof input === 'object'
    && input.request !== undefined
  ) {
    return { request: input.request, context: input }
  }
  return { request: input, context: {} }
}

function assertAppendHints(context, prepared) {
  if (
    context.content !== undefined
    && !Buffer.from(context.content).equals(prepared.content)
  ) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_APPEND_HINT_MISMATCH',
      'append content does not match the exact validated request bytes',
    )
  }
  if (
    context.leafHash !== undefined
    && context.leafHash !== prepared.leafHash
  ) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_APPEND_HINT_MISMATCH',
      'append leafHash does not match the exact validated request bytes',
    )
  }
  if (
    context.attestation !== undefined
    && !canonicalAttestationBytes(context.attestation).equals(prepared.content)
  ) {
    throw storeError(
      'REFERENCE_TRANSPARENCY_APPEND_HINT_MISMATCH',
      'append attestation does not match the exact validated request bytes',
    )
  }
}

export class ReferenceTransparencyLogStore {
  constructor(options = {}) {
    const directory = options.directory ?? options.stateDirectory
    const privateKeyBytes = options.privateKeyBytes ?? options.signingKeyBytes
    if (typeof directory !== 'string' || directory.length === 0) {
      throw storeError(
        'REFERENCE_TRANSPARENCY_STATE_PATH_INVALID',
        'reference transparency log requires an explicit state directory',
      )
    }
    if (!isAbsolute(directory)) {
      throw storeError(
        'REFERENCE_TRANSPARENCY_STATE_PATH_INVALID',
        'reference transparency log state directory must be absolute',
      )
    }
    if (
      typeof options.origin !== 'string'
      || options.origin.length < 3
      || options.origin.length > 256
      || !ORIGIN.test(options.origin)
    ) {
      throw storeError(
        'REFERENCE_TRANSPARENCY_ORIGIN_INVALID',
        'reference transparency log origin is invalid',
      )
    }
    if (privateKeyBytes === undefined) {
      throw storeError(
        'REFERENCE_TRANSPARENCY_SIGNING_KEY_REQUIRED',
        'reference transparency log requires an external Ed25519 private key',
      )
    }
    this.directory = resolve(directory)
    this.origin = options.origin
    this.limits = normalizeLimits(options.limits)
    this._privateKeyBytes = privateKeyBytes
    this._key = parseTransparencyPrivateKey(privateKeyBytes)
    this.keyId = this._key.keyId
    this.publicKeyBytes = Buffer.from(
      this._key.publicKey.export({ type: 'spki', format: 'pem' }),
      'utf8',
    )
    this._clock = options.now ?? (() => new Date())
    this._trustedCheckpoint = parseTrustedCheckpoint(options)
    if (this._trustedCheckpoint !== null) {
      try {
        verifyTransparencySignedCheckpoint({
          signedCheckpoint: this._trustedCheckpoint.document,
          publicKeyBytes: this.publicKeyBytes,
          expectedOrigin: this.origin,
          now: normalizeInstant(this._clock, 'trusted checkpoint clock'),
          maxClockSkewMs: 300_000,
        })
      } catch (error) {
        throw storeError(
          'REFERENCE_TRANSPARENCY_TRUSTED_CHECKPOINT_INVALID',
          `trusted checkpoint verification failed: ${error.message}`,
          { cause: error },
        )
      }
    }
    this._faultInjector = options.faultInjector
    if (
      this._faultInjector !== undefined
      && typeof this._faultInjector !== 'function'
    ) {
      throw storeError(
        'REFERENCE_TRANSPARENCY_FAULT_INJECTOR_INVALID',
        'faultInjector must be a function when supplied',
      )
    }
    this._auditBundleDirectory = options.auditBundleDirectory
    this._state = emptyState()
    this._closed = false
    this._initialized = false
  }

  static async open(options) {
    const store = new ReferenceTransparencyLogStore(options)
    await store._initialize()
    return store
  }

  async _initialize() {
    await assertNoLinkedAncestor(this.directory)
    await mkdir(this.directory, { recursive: true, mode: 0o700 })
    await assertStateDirectory(this.directory, 'requested transparency state directory')
    const realDirectory = await realpath(this.directory)
    if (comparablePath(this.directory) !== comparablePath(realDirectory)) {
      throw storeError(
        'REFERENCE_TRANSPARENCY_STATE_PATH_ALIAS',
        'transparency state path cannot traverse a symlink or junction ancestor',
      )
    }
    this.directory = realDirectory
    await assertStateDirectory(this.directory, 'transparency state directory')
    await assertOutsideAuditBundle(
      this.directory,
      this._auditBundleDirectory,
    )
    await mkdir(join(this.directory, ENTRY_DIRECTORY), {
      recursive: false,
      mode: 0o700,
    }).catch((error) => {
      if (error.code !== 'EEXIST') throw error
    })
    await mkdir(join(this.directory, CHECKPOINT_DIRECTORY), {
      recursive: false,
      mode: 0o700,
    }).catch((error) => {
      if (error.code !== 'EEXIST') throw error
    })
    await assertStateDirectory(
      join(this.directory, ENTRY_DIRECTORY),
      'entry directory',
    )
    await assertStateDirectory(
      join(this.directory, CHECKPOINT_DIRECTORY),
      'checkpoint directory',
    )

    await withLock(this, async () => {
      const metadataPath = join(this.directory, METADATA_FILE)
      await reconcileNamedAtomicTemporary(
        this.directory,
        METADATA_FILE,
        METADATA_TEMPORARY_NAME,
        'transparency state metadata',
      )
      await reconcileStateTemporaries(
        join(this.directory, ENTRY_DIRECTORY),
        'entry',
        this.limits.maxEntries,
      )
      await reconcileStateTemporaries(
        join(this.directory, CHECKPOINT_DIRECTORY),
        'checkpoint',
        this.limits.maxEntries,
      )
      if (!(await pathExists(metadataPath))) {
        const entries = await boundedDirectoryNames(
          join(this.directory, ENTRY_DIRECTORY),
          this.limits.maxEntries + 16,
          'entry directory',
        )
        const checkpoints = await boundedDirectoryNames(
          join(this.directory, CHECKPOINT_DIRECTORY),
          this.limits.maxEntries + 16,
          'checkpoint directory',
        )
        if (entries.length !== 0 || checkpoints.length !== 0) {
          throw storeError(
            'REFERENCE_TRANSPARENCY_METADATA_MISSING',
            'non-empty transparency state is missing its signed metadata',
          )
        }
        const metadata = signDocument(METADATA_CONTEXT, {
          schema_version: STATE_SCHEMA_VERSION,
          kind: STATE_KIND,
          origin: this.origin,
          signing: {
            algorithm: SIGNING_ALGORITHM,
            key_id: this.keyId,
          },
          created_at: normalizeInstant(
            this._clock,
            'metadata clock',
          ).toISOString(),
          genesis_nonce: randomBytes(16).toString('hex'),
        }, this._key.key)
        await createCanonicalFile(metadataPath, metadata)
        await syncDirectory(this.directory)
      }
      const metadata = await readCanonicalDocument(
        metadataPath,
        16 * 1024,
        'transparency state metadata',
      )
      validateMetadata(metadata.document, this)
      this._state = await loadState(this, { recover: true })
    })
    this._initialized = true
  }

  _assertOpen() {
    if (!this._initialized || this._closed) {
      throw storeError(
        'REFERENCE_TRANSPARENCY_STORE_CLOSED',
        'reference transparency log store is not open',
      )
    }
  }

  async _inject(phase, details) {
    if (this._faultInjector !== undefined) {
      await this._faultInjector(phase, Object.freeze({ ...details }))
    }
  }

  async append(input, options = {}) {
    this._assertOpen()
    const { request, context } = requestFromAppendInput(input)
    const prepared = parseRequest(request, this.limits)
    assertAppendHints(context, prepared)
    const instant = normalizeInstant(
      options.issuedAt
        ?? options.now
        ?? context.issuedAt
        ?? context.now
        ?? this._clock,
      'append clock',
    )

    return withLock(this, async () => {
      const state = await loadState(this, { recover: true })
      if (
        state.lastCommittedAt !== null
        && instant.getTime() < state.lastCommittedAt
      ) {
        throw storeError(
          'REFERENCE_TRANSPARENCY_CLOCK_ROLLBACK',
          'append clock cannot move backward from the latest durable checkpoint',
        )
      }
      const duplicateIndex = state.contentIndex.get(prepared.contentDigest)
      if (duplicateIndex !== undefined) {
        const persisted = state.entries[duplicateIndex]
        if (
          persisted.request.entry.content_base64
            !== prepared.request.entry.content_base64
        ) {
          throw storeError(
            'REFERENCE_TRANSPARENCY_DIGEST_COLLISION',
            'a persisted content digest maps to different exact bytes',
          )
        }
        this._state = state
        return {
          leafIndex: duplicateIndex,
          treeSize: state.leaves.length,
          inclusionPath: referenceTransparencyInclusionPath(
            state.leaves,
            duplicateIndex,
          ),
          rootHash: state.rootHash,
          duplicate: true,
          attestation: prepared.attestation,
        }
      }
      if (state.leaves.length >= this.limits.maxEntries) {
        throw storeError(
          'REFERENCE_TRANSPARENCY_ENTRY_LIMIT',
          'transparency log has reached maxEntries',
        )
      }
      if (
        state.totalEntryBytes + prepared.content.length
          > this.limits.maxTotalEntryBytes
      ) {
        throw storeError(
          'REFERENCE_TRANSPARENCY_TOTAL_BYTES_LIMIT',
          'transparency log has reached maxTotalEntryBytes',
        )
      }
      const index = state.leaves.length
      const entry = signDocument(ENTRY_CONTEXT, {
        schema_version: STATE_SCHEMA_VERSION,
        kind: ENTRY_KIND,
        index,
        origin: this.origin,
        signing: {
          algorithm: SIGNING_ALGORITHM,
          key_id: this.keyId,
        },
        previous_entry_sha256: state.lastEntrySha256,
        accepted_at: instant.toISOString(),
        request: prepared.request,
        leaf_hash: prepared.leafHash,
        content_bytes: prepared.content.length,
      }, this._key.key)
      const entryBytes = await createCanonicalFile(
        join(
          this.directory,
          ENTRY_DIRECTORY,
          stateIndexName(index, 'entry'),
        ),
        entry,
      )
      await this._inject('after-entry-durable', {
        index,
        treeSize: index + 1,
      })

      const leaves = [...state.leaves, prepared.leafHash]
      const rootHash = referenceTransparencyMerkleRoot(leaves)
      const entrySha256 = sha256(entryBytes)
      const checkpoint = createCheckpoint(this, {
        index,
        rootHash,
        entrySha256,
        previousCheckpointSha256: state.lastCheckpointSha256,
        committedAt: instant.toISOString(),
      })
      const checkpointBytes = await createCanonicalFile(
        join(
          this.directory,
          CHECKPOINT_DIRECTORY,
          stateIndexName(index, 'checkpoint'),
        ),
        checkpoint,
      )
      await this._inject('after-checkpoint-durable', {
        index,
        treeSize: index + 1,
        rootHash,
      })

      state.entries.push(entry)
      state.entryBytes.push(entryBytes)
      state.leaves.push(prepared.leafHash)
      state.contentIndex.set(prepared.contentDigest, index)
      state.totalEntryBytes += prepared.content.length
      state.rootHash = rootHash
      state.lastEntrySha256 = entrySha256
      state.lastCheckpointSha256 = sha256(checkpointBytes)
      state.lastCommittedAt = instant.getTime()
      this._state = state
      return {
        leafIndex: index,
        treeSize: leaves.length,
        inclusionPath: referenceTransparencyInclusionPath(leaves, index),
        rootHash,
        duplicate: false,
        attestation: prepared.attestation,
      }
    })
  }

  async publish(request, context = {}) {
    this._assertOpen()
    const issuedAt = normalizeInstant(
      context.issuedAt ?? context.now ?? this._clock,
      'checkpoint clock',
    )
    const result = await this.append({
      request,
      now: issuedAt,
    })
    const receipt = createTransparencyInclusionReceipt({
      attestation: result.attestation,
      leafIndex: result.leafIndex,
      treeSize: result.treeSize,
      inclusionPath: result.inclusionPath,
      rootHash: result.rootHash,
      origin: this.origin,
      privateKeyBytes: this._privateKeyBytes,
      issuedAt,
    })
    return {
      receipt,
      created: !result.duplicate,
      idempotent: result.duplicate,
    }
  }

  async consistencyProof({
    firstSize,
    secondSize,
    firstRootHash,
    secondRootHash,
  } = {}) {
    this._assertOpen()
    return withLock(this, async () => {
      const state = await loadState(this, { recover: true })
      const targetSize = secondSize ?? state.leaves.length
      if (
        !Number.isSafeInteger(firstSize)
        || !Number.isSafeInteger(targetSize)
        || firstSize < 1
        || targetSize < firstSize
        || targetSize > state.leaves.length
      ) {
        throw storeError(
          'REFERENCE_TRANSPARENCY_CONSISTENCY_RANGE_INVALID',
          'consistency sizes must identify ordered committed tree prefixes',
        )
      }
      const cache = new Map()
      const exactFirstRoot = merkleRootRange(
        state.leaves,
        0,
        firstSize,
        cache,
      )
      const exactSecondRoot = merkleRootRange(
        state.leaves,
        0,
        targetSize,
        cache,
      )
      if (
        (firstRootHash !== undefined && firstRootHash !== exactFirstRoot)
        || (secondRootHash !== undefined && secondRootHash !== exactSecondRoot)
      ) {
        throw storeError(
          'REFERENCE_TRANSPARENCY_CHECKPOINT_NOT_FOUND',
          'a requested signed checkpoint does not match the exact committed historical tree',
        )
      }
      const consistencyPath = referenceTransparencyConsistencyPath(
        state.leaves,
        firstSize,
        targetSize,
      )
      this._state = state
      return Object.freeze({
        first: Object.freeze({
          tree_size: firstSize,
          root_hash: exactFirstRoot,
        }),
        second: Object.freeze({
          tree_size: targetSize,
          root_hash: exactSecondRoot,
        }),
        consistency_path: Object.freeze([...consistencyPath]),
      })
    })
  }

  async proveConsistency(request, context = {}) {
    this._assertOpen()
    assertValidTransparencyConsistencyRequest(request)
    const issuedAt = normalizeInstant(
      context.issuedAt ?? context.now ?? this._clock,
      'consistency checkpoint clock',
    )
    const historical = await this.consistencyProof({
      firstSize: request.first_tree_size,
      secondSize: request.second_tree_size,
    })
    const firstCheckpoint = createTransparencySignedCheckpoint({
      treeSize: historical.first.tree_size,
      rootHash: historical.first.root_hash,
      origin: this.origin,
      privateKeyBytes: this._privateKeyBytes,
      issuedAt,
    })
    const secondCheckpoint = createTransparencySignedCheckpoint({
      treeSize: historical.second.tree_size,
      rootHash: historical.second.root_hash,
      origin: this.origin,
      privateKeyBytes: this._privateKeyBytes,
      issuedAt,
    })
    const proof = createTransparencyConsistencyProof({
      firstCheckpoint,
      secondCheckpoint,
      consistencyPath: historical.consistency_path,
    })
    verifyTransparencyConsistencyProof({
      proof,
      publicKeyBytes: this.publicKeyBytes,
      expectedOrigin: this.origin,
      now: issuedAt,
    })
    return proof
  }

  snapshot() {
    this._assertOpen()
    return structuredClone(snapshotFrom(this, this._state))
  }

  async refresh() {
    this._assertOpen()
    return withLock(this, async () => {
      this._state = await loadState(this, { recover: true })
      return this.snapshot()
    })
  }

  async close() {
    this._closed = true
  }
}

export async function openReferenceTransparencyLogStore(options) {
  return ReferenceTransparencyLogStore.open(options)
}
