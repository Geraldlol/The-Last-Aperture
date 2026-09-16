import { constants as fsConstants, readFileSync } from 'node:fs'
import { createHash, randomBytes } from 'node:crypto'
import {
  link,
  lstat,
  mkdir,
  open,
  opendir,
  readFile,
  realpath,
  rename,
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
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'

import {
  assertValidTransparencyConsistencyProof,
  assertValidTransparencySignedCheckpoint,
  verifyTransparencyConsistencyProof,
  verifyTransparencySignedCheckpoint,
} from './transparency-log-contracts.mjs'
import { stableJson } from './run-engine.mjs'

const RECORD_SCHEMA_URL = new URL(
  '../../schemas/transparency-checkpoint-journal-record.schema.json',
  import.meta.url,
)
const SIGNED_CHECKPOINT_SCHEMA_URL = new URL(
  '../../schemas/transparency-signed-checkpoint.schema.json',
  import.meta.url,
)
const CONSISTENCY_PROOF_SCHEMA_URL = new URL(
  '../../schemas/transparency-consistency-proof.schema.json',
  import.meta.url,
)
const RECORD_SCHEMA_VERSION = '1.0.0'
const RECORD_KIND = 'red-team-audit/transparency-checkpoint-journal-record'
const LOCK_KIND = 'red-team-audit/transparency-checkpoint-journal-lock-owner'
const RECORD_NAME = /^(\d{16})\.checkpoint-journal\.json$/
const TEMPORARY_NAME = /^\.(\d{16})\.checkpoint-journal\.json\.tmp-\d+-[a-f0-9]{24}$/
const LOCK_DIRECTORY = '.checkpoint-journal.lock'
const LOCK_OWNER_FILE = 'owner.json'
const OPEN_READ_ONLY_NO_FOLLOW = fsConstants.O_RDONLY
  | (typeof fsConstants.O_NOFOLLOW === 'number' ? fsConstants.O_NOFOLLOW : 0)

function loadJson(url) {
  return JSON.parse(readFileSync(fileURLToPath(url), 'utf8'))
}

export const transparencyCheckpointJournalRecordSchema = loadJson(
  RECORD_SCHEMA_URL,
)
const transparencySignedCheckpointSchema = loadJson(
  SIGNED_CHECKPOINT_SCHEMA_URL,
)
const transparencyConsistencyProofSchema = loadJson(
  CONSISTENCY_PROOF_SCHEMA_URL,
)

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})
for (const schema of [
  transparencySignedCheckpointSchema,
  transparencyConsistencyProofSchema,
  transparencyCheckpointJournalRecordSchema,
]) {
  ajv.addSchema(schema)
}
const validateRecordSchema = ajv.getSchema(
  transparencyCheckpointJournalRecordSchema.$id,
)

export const DEFAULT_TRANSPARENCY_CHECKPOINT_JOURNAL_LIMITS = Object.freeze({
  maxRecords: 1_000_000,
  maxRecordBytes: 512 * 1024,
  maxTotalBytes: 1024 * 1024 * 1024,
  lockTimeoutMs: 10_000,
  staleLockMs: 30_000,
  lockPollMs: 10,
})

export class TransparencyCheckpointJournalError extends Error {
  constructor(code, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'TransparencyCheckpointJournalError'
    this.code = code
    if (options.details !== undefined) this.details = options.details
  }
}

function journalError(code, message, options) {
  return new TransparencyCheckpointJournalError(code, message, options)
}

function normalizeAjvErrors(errors = []) {
  return errors.map((error) => ({
    keyword: error.keyword,
    code: `SCHEMA_${String(error.keyword).toUpperCase()}`,
    instancePath: error.instancePath || '/',
    message: error.message ?? 'schema validation failed',
    params: error.params,
  }))
}

export function validateTransparencyCheckpointJournalRecord(value) {
  const valid = validateRecordSchema(value)
  return {
    valid: Boolean(valid),
    errors: valid ? [] : normalizeAjvErrors(validateRecordSchema.errors),
  }
}

export function assertValidTransparencyCheckpointJournalRecord(value) {
  const validation = validateTransparencyCheckpointJournalRecord(value)
  if (!validation.valid) {
    throw journalError(
      'TRANSPARENCY_CHECKPOINT_JOURNAL_RECORD_INVALID',
      'transparency checkpoint journal record validation failed',
      { details: validation.errors },
    )
  }
  return value
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function canonicalBytes(value) {
  return Buffer.from(stableJson(value, 0), 'utf8')
}

function canonicalEqual(left, right) {
  return canonicalBytes(left).equals(canonicalBytes(right))
}

function sameCheckpointHead(left, right) {
  return left?.checkpoint?.origin === right?.checkpoint?.origin
    && left?.checkpoint?.tree_size === right?.checkpoint?.tree_size
    && left?.checkpoint?.root_hash === right?.checkpoint?.root_hash
    && left?.checkpoint?.signing?.algorithm
      === right?.checkpoint?.signing?.algorithm
    && left?.checkpoint?.signing?.key_id
      === right?.checkpoint?.signing?.key_id
}

function integerLimit(value, fallback, name, minimum, maximum) {
  const selected = value ?? fallback
  if (
    !Number.isSafeInteger(selected)
    || selected < minimum
    || selected > maximum
  ) {
    throw journalError(
      'TRANSPARENCY_CHECKPOINT_JOURNAL_LIMIT_INVALID',
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
    throw journalError(
      'TRANSPARENCY_CHECKPOINT_JOURNAL_LIMIT_INVALID',
      'checkpoint journal limits must be an object',
    )
  }
  return Object.freeze({
    maxRecords: integerLimit(
      limitValue(limits, 'maxRecords', 'max_records'),
      DEFAULT_TRANSPARENCY_CHECKPOINT_JOURNAL_LIMITS.maxRecords,
      'maxRecords',
      1,
      10_000_000,
    ),
    maxRecordBytes: integerLimit(
      limitValue(limits, 'maxRecordBytes', 'max_record_bytes'),
      DEFAULT_TRANSPARENCY_CHECKPOINT_JOURNAL_LIMITS.maxRecordBytes,
      'maxRecordBytes',
      4096,
      16 * 1024 * 1024,
    ),
    maxTotalBytes: integerLimit(
      limitValue(limits, 'maxTotalBytes', 'max_total_bytes'),
      DEFAULT_TRANSPARENCY_CHECKPOINT_JOURNAL_LIMITS.maxTotalBytes,
      'maxTotalBytes',
      4096,
      1024 * 1024 * 1024 * 1024,
    ),
    lockTimeoutMs: integerLimit(
      limitValue(limits, 'lockTimeoutMs', 'lock_timeout_ms'),
      DEFAULT_TRANSPARENCY_CHECKPOINT_JOURNAL_LIMITS.lockTimeoutMs,
      'lockTimeoutMs',
      1,
      300_000,
    ),
    staleLockMs: integerLimit(
      limitValue(limits, 'staleLockMs', 'stale_lock_ms'),
      DEFAULT_TRANSPARENCY_CHECKPOINT_JOURNAL_LIMITS.staleLockMs,
      'staleLockMs',
      1,
      24 * 60 * 60 * 1000,
    ),
    lockPollMs: integerLimit(
      limitValue(limits, 'lockPollMs', 'lock_poll_ms'),
      DEFAULT_TRANSPARENCY_CHECKPOINT_JOURNAL_LIMITS.lockPollMs,
      'lockPollMs',
      1,
      1000,
    ),
  })
}

function comparablePath(path) {
  const normalized = resolve(path)
  return process.platform === 'win32' ? normalized.toLowerCase() : normalized
}

function isWithin(parent, child) {
  const path = relative(resolve(parent), resolve(child))
  return path === '' || (!path.startsWith('..') && !isAbsolute(path))
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
    throw journalError(
      'TRANSPARENCY_CHECKPOINT_JOURNAL_PATH_ALIAS',
      'checkpoint journal path cannot traverse a symlink or junction ancestor',
    )
  }
  const canonical = await realpath(candidate)
  if (comparablePath(candidate) !== comparablePath(canonical)) {
    throw journalError(
      'TRANSPARENCY_CHECKPOINT_JOURNAL_PATH_ALIAS',
      'checkpoint journal path cannot traverse a symlink or junction ancestor',
    )
  }
}

function configuredExclusions(options) {
  if (
    options.excludedDirectories !== undefined
    && !Array.isArray(options.excludedDirectories)
  ) {
    throw journalError(
      'TRANSPARENCY_CHECKPOINT_JOURNAL_EXCLUSION_INVALID',
      'excludedDirectories must be an array when supplied',
    )
  }
  const candidates = [
    options.targetDirectory,
    options.auditBundleDirectory,
    options.logStateDirectory,
    ...(options.excludedDirectories ?? []),
  ].filter((value) => value !== undefined)
  return candidates.map((value, index) => {
    if (typeof value !== 'string' || !isAbsolute(value)) {
      throw journalError(
        'TRANSPARENCY_CHECKPOINT_JOURNAL_EXCLUSION_INVALID',
        `excluded checkpoint-journal path ${index + 1} must be absolute`,
      )
    }
    return resolve(value)
  })
}

function assertExternalPlacement(directory, exclusions) {
  for (const exclusion of exclusions) {
    if (isWithin(exclusion, directory) || isWithin(directory, exclusion)) {
      throw journalError(
        'TRANSPARENCY_CHECKPOINT_JOURNAL_NOT_EXTERNAL',
        'checkpoint journal must be separate from every configured target, bundle, and log-state directory',
      )
    }
  }
}

async function assertRealDirectory(path, label) {
  const info = await lstat(path)
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw journalError(
      'TRANSPARENCY_CHECKPOINT_JOURNAL_DIRECTORY_UNSAFE',
      `${label} must be a real non-symlink directory`,
    )
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

async function boundedDirectoryNames(path, maximum, label) {
  const directory = await opendir(path)
  const names = []
  try {
    for await (const entry of directory) {
      names.push(entry.name)
      if (names.length > maximum) {
        throw journalError(
          'TRANSPARENCY_CHECKPOINT_JOURNAL_DIRECTORY_LIMIT',
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

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino
}

function assertRegularFile(info, label, allowedLinkCounts = [1]) {
  if (
    !info.isFile()
    || info.isSymbolicLink()
    || (
      typeof info.nlink === 'number'
      && !allowedLinkCounts.includes(info.nlink)
    )
  ) {
    throw journalError(
      'TRANSPARENCY_CHECKPOINT_JOURNAL_FILE_UNSAFE',
      `${label} must be a regular non-symlink file with an expected link count`,
    )
  }
}

async function readBoundedRegularFile(
  path,
  maximumBytes,
  label,
  { allowedLinkCounts = [1] } = {},
) {
  const pathInfo = await lstat(path)
  assertRegularFile(pathInfo, label, allowedLinkCounts)
  if (pathInfo.size > maximumBytes) {
    throw journalError(
      'TRANSPARENCY_CHECKPOINT_JOURNAL_FILE_TOO_LARGE',
      `${label} exceeds its ${maximumBytes}-byte limit`,
    )
  }
  const handle = await open(path, OPEN_READ_ONLY_NO_FOLLOW)
  try {
    const before = await handle.stat()
    if (!sameFileIdentity(pathInfo, before)) {
      throw journalError(
        'TRANSPARENCY_CHECKPOINT_JOURNAL_FILE_CHANGED',
        `${label} changed before it was read`,
      )
    }
    const bytes = await handle.readFile()
    const after = await handle.stat()
    if (
      !sameFileIdentity(before, after)
      || before.size !== after.size
      || before.mtimeMs !== after.mtimeMs
      || bytes.length !== after.size
    ) {
      throw journalError(
        'TRANSPARENCY_CHECKPOINT_JOURNAL_FILE_CHANGED',
        `${label} changed while it was being read`,
      )
    }
    return bytes
  } finally {
    await handle.close()
  }
}

async function readCanonicalDocument(path, maximumBytes, label) {
  const bytes = await readBoundedRegularFile(path, maximumBytes, label)
  let document
  try {
    document = JSON.parse(bytes.toString('utf8'))
  } catch (error) {
    throw journalError(
      'TRANSPARENCY_CHECKPOINT_JOURNAL_JSON_INVALID',
      `${label} is not valid JSON`,
      { cause: error },
    )
  }
  if (!canonicalBytes(document).equals(bytes)) {
    throw journalError(
      'TRANSPARENCY_CHECKPOINT_JOURNAL_NONCANONICAL',
      `${label} is not canonical JSON`,
    )
  }
  return { bytes, document }
}

async function reconcileTemporary(directory, targetName, temporaryName) {
  const targetPath = join(directory, targetName)
  const temporaryPath = join(directory, temporaryName)
  const temporaryInfo = await lstat(temporaryPath)
  assertRegularFile(temporaryInfo, 'checkpoint journal temporary file', [1, 2])

  let targetInfo
  try {
    targetInfo = await lstat(targetPath)
  } catch (error) {
    if (error.code !== 'ENOENT') throw error
  }
  if (targetInfo === undefined) {
    if (temporaryInfo.nlink !== 1) {
      throw journalError(
        'TRANSPARENCY_CHECKPOINT_JOURNAL_TEMPORARY_AMBIGUOUS',
        'uncommitted checkpoint journal temporary has an unexpected link count',
      )
    }
    await unlink(temporaryPath)
    await syncDirectory(directory)
    return
  }

  assertRegularFile(targetInfo, 'checkpoint journal target file', [2])
  if (
    temporaryInfo.nlink !== 2
    || !sameFileIdentity(temporaryInfo, targetInfo)
  ) {
    throw journalError(
      'TRANSPARENCY_CHECKPOINT_JOURNAL_TEMPORARY_AMBIGUOUS',
      'checkpoint journal target and temporary are not the same two-link inode',
    )
  }
  await unlink(temporaryPath)
  await syncDirectory(directory)
  const reconciled = await lstat(targetPath)
  assertRegularFile(reconciled, 'reconciled checkpoint journal target')
}

async function reconcileTemporaries(journal) {
  const names = await boundedDirectoryNames(
    journal.directory,
    journal.limits.maxRecords + 16,
    'checkpoint journal directory',
  )
  const byTarget = new Map()
  for (const name of names) {
    const match = TEMPORARY_NAME.exec(name)
    if (match === null) continue
    const targetName = `${match[1]}.checkpoint-journal.json`
    if (byTarget.has(targetName)) {
      throw journalError(
        'TRANSPARENCY_CHECKPOINT_JOURNAL_TEMPORARY_AMBIGUOUS',
        `checkpoint journal record ${match[1]} has multiple temporaries`,
      )
    }
    byTarget.set(targetName, name)
  }
  for (const [targetName, temporaryName] of byTarget) {
    await reconcileTemporary(journal.directory, targetName, temporaryName)
  }
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
  let canonicalTime = false
  if (typeof value?.acquired_at === 'string') {
    const milliseconds = Date.parse(value.acquired_at)
    canonicalTime = Number.isFinite(milliseconds)
      && new Date(milliseconds).toISOString() === value.acquired_at
  }
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.keys(value).length === 5
    && value.schema_version === RECORD_SCHEMA_VERSION
    && value.kind === LOCK_KIND
    && Number.isSafeInteger(value.pid)
    && value.pid > 0
    && canonicalTime
    && /^[a-f0-9]{32}$/.test(value.nonce ?? '')
}

async function inspectLock(lockPath) {
  const before = await lstat(lockPath)
  if (!before.isDirectory() || before.isSymbolicLink()) {
    throw journalError(
      'TRANSPARENCY_CHECKPOINT_JOURNAL_LOCK_UNSAFE',
      'checkpoint journal lock must be a real directory',
    )
  }
  const names = await boundedDirectoryNames(lockPath, 1, 'checkpoint journal lock')
  if (names.some((name) => name !== LOCK_OWNER_FILE)) {
    throw journalError(
      'TRANSPARENCY_CHECKPOINT_JOURNAL_LOCK_UNSAFE',
      'checkpoint journal lock contains an unexpected file',
    )
  }
  let owner = null
  let ownerBytes = null
  if (names.includes(LOCK_OWNER_FILE)) {
    ownerBytes = await readBoundedRegularFile(
      join(lockPath, LOCK_OWNER_FILE),
      4096,
      'checkpoint journal lock owner',
    )
    try {
      owner = JSON.parse(ownerBytes.toString('utf8'))
    } catch {
      owner = null
    }
    if (
      owner !== null
      && !canonicalBytes(owner).equals(ownerBytes)
    ) {
      owner = null
    }
  }
  const after = await lstat(lockPath)
  if (
    !sameFileIdentity(before, after)
    || before.mtimeMs !== after.mtimeMs
  ) {
    throw journalError(
      'TRANSPARENCY_CHECKPOINT_JOURNAL_LOCK_CHANGED',
      'checkpoint journal lock changed during inspection',
    )
  }
  const acquiredAt = validLockOwner(owner)
    ? Date.parse(owner.acquired_at)
    : Number.NaN
  return {
    info: before,
    owner,
    ownerBytes,
    missingOwner: ownerBytes === null,
    ageReference: Number.isFinite(acquiredAt) ? acquiredAt : before.mtimeMs,
  }
}

function sameLockObservation(left, right) {
  return sameFileIdentity(left.info, right.info)
    && left.info.mtimeMs === right.info.mtimeMs
    && (
      left.ownerBytes === null
        ? right.ownerBytes === null
        : right.ownerBytes !== null && left.ownerBytes.equals(right.ownerBytes)
    )
}

async function removeEmptyDirectory(path) {
  const deadline = Date.now() + 2000
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

async function removeInspectedLock(path, inspected) {
  const current = await inspectLock(path)
  if (
    !sameFileIdentity(current.info, inspected.info)
    || current.info.mtimeMs !== inspected.info.mtimeMs
    || (
      current.ownerBytes === null
        ? inspected.ownerBytes !== null
        : inspected.ownerBytes === null
          || !current.ownerBytes.equals(inspected.ownerBytes)
    )
  ) {
    throw journalError(
      'TRANSPARENCY_CHECKPOINT_JOURNAL_LOCK_CHANGED',
      'checkpoint journal lock changed during recovery',
    )
  }
  if (current.ownerBytes !== null) {
    await unlink(join(path, LOCK_OWNER_FILE))
    await syncDirectory(path)
  }
  await removeEmptyDirectory(path)
  await syncDirectory(dirname(path))
}

async function recoverStaleLock(lockPath, inspected) {
  const quarantine = `${lockPath}.stale-${process.pid}-${randomBytes(12).toString('hex')}`
  try {
    await rename(lockPath, quarantine)
  } catch (error) {
    if (['ENOENT', 'EEXIST'].includes(error.code)) return false
    throw error
  }
  try {
    await removeInspectedLock(quarantine, inspected)
  } catch (error) {
    try {
      await rename(quarantine, lockPath)
    } catch (restoreError) {
      throw new AggregateError(
        [error, restoreError],
        'stale checkpoint journal lock changed and could not be restored',
      )
    }
    throw error
  }
  return true
}

async function createLockOwner(lockPath, owner) {
  const bytes = canonicalBytes(owner)
  const ownerPath = join(lockPath, LOCK_OWNER_FILE)
  const handle = await open(ownerPath, 'wx', 0o600)
  try {
    await handle.writeFile(bytes)
    await handle.sync()
  } finally {
    await handle.close()
  }
  await syncDirectory(lockPath)
  return bytes
}

async function acquireLock(journal) {
  const lockPath = join(journal.directory, LOCK_DIRECTORY)
  const deadline = Date.now() + journal.limits.lockTimeoutMs
  let incompleteOwner = null
  for (;;) {
    try {
      await mkdir(lockPath, { recursive: false, mode: 0o700 })
      const owner = {
        schema_version: RECORD_SCHEMA_VERSION,
        kind: LOCK_KIND,
        pid: process.pid,
        acquired_at: new Date().toISOString(),
        nonce: randomBytes(16).toString('hex'),
      }
      const ownerBytes = await createLockOwner(lockPath, owner)
      await syncDirectory(journal.directory)
      return { path: lockPath, owner, ownerBytes }
    } catch (error) {
      if (error.code !== 'EEXIST') throw error
    }

    let inspected
    try {
      inspected = await inspectLock(lockPath)
    } catch (error) {
      if (
        error.code === 'ENOENT'
        || error.code === 'TRANSPARENCY_CHECKPOINT_JOURNAL_LOCK_CHANGED'
        || error.code === 'TRANSPARENCY_CHECKPOINT_JOURNAL_FILE_CHANGED'
      ) {
        incompleteOwner = null
        if (Date.now() >= deadline) {
          throw journalError(
            'TRANSPARENCY_CHECKPOINT_JOURNAL_LOCK_TIMEOUT',
            'timed out waiting for a complete checkpoint journal lock owner record',
            { cause: error },
          )
        }
        await sleep(Math.min(
          journal.limits.lockPollMs,
          Math.max(1, deadline - Date.now()),
        ))
        continue
      }
      throw error
    }
    if (inspected.ownerBytes !== null && !validLockOwner(inspected.owner)) {
      const unchanged = incompleteOwner !== null
        && sameLockObservation(incompleteOwner, inspected)
      incompleteOwner = inspected
      await journal._inject('after-incomplete-lock-owner-observed', { unchanged })
      if (Date.now() >= deadline) {
        throw journalError(
          unchanged
            ? 'TRANSPARENCY_CHECKPOINT_JOURNAL_LOCK_UNSAFE'
            : 'TRANSPARENCY_CHECKPOINT_JOURNAL_LOCK_TIMEOUT',
          unchanged
            ? 'checkpoint journal lock owner is malformed and cannot be stolen'
            : 'timed out waiting for a complete checkpoint journal lock owner record',
        )
      }
      await sleep(Math.min(
        journal.limits.lockPollMs,
        Math.max(1, deadline - Date.now()),
      ))
      continue
    }
    incompleteOwner = null
    const age = Date.now() - inspected.ageReference
    const ownerAlive = inspected.missingOwner
      ? false
      : processIsAlive(inspected.owner.pid)
    if (age >= journal.limits.staleLockMs && !ownerAlive) {
      if (await recoverStaleLock(lockPath, inspected)) continue
    }
    if (Date.now() >= deadline) {
      throw journalError(
        'TRANSPARENCY_CHECKPOINT_JOURNAL_LOCK_TIMEOUT',
        ownerAlive
          ? 'timed out waiting for an active checkpoint journal lock'
          : 'timed out waiting to recover the checkpoint journal lock',
      )
    }
    await sleep(Math.min(
      journal.limits.lockPollMs,
      Math.max(1, deadline - Date.now()),
    ))
  }
}

async function releaseLock(lock) {
  const inspected = await inspectLock(lock.path)
  if (
    inspected.ownerBytes === null
    || !inspected.ownerBytes.equals(lock.ownerBytes)
  ) {
    throw journalError(
      'TRANSPARENCY_CHECKPOINT_JOURNAL_LOCK_CHANGED',
      'checkpoint journal lock changed while held',
    )
  }
  await unlink(join(lock.path, LOCK_OWNER_FILE))
  await syncDirectory(lock.path)
  await removeEmptyDirectory(lock.path)
  await syncDirectory(dirname(lock.path))
}

async function withLock(journal, operation) {
  const lock = await acquireLock(journal)
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
        'checkpoint journal operation failed and its lock could not be released safely',
      )
    }
    throw releaseError
  }
  if (operationError) throw operationError
  return result
}

function recordName(sequence) {
  return `${String(sequence).padStart(16, '0')}.checkpoint-journal.json`
}

async function indexedRecordFiles(journal) {
  const names = await boundedDirectoryNames(
    journal.directory,
    journal.limits.maxRecords + 16,
    'checkpoint journal directory',
  )
  const records = []
  for (const name of names) {
    if (name === LOCK_DIRECTORY) continue
    const match = RECORD_NAME.exec(name)
    if (match !== null) {
      records.push({ name, sequence: Number(match[1]) })
      continue
    }
    throw journalError(
      'TRANSPARENCY_CHECKPOINT_JOURNAL_UNEXPECTED_FILE',
      `checkpoint journal contains unexpected entry ${JSON.stringify(name)}`,
    )
  }
  records.sort((left, right) => left.sequence - right.sequence)
  if (records.length > journal.limits.maxRecords) {
    throw journalError(
      'TRANSPARENCY_CHECKPOINT_JOURNAL_RECORD_LIMIT',
      'checkpoint journal exceeds its record limit',
    )
  }
  records.forEach(({ sequence }, position) => {
    if (sequence !== position) {
      throw journalError(
        'TRANSPARENCY_CHECKPOINT_JOURNAL_HOLE',
        `checkpoint journal has a missing or non-sequential record at ${position}`,
      )
    }
  })
  return records
}

function verificationOptions(journal) {
  return {
    publicKeyBytes: journal._publicKeyBytes,
    expectedOrigin: journal.expectedOrigin,
    now: journal._clock(),
    maxClockSkewMs: journal.maxClockSkewMs,
  }
}

function verifyCheckpoint(journal, checkpoint, label) {
  try {
    assertValidTransparencySignedCheckpoint(checkpoint)
    return verifyTransparencySignedCheckpoint({
      signedCheckpoint: checkpoint,
      ...verificationOptions(journal),
    })
  } catch (error) {
    throw journalError(
      'TRANSPARENCY_CHECKPOINT_JOURNAL_CHECKPOINT_INVALID',
      `${label} is not a valid checkpoint under the pinned log identity: ${error.message}`,
      { cause: error },
    )
  }
}

function verifyConsistency(journal, proof, label) {
  try {
    assertValidTransparencyConsistencyProof(proof)
    return verifyTransparencyConsistencyProof({
      proof,
      ...verificationOptions(journal),
    })
  } catch (error) {
    throw journalError(
      'TRANSPARENCY_CHECKPOINT_JOURNAL_CONSISTENCY_INVALID',
      `${label} is not a valid consistency proof under the pinned log identity: ${error.message}`,
      { cause: error },
    )
  }
}

function emptyState() {
  return {
    records: [],
    recordBytes: [],
    recordDigests: [],
    totalBytes: 0,
    head: null,
    headRecordSha256: null,
  }
}

async function loadState(journal, { reconcile = true } = {}) {
  if (reconcile) await reconcileTemporaries(journal)
  const files = await indexedRecordFiles(journal)
  const state = emptyState()
  for (const { name, sequence } of files) {
    const loaded = await readCanonicalDocument(
      join(journal.directory, name),
      journal.limits.maxRecordBytes,
      `checkpoint journal record ${sequence}`,
    )
    state.totalBytes += loaded.bytes.length
    if (state.totalBytes > journal.limits.maxTotalBytes) {
      throw journalError(
        'TRANSPARENCY_CHECKPOINT_JOURNAL_TOTAL_BYTES_LIMIT',
        'checkpoint journal exceeds its cumulative byte limit',
      )
    }
    const record = assertValidTransparencyCheckpointJournalRecord(
      loaded.document,
    )
    if (record.sequence !== sequence) {
      throw journalError(
        'TRANSPARENCY_CHECKPOINT_JOURNAL_SEQUENCE_MISMATCH',
        `checkpoint journal filename and record sequence differ at ${sequence}`,
      )
    }
    if (record.previous_record_sha256 !== state.headRecordSha256) {
      throw journalError(
        'TRANSPARENCY_CHECKPOINT_JOURNAL_CHAIN_INVALID',
        `checkpoint journal record ${sequence} does not bind its predecessor`,
      )
    }
    verifyCheckpoint(journal, record.checkpoint, `journal record ${sequence}`)
    if (sequence === 0) {
      if (record.consistency_proof !== null) {
        throw journalError(
          'TRANSPARENCY_CHECKPOINT_JOURNAL_GENESIS_INVALID',
          'checkpoint journal baseline cannot contain a consistency proof',
        )
      }
    } else {
      if (
        !sameCheckpointHead(
          record.consistency_proof.first_checkpoint,
          state.head.checkpoint,
        )
        || !sameCheckpointHead(
          record.consistency_proof.second_checkpoint,
          record.checkpoint,
        )
      ) {
        throw journalError(
          'TRANSPARENCY_CHECKPOINT_JOURNAL_PROOF_BINDING_INVALID',
          `checkpoint journal record ${sequence} proof does not bind its adjacent checkpoints`,
        )
      }
      verifyConsistency(
        journal,
        record.consistency_proof,
        `journal record ${sequence}`,
      )
    }
    const digest = sha256(loaded.bytes)
    state.records.push(record)
    state.recordBytes.push(loaded.bytes)
    state.recordDigests.push(digest)
    state.head = record
    state.headRecordSha256 = digest
  }
  return state
}

function snapshotFrom(journal, state) {
  return {
    directory: journal.directory,
    expected_origin: journal.expectedOrigin,
    record_count: state.records.length,
    total_record_bytes: state.totalBytes,
    head_record_sha256: state.headRecordSha256,
    head: state.head === null ? null : structuredClone(state.head.checkpoint),
  }
}

async function installRecord(journal, targetName, bytes, sequence) {
  const temporaryName = `.${targetName}.tmp-${process.pid}-${randomBytes(12).toString('hex')}`
  const temporaryPath = join(journal.directory, temporaryName)
  const targetPath = join(journal.directory, targetName)
  let handle
  try {
    handle = await open(temporaryPath, 'wx', 0o600)
    await handle.writeFile(bytes)
    await handle.sync()
    await handle.close()
    handle = undefined
  } catch (error) {
    await handle?.close().catch(() => {})
    try {
      const info = await lstat(temporaryPath)
      if (info.isFile() && !info.isSymbolicLink() && info.nlink === 1) {
        await unlink(temporaryPath)
      }
    } catch (cleanupError) {
      if (cleanupError.code !== 'ENOENT') {
        throw new AggregateError(
          [error, cleanupError],
          'checkpoint journal temporary write failed and could not be cleaned safely',
        )
      }
    }
    throw error
  }

  await journal._inject('after-temporary-durable', { sequence, targetName })
  await link(temporaryPath, targetPath)
  await journal._inject('after-record-linked', { sequence, targetName })
  await syncDirectory(journal.directory)
  await journal._inject('after-record-durable', { sequence, targetName })
  await unlink(temporaryPath)
  await syncDirectory(journal.directory)
  await journal._inject('after-temporary-removed', { sequence, targetName })
}

function cloneInput(value, label) {
  try {
    return structuredClone(value)
  } catch (error) {
    throw journalError(
      'TRANSPARENCY_CHECKPOINT_JOURNAL_INPUT_INVALID',
      `${label} must be structured-cloneable`,
      { cause: error },
    )
  }
}

export class TransparencyCheckpointJournal {
  constructor(options = {}) {
    if (typeof options.directory !== 'string' || !isAbsolute(options.directory)) {
      throw journalError(
        'TRANSPARENCY_CHECKPOINT_JOURNAL_PATH_INVALID',
        'checkpoint journal directory must be an absolute path',
      )
    }
    if (
      typeof options.expectedOrigin !== 'string'
      || options.expectedOrigin.length === 0
    ) {
      throw journalError(
        'TRANSPARENCY_CHECKPOINT_JOURNAL_ORIGIN_REQUIRED',
        'checkpoint journal requires an expected log origin',
      )
    }
    if (
      options.publicKeyBytes === undefined
      || options.publicKeyBytes === null
    ) {
      throw journalError(
        'TRANSPARENCY_CHECKPOINT_JOURNAL_PUBLIC_KEY_REQUIRED',
        'checkpoint journal requires an externally pinned log public key',
      )
    }
    this.directory = resolve(options.directory)
    this.expectedOrigin = options.expectedOrigin
    this._publicKeyBytes = Buffer.from(options.publicKeyBytes)
    this.limits = normalizeLimits(options.limits)
    this.maxClockSkewMs = integerLimit(
      options.maxClockSkewMs,
      0,
      'maxClockSkewMs',
      0,
      300_000,
    )
    this._clock = options.now ?? (() => new Date())
    if (typeof this._clock !== 'function') {
      throw journalError(
        'TRANSPARENCY_CHECKPOINT_JOURNAL_CLOCK_INVALID',
        'checkpoint journal now option must be a function',
      )
    }
    this._faultInjector = options.faultInjector
    if (
      this._faultInjector !== undefined
      && typeof this._faultInjector !== 'function'
    ) {
      throw journalError(
        'TRANSPARENCY_CHECKPOINT_JOURNAL_FAULT_INJECTOR_INVALID',
        'checkpoint journal faultInjector must be a function',
      )
    }
    this._exclusions = configuredExclusions(options)
    this.readOnly = options.readOnly === true
    this._state = emptyState()
    this._initialized = false
    this._closed = false
  }

  static async open(options) {
    const journal = new TransparencyCheckpointJournal(options)
    await journal._initialize()
    return journal
  }

  async _initialize() {
    await assertNoLinkedAncestor(this.directory)
    assertExternalPlacement(this.directory, this._exclusions)
    if (this.readOnly) {
      try {
        await realpath(this.directory)
      } catch (error) {
        throw journalError(
          'TRANSPARENCY_CHECKPOINT_JOURNAL_NOT_FOUND',
          `read-only checkpoint journal does not exist: ${error.message}`,
          { cause: error },
        )
      }
    } else {
      await mkdir(this.directory, { recursive: true, mode: 0o700 })
    }
    await assertRealDirectory(this.directory, 'checkpoint journal directory')
    const canonical = await realpath(this.directory)
    if (comparablePath(this.directory) !== comparablePath(canonical)) {
      throw journalError(
        'TRANSPARENCY_CHECKPOINT_JOURNAL_PATH_ALIAS',
        'checkpoint journal directory cannot be a symlink or junction alias',
      )
    }
    this.directory = canonical
    assertExternalPlacement(this.directory, this._exclusions)
    this._state = this.readOnly
      ? await loadState(this, { reconcile: false })
      : await withLock(this, () => loadState(this))
    this._initialized = true
  }

  _assertOpen() {
    if (!this._initialized || this._closed) {
      throw journalError(
        'TRANSPARENCY_CHECKPOINT_JOURNAL_CLOSED',
        'checkpoint journal is not open',
      )
    }
  }

  async _inject(phase, details) {
    if (this._faultInjector !== undefined) {
      await this._faultInjector(phase, Object.freeze({ ...details }))
    }
  }

  snapshot() {
    this._assertOpen()
    return structuredClone(snapshotFrom(this, this._state))
  }

  async load() {
    this._assertOpen()
    if (this.readOnly) {
      this._state = await loadState(this, { reconcile: false })
      return this.snapshot()
    }
    return withLock(this, async () => {
      this._state = await loadState(this)
      return this.snapshot()
    })
  }

  async advance({
    expectedHead = null,
    checkpoint,
    consistencyProof = null,
  } = {}) {
    this._assertOpen()
    if (this.readOnly) {
      throw journalError(
        'TRANSPARENCY_CHECKPOINT_JOURNAL_READ_ONLY',
        'read-only checkpoint journal cannot be advanced',
      )
    }
    const proposedCheckpoint = cloneInput(checkpoint, 'checkpoint')
    const proposedExpectedHead = expectedHead === null
      ? null
      : cloneInput(expectedHead, 'expectedHead')
    const proposedProof = consistencyProof === null
      ? null
      : cloneInput(consistencyProof, 'consistencyProof')

    verifyCheckpoint(this, proposedCheckpoint, 'proposed checkpoint')
    if (proposedExpectedHead !== null) {
      verifyCheckpoint(this, proposedExpectedHead, 'expected journal head')
    }
    if (proposedProof !== null) {
      verifyConsistency(this, proposedProof, 'proposed consistency proof')
    }

    return withLock(this, async () => {
      const state = await loadState(this)
      if (
        state.head !== null
        && sameCheckpointHead(state.head.checkpoint, proposedCheckpoint)
      ) {
        this._state = state
        return {
          created: false,
          idempotent: true,
          sequence: state.head.sequence,
          record_sha256: state.headRecordSha256,
          record: structuredClone(state.head),
        }
      }

      if (state.head === null) {
        if (proposedExpectedHead !== null || proposedProof !== null) {
          throw journalError(
            'TRANSPARENCY_CHECKPOINT_JOURNAL_GENESIS_INVALID',
            'an empty checkpoint journal requires null expectedHead and null consistencyProof',
          )
        }
      } else {
        const currentSize = state.head.checkpoint.checkpoint.tree_size
        const proposedSize = proposedCheckpoint.checkpoint.tree_size
        if (proposedSize < currentSize) {
          throw journalError(
            'TRANSPARENCY_CHECKPOINT_JOURNAL_ROLLBACK',
            'checkpoint journal cannot move to a smaller tree',
          )
        }
        if (proposedSize === currentSize) {
          throw journalError(
            'TRANSPARENCY_CHECKPOINT_JOURNAL_FORK',
            'checkpoint journal received a different root at its current tree size',
          )
        }
        if (
          proposedExpectedHead === null
          || !canonicalEqual(proposedExpectedHead, state.head.checkpoint)
        ) {
          throw journalError(
            'TRANSPARENCY_CHECKPOINT_JOURNAL_CAS_CONFLICT',
            'checkpoint journal head differs from the expected head',
          )
        }
        if (proposedProof === null) {
          throw journalError(
            'TRANSPARENCY_CHECKPOINT_JOURNAL_PROOF_REQUIRED',
            'checkpoint journal advancement requires a consistency proof',
          )
        }
        if (
          !sameCheckpointHead(
            proposedProof.first_checkpoint,
            state.head.checkpoint,
          )
          || !sameCheckpointHead(
            proposedProof.second_checkpoint,
            proposedCheckpoint,
          )
        ) {
          throw journalError(
            'TRANSPARENCY_CHECKPOINT_JOURNAL_PROOF_BINDING_INVALID',
            'consistency proof does not bind the expected and proposed checkpoints',
          )
        }
      }

      if (state.records.length >= this.limits.maxRecords) {
        throw journalError(
          'TRANSPARENCY_CHECKPOINT_JOURNAL_RECORD_LIMIT',
          'checkpoint journal has reached its record limit',
        )
      }
      const sequence = state.records.length
      const record = assertValidTransparencyCheckpointJournalRecord({
        schema_version: RECORD_SCHEMA_VERSION,
        kind: RECORD_KIND,
        sequence,
        previous_record_sha256: state.headRecordSha256,
        checkpoint: proposedCheckpoint,
        consistency_proof: proposedProof,
      })
      const bytes = canonicalBytes(record)
      if (bytes.length > this.limits.maxRecordBytes) {
        throw journalError(
          'TRANSPARENCY_CHECKPOINT_JOURNAL_RECORD_BYTES_LIMIT',
          'checkpoint journal record exceeds its byte limit',
        )
      }
      if (state.totalBytes + bytes.length > this.limits.maxTotalBytes) {
        throw journalError(
          'TRANSPARENCY_CHECKPOINT_JOURNAL_TOTAL_BYTES_LIMIT',
          'checkpoint journal advancement exceeds its cumulative byte limit',
        )
      }
      const targetName = recordName(sequence)
      await installRecord(this, targetName, bytes, sequence)
      this._state = await loadState(this)
      return {
        created: true,
        idempotent: false,
        sequence,
        record_sha256: this._state.headRecordSha256,
        record: structuredClone(this._state.head),
      }
    })
  }

  async continuityForCheckpoint(checkpoint) {
    this._assertOpen()
    const suppliedCheckpoint = cloneInput(checkpoint, 'checkpoint')
    const verification = verifyCheckpoint(
      this,
      suppliedCheckpoint,
      'checkpoint continuity query',
    )
    const inspect = async () => {
      const state = await loadState(this, {
        reconcile: !this.readOnly,
      })
      const suppliedSize = suppliedCheckpoint.checkpoint.tree_size
      const sameSize = state.records.find(
        (record) => record.checkpoint.checkpoint.tree_size === suppliedSize,
      )
      if (sameSize === undefined) {
        throw journalError(
          'TRANSPARENCY_CHECKPOINT_JOURNAL_CHECKPOINT_ABSENT',
          'signed checkpoint is not an exact checkpoint retained by the journal',
        )
      }
      if (!sameCheckpointHead(sameSize.checkpoint, suppliedCheckpoint)) {
        throw journalError(
          'TRANSPARENCY_CHECKPOINT_JOURNAL_FORK',
          'signed checkpoint conflicts with the journal root at the same tree size',
        )
      }
      const sequence = sameSize.sequence
      const recordSha256 = state.recordDigests[sequence]
      const baselineSize = state.records[0].checkpoint.checkpoint.tree_size
      this._state = state
      if (sequence === 0) {
        return {
          status: 'NOT_VERIFIED',
          claim: 'CHECKPOINT_BASELINE_ONLY',
          consistency: 'NOT_VERIFIED',
          log_key_id: verification.log_key_id,
          origin: verification.origin,
          baseline_tree_size: baselineSize,
          current_tree_size: suppliedSize,
          record_sequence: sequence,
          record_sha256: recordSha256,
          witness_quorum: 'NOT_VERIFIED',
          trusted_time: false,
        }
      }
      return {
        status: 'VERIFIED',
        claim: 'CONSISTENT_WITH_EXTERNALLY_RETAINED_CHECKPOINT',
        consistency: 'CONSISTENT_WITH_EXTERNALLY_RETAINED_CHECKPOINT',
        log_key_id: verification.log_key_id,
        origin: verification.origin,
        baseline_tree_size: baselineSize,
        current_tree_size: suppliedSize,
        record_sequence: sequence,
        record_sha256: recordSha256,
        witness_quorum: 'NOT_VERIFIED',
        trusted_time: false,
      }
    }
    return this.readOnly ? inspect() : withLock(this, inspect)
  }

  async close() {
    this._closed = true
  }
}

export async function openTransparencyCheckpointJournal(options) {
  return TransparencyCheckpointJournal.open(options)
}

export async function loadTransparencyCheckpointJournal(options) {
  const journal = await openTransparencyCheckpointJournal(options)
  const snapshot = journal.snapshot()
  await journal.close()
  return snapshot
}
