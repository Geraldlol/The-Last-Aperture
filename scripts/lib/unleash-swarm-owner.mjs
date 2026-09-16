import { randomBytes as systemRandomBytes } from 'node:crypto'
import { constants as fsConstants } from 'node:fs'
import {
  link,
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  unlink,
} from 'node:fs/promises'
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
} from 'node:path'
import { TextDecoder } from 'node:util'

import { compareCanonicalStrings } from './canonical-order.mjs'
import {
  publishFileCreateOnlyDurably,
  syncRecoverableDirectoryChange,
} from './durable-file-publication.mjs'
import { canonicalUnleashCampaignJson } from './unleash-campaign-storage.mjs'
import { digestUnleashValue } from './unleash-contracts.mjs'

const LOCK_DIRECTORY = 'swarm-owner-lock'
const OWNER_FILE = 'owner.json'
const RETIRING_FILE = /^retiring-([1-9][0-9]*)-([a-f0-9]{24})\.json$/u
const OWNER_RESIDUE = /^swarm-owner-(stage|stale|release)-([1-9][0-9]*)-([a-f0-9]{24})$/u
const OWNER_RESIDUE_PREFIX = 'swarm-owner-'
const CAMPAIGN_DIRECTORY = /^campaign-[a-f0-9]{24}$/u
const SHA256 = /^[a-f0-9]{64}$/u
const CAMPAIGN_ID = /^campaign:sha256:[a-f0-9]{64}$/u
const NONCE = /^[a-f0-9]{24}$/u
const OWNER_ID = /^swarm-owner:sha256:[a-f0-9]{64}$/u
const RETIREMENT_ID = /^swarm-retirement:sha256:[a-f0-9]{64}$/u
const MAX_OWNER_BYTES = 4096
const MAX_CAMPAIGN_ENTRIES = 4096
const MAX_OWNER_RESIDUES = 256
const MAX_RETIREMENT_ENTRIES = 4096
const RETIREMENT_ADMISSION_LIMIT = 32
const MAX_TRANSITION_ATTEMPTS = 16
const SUPPORTED_PUBLICATION_PLATFORMS = new Set([
  'aix',
  'darwin',
  'freebsd',
  'linux',
  'openbsd',
  'sunos',
  'win32',
])
const OWNER_FIELDS = [
  'schema_version',
  'kind',
  'campaign_id',
  'plan_sha256',
  'owner_pid',
  'nonce',
  'acquired_at',
  'owner_id',
]
const RETIREMENT_FIELDS = [
  'schema_version',
  'kind',
  'campaign_id',
  'plan_sha256',
  'target_owner_id',
  'target_owner_pid',
  'target_owner_nonce',
  'retirer_pid',
  'nonce',
  'acquired_at',
  'retirement_id',
]
const ACQUIRE_INPUT_FIELDS = ['campaignDirectory', 'campaignId', 'planSha256']
const DEPENDENCY_FIELDS = [
  'directorySyncImpl',
  'faultInjector',
  'now',
  'pid',
  'processIsAlive',
  'publicationPlatform',
  'randomBytes',
  'win32MoveImpl',
]
const READ_ONLY_NO_FOLLOW = fsConstants.O_RDONLY
  | (fsConstants.O_NOFOLLOW ?? 0)
  | (fsConstants.O_NONBLOCK ?? 0)
const WRITE_CREATE_ONLY = fsConstants.O_WRONLY
  | fsConstants.O_CREAT
  | fsConstants.O_EXCL
  | (fsConstants.O_NOFOLLOW ?? 0)
const utf8Decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })
const tokenState = new WeakMap()

export class UnleashSwarmOwnerError extends Error {
  constructor(code, message, { cause } = {}) {
    super(message, cause === undefined ? undefined : { cause })
    this.name = 'UnleashSwarmOwnerError'
    this.code = code
  }
}

function ownerError(code, message, cause) {
  return new UnleashSwarmOwnerError(code, message, { cause })
}

function exactDataRecord(value, fields) {
  let prototype
  let descriptors
  try {
    prototype = Object.getPrototypeOf(value)
    descriptors = Object.getOwnPropertyDescriptors(value)
  } catch {
    return null
  }
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || ![Object.prototype, null].includes(prototype)
  ) return null
  const keys = Reflect.ownKeys(descriptors)
  if (
    keys.length !== fields.length
    || keys.some((key) => typeof key !== 'string'
      || !fields.includes(key)
      || descriptors[key].enumerable !== true
      || !Object.hasOwn(descriptors[key], 'value'))
  ) return null
  return Object.fromEntries(fields.map((field) => [field, descriptors[field].value]))
}

function samePath(left, right) {
  const normalizedLeft = resolve(left)
  const normalizedRight = resolve(right)
  return process.platform === 'win32'
    ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
    : normalizedLeft === normalizedRight
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino
}

function sameFileSnapshot(left, right) {
  return sameFileIdentity(left, right)
    && left.size === right.size
    && left.nlink === right.nlink
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs
}

function sameOwnerSnapshot(left, right) {
  return sameFileSnapshot(left.info, right.info)
    && left.bytes.equals(right.bytes)
    && left.owner.owner_id === right.owner.owner_id
}

function sameRetirementSnapshot(left, right) {
  return sameFileSnapshot(left.info, right.info)
    && left.bytes.equals(right.bytes)
    && left.retirement.retirement_id === right.retirement.retirement_id
}

function samePublishedOwner(left, right) {
  return sameFileIdentity(left.info, right.info)
    && left.info.size === right.info.size
    && left.bytes.equals(right.bytes)
    && left.owner.owner_id === right.owner.owner_id
}

function samePublishedRetirement(left, right) {
  return sameFileIdentity(left.info, right.info)
    && left.info.size === right.info.size
    && left.bytes.equals(right.bytes)
    && left.retirement.retirement_id === right.retirement.retirement_id
}

function processIsAlive(pid) {
  try {
    process.kill(pid, 0)
    return true
  } catch (cause) {
    return cause?.code !== 'ESRCH'
  }
}

function dependencySnapshot(value = {}) {
  const retained = exactDataRecord(value, Object.keys(value))
  if (
    retained === null
    || Object.keys(retained).some((field) => !DEPENDENCY_FIELDS.includes(field))
  ) throw ownerError('UNLEASH_SWARM_OWNER_DEPENDENCIES_INVALID', 'swarm owner dependencies contain unknown or computed data')
  const now = retained.now ?? (() => new Date())
  const pid = retained.pid ?? process.pid
  const randomBytes = retained.randomBytes ?? systemRandomBytes
  const isAlive = retained.processIsAlive ?? processIsAlive
  const publicationPlatform = retained.publicationPlatform ?? process.platform
  const faultInjector = retained.faultInjector
  const directorySyncImpl = retained.directorySyncImpl
  const win32MoveImpl = retained.win32MoveImpl
  if (
    typeof now !== 'function'
    || !Number.isSafeInteger(pid)
    || pid < 1
    || typeof randomBytes !== 'function'
    || typeof isAlive !== 'function'
    || !SUPPORTED_PUBLICATION_PLATFORMS.has(publicationPlatform)
    || !['function', 'undefined'].includes(typeof faultInjector)
    || !['function', 'undefined'].includes(typeof directorySyncImpl)
    || !['function', 'undefined'].includes(typeof win32MoveImpl)
  ) throw ownerError('UNLEASH_SWARM_OWNER_DEPENDENCIES_INVALID', 'swarm owner dependencies are invalid')
  return {
    directorySyncImpl,
    faultInjector,
    now,
    pid,
    processIsAlive: isAlive,
    publicationPlatform,
    randomBytes,
    win32MoveImpl,
  }
}

function sampleNow(now) {
  let sampled
  try {
    sampled = now()
  } catch (cause) {
    throw ownerError('UNLEASH_SWARM_OWNER_CLOCK_INVALID', 'swarm owner clock failed', cause)
  }
  const date = sampled instanceof Date ? new Date(sampled.getTime()) : new Date(sampled)
  if (!Number.isFinite(date.getTime())) {
    throw ownerError('UNLEASH_SWARM_OWNER_CLOCK_INVALID', 'swarm owner clock returned an invalid instant')
  }
  return date.toISOString()
}

function randomNonce(randomBytes) {
  let value
  try {
    value = randomBytes(12)
  } catch (cause) {
    throw ownerError('UNLEASH_SWARM_OWNER_NONCE_INVALID', 'swarm owner nonce source failed', cause)
  }
  if (!Buffer.isBuffer(value) || value.length !== 12) {
    throw ownerError('UNLEASH_SWARM_OWNER_NONCE_INVALID', 'swarm owner nonce source must return exactly 12 bytes')
  }
  return value.toString('hex')
}

function inputSnapshot(value) {
  const retained = exactDataRecord(value, ACQUIRE_INPUT_FIELDS)
  if (
    retained === null
    || typeof retained.campaignDirectory !== 'string'
    || !isAbsolute(retained.campaignDirectory)
    || resolve(retained.campaignDirectory) !== retained.campaignDirectory
    || !CAMPAIGN_DIRECTORY.test(basename(retained.campaignDirectory))
    || !CAMPAIGN_ID.test(retained.campaignId ?? '')
    || !SHA256.test(retained.planSha256 ?? '')
  ) throw ownerError('UNLEASH_SWARM_OWNER_INPUT_INVALID', 'swarm owner identity must bind one canonical campaign directory, campaign, and plan')
  return retained
}

async function canonicalCampaignDirectory(path) {
  let before
  let canonical
  let after
  try {
    before = await lstat(path, { bigint: true })
    canonical = await realpath(path)
    after = await lstat(path, { bigint: true })
  } catch (cause) {
    throw ownerError('UNLEASH_SWARM_OWNER_DIRECTORY_UNSAFE', 'swarm owner campaign directory is unavailable', cause)
  }
  if (
    !before.isDirectory()
    || before.isSymbolicLink()
    || !after.isDirectory()
    || after.isSymbolicLink()
    || !sameFileIdentity(before, after)
    || !samePath(canonical, path)
  ) throw ownerError('UNLEASH_SWARM_OWNER_DIRECTORY_UNSAFE', 'swarm owner campaign directory changed or is an alias')
  return { path: canonical, info: after }
}

function ownerIdentity(owner) {
  return {
    campaign_id: owner.campaign_id,
    plan_sha256: owner.plan_sha256,
    owner_pid: owner.owner_pid,
    nonce: owner.nonce,
    acquired_at: owner.acquired_at,
  }
}

function retirementIdentity(retirement) {
  return {
    campaign_id: retirement.campaign_id,
    plan_sha256: retirement.plan_sha256,
    target_owner_id: retirement.target_owner_id,
    target_owner_pid: retirement.target_owner_pid,
    target_owner_nonce: retirement.target_owner_nonce,
    retirer_pid: retirement.retirer_pid,
    nonce: retirement.nonce,
    acquired_at: retirement.acquired_at,
  }
}

function createOwner(input, dependencies) {
  const unsigned = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-swarm-owner',
    campaign_id: input.campaignId,
    plan_sha256: input.planSha256,
    owner_pid: dependencies.pid,
    nonce: randomNonce(dependencies.randomBytes),
    acquired_at: sampleNow(dependencies.now),
  }
  return Object.freeze({
    ...unsigned,
    owner_id: `swarm-owner:sha256:${digestUnleashValue(ownerIdentity(unsigned))}`,
  })
}

function createRetirement(owner, dependencies) {
  const unsigned = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-swarm-owner-retirement',
    campaign_id: owner.campaign_id,
    plan_sha256: owner.plan_sha256,
    target_owner_id: owner.owner_id,
    target_owner_pid: owner.owner_pid,
    target_owner_nonce: owner.nonce,
    retirer_pid: dependencies.pid,
    nonce: randomNonce(dependencies.randomBytes),
    acquired_at: sampleNow(dependencies.now),
  }
  return Object.freeze({
    ...unsigned,
    retirement_id: `swarm-retirement:sha256:${digestUnleashValue(retirementIdentity(unsigned))}`,
  })
}

function assertOwnerRecord(value, expected = undefined) {
  const owner = exactDataRecord(value, OWNER_FIELDS)
  let canonicalInstant = false
  try {
    canonicalInstant = new Date(owner?.acquired_at).toISOString() === owner?.acquired_at
  } catch {}
  if (
    owner === null
    || owner.schema_version !== '1.0.0'
    || owner.kind !== 'last-aperture/unleash-swarm-owner'
    || !CAMPAIGN_ID.test(owner.campaign_id ?? '')
    || !SHA256.test(owner.plan_sha256 ?? '')
    || !Number.isSafeInteger(owner.owner_pid)
    || owner.owner_pid < 1
    || !NONCE.test(owner.nonce ?? '')
    || !canonicalInstant
    || !OWNER_ID.test(owner.owner_id ?? '')
    || owner.owner_id !== `swarm-owner:sha256:${digestUnleashValue(ownerIdentity(owner))}`
  ) throw ownerError('UNLEASH_SWARM_OWNER_RECORD_UNSAFE', 'swarm owner record is invalid or not self-bound')
  if (
    expected !== undefined
    && (
      owner.campaign_id !== expected.campaignId
      || owner.plan_sha256 !== expected.planSha256
    )
  ) throw ownerError('UNLEASH_SWARM_OWNER_BINDING_MISMATCH', 'swarm owner record belongs to a different campaign or plan')
  return Object.freeze(owner)
}

function assertRetirementRecord(value, expected = undefined) {
  const retirement = exactDataRecord(value, RETIREMENT_FIELDS)
  let canonicalInstant = false
  try {
    canonicalInstant = new Date(retirement?.acquired_at).toISOString() === retirement?.acquired_at
  } catch {}
  if (
    retirement === null
    || retirement.schema_version !== '1.0.0'
    || retirement.kind !== 'last-aperture/unleash-swarm-owner-retirement'
    || !CAMPAIGN_ID.test(retirement.campaign_id ?? '')
    || !SHA256.test(retirement.plan_sha256 ?? '')
    || !OWNER_ID.test(retirement.target_owner_id ?? '')
    || !Number.isSafeInteger(retirement.target_owner_pid)
    || retirement.target_owner_pid < 1
    || !NONCE.test(retirement.target_owner_nonce ?? '')
    || !Number.isSafeInteger(retirement.retirer_pid)
    || retirement.retirer_pid < 1
    || !NONCE.test(retirement.nonce ?? '')
    || !canonicalInstant
    || !RETIREMENT_ID.test(retirement.retirement_id ?? '')
    || retirement.retirement_id !== `swarm-retirement:sha256:${digestUnleashValue(retirementIdentity(retirement))}`
  ) throw ownerError('UNLEASH_SWARM_OWNER_RECORD_UNSAFE', 'swarm owner retirement record is invalid or not self-bound')
  if (
    expected !== undefined
    && (
      retirement.campaign_id !== expected.campaignId
      || retirement.plan_sha256 !== expected.planSha256
    )
  ) throw ownerError('UNLEASH_SWARM_OWNER_BINDING_MISMATCH', 'swarm owner retirement belongs to a different campaign or plan')
  return Object.freeze(retirement)
}

function childPath(parent, name) {
  const path = join(parent, name)
  const fromParent = relative(parent, path)
  if (
    fromParent !== name
    || isAbsolute(fromParent)
    || dirname(path) !== parent
  ) throw ownerError('UNLEASH_SWARM_OWNER_DIRECTORY_UNSAFE', 'swarm owner path escaped its controller-owned directory')
  return path
}

function residueFilename(kind, owner) {
  return `swarm-owner-${kind}-${owner.owner_pid}-${owner.nonce}`
}

function residuePath(campaignDirectory, kind, owner) {
  return childPath(campaignDirectory, residueFilename(kind, owner))
}

function claimTemporaryPath(campaignDirectory, owner) {
  return residuePath(campaignDirectory, 'stage', owner)
}

function retirementTemporaryPath(campaignDirectory, retirement) {
  return childPath(
    campaignDirectory,
    `swarm-owner-release-${retirement.retirer_pid}-${retirement.nonce}`,
  )
}

function retiringFilename(retirement) {
  return `retiring-${retirement.retirer_pid}-${retirement.nonce}.json`
}

async function inspectLockDirectory(lockPath) {
  let before
  let canonical
  let after
  try {
    before = await lstat(lockPath, { bigint: true })
    canonical = await realpath(lockPath)
    after = await lstat(lockPath, { bigint: true })
  } catch (cause) {
    if (cause?.code === 'ENOENT') throw cause
    throw ownerError('UNLEASH_SWARM_OWNER_LOCK_UNSAFE', 'swarm owner lock container is unavailable', cause)
  }
  const effectiveUid = typeof process.getuid === 'function' ? BigInt(process.getuid()) : null
  if (
    !before.isDirectory()
    || before.isSymbolicLink()
    || !after.isDirectory()
    || after.isSymbolicLink()
    || !sameFileIdentity(before, after)
    || !samePath(canonical, lockPath)
    || (effectiveUid !== null && after.uid !== effectiveUid)
    || (process.platform !== 'win32' && (after.mode & 0o077n) !== 0n)
  ) throw ownerError('UNLEASH_SWARM_OWNER_LOCK_UNSAFE', 'swarm owner lock container is not one canonical private directory')
  return { path: lockPath, info: after }
}

async function readCanonicalRecordSnapshot(path, allowedLinks, expected, recordKind) {
  let before
  try {
    before = await lstat(path, { bigint: true })
  } catch (cause) {
    if (cause?.code === 'ENOENT') {
      throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'swarm owner record disappeared during inspection', cause)
    }
    throw ownerError('UNLEASH_SWARM_OWNER_RECORD_UNSAFE', 'swarm owner record cannot be inspected', cause)
  }
  if (
    !before.isFile()
    || before.isSymbolicLink()
    || before.size < 1n
    || before.size > BigInt(MAX_OWNER_BYTES)
    || before.nlink > 2n
  ) throw ownerError('UNLEASH_SWARM_OWNER_RECORD_UNSAFE', 'swarm owner record is not one bounded regular file with a safe link count')
  if (!allowedLinks.includes(before.nlink)) {
    throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'swarm owner record link count changed during inspection')
  }
  let handle
  try {
    handle = await open(path, READ_ONLY_NO_FOLLOW)
    const opened = await handle.stat({ bigint: true })
    if (!opened.isFile() || !allowedLinks.includes(opened.nlink) || !sameFileSnapshot(before, opened)) {
      throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'swarm owner record changed before it could be read')
    }
    const bytes = Buffer.alloc(Number(opened.size))
    let offset = 0
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset)
      if (bytesRead === 0) break
      offset += bytesRead
    }
    const after = await handle.stat({ bigint: true })
    let endpointAfter
    try {
      endpointAfter = await lstat(path, { bigint: true })
    } catch (cause) {
      throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'swarm owner record disappeared while being read', cause)
    }
    if (
      offset !== bytes.length
      || !sameFileSnapshot(opened, after)
      || !sameFileSnapshot(after, endpointAfter)
    ) throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'swarm owner record changed while being read')
    let parsed
    try {
      parsed = JSON.parse(utf8Decoder.decode(bytes))
    } catch (cause) {
      throw ownerError('UNLEASH_SWARM_OWNER_RECORD_UNSAFE', 'swarm owner record is not valid UTF-8 JSON', cause)
    }
    const record = recordKind === 'owner'
      ? assertOwnerRecord(parsed, expected)
      : assertRetirementRecord(parsed, expected)
    if (!bytes.equals(Buffer.from(canonicalUnleashCampaignJson(record), 'utf8'))) {
      throw ownerError('UNLEASH_SWARM_OWNER_RECORD_UNSAFE', 'swarm owner record is not canonical')
    }
    return { path, info: after, record, bytes }
  } catch (cause) {
    if (cause instanceof UnleashSwarmOwnerError) throw cause
    if (cause?.code === 'ENOENT') {
      throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'swarm owner record disappeared during inspection', cause)
    }
    if (
      process.platform === 'win32'
      && ['EACCES', 'EBUSY', 'EPERM'].includes(cause?.code)
    ) throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'swarm owner record was delete-pending during inspection', cause)
    throw ownerError('UNLEASH_SWARM_OWNER_RECORD_UNSAFE', 'swarm owner record could not be read safely', cause)
  } finally {
    await handle?.close()
  }
}

async function readOwnerSnapshot(path, allowedLinks, expected) {
  const snapshot = await readCanonicalRecordSnapshot(path, allowedLinks, expected, 'owner')
  return { ...snapshot, owner: snapshot.record }
}

async function readRetirementSnapshot(path, allowedLinks, expected) {
  const snapshot = await readCanonicalRecordSnapshot(path, allowedLinks, expected, 'retirement')
  return { ...snapshot, retirement: snapshot.record }
}

async function finishLockInspection(lock, state) {
  let after
  try {
    after = await lstat(lock.path, { bigint: true })
  } catch (cause) {
    throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'swarm owner lock container disappeared during inspection', cause)
  }
  if (!sameFileSnapshot(lock.info, after)) {
    throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'swarm owner lock container changed during inspection')
  }
  return Object.freeze({ ...state, lock: { path: lock.path, info: after } })
}

async function inspectLockState(lockPath, expected) {
  const lock = await inspectLockDirectory(lockPath)
  let entries
  try {
    entries = await readdir(lockPath, { withFileTypes: true })
  } catch (cause) {
    throw ownerError('UNLEASH_SWARM_OWNER_LOCK_UNSAFE', 'swarm owner lock container could not be listed', cause)
  }
  if (entries.length === 0) return finishLockInspection(lock, { state: 'EMPTY' })
  if (entries.length > MAX_RETIREMENT_ENTRIES + 1) {
    throw ownerError('UNLEASH_SWARM_OWNER_LOCK_UNSAFE', 'swarm owner lock container has unexpected contents')
  }
  const ownerEntry = entries.find((entry) => entry.name === OWNER_FILE)
  const retirementEntries = entries
    .filter((entry) => RETIRING_FILE.test(entry.name))
    .sort((left, right) => compareCanonicalStrings(left.name, right.name))
  if (
    entries.some((entry) => entry.name !== OWNER_FILE && !RETIRING_FILE.test(entry.name))
    || ownerEntry?.isDirectory()
    || ownerEntry?.isSymbolicLink()
    || retirementEntries.some((entry) => entry.isDirectory() || entry.isSymbolicLink())
  ) throw ownerError('UNLEASH_SWARM_OWNER_LOCK_UNSAFE', 'swarm owner lock container has an unexpected or unsafe child')

  if (ownerEntry !== undefined && retirementEntries.length === 0) {
    const owner = await readOwnerSnapshot(childPath(lockPath, OWNER_FILE), [1n, 2n], expected)
    if (owner.info.nlink === 1n) {
      return finishLockInspection(lock, { state: 'OWNED', owner })
    }
    const claimTemporary = claimTemporaryPath(dirname(lockPath), owner.owner)
    const temporary = await readOwnerSnapshot(claimTemporary, [2n], expected)
    if (!sameOwnerSnapshot(owner, temporary)) {
      throw ownerError('UNLEASH_SWARM_OWNER_RECORD_UNSAFE', 'swarm owner claim has an unexplained hard-link alias')
    }
    return finishLockInspection(lock, {
      state: 'CLAIM_PUBLICATION_TAIL',
      owner,
      temporary,
    })
  }

  if (retirementEntries.length === 0) {
    throw ownerError('UNLEASH_SWARM_OWNER_LOCK_UNSAFE', 'swarm owner lock container is missing its exact owner state')
  }
  const retirements = []
  for (const entry of retirementEntries) {
    const match = entry.name.match(RETIRING_FILE)
    const retiring = await readRetirementSnapshot(
      childPath(lockPath, entry.name),
      [1n, 2n],
      expected,
    )
    if (
      retiring.retirement.retirer_pid !== Number(match[1])
      || retiring.retirement.nonce !== match[2]
    ) throw ownerError('UNLEASH_SWARM_OWNER_RECORD_UNSAFE', 'swarm owner retirement name does not match its exact record')
    let temporary
    if (retiring.info.nlink === 2n) {
      temporary = await readRetirementSnapshot(
        retirementTemporaryPath(dirname(lockPath), retiring.retirement),
        [2n],
        expected,
      )
      if (!sameRetirementSnapshot(retiring, temporary)) {
        throw ownerError('UNLEASH_SWARM_OWNER_RECORD_UNSAFE', 'swarm owner retirement has an unexplained hard-link alias')
      }
    }
    retirements.push({ retiring, temporary })
  }
  if (ownerEntry === undefined) {
    return finishLockInspection(lock, {
      state: 'RETIRING_AFTER_CLAIM',
      retirements,
    })
  }
  const owner = await readOwnerSnapshot(childPath(lockPath, OWNER_FILE), [1n], expected)
  return finishLockInspection(lock, {
    state: 'RETIRING_WITH_CLAIM',
    owner,
    retirements,
  })
}

function sameLockIdentity(left, right) {
  return sameFileIdentity(left.lock.info, right.lock.info)
}

function stateOwner(state) {
  return state.retirements?.[0]?.retiring.retirement ?? state.owner?.owner ?? null
}

function publicOwner(owner) {
  return Object.freeze({
    owner_id: owner.owner_id ?? owner.retirement_id,
    owner_pid: owner.owner_pid ?? owner.retirer_pid,
    acquired_at: owner.acquired_at,
  })
}

function observeOwnerLiveness(owner, dependencies) {
  let alive
  try {
    alive = dependencies.processIsAlive(owner.owner_pid ?? owner.retirer_pid)
  } catch (cause) {
    throw ownerError('UNLEASH_SWARM_OWNER_LIVENESS_UNKNOWN', 'swarm owner process liveness could not be determined', cause)
  }
  if (typeof alive !== 'boolean') {
    throw ownerError('UNLEASH_SWARM_OWNER_LIVENESS_UNKNOWN', 'swarm owner process liveness check returned an invalid result')
  }
  return alive
}

async function ensureLockContainer(campaignDirectory) {
  const lockPath = childPath(campaignDirectory, LOCK_DIRECTORY)
  try {
    await mkdir(lockPath, { recursive: false, mode: 0o700 })
    await syncRecoverableDirectoryChange(campaignDirectory)
  } catch (cause) {
    if (cause?.code !== 'EEXIST') {
      throw ownerError('UNLEASH_SWARM_OWNER_LOCK_UNSAFE', 'swarm owner lock container could not be created', cause)
    }
  }
  await inspectLockDirectory(lockPath)
  return lockPath
}

async function recoverOwnerResidues(campaignDirectory, lockPath, expected, dependencies) {
  let lastCause
  for (let attempt = 0; attempt < MAX_TRANSITION_ATTEMPTS; attempt += 1) {
    let entries
    try {
      entries = await readdir(campaignDirectory, { withFileTypes: true })
    } catch (cause) {
      throw ownerError('UNLEASH_SWARM_OWNER_DIRECTORY_UNSAFE', 'swarm owner campaign directory could not be scanned', cause)
    }
    if (entries.length > MAX_CAMPAIGN_ENTRIES) {
      throw ownerError('UNLEASH_SWARM_OWNER_DIRECTORY_UNSAFE', 'swarm owner campaign directory exceeds the bounded startup scan')
    }
    const residues = entries.filter((entry) => (
      entry.name.startsWith(OWNER_RESIDUE_PREFIX)
      && entry.name !== LOCK_DIRECTORY
    ))
    if (residues.length > MAX_OWNER_RESIDUES) {
      throw ownerError('UNLEASH_SWARM_OWNER_DIRECTORY_UNSAFE', 'swarm owner campaign directory has too many owner residues')
    }
    let restart = false
    for (const entry of residues) {
      const match = entry.name.match(OWNER_RESIDUE)
      if (
        match === null
        || !entry.isFile()
        || entry.isDirectory()
        || entry.isSymbolicLink()
      ) throw ownerError('UNLEASH_SWARM_OWNER_RECORD_UNSAFE', 'swarm owner residue has an unexpected name or endpoint type')
      const [, kind, pidText, nonce] = match
      const path = childPath(campaignDirectory, entry.name)
      const isOwner = kind === 'stage'
      const readSnapshot = isOwner ? readOwnerSnapshot : readRetirementSnapshot
      const sameSnapshot = isOwner ? sameOwnerSnapshot : sameRetirementSnapshot
      let residue
      try {
        residue = await readSnapshot(path, [1n, 2n], expected)
      } catch (cause) {
        if (cause?.code === 'UNLEASH_SWARM_OWNER_CHANGED') {
          lastCause = cause
          restart = true
          break
        }
        throw cause
      }
      const recordPid = isOwner ? residue.owner.owner_pid : residue.retirement.retirer_pid
      const recordNonce = isOwner ? residue.owner.nonce : residue.retirement.nonce
      if (recordPid !== Number(pidText) || recordNonce !== nonce) {
        throw ownerError('UNLEASH_SWARM_OWNER_RECORD_UNSAFE', 'swarm owner residue name does not match its exact record')
      }
      if (observeOwnerLiveness(isOwner ? residue.owner : residue.retirement, dependencies)) continue
      if (residue.info.nlink === 2n) {
        const destinationPath = childPath(
          lockPath,
          isOwner ? OWNER_FILE : retiringFilename(residue.retirement),
        )
        let destination
        try {
          destination = await readSnapshot(destinationPath, [2n], expected)
        } catch (cause) {
          if (cause?.code === 'UNLEASH_SWARM_OWNER_CHANGED') {
            lastCause = cause
            restart = true
            break
          }
          throw cause
        }
        if (!sameSnapshot(residue, destination)) {
          throw ownerError('UNLEASH_SWARM_OWNER_RECORD_UNSAFE', 'swarm owner residue has an unexplained hard-link alias')
        }
      }
      let verified
      try {
        verified = await readSnapshot(path, [residue.info.nlink], expected)
      } catch (cause) {
        if (cause?.code === 'UNLEASH_SWARM_OWNER_CHANGED') {
          lastCause = cause
          restart = true
          break
        }
        throw cause
      }
      if (!sameSnapshot(verified, residue)) {
        lastCause = ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'swarm owner residue changed before cleanup')
        restart = true
        break
      }
      try {
        await unlink(path)
      } catch (cause) {
        if (cause?.code === 'ENOENT') {
          lastCause = ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'swarm owner residue was cleaned concurrently', cause)
          restart = true
          break
        }
        throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'exact dead swarm owner residue could not be removed', cause)
      }
      await syncRecoverableDirectoryChange(campaignDirectory)
    }
    if (restart) continue
    return
  }
  throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'swarm owner residues changed repeatedly during startup cleanup', lastCause)
}

async function createStagedOwner(campaignDirectory, owner) {
  const path = claimTemporaryPath(campaignDirectory, owner)
  const bytes = Buffer.from(canonicalUnleashCampaignJson(owner), 'utf8')
  let handle
  try {
    handle = await open(path, WRITE_CREATE_ONLY, 0o600)
    await handle.writeFile(bytes)
    await handle.sync()
  } catch (cause) {
    throw ownerError(
      cause?.code === 'EEXIST'
        ? 'UNLEASH_SWARM_OWNER_CLAIM_COLLISION'
        : 'UNLEASH_SWARM_OWNER_CLAIM_FAILED',
      'swarm owner claim could not be staged durably',
      cause,
    )
  } finally {
    await handle?.close()
  }
  await syncRecoverableDirectoryChange(campaignDirectory)
  const staged = await readOwnerSnapshot(path, [1n], {
    campaignId: owner.campaign_id,
    planSha256: owner.plan_sha256,
  })
  if (!staged.bytes.equals(bytes) || staged.owner.owner_id !== owner.owner_id) {
    throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'staged swarm owner claim differs from its exact record')
  }
  return staged
}

async function createStagedRetirement(campaignDirectory, retirement) {
  const path = retirementTemporaryPath(campaignDirectory, retirement)
  const bytes = Buffer.from(canonicalUnleashCampaignJson(retirement), 'utf8')
  let handle
  try {
    handle = await open(path, WRITE_CREATE_ONLY, 0o600)
    await handle.writeFile(bytes)
    await handle.sync()
  } catch (cause) {
    throw ownerError(
      cause?.code === 'EEXIST'
        ? 'UNLEASH_SWARM_OWNER_CLAIM_COLLISION'
        : 'UNLEASH_SWARM_OWNER_CLAIM_FAILED',
      'swarm owner retirement could not be staged durably',
      cause,
    )
  } finally {
    await handle?.close()
  }
  await syncRecoverableDirectoryChange(campaignDirectory)
  const staged = await readRetirementSnapshot(path, [1n], {
    campaignId: retirement.campaign_id,
    planSha256: retirement.plan_sha256,
  })
  if (
    !staged.bytes.equals(bytes)
    || staged.retirement.retirement_id !== retirement.retirement_id
  ) throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'staged swarm owner retirement differs from its exact record')
  return staged
}

async function cleanupStagedOwner(staged) {
  let current
  try {
    current = await readOwnerSnapshot(staged.path, [1n], {
      campaignId: staged.owner.campaign_id,
      planSha256: staged.owner.plan_sha256,
    })
  } catch (cause) {
    if (cause?.cause?.code === 'ENOENT' || cause?.code === 'ENOENT') return
    throw cause
  }
  if (!sameOwnerSnapshot(current, staged)) {
    throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'staged swarm owner claim changed before cleanup')
  }
  await unlink(staged.path)
  await syncRecoverableDirectoryChange(dirname(staged.path))
}

async function cleanupWithdrawnOwnerStage(staged) {
  let current
  try {
    current = await readOwnerSnapshot(staged.path, [1n], {
      campaignId: staged.owner.campaign_id,
      planSha256: staged.owner.plan_sha256,
    })
  } catch (cause) {
    if (cause?.cause?.code === 'ENOENT' || cause?.code === 'ENOENT') return
    throw cause
  }
  if (!samePublishedOwner(current, staged)) {
    throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'withdrawn swarm owner private stage changed before cleanup')
  }
  const verified = await readOwnerSnapshot(staged.path, [1n], {
    campaignId: staged.owner.campaign_id,
    planSha256: staged.owner.plan_sha256,
  })
  if (!sameOwnerSnapshot(verified, current)) {
    throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'withdrawn swarm owner private stage changed during cleanup')
  }
  await unlink(verified.path)
  await syncRecoverableDirectoryChange(dirname(verified.path))
}

async function cleanupStagedRetirement(staged) {
  let current
  try {
    current = await readRetirementSnapshot(staged.path, [1n], {
      campaignId: staged.retirement.campaign_id,
      planSha256: staged.retirement.plan_sha256,
    })
  } catch (cause) {
    if (cause?.cause?.code === 'ENOENT' || cause?.code === 'ENOENT') return
    throw cause
  }
  if (!sameRetirementSnapshot(current, staged)) {
    throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'staged swarm owner retirement changed before cleanup')
  }
  await unlink(staged.path)
  await syncRecoverableDirectoryChange(dirname(staged.path))
}

async function cleanupAbandonedRetirementStage(staged) {
  let current
  try {
    current = await readRetirementSnapshot(staged.path, [1n], {
      campaignId: staged.retirement.campaign_id,
      planSha256: staged.retirement.plan_sha256,
    })
  } catch (cause) {
    if (cause?.cause?.code === 'ENOENT' || cause?.code === 'ENOENT') return
    throw cause
  }
  if (!samePublishedRetirement(current, staged)) {
    throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'abandoned swarm owner retirement stage changed before cleanup')
  }
  const verified = await readRetirementSnapshot(staged.path, [1n], {
    campaignId: staged.retirement.campaign_id,
    planSha256: staged.retirement.plan_sha256,
  })
  if (!sameRetirementSnapshot(verified, current)) {
    throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'abandoned swarm owner retirement stage changed during cleanup')
  }
  await unlink(verified.path)
  await syncRecoverableDirectoryChange(dirname(verified.path))
}

async function durableClaimDirectorySync(lockPath, campaignDirectory, dependencies) {
  if (dependencies.directorySyncImpl !== undefined) {
    await dependencies.directorySyncImpl(lockPath, campaignDirectory)
    return
  }
  await syncRecoverableDirectoryChange(lockPath)
  await syncRecoverableDirectoryChange(campaignDirectory)
}

async function settleVisibleOwnerClaim(visible, empty, staged, dependencies) {
  const expected = {
    campaignId: staged.owner.campaign_id,
    planSha256: staged.owner.plan_sha256,
  }
  let current = visible
  if (current.state === 'CLAIM_PUBLICATION_TAIL') {
    if (!await recoverClaimPublicationTail(current, expected)) {
      throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'exact visible swarm owner claim could not finish its publication tail')
    }
    current = await inspectWithRetries(current.lock.path, expected)
  }
  await durableClaimDirectorySync(
    current.lock.path,
    dirname(current.lock.path),
    dependencies,
  )
  const settled = await inspectWithRetries(current.lock.path, expected)
  if (
    settled.state !== 'OWNED'
    || !sameLockIdentity(settled, empty)
    || !samePublishedOwner(settled.owner, staged)
    || settled.owner.info.nlink !== 1n
  ) throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'exact visible swarm owner claim did not settle durably')
  return { state: 'ACQUIRED', inspected: settled }
}

async function removeVisibleOwnerClaim(lockPath, empty, staged) {
  const expected = {
    campaignId: staged.owner.campaign_id,
    planSha256: staged.owner.plan_sha256,
  }
  let current = await inspectWithRetries(lockPath, expected)
  if (current.state === 'CLAIM_PUBLICATION_TAIL') {
    if (!await recoverClaimPublicationTail(current, expected)) return false
    current = await inspectWithRetries(lockPath, expected)
  }
  if (
    current.state !== 'OWNED'
    || !sameLockIdentity(current, empty)
    || !samePublishedOwner(current.owner, staged)
  ) return false
  const verified = await inspectWithRetries(lockPath, expected)
  if (
    verified.state !== 'OWNED'
    || !sameLockIdentity(verified, current)
    || !sameOwnerSnapshot(verified.owner, current.owner)
  ) return false
  try {
    await unlink(verified.owner.path)
  } catch (cause) {
    if (cause?.code === 'ENOENT') return false
    throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'exact visible swarm owner claim could not be removed after failed publication', cause)
  }
  await syncRecoverableDirectoryChange(verified.lock.path)
  return true
}

async function withdrawTentativeOwnerClaim(lockPath, empty, staged, dependencies) {
  const expected = {
    campaignId: staged.owner.campaign_id,
    planSha256: staged.owner.plan_sha256,
  }
  const ownerPath = childPath(lockPath, OWNER_FILE)
  const lock = await inspectLockDirectory(lockPath)
  if (!sameFileIdentity(lock.info, empty.lock.info)) {
    throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'swarm owner lock container changed before tentative claim withdrawal')
  }

  let current
  try {
    current = await readOwnerSnapshot(ownerPath, [1n, 2n], expected)
  } catch (cause) {
    if (cause?.cause?.code !== 'ENOENT' && cause?.code !== 'ENOENT') throw cause
    await cleanupStagedOwner(staged)
    return false
  }
  if (!samePublishedOwner(current, staged)) {
    await cleanupStagedOwner(staged)
    return false
  }

  let temporary
  if (current.info.nlink === 2n) {
    temporary = await readOwnerSnapshot(staged.path, [2n], expected)
    if (!sameOwnerSnapshot(current, temporary)) {
      throw ownerError('UNLEASH_SWARM_OWNER_RECORD_UNSAFE', 'tentative swarm owner claim has an unexplained hard-link alias')
    }
  } else {
    let stageExists = true
    try {
      await lstat(staged.path, { bigint: true })
    } catch (cause) {
      if (cause?.code === 'ENOENT') stageExists = false
      else throw cause
    }
    if (stageExists) {
      throw ownerError('UNLEASH_SWARM_OWNER_RECORD_UNSAFE', 'settled tentative swarm owner claim retained an unexpected private stage')
    }
  }

  const verifiedLock = await inspectLockDirectory(lockPath)
  if (!sameFileIdentity(verifiedLock.info, lock.info)) {
    throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'swarm owner lock container changed before tentative claim withdrawal')
  }
  const verifiedOwner = await readOwnerSnapshot(
    ownerPath,
    [current.info.nlink],
    expected,
  )
  if (!sameOwnerSnapshot(verifiedOwner, current)) {
    throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'tentative swarm owner claim changed before withdrawal')
  }
  if (temporary !== undefined) {
    const verifiedTemporary = await readOwnerSnapshot(staged.path, [2n], expected)
    if (!sameOwnerSnapshot(verifiedTemporary, temporary)) {
      throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'tentative swarm owner private stage changed before withdrawal')
    }
  }

  try {
    await unlink(verifiedOwner.path)
  } catch (cause) {
    if (cause?.code !== 'ENOENT') {
      throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'exact tentative swarm owner claim could not be withdrawn', cause)
    }
    if (temporary !== undefined) await cleanupWithdrawnOwnerStage(staged)
    return false
  }
  await syncRecoverableDirectoryChange(lockPath)
  await dependencies.faultInjector?.('after-owner-claim-withdrawn', {
    owner: verifiedOwner.path,
    temporary: temporary?.path,
  })
  if (temporary !== undefined) await cleanupWithdrawnOwnerStage(staged)
  return true
}

async function publishOwnerClaim(empty, staged, dependencies) {
  const lockPath = empty.lock.path
  const campaignDirectory = dirname(lockPath)
  const destination = childPath(lockPath, OWNER_FILE)
  let publicationAttempted = false
  let before
  try {
    before = await inspectWithRetries(lockPath, {
      campaignId: staged.owner.campaign_id,
      planSha256: staged.owner.plan_sha256,
    })
  } catch (cause) {
    if (cause?.code === 'UNLEASH_SWARM_OWNER_CHANGED') return { state: 'RETRY' }
    throw cause
  }
  if (before.state !== 'EMPTY' || !sameLockIdentity(before, empty)) return { state: 'RETRY' }

  try {
    await dependencies.faultInjector?.('before-owner-claim-publication', {
      destination,
      temporary: staged.path,
    })
    publicationAttempted = true
    await publishFileCreateOnlyDurably(staged.path, destination, {
      afterVisible: () => {
        return dependencies.faultInjector?.('after-owner-claim-visible', {
          destination,
          temporary: staged.path,
        })
      },
      directorySyncImpl: () => durableClaimDirectorySync(
        lockPath,
        campaignDirectory,
        dependencies,
      ),
      platform: dependencies.publicationPlatform,
      win32MoveImpl: dependencies.win32MoveImpl,
    })
  } catch (cause) {
    let visible
    let inspectionCause
    try {
      visible = await inspectWithRetries(lockPath, {
        campaignId: staged.owner.campaign_id,
        planSha256: staged.owner.plan_sha256,
      })
    } catch (cause) {
      inspectionCause = cause
    }
    if (
      ['CLAIM_PUBLICATION_TAIL', 'OWNED'].includes(visible?.state)
      && sameLockIdentity(visible, empty)
      && samePublishedOwner(visible.owner, staged)
      && (
        visible.state === 'OWNED'
        || samePublishedOwner(visible.temporary, staged)
      )
    ) {
      try {
        return await settleVisibleOwnerClaim(visible, empty, staged, dependencies)
      } catch (settleCause) {
        try {
          await removeVisibleOwnerClaim(lockPath, empty, staged)
        } catch (cleanupCause) {
          throw ownerError(
            'UNLEASH_SWARM_OWNER_CHANGED',
            'failed visible swarm owner claim could neither settle nor clean its exact publication',
            new AggregateError([cause, settleCause, cleanupCause]),
          )
        }
        throw ownerError(
          'UNLEASH_SWARM_OWNER_CLAIM_FAILED',
          'visible swarm owner claim could not settle durably and was removed',
          new AggregateError([cause, settleCause]),
        )
      }
    }
    if (publicationAttempted) {
      let withdrawn = false
      try {
        withdrawn = await withdrawTentativeOwnerClaim(
          lockPath,
          empty,
          staged,
          dependencies,
        )
      } catch (cleanupCause) {
        throw ownerError(
          'UNLEASH_SWARM_OWNER_CHANGED',
          'visible swarm owner claim could not be inspected or withdrawn exactly',
          new AggregateError(
            [cause, inspectionCause, cleanupCause].filter((value) => value !== undefined),
          ),
        )
      }
      if (!withdrawn && cause?.code === 'EEXIST') return { state: 'RETRY' }
      throw ownerError(
        'UNLEASH_SWARM_OWNER_CLAIM_FAILED',
        'visible swarm owner claim was withdrawn after publication failed',
        new AggregateError(
          [cause, inspectionCause].filter((value) => value !== undefined),
        ),
      )
    }
    try {
      await cleanupStagedOwner(staged)
    } catch (cleanupCause) {
      throw ownerError(
        'UNLEASH_SWARM_OWNER_CHANGED',
        'failed swarm owner claim could not clean its exact private stage',
        new AggregateError([cause, cleanupCause]),
      )
    }
    if (cause?.code === 'EEXIST') return { state: 'RETRY' }
    throw ownerError('UNLEASH_SWARM_OWNER_CLAIM_FAILED', 'swarm owner claim publication failed', cause)
  }

  let published
  try {
    published = await inspectWithRetries(lockPath, {
      campaignId: staged.owner.campaign_id,
      planSha256: staged.owner.plan_sha256,
    })
  } catch (cause) {
    try {
      await withdrawTentativeOwnerClaim(lockPath, empty, staged, dependencies)
    } catch (cleanupCause) {
      throw ownerError(
        'UNLEASH_SWARM_OWNER_CHANGED',
        'published swarm owner claim could not be inspected or withdrawn exactly',
        new AggregateError([cause, cleanupCause]),
      )
    }
    throw ownerError(
      'UNLEASH_SWARM_OWNER_CLAIM_FAILED',
      'published swarm owner claim was withdrawn after exact inspection failed',
      cause,
    )
  }
  if (
    published.state !== 'OWNED'
    || !sameLockIdentity(published, empty)
    || !samePublishedOwner(published.owner, staged)
    || published.owner.info.nlink !== 1n
  ) {
    try {
      await withdrawTentativeOwnerClaim(lockPath, empty, staged, dependencies)
    } catch (cleanupCause) {
      throw ownerError(
        'UNLEASH_SWARM_OWNER_CHANGED',
        'published swarm owner claim differed and could not be withdrawn exactly',
        cleanupCause,
      )
    }
    throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'published swarm owner claim differs from its exact staged record')
  }
  return { state: 'ACQUIRED', inspected: published }
}

async function recoverClaimPublicationTail(inspected, expected) {
  const current = await inspectWithRetries(inspected.lock.path, expected)
  if (
    current.state !== 'CLAIM_PUBLICATION_TAIL'
    || !sameLockIdentity(current, inspected)
    || !sameOwnerSnapshot(current.owner, inspected.owner)
    || !sameOwnerSnapshot(current.temporary, inspected.temporary)
  ) return false
  try {
    await unlink(current.temporary.path)
  } catch (cause) {
    if (cause?.code === 'ENOENT') return false
    throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'swarm owner publication tail could not be removed', cause)
  }
  await syncRecoverableDirectoryChange(dirname(current.temporary.path))
  await syncRecoverableDirectoryChange(current.lock.path)
  const recovered = await inspectWithRetries(current.lock.path, expected)
  if (
    recovered.state !== 'OWNED'
    || !sameLockIdentity(recovered, current)
    || !samePublishedOwner(recovered.owner, current.owner)
    || recovered.owner.info.nlink !== 1n
  ) throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'swarm owner publication tail recovery changed its exact claim')
  return true
}

function findRetirement(inspected, retirementId) {
  return inspected.retirements?.find(({ retiring }) => (
    retiring.retirement.retirement_id === retirementId
  ))
}

async function removeRetirementClaim(inspected, expected, expectedRetirement) {
  let current = await inspectWithRetries(inspected.lock.path, expected)
  let entry = findRetirement(current, expectedRetirement.retirement.retirement_id)
  if (
    entry === undefined
    || !sameLockIdentity(current, inspected)
    || !samePublishedRetirement(entry.retiring, expectedRetirement)
  ) return false
  if (entry.temporary !== undefined) {
    const verifiedTail = await inspectWithRetries(current.lock.path, expected)
    const verifiedEntry = findRetirement(
      verifiedTail,
      expectedRetirement.retirement.retirement_id,
    )
    if (
      verifiedEntry?.temporary === undefined
      || !sameLockIdentity(verifiedTail, current)
      || !sameRetirementSnapshot(verifiedEntry.retiring, entry.retiring)
      || !sameRetirementSnapshot(verifiedEntry.temporary, entry.temporary)
    ) return false
    try {
      await unlink(verifiedEntry.temporary.path)
    } catch (cause) {
      if (cause?.code === 'ENOENT') return false
      throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'swarm owner retirement publication tail could not be removed', cause)
    }
    await syncRecoverableDirectoryChange(dirname(verifiedEntry.temporary.path))
    current = await inspectWithRetries(current.lock.path, expected)
    entry = findRetirement(current, expectedRetirement.retirement.retirement_id)
  }
  if (
    entry === undefined
    || entry.temporary !== undefined
    || !sameLockIdentity(current, inspected)
    || !samePublishedRetirement(entry.retiring, expectedRetirement)
    || entry.retiring.info.nlink !== 1n
  ) return false
  const verified = await inspectWithRetries(current.lock.path, expected)
  const verifiedEntry = findRetirement(
    verified,
    expectedRetirement.retirement.retirement_id,
  )
  if (
    verifiedEntry === undefined
    || verifiedEntry.temporary !== undefined
    || !sameLockIdentity(verified, current)
    || !sameRetirementSnapshot(verifiedEntry.retiring, entry.retiring)
  ) return false
  try {
    await unlink(verifiedEntry.retiring.path)
  } catch (cause) {
    if (cause?.code === 'ENOENT') return false
    throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'exact swarm owner retirement could not be removed', cause)
  }
  await syncRecoverableDirectoryChange(verified.lock.path)
  return true
}

async function removeOwnRetirementDirect(lockPath, expected, staged, expectedLock = undefined) {
  const lock = await inspectLockDirectory(lockPath)
  if (expectedLock !== undefined && !sameFileIdentity(lock.info, expectedLock.lock.info)) {
    throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'swarm owner lock container changed before unique retirement cleanup')
  }
  const path = childPath(lockPath, retiringFilename(staged.retirement))
  let current
  try {
    current = await readRetirementSnapshot(path, [1n], expected)
  } catch (cause) {
    if (cause?.cause?.code === 'ENOENT') return true
    throw cause
  }
  if (!samePublishedRetirement(current, staged)) {
    throw ownerError('UNLEASH_SWARM_OWNER_RECORD_UNSAFE', 'unique swarm owner retirement path contains another record')
  }
  let verified
  try {
    verified = await readRetirementSnapshot(path, [1n], expected)
  } catch (cause) {
    if (cause?.cause?.code === 'ENOENT') return true
    throw cause
  }
  if (!sameRetirementSnapshot(verified, current)) {
    throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'unique swarm owner retirement changed before direct cleanup')
  }
  try {
    await unlink(path)
  } catch (cause) {
    if (cause?.code === 'ENOENT') return true
    throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'saturated swarm owner retirement could not remove its unique claim', cause)
  }
  await syncRecoverableDirectoryChange(lockPath)
  return true
}

async function cleanupAcquireRetirementTransition(inspected, expected, transition) {
  const lockPath = inspected.lock.path
  const marker = transition.marker
  const stage = {
    ...marker,
    path: retirementTemporaryPath(dirname(lockPath), marker.retirement),
  }
  const markerPath = childPath(lockPath, retiringFilename(marker.retirement))
  const lock = await inspectLockDirectory(lockPath)
  if (!sameFileIdentity(lock.info, inspected.lock.info)) {
    throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'swarm owner lock container changed before acquisition transition cleanup')
  }

  let current
  try {
    current = await readRetirementSnapshot(markerPath, [1n, 2n], expected)
  } catch (cause) {
    if (cause?.cause?.code !== 'ENOENT' && cause?.code !== 'ENOENT') throw cause
    await cleanupAbandonedRetirementStage(stage)
    return
  }
  if (!samePublishedRetirement(current, marker)) {
    throw ownerError('UNLEASH_SWARM_OWNER_RECORD_UNSAFE', 'acquisition retirement path contains another transition')
  }

  if (current.info.nlink === 2n) {
    const temporary = await readRetirementSnapshot(stage.path, [2n], expected)
    if (!sameRetirementSnapshot(temporary, current)) {
      throw ownerError('UNLEASH_SWARM_OWNER_RECORD_UNSAFE', 'acquisition retirement has an unexplained hard-link alias')
    }
    const verifiedLock = await inspectLockDirectory(lockPath)
    const verifiedMarker = await readRetirementSnapshot(markerPath, [2n], expected)
    const verifiedTemporary = await readRetirementSnapshot(stage.path, [2n], expected)
    if (
      !sameFileIdentity(verifiedLock.info, lock.info)
      || !sameRetirementSnapshot(verifiedMarker, current)
      || !sameRetirementSnapshot(verifiedTemporary, temporary)
    ) throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'acquisition retirement tail changed before cleanup')
    try {
      await unlink(verifiedTemporary.path)
    } catch (cause) {
      if (cause?.code !== 'ENOENT') {
        throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'acquisition retirement tail could not be removed', cause)
      }
    }
    await syncRecoverableDirectoryChange(dirname(verifiedTemporary.path))
    try {
      current = await readRetirementSnapshot(markerPath, [1n], expected)
    } catch (cause) {
      if (cause?.cause?.code === 'ENOENT' || cause?.code === 'ENOENT') return
      throw cause
    }
    if (!samePublishedRetirement(current, marker)) {
      throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'acquisition retirement did not settle to its exact marker')
    }
  } else {
    let stageExists = true
    try {
      await lstat(stage.path, { bigint: true })
    } catch (cause) {
      if (cause?.code === 'ENOENT') stageExists = false
      else throw cause
    }
    if (stageExists) {
      throw ownerError('UNLEASH_SWARM_OWNER_RECORD_UNSAFE', 'settled acquisition retirement retained an unexpected private stage')
    }
  }

  const verifiedLock = await inspectLockDirectory(lockPath)
  const verifiedMarker = await readRetirementSnapshot(markerPath, [1n], expected)
  if (
    !sameFileIdentity(verifiedLock.info, lock.info)
    || !sameRetirementSnapshot(verifiedMarker, current)
  ) throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'acquisition retirement changed before marker cleanup')
  try {
    await unlink(verifiedMarker.path)
  } catch (cause) {
    if (cause?.code !== 'ENOENT') {
      throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'acquisition retirement marker could not be removed', cause)
    }
    return
  }
  await syncRecoverableDirectoryChange(lockPath)
}

async function cleanupOwnRetirementAfterFailure(cause, inspected, expected, retirement) {
  try {
    await removeOwnRetirementDirect(inspected.lock.path, expected, retirement, inspected)
  } catch (cleanupCause) {
    throw ownerError(
      'UNLEASH_SWARM_OWNER_CHANGED',
      'failed swarm owner retirement could not clean its exact unique transition',
      new AggregateError([cause, cleanupCause]),
    )
  }
  throw cause
}

async function publishRetirementClaim(inspected, staged, dependencies, onVisible = undefined) {
  const lockPath = inspected.lock.path
  const campaignDirectory = dirname(lockPath)
  const destination = childPath(
    lockPath,
    retiringFilename(staged.retirement),
  )
  let before
  try {
    before = await inspectWithRetries(lockPath, {
      campaignId: staged.retirement.campaign_id,
      planSha256: staged.retirement.plan_sha256,
    })
  } catch (cause) {
    if (cause?.code === 'UNLEASH_SWARM_OWNER_CHANGED') return { state: 'RETRY' }
    throw cause
  }
  if (
    before.state !== 'OWNED'
    || !sameLockIdentity(before, inspected)
    || !sameOwnerSnapshot(before.owner, inspected.owner)
  ) return { state: 'RETRY' }
  try {
    await dependencies.faultInjector?.('before-owner-retirement-link', {
      destination,
      owner: before.owner.path,
      temporary: staged.path,
    })
  } catch (cause) {
    await cleanupStagedRetirement(staged)
    throw cause
  }
  onVisible?.({
    marker: { ...staged, path: destination },
    target: inspected.owner,
  })
  try {
    await publishFileCreateOnlyDurably(staged.path, destination, {
      afterVisible: () => dependencies.faultInjector?.('after-owner-retirement-visible', {
        destination,
        owner: before.owner.path,
        temporary: staged.path,
      }),
      directorySyncImpl: () => durableClaimDirectorySync(
        lockPath,
        campaignDirectory,
        dependencies,
      ),
      platform: dependencies.publicationPlatform,
      win32MoveImpl: dependencies.win32MoveImpl,
    })
  } catch (cause) {
    let visible
    try {
      visible = await inspectWithRetries(lockPath, {
        campaignId: staged.retirement.campaign_id,
        planSha256: staged.retirement.plan_sha256,
      })
    } catch {}
    const visibleEntry = visible === undefined
      ? undefined
      : findRetirement(visible, staged.retirement.retirement_id)
    if (
      visibleEntry !== undefined
      && sameLockIdentity(visible, inspected)
      && samePublishedRetirement(visibleEntry.retiring, staged)
      && (
        visibleEntry.temporary === undefined
        || samePublishedRetirement(visibleEntry.temporary, staged)
      )
    ) {
      onVisible?.({ marker: visibleEntry.retiring, target: inspected.owner })
      throw cause
    }
    try {
      await cleanupStagedRetirement(staged)
    } catch (cleanupCause) {
      throw ownerError(
        'UNLEASH_SWARM_OWNER_CHANGED',
        'failed swarm owner retirement could not clean its exact private stage',
        new AggregateError([cause, cleanupCause]),
      )
    }
    if (cause?.code === 'EEXIST') return { state: 'RETRY' }
    throw ownerError('UNLEASH_SWARM_OWNER_CLAIM_FAILED', 'swarm owner retirement publication failed', cause)
  }
  onVisible?.({
    marker: { ...staged, path: destination },
    target: inspected.owner,
  })
  try {
    await dependencies.faultInjector?.('after-owner-retirement-published', {
      destination,
      owner: inspected.owner.path,
    })
  } catch (cause) {
    try {
      await dependencies.faultInjector?.('before-owner-retirement-cleanup', {
        destination,
        owner: inspected.owner.path,
      })
      await removeOwnRetirementDirect(lockPath, {
        campaignId: staged.retirement.campaign_id,
        planSha256: staged.retirement.plan_sha256,
      }, staged, inspected)
    } catch (cleanupCause) {
      throw ownerError(
        'UNLEASH_SWARM_OWNER_CHANGED',
        'published swarm owner retirement failed before validation and could not clean its exact transition',
        new AggregateError([cause, cleanupCause]),
      )
    }
    throw cause
  }
  let lockEntries
  try {
    lockEntries = await readdir(lockPath, { withFileTypes: true })
  } catch (cause) {
    await removeOwnRetirementDirect(lockPath, {
      campaignId: staged.retirement.campaign_id,
      planSha256: staged.retirement.plan_sha256,
    }, staged, inspected)
    throw ownerError('UNLEASH_SWARM_OWNER_LOCK_UNSAFE', 'swarm owner lock container could not enforce retirement admission', cause)
  }
  if (lockEntries.length > MAX_RETIREMENT_ENTRIES + 1) {
    await removeOwnRetirementDirect(lockPath, {
      campaignId: staged.retirement.campaign_id,
      planSha256: staged.retirement.plan_sha256,
    }, staged, inspected)
    return { state: 'RETRY' }
  }
  const retirementCount = lockEntries.filter((entry) => RETIRING_FILE.test(entry.name)).length
  if (retirementCount > RETIREMENT_ADMISSION_LIMIT) {
    await removeOwnRetirementDirect(lockPath, {
      campaignId: staged.retirement.campaign_id,
      planSha256: staged.retirement.plan_sha256,
    }, staged, inspected)
    return { state: 'RETRY' }
  }
  const expected = {
    campaignId: staged.retirement.campaign_id,
    planSha256: staged.retirement.plan_sha256,
  }
  let published
  try {
    published = await inspectWithRetries(lockPath, expected)
  } catch (cause) {
    await removeOwnRetirementDirect(lockPath, expected, staged, inspected)
    if (cause?.code === 'UNLEASH_SWARM_OWNER_CHANGED') return { state: 'RETRY' }
    throw cause
  }
  const publishedEntry = findRetirement(published, staged.retirement.retirement_id)
  if (
    publishedEntry === undefined
    || publishedEntry.temporary !== undefined
    || !sameLockIdentity(published, inspected)
    || !samePublishedRetirement(publishedEntry.retiring, staged)
    || publishedEntry.retiring.info.nlink !== 1n
  ) {
    await removeOwnRetirementDirect(lockPath, expected, staged, inspected)
    return { state: 'RETRY' }
  }
  return { state: 'CLAIMED', inspected: published, retiring: publishedEntry.retiring }
}

async function retireOwner(inspected, expected, dependencies, onPublished = undefined) {
  const target = inspected.owner
  const retirement = createRetirement(target.owner, dependencies)
  let staged
  try {
    staged = await createStagedRetirement(dirname(inspected.lock.path), retirement)
  } catch (cause) {
    if (cause?.code === 'UNLEASH_SWARM_OWNER_CLAIM_COLLISION') return false
    throw cause
  }
  const published = await publishRetirementClaim(
    inspected,
    staged,
    dependencies,
    onPublished,
  )
  if (published.state === 'RETRY') {
    try {
      await cleanupStagedRetirement(staged)
    } catch (cause) {
      if (cause?.code !== 'UNLEASH_SWARM_OWNER_CHANGED') throw cause
    }
    onPublished?.(undefined)
    return false
  }
  const marker = published.retiring
  const publishedOwner = published.inspected.owner
  if (
    publishedOwner === undefined
    || !sameOwnerSnapshot(publishedOwner, target)
    || retirement.target_owner_id !== target.owner.owner_id
  ) {
    await removeOwnRetirementDirect(inspected.lock.path, expected, marker, inspected)
    onPublished?.(undefined)
    return false
  }
  try {
    await dependencies.faultInjector?.('after-owner-retirement-linked', {
      marker: marker.path,
      owner: publishedOwner.path,
    })
  } catch (cause) {
    await cleanupOwnRetirementAfterFailure(cause, inspected, expected, marker)
  }
  let verified
  try {
    verified = await inspectWithRetries(inspected.lock.path, expected)
  } catch (cause) {
    await cleanupOwnRetirementAfterFailure(cause, inspected, expected, marker)
  }
  const verifiedEntry = findRetirement(verified, retirement.retirement_id)
  if (
    verifiedEntry === undefined
    || verifiedEntry.temporary !== undefined
    || verified.owner === undefined
    || !sameLockIdentity(verified, inspected)
    || !sameRetirementSnapshot(verifiedEntry.retiring, marker)
    || !sameOwnerSnapshot(verified.owner, target)
  ) {
    await removeOwnRetirementDirect(inspected.lock.path, expected, marker, inspected)
    onPublished?.(undefined)
    return false
  }
  onPublished?.({ marker, target })
  try {
    await dependencies.faultInjector?.('before-owner-claim-retired', {
      marker: verifiedEntry.retiring.path,
      owner: verified.owner.path,
    })
  } catch (cause) {
    await cleanupOwnRetirementAfterFailure(cause, inspected, expected, marker)
  }
  try {
    await unlink(verified.owner.path)
  } catch (cause) {
    if (cause?.code !== 'ENOENT') {
      await cleanupOwnRetirementAfterFailure(
        ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'exact swarm owner claim could not enter retirement', cause),
        inspected,
        expected,
        marker,
      )
    }
  }
  try {
    await syncRecoverableDirectoryChange(verified.lock.path)
    await dependencies.faultInjector?.('after-owner-claim-retired', {
      marker: verifiedEntry.retiring.path,
      owner: verified.owner.path,
    })
  } catch (cause) {
    await cleanupOwnRetirementAfterFailure(cause, inspected, expected, marker)
  }
  let retired
  try {
    retired = await inspectWithRetries(verified.lock.path, expected)
  } catch (cause) {
    await cleanupOwnRetirementAfterFailure(cause, inspected, expected, marker)
  }
  const retiredEntry = findRetirement(retired, retirement.retirement_id)
  if (
    retired.owner !== undefined
    || retiredEntry === undefined
    || !sameLockIdentity(retired, verified)
    || !sameRetirementSnapshot(retiredEntry.retiring, verifiedEntry.retiring)
  ) {
    await cleanupOwnRetirementAfterFailure(
      ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'swarm owner retirement did not retain its exact transition barrier'),
      inspected,
      expected,
      marker,
    )
  }
  await dependencies.faultInjector?.('before-owner-retirement-removed', {
    marker: retiredEntry.retiring.path,
    owner: childPath(retired.lock.path, OWNER_FILE),
  })
  await removeOwnRetirementDirect(
    inspected.lock.path,
    expected,
    retiredEntry.retiring,
    inspected,
  )
  await dependencies.faultInjector?.('after-owner-retirement-removed', {
    marker: retiredEntry.retiring.path,
    owner: childPath(retired.lock.path, OWNER_FILE),
  })
  return true
}

async function inspectWithRetries(lockPath, expected) {
  let lastCause
  for (let attempt = 0; attempt < MAX_TRANSITION_ATTEMPTS; attempt += 1) {
    try {
      return await inspectLockState(lockPath, expected)
    } catch (cause) {
      if (cause?.code !== 'UNLEASH_SWARM_OWNER_CHANGED') throw cause
      lastCause = cause
    }
  }
  throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'swarm owner state changed repeatedly during inspection', lastCause)
}

export async function inspectUnleashSwarmOwner(input, dependencies = {}) {
  const retained = inputSnapshot(input)
  const deps = dependencySnapshot(dependencies)
  const campaign = await canonicalCampaignDirectory(retained.campaignDirectory)
  const lockPath = childPath(campaign.path, LOCK_DIRECTORY)
  let inspected
  try {
    inspected = await inspectWithRetries(lockPath, retained)
  } catch (cause) {
    if (cause?.code === 'ENOENT') return Object.freeze({ state: 'AVAILABLE', owner: null })
    throw cause
  }
  let owner = stateOwner(inspected)
  if (owner === null) return Object.freeze({ state: 'AVAILABLE', owner: null })
  if (inspected.retirements !== undefined) {
    const live = inspected.retirements.find(({ retiring }) => (
      observeOwnerLiveness(retiring.retirement, deps)
    ))
    if (live !== undefined) owner = live.retiring.retirement
  }
  return Object.freeze({
    state: observeOwnerLiveness(owner, deps) ? 'ACTIVE' : 'STALE',
    owner: publicOwner(owner),
  })
}

export async function acquireUnleashSwarmOwner(input, dependencies = {}) {
  const retained = inputSnapshot(input)
  const deps = dependencySnapshot(dependencies)
  const campaign = await canonicalCampaignDirectory(retained.campaignDirectory)
  const lockPath = await ensureLockContainer(campaign.path)
  await recoverOwnerResidues(campaign.path, lockPath, retained, deps)
  let lastCause
  for (let attempt = 0; attempt < MAX_TRANSITION_ATTEMPTS; attempt += 1) {
    let inspected
    try {
      inspected = await inspectLockState(lockPath, retained)
    } catch (cause) {
      if (cause?.code === 'UNLEASH_SWARM_OWNER_CHANGED') {
        lastCause = cause
        continue
      }
      throw cause
    }
    if (inspected.state === 'EMPTY') {
      const owner = createOwner(retained, deps)
      let staged
      try {
        staged = await createStagedOwner(campaign.path, owner)
      } catch (cause) {
        if (cause?.code === 'UNLEASH_SWARM_OWNER_CLAIM_COLLISION') {
          lastCause = cause
          continue
        }
        throw cause
      }
      await deps.faultInjector?.('after-owner-stage-durable', {
        temporary: staged.path,
      })
      const outcome = await publishOwnerClaim(inspected, staged, deps)
      if (outcome.state === 'RETRY') {
        try {
          await cleanupStagedOwner(staged)
        } catch (cause) {
          if (cause?.code !== 'UNLEASH_SWARM_OWNER_CHANGED') throw cause
        }
        continue
      }
      const token = Object.freeze({
        campaign_directory: campaign.path,
        campaign_id: retained.campaignId,
        plan_sha256: retained.planSha256,
        owner_id: owner.owner_id,
      })
      tokenState.set(token, { inspected: outcome.inspected, dependencies: deps })
      return Object.freeze({ state: 'ACQUIRED', owner: token })
    }
    if (inspected.state === 'CLAIM_PUBLICATION_TAIL') {
      const owner = stateOwner(inspected)
      if (observeOwnerLiveness(owner, deps)) {
        return Object.freeze({ state: 'BUSY', owner: publicOwner(owner) })
      }
      try {
        await recoverClaimPublicationTail(inspected, retained)
      } catch (cause) {
        if (cause?.code !== 'UNLEASH_SWARM_OWNER_CHANGED') throw cause
        lastCause = cause
      }
      continue
    }
    if (inspected.retirements !== undefined) {
      const live = inspected.retirements.find(({ retiring }) => (
        observeOwnerLiveness(retiring.retirement, deps)
      ))
      if (live !== undefined) {
        return Object.freeze({
          state: 'BUSY',
          owner: publicOwner(live.retiring.retirement),
        })
      }
      for (const { retiring } of inspected.retirements) {
        try {
          await removeRetirementClaim(inspected, retained, retiring)
        } catch (cause) {
          if (cause?.code !== 'UNLEASH_SWARM_OWNER_CHANGED') throw cause
          lastCause = cause
        }
      }
      continue
    }
    const owner = stateOwner(inspected)
    if (observeOwnerLiveness(owner, deps)) {
      return Object.freeze({ state: 'BUSY', owner: publicOwner(owner) })
    }
    let acquisitionRetirement
    try {
      await retireOwner(
        inspected,
        retained,
        deps,
        (transition) => { acquisitionRetirement = transition },
      )
    } catch (cause) {
      if (acquisitionRetirement !== undefined) {
        try {
          await cleanupAcquireRetirementTransition(
            inspected,
            retained,
            acquisitionRetirement,
          )
        } catch (cleanupCause) {
          throw ownerError(
            'UNLEASH_SWARM_OWNER_CHANGED',
            'failed acquisition retirement could not clean its exact transition',
            new AggregateError([cause, cleanupCause]),
          )
        }
      }
      if (cause?.code !== 'UNLEASH_SWARM_OWNER_CHANGED') throw cause
      lastCause = cause
    }
  }
  throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'swarm owner changed repeatedly during exclusive acquisition', lastCause)
}

export async function assertUnleashSwarmOwner(owner) {
  const retained = tokenState.get(owner)
  if (retained === undefined) {
    throw ownerError('UNLEASH_SWARM_OWNER_TOKEN_INVALID', 'swarm owner token was not issued by this controller process')
  }
  let current
  try {
    current = await inspectWithRetries(retained.inspected.lock.path, {
      campaignId: retained.inspected.owner.owner.campaign_id,
      planSha256: retained.inspected.owner.owner.plan_sha256,
    })
  } catch (cause) {
    throw ownerError('UNLEASH_SWARM_OWNER_SUPERSEDED', 'swarm owner token no longer controls the campaign claim', cause)
  }
  if (
    current.state !== 'OWNED'
    || !sameLockIdentity(current, retained.inspected)
    || !sameOwnerSnapshot(current.owner, retained.inspected.owner)
    || current.owner.owner.owner_id !== owner.owner_id
  ) throw ownerError('UNLEASH_SWARM_OWNER_SUPERSEDED', 'swarm owner token no longer controls the campaign claim')
  return true
}

async function resumeTokenRetirement(retained, expected) {
  const saved = retained.retirement
  let current = await inspectWithRetries(retained.inspected.lock.path, expected)
  let entry = findRetirement(current, saved.marker.retirement.retirement_id)
  if (entry === undefined) {
    return current.owner === undefined
      || !sameOwnerSnapshot(current.owner, retained.inspected.owner)
  }
  if (
    !sameLockIdentity(current, retained.inspected)
    || !samePublishedRetirement(entry.retiring, saved.marker)
  ) throw ownerError('UNLEASH_SWARM_OWNER_SUPERSEDED', 'saved swarm owner retirement no longer controls its exact transition')
  if (entry.temporary !== undefined) {
    const verifiedTail = await inspectWithRetries(current.lock.path, expected)
    const verifiedEntry = findRetirement(
      verifiedTail,
      saved.marker.retirement.retirement_id,
    )
    if (
      verifiedEntry?.temporary === undefined
      || !sameLockIdentity(verifiedTail, retained.inspected)
      || !sameRetirementSnapshot(verifiedEntry.retiring, entry.retiring)
      || !sameRetirementSnapshot(verifiedEntry.temporary, entry.temporary)
    ) throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'saved swarm owner retirement tail changed before retry cleanup')
    try {
      await unlink(verifiedEntry.temporary.path)
    } catch (cause) {
      if (cause?.code !== 'ENOENT') {
        throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'saved swarm owner retirement tail could not be removed', cause)
      }
    }
    await syncRecoverableDirectoryChange(dirname(verifiedEntry.temporary.path))
    current = await inspectWithRetries(current.lock.path, expected)
    entry = findRetirement(current, saved.marker.retirement.retirement_id)
    if (
      entry === undefined
      || entry.temporary !== undefined
      || !sameLockIdentity(current, retained.inspected)
      || !samePublishedRetirement(entry.retiring, saved.marker)
    ) throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'saved swarm owner retirement tail did not settle to one exact barrier')
  }
  if (current.owner !== undefined) {
    if (
      saved.marker.retirement.target_owner_id !== retained.inspected.owner.owner.owner_id
      || !sameOwnerSnapshot(current.owner, retained.inspected.owner)
    ) {
      await removeOwnRetirementDirect(
        current.lock.path,
        expected,
        entry.retiring,
        retained.inspected,
      )
      return true
    }
    await retained.dependencies.faultInjector?.('before-owner-claim-retired', {
      marker: entry.retiring.path,
      owner: current.owner.path,
    })
    current = await inspectWithRetries(current.lock.path, expected)
    entry = findRetirement(current, saved.marker.retirement.retirement_id)
    if (
      entry === undefined
      || current.owner === undefined
      || !sameLockIdentity(current, retained.inspected)
      || !samePublishedRetirement(entry.retiring, saved.marker)
      || !sameOwnerSnapshot(current.owner, retained.inspected.owner)
    ) throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'saved swarm owner retirement changed before retry unlink')
    try {
      await unlink(current.owner.path)
    } catch (cause) {
      if (cause?.code !== 'ENOENT') {
        throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'retried swarm owner claim could not enter retirement', cause)
      }
    }
    await syncRecoverableDirectoryChange(current.lock.path)
    await retained.dependencies.faultInjector?.('after-owner-claim-retired', {
      marker: entry.retiring.path,
      owner: current.owner.path,
    })
  }
  const retired = await inspectWithRetries(current.lock.path, expected)
  const retiredEntry = findRetirement(retired, saved.marker.retirement.retirement_id)
  if (
    retired.owner !== undefined
    || retiredEntry === undefined
    || !sameLockIdentity(retired, retained.inspected)
    || !samePublishedRetirement(retiredEntry.retiring, saved.marker)
  ) throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'retried swarm owner retirement lost its exact transition barrier')
  await retained.dependencies.faultInjector?.('before-owner-retirement-removed', {
    marker: retiredEntry.retiring.path,
    owner: childPath(retired.lock.path, OWNER_FILE),
  })
  await removeOwnRetirementDirect(
    retired.lock.path,
    expected,
    retiredEntry.retiring,
    retained.inspected,
  )
  await retained.dependencies.faultInjector?.('after-owner-retirement-removed', {
    marker: retiredEntry.retiring.path,
    owner: childPath(retired.lock.path, OWNER_FILE),
  })
  return true
}

async function reconcileReleaseFailure(owner, retained, expected) {
  let current
  try {
    current = await inspectWithRetries(retained.inspected.lock.path, expected)
  } catch {
    return
  }
  if (!sameLockIdentity(current, retained.inspected)) return
  const saved = retained.retirement
  const entry = saved === undefined
    ? undefined
    : findRetirement(current, saved.marker.retirement.retirement_id)
  if (
    entry !== undefined
    && samePublishedRetirement(entry.retiring, saved.marker)
  ) return
  if (
    current.owner !== undefined
    && sameOwnerSnapshot(current.owner, retained.inspected.owner)
  ) {
    retained.retirement = undefined
    return
  }
  tokenState.delete(owner)
}

async function performUnleashSwarmOwnerRelease(owner, retained) {
  const expected = {
    campaignId: retained.inspected.owner.owner.campaign_id,
    planSha256: retained.inspected.owner.owner.plan_sha256,
  }
  if (retained.retirement !== undefined) {
    try {
      if (await resumeTokenRetirement(retained, expected)) {
        tokenState.delete(owner)
        return
      }
      retained.retirement = undefined
    } catch (cause) {
      await reconcileReleaseFailure(owner, retained, expected)
      throw cause
    }
  }
  let released = false
  try {
    for (let attempt = 0; attempt < MAX_TRANSITION_ATTEMPTS; attempt += 1) {
      let current
      try {
        current = await inspectLockState(retained.inspected.lock.path, expected)
      } catch (cause) {
        if (cause?.code === 'UNLEASH_SWARM_OWNER_CHANGED') continue
        throw ownerError('UNLEASH_SWARM_OWNER_SUPERSEDED', 'swarm owner token no longer controls the campaign claim', cause)
      }
      if (current.state === 'EMPTY') {
        throw ownerError('UNLEASH_SWARM_OWNER_SUPERSEDED', 'swarm owner token no longer controls the campaign claim')
      }
      if (!sameLockIdentity(current, retained.inspected)) {
        throw ownerError('UNLEASH_SWARM_OWNER_SUPERSEDED', 'swarm owner token no longer controls the campaign claim')
      }
      if (current.state === 'CLAIM_PUBLICATION_TAIL') {
        if (current.owner.owner.owner_id !== owner.owner_id) {
          throw ownerError('UNLEASH_SWARM_OWNER_SUPERSEDED', 'swarm owner token no longer controls the campaign claim')
        }
        if (!await recoverClaimPublicationTail(current, expected)) continue
        continue
      }
      if (current.retirements !== undefined) {
        const live = current.retirements.find(({ retiring }) => (
          observeOwnerLiveness(retiring.retirement, retained.dependencies)
        ))
        if (live !== undefined) {
          throw ownerError('UNLEASH_SWARM_OWNER_SUPERSEDED', 'swarm owner token is already controlled by a live retirement')
        }
        for (const { retiring } of current.retirements) {
          await removeRetirementClaim(current, expected, retiring)
        }
        continue
      }
      if (current.owner?.owner.owner_id !== owner.owner_id) {
        throw ownerError('UNLEASH_SWARM_OWNER_SUPERSEDED', 'swarm owner token no longer controls the campaign claim')
      }
      if (await retireOwner(
        current,
        expected,
        retained.dependencies,
        (retirement) => { retained.retirement = retirement },
      )) {
        released = true
        return
      }
    }
    throw ownerError('UNLEASH_SWARM_OWNER_CHANGED', 'swarm owner changed repeatedly during exact release')
  } catch (cause) {
    await reconcileReleaseFailure(owner, retained, expected)
    throw cause
  } finally {
    if (released) tokenState.delete(owner)
  }
}

export async function releaseUnleashSwarmOwner(owner) {
  const retained = tokenState.get(owner)
  if (retained === undefined) {
    throw ownerError('UNLEASH_SWARM_OWNER_TOKEN_INVALID', 'swarm owner token was not issued by this controller process')
  }
  if (retained.releasePromise !== undefined) return retained.releasePromise
  const releasePromise = performUnleashSwarmOwnerRelease(owner, retained)
  retained.releasePromise = releasePromise
  try {
    return await releasePromise
  } finally {
    if (
      tokenState.get(owner) === retained
      && retained.releasePromise === releasePromise
    ) retained.releasePromise = undefined
  }
}

export function bindUnleashSwarmOwnerStorage(storage, owner) {
  if (
    storage === null
    || typeof storage !== 'object'
    || typeof storage.writeImmutableJson !== 'function'
    || typeof storage.replaceMutableJson !== 'function'
    || typeof storage.readJson !== 'function'
    || typeof storage.listJsonFilenames !== 'function'
    || !samePath(storage.campaign_directory, owner?.campaign_directory ?? '')
  ) throw ownerError('UNLEASH_SWARM_OWNER_STORAGE_INVALID', 'swarm owner cannot bind an invalid or different campaign storage')
  return Object.freeze({
    runs_root: storage.runs_root,
    campaign_directory: storage.campaign_directory,
    writeImmutableJson: async (...args) => {
      await assertUnleashSwarmOwner(owner)
      return storage.writeImmutableJson(...args)
    },
    replaceMutableJson: async (...args) => {
      await assertUnleashSwarmOwner(owner)
      return storage.replaceMutableJson(...args)
    },
    readJson: (...args) => storage.readJson(...args),
    listJsonFilenames: (...args) => storage.listJsonFilenames(...args),
  })
}
