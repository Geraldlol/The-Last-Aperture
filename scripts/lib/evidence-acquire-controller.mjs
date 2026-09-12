import { createHash, randomUUID } from 'node:crypto'
import { constants as fsConstants } from 'node:fs'
import { lstat, mkdir, open, realpath, rename, rm } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { compareCanonicalStrings } from './canonical-order.mjs'
import { resolveEvidenceAdapter } from './evidence-adapters.mjs'
import { EVIDENCE_MANIFEST_FILE, loadEvidenceBundle, verifyEvidenceBundle } from './evidence-bundle.mjs'
import { createArtifactAdapter } from './evidence-adapters/artifact.mjs'
import { createRegistryAdapter } from './evidence-adapters/registry.mjs'
import { createDeployedAdapter } from './evidence-adapters/deployed.mjs'
import { createRuntimeAdapter } from './evidence-adapters/runtime.mjs'
import {
  publishFileCreateOnlyDurably,
  replaceFileDurably,
  syncRecoverableDirectoryChange,
} from './durable-file-publication.mjs'

const PLAN_FILE = 'acquisition-plan.json'
const STATE_FILE = 'acquisition-state.json'
const STOP_FILE = 'acquisition-stop.json'
const RECEIPT_FILE = 'execution-receipt.json'
const LOCK_FILE = '.acquisition-lock'
const LOCK_RECLAIM_FILE = '.acquisition-lock-reclaim'
const MAX_LOCK_BYTES = 4096
const LOCK_RECLAIM_ATTEMPTS = 32
const LOCK_ACQUIRE_ATTEMPTS = 8
const MAX_CONTROL_BYTES = 4 * 1024 * 1024
const OPEN_READ_FLAGS = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0)
const OPEN_WRITE_FLAGS = fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL
  | (fsConstants.O_NOFOLLOW ?? 0)

const ADAPTER_FACTORIES = new Map([
  ['artifact', createArtifactAdapter],
  ['registry', createRegistryAdapter],
  ['deployed', createDeployedAdapter],
  ['runtime', createRuntimeAdapter],
])

export class AcquisitionError extends Error {
  constructor(code, message) {
    super(message)
    this.name = 'AcquisitionError'
    this.code = code
  }
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize)
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort(compareCanonicalStrings)
      .map((key) => [key, canonicalize(value[key])]))
  }
  return value
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value))
}

function sha256Json(value) {
  return createHash('sha256').update(canonicalJson(value)).digest('hex')
}

function immutablePlanRecord(record) {
  return {
    schema: record.schema,
    adapter_id: record.adapter_id,
    evidence_class: record.evidence_class,
    adapter_profile: record.adapter_profile,
    plan: record.plan,
  }
}

export function acquisitionPlanDigest(record) {
  return sha256Json(immutablePlanRecord(record))
}

function executionReceiptDigest(receipt) {
  const { receipt_sha256: _digest, ...material } = receipt
  return sha256Json(material)
}

function sameFile(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size
    && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs && left.nlink === right.nlink
}

function samePath(left, right) {
  return process.platform === 'win32' ? left.toLowerCase() === right.toLowerCase() : left === right
}

async function createSafeDirectoryTree(path) {
  const missing = []
  let current = resolve(path)
  while (true) {
    let metadata
    try {
      metadata = await lstat(current, { bigint: true })
    } catch (error) {
      if (error?.code !== 'ENOENT') {
        throw new AcquisitionError('ACQUISITION_ROOT_UNSAFE',
          `acquisition ancestor is unsafe: ${error?.code ?? error?.message}`)
      }
      missing.push(current)
      const parent = dirname(current)
      if (parent === current) {
        throw new AcquisitionError('ACQUISITION_ROOT_UNSAFE', 'no safe acquisition ancestor exists')
      }
      current = parent
      continue
    }
    let canonical
    try {
      canonical = await realpath(current)
    } catch (error) {
      throw new AcquisitionError('ACQUISITION_ROOT_UNSAFE',
        `acquisition ancestor cannot be resolved safely: ${error?.code ?? error?.message}`)
    }
    if (!metadata.isDirectory() || metadata.isSymbolicLink() || !samePath(canonical, current)) {
      throw new AcquisitionError('ACQUISITION_ROOT_UNSAFE',
        `acquisition ancestor is linked or non-canonical: ${current}`)
    }
    break
  }
  for (const directory of missing.reverse()) {
    try {
      await mkdir(directory, { recursive: false, mode: 0o700 })
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error
    }
    const metadata = await lstat(directory, { bigint: true })
    const canonical = await realpath(directory)
    if (!metadata.isDirectory() || metadata.isSymbolicLink() || !samePath(canonical, directory)) {
      throw new AcquisitionError('ACQUISITION_ROOT_UNSAFE',
        `created acquisition ancestor is linked or non-canonical: ${directory}`)
    }
  }
}

async function ensureSafeRoot(bundle, { create = false } = {}) {
  const directory = resolve(bundle)
  if (create) await createSafeDirectoryTree(directory)
  let metadata
  let canonical
  try {
    metadata = await lstat(directory, { bigint: true })
    canonical = await realpath(directory)
  } catch (error) {
    if (error?.code === 'ENOENT') {
      throw new AcquisitionError('ACQUISITION_ROOT_MISSING',
        `acquisition root is absent: ${directory}`)
    }
    throw new AcquisitionError('ACQUISITION_ROOT_UNSAFE',
      `acquisition root is unsafe: ${error?.code ?? error?.message}`)
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || !samePath(canonical, directory)) {
    throw new AcquisitionError('ACQUISITION_ROOT_UNSAFE',
      'acquisition root must be one canonical local directory')
  }
  return directory
}

async function writeBytesExclusively(path, bytes) {
  let handle
  let metadata
  try {
    handle = await open(path, OPEN_WRITE_FLAGS, 0o600)
    let offset = 0
    while (offset < bytes.length) {
      const { bytesWritten } = await handle.write(bytes, offset, bytes.length - offset, offset)
      if (bytesWritten < 1) throw new Error('control-file write made no progress')
      offset += bytesWritten
    }
    await handle.sync()
    metadata = await handle.stat({ bigint: true })
    if (!metadata.isFile() || metadata.nlink !== 1n || metadata.size !== BigInt(bytes.length)) {
      throw new Error('control-file identity changed during write')
    }
  } finally {
    await handle?.close()
  }
  return metadata
}

async function atomicWriteJson(bundle, file, value, { replace = false } = {}) {
  const directory = await ensureSafeRoot(bundle, { create: true })
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8')
  if (bytes.length > MAX_CONTROL_BYTES) {
    throw new AcquisitionError('ACQUISITION_CONTROL_TOO_LARGE', `${file} exceeds its bounded limit`)
  }
  const target = join(directory, file)
  const temporary = join(directory, `.${file}.${randomUUID()}.tmp`)
  try {
    await writeBytesExclusively(temporary, bytes)
    if (replace) {
      const current = await lstat(target, { bigint: true })
      if (!current.isFile() || current.isSymbolicLink() || current.nlink !== 1n) {
        throw new AcquisitionError('ACQUISITION_CONTROL_INVALID',
          `${file} must remain one regular, unlinked file before replacement`)
      }
      await replaceFileDurably(temporary, target)
      const published = await lstat(target, { bigint: true })
      if (!published.isFile() || published.isSymbolicLink() || published.nlink !== 1n
        || published.size !== BigInt(bytes.length)) {
        throw new AcquisitionError('ACQUISITION_CONTROL_WRITE_FAILED',
          `${file} identity changed during atomic replacement`)
      }
    }
    else {
      await publishFileCreateOnlyDurably(temporary, target)
    }
  } catch (error) {
    await rm(temporary, { force: true })
    if (error instanceof AcquisitionError) throw error
    const code = error?.code === 'EEXIST' ? 'ACQUISITION_CONTROL_EXISTS' : 'ACQUISITION_CONTROL_WRITE_FAILED'
    throw new AcquisitionError(code, `atomic publication of ${file} failed: ${error?.code ?? error?.message}`)
  }
  return value
}

async function readBoundedJson(bundle, file, {
  missingCode = 'ACQUISITION_CONTROL_MISSING',
  invalidCode = 'ACQUISITION_CONTROL_INVALID',
  missingOkay = false,
} = {}) {
  const directory = await ensureSafeRoot(bundle)
  const path = join(directory, file)
  let before
  try {
    before = await lstat(path, { bigint: true })
  } catch (error) {
    if (missingOkay && error?.code === 'ENOENT') return null
    throw new AcquisitionError(missingCode, `${file} is absent or unreadable: ${error?.code ?? error?.message}`)
  }
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n) {
    throw new AcquisitionError(invalidCode, `${file} must be one regular, unlinked file`)
  }
  if (before.size > BigInt(MAX_CONTROL_BYTES)) {
    throw new AcquisitionError(invalidCode, `${file} exceeds its bounded limit`)
  }
  let handle
  let bytes
  try {
    handle = await open(path, OPEN_READ_FLAGS)
    const heldBefore = await handle.stat({ bigint: true })
    if (!heldBefore.isFile() || heldBefore.nlink !== 1n || !sameFile(before, heldBefore)) {
      throw new AcquisitionError(invalidCode, `${file} identity changed before reading`)
    }
    bytes = Buffer.alloc(Number(heldBefore.size))
    let offset = 0
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset)
      if (bytesRead < 1) break
      offset += bytesRead
    }
    const heldAfter = await handle.stat({ bigint: true })
    if (offset !== bytes.length || !sameFile(heldBefore, heldAfter)) {
      throw new AcquisitionError(invalidCode, `${file} changed while reading`)
    }
  } catch (error) {
    if (error instanceof AcquisitionError) throw error
    throw new AcquisitionError(invalidCode, `${file} could not be opened safely: ${error?.code ?? error?.message}`)
  } finally {
    await handle?.close()
  }
  try {
    return JSON.parse(bytes.toString('utf8'))
  } catch {
    throw new AcquisitionError(invalidCode, `${file} is unparseable or invalid JSON`)
  }
}

function delay(milliseconds) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds))
}

function processIsAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid < 1) return false
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    return error?.code !== 'ESRCH'
  }
}

function lockRecord() {
  return {
    schema_version: '1.0.0',
    pid: process.pid,
    acquired_at: new Date().toISOString(),
    nonce: randomUUID(),
  }
}

function validateLockRecord(snapshot, label) {
  let record
  try {
    record = JSON.parse(snapshot.bytes.toString('utf8'))
  } catch {
    throw new AcquisitionError('ACQUISITION_LOCK_UNSAFE', `${label} is not valid JSON`)
  }
  if (
    record === null
    || typeof record !== 'object'
    || Array.isArray(record)
    || Object.getPrototypeOf(record) !== Object.prototype
    || Object.keys(record).sort().join(',') !== 'acquired_at,nonce,pid,schema_version'
    || record.schema_version !== '1.0.0'
    || !Number.isSafeInteger(record.pid)
    || record.pid < 1
    || typeof record.nonce !== 'string'
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(record.nonce)
    || typeof record.acquired_at !== 'string'
    || Number.isNaN(Date.parse(record.acquired_at))
    || new Date(record.acquired_at).toISOString() !== record.acquired_at
    || snapshot.bytes.toString('utf8') !== canonicalJson(record)
  ) {
    throw new AcquisitionError('ACQUISITION_LOCK_UNSAFE', `${label} is malformed or non-canonical`)
  }
  return record
}

async function readLockSnapshot(path, label) {
  let before
  try {
    before = await lstat(path, { bigint: true })
  } catch (error) {
    throw new AcquisitionError(
      error?.code === 'ENOENT' ? 'ACQUISITION_LOCK_MISSING' : 'ACQUISITION_LOCK_UNSAFE',
      `${label} is absent or unreadable: ${error?.code ?? error?.message}`,
    )
  }
  if (!before.isFile() || before.isSymbolicLink() || ![1n, 2n].includes(before.nlink)
    || before.size < 1n || before.size > BigInt(MAX_LOCK_BYTES)) {
    throw new AcquisitionError('ACQUISITION_LOCK_UNSAFE', `${label} is not one bounded regular file`)
  }
  let handle
  let bytes
  try {
    handle = await open(path, OPEN_READ_FLAGS)
    const opened = await handle.stat({ bigint: true })
    if (!opened.isFile() || ![1n, 2n].includes(opened.nlink) || !sameFile(before, opened)) {
      throw new AcquisitionError('ACQUISITION_LOCK_CHANGED', `${label} changed before reading`)
    }
    bytes = Buffer.alloc(Number(opened.size))
    let offset = 0
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset)
      if (bytesRead < 1) break
      offset += bytesRead
    }
    const heldAfter = await handle.stat({ bigint: true })
    const endpointAfter = await lstat(path, { bigint: true })
    if (offset !== bytes.length || !sameFile(opened, heldAfter) || !sameFile(heldAfter, endpointAfter)) {
      throw new AcquisitionError('ACQUISITION_LOCK_CHANGED', `${label} changed while reading`)
    }
    return { path, info: heldAfter, bytes }
  } catch (error) {
    if (error instanceof AcquisitionError) throw error
    throw new AcquisitionError(
      error?.code === 'ENOENT' ? 'ACQUISITION_LOCK_CHANGED' : 'ACQUISITION_LOCK_UNSAFE',
      `${label} could not be read safely: ${error?.code ?? error?.message}`,
    )
  } finally {
    await handle?.close()
  }
}

function lockSnapshotMatches(left, right) {
  return left.info.dev === right.info.dev
    && left.info.ino === right.info.ino
    && left.info.size === right.info.size
    && left.info.mtimeNs === right.info.mtimeNs
    && left.info.nlink === right.info.nlink
    && left.bytes.equals(right.bytes)
}

function publishedLockMatches(snapshot, created, bytes) {
  return snapshot.info.dev === created.dev
    && snapshot.info.ino === created.ino
    && snapshot.info.size === created.size
    && snapshot.info.mtimeNs === created.mtimeNs
    && snapshot.bytes.equals(bytes)
}

function privateLockTemporary(directory, kind) {
  return join(dirname(directory), `.last-aperture-${kind}-${process.pid}-${randomUUID()}.tmp`)
}

async function createPublishedLock(directory, file, label, faultInjector, publicationPhase) {
  const target = join(directory, file)
  const temporary = privateLockTemporary(directory, file.replaceAll('.', '') || 'lock')
  const record = lockRecord()
  const bytes = Buffer.from(canonicalJson(record), 'utf8')
  let created
  let failure
  let snapshot
  try {
    created = await writeBytesExclusively(temporary, bytes)
    await publishFileCreateOnlyDurably(temporary, target)
    await faultInjector?.(publicationPhase, { path: target })
    snapshot = await readLockSnapshot(target, label)
    validateLockRecord(snapshot, label)
    if (snapshot.info.nlink !== 1n || !publishedLockMatches(snapshot, created, bytes)) {
      throw new AcquisitionError('ACQUISITION_LOCK_CHANGED', `${label} changed during publication`)
    }
  } catch (error) {
    failure = error
  } finally {
    await rm(temporary, { force: true }).catch(() => {})
  }
  if (failure) {
    if (created !== undefined) {
      let visible
      try {
        visible = await readLockSnapshot(target, label)
      } catch {
        // An absent, malformed, or replaced target cannot be proven to be ours.
        // Leave it untouched and preserve the publication failure.
      }
      if (visible && publishedLockMatches(visible, created, bytes)) {
        try {
          await quarantineExpectedLock({
            path: target,
            expected: visible,
            phase: 'before-acquisition-lock-failed-publication-quarantine',
            suffix: 'failed',
          })
        } catch (cleanupError) {
          throw new AggregateError(
            [failure, cleanupError],
            `${label} publication failed and its exact visible owner could not be removed`,
          )
        }
      }
    }
    throw failure
  }
  return snapshot
}

async function renameLockWithRetry(source, destination) {
  const deadline = Date.now() + 2_000
  while (true) {
    try {
      await rename(source, destination)
      return
    } catch (error) {
      if (process.platform === 'win32'
        && ['EACCES', 'EBUSY', 'EPERM'].includes(error?.code)
        && Date.now() < deadline) {
        await delay(10)
        continue
      }
      throw error
    }
  }
}

async function quarantineExpectedLock({ path, expected, faultInjector, phase, suffix }) {
  await faultInjector?.(phase, { path })
  // Keep crash residue outside the evidence root so an interrupted quarantine
  // cannot permanently make an otherwise valid bundle unpublishable. The
  // bundle's parent is on the same filesystem, preserving atomic rename.
  const quarantine = privateLockTemporary(dirname(path), `${suffix}-quarantine`)
  try {
    await renameLockWithRetry(path, quarantine)
  } catch (error) {
    throw new AcquisitionError(
      error?.code === 'ENOENT' ? 'ACQUISITION_LOCK_CHANGED' : 'ACQUISITION_LOCK_RELEASE_FAILED',
      `acquisition lock could not be quarantined safely: ${error?.code ?? error?.message}`,
    )
  }
  await syncRecoverableDirectoryChange(dirname(path))
  await syncRecoverableDirectoryChange(dirname(quarantine))
  const afterPhase = phase.startsWith('before-') ? `after-${phase.slice(7)}` : `${phase}-complete`
  await faultInjector?.(afterPhase, { path, quarantine })
  try {
    const current = await readLockSnapshot(quarantine, 'quarantined acquisition lock')
    if (!lockSnapshotMatches(current, expected)) {
      throw new AcquisitionError('ACQUISITION_LOCK_CHANGED', 'acquisition lock was replaced before quarantine')
    }
  } catch (error) {
    try {
      await publishFileCreateOnlyDurably(quarantine, path)
    } catch (restoreError) {
      throw new AcquisitionError('ACQUISITION_LOCK_CHANGED',
        `replacement acquisition lock could not be restored: ${restoreError?.code ?? restoreError?.message}`)
    }
    throw error
  }
  await rm(quarantine)
  await syncRecoverableDirectoryChange(dirname(quarantine))
}

async function acquireReclaimGuard(directory) {
  const path = join(directory, LOCK_RECLAIM_FILE)
  let lastError
  for (let attempt = 0; attempt < LOCK_RECLAIM_ATTEMPTS; attempt += 1) {
    try {
      return await createPublishedLock(directory, LOCK_RECLAIM_FILE, 'acquisition reclaim guard')
    } catch (error) {
      if (!['EEXIST', 'EPERM'].includes(error?.code)) throw error
      lastError = error
    }
    let observed
    try {
      observed = await readLockSnapshot(path, 'acquisition reclaim guard')
      const owner = validateLockRecord(observed, 'acquisition reclaim guard')
      if (!processIsAlive(owner.pid)) {
        await quarantineExpectedLock({
          path,
          expected: observed,
          phase: 'before-acquisition-reclaim-guard-stale-quarantine',
          suffix: 'stale',
        })
        continue
      }
    } catch (error) {
      if (!['ACQUISITION_LOCK_MISSING', 'ACQUISITION_LOCK_CHANGED'].includes(error?.code)) throw error
      lastError = error
    }
    await delay(2)
  }
  throw new AcquisitionError('ACQUISITION_LOCK_RECLAIM_BUSY',
    `acquisition stale-lock recovery remained contended: ${lastError?.code ?? 'busy'}`)
}

async function releaseReclaimGuard(guard, faultInjector) {
  await quarantineExpectedLock({
    path: guard.path,
    expected: guard,
    faultInjector,
    phase: 'before-acquisition-reclaim-guard-release-quarantine',
    suffix: 'release',
  })
}

async function acquireAcquisitionLock(directory, faultInjector) {
  const path = join(directory, LOCK_FILE)
  for (let attempt = 0; attempt < LOCK_ACQUIRE_ATTEMPTS; attempt += 1) {
    try {
      return await createPublishedLock(
        directory,
        LOCK_FILE,
        'acquisition lock',
        faultInjector,
        'after-acquisition-lock-published',
      )
    } catch (error) {
      if (!['EEXIST', 'EPERM'].includes(error?.code)) throw error
    }
    await faultInjector?.('after-acquisition-lock-collision', { path })
    const guard = await acquireReclaimGuard(directory)
    try {
      let observed
      try {
        observed = await readLockSnapshot(path, 'acquisition lock')
      } catch (error) {
        if (['ACQUISITION_LOCK_MISSING', 'ACQUISITION_LOCK_CHANGED'].includes(error?.code)) continue
        throw error
      }
      const owner = validateLockRecord(observed, 'acquisition lock')
      if (processIsAlive(owner.pid)) {
        throw new AcquisitionError('ACQUISITION_BUSY', 'another acquisition transition owns this bundle')
      }
      const current = await readLockSnapshot(path, 'acquisition lock')
      if (!lockSnapshotMatches(current, observed)) continue
      await quarantineExpectedLock({
        path,
        expected: observed,
        faultInjector,
        phase: 'before-acquisition-lock-stale-quarantine',
        suffix: 'stale',
      })
    } finally {
      await releaseReclaimGuard(guard, faultInjector)
    }
  }
  throw new AcquisitionError('ACQUISITION_BUSY', 'acquisition bundle lock remained contended')
}

async function releaseAcquisitionLock(lock, faultInjector) {
  try {
    await quarantineExpectedLock({
      path: lock.path,
      expected: lock,
      faultInjector,
      phase: 'before-acquisition-lock-release-quarantine',
      suffix: 'release',
    })
  } catch (error) {
    if (error instanceof AcquisitionError
      && ['ACQUISITION_LOCK_CHANGED', 'ACQUISITION_LOCK_UNSAFE'].includes(error.code)) {
      throw new AcquisitionError('ACQUISITION_LOCK_CHANGED',
        'acquisition lock changed while the controller held it')
    }
    throw new AcquisitionError('ACQUISITION_LOCK_RELEASE_FAILED',
      `acquisition lock could not be released safely: ${error?.code ?? error?.message}`)
  }
}

async function withAcquisitionLock(bundle, callback, { faultInjector } = {}) {
  if (faultInjector !== undefined && typeof faultInjector !== 'function') {
    throw new TypeError('acquisition lock fault injector must be a function')
  }
  const directory = await ensureSafeRoot(bundle, { create: true })
  const lock = await acquireAcquisitionLock(directory, faultInjector)
  let callbackError
  try {
    await faultInjector?.('after-acquisition-lock-acquired', { path: lock.path })
    return await callback(directory)
  } catch (error) {
    callbackError = error
    throw error
  } finally {
    try {
      await releaseAcquisitionLock(lock, faultInjector)
    } catch (releaseError) {
      if (callbackError) {
        throw new AggregateError([callbackError, releaseError],
          'acquisition transition failed and its exact lock could not be released')
      }
      throw releaseError
    }
  }
}

function assertPlanIntegrity(record, expectedPlanSha256) {
  if (record?.schema === 'evidence-acquisition-plan-v1') {
    throw new AcquisitionError('ACQUISITION_PLAN_MIGRATION_REQUIRED',
      'legacy acquisition-plan-v1 cannot execute; create a deterministic v2 plan')
  }
  if (record?.schema !== 'evidence-acquisition-plan-v2') {
    throw new AcquisitionError('ACQUISITION_PLAN_SCHEMA_INVALID', 'acquisition plan schema is invalid')
  }
  if (!/^[a-f0-9]{64}$/.test(record.plan_sha256 ?? '')) {
    throw new AcquisitionError('ACQUISITION_PLAN_DIGEST_INVALID', 'acquisition plan is missing its immutable digest')
  }
  const actual = acquisitionPlanDigest(record)
  if (actual !== record.plan_sha256 || (expectedPlanSha256 && actual !== expectedPlanSha256)) {
    throw new AcquisitionError('ACQUISITION_PLAN_DIGEST_MISMATCH',
      'acquisition plan no longer matches the caller-approved immutable plan')
  }
  if (record.adapter_profile === null || typeof record.adapter_profile !== 'object'
    || record.plan?.execution_profile === null || typeof record.plan?.execution_profile !== 'object') {
    throw new AcquisitionError('ACQUISITION_EXECUTION_PROFILE_MISSING',
      'acquisition plan does not bind its adapter version and execution profile')
  }
}

function assertState(state, planSha256) {
  if (state?.schema !== 'evidence-acquisition-state-v1' || state.plan_sha256 !== planSha256
    || !['PLANNED', 'RUNNING', 'ACQUIRED'].includes(state.state)) {
    throw new AcquisitionError('ACQUISITION_STATE_INVALID',
      'acquisition state is invalid or belongs to another plan')
  }
  return state
}

async function readPlanFile(bundle) {
  return readBoundedJson(bundle, PLAN_FILE, {
    missingCode: 'ACQUISITION_PLAN_MISSING', invalidCode: 'ACQUISITION_PLAN_INVALID',
  })
}

async function readStateFile(bundle, planSha256) {
  return assertState(await readBoundedJson(bundle, STATE_FILE, {
    missingCode: 'ACQUISITION_STATE_MISSING', invalidCode: 'ACQUISITION_STATE_INVALID',
  }), planSha256)
}

export async function isAcquisitionStopped(bundle) {
  let marker
  try {
    marker = await readBoundedJson(bundle, STOP_FILE, {
      invalidCode: 'ACQUISITION_STOP_STATE_INVALID', missingOkay: true,
    })
  } catch (error) {
    if (error?.code === 'ACQUISITION_ROOT_MISSING') return false
    throw error
  }
  if (marker === null) return false
  if (marker?.schema !== 'evidence-acquisition-stop-v1' || marker.state !== 'STOPPED') {
    throw new AcquisitionError('ACQUISITION_STOP_STATE_INVALID', 'acquisition stop marker is invalid')
  }
  return true
}

function assertAdapterProfile(record, adapter) {
  if (canonicalJson(record.adapter_profile) !== canonicalJson(adapter.describe())) {
    throw new AcquisitionError('ACQUISITION_ADAPTER_PROFILE_MISMATCH',
      'planned adapter version/profile does not match the executing adapter')
  }
}

function assertRoute(record, expectedAdapterId) {
  const routed = resolveEvidenceAdapter(expectedAdapterId)
  if (record.adapter_id !== expectedAdapterId) {
    throw new AcquisitionError('ACQUISITION_ADAPTER_MISMATCH',
      `acquisition plan adapter "${record.adapter_id}" does not match expected adapter "${expectedAdapterId}"`)
  }
  if (record.evidence_class !== routed.evidence_class
    || record.plan?.evidence_context_seed?.adapter_id !== expectedAdapterId
    || record.plan?.evidence_context_seed?.evidence_class !== routed.evidence_class) {
    throw new AcquisitionError('ACQUISITION_PLAN_ROUTE_MISMATCH',
      'acquisition plan adapter and evidence class do not match the canonical route')
  }
  return routed
}

function receiptBinding(record) {
  return {
    plan_sha256: record.plan_sha256,
    adapter_profile: record.adapter_profile,
    execution_profile: record.plan.execution_profile,
    evidence_class: record.evidence_class,
    evidence_context_seed: record.plan.evidence_context_seed,
    target_class: record.plan.target_class,
    phi_scope: record.plan.phi_scope,
    source_integrity: record.plan.source_integrity ?? null,
    image_reference: record.plan.image_reference ?? null,
    context: record.plan.context ?? null,
  }
}

function buildExecutionReceipt(record, written, operatorId, authorizationConfirmed, runNonce) {
  const receipt = {
    schema: 'evidence-acquisition-execution-receipt-v1',
    run_nonce: runNonce,
    ...receiptBinding(record),
    bundle_root_sha256: written.root_sha256,
    result_evidence_context: written.profile.evidence_context,
    run_authorization: record.plan.authorization_gate ? {
      mode: record.plan.authorization_gate.mode,
      current_authorization_confirmed: authorizationConfirmed === true,
      third_party_acknowledged: record.plan.authorization_gate.acknowledge_third_party === true,
      confirmed_by: operatorId ?? null,
    } : null,
  }
  receipt.receipt_sha256 = executionReceiptDigest(receipt)
  return receipt
}

function assertExecutionReceipt(receipt, record, state) {
  if (receipt?.schema !== 'evidence-acquisition-execution-receipt-v1'
    || typeof receipt.run_nonce !== 'string'
    || receipt.run_nonce !== state?.run_nonce
    || !/^[a-f0-9]{64}$/.test(receipt.receipt_sha256 ?? '')
    || executionReceiptDigest(receipt) !== receipt.receipt_sha256) {
    throw new AcquisitionError('ACQUISITION_RECEIPT_INVALID',
      'execution receipt is missing or has invalid integrity')
  }
  const expected = receiptBinding(record)
  const actual = Object.fromEntries(Object.keys(expected).map((key) => [key, receipt[key]]))
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    throw new AcquisitionError('ACQUISITION_RECEIPT_PLAN_MISMATCH',
      'execution receipt does not bind the complete immutable acquisition plan')
  }
  return receipt
}

async function assertNoPriorExecutionArtifacts(directory) {
  for (const name of [RECEIPT_FILE, EVIDENCE_MANIFEST_FILE, 'payload']) {
    try {
      await lstat(join(directory, name), { bigint: true })
    } catch (error) {
      if (error?.code === 'ENOENT') continue
      throw new AcquisitionError('ACQUISITION_OUTPUT_STATE_UNREADABLE',
        `could not establish whether prior acquisition output exists: ${name}`)
    }
    throw new AcquisitionError('ACQUISITION_ALREADY_RUN',
      `prior acquisition output already exists: ${name}`)
  }
}

export async function planAcquisition({ adapterId, request, out, env = process.env, resolver, credentialResolver }) {
  const routed = resolveEvidenceAdapter(adapterId)
  if (routed.selection_status !== 'SELECTED') {
    throw new AcquisitionError('ACQUISITION_ADAPTER_UNKNOWN',
      `unknown adapter "${adapterId}"; an unlisted acquisition target selects inventory-only and cannot be planned`)
  }
  const factory = ADAPTER_FACTORIES.get(adapterId)
  if (!factory) throw new AcquisitionError('ACQUISITION_ADAPTER_UNIMPLEMENTED', `adapter "${adapterId}" is not implemented`)
  const adapter = factory({ env, resolver, credentialResolver })
  const plan = await adapter.plan(request)
  const record = {
    schema: 'evidence-acquisition-plan-v2',
    adapter_id: adapterId,
    evidence_class: routed.evidence_class,
    adapter_profile: adapter.describe(),
    plan,
  }
  record.plan_sha256 = acquisitionPlanDigest(record)
  const directory = resolve(out)
  await withAcquisitionLock(directory, async () => {
    if (await isAcquisitionStopped(directory)) {
      throw new AcquisitionError('ACQUISITION_STOPPED', 'this acquisition was stopped before planning')
    }
    await atomicWriteJson(directory, PLAN_FILE, record)
    await atomicWriteJson(directory, STATE_FILE, {
      schema: 'evidence-acquisition-state-v1', state: 'PLANNED', plan_sha256: record.plan_sha256,
    })
  })
  return { directory, plan, plan_sha256: record.plan_sha256 }
}

export async function runAcquisition({
  bundle, expectedAdapterId, expectedPlanSha256, operatorId, authorizationConfirmed = false,
  env = process.env, resolver, credentialResolver,
}, transitionHooks = {}) {
  if (transitionHooks.afterReceiptPublished !== undefined
    && typeof transitionHooks.afterReceiptPublished !== 'function') {
    throw new TypeError('afterReceiptPublished transition hook must be a function')
  }
  if (transitionHooks.lockFaultInjector !== undefined
    && typeof transitionHooks.lockFaultInjector !== 'function') {
    throw new TypeError('lockFaultInjector transition hook must be a function')
  }
  if (typeof expectedAdapterId !== 'string' || expectedAdapterId.trim() === '') {
    throw new AcquisitionError('ACQUISITION_EXPECTED_ADAPTER_REQUIRED',
      'runAcquisition requires an explicit expectedAdapterId before reading a plan')
  }
  if (!ADAPTER_FACTORIES.has(expectedAdapterId)) {
    throw new AcquisitionError('ACQUISITION_EXPECTED_ADAPTER_UNKNOWN',
      `runAcquisition refuses unknown expected adapter "${expectedAdapterId}"`)
  }
  if (!/^[a-f0-9]{64}$/.test(expectedPlanSha256 ?? '')) {
    throw new AcquisitionError('ACQUISITION_EXPECTED_PLAN_DIGEST_REQUIRED',
      'runAcquisition requires the caller-approved plan digest before reading a plan')
  }

  return withAcquisitionLock(bundle, async (directory) => {
    const record = await readPlanFile(directory)
    assertPlanIntegrity(record, expectedPlanSha256)
    const state = await readStateFile(directory, record.plan_sha256)
    if (state.state === 'ACQUIRED') {
      throw new AcquisitionError('ACQUISITION_ALREADY_RUN', 'this plan already produced a bundle')
    }
    if (state.state === 'RUNNING') {
      throw new AcquisitionError('ACQUISITION_RUN_INCOMPLETE',
        'a prior run may have dispatched; recovery must validate its receipt before any retry')
    }
    if (await isAcquisitionStopped(directory)) {
      throw new AcquisitionError('ACQUISITION_STOPPED', 'this acquisition was stopped and cannot run')
    }
    const routed = assertRoute(record, expectedAdapterId)
    const adapter = ADAPTER_FACTORIES.get(expectedAdapterId)({ env, resolver, credentialResolver })
    assertAdapterProfile(record, adapter)
    if (routed.authorization.operator_identity && !operatorId) {
      throw new AcquisitionError('ACQUISITION_OPERATOR_REQUIRED', 'this class requires a named operator')
    }
    if (routed.authorization.attestation && authorizationConfirmed !== true) {
      throw new AcquisitionError('ACQUISITION_AUTHORIZATION_REQUIRED',
        'this class requires --confirm-authorization-current at run time')
    }
    if (record.plan.target_class === 'THIRD_PARTY') {
      const gate = record.plan.authorization_gate
      if (gate?.mode !== 'INTERIM_OPERATOR_ACKNOWLEDGED_THIRD_PARTY'
        || gate.acknowledge_third_party !== true) {
        throw new AcquisitionError('ACQUISITION_THIRD_PARTY_PLAN_ACKNOWLEDGMENT_MISSING',
          'THIRD_PARTY acquisition plan is missing its exact sealed interim acknowledgment')
      }
    }
    await assertNoPriorExecutionArtifacts(directory)
    const runNonce = randomUUID()
    await atomicWriteJson(directory, STATE_FILE, {
      schema: 'evidence-acquisition-state-v1', state: 'RUNNING',
      plan_sha256: record.plan_sha256, operator_id: operatorId ?? null, run_nonce: runNonce,
    }, { replace: true })
    if (await isAcquisitionStopped(directory)) {
      throw new AcquisitionError('ACQUISITION_STOPPED', 'this acquisition was stopped before dispatch')
    }
    const written = await adapter.run(record.plan, {
      out: directory, authorizationConfirmed, shouldStop: () => isAcquisitionStopped(directory),
    })
    if (written?.profile?.evidence_context?.adapter_id !== expectedAdapterId
      || written?.profile?.evidence_context?.evidence_class !== routed.evidence_class) {
      throw new AcquisitionError('ACQUISITION_RESULT_ROUTE_MISMATCH',
        'acquired evidence does not match the approved adapter and evidence class')
    }
    const receipt = buildExecutionReceipt(
      record,
      written,
      operatorId,
      authorizationConfirmed,
      runNonce,
    )
    await atomicWriteJson(directory, RECEIPT_FILE, receipt)
    // Internal fault-injection/telemetry seam. It receives no receipt material,
    // so it cannot become a second trust channel for recovery.
    await transitionHooks.afterReceiptPublished?.()
    await atomicWriteJson(directory, STATE_FILE, {
      schema: 'evidence-acquisition-state-v1', state: 'ACQUIRED', plan_sha256: record.plan_sha256,
      receipt_sha256: receipt.receipt_sha256, root_sha256: written.root_sha256,
      run_nonce: runNonce,
    }, { replace: true })
    return { ...written, execution_receipt_sha256: receipt.receipt_sha256 }
  }, { faultInjector: transitionHooks.lockFaultInjector })
}

export async function validateAcquisition(bundle) {
  return { path: resolve(bundle), ...(await verifyEvidenceBundle(bundle)) }
}

export async function finalizeAcquisition(bundle, {
  expectedAdapterId,
  expectedPlanSha256,
  expectedReceiptSha256,
} = {}) {
  if (typeof expectedAdapterId !== 'string' || expectedAdapterId.trim() === '') {
    throw new AcquisitionError('ACQUISITION_EXPECTED_ADAPTER_REQUIRED',
      'finalizeAcquisition requires an explicit expectedAdapterId before reading a plan')
  }
  if (!ADAPTER_FACTORIES.has(expectedAdapterId)) {
    throw new AcquisitionError('ACQUISITION_EXPECTED_ADAPTER_UNKNOWN',
      `finalizeAcquisition refuses unknown expected adapter "${expectedAdapterId}"`)
  }
  if (!/^[a-f0-9]{64}$/.test(expectedPlanSha256 ?? '')) {
    throw new AcquisitionError('ACQUISITION_EXPECTED_PLAN_DIGEST_REQUIRED',
      'finalizeAcquisition requires the caller-approved plan digest before reading a plan')
  }
  if (!/^[a-f0-9]{64}$/.test(expectedReceiptSha256 ?? '')) {
    throw new AcquisitionError('ACQUISITION_EXPECTED_RECEIPT_DIGEST_REQUIRED',
      'finalizeAcquisition requires the receipt digest returned by the trusted run before reading a plan')
  }
  return withAcquisitionLock(bundle, async (directory) => {
    const record = await readPlanFile(directory)
    assertPlanIntegrity(record, expectedPlanSha256)
    assertRoute(record, expectedAdapterId)
    const state = await readStateFile(directory, record.plan_sha256)
    if (state.state === 'PLANNED') {
      throw new AcquisitionError('ACQUISITION_NOT_ACQUIRED', 'finalize requires a completed acquisition')
    }
    if (state.state === 'RUNNING') {
      throw new AcquisitionError('ACQUISITION_RUN_INCOMPLETE',
        'a RUNNING acquisition never returned a caller-trusted receipt digest and cannot be finalized')
    }
    const receipt = assertExecutionReceipt(await readBoundedJson(directory, RECEIPT_FILE, {
      missingCode: 'ACQUISITION_RECEIPT_MISSING', invalidCode: 'ACQUISITION_RECEIPT_INVALID',
    }), record, state)
    if (receipt.receipt_sha256 !== expectedReceiptSha256) {
      throw new AcquisitionError('ACQUISITION_RECEIPT_DIGEST_MISMATCH',
        'execution receipt does not match the digest returned by the trusted run')
    }
    if (state.state === 'ACQUIRED' && (
      state.receipt_sha256 !== receipt.receipt_sha256
      || state.root_sha256 !== receipt.bundle_root_sha256
    )) {
      throw new AcquisitionError('ACQUISITION_STATE_RECEIPT_MISMATCH', 'state does not bind the execution receipt')
    }
    let read
    try {
      read = await loadEvidenceBundle(directory)
    } catch (error) {
      if (error?.code !== 'EVIDENCE_BUNDLE_INVALID') throw error
      throw new AcquisitionError('ACQUISITION_INVALID',
        'the bundle did not verify; finalize refuses evidence of uncertain provenance')
    }
    const routed = resolveEvidenceAdapter(record.adapter_id)
    if (routed.selection_status !== 'SELECTED' || routed.evidence_class !== record.evidence_class
      || read.evidence_context.adapter_id !== record.adapter_id
      || read.evidence_context.evidence_class !== record.evidence_class
      || read.root_sha256 !== receipt.bundle_root_sha256
      || canonicalJson(read.evidence_context) !== canonicalJson(receipt.result_evidence_context)) {
      throw new AcquisitionError('ACQUISITION_RECORD_MISMATCH',
        'finalize refuses a bundle that does not match its trusted execution receipt')
    }
    return {
      directory, state: 'ACQUIRED', evidence_id: read.evidence_context.evidence_id,
      evidence_class: read.evidence_context.evidence_class, coverage_state: read.profile.coverage_state,
      root_sha256: read.root_sha256,
    }
  })
}

export async function requestAcquisitionStop({ bundle, operatorId, reason }) {
  const directory = await ensureSafeRoot(bundle, { create: true })
  const marker = {
    schema: 'evidence-acquisition-stop-v1', state: 'STOPPED',
    stopped_by: operatorId ?? null, stop_reason: reason ?? null,
  }
  try {
    return await atomicWriteJson(directory, STOP_FILE, marker)
  } catch (error) {
    if (error?.code !== 'ACQUISITION_CONTROL_EXISTS') throw error
    const existing = await readBoundedJson(directory, STOP_FILE, {
      invalidCode: 'ACQUISITION_STOP_STATE_INVALID',
    })
    if (existing?.schema !== marker.schema || existing.state !== 'STOPPED') {
      throw new AcquisitionError('ACQUISITION_STOP_STATE_INVALID', 'existing stop marker is invalid')
    }
    return existing
  }
}
