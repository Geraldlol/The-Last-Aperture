import { constants as fsConstants } from 'node:fs'
import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto'
import {
  link,
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  rename,
  rmdir,
  stat,
  unlink,
} from 'node:fs/promises'
import { dirname, isAbsolute, join, resolve } from 'node:path'

import {
  canonicalJson,
  httpAuthedAuthorizationEvidence,
} from './http-authed-contracts.mjs'
import {
  HTTP_AUTHED_JSON_SHAPE_FAILURE_STAGE,
  assertHttpAuthedResponseByteBucket,
  sanitizeHttpAuthedHeaderNames,
} from './http-authed-response-metadata.mjs'
import { sanitizeHttpAuthedJsonShape } from './http-authed-json-shape.mjs'
import { stableJson } from './run-engine.mjs'

const RECORD_KIND = 'red-team-audit/http-authed-campaign-record'
const JSON_SHAPE_RECORD_SCHEMA_VERSION = '1.3.0'
const CURRENT_RECORD_SCHEMA_VERSION = '1.4.0'
const SUPPORTED_RECORD_SCHEMA_VERSIONS = new Set([
  '1.2.0',
  JSON_SHAPE_RECORD_SCHEMA_VERSION,
  CURRENT_RECORD_SCHEMA_VERSION,
])
const RECORD_NAME = /^(\d{16})\.http-authed-campaign\.json$/
const TEMPORARY_NAME = /^\.(\d{16}\.http-authed-campaign\.json)\.tmp-\d+-[a-f0-9]{24}$/
const LOCK_DIRECTORY = '.http-authed-campaign.lock'
const LOCK_OWNER = 'owner.json'
const SESSION_CONFIRMATION = 'CURRENT_AUTHORIZATION_CONFIRMED'
const CLEANUP_SESSION_CONFIRMATION = 'CLEANUP_ONLY_CONFIRMED'
const DISCOVERED_CANDIDATE_IDENTITY_DOMAIN = Buffer.from(
  'red-team-audit/http-authed-discovered-candidate/v1\0',
  'utf8',
)
const OPEN_READ_ONLY_NO_FOLLOW = fsConstants.O_RDONLY
  | (typeof fsConstants.O_NOFOLLOW === 'number' ? fsConstants.O_NOFOLLOW : 0)
const PHASES = new Set([
  'CREDENTIAL_PREFLIGHT',
  'PROBE',
  'BEFORE_READ',
  'MUTATION',
  'AFTER_READ',
  'ROLLBACK',
  'ROLLBACK_VERIFY',
])
const PROVENANCE = new Set(['SEALED_PLAN', 'DISCOVERED', 'OPERATOR_SUPPLIED'])
const TERMINAL_OUTCOMES = new Set([
  'PROBE_COMPLETED',
  'PROBE_OBSERVATION_FAILED',
  'MUTATION_VERIFIED_ROLLBACK_VERIFIED',
  'FAILED_BEFORE_SEND',
  'FAILED_BEFORE_MUTATION',
  'ROLLBACK_VERIFIED_AFTER_FAILURE',
  'ROLLBACK_RECOVERED_CONTEXT_UNVERIFIED',
  'DELIVERY_UNCERTAIN',
  'MANUAL_INTERVENTION_REQUIRED',
  'CAMPAIGN_STOPPED',
])

export const HTTP_AUTHED_CAMPAIGN_LEDGER_LIMITS = Object.freeze({
  maxRecordBytes: 64 * 1024,
  lockTimeoutMs: 10_000,
  staleLockMs: 30_000,
  lockPollMs: 10,
})

export class HttpAuthedCampaignLedgerError extends Error {
  constructor(code, message, options = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause })
    this.name = 'HttpAuthedCampaignLedgerError'
    this.code = code
  }
}

function ledgerError(code, message, options) {
  return new HttpAuthedCampaignLedgerError(code, message, options)
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function exactSha256(value, label) {
  if (!/^[a-f0-9]{64}$/.test(value ?? '')) {
    throw ledgerError('HTTP_AUTHED_LEDGER_DIGEST_INVALID', `${label} must be a SHA-256 hex digest`)
  }
  return value
}

function exactIdentifier(value, label) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{2,199}$/.test(value)) {
    throw ledgerError('HTTP_AUTHED_LEDGER_ID_INVALID', `${label} is invalid`)
  }
  return value
}

function exactInstant(value, label) {
  const timestamp = value instanceof Date ? value : new Date(value)
  if (!Number.isFinite(timestamp.getTime())) {
    throw ledgerError('HTTP_AUTHED_LEDGER_TIME_INVALID', `${label} must be a valid instant`)
  }
  return timestamp.toISOString()
}

function integer(value, label, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw ledgerError('HTTP_AUTHED_LEDGER_INTEGER_INVALID', `${label} is outside its valid range`)
  }
  return value
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
    throw ledgerError(
      'HTTP_AUTHED_LEDGER_PATH_ALIAS',
      'campaign ledger path cannot traverse a symlink or junction ancestor',
    )
  }
  const canonical = await realpath(candidate)
  if (comparablePath(candidate) !== comparablePath(canonical)) {
    throw ledgerError(
      'HTTP_AUTHED_LEDGER_PATH_ALIAS',
      'campaign ledger path cannot traverse a symlink or junction ancestor',
    )
  }
}

function normalizeLimits(input = {}) {
  if (!input || Object.getPrototypeOf(input) !== Object.prototype) {
    throw ledgerError('HTTP_AUTHED_LEDGER_LIMITS_INVALID', 'campaign ledger limits must be plain')
  }
  return {
    maxRecordBytes: integer(
      input.maxRecordBytes ?? HTTP_AUTHED_CAMPAIGN_LEDGER_LIMITS.maxRecordBytes,
      'maxRecordBytes',
      4096,
      1024 * 1024,
    ),
    lockTimeoutMs: integer(
      input.lockTimeoutMs ?? HTTP_AUTHED_CAMPAIGN_LEDGER_LIMITS.lockTimeoutMs,
      'lockTimeoutMs',
      1,
      60_000,
    ),
    staleLockMs: integer(
      input.staleLockMs ?? HTTP_AUTHED_CAMPAIGN_LEDGER_LIMITS.staleLockMs,
      'staleLockMs',
      0,
      24 * 60 * 60 * 1000,
    ),
    lockPollMs: integer(
      input.lockPollMs ?? HTTP_AUTHED_CAMPAIGN_LEDGER_LIMITS.lockPollMs,
      'lockPollMs',
      1,
      1000,
    ),
  }
}

function normalizeTrustedHead(input) {
  if (input === undefined) return null
  exactKeys(input, ['recordCount', 'headSha256'], 'trusted campaign ledger head')
  return Object.freeze({
    recordCount: integer(
      input.recordCount,
      'trusted campaign ledger record count',
      1,
      Number.MAX_SAFE_INTEGER,
    ),
    headSha256: exactSha256(input.headSha256, 'trusted campaign ledger head'),
  })
}

function normalizeAuthorizationEvidence(options) {
  const authorizationMode = options.authorizationMode
    ?? (options.authorizationDocumentSha256 === undefined
      ? undefined
      : 'WRITTEN_AUTHORIZATION_AUTHED')
  let evidence
  try {
    evidence = httpAuthedAuthorizationEvidence({
      authorization: { mode: authorizationMode },
    })
  } catch (cause) {
    throw ledgerError(
      'HTTP_AUTHED_LEDGER_AUTHORIZATION_MODE_INVALID',
      'campaign ledger requires an explicit runtime authorization mode',
      { cause },
    )
  }
  if (
    options.independentlyVerified !== undefined
    && options.independentlyVerified !== evidence.independentlyVerified
  ) {
    throw ledgerError(
      'HTTP_AUTHED_LEDGER_ASSURANCE_MISMATCH',
      'campaign ledger assurance does not match its authorization mode',
    )
  }
  return evidence
}

function candidateWithoutSequence(candidateDraft) {
  if (!candidateDraft || Object.getPrototypeOf(candidateDraft) !== Object.prototype) {
    throw ledgerError('HTTP_AUTHED_LEDGER_CANDIDATE_INVALID', 'campaign candidate must be plain')
  }
  const candidate = structuredClone(candidateDraft)
  delete candidate.sequence
  delete candidate.action_id
  if (!['probe', 'mutate'].includes(candidate.kind)) {
    throw ledgerError('HTTP_AUTHED_LEDGER_CANDIDATE_INVALID', 'campaign candidate kind is invalid')
  }
  if (typeof candidate.method !== 'string' || candidate.method.length === 0) {
    throw ledgerError('HTTP_AUTHED_LEDGER_CANDIDATE_INVALID', 'campaign candidate method is invalid')
  }
  if (typeof candidate.url !== 'string' || candidate.url.length === 0) {
    throw ledgerError('HTTP_AUTHED_LEDGER_CANDIDATE_INVALID', 'campaign candidate URL is invalid')
  }
  if (typeof candidate.test_category !== 'string' || candidate.test_category.length === 0) {
    throw ledgerError('HTTP_AUTHED_LEDGER_CANDIDATE_INVALID', 'campaign test category is invalid')
  }
  return candidate
}

export function httpAuthedCandidateIdentity({ campaignGrantSha256, candidateDraft }) {
  const candidate = candidateWithoutSequence(candidateDraft)
  const candidateSha256 = sha256(Buffer.from(canonicalJson({
    campaign_grant_sha256: exactSha256(campaignGrantSha256, 'campaign grant'),
    candidate,
  }), 'utf8'))
  return {
    actionId: `http-authed-action:${candidateSha256}`,
    candidateSha256,
    candidate,
  }
}

function privateDiscoveredCandidateIdentity({
  campaignGrantSha256,
  candidate,
  hmacKey,
}) {
  const candidateSha256 = createHmac('sha256', hmacKey)
    .update(DISCOVERED_CANDIDATE_IDENTITY_DOMAIN)
    .update(Buffer.from(canonicalJson({
      campaign_grant_sha256: campaignGrantSha256,
      candidate,
    }), 'utf8'))
    .digest('hex')
  return {
    actionId: `http-authed-action:${candidateSha256}`,
    candidateSha256,
    candidate,
  }
}

function exactKeys(value, expected, label) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype) {
    throw ledgerError('HTTP_AUTHED_LEDGER_RECORD_INVALID', `${label} must be a plain object`)
  }
  const actual = Object.keys(value).sort()
  const required = [...expected].sort()
  if (actual.length !== required.length || actual.some((key, index) => key !== required[index])) {
    throw ledgerError('HTTP_AUTHED_LEDGER_RECORD_INVALID', `${label} has unexpected fields`)
  }
}

function validateHeaderNames(value) {
  try {
    return sanitizeHttpAuthedHeaderNames(value)
  } catch {
    throw ledgerError('HTTP_AUTHED_LEDGER_RECORD_INVALID', 'response header names are invalid')
  }
}

function validateEvent(event, {
  allowJsonShape = true,
  allowObservationFailure = true,
} = {}) {
  if (!event || Object.getPrototypeOf(event) !== Object.prototype || typeof event.type !== 'string') {
    throw ledgerError('HTTP_AUTHED_LEDGER_RECORD_INVALID', 'campaign ledger event is invalid')
  }
  if (event.type === 'CAMPAIGN_OPENED') {
    exactKeys(event, ['type', 'operator_id'], 'CAMPAIGN_OPENED event')
    exactIdentifier(event.operator_id, 'campaign operator')
    return event
  }
  if (event.type === 'CAMPAIGN_SESSION_CONFIRMED') {
    exactKeys(
      event,
      ['type', 'operator_id', 'authorization_mode', 'confirmation'],
      'CAMPAIGN_SESSION_CONFIRMED event',
    )
    exactIdentifier(event.operator_id, 'campaign session operator')
    if (!['OPERATOR_ATTESTED_AUTHED', 'WRITTEN_AUTHORIZATION_AUTHED']
      .includes(event.authorization_mode)
      || event.confirmation !== SESSION_CONFIRMATION) {
      throw ledgerError(
        'HTTP_AUTHED_LEDGER_RECORD_INVALID',
        'campaign session confirmation is invalid',
      )
    }
    return event
  }
  if (event.type === 'CLEANUP_SESSION_CONFIRMED') {
    exactKeys(
      event,
      ['type', 'operator_id', 'authorization_mode', 'confirmation'],
      'CLEANUP_SESSION_CONFIRMED event',
    )
    exactIdentifier(event.operator_id, 'cleanup session operator')
    if (!['OPERATOR_ATTESTED_AUTHED', 'WRITTEN_AUTHORIZATION_AUTHED']
      .includes(event.authorization_mode)
      || event.confirmation !== CLEANUP_SESSION_CONFIRMATION) {
      throw ledgerError(
        'HTTP_AUTHED_LEDGER_RECORD_INVALID',
        'cleanup session confirmation is invalid',
      )
    }
    return event
  }
  if (event.type === 'CANDIDATE_ENQUEUED') {
    exactKeys(event, [
      'type', 'action_id', 'candidate_sha256', 'action_sequence', 'action_kind',
      'method', 'test_category', 'provenance',
    ], 'CANDIDATE_ENQUEUED event')
    if (!/^http-authed-action:[a-f0-9]{64}$/.test(event.action_id)) {
      throw ledgerError('HTTP_AUTHED_LEDGER_RECORD_INVALID', 'candidate action id is invalid')
    }
    exactSha256(event.candidate_sha256, 'candidate digest')
    integer(event.action_sequence, 'action sequence', 1, Number.MAX_SAFE_INTEGER)
    if (!['probe', 'mutate'].includes(event.action_kind)) {
      throw ledgerError('HTTP_AUTHED_LEDGER_RECORD_INVALID', 'candidate kind is invalid')
    }
    if (typeof event.method !== 'string' || !/^[!#$%&'*+.^_`|~0-9A-Z-]{1,64}$/.test(event.method)) {
      throw ledgerError('HTTP_AUTHED_LEDGER_RECORD_INVALID', 'candidate method is invalid')
    }
    exactIdentifier(event.test_category, 'candidate test category')
    if (!PROVENANCE.has(event.provenance)) {
      throw ledgerError('HTTP_AUTHED_LEDGER_RECORD_INVALID', 'candidate provenance is invalid')
    }
    return event
  }
  if (event.type === 'ACTION_LEASED') {
    exactKeys(event, ['type', 'action_id', 'lease_id', 'operator_id'], 'ACTION_LEASED event')
    if (!/^http-authed-action:[a-f0-9]{64}$/.test(event.action_id)
      || !/^[a-f0-9-]{36}$/.test(event.lease_id)) {
      throw ledgerError('HTTP_AUTHED_LEDGER_RECORD_INVALID', 'action lease identity is invalid')
    }
    exactIdentifier(event.operator_id, 'lease operator')
    return event
  }
  if (event.type === 'APPROVAL_CONSUMED') {
    exactKeys(event, [
      'type', 'action_id', 'lease_id', 'approval_nonce_sha256',
      'countersignature_binding_sha256',
    ], 'APPROVAL_CONSUMED event')
    exactSha256(event.approval_nonce_sha256, 'approval nonce digest')
    exactSha256(event.countersignature_binding_sha256, 'countersignature binding')
    return event
  }
  if (event.type === 'REQUEST_PRE_DISPATCH') {
    exactKeys(event, [
      'type', 'action_id', 'lease_id', 'phase', 'request_binding_sha256',
    ], 'REQUEST_PRE_DISPATCH event')
    if (!PHASES.has(event.phase)) {
      throw ledgerError('HTTP_AUTHED_LEDGER_RECORD_INVALID', 'request phase is invalid')
    }
    exactSha256(event.request_binding_sha256, 'request binding')
    return event
  }
  if (event.type === 'REQUEST_SETTLED') {
    const hasFailureStage = Object.hasOwn(event, 'failure_stage_code')
    const hasResponseByteBucket = Object.hasOwn(event, 'response_byte_bucket')
    const hasObservationFailure = hasFailureStage || hasResponseByteBucket
    if (Object.hasOwn(event, 'json_shape') && !allowJsonShape) {
      throw ledgerError(
        'HTTP_AUTHED_LEDGER_RECORD_INVALID',
        'legacy campaign records cannot contain JSON shape metadata',
      )
    }
    if (hasObservationFailure && !allowObservationFailure) {
      throw ledgerError(
        'HTTP_AUTHED_LEDGER_RECORD_INVALID',
        'legacy campaign records cannot contain observation-failure metadata',
      )
    }
    const keys = [
      'type', 'action_id', 'lease_id', 'phase', 'outcome', 'status',
      'header_names', 'request_may_have_been_sent',
    ]
    if (hasObservationFailure) {
      keys.push('failure_stage_code', 'response_byte_bucket')
    } else {
      keys.push('bytes')
    }
    if (Object.hasOwn(event, 'json_shape')) keys.push('json_shape')
    exactKeys(event, keys, 'REQUEST_SETTLED event')
    if (!PHASES.has(event.phase) || !['SETTLED', 'FAILED'].includes(event.outcome)) {
      throw ledgerError('HTTP_AUTHED_LEDGER_RECORD_INVALID', 'request outcome is invalid')
    }
    if (event.status !== null) integer(event.status, 'response status', 100, 599)
    if (!hasObservationFailure) integer(event.bytes, 'response bytes', 0, Number.MAX_SAFE_INTEGER)
    event.header_names = validateHeaderNames(event.header_names)
    if (event.json_shape !== undefined) {
      try {
        event.json_shape = sanitizeHttpAuthedJsonShape(event.json_shape)
      } catch {
        throw ledgerError('HTTP_AUTHED_LEDGER_RECORD_INVALID', 'JSON shape metadata is invalid')
      }
    }
    if (typeof event.request_may_have_been_sent !== 'boolean') {
      throw ledgerError('HTTP_AUTHED_LEDGER_RECORD_INVALID', 'delivery flag is invalid')
    }
    if (hasObservationFailure) {
      try {
        assertHttpAuthedResponseByteBucket(event.response_byte_bucket)
      } catch {
        throw ledgerError(
          'HTTP_AUTHED_LEDGER_RECORD_INVALID',
          'observation-failure response byte bucket is invalid',
        )
      }
      if (
        !hasFailureStage
        || !hasResponseByteBucket
        || event.phase !== 'PROBE'
        || event.outcome !== 'SETTLED'
        || event.status === null
        || event.request_may_have_been_sent !== true
        || event.failure_stage_code !== HTTP_AUTHED_JSON_SHAPE_FAILURE_STAGE
        || event.json_shape !== undefined
      ) {
        throw ledgerError(
          'HTTP_AUTHED_LEDGER_RECORD_INVALID',
          'observation-failure metadata is invalid',
        )
      }
    }
    return event
  }
  if (event.type === 'VERIFICATION_RECORDED') {
    exactKeys(event, [
      'type', 'action_id', 'lease_id', 'phase', 'value_match', 'context_match',
    ], 'VERIFICATION_RECORDED event')
    if (!PHASES.has(event.phase)
      || typeof event.value_match !== 'boolean'
      || typeof event.context_match !== 'boolean') {
      throw ledgerError('HTTP_AUTHED_LEDGER_RECORD_INVALID', 'verification event is invalid')
    }
    return event
  }
  if (event.type === 'DISCOVERY_SUMMARY') {
    exactKeys(event, [
      'type', 'action_id', 'lease_id', 'accepted_count', 'duplicate_count',
      'rejected_count',
    ], 'DISCOVERY_SUMMARY event')
    for (const key of ['accepted_count', 'duplicate_count', 'rejected_count']) {
      integer(event[key], key, 0, Number.MAX_SAFE_INTEGER)
    }
    return event
  }
  if (event.type === 'ACTION_TERMINAL') {
    exactKeys(event, ['type', 'action_id', 'lease_id', 'outcome', 'reason_code'], 'ACTION_TERMINAL event')
    if (!TERMINAL_OUTCOMES.has(event.outcome)) {
      throw ledgerError('HTTP_AUTHED_LEDGER_RECORD_INVALID', 'terminal outcome is invalid')
    }
    if (event.reason_code !== null
      && (typeof event.reason_code !== 'string' || !/^[A-Z][A-Z0-9_]{2,79}$/.test(event.reason_code))) {
      throw ledgerError('HTTP_AUTHED_LEDGER_RECORD_INVALID', 'terminal reason code is invalid')
    }
    return event
  }
  if (event.type === 'CAMPAIGN_STOPPED') {
    exactKeys(event, ['type', 'reason_code'], 'CAMPAIGN_STOPPED event')
    if (typeof event.reason_code !== 'string' || !/^[A-Z][A-Z0-9_]{2,79}$/.test(event.reason_code)) {
      throw ledgerError('HTTP_AUTHED_LEDGER_RECORD_INVALID', 'campaign stop reason is invalid')
    }
    return event
  }
  throw ledgerError('HTTP_AUTHED_LEDGER_RECORD_INVALID', 'campaign ledger event type is invalid')
}

function validateRecord(record) {
  exactKeys(record, [
    'schema_version', 'kind', 'record_sequence', 'previous_record_sha256',
    'campaign_grant_sha256', 'authorization_binding_sha256', 'authorization_mode',
    'independently_verified', 'authorization_assurance', 'authorization_nonclaim',
    'at', 'event',
  ], 'campaign ledger record')
  if (!SUPPORTED_RECORD_SCHEMA_VERSIONS.has(record.schema_version) || record.kind !== RECORD_KIND) {
    throw ledgerError('HTTP_AUTHED_LEDGER_RECORD_INVALID', 'campaign ledger record identity is invalid')
  }
  integer(record.record_sequence, 'record sequence', 0, Number.MAX_SAFE_INTEGER)
  if (record.previous_record_sha256 !== null) {
    exactSha256(record.previous_record_sha256, 'previous record digest')
  }
  exactSha256(record.campaign_grant_sha256, 'record campaign grant')
  exactSha256(record.authorization_binding_sha256, 'record authorization binding')
  let evidence
  try {
    evidence = httpAuthedAuthorizationEvidence({
      authorization: { mode: record.authorization_mode },
    })
  } catch {
    throw ledgerError('HTTP_AUTHED_LEDGER_RECORD_INVALID', 'record authorization mode is invalid')
  }
  if (
    record.independently_verified !== evidence.independentlyVerified
    || record.authorization_assurance !== evidence.authorizationAssurance
    || record.authorization_nonclaim !== evidence.authorizationNonclaim
  ) {
    throw ledgerError('HTTP_AUTHED_LEDGER_RECORD_INVALID', 'record authorization assurance is invalid')
  }
  exactInstant(record.at, 'record timestamp')
  validateEvent(record.event, {
    allowJsonShape: [JSON_SHAPE_RECORD_SCHEMA_VERSION, CURRENT_RECORD_SCHEMA_VERSION]
      .includes(record.schema_version),
    allowObservationFailure: record.schema_version === CURRENT_RECORD_SCHEMA_VERSION,
  })
  return record
}

function sleep(milliseconds) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds))
}

function processIsAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid < 1) return false
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    return error.code === 'EPERM'
  }
}

async function syncDirectory(path) {
  let handle
  try {
    handle = await open(path, fsConstants.O_RDONLY)
    await handle.sync()
  } catch (error) {
    if (!['EINVAL', 'EISDIR', 'ENOTSUP', 'EPERM'].includes(error.code)) throw error
  } finally {
    await handle?.close()
  }
}

async function readExactFile(path, maxBytes, label, allowedLinks = [1]) {
  const before = await lstat(path)
  if (!before.isFile() || before.isSymbolicLink() || !allowedLinks.includes(before.nlink)
    || before.size < 1 || before.size > maxBytes) {
    throw ledgerError('HTTP_AUTHED_LEDGER_FILE_UNSAFE', `${label} is not a safe bounded regular file`)
  }
  const handle = await open(path, OPEN_READ_ONLY_NO_FOLLOW)
  try {
    const opened = await handle.stat()
    const bytes = await handle.readFile()
    const after = await handle.stat()
    if (opened.dev !== after.dev || opened.ino !== after.ino || opened.size !== after.size
      || before.dev !== after.dev || before.ino !== after.ino || bytes.length !== after.size) {
      throw ledgerError('HTTP_AUTHED_LEDGER_FILE_CHANGED', `${label} changed while being read`)
    }
    return { bytes, info: after }
  } finally {
    await handle.close()
  }
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino
}

function lockOwnerValid(owner) {
  return owner
    && Object.getPrototypeOf(owner) === Object.prototype
    && Object.keys(owner).sort().join(',') === 'created_at,nonce,pid'
    && Number.isSafeInteger(owner.pid)
    && owner.pid > 0
    && typeof owner.nonce === 'string'
    && /^[a-f0-9]{24}$/.test(owner.nonce)
    && Number.isFinite(Date.parse(owner.created_at))
}

async function inspectLock(lockPath) {
  const before = await lstat(lockPath)
  if (!before.isDirectory() || before.isSymbolicLink()) {
    throw ledgerError('HTTP_AUTHED_LEDGER_LOCK_UNSAFE', 'campaign ledger lock is not a real directory')
  }
  const names = await readdir(lockPath)
  if (names.length !== 1 || names[0] !== LOCK_OWNER) {
    throw ledgerError('HTTP_AUTHED_LEDGER_LOCK_UNSAFE', 'campaign ledger lock has unexpected contents')
  }
  const { bytes, info: ownerInfo } = await readExactFile(
    join(lockPath, LOCK_OWNER),
    4096,
    'campaign ledger lock owner',
  )
  let owner
  try {
    owner = JSON.parse(bytes.toString('utf8'))
  } catch (cause) {
    throw ledgerError('HTTP_AUTHED_LEDGER_LOCK_UNSAFE', 'campaign ledger lock owner is invalid', { cause })
  }
  if (!lockOwnerValid(owner) || !bytes.equals(Buffer.from(stableJson(owner), 'utf8'))) {
    throw ledgerError('HTTP_AUTHED_LEDGER_LOCK_UNSAFE', 'campaign ledger lock owner is not canonical')
  }
  const after = await lstat(lockPath)
  if (!sameFileIdentity(before, after) || before.mtimeMs !== after.mtimeMs) {
    throw ledgerError('HTTP_AUTHED_LEDGER_LOCK_CHANGED', 'campaign ledger lock changed during inspection')
  }
  return { info: before, ownerInfo, owner, bytes }
}

function sameLockInspection(left, right) {
  return sameFileIdentity(left.info, right.info)
    && left.info.mtimeMs === right.info.mtimeMs
    && sameFileIdentity(left.ownerInfo, right.ownerInfo)
    && left.ownerInfo.mtimeMs === right.ownerInfo.mtimeMs
    && left.ownerInfo.size === right.ownerInfo.size
    && left.bytes.equals(right.bytes)
}

async function removeInspectedLock(path, inspected) {
  const current = await inspectLock(path)
  if (!sameLockInspection(current, inspected)) {
    throw ledgerError('HTTP_AUTHED_LEDGER_LOCK_CHANGED', 'campaign ledger lock changed during recovery')
  }
  await unlink(join(path, LOCK_OWNER))
  await syncDirectory(path)
  await rmdir(path)
  await syncDirectory(dirname(path))
}

async function recoverStaleLock(ledger, lockPath, inspected) {
  const quarantine = `${lockPath}.stale-${process.pid}-${randomBytes(12).toString('hex')}`
  await ledger._inject('before-stale-lock-quarantine', {})
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
        'stale campaign ledger lock changed and could not be restored',
      )
    }
    throw error
  }
  return true
}

async function acquireLock(ledger) {
  const lockPath = join(ledger.directory, LOCK_DIRECTORY)
  const deadline = Date.now() + ledger.limits.lockTimeoutMs
  while (true) {
    try {
      await mkdir(lockPath, { recursive: false, mode: 0o700 })
      const owner = {
        pid: process.pid,
        nonce: randomBytes(12).toString('hex'),
        created_at: new Date().toISOString(),
      }
      const bytes = Buffer.from(stableJson(owner), 'utf8')
      const handle = await open(join(lockPath, LOCK_OWNER), 'wx', 0o600)
      try {
        await handle.writeFile(bytes)
        await handle.sync()
      } finally {
        await handle.close()
      }
      await syncDirectory(lockPath)
      await syncDirectory(ledger.directory)
      const inspected = await inspectLock(lockPath)
      return { path: lockPath, ...inspected }
    } catch (error) {
      if (error.code !== 'EEXIST') throw error
    }

    const inspected = await inspectLock(lockPath)
    const age = Date.now() - Date.parse(inspected.owner.created_at)
    if (age >= ledger.limits.staleLockMs && !processIsAlive(inspected.owner.pid)) {
      if (await recoverStaleLock(ledger, lockPath, inspected)) continue
    }
    if (Date.now() >= deadline) {
      throw ledgerError('HTTP_AUTHED_LEDGER_LOCK_TIMEOUT', 'timed out waiting for campaign ledger lock')
    }
    await sleep(ledger.limits.lockPollMs)
  }
}

async function releaseLock(lock, directory) {
  try {
    await removeInspectedLock(lock.path, lock)
  } catch (cause) {
    throw ledgerError(
      'HTTP_AUTHED_LEDGER_LOCK_CHANGED',
      'campaign ledger lock changed while held',
      { cause },
    )
  }
}

function recordName(sequence) {
  return `${String(sequence).padStart(16, '0')}.http-authed-campaign.json`
}

async function installRecord(ledger, name, bytes, sequence) {
  const temporaryName = `.${name}.tmp-${process.pid}-${randomBytes(12).toString('hex')}`
  const temporaryPath = join(ledger.directory, temporaryName)
  const targetPath = join(ledger.directory, name)
  let handle
  try {
    handle = await open(temporaryPath, 'wx', 0o600)
    await handle.writeFile(bytes)
    await handle.sync()
    await handle.close()
    handle = undefined
  } catch (error) {
    await handle?.close().catch(() => {})
    throw error
  }
  await ledger._inject('after-temporary-durable', { sequence, name })
  await link(temporaryPath, targetPath)
  await ledger._inject('after-record-linked', { sequence, name })
  await syncDirectory(ledger.directory)
  await ledger._inject('after-record-durable', { sequence, name })
  await unlink(temporaryPath)
  await syncDirectory(ledger.directory)
  await ledger._inject('after-temporary-removed', { sequence, name })
}

async function reconcileTemporaries(ledger) {
  const names = await readdir(ledger.directory)
  const temporaries = new Map()
  for (const name of names) {
    const match = TEMPORARY_NAME.exec(name)
    if (!match) continue
    if (temporaries.has(match[1])) {
      throw ledgerError('HTTP_AUTHED_LEDGER_RESIDUE_AMBIGUOUS', 'campaign ledger record has multiple temporaries')
    }
    temporaries.set(match[1], name)
  }
  for (const [targetName, temporaryName] of temporaries) {
    const temporaryPath = join(ledger.directory, temporaryName)
    const targetPath = join(ledger.directory, targetName)
    const temporary = await lstat(temporaryPath)
    if (!temporary.isFile() || temporary.isSymbolicLink() || ![1, 2].includes(temporary.nlink)) {
      throw ledgerError('HTTP_AUTHED_LEDGER_RESIDUE_UNSAFE', 'campaign ledger temporary is unsafe')
    }
    let target
    try {
      target = await lstat(targetPath)
    } catch (error) {
      if (error.code !== 'ENOENT') throw error
    }
    if (target === undefined) {
      if (temporary.nlink !== 1) {
        throw ledgerError('HTTP_AUTHED_LEDGER_RESIDUE_AMBIGUOUS', 'orphan temporary has an unexpected link count')
      }
      await unlink(temporaryPath)
      continue
    }
    if (!target.isFile() || target.isSymbolicLink() || temporary.nlink !== 2
      || target.nlink !== 2 || target.dev !== temporary.dev || target.ino !== temporary.ino) {
      throw ledgerError('HTTP_AUTHED_LEDGER_RESIDUE_AMBIGUOUS', 'campaign ledger target and temporary conflict')
    }
    await unlink(temporaryPath)
  }
  if (temporaries.size > 0) await syncDirectory(ledger.directory)
}

function emptyProjection() {
  return {
    records: [],
    headSha256: null,
    campaignOperatorId: null,
    lastSessionConfirmation: null,
    lastCleanupSessionConfirmation: null,
    actions: new Map(),
    candidates: new Map(),
    consumedApprovals: new Set(),
    nextActionSequence: 1,
    stopped: false,
  }
}

function assertPhaseAllowedForAction(action, phase) {
  const allowed = action.action_kind === 'mutate'
    ? new Set([
        'CREDENTIAL_PREFLIGHT',
        'BEFORE_READ',
        'MUTATION',
        'AFTER_READ',
        'ROLLBACK',
        'ROLLBACK_VERIFY',
      ])
    : new Set(['CREDENTIAL_PREFLIGHT', 'PROBE'])
  if (!allowed.has(phase)) {
    throw ledgerError(
      'HTTP_AUTHED_LEDGER_PHASE_INVALID',
      `request phase ${phase} is invalid for a ${action.action_kind} action`,
    )
  }
}

function assertPhasePredecessor(projection, action, phase) {
  let allowedStates
  if (action.action_kind !== 'mutate') {
    allowedStates = phase === 'CREDENTIAL_PREFLIGHT'
      ? new Set(['LEASED'])
      : new Set(['LEASED', 'CREDENTIAL_PREFLIGHT_SETTLED'])
  } else if (phase === 'CREDENTIAL_PREFLIGHT') {
    allowedStates = new Set(['LEASED'])
  } else if (phase === 'BEFORE_READ') {
    allowedStates = new Set(['CREDENTIAL_PREFLIGHT_SETTLED'])
  } else if (phase === 'MUTATION') {
    allowedStates = new Set(['APPROVAL_CONSUMED'])
  } else if (phase === 'AFTER_READ') {
    allowedStates = new Set(['MUTATION_SETTLED'])
    if (action.phase_outcomes.MUTATION?.request_may_have_been_sent === true) {
      allowedStates.add('MUTATION_FAILED')
    }
  } else if (phase === 'ROLLBACK') {
    allowedStates = new Set(['AFTER_READ_SETTLED', 'AFTER_READ_FAILED', 'AFTER_READ_VERIFIED'])
    if (projection.stopped) {
      allowedStates.add('MUTATION_SETTLED')
      if (action.phase_outcomes.MUTATION?.request_may_have_been_sent === true) {
        allowedStates.add('MUTATION_FAILED')
      }
    }
  } else {
    allowedStates = new Set(['ROLLBACK_SETTLED', 'ROLLBACK_FAILED'])
  }
  if (!allowedStates.has(action.state)) {
    throw ledgerError(
      'HTTP_AUTHED_LEDGER_PHASE_PREDECESSOR_INVALID',
      `request phase ${phase} has no valid predecessor in action state ${action.state}`,
    )
  }
}

function assertTerminalOutcomeAllowed(action, outcome) {
  if (
    outcome === 'PROBE_COMPLETED'
    && (
      action.action_kind === 'mutate'
      || action.pending_phase !== null
      || action.phase_outcomes.PROBE?.outcome !== 'SETTLED'
      || action.phase_outcomes.PROBE?.failure_stage_code !== undefined
    )
  ) {
    throw ledgerError(
      'HTTP_AUTHED_LEDGER_TERMINAL_TRANSITION_INVALID',
      'a probe can be completed only after its request settled',
    )
  }
  if (
    outcome === 'PROBE_OBSERVATION_FAILED'
    && (
      action.action_kind === 'mutate'
      || action.pending_phase !== null
      || action.phase_outcomes.PROBE?.outcome !== 'SETTLED'
      || action.phase_outcomes.PROBE?.failure_stage_code
        !== HTTP_AUTHED_JSON_SHAPE_FAILURE_STAGE
    )
  ) {
    throw ledgerError(
      'HTTP_AUTHED_LEDGER_TERMINAL_TRANSITION_INVALID',
      'a probe observation can fail only after its request settled with bounded failure metadata',
    )
  }
  if (
    ['MUTATION_VERIFIED_ROLLBACK_VERIFIED', 'ROLLBACK_VERIFIED_AFTER_FAILURE']
      .includes(outcome)
    && (
      action.action_kind !== 'mutate'
      || action.state !== 'ROLLBACK_VERIFY_VERIFIED'
      || action.last_verification?.value_match !== true
      || action.last_verification?.context_match !== true
    )
  ) {
    throw ledgerError(
      'HTTP_AUTHED_LEDGER_TERMINAL_TRANSITION_INVALID',
      'a reversible mutation can complete only after rollback verification',
    )
  }
}

function applyEvent(projection, record) {
  const event = record.event
  if (record.record_sequence === 0) {
    if (event.type !== 'CAMPAIGN_OPENED' || record.previous_record_sha256 !== null) {
      throw ledgerError('HTTP_AUTHED_LEDGER_GENESIS_INVALID', 'campaign ledger genesis is invalid')
    }
    projection.campaignOperatorId = event.operator_id
    return
  }
  if (event.type === 'CAMPAIGN_OPENED') {
    throw ledgerError('HTTP_AUTHED_LEDGER_EVENT_INVALID', 'campaign ledger can contain only one genesis')
  }
  if (event.type === 'CAMPAIGN_SESSION_CONFIRMED') {
    if (
      event.operator_id !== projection.campaignOperatorId
      || event.authorization_mode !== record.authorization_mode
    ) {
      throw ledgerError(
        'HTTP_AUTHED_LEDGER_EVENT_INVALID',
        'campaign session confirmation does not match ledger authority',
      )
    }
    projection.lastSessionConfirmation = {
      record_sequence: record.record_sequence,
      at: record.at,
      operator_id: event.operator_id,
      authorization_mode: event.authorization_mode,
      confirmation: event.confirmation,
    }
    return
  }
  if (event.type === 'CLEANUP_SESSION_CONFIRMED') {
    if (
      event.operator_id !== projection.campaignOperatorId
      || event.authorization_mode !== record.authorization_mode
    ) {
      throw ledgerError(
        'HTTP_AUTHED_LEDGER_EVENT_INVALID',
        'cleanup session confirmation does not match ledger authority',
      )
    }
    projection.lastCleanupSessionConfirmation = {
      record_sequence: record.record_sequence,
      at: record.at,
      operator_id: event.operator_id,
      authorization_mode: event.authorization_mode,
      confirmation: event.confirmation,
    }
    return
  }
  if (event.type === 'CAMPAIGN_STOPPED') {
    if (projection.stopped) {
      throw ledgerError('HTTP_AUTHED_LEDGER_EVENT_INVALID', 'campaign is already stopped')
    }
    projection.stopped = true
    return
  }
  if (event.type === 'CANDIDATE_ENQUEUED') {
    if (projection.actions.has(event.action_id) || projection.candidates.has(event.candidate_sha256)) {
      throw ledgerError('HTTP_AUTHED_LEDGER_EVENT_INVALID', 'candidate was enqueued more than once')
    }
    if (event.action_sequence !== projection.nextActionSequence) {
      throw ledgerError('HTTP_AUTHED_LEDGER_EVENT_INVALID', 'candidate action sequence is not monotonic')
    }
    const action = {
      action_id: event.action_id,
      candidate_sha256: event.candidate_sha256,
      action_sequence: event.action_sequence,
      action_kind: event.action_kind,
      method: event.method,
      test_category: event.test_category,
      provenance: event.provenance,
      state: 'QUEUED',
      lease_id: null,
      pending_phase: null,
      settled_phases: [],
      phase_outcomes: {},
      terminal: false,
      outcome: null,
      approval_consumed: false,
    }
    projection.actions.set(event.action_id, action)
    projection.candidates.set(event.candidate_sha256, event.action_id)
    projection.nextActionSequence += 1
    return
  }
  const action = projection.actions.get(event.action_id)
  if (!action) throw ledgerError('HTTP_AUTHED_LEDGER_EVENT_INVALID', 'event names an unknown action')
  if (event.type === 'ACTION_LEASED') {
    if (projection.stopped || action.state !== 'QUEUED' || action.terminal) {
      throw ledgerError('HTTP_AUTHED_LEDGER_EVENT_INVALID', 'action cannot be leased from its current state')
    }
    if (event.operator_id !== projection.campaignOperatorId) {
      throw ledgerError(
        'HTTP_AUTHED_LEDGER_OPERATOR_MISMATCH',
        'action lease operator does not match campaign genesis',
      )
    }
    action.lease_id = event.lease_id
    action.state = 'LEASED'
    return
  }
  if (event.lease_id !== action.lease_id || action.terminal) {
    throw ledgerError('HTTP_AUTHED_LEDGER_EVENT_INVALID', 'event lease is stale or action is terminal')
  }
  if (event.type === 'APPROVAL_CONSUMED') {
    if (
      action.action_kind !== 'mutate'
      || action.approval_consumed
      || action.pending_phase !== null
      || action.state !== 'BEFORE_READ_VERIFIED'
      || action.last_verification?.value_match !== true
      || action.last_verification?.context_match !== true
    ) {
      throw ledgerError(
        'HTTP_AUTHED_LEDGER_APPROVAL_STATE_INVALID',
        'mutation approval can be consumed only after exact before-state verification',
      )
    }
    if (projection.consumedApprovals.has(event.approval_nonce_sha256)) {
      throw ledgerError(
        'HTTP_AUTHED_LEDGER_APPROVAL_REPLAY',
        'mutation approval nonce was already consumed',
      )
    }
    projection.consumedApprovals.add(event.approval_nonce_sha256)
    action.approval_consumed = true
    action.state = 'APPROVAL_CONSUMED'
    return
  }
  if (event.type === 'REQUEST_PRE_DISPATCH') {
    assertPhaseAllowedForAction(action, event.phase)
    if (action.pending_phase !== null || action.settled_phases.includes(event.phase)) {
      throw ledgerError('HTTP_AUTHED_LEDGER_EVENT_INVALID', 'request pre-dispatch would replay a phase')
    }
    if (projection.stopped && !['ROLLBACK', 'ROLLBACK_VERIFY'].includes(event.phase)) {
      throw ledgerError('HTTP_AUTHED_LEDGER_EVENT_INVALID', 'stopped campaign permits cleanup phases only')
    }
    if (event.phase === 'MUTATION' && action.approval_consumed !== true) {
      throw ledgerError(
        'HTTP_AUTHED_LEDGER_APPROVAL_REQUIRED',
        'mutation pre-dispatch requires a durably consumed countersignature approval',
      )
    }
    assertPhasePredecessor(projection, action, event.phase)
    action.pending_phase = event.phase
    action.state = `${event.phase}_PRE_DISPATCH`
    return
  }
  if (event.type === 'REQUEST_SETTLED') {
    if (action.pending_phase !== event.phase) {
      throw ledgerError('HTTP_AUTHED_LEDGER_EVENT_INVALID', 'request outcome does not match pre-dispatch')
    }
    action.pending_phase = null
    action.settled_phases.push(event.phase)
    action.phase_outcomes[event.phase] = {
      outcome: event.outcome,
      request_may_have_been_sent: event.request_may_have_been_sent,
      ...(event.json_shape === undefined
        ? {}
        : { json_shape: structuredClone(event.json_shape) }),
      ...(event.failure_stage_code === undefined
        ? {}
        : {
            status: event.status,
            header_names: [...event.header_names],
            response_byte_bucket: event.response_byte_bucket,
            failure_stage_code: event.failure_stage_code,
          }),
    }
    action.state = `${event.phase}_${event.outcome}`
    return
  }
  if (event.type === 'VERIFICATION_RECORDED') {
    if (
      action.action_kind !== 'mutate'
      || !['BEFORE_READ', 'AFTER_READ', 'ROLLBACK_VERIFY'].includes(event.phase)
      || action.state !== `${event.phase}_SETTLED`
      || action.phase_outcomes[event.phase]?.outcome !== 'SETTLED'
    ) {
      throw ledgerError(
        'HTTP_AUTHED_LEDGER_VERIFICATION_STATE_INVALID',
        'verification requires the exact settled read phase and cannot replay',
      )
    }
    action.state = `${event.phase}_VERIFIED`
    action.last_verification = {
      value_match: event.value_match,
      context_match: event.context_match,
    }
    return
  }
  if (event.type === 'DISCOVERY_SUMMARY') {
    action.discovery_summary = {
      accepted_count: event.accepted_count,
      duplicate_count: event.duplicate_count,
      rejected_count: event.rejected_count,
    }
    return
  }
  if (event.type === 'ACTION_TERMINAL') {
    assertTerminalOutcomeAllowed(action, event.outcome)
    action.terminal = true
    action.outcome = event.outcome
    action.state = event.outcome
    action.pending_phase = null
    return
  }
  throw ledgerError('HTTP_AUTHED_LEDGER_EVENT_INVALID', 'campaign ledger transition is invalid')
}

async function loadProjection(ledger) {
  await reconcileTemporaries(ledger)
  const names = await readdir(ledger.directory)
  const recordNames = []
  for (const name of names) {
    if (name === LOCK_DIRECTORY) continue
    if (RECORD_NAME.test(name)) {
      recordNames.push(name)
      continue
    }
    if (TEMPORARY_NAME.test(name)) {
      throw ledgerError('HTTP_AUTHED_LEDGER_RESIDUE_AMBIGUOUS', 'campaign ledger temporary survived reconciliation')
    }
    throw ledgerError('HTTP_AUTHED_LEDGER_DIRECTORY_UNSAFE', `campaign ledger contains unexpected entry ${JSON.stringify(name)}`)
  }
  recordNames.sort()
  const projection = emptyProjection()
  let previousBytes = null
  for (let sequence = 0; sequence < recordNames.length; sequence += 1) {
    const expectedName = recordName(sequence)
    if (recordNames[sequence] !== expectedName) {
      throw ledgerError('HTTP_AUTHED_LEDGER_SEQUENCE_GAP', 'campaign ledger contains a missing record')
    }
    const { bytes } = await readExactFile(
      join(ledger.directory, expectedName),
      ledger.limits.maxRecordBytes,
      `campaign ledger record ${sequence}`,
    )
    let record
    try {
      record = JSON.parse(bytes.toString('utf8'))
    } catch (cause) {
      throw ledgerError('HTTP_AUTHED_LEDGER_RECORD_INVALID', 'campaign ledger record is not valid JSON', { cause })
    }
    validateRecord(record)
    if (!bytes.equals(Buffer.from(stableJson(record), 'utf8'))) {
      throw ledgerError('HTTP_AUTHED_LEDGER_RECORD_NONCANONICAL', 'campaign ledger record is not canonical')
    }
    if (record.record_sequence !== sequence) {
      throw ledgerError('HTTP_AUTHED_LEDGER_SEQUENCE_GAP', 'campaign ledger filename and sequence differ')
    }
    const expectedPrevious = previousBytes === null ? null : sha256(previousBytes)
    if (record.previous_record_sha256 !== expectedPrevious) {
      throw ledgerError('HTTP_AUTHED_LEDGER_CHAIN_INVALID', 'campaign ledger predecessor hash does not match')
    }
    if (
      record.campaign_grant_sha256 !== ledger.campaignGrantSha256
      || record.authorization_binding_sha256 !== ledger.authorizationBindingSha256
      || record.authorization_mode !== ledger.authorizationMode
      || record.independently_verified !== ledger.independentlyVerified
      || record.authorization_assurance !== ledger.authorizationAssurance
      || record.authorization_nonclaim !== ledger.authorizationNonclaim
    ) {
      throw ledgerError('HTTP_AUTHED_LEDGER_CAMPAIGN_MISMATCH', 'campaign ledger binding does not match')
    }
    applyEvent(projection, record)
    projection.records.push(record)
    projection.headSha256 = sha256(bytes)
    previousBytes = bytes
  }
  if (
    projection.records.length > 0
    && projection.campaignOperatorId !== ledger.operatorId
  ) {
    throw ledgerError(
      'HTTP_AUTHED_LEDGER_OPERATOR_MISMATCH',
      'campaign ledger genesis operator does not match the selected operator',
    )
  }
  return projection
}

function assertTrustedHead(projection, trustedHead) {
  if (trustedHead === null) return
  if (projection.records.length < trustedHead.recordCount) {
    throw ledgerError(
      'HTTP_AUTHED_LEDGER_TRUSTED_HEAD_TRUNCATED',
      'campaign ledger is shorter than the trusted retained record count',
    )
  }
  const retainedRecord = projection.records[trustedHead.recordCount - 1]
  const retainedDigest = sha256(Buffer.from(stableJson(retainedRecord), 'utf8'))
  if (retainedDigest !== trustedHead.headSha256) {
    throw ledgerError(
      'HTTP_AUTHED_LEDGER_TRUSTED_HEAD_MISMATCH',
      'campaign ledger diverges from the trusted retained head',
    )
  }
}

function publicAction(action) {
  if (!action) return null
  return structuredClone(action)
}

export class HttpAuthedCampaignLedger {
  constructor(options) {
    if (!isAbsolute(options.directory ?? '')) {
      throw ledgerError('HTTP_AUTHED_LEDGER_DIRECTORY_INVALID', 'campaign ledger directory must be absolute')
    }
    this.directory = resolve(options.directory)
    this.campaignGrantSha256 = exactSha256(options.campaignGrantSha256, 'campaign grant')
    if (
      options.authorizationBindingSha256 !== undefined
      && options.authorizationDocumentSha256 !== undefined
      && options.authorizationBindingSha256 !== options.authorizationDocumentSha256
    ) {
      throw ledgerError(
        'HTTP_AUTHED_LEDGER_BINDING_AMBIGUOUS',
        'campaign ledger received conflicting authorization bindings',
      )
    }
    this.authorizationBindingSha256 = exactSha256(
      options.authorizationBindingSha256 ?? options.authorizationDocumentSha256,
      'authorization binding',
    )
    const evidence = normalizeAuthorizationEvidence(options)
    this.authorizationMode = evidence.authorizationMode
    this.independentlyVerified = evidence.independentlyVerified
    this.authorizationAssurance = evidence.authorizationAssurance
    this.authorizationNonclaim = evidence.authorizationNonclaim
    this.operatorId = exactIdentifier(options.operatorId, 'campaign operator')
    this.initialize = options.initialize === true
    this.limits = normalizeLimits(options.limits)
    this.trustedHead = normalizeTrustedHead(options.trustedHead)
    this._clock = options.now ?? (() => new Date())
    this._faultInjector = options.faultInjector
    if (typeof this._clock !== 'function'
      || (this._faultInjector !== undefined && typeof this._faultInjector !== 'function')) {
      throw ledgerError('HTTP_AUTHED_LEDGER_OPTION_INVALID', 'campaign ledger callback option is invalid')
    }
    this._lock = null
    this._projection = emptyProjection()
    this._operationTail = Promise.resolve()
    this._discoveredCandidateIdentityKey = randomBytes(32)
    this._discoveredCandidateIdentities = new Map()
    this._open = false
  }

  static async open(options) {
    const ledger = new HttpAuthedCampaignLedger(options)
    await ledger._initialize()
    return ledger
  }

  async _initialize() {
    try {
      await assertNoLinkedAncestor(this.directory)
      if (this.initialize) {
        await mkdir(this.directory, { recursive: true, mode: 0o700 })
      }
      const info = await stat(this.directory)
      if (!info.isDirectory()) {
        throw ledgerError('HTTP_AUTHED_LEDGER_DIRECTORY_INVALID', 'campaign ledger path is not a directory')
      }
      const alias = await lstat(this.directory)
      if (!alias.isDirectory() || alias.isSymbolicLink()) {
        throw ledgerError('HTTP_AUTHED_LEDGER_DIRECTORY_INVALID', 'campaign ledger directory is a link')
      }
      const canonical = await realpath(this.directory)
      if (comparablePath(this.directory) !== comparablePath(canonical)) {
        throw ledgerError(
          'HTTP_AUTHED_LEDGER_PATH_ALIAS',
          'campaign ledger directory cannot be a symlink or junction alias',
        )
      }
      this.directory = canonical
      this._lock = await acquireLock(this)
      this._projection = await loadProjection(this)
      assertTrustedHead(this._projection, this.trustedHead)
      this._open = true
      if (this._projection.records.length === 0) {
        if (!this.initialize) {
          throw ledgerError('HTTP_AUTHED_LEDGER_NOT_INITIALIZED', 'campaign ledger has no genesis')
        }
        await this._append({ type: 'CAMPAIGN_OPENED', operator_id: this.operatorId })
      }
      await this._recoverInterruptedDispatches()
    } catch (error) {
      if (this._lock !== null) {
        await releaseLock(this._lock, this.directory).catch(() => {})
        this._lock = null
      }
      this._open = false
      this._destroyDiscoveredCandidateIdentityState()
      throw error
    }
  }

  _destroyDiscoveredCandidateIdentityState() {
    this._discoveredCandidateIdentityKey?.fill(0)
    this._discoveredCandidateIdentityKey = null
    this._discoveredCandidateIdentities.clear()
  }

  _candidateIdentity(candidateDraft, { provenance } = {}) {
    const deterministicIdentity = httpAuthedCandidateIdentity({
      campaignGrantSha256: this.campaignGrantSha256,
      candidateDraft,
    })
    if (
      provenance === 'SEALED_PLAN'
      || deterministicIdentity.candidate.kind === 'mutate'
      || this._projection.candidates.has(deterministicIdentity.candidateSha256)
    ) {
      return deterministicIdentity
    }
    const mappedIdentity = this._discoveredCandidateIdentities.get(
      deterministicIdentity.candidateSha256,
    )
    if (mappedIdentity !== undefined) {
      return { ...mappedIdentity, candidate: deterministicIdentity.candidate }
    }
    if (provenance !== 'DISCOVERED') {
      return deterministicIdentity
    }
    const privateIdentity = privateDiscoveredCandidateIdentity({
      campaignGrantSha256: this.campaignGrantSha256,
      candidate: deterministicIdentity.candidate,
      hmacKey: this._discoveredCandidateIdentityKey,
    })
    this._discoveredCandidateIdentities.set(
      deterministicIdentity.candidateSha256,
      Object.freeze({
        actionId: privateIdentity.actionId,
        candidateSha256: privateIdentity.candidateSha256,
      }),
    )
    return privateIdentity
  }

  _assertOpen() {
    if (!this._open) throw ledgerError('HTTP_AUTHED_LEDGER_CLOSED', 'campaign ledger is closed')
  }

  async _runExclusive(operation) {
    const preceding = this._operationTail
    let release
    this._operationTail = new Promise((resolveOperation) => {
      release = resolveOperation
    })
    await preceding
    try {
      return await operation()
    } finally {
      release()
    }
  }

  async _inject(phase, details) {
    if (this._faultInjector !== undefined) {
      await this._faultInjector(phase, Object.freeze({ ...details }))
    }
  }

  async _append(event) {
    validateEvent(event)
    const sequence = this._projection.records.length
    const recordSchemaVersion = event.type === 'REQUEST_SETTLED'
      && event.failure_stage_code !== undefined
      ? CURRENT_RECORD_SCHEMA_VERSION
      : event.type === 'REQUEST_SETTLED' && event.json_shape !== undefined
        ? JSON_SHAPE_RECORD_SCHEMA_VERSION
        : '1.2.0'
    const record = validateRecord({
      schema_version: recordSchemaVersion,
      kind: RECORD_KIND,
      record_sequence: sequence,
      previous_record_sha256: this._projection.headSha256,
      campaign_grant_sha256: this.campaignGrantSha256,
      authorization_binding_sha256: this.authorizationBindingSha256,
      authorization_mode: this.authorizationMode,
      independently_verified: this.independentlyVerified,
      authorization_assurance: this.authorizationAssurance,
      authorization_nonclaim: this.authorizationNonclaim,
      at: exactInstant(this._clock(), 'campaign ledger clock'),
      event: structuredClone(event),
    })
    const bytes = Buffer.from(stableJson(record), 'utf8')
    if (bytes.length > this.limits.maxRecordBytes) {
      throw ledgerError('HTTP_AUTHED_LEDGER_RECORD_TOO_LARGE', 'campaign ledger record exceeds its byte limit')
    }
    applyEvent(this._projection, record)
    try {
      await installRecord(this, recordName(sequence), bytes, sequence)
    } catch (error) {
      this._projection = await loadProjection(this)
      throw error
    }
    this._projection.records.push(record)
    this._projection.headSha256 = sha256(bytes)
    return record
  }

  async _recoverInterruptedDispatches() {
    const interrupted = [...this._projection.actions.values()]
      .filter((action) => (
        !action.terminal
        && (action.state !== 'QUEUED' || action.provenance === 'DISCOVERED')
      ))
    for (const action of interrupted) {
      let outcome
      let reasonCode
      if (
        action.action_kind === 'mutate'
        && action.approval_consumed === true
        && ['MUTATION', 'AFTER_READ', 'ROLLBACK'].includes(action.pending_phase)
      ) {
        // A durable write/cleanup pre-dispatch record is consumed. Convert the
        // interrupted request to an explicit ambiguous settlement, stop all new
        // campaign work, and leave the action open for cleanup-only recovery.
        await this._append({
          type: 'REQUEST_SETTLED',
          action_id: action.action_id,
          lease_id: action.lease_id,
          phase: action.pending_phase,
          outcome: 'FAILED',
          status: null,
          bytes: 0,
          header_names: [],
          request_may_have_been_sent: true,
        })
        if (!this._projection.stopped) {
          await this._append({
            type: 'CAMPAIGN_STOPPED',
            reason_code: 'INTERRUPTED_MUTATION_CLEANUP_REQUIRED',
          })
        }
        continue
      }
      if (
        action.action_kind === 'mutate'
        && action.approval_consumed === true
        && action.pending_phase === null
        && ['MUTATION', 'AFTER_READ', 'ROLLBACK'].some(
          (phase) => action.settled_phases.includes(phase),
        )
        && !action.settled_phases.includes('ROLLBACK_VERIFY')
      ) {
        if (!this._projection.stopped) {
          await this._append({
            type: 'CAMPAIGN_STOPPED',
            reason_code: 'INTERRUPTED_MUTATION_CLEANUP_REQUIRED',
          })
        }
        continue
      }
      if (action.state === 'QUEUED' && action.provenance === 'DISCOVERED') {
        // Discovery response values are deliberately never persisted. A queued
        // discovered action therefore cannot be reconstructed safely after a
        // process restart; record the gap instead of guessing or replaying it.
        outcome = 'CAMPAIGN_STOPPED'
        reasonCode = 'DISCOVERED_CANDIDATE_UNAVAILABLE_AFTER_RESTART'
      } else if (action.pending_phase !== null) {
        const cleanupUncertain = ['ROLLBACK', 'ROLLBACK_VERIFY'].includes(action.pending_phase)
        outcome = cleanupUncertain ? 'MANUAL_INTERVENTION_REQUIRED' : 'DELIVERY_UNCERTAIN'
        reasonCode = cleanupUncertain
          ? 'INTERRUPTED_DURING_CLEANUP'
          : 'INTERRUPTED_AFTER_PRE_DISPATCH'
      } else if (
        action.action_kind !== 'mutate'
        && action.phase_outcomes.PROBE?.outcome === 'SETTLED'
      ) {
        const observationFailed = action.phase_outcomes.PROBE.failure_stage_code
          === HTTP_AUTHED_JSON_SHAPE_FAILURE_STAGE
        outcome = observationFailed ? 'PROBE_OBSERVATION_FAILED' : 'PROBE_COMPLETED'
        reasonCode = observationFailed
          ? 'PROBE_JSON_SHAPE_OBSERVATION_FAILED'
          : 'RECOVERED_AFTER_SETTLED_PROBE'
      } else if (
        action.action_kind !== 'mutate'
        && action.phase_outcomes.PROBE?.outcome === 'FAILED'
      ) {
        const deliveryUncertain =
          action.phase_outcomes.PROBE.request_may_have_been_sent === true
        outcome = deliveryUncertain ? 'DELIVERY_UNCERTAIN' : 'FAILED_BEFORE_SEND'
        reasonCode = deliveryUncertain
          ? 'RECOVERED_FAILED_PROBE_DELIVERY_UNCERTAIN'
          : 'RECOVERED_FAILED_PROBE_BEFORE_SEND'
      } else if (
        action.action_kind === 'mutate'
        && action.state === 'ROLLBACK_VERIFY_VERIFIED'
        && action.last_verification?.value_match === true
        && action.last_verification?.context_match === true
      ) {
        outcome = 'ROLLBACK_VERIFIED_AFTER_FAILURE'
        reasonCode = 'RECOVERED_AFTER_ROLLBACK_VERIFICATION'
      } else if (
        action.action_kind === 'mutate'
        && action.settled_phases.some((phase) => [
          'MUTATION', 'AFTER_READ', 'ROLLBACK', 'ROLLBACK_VERIFY',
        ].includes(phase))
      ) {
        outcome = 'MANUAL_INTERVENTION_REQUIRED'
        reasonCode = 'INTERRUPTED_MUTATION_REQUIRES_REVIEW'
      } else if (action.action_kind === 'mutate' && !action.approval_consumed) {
        outcome = 'FAILED_BEFORE_MUTATION'
        reasonCode = 'INTERRUPTED_BEFORE_MUTATION'
      } else {
        outcome = 'FAILED_BEFORE_SEND'
        reasonCode = 'INTERRUPTED_BEFORE_SEND'
      }
      await this._append({
        type: 'ACTION_TERMINAL',
        action_id: action.action_id,
        lease_id: action.lease_id,
        outcome,
        reason_code: reasonCode,
      })
    }
  }

  snapshot() {
    this._assertOpen()
    const actions = [...this._projection.actions.values()]
    return {
      directory: this.directory,
      campaign_grant_sha256: this.campaignGrantSha256,
      authorization_binding_sha256: this.authorizationBindingSha256,
      authorization_mode: this.authorizationMode,
      independently_verified: this.independentlyVerified,
      authorization_assurance: this.authorizationAssurance,
      authorization_nonclaim: this.authorizationNonclaim,
      operator_id: this._projection.campaignOperatorId,
      last_session_confirmation: this._projection.lastSessionConfirmation === null
        ? null
        : structuredClone(this._projection.lastSessionConfirmation),
      last_cleanup_session_confirmation: this._projection.lastCleanupSessionConfirmation === null
        ? null
        : structuredClone(this._projection.lastCleanupSessionConfirmation),
      record_count: this._projection.records.length,
      head_sha256: this._projection.headSha256,
      next_action_sequence: this._projection.nextActionSequence,
      queued_actions: actions.filter((action) => action.state === 'QUEUED').length,
      terminal_actions: actions.filter((action) => action.terminal).length,
      stopped: this._projection.stopped,
    }
  }

  actionState(actionId) {
    this._assertOpen()
    return publicAction(this._projection.actions.get(actionId))
  }

  async confirmCampaignSession({ operatorId, authorizationMode }) {
    return this._runExclusive(async () => {
      this._assertOpen()
      if (
        exactIdentifier(operatorId, 'campaign session operator') !== this.operatorId
        || authorizationMode !== this.authorizationMode
      ) {
        throw ledgerError(
          'HTTP_AUTHED_LEDGER_SESSION_AUTHORITY_MISMATCH',
          'campaign session confirmation does not match the sealed ledger authority',
        )
      }
      await this._append({
        type: 'CAMPAIGN_SESSION_CONFIRMED',
        operator_id: this.operatorId,
        authorization_mode: this.authorizationMode,
        confirmation: SESSION_CONFIRMATION,
      })
      return structuredClone(this._projection.lastSessionConfirmation)
    })
  }

  async confirmCleanupSession({ operatorId, authorizationMode }) {
    return this._runExclusive(async () => {
      this._assertOpen()
      if (
        exactIdentifier(operatorId, 'cleanup session operator') !== this.operatorId
        || authorizationMode !== this.authorizationMode
        || this._projection.stopped !== true
      ) {
        throw ledgerError(
          'HTTP_AUTHED_LEDGER_CLEANUP_SESSION_INVALID',
          'cleanup session confirmation requires the stopped campaign authority',
        )
      }
      await this._append({
        type: 'CLEANUP_SESSION_CONFIRMED',
        operator_id: this.operatorId,
        authorization_mode: this.authorizationMode,
        confirmation: CLEANUP_SESSION_CONFIRMATION,
      })
      return structuredClone(this._projection.lastCleanupSessionConfirmation)
    })
  }

  async enqueueCandidate({ candidateDraft, provenance }) {
    return this._runExclusive(async () => {
      this._assertOpen()
      if (!PROVENANCE.has(provenance)) {
        throw ledgerError('HTTP_AUTHED_LEDGER_PROVENANCE_INVALID', 'candidate provenance is invalid')
      }
      const identity = this._candidateIdentity(candidateDraft, { provenance })
      const existingId = this._projection.candidates.get(identity.candidateSha256)
      if (existingId !== undefined) {
        const existing = this._projection.actions.get(existingId)
        return {
          created: false,
          actionId: existing.action_id,
          candidateSha256: existing.candidate_sha256,
          actionSequence: existing.action_sequence,
          allocatedAction: { ...structuredClone(identity.candidate), sequence: existing.action_sequence },
          headSha256: this._projection.headSha256,
        }
      }
      const actionSequence = this._projection.nextActionSequence
      await this._append({
        type: 'CANDIDATE_ENQUEUED',
        action_id: identity.actionId,
        candidate_sha256: identity.candidateSha256,
        action_sequence: actionSequence,
        action_kind: identity.candidate.kind,
        method: identity.candidate.method,
        test_category: identity.candidate.test_category,
        provenance,
      })
      return {
        created: true,
        actionId: identity.actionId,
        candidateSha256: identity.candidateSha256,
        actionSequence,
        allocatedAction: { ...structuredClone(identity.candidate), sequence: actionSequence },
        headSha256: this._projection.headSha256,
      }
    })
  }

  async leaseAction({ candidateDraft, operatorId }) {
    return this._runExclusive(async () => {
      this._assertOpen()
      const identity = this._candidateIdentity(candidateDraft)
      const action = this._projection.actions.get(identity.actionId)
      if (!action) throw ledgerError('HTTP_AUTHED_LEDGER_ACTION_UNKNOWN', 'candidate is not queued')
      if (action.terminal) {
        throw ledgerError('HTTP_AUTHED_LEDGER_ACTION_TERMINAL', `action is terminal: ${action.outcome}`)
      }
      if (action.state !== 'QUEUED') {
        throw ledgerError('HTTP_AUTHED_LEDGER_ACTION_ACTIVE', 'action is already leased or dispatched')
      }
      if (this._projection.stopped) {
        throw ledgerError('HTTP_AUTHED_LEDGER_STOPPED', 'campaign is stopped')
      }
      const exactOperator = exactIdentifier(operatorId, 'lease operator')
      if (exactOperator !== this.operatorId) {
        throw ledgerError('HTTP_AUTHED_LEDGER_OPERATOR_MISMATCH', 'lease operator does not match campaign')
      }
      const leaseId = randomUUID()
      await this._append({
        type: 'ACTION_LEASED',
        action_id: action.action_id,
        lease_id: leaseId,
        operator_id: exactOperator,
      })
      return {
        actionId: action.action_id,
        candidateSha256: action.candidate_sha256,
        actionSequence: action.action_sequence,
        allocatedAction: { ...structuredClone(identity.candidate), sequence: action.action_sequence },
        leaseId,
        headSha256: this._projection.headSha256,
      }
    })
  }

  async consumeApproval({
    actionId,
    leaseId,
    nonce,
    countersignatureBindingSha256,
  }) {
    return this._runExclusive(async () => {
      this._assertOpen()
      if (
        typeof nonce !== 'string'
        || nonce.length < 16
        || nonce.length > 128
        || !/^[A-Za-z0-9._~-]+$/.test(nonce)
      ) {
        throw ledgerError(
          'HTTP_AUTHED_LEDGER_APPROVAL_NONCE_INVALID',
          'mutation approval nonce is invalid',
        )
      }
      await this._append({
        type: 'APPROVAL_CONSUMED',
        action_id: actionId,
        lease_id: leaseId,
        approval_nonce_sha256: sha256(Buffer.from(
          `red-team-audit/http-authed-approval-nonce/v1\0${nonce}`,
          'utf8',
        )),
        countersignature_binding_sha256: exactSha256(
          countersignatureBindingSha256,
          'countersignature binding',
        ),
      })
      return { consumed: true, headSha256: this._projection.headSha256 }
    })
  }

  async markPreDispatch({ actionId, leaseId, phase, requestBindingSha256 }) {
    return this._runExclusive(async () => {
      this._assertOpen()
      const action = this._projection.actions.get(actionId)
      if (!action || action.terminal) {
        throw ledgerError('HTTP_AUTHED_LEDGER_ACTION_TERMINAL', 'action is unknown or terminal')
      }
      if (action.pending_phase !== null || action.settled_phases.includes(phase)) {
        throw ledgerError('HTTP_AUTHED_LEDGER_PRE_DISPATCH_REPLAY', 'request phase already has pre-dispatch state')
      }
      await this._append({
        type: 'REQUEST_PRE_DISPATCH',
        action_id: actionId,
        lease_id: leaseId,
        phase,
        request_binding_sha256: exactSha256(requestBindingSha256, 'request binding'),
      })
      return { sendPermit: true, headSha256: this._projection.headSha256 }
    })
  }

  async markOutcome({ actionId, leaseId, phase, outcome, responseMetadata = {} }) {
    return this._runExclusive(async () => {
      this._assertOpen()
      const statusValue = responseMetadata.status ?? null
      const headerNames = validateHeaderNames(responseMetadata.headerNames ?? [])
      const hasFailureStage = Object.hasOwn(responseMetadata, 'failureStageCode')
      const hasResponseByteBucket = Object.hasOwn(responseMetadata, 'responseByteBucket')
      const hasObservationFailure = hasFailureStage || hasResponseByteBucket
      let jsonShape
      try {
        jsonShape = responseMetadata.jsonShape === undefined
          ? undefined
          : sanitizeHttpAuthedJsonShape(responseMetadata.jsonShape)
      } catch {
        throw ledgerError('HTTP_AUTHED_LEDGER_RESPONSE_INVALID', 'JSON shape metadata is invalid')
      }
      let responseByteBucket
      if (hasObservationFailure) {
        try {
          responseByteBucket = assertHttpAuthedResponseByteBucket(
            responseMetadata.responseByteBucket,
          )
        } catch {
          throw ledgerError(
            'HTTP_AUTHED_LEDGER_RESPONSE_INVALID',
            'observation-failure response byte bucket is invalid',
          )
        }
        if (
          !hasFailureStage
          || !hasResponseByteBucket
          || responseMetadata.failureStageCode !== HTTP_AUTHED_JSON_SHAPE_FAILURE_STAGE
          || responseMetadata.bytes !== undefined
          || jsonShape !== undefined
        ) {
          throw ledgerError(
            'HTTP_AUTHED_LEDGER_RESPONSE_INVALID',
            'observation-failure response metadata is invalid',
          )
        }
      }
      await this._append({
        type: 'REQUEST_SETTLED',
        action_id: actionId,
        lease_id: leaseId,
        phase,
        outcome,
        status: statusValue,
        header_names: headerNames,
        request_may_have_been_sent: responseMetadata.requestMayHaveBeenSent === true,
        ...(hasObservationFailure
          ? {
              response_byte_bucket: responseByteBucket,
              failure_stage_code: HTTP_AUTHED_JSON_SHAPE_FAILURE_STAGE,
            }
          : { bytes: responseMetadata.bytes ?? 0 }),
        ...(jsonShape === undefined ? {} : { json_shape: jsonShape }),
      })
      return { headSha256: this._projection.headSha256 }
    })
  }

  async recordVerification({ actionId, leaseId, phase, valueMatch, contextMatch }) {
    return this._runExclusive(async () => {
      this._assertOpen()
      await this._append({
        type: 'VERIFICATION_RECORDED',
        action_id: actionId,
        lease_id: leaseId,
        phase,
        value_match: valueMatch === true,
        context_match: contextMatch === true,
      })
      return { headSha256: this._projection.headSha256 }
    })
  }

  async recordDiscoverySummary({
    actionId,
    leaseId,
    acceptedCount,
    duplicateCount,
    rejectedCount,
  }) {
    return this._runExclusive(async () => {
      this._assertOpen()
      await this._append({
        type: 'DISCOVERY_SUMMARY',
        action_id: actionId,
        lease_id: leaseId,
        accepted_count: acceptedCount,
        duplicate_count: duplicateCount,
        rejected_count: rejectedCount,
      })
      return { headSha256: this._projection.headSha256 }
    })
  }

  async terminalizeAction({ actionId, leaseId, outcome, reasonCode = null }) {
    return this._runExclusive(async () => {
      this._assertOpen()
      await this._append({
        type: 'ACTION_TERMINAL',
        action_id: actionId,
        lease_id: leaseId,
        outcome,
        reason_code: reasonCode,
      })
      return { headSha256: this._projection.headSha256 }
    })
  }

  async stopCampaign(reasonCode = 'OPERATOR_REQUESTED') {
    return this._runExclusive(async () => {
      this._assertOpen()
      await this._append({ type: 'CAMPAIGN_STOPPED', reason_code: reasonCode })
      return this.snapshot()
    })
  }

  async close() {
    return this._runExclusive(async () => {
      if (!this._open) {
        this._destroyDiscoveredCandidateIdentityState()
        return
      }
      this._open = false
      const lock = this._lock
      this._lock = null
      try {
        if (lock !== null) await releaseLock(lock, this.directory)
      } finally {
        this._destroyDiscoveredCandidateIdentityState()
      }
    })
  }
}

export async function openHttpAuthedCampaignLedger(options) {
  return HttpAuthedCampaignLedger.open(options)
}
