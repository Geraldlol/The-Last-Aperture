import { createHash } from 'node:crypto'
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  lstatSync,
  writeFileSync,
} from 'node:fs'
import { dirname, isAbsolute, resolve } from 'node:path'
import { TextDecoder } from 'node:util'
import { stableJson } from './run-engine.mjs'

const ZERO_SHA256 = '0'.repeat(64)
const SHA256 = /^[a-f0-9]{64}$/
const RECORD_NAME = /^(\d{12})\.json$/
const MAX_RECORD_BYTES = 1024 * 1024
const MAX_RECORDS = 2_000_001
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true })
const BINDING_FIELDS = Object.freeze([
  'authorization_id',
  'authorization_sha256',
  'engagement_id',
  'plan_sha256',
  'scope_revision_sha256',
  'target_sha256',
])

export const BOUNTY_SCAN_LEDGER_DIRECTORY = 'scan-ledger'

export class BountyScanLedgerError extends Error {
  constructor(code, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'BountyScanLedgerError'
    this.code = code
  }
}

function ledgerError(code, message, options) {
  return new BountyScanLedgerError(code, message, options)
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

export function digestBountyScanLedgerValue(value) {
  return sha256(Buffer.from(stableJson(value, 0), 'utf8'))
}

function assertSha256(value, label) {
  if (typeof value !== 'string' || !SHA256.test(value)) {
    throw ledgerError('BOUNTY_SCAN_LEDGER_BINDING_INVALID', `${label} must be a SHA-256 digest`)
  }
}

function canonicalTimestamp(value, label) {
  const parsed = typeof value === 'string' ? Date.parse(value) : Number.NaN
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw ledgerError('BOUNTY_SCAN_LEDGER_EVENT_INVALID', `${label} must be a canonical timestamp`)
  }
  return parsed
}

function canonicalSnapshot(value, label) {
  let rendered
  let snapshot
  try {
    rendered = stableJson(value, 0)
    if (Buffer.byteLength(rendered, 'utf8') > 1024 * 1024) {
      throw new Error(`${label} exceeds its byte limit`)
    }
    snapshot = JSON.parse(rendered)
  } catch (error) {
    throw ledgerError('BOUNTY_SCAN_LEDGER_VALUE_INVALID', `${label} must be bounded plain JSON`, {
      cause: error,
    })
  }
  if (stableJson(snapshot, 0) !== rendered) {
    throw ledgerError('BOUNTY_SCAN_LEDGER_VALUE_INVALID', `${label} is not stable JSON`)
  }
  return snapshot
}

function normalizeBinding(value) {
  const binding = canonicalSnapshot(value, 'bounty scan ledger binding')
  if (
    Object.keys(binding).sort().join('\n') !== [...BINDING_FIELDS].sort().join('\n')
    || typeof binding.authorization_id !== 'string'
    || binding.authorization_id.length < 3
    || typeof binding.engagement_id !== 'string'
    || binding.engagement_id.length < 3
  ) {
    throw ledgerError(
      'BOUNTY_SCAN_LEDGER_BINDING_INVALID',
      'bounty scan ledger binding is incomplete or has unexpected fields',
    )
  }
  for (const field of [
    'authorization_sha256',
    'plan_sha256',
    'scope_revision_sha256',
    'target_sha256',
  ]) assertSha256(binding[field], field)
  return Object.freeze(binding)
}

function sameValue(left, right) {
  return stableJson(left, 0) === stableJson(right, 0)
}

function blankProjection(binding) {
  return {
    binding,
    records: [],
    headSha256: ZERO_SHA256,
    qualified: 0,
    settled: 0,
    pending: null,
    completed: false,
  }
}

function assertExactEventFields(event, fields) {
  if (
    event === null
    || typeof event !== 'object'
    || Array.isArray(event)
    || Object.keys(event).sort().join('\n') !== [...fields].sort().join('\n')
  ) {
    throw ledgerError('BOUNTY_SCAN_LEDGER_EVENT_INVALID', 'ledger event fields are incomplete or unexpected')
  }
}

function applyEvent(projection, event) {
  if (projection.completed) {
    throw ledgerError('BOUNTY_SCAN_LEDGER_TERMINAL', 'completed bounty scan ledger cannot be extended')
  }
  if (event.type === 'SEND_QUALIFIED') {
    assertExactEventFields(event, [
      'action_id',
      'action_index',
      'action_sha256',
      'authorization_sha256',
      'operator_stop_checked',
      'plan_sha256',
      'qualified_at',
      'request_sha256',
      'revocation_checked',
      'rule_id',
      'scope_revision_sha256',
      'type',
    ])
    if (
      projection.pending !== null
      || !Number.isSafeInteger(event.action_index)
      || event.action_index !== projection.qualified + 1
      || typeof event.action_id !== 'string'
      || event.action_id !== `send:${String(event.action_index).padStart(8, '0')}`
      || event.operator_stop_checked !== true
      || event.revocation_checked !== true
      || typeof event.rule_id !== 'string'
      || event.rule_id.length < 1
      || event.plan_sha256 !== projection.binding.plan_sha256
      || event.scope_revision_sha256 !== projection.binding.scope_revision_sha256
      || event.authorization_sha256 !== projection.binding.authorization_sha256
    ) {
      throw ledgerError(
        'BOUNTY_SCAN_LEDGER_EVENT_INVALID',
        'send qualification is stale, concurrent, or not bound to current authority',
      )
    }
    assertSha256(event.action_sha256, 'action_sha256')
    assertSha256(event.request_sha256, 'request_sha256')
    canonicalTimestamp(event.qualified_at, 'qualified_at')
    projection.qualified += 1
    projection.pending = {
      action_id: event.action_id,
      action_index: event.action_index,
      action_sha256: event.action_sha256,
      qualified_at: event.qualified_at,
    }
    return
  }
  if (event.type === 'SEND_SETTLED') {
    assertExactEventFields(event, [
      'action_id',
      'action_index',
      'action_sha256',
      'error_name',
      'http_status',
      'outcome',
      'send_certainty',
      'settled_at',
      'type',
    ])
    const pending = projection.pending
    const returned = event.outcome === 'RETURNED'
    const threw = event.outcome === 'THREW'
    if (
      pending === null
      || event.action_id !== pending.action_id
      || event.action_index !== pending.action_index
      || event.action_sha256 !== pending.action_sha256
      || (!returned && !threw)
      || (returned && (
        event.send_certainty !== 'SENT'
        || !Number.isInteger(event.http_status)
        || event.http_status < 100
        || event.http_status > 599
        || event.error_name !== null
      ))
      || (threw && (
        event.send_certainty !== 'MAY_HAVE_BEEN_SENT'
        || event.http_status !== null
        || typeof event.error_name !== 'string'
        || event.error_name.length < 1
        || event.error_name.length > 160
      ))
    ) {
      throw ledgerError('BOUNTY_SCAN_LEDGER_EVENT_INVALID', 'send settlement does not match its qualification')
    }
    const settledAt = canonicalTimestamp(event.settled_at, 'settled_at')
    if (settledAt < Date.parse(pending.qualified_at)) {
      throw ledgerError('BOUNTY_SCAN_LEDGER_EVENT_INVALID', 'send settlement predates its qualification')
    }
    projection.settled += 1
    projection.pending = null
    return
  }
  if (event.type === 'SCAN_COMPLETED') {
    assertExactEventFields(event, [
      'completed_at',
      'qualified_sends',
      'settled_sends',
      'summary_sha256',
      'type',
    ])
    if (
      projection.pending !== null
      || event.qualified_sends !== projection.qualified
      || event.settled_sends !== projection.settled
      || projection.qualified !== projection.settled
    ) {
      throw ledgerError('BOUNTY_SCAN_LEDGER_EVENT_INVALID', 'scan completed with an unsettled or miscounted send')
    }
    assertSha256(event.summary_sha256, 'summary_sha256')
    canonicalTimestamp(event.completed_at, 'completed_at')
    projection.completed = true
    return
  }
  throw ledgerError('BOUNTY_SCAN_LEDGER_EVENT_INVALID', `unsupported bounty scan ledger event ${event?.type}`)
}

function publicSnapshot(projection) {
  const status = projection.pending !== null
    ? 'OUTCOME_UNCERTAIN'
    : projection.completed
      ? 'SETTLED'
      : projection.qualified > 0
        ? 'PARTIAL_REQUIRES_RECONCILIATION'
        : 'READY'
  return Object.freeze({
    schema_version: '1.0.0',
    kind: 'red-team-audit/bounty-scan-ledger-status',
    status,
    completed: projection.completed,
    qualified_sends: projection.qualified,
    settled_sends: projection.settled,
    pending_action_sha256: projection.pending?.action_sha256 ?? null,
    head_sha256: projection.headSha256,
  })
}

function loadProjection(directory, binding) {
  const projection = blankProjection(binding)
  const names = readdirSync(directory)
  if (names.length > MAX_RECORDS) {
    throw ledgerError('BOUNTY_SCAN_LEDGER_CORRUPT', 'bounty scan ledger exceeds its finite record limit')
  }
  const recordNames = names.filter((name) => RECORD_NAME.test(name)).sort()
  if (recordNames.length !== names.length) {
    throw ledgerError('BOUNTY_SCAN_LEDGER_CORRUPT', 'bounty scan ledger contains an unexpected file')
  }
  for (let index = 0; index < recordNames.length; index += 1) {
    const name = recordNames[index]
    const expectedName = `${String(index + 1).padStart(12, '0')}.json`
    if (name !== expectedName) {
      throw ledgerError('BOUNTY_SCAN_LEDGER_CORRUPT', 'bounty scan ledger sequence is missing or reordered')
    }
    const recordPath = resolve(directory, name)
    const recordStat = lstatSync(recordPath)
    if (recordStat.isSymbolicLink() || !recordStat.isFile() || recordStat.size > MAX_RECORD_BYTES) {
      throw ledgerError(
        'BOUNTY_SCAN_LEDGER_CORRUPT',
        'bounty scan ledger record is not one bounded regular file',
      )
    }
    const bytes = readFileSync(recordPath)
    if (bytes.byteLength > MAX_RECORD_BYTES) {
      throw ledgerError('BOUNTY_SCAN_LEDGER_CORRUPT', 'bounty scan ledger record exceeds its byte limit')
    }
    let text
    try {
      text = UTF8_DECODER.decode(bytes)
    } catch (error) {
      throw ledgerError('BOUNTY_SCAN_LEDGER_CORRUPT', 'bounty scan ledger record is not valid UTF-8', {
        cause: error,
      })
    }
    let record
    try {
      record = JSON.parse(text)
    } catch (error) {
      throw ledgerError('BOUNTY_SCAN_LEDGER_CORRUPT', 'bounty scan ledger record is not JSON', { cause: error })
    }
    if (
      record === null
      || typeof record !== 'object'
      || Array.isArray(record)
      || stableJson(record, 0) !== text
      || record?.schema_version !== '1.0.0'
      || record.kind !== 'red-team-audit/bounty-scan-ledger-record'
      || record.sequence !== index + 1
      || record.previous_sha256 !== projection.headSha256
      || !sameValue(record.binding, binding)
      || Object.keys(record).sort().join('\n')
        !== ['binding', 'event', 'kind', 'previous_sha256', 'schema_version', 'sequence'].sort().join('\n')
    ) {
      throw ledgerError('BOUNTY_SCAN_LEDGER_CORRUPT', 'bounty scan ledger hash chain or binding is invalid')
    }
    applyEvent(projection, record.event)
    projection.records.push(record)
    projection.headSha256 = sha256(bytes)
  }
  return projection
}

function syncDirectory(directory) {
  if (process.platform === 'win32') return
  const descriptor = openSync(directory, 'r')
  try {
    fsyncSync(descriptor)
  } finally {
    closeSync(descriptor)
  }
}

export class BountyScanLedger {
  constructor({ directory, binding, fsyncFile, fsyncDirectory }) {
    this.directory = directory
    this.binding = binding
    this._fsyncFile = fsyncFile
    this._fsyncDirectory = fsyncDirectory
    this._projection = loadProjection(directory, binding)
    this._failedClosed = false
  }

  snapshot() {
    return publicSnapshot(this._projection)
  }

  assertDispatchable() {
    const snapshot = this.snapshot()
    if (snapshot.status === 'OUTCOME_UNCERTAIN') {
      throw ledgerError(
        'BOUNTY_SCAN_LEDGER_OUTCOME_UNCERTAIN',
        'a prior qualified send has no durable settlement; its outcome is uncertain and it cannot be replayed',
      )
    }
    if (snapshot.completed) {
      throw ledgerError('BOUNTY_SCAN_LEDGER_TERMINAL', 'this exact bounty scan is already completed')
    }
    if (snapshot.qualified_sends > 0) {
      throw ledgerError(
        'BOUNTY_SCAN_LEDGER_PARTIAL_REQUIRES_RECONCILIATION',
        'a prior bounty scan stopped after settled sends; use a new operator-authorized plan after reconciliation instead of replaying from request one',
      )
    }
    return snapshot
  }

  _append(event) {
    if (this._failedClosed) {
      throw ledgerError('BOUNTY_SCAN_LEDGER_FAILED_CLOSED', 'bounty scan ledger must be reopened after an append failure')
    }
    const safeEvent = canonicalSnapshot(event, 'bounty scan ledger event')
    const sequence = this._projection.records.length + 1
    const record = {
      schema_version: '1.0.0',
      kind: 'red-team-audit/bounty-scan-ledger-record',
      sequence,
      previous_sha256: this._projection.headSha256,
      binding: structuredClone(this.binding),
      event: safeEvent,
    }
    const bytes = Buffer.from(stableJson(record, 0), 'utf8')
    const path = resolve(this.directory, `${String(sequence).padStart(12, '0')}.json`)
    if (!path.startsWith(`${this.directory}\\`) && !path.startsWith(`${this.directory}/`)) {
      throw ledgerError('BOUNTY_SCAN_LEDGER_PATH_UNSAFE', 'bounty scan ledger record escaped its directory')
    }
    applyEvent(this._projection, safeEvent)
    let descriptor = null
    try {
      descriptor = openSync(path, 'wx', 0o600)
      writeFileSync(descriptor, bytes)
      this._fsyncFile(descriptor)
      closeSync(descriptor)
      descriptor = null
      this._fsyncDirectory(this.directory)
    } catch (error) {
      this._failedClosed = true
      try {
        this._projection = loadProjection(this.directory, this.binding)
      } catch {
        // Preserve the append error; a fresh open will diagnose any partial record.
      }
      throw ledgerError('BOUNTY_SCAN_LEDGER_APPEND_FAILED', 'bounty scan ledger append failed closed', {
        cause: error,
      })
    } finally {
      if (descriptor !== null) closeSync(descriptor)
    }
    this._projection.records.push(record)
    this._projection.headSha256 = sha256(bytes)
    return this.snapshot()
  }

  qualifySend({
    actionIndex,
    actionSha256,
    requestSha256,
    ruleId,
    qualifiedAt,
  }) {
    return this._append({
      type: 'SEND_QUALIFIED',
      action_id: `send:${String(actionIndex).padStart(8, '0')}`,
      action_index: actionIndex,
      action_sha256: actionSha256,
      request_sha256: requestSha256,
      rule_id: ruleId,
      plan_sha256: this.binding.plan_sha256,
      scope_revision_sha256: this.binding.scope_revision_sha256,
      authorization_sha256: this.binding.authorization_sha256,
      operator_stop_checked: true,
      revocation_checked: true,
      qualified_at: qualifiedAt,
    })
  }

  settleSend({ actionIndex, actionSha256, outcome, httpStatus, errorName, settledAt }) {
    return this._append({
      type: 'SEND_SETTLED',
      action_id: `send:${String(actionIndex).padStart(8, '0')}`,
      action_index: actionIndex,
      action_sha256: actionSha256,
      outcome,
      send_certainty: outcome === 'RETURNED' ? 'SENT' : 'MAY_HAVE_BEEN_SENT',
      http_status: httpStatus,
      error_name: errorName,
      settled_at: settledAt,
    })
  }

  complete({ summarySha256, completedAt }) {
    return this._append({
      type: 'SCAN_COMPLETED',
      qualified_sends: this._projection.qualified,
      settled_sends: this._projection.settled,
      summary_sha256: summarySha256,
      completed_at: completedAt,
    })
  }
}

export function openBountyScanLedger({
  directory,
  binding,
  fsyncFile = fsyncSync,
  fsyncDirectory = syncDirectory,
} = {}) {
  if (typeof directory !== 'string' || !isAbsolute(directory)) {
    throw ledgerError('BOUNTY_SCAN_LEDGER_DIRECTORY_INVALID', 'bounty scan ledger directory must be absolute')
  }
  if (typeof fsyncFile !== 'function' || typeof fsyncDirectory !== 'function') {
    throw ledgerError('BOUNTY_SCAN_LEDGER_DURABILITY_INVALID', 'bounty scan ledger requires durability functions')
  }
  const root = resolve(directory)
  const parent = dirname(root)
  if (!existsSync(parent)) {
    throw ledgerError('BOUNTY_SCAN_LEDGER_DIRECTORY_INVALID', 'bounty scan ledger parent must exist')
  }
  let created = false
  try {
    mkdirSync(root, { recursive: false, mode: 0o700 })
    created = true
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error
  }
  const directoryStat = lstatSync(root)
  if (directoryStat.isSymbolicLink() || !directoryStat.isDirectory()) {
    throw ledgerError(
      'BOUNTY_SCAN_LEDGER_DIRECTORY_INVALID',
      'bounty scan ledger path must be one real directory, not a link or another file type',
    )
  }
  if (created) fsyncDirectory(parent)
  return new BountyScanLedger({
    directory: root,
    binding: normalizeBinding(binding),
    fsyncFile,
    fsyncDirectory,
  })
}
