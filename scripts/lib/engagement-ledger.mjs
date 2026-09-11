import { createHash } from 'node:crypto'
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readSync,
  readdirSync,
  realpathSync,
  writeFileSync,
} from 'node:fs'
import { dirname, isAbsolute, resolve, sep } from 'node:path'
import { TextDecoder } from 'node:util'

import { assertLocalFilesystemEndpoint } from './filesystem-endpoint.mjs'
import { stableJson } from './run-engine.mjs'

export const ENGAGEMENT_LEDGER_SCHEMA_VERSION = '1.0.0'
export const ENGAGEMENT_LEDGER_RECORD_KIND = 'last-aperture/engagement-ledger-record'
export const ENGAGEMENT_LEDGER_ANCHOR_KIND = 'last-aperture/engagement-ledger-anchor'

const ZERO_SHA256 = '0'.repeat(64)
const SHA256 = /^[a-f0-9]{64}$/
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{2,159}$/
const REASON_CODE = /^[A-Z][A-Z0-9_]{2,127}$/
const RECORD_NAME = /^(\d{16})\.engagement\.json$/
const ANCHOR_NAME = /^(\d{16})\.anchor\.json$/
const MAX_RECORD_BYTES = 1024 * 1024
const MAX_ANCHOR_BYTES = 16 * 1024
const MAX_TEXT_BYTES = 16 * 1024
const MAX_REPOSITORY_RESULT_BYTES = 8 * 1024 * 1024
const MAX_APPEND_RETRIES = 32
const ROUTE_OUTCOMES = new Set([
  'SUCCEEDED',
  'PARTIAL',
  'FAILED',
  'CANCELLED_BEFORE_SEND',
  'UNCERTAIN',
  'STOPPED',
])
const TERMINAL_STATUSES = new Set([
  'COMPLETED',
  'COMPLETED_WITH_GAPS',
  'FAILED',
  'STOPPED',
])
const REPOSITORY_CHECKPOINT_OPERATIONS = new Set([
  'INITIAL',
  'NEXT',
  'STATUS',
  'INGEST',
  'FINALIZE',
  'VALIDATE',
])
const REPOSITORY_TERMINAL_STATES = new Set(['COMPLETED', 'COMPLETE_WITH_GAPS', 'FAILED', 'ABORTED'])
const REPOSITORY_WORK_RESULT_STATES = new Set(['RESULT_INGESTED'])
const REPOSITORY_INGEST_RECONCILIATIONS = new Set(['APPLIED', 'NOT_APPLIED', 'CONFLICT'])
const BINDING_FIELDS = Object.freeze([
  'authority_sha256',
  'engagement_id',
  'target_sha256',
])

export class EngagementLedgerError extends Error {
  constructor(code, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'EngagementLedgerError'
    this.code = code
  }
}

function ledgerError(code, message, options) {
  return new EngagementLedgerError(code, message, options)
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function exactFields(value, fields, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw ledgerError('ENGAGEMENT_LEDGER_EVENT_INVALID', `${label} must be an object`)
  }
  const actual = Object.keys(value).sort()
  const expected = [...fields].sort()
  if (stableJson(actual, 0) !== stableJson(expected, 0)) {
    throw ledgerError(
      'ENGAGEMENT_LEDGER_EVENT_INVALID',
      `${label} contains missing or unexpected fields`,
    )
  }
}

function exactSha256(value, label) {
  if (typeof value !== 'string' || !SHA256.test(value)) {
    throw ledgerError('ENGAGEMENT_LEDGER_DIGEST_INVALID', `${label} must be a SHA-256 digest`)
  }
  return value
}

function exactIdentifier(value, label) {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) {
    throw ledgerError('ENGAGEMENT_LEDGER_ID_INVALID', `${label} is invalid`)
  }
  return value
}

function exactTimestamp(value, label) {
  if (typeof value !== 'string') {
    throw ledgerError('ENGAGEMENT_LEDGER_TIME_INVALID', `${label} must be a canonical timestamp`)
  }
  const parsed = Date.parse(value)
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw ledgerError('ENGAGEMENT_LEDGER_TIME_INVALID', `${label} must be a canonical timestamp`)
  }
  return value
}

function exactReason(value) {
  if (
    typeof value !== 'string'
    || value.trim() !== value
    || value.length < 1
    || Buffer.byteLength(value, 'utf8') > MAX_TEXT_BYTES
    || /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw ledgerError('ENGAGEMENT_LEDGER_STOP_INVALID', 'stop reason must be bounded human text')
  }
  return value
}

function canonicalSnapshot(value, label, maximumBytes = MAX_RECORD_BYTES) {
  const active = new WeakSet()
  const stack = [{ value, depth: 0 }]
  let nodes = 0
  while (stack.length > 0) {
    const current = stack.pop()
    if (current.exit) {
      active.delete(current.value)
      continue
    }
    nodes += 1
    if (nodes > 20_000 || current.depth > 32) {
      throw ledgerError('ENGAGEMENT_LEDGER_VALUE_TOO_LARGE', `${label} exceeds JSON limits`)
    }
    const item = current.value
    if (item === null || typeof item === 'string' || typeof item === 'boolean') continue
    if (typeof item === 'number') {
      if (!Number.isFinite(item)) {
        throw ledgerError('ENGAGEMENT_LEDGER_VALUE_INVALID', `${label} contains a non-finite number`)
      }
      continue
    }
    if (typeof item !== 'object' || active.has(item)) {
      throw ledgerError('ENGAGEMENT_LEDGER_VALUE_INVALID', `${label} is not plain JSON`)
    }
    const array = Array.isArray(item)
    const prototype = Object.getPrototypeOf(item)
    if (
      (!array && prototype !== Object.prototype && prototype !== null)
      || (array && prototype !== Array.prototype)
      || Object.getOwnPropertySymbols(item).length > 0
    ) {
      throw ledgerError('ENGAGEMENT_LEDGER_VALUE_INVALID', `${label} is not plain JSON`)
    }
    active.add(item)
    stack.push({ value: item, exit: true })
    for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(item))) {
      if (array && key === 'length') continue
      if (!descriptor.enumerable || 'get' in descriptor || 'set' in descriptor) {
        throw ledgerError('ENGAGEMENT_LEDGER_VALUE_INVALID', `${label} contains hidden state`)
      }
      stack.push({ value: descriptor.value, depth: current.depth + 1 })
    }
  }
  const rendered = stableJson(value, 0)
  if (Buffer.byteLength(rendered, 'utf8') > maximumBytes) {
    throw ledgerError('ENGAGEMENT_LEDGER_VALUE_TOO_LARGE', `${label} exceeds its byte limit`)
  }
  try {
    return JSON.parse(rendered)
  } catch (cause) {
    throw ledgerError('ENGAGEMENT_LEDGER_VALUE_INVALID', `${label} is not JSON`, { cause })
  }
}

function normalizeBinding(value) {
  const binding = canonicalSnapshot(value, 'engagement ledger binding', 4096)
  const fields = Object.keys(binding).sort()
  if (stableJson(fields, 0) !== stableJson([...BINDING_FIELDS].sort(), 0)) {
    throw ledgerError(
      'ENGAGEMENT_LEDGER_BINDING_INVALID',
      'engagement ledger binding has missing or unexpected fields',
    )
  }
  exactIdentifier(binding.engagement_id, 'engagement_id')
  exactSha256(binding.authority_sha256, 'authority_sha256')
  exactSha256(binding.target_sha256, 'target_sha256')
  return Object.freeze(binding)
}

function normalizeExpectedHead(value) {
  if (value === undefined) return null
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw ledgerError('ENGAGEMENT_LEDGER_TRUSTED_HEAD_INVALID', 'expected head must be an object')
  }
  const fields = Object.keys(value).sort()
  if (stableJson(fields, 0) !== stableJson(['headSha256', 'recordCount'], 0)) {
    throw ledgerError('ENGAGEMENT_LEDGER_TRUSTED_HEAD_INVALID', 'expected head has unexpected fields')
  }
  if (!Number.isSafeInteger(value.recordCount) || value.recordCount < 0) {
    throw ledgerError('ENGAGEMENT_LEDGER_TRUSTED_HEAD_INVALID', 'expected record count is invalid')
  }
  exactSha256(value.headSha256, 'expected head_sha256')
  if ((value.recordCount === 0) !== (value.headSha256 === ZERO_SHA256)) {
    throw ledgerError('ENGAGEMENT_LEDGER_TRUSTED_HEAD_INVALID', 'empty expected head must use the zero digest')
  }
  return Object.freeze({ recordCount: value.recordCount, headSha256: value.headSha256 })
}

function blankProjection(binding) {
  return {
    binding,
    records: [],
    recordDigests: [],
    headSha256: ZERO_SHA256,
    started: false,
    manifestSha256: null,
    startedAt: null,
    resumeCount: 0,
    routes: new Map(),
    repositoryCheckpoints: [],
    repositoryWorks: new Map(),
    stopRequest: null,
    terminalResult: null,
  }
}

function latestProjectionTimestamp(projection) {
  const timestamps = [projection.startedAt, projection.stopRequest?.requested_at]
  for (const route of projection.routes.values()) {
    timestamps.push(
      route.planned_at,
      route.waiting?.waiting_at,
      route.permitted_at,
      route.outcome?.completed_at,
    )
  }
  for (const checkpoint of projection.repositoryCheckpoints) timestamps.push(checkpoint.checkpointed_at)
  for (const work of projection.repositoryWorks.values()) {
    timestamps.push(work.issued_at, work.result?.recorded_at)
    for (const attempt of work.ingest_attempts) {
      timestamps.push(attempt.dispatched_at, attempt.reconciliation?.reconciled_at)
    }
  }
  return timestamps.filter(Boolean).sort().at(-1) ?? null
}

function orderedEventTimestamp(value, label, ...floors) {
  const timestamp = exactTimestamp(value, label)
  const latestFloor = floors.filter(Boolean).sort().at(-1)
  if (latestFloor !== undefined && Date.parse(timestamp) < Date.parse(latestFloor)) {
    throw ledgerError(
      'ENGAGEMENT_LEDGER_TIME_REGRESSION',
      `${label} predates the lifecycle state it records`,
    )
  }
  return timestamp
}

function assertStarted(projection) {
  if (!projection.started) {
    throw ledgerError('ENGAGEMENT_LEDGER_NOT_STARTED', 'engagement has not started')
  }
}

function assertActive(projection) {
  assertStarted(projection)
  if (projection.terminalResult !== null) {
    throw ledgerError('ENGAGEMENT_LEDGER_TERMINAL', 'engagement is terminal')
  }
}

function exactRoute(projection, event) {
  const route = projection.routes.get(event.route_id)
  if (route === undefined) {
    throw ledgerError('ENGAGEMENT_LEDGER_ROUTE_UNKNOWN', 'route has not been planned')
  }
  if (route.plan_sha256 !== event.plan_sha256) {
    throw ledgerError('ENGAGEMENT_LEDGER_ROUTE_PLAN_MISMATCH', 'route plan digest does not match')
  }
  return route
}

function assertDispatchAllowedInProjection(projection, routeId, planSha256) {
  assertActive(projection)
  if (projection.stopRequest !== null) {
    throw ledgerError('ENGAGEMENT_LEDGER_STOP_REQUESTED', 'engagement stop was requested')
  }
  exactIdentifier(routeId, 'route_id')
  exactSha256(planSha256, 'plan_sha256')
  const route = exactRoute(projection, { route_id: routeId, plan_sha256: planSha256 })
  if (route.outcome !== null) {
    throw ledgerError('ENGAGEMENT_LEDGER_ROUTE_SETTLED', 'route already has a terminal outcome')
  }
  if (route.permit_sha256 !== null) {
    throw ledgerError('ENGAGEMENT_LEDGER_DISPATCH_ALREADY_PERMITTED', 'route dispatch is already permitted')
  }
  return route
}

function applyEvent(projection, event) {
  if (event.type === 'ENGAGEMENT_STARTED') {
    exactFields(event, ['manifest_sha256', 'started_at', 'type'], 'engagement start event')
    if (projection.records.length !== 0 || projection.started) {
      throw ledgerError('ENGAGEMENT_LEDGER_ALREADY_STARTED', 'engagement already started')
    }
    projection.manifestSha256 = exactSha256(event.manifest_sha256, 'manifest_sha256')
    projection.startedAt = exactTimestamp(event.started_at, 'started_at')
    projection.started = true
    return
  }

  assertActive(projection)
  if (event.type === 'ENGAGEMENT_RESUMED') {
    exactFields(event, ['resume_count', 'resumed_at', 'type'], 'engagement resume event')
    if (projection.stopRequest !== null) {
      throw ledgerError('ENGAGEMENT_LEDGER_STOP_REQUESTED', 'stopped engagement cannot resume')
    }
    if (!Number.isSafeInteger(event.resume_count) || event.resume_count !== projection.resumeCount + 1) {
      throw ledgerError('ENGAGEMENT_LEDGER_EVENT_INVALID', 'resume count is not monotonic')
    }
    orderedEventTimestamp(
      event.resumed_at,
      'resumed_at',
      latestProjectionTimestamp(projection),
    )
    projection.resumeCount = event.resume_count
    return
  }

  if (event.type === 'ROUTE_PLANNED') {
    exactFields(event, ['plan_sha256', 'planned_at', 'route_id', 'type'], 'route plan event')
    if (projection.stopRequest !== null) {
      throw ledgerError('ENGAGEMENT_LEDGER_STOP_REQUESTED', 'engagement stop was requested')
    }
    exactIdentifier(event.route_id, 'route_id')
    exactSha256(event.plan_sha256, 'plan_sha256')
    orderedEventTimestamp(
      event.planned_at,
      'planned_at',
      latestProjectionTimestamp(projection),
    )
    if (projection.routes.has(event.route_id)) {
      throw ledgerError('ENGAGEMENT_LEDGER_ROUTE_DUPLICATE', 'route identifier is already planned')
    }
    projection.routes.set(event.route_id, {
      route_id: event.route_id,
      plan_sha256: event.plan_sha256,
      planned_at: event.planned_at,
      state: 'PLANNED',
      waiting: null,
      permit_sha256: null,
      permitted_at: null,
      outcome: null,
    })
    return
  }

  if (event.type === 'ROUTE_WAITING') {
    exactFields(
      event,
      ['plan_sha256', 'reason_code', 'route_id', 'type', 'waiting_at'],
      'route waiting event',
    )
    if (projection.stopRequest !== null) {
      throw ledgerError('ENGAGEMENT_LEDGER_STOP_REQUESTED', 'engagement stop was requested')
    }
    exactIdentifier(event.route_id, 'route_id')
    exactSha256(event.plan_sha256, 'plan_sha256')
    if (typeof event.reason_code !== 'string' || !REASON_CODE.test(event.reason_code)) {
      throw ledgerError('ENGAGEMENT_LEDGER_EVENT_INVALID', 'route waiting reason code is invalid')
    }
    const route = exactRoute(projection, event)
    if (route.permit_sha256 !== null || route.outcome !== null) {
      throw ledgerError('ENGAGEMENT_LEDGER_ROUTE_SETTLED', 'dispatched or settled route cannot wait for material')
    }
    orderedEventTimestamp(
      event.waiting_at,
      'waiting_at',
      latestProjectionTimestamp(projection),
      route.planned_at,
    )
    route.state = 'WAITING'
    route.waiting = { reason_code: event.reason_code, waiting_at: event.waiting_at }
    return
  }

  if (event.type === 'ROUTE_DISPATCH_PERMITTED') {
    exactFields(
      event,
      ['permit_sha256', 'permitted_at', 'plan_sha256', 'route_id', 'type'],
      'route dispatch permit event',
    )
    const route = assertDispatchAllowedInProjection(projection, event.route_id, event.plan_sha256)
    exactSha256(event.permit_sha256, 'permit_sha256')
    orderedEventTimestamp(
      event.permitted_at,
      'permitted_at',
      latestProjectionTimestamp(projection),
      route.planned_at,
      route.waiting?.waiting_at,
    )
    route.state = 'DISPATCH_PERMITTED'
    route.permit_sha256 = event.permit_sha256
    route.permitted_at = event.permitted_at
    return
  }

  if (event.type === 'ROUTE_OUTCOME_RECORDED') {
    exactFields(
      event,
      [
        'completed_at',
        'plan_sha256',
        'request_may_have_been_sent',
        'result_sha256',
        'route_id',
        'status',
        'type',
      ],
      'route outcome event',
    )
    exactIdentifier(event.route_id, 'route_id')
    exactSha256(event.plan_sha256, 'plan_sha256')
    exactSha256(event.result_sha256, 'result_sha256')
    if (!ROUTE_OUTCOMES.has(event.status) || typeof event.request_may_have_been_sent !== 'boolean') {
      throw ledgerError('ENGAGEMENT_LEDGER_EVENT_INVALID', 'route outcome is invalid')
    }
    const route = exactRoute(projection, event)
    if (route.permit_sha256 === null) {
      throw ledgerError('ENGAGEMENT_LEDGER_DISPATCH_NOT_PERMITTED', 'route outcome lacks a dispatch permit')
    }
    if (route.outcome !== null) {
      throw ledgerError('ENGAGEMENT_LEDGER_ROUTE_SETTLED', 'route already has an outcome')
    }
    orderedEventTimestamp(
      event.completed_at,
      'completed_at',
      latestProjectionTimestamp(projection),
      route.permitted_at,
    )
    route.state = event.status
    route.outcome = {
      status: event.status,
      result_sha256: event.result_sha256,
      request_may_have_been_sent: event.request_may_have_been_sent,
      completed_at: event.completed_at,
    }
    return
  }

  if (event.type === 'REPOSITORY_CHILD_CHECKPOINTED') {
    exactFields(event, [
      'checkpoint_sha256',
      'checkpointed_at',
      'child_bundle_sha256',
      'child_state',
      'child_tree_sha256',
      'operation',
      'route_id',
      'status_sha256',
      'terminal',
      'type',
    ], 'repository child checkpoint event')
    if (event.route_id !== 'repository-audit') {
      throw ledgerError('ENGAGEMENT_LEDGER_EVENT_INVALID', 'repository checkpoint route is invalid')
    }
    const route = projection.routes.get(event.route_id)
    if (route?.outcome?.status !== 'PARTIAL') {
      throw ledgerError(
        'ENGAGEMENT_LEDGER_REPOSITORY_ROUTE_INVALID',
        'repository checkpoints require a planned-only repository route outcome',
      )
    }
    if (!REPOSITORY_CHECKPOINT_OPERATIONS.has(event.operation)) {
      throw ledgerError('ENGAGEMENT_LEDGER_EVENT_INVALID', 'repository checkpoint operation is invalid')
    }
    exactSha256(event.child_bundle_sha256, 'child_bundle_sha256')
    exactSha256(event.child_tree_sha256, 'child_tree_sha256')
    exactSha256(event.status_sha256, 'status_sha256')
    exactSha256(event.checkpoint_sha256, 'checkpoint_sha256')
    if (typeof event.child_state !== 'string' || !REASON_CODE.test(event.child_state)) {
      throw ledgerError('ENGAGEMENT_LEDGER_EVENT_INVALID', 'repository child state is invalid')
    }
    if (typeof event.terminal !== 'boolean'
      || event.terminal !== REPOSITORY_TERMINAL_STATES.has(event.child_state)) {
      throw ledgerError('ENGAGEMENT_LEDGER_EVENT_INVALID', 'repository child terminal state is inconsistent')
    }
    if ((event.operation === 'INITIAL') !== (projection.repositoryCheckpoints.length === 0)) {
      throw ledgerError('ENGAGEMENT_LEDGER_REPOSITORY_CHECKPOINT_INVALID', 'repository initial checkpoint is not unique')
    }
    const prior = projection.repositoryCheckpoints.at(-1)
    const activeWork = [...projection.repositoryWorks.values()].find((work) => work.result === null)
    if (activeWork !== undefined && activeWork.ingest !== null && event.operation !== 'INGEST') {
      throw ledgerError(
        'ENGAGEMENT_LEDGER_REPOSITORY_RECOVERY_REQUIRED',
        'an unresolved repository ingest permits only its reconciled INGEST checkpoint',
      )
    }
    if (
      event.operation === 'INGEST'
      && activeWork?.ingest?.reconciliation?.outcome !== 'APPLIED'
    ) {
      throw ledgerError(
        'ENGAGEMENT_LEDGER_REPOSITORY_RECOVERY_REQUIRED',
        'repository ingest checkpoint requires an exact applied-result reconciliation',
      )
    }
    if (
      event.operation === 'INGEST'
      && prior?.operation === 'INGEST'
      && activeWork !== undefined
    ) {
      throw ledgerError(
        'ENGAGEMENT_LEDGER_REPOSITORY_CHECKPOINT_INVALID',
        'repository ingest checkpoint is already recorded for the active work',
      )
    }
    if (prior !== undefined && prior.child_bundle_sha256 !== event.child_bundle_sha256) {
      throw ledgerError('ENGAGEMENT_LEDGER_REPOSITORY_CHILD_CHANGED', 'repository child bundle identity changed')
    }
    const checkpointedAt = orderedEventTimestamp(
      event.checkpointed_at,
      'checkpointed_at',
      latestProjectionTimestamp(projection),
      route.outcome.completed_at,
    )
    projection.repositoryCheckpoints.push({
      operation: event.operation,
      route_id: event.route_id,
      child_bundle_sha256: event.child_bundle_sha256,
      child_tree_sha256: event.child_tree_sha256,
      status_sha256: event.status_sha256,
      checkpoint_sha256: event.checkpoint_sha256,
      child_state: event.child_state,
      terminal: event.terminal,
      checkpointed_at: checkpointedAt,
    })
    return
  }

  if (event.type === 'REPOSITORY_WORK_ISSUED') {
    exactFields(event, [
      'child_tree_sha256',
      'envelope_sha256',
      'issued_at',
      'type',
      'work_id',
    ], 'repository work issue event')
    const checkpoint = projection.repositoryCheckpoints.at(-1)
    if (checkpoint === undefined || checkpoint.terminal) {
      throw ledgerError('ENGAGEMENT_LEDGER_REPOSITORY_CHECKPOINT_MISSING', 'repository work requires a current nonterminal child checkpoint')
    }
    exactIdentifier(event.work_id, 'work_id')
    exactSha256(event.envelope_sha256, 'envelope_sha256')
    exactSha256(event.child_tree_sha256, 'child_tree_sha256')
    if (event.child_tree_sha256 !== checkpoint.child_tree_sha256) {
      throw ledgerError('ENGAGEMENT_LEDGER_REPOSITORY_CHILD_CHANGED', 'repository work was issued from a stale child checkpoint')
    }
    if (projection.repositoryWorks.has(event.work_id)
      || [...projection.repositoryWorks.values()].some((work) => work.result === null)) {
      throw ledgerError('ENGAGEMENT_LEDGER_REPOSITORY_WORK_ACTIVE', 'repository work is duplicate or another work lease is active')
    }
    const issuedAt = orderedEventTimestamp(
      event.issued_at,
      'issued_at',
      latestProjectionTimestamp(projection),
      checkpoint.checkpointed_at,
    )
    projection.repositoryWorks.set(event.work_id, {
      work_id: event.work_id,
      envelope_sha256: event.envelope_sha256,
      child_tree_sha256: event.child_tree_sha256,
      issued_at: issuedAt,
      ingest_attempts: [],
      ingest: null,
      result: null,
    })
    return
  }

  if (event.type === 'REPOSITORY_INGEST_DISPATCHED') {
    exactFields(event, [
      'attempt',
      'dispatched_at',
      'envelope_sha256',
      'pre_child_tree_sha256',
      'result_sha256',
      'result_size_bytes',
      'result_state',
      'staged_relative_path',
      'type',
      'work_id',
    ], 'repository ingest dispatch event')
    exactIdentifier(event.work_id, 'work_id')
    exactSha256(event.envelope_sha256, 'envelope_sha256')
    exactSha256(event.pre_child_tree_sha256, 'pre_child_tree_sha256')
    exactSha256(event.result_sha256, 'result_sha256')
    if (!Number.isSafeInteger(event.attempt) || event.attempt < 1) {
      throw ledgerError('ENGAGEMENT_LEDGER_EVENT_INVALID', 'repository ingest attempt is invalid')
    }
    if (
      !Number.isSafeInteger(event.result_size_bytes)
      || event.result_size_bytes < 0
      || event.result_size_bytes > MAX_REPOSITORY_RESULT_BYTES
    ) {
      throw ledgerError('ENGAGEMENT_LEDGER_EVENT_INVALID', 'repository ingest result size is invalid')
    }
    if (typeof event.result_state !== 'string' || !REASON_CODE.test(event.result_state)) {
      throw ledgerError('ENGAGEMENT_LEDGER_EVENT_INVALID', 'repository ingest result state is invalid')
    }
    const expectedStagedName = `${event.envelope_sha256}-${event.result_sha256}.json`
    if (event.staged_relative_path !== expectedStagedName) {
      throw ledgerError('ENGAGEMENT_LEDGER_EVENT_INVALID', 'repository ingest staged path is not content-bound')
    }
    const work = projection.repositoryWorks.get(event.work_id)
    const checkpoint = projection.repositoryCheckpoints.at(-1)
    if (
      work === undefined
      || work.result !== null
      || work.ingest !== null
      || work.envelope_sha256 !== event.envelope_sha256
      || checkpoint === undefined
      || checkpoint.child_tree_sha256 !== event.pre_child_tree_sha256
    ) {
      throw ledgerError('ENGAGEMENT_LEDGER_REPOSITORY_WORK_INVALID', 'repository ingest dispatch lacks its exact active work checkpoint')
    }
    if (event.attempt !== work.ingest_attempts.length + 1) {
      throw ledgerError('ENGAGEMENT_LEDGER_EVENT_INVALID', 'repository ingest attempt is not monotonic')
    }
    const prior = work.ingest_attempts.at(-1)
    if (prior !== undefined && (
      prior.result_sha256 !== event.result_sha256
      || prior.result_size_bytes !== event.result_size_bytes
      || prior.staged_relative_path !== event.staged_relative_path
      || prior.result_state !== event.result_state
    )) {
      throw ledgerError('ENGAGEMENT_LEDGER_REPOSITORY_WORK_INVALID', 'repository ingest retry differs from the exact first result')
    }
    const dispatchedAt = orderedEventTimestamp(
      event.dispatched_at,
      'dispatched_at',
      latestProjectionTimestamp(projection),
      work.issued_at,
      checkpoint.checkpointed_at,
    )
    const attempt = {
      attempt: event.attempt,
      envelope_sha256: event.envelope_sha256,
      pre_child_tree_sha256: event.pre_child_tree_sha256,
      staged_relative_path: event.staged_relative_path,
      result_sha256: event.result_sha256,
      result_size_bytes: event.result_size_bytes,
      result_state: event.result_state,
      dispatched_at: dispatchedAt,
      reconciliation: null,
    }
    work.ingest_attempts.push(attempt)
    work.ingest = attempt
    return
  }

  if (event.type === 'REPOSITORY_INGEST_RECONCILED') {
    exactFields(event, [
      'attempt',
      'envelope_sha256',
      'observed_child_tree_sha256',
      'outcome',
      'reconciled_at',
      'type',
      'work_id',
    ], 'repository ingest reconciliation event')
    exactIdentifier(event.work_id, 'work_id')
    exactSha256(event.envelope_sha256, 'envelope_sha256')
    exactSha256(event.observed_child_tree_sha256, 'observed_child_tree_sha256')
    if (!Number.isSafeInteger(event.attempt) || event.attempt < 1
      || !REPOSITORY_INGEST_RECONCILIATIONS.has(event.outcome)) {
      throw ledgerError('ENGAGEMENT_LEDGER_EVENT_INVALID', 'repository ingest reconciliation is invalid')
    }
    const work = projection.repositoryWorks.get(event.work_id)
    const ingest = work?.ingest
    if (
      work === undefined
      || work.result !== null
      || work.envelope_sha256 !== event.envelope_sha256
      || ingest === null
      || ingest.attempt !== event.attempt
      || ingest.reconciliation !== null
    ) {
      throw ledgerError('ENGAGEMENT_LEDGER_REPOSITORY_WORK_INVALID', 'repository ingest reconciliation lacks its exact active dispatch')
    }
    if (event.outcome === 'NOT_APPLIED'
      && event.observed_child_tree_sha256 !== ingest.pre_child_tree_sha256) {
      throw ledgerError('ENGAGEMENT_LEDGER_REPOSITORY_CHILD_CHANGED', 'not-applied reconciliation requires the exact pre-dispatch child tree')
    }
    const reconciledAt = orderedEventTimestamp(
      event.reconciled_at,
      'reconciled_at',
      latestProjectionTimestamp(projection),
      ingest.dispatched_at,
    )
    ingest.reconciliation = {
      outcome: event.outcome,
      observed_child_tree_sha256: event.observed_child_tree_sha256,
      reconciled_at: reconciledAt,
    }
    if (event.outcome === 'NOT_APPLIED') work.ingest = null
    return
  }

  if (event.type === 'REPOSITORY_WORK_RESULT_RECORDED') {
    exactFields(event, [
      'child_tree_sha256',
      'envelope_sha256',
      'receipt_sha256',
      'recorded_at',
      'status',
      'type',
      'work_id',
    ], 'repository work result event')
    exactIdentifier(event.work_id, 'work_id')
    exactSha256(event.envelope_sha256, 'envelope_sha256')
    exactSha256(event.receipt_sha256, 'receipt_sha256')
    exactSha256(event.child_tree_sha256, 'child_tree_sha256')
    if (!REPOSITORY_WORK_RESULT_STATES.has(event.status)) {
      throw ledgerError('ENGAGEMENT_LEDGER_EVENT_INVALID', 'repository work result state is invalid')
    }
    const work = projection.repositoryWorks.get(event.work_id)
    const checkpoint = projection.repositoryCheckpoints.at(-1)
    if (work === undefined || work.result !== null || work.envelope_sha256 !== event.envelope_sha256) {
      throw ledgerError('ENGAGEMENT_LEDGER_REPOSITORY_WORK_INVALID', 'repository work result lacks its exact active envelope')
    }
    if (event.status === 'RESULT_INGESTED'
      && work.ingest?.reconciliation?.outcome !== 'APPLIED') {
      throw ledgerError('ENGAGEMENT_LEDGER_REPOSITORY_WORK_INVALID', 'repository result lacks an exact applied ingest reconciliation')
    }
    if (checkpoint === undefined || checkpoint.child_tree_sha256 !== event.child_tree_sha256) {
      throw ledgerError('ENGAGEMENT_LEDGER_REPOSITORY_CHILD_CHANGED', 'repository work result lacks its child checkpoint')
    }
    if (checkpoint.operation !== 'INGEST') {
      throw ledgerError('ENGAGEMENT_LEDGER_REPOSITORY_WORK_INVALID', 'repository result requires its exact ingest checkpoint')
    }
    const recordedAt = orderedEventTimestamp(
      event.recorded_at,
      'recorded_at',
      latestProjectionTimestamp(projection),
      work.issued_at,
      checkpoint.checkpointed_at,
    )
    work.result = {
      status: event.status,
      receipt_sha256: event.receipt_sha256,
      child_tree_sha256: event.child_tree_sha256,
      recorded_at: recordedAt,
    }
    work.ingest = null
    return
  }

  if (event.type === 'ENGAGEMENT_STOP_REQUESTED') {
    exactFields(event, ['reason', 'requested_at', 'type'], 'engagement stop event')
    if (projection.stopRequest !== null) {
      throw ledgerError('ENGAGEMENT_LEDGER_STOP_DUPLICATE', 'engagement stop is already recorded')
    }
    projection.stopRequest = {
      reason: exactReason(event.reason),
      requested_at: orderedEventTimestamp(
        event.requested_at,
        'requested_at',
        projection.startedAt,
      ),
    }
    return
  }

  if (event.type === 'ENGAGEMENT_TERMINAL') {
    exactFields(event, ['result_sha256', 'status', 'terminal_at', 'type'], 'terminal event')
    if (!TERMINAL_STATUSES.has(event.status)) {
      throw ledgerError('ENGAGEMENT_LEDGER_EVENT_INVALID', 'terminal status is invalid')
    }
    if ((projection.stopRequest !== null) !== (event.status === 'STOPPED')) {
      throw ledgerError(
        'ENGAGEMENT_LEDGER_EVENT_INVALID',
        'stopped engagements require a STOPPED terminal result and vice versa',
      )
    }
    const unresolvedIngest = [...projection.repositoryWorks.values()]
      .find((work) => work.result === null && work.ingest !== null)
    if (unresolvedIngest !== undefined) {
      throw ledgerError(
        'ENGAGEMENT_LEDGER_REPOSITORY_RECOVERY_REQUIRED',
        'terminal engagement would hide an unresolved repository ingest dispatch',
      )
    }
    const routes = [...projection.routes.values()]
    for (const route of routes) {
      if (route.permit_sha256 !== null && route.outcome === null) {
        throw ledgerError(
          'ENGAGEMENT_LEDGER_DISPATCH_UNSETTLED',
          'terminal engagement would hide an unsettled route dispatch',
        )
      }
    }
    if (event.status !== 'STOPPED') {
      if (routes.length === 0 || routes.some((route) => route.outcome === null)) {
        throw ledgerError(
          'ENGAGEMENT_LEDGER_TERMINAL_INCOMPLETE',
          'non-stopped terminal engagements require every planned route to have an outcome',
        )
      }
      const allSucceeded = routes.every((route) => route.outcome.status === 'SUCCEEDED')
      const whollyFailed = routes.every((route) => [
        'FAILED',
        'CANCELLED_BEFORE_SEND',
      ].includes(route.outcome.status))
      if (
        (event.status === 'COMPLETED' && !allSucceeded)
        || (event.status === 'COMPLETED_WITH_GAPS' && allSucceeded)
        || (event.status === 'FAILED' && !whollyFailed)
      ) {
        throw ledgerError(
          'ENGAGEMENT_LEDGER_TERMINAL_STATUS_MISMATCH',
          'terminal status does not match the recorded route outcomes',
        )
      }
    }
    const terminalAt = orderedEventTimestamp(
      event.terminal_at,
      'terminal_at',
      latestProjectionTimestamp(projection),
    )
    projection.terminalResult = {
      status: event.status,
      result_sha256: exactSha256(event.result_sha256, 'result_sha256'),
      terminal_at: terminalAt,
    }
    return
  }

  throw ledgerError('ENGAGEMENT_LEDGER_EVENT_INVALID', `unsupported event ${event.type ?? '(missing)'}`)
}

const FILE_IDENTITY_FIELDS = Object.freeze([
  'dev',
  'ino',
  'mode',
  'nlink',
  'uid',
  'gid',
  'size',
  'mtimeNs',
  'ctimeNs',
  'birthtimeNs',
])

function isSingleRegularFile(metadata) {
  return metadata.isFile() && !metadata.isSymbolicLink() && metadata.nlink === 1n
}

function sameFileIdentity(left, right) {
  return FILE_IDENTITY_FIELDS.every((field) => left[field] === right[field])
}

function readBoundedDescriptor(descriptor, maximumBytes, code, label) {
  const destination = Buffer.allocUnsafe(maximumBytes + 1)
  let offset = 0
  while (offset <= maximumBytes) {
    const read = readSync(
      descriptor,
      destination,
      offset,
      destination.length - offset,
      null,
    )
    if (read === 0) break
    offset += read
  }
  if (offset > maximumBytes) {
    throw ledgerError(code, `${label} exceeds its byte limit`)
  }
  return Buffer.from(destination.subarray(0, offset))
}

function readStableRegularFile(path, maximumBytes, code, label) {
  let descriptor = null
  try {
    const pathBefore = lstatSync(path, { bigint: true })
    if (!isSingleRegularFile(pathBefore) || pathBefore.size > BigInt(maximumBytes)) {
      throw ledgerError(code, `${label} must be one bounded regular file with one link`)
    }

    const noFollow = constants.O_NOFOLLOW ?? 0
    descriptor = openSync(path, constants.O_RDONLY | noFollow)
    const handleBefore = fstatSync(descriptor, { bigint: true })
    if (
      !isSingleRegularFile(handleBefore)
      || handleBefore.size > BigInt(maximumBytes)
      || !sameFileIdentity(pathBefore, handleBefore)
    ) {
      throw ledgerError(code, `${label} changed while its read handle was acquired`)
    }

    const bytes = readBoundedDescriptor(descriptor, maximumBytes, code, label)
    const handleAfter = fstatSync(descriptor, { bigint: true })
    const pathAfter = lstatSync(path, { bigint: true })
    if (
      bytes.length !== Number(handleAfter.size)
      || !isSingleRegularFile(handleAfter)
      || !isSingleRegularFile(pathAfter)
      || !sameFileIdentity(handleBefore, handleAfter)
      || !sameFileIdentity(handleAfter, pathAfter)
    ) {
      throw ledgerError(code, `${label} changed during its held-handle read`)
    }
    return bytes
  } catch (cause) {
    if (cause instanceof EngagementLedgerError) throw cause
    throw ledgerError(code, `${label} is unavailable or unsafe`, { cause })
  } finally {
    if (descriptor !== null) closeSync(descriptor)
  }
}

function parseCanonicalRecord(bytes, parseCode, canonicalCode, label) {
  let value
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch (cause) {
    throw ledgerError(parseCode, `${label} is invalid JSON`, { cause })
  }
  if (!bytes.equals(Buffer.from(stableJson(value), 'utf8'))) {
    throw ledgerError(canonicalCode, `${label} is not canonical JSON`)
  }
  return value
}

function validateRecordFile(path) {
  return readStableRegularFile(
    path,
    MAX_RECORD_BYTES,
    'ENGAGEMENT_LEDGER_RECORD_INVALID',
    'ledger record',
  )
}

function loadProjection(directory, binding) {
  const projection = blankProjection(binding)
  const records = readdirSync(directory).map((name) => {
    const match = RECORD_NAME.exec(name)
    if (!match) {
      throw ledgerError(
        'ENGAGEMENT_LEDGER_DIRECTORY_UNSAFE',
        `unexpected engagement ledger entry ${JSON.stringify(name)}`,
      )
    }
    return { name, sequence: Number(match[1]) }
  }).sort((left, right) => left.sequence - right.sequence)

  for (let index = 0; index < records.length; index += 1) {
    const entry = records[index]
    const sequence = index + 1
    if (entry.sequence !== sequence) {
      throw ledgerError('ENGAGEMENT_LEDGER_SEQUENCE_INVALID', 'ledger sequence is missing or duplicated')
    }
    const bytes = validateRecordFile(resolve(directory, entry.name))
    const record = parseCanonicalRecord(
      bytes,
      'ENGAGEMENT_LEDGER_RECORD_INVALID',
      'ENGAGEMENT_LEDGER_RECORD_NONCANONICAL',
      'ledger record',
    )
    const expectedFields = [
      'binding',
      'event',
      'kind',
      'previous_sha256',
      'schema_version',
      'sequence',
    ]
    if (
      record === null
      || typeof record !== 'object'
      || Array.isArray(record)
      || stableJson(Object.keys(record).sort(), 0) !== stableJson(expectedFields.sort(), 0)
      || record.schema_version !== ENGAGEMENT_LEDGER_SCHEMA_VERSION
      || record.kind !== ENGAGEMENT_LEDGER_RECORD_KIND
      || record.sequence !== sequence
      || record.previous_sha256 !== projection.headSha256
    ) {
      throw ledgerError('ENGAGEMENT_LEDGER_CHAIN_INVALID', 'ledger record chain or binding is invalid')
    }
    if (stableJson(record.binding, 0) !== stableJson(binding, 0)) {
      throw ledgerError(
        'ENGAGEMENT_LEDGER_BINDING_MISMATCH',
        'runtime engagement, authority, or target binding differs from the ledger',
      )
    }
    applyEvent(projection, canonicalSnapshot(record.event, 'engagement ledger event'))
    projection.records.push(record)
    projection.headSha256 = sha256(bytes)
    projection.recordDigests.push(projection.headSha256)
  }
  return projection
}

function loadAnchorState(directory, binding, projection) {
  const state = { recordCount: 0, headSha256: ZERO_SHA256 }
  const anchors = readdirSync(directory).map((name) => {
    const match = ANCHOR_NAME.exec(name)
    if (!match) {
      throw ledgerError(
        'ENGAGEMENT_LEDGER_ANCHOR_DIRECTORY_UNSAFE',
        `unexpected engagement ledger anchor entry ${JSON.stringify(name)}`,
      )
    }
    return { name, sequence: Number(match[1]) }
  }).sort((left, right) => left.sequence - right.sequence)

  for (let index = 0; index < anchors.length; index += 1) {
    const entry = anchors[index]
    const sequence = index + 1
    if (entry.sequence !== sequence) {
      throw ledgerError(
        'ENGAGEMENT_LEDGER_ANCHOR_SEQUENCE_INVALID',
        'ledger anchor sequence is missing or duplicated',
      )
    }
    const bytes = readStableRegularFile(
      resolve(directory, entry.name),
      MAX_ANCHOR_BYTES,
      'ENGAGEMENT_LEDGER_ANCHOR_INVALID',
      'ledger anchor',
    )
    const anchor = parseCanonicalRecord(
      bytes,
      'ENGAGEMENT_LEDGER_ANCHOR_INVALID',
      'ENGAGEMENT_LEDGER_ANCHOR_INVALID',
      'ledger anchor',
    )
    const expectedFields = [
      'binding',
      'kind',
      'previous_anchor_sha256',
      'record_sha256',
      'schema_version',
      'sequence',
    ]
    if (
      anchor === null
      || typeof anchor !== 'object'
      || Array.isArray(anchor)
      || stableJson(Object.keys(anchor).sort(), 0) !== stableJson(expectedFields.sort(), 0)
      || anchor.schema_version !== ENGAGEMENT_LEDGER_SCHEMA_VERSION
      || anchor.kind !== ENGAGEMENT_LEDGER_ANCHOR_KIND
      || anchor.sequence !== sequence
      || anchor.previous_anchor_sha256 !== state.headSha256
      || anchor.record_sha256 !== projection.recordDigests[index]
    ) {
      throw ledgerError(
        'ENGAGEMENT_LEDGER_ANCHOR_MISMATCH',
        'ledger anchors do not match the complete ledger history',
      )
    }
    if (stableJson(anchor.binding, 0) !== stableJson(binding, 0)) {
      throw ledgerError(
        'ENGAGEMENT_LEDGER_ANCHOR_BINDING_MISMATCH',
        'ledger anchor binding differs from the active engagement',
      )
    }
    state.recordCount = sequence
    state.headSha256 = sha256(bytes)
  }

  if (state.recordCount !== projection.records.length) {
    throw ledgerError(
      'ENGAGEMENT_LEDGER_ANCHOR_MISMATCH',
      'ledger and independently retained anchor histories have different lengths',
    )
  }
  return state
}

function publicSnapshot(projection) {
  const repositoryCheckpoints = projection.repositoryCheckpoints.map((value) => structuredClone(value))
  const repositoryWorks = [...projection.repositoryWorks.values()].map((value) => structuredClone(value))
  return {
    binding: structuredClone(projection.binding),
    fresh: projection.records.length === 0,
    started: projection.started,
    manifest_sha256: projection.manifestSha256,
    started_at: projection.startedAt,
    resume_count: projection.resumeCount,
    stop_requested: projection.stopRequest !== null,
    stop_request: projection.stopRequest === null ? null : structuredClone(projection.stopRequest),
    terminal: projection.terminalResult !== null,
    terminal_result: projection.terminalResult === null
      ? null
      : structuredClone(projection.terminalResult),
    latest_at: latestProjectionTimestamp(projection),
    routes: [...projection.routes.values()].map((route) => structuredClone(route)),
    repository: {
      checkpoints: repositoryCheckpoints,
      current_checkpoint: repositoryCheckpoints.at(-1) ?? null,
      works: repositoryWorks,
      active_work: repositoryWorks.find((work) => work.result === null) ?? null,
    },
    record_count: projection.records.length,
    head_sha256: projection.headSha256,
  }
}

function syncDirectoryEntry(path) {
  if (process.platform === 'win32') return
  const descriptor = openSync(path, 'r')
  try {
    fsyncSync(descriptor)
  } finally {
    closeSync(descriptor)
  }
}

function comparablePath(path) {
  const normalized = resolve(path)
  return process.platform === 'win32' ? normalized.toLowerCase() : normalized
}

function pathContains(parent, candidate) {
  const normalizedParent = comparablePath(parent)
  const normalizedCandidate = comparablePath(candidate)
  const prefix = normalizedParent.endsWith(sep)
    ? normalizedParent
    : `${normalizedParent}${sep}`
  return normalizedCandidate === normalizedParent
    || normalizedCandidate.startsWith(prefix)
}

function assertExistingDirectory(path, code) {
  let metadata
  try {
    metadata = lstatSync(path)
  } catch (cause) {
    throw ledgerError(code, 'engagement ledger directory is unavailable', { cause })
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw ledgerError('ENGAGEMENT_LEDGER_DIRECTORY_INVALID', 'ledger path must be a regular directory')
  }
  let canonical
  try {
    canonical = realpathSync(path)
  } catch (cause) {
    throw ledgerError('ENGAGEMENT_LEDGER_DIRECTORY_INVALID', 'ledger path cannot be canonicalized', { cause })
  }
  if (comparablePath(path) !== comparablePath(canonical)) {
    throw ledgerError('ENGAGEMENT_LEDGER_DIRECTORY_INVALID', 'ledger path cannot traverse an alias')
  }
}

export class EngagementLedger {
  constructor({ directory, anchorDirectory, binding, fsyncFile, fsyncDirectory }) {
    this.directory = directory
    this.anchorDirectory = anchorDirectory
    this.binding = binding
    this._fsyncFile = fsyncFile
    this._fsyncDirectory = fsyncDirectory
    this._projection = null
    this._anchorState = null
    this._failedClosed = false
    this._reload()
  }

  _reload() {
    this._projection = loadProjection(this.directory, this.binding)
    this._anchorState = this.anchorDirectory === null
      ? null
      : loadAnchorState(this.anchorDirectory, this.binding, this._projection)
    return this._projection
  }

  snapshot() {
    return publicSnapshot(this._reload())
  }

  assertDispatchAllowed({ routeId, planSha256 } = {}) {
    const projection = this._reload()
    assertDispatchAllowedInProjection(projection, routeId, planSha256)
    return publicSnapshot(projection)
  }

  async _append(eventFactory) {
    if (this._failedClosed) {
      throw ledgerError('ENGAGEMENT_LEDGER_FAILED_CLOSED', 'ledger must be reopened after an append failure')
    }
    for (let attempt = 0; attempt < MAX_APPEND_RETRIES; attempt += 1) {
      const projection = this._reload()
      const proposed = eventFactory(projection)
      if (proposed === null) return publicSnapshot(projection)
      const event = canonicalSnapshot(proposed, 'engagement ledger event')
      applyEvent(projection, event)
      const sequence = projection.records.length + 1
      const record = {
        schema_version: ENGAGEMENT_LEDGER_SCHEMA_VERSION,
        kind: ENGAGEMENT_LEDGER_RECORD_KIND,
        sequence,
        previous_sha256: projection.headSha256,
        binding: structuredClone(this.binding),
        event,
      }
      const bytes = Buffer.from(stableJson(record), 'utf8')
      if (bytes.length > MAX_RECORD_BYTES) {
        throw ledgerError('ENGAGEMENT_LEDGER_VALUE_TOO_LARGE', 'ledger record exceeds its byte limit')
      }
      const path = resolve(this.directory, `${String(sequence).padStart(16, '0')}.engagement.json`)
      let descriptor = null
      let recordCreated = false
      try {
        descriptor = openSync(path, 'wx', 0o600)
        recordCreated = true
        writeFileSync(descriptor, bytes)
        this._fsyncFile(descriptor)
        closeSync(descriptor)
        descriptor = null
        this._fsyncDirectory(this.directory)

        if (this.anchorDirectory !== null) {
          const anchor = {
            schema_version: ENGAGEMENT_LEDGER_SCHEMA_VERSION,
            kind: ENGAGEMENT_LEDGER_ANCHOR_KIND,
            sequence,
            previous_anchor_sha256: this._anchorState.headSha256,
            record_sha256: sha256(bytes),
            binding: structuredClone(this.binding),
          }
          const anchorBytes = Buffer.from(stableJson(anchor), 'utf8')
          if (anchorBytes.length > MAX_ANCHOR_BYTES) {
            throw ledgerError(
              'ENGAGEMENT_LEDGER_ANCHOR_INVALID',
              'ledger anchor exceeds its byte limit',
            )
          }
          const anchorPath = resolve(
            this.anchorDirectory,
            `${String(sequence).padStart(16, '0')}.anchor.json`,
          )
          descriptor = openSync(anchorPath, 'wx', 0o600)
          writeFileSync(descriptor, anchorBytes)
          this._fsyncFile(descriptor)
          closeSync(descriptor)
          descriptor = null
          this._fsyncDirectory(this.anchorDirectory)
          this._anchorState = {
            recordCount: sequence,
            headSha256: sha256(anchorBytes),
          }
        }
      } catch (cause) {
        if (descriptor !== null) closeSync(descriptor)
        if (!recordCreated && cause?.code === 'EEXIST') continue
        this._failedClosed = true
        throw ledgerError('ENGAGEMENT_LEDGER_APPEND_FAILED', 'ledger append failed closed', { cause })
      }
      projection.records.push(record)
      projection.headSha256 = sha256(bytes)
      this._projection = projection
      return publicSnapshot(projection)
    }
    throw ledgerError('ENGAGEMENT_LEDGER_CONTENTION', 'ledger could not append after concurrent updates')
  }

  start({ manifestSha256, startedAt } = {}) {
    return this._append(() => ({
      type: 'ENGAGEMENT_STARTED',
      manifest_sha256: manifestSha256,
      started_at: startedAt,
    }))
  }

  recordResume({ resumedAt } = {}) {
    return this._append((projection) => ({
      type: 'ENGAGEMENT_RESUMED',
      resume_count: projection.resumeCount + 1,
      resumed_at: resumedAt,
    }))
  }

  recordRoutePlan({ routeId, planSha256, plannedAt } = {}) {
    return this._append(() => ({
      type: 'ROUTE_PLANNED',
      route_id: routeId,
      plan_sha256: planSha256,
      planned_at: plannedAt,
    }))
  }

  recordRouteWaiting({ routeId, planSha256, reasonCode, waitingAt } = {}) {
    return this._append(() => ({
      type: 'ROUTE_WAITING',
      route_id: routeId,
      plan_sha256: planSha256,
      reason_code: reasonCode,
      waiting_at: waitingAt,
    }))
  }

  recordDispatchPermit({ routeId, planSha256, permitSha256, permittedAt } = {}) {
    return this._append(() => ({
      type: 'ROUTE_DISPATCH_PERMITTED',
      route_id: routeId,
      plan_sha256: planSha256,
      permit_sha256: permitSha256,
      permitted_at: permittedAt,
    }))
  }

  recordRouteOutcome({
    routeId,
    planSha256,
    status,
    resultSha256,
    requestMayHaveBeenSent,
    completedAt,
  } = {}) {
    return this._append(() => ({
      type: 'ROUTE_OUTCOME_RECORDED',
      route_id: routeId,
      plan_sha256: planSha256,
      status,
      result_sha256: resultSha256,
      request_may_have_been_sent: requestMayHaveBeenSent,
      completed_at: completedAt,
    }))
  }

  recordRepositoryChildCheckpoint({
    operation,
    childBundleSha256,
    childTreeSha256,
    statusSha256,
    checkpointSha256,
    childState,
    terminal,
    checkpointedAt,
  } = {}) {
    return this._append(() => ({
      type: 'REPOSITORY_CHILD_CHECKPOINTED',
      route_id: 'repository-audit',
      operation,
      child_bundle_sha256: childBundleSha256,
      child_tree_sha256: childTreeSha256,
      status_sha256: statusSha256,
      checkpoint_sha256: checkpointSha256,
      child_state: childState,
      terminal,
      checkpointed_at: checkpointedAt,
    }))
  }

  recordRepositoryWorkIssued({ workId, envelopeSha256, childTreeSha256, issuedAt } = {}) {
    return this._append(() => ({
      type: 'REPOSITORY_WORK_ISSUED',
      work_id: workId,
      envelope_sha256: envelopeSha256,
      child_tree_sha256: childTreeSha256,
      issued_at: issuedAt,
    }))
  }

  recordRepositoryIngestDispatch({
    workId,
    envelopeSha256,
    preChildTreeSha256,
    stagedRelativePath,
    resultSha256,
    resultSizeBytes,
    resultState,
    dispatchedAt,
  } = {}) {
    return this._append((projection) => {
      const work = projection.repositoryWorks.get(workId)
      return {
        type: 'REPOSITORY_INGEST_DISPATCHED',
        work_id: workId,
        envelope_sha256: envelopeSha256,
        attempt: (work?.ingest_attempts.length ?? 0) + 1,
        pre_child_tree_sha256: preChildTreeSha256,
        staged_relative_path: stagedRelativePath,
        result_sha256: resultSha256,
        result_size_bytes: resultSizeBytes,
        result_state: resultState,
        dispatched_at: dispatchedAt,
      }
    })
  }

  recordRepositoryIngestReconciliation({
    workId,
    envelopeSha256,
    attempt,
    outcome,
    observedChildTreeSha256,
    reconciledAt,
  } = {}) {
    return this._append(() => ({
      type: 'REPOSITORY_INGEST_RECONCILED',
      work_id: workId,
      envelope_sha256: envelopeSha256,
      attempt,
      outcome,
      observed_child_tree_sha256: observedChildTreeSha256,
      reconciled_at: reconciledAt,
    }))
  }

  recordRepositoryWorkResult({
    workId,
    envelopeSha256,
    receiptSha256,
    childTreeSha256,
    status,
    recordedAt,
  } = {}) {
    return this._append(() => ({
      type: 'REPOSITORY_WORK_RESULT_RECORDED',
      work_id: workId,
      envelope_sha256: envelopeSha256,
      receipt_sha256: receiptSha256,
      child_tree_sha256: childTreeSha256,
      status,
      recorded_at: recordedAt,
    }))
  }

  requestStop({ reason, requestedAt } = {}) {
    return this._append((projection) => projection.stopRequest === null
      ? { type: 'ENGAGEMENT_STOP_REQUESTED', reason, requested_at: requestedAt }
      : null)
  }

  recordTerminal({ status, resultSha256, terminalAt } = {}) {
    return this._append(() => ({
      type: 'ENGAGEMENT_TERMINAL',
      status,
      result_sha256: resultSha256,
      terminal_at: terminalAt,
    }))
  }
}

export async function openEngagementLedger({
  directory,
  anchorDirectory,
  binding,
  initialize = false,
  expectedHead,
  fsyncFile = fsyncSync,
  fsyncDirectory = syncDirectoryEntry,
} = {}) {
  try {
    assertLocalFilesystemEndpoint(directory, 'engagement ledger directory')
  } catch (cause) {
    throw ledgerError(
      'ENGAGEMENT_LEDGER_DIRECTORY_INVALID',
      'ledger directory must use a local filesystem endpoint',
      { cause },
    )
  }
  if (typeof directory !== 'string' || !isAbsolute(directory)) {
    throw ledgerError('ENGAGEMENT_LEDGER_DIRECTORY_INVALID', 'ledger directory must be absolute')
  }
  if (typeof initialize !== 'boolean') {
    throw ledgerError('ENGAGEMENT_LEDGER_DIRECTORY_INVALID', 'initialize must be boolean')
  }
  if (typeof fsyncFile !== 'function' || typeof fsyncDirectory !== 'function') {
    throw ledgerError('ENGAGEMENT_LEDGER_DURABILITY_INVALID', 'ledger requires durability functions')
  }
  const root = resolve(directory)
  let anchorRoot = null
  if (anchorDirectory !== undefined) {
    try {
      assertLocalFilesystemEndpoint(anchorDirectory, 'engagement ledger anchor directory')
    } catch (cause) {
      throw ledgerError(
        'ENGAGEMENT_LEDGER_ANCHOR_DIRECTORY_INVALID',
        'anchor directory must use a local filesystem endpoint',
        { cause },
      )
    }
    if (typeof anchorDirectory !== 'string' || !isAbsolute(anchorDirectory)) {
      throw ledgerError(
        'ENGAGEMENT_LEDGER_ANCHOR_DIRECTORY_INVALID',
        'anchor directory must be absolute',
      )
    }
    anchorRoot = resolve(anchorDirectory)
    if (pathContains(root, anchorRoot) || pathContains(anchorRoot, root)) {
      throw ledgerError(
        'ENGAGEMENT_LEDGER_ANCHOR_DIRECTORY_INVALID',
        'anchor directory must be external to the ledger directory',
      )
    }
  }
  const normalizedBinding = normalizeBinding(binding)
  const trustedHead = normalizeExpectedHead(expectedHead)
  if (initialize) {
    const parent = dirname(root)
    assertExistingDirectory(parent, 'ENGAGEMENT_LEDGER_DIRECTORY_INVALID')
    if (anchorRoot !== null) {
      assertExistingDirectory(dirname(anchorRoot), 'ENGAGEMENT_LEDGER_ANCHOR_DIRECTORY_INVALID')
      if (existsSync(anchorRoot)) {
        throw ledgerError(
          'ENGAGEMENT_LEDGER_ANCHOR_DIRECTORY_EXISTS',
          'anchor initialization is create-exclusive',
        )
      }
    }
    try {
      mkdirSync(root, { recursive: false, mode: 0o700 })
      fsyncDirectory(parent)
    } catch (cause) {
      if (cause?.code === 'EEXIST') {
        throw ledgerError('ENGAGEMENT_LEDGER_DIRECTORY_EXISTS', 'ledger initialization is create-exclusive')
      }
      throw ledgerError('ENGAGEMENT_LEDGER_DIRECTORY_INVALID', 'ledger directory could not be created', { cause })
    }
    if (anchorRoot !== null) {
      try {
        mkdirSync(anchorRoot, { recursive: false, mode: 0o700 })
        fsyncDirectory(dirname(anchorRoot))
      } catch (cause) {
        if (cause?.code === 'EEXIST') {
          throw ledgerError(
            'ENGAGEMENT_LEDGER_ANCHOR_DIRECTORY_EXISTS',
            'anchor initialization is create-exclusive',
          )
        }
        throw ledgerError(
          'ENGAGEMENT_LEDGER_ANCHOR_DIRECTORY_INVALID',
          'anchor directory could not be created',
          { cause },
        )
      }
    }
  } else {
    if (!existsSync(root)) {
      throw ledgerError('ENGAGEMENT_LEDGER_DIRECTORY_MISSING', 'ledger directory does not exist')
    }
    assertExistingDirectory(root, 'ENGAGEMENT_LEDGER_DIRECTORY_MISSING')
    if (anchorRoot !== null) {
      if (!existsSync(anchorRoot)) {
        throw ledgerError(
          'ENGAGEMENT_LEDGER_ANCHOR_DIRECTORY_MISSING',
          'anchor directory does not exist',
        )
      }
      assertExistingDirectory(anchorRoot, 'ENGAGEMENT_LEDGER_ANCHOR_DIRECTORY_MISSING')
    }
  }

  const ledger = new EngagementLedger({
    directory: root,
    anchorDirectory: anchorRoot,
    binding: normalizedBinding,
    fsyncFile,
    fsyncDirectory,
  })
  const snapshot = publicSnapshot(ledger._projection)
  if (
    trustedHead !== null
    && (
      snapshot.record_count !== trustedHead.recordCount
      || snapshot.head_sha256 !== trustedHead.headSha256
    )
  ) {
    throw ledgerError(
      'ENGAGEMENT_LEDGER_TRUSTED_HEAD_MISMATCH',
      'ledger does not match the expected record count and head digest',
    )
  }
  return ledger
}
