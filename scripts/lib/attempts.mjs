import { randomBytes, randomUUID } from 'node:crypto'
import { isDeepStrictEqual } from 'node:util'

import {
  assertValidRun,
  assertValidRunTransition,
  hashAttemptEvent,
  parseContractTimestamp,
} from './contracts.mjs'
import { prepareJobStart } from './job-protocol.mjs'

const ACTIVE_EVENTS = new Set([
  'LEASED',
  'STARTED',
  'RESULT_CAPTURED',
  'VALIDATED',
])

function clone(value) {
  return structuredClone(value)
}

function requireString(value, name) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(`${name} must be a non-empty string`)
  }
  return value
}

function requireTimestamp(value, name) {
  const milliseconds = parseContractTimestamp(value)
  if (!Number.isFinite(milliseconds)) {
    throw new TypeError(`${name} must be a semantically valid timestamp`)
  }
  return milliseconds
}

function resolveInstant(value, name) {
  if (value === undefined) {
    const date = new Date()
    return {
      occurred_at: date.toISOString(),
      milliseconds: date.getTime(),
    }
  }
  if (value instanceof Date || typeof value === 'number') {
    const date = value instanceof Date ? value : new Date(value)
    const milliseconds = date.getTime()
    if (!Number.isFinite(milliseconds)) {
      throw new TypeError(`${name} must be a valid instant`)
    }
    return {
      occurred_at: date.toISOString(),
      milliseconds,
    }
  }
  return {
    occurred_at: value,
    milliseconds: requireTimestamp(value, name),
  }
}

function jobById(run, jobId) {
  const job = run.jobs?.find((entry) => entry.job_id === jobId)
  if (!job) throw new Error(`Unknown provider job ${jobId}`)
  return job
}

function attemptRecords(run) {
  const records = new Map()
  for (const event of run.attempt_events ?? []) {
    const record = records.get(event.attempt_id) ?? {
      attempt_id: event.attempt_id,
      job_id: event.job_id,
      state: undefined,
      lease: undefined,
      last_event: undefined,
      execution_artifact_key: undefined,
      execution_artifact_sha256: undefined,
      receipt_sha256: undefined,
      failure_artifact_key: undefined,
      failure_artifact_sha256: undefined,
      partial_receipt_sha256: undefined,
    }
    if (event.event === 'LEASED') record.lease = event
    if (['RESULT_CAPTURED', 'VALIDATED', 'COMMITTED'].includes(event.event)) {
      record.execution_artifact_key = event.execution_artifact_key
      record.execution_artifact_sha256 = event.execution_artifact_sha256
      record.receipt_sha256 = event.receipt_sha256
    }
    if (event.event === 'FAILED' && event.failure_artifact_key !== undefined) {
      record.failure_artifact_key = event.failure_artifact_key
      record.failure_artifact_sha256 = event.failure_artifact_sha256
      record.partial_receipt_sha256 = event.partial_receipt_sha256
    }
    record.state = event.event
    record.last_event = event
    records.set(event.attempt_id, record)
  }
  return records
}

function attemptById(run, attemptId) {
  const record = attemptRecords(run).get(attemptId)
  if (!record) throw new Error(`Unknown provider attempt ${attemptId}`)
  return record
}

function appendEventToCandidate(previous, candidate, eventInput) {
  const next = clone(candidate)
  const priorEvents = previous.attempt_events ?? []
  const candidateEvents = next.attempt_events ?? []
  if (!isDeepStrictEqual(candidateEvents, priorEvents)) {
    throw new Error('Candidate run must preserve the exact attempt event prefix')
  }
  const unsigned = {
    ...clone(eventInput),
    sequence: priorEvents.length + 1,
    previous_event_sha256:
      priorEvents.length === 0
        ? null
        : priorEvents[priorEvents.length - 1].event_sha256,
  }
  delete unsigned.event_sha256
  const event = {
    ...unsigned,
    event_sha256: hashAttemptEvent(unsigned),
  }
  next.attempt_events = [...priorEvents, event]
  assertValidRunTransition(previous, next)
  return next
}

export { hashAttemptEvent }

export function findActiveAttempt(run, jobId = undefined) {
  assertValidRun(run)
  const active = [...attemptRecords(run).values()]
    .filter((record) => ACTIVE_EVENTS.has(record.state))
    .filter((record) => jobId === undefined || record.job_id === jobId)
    .sort((left, right) =>
      left.lease.sequence - right.lease.sequence)
  if (jobId !== undefined && active.length > 1) {
    throw new Error(`Job ${jobId} has more than one active attempt`)
  }
  return active.length === 0
    ? null
    : clone(jobId === undefined ? active : active[0])
}

export function findProviderAttempt(run, attemptId) {
  assertValidRun(run)
  return clone(attemptById(run, attemptId))
}

export function appendAttemptEvent(run, eventInput) {
  assertValidRun(run)
  return appendEventToCandidate(run, run, eventInput)
}

export function leaseProviderAttempt(run, jobId, metadata) {
  assertValidRun(run)
  if (!['2.0.0', '3.0.0', '4.0.0', '5.0.0', '6.0.0', '7.0.0'].includes(run.schema_version)) {
    throw new Error('Observed provider attempts require a v2-v7 run')
  }
  if (!run.source_snapshot || !run.control_snapshot) {
    throw new Error('Observed provider attempts require sealed source and control snapshots')
  }
  const job = jobById(run, jobId)
  if (job.state !== 'PENDING') {
    throw new Error(`Job ${jobId} is ${job.state}; only PENDING jobs can be leased`)
  }
  if (findActiveAttempt(run, jobId)) {
    throw new Error(`Job ${jobId} already has an active attempt`)
  }

  const occurredAt = metadata?.occurred_at ?? new Date().toISOString()
  const occurredAtMilliseconds = requireTimestamp(occurredAt, 'occurred_at')
  const budgets = clone(metadata?.budgets)
  if (!budgets || typeof budgets !== 'object') {
    throw new TypeError('budgets are required')
  }
  if (!Number.isInteger(budgets.wall_clock_ms)) {
    throw new TypeError('budgets.wall_clock_ms must be an integer')
  }
  const attemptId = metadata?.attempt_id ?? `attempt:${randomUUID()}`
  const expiresAt = metadata?.expires_at
    ?? new Date(
      occurredAtMilliseconds + budgets.wall_clock_ms + 30_000,
    ).toISOString()
  const expiresAtMilliseconds = requireTimestamp(expiresAt, 'expires_at')
  if (expiresAtMilliseconds <= occurredAtMilliseconds) {
    throw new RangeError('expires_at must be strictly after occurred_at')
  }
  const containerName = metadata?.container_name
    ?? `rta-${attemptId.replace(/[^a-z0-9_.-]/gi, '-').toLowerCase()}`.slice(0, 128)

  const next = prepareJobStart(run, jobId)

  return appendEventToCandidate(run, next, {
    attempt_id: attemptId,
    job_id: jobId,
    event: 'LEASED',
    backend: 'SEALED_CONTAINER',
    occurred_at: occurredAt,
    nonce: metadata?.nonce ?? randomBytes(32).toString('hex'),
    packet_sha256: requireString(metadata?.packet_sha256, 'packet_sha256'),
    plan_sha256: run.plan_digest,
    repository_tree_sha256: run.repository.tree_digest,
    lens_pack_sha256: run.lens_pack_digest,
    policy_sha256: run.policy_digest,
    provider_config_sha256: requireString(
      metadata?.provider_config_sha256,
      'provider_config_sha256',
    ),
    sandbox_policy_sha256: requireString(
      metadata?.sandbox_policy_sha256,
      'sandbox_policy_sha256',
    ),
    source_snapshot_sha256: run.source_snapshot.root_sha256,
    control_snapshot_sha256: run.control_snapshot.root_sha256,
    budgets,
    expires_at: expiresAt,
    container_name: containerName,
  })
}

export function leaseRemoteAttempt(run, jobId, metadata) {
  assertValidRun(run)
  if (!['6.0.0', '7.0.0'].includes(run.schema_version)) {
    throw new Error('Remote gateway attempts require a v6 or v7 run')
  }
  if (!run.source_snapshot || !run.control_snapshot) {
    throw new Error('Remote gateway attempts require sealed source and control snapshots')
  }
  const job = jobById(run, jobId)
  if (job.state !== 'PENDING') {
    throw new Error(`Job ${jobId} is ${job.state}; only PENDING jobs can be leased`)
  }
  if (findActiveAttempt(run, jobId)) {
    throw new Error(`Job ${jobId} already has an active attempt`)
  }

  const occurredAt = metadata?.occurred_at ?? new Date().toISOString()
  const occurredAtMilliseconds = requireTimestamp(occurredAt, 'occurred_at')
  const budgets = clone(metadata?.budgets)
  if (!budgets || typeof budgets !== 'object') {
    throw new TypeError('budgets are required')
  }
  if (!Number.isInteger(budgets.wall_clock_ms)) {
    throw new TypeError('budgets.wall_clock_ms must be an integer')
  }
  const attemptId = metadata?.attempt_id ?? `attempt:${randomUUID()}`
  const expiresAt = metadata?.expires_at
    ?? new Date(
      occurredAtMilliseconds + budgets.wall_clock_ms + 30_000,
    ).toISOString()
  const expiresAtMilliseconds = requireTimestamp(expiresAt, 'expires_at')
  if (expiresAtMilliseconds <= occurredAtMilliseconds) {
    throw new RangeError('expires_at must be strictly after occurred_at')
  }
  const artifactKey = requireString(
    metadata?.request_artifact_key,
    'request_artifact_key',
  )
  const artifact = clone(metadata?.request_artifact)
  if (
    !artifact
    || typeof artifact.path !== 'string'
    || typeof artifact.sha256 !== 'string'
  ) {
    throw new TypeError('request_artifact must contain path and sha256')
  }
  if (Object.hasOwn(run.artifacts ?? {}, artifactKey)) {
    throw new Error(`Artifact key ${artifactKey} already exists`)
  }

  const next = prepareJobStart(run, jobId)
  next.artifacts[artifactKey] = artifact
  return appendEventToCandidate(run, next, {
    attempt_id: attemptId,
    job_id: jobId,
    event: 'LEASED',
    backend: 'REMOTE_GATEWAY',
    occurred_at: occurredAt,
    nonce: metadata?.nonce ?? randomBytes(32).toString('hex'),
    packet_sha256: requireString(metadata?.packet_sha256, 'packet_sha256'),
    plan_sha256: run.plan_digest,
    repository_tree_sha256: run.repository.tree_digest,
    lens_pack_sha256: run.lens_pack_digest,
    policy_sha256: run.policy_digest,
    remote_gateway_config_sha256: requireString(
      metadata?.remote_gateway_config_sha256,
      'remote_gateway_config_sha256',
    ),
    controller_key_id: requireString(
      metadata?.controller_key_id,
      'controller_key_id',
    ),
    gateway_key_id: requireString(
      metadata?.gateway_key_id,
      'gateway_key_id',
    ),
    request_id: requireString(metadata?.request_id, 'request_id'),
    request_artifact_key: artifactKey,
    request_artifact_sha256: artifact.sha256,
    source_snapshot_sha256: run.source_snapshot.root_sha256,
    control_snapshot_sha256: run.control_snapshot.root_sha256,
    budgets,
    expires_at: expiresAt,
  })
}

export function markProviderAttemptStarted(run, attemptId, metadata = {}) {
  assertValidRun(run)
  const attempt = attemptById(run, attemptId)
  if (attempt.state !== 'LEASED') {
    throw new Error(`Attempt ${attemptId} is ${attempt.state}; expected LEASED`)
  }
  const occurredAt = metadata.occurred_at ?? new Date().toISOString()
  const startedAt = requireTimestamp(occurredAt, 'occurred_at')
  const expiresAt = requireTimestamp(
    attempt.lease.expires_at,
    'attempt lease expires_at',
  )
  if (startedAt >= expiresAt) {
    throw new Error(
      `Attempt ${attemptId} lease expired at ${attempt.lease.expires_at}; refusing STARTED`,
    )
  }
  return appendEventToCandidate(run, run, {
    attempt_id: attemptId,
    job_id: attempt.job_id,
    event: 'STARTED',
    occurred_at: occurredAt,
  })
}

export function classifyProviderAttemptRecovery(run, attemptId, options = {}) {
  assertValidRun(run)
  const attempt = attemptById(run, attemptId)
  const now = resolveInstant(options.now, 'now')
  const expiresAt = requireTimestamp(
    attempt.lease.expires_at,
    'attempt lease expires_at',
  )
  let status = 'TERMINAL'
  if (['RESULT_CAPTURED', 'VALIDATED'].includes(attempt.state)) {
    status = 'RESUMABLE'
  } else if (['LEASED', 'STARTED'].includes(attempt.state)) {
    status = now.milliseconds >= expiresAt
      ? 'ACTIVE_EXPIRED'
      : 'ACTIVE_UNEXPIRED'
  }
  return {
    attempt_id: attempt.attempt_id,
    job_id: attempt.job_id,
    state: attempt.state,
    status,
    observed_at: now.occurred_at,
    expires_at: attempt.lease.expires_at,
  }
}

export function recoverExpiredProviderAttempt(run, attemptId, metadata = {}) {
  const occurredAt = resolveInstant(
    metadata.occurred_at,
    'occurred_at',
  ).occurred_at
  const recovery = classifyProviderAttemptRecovery(run, attemptId, {
    now: occurredAt,
  })
  if (recovery.status !== 'ACTIVE_EXPIRED') {
    throw new Error(
      `Attempt ${attemptId} is ${recovery.status}; only an expired LEASED or STARTED attempt can be recovered`,
    )
  }
  return failProviderAttempt(run, attemptId, {
    occurred_at: occurredAt,
    reason: metadata.reason
      ?? `attempt lease expired at ${recovery.expires_at}`,
    recoverable: true,
  })
}

export function failProviderAttempt(run, attemptId, metadata = {}) {
  assertValidRun(run)
  const attempt = attemptById(run, attemptId)
  if (!ACTIVE_EVENTS.has(attempt.state)) {
    throw new Error(`Attempt ${attemptId} is already terminal`)
  }
  const recoverable = metadata.recoverable !== false
  const reason = requireString(metadata.reason, 'reason')
  const next = clone(run)
  const job = jobById(next, attempt.job_id)
  job.state = recoverable ? 'PENDING' : 'FAILED'
  if (recoverable) {
    delete job.reason
  } else {
    job.reason = reason
  }
  let failureEvidence = {}
  if (
    metadata.failure_artifact_key !== undefined
    || metadata.failure_artifact !== undefined
  ) {
    const artifactKey = requireString(
      metadata.failure_artifact_key,
      'failure_artifact_key',
    )
    const artifact = clone(metadata.failure_artifact)
    if (
      !artifact
      || typeof artifact.path !== 'string'
      || typeof artifact.sha256 !== 'string'
    ) {
      throw new TypeError('failure_artifact must contain path and sha256')
    }
    if (Object.hasOwn(run.artifacts ?? {}, artifactKey)) {
      throw new Error(`Artifact key ${artifactKey} already exists`)
    }
    next.artifacts[artifactKey] = artifact
    failureEvidence = {
      failure_artifact_key: artifactKey,
      failure_artifact_sha256: artifact.sha256,
      ...(metadata.partial_receipt_sha256 === undefined
        ? {}
        : {
            partial_receipt_sha256: requireString(
              metadata.partial_receipt_sha256,
              'partial_receipt_sha256',
            ),
          }),
    }
  } else if (metadata.partial_receipt_sha256 !== undefined) {
    throw new TypeError('partial_receipt_sha256 requires a failure artifact')
  }
  return appendEventToCandidate(run, next, {
    attempt_id: attemptId,
    job_id: attempt.job_id,
    event: 'FAILED',
    occurred_at: metadata.occurred_at ?? new Date().toISOString(),
    reason,
    recoverable,
    ...failureEvidence,
  })
}

export function recordProviderResultCaptured(run, attemptId, metadata) {
  assertValidRun(run)
  const attempt = attemptById(run, attemptId)
  if (attempt.state !== 'STARTED') {
    throw new Error(`Attempt ${attemptId} is ${attempt.state}; expected STARTED`)
  }
  const artifactKey = requireString(
    metadata?.execution_artifact_key,
    'execution_artifact_key',
  )
  const artifact = clone(metadata?.execution_artifact)
  if (
    !artifact
    || typeof artifact.path !== 'string'
    || typeof artifact.sha256 !== 'string'
  ) {
    throw new TypeError('execution_artifact must contain path and sha256')
  }
  if (Object.hasOwn(run.artifacts ?? {}, artifactKey)) {
    throw new Error(`Artifact key ${artifactKey} already exists`)
  }
  const next = clone(run)
  next.artifacts[artifactKey] = artifact
  return appendEventToCandidate(run, next, {
    attempt_id: attemptId,
    job_id: attempt.job_id,
    event: 'RESULT_CAPTURED',
    occurred_at: metadata.occurred_at ?? new Date().toISOString(),
    execution_artifact_key: artifactKey,
    execution_artifact_sha256: artifact.sha256,
    receipt_sha256: requireString(metadata.receipt_sha256, 'receipt_sha256'),
  })
}

export function recordProviderResultValidated(run, attemptId, metadata = {}) {
  assertValidRun(run)
  const attempt = attemptById(run, attemptId)
  if (attempt.state !== 'RESULT_CAPTURED') {
    throw new Error(`Attempt ${attemptId} is ${attempt.state}; expected RESULT_CAPTURED`)
  }
  return appendEventToCandidate(run, run, {
    attempt_id: attemptId,
    job_id: attempt.job_id,
    event: 'VALIDATED',
    occurred_at: metadata.occurred_at ?? new Date().toISOString(),
    execution_artifact_key: attempt.execution_artifact_key,
    execution_artifact_sha256: attempt.execution_artifact_sha256,
    receipt_sha256: attempt.receipt_sha256,
  })
}

export function commitProviderAttempt(previous, candidateRun, attemptId, metadata = {}) {
  assertValidRun(previous)
  const attempt = attemptById(previous, attemptId)
  if (attempt.state !== 'VALIDATED') {
    throw new Error(`Attempt ${attemptId} is ${attempt.state}; expected VALIDATED`)
  }
  const next = clone(candidateRun)
  const job = jobById(next, attempt.job_id)
  if (!['SUCCEEDED', 'FAILED'].includes(job.state)) {
    throw new Error('Candidate run must contain the terminal provider result')
  }
  job.coverage_authority = attempt.lease.backend === 'REMOTE_GATEWAY'
    ? 'REMOTE_REQUEST_ACCEPTED'
    : 'CONTROLLER_OBSERVED_CONSUMPTION'
  job.attempt_id = attemptId
  job.receipt_sha256 = attempt.receipt_sha256
  job.execution_artifact_key = attempt.execution_artifact_key
  return appendEventToCandidate(previous, next, {
    attempt_id: attemptId,
    job_id: attempt.job_id,
    event: 'COMMITTED',
    occurred_at: metadata.occurred_at ?? new Date().toISOString(),
    execution_artifact_key: attempt.execution_artifact_key,
    execution_artifact_sha256: attempt.execution_artifact_sha256,
    receipt_sha256: attempt.receipt_sha256,
  })
}
