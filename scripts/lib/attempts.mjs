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

const SERVICE_PROOF_SCHEMA_VERSION = '7.0.0'
const SERVICE_PROOF_BACKEND = 'SERVICE_PROOF_CONTAINER'
const SERVICE_CONTAINER_NAME_PATTERN = /^rta-proof-[a-z0-9][a-z0-9-]{7,64}$/
// proof-docker-runner reserves up to twenty active and six cleanup Docker
// command slots in addition to the worker wall clock: 3,600,000 + 26*120,000.
const SERVICE_CONTROLLER_SESSION_MAX_MS = 6_720_000
const SERVICE_CAPTURE_GRACE_MAX_MS = 600_000
const SERVICE_CONTROLLER_WALL_CLOCK_MAX_MS =
  (2 * SERVICE_CONTROLLER_SESSION_MAX_MS) + SERVICE_CAPTURE_GRACE_MAX_MS

function clone(value) {
  return structuredClone(value)
}

function requireString(value, name) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(`${name} must be a non-empty string`)
  }
  return value
}

function requireBoundedInteger(value, name, minimum, maximum) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(
      `${name} must be an integer from ${minimum} through ${maximum}`,
    )
  }
  return value
}

function normalizeServiceContainerNames(value) {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || Object.keys(value).length !== 2
    || !Object.hasOwn(value, 'attack')
    || !Object.hasOwn(value, 'control')
  ) {
    throw new TypeError(
      'service_container_names must contain exactly attack and control',
    )
  }
  const names = {
    attack: requireString(value.attack, 'service_container_names.attack'),
    control: requireString(value.control, 'service_container_names.control'),
  }
  for (const [role, name] of Object.entries(names)) {
    if (!SERVICE_CONTAINER_NAME_PATTERN.test(name)) {
      throw new TypeError(
        `service_container_names.${role} must be a valid lowercase container name`,
      )
    }
  }
  if (names.attack === names.control) {
    throw new Error('attack and control container names must be distinct')
  }
  return names
}

function defaultServiceContainerNames(attemptId) {
  const token = attemptId
    .replace(/[^a-z0-9-]/gi, '-')
    .toLowerCase()
    .slice(0, 40)
  return {
    attack: `rta-proof-service-attack-${token}`,
    control: `rta-proof-service-control-${token}`,
  }
}

function normalizeServiceSessionBudget(value) {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || Object.keys(value).some((key) => ![
      'attack_controller_wall_clock_ms',
      'control_controller_wall_clock_ms',
      'capture_grace_ms',
      'controller_wall_clock_ms',
    ].includes(key))
  ) {
    throw new TypeError('service_session_budget must be an exact object')
  }
  const budget = {
    attack_controller_wall_clock_ms: requireBoundedInteger(
      value.attack_controller_wall_clock_ms,
      'service_session_budget.attack_controller_wall_clock_ms',
      1_000,
      SERVICE_CONTROLLER_SESSION_MAX_MS,
    ),
    control_controller_wall_clock_ms: requireBoundedInteger(
      value.control_controller_wall_clock_ms,
      'service_session_budget.control_controller_wall_clock_ms',
      1_000,
      SERVICE_CONTROLLER_SESSION_MAX_MS,
    ),
    capture_grace_ms: requireBoundedInteger(
      value.capture_grace_ms,
      'service_session_budget.capture_grace_ms',
      1_000,
      SERVICE_CAPTURE_GRACE_MAX_MS,
    ),
    controller_wall_clock_ms: requireBoundedInteger(
      value.controller_wall_clock_ms,
      'service_session_budget.controller_wall_clock_ms',
      3_000,
      SERVICE_CONTROLLER_WALL_CLOCK_MAX_MS,
    ),
  }
  if (
    budget.controller_wall_clock_ms
    !== budget.attack_controller_wall_clock_ms
      + budget.control_controller_wall_clock_ms
      + budget.capture_grace_ms
  ) {
    throw new Error(
      'service_session_budget.controller_wall_clock_ms must equal attack, control, and capture budgets',
    )
  }
  return budget
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

/**
 * Lease the two fresh, sequential containers used by a public T2 service proof.
 * The names and all trusted configuration digests are committed before Docker
 * is reachable, making an expired STARTED attempt safely identifiable later.
 */
export function leaseServiceProofAttempt(run, jobId, metadata) {
  assertValidRun(run)
  if (run.schema_version !== SERVICE_PROOF_SCHEMA_VERSION) {
    throw new Error('Observed service-proof attempts require a v7 run')
  }
  if (!run.source_snapshot || !run.control_snapshot) {
    throw new Error(
      'Observed service-proof attempts require sealed source and control snapshots',
    )
  }
  const job = jobById(run, jobId)
  if (job.kind !== 'PROOF' || !job.job_id.startsWith('proof-verification:')) {
    throw new Error(
      `Job ${jobId} is not a proof-verification PROOF job`,
    )
  }
  if (!Array.isArray(job.candidate_ids) || job.candidate_ids.length !== 1) {
    throw new Error(
      `proof-verification job ${jobId} must name exactly one candidate`,
    )
  }
  if (job.state !== 'PENDING') {
    throw new Error(`Job ${jobId} is ${job.state}; only PENDING jobs can be leased`)
  }
  if (findActiveAttempt(run, jobId)) {
    throw new Error(`Job ${jobId} already has an active attempt`)
  }

  const occurredAt = metadata?.occurred_at ?? new Date().toISOString()
  const occurredAtMilliseconds = requireTimestamp(occurredAt, 'occurred_at')
  const attemptId = metadata?.attempt_id ?? `attempt:${randomUUID()}`
  const serviceContainerNames = normalizeServiceContainerNames(
    metadata?.service_container_names ?? defaultServiceContainerNames(attemptId),
  )
  const serviceSessionBudget = normalizeServiceSessionBudget(
    metadata?.service_session_budget,
  )
  const minimumExpiryMilliseconds = occurredAtMilliseconds
    + serviceSessionBudget.controller_wall_clock_ms
  const expiresAt = metadata?.expires_at
    ?? new Date(minimumExpiryMilliseconds).toISOString()
  const expiresAtMilliseconds = requireTimestamp(expiresAt, 'expires_at')
  if (expiresAtMilliseconds !== minimumExpiryMilliseconds) {
    throw new RangeError(
      'expires_at must equal the complete service-proof controller budget',
    )
  }

  const next = prepareJobStart(run, jobId)
  return appendEventToCandidate(run, next, {
    attempt_id: attemptId,
    job_id: jobId,
    event: 'LEASED',
    backend: SERVICE_PROOF_BACKEND,
    occurred_at: occurredAt,
    nonce: metadata?.nonce ?? randomBytes(32).toString('hex'),
    packet_sha256: requireString(metadata?.packet_sha256, 'packet_sha256'),
    plan_sha256: run.plan_digest,
    repository_tree_sha256: run.repository.tree_digest,
    lens_pack_sha256: run.lens_pack_digest,
    policy_sha256: run.policy_digest,
    proof_config_sha256: requireString(
      metadata?.proof_config_sha256,
      'proof_config_sha256',
    ),
    proof_worker_config_sha256: requireString(
      metadata?.proof_worker_config_sha256,
      'proof_worker_config_sha256',
    ),
    source_snapshot_sha256: run.source_snapshot.root_sha256,
    control_snapshot_sha256: run.control_snapshot.root_sha256,
    service_container_names: serviceContainerNames,
    service_session_budget: serviceSessionBudget,
    expires_at: expiresAt,
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

function serviceProofAttemptById(run, attemptId) {
  assertValidRun(run)
  const attempt = attemptById(run, attemptId)
  if (attempt.lease?.backend !== SERVICE_PROOF_BACKEND) {
    throw new Error(`Attempt ${attemptId} is not a service-proof container attempt`)
  }
  normalizeServiceContainerNames(attempt.lease.service_container_names)
  const budget = normalizeServiceSessionBudget(
    attempt.lease.service_session_budget,
  )
  const leaseOccurredAt = requireTimestamp(
    attempt.lease.occurred_at,
    'service-proof lease occurred_at',
  )
  const expiresAt = requireTimestamp(
    attempt.lease.expires_at,
    'service-proof lease expires_at',
  )
  if (expiresAt !== leaseOccurredAt + budget.controller_wall_clock_ms) {
    throw new Error(
      'service-proof lease expiry does not equal its controller budget',
    )
  }
  return attempt
}

export function markServiceProofAttemptStarted(run, attemptId, metadata = {}) {
  serviceProofAttemptById(run, attemptId)
  return markProviderAttemptStarted(run, attemptId, metadata)
}

/**
 * Return the only safe restart action for a service-proof attempt. In
 * particular, elapsed time never authorizes stealing an unexpired lease and
 * an expired STARTED lease carries its exact two cleanup targets.
 */
export function classifyServiceProofAttemptRecovery(run, attemptId, options = {}) {
  const attempt = serviceProofAttemptById(run, attemptId)
  const recovery = classifyProviderAttemptRecovery(run, attemptId, options)
  let status = recovery.status
  let cleanupRequired = false
  if (recovery.status === 'ACTIVE_EXPIRED' && attempt.state === 'LEASED') {
    status = 'EXPIRED_LEASED'
  } else if (recovery.status === 'ACTIVE_EXPIRED' && attempt.state === 'STARTED') {
    status = 'EXPIRED_STARTED'
    cleanupRequired = true
  }
  return {
    ...recovery,
    status,
    cleanup_required: cleanupRequired,
    service_container_names: clone(attempt.lease.service_container_names),
    proof_config_sha256: attempt.lease.proof_config_sha256,
    proof_worker_config_sha256: attempt.lease.proof_worker_config_sha256,
    packet_sha256: attempt.lease.packet_sha256,
    service_session_budget: clone(attempt.lease.service_session_budget),
  }
}

/**
 * Close an expired service-proof lease. LEASED means Docker was never
 * dispatchable and is recoverable directly. STARTED requires a cleanup result
 * for both exact leased names; ambiguity is persisted as terminal failure.
 */
export function recoverExpiredServiceProofAttempt(run, attemptId, metadata = {}) {
  if (
    metadata.failure_artifact_key !== undefined
    || metadata.failure_artifact !== undefined
    || metadata.partial_receipt_sha256 !== undefined
  ) {
    throw new Error('service-proof recovery does not accept provider failure artifacts')
  }
  const occurredAt = resolveInstant(
    metadata.occurred_at,
    'occurred_at',
  ).occurred_at
  const recovery = classifyServiceProofAttemptRecovery(run, attemptId, {
    now: occurredAt,
  })
  let recoverable
  let cleanedServiceContainerNames
  if (recovery.status === 'EXPIRED_LEASED') {
    recoverable = true
  } else if (recovery.status === 'EXPIRED_STARTED') {
    if (typeof metadata.cleanup_verified !== 'boolean') {
      throw new TypeError('cleanup_verified must be a boolean for an expired STARTED attempt')
    }
    let observedNames
    try {
      observedNames = normalizeServiceContainerNames(metadata.service_container_names)
    } catch {
      throw new Error('cleanup must bind the exact leased service container names')
    }
    if (!isDeepStrictEqual(observedNames, recovery.service_container_names)) {
      throw new Error('cleanup must bind the exact leased service container names')
    }
    cleanedServiceContainerNames = observedNames
    recoverable = metadata.cleanup_verified
  } else {
    throw new Error(
      `Attempt ${attemptId} is ${recovery.status}; only an expired LEASED or STARTED service-proof attempt can be recovered`,
    )
  }
  const attempt = serviceProofAttemptById(run, attemptId)
  return failAttempt(run, attempt, {
    occurred_at: occurredAt,
    reason: metadata.reason ?? (
      recoverable
        ? `service-proof attempt lease expired at ${recovery.expires_at}`
        : 'service-proof container cleanup could not be verified'
    ),
    recoverable,
    ...(recovery.status === 'EXPIRED_STARTED'
      ? { cleanup_verified: metadata.cleanup_verified }
      : {}),
  }, cleanedServiceContainerNames)
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

function failAttempt(run, attempt, metadata = {}, serviceContainerNames) {
  if (!ACTIVE_EVENTS.has(attempt.state)) {
    throw new Error(`Attempt ${attempt.attempt_id} is already terminal`)
  }
  const recoverable = metadata.recoverable !== false
  if (
    metadata.cleanup_verified !== undefined
    && typeof metadata.cleanup_verified !== 'boolean'
  ) {
    throw new TypeError('cleanup_verified must be a boolean when supplied')
  }
  const normalizedServiceContainerNames = serviceContainerNames === undefined
    ? undefined
    : normalizeServiceContainerNames(serviceContainerNames)
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
    attempt_id: attempt.attempt_id,
    job_id: attempt.job_id,
    event: 'FAILED',
    occurred_at: metadata.occurred_at ?? new Date().toISOString(),
    reason,
    recoverable,
    ...(metadata.cleanup_verified === undefined
      ? {}
      : { cleanup_verified: metadata.cleanup_verified }),
    ...(normalizedServiceContainerNames === undefined
      ? {}
      : { service_container_names: normalizedServiceContainerNames }),
    ...failureEvidence,
  })
}

export function failProviderAttempt(run, attemptId, metadata = {}) {
  assertValidRun(run)
  const attempt = attemptById(run, attemptId)
  if (attempt.lease?.backend === SERVICE_PROOF_BACKEND) {
    throw new Error(
      'generic provider failure cannot mutate a service-proof attempt; use the service-proof failure or recovery API',
    )
  }
  return failAttempt(run, attempt, metadata)
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

export function recordServiceProofResultCaptured(run, attemptId, metadata) {
  const attempt = serviceProofAttemptById(run, attemptId)
  const occurredAt = resolveInstant(
    metadata?.occurred_at,
    'occurred_at',
  )
  const expiresAt = requireTimestamp(
    attempt.lease.expires_at,
    'service-proof lease expires_at',
  )
  if (occurredAt.milliseconds >= expiresAt) {
    throw new Error(
      `Attempt ${attemptId} lease expired at ${attempt.lease.expires_at}; refusing RESULT_CAPTURED`,
    )
  }
  const receiptSha256 = requireString(
    metadata?.receipt_sha256,
    'receipt_sha256',
  )
  const executionArtifactSha256 = requireString(
    metadata?.execution_artifact?.sha256,
    'execution_artifact.sha256',
  )
  if (receiptSha256 !== executionArtifactSha256) {
    throw new Error(
      'service-proof receipt_sha256 must equal execution_artifact.sha256',
    )
  }
  return recordProviderResultCaptured(run, attemptId, {
    ...metadata,
    occurred_at: occurredAt.occurred_at,
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

export function recordServiceProofResultValidated(run, attemptId, metadata = {}) {
  serviceProofAttemptById(run, attemptId)
  return recordProviderResultValidated(run, attemptId, metadata)
}

export function failServiceProofAttempt(run, attemptId, metadata = {}) {
  const attempt = serviceProofAttemptById(run, attemptId)
  if (
    metadata.failure_artifact_key !== undefined
    || metadata.failure_artifact !== undefined
    || metadata.partial_receipt_sha256 !== undefined
  ) {
    throw new Error('service-proof attempts do not accept provider failure artifacts')
  }
  if (['RESULT_CAPTURED', 'VALIDATED'].includes(attempt.state)) {
    throw new Error(
      'captured service-proof results are resume-only and cannot be failed',
    )
  }
  if (
    metadata.recoverable !== undefined
    && typeof metadata.recoverable !== 'boolean'
  ) {
    throw new TypeError('recoverable must be a boolean when supplied')
  }
  if (metadata.recoverable === true) {
    throw new Error(
      'ordinary service-proof failures are terminal-only; use expired service-proof recovery for retry',
    )
  }
  if (
    metadata.cleanup_verified !== undefined
    || metadata.service_container_names !== undefined
  ) {
    throw new Error(
      'ordinary service-proof failures do not accept recovery cleanup metadata',
    )
  }
  return failAttempt(run, attempt, {
    ...metadata,
    recoverable: false,
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

export function commitServiceProofAttempt(
  previous,
  candidateRun,
  attemptId,
  metadata = {},
) {
  serviceProofAttemptById(previous, attemptId)
  return commitProviderAttempt(previous, candidateRun, attemptId, metadata)
}
