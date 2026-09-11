import { createHash } from 'node:crypto'
import { constants as FS_CONSTANTS } from 'node:fs'
import { lstat, open, realpath } from 'node:fs/promises'
import { isAbsolute, join, normalize, parse, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { assertLocalFilesystemEndpoint } from './filesystem-endpoint.mjs'
import { stableJson } from './run-engine.mjs'

const AUDIT_CLI = fileURLToPath(new URL('../audit.mjs', import.meta.url))
const MAX_SCALAR_BYTES = 64 * 1024
const MAX_JSON_BYTES = 4 * 1024 * 1024
const TERMINAL_CHILD_STATES = new Set(['COMPLETED', 'COMPLETE_WITH_GAPS', 'FAILED', 'ABORTED'])
const ACTION_FAILURE_CODES = Object.freeze({
  plan: 'REPOSITORY_PLAN_FAILED',
  next: 'REPOSITORY_NEXT_FAILED',
  status: 'REPOSITORY_STATUS_FAILED',
  'check-result': 'REPOSITORY_RESULT_CHECK_FAILED',
  ingest: 'REPOSITORY_RESULT_INGEST_FAILED',
  finalize: 'REPOSITORY_FINALIZE_FAILED',
  validate: 'REPOSITORY_VALIDATE_FAILED',
})

const ACTION_FIELDS = Object.freeze({
  plan: ['repositoryPath', 'outputDirectory'],
  next: ['childBundle'],
  status: ['childBundle'],
  'check-result': ['childBundle', 'resultPath', 'resultSha256', 'resultSize'],
  ingest: ['childBundle', 'resultPath', 'resultSha256', 'resultSize'],
  finalize: ['childBundle'],
  validate: ['childBundle'],
})

export class RepositoryWorkflowError extends Error {
  constructor(code, message, options = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause })
    this.name = 'RepositoryWorkflowError'
    this.code = code
    if (options.recovery !== undefined) this.recovery = structuredClone(options.recovery)
  }
}

function fail(code, message, options) {
  throw new RepositoryWorkflowError(code, message, options)
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function exactFields(value, expected) {
  if (!isRecord(value)) return false
  const actual = Object.keys(value).sort()
  const fields = [...expected].sort()
  return actual.length === fields.length
    && actual.every((field, index) => field === fields[index])
}

function assertExactFields(value, expected, code, label) {
  if (!exactFields(value, expected)) {
    fail(code, `${label} must contain exactly the documented fields`)
  }
  return value
}

function scalar(value, name, code = 'REPOSITORY_WORKFLOW_MATERIAL_INVALID') {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.includes('\0')
    || Buffer.byteLength(value, 'utf8') > MAX_SCALAR_BYTES
  ) {
    fail(code, `${name} must be a bounded non-empty string without NUL`)
  }
  return value
}

function samePath(left, right) {
  return process.platform === 'win32'
    ? left.toLowerCase() === right.toLowerCase()
    : left === right
}

function canonicalPath(value, name, code = 'REPOSITORY_WORKFLOW_MATERIAL_INVALID') {
  scalar(value, name, code)
  try {
    assertLocalFilesystemEndpoint(value, name)
  } catch (cause) {
    fail(code, `${name} must be a canonical local filesystem path`, { cause })
  }
  if (!isAbsolute(value) || !samePath(resolve(value), value) || !samePath(normalize(value), value)) {
    fail(code, `${name} must be a canonical absolute local filesystem path`)
  }
  if (process.platform === 'win32') {
    const root = parse(value).root
    if (value.slice(root.length).includes(':')) {
      fail(code, `${name} cannot use a Windows alternate data stream`)
    }
  }
  return value
}

function relativeContainment(root, candidate) {
  const path = relative(root, candidate)
  return path === '' ? 'equal' : (!path.startsWith('..') && !isAbsolute(path) ? 'inside' : 'outside')
}

function assertDisjointPaths(left, right, code, label) {
  if (relativeContainment(left, right) !== 'outside' || relativeContainment(right, left) !== 'outside') {
    fail(code, `${label} must not overlap`)
  }
}

function assertStrictlyContained(root, candidate, code, label) {
  if (relativeContainment(root, candidate) !== 'inside') {
    fail(code, `${label} must be a strict descendant of its controller-owned parent`)
  }
  return candidate
}

function sha256(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

function digest(value, name, code = 'REPOSITORY_WORKFLOW_MATERIAL_INVALID') {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) {
    fail(code, `${name} must be a lowercase SHA-256 digest`)
  }
  return value
}

function nonNegativeInteger(value, name, code) {
  if (!Number.isSafeInteger(value) || value < 0) fail(code, `${name} must be a non-negative integer`)
  return value
}

function canonicalJsonClone(value, code, label) {
  let serialized
  try {
    serialized = stableJson(value, 0)
  } catch (cause) {
    fail(code, `${label} must be finite JSON data`, { cause })
  }
  if (Buffer.byteLength(serialized, 'utf8') > MAX_JSON_BYTES) {
    fail(code, `${label} exceeds the maximum JSON size`)
  }
  let clone
  try {
    clone = JSON.parse(serialized)
  } catch (cause) {
    fail(code, `${label} must be finite JSON data`, { cause })
  }
  return { clone, serialized }
}

function invocation(arguments_) {
  return {
    public_entrypoint: process.execPath,
    arguments: [AUDIT_CLI, ...arguments_],
    shell: false,
  }
}

/** Build one allowlisted audit CLI invocation. This API accepts no argv or command override. */
export function buildRepositoryAuditInvocation(action, material) {
  if (typeof action !== 'string' || !Object.hasOwn(ACTION_FIELDS, action)) {
    fail('REPOSITORY_WORKFLOW_ACTION_UNKNOWN', 'repository workflow action is not allowlisted')
  }
  assertExactFields(
    material,
    ACTION_FIELDS[action],
    'REPOSITORY_WORKFLOW_MATERIAL_INVALID',
    `${action} material`,
  )

  if (action === 'plan') {
    const repositoryPath = canonicalPath(material.repositoryPath, 'repositoryPath')
    const outputDirectory = canonicalPath(material.outputDirectory, 'outputDirectory')
    assertDisjointPaths(
      repositoryPath,
      outputDirectory,
      'REPOSITORY_WORKFLOW_MATERIAL_INVALID',
      'repositoryPath and outputDirectory',
    )
    return invocation([
      'plan',
      repositoryPath,
      '--out',
      outputDirectory,
      '--seal-source',
      '--json',
    ])
  }

  const childBundle = canonicalPath(material.childBundle, 'childBundle')
  if (action === 'next') return invocation(['next', childBundle])
  if (action === 'status') return invocation(['status', childBundle, '--json'])
  if (action === 'finalize') return invocation(['finalize', childBundle])
  if (action === 'validate') return invocation(['validate', childBundle, '--json'])

  const resultPath = canonicalPath(material.resultPath, 'resultPath')
  const resultSha256 = digest(material.resultSha256, 'resultSha256')
  const resultSize = nonNegativeInteger(
    material.resultSize,
    'resultSize',
    'REPOSITORY_WORKFLOW_MATERIAL_INVALID',
  )
  const resultBinding = [
    '--expected-sha256', resultSha256,
    '--expected-size', String(resultSize),
  ]
  if (action === 'check-result') {
    return invocation(['check-result', childBundle, resultPath, ...resultBinding, '--json'])
  }
  return invocation(['ingest', childBundle, resultPath, ...resultBinding])
}

function assertExecutor(dependencies) {
  if (!isRecord(dependencies) || typeof dependencies.execute !== 'function') {
    fail('REPOSITORY_WORKFLOW_EXECUTOR_INVALID', 'repository workflow requires an execute dependency')
  }
  return dependencies.execute
}

async function executeAction(action, material, dependencies) {
  const execute = assertExecutor(dependencies)
  const invocation = buildRepositoryAuditInvocation(action, material)
  let result
  try {
    result = await execute({ action, invocation })
  } catch (cause) {
    if (action === 'ingest' && cause?.requestMayHaveBeenSent !== false) {
      fail(
        'REPOSITORY_INGEST_OUTCOME_AMBIGUOUS',
        'repository ingest may have mutated the child bundle before execution failed',
        { cause },
      )
    }
    fail(ACTION_FAILURE_CODES[action], `repository ${action} execution failed`, { cause })
  }
  const supervisorStatusRejected = typeof result?.status === 'string'
    && !['SUCCEEDED', 'PARTIAL'].includes(result.status)
  const supervisorError = typeof result?.errorCode === 'string' && result.errorCode.length > 0
  const terminationRejected = result?.termination_confirmed === false
    || result?.terminationConfirmed === false
    || (
      result?.started === true
      && result?.termination_confirmed !== true
      && result?.terminationConfirmed !== true
    )
  if (
    !isRecord(result)
    || !Number.isSafeInteger(result.exitCode)
    || typeof result.stdout !== 'string'
    || typeof result.stderr !== 'string'
    || result.exitCode !== 0
    || result.timedOut === true
    || (result.signal !== undefined && result.signal !== null)
    || supervisorStatusRejected
    || supervisorError
    || terminationRejected
  ) {
    if (action === 'ingest' && result?.requestMayHaveBeenSent !== false) {
      fail(
        'REPOSITORY_INGEST_OUTCOME_AMBIGUOUS',
        'repository ingest did not return a conclusive outcome after it may have started',
      )
    }
    fail(ACTION_FAILURE_CODES[action], `repository ${action} execution did not complete successfully`)
  }
  if (Buffer.byteLength(result.stdout, 'utf8') > MAX_JSON_BYTES) {
    if (action === 'ingest') {
      fail(
        'REPOSITORY_INGEST_OUTCOME_AMBIGUOUS',
        'repository ingest output was invalid after the child bundle may have been mutated',
      )
    }
    fail(ACTION_FAILURE_CODES[action], `repository ${action} output exceeded the allowed size`)
  }
  return result
}

function parseJsonOutput(result, action) {
  let value
  try {
    value = JSON.parse(result.stdout)
  } catch (cause) {
    fail(ACTION_FAILURE_CODES[action], `repository ${action} did not return valid JSON`, { cause })
  }
  if (!isRecord(value)) {
    fail(ACTION_FAILURE_CODES[action], `repository ${action} did not return a JSON object`)
  }
  return value
}

/** Plan the child audit while preserving the fact that no analysis result exists yet. */
export async function planRepositoryWorkflow(material, dependencies) {
  const repositoryPath = await existingCanonicalDirectory(
    material?.repositoryPath,
    'repositoryPath',
    'REPOSITORY_WORKFLOW_MATERIAL_INVALID',
  )
  const outputDirectory = await existingCanonicalDirectory(
    material?.outputDirectory,
    'outputDirectory',
    'REPOSITORY_WORKFLOW_MATERIAL_INVALID',
  )
  assertDisjointPaths(
    repositoryPath,
    outputDirectory,
    'REPOSITORY_WORKFLOW_MATERIAL_INVALID',
    'repositoryPath and outputDirectory',
  )
  const result = await executeAction('plan', { repositoryPath, outputDirectory }, dependencies)
  const planned = parseJsonOutput(result, 'plan')
  const childBundle = await existingCanonicalDirectory(
    planned.bundle,
    'plan bundle',
    'REPOSITORY_PLAN_FAILED',
  )
  assertStrictlyContained(
    outputDirectory,
    childBundle,
    'REPOSITORY_PLAN_FAILED',
    'planned child bundle',
  )
  const runId = scalar(planned.run_id, 'plan run_id', 'REPOSITORY_PLAN_FAILED')
  const capabilityMode = scalar(
    planned.capability_mode,
    'plan capability_mode',
    'REPOSITORY_PLAN_FAILED',
  )
  if (typeof planned.source_sealed !== 'boolean') {
    fail('REPOSITORY_PLAN_FAILED', 'repository plan source_sealed must be boolean')
  }
  if (planned.source_sealed !== true) {
    fail('REPOSITORY_PLAN_FAILED', 'repository plan must return an exact sealed source snapshot')
  }

  return {
    schema_version: '1.0.0',
    state: 'WAITING_FOR_AGENT_RESULT',
    child_bundle: childBundle,
    run_id: runId,
    child_state: 'PLANNED',
    child_phase: 'RECON',
    capability_mode: capabilityMode,
    source_sealed: planned.source_sealed,
    next_step: { code: 'INSPECT_PENDING_WORK' },
  }
}

function statusCount(container, name, code = 'REPOSITORY_CHILD_STATUS_INVALID') {
  if (!isRecord(container)) fail(code, `${name} container is invalid`)
  return nonNegativeInteger(container.total, `${name}.total`, code)
}

function publicChildState(status, pendingCount, runningCount, activeAttemptCount) {
  if (status.state === 'COMPLETED') return 'COMPLETED'
  if (status.state === 'COMPLETE_WITH_GAPS') return 'COMPLETE_WITH_GAPS'
  if (status.state === 'FAILED' || status.state === 'ABORTED') return 'FAILED'
  if (status.next_step.code === 'REVIEW_FINALIZATION') return 'READY_TO_FINALIZE'
  if (status.next_step.code === 'REVIEW_CAPTURED_RESULT') return 'RESULT_REVIEW_REQUIRED'
  if (
    pendingCount > 0
    || runningCount > 0
    || activeAttemptCount > 0
    || ['INSPECT_PENDING_WORK', 'AWAIT_RESULTS'].includes(status.next_step.code)
  ) return 'WAITING_FOR_AGENT_RESULT'
  return 'BLOCKED'
}

/** Project validated child status without touching the bundle or retaining target text. */
export function projectRepositoryChildStatus(value) {
  const { clone: status } = canonicalJsonClone(
    value,
    'REPOSITORY_CHILD_STATUS_INVALID',
    'repository child status',
  )
  if (!isRecord(status)) fail('REPOSITORY_CHILD_STATUS_INVALID', 'repository child status must be an object')
  const runId = scalar(status.run_id, 'status run_id', 'REPOSITORY_CHILD_STATUS_INVALID')
  const childState = scalar(status.state, 'status state', 'REPOSITORY_CHILD_STATUS_INVALID')
  const childPhase = scalar(status.phase, 'status phase', 'REPOSITORY_CHILD_STATUS_INVALID')
  const capabilityMode = scalar(
    status.capability_mode,
    'status capability_mode',
    'REPOSITORY_CHILD_STATUS_INVALID',
  )
  if (typeof status.source_sealed !== 'boolean' || typeof status.terminal !== 'boolean') {
    fail('REPOSITORY_CHILD_STATUS_INVALID', 'repository child status flags are invalid')
  }
  if (status.terminal !== TERMINAL_CHILD_STATES.has(childState)) {
    fail('REPOSITORY_CHILD_STATUS_INVALID', 'repository child terminal flag does not match its state')
  }
  if (status.bundle_integrity !== 'VERIFIED') {
    fail('REPOSITORY_CHILD_STATUS_INVALID', 'repository child bundle is not verified')
  }
  if (!isRecord(status.jobs) || !isRecord(status.next_step)) {
    fail('REPOSITORY_CHILD_STATUS_INVALID', 'repository child job or next-step status is invalid')
  }
  const pendingCount = statusCount(status.jobs.pending_current_phase, 'pending_current_phase')
  const runningCount = statusCount(status.jobs.running, 'running')
  const activeAttemptCount = statusCount(status.active_attempts, 'active_attempts')
  const nextCode = scalar(
    status.next_step.code,
    'status next_step.code',
    'REPOSITORY_CHILD_STATUS_INVALID',
  )
  if (!isRecord(status.findings) || !isRecord(status.coverage) || !isRecord(status.errors)) {
    fail('REPOSITORY_CHILD_STATUS_INVALID', 'repository child summary sections are invalid')
  }
  const errorCount = statusCount(status.errors, 'errors')
  const errorsOmitted = nonNegativeInteger(
    status.errors.omitted,
    'errors.omitted',
    'REPOSITORY_CHILD_STATUS_INVALID',
  )

  return {
    schema_version: '1.0.0',
    state: publicChildState(status, pendingCount, runningCount, activeAttemptCount),
    run_id: runId,
    child_state: childState,
    child_phase: childPhase,
    terminal: status.terminal,
    capability_mode: capabilityMode,
    source_sealed: status.source_sealed,
    bundle_integrity: 'VERIFIED',
    root_authenticity: status.root_authenticity === 'ANCHORED' ? 'ANCHORED' : 'UNANCHORED',
    live_repository: status.live_repository === 'VERIFIED' ? 'VERIFIED' : 'NOT_CHECKED',
    pending_job_count: pendingCount,
    running_job_count: runningCount,
    active_attempt_count: activeAttemptCount,
    findings: structuredClone(status.findings),
    coverage: structuredClone(status.coverage),
    errors: { total: errorCount, omitted: errorsOmitted },
    next_step: { code: nextCode },
  }
}

/** Read and project a child status. The audit status command itself is inspection-only. */
export async function readRepositoryChildStatus(material, dependencies) {
  const childBundle = await existingCanonicalDirectory(
    material?.childBundle,
    'childBundle',
    'REPOSITORY_WORKFLOW_MATERIAL_INVALID',
  )
  const result = await executeAction('status', { childBundle }, dependencies)
  return projectRepositoryChildStatus(parseJsonOutput(result, 'status'))
}

function validatePacket(value) {
  const { clone: packet, serialized } = canonicalJsonClone(
    value,
    'REPOSITORY_PACKET_INVALID',
    'repository job packet',
  )
  if (!isRecord(packet)) fail('REPOSITORY_PACKET_INVALID', 'repository job packet must be an object')
  const runId = scalar(packet.run_id, 'packet run_id', 'REPOSITORY_PACKET_INVALID')
  const jobId = scalar(packet.job_id, 'packet job_id', 'REPOSITORY_PACKET_INVALID')
  const kind = scalar(packet.kind, 'packet kind', 'REPOSITORY_PACKET_INVALID')
  const packetSha256 = digest(
    packet.packet_sha256,
    'packet_sha256',
    'REPOSITORY_PACKET_INVALID',
  )
  const { packet_sha256: _packetSha256, ...unsigned } = packet
  if (sha256(stableJson(unsigned, 0)) !== packetSha256) {
    fail('REPOSITORY_PACKET_INVALID', 'repository job packet digest does not match its content')
  }
  return { packet, serialized, runId, jobId, kind, packetSha256 }
}

const ENVELOPE_INPUT_FIELDS = Object.freeze([
  'engagementId',
  'authoritySha256',
  'targetSha256',
  'childBundle',
  'childState',
  'childPhase',
  'packet',
])

/** Create a deterministic work item. It carries bindings, not the immutable authority statement. */
export function createRepositoryWorkEnvelope(input) {
  assertExactFields(
    input,
    ENVELOPE_INPUT_FIELDS,
    'REPOSITORY_WORK_ENVELOPE_INVALID',
    'repository work envelope input',
  )
  const engagementId = scalar(
    input.engagementId,
    'engagementId',
    'REPOSITORY_WORK_ENVELOPE_INVALID',
  )
  const authoritySha256 = digest(
    input.authoritySha256,
    'authoritySha256',
    'REPOSITORY_WORK_ENVELOPE_INVALID',
  )
  const targetSha256 = digest(
    input.targetSha256,
    'targetSha256',
    'REPOSITORY_WORK_ENVELOPE_INVALID',
  )
  const childBundle = canonicalPath(
    input.childBundle,
    'childBundle',
    'REPOSITORY_WORK_ENVELOPE_INVALID',
  )
  const childState = scalar(
    input.childState,
    'childState',
    'REPOSITORY_WORK_ENVELOPE_INVALID',
  )
  const childPhase = scalar(
    input.childPhase,
    'childPhase',
    'REPOSITORY_WORK_ENVELOPE_INVALID',
  )
  const packet = validatePacket(input.packet)

  const core = {
    schema_version: '1.0.0',
    kind: 'last-aperture/repository-work-envelope',
    state: 'WAITING_FOR_AGENT_RESULT',
    result_contract: 'schemas/job-result.schema.json',
    binding: {
      engagement_id: engagementId,
      authority_sha256: authoritySha256,
      target_sha256: targetSha256,
      child_bundle: childBundle,
      child_run_id: packet.runId,
      child_state: childState,
      child_phase: childPhase,
      job_id: packet.jobId,
      job_kind: packet.kind,
      packet_sha256: packet.packetSha256,
    },
    packet: packet.packet,
  }
  const workId = `repository-work:${sha256(stableJson(core, 0))}`
  const unsignedEnvelope = { ...core, work_id: workId }
  return {
    ...unsignedEnvelope,
    work_envelope_sha256: sha256(stableJson(unsignedEnvelope, 0)),
  }
}

const ENVELOPE_FIELDS = Object.freeze([
  'schema_version',
  'kind',
  'state',
  'result_contract',
  'binding',
  'packet',
  'work_id',
  'work_envelope_sha256',
])
const ENVELOPE_BINDING_FIELDS = Object.freeze([
  'engagement_id',
  'authority_sha256',
  'target_sha256',
  'child_bundle',
  'child_run_id',
  'child_state',
  'child_phase',
  'job_id',
  'job_kind',
  'packet_sha256',
])

/** Verify both the packet digest and every engagement/child binding in an envelope. */
export function verifyRepositoryWorkEnvelope(value, expected) {
  const { clone: envelope, serialized } = canonicalJsonClone(
    value,
    'REPOSITORY_WORK_ENVELOPE_INVALID',
    'repository work envelope',
  )
  assertExactFields(
    envelope,
    ENVELOPE_FIELDS,
    'REPOSITORY_WORK_ENVELOPE_INVALID',
    'repository work envelope',
  )
  assertExactFields(
    envelope.binding,
    ENVELOPE_BINDING_FIELDS,
    'REPOSITORY_WORK_ENVELOPE_INVALID',
    'repository work envelope binding',
  )
  if (
    envelope.schema_version !== '1.0.0'
    || envelope.kind !== 'last-aperture/repository-work-envelope'
    || envelope.state !== 'WAITING_FOR_AGENT_RESULT'
    || envelope.result_contract !== 'schemas/job-result.schema.json'
  ) fail('REPOSITORY_WORK_ENVELOPE_INVALID', 'repository work envelope constants are invalid')

  scalar(envelope.binding.engagement_id, 'binding engagement_id', 'REPOSITORY_WORK_ENVELOPE_INVALID')
  digest(envelope.binding.authority_sha256, 'binding authority_sha256', 'REPOSITORY_WORK_ENVELOPE_INVALID')
  digest(envelope.binding.target_sha256, 'binding target_sha256', 'REPOSITORY_WORK_ENVELOPE_INVALID')
  canonicalPath(
    envelope.binding.child_bundle,
    'binding child_bundle',
    'REPOSITORY_WORK_ENVELOPE_INVALID',
  )
  scalar(envelope.binding.child_state, 'binding child_state', 'REPOSITORY_WORK_ENVELOPE_INVALID')
  scalar(envelope.binding.child_phase, 'binding child_phase', 'REPOSITORY_WORK_ENVELOPE_INVALID')
  const packet = validatePacket(envelope.packet)
  if (
    envelope.binding.child_run_id !== packet.runId
    || envelope.binding.job_id !== packet.jobId
    || envelope.binding.job_kind !== packet.kind
    || envelope.binding.packet_sha256 !== packet.packetSha256
  ) fail('REPOSITORY_WORK_ENVELOPE_INVALID', 'repository work envelope packet binding does not match')

  const { work_envelope_sha256: envelopeDigest, ...unsignedEnvelope } = envelope
  digest(envelopeDigest, 'work_envelope_sha256', 'REPOSITORY_WORK_ENVELOPE_INVALID')
  if (sha256(stableJson(unsignedEnvelope, 0)) !== envelopeDigest) {
    fail('REPOSITORY_WORK_ENVELOPE_INVALID', 'repository work envelope digest does not match')
  }
  const { work_id: workId, ...core } = unsignedEnvelope
  if (workId !== `repository-work:${sha256(stableJson(core, 0))}`) {
    fail('REPOSITORY_WORK_ENVELOPE_INVALID', 'repository work identifier does not match its bindings')
  }
  if (expected !== undefined) {
    if (typeof expected === 'string') {
      digest(expected, 'expected work envelope digest', 'REPOSITORY_WORK_ENVELOPE_EXPECTATION_INVALID')
      if (expected !== envelopeDigest) {
        fail('REPOSITORY_WORK_ENVELOPE_NOT_PERSISTED', 'repository work envelope differs from its persisted digest')
      }
    } else {
      const { clone: expectedEnvelope, serialized: expectedSerialized } = canonicalJsonClone(
        expected,
        'REPOSITORY_WORK_ENVELOPE_EXPECTATION_INVALID',
        'persisted repository work envelope',
      )
      verifyRepositoryWorkEnvelope(expectedEnvelope)
      if (serialized !== expectedSerialized) {
        fail('REPOSITORY_WORK_ENVELOPE_NOT_PERSISTED', 'repository work envelope differs from its persisted record')
      }
    }
  }
  return true
}

const NEXT_WORK_FIELDS = Object.freeze([
  'engagementId',
  'authoritySha256',
  'targetSha256',
  'childBundle',
])

/** Inspect the current child phase and expose one deterministic packet for an agent. */
export async function prepareRepositoryNextWork(input, dependencies) {
  assertExactFields(
    input,
    NEXT_WORK_FIELDS,
    'REPOSITORY_WORKFLOW_MATERIAL_INVALID',
    'repository next-work input',
  )
  scalar(input.engagementId, 'engagementId')
  digest(input.authoritySha256, 'authoritySha256')
  digest(input.targetSha256, 'targetSha256')
  const childBundle = await existingCanonicalDirectory(
    input.childBundle,
    'childBundle',
    'REPOSITORY_WORKFLOW_MATERIAL_INVALID',
  )

  const result = await executeAction('next', { childBundle }, dependencies)
  const next = parseJsonOutput(result, 'next')
  const runId = scalar(next.run_id, 'next run_id', 'REPOSITORY_NEXT_FAILED')
  const childState = scalar(next.state, 'next state', 'REPOSITORY_NEXT_FAILED')
  const childPhase = scalar(next.phase, 'next phase', 'REPOSITORY_NEXT_FAILED')
  if (!Array.isArray(next.pending_jobs)) {
    fail('REPOSITORY_NEXT_FAILED', 'repository next pending_jobs must be an array')
  }
  if (next.pending_jobs.length === 0) {
    return {
      schema_version: '1.0.0',
      state: 'NO_PENDING_PACKET',
      child_bundle: childBundle,
      run_id: runId,
      child_state: childState,
      child_phase: childPhase,
      pending_packet_count: 0,
      next_step: { code: 'READ_CHILD_STATUS' },
    }
  }

  const currentPacket = validatePacket(next.pending_jobs[0])
  if (currentPacket.runId !== runId) {
    fail('REPOSITORY_NEXT_FAILED', 'repository next packet belongs to a different child run')
  }
  const workEnvelope = createRepositoryWorkEnvelope({
    engagementId: input.engagementId,
    authoritySha256: input.authoritySha256,
    targetSha256: input.targetSha256,
    childBundle,
    childState,
    childPhase,
    packet: currentPacket.packet,
  })
  return {
    schema_version: '1.0.0',
    state: 'WAITING_FOR_AGENT_RESULT',
    child_bundle: childBundle,
    run_id: runId,
    child_state: childState,
    child_phase: childPhase,
    pending_packet_count: next.pending_jobs.length,
    work_envelope: workEnvelope,
    next_step: { code: 'SUBMIT_BOUND_RESULT' },
  }
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs
    && left.nlink === right.nlink
}

async function existingCanonicalDirectory(value, name, code) {
  const path = canonicalPath(value, name, code)
  let metadata
  let canonical
  try {
    metadata = await lstat(path, { bigint: true })
    canonical = await realpath(path)
  } catch (cause) {
    fail(code, `${name} must be an existing controller-owned directory`, { cause })
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || !samePath(canonical, path)) {
    fail(code, `${name} must be one canonical unlinked directory`)
  }
  return path
}

async function readHandleBytes(handle, size, code, label) {
  if (size < 1n || size > BigInt(MAX_JSON_BYTES)) {
    fail(code, `${label} must be a non-empty regular file within the maximum JSON size`)
  }
  const bytes = Buffer.alloc(Number(size))
  let offset = 0
  while (offset < bytes.length) {
    const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset)
    if (bytesRead === 0) break
    offset += bytesRead
  }
  if (offset !== bytes.length) fail(code, `${label} changed length while it was read`)
  return bytes
}

async function openStableFile(value, name, code) {
  const path = canonicalPath(value, name, code)
  let before
  let canonicalBefore
  try {
    before = await lstat(path, { bigint: true })
    canonicalBefore = await realpath(path)
  } catch (cause) {
    fail(code, `${name} must be an existing canonical file`, { cause })
  }
  if (
    !before.isFile()
    || before.isSymbolicLink()
    || before.nlink !== 1n
    || !samePath(canonicalBefore, path)
  ) fail(code, `${name} must be one canonical unlinked single-name regular file`)

  let handle
  try {
    handle = await open(path, FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0))
    const heldBefore = await handle.stat({ bigint: true })
    if (!heldBefore.isFile() || heldBefore.nlink !== 1n || !sameFileIdentity(before, heldBefore)) {
      fail(code, `${name} identity changed before it was read`)
    }
    const bytes = await readHandleBytes(handle, heldBefore.size, code, name)
    const heldAfter = await handle.stat({ bigint: true })
    const after = await lstat(path, { bigint: true })
    const canonicalAfter = await realpath(path)
    if (
      !sameFileIdentity(heldBefore, heldAfter)
      || !sameFileIdentity(heldBefore, after)
      || !samePath(canonicalAfter, path)
    ) fail(code, `${name} identity changed while it was read`)
    return { path, bytes, sha256: createHash('sha256').update(bytes).digest('hex') }
  } catch (cause) {
    if (cause instanceof RepositoryWorkflowError) throw cause
    fail(code, `${name} could not be read through a stable file handle`, { cause })
  } finally {
    await handle?.close()
  }
}

async function syncDirectory(path) {
  let handle
  try {
    handle = await open(path, FS_CONSTANTS.O_RDONLY)
    await handle.sync()
  } catch (cause) {
    if (!['EINVAL', 'ENOTSUP', 'EPERM', 'EISDIR'].includes(cause?.code)) throw cause
  } finally {
    await handle?.close()
  }
}

async function openBoundStagedFile(path, expected) {
  const opened = await openStableFile(path, 'staged result', 'REPOSITORY_RESULT_STAGING_FAILED')
  if (opened.sha256 !== expected.sha256 || opened.bytes.length !== expected.size_bytes) {
    fail('REPOSITORY_RESULT_STAGING_CONFLICT', 'the staged result path contains different bytes')
  }
  const handle = await open(path, FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0))
  const identity = await handle.stat({ bigint: true })
  if (!identity.isFile() || identity.nlink !== 1n || identity.size !== BigInt(expected.size_bytes)) {
    await handle.close()
    fail('REPOSITORY_RESULT_STAGING_FAILED', 'the staged result identity is invalid')
  }
  return { handle, identity }
}

async function verifyBoundStagedFile(path, expected, held) {
  let pathIdentity
  let canonical
  try {
    pathIdentity = await lstat(path, { bigint: true })
    canonical = await realpath(path)
  } catch (cause) {
    fail('REPOSITORY_RESULT_STAGING_CHANGED', 'the staged result is unavailable', { cause })
  }
  const heldIdentity = await held.handle.stat({ bigint: true })
  if (
    !samePath(canonical, path)
    || !sameFileIdentity(held.identity, heldIdentity)
    || !sameFileIdentity(held.identity, pathIdentity)
  ) fail('REPOSITORY_RESULT_STAGING_CHANGED', 'the staged result pathname or identity changed')
  const bytes = await readHandleBytes(
    held.handle,
    heldIdentity.size,
    'REPOSITORY_RESULT_STAGING_CHANGED',
    'staged result',
  )
  if (
    bytes.length !== expected.size_bytes
    || createHash('sha256').update(bytes).digest('hex') !== expected.sha256
  ) fail('REPOSITORY_RESULT_STAGING_CHANGED', 'the staged result bytes changed')
}

async function stageExactResult(resultPath, stagingDirectory, envelope) {
  const source = await openStableFile(
    resultPath,
    'resultPath',
    'REPOSITORY_RESULT_SOURCE_INVALID',
  )
  const directory = await existingCanonicalDirectory(
    stagingDirectory,
    'stagingDirectory',
    'REPOSITORY_RESULT_STAGING_FAILED',
  )
  assertDisjointPaths(
    source.path,
    directory,
    'REPOSITORY_RESULT_STAGING_FAILED',
    'source result and stagingDirectory',
  )
  assertDisjointPaths(
    envelope.binding.child_bundle,
    directory,
    'REPOSITORY_RESULT_STAGING_FAILED',
    'child bundle and stagingDirectory',
  )
  if (relativeContainment(envelope.binding.child_bundle, source.path) !== 'outside') {
    fail('REPOSITORY_RESULT_SOURCE_INVALID', 'resultPath cannot be stored inside the child audit bundle')
  }

  const filename = `${envelope.work_envelope_sha256}-${source.sha256}.json`
  const stagedPath = join(directory, filename)
  assertStrictlyContained(
    directory,
    stagedPath,
    'REPOSITORY_RESULT_STAGING_FAILED',
    'staged result path',
  )
  let recovered = false
  let writer
  try {
    writer = await open(
      stagedPath,
      FS_CONSTANTS.O_WRONLY
        | FS_CONSTANTS.O_CREAT
        | FS_CONSTANTS.O_EXCL
        | (FS_CONSTANTS.O_NOFOLLOW ?? 0),
      0o400,
    )
    await writer.writeFile(source.bytes)
    await writer.sync()
  } catch (cause) {
    if (cause?.code !== 'EEXIST') {
      fail('REPOSITORY_RESULT_STAGING_FAILED', 'could not create the immutable staged result', { cause })
    }
    recovered = true
  } finally {
    await writer?.close()
  }
  if (!recovered) {
    try {
      await syncDirectory(directory)
    } catch (cause) {
      fail('REPOSITORY_RESULT_STAGING_FAILED', 'could not durably publish the staged result', { cause })
    }
  }

  const expected = {
    relative_path: filename,
    sha256: source.sha256,
    size_bytes: source.bytes.length,
    recovered,
  }
  return {
    path: stagedPath,
    binding: expected,
    held: await openBoundStagedFile(stagedPath, expected),
  }
}

async function assertPersistedEnvelope(envelope, dependencies) {
  if (!isRecord(dependencies) || typeof dependencies.loadExpectedEnvelope !== 'function') {
    fail(
      'REPOSITORY_WORK_ENVELOPE_EXPECTATION_REQUIRED',
      'result submission requires a controller-owned persisted work-envelope loader',
    )
  }
  let expected
  try {
    expected = await dependencies.loadExpectedEnvelope(Object.freeze({
      workId: envelope.work_id,
      workEnvelopeSha256: envelope.work_envelope_sha256,
    }))
  } catch (cause) {
    fail('REPOSITORY_WORK_ENVELOPE_EXPECTATION_UNAVAILABLE', 'persisted work envelope could not be loaded', { cause })
  }
  if (expected === undefined || expected === null) {
    fail('REPOSITORY_WORK_ENVELOPE_NOT_PERSISTED', 'repository work envelope has no controller-owned persisted record')
  }
  verifyRepositoryWorkEnvelope(envelope, expected)
}

function ambiguousIngestRecovery(envelope, staged) {
  return {
    schema_version: '1.0.0',
    state: 'INGEST_OUTCOME_AMBIGUOUS',
    work_id: envelope.work_id,
    child_bundle: envelope.binding.child_bundle,
    run_id: envelope.binding.child_run_id,
    job_id: envelope.binding.job_id,
    staged_result: structuredClone(staged.binding),
    next_step: { code: 'RECONCILE_CHILD_STATUS_BEFORE_RETRY' },
  }
}

function persistedStagedBinding(staged) {
  return {
    relative_path: staged.binding.relative_path,
    sha256: staged.binding.sha256,
    size_bytes: staged.binding.size_bytes,
  }
}

function assertStagedBinding(value, envelope) {
  assertExactFields(
    value,
    ['relative_path', 'sha256', 'size_bytes'],
    'REPOSITORY_RESULT_STAGING_FAILED',
    'persisted staged result binding',
  )
  const resultSha256 = digest(value.sha256, 'staged result sha256', 'REPOSITORY_RESULT_STAGING_FAILED')
  const resultSize = nonNegativeInteger(
    value.size_bytes,
    'staged result size_bytes',
    'REPOSITORY_RESULT_STAGING_FAILED',
  )
  const expectedName = `${envelope.work_envelope_sha256}-${resultSha256}.json`
  if (value.relative_path !== expectedName || value.relative_path !== parse(value.relative_path).base) {
    fail('REPOSITORY_RESULT_STAGING_FAILED', 'persisted staged result path is not bound to the work envelope')
  }
  return { relative_path: expectedName, sha256: resultSha256, size_bytes: resultSize }
}

function validateCheckedResult(checked, envelope, { allowApplied }) {
  if (
    checked.valid !== true
    || typeof checked.applied !== 'boolean'
    || (!allowApplied && checked.applied !== false)
  ) {
    fail('REPOSITORY_RESULT_CHECK_FAILED', 'repository result did not pass exact non-mutating validation')
  }
  if (
    checked.run_id !== envelope.binding.child_run_id
    || checked.job_id !== envelope.binding.job_id
  ) {
    fail('REPOSITORY_RESULT_BINDING_MISMATCH', 'validated result does not match the work envelope')
  }
  return scalar(
    checked.result_state,
    'checked result_state',
    'REPOSITORY_RESULT_CHECK_FAILED',
  )
}

/** Check a bound result without mutation, then ingest that same path only after a matching acceptance. */
export async function submitRepositoryWorkResult(input, dependencies) {
  assertExactFields(
    input,
    ['envelope', 'resultPath'],
    'REPOSITORY_WORKFLOW_MATERIAL_INVALID',
    'repository result submission',
  )
  verifyRepositoryWorkEnvelope(input.envelope)
  const { clone: envelope } = canonicalJsonClone(
    input.envelope,
    'REPOSITORY_WORK_ENVELOPE_INVALID',
    'repository work envelope',
  )
  await assertPersistedEnvelope(envelope, dependencies)
  const resultPath = canonicalPath(input.resultPath, 'resultPath')
  const childBundle = envelope.binding.child_bundle
  await existingCanonicalDirectory(
    childBundle,
    'childBundle',
    'REPOSITORY_WORK_ENVELOPE_INVALID',
  )
  const staged = await stageExactResult(resultPath, dependencies?.stagingDirectory, envelope)
  try {
    const checkedResult = await executeAction(
      'check-result',
      {
        childBundle,
        resultPath: staged.path,
        resultSha256: staged.binding.sha256,
        resultSize: staged.binding.size_bytes,
      },
      dependencies,
    )
    const checked = parseJsonOutput(checkedResult, 'check-result')
    const resultState = validateCheckedResult(checked, envelope, { allowApplied: false })

    await verifyBoundStagedFile(staged.path, staged.binding, staged.held)
    if (typeof dependencies?.beforeIngest !== 'function') {
      fail(
        'REPOSITORY_INGEST_DISPATCH_RECORD_REQUIRED',
        'repository ingest requires a durable controller dispatch record before mutation',
      )
    }
    try {
      await dependencies.beforeIngest(Object.freeze({
        work_id: envelope.work_id,
        envelope_sha256: envelope.work_envelope_sha256,
        result_state: resultState,
        staged_result: Object.freeze(persistedStagedBinding(staged)),
      }))
    } catch (cause) {
      fail(
        'REPOSITORY_INGEST_DISPATCH_RECORD_FAILED',
        'repository ingest dispatch was not durably recorded before mutation',
        { cause },
      )
    }
    try {
      await executeAction('ingest', {
        childBundle,
        resultPath: staged.path,
        resultSha256: staged.binding.sha256,
        resultSize: staged.binding.size_bytes,
      }, dependencies)
    } catch (cause) {
      if (cause?.code === 'REPOSITORY_INGEST_OUTCOME_AMBIGUOUS') {
        fail(
          'REPOSITORY_INGEST_OUTCOME_AMBIGUOUS',
          'repository ingest requires child-status reconciliation before any retry',
          { cause, recovery: ambiguousIngestRecovery(envelope, staged) },
        )
      }
      throw cause
    }
    try {
      await verifyBoundStagedFile(staged.path, staged.binding, staged.held)
    } catch (cause) {
      fail(
        'REPOSITORY_INGEST_OUTCOME_AMBIGUOUS',
        'the staged result changed while repository ingest may have mutated the child bundle',
        { cause, recovery: ambiguousIngestRecovery(envelope, staged) },
      )
    }
    return {
      schema_version: '1.0.0',
      state: 'RESULT_INGESTED',
      accepted: true,
      applied: true,
      work_id: envelope.work_id,
      child_bundle: childBundle,
      run_id: envelope.binding.child_run_id,
      job_id: envelope.binding.job_id,
      packet_sha256: envelope.binding.packet_sha256,
      result_state: resultState,
      staged_result: structuredClone(staged.binding),
      next_step: { code: 'READ_CHILD_STATUS' },
    }
  } finally {
    await staged.held.handle.close()
  }
}

/** Reconcile one durably dispatched ingest against the exact retained staged bytes. */
export async function reconcileRepositoryWorkResult(input, dependencies) {
  assertExactFields(
    input,
    ['envelope', 'stagedResult'],
    'REPOSITORY_WORKFLOW_MATERIAL_INVALID',
    'repository result reconciliation',
  )
  verifyRepositoryWorkEnvelope(input.envelope)
  const { clone: envelope } = canonicalJsonClone(
    input.envelope,
    'REPOSITORY_WORK_ENVELOPE_INVALID',
    'repository work envelope',
  )
  await assertPersistedEnvelope(envelope, dependencies)
  const stagedBinding = assertStagedBinding(input.stagedResult, envelope)
  const stagingDirectory = await existingCanonicalDirectory(
    dependencies?.stagingDirectory,
    'stagingDirectory',
    'REPOSITORY_RESULT_STAGING_FAILED',
  )
  const stagedPath = join(stagingDirectory, stagedBinding.relative_path)
  assertStrictlyContained(
    stagingDirectory,
    stagedPath,
    'REPOSITORY_RESULT_STAGING_FAILED',
    'staged result path',
  )
  const held = await openBoundStagedFile(stagedPath, stagedBinding)
  try {
    const checkedResult = await executeAction('check-result', {
      childBundle: envelope.binding.child_bundle,
      resultPath: stagedPath,
      resultSha256: stagedBinding.sha256,
      resultSize: stagedBinding.size_bytes,
    }, dependencies)
    const checked = parseJsonOutput(checkedResult, 'check-result')
    const resultState = validateCheckedResult(checked, envelope, { allowApplied: true })
    await verifyBoundStagedFile(stagedPath, stagedBinding, held)
    return {
      schema_version: '1.0.0',
      state: checked.applied ? 'RESULT_INGESTED' : 'RESULT_NOT_INGESTED',
      applied: checked.applied,
      work_id: envelope.work_id,
      child_bundle: envelope.binding.child_bundle,
      run_id: envelope.binding.child_run_id,
      job_id: envelope.binding.job_id,
      packet_sha256: envelope.binding.packet_sha256,
      result_state: resultState,
      staged_result: structuredClone(stagedBinding),
      next_step: {
        code: checked.applied ? 'READ_CHILD_STATUS' : 'RETRY_EXACT_RESULT',
      },
    }
  } finally {
    await held.handle.close()
  }
}
