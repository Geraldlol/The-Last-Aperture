/**
 * Maps a proof outcome onto the finding's evidence fields.
 *
 * Vulnerability validation and remediation are independent. A reproduced
 * attack with a passing explicit control confirms the vulnerability whether or
 * not a candidate patch exists. The legacy demonstration-plus-passing-patch
 * shape remains readable during migration.
 */
import { createHash } from 'node:crypto'

const MAX_DETAIL = 2000
const EMPTY_OUTPUT_SHA256 = createHash('sha256').digest('hex')

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function isSha256Hex(value) {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value)
}

function isSha256Image(value) {
  return typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value)
}

function truncated(text) {
  const value = String(text ?? '').trim()
  if (value.length === 0) return 'no output'
  return value.length > MAX_DETAIL ? `${value.slice(0, MAX_DETAIL)}…` : value
}

// Recorded on the finding rather than dropped: a run nobody watched and a rule
// that could not be applied are both facts a reader needs.
function caveatsFor(config, context) {
  const entries = []
  if (!config.destination_guard?.installed) {
    entries.push('execution was unmonitored: no destination guard was installed')
  }
  if (!context.ruleSixApplicable) {
    entries.push('previous revision check not applied: the target has no revision history')
  }
  return entries
}

function isVersionedOracle(config) {
  return ['2.0.0', '3.0.0'].includes(config?.schema_version)
    && Array.isArray(config?.oracle?.attack_exit_codes)
    && Array.isArray(config?.oracle?.control_exit_codes)
}

function attackExitMatches(result, config) {
  return isVersionedOracle(config)
    ? config.oracle.attack_exit_codes.includes(result?.code)
    : result?.code !== 0
}

function controlExitMatches(result, config) {
  return isVersionedOracle(config)
    ? config.oracle.control_exit_codes.includes(result?.code)
    : result?.code === 0
}

function proofArtifact(config, useReproducer = false) {
  const manifest = config.proof_files
    .map(({ path, contents }) => `${path}\0${sha256(contents)}`)
    .join('\n')
  return {
    path: useReproducer
      ? (config.reproducer?.path ?? config.proof_files[0].path)
      : config.proof_files[0].path,
    sha256: sha256(manifest),
  }
}

function serviceRemediationEvidence(remediation, config) {
  if (remediation === null || remediation === undefined) {
    return {
      status: 'NOT_ATTEMPTED',
      detail: 'no candidate patch was supplied',
    }
  }
  if (controlExitMatches(remediation, config)) {
    return {
      status: 'FIX_VERIFIED',
      detail: 'the sealed remediation command matched its declared exit class',
    }
  }
  return {
    status: 'FIX_FAILED',
    detail: 'the sealed remediation command did not match its declared exit class',
  }
}

function serviceFailureReason(code) {
  if (/^SERVICE_PROOF_PRE_BOOT_/.test(code)) {
    return 'the controller could not prove the loopback port was closed before service boot'
  }
  if (/^SERVICE_PROOF_STARTUP_/.test(code)) {
    return 'the controller could not establish loopback TCP readiness within the startup bound'
  }
  if (/^SERVICE_PROOF_POST_PROBE_/.test(code)) {
    return 'the controller could not re-establish loopback service readiness after the proof probe'
  }
  if (/^SERVICE_PROOF_CLEANUP_/.test(code)) {
    return 'the controller could not verify cleanup of the disposable service container'
  }
  return 'the controller stopped the local-service lifecycle before T2 proof completed'
}

function serviceUnproven(config, context, blockingReason) {
  const caveats = caveatsFor(config, context)
  return {
    proof_tier: 'T0',
    verification_status: 'UNPROVEN',
    artifact: proofArtifact(config, true),
    remediation: serviceRemediationEvidence(null, config),
    blocking_reason: [blockingReason, ...caveats].join('; '),
  }
}

export function serviceProofFailureEvidence(error, config, context = {}) {
  const code = typeof error?.code === 'string' ? error.code : ''
  const cleanupVerified = error?.evidence?.cleanup_verified === true
    || error?.cleanup_verified === true
  if (!/^SERVICE_PROOF_[A-Z0-9_]+$/.test(code) || !cleanupVerified) {
    return serviceUnproven(
      config,
      context,
      'the service failure lacked a controller-trusted, cleanup-verified lifecycle record',
    )
  }
  return serviceUnproven(config, context, serviceFailureReason(code))
}

function expectedServiceWorker(context) {
  const worker = context?.proofWorker
  if (
    worker === null
    || typeof worker !== 'object'
    || Array.isArray(worker)
    || !isSha256Hex(worker.config_sha256)
    || !isSha256Image(worker.image)
    || !Number.isSafeInteger(worker.wall_time_ms)
    || worker.wall_time_ms < 1_000
    || worker.wall_time_ms > 3_600_000
    || !Number.isSafeInteger(worker.controller_session_budget_ms)
    || !Number.isSafeInteger(worker.controller_active_budget_ms)
    || !Number.isSafeInteger(worker.controller_cleanup_reserve_ms)
    || worker.controller_active_budget_ms < worker.wall_time_ms
    || worker.controller_cleanup_reserve_ms < 1_000
    || worker.controller_session_budget_ms
      !== worker.controller_active_budget_ms + worker.controller_cleanup_reserve_ms
    || worker.controller_session_budget_ms > 6_720_000
  ) {
    return null
  }
  return worker
}

function expectedProofWorktreeSha256(context) {
  return isSha256Hex(context?.proofWorktreeSha256)
    ? context.proofWorktreeSha256
    : null
}

function serviceExecutionProblem(result, config, label) {
  const incomplete = incompleteExecution(result, label)
  if (incomplete) return incomplete
  if (result.timed_out !== false || result.spawn_error !== false || result.signal !== null) {
    return `${label} service session did not record a complete terminal process state`
  }
  if (!Number.isSafeInteger(result.code) || result.code < 0 || result.code > 255) {
    return `${label} service session lacks complete exit metadata`
  }
  if (
    !Number.isSafeInteger(result.duration_ms)
    || result.duration_ms < 0
    || result.duration_ms > config.limits.timeout_ms
  ) {
    return `${label} service session lacks complete duration metadata`
  }
  if (
    result.output_omitted !== true
    || result.stdout !== ''
    || result.stderr !== ''
  ) {
    return `${label} service session did not preserve the raw-output boundary`
  }
  for (const stream of ['stdout', 'stderr']) {
    if (!Number.isSafeInteger(result[`${stream}_bytes`]) || result[`${stream}_bytes`] < 0) {
      return `${label} service session lacks complete ${stream} byte metadata`
    }
    if (!isSha256Hex(result[`${stream}_sha256`])) {
      return `${label} service session lacks complete ${stream} digest metadata`
    }
    if (
      (result[`${stream}_bytes`] === 0)
      !== (result[`${stream}_sha256`] === EMPTY_OUTPUT_SHA256)
    ) {
      return `${label} service session has inconsistent ${stream} byte and digest metadata`
    }
    if (result[`${stream}_truncated`] !== false) {
      return result[`${stream}_truncated`] === true
        ? `${label} exceeded its sealed output bound`
        : `${label} service session did not record ${stream} truncation state`
    }
  }
  if (result.stdout_bytes + result.stderr_bytes > config.limits.max_output_bytes) {
    return `${label} service session exceeded its sealed output-byte bound`
  }
  return null
}

function serviceSessionProblem(result, config, label, worker, proofWorktreeSha256) {
  if (result === null || typeof result !== 'object') {
    return `${label} service session was not observed`
  }
  const executionProblem = serviceExecutionProblem(result, config, label)
  if (executionProblem) return executionProblem
  const sandbox = result.sandbox
  if (sandbox === null || typeof sandbox !== 'object') {
    return `${label} service session lacks controller sandbox evidence`
  }
  if (sandbox.backend !== 'OCI_DOCKER') {
    return `${label} service session did not use the Docker proof backend`
  }
  if (!isSha256Hex(sandbox.worker_config_sha256)) {
    return `${label} service session lacks an immutable worker binding`
  }
  if (!isSha256Image(sandbox.image)) {
    return `${label} service session lacks an immutable image binding`
  }
  if (
    sandbox.worker_config_sha256 !== worker.config_sha256
    || sandbox.image !== worker.image
  ) {
    return `${label} service session did not match the controller-selected receipt worker`
  }
  if (!isSha256Hex(sandbox.container_id)) {
    return `${label} service session lacks an exact container identity`
  }
  if (sandbox.network_mode !== 'none') {
    return `${label} service session was not network-none`
  }
  if (!Array.isArray(sandbox.mounts) || sandbox.mounts.length !== 0) {
    return `${label} service session used a host mount`
  }
  if (sandbox.environment !== 'controller-minimal') {
    return `${label} service session did not use the controller-minimal environment`
  }
  if (sandbox.cleanup_verified !== true) {
    return `${label} service session cleanup was not verified`
  }
  const service = sandbox.service
  if (
    service?.protocol !== 'loopback-tcp-v1'
    || service?.host !== '127.0.0.1'
    || service?.port !== config.service.port
  ) {
    return `${label} service session did not bind the configured loopback service`
  }
  if (service.supervisor_ttl_ms !== worker.wall_time_ms) {
    return `${label} service supervisor TTL did not match the controller-selected worker wall time`
  }
  if (
    service.controller_session_budget_ms !== worker.controller_session_budget_ms
    || service.controller_active_budget_ms !== worker.controller_active_budget_ms
    || service.controller_cleanup_reserve_ms !== worker.controller_cleanup_reserve_ms
  ) {
    return `${label} service session did not match the cumulative controller deadline`
  }
  if (service.pre_boot_closed !== true) {
    return `${label} service session did not prove the port closed before boot`
  }
  if (service.pre_probe_ready !== true) {
    return `${label} service session was not ready before the proof probe`
  }
  if (service.post_probe_ready !== true) {
    return `${label} service session was not ready after the proof probe`
  }
  if (service.output_omitted !== true) {
    return `${label} service lifecycle did not preserve nested raw-output omission`
  }
  if (service.source_immutable !== true) {
    return `${label} service session did not prove the copied source immutable`
  }
  if (
    !isSha256Hex(service.source_tree_sha256)
    || service.source_tree_sha256 !== proofWorktreeSha256
  ) {
    return `${label} service session did not match the controller-computed proof worktree digest`
  }
  if (service.runtime_root !== '/work/runtime') {
    return `${label} service session did not confine target writes to the fixed runtime scratch root`
  }
  return null
}

function serviceProofEvidence(outcome, config, context = {}) {
  if (outcome?.failure) {
    return serviceProofFailureEvidence({
      code: outcome.failure.code,
      cleanup_verified: outcome.failure.cleanup_verified,
    }, config, context)
  }
  const worker = expectedServiceWorker(context)
  if (!worker) {
    return serviceUnproven(
      config,
      context,
      'the controller-selected receipt worker binding was missing or invalid',
    )
  }
  const proofWorktreeSha256 = expectedProofWorktreeSha256(context)
  if (!proofWorktreeSha256) {
    return serviceUnproven(
      config,
      context,
      'the controller-computed proof worktree digest was missing or invalid',
    )
  }
  const demonstrationProblem = serviceSessionProblem(
    outcome?.demonstration,
    config,
    'attack',
    worker,
    proofWorktreeSha256,
  )
  if (demonstrationProblem) return serviceUnproven(config, context, demonstrationProblem)
  const controlProblem = serviceSessionProblem(
    outcome?.control,
    config,
    'control',
    worker,
    proofWorktreeSha256,
  )
  if (controlProblem) return serviceUnproven(config, context, controlProblem)

  const attackSandbox = outcome.demonstration.sandbox
  const controlSandbox = outcome.control.sandbox
  if (attackSandbox.container_id === controlSandbox.container_id) {
    return serviceUnproven(
      config,
      context,
      'attack and control did not use independent fresh service containers',
    )
  }
  if (
    attackSandbox.worker_config_sha256 !== controlSandbox.worker_config_sha256
    || attackSandbox.image !== controlSandbox.image
  ) {
    return serviceUnproven(
      config,
      context,
      'attack and control service sessions did not share one immutable worker binding',
    )
  }

  const base = {
    proof_tier: 'T2',
    command: 'controller-sealed T2 service differential',
    artifact: proofArtifact(config, true),
  }
  const caveats = caveatsFor(config, context)
  const withCaveats = (text) => [text, ...caveats].join('; ')
  const attackIncomplete = incompleteExecution(outcome.demonstration, 'the demonstration')
  if (
    attackIncomplete
    || outcome.demonstration.stdout_truncated === true
    || outcome.demonstration.stderr_truncated === true
  ) {
    return serviceUnproven(
      config,
      context,
      attackIncomplete ?? 'the demonstration exceeded its sealed output bound',
    )
  }
  const controlIncomplete = incompleteExecution(outcome.control, 'the explicit control')
  if (
    controlIncomplete
    || outcome.control.stdout_truncated === true
    || outcome.control.stderr_truncated === true
  ) {
    return serviceUnproven(
      config,
      context,
      controlIncomplete ?? 'the explicit control exceeded its sealed output bound',
    )
  }

  const remediation = serviceRemediationEvidence(outcome.remediation, config)
  const controlPassed = controlExitMatches(outcome.control, config)
  const attackMatched = attackExitMatches(outcome.demonstration, config)
  const attackWasControlClass = config.oracle.control_exit_codes
    .includes(outcome.demonstration.code)
  if (!controlPassed) {
    return {
      ...base,
      verification_status: 'INCONCLUSIVE',
      remediation,
      reason: withCaveats(
        'the explicit control did not match its sealed exit class, so the oracle is invalid',
      ),
    }
  }
  if (!attackMatched) {
    if (!attackWasControlClass) {
      return {
        ...base,
        verification_status: 'INCONCLUSIVE',
        remediation,
        reason: withCaveats(
          'the demonstration exit code was not declared by the v3 oracle',
        ),
      }
    }
    return {
      ...base,
      verification_status: 'UNPROVEN',
      pre_result: {
        assertion: 'the demonstration matched the provider-declared non-attack exit class',
        path_reached: config.reproducer.path,
        control: 'the independent control session matched the provider-declared control exit class',
        control_status: 'passed',
        ...(caveats.length > 0 ? { detail: caveats.join('; ') } : {}),
      },
      blocking_reason: withCaveats(
        'controller observed the declared non-attack/control exit result, but no controller-authenticated semantic oracle is enrolled to clear the finding',
      ),
      remediation,
    }
  }

  return {
    ...base,
    verification_status: 'UNPROVEN',
    pre_result: {
      assertion: 'the demonstration matched the provider-declared attack exit class',
      path_reached: config.reproducer.path,
      control: 'the independent control session matched the provider-declared control exit class',
      control_status: 'passed',
      ...(caveats.length > 0 ? { detail: caveats.join('; ') } : {}),
    },
    blocking_reason: withCaveats(
      'controller observed the declared attack/control exit differential, but no controller-authenticated semantic oracle is enrolled',
    ),
    remediation,
  }
}

function remediationEvidence(remediation, config) {
  if (remediation === null || remediation === undefined) {
    return {
      status: 'NOT_ATTEMPTED',
      detail: 'no candidate patch was supplied',
    }
  }
  if (controlExitMatches(remediation, config)) {
    return {
      status: 'FIX_VERIFIED',
      detail: truncated(remediation.stdout || remediation.stderr),
    }
  }
  return {
    status: 'FIX_FAILED',
    detail: truncated(remediation.stdout || remediation.stderr),
  }
}

function incompleteExecution(result, label) {
  if (result?.timed_out === true) return `${label} timed out before producing an oracle result`
  if (result?.spawn_error === true) return `${label} could not start`
  if (typeof result?.signal === 'string' && result.signal.length > 0) {
    return `${label} terminated by signal ${result.signal}`
  }
  return null
}

export function proofEvidence(outcome, config, context) {
  if (config?.schema_version === '3.0.0') {
    return serviceProofEvidence(outcome, config, context)
  }
  const { demonstration, remediation, control } = outcome
  const base = {
    proof_tier: 'T1',
    command: 'controller-sealed T1 proof command',
    artifact: proofArtifact(config),
  }
  const caveats = caveatsFor(config, context)
  const withCaveats = (text) => [text, ...caveats].join('; ')

  const demonstrationIncomplete = incompleteExecution(demonstration, 'the demonstration')
  if (demonstrationIncomplete !== null) {
    return {
      ...base,
      verification_status: 'INCONCLUSIVE',
      remediation: remediationEvidence(remediation, config),
      reason: withCaveats(
        `${demonstrationIncomplete}: ${truncated(demonstration.stdout || demonstration.stderr)}`,
      ),
    }
  }

  // Version 2 binds the oracle's exact attack/control exit classes. Legacy
  // proof configurations retain the historical nonzero/zero convention.
  if (!attackExitMatches(demonstration, config)) {
    if (
      isVersionedOracle(config)
      && !config.oracle.control_exit_codes.includes(demonstration.code)
    ) {
      return {
        ...base,
        verification_status: 'INCONCLUSIVE',
        remediation: remediationEvidence(remediation, config),
        reason: withCaveats(
          `demonstration exit code ${demonstration.code} was not declared by the v2 oracle: ${truncated(demonstration.stdout || demonstration.stderr)}`,
        ),
      }
    }
    return {
      ...base,
      verification_status: 'NOT_REPRODUCED',
      reason: withCaveats(
        `the demonstration passed against the unmodified target: ${truncated(demonstration.stdout)}`,
      ),
    }
  }

  const preResult = {
    assertion: truncated(demonstration.stdout || demonstration.stderr),
    path_reached: config.proof_files[0].path,
    control: control === undefined
      ? config.proof_files.length > 1
        ? config.proof_files[1].path
        : 'the unmodified target'
      : truncated(control.stdout || control.stderr),
    ...(control === undefined
      ? {}
      : { control_status: controlExitMatches(control, config) ? 'passed' : 'failed' }),
    ...(caveats.length > 0 ? { detail: caveats.join('; ') } : {}),
  }

  const remediationResult = remediationEvidence(remediation, config)

  if (control !== undefined) {
    const controlIncomplete = incompleteExecution(control, 'the explicit control')
    if (controlIncomplete !== null) {
      return {
        ...base,
        verification_status: 'INCONCLUSIVE',
        pre_result: preResult,
        remediation: remediationResult,
        reason: withCaveats(
          `${controlIncomplete}: ${truncated(control.stdout || control.stderr)}`,
        ),
      }
    }
    if (!controlExitMatches(control, config)) {
      return {
        ...base,
        verification_status: 'INCONCLUSIVE',
        pre_result: preResult,
        remediation: remediationResult,
        reason: withCaveats(
          `the explicit control failed, so the attack oracle is invalid: ${truncated(control.stdout || control.stderr)}`,
        ),
      }
    }
    return {
      ...base,
      verification_status: 'CONFIRMED',
      pre_result: preResult,
      remediation: remediationResult,
    }
  }

  if (remediation === null || remediation === undefined) {
    return {
      ...base,
      verification_status: 'UNPROVEN',
      pre_result: preResult,
      remediation: remediationResult,
      blocking_reason: withCaveats(
        'the attack was reproduced, but no explicit control validated the oracle and no passing legacy patch result exists',
      ),
    }
  }

  const remediationPassed = controlExitMatches(remediation, config)
  const postResult = {
    status: remediationPassed ? 'passed' : 'failed',
    regressions: remediationPassed
      ? 'none observed in the project suite'
      : truncated(remediation.stdout || remediation.stderr),
    ...(caveats.length > 0 ? { detail: caveats.join('; ') } : {}),
  }

  if (postResult.status === 'failed') {
    return {
      ...base,
      verification_status: 'INCONCLUSIVE',
      pre_result: preResult,
      post_result: postResult,
      remediation: remediationResult,
      reason: withCaveats('the candidate patch did not leave the project suite green'),
    }
  }

  return {
    ...base,
    verification_status: 'CONFIRMED',
    pre_result: preResult,
    post_result: postResult,
    remediation: remediationResult,
  }
}
