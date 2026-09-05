import { createHash } from 'node:crypto'
import { stableJson } from './run-engine.mjs'

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function proofFileManifest(files = []) {
  return files.map(({ path, contents }) => ({
    path,
    sha256: sha256(contents),
    bytes: Buffer.byteLength(contents, 'utf8'),
  }))
}

function commandObservation(command) {
  return {
    program: command.program,
    args_count: command.args.length,
    args_sha256: sha256(stableJson(command.args, 0)),
  }
}

function serviceConfigurationObservation(service) {
  return {
    protocol: service.protocol,
    command: commandObservation(service.command),
    port: service.port,
    startup_timeout_ms: service.startup_timeout_ms,
    probe_interval_ms: service.probe_interval_ms,
  }
}

function serviceSandboxObservation(service) {
  if (service === null || typeof service !== 'object' || Array.isArray(service)) {
    return null
  }
  return {
    protocol: service.protocol,
    host: service.host,
    port: service.port,
    supervisor_ttl_ms: service.supervisor_ttl_ms,
    controller_session_budget_ms: service.controller_session_budget_ms,
    controller_active_budget_ms: service.controller_active_budget_ms,
    controller_cleanup_reserve_ms: service.controller_cleanup_reserve_ms,
    pre_boot_closed: service.pre_boot_closed,
    pre_probe_ready: service.pre_probe_ready,
    post_probe_ready: service.post_probe_ready,
    source_immutable: service.source_immutable,
    source_tree_sha256: service.source_tree_sha256,
    runtime_root: service.runtime_root,
    output_omitted: service.output_omitted,
  }
}

export function serviceProofAttemptReceiptBinding(attempt) {
  if (attempt === null || typeof attempt !== 'object' || Array.isArray(attempt)) {
    return null
  }
  const lease = attempt.lease
  if (lease === null || typeof lease !== 'object' || Array.isArray(lease)) {
    return null
  }
  return {
    backend: lease.backend,
    attempt_id: attempt.attempt_id,
    attempt_nonce: lease.nonce,
    lease_event_sha256: lease.event_sha256,
    packet_sha256: lease.packet_sha256,
    proof_config_sha256: lease.proof_config_sha256,
    proof_worker_config_sha256: lease.proof_worker_config_sha256,
    service_container_names: structuredClone(lease.service_container_names),
    service_session_budget: structuredClone(lease.service_session_budget),
  }
}

function proofSandboxObservation(sandbox) {
  const observation = {
    backend: sandbox.backend,
    worker_config_sha256: sandbox.worker_config_sha256,
    runtime_version: sandbox.runtime_version,
    image: sandbox.image,
    container_id: sandbox.container_id,
    network_mode: sandbox.network_mode,
    mounts: Array.isArray(sandbox.mounts) ? structuredClone(sandbox.mounts) : sandbox.mounts,
    environment: sandbox.environment,
    cleanup_verified: sandbox.cleanup_verified,
  }
  if (sandbox.service !== undefined) {
    observation.service = serviceSandboxObservation(sandbox.service)
  }
  return observation
}

function proofProcessObservation(result) {
  if (result === null || result === undefined) return null
  const stdout = String(result.stdout ?? '')
  const stderr = String(result.stderr ?? '')
  return {
    code: result.code,
    signal: result.signal ?? null,
    timed_out: result.timed_out === true,
    spawn_error: result.spawn_error === true,
    duration_ms: Number.isSafeInteger(result.duration_ms) && result.duration_ms >= 0
      ? result.duration_ms
      : null,
    stdout_bytes: Number.isSafeInteger(result.stdout_bytes)
      ? result.stdout_bytes
      : Buffer.byteLength(stdout, 'utf8'),
    stdout_sha256: result.stdout_sha256 ?? sha256(stdout),
    stdout_truncated: result.stdout_truncated === true,
    stderr_bytes: Number.isSafeInteger(result.stderr_bytes)
      ? result.stderr_bytes
      : Buffer.byteLength(stderr, 'utf8'),
    stderr_sha256: result.stderr_sha256 ?? sha256(stderr),
    stderr_truncated: result.stderr_truncated === true,
    ...(result.output_omitted === true ? { output_omitted: true } : {}),
    ...(result.sandbox ? { sandbox: proofSandboxObservation(result.sandbox) } : {}),
  }
}

function proofFailureObservation(failure) {
  if (failure === null || failure === undefined) return null
  return {
    code: failure.code,
    lifecycle_phase: failure.lifecycle_phase,
    cleanup_verified: failure.cleanup_verified === true,
  }
}

export function buildProofReceipt({
  run,
  job,
  config,
  packetSha256,
  outcome,
  evidence,
  ruleSixApplicable,
  proofWorker,
  proofWorktreeSha256,
  serviceProofAttempt,
}) {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/proof-receipt',
    run_id: run.run_id,
    job_id: job.job_id,
    candidate_id: job.candidate_ids[0],
    input_sha256: packetSha256,
    repository_snapshot: {
      tree_digest: run.repository.tree_digest,
      source_snapshot_sha256: run.source_snapshot.root_sha256,
      plan_digest: run.plan_digest,
      policy_digest: run.policy_digest,
      lens_pack_digest: run.lens_pack_digest,
      ...(proofWorktreeSha256
        ? { proof_worktree_sha256: proofWorktreeSha256 }
        : {}),
    },
    proof_configuration: {
      schema_version: config.schema_version,
      sha256: sha256(stableJson(config, 0)),
      command: commandObservation(config.command),
      ...(config.control_command
        ? { control_command: commandObservation(config.control_command) }
        : {}),
      ...(config.service
        ? { service: serviceConfigurationObservation(config.service) }
        : {}),
      proof_files: proofFileManifest(config.proof_files),
      ...(config.patch_files
        ? { patch_files: proofFileManifest(config.patch_files) }
        : {}),
      destination_guard: config.destination_guard,
      ...(config.strategy ? { strategy: config.strategy } : {}),
      ...(config.oracle ? { oracle: config.oracle } : {}),
      ...(config.limits ? { limits: config.limits } : {}),
      ...(config.reproducer ? { reproducer: config.reproducer } : {}),
    },
    ...(proofWorker ? { proof_worker: structuredClone(proofWorker) } : {}),
    ...(serviceProofAttempt
      ? { execution_attempt: serviceProofAttemptReceiptBinding(serviceProofAttempt) }
      : {}),
    outcome: {
      demonstration: proofProcessObservation(outcome.demonstration),
      control: proofProcessObservation(outcome.control),
      remediation: proofProcessObservation(outcome.remediation),
      owned_paths: outcome.ownedPaths,
      rule_six_applicable: ruleSixApplicable,
      ...(outcome.failure
        ? { failure: proofFailureObservation(outcome.failure) }
        : {}),
    },
    evidence,
  }
}

export function findingWithProofEvidence(finding, evidence) {
  const next = { ...finding, ...evidence }
  if (
    ['UNPROVEN', 'INCONCLUSIVE'].includes(evidence.verification_status)
    && ['Critical', 'High'].includes(next.effective_severity)
  ) {
    next.effective_severity = 'Medium'
  }
  return next
}
