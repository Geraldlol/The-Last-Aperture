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
    stdout_bytes: Buffer.byteLength(stdout, 'utf8'),
    stdout_sha256: sha256(stdout),
    stdout_truncated: result.stdout_truncated === true,
    stderr_bytes: Buffer.byteLength(stderr, 'utf8'),
    stderr_sha256: sha256(stderr),
    stderr_truncated: result.stderr_truncated === true,
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
    },
    proof_configuration: {
      schema_version: config.schema_version,
      sha256: sha256(stableJson(config, 0)),
      command: config.command,
      ...(config.control_command ? { control_command: config.control_command } : {}),
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
    outcome: {
      demonstration: proofProcessObservation(outcome.demonstration),
      control: proofProcessObservation(outcome.control),
      remediation: proofProcessObservation(outcome.remediation),
      owned_paths: outcome.ownedPaths,
      rule_six_applicable: ruleSixApplicable,
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
