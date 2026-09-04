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

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
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

function isV2Oracle(config) {
  return config?.schema_version === '2.0.0'
    && Array.isArray(config?.oracle?.attack_exit_codes)
    && Array.isArray(config?.oracle?.control_exit_codes)
}

function attackExitMatches(result, config) {
  return isV2Oracle(config)
    ? config.oracle.attack_exit_codes.includes(result?.code)
    : result?.code !== 0
}

function controlExitMatches(result, config) {
  return isV2Oracle(config)
    ? config.oracle.control_exit_codes.includes(result?.code)
    : result?.code === 0
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
  const { demonstration, remediation, control } = outcome
  const manifest = config.proof_files
    .map(({ path, contents }) => `${path}\0${sha256(contents)}`)
    .join('\n')
  const base = {
    proof_tier: 'T1',
    command: `${config.command.program} ${config.command.args.join(' ')}`.trim(),
    artifact: {
      path: config.proof_files[0].path,
      sha256: sha256(manifest),
    },
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
      isV2Oracle(config)
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
