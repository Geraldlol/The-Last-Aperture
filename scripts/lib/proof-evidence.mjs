/**
 * Maps a proof outcome onto the finding's evidence fields.
 *
 * CONFIRMED is not "the bug is real". finding.schema.json requires artifact,
 * command, pre_result and post_result with post_result.status 'passed', so a
 * finding confirms only once a candidate fix ran green. A bug demonstrated and
 * left unfixed rests at UNPROVEN, which caps at Medium — the honest state, and
 * a common one.
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

export function proofEvidence(outcome, config, context) {
  const { demonstration, remediation } = outcome
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

  // The demonstration must fail against the unmodified mirror. One that passes
  // there did not reproduce the bug it claims.
  if (demonstration.code === 0) {
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
    control: config.proof_files.length > 1
      ? config.proof_files[1].path
      : 'the unmodified target',
    ...(caveats.length > 0 ? { detail: caveats.join('; ') } : {}),
  }

  if (remediation === null) {
    return {
      ...base,
      verification_status: 'UNPROVEN',
      pre_result: preResult,
      blocking_reason: withCaveats(
        'the bug was demonstrated but no candidate patch was supplied, so no post-fix result exists',
      ),
    }
  }

  const postResult = {
    status: remediation.code === 0 ? 'passed' : 'failed',
    regressions: remediation.code === 0
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
      reason: withCaveats('the candidate patch did not leave the project suite green'),
    }
  }

  return {
    ...base,
    verification_status: 'CONFIRMED',
    pre_result: preResult,
    post_result: postResult,
  }
}
