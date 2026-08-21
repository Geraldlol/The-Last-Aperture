import { responseDigest } from './bounty-authz-normalize.mjs'

// No verdict here asserts a vulnerability or a clean bill of health. The
// strongest is a CANDIDATE, which a human must prove before submission, and the
// weakest says only what was observed for one request under one role.
export const AUTHZ_VERDICTS = Object.freeze([
  'AUTHZ_BYPASS_CANDIDATE',
  'UNPROVEN_VOLATILE',
  'ACCESS_DENIED',
  'NOT_FOUND',
  'DIFFERENT_CONTENT',
  'SERVER_ERROR',
  'REPLAY_FAILED',
])

// Replay the request twice as its owning role. Anything that differs between two
// identical-role runs is volatile by definition, so this establishes the noise
// floor before any cross-role claim is made. When the floor cannot be
// established, that is reported rather than assumed away.
export function calibrateBaseline({ first, second }) {
  if (first?.error || second?.error) {
    return { stable: false, digest: null, reason: 'baseline-replay-failed' }
  }
  if (first?.status !== second?.status) {
    return { stable: false, digest: null, reason: 'baseline-status-differs' }
  }
  const firstDigest = responseDigest(first.normalized)
  const secondDigest = responseDigest(second.normalized)
  if (firstDigest !== secondDigest) {
    return { stable: false, digest: firstDigest, reason: 'baseline-body-differs' }
  }
  return { stable: true, digest: firstDigest, reason: 'baseline-reproducible' }
}

export function classifyAuthzOutcome({ baseline, testerResponse, testerRole }) {
  const role = testerRole?.id ?? 'unknown'

  if (testerResponse?.error) {
    return {
      verdict: 'REPLAY_FAILED',
      confidence: 'none',
      rationale: `replay as ${role} did not complete: ${testerResponse.error}`,
    }
  }

  const status = testerResponse.status
  if (status === 401 || status === 403) {
    return {
      verdict: 'ACCESS_DENIED',
      confidence: 'high',
      rationale: `${role} received ${status}; this request was refused for this role`,
    }
  }
  if (status === 404) {
    return {
      verdict: 'NOT_FOUND',
      confidence: 'low',
      rationale: `${role} received 404, which may be correct scoping or an existence oracle`,
    }
  }
  if (status >= 500) {
    return {
      verdict: 'SERVER_ERROR',
      confidence: 'low',
      rationale: `${role} triggered ${status}; an unexpected role reaching a handler is worth reading`,
    }
  }

  // Everything below compares content, so an unstable baseline poisons all of it.
  // A non-match is no more meaningful than a match when the owner's own two
  // replays disagreed: the difference may be nothing but volatility. Checking the
  // match first and only then the baseline would confidently report per-role
  // scoping on an endpoint that simply changes every call.
  //
  // The status branches above are unaffected: a 403 means the same thing whether
  // or not the body is stable.
  if (!baseline.stable) {
    return {
      verdict: 'UNPROVEN_VOLATILE',
      confidence: 'low',
      rationale: `${role} received ${status}, but the owner's own two replays differed (${baseline.reason}), so no content comparison here can support a claim in either direction`,
    }
  }

  const testerDigest = responseDigest(testerResponse.normalized)
  if (testerDigest !== baseline.digest) {
    // The most common correct outcome, and the biggest source of noise if
    // mistaken for a finding: on /api/me, another role legitimately receives its
    // own profile with a 200.
    return {
      verdict: 'DIFFERENT_CONTENT',
      confidence: 'high',
      rationale: `${role} received ${status} with content differing from the owner's, consistent with per-role scoping`,
    }
  }

  return {
    verdict: 'AUTHZ_BYPASS_CANDIDATE',
    confidence: 'high',
    rationale: `${role} received ${status} byte-equivalent to the owner's response after normalization, and the owner's baseline was reproducible`,
  }
}

export function summarizeMatrix(results) {
  const byVerdict = {}
  for (const verdict of AUTHZ_VERDICTS) byVerdict[verdict] = 0
  for (const result of results) {
    if (Object.hasOwn(byVerdict, result.verdict)) byVerdict[result.verdict] += 1
  }
  return {
    total: results.length,
    byVerdict,
    // Reported separately and never summed: a volatile endpoint must not be able
    // to inflate the candidate count.
    candidates: byVerdict.AUTHZ_BYPASS_CANDIDATE,
    unproven: byVerdict.UNPROVEN_VOLATILE,
  }
}
