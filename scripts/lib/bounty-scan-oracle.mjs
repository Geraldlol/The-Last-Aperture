import { scanResponseBody } from './bounty-scan-passive.mjs'
import { responseDigest } from './bounty-authz-normalize.mjs'

// An active scanner is only as trustworthy as its oracle. Three are used here,
// and every one of them is designed to say "inconclusive" rather than guess.

export const SCAN_VERDICTS = Object.freeze([
  'INJECTION_ERROR_CANDIDATE',
  'DIFFERENTIAL_CANDIDATE',
  'OOB_INTERACTION_CANDIDATE',
  'NO_SIGNAL',
  'UNPROVEN_VOLATILE',
  'PROBE_FAILED',
])

// Payload classes that provoke a parser error when input reaches an interpreter.
// A returned error is strong evidence of injection reach -- far stronger than a
// content diff -- because a benign application has no reason to leak one.
export const ERROR_PROBES = Object.freeze([
  { id: 'single-quote', payload: "'", mode: 'append' },
  { id: 'double-quote', payload: '"', mode: 'append' },
  { id: 'backslash', payload: '\\', mode: 'append' },
  { id: 'sql-comment', payload: "'--", mode: 'append' },
  { id: 'brace', payload: '{{', mode: 'append' },
])

// The control is the whole point. It is the same *shape* of change as the probe
// but semantically inert, so if the control also moves the response the endpoint
// is simply noisy and no diff from it can mean anything.
export const CONTROL_PROBES = Object.freeze([
  { id: 'benign-suffix', payload: 'zq', mode: 'append' },
])

export function detectErrorSignature(body) {
  const observations = scanResponseBody(body).filter((o) => o.kind === 'verbose-error')
  return observations.length === 0
    ? null
    : { ruleIds: observations.map((o) => o.rule_id), labels: observations.map((o) => o.label) }
}

function digestOf(response) {
  return response?.normalized === null || response?.normalized === undefined
    ? null
    : responseDigest(response.normalized)
}

// baseline: two untouched requests, establishing whether the endpoint is stable
// at all. Same self-calibration as the authz grinder, for the same reason.
export function calibrateProbeBaseline({ first, second }) {
  if (first?.error || second?.error) {
    return { stable: false, digest: null, reason: 'baseline-probe-failed' }
  }
  if (first.status !== second.status) {
    return { stable: false, digest: null, reason: 'baseline-status-differs' }
  }
  const firstDigest = digestOf(first)
  if (firstDigest !== digestOf(second)) {
    return { stable: false, digest: firstDigest, reason: 'baseline-body-differs' }
  }
  return { stable: true, digest: firstDigest, reason: 'baseline-reproducible' }
}

export function classifyProbe({ baseline, control, probe, insertionPoint, probeId }) {
  const where = insertionPoint === undefined ? 'the request' : `${insertionPoint.location}:${insertionPoint.pointer}`

  if (probe?.error) {
    return {
      verdict: 'PROBE_FAILED',
      confidence: 'none',
      rationale: `probe ${probeId} at ${where} did not complete: ${probe.error}`,
    }
  }

  // Checked before any diff reasoning: an error signature is meaningful even on a
  // volatile endpoint, because a stack trace is not noise.
  const signature = detectErrorSignature(probe.normalized?.normalizedBody ?? '')
  if (signature !== null) {
    const baselineSignature = detectErrorSignature(baseline?.normalizedBody ?? '')
    if (baselineSignature === null) {
      return {
        verdict: 'INJECTION_ERROR_CANDIDATE',
        confidence: 'high',
        rationale: `payload ${probeId} at ${where} provoked ${signature.labels.join(', ')} that the untouched request did not produce`,
        evidence: signature.ruleIds,
      }
    }
  }

  if (!baseline.stable) {
    return {
      verdict: 'UNPROVEN_VOLATILE',
      confidence: 'low',
      rationale: `the untouched request was not reproducible (${baseline.reason}), so no response comparison at ${where} can support a claim`,
    }
  }

  const controlDigest = digestOf(control)
  const probeDigest = digestOf(probe)

  if (controlDigest !== baseline.digest) {
    // The inert payload also moved the response, so this endpoint reacts to any
    // change and a diff proves nothing about the probe specifically.
    return {
      verdict: 'UNPROVEN_VOLATILE',
      confidence: 'low',
      rationale: `an inert control payload at ${where} also changed the response, so the endpoint reacts to any input change and no differential signal here is meaningful`,
    }
  }

  if (probeDigest !== baseline.digest) {
    return {
      verdict: 'DIFFERENTIAL_CANDIDATE',
      confidence: 'medium',
      rationale: `payload ${probeId} at ${where} changed the response while an inert control payload did not, indicating the value reaches logic that interprets it`,
    }
  }

  return {
    verdict: 'NO_SIGNAL',
    confidence: 'high',
    rationale: `payload ${probeId} at ${where} produced no observable difference`,
  }
}

// Blind classes have no in-band oracle at all: the only evidence is a callback.
// Absence of one is inconclusive, never a clearance.
export function classifyOobProbe({ interactions, nonce, insertionPoint, probeId }) {
  const where = `${insertionPoint.location}:${insertionPoint.pointer}`
  const matched = interactions.filter((entry) => entry.matched === true && entry.nonce === nonce)
  if (matched.length === 0) {
    return {
      verdict: 'NO_SIGNAL',
      confidence: 'low',
      rationale: `no out-of-band interaction was observed for ${probeId} at ${where}; a blind vector without a callback is inconclusive, not negative`,
    }
  }
  const protocols = [...new Set(matched.map((entry) => entry.interaction?.protocol).filter(Boolean))]
  return {
    verdict: 'OOB_INTERACTION_CANDIDATE',
    confidence: 'high',
    rationale: `${matched.length} out-of-band ${protocols.join('/')} interaction(s) correlated to payload ${probeId} at ${where}, so the target fetched a host it was given`,
    evidence: matched.map((entry) => entry.interaction?.remoteAddress).filter(Boolean),
  }
}

export function summarizeScan(results) {
  const byVerdict = {}
  for (const verdict of SCAN_VERDICTS) byVerdict[verdict] = 0
  for (const result of results) {
    if (Object.hasOwn(byVerdict, result.verdict)) byVerdict[result.verdict] += 1
  }
  return {
    total: results.length,
    byVerdict,
    candidates: byVerdict.INJECTION_ERROR_CANDIDATE
      + byVerdict.DIFFERENTIAL_CANDIDATE
      + byVerdict.OOB_INTERACTION_CANDIDATE,
    unproven: byVerdict.UNPROVEN_VOLATILE,
  }
}
