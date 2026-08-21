// CVSS v3.1 base score, implemented from the specification's formulas so a
// report can carry a vector a triager can recompute. Only the base metrics:
// temporal and environmental scoring are the program's business, not ours.

const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }
const AC = { L: 0.77, H: 0.44 }
const PR_UNCHANGED = { N: 0.85, L: 0.62, H: 0.27 }
// Privileges Required is weighted higher when the scope changes, because
// escaping a security boundary with low privilege is worth more.
const PR_CHANGED = { N: 0.85, L: 0.68, H: 0.50 }
const UI = { N: 0.85, R: 0.62 }
const CIA = { H: 0.56, L: 0.22, N: 0 }

export const CVSS_METRIC_ORDER = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']

// CVSS 3.1 Appendix A: round up to one decimal, with the integer-arithmetic
// definition that avoids floating point surprises.
export function cvssRoundUp(input) {
  const scaled = Math.round(input * 100000)
  if (scaled % 10000 === 0) return scaled / 100000
  return (Math.floor(scaled / 10000) + 1) / 10
}

function requireMetric(table, value, name) {
  if (!Object.hasOwn(table, value)) {
    throw new Error(`CVSS metric ${name} has no value ${value}`)
  }
  return table[value]
}

export function cvssBaseScore(metrics) {
  const scopeChanged = metrics.S === 'C'
  if (metrics.S !== 'C' && metrics.S !== 'U') {
    throw new Error(`CVSS metric S has no value ${metrics.S}`)
  }
  const confidentiality = requireMetric(CIA, metrics.C, 'C')
  const integrity = requireMetric(CIA, metrics.I, 'I')
  const availability = requireMetric(CIA, metrics.A, 'A')

  const iss = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability))
  const impact = scopeChanged
    ? (7.52 * (iss - 0.029)) - (3.25 * ((iss - 0.02) ** 15))
    : 6.42 * iss
  if (impact <= 0) return 0

  const exploitability = 8.22
    * requireMetric(AV, metrics.AV, 'AV')
    * requireMetric(AC, metrics.AC, 'AC')
    * requireMetric(scopeChanged ? PR_CHANGED : PR_UNCHANGED, metrics.PR, 'PR')
    * requireMetric(UI, metrics.UI, 'UI')

  const combined = impact + exploitability
  return cvssRoundUp(Math.min(scopeChanged ? combined * 1.08 : combined, 10))
}

export function cvssVectorString(metrics) {
  return `CVSS:3.1/${CVSS_METRIC_ORDER.map((key) => `${key}:${metrics[key]}`).join('/')}`
}

export function cvssSeverityBand(score) {
  if (score === 0) return 'None'
  if (score < 4) return 'Low'
  if (score < 7) return 'Medium'
  if (score < 9) return 'High'
  return 'Critical'
}

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

// Derives a SUGGESTED vector with a stated reason per metric. Suggested, not
// asserted: severity is a judgment the operator signs their name to, and a
// generator that quietly inflates it is worse than one that offers nothing.
export function suggestAuthzVector({ testerRole, method, ownerStatus }) {
  const anonymous = testerRole === 'anonymous'
  const mutating = MUTATING_METHODS.has(String(method).toUpperCase())
  const metrics = {
    AV: 'N',
    AC: 'L',
    PR: anonymous ? 'N' : 'L',
    UI: 'N',
    S: 'U',
    C: 'H',
    // Deliberately N even for a mutating method: the grinder compared responses,
    // it did not prove a write landed. Claiming integrity impact on that evidence
    // would be an overclaim, so it is flagged for confirmation instead.
    I: 'N',
    A: 'N',
  }
  const rationale = [
    'AV:N — reachable over the network',
    'AC:L — a single direct request, no special conditions',
    anonymous
      ? 'PR:N — an unauthenticated caller received the data'
      : 'PR:L — an authenticated account with no entitlement to this object received it',
    'UI:N — no victim interaction required',
    'S:U — impact confined to the vulnerable component',
    `C:H — the response was byte-equivalent to the owner's (owner status ${ownerStatus}), so another principal's data was disclosed`,
    'I:N — response comparison does not prove a write; confirm before claiming integrity impact',
    'A:N — no availability impact observed',
  ]
  const caveats = []
  if (mutating) {
    caveats.push(
      `This is a ${String(method).toUpperCase()} request. If it mutates state, integrity impact may be higher than I:N — verify the write actually occurred before raising it.`,
    )
  }
  const score = cvssBaseScore(metrics)
  return {
    metrics,
    vector: cvssVectorString(metrics),
    score,
    band: cvssSeverityBand(score),
    rationale,
    caveats,
    assessment: 'SUGGESTED_REQUIRES_OPERATOR_REVIEW',
  }
}
