import { SCOPE_ALLOW, decideScope } from './bounty-scope-kernel.mjs'

const APPROVAL_BRAND = '__scopeApproved'

const DEFAULT_PORT = 443

function buildUrl(host, port) {
  return port === DEFAULT_PORT ? `https://${host}/` : `https://${host}:${port}/`
}

// Every network-touching function in this phase calls assertApproved, so the
// only way to reach a socket is through gateCandidates. The brand is deliberately
// unforgeable-by-accident: a caller assembling a plausible-looking object by hand
// does not get past it, which is the same fail-closed reasoning as the kernel,
// one layer up.
export function assertApproved(value) {
  if (value === null || typeof value !== 'object' || value[APPROVAL_BRAND] !== true) {
    throw new Error('target is not scope-approved; it must come from gateCandidates')
  }
}

export function gateCandidates({ sealedScope, candidates, port = DEFAULT_PORT }) {
  // The program mandates an identifying marker, and this is the only route to a
  // socket in this phase, so a scope without one must approve nothing. Refused
  // rather than thrown, because that is how this gate already reports a scope it
  // cannot use, and a distinct reason keeps the diagnosis unambiguous.
  const userAgent = sealedScope?.program?.required_user_agent
  const markerMissing = typeof userAgent !== 'string' || userAgent.length === 0
  const approved = []
  const refused = []
  for (const candidate of candidates) {
    if (candidate === null || typeof candidate !== 'object') continue

    // A wildcard SAN proves a zone exists but names no host. Probing the zone
    // itself would be inventing a target the source never actually observed.
    if (candidate.kind !== 'host') {
      refused.push({ host: candidate.value, reason: 'zone-hint-not-probeable', ruleId: 'none' })
      continue
    }

    const url = buildUrl(candidate.value, port)
    const decision = decideScope(sealedScope, url)
    if (decision.decision === SCOPE_ALLOW) {
      // Checked here, not up front: a host that is out of scope deserves its own
      // reason, and only a host we would otherwise probe needs the marker.
      if (markerMissing) {
        refused.push({ host: candidate.value, reason: 'sealed-scope-user-agent-missing', ruleId: decision.rule_id })
        continue
      }
      approved.push({
        [APPROVAL_BRAND]: true,
        host: candidate.value,
        port,
        url,
        ruleId: decision.rule_id,
        userAgent,
      })
      continue
    }
    refused.push({ host: candidate.value, reason: decision.reason, ruleId: decision.rule_id })
  }
  return { approved, refused }
}
