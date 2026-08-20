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
      approved.push({
        [APPROVAL_BRAND]: true,
        host: candidate.value,
        port,
        url,
        ruleId: decision.rule_id,
      })
      continue
    }
    refused.push({ host: candidate.value, reason: decision.reason, ruleId: decision.rule_id })
  }
  return { approved, refused }
}
