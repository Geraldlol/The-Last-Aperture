import { canonicalizeCandidate } from './bounty-target.mjs'

export const SCOPE_ALLOW = 'ALLOW'
export const SCOPE_DENY = 'DENY'

const DEFAULT_PORTS = [80, 443]

const METADATA_HOSTS = new Set([
  '169.254.169.254',
  '100.100.100.200',
  'metadata.google.internal',
  'metadata',
])

function deny(reason, ruleId = 'none') {
  return { decision: SCOPE_DENY, rule_id: ruleId, reason }
}

function allow(ruleId) {
  return { decision: SCOPE_ALLOW, rule_id: ruleId, reason: 'allow-rule-matched' }
}

function ipv4Octets(host) {
  const parts = host.split('.')
  if (parts.length !== 4) return null
  const octets = parts.map((part) => Number.parseInt(part, 10))
  return octets.some((octet) => !Number.isInteger(octet)) ? null : octets
}

function isPrivateTarget(target) {
  if (METADATA_HOSTS.has(target.host)) return true
  if (target.hostKind === 'domain') return target.host === 'localhost'
  if (target.hostKind === 'ipv6') {
    return target.host === '::1'
      || target.host === '::'
      || target.host.startsWith('fe80:')
      || target.host.startsWith('fc')
      || target.host.startsWith('fd')
  }
  const octets = ipv4Octets(target.host)
  if (octets === null) return true
  const [a, b] = octets
  if (a === 10 || a === 127 || a === 0) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  if (a === 169 && b === 254) return true
  if (a === 100 && b >= 64 && b <= 127) return true
  return false
}

function hostMatches(rule, target) {
  if (rule.host_kind === 'ip') {
    return target.hostKind !== 'domain' && target.host === rule.host
  }
  if (target.hostKind !== 'domain') return false
  if (rule.host_kind === 'exact') return target.host === rule.host
  if (rule.host_kind === 'wildcard') {
    return target.host !== rule.host && target.host.endsWith(`.${rule.host}`)
  }
  return false
}

function portMatches(rule, target) {
  const ports = Array.isArray(rule.ports) ? rule.ports : DEFAULT_PORTS
  return ports.includes(target.port)
}

function pathMatches(rule, target) {
  if (typeof rule.path_prefix !== 'string' || rule.path_prefix.length === 0) return true
  const prefix = rule.path_prefix.endsWith('/')
    ? rule.path_prefix.slice(0, -1)
    : rule.path_prefix
  if (target.path === prefix) return true
  return target.path.startsWith(`${prefix}/`)
}

function ruleMatches(rule, target) {
  if (rule === null || typeof rule !== 'object') return false
  return hostMatches(rule, target) && portMatches(rule, target) && pathMatches(rule, target)
}

function ruleId(rule) {
  return typeof rule?.rule_id === 'string' ? rule.rule_id : 'unnamed-rule'
}

export function decideScope(sealedScope, rawCandidate) {
  try {
    const rules = sealedScope?.scope_rules
    if (rules === null || typeof rules !== 'object') {
      return deny('sealed-scope-not-usable')
    }
    if (!Array.isArray(rules.allow) || !Array.isArray(rules.deny)) {
      return deny('sealed-scope-not-usable')
    }
    const canonical = canonicalizeCandidate(rawCandidate)
    if (!canonical.ok) return deny(canonical.reason)
    const target = canonical.target

    for (const rule of rules.deny) {
      if (ruleMatches(rule, target)) return deny('explicit-deny-rule', ruleId(rule))
    }
    if (isPrivateTarget(target) && rules.private_targets_sealed !== true) {
      return deny('private-target-not-sealed')
    }
    for (const rule of rules.allow) {
      if (ruleMatches(rule, target)) return allow(ruleId(rule))
    }
    return deny('candidate-unlisted')
  } catch {
    return deny('kernel-error')
  }
}
