import { isIP } from 'node:net'
import {
  BOUNTY_SCOPE_SCHEMA_VERSION,
  assertScopeCurrent,
  PROGRAM_POLICY_SEALED_STATEMENT,
  assertValidBountyScope,
  digestPolicySnapshot,
} from './bounty-contracts.mjs'

const DEFAULT_MAX_FINDINGS = 500

const INTENSITY_TIERS = ['normal', 'aggressive', 'ham']

export function parseScopeRuleSpec(spec) {
  if (typeof spec !== 'string' || spec.trim().length === 0) {
    throw new Error('scope rule spec must be a non-empty string')
  }
  let rest = spec.trim()
  let pathPrefix = null
  const slashIndex = rest.indexOf('/')
  if (slashIndex !== -1) {
    pathPrefix = rest.slice(slashIndex)
    rest = rest.slice(0, slashIndex)
  }
  let ports = null
  const colonIndex = rest.lastIndexOf(':')
  if (colonIndex !== -1 && !rest.includes('[')) {
    const portText = rest.slice(colonIndex + 1)
    const port = Number.parseInt(portText, 10)
    if (!Number.isInteger(port) || String(port) !== portText) {
      throw new Error(`scope rule spec has an invalid port: ${spec}`)
    }
    ports = [port]
    rest = rest.slice(0, colonIndex)
  }
  let hostKind = 'exact'
  if (rest.startsWith('*.')) {
    hostKind = 'wildcard'
    rest = rest.slice(2)
  }
  const host = rest.toLowerCase()
  if (host.length === 0) {
    throw new Error(`scope rule spec has no host: ${spec}`)
  }
  if (hostKind === 'exact' && isIP(host) !== 0) {
    hostKind = 'ip'
  }
  const rule = { host_kind: hostKind, host }
  if (ports !== null) rule.ports = ports
  if (pathPrefix !== null) rule.path_prefix = pathPrefix
  return rule
}

function sealRules(specs, prefix) {
  return specs.map((spec, index) => ({
    rule_id: `${prefix}-${index + 1}`,
    ...parseScopeRuleSpec(spec),
  }))
}

function checkPermissions(permissions) {
  if (permissions === null || typeof permissions !== 'object') {
    throw new Error('permissions must be an object')
  }
  if (permissions.phi === true) {
    throw new Error('bounty-v1 refuses phi permission; this protocol never handles PHI')
  }
  const intensity = permissions.intensity
  if (!INTENSITY_TIERS.includes(intensity)) {
    throw new Error(`intensity must be one of ${INTENSITY_TIERS.join(', ')}`)
  }
  if (intensity !== 'normal' && permissions.active_testing !== true) {
    throw new Error(`intensity ${intensity} requires active_testing`)
  }
  if (intensity === 'ham' && permissions.automation_allowed !== true) {
    throw new Error('intensity ham requires automation_allowed; HAM is sustained automated volume')
  }
  if (permissions.desync_probes === true && intensity !== 'ham') {
    throw new Error('desync_probes requires intensity ham')
  }
}

// Printable ASCII with no leading or trailing space. A marker carrying CR, LF,
// or a tab would smuggle a second header past the kernel, which decides on hosts
// and never inspects bytes.
const USER_AGENT_PATTERN = /^[\x21-\x7e]([\x20-\x7e]*[\x21-\x7e])?$/

// Programs may mandate an identifying marker (for example, BugBounty-Example) so their
// logs can attribute the traffic to a researcher. Defaulting to our own tool
// string would send unidentified traffic under a perimeter claiming to be
// identified, so an undeclared marker is an unsealed field and fails closed.
function checkUserAgent(value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error('a required user agent must be declared; the program mandates an identifying marker')
  }
  if (value.length > 256 || !USER_AGENT_PATTERN.test(value)) {
    throw new Error('required user agent must be printable ASCII with no leading, trailing, or control whitespace')
  }
}

export function createProgramSealedScope(options) {
  const {
    engagementId,
    platform,
    programHandle,
    policyUrl,
    policySnapshotBytes,
    operatorId,
    authorizedBy,
    requiredUserAgent,
    allowSpecs,
    denySpecs = [],
    permissions,
    validity,
    maxFindings = DEFAULT_MAX_FINDINGS,
    now,
  } = options ?? {}

  if (!Array.isArray(allowSpecs) || allowSpecs.length === 0) {
    throw new Error('at least one allow scope rule is required; empty allow lists are refused')
  }
  checkUserAgent(requiredUserAgent)
  checkPermissions(permissions)
  const notBefore = new Date(validity?.notBefore ?? '')
  const notAfter = new Date(validity?.notAfter ?? '')
  if (Number.isNaN(notBefore.getTime()) || Number.isNaN(notAfter.getTime())) {
    throw new Error('validity requires parseable not_before and not_after timestamps')
  }
  if (notAfter.getTime() <= notBefore.getTime()) {
    throw new Error('validity not_after must be after not_before')
  }
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) {
    throw new Error('now must be a valid Date; the planner never reads the ambient clock')
  }

  // Sealing an attestation outside its own validity window is incoherent: the
  // operator would be declaring authorization for a period that does not include
  // the moment of declaration. Mirrors the http-authed attestation-window rule.
  assertScopeCurrent({ scope: { validity: { not_before: notBefore.toISOString(), not_after: notAfter.toISOString() } }, now })

  const scope = {
    schema_version: BOUNTY_SCOPE_SCHEMA_VERSION,
    kind: 'red-team-audit/bounty-scope',
    engagement_id: engagementId,
    platform,
    environment: permissions.production === true ? 'production' : 'non_production',
    data_class: 'non_phi',
    program: {
      program_handle: programHandle,
      policy_url: policyUrl,
      policy_snapshot_sha256: digestPolicySnapshot(policySnapshotBytes),
      required_user_agent: requiredUserAgent,
    },
    authorization: {
      mode: 'PROGRAM_POLICY_SEALED',
      authorization_id: `${engagementId}-auth`,
      statement: PROGRAM_POLICY_SEALED_STATEMENT,
      operator_id: operatorId,
      authorized_by: authorizedBy,
      authorization_reference: policyUrl,
      attested_at: now.toISOString(),
      independently_verified: false,
      permissions: {
        active_testing: permissions.active_testing === true,
        production: permissions.production === true,
        third_party: permissions.third_party === true,
        phi: false,
        mutation: permissions.mutation === true,
        automation_allowed: permissions.automation_allowed === true,
        intensity: permissions.intensity,
        desync_probes: permissions.desync_probes === true,
        rate_limit_rps: permissions.rate_limit_rps,
      },
    },
    validity: { not_before: notBefore.toISOString(), not_after: notAfter.toISOString() },
    scope_rules: {
      allow: sealRules(allowSpecs, 'allow'),
      deny: sealRules(denySpecs, 'deny'),
    },
    stop_conditions: { max_findings: maxFindings, operator_stop: false },
  }
  assertValidBountyScope(scope)
  return scope
}
