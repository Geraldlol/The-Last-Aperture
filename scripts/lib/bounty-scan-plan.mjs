import { createHash } from 'node:crypto'
import { isIP } from 'node:net'
import { canonicalizeCandidate } from './bounty-target.mjs'
import { normalizeCapturedRequest, sanitizeCapturedRequest } from './bounty-authz-request.mjs'
import {
  selectInsertionPoints,
  selectProbes,
  selectRequests,
} from './bounty-intensity.mjs'
import {
  describeInsertion,
  findInsertionPoints,
  isSsrfCandidate,
} from './bounty-scan-insertion.mjs'
import { CONTROL_PROBES, ERROR_PROBES } from './bounty-scan-oracle.mjs'
import { SCOPE_ALLOW, decideScope } from './bounty-scope-kernel.mjs'
import { assertValidAdversarialPlan } from './adversarial-validation-contracts.mjs'
import { stableJson } from './run-engine.mjs'

export const BOUNTY_SCAN_ADAPTER_VERSION = '1.0.0'
export const BOUNTY_SCAN_PAYLOAD_CATALOG_VERSION = '1.0.0'

const MAX_ACTION_TIME_MS = 15_000
const MAX_WALL_TIME_MS = 86_400_000
const MAX_INPUT_BYTES = 16 * 1024 * 1024
const MAX_OUTPUT_BYTES = 2 * 1024 * 1024
const MAX_AGGREGATE_OUTPUT_BYTES = 256 * 1024 * 1024
const INPUT_HEADROOM_BYTES = 16 * 1024
const SAFE_REQUEST_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])
const STATE_CHANGING_ROUTE_ACTIONS = new Set([
  'activate', 'approve', 'archive', 'ban', 'block', 'cancel', 'create', 'deactivate',
  'delete', 'deploy', 'destroy', 'disable', 'drop', 'enable', 'execute', 'invite',
  'lock', 'logout', 'patch', 'post', 'publish', 'purge', 'put', 'reject', 'remove',
  'reset', 'restore', 'revoke', 'run', 'save', 'send', 'signout', 'start', 'stop',
  'submit', 'suspend', 'sync', 'terminate', 'truncate', 'unlock', 'unpublish',
  'unsubscribe', 'update', 'upload', 'write',
])
const ACTION_QUERY_NAMES = new Set([
  '_method', 'action', 'cmd', 'command', 'do', 'event', 'method', 'mode', 'op',
  'operation', 'submit', 'task',
])
const READ_SHAPED_ACTION_SUFFIXES = new Set([
  'detail', 'details', 'history', 'list', 'preview', 'report', 'result', 'results', 'status',
])
const FORBIDDEN_ROUTING_HEADERS = new Set([
  'host',
  ':authority',
  'forwarded',
  'x-forwarded-host',
  'x-forwarded-server',
  'x-original-host',
  'x-original-url',
  'x-original-uri',
  'x-forwarded-uri',
  'x-rewrite-url',
  'x-http-method-override',
  'x-http-method',
  'x-method-override',
])

function forbiddenRoutingHeader(name) {
  const lower = name.toLowerCase()
  return FORBIDDEN_ROUTING_HEADERS.has(lower)
    || lower.startsWith('x-forwarded-')
    || lower.startsWith('x-original-')
    || lower.startsWith('x-rewrite-')
    || lower === 'x-envoy-original-path'
    || lower === 'x-http-url-override'
}

const ERROR_PROBE_CATALOG = deepFreeze(ERROR_PROBES.map((probe) => structuredClone(probe)))
const CONTROL_PROBE_CATALOG = deepFreeze(CONTROL_PROBES.map((probe) => structuredClone(probe)))

const PAYLOAD_CATALOG = deepFreeze({
  version: BOUNTY_SCAN_PAYLOAD_CATALOG_VERSION,
  baseline_requests: 2,
  error_controls: CONTROL_PROBE_CATALOG,
  error_probes: ERROR_PROBE_CATALOG,
  ssrf_oob_template: 'http://{controller_correlated_oob_host}/',
})

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function canonicalDigest(value) {
  return sha256(Buffer.from(stableJson(value, 0), 'utf8'))
}

function canonicalBytes(value) {
  return Buffer.byteLength(stableJson(value, 0), 'utf8')
}

function normalizedRole(role) {
  if (typeof role?.id !== 'string' || role.id.length === 0) {
    throw new Error('a bounty scan plan requires an explicit role identity')
  }
  const auth = role?.auth ?? {}
  if (
    auth.kind === 'header'
    && typeof auth.name === 'string'
    && forbiddenRoutingHeader(auth.name)
  ) {
    throw new Error(`role authentication cannot use forbidden routing header ${auth.name}`)
  }
  return {
    id: role?.id,
    label: role?.label,
    auth: {
      kind: auth.kind,
      ...(typeof auth.name === 'string' ? { name: auth.name } : {}),
      ...(typeof auth.value_env === 'string' ? { value_env: auth.value_env } : {}),
    },
  }
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child)
    Object.freeze(value)
  }
  return value
}

export function snapshotBountyScanRole(role) {
  return deepFreeze(normalizedRole(structuredClone(role)))
}

export function bountyScanPayloadCatalog() {
  return PAYLOAD_CATALOG
}

function normalizeOobBinding(value) {
  if (value === null) return null
  if (value === undefined || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('an OOB-enabled bounty scan requires a concrete session binding')
  }
  if (!['hosted', 'self_hosted'].includes(value.backend)) {
    throw new Error('bounty scan OOB session binding carries an unknown backend')
  }
  if (typeof value.server !== 'string' || value.server.length === 0 || value.server.length > 253) {
    throw new Error('bounty scan OOB session binding carries an invalid server')
  }
  const server = value.server.toLowerCase()
  const labels = server.split('.')
  let parsed
  try {
    parsed = new URL(`http://${server}/`)
  } catch {
    throw new Error('bounty scan OOB session server must be a canonical DNS hostname')
  }
  if (
    server !== value.server.trim().toLowerCase()
    || isIP(server) !== 0
    || labels.length < 2
    || labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
    || server === 'localhost'
    || server.endsWith('.localhost')
    || server.endsWith('.local')
    || parsed.username !== ''
    || parsed.password !== ''
    || parsed.port !== ''
    || parsed.hostname !== server
    || parsed.host !== server
  ) {
    throw new Error('bounty scan OOB session server must be a canonical DNS hostname')
  }
  if (!/^[a-z0-9]{20}$/.test(value.correlation_id ?? '')) {
    throw new Error('bounty scan OOB session binding carries an invalid correlation id')
  }
  const createdAt = new Date(value.created_at)
  if (
    Number.isNaN(createdAt.valueOf())
    || createdAt.toISOString() !== value.created_at
  ) {
    throw new Error('bounty scan OOB session binding carries an invalid creation time')
  }
  return {
    backend: value.backend,
    server,
    correlation_id: value.correlation_id,
    created_at: value.created_at,
  }
}

function targetOf(request) {
  const result = canonicalizeCandidate(request.url)
  if (!result.ok) {
    throw new Error(`cannot plan bounty scan request ${request.request_id ?? '(unnamed)'}: ${result.reason}`)
  }
  return result.target
}

function actionParts(value) {
  let decoded = String(value)
  for (let pass = 0; pass < 8; pass += 1) {
    let next
    try { next = decodeURIComponent(decoded) } catch {
      return { ambiguous: decoded.includes('%'), tokens: decoded.toLowerCase().split(/[^a-z0-9]+/u).filter(Boolean) }
    }
    if (next === decoded) {
      return { ambiguous: false, tokens: decoded.toLowerCase().split(/[^a-z0-9]+/u).filter(Boolean) }
    }
    decoded = next
  }
  let ambiguous = false
  try { ambiguous = decodeURIComponent(decoded) !== decoded } catch {}
  return { ambiguous, tokens: decoded.toLowerCase().split(/[^a-z0-9]+/u).filter(Boolean) }
}

function actionQueryName(value) {
  const parts = actionParts(value)
  return parts.ambiguous ? null : parts.tokens.join('')
}

function carriesStateChangingAction(value, { allowReadSuffix = true } = {}) {
  const { ambiguous, tokens } = actionParts(value)
  if (ambiguous) return true
  if (allowReadSuffix && READ_SHAPED_ACTION_SUFFIXES.has(tokens.at(-1))) return false
  return tokens.length > 0 && (
    STATE_CHANGING_ROUTE_ACTIONS.has(tokens.join(''))
    || tokens.some((token) => STATE_CHANGING_ROUTE_ACTIONS.has(token))
  )
}

export function bountyScanStateChangingReason(request) {
  if (!SAFE_REQUEST_METHODS.has(request.method)) return `method ${request.method}`
  let parsed
  try { parsed = new URL(request.url) } catch { return 'unparseable route' }
  const pathSegments = parsed.pathname.split('/').filter(Boolean)
  for (const [index, segment] of pathSegments.entries()) {
    if (!carriesStateChangingAction(segment)) continue
    // A root /archive commonly names a read-only collection. The same terminal
    // segment beneath a resource path is an action endpoint.
    if (index === 0 && pathSegments.length === 1 && actionParts(segment).tokens.join('') === 'archive') {
      continue
    }
    return `route ${parsed.pathname}`
  }
  for (const [name, value] of parsed.searchParams) {
    const normalizedName = actionQueryName(name)
    if (
      normalizedName === null
      || (ACTION_QUERY_NAMES.has(normalizedName)
        && carriesStateChangingAction(value, { allowReadSuffix: false }))
      || (carriesStateChangingAction(name) && /^(?:1|true|yes|on)$/iu.test(value))
    ) return `route ${parsed.pathname} query action`
  }
  return null
}

function isLiteralLoopback(target) {
  if (target.hostKind === 'ipv4') {
    return target.host.split('.')[0] === '127'
  }
  return target.hostKind === 'ipv6' && target.host === '::1'
}

export function classifyBountyScanTarget(requests) {
  if (!Array.isArray(requests) || requests.length === 0) {
    throw new Error('cannot classify an empty bounty scan request set')
  }
  const normalized = requests.map((request) => normalizeCapturedRequest(request))
  return normalized.every((request) => isLiteralLoopback(targetOf(request)))
    ? 'local_service'
    : 'live'
}

export function digestBountyScanScope(scope) {
  return canonicalDigest(scope)
}

export function authorizeBountyScanRequest({ scope, request }) {
  const normalized = normalizeCapturedRequest(request)
  const forbiddenHeader = Object.keys(normalized.headers)
    .find((name) => forbiddenRoutingHeader(name))
  if (forbiddenHeader !== undefined) {
    return {
      allowed: false,
      reason: `forbidden-routing-header:${forbiddenHeader}`,
      rule_id: 'none',
      request: normalized,
    }
  }
  const candidate = canonicalizeCandidate(normalized.url)
  if (!candidate.ok) {
    return { allowed: false, reason: candidate.reason, rule_id: 'none', request: normalized }
  }
  const decision = decideScope(scope, normalized.url)
  if (decision.decision !== SCOPE_ALLOW) {
    return {
      allowed: false,
      reason: decision.reason,
      rule_id: decision.rule_id,
      request: normalized,
    }
  }
  const userAgent = scope?.program?.required_user_agent
  if (typeof userAgent !== 'string' || userAgent.length === 0) {
    return {
      allowed: false,
      reason: 'sealed-scope-user-agent-missing',
      rule_id: decision.rule_id,
      request: normalized,
    }
  }
  return { allowed: true, reason: 'scope-allow', rule_id: decision.rule_id, request: normalized }
}

function assertRequestsInScope(scope, requests) {
  for (const request of requests) {
    const decision = authorizeBountyScanRequest({ scope, request })
    if (!decision.allowed) {
      throw new Error(
        `bounty scan request ${request.request_id ?? request.url} is outside the current scope: ${decision.reason}`,
      )
    }
  }
}

function actionBudget(requests, classes, profile) {
  let maxActions = 0
  for (const request of requests) {
    maxActions += PAYLOAD_CATALOG.baseline_requests
    const points = selectInsertionPoints(findInsertionPoints(request), profile).items
    for (const point of points) {
      if (classes.includes('error-injection')) {
        maxActions += CONTROL_PROBE_CATALOG.length
        maxActions += selectProbes(ERROR_PROBE_CATALOG, profile).items.length
      }
      if (classes.includes('ssrf-oob') && isSsrfCandidate(point)) {
        maxActions += 1
      }
    }
  }
  return maxActions
}

function targetIdentity(requests) {
  const targets = requests.map((request) => targetOf(request))
  const origins = [...new Set(targets.map((target) => {
    const host = target.hostKind === 'ipv6' ? `[${target.host}]` : target.host
    const defaultPort = target.scheme === 'http:' ? 80 : 443
    return `${target.scheme}//${host}${target.port === defaultPort ? '' : `:${target.port}`}`
  }))].sort()
  const digest = canonicalDigest(origins)
  return {
    digest,
    locator: origins.length === 1
      ? origins[0]
      : `bounty-scan://request-set/${digest}`,
  }
}

function insertionPointIds(requests, profile) {
  const values = new Set()
  for (const request of requests) {
    for (const point of selectInsertionPoints(findInsertionPoints(request), profile).items) {
      values.add(`request.${describeInsertion(point).split(':', 1)[0]}`)
    }
  }
  return values.size === 0
    ? ['request.none']
    : [...values].sort()
}

export function buildBountyScanPlan({
  scope,
  requests,
  classes,
  role,
  profile,
  oobBinding = null,
}) {
  if (!Array.isArray(requests) || requests.length === 0) {
    throw new Error('cannot build a bounty scan plan without requests')
  }
  const normalizedClasses = Array.isArray(classes)
    ? [...new Set(classes.filter((entry) => profile.classes.includes(entry)))].sort()
    : []
  if (!normalizedClasses.some((entry) =>
    entry === 'error-injection' || entry === 'ssrf-oob')) {
    throw new Error('a crafted bounty scan plan requires error-injection or ssrf-oob')
  }
  const normalizedRequests = selectRequests(
    requests.map((request) => sanitizeCapturedRequest(request)),
    profile,
  ).items
  assertRequestsInScope(scope, normalizedRequests)

  const unsafeRequest = normalizedRequests.find((request) =>
    bountyScanStateChangingReason(request) !== null)
  if (unsafeRequest !== undefined) {
    const reason = bountyScanStateChangingReason(unsafeRequest)
    throw new Error(
      `crafted bounty scanning refuses state-changing ${reason}; use the mutation campaign`,
    )
  }
  const normalizedOob = normalizeOobBinding(oobBinding)
  if (normalizedClasses.includes('ssrf-oob') && normalizedOob === null) {
    throw new Error('ssrf-oob requires an exact OOB session binding')
  }
  if (!normalizedClasses.includes('ssrf-oob') && normalizedOob !== null) {
    throw new Error('an OOB session cannot be bound when ssrf-oob is not selected')
  }
  if (
    normalizedOob?.backend === 'hosted'
    && scope?.authorization?.permissions?.third_party !== true
  ) {
    throw new Error('a hosted OOB session requires third_party in the sealed permissions')
  }

  const roleBinding = normalizedRole(role)
  const scopeDigest = digestBountyScanScope(scope)
  const requestDigest = canonicalDigest(normalizedRequests)
  const roleDigest = canonicalDigest(roleBinding)
  const catalogDigest = canonicalDigest(PAYLOAD_CATALOG)
  const oobDigest = normalizedOob === null ? null : canonicalDigest(normalizedOob)
  const maxActions = actionBudget(normalizedRequests, normalizedClasses, profile)
  if (maxActions < 1 || maxActions > 1_000_000) {
    throw new Error(`crafted bounty scan action budget is outside the supported finite range: ${maxActions}`)
  }
  const largestRequestBytes = Math.max(...normalizedRequests.map(canonicalBytes))
  const maxInputBytes = largestRequestBytes + INPUT_HEADROOM_BYTES
  if (maxInputBytes > MAX_INPUT_BYTES) {
    throw new Error('a normalized bounty scan request exceeds the adversarial input limit')
  }
  const target = targetIdentity(normalizedRequests)
  const binding = {
    adapter: 'bounty.scan',
    adapter_version: BOUNTY_SCAN_ADAPTER_VERSION,
    payload_catalog_version: BOUNTY_SCAN_PAYLOAD_CATALOG_VERSION,
    payload_catalog_sha256: catalogDigest,
    request_inputs_sha256: requestDigest,
    request_count: normalizedRequests.length,
    classes: normalizedClasses,
    role_id: roleBinding.id,
    role_profile_sha256: roleDigest,
    intensity: profile.tier,
    request_cap: profile.requestCap,
    insertion_point_cap: profile.insertionPointCap,
    probes_per_insertion_point: profile.probesPerInsertionPoint,
    rate_limit_rps: profile.rateLimitRps,
    oob_session: normalizedOob,
    oob_session_sha256: oobDigest,
  }
  const bindingDigest = canonicalDigest({
    scope_sha256: scopeDigest,
    target_sha256: target.digest,
    binding,
    max_actions: maxActions,
  })
  const plan = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-plan',
    plan_id: `plan:bounty-scan-${bindingDigest.slice(0, 32)}`,
    engagement_id: scope.engagement_id,
    scope_revision_sha256: scopeDigest,
    candidate_id: `candidate:bounty-scan-${bindingDigest.slice(0, 32)}`,
    target: {
      kind: classifyBountyScanTarget(normalizedRequests),
      target_id: `target:bounty-scan-${target.digest.slice(0, 32)}`,
      locator: target.locator,
      identity_sha256: target.digest,
    },
    strategy_id: `bounty.scan/crafted-v${BOUNTY_SCAN_ADAPTER_VERSION}`,
    risk_class: normalizedOob?.backend === 'hosted'
      ? 'SENSITIVE_DATA'
      : 'READ_ONLY',
    autonomy_profile: 'L1_ASSISTED',
    attack: {
      id: 'attack:bounty-crafted-scan',
      description: 'Send only the selected bounded crafted payload classes to the sealed request set.',
      expected_observation: 'A vulnerability-specific differential, error, or correlated OOB signal is observed.',
    },
    control: {
      id: 'control:bounty-baseline-and-inert-input',
      description: 'Compare repeatable untouched baselines and inert input controls with crafted probes.',
      expected_observation: 'The baseline is attributable and the inert control does not reproduce the attack signal.',
    },
    oracle: {
      id: 'oracle:bounty-scan-differential-v1',
      confirmation_condition: 'The selected oracle reports a candidate only when its attack-specific signal is attributable.',
      inconclusive_condition: 'A volatile baseline, failed control, missing callback, or failed request remains unproven.',
    },
    limits: {
      max_actions: maxActions,
      max_wall_time_ms: MAX_WALL_TIME_MS,
      max_action_time_ms: MAX_ACTION_TIME_MS,
      max_input_bytes: maxInputBytes,
      max_output_bytes: MAX_OUTPUT_BYTES,
      max_aggregate_output_bytes: MAX_AGGREGATE_OUTPUT_BYTES,
      // The current controller dispatches serially. Bind the behavior it
      // actually performs, even when a broader intensity profile would permit
      // more parallel work in a future adapter.
      max_concurrency: 1,
      min_action_interval_ms: Math.floor(1000 / profile.rateLimitRps),
    },
    generator: {
      generator_id: 'generator:bounty-scan-catalog-v1',
      algorithm: 'bounty.scan/deterministic-catalog',
      version: BOUNTY_SCAN_ADAPTER_VERSION,
      generator_sha256: catalogDigest,
      deterministic: true,
      seed: requestDigest,
      max_cases: maxActions,
      max_case_bytes: maxInputBytes,
      insertion_points: insertionPointIds(normalizedRequests, profile),
      purposes: ['baseline', 'control', 'attack'],
      template: {
        action_category: 'http.adversarial',
        operation: 'http.request',
        parameters: binding,
      },
    },
  }
  return assertValidAdversarialPlan(plan)
}
