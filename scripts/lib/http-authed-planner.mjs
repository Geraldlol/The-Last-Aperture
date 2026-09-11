import { open, unlink } from 'node:fs/promises'
import { isAbsolute, resolve } from 'node:path'

import {
  assertValidHttpAuthedScope,
  canonicalJson,
  httpAuthedAuthorizationEvidence,
  HttpAuthedContractError,
  OPERATOR_ATTESTED_AUTHED_STATEMENT,
  sha256Hex,
  verifyHttpAuthedAuthorization,
} from './http-authed-contracts.mjs'
import {
  HttpAuthedCredentialError,
  resolveHttpAuthedCredential,
} from './http-authed-credential.mjs'
import { discoverHttpAuthedCandidates } from './http-authed-discovery.mjs'

const DEFAULT_LIMITS = Object.freeze({
  request_timeout_ms: 10_000,
  max_response_bytes: 65_536,
  min_interval_ms: 1_000,
  concurrency: 1,
  max_actions: 10_000,
})

const EVIDENCE_HANDLING = Object.freeze({
  persist_request_bodies: false,
  persist_response_bodies: false,
  persist_credential_values: false,
  persist_header_values: false,
  stop_on_sensitive_data: true,
  test_data: 'synthetic_only',
})

const STOP_CONDITIONS = Object.freeze([
  'AUTHORIZATION_WITHDRAWN',
  'EMERGENCY_STOP_REQUESTED',
  'AUTHORIZATION_WINDOW_CLOSED',
  'TARGET_IDENTITY_CHANGED',
  'LIMIT_REACHED',
  'UNEXPECTED_SIDE_EFFECT',
  'VERIFICATION_MISMATCH',
  'ROLLBACK_REQUIRED',
  'CREDENTIAL_INVALID',
])

const DISCOVERY_SOURCES = Object.freeze([
  'link_header',
  'location_header',
  'allow_header',
  'html_links',
  'html_forms',
  'json_links',
  'openapi_paths',
  'sitemap_xml',
])

const STATE_SAFE_METHODS = new Set(['HEAD', 'GET', 'OPTIONS'])
const SYNTHETIC_VALUE = /^SYNTHETIC_[A-Z0-9_-]{4,128}$/

export class HttpAuthedPlannerError extends Error {
  constructor(code, message) {
    super(message)
    this.name = 'HttpAuthedPlannerError'
    this.code = code
  }
}

function plannerError(code, message) {
  return new HttpAuthedPlannerError(code, message)
}

function safeContractFailure(error) {
  if (!(error instanceof HttpAuthedContractError)) {
    return 'the planned authenticated scope failed validation or authorization verification'
  }
  const detail = error.details?.[0]
  if (error.code === 'HTTP_AUTHED_SCHEMA_INVALID' && detail) {
    return `the planned authenticated scope violates its schema at ${detail.instancePath}: ${detail.message}`
  }
  return `the planned authenticated scope is invalid (${error.code}): ${error.message}`
}

function snapshotInput(input) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    throw plannerError('HTTP_AUTHED_PLAN_INPUT_INVALID', 'planner input must be an object')
  }
  try {
    return structuredClone(input)
  } catch {
    throw plannerError(
      'HTTP_AUTHED_PLAN_INPUT_INVALID',
      'planner input must contain cloneable data values only',
    )
  }
}

function requireArray(value, label) {
  if (!Array.isArray(value) || value.length === 0) {
    throw plannerError('HTTP_AUTHED_PLAN_INPUT_INVALID', `${label} must be a non-empty array`)
  }
  const copy = [...value]
  if (new Set(copy).size !== copy.length) {
    throw plannerError('HTTP_AUTHED_PLAN_INPUT_INVALID', `${label} must not contain duplicates`)
  }
  return copy
}

function clockInstant(clock) {
  let value
  try {
    value = clock()
  } catch {
    throw plannerError('HTTP_AUTHED_PLAN_TIME_INVALID', 'planner clock is unavailable')
  }
  const instant = value instanceof Date ? value : new Date(value)
  if (!Number.isFinite(instant.getTime())) {
    throw plannerError('HTTP_AUTHED_PLAN_TIME_INVALID', 'planner clock returned an invalid time')
  }
  return instant
}

async function resolveCredentialBinding(credential, deps) {
  let bytes
  try {
    bytes = await resolveHttpAuthedCredential({ credential, ...deps })
    return sha256Hex(bytes)
  } catch (error) {
    if (!(error instanceof HttpAuthedCredentialError)) throw error
    const unavailable = error.code === 'HTTP_AUTHED_CREDENTIAL_UNAVAILABLE'
    throw plannerError(
      unavailable
        ? 'HTTP_AUTHED_PLAN_CREDENTIAL_UNAVAILABLE'
        : 'HTTP_AUTHED_PLAN_CREDENTIAL_INVALID',
      error.message,
    )
  } finally {
    bytes?.fill(0)
  }
}

function plannedCredential(credential, bindingSha256) {
  if (credential?.mode === 'CHROME_ACTIVE_TAB_SESSION') {
    return {
      mode: 'CHROME_ACTIVE_TAB_SESSION',
      extension_id: credential.extensionId,
      origin: credential.origin,
      ...(credential.pageSessionAdapter === undefined
        ? {}
        : { session_adapter: structuredClone(credential.pageSessionAdapter) }),
    }
  }
  return {
    ref: credential.ref,
    kind: credential.kind,
    binding_sha256: bindingSha256,
  }
}

function normalizeProbeSeed(seed, sequence, defaultCategory) {
  const source = typeof seed === 'string' ? { url: seed } : seed
  if (source === null || typeof source !== 'object' || Array.isArray(source)) {
    throw plannerError('HTTP_AUTHED_PLAN_SEED_INVALID', 'every seed must be a URL or action object')
  }
  if (source.kind !== undefined && source.kind !== 'probe') {
    throw plannerError(
      'HTTP_AUTHED_PLAN_SEED_INVALID',
      'non-mutation seeds must use the executable probe action kind',
    )
  }
  return {
    kind: 'probe',
    sequence,
    test_category: source.test_category ?? source.testCategory ?? defaultCategory,
    method: source.method ?? 'GET',
    url: source.url,
    ...(source.request_body === undefined ? {} : { request_body: source.request_body }),
    expected_effect: 'none',
  }
}

function normalizeSeed(seed, sequence, defaultCategory, mutationAuthorized) {
  if (seed?.kind !== 'mutate') {
    const probe = normalizeProbeSeed(seed, sequence, defaultCategory)
    if (!mutationAuthorized && !STATE_SAFE_METHODS.has(probe.method)) {
      throw plannerError(
        'HTTP_AUTHED_PLAN_MUTATION_AUTHORIZATION_REQUIRED',
        'without explicit mutation authorization every seed method must be HEAD, GET, or OPTIONS',
      )
    }
    if (!mutationAuthorized && probe.request_body !== undefined) {
      throw plannerError(
        'HTTP_AUTHED_PLAN_MUTATION_AUTHORIZATION_REQUIRED',
        'a body-bearing seed requires explicit mutation authorization',
      )
    }
    return probe
  }
  if (!mutationAuthorized) {
    throw plannerError(
      'HTTP_AUTHED_PLAN_MUTATION_AUTHORIZATION_REQUIRED',
      'a declared mutation requires explicit mutation authorization',
    )
  }
  return {
    ...seed,
    sequence,
    test_category: seed.test_category ?? seed.testCategory ?? defaultCategory,
  }
}

function normalizeSeeds(seeds, categories, mutationAuthorized) {
  const values = requireArray(seeds, 'seedRequests')
  const defaultCategory = categories[0]
  return values.map((seed, index) => (
    normalizeSeed(seed, index + 1, defaultCategory, mutationAuthorized)
  ))
}

function normalizeLimits(limits) {
  if (limits === undefined) return { ...DEFAULT_LIMITS }
  if (limits === null || typeof limits !== 'object' || Array.isArray(limits)) {
    throw plannerError('HTTP_AUTHED_PLAN_INPUT_INVALID', 'limits must be an object')
  }
  const normalized = { ...DEFAULT_LIMITS }
  for (const [key, value] of Object.entries(limits)) {
    if (value !== undefined) normalized[key] = value
  }
  return normalized
}

function buildResponseObservation(observation) {
  if (observation === undefined) return undefined
  if (observation === null || typeof observation !== 'object' || Array.isArray(observation)) {
    throw plannerError(
      'HTTP_AUTHED_PLAN_RESPONSE_OBSERVATION_INVALID',
      'response observation must be an explicit bounded object',
    )
  }
  const safeKeyNames = requireArray(
    observation.safeKeyNames,
    'responseObservation.safeKeyNames',
  )
  if (observation.aspNetD !== undefined && typeof observation.aspNetD !== 'boolean') {
    throw plannerError(
      'HTTP_AUTHED_PLAN_RESPONSE_OBSERVATION_INVALID',
      'ASP.NET d JSON shape selection must be an explicit boolean',
    )
  }
  const maxDepth = observation.maxDepth ?? 4
  if (!Number.isSafeInteger(maxDepth) || maxDepth < 1 || maxDepth > 4) {
    throw plannerError(
      'HTTP_AUTHED_PLAN_RESPONSE_OBSERVATION_INVALID',
      'JSON shape observation depth must be an integer from 1 through 4',
    )
  }
  return {
    mode: observation.aspNetD === true
      ? 'ASPNET_D_JSON_SHAPE_ONLY'
      : 'JSON_SHAPE_ONLY',
    max_depth: maxDepth,
    safe_key_names: safeKeyNames,
  }
}

function buildDiscovery(discovery, { targetOrigin, pathPrefixes, methods, categories, limits }) {
  if (discovery === undefined || discovery === false) return undefined
  if (discovery !== true && (
    discovery === null
    || typeof discovery !== 'object'
    || Array.isArray(discovery)
  )) {
    throw plannerError('HTTP_AUTHED_PLAN_INPUT_INVALID', 'discovery must be true or an object')
  }
  const options = discovery === true ? {} : discovery
  const candidateMethods = methods.filter((method) => STATE_SAFE_METHODS.has(method))
  return {
    enabled: true,
    origin: targetOrigin,
    path_prefixes: options.pathPrefixes ?? pathPrefixes,
    sources: options.sources ?? [...DISCOVERY_SOURCES],
    candidate_methods: candidateMethods,
    test_category: options.testCategory ?? categories[0],
    synthetic_query_values: options.syntheticQueryValues ?? {},
    synthetic_path_values: options.syntheticPathValues ?? {},
    max_response_bytes: options.maxResponseBytes ?? limits.max_response_bytes,
    // The total sealed action budget is the default expansion budget too. This
    // avoids a second hidden product ceiling while preserving a finite,
    // operator-reviewable campaign boundary.
    max_depth: options.maxDepth ?? limits.max_actions,
    max_candidates: options.maxCandidates ?? limits.max_actions,
  }
}

async function exclusiveCanonicalWrite(path, value, { openImpl = open, unlinkImpl = unlink } = {}) {
  let handle
  let created = false
  let failure
  try {
    handle = await openImpl(path, 'wx', 0o600)
    created = true
    await handle.writeFile(Buffer.from(canonicalJson(value), 'utf8'))
    await handle.sync()
  } catch (error) {
    failure = error
  }
  try {
    await handle?.close()
  } catch (error) {
    failure ??= error
  }
  if (!failure) return
  if (created) {
    try {
      await unlinkImpl(path)
    } catch {
      // Only the exact file exclusively created above is eligible for cleanup.
    }
  }
  if (failure?.code === 'EEXIST') {
    throw plannerError(
      'HTTP_AUTHED_PLAN_OUTPUT_EXISTS',
      'the scope output already exists; planning never overwrites it',
    )
  }
  throw plannerError('HTTP_AUTHED_PLAN_OUTPUT_FAILED', 'the scope output could not be committed')
}

function validateMutationFlag(value) {
  if (value !== undefined && typeof value !== 'boolean') {
    throw plannerError(
      'HTTP_AUTHED_PLAN_INPUT_INVALID',
      'mutationAuthorized must be an explicit boolean when supplied',
    )
  }
  return value === true
}

function publicSummary(scope, outputPath, verified) {
  const evidence = httpAuthedAuthorizationEvidence(scope)
  return {
    kind: 'red-team-audit/http-authed-attested-plan',
    schema_version: scope.schema_version,
    engagement_id: scope.engagement_id,
    authorization_mode: scope.authorization.mode,
    authorization_id: scope.authorization.authorization_id,
    target_origin: scope.target.origin,
    environment: scope.environment,
    data_class: scope.data_class,
    request_count: scope.requests.length,
    mutation_authorized: scope.authorization.permissions.mutation,
    discovery_enabled: scope.discovery?.enabled === true,
    independently_verified: scope.authorization.independently_verified,
    authorization_assurance: evidence.authorizationAssurance,
    authorization_nonclaim: evidence.authorizationNonclaim,
    authorization_binding_sha256: verified.authorizationBindingSha256,
    campaign_grant_sha256: verified.campaignGrantSha256,
    output_path: outputPath,
  }
}

function assertSyntheticPersistedIdentifier(value, label) {
  if (!SYNTHETIC_VALUE.test(value ?? '')) {
    throw plannerError(
      'HTTP_AUTHED_PLAN_IDENTIFIER_NOT_SYNTHETIC',
      `${label} must use an explicit SYNTHETIC_ non-PHI identifier`,
    )
  }
}

function assertPersistenceSafeUrl(url, label) {
  let parsed
  try {
    parsed = new URL(url)
  } catch {
    return
  }
  if ([...parsed.searchParams.values()].some((value) => !SYNTHETIC_VALUE.test(value))) {
    throw plannerError(
      'HTTP_AUTHED_PLAN_QUERY_NOT_SYNTHETIC',
      `${label} query values must use explicit SYNTHETIC_ non-PHI identifiers`,
    )
  }
}

function assertPersistedScopeMetadataIsSynthetic(requests, preflightUrl) {
  assertPersistenceSafeUrl(preflightUrl, 'credential preflight URL')
  for (const [index, action] of requests.entries()) {
    const label = `seedRequests[${index}]`
    assertPersistenceSafeUrl(action.url, `${label} URL`)
    if (action.request_body !== undefined) {
      assertSyntheticPersistedIdentifier(action.request_body.body_id, `${label} body_id`)
    }
    if (action.kind !== 'mutate') continue
    assertSyntheticPersistedIdentifier(
      action.expected_mutation?.resource_ref,
      `${label} resource_ref`,
    )
    for (const [nestedLabel, request] of [
      ['before_read', action.before_read],
      ['after_read', action.after_read],
      ['rollback', action.rollback],
      ['rollback.verification_read', action.rollback?.verification_read],
    ]) {
      assertPersistenceSafeUrl(request?.url, `${label} ${nestedLabel} URL`)
    }
    if (action.rollback?.request_body !== undefined) {
      assertSyntheticPersistedIdentifier(
        action.rollback.request_body.body_id,
        `${label} rollback body_id`,
      )
    }
  }
}

function assertDiscoverySeedsArePersistenceSafe(scope) {
  if (scope.discovery === undefined) return
  for (const action of scope.requests) {
    let parsed
    try {
      parsed = new URL(action.url)
    } catch {
      throw plannerError(
        'HTTP_AUTHED_PLAN_DISCOVERY_SEED_INVALID',
        'every discovery seed must use one persistence-safe scoped HTTPS URL',
      )
    }
    if (
      parsed.hash !== ''
      || [...parsed.searchParams.values()].some((value) => !SYNTHETIC_VALUE.test(value))
    ) {
      throw plannerError(
        'HTTP_AUTHED_PLAN_DISCOVERY_SEED_INVALID',
        'discovery seed query values must be explicit SYNTHETIC_ values and fragments are refused',
      )
    }
    try {
      discoverHttpAuthedCandidates({
        policy: scope.discovery,
        sourceAction: action,
        headers: [],
        bodyChunks: [],
      })
    } catch {
      throw plannerError(
        'HTTP_AUTHED_PLAN_DISCOVERY_SEED_INVALID',
        'every discovery seed must match the sealed category, origin, path, and query policy',
      )
    }
  }
}

async function planHttpAuthedScope(input, deps) {
  const planned = snapshotInput(input)
  if (typeof planned.outputPath !== 'string' || !isAbsolute(planned.outputPath)) {
    throw plannerError(
      'HTTP_AUTHED_PLAN_OUTPUT_ABSOLUTE_REQUIRED',
      'scope output path must be absolute',
    )
  }
  const io = {
    openImpl: deps.openImpl ?? open,
    unlinkImpl: deps.unlinkImpl ?? unlink,
  }
  const environment = deps.env ?? process.env
  const now = clockInstant(deps.clock ?? (() => new Date()))
  const mutationAuthorized = validateMutationFlag(planned.mutationAuthorized)
  const authorization = planned.authorization ?? {}
  if (authorization.attestAuthorized !== true) {
    throw plannerError(
      'HTTP_AUTHED_PLAN_ATTESTATION_REQUIRED',
      'operator-attested planning requires an explicit current authorization attestation',
    )
  }
  const permissions = authorization.permissions ?? {}
  const authorizedScope = planned.authorizedScope ?? {}
  const target = planned.target ?? {}
  const classification = planned.classification ?? {}
  const credential = planned.credential ?? {}
  const pathPrefixes = requireArray(authorizedScope.pathPrefixes, 'authorizedScope.pathPrefixes')
  const methods = requireArray(authorizedScope.methods, 'authorizedScope.methods')
  const categories = requireArray(authorizedScope.testCategories, 'authorizedScope.testCategories')
  if (!methods.includes('GET')) {
    throw plannerError(
      'HTTP_AUTHED_PLAN_PREFLIGHT_METHOD_REQUIRED',
      'authorized methods must include GET for credential preflight',
    )
  }
  const requests = normalizeSeeds(planned.seedRequests, categories, mutationAuthorized)
  const preflightUrl = planned.liveness?.credentialPreflightUrl ?? requests[0].url
  assertPersistedScopeMetadataIsSynthetic(requests, preflightUrl)
  const limits = normalizeLimits(planned.limits)
  const responseObservation = buildResponseObservation(planned.responseObservation)
  const browserSession = credential.mode === 'CHROME_ACTIVE_TAB_SESSION'
  const credentialBindingSha256 = browserSession
    ? undefined
    : await resolveCredentialBinding(credential, {
        env: environment,
        transientCredential: deps.transientCredential,
        credentialInput: deps.credentialInput,
        readStdin: deps.credentialStdinReader,
      })
  const scope = {
    schema_version: credential.pageSessionAdapter !== undefined
      ? '1.4.0'
      : responseObservation === undefined
        ? '1.0.0'
        : responseObservation.mode === 'ASPNET_D_JSON_SHAPE_ONLY'
          ? '1.2.0'
          : '1.1.0',
    kind: 'red-team-audit/http-authed-scope',
    engagement_id: planned.engagementId,
    environment: classification.environment,
    data_class: classification.dataClass,
    authorization: {
      mode: 'OPERATOR_ATTESTED_AUTHED',
      authorization_id: authorization.authorizationId,
      statement: OPERATOR_ATTESTED_AUTHED_STATEMENT,
      operator_id: authorization.operatorId,
      authorized_by: authorization.authorizedBy,
      authorization_reference: authorization.authorizationReference,
      attested_at: authorization.attestedAt ?? now.toISOString(),
      independently_verified: false,
      permissions: {
        active_testing: permissions.activeTesting === true,
        production: permissions.production === true,
        third_party: permissions.thirdParty === true,
        phi: permissions.phi === true,
        mutation: mutationAuthorized,
      },
      authorized_scope: {
        origins: authorizedScope.origins ?? [target.origin],
        path_prefixes: pathPrefixes,
        methods,
        test_categories: categories,
      },
    },
    target: {
      origin: target.origin,
      ownership: target.ownership,
      tls: target.tls ?? { mode: 'PKIX_HOSTNAME' },
    },
    credential: plannedCredential(credential, credentialBindingSha256),
    evidence_handling: { ...EVIDENCE_HANDLING },
    liveness: {
      credential_preflight: {
        method: 'GET',
        url: preflightUrl,
      },
    },
    validity: {
      not_before: planned.validity?.notBefore,
      not_after: planned.validity?.notAfter,
      cleanup_not_after: planned.validity?.cleanupNotAfter
        ?? planned.validity?.notAfter,
    },
    limits,
    stop_conditions: [...STOP_CONDITIONS],
    requests,
  }
  if (responseObservation !== undefined) scope.response_observation = responseObservation
  const discovery = buildDiscovery(planned.discovery, {
    targetOrigin: target.origin,
    pathPrefixes,
    methods,
    categories,
    limits,
  })
  if (discovery !== undefined) scope.discovery = discovery
  assertDiscoverySeedsArePersistenceSafe(scope)

  const assertScope = deps.assertValidScope ?? assertValidHttpAuthedScope
  const verifyAuthorization = deps.verifyAuthorization ?? verifyHttpAuthedAuthorization
  let verified
  try {
    assertScope(scope)
    verified = verifyAuthorization({ scope, now })
  } catch (error) {
    throw plannerError(
      'HTTP_AUTHED_PLAN_SCOPE_INVALID',
      safeContractFailure(error),
    )
  }

  const outputPath = resolve(planned.outputPath)
  await exclusiveCanonicalWrite(outputPath, scope, io)
  return publicSummary(scope, outputPath, verified)
}

export function planHttpAuthedAttestedScope(input, deps = {}) {
  return planHttpAuthedScope(input, deps)
}
