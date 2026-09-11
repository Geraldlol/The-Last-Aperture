import { createHash } from 'node:crypto'
import { lstat, mkdir, readdir, realpath } from 'node:fs/promises'
import { isAbsolute, join, resolve } from 'node:path'

import {
  canonicalEngagementJson,
} from './engagement-contracts.mjs'
import {
  digestEngagementAuthority,
  verifyEngagementAuthority,
  verifyEngagementManifest,
} from './engagement-authorization.mjs'
import {
  canonicalJson,
  OPERATOR_ATTESTED_AUTHED_STATEMENT,
  readAndVerifyHttpAuthedAuthorization,
} from './http-authed-contracts.mjs'
import { planHttpAuthedAttestedScope } from './http-authed-planner.mjs'
import { assertLocalFilesystemEndpoint } from './filesystem-endpoint.mjs'

const ROUTE_ID = 'authenticated-http-browser'
const BROWSER_REFERENCE = /^(?:browser|browser-session):[A-Za-z0-9][A-Za-z0-9._:/-]*$/u
const EXTENSION_ID = /^[a-p]{32}$/u
const SCOPE_NAME = /^scope-([a-f0-9]{64})\.json$/u
const SCOPE_LIFETIME_MS = 60 * 60 * 1000
const MAX_RETAINED_SCOPES = 64

const METHODS = Object.freeze(['GET', 'HEAD', 'OPTIONS'])
const TEST_CATEGORIES = Object.freeze([
  'authentication',
  'authorization',
  'session_management',
  'api_security',
])
const LIMITS = Object.freeze({
  request_timeout_ms: 10_000,
  max_response_bytes: 65_536,
  min_interval_ms: 1_000,
  concurrency: 1,
  max_actions: 256,
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

export class EngagementAuthHttpMaterialError extends Error {
  constructor(code, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'EngagementAuthHttpMaterialError'
    this.code = code
  }
}

function fail(code, message, options) {
  throw new EngagementAuthHttpMaterialError(code, message, options)
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function exactPlainObject(value, allowedFields) {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  ) return false
  return Object.keys(value).every((field) => allowedFields.includes(field))
}

function deepFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const nested of Object.values(value)) deepFreeze(nested)
  return Object.freeze(value)
}

function frozenCopy(value) {
  return deepFreeze(structuredClone(value))
}

function instant(value, label) {
  const parsed = value instanceof Date ? new Date(value.getTime()) : new Date(value)
  if (!Number.isFinite(parsed.getTime())) {
    fail('ENGAGEMENT_AUTH_HTTP_TIME_INVALID', `${label} must produce a valid instant`)
  }
  return parsed
}

function comparablePath(value) {
  const canonical = resolve(value)
  return process.platform === 'win32' ? canonical.toLowerCase() : canonical
}

async function assertCanonicalDirectory(path, label) {
  let metadata
  let canonical
  try {
    metadata = await lstat(path)
    canonical = await realpath(path)
  } catch (cause) {
    fail('ENGAGEMENT_AUTH_HTTP_DIRECTORY_INVALID', `${label} is unavailable`, { cause })
  }
  if (
    !metadata.isDirectory()
    || metadata.isSymbolicLink()
    || comparablePath(path) !== comparablePath(canonical)
  ) {
    fail(
      'ENGAGEMENT_AUTH_HTTP_DIRECTORY_INVALID',
      `${label} must be one canonical local non-link directory`,
    )
  }
  return canonical
}

async function ensureOwnedDirectory(path, label) {
  try {
    await mkdir(path, { recursive: false, mode: 0o700 })
  } catch (cause) {
    if (cause?.code !== 'EEXIST') {
      fail('ENGAGEMENT_AUTH_HTTP_DIRECTORY_INVALID', `${label} could not be created`, { cause })
    }
  }
  return assertCanonicalDirectory(path, label)
}

function adapterRequired(reasonCode) {
  return frozenCopy({
    state: 'ADAPTER_REQUIRED',
    route_id: ROUTE_ID,
    reason_code: reasonCode,
  })
}

function validateAuthorityBinding(authority, manifest) {
  const verifiedAuthority = verifyEngagementAuthority(authority, {
    expectedEngagementId: manifest?.engagement_id,
    expectedTarget: manifest?.target,
  })
  const verifiedManifest = verifyEngagementManifest(manifest, { authority: verifiedAuthority })
  if (!['https', 'browser'].includes(verifiedManifest.target.kind)) {
    fail(
      'ENGAGEMENT_AUTH_HTTP_TARGET_KIND_INVALID',
      'authenticated HTTP material requires an HTTPS or browser engagement target',
    )
  }
  if (
    !verifiedAuthority.capabilities.includes(ROUTE_ID)
    || !verifiedAuthority.effects.includes('SEND_AUTHENTICATED_TARGET_REQUESTS')
  ) {
    fail(
      'ENGAGEMENT_AUTH_HTTP_CAPABILITY_MISSING',
      'engagement authority does not grant the authenticated HTTP route',
    )
  }
  return { authority: verifiedAuthority, manifest: verifiedManifest }
}

function browserReferences(authority) {
  return authority.credential_references.filter((reference) => BROWSER_REFERENCE.test(reference))
}

function normalizeBrowserCredential(value, references) {
  if (value === undefined || value === null) return null
  if (!exactPlainObject(value, ['credentialReference', 'extensionId', 'pageSessionAdapter'])) {
    fail(
      'ENGAGEMENT_AUTH_HTTP_ADAPTER_RESULT_INVALID',
      'browser credential adapter may return only a named reference and browser session metadata',
    )
  }
  const credentialReference = value.credentialReference
    ?? (references.length === 1 ? references[0] : undefined)
  if (!references.includes(credentialReference)) {
    fail(
      'ENGAGEMENT_AUTH_HTTP_CREDENTIAL_REFERENCE_DRIFT',
      'browser credential adapter selected a reference outside the engagement authority',
    )
  }
  if (!EXTENSION_ID.test(value.extensionId ?? '')) {
    fail(
      'ENGAGEMENT_AUTH_HTTP_ADAPTER_RESULT_INVALID',
      'browser credential adapter must provide one Chrome extension id',
    )
  }
  return {
    credentialReference,
    extensionId: value.extensionId,
    ...(value.pageSessionAdapter === undefined
      ? {}
      : { pageSessionAdapter: structuredClone(value.pageSessionAdapter) }),
  }
}

function routeBinding({ authority, manifest, credentialReference }) {
  const credentialReferenceSha256 = sha256(Buffer.from(credentialReference, 'utf8'))
  const bindingSha256 = sha256(Buffer.from(canonicalEngagementJson({
    authority_sha256: manifest.authority_sha256,
    target_sha256: manifest.target_sha256,
    credential_reference_sha256: credentialReferenceSha256,
  }), 'utf8'))
  return {
    authorizationId: `engagement-auth-http:${bindingSha256}`,
    authorizationReference: `Engagement authority SHA-256 ${digestEngagementAuthority(authority)}; browser credential reference SHA-256 ${credentialReferenceSha256}`,
  }
}

function scopePolicy({ authority, manifest, credential, issuedAt }) {
  const target = new URL(manifest.target.locator)
  const notAfter = new Date(issuedAt.getTime() + SCOPE_LIFETIME_MS)
  const binding = routeBinding({
    authority,
    manifest,
    credentialReference: credential.credentialReference,
  })
  const scopeCredential = {
    mode: 'CHROME_ACTIVE_TAB_SESSION',
    extension_id: credential.extensionId,
    origin: target.origin,
    ...(credential.pageSessionAdapter === undefined
      ? {}
      : { session_adapter: structuredClone(credential.pageSessionAdapter) }),
  }
  const pathPrefix = target.pathname
  const discovery = {
    enabled: true,
    origin: target.origin,
    path_prefixes: [pathPrefix],
    sources: [...DISCOVERY_SOURCES],
    candidate_methods: [...METHODS],
    test_category: TEST_CATEGORIES[0],
    synthetic_query_values: {},
    synthetic_path_values: {},
    max_response_bytes: LIMITS.max_response_bytes,
    max_depth: LIMITS.max_actions,
    max_candidates: LIMITS.max_actions,
  }
  return {
    schema_version: credential.pageSessionAdapter === undefined ? '1.0.0' : '1.4.0',
    kind: 'red-team-audit/http-authed-scope',
    engagement_id: authority.engagement_id,
    environment: 'production',
    data_class: 'unknown',
    authorization: {
      mode: 'OPERATOR_ATTESTED_AUTHED',
      authorization_id: binding.authorizationId,
      statement: OPERATOR_ATTESTED_AUTHED_STATEMENT,
      operator_id: authority.operator_id,
      authorized_by: 'engagement operator',
      authorization_reference: binding.authorizationReference,
      attested_at: issuedAt.toISOString(),
      independently_verified: false,
      permissions: {
        active_testing: true,
        production: true,
        third_party: true,
        phi: true,
        mutation: false,
      },
      authorized_scope: {
        origins: [target.origin],
        path_prefixes: [pathPrefix],
        methods: [...METHODS],
        test_categories: [...TEST_CATEGORIES],
      },
    },
    target: {
      origin: target.origin,
      ownership: 'third_party_owned',
      tls: { mode: 'PKIX_HOSTNAME' },
    },
    credential: scopeCredential,
    evidence_handling: { ...EVIDENCE_HANDLING },
    liveness: {
      credential_preflight: { method: 'GET', url: manifest.target.locator },
    },
    validity: {
      not_before: issuedAt.toISOString(),
      not_after: notAfter.toISOString(),
      cleanup_not_after: notAfter.toISOString(),
    },
    limits: { ...LIMITS },
    stop_conditions: [...STOP_CONDITIONS],
    requests: [{
      kind: 'probe',
      sequence: 1,
      test_category: TEST_CATEGORIES[0],
      method: 'GET',
      url: manifest.target.locator,
      expected_effect: 'none',
    }],
    discovery,
  }
}

function plannerInput({ authority, manifest, credential, issuedAt, scopePath }) {
  const expected = scopePolicy({ authority, manifest, credential, issuedAt })
  return {
    outputPath: scopePath,
    engagementId: authority.engagement_id,
    classification: {
      environment: expected.environment,
      dataClass: expected.data_class,
    },
    authorization: {
      attestAuthorized: true,
      authorizationId: expected.authorization.authorization_id,
      operatorId: authority.operator_id,
      authorizedBy: expected.authorization.authorized_by,
      authorizationReference: expected.authorization.authorization_reference,
      attestedAt: issuedAt.toISOString(),
      permissions: {
        activeTesting: true,
        production: true,
        thirdParty: true,
        phi: true,
      },
    },
    target: {
      origin: expected.target.origin,
      ownership: expected.target.ownership,
      tls: expected.target.tls,
    },
    credential: {
      mode: 'CHROME_ACTIVE_TAB_SESSION',
      extensionId: credential.extensionId,
      origin: expected.target.origin,
      ...(credential.pageSessionAdapter === undefined
        ? {}
        : { pageSessionAdapter: structuredClone(credential.pageSessionAdapter) }),
    },
    authorizedScope: {
      origins: [...expected.authorization.authorized_scope.origins],
      pathPrefixes: [...expected.authorization.authorized_scope.path_prefixes],
      methods: [...expected.authorization.authorized_scope.methods],
      testCategories: [...expected.authorization.authorized_scope.test_categories],
    },
    mutationAuthorized: false,
    seedRequests: [{
      kind: 'probe',
      method: 'GET',
      url: manifest.target.locator,
      testCategory: TEST_CATEGORIES[0],
    }],
    discovery: true,
    liveness: { credentialPreflightUrl: manifest.target.locator },
    validity: {
      notBefore: issuedAt.toISOString(),
      notAfter: expected.validity.not_after,
      cleanupNotAfter: expected.validity.cleanup_not_after,
    },
    limits: { ...LIMITS },
  }
}

async function verifyDerivedScope({ path, authority, manifest, credential, issuedAt, now }) {
  const notAfter = issuedAt.getTime() + SCOPE_LIFETIME_MS
  const verificationTime = new Date(Math.min(now.getTime(), notAfter - 1))
  let verified
  try {
    verified = await readAndVerifyHttpAuthedAuthorization({
      scopePath: path,
      requiredMode: 'OPERATOR_ATTESTED_AUTHED',
      now: verificationTime,
    })
  } catch (cause) {
    fail(
      'ENGAGEMENT_AUTH_HTTP_SCOPE_INVALID',
      'controller-owned authenticated HTTP scope is invalid',
      { cause },
    )
  }
  const expected = scopePolicy({ authority, manifest, credential, issuedAt })
  const expectedGrantSha256 = sha256(Buffer.from(canonicalJson(expected), 'utf8'))
  if (
    canonicalJson(verified.scope) !== canonicalJson(expected)
    || verified.campaignGrantSha256 !== expectedGrantSha256
    || path !== join(resolve(path, '..'), `scope-${expectedGrantSha256}.json`)
  ) {
    fail(
      'ENGAGEMENT_AUTH_HTTP_SCOPE_BINDING_DRIFT',
      'controller-owned authenticated HTTP scope differs from its authority, target, or browser binding',
    )
  }
  return verified
}

async function retainedScope(scopesDirectory, binding) {
  let entries
  try {
    entries = await readdir(scopesDirectory, { withFileTypes: true })
  } catch (cause) {
    fail('ENGAGEMENT_AUTH_HTTP_DIRECTORY_INVALID', 'scope directory could not be inspected', { cause })
  }
  if (entries.length > MAX_RETAINED_SCOPES) {
    fail('ENGAGEMENT_AUTH_HTTP_SCOPE_LIMIT', 'controller-owned scope history exceeds its bounded limit')
  }
  const scopes = entries.map((entry) => {
    const match = SCOPE_NAME.exec(entry.name)
    if (!entry.isFile() || match === null) {
      fail(
        'ENGAGEMENT_AUTH_HTTP_SCOPE_ENTRY_INVALID',
        'controller-owned scope directory contains an unexpected entry',
      )
    }
    return { path: join(scopesDirectory, entry.name), grantSha256: match[1] }
  })
  if (scopes.length === 0) return { current: null, count: 0 }
  const current = []
  for (const scope of scopes) {
    let verified
    try {
      verified = await readAndVerifyHttpAuthedAuthorization({
        scopePath: scope.path,
        requiredMode: 'OPERATOR_ATTESTED_AUTHED',
        now: binding.now,
      })
    } catch (cause) {
      if (cause?.code === 'HTTP_AUTHED_AUTHORIZATION_EXPIRED') continue
      fail(
        cause?.code === 'HTTP_AUTHED_AUTHORIZATION_NOT_YET_VALID'
          || cause?.code === 'HTTP_AUTHED_ATTESTATION_FUTURE'
          ? 'ENGAGEMENT_AUTH_HTTP_CLOCK_ROLLBACK'
          : 'ENGAGEMENT_AUTH_HTTP_SCOPE_INVALID',
        'controller-owned authenticated HTTP scope is invalid',
        { cause },
      )
    }
    const issuedAt = instant(
      verified.scope.authorization.attested_at,
      'controller-owned scope attested_at',
    )
    const rebound = await verifyDerivedScope({
      path: scope.path,
      authority: binding.authority,
      manifest: binding.manifest,
      credential: binding.credential,
      issuedAt,
      now: binding.now,
    })
    if (scope.grantSha256 !== rebound.campaignGrantSha256) {
      fail(
        'ENGAGEMENT_AUTH_HTTP_SCOPE_BINDING_DRIFT',
        'controller-owned scope path differs from its campaign grant digest',
      )
    }
    current.push({ ...scope, issuedAt, verified: rebound })
  }
  current.sort((left, right) => right.issuedAt.getTime() - left.issuedAt.getTime())
  return { current: current[0] ?? null, count: scopes.length }
}

function readyMaterial({ scopePath, verified, ledgerDirectory, materialsDirectory, operatorId }) {
  return frozenCopy({
    state: 'READY',
    route_id: ROUTE_ID,
    material: {
      scope_path: scopePath,
      campaign_grant_sha256: verified.campaignGrantSha256,
      ledger_directory: ledgerDirectory,
      materials_directory: materialsDirectory,
      operator_id: operatorId,
      credential_transport: 'browser',
    },
  })
}

/**
 * Derive the fixed authenticated HTTP/browser route material from one verified
 * engagement authority. The optional adapter resolves only a named browser
 * reference to non-secret Chrome/session metadata; credential bytes are neither
 * accepted nor persisted by this boundary.
 */
export async function deriveEngagementAuthHttpMaterial({
  bundle,
  authority,
  manifest,
} = {}, {
  resolveBrowserCredential,
  now = () => new Date(),
  planScope = planHttpAuthedAttestedScope,
} = {}) {
  const binding = validateAuthorityBinding(authority, manifest)
  const references = browserReferences(binding.authority)
  if (references.length === 0) {
    return adapterRequired('BROWSER_CREDENTIAL_REFERENCE_REQUIRED')
  }
  if (typeof resolveBrowserCredential !== 'function') {
    return adapterRequired('BROWSER_CREDENTIAL_ADAPTER_REQUIRED')
  }

  const adapterInput = frozenCopy({
    engagementId: binding.authority.engagement_id,
    authoritySha256: binding.manifest.authority_sha256,
    target: binding.manifest.target,
    browserCredentialReferences: references,
  })
  const credential = normalizeBrowserCredential(
    await resolveBrowserCredential(adapterInput),
    references,
  )
  if (credential === null) {
    return adapterRequired('BROWSER_CREDENTIAL_ADAPTER_UNAVAILABLE')
  }

  assertLocalFilesystemEndpoint(bundle, 'engagement bundle')
  if (typeof bundle !== 'string' || !isAbsolute(bundle)) {
    fail('ENGAGEMENT_AUTH_HTTP_BUNDLE_INVALID', 'engagement bundle must be an absolute local path')
  }
  const bundleDirectory = await assertCanonicalDirectory(resolve(bundle), 'engagement bundle')
  const routeDirectory = await assertCanonicalDirectory(
    join(bundleDirectory, 'routes', ROUTE_ID),
    'authenticated HTTP route directory',
  )
  const scopesDirectory = await ensureOwnedDirectory(join(routeDirectory, 'scopes'), 'scope directory')
  const ledgerDirectory = await ensureOwnedDirectory(
    join(routeDirectory, 'campaign-ledger'),
    'campaign ledger directory',
  )
  const materialsDirectory = await ensureOwnedDirectory(
    join(routeDirectory, 'campaign-materials'),
    'campaign materials directory',
  )
  const current = instant(now(), 'authenticated HTTP material clock')
  const declaredAt = instant(binding.authority.declared_at, 'engagement authority declared_at')
  const createdAt = instant(binding.manifest.created_at, 'engagement manifest created_at')
  if (current.getTime() < declaredAt.getTime() || current.getTime() < createdAt.getTime()) {
    fail(
      'ENGAGEMENT_AUTH_HTTP_CLOCK_ROLLBACK',
      'authenticated HTTP material clock predates the engagement authority or manifest',
    )
  }

  const retained = await retainedScope(scopesDirectory, {
    ...binding,
    credential,
    now: current,
  })
  if (retained.current !== null) {
    return readyMaterial({
      scopePath: retained.current.path,
      verified: retained.current.verified,
      ledgerDirectory,
      materialsDirectory,
      operatorId: binding.authority.operator_id,
    })
  }
  if (retained.count >= MAX_RETAINED_SCOPES) {
    fail('ENGAGEMENT_AUTH_HTTP_SCOPE_LIMIT', 'controller-owned scope history cannot grow past its bounded limit')
  }

  const expectedScope = scopePolicy({
    ...binding,
    credential,
    issuedAt: current,
  })
  const expectedGrantSha256 = sha256(Buffer.from(canonicalJson(expectedScope), 'utf8'))
  const scopePath = join(scopesDirectory, `scope-${expectedGrantSha256}.json`)
  try {
    await planScope(
      plannerInput({
        ...binding,
        credential,
        issuedAt: current,
        scopePath,
      }),
      { clock: () => new Date(current.getTime()) },
    )
  } catch (cause) {
    if (cause?.code !== 'HTTP_AUTHED_PLAN_OUTPUT_EXISTS') {
      fail('ENGAGEMENT_AUTH_HTTP_SCOPE_CREATE_FAILED', 'authenticated HTTP scope could not be created', { cause })
    }
  }
  const verified = await verifyDerivedScope({
    path: scopePath,
    ...binding,
    credential,
    issuedAt: current,
    now: current,
  })
  return readyMaterial({
    scopePath,
    verified,
    ledgerDirectory,
    materialsDirectory,
    operatorId: binding.authority.operator_id,
  })
}
