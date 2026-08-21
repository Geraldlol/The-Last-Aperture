import { constants as fsConstants, readFileSync } from 'node:fs'
import { lstat, open } from 'node:fs/promises'
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as signBytes,
  verify as verifyBytes,
} from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { isAbsolute, resolve } from 'node:path'
import Ajv2020 from 'ajv/dist/2020.js'
import { stableJson } from './run-engine.mjs'
import { resolveHttpReconResponseObservation } from './http-recon-response-observations.mjs'

// The small crypto/canonicalization helpers below intentionally mirror
// http-recon-contracts.mjs rather than importing its module-private functions,
// so this new tier stays self-contained. Candidate to factor into a shared
// http-signing module once both tiers are stable (ADR 0016).

const SCOPE_SCHEMA_URL = new URL(
  '../../schemas/http-authed-scope.schema.json',
  import.meta.url,
)

const ROE_SIGNATURE_CONTEXT = Buffer.from(
  'red-team-audit/http-authed-roe/v1\0',
  'utf8',
)
const COUNTERSIGN_CONTEXT = Buffer.from(
  'red-team-audit/http-authed-countersign/v1\0',
  'utf8',
)

export const OPERATOR_ATTESTED_AUTHED_STATEMENT =
  'I confirm that I am authorized by the asset owner to perform these exact bounded authenticated HTTP actions.'

export const WRITTEN_AUTHORIZATION_AUTHED_STATEMENT =
  'I attest that the supplied written authorization permits authenticated HTTP testing throughout the sealed engagement scope.'

const MAX_WRITTEN_AUTHORIZATION_BYTES = 16 * 1024 * 1024
const MAX_WRITTEN_SCOPE_BYTES = 64 * 1024 * 1024
const STATE_SAFE_PROBE_METHODS = new Set(['HEAD', 'GET', 'OPTIONS'])
const FETCH_FORBIDDEN_METHODS = new Set(['CONNECT', 'TRACE', 'TRACK'])
const TUNNEL_METHODS = new Set(['CONNECT'])
const RUNTIME_DECLARED_AUTHORIZATION_MODES = new Set([
  'OPERATOR_ATTESTED_AUTHED',
  'WRITTEN_AUTHORIZATION_AUTHED',
])
const AMBIGUOUS_PATH_ENCODING = /(?:\\|%(?:25)*(?:2e|2f|5c))/i
const SYNTHETIC_PERSISTED_VALUE = /^SYNTHETIC_[A-Z0-9_-]{4,128}$/
const OPEN_READ_ONLY_NO_FOLLOW = fsConstants.O_RDONLY
  | (typeof fsConstants.O_NOFOLLOW === 'number' ? fsConstants.O_NOFOLLOW : 0)

export const httpAuthedScopeSchema = JSON.parse(
  readFileSync(fileURLToPath(SCOPE_SCHEMA_URL), 'utf8'),
)

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})
ajv.addSchema(httpAuthedScopeSchema)
const validateScopeSchema = ajv.getSchema(httpAuthedScopeSchema.$id)
const validateActionSchema = ajv.compile({
  $ref: `${httpAuthedScopeSchema.$id}#/$defs/action`,
})

export class HttpAuthedContractError extends Error {
  constructor(code, message, details = [], options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'HttpAuthedContractError'
    this.code = code
    this.details = details
  }
}

function contractError(code, message, details, options) {
  return new HttpAuthedContractError(code, message, details, options)
}

function normalizeAjvErrors(errors = []) {
  return errors.map((error) => ({
    keyword: error.keyword,
    code: `SCHEMA_${String(error.keyword).toUpperCase()}`,
    instancePath: error.instancePath || '/',
    message: error.message ?? 'schema validation failed',
    params: error.params,
  }))
}

function assertSchema(validate, value, label) {
  if (!validate(value)) {
    throw contractError(
      'HTTP_AUTHED_SCHEMA_INVALID',
      `${label} violates its JSON schema`,
      normalizeAjvErrors(validate.errors),
    )
  }
  return value
}

export function canonicalJson(value) {
  const rendered = stableJson(value, 0)
  return rendered.endsWith('\n') ? rendered.slice(0, -1) : rendered
}

export function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex')
}

export function isHttpAuthedBrowserSessionCredential(credential) {
  return credential?.mode === 'CHROME_ACTIVE_TAB_SESSION'
}

export function isHttpAuthedRuntimeAuthorizationMode(mode) {
  return RUNTIME_DECLARED_AUTHORIZATION_MODES.has(mode)
}

export function httpAuthedAuthorizationEvidence(scope) {
  const mode = scope?.authorization?.mode
  if (mode === 'OPERATOR_ATTESTED_AUTHED') {
    return Object.freeze({
      authorizationMode: mode,
      independentlyVerified: false,
      authorizationAssurance: 'OPERATOR_DECLARATION_ONLY',
      authorizationNonclaim: 'NOT_INDEPENDENTLY_VERIFIED',
    })
  }
  if (mode === 'WRITTEN_AUTHORIZATION_AUTHED') {
    return Object.freeze({
      authorizationMode: mode,
      independentlyVerified: false,
      authorizationAssurance: 'DOCUMENT_BOUND_OPERATOR_EXTRACTION',
      authorizationNonclaim: 'ISSUER_AND_LEGAL_SUFFICIENCY_NOT_VERIFIED',
    })
  }
  throw contractError(
    'HTTP_AUTHED_RUNTIME_MODE_REQUIRED',
    'authorization evidence requires operator-attested or written authorization',
  )
}

function unsignedDocument(value) {
  const { signature: _signature, ...unsigned } = value
  return unsigned
}

function signingPayload(context, value) {
  return Buffer.concat([
    context,
    Buffer.from(canonicalJson(unsignedDocument(value)), 'utf8'),
  ])
}

function publicKeyIdentity(key) {
  if (key.asymmetricKeyType !== 'ed25519') {
    throw contractError(
      'HTTP_AUTHED_KEY_INVALID',
      'authed owner/approver key must be Ed25519',
    )
  }
  const spki = key.export({ type: 'spki', format: 'der' })
  return { key, keyId: `ed25519:${sha256Hex(spki)}` }
}

function parsePublicKey(keyBytes) {
  try {
    const asText = Buffer.isBuffer(keyBytes) ? keyBytes.toString('latin1') : String(keyBytes)
    const keyInput = asText.startsWith('-----BEGIN ')
      ? keyBytes
      : { key: Buffer.isBuffer(keyBytes) ? keyBytes : Buffer.from(keyBytes), format: 'der', type: 'spki' }
    return publicKeyIdentity(createPublicKey(keyInput))
  } catch (error) {
    if (error instanceof HttpAuthedContractError) throw error
    throw contractError(
      'HTTP_AUTHED_KEY_INVALID',
      `cannot parse public key: ${error.message}`,
      [],
      { cause: error },
    )
  }
}

function parsePrivateKey(keyBytes, passphrase) {
  try {
    const key = passphrase === undefined
      ? createPrivateKey(keyBytes)
      : createPrivateKey({ key: keyBytes, format: 'pem', passphrase })
    if (key.asymmetricKeyType !== 'ed25519') {
      throw contractError(
        'HTTP_AUTHED_KEY_INVALID',
        'authed signing key must be Ed25519',
      )
    }
    const identity = publicKeyIdentity(createPublicKey(key))
    return { key, keyId: identity.keyId }
  } catch (error) {
    if (error instanceof HttpAuthedContractError) throw error
    throw contractError(
      'HTTP_AUTHED_KEY_INVALID',
      `cannot parse signing key: ${error.message}`,
      [],
      { cause: error },
    )
  }
}

function decodeSignature(value) {
  const signature = value?.signature?.value_base64
  const decoded = Buffer.from(signature ?? '', 'base64')
  if (
    decoded.length !== 64
    || decoded.toString('base64') !== signature
    || value?.signature?.algorithm !== 'Ed25519'
  ) {
    throw contractError(
      'HTTP_AUTHED_SIGNATURE_INVALID',
      'authed signature must be canonical base64 Ed25519 data',
    )
  }
  return decoded
}

function verifySignedDocument({ value, publicKeyBytes, context, label }) {
  const identity = parsePublicKey(publicKeyBytes)
  if (
    value.signing?.algorithm !== 'Ed25519'
    || value.signing?.key_id !== identity.keyId
  ) {
    throw contractError(
      'HTTP_AUTHED_KEY_ID_MISMATCH',
      `${label} does not match the externally pinned key`,
    )
  }
  if (!verifyBytes(
    null,
    signingPayload(context, value),
    identity.key,
    decodeSignature(value),
  )) {
    throw contractError(
      'HTTP_AUTHED_SIGNATURE_INVALID',
      `${label} signature is invalid under the pinned key`,
    )
  }
  return identity
}

function signDocument({ value, privateKeyBytes, passphrase, context }) {
  const identity = parsePrivateKey(privateKeyBytes, passphrase)
  const prepared = {
    ...structuredClone(unsignedDocument(value)),
    signing: { algorithm: 'Ed25519', key_id: identity.keyId },
  }
  return {
    ...prepared,
    signature: {
      algorithm: 'Ed25519',
      value_base64: signBytes(
        null,
        signingPayload(context, prepared),
        identity.key,
      ).toString('base64'),
    },
  }
}

function parseExactTimestamp(value, label) {
  const timestamp = Date.parse(value)
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    throw contractError(
      'HTTP_AUTHED_TIME_INVALID',
      `${label} must be a real canonical UTC millisecond timestamp`,
    )
  }
  return timestamp
}

function assertSyntheticQueryValues(parsed, label) {
  for (const value of parsed.searchParams.values()) {
    if (!SYNTHETIC_PERSISTED_VALUE.test(value)) {
      throw contractError(
        'HTTP_AUTHED_QUERY_VALUE_NOT_SYNTHETIC',
        `${label} query values must use explicit SYNTHETIC_ non-PHI identifiers`,
      )
    }
  }
}

function assertUnderOrigin(url, originUrl, label) {
  let parsed
  try {
    parsed = new URL(url)
  } catch (error) {
    throw contractError(
      'HTTP_AUTHED_URL_INVALID',
      `${label} is not a valid URL`,
      [],
      { cause: error },
    )
  }
  if (parsed.username !== '' || parsed.password !== '') {
    throw contractError(
      'HTTP_AUTHED_URL_CREDENTIALS_REFUSED',
      `${label} must not contain URL credentials`,
    )
  }
  if (parsed.hash !== '') {
    throw contractError(
      'HTTP_AUTHED_URL_FRAGMENT_REFUSED',
      `${label} must not contain a URL fragment`,
    )
  }
  if (parsed.protocol !== 'https:' || parsed.origin !== originUrl.origin) {
    throw contractError(
      'HTTP_AUTHED_ACTION_ORIGIN_MISMATCH',
      `${label} must be an HTTPS URL under the sealed origin ${originUrl.origin}`,
    )
  }
  assertSyntheticQueryValues(parsed, label)
}

function assertCanonicalPathValue(value, label) {
  if (AMBIGUOUS_PATH_ENCODING.test(value)) {
    throw contractError(
      'HTTP_AUTHED_WRITTEN_PATH_NONCANONICAL',
      `${label} contains an encoded dot/separator or backslash`,
    )
  }
  const segments = value.split('/')
  if (segments.some((segment) => segment === '.' || segment === '..')) {
    throw contractError(
      'HTTP_AUTHED_WRITTEN_PATH_NONCANONICAL',
      `${label} contains a dot segment`,
    )
  }
}

function pathMatchesPrefix(pathname, prefix) {
  assertCanonicalPathValue(pathname, 'request path')
  assertCanonicalPathValue(prefix, 'authorized path prefix')
  if (prefix === '/') return true
  if (prefix.endsWith('/')) return pathname.startsWith(prefix)
  return pathname === prefix || pathname.startsWith(`${prefix}/`)
}

function requiresMutationPermission(action) {
  return action.kind === 'mutate'
    || (
      action.kind === 'probe'
      && (!STATE_SAFE_PROBE_METHODS.has(action.method) || action.request_body !== undefined)
    )
}

function assertBoundedResponseObservation(scope, action, label) {
  if (action.response_observation === undefined) return
  if (
    scope.schema_version !== '1.3.0'
    || scope.response_observation !== undefined
    || scope.discovery !== undefined
    || scope.requests.length !== 1
    || action.kind !== 'probe'
    || action.method !== 'GET'
    || action.request_body !== undefined
  ) {
    throw contractError(
      'HTTP_AUTHED_RESPONSE_OBSERVATION_SCOPE_INVALID',
      `${label} bounded response observation requires one exact bodyless GET probe`,
    )
  }
  try {
    resolveHttpReconResponseObservation({
      descriptor: action.response_observation,
      method: action.method,
      url: action.url,
      maxResponseBytes: scope.limits.max_response_bytes,
    })
  } catch (cause) {
    throw contractError(
      'HTTP_AUTHED_RESPONSE_OBSERVATION_SCOPE_INVALID',
      `${label} bounded response observation does not match its controller-owned profile`,
      [],
      { cause },
    )
  }
}

function assertCandidateResponseObservation(scope, action) {
  const sealed = scope.requests.find((request) => request.response_observation !== undefined)
  if (sealed === undefined && action.response_observation === undefined) return
  if (
    sealed === undefined
    || action.response_observation === undefined
    || canonicalJson(action) !== canonicalJson(sealed)
  ) {
    throw contractError(
      'HTTP_AUTHED_RESPONSE_OBSERVATION_CANDIDATE_MISMATCH',
      'runtime response-observation candidate does not match the one exact sealed action',
    )
  }
  assertBoundedResponseObservation(scope, action, 'runtime candidate')
}

function assertDeclaredRequestScope(scope, request, label) {
  const authorizedScope = scope.authorization.authorized_scope
  assertCanonicalPathValue(request.url, `${label} URL`)
  const url = new URL(request.url)
  if (url.username !== '' || url.password !== '') {
    throw contractError(
      'HTTP_AUTHED_URL_CREDENTIALS_REFUSED',
      `${label} must not contain URL credentials`,
    )
  }
  if (url.hash !== '') {
    throw contractError(
      'HTTP_AUTHED_URL_FRAGMENT_REFUSED',
      `${label} must not contain a URL fragment`,
    )
  }
  assertSyntheticQueryValues(url, label)
  if (!authorizedScope.origins.includes(url.origin)) {
    throw contractError(
      'HTTP_AUTHED_WRITTEN_ORIGIN_OUT_OF_SCOPE',
      `${label} origin is outside the sealed authorization scope`,
    )
  }
  if (!authorizedScope.methods.includes(request.method)) {
    throw contractError(
      'HTTP_AUTHED_WRITTEN_METHOD_OUT_OF_SCOPE',
      `${label} method is outside the sealed authorization scope`,
    )
  }
  if (!authorizedScope.path_prefixes.some((prefix) => pathMatchesPrefix(url.pathname, prefix))) {
    throw contractError(
      'HTTP_AUTHED_WRITTEN_PATH_OUT_OF_SCOPE',
      `${label} path is outside the sealed authorization scope`,
    )
  }
  if (
    request.test_category !== undefined
    && !authorizedScope.test_categories.includes(request.test_category)
  ) {
    throw contractError(
      'HTTP_AUTHED_WRITTEN_CATEGORY_OUT_OF_SCOPE',
      `${label} test category is outside the sealed authorization scope`,
    )
  }
}

function assertMutationSemantics(action, label) {
  if (action.expected_mutation.before_digest === action.expected_mutation.after_digest) {
    throw contractError(
      'HTTP_AUTHED_MUTATION_NO_STATE_CHANGE',
      `${label} must declare distinct before and after values`,
    )
  }
  if (action.rollback.expected_after_digest !== action.expected_mutation.before_digest) {
    throw contractError(
      'HTTP_AUTHED_ROLLBACK_TARGET_MISMATCH',
      `${label} rollback must restore the declared before value`,
    )
  }
  const pointer = action.expected_mutation.field
  for (const [name, read] of [
    ['before_read', action.before_read],
    ['after_read', action.after_read],
    ['rollback.verification_read', action.rollback.verification_read],
  ]) {
    if (read.observation.json_pointer !== pointer) {
      throw contractError(
        'HTTP_AUTHED_MUTATION_OBSERVATION_MISMATCH',
        `${label} ${name} must observe the declared mutation field`,
      )
    }
  }
}

function assertScopeSemantics(scope) {
  const tunnelMethod = scope.authorization.authorized_scope?.methods
    ?.find((method) => TUNNEL_METHODS.has(method))
  if (tunnelMethod !== undefined) {
    throw contractError(
      'HTTP_AUTHED_METHOD_UNSUPPORTED',
      'authenticated campaigns refuse CONNECT tunnels before network I/O',
    )
  }
  if (isHttpAuthedBrowserSessionCredential(scope.credential)) {
    if (scope.credential.origin !== scope.target.origin) {
      throw contractError(
        'HTTP_AUTHED_BROWSER_ORIGIN_MISMATCH',
        'the Chrome active-tab session origin must equal the sealed target origin',
      )
    }
    if (scope.target.tls.mode !== 'PKIX_HOSTNAME') {
      throw contractError(
        'HTTP_AUTHED_BROWSER_TLS_MODE_UNSUPPORTED',
        'the Chrome active-tab transport supports browser-verified PKIX hostname TLS only',
      )
    }
    const forbidden = scope.authorization.authorized_scope?.methods
      ?.find((method) => FETCH_FORBIDDEN_METHODS.has(method))
    if (forbidden !== undefined) {
      throw contractError(
        'HTTP_AUTHED_BROWSER_METHOD_UNSUPPORTED',
        'the Chrome active-tab transport cannot authorize CONNECT, TRACE, or TRACK',
      )
    }
  }

  if (scope.discovery !== undefined) {
    if (!isHttpAuthedRuntimeAuthorizationMode(scope.authorization.mode)) {
      throw contractError(
        'HTTP_AUTHED_DISCOVERY_DECLARED_SCOPE_REQUIRED',
        'automated discovery requires an operator-attested or document-bound declared scope',
      )
    }
    const authorized = scope.authorization.authorized_scope
    if (
      scope.discovery.origin !== scope.target.origin
      || !authorized.origins.includes(scope.discovery.origin)
    ) {
      throw contractError(
        'HTTP_AUTHED_DISCOVERY_ORIGIN_OUT_OF_SCOPE',
        'discovery origin must equal the sealed target and authorized origin',
      )
    }
    if (scope.discovery.candidate_methods.some((method) => !authorized.methods.includes(method))) {
      throw contractError(
        'HTTP_AUTHED_DISCOVERY_METHOD_OUT_OF_SCOPE',
        'discovery methods must be a subset of the authorized methods',
      )
    }
    if (!authorized.test_categories.includes(scope.discovery.test_category)) {
      throw contractError(
        'HTTP_AUTHED_DISCOVERY_CATEGORY_OUT_OF_SCOPE',
        'discovery category must be listed in the authorized test categories',
      )
    }
    if (scope.discovery.path_prefixes.some((candidatePrefix) => (
      !authorized.path_prefixes.some((authorizedPrefix) => (
        pathMatchesPrefix(candidatePrefix, authorizedPrefix)
      ))
    ))) {
      throw contractError(
        'HTTP_AUTHED_DISCOVERY_PATH_OUT_OF_SCOPE',
        'discovery path prefixes must be within the authorized path prefixes',
      )
    }
    if (scope.discovery.max_response_bytes > scope.limits.max_response_bytes) {
      throw contractError(
        'HTTP_AUTHED_DISCOVERY_RESPONSE_LIMIT_WIDENED',
        'discovery response bytes cannot exceed the sealed per-request response limit',
      )
    }
  }

  if (isHttpAuthedRuntimeAuthorizationMode(scope.authorization.mode)) {
    const written = scope.authorization.mode === 'WRITTEN_AUTHORIZATION_AUTHED'
    const permissions = scope.authorization.permissions
    const requiredPermissions = [['active_testing', 'active testing']]
    if (scope.environment === 'production') {
      requiredPermissions.push(['production', 'production testing'])
    }
    if (scope.target.ownership === 'third_party_owned') {
      requiredPermissions.push(['third_party', 'third-party testing'])
    }
    if (scope.data_class === 'phi' || scope.data_class === 'unknown') {
      requiredPermissions.push(['phi', 'PHI-sensitive testing'])
    }
    if (scope.requests.some(requiresMutationPermission)) {
      requiredPermissions.push(['mutation', 'mutation testing'])
    }
    for (const [field, label] of requiredPermissions) {
      if (permissions[field] !== true) {
        throw contractError(
          written
            ? 'HTTP_AUTHED_WRITTEN_PERMISSION_MISSING'
            : 'HTTP_AUTHED_ATTESTED_PERMISSION_MISSING',
          `${written ? 'written authorization' : 'operator attestation'} must explicitly permit ${label}`,
        )
      }
    }

    const authorizedScope = scope.authorization.authorized_scope
    if (!authorizedScope.origins.includes(scope.target.origin)) {
      throw contractError(
        written
          ? 'HTTP_AUTHED_WRITTEN_ORIGIN_OUT_OF_SCOPE'
          : 'HTTP_AUTHED_ATTESTED_ORIGIN_OUT_OF_SCOPE',
        `sealed target origin is outside the ${written ? 'written authorization' : 'operator-attested'} scope`,
      )
    }
    assertDeclaredRequestScope(
      scope,
      scope.liveness.credential_preflight,
      'liveness.credential_preflight',
    )
    scope.requests.forEach((action, index) => {
      assertDeclaredRequestScope(scope, action, `requests[${index}]`)
      assertBoundedResponseObservation(scope, action, `requests[${index}]`)
      if (action.kind === 'mutate') {
        assertMutationSemantics(action, `requests[${index}]`)
        assertDeclaredRequestScope(scope, action.before_read, `requests[${index}].before_read`)
        assertDeclaredRequestScope(scope, action.after_read, `requests[${index}].after_read`)
        assertDeclaredRequestScope(scope, action.rollback, `requests[${index}].rollback`)
        assertDeclaredRequestScope(
          scope,
          action.rollback.verification_read,
          `requests[${index}].rollback.verification_read`,
        )
      }
    })

    if (written) {
      const issuedAt = parseExactTimestamp(
        scope.authorization.document_issued_at,
        'authorization.document_issued_at',
      )
      const attestedAt = parseExactTimestamp(
        scope.authorization.attested_at,
        'authorization.attested_at',
      )
      if (issuedAt > attestedAt) {
        throw contractError(
          'HTTP_AUTHED_WRITTEN_DOCUMENT_TIME_INVALID',
          'written authorization cannot be issued after the operator attestation',
        )
      }
    }
  }

  // Four-eyes on production: the owner (RoE signer) and the approver
  // (per-action countersigner) must be distinct keys. Enforced here because
  // JSON Schema cannot express cross-field inequality without $data.
  if (
    scope.environment === 'production'
    && scope.approver
    && scope.authorization.owner_key_id
    && scope.authorization.owner_key_id === scope.approver.key_id
  ) {
    throw contractError(
      'HTTP_AUTHED_APPROVER_NOT_INDEPENDENT',
      'production requires owner_key_id to differ from approver.key_id (four-eyes)',
    )
  }

  // A file-based approver key_id must equal ed25519:sha256(spki) of its public key.
  if (scope.approver?.mechanism === 'ed25519_file') {
    const spkiDer = Buffer.from(scope.approver.public_key.value_base64, 'base64')
    let fingerprint = null
    try {
      fingerprint = parsePublicKey(spkiDer).keyId
    } catch {
      fingerprint = null
    }
    if (!fingerprint || fingerprint !== scope.approver.key_id) {
      throw contractError(
        'HTTP_AUTHED_APPROVER_KEY_MISMATCH',
        'approver.key_id must equal ed25519:sha256(spki) of approver.public_key',
      )
    }
  }

  const notBefore = parseExactTimestamp(scope.validity.not_before, 'validity.not_before')
  const notAfter = parseExactTimestamp(scope.validity.not_after, 'validity.not_after')
  const cleanupNotAfter = parseExactTimestamp(
    scope.validity.cleanup_not_after,
    'validity.cleanup_not_after',
  )
  if (notBefore >= notAfter) {
    throw contractError(
      'HTTP_AUTHED_VALIDITY_WINDOW_INVALID',
      'validity must be increasing',
    )
  }
  if (notAfter > cleanupNotAfter) {
    throw contractError(
      'HTTP_AUTHED_CLEANUP_WINDOW_INVALID',
      'validity.cleanup_not_after must be at or after validity.not_after',
    )
  }
  if (isHttpAuthedRuntimeAuthorizationMode(scope.authorization.mode)) {
    const attestedAt = parseExactTimestamp(
      scope.authorization.attested_at,
      'authorization.attested_at',
    )
    if (attestedAt < notBefore || attestedAt >= notAfter) {
      throw contractError(
        'HTTP_AUTHED_ATTESTATION_WINDOW_INVALID',
        'authorization attestation must fall inside the sealed validity window',
      )
    }
  }

  const originUrl = new URL(scope.target.origin)
  if (originUrl.username !== '' || originUrl.password !== '') {
    throw contractError(
      'HTTP_AUTHED_URL_CREDENTIALS_REFUSED',
      'target.origin must not contain URL credentials',
    )
  }
  if (originUrl.hash !== '') {
    throw contractError(
      'HTTP_AUTHED_URL_FRAGMENT_REFUSED',
      'target.origin must not contain a URL fragment',
    )
  }
  for (const authorizedOrigin of scope.authorization.authorized_scope?.origins ?? []) {
    const authorizedUrl = new URL(authorizedOrigin)
    if (authorizedUrl.username !== '' || authorizedUrl.password !== '') {
      throw contractError(
        'HTTP_AUTHED_URL_CREDENTIALS_REFUSED',
        'authorization origins must not contain URL credentials',
      )
    }
    if (authorizedUrl.hash !== '') {
      throw contractError(
        'HTTP_AUTHED_URL_FRAGMENT_REFUSED',
        'authorization origins must not contain URL fragments',
      )
    }
  }
  scope.requests.forEach((action, index) => {
    if (action.sequence !== index + 1) {
      throw contractError(
        'HTTP_AUTHED_ACTION_ORDER_INVALID',
        'action sequence numbers must be contiguous starting at 1',
      )
    }
    assertUnderOrigin(action.url, originUrl, `requests[${index}].url`)
    if (action.kind === 'mutate') {
      assertUnderOrigin(action.before_read.url, originUrl, `requests[${index}].before_read.url`)
      assertUnderOrigin(action.after_read.url, originUrl, `requests[${index}].after_read.url`)
      assertUnderOrigin(action.rollback.url, originUrl, `requests[${index}].rollback.url`)
      assertUnderOrigin(
        action.rollback.verification_read.url,
        originUrl,
        `requests[${index}].rollback.verification_read.url`,
      )
    }
  })

  return scope
}

export function validateHttpAuthedScope(value) {
  const valid = validateScopeSchema(value)
  return { valid, errors: valid ? [] : normalizeAjvErrors(validateScopeSchema.errors) }
}

export function assertValidHttpAuthedScope(value) {
  assertSchema(validateScopeSchema, value, 'http-authed scope')
  return assertScopeSemantics(value)
}

function assertHttpAuthedCandidateWithinScope({ scope, action }) {
  if (!isHttpAuthedRuntimeAuthorizationMode(scope.authorization.mode)) {
    throw contractError(
      'HTTP_AUTHED_RUNTIME_MODE_REQUIRED',
      'runtime campaign candidate validation requires operator-attested or written authorization',
    )
  }
  assertSchema(validateActionSchema, action, 'http-authed runtime candidate')
  assertCandidateResponseObservation(scope, action)
  const originUrl = new URL(scope.target.origin)
  assertUnderOrigin(action.url, originUrl, 'runtime candidate url')
  assertDeclaredRequestScope(scope, action, 'runtime candidate')
  if (requiresMutationPermission(action) && scope.authorization.permissions.mutation !== true) {
    const written = scope.authorization.mode === 'WRITTEN_AUTHORIZATION_AUTHED'
    throw contractError(
      written
        ? 'HTTP_AUTHED_WRITTEN_PERMISSION_MISSING'
        : 'HTTP_AUTHED_ATTESTED_PERMISSION_MISSING',
      `${written ? 'written authorization' : 'operator attestation'} must explicitly permit mutation testing for write-capable or body-bearing probes`,
    )
  }
  if (action.kind === 'mutate') {
    assertMutationSemantics(action, 'runtime candidate')
    assertUnderOrigin(action.before_read.url, originUrl, 'runtime candidate before_read url')
    assertUnderOrigin(action.after_read.url, originUrl, 'runtime candidate after_read url')
    assertUnderOrigin(action.rollback.url, originUrl, 'runtime candidate rollback url')
    assertUnderOrigin(
      action.rollback.verification_read.url,
      originUrl,
      'runtime candidate rollback.verification_read url',
    )
    assertDeclaredRequestScope(scope, action.before_read, 'runtime candidate before_read')
    assertDeclaredRequestScope(scope, action.after_read, 'runtime candidate after_read')
    assertDeclaredRequestScope(scope, action.rollback, 'runtime candidate rollback')
    assertDeclaredRequestScope(
      scope,
      action.rollback.verification_read,
      'runtime candidate rollback.verification_read',
    )
  }
  return action
}

export function httpAuthedAuthorizationBindingSha256(scope) {
  const mode = scope?.authorization?.mode
  if (mode === 'WRITTEN_AUTHORIZATION_AUTHED') {
    return scope.authorization.written_authorization_sha256
  }
  if (mode === 'OPERATOR_ATTESTED_AUTHED') {
    return sha256Hex(Buffer.from(
      `red-team-audit/http-authed-operator-attestation/v1\0${canonicalJson(scope.authorization)}`,
      'utf8',
    ))
  }
  throw contractError(
    'HTTP_AUTHED_RUNTIME_MODE_REQUIRED',
    'authorization binding requires operator-attested or written authorization',
  )
}

function verifyHttpAuthedAuthorizationForPurpose({
  scope,
  documentBytes,
  now,
  cleanupOnly,
}) {
  assertValidHttpAuthedScope(scope)
  if (!isHttpAuthedRuntimeAuthorizationMode(scope.authorization.mode)) {
    throw contractError(
      'HTTP_AUTHED_RUNTIME_MODE_REQUIRED',
      'runtime verification requires operator-attested or written authorization',
    )
  }
  const written = scope.authorization.mode === 'WRITTEN_AUTHORIZATION_AUTHED'
  let authorizationDocumentSha256
  if (written) {
    if (!(Buffer.isBuffer(documentBytes) || documentBytes instanceof Uint8Array)) {
      throw contractError(
        'HTTP_AUTHED_WRITTEN_DOCUMENT_INVALID',
        'written authorization document must be supplied as bytes',
      )
    }
    const bytes = Buffer.from(documentBytes)
    if (bytes.length === 0 || bytes.length > MAX_WRITTEN_AUTHORIZATION_BYTES) {
      throw contractError(
        'HTTP_AUTHED_WRITTEN_DOCUMENT_INVALID',
        `written authorization document must contain 1 to ${MAX_WRITTEN_AUTHORIZATION_BYTES} bytes`,
      )
    }
    authorizationDocumentSha256 = sha256Hex(bytes)
    if (authorizationDocumentSha256 !== scope.authorization.written_authorization_sha256) {
      throw contractError(
        'HTTP_AUTHED_WRITTEN_DOCUMENT_DIGEST_MISMATCH',
        'written authorization document digest does not match the sealed scope',
      )
    }
  } else if (documentBytes !== undefined) {
    throw contractError(
      'HTTP_AUTHED_ATTESTED_DOCUMENT_REFUSED',
      'operator-attested authorization must not be represented as a written authorization document',
    )
  }

  const current = now instanceof Date ? now.getTime() : new Date(now).getTime()
  if (!Number.isFinite(current)) {
    throw contractError('HTTP_AUTHED_TIME_INVALID', 'verification time must be valid')
  }
  const notBefore = parseExactTimestamp(scope.validity.not_before, 'validity.not_before')
  const notAfter = parseExactTimestamp(scope.validity.not_after, 'validity.not_after')
  const cleanupNotAfter = parseExactTimestamp(
    scope.validity.cleanup_not_after,
    'validity.cleanup_not_after',
  )
  const attestedAt = parseExactTimestamp(
    scope.authorization.attested_at,
    'authorization.attested_at',
  )
  if (attestedAt > current) {
    throw contractError(
      'HTTP_AUTHED_ATTESTATION_FUTURE',
      'authorization attestation cannot be in the future at verification time',
    )
  }
  if (current < notBefore) {
    throw contractError(
      'HTTP_AUTHED_AUTHORIZATION_NOT_YET_VALID',
      'authenticated campaign validity window has not started',
    )
  }
  if (cleanupOnly ? current >= cleanupNotAfter : current >= notAfter) {
    throw contractError(
      cleanupOnly
        ? 'HTTP_AUTHED_CLEANUP_AUTHORIZATION_EXPIRED'
        : 'HTTP_AUTHED_AUTHORIZATION_EXPIRED',
      cleanupOnly
        ? 'authenticated campaign cleanup window has expired'
        : 'authenticated campaign validity window has expired',
    )
  }
  return {
    scope,
    authorizationBindingSha256: httpAuthedAuthorizationBindingSha256(scope),
    ...(authorizationDocumentSha256 === undefined
      ? {}
      : { authorizationDocumentSha256 }),
    campaignGrantSha256: sha256Hex(canonicalJson(scope)),
  }
}

export function verifyHttpAuthedAuthorization({ scope, documentBytes, now = new Date() }) {
  return verifyHttpAuthedAuthorizationForPurpose({
    scope,
    documentBytes,
    now,
    cleanupOnly: false,
  })
}

export function verifyHttpAuthedWrittenAuthorization({ scope, documentBytes, now = new Date() }) {
  if (scope?.authorization?.mode !== 'WRITTEN_AUTHORIZATION_AUTHED') {
    throw contractError(
      'HTTP_AUTHED_WRITTEN_MODE_REQUIRED',
      'written authorization verification requires WRITTEN_AUTHORIZATION_AUTHED mode',
    )
  }
  return verifyHttpAuthedAuthorization({ scope, documentBytes, now })
}

export function verifyHttpAuthedCandidate({
  scope,
  action,
  documentBytes,
  expectedCampaignGrantSha256,
  now = new Date(),
}) {
  if (!/^[a-f0-9]{64}$/.test(expectedCampaignGrantSha256 ?? '')) {
    throw contractError(
      'HTTP_AUTHED_CAMPAIGN_GRANT_REQUIRED',
      'runtime candidate verification requires the controller-held campaign grant digest',
    )
  }
  const verified = verifyHttpAuthedAuthorization({ scope, documentBytes, now })
  if (verified.campaignGrantSha256 !== expectedCampaignGrantSha256) {
    throw contractError(
      'HTTP_AUTHED_CAMPAIGN_GRANT_MISMATCH',
      'current campaign scope does not match the controller-held campaign grant digest',
    )
  }
  assertHttpAuthedCandidateWithinScope({ scope, action })
  return {
    action,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    ...(verified.authorizationDocumentSha256 === undefined
      ? {}
      : { authorizationDocumentSha256: verified.authorizationDocumentSha256 }),
    campaignGrantSha256: verified.campaignGrantSha256,
  }
}

/**
 * Verify only the authorization envelope for an already-dispatched reversible
 * mutation's cleanup phases. This deliberately does not admit probes or a new
 * mutation dispatch; the mutation controller must additionally prove the
 * matching consumed lease from the durable campaign ledger.
 */
export function verifyHttpAuthedCleanupCandidate({
  scope,
  action,
  documentBytes,
  expectedCampaignGrantSha256,
  now = new Date(),
}) {
  if (!/^[a-f0-9]{64}$/.test(expectedCampaignGrantSha256 ?? '')) {
    throw contractError(
      'HTTP_AUTHED_CAMPAIGN_GRANT_REQUIRED',
      'cleanup verification requires the controller-held campaign grant digest',
    )
  }
  if (
    action?.kind !== 'mutate'
    || action.rollback_policy !== 'ALWAYS'
    || action.rollback?.idempotent_restore !== true
  ) {
    throw contractError(
      'HTTP_AUTHED_CLEANUP_ACTION_INVALID',
      'cleanup verification admits only an already-dispatched always-on idempotent mutation restore',
    )
  }
  const verified = verifyHttpAuthedAuthorizationForPurpose({
    scope,
    documentBytes,
    now,
    cleanupOnly: true,
  })
  if (verified.campaignGrantSha256 !== expectedCampaignGrantSha256) {
    throw contractError(
      'HTTP_AUTHED_CAMPAIGN_GRANT_MISMATCH',
      'current cleanup scope does not match the controller-held campaign grant digest',
    )
  }
  assertHttpAuthedCandidateWithinScope({ scope, action })
  return {
    action,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    ...(verified.authorizationDocumentSha256 === undefined
      ? {}
      : { authorizationDocumentSha256: verified.authorizationDocumentSha256 }),
    campaignGrantSha256: verified.campaignGrantSha256,
    cleanupOnly: true,
  }
}

export function verifyHttpAuthedWrittenCandidate(input) {
  if (input?.scope?.authorization?.mode !== 'WRITTEN_AUTHORIZATION_AUTHED') {
    throw contractError(
      'HTTP_AUTHED_WRITTEN_MODE_REQUIRED',
      'written candidate verification requires WRITTEN_AUTHORIZATION_AUTHED mode',
    )
  }
  return verifyHttpAuthedCandidate(input)
}

async function readStableBoundedFile(path, { label, maxBytes }) {
  const info = await lstat(path)
  if (!info.isFile() || info.isSymbolicLink() || info.size < 1 || info.size > maxBytes) {
    throw contractError(
      'HTTP_AUTHED_INPUT_FILE_UNSAFE',
      `${label} must be a regular non-symlink file containing 1 to ${maxBytes} bytes`,
    )
  }
  const handle = await open(path, OPEN_READ_ONLY_NO_FOLLOW)
  try {
    const before = await handle.stat()
    const bytes = await handle.readFile()
    const after = await handle.stat()
    if (
      before.size !== after.size
      || before.mtimeMs !== after.mtimeMs
      || before.ino !== after.ino
      || bytes.length !== after.size
    ) {
      throw contractError(
        'HTTP_AUTHED_INPUT_FILE_CHANGED',
        `${label} changed while it was read`,
      )
    }
    return bytes
  } finally {
    await handle.close()
  }
}

export async function readAndVerifyHttpAuthedWrittenAuthorization({
  scopePath,
  authorizationDocumentPath,
  now = new Date(),
}) {
  return readAndVerifyHttpAuthedAuthorization({
    scopePath,
    authorizationDocumentPath,
    requiredMode: 'WRITTEN_AUTHORIZATION_AUTHED',
    now,
  })
}

export async function readAndVerifyHttpAuthedAuthorization({
  scopePath,
  authorizationDocumentPath,
  requiredMode,
  now = new Date(),
}) {
  const scopeBytes = await readStableBoundedFile(scopePath, {
    label: 'http-authed scope',
    maxBytes: MAX_WRITTEN_SCOPE_BYTES,
  })
  let scope
  try {
    scope = JSON.parse(scopeBytes.toString('utf8'))
  } catch (error) {
    throw contractError(
      'HTTP_AUTHED_SCOPE_JSON_INVALID',
      `http-authed scope is not valid JSON: ${error.message}`,
      [],
      { cause: error },
    )
  }
  if (requiredMode !== undefined && scope.authorization?.mode !== requiredMode) {
    throw contractError(
      'HTTP_AUTHED_AUTHORIZATION_MODE_MISMATCH',
      'scope authorization mode does not match the selected command',
    )
  }
  let documentBytes
  if (scope.authorization?.mode === 'WRITTEN_AUTHORIZATION_AUTHED') {
    if (typeof authorizationDocumentPath !== 'string' || authorizationDocumentPath.length === 0) {
      throw contractError(
        'HTTP_AUTHED_WRITTEN_DOCUMENT_INVALID',
        'written authorization document path is required',
      )
    }
    documentBytes = await readStableBoundedFile(authorizationDocumentPath, {
      label: 'written authorization document',
      maxBytes: MAX_WRITTEN_AUTHORIZATION_BYTES,
    })
  } else if (authorizationDocumentPath !== undefined) {
    throw contractError(
      'HTTP_AUTHED_ATTESTED_DOCUMENT_REFUSED',
      'operator-attested authorization does not accept an authorization document path',
    )
  }
  return verifyHttpAuthedAuthorization({ scope, documentBytes, now })
}

// --- Owner RoE signing / verification -------------------------------------

export function signHttpAuthedRoe({ roe, privateKeyBytes, passphrase }) {
  return signDocument({
    value: roe,
    privateKeyBytes,
    passphrase,
    context: ROE_SIGNATURE_CONTEXT,
  })
}

export function verifyHttpAuthedRoeSignature({ roe, ownerPublicKeyBytes }) {
  return verifySignedDocument({
    value: roe,
    publicKeyBytes: ownerPublicKeyBytes,
    context: ROE_SIGNATURE_CONTEXT,
    label: 'signed authed RoE',
  })
}

// --- Per-action approver countersignature ---------------------------------

function actionIdentityInput(action) {
  const candidate = structuredClone(action)
  delete candidate.sequence
  delete candidate.action_id
  delete candidate.countersignature
  return candidate
}

export function actionCandidateSha256(action) {
  return sha256Hex(canonicalJson(actionIdentityInput(action)))
}

export function actionId(action) {
  return `http-authed-action:${actionCandidateSha256(action)}`
}

export function httpAuthedCampaignLedgerBindingSha256(directory) {
  if (!isAbsolute(directory ?? '')) {
    throw contractError(
      'HTTP_AUTHED_CAMPAIGN_LEDGER_DIRECTORY_INVALID',
      'campaign ledger binding requires an absolute directory',
    )
  }
  const canonicalDirectory = process.platform === 'win32'
    ? resolve(directory).replaceAll('\\', '/').toLowerCase()
    : resolve(directory)
  return sha256Hex(Buffer.from(
    `red-team-audit/http-authed-campaign-ledger-binding/v1\0${canonicalDirectory}`,
    'utf8',
  ))
}

export function buildActionCountersignaturePayload({
  action,
  planSha256,
  campaignLedgerSha256,
  nonce,
  at,
}) {
  if (!/^[a-f0-9]{64}$/.test(campaignLedgerSha256 ?? '')) {
    throw contractError(
      'HTTP_AUTHED_CAMPAIGN_LEDGER_BINDING_INVALID',
      'countersignature requires a campaign ledger binding digest',
    )
  }
  return {
    kind: 'red-team-audit/http-authed-countersignature',
    action_id: action.action_id ?? actionId(action),
    candidate_sha256: actionCandidateSha256(action),
    method: action.method,
    url: action.url,
    expected_mutation_sha256: sha256Hex(canonicalJson(action.expected_mutation)),
    rollback_sha256: sha256Hex(canonicalJson(action.rollback)),
    plan_sha256: planSha256,
    campaign_ledger_sha256: campaignLedgerSha256,
    nonce,
    at,
  }
}

export function signHttpAuthedActionCountersignature({ payload, privateKeyBytes, passphrase }) {
  return signDocument({
    value: payload,
    privateKeyBytes,
    passphrase,
    context: COUNTERSIGN_CONTEXT,
  })
}

export function verifyHttpAuthedActionCountersignature({
  countersignature,
  approverPublicKeyBytes,
  expected,
  now = new Date(),
  maxAgeMs = 300000,
}) {
  const identity = verifySignedDocument({
    value: countersignature,
    publicKeyBytes: approverPublicKeyBytes,
    context: COUNTERSIGN_CONTEXT,
    label: 'action countersignature',
  })
  for (const field of [
    'action_id',
    'candidate_sha256',
    'method',
    'url',
    'expected_mutation_sha256',
    'rollback_sha256',
    'plan_sha256',
    'campaign_ledger_sha256',
  ]) {
    if (expected[field] !== undefined && countersignature[field] !== expected[field]) {
      throw contractError(
        'HTTP_AUTHED_COUNTERSIGN_BINDING_MISMATCH',
        `countersignature ${field} does not match the sealed action`,
      )
    }
  }
  const signedAt = parseExactTimestamp(countersignature.at, 'countersignature.at')
  const current = now instanceof Date ? now.getTime() : new Date(now).getTime()
  if (!Number.isFinite(current) || signedAt > current || current - signedAt > maxAgeMs) {
    throw contractError(
      'HTTP_AUTHED_COUNTERSIGN_STALE',
      'action countersignature is not fresh at verification time',
    )
  }
  return identity
}

// --- WebAuthn approver (deferred) -----------------------------------------

export function verifyWebauthnAssertion() {
  // ADR 0016 lists a WebAuthn/passkey approver as the recommended production
  // path, but this engagement selected the ed25519_file approver. The COSE
  // clientDataJSON/authenticatorData verifier is intentionally not implemented
  // here yet so no half-built crypto path ships.
  throw contractError(
    'HTTP_AUTHED_WEBAUTHN_NOT_IMPLEMENTED',
    'WebAuthn approver path is deferred (ed25519_file approver selected); see ADR 0016 future work',
  )
}
