import { constants as fsConstants, readFileSync } from 'node:fs'
import { lstat, open } from 'node:fs/promises'
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as signBytes,
  verify as verifyBytes,
} from 'node:crypto'
import { isIP } from 'node:net'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import { stableJson } from './run-engine.mjs'

const ROE_SCHEMA_URL = new URL('../../schemas/http-recon-roe.schema.json', import.meta.url)
const PROOF_SCHEMA_URL = new URL(
  '../../schemas/http-recon-target-proof.schema.json',
  import.meta.url,
)
const ATTESTED_SCOPE_SCHEMA_URL = new URL(
  '../../schemas/http-recon-attested-scope.schema.json',
  import.meta.url,
)
const RUN_SCHEMA_URL = new URL('../../schemas/http-recon-run.schema.json', import.meta.url)
const OBSERVATION_SCHEMA_URL = new URL(
  '../../schemas/http-recon-observation.schema.json',
  import.meta.url,
)
const ROE_SIGNATURE_CONTEXT = Buffer.from(
  'red-team-audit/http-recon-roe/v1\u0000',
  'utf8',
)
const PROOF_SIGNATURE_CONTEXT = Buffer.from(
  'red-team-audit/http-recon-target-proof/v1\u0000',
  'utf8',
)
const MAX_ROE_BYTES = 1024 * 1024
const OPEN_READ_ONLY_NO_FOLLOW = fsConstants.O_RDONLY
  | (typeof fsConstants.O_NOFOLLOW === 'number' ? fsConstants.O_NOFOLLOW : 0)

export const OPERATOR_ATTESTED_AUTHORIZATION_STATEMENT =
  'I confirm that I am authorized by the asset owner to perform this exact bounded HTTP reconnaissance action.'

export const OPERATOR_ATTESTED_LIMITS = Object.freeze({
  max_probe_requests: 1,
  max_target_proof_requests: 0,
  max_target_proof_response_bytes: 0,
  request_timeout_ms: 10_000,
  max_response_bytes: 1_048_576,
  max_aggregate_response_bytes: 1_048_576,
  max_wall_time_ms: 900_000,
  min_interval_ms: 1_000,
  concurrency: 1,
})

export const httpReconRoeSchema = JSON.parse(
  readFileSync(fileURLToPath(ROE_SCHEMA_URL), 'utf8'),
)
export const httpReconTargetProofSchema = JSON.parse(
  readFileSync(fileURLToPath(PROOF_SCHEMA_URL), 'utf8'),
)
export const httpReconAttestedScopeSchema = JSON.parse(
  readFileSync(fileURLToPath(ATTESTED_SCOPE_SCHEMA_URL), 'utf8'),
)
export const httpReconRunSchema = JSON.parse(
  readFileSync(fileURLToPath(RUN_SCHEMA_URL), 'utf8'),
)
export const httpReconObservationSchema = JSON.parse(
  readFileSync(fileURLToPath(OBSERVATION_SCHEMA_URL), 'utf8'),
)

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})
for (const schema of [
  httpReconRoeSchema,
  httpReconTargetProofSchema,
  httpReconAttestedScopeSchema,
  httpReconRunSchema,
  httpReconObservationSchema,
]) {
  ajv.addSchema(schema)
}
const validateRoeSchema = ajv.getSchema(httpReconRoeSchema.$id)
const validateProofSchema = ajv.getSchema(httpReconTargetProofSchema.$id)
const validateAttestedScopeSchema = ajv.getSchema(httpReconAttestedScopeSchema.$id)
const validateRunSchema = ajv.getSchema(httpReconRunSchema.$id)
const validateObservationSchema = ajv.getSchema(httpReconObservationSchema.$id)

export class HttpReconContractError extends Error {
  constructor(code, message, details = [], options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'HttpReconContractError'
    this.code = code
    this.details = details
  }
}

function contractError(code, message, details, options) {
  return new HttpReconContractError(code, message, details, options)
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
      'HTTP_RECON_SCHEMA_INVALID',
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
      'HTTP_RECON_KEY_INVALID',
      'authorized HTTP-recon owner key must be Ed25519',
    )
  }
  const spki = key.export({ type: 'spki', format: 'der' })
  return { key, keyId: `ed25519:${sha256Hex(spki)}` }
}

function parsePublicKey(keyBytes) {
  try {
    return publicKeyIdentity(createPublicKey(keyBytes))
  } catch (error) {
    if (error instanceof HttpReconContractError) throw error
    throw contractError(
      'HTTP_RECON_KEY_INVALID',
      `cannot parse externally pinned owner public key: ${error.message}`,
      [],
      { cause: error },
    )
  }
}

function parsePrivateKey(keyBytes) {
  try {
    const key = createPrivateKey(keyBytes)
    if (key.asymmetricKeyType !== 'ed25519') {
      throw contractError(
        'HTTP_RECON_KEY_INVALID',
        'authorized HTTP-recon signing key must be Ed25519',
      )
    }
    const identity = publicKeyIdentity(createPublicKey(key))
    return { key, keyId: identity.keyId }
  } catch (error) {
    if (error instanceof HttpReconContractError) throw error
    throw contractError(
      'HTTP_RECON_KEY_INVALID',
      `cannot parse HTTP-recon signing key: ${error.message}`,
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
      'HTTP_RECON_SIGNATURE_INVALID',
      'HTTP-recon signature must be canonical base64 Ed25519 data',
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
      'HTTP_RECON_KEY_ID_MISMATCH',
      `${label} does not match the externally pinned owner key`,
    )
  }
  if (!verifyBytes(
    null,
    signingPayload(context, value),
    identity.key,
    decodeSignature(value),
  )) {
    throw contractError(
      'HTTP_RECON_SIGNATURE_INVALID',
      `${label} signature is invalid under the externally pinned owner key`,
    )
  }
  return identity
}

function signDocument({ value, privateKeyBytes, context }) {
  const identity = parsePrivateKey(privateKeyBytes)
  const prepared = {
    ...structuredClone(unsignedDocument(value)),
    signing: {
      algorithm: 'Ed25519',
      key_id: identity.keyId,
    },
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
      'HTTP_RECON_TIME_INVALID',
      `${label} must be a real canonical UTC millisecond timestamp`,
    )
  }
  return timestamp
}

function assertNoAmbiguousPath(url, label) {
  if (
    url.pathname.includes('\\')
    || /%(?:2e|2f|5c)/i.test(url.pathname)
    || url.pathname.split('/').some((part) => part === '.' || part === '..')
  ) {
    throw contractError(
      'HTTP_RECON_URL_AMBIGUOUS',
      `${label} contains an ambiguous path encoding`,
    )
  }
}

function parseExactHttpsUrl(value, label, { originOnly = false } = {}) {
  let url
  try {
    url = new URL(value)
  } catch (error) {
    throw contractError(
      'HTTP_RECON_URL_INVALID',
      `${label} is not a valid URL`,
      [],
      { cause: error },
    )
  }
  if (
    url.protocol !== 'https:'
    || url.username !== ''
    || url.password !== ''
    || url.hash !== ''
    || url.search !== ''
    || isIP(url.hostname) !== 0
    || url.hostname.endsWith('.')
    || url.hostname.includes('*')
  ) {
    throw contractError(
      'HTTP_RECON_URL_SCOPE_INVALID',
      `${label} must be one credential-free, non-IP HTTPS URL without query or fragment`,
    )
  }
  if (originOnly) {
    if (value !== url.origin || url.pathname !== '/') {
      throw contractError(
        'HTTP_RECON_ORIGIN_NOT_CANONICAL',
        `${label} must be an exact canonical HTTPS origin without a trailing slash`,
      )
    }
  } else if (value !== url.href) {
    throw contractError(
      'HTTP_RECON_URL_NOT_CANONICAL',
      `${label} must equal its canonical URL serialization`,
    )
  }
  assertNoAmbiguousPath(url, label)
  return url
}

function assertRoeSemantics(roe, { now, requireCurrentValidity = true } = {}) {
  const targetOrigin = parseExactHttpsUrl(
    roe.target.origin,
    'target.origin',
    { originOnly: true },
  )
  const proofUrl = parseExactHttpsUrl(roe.target.proof.url, 'target.proof.url')
  if (proofUrl.origin !== targetOrigin.origin) {
    throw contractError(
      'HTTP_RECON_PROOF_ORIGIN_MISMATCH',
      'target proof URL must use the exact signed target origin',
    )
  }
  const seen = new Set()
  for (const [index, request] of roe.requests.entries()) {
    const url = parseExactHttpsUrl(request.url, `requests[${index}].url`)
    if (url.origin !== targetOrigin.origin) {
      throw contractError(
        'HTTP_RECON_ACTION_ORIGIN_MISMATCH',
        `requests[${index}] does not use the exact signed target origin`,
      )
    }
    if (request.url === roe.target.proof.url) {
      throw contractError(
        'HTTP_RECON_PROOF_ACTION_OVERLAP',
        'target proof URL cannot also be a probe action',
      )
    }
    const tuple = `${request.method}\u0000${request.url}`
    if (seen.has(tuple)) {
      throw contractError(
        'HTTP_RECON_ACTION_DUPLICATE',
        `requests[${index}] duplicates an earlier exact action`,
      )
    }
    seen.add(tuple)
  }
  if (
    roe.limits.max_probe_requests !== roe.requests.length
    || roe.limits.max_target_proof_requests !== roe.requests.length
  ) {
    throw contractError(
      'HTTP_RECON_DENOMINATOR_LIMIT_MISMATCH',
      'probe and target-proof request limits must equal the exact signed action count',
    )
  }
  const notBefore = parseExactTimestamp(roe.validity.not_before, 'validity.not_before')
  const notAfter = parseExactTimestamp(roe.validity.not_after, 'validity.not_after')
  if (
    notBefore >= notAfter
    || notAfter - notBefore > roe.limits.max_wall_time_ms
  ) {
    throw contractError(
      'HTTP_RECON_VALIDITY_WINDOW_INVALID',
      'RoE validity must be increasing and no longer than max_wall_time_ms',
    )
  }
  if (requireCurrentValidity) {
    const current = now instanceof Date ? now.getTime() : new Date(now).getTime()
    if (!Number.isFinite(current)) {
      throw contractError('HTTP_RECON_TIME_INVALID', 'verification time is invalid')
    }
    if (current < notBefore) {
      throw contractError(
        'HTTP_RECON_AUTHORIZATION_NOT_YET_VALID',
        `authorization is not valid before ${roe.validity.not_before}`,
      )
    }
    if (current >= notAfter) {
      throw contractError(
        'HTTP_RECON_AUTHORIZATION_EXPIRED',
        `authorization expired at ${roe.validity.not_after}`,
      )
    }
  }
  return roe
}

export function validateHttpReconRoe(value) {
  const valid = validateRoeSchema(value)
  return { valid, errors: valid ? [] : normalizeAjvErrors(validateRoeSchema.errors) }
}

export function assertValidHttpReconRoe(value, options = {}) {
  assertSchema(validateRoeSchema, value, 'authorized HTTP-recon RoE')
  return assertRoeSemantics(value, options)
}

export function signHttpReconRoe({ roe, privateKeyBytes }) {
  const signed = signDocument({
    value: roe,
    privateKeyBytes,
    context: ROE_SIGNATURE_CONTEXT,
  })
  assertSchema(validateRoeSchema, signed, 'signed authorized HTTP-recon RoE')
  assertRoeSemantics(signed, { requireCurrentValidity: false })
  return signed
}

export function verifyHttpReconRoeSignature({ roe, ownerPublicKeyBytes }) {
  assertSchema(validateRoeSchema, roe, 'signed authorized HTTP-recon RoE')
  return verifySignedDocument({
    value: roe,
    publicKeyBytes: ownerPublicKeyBytes,
    context: ROE_SIGNATURE_CONTEXT,
    label: 'signed RoE',
  })
}

async function readBoundedRoe(path) {
  const info = await lstat(path)
  if (!info.isFile() || info.isSymbolicLink() || info.size > MAX_ROE_BYTES) {
    throw contractError(
      'HTTP_RECON_ROE_FILE_UNSAFE',
      `signed RoE must be a regular non-symlink file no larger than ${MAX_ROE_BYTES} bytes`,
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
        'HTTP_RECON_ROE_CHANGED',
        'signed RoE changed while it was read',
      )
    }
    return bytes
  } finally {
    await handle.close()
  }
}

export async function readAndVerifyHttpReconRoe({
  roePath,
  ownerPublicKeyBytes,
  authorizationDocumentBytes,
  now = new Date(),
  requireCurrentValidity = true,
}) {
  const bytes = await readBoundedRoe(roePath)
  let roe
  try {
    roe = JSON.parse(bytes.toString('utf8'))
  } catch (error) {
    throw contractError(
      'HTTP_RECON_ROE_JSON_INVALID',
      `signed RoE is not valid JSON: ${error.message}`,
      [],
      { cause: error },
    )
  }
  assertValidHttpReconRoe(roe, { now, requireCurrentValidity })
  const identity = verifyHttpReconRoeSignature({ roe, ownerPublicKeyBytes })
  const authorizationDocumentSha256 = sha256Hex(authorizationDocumentBytes)
  if (authorizationDocumentSha256 !== roe.authorization.document_sha256) {
    throw contractError(
      'HTTP_RECON_AUTHORIZATION_DOCUMENT_MISMATCH',
      'external authorization document does not match the signed RoE digest',
    )
  }
  return {
    roe,
    ownerKeyId: identity.keyId,
    roeSha256: sha256Hex(bytes),
    payloadSha256: sha256Hex(canonicalJson(unsignedDocument(roe))),
    authorizationDocumentSha256,
  }
}

export function buildHttpReconPlan(roe) {
  assertValidHttpReconRoe(roe, { requireCurrentValidity: false })
  const actions = roe.requests.map((request, index) => {
    const projection = {
      sequence: index + 1,
      method: request.method,
      url: request.url,
      safe_to_get: request.method === 'GET',
    }
    return {
      action_id: `http-recon-action:${sha256Hex(canonicalJson(projection))}`,
      ...projection,
    }
  })
  const plan = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/http-recon-plan',
    engagement_id: roe.engagement_id,
    authorization_id: roe.authorization.authorization_id,
    authorization_document_sha256: roe.authorization.document_sha256,
    target: structuredClone(roe.target),
    validity: structuredClone(roe.validity),
    limits: structuredClone(roe.limits),
    actions,
  }
  return {
    plan,
    actions,
    plan_sha256: sha256Hex(canonicalJson(plan)),
  }
}

function assertAttestedScopeSemantics(
  scope,
  { now, requireCurrentValidity = true } = {},
) {
  const targetOrigin = parseExactHttpsUrl(
    scope.target.origin,
    'target.origin',
    { originOnly: true },
  )
  const requestUrl = parseExactHttpsUrl(scope.requests[0].url, 'requests[0].url')
  if (requestUrl.origin !== targetOrigin.origin) {
    throw contractError(
      'HTTP_RECON_ACTION_ORIGIN_MISMATCH',
      'the attested action must use the exact attested target origin',
    )
  }
  const notBefore = parseExactTimestamp(
    scope.validity.not_before,
    'validity.not_before',
  )
  const notAfter = parseExactTimestamp(
    scope.validity.not_after,
    'validity.not_after',
  )
  const attestedAt = parseExactTimestamp(
    scope.authorization.attested_at,
    'authorization.attested_at',
  )
  if (
    attestedAt !== notBefore
    || notBefore >= notAfter
    || notAfter - notBefore !== OPERATOR_ATTESTED_LIMITS.max_wall_time_ms
  ) {
    throw contractError(
      'HTTP_RECON_VALIDITY_WINDOW_INVALID',
      'operator-attested validity must begin at attestation and use the fixed 15-minute window',
    )
  }
  if (requireCurrentValidity) {
    const current = now instanceof Date ? now.getTime() : new Date(now).getTime()
    if (!Number.isFinite(current)) {
      throw contractError('HTTP_RECON_TIME_INVALID', 'verification time is invalid')
    }
    if (current < notBefore) {
      throw contractError(
        'HTTP_RECON_AUTHORIZATION_NOT_YET_VALID',
        `operator attestation is not valid before ${scope.validity.not_before}`,
      )
    }
    if (current >= notAfter) {
      throw contractError(
        'HTTP_RECON_AUTHORIZATION_EXPIRED',
        `operator attestation expired at ${scope.validity.not_after}`,
      )
    }
  }
  return scope
}

export function validateOperatorAttestedHttpReconScope(value) {
  const valid = validateAttestedScopeSchema(value)
  return {
    valid,
    errors: valid ? [] : normalizeAjvErrors(validateAttestedScopeSchema.errors),
  }
}

export function assertValidOperatorAttestedHttpReconScope(value, options = {}) {
  assertSchema(
    validateAttestedScopeSchema,
    value,
    'operator-attested HTTP-recon scope',
  )
  return assertAttestedScopeSemantics(value, options)
}

export function createOperatorAttestedHttpReconScope({
  engagementId,
  authorizationId,
  targetUrl,
  tlsSpkiSha256,
  method = 'HEAD',
  safeToGet = false,
  operatorId,
  authorizedBy,
  authorizationReference,
  environment = 'production',
  now = new Date(),
}) {
  const normalizedMethod = typeof method === 'string' ? method.toUpperCase() : method
  if (
    (normalizedMethod === 'GET' && safeToGet !== true)
    || (normalizedMethod !== 'GET' && safeToGet === true)
  ) {
    throw contractError(
      'HTTP_RECON_GET_ACKNOWLEDGMENT_INVALID',
      'safe-to-get acknowledgment is required only for an attested GET action',
    )
  }
  const parsedTarget = parseExactHttpsUrl(targetUrl, 'targetUrl')
  const attestedAt = new Date(now).toISOString()
  const request = {
    method: normalizedMethod,
    url: parsedTarget.href,
    ...(normalizedMethod === 'GET' ? { safe_to_get: safeToGet } : {}),
  }
  const scope = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/http-recon-attested-scope',
    engagement_id: engagementId,
    environment,
    authorization: {
      mode: 'OPERATOR_ATTESTED',
      authorization_id: authorizationId,
      statement: OPERATOR_ATTESTED_AUTHORIZATION_STATEMENT,
      operator_id: operatorId,
      authorized_by: authorizedBy,
      authorization_reference: authorizationReference,
      attested_at: attestedAt,
      independently_verified: false,
    },
    target: {
      origin: parsedTarget.origin,
      tls: tlsSpkiSha256 === undefined
        ? { mode: 'PKIX_HOSTNAME' }
        : {
            mode: 'PKIX_HOSTNAME_AND_SPKI_PIN',
            spki_sha256: tlsSpkiSha256,
          },
    },
    validity: {
      not_before: attestedAt,
      not_after: new Date(
        Date.parse(attestedAt) + OPERATOR_ATTESTED_LIMITS.max_wall_time_ms,
      ).toISOString(),
    },
    limits: structuredClone(OPERATOR_ATTESTED_LIMITS),
    stop_conditions: [
      'AUTHORIZATION_WITHDRAWN',
      'EMERGENCY_STOP_REQUESTED',
      'AUTHORIZATION_WINDOW_CLOSED',
      'TARGET_IDENTITY_CHANGED',
      'LIMIT_REACHED',
      'UNEXPECTED_SIDE_EFFECT',
    ],
    requests: [request],
  }
  return assertValidOperatorAttestedHttpReconScope(scope, {
    now: new Date(attestedAt),
  })
}

export function buildOperatorAttestedHttpReconPlan(scope) {
  assertValidOperatorAttestedHttpReconScope(scope, {
    requireCurrentValidity: false,
  })
  const request = scope.requests[0]
  const projection = {
    sequence: 1,
    method: request.method,
    url: request.url,
    safe_to_get: request.method === 'GET',
  }
  const actions = [{
    action_id: `http-recon-action:${sha256Hex(canonicalJson(projection))}`,
    ...projection,
  }]
  const plan = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/http-recon-plan',
    authorization_mode: 'OPERATOR_ATTESTED',
    engagement_id: scope.engagement_id,
    authorization: structuredClone(scope.authorization),
    target: {
      ...structuredClone(scope.target),
      proof: null,
    },
    validity: structuredClone(scope.validity),
    limits: structuredClone(scope.limits),
    actions,
  }
  return {
    plan,
    actions,
    plan_sha256: sha256Hex(canonicalJson(plan)),
    scope_sha256: sha256Hex(canonicalJson(scope)),
  }
}

export function validateHttpReconTargetProof(value) {
  const valid = validateProofSchema(value)
  return { valid, errors: valid ? [] : normalizeAjvErrors(validateProofSchema.errors) }
}

export function assertValidHttpReconTargetProof(value) {
  assertSchema(validateProofSchema, value, 'HTTP-recon target-control proof')
  parseExactTimestamp(value.issued_at, 'target proof issued_at')
  parseExactTimestamp(value.expires_at, 'target proof expires_at')
  parseExactHttpsUrl(value.target_origin, 'target proof target_origin', {
    originOnly: true,
  })
  parseExactHttpsUrl(value.proof_url, 'target proof proof_url')
  return value
}

export function signHttpReconTargetProof({ proof, privateKeyBytes }) {
  const signed = signDocument({
    value: proof,
    privateKeyBytes,
    context: PROOF_SIGNATURE_CONTEXT,
  })
  return assertValidHttpReconTargetProof(signed)
}

export function verifyHttpReconTargetProof({
  proof,
  roe,
  planSha256,
  ownerPublicKeyBytes,
  now = new Date(),
}) {
  assertValidHttpReconTargetProof(proof)
  assertValidHttpReconRoe(roe, { requireCurrentValidity: false })
  verifySignedDocument({
    value: proof,
    publicKeyBytes: ownerPublicKeyBytes,
    context: PROOF_SIGNATURE_CONTEXT,
    label: 'target-control proof',
  })
  const expected = {
    engagement_id: roe.engagement_id,
    authorization_id: roe.authorization.authorization_id,
    authorization_document_sha256: roe.authorization.document_sha256,
    target_origin: roe.target.origin,
    target_tls_spki_sha256: roe.target.tls_spki_sha256,
    proof_url: roe.target.proof.url,
    challenge_nonce: roe.target.proof.challenge_nonce,
    plan_sha256: planSha256,
  }
  for (const [field, value] of Object.entries(expected)) {
    if (proof[field] !== value) {
      throw contractError(
        'HTTP_RECON_TARGET_PROOF_BINDING_MISMATCH',
        `target-control proof ${field} does not match the signed engagement`,
      )
    }
  }
  const issuedAt = parseExactTimestamp(proof.issued_at, 'target proof issued_at')
  const expiresAt = parseExactTimestamp(proof.expires_at, 'target proof expires_at')
  const current = now instanceof Date ? now.getTime() : new Date(now).getTime()
  if (
    !Number.isFinite(current)
    || issuedAt > current
    || current >= expiresAt
    || expiresAt <= issuedAt
    || expiresAt - issuedAt > roe.target.proof.max_age_ms
  ) {
    throw contractError(
      'HTTP_RECON_TARGET_PROOF_EXPIRED',
      'target-control proof is not fresh at the verification time',
    )
  }
  return proof
}

export function validateHttpReconRun(value) {
  const valid = validateRunSchema(value)
  return { valid, errors: valid ? [] : normalizeAjvErrors(validateRunSchema.errors) }
}

function assertActionState(action) {
  const hasLease = action.leased_at !== null
  const hasSent = action.sent_at !== null
  const hasCompleted = action.completed_at !== null
  const hasObservation = action.observation_path !== null
    && action.observation_sha256 !== null
  const hasError = action.error !== null
  const valid = {
    PENDING: action.attempt_count === 0
      && !hasLease && !hasSent && !hasCompleted && !hasObservation && !hasError,
    LEASED: action.attempt_count === 1
      && hasLease && !hasSent && !hasCompleted && !hasObservation && !hasError,
    SENT: action.attempt_count === 1
      && hasLease && hasSent && !hasCompleted && !hasObservation && !hasError,
    COMMITTED: action.attempt_count === 1
      && hasLease && hasSent && hasCompleted && hasObservation && !hasError,
    FAILED: action.attempt_count === 1
      && hasLease && hasCompleted && !hasObservation && hasError,
    DELIVERY_AMBIGUOUS: action.attempt_count === 1
      && hasLease && hasSent && hasCompleted && !hasObservation && hasError,
  }[action.state]
  if (!valid) {
    throw contractError(
      'HTTP_RECON_ACTION_STATE_INVALID',
      `action ${action.action_id} fields do not match state ${action.state}`,
    )
  }
}

export function assertValidHttpReconRun(value) {
  assertSchema(validateRunSchema, value, 'authorized HTTP-recon run')
  const operatorAttested = value.authorization.mode === 'OPERATOR_ATTESTED'
  if (operatorAttested) {
    if (
      value.target.proof !== null
      || value.target_proof !== null
      || value.actions.length !== 1
      || value.limits.max_probe_requests !== 1
      || value.limits.max_target_proof_requests !== 0
      || value.limits.max_target_proof_response_bytes !== 0
      || value.budget.proof_requests_used !== 0
      || value.authorization.attested_at !== value.authorization.valid_from
      || !['PKIX_HOSTNAME', 'PKIX_HOSTNAME_AND_SPKI_PIN'].includes(
        value.target.tls?.mode,
      )
    ) {
      throw contractError(
        'HTTP_RECON_ATTESTED_MODE_INVALID',
        'operator-attested runs require one action, an explicit PKIX TLS policy, no target proof, and zero proof budget',
      )
    }
  } else if (
    value.target.proof === null
    || value.limits.max_target_proof_requests < value.actions.length
    || value.limits.max_target_proof_response_bytes < 256
  ) {
    throw contractError(
      'HTTP_RECON_SIGNED_MODE_INVALID',
      'externally signed runs require their target proof descriptor and proof budget',
    )
  }
  if (Date.parse(value.updated_at) < Date.parse(value.created_at)) {
    throw contractError(
      'HTTP_RECON_RUN_TIME_INVALID',
      'run updated_at cannot precede created_at',
    )
  }
  const actionIds = new Set()
  for (const [index, action] of value.actions.entries()) {
    if (action.sequence !== index + 1 || actionIds.has(action.action_id)) {
      throw contractError(
      'HTTP_RECON_ACTION_ORDER_INVALID',
      'run actions must have unique IDs in contiguous sealed sequence order',
      )
    }
    actionIds.add(action.action_id)
    assertActionState(action)
  }
  if (
    value.budget.proof_requests_used > value.limits.max_target_proof_requests
    || value.budget.probe_requests_used > value.limits.max_probe_requests
    || value.budget.response_bytes_used > value.limits.max_aggregate_response_bytes
  ) {
    throw contractError(
      'HTTP_RECON_BUDGET_INVALID',
      'run budget exceeds the sealed hard limits',
    )
  }
  if (
    value.target_proof
    && sha256Hex(canonicalJson(value.target_proof.proof))
      !== value.target_proof.proof_sha256
  ) {
    throw contractError(
      'HTTP_RECON_TARGET_PROOF_RECEIPT_INVALID',
      'run target-proof receipt digest does not match its signed proof',
    )
  }
  if (
    value.state === 'PLANNED'
    && value.actions.some(({ state }) => state !== 'PENDING')
  ) {
    throw contractError(
      'HTTP_RECON_RUN_STATE_INVALID',
      'PLANNED run cannot contain attempted actions',
    )
  }
  if (
    value.state === 'PROBE_PLAN_COMPLETE'
    && value.actions.some(({ state }) => state !== 'COMMITTED')
  ) {
    throw contractError(
      'HTTP_RECON_RUN_STATE_INVALID',
      'PROBE_PLAN_COMPLETE requires every signed action to be committed',
    )
  }
  if (value.state === 'STOPPED' && value.stop === null) {
    throw contractError(
      'HTTP_RECON_RUN_STATE_INVALID',
      'STOPPED run requires stop evidence',
    )
  }
  if (
    value.state === 'OUTCOME_UNCERTAIN'
    && !value.actions.some(({ state }) => state === 'DELIVERY_AMBIGUOUS')
  ) {
    throw contractError(
      'HTTP_RECON_RUN_STATE_INVALID',
      'OUTCOME_UNCERTAIN requires a delivery-ambiguous action',
    )
  }
  return value
}

export function validateHttpReconObservation(value) {
  const valid = validateObservationSchema(value)
  return {
    valid,
    errors: valid ? [] : normalizeAjvErrors(validateObservationSchema.errors),
  }
}

export function assertValidHttpReconObservation(value) {
  assertSchema(
    validateObservationSchema,
    value,
    'authorized HTTP-recon observation',
  )
  parseExactHttpsUrl(value.url, 'observation.url')
  if (
    value.body.truncated
    && value.body.digest_scope !== 'captured-prefix'
  ) {
    throw contractError(
      'HTTP_RECON_OBSERVATION_BODY_INVALID',
      'truncated observation body must use captured-prefix digest scope',
    )
  }
  return value
}
