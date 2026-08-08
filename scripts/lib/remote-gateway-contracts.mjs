import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  randomUUID,
  sign as signBytes,
  verify as verifyBytes,
} from 'node:crypto'
import { readFileSync } from 'node:fs'
import { posix, win32 } from 'node:path'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'

import { stableJson } from './run-engine.mjs'
import { compareCanonicalStrings } from './canonical-order.mjs'

const FINDING_SCHEMA_URL = new URL(
  '../../schemas/finding.schema.json',
  import.meta.url,
)
const STORE_PROFILE_SCHEMA_URL = new URL(
  '../../schemas/store-profile.schema.json',
  import.meta.url,
)
const STORE_CONTRIBUTION_SCHEMA_URL = new URL(
  '../../schemas/store-contribution.schema.json',
  import.meta.url,
)
const JOB_RESULT_SCHEMA_URL = new URL(
  '../../schemas/job-result.schema.json',
  import.meta.url,
)
const CONFIG_SCHEMA_URL = new URL(
  '../../schemas/remote-gateway-config.schema.json',
  import.meta.url,
)
const REQUEST_SCHEMA_URL = new URL(
  '../../schemas/remote-request-envelope.schema.json',
  import.meta.url,
)
const ACCEPTANCE_SCHEMA_URL = new URL(
  '../../schemas/remote-acceptance-envelope.schema.json',
  import.meta.url,
)
const REQUEST_SIGNATURE_CONTEXT = Buffer.from(
  'red-team-audit/remote-gateway-request/v1\u0000',
  'utf8',
)
const ACCEPTANCE_SIGNATURE_CONTEXT = Buffer.from(
  'red-team-audit/remote-gateway-acceptance/v1\u0000',
  'utf8',
)
const DIGEST = /^[a-f0-9]{64}$/

function loadJson(url) {
  return JSON.parse(readFileSync(fileURLToPath(url), 'utf8'))
}

export const remoteGatewayConfigSchema = loadJson(CONFIG_SCHEMA_URL)
export const remoteRequestEnvelopeSchema = loadJson(REQUEST_SCHEMA_URL)
export const remoteAcceptanceEnvelopeSchema = loadJson(ACCEPTANCE_SCHEMA_URL)
const findingSchema = loadJson(FINDING_SCHEMA_URL)
const storeProfileSchema = loadJson(STORE_PROFILE_SCHEMA_URL)
const storeContributionSchema = loadJson(STORE_CONTRIBUTION_SCHEMA_URL)
const jobResultSchema = loadJson(JOB_RESULT_SCHEMA_URL)

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})
for (const schema of [
  findingSchema,
  storeProfileSchema,
  storeContributionSchema,
  jobResultSchema,
  remoteGatewayConfigSchema,
  remoteRequestEnvelopeSchema,
  remoteAcceptanceEnvelopeSchema,
]) {
  ajv.addSchema(schema)
}
const validateConfigSchema = ajv.getSchema(remoteGatewayConfigSchema.$id)
const validateRequestSchema = ajv.getSchema(remoteRequestEnvelopeSchema.$id)
const validateAcceptanceSchema = ajv.getSchema(remoteAcceptanceEnvelopeSchema.$id)

export class RemoteGatewayContractError extends Error {
  constructor(message, details = []) {
    super(message)
    this.name = 'RemoteGatewayContractError'
    this.code = 'REMOTE_GATEWAY_CONTRACT_INVALID'
    this.details = details
  }
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
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

function contractError(code, instancePath, message, params = {}) {
  return {
    keyword: 'contract',
    code,
    instancePath,
    message,
    params,
  }
}

function validTimestamp(value) {
  if (typeof value !== 'string') return null
  const milliseconds = Date.parse(value)
  if (!Number.isFinite(milliseconds)) return null
  return new Date(milliseconds).toISOString() === value ? milliseconds : null
}

function isPortableAbsolutePath(value) {
  return typeof value === 'string'
    && (posix.isAbsolute(value) || win32.isAbsolute(value))
}

function configSemanticErrors(value) {
  const errors = []
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return errors

  let gatewayUrl
  try {
    gatewayUrl = new URL(value.gateway_url)
  } catch {
    gatewayUrl = null
    if (typeof value.gateway_url === 'string') {
      errors.push(contractError(
        'REMOTE_GATEWAY_URL_INVALID',
        '/gateway_url',
        'gateway_url must be a valid absolute HTTPS URL',
      ))
    }
  }
  if (
    gatewayUrl
    && (
      gatewayUrl.protocol !== 'https:'
      || gatewayUrl.username !== ''
      || gatewayUrl.password !== ''
      || gatewayUrl.search !== ''
      || gatewayUrl.hash !== ''
    )
  ) {
    errors.push(contractError(
      'REMOTE_GATEWAY_URL_NOT_EXACT_HTTPS',
      '/gateway_url',
      'gateway_url must be one exact HTTPS endpoint without credentials, query, or fragment',
    ))
  }

  for (const key of [
    'controller_signing_private_key_path',
    'gateway_public_key_path',
  ]) {
    if (value[key] !== undefined && !isPortableAbsolutePath(value[key])) {
      errors.push(contractError(
        'REMOTE_GATEWAY_PATH_NOT_ABSOLUTE',
        `/${key}`,
        `${key} must be an absolute POSIX, drive-qualified Windows, or UNC path`,
      ))
    }
    if (typeof value[key] === 'string' && /[\u0000-\u001f\u007f]/.test(value[key])) {
      errors.push(contractError(
        'REMOTE_GATEWAY_PATH_HAS_CONTROL_CHARACTER',
        `/${key}`,
        `${key} cannot contain control characters`,
      ))
    }
  }

  const limits = value.limits
  if (limits === null || typeof limits !== 'object' || Array.isArray(limits)) {
    return errors
  }
  if (
    Number.isSafeInteger(limits.max_file_bytes)
    && Number.isSafeInteger(limits.max_total_artifact_bytes)
    && limits.max_file_bytes > limits.max_total_artifact_bytes
  ) {
    errors.push(contractError(
      'REMOTE_GATEWAY_FILE_LIMIT_EXCEEDS_TOTAL',
      '/limits/max_file_bytes',
      'max_file_bytes cannot exceed max_total_artifact_bytes',
    ))
  }
  if (
    Number.isSafeInteger(limits.max_total_artifact_bytes)
    && Number.isSafeInteger(limits.max_request_bytes)
  ) {
    const encodedBytes = Math.ceil(limits.max_total_artifact_bytes / 3) * 4
    if (encodedBytes + 65_536 > limits.max_request_bytes) {
      errors.push(contractError(
        'REMOTE_GATEWAY_REQUEST_LIMIT_TOO_SMALL',
        '/limits/max_request_bytes',
        'max_request_bytes must fit the configured artifact bytes after base64 encoding plus bounded protocol metadata',
        { minimum: encodedBytes + 65_536 },
      ))
    }
  }
  if (
    Number.isSafeInteger(limits.request_timeout_ms)
    && Number.isSafeInteger(limits.request_ttl_ms)
    && limits.request_timeout_ms > limits.request_ttl_ms
  ) {
    errors.push(contractError(
      'REMOTE_GATEWAY_TIMEOUT_EXCEEDS_TTL',
      '/limits/request_timeout_ms',
      'request_timeout_ms cannot exceed request_ttl_ms',
    ))
  }
  return errors
}

export function validateRemoteGatewayConfig(value) {
  const schemaValid = validateConfigSchema(value)
  const errors = [
    ...(schemaValid ? [] : normalizeAjvErrors(validateConfigSchema.errors)),
    ...configSemanticErrors(value),
  ]
  return { valid: errors.length === 0, errors }
}

export function assertValidRemoteGatewayConfig(value) {
  const validation = validateRemoteGatewayConfig(value)
  if (!validation.valid) {
    throw new RemoteGatewayContractError(
      'remote gateway configuration validation failed',
      validation.errors,
    )
  }
  return value
}

function keyIdentity(key) {
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new RemoteGatewayContractError(
      'remote gateway signing keys must be Ed25519',
    )
  }
  const publicKey = key.type === 'private' ? createPublicKey(key) : key
  const spki = publicKey.export({ type: 'spki', format: 'der' })
  return {
    key,
    publicKey,
    keyId: `ed25519:${sha256(spki)}`,
    publicSpkiBase64: spki.toString('base64'),
  }
}

export function parseRemotePrivateKey(keyBytes) {
  try {
    return keyIdentity(createPrivateKey(keyBytes))
  } catch (error) {
    if (error instanceof RemoteGatewayContractError) throw error
    throw new RemoteGatewayContractError(
      `cannot parse remote gateway private key: ${error.message}`,
    )
  }
}

export function parseRemotePublicKey(keyBytes) {
  try {
    return keyIdentity(
      keyBytes?.type === 'public' ? keyBytes : createPublicKey(keyBytes),
    )
  } catch (error) {
    if (error instanceof RemoteGatewayContractError) throw error
    throw new RemoteGatewayContractError(
      `cannot parse remote gateway public key: ${error.message}`,
    )
  }
}

function withoutSignature(value) {
  const { signature: _signature, ...unsigned } = value
  return unsigned
}

function signingPayload(context, value) {
  return Buffer.concat([
    context,
    Buffer.from(stableJson(withoutSignature(value), 0), 'utf8'),
  ])
}

function canonicalSignature(value) {
  if (typeof value !== 'string') return false
  const decoded = Buffer.from(value, 'base64')
  return decoded.length === 64 && decoded.toString('base64') === value
}

function signEnvelope(unsigned, identity, context) {
  return {
    ...unsigned,
    signature: {
      algorithm: 'Ed25519',
      value_base64: signBytes(
        null,
        Buffer.concat([
          context,
          Buffer.from(stableJson(unsigned, 0), 'utf8'),
        ]),
        identity.key,
      ).toString('base64'),
    },
  }
}

function verifyEnvelopeSignature(value, identity, context, label) {
  if (!canonicalSignature(value.signature?.value_base64)) {
    throw new RemoteGatewayContractError(`${label} signature is not canonical Ed25519 base64`)
  }
  if (!verifyBytes(
    null,
    signingPayload(context, value),
    identity.publicKey,
    Buffer.from(value.signature.value_base64, 'base64'),
  )) {
    throw new RemoteGatewayContractError(`${label} signature verification failed`)
  }
}

function normalizeArtifact(artifact) {
  const bytes = Buffer.isBuffer(artifact?.bytes)
    ? Buffer.from(artifact.bytes)
    : Buffer.from(artifact?.bytes ?? [])
  return {
    artifact_id: artifact.artifact_id,
    kind: artifact.kind,
    logical_name: artifact.logical_name,
    size: bytes.length,
    sha256: sha256(bytes),
    content_base64: bytes.toString('base64'),
  }
}

function packetDigest(packet) {
  if (packet === null || typeof packet !== 'object' || Array.isArray(packet)) {
    return null
  }
  const { packet_sha256: _packetSha256, ...unsigned } = packet
  return sha256(stableJson(unsigned, 0))
}

function payloadDigest(packet, artifacts) {
  return sha256(stableJson({
    job_packet: packet,
    artifacts,
  }, 0))
}

function requestSemanticErrors(value) {
  const errors = []
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return errors
  const controller = value.controller
  if (controller === null || typeof controller !== 'object') return errors

  const createdAt = validTimestamp(controller.created_at)
  const expiresAt = validTimestamp(controller.expires_at)
  if (createdAt === null) {
    errors.push(contractError(
      'REMOTE_REQUEST_CREATED_AT_INVALID',
      '/controller/created_at',
      'created_at must be a real timestamp',
    ))
  }
  if (expiresAt === null) {
    errors.push(contractError(
      'REMOTE_REQUEST_EXPIRES_AT_INVALID',
      '/controller/expires_at',
      'expires_at must be a real timestamp',
    ))
  }
  if (createdAt !== null && expiresAt !== null && expiresAt <= createdAt) {
    errors.push(contractError(
      'REMOTE_REQUEST_TIME_WINDOW_INVALID',
      '/controller/expires_at',
      'expires_at must be strictly after created_at',
    ))
  }

  const actualPacketDigest = packetDigest(value.job_packet)
  if (
    typeof controller.packet_sha256 === 'string'
    && (
      value.job_packet?.packet_sha256 !== controller.packet_sha256
      || actualPacketDigest !== controller.packet_sha256
    )
  ) {
    errors.push(contractError(
      'REMOTE_REQUEST_PACKET_DIGEST_MISMATCH',
      '/controller/packet_sha256',
      'controller and embedded packet digests must bind the canonical job packet',
    ))
  }
  if (
    typeof controller.run_id === 'string'
    && typeof value.job_packet?.run_id === 'string'
    && controller.run_id !== value.job_packet.run_id
  ) {
    errors.push(contractError(
      'REMOTE_REQUEST_RUN_ID_MISMATCH',
      '/controller/run_id',
      'controller run_id must match the embedded job packet',
    ))
  }
  if (
    typeof controller.job_id === 'string'
    && typeof value.job_packet?.job_id === 'string'
    && controller.job_id !== value.job_packet.job_id
  ) {
    errors.push(contractError(
      'REMOTE_REQUEST_JOB_ID_MISMATCH',
      '/controller/job_id',
      'controller job_id must match the embedded job packet',
    ))
  }

  const artifactIds = new Set()
  const logicalNames = new Set()
  const suppliedFiles = new Set()
  const artifacts = Array.isArray(value.artifacts) ? value.artifacts : []
  for (const [index, artifact] of artifacts.entries()) {
    if (artifact === null || typeof artifact !== 'object' || Array.isArray(artifact)) {
      continue
    }
    const path = `/artifacts/${index}`
    if (artifactIds.has(artifact.artifact_id)) {
      errors.push(contractError(
        'REMOTE_REQUEST_DUPLICATE_ARTIFACT_ID',
        `${path}/artifact_id`,
        'artifact_id values must be unique',
      ))
    }
    artifactIds.add(artifact.artifact_id)
    if (logicalNames.has(artifact.logical_name)) {
      errors.push(contractError(
        'REMOTE_REQUEST_DUPLICATE_LOGICAL_NAME',
        `${path}/logical_name`,
        'logical_name values must be unique',
      ))
    }
    logicalNames.add(artifact.logical_name)
    if (typeof artifact.logical_name === 'string') {
      const segments = artifact.logical_name.split('/')
      const unsafeName = (
        artifact.logical_name.startsWith('/')
        || artifact.logical_name.includes('\\')
        || /^[A-Za-z]:/.test(artifact.logical_name)
        || segments.some((segment) =>
          segment === '' || segment === '.' || segment === '..')
      )
      if (unsafeName) {
        errors.push(contractError(
          'REMOTE_REQUEST_LOGICAL_NAME_UNSAFE',
          `${path}/logical_name`,
          'logical_name must be a relative POSIX path without empty, dot, or parent segments',
        ))
      } else if (artifact.kind === 'FILE') {
        suppliedFiles.add(artifact.logical_name)
      }
    }
    if (typeof artifact.content_base64 !== 'string') continue
    const bytes = Buffer.from(artifact.content_base64, 'base64')
    if (bytes.toString('base64') !== artifact.content_base64) {
      errors.push(contractError(
        'REMOTE_REQUEST_ARTIFACT_BASE64_NONCANONICAL',
        `${path}/content_base64`,
        'artifact content must use canonical base64 encoding',
      ))
    }
    if (bytes.length !== artifact.size) {
      errors.push(contractError(
        'REMOTE_REQUEST_ARTIFACT_SIZE_MISMATCH',
        `${path}/size`,
        'artifact size must equal the decoded byte length',
      ))
    }
    if (sha256(bytes) !== artifact.sha256) {
      errors.push(contractError(
        'REMOTE_REQUEST_ARTIFACT_DIGEST_MISMATCH',
        `${path}/sha256`,
        'artifact digest must match the exact decoded bytes',
      ))
    }
  }
  if (Array.isArray(value.job_packet?.scoped_files)) {
    const expectedFiles = new Set(value.job_packet.scoped_files)
    if (
      suppliedFiles.size !== expectedFiles.size
      || [...expectedFiles].some((file) => !suppliedFiles.has(file))
    ) {
      errors.push(contractError(
        'REMOTE_REQUEST_FILE_SET_MISMATCH',
        '/artifacts',
        'FILE artifacts must exactly match the embedded packet scoped_files',
      ))
    }
  }

  if (
    typeof controller.payload_sha256 === 'string'
    && controller.payload_sha256 !== payloadDigest(value.job_packet, value.artifacts)
  ) {
    errors.push(contractError(
      'REMOTE_REQUEST_PAYLOAD_DIGEST_MISMATCH',
      '/controller/payload_sha256',
      'payload_sha256 must bind the exact packet and artifact representation',
    ))
  }
  return errors
}

export function validateRemoteRequestEnvelope(value) {
  const schemaValid = validateRequestSchema(value)
  const errors = [
    ...(schemaValid ? [] : normalizeAjvErrors(validateRequestSchema.errors)),
    ...requestSemanticErrors(value),
  ]
  return { valid: errors.length === 0, errors }
}

export function assertValidRemoteRequestEnvelope(value) {
  const validation = validateRemoteRequestEnvelope(value)
  if (!validation.valid) {
    throw new RemoteGatewayContractError(
      'remote request envelope validation failed',
      validation.errors,
    )
  }
  return value
}

function normalizeInstant(value, label) {
  const instant = value instanceof Date ? value : new Date(value)
  if (Number.isNaN(instant.valueOf())) {
    throw new RemoteGatewayContractError(`${label} must be a valid instant`)
  }
  return instant
}

function requireDigest(value, label) {
  if (!DIGEST.test(value ?? '')) {
    throw new RemoteGatewayContractError(`${label} must be a lowercase SHA-256 digest`)
  }
  return value
}

export function createRemoteRequestEnvelope({
  provenance,
  packet,
  artifacts,
  promptTransform,
  privateKeyBytes,
  attemptId = `attempt:${randomUUID()}`,
  requestId = `remote:${randomUUID()}`,
  nonce = randomBytes(32).toString('hex'),
  createdAt = new Date(),
  ttlMs,
}) {
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1000 || ttlMs > 300000) {
    throw new RemoteGatewayContractError('remote request ttlMs must be between 1000 and 300000')
  }
  const identity = parseRemotePrivateKey(privateKeyBytes)
  const created = normalizeInstant(createdAt, 'createdAt')
  const normalizedArtifacts = (artifacts ?? [])
    .map(normalizeArtifact)
    .sort((left, right) =>
      compareCanonicalStrings(left.kind, right.kind)
      || compareCanonicalStrings(left.logical_name, right.logical_name)
      || compareCanonicalStrings(left.artifact_id, right.artifact_id))
  const packetSha256 = requireDigest(packet?.packet_sha256, 'packet.packet_sha256')
  if (packetDigest(packet) !== packetSha256) {
    throw new RemoteGatewayContractError(
      'packet.packet_sha256 does not bind the canonical packet',
    )
  }
  const controller = {
    request_id: requestId,
    attempt_id: attemptId,
    attempt_nonce: requireDigest(nonce, 'nonce'),
    created_at: created.toISOString(),
    expires_at: new Date(created.getTime() + ttlMs).toISOString(),
    run_id: provenance.run_id,
    job_id: provenance.job_id,
    packet_sha256: packetSha256,
    plan_sha256: requireDigest(provenance.plan_sha256, 'provenance.plan_sha256'),
    repository_tree_sha256: requireDigest(
      provenance.repository_tree_sha256,
      'provenance.repository_tree_sha256',
    ),
    lens_pack_sha256: requireDigest(
      provenance.lens_pack_sha256,
      'provenance.lens_pack_sha256',
    ),
    policy_sha256: requireDigest(
      provenance.policy_sha256,
      'provenance.policy_sha256',
    ),
    source_snapshot_sha256: requireDigest(
      provenance.source_snapshot_sha256,
      'provenance.source_snapshot_sha256',
    ),
    control_snapshot_sha256: requireDigest(
      provenance.control_snapshot_sha256,
      'provenance.control_snapshot_sha256',
    ),
    payload_sha256: payloadDigest(packet, normalizedArtifacts),
    prompt_transform: structuredClone(promptTransform),
    key_id: identity.keyId,
    public_key_spki_base64: identity.publicSpkiBase64,
  }
  return assertValidRemoteRequestEnvelope(signEnvelope({
    schema_version: '1.0.0',
    protocol: 'remote-gateway-v1',
    controller,
    job_packet: structuredClone(packet),
    artifacts: normalizedArtifacts,
  }, identity, REQUEST_SIGNATURE_CONTEXT))
}

function embeddedPublicIdentity(keyId, spkiBase64, label) {
  let spki
  let identity
  try {
    spki = Buffer.from(spkiBase64, 'base64')
    if (spki.toString('base64') !== spkiBase64) throw new Error('non-canonical base64')
    identity = keyIdentity(createPublicKey({ key: spki, type: 'spki', format: 'der' }))
  } catch (error) {
    throw new RemoteGatewayContractError(`${label} embedded public key is invalid: ${error.message}`)
  }
  if (identity.keyId !== keyId) {
    throw new RemoteGatewayContractError(`${label} embedded public key does not match key_id`)
  }
  return identity
}

export function verifyRemoteRequestEnvelope({
  envelope,
  publicKeyBytes,
  expectedPromptTransform,
  now = new Date(),
  maxClockSkewMs = 0,
  maxRequestTtlMs = 300000,
}) {
  assertValidRemoteRequestEnvelope(envelope)
  const pinned = parseRemotePublicKey(publicKeyBytes)
  const embedded = embeddedPublicIdentity(
    envelope.controller.key_id,
    envelope.controller.public_key_spki_base64,
    'remote request',
  )
  if (pinned.keyId !== embedded.keyId) {
    throw new RemoteGatewayContractError(
      'remote request signing key does not match the externally trusted controller key',
    )
  }
  verifyEnvelopeSignature(
    envelope,
    pinned,
    REQUEST_SIGNATURE_CONTEXT,
    'remote request',
  )
  if (
    expectedPromptTransform
    && stableJson(envelope.controller.prompt_transform, 0)
      !== stableJson(expectedPromptTransform, 0)
  ) {
    throw new RemoteGatewayContractError(
      'remote request prompt transform does not match the trusted gateway configuration',
    )
  }
  const current = normalizeInstant(now, 'now').getTime()
  const created = Date.parse(envelope.controller.created_at)
  const expires = Date.parse(envelope.controller.expires_at)
  if (expires - created > maxRequestTtlMs) {
    throw new RemoteGatewayContractError('remote request lifetime exceeds the trusted maximum')
  }
  if (current < created - maxClockSkewMs || current > expires + maxClockSkewMs) {
    throw new RemoteGatewayContractError('remote request is not valid at the current time')
  }
  return {
    key_id: pinned.keyId,
    request_id: envelope.controller.request_id,
    request_sha256: sha256(stableJson(envelope, 0)),
    decoded_artifacts: envelope.artifacts.map((artifact) => ({
      artifact_id: artifact.artifact_id,
      kind: artifact.kind,
      logical_name: artifact.logical_name,
      bytes: Buffer.from(artifact.content_base64, 'base64'),
      sha256: artifact.sha256,
    })),
  }
}

function acceptanceSemanticErrors(value) {
  const errors = []
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return errors
  const gateway = value.gateway
  const result = value.job_result
  if (
    gateway === null
    || typeof gateway !== 'object'
    || result === null
    || typeof result !== 'object'
  ) {
    return errors
  }
  if (validTimestamp(gateway.accepted_at) === null) {
    errors.push(contractError(
      'REMOTE_ACCEPTANCE_TIME_INVALID',
      '/gateway/accepted_at',
      'accepted_at must be a real timestamp',
    ))
  }
  if (
    gateway.run_id !== result.run_id
    || gateway.job_id !== result.job_id
    || gateway.packet_sha256 !== result.input_sha256
  ) {
    errors.push(contractError(
      'REMOTE_ACCEPTANCE_RESULT_BINDING_MISMATCH',
      '/job_result',
      'gateway acceptance must bind the raw job result run, job, and input packet',
    ))
  }
  if (
    typeof gateway.job_result_sha256 === 'string'
    && gateway.job_result_sha256 !== sha256(stableJson(result, 0))
  ) {
    errors.push(contractError(
      'REMOTE_ACCEPTANCE_RESULT_DIGEST_MISMATCH',
      '/gateway/job_result_sha256',
      'job_result_sha256 must bind the exact job result',
    ))
  }
  return errors
}

export function validateRemoteAcceptanceEnvelope(value) {
  const schemaValid = validateAcceptanceSchema(value)
  const errors = [
    ...(schemaValid ? [] : normalizeAjvErrors(validateAcceptanceSchema.errors)),
    ...acceptanceSemanticErrors(value),
  ]
  return { valid: errors.length === 0, errors }
}

export function assertValidRemoteAcceptanceEnvelope(value) {
  const validation = validateRemoteAcceptanceEnvelope(value)
  if (!validation.valid) {
    throw new RemoteGatewayContractError(
      'remote acceptance envelope validation failed',
      validation.errors,
    )
  }
  return value
}

export function createRemoteAcceptanceEnvelope({
  requestEnvelope,
  requestBytes,
  jobResult,
  upstreamRequestBytes,
  gatewayPrivateKeyBytes,
  acceptedAt = new Date(),
}) {
  assertValidRemoteRequestEnvelope(requestEnvelope)
  const requestContent = Buffer.from(requestBytes)
  const canonicalRequest = Buffer.from(stableJson(requestEnvelope, 0), 'utf8')
  if (!requestContent.equals(canonicalRequest)) {
    throw new RemoteGatewayContractError(
      'gateway acceptance requires the exact canonical request bytes',
    )
  }
  const identity = parseRemotePrivateKey(gatewayPrivateKeyBytes)
  const accepted = normalizeInstant(acceptedAt, 'acceptedAt')
  const gateway = {
    request_id: requestEnvelope.controller.request_id,
    request_sha256: sha256(requestContent),
    attempt_id: requestEnvelope.controller.attempt_id,
    attempt_nonce: requestEnvelope.controller.attempt_nonce,
    accepted_at: accepted.toISOString(),
    run_id: requestEnvelope.controller.run_id,
    job_id: requestEnvelope.controller.job_id,
    packet_sha256: requestEnvelope.controller.packet_sha256,
    prompt_transform: structuredClone(
      requestEnvelope.controller.prompt_transform,
    ),
    upstream_request_sha256: sha256(Buffer.from(upstreamRequestBytes)),
    job_result_sha256: sha256(stableJson(jobResult, 0)),
    semantic_analysis_proven: false,
    key_id: identity.keyId,
    public_key_spki_base64: identity.publicSpkiBase64,
  }
  return assertValidRemoteAcceptanceEnvelope(signEnvelope({
    schema_version: '1.0.0',
    authority: 'REMOTE_REQUEST_ACCEPTED',
    gateway,
    job_result: structuredClone(jobResult),
  }, identity, ACCEPTANCE_SIGNATURE_CONTEXT))
}

export function verifyRemoteAcceptanceEnvelope({
  envelope,
  requestEnvelope,
  requestBytes,
  gatewayPublicKeyBytes,
  expectedPromptTransform,
  now = new Date(),
  maxClockSkewMs = 0,
}) {
  assertValidRemoteRequestEnvelope(requestEnvelope)
  assertValidRemoteAcceptanceEnvelope(envelope)
  const exactRequestBytes = Buffer.from(requestBytes)
  const canonicalRequestBytes = Buffer.from(
    stableJson(requestEnvelope, 0),
    'utf8',
  )
  if (!exactRequestBytes.equals(canonicalRequestBytes)) {
    throw new RemoteGatewayContractError(
      'remote acceptance verification requires the exact canonical request bytes',
    )
  }
  const pinned = parseRemotePublicKey(gatewayPublicKeyBytes)
  const embedded = embeddedPublicIdentity(
    envelope.gateway.key_id,
    envelope.gateway.public_key_spki_base64,
    'remote acceptance',
  )
  if (pinned.keyId !== embedded.keyId) {
    throw new RemoteGatewayContractError(
      'remote acceptance signing key does not match the externally pinned gateway key',
    )
  }
  verifyEnvelopeSignature(
    envelope,
    pinned,
    ACCEPTANCE_SIGNATURE_CONTEXT,
    'remote acceptance',
  )
  const expectedBindings = {
    request_id: requestEnvelope.controller.request_id,
    request_sha256: sha256(exactRequestBytes),
    attempt_id: requestEnvelope.controller.attempt_id,
    attempt_nonce: requestEnvelope.controller.attempt_nonce,
    run_id: requestEnvelope.controller.run_id,
    job_id: requestEnvelope.controller.job_id,
    packet_sha256: requestEnvelope.controller.packet_sha256,
  }
  for (const [field, expected] of Object.entries(expectedBindings)) {
    if (envelope.gateway[field] !== expected) {
      throw new RemoteGatewayContractError(
        `remote acceptance ${field} does not bind the exact request`,
      )
    }
  }
  const transform = expectedPromptTransform
    ?? requestEnvelope.controller.prompt_transform
  if (
    stableJson(envelope.gateway.prompt_transform, 0)
    !== stableJson(transform, 0)
  ) {
    throw new RemoteGatewayContractError(
      'remote acceptance prompt transform does not match the trusted configuration',
    )
  }
  const suppliedFiles = new Set(
    requestEnvelope.artifacts
      .filter(({ kind }) => kind === 'FILE')
      .map(({ logical_name: logicalName }) => logicalName),
  )
  for (const path of envelope.job_result.examined_files) {
    if (!suppliedFiles.has(path)) {
      throw new RemoteGatewayContractError(
        `remote acceptance examined file ${path} was not supplied in the exact request`,
      )
    }
  }
  const accepted = Date.parse(envelope.gateway.accepted_at)
  const created = Date.parse(requestEnvelope.controller.created_at)
  const expires = Date.parse(requestEnvelope.controller.expires_at)
  const current = normalizeInstant(now, 'now').getTime()
  if (
    accepted < created - maxClockSkewMs
    || accepted > expires + maxClockSkewMs
    || accepted > current + maxClockSkewMs
  ) {
    throw new RemoteGatewayContractError(
      'remote acceptance time falls outside the trusted request window',
    )
  }
  return {
    authority: 'REMOTE_REQUEST_ACCEPTED',
    gateway_key_id: pinned.keyId,
    request_sha256: envelope.gateway.request_sha256,
    upstream_request_sha256: envelope.gateway.upstream_request_sha256,
    accepted_at: envelope.gateway.accepted_at,
    job_result: structuredClone(envelope.job_result),
    acceptance_envelope: structuredClone(envelope),
  }
}

export function contentDigestHeader(bytes) {
  return `sha-256=:${createHash('sha256').update(bytes).digest('base64')}:`
}

export function assertContentDigestHeader(value, bytes, label = 'HTTP content') {
  const expected = contentDigestHeader(bytes)
  if (value !== expected) {
    throw new RemoteGatewayContractError(
      `${label} Content-Digest does not match the exact body bytes`,
    )
  }
  return expected
}
