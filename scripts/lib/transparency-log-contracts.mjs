import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as signBytes,
  verify as verifyBytes,
} from 'node:crypto'
import { readFileSync } from 'node:fs'
import { posix, win32 } from 'node:path'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'

import {
  assertValidRootAttestation,
} from './root-attestation.mjs'
import { stableJson } from './run-engine.mjs'

const CONFIG_SCHEMA_URL = new URL(
  '../../schemas/transparency-log-config.schema.json',
  import.meta.url,
)
const REQUEST_SCHEMA_URL = new URL(
  '../../schemas/transparency-publish-request.schema.json',
  import.meta.url,
)
const RECEIPT_SCHEMA_URL = new URL(
  '../../schemas/transparency-inclusion-receipt.schema.json',
  import.meta.url,
)
const SIGNED_CHECKPOINT_SCHEMA_URL = new URL(
  '../../schemas/transparency-signed-checkpoint.schema.json',
  import.meta.url,
)
const CONSISTENCY_REQUEST_SCHEMA_URL = new URL(
  '../../schemas/transparency-consistency-request.schema.json',
  import.meta.url,
)
const CONSISTENCY_PROOF_SCHEMA_URL = new URL(
  '../../schemas/transparency-consistency-proof.schema.json',
  import.meta.url,
)
const CHECKPOINT_SIGNATURE_CONTEXT = Buffer.from(
  'red-team-audit/transparency-checkpoint/v1\u0000',
  'utf8',
)
const DIGEST = /^[a-f0-9]{64}$/

function loadJson(url) {
  return JSON.parse(readFileSync(fileURLToPath(url), 'utf8'))
}

export const transparencyLogConfigSchema = loadJson(CONFIG_SCHEMA_URL)
export const transparencyPublishRequestSchema = loadJson(REQUEST_SCHEMA_URL)
export const transparencyInclusionReceiptSchema = loadJson(RECEIPT_SCHEMA_URL)
export const transparencySignedCheckpointSchema = loadJson(
  SIGNED_CHECKPOINT_SCHEMA_URL,
)
export const transparencyConsistencyRequestSchema = loadJson(
  CONSISTENCY_REQUEST_SCHEMA_URL,
)
export const transparencyConsistencyProofSchema = loadJson(
  CONSISTENCY_PROOF_SCHEMA_URL,
)

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})
for (const schema of [
  transparencyLogConfigSchema,
  transparencyPublishRequestSchema,
  transparencyInclusionReceiptSchema,
  transparencySignedCheckpointSchema,
  transparencyConsistencyRequestSchema,
  transparencyConsistencyProofSchema,
]) {
  ajv.addSchema(schema)
}
const validateConfigSchema = ajv.getSchema(transparencyLogConfigSchema.$id)
const validateRequestSchema = ajv.getSchema(transparencyPublishRequestSchema.$id)
const validateReceiptSchema = ajv.getSchema(transparencyInclusionReceiptSchema.$id)
const validateSignedCheckpointSchema = ajv.getSchema(
  transparencySignedCheckpointSchema.$id,
)
const validateConsistencyRequestSchema = ajv.getSchema(
  transparencyConsistencyRequestSchema.$id,
)
const validateConsistencyProofSchema = ajv.getSchema(
  transparencyConsistencyProofSchema.$id,
)

export class TransparencyLogContractError extends Error {
  constructor(message, details = []) {
    super(message)
    this.name = 'TransparencyLogContractError'
    this.code = 'TRANSPARENCY_LOG_CONTRACT_INVALID'
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
  let logUrl
  try {
    logUrl = new URL(value.log_url)
  } catch {
    logUrl = null
    if (typeof value.log_url === 'string') {
      errors.push(contractError(
        'TRANSPARENCY_LOG_URL_INVALID',
        '/log_url',
        'log_url must be a valid absolute HTTPS URL',
      ))
    }
  }
  if (
    logUrl
    && (
      logUrl.protocol !== 'https:'
      || logUrl.username !== ''
      || logUrl.password !== ''
      || logUrl.search !== ''
      || logUrl.hash !== ''
    )
  ) {
    errors.push(contractError(
      'TRANSPARENCY_LOG_URL_NOT_EXACT_HTTPS',
      '/log_url',
      'log_url must be one exact HTTPS endpoint without credentials, query, or fragment',
    ))
  }
  let consistencyUrl
  if (value.consistency_url !== undefined) {
    try {
      consistencyUrl = new URL(value.consistency_url)
    } catch {
      consistencyUrl = null
      if (typeof value.consistency_url === 'string') {
        errors.push(contractError(
          'TRANSPARENCY_CONSISTENCY_URL_INVALID',
          '/consistency_url',
          'consistency_url must be a valid absolute HTTPS URL',
        ))
      }
    }
    if (
      consistencyUrl
      && (
        consistencyUrl.protocol !== 'https:'
        || consistencyUrl.username !== ''
        || consistencyUrl.password !== ''
        || consistencyUrl.search !== ''
        || consistencyUrl.hash !== ''
      )
    ) {
      errors.push(contractError(
        'TRANSPARENCY_CONSISTENCY_URL_NOT_EXACT_HTTPS',
        '/consistency_url',
        'consistency_url must be one exact HTTPS endpoint without credentials, query, or fragment',
      ))
    }
    if (logUrl && consistencyUrl && logUrl.href === consistencyUrl.href) {
      errors.push(contractError(
        'TRANSPARENCY_CONSISTENCY_URL_NOT_DISTINCT',
        '/consistency_url',
        'consistency_url must be distinct from the publication log_url',
      ))
    }
  }
  if (
    value.log_public_key_path !== undefined
    && !isPortableAbsolutePath(value.log_public_key_path)
  ) {
    errors.push(contractError(
      'TRANSPARENCY_LOG_KEY_PATH_NOT_ABSOLUTE',
      '/log_public_key_path',
      'log_public_key_path must be an absolute POSIX, drive-qualified Windows, or UNC path',
    ))
  }
  if (
    typeof value.log_public_key_path === 'string'
    && /[\u0000-\u001f\u007f]/.test(value.log_public_key_path)
  ) {
    errors.push(contractError(
      'TRANSPARENCY_LOG_KEY_PATH_HAS_CONTROL_CHARACTER',
      '/log_public_key_path',
      'log_public_key_path cannot contain control characters',
    ))
  }
  return errors
}

export function validateTransparencyLogConfig(value) {
  const schemaValid = validateConfigSchema(value)
  const errors = [
    ...(schemaValid ? [] : normalizeAjvErrors(validateConfigSchema.errors)),
    ...configSemanticErrors(value),
  ]
  return { valid: errors.length === 0, errors }
}

export function assertValidTransparencyLogConfig(value) {
  const validation = validateTransparencyLogConfig(value)
  if (!validation.valid) {
    throw new TransparencyLogContractError(
      'transparency log configuration validation failed',
      validation.errors,
    )
  }
  return value
}

function keyIdentity(key) {
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new TransparencyLogContractError(
      'transparency log signing keys must be Ed25519',
    )
  }
  const publicKey = key.type === 'private' ? createPublicKey(key) : key
  const spki = publicKey.export({ type: 'spki', format: 'der' })
  return {
    key,
    publicKey,
    keyId: `ed25519:${sha256(spki)}`,
  }
}

export function parseTransparencyPrivateKey(keyBytes) {
  try {
    return keyIdentity(createPrivateKey(keyBytes))
  } catch (error) {
    if (error instanceof TransparencyLogContractError) throw error
    throw new TransparencyLogContractError(
      `cannot parse transparency log private key: ${error.message}`,
    )
  }
}

export function parseTransparencyPublicKey(keyBytes) {
  try {
    return keyIdentity(
      keyBytes?.type === 'public' ? keyBytes : createPublicKey(keyBytes),
    )
  } catch (error) {
    if (error instanceof TransparencyLogContractError) throw error
    throw new TransparencyLogContractError(
      `cannot parse transparency log public key: ${error.message}`,
    )
  }
}

export function canonicalAttestationBytes(attestation) {
  assertValidRootAttestation(attestation)
  return Buffer.from(stableJson(attestation, 0), 'utf8')
}

export function transparencyLeafHash(content) {
  return sha256(Buffer.concat([Buffer.from([0]), Buffer.from(content)]))
}

export function transparencyNodeHash(left, right) {
  if (!DIGEST.test(left ?? '') || !DIGEST.test(right ?? '')) {
    throw new TransparencyLogContractError(
      'transparency Merkle nodes must be lowercase SHA-256 digests',
    )
  }
  return sha256(Buffer.concat([
    Buffer.from([1]),
    Buffer.from(left, 'hex'),
    Buffer.from(right, 'hex'),
  ]))
}

export function transparencyRootFromInclusionProof({
  leafHash,
  leafIndex,
  treeSize,
  inclusionPath,
}) {
  if (!DIGEST.test(leafHash ?? '')) {
    throw new TransparencyLogContractError(
      'transparency leaf hash must be a lowercase SHA-256 digest',
    )
  }
  if (
    !Number.isSafeInteger(leafIndex)
    || !Number.isSafeInteger(treeSize)
    || treeSize < 1
    || leafIndex < 0
    || leafIndex >= treeSize
  ) {
    throw new TransparencyLogContractError(
      'transparency leaf index must identify an entry inside the checkpoint tree',
    )
  }
  if (!Array.isArray(inclusionPath) || inclusionPath.length > 64) {
    throw new TransparencyLogContractError(
      'transparency inclusion path must contain at most 64 hashes',
    )
  }
  let node = leafHash
  let leaf = leafIndex
  let last = treeSize - 1
  let proofIndex = 0
  while (last > 0) {
    const sibling = inclusionPath[proofIndex]
    if (!DIGEST.test(sibling ?? '')) {
      throw new TransparencyLogContractError(
        'transparency inclusion path is incomplete or contains a non-digest node',
      )
    }
    proofIndex += 1
    if ((leaf % 2) === 1 || leaf === last) {
      node = transparencyNodeHash(sibling, node)
      while ((leaf % 2) === 0 && leaf !== 0) {
        leaf = Math.floor(leaf / 2)
        last = Math.floor(last / 2)
      }
    } else {
      node = transparencyNodeHash(node, sibling)
    }
    leaf = Math.floor(leaf / 2)
    last = Math.floor(last / 2)
  }
  if (proofIndex !== inclusionPath.length) {
    throw new TransparencyLogContractError(
      'transparency inclusion path contains unused nodes',
    )
  }
  return node
}

function requestSemanticErrors(value) {
  const errors = []
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return errors
  const entry = value.entry
  if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) return errors
  if (typeof entry.content_base64 !== 'string') return errors
  const content = Buffer.from(entry.content_base64, 'base64')
  if (content.toString('base64') !== entry.content_base64) {
    errors.push(contractError(
      'TRANSPARENCY_ENTRY_BASE64_NONCANONICAL',
      '/entry/content_base64',
      'entry content must use canonical base64 encoding',
    ))
    return errors
  }
  if (entry.content_sha256 !== sha256(content)) {
    errors.push(contractError(
      'TRANSPARENCY_ENTRY_DIGEST_MISMATCH',
      '/entry/content_sha256',
      'entry digest must bind the exact decoded content bytes',
    ))
  }
  try {
    const attestation = JSON.parse(content.toString('utf8'))
    assertValidRootAttestation(attestation)
    if (!canonicalAttestationBytes(attestation).equals(content)) {
      errors.push(contractError(
        'TRANSPARENCY_ENTRY_NOT_CANONICAL',
        '/entry/content_base64',
        'entry content must be the canonical root-attestation JSON bytes',
      ))
    }
  } catch (error) {
    errors.push(contractError(
      'TRANSPARENCY_ENTRY_ATTESTATION_INVALID',
      '/entry/content_base64',
      `entry content is not a valid root attestation: ${error.message}`,
    ))
  }
  return errors
}

export function validateTransparencyPublishRequest(value) {
  const schemaValid = validateRequestSchema(value)
  const errors = [
    ...(schemaValid ? [] : normalizeAjvErrors(validateRequestSchema.errors)),
    ...requestSemanticErrors(value),
  ]
  return { valid: errors.length === 0, errors }
}

export function assertValidTransparencyPublishRequest(value) {
  const validation = validateTransparencyPublishRequest(value)
  if (!validation.valid) {
    throw new TransparencyLogContractError(
      'transparency publication request validation failed',
      validation.errors,
    )
  }
  return value
}

export function createTransparencyPublishRequest(attestation) {
  const content = canonicalAttestationBytes(attestation)
  return assertValidTransparencyPublishRequest({
    schema_version: '1.0.0',
    protocol: 'transparency-log-v1',
    entry: {
      kind: 'red-team-audit/root-manifest-attestation',
      content_sha256: sha256(content),
      content_base64: content.toString('base64'),
    },
  })
}

function receiptSemanticErrors(value) {
  const errors = []
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return errors
  if (validTimestamp(value.checkpoint?.issued_at) === null) {
    errors.push(contractError(
      'TRANSPARENCY_CHECKPOINT_TIME_INVALID',
      '/checkpoint/issued_at',
      'checkpoint issued_at must be a real canonical timestamp',
    ))
  }
  if (
    Number.isSafeInteger(value.leaf_index)
    && Number.isSafeInteger(value.checkpoint?.tree_size)
    && value.leaf_index >= value.checkpoint.tree_size
  ) {
    errors.push(contractError(
      'TRANSPARENCY_LEAF_INDEX_OUT_OF_RANGE',
      '/leaf_index',
      'leaf_index must be smaller than checkpoint tree_size',
    ))
  }
  const signature = Buffer.from(value.signature ?? '', 'base64')
  if (
    signature.length !== 64
    || signature.toString('base64') !== value.signature
  ) {
    errors.push(contractError(
      'TRANSPARENCY_SIGNATURE_NONCANONICAL',
      '/signature',
      'checkpoint signature must be canonical base64 Ed25519 data',
    ))
  }
  return errors
}

export function validateTransparencyInclusionReceipt(value) {
  const schemaValid = validateReceiptSchema(value)
  const errors = [
    ...(schemaValid ? [] : normalizeAjvErrors(validateReceiptSchema.errors)),
    ...receiptSemanticErrors(value),
  ]
  return { valid: errors.length === 0, errors }
}

export function assertValidTransparencyInclusionReceipt(value) {
  const validation = validateTransparencyInclusionReceipt(value)
  if (!validation.valid) {
    throw new TransparencyLogContractError(
      'transparency inclusion receipt validation failed',
      validation.errors,
    )
  }
  return value
}

function signedCheckpointSemanticErrors(value) {
  const errors = []
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return errors
  }
  if (validTimestamp(value.checkpoint?.issued_at) === null) {
    errors.push(contractError(
      'TRANSPARENCY_CHECKPOINT_TIME_INVALID',
      '/checkpoint/issued_at',
      'checkpoint issued_at must be a real canonical timestamp',
    ))
  }
  const signature = Buffer.from(value.signature ?? '', 'base64')
  if (
    signature.length !== 64
    || signature.toString('base64') !== value.signature
  ) {
    errors.push(contractError(
      'TRANSPARENCY_SIGNATURE_NONCANONICAL',
      '/signature',
      'checkpoint signature must be canonical base64 Ed25519 data',
    ))
  }
  return errors
}

export function validateTransparencySignedCheckpoint(value) {
  const schemaValid = validateSignedCheckpointSchema(value)
  const errors = [
    ...(schemaValid
      ? []
      : normalizeAjvErrors(validateSignedCheckpointSchema.errors)),
    ...signedCheckpointSemanticErrors(value),
  ]
  return { valid: errors.length === 0, errors }
}

export function assertValidTransparencySignedCheckpoint(value) {
  const validation = validateTransparencySignedCheckpoint(value)
  if (!validation.valid) {
    throw new TransparencyLogContractError(
      'signed transparency checkpoint validation failed',
      validation.errors,
    )
  }
  return value
}

function consistencyRequestSemanticErrors(value) {
  const errors = []
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return errors
  }
  if (
    Number.isSafeInteger(value.first_tree_size)
    && Number.isSafeInteger(value.second_tree_size)
    && value.first_tree_size > value.second_tree_size
  ) {
    errors.push(contractError(
      'TRANSPARENCY_CONSISTENCY_SIZE_ORDER_INVALID',
      '/first_tree_size',
      'first_tree_size must not exceed second_tree_size',
    ))
  }
  return errors
}

export function validateTransparencyConsistencyRequest(value) {
  const schemaValid = validateConsistencyRequestSchema(value)
  const errors = [
    ...(schemaValid
      ? []
      : normalizeAjvErrors(validateConsistencyRequestSchema.errors)),
    ...consistencyRequestSemanticErrors(value),
  ]
  return { valid: errors.length === 0, errors }
}

export function assertValidTransparencyConsistencyRequest(value) {
  const validation = validateTransparencyConsistencyRequest(value)
  if (!validation.valid) {
    throw new TransparencyLogContractError(
      'transparency consistency request validation failed',
      validation.errors,
    )
  }
  return value
}

export function createTransparencyConsistencyRequest({
  firstSize,
  secondSize,
}) {
  return assertValidTransparencyConsistencyRequest({
    schema_version: '1.0.0',
    protocol: 'transparency-log-consistency-v1',
    kind: 'red-team-audit/transparency-consistency-request',
    first_tree_size: firstSize,
    second_tree_size: secondSize,
  })
}

function largestPowerOfTwoBelow(value) {
  let power = 1
  while (power * 2 < value) power *= 2
  return power
}

function consistencyProofLength(firstSize, secondSize, complete) {
  if (firstSize === secondSize) return complete ? 0 : 1
  const split = largestPowerOfTwoBelow(secondSize)
  return 1 + (
    firstSize <= split
      ? consistencyProofLength(firstSize, split, complete)
      : consistencyProofLength(
        firstSize - split,
        secondSize - split,
        false,
      )
  )
}

export function transparencyConsistencyProofLength(firstSize, secondSize) {
  if (
    !Number.isSafeInteger(firstSize)
    || !Number.isSafeInteger(secondSize)
    || firstSize < 1
    || firstSize > secondSize
  ) {
    throw new TransparencyLogContractError(
      'transparency consistency sizes must satisfy 1 <= firstSize <= secondSize',
    )
  }
  return consistencyProofLength(firstSize, secondSize, true)
}

function prefixedContractErrors(errors, prefix) {
  return errors.map((error) => ({
    ...error,
    instancePath: error.instancePath === '/'
      ? prefix
      : `${prefix}${error.instancePath}`,
  }))
}

function consistencyProofSemanticErrors(value) {
  const errors = []
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return errors
  }
  const first = value.first_checkpoint
  const second = value.second_checkpoint
  if (first !== undefined) {
    errors.push(...prefixedContractErrors(
      signedCheckpointSemanticErrors(first),
      '/first_checkpoint',
    ))
  }
  if (second !== undefined) {
    errors.push(...prefixedContractErrors(
      signedCheckpointSemanticErrors(second),
      '/second_checkpoint',
    ))
  }
  const firstCheckpoint = first?.checkpoint
  const secondCheckpoint = second?.checkpoint
  const firstSize = firstCheckpoint?.tree_size
  const secondSize = secondCheckpoint?.tree_size
  if (
    Number.isSafeInteger(firstSize)
    && Number.isSafeInteger(secondSize)
  ) {
    if (firstSize > secondSize) {
      errors.push(contractError(
        'TRANSPARENCY_CONSISTENCY_SIZE_ORDER_INVALID',
        '/first_checkpoint/checkpoint/tree_size',
        'first checkpoint tree_size must not exceed second checkpoint tree_size',
      ))
    } else if (Array.isArray(value.consistency_path)) {
      const expectedLength = transparencyConsistencyProofLength(
        firstSize,
        secondSize,
      )
      if (value.consistency_path.length !== expectedLength) {
        errors.push(contractError(
          'TRANSPARENCY_CONSISTENCY_PATH_LENGTH_INVALID',
          '/consistency_path',
          `consistency_path must contain exactly ${expectedLength} nodes for the supplied tree sizes`,
          { expectedLength },
        ))
      }
    }
    if (
      firstSize === secondSize
      && typeof firstCheckpoint?.root_hash === 'string'
      && typeof secondCheckpoint?.root_hash === 'string'
      && firstCheckpoint.root_hash !== secondCheckpoint.root_hash
    ) {
      errors.push(contractError(
        'TRANSPARENCY_CONSISTENCY_SAME_SIZE_ROOT_MISMATCH',
        '/second_checkpoint/checkpoint/root_hash',
        'same-size checkpoints must have the same root_hash',
      ))
    }
  }
  if (
    typeof firstCheckpoint?.origin === 'string'
    && typeof secondCheckpoint?.origin === 'string'
    && firstCheckpoint.origin !== secondCheckpoint.origin
  ) {
    errors.push(contractError(
      'TRANSPARENCY_CONSISTENCY_ORIGIN_MISMATCH',
      '/second_checkpoint/checkpoint/origin',
      'consistency checkpoints must name the same log origin',
    ))
  }
  if (
    typeof firstCheckpoint?.signing?.key_id === 'string'
    && typeof secondCheckpoint?.signing?.key_id === 'string'
    && firstCheckpoint.signing.key_id !== secondCheckpoint.signing.key_id
  ) {
    errors.push(contractError(
      'TRANSPARENCY_CONSISTENCY_KEY_MISMATCH',
      '/second_checkpoint/checkpoint/signing/key_id',
      'consistency checkpoints must use the same log signing key',
    ))
  }
  const firstIssued = validTimestamp(firstCheckpoint?.issued_at)
  const secondIssued = validTimestamp(secondCheckpoint?.issued_at)
  if (
    firstIssued !== null
    && secondIssued !== null
    && secondIssued < firstIssued
  ) {
    errors.push(contractError(
      'TRANSPARENCY_CONSISTENCY_TIME_ROLLBACK',
      '/second_checkpoint/checkpoint/issued_at',
      'second checkpoint issued_at must not precede first checkpoint issued_at',
    ))
  }
  return errors
}

export function validateTransparencyConsistencyProof(value) {
  const schemaValid = validateConsistencyProofSchema(value)
  const errors = [
    ...(schemaValid
      ? []
      : normalizeAjvErrors(validateConsistencyProofSchema.errors)),
    ...consistencyProofSemanticErrors(value),
  ]
  return { valid: errors.length === 0, errors }
}

export function assertValidTransparencyConsistencyProof(value) {
  const validation = validateTransparencyConsistencyProof(value)
  if (!validation.valid) {
    throw new TransparencyLogContractError(
      'transparency consistency proof validation failed',
      validation.errors,
    )
  }
  return value
}

export function createTransparencyConsistencyProof({
  firstCheckpoint,
  secondCheckpoint,
  consistencyPath,
}) {
  return assertValidTransparencyConsistencyProof({
    schema_version: '1.0.0',
    kind: 'red-team-audit/transparency-consistency-proof',
    first_checkpoint: structuredClone(firstCheckpoint),
    second_checkpoint: structuredClone(secondCheckpoint),
    consistency_path: [...consistencyPath],
  })
}

function checkpointSigningPayload(checkpoint) {
  return Buffer.concat([
    CHECKPOINT_SIGNATURE_CONTEXT,
    Buffer.from(stableJson(checkpoint, 0), 'utf8'),
  ])
}

export function createTransparencySignedCheckpoint({
  treeSize,
  rootHash,
  origin,
  privateKeyBytes,
  issuedAt = new Date(),
}) {
  const timestamp = normalizeInstant(issuedAt, 'checkpoint issuedAt')
  const signingKey = parseTransparencyPrivateKey(privateKeyBytes)
  const checkpoint = {
    origin,
    tree_size: treeSize,
    root_hash: rootHash,
    issued_at: timestamp.toISOString(),
    signing: {
      algorithm: 'Ed25519',
      key_id: signingKey.keyId,
    },
  }
  return assertValidTransparencySignedCheckpoint({
    schema_version: '1.0.0',
    kind: 'red-team-audit/transparency-signed-checkpoint',
    checkpoint,
    signature: signBytes(
      null,
      checkpointSigningPayload(checkpoint),
      signingKey.key,
    ).toString('base64'),
  })
}

export function projectTransparencySignedCheckpoint(receipt) {
  assertValidTransparencyInclusionReceipt(receipt)
  return assertValidTransparencySignedCheckpoint({
    schema_version: '1.0.0',
    kind: 'red-team-audit/transparency-signed-checkpoint',
    checkpoint: structuredClone(receipt.checkpoint),
    signature: receipt.signature,
  })
}

export const createTransparencySignedCheckpointFromReceipt =
  projectTransparencySignedCheckpoint

export function createTransparencyInclusionReceipt({
  attestation,
  leafIndex,
  treeSize,
  inclusionPath,
  rootHash,
  origin,
  privateKeyBytes,
  issuedAt = new Date(),
}) {
  const content = canonicalAttestationBytes(attestation)
  const entry = {
    kind: 'red-team-audit/root-manifest-attestation',
    content_sha256: sha256(content),
    leaf_hash: transparencyLeafHash(content),
  }
  const calculatedRoot = transparencyRootFromInclusionProof({
    leafHash: entry.leaf_hash,
    leafIndex,
    treeSize,
    inclusionPath,
  })
  if (calculatedRoot !== rootHash) {
    throw new TransparencyLogContractError(
      'transparency inclusion proof does not produce the supplied checkpoint root',
    )
  }
  const timestamp = issuedAt instanceof Date ? issuedAt : new Date(issuedAt)
  if (Number.isNaN(timestamp.valueOf())) {
    throw new TransparencyLogContractError(
      'transparency checkpoint time is invalid',
    )
  }
  const signingKey = parseTransparencyPrivateKey(privateKeyBytes)
  const checkpoint = {
    origin,
    tree_size: treeSize,
    root_hash: rootHash,
    issued_at: timestamp.toISOString(),
    signing: {
      algorithm: 'Ed25519',
      key_id: signingKey.keyId,
    },
  }
  return assertValidTransparencyInclusionReceipt({
    schema_version: '1.0.0',
    kind: 'red-team-audit/transparency-inclusion-receipt',
    entry,
    leaf_index: leafIndex,
    inclusion_path: [...inclusionPath],
    checkpoint,
    signature: signBytes(
      null,
      checkpointSigningPayload(checkpoint),
      signingKey.key,
    ).toString('base64'),
  })
}

function normalizeInstant(value, label) {
  const instant = value instanceof Date ? value : new Date(value)
  if (Number.isNaN(instant.valueOf())) {
    throw new TransparencyLogContractError(`${label} must be a valid instant`)
  }
  return instant
}

function normalizeMaxClockSkew(maxClockSkewMs) {
  if (
    !Number.isSafeInteger(maxClockSkewMs)
    || maxClockSkewMs < 0
    || maxClockSkewMs > 300000
  ) {
    throw new TransparencyLogContractError(
      'transparency maxClockSkewMs must be between 0 and 300000',
    )
  }
  return maxClockSkewMs
}

function verifySignedCheckpointWithIdentity({
  signedCheckpoint,
  publicKey,
  expectedOrigin,
  currentTime,
  maxClockSkewMs,
}) {
  assertValidTransparencySignedCheckpoint(signedCheckpoint)
  const checkpoint = signedCheckpoint.checkpoint
  if (checkpoint.signing.key_id !== publicKey.keyId) {
    throw new TransparencyLogContractError(
      'transparency checkpoint key does not match the externally pinned public key',
    )
  }
  if (
    expectedOrigin !== undefined
    && checkpoint.origin !== expectedOrigin
  ) {
    throw new TransparencyLogContractError(
      'transparency checkpoint origin does not match the trusted log configuration',
    )
  }
  if (!verifyBytes(
    null,
    checkpointSigningPayload(checkpoint),
    publicKey.publicKey,
    Buffer.from(signedCheckpoint.signature, 'base64'),
  )) {
    throw new TransparencyLogContractError(
      'transparency checkpoint signature verification failed',
    )
  }
  const issued = Date.parse(checkpoint.issued_at)
  if (issued > currentTime + maxClockSkewMs) {
    throw new TransparencyLogContractError(
      'transparency checkpoint is issued in the future beyond the permitted clock skew',
    )
  }
  return checkpoint
}

export function verifyTransparencySignedCheckpoint({
  signedCheckpoint,
  publicKeyBytes,
  expectedOrigin,
  now = new Date(),
  maxClockSkewMs = 0,
}) {
  const skew = normalizeMaxClockSkew(maxClockSkewMs)
  const current = normalizeInstant(now, 'now').getTime()
  const publicKey = parseTransparencyPublicKey(publicKeyBytes)
  const checkpoint = verifySignedCheckpointWithIdentity({
    signedCheckpoint,
    publicKey,
    expectedOrigin,
    currentTime: current,
    maxClockSkewMs: skew,
  })
  return {
    status: 'VERIFIED',
    claim: 'SIGNED_TRANSPARENCY_CHECKPOINT',
    log_key_id: publicKey.keyId,
    origin: checkpoint.origin,
    tree_size: checkpoint.tree_size,
    root_hash: checkpoint.root_hash,
    issued_at: checkpoint.issued_at,
    consistency: 'NOT_VERIFIED',
    witness_quorum: 'NOT_VERIFIED',
    trusted_time: false,
  }
}

function isExactPowerOfTwo(value) {
  let remaining = value
  while (remaining > 1 && (remaining % 2) === 0) {
    remaining = Math.floor(remaining / 2)
  }
  return remaining === 1
}

export function verifyTransparencyConsistency({
  firstTreeSize,
  firstRootHash,
  secondTreeSize,
  secondRootHash,
  consistencyPath,
}) {
  if (
    !Number.isSafeInteger(firstTreeSize)
    || !Number.isSafeInteger(secondTreeSize)
    || firstTreeSize < 1
    || firstTreeSize > secondTreeSize
  ) {
    throw new TransparencyLogContractError(
      'transparency consistency sizes must satisfy 1 <= firstTreeSize <= secondTreeSize',
    )
  }
  if (!DIGEST.test(firstRootHash ?? '') || !DIGEST.test(secondRootHash ?? '')) {
    throw new TransparencyLogContractError(
      'transparency consistency roots must be lowercase SHA-256 digests',
    )
  }
  if (!Array.isArray(consistencyPath) || consistencyPath.length > 64) {
    throw new TransparencyLogContractError(
      'transparency consistency path must contain at most 64 hashes',
    )
  }
  for (const node of consistencyPath) {
    if (!DIGEST.test(node ?? '')) {
      throw new TransparencyLogContractError(
        'transparency consistency path contains a non-digest node',
      )
    }
  }
  const expectedLength = transparencyConsistencyProofLength(
    firstTreeSize,
    secondTreeSize,
  )
  if (consistencyPath.length !== expectedLength) {
    throw new TransparencyLogContractError(
      `transparency consistency path must contain exactly ${expectedLength} nodes for the supplied tree sizes`,
    )
  }
  if (firstTreeSize === secondTreeSize) {
    if (firstRootHash !== secondRootHash) {
      throw new TransparencyLogContractError(
        'same-size transparency checkpoints have different roots',
      )
    }
    return {
      status: 'VERIFIED',
      relation: 'SAME_SIZE_SAME_ROOT',
      first_tree_size: firstTreeSize,
      second_tree_size: secondTreeSize,
      first_root_hash: firstRootHash,
      second_root_hash: secondRootHash,
      consumed_nodes: 0,
    }
  }

  const path = [...consistencyPath]
  if (isExactPowerOfTwo(firstTreeSize)) path.unshift(firstRootHash)
  if (path.length === 0) {
    throw new TransparencyLogContractError(
      'different-size transparency checkpoints require a consistency path',
    )
  }
  let firstNode = firstTreeSize - 1
  let secondNode = secondTreeSize - 1
  while ((firstNode % 2) === 1) {
    firstNode = Math.floor(firstNode / 2)
    secondNode = Math.floor(secondNode / 2)
  }
  let firstCalculated = path[0]
  let secondCalculated = path[0]
  let proofIndex = 1
  while (proofIndex < path.length) {
    if (secondNode === 0) {
      throw new TransparencyLogContractError(
        'transparency consistency path contains unused nodes',
      )
    }
    const node = path[proofIndex]
    proofIndex += 1
    if ((firstNode % 2) === 1 || firstNode === secondNode) {
      firstCalculated = transparencyNodeHash(node, firstCalculated)
      secondCalculated = transparencyNodeHash(node, secondCalculated)
      if ((firstNode % 2) === 0) {
        while (firstNode !== 0 && (firstNode % 2) === 0) {
          firstNode = Math.floor(firstNode / 2)
          secondNode = Math.floor(secondNode / 2)
        }
      }
    } else {
      secondCalculated = transparencyNodeHash(secondCalculated, node)
    }
    firstNode = Math.floor(firstNode / 2)
    secondNode = Math.floor(secondNode / 2)
  }
  if (
    proofIndex !== path.length
    || firstNode !== 0
    || secondNode !== 0
    || firstCalculated !== firstRootHash
    || secondCalculated !== secondRootHash
  ) {
    throw new TransparencyLogContractError(
      'transparency consistency path does not prove the supplied checkpoint roots',
    )
  }
  return {
    status: 'VERIFIED',
    relation: 'APPEND_ONLY_EXTENSION',
    first_tree_size: firstTreeSize,
    second_tree_size: secondTreeSize,
    first_root_hash: firstRootHash,
    second_root_hash: secondRootHash,
    consumed_nodes: consistencyPath.length,
  }
}

export const verifyTransparencyConsistencyPath =
  verifyTransparencyConsistency

export function verifyTransparencyConsistencyProof({
  proof,
  publicKeyBytes,
  expectedOrigin,
  now = new Date(),
  maxClockSkewMs = 0,
}) {
  assertValidTransparencyConsistencyProof(proof)
  const skew = normalizeMaxClockSkew(maxClockSkewMs)
  const current = normalizeInstant(now, 'now').getTime()
  const publicKey = parseTransparencyPublicKey(publicKeyBytes)
  const first = verifySignedCheckpointWithIdentity({
    signedCheckpoint: proof.first_checkpoint,
    publicKey,
    expectedOrigin,
    currentTime: current,
    maxClockSkewMs: skew,
  })
  const second = verifySignedCheckpointWithIdentity({
    signedCheckpoint: proof.second_checkpoint,
    publicKey,
    expectedOrigin,
    currentTime: current,
    maxClockSkewMs: skew,
  })
  if (Date.parse(second.issued_at) < Date.parse(first.issued_at)) {
    throw new TransparencyLogContractError(
      'second transparency checkpoint time precedes the first checkpoint time',
    )
  }
  const continuity = verifyTransparencyConsistency({
    firstTreeSize: first.tree_size,
    firstRootHash: first.root_hash,
    secondTreeSize: second.tree_size,
    secondRootHash: second.root_hash,
    consistencyPath: proof.consistency_path,
  })
  return {
    status: 'VERIFIED',
    claim: 'CONSISTENCY_BETWEEN_SIGNED_CHECKPOINTS',
    relation: continuity.relation,
    log_key_id: publicKey.keyId,
    origin: first.origin,
    first_tree_size: first.tree_size,
    first_root_hash: first.root_hash,
    first_issued_at: first.issued_at,
    second_tree_size: second.tree_size,
    second_root_hash: second.root_hash,
    second_issued_at: second.issued_at,
    consistency: 'VERIFIED_BETWEEN_SUPPLIED_CHECKPOINTS',
    split_view_detection: 'NOT_VERIFIED',
    witness_quorum: 'NOT_VERIFIED',
    trusted_time: false,
  }
}

export function verifyTransparencyInclusion({
  receipt,
  attestation,
  publicKeyBytes,
  expectedOrigin,
  now = new Date(),
  maxClockSkewMs = 0,
}) {
  assertValidTransparencyInclusionReceipt(receipt)
  if (
    !Number.isSafeInteger(maxClockSkewMs)
    || maxClockSkewMs < 0
    || maxClockSkewMs > 300000
  ) {
    throw new TransparencyLogContractError(
      'transparency maxClockSkewMs must be between 0 and 300000',
    )
  }
  const publicKey = parseTransparencyPublicKey(publicKeyBytes)
  if (receipt.checkpoint.signing.key_id !== publicKey.keyId) {
    throw new TransparencyLogContractError(
      'transparency checkpoint key does not match the externally pinned public key',
    )
  }
  if (
    expectedOrigin !== undefined
    && receipt.checkpoint.origin !== expectedOrigin
  ) {
    throw new TransparencyLogContractError(
      'transparency checkpoint origin does not match the trusted log configuration',
    )
  }
  const signatureValid = verifyBytes(
    null,
    checkpointSigningPayload(receipt.checkpoint),
    publicKey.publicKey,
    Buffer.from(receipt.signature, 'base64'),
  )
  if (!signatureValid) {
    throw new TransparencyLogContractError(
      'transparency checkpoint signature verification failed',
    )
  }
  const current = normalizeInstant(now, 'now').getTime()
  const issued = Date.parse(receipt.checkpoint.issued_at)
  if (issued > current + maxClockSkewMs) {
    throw new TransparencyLogContractError(
      'transparency checkpoint is issued in the future beyond the permitted clock skew',
    )
  }
  const content = canonicalAttestationBytes(attestation)
  const contentSha256 = sha256(content)
  const leafHash = transparencyLeafHash(content)
  if (
    receipt.entry.content_sha256 !== contentSha256
    || receipt.entry.leaf_hash !== leafHash
  ) {
    throw new TransparencyLogContractError(
      'transparency receipt does not bind the supplied root attestation',
    )
  }
  const calculatedRoot = transparencyRootFromInclusionProof({
    leafHash,
    leafIndex: receipt.leaf_index,
    treeSize: receipt.checkpoint.tree_size,
    inclusionPath: receipt.inclusion_path,
  })
  if (calculatedRoot !== receipt.checkpoint.root_hash) {
    throw new TransparencyLogContractError(
      'transparency inclusion proof does not produce the signed checkpoint root',
    )
  }
  return {
    status: 'VERIFIED',
    claim: 'INCLUSION_AT_SIGNED_CHECKPOINT',
    log_key_id: publicKey.keyId,
    origin: receipt.checkpoint.origin,
    tree_size: receipt.checkpoint.tree_size,
    leaf_index: receipt.leaf_index,
    root_hash: receipt.checkpoint.root_hash,
    issued_at: receipt.checkpoint.issued_at,
    consistency: 'NOT_VERIFIED',
    witness_quorum: 'NOT_VERIFIED',
    trusted_time: false,
  }
}
