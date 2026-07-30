import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as signBytes,
  verify as verifyBytes,
} from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import { stableJson } from './run-engine.mjs'

const ROOT_ATTESTATION_SCHEMA_URL = new URL(
  '../../schemas/root-attestation.schema.json',
  import.meta.url,
)
const SIGNATURE_CONTEXT = Buffer.from(
  'red-team-audit/root-manifest-attestation/v1\u0000',
  'utf8',
)

export const rootAttestationSchema = JSON.parse(
  readFileSync(fileURLToPath(ROOT_ATTESTATION_SCHEMA_URL), 'utf8'),
)

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})
ajv.addSchema(rootAttestationSchema)
const validateRootAttestationSchema = ajv.getSchema(rootAttestationSchema.$id)

export class RootAttestationError extends Error {
  constructor(message, details = []) {
    super(message)
    this.name = 'RootAttestationError'
    this.code = 'ROOT_ATTESTATION_INVALID'
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

function publicKeyIdentity(key) {
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new RootAttestationError('root manifest signing key must be Ed25519')
  }
  const spki = key.export({ type: 'spki', format: 'der' })
  return {
    key,
    keyId: `ed25519:${sha256(spki)}`,
  }
}

function parsePrivateKey(keyBytes) {
  try {
    const privateKey = createPrivateKey(keyBytes)
    if (privateKey.asymmetricKeyType !== 'ed25519') {
      throw new RootAttestationError('root manifest signing key must be Ed25519')
    }
    const identity = publicKeyIdentity(createPublicKey(privateKey))
    return {
      key: privateKey,
      keyId: identity.keyId,
    }
  } catch (error) {
    if (error instanceof RootAttestationError) throw error
    throw new RootAttestationError(
      `cannot parse root manifest signing key: ${error.message}`,
    )
  }
}

function parsePublicKey(keyBytes) {
  try {
    return publicKeyIdentity(createPublicKey(keyBytes))
  } catch (error) {
    if (error instanceof RootAttestationError) throw error
    throw new RootAttestationError(
      `cannot parse root manifest public key: ${error.message}`,
    )
  }
}

function unsignedAttestation(attestation) {
  const {
    signature: _signature,
    ...unsigned
  } = attestation
  return unsigned
}

function signingPayload(attestation) {
  return Buffer.concat([
    SIGNATURE_CONTEXT,
    Buffer.from(stableJson(unsignedAttestation(attestation), 0), 'utf8'),
  ])
}

function assertDigest(value) {
  if (!/^[a-f0-9]{64}$/.test(value ?? '')) {
    throw new RootAttestationError(
      'root manifest SHA-256 must be a lowercase 64-character digest',
    )
  }
}

export function validateRootAttestation(value) {
  const valid = validateRootAttestationSchema(value)
  return {
    valid,
    errors: valid ? [] : normalizeAjvErrors(validateRootAttestationSchema.errors),
  }
}

export function assertValidRootAttestation(value) {
  const result = validateRootAttestation(value)
  if (!result.valid) {
    throw new RootAttestationError(
      'root manifest attestation violates its schema',
      result.errors,
    )
  }
  const decoded = Buffer.from(value.signature, 'base64')
  if (decoded.length !== 64 || decoded.toString('base64') !== value.signature) {
    throw new RootAttestationError(
      'root manifest attestation signature is not canonical base64 Ed25519 data',
    )
  }
  if (Number.isNaN(Date.parse(value.signed_at))) {
    throw new RootAttestationError(
      'root manifest attestation signed_at is not a real timestamp',
    )
  }
  return value
}

export function createRootAttestation({
  run,
  runSha256,
  privateKeyBytes,
  signedAt = new Date(),
}) {
  assertDigest(runSha256)
  if (
    run === null
    || typeof run !== 'object'
    || !['COMPLETED', 'COMPLETE_WITH_GAPS', 'ABORTED', 'FAILED'].includes(run.state)
    || run.phase !== 'FINALIZED'
  ) {
    throw new RootAttestationError(
      'only a terminal FINALIZED run manifest can be attested',
    )
  }
  const signingKey = parsePrivateKey(privateKeyBytes)
  const timestamp = signedAt instanceof Date ? signedAt : new Date(signedAt)
  if (Number.isNaN(timestamp.valueOf())) {
    throw new RootAttestationError('root manifest attestation time is invalid')
  }
  const attestation = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/root-manifest-attestation',
    signed_at: timestamp.toISOString(),
    run: {
      run_id: run.run_id,
      schema_version: run.schema_version,
      state: run.state,
      phase: run.phase,
      sha256: runSha256,
    },
    signing: {
      algorithm: 'Ed25519',
      key_id: signingKey.keyId,
    },
  }
  const signature = signBytes(
    null,
    signingPayload(attestation),
    signingKey.key,
  ).toString('base64')
  return assertValidRootAttestation({
    ...attestation,
    signature,
  })
}

export function verifyRootAttestation({
  attestation,
  run,
  runSha256,
  publicKeyBytes,
}) {
  assertDigest(runSha256)
  assertValidRootAttestation(attestation)
  const publicKey = parsePublicKey(publicKeyBytes)
  if (attestation.signing.key_id !== publicKey.keyId) {
    throw new RootAttestationError(
      'root manifest attestation key does not match the externally pinned public key',
    )
  }
  const expectedRun = {
    run_id: run?.run_id,
    schema_version: run?.schema_version,
    state: run?.state,
    phase: run?.phase,
    sha256: runSha256,
  }
  if (stableJson(attestation.run, 0) !== stableJson(expectedRun, 0)) {
    throw new RootAttestationError(
      'root manifest attestation does not describe the exact loaded run manifest',
    )
  }
  const valid = verifyBytes(
    null,
    signingPayload(attestation),
    publicKey.key,
    Buffer.from(attestation.signature, 'base64'),
  )
  if (!valid) {
    throw new RootAttestationError(
      'root manifest attestation signature verification failed',
    )
  }
  return {
    status: 'VERIFIED',
    key_id: publicKey.keyId,
    run_sha256: runSha256,
    signed_at: attestation.signed_at,
  }
}
