import { TextDecoder } from 'node:util'

import { contentDigestHeader } from '../../scripts/lib/remote-gateway-contracts.mjs'
import { stableJson } from '../../scripts/lib/run-engine.mjs'
import {
  TransparencyLogContractError,
  assertValidTransparencyConsistencyProof,
  assertValidTransparencyConsistencyRequest,
  assertValidTransparencyInclusionReceipt,
  assertValidTransparencyPublishRequest,
  parseTransparencyPublicKey,
  verifyTransparencyConsistencyProof,
  verifyTransparencyInclusion,
} from '../../scripts/lib/transparency-log-contracts.mjs'

const PROTOCOL = 'transparency-log-v1'
const CONSISTENCY_PROTOCOL = 'transparency-log-consistency-v1'
const JSON_MEDIA_TYPE = 'application/json'
const DEFAULT_MAX_REQUEST_BYTES = 256 * 1024
const DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024
const DEFAULT_MAX_HEADER_BYTES = 16 * 1024
const DEFAULT_MAX_HEADER_COUNT = 64
const MAX_MESSAGE_BYTES = 1024 * 1024
const ORIGIN = /^[A-Za-z0-9][A-Za-z0-9._:/-]+$/
const UTF8 = new TextDecoder('utf-8', { fatal: true })

export class ReferenceTransparencyLogRequestError extends TransparencyLogContractError {
  constructor(message, details = []) {
    super(message, details)
    this.name = 'ReferenceTransparencyLogRequestError'
    this.code = 'TRANSPARENCY_REQUEST_INVALID'
  }
}

function contractError(message) {
  return new TransparencyLogContractError(message)
}

function requestError(message, details = []) {
  return new ReferenceTransparencyLogRequestError(message, details)
}

function requireBound(value, label, maximum = MAX_MESSAGE_BYTES) {
  if (
    !Number.isSafeInteger(value)
    || value < 1
    || value > maximum
  ) {
    throw new TypeError(
      `reference transparency ${label} must be an integer between 1 and ${maximum}`,
    )
  }
  return value
}

function normalizeHeaders(headers, { maxHeaderBytes, maxHeaderCount }) {
  if (headers === null || typeof headers !== 'object' || Array.isArray(headers)) {
    throw requestError('reference transparency request headers must be a Node-style header object')
  }
  const normalized = new Map()
  let count = 0
  let bytes = 0
  for (const [rawName, rawValue] of Object.entries(headers)) {
    const name = rawName.toLowerCase()
    if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name)) {
      throw requestError(`reference transparency request header ${rawName} has an invalid name`)
    }
    if (normalized.has(name)) {
      throw requestError(
        `reference transparency request header ${name} is ambiguous`,
      )
    }
    if (Array.isArray(rawValue)) {
      throw requestError(
        `reference transparency request header ${name} must have one value`,
      )
    }
    if (typeof rawValue !== 'string' || /[\r\n\u0000]/.test(rawValue)) {
      throw requestError(
        `reference transparency request header ${name} has an invalid value`,
      )
    }
    count += 1
    bytes += Buffer.byteLength(rawName, 'utf8')
      + Buffer.byteLength(rawValue, 'utf8')
      + 4
    if (count > maxHeaderCount || bytes > maxHeaderBytes) {
      throw requestError(
        'reference transparency request headers exceeded the configured limit',
      )
    }
    normalized.set(name, rawValue)
  }
  return normalized
}

function bodyBytes(body) {
  if (body === undefined || body === null) return Buffer.alloc(0)
  if (
    typeof body !== 'string'
    && !Buffer.isBuffer(body)
    && !(body instanceof Uint8Array)
  ) {
    throw requestError(
      'reference transparency request body must contain exact bytes',
    )
  }
  return Buffer.from(body)
}

function parseContentLength(value) {
  if (value === undefined) {
    throw requestError('reference transparency request requires Content-Length')
  }
  if (!/^(?:0|[1-9][0-9]*)$/.test(value)) {
    throw requestError(
      'reference transparency request Content-Length must be one canonical decimal integer',
    )
  }
  const length = Number(value)
  if (!Number.isSafeInteger(length)) {
    throw requestError(
      'reference transparency request Content-Length exceeds the safe integer range',
    )
  }
  return length
}

function parseCanonicalRequest(bytes) {
  let text
  try {
    text = UTF8.decode(bytes)
  } catch (error) {
    throw requestError(
      `reference transparency request is not valid UTF-8: ${error.message}`,
    )
  }
  let document
  try {
    document = JSON.parse(text)
  } catch (error) {
    throw requestError(
      `reference transparency request is not valid JSON: ${error.message}`,
    )
  }
  let canonical
  try {
    canonical = Buffer.from(stableJson(document, 0), 'utf8')
  } catch (error) {
    throw requestError(
      `reference transparency request cannot be canonicalized: ${error.message}`,
    )
  }
  if (!canonical.equals(bytes)) {
    throw requestError(
      'reference transparency request must use canonical JSON bytes',
    )
  }
  try {
    assertValidTransparencyPublishRequest(document)
  } catch (error) {
    if (error instanceof TransparencyLogContractError) {
      throw requestError(error.message, error.details)
    }
    throw error
  }
  return document
}

function parseCanonicalConsistencyRequest(bytes) {
  let text
  try {
    text = UTF8.decode(bytes)
  } catch (error) {
    throw requestError(
      `reference transparency consistency request is not valid UTF-8: ${error.message}`,
    )
  }
  let document
  try {
    document = JSON.parse(text)
  } catch (error) {
    throw requestError(
      `reference transparency consistency request is not valid JSON: ${error.message}`,
    )
  }
  let canonical
  try {
    canonical = Buffer.from(stableJson(document, 0), 'utf8')
  } catch (error) {
    throw requestError(
      `reference transparency consistency request cannot be canonicalized: ${error.message}`,
    )
  }
  if (!canonical.equals(bytes)) {
    throw requestError(
      'reference transparency consistency request must use canonical JSON bytes',
    )
  }
  try {
    assertValidTransparencyConsistencyRequest(document)
  } catch (error) {
    if (error instanceof TransparencyLogContractError) {
      throw requestError(error.message, error.details)
    }
    throw error
  }
  return document
}

function normalizeInstant(value) {
  const instant = value instanceof Date
    ? new Date(value.getTime())
    : new Date(value)
  if (Number.isNaN(instant.valueOf())) {
    throw requestError('reference transparency request time must be a valid instant')
  }
  return instant
}

function resolvePublisher({ append, store }) {
  if (append !== undefined && store !== undefined) {
    throw new TypeError(
      'reference transparency handler accepts either append or store, not both',
    )
  }
  if (typeof append === 'function') {
    return (document, instant) => append(document, { now: instant })
  }
  if (store && typeof store.publish === 'function') {
    return (document, instant) => store.publish(document, {
      now: instant,
      issuedAt: instant,
    })
  }
  throw new TypeError(
    'reference transparency handler requires an append function or publish-capable store',
  )
}

function resolveConsistencyProver({ prove, store }) {
  if (prove !== undefined && store !== undefined) {
    throw new TypeError(
      'reference transparency consistency handler accepts either prove or store, not both',
    )
  }
  if (typeof prove === 'function') {
    return (document, instant) => prove(document, { now: instant })
  }
  if (store && typeof store.proveConsistency === 'function') {
    return (document, instant) => store.proveConsistency(document, {
      now: instant,
      issuedAt: instant,
    })
  }
  throw new TypeError(
    'reference transparency consistency handler requires a prove function or consistency-capable store',
  )
}

function trustedOrigin(origin) {
  if (
    typeof origin !== 'string'
    || origin.length < 3
    || origin.length > 256
    || !ORIGIN.test(origin)
  ) {
    throw new TypeError(
      'reference transparency handler origin must be a valid transparency log origin',
    )
  }
  return origin
}

/**
 * Creates the protocol boundary used by the reference HTTPS adapter. The
 * returned function consumes an already-buffered Node-style request
 * description and deliberately performs no socket I/O.
 */
export function createReferenceTransparencyLogHandler({
  append,
  store,
  origin,
  logPublicKeyBytes,
  maxClockSkewMs = 0,
  maxRequestBytes = DEFAULT_MAX_REQUEST_BYTES,
  maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
  maxHeaderBytes = DEFAULT_MAX_HEADER_BYTES,
  maxHeaderCount = DEFAULT_MAX_HEADER_COUNT,
} = {}) {
  const publish = resolvePublisher({ append, store })
  const expectedOrigin = trustedOrigin(origin ?? store?.origin)
  const publicIdentity = parseTransparencyPublicKey(
    logPublicKeyBytes ?? store?.publicKeyBytes,
  )
  if (store?.origin !== undefined && store.origin !== expectedOrigin) {
    throw contractError(
      'reference transparency store origin does not match the trusted origin',
    )
  }
  if (store?.keyId !== undefined && store.keyId !== publicIdentity.keyId) {
    throw contractError(
      'reference transparency store key does not match the trusted public key',
    )
  }
  requireBound(maxRequestBytes, 'maxRequestBytes')
  requireBound(maxResponseBytes, 'maxResponseBytes')
  requireBound(maxHeaderBytes, 'maxHeaderBytes', 64 * 1024)
  requireBound(maxHeaderCount, 'maxHeaderCount', 1024)
  if (
    !Number.isSafeInteger(maxClockSkewMs)
    || maxClockSkewMs < 0
    || maxClockSkewMs > 300_000
  ) {
    throw new TypeError(
      'reference transparency maxClockSkewMs must be between 0 and 300000',
    )
  }

  return async function handleReferenceTransparencyLogRequest({
    method,
    headers,
    body,
    now = new Date(),
  } = {}) {
    if (method !== 'POST') {
      throw requestError('reference transparency request method must be POST')
    }
    const requestHeaders = normalizeHeaders(headers, {
      maxHeaderBytes,
      maxHeaderCount,
    })
    if (requestHeaders.get('content-type')?.trim().toLowerCase() !== JSON_MEDIA_TYPE) {
      throw requestError(
        'reference transparency request must use application/json',
      )
    }
    if (requestHeaders.has('content-encoding')) {
      throw requestError(
        'reference transparency request must not use a content encoding',
      )
    }
    if (requestHeaders.has('transfer-encoding')) {
      throw requestError(
        'reference transparency request must not use Transfer-Encoding',
      )
    }
    if (requestHeaders.get('x-rta-protocol') !== PROTOCOL) {
      throw requestError(
        'reference transparency request must declare transparency-log-v1',
      )
    }

    const declaredLength = parseContentLength(
      requestHeaders.get('content-length'),
    )
    if (declaredLength > maxRequestBytes) {
      throw requestError(
        'reference transparency request exceeded maxRequestBytes',
      )
    }
    const requestBody = bodyBytes(body)
    if (requestBody.length > maxRequestBytes) {
      throw requestError(
        'reference transparency request exceeded maxRequestBytes',
      )
    }
    if (declaredLength !== requestBody.length) {
      throw requestError(
        'reference transparency request was truncated or Content-Length did not match the exact body bytes',
      )
    }
    const expectedDigest = contentDigestHeader(requestBody)
    if (requestHeaders.get('content-digest') !== expectedDigest) {
      throw requestError(
        'reference transparency request Content-Digest does not match the exact body bytes',
      )
    }

    const requestDocument = parseCanonicalRequest(requestBody)
    const instant = normalizeInstant(now)
    const attestationBytes = Buffer.from(
      requestDocument.entry.content_base64,
      'base64',
    )
    const attestation = JSON.parse(UTF8.decode(attestationBytes))

    const published = await publish(requestDocument, instant)
    const candidate = published?.receipt ?? published
    const alreadyPublished = published?.created === false
      || published?.idempotent === true
    let receipt
    try {
      receipt = structuredClone(candidate)
    } catch (error) {
      throw contractError(
        `reference transparency store returned an invalid receipt value: ${error.message}`,
      )
    }
    assertValidTransparencyInclusionReceipt(receipt)
    verifyTransparencyInclusion({
      receipt,
      attestation,
      publicKeyBytes: publicIdentity.publicKey,
      expectedOrigin,
      now: instant,
      maxClockSkewMs,
    })

    const responseBody = Buffer.from(stableJson(receipt, 0), 'utf8')
    if (responseBody.length > maxResponseBytes) {
      throw contractError(
        'reference transparency response exceeded maxResponseBytes',
      )
    }
    return {
      statusCode: alreadyPublished ? 200 : 201,
      headers: {
        'content-type': JSON_MEDIA_TYPE,
        'content-length': String(responseBody.length),
        'content-digest': contentDigestHeader(responseBody),
        'cache-control': 'no-store',
        'x-rta-protocol': PROTOCOL,
      },
      body: responseBody,
    }
  }
}

/**
 * Creates the read-only RFC 6962/9162 checkpoint-consistency boundary. It is
 * deliberately separate from publication so malformed requests cannot append.
 */
export function createReferenceTransparencyConsistencyHandler({
  prove,
  store,
  origin,
  logPublicKeyBytes,
  maxClockSkewMs = 0,
  maxRequestBytes = DEFAULT_MAX_REQUEST_BYTES,
  maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
  maxHeaderBytes = DEFAULT_MAX_HEADER_BYTES,
  maxHeaderCount = DEFAULT_MAX_HEADER_COUNT,
} = {}) {
  const generateProof = resolveConsistencyProver({ prove, store })
  const expectedOrigin = trustedOrigin(origin ?? store?.origin)
  const publicIdentity = parseTransparencyPublicKey(
    logPublicKeyBytes ?? store?.publicKeyBytes,
  )
  if (store?.origin !== undefined && store.origin !== expectedOrigin) {
    throw contractError(
      'reference transparency store origin does not match the trusted origin',
    )
  }
  if (store?.keyId !== undefined && store.keyId !== publicIdentity.keyId) {
    throw contractError(
      'reference transparency store key does not match the trusted public key',
    )
  }
  requireBound(maxRequestBytes, 'maxRequestBytes')
  requireBound(maxResponseBytes, 'maxResponseBytes')
  requireBound(maxHeaderBytes, 'maxHeaderBytes', 64 * 1024)
  requireBound(maxHeaderCount, 'maxHeaderCount', 1024)
  if (
    !Number.isSafeInteger(maxClockSkewMs)
    || maxClockSkewMs < 0
    || maxClockSkewMs > 300_000
  ) {
    throw new TypeError(
      'reference transparency maxClockSkewMs must be between 0 and 300000',
    )
  }

  return async function handleReferenceTransparencyConsistencyRequest({
    method,
    headers,
    body,
    now = new Date(),
  } = {}) {
    if (method !== 'POST') {
      throw requestError(
        'reference transparency consistency request method must be POST',
      )
    }
    const requestHeaders = normalizeHeaders(headers, {
      maxHeaderBytes,
      maxHeaderCount,
    })
    if (requestHeaders.get('content-type')?.trim().toLowerCase() !== JSON_MEDIA_TYPE) {
      throw requestError(
        'reference transparency consistency request must use application/json',
      )
    }
    if (requestHeaders.has('content-encoding')) {
      throw requestError(
        'reference transparency consistency request must not use a content encoding',
      )
    }
    if (requestHeaders.has('transfer-encoding')) {
      throw requestError(
        'reference transparency consistency request must not use Transfer-Encoding',
      )
    }
    if (requestHeaders.get('x-rta-protocol') !== CONSISTENCY_PROTOCOL) {
      throw requestError(
        `reference transparency consistency request must declare ${CONSISTENCY_PROTOCOL}`,
      )
    }
    const declaredLength = parseContentLength(
      requestHeaders.get('content-length'),
    )
    if (declaredLength > maxRequestBytes) {
      throw requestError(
        'reference transparency consistency request exceeded maxRequestBytes',
      )
    }
    const requestBody = bodyBytes(body)
    if (requestBody.length > maxRequestBytes) {
      throw requestError(
        'reference transparency consistency request exceeded maxRequestBytes',
      )
    }
    if (declaredLength !== requestBody.length) {
      throw requestError(
        'reference transparency consistency request was truncated or Content-Length did not match the exact body bytes',
      )
    }
    if (requestHeaders.get('content-digest') !== contentDigestHeader(requestBody)) {
      throw requestError(
        'reference transparency consistency request Content-Digest does not match the exact body bytes',
      )
    }

    const requestDocument = parseCanonicalConsistencyRequest(requestBody)
    const instant = normalizeInstant(now)
    const candidate = await generateProof(requestDocument, instant)
    let proof
    try {
      proof = structuredClone(candidate?.proof ?? candidate)
    } catch (error) {
      throw contractError(
        `reference transparency store returned an invalid consistency proof value: ${error.message}`,
      )
    }
    assertValidTransparencyConsistencyProof(proof)
    if (
      proof.first_checkpoint.checkpoint.tree_size
        !== requestDocument.first_tree_size
      || proof.second_checkpoint.checkpoint.tree_size
        !== requestDocument.second_tree_size
    ) {
      throw contractError(
        'reference transparency consistency proof does not match the exact requested tree sizes',
      )
    }
    verifyTransparencyConsistencyProof({
      proof,
      publicKeyBytes: publicIdentity.publicKey,
      expectedOrigin,
      now: instant,
      maxClockSkewMs,
    })
    const responseBody = Buffer.from(stableJson(proof, 0), 'utf8')
    if (responseBody.length > maxResponseBytes) {
      throw contractError(
        'reference transparency consistency response exceeded maxResponseBytes',
      )
    }
    return {
      statusCode: 200,
      headers: {
        'content-type': JSON_MEDIA_TYPE,
        'content-length': String(responseBody.length),
        'content-digest': contentDigestHeader(responseBody),
        'cache-control': 'no-store',
        'x-rta-protocol': CONSISTENCY_PROTOCOL,
      },
      body: responseBody,
    }
  }
}
