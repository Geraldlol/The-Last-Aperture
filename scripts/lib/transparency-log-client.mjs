import { request as httpsRequest } from 'node:https'

import {
  assertContentDigestHeader,
  contentDigestHeader,
} from './remote-gateway-contracts.mjs'
import {
  assertPublicRemoteUrl,
  createPinnedServerIdentity,
  createRemoteGatewayLookup,
} from './remote-gateway-client.mjs'
import {
  TransparencyLogContractError,
  assertValidTransparencyConsistencyProof,
  assertValidTransparencyConsistencyRequest,
  assertValidTransparencyLogConfig,
  assertValidTransparencyPublishRequest,
  verifyTransparencyConsistencyProof,
  verifyTransparencyInclusion,
  verifyTransparencySignedCheckpoint,
} from './transparency-log-contracts.mjs'
import { stableJson } from './run-engine.mjs'

function exactResponseHeaders(rawHeaders) {
  const headers = Object.create(null)
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index].toLowerCase()
    const value = rawHeaders[index + 1]
    if (headers[name] === undefined) {
      headers[name] = value
    } else if (Array.isArray(headers[name])) {
      headers[name].push(value)
    } else {
      headers[name] = [headers[name], value]
    }
  }
  return headers
}

function headerValue(headers, name) {
  if (headers === null || typeof headers !== 'object' || Array.isArray(headers)) {
    throw new TransparencyLogContractError(
      'transparency log response headers are invalid',
    )
  }
  const matches = Object.entries(headers)
    .filter(([candidate]) => candidate.toLowerCase() === name.toLowerCase())
  if (matches.length > 1) {
    throw new TransparencyLogContractError(
      `transparency log response header ${name} is ambiguous`,
    )
  }
  const value = matches[0]?.[1]
  if (Array.isArray(value)) {
    throw new TransparencyLogContractError(
      `transparency log response header ${name} is ambiguous`,
    )
  }
  if (value !== undefined && typeof value !== 'string') {
    throw new TransparencyLogContractError(
      `transparency log response header ${name} is invalid`,
    )
  }
  return value
}

function exactContentLength(headers, bodyLength) {
  const value = headerValue(headers, 'content-length')
  if (value === undefined || !/^(?:0|[1-9][0-9]*)$/.test(value)) {
    throw new TransparencyLogContractError(
      'transparency log response requires one canonical Content-Length',
    )
  }
  const declared = Number(value)
  if (!Number.isSafeInteger(declared) || declared !== bodyLength) {
    throw new TransparencyLogContractError(
      'transparency log response was truncated or Content-Length did not match the exact body bytes',
    )
  }
}

export function httpsTransparencyLogTransport({
  config,
  endpointUrl,
  body,
  headers,
  lookup = createRemoteGatewayLookup(),
  ca,
}) {
  assertValidTransparencyLogConfig(config)
  const url = assertPublicRemoteUrl(
    endpointUrl ?? config.log_url,
    'transparency log',
  )
  return new Promise((resolve, reject) => {
    const request = httpsRequest(url, {
      method: 'POST',
      agent: false,
      headers,
      checkServerIdentity: createPinnedServerIdentity(
        config.tls_spki_sha256,
        'transparency log',
      ),
      lookup,
      ...(ca === undefined ? {} : { ca }),
      autoSelectFamily: false,
      timeout: config.limits.request_timeout_ms,
    })
    request.once('timeout', () => {
      const error = new Error('transparency log request timed out')
      error.code = 'TRANSPARENCY_LOG_TIMEOUT'
      request.destroy(error)
    })
    request.once('error', reject)
    request.once('response', (response) => {
      const chunks = []
      let total = 0
      response.on('data', (chunk) => {
        total += chunk.length
        if (total > config.limits.max_response_bytes) {
          const error = new Error(
            'transparency log response exceeded max_response_bytes',
          )
          error.code = 'TRANSPARENCY_LOG_RESPONSE_TOO_LARGE'
          response.destroy(error)
          return
        }
        chunks.push(Buffer.from(chunk))
      })
      response.once('error', reject)
      response.once('aborted', () => {
        const error = new Error('transparency log response was truncated')
        error.code = 'TRANSPARENCY_LOG_RESPONSE_TRUNCATED'
        reject(error)
      })
      response.once('end', () => {
        if (!response.complete) {
          const error = new Error('transparency log response was truncated')
          error.code = 'TRANSPARENCY_LOG_RESPONSE_TRUNCATED'
          reject(error)
          return
        }
        resolve({
          statusCode: response.statusCode,
          headers: exactResponseHeaders(response.rawHeaders),
          body: Buffer.concat(chunks),
        })
      })
    })
    request.end(body)
  })
}

export async function submitTransparencyLogEntry({
  config,
  requestDocument,
  attestation,
  logPublicKeyBytes,
  transport = httpsTransparencyLogTransport,
  now = new Date(),
}) {
  assertValidTransparencyLogConfig(config)
  assertValidTransparencyPublishRequest(requestDocument)
  const requestBody = Buffer.from(stableJson(requestDocument, 0), 'utf8')
  if (requestBody.length > config.limits.max_request_bytes) {
    throw new TransparencyLogContractError(
      'transparency publication request exceeded max_request_bytes',
    )
  }
  const response = await transport({
    config,
    body: requestBody,
    headers: {
      accept: 'application/json',
      'content-type': 'application/json',
      'content-length': String(requestBody.length),
      'content-digest': contentDigestHeader(requestBody),
      'x-rta-protocol': 'transparency-log-v1',
    },
  })
  if (![200, 201].includes(response?.statusCode)) {
    throw new TransparencyLogContractError(
      `transparency log returned HTTP ${String(response?.statusCode)}`,
    )
  }
  const responseBody = Buffer.from(response.body ?? [])
  if (responseBody.length > config.limits.max_response_bytes) {
    throw new TransparencyLogContractError(
      'transparency log response exceeded max_response_bytes',
    )
  }
  exactContentLength(response.headers, responseBody.length)
  if (headerValue(response.headers, 'transfer-encoding') !== undefined) {
    throw new TransparencyLogContractError(
      'transparency log response must not use Transfer-Encoding',
    )
  }
  const contentType = String(headerValue(response.headers, 'content-type') ?? '')
    .split(';', 1)[0]
    .trim()
    .toLowerCase()
  if (contentType !== 'application/json') {
    throw new TransparencyLogContractError(
      'transparency log response must use application/json',
    )
  }
  if (headerValue(response.headers, 'content-encoding') !== undefined) {
    throw new TransparencyLogContractError(
      'transparency log response must not use a transforming content encoding',
    )
  }
  if (headerValue(response.headers, 'x-rta-protocol') !== 'transparency-log-v1') {
    throw new TransparencyLogContractError(
      'transparency log response must declare transparency-log-v1',
    )
  }
  assertContentDigestHeader(
    headerValue(response.headers, 'content-digest'),
    responseBody,
    'transparency log response',
  )
  let receipt
  try {
    receipt = JSON.parse(responseBody.toString('utf8'))
  } catch (error) {
    throw new TransparencyLogContractError(
      `transparency log response is not valid JSON: ${error.message}`,
    )
  }
  const canonicalResponse = Buffer.from(stableJson(receipt, 0), 'utf8')
  if (!canonicalResponse.equals(responseBody)) {
    throw new TransparencyLogContractError(
      'transparency log response must use canonical JSON bytes',
    )
  }
  return {
    receipt,
    verification: verifyTransparencyInclusion({
      receipt,
      attestation,
      publicKeyBytes: logPublicKeyBytes,
      expectedOrigin: config.log_origin,
      now,
      maxClockSkewMs: config.limits.max_clock_skew_ms,
    }),
  }
}

function assertCheckpointIdentityMatches(actual, expected, label) {
  if (expected === undefined) return
  const actualCheckpoint = actual?.checkpoint
  const expectedCheckpoint = expected?.checkpoint
  if (
    actualCheckpoint?.tree_size !== expectedCheckpoint?.tree_size
    || actualCheckpoint?.root_hash !== expectedCheckpoint?.root_hash
    || actualCheckpoint?.origin !== expectedCheckpoint?.origin
    || actualCheckpoint?.signing?.key_id
      !== expectedCheckpoint?.signing?.key_id
  ) {
    throw new TransparencyLogContractError(
      `transparency consistency ${label} does not match the externally supplied signed checkpoint`,
    )
  }
}

export async function submitTransparencyConsistencyRequest({
  config,
  requestDocument,
  logPublicKeyBytes,
  expectedFirstCheckpoint,
  expectedSecondCheckpoint,
  transport = httpsTransparencyLogTransport,
  now = new Date(),
}) {
  assertValidTransparencyLogConfig(config)
  assertValidTransparencyConsistencyRequest(requestDocument)
  if (typeof config.consistency_url !== 'string') {
    throw new TransparencyLogContractError(
      'transparency consistency retrieval requires config consistency_url',
    )
  }
  const requestBody = Buffer.from(stableJson(requestDocument, 0), 'utf8')
  if (requestBody.length > config.limits.max_request_bytes) {
    throw new TransparencyLogContractError(
      'transparency consistency request exceeded max_request_bytes',
    )
  }
  const response = await transport({
    config,
    endpointUrl: config.consistency_url,
    body: requestBody,
    headers: {
      accept: 'application/json',
      'content-type': 'application/json',
      'content-length': String(requestBody.length),
      'content-digest': contentDigestHeader(requestBody),
      'x-rta-protocol': 'transparency-log-consistency-v1',
    },
  })
  if (response?.statusCode !== 200) {
    throw new TransparencyLogContractError(
      `transparency consistency endpoint returned HTTP ${String(response?.statusCode)}`,
    )
  }
  const responseBody = Buffer.from(response.body ?? [])
  if (responseBody.length > config.limits.max_response_bytes) {
    throw new TransparencyLogContractError(
      'transparency consistency response exceeded max_response_bytes',
    )
  }
  exactContentLength(response.headers, responseBody.length)
  if (headerValue(response.headers, 'transfer-encoding') !== undefined) {
    throw new TransparencyLogContractError(
      'transparency consistency response must not use Transfer-Encoding',
    )
  }
  const contentType = String(headerValue(response.headers, 'content-type') ?? '')
    .split(';', 1)[0]
    .trim()
    .toLowerCase()
  if (contentType !== 'application/json') {
    throw new TransparencyLogContractError(
      'transparency consistency response must use application/json',
    )
  }
  if (headerValue(response.headers, 'content-encoding') !== undefined) {
    throw new TransparencyLogContractError(
      'transparency consistency response must not use a transforming content encoding',
    )
  }
  if (
    headerValue(response.headers, 'x-rta-protocol')
      !== 'transparency-log-consistency-v1'
  ) {
    throw new TransparencyLogContractError(
      'transparency consistency response must declare transparency-log-consistency-v1',
    )
  }
  assertContentDigestHeader(
    headerValue(response.headers, 'content-digest'),
    responseBody,
    'transparency consistency response',
  )
  let proof
  try {
    proof = JSON.parse(responseBody.toString('utf8'))
  } catch (error) {
    throw new TransparencyLogContractError(
      `transparency consistency response is not valid JSON: ${error.message}`,
    )
  }
  const canonicalResponse = Buffer.from(stableJson(proof, 0), 'utf8')
  if (!canonicalResponse.equals(responseBody)) {
    throw new TransparencyLogContractError(
      'transparency consistency response must use canonical JSON bytes',
    )
  }
  assertValidTransparencyConsistencyProof(proof)
  const first = proof.first_checkpoint
  const second = proof.second_checkpoint
  if (
    first.checkpoint.tree_size !== requestDocument.first_tree_size
    || second.checkpoint.tree_size !== requestDocument.second_tree_size
  ) {
    throw new TransparencyLogContractError(
      'transparency consistency response does not match the exact requested tree sizes',
    )
  }
  for (const checkpoint of [expectedFirstCheckpoint, expectedSecondCheckpoint]) {
    if (checkpoint !== undefined) {
      verifyTransparencySignedCheckpoint({
        signedCheckpoint: checkpoint,
        publicKeyBytes: logPublicKeyBytes,
        expectedOrigin: config.log_origin,
        now,
        maxClockSkewMs: config.limits.max_clock_skew_ms,
      })
    }
  }
  assertCheckpointIdentityMatches(
    first,
    expectedFirstCheckpoint,
    'first checkpoint',
  )
  assertCheckpointIdentityMatches(
    second,
    expectedSecondCheckpoint,
    'second checkpoint',
  )
  return {
    proof,
    verification: verifyTransparencyConsistencyProof({
      proof,
      publicKeyBytes: logPublicKeyBytes,
      expectedOrigin: config.log_origin,
      now,
      maxClockSkewMs: config.limits.max_clock_skew_ms,
    }),
  }
}
