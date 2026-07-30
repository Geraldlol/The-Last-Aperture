import { createHash, X509Certificate } from 'node:crypto'
import { request as httpsRequest } from 'node:https'
import { checkServerIdentity } from 'node:tls'

import {
  RemoteGatewayContractError,
  assertContentDigestHeader,
  assertValidRemoteGatewayConfig,
  assertValidRemoteRequestEnvelope,
  contentDigestHeader,
  verifyRemoteAcceptanceEnvelope,
} from './remote-gateway-contracts.mjs'
import { stableJson } from './run-engine.mjs'

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function headerValue(headers, name) {
  const value = headers?.[name] ?? headers?.[name.toLowerCase()]
  return Array.isArray(value) ? value[0] : value
}

function pinnedServerIdentity(expectedSpkiSha256) {
  return (hostname, certificate) => {
    const hostnameError = checkServerIdentity(hostname, certificate)
    if (hostnameError) return hostnameError
    try {
      const x509 = new X509Certificate(certificate.raw)
      const spki = x509.publicKey.export({ type: 'spki', format: 'der' })
      const actual = sha256(spki)
      if (actual !== expectedSpkiSha256) {
        const error = new Error(
          'remote gateway TLS certificate SPKI does not match the trusted pin',
        )
        error.code = 'REMOTE_GATEWAY_TLS_PIN_MISMATCH'
        return error
      }
      return undefined
    } catch (error) {
      const wrapped = new Error(
        `remote gateway TLS certificate could not be pinned: ${error.message}`,
      )
      wrapped.code = 'REMOTE_GATEWAY_TLS_PIN_INVALID'
      return wrapped
    }
  }
}

export function httpsRemoteGatewayTransport({
  config,
  body,
  headers,
}) {
  assertValidRemoteGatewayConfig(config)
  const url = new URL(config.gateway_url)
  return new Promise((resolve, reject) => {
    const request = httpsRequest(url, {
      method: 'POST',
      agent: false,
      headers,
      checkServerIdentity: pinnedServerIdentity(config.tls_spki_sha256),
      timeout: config.limits.request_timeout_ms,
    })
    request.once('timeout', () => {
      const error = new Error('remote gateway request timed out')
      error.code = 'REMOTE_GATEWAY_TIMEOUT'
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
            'remote gateway response exceeded max_response_bytes',
          )
          error.code = 'REMOTE_GATEWAY_RESPONSE_TOO_LARGE'
          response.destroy(error)
          return
        }
        chunks.push(Buffer.from(chunk))
      })
      response.once('error', reject)
      response.once('end', () => {
        resolve({
          statusCode: response.statusCode,
          headers: response.headers,
          body: Buffer.concat(chunks),
        })
      })
    })
    request.end(body)
  })
}

export async function submitRemoteGatewayRequest({
  config,
  requestEnvelope,
  gatewayPublicKeyBytes,
  transport = httpsRemoteGatewayTransport,
  now = new Date(),
}) {
  assertValidRemoteGatewayConfig(config)
  assertValidRemoteRequestEnvelope(requestEnvelope)
  if (
    stableJson(requestEnvelope.controller.prompt_transform, 0)
    !== stableJson(config.prompt_transform, 0)
  ) {
    throw new RemoteGatewayContractError(
      'remote gateway request prompt transform differs from the trusted configuration',
    )
  }
  const requestLifetime = (
    Date.parse(requestEnvelope.controller.expires_at)
    - Date.parse(requestEnvelope.controller.created_at)
  )
  if (requestLifetime > config.limits.request_ttl_ms) {
    throw new RemoteGatewayContractError(
      'remote gateway request lifetime exceeds request_ttl_ms',
    )
  }
  if (requestEnvelope.artifacts.length > config.limits.max_artifacts) {
    throw new RemoteGatewayContractError(
      'remote gateway request exceeded max_artifacts',
    )
  }
  let totalArtifactBytes = 0
  for (const artifact of requestEnvelope.artifacts) {
    if (artifact.size > config.limits.max_file_bytes) {
      throw new RemoteGatewayContractError(
        `remote gateway artifact ${artifact.logical_name} exceeded max_file_bytes`,
      )
    }
    totalArtifactBytes += artifact.size
  }
  if (totalArtifactBytes > config.limits.max_total_artifact_bytes) {
    throw new RemoteGatewayContractError(
      'remote gateway request exceeded max_total_artifact_bytes',
    )
  }
  const requestBody = Buffer.from(stableJson(requestEnvelope, 0), 'utf8')
  if (requestBody.length > config.limits.max_request_bytes) {
    throw new RemoteGatewayContractError(
      'remote gateway request exceeded max_request_bytes',
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
      'x-rta-protocol': 'remote-gateway-v1',
    },
  })
  if (response?.statusCode !== 200) {
    throw new RemoteGatewayContractError(
      `remote gateway returned HTTP ${String(response?.statusCode)}`,
    )
  }
  const responseBody = Buffer.from(response.body ?? [])
  if (responseBody.length > config.limits.max_response_bytes) {
    throw new RemoteGatewayContractError(
      'remote gateway response exceeded max_response_bytes',
    )
  }
  const contentType = String(headerValue(response.headers, 'content-type') ?? '')
    .split(';', 1)[0]
    .trim()
    .toLowerCase()
  if (contentType !== 'application/json') {
    throw new RemoteGatewayContractError(
      'remote gateway response must use application/json',
    )
  }
  if (headerValue(response.headers, 'content-encoding') !== undefined) {
    throw new RemoteGatewayContractError(
      'remote gateway response must not use a transforming content encoding',
    )
  }
  if (headerValue(response.headers, 'x-rta-protocol') !== 'remote-gateway-v1') {
    throw new RemoteGatewayContractError(
      'remote gateway response must declare remote-gateway-v1',
    )
  }
  assertContentDigestHeader(
    headerValue(response.headers, 'content-digest'),
    responseBody,
    'remote gateway response',
  )
  let envelope
  try {
    envelope = JSON.parse(responseBody.toString('utf8'))
  } catch (error) {
    throw new RemoteGatewayContractError(
      `remote gateway response is not valid JSON: ${error.message}`,
    )
  }
  const canonicalResponse = Buffer.from(stableJson(envelope, 0), 'utf8')
  if (!canonicalResponse.equals(responseBody)) {
    throw new RemoteGatewayContractError(
      'remote gateway response must use canonical JSON bytes',
    )
  }
  return verifyRemoteAcceptanceEnvelope({
    envelope,
    requestEnvelope,
    requestBytes: requestBody,
    gatewayPublicKeyBytes,
    expectedPromptTransform: config.prompt_transform,
    now,
    maxClockSkewMs: config.limits.max_clock_skew_ms,
  })
}
