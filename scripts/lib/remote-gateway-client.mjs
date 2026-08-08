import { createHash, X509Certificate } from 'node:crypto'
import { lookup as dnsLookup } from 'node:dns'
import { request as httpsRequest } from 'node:https'
import { BlockList, isIP } from 'node:net'
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

const NON_PUBLIC_REMOTE_IPV4_ADDRESSES = new BlockList()
for (const [address, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
]) {
  NON_PUBLIC_REMOTE_IPV4_ADDRESSES.addSubnet(address, prefix, 'ipv4')
}
const NON_PUBLIC_REMOTE_IPV6_ADDRESSES = new BlockList()
for (const [address, prefix] of [
  ['::', 128],
  ['::1', 128],
  ['::ffff:0:0', 96],
  ['64:ff9b::', 96],
  ['64:ff9b:1::', 48],
  ['100::', 64],
  ['2001::', 23],
  ['2001:db8::', 32],
  ['2002::', 16],
  ['3fff::', 20],
  ['5f00::', 16],
  ['fc00::', 7],
  ['fe80::', 10],
  ['fec0::', 10],
  ['ff00::', 8],
]) {
  NON_PUBLIC_REMOTE_IPV6_ADDRESSES.addSubnet(address, prefix, 'ipv6')
}

export function isPublicRemoteAddress(address) {
  const family = isIP(address)
  if (family === 0) return false
  return family === 4
    ? !NON_PUBLIC_REMOTE_IPV4_ADDRESSES.check(address, 'ipv4')
    : !NON_PUBLIC_REMOTE_IPV6_ADDRESSES.check(address, 'ipv6')
}

export function assertPublicRemoteUrl(urlValue, label = 'remote gateway') {
  const url = urlValue instanceof URL ? urlValue : new URL(urlValue)
  const hostname = url.hostname.startsWith('[') && url.hostname.endsWith(']')
    ? url.hostname.slice(1, -1)
    : url.hostname
  if (isIP(hostname) !== 0 && !isPublicRemoteAddress(hostname)) {
    const error = new Error(
      `${label} URL uses a non-public literal IP address`,
    )
    error.code = 'REMOTE_GATEWAY_LITERAL_IP_SCOPE_DENIED'
    throw error
  }
  return url
}

export function createRemoteGatewayLookup(lookup = dnsLookup) {
  if (typeof lookup !== 'function') {
    throw new TypeError('remote gateway DNS lookup must be a function')
  }
  return (hostname, options, callback) => {
    const requestedFamily = typeof options === 'number'
      ? options
      : (options?.family ?? 0)
    let settled = false
    const finish = (...values) => {
      if (settled) return
      settled = true
      callback(...values)
    }
    try {
      lookup(hostname, { all: true, verbatim: true }, (error, addresses) => {
        if (error) {
          finish(error)
          return
        }
        const candidates = Array.isArray(addresses)
          ? addresses.filter(({ address, family }) =>
              (requestedFamily === 0 || requestedFamily === family)
              && family === isIP(address)
              && isPublicRemoteAddress(address))
          : []
        if (candidates.length === 0) {
          const scopeError = new Error(
            `remote gateway DNS for ${hostname} returned no permitted public address`,
          )
          scopeError.code = 'REMOTE_GATEWAY_DNS_SCOPE_DENIED'
          finish(scopeError)
          return
        }
        finish(null, candidates[0].address, candidates[0].family)
      })
    } catch (error) {
      finish(error)
    }
  }
}

export function createPinnedServerIdentity(
  expectedSpkiSha256,
  peerLabel = 'remote gateway',
) {
  return (hostname, certificate) => {
    const hostnameError = checkServerIdentity(hostname, certificate)
    if (hostnameError) return hostnameError
    try {
      const x509 = new X509Certificate(certificate.raw)
      const spki = x509.publicKey.export({ type: 'spki', format: 'der' })
      const actual = sha256(spki)
      if (actual !== expectedSpkiSha256) {
        const error = new Error(
          `${peerLabel} TLS certificate SPKI does not match the trusted pin`,
        )
        error.code = 'REMOTE_GATEWAY_TLS_PIN_MISMATCH'
        return error
      }
      return undefined
    } catch (error) {
      const wrapped = new Error(
        `${peerLabel} TLS certificate could not be pinned: ${error.message}`,
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
  const url = assertPublicRemoteUrl(config.gateway_url)
  return new Promise((resolve, reject) => {
    const request = httpsRequest(url, {
      method: 'POST',
      agent: false,
      headers,
      checkServerIdentity: createPinnedServerIdentity(config.tls_spki_sha256),
      lookup: createRemoteGatewayLookup(),
      autoSelectFamily: false,
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
