import {
  RemoteGatewayContractError,
  assertContentDigestHeader,
  contentDigestHeader,
  createRemoteAcceptanceEnvelope,
  verifyRemoteRequestEnvelope,
} from '../../scripts/lib/remote-gateway-contracts.mjs'
import { stableJson } from '../../scripts/lib/run-engine.mjs'

function headerValue(headers, name) {
  const value = headers?.[name] ?? headers?.[name.toLowerCase()]
  return Array.isArray(value) ? value[0] : value
}

export function createReferenceRemoteGateway({
  controllerPublicKeyBytes,
  gatewayPrivateKeyBytes,
  promptTransform,
  provider,
  replayStore = new Set(),
  maxClockSkewMs = 0,
  maxRequestTtlMs = 300000,
  maxRequestBytes = 67108864,
  maxArtifacts = 65536,
  maxFileBytes = 67108864,
  maxTotalArtifactBytes = 67108864,
}) {
  if (typeof provider !== 'function') {
    throw new TypeError('reference remote gateway requires a provider function')
  }
  if (
    !replayStore
    || typeof replayStore.has !== 'function'
    || typeof replayStore.add !== 'function'
  ) {
    throw new TypeError('reference remote gateway requires a Set-compatible replay store')
  }

  return async function handleRemoteGatewayRequest({
    headers,
    body,
    now = new Date(),
  }) {
    const contentType = String(headerValue(headers, 'content-type') ?? '')
      .split(';', 1)[0]
      .trim()
      .toLowerCase()
    if (contentType !== 'application/json') {
      throw new RemoteGatewayContractError(
        'remote gateway request must use application/json',
      )
    }
    if (headerValue(headers, 'content-encoding') !== undefined) {
      throw new RemoteGatewayContractError(
        'remote gateway request must not use a transforming content encoding',
      )
    }
    if (headerValue(headers, 'x-rta-protocol') !== 'remote-gateway-v1') {
      throw new RemoteGatewayContractError(
        'remote gateway request must declare remote-gateway-v1',
      )
    }
    const requestBytes = Buffer.from(body ?? [])
    if (requestBytes.length > maxRequestBytes) {
      throw new RemoteGatewayContractError(
        'remote gateway request exceeded the configured byte limit',
      )
    }
    assertContentDigestHeader(
      headerValue(headers, 'content-digest'),
      requestBytes,
      'remote gateway request',
    )
    let requestEnvelope
    try {
      requestEnvelope = JSON.parse(requestBytes.toString('utf8'))
    } catch (error) {
      throw new RemoteGatewayContractError(
        `remote gateway request is not valid JSON: ${error.message}`,
      )
    }
    const canonicalRequest = Buffer.from(
      stableJson(requestEnvelope, 0),
      'utf8',
    )
    if (!canonicalRequest.equals(requestBytes)) {
      throw new RemoteGatewayContractError(
        'remote gateway request must use canonical JSON bytes',
      )
    }
    const verified = verifyRemoteRequestEnvelope({
      envelope: requestEnvelope,
      publicKeyBytes: controllerPublicKeyBytes,
      expectedPromptTransform: promptTransform,
      now,
      maxClockSkewMs,
      maxRequestTtlMs,
    })
    if (requestEnvelope.artifacts.length > maxArtifacts) {
      throw new RemoteGatewayContractError(
        'remote gateway request exceeded the configured artifact count',
      )
    }
    let totalArtifactBytes = 0
    for (const artifact of requestEnvelope.artifacts) {
      if (artifact.size > maxFileBytes) {
        throw new RemoteGatewayContractError(
          `remote gateway artifact ${artifact.logical_name} exceeded the configured file limit`,
        )
      }
      totalArtifactBytes += artifact.size
    }
    if (totalArtifactBytes > maxTotalArtifactBytes) {
      throw new RemoteGatewayContractError(
        'remote gateway request exceeded the configured total artifact byte limit',
      )
    }
    if (replayStore.has(verified.request_id)) {
      throw new RemoteGatewayContractError(
        `remote gateway request ${verified.request_id} was already accepted`,
      )
    }
    replayStore.add(verified.request_id)

    let providerOutput
    providerOutput = await provider({
      request: requestEnvelope,
      packet: structuredClone(requestEnvelope.job_packet),
      artifacts: verified.decoded_artifacts,
    })
    if (
      providerOutput === null
      || typeof providerOutput !== 'object'
      || providerOutput.jobResult === undefined
      || providerOutput.upstreamRequestBytes === undefined
    ) {
      throw new RemoteGatewayContractError(
        'remote gateway provider must return jobResult and upstreamRequestBytes',
      )
    }
    const acceptance = createRemoteAcceptanceEnvelope({
      requestEnvelope,
      requestBytes,
      jobResult: providerOutput.jobResult,
      upstreamRequestBytes: providerOutput.upstreamRequestBytes,
      gatewayPrivateKeyBytes,
      acceptedAt: now,
    })
    const responseBody = Buffer.from(stableJson(acceptance, 0), 'utf8')
    return {
      statusCode: 200,
      headers: {
        'content-type': 'application/json',
        'content-length': String(responseBody.length),
        'content-digest': contentDigestHeader(responseBody),
        'x-rta-protocol': 'remote-gateway-v1',
      },
      body: responseBody,
    }
  }
}
