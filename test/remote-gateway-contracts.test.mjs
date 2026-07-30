import { createHash, generateKeyPairSync } from 'node:crypto'
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { createReferenceRemoteGateway } from '../providers/reference-remote-gateway/gateway.mjs'
import {
  RemoteGatewayContractError,
  assertContentDigestHeader,
  contentDigestHeader,
  createRemoteRequestEnvelope,
  validateRemoteGatewayConfig,
  validateRemoteRequestEnvelope,
  verifyRemoteRequestEnvelope,
} from '../scripts/lib/remote-gateway-contracts.mjs'
import { submitRemoteGatewayRequest } from '../scripts/lib/remote-gateway-client.mjs'
import { stableJson } from '../scripts/lib/run-engine.mjs'

const SHA_A = 'a'.repeat(64)
const SHA_B = 'b'.repeat(64)
const SHA_C = 'c'.repeat(64)
const SHA_D = 'd'.repeat(64)
const SHA_E = 'e'.repeat(64)
const SHA_F = 'f'.repeat(64)
const NOW = new Date('2026-07-30T12:00:00.000Z')
const TRANSFORM = Object.freeze({
  id: 'red-team-audit/reference-prompt/v1',
  sha256: SHA_F,
})

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function keyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  return {
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }),
  }
}

function packet() {
  const unsigned = {
    schema_version: '2.0.0',
    run_id: 'run:remote-fixture',
    job_id: 'lens:web-and-api',
    kind: 'LENS',
    capability_mode: 'STATIC',
    scoped_files: ['src/app.mjs'],
  }
  return {
    ...unsigned,
    packet_sha256: sha256(stableJson(unsigned, 0)),
  }
}

function provenance(boundPacket = packet()) {
  return {
    run_id: boundPacket.run_id,
    job_id: boundPacket.job_id,
    plan_sha256: SHA_A,
    repository_tree_sha256: SHA_B,
    lens_pack_sha256: SHA_C,
    policy_sha256: SHA_D,
    source_snapshot_sha256: SHA_E,
    control_snapshot_sha256: SHA_F,
  }
}

function artifact() {
  const bytes = Buffer.from('export const reviewed = true\n', 'utf8')
  return {
    artifact_id: 'file_0123456789abcdef',
    kind: 'FILE',
    logical_name: 'src/app.mjs',
    bytes,
  }
}

function config() {
  return {
    schema_version: '1.0.0',
    protocol: 'remote-gateway-v1',
    gateway_url: 'https://gateway.example.test/v1/audit',
    controller_signing_private_key_path: 'C:\\trusted\\controller-private.pem',
    gateway_public_key_path: 'C:\\trusted\\gateway-public.pem',
    tls_spki_sha256: SHA_A,
    prompt_transform: TRANSFORM,
    limits: {
      request_timeout_ms: 10_000,
      request_ttl_ms: 30_000,
      max_clock_skew_ms: 1_000,
      max_request_bytes: 131_072,
      max_response_bytes: 65_536,
      max_artifacts: 16,
      max_file_bytes: 4096,
      max_total_artifact_bytes: 4096,
    },
  }
}

function jobResult(boundPacket = packet()) {
  return {
    schema_version: '1.0.0',
    run_id: boundPacket.run_id,
    job_id: boundPacket.job_id,
    input_sha256: boundPacket.packet_sha256,
    producer: {
      name: 'reference-remote-gateway',
      version: '1.0.0',
      instance_id: 'reference-remote-gateway:test',
    },
    state: 'SUCCEEDED',
    examined_files: ['src/app.mjs'],
    findings: [],
    coverage_gaps: [],
  }
}

function requestFixture(controller, boundPacket = packet()) {
  return createRemoteRequestEnvelope({
    provenance: provenance(boundPacket),
    packet: boundPacket,
    artifacts: [artifact()],
    promptTransform: TRANSFORM,
    privateKeyBytes: controller.privatePem,
    attemptId: 'attempt:remote-fixture',
    requestId: 'remote:request-fixture',
    nonce: '1'.repeat(64),
    createdAt: NOW,
    ttlMs: 30_000,
  })
}

test('remote gateway configuration requires one exact HTTPS endpoint and bounded payloads', () => {
  assert.equal(validateRemoteGatewayConfig(config()).valid, true)

  const http = structuredClone(config())
  http.gateway_url = 'http://gateway.example.test/v1/audit'
  assert.equal(validateRemoteGatewayConfig(http).valid, false)

  const query = structuredClone(config())
  query.gateway_url = 'https://gateway.example.test/v1/audit?route=other'
  assert.equal(validateRemoteGatewayConfig(query).valid, false)

  const malformed = structuredClone(config())
  malformed.gateway_url = 'https://%%%%invalid'
  assert.equal(validateRemoteGatewayConfig(malformed).valid, false)

  const impossible = structuredClone(config())
  impossible.limits.max_total_artifact_bytes = 100_000
  impossible.limits.max_file_bytes = 100_000
  assert.equal(validateRemoteGatewayConfig(impossible).valid, false)
})

test('remote request signing binds the packet, exact artifacts, transform, and time window', () => {
  const controller = keyPair()
  const envelope = requestFixture(controller)
  const verified = verifyRemoteRequestEnvelope({
    envelope,
    publicKeyBytes: controller.publicPem,
    expectedPromptTransform: TRANSFORM,
    now: new Date(NOW.getTime() + 1_000),
    maxRequestTtlMs: 30_000,
  })

  assert.equal(verified.request_id, 'remote:request-fixture')
  assert.deepEqual(
    verified.decoded_artifacts.map(({ logical_name: name, bytes }) => [
      name,
      bytes.toString('utf8'),
    ]),
    [['src/app.mjs', 'export const reviewed = true\n']],
  )

  const tampered = structuredClone(envelope)
  tampered.artifacts[0].content_base64 = Buffer.from('different').toString('base64')
  const validation = validateRemoteRequestEnvelope(tampered)
  assert.equal(validation.valid, false)
  assert.ok(validation.errors.some(({ code }) =>
    code === 'REMOTE_REQUEST_ARTIFACT_SIZE_MISMATCH'
    || code === 'REMOTE_REQUEST_ARTIFACT_DIGEST_MISMATCH'))

  assert.throws(
    () => verifyRemoteRequestEnvelope({
      envelope,
      publicKeyBytes: controller.publicPem,
      expectedPromptTransform: TRANSFORM,
      now: new Date(NOW.getTime() + 31_001),
      maxRequestTtlMs: 30_000,
    }),
    /not valid at the current time/,
  )

  const attacker = keyPair()
  assert.throws(
    () => verifyRemoteRequestEnvelope({
      envelope,
      publicKeyBytes: attacker.publicPem,
      expectedPromptTransform: TRANSFORM,
      now: NOW,
      maxRequestTtlMs: 30_000,
    }),
    /does not match the externally trusted controller key/,
  )

  const wrongRun = structuredClone(envelope)
  wrongRun.controller.run_id = 'run:other'
  assert.equal(validateRemoteRequestEnvelope(wrongRun).valid, false)

  const dotSegment = structuredClone(envelope)
  dotSegment.artifacts[0].logical_name = 'src/./app.mjs'
  assert.equal(validateRemoteRequestEnvelope(dotSegment).valid, false)

  const missingFile = structuredClone(envelope)
  missingFile.artifacts = []
  assert.equal(validateRemoteRequestEnvelope(missingFile).valid, false)

  const nonCanonicalTime = structuredClone(envelope)
  nonCanonicalTime.controller.created_at = '2026-07-30T12:00:00Z'
  assert.equal(validateRemoteRequestEnvelope(nonCanonicalTime).valid, false)
})

test('reference gateway and client complete one packet-bound acceptance end to end', async () => {
  const controller = keyPair()
  const gateway = keyPair()
  const boundPacket = packet()
  const requestEnvelope = requestFixture(controller, boundPacket)
  let providerCalls = 0
  const handler = createReferenceRemoteGateway({
    controllerPublicKeyBytes: controller.publicPem,
    gatewayPrivateKeyBytes: gateway.privatePem,
    promptTransform: TRANSFORM,
    maxClockSkewMs: 1_000,
    maxRequestTtlMs: 30_000,
    provider: async ({ packet: receivedPacket, artifacts }) => {
      providerCalls += 1
      assert.equal(receivedPacket.packet_sha256, boundPacket.packet_sha256)
      assert.equal(artifacts[0].bytes.toString('utf8'), 'export const reviewed = true\n')
      const upstreamRequestBytes = Buffer.from(stableJson({
        transform: TRANSFORM,
        packet_sha256: receivedPacket.packet_sha256,
        artifact_sha256: artifacts[0].sha256,
      }, 0), 'utf8')
      return {
        jobResult: jobResult(boundPacket),
        upstreamRequestBytes,
      }
    },
  })

  const accepted = await submitRemoteGatewayRequest({
    config: config(),
    requestEnvelope,
    gatewayPublicKeyBytes: gateway.publicPem,
    now: new Date(NOW.getTime() + 1_000),
    transport: ({ body, headers }) => handler({
      body,
      headers,
      now: new Date(NOW.getTime() + 500),
    }),
  })

  assert.equal(accepted.authority, 'REMOTE_REQUEST_ACCEPTED')
  assert.equal(accepted.job_result.state, 'SUCCEEDED')
  assert.equal(accepted.job_result.input_sha256, boundPacket.packet_sha256)
  assert.equal(providerCalls, 1)
})

test('reference gateway rejects replay before invoking the provider twice', async () => {
  const controller = keyPair()
  const gateway = keyPair()
  const requestEnvelope = requestFixture(controller)
  let providerCalls = 0
  const handler = createReferenceRemoteGateway({
    controllerPublicKeyBytes: controller.publicPem,
    gatewayPrivateKeyBytes: gateway.privatePem,
    promptTransform: TRANSFORM,
    provider: async () => {
      providerCalls += 1
      return {
        jobResult: jobResult(),
        upstreamRequestBytes: Buffer.from('upstream'),
      }
    },
  })
  const body = Buffer.from(stableJson(requestEnvelope, 0), 'utf8')
  const headers = {
    'content-type': 'application/json',
    'content-digest': contentDigestHeader(body),
    'x-rta-protocol': 'remote-gateway-v1',
  }

  await handler({ headers, body, now: NOW })
  await assert.rejects(
    () => handler({ headers, body, now: NOW }),
    /was already accepted/,
  )
  assert.equal(providerCalls, 1)
})

test('reference gateway rejects transformed or protocol-ambiguous requests', async () => {
  const controller = keyPair()
  const gateway = keyPair()
  const requestEnvelope = requestFixture(controller)
  const handler = createReferenceRemoteGateway({
    controllerPublicKeyBytes: controller.publicPem,
    gatewayPrivateKeyBytes: gateway.privatePem,
    promptTransform: TRANSFORM,
    provider: async () => ({
      jobResult: jobResult(),
      upstreamRequestBytes: Buffer.from('upstream'),
    }),
  })
  const body = Buffer.from(stableJson(requestEnvelope, 0), 'utf8')
  const baseHeaders = {
    'content-type': 'application/json',
    'content-digest': contentDigestHeader(body),
  }

  await assert.rejects(
    () => handler({
      headers: {
        ...baseHeaders,
        'content-encoding': 'gzip',
        'x-rta-protocol': 'remote-gateway-v1',
      },
      body,
      now: NOW,
    }),
    /must not use a transforming content encoding/,
  )
  await assert.rejects(
    () => handler({ headers: baseHeaders, body, now: NOW }),
    /must declare remote-gateway-v1/,
  )
})

test('gateway consumes the replay identifier even when the provider fails', async () => {
  const controller = keyPair()
  const gateway = keyPair()
  const requestEnvelope = requestFixture(controller)
  let providerCalls = 0
  const handler = createReferenceRemoteGateway({
    controllerPublicKeyBytes: controller.publicPem,
    gatewayPrivateKeyBytes: gateway.privatePem,
    promptTransform: TRANSFORM,
    provider: async () => {
      providerCalls += 1
      throw new Error('upstream outcome is ambiguous')
    },
  })
  const body = Buffer.from(stableJson(requestEnvelope, 0), 'utf8')
  const headers = {
    'content-type': 'application/json',
    'content-digest': contentDigestHeader(body),
    'x-rta-protocol': 'remote-gateway-v1',
  }

  await assert.rejects(
    () => handler({ headers, body, now: NOW }),
    /upstream outcome is ambiguous/,
  )
  await assert.rejects(
    () => handler({ headers, body, now: NOW }),
    /was already accepted/,
  )
  assert.equal(providerCalls, 1)
})

test('client rejects transform drift, response tampering, and an untrusted gateway key', async () => {
  const controller = keyPair()
  const gateway = keyPair()
  const attackerGateway = keyPair()
  const boundPacket = packet()
  const requestEnvelope = requestFixture(controller, boundPacket)
  const handler = createReferenceRemoteGateway({
    controllerPublicKeyBytes: controller.publicPem,
    gatewayPrivateKeyBytes: gateway.privatePem,
    promptTransform: TRANSFORM,
    provider: async () => ({
      jobResult: jobResult(boundPacket),
      upstreamRequestBytes: Buffer.from('exact-upstream-request'),
    }),
  })

  const driftedConfig = structuredClone(config())
  driftedConfig.prompt_transform.sha256 = SHA_A
  await assert.rejects(
    () => submitRemoteGatewayRequest({
      config: driftedConfig,
      requestEnvelope,
      gatewayPublicKeyBytes: gateway.publicPem,
      now: NOW,
      transport: ({ body, headers }) => handler({ body, headers, now: NOW }),
    }),
    /prompt transform differs/,
  )

  await assert.rejects(
    () => submitRemoteGatewayRequest({
      config: config(),
      requestEnvelope,
      gatewayPublicKeyBytes: gateway.publicPem,
      now: NOW,
      transport: async ({ body, headers }) => {
        const response = await handler({ body, headers, now: NOW })
        return {
          ...response,
          body: Buffer.concat([response.body, Buffer.from(' ')]),
        }
      },
    }),
    /Content-Digest does not match/,
  )

  const freshHandler = createReferenceRemoteGateway({
    controllerPublicKeyBytes: controller.publicPem,
    gatewayPrivateKeyBytes: gateway.privatePem,
    promptTransform: TRANSFORM,
    provider: async () => ({
      jobResult: jobResult(boundPacket),
      upstreamRequestBytes: Buffer.from('exact-upstream-request'),
    }),
  })
  await assert.rejects(
    () => submitRemoteGatewayRequest({
      config: config(),
      requestEnvelope,
      gatewayPublicKeyBytes: attackerGateway.publicPem,
      now: NOW,
      transport: ({ body, headers }) => freshHandler({
        body,
        headers,
        now: NOW,
      }),
    }),
    /does not match the externally pinned gateway key/,
  )
})

test('content digest rejects a transformed request or response body', () => {
  const body = Buffer.from('{"exact":true}\n', 'utf8')
  assert.equal(
    assertContentDigestHeader(contentDigestHeader(body), body),
    contentDigestHeader(body),
  )
  assert.throws(
    () => assertContentDigestHeader(
      contentDigestHeader(body),
      Buffer.from('{"exact":false}\n', 'utf8'),
    ),
    RemoteGatewayContractError,
  )
})
