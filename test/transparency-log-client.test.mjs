import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync } from 'node:crypto'

import { contentDigestHeader } from '../scripts/lib/remote-gateway-contracts.mjs'
import { createRootAttestation } from '../scripts/lib/root-attestation.mjs'
import { stableJson } from '../scripts/lib/run-engine.mjs'
import {
  createTransparencyConsistencyProof,
  createTransparencyConsistencyRequest,
  createTransparencyInclusionReceipt,
  createTransparencyPublishRequest,
  createTransparencySignedCheckpoint,
  projectTransparencySignedCheckpoint,
  transparencyLeafHash,
  transparencyNodeHash,
  canonicalAttestationBytes,
} from '../scripts/lib/transparency-log-contracts.mjs'
import {
  httpsTransparencyLogTransport,
  submitTransparencyConsistencyRequest,
  submitTransparencyLogEntry,
} from '../scripts/lib/transparency-log-client.mjs'

function keyPair() {
  return generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })
}

function digest(value) {
  return createHash('sha256').update(value).digest('hex')
}

function fixture() {
  const rootKeys = keyPair()
  const logKeys = keyPair()
  const attestation = createRootAttestation({
    run: {
      schema_version: '6.0.0',
      run_id: 'run:2026-08-01T10-00-00-000Z:abcdef123456',
      state: 'COMPLETED',
      phase: 'FINALIZED',
    },
    runSha256: digest('terminal run'),
    privateKeyBytes: rootKeys.privateKey,
    signedAt: new Date('2026-08-01T10:01:00.000Z'),
  })
  const leafHash = transparencyLeafHash(canonicalAttestationBytes(attestation))
  const receipt = createTransparencyInclusionReceipt({
    attestation,
    leafIndex: 0,
    treeSize: 1,
    inclusionPath: [],
    rootHash: leafHash,
    origin: 'audit-log.example/v1',
    privateKeyBytes: logKeys.privateKey,
    issuedAt: new Date('2026-08-01T10:02:00.000Z'),
  })
  const config = {
    schema_version: '1.0.0',
    protocol: 'transparency-log-v1',
    log_url: 'https://log.example/v1/entries',
    log_origin: 'audit-log.example/v1',
    log_public_key_path: 'C:\\trusted\\log-public.pem',
    tls_spki_sha256: digest('tls spki'),
    limits: {
      request_timeout_ms: 30000,
      max_clock_skew_ms: 30000,
      max_request_bytes: 262144,
      max_response_bytes: 262144,
    },
  }
  return { attestation, logKeys, receipt, config }
}

function responseFor(receipt, overrides = {}) {
  const body = Buffer.from(stableJson(receipt, 0), 'utf8')
  const response = {
    statusCode: 201,
    headers: {
      'content-type': 'application/json',
      'content-length': String(body.length),
      'content-digest': contentDigestHeader(body),
      'x-rta-protocol': 'transparency-log-v1',
    },
    body,
  }
  return {
    ...response,
    ...overrides,
    headers: {
      ...response.headers,
      ...overrides.headers,
    },
  }
}

function consistencyClientFixture() {
  const base = fixture()
  const retainedCheckpoint = projectTransparencySignedCheckpoint(base.receipt)
  const appendedLeaf = transparencyLeafHash(Buffer.from('second committed leaf'))
  const secondRoot = transparencyNodeHash(
    retainedCheckpoint.checkpoint.root_hash,
    appendedLeaf,
  )
  const receiptHead = createTransparencyInclusionReceipt({
    attestation: base.attestation,
    leafIndex: 0,
    treeSize: 2,
    inclusionPath: [appendedLeaf],
    rootHash: secondRoot,
    origin: base.config.log_origin,
    privateKeyBytes: base.logKeys.privateKey,
    issuedAt: new Date('2026-08-01T10:03:00.000Z'),
  })
  const receiptCheckpoint = projectTransparencySignedCheckpoint(receiptHead)
  const requestDocument = createTransparencyConsistencyRequest({
    firstSize: retainedCheckpoint.checkpoint.tree_size,
    secondSize: receiptCheckpoint.checkpoint.tree_size,
  })
  const proof = createTransparencyConsistencyProof({
    firstCheckpoint: retainedCheckpoint,
    secondCheckpoint: receiptCheckpoint,
    consistencyPath: [appendedLeaf],
  })
  return {
    ...base,
    config: {
      ...base.config,
      schema_version: '1.1.0',
      consistency_url: 'https://log.example/v1/consistency',
    },
    retainedCheckpoint,
    receiptCheckpoint,
    receiptHead,
    requestDocument,
    proof,
  }
}

function consistencyResponseFor(proof, overrides = {}) {
  const body = Buffer.from(stableJson(proof, 0), 'utf8')
  const response = {
    statusCode: 200,
    headers: {
      'content-type': 'application/json',
      'content-length': String(body.length),
      'content-digest': contentDigestHeader(body),
      'x-rta-protocol': 'transparency-log-consistency-v1',
    },
    body,
  }
  return {
    ...response,
    ...overrides,
    headers: {
      ...response.headers,
      ...overrides.headers,
    },
  }
}

test('transparency client submits canonical bytes and verifies the returned receipt', async () => {
  const { attestation, logKeys, receipt, config } = fixture()
  const requestDocument = createTransparencyPublishRequest(attestation)
  let observed
  const result = await submitTransparencyLogEntry({
    config,
    requestDocument,
    attestation,
    logPublicKeyBytes: logKeys.publicKey,
    now: new Date('2026-08-01T10:03:00.000Z'),
    transport: async (request) => {
      observed = request
      return responseFor(receipt)
    },
  })

  assert.equal(
    observed.body.toString('utf8'),
    stableJson(requestDocument, 0),
  )
  assert.equal(observed.headers['x-rta-protocol'], 'transparency-log-v1')
  assert.equal(result.verification.claim, 'INCLUSION_AT_SIGNED_CHECKPOINT')
  assert.deepEqual(result.receipt, receipt)
})

test('transparency client rejects transformed and unauthenticated responses', async () => {
  const { attestation, logKeys, receipt, config } = fixture()
  const requestDocument = createTransparencyPublishRequest(attestation)
  const base = {
    config,
    requestDocument,
    attestation,
    logPublicKeyBytes: logKeys.publicKey,
    now: new Date('2026-08-01T10:03:00.000Z'),
  }

  await assert.rejects(
    submitTransparencyLogEntry({
      ...base,
      transport: async () => responseFor(receipt, {
        headers: {
          'content-type': 'application/json',
          'content-digest': 'sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:',
          'x-rta-protocol': 'transparency-log-v1',
        },
      }),
    }),
    /Content-Digest does not match/i,
  )

  await assert.rejects(
    submitTransparencyLogEntry({
      ...base,
      transport: async () => responseFor(receipt, {
        headers: {
          'content-type': 'application/json',
          'content-digest': contentDigestHeader(
            Buffer.from(stableJson(receipt, 0), 'utf8'),
          ),
          'content-encoding': 'gzip',
          'x-rta-protocol': 'transparency-log-v1',
        },
      }),
    }),
    /must not use a transforming content encoding/i,
  )
})

test('transparency client rejects truncated and ambiguous responses', async () => {
  const { attestation, logKeys, receipt, config } = fixture()
  const requestDocument = createTransparencyPublishRequest(attestation)
  const base = {
    config,
    requestDocument,
    attestation,
    logPublicKeyBytes: logKeys.publicKey,
    now: new Date('2026-08-01T10:03:00.000Z'),
  }
  const completeBody = Buffer.from(stableJson(receipt, 0), 'utf8')
  const truncatedBody = completeBody.subarray(0, completeBody.length - 1)

  await assert.rejects(
    submitTransparencyLogEntry({
      ...base,
      transport: async () => responseFor(receipt, {
        body: truncatedBody,
        headers: {
          'content-digest': contentDigestHeader(truncatedBody),
        },
      }),
    }),
    /truncated|Content-Length did not match/i,
  )

  await assert.rejects(
    submitTransparencyLogEntry({
      ...base,
      transport: async () => responseFor(receipt, {
        headers: {
          'content-digest': [
            contentDigestHeader(completeBody),
            contentDigestHeader(completeBody),
          ],
        },
      }),
    }),
    /header content-digest is ambiguous/i,
  )

  await assert.rejects(
    submitTransparencyLogEntry({
      ...base,
      transport: async () => responseFor(receipt, {
        headers: {
          'Content-Digest': contentDigestHeader(completeBody),
        },
      }),
    }),
    /header content-digest is ambiguous/i,
  )
})

test('v1.1 consistency client uses the exact endpoint and binds retained and receipt heads', async () => {
  const fixture = consistencyClientFixture()
  let observed
  const result = await submitTransparencyConsistencyRequest({
    config: fixture.config,
    requestDocument: fixture.requestDocument,
    logPublicKeyBytes: fixture.logKeys.publicKey,
    expectedFirstCheckpoint: fixture.retainedCheckpoint,
    expectedSecondCheckpoint: fixture.receiptCheckpoint,
    now: new Date('2026-08-01T10:04:00.000Z'),
    transport: async (request) => {
      observed = request
      return consistencyResponseFor(fixture.proof)
    },
  })

  assert.equal(observed.endpointUrl, fixture.config.consistency_url)
  assert.notEqual(observed.endpointUrl, fixture.config.log_url)
  assert.equal(
    observed.body.toString('utf8'),
    stableJson(fixture.requestDocument, 0),
  )
  assert.equal(
    observed.headers['x-rta-protocol'],
    'transparency-log-consistency-v1',
  )
  assert.equal(
    observed.headers['content-digest'],
    contentDigestHeader(observed.body),
  )
  assert.deepEqual(result.proof, fixture.proof)
  assert.equal(result.verification.claim, 'CONSISTENCY_BETWEEN_SIGNED_CHECKPOINTS')
  assert.equal(result.verification.relation, 'APPEND_ONLY_EXTENSION')
  assert.equal(
    result.verification.first_root_hash,
    fixture.retainedCheckpoint.checkpoint.root_hash,
  )
  assert.equal(
    result.verification.second_root_hash,
    fixture.receiptHead.checkpoint.root_hash,
  )
})

test('consistency client rejects wrong protocol, sizes, retained or receipt heads, truncation, and extra framing', async (t) => {
  const fixture = consistencyClientFixture()
  const base = {
    config: fixture.config,
    requestDocument: fixture.requestDocument,
    logPublicKeyBytes: fixture.logKeys.publicKey,
    expectedFirstCheckpoint: fixture.retainedCheckpoint,
    expectedSecondCheckpoint: fixture.receiptCheckpoint,
    now: new Date('2026-08-01T10:04:00.000Z'),
  }

  await t.test('wrong response protocol', async () => {
    await assert.rejects(
      submitTransparencyConsistencyRequest({
        ...base,
        transport: async () => consistencyResponseFor(fixture.proof, {
          headers: { 'x-rta-protocol': 'transparency-log-v1' },
        }),
      }),
      /must declare transparency-log-consistency-v1/i,
    )
  })

  await t.test('proof for different tree sizes', async () => {
    const wrongSizeProof = createTransparencyConsistencyProof({
      firstCheckpoint: fixture.retainedCheckpoint,
      secondCheckpoint: fixture.retainedCheckpoint,
      consistencyPath: [],
    })
    await assert.rejects(
      submitTransparencyConsistencyRequest({
        ...base,
        transport: async () => consistencyResponseFor(wrongSizeProof),
      }),
      /does not match the exact requested tree sizes/i,
    )
  })

  const wrongRetainedCheckpoint = createTransparencySignedCheckpoint({
    treeSize: 1,
    rootHash: digest('wrong retained root'),
    origin: fixture.config.log_origin,
    privateKeyBytes: fixture.logKeys.privateKey,
    issuedAt: new Date('2026-08-01T10:02:00.000Z'),
  })
  const wrongReceiptCheckpoint = createTransparencySignedCheckpoint({
    treeSize: 2,
    rootHash: digest('wrong receipt root'),
    origin: fixture.config.log_origin,
    privateKeyBytes: fixture.logKeys.privateKey,
    issuedAt: new Date('2026-08-01T10:03:00.000Z'),
  })
  for (const [name, expected] of [
    ['retained head mismatch', {
      expectedFirstCheckpoint: wrongRetainedCheckpoint,
    }],
    ['receipt head mismatch', {
      expectedSecondCheckpoint: wrongReceiptCheckpoint,
    }],
  ]) {
    await t.test(name, async () => {
      await assert.rejects(
        submitTransparencyConsistencyRequest({
          ...base,
          ...expected,
          transport: async () => consistencyResponseFor(fixture.proof),
        }),
        /does not match the externally supplied signed checkpoint/i,
      )
    })
  }

  await t.test('truncated response', async () => {
    const completeBody = Buffer.from(stableJson(fixture.proof, 0), 'utf8')
    const truncatedBody = completeBody.subarray(0, completeBody.length - 1)
    await assert.rejects(
      submitTransparencyConsistencyRequest({
        ...base,
        transport: async () => consistencyResponseFor(fixture.proof, {
          body: truncatedBody,
          headers: {
            'content-digest': contentDigestHeader(truncatedBody),
          },
        }),
      }),
      /truncated|Content-Length did not match/i,
    )
  })

  for (const [name, headers, pattern] of [
    [
      'transfer encoding',
      { 'transfer-encoding': 'chunked' },
      /must not use Transfer-Encoding/i,
    ],
    [
      'content encoding',
      { 'content-encoding': 'gzip' },
      /must not use a transforming content encoding/i,
    ],
    [
      'ambiguous protected header',
      { 'Content-Digest': contentDigestHeader(
        Buffer.from(stableJson(fixture.proof, 0), 'utf8'),
      ) },
      /header content-digest is ambiguous/i,
    ],
  ]) {
    await t.test(name, async () => {
      await assert.rejects(
        submitTransparencyConsistencyRequest({
          ...base,
          transport: async () => consistencyResponseFor(
            fixture.proof,
            { headers },
          ),
        }),
        pattern,
      )
    })
  }
})

test('transparency HTTPS transport rejects a non-public literal endpoint before I/O', () => {
  const { config } = fixture()
  config.log_url = 'https://127.0.0.1/v1/entries'
  assert.throws(
    () => httpsTransparencyLogTransport({
      config,
      body: Buffer.from('{}\n'),
      headers: {},
    }),
    /non-public literal IP address/i,
  )
})
