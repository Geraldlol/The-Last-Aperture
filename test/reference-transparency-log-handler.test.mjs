import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync } from 'node:crypto'
import { request as httpsRequest } from 'node:https'

import {
  createReferenceTransparencyConsistencyHandler,
  createReferenceTransparencyLogHandler,
} from '../providers/reference-transparency-log/handler.mjs'
import { createReferenceTransparencyHttpsServer } from '../providers/reference-transparency-log/server.mjs'
import { contentDigestHeader } from '../scripts/lib/remote-gateway-contracts.mjs'
import { createRootAttestation } from '../scripts/lib/root-attestation.mjs'
import { stableJson } from '../scripts/lib/run-engine.mjs'
import {
  canonicalAttestationBytes,
  createTransparencyConsistencyProof,
  createTransparencyConsistencyRequest,
  createTransparencyInclusionReceipt,
  createTransparencyPublishRequest,
  createTransparencySignedCheckpoint,
  transparencyLeafHash,
  transparencyNodeHash,
  verifyTransparencyConsistencyProof,
} from '../scripts/lib/transparency-log-contracts.mjs'
import {
  REFERENCE_TLS_PASSPHRASE,
  REFERENCE_TLS_PFX,
} from './fixtures/reference-transparency-tls.mjs'

const NOW = new Date('2026-08-01T12:00:00.000Z')
const ORIGIN = 'audit-log.example/v1'

function keyPair() {
  return generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function rootAttestation(keys, suffix = 'a') {
  return createRootAttestation({
    run: {
      schema_version: '6.0.0',
      run_id: `run:2026-08-01T11-00-00-000Z:${suffix.repeat(12)}`,
      state: 'COMPLETED',
      phase: 'FINALIZED',
    },
    runSha256: sha256(`terminal-run-${suffix}`),
    privateKeyBytes: keys.privateKey,
    signedAt: new Date('2026-08-01T11:30:00.000Z'),
  })
}

function receiptFor({
  attestation,
  logKeys,
  origin = ORIGIN,
  issuedAt = NOW,
}) {
  const leafHash = transparencyLeafHash(canonicalAttestationBytes(attestation))
  return createTransparencyInclusionReceipt({
    attestation,
    leafIndex: 0,
    treeSize: 1,
    inclusionPath: [],
    rootHash: leafHash,
    origin,
    privateKeyBytes: logKeys.privateKey,
    issuedAt,
  })
}

function requestFixture() {
  const rootKeys = keyPair()
  const logKeys = keyPair()
  const attestation = rootAttestation(rootKeys)
  const requestDocument = createTransparencyPublishRequest(attestation)
  const body = Buffer.from(stableJson(requestDocument, 0), 'utf8')
  const receipt = receiptFor({ attestation, logKeys })
  return {
    rootKeys,
    logKeys,
    attestation,
    requestDocument,
    body,
    receipt,
  }
}

function headersFor(body, overrides = {}) {
  return {
    'content-type': 'application/json',
    'content-length': String(body.length),
    'content-digest': contentDigestHeader(body),
    'x-rta-protocol': 'transparency-log-v1',
    ...overrides,
  }
}

function consistencyFixture() {
  const logKeys = keyPair()
  const firstRoot = transparencyLeafHash(Buffer.from('first leaf'))
  const appendedRoot = transparencyLeafHash(Buffer.from('second leaf'))
  const secondRoot = transparencyNodeHash(firstRoot, appendedRoot)
  const requestDocument = createTransparencyConsistencyRequest({
    firstSize: 1,
    secondSize: 2,
  })
  const body = Buffer.from(stableJson(requestDocument, 0), 'utf8')
  const firstCheckpoint = createTransparencySignedCheckpoint({
    treeSize: 1,
    rootHash: firstRoot,
    origin: ORIGIN,
    privateKeyBytes: logKeys.privateKey,
    issuedAt: NOW,
  })
  const secondCheckpoint = createTransparencySignedCheckpoint({
    treeSize: 2,
    rootHash: secondRoot,
    origin: ORIGIN,
    privateKeyBytes: logKeys.privateKey,
    issuedAt: NOW,
  })
  const proof = createTransparencyConsistencyProof({
    firstCheckpoint,
    secondCheckpoint,
    consistencyPath: [appendedRoot],
  })
  return {
    logKeys,
    requestDocument,
    body,
    firstCheckpoint,
    secondCheckpoint,
    proof,
  }
}

function consistencyHeaders(body, overrides = {}) {
  return {
    'content-type': 'application/json',
    'content-length': String(body.length),
    'content-digest': contentDigestHeader(body),
    'x-rta-protocol': 'transparency-log-consistency-v1',
    ...overrides,
  }
}

function requestLocalHttps({ port, path, body, headers }) {
  return new Promise((resolve, reject) => {
    const request = httpsRequest({
      host: '127.0.0.1',
      port,
      path,
      method: 'POST',
      rejectUnauthorized: false,
      agent: false,
      headers,
    }, (response) => {
      const chunks = []
      response.on('data', (chunk) => chunks.push(Buffer.from(chunk)))
      response.once('error', reject)
      response.once('end', () => resolve({
        statusCode: response.statusCode,
        headers: response.headers,
        body: Buffer.concat(chunks),
      }))
    })
    request.once('error', reject)
    request.end(body)
  })
}

test('reference transparency handler publishes through the store and returns exact canonical HTTP output', async () => {
  const fixture = requestFixture()
  let observed
  const store = {
    origin: ORIGIN,
    keyId: fixture.receipt.checkpoint.signing.key_id,
    publicKeyBytes: fixture.logKeys.publicKey,
    async publish(document, context) {
      observed = { document, context }
      return fixture.receipt
    },
  }
  const handler = createReferenceTransparencyLogHandler({ store })
  const response = await handler({
    method: 'POST',
    headers: headersFor(fixture.body),
    body: fixture.body,
    now: NOW,
  })

  assert.deepEqual(observed.document, fixture.requestDocument)
  assert.equal(observed.context.now.toISOString(), NOW.toISOString())
  assert.equal(observed.context.issuedAt.toISOString(), NOW.toISOString())
  assert.equal(response.statusCode, 201)
  assert.equal(response.body.toString('utf8'), stableJson(fixture.receipt, 0))
  assert.deepEqual(response.headers, {
    'content-type': 'application/json',
    'content-length': String(response.body.length),
    'content-digest': contentDigestHeader(response.body),
    'cache-control': 'no-store',
    'x-rta-protocol': 'transparency-log-v1',
  })
})

test('reference transparency handler accepts an append function and unwraps its receipt', async () => {
  const fixture = requestFixture()
  let appendCalls = 0
  const handler = createReferenceTransparencyLogHandler({
    append: async (document, { now }) => {
      appendCalls += 1
      assert.deepEqual(document, fixture.requestDocument)
      assert.equal(now.toISOString(), NOW.toISOString())
      return { receipt: fixture.receipt }
    },
    origin: ORIGIN,
    logPublicKeyBytes: fixture.logKeys.publicKey,
  })

  const response = await handler({
    method: 'POST',
    headers: headersFor(fixture.body),
    body: fixture.body,
    now: NOW,
  })
  assert.equal(appendCalls, 1)
  assert.deepEqual(JSON.parse(response.body.toString('utf8')), fixture.receipt)
})

test('reference transparency handler reports an idempotent publication as HTTP 200', async () => {
  const fixture = requestFixture()
  const handler = createReferenceTransparencyLogHandler({
    append: async () => ({
      receipt: fixture.receipt,
      created: false,
      idempotent: true,
    }),
    origin: ORIGIN,
    logPublicKeyBytes: fixture.logKeys.publicKey,
  })
  const response = await handler({
    method: 'POST',
    headers: headersFor(fixture.body),
    body: fixture.body,
    now: NOW,
  })
  assert.equal(response.statusCode, 200)
})

test('malformed, transformed, ambiguous, and truncated requests never reach append', async (t) => {
  const fixture = requestFixture()
  let appendCalls = 0
  const handler = createReferenceTransparencyLogHandler({
    append: async () => {
      appendCalls += 1
      return fixture.receipt
    },
    origin: ORIGIN,
    logPublicKeyBytes: fixture.logKeys.publicKey,
  })
  const valid = () => ({
    method: 'POST',
    headers: headersFor(fixture.body),
    body: fixture.body,
    now: NOW,
  })
  const malformedJson = Buffer.from('{"schema_version":', 'utf8')
  const nonCanonical = Buffer.from(
    JSON.stringify(fixture.requestDocument, null, 2),
    'utf8',
  )
  const invalidSchema = Buffer.from(stableJson({
    schema_version: '1.0.0',
    protocol: 'transparency-log-v1',
  }, 0), 'utf8')
  const cases = [
    {
      name: 'non-POST method',
      request: { ...valid(), method: 'GET' },
      pattern: /method must be POST/i,
    },
    {
      name: 'missing method',
      request: { ...valid(), method: undefined },
      pattern: /method must be POST/i,
    },
    {
      name: 'wrong media type',
      request: {
        ...valid(),
        headers: headersFor(fixture.body, { 'content-type': 'text/plain' }),
      },
      pattern: /must use application\/json/i,
    },
    {
      name: 'media type parameters',
      request: {
        ...valid(),
        headers: headersFor(fixture.body, {
          'content-type': 'application/json; charset=utf-8',
        }),
      },
      pattern: /must use application\/json/i,
    },
    {
      name: 'content encoding',
      request: {
        ...valid(),
        headers: headersFor(fixture.body, { 'content-encoding': 'identity' }),
      },
      pattern: /must not use a content encoding/i,
    },
    {
      name: 'transfer encoding',
      request: {
        ...valid(),
        headers: headersFor(fixture.body, { 'transfer-encoding': 'chunked' }),
      },
      pattern: /must not use Transfer-Encoding/i,
    },
    {
      name: 'wrong protocol',
      request: {
        ...valid(),
        headers: headersFor(fixture.body, {
          'x-rta-protocol': 'transparency-log-v2',
        }),
      },
      pattern: /must declare transparency-log-v1/i,
    },
    {
      name: 'missing content length',
      request: {
        ...valid(),
        headers: {
          'content-type': 'application/json',
          'content-digest': contentDigestHeader(fixture.body),
          'x-rta-protocol': 'transparency-log-v1',
        },
      },
      pattern: /requires Content-Length/i,
    },
    {
      name: 'non-canonical content length',
      request: {
        ...valid(),
        headers: headersFor(fixture.body, {
          'content-length': `0${fixture.body.length}`,
        }),
      },
      pattern: /canonical decimal integer/i,
    },
    {
      name: 'truncated body',
      request: {
        ...valid(),
        headers: headersFor(fixture.body, {
          'content-length': String(fixture.body.length + 1),
        }),
      },
      pattern: /truncated or Content-Length did not match/i,
    },
    {
      name: 'wrong content digest',
      request: {
        ...valid(),
        headers: headersFor(fixture.body, {
          'content-digest': 'sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:',
        }),
      },
      pattern: /Content-Digest does not match/i,
    },
    {
      name: 'case-ambiguous protected header',
      request: {
        ...valid(),
        headers: {
          ...headersFor(fixture.body),
          'Content-Length': String(fixture.body.length),
        },
      },
      pattern: /content-length is ambiguous/i,
    },
    {
      name: 'malformed JSON',
      request: {
        method: 'POST',
        headers: headersFor(malformedJson),
        body: malformedJson,
        now: NOW,
      },
      pattern: /not valid JSON/i,
    },
    {
      name: 'non-canonical JSON',
      request: {
        method: 'POST',
        headers: headersFor(nonCanonical),
        body: nonCanonical,
        now: NOW,
      },
      pattern: /canonical JSON bytes/i,
    },
    {
      name: 'schema-invalid canonical JSON',
      request: {
        method: 'POST',
        headers: headersFor(invalidSchema),
        body: invalidSchema,
        now: NOW,
      },
      pattern: /publication request validation failed/i,
    },
    {
      name: 'invalid request instant',
      request: { ...valid(), now: 'not-an-instant' },
      pattern: /time must be a valid instant/i,
    },
  ]

  for (const entry of cases) {
    await t.test(entry.name, async () => {
      await assert.rejects(() => handler(entry.request), entry.pattern)
      assert.equal(appendCalls, 0)
    })
  }

  const overLimitBody = Buffer.alloc(4097, 0x20)
  const boundedHandler = createReferenceTransparencyLogHandler({
    append: async () => {
      appendCalls += 1
      return fixture.receipt
    },
    origin: ORIGIN,
    logPublicKeyBytes: fixture.logKeys.publicKey,
    maxRequestBytes: 4096,
  })
  await t.test('over-limit body', async () => {
    await assert.rejects(
      () => boundedHandler({
        method: 'POST',
        headers: headersFor(overLimitBody),
        body: overLimitBody,
        now: NOW,
      }),
      /exceeded maxRequestBytes/i,
    )
    assert.equal(appendCalls, 0)
  })
})

test('invalid trusted key and store identity drift fail before publication', () => {
  const fixture = requestFixture()
  let publishCalls = 0
  assert.throws(
    () => createReferenceTransparencyLogHandler({
      append: async () => {
        publishCalls += 1
        return fixture.receipt
      },
      origin: ORIGIN,
      logPublicKeyBytes: Buffer.from('not a public key'),
    }),
    /cannot parse transparency log public key/i,
  )
  assert.throws(
    () => createReferenceTransparencyLogHandler({
      store: {
        origin: ORIGIN,
        keyId: `ed25519:${'0'.repeat(64)}`,
        publicKeyBytes: fixture.logKeys.publicKey,
        async publish() {
          publishCalls += 1
          return fixture.receipt
        },
      },
    }),
    /store key does not match/i,
  )
  assert.equal(publishCalls, 0)
})

test('handler distinguishes request rejection from post-publication dependency failure', async () => {
  const fixture = requestFixture()
  const attackerKeys = keyPair()
  let appendCalls = 0
  const handler = createReferenceTransparencyLogHandler({
    append: async () => {
      appendCalls += 1
      return receiptFor({
        attestation: fixture.attestation,
        logKeys: attackerKeys,
      })
    },
    origin: ORIGIN,
    logPublicKeyBytes: fixture.logKeys.publicKey,
  })

  await assert.rejects(
    () => handler({
      method: 'GET',
      headers: headersFor(fixture.body),
      body: fixture.body,
      now: NOW,
    }),
    (error) => {
      assert.equal(error.code, 'TRANSPARENCY_REQUEST_INVALID')
      return true
    },
  )
  assert.equal(appendCalls, 0)

  await assert.rejects(
    () => handler({
      method: 'POST',
      headers: headersFor(fixture.body),
      body: fixture.body,
      now: NOW,
    }),
    (error) => {
      assert.notEqual(error.code, 'TRANSPARENCY_REQUEST_INVALID')
      return true
    },
  )
  assert.equal(appendCalls, 1)
})

test('handler refuses receipts with a substituted key, origin, signature, or entry', async (t) => {
  const fixture = requestFixture()
  const attackerKeys = keyPair()
  const otherAttestation = rootAttestation(fixture.rootKeys, 'b')
  const cases = [
    {
      name: 'substituted signing key',
      receipt: receiptFor({
        attestation: fixture.attestation,
        logKeys: attackerKeys,
      }),
      pattern: /does not match the externally pinned public key/i,
    },
    {
      name: 'substituted origin',
      receipt: receiptFor({
        attestation: fixture.attestation,
        logKeys: fixture.logKeys,
        origin: 'attacker-log.example/v1',
      }),
      pattern: /origin does not match/i,
    },
    {
      name: 'invalid signature',
      receipt: {
        ...structuredClone(fixture.receipt),
        signature: Buffer.alloc(64).toString('base64'),
      },
      pattern: /signature verification failed/i,
    },
    {
      name: 'substituted entry',
      receipt: receiptFor({
        attestation: otherAttestation,
        logKeys: fixture.logKeys,
      }),
      pattern: /does not bind the supplied root attestation/i,
    },
  ]

  for (const entry of cases) {
    await t.test(entry.name, async () => {
      let appendCalls = 0
      const handler = createReferenceTransparencyLogHandler({
        append: async () => {
          appendCalls += 1
          return entry.receipt
        },
        origin: ORIGIN,
        logPublicKeyBytes: fixture.logKeys.publicKey,
      })
      await assert.rejects(
        () => handler({
          method: 'POST',
          headers: headersFor(fixture.body),
          body: fixture.body,
          now: NOW,
        }),
        entry.pattern,
      )
      assert.equal(appendCalls, 1)
    })
  }
})

test('handler enforces the canonical response byte limit', async () => {
  const fixture = requestFixture()
  const origin = 'a'.repeat(256)
  const leafHash = transparencyLeafHash(
    canonicalAttestationBytes(fixture.attestation),
  )
  const inclusionPath = Array.from(
    { length: 53 },
    (_, index) => sha256(`wide-proof-sibling-${index}`),
  )
  let rootHash = leafHash
  for (const sibling of inclusionPath) {
    rootHash = transparencyNodeHash(rootHash, sibling)
  }
  const receipt = createTransparencyInclusionReceipt({
    attestation: fixture.attestation,
    leafIndex: 0,
    treeSize: Number.MAX_SAFE_INTEGER,
    inclusionPath,
    rootHash,
    origin,
    privateKeyBytes: fixture.logKeys.privateKey,
    issuedAt: NOW,
  })
  assert.ok(Buffer.byteLength(stableJson(receipt, 0), 'utf8') > 4096)
  let appendCalls = 0
  const handler = createReferenceTransparencyLogHandler({
    append: async () => {
      appendCalls += 1
      return receipt
    },
    origin,
    logPublicKeyBytes: fixture.logKeys.publicKey,
    maxResponseBytes: 4096,
  })

  await assert.rejects(
    () => handler({
      method: 'POST',
      headers: headersFor(fixture.body),
      body: fixture.body,
      now: NOW,
    }),
    /response exceeded maxResponseBytes/i,
  )
  assert.equal(appendCalls, 1)
})

test('consistency handler is read-only and returns exact authenticated framing', async () => {
  const fixture = consistencyFixture()
  let observed
  let publishCalls = 0
  const store = {
    origin: ORIGIN,
    keyId: fixture.firstCheckpoint.checkpoint.signing.key_id,
    publicKeyBytes: fixture.logKeys.publicKey,
    async publish() {
      publishCalls += 1
      throw new Error('consistency retrieval must not publish')
    },
    async proveConsistency(document, context) {
      observed = { document, context }
      return fixture.proof
    },
  }
  const handler = createReferenceTransparencyConsistencyHandler({ store })
  const response = await handler({
    method: 'POST',
    headers: consistencyHeaders(fixture.body),
    body: fixture.body,
    now: NOW,
  })

  assert.equal(publishCalls, 0)
  assert.deepEqual(observed.document, fixture.requestDocument)
  assert.equal(observed.context.now.toISOString(), NOW.toISOString())
  assert.equal(observed.context.issuedAt.toISOString(), NOW.toISOString())
  assert.equal(response.statusCode, 200)
  assert.equal(response.body.toString('utf8'), stableJson(fixture.proof, 0))
  assert.deepEqual(response.headers, {
    'content-type': 'application/json',
    'content-length': String(response.body.length),
    'content-digest': contentDigestHeader(response.body),
    'cache-control': 'no-store',
    'x-rta-protocol': 'transparency-log-consistency-v1',
  })
  assert.equal(
    verifyTransparencyConsistencyProof({
      proof: JSON.parse(response.body.toString('utf8')),
      publicKeyBytes: fixture.logKeys.publicKey,
      expectedOrigin: ORIGIN,
      now: NOW,
    }).relation,
    'APPEND_ONLY_EXTENSION',
  )
})

test('malformed consistency sizes, method, headers, and digest never reach the prover', async (t) => {
  const fixture = consistencyFixture()
  let proveCalls = 0
  const handler = createReferenceTransparencyConsistencyHandler({
    prove: async () => {
      proveCalls += 1
      return fixture.proof
    },
    origin: ORIGIN,
    logPublicKeyBytes: fixture.logKeys.publicKey,
  })
  const invalidSizeDocuments = [
    { ...fixture.requestDocument, first_tree_size: 0 },
    {
      ...fixture.requestDocument,
      first_tree_size: 3,
      second_tree_size: 2,
    },
  ]
  const cases = [
    {
      name: 'non-POST method',
      method: 'GET',
      body: fixture.body,
      headers: consistencyHeaders(fixture.body),
      pattern: /method must be POST/i,
    },
    {
      name: 'wrong protocol header',
      method: 'POST',
      body: fixture.body,
      headers: consistencyHeaders(fixture.body, {
        'x-rta-protocol': 'transparency-log-v1',
      }),
      pattern: /must declare transparency-log-consistency-v1/i,
    },
    {
      name: 'truncated declared length',
      method: 'POST',
      body: fixture.body,
      headers: consistencyHeaders(fixture.body, {
        'content-length': String(fixture.body.length + 1),
      }),
      pattern: /truncated|Content-Length/i,
    },
    {
      name: 'ambiguous digest header',
      method: 'POST',
      body: fixture.body,
      headers: {
        ...consistencyHeaders(fixture.body),
        'Content-Digest': contentDigestHeader(fixture.body),
      },
      pattern: /header content-digest is ambiguous/i,
    },
    {
      name: 'wrong body digest',
      method: 'POST',
      body: fixture.body,
      headers: consistencyHeaders(fixture.body, {
        'content-digest': contentDigestHeader(Buffer.from('different')),
      }),
      pattern: /Content-Digest does not match/i,
    },
    ...invalidSizeDocuments.map((document, index) => {
      const body = Buffer.from(stableJson(document, 0), 'utf8')
      return {
        name: `invalid size document ${index + 1}`,
        method: 'POST',
        body,
        headers: consistencyHeaders(body),
        pattern: /consistency request validation failed/i,
      }
    }),
  ]

  for (const entry of cases) {
    await t.test(entry.name, async () => {
      await assert.rejects(
        handler({
          method: entry.method,
          headers: entry.headers,
          body: entry.body,
          now: NOW,
        }),
        entry.pattern,
      )
    })
  }
  assert.equal(proveCalls, 0)
})

test('consistency handler rejects an otherwise valid proof for different requested sizes', async () => {
  const fixture = consistencyFixture()
  const requestDocument = createTransparencyConsistencyRequest({
    firstSize: 1,
    secondSize: 1,
  })
  const body = Buffer.from(stableJson(requestDocument, 0), 'utf8')
  let proveCalls = 0
  const handler = createReferenceTransparencyConsistencyHandler({
    prove: async () => {
      proveCalls += 1
      return fixture.proof
    },
    origin: ORIGIN,
    logPublicKeyBytes: fixture.logKeys.publicKey,
  })

  await assert.rejects(
    handler({
      method: 'POST',
      headers: consistencyHeaders(body),
      body,
      now: NOW,
    }),
    /does not match the exact requested tree sizes/i,
  )
  assert.equal(proveCalls, 1)
})

test('HTTPS server routes consistency separately and preserves its protocol on read errors', async (t) => {
  const fixture = consistencyFixture()
  let publicationCalls = 0
  let proveCalls = 0
  const publicationHandler = async () => {
    publicationCalls += 1
    throw new Error('consistency route reached publication')
  }
  const consistencyHandler = createReferenceTransparencyConsistencyHandler({
    prove: async (_document, { now }) => {
      proveCalls += 1
      const firstCheckpoint = createTransparencySignedCheckpoint({
        treeSize: 1,
        rootHash: fixture.firstCheckpoint.checkpoint.root_hash,
        origin: ORIGIN,
        privateKeyBytes: fixture.logKeys.privateKey,
        issuedAt: now,
      })
      const secondCheckpoint = createTransparencySignedCheckpoint({
        treeSize: 2,
        rootHash: fixture.secondCheckpoint.checkpoint.root_hash,
        origin: ORIGIN,
        privateKeyBytes: fixture.logKeys.privateKey,
        issuedAt: now,
      })
      return createTransparencyConsistencyProof({
        firstCheckpoint,
        secondCheckpoint,
        consistencyPath: fixture.proof.consistency_path,
      })
    },
    origin: ORIGIN,
    logPublicKeyBytes: fixture.logKeys.publicKey,
  })
  const service = createReferenceTransparencyHttpsServer({
    handler: publicationHandler,
    consistencyHandler,
    tls: {
      pfx: REFERENCE_TLS_PFX,
      passphrase: REFERENCE_TLS_PASSPHRASE,
    },
    maxRequestBytes: 4096,
  })
  t.after(() => service.stop())
  const address = await service.start()

  const success = await requestLocalHttps({
    port: address.port,
    path: address.consistencyPath,
    body: fixture.body,
    headers: consistencyHeaders(fixture.body),
  })
  assert.equal(success.statusCode, 200)
  assert.equal(
    success.headers['x-rta-protocol'],
    'transparency-log-consistency-v1',
  )
  assert.equal(publicationCalls, 0)
  assert.equal(proveCalls, 1)
  assert.equal(
    JSON.parse(success.body.toString('utf8')).kind,
    'red-team-audit/transparency-consistency-proof',
  )

  const oversizedBody = Buffer.alloc(4097, 0x61)
  const rejected = await requestLocalHttps({
    port: address.port,
    path: address.consistencyPath,
    body: oversizedBody,
    headers: consistencyHeaders(oversizedBody),
  })
  assert.equal(rejected.statusCode, 413)
  assert.equal(
    rejected.headers['x-rta-protocol'],
    'transparency-log-consistency-v1',
  )
  assert.deepEqual(JSON.parse(rejected.body.toString('utf8')), {
    schema_version: '1.0.0',
    protocol: 'transparency-log-consistency-v1',
    error: { code: 'TRANSPARENCY_REQUEST_TOO_LARGE' },
  })
  assert.equal(publicationCalls, 0)
  assert.equal(proveCalls, 1)
})
