import assert from 'node:assert/strict'
import { request as httpRequest } from 'node:http'
import { test } from 'node:test'

const EXTENSION_ID = 'abcdefghijklmnopabcdefghijklmnop'
const EXTENSION_ORIGIN = `chrome-extension://${EXTENSION_ID}`
const TARGET_ORIGIN = 'https://bounty.example.test'
const CAMPAIGN_ID = 'synthetic-browser-campaign-0001'
const DOCUMENT_NONCE = 'synthetic-document-nonce-000000000001'
const CAPABILITY_BYTES = Buffer.alloc(32, 0xa5)
const pairingCodes = new WeakMap()

async function bridgeApi() {
  return import('../scripts/lib/http-authed-browser-bridge.mjs')
}

function createSession(createHttpAuthedBrowserBridgeSession, overrides = {}) {
  let randomCalls = 0
  const session = createHttpAuthedBrowserBridgeSession({
    extensionId: EXTENSION_ID,
    targetOrigin: TARGET_ORIGIN,
    campaignId: CAMPAIGN_ID,
    clock: () => new Date('2026-08-17T10:00:00.000Z'),
    randomBytes: (size) => {
      randomCalls += 1
      assert.equal(size, 32)
      return Buffer.from(CAPABILITY_BYTES)
    },
    ...overrides,
  })
  pairingCodes.set(session, session.takePairingCode())
  return { session, randomCalls: () => randomCalls }
}

function openSession(session, overrides = {}) {
  return session.open({
    origin: EXTENSION_ORIGIN,
    capability: pairingCodes.get(session),
    campaignId: CAMPAIGN_ID,
    tabId: 17,
    documentNonce: DOCUMENT_NONCE,
    ...overrides,
  })
}

function request(overrides = {}) {
  return {
    url: `${TARGET_ORIGIN}/approved/seed?subject=SYNTHETIC_VALUE`,
    method: 'GET',
    headers: { accept: '*/*' },
    body: null,
    timeoutMs: 10_000,
    maxResponseBytes: 65_536,
    tls: { mode: 'BROWSER_MANAGED' },
    ...overrides,
  }
}

test('browser bridge consumes one exact 256-bit pairing capability from its pinned extension', async () => {
  const {
    HttpAuthedBrowserBridgeError,
    createHttpAuthedBrowserBridgeSession,
  } = await bridgeApi()
  const expectedCapability = CAPABILITY_BYTES.toString('base64url')

  for (const attempt of [
    { origin: 'chrome-extension://ponmlkjihgfedcbaponmlkjihgfedcba' },
    { capability: Buffer.alloc(32, 0x5a).toString('base64url') },
    { campaignId: 'different-campaign' },
  ]) {
    const { session } = createSession(createHttpAuthedBrowserBridgeSession)
    assert.equal(pairingCodes.get(session), expectedCapability)
    await assert.rejects(
      Promise.resolve().then(() => openSession(session, attempt)),
      (error) => {
        assert.ok(error instanceof HttpAuthedBrowserBridgeError)
        assert.equal(error.message.includes(expectedCapability), false)
        return true
      },
    )
    assert.equal(session.snapshot().state, 'NEW')
  }

  const created = createSession(createHttpAuthedBrowserBridgeSession)
  assert.equal(created.randomCalls(), 1)
  assert.match(pairingCodes.get(created.session), /^[A-Za-z0-9_-]{43}$/)
  const opened = openSession(created.session)
  assert.equal(created.session.snapshot().state, 'OPEN')
  assert.equal(JSON.stringify(created.session.snapshot()).includes(expectedCapability), false)
  assert.match(opened.session_capability, /^[A-Za-z0-9_-]{43}$/)
  assert.equal(JSON.stringify(created.session.snapshot()).includes(opened.session_capability), false)
  await assert.rejects(
    Promise.resolve().then(() => openSession(created.session)),
    (error) => error instanceof HttpAuthedBrowserBridgeError,
  )
})

test('browser bridge prepares only one exact-origin action and refuses credential headers', async () => {
  const {
    HttpAuthedBrowserBridgeError,
    createHttpAuthedBrowserBridgeSession,
  } = await bridgeApi()

  for (const unsafeRequest of [
    request({ url: 'https://other.example.test/approved/seed' }),
    request({ url: `${TARGET_ORIGIN}/approved/seed#fragment` }),
    request({ method: 'get' }),
    request({ method: 'TRACE' }),
    request({
      body: Buffer.from('x'),
      headers: {
        accept: '*/*',
        'content-type': 'application/octet-stream',
        'content-length': '1',
      },
    }),
    request({ headers: { cookie: 'SYNTHETIC_COOKIE_MUST_NOT_CROSS_BRIDGE' } }),
    request({ headers: { authorization: 'Bearer SYNTHETIC_TOKEN_MUST_NOT_CROSS_BRIDGE' } }),
  ]) {
    const { session } = createSession(createHttpAuthedBrowserBridgeSession)
    openSession(session)
    await assert.rejects(
      Promise.resolve().then(() => session.prepare({
        actionId: 'synthetic-action-0001',
        request: unsafeRequest,
      })),
      (error) => {
        assert.ok(error instanceof HttpAuthedBrowserBridgeError)
        assert.doesNotMatch(
          error.message,
          /SYNTHETIC_COOKIE_MUST_NOT_CROSS_BRIDGE|SYNTHETIC_TOKEN_MUST_NOT_CROSS_BRIDGE/,
        )
        return true
      },
    )
    assert.equal(session.snapshot().state, 'OPEN')
  }

  const { session } = createSession(createHttpAuthedBrowserBridgeSession)
  openSession(session)
  const prepared = session.prepare({
    actionId: 'synthetic-action-0001',
    request: request(),
  })
  assert.equal(session.snapshot().state, 'PREPARE')
  assert.equal(prepared.type, 'PREPARE')
  assert.equal(prepared.request.origin, TARGET_ORIGIN)
  assert.match(prepared.action_sha256, /^[a-f0-9]{64}$/)
  assert.doesNotMatch(JSON.stringify(prepared), /cookie|authorization/i)

  await assert.rejects(
    Promise.resolve().then(() => session.prepare({
      actionId: 'synthetic-action-0002',
      request: request({ url: `${TARGET_ORIGIN}/approved/second` }),
    })),
    (error) => error instanceof HttpAuthedBrowserBridgeError,
  )
  assert.equal(session.snapshot().state, 'PREPARE')
})

test('browser bridge close is safe before commit and conservative after commit', async () => {
  const { createHttpAuthedBrowserBridgeSession } = await bridgeApi()

  const before = createSession(createHttpAuthedBrowserBridgeSession).session
  openSession(before)
  before.prepare({ actionId: 'synthetic-action-before', request: request() })
  before.close('synthetic pre-commit disconnect')
  assert.equal(before.snapshot().request_may_have_been_sent, false)
  assert.equal(before.snapshot().state, 'CLOSED')

  // The READY/COMMIT portion below is intentionally expressed through the
  // protocol envelopes returned by the implementation: tests mutate only one
  // bound field at a time and never synthesize browser credentials.
  const after = createSession(createHttpAuthedBrowserBridgeSession).session
  openSession(after)
  const prepared = after.prepare({
    actionId: 'synthetic-action-after',
    request: request(),
  })
  const ready = {
    protocol: prepared.protocol,
    schema_version: prepared.schema_version,
    type: 'READY',
    campaign_id: prepared.campaign_id,
    action_id: prepared.action_id,
    action_nonce: prepared.action_nonce,
    action_sha256: prepared.action_sha256,
    document_nonce: prepared.document_nonce,
  }
  after.acceptReady(ready)
  let beforeSendCalls = 0
  const committed = await after.commit({
    beforeSend: async () => { beforeSendCalls += 1 },
  })
  assert.equal(beforeSendCalls, 1)
  assert.equal(committed.type, 'COMMIT')
  assert.equal(after.snapshot().state, 'COMMIT')
  after.close('synthetic post-commit disconnect')
  assert.equal(after.snapshot().request_may_have_been_sent, true)
})

test('browser bridge refuses READY binding drift before durable pre-send authorization', async () => {
  const {
    HttpAuthedBrowserBridgeError,
    createHttpAuthedBrowserBridgeSession,
  } = await bridgeApi()
  const { session } = createSession(createHttpAuthedBrowserBridgeSession)
  openSession(session)
  const prepared = session.prepare({ actionId: 'synthetic-action-0001', request: request() })
  let beforeSendCalls = 0

  const ready = {
    protocol: prepared.protocol,
    schema_version: prepared.schema_version,
    type: 'READY',
    campaign_id: prepared.campaign_id,
    action_id: prepared.action_id,
    action_nonce: prepared.action_nonce,
    action_sha256: 'b'.repeat(64),
    document_nonce: prepared.document_nonce,
  }
  await assert.rejects(
    Promise.resolve().then(() => session.acceptReady(ready)),
    (error) => error instanceof HttpAuthedBrowserBridgeError,
  )
  await assert.rejects(
    session.commit({ beforeSend: async () => { beforeSendCalls += 1 } }),
    (error) => error instanceof HttpAuthedBrowserBridgeError,
  )
  assert.equal(beforeSendCalls, 0)
  assert.equal(session.snapshot().state, 'PREPARE')
})

test('browser bridge validates transient RESULT metadata and scrubs response values', async () => {
  const {
    HttpAuthedBrowserBridgeError,
    createHttpAuthedBrowserBridgeSession,
  } = await bridgeApi()
  const headerSecret = 'SYNTHETIC_BROWSER_HEADER_VALUE'
  const bodySecret = Buffer.from('SYNTHETIC_BROWSER_RESPONSE_BODY')
  let observed
  const { session } = createSession(createHttpAuthedBrowserBridgeSession)
  openSession(session)
  const prepared = session.prepare({
    actionId: 'synthetic-action-result',
    request: request({
      responseObserver: async (value) => { observed = value },
    }),
  })
  const bound = {
    protocol: prepared.protocol,
    schema_version: prepared.schema_version,
    campaign_id: prepared.campaign_id,
    action_id: prepared.action_id,
    action_nonce: prepared.action_nonce,
    action_sha256: prepared.action_sha256,
    document_nonce: prepared.document_nonce,
  }
  session.acceptReady({ ...bound, type: 'READY' })
  await session.commit({ beforeSend: async () => {} })

  const validResult = {
    ...bound,
    type: 'RESULT',
    outcome: 'RESPONSE',
    response: {
      status: 200,
      response_bytes: bodySecret.length,
      response_header_names: ['content-type', 'set-cookie'],
      headers: [
        { name: 'content-type', value_base64: Buffer.from('application/json').toString('base64') },
        { name: 'x-synthetic-secret', value_base64: Buffer.from(headerSecret).toString('base64') },
      ],
      body_base64: bodySecret.toString('base64'),
    },
  }

  for (const invalid of [
    { ...validResult, action_sha256: 'c'.repeat(64) },
    {
      ...validResult,
      response: {
        ...validResult.response,
        response_bytes: request().maxResponseBytes + 1,
      },
    },
    { ...validResult, unexpected: true },
  ]) {
    await assert.rejects(
      session.acceptResult(invalid),
      (error) => error instanceof HttpAuthedBrowserBridgeError,
    )
    assert.equal(session.snapshot().state, 'COMMIT')
  }

  const result = await session.acceptResult(validResult)
  assert.deepEqual(result, {
    status: 200,
    responseBytes: bodySecret.length,
    responseHeaderNames: ['content-type', 'set-cookie'],
  })
  assert.equal(session.snapshot().state, 'OPEN')
  assert.equal(JSON.stringify(result).includes(headerSecret), false)
  assert.equal(JSON.stringify(result).includes(bodySecret.toString()), false)
  assert.deepEqual(observed.headers, [
    { name: 'content-type', value: 'application/json' },
    { name: 'x-synthetic-secret', value: headerSecret },
  ])
  assert.deepEqual(Buffer.concat(observed.bodyChunks), bodySecret)
})

test('loopback bridge rotates one-use pairing into a continuous session transport', async (t) => {
  const {
    HTTP_AUTHED_BROWSER_BRIDGE_PAIRING_HEADER,
    HTTP_AUTHED_BROWSER_BRIDGE_SESSION_HEADER,
    createHttpAuthedBrowserBridgeServer,
  } = await bridgeApi()
  const campaignGrantSha256 = 'a'.repeat(64)
  const bridge = await createHttpAuthedBrowserBridgeServer({
    extensionId: EXTENSION_ID,
    targetOrigin: TARGET_ORIGIN,
    campaignGrantSha256,
    timeoutMs: 5_000,
  })
  t.after(() => bridge.close())
  const pairing = bridge.pairing
  assert.equal(bridge.pairing, undefined)
  assert.equal(pairing.campaign_grant_sha256, campaignGrantSha256)
  assert.equal(pairing.target_origin, TARGET_ORIGIN)

  const commonHeaders = { origin: EXTENSION_ORIGIN }
  const mismatchedHostStatus = await new Promise((resolve, reject) => {
    const pending = httpRequest(`${pairing.bridge_origin}/v1/preview`, {
      headers: {
        host: `localhost:${new URL(pairing.bridge_origin).port}`,
        origin: EXTENSION_ORIGIN,
        [HTTP_AUTHED_BROWSER_BRIDGE_PAIRING_HEADER]: pairing.pairing_code,
      },
    }, (response) => {
      response.resume()
      response.once('end', () => resolve(response.statusCode))
    })
    pending.once('error', reject)
    pending.end()
  })
  assert.equal(mismatchedHostStatus, 403)
  const previewResponse = await fetch(`${pairing.bridge_origin}/v1/preview`, {
    headers: {
      ...commonHeaders,
      [HTTP_AUTHED_BROWSER_BRIDGE_PAIRING_HEADER]: pairing.pairing_code,
    },
  })
  assert.equal(previewResponse.status, 200)
  assert.equal(previewResponse.headers.get('cache-control'), 'no-store, max-age=0')
  const preview = await previewResponse.json()
  assert.equal(preview.target_origin, TARGET_ORIGIN)
  assert.equal(preview.campaign_grant_sha256, campaignGrantSha256)

  const attach = bridge.waitForAttach()
  const openResponse = await fetch(`${pairing.bridge_origin}/v1/open`, {
    method: 'POST',
    headers: {
      ...commonHeaders,
      'content-type': 'application/json',
      [HTTP_AUTHED_BROWSER_BRIDGE_PAIRING_HEADER]: pairing.pairing_code,
    },
    body: JSON.stringify({
      protocol: preview.protocol,
      schema_version: preview.schema_version,
      type: 'OPEN',
      campaign_id: campaignGrantSha256,
      target_origin: TARGET_ORIGIN,
      tab_id: 17,
      document_nonce: DOCUMENT_NONCE,
    }),
  })
  assert.equal(openResponse.status, 200)
  const opened = await openResponse.json()
  assert.match(opened.session_capability, /^[A-Za-z0-9_-]{43}$/)
  await attach

  let beforeSendCalls = 0
  const transportResult = bridge.transport({
    ...request({ tls: { mode: 'PKIX_HOSTNAME' } }),
    beforeSend: async () => { beforeSendCalls += 1 },
  })
  const authenticatedHeaders = {
    ...commonHeaders,
    [HTTP_AUTHED_BROWSER_BRIDGE_SESSION_HEADER]: opened.session_capability,
  }
  const preparePreflight = await fetch(`${pairing.bridge_origin}/v1/prepare`, {
    method: 'OPTIONS',
    headers: {
      ...commonHeaders,
      'access-control-request-method': 'POST',
      'access-control-request-headers': HTTP_AUTHED_BROWSER_BRIDGE_SESSION_HEADER,
    },
  })
  assert.equal(preparePreflight.status, 204)
  const refusedPrepare = await fetch(`${pairing.bridge_origin}/v1/prepare`, {
    headers: authenticatedHeaders,
  })
  assert.equal(refusedPrepare.status, 405)
  const prepareResponse = await fetch(`${pairing.bridge_origin}/v1/prepare`, {
    method: 'POST',
    headers: authenticatedHeaders,
  })
  assert.equal(prepareResponse.status, 200)
  const prepared = await prepareResponse.json()
  const bound = {
    protocol: prepared.protocol,
    schema_version: prepared.schema_version,
    campaign_id: prepared.campaign_id,
    action_id: prepared.action_id,
    action_nonce: prepared.action_nonce,
    action_sha256: prepared.action_sha256,
    document_nonce: prepared.document_nonce,
  }

  const readyResponse = await fetch(`${pairing.bridge_origin}/v1/ready`, {
    method: 'POST',
    headers: { ...authenticatedHeaders, 'content-type': 'application/json' },
    body: JSON.stringify({ ...bound, type: 'READY' }),
  })
  assert.equal(readyResponse.status, 200)
  assert.equal((await readyResponse.json()).type, 'COMMIT')
  assert.equal(beforeSendCalls, 1)

  const resultResponse = await fetch(`${pairing.bridge_origin}/v1/result`, {
    method: 'POST',
    headers: { ...authenticatedHeaders, 'content-type': 'application/json' },
    body: JSON.stringify({
      ...bound,
      type: 'RESULT',
      outcome: 'RESPONSE',
      response: {
        status: 204,
        response_bytes: 0,
        response_header_names: [],
        headers: [],
        body_base64: null,
      },
    }),
  })
  assert.equal(resultResponse.status, 200)
  assert.deepEqual(await transportResult, {
    status: 204,
    responseBytes: 0,
    responseHeaderNames: [],
  })
})

test('closing during transient result observation cannot resurrect the session', async () => {
  const {
    HttpAuthedBrowserBridgeError,
    createHttpAuthedBrowserBridgeSession,
  } = await bridgeApi()
  let observerStarted
  let releaseObserver
  const started = new Promise((resolve) => { observerStarted = resolve })
  const release = new Promise((resolve) => { releaseObserver = resolve })
  const { session } = createSession(createHttpAuthedBrowserBridgeSession)
  openSession(session)
  const prepared = session.prepare({
    actionId: 'synthetic-action-close-race',
    request: request({
      responseObserver: async () => {
        observerStarted()
        await release
      },
    }),
  })
  const bound = {
    protocol: prepared.protocol,
    schema_version: prepared.schema_version,
    campaign_id: prepared.campaign_id,
    action_id: prepared.action_id,
    action_nonce: prepared.action_nonce,
    action_sha256: prepared.action_sha256,
    document_nonce: prepared.document_nonce,
  }
  session.acceptReady({ ...bound, type: 'READY' })
  await session.commit({ beforeSend: async () => {} })
  const result = session.acceptResult({
    ...bound,
    type: 'RESULT',
    outcome: 'RESPONSE',
    response: {
      status: 200,
      response_bytes: 1,
      response_header_names: [],
      headers: [],
      body_base64: Buffer.from('x').toString('base64'),
    },
  })
  await started
  session.close('synthetic concurrent close')
  releaseObserver()
  await assert.rejects(
    result,
    (error) => error instanceof HttpAuthedBrowserBridgeError
      && error.code === 'HTTP_AUTHED_BROWSER_BRIDGE_RESULT_CANCELLED',
  )
  assert.equal(session.snapshot().state, 'CLOSED')
  assert.equal(session.snapshot().request_may_have_been_sent, true)
})
