import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { request as httpRequest } from 'node:http'
import { test } from 'node:test'

import { discoverHttpAuthedCandidates } from '../scripts/lib/http-authed-discovery.mjs'
import { pageSessionAdapterSha256 } from '../scripts/lib/page-session-adapter.mjs'

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

function pageSessionAdapter() {
  return {
    schema_version: '1.0.0',
    kind: 'last-aperture/page-session-adapter',
    adapter_id: 'synthetic-page-session',
    source: {
      type: 'WEB_STORAGE',
      area: 'LOCAL',
      key: 'application.session',
      extraction: { mode: 'RAW' },
    },
    carrier: { type: 'REQUEST_HEADER', name: 'authorization', prefix: 'Bearer ' },
    target_constraints: [{
      origin: TARGET_ORIGIN,
      method: 'GET',
      path_prefix: '/approved',
    }],
    validity: {
      not_before: '2026-01-01T00:00:00.000Z',
      not_after: '2027-01-01T00:00:00.000Z',
    },
    limits: { max_value_bytes: 4096 },
  }
}

function loopbackRequest(url, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const pending = httpRequest(url, { method, headers, agent: false }, (response) => {
      const chunks = []
      response.on('data', (chunk) => chunks.push(Buffer.from(chunk)))
      response.once('error', reject)
      response.once('end', () => {
        const payload = Buffer.concat(chunks)
        resolve({
          status: response.statusCode,
          headers: {
            get(name) {
              const value = response.headers[String(name).toLowerCase()]
              return Array.isArray(value) ? value.join(', ') : value ?? null
            },
          },
          async json() { return JSON.parse(payload.toString('utf8')) },
          async arrayBuffer() { return Buffer.from(payload) },
        })
      })
    })
    pending.once('error', reject)
    if (body !== undefined && body !== null) pending.write(body)
    pending.end()
  })
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

test('browser bridge binds a declarative page session adapter into every action message', async () => {
  const {
    HttpAuthedBrowserBridgeError,
    createHttpAuthedBrowserBridgeSession,
  } = await bridgeApi()
  const adapter = pageSessionAdapter()
  const adapterSha256 = pageSessionAdapterSha256(adapter)
  const { session } = createSession(createHttpAuthedBrowserBridgeSession, {
    pageSessionAdapter: adapter,
  })
  openSession(session)
  const prepared = session.prepare({
    actionId: 'synthetic-adapter-action',
    request: request(),
  })
  assert.deepEqual(prepared.session_adapter, adapter)
  assert.equal(prepared.session_adapter_sha256, adapterSha256)
  assert.doesNotMatch(JSON.stringify(prepared), /SYNTHETIC_PAGE_TOKEN/)

  const ready = {
    protocol: prepared.protocol,
    schema_version: prepared.schema_version,
    type: 'READY',
    campaign_id: prepared.campaign_id,
    action_id: prepared.action_id,
    action_nonce: prepared.action_nonce,
    action_sha256: prepared.action_sha256,
    document_nonce: prepared.document_nonce,
    session_adapter_sha256: adapterSha256,
  }
  assert.equal(session.acceptReady(ready).session_adapter_sha256, adapterSha256)
  const committed = await session.commit({ beforeSend: async () => {} })
  assert.equal(committed.session_adapter_sha256, adapterSha256)
  session.close()

  const refused = createSession(createHttpAuthedBrowserBridgeSession, {
    pageSessionAdapter: adapter,
  }).session
  openSession(refused)
  assert.throws(
    () => refused.prepare({
      actionId: 'synthetic-outside-adapter',
      request: request({ url: `${TARGET_ORIGIN}/outside` }),
    }),
    (error) => error instanceof HttpAuthedBrowserBridgeError
      && error.code === 'HTTP_AUTHED_BROWSER_BRIDGE_SESSION_ADAPTER_REFUSED',
  )
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
  const headerSecret = '</approved/discovered>; rel="next"'
  const bodySecret = Buffer.from('SYNTHETIC_BROWSER_RESPONSE_BODY')
  let observed
  let discovery
  const { session } = createSession(createHttpAuthedBrowserBridgeSession)
  openSession(session)
  const prepared = session.prepare({
    actionId: 'synthetic-action-result',
    request: request({
      responseObserver: async (value) => {
        observed = value
        discovery = discoverHttpAuthedCandidates({
          policy: {
            enabled: true,
            origin: TARGET_ORIGIN,
            path_prefixes: ['/approved'],
            sources: ['link_header'],
            candidate_methods: ['GET'],
            test_category: 'authz_horizontal',
            synthetic_query_values: { subject: 'SYNTHETIC_VALUE' },
            synthetic_path_values: {},
            max_response_bytes: 65_536,
            max_candidates: 4,
            max_depth: 4,
          },
          sourceAction: {
            url: `${TARGET_ORIGIN}/approved/seed?subject=SYNTHETIC_VALUE`,
            method: 'GET',
            test_category: 'authz_horizontal',
          },
          headers: value.headers,
          bodyChunks: value.bodyChunks,
        })
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

  const validResult = {
    ...bound,
    type: 'RESULT',
    outcome: 'OBSERVED',
    response_truncated: false,
    response: {
      status: 200,
      response_bytes: bodySecret.length,
      response_header_names: ['content-type', 'link', 'set-cookie'],
      headers: [
        { name: 'content-type', value_base64: Buffer.from('application/json').toString('base64') },
        { name: 'link', value_base64: Buffer.from(headerSecret).toString('base64') },
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
    {
      ...validResult,
      response: {
        ...validResult.response,
        headers: [
          { name: 'x-synthetic-secret', value_base64: Buffer.from(headerSecret).toString('base64') },
        ],
      },
    },
    {
      ...validResult,
      response: {
        ...validResult.response,
        headers: [{
          name: 'location',
          value_base64: Buffer.from('/approved/other').toString('base64'),
        }],
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
    responseHeaderNames: ['content-type', 'link', 'set-cookie'],
  })
  assert.equal(session.snapshot().state, 'OPEN')
  assert.equal(JSON.stringify(result).includes(headerSecret), false)
  assert.equal(JSON.stringify(result).includes(bodySecret.toString()), false)
  assert.deepEqual(observed.headers, [
    { name: 'content-type', value: 'application/json' },
    { name: 'link', value: headerSecret },
  ])
  assert.deepEqual(Buffer.concat(observed.bodyChunks), bodySecret)
  assert.deepEqual(discovery.candidates, [{
    kind: 'probe',
    test_category: 'authz_horizontal',
    method: 'GET',
    url: `${TARGET_ORIGIN}/approved/discovered`,
    expected_effect: 'none',
  }])
})

test('browser bridge rejects bounded or incomplete observations without invoking discovery', async () => {
  const {
    HttpAuthedBrowserBridgeError,
    createHttpAuthedBrowserBridgeSession,
  } = await bridgeApi()

  for (const scenario of [
    {
      outcome: 'RESPONSE_BOUNDED',
      response_truncated: true,
      code: 'HTTP_AUTHED_BROWSER_BRIDGE_RESPONSE_BOUNDED',
    },
    {
      outcome: 'OBSERVATION_INCOMPLETE',
      response_truncated: false,
      code: 'HTTP_AUTHED_BROWSER_BRIDGE_OBSERVATION_INCOMPLETE',
    },
  ]) {
    let observerCalls = 0
    const { session } = createSession(createHttpAuthedBrowserBridgeSession)
    openSession(session)
    const prepared = session.prepare({
      actionId: `synthetic-action-${scenario.outcome.toLowerCase()}`,
      request: request({
        responseObserver: async () => { observerCalls += 1 },
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
    await assert.rejects(
      session.acceptResult({
        ...bound,
        type: 'RESULT',
        outcome: scenario.outcome,
        response_truncated: scenario.response_truncated,
        response: {
          status: 200,
          response_bytes: 3,
          response_header_names: ['content-type'],
          headers: [{
            name: 'content-type',
            value_base64: Buffer.from('application/json').toString('base64'),
          }],
          body_base64: Buffer.from('abc').toString('base64'),
        },
      }),
      (error) => error instanceof HttpAuthedBrowserBridgeError
        && error.code === scenario.code
        && error.request_may_have_been_sent === true,
    )
    assert.equal(observerCalls, 0)
    assert.equal(session.snapshot().state, 'FAILED')
    assert.equal(session.snapshot().request_may_have_been_sent, true)
    session.close('synthetic partial observation')
    assert.equal(session.snapshot().state, 'CLOSED')
    assert.equal(session.snapshot().request_may_have_been_sent, true)
  }
})

test('a transport timeout after COMMIT closes the session instead of permitting another action', async () => {
  const {
    HttpAuthedBrowserBridgeError,
    createHttpAuthedBrowserBridgeSession,
    createHttpAuthedBrowserBridgeTransport,
  } = await bridgeApi()
  const timers = []
  const { session } = createSession(createHttpAuthedBrowserBridgeSession, {
    setTimer(callback) {
      timers.push(callback)
      return callback
    },
    clearTimer() {},
  })
  openSession(session)
  const transport = createHttpAuthedBrowserBridgeTransport({ session })
  const pending = transport({
    ...request(),
    beforeSend: async () => {},
  })
  void pending.catch(() => {})
  const prepared = session.takePrepared()
  session.acceptReady({
    protocol: prepared.protocol,
    schema_version: prepared.schema_version,
    type: 'READY',
    campaign_id: prepared.campaign_id,
    action_id: prepared.action_id,
    action_nonce: prepared.action_nonce,
    action_sha256: prepared.action_sha256,
    document_nonce: prepared.document_nonce,
  })
  await session.commit()
  timers[0]()
  await assert.rejects(
    pending,
    (error) => error instanceof HttpAuthedBrowserBridgeError
      && error.code === 'HTTP_AUTHED_BROWSER_BRIDGE_TIMEOUT'
      && error.request_may_have_been_sent === true,
  )
  assert.equal(session.snapshot().state, 'CLOSED')
  assert.equal(session.snapshot().request_may_have_been_sent, true)
})

test('a browser transport timer setup failure erases its prepared request body and restores the session', async (t) => {
  const {
    HttpAuthedBrowserBridgeError,
    createHttpAuthedBrowserBridgeSession,
    createHttpAuthedBrowserBridgeTransport,
  } = await bridgeApi()
  const supplied = Buffer.from('synthetic-browser-timer-body')
  const copies = []
  const originalFrom = Buffer.from
  t.mock.method(Buffer, 'from', function (value, ...args) {
    const copy = originalFrom.call(Buffer, value, ...args)
    if (value === supplied) copies.push(copy)
    return copy
  })
  const { session } = createSession(createHttpAuthedBrowserBridgeSession, {
    setTimer() { throw new Error('synthetic browser timer setup failure') },
  })
  openSession(session)
  const transport = createHttpAuthedBrowserBridgeTransport({ session })

  await assert.rejects(
    transport({
      ...request(),
      method: 'POST',
      headers: {
        'content-length': String(supplied.length),
        'content-type': 'application/octet-stream',
      },
      body: supplied,
      beforeSend: async () => {},
    }),
    (error) => error instanceof HttpAuthedBrowserBridgeError
      && error.code === 'HTTP_AUTHED_BROWSER_BRIDGE_TIMER_FAILED'
      && error.request_may_have_been_sent === false,
  )
  assert.equal(copies.length, 1)
  assert.equal(copies[0].every((byte) => byte === 0), true)
  assert.equal(session.snapshot().state, 'OPEN')
  assert.equal(session.snapshot().in_flight, null)
})

test('a browser timer cleanup failure cannot strand request or session secret bytes', async (t) => {
  const {
    HttpAuthedBrowserBridgeError,
    createHttpAuthedBrowserBridgeSession,
    createHttpAuthedBrowserBridgeTransport,
  } = await bridgeApi()
  const pairingSource = Buffer.alloc(32, 0x31)
  const sessionSource = Buffer.alloc(32, 0x32)
  const suppliedBody = Buffer.from('synthetic-browser-clear-timer-body')
  const requestCopies = []
  const sessionSecretCopies = []
  const originalFrom = Buffer.from
  t.mock.method(Buffer, 'from', function (value, ...args) {
    const copy = originalFrom.call(Buffer, value, ...args)
    if (value === suppliedBody) requestCopies.push(copy)
    if (value === sessionSource) sessionSecretCopies.push(copy)
    return copy
  })
  let randomCalls = 0
  const { session } = createSession(createHttpAuthedBrowserBridgeSession, {
    randomBytes(size) {
      assert.equal(size, 32)
      randomCalls += 1
      return randomCalls === 1 ? pairingSource : sessionSource
    },
    setTimer(callback) { return callback },
    clearTimer() { throw new Error('synthetic browser timer cleanup failure') },
  })
  openSession(session)
  const transport = createHttpAuthedBrowserBridgeTransport({ session })
  const pending = transport({
    ...request(),
    method: 'POST',
    headers: {
      'content-length': String(suppliedBody.length),
      'content-type': 'application/octet-stream',
    },
    body: suppliedBody,
    beforeSend: async () => {},
  })
  void pending.catch(() => {})

  assert.deepEqual(session.close('synthetic timer cleanup failure'), {
    state: 'CLOSED',
    request_may_have_been_sent: false,
  })
  await assert.rejects(
    pending,
    (error) => error instanceof HttpAuthedBrowserBridgeError
      && error.code === 'HTTP_AUTHED_BROWSER_BRIDGE_CLOSED'
      && error.request_may_have_been_sent === false,
  )
  assert.equal(requestCopies.length, 1)
  assert.equal(requestCopies[0].every((byte) => byte === 0), true)
  assert.equal(sessionSecretCopies.length, 2)
  assert.equal(sessionSecretCopies.every((copy) => copy.every((byte) => byte === 0)), true)
  assert.equal(session.snapshot().state, 'CLOSED')
  assert.equal(session.snapshot().in_flight, null)
})

test('an uncleared stale timer cannot cancel a later action that reuses an external action id', async () => {
  const {
    HttpAuthedBrowserBridgeError,
    createHttpAuthedBrowserBridgeSession,
    createHttpAuthedBrowserBridgeTransport,
  } = await bridgeApi()
  const timerCallbacks = []
  const { session } = createSession(createHttpAuthedBrowserBridgeSession, {
    setTimer(callback) {
      timerCallbacks.push(callback)
      return callback
    },
    clearTimer() { throw new Error('synthetic stale timer cleanup failure') },
  })
  openSession(session)
  const transport = createHttpAuthedBrowserBridgeTransport({
    session,
    actionIdFactory: () => 'synthetic-reused-external-action',
  })
  const firstPending = transport({ ...request(), beforeSend: async () => {} })
  const firstPrepared = session.takePrepared()
  const firstBound = {
    protocol: firstPrepared.protocol,
    schema_version: firstPrepared.schema_version,
    campaign_id: firstPrepared.campaign_id,
    action_id: firstPrepared.action_id,
    action_nonce: firstPrepared.action_nonce,
    action_sha256: firstPrepared.action_sha256,
    document_nonce: firstPrepared.document_nonce,
  }
  session.acceptReady({ ...firstBound, type: 'READY' })
  await session.commit({ beforeSend: async () => {} })
  await session.acceptResult({
    ...firstBound,
    type: 'RESULT',
    outcome: 'OBSERVED',
    response_truncated: false,
    response: {
      status: 204,
      response_bytes: 0,
      response_header_names: [],
      headers: [],
      body_base64: null,
    },
  })
  await firstPending

  const secondPending = transport({ ...request(), beforeSend: async () => {} })
  void secondPending.catch(() => {})
  assert.equal(session.snapshot().state, 'PREPARE')
  timerCallbacks[0]()
  assert.equal(session.snapshot().state, 'PREPARE')
  session.close('synthetic stale timer regression cleanup')
  await assert.rejects(
    secondPending,
    (error) => error instanceof HttpAuthedBrowserBridgeError
      && error.code === 'HTTP_AUTHED_BROWSER_BRIDGE_CLOSED',
  )
})

test('loopback bridge attach timer setup failure resets the waiter for retry', async (t) => {
  const {
    createHttpAuthedBrowserBridgeServer,
  } = await bridgeApi()
  let timerCalls = 0
  const bridge = await createHttpAuthedBrowserBridgeServer({
    extensionId: EXTENSION_ID,
    targetOrigin: TARGET_ORIGIN,
    campaignGrantSha256: 'a'.repeat(64),
    setTimer() {
      timerCalls += 1
      throw new Error('synthetic attach timer setup failure')
    },
    clearTimer() {},
  })
  t.after(() => bridge.close())

  for (let attempt = 0; attempt < 2; attempt += 1) {
    await assert.rejects(
      bridge.waitForAttach(),
      { code: 'HTTP_AUTHED_BROWSER_BRIDGE_ATTACH_TIMER_FAILED' },
    )
  }
  assert.equal(timerCalls, 2)
})

test('loopback bridge close settles its attach waiter when timer cleanup throws', async () => {
  const {
    createHttpAuthedBrowserBridgeServer,
  } = await bridgeApi()
  let clearTimerCalls = 0
  const bridge = await createHttpAuthedBrowserBridgeServer({
    extensionId: EXTENSION_ID,
    targetOrigin: TARGET_ORIGIN,
    campaignGrantSha256: 'a'.repeat(64),
    setTimer: () => 71,
    clearTimer() {
      clearTimerCalls += 1
      throw new Error('synthetic attach timer cleanup failure')
    },
  })
  const attached = bridge.waitForAttach()
  void attached.catch(() => {})

  await bridge.close()
  await assert.rejects(
    attached,
    { code: 'HTTP_AUTHED_BROWSER_BRIDGE_CLOSED' },
  )
  await bridge.close()
  assert.equal(clearTimerCalls, 1)
})

test('loopback bridge attach succeeds when timer cleanup throws', async (t) => {
  const {
    HTTP_AUTHED_BROWSER_BRIDGE_EXTENSION_HEADER,
    HTTP_AUTHED_BROWSER_BRIDGE_PAIRING_HEADER,
    createHttpAuthedBrowserBridgeServer,
  } = await bridgeApi()
  const campaignGrantSha256 = 'a'.repeat(64)
  let clearTimerCalls = 0
  const bridge = await createHttpAuthedBrowserBridgeServer({
    extensionId: EXTENSION_ID,
    targetOrigin: TARGET_ORIGIN,
    campaignGrantSha256,
    setTimer: () => 72,
    clearTimer() {
      clearTimerCalls += 1
      throw new Error('synthetic attach timer cleanup failure')
    },
  })
  t.after(() => bridge.close())
  const pairing = bridge.pairing
  const attached = bridge.waitForAttach()
  const opened = await loopbackRequest(`${pairing.bridge_origin}/v1/open`, {
    method: 'POST',
    headers: {
      origin: EXTENSION_ORIGIN,
      'content-type': 'application/json',
      [HTTP_AUTHED_BROWSER_BRIDGE_EXTENSION_HEADER]: EXTENSION_ID,
      [HTTP_AUTHED_BROWSER_BRIDGE_PAIRING_HEADER]: pairing.pairing_code,
    },
    body: JSON.stringify({
      protocol: 'red-team-audit/http-authed-browser-bridge',
      schema_version: '1.0.0',
      type: 'OPEN',
      campaign_id: campaignGrantSha256,
      target_origin: TARGET_ORIGIN,
      tab_id: 17,
      document_nonce: DOCUMENT_NONCE,
    }),
  })

  assert.equal(opened.status, 200)
  assert.deepEqual(await attached, {
    extension_id: EXTENSION_ID,
    target_origin: TARGET_ORIGIN,
    campaign_grant_sha256: campaignGrantSha256,
  })
  assert.equal(clearTimerCalls, 1)
})

test('loopback response finish cleanup tolerates a body detached by response.end', async (t) => {
  const {
    HTTP_AUTHED_BROWSER_BRIDGE_EXTENSION_HEADER,
    HTTP_AUTHED_BROWSER_BRIDGE_PAIRING_HEADER,
    createHttpAuthedBrowserBridgeServer,
  } = await bridgeApi()
  const originalFrom = Buffer.from
  t.mock.method(Buffer, 'from', function (value, ...args) {
    const ordinary = originalFrom.call(Buffer, value, ...args)
    if (typeof value !== 'string' || !value.includes('"type":"PREVIEW"')) return ordinary
    const isolated = Buffer.allocUnsafeSlow(ordinary.length)
    ordinary.copy(isolated)
    return isolated
  })
  let requestListener
  const server = new EventEmitter()
  server.listen = () => queueMicrotask(() => server.emit('listening'))
  server.address = () => ({ address: '127.0.0.1', port: 4712, family: 'IPv4' })
  server.close = (callback) => queueMicrotask(() => callback?.())
  server.closeAllConnections = () => {}
  const bridge = await createHttpAuthedBrowserBridgeServer({
    extensionId: EXTENSION_ID,
    targetOrigin: TARGET_ORIGIN,
    campaignGrantSha256: 'a'.repeat(64),
    port: 4712,
    serverFactory(listener) {
      requestListener = listener
      return server
    },
  })
  t.after(() => bridge.close())
  const pairing = bridge.pairing
  const response = new EventEmitter()
  response.headersSent = false
  response.setHeader = () => {}
  response.destroy = () => { response.destroyed = true }
  let handedOffBody
  response.end = (body) => {
    handedOffBody = body
    response.headersSent = true
    structuredClone(body, { transfer: [body.buffer] })
  }
  await requestListener({
    url: '/v1/preview',
    method: 'GET',
    headers: {
      host: '127.0.0.1:4712',
      origin: EXTENSION_ORIGIN,
      [HTTP_AUTHED_BROWSER_BRIDGE_EXTENSION_HEADER]: EXTENSION_ID,
      [HTTP_AUTHED_BROWSER_BRIDGE_PAIRING_HEADER]: pairing.pairing_code,
    },
  }, response)

  assert.equal(response.statusCode, 200)
  assert.equal(handedOffBody.byteLength, 0)
  assert.doesNotThrow(() => response.emit('finish'))
  assert.doesNotThrow(() => response.emit('close'))
})

test('loopback bridge rotates one-use pairing into a continuous session transport', async (t) => {
  const {
    HTTP_AUTHED_BROWSER_BRIDGE_EXTENSION_HEADER,
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

  const commonHeaders = {
    origin: EXTENSION_ORIGIN,
    [HTTP_AUTHED_BROWSER_BRIDGE_EXTENSION_HEADER]: EXTENSION_ID,
  }
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
  const unboundOriginlessResponse = await loopbackRequest(`${pairing.bridge_origin}/v1/preview`, {
    headers: {
      [HTTP_AUTHED_BROWSER_BRIDGE_EXTENSION_HEADER]: EXTENSION_ID,
      [HTTP_AUTHED_BROWSER_BRIDGE_PAIRING_HEADER]: pairing.pairing_code,
    },
  })
  assert.equal(unboundOriginlessResponse.status, 403)
  await unboundOriginlessResponse.arrayBuffer()
  const chromeExtensionResponse = await loopbackRequest(`${pairing.bridge_origin}/v1/preview`, {
    headers: {
      [HTTP_AUTHED_BROWSER_BRIDGE_EXTENSION_HEADER]: EXTENSION_ID,
      [HTTP_AUTHED_BROWSER_BRIDGE_PAIRING_HEADER]: pairing.pairing_code,
      'sec-fetch-site': 'none',
      'sec-fetch-mode': 'cors',
      'sec-fetch-dest': 'empty',
    },
  })
  assert.equal(chromeExtensionResponse.status, 200)
  await chromeExtensionResponse.arrayBuffer()
  const previewResponse = await loopbackRequest(`${pairing.bridge_origin}/v1/preview`, {
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
  const openResponse = await loopbackRequest(`${pairing.bridge_origin}/v1/open`, {
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
  const preparePreflight = await loopbackRequest(`${pairing.bridge_origin}/v1/prepare`, {
    method: 'OPTIONS',
    headers: {
      ...commonHeaders,
      'access-control-request-method': 'POST',
      'access-control-request-headers': HTTP_AUTHED_BROWSER_BRIDGE_SESSION_HEADER,
    },
  })
  assert.equal(preparePreflight.status, 204)
  const refusedPrepare = await loopbackRequest(`${pairing.bridge_origin}/v1/prepare`, {
    headers: authenticatedHeaders,
  })
  assert.equal(refusedPrepare.status, 405)
  await refusedPrepare.arrayBuffer()
  const prepareResponse = await loopbackRequest(`${pairing.bridge_origin}/v1/prepare`, {
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

  const readyResponse = await loopbackRequest(`${pairing.bridge_origin}/v1/ready`, {
    method: 'POST',
    headers: { ...authenticatedHeaders, 'content-type': 'application/json' },
    body: JSON.stringify({ ...bound, type: 'READY' }),
  })
  assert.equal(readyResponse.status, 200)
  assert.equal((await readyResponse.json()).type, 'COMMIT')
  assert.equal(beforeSendCalls, 1)

  const resultResponse = await loopbackRequest(`${pairing.bridge_origin}/v1/result`, {
    method: 'POST',
    headers: { ...authenticatedHeaders, 'content-type': 'application/json' },
    body: JSON.stringify({
      ...bound,
      type: 'RESULT',
      outcome: 'OBSERVED',
      response_truncated: false,
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
  await resultResponse.arrayBuffer()
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
  let retainedObserverChunk
  const started = new Promise((resolve) => { observerStarted = resolve })
  const release = new Promise((resolve) => { releaseObserver = resolve })
  const { session } = createSession(createHttpAuthedBrowserBridgeSession)
  openSession(session)
  const prepared = session.prepare({
    actionId: 'synthetic-action-close-race',
    request: request({
      responseObserver: async ({ bodyChunks }) => {
        retainedObserverChunk = bodyChunks.shift()
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
    outcome: 'OBSERVED',
    response_truncated: false,
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
  assert.equal(retainedObserverChunk.every((byte) => byte === 0), true)
  releaseObserver()
  await assert.rejects(
    result,
    (error) => error instanceof HttpAuthedBrowserBridgeError
      && error.code === 'HTTP_AUTHED_BROWSER_BRIDGE_RESULT_CANCELLED',
  )
  assert.equal(session.snapshot().state, 'CLOSED')
  assert.equal(session.snapshot().request_may_have_been_sent, true)
})

test('browser bridge settles after an observer transfers its response copy before rejecting', async () => {
  const {
    HttpAuthedBrowserBridgeError,
    createHttpAuthedBrowserBridgeSession,
    createHttpAuthedBrowserBridgeTransport,
  } = await bridgeApi()
  const { session } = createSession(createHttpAuthedBrowserBridgeSession, {
    setTimer: () => ({ kind: 'synthetic-timer' }),
    clearTimer: () => {},
  })
  openSession(session)
  const transport = createHttpAuthedBrowserBridgeTransport({ session })
  const pending = transport({
    ...request({ maxResponseBytes: 32 * 1024 }),
    beforeSend: async () => {},
    responseObserver: async ({ bodyChunks }) => {
      Object.freeze(bodyChunks)
      structuredClone(bodyChunks[0], { transfer: [bodyChunks[0].buffer] })
      throw new Error('synthetic detached browser observer rejection')
    },
  })
  void pending.catch(() => {})
  const prepared = session.takePrepared()
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
  await session.commit()
  const body = Buffer.alloc(16 * 1024, 0x61)
  const accepted = session.acceptResult({
    ...bound,
    type: 'RESULT',
    outcome: 'OBSERVED',
    response_truncated: false,
    response: {
      status: 200,
      response_bytes: body.length,
      response_header_names: ['content-type'],
      headers: [{
        name: 'content-type',
        value_base64: Buffer.from('application/octet-stream').toString('base64'),
      }],
      body_base64: body.toString('base64'),
    },
  })

  const outcomeWithin = (promise) => new Promise((resolve) => {
    const watchdog = setTimeout(() => resolve({ timeout: true }), 500)
    promise.then(
      (value) => {
        clearTimeout(watchdog)
        resolve({ value })
      },
      (error) => {
        clearTimeout(watchdog)
        resolve({ error })
      },
    )
  })
  const [acceptedOutcome, waiterOutcome] = await Promise.all([
    outcomeWithin(accepted),
    outcomeWithin(pending),
  ])
  for (const outcome of [acceptedOutcome, waiterOutcome]) {
    assert.equal(outcome.timeout, undefined)
    assert.ok(outcome.error instanceof HttpAuthedBrowserBridgeError)
    assert.equal(outcome.error.code, 'HTTP_AUTHED_BROWSER_BRIDGE_RESPONSE_OBSERVER_FAILED')
    assert.equal(outcome.error.request_may_have_been_sent, true)
  }
  assert.equal(session.snapshot().state, 'OPEN')
  assert.equal(session.snapshot().request_may_have_been_sent, true)
})

test('a concurrent duplicate result cannot replace the pending observer cleanup tracker', async () => {
  const {
    HttpAuthedBrowserBridgeError,
    createHttpAuthedBrowserBridgeSession,
  } = await bridgeApi()
  const retainedObserverChunks = []
  const releaseObservers = []
  let observerCalls = 0
  const { session } = createSession(createHttpAuthedBrowserBridgeSession)
  openSession(session)
  const prepared = session.prepare({
    actionId: 'synthetic-action-duplicate-result',
    request: request({
      responseObserver: ({ bodyChunks }) => {
        observerCalls += 1
        retainedObserverChunks.push(bodyChunks.shift())
        return new Promise((resolve) => { releaseObservers.push(resolve) })
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
  const resultEnvelope = {
    ...bound,
    type: 'RESULT',
    outcome: 'OBSERVED',
    response_truncated: false,
    response: {
      status: 200,
      response_bytes: 1,
      response_header_names: [],
      headers: [],
      body_base64: Buffer.from('x').toString('base64'),
    },
  }
  session.acceptReady({ ...bound, type: 'READY' })
  await session.commit({ beforeSend: async () => {} })
  const first = session.acceptResult(resultEnvelope)
  void first.catch(() => {})
  const second = session.acceptResult(resultEnvelope)
  const secondOutcome = await Promise.race([
    second.then(
      () => ({ kind: 'RESOLVED' }),
      (error) => ({ kind: 'REJECTED', error }),
    ),
    new Promise((resolve) => setImmediate(() => resolve({ kind: 'PENDING' }))),
  ])

  session.close('synthetic duplicate result')
  const erasedAtClose = retainedObserverChunks.every(
    (chunk) => chunk.every((byte) => byte === 0),
  )
  for (const release of releaseObservers) release()
  await Promise.allSettled([first, second])

  assert.equal(secondOutcome.kind, 'REJECTED')
  assert.ok(secondOutcome.error instanceof HttpAuthedBrowserBridgeError)
  assert.equal(secondOutcome.error.code, 'HTTP_AUTHED_BROWSER_BRIDGE_RESULT_UNEXPECTED')
  assert.equal(observerCalls, 1)
  assert.equal(erasedAtClose, true)
})
