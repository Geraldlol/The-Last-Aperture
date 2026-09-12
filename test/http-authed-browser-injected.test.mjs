import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { test } from 'node:test'

import {
  PAGE_SESSION_ROUTING_CARRIER_HEADERS,
  pageSessionAdapterSha256,
} from '../scripts/lib/page-session-adapter.mjs'

const TARGET_ORIGIN = 'https://bounty.example.test'
const DOCUMENT_NONCE = 'synthetic-document-nonce-000000000001'
const ACTION_BINDING = 'a'.repeat(64)
const COOKIE_V1 = 'session=SYNTHETIC_BROWSER_COOKIE_V1'
const COOKIE_V2 = 'session=SYNTHETIC_BROWSER_COOKIE_V2'
const RESPONSE_HEADER_VALUE = 'SYNTHETIC_RESPONSE_HEADER_VALUE'
const RESPONSE_AUTHORIZATION_VALUE = 'Bearer SYNTHETIC_RESPONSE_AUTHORIZATION_VALUE'
const RESPONSE_BODY = 'SYNTHETIC_RESPONSE_BODY_VALUE'

function pageSessionAdapter(overrides = {}) {
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
    carrier: {
      type: 'REQUEST_HEADER',
      name: 'authorization',
      prefix: 'Bearer ',
    },
    target_constraints: [{
      origin: TARGET_ORIGIN,
      method: 'GET',
      path_prefix: '/approved',
    }],
    validity: {
      not_before: '2026-01-01T00:00:00.000Z',
      not_after: '2031-01-01T00:00:00.000Z',
    },
    limits: { max_value_bytes: 4096 },
    ...overrides,
  }
}

function adapterCommand(adapter, overrides = {}) {
  return command({
    session_adapter: adapter,
    session_adapter_sha256: pageSessionAdapterSha256(adapter),
    ...overrides,
  })
}

async function injectedApi() {
  return import('../browser/http-authed-chrome/injected-fetch.mjs')
}

function command(overrides = {}) {
  return {
    protocol: 'red-team-audit/http-authed-browser-bridge',
    schema_version: '1.0.0',
    session_id: 'synthetic-browser-session-0001',
    dispatch_id: 'synthetic-browser-dispatch-0001',
    target_origin: TARGET_ORIGIN,
    document_nonce: DOCUMENT_NONCE,
    action_binding_sha256: ACTION_BINDING,
    method: 'GET',
    relative_url: '/approved/seed?subject=SYNTHETIC_VALUE',
    body: null,
    deadline_epoch_ms: 4_102_444_800_000,
    ...overrides,
  }
}

function response() {
  return new Response(RESPONSE_BODY, {
    status: 200,
    headers: {
      allow: 'GET, HEAD',
      authorization: RESPONSE_AUTHORIZATION_VALUE,
      'content-encoding': 'identity',
      'content-type': 'application/json',
      link: '</approved/next>; rel="next"',
      location: '/approved/next',
      'set-cookie': 'response-session=SYNTHETIC_RESPONSE_COOKIE',
      'x-synthetic-secret': RESPONSE_HEADER_VALUE,
    },
  })
}

function fakeBrowserNetwork() {
  let currentCookie = COOKIE_V1
  const observedCookies = []
  const calls = []
  return {
    calls,
    observedCookies,
    async fetchImpl(url, options) {
      calls.push({ url, options: structuredClone(options) })
      // This closure represents Chrome's network service. The injected
      // function receives no cookie bytes; the fake jar attaches them here.
      observedCookies.push(currentCookie)
      currentCookie = COOKIE_V2
      return response()
    },
  }
}

function runtime(network, overrides = {}) {
  return {
    location: { origin: TARGET_ORIGIN },
    documentNonce: DOCUMENT_NONCE,
    preparedActionBindingSha256: ACTION_BINDING,
    fetchImpl: network.fetchImpl,
    ...overrides,
  }
}

test('fixed injected fetch uses the current opaque browser session on every request', async () => {
  const { executeHttpAuthedInjectedFetch } = await injectedApi()
  const network = fakeBrowserNetwork()

  const first = await executeHttpAuthedInjectedFetch(command(), runtime(network))
  const second = await executeHttpAuthedInjectedFetch(command({
    dispatch_id: 'synthetic-browser-dispatch-0002',
    relative_url: '/approved/discovered',
  }), runtime(network))

  assert.equal(network.calls.length, 2)
  assert.deepEqual(network.observedCookies, [COOKIE_V1, COOKIE_V2])
  assert.deepEqual(network.calls.map(({ url }) => url), [
    `${TARGET_ORIGIN}/approved/seed?subject=SYNTHETIC_VALUE`,
    `${TARGET_ORIGIN}/approved/discovered`,
  ])
  for (const { options } of network.calls) {
    assert.equal(options.method, 'GET')
    assert.equal(options.credentials, 'same-origin')
    assert.equal(options.redirect, 'error')
    assert.equal(options.cache, 'no-store')
    assert.equal(options.body, undefined)
    assert.equal(Object.keys(options.headers ?? {}).some(
      (name) => ['cookie', 'authorization'].includes(name.toLowerCase()),
    ), false)
  }

  const rendered = JSON.stringify([first, second, network.calls])
  assert.equal(rendered.includes(COOKIE_V1), false)
  assert.equal(rendered.includes(COOKIE_V2), false)
  assert.equal(rendered.includes(RESPONSE_HEADER_VALUE), false)
  assert.equal(rendered.includes(RESPONSE_AUTHORIZATION_VALUE), false)
  assert.equal(rendered.includes(Buffer.from(RESPONSE_HEADER_VALUE).toString('base64')), false)
  assert.equal(rendered.includes(Buffer.from(RESPONSE_AUTHORIZATION_VALUE).toString('base64')), false)
  assert.equal(rendered.includes(RESPONSE_BODY), false)
  assert.equal(first.status, 200)
  assert.equal(first.bytes, Buffer.byteLength(RESPONSE_BODY))
  assert.deepEqual(first.header_names, [
    'allow',
    'content-encoding',
    'content-type',
    'link',
    'location',
    'other',
    'set-cookie',
  ])
  assert.deepEqual(first.response.headers.map(({ name, value_base64 }) => ({
    name,
    value: Buffer.from(value_base64, 'base64').toString('utf8'),
  })), [
    { name: 'allow', value: 'GET, HEAD' },
    { name: 'content-encoding', value: 'identity' },
    { name: 'content-type', value: 'application/json' },
    { name: 'link', value: '</approved/next>; rel="next"' },
    { name: 'location', value: '/approved/next' },
  ])
})

test('injected fetch accepts Chrome-serialized omission of a null request body', async () => {
  const { executeHttpAuthedInjectedFetch } = await injectedApi()
  const network = fakeBrowserNetwork()
  const serializedCommand = command()
  delete serializedCommand.body
  const result = await executeHttpAuthedInjectedFetch(serializedCommand, runtime(network))
  assert.equal(result.outcome, 'OBSERVED')
  assert.equal(network.calls.length, 1)
  assert.equal(network.calls[0].options.body, undefined)
})

test('injected fetch reacquires an exact local-storage session value for every dispatch', async () => {
  const { executeHttpAuthedInjectedFetch } = await injectedApi()
  const adapter = pageSessionAdapter()
  const adapterSha256 = pageSessionAdapterSha256(adapter)
  let storedValue = 'SYNTHETIC_PAGE_TOKEN_V1'
  const observed = []
  const localStorage = {
    getItem(key) {
      assert.equal(key, 'application.session')
      return storedValue
    },
  }
  const fetchImpl = async (_url, options) => {
    observed.push(createHash('sha256').update(options.headers.authorization).digest('hex'))
    assert.equal(options.headers.authorization, `Bearer ${storedValue}`)
    return response()
  }
  const baseRuntime = {
    location: { origin: TARGET_ORIGIN },
    documentNonce: DOCUMENT_NONCE,
    preparedActionBindingSha256: ACTION_BINDING,
    preparedSessionAdapterSha256: adapterSha256,
    localStorage,
    fetchImpl,
  }

  const first = await executeHttpAuthedInjectedFetch(adapterCommand(adapter), baseRuntime)
  storedValue = 'SYNTHETIC_PAGE_TOKEN_V2'
  const second = await executeHttpAuthedInjectedFetch(adapterCommand(adapter, {
    dispatch_id: 'synthetic-browser-dispatch-0002',
  }), baseRuntime)

  assert.equal(observed.length, 2)
  assert.equal(first.session_adapter_sha256, adapterSha256)
  assert.equal(second.session_adapter_sha256, adapterSha256)
  const rendered = JSON.stringify([first, second, observed])
  assert.equal(rendered.includes('SYNTHETIC_PAGE_TOKEN_V1'), false)
  assert.equal(rendered.includes('SYNTHETIC_PAGE_TOKEN_V2'), false)
})

test('injected fetch resolves only a strict session-storage JSON pointer', async () => {
  const { executeHttpAuthedInjectedFetch } = await injectedApi()
  const adapter = pageSessionAdapter({
    source: {
      type: 'WEB_STORAGE',
      area: 'SESSION',
      key: 'application.state',
      extraction: { mode: 'JSON_POINTER', pointer: '/auth/access~1token' },
    },
    carrier: {
      type: 'REQUEST_HEADER',
      name: 'x-application-session',
    },
  })
  const adapterSha256 = pageSessionAdapterSha256(adapter)
  let calls = 0
  const result = await executeHttpAuthedInjectedFetch(adapterCommand(adapter), {
    location: { origin: TARGET_ORIGIN },
    documentNonce: DOCUMENT_NONCE,
    preparedActionBindingSha256: ACTION_BINDING,
    preparedSessionAdapterSha256: adapterSha256,
    sessionStorage: {
      getItem(key) {
        assert.equal(key, 'application.state')
        return JSON.stringify({ auth: { 'access/token': 'SYNTHETIC_JSON_TOKEN' } })
      },
    },
    fetchImpl: async (_url, options) => {
      calls += 1
      assert.equal(options.headers['x-application-session'], 'SYNTHETIC_JSON_TOKEN')
      return response()
    },
  })
  assert.equal(calls, 1)
  assert.equal(JSON.stringify(result).includes('SYNTHETIC_JSON_TOKEN'), false)
})

test('injected fetch refuses missing, non-string, oversized, expired, drifted, and undeclared adapter values before fetch', async () => {
  const { executeHttpAuthedInjectedFetch } = await injectedApi()
  let calls = 0
  const fetchImpl = async () => { calls += 1; return response() }
  const scenarios = [
    {
      adapter: pageSessionAdapter(),
      storage: { getItem: () => null },
      code: 'HTTP_AUTHED_BROWSER_SESSION_ADAPTER_VALUE_INVALID',
    },
    {
      adapter: pageSessionAdapter({
        source: {
          type: 'WEB_STORAGE', area: 'LOCAL', key: 'application.session',
          extraction: { mode: 'JSON_POINTER', pointer: '/token' },
        },
      }),
      storage: { getItem: () => JSON.stringify({ token: 42 }) },
      code: 'HTTP_AUTHED_BROWSER_SESSION_ADAPTER_VALUE_INVALID',
    },
    {
      adapter: pageSessionAdapter({ limits: { max_value_bytes: 8 } }),
      storage: { getItem: () => 'SYNTHETIC_OVERSIZED_TOKEN' },
      code: 'HTTP_AUTHED_BROWSER_SESSION_ADAPTER_VALUE_BOUNDED',
    },
    {
      adapter: pageSessionAdapter(),
      storage: { getItem: () => ' SYNTHETIC_TOKEN\t' },
      code: 'HTTP_AUTHED_BROWSER_SESSION_ADAPTER_VALUE_INVALID',
    },
    {
      adapter: pageSessionAdapter({
        validity: {
          not_before: '2025-01-01T00:00:00.000Z',
          not_after: '2025-12-31T23:59:59.999Z',
        },
      }),
      storage: { getItem: () => 'SYNTHETIC_TOKEN' },
      code: 'HTTP_AUTHED_BROWSER_SESSION_ADAPTER_EXPIRED',
    },
    {
      adapter: pageSessionAdapter({
        target_constraints: [{
          origin: TARGET_ORIGIN, method: 'GET', path_prefix: '/different',
        }],
      }),
      storage: { getItem: () => 'SYNTHETIC_TOKEN' },
      code: 'HTTP_AUTHED_BROWSER_SESSION_ADAPTER_TARGET_REFUSED',
    },
  ]

  for (const scenario of scenarios) {
    const digest = pageSessionAdapterSha256(scenario.adapter)
    await assert.rejects(
      executeHttpAuthedInjectedFetch(adapterCommand(scenario.adapter), {
        location: { origin: TARGET_ORIGIN },
        documentNonce: DOCUMENT_NONCE,
        preparedActionBindingSha256: ACTION_BINDING,
        preparedSessionAdapterSha256: digest,
        localStorage: scenario.storage,
        fetchImpl,
      }),
      { code: scenario.code },
    )
  }
  const validAdapter = pageSessionAdapter()
  const validDigest = pageSessionAdapterSha256(validAdapter)
  const wildcardAdapter = structuredClone(validAdapter)
  wildcardAdapter.target_constraints[0].origin = 'https://*.example.test'
  const browserControlledHeaderAdapter = structuredClone(validAdapter)
  browserControlledHeaderAdapter.carrier.name = 'sec-fetch-site'
  const routingHeaderAdapters = PAGE_SESSION_ROUTING_CARRIER_HEADERS.map((name) => {
    const candidate = structuredClone(validAdapter)
    candidate.carrier.name = name
    return candidate
  })
  for (const invalidAdapter of [
    wildcardAdapter,
    browserControlledHeaderAdapter,
    ...routingHeaderAdapters,
  ]) {
    await assert.rejects(
      executeHttpAuthedInjectedFetch(command({
        session_adapter: invalidAdapter,
        session_adapter_sha256: validDigest,
      }), {
        location: { origin: TARGET_ORIGIN },
        documentNonce: DOCUMENT_NONCE,
        preparedActionBindingSha256: ACTION_BINDING,
        preparedSessionAdapterSha256: validDigest,
        localStorage: { getItem: () => 'SYNTHETIC_TOKEN' },
        fetchImpl,
      }),
      { code: 'HTTP_AUTHED_BROWSER_SESSION_ADAPTER_INVALID' },
    )
  }
  assert.equal(calls, 0)
})

test('fixed injected fetch refuses origin, document, action, and URL drift before fetch', async () => {
  const { executeHttpAuthedInjectedFetch } = await injectedApi()
  const cases = [
    {
      name: 'tab origin changed',
      command: command(),
      runtime: { location: { origin: 'https://other.example.test' } },
      code: 'HTTP_AUTHED_BROWSER_ORIGIN_MISMATCH',
    },
    {
      name: 'same-origin navigation replaced the document',
      command: command(),
      runtime: { documentNonce: 'different-document-nonce-0000001' },
      code: 'HTTP_AUTHED_BROWSER_DOCUMENT_MISMATCH',
    },
    {
      name: 'commit action binding changed',
      command: command({ action_binding_sha256: 'b'.repeat(64) }),
      runtime: {},
      code: 'HTTP_AUTHED_BROWSER_ACTION_BINDING_MISMATCH',
    },
    {
      name: 'absolute URL supplied',
      command: command({ relative_url: 'https://other.example.test/escape' }),
      runtime: {},
      code: 'HTTP_AUTHED_BROWSER_ACTION_INVALID',
    },
    {
      name: 'network-path reference supplied',
      command: command({ relative_url: '//other.example.test/escape' }),
      runtime: {},
      code: 'HTTP_AUTHED_BROWSER_ACTION_INVALID',
    },
    {
      name: 'fragment supplied',
      command: command({ relative_url: '/approved/seed#fragment' }),
      runtime: {},
      code: 'HTTP_AUTHED_BROWSER_ACTION_INVALID',
    },
    {
      name: 'encoded separator supplied',
      command: command({ relative_url: '/approved/%252fescape' }),
      runtime: {},
      code: 'HTTP_AUTHED_BROWSER_ACTION_INVALID',
    },
    {
      name: 'backslash path supplied',
      command: command({ relative_url: '/approved\\escape' }),
      runtime: {},
      code: 'HTTP_AUTHED_BROWSER_ACTION_INVALID',
    },
    {
      name: 'method is not canonical uppercase',
      command: command({ method: 'get' }),
      runtime: {},
      code: 'HTTP_AUTHED_BROWSER_ACTION_INVALID',
    },
  ]

  for (const scenario of cases) {
    const network = fakeBrowserNetwork()
    await assert.rejects(
      executeHttpAuthedInjectedFetch(
        scenario.command,
        runtime(network, scenario.runtime),
      ),
      (error) => error.code === scenario.code,
      scenario.name,
    )
    assert.equal(network.calls.length, 0, scenario.name)
  }
})

test('fixed injected fetch refuses redirects and never retries an ambiguous dispatch', async () => {
  const { executeHttpAuthedInjectedFetch } = await injectedApi()
  let calls = 0
  const redirectValue = 'https://other.example.test/SYNTHETIC_REDIRECT_SECRET'
  const fetchImpl = async (_url, options) => {
    calls += 1
    assert.equal(options.redirect, 'error')
    const error = new TypeError(`redirect refused: ${redirectValue}`)
    error.request_may_have_been_sent = true
    throw error
  }

  await assert.rejects(
    executeHttpAuthedInjectedFetch(command(), runtime({ fetchImpl }, { fetchImpl })),
    (error) => {
      assert.equal(error.request_may_have_been_sent, true)
      assert.equal(error.message.includes(redirectValue), false)
      return true
    },
  )
  assert.equal(calls, 1)
})

test('injected fetch distinguishes exact, bounded, and incomplete response observations', async () => {
  const { executeHttpAuthedInjectedFetch } = await injectedApi()
  const encoder = new TextEncoder()

  const exact = await executeHttpAuthedInjectedFetch(
    command({ max_response_bytes: 3 }),
    runtime({ fetchImpl: async () => new Response('abc') }, {
      fetchImpl: async () => new Response('abc'),
    }),
  )
  assert.equal(exact.outcome, 'OBSERVED')
  assert.equal(exact.response_truncated, false)
  assert.equal(Buffer.from(exact.response.body_base64, 'base64').toString(), 'abc')

  const boundedFetch = async () => new Response('abcdef')
  const bounded = await executeHttpAuthedInjectedFetch(
    command({ max_response_bytes: 3 }),
    runtime({ fetchImpl: boundedFetch }, { fetchImpl: boundedFetch }),
  )
  assert.equal(bounded.outcome, 'RESPONSE_BOUNDED')
  assert.equal(bounded.response_truncated, true)
  assert.equal(Buffer.from(bounded.response.body_base64, 'base64').toString(), 'abc')

  let reads = 0
  const incompleteFetch = async () => ({
    status: 200,
    redirected: false,
    headers: new Headers({ 'content-type': 'application/json' }),
    body: {
      getReader() {
        return {
          async read() {
            reads += 1
            if (reads === 1) return { done: false, value: encoder.encode('ab') }
            throw new Error('synthetic stream failure')
          },
        }
      },
    },
  })
  const incomplete = await executeHttpAuthedInjectedFetch(
    command({ max_response_bytes: 3 }),
    runtime({ fetchImpl: incompleteFetch }, { fetchImpl: incompleteFetch }),
  )
  assert.equal(incomplete.outcome, 'OBSERVATION_INCOMPLETE')
  assert.equal(incomplete.response_truncated, false)
  assert.equal(Buffer.from(incomplete.response.body_base64, 'base64').toString(), 'ab')
})

test('injected fetch keeps a bounded observation when response cancellation rejects', async () => {
  const { executeHttpAuthedInjectedFetch } = await injectedApi()
  const encoder = new TextEncoder()
  let cancelCalls = 0
  let requestSignal
  const fetchImpl = async (_url, options) => {
    requestSignal = options.signal
    return {
      status: 200,
      redirected: false,
      headers: new Headers({ 'content-type': 'application/json' }),
      body: {
        getReader() {
          return {
            async read() {
              return { done: false, value: encoder.encode('abcdef') }
            },
            async cancel() {
              cancelCalls += 1
              throw new Error('synthetic cancellation failure')
            },
          }
        }
      },
    }
  }

  const bounded = await executeHttpAuthedInjectedFetch(
    command({ max_response_bytes: 3 }),
    runtime({ fetchImpl }, { fetchImpl }),
  )

  assert.equal(cancelCalls, 1)
  assert.equal(requestSignal.aborted, true)
  assert.equal(bounded.outcome, 'RESPONSE_BOUNDED')
  assert.equal(bounded.response_truncated, true)
  assert.equal(Buffer.from(bounded.response.body_base64, 'base64').toString(), 'abc')
})

test('injected fetch rechecks cancellation and the absolute deadline after asynchronous preflight', async () => {
  const { executeHttpAuthedInjectedFetch } = await injectedApi()
  const body = Buffer.from('synthetic-write-body')
  const bodyCommand = command({
    method: 'POST',
    headers: [{ name: 'content-type', value: 'application/octet-stream' }],
    body: {
      encoding: 'base64',
      value: body.toString('base64'),
      byte_length: body.length,
      sha256: createHash('sha256').update(body).digest('hex'),
      content_type: 'application/octet-stream',
    },
  })
  let preparedBinding = ACTION_BINDING
  let calls = 0
  const pending = executeHttpAuthedInjectedFetch(bodyCommand, {
    location: { origin: TARGET_ORIGIN },
    documentNonce: DOCUMENT_NONCE,
    get preparedActionBindingSha256() { return preparedBinding },
    fetchImpl: async () => { calls += 1; return response() },
  })
  preparedBinding = null
  await assert.rejects(pending, { code: 'HTTP_AUTHED_BROWSER_OPERATION_CANCELLED' })
  assert.equal(calls, 0)

  await assert.rejects(
    executeHttpAuthedInjectedFetch(
      command({ deadline_epoch_ms: 1_099 }),
      runtime({ fetchImpl: async () => { calls += 1; return response() } }, {
        clockMilliseconds: () => 1_000,
      }),
    ),
    { code: 'HTTP_AUTHED_BROWSER_ACTION_EXPIRED' },
  )
  assert.equal(calls, 0)
})
