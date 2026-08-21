import assert from 'node:assert/strict'
import { test } from 'node:test'

const TARGET_ORIGIN = 'https://bounty.example.test'
const DOCUMENT_NONCE = 'synthetic-document-nonce-000000000001'
const ACTION_BINDING = 'a'.repeat(64)
const COOKIE_V1 = 'session=SYNTHETIC_BROWSER_COOKIE_V1'
const COOKIE_V2 = 'session=SYNTHETIC_BROWSER_COOKIE_V2'
const RESPONSE_HEADER_VALUE = 'SYNTHETIC_RESPONSE_HEADER_VALUE'
const RESPONSE_BODY = 'SYNTHETIC_RESPONSE_BODY_VALUE'

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
    ...overrides,
  }
}

function response() {
  return new Response(RESPONSE_BODY, {
    status: 200,
    headers: {
      'content-type': 'application/json',
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
  assert.equal(rendered.includes(RESPONSE_BODY), false)
  assert.equal(first.status, 200)
  assert.equal(first.bytes, Buffer.byteLength(RESPONSE_BODY))
  assert.deepEqual(first.header_names, ['content-type', 'other'])
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
