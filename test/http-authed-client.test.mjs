import assert from 'node:assert/strict'
import { X509Certificate } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { test } from 'node:test'
import {
  createHttpAuthedHttpsTransport,
  dispatchHttpAuthedProbe,
  HttpAuthedClientError,
} from '../scripts/lib/http-authed-client.mjs'
import {
  sha256Hex,
  verifyHttpAuthedAuthorization,
} from '../scripts/lib/http-authed-contracts.mjs'
import { attestedScope } from './helpers/http-authed-fixtures.mjs'
import { httpAuthedResponseByteBucket } from '../scripts/lib/http-authed-response-metadata.mjs'
import { REFERENCE_TLS_CERTIFICATE } from './fixtures/reference-transparency-tls.mjs'

const NOW = new Date('2026-08-16T12:00:00.000Z')
const CREDENTIAL = Buffer.from('synthetic-credential-value')
const VERIFY_BEFORE_SEND = async () => {}

function campaign({ method = 'PROPFIND', action = {} } = {}) {
  const scope = attestedScope({ actionCount: 1 })
  if (!scope.authorization.authorized_scope.methods.includes(method)) {
    scope.authorization.authorized_scope.methods.push(method)
  }
  scope.credential.binding_sha256 = sha256Hex(CREDENTIAL)
  const candidate = {
    kind: 'probe',
    sequence: 2_000_000,
    test_category: 'api_security',
    method,
    url: 'https://app.example.test/discovered/method-surface',
    expected_effect: 'none',
    ...action,
  }
  scope.requests = [{ ...candidate, sequence: 1 }]
  const expectedCampaignGrantSha256 = verifyHttpAuthedAuthorization({
    scope,
    now: NOW,
  }).campaignGrantSha256
  return { scope, candidate, expectedCampaignGrantSha256 }
}

test('method-complete operator-attested probe reaches one injected transport without an action-count gate', async () => {
  const { scope, candidate, expectedCampaignGrantSha256 } = campaign()
  const calls = []
  const result = await dispatchHttpAuthedProbe({
    scope,
    action: candidate,
    expectedCampaignGrantSha256,
    credentialValue: CREDENTIAL,
    now: NOW,
    beforeSend: VERIFY_BEFORE_SEND,
    transport: async (request) => {
      calls.push(request)
      return {
        status: 207,
        responseBytes: 8192,
        responseHeaderNames: [
          'content-type',
          'set-cookie',
          'x-synthetic-patient-identifier-12345',
        ],
        responseHeaderValues: ['application/xml', 'secret-cookie-value'],
      }
    },
  })

  assert.equal(calls.length, 1)
  assert.equal(calls[0].method, 'PROPFIND')
  assert.equal(calls[0].url, candidate.url)
  assert.equal(calls[0].responseObserver, undefined)
  assert.equal(calls[0].headers['user-agent'], 'red-team-audit-http-authed/0.16')
  assert.equal(calls[0].headers.authorization, `Bearer ${CREDENTIAL.toString('utf8')}`)
  assert.equal(result.action.sequence, 2_000_000)
  assert.deepEqual(result.response, {
    status: 207,
    bytes: 8192,
    header_names: ['content-type', 'set-cookie', 'other'],
  })
  assert.equal(result.schema_version, '1.0.0')
  const rendered = JSON.stringify(result)
  assert.doesNotMatch(rendered, /synthetic-credential-value|secret-cookie-value/)
  assert.doesNotMatch(rendered, /patient-identifier-12345/)
  assert.doesNotMatch(rendered, /SYNTHETIC_TEST_CREDENTIAL/)
})

test('JSON schema-only observation works with bearer and cookie credentials without retaining values', async () => {
  const responseValue = 'SYNTHETIC_RESPONSE_VALUE_MUST_NOT_PERSIST'
  const observedBodies = []
  for (const kind of ['bearer', 'cookie']) {
    const { scope, candidate } = campaign({ method: 'GET' })
    scope.credential.kind = kind
    scope.schema_version = '1.1.0'
    scope.response_observation = {
      mode: 'JSON_SHAPE_ONLY',
      max_depth: 4,
      safe_key_names: ['id', 'label', 'records'],
    }
    const expectedCampaignGrantSha256 = verifyHttpAuthedAuthorization({
      scope,
      now: NOW,
    }).campaignGrantSha256
    const result = await dispatchHttpAuthedProbe({
      scope,
      action: candidate,
      expectedCampaignGrantSha256,
      credentialValue: CREDENTIAL,
      now: NOW,
      beforeSend: VERIFY_BEFORE_SEND,
      transport: async (request) => {
        assert.equal(
          kind === 'bearer' ? request.headers.authorization : request.headers.cookie,
          kind === 'bearer' ? `Bearer ${CREDENTIAL.toString('utf8')}` : CREDENTIAL.toString('utf8'),
        )
        await request.beforeSend()
        const responseBody = Buffer.from(JSON.stringify({
          records: [{ id: 8675309, label: responseValue }],
        }))
        observedBodies.push(responseBody)
        await request.responseObserver({
          status: 200,
          headers: [{ name: 'content-type', value: 'application/json' }],
          bodyChunks: [responseBody],
        })
        return {
          status: 200,
          responseBytes: 92,
          responseHeaderNames: ['content-type', 'set-cookie'],
        }
      },
    })

    assert.equal(result.response.json_shape.root_type, 'object')
    assert.deepEqual(result.response.json_shape.key_names, ['id', 'label', 'records'])
    assert.deepEqual(
      result.response.json_shape.value_types.find(({ path }) => path.join('/') === 'records/[]/id'),
      { path: ['records', '[]', 'id'], types: ['number'] },
    )
    const rendered = JSON.stringify(result)
    assert.equal(rendered.includes(responseValue), false)
    assert.equal(rendered.includes('8675309'), false)
    assert.equal(rendered.includes(CREDENTIAL.toString('utf8')), false)
  }
  assert.equal(observedBodies.every((body) => body.every((byte) => byte === 0)), true)
})

test('ASP.NET d JSON projection is scope-bound and retains only inner shape metadata', async () => {
  const responseValue = 'SYNTHETIC_ASMX_RESPONSE_VALUE_MUST_NOT_PERSIST'
  const { scope, candidate } = campaign({ method: 'GET' })
  scope.schema_version = '1.2.0'
  scope.response_observation = {
    mode: 'ASPNET_D_JSON_SHAPE_ONLY',
    max_depth: 4,
    safe_key_names: ['id', 'label', 'records'],
  }
  const expectedCampaignGrantSha256 = verifyHttpAuthedAuthorization({
    scope,
    now: NOW,
  }).campaignGrantSha256
  const result = await dispatchHttpAuthedProbe({
    scope,
    action: candidate,
    expectedCampaignGrantSha256,
    credentialValue: CREDENTIAL,
    now: NOW,
    beforeSend: VERIFY_BEFORE_SEND,
    transport: async (request) => {
      await request.beforeSend()
      await request.responseObserver({
        status: 200,
        headers: [{ name: 'content-type', value: 'application/json; charset=utf-8' }],
        bodyChunks: [Buffer.from(JSON.stringify({
          d: JSON.stringify({ records: [{ id: 8675309, label: responseValue }] }),
        }))],
      })
      return {
        status: 200,
        responseBytes: 128,
        responseHeaderNames: ['content-type'],
      }
    },
  })

  assert.equal(result.schema_version, '1.2.0')
  assert.equal(result.response.json_shape.schema_version, '1.1.0')
  assert.equal(result.response.json_shape.projection, 'ASPNET_D_JSON_STRING')
  assert.deepEqual(result.response.json_shape.key_names, ['id', 'label', 'records'])
  const rendered = JSON.stringify(result)
  assert.equal(rendered.includes(responseValue), false)
  assert.equal(rendered.includes('8675309'), false)
})

test('ASP.NET d JSON projection reports a settled bounded observation failure', async () => {
  const marker = 'SYNTHETIC_ASMX_INVALID_INNER_VALUE'
  const responseBody = Buffer.from(JSON.stringify({ d: `<html>${marker}</html>` }))
  const { scope, candidate } = campaign({ method: 'GET' })
  scope.schema_version = '1.2.0'
  scope.response_observation = {
    mode: 'ASPNET_D_JSON_SHAPE_ONLY',
    max_depth: 4,
    safe_key_names: ['d', 'value'],
  }
  const expectedCampaignGrantSha256 = verifyHttpAuthedAuthorization({
    scope,
    now: NOW,
  }).campaignGrantSha256

  let downstreamObserverCalls = 0
  const result = await dispatchHttpAuthedProbe({
    scope,
    action: candidate,
    expectedCampaignGrantSha256,
    credentialValue: CREDENTIAL,
    now: NOW,
    beforeSend: VERIFY_BEFORE_SEND,
    responseObserver: async () => { downstreamObserverCalls += 1 },
    transport: async (request) => {
      await request.beforeSend()
      await request.responseObserver({
        status: 500,
        headers: [{ name: 'content-type', value: 'application/json' }],
        bodyChunks: [responseBody],
      })
      return {
        status: 500,
        responseBytes: 3000,
        responseHeaderNames: ['content-type', 'x-synthetic-subject-8675309'],
      }
    },
  })

  assert.equal(downstreamObserverCalls, 0)
  assert.equal(responseBody.every((byte) => byte === 0), true)
  assert.equal(result.schema_version, '1.3.0')
  assert.deepEqual(result.response, {
    status: 500,
    header_names: ['content-type', 'other'],
    response_byte_bucket: 'LE_4_KIB',
    failure_stage_code: 'JSON_SHAPE_OBSERVATION',
  })
  assert.equal(Object.hasOwn(result.response, 'bytes'), false)
  assert.equal(Object.hasOwn(result.response, 'json_shape'), false)
  assert.equal(JSON.stringify(result).includes(marker), false)
  assert.equal(JSON.stringify(result).includes('8675309'), false)
})

test('claimed malformed JSON reports only bounded observation-failure telemetry', async () => {
  const marker = 'SYNTHETIC_MALFORMED_JSON_VALUE'
  const { scope, candidate } = campaign({ method: 'GET' })
  scope.schema_version = '1.1.0'
  scope.response_observation = {
    mode: 'JSON_SHAPE_ONLY',
    max_depth: 4,
    safe_key_names: ['value'],
  }
  const observationCampaignGrantSha256 = verifyHttpAuthedAuthorization({
    scope,
    now: NOW,
  }).campaignGrantSha256
  const result = await dispatchHttpAuthedProbe({
    scope,
    action: candidate,
    expectedCampaignGrantSha256: observationCampaignGrantSha256,
    credentialValue: CREDENTIAL,
    now: NOW,
    beforeSend: VERIFY_BEFORE_SEND,
    transport: async (request) => {
      await request.beforeSend()
      await request.responseObserver({
        status: 200,
        headers: [{ name: 'content-type', value: 'application/json' }],
        bodyChunks: [Buffer.from(`{"value":"${marker}"`)],
      })
      return {
        status: 200,
        responseBytes: 700,
        responseHeaderNames: ['content-type'],
      }
    },
  })

  assert.deepEqual(result.response, {
    status: 200,
    header_names: ['content-type'],
    response_byte_bucket: 'LE_1_KIB',
    failure_stage_code: 'JSON_SHAPE_OBSERVATION',
  })
  assert.equal(JSON.stringify(result).includes(marker), false)
})

test('response byte bucketing uses only the fixed bounded vocabulary', () => {
  assert.deepEqual([
    0, 1, 1024, 1025, 4096, 4097, 16384, 16385, 65536, 65537,
    262144, 262145, 1048576,
  ].map(httpAuthedResponseByteBucket), [
    'EMPTY',
    'LE_1_KIB', 'LE_1_KIB',
    'LE_4_KIB', 'LE_4_KIB',
    'LE_16_KIB', 'LE_16_KIB',
    'LE_64_KIB', 'LE_64_KIB',
    'LE_256_KIB', 'LE_256_KIB',
    'LE_1_MIB', 'LE_1_MIB',
  ])
  assert.throws(() => httpAuthedResponseByteBucket(1048577), /bounded range/i)
})

test('a downstream response observer failure remains delivery-uncertain', async () => {
  const marker = 'SYNTHETIC_DOWNSTREAM_OBSERVER_SECRET'
  const responseBody = Buffer.from('{"value":true}')
  const { scope, candidate } = campaign({ method: 'GET' })
  scope.schema_version = '1.1.0'
  scope.response_observation = {
    mode: 'JSON_SHAPE_ONLY',
    max_depth: 4,
    safe_key_names: ['value'],
  }
  const expectedCampaignGrantSha256 = verifyHttpAuthedAuthorization({
    scope,
    now: NOW,
  }).campaignGrantSha256

  await assert.rejects(
    () => dispatchHttpAuthedProbe({
      scope,
      action: candidate,
      expectedCampaignGrantSha256,
      credentialValue: CREDENTIAL,
      now: NOW,
      beforeSend: VERIFY_BEFORE_SEND,
      responseObserver: async () => { throw new Error(marker) },
      transport: async (request) => {
        await request.beforeSend()
        await request.responseObserver({
          status: 200,
          headers: [{ name: 'content-type', value: 'application/json' }],
          bodyChunks: [responseBody],
        })
      },
    }),
    (error) => {
      assert.equal(error.code, 'HTTP_AUTHED_RESPONSE_OBSERVER_FAILED')
      assert.equal(error.request_may_have_been_sent, true)
      assert.equal(error.message.includes(marker), false)
      return true
    },
  )
  assert.equal(responseBody.every((byte) => byte === 0), true)
})

test('candidate, campaign, and operator-attested scope drift fail before the transport boundary', async () => {
  const { scope, candidate, expectedCampaignGrantSha256 } = campaign()
  const widenedScope = structuredClone(scope)
  widenedScope.authorization.authorized_scope.methods.push('SEARCH')
  let calls = 0
  const transport = async () => { calls += 1 }
  const attempts = [
    {
      action: { ...candidate, method: 'SEARCH' },
      expectedCampaignGrantSha256,
    },
    {
      scope: widenedScope,
      action: candidate,
      expectedCampaignGrantSha256,
    },
    {
      action: candidate,
      expectedCampaignGrantSha256: 'f'.repeat(64),
    },
  ]

  for (const attempt of attempts) {
    await assert.rejects(
      () => dispatchHttpAuthedProbe({
        scope,
        credentialValue: CREDENTIAL,
        now: NOW,
        beforeSend: VERIFY_BEFORE_SEND,
        transport,
        ...attempt,
      }),
      /method|campaign|grant|digest|scope/i,
    )
  }
  assert.equal(calls, 0)
})

test('credential and synthetic body bytes must match their sealed bindings', async () => {
  const body = Buffer.from('{"synthetic":true}')
  const { scope, candidate, expectedCampaignGrantSha256 } = campaign({
    method: 'POST',
    action: {
      request_body: {
        body_id: 'SYNTHETIC_ACTIVE_PROBE_BODY_0001',
        sha256: sha256Hex(body),
        byte_length: body.length,
        content_type: 'application/json',
        data_class: 'synthetic_non_phi',
      },
    },
  })
  const calls = []
  let bodyAtTransport
  const transport = async (request) => {
    calls.push(request)
    bodyAtTransport = Buffer.from(request.body)
    return { status: 204, responseBytes: 0, responseHeaderNames: [] }
  }

  await assert.rejects(
    () => dispatchHttpAuthedProbe({
      scope,
      action: candidate,
      expectedCampaignGrantSha256,
      credentialValue: Buffer.from('wrong credential'),
      requestBodyBytes: body,
      now: NOW,
      beforeSend: VERIFY_BEFORE_SEND,
      transport,
    }),
    /credential|binding|digest/i,
  )
  await assert.rejects(
    () => dispatchHttpAuthedProbe({
      scope,
      action: candidate,
      expectedCampaignGrantSha256,
      credentialValue: CREDENTIAL,
      requestBodyBytes: Buffer.from('changed body'),
      now: NOW,
      beforeSend: VERIFY_BEFORE_SEND,
      transport,
    }),
    /body|length|digest/i,
  )
  assert.equal(calls.length, 0)

  const result = await dispatchHttpAuthedProbe({
    scope,
    action: candidate,
    expectedCampaignGrantSha256,
    credentialValue: CREDENTIAL,
    requestBodyBytes: body,
    now: NOW,
    beforeSend: VERIFY_BEFORE_SEND,
    transport,
  })
  assert.equal(calls.length, 1)
  assert.deepEqual(bodyAtTransport, body)
  assert.equal(calls[0].body.every((byte) => byte === 0), true)
  assert.doesNotMatch(JSON.stringify(result), /SYNTHETIC_ACTIVE_PROBE_BODY_0001|synthetic-credential/)
})

test('oversized credential bytes are rejected before any private copy is allocated', async (t) => {
  const supplied = Buffer.alloc((64 * 1024) + 1, 0x64)
  const { scope, candidate } = campaign({ method: 'GET' })
  scope.credential.binding_sha256 = sha256Hex(supplied)
  const expectedCampaignGrantSha256 = verifyHttpAuthedAuthorization({ scope, now: NOW })
    .campaignGrantSha256
  const originalFrom = Buffer.from
  let suppliedCopies = 0
  t.mock.method(Buffer, 'from', function (value, ...args) {
    if (value === supplied) suppliedCopies += 1
    return originalFrom.call(Buffer, value, ...args)
  })
  let calls = 0
  await assert.rejects(dispatchHttpAuthedProbe({
    scope,
    action: candidate,
    expectedCampaignGrantSha256,
    credentialValue: supplied,
    now: NOW,
    beforeSend: VERIFY_BEFORE_SEND,
    transport: async () => { calls += 1 },
  }), { code: 'HTTP_AUTHED_BYTES_INVALID' })
  assert.equal(calls, 0)
  assert.equal(suppliedCopies, 0)
  assert.equal(supplied.every((byte) => byte === 0x64), true)
})

test('a rejected probe body erases its preflight copy before transport dispatch', async (t) => {
  const supplied = Buffer.from('synthetic-mismatched-body')
  const { scope, candidate, expectedCampaignGrantSha256 } = campaign({
    method: 'POST',
    action: { request_body: {
      body_id: 'SYNTHETIC_ACTIVE_PROBE_BODY_0001',
      sha256: '0'.repeat(64),
      byte_length: supplied.length,
      content_type: 'application/json',
      data_class: 'synthetic_non_phi',
    } },
  })
  const copies = []
  const originalFrom = Buffer.from
  t.mock.method(Buffer, 'from', function (value, ...args) {
    const copy = originalFrom.call(Buffer, value, ...args)
    if (
      value === CREDENTIAL
      || (value instanceof ArrayBuffer && value.byteLength === supplied.byteLength)
    ) copies.push(copy)
    return copy
  })
  let calls = 0
  await assert.rejects(dispatchHttpAuthedProbe({
    scope,
    action: candidate,
    expectedCampaignGrantSha256,
    credentialValue: CREDENTIAL,
    requestBodyBytes: supplied,
    now: NOW,
    beforeSend: VERIFY_BEFORE_SEND,
    transport: async () => { calls += 1 },
  }), { code: 'HTTP_AUTHED_BODY_BINDING_MISMATCH' })
  assert.equal(calls, 0)
  assert.equal(copies.length, 2)
  assert.equal(copies.every((copy) => copy.every((byte) => byte === 0)), true)
})

test('a failed dedicated string body copy erases its temporary source and partial destination', async (t) => {
  const supplied = 'synthetic-partial-body-copy'
  const expectedBytes = Buffer.from(supplied)
  const { scope, candidate, expectedCampaignGrantSha256 } = campaign({
    method: 'POST',
    action: { request_body: {
      body_id: 'SYNTHETIC_ACTIVE_PROBE_BODY_0001',
      sha256: sha256Hex(expectedBytes),
      byte_length: expectedBytes.byteLength,
      content_type: 'application/json',
      data_class: 'synthetic_non_phi',
    } },
  })
  const copies = []
  const originalFrom = Buffer.from
  t.mock.method(Buffer, 'from', function (value, ...args) {
    const copy = originalFrom.call(Buffer, value, ...args)
    if (value === supplied) copies.push(copy)
    if (value instanceof ArrayBuffer && value.byteLength === expectedBytes.byteLength) {
      copies.push(copy)
      Object.defineProperty(copy, 'set', {
        value(source) {
          Reflect.apply(Uint8Array.prototype.set, this, [source.subarray(0, 7)])
          throw new Error('synthetic partial owned-copy failure')
        },
      })
    }
    return copy
  })
  let calls = 0
  await assert.rejects(dispatchHttpAuthedProbe({
    scope,
    action: candidate,
    expectedCampaignGrantSha256,
    credentialValue: CREDENTIAL,
    requestBodyBytes: supplied,
    now: NOW,
    beforeSend: VERIFY_BEFORE_SEND,
    transport: async () => { calls += 1 },
  }), /synthetic partial owned-copy failure/)
  assert.equal(calls, 0)
  assert.equal(copies.length, 2)
  assert.equal(copies.every((copy) => copy.every((byte) => byte === 0)), true)
})

test('declared mutation actions stay out of the probe dispatcher', async () => {
  const scope = attestedScope({ actionCount: 1 })
  scope.credential.binding_sha256 = sha256Hex(CREDENTIAL)
  const expectedCampaignGrantSha256 = verifyHttpAuthedAuthorization({
    scope,
    now: NOW,
  }).campaignGrantSha256
  let calls = 0
  await assert.rejects(
    () => dispatchHttpAuthedProbe({
      scope,
      action: scope.requests[0],
      expectedCampaignGrantSha256,
      credentialValue: CREDENTIAL,
      requestBodyBytes: Buffer.alloc(64),
      now: NOW,
      beforeSend: VERIFY_BEFORE_SEND,
      transport: async () => { calls += 1 },
    }),
    /probe dispatcher|mutation/i,
  )
  assert.equal(calls, 0)
})

test('live probe dispatch requires an immediate pre-send verifier', async () => {
  const { scope, candidate, expectedCampaignGrantSha256 } = campaign()
  let calls = 0
  await assert.rejects(
    () => dispatchHttpAuthedProbe({
      scope,
      action: candidate,
      expectedCampaignGrantSha256,
      credentialValue: CREDENTIAL,
      now: NOW,
      transport: async () => { calls += 1 },
    }),
    /before.send|verifier|required/i,
  )
  assert.equal(calls, 0)
})

test('protected HTTPS transport refuses noncanonical method casing before I/O', async () => {
  let networkCalls = 0
  const transport = createHttpAuthedHttpsTransport({
    dnsLookup: () => { networkCalls += 1 },
    httpsRequest: () => { networkCalls += 1 },
  })
  await assert.rejects(
    () => transport({
      url: 'https://app.example.test/method-surface',
      method: 'customProbe',
      headers: {},
      body: null,
      timeoutMs: 5_000,
      maxResponseBytes: 1024,
      tls: { mode: 'PKIX_HOSTNAME' },
    }),
    /method|uppercase|canonical/i,
  )
  assert.equal(networkCalls, 0)
})

test('protected native HTTPS transport refuses CONNECT before DNS or request construction', async () => {
  let dnsCalls = 0
  let requestCalls = 0
  let beforeSendCalls = 0
  const transport = createHttpAuthedHttpsTransport({
    dnsLookup: (_hostname, _options, callback) => {
      dnsCalls += 1
      callback(null, [{ address: '93.184.216.34', family: 4 }])
    },
    httpsRequest: () => {
      requestCalls += 1
      throw new Error('CONNECT must be refused before request construction')
    },
  })

  await assert.rejects(
    transport({
      url: 'https://app.example.test/tunnel-target',
      method: 'CONNECT',
      headers: {},
      body: null,
      timeoutMs: 5_000,
      maxResponseBytes: 1024,
      tls: { mode: 'PKIX_HOSTNAME' },
      beforeSend: async () => { beforeSendCalls += 1 },
    }),
    /CONNECT|tunnel|method.*unsupported|method.*refused/i,
  )
  assert.equal(dnsCalls, 0)
  assert.equal(requestCalls, 0)
  assert.equal(beforeSendCalls, 0)
})

test('protected native HTTPS transport preserves a synchronous pre-DNS timeout as unsent', async () => {
  let dnsCalls = 0
  let requestCalls = 0
  const transport = createHttpAuthedHttpsTransport({
    dnsLookup: () => { dnsCalls += 1 },
    httpsRequest: () => { requestCalls += 1 },
    setTimer: (callback) => {
      callback()
      return { kind: 'synthetic-timer' }
    },
    clearTimer: () => {},
  })

  await assert.rejects(
    transport({
      url: 'https://app.example.test/pre-dns-timeout',
      method: 'GET',
      headers: {},
      body: null,
      timeoutMs: 5_000,
      maxResponseBytes: 1024,
      tls: { mode: 'PKIX_HOSTNAME' },
    }),
    (error) => error instanceof HttpAuthedClientError
      && error.code === 'HTTP_AUTHED_TIMEOUT'
      && error.request_may_have_been_sent === false,
  )
  assert.equal(dnsCalls, 0)
  assert.equal(requestCalls, 0)
})

test('protected native HTTPS transport preserves a DNS-pending timeout as unsent', async () => {
  let timerCallback
  let dnsCalls = 0
  let requestCalls = 0
  const transport = createHttpAuthedHttpsTransport({
    dnsLookup: () => { dnsCalls += 1 },
    httpsRequest: () => { requestCalls += 1 },
    setTimer: (callback) => {
      timerCallback = callback
      return { kind: 'synthetic-timer' }
    },
    clearTimer: () => {},
  })

  const pending = transport({
    url: 'https://app.example.test/dns-pending-timeout',
    method: 'GET',
    headers: {},
    body: null,
    timeoutMs: 5_000,
    maxResponseBytes: 1024,
    tls: { mode: 'PKIX_HOSTNAME' },
  })
  assert.equal(dnsCalls, 1)
  timerCallback()
  await assert.rejects(
    pending,
    (error) => error instanceof HttpAuthedClientError
      && error.code === 'HTTP_AUTHED_TIMEOUT'
      && error.request_may_have_been_sent === false,
  )
  assert.equal(requestCalls, 0)
})

test('protected HTTPS transport erases its private body copy when timer setup or cleanup throws', async (t) => {
  const supplied = Buffer.from('synthetic-timer-failure-body')
  const copies = []
  const originalFrom = Buffer.from
  t.mock.method(Buffer, 'from', function (value, ...args) {
    const copy = originalFrom.call(Buffer, value, ...args)
    if (value instanceof ArrayBuffer && value.byteLength === supplied.byteLength) copies.push(copy)
    return copy
  })
  const input = {
    url: 'https://app.example.test/timer-failure',
    method: 'POST',
    headers: {},
    body: supplied,
    timeoutMs: 5_000,
    maxResponseBytes: 1024,
    tls: { mode: 'PKIX_HOSTNAME' },
  }

  const setupFailure = createHttpAuthedHttpsTransport({
    setTimer: () => { throw new Error('synthetic timer setup failure') },
  })
  await assert.rejects(setupFailure(input), /timer setup failure/i)

  const cleanupFailure = createHttpAuthedHttpsTransport({
    dnsLookup: (_hostname, _options, callback) => queueMicrotask(() => {
      callback(new Error('synthetic DNS failure'))
    }),
    setTimer: () => ({ synthetic: 'timer' }),
    clearTimer: () => { throw new Error('synthetic timer cleanup failure') },
  })
  await assert.rejects(cleanupFailure(input), /DNS|synthetic DNS failure/i)

  assert.equal(copies.length, 2)
  assert.equal(copies.every((copy) => copy.every((byte) => byte === 0)), true)
})

test('a native HTTPS timer cleanup failure cannot overturn a settled response', async () => {
  const certificate = new X509Certificate(REFERENCE_TLS_CERTIFICATE).toLegacyObject()
  const dnsLookup = (_hostname, _options, callback) => queueMicrotask(() => callback(null, [
    { address: '93.184.216.34', family: 4 },
  ]))
  let clearTimerCalls = 0
  const httpsRequest = (url, options) => {
    const request = new EventEmitter()
    request.destroy = (error) => {
      request.destroyed = true
      if (error) queueMicrotask(() => request.emit('error', error))
    }
    request.end = () => {
      const response = new EventEmitter()
      response.statusCode = 204
      response.rawHeaders = ['ETag', '"synthetic-settled-response"']
      response.destroy = () => { response.destroyed = true }
      queueMicrotask(() => {
        request.emit('response', response)
        response.emit('end')
      })
    }
    queueMicrotask(() => {
      options.lookup(url.hostname, {}, (error) => {
        if (error) return request.emit('error', error)
        const socket = new EventEmitter()
        socket.encrypted = true
        socket.authorized = true
        request.emit('socket', socket)
        const identityError = options.checkServerIdentity(url.hostname, certificate)
        if (identityError) return request.emit('error', identityError)
        socket.emit('secureConnect')
      })
    })
    return request
  }
  const transport = createHttpAuthedHttpsTransport({
    dnsLookup,
    httpsRequest,
    setTimer: () => ({ kind: 'synthetic-timer' }),
    clearTimer: () => {
      clearTimerCalls += 1
      throw new Error('synthetic post-settlement timer cleanup failure')
    },
  })

  const result = await transport({
    url: 'https://reference-log.example.test/settled-timer-cleanup',
    method: 'GET',
    headers: {},
    body: null,
    timeoutMs: 5_000,
    maxResponseBytes: 1024,
    tls: { mode: 'PKIX_HOSTNAME' },
    beforeSend: async () => {},
  })

  assert.deepEqual(result, {
    status: 204,
    responseBytes: 0,
    responseHeaderNames: ['etag'],
  })
  assert.equal(clearTimerCalls, 1)
})

test('protected HTTPS transport retains response copies only for observation and reclaims them until handoff', async (t) => {
  const certificate = new X509Certificate(REFERENCE_TLS_CERTIFICATE).toLegacyObject()
  const unobservedChunk = Buffer.from('public')
  const observedPrefix = Buffer.from('abc')
  const observedOverflow = Buffer.from('def')
  const handedOffObserverChunk = Buffer.from('handed-off-observer-value')
  const rejectedObserverChunk = Buffer.from('rejected-observer-secret')
  const timedOutObserverChunk = Buffer.from('timed-out-observer-secret')
  const sourceChunks = new Set([
    unobservedChunk,
    observedPrefix,
    observedOverflow,
    handedOffObserverChunk,
    rejectedObserverChunk,
    timedOutObserverChunk,
  ])
  const copies = []
  const originalFrom = Buffer.from
  t.mock.method(Buffer, 'from', function (value, ...args) {
    const copy = originalFrom.call(Buffer, value, ...args)
    if (sourceChunks.has(value)) copies.push(copy)
    return copy
  })
  const dnsLookup = (_hostname, _options, callback) => queueMicrotask(() => callback(null, [
    { address: '93.184.216.34', family: 4 },
  ]))
  const send = async ({ chunks, maxResponseBytes, responseObserver, transportOptions = {} }) => {
    const httpsRequest = (url, options) => {
      const request = new EventEmitter()
      request.destroy = (error) => {
        request.destroyed = true
        if (error) queueMicrotask(() => request.emit('error', error))
      }
      request.end = () => {
        const response = new EventEmitter()
        response.statusCode = 200
        response.rawHeaders = ['Content-Type', 'application/json']
        response.destroy = () => { response.destroyed = true }
        queueMicrotask(() => {
          request.emit('response', response)
          for (const chunk of chunks) response.emit('data', chunk)
          response.emit('end')
        })
      }
      queueMicrotask(() => {
        options.lookup(url.hostname, {}, (error) => {
          if (error) return request.emit('error', error)
          const socket = new EventEmitter()
          socket.encrypted = true
          socket.authorized = true
          request.emit('socket', socket)
          const identityError = options.checkServerIdentity(url.hostname, certificate)
          if (identityError) return request.emit('error', identityError)
          socket.emit('secureConnect')
        })
      })
      return request
    }
    return createHttpAuthedHttpsTransport({ dnsLookup, httpsRequest, ...transportOptions })({
      url: 'https://reference-log.example.test/response-copy-ownership',
      method: 'GET',
      headers: {},
      body: null,
      timeoutMs: 5_000,
      maxResponseBytes,
      tls: { mode: 'PKIX_HOSTNAME' },
      responseObserver,
    })
  }

  await send({ chunks: [unobservedChunk], maxResponseBytes: 1024 })
  await assert.rejects(
    send({
      chunks: [observedPrefix, observedOverflow],
      maxResponseBytes: 4,
      responseObserver: async () => {},
    }),
    { code: 'HTTP_AUTHED_RESPONSE_LIMIT_EXCEEDED' },
  )

  let handedOffObserverCopies
  let handedOffObserverCopy
  await send({
    chunks: [handedOffObserverChunk],
    maxResponseBytes: 1024,
    responseObserver: async ({ bodyChunks }) => {
      handedOffObserverCopies = bodyChunks
      handedOffObserverCopy = bodyChunks[0]
    },
  })
  assert.deepEqual(handedOffObserverCopy, Buffer.from('handed-off-observer-value'))
  assert.equal(handedOffObserverCopies.length, 1)
  handedOffObserverCopy.fill(0)
  handedOffObserverCopies.length = 0

  let rejectedObserverCopies
  let rejectedObserverCopy
  await assert.rejects(
    send({
      chunks: [rejectedObserverChunk],
      maxResponseBytes: 1024,
      responseObserver: async ({ bodyChunks }) => {
        rejectedObserverCopies = bodyChunks
        rejectedObserverCopy = bodyChunks.shift()
        throw new Error('synthetic observer rejection')
      },
    }),
    { code: 'HTTP_AUTHED_RESPONSE_OBSERVER_FAILED' },
  )

  let fireTimeout
  let timedOutObserverCopies
  let timedOutObserverCopy
  await assert.rejects(
    send({
      chunks: [timedOutObserverChunk],
      maxResponseBytes: 1024,
      responseObserver: ({ bodyChunks }) => {
        timedOutObserverCopies = bodyChunks
        timedOutObserverCopy = bodyChunks.shift()
        fireTimeout()
        return new Promise(() => {})
      },
      transportOptions: {
        setTimer(callback) {
          fireTimeout = callback
          return { kind: 'synthetic-timer' }
        },
        clearTimer() { throw new Error('synthetic timeout timer cleanup failure') },
      },
    }),
    { code: 'HTTP_AUTHED_TIMEOUT' },
  )

  assert.equal(copies.length, 4)
  assert.equal(copies.every((copy) => copy.every((byte) => byte === 0)), true)
  assert.equal(rejectedObserverCopy.every((byte) => byte === 0), true)
  assert.equal(rejectedObserverCopies.length, 0)
  assert.equal(timedOutObserverCopy.every((byte) => byte === 0), true)
  assert.equal(timedOutObserverCopies.length, 0)
})

test('protected HTTPS transport settles when an observer transfers its body copy before rejecting', async () => {
  const certificate = new X509Certificate(REFERENCE_TLS_CERTIFICATE).toLegacyObject()
  const responseChunk = Buffer.alloc(16 * 1024, 0x61)
  const dnsLookup = (_hostname, _options, callback) => queueMicrotask(() => callback(null, [
    { address: '93.184.216.34', family: 4 },
  ]))
  const httpsRequest = (url, options) => {
    const request = new EventEmitter()
    request.destroy = (error) => {
      request.destroyed = true
      if (error) queueMicrotask(() => request.emit('error', error))
    }
    request.end = () => {
      const response = new EventEmitter()
      response.statusCode = 200
      response.rawHeaders = ['Content-Type', 'application/octet-stream']
      response.destroy = () => { response.destroyed = true }
      queueMicrotask(() => {
        request.emit('response', response)
        response.emit('data', responseChunk)
        response.emit('end')
      })
    }
    queueMicrotask(() => {
      options.lookup(url.hostname, {}, (error) => {
        if (error) return request.emit('error', error)
        const socket = new EventEmitter()
        socket.encrypted = true
        socket.authorized = true
        request.emit('socket', socket)
        const identityError = options.checkServerIdentity(url.hostname, certificate)
        if (identityError) return request.emit('error', identityError)
        socket.emit('secureConnect')
      })
    })
    return request
  }
  const transport = createHttpAuthedHttpsTransport({
    dnsLookup,
    httpsRequest,
    setTimer: () => ({ kind: 'synthetic-timer' }),
    clearTimer: () => {},
  })
  const pending = transport({
    url: 'https://reference-log.example.test/detached-observer-copy',
    method: 'GET',
    headers: {},
    body: null,
    timeoutMs: 5_000,
    maxResponseBytes: 32 * 1024,
    tls: { mode: 'PKIX_HOSTNAME' },
    responseObserver: async ({ bodyChunks }) => {
      Object.freeze(bodyChunks)
      structuredClone(bodyChunks[0], { transfer: [bodyChunks[0].buffer] })
      throw new Error('synthetic detached observer rejection')
    },
  })
  let watchdog
  try {
    await assert.rejects(
      Promise.race([
        pending,
        new Promise((_, reject) => {
          watchdog = setTimeout(() => reject(new Error('detached observer cleanup did not settle')), 500)
        }),
      ]),
      (error) => error?.code === 'HTTP_AUTHED_RESPONSE_OBSERVER_FAILED'
        && error.request_may_have_been_sent === true,
    )
  } finally {
    clearTimeout(watchdog)
  }
})

test('protected HTTPS transport preserves success when request.end detaches its private body', async () => {
  const certificate = new X509Certificate(REFERENCE_TLS_CERTIFICATE).toLegacyObject()
  const suppliedBody = Buffer.alloc(257, 0x62)
  const dnsLookup = (_hostname, _options, callback) => queueMicrotask(() => callback(null, [
    { address: '93.184.216.34', family: 4 },
  ]))
  let sentBytes = 0
  const httpsRequest = (url, options) => {
    const request = new EventEmitter()
    request.destroy = () => { request.destroyed = true }
    request.end = (body) => {
      sentBytes = body.byteLength
      assert.equal(body.byteOffset, 0)
      assert.equal(body.buffer.byteLength, body.byteLength)
      structuredClone(body.buffer, { transfer: [body.buffer] })
      assert.equal(body.byteLength, 0)
      const response = new EventEmitter()
      response.statusCode = 204
      response.rawHeaders = ['ETag', 'synthetic']
      response.destroy = () => { response.destroyed = true }
      queueMicrotask(() => {
        request.emit('response', response)
        response.emit('end')
      })
    }
    queueMicrotask(() => {
      options.lookup(url.hostname, {}, (error) => {
        if (error) return request.emit('error', error)
        const socket = new EventEmitter()
        socket.encrypted = true
        socket.authorized = true
        request.emit('socket', socket)
        const identityError = options.checkServerIdentity(url.hostname, certificate)
        if (identityError) return request.emit('error', identityError)
        socket.emit('secureConnect')
      })
    })
    return request
  }
  const transport = createHttpAuthedHttpsTransport({
    dnsLookup,
    httpsRequest,
    setTimer: () => ({ kind: 'synthetic-timer' }),
    clearTimer: () => {},
  })

  const result = await transport({
    url: 'https://reference-log.example.test/detached-request-body',
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream' },
    body: suppliedBody,
    timeoutMs: 5_000,
    maxResponseBytes: 1024,
    tls: { mode: 'PKIX_HOSTNAME' },
    beforeSend: async () => {},
  })
  assert.equal(sentBytes, 257)
  assert.equal(suppliedBody.every((byte) => byte === 0x62), true)
  assert.deepEqual(result, {
    status: 204,
    responseBytes: 0,
    responseHeaderNames: ['etag'],
  })
})

test('probe dispatch preserves success when an injected transport detaches the request body', async () => {
  const body = Buffer.alloc(257, 0x63)
  const { scope, candidate, expectedCampaignGrantSha256 } = campaign({
    method: 'POST',
    action: {
      request_body: {
        body_id: 'SYNTHETIC_DETACHED_REQUEST_BODY_0001',
        sha256: sha256Hex(body),
        byte_length: body.length,
        content_type: 'application/octet-stream',
        data_class: 'synthetic_non_phi',
      },
    },
  })
  const result = await dispatchHttpAuthedProbe({
    scope,
    action: candidate,
    expectedCampaignGrantSha256,
    credentialValue: CREDENTIAL,
    requestBodyBytes: body,
    now: NOW,
    beforeSend: VERIFY_BEFORE_SEND,
    transport: async (request) => {
      assert.equal(request.body.byteOffset, 0)
      assert.equal(request.body.buffer.byteLength, request.body.byteLength)
      structuredClone(request.body.buffer, { transfer: [request.body.buffer] })
      assert.equal(request.body.byteLength, 0)
      return { status: 204, responseBytes: 0, responseHeaderNames: [] }
    },
  })
  assert.equal(result.response.status, 204)
  assert.equal(body.every((byte) => byte === 0x63), true)
})

test('bounded observation cleanup ignores an overridden callback-visible byte fill', async () => {
  const responseBody = Buffer.from('{"ready":true}')
  responseBody.fill = () => { throw new Error('synthetic hostile fill') }
  const { scope, candidate } = campaign({ method: 'GET' })
  scope.schema_version = '1.1.0'
  scope.response_observation = {
    mode: 'JSON_SHAPE_ONLY',
    max_depth: 4,
    safe_key_names: ['ready'],
  }
  const expectedCampaignGrantSha256 = verifyHttpAuthedAuthorization({ scope, now: NOW })
    .campaignGrantSha256

  const result = await dispatchHttpAuthedProbe({
    scope,
    action: candidate,
    expectedCampaignGrantSha256,
    credentialValue: CREDENTIAL,
    now: NOW,
    beforeSend: VERIFY_BEFORE_SEND,
    transport: async (request) => {
      await request.responseObserver({
        status: 200,
        headers: [{ name: 'content-type', value: 'application/json' }],
        bodyChunks: [responseBody],
      })
      return {
        status: 200,
        responseBytes: responseBody.byteLength,
        responseHeaderNames: ['content-type'],
      }
    },
  })
  assert.equal(result.response.status, 200)
  assert.equal(responseBody.every((byte) => byte === 0), true)
})

test('protected HTTPS transport sends every authorized non-tunneling method once and erases its body copies', async () => {
  const certificate = new X509Certificate(REFERENCE_TLS_CERTIFICATE).toLegacyObject()
  const state = {
    requests: 0,
    ended: 0,
    beforeSend: 0,
    methods: [],
    bodies: [],
    sentBodies: [],
  }
  const dnsLookup = (_hostname, _options, callback) => queueMicrotask(() => callback(null, [
    { address: '93.184.216.34', family: 4 },
  ]))
  const httpsRequest = (url, options) => {
    state.requests += 1
    state.url = url
    state.options = options
    state.methods.push(options.method)
    const request = new EventEmitter()
    request.destroy = (error) => { request.destroyed = true; request.destroyError = error }
    request.end = (body) => {
      state.ended += 1
      state.body = body
      state.bodies.push(body)
      state.sentBodies.push(Buffer.from(body))
      const response = new EventEmitter()
      response.statusCode = 302
      response.rawHeaders = [
        'Location', 'https://redirect.example.test/private',
        'Set-Cookie', 'secret-response-cookie',
      ]
      response.destroy = () => { response.destroyed = true }
      queueMicrotask(() => {
        request.emit('response', response)
        response.emit('data', Buffer.from('discarded response body'))
        response.emit('end')
      })
    }
    queueMicrotask(() => {
      options.lookup(url.hostname, {}, (error) => {
        if (error) return request.emit('error', error)
        const socket = new EventEmitter()
        socket.encrypted = true
        socket.authorized = true
        request.emit('socket', socket)
        const identityError = options.checkServerIdentity(url.hostname, certificate)
        if (identityError) return request.emit('error', identityError)
        socket.emit('secureConnect')
      })
    })
    return request
  }
  const transport = createHttpAuthedHttpsTransport({ dnsLookup, httpsRequest })
  const methods = [
    'POST', 'PUT', 'PATCH', 'DELETE', 'TRACE',
    'PROPFIND', 'COPY', 'MOVE', 'LOCK', 'UNLOCK', 'X-EXAMPLE-AUDIT',
  ]
  assert.equal(methods.includes('CONNECT'), false)
  const results = []
  for (const [index, method] of methods.entries()) {
    results.push(await transport({
      url: 'https://reference-log.example.test/method-surface',
      method,
      headers: { authorization: 'Bearer synthetic-secret' },
      body: Buffer.from('synthetic-body'),
      timeoutMs: 5_000,
      maxResponseBytes: 1024,
      tls: { mode: 'PKIX_HOSTNAME' },
      beforeSend: async () => {
        assert.equal(state.ended, index)
        state.beforeSend += 1
      },
    }))
  }

  assert.equal(state.requests, methods.length)
  assert.equal(state.beforeSend, methods.length)
  assert.equal(state.ended, methods.length)
  assert.deepEqual(state.methods, methods)
  for (const body of state.sentBodies) assert.deepEqual(body, Buffer.from('synthetic-body'))
  for (const body of state.bodies) {
    assert.equal(body.every((byte) => byte === 0), true)
  }
  for (const result of results) {
    assert.deepEqual(result, {
      status: 302,
      responseBytes: Buffer.byteLength('discarded response body'),
      responseHeaderNames: ['location', 'set-cookie'],
    })
  }
  assert.doesNotMatch(JSON.stringify(results), /secret-response-cookie|synthetic-secret|synthetic-body/)
})

test('operator-attested dispatcher executes a verified custom method without returning sensitive values', async () => {
  const urlMarker = 'SYNTHETIC_PATIENT_IDENTIFIER_8675309'
  const { scope, candidate, expectedCampaignGrantSha256 } = campaign({
    action: {
      url: `https://app.example.test/discovered/${urlMarker}?subject=${urlMarker}`,
    },
  })
  let calls = 0
  const result = await dispatchHttpAuthedProbe({
    scope,
    action: candidate,
    expectedCampaignGrantSha256,
    credentialValue: CREDENTIAL,
    now: NOW,
    beforeSend: VERIFY_BEFORE_SEND,
    transport: async (request) => {
      await request.beforeSend()
      calls += 1
      return { status: 200, responseBytes: 42, responseHeaderNames: ['content-type'] }
    },
  })

  assert.equal(calls, 1)
  assert.equal(result.action.method, 'PROPFIND')
  assert.equal(result.response.bytes, 42)
  const serialized = JSON.stringify(result)
  assert.doesNotMatch(serialized, /synthetic-credential|SYNTHETIC_TEST_CREDENTIAL/)
  assert.doesNotMatch(serialized, new RegExp(urlMarker))
})

test('operator-attested dispatcher supports an explicitly sealed empty synthetic request body', async () => {
  const emptyBody = Buffer.alloc(0)
  const { scope, candidate, expectedCampaignGrantSha256 } = campaign({
    method: 'POST',
    action: {
      request_body: {
        body_id: 'SYNTHETIC_EMPTY_REQUEST_BODY_0001',
        sha256: sha256Hex(emptyBody),
        byte_length: 0,
        content_type: 'application/json',
        data_class: 'synthetic_non_phi',
      },
    },
  })
  let sent = 0

  await dispatchHttpAuthedProbe({
    scope,
    action: candidate,
    requestBodyBytes: emptyBody,
    expectedCampaignGrantSha256,
    credentialValue: CREDENTIAL,
    now: NOW,
    beforeSend: VERIFY_BEFORE_SEND,
    transport: async (request) => {
      await request.beforeSend()
      assert.equal(request.body.length, 0)
      sent += 1
      return { status: 204, responseBytes: 0, responseHeaderNames: [] }
    },
  })
  assert.equal(sent, 1)
})

test('operator-attested dispatcher propagates a failed authorization recheck before send', async () => {
  const { scope, candidate, expectedCampaignGrantSha256 } = campaign()
  const widened = structuredClone(scope)
  widened.authorization.authorized_scope.methods.push('SEARCH')
  let sent = 0

  await assert.rejects(
    () => dispatchHttpAuthedProbe({
      scope,
      action: candidate,
      expectedCampaignGrantSha256,
      credentialValue: CREDENTIAL,
      now: NOW,
      beforeSend: async () => {
        const rechecked = verifyHttpAuthedAuthorization({ scope: widened, now: NOW })
        assert.equal(rechecked.campaignGrantSha256, expectedCampaignGrantSha256)
      },
      transport: async (request) => {
        await request.beforeSend()
        sent += 1
      },
    }),
    (error) => error.code === 'HTTP_AUTHED_BEFORE_SEND_REJECTED',
  )
  assert.equal(sent, 0)
})

test('operator-attested dispatcher propagates controller candidate-binding rejection before send', async () => {
  const { scope, candidate, expectedCampaignGrantSha256 } = campaign()
  const driftedCandidate = {
    ...candidate,
    sequence: candidate.sequence + 1,
    url: 'https://app.example.test/discovered/other-authorized-path',
  }
  let sent = 0

  await assert.rejects(
    () => dispatchHttpAuthedProbe({
      scope,
      action: candidate,
      expectedCampaignGrantSha256,
      credentialValue: CREDENTIAL,
      now: NOW,
      beforeSend: async () => assert.deepEqual(driftedCandidate, candidate),
      transport: async (request) => {
        await request.beforeSend()
        sent += 1
      },
    }),
    (error) => error.code === 'HTTP_AUTHED_BEFORE_SEND_REJECTED',
  )
  assert.equal(sent, 0)
})
