import assert from 'node:assert/strict'
import { X509Certificate } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import {
  createHttpAuthedHttpsTransport,
  dispatchHttpAuthedProbe,
} from '../scripts/lib/http-authed-client.mjs'
import {
  sha256Hex,
  verifyHttpAuthedWrittenAuthorization,
} from '../scripts/lib/http-authed-contracts.mjs'
import { writtenScope } from './helpers/http-authed-fixtures.mjs'
import { httpAuthedResponseByteBucket } from '../scripts/lib/http-authed-response-metadata.mjs'
import { REFERENCE_TLS_CERTIFICATE } from './fixtures/reference-transparency-tls.mjs'
import { main as httpAuthedMain } from '../scripts/http-authed.mjs'

const DOCUMENT_BYTES = Buffer.from('synthetic authorization fixture')
const NOW = new Date('2026-08-16T12:00:00.000Z')
const CREDENTIAL = Buffer.from('synthetic-credential-value')
const VERIFY_BEFORE_SEND = async () => {}

function campaign({ method = 'PROPFIND', action = {} } = {}) {
  const scope = writtenScope({ actionCount: 1 })
  if (!scope.authorization.authorized_scope.methods.includes(method)) {
    scope.authorization.authorized_scope.methods.push(method)
  }
  scope.credential.binding_sha256 = sha256Hex(CREDENTIAL)
  const candidate = {
    kind: 'probe',
    sequence: 2_000_000,
    test_category: 'api_security',
    method,
    url: 'https://peerstar-test.example.test/discovered/method-surface',
    expected_effect: 'none',
    ...action,
  }
  const expectedCampaignGrantSha256 = verifyHttpAuthedWrittenAuthorization({
    scope,
    documentBytes: DOCUMENT_BYTES,
    now: NOW,
  }).campaignGrantSha256
  return { scope, candidate, expectedCampaignGrantSha256 }
}

test('method-complete written probe reaches one injected transport without an action-count gate', async () => {
  const { scope, candidate, expectedCampaignGrantSha256 } = campaign()
  const calls = []
  const result = await dispatchHttpAuthedProbe({
    scope,
    action: candidate,
    documentBytes: DOCUMENT_BYTES,
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
  assert.equal(calls[0].headers['user-agent'], 'red-team-audit-http-authed/0.12')
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
  for (const kind of ['bearer', 'cookie']) {
    const { scope, candidate } = campaign({ method: 'GET' })
    scope.credential.kind = kind
    scope.schema_version = '1.1.0'
    scope.response_observation = {
      mode: 'JSON_SHAPE_ONLY',
      max_depth: 4,
      safe_key_names: ['id', 'label', 'records'],
    }
    const expectedCampaignGrantSha256 = verifyHttpAuthedWrittenAuthorization({
      scope,
      documentBytes: DOCUMENT_BYTES,
      now: NOW,
    }).campaignGrantSha256
    const result = await dispatchHttpAuthedProbe({
      scope,
      action: candidate,
      documentBytes: DOCUMENT_BYTES,
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
        await request.responseObserver({
          status: 200,
          headers: [{ name: 'content-type', value: 'application/json' }],
          bodyChunks: [Buffer.from(JSON.stringify({
            records: [{ id: 8675309, label: responseValue }],
          }))],
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
  const expectedCampaignGrantSha256 = verifyHttpAuthedWrittenAuthorization({
    scope,
    documentBytes: DOCUMENT_BYTES,
    now: NOW,
  }).campaignGrantSha256
  const result = await dispatchHttpAuthedProbe({
    scope,
    action: candidate,
    documentBytes: DOCUMENT_BYTES,
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
  const { scope, candidate } = campaign({ method: 'GET' })
  scope.schema_version = '1.2.0'
  scope.response_observation = {
    mode: 'ASPNET_D_JSON_SHAPE_ONLY',
    max_depth: 4,
    safe_key_names: ['d', 'value'],
  }
  const expectedCampaignGrantSha256 = verifyHttpAuthedWrittenAuthorization({
    scope,
    documentBytes: DOCUMENT_BYTES,
    now: NOW,
  }).campaignGrantSha256

  let downstreamObserverCalls = 0
  const result = await dispatchHttpAuthedProbe({
    scope,
    action: candidate,
    documentBytes: DOCUMENT_BYTES,
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
        bodyChunks: [Buffer.from(JSON.stringify({ d: `<html>${marker}</html>` }))],
      })
      return {
        status: 500,
        responseBytes: 3000,
        responseHeaderNames: ['content-type', 'x-synthetic-subject-8675309'],
      }
    },
  })

  assert.equal(downstreamObserverCalls, 0)
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
  const observationCampaignGrantSha256 = verifyHttpAuthedWrittenAuthorization({
    scope,
    documentBytes: DOCUMENT_BYTES,
    now: NOW,
  }).campaignGrantSha256
  const result = await dispatchHttpAuthedProbe({
    scope,
    action: candidate,
    documentBytes: DOCUMENT_BYTES,
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
  const { scope, candidate } = campaign({ method: 'GET' })
  scope.schema_version = '1.1.0'
  scope.response_observation = {
    mode: 'JSON_SHAPE_ONLY',
    max_depth: 4,
    safe_key_names: ['value'],
  }
  const expectedCampaignGrantSha256 = verifyHttpAuthedWrittenAuthorization({
    scope,
    documentBytes: DOCUMENT_BYTES,
    now: NOW,
  }).campaignGrantSha256

  await assert.rejects(
    () => dispatchHttpAuthedProbe({
      scope,
      action: candidate,
      documentBytes: DOCUMENT_BYTES,
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
          bodyChunks: [Buffer.from('{"value":true}')],
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
})

test('document, campaign, and scope drift fail before the transport boundary', async () => {
  const { scope, candidate, expectedCampaignGrantSha256 } = campaign()
  let calls = 0
  const transport = async () => { calls += 1 }
  const attempts = [
    {
      action: { ...candidate, method: 'SEARCH' },
      documentBytes: DOCUMENT_BYTES,
      expectedCampaignGrantSha256,
    },
    {
      action: candidate,
      documentBytes: Buffer.from('substituted authorization'),
      expectedCampaignGrantSha256,
    },
    {
      action: candidate,
      documentBytes: DOCUMENT_BYTES,
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
      /method|document|campaign|grant|digest|scope/i,
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
  const transport = async (request) => {
    calls.push(request)
    return { status: 204, responseBytes: 0, responseHeaderNames: [] }
  }

  await assert.rejects(
    () => dispatchHttpAuthedProbe({
      scope,
      action: candidate,
      documentBytes: DOCUMENT_BYTES,
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
      documentBytes: DOCUMENT_BYTES,
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
    documentBytes: DOCUMENT_BYTES,
    expectedCampaignGrantSha256,
    credentialValue: CREDENTIAL,
    requestBodyBytes: body,
    now: NOW,
    beforeSend: VERIFY_BEFORE_SEND,
    transport,
  })
  assert.equal(calls.length, 1)
  assert.deepEqual(calls[0].body, body)
  assert.doesNotMatch(JSON.stringify(result), /SYNTHETIC_ACTIVE_PROBE_BODY_0001|synthetic-credential/)
})

test('declared mutation actions stay out of the probe dispatcher', async () => {
  const { scope, expectedCampaignGrantSha256 } = campaign()
  let calls = 0
  await assert.rejects(
    () => dispatchHttpAuthedProbe({
      scope,
      action: scope.requests[0],
      documentBytes: DOCUMENT_BYTES,
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
      documentBytes: DOCUMENT_BYTES,
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
      url: 'https://peerstar-test.example.test/method-surface',
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
      url: 'https://peerstar-test.example.test/tunnel-target',
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

test('protected HTTPS transport sends every authorized non-tunneling method once and never follows redirects', async () => {
  const certificate = new X509Certificate(REFERENCE_TLS_CERTIFICATE).toLegacyObject()
  const state = { requests: 0, ended: 0, beforeSend: 0, methods: [], bodies: [] }
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
    'PROPFIND', 'COPY', 'MOVE', 'LOCK', 'UNLOCK', 'X-PEERSTAR-AUDIT',
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
  for (const body of state.bodies) assert.deepEqual(body, Buffer.from('synthetic-body'))
  for (const result of results) {
    assert.deepEqual(result, {
      status: 302,
      responseBytes: Buffer.byteLength('discarded response body'),
      responseHeaderNames: ['location', 'set-cookie'],
    })
  }
  assert.doesNotMatch(JSON.stringify(results), /secret-response-cookie|synthetic-secret|synthetic-body/)
})

test('probe-written CLI executes a verified custom method without printing sensitive values', async (t) => {
  const { scope, candidate, expectedCampaignGrantSha256 } = campaign()
  const urlMarker = 'SYNTHETIC_PATIENT_IDENTIFIER_8675309'
  candidate.url = `https://peerstar-test.example.test/discovered/${urlMarker}?subject=${urlMarker}`
  const directory = await mkdtemp(join(tmpdir(), 'rta-http-authed-probe-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  const scopePath = join(directory, 'scope.json')
  const documentPath = join(directory, 'authorization.txt')
  const candidatePath = join(directory, 'candidate.json')
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  await writeFile(documentPath, DOCUMENT_BYTES)
  await writeFile(candidatePath, JSON.stringify(candidate), 'utf8')
  let calls = 0
  let output = ''

  await httpAuthedMain([
    'probe-written',
    '--scope', scopePath,
    '--authorization-document', documentPath,
    '--candidate', candidatePath,
    '--campaign-grant-sha256', expectedCampaignGrantSha256,
    '--operator-id', scope.authorization.operator_id,
    '--confirm-authorization-current',
    '--json',
  ], {
    clock: () => NOW,
    env: { SYNTHETIC_TEST_CREDENTIAL: CREDENTIAL.toString('utf8') },
    transport: async (request) => {
      await request.beforeSend()
      calls += 1
      return { status: 200, responseBytes: 42, responseHeaderNames: ['content-type'] }
    },
    write: (text) => { output += text },
  })

  assert.equal(calls, 1)
  const result = JSON.parse(output)
  assert.equal(result.action.method, 'PROPFIND')
  assert.equal(result.response.bytes, 42)
  assert.doesNotMatch(output, /synthetic-credential|SYNTHETIC_TEST_CREDENTIAL/)
  assert.doesNotMatch(output, new RegExp(urlMarker))
})

test('probe-written supports an explicitly sealed empty synthetic request body', async (t) => {
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
  const directory = await mkdtemp(join(tmpdir(), 'rta-http-authed-empty-body-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  const scopePath = join(directory, 'scope.json')
  const documentPath = join(directory, 'authorization.txt')
  const candidatePath = join(directory, 'candidate.json')
  const bodyPath = join(directory, 'body.bin')
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  await writeFile(documentPath, DOCUMENT_BYTES)
  await writeFile(candidatePath, JSON.stringify(candidate), 'utf8')
  await writeFile(bodyPath, emptyBody)
  let sent = 0

  await httpAuthedMain([
    'probe-written',
    '--scope', scopePath,
    '--authorization-document', documentPath,
    '--candidate', candidatePath,
    '--request-body', bodyPath,
    '--campaign-grant-sha256', expectedCampaignGrantSha256,
    '--operator-id', scope.authorization.operator_id,
    '--confirm-authorization-current',
    '--json',
  ], {
    clock: () => NOW,
    env: { SYNTHETIC_TEST_CREDENTIAL: CREDENTIAL.toString('utf8') },
    transport: async (request) => {
      await request.beforeSend()
      assert.equal(request.body.length, 0)
      sent += 1
      return { status: 204, responseBytes: 0, responseHeaderNames: [] }
    },
    write: () => {},
  })
  assert.equal(sent, 1)
})

test('probe-written rereads the campaign grant immediately before transport send', async (t) => {
  const { scope, candidate, expectedCampaignGrantSha256 } = campaign()
  const directory = await mkdtemp(join(tmpdir(), 'rta-http-authed-presend-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  const scopePath = join(directory, 'scope.json')
  const documentPath = join(directory, 'authorization.txt')
  const candidatePath = join(directory, 'candidate.json')
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  await writeFile(documentPath, DOCUMENT_BYTES)
  await writeFile(candidatePath, JSON.stringify(candidate), 'utf8')
  let sent = 0

  await assert.rejects(
    () => httpAuthedMain([
      'probe-written',
      '--scope', scopePath,
      '--authorization-document', documentPath,
      '--candidate', candidatePath,
      '--campaign-grant-sha256', expectedCampaignGrantSha256,
      '--operator-id', scope.authorization.operator_id,
      '--confirm-authorization-current',
      '--json',
    ], {
      clock: () => NOW,
      env: { SYNTHETIC_TEST_CREDENTIAL: CREDENTIAL.toString('utf8') },
      transport: async (request) => {
        const widened = structuredClone(scope)
        widened.authorization.authorized_scope.methods.push('SEARCH')
        await writeFile(scopePath, JSON.stringify(widened), 'utf8')
        await request.beforeSend()
        sent += 1
      },
      write: () => {},
    }),
    /campaign|grant|digest|scope/i,
  )
  assert.equal(sent, 0)
})

test('probe-written refuses candidate drift immediately before transport send', async (t) => {
  const { scope, candidate, expectedCampaignGrantSha256 } = campaign()
  const directory = await mkdtemp(join(tmpdir(), 'rta-http-authed-candidate-presend-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  const scopePath = join(directory, 'scope.json')
  const documentPath = join(directory, 'authorization.txt')
  const candidatePath = join(directory, 'candidate.json')
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  await writeFile(documentPath, DOCUMENT_BYTES)
  await writeFile(candidatePath, JSON.stringify(candidate), 'utf8')
  let sent = 0

  await assert.rejects(
    () => httpAuthedMain([
      'probe-written',
      '--scope', scopePath,
      '--authorization-document', documentPath,
      '--candidate', candidatePath,
      '--campaign-grant-sha256', expectedCampaignGrantSha256,
      '--operator-id', scope.authorization.operator_id,
      '--confirm-authorization-current',
      '--json',
    ], {
      clock: () => NOW,
      env: { SYNTHETIC_TEST_CREDENTIAL: CREDENTIAL.toString('utf8') },
      transport: async (request) => {
        await writeFile(candidatePath, JSON.stringify({
          ...candidate,
          sequence: candidate.sequence + 1,
          url: 'https://peerstar-test.example.test/discovered/other-authorized-path',
        }), 'utf8')
        await request.beforeSend()
        sent += 1
      },
      write: () => {},
    }),
    /candidate|action|changed|binding/i,
  )
  assert.equal(sent, 0)
})
