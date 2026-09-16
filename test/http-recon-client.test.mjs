import assert from 'node:assert/strict'
import { createHash, X509Certificate } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { test } from 'node:test'

import {
  HttpReconStopCondition,
  fetchHttpsProof,
  probeHttps,
  resolveHttpReconDns,
} from '../scripts/lib/http-recon-client.mjs'
import {
  REFERENCE_TLS_CERTIFICATE,
} from './fixtures/reference-transparency-tls.mjs'
import {
  createHttpReconRequestHeaderDescriptor,
} from '../scripts/lib/http-recon-request-headers.mjs'

const HOSTNAME = 'reference-log.example.test'
const URL_VALUE = `https://${HOSTNAME}/authorized`
const PUBLIC_ANSWERS = [
  { address: '93.184.216.34', family: 4 },
  { address: '1.1.1.1', family: 4 },
]
const CERTIFICATE = new X509Certificate(REFERENCE_TLS_CERTIFICATE)
const CERTIFICATE_OBJECT = CERTIFICATE.toLegacyObject()
const TLS_PIN = createHash('sha256')
  .update(CERTIFICATE.publicKey.export({ type: 'spki', format: 'der' }))
  .digest('hex')

function digest(value) {
  return createHash('sha256').update(value).digest('hex')
}

function retainedHeaders(result, name) {
  return result.response_headers
    .filter((header) => header.name === name)
    .map((header) => header.value)
}

function rawHeaders(headers) {
  const output = []
  for (const [name, rawValue] of Object.entries(headers)) {
    const values = Array.isArray(rawValue) ? rawValue : [rawValue]
    for (const value of values) output.push(name, String(value))
  }
  return output
}

class FakeSocket extends EventEmitter {
  constructor(authorized = true) {
    super()
    this.encrypted = true
    this.authorized = authorized
    this.remoteAddress = PUBLIC_ANSWERS[0].address
  }

  getProtocol() {
    return 'TLSv1.3'
  }

  getCipher() {
    return { standardName: 'TLS_AES_256_GCM_SHA384' }
  }
}

class FakeResponse extends EventEmitter {
  constructor({ status, headers, socket }) {
    super()
    this.statusCode = status
    this.headers = headers
    this.rawHeaders = rawHeaders(headers)
    this.complete = true
    this.socket = socket
    this.destroyed = false
  }

  destroy(error) {
    this.destroyed = true
    this.destroyError = error
  }
}

class FakeRequest extends EventEmitter {
  constructor(onEnd) {
    super()
    this.onEnd = onEnd
    this.ended = false
    this.destroyed = false
    this.endArguments = null
  }

  end(...args) {
    this.ended = true
    this.endArguments = args
    this.onEnd()
  }

  destroy(error) {
    this.destroyed = true
    this.destroyError = error
  }
}

function createHarness({
  answers = PUBLIC_ANSWERS,
  status = 200,
  headers = { 'content-type': 'text/plain' },
  chunks = [Buffer.from('observed response')],
  autoRespond = true,
  certificate = CERTIFICATE_OBJECT,
  socketAuthorized = true,
} = {}) {
  const state = {
    dnsCalls: 0,
    httpsCalls: 0,
    request: undefined,
    response: undefined,
    requestUrl: undefined,
    requestOptions: undefined,
    pinnedLookup: undefined,
  }
  let sentResolve
  state.sent = new Promise((resolve) => {
    sentResolve = resolve
  })

  const dnsLookup = (hostname, options, callback) => {
    state.dnsCalls += 1
    state.dnsHostname = hostname
    state.dnsOptions = options
    queueMicrotask(() => callback(null, answers.map((answer) => ({
      ...answer,
    }))))
  }

  const httpsRequest = (url, options) => {
    state.httpsCalls += 1
    state.requestUrl = url
    state.requestOptions = options
    const socket = new FakeSocket(socketAuthorized)
    const emitResponse = () => {
      sentResolve()
      if (!autoRespond || state.request.destroyed) return
      queueMicrotask(() => {
        if (state.request.destroyed) return
        const response = new FakeResponse({ status, headers, socket })
        state.response = response
        state.request.emit('response', response)
        if (response.destroyed) return
        for (const chunk of chunks) {
          response.emit('data', Buffer.from(chunk))
          if (response.destroyed) return
        }
        response.emit('end')
      })
    }
    const request = new FakeRequest(emitResponse)
    state.request = request
    queueMicrotask(() => {
      options.lookup(url.hostname, { family: options.family }, (
        lookupError,
        address,
        family,
      ) => {
        state.pinnedLookup = { lookupError, address, family }
        if (lookupError) {
          request.emit('error', lookupError)
          return
        }
        request.emit('socket', socket)
        const identityError = options.checkServerIdentity(
          url.hostname,
          certificate,
        )
        if (identityError) {
          request.emit('error', identityError)
          return
        }
        socket.emit('secureConnect')
      })
    })
    return request
  }

  state.dependencies = {
    dnsLookup,
    httpsRequest,
    clock: (() => {
      let current = 0
      return () => {
        current += 5
        return current
      }
    })(),
  }
  return state
}

function baseOptions(harness, overrides = {}) {
  return {
    url: URL_VALUE,
    method: 'GET',
    tlsVerificationMode: 'PKIX_HOSTNAME_AND_SPKI_PIN',
    tlsSpkiSha256: TLS_PIN,
    timeoutMs: 5_000,
    maxResponseBytes: 1024,
    dependencies: harness.dependencies,
    ...overrides,
  }
}

test('probe uses one pinned, bodyless HTTPS request and retains no body', async () => {
  const body = Buffer.from('bounded observation')
  const harness = createHarness({
    headers: {
      'access-control-allow-credentials': 'true',
      'access-control-allow-origin': '*',
      'access-control-expose-headers': 'x-safe',
      'content-type': 'text/plain; charset=utf-8',
      'set-cookie': ['session=secret', 'other=secret'],
      location: 'https://elsewhere.example/path?token=secret',
      'x-private-debug': 'must not be retained',
    },
    chunks: [body.subarray(0, 5), body.subarray(5)],
  })
  let beforeSend
  const result = await probeHttps(baseOptions(harness, {
    beforeSend: async (context) => {
      beforeSend = context
      assert.equal(harness.request.ended, false)
    },
  }))

  assert.equal(harness.dnsCalls, 1)
  assert.deepEqual(harness.dnsOptions, { all: true, verbatim: true })
  assert.equal(harness.httpsCalls, 1)
  assert.equal(harness.requestUrl.href, new URL(URL_VALUE).href)
  assert.deepEqual(harness.pinnedLookup, {
    lookupError: null,
    address: PUBLIC_ANSWERS[0].address,
    family: 4,
  })
  assert.equal(harness.requestOptions.agent, false)
  assert.equal(harness.requestOptions.servername, HOSTNAME)
  assert.equal(harness.requestOptions.rejectUnauthorized, true)
  assert.equal(harness.requestOptions.minVersion, 'TLSv1.2')
  assert.deepEqual(harness.requestOptions.ALPNProtocols, ['http/1.1'])
  assert.deepEqual(harness.requestOptions.headers, {
    accept: '*/*',
    'accept-encoding': 'identity',
    'cache-control': 'no-store',
    connection: 'close',
    'user-agent': 'red-team-audit-http-recon/0.16',
    host: HOSTNAME,
  })
  assert.deepEqual(harness.request.endArguments, [])
  assert.equal(beforeSend.tls.spki_sha256, TLS_PIN)
  assert.equal(beforeSend.tls.authorized, true)
  assert.equal(beforeSend.tls.verification_mode, 'PKIX_HOSTNAME_AND_SPKI_PIN')
  assert.equal(result.status, 200)
  assert.equal(result.body.bytes, null)
  assert.equal(result.body.retained, false)
  assert.equal(result.body.size, body.length)
  assert.equal(result.body.sha256, digest(body))
  assert.equal(result.body.truncated, false)
  assert.deepEqual(retainedHeaders(result, 'set-cookie'), ['[REDACTED]'])
  assert.deepEqual(retainedHeaders(result, 'location'), ['[REDACTED]'])
  assert.deepEqual(retainedHeaders(result, 'access-control-allow-origin'), ['*'])
  assert.deepEqual(retainedHeaders(result, 'access-control-allow-credentials'), ['true'])
  assert.deepEqual(retainedHeaders(result, 'access-control-expose-headers'), ['x-safe'])
  assert.deepEqual(retainedHeaders(result, 'x-private-debug'), [])
  assert.deepEqual(
    result.response_header_summary.redacted_names,
    ['location', 'set-cookie'],
  )
  assert.equal(result.dns.selected_ip, PUBLIC_ANSWERS[0].address)
  assert.deepEqual(result.dns.answers, [
    PUBLIC_ANSWERS[1],
    PUBLIC_ANSWERS[0],
  ])
  assert.equal(result.tls.spki_sha256, TLS_PIN)
  assert.equal(result.tls.verification_mode, 'PKIX_HOSTNAME_AND_SPKI_PIN')
  assert.equal(result.tls.protocol, 'TLSv1.3')
  assert.equal(result.request_may_have_been_sent, true)
  assert.ok(result.timing.total_ms >= 0)
})

test('probe expands one sealed diagnostic header profile without exposing its value to evidence', async () => {
  const harness = createHarness()
  const descriptor = createHttpReconRequestHeaderDescriptor({
    profile: 'x-forwarded-for-loopback-v1',
    method: 'GET',
  })
  let beforeSend
  await probeHttps(baseOptions(harness, {
    requestHeaderProfile: descriptor,
    beforeSend: async (context) => { beforeSend = context },
  }))

  assert.equal(harness.requestOptions.headers['x-forwarded-for'], '127.0.0.1')
  assert.deepEqual(beforeSend.request_headers, descriptor)
  assert.equal(JSON.stringify(beforeSend).includes('127.0.0.1'), false)
  assert.deepEqual(harness.request.endArguments, [])
})

test('hostile-origin profile emits one fixed Origin and retains the returned CORS policy', async () => {
  const harness = createHarness({
    headers: {
      'access-control-allow-origin': '*',
      'access-control-allow-credentials': 'true',
    },
  })
  const descriptor = createHttpReconRequestHeaderDescriptor({
    profile: 'cors-hostile-origin-get-v1',
    method: 'GET',
  })
  let beforeSend
  const result = await probeHttps(baseOptions(harness, {
    requestHeaderProfile: descriptor,
    beforeSend: async (context) => { beforeSend = context },
  }))

  assert.equal(harness.requestOptions.headers.origin, 'https://red-team-audit.invalid')
  assert.deepEqual(beforeSend.request_headers, descriptor)
  assert.equal(JSON.stringify(beforeSend).includes('red-team-audit.invalid'), false)
  assert.deepEqual(retainedHeaders(result, 'access-control-allow-origin'), ['*'])
  assert.deepEqual(retainedHeaders(result, 'access-control-allow-credentials'), ['true'])
  assert.equal(JSON.stringify(result).includes('red-team-audit.invalid'), false)
  assert.deepEqual(harness.request.endArguments, [])
})

test('proof fetches and forged diagnostic descriptors fail before I/O', async () => {
  const descriptor = createHttpReconRequestHeaderDescriptor({
    profile: 'x-forwarded-for-loopback-v1',
    method: 'GET',
  })
  for (const [mode, requestHeaderProfile] of [
    ['proof', descriptor],
    ['probe', { ...descriptor, header_set_sha256: '0'.repeat(64) }],
  ]) {
    const harness = createHarness()
    const call = mode === 'proof' ? fetchHttpsProof : probeHttps
    await assert.rejects(
      call(baseOptions(harness, {
        requestHeaderProfile,
        ...(mode === 'proof' ? { maxProofBodyBytes: 1024 } : {}),
      })),
      /diagnostic|profile|descriptor/i,
    )
    assert.equal(harness.dnsCalls, 0)
    assert.equal(harness.httpsCalls, 0)
  }
})

test('probe can use PKIX and hostname validation without an advance SPKI pin', async () => {
  const harness = createHarness()
  const result = await probeHttps(baseOptions(harness, {
    tlsVerificationMode: 'PKIX_HOSTNAME',
    tlsSpkiSha256: undefined,
  }))
  assert.equal(harness.dnsCalls, 1)
  assert.equal(harness.httpsCalls, 1)
  assert.equal(harness.requestOptions.rejectUnauthorized, true)
  assert.equal(harness.requestOptions.servername, HOSTNAME)
  assert.equal(result.tls.authorized, true)
  assert.equal(result.tls.verification_mode, 'PKIX_HOSTNAME')
  assert.equal(result.tls.spki_sha256, TLS_PIN)
  assert.equal(result.tls.certificate_sha256, digest(CERTIFICATE.raw))
})

test('target-control proof transport still requires an advance SPKI pin', async () => {
  const harness = createHarness()
  await assert.rejects(
    fetchHttpsProof(baseOptions(harness, {
      tlsVerificationMode: 'PKIX_HOSTNAME_AND_SPKI_PIN',
      tlsSpkiSha256: undefined,
      maxProofBodyBytes: 1024,
    })),
    (error) => {
      assert.equal(error.code, 'HTTP_RECON_INVALID_REQUEST')
      assert.match(error.message, /do not describe one policy/)
      assert.equal(error.request_may_have_been_sent, false)
      return true
    },
  )
  assert.equal(harness.dnsCalls, 0)
  assert.equal(harness.httpsCalls, 0)
})

test('TLS verification mode cannot silently add or drop a pin', async () => {
  for (const override of [
    {
      tlsVerificationMode: 'PKIX_HOSTNAME',
      tlsSpkiSha256: TLS_PIN,
    },
    {
      tlsVerificationMode: 'PKIX_HOSTNAME_AND_SPKI_PIN',
      tlsSpkiSha256: undefined,
    },
  ]) {
    const harness = createHarness()
    await assert.rejects(
      probeHttps(baseOptions(harness, override)),
      (error) => {
        assert.equal(error.code, 'HTTP_RECON_INVALID_REQUEST')
        assert.match(error.message, /do not describe one policy/)
        return true
      },
    )
    assert.equal(harness.dnsCalls, 0)
    assert.equal(harness.httpsCalls, 0)
  }
})

test('URL, method, caller headers, and literal IP inputs fail before I/O', async (t) => {
  const cases = [
    ['plaintext URL', { url: 'http://example.com/' }, 'HTTP_RECON_HTTPS_REQUIRED'],
    ['IPv4 literal', { url: 'https://8.8.8.8/' }, 'HTTP_RECON_LITERAL_IP_DENIED'],
    ['IPv6 literal', { url: 'https://[2606:4700:4700::1111]/' }, 'HTTP_RECON_LITERAL_IP_DENIED'],
    ['credentials', { url: 'https://user:secret@example.com/' }, 'HTTP_RECON_URL_CREDENTIALS_DENIED'],
    ['fragment', { url: 'https://example.com/#secret' }, 'HTTP_RECON_URL_FRAGMENT_DENIED'],
    ['query', { url: 'https://example.com/?probe=one' }, 'HTTP_RECON_URL_QUERY_DENIED'],
    ['non-canonical host', { url: 'https://EXAMPLE.com/' }, 'HTTP_RECON_URL_NOT_CANONICAL'],
    ['ambiguous path', { url: 'https://example.com/%2e%2e/admin' }, 'HTTP_RECON_URL_NOT_CANONICAL'],
    ['wildcard host', { url: 'https://*.example.com/' }, 'HTTP_RECON_URL_SCOPE_INVALID'],
    ['unsafe method', { method: 'POST' }, 'HTTP_RECON_METHOD_DENIED'],
    ['caller headers', { headers: { authorization: 'secret' } }, 'HTTP_RECON_INVALID_REQUEST'],
    ['caller body', { body: Buffer.from('secret') }, 'HTTP_RECON_INVALID_REQUEST'],
  ]
  for (const [name, override, code] of cases) {
    await t.test(name, async () => {
      const harness = createHarness()
      await assert.rejects(
        probeHttps(baseOptions(harness, override)),
        (error) => {
          assert.equal(error.code, code)
          assert.equal(error.request_may_have_been_sent, false)
          return true
        },
      )
      assert.equal(harness.dnsCalls, 0)
      assert.equal(harness.httpsCalls, 0)
    })
  }
})

test('DNS rejects an entire mixed or reserved answer set and supports pinning', async () => {
  for (const unsafeAddress of ['10.0.0.9', '192.0.2.9', '::1', 'fc00::9']) {
    const harness = createHarness({
      answers: [PUBLIC_ANSWERS[0], {
        address: unsafeAddress,
        family: unsafeAddress.includes(':') ? 6 : 4,
      }],
    })
    await assert.rejects(
      probeHttps(baseOptions(harness)),
      (error) => {
        assert.equal(error.code, 'HTTP_RECON_DNS_SCOPE_DENIED')
        assert.equal(error.request_may_have_been_sent, false)
        return true
      },
    )
    assert.equal(harness.httpsCalls, 0)
  }

  const resolved = await resolveHttpReconDns(HOSTNAME, {
    lookup: (hostname, options, callback) => {
      assert.equal(hostname, HOSTNAME)
      assert.deepEqual(options, { all: true, verbatim: true })
      callback(null, PUBLIC_ANSWERS)
    },
  })
  const accepted = createHarness()
  const result = await probeHttps(baseOptions(accepted, {
    expectedDnsSha256: resolved.answer_sha256,
  }))
  assert.equal(result.dns.answer_sha256, resolved.answer_sha256)

  const rejected = createHarness()
  await assert.rejects(
    probeHttps(baseOptions(rejected, {
      expectedDnsSha256: '0'.repeat(64),
    })),
    (error) => {
      assert.equal(error.code, 'HTTP_RECON_DNS_PIN_MISMATCH')
      assert.equal(error.request_may_have_been_sent, false)
      return true
    },
  )
  assert.equal(rejected.httpsCalls, 0)
})

test('DNS listener cleanup cannot strand a successful resolution', async () => {
  let removeCalls = 0
  let watchdog
  const signal = {
    aborted: false,
    addEventListener(type, listener, options) {
      assert.equal(type, 'abort')
      assert.equal(typeof listener, 'function')
      assert.deepEqual(options, { once: true })
    },
    removeEventListener(type, listener) {
      assert.equal(type, 'abort')
      assert.equal(typeof listener, 'function')
      removeCalls += 1
      throw new Error('synthetic DNS listener removal failure')
    },
  }

  try {
    const resolved = await Promise.race([
      resolveHttpReconDns(HOSTNAME, {
        signal,
        lookup(hostname, options, callback) {
          assert.equal(hostname, HOSTNAME)
          assert.deepEqual(options, { all: true, verbatim: true })
          callback(null, PUBLIC_ANSWERS)
        },
      }),
      new Promise((resolve) => {
        watchdog = setTimeout(() => resolve('watchdog'), 100)
      }),
    ])
    assert.notEqual(resolved, 'watchdog')
    assert.equal(resolved.answer_count, PUBLIC_ANSWERS.length)
  } finally {
    clearTimeout(watchdog)
  }
  assert.equal(removeCalls, 1)
})

test('DNS listener setup failure removes a possibly retained binding before lookup', async () => {
  let retainedListener
  let removeCalls = 0
  let lookupCalls = 0
  const signal = {
    aborted: false,
    addEventListener(type, listener, options) {
      assert.equal(type, 'abort')
      assert.deepEqual(options, { once: true })
      retainedListener = listener
      throw new Error('synthetic DNS listener setup failure')
    },
    removeEventListener(type, listener) {
      assert.equal(type, 'abort')
      assert.equal(listener, retainedListener)
      removeCalls += 1
    },
  }

  await assert.rejects(
    resolveHttpReconDns(HOSTNAME, {
      signal,
      lookup() {
        lookupCalls += 1
      },
    }),
    /synthetic DNS listener setup failure/,
  )
  assert.equal(removeCalls, 1)
  assert.equal(lookupCalls, 0)
})

test('TLS hostname and SPKI failures occur before the request is sent', async () => {
  const badPin = createHarness()
  await assert.rejects(
    probeHttps(baseOptions(badPin, { tlsSpkiSha256: '0'.repeat(64) })),
    (error) => {
      assert.equal(error.code, 'HTTP_RECON_TLS_PIN_MISMATCH')
      assert.equal(error.request_may_have_been_sent, false)
      return true
    },
  )
  assert.equal(badPin.request.ended, false)

  const badHostname = createHarness()
  await assert.rejects(
    probeHttps(baseOptions(badHostname, {
      url: 'https://different.example/authorized',
    })),
    (error) => {
      assert.equal(error.code, 'HTTP_RECON_TLS_HOSTNAME_MISMATCH')
      assert.equal(error.request_may_have_been_sent, false)
      return true
    },
  )
  assert.equal(badHostname.request.ended, false)

  const unauthorized = createHarness({ socketAuthorized: false })
  await assert.rejects(
    probeHttps(baseOptions(unauthorized, {
      tlsVerificationMode: 'PKIX_HOSTNAME',
      tlsSpkiSha256: undefined,
    })),
    (error) => {
      assert.equal(error.code, 'HTTP_RECON_TLS_VERIFICATION_MISSING')
      assert.equal(error.request_may_have_been_sent, false)
      return true
    },
  )
  assert.equal(unauthorized.request.ended, false)
})

test('beforeSend rejection destroys the TLS connection without sending', async () => {
  const harness = createHarness()
  await assert.rejects(
    probeHttps(baseOptions(harness, {
      beforeSend: async () => {
        throw new Error('durable lifecycle write failed')
      },
    })),
    (error) => {
      assert.equal(error.code, 'HTTP_RECON_BEFORE_SEND_REJECTED')
      assert.equal(error.request_may_have_been_sent, false)
      return true
    },
  )
  assert.equal(harness.request.ended, false)
  assert.equal(harness.request.destroyed, true)
})

test('redirect, rate-limit, and server responses are typed stop conditions', async (t) => {
  for (const [status, condition, code] of [
    [302, 'REDIRECT', 'HTTP_RECON_REDIRECT'],
    [429, 'RATE_LIMITED', 'HTTP_RECON_RATE_LIMITED'],
    [503, 'SERVER_ERROR', 'HTTP_RECON_SERVER_ERROR'],
  ]) {
    await t.test(String(status), async () => {
      const harness = createHarness({
        status,
        headers: {
          location: 'https://private.example/path?token=secret',
          'retry-after': '60',
        },
      })
      await assert.rejects(
        probeHttps(baseOptions(harness)),
        (error) => {
          assert.ok(error instanceof HttpReconStopCondition)
          assert.equal(error.code, code)
          assert.equal(error.condition, condition)
          assert.equal(error.status, status)
          assert.equal(error.request_may_have_been_sent, true)
          assert.deepEqual(
            retainedHeaders(error.result, 'location'),
            ['[REDACTED]'],
          )
          assert.equal(error.result.body.bytes, null)
          return true
        },
      )
      assert.equal(harness.httpsCalls, 1)
      assert.equal(harness.request.destroyed, true)
      assert.equal(harness.response.destroyed, true)
    })
  }
})

test('proof fetch retains only its small bound while hashing the response', async () => {
  const body = Buffer.from('0123456789abcdef')
  const harness = createHarness({ chunks: [body] })
  const result = await fetchHttpsProof(baseOptions(harness, {
    maxResponseBytes: 64,
    maxProofBodyBytes: 8,
  }))

  assert.deepEqual(result.body.bytes, body.subarray(0, 8))
  assert.equal(result.body.retained, true)
  assert.equal(result.body.retained_size, 8)
  assert.equal(result.body.size, body.length)
  assert.equal(result.body.sha256, digest(body))
  assert.equal(result.body.digest_scope, 'complete')
  assert.equal(result.body.truncated, true)

  const capped = createHarness({ chunks: [body] })
  const cappedResult = await fetchHttpsProof(baseOptions(capped, {
    maxResponseBytes: 10,
    maxProofBodyBytes: 8,
  }))
  assert.deepEqual(cappedResult.body.bytes, body.subarray(0, 8))
  assert.equal(cappedResult.body.size, 10)
  assert.equal(cappedResult.body.sha256, digest(body.subarray(0, 10)))
  assert.equal(cappedResult.body.digest_scope, 'captured-prefix')
  assert.equal(cappedResult.body.truncated, true)
  assert.equal(capped.request.destroyed, true)
  assert.equal(capped.response.destroyed, true)
})

test('stop signals and timeouts destroy an in-flight sent request', async () => {
  const stoppedHarness = createHarness({ autoRespond: false })
  const stopController = new AbortController()
  const stopped = probeHttps(baseOptions(stoppedHarness, {
    signal: stopController.signal,
  }))
  await stoppedHarness.sent
  stopController.abort()
  await assert.rejects(stopped, (error) => {
    assert.equal(error.code, 'HTTP_RECON_ABORTED')
    assert.equal(error.request_may_have_been_sent, true)
    return true
  })
  assert.equal(stoppedHarness.request.destroyed, true)

  const timeoutHarness = createHarness({ autoRespond: false })
  let fireTimeout
  timeoutHarness.dependencies.clock = {
    value: 0,
    now() {
      this.value += 1
      return this.value
    },
    setTimeout(callback) {
      fireTimeout = callback
      return 7
    },
    clearTimeout(handle) {
      assert.equal(handle, 7)
      throw new Error('synthetic recon timeout cleanup failure')
    },
  }
  const timedOut = probeHttps(baseOptions(timeoutHarness))
  await timeoutHarness.sent
  fireTimeout()
  await assert.rejects(timedOut, (error) => {
    assert.equal(error.code, 'HTTP_RECON_TIMEOUT')
    assert.equal(error.request_may_have_been_sent, true)
    return true
  })
  assert.equal(timeoutHarness.request.destroyed, true)
})

test('recon timer setup failure removes its stop listener before network I/O', async () => {
  const harness = createHarness()
  let added = 0
  let removed = 0
  const signal = {
    aborted: false,
    addEventListener(type, listener, options) {
      assert.equal(type, 'abort')
      assert.equal(typeof listener, 'function')
      assert.deepEqual(options, { once: true })
      added += 1
    },
    removeEventListener(type, listener) {
      assert.equal(type, 'abort')
      assert.equal(typeof listener, 'function')
      removed += 1
      throw new Error('synthetic recon listener removal failure')
    },
  }
  harness.dependencies.clock = {
    now: () => 0,
    setTimeout() { throw new Error('synthetic recon timer setup failure') },
    clearTimeout() { assert.fail('an uncreated recon timer cannot be cleared') },
  }

  await assert.rejects(
    probeHttps(baseOptions(harness, { signal })),
    /synthetic recon timer setup failure/,
  )
  assert.equal(harness.dnsCalls, 0)
  assert.equal(harness.httpsCalls, 0)
  assert.equal(added, 1)
  assert.equal(removed, 1)
})

test('recon listener setup failure removes a possibly retained binding before network I/O', async () => {
  const harness = createHarness()
  let retainedListener
  let removeCalls = 0
  const signal = {
    aborted: false,
    addEventListener(type, listener, options) {
      assert.equal(type, 'abort')
      assert.deepEqual(options, { once: true })
      retainedListener = listener
      throw new Error('synthetic recon listener setup failure')
    },
    removeEventListener(type, listener) {
      assert.equal(type, 'abort')
      assert.equal(listener, retainedListener)
      removeCalls += 1
    },
  }

  await assert.rejects(
    probeHttps(baseOptions(harness, { signal })),
    /synthetic recon listener setup failure/,
  )
  assert.equal(removeCalls, 1)
  assert.equal(harness.dnsCalls, 0)
  assert.equal(harness.httpsCalls, 0)
})

test('recon listener cleanup cannot overturn a successful request', async () => {
  const harness = createHarness({ status: 204, chunks: [] })
  let removeCalls = 0
  const signal = {
    aborted: false,
    addEventListener(type, listener, options) {
      assert.equal(type, 'abort')
      assert.equal(typeof listener, 'function')
      assert.deepEqual(options, { once: true })
    },
    removeEventListener(type, listener) {
      assert.equal(type, 'abort')
      assert.equal(typeof listener, 'function')
      removeCalls += 1
      throw new Error('synthetic recon listener removal failure')
    },
  }

  const result = await probeHttps(baseOptions(harness, { signal }))
  assert.equal(result.status, 204)
  assert.equal(removeCalls, 1)
})

test('recon timer cleanup failure cannot overturn a settled response', async () => {
  const harness = createHarness({ status: 204, chunks: [] })
  let clearTimerCalls = 0
  harness.dependencies.clock = {
    value: 0,
    now() {
      this.value += 1
      return this.value
    },
    setTimeout: () => 81,
    clearTimeout(handle) {
      assert.equal(handle, 81)
      clearTimerCalls += 1
      throw new Error('synthetic recon settled cleanup failure')
    },
  }

  const result = await probeHttps(baseOptions(harness))
  assert.equal(result.status, 204)
  assert.equal(result.body.size, 0)
  assert.equal(clearTimerCalls, 1)
})

test('transformed responses are rejected without decompression', async () => {
  const harness = createHarness({
    headers: { 'content-encoding': 'gzip' },
    chunks: [Buffer.from('not decompressed')],
  })
  await assert.rejects(
    probeHttps(baseOptions(harness)),
    (error) => {
      assert.equal(error.code, 'HTTP_RECON_CONTENT_ENCODING_DENIED')
      assert.equal(error.request_may_have_been_sent, true)
      return true
    },
  )
  assert.equal(harness.requestOptions.headers['accept-encoding'], 'identity')
  assert.equal(harness.request.destroyed, true)
  assert.equal(harness.response.destroyed, true)
})

test('transport rejects undeclared target-specific response adapters before I/O', async () => {
  const harness = createHarness()
  await assert.rejects(
    probeHttps(baseOptions(harness, {
      responseObservationProfile: {
        profile: 'target-specific-parser-v1',
      },
    })),
    (error) => {
      assert.equal(error.code, 'HTTP_RECON_INVALID_REQUEST')
      return true
    },
  )
  assert.equal(harness.httpsCalls, 0)
})
