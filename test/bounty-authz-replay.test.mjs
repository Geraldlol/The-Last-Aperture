import assert from 'node:assert/strict'
import { test } from 'node:test'
import { approveRequestTarget, replayAsRole } from '../scripts/lib/bounty-authz-replay.mjs'
import { ANONYMOUS_ROLE } from '../scripts/lib/bounty-authz-roles.mjs'

const ROLE = { id: 'bob', label: 'other', auth: { kind: 'header', name: 'Authorization', value_env: 'TB_BOB' } }
const ENV = { TB_BOB: 'Bearer bob' }

function sealedScope() {
  return {
    program: { required_user_agent: 'BugBounty-acme' },
    scope_rules: {
      allow: [{ rule_id: 'a1', host_kind: 'wildcard', host: 'acme.example' }],
      deny: [{ rule_id: 'd1', host_kind: 'exact', host: 'legacy.acme.example' }],
    },
  }
}

const request = {
  method: 'GET',
  url: 'https://api.acme.example/orders/2',
  headers: { accept: 'application/json' },
  body: null,
}

function countingLimiter() {
  let calls = 0
  return { acquire: async () => { calls += 1 }, calls: () => calls }
}

const jsonReply = (body, status = 200) => new Response(body, {
  status, headers: { 'content-type': 'application/json' },
})

test('approves an in-scope request target and derives the port', () => {
  const { approval, refusal } = approveRequestTarget({ request, sealedScope: sealedScope() })
  assert.equal(refusal, null)
  assert.equal(approval.host, 'api.acme.example')
  assert.equal(approval.port, 443)
})

test('refuses an out-of-scope or denied host', () => {
  const outside = approveRequestTarget({
    request: { ...request, url: 'https://evil.example/x' }, sealedScope: sealedScope(),
  })
  assert.equal(outside.approval, null)
  assert.equal(outside.refusal.reason, 'candidate-unlisted')
  const denied = approveRequestTarget({
    request: { ...request, url: 'https://legacy.acme.example/x' }, sealedScope: sealedScope(),
  })
  assert.equal(denied.refusal.reason, 'explicit-deny-rule')
})

test('refuses an unparseable url', () => {
  const { refusal } = approveRequestTarget({
    request: { ...request, url: 'not a url' }, sealedScope: sealedScope(),
  })
  assert.equal(refusal.reason, 'candidate-unparsable')
})

test('an out-of-scope replay never reaches fetch', async () => {
  let fetched = 0
  const result = await replayAsRole({
    request: { ...request, url: 'https://evil.example/x' },
    role: ROLE,
    sealedScope: sealedScope(),
    limiter: countingLimiter(),
    fetchImpl: async () => { fetched += 1; return jsonReply('{}') },
    env: ENV,
  })
  assert.equal(fetched, 0)
  assert.match(result.error, /out of scope/)
  assert.equal(result.refusal.reason, 'candidate-unlisted')
})

test('a persisted query or body credential placeholder requires a transient adapter before replay', async () => {
  let fetched = 0
  const limiter = countingLimiter()
  const result = await replayAsRole({
    request: {
      ...request,
      url: 'https://api.acme.example/orders/2?access_token=%3Credacted%3E',
      redacted_query_parameters: ['access_token'],
      redacted_body_fields: ['csrfToken'],
    },
    role: ROLE,
    sealedScope: sealedScope(),
    limiter,
    fetchImpl: async () => { fetched += 1; return jsonReply('{}') },
    env: ENV,
  })

  assert.equal(fetched, 0)
  assert.equal(limiter.calls(), 0)
  assert.equal(result.status, null)
  assert.match(result.error, /transient.*adapter|adapter.*credential/i)
})

test('legacy raw credential carriers are re-redacted before direct replay', async () => {
  let fetched = 0
  const limiter = countingLimiter()
  const result = await replayAsRole({
    request: {
      ...request,
      method: 'POST',
      url: 'https://api.acme.example/login?access_token=legacy-query-secret',
      headers: {
        'content-type': 'application/json',
        'x-access-token': 'legacy-header-secret',
        'x-csrf-token': 'legacy-csrf-secret',
      },
      body: '{"password":"legacy-body-secret"}',
    },
    role: ROLE,
    sealedScope: sealedScope(),
    limiter,
    fetchImpl: async () => { fetched += 1; return jsonReply('{}') },
    env: ENV,
  })

  assert.equal(fetched, 0)
  assert.equal(limiter.calls(), 0)
  assert.equal(result.status, null)
  assert.match(result.error, /transient.*adapter|adapter.*credential/i)
  assert.doesNotMatch(JSON.stringify(result), /legacy-(?:query|header|csrf|body)-secret/)
})

test('a redaction placeholder cannot be replayed when its metadata was omitted', async () => {
  let fetched = 0
  const limiter = countingLimiter()
  const result = await replayAsRole({
    request: {
      ...request,
      url: 'https://api.acme.example/orders/2?access_token=%3Credacted%3E',
    },
    role: ROLE,
    sealedScope: sealedScope(),
    limiter,
    fetchImpl: async () => { fetched += 1; return jsonReply('{}') },
    env: ENV,
  })

  assert.equal(fetched, 0)
  assert.equal(limiter.calls(), 0)
  assert.match(result.error, /redacted|transient.*adapter/i)
})

test('an encoded form redaction placeholder cannot be replayed without metadata', async () => {
  let fetched = 0
  const limiter = countingLimiter()
  const result = await replayAsRole({
    request: {
      ...request,
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'username=alice&password=%3Credacted%3E',
    },
    role: ROLE,
    sealedScope: sealedScope(),
    limiter,
    fetchImpl: async () => { fetched += 1; return jsonReply('{}') },
    env: ENV,
  })

  assert.equal(fetched, 0)
  assert.equal(limiter.calls(), 0)
  assert.match(result.error, /redacted|transient.*adapter/i)
})

test('escaped body and secondary-header placeholders cannot bypass missing redaction metadata', async () => {
  let fetched = 0
  for (const candidate of [
    {
      ...request,
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"password":"\\u003credacted\\u003e"}',
    },
    {
      ...request,
      headers: { ...request.headers, 'x-csrf-token': '<redacted>' },
    },
  ]) {
    const limiter = countingLimiter()
    const result = await replayAsRole({
      request: candidate,
      role: ROLE,
      sealedScope: sealedScope(),
      limiter,
      fetchImpl: async () => { fetched += 1; return jsonReply('{}') },
      env: ENV,
    })
    assert.equal(limiter.calls(), 0)
    assert.match(result.error, /redacted|transient.*adapter/i)
  }
  assert.equal(fetched, 0)
})

test('replay refuses redacted secondary headers that the selected role cannot reconstruct', async () => {
  let fetched = 0
  const limiter = countingLimiter()
  const result = await replayAsRole({
    request: {
      ...request,
      redacted_headers: ['authorization', 'x-csrf-token'],
    },
    role: ROLE,
    sealedScope: sealedScope(),
    limiter,
    fetchImpl: async () => { fetched += 1; return jsonReply('{}') },
    env: ENV,
  })

  assert.equal(fetched, 0)
  assert.equal(limiter.calls(), 0)
  assert.match(result.error, /x-csrf-token.*adapter|adapter.*x-csrf-token/i)
})

test('replay accepts a redacted primary header that the selected role reconstructs', async () => {
  let sentAuthorization = null
  const result = await replayAsRole({
    request: { ...request, redacted_headers: ['authorization'] },
    role: ROLE,
    sealedScope: sealedScope(),
    limiter: countingLimiter(),
    fetchImpl: async (_url, init) => {
      sentAuthorization = init.headers.authorization
      return jsonReply('{}')
    },
    env: ENV,
  })

  assert.equal(result.status, 200)
  assert.equal(sentAuthorization, ENV.TB_BOB)
})

test('applies the role credential to the outgoing request', async () => {
  const seen = []
  await replayAsRole({
    request,
    role: ROLE,
    sealedScope: sealedScope(),
    limiter: countingLimiter(),
    fetchImpl: async (url, init) => { seen.push(init); return jsonReply('{"a":1}') },
    env: ENV,
  })
  assert.equal(seen[0].headers.authorization, 'Bearer bob')
  assert.equal(seen[0].redirect, 'manual', 'redirects are not followed')
})

test('the anonymous role sends no credential', async () => {
  const seen = []
  await replayAsRole({
    request: { ...request, headers: { ...request.headers, authorization: 'Bearer ORIGINAL' } },
    role: ANONYMOUS_ROLE,
    sealedScope: sealedScope(),
    limiter: countingLimiter(),
    fetchImpl: async (url, init) => { seen.push(init); return jsonReply('{}') },
    env: ENV,
  })
  assert.equal(Object.hasOwn(seen[0].headers, 'authorization'), false)
})

test('pays exactly one rate-limit token per replay', async () => {
  const limiter = countingLimiter()
  await replayAsRole({
    request, role: ROLE, sealedScope: sealedScope(), limiter,
    fetchImpl: async () => jsonReply('{}'), env: ENV,
  })
  assert.equal(limiter.calls(), 1)
})

test('refuses to run without a rate limiter', async () => {
  await assert.rejects(
    () => replayAsRole({
      request, role: ROLE, sealedScope: sealedScope(),
      fetchImpl: async () => jsonReply('{}'), env: ENV,
    }),
    /rate limiter/,
  )
})

test('normalizes the response so the classifier can compare it', async () => {
  const result = await replayAsRole({
    request, role: ROLE, sealedScope: sealedScope(), limiter: countingLimiter(),
    fetchImpl: async () => jsonReply('{"order":2}'), env: ENV,
  })
  assert.equal(result.status, 200)
  assert.equal(result.error, null)
  assert.ok(result.normalized.bodyDigest)
})

test('a transport failure is returned, not thrown', async () => {
  const result = await replayAsRole({
    request, role: ROLE, sealedScope: sealedScope(), limiter: countingLimiter(),
    fetchImpl: async () => { const e = new Error('socket hang up'); e.name = 'TypeError'; throw e },
    env: ENV,
  })
  assert.equal(result.status, null)
  assert.match(result.error, /socket hang up/)
})

test('a missing credential throws rather than replaying unauthenticated', async () => {
  await assert.rejects(
    () => replayAsRole({
      request, role: ROLE, sealedScope: sealedScope(), limiter: countingLimiter(),
      fetchImpl: async () => jsonReply('{}'), env: {},
    }),
    /TB_BOB/,
  )
})

test('a GET carries no body even when the capture recorded one', async () => {
  const seen = []
  await replayAsRole({
    request: { ...request, method: 'GET', body: '{"a":1}' },
    role: ROLE, sealedScope: sealedScope(), limiter: countingLimiter(),
    fetchImpl: async (url, init) => { seen.push(init); return jsonReply('{}') },
    env: ENV,
  })
  assert.equal(Object.hasOwn(seen[0], 'body'), false)
})

test('a POST forwards its body', async () => {
  const seen = []
  await replayAsRole({
    request: { ...request, method: 'POST', body: '{"a":1}' },
    role: ROLE, sealedScope: sealedScope(), limiter: countingLimiter(),
    fetchImpl: async (url, init) => { seen.push(init); return jsonReply('{}') },
    env: ENV,
  })
  assert.equal(seen[0].body, '{"a":1}')
})

test('response streaming stops at the byte cap without awaiting hostile cancellation', async () => {
  const chunk = new Uint8Array(400 * 1024).fill('z'.charCodeAt(0))
  let reads = 0
  let cancels = 0
  const settlements = []
  let watchdog
  try {
    const result = await Promise.race([
      replayAsRole({
        request, role: ROLE, sealedScope: sealedScope(), limiter: countingLimiter(), env: ENV,
        fetchImpl: async () => ({
          status: 200,
          headers: new Headers({ 'content-type': 'text/plain' }),
          body: {
            getReader() {
              return {
                async read() { reads += 1; return { done: false, value: chunk } },
                cancel() { cancels += 1; return new Promise(() => {}) },
              }
            },
          },
        }),
        onResponseSettled: async (settlement) => settlements.push(settlement),
      }),
      new Promise((_, reject) => {
        watchdog = setTimeout(() => reject(new Error('bounded replay exceeded deadline')), 300)
      }),
    ])

    assert.equal(reads, 2)
    assert.equal(cancels, 1)
    assert.equal(result.status, 200)
    assert.equal(result.error, null)
    assert.equal(result.responseTruncated, true)
    assert.equal(Buffer.byteLength(result.normalized.normalizedBody), 512 * 1024)
    assert.deepEqual(settlements, [{ outcome: 'RETURNED', httpStatus: 200, errorName: null }])
  } finally {
    clearTimeout(watchdog)
  }
})

test('replay deadline bounds a response reader that ignores abort', async () => {
  let cancels = 0
  let requestSignal
  const settlements = []
  let watchdog
  try {
    const result = await Promise.race([
      replayAsRole({
        request, role: ROLE, sealedScope: sealedScope(), limiter: countingLimiter(), env: ENV,
        timeoutMs: 20,
        fetchImpl: async (_url, init) => {
          requestSignal = init.signal
          return {
            status: 200,
            headers: new Headers({ 'content-type': 'text/plain' }),
            body: {
              getReader() {
                return {
                  read() { return new Promise(() => {}) },
                  cancel() { cancels += 1; return new Promise(() => {}) },
                }
              },
            },
          }
        },
        onResponseSettled: async (settlement) => settlements.push(settlement),
      }),
      new Promise((_, reject) => {
        watchdog = setTimeout(() => reject(new Error('replay response reader exceeded its deadline')), 300)
      }),
    ])

    assert.equal(result.status, null)
    assert.match(result.error, /TimeoutError|timed out/i)
    assert.equal(requestSignal.aborted, true)
    assert.equal(cancels, 1)
    assert.deepEqual(settlements, [{ outcome: 'THREW', httpStatus: null, errorName: 'TimeoutError' }])
  } finally {
    clearTimeout(watchdog)
  }
})

test('replay rechecks its deadline after a synchronous transport invocation', async () => {
  let fetchCalls = 0
  const result = await replayAsRole({
    request, role: ROLE, sealedScope: sealedScope(), limiter: countingLimiter(), env: ENV,
    timeoutMs: 5,
    fetchImpl: () => {
      fetchCalls += 1
      const until = performance.now() + 40
      while (performance.now() < until) {}
      return jsonReply('{}')
    },
  })

  assert.equal(fetchCalls, 1)
  assert.equal(result.status, null)
  assert.match(result.error, /TimeoutError|timed out/i)
})

test('replay rechecks its deadline after synchronous response metadata processing', async () => {
  const response = {
    get status() {
      const until = performance.now() + 40
      while (performance.now() < until) {}
      return 200
    },
    headers: new Headers({ 'content-type': 'application/json' }),
    body: new Response('{}').body,
  }
  const result = await replayAsRole({
    request,
    role: ROLE,
    sealedScope: sealedScope(),
    limiter: countingLimiter(),
    env: ENV,
    timeoutMs: 5,
    fetchImpl: async () => response,
  })

  assert.equal(result.status, null)
  assert.match(result.error, /TimeoutError|timed out/i)
})

test('replay rejects response header collections beyond the normalization boundary', async () => {
  let settled = null
  const result = await replayAsRole({
    request,
    role: ROLE,
    sealedScope: sealedScope(),
    limiter: countingLimiter(),
    env: ENV,
    fetchImpl: async () => ({
      status: 200,
      headers: {
        get(name) { return name === 'content-type' ? 'application/json' : null },
        * entries() {
          for (let index = 0; index < 257; index += 1) {
            yield [`x-observed-${index}`, 'value']
          }
        },
      },
      body: new Response('{}').body,
    }),
    onResponseSettled: async (value) => { settled = value },
  })

  assert.equal(result.status, null)
  assert.match(result.error, /response headers|header.*limit/i)
  assert.deepEqual(settled, { outcome: 'THREW', httpStatus: null, errorName: 'TypeError' })
})

test('replay deadline also bounds durable response settlement', async () => {
  const settlements = []
  let watchdog
  try {
    const result = await Promise.race([
      replayAsRole({
        request, role: ROLE, sealedScope: sealedScope(), limiter: countingLimiter(), env: ENV,
        timeoutMs: 20,
        fetchImpl: async () => jsonReply('{}'),
        onResponseSettled: async (settlement) => {
          settlements.push(settlement)
          return new Promise(() => {})
        },
      }),
      new Promise((_, reject) => {
        watchdog = setTimeout(() => reject(new Error('durable settlement exceeded replay deadline')), 300)
      }),
    ])
    assert.equal(result.status, null)
    assert.match(result.error, /TimeoutError|timed out/i)
    assert.deepEqual(settlements, [{ outcome: 'RETURNED', httpStatus: 200, errorName: null }])
  } finally {
    clearTimeout(watchdog)
  }
})

test('replay clears a response chunk retained before a hostile reader times out', async () => {
  const observedChunk = new Uint8Array(Buffer.from('transient-response-secret'))
  let reads = 0
  let cancels = 0
  const result = await replayAsRole({
    request, role: ROLE, sealedScope: sealedScope(), limiter: countingLimiter(), env: ENV,
    timeoutMs: 20,
    fetchImpl: async () => ({
      status: 200,
      headers: new Headers({ 'content-type': 'text/plain' }),
      body: {
        getReader() {
          return {
            read() {
              reads += 1
              return reads === 1
                ? Promise.resolve({ done: false, value: observedChunk })
                : new Promise(() => {})
            },
            cancel() { cancels += 1; return new Promise(() => {}) },
          }
        },
      },
    }),
  })

  assert.equal(result.status, null)
  assert.match(result.error, /TimeoutError|timed out/i)
  assert.equal(cancels, 1)
  assert.deepEqual([...observedChunk], Array(observedChunk.length).fill(0))
})

test('replacement decoding cannot expand a bounded response beyond the byte cap', async () => {
  const invalidUtf8 = new Uint8Array(512 * 1024).fill(0xff)
  let reads = 0
  const result = await replayAsRole({
    request, role: ROLE, sealedScope: sealedScope(), limiter: countingLimiter(), env: ENV,
    fetchImpl: async () => ({
      status: 200,
      headers: new Headers({ 'content-type': 'text/plain' }),
      body: {
        getReader() {
          return {
            async read() {
              reads += 1
              return reads === 1
                ? { done: false, value: invalidUtf8 }
                : { done: true, value: undefined }
            },
            async cancel() {},
          }
        },
      },
    }),
  })

  assert.equal(result.status, 200)
  assert.equal(result.responseTruncated, true)
  assert.ok(Buffer.byteLength(result.normalized.normalizedBody, 'utf8') <= 512 * 1024)
})

test('response stream failures are failed observations rather than successful empty responses', async () => {
  let reads = 0
  const settlements = []
  const result = await replayAsRole({
    request, role: ROLE, sealedScope: sealedScope(), limiter: countingLimiter(), env: ENV,
    fetchImpl: async () => ({
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      body: {
        getReader() {
          return {
            async read() {
              reads += 1
              if (reads === 1) return { done: false, value: new TextEncoder().encode('{"a":') }
              const error = new Error('synthetic response stream failure')
              error.name = 'StreamError'
              throw error
            },
            async cancel() {},
          }
        },
      },
    }),
    onResponseSettled: async (settlement) => settlements.push(settlement),
  })

  assert.equal(result.status, null)
  assert.match(result.error, /StreamError: synthetic response stream failure/)
  assert.equal(result.normalized, null)
  assert.deepEqual(settlements, [{ outcome: 'THREW', httpStatus: null, errorName: 'StreamError' }])
})
