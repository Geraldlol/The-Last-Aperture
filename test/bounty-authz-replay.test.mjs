import assert from 'node:assert/strict'
import { test } from 'node:test'
import { approveRequestTarget, replayAsRole } from '../scripts/lib/bounty-authz-replay.mjs'
import { ANONYMOUS_ROLE } from '../scripts/lib/bounty-authz-roles.mjs'

const ROLE = { id: 'bob', label: 'other', auth: { kind: 'header', name: 'Authorization', value_env: 'TB_BOB' } }
const ENV = { TB_BOB: 'Bearer bob' }

function sealedScope() {
  return {
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
