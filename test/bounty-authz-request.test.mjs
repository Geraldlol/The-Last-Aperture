import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  SENSITIVE_HEADERS,
  importHarEntries,
  normalizeCapturedRequest,
  redactRequest,
  requestSignature,
} from '../scripts/lib/bounty-authz-request.mjs'

function har(entries) {
  return { log: { entries } }
}

function entry(overrides = {}) {
  return {
    request: {
      method: 'GET',
      url: 'https://api.acme.example/orders?id=2',
      headers: [
        { name: 'Accept', value: 'application/json' },
        { name: 'Authorization', value: 'Bearer secret-token' },
        { name: ':method', value: 'GET' },
      ],
      ...overrides,
    },
  }
}

test('normalizes method case and lowercases headers', () => {
  const request = normalizeCapturedRequest({
    method: 'post', url: 'https://x.example/', headers: { 'Content-Type': 'application/json' },
  })
  assert.equal(request.method, 'POST')
  assert.equal(request.headers['content-type'], 'application/json')
})

test('refuses a request missing method or url', () => {
  assert.throws(() => normalizeCapturedRequest({ url: 'https://x.example/' }), /method/)
  assert.throws(() => normalizeCapturedRequest({ method: 'GET' }), /url/)
  assert.throws(() => normalizeCapturedRequest(null), /object/)
})

test('imports a HAR entry with its headers and body', () => {
  const { requests } = importHarEntries(
    har([entry({ method: 'POST', postData: { text: '{"a":1}' } })]),
    { ownerRole: 'alice' },
  )
  assert.equal(requests.length, 1)
  assert.equal(requests[0].method, 'POST')
  assert.equal(requests[0].body, '{"a":1}')
  assert.equal(requests[0].owner_role, 'alice')
  assert.equal(requests[0].headers.accept, 'application/json')
})

test('drops HTTP/2 pseudo-headers, which are transport detail', () => {
  const { requests } = importHarEntries(har([entry()]), { ownerRole: 'alice' })
  assert.equal(Object.hasOwn(requests[0].headers, ':method'), false)
})

test('skips non-http entries and records why', () => {
  const { requests, skipped } = importHarEntries(
    har([
      entry({ url: 'data:text/plain,hello' }),
      entry({ url: 'ws://api.acme.example/socket' }),
      entry(),
    ]),
    { ownerRole: 'alice' },
  )
  assert.equal(requests.length, 1)
  assert.equal(skipped.length, 2)
  assert.equal(skipped.every((s) => s.reason === 'not-an-http-url'), true)
})

test('a HAR with no entries yields a recorded reason rather than a crash', () => {
  const { requests, skipped } = importHarEntries({}, { ownerRole: 'alice' })
  assert.equal(requests.length, 0)
  assert.equal(skipped[0].reason, 'har-has-no-entries')
})

test('redaction removes every sensitive header and keeps the rest', () => {
  const request = normalizeCapturedRequest({
    method: 'GET',
    url: 'https://x.example/',
    headers: {
      accept: 'application/json',
      authorization: 'Bearer secret-token',
      cookie: 'session=abc',
      'x-api-key': 'k',
      'user-agent': 'curl',
    },
  })
  const redacted = redactRequest(request)
  assert.equal(redacted.headers.accept, 'application/json')
  assert.equal(redacted.headers['user-agent'], 'curl')
  assert.equal(Object.hasOwn(redacted.headers, 'authorization'), false)
  assert.equal(Object.hasOwn(redacted.headers, 'cookie'), false)
  assert.equal(Object.hasOwn(redacted.headers, 'x-api-key'), false)
  assert.deepEqual(redacted.redacted_headers.sort(), ['authorization', 'cookie', 'x-api-key'])
  assert.equal(JSON.stringify(redacted).includes('secret-token'), false)
})

test('redaction accepts extra sensitive header names', () => {
  const request = normalizeCapturedRequest({
    method: 'GET', url: 'https://x.example/', headers: { 'x-tenant-secret': 'abc', accept: '*/*' },
  })
  const redacted = redactRequest(request, { extraSensitive: ['X-Tenant-Secret'] })
  assert.equal(Object.hasOwn(redacted.headers, 'x-tenant-secret'), false)
})

test('the sensitive header set covers the common credential carriers', () => {
  for (const name of ['authorization', 'cookie', 'set-cookie', 'x-api-key', 'x-auth-token']) {
    assert.equal(SENSITIVE_HEADERS.has(name), true, name)
  }
})

test('signature is stable across header order and query value changes', () => {
  const a = normalizeCapturedRequest({
    method: 'GET', url: 'https://x.example/orders?id=1&sort=asc', headers: { a: '1', b: '2' },
  })
  const b = normalizeCapturedRequest({
    method: 'GET', url: 'https://x.example/orders?sort=desc&id=99', headers: { b: '2', a: '1' },
  })
  assert.equal(requestSignature(a), requestSignature(b))
})

test('signature differs on method, path, and body shape', () => {
  const base = { method: 'GET', url: 'https://x.example/orders' }
  const get = normalizeCapturedRequest(base)
  const post = normalizeCapturedRequest({ ...base, method: 'POST' })
  const other = normalizeCapturedRequest({ ...base, url: 'https://x.example/users' })
  const withBody = normalizeCapturedRequest({ ...base, method: 'POST', body: '{"a":1}' })
  const otherBody = normalizeCapturedRequest({ ...base, method: 'POST', body: '{"b":1}' })
  assert.notEqual(requestSignature(get), requestSignature(post))
  assert.notEqual(requestSignature(get), requestSignature(other))
  assert.notEqual(requestSignature(withBody), requestSignature(otherBody))
})

test('signature tolerates an unparseable url', () => {
  const request = normalizeCapturedRequest({ method: 'GET', url: 'not a url' })
  assert.match(requestSignature(request), /^[0-9a-f]{32}$/)
})
