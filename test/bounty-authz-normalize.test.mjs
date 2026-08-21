import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  VOLATILE_HEADERS,
  normalizeResponse,
  normalizeResponseBody,
  responseDigest,
} from '../scripts/lib/bounty-authz-normalize.mjs'

const JSON_TYPE = 'application/json'

function digestOf(body, { status = 200, contentType = JSON_TYPE, headers = {} } = {}) {
  return responseDigest(normalizeResponse({ status, headers, body, contentType }))
}

test('two bodies differing only in a uuid normalize identical', () => {
  const a = '{"id":"11111111-2222-3333-4444-555555555555","name":"acme"}'
  const b = '{"id":"99999999-8888-7777-6666-555555555555","name":"acme"}'
  assert.equal(digestOf(a), digestOf(b))
})

test('two bodies differing only in an ISO timestamp normalize identical', () => {
  const a = '{"createdAt":"2026-08-21T10:00:00.000Z","name":"acme"}'
  const b = '{"createdAt":"2026-08-21T11:30:45.123Z","name":"acme"}'
  assert.equal(digestOf(a), digestOf(b))
})

test('a numeric epoch under a temporal key is redacted by key name', () => {
  assert.equal(digestOf('{"timestamp":1755770000,"n":1}'), digestOf('{"timestamp":1755779999,"n":1}'))
  assert.equal(digestOf('{"iat":1755770000,"n":1}'), digestOf('{"iat":1755779999,"n":1}'))
})

test('an epoch-shaped number under a non-temporal key is deliberately NOT scrubbed', () => {
  // Precision over recall, on purpose. A 10-digit value that differs between two
  // roles may be the identifier that proves a bypass; masking it by shape alone
  // would invent a false positive, which is the costlier error here.
  assert.notEqual(digestOf('{"accountNo":1755770000}'), digestOf('{"accountNo":1755779999}'))
})

test('an epoch inside a string is scrubbed by the text path', () => {
  assert.equal(digestOf('{"note":"at 1755770000"}'), digestOf('{"note":"at 1755779999"}'))
})

test('two bodies differing only in a long hex token normalize identical', () => {
  const a = '{"sig":"a1b2c3d4e5f60718293a4b5c6d7e8f90","n":1}'
  const b = '{"sig":"ffffffffffffffffffffffffffffffff","n":1}'
  assert.equal(digestOf(a), digestOf(b))
})

test('csrf-like keys are redacted regardless of value shape', () => {
  const a = '{"csrf":"short1","data":"x"}'
  const b = '{"csrf":"totallydifferent","data":"x"}'
  assert.equal(digestOf(a), digestOf(b))
})

test('json key order does not create a difference', () => {
  assert.equal(digestOf('{"a":1,"b":2}'), digestOf('{"b":2,"a":1}'))
})

test('nested objects and arrays are normalized too', () => {
  const a = '{"items":[{"id":"11111111-2222-3333-4444-555555555555","q":2}]}'
  const b = '{"items":[{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","q":2}]}'
  assert.equal(digestOf(a), digestOf(b))
})

test('genuinely different data still differs', () => {
  // The whole point: normalization must remove machine noise and nothing else.
  assert.notEqual(digestOf('{"account":"alice","balance":100}'), digestOf('{"account":"bob","balance":100}'))
  assert.notEqual(digestOf('{"account":"alice","balance":100}'), digestOf('{"account":"alice","balance":250}'))
})

test('a rendered username in html still differs', () => {
  const a = '<html><body>Welcome, alice</body></html>'
  const b = '<html><body>Welcome, bob</body></html>'
  assert.notEqual(digestOf(a, { contentType: 'text/html' }), digestOf(b, { contentType: 'text/html' }))
})

test('a different status is a different response even with the same body', () => {
  assert.notEqual(digestOf('{"a":1}', { status: 200 }), digestOf('{"a":1}', { status: 403 }))
})

test('malformed json falls back to text normalization without throwing', () => {
  assert.doesNotThrow(() => normalizeResponseBody('{not json', JSON_TYPE))
  const a = normalizeResponseBody('{broken 11111111-2222-3333-4444-555555555555', JSON_TYPE)
  const b = normalizeResponseBody('{broken aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', JSON_TYPE)
  assert.equal(a, b, 'text fallback still scrubs uuids')
})

test('an empty or absent body normalizes to empty', () => {
  assert.equal(normalizeResponseBody('', JSON_TYPE), '')
  assert.equal(normalizeResponseBody(null, JSON_TYPE), '')
  assert.equal(normalizeResponseBody(undefined, JSON_TYPE), '')
})

test('volatile headers are excluded and stable ones retained', () => {
  const withNoise = normalizeResponse({
    status: 200,
    headers: { 'content-type': JSON_TYPE, date: 'Thu, 21 Aug 2026 10:00:00 GMT', 'x-request-id': 'abc' },
    body: '{"a":1}',
  })
  const withoutNoise = normalizeResponse({
    status: 200,
    headers: { 'content-type': JSON_TYPE, date: 'Fri, 22 Aug 2026 11:00:00 GMT', 'x-request-id': 'zzz' },
    body: '{"a":1}',
  })
  assert.equal(withNoise.headerDigest, withoutNoise.headerDigest)
  const differentType = normalizeResponse({
    status: 200, headers: { 'content-type': 'text/html' }, body: '{"a":1}',
  })
  assert.notEqual(withNoise.headerDigest, differentType.headerDigest, 'content-type still counts')
})

test('the volatile header set covers the common offenders', () => {
  for (const name of ['date', 'set-cookie', 'etag', 'x-request-id', 'cf-ray', 'content-length']) {
    assert.equal(VOLATILE_HEADERS.has(name), true, name)
  }
})

test('accepts a Headers instance as well as a plain object', () => {
  const viaHeaders = normalizeResponse({
    status: 200, headers: new Headers({ 'content-type': JSON_TYPE }), body: '{"a":1}',
  })
  const viaObject = normalizeResponse({
    status: 200, headers: { 'content-type': JSON_TYPE }, body: '{"a":1}',
  })
  assert.equal(responseDigest(viaHeaders), responseDigest(viaObject))
})
