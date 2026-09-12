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

test('redaction removes credentials from query strings and structured bodies', () => {
  const request = normalizeCapturedRequest({
    method: 'POST',
    url: 'https://x.example/login?access_token=query-secret&next=%2Fhome',
    headers: {
      authorization: 'Bearer header-secret',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      username: 'alice',
      password: 'body-password',
      csrfToken: 'body-csrf',
      sessionCookie: 'body-cookie',
    }),
  })

  const redacted = redactRequest(request)
  const persisted = JSON.stringify(redacted)
  const url = new URL(redacted.url)
  const body = JSON.parse(redacted.body)

  assert.equal(url.searchParams.get('access_token'), '<redacted>')
  assert.equal(url.searchParams.get('next'), '/home')
  assert.equal(body.username, 'alice')
  assert.equal(body.password, '<redacted>')
  assert.equal(body.csrfToken, '<redacted>')
  assert.equal(body.sessionCookie, '<redacted>')
  assert.deepEqual(redacted.redacted_query_parameters, ['access_token'])
  assert.deepEqual(redacted.redacted_body_fields, ['csrfToken', 'password', 'sessionCookie'])
  assert.doesNotMatch(persisted, /query-secret|header-secret|body-password|body-csrf|body-cookie/)
})

test('redaction removes credentials from form bodies', () => {
  const request = normalizeCapturedRequest({
    method: 'POST',
    url: 'https://x.example/login',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'username=alice&password=form-password&_csrf=form-csrf&session_cookie=form-cookie',
  })

  const redacted = redactRequest(request)
  const form = new URLSearchParams(redacted.body)
  assert.equal(form.get('username'), 'alice')
  assert.equal(form.get('password'), '<redacted>')
  assert.equal(form.get('_csrf'), '<redacted>')
  assert.equal(form.get('session_cookie'), '<redacted>')
  assert.doesNotMatch(JSON.stringify(redacted), /form-password|form-csrf|form-cookie/)
})

test('redaction resolves bounded layered field names before retaining query and form values', () => {
  let unresolvedTokenName = '%74oken'
  for (let pass = 0; pass < 9; pass += 1) unresolvedTokenName = encodeURIComponent(unresolvedTokenName)
  const redacted = redactRequest(normalizeCapturedRequest({
    method: 'POST',
    url: `https://x.example/login?%2574oken=layered-query-secret&${unresolvedTokenName}=unresolved-query-secret&safe=value`,
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: `%2570assword=layered-form-secret&${unresolvedTokenName}=unresolved-form-secret&safe=value`,
  }))

  assert.doesNotMatch(
    JSON.stringify(redacted),
    /layered-query-secret|layered-form-secret|unresolved-query-secret|unresolved-form-secret/,
  )
  assert.equal(new URL(redacted.url).searchParams.get('%74oken'), '<redacted>')
  assert.equal(new URLSearchParams(redacted.body).get('%70assword'), '<redacted>')
  assert.equal(new URLSearchParams(redacted.body).get('safe'), 'value')
})

test('redaction strips URL authority and fragment credentials and refuses malformed URLs', () => {
  const redacted = redactRequest(normalizeCapturedRequest({
    method: 'GET',
    url: 'https://alice:authority-secret@x.example/callback#access_token=fragment-secret&token_type=Bearer',
  }))

  assert.equal(redacted.url, 'https://x.example/callback')
  assert.deepEqual(redacted.redacted_query_parameters, ['<url-credentials>'])
  assert.doesNotMatch(JSON.stringify(redacted), /alice|authority-secret|fragment-secret/)

  for (const url of [
    'https://x.example/%?access_token=query-secret#access_token=fragment-secret',
    'https://x.example/path#access_token=fragment-secret%',
  ]) {
    assert.throws(
      () => redactRequest(normalizeCapturedRequest({ method: 'GET', url })),
      /URL.*parse|parse.*URL|valid.*URL/i,
      url,
    )
  }
})

test('redaction covers common signed-request, SSO, and secondary-header carriers', () => {
  const request = normalizeCapturedRequest({
    method: 'POST',
    url: 'https://x.example/login?X-Amz-Signature=query-signature&key=query-key&sig=sas-signature&state=oauth-state',
    headers: {
      'content-type': 'application/json',
      'api-key': 'header-api-key',
      'x-access-token': 'header-access-token',
      'x-amz-security-token': 'header-amz-token',
      'x-client-secret': 'header-client-secret',
      'x-goog-api-key': 'header-google-key',
      'x-hub-signature-256': 'header-hub-signature',
      'x-service-signature': 'header-service-signature',
    },
    body: JSON.stringify({
      SAMLRequest: 'saml-request-secret',
      SAMLResponse: 'saml-response-secret',
      RelayState: 'saml-relay-secret',
      assertion: 'assertion-secret',
    }),
  })

  const redacted = redactRequest(request)
  const persisted = JSON.stringify(redacted)
  assert.deepEqual(redacted.redacted_query_parameters, ['X-Amz-Signature', 'key', 'sig', 'state'])
  assert.deepEqual(redacted.redacted_body_fields, ['RelayState', 'SAMLRequest', 'SAMLResponse', 'assertion'])
  assert.deepEqual(redacted.redacted_headers, [
    'api-key',
    'x-access-token',
    'x-amz-security-token',
    'x-client-secret',
    'x-goog-api-key',
    'x-hub-signature-256',
    'x-service-signature',
  ])
  assert.doesNotMatch(
    persisted,
    /query-signature|query-key|sas-signature|oauth-state|header-api-key|header-access-token|header-amz-token|header-client-secret|header-google-key|header-hub-signature|header-service-signature|saml-request-secret|saml-response-secret|saml-relay-secret|assertion-secret/,
  )
})

test('redaction removes vendor-prefixed and layered SSO header carriers', () => {
  const layeredSamlResponse = 'x-okta-%2573aml-response-v3'
  const request = normalizeCapturedRequest({
    method: 'GET',
    url: 'https://x.example/callback',
    headers: {
      'x-oauth-state': 'oauth-state-secret',
      'x-okta-saml-response': 'okta-saml-secret',
      'x-auth-relay-state': 'relay-state-secret',
      'x-auth-code': 'authorization-code-secret',
      'x-%2561uth-code-v2': 'layered-authorization-code-secret',
      'x-vendor-saml-request-v12': 'versioned-saml-secret',
      [layeredSamlResponse]: 'layered-saml-secret',
      'x-status-code': '200',
      'x-response-code': 'accepted',
      'x-error-code': 'none',
      'x-public-shape': 'visible',
    },
  })

  const redacted = redactRequest(request)
  assert.equal(redacted.headers['x-public-shape'], 'visible')
  for (const name of [
    'x-oauth-state',
    'x-okta-saml-response',
    'x-auth-relay-state',
    'x-auth-code',
    'x-%2561uth-code-v2',
    'x-vendor-saml-request-v12',
    layeredSamlResponse,
  ]) {
    assert.equal(redacted.headers[name], undefined, name)
    assert.equal(redacted.redacted_headers.includes(name), true, name)
  }
  assert.equal(redacted.headers['x-status-code'], '200')
  assert.equal(redacted.headers['x-response-code'], 'accepted')
  assert.equal(redacted.headers['x-error-code'], 'none')
  assert.doesNotMatch(
    JSON.stringify(redacted),
    /oauth-state-secret|okta-saml-secret|relay-state-secret|authorization-code-secret|layered-authorization-code-secret|versioned-saml-secret|layered-saml-secret/,
  )
})

test('credential-free structured bodies retain their exact captured bytes', () => {
  for (const [contentType, body] of [
    ['application/json', '{"count":9007199254740993}\n'],
    ['application/x-www-form-urlencoded', 'x=%20&x=%2B'],
  ]) {
    const redacted = redactRequest(normalizeCapturedRequest({
      method: 'POST',
      url: 'https://x.example/submit',
      headers: { 'content-type': contentType },
      body,
    }))
    assert.equal(redacted.body, body, contentType)
    assert.deepEqual(redacted.redacted_body_fields, [], contentType)
  }
})

test('redaction is idempotent and retains legacy redaction evidence', () => {
  const first = redactRequest(normalizeCapturedRequest({
    method: 'POST',
    url: 'https://x.example/login?access_token=query-secret',
    headers: { 'content-type': 'application/json' },
    body: '{"password":"body-secret","safe":9007199254740993}',
    redacted_headers: ['authorization'],
  }))
  const second = redactRequest(normalizeCapturedRequest(first))

  assert.deepEqual(second, first)
  assert.deepEqual(second.redacted_headers, ['authorization'])
  assert.deepEqual(second.redacted_query_parameters, ['access_token'])
  assert.deepEqual(second.redacted_body_fields, ['password'])
})

test('redaction covers one-time-password and PIN credential fields', () => {
  const redacted = redactRequest(normalizeCapturedRequest({
    method: 'POST',
    url: 'https://x.example/verify?otp=query-otp&verification_code=query-code',
    headers: {
      'content-type': 'application/json',
      'x-otp': 'header-otp',
      'x-totp': 'header-totp',
      'x-pin': 'header-pin',
      'x-verification-code': 'header-code',
    },
    body: JSON.stringify({ pin: '1234', totp: '567890', one_time_password: 'body-otp' }),
  }))

  assert.doesNotMatch(
    JSON.stringify(redacted),
    /query-otp|query-code|header-otp|header-totp|header-pin|header-code|1234|567890|body-otp/,
  )
  assert.deepEqual(redacted.redacted_headers, [
    'x-otp', 'x-pin', 'x-totp', 'x-verification-code',
  ])
  assert.deepEqual(redacted.redacted_query_parameters, ['otp', 'verification_code'])
  assert.deepEqual(redacted.redacted_body_fields, ['one_time_password', 'pin', 'totp'])
})

test('unkeyed JSON values are removed because they cannot be proven credential-free', () => {
  for (const body of [
    '"top-level-secret"',
    '123456',
    'true',
    '["array-secret",{"name":"safe-label","assertion":"assertion-secret"}]',
    '[123456,false]',
    '{"items":["nested-array-secret"]}',
  ]) {
    const redacted = redactRequest(normalizeCapturedRequest({
      method: 'POST',
      url: 'https://x.example/submit',
      headers: { 'content-type': 'application/json' },
      body,
    }))
    assert.doesNotMatch(JSON.stringify(redacted), /top-level-secret|array-secret|assertion-secret|123456/)
    assert.notEqual(redacted.body, body)
    assert.ok(redacted.redacted_body_fields.length > 0)
  }
})

test('malformed form encoding is removed rather than preserved as credential-free bytes', () => {
  const redacted = redactRequest(normalizeCapturedRequest({
    method: 'POST',
    url: 'https://x.example/login',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'to%ZZken=malformed-form-secret&safe=value',
  }))

  assert.equal(redacted.body, null)
  assert.deepEqual(redacted.redacted_body_fields, ['<malformed-structured-body>'])
  assert.doesNotMatch(JSON.stringify(redacted), /malformed-form-secret/)
})

test('the sensitive header set covers the common credential carriers', () => {
  for (const name of [
    'authorization', 'cookie', 'set-cookie', 'x-api-key', 'x-auth-token',
    'api-key', 'x-access-token', 'x-amz-security-token', 'x-client-secret', 'x-goog-api-key',
    'x-mfa-code', 'x-one-time-password', 'x-otp', 'x-pin', 'x-totp', 'x-verification-code',
  ]) {
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
