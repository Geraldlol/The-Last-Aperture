import assert from 'node:assert/strict'
import { test } from 'node:test'
import { canonicalizeCandidate } from '../scripts/lib/bounty-target.mjs'

test('canonicalizes a plain https url with default port', () => {
  const result = canonicalizeCandidate('https://api.example.com/v1/users')
  assert.equal(result.ok, true)
  assert.deepEqual(result.target, {
    scheme: 'https:',
    host: 'api.example.com',
    port: 443,
    path: '/v1/users',
    hostKind: 'domain',
  })
})

test('rejects a candidate carrying userinfo', () => {
  const result = canonicalizeCandidate('https://allowed.example.com@evil.example/')
  assert.equal(result.ok, false)
  assert.equal(result.reason, 'candidate-carries-userinfo')
})

test('lowercases the host and strips a single trailing dot', () => {
  const result = canonicalizeCandidate('https://API.Example.COM./x')
  assert.equal(result.ok, true)
  assert.equal(result.target.host, 'api.example.com')
})

test('records an explicit non-default port', () => {
  const result = canonicalizeCandidate('https://api.example.com:8443/')
  assert.equal(result.ok, true)
  assert.equal(result.target.port, 8443)
})

test('classifies ipv4 and ipv6 hosts and unwraps ipv6 brackets', () => {
  const four = canonicalizeCandidate('http://203.0.113.7/')
  assert.equal(four.target.hostKind, 'ipv4')
  assert.equal(four.target.host, '203.0.113.7')
  const six = canonicalizeCandidate('http://[2001:db8::1]/')
  assert.equal(six.target.hostKind, 'ipv6')
  assert.equal(six.target.host, '2001:db8::1')
})

test('normalizes dot segments in the path', () => {
  const result = canonicalizeCandidate('https://api.example.com/a/b/../../etc/passwd')
  assert.equal(result.target.path, '/etc/passwd')
})

test('rejects non-http schemes', () => {
  assert.equal(canonicalizeCandidate('file:///etc/passwd').reason, 'scheme-not-http')
  assert.equal(canonicalizeCandidate('gopher://example.com/').reason, 'scheme-not-http')
})

test('rejects unparsable and non-string candidates', () => {
  assert.equal(canonicalizeCandidate('not a url').reason, 'candidate-unparsable')
  assert.equal(canonicalizeCandidate('').reason, 'candidate-not-a-string')
  assert.equal(canonicalizeCandidate(null).reason, 'candidate-not-a-string')
})

test('encodes internationalized hosts to punycode', () => {
  const result = canonicalizeCandidate('https://exämple.com/')
  assert.equal(result.ok, true)
  assert.equal(result.target.host, 'xn--exmple-cua.com')
})
