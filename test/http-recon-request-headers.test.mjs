import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  createHttpReconRequestHeaderDescriptor,
  resolveHttpReconRequestHeaders,
} from '../scripts/lib/http-recon-request-headers.mjs'

const CASES = [
  ['cors-hostile-origin-get-v1', 'GET', { origin: 'https://red-team-audit.invalid' }],
  ['x-original-url-order-programs-v1', 'GET', { 'x-original-url': '/api/Order/GetPrograms' }],
  ['x-rewrite-url-order-programs-v1', 'GET', { 'x-rewrite-url': '/api/Order/GetPrograms' }],
  ['x-original-url-tabaccess-getall-v1', 'GET', { 'x-original-url': '/api/TabAccess/GetAll' }],
  ['x-rewrite-url-tabaccess-getall-v1', 'GET', { 'x-rewrite-url': '/api/TabAccess/GetAll' }],
  ['x-forwarded-for-loopback-v1', 'GET', { 'x-forwarded-for': '127.0.0.1' }],
  ['x-real-ip-loopback-v1', 'GET', { 'x-real-ip': '127.0.0.1' }],
  ['forwarded-loopback-https-v1', 'GET', { forwarded: 'for=127.0.0.1;proto=https' }],
  ['x-http-method-override-get-v1', 'OPTIONS', { 'x-http-method-override': 'GET' }],
]

test('diagnostic header profiles resolve only fixed controller-owned values', () => {
  for (const [profile, method, expected] of CASES) {
    const descriptor = createHttpReconRequestHeaderDescriptor({ profile, method })
    assert.deepEqual(descriptor.names, Object.keys(expected).sort())
    assert.match(descriptor.header_set_sha256, /^[a-f0-9]{64}$/)
    assert.equal(JSON.stringify(descriptor).includes(Object.values(expected)[0]), false)
    assert.deepEqual(resolveHttpReconRequestHeaders({ descriptor, method }), expected)
  }
})

test('unknown, method-mismatched, and forged profiles fail closed', () => {
  assert.throws(
    () => createHttpReconRequestHeaderDescriptor({ profile: 'arbitrary-header-v1', method: 'GET' }),
    /profile/i,
  )
  assert.throws(
    () => createHttpReconRequestHeaderDescriptor({
      profile: 'x-http-method-override-get-v1',
      method: 'GET',
    }),
    /method/i,
  )
  const descriptor = createHttpReconRequestHeaderDescriptor({
    profile: 'x-forwarded-for-loopback-v1',
    method: 'GET',
  })
  descriptor.header_set_sha256 = '0'.repeat(64)
  assert.throws(
    () => resolveHttpReconRequestHeaders({ descriptor, method: 'GET' }),
    /descriptor|digest/i,
  )
})
