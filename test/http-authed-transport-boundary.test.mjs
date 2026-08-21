import assert from 'node:assert/strict'
import { X509Certificate } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { test } from 'node:test'

import { createHttpAuthedHttpsTransport } from '../scripts/lib/http-authed-client.mjs'
import { REFERENCE_TLS_CERTIFICATE } from './fixtures/reference-transparency-tls.mjs'

function transportThatFails({ beforeEnd = false } = {}) {
  const certificate = new X509Certificate(REFERENCE_TLS_CERTIFICATE).toLegacyObject()
  const state = { ended: 0 }
  const transport = createHttpAuthedHttpsTransport({
    dnsLookup: (_hostname, _options, callback) => queueMicrotask(() => callback(null, [
      { address: '93.184.216.34', family: 4 },
    ])),
    httpsRequest: (url, options) => {
      const request = new EventEmitter()
      request.destroy = () => {}
      request.end = () => {
        state.ended += 1
        queueMicrotask(() => request.emit('error', new Error('synthetic transport failure')))
      }
      queueMicrotask(() => {
        const socket = new EventEmitter()
        socket.encrypted = true
        socket.authorized = true
        request.emit('socket', socket)
        const identityError = options.checkServerIdentity(url.hostname, certificate)
        if (identityError) request.emit('error', identityError)
        else socket.emit('secureConnect')
      })
      return request
    },
  })
  const request = {
    url: 'https://reference-log.example.test/synthetic',
    method: 'POST',
    headers: {},
    body: Buffer.from('synthetic'),
    timeoutMs: 5_000,
    maxResponseBytes: 1_024,
    tls: { mode: 'PKIX_HOSTNAME' },
    beforeSend: beforeEnd
      ? async () => { throw new Error('synthetic verifier failure') }
      : async () => {},
  }
  return { transport, request, state }
}

test('transport errors state whether request bytes may have been sent', async () => {
  const after = transportThatFails()
  await assert.rejects(
    () => after.transport(after.request),
    (error) => {
      assert.equal(error.request_may_have_been_sent, true)
      return true
    },
  )
  assert.equal(after.state.ended, 1)

  const before = transportThatFails({ beforeEnd: true })
  await assert.rejects(
    () => before.transport(before.request),
    (error) => {
      assert.equal(error.request_may_have_been_sent, false)
      return true
    },
  )
  assert.equal(before.state.ended, 0)
})

test('protected transport exposes bounded discovery inputs only to a transient observer', async () => {
  const certificate = new X509Certificate(REFERENCE_TLS_CERTIFICATE).toLegacyObject()
  const secret = 'SYNTHETIC_TRANSIENT_RESPONSE_MARKER'
  let observed
  const transport = createHttpAuthedHttpsTransport({
    dnsLookup: (_hostname, _options, callback) => queueMicrotask(() => callback(null, [
      { address: '93.184.216.34', family: 4 },
    ])),
    httpsRequest: (url, options) => {
      const request = new EventEmitter()
      request.destroy = () => {}
      request.end = () => {
        const response = new EventEmitter()
        response.statusCode = 200
        response.rawHeaders = [
          'Content-Type', 'text/html; charset=utf-8',
          'Link', '</approved/next?subject=real-value>; rel="next"',
          'Set-Cookie', `session=${secret}`,
        ]
        response.destroy = () => {}
        queueMicrotask(() => {
          request.emit('response', response)
          response.emit('data', Buffer.from(`<a href="/approved/next">${secret}</a>`))
          response.emit('end')
        })
      }
      queueMicrotask(() => {
        const socket = new EventEmitter()
        socket.encrypted = true
        socket.authorized = true
        request.emit('socket', socket)
        const identityError = options.checkServerIdentity(url.hostname, certificate)
        if (identityError) request.emit('error', identityError)
        else socket.emit('secureConnect')
      })
      return request
    },
  })

  const result = await transport({
    url: 'https://reference-log.example.test/approved/start',
    method: 'GET',
    headers: {},
    body: null,
    timeoutMs: 5_000,
    maxResponseBytes: 1_024,
    tls: { mode: 'PKIX_HOSTNAME' },
    beforeSend: async () => {},
    responseObserver: async (input) => { observed = input },
  })

  assert.equal(observed.status, 200)
  assert.deepEqual(observed.headers.map(({ name }) => name), ['content-type', 'link'])
  assert.match(Buffer.concat(observed.bodyChunks).toString('utf8'), new RegExp(secret))
  assert.deepEqual(result, {
    status: 200,
    responseBytes: Buffer.byteLength(`<a href="/approved/next">${secret}</a>`),
    responseHeaderNames: ['content-type', 'link', 'set-cookie'],
  })
  assert.doesNotMatch(JSON.stringify(result), new RegExp(secret))
})
