import assert from 'node:assert/strict'
import { request } from 'node:http'
import { test } from 'node:test'
import { hostFromHeader, startHttpListener } from '../scripts/lib/bounty-oob-http.mjs'

// fetch() treats Host as a forbidden header and drops it, so the raw http client
// is used here: the Host header is the whole point of an OOB HTTP callback.
function send({ port, path = '/', method = 'GET', headers = {}, body }) {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, path, method, headers }, (res) => {
      const chunks = []
      res.on('data', (chunk) => chunks.push(chunk))
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }))
    })
    req.on('error', reject)
    if (body !== undefined) req.write(body)
    req.end()
  })
}

test('extracts a host without its port', () => {
  assert.equal(hostFromHeader('ABC.oob.example:8080'), 'abc.oob.example')
  assert.equal(hostFromHeader('abc.oob.example'), 'abc.oob.example')
  assert.equal(hostFromHeader('[2001:db8::1]:443'), '[2001:db8::1]')
  assert.equal(hostFromHeader(undefined), null)
  assert.equal(hostFromHeader(''), null)
})

test('captures a request over loopback including the host header', async () => {
  const seen = []
  const listener = await startHttpListener({
    port: 0,
    address: '127.0.0.1',
    onRequest: (event) => seen.push(event),
  })
  const oobHost = `${'c'.repeat(20)}${'n'.repeat(13)}.oob.example`
  const response = await send({
    port: listener.port,
    path: '/hit?x=1',
    method: 'POST',
    headers: { 'X-Probe': 'oob', Host: oobHost, 'Content-Length': '12' },
    body: 'payload-body',
  })
  await listener.close()
  assert.equal(response.status, 200)
  assert.equal(seen.length, 1)
  assert.equal(seen[0].protocol, 'http')
  assert.equal(seen[0].method, 'POST')
  assert.equal(seen[0].path, '/hit?x=1')
  assert.equal(seen[0].host, oobHost)
  assert.equal(seen[0].headers['x-probe'], 'oob')
  assert.equal(seen[0].body, 'payload-body')
  assert.equal(seen[0].bodyTruncated, false)
})

test('caps the captured body and flags truncation', async () => {
  const seen = []
  const listener = await startHttpListener({
    port: 0,
    address: '127.0.0.1',
    maxBodyBytes: 16,
    onRequest: (event) => seen.push(event),
  })
  await send({
    port: listener.port,
    method: 'POST',
    headers: { 'Content-Length': '512' },
    body: 'x'.repeat(512),
  })
  await listener.close()
  assert.equal(seen[0].body.length, 16)
  assert.equal(seen[0].bodyTruncated, true)
})

test('the response never reflects attacker controlled input', async () => {
  const listener = await startHttpListener({ port: 0, address: '127.0.0.1', onRequest: () => {} })
  const response = await send({
    port: listener.port,
    path: '/%3Cscript%3Ealert(1)%3C/script%3E',
    headers: { 'X-Evil': '<script>' },
  })
  await listener.close()
  assert.equal(response.body, 'ok\n')
  assert.equal(response.body.includes('script'), false)
})
