import assert from 'node:assert/strict'
import { constants, publicEncrypt, randomBytes } from 'node:crypto'
import { test } from 'node:test'
import { generateSessionKeypair, sealInteractionForTest } from '../scripts/lib/bounty-oob-crypto.mjs'
import {
  HOSTED_SERVERS,
  deregisterHostedSession,
  pollHostedSession,
  registerHostedSession,
} from '../scripts/lib/bounty-oob-hosted.mjs'

const CID = 'c'.repeat(20)

function stubFetch(handler) {
  const calls = []
  const impl = async (url, init) => {
    calls.push({ url: String(url), init })
    return handler(String(url), init)
  }
  impl.calls = calls
  return impl
}

const ok = (body) => new Response(JSON.stringify(body), {
  status: 200,
  headers: { 'Content-Type': 'application/json' },
})

test('the documented public servers are present', () => {
  assert.ok(HOSTED_SERVERS.includes('oast.fun'))
  assert.ok(HOSTED_SERVERS.length >= 4)
})

test('register posts to /register and succeeds on 200', async () => {
  const fetchImpl = stubFetch(() => ok({ message: 'registration successful' }))
  await registerHostedSession({
    server: 'oast.fun',
    correlationId: CID,
    secret: 's',
    publicKeyBase64: 'UEs=',
    fetchImpl,
  })
  assert.match(fetchImpl.calls[0].url, /^https:\/\/oast\.fun\/register$/)
  assert.equal(fetchImpl.calls[0].init.method, 'POST')
  assert.equal(JSON.parse(fetchImpl.calls[0].init.body)['correlation-id'], CID)
})

test('register throws on a non-2xx response', async () => {
  const fetchImpl = stubFetch(() => new Response('nope', { status: 400 }))
  await assert.rejects(
    () => registerHostedSession({
      server: 'oast.fun',
      correlationId: CID,
      secret: 's',
      publicKeyBase64: 'UEs=',
      fetchImpl,
    }),
    /400/,
  )
})

test('poll decrypts every returned interaction', async () => {
  const keys = generateSessionKeypair()
  const aesKey = randomBytes(32)
  const wrapped = publicEncrypt(
    { key: keys.publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    aesKey,
  ).toString('base64')
  const one = { protocol: 'dns', 'full-id': `${'a'.repeat(33)}.oast.fun`, 'q-type': 'A' }
  const two = { protocol: 'http', 'full-id': `${'b'.repeat(33)}.oast.fun` }
  const fetchImpl = stubFetch(() => ok({
    aes_key: wrapped,
    data: [
      sealInteractionForTest({ aesKey, interaction: one, iv: randomBytes(16) }),
      sealInteractionForTest({ aesKey, interaction: two, iv: randomBytes(16) }),
    ],
  }))
  const out = await pollHostedSession({
    server: 'oast.fun',
    correlationId: CID,
    secret: 's',
    privateKey: keys.privateKey,
    fetchImpl,
  })
  assert.equal(out.length, 2)
  assert.equal(out[0].protocol, 'dns')
  assert.equal(out[1].protocol, 'http')
  assert.match(fetchImpl.calls[0].url, /\/poll\?id=c{20}&secret=s$/)
})

test('poll returns an empty list when the server reports no data', async () => {
  const fetchImpl = stubFetch(() => ok({ aes_key: null, data: null }))
  const out = await pollHostedSession({
    server: 'oast.fun',
    correlationId: CID,
    secret: 's',
    privateKey: generateSessionKeypair().privateKey,
    fetchImpl,
  })
  assert.deepEqual(out, [])
})

test('poll throws when data arrives without an aes key', async () => {
  const fetchImpl = stubFetch(() => ok({ aes_key: null, data: ['AAAA'] }))
  await assert.rejects(
    () => pollHostedSession({
      server: 'oast.fun',
      correlationId: CID,
      secret: 's',
      privateKey: generateSessionKeypair().privateKey,
      fetchImpl,
    }),
    /aes key/,
  )
})

test('deregister posts the correlation id and secret', async () => {
  const fetchImpl = stubFetch(() => ok({ message: 'deregistration successful' }))
  await deregisterHostedSession({ server: 'oast.fun', correlationId: CID, secret: 's', fetchImpl })
  assert.match(fetchImpl.calls[0].url, /\/deregister$/)
  assert.equal(JSON.parse(fetchImpl.calls[0].init.body)['secret-key'], 's')
})
