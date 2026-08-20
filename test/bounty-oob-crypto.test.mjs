import assert from 'node:assert/strict'
import { constants, publicEncrypt, randomBytes } from 'node:crypto'
import { test } from 'node:test'
import {
  INTERACTSH_CIPHER,
  buildRegisterBody,
  decryptInteraction,
  generateSessionKeypair,
  sealInteractionForTest,
  unwrapAesKey,
} from '../scripts/lib/bounty-oob-crypto.mjs'

test('the cipher is aes-256-ctr, not cfb', () => {
  // Verified empirically against oast.fun on 2026-08-21. CFB, OFB and CTR all
  // produce an identical first block, so a wrong choice here looks correct for
  // exactly 16 bytes. Do not change without re-probing a live server.
  assert.equal(INTERACTSH_CIPHER, 'aes-256-ctr')
})

test('generates a keypair whose public half is base64 of an SPKI PEM', () => {
  const keys = generateSessionKeypair()
  const pem = Buffer.from(keys.publicKeyBase64, 'base64').toString('utf8')
  assert.match(pem, /^-----BEGIN PUBLIC KEY-----/)
})

test('builds the register body with the exact server field names', () => {
  const body = JSON.parse(buildRegisterBody({
    publicKeyBase64: 'UEs=',
    secret: 'sec',
    correlationId: 'c'.repeat(20),
  }))
  assert.deepEqual(Object.keys(body).sort(), ['correlation-id', 'public-key', 'secret-key'])
  assert.equal(body['correlation-id'], 'c'.repeat(20))
})

test('unwraps an RSA-OAEP sha256 wrapped aes key', () => {
  const keys = generateSessionKeypair()
  const aesKey = randomBytes(32)
  const wrapped = publicEncrypt(
    { key: keys.publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    aesKey,
  )
  const out = unwrapAesKey({ privateKey: keys.privateKey, aesKeyBase64: wrapped.toString('base64') })
  assert.equal(out.length, 32)
  assert.equal(Buffer.compare(out, aesKey), 0)
})

test('round trips an interaction through the real cipher', () => {
  const aesKey = randomBytes(32)
  const interaction = { protocol: 'dns', 'full-id': `${'x'.repeat(33)}.oast.fun`, 'q-type': 'A' }
  const sealed = sealInteractionForTest({ aesKey, interaction, iv: randomBytes(16) })
  assert.deepEqual(decryptInteraction({ aesKey, dataBase64: sealed }), interaction)
})

test('round trips a payload longer than one block', () => {
  const aesKey = randomBytes(32)
  const interaction = {
    protocol: 'http',
    'full-id': `${'y'.repeat(33)}.oast.fun`,
    'raw-request': 'GET /'.padEnd(2048, 'x'),
  }
  const sealed = sealInteractionForTest({ aesKey, interaction, iv: randomBytes(16) })
  assert.deepEqual(decryptInteraction({ aesKey, dataBase64: sealed }), interaction)
})

test('decrypting with the wrong key does not yield the plaintext', () => {
  const aesKey = randomBytes(32)
  const sealed = sealInteractionForTest({
    aesKey,
    interaction: { protocol: 'dns', 'full-id': 'a' },
    iv: randomBytes(16),
  })
  assert.throws(() => decryptInteraction({ aesKey: randomBytes(32), dataBase64: sealed }))
})

test('refuses a payload too short to carry an iv', () => {
  assert.throws(
    () => decryptInteraction({ aesKey: randomBytes(32), dataBase64: Buffer.alloc(8).toString('base64') }),
    /too short/,
  )
})
