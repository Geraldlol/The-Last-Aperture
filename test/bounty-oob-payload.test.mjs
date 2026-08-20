import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  buildPayloadHost,
  createCorrelationId,
  createMintLedger,
  extractNonce,
  lookupMint,
  mintNonce,
  recordMint,
} from '../scripts/lib/bounty-oob-payload.mjs'

const seq = (n) => Buffer.from(Array.from({ length: n }, (_, i) => i))

test('correlation ids and nonces have the interactsh lengths and alphabet', () => {
  const cid = createCorrelationId(seq)
  const nonce = mintNonce(seq)
  assert.equal(cid.length, 20)
  assert.equal(nonce.length, 13)
  assert.match(cid, /^[a-z0-9]{20}$/)
  assert.match(nonce, /^[a-z0-9]{13}$/)
})

test('builds a lowercase 33 character label plus the server', () => {
  const host = buildPayloadHost({ correlationId: 'c'.repeat(20), nonce: 'n'.repeat(13), server: 'oast.fun' })
  assert.equal(host, `${'c'.repeat(20)}${'n'.repeat(13)}.oast.fun`)
  assert.equal(host.split('.')[0].length, 33)
})

test('rejects a correlation id or nonce of the wrong length', () => {
  assert.throws(
    () => buildPayloadHost({ correlationId: 'short', nonce: 'n'.repeat(13), server: 'oast.fun' }),
    /correlation/,
  )
  assert.throws(
    () => buildPayloadHost({ correlationId: 'c'.repeat(20), nonce: 'short', server: 'oast.fun' }),
    /nonce/,
  )
})

test('extracts the nonce back out of a callback host', () => {
  const correlationId = 'c'.repeat(20)
  const host = buildPayloadHost({ correlationId, nonce: 'abcdefghijklm', server: 'oast.fun' })
  assert.equal(extractNonce({ host, correlationId, server: 'oast.fun' }), 'abcdefghijklm')
})

test('extraction is case insensitive because resolvers randomize case', () => {
  const correlationId = 'c'.repeat(20)
  const host = `${'C'.repeat(20)}ABCDEFGHIJKLM.OAST.FUN`
  assert.equal(extractNonce({ host, correlationId, server: 'oast.fun' }), 'abcdefghijklm')
})

test('extraction tolerates a trailing dot and deeper labels', () => {
  const correlationId = 'c'.repeat(20)
  assert.equal(
    extractNonce({ host: `${'c'.repeat(20)}abcdefghijklm.oast.fun.`, correlationId, server: 'oast.fun' }),
    'abcdefghijklm',
  )
  assert.equal(
    extractNonce({ host: `x.y.${'c'.repeat(20)}abcdefghijklm.oast.fun`, correlationId, server: 'oast.fun' }),
    'abcdefghijklm',
  )
})

test('extraction refuses a foreign correlation id or server', () => {
  const correlationId = 'c'.repeat(20)
  const foreign = buildPayloadHost({ correlationId: 'd'.repeat(20), nonce: 'abcdefghijklm', server: 'oast.fun' })
  assert.equal(extractNonce({ host: foreign, correlationId, server: 'oast.fun' }), null)
  const ours = buildPayloadHost({ correlationId, nonce: 'abcdefghijklm', server: 'oast.fun' })
  assert.equal(extractNonce({ host: ours, correlationId, server: 'evil.example' }), null)
})

test('extraction refuses a malformed label length', () => {
  const correlationId = 'c'.repeat(20)
  assert.equal(extractNonce({ host: `${'c'.repeat(20)}short.oast.fun`, correlationId, server: 'oast.fun' }), null)
  assert.equal(extractNonce({ host: 'oast.fun', correlationId, server: 'oast.fun' }), null)
  assert.equal(extractNonce({ host: '', correlationId, server: 'oast.fun' }), null)
  assert.equal(extractNonce({ host: null, correlationId, server: 'oast.fun' }), null)
})

test('the ledger records and retrieves mint provenance', () => {
  let ledger = createMintLedger()
  ledger = recordMint(ledger, {
    nonce: 'abcdefghijklm',
    label: 'checkout-callback-url',
    requestId: 'flow-42',
    insertionPoint: 'body:json:/order/callbackUrl',
    role: 'customer',
    bugClass: 'ssrf',
    mintedAt: '2026-08-21T10:00:00.000Z',
  })
  const entry = lookupMint(ledger, 'abcdefghijklm')
  assert.equal(entry.requestId, 'flow-42')
  assert.equal(entry.insertionPoint, 'body:json:/order/callbackUrl')
  assert.equal(entry.bugClass, 'ssrf')
  assert.equal(lookupMint(ledger, 'nnnnnnnnnnnnn'), null)
})

test('the ledger refuses a duplicate nonce', () => {
  let ledger = createMintLedger()
  const mint = {
    nonce: 'abcdefghijklm',
    label: 'a',
    requestId: 'r',
    insertionPoint: 'p',
    role: 'x',
    bugClass: 'ssrf',
    mintedAt: '2026-08-21T10:00:00.000Z',
  }
  ledger = recordMint(ledger, mint)
  assert.throws(() => recordMint(ledger, mint), /already/)
})

test('ledger lookup is case insensitive', () => {
  let ledger = createMintLedger()
  ledger = recordMint(ledger, {
    nonce: 'abcdefghijklm',
    label: 'a',
    requestId: 'r',
    insertionPoint: 'p',
    role: 'x',
    bugClass: 'ssrf',
    mintedAt: '2026-08-21T10:00:00.000Z',
  })
  assert.equal(lookupMint(ledger, 'ABCDEFGHIJKLM').requestId, 'r')
})
