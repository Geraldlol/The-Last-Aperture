import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  correlateInteraction,
  normalizeInteraction,
  summarizeCorrelation,
} from '../scripts/lib/bounty-oob-correlator.mjs'
import { createMintLedger, recordMint } from '../scripts/lib/bounty-oob-payload.mjs'

const CID = 'c'.repeat(20)
const NONCE = 'abcdefghijklm'
const SERVER = 'oast.fun'

function ledgerWithMint() {
  return recordMint(createMintLedger(), {
    nonce: NONCE,
    label: 'checkout-callback-url',
    requestId: 'flow-42',
    insertionPoint: 'body:json:/order/callbackUrl',
    role: 'customer',
    bugClass: 'ssrf',
    mintedAt: '2026-08-21T10:00:00.000Z',
  })
}

function dnsRaw(host = `${CID}${NONCE}.${SERVER}`) {
  return {
    protocol: 'dns',
    'unique-id': host.split('.')[0],
    'full-id': host,
    'q-type': 'A',
    'raw-request': ';; opcode: QUERY',
    'raw-response': ';; opcode: QUERY, status: NOERROR',
    'remote-address': '194.65.39.214',
    timestamp: '2026-08-21T10:05:00.123456789Z',
  }
}

test('normalizes a dns interaction into the canonical shape', () => {
  const record = normalizeInteraction(dnsRaw())
  assert.equal(record.protocol, 'dns')
  assert.equal(record.fullId, `${CID}${NONCE}.${SERVER}`)
  assert.equal(record.qType, 'A')
  assert.equal(record.remoteAddress, '194.65.39.214')
  assert.equal(record.observedAt, '2026-08-21T10:05:00.123456789Z')
})

test('normalizes an http interaction with no q-type', () => {
  const record = normalizeInteraction({
    protocol: 'http',
    'full-id': `${CID}${NONCE}.${SERVER}`,
    'raw-request': 'GET /hit?x=1 HTTP/1.1\r\nHost: x\r\n\r\n',
    'remote-address': '203.0.113.9',
    timestamp: '2026-08-21T10:06:00Z',
  })
  assert.equal(record.protocol, 'http')
  assert.equal(record.qType, null)
  assert.match(record.rawRequest, /^GET \/hit/)
})

test('refuses an interaction missing protocol or full-id', () => {
  assert.throws(() => normalizeInteraction({ 'full-id': 'x' }), /protocol/)
  assert.throws(() => normalizeInteraction({ protocol: 'dns' }), /full-id/)
})

test('correlates a callback back to the minting request', () => {
  const result = correlateInteraction({
    ledger: ledgerWithMint(),
    correlationId: CID,
    server: SERVER,
    interaction: normalizeInteraction(dnsRaw()),
  })
  assert.equal(result.matched, true)
  assert.equal(result.nonce, NONCE)
  assert.equal(result.mint.requestId, 'flow-42')
  assert.equal(result.mint.insertionPoint, 'body:json:/order/callbackUrl')
  assert.equal(result.mint.bugClass, 'ssrf')
})

test('correlates despite resolver case randomization', () => {
  const shouty = dnsRaw(`${CID}${NONCE}.${SERVER}`.toUpperCase())
  const result = correlateInteraction({
    ledger: ledgerWithMint(),
    correlationId: CID,
    server: SERVER,
    interaction: normalizeInteraction(shouty),
  })
  assert.equal(result.matched, true)
  assert.equal(result.nonce, NONCE)
})

test('reports a foreign host as not ours', () => {
  const result = correlateInteraction({
    ledger: ledgerWithMint(),
    correlationId: CID,
    server: SERVER,
    interaction: normalizeInteraction(dnsRaw('somebody.else.example')),
  })
  assert.equal(result.matched, false)
  assert.equal(result.reason, 'host-not-ours')
})

test('reports a well formed host whose nonce was never minted', () => {
  const result = correlateInteraction({
    ledger: createMintLedger(),
    correlationId: CID,
    server: SERVER,
    interaction: normalizeInteraction(dnsRaw()),
  })
  assert.equal(result.matched, false)
  assert.equal(result.reason, 'nonce-not-in-ledger')
})

test('summarizes a batch by bug class', () => {
  const ledger = ledgerWithMint()
  const results = [
    correlateInteraction({ ledger, correlationId: CID, server: SERVER, interaction: normalizeInteraction(dnsRaw()) }),
    correlateInteraction({ ledger, correlationId: CID, server: SERVER, interaction: normalizeInteraction(dnsRaw()) }),
    correlateInteraction({
      ledger,
      correlationId: CID,
      server: SERVER,
      interaction: normalizeInteraction(dnsRaw('nope.example')),
    }),
  ]
  const summary = summarizeCorrelation(results)
  assert.equal(summary.total, 3)
  assert.equal(summary.matched, 2)
  assert.equal(summary.unmatched, 1)
  assert.equal(summary.byBugClass.ssrf, 2)
})

test('an empty batch is NO_INTERACTION_OBSERVED, never a clearance', () => {
  const summary = summarizeCorrelation([])
  assert.equal(summary.total, 0)
  assert.equal(summary.matched, 0)
  assert.equal(summary.status, 'NO_INTERACTION_OBSERVED')
})
