import assert from 'node:assert/strict'
import {
  constants,
  createPublicKey,
  publicEncrypt,
  randomBytes as cryptoRandomBytes,
} from 'node:crypto'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import {
  closeOobSession,
  ingestSelfHostedEvent,
  mintOobPayload,
  oobSessionStatus,
  openOobSession,
  pollOobSession,
} from '../scripts/lib/bounty-oob-controller.mjs'
import { sealInteractionForTest } from '../scripts/lib/bounty-oob-crypto.mjs'

const NOW = new Date('2026-08-21T10:00:00.000Z')
const seq = (n) => cryptoRandomBytes(n)

function okJson(body) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

const registerOk = () => okJson({ message: 'registration successful' })

async function workspace() {
  return mkdtemp(join(tmpdir(), 'bounty-oob-'))
}

// Serves a poll response encrypted to the session's own key, for whatever host
// the holder currently points at. Avoids ordering hazards between mint and poll.
function pollServer(holder) {
  const aesKey = cryptoRandomBytes(32)
  return async (url) => {
    if (String(url).endsWith('/register')) return registerOk()
    if (String(url).endsWith('/deregister')) return okJson({ message: 'deregistration successful' })
    const publicKey = createPublicKey({ key: holder.session.private_key_pem, format: 'pem' })
    const wrapped = publicEncrypt(
      { key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      aesKey,
    ).toString('base64')
    return okJson({
      aes_key: wrapped,
      data: holder.hosts.map((host) => sealInteractionForTest({
        aesKey,
        interaction: {
          protocol: 'dns',
          'full-id': host,
          'q-type': 'A',
          'remote-address': '194.65.39.214',
          timestamp: '2026-08-21T10:05:00Z',
        },
        iv: cryptoRandomBytes(16),
      })),
    })
  }
}

test('open registers a hosted session and persists it', async () => {
  const dir = await workspace()
  try {
    const calls = []
    const fetchImpl = async (url) => { calls.push(String(url)); return registerOk() }
    const session = await openOobSession({
      bundlePath: dir, backend: 'hosted', server: 'oast.fun', randomBytes: seq, now: NOW, fetchImpl,
    })
    assert.equal(session.backend, 'hosted')
    assert.equal(session.server, 'oast.fun')
    assert.equal(session.correlation_id.length, 20)
    assert.match(calls[0], /\/register$/)
    const onDisk = JSON.parse(await readFile(join(dir, 'oob-session.json'), 'utf8'))
    assert.equal(onDisk.correlation_id, session.correlation_id)
    assert.ok(onDisk.private_key_pem.includes('PRIVATE KEY'))
    assert.equal(onDisk.backend, 'hosted', 'backend recorded as evidence')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('refuses an unknown backend', async () => {
  const dir = await workspace()
  try {
    await assert.rejects(
      () => openOobSession({
        bundlePath: dir, backend: 'carrier-pigeon', server: 'x', randomBytes: seq, now: NOW,
        fetchImpl: registerOk,
      }),
      /unknown oob backend/,
    )
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('mint produces a host carrying the session correlation id and records provenance', async () => {
  const dir = await workspace()
  try {
    const session = await openOobSession({
      bundlePath: dir, backend: 'hosted', server: 'oast.fun', randomBytes: seq, now: NOW,
      fetchImpl: registerOk,
    })
    const minted = await mintOobPayload({
      bundlePath: dir, label: 'checkout-callback', requestId: 'flow-42',
      insertionPoint: 'body:json:/order/callbackUrl', role: 'customer', bugClass: 'ssrf',
      randomBytes: seq, now: NOW,
    })
    assert.equal(minted.host, `${session.correlation_id}${minted.nonce}.oast.fun`)
    assert.equal(minted.host.split('.')[0].length, 33)
    const status = await oobSessionStatus({ bundlePath: dir })
    assert.equal(status.mints, 1)
    assert.equal(status.status, 'NO_INTERACTION_OBSERVED')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('two mints never collide and both are retrievable', async () => {
  const dir = await workspace()
  try {
    await openOobSession({
      bundlePath: dir, backend: 'hosted', server: 'oast.fun', randomBytes: seq, now: NOW,
      fetchImpl: registerOk,
    })
    const a = await mintOobPayload({
      bundlePath: dir, label: 'a', bugClass: 'ssrf', randomBytes: seq, now: NOW,
    })
    const b = await mintOobPayload({
      bundlePath: dir, label: 'b', bugClass: 'xxe', randomBytes: seq, now: NOW,
    })
    assert.notEqual(a.nonce, b.nonce)
    assert.equal((await oobSessionStatus({ bundlePath: dir })).mints, 2)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('poll correlates a callback back to the mint and records it', async () => {
  const dir = await workspace()
  try {
    const holder = { session: null, hosts: [] }
    const fetchImpl = pollServer(holder)
    holder.session = await openOobSession({
      bundlePath: dir, backend: 'hosted', server: 'oast.fun', randomBytes: seq, now: NOW, fetchImpl,
    })
    const minted = await mintOobPayload({
      bundlePath: dir, label: 'ssrf-probe', requestId: 'flow-9', insertionPoint: 'query:url',
      role: 'anonymous', bugClass: 'ssrf', randomBytes: seq, now: NOW,
    })
    holder.hosts = [minted.host]
    const { results, summary } = await pollOobSession({ bundlePath: dir, fetchImpl })
    assert.equal(summary.matched, 1)
    assert.equal(summary.status, 'INTERACTIONS_OBSERVED')
    assert.equal(results[0].mint.requestId, 'flow-9')
    assert.equal(results[0].mint.bugClass, 'ssrf')
    assert.equal(results[0].mint.insertionPoint, 'query:url')
    const jsonl = await readFile(join(dir, 'oob-interactions.jsonl'), 'utf8')
    assert.equal(jsonl.trim().split('\n').length, 1)
    const status = await oobSessionStatus({ bundlePath: dir })
    assert.equal(status.observed, 1)
    assert.equal(status.matched, 1)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('poll correlates despite resolver case randomization', async () => {
  const dir = await workspace()
  try {
    const holder = { session: null, hosts: [] }
    const fetchImpl = pollServer(holder)
    holder.session = await openOobSession({
      bundlePath: dir, backend: 'hosted', server: 'oast.fun', randomBytes: seq, now: NOW, fetchImpl,
    })
    const minted = await mintOobPayload({
      bundlePath: dir, label: 'case', bugClass: 'ssrf', randomBytes: seq, now: NOW,
    })
    holder.hosts = [minted.host.toUpperCase()]
    const { summary } = await pollOobSession({ bundlePath: dir, fetchImpl })
    assert.equal(summary.matched, 1)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('a callback for an unminted nonce is recorded as unmatched, not dropped', async () => {
  const dir = await workspace()
  try {
    const holder = { session: null, hosts: [] }
    const fetchImpl = pollServer(holder)
    holder.session = await openOobSession({
      bundlePath: dir, backend: 'hosted', server: 'oast.fun', randomBytes: seq, now: NOW, fetchImpl,
    })
    holder.hosts = [`${holder.session.correlation_id}zzzzzzzzzzzzz.oast.fun`]
    const { summary, results } = await pollOobSession({ bundlePath: dir, fetchImpl })
    assert.equal(summary.matched, 0)
    assert.equal(summary.unmatched, 1)
    assert.equal(results[0].reason, 'nonce-not-in-ledger')
    const jsonl = await readFile(join(dir, 'oob-interactions.jsonl'), 'utf8')
    assert.equal(jsonl.trim().split('\n').length, 1, 'unmatched callbacks are still recorded')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('an empty poll reports NO_INTERACTION_OBSERVED and writes nothing', async () => {
  const dir = await workspace()
  try {
    const fetchImpl = async (url) => (String(url).endsWith('/register')
      ? registerOk()
      : okJson({ aes_key: null, data: null }))
    await openOobSession({
      bundlePath: dir, backend: 'hosted', server: 'oast.fun', randomBytes: seq, now: NOW, fetchImpl,
    })
    const { summary } = await pollOobSession({ bundlePath: dir, fetchImpl })
    assert.equal(summary.total, 0)
    assert.equal(summary.status, 'NO_INTERACTION_OBSERVED')
    await assert.rejects(() => readFile(join(dir, 'oob-interactions.jsonl'), 'utf8'), /ENOENT/)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('close deregisters a hosted session', async () => {
  const dir = await workspace()
  try {
    const calls = []
    const fetchImpl = async (url) => { calls.push(String(url)); return okJson({ message: 'ok' }) }
    await openOobSession({
      bundlePath: dir, backend: 'hosted', server: 'oast.fun', randomBytes: seq, now: NOW, fetchImpl,
    })
    const result = await closeOobSession({ bundlePath: dir, fetchImpl })
    assert.equal(result.deregistered, true)
    assert.ok(calls.some((url) => url.endsWith('/deregister')))
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('a self-hosted session opens with no network call at all', async () => {
  const dir = await workspace()
  try {
    const fetchImpl = async () => { throw new Error('self-hosted must not call the network') }
    const session = await openOobSession({
      bundlePath: dir, backend: 'self_hosted', server: 'oob.mydomain.example',
      randomBytes: seq, now: NOW, fetchImpl,
    })
    assert.equal(session.backend, 'self_hosted')
    assert.equal(session.server, 'oob.mydomain.example')
    const closed = await closeOobSession({ bundlePath: dir, fetchImpl })
    assert.equal(closed.deregistered, false)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('self-hosted poll is refused with a pointer to the right path', async () => {
  const dir = await workspace()
  try {
    await openOobSession({
      bundlePath: dir, backend: 'self_hosted', server: 'oob.mydomain.example',
      randomBytes: seq, now: NOW, fetchImpl: async () => { throw new Error('no network') },
    })
    await assert.rejects(() => pollOobSession({ bundlePath: dir }), /ingestSelfHostedEvent/)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('a self-hosted dns listener event correlates to its mint', async () => {
  const dir = await workspace()
  try {
    await openOobSession({
      bundlePath: dir, backend: 'self_hosted', server: 'oob.mydomain.example',
      randomBytes: seq, now: NOW, fetchImpl: async () => { throw new Error('no network') },
    })
    const minted = await mintOobPayload({
      bundlePath: dir, label: 'blind-xxe', requestId: 'flow-7', insertionPoint: 'body:xml:/root/ext',
      role: 'admin', bugClass: 'xxe', randomBytes: seq, now: NOW,
    })
    const result = await ingestSelfHostedEvent({
      bundlePath: dir,
      now: NOW,
      event: {
        protocol: 'dns',
        name: minted.host,
        qType: 'A',
        remoteAddress: '203.0.113.55',
        rawRequest: 'AAAA',
      },
    })
    assert.equal(result.matched, true)
    assert.equal(result.mint.bugClass, 'xxe')
    assert.equal(result.mint.insertionPoint, 'body:xml:/root/ext')
    assert.equal(result.interaction.remoteAddress, '203.0.113.55')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('a self-hosted http listener event correlates and keeps the raw request', async () => {
  const dir = await workspace()
  try {
    await openOobSession({
      bundlePath: dir, backend: 'self_hosted', server: 'oob.mydomain.example',
      randomBytes: seq, now: NOW, fetchImpl: async () => { throw new Error('no network') },
    })
    const minted = await mintOobPayload({
      bundlePath: dir, label: 'blind-ssrf', bugClass: 'ssrf', randomBytes: seq, now: NOW,
    })
    const result = await ingestSelfHostedEvent({
      bundlePath: dir,
      now: NOW,
      event: {
        protocol: 'http',
        method: 'GET',
        path: '/callback?token=abc',
        host: minted.host,
        headers: { 'user-agent': 'curl/8.0' },
        body: '',
        remoteAddress: '203.0.113.56',
      },
    })
    assert.equal(result.matched, true)
    assert.equal(result.mint.bugClass, 'ssrf')
    assert.match(result.interaction.rawRequest, /^GET \/callback\?token=abc/)
    assert.match(result.interaction.rawRequest, /user-agent: curl\/8\.0/)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})
