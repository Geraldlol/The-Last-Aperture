import assert from 'node:assert/strict'
import { createSocket } from 'node:dgram'
import { test } from 'node:test'
import {
  DNS_TYPE,
  buildDnsResponse,
  parseDnsQuery,
  startDnsListener,
} from '../scripts/lib/bounty-oob-dns.mjs'

// Hand-build a query: 12-byte header, length-prefixed labels, root, qtype, qclass.
function queryFor(name, qtype = DNS_TYPE.A) {
  const labels = name.split('.').map((label) => {
    const out = Buffer.alloc(1 + label.length)
    out.writeUInt8(label.length, 0)
    out.write(label, 1, 'ascii')
    return out
  })
  const header = Buffer.alloc(12)
  header.writeUInt16BE(0x1234, 0)
  header.writeUInt16BE(0x0100, 2)
  header.writeUInt16BE(1, 4)
  const tail = Buffer.alloc(5)
  tail.writeUInt8(0, 0)
  tail.writeUInt16BE(qtype, 1)
  tail.writeUInt16BE(1, 3)
  return Buffer.concat([header, ...labels, tail])
}

test('parses a well formed A query', () => {
  const parsed = parseDnsQuery(queryFor('abc.example'))
  assert.equal(parsed.id, 0x1234)
  assert.equal(parsed.name, 'abc.example')
  assert.equal(parsed.qtype, DNS_TYPE.A)
  assert.equal(parsed.qclass, 1)
})

test('parses a 33 character interactsh style label', () => {
  const host = `${'c'.repeat(20)}${'n'.repeat(13)}.oob.example`
  assert.equal(parseDnsQuery(queryFor(host)).name, host)
})

test('parses an AAAA query type', () => {
  assert.equal(parseDnsQuery(queryFor('x.example', DNS_TYPE.AAAA)).qtype, DNS_TYPE.AAAA)
})

test('refuses a truncated packet', () => {
  assert.throws(() => parseDnsQuery(Buffer.alloc(4)), /too short/)
})

test('refuses a packet with no question', () => {
  const header = Buffer.alloc(12)
  header.writeUInt16BE(0, 4)
  assert.throws(() => parseDnsQuery(header), /question/)
})

test('refuses a label length that runs past the packet', () => {
  const bad = Buffer.concat([queryFor('abc.example').subarray(0, 12), Buffer.from([0x40, 0x61])])
  assert.throws(() => parseDnsQuery(bad), /malformed/)
})

test('refuses compression pointers in the question', () => {
  const bad = Buffer.concat([queryFor('abc.example').subarray(0, 12), Buffer.from([0xc0, 0x0c])])
  assert.throws(() => parseDnsQuery(bad), /compression/)
})

test('builds a response that echoes the id and question and answers A', () => {
  const buffer = queryFor('abc.example')
  const query = parseDnsQuery(buffer)
  const response = buildDnsResponse({ query, buffer, address: '203.0.113.7', ttl: 60 })
  assert.equal(response.readUInt16BE(0), 0x1234, 'id echoed')
  assert.equal((response.readUInt16BE(2) & 0x8000) !== 0, true, 'QR bit set')
  assert.equal((response.readUInt16BE(2) & 0x0400) !== 0, true, 'AA bit set')
  assert.equal(response.readUInt16BE(4), 1, 'QDCOUNT echoed')
  assert.equal(response.readUInt16BE(6), 1, 'ANCOUNT is 1')
  assert.deepEqual([...response.subarray(response.length - 4)], [203, 0, 113, 7], 'rdata is the address')
})

test('the answer record carries type A, class IN, the ttl, and rdlength 4', () => {
  const buffer = queryFor('abc.example')
  const query = parseDnsQuery(buffer)
  const response = buildDnsResponse({ query, buffer, address: '198.51.100.9', ttl: 42 })
  // answer RR trailer is the last 14 bytes: type(2) class(2) ttl(4) rdlen(2) rdata(4)
  const trailer = response.subarray(response.length - 14)
  assert.equal(trailer.readUInt16BE(0), DNS_TYPE.A)
  assert.equal(trailer.readUInt16BE(2), 1)
  assert.equal(trailer.readUInt32BE(4), 42)
  assert.equal(trailer.readUInt16BE(8), 4)
  assert.deepEqual([...trailer.subarray(10)], [198, 51, 100, 9])
})

test('answers with zero records for a non-A query but still responds', () => {
  const buffer = queryFor('abc.example', DNS_TYPE.AAAA)
  const query = parseDnsQuery(buffer)
  const response = buildDnsResponse({ query, buffer, address: '203.0.113.7', ttl: 60 })
  assert.equal(response.readUInt16BE(6), 0, 'ANCOUNT is 0 for AAAA')
  assert.equal(response.readUInt16BE(4), 1, 'question still echoed')
})

test('refuses a non-ipv4 answer address', () => {
  const buffer = queryFor('abc.example')
  const query = parseDnsQuery(buffer)
  assert.throws(() => buildDnsResponse({ query, buffer, address: '2001:db8::1' }), /ipv4/)
})

test('the listener captures a real query over loopback udp', async () => {
  const seen = []
  const listener = await startDnsListener({
    port: 0,
    address: '127.0.0.1',
    answerAddress: '203.0.113.7',
    onQuery: (event) => { seen.push(event) },
  })
  const client = createSocket('udp4')
  const host = `${'c'.repeat(20)}${'n'.repeat(13)}.oob.example`
  const reply = new Promise((resolve) => { client.once('message', resolve) })
  await new Promise((resolve, reject) => {
    client.send(queryFor(host), listener.port, '127.0.0.1', (error) => (error ? reject(error) : resolve()))
  })
  const response = await reply
  client.close()
  await listener.close()
  assert.equal(seen.length, 1)
  assert.equal(seen[0].name, host)
  assert.equal(seen[0].protocol, 'dns')
  assert.equal(seen[0].qType, 'A')
  assert.equal(seen[0].remoteAddress, '127.0.0.1')
  assert.deepEqual([...response.subarray(response.length - 4)], [203, 0, 113, 7])
})

test('the listener ignores garbage without dying', async () => {
  const seen = []
  const listener = await startDnsListener({
    port: 0,
    address: '127.0.0.1',
    onQuery: (event) => { seen.push(event) },
  })
  const client = createSocket('udp4')
  await new Promise((resolve, reject) => {
    client.send(Buffer.from('not a dns packet'), listener.port, '127.0.0.1', (e) => (e ? reject(e) : resolve()))
  })
  // then a valid query proves the listener is still alive
  const host = `${'d'.repeat(20)}${'m'.repeat(13)}.oob.example`
  const reply = new Promise((resolve) => { client.once('message', resolve) })
  await new Promise((resolve, reject) => {
    client.send(queryFor(host), listener.port, '127.0.0.1', (e) => (e ? reject(e) : resolve()))
  })
  await reply
  client.close()
  await listener.close()
  assert.equal(seen.length, 1)
  assert.equal(seen[0].name, host)
})
