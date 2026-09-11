import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import Ajv2020 from 'ajv/dist/2020.js'

import {
  assertValidNativeInteractionContract,
  buildNativeInteractionContract,
} from '../scripts/lib/reverse-protocol.mjs'
import {
  importBurpHttpItemsEvidence,
} from '../scripts/lib/reverse-web-burp.mjs'
import {
  assertValidWebSessionEvidence,
  canonicalWebSessionEvidence,
  importWebHarEvidence,
} from '../scripts/lib/reverse-web-har.mjs'
import { stableJson } from '../scripts/lib/run-engine.mjs'

const SOURCE_HASH = 'c'.repeat(64)
const WEB_SESSION_SCHEMA = JSON.parse(readFileSync(
  new URL('../schemas/web-session-evidence.schema.json', import.meta.url),
  'utf8',
))
const validateWebSessionSchema = new Ajv2020({
  strict: true,
  strictTuples: false,
  allErrors: true,
  allowUnionTypes: true,
}).compile(WEB_SESSION_SCHEMA)

function xmlEscape(value) {
  return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
}

function burpItem({ request, response, url = 'https://service.example/auth/login?tenant=private&mode=private-mode', method = 'POST', status = 302, base64 = true }) {
  const encode = (value) => base64
    ? Buffer.from(value, 'utf8').toString('base64')
    : `<![CDATA[${value}]]>`
  const parsed = new URL(url)
  return `<item>
    <time>Thu Sep 11 12:00:00 EEST 2026</time>
    <url>${xmlEscape(url)}</url>
    <host ip="192.0.2.10">service.example</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>${method}</method>
    <path>${xmlEscape(`${parsed.pathname}${parsed.search}`)}</path>
    <request base64="${base64}">${encode(request)}</request>
    <status>${status}</status>
    <responselength>${Buffer.byteLength(response)}</responselength>
    <mimetype>JSON</mimetype>
    <response base64="${base64}">${encode(response)}</response>
    <comment>operator note that must not be retained</comment>
  </item>`
}

function document(item) {
  return `<?xml version="1.0" encoding="UTF-8"?>
  <items burpVersion="2026.8" exportTime="Thu Sep 11 12:01:00 EEST 2026">${item}</items>`
}

const REQUEST = [
  'POST /auth/login?tenant=private&mode=private-mode HTTP/1.1',
  'Host: service.example',
  'Authorization: Bearer private-token',
  'Cookie: SessionId=private-cookie',
  'Content-Type: application/json',
  '',
  '{"username":"private-user","password":"private-password"}',
].join('\r\n')

const RESPONSE = [
  'HTTP/1.1 302 Found',
  'Set-Cookie: SessionId=private-response-cookie; Secure; HttpOnly',
  'Location: /home?ticket=private-ticket',
  'Content-Type: application/json',
  '',
  '{"nextUrl":"/home?ticket=private-ticket","account":"private-account"}',
].join('\r\n')

test('Burp HTTP-items XML imports base64 messages through value-free web evidence', () => {
  const evidence = importBurpHttpItemsEvidence(document(burpItem({ request: REQUEST, response: RESPONSE })), {
    sourceSha256: SOURCE_HASH,
    targetOrigins: ['https://service.example'],
    pathLiterals: ['home'],
  })

  assert.equal(assertValidWebSessionEvidence(evidence), evidence)
  assert.equal(evidence.schema_version, '1.1.0')
  assert.equal(validateWebSessionSchema(evidence), true)
  assert.equal(evidence.source.kind, 'BURP_XML')
  assert.equal(evidence.entries.length, 1)
  assert.deepEqual(evidence.entries[0].request.header_names, [
    'authorization', 'content-type', 'cookie', 'host',
  ])
  assert.deepEqual(evidence.entries[0].request.credential_carriers, [
    'body:password', 'body:username', 'cookie:SessionId', 'header:authorization',
  ])
  assert.equal(evidence.entries[0].response.redirect.path_template, '/home')
  assert.deepEqual(evidence.gaps.map(({ code }) => code), ['BURP_XML_METADATA_ONLY'])

  const serialized = canonicalWebSessionEvidence(evidence)
  for (const value of [
    'private-token', 'private-cookie', 'private-response-cookie', 'private-ticket',
    'private-user', 'private-password', 'private-account', 'private-mode', 'operator note', '192.0.2.10',
  ]) assert.equal(serialized.includes(value), false, value)
})

test('Burp HTTP-items XML applies the same exact path-prefix boundary to requests and destinations', () => {
  const outsideUrl = 'https://service.example/authentication?tenant=private&mode=private-mode'
  const outsideRequest = REQUEST.replace(
    'POST /auth/login?tenant=private&mode=private-mode',
    'POST /authentication?tenant=private&mode=private-mode',
  )
  const xml = document([
    burpItem({ request: REQUEST, response: RESPONSE }),
    burpItem({ request: outsideRequest, response: RESPONSE, url: outsideUrl }),
  ].join('\n'))
  const evidence = importBurpHttpItemsEvidence(xml, {
    sourceSha256: SOURCE_HASH,
    targetOrigins: ['https://service.example'],
    targetPathPrefix: '/auth',
  })

  assert.deepEqual(evidence.entries.map(({ request }) => request.path_template), ['/auth/login'])
  assert.equal(evidence.skipped.off_scope, 1)
  assert.equal(evidence.entries[0].response.redirect, null)
  assert.deepEqual(evidence.entries[0].response.destinations, [])
})

test('Burp HTTP-items XML accepts plain raw HTTP and normalizes mixed source provenance', () => {
  const burp = importBurpHttpItemsEvidence(document(burpItem({
    request: REQUEST,
    response: RESPONSE,
    base64: false,
  })), {
    sourceSha256: SOURCE_HASH,
    targetOrigins: ['https://service.example'],
    pathLiterals: ['home'],
  })
  const har = importWebHarEvidence({ log: { entries: [{
    request: {
      method: 'POST',
      url: 'https://service.example/auth/login?tenant=another-private-value',
      headers: [{ name: 'Authorization', value: 'Bearer another-private-token' }],
      cookies: [],
      postData: { mimeType: 'application/json', text: '{"password":"another-private-password"}' },
    },
    response: { status: 200, headers: [], cookies: [], content: { mimeType: 'application/json', size: 2, text: '{}' } },
  }] } }, {
    sourceSha256: 'd'.repeat(64),
    targetOrigins: ['https://service.example'],
  })
  const contract = buildNativeInteractionContract({
    webSessionEvidence: [burp, har],
    generatedAt: '2026-09-11T12:01:00.000Z',
  })
  assert.deepEqual(contract.endpoints[0].discovered_via, ['BURP_XML', 'WEB_HAR'])
  assert.equal(contract.endpoints[0].protocol_role, 'AUTH')

  const forged = structuredClone(contract)
  forged.endpoints[0].discovered_via = ['WEB_HAR']
  const { contract_id: ignored, ...material } = forged
  forged.contract_id = `interaction:${createHash('sha256').update(stableJson(material, 0)).digest('hex').slice(0, 32)}`
  assert.throws(() => assertValidNativeInteractionContract(forged), /provenance/i)
})

test('Burp HTTP-items XML preserves request-only records as status zero evidence', () => {
  const emptyResponse = document(burpItem({
    request: REQUEST,
    response: '',
    status: 0,
  }))
  const missingResponse = emptyResponse
    .replace(/\s*<status>0<\/status>/u, '')
    .replace(/\s*<responselength>0<\/responselength>/u, '')
    .replace(/\s*<response base64="true"><\/response>/u, '')

  for (const xml of [emptyResponse, missingResponse]) {
    const evidence = importBurpHttpItemsEvidence(xml, {
      sourceSha256: SOURCE_HASH,
      targetOrigins: ['https://service.example'],
    })
    assert.equal(assertValidWebSessionEvidence(evidence), evidence)
    assert.equal(evidence.entries.length, 1)
    assert.equal(evidence.entries[0].response.status, 0)
    assert.equal(evidence.entries[0].response.body.format, 'NONE')
    assert.equal(evidence.entries[0].response.body.byte_bucket, 'EMPTY')
  }
})

test('Burp XML rejects declarations, external entity vocabulary, and malformed structures', () => {
  const valid = document(burpItem({ request: REQUEST, response: RESPONSE }))
  const attacks = [
    `<!DOCTYPE items [<!ENTITY xxe SYSTEM "file:///private">]>${valid}`,
    valid.replace('<items ', '<!ENTITY leak PUBLIC "x" "y"><items '),
    valid.replace('</items>', ''),
    valid.replace('<request base64="true">', '<request base64="true"><nested>'),
    valid.replace(Buffer.from(REQUEST).toString('base64'), 'not-base64!'),
    document(burpItem({
      request: REQUEST.replace('POST /auth/login?tenant=private&mode=private-mode', 'GET /other'),
      response: RESPONSE,
    })),
  ]
  for (const attack of attacks) assert.throws(
    () => importBurpHttpItemsEvidence(attack, {
      sourceSha256: SOURCE_HASH,
      targetOrigins: ['https://service.example'],
    }),
    /Burp|XML|HTTP|base64|declaration|mismatch|malformed/i,
  )
})

test('Burp importer rejects duplicate singleton fields and unsafe HTTP header folding', () => {
  const duplicateUrl = document(burpItem({ request: REQUEST, response: RESPONSE }))
    .replace('<url>', '<url>https://service.example/duplicate</url><url>')
  const folded = document(burpItem({
    request: REQUEST.replace('Authorization:', ' continuation\r\nAuthorization:'),
    response: RESPONSE,
  }))

  for (const value of [duplicateUrl, folded]) assert.throws(
    () => importBurpHttpItemsEvidence(value, {
      sourceSha256: SOURCE_HASH,
      targetOrigins: ['https://service.example'],
    }),
    /duplicate|header|fold|Burp/i,
  )
})

test('web evidence schema admits only HAR and Burp XML source kinds', () => {
  assert.deepEqual(WEB_SESSION_SCHEMA.$defs.source.properties.kind.enum, [
    'BURP_XML', 'HAR', 'HTTP_AUTHED_CAMPAIGN', 'HTTP_RECON',
  ])
})
