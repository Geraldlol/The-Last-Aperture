import assert from 'node:assert/strict'
import { test } from 'node:test'
import { normalizeResponse } from '../scripts/lib/bounty-authz-normalize.mjs'
import {
  CONTROL_PROBES,
  ERROR_PROBES,
  SCAN_VERDICTS,
  calibrateProbeBaseline,
  classifyOobProbe,
  classifyProbe,
  detectErrorSignature,
  summarizeScan,
} from '../scripts/lib/bounty-scan-oracle.mjs'
import {
  applyPayload,
  classifyValueHints,
  findInsertionPoints,
  isSsrfCandidate,
} from '../scripts/lib/bounty-scan-insertion.mjs'

const JSON_TYPE = 'application/json'
const POINT = { location: 'query', pointer: 'q' }

function reply(body, status = 200) {
  return {
    status,
    error: null,
    normalized: normalizeResponse({ status, headers: { 'content-type': JSON_TYPE }, body, contentType: JSON_TYPE }),
  }
}

const baselineOf = (a, b) => calibrateProbeBaseline({ first: reply(a), second: reply(b ?? a) })

// --- insertion points ---

test('finds query, path, json, and header insertion points', () => {
  const points = findInsertionPoints({
    method: 'POST',
    url: 'https://api.acme.example/v1/orders/7?q=widget&url=https://cdn.example/a.png',
    headers: { 'x-tenant': 'acme', authorization: 'secret', accept: '*/*' },
    body: JSON.stringify({ order: { id: 7, note: 'hi' } }),
  })
  const kinds = points.map((p) => `${p.location}:${p.pointer}`)
  assert.ok(kinds.includes('query:q'))
  assert.ok(kinds.includes('query:url'))
  assert.ok(kinds.includes('json:/order/id'))
  assert.ok(kinds.includes('header:x-tenant'))
  assert.equal(kinds.some((k) => k === 'header:authorization'), false, 'credentials are not fuzzed')
  assert.equal(kinds.some((k) => k === 'header:accept'), false, 'boilerplate headers are skipped')
})

test('an opaque body yields no json insertion points', () => {
  const points = findInsertionPoints({
    method: 'POST', url: 'https://api.acme.example/x', headers: {}, body: 'binary-blob',
  })
  assert.equal(points.filter((p) => p.location === 'json').length, 0)
})

test('value hints drive narrow payload selection', () => {
  assert.ok(classifyValueHints('url', 'https://cdn.example/a').includes('url-valued'))
  assert.ok(classifyValueHints('redirect', '/local/path').includes('url-named'))
  assert.ok(classifyValueHints('id', '42').includes('numeric'))
  assert.ok(classifyValueHints('host', 'cdn.example.com').includes('hostname-valued'))
})

test('SSRF candidates are selected by name or value shape, not sprayed', () => {
  assert.equal(isSsrfCandidate({ hints: ['url-valued'] }), true)
  assert.equal(isSsrfCandidate({ hints: ['url-named'] }), true)
  assert.equal(isSsrfCandidate({ hints: ['hostname-valued'] }), true)
  assert.equal(isSsrfCandidate({ hints: ['numeric'] }), false)
})

test('payloads apply by replace or append without disturbing the rest', () => {
  const request = {
    method: 'GET', url: 'https://api.acme.example/x?a=1&b=2', headers: {}, body: null,
  }
  const point = findInsertionPoints(request).find((p) => p.pointer === 'a')
  assert.match(applyPayload(request, point, "'", { mode: 'append' }).url, /a=1%27/)
  assert.match(applyPayload(request, point, 'X').url, /a=X/)
  assert.match(applyPayload(request, point, 'X').url, /b=2/)
})

test('json payloads preserve the surrounding document', () => {
  const request = {
    method: 'POST', url: 'https://api.acme.example/x', headers: {},
    body: JSON.stringify({ a: 1, nested: { b: 'keep' } }),
  }
  const point = findInsertionPoints(request).find((p) => p.pointer === '/a')
  const mutated = applyPayload(request, point, "'", { mode: 'append' })
  assert.equal(JSON.parse(mutated.body).a, "1'")
  assert.equal(JSON.parse(mutated.body).nested.b, 'keep')
})

// --- oracle ---

test('probe sets include an inert control, which is the point', () => {
  assert.ok(ERROR_PROBES.length >= 4)
  assert.equal(CONTROL_PROBES.length >= 1, true)
  assert.ok(CONTROL_PROBES.every((probe) => /^[a-z]+$/.test(probe.payload)), 'the control must be semantically inert')
})

test('detects an error signature and ignores clean output', () => {
  assert.ok(detectErrorSignature('You have an error in your SQL syntax; check the manual'))
  assert.equal(detectErrorSignature('{"ok":true}'), null)
})

test('an error signature the untouched request lacked is an injection candidate', () => {
  const result = classifyProbe({
    baseline: { ...baselineOf('{"ok":true}'), normalizedBody: '{"ok":true}' },
    control: reply('{"ok":true}'),
    probe: reply('You have an error in your SQL syntax'),
    insertionPoint: POINT,
    probeId: 'single-quote',
  })
  assert.equal(result.verdict, 'INJECTION_ERROR_CANDIDATE')
  assert.equal(result.confidence, 'high')
  assert.match(result.rationale, /SQL error/)
})

test('an error the untouched request already produced is not attributed to the payload', () => {
  const alwaysErrors = 'Traceback (most recent call last):'
  const result = classifyProbe({
    baseline: { ...baselineOf(alwaysErrors), normalizedBody: alwaysErrors },
    control: reply(alwaysErrors),
    probe: reply(alwaysErrors),
    insertionPoint: POINT,
    probeId: 'single-quote',
  })
  assert.notEqual(result.verdict, 'INJECTION_ERROR_CANDIDATE')
})

test('a diff the inert control also produces is unproven, not a finding', () => {
  // The trap this closes: an endpoint that echoes any input change would
  // otherwise report a differential candidate for every payload sent.
  const result = classifyProbe({
    baseline: { ...baselineOf('{"echo":"orig"}'), normalizedBody: '{"echo":"orig"}' },
    control: reply('{"echo":"origzq"}'),
    probe: reply(`{"echo":"orig'"}`),
    insertionPoint: POINT,
    probeId: 'single-quote',
  })
  assert.equal(result.verdict, 'UNPROVEN_VOLATILE')
  assert.match(result.rationale, /inert control payload/)
})

test('a diff the control did not produce is a differential candidate', () => {
  const result = classifyProbe({
    baseline: { ...baselineOf('{"rows":3}'), normalizedBody: '{"rows":3}' },
    control: reply('{"rows":3}'),
    probe: reply('{"rows":0}'),
    insertionPoint: POINT,
    probeId: 'sql-comment',
  })
  assert.equal(result.verdict, 'DIFFERENTIAL_CANDIDATE')
  assert.equal(result.confidence, 'medium')
})

test('an unstable untouched request makes every diff unproven', () => {
  const result = classifyProbe({
    baseline: { ...baselineOf('{"n":1}', '{"n":2}'), normalizedBody: '{"n":1}' },
    control: reply('{"n":3}'),
    probe: reply('{"n":4}'),
    insertionPoint: POINT,
    probeId: 'single-quote',
  })
  assert.equal(result.verdict, 'UNPROVEN_VOLATILE')
})

test('no difference at all is NO_SIGNAL', () => {
  const result = classifyProbe({
    baseline: { ...baselineOf('{"ok":true}'), normalizedBody: '{"ok":true}' },
    control: reply('{"ok":true}'),
    probe: reply('{"ok":true}'),
    insertionPoint: POINT,
    probeId: 'single-quote',
  })
  assert.equal(result.verdict, 'NO_SIGNAL')
})

test('a failed probe is recorded, not silently dropped', () => {
  const result = classifyProbe({
    baseline: baselineOf('{"ok":true}'),
    control: reply('{"ok":true}'),
    probe: { status: null, error: 'ETIMEDOUT', normalized: null },
    insertionPoint: POINT,
    probeId: 'single-quote',
  })
  assert.equal(result.verdict, 'PROBE_FAILED')
})

test('a correlated out-of-band callback is a candidate', () => {
  const result = classifyOobProbe({
    interactions: [{ matched: true, nonce: 'abc', interaction: { protocol: 'dns', remoteAddress: '203.0.113.9' } }],
    nonce: 'abc',
    insertionPoint: POINT,
    probeId: 'ssrf-oob',
  })
  assert.equal(result.verdict, 'OOB_INTERACTION_CANDIDATE')
  assert.match(result.rationale, /fetched a host it was given/)
  assert.deepEqual(result.evidence, ['203.0.113.9'])
})

test('no callback is inconclusive and says so explicitly', () => {
  const result = classifyOobProbe({
    interactions: [], nonce: 'abc', insertionPoint: POINT, probeId: 'ssrf-oob',
  })
  assert.equal(result.verdict, 'NO_SIGNAL')
  assert.match(result.rationale, /inconclusive, not negative/)
})

test('a callback for a different payload is not attributed to this one', () => {
  const result = classifyOobProbe({
    interactions: [{ matched: true, nonce: 'other', interaction: { protocol: 'dns' } }],
    nonce: 'abc',
    insertionPoint: POINT,
    probeId: 'ssrf-oob',
  })
  assert.equal(result.verdict, 'NO_SIGNAL')
})

test('no scan verdict asserts a vulnerability', () => {
  for (const verdict of SCAN_VERDICTS) {
    assert.equal(/VULNERABLE|EXPLOITED|CONFIRMED|SECURE|SAFE/.test(verdict), false, verdict)
  }
})

test('the summary keeps unproven out of the candidate count', () => {
  const summary = summarizeScan([
    { verdict: 'INJECTION_ERROR_CANDIDATE' },
    { verdict: 'DIFFERENTIAL_CANDIDATE' },
    { verdict: 'OOB_INTERACTION_CANDIDATE' },
    { verdict: 'UNPROVEN_VOLATILE' },
    { verdict: 'NO_SIGNAL' },
  ])
  assert.equal(summary.candidates, 3)
  assert.equal(summary.unproven, 1)
  assert.equal(summary.total, 5)
})
