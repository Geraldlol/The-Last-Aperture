import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  classifyCandidate,
  dedupeCandidates,
  expandZoneHint,
  normalizeCandidateName,
} from '../scripts/lib/bounty-recon-candidate.mjs'

test('normalizes case and a trailing dot', () => {
  assert.equal(normalizeCandidateName('WWW.Example.COM.'), 'www.example.com')
})

test('strips a DNS: prefix as emitted by certificate SANs', () => {
  assert.equal(normalizeCandidateName('DNS:api.example.com'), 'api.example.com')
  assert.equal(normalizeCandidateName('dns:api.example.com'), 'api.example.com')
})

test('rejects anything that is not a bare name', () => {
  // A source emitting a URL is a source bug. Coercing it silently would hide that.
  for (const bad of [
    'http://example.com',
    'https://example.com',
    'example.com/path',
    'example.com:443',
    'exa mple.com',
    '  ',
    '',
    '.',
    null,
    undefined,
    42,
  ]) {
    assert.equal(normalizeCandidateName(bad), null, JSON.stringify(bad))
  }
})

test('classifies a bare name as a probeable host', () => {
  assert.deepEqual(classifyCandidate('api.example.com'), { kind: 'host', value: 'api.example.com' })
})

test('classifies a wildcard as a zone hint, never a host', () => {
  assert.deepEqual(classifyCandidate('*.m.example.com'), { kind: 'zone_hint', value: 'm.example.com' })
  assert.deepEqual(classifyCandidate('*.example.com'), { kind: 'zone_hint', value: 'example.com' })
})

test('a bare wildcard with nothing under it is rejected', () => {
  assert.equal(classifyCandidate('*'), null)
  assert.equal(classifyCandidate('*.'), null)
})

test('a nested wildcard is still only a zone hint', () => {
  assert.equal(classifyCandidate('*.*.example.com').kind, 'zone_hint')
})

test('expandZoneHint names the apex the wildcard covers', () => {
  assert.equal(expandZoneHint({ kind: 'zone_hint', value: 'm.example.com' }), 'm.example.com')
})

test('dedupes while preserving first-seen order', () => {
  const input = [
    { kind: 'host', value: 'b.example.com' },
    { kind: 'host', value: 'a.example.com' },
    { kind: 'host', value: 'b.example.com' },
    { kind: 'zone_hint', value: 'a.example.com' },
  ]
  const out = dedupeCandidates(input)
  assert.deepEqual(out.map((c) => `${c.kind}:${c.value}`), [
    'host:b.example.com',
    'host:a.example.com',
    'zone_hint:a.example.com',
  ])
})

test('a host and a zone hint with the same value are distinct entries', () => {
  const out = dedupeCandidates([
    { kind: 'host', value: 'example.com' },
    { kind: 'zone_hint', value: 'example.com' },
  ])
  assert.equal(out.length, 2)
})

test('classifies the real wikipedia SAN set into hosts and zone hints', () => {
  // Shape taken from the live cert observed 2026-08-21: 41 DNS SANs, 26 wildcards.
  const sans = [
    'DNS:*.m.mediawiki.org',
    'DNS:*.m.wikibooks.org',
    'DNS:www.wikipedia.org',
    'DNS:wikipedia.org',
    'DNS:*.wikipedia.org',
  ]
  const classified = sans.map(classifyCandidate).filter(Boolean)
  assert.equal(classified.filter((c) => c.kind === 'zone_hint').length, 3)
  assert.equal(classified.filter((c) => c.kind === 'host').length, 2)
  assert.equal(classified.every((c) => !c.value.startsWith('*')), true, 'no wildcard survives into a value')
})
