import assert from 'node:assert/strict'
import { test } from 'node:test'
import { gateCandidates } from '../scripts/lib/bounty-recon-gate.mjs'
import {
  certificateFacts,
  harvestTlsSans,
  parseSubjectAltName,
} from '../scripts/lib/bounty-recon-tls.mjs'

// Shape recorded from the live www.wikipedia.org certificate on 2026-08-21.
const WIKIPEDIA_SAN = [
  'DNS:*.m.mediawiki.org', 'DNS:*.m.wikibooks.org', 'DNS:*.m.wikidata.org',
  'DNS:*.m.wikimedia.org', 'DNS:*.m.wikinews.org', 'DNS:*.wikipedia.org',
  'DNS:wikipedia.org', 'DNS:www.wikipedia.org',
].join(', ')

function approvalFor(host) {
  const scope = {
    scope_rules: {
      allow: [
        { rule_id: 'a1', host_kind: 'wildcard', host: 'wikipedia.org' },
        { rule_id: 'a2', host_kind: 'exact', host: 'wikipedia.org' },
      ],
      deny: [],
    },
  }
  const { approved } = gateCandidates({ sealedScope: scope, candidates: [{ kind: 'host', value: host }] })
  return approved[0]
}

test('parses DNS and IP SAN entries', () => {
  const { dns, ip } = parseSubjectAltName('DNS:a.example, DNS:*.b.example, IP Address:203.0.113.7')
  assert.deepEqual(dns, ['a.example', '*.b.example'])
  assert.deepEqual(ip, ['203.0.113.7'])
})

test('parses the recorded wikipedia SAN set with its wildcards intact', () => {
  const { dns } = parseSubjectAltName(WIKIPEDIA_SAN)
  assert.equal(dns.length, 8)
  assert.equal(dns.filter((d) => d.startsWith('*.')).length, 6)
})

test('an absent or empty SAN yields empty lists rather than throwing', () => {
  assert.deepEqual(parseSubjectAltName(undefined), { dns: [], ip: [] })
  assert.deepEqual(parseSubjectAltName(''), { dns: [], ip: [] })
})

test('extracts certificate facts', () => {
  const facts = certificateFacts({
    subject: { CN: 'www.wikipedia.org' },
    issuer: { O: 'Google Trust Services' },
    valid_from: 'Jul 1 00:00:00 2026 GMT',
    valid_to: 'Sep 28 21:37:55 2026 GMT',
    fingerprint256: '62:B6:B7:42',
  })
  assert.equal(facts.commonName, 'www.wikipedia.org')
  assert.equal(facts.issuer, 'Google Trust Services')
  assert.equal(facts.validTo, 'Sep 28 21:37:55 2026 GMT')
})

test('harvests SANs through an injected connect and includes the CN', () => {
  return harvestTlsSans({
    approval: approvalFor('www.wikipedia.org'),
    connectImpl: async () => ({
      subject: { CN: 'www.wikipedia.org' },
      issuer: { O: 'Google Trust Services' },
      subjectaltname: WIKIPEDIA_SAN,
      valid_to: 'Sep 28 21:37:55 2026 GMT',
    }),
  }).then((result) => {
    assert.equal(result.gap, null)
    assert.equal(result.names.length, 8, 'CN already present in SANs is not duplicated')
    assert.equal(result.certificate.commonName, 'www.wikipedia.org')
  })
})

test('adds the CN when the SAN list omits it', async () => {
  const result = await harvestTlsSans({
    approval: approvalFor('www.wikipedia.org'),
    connectImpl: async () => ({
      subject: { CN: 'extra.wikipedia.org' },
      subjectaltname: 'DNS:only.wikipedia.org',
    }),
  })
  assert.deepEqual(result.names, ['only.wikipedia.org', 'extra.wikipedia.org'])
})

test('a handshake failure returns a gap instead of throwing', async () => {
  const result = await harvestTlsSans({
    approval: approvalFor('www.wikipedia.org'),
    connectImpl: async () => { throw new Error('ECONNREFUSED') },
  })
  assert.equal(result.names.length, 0)
  assert.equal(result.gap.source, 'tls')
  assert.equal(result.gap.reason, 'tls-handshake-failed')
  assert.match(result.gap.detail, /ECONNREFUSED/)
})

test('refuses an unbranded target', async () => {
  await assert.rejects(
    () => harvestTlsSans({
      approval: { host: 'evil.example', port: 443 },
      connectImpl: async () => ({}),
    }),
    /scope-approved/,
  )
})

test('passes the approved host and port to the connector, not a caller-supplied one', async () => {
  const seen = []
  await harvestTlsSans({
    approval: approvalFor('api.wikipedia.org'),
    connectImpl: async (options) => { seen.push(options); return {} },
  })
  assert.equal(seen[0].host, 'api.wikipedia.org')
  assert.equal(seen[0].port, 443)
})
