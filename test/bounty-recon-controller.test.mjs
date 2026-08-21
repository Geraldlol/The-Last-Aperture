import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { fetchCtLogNames, parseCtLogRows } from '../scripts/lib/bounty-recon-ctlog.mjs'
import { reconStatus, runRecon } from '../scripts/lib/bounty-recon-controller.mjs'

const NOW = new Date('2026-08-21T10:00:00.000Z')

function sealedScope(rateLimit = 5) {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/bounty-scope',
    engagement_id: 'ywh-acme-2026-08',
    platform: 'yeswehack',
    environment: 'production',
    data_class: 'non_phi',
    program: {
      program_handle: 'acme',
      policy_url: 'https://yeswehack.com/programs/acme',
      policy_snapshot_sha256: 'a'.repeat(64),
    },
    authorization: {
      mode: 'PROGRAM_POLICY_SEALED',
      authorization_id: 'auth-1',
      statement: 'declared',
      operator_id: 'op',
      authorized_by: 'acme',
      authorization_reference: 'https://yeswehack.com/programs/acme',
      attested_at: '2026-08-21T00:00:00.000Z',
      independently_verified: false,
      permissions: {
        active_testing: true, production: true, third_party: false, phi: false,
        mutation: false, automation_allowed: true, intensity: 'normal',
        desync_probes: false, rate_limit_rps: rateLimit,
      },
    },
    validity: { not_before: '2026-08-21T00:00:00.000Z', not_after: '2026-11-21T00:00:00.000Z' },
    scope_rules: {
      allow: [
        { rule_id: 'a1', host_kind: 'wildcard', host: 'acme.example' },
        { rule_id: 'a2', host_kind: 'exact', host: 'acme.example' },
      ],
      deny: [{ rule_id: 'd1', host_kind: 'exact', host: 'legacy.acme.example' }],
    },
    stop_conditions: { max_findings: 100, operator_stop: false },
  }
}

async function bundle(rateLimit) {
  const dir = await mkdtemp(join(tmpdir(), 'bounty-recon-'))
  await writeFile(join(dir, 'scope.json'), JSON.stringify(sealedScope(rateLimit), null, 2), 'utf8')
  return dir
}

const okHtml = () => new Response('<html><title>Acme</title></html>', {
  status: 200, headers: { 'content-type': 'text/html', server: 'nginx' },
})

// crt.sh unavailable, which is its common state.
const ctDown = async (url) => (String(url).includes('crt.sh')
  ? new Response('<html>502</html>', { status: 502 })
  : okHtml())

test('parses crt.sh rows with multi-name fields', () => {
  const names = parseCtLogRows([
    { name_value: 'a.acme.example\n*.acme.example', common_name: 'a.acme.example' },
    { name_value: 'b.acme.example' },
    { nonsense: true },
  ])
  assert.ok(names.includes('a.acme.example'))
  assert.ok(names.includes('*.acme.example'))
  assert.ok(names.includes('b.acme.example'))
})

test('crt.sh returns a gap after exhausting attempts rather than throwing', async () => {
  let calls = 0
  const result = await fetchCtLogNames({
    apex: 'acme.example',
    attempts: 3,
    fetchImpl: async () => { calls += 1; return new Response('502', { status: 502 }) },
  })
  assert.equal(calls, 3)
  assert.equal(result.names.length, 0)
  assert.equal(result.gap.source, 'crt.sh')
  assert.equal(result.gap.reason, 'source-unavailable')
  assert.match(result.gap.detail, /HTTP 502/)
})

test('crt.sh malformed json becomes a gap', async () => {
  const result = await fetchCtLogNames({
    apex: 'acme.example',
    attempts: 1,
    fetchImpl: async () => new Response('not json', { status: 200 }),
  })
  assert.equal(result.gap.reason, 'source-unavailable')
})

test('runs recon, discovers SANs, probes them, and persists the inventory', async () => {
  const dir = await bundle()
  try {
    const summary = await runRecon({
      bundlePath: dir,
      seeds: ['acme.example'],
      sources: ['tls'],
      now: NOW,
      fetchImpl: async () => okHtml(),
      connectImpl: async () => ({
        subject: { CN: 'acme.example' },
        subjectaltname: 'DNS:acme.example, DNS:api.acme.example, DNS:*.m.acme.example',
      }),
      sleep: async () => {},
      clock: () => 0,
    })
    assert.equal(summary.status, 'OBSERVED')
    assert.equal(summary.zoneHints, 1, 'the wildcard became a zone hint')
    const inventory = JSON.parse(await readFile(join(dir, 'surface-inventory.json'), 'utf8'))
    const hosts = inventory.hosts.map((h) => h.host).sort()
    assert.deepEqual(hosts, ['acme.example', 'api.acme.example'])
    assert.equal(inventory.hosts.find((h) => h.host === 'api.acme.example').probe.status, 200)
    assert.equal(inventory.zone_hints[0].zone, 'm.acme.example')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('the seed is probed even when absent from its own certificate SANs', async () => {
  // Regression: www.wikipedia.org does not appear in its own SAN list, so relying
  // on discovery to surface the seed left it with no liveness data at all.
  const dir = await bundle()
  try {
    const probed = []
    await runRecon({
      bundlePath: dir,
      seeds: ['www.acme.example'],
      sources: ['tls'],
      now: NOW,
      fetchImpl: async (url) => { probed.push(String(url)); return okHtml() },
      connectImpl: async () => ({ subjectaltname: 'DNS:*.acme.example, DNS:other.acme.example' }),
      sleep: async () => {},
      clock: () => 0,
    })
    assert.ok(probed.includes('https://www.acme.example/'), 'the seed was probed')
    assert.ok(probed.includes('https://other.acme.example/'), 'discovery was probed too')
    const inventory = JSON.parse(await readFile(join(dir, 'surface-inventory.json'), 'utf8'))
    const seed = inventory.hosts.find((h) => h.host === 'www.acme.example')
    assert.equal(seed.probe.status, 200)
    assert.deepEqual(seed.sources, ['seed', 'probe'], 'provenance keeps both')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('a host discovered twice is probed only once', async () => {
  const dir = await bundle()
  try {
    const probed = []
    await runRecon({
      bundlePath: dir,
      seeds: ['api.acme.example'],
      sources: ['tls'],
      now: NOW,
      fetchImpl: async (url) => { probed.push(String(url)); return okHtml() },
      // the seed also appears in its own SANs
      connectImpl: async () => ({ subjectaltname: 'DNS:api.acme.example' }),
      sleep: async () => {},
      clock: () => 0,
    })
    const hits = probed.filter((u) => u === 'https://api.acme.example/')
    assert.equal(hits.length, 1, 'no duplicate request for the same host:port')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('an out-of-scope discovery is refused and never probed', async () => {
  const dir = await bundle()
  try {
    const probed = []
    await runRecon({
      bundlePath: dir,
      seeds: ['acme.example'],
      sources: ['tls'],
      now: NOW,
      fetchImpl: async (url) => { probed.push(String(url)); return okHtml() },
      connectImpl: async () => ({
        subjectaltname: 'DNS:api.acme.example, DNS:unrelated.example, DNS:legacy.acme.example',
      }),
      sleep: async () => {},
      clock: () => 0,
    })
    assert.ok(probed.includes('https://api.acme.example/'))
    assert.equal(probed.some((u) => u.includes('unrelated.example')), false, 'out of scope never fetched')
    assert.equal(probed.some((u) => u.includes('legacy.acme.example')), false, 'denied host never fetched')
    const inventory = JSON.parse(await readFile(join(dir, 'surface-inventory.json'), 'utf8'))
    const reasons = inventory.refused.map((r) => `${r.host}:${r.reason}`)
    assert.ok(reasons.includes('unrelated.example:candidate-unlisted'))
    assert.ok(reasons.includes('legacy.acme.example:explicit-deny-rule'))
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('an out-of-scope seed is refused before any socket opens', async () => {
  const dir = await bundle()
  try {
    let connects = 0
    const summary = await runRecon({
      bundlePath: dir,
      seeds: ['evil.example'],
      sources: ['tls'],
      now: NOW,
      fetchImpl: async () => okHtml(),
      connectImpl: async () => { connects += 1; return {} },
      sleep: async () => {},
      clock: () => 0,
    })
    assert.equal(connects, 0, 'the TLS source was never reached')
    assert.equal(summary.hosts, 0)
    assert.equal(summary.refused, 1)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('a dead crt.sh yields PARTIAL with the gap recorded, not a crash', async () => {
  const dir = await bundle()
  try {
    const summary = await runRecon({
      bundlePath: dir,
      seeds: ['acme.example'],
      sources: ['tls', 'ctlog'],
      now: NOW,
      fetchImpl: ctDown,
      connectImpl: async () => ({ subjectaltname: 'DNS:api.acme.example' }),
      sleep: async () => {},
      clock: () => 0,
    })
    assert.equal(summary.status, 'PARTIAL')
    assert.equal(summary.gaps, 1)
    assert.ok(summary.hosts > 0, 'other sources still contributed')
    const status = await reconStatus({ bundlePath: dir })
    assert.equal(status.status, 'PARTIAL')
    assert.equal(status.gapDetail[0].source, 'crt.sh')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('the limiter is built from the sealed rate limit, not a caller flag', async () => {
  const dir = await bundle(2)
  try {
    let millis = 0
    const summary = await runRecon({
      bundlePath: dir,
      seeds: ['acme.example'],
      sources: ['tls'],
      now: NOW,
      fetchImpl: async () => okHtml(),
      connectImpl: async () => ({
        subjectaltname: 'DNS:a.acme.example, DNS:b.acme.example, DNS:c.acme.example',
      }),
      sleep: async (ms) => { millis += ms },
      clock: () => millis,
    })
    assert.equal(summary.rateLimitRps, 2)
    // 4 probes (the seed plus three discovered) at 2/sec: the first is free,
    // then three 500ms waits.
    assert.equal(millis, 1500)
    assert.equal(summary.paced.issued, 4)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('refuses to run with no seeds', async () => {
  const dir = await bundle()
  try {
    await assert.rejects(() => runRecon({ bundlePath: dir, seeds: [], now: NOW }), /--seed/)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('a TLS handshake failure is a gap, and the sweep continues', async () => {
  const dir = await bundle()
  try {
    const summary = await runRecon({
      bundlePath: dir,
      seeds: ['acme.example'],
      sources: ['tls'],
      now: NOW,
      fetchImpl: async () => okHtml(),
      connectImpl: async () => { throw new Error('ECONNREFUSED') },
      sleep: async () => {},
      clock: () => 0,
    })
    assert.equal(summary.status, 'PARTIAL')
    assert.equal(summary.gaps, 1)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})
