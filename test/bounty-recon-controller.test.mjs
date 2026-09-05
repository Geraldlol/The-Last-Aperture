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
      required_user_agent: 'BugBounty-acme',
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
    assert.deepEqual(
      inventory.zone_hints[0].sources,
      ['tls'],
      'a SAN-discovered zone hint is attributed to the handshake that produced it',
    )
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

// A sealed wildcard is now a valid starting point on its own, so the refusal is
// narrower than it was: recon still declines when there is nothing at all to
// start from. Stub impls keep this offline -- the guard must fire before any
// source runs, and a real fetch here would prove the opposite.
test('refuses to run with neither a seed nor a zone it can enumerate', async () => {
  const dir = await bundle()
  const stub = { fetchImpl: async () => { throw new Error('no request may be made') }, connectImpl: async () => { throw new Error('no socket may open') } }
  try {
    // tls cannot expand a zone, so with no seed there is no entry point
    await assert.rejects(
      () => runRecon({ bundlePath: dir, seeds: [], sources: ['tls'], now: NOW, ...stub }),
      /--seed/,
    )
    // and with no source at all, likewise
    await assert.rejects(
      () => runRecon({ bundlePath: dir, seeds: [], sources: [], now: NOW, ...stub }),
      /--seed/,
    )
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

// --- a sealed wildcard is a grant to enumerate that zone ---

// A program that grants *.zone but not the apex leaves the apex unprobeable, and
// the apex is the only natural seed for expanding the zone. Asking crt.sh about a
// zone sends nothing to the target, so the seed gate -- which exists to stop
// packets reaching out-of-scope hosts -- must not also stop enumeration of a zone
// we plainly hold. Discovered names are still gated before anything is probed.
test('ctlog enumerates every sealed wildcard zone, apex seed or not', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bounty-recon-zone-'))
  try {
    const scope = sealedScope()
    scope.scope_rules = {
      allow: [
        { rule_id: 'a1', host_kind: 'wildcard', host: 'service.example.test' },
        { rule_id: 'a2', host_kind: 'wildcard', host: 'secondary.example.test' },
        { rule_id: 'a3', host_kind: 'exact', host: 'api.acme.example' },
      ],
      deny: [],
    }
    await writeFile(join(dir, 'scope.json'), JSON.stringify(scope), 'utf8')

    const queried = []
    const probed = []
    await runRecon({
      bundlePath: dir,
      // The apex is deliberately NOT supplied and is not in scope on its own.
      seeds: [],
      sources: ['ctlog'],
      now: NOW,
      fetchImpl: async (url) => {
        const text = String(url)
        if (text.includes('crt.sh')) {
          queried.push(text)
          return new Response(JSON.stringify([{ name_value: 'gatekeeper.service.example.test' }]), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          })
        }
        probed.push(text)
        return new Response('<html><title>x</title></html>', {
          status: 200,
          headers: { 'content-type': 'text/html' },
        })
      },
      sleep: async () => {},
      clock: () => 0,
    })

    assert.ok(
      queried.some((u) => u.includes(encodeURIComponent('%.service.example.test'))),
      'the sealed wildcard zone must be enumerated',
    )
    assert.ok(
      queried.some((u) => u.includes(encodeURIComponent('%.secondary.example.test'))),
      'every sealed wildcard zone, not just the first',
    )
    assert.equal(
      queried.some((u) => u.includes(encodeURIComponent('%.api.acme.example'))),
      false,
      'an exact-host rule is not a zone grant and must not be enumerated',
    )
    assert.ok(
      probed.includes('https://gatekeeper.service.example.test/'),
      'a discovered in-zone host is probed as normal',
    )
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

// The perimeter must not widen: enumeration finds names, the gate still decides.
test('a name outside the perimeter is never probed even when ctlog returns it', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bounty-recon-zone-'))
  try {
    const scope = sealedScope()
    scope.scope_rules = {
      allow: [{ rule_id: 'a1', host_kind: 'wildcard', host: 'service.example.test' }],
      deny: [{ rule_id: 'd1', host_kind: 'exact', host: 'secret.service.example.test' }],
    }
    await writeFile(join(dir, 'scope.json'), JSON.stringify(scope), 'utf8')

    const probed = []
    await runRecon({
      bundlePath: dir,
      seeds: [],
      sources: ['ctlog'],
      now: NOW,
      fetchImpl: async (url) => {
        const text = String(url)
        if (text.includes('crt.sh')) {
          return new Response(
            JSON.stringify([
              { name_value: 'ok.service.example.test' },
              { name_value: 'secret.service.example.test' },
              { name_value: 'elsewhere.example.com' },
            ]),
            { status: 200, headers: { 'content-type': 'application/json' } },
          )
        }
        probed.push(text)
        return new Response('', { status: 200, headers: { 'content-type': 'text/plain' } })
      },
      sleep: async () => {},
      clock: () => 0,
    })

    assert.ok(probed.includes('https://ok.service.example.test/'), 'in-zone name is probed')
    assert.equal(
      probed.some((u) => u.includes('secret.service.example.test')),
      false,
      'an explicitly denied name is never probed',
    )
    assert.equal(
      probed.some((u) => u.includes('elsewhere.example.com')),
      false,
      'a name outside the perimeter is never probed',
    )
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

// A zone hint records where the name came from, because the inventory is
// evidence: a certificate-log observation attributed to a TLS handshake claims a
// socket that a ctlog-only sweep never opens.
test('a zone hint discovered from ctlog is attributed to ctlog, not to tls', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bounty-recon-prov-'))
  try {
    const scope = sealedScope()
    scope.scope_rules = {
      allow: [{ rule_id: 'a1', host_kind: 'wildcard', host: 'service.example.test' }],
      deny: [],
    }
    await writeFile(join(dir, 'scope.json'), JSON.stringify(scope), 'utf8')

    await runRecon({
      bundlePath: dir,
      // No seed and no tls source: nothing in this run opens a socket to a target.
      seeds: [],
      sources: ['ctlog'],
      now: NOW,
      fetchImpl: async (url) => {
        if (String(url).includes('crt.sh')) {
          return new Response(
            JSON.stringify([{ name_value: '*.internal.service.example.test' }]),
            { status: 200, headers: { 'content-type': 'application/json' } },
          )
        }
        return new Response('<html><title>x</title></html>', {
          status: 200,
          headers: { 'content-type': 'text/html' },
        })
      },
      sleep: async () => {},
      clock: () => 0,
    })

    const inventory = JSON.parse(
      await readFile(join(dir, 'surface-inventory.json'), 'utf8'),
    )
    const hint = inventory.zone_hints.find(
      (entry) => entry.zone === 'internal.service.example.test',
    )
    assert.ok(hint, 'the wildcard name became a zone hint')
    assert.deepEqual(
      hint.sources,
      ['ctlog'],
      'a ctlog-discovered zone hint must not claim a TLS handshake that never happened',
    )
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

// A sweep whose scope blocked every probe is the PARTIAL case by definition:
// nothing was observed. Recording only refusals leaves the summary reading
// `OBSERVED gaps=0`, which is indistinguishable from a surface that is genuinely
// empty.
test('a scope sealing no user-agent marker yields PARTIAL with the gap recorded', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bounty-recon-nomarker-'))
  try {
    const scope = sealedScope()
    // A bundle sealed before the marker was mandated.
    delete scope.program.required_user_agent
    await writeFile(join(dir, 'scope.json'), JSON.stringify(scope), 'utf8')

    const probed = []
    const summary = await runRecon({
      bundlePath: dir,
      seeds: ['acme.example'],
      sources: ['tls'],
      now: NOW,
      fetchImpl: async (url) => {
        probed.push(String(url))
        return new Response('', { status: 200 })
      },
      connectImpl: async () => ({
        subjectaltname: 'DNS:acme.example',
      }),
      sleep: async () => {},
      clock: () => 0,
    })

    assert.deepEqual(probed, [], 'no socket may open without the mandated marker')
    assert.equal(
      summary.status,
      'PARTIAL',
      'a sweep that probed nothing must not report OBSERVED',
    )
    const inventory = JSON.parse(
      await readFile(join(dir, 'surface-inventory.json'), 'utf8'),
    )
    assert.ok(
      inventory.gaps.some(({ reason }) => reason.includes('user-agent')),
      'the missing marker is recorded as the gap that stopped the sweep',
    )
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})
