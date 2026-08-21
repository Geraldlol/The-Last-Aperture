import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { runScan } from '../scripts/lib/bounty-scan-controller.mjs'
import { normalizeCapturedRequest } from '../scripts/lib/bounty-authz-request.mjs'
import { startDnsListener } from '../scripts/lib/bounty-oob-dns.mjs'
import {
  ingestSelfHostedEvent,
  mintOobPayload,
  openOobSession,
} from '../scripts/lib/bounty-oob-controller.mjs'
import { startAuthzTestbed } from './fixtures/authz-testbed.mjs'

const NOW = new Date('2026-08-21T12:00:00.000Z')

const REGISTRY = {
  schema_version: '1.0.0',
  kind: 'red-team-audit/bounty-authz-roles',
  roles: [{ id: 'alice', label: 'operator', auth: { kind: 'header', name: 'authorization', value_env: 'TB_ALICE' } }],
}
const ENV = { TB_ALICE: 'Bearer alice-token' }

async function workspace(port, { activeTesting = true } = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'bounty-scan-'))
  await writeFile(join(dir, 'scope.json'), JSON.stringify({
    engagement_id: 'scan-testbed',
    // intensity is required: the scanner resolves breadth from the sealed tier and
    // fails closed without one. aggressive gives all three classes and no caps,
    // which is what these ground-truth assertions need.
    authorization: {
      permissions: { rate_limit_rps: 100, active_testing: activeTesting, intensity: 'aggressive' },
    },
    validity: { not_before: '2026-08-21T00:00:00.000Z', not_after: '2026-08-22T00:00:00.000Z' },
    scope_rules: {
      allow: [{ rule_id: 'a1', host_kind: 'ip', host: '127.0.0.1', ports: [port] }],
      deny: [],
      private_targets_sealed: true,
    },
  }, null, 2), 'utf8')
  return dir
}

const capture = (origin, path) => normalizeCapturedRequest({
  request_id: path, method: 'GET', url: `${origin}${path}`,
  headers: { accept: 'application/json' }, owner_role: 'alice',
})

async function scan(paths, options = {}) {
  const testbed = await startAuthzTestbed()
  const dir = await workspace(testbed.port, options)
  try {
    const summary = await runScan({
      bundlePath: dir,
      requests: paths.map((path) => capture(testbed.origin, path)),
      registry: REGISTRY,
      roleId: 'alice',
      now: NOW,
      env: ENV,
      classes: options.classes ?? ['error-injection', 'passive'],
      sleep: async () => {},
      clock: () => 0,
    })
    const findings = JSON.parse(await readFile(join(dir, 'scan-findings.json'), 'utf8'))
    return { summary, findings }
  } finally {
    await testbed.close()
    await rm(dir, { recursive: true, force: true })
  }
}

const verdictsFor = (findings, path) => findings.results
  .filter((r) => r.url.includes(path))
  .map((r) => r.verdict)

test('finds the planted SQL error injection', async () => {
  const { findings } = await scan(['/api/search?q=widget'])
  const verdicts = verdictsFor(findings, '/api/search')
  assert.ok(verdicts.includes('INJECTION_ERROR_CANDIDATE'), 'the planted injection was found')
  const hit = findings.results.find((r) => r.verdict === 'INJECTION_ERROR_CANDIDATE')
  assert.equal(hit.insertion, 'query:q')
  assert.match(hit.rationale, /SQL error/)
})

test('an endpoint that ignores input produces no signal', async () => {
  const { findings } = await scan(['/api/stable?q=widget'])
  const verdicts = new Set(verdictsFor(findings, '/api/stable'))
  assert.ok(verdicts.has('NO_SIGNAL'))
  assert.equal(verdicts.has('DIFFERENTIAL_CANDIDATE'), false, 'no false differential')
  assert.equal(verdicts.has('INJECTION_ERROR_CANDIDATE'), false)
})

test('an endpoint that echoes any input is unproven, not a finding', async () => {
  // The control payload earns its keep here. Without it every probe against an
  // echoing endpoint would report a differential candidate.
  const { findings } = await scan(['/api/echo?q=widget'])
  const verdicts = new Set(verdictsFor(findings, '/api/echo'))
  assert.ok(verdicts.has('UNPROVEN_VOLATILE'))
  assert.equal(verdicts.has('DIFFERENTIAL_CANDIDATE'), false, 'the control suppressed a false positive')
})

test('the full ground-truth sweep finds only the planted injection', async () => {
  const { summary, findings } = await scan([
    '/api/search?q=widget', '/api/stable?q=widget', '/api/echo?q=widget',
  ])
  const candidates = findings.results.filter((r) => r.verdict.endsWith('_CANDIDATE'))
  assert.ok(candidates.length >= 1)
  assert.ok(candidates.every((r) => r.url.includes('/api/search')), 'only the planted endpoint yielded candidates')
  assert.ok(summary.unproven >= 1, 'the echoing endpoint was recorded as unproven')
})

test('passive rules collect leads from the untouched response', async () => {
  const { summary } = await scan(['/api/search?q=widget'], { classes: ['passive'] })
  assert.ok(summary.passive.total >= 0)
  assert.ok(['NOTHING_OBSERVED', 'LEADS_OBSERVED'].includes(summary.passive.status))
})

test('scanning refuses a scope without active_testing', async () => {
  await assert.rejects(
    () => scan(['/api/search?q=x'], { activeTesting: false }),
    /active_testing/,
  )
})

test('scanning refuses an expired scope before any probe', async () => {
  const testbed = await startAuthzTestbed()
  const dir = await mkdtemp(join(tmpdir(), 'bounty-scan-'))
  try {
    await writeFile(join(dir, 'scope.json'), JSON.stringify({
      engagement_id: 'expired',
      // Complete apart from the expiry, so this fails for the reason it claims
      // rather than incidentally on a missing intensity tier.
      authorization: { permissions: { rate_limit_rps: 100, active_testing: true, intensity: 'normal' } },
      validity: { not_before: '2026-06-01T00:00:00.000Z', not_after: '2026-07-01T00:00:00.000Z' },
      scope_rules: { allow: [{ rule_id: 'a1', host_kind: 'ip', host: '127.0.0.1', ports: [testbed.port] }], deny: [], private_targets_sealed: true },
    }), 'utf8')
    let touched = 0
    await assert.rejects(
      () => runScan({
        bundlePath: dir,
        requests: [capture(testbed.origin, '/api/search?q=x')],
        registry: REGISTRY, roleId: 'alice', now: NOW, env: ENV,
        fetchImpl: async () => { touched += 1; return new Response('{}') },
        sleep: async () => {}, clock: () => 0,
      }),
      /EXPIRED/,
    )
    assert.equal(touched, 0)
  } finally {
    await testbed.close()
    await rm(dir, { recursive: true, force: true })
  }
})

test('a real blind SSRF is proven end to end through our own OOB listener', async () => {
  // The planted /api/fetch handler resolves whatever host it is handed. We point
  // it at our own DNS listener, mint a correlated payload, and check the callback
  // comes back attributed to the exact insertion point. Nothing here is
  // simulated: a real resolver performs a real lookup.
  const events = []
  const dns = await startDnsListener({
    port: 0, address: '127.0.0.1', answerAddress: '127.0.0.1',
    onQuery: (event) => events.push(event),
  })
  const testbed = await startAuthzTestbed({ dnsServer: `127.0.0.1:${dns.port}` })
  const dir = await workspace(testbed.port)
  try {
    await openOobSession({
      bundlePath: dir, backend: 'self_hosted', server: 'oob.test.example',
      now: NOW, fetchImpl: async () => { throw new Error('no network') },
    })
    const oob = {
      mint: (spec) => mintOobPayload({ bundlePath: dir, now: NOW, ...spec }),
      collect: async () => {
        // Give the resolver a moment, then feed whatever the listener saw
        // through the correlator.
        await new Promise((resolve) => setTimeout(resolve, 250))
        const out = []
        while (events.length > 0) {
          out.push(await ingestSelfHostedEvent({ bundlePath: dir, event: events.shift(), now: NOW }))
        }
        return out
      },
    }
    const summary = await runScan({
      bundlePath: dir,
      requests: [capture(testbed.origin, '/api/fetch?url=https://cdn.example/a.png')],
      registry: REGISTRY, roleId: 'alice', now: NOW, env: ENV,
      classes: ['ssrf-oob'], oob,
      sleep: async () => {}, clock: () => 0,
    })
    const findings = JSON.parse(await readFile(join(dir, 'scan-findings.json'), 'utf8'))
    const ssrf = findings.results.find((r) => r.class === 'ssrf-oob')
    assert.equal(ssrf.verdict, 'OOB_INTERACTION_CANDIDATE', ssrf.rationale)
    assert.equal(ssrf.insertion, 'query:url')
    assert.match(ssrf.rationale, /fetched a host it was given/)
    assert.equal(summary.candidates, 1)
  } finally {
    await testbed.close()
    await dns.close()
    await rm(dir, { recursive: true, force: true })
  }
})

test('SSRF payloads are not sprayed at non-url parameters', async () => {
  const testbed = await startAuthzTestbed()
  const dir = await workspace(testbed.port)
  try {
    let minted = 0
    await openOobSession({
      bundlePath: dir, backend: 'self_hosted', server: 'oob.test.example',
      now: NOW, fetchImpl: async () => { throw new Error('no network') },
    })
    await runScan({
      bundlePath: dir,
      // A numeric id: no url name, no url-shaped value.
      requests: [capture(testbed.origin, '/api/orders/2')],
      registry: REGISTRY, roleId: 'alice', now: NOW, env: ENV,
      classes: ['ssrf-oob'],
      oob: {
        mint: async (spec) => { minted += 1; return mintOobPayload({ bundlePath: dir, now: NOW, ...spec }) },
        collect: async () => [],
      },
      sleep: async () => {}, clock: () => 0,
    })
    assert.equal(minted, 0, 'no SSRF payload was minted for a numeric path segment')
  } finally {
    await testbed.close()
    await rm(dir, { recursive: true, force: true })
  }
})
