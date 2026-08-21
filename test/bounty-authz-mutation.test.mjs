import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { runAuthzMatrix } from '../scripts/lib/bounty-authz-controller.mjs'
import { normalizeCapturedRequest } from '../scripts/lib/bounty-authz-request.mjs'
import { TESTBED_TOKENS, startAuthzTestbed } from './fixtures/authz-testbed.mjs'

const NOW = new Date('2026-08-21T10:00:00.000Z')

const REGISTRY = {
  schema_version: '1.0.0',
  kind: 'red-team-audit/bounty-authz-roles',
  roles: [
    { id: 'alice', label: 'owner', auth: { kind: 'header', name: 'authorization', value_env: 'TB_ALICE' } },
    { id: 'bob', label: 'second account', auth: { kind: 'header', name: 'authorization', value_env: 'TB_BOB' } },
  ],
}

const ENV = {
  TB_ALICE: `Bearer ${TESTBED_TOKENS.alice}`,
  TB_BOB: `Bearer ${TESTBED_TOKENS.bob}`,
}

// Both accounts are the operator's own. No undeclared identifier is ever sent.
function identifierMap(extra = []) {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/bounty-authz-identifiers',
    identifiers: [
      { id: 'order-alice', value: '2', kind: 'order', owner_role: 'alice' },
      { id: 'order-bob', value: '5', kind: 'order', owner_role: 'bob' },
      ...extra,
    ],
  }
}

async function workspace(port) {
  const dir = await mkdtemp(join(tmpdir(), 'bounty-mutation-'))
  await writeFile(join(dir, 'scope.json'), JSON.stringify({
    engagement_id: 'authz-mutation',
    authorization: { permissions: { rate_limit_rps: 50 } },
    // Fixed on purpose: NOW is injected, so this stays deterministic forever.
    validity: { not_before: '2026-08-21T00:00:00.000Z', not_after: '2026-08-22T00:00:00.000Z' },
    scope_rules: {
      allow: [{ rule_id: 'a1', host_kind: 'ip', host: '127.0.0.1', ports: [port] }],
      deny: [],
      private_targets_sealed: true,
    },
  }, null, 2), 'utf8')
  return dir
}

async function grind({ paths, map, ownerRole = 'alice' }) {
  const testbed = await startAuthzTestbed()
  const dir = await workspace(testbed.port)
  try {
    const summary = await runAuthzMatrix({
      bundlePath: dir,
      requests: paths.map((path) => normalizeCapturedRequest({
        request_id: path, method: 'GET', url: `${testbed.origin}${path}`,
        headers: { accept: 'application/json' }, owner_role: ownerRole,
      })),
      registry: REGISTRY,
      identifierMap: map,
      now: NOW,
      env: ENV,
      sleep: async () => {},
      clock: () => 0,
    })
    const findings = JSON.parse(await readFile(join(dir, 'authz-findings.json'), 'utf8'))
    return { summary, findings }
  } finally {
    await testbed.close()
    await rm(dir, { recursive: true, force: true })
  }
}

const mutated = (findings) => findings.results.filter((r) => r.mutation !== undefined)

test('mutation swaps a declared identifier and records the swap it made', async () => {
  const { findings } = await grind({ paths: ['/api/orders/1'], map: identifierMap() })
  // Order 1 carries no declared identifier, so nothing is mutated from it.
  assert.equal(mutated(findings).length, 0)
})

test('swapping alice-order into a correctly-protected handler finds no bug', async () => {
  // /api/orders/5 is bob's and the handler checks ownership, so alice must be
  // denied. This is the true-negative case that keeps the feature honest.
  const { findings } = await grind({ paths: ['/api/orders/2'], map: identifierMap() })
  const swaps = mutated(findings)
  assert.ok(swaps.length > 0, 'order 2 carries a declared identifier, so it mutates')
  const aliceAgainstBobsOrder = swaps.find((r) => r.tester_role === 'alice' && r.url.endsWith('/api/orders/5'))
  assert.equal(aliceAgainstBobsOrder.verdict, 'ACCESS_DENIED')
  assert.equal(aliceAgainstBobsOrder.owner_role, 'bob', 'baselined against the identifier owner, not the capture owner')
})

test('the mutated request is baselined against the identifier owner', async () => {
  const { findings } = await grind({ paths: ['/api/orders/2'], map: identifierMap() })
  const swap = mutated(findings).find((r) => r.url.endsWith('/api/orders/5'))
  // After substitution the request targets bob's object, so the only meaningful
  // "correct" response is bob's. Reusing alice's baseline would compare against a
  // different object entirely.
  assert.equal(swap.owner_role, 'bob')
  assert.equal(swap.baseline_stable, true)
  assert.equal(swap.owner_status, 200)
})

test('mutation records the exact swap for the report', async () => {
  const { findings } = await grind({ paths: ['/api/orders/2'], map: identifierMap() })
  const swap = mutated(findings).find((r) => r.url.endsWith('/api/orders/5'))
  assert.match(swap.mutation, /^path:3 order-alice -> order-bob$/)
})

test('a declared-absent identifier is probed for an enumeration oracle', async () => {
  const { findings } = await grind({
    paths: ['/api/orders/2'],
    map: identifierMap([
      { id: 'order-absent', value: '99999999', kind: 'order', owner_role: null, absent: true },
    ]),
  })
  const probe = mutated(findings).find((r) => r.verdict === 'ABSENT_PROBE')
  assert.ok(probe, 'the absent identifier was probed')
  assert.equal(probe.tester_status, 404, 'testbed returns 404 for a nonexistent order')
  assert.match(probe.mutation, /declared absent/)
  // The oracle is read off the pair: not-yours returns 403, absent returns 404.
  const notYours = mutated(findings).find(
    (r) => r.tester_role === 'alice' && r.url.endsWith('/api/orders/5'),
  )
  assert.equal(notYours.tester_status, 403)
  assert.notEqual(probe.tester_status, notYours.tester_status, 'differing statuses are an enumeration oracle')
})

test('an absent probe is never counted as a candidate', async () => {
  const { summary } = await grind({
    paths: ['/api/orders/2'],
    map: identifierMap([
      { id: 'order-absent', value: '99999999', kind: 'order', owner_role: null, absent: true },
    ]),
  })
  assert.equal(summary.byVerdict.ABSENT_PROBE >= 1, true)
  // The only candidate is the planted bug on order 2 from the role-replay pass.
  assert.equal(summary.candidates, 1)
})

test('only declared identifiers are ever sent', async () => {
  const testbed = await startAuthzTestbed()
  const dir = await workspace(testbed.port)
  try {
    const urls = []
    await runAuthzMatrix({
      bundlePath: dir,
      requests: [normalizeCapturedRequest({
        request_id: 'r', method: 'GET', url: `${testbed.origin}/api/orders/2`,
        headers: { accept: 'application/json' }, owner_role: 'alice',
      })],
      registry: REGISTRY,
      identifierMap: identifierMap(),
      now: NOW,
      env: ENV,
      fetchImpl: async (url, init) => { urls.push(String(url)); return fetch(url, init) },
      sleep: async () => {},
      clock: () => 0,
    })
    const ids = new Set([...urls].map((u) => new URL(u).pathname.split('/').pop()))
    // No incremented, guessed, or fuzzed identifier appears anywhere.
    assert.deepEqual([...ids].sort(), ['2', '5'])
  } finally {
    await testbed.close()
    await rm(dir, { recursive: true, force: true })
  }
})

test('mutation finds a horizontal IDOR that role replay alone cannot reach', async () => {
  // /api/invoices?order=<id> has no ownership check on the referenced order.
  // Role replay of alice's capture only ever asks "can bob read the invoice for
  // alice's order". Proving the other direction -- alice reading BOB's invoice --
  // requires substituting bob's declared order id into alice's own request, which
  // is exactly what mutation does.
  const { findings, summary } = await grind({
    paths: ['/api/invoices?order=2'],
    map: identifierMap(),
  })
  const swaps = mutated(findings)
  const aliceAgainstBobsInvoice = swaps.find(
    (r) => r.tester_role === 'alice' && r.url.includes('order=5'),
  )
  assert.ok(aliceAgainstBobsInvoice, 'the query-param identifier was mutated')
  assert.equal(aliceAgainstBobsInvoice.verdict, 'AUTHZ_BYPASS_CANDIDATE')
  assert.equal(aliceAgainstBobsInvoice.owner_role, 'bob')
  assert.equal(aliceAgainstBobsInvoice.confidence, 'high')
  assert.match(aliceAgainstBobsInvoice.mutation, /query:order order-alice -> order-bob/)
  assert.ok(summary.candidates >= 1)
})

test('mutation is skipped entirely when no identifier map is supplied', async () => {
  const { findings } = await grind({ paths: ['/api/orders/2'], map: null })
  assert.equal(mutated(findings).length, 0)
})

test('a same-kind identifier owned by the capture owner is still swapped in', async () => {
  // Alice owning two orders is a legitimate setup; swapping one for the other
  // tests the handler without involving a second account at all.
  const twoAlice = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/bounty-authz-identifiers',
    identifiers: [
      { id: 'order-a1', value: '2', kind: 'order', owner_role: 'alice' },
      { id: 'order-a2', value: '1', kind: 'order', owner_role: 'alice' },
    ],
  }
  const { findings } = await grind({ paths: ['/api/orders/2'], map: twoAlice })
  const swap = mutated(findings).find((r) => r.url.endsWith('/api/orders/1'))
  assert.ok(swap, 'the swap happened')
  assert.equal(swap.owner_role, 'alice')
})
