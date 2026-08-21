import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { runAuthzMatrix } from '../scripts/lib/bounty-authz-controller.mjs'
import { normalizeCapturedRequest } from '../scripts/lib/bounty-authz-request.mjs'
import { TESTBED_TOKENS, startAuthzTestbed } from './fixtures/authz-testbed.mjs'

const NOW = new Date('2026-08-21T10:00:00.000Z')

// The testbed lives on loopback on an ephemeral port, so the scope must seal both
// the private target and that exact port. Sealing after the server starts is not
// test scaffolding awkwardness -- it is the kernel's port rule working: an
// unsealed port is denied, and the first run of these tests proved it by refusing
// every request until the real port was sealed.
function sealedScope(port) {
  return {
    engagement_id: 'authz-testbed',
    authorization: { permissions: { rate_limit_rps: 50 } },
    // Fixed, and deliberately not relative: this test injects NOW, so a window
    // containing NOW is deterministic forever. Relative dates would only add
    // nondeterminism here.
    validity: { not_before: '2026-08-21T00:00:00.000Z', not_after: '2026-08-22T00:00:00.000Z' },
    scope_rules: {
      allow: [{ rule_id: 'a1', host_kind: 'ip', host: '127.0.0.1', ports: [port] }],
      deny: [],
      private_targets_sealed: true,
    },
  }
}

const REGISTRY = {
  schema_version: '1.0.0',
  kind: 'red-team-audit/bounty-authz-roles',
  roles: [
    { id: 'alice', label: 'owner', auth: { kind: 'header', name: 'authorization', value_env: 'TB_ALICE' } },
    { id: 'bob', label: 'other user', auth: { kind: 'header', name: 'authorization', value_env: 'TB_BOB' } },
    { id: 'anonymous', label: 'unauthenticated', auth: { kind: 'none' } },
  ],
}

const ENV = {
  TB_ALICE: `Bearer ${TESTBED_TOKENS.alice}`,
  TB_BOB: `Bearer ${TESTBED_TOKENS.bob}`,
}

async function workspace(port = 443) {
  const dir = await mkdtemp(join(tmpdir(), 'bounty-authz-'))
  await writeFile(join(dir, 'scope.json'), JSON.stringify(sealedScope(port), null, 2), 'utf8')
  return dir
}

function capture(origin, path) {
  return normalizeCapturedRequest({
    request_id: path,
    method: 'GET',
    url: `${origin}${path}`,
    headers: { accept: 'application/json' },
    owner_role: 'alice',
  })
}

async function grind(paths) {
  const testbed = await startAuthzTestbed()
  const dir = await workspace(testbed.port)
  try {
    const summary = await runAuthzMatrix({
      bundlePath: dir,
      requests: paths.map((path) => capture(testbed.origin, path)),
      registry: REGISTRY,
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

function verdictFor(findings, path, role) {
  return findings.results.find((r) => r.url.endsWith(path) && r.tester_role === role)?.verdict
}

test('finds the planted bypass on the unowned order', async () => {
  const { findings } = await grind(['/api/orders/2'])
  assert.equal(verdictFor(findings, '/api/orders/2', 'bob'), 'AUTHZ_BYPASS_CANDIDATE')
})

test('finds the planted bypass on the unprotected admin endpoint, including anonymous', async () => {
  const { findings } = await grind(['/api/admin/users'])
  assert.equal(verdictFor(findings, '/api/admin/users', 'bob'), 'AUTHZ_BYPASS_CANDIDATE')
  assert.equal(verdictFor(findings, '/api/admin/users', 'anonymous'), 'AUTHZ_BYPASS_CANDIDATE')
})

test('the correctly protected order is reported as denied, not as a finding', async () => {
  const { findings } = await grind(['/api/orders/1'])
  assert.equal(verdictFor(findings, '/api/orders/1', 'bob'), 'ACCESS_DENIED')
  assert.equal(verdictFor(findings, '/api/orders/1', 'anonymous'), 'ACCESS_DENIED')
})

test('per-role content on /api/me is DIFFERENT_CONTENT and never a candidate', async () => {
  const { summary, findings } = await grind(['/api/me'])
  assert.equal(verdictFor(findings, '/api/me', 'bob'), 'DIFFERENT_CONTENT')
  assert.equal(summary.candidates, 0, 'bob seeing bob is not a bug')
})

test('a genuinely volatile endpoint is UNPROVEN_VOLATILE, not a false positive', async () => {
  const { summary, findings } = await grind(['/api/volatile'])
  assert.equal(verdictFor(findings, '/api/volatile', 'bob'), 'UNPROVEN_VOLATILE')
  assert.equal(summary.candidates, 0, 'over-stripping would have reported a bypass here')
  assert.ok(summary.unproven >= 1)
  const row = findings.results.find((r) => r.url.endsWith('/api/volatile'))
  assert.equal(row.baseline_stable, false)
  assert.equal(row.baseline_reason, 'baseline-body-differs')
})

test('the full ground-truth sweep finds exactly the planted bugs', async () => {
  const { summary, findings } = await grind([
    '/api/orders/1', '/api/orders/2', '/api/admin/users', '/api/me', '/api/volatile', '/api/health',
  ])
  // orders/2 (bob) + admin/users (bob, anonymous) = 3. /api/health is public and
  // identical for everyone, so it is legitimately equivalent across roles too.
  const candidates = findings.results.filter((r) => r.verdict === 'AUTHZ_BYPASS_CANDIDATE')
  const candidatePaths = new Set(candidates.map((r) => new URL(r.url).pathname))
  assert.ok(candidatePaths.has('/api/orders/2'), 'planted order bug found')
  assert.ok(candidatePaths.has('/api/admin/users'), 'planted admin bug found')
  assert.equal(candidatePaths.has('/api/orders/1'), false, 'protected order not flagged')
  assert.equal(candidatePaths.has('/api/me'), false, 'per-role content not flagged')
  assert.equal(candidatePaths.has('/api/volatile'), false, 'volatile endpoint not flagged')
  assert.ok(summary.unproven >= 1, 'the volatile endpoint was recorded as unproven')
})

test('request count is requests times two owner replays plus each other role', async () => {
  const { summary } = await grind(['/api/me', '/api/health'])
  // 2 requests x (2 baseline + 2 testers) = 8
  assert.equal(summary.paced.issued, 8)
})

test('an out-of-scope captured request is refused before any socket opens', async () => {
  const dir = await workspace()
  try {
    let fetched = 0
    const summary = await runAuthzMatrix({
      bundlePath: dir,
      requests: [normalizeCapturedRequest({
        request_id: 'external',
        method: 'GET',
        url: 'https://evil.example/api/orders/2',
        owner_role: 'alice',
      })],
      registry: REGISTRY,
      now: NOW,
      env: ENV,
      fetchImpl: async () => { fetched += 1; return new Response('{}', { status: 200 }) },
      sleep: async () => {},
      clock: () => 0,
    })
    assert.equal(fetched, 0, 'nothing was fetched')
    assert.equal(summary.candidates, 0)
    assert.equal(summary.byVerdict.REPLAY_FAILED, 1)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('a missing role credential fails loudly instead of reporting a false denial', async () => {
  const testbed = await startAuthzTestbed()
  const dir = await workspace(testbed.port)
  try {
    await assert.rejects(
      () => runAuthzMatrix({
        bundlePath: dir,
        requests: [capture(testbed.origin, '/api/me')],
        registry: REGISTRY,
        now: NOW,
        env: { TB_ALICE: ENV.TB_ALICE },
        sleep: async () => {},
        clock: () => 0,
      }),
      /TB_BOB/,
    )
  } finally {
    await testbed.close()
    await rm(dir, { recursive: true, force: true })
  }
})

test('no credential value is written into the persisted findings', async () => {
  const testbed = await startAuthzTestbed()
  const dir = await workspace(testbed.port)
  try {
    await runAuthzMatrix({
      bundlePath: dir,
      requests: [capture(testbed.origin, '/api/me')],
      registry: REGISTRY,
      now: NOW,
      env: ENV,
      sleep: async () => {},
      clock: () => 0,
    })
    const raw = await readFile(join(dir, 'authz-findings.json'), 'utf8')
    assert.equal(raw.includes(TESTBED_TOKENS.alice), false)
    assert.equal(raw.includes(TESTBED_TOKENS.bob), false)
    assert.equal(raw.includes('Bearer'), false)
  } finally {
    await testbed.close()
    await rm(dir, { recursive: true, force: true })
  }
})
