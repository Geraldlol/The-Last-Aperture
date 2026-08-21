import assert from 'node:assert/strict'
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { draftAuthzReports } from '../scripts/lib/bounty-report-controller.mjs'

const NOW = new Date('2026-08-21T12:00:00.000Z')

const REGISTRY = {
  schema_version: '1.0.0',
  kind: 'red-team-audit/bounty-authz-roles',
  roles: [
    { id: 'alice', label: 'first', auth: { kind: 'header', name: 'authorization', value_env: 'TB_ALICE' } },
    { id: 'bob', label: 'second', auth: { kind: 'header', name: 'authorization', value_env: 'TB_BOB' } },
  ],
}

const ENV = { TB_ALICE: 'Bearer alice-secret-value', TB_BOB: 'Bearer bob-secret-value' }

function candidate(overrides = {}) {
  return {
    request_id: '/api/orders/2',
    url: 'https://api.acme.example/api/orders/2',
    method: 'GET',
    owner_role: 'alice',
    tester_role: 'bob',
    owner_status: 200,
    tester_status: 200,
    verdict: 'AUTHZ_BYPASS_CANDIDATE',
    confidence: 'high',
    rationale: 'bob received 200 byte-equivalent to the owner',
    baseline_stable: true,
    ...overrides,
  }
}

async function bundle(results, { validity } = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'bounty-report-'))
  await writeFile(join(dir, 'scope.json'), JSON.stringify({
    platform: 'yeswehack',
    engagement_id: 'ywh-acme',
    program: {
      program_handle: 'acme-public',
      policy_url: 'https://yeswehack.com/programs/acme-public',
      policy_snapshot_sha256: 'a'.repeat(64),
    },
    authorization: { permissions: { rate_limit_rps: 5 } },
    validity: validity ?? { not_before: '2026-08-21T00:00:00.000Z', not_after: '2026-11-21T00:00:00.000Z' },
    scope_rules: { allow: [], deny: [] },
  }, null, 2), 'utf8')
  await writeFile(join(dir, 'authz-findings.json'), JSON.stringify({
    schema_version: '1.0.0', results, summary: {},
  }, null, 2), 'utf8')
  await writeFile(join(dir, 'authz-requests.json'), JSON.stringify({
    schema_version: '1.0.0',
    requests: [{
      request_id: '/api/orders/2',
      method: 'GET',
      url: 'https://api.acme.example/api/orders/2',
      headers: { accept: 'application/json', authorization: ENV.TB_ALICE },
      body: null,
      owner_role: 'alice',
    }],
  }, null, 2), 'utf8')
  return dir
}

test('drafts one report per reportable finding', async () => {
  const dir = await bundle([candidate(), candidate({ tester_role: 'anonymous' })])
  try {
    const result = await draftAuthzReports({ bundlePath: dir, registry: REGISTRY, now: NOW, env: ENV })
    assert.equal(result.drafted, 2)
    assert.equal(result.status, 'DRAFTED_PENDING_REVIEW')
    const files = await readdir(join(dir, 'reports'))
    assert.equal(files.length, 2)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('declines unreportable verdicts with a stated reason and writes nothing', async () => {
  const dir = await bundle([
    candidate({ verdict: 'UNPROVEN_VOLATILE' }),
    candidate({ verdict: 'DIFFERENT_CONTENT' }),
    candidate({ verdict: 'ACCESS_DENIED' }),
  ])
  try {
    const result = await draftAuthzReports({ bundlePath: dir, registry: REGISTRY, now: NOW, env: ENV })
    assert.equal(result.drafted, 0)
    assert.equal(result.status, 'NO_REPORTABLE_FINDINGS')
    assert.equal(result.declined.length, 3)
    assert.ok(result.declined.every((entry) => entry.why.length > 10))
    await assert.rejects(() => readdir(join(dir, 'reports')), /ENOENT/)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('no credential value reaches any drafted report', async () => {
  const dir = await bundle([candidate()])
  try {
    await draftAuthzReports({ bundlePath: dir, registry: REGISTRY, now: NOW, env: ENV })
    const files = await readdir(join(dir, 'reports'))
    for (const file of files) {
      const text = await readFile(join(dir, 'reports', file), 'utf8')
      assert.equal(text.includes('alice-secret-value'), false, file)
      assert.equal(text.includes('bob-secret-value'), false, file)
      assert.match(text, /\$TB_ALICE/, 'the variable reference is present instead')
    }
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('a mutated finding reproduces the substituted url', async () => {
  const dir = await bundle([candidate({
    url: 'https://api.acme.example/api/invoices?order=5',
    owner_role: 'bob',
    tester_role: 'alice',
    mutation: 'query:order order-mine -> order-second',
  })])
  try {
    await draftAuthzReports({ bundlePath: dir, registry: REGISTRY, now: NOW, env: ENV })
    const files = await readdir(join(dir, 'reports'))
    const text = await readFile(join(dir, 'reports', files[0]), 'utf8')
    assert.match(text, /order=5/, 'the repro targets the substituted object')
    assert.match(text, /identifier substitution/)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('the authorization state at drafting time is reported', async () => {
  const expired = await bundle([candidate()], {
    validity: { not_before: '2026-06-01T00:00:00.000Z', not_after: '2026-07-01T00:00:00.000Z' },
  })
  try {
    // Drafting from an old bundle is legitimate -- the evidence outlives the
    // grant -- but submitting it under a lapsed authorization is worth knowing.
    const result = await draftAuthzReports({ bundlePath: expired, registry: REGISTRY, now: NOW, env: ENV })
    assert.equal(result.authorization, 'EXPIRED')
    assert.equal(result.drafted, 1, 'still drafted; the operator decides')
  } finally {
    await rm(expired, { recursive: true, force: true })
  }
})

test('report filenames are stable, ordered, and filesystem safe', async () => {
  const dir = await bundle([candidate(), candidate({ tester_role: 'anonymous' })])
  try {
    await draftAuthzReports({ bundlePath: dir, registry: REGISTRY, now: NOW, env: ENV })
    const files = (await readdir(join(dir, 'reports'))).sort()
    assert.match(files[0], /^01-bob-api-orders-2\.md$/)
    assert.match(files[1], /^02-anonymous-api-orders-2\.md$/)
    assert.ok(files.every((file) => !/[^a-zA-Z0-9._-]/.test(file)))
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})
