import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import {
  SCOPE_CURRENCY_STATES,
  assertScopeCurrent,
  describeScopeCurrency,
} from '../scripts/lib/bounty-contracts.mjs'
import { runAuthzMatrix } from '../scripts/lib/bounty-authz-controller.mjs'
import { validateBountyBundle } from '../scripts/lib/bounty-controller.mjs'
import { createProgramSealedScope } from '../scripts/lib/bounty-planner.mjs'
import { runRecon } from '../scripts/lib/bounty-recon-controller.mjs'
import { normalizeCapturedRequest } from '../scripts/lib/bounty-authz-request.mjs'

const NOW = new Date('2026-08-21T12:00:00.000Z')

const windowOf = (notBefore, notAfter) => ({
  validity: { not_before: notBefore, not_after: notAfter },
})

test('a window containing now is CURRENT', () => {
  const currency = describeScopeCurrency({
    scope: windowOf('2026-08-21T00:00:00.000Z', '2026-08-22T00:00:00.000Z'),
    now: NOW,
  })
  assert.equal(currency.status, 'CURRENT')
  assert.equal(currency.now, '2026-08-21T12:00:00.000Z')
})

test('a window that has not opened is NOT_YET_VALID', () => {
  assert.equal(
    describeScopeCurrency({
      scope: windowOf('2026-09-01T00:00:00.000Z', '2026-10-01T00:00:00.000Z'),
      now: NOW,
    }).status,
    'NOT_YET_VALID',
  )
})

test('a window that has closed is EXPIRED', () => {
  assert.equal(
    describeScopeCurrency({
      scope: windowOf('2026-07-01T00:00:00.000Z', '2026-08-01T00:00:00.000Z'),
      now: NOW,
    }).status,
    'EXPIRED',
  )
})

test('the upper bound is exclusive, matching http-authed', () => {
  const atTheEdge = describeScopeCurrency({
    scope: windowOf('2026-08-01T00:00:00.000Z', '2026-08-21T12:00:00.000Z'),
    now: NOW,
  })
  assert.equal(atTheEdge.status, 'EXPIRED', 'at exactly not_after the grant has run out')
  const justInside = describeScopeCurrency({
    scope: windowOf('2026-08-21T12:00:00.000Z', '2026-08-22T00:00:00.000Z'),
    now: NOW,
  })
  assert.equal(justInside.status, 'CURRENT', 'at exactly not_before it has begun')
})

test('an absent, partial, or unparseable window is VALIDITY_MISSING', () => {
  for (const scope of [
    {},
    { validity: null },
    { validity: {} },
    { validity: { not_before: '2026-08-21T00:00:00.000Z' } },
    { validity: { not_before: 'not-a-date', not_after: 'also-not' } },
  ]) {
    assert.equal(describeScopeCurrency({ scope, now: NOW }).status, 'VALIDITY_MISSING')
  }
})

test('describeScopeCurrency refuses an invalid now rather than guessing', () => {
  assert.throws(
    () => describeScopeCurrency({ scope: windowOf('2026-08-01T00:00:00.000Z', '2026-09-01T00:00:00.000Z') }),
    /valid Date/,
  )
})

test('assertScopeCurrent passes only a current window', () => {
  assert.doesNotThrow(() => assertScopeCurrent({
    scope: windowOf('2026-08-21T00:00:00.000Z', '2026-08-22T00:00:00.000Z'), now: NOW,
  }))
  assert.throws(() => assertScopeCurrent({
    scope: windowOf('2026-07-01T00:00:00.000Z', '2026-08-01T00:00:00.000Z'), now: NOW,
  }), /EXPIRED/)
  assert.throws(() => assertScopeCurrent({
    scope: windowOf('2026-09-01T00:00:00.000Z', '2026-10-01T00:00:00.000Z'), now: NOW,
  }), /NOT_YET_VALID/)
})

test('a scope with no window fails closed, not open', () => {
  // An unsealed validity period is an invalid scope, not a permissive one.
  assert.throws(() => assertScopeCurrent({ scope: {}, now: NOW }), /no usable validity window/)
})

test('the currency states are a closed set', () => {
  assert.deepEqual([...SCOPE_CURRENCY_STATES].sort(), [
    'CURRENT', 'EXPIRED', 'NOT_YET_VALID', 'VALIDITY_MISSING',
  ])
})

test('the planner refuses to seal a window that excludes its own attestation', () => {
  const base = {
    engagementId: 'ywh-acme',
    platform: 'yeswehack',
    programHandle: 'acme',
    policyUrl: 'https://yeswehack.com/programs/acme',
    policySnapshotBytes: Buffer.from('policy\n'),
    operatorId: 'op',
    authorizedBy: 'acme',
    requiredUserAgent: 'BugBounty-acme',
    allowSpecs: ['*.acme.example'],
    permissions: {
      active_testing: true, production: true, third_party: false, mutation: false,
      automation_allowed: true, intensity: 'normal', desync_probes: false, rate_limit_rps: 5,
    },
    now: NOW,
  }
  assert.throws(() => createProgramSealedScope({
    ...base,
    validity: { notBefore: '2026-07-01T00:00:00.000Z', notAfter: '2026-08-01T00:00:00.000Z' },
  }), /EXPIRED/)
  assert.throws(() => createProgramSealedScope({
    ...base,
    validity: { notBefore: '2026-09-01T00:00:00.000Z', notAfter: '2026-10-01T00:00:00.000Z' },
  }), /NOT_YET_VALID/)
  assert.doesNotThrow(() => createProgramSealedScope({
    ...base,
    validity: { notBefore: '2026-08-21T00:00:00.000Z', notAfter: '2026-11-21T00:00:00.000Z' },
  }))
})

async function bundleWith(validity) {
  const dir = await mkdtemp(join(tmpdir(), 'bounty-currency-'))
  await writeFile(join(dir, 'scope.json'), JSON.stringify({
    engagement_id: 'currency',
    authorization: { permissions: { rate_limit_rps: 10 } },
    validity,
    program: { required_user_agent: 'BugBounty-acme' },
    scope_rules: {
      allow: [{ rule_id: 'a1', host_kind: 'wildcard', host: 'acme.example' }],
      deny: [],
    },
  }, null, 2), 'utf8')
  return dir
}

test('recon refuses an expired scope before any socket opens', async () => {
  const dir = await bundleWith({ not_before: '2026-07-01T00:00:00.000Z', not_after: '2026-08-01T00:00:00.000Z' })
  try {
    let touched = 0
    await assert.rejects(
      () => runRecon({
        bundlePath: dir,
        seeds: ['api.acme.example'],
        sources: ['tls'],
        now: NOW,
        fetchImpl: async () => { touched += 1; return new Response('{}') },
        connectImpl: async () => { touched += 1; return {} },
        sleep: async () => {},
        clock: () => 0,
      }),
      /EXPIRED/,
    )
    assert.equal(touched, 0, 'nothing was contacted under a lapsed authorization')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('recon refuses a scope with no validity window at all', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bounty-currency-'))
  try {
    await writeFile(join(dir, 'scope.json'), JSON.stringify({
      engagement_id: 'no-window',
      authorization: { permissions: { rate_limit_rps: 10 } },
      program: { required_user_agent: 'BugBounty-acme' },
      scope_rules: { allow: [{ rule_id: 'a1', host_kind: 'wildcard', host: 'acme.example' }], deny: [] },
    }), 'utf8')
    await assert.rejects(
      () => runRecon({
        bundlePath: dir, seeds: ['api.acme.example'], sources: ['tls'], now: NOW,
        connectImpl: async () => ({}), sleep: async () => {}, clock: () => 0,
      }),
      /no usable validity window/,
    )
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('the authz grinder refuses an expired scope before any replay', async () => {
  const dir = await bundleWith({ not_before: '2026-07-01T00:00:00.000Z', not_after: '2026-08-01T00:00:00.000Z' })
  try {
    let replays = 0
    await assert.rejects(
      () => runAuthzMatrix({
        bundlePath: dir,
        requests: [normalizeCapturedRequest({
          request_id: 'r', method: 'GET', url: 'https://api.acme.example/orders/2', owner_role: 'alice',
        })],
        registry: {
          schema_version: '1.0.0',
          kind: 'red-team-audit/bounty-authz-roles',
          roles: [{ id: 'alice', label: 'owner', auth: { kind: 'none' } }],
        },
        now: NOW,
        fetchImpl: async () => { replays += 1; return new Response('{}') },
        sleep: async () => {},
        clock: () => 0,
      }),
      /EXPIRED/,
    )
    assert.equal(replays, 0)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('recon proceeds under a current scope', async () => {
  const dir = await bundleWith({ not_before: '2026-08-21T00:00:00.000Z', not_after: '2026-08-22T00:00:00.000Z' })
  try {
    const summary = await runRecon({
      bundlePath: dir,
      seeds: ['api.acme.example'],
      sources: ['tls'],
      now: NOW,
      fetchImpl: async () => new Response('<html><title>x</title></html>', {
        status: 200, headers: { 'content-type': 'text/html' },
      }),
      connectImpl: async () => ({ subjectaltname: 'DNS:api.acme.example' }),
      sleep: async () => {},
      clock: () => 0,
    })
    assert.ok(summary.hosts >= 1)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})
