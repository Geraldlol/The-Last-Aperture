import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { digestAdversarialPlan } from '../scripts/lib/adversarial-validation-contracts.mjs'
import { digestPolicySnapshot } from '../scripts/lib/bounty-contracts.mjs'
import {
  INTENSITY_TIERS,
  applyCap,
  describeIntensity,
  resolveIntensityProfile,
  selectProbes,
} from '../scripts/lib/bounty-intensity.mjs'
import { runScan } from '../scripts/lib/bounty-scan-controller.mjs'
import { normalizeCapturedRequest } from '../scripts/lib/bounty-authz-request.mjs'
import { findRole } from '../scripts/lib/bounty-authz-roles.mjs'
import {
  buildBountyScanPlan,
  snapshotBountyScanRole,
} from '../scripts/lib/bounty-scan-plan.mjs'
import {
  OPERATOR_AUTHORIZATION_KIND,
  OPERATOR_AUTHORIZATION_STATUS,
  OPERATOR_CAMPAIGN_AUTHORIZATION_STATEMENT,
  verifyBoundOperatorAuthorization,
} from '../scripts/lib/operator-authorization.mjs'
import { startAuthzTestbed } from './fixtures/authz-testbed.mjs'

const NOW = new Date('2026-08-21T12:00:00.000Z')
const REGISTRY = {
  schema_version: '1.0.0',
  kind: 'red-team-audit/bounty-authz-roles',
  roles: [{ id: 'alice', label: 'op', auth: { kind: 'header', name: 'authorization', value_env: 'TB_ALICE' } }],
}
const ENV = { TB_ALICE: 'Bearer alice-token' }

function operatorAuthorizationFor(scope, requests) {
  const role = snapshotBountyScanRole(findRole(REGISTRY, 'alice'))
  const plan = buildBountyScanPlan({
    scope,
    requests,
    classes: ['error-injection'],
    role,
    profile: resolveIntensityProfile(scope),
  })
  return verifyBoundOperatorAuthorization({
    value: {
      schema_version: '1.0.0',
      kind: OPERATOR_AUTHORIZATION_KIND,
      status: OPERATOR_AUTHORIZATION_STATUS,
      operator_id: 'operator:intensity-test',
      authorization_reference: `authorization:${plan.plan_id}`,
      statement: OPERATOR_CAMPAIGN_AUTHORIZATION_STATEMENT,
      declared_at: '2026-08-21T11:59:00.000Z',
      target: structuredClone(plan.target),
      plan_sha256: digestAdversarialPlan(plan),
      scope_revision_sha256: plan.scope_revision_sha256,
    },
    planSha256: digestAdversarialPlan(plan),
    scopeRevisionSha256: plan.scope_revision_sha256,
    target: plan.target,
    now: NOW,
    fail(code, message) {
      throw new Error(`${code}: ${message}`)
    },
  })
}

const scopeWith = (intensity, rateLimit = 100) => ({
  authorization: { permissions: { intensity, rate_limit_rps: rateLimit, active_testing: true } },
})

test('every sealed tier resolves to a profile', () => {
  for (const tier of INTENSITY_TIERS) {
    assert.equal(resolveIntensityProfile(scopeWith(tier)).tier, tier)
  }
})

test('an unusable tier throws rather than defaulting', () => {
  assert.throws(() => resolveIntensityProfile(scopeWith('nuclear')), /intensity tier/)
  assert.throws(() => resolveIntensityProfile({}), /intensity tier/)
})

test('breadth increases monotonically with tier', () => {
  const normal = resolveIntensityProfile(scopeWith('normal'))
  const aggressive = resolveIntensityProfile(scopeWith('aggressive'))
  const ham = resolveIntensityProfile(scopeWith('ham'))
  assert.ok(normal.insertionPointCap < aggressive.insertionPointCap)
  assert.ok(aggressive.insertionPointCap < ham.insertionPointCap)
  assert.ok(normal.probesPerInsertionPoint < aggressive.probesPerInsertionPoint)
  assert.equal(normal.earlyExitOnSignal, true)
  assert.equal(aggressive.earlyExitOnSignal, false)
  assert.equal(ham.recurseOnDiscovery, true)
  assert.equal(ham.compoundAttacks, true)
  assert.equal(normal.recurseOnDiscovery, false)
})

test('HAM requests its finite concurrency ceiling and is clamped by the sealed rate limit', () => {
  // The invariant that keeps HAM deployable: the program's stated limit IS the
  // authorization, and no tier outranks it.
  const ham = resolveIntensityProfile(scopeWith('ham', 5))
  assert.equal(ham.concurrency, 5)
  const slower = resolveIntensityProfile(scopeWith('ham', 1))
  assert.equal(slower.concurrency, 1)
  assert.notEqual(ham.concurrency, Number.POSITIVE_INFINITY)
})

test('every workload tier has finite work ceilings', () => {
  for (const tier of INTENSITY_TIERS) {
    const profile = resolveIntensityProfile(scopeWith(tier))
    assert.equal(Number.isFinite(profile.probesPerInsertionPoint), true, tier)
    assert.equal(Number.isFinite(profile.insertionPointCap), true, tier)
    assert.equal(Number.isFinite(profile.requestCap), true, tier)
    assert.equal(Number.isFinite(profile.concurrency), true, tier)
  }
})

test('a lower tier never exceeds its own concurrency even on a generous limit', () => {
  assert.equal(resolveIntensityProfile(scopeWith('normal', 200)).concurrency, 1)
  assert.equal(resolveIntensityProfile(scopeWith('aggressive', 200)).concurrency, 2)
})

test('an absent or invalid rate limit clamps to one, never to unbounded', () => {
  // Built directly rather than through the helper, whose default would supply a
  // perfectly valid limit and make the assertion vacuous.
  const noLimit = { authorization: { permissions: { intensity: 'ham' } } }
  const zeroLimit = { authorization: { permissions: { intensity: 'ham', rate_limit_rps: 0 } } }
  const negative = { authorization: { permissions: { intensity: 'ham', rate_limit_rps: -5 } } }
  for (const scope of [noLimit, zeroLimit, negative]) {
    const profile = resolveIntensityProfile(scope)
    assert.equal(profile.concurrency, 1, JSON.stringify(scope.authorization.permissions))
    assert.notEqual(profile.concurrency, Number.POSITIVE_INFINITY)
  }
})

test('caps report what they dropped rather than truncating silently', () => {
  const capped = applyCap([1, 2, 3, 4, 5], 2, 'things')
  assert.deepEqual(capped.items, [1, 2])
  assert.equal(capped.dropped, 3)
  assert.match(capped.note, /covered 2 of 5, 3 not examined/)
  const uncapped = applyCap([1, 2], Number.POSITIVE_INFINITY, 'things')
  assert.equal(uncapped.dropped, 0)
  assert.equal(uncapped.note, null)
})

test('normal samples probes while higher tiers take them all', () => {
  const probes = [1, 2, 3, 4, 5]
  assert.equal(selectProbes(probes, resolveIntensityProfile(scopeWith('normal'))).items.length, 2)
  assert.equal(selectProbes(probes, resolveIntensityProfile(scopeWith('ham'))).items.length, 5)
})

test('the description states the clamp so it is visible in output', () => {
  const text = describeIntensity(resolveIntensityProfile(scopeWith('ham', 4)))
  assert.match(text, /tier=ham/)
  assert.match(text, /concurrency=4 \(clamped to 4\/s\)/)
  assert.match(text, /requests=1000/)
  assert.doesNotMatch(text, /unbounded/)
})

// --- the dial actually changing scanner behaviour ---

async function scanAt(intensity, path) {
  const testbed = await startAuthzTestbed()
  const dir = await mkdtemp(join(tmpdir(), 'bounty-intensity-'))
  try {
    const sealedScope = {
      schema_version: '1.0.0',
      kind: 'red-team-audit/bounty-scope',
      engagement_id: 'intensity',
      platform: 'direct',
      environment: 'non_production',
      data_class: 'non_phi',
      authorization: {
        mode: 'PROGRAM_POLICY_SEALED',
        authorization_id: 'intensity-auth',
        statement: 'Synthetic authorization for the local intensity fixture.',
        operator_id: 'operator-test',
        authorized_by: 'test engagement owner',
        authorization_reference: 'https://policy.example.test/scope',
        attested_at: '2026-08-21T00:00:00.000Z',
        independently_verified: false,
        permissions: {
          intensity,
          rate_limit_rps: 100,
          active_testing: true,
          production: false,
          third_party: false,
          phi: false,
          mutation: false,
          automation_allowed: true,
          desync_probes: false,
        },
      },
      validity: { not_before: '2026-08-21T00:00:00.000Z', not_after: '2026-08-22T00:00:00.000Z' },
      program: {
        program_handle: 'test-program',
        policy_url: 'https://policy.example.test/scope',
        policy_snapshot_sha256: 'a'.repeat(64),
        required_user_agent: 'BugBounty-acme',
      },
      scope_rules: {
        allow: [{ rule_id: 'a1', host_kind: 'ip', host: '127.0.0.1', ports: [testbed.port] }],
        deny: [], private_targets_sealed: true,
      },
      stop_conditions: { max_findings: 10, operator_stop: false },
    }
    const scopeText = `${JSON.stringify(sealedScope, null, 2)}\n`
    await writeFile(join(dir, 'scope.json'), scopeText, 'utf8')
    await writeFile(join(dir, 'bundle.json'), `${JSON.stringify({
      kind: 'red-team-audit/bounty-bundle',
      schema_version: '1.0.0',
      engagement_id: sealedScope.engagement_id,
      scope_sha256: digestPolicySnapshot(scopeText),
      created_at: sealedScope.authorization.attested_at,
    }, null, 2)}\n`, 'utf8')
    const requests = [normalizeCapturedRequest({
      request_id: path, method: 'GET', url: `${testbed.origin}${path}`,
      headers: { accept: 'application/json' }, owner_role: 'alice',
    })]
    const summary = await runScan({
      bundlePath: dir,
      requests,
      registry: REGISTRY, roleId: 'alice', now: NOW, env: ENV,
      classes: ['error-injection'],
      operatorAuthorizationReceipt: operatorAuthorizationFor(sealedScope, requests),
      isAuthorizationRevoked: async () => false,
      isOperatorStopRequested: async () => false,
      sleep: async () => {}, clock: () => 0,
    })
    const findings = JSON.parse(await readFile(join(dir, 'scan-findings.json'), 'utf8'))
    return { summary, findings }
  } finally {
    await testbed.close()
    await rm(dir, { recursive: true, force: true })
  }
}

test('the sealed tier changes how many probes actually go out', async () => {
  const normal = await scanAt('normal', '/api/stable?q=x')
  const ham = await scanAt('ham', '/api/stable?q=x')
  assert.ok(ham.summary.paced.issued > normal.summary.paced.issued,
    `ham (${ham.summary.paced.issued}) should send more than normal (${normal.summary.paced.issued})`)
  assert.match(normal.summary.intensity, /tier=normal/)
  assert.match(ham.summary.intensity, /tier=ham/)
})

test('a capped sweep says so instead of looking complete', async () => {
  const normal = await scanAt('normal', '/api/stable?q=x')
  assert.equal(normal.summary.coverage, 'CAPPED_BY_INTENSITY')
  assert.ok(normal.summary.coverageNotes.some((note) => /not examined at this intensity/.test(note)))
  const ham = await scanAt('ham', '/api/stable?q=x')
  assert.equal(ham.summary.coverage, 'FULL_AT_THIS_INTENSITY')
  assert.deepEqual(ham.summary.coverageNotes, [])
})

test('normal stops at the first signal, ham exhausts the point', async () => {
  const normal = await scanAt('normal', '/api/search?q=widget')
  const ham = await scanAt('ham', '/api/search?q=widget')
  const candidatesAt = (r) => r.findings.results.filter((x) => x.verdict.endsWith('_CANDIDATE')).length
  assert.ok(candidatesAt(normal) >= 1, 'normal still finds the planted bug')
  assert.ok(candidatesAt(ham) > candidatesAt(normal),
    'ham characterises it with more of the payload set')
})

test('the recorded findings carry the tier they were produced at', async () => {
  const { findings } = await scanAt('aggressive', '/api/stable?q=x')
  assert.equal(findings.intensity, 'aggressive')
})
