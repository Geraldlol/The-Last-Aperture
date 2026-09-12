import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { digestAdversarialPlan } from '../scripts/lib/adversarial-validation-contracts.mjs'
import { digestPolicySnapshot } from '../scripts/lib/bounty-contracts.mjs'
import { loadScanRequests, runScan } from '../scripts/lib/bounty-scan-controller.mjs'
import { normalizeCapturedRequest } from '../scripts/lib/bounty-authz-request.mjs'
import { findRole } from '../scripts/lib/bounty-authz-roles.mjs'
import { resolveIntensityProfile } from '../scripts/lib/bounty-intensity.mjs'
import {
  buildBountyScanPlan,
  snapshotBountyScanRole,
} from '../scripts/lib/bounty-scan-plan.mjs'
import { startDnsListener } from '../scripts/lib/bounty-oob-dns.mjs'
import {
  ingestSelfHostedEvent,
  mintOobPayload,
  openOobSession,
} from '../scripts/lib/bounty-oob-controller.mjs'
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
  roles: [{ id: 'alice', label: 'operator', auth: { kind: 'header', name: 'authorization', value_env: 'TB_ALICE' } }],
}
const ENV = { TB_ALICE: 'Bearer alice-token' }

function operatorAuthorizationFor({ scope, requests, classes, oobBinding = null }) {
  const role = snapshotBountyScanRole(findRole(REGISTRY, 'alice'))
  const plan = buildBountyScanPlan({
    scope,
    requests,
    classes,
    role,
    profile: resolveIntensityProfile(scope),
    oobBinding,
  })
  return verifyBoundOperatorAuthorization({
    value: {
      schema_version: '1.0.0',
      kind: OPERATOR_AUTHORIZATION_KIND,
      status: OPERATOR_AUTHORIZATION_STATUS,
      operator_id: 'operator:scan-controller-test',
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

async function workspace(port, { activeTesting = true } = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'bounty-scan-'))
  const sealedScope = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/bounty-scope',
    engagement_id: 'scan-testbed',
    platform: 'direct',
    environment: 'non_production',
    data_class: 'non_phi',
    // intensity is required: the scanner resolves breadth from the sealed tier and
    // fails closed without one. aggressive gives all three classes and no caps,
    // which is what these ground-truth assertions need.
    authorization: {
      mode: 'PROGRAM_POLICY_SEALED',
      authorization_id: 'scan-testbed-auth',
      statement: 'Synthetic authorization for the local scanner fixture.',
      operator_id: 'operator-test',
      authorized_by: 'test engagement owner',
      authorization_reference: 'https://policy.example.test/scope',
      attested_at: '2026-08-21T00:00:00.000Z',
      independently_verified: false,
      permissions: {
        rate_limit_rps: 100,
        active_testing: activeTesting,
        production: false,
        third_party: false,
        phi: false,
        mutation: false,
        automation_allowed: true,
        intensity: 'aggressive',
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
      allow: [{ rule_id: 'a1', host_kind: 'ip', host: '127.0.0.1', ports: [port] }],
      deny: [],
      private_targets_sealed: true,
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
    const requests = paths.map((path) => capture(testbed.origin, path))
    const classes = options.classes ?? ['error-injection', 'passive']
    const sealedScope = JSON.parse(await readFile(join(dir, 'scope.json'), 'utf8'))
    const crafted = classes.includes('error-injection') || classes.includes('ssrf-oob')
    const summary = await runScan({
      bundlePath: dir,
      requests,
      registry: REGISTRY,
      roleId: 'alice',
      now: NOW,
      env: ENV,
      classes,
      ...(crafted ? {
        operatorAuthorizationReceipt: operatorAuthorizationFor({
          scope: sealedScope,
          requests,
          classes,
        }),
        isAuthorizationRevoked: async () => false,
        isOperatorStopRequested: async () => false,
      } : {}),
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
  assert.equal(summary.passive.total, 0)
  assert.equal(summary.passive.status, 'NOT_ASSESSED')
  assert.equal(summary.coverage, 'NOT_ASSESSED_MISSING_RESPONSE_EVIDENCE')
})

test('passive-only review accepts a captured POST without target I/O', async () => {
  const testbed = await startAuthzTestbed()
  const dir = await workspace(testbed.port)
  let sends = 0
  try {
    const request = normalizeCapturedRequest({
      request_id: 'captured-login-post',
      method: 'POST',
      url: `${testbed.origin}/login`,
      headers: { accept: 'application/json' },
      owner_role: 'alice',
    })
    const summary = await runScan({
      bundlePath: dir,
      requests: [request],
      registry: REGISTRY,
      roleId: 'alice',
      now: NOW,
      env: ENV,
      classes: ['passive'],
      fetchImpl: async () => {
        sends += 1
        throw new Error('passive review must not dispatch')
      },
      sleep: async () => {},
      clock: () => 0,
    })
    assert.equal(sends, 0)
    assert.equal(summary.passive.status, 'NOT_ASSESSED')
    assert.equal(summary.coverage, 'NOT_ASSESSED_MISSING_RESPONSE_EVIDENCE')
  } finally {
    await testbed.close()
    await rm(dir, { recursive: true, force: true })
  }
})

test('scan request loading sanitizes legacy credential-bearing bundles', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'bounty-scan-legacy-'))
  t.after(() => rm(dir, { recursive: true, force: true }))
  await writeFile(join(dir, 'authz-requests.json'), JSON.stringify({
    requests: [{
      request_id: 'legacy-scan-request',
      method: 'POST',
      url: 'https://api.example.test/login?access_token=legacy-query-secret',
      headers: {
        'content-type': 'application/json',
        'x-access-token': 'legacy-header-secret',
      },
      body: '{"password":"legacy-body-secret"}',
      owner_role: 'alice',
    }],
  }), 'utf8')

  const loaded = await loadScanRequests(dir)
  const serialized = JSON.stringify(loaded)
  assert.doesNotMatch(serialized, /legacy-(?:query|header|body)-secret/)
  assert.deepEqual(loaded[0].redacted_headers, ['x-access-token'])
  assert.deepEqual(loaded[0].redacted_query_parameters, ['access_token'])
  assert.deepEqual(loaded[0].redacted_body_fields, ['password'])
})

test('scanning refuses a scope without active_testing', async () => {
  await assert.rejects(
    () => scan(['/api/search?q=x'], { activeTesting: false }),
    /active_testing/,
  )
})

test('scanning refuses an expired scope before any probe', async () => {
  const testbed = await startAuthzTestbed()
  const dir = await workspace(testbed.port)
  try {
    const expired = JSON.parse(await readFile(join(dir, 'scope.json'), 'utf8'))
    expired.validity = {
      not_before: '2026-06-01T00:00:00.000Z',
      not_after: '2026-07-01T00:00:00.000Z',
    }
    const scopeText = `${JSON.stringify(expired, null, 2)}\n`
    await writeFile(join(dir, 'scope.json'), scopeText, 'utf8')
    await writeFile(join(dir, 'bundle.json'), `${JSON.stringify({
      kind: 'red-team-audit/bounty-bundle',
      schema_version: '1.0.0',
      engagement_id: expired.engagement_id,
      scope_sha256: digestPolicySnapshot(scopeText),
      created_at: expired.authorization.attested_at,
    }, null, 2)}\n`, 'utf8')
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
    const session = await openOobSession({
      bundlePath: dir, backend: 'self_hosted', server: 'oob.test.example',
      now: NOW, fetchImpl: async () => { throw new Error('no network') },
    })
    const oobBinding = {
      backend: session.backend,
      server: session.server,
      correlation_id: session.correlation_id,
      created_at: session.created_at,
    }
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
    const requests = [capture(testbed.origin, '/api/fetch?url=https://cdn.example/a.png')]
    const sealedScope = JSON.parse(await readFile(join(dir, 'scope.json'), 'utf8'))
    const summary = await runScan({
      bundlePath: dir,
      requests,
      registry: REGISTRY, roleId: 'alice', now: NOW, env: ENV,
      classes: ['ssrf-oob'], oob,
      operatorAuthorizationReceipt: operatorAuthorizationFor({
        scope: sealedScope,
        requests,
        classes: ['ssrf-oob'],
        oobBinding,
      }),
      isAuthorizationRevoked: async () => false,
      isOperatorStopRequested: async () => false,
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
    const session = await openOobSession({
      bundlePath: dir, backend: 'self_hosted', server: 'oob.test.example',
      now: NOW, fetchImpl: async () => { throw new Error('no network') },
    })
    const oobBinding = {
      backend: session.backend,
      server: session.server,
      correlation_id: session.correlation_id,
      created_at: session.created_at,
    }
    const requests = [capture(testbed.origin, '/api/orders/2')]
    const sealedScope = JSON.parse(await readFile(join(dir, 'scope.json'), 'utf8'))
    await runScan({
      bundlePath: dir,
      // A numeric id: no url name, no url-shaped value.
      requests,
      registry: REGISTRY, roleId: 'alice', now: NOW, env: ENV,
      classes: ['ssrf-oob'],
      operatorAuthorizationReceipt: operatorAuthorizationFor({
        scope: sealedScope,
        requests,
        classes: ['ssrf-oob'],
        oobBinding,
      }),
      isAuthorizationRevoked: async () => false,
      isOperatorStopRequested: async () => false,
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
