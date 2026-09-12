import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  BOUNTY_SCAN_ADAPTER_VERSION,
  BOUNTY_SCAN_PAYLOAD_CATALOG_VERSION,
  bountyScanStateChangingReason,
  buildBountyScanPlan,
  classifyBountyScanTarget,
  digestBountyScanScope,
} from '../scripts/lib/bounty-scan-plan.mjs'
import { ANONYMOUS_ROLE } from '../scripts/lib/bounty-authz-roles.mjs'
import {
  normalizeCapturedRequest,
  sanitizeCapturedRequest,
} from '../scripts/lib/bounty-authz-request.mjs'
import { resolveIntensityProfile } from '../scripts/lib/bounty-intensity.mjs'
import { ERROR_PROBES } from '../scripts/lib/bounty-scan-oracle.mjs'
import {
  digestAdversarialPlan,
  validateAdversarialPlan,
} from '../scripts/lib/adversarial-validation-contracts.mjs'

function scope(host = 'api.example.test', hostKind = 'exact') {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/bounty-scope',
    engagement_id: 'engagement-scan-plan-001',
    platform: 'direct',
    environment: 'non_production',
    data_class: 'non_phi',
    authorization: {
      mode: 'PROGRAM_POLICY_SEALED',
      authorization_id: 'engagement-scan-plan-001-auth',
      statement: 'Synthetic test authorization.',
      operator_id: 'operator-test',
      authorized_by: 'test owner',
      authorization_reference: 'https://policy.example.test/scope',
      attested_at: '2026-08-21T00:00:00.000Z',
      independently_verified: false,
      permissions: {
        rate_limit_rps: 10,
        active_testing: true,
        production: false,
        third_party: false,
        phi: false,
        mutation: false,
        automation_allowed: true,
        intensity: 'normal',
        desync_probes: false,
      },
    },
    validity: {
      not_before: '2026-08-21T00:00:00.000Z',
      not_after: '2026-08-22T00:00:00.000Z',
    },
    program: {
      program_handle: 'test-program',
      policy_url: 'https://policy.example.test/scope',
      policy_snapshot_sha256: 'a'.repeat(64),
      required_user_agent: 'BugBounty-acme',
    },
    scope_rules: {
      allow: [{ rule_id: 'allow-scan', host_kind: hostKind, host, ports: [443] }],
      deny: [],
      private_targets_sealed: hostKind === 'ip',
    },
    stop_conditions: { max_findings: 10, operator_stop: false },
  }
}

function request(url = 'https://api.example.test/search?q=widget') {
  return normalizeCapturedRequest({
    request_id: 'request:search-001',
    method: 'get',
    url,
    headers: { Accept: 'application/json' },
    owner_role: 'alice',
  })
}

function plan(overrides = {}) {
  const sealedScope = overrides.scope ?? scope()
  return buildBountyScanPlan({
    scope: sealedScope,
    requests: overrides.requests ?? [request()],
    classes: overrides.classes ?? ['error-injection'],
    role: overrides.role ?? ANONYMOUS_ROLE,
    profile: resolveIntensityProfile(sealedScope),
    oobBinding: overrides.oobBinding ?? null,
  })
}

test('the pure scan plan binds scope, normalized requests, classes, role, catalog, and finite limits', () => {
  const sealedScope = scope()
  const value = plan({ scope: sealedScope })

  assert.deepEqual(validateAdversarialPlan(value), { valid: true, errors: [] })
  assert.equal(value.target.kind, 'live')
  assert.equal(value.scope_revision_sha256, digestBountyScanScope(sealedScope))
  assert.equal(value.strategy_id, `bounty.scan/crafted-v${BOUNTY_SCAN_ADAPTER_VERSION}`)
  assert.equal(value.generator.version, BOUNTY_SCAN_ADAPTER_VERSION)
  assert.equal(value.generator.max_cases, value.limits.max_actions)
  assert.ok(value.limits.max_actions >= 2)
  assert.ok(value.limits.max_wall_time_ms > 0)
  assert.equal(value.limits.max_concurrency, 1)

  const binding = value.generator.template.parameters
  assert.equal(binding.payload_catalog_version, BOUNTY_SCAN_PAYLOAD_CATALOG_VERSION)
  assert.match(binding.payload_catalog_sha256, /^[a-f0-9]{64}$/)
  assert.match(binding.request_inputs_sha256, /^[a-f0-9]{64}$/)
  assert.deepEqual(binding.classes, ['error-injection'])
  assert.equal(binding.role_id, 'anonymous')
  assert.match(binding.role_profile_sha256, /^[a-f0-9]{64}$/)
})

test('scan planning is deterministic and every authority-bearing input changes the plan digest', () => {
  const original = plan()
  assert.equal(digestAdversarialPlan(plan()), digestAdversarialPlan(original))

  const changedScope = scope()
  changedScope.authorization.permissions.rate_limit_rps = 9
  const variants = [
    plan({ scope: changedScope }),
    plan({ requests: [request('https://api.example.test/search?q=changed')] }),
    plan({ classes: ['error-injection', 'passive'] }),
    plan({ role: { id: 'reviewer', label: 'reviewer', auth: { kind: 'none' } } }),
  ]
  for (const variant of variants) {
    assert.notEqual(digestAdversarialPlan(variant), digestAdversarialPlan(original))
  }
})

test('scan planning binds the sanitized form of legacy credential-bearing requests', () => {
  const raw = normalizeCapturedRequest({
    request_id: 'legacy-plan-request',
    method: 'GET',
    url: 'https://api.example.test/search?q=widget&access_token=legacy-query-secret',
    headers: { accept: 'application/json', 'x-access-token': 'legacy-header-secret' },
    owner_role: 'alice',
  })

  assert.deepEqual(
    plan({ requests: [raw] }),
    plan({ requests: [sanitizeCapturedRequest(raw)] }),
  )
})

test('the approved catalog is isolated from mutable oracle exports', () => {
  const before = digestAdversarialPlan(plan())
  const original = ERROR_PROBES[0].payload
  try {
    ERROR_PROBES[0].payload = `${original}-runtime-drift`
    assert.equal(digestAdversarialPlan(plan()), before)
  } finally {
    ERROR_PROBES[0].payload = original
  }
})

test('only literal loopback request sets are classified as local_service', () => {
  assert.equal(classifyBountyScanTarget([
    request('http://127.0.0.1:8080/search?q=x'),
    request('http://127.1.2.3:8080/search?q=y'),
  ]), 'local_service')
  assert.equal(classifyBountyScanTarget([
    request('http://[::1]:8080/search?q=x'),
  ]), 'local_service')
  assert.equal(classifyBountyScanTarget([
    request('http://localhost:8080/search?q=x'),
  ]), 'live')
  assert.equal(classifyBountyScanTarget([
    request('https://audit-edge.example.test/search?q=x'),
  ]), 'live')
  assert.equal(classifyBountyScanTarget([
    request('http://127.0.0.1:8080/search?q=x'),
    request('https://api.example.test/search?q=x'),
  ]), 'live')
})

test('scan planning applies the exact scope kernel to every selected request', () => {
  const sealedScope = scope()
  sealedScope.scope_rules.allow[0].path_prefix = '/allowed/'

  assert.throws(
    () => plan({
      scope: sealedScope,
      requests: [request('https://api.example.test/outside?q=x')],
    }),
    /outside the current scope/i,
  )
})

test('crafted scanning refuses state-changing methods even when mutation is sealed', () => {
  const post = request()
  post.method = 'POST'

  assert.throws(
    () => plan({ requests: [post] }),
    /state-changing.*mutation campaign|mutation campaign.*state-changing/i,
  )

  const mutationScope = scope()
  mutationScope.authorization.permissions.mutation = true
  assert.throws(
    () => plan({ scope: mutationScope, requests: [post] }),
    /state-changing.*mutation campaign|mutation campaign.*state-changing/i,
  )
})

test('crafted scanning refuses safe-method routes with state-changing semantics', () => {
  let deeplyEncodedName = '%61ction'
  let deeplyEncodedValue = '%64elete'
  let deeplyEncodedPath = '%64elete'
  for (let index = 0; index < 16; index += 1) {
    deeplyEncodedName = encodeURIComponent(deeplyEncodedName)
    deeplyEncodedValue = encodeURIComponent(deeplyEncodedValue)
    deeplyEncodedPath = encodeURIComponent(deeplyEncodedPath)
  }
  for (const url of [
    'https://api.example.test/delete?id=123',
    'https://api.example.test/session/logout',
    'https://api.example.test/records/123/delete-item',
    'https://api.example.test/records?action=delete&id=123',
    'https://api.example.test/users/1/ban',
    'https://api.example.test/records?_method=DELETE&id=123',
    'https://api.example.test/records?op=delete&id=123',
    'https://api.example.test/records?act%2569on=%2564elete&id=123',
    'https://api.example.test/records?%ZZaction=read&id=123',
    `https://api.example.test/records?${deeplyEncodedName}=${deeplyEncodedValue}&id=123`,
    `https://api.example.test/${deeplyEncodedPath}?id=123`,
  ]) {
    assert.throws(
      () => plan({ requests: [request(url)] }),
      /state-changing.*route|route.*state-changing|mutation campaign|percent encoding/i,
      url,
    )
  }
})

test('route mutation classification does not treat read-shaped names as actions', () => {
  for (const url of [
    'https://api.example.test/archive',
    'https://api.example.test/jobs/run-status',
  ]) {
    assert.equal(bountyScanStateChangingReason(request(url)), null, url)
  }
  assert.match(
    bountyScanStateChangingReason(request('https://api.example.test/records/123/archive')),
    /route/i,
  )
})

test('the OOB session destination is an exact authority-bearing plan input', () => {
  const aggressiveScope = scope()
  aggressiveScope.authorization.permissions.intensity = 'aggressive'
  const common = {
    scope: aggressiveScope,
    classes: ['ssrf-oob'],
  }
  const first = plan({
    ...common,
    oobBinding: {
      backend: 'self_hosted',
      server: 'oob-a.example.test',
      correlation_id: 'a'.repeat(20),
      created_at: '2026-08-21T11:00:00.000Z',
    },
  })
  const changed = plan({
    ...common,
    oobBinding: {
      backend: 'self_hosted',
      server: 'oob-b.example.test',
      correlation_id: 'a'.repeat(20),
      created_at: '2026-08-21T11:00:00.000Z',
    },
  })

  assert.notEqual(digestAdversarialPlan(first), digestAdversarialPlan(changed))
  assert.throws(
    () => plan(common),
    /OOB.*session.*required|requires.*OOB/i,
  )
})

test('routing override headers and role credentials cannot bypass URL scope', () => {
  const routed = request()
  routed.headers.host = 'internal-admin.example'
  assert.throws(
    () => plan({ requests: [routed] }),
    /routing.*header|host.*forbidden/i,
  )
  assert.throws(
    () => plan({
      role: {
        id: 'routed-role',
        label: 'routed role',
        auth: { kind: 'header', name: 'Host', value_env: 'ROUTED_SECRET' },
      },
    }),
    /routing.*header|host.*forbidden/i,
  )
  const override = request()
  override.headers['x-http-method-override'] = 'DELETE'
  assert.throws(
    () => plan({ requests: [override] }),
    /routing.*header|method-override.*forbidden/i,
  )
  for (const name of [
    'x-original-uri', 'x-forwarded-uri', 'x-http-method', 'x-forwarded-prefix',
    'x-original-method', 'x-rewrite-uri', 'x-envoy-original-path', 'x-http-url-override',
  ]) {
    const alternate = request()
    alternate.headers[name] = '/admin'
    assert.throws(
      () => plan({ requests: [alternate] }),
      /routing.*header|forbidden/i,
      name,
    )
  }
})

test('OOB session binding accepts only canonical DNS hostnames', () => {
  const aggressiveScope = scope()
  aggressiveScope.authorization.permissions.intensity = 'aggressive'
  const common = {
    scope: aggressiveScope,
    classes: ['ssrf-oob'],
  }
  for (const server of [
    'oob.example@169.254.169.254',
    '127.0.0.1',
    'localhost',
    'oob.example.test:443',
    'oob.example.test/path',
  ]) {
    assert.throws(
      () => plan({
        ...common,
        oobBinding: {
          backend: 'self_hosted',
          server,
          correlation_id: 'a'.repeat(20),
          created_at: '2026-08-21T11:00:00.000Z',
        },
      }),
      /canonical DNS hostname/i,
    )
  }
})
