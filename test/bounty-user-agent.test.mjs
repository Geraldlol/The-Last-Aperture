import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import {
  BOUNTY_SCOPE_SCHEMA_VERSION,
  assertValidBountyScope,
} from '../scripts/lib/bounty-contracts.mjs'
import { createProgramSealedScope } from '../scripts/lib/bounty-planner.mjs'
import { gateCandidates } from '../scripts/lib/bounty-recon-gate.mjs'
import { probeHost } from '../scripts/lib/bounty-recon-probe.mjs'
import { composeUserAgent, replayAsRole } from '../scripts/lib/bounty-authz-replay.mjs'
import { ANONYMOUS_ROLE } from '../scripts/lib/bounty-authz-roles.mjs'

// Some bounty programs mandate an identifying User-Agent (for example,
// BugBounty-Example). Sending traffic without it is how a hunter gets
// treated as an unidentified scanner and has findings voided, so the marker is
// sealed with the perimeter rather than chosen per call.
function validScope() {
  return {
    schema_version: BOUNTY_SCOPE_SCHEMA_VERSION,
    kind: 'red-team-audit/bounty-scope',
    engagement_id: 'example-program-2026-08',
    platform: 'direct',
    environment: 'production',
    data_class: 'non_phi',
    program: {
      program_handle: 'example-web-applications',
      policy_url: 'https://bounty.example.test/programs/example-web-applications',
      policy_snapshot_sha256: 'a'.repeat(64),
      required_user_agent: 'BugBounty-Example',
    },
    authorization: {
      mode: 'PROGRAM_POLICY_SEALED',
      authorization_id: 'auth-001',
      statement: 'Operator declares enrollment in the named bounty program.',
      operator_id: 'operator-1',
      authorized_by: 'Example Corp program policy',
      authorization_reference: 'https://bounty.example.test/programs/example-web-applications',
      attested_at: '2026-08-20T12:00:00.000Z',
      independently_verified: false,
      permissions: {
        active_testing: true,
        production: true,
        third_party: false,
        phi: false,
        mutation: false,
        automation_allowed: true,
        intensity: 'normal',
        desync_probes: false,
        rate_limit_rps: 5,
      },
    },
    validity: { not_before: '2026-08-20T00:00:00.000Z', not_after: '2026-11-20T00:00:00.000Z' },
    scope_rules: {
      allow: [{ rule_id: 'a1', host_kind: 'wildcard', host: 'example.test' }],
      deny: [],
    },
    stop_conditions: { max_findings: 100, operator_stop: false },
  }
}

test('accepts a scope carrying the program mandated user agent', () => {
  assert.doesNotThrow(() => assertValidBountyScope(validScope()))
})

test('refuses a scope with no required user agent', () => {
  const scope = validScope()
  delete scope.program.required_user_agent
  assert.throws(() => assertValidBountyScope(scope), /required_user_agent/)
})

test('refuses an empty required user agent', () => {
  const scope = validScope()
  scope.program.required_user_agent = ''
  assert.throws(() => assertValidBountyScope(scope), /required_user_agent/)
})

// A sealed UA is written straight into a request header. A value carrying CR or
// LF would smuggle a second header past the kernel, which checks hosts, not bytes.
test('refuses a required user agent carrying a header injection', () => {
  const hostile = [
    'BugBounty-Example\r\nX-Injected: 1',
    'BugBounty-Example\nX-Injected: 1',
    'BugBounty-Example\r',
    'BugBounty-Example\t',
    'BugBounty-Example ',
  ]
  for (const value of hostile) {
    const scope = validScope()
    scope.program.required_user_agent = value
    assert.throws(
      () => assertValidBountyScope(scope),
      /required_user_agent/,
      `expected refusal for ${JSON.stringify(value)}`,
    )
  }
})

test('accepts representative user agent shapes that programs may mandate', () => {
  for (const ua of [
    'BugBounty-Example',
    'ExampleProgram/BB',
    '-BugBounty-example-1-31338',
    'BBC-Example-Bugbounty-<pseudo>',
    'ExampleOrg-Bugbounty',
    'Bug-Bounty-Hunter-#ExampleUserName#',
  ]) {
    const scope = validScope()
    scope.program.required_user_agent = ua
    assert.doesNotThrow(() => assertValidBountyScope(scope), `expected ${ua} to seal`)
  }
})

// --- the planner must seal the marker, never invent one ---

function plannerOptions(overrides = {}) {
  return {
    engagementId: 'example-program-2026-08',
    platform: 'direct',
    programHandle: 'example-web-applications',
    policyUrl: 'https://bounty.example.test/programs/example-web-applications',
    policySnapshotBytes: Buffer.from('Example program policy. UA: BugBounty-Example\n'),
    operatorId: 'operator-1',
    authorizedBy: 'Example Corp program policy',
    requiredUserAgent: 'BugBounty-Example',
    allowSpecs: ['*.example.test'],
    denySpecs: [],
    permissions: {
      active_testing: true,
      production: true,
      third_party: false,
      phi: false,
      mutation: false,
      automation_allowed: true,
      intensity: 'normal',
      desync_probes: false,
      rate_limit_rps: 5,
    },
    validity: { notBefore: '2026-08-20T00:00:00.000Z', notAfter: '2026-11-20T00:00:00.000Z' },
    now: new Date('2026-08-21T00:00:00.000Z'),
    ...overrides,
  }
}

test('seals the program mandated user agent into the scope', () => {
  const scope = createProgramSealedScope(plannerOptions())
  assert.equal(scope.program.required_user_agent, 'BugBounty-Example')
  assert.doesNotThrow(() => assertValidBountyScope(scope))
})

// Defaulting to our own tool string would send unidentified traffic under a
// perimeter that claims to be identified. An absent marker is an unsealed
// field, so it fails closed like every other one.
test('refuses to seal a scope when no user agent is declared', () => {
  assert.throws(
    () => createProgramSealedScope(plannerOptions({ requiredUserAgent: undefined })),
    /user agent/i,
  )
})

test('refuses a declared user agent that could inject a header', () => {
  assert.throws(
    () => createProgramSealedScope(plannerOptions({ requiredUserAgent: 'X\r\nY: 1' })),
    /user agent/i,
  )
})

// --- the marker must reach the wire ---

function scopeWithUserAgent(ua) {
  return {
    program: ua === undefined ? {} : { required_user_agent: ua },
    scope_rules: {
      allow: [{ rule_id: 'a1', host_kind: 'wildcard', host: 'example.test' }],
      deny: [],
    },
  }
}

const countingLimiter = () => ({ acquire: async () => {} })

test('gating carries the sealed user agent onto every approval', () => {
  const { approved } = gateCandidates({
    sealedScope: scopeWithUserAgent('BugBounty-Example'),
    candidates: [{ kind: 'host', value: 'shop.example.test' }, { kind: 'host', value: 'api.example.test' }],
  })
  assert.equal(approved.length, 2)
  for (const approval of approved) {
    assert.equal(approval.userAgent, 'BugBounty-Example')
  }
})

// gateCandidates is the only route to a socket, so it is the right chokepoint.
// It refuses rather than throws, matching how it already reports a scope it
// cannot use, and approving nothing is what keeps an unmarked probe impossible.
test('gating approves nothing when the scope seals no user agent', () => {
  const { approved, refused } = gateCandidates({
    sealedScope: scopeWithUserAgent(undefined),
    candidates: [{ kind: 'host', value: 'shop.example.test' }],
  })
  assert.equal(approved.length, 0)
  assert.equal(refused[0].reason, 'sealed-scope-user-agent-missing')
})

test('a probe sends the sealed user agent rather than a tool default', async () => {
  const { approved } = gateCandidates({
    sealedScope: scopeWithUserAgent('BugBounty-Example'),
    candidates: [{ kind: 'host', value: 'shop.example.test' }],
  })
  let seen = null
  await probeHost({
    approval: approved[0],
    limiter: countingLimiter(),
    fetchImpl: async (url, init) => {
      seen = init.headers
      return new Response('', { status: 200, headers: { 'content-type': 'text/plain' } })
    },
  })
  assert.equal(seen['User-Agent'], 'BugBounty-Example')
  assert.equal(
    JSON.stringify(seen).includes('red-team-audit-bounty-recon'),
    false,
    'the hardcoded tool default must not reach the wire',
  )
})

test('a probe refuses an approval carrying no user agent', async () => {
  await assert.rejects(
    () => probeHost({
      approval: { __scopeApproved: true, host: 'shop.example.test', port: 443, url: 'https://shop.example.test/', ruleId: 'a1' },
      limiter: countingLimiter(),
      fetchImpl: async () => new Response(''),
    }),
    /user agent/i,
  )
})

// --- the replay path is the highest-volume egress, so it must be marked too ---

// Replaces the single "overrides" test. The marker is APPENDED to the captured
// browser User-Agent rather than replacing it: the program mandates the marker so
// its logs can attribute the traffic, but a bare marker is not a browser and the
// site's bot protection answered one with a 403. Appending satisfies both -- the
// request still looks like the session it was captured from, and the marker is
// plainly there for anyone reading the logs. It is one header value, not two
// headers, so the request stays unambiguous.

async function replayWith(capturedHeaders, marker = 'BugBounty-Example') {
  let seen = null
  const result = await replayAsRole({
    request: {
      method: 'GET',
      url: 'https://shop.example.test/orders/2',
      headers: capturedHeaders,
      body: null,
    },
    role: ANONYMOUS_ROLE,
    sealedScope: scopeWithUserAgent(marker),
    limiter: countingLimiter(),
    fetchImpl: async (url, init) => {
      seen = init.headers
      return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })
    },
  })
  const names = Object.keys(seen).filter((n) => n.toLowerCase() === 'user-agent')
  assert.equal(names.length, 1, 'exactly one user-agent header may be sent')
  return { status: result.status, userAgent: seen[names[0]] }
}

test('a replay appends the marker to the captured browser user agent', async () => {
  const { status, userAgent } = await replayWith({
    accept: 'application/json',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
  })
  assert.equal(status, 200)
  assert.equal(userAgent, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) BugBounty-Example')
})

test('a replay sends the marker alone when the capture carried no user agent', async () => {
  const { userAgent } = await replayWith({ accept: 'application/json' })
  assert.equal(userAgent, 'BugBounty-Example')
})

// A capture taken through our own proxy already carries the marker. Appending a
// second copy would make the string drift a little further on every pass.
test('a replay does not append the marker twice', async () => {
  const { userAgent } = await replayWith({
    accept: 'application/json',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) BugBounty-Example',
  })
  assert.equal(userAgent, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) BugBounty-Example')
})

// The gate refuses rather than throws, so an unmarked scope surfaces as an
// out-of-scope replay result and no socket is opened.
test('a replay reaches no socket when the scope seals no marker', async () => {
  let called = false
  const result = await replayAsRole({
    request: { method: 'GET', url: 'https://shop.example.test/orders/2', headers: {}, body: null },
    role: ANONYMOUS_ROLE,
    sealedScope: scopeWithUserAgent(undefined),
    limiter: countingLimiter(),
    fetchImpl: async () => { called = true; return new Response('') },
  })
  assert.equal(called, false, 'no request may be sent without the marker')
  assert.equal(result.status, null)
  assert.equal(result.refusal.reason, 'sealed-scope-user-agent-missing')
})

// The marker is enforced on three egress paths in two languages. The shared
// oracle is what keeps them from drifting: this asserts the Node side against
// it, and proxy/conformance.py asserts the Python side against the same file.
test('user-agent composition matches the shared cross-language oracle', () => {
  const suite = JSON.parse(
    readFileSync(new URL('../fixtures/bounty/user-agent-cases.json', import.meta.url), 'utf8'),
  )
  assert.ok(suite.cases.length >= 16, 'the shared fixture suite was loaded')
  for (const { case_id: caseId, captured, marker, expect } of suite.cases) {
    assert.equal(
      composeUserAgent(captured, marker),
      expect,
      `${caseId}: node must reproduce the shared oracle`,
    )
  }
})

// The defect the boundary rule exists to prevent, stated as its own regression:
// a marker that is a substring of a product token must still be appended, or
// the request goes out unmarked while the code believes it is marked.
test('a marker inside a larger token is still appended', () => {
  assert.equal(composeUserAgent('curl/8.4.0', 'curl'), 'curl/8.4.0 curl')
  assert.equal(composeUserAgent('Mozilla/5.0', 'M'), 'Mozilla/5.0 M')
  assert.equal(composeUserAgent('BugBounty-Example', 'Example'), 'BugBounty-Example Example')
  // ...while a real bounded token is still recognized and not duplicated.
  assert.equal(composeUserAgent('Exampleized Example', 'Example'), 'Exampleized Example')
})
