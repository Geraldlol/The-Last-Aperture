import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  assertNoSecretLeak,
  buildReproCurl,
  credentialPlaceholder,
  reproPreamble,
  shellQuote,
} from '../scripts/lib/bounty-report-curl.mjs'
import {
  REPORTABLE_VERDICTS,
  explainUnreportable,
  isReportable,
  renderAuthzReport,
} from '../scripts/lib/bounty-report.mjs'

const ALICE = { id: 'alice', label: 'owner', auth: { kind: 'header', name: 'authorization', value_env: 'TB_ALICE' } }
const BOB = { id: 'bob', label: 'second account', auth: { kind: 'cookie', name: 'session', value_env: 'TB_BOB' } }
const ANON = { id: 'anonymous', label: 'unauthenticated', auth: { kind: 'none' } }

const SECRET = 'Bearer super-secret-token-value'

function request(overrides = {}) {
  return {
    method: 'GET',
    url: 'https://api.acme.example/api/orders/2',
    headers: {
      accept: 'application/json',
      'content-type': 'application/json',
      authorization: SECRET,
      cookie: 'session=also-secret',
      'user-agent': 'Mozilla/5.0 (very long and pointless)',
    },
    body: null,
    ...overrides,
  }
}

function scope() {
  return {
    platform: 'yeswehack',
    engagement_id: 'ywh-acme-2026-08',
    program: { program_handle: 'acme-public', policy_snapshot_sha256: 'a'.repeat(64) },
    validity: { not_before: '2026-08-21T00:00:00.000Z', not_after: '2026-11-21T00:00:00.000Z' },
  }
}

function result(overrides = {}) {
  return {
    url: 'https://api.acme.example/api/orders/2',
    method: 'GET',
    owner_role: 'alice',
    tester_role: 'bob',
    owner_status: 200,
    tester_status: 200,
    verdict: 'AUTHZ_BYPASS_CANDIDATE',
    confidence: 'high',
    rationale: 'bob received 200 byte-equivalent to the owner after normalization',
    baseline_stable: true,
    ...overrides,
  }
}

const render = (overrides = {}, roles = { ownerRole: ALICE, testerRole: BOB }) => renderAuthzReport({
  result: result(overrides),
  scope: scope(),
  request: request(),
  generatedAt: '2026-08-21T12:00:00.000Z',
  ...roles,
})

test('shellQuote survives embedded single quotes', () => {
  assert.equal(shellQuote("it's"), `'it'\\''s'`)
  assert.equal(shellQuote('plain'), `'plain'`)
})

test('credentials appear as variable references, never values', () => {
  assert.equal(credentialPlaceholder(ALICE), '$TB_ALICE')
  assert.equal(credentialPlaceholder(BOB), '$TB_BOB')
  assert.equal(credentialPlaceholder(ANON), null)
})

test('the repro curl carries no secret and no header noise', () => {
  const curl = buildReproCurl({ request: request(), role: ALICE })
  assert.equal(curl.includes(SECRET), false, 'the token must not appear')
  assert.equal(curl.includes('also-secret'), false, 'the cookie must not appear')
  assert.equal(curl.includes('Mozilla'), false, 'browser noise is not reproduction detail')
  assert.match(curl, /\$TB_ALICE/)
  assert.match(curl, /content-type: application\/json/)
  assert.match(curl, /https:\/\/api\.acme\.example\/api\/orders\/2/)
})

test('a cookie role reproduces as a Cookie header with the variable', () => {
  const curl = buildReproCurl({ request: request(), role: BOB })
  assert.match(curl, /-H "Cookie: session=\$TB_BOB"/)
})

test('the anonymous role sends no credential header at all', () => {
  const curl = buildReproCurl({ request: request(), role: ANON })
  assert.equal(/-H "(Authorization|Cookie)/i.test(curl), false)
})

test('a body is included for mutating methods and omitted for GET', () => {
  const post = buildReproCurl({
    request: request({ method: 'POST', body: '{"a":1}' }), role: ALICE,
  })
  assert.match(post, /--data-raw '\{"a":1\}'/)
  const get = buildReproCurl({ request: request({ body: '{"a":1}' }), role: ALICE })
  assert.equal(get.includes('--data-raw'), false)
})

test('the preamble names the variables the reader must set', () => {
  const preamble = reproPreamble([ALICE, BOB, ANON])
  assert.match(preamble, /export TB_ALICE=/)
  assert.match(preamble, /export TB_BOB=/)
  assert.match(preamble, /intentionally absent/)
})

test('assertNoSecretLeak throws on a leak and passes clean text', () => {
  assert.throws(() => assertNoSecretLeak(`x ${SECRET} y`, [SECRET]), /credential value/)
  assert.doesNotThrow(() => assertNoSecretLeak('clean', [SECRET]))
  assert.doesNotThrow(() => assertNoSecretLeak('clean', ['', null, undefined]))
})

test('only a bypass candidate is reportable', () => {
  assert.deepEqual(REPORTABLE_VERDICTS, ['AUTHZ_BYPASS_CANDIDATE'])
  assert.equal(isReportable(result()), true)
  for (const verdict of [
    'UNPROVEN_VOLATILE', 'ACCESS_DENIED', 'NOT_FOUND',
    'DIFFERENT_CONTENT', 'SERVER_ERROR', 'REPLAY_FAILED', 'ABSENT_PROBE',
  ]) {
    assert.equal(isReportable(result({ verdict })), false, verdict)
    assert.ok(explainUnreportable(result({ verdict })).length > 10, verdict)
  }
})

test('drafting refuses an unreportable verdict and says why', () => {
  // Submitting these is exactly how a researcher's signal gets destroyed.
  assert.throws(() => render({ verdict: 'UNPROVEN_VOLATILE' }), /not reproducible/)
  assert.throws(() => render({ verdict: 'DIFFERENT_CONTENT' }), /correct behaviour/)
  assert.throws(() => render({ verdict: 'ACCESS_DENIED' }), /correctly refused/)
})

test('the rendered report contains no credential value anywhere', () => {
  const report = render()
  assert.doesNotThrow(() => assertNoSecretLeak(report, [SECRET, 'also-secret', 'super-secret-token-value']))
  assert.equal(report.includes('Bearer super-secret'), false)
})

test('the report carries the sections a triager looks for', () => {
  const report = render()
  for (const heading of [
    '## Summary', '## Impact', '## Evidence', '## Steps to reproduce',
    '## Remediation', '## Testing scope and authorisation',
  ]) {
    assert.ok(report.includes(heading), heading)
  }
})

test('severity is presented as a suggestion needing review, not a verdict', () => {
  const report = render()
  assert.match(report, /Severity \(suggested\)/)
  assert.match(report, /has not\n> been reviewed/)
  assert.match(report, /CVSS:3\.1\//)
})

test('an anonymous finding is scored and worded more severely', () => {
  const anon = render({ tester_role: 'anonymous' }, { ownerRole: ALICE, testerRole: ANON })
  assert.match(anon, /Unauthenticated access/)
  assert.match(anon, /High 7\.5/)
  assert.match(anon, /No credential is required/)
  const authed = render()
  assert.match(authed, /Medium 6\.5/)
})

test('the report states the authorisation it was collected under', () => {
  const report = render()
  assert.match(report, /yeswehack program `acme-public`/)
  assert.match(report, /Program policy digest/)
  assert.match(report, /2026-08-21T00:00:00\.000Z to 2026-11-21T00:00:00\.000Z/)
  assert.match(report, /researcher-controlled test accounts/)
})

test('the report says it was not submitted automatically', () => {
  assert.match(render(), /Not submitted automatically; review before sending/)
})

test('an identifier substitution is disclosed in the title and evidence', () => {
  const report = render({ mutation: 'query:order order-alice -> order-bob' })
  assert.match(report, /via object identifier substitution/)
  assert.match(report, /Identifier substitution/)
})

test('the remediation names the existence-oracle trap', () => {
  assert.match(render(), /existence oracle/)
})
