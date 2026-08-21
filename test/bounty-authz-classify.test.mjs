import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  AUTHZ_VERDICTS,
  calibrateBaseline,
  classifyAuthzOutcome,
  summarizeMatrix,
} from '../scripts/lib/bounty-authz-classify.mjs'
import { normalizeResponse } from '../scripts/lib/bounty-authz-normalize.mjs'

const JSON_TYPE = 'application/json'

function reply(body, status = 200) {
  return {
    status,
    error: null,
    normalized: normalizeResponse({ status, headers: { 'content-type': JSON_TYPE }, body, contentType: JSON_TYPE }),
  }
}

const failed = (message) => ({ status: null, error: message, normalized: null })
const bob = { id: 'bob' }

test('a reproducible owner baseline is stable', () => {
  const baseline = calibrateBaseline({ first: reply('{"order":2}'), second: reply('{"order":2}') })
  assert.equal(baseline.stable, true)
  assert.equal(baseline.reason, 'baseline-reproducible')
  assert.ok(baseline.digest)
})

test('an owner baseline that differs only in a uuid is still stable', () => {
  const baseline = calibrateBaseline({
    first: reply('{"order":2,"trace":"11111111-2222-3333-4444-555555555555"}'),
    second: reply('{"order":2,"trace":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}'),
  })
  assert.equal(baseline.stable, true, 'normalization absorbed the noise')
})

test('a genuinely volatile endpoint is unstable', () => {
  const baseline = calibrateBaseline({ first: reply('{"n":1}'), second: reply('{"n":2}') })
  assert.equal(baseline.stable, false)
  assert.equal(baseline.reason, 'baseline-body-differs')
})

test('a baseline whose statuses differ is unstable', () => {
  const baseline = calibrateBaseline({ first: reply('{}', 200), second: reply('{}', 500) })
  assert.equal(baseline.stable, false)
  assert.equal(baseline.reason, 'baseline-status-differs')
})

test('a baseline replay failure is unstable, not silently stable', () => {
  const baseline = calibrateBaseline({ first: failed('ECONNRESET'), second: reply('{}') })
  assert.equal(baseline.stable, false)
  assert.equal(baseline.reason, 'baseline-replay-failed')
})

test('stable baseline plus a matching tester is a bypass candidate', () => {
  const baseline = calibrateBaseline({ first: reply('{"order":2,"owner":"alice"}'), second: reply('{"order":2,"owner":"alice"}') })
  const result = classifyAuthzOutcome({
    baseline, testerResponse: reply('{"order":2,"owner":"alice"}'), testerRole: bob,
  })
  assert.equal(result.verdict, 'AUTHZ_BYPASS_CANDIDATE')
  assert.equal(result.confidence, 'high')
  assert.match(result.rationale, /bob/)
  assert.match(result.rationale, /reproducible/)
})

test('an unstable baseline downgrades a match to unproven, never a candidate', () => {
  // The endpoint that would otherwise generate a flood of false positives.
  const baseline = calibrateBaseline({ first: reply('{"n":1}'), second: reply('{"n":2}') })
  const result = classifyAuthzOutcome({ baseline, testerResponse: reply('{"n":1}'), testerRole: bob })
  assert.equal(result.verdict, 'UNPROVEN_VOLATILE')
  assert.equal(result.confidence, 'low')
  assert.match(result.rationale, /support a claim/)
})

test('an unstable baseline also downgrades a NON-match, not just a match', () => {
  // Caught by the ground-truth testbed: checking the content match before the
  // baseline reported confident per-role scoping on an endpoint that simply
  // changes every call. Instability poisons the comparison in both directions.
  const baseline = calibrateBaseline({ first: reply('{"n":1}'), second: reply('{"n":2}') })
  const result = classifyAuthzOutcome({ baseline, testerResponse: reply('{"n":3}'), testerRole: bob })
  assert.equal(result.verdict, 'UNPROVEN_VOLATILE')
  assert.notEqual(result.verdict, 'DIFFERENT_CONTENT')
})

test('a status verdict survives an unstable baseline', () => {
  // 403 means the same thing whether or not the body is reproducible.
  const baseline = calibrateBaseline({ first: reply('{"n":1}'), second: reply('{"n":2}') })
  const result = classifyAuthzOutcome({ baseline, testerResponse: reply('{}', 403), testerRole: bob })
  assert.equal(result.verdict, 'ACCESS_DENIED')
})

test('401 and 403 classify as access denied', () => {
  const baseline = calibrateBaseline({ first: reply('{"a":1}'), second: reply('{"a":1}') })
  for (const status of [401, 403]) {
    const result = classifyAuthzOutcome({ baseline, testerResponse: reply('{}', status), testerRole: bob })
    assert.equal(result.verdict, 'ACCESS_DENIED', String(status))
  }
})

test('404 classifies as not found at low confidence', () => {
  const baseline = calibrateBaseline({ first: reply('{"a":1}'), second: reply('{"a":1}') })
  const result = classifyAuthzOutcome({ baseline, testerResponse: reply('{}', 404), testerRole: bob })
  assert.equal(result.verdict, 'NOT_FOUND')
  assert.equal(result.confidence, 'low')
})

test('5xx classifies as server error', () => {
  const baseline = calibrateBaseline({ first: reply('{"a":1}'), second: reply('{"a":1}') })
  const result = classifyAuthzOutcome({ baseline, testerResponse: reply('boom', 500), testerRole: bob })
  assert.equal(result.verdict, 'SERVER_ERROR')
})

test('a 200 with different content is NOT a finding', () => {
  // /api/me: bob correctly receives bob's own profile. Treating this as a leak is
  // the single most common authz-grinder false positive.
  const baseline = calibrateBaseline({
    first: reply('{"me":"alice"}'), second: reply('{"me":"alice"}'),
  })
  const result = classifyAuthzOutcome({ baseline, testerResponse: reply('{"me":"bob"}'), testerRole: bob })
  assert.equal(result.verdict, 'DIFFERENT_CONTENT')
  assert.notEqual(result.verdict, 'AUTHZ_BYPASS_CANDIDATE')
})

test('a transport failure classifies as replay failed', () => {
  const baseline = calibrateBaseline({ first: reply('{"a":1}'), second: reply('{"a":1}') })
  const result = classifyAuthzOutcome({ baseline, testerResponse: failed('ETIMEDOUT'), testerRole: bob })
  assert.equal(result.verdict, 'REPLAY_FAILED')
  assert.equal(result.confidence, 'none')
})

test('no verdict claims a vulnerability or a clearance', () => {
  // "PASS" is deliberately absent from this list: AUTHZ_BYPASS_CANDIDATE
  // contains it as a substring of "BYPASS", which is not an overclaim.
  const overclaims = /VULNERABLE|EXPLOITED|CONFIRMED|PROVEN(?!_)|SECURE|SAFE|CLEAN|COMPLIANT/
  for (const verdict of AUTHZ_VERDICTS) {
    assert.equal(overclaims.test(verdict), false, verdict)
  }
  // The strongest available verdict is explicitly a candidate, not a finding.
  assert.ok(AUTHZ_VERDICTS.includes('AUTHZ_BYPASS_CANDIDATE'))
  assert.equal(AUTHZ_VERDICTS.some((v) => v.includes('CANDIDATE')), true)
  assert.ok(AUTHZ_VERDICTS.includes('UNPROVEN_VOLATILE'))
})

test('the summary reports candidates and unproven separately', () => {
  const summary = summarizeMatrix([
    { verdict: 'AUTHZ_BYPASS_CANDIDATE' },
    { verdict: 'UNPROVEN_VOLATILE' },
    { verdict: 'UNPROVEN_VOLATILE' },
    { verdict: 'ACCESS_DENIED' },
    { verdict: 'DIFFERENT_CONTENT' },
  ])
  assert.equal(summary.total, 5)
  assert.equal(summary.candidates, 1)
  assert.equal(summary.unproven, 2)
  assert.equal(summary.byVerdict.ACCESS_DENIED, 1)
  assert.notEqual(summary.candidates, summary.candidates + summary.unproven)
})
