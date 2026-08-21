import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  cvssBaseScore,
  cvssRoundUp,
  cvssSeverityBand,
  cvssVectorString,
  suggestAuthzVector,
} from '../scripts/lib/bounty-report-cvss.mjs'

function parse(vector) {
  const metrics = {}
  for (const part of vector.replace(/^CVSS:3\.1\//, '').split('/')) {
    const [key, value] = part.split(':')
    metrics[key] = value
  }
  return metrics
}

// Published CVSS v3.1 reference vectors. If the arithmetic here is wrong these
// are what catch it -- my own worked examples would only confirm my own mistake.
const REFERENCE = [
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 7.5],
  ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', 6.5],
  // The canonical reflected-XSS vector is S:C, and 6.1 is its score. The S:U
  // variant of the same metrics is 5.4; both branches are asserted because the
  // scope flag changes the Impact formula and the PR weighting, not just a
  // multiplier.
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1],
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N', 5.4],
  ['CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 7.8],
  ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N', 5.9],
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0],
  ['CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N', 1.6],
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0.0],
  ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N', 7.7],
]

for (const [vector, expected] of REFERENCE) {
  test(`reference vector ${vector} scores ${expected}`, () => {
    assert.equal(cvssBaseScore(parse(vector)), expected)
  })
}

test('roundUp matches the specification definition', () => {
  assert.equal(cvssRoundUp(4.0), 4.0)
  assert.equal(cvssRoundUp(4.02), 4.1)
  assert.equal(cvssRoundUp(6.5), 6.5)
  assert.equal(cvssRoundUp(0), 0)
})

test('vector strings round trip in canonical metric order', () => {
  const metrics = parse('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N')
  assert.equal(cvssVectorString(metrics), 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N')
})

test('severity bands follow the specification ranges', () => {
  assert.equal(cvssSeverityBand(0), 'None')
  assert.equal(cvssSeverityBand(3.9), 'Low')
  assert.equal(cvssSeverityBand(4.0), 'Medium')
  assert.equal(cvssSeverityBand(6.9), 'Medium')
  assert.equal(cvssSeverityBand(7.0), 'High')
  assert.equal(cvssSeverityBand(8.9), 'High')
  assert.equal(cvssSeverityBand(9.0), 'Critical')
  assert.equal(cvssSeverityBand(10), 'Critical')
})

test('an unknown metric value throws rather than scoring silently', () => {
  assert.throws(() => cvssBaseScore(parse('CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N')), /AV/)
  assert.throws(() => cvssBaseScore(parse('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:Q/C:H/I:N/A:N')), /S/)
})

test('an anonymous bypass suggests PR:N and scores higher than an authenticated one', () => {
  const anon = suggestAuthzVector({ testerRole: 'anonymous', method: 'GET', ownerStatus: 200 })
  const authed = suggestAuthzVector({ testerRole: 'bob', method: 'GET', ownerStatus: 200 })
  assert.equal(anon.metrics.PR, 'N')
  assert.equal(authed.metrics.PR, 'L')
  assert.equal(anon.score, 7.5)
  assert.equal(authed.score, 6.5)
  assert.ok(anon.score > authed.score)
})

test('the suggested vector never claims integrity on response comparison alone', () => {
  // The grinder compared responses; it did not prove a write landed. Claiming
  // I:H here would be inventing evidence.
  for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']) {
    const suggestion = suggestAuthzVector({ testerRole: 'bob', method, ownerStatus: 200 })
    assert.equal(suggestion.metrics.I, 'N', method)
  }
})

test('a mutating method raises a caveat instead of raising the score', () => {
  const get = suggestAuthzVector({ testerRole: 'bob', method: 'GET', ownerStatus: 200 })
  const post = suggestAuthzVector({ testerRole: 'bob', method: 'POST', ownerStatus: 200 })
  assert.equal(get.caveats.length, 0)
  assert.equal(post.caveats.length, 1)
  assert.match(post.caveats[0], /verify the write actually occurred/)
  assert.equal(get.score, post.score, 'the caveat informs the operator, it does not inflate the number')
})

test('every suggestion is marked as requiring operator review', () => {
  const suggestion = suggestAuthzVector({ testerRole: 'bob', method: 'GET', ownerStatus: 200 })
  assert.equal(suggestion.assessment, 'SUGGESTED_REQUIRES_OPERATOR_REVIEW')
  assert.equal(suggestion.rationale.length, 8, 'one stated reason per metric')
})
