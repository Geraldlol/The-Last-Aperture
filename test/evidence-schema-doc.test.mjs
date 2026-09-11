import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const SCHEMA_DOC = 'skills/last-aperture/lenses/_schema.md'

function doc() {
  return readFileSync(SCHEMA_DOC, 'utf8')
}

test('invariant 16 is stated and numbered', () => {
  const text = doc()
  const invariant = /^16\. (.+?)(?=\n\n|\n\d{1,2}\. |\n---)/ms.exec(text)
  assert.ok(invariant, 'invariant 16 must exist')
  const body = invariant[1]
  assert.match(body, /evidence_context/)
  assert.match(body, /consumed/)
  assert.match(body, /may_conclude/)
  assert.match(body, /higher-precedence/)
  assert.match(body, /NOT_ASSESSED/)
  assert.match(body, /INVENTORY_ONLY/)
  assert.match(body, /UNPROVEN/)
  assert.match(body, /Medium/)
})

test('invariant 15 is untouched and 17 does not exist', () => {
  const text = doc()
  assert.match(text, /^15\. A record with `lens: database-and-data-stores`/m)
  assert.equal(/^17\. /m.test(text), false)
})

test('the Stage 1 table declares evidence_context and evidence_claim', () => {
  const text = doc()
  assert.match(text, /^\| `evidence_context` \| object \|/m)
  assert.match(text, /^\| `evidence_claim` \|/m)
})

test('the location section documents the evidence-qualified form', () => {
  const text = doc()
  assert.match(text, /peerstar-api-image:layer\/02\//)
  assert.match(text, /prod-cluster:v1\/Namespace\//)
})

test('the three existence_check outcomes carry over unchanged', () => {
  const text = doc()
  const section = text.slice(text.indexOf('### Evidence-qualified `location`'))
  assert.match(section, /NOT_REPRODUCED/)
  assert.match(section, /DISPROVED/)
})

test('every evidence_context field named in the doc matches the schema', () => {
  const schema = JSON.parse(readFileSync('schemas/finding.schema.json', 'utf8'))
  const required = schema.$defs.evidenceContext.required
  const text = doc()
  const block = text.slice(text.indexOf('### Evidence context'))
  for (const field of required) {
    assert.ok(block.includes(field), `_schema.md must document ${field}`)
  }
})
