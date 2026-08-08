import { test } from 'node:test'
import assert from 'node:assert/strict'
import { validateFinding, assertValidFindingTransition } from '../scripts/lib/contracts.mjs'

function stageOne(overrides = {}) {
  return {
    candidate_id: 'authz-object-level:a3f19c2e',
    lens: 'web-and-api',
    topic: 'authz-object-level',
    title: 'Invoice route loads another tenant by identifier',
    claimed_impact_severity: 'High',
    location: ['src/routes/invoices.ts:88'],
    cwe: 'CWE-639',
    evidence: 'const invoice = await repo.findById(req.params.id)',
    attack: 'GET /api/invoices/8814 while authenticated to another tenant',
    impact: 'Reads another tenant invoice and billing address',
    reachable_from: 'GET /api/invoices/:id',
    confidence: 'High',
    proof_plan: 'Request subject A invoice as subject B and assert refusal',
    ...overrides,
  }
}

test('a finding may carry quotes', () => {
  const { errors } = validateFinding(stageOne({
    quotes: [{
      path: 'src/routes/invoices.ts',
      line: 88,
      text: 'const invoice = await repo.findById(req.params.id)',
    }],
  }))
  assert.deepEqual(errors, [])
})

test('a finding may carry absence claims', () => {
  const { errors } = validateFinding(stageOne({
    absence_claims: [{
      pattern: 'constantTimeEquals',
      kind: 'literal',
      scope: ['src/routes'],
    }],
  }))
  assert.deepEqual(errors, [])
})

test('a quote line must be a positive integer', () => {
  const { errors } = validateFinding(stageOne({
    quotes: [{ path: 'src/routes/invoices.ts', line: 0, text: 'x' }],
  }))
  assert.ok(errors.length > 0)
})

test('an absence claim rejects an empty scope', () => {
  const { errors } = validateFinding(stageOne({
    absence_claims: [{ pattern: 'x', kind: 'literal', scope: [] }],
  }))
  assert.ok(errors.length > 0)
})

test('an absence claim rejects a regex kind', () => {
  const { errors } = validateFinding(stageOne({
    absence_claims: [{ pattern: 'x', kind: 'regex', scope: ['src'] }],
  }))
  assert.ok(errors.length > 0)
})

test('quotes cannot change across a transition', () => {
  const before = stageOne({
    quotes: [{ path: 'src/routes/invoices.ts', line: 88, text: 'a' }],
  })
  const after = structuredClone(before)
  after.quotes[0].text = 'b'
  assert.throws(() => assertValidFindingTransition(before, after), /immutable/i)
})
