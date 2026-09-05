import { test } from 'node:test'
import assert from 'node:assert/strict'
import { compareRuns } from '../scripts/lib/lifecycle.mjs'

function crossCuttingFinding() {
  return {
    candidate_id: 'cand:ai-review:001',
    lens: 'ai-generated-code',
    topic: 'authz-object-level',
    raised_by: 'ai-generated-code',
    title: 'Generated handler pattern bypasses tenant ownership',
    claimed_impact_severity: 'High',
    location: ['src/orders.js:42'],
    evidence: 'approveOrder(req.params.id) does not bind the tenant',
    attack: 'Approve another tenant order by identifier.',
    impact: 'A tenant can change another tenant order state.',
    reachable_from: 'POST /orders/:id/approve',
    confidence: 'High',
    proof_plan: 'Use two tenants and approve tenant B data as tenant A.',
  }
}

function lensJob(lens, lensDigest, ownedTopics, state = 'SUCCEEDED') {
  return {
    job_id: `lens:${lens}`,
    kind: 'LENS',
    lens,
    lens_digest: lensDigest,
    owned_topics: ownedTopics,
    state,
    ...(state === 'SUCCEEDED'
      ? { coverage_authority: 'PROVIDER_DECLARED' }
      : { reason: 'lens activation matched no repository input' }),
  }
}

function lifecycleRun(overrides = {}) {
  return {
    run_id: 'run:ai-review:baseline',
    state: 'COMPLETED',
    capability_mode: 'STATIC',
    repository: {
      root: 'C:\\repo',
      tree_digest: 'a'.repeat(64),
    },
    coverage: {
      inventory: ['src/orders.js'],
      examined: ['src/orders.js'],
      unexamined: [],
      lenses: [{
        lens: 'ai-generated-code',
        status: 'RAN',
        examined_paths: ['src/orders.js'],
      }],
      gaps: [],
    },
    findings: [crossCuttingFinding()],
    jobs: [
      lensJob('ai-generated-code', '1'.repeat(64), []),
      lensJob('web-and-api', '2'.repeat(64), ['authz-object-level'], 'SKIPPED'),
    ],
    errors: [],
    policy_digest: 'b'.repeat(64),
    lens_pack_digest: 'c'.repeat(64),
    lens_shared_contract_digest: 'd'.repeat(64),
    plan_digest: 'e'.repeat(64),
    tool: { version: '0.12.0' },
    ...overrides,
  }
}

test('a removed registry topic prevents a zero-owner lens absence claim', () => {
  const baseline = lifecycleRun()
  const current = lifecycleRun({
    run_id: 'run:ai-review:topic-removed',
    findings: [],
    lens_pack_digest: 'f'.repeat(64),
    jobs: [
      lensJob('ai-generated-code', '1'.repeat(64), []),
      lensJob('web-and-api', '3'.repeat(64), ['renamed-authz-topic'], 'SKIPPED'),
    ],
  })

  const comparison = compareRuns(baseline, current)
  assert.equal(comparison.lens_comparability[0].comparable, true)
  assert.equal(comparison.counts['claimed-fixed'], 0)
  assert.equal(comparison.counts['not-observed'], 1)
})

test('an additive pack change preserves a zero-owner finding topic contract', () => {
  const baseline = lifecycleRun()
  const current = lifecycleRun({
    run_id: 'run:ai-review:additive-lens',
    findings: [],
    lens_pack_digest: 'f'.repeat(64),
    jobs: [
      lensJob('ai-generated-code', '1'.repeat(64), []),
      lensJob('web-and-api', '2'.repeat(64), ['authz-object-level'], 'SKIPPED'),
      lensJob('embedded-iot-ot-security', '3'.repeat(64), ['iot-secure-boot'], 'SKIPPED'),
    ],
  })

  const comparison = compareRuns(baseline, current)
  assert.equal(comparison.partially_comparable, true)
  assert.equal(comparison.counts['claimed-fixed'], 1)
  assert.equal(comparison.counts['not-observed'], 0)
})

test('a topic owner transfer prevents a zero-owner lens absence claim', () => {
  const baseline = lifecycleRun()
  const current = lifecycleRun({
    run_id: 'run:ai-review:owner-transferred',
    findings: [],
    lens_pack_digest: 'f'.repeat(64),
    jobs: [
      lensJob('ai-generated-code', '1'.repeat(64), []),
      lensJob('web-and-api', '2'.repeat(64), [], 'SKIPPED'),
      lensJob('crypto-and-key-management', '3'.repeat(64), ['authz-object-level'], 'SKIPPED'),
    ],
  })

  const comparison = compareRuns(baseline, current)
  assert.equal(comparison.lens_comparability[0].comparable, true)
  assert.equal(comparison.counts['claimed-fixed'], 0)
  assert.equal(comparison.counts['not-observed'], 1)
})

test('a changed topic-owner lens prevents a zero-owner lens absence claim', () => {
  const baseline = lifecycleRun()
  const current = lifecycleRun({
    run_id: 'run:ai-review:owner-changed',
    findings: [],
    lens_pack_digest: 'f'.repeat(64),
    jobs: [
      lensJob('ai-generated-code', '1'.repeat(64), []),
      lensJob('web-and-api', '3'.repeat(64), ['authz-object-level'], 'SKIPPED'),
    ],
  })

  const comparison = compareRuns(baseline, current)
  assert.equal(comparison.lens_comparability[0].comparable, true)
  assert.equal(comparison.counts['claimed-fixed'], 0)
  assert.equal(comparison.counts['not-observed'], 1)
})
