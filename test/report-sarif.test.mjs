import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  comparisonCompatibility,
  compareRuns,
  coverageSupportsResolution,
  findingFingerprint,
} from '../scripts/lib/lifecycle.mjs'
import { renderMarkdownReport, renderSarif } from '../scripts/lib/report.mjs'
import { createLensFileCoverageGap } from '../scripts/lib/coverage-gaps.mjs'

function finding(overrides = {}) {
  return {
    candidate_id: 'cand:web:001',
    lens: 'web-and-api',
    topic: 'authz-object-level',
    title: 'Tenant object is loaded without an ownership check',
    claimed_impact_severity: 'High',
    effective_severity: 'Medium',
    location: ['src/orders.js:42'],
    evidence: 'return Orders.findById(req.params.id)',
    attack: 'Request another tenant order identifier.',
    impact: 'An authenticated tenant can read another tenant order.',
    reachable_from: 'GET /orders/:id',
    confidence: 'High',
    proof_plan: 'Use two tenants and request tenant B data as tenant A.',
    triage_disposition: 'queued',
    verification_status: 'UNPROVEN',
    proof_tier: 'T0',
    ...overrides,
  }
}

function run(overrides = {}) {
  return {
    run_id: 'run:test:0001',
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
      lenses: [{ lens: 'web-and-api', status: 'RAN', examined_paths: ['src/orders.js'] }],
      gaps: [],
    },
    findings: [finding()],
    jobs: [{
      job_id: 'lens:web-and-api',
      kind: 'LENS',
      lens: 'web-and-api',
      state: 'SUCCEEDED',
      coverage_authority: 'PROVIDER_DECLARED',
    }],
    errors: [],
    policy_digest: 'b'.repeat(64),
    lens_pack_digest: 'c'.repeat(64),
    plan_digest: 'd'.repeat(64),
    tool: { version: '0.2.0' },
    ...overrides,
  }
}

test('semantic identity is the stable lifecycle fingerprint', () => {
  const original = findingFingerprint(finding())
  assert.match(original, /^sha256:[a-f0-9]{64}$/)
  assert.equal(
    findingFingerprint(finding({ candidate_id: 'cand:web:regenerated' })),
    original,
  )
  assert.equal(
    findingFingerprint(finding({ location: ['src/orders.js:43'] })),
    original,
  )
  assert.notEqual(
    findingFingerprint(finding({ location: ['src/other-orders.js:42'] })),
    original,
  )
})

test('line drift is an updated finding, never a synthetic fixed plus new pair', () => {
  const baseline = run()
  const current = run({
    run_id: 'run:test:line-drift',
    findings: [finding({ location: ['src/orders.js:43'] })],
  })
  const comparison = compareRuns(baseline, current)
  assert.deepEqual(comparison.counts, {
    new: 0,
    updated: 1,
    unchanged: 0,
    fixed: 0,
    'not-observed': 0,
  })
  assert.match(comparison.resolution_authority, /provider-declared/)
})

test('an absent finding is fixed only when current coverage supports that conclusion', () => {
  const baseline = run()
  const incomplete = run({
    run_id: 'run:test:0002',
    state: 'INCOMPLETE',
    findings: [],
    coverage: {
      inventory: ['src/orders.js'],
      examined: [],
      unexamined: [{ path: 'src/orders.js', reason: 'provider failed' }],
      lenses: [{ lens: 'web-and-api', status: 'FAILED', examined_paths: [], reason: 'provider failed' }],
      gaps: [{ area: 'src/orders.js', reason: 'provider failed' }],
    },
  })
  assert.equal(coverageSupportsResolution(incomplete, finding()), false)
  assert.deepEqual(compareRuns(baseline, incomplete).counts, {
    new: 0,
    updated: 0,
    unchanged: 0,
    fixed: 0,
    'not-observed': 1,
  })

  const completed = run({ run_id: 'run:test:0003', findings: [] })
  assert.equal(compareRuns(baseline, completed).counts.fixed, 1)
})

test('lifecycle authority never invents a provider declaration for absent or failed work', () => {
  const baseline = run()
  for (const [name, jobs] of [
    ['absent', []],
    ['pending', [{
      job_id: 'lens:web-and-api',
      kind: 'LENS',
      lens: 'web-and-api',
      state: 'PENDING',
    }]],
    ['failed', [{
      job_id: 'lens:web-and-api',
      kind: 'LENS',
      lens: 'web-and-api',
      state: 'FAILED',
    }]],
  ]) {
    const current = run({
      run_id: `run:test:no-authority:${name}`,
      findings: [],
      jobs,
      state: 'INCOMPLETE',
    })
    const comparison = compareRuns(baseline, current)
    assert.equal(
      comparison.results[0].resolution_authority,
      'NO_CURRENT_COVERAGE_AUTHORITY',
    )
    assert.match(comparison.resolution_authority, /no current successful lens/i)
  }
})

test('a lens shard that failed withdraws the whole lens coverage authority', () => {
  const shard = (index, state, authority) => ({
    job_id: `lens:web-and-api:shard-000${index}-aaaaaaaaaaaa`,
    kind: 'LENS',
    lens: 'web-and-api',
    state,
    ...(authority ? { coverage_authority: authority } : {}),
  })
  const baseline = run({ findings: [] })
  const observed = 'CONTROLLER_OBSERVED_CONSUMPTION'

  for (const jobs of [
    [shard(1, 'SUCCEEDED', observed), shard(2, 'FAILED'), shard(3, 'FAILED')],
    [shard(1, 'FAILED'), shard(2, 'SUCCEEDED', observed), shard(3, 'SUCCEEDED', observed)],
  ]) {
    const comparison = compareRuns(baseline, run({
      run_id: 'run:test:partial-shards',
      state: 'COMPLETE_WITH_GAPS',
      jobs,
    }))
    assert.equal(
      comparison.results[0].resolution_authority,
      'NO_CURRENT_COVERAGE_AUTHORITY',
      'one succeeded shard cannot speak for shards that never produced',
    )
    assert.doesNotMatch(comparison.resolution_authority, /controller-observed byte consumption/)
  }
})

test('lens authority is the weakest authority across every shard that ran', () => {
  const shard = (index, authority) => ({
    job_id: `lens:web-and-api:shard-000${index}-aaaaaaaaaaaa`,
    kind: 'LENS',
    lens: 'web-and-api',
    state: 'SUCCEEDED',
    coverage_authority: authority,
  })
  const baseline = run({ findings: [] })
  const authorityFor = (jobs) => compareRuns(baseline, run({
    run_id: 'run:test:shard-authority',
    jobs,
  })).results[0].resolution_authority

  assert.equal(
    authorityFor([shard(1, 'CONTROLLER_OBSERVED_CONSUMPTION'), shard(2, 'CONTROLLER_OBSERVED_CONSUMPTION')]),
    'CONTROLLER_OBSERVED_CONSUMPTION',
  )
  assert.equal(
    authorityFor([shard(1, 'REMOTE_REQUEST_ACCEPTED'), shard(2, 'REMOTE_REQUEST_ACCEPTED')]),
    'REMOTE_REQUEST_ACCEPTED',
  )
  assert.equal(
    authorityFor([shard(1, 'CONTROLLER_OBSERVED_CONSUMPTION'), shard(2, 'PROVIDER_DECLARED')]),
    'PROVIDER_DECLARED',
  )
})

test('dormant and skipped closure templates never withdraw a completed lens authority', () => {
  const baseline = run({ findings: [] })
  const comparison = compareRuns(baseline, run({
    run_id: 'run:test:closure-templates',
    jobs: [
      {
        job_id: 'lens:web-and-api:shard-0001-aaaaaaaaaaaa',
        kind: 'LENS',
        lens: 'web-and-api',
        state: 'SUCCEEDED',
        coverage_authority: 'CONTROLLER_OBSERVED_CONSUMPTION',
      },
      {
        job_id: 'closure:01:shard-0001-aaaaaaaaaaaa:bbbbbbbbbbbb',
        kind: 'LENS',
        lens: 'web-and-api',
        state: 'SKIPPED',
        closure_round: 1,
      },
      {
        job_id: 'closure:02:shard-0001-aaaaaaaaaaaa:cccccccccccc',
        kind: 'LENS',
        lens: 'web-and-api',
        state: 'DORMANT',
        closure_round: 2,
      },
    ],
  }))
  assert.equal(
    comparison.results[0].resolution_authority,
    'CONTROLLER_OBSERVED_CONSUMPTION',
  )
})

test('resolution requires every shard of the lens, not merely one of them', () => {
  const partial = run({
    run_id: 'run:test:partial-resolution',
    state: 'COMPLETE_WITH_GAPS',
    findings: [],
    jobs: [
      {
        job_id: 'lens:web-and-api:shard-0001-aaaaaaaaaaaa',
        kind: 'LENS',
        lens: 'web-and-api',
        state: 'SUCCEEDED',
        coverage_authority: 'CONTROLLER_OBSERVED_CONSUMPTION',
      },
      {
        job_id: 'lens:web-and-api:shard-0002-bbbbbbbbbbbb',
        kind: 'LENS',
        lens: 'web-and-api',
        state: 'FAILED',
      },
    ],
  })
  assert.equal(coverageSupportsResolution(partial, finding()), false)
  assert.equal(compareRuns(run(), partial).counts.fixed, 0)
  assert.equal(compareRuns(run(), partial).counts['not-observed'], 1)
})

test('lifecycle summary preserves mixed declared and observed authority', () => {
  const cryptoFinding = finding({
    candidate_id: 'cand:crypto:001',
    lens: 'crypto-and-key-management',
    topic: 'hmac-and-constant-time-comparison',
    title: 'MAC comparison is not constant time',
    location: ['src/mac.js:9'],
  })
  const baseline = run({ findings: [] })
  const current = run({
    run_id: 'run:test:mixed-authority',
    findings: [finding(), cryptoFinding],
    jobs: [
      {
        job_id: 'lens:web-and-api',
        kind: 'LENS',
        lens: 'web-and-api',
        state: 'SUCCEEDED',
        coverage_authority: 'CONTROLLER_OBSERVED_CONSUMPTION',
      },
      {
        job_id: 'lens:crypto-and-key-management',
        kind: 'LENS',
        lens: 'crypto-and-key-management',
        state: 'SUCCEEDED',
        coverage_authority: 'PROVIDER_DECLARED',
      },
    ],
  })
  const comparison = compareRuns(baseline, current)
  assert.deepEqual(
    new Set(comparison.results.map(
      ({ resolution_authority: authority }) => authority,
    )),
    new Set([
      'CONTROLLER_OBSERVED_CONSUMPTION',
      'PROVIDER_DECLARED',
    ]),
  )
  assert.match(comparison.resolution_authority, /mixed provider-declared/i)
})

test('remote acceptance remains a distinct lifecycle and report authority', () => {
  const baseline = run()
  const current = run({
    run_id: 'run:test:remote-authority',
    findings: [],
    jobs: [{
      job_id: 'lens:web-and-api',
      kind: 'LENS',
      lens: 'web-and-api',
      state: 'SUCCEEDED',
      coverage_authority: 'REMOTE_REQUEST_ACCEPTED',
      producer: {
        name: 'remote-fixture',
        version: '1.0.0',
        instance_id: 'remote:fixture',
      },
    }],
  })
  const comparison = compareRuns(baseline, current)
  assert.equal(
    comparison.results[0].resolution_authority,
    'REMOTE_REQUEST_ACCEPTED',
  )
  assert.match(
    comparison.resolution_authority,
    /remote gateway request acceptance/i,
  )
  const report = renderMarkdownReport(current)
  assert.match(report, /Remote request accepted jobs: 1/)
  assert.match(report, /REMOTE_REQUEST_ACCEPTED proves the pinned gateway/i)
})

test('attributable coverage gaps veto only the resolutions they can affect', () => {
  const baseline = run()
  const affected = run({
    run_id: 'run:test:affected-gap',
    state: 'COMPLETE_WITH_GAPS',
    findings: [],
    coverage: {
      ...run().coverage,
      gaps: [{
        area: 'lens:web-and-api:src/other-orders.js',
        reason: 'web analysis did not complete',
      }],
    },
  })
  assert.equal(coverageSupportsResolution(affected, finding()), false)
  assert.equal(compareRuns(baseline, affected).counts.fixed, 0)
  assert.equal(compareRuns(baseline, affected).counts['not-observed'], 1)

  const exactPathGap = run({
    run_id: 'run:test:exact-path-gap',
    state: 'COMPLETE_WITH_GAPS',
    findings: [],
    coverage: {
      ...run().coverage,
      gaps: [{ area: 'src/orders.js', reason: 'analysis incomplete' }],
    },
  })
  assert.equal(coverageSupportsResolution(exactPathGap, finding()), false)

  const unrelated = run({
    run_id: 'run:test:unrelated-gap',
    state: 'COMPLETE_WITH_GAPS',
    findings: [],
    coverage: {
      inventory: ['src/orders.js', 'src/key.js'],
      examined: ['src/orders.js'],
      unexamined: [{ path: 'src/key.js', reason: 'crypto analysis incomplete' }],
      lenses: [
        { lens: 'web-and-api', status: 'RAN', examined_paths: ['src/orders.js'] },
        {
          lens: 'crypto-and-key-management',
          status: 'FAILED',
          examined_paths: [],
          reason: 'crypto analysis incomplete',
        },
      ],
      gaps: [{
        area: 'lens:crypto-and-key-management:src/key.js',
        reason: 'crypto analysis incomplete',
      }],
    },
  })
  assert.equal(coverageSupportsResolution(unrelated, finding()), true)

  const unattributable = run({
    run_id: 'run:test:unattributable-gap',
    state: 'COMPLETE_WITH_GAPS',
    findings: [],
    coverage: {
      ...run().coverage,
      gaps: [{ area: 'provider analysis incomplete', reason: 'unknown scope' }],
    },
  })
  assert.equal(coverageSupportsResolution(unattributable, finding()), false)
})

test('a resolved lens/file gap no longer vetoes lifecycle resolution', () => {
  const gap = createLensFileCoverageGap({
    lens: 'web-and-api',
    path: 'src/orders.js',
    reason: 'the first bounded shard omitted this file',
  })
  const current = run({
    run_id: 'run:test:resolved-gap',
    findings: [],
    coverage: {
      ...run().coverage,
      gaps: [gap],
      resolved_gap_ids: [gap.gap_id],
    },
  })

  assert.equal(coverageSupportsResolution(current, finding()), true)
  assert.equal(compareRuns(run(), current).counts.fixed, 1)
})

test('unrelated or differently governed runs cannot claim a finding was fixed', () => {
  const baseline = run()
  const unrelated = run({
    run_id: 'run:other:0001',
    findings: [],
    repository: {
      root: 'C:\\other-repository',
      tree_digest: 'e'.repeat(64),
    },
  })
  const changedLensPack = run({
    run_id: 'run:test:changed-lenses',
    findings: [],
    lens_pack_digest: 'f'.repeat(64),
  })
  const changedPolicy = run({
    run_id: 'run:test:changed-policy',
    findings: [],
    policy_digest: '9'.repeat(64),
  })

  assert.equal(comparisonCompatibility(baseline, unrelated).comparable, false)
  assert.equal(compareRuns(baseline, unrelated).counts['not-observed'], 1)
  assert.equal(compareRuns(baseline, unrelated).counts.fixed, 0)
  assert.deepEqual(compareRuns(baseline, changedLensPack).comparability_reasons, [
    'lens packs differ',
  ])
  assert.deepEqual(compareRuns(baseline, changedPolicy).comparability_reasons, [
    'Rules of Engagement differ',
  ])
})

test('lifecycle comparison preserves colliding findings instead of overwriting them', () => {
  const left = finding({
    candidate_id: 'cand:web:left',
    fingerprint: 'explicit:collision',
    title: 'Left occurrence',
  })
  const right = finding({
    candidate_id: 'cand:web:right',
    fingerprint: 'explicit:collision',
    title: 'Right occurrence',
  })
  const comparison = compareRuns(
    run({ findings: [left, right] }),
    run({ run_id: 'run:test:collision-current', findings: [left, right] }),
  )
  assert.equal(comparison.results.length, 2)
  assert.equal(comparison.counts.unchanged, 2)
})

test('database resolution requires the same assessed store, topic, adapter, and principal', () => {
  const database = finding({
    candidate_id: 'cand:db:orders',
    lens: 'database-and-data-stores',
    topic: 'database-native-authorization-and-tenant-isolation',
    location: ['db/policies.sql:41'],
    store_context: {
      store_id: 'orders-primary',
      family: 'relational',
      engine: 'postgresql',
      engine_version: '16',
      deployment_variant: 'self-managed',
      adapter_id: 'postgresql',
    },
    principal_path: {
      authenticated_principal: 'application user',
      session_principal: 'orders_runtime',
      effective_principal: 'orders_runtime',
      owner_or_definer: 'orders_owner',
      bypass_capabilities: [],
    },
  })
  const baseCoverage = {
    inventory: ['db/policies.sql'],
    examined: ['db/policies.sql'],
    unexamined: [],
    lenses: [{
      lens: 'database-and-data-stores',
      status: 'RAN',
      examined_paths: ['db/policies.sql'],
    }],
    gaps: [],
  }
  const databaseJobs = [{
    job_id: 'lens:database-and-data-stores',
    kind: 'LENS',
    lens: 'database-and-data-stores',
    state: 'SUCCEEDED',
    coverage_authority: 'PROVIDER_DECLARED',
  }]
  const baseline = run({
    findings: [database],
    coverage: baseCoverage,
    jobs: databaseJobs,
  })
  const inventoryOnly = run({
    run_id: 'run:test:db-current',
    findings: [],
    coverage: baseCoverage,
    jobs: databaseJobs,
    store_profiles: [{
      store_context: {
        ...database.store_context,
        adapter_id: 'inventory-only',
      },
      principal_path: database.principal_path,
      evidence_paths: ['db/policies.sql'],
      coverage_state: 'NOT_ASSESSED',
      assessed_topics: [],
      coverage_gaps: [{ area: 'adapter', reason: 'engine semantics unresolved' }],
    }],
  })
  assert.equal(coverageSupportsResolution(inventoryOnly, database), false)
  assert.equal(compareRuns(baseline, inventoryOnly).counts.fixed, 0)
  assert.equal(compareRuns(baseline, inventoryOnly).counts['not-observed'], 1)

  const assessed = run({
    ...inventoryOnly,
    run_id: 'run:test:db-assessed',
    store_profiles: [{
      store_context: database.store_context,
      principal_path: database.principal_path,
      evidence_paths: ['db/policies.sql'],
      coverage_state: 'ASSESSED',
      assessed_topics: [database.topic],
      coverage_gaps: [],
    }],
  })
  assert.equal(coverageSupportsResolution(assessed, database), true)
  assert.equal(compareRuns(baseline, assessed).counts.fixed, 1)

  const storeGap = run({
    ...assessed,
    run_id: 'run:test:db-store-gap',
    state: 'COMPLETE_WITH_GAPS',
    coverage: {
      ...baseCoverage,
      gaps: [{
        area: 'store:orders-primary:replica',
        reason: 'replica authorization was not assessed',
      }],
    },
  })
  assert.equal(coverageSupportsResolution(storeGap, database), false)
  assert.equal(compareRuns(baseline, storeGap).counts['not-observed'], 1)

  const changedVersion = run({
    ...assessed,
    run_id: 'run:test:db-version-change',
    store_profiles: [{
      ...assessed.store_profiles[0],
      store_context: {
        ...assessed.store_profiles[0].store_context,
        engine_version: '17',
      },
    }],
  })
  assert.equal(coverageSupportsResolution(changedVersion, database), false)
  assert.equal(compareRuns(baseline, changedVersion).counts['not-observed'], 1)
})

test('database fingerprints distinguish stores and engine semantics', () => {
  const base = {
    lens: 'database-and-data-stores',
    topic: 'database-native-authorization-and-tenant-isolation',
    location: ['db/policies.sql:41'],
    evidence: 'USING (tenant_id = current_setting(...))',
  }
  assert.notEqual(
    findingFingerprint(finding({
      ...base,
      store_context: { store_id: 'orders-primary', adapter_id: 'postgresql' },
    })),
    findingFingerprint(finding({
      ...base,
      store_context: { store_id: 'billing-primary', adapter_id: 'postgresql' },
    })),
  )
  assert.notEqual(
    findingFingerprint(finding({
      ...base,
      store_context: {
        store_id: 'orders-primary',
        engine: 'postgresql',
        engine_version: '16',
        deployment_variant: 'self-managed',
        adapter_id: 'postgresql',
      },
    })),
    findingFingerprint(finding({
      ...base,
      store_context: {
        store_id: 'orders-primary',
        engine: 'postgresql',
        engine_version: '17',
        deployment_variant: 'self-managed',
        adapter_id: 'postgresql',
      },
    })),
  )
})

test('large colliding lifecycle groups compare without quadratic matching', { timeout: 5_000 }, () => {
  const count = 3_000
  const baselineFindings = Array.from({ length: count }, (_, index) => finding({
    candidate_id: `cand:web:baseline:${String(index).padStart(4, '0')}`,
    fingerprint: 'explicit:large-collision',
    attack: `baseline attack ${index}`,
  }))
  const currentFindings = Array.from({ length: count }, (_, index) => finding({
    candidate_id: `cand:web:current:${String(index).padStart(4, '0')}`,
    fingerprint: 'explicit:large-collision',
    attack: `current attack ${index}`,
  }))
  const comparison = compareRuns(
    run({ findings: baselineFindings }),
    run({ run_id: 'run:test:large-collision', findings: currentFindings }),
  )
  assert.equal(comparison.results.length, count)
  assert.equal(comparison.counts.updated, count)
})

test('report never presents an unfinished zero-finding run as clean', () => {
  const report = renderMarkdownReport(run({
    state: 'PLANNED',
    findings: [],
    coverage: {
      inventory: ['src/orders.js'],
      examined: [],
      unexamined: [{ path: 'src/orders.js', reason: 'audit job has not run' }],
      lenses: [{ lens: 'web-and-api', status: 'NOT_ASSESSED', examined_paths: [], reason: 'audit job has not run' }],
      gaps: [],
    },
  }))
  assert.match(report, /not a clean audit result/i)
  assert.match(report, /No surviving findings were recorded\. This does not override/)
  assert.match(report, /src\/orders\.js/)
})

test('Markdown report preserves findings, removals, gaps and provenance', () => {
  const dropped = finding({
    candidate_id: 'cand:web:002',
    title: 'Dropped candidate',
    triage_disposition: 'dropped',
    drop_reason: 'The cited route does not exist.',
  })
  const report = renderMarkdownReport(run({
    state: 'COMPLETE_WITH_GAPS',
    findings: [finding(), dropped],
    coverage: {
      inventory: ['src/orders.js', 'generated.bin'],
      examined: ['src/orders.js'],
      unexamined: [{ path: 'generated.bin', reason: 'binary-content-not-decoded' }],
      lenses: [{ lens: 'web-and-api', status: 'RAN', examined_paths: ['src/orders.js'] }],
      gaps: [{ area: 'generated.bin', reason: 'binary input excluded' }],
    },
  }))
  assert.match(report, /Tenant object is loaded/)
  assert.match(report, /Withdrawn candidates/)
  assert.match(report, /The cited route does not exist/)
  assert.match(report, /binary input excluded/)
  assert.match(report, /Plan digest/)
})

test('coverage reporting separates unique files, lens obligations, groups, and raw records', () => {
  const webGap = createLensFileCoverageGap({
    lens: 'web-and-api',
    path: 'src/app.js',
    reason: 'the initial web shard omitted the file',
  })
  const webRetryGap = createLensFileCoverageGap({
    lens: 'web-and-api',
    path: 'src/app.js',
    reason: 'the retry also omitted the file',
  })
  const cryptoGap = createLensFileCoverageGap({
    lens: 'crypto-and-key-management',
    path: 'src/app.js',
    reason: 'the crypto shard omitted the file',
  })
  const resolvedDatabaseGap = createLensFileCoverageGap({
    lens: 'database-and-data-stores',
    path: 'db/policy.sql',
    reason: 'resolved database omission',
  })
  const coverage = {
    inventory: ['README.md', 'db/policy.sql', 'src/app.js'],
    examined: ['db/policy.sql'],
    unexamined: [{
      path: 'README.md',
      reason: 'documentation was not examined',
    }],
    denominators: [{
      category: 'canonical-source',
      files_total: 2,
      bytes_total: 512,
      files_examined: 1,
      bytes_examined: 256,
      files_unexamined: 1,
      bytes_unexamined: 256,
    }],
    lenses: [
      {
        lens: 'web-and-api',
        status: 'NOT_ASSESSED',
        applicable_paths: ['src/app.js'],
        examined_paths: [],
        reason: 'one obligation remains',
      },
      {
        lens: 'crypto-and-key-management',
        status: 'NOT_ASSESSED',
        applicable_paths: ['src/app.js'],
        examined_paths: [],
        reason: 'one obligation remains',
      },
      {
        lens: 'database-and-data-stores',
        status: 'RAN',
        applicable_paths: ['db/policy.sql'],
        examined_paths: ['db/policy.sql'],
      },
    ],
    gaps: [
      webGap,
      webRetryGap,
      cryptoGap,
      resolvedDatabaseGap,
      { area: 'store:orders:roles', reason: 'runtime role unresolved' },
      { area: 'store:orders:roles', reason: 'migration role unresolved' },
      { area: 'provider analysis', reason: 'semantic analysis incomplete' },
    ],
    resolved_gap_ids: [resolvedDatabaseGap.gap_id],
  }
  const current = run({
    state: 'COMPLETE_WITH_GAPS',
    coverage,
  })
  const report = renderMarkdownReport(current)
  const properties = renderSarif(current).runs[0].invocations[0].properties

  assert.match(report, /Unique open files: 2/)
  assert.match(report, /Open lens\/file obligations: 2/)
  assert.match(report, /Conceptual unique open gaps: 4/)
  assert.match(report, /Exact open lens\/file gaps: 2/)
  assert.match(report, /Unique non-file gap groups: 2/)
  assert.match(report, /Raw open gap records: 6/)
  assert.match(report, /Resolved historical gap records: 1/)
  assert.match(
    report,
    /\| canonical-source \| 2 \| 1 \| 1 \| 512 \| 256 \| 256 \|/,
  )
  assert.match(report, /\| store:orders:roles \| 2 \|/)
  assert.doesNotMatch(report, /resolved database omission/)

  assert.equal(properties.coverage_unique_open_files, 2)
  assert.equal(properties.coverage_open_lens_file_obligations, 2)
  assert.equal(properties.coverage_conceptual_unique_open_gaps, 4)
  assert.equal(properties.coverage_exact_open_gap_identities, 5)
  assert.equal(properties.coverage_exact_open_lens_file_gaps, 2)
  assert.equal(properties.coverage_unique_non_file_gap_groups, 2)
  assert.equal(properties.coverage_raw_open_gap_records, 6)
  assert.equal(properties.coverage_resolved_gap_records, 1)
  assert.equal(properties.coverage_gap_history_records, 7)
  assert.deepEqual(properties.coverage_denominators, [{
    category: 'canonical-source',
    files_total: 2,
    files_examined: 1,
    files_unexamined: 1,
    bytes_total: 512,
    bytes_examined: 256,
    bytes_unexamined: 256,
  }])
})

test('legacy lens-prefixed gaps remain attributable in deduplicated reports', () => {
  const current = run({
    state: 'COMPLETE_WITH_GAPS',
    coverage: {
      inventory: ['src/app.js'],
      examined: [],
      unexamined: [],
      lenses: [{
        lens: 'web-and-api',
        status: 'NOT_ASSESSED',
        examined_paths: [],
        reason: 'legacy provider did not finish',
      }],
      gaps: [{
        area: 'lens:web-and-api:src/app.js',
        reason: 'legacy provider did not finish',
      }],
    },
  })
  const report = renderMarkdownReport(current)
  const properties = renderSarif(current).runs[0].invocations[0].properties

  assert.match(report, /Unique open files: 1/)
  assert.match(report, /Open lens\/file obligations: 1/)
  assert.match(report, /Unique non-file gap groups: 0/)
  assert.match(report, /src\/app\.js/)
  assert.equal(properties.coverage_unique_open_files, 1)
  assert.equal(properties.coverage_open_lens_file_obligations, 1)
  assert.equal(properties.coverage_unique_non_file_gap_groups, 0)
})

test('Markdown bounds open-file samples while preserving exact totals', () => {
  const paths = Array.from(
    { length: 35 },
    (_, index) => `src/open-${String(index).padStart(2, '0')}.js`,
  )
  const report = renderMarkdownReport(run({
    state: 'PLANNED',
    findings: [],
    coverage: {
      inventory: paths,
      examined: [],
      unexamined: paths.map((path) => ({
        path,
        reason: 'audit job has not run',
      })),
      lenses: [],
      gaps: [],
    },
  }))

  assert.match(report, /Unique open files: 35/)
  assert.match(report, /15 additional open file samples omitted/)
  assert.match(report, /src\/open-00\.js/)
  assert.doesNotMatch(report, /src\/open-34\.js/)
})

test('v3 reports deterministic file and byte denominators plus bounded closure history', () => {
  const history = Array.from({ length: 25 }, (_, round) => ({
    round,
    status: round === 24 ? 'BUDGET_EXHAUSTED' : 'REQUEUED',
    applicable_lens_file_pairs: 30,
    examined_lens_file_pairs: round,
    uncovered_lens_file_pairs: 30 - round,
    uncovered_shards: [{
      job_id: `closure-sensitive-shard-${round}`,
      lens: 'web-and-api',
      shard_id: `shard-${round}`,
    }],
  }))
  const denominators = [
    {
      class: 'BINARY',
      files_total: 1,
      files_examined: 0,
      files_unexamined: 1,
      bytes_total: 4096,
      bytes_examined: 0,
      bytes_unexamined: 4096,
    },
    {
      class: 'DOCUMENTATION',
      files_total: 2,
      files_examined: 1,
      files_unexamined: 1,
      bytes_total: 800,
      bytes_examined: 500,
      bytes_unexamined: 300,
    },
    {
      class: 'CANONICAL_SOURCE',
      files_total: 3,
      files_examined: 2,
      files_unexamined: 1,
      bytes_total: 900,
      bytes_examined: 700,
      bytes_unexamined: 200,
    },
    {
      class: 'TEST',
      files_total: 4,
      files_examined: 4,
      files_unexamined: 0,
      bytes_total: 1200,
      bytes_examined: 1200,
      bytes_unexamined: 0,
    },
    {
      class: 'GENERATED_CODE',
      files_total: 5,
      files_examined: 1,
      files_unexamined: 4,
      bytes_total: 5000,
      bytes_examined: 1000,
      bytes_unexamined: 4000,
    },
  ]
  const current = run({
    state: 'COMPLETE_WITH_GAPS',
    coverage: {
      inventory: ['src/app.js'],
      examined: [],
      unexamined: [{ path: 'src/app.js', reason: 'closure exhausted' }],
      lenses: [{
        lens: 'web-and-api',
        status: 'FAILED',
        applicable_paths: ['src/app.js'],
        examined_paths: [],
        reason: 'closure exhausted',
      }],
      gaps: [],
      denominators,
      closure: {
        required_source_closure: true,
        max_rounds: 24,
        round: 24,
        status: 'BUDGET_EXHAUSTED',
        applicable_lens_file_pairs: 30,
        examined_lens_file_pairs: 24,
        uncovered_lens_file_pairs: 6,
        uncovered_shards: [{
          job_id: 'closure-sensitive-current-shard',
          lens: 'web-and-api',
          shard_id: 'shard-current',
        }],
        history,
      },
    },
  })
  const report = renderMarkdownReport(current)
  const properties = renderSarif(current).runs[0].invocations[0].properties

  assert.match(
    report,
    /\| CANONICAL_SOURCE \| 3 \| 2 \| 1 \| 900 \| 700 \| 200 \|/,
  )
  assert.ok(
    report.indexOf('| CANONICAL_SOURCE |')
      < report.indexOf('| GENERATED_CODE |'),
  )
  assert.ok(report.indexOf('| GENERATED_CODE |') < report.indexOf('| TEST |'))
  assert.ok(report.indexOf('| TEST |') < report.indexOf('| DOCUMENTATION |'))
  assert.ok(report.indexOf('| DOCUMENTATION |') < report.indexOf('| BINARY |'))
  assert.match(report, /### Recursive coverage closure/)
  assert.match(report, /Status: `BUDGET_EXHAUSTED`/)
  assert.match(report, /Round: 24 of 24/)
  assert.match(report, /Source closure required: yes/)
  assert.match(report, /Open lens\/file pairs: 6/)
  assert.match(report, /5 earlier closure measurement records omitted/)
  assert.doesNotMatch(report, /closure-sensitive/)

  assert.deepEqual(
    properties.coverage_denominators.map(({ category }) => category),
    [
      'CANONICAL_SOURCE',
      'GENERATED_CODE',
      'TEST',
      'DOCUMENTATION',
      'BINARY',
    ],
  )
  assert.equal(properties.coverage_closure_status, 'BUDGET_EXHAUSTED')
  assert.equal(properties.coverage_closure_round, 24)
  assert.equal(properties.coverage_closure_max_rounds, 24)
  assert.equal(properties.coverage_closure_source_required, true)
  assert.equal(properties.coverage_closure_open_lens_file_pairs, 6)
  assert.equal(properties.coverage_closure_history_records, 25)
  assert.equal(properties.coverage_closure_history.length, 20)
  assert.equal(properties.coverage_closure_history[0].round, 5)
  assert.equal(properties.coverage_closure_history.at(-1).round, 24)
  assert.equal(properties.coverage_closure_history_omitted_records, 5)
  assert.deepEqual(properties.coverage_denominators[0], {
    category: 'CANONICAL_SOURCE',
    files_total: 3,
    files_examined: 2,
    files_unexamined: 1,
    bytes_total: 900,
    bytes_examined: 700,
    bytes_unexamined: 200,
  })
})

test('report exposes coverage separately for every discovered data store', () => {
  const current = run({
    activated_lenses: ['database-and-data-stores'],
    store_profiles: [{
      store_context: {
        store_id: 'orders-primary',
        engine: 'postgresql',
        deployment_variant: 'supabase',
        adapter_id: 'postgresql',
      },
      principal_path: {
        effective_principal: 'authenticated',
      },
      coverage_state: 'PARTIAL',
      assessed_topics: ['database-native-authorization-and-tenant-isolation'],
    }],
  })
  const report = renderMarkdownReport(current)
  const sarif = renderSarif(current)
  assert.match(report, /Data-store coverage/)
  assert.match(report, /orders-primary/)
  assert.match(report, /PARTIAL/)
  assert.equal(sarif.runs[0].invocations[0].properties.data_stores, 1)
  assert.equal(
    sarif.runs[0].invocations[0].properties.data_stores_not_assessed,
    1,
  )
})

test('Markdown report separates claimed severity from proof-backed status', () => {
  const unproven = finding({
    blocking_reason: 'Static mode cannot run the required two-tenant proof.',
  })
  const disproved = finding({
    candidate_id: 'cand:web:disproved',
    verification_status: 'DISPROVED',
    disproof_basis: 'falsified-code-premise',
    reason: 'The resolved handler performs a tenant-scoped lookup.',
  })
  const confirmed = finding({
    candidate_id: 'cand:web:confirmed',
    verification_status: 'CONFIRMED',
    proof_tier: 'T1',
    existence_check: {
      status: 'located',
      method: 'planned snapshot lookup',
    },
    post_result: {
      status: 'passed',
      regressions: 'none observed',
    },
  })
  const report = renderMarkdownReport(run({
    findings: [unproven, disproved, confirmed],
  }))
  const summary = report.slice(
    report.indexOf('### Unverified high-impact claims'),
    report.indexOf('## Findings'),
  )

  assert.match(report, /Claimed severity: `High`/)
  assert.match(report, /Effective severity: `Medium`/)
  assert.match(report, /Proof tier: `T0`/)
  assert.match(report, /Proof status: UNPROVEN.*Static mode/)
  assert.match(summary, /cand:web:001/)
  assert.match(summary, /cand:web:disproved/)
  assert.doesNotMatch(summary, /cand:web:confirmed/)
  assert.match(report, /DISPROVED.*falsified.*tenant-scoped lookup/)
})

test('Markdown report neutralizes provider-controlled markup and line breaks', () => {
  const hostile = finding({
    title: 'Legitimate title\n## Forged heading \u202eexe.txt <img src="https://attacker.invalid/pixel">',
    impact: 'Impact text\n# Forged impact <script>alert(1)</script> [click](javascript:alert(1))',
    attack: 'Attack path\n| forged | ![beacon](https://attacker.invalid/pixel)',
    proof_plan: 'Proof plan\n## Forged proof [run](javascript:alert(1))',
    reachable_from: 'GET /orders/:id`\n## Forged reachability',
    blocking_reason: 'Blocked\n| forged | <img src="https://attacker.invalid/blocker">',
  })
  const report = renderMarkdownReport(run({
    findings: [hostile],
    coverage: {
      inventory: ['src/orders.js'],
      examined: ['src/orders.js'],
      unexamined: [],
      lenses: [{
        lens: 'web-and-api',
        status: 'RAN',
        examined_paths: ['src/orders.js'],
        reason: 'ran\n| forged | <script>alert(1)</script>',
      }],
      gaps: [{
        area: 'src/orders.js\n| forged |',
        reason: '<img src="https://attacker.invalid/gap">',
      }],
    },
    errors: [{
      phase: 'REPORT',
      code: 'PROVIDER_TEXT',
      message: 'message\n## Forged error <script>alert(1)</script>',
    }],
  }))

  assert.doesNotMatch(report, /^#{1,6} Forged/m)
  assert.doesNotMatch(report, /^\| forged \|/m)
  assert.doesNotMatch(report, /<img|<script/i)
  assert.doesNotMatch(report, /\]\(javascript:/i)
  assert.doesNotMatch(report, /[\u202a-\u202e\u2066-\u2069]/u)
  assert.match(report, /�exe\.txt/)
  assert.match(report, /&lt;img/)
  assert.match(report, /&lt;script&gt;/)
  assert.match(
    report,
    /^### Medium — Legitimate title \\#\\# Forged heading �exe\.txt &lt;img/m,
  )
  assert.equal((report.match(/^## Findings$/gm) ?? []).length, 1)
  assert.equal((report.match(/^## Coverage$/gm) ?? []).length, 1)
  assert.equal((report.match(/^## Provenance$/gm) ?? []).length, 1)
})

test('disproved and not-reproduced candidates are preserved but not reported as findings', () => {
  const disproved = finding({
    verification_status: 'DISPROVED',
    reason: 'The cited route uses a tenant-scoped lookup in the resolved implementation.',
  })
  const notReproduced = finding({
    candidate_id: 'cand:web:negative',
    verification_status: 'NOT_REPRODUCED',
    reason: 'The cited artifact was not present in the planned snapshot.',
  })
  const current = run({ findings: [disproved, notReproduced] })
  const report = renderMarkdownReport(current)
  const sarif = renderSarif(current)

  assert.match(report, /\| 0 \| 0 \| 0 \| 0 \| 0 \|/)
  assert.doesNotMatch(report, /### Medium .*Tenant object/)
  assert.match(report, /Withdrawn candidates/)
  assert.match(report, /DISPROVED/)
  assert.match(report, /NOT_REPRODUCED/)
  assert.equal(sarif.runs[0].results.length, 2)
  assert.deepEqual(
    sarif.runs[0].results.map(({ suppressions }) => suppressions[0].kind),
    ['external', 'external'],
  )
  assert.deepEqual(
    sarif.runs[0].results.map(({ suppressions }) => suppressions[0].status),
    ['accepted', 'accepted'],
  )
  assert.match(
    sarif.runs[0].results[0].suppressions[0].justification,
    /DISPROVED|NOT REPRODUCED/,
  )
  const properties = sarif.runs[0].invocations[0].properties
  assert.equal(properties.findings_state, 'NO_FINDINGS_REPORTED')
  assert.equal(properties.withdrawn_candidates, 2)
  assert.equal(properties.withdrawn_high_impact_candidates, 2)
  assert.equal(properties.unverified_high_impact_claims, 2)
  assert.equal(compareRuns(run(), current).counts.unchanged, 0)
})

test('SARIF records a dropped Critical instead of emitting a clean empty result set', () => {
  const dropped = finding({
    candidate_id: 'cand:web:dropped',
    claimed_impact_severity: 'Critical',
    triage_disposition: 'dropped',
    drop_reason: 'The cited route is unreachable in the shipped build.',
  })
  const merged = finding({
    candidate_id: 'cand:web:merged',
    claimed_impact_severity: 'Critical',
    triage_disposition: 'merged',
    merged_into_candidate_id: 'cand:web:dropped',
  })
  const sarif = renderSarif(run({ findings: [dropped, merged] }))
  const properties = sarif.runs[0].invocations[0].properties

  assert.equal(properties.findings_state, 'NO_FINDINGS_REPORTED')
  assert.equal(properties.withdrawn_candidates, 2)
  assert.equal(properties.withdrawn_high_impact_candidates, 2)
  assert.equal(sarif.runs[0].results.length, 2)
  assert.deepEqual(
    sarif.runs[0].results.map(({ properties: entry }) => entry.candidate_id),
    ['cand:web:dropped', 'cand:web:merged'],
  )
  assert.deepEqual(
    sarif.runs[0].results.map(({ properties: entry }) => entry.triage_disposition),
    ['dropped', 'merged'],
  )
  assert.equal(
    sarif.runs[0].results[1].properties.merged_into_candidate_id,
    'cand:web:dropped',
  )
  assert.match(
    sarif.runs[0].results[0].suppressions[0].justification,
    /DROPPED before proof: The cited route is unreachable/,
  )
})

test('SARIF suppresses only withdrawn candidates and leaves survivors as open results', () => {
  const survivor = finding()
  const dropped = finding({
    candidate_id: 'cand:web:dropped',
    triage_disposition: 'dropped',
    drop_reason: 'Duplicate of an accepted candidate.',
  })
  const sarif = renderSarif(run({ findings: [survivor, dropped] }))
  const [first, second] = sarif.runs[0].results

  assert.equal(sarif.runs[0].results.length, 2)
  assert.equal(Object.hasOwn(first, 'suppressions'), false)
  assert.equal(first.properties.candidate_id, 'cand:web:001')
  assert.equal(second.suppressions.length, 1)
  assert.equal(second.properties.candidate_id, 'cand:web:dropped')
  assert.equal(
    sarif.runs[0].invocations[0].properties.findings_state,
    'FINDINGS_REPORTED',
  )
  assert.equal(sarif.runs[0].invocations[0].properties.withdrawn_candidates, 1)
})

test('SARIF carries stable rule IDs, locations, fingerprints and run honesty', () => {
  const baseline = run({ run_id: 'run:test:baseline', findings: [] })
  const current = run()
  const lifecycle = compareRuns(baseline, current)
  const sarif = renderSarif(current, { lifecycle })
  assert.equal(sarif.version, '2.1.0')
  assert.equal(sarif.runs[0].tool.driver.rules[0].id, 'authz-object-level')
  assert.equal(
    Object.hasOwn(sarif.runs[0].tool.driver, 'informationUri'),
    false,
    'omit the optional product URL until packaging declares a canonical one',
  )
  assert.equal(sarif.runs[0].results[0].ruleId, 'authz-object-level')
  assert.equal(
    sarif.runs[0].results[0].partialFingerprints['redTeamAudit/semantic/v1'],
    findingFingerprint(finding()),
  )
  assert.equal(sarif.runs[0].results[0].baselineState, 'new')
  assert.equal(
    sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine,
    42,
  )
  assert.equal(
    sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri,
    'src/orders.js',
  )
  assert.equal(sarif.runs[0].originalUriBaseIds, undefined)
  assert.doesNotMatch(JSON.stringify(sarif), /C:\\\\repo/)
  assert.equal(sarif.runs[0].invocations[0].executionSuccessful, true)
})

test('reports expose controller-owned database discovery before provider profiles exist', () => {
  const databaseDiscovery = {
    digest: `sha256:${'e'.repeat(64)}`,
    store_candidates: [{
      store_id: 'store-0123456789abcdefabcd',
      engine_candidates: ['sqlserver'],
      engine_version_candidates: [],
      confidence: 'medium',
      open_reasons: ['server-version-unresolved'],
    }],
    path_scope: [
      { path: 'src/db.ts', state: 'in-scope' },
      { path: 'README.md', state: 'context-only' },
    ],
    unresolved: [{ observation_id: 'unresolved-1' }],
    gaps: [{ gap_id: 'gap-1' }],
  }
  const current = run({
    state: 'COMPLETE_WITH_GAPS',
    database_discovery: databaseDiscovery,
    store_profiles: [],
    activated_lenses: ['database-and-data-stores'],
  })
  const report = renderMarkdownReport(current)
  const properties = renderSarif(current).runs[0].invocations[0].properties

  assert.match(report, /Controller database discovery/)
  assert.match(report, /store-0123456789abcdefabcd/)
  assert.match(report, /sqlserver/)
  assert.match(report, /NOT ASSESSED/)
  assert.equal(properties.database_discovery_digest, databaseDiscovery.digest)
  assert.equal(properties.database_discovered_stores, 1)
  assert.equal(properties.database_discovery_scoped_paths, 1)
  assert.equal(properties.database_discovery_unresolved, 1)
  assert.equal(properties.database_discovery_limit_gaps, 1)
})

// Severity and confidence are two axes. SARIF has a field for each: `level` is
// how bad the finding is, `rank` is how urgent it is to act on. Collapsing both
// into `level` reported a claimed Critical to every machine consumer as a
// warning, which reads as "moderate" rather than as "unverified".

test('SARIF level carries claimed impact, not confidence-gated priority', () => {
  const sarif = renderSarif(run())
  const result = sarif.runs[0].results[0]
  assert.equal(result.properties.claimed_impact_severity, 'High')
  assert.equal(result.properties.effective_severity, 'Medium')
  assert.equal(
    result.level,
    'error',
    'a claimed High must reach a CI gate as error even while unproven',
  )
})

test('SARIF rank carries the confidence-gated priority', () => {
  const result = renderSarif(run()).runs[0].results[0]
  assert.equal(typeof result.rank, 'number')
  assert.ok(result.rank >= 0 && result.rank <= 100, 'rank is a SARIF 0-100 score')
  const confirmed = renderSarif(run({
    findings: [finding({
      claimed_impact_severity: 'High',
      effective_severity: 'High',
      verification_status: 'CONFIRMED',
      proof_tier: 'T1',
    })],
  })).runs[0].results[0]
  assert.ok(
    confirmed.rank > result.rank,
    'a demonstrated finding outranks the same claim left unproven',
  )
})

test('an unproven Critical outranks a confirmed Medium in SARIF level', () => {
  const critical = finding({
    candidate_id: 'cand:web:critical',
    claimed_impact_severity: 'Critical',
    effective_severity: 'Medium',
    verification_status: 'UNPROVEN',
    proof_tier: 'T0',
  })
  const moderate = finding({
    candidate_id: 'cand:web:moderate',
    claimed_impact_severity: 'Medium',
    effective_severity: 'Medium',
    verification_status: 'CONFIRMED',
    proof_tier: 'T1',
  })
  const results = renderSarif(run({ findings: [moderate, critical] })).runs[0].results
  const byId = new Map(results.map((entry) => [entry.properties.candidate_id, entry]))
  assert.equal(byId.get('cand:web:critical').level, 'error')
  assert.equal(byId.get('cand:web:moderate').level, 'warning')
})

test('the markdown findings list sorts by claimed impact before confidence', () => {
  // Both carry effective Medium, so the old comparator ties and falls through
  // to candidate_id. The ids are chosen so alphabetical order is the wrong
  // answer — otherwise this test passes without the comparator changing.
  const critical = finding({
    candidate_id: 'cand:web:zzz',
    title: 'Unproven critical claim',
    claimed_impact_severity: 'Critical',
    effective_severity: 'Medium',
  })
  const moderate = finding({
    candidate_id: 'cand:web:aaa',
    title: 'Confirmed moderate claim',
    claimed_impact_severity: 'Medium',
    effective_severity: 'Medium',
    verification_status: 'CONFIRMED',
    proof_tier: 'T1',
  })
  const report = renderMarkdownReport(run({ findings: [moderate, critical] }))
  assert.ok(
    report.indexOf('Unproven critical claim') < report.indexOf('Confirmed moderate claim'),
    'an unproven Critical belongs above a confirmed Medium, labelled rather than buried',
  )
})
