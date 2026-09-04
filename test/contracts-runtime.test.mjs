import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  ContractValidationError,
  finalizeFinding,
  finalizeRun,
  findingSchema,
  inferFindingStage,
  runSchema,
  storeProfileSchema,
  validateFinding,
  validateFindingTransition,
  validateRun,
  validateRunTransition,
} from '../scripts/lib/contracts.mjs'

const SHA_A = 'a'.repeat(64)
const SHA_B = 'b'.repeat(64)
const SHA_C = 'c'.repeat(64)

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
    proof_plan: 'Request subject A invoice as subject B and assert refusal plus marker absence',
    ...overrides,
  }
}

function triaged(overrides = {}) {
  return {
    ...stageOne(),
    effective_severity: 'High',
    triage_disposition: 'queued',
    ...overrides,
  }
}

function withExistence(overrides = {}) {
  return {
    ...triaged(),
    existence_check: {
      status: 'located',
      method: 'read src/routes/invoices.ts:88 and compare the quoted evidence verbatim',
    },
    ...overrides,
  }
}

function confirmed(overrides = {}) {
  return {
    ...withExistence(),
    proof_tier: 'T1',
    verification_status: 'CONFIRMED',
    artifact: {
      path: 'test/security/invoice-authz.test.mjs',
      sha256: SHA_A,
    },
    command: 'node --test test/security/invoice-authz.test.mjs',
    pre_result: {
      assertion: 'expected 403, received 200 containing CANARY-SUBJECT-A',
      path_reached: 'repo.findById spy observed invoice id 8814',
      control: 'the same request for subject B invoice returned 200 and its marker',
    },
    post_result: {
      status: 'passed',
      regressions: 'node --test: 149 passed, 0 failed',
    },
    ...overrides,
  }
}

function databaseFinding(overrides = {}) {
  return stageOne({
    candidate_id: 'database-native-authorization:4ba01c9f',
    lens: 'database-and-data-stores',
    topic: 'database-native-authorization-and-tenant-isolation',
    title: 'Runtime role can bypass the tenant policy',
    location: ['db/policies.sql:41'],
    evidence: 'ALTER TABLE invoices DISABLE ROW LEVEL SECURITY;',
    attack: 'Use the deployed runtime role to select another tenant invoice',
    impact: 'Reads all tenant invoices',
    reachable_from: 'POST /graphql',
    proof_plan: 'Run a two-principal transaction against an isolated database',
    store_context: {
      store_id: 'orders-primary',
      family: 'relational',
      engine: 'postgresql',
      engine_version: '16',
      deployment_variant: 'self-managed',
      adapter_id: 'postgresql',
      detection_evidence: [
        'compose.yml:19 postgres:16',
      ],
      confidence: 'high',
    },
    principal_path: {
      authenticated_principal: 'application user',
      session_principal: 'orders_runtime',
      effective_principal: 'orders_runtime',
      owner_or_definer: 'orders_owner',
      bypass_capabilities: [
        'inherited owner role',
      ],
    },
    enforcement_plane: 'database',
    semantic_sensitivity: 'version-sensitive',
    adapter_rule_id: 'db.authorization.postgresql.rls-bypass',
    semantic_source: {
      url: 'https://www.postgresql.org/docs/16/ddl-rowsecurity.html',
      verified_on: '2026-07-28',
    },
    ...overrides,
  })
}

function completedRun(overrides = {}) {
  return {
    schema_version: '1.0.0',
    run_id: 'run:20260728:6d02c1',
    state: 'COMPLETED',
    phase: 'FINALIZED',
    capability_mode: 'TEST_EXECUTION',
    created_at: '2026-07-28T10:00:00Z',
    completed_at: '2026-07-28T10:10:00Z',
    tool: {
      name: 'red-team-audit',
      version: '0.2.0',
      corpus_sha256: SHA_B,
    },
    plan_digest: SHA_A,
    policy_digest: SHA_A,
    lens_pack_digest: SHA_B,
    repository: {
      root: 'C:/workspace/example',
      tree_digest: SHA_C,
      dirty: 'unknown',
    },
    scope: {
      included_paths: ['src'],
      excluded_paths: [
        {
          path: 'vendor',
          reason: 'third-party generated source outside the agreed scope',
        },
      ],
    },
    activated_lenses: ['web-and-api'],
    jobs: [
      {
        job_id: 'lens:web-and-api',
        kind: 'LENS',
        lens: 'web-and-api',
        state: 'SUCCEEDED',
        candidate_ids: ['authz-object-level:a3f19c2e'],
      },
      {
        job_id: 'report:final',
        kind: 'REPORT',
        state: 'SUCCEEDED',
      },
    ],
    coverage: {
      inventory: ['src/routes/invoices.ts'],
      examined: ['src/routes/invoices.ts'],
      unexamined: [],
      lenses: [
        {
          lens: 'web-and-api',
          status: 'RAN',
          examined_paths: ['src/routes/invoices.ts'],
        },
      ],
      gaps: [],
    },
    store_profiles: [],
    findings: [confirmed()],
    errors: [],
    artifacts: {
      report: {
        path: 'audit/report.md',
        sha256: SHA_A,
      },
      sarif: {
        path: 'audit/results.sarif',
        sha256: SHA_A,
      },
      coverage: {
        path: 'audit/coverage.json',
        sha256: SHA_A,
      },
      proof_invoice_authz: {
        path: 'test/security/invoice-authz.test.mjs',
        sha256: SHA_A,
      },
    },
    ...overrides,
  }
}

function notAssessedDatabaseProfile(overrides = {}) {
  const categories = Object.fromEntries(
    ['replica', 'cdc', 'history', 'backup', 'export', 'cache'].map((category) => [
      category,
      { state: 'NOT_ASSESSED', reason: `${category} was not assessed` },
    ]),
  )
  const profile = {
    store_context: {
      store_id: 'orders-primary',
      family: 'relational',
      engine: 'postgresql',
      engine_version: '16',
      deployment_variant: 'self-managed',
      adapter_id: 'postgresql',
      detection_evidence: ['src/routes/invoices.ts:1 declares the store'],
      confidence: 'high',
    },
    engine_edition: 'community',
    compatibility_mode: 'native',
    engine_evidence_paths: ['src/routes/invoices.ts'],
    principal_evidence_paths: ['src/routes/invoices.ts'],
    tenancy: {
      model: 'unknown',
      tenant_attribute: 'unknown',
      claimed_guarantee: 'unknown',
      evidence: 'The bounded source does not establish tenancy semantics.',
      evidence_paths: ['src/routes/invoices.ts'],
    },
    principal_path: {
      authenticated_principal: 'unknown',
      session_principal: 'unknown',
      effective_principal: 'unknown',
      owner_or_definer: 'unknown',
      bypass_capabilities: [],
    },
    evidence_paths: ['src/routes/invoices.ts'],
    enforcement_paths: {
      inventory_closed: false,
      paths: [{
        name: 'runtime',
        state: 'NOT_ASSESSED',
        reason: 'runtime enforcement was not assessed',
      }],
    },
    copy_artifact_closure: {
      artifact_set_closed: false,
      closure_basis: 'copy artifacts were not enumerated',
      evidence_paths: ['src/routes/invoices.ts'],
      categories,
    },
    availability_budget: {
      state: 'NOT_ASSESSED',
      description: 'No bounded availability objective was found.',
      reason: 'availability was not assessed',
    },
    assumptions: [],
    coverage_state: 'NOT_ASSESSED',
    assessed_topics: [],
    coverage_gaps: [{
      area: 'store semantics',
      reason: 'the store remains inventory only',
    }],
  }
  return {
    ...profile,
    ...overrides,
    store_context: {
      ...profile.store_context,
      ...(overrides.store_context ?? {}),
    },
  }
}

function hasCode(validation, code) {
  return validation.errors.some((error) => error.code === code)
}

test('schemas identify Draft 2020-12 and validate a meaningful Stage 1 record', () => {
  assert.equal(findingSchema.$schema, 'https://json-schema.org/draft/2020-12/schema')
  assert.equal(runSchema.$schema, 'https://json-schema.org/draft/2020-12/schema')
  assert.equal(storeProfileSchema.$schema, 'https://json-schema.org/draft/2020-12/schema')

  const validation = validateFinding(stageOne(), { stage: 1 })
  assert.equal(validation.valid, true, JSON.stringify(validation.errors, null, 2))
  assert.equal(inferFindingStage(stageOne()), 1)
})

test('Stage 1 cannot omit the dedup boundary or substitute vague non-evidence', () => {
  const noTopic = stageOne()
  delete noTopic.topic
  assert.equal(validateFinding(noTopic).valid, false)

  const blankEvidence = stageOne({ evidence: '   ' })
  const validation = validateFinding(blankEvidence)
  assert.equal(validation.valid, false)
  assert.ok(validation.errors.some((error) => error.instancePath === '/evidence'))
})

test('triage transition preserves identity and claim semantics while allowing location union', () => {
  const before = stageOne()
  const after = triaged({
    location: [
      'src/routes/invoices.ts:88',
      'src/routes/invoice-export.ts:31',
    ],
  })
  assert.equal(validateFindingTransition(before, after).valid, true)

  const rewrittenClaim = {
    ...after,
    claimed_impact_severity: 'Medium',
  }
  const bypass = validateFindingTransition(before, rewrittenClaim)
  assert.equal(bypass.valid, false)
  assert.ok(hasCode(bypass, 'CLAIM_FIELD_CHANGED'))

  const replacedLocation = triaged({
    location: ['src/routes/invoice-export.ts:31'],
  })
  assert.ok(hasCode(validateFindingTransition(before, replacedLocation), 'LOCATION_REWRITTEN'))
})

test('existence must be its own transition before a proof argument', () => {
  const direct = validateFindingTransition(triaged(), confirmed())
  assert.equal(direct.valid, false)
  assert.ok(hasCode(direct, 'EXISTENCE_CHECK_NOT_FIRST'))

  const existence = withExistence()
  const existenceTransition = validateFindingTransition(triaged(), existence)
  assert.equal(existenceTransition.valid, true, JSON.stringify(existenceTransition.errors, null, 2))

  const proofTransition = validateFindingTransition(existence, confirmed())
  assert.equal(proofTransition.valid, true, JSON.stringify(proofTransition.errors, null, 2))
})

test('finalization freezes a valid proof-backed High finding', () => {
  const final = finalizeFinding(confirmed())
  assert.equal(final.verification_status, 'CONFIRMED')
  assert.equal(Object.isFrozen(final), true)
  assert.equal(Object.isFrozen(final.pre_result), true)
})

test('severity and proof caps reject optimistic grading', () => {
  const unreachableHigh = triaged({ reachable_from: 'unknown' })
  assert.ok(hasCode(validateFinding(unreachableHigh), 'REACHABILITY_CAP'))

  const staticHigh = {
    ...withExistence(),
    proof_tier: 'T0',
    verification_status: 'UNPROVEN',
    blocking_reason: 'static mode cannot execute the harness',
  }
  const staticValidation = validateFinding(staticHigh)
  assert.equal(staticValidation.valid, false)
  assert.ok(hasCode(staticValidation, 'PROOF_TIER_CAP'))
  assert.ok(hasCode(staticValidation, 'VERIFICATION_CAP'))

  assert.throws(
    () => finalizeFinding(triaged()),
    (error) => error instanceof ContractValidationError
      && error.errors.some((entry) => entry.code === 'UNFINISHED_PROOF'),
  )
})

test('dispositions require explicit drop and merge lineage', () => {
  const droppedWithoutReason = triaged({ triage_disposition: 'dropped' })
  assert.equal(validateFinding(droppedWithoutReason).valid, false)

  const mergedWithoutTarget = triaged({ triage_disposition: 'merged' })
  assert.equal(validateFinding(mergedWithoutTarget).valid, false)

  const selfMerge = triaged({
    triage_disposition: 'merged',
    merged_into_candidate_id: 'authz-object-level:a3f19c2e',
  })
  const validation = validateFinding(selfMerge)
  assert.equal(validation.valid, false)
  assert.ok(hasCode(validation, 'SELF_MERGE'))
})

test('database topics require one profiled store, principal path, and semantic source', () => {
  const missingContext = stageOne({
    topic: 'database-native-authorization-and-tenant-isolation',
  })
  assert.equal(validateFinding(missingContext).valid, false)

  const database = databaseFinding()
  assert.equal(validateFinding(database).valid, true)

  const missingSource = databaseFinding()
  delete missingSource.semantic_source
  assert.equal(validateFinding(missingSource).valid, false)
})

test('inventory-only and unresolved database profiles cannot manufacture a clearance', () => {
  const inventoryOnly = {
    ...databaseFinding({
      store_context: {
        ...databaseFinding().store_context,
        engine_version: 'unknown',
        deployment_variant: 'unknown',
        adapter_id: 'inventory-only',
      },
      semantic_sensitivity: 'stable',
      adapter_rule_id: undefined,
      semantic_source: undefined,
    }),
    effective_severity: 'Medium',
    triage_disposition: 'queued',
    existence_check: {
      status: 'located',
      method: 'read db/policies.sql:41',
    },
    proof_tier: 'T0',
    verification_status: 'DISPROVED',
    reason: 'generic inventory found no matching policy pattern',
  }
  delete inventoryOnly.adapter_rule_id
  delete inventoryOnly.semantic_source

  const validation = validateFinding(inventoryOnly)
  assert.equal(validation.valid, false)
  assert.ok(
    hasCode(validation, 'INVENTORY_ONLY_CLEARANCE')
      || validation.errors.some((error) => error.instancePath === '/verification_status'),
  )
})

test('unresolved principal phrases cannot manufacture a database clearance', () => {
  for (const effectivePrincipal of [
    'unknown effective principal',
    'effective principal not known',
    'N/A',
    '??',
  ]) {
    const database = databaseFinding({
      principal_path: {
        ...databaseFinding().principal_path,
        effective_principal: effectivePrincipal,
      },
      effective_severity: 'Medium',
      triage_disposition: 'queued',
      existence_check: {
        status: 'located',
        method: 'read db/policies.sql:41',
        observed: 'The policy artifact exists, but the effective role was not established.',
      },
      proof_tier: 'T0',
      verification_status: 'DISPROVED',
      disproof_basis: 'falsified-code-premise',
      reason: 'the provider asserted that the code premise was false',
    })
    const validation = validateFinding(database)
    assert.equal(validation.valid, false, effectivePrincipal)
    assert.ok(
      hasCode(validation, 'UNRESOLVED_DATABASE_PRINCIPAL_CLEARANCE'),
      effectivePrincipal,
    )
  }
})

test('direct run validation re-routes store adapters and binds profile evidence to database coverage', () => {
  const base = completedRun({
    state: 'COMPLETE_WITH_GAPS',
    activated_lenses: ['database-and-data-stores', 'web-and-api'],
    jobs: [
      {
        job_id: 'lens:database-and-data-stores',
        kind: 'LENS',
        lens: 'database-and-data-stores',
        state: 'SUCCEEDED',
      },
      ...completedRun().jobs,
    ],
    coverage: {
      ...completedRun().coverage,
      lenses: [
        {
          lens: 'database-and-data-stores',
          status: 'RAN',
          examined_paths: ['src/routes/invoices.ts'],
        },
        ...completedRun().coverage.lenses,
      ],
    },
  })

  const mismatchedAdapter = structuredClone(base)
  mismatchedAdapter.store_profiles = [notAssessedDatabaseProfile({
    store_context: { adapter_id: 'mysql' },
  })]
  assert.ok(
    hasCode(validateRun(mismatchedAdapter), 'DATABASE_PROFILE_ADAPTER_MISMATCH'),
  )

  const unexaminedEvidence = structuredClone(base)
  unexaminedEvidence.store_profiles = [notAssessedDatabaseProfile({
    store_context: {
      engine: 'unknown',
      engine_version: 'unknown',
      deployment_variant: 'unknown',
      adapter_id: 'inventory-only',
    },
    evidence_paths: ['db/not-in-inventory.sql'],
  })]
  const evidenceValidation = validateRun(unexaminedEvidence)
  assert.ok(hasCode(evidenceValidation, 'DATABASE_PROFILE_EVIDENCE_OUT_OF_SCOPE'))

  const unboundDimension = structuredClone(base)
  unboundDimension.store_profiles = [notAssessedDatabaseProfile({
    engine_evidence_paths: ['db/not-in-profile-denominator.sql'],
  })]
  assert.ok(
    hasCode(validateRun(unboundDimension), 'DATABASE_PROFILE_UNDECLARED_EVIDENCE'),
  )

  const unboundDetection = structuredClone(base)
  unboundDetection.store_profiles = [notAssessedDatabaseProfile({
    store_context: {
      detection_evidence: ['trust me'],
    },
  })]
  assert.ok(
    hasCode(
      validateRun(unboundDetection),
      'DATABASE_PROFILE_UNBOUND_DETECTION_EVIDENCE',
    ),
  )
})

test('run finalization binds capability, coverage denominator, and hashed report', () => {
  const run = completedRun()
  const validation = validateRun(run)
  assert.equal(validation.valid, true, JSON.stringify(validation.errors, null, 2))
  for (const field of ['tool', 'plan_digest', 'store_profiles']) {
    const missing = structuredClone(run)
    delete missing[field]
    assert.equal(
      validateRun(missing).valid,
      false,
      `run schema must require ${field}`,
    )
  }

  const final = finalizeRun(run)
  assert.equal(Object.isFrozen(final), true)
  assert.equal(Object.isFrozen(final.coverage), true)

  const staticBypass = completedRun({ capability_mode: 'STATIC' })
  const bypassValidation = validateRun(staticBypass)
  assert.equal(bypassValidation.valid, false)
  assert.ok(hasCode(bypassValidation, 'CAPABILITY_TIER_BYPASS'))
})

test('a coverage hole cannot be finalized as COMPLETED', () => {
  const coverage = {
    ...completedRun().coverage,
    inventory: [
      'src/routes/invoices.ts',
      'src/routes/admin.ts',
    ],
    unexamined: [
      {
        path: 'src/routes/admin.ts',
        reason: 'agent job timed out',
      },
    ],
  }
  const falseComplete = completedRun({ coverage })
  assert.throws(
    () => finalizeRun(falseComplete),
    (error) => error instanceof ContractValidationError
      && error.errors.some((entry) => entry.code === 'FALSE_COMPLETE_STATE'),
  )

  const honest = completedRun({ state: 'COMPLETE_WITH_GAPS', coverage })
  assert.equal(finalizeRun(honest).state, 'COMPLETE_WITH_GAPS')
})

test('every terminal run closes its jobs and required analysis failures are not reportable gaps', () => {
  for (const state of ['COMPLETED', 'COMPLETE_WITH_GAPS', 'ABORTED', 'FAILED']) {
    const terminalWithPending = completedRun({
      state,
      jobs: [{
        job_id: 'lens:web-and-api',
        kind: 'LENS',
        lens: 'web-and-api',
        state: 'PENDING',
      }],
    })
    const validation = validateRun(terminalWithPending)
    assert.equal(validation.valid, false)
    assert.ok(hasCode(validation, 'NONTERMINAL_JOB_IN_TERMINAL_RUN'))
  }

  const reportableRequiredFailure = completedRun({
    state: 'COMPLETE_WITH_GAPS',
    jobs: [
      completedRun().jobs[0],
      {
        job_id: 'triage:business-logic',
        kind: 'TRIAGE',
        lens: 'business-logic',
        state: 'FAILED',
        reason: 'provider crashed',
      },
      completedRun().jobs[1],
    ],
    errors: [{
      error_id: 'triage:business-logic:error:1',
      phase: 'TRIAGE',
      code: 'PROVIDER_CRASH',
      message: 'provider crashed',
      recoverable: false,
      job_id: 'triage:business-logic',
    }],
  })
  const validation = validateRun(reportableRequiredFailure)
  assert.equal(validation.valid, false)
  assert.ok(hasCode(validation, 'REQUIRED_JOB_FAILURE_MUST_FAIL_RUN'))
})

test('run state transitions preserve the policy and repository snapshot', () => {
  const running = completedRun({
    state: 'RUNNING',
    phase: 'RECON',
    findings: [],
    jobs: [
      {
        job_id: 'recon:root',
        kind: 'RECON',
        state: 'PENDING',
      },
    ],
    coverage: {
      inventory: ['src/routes/invoices.ts'],
      examined: [],
      unexamined: [],
      lenses: [],
      gaps: [],
    },
    artifacts: {},
  })
  delete running.completed_at

  const fanout = {
    ...structuredClone(running),
    phase: 'FANOUT',
    findings: [],
    jobs: [
      {
        ...running.jobs[0],
        state: 'RUNNING',
      },
    ],
  }
  const legal = validateRunTransition(running, fanout)
  assert.equal(legal.valid, true, JSON.stringify(legal.errors, null, 2))

  const withGap = structuredClone(running)
  withGap.coverage.gaps = [{
    area: 'db/replica.conf',
    reason: 'replica authorization was not assessed',
  }]
  const erasedGap = structuredClone(withGap)
  erasedGap.coverage.gaps = []
  assert.ok(hasCode(
    validateRunTransition(withGap, erasedGap),
    'COVERAGE_GAP_HISTORY_REWRITTEN',
  ))

  const changedPolicy = {
    ...structuredClone(fanout),
    policy_digest: SHA_C,
  }
  assert.ok(hasCode(validateRunTransition(fanout, changedPolicy), 'RUN_PROVENANCE_CHANGED'))

  const forgedSchedule = structuredClone(running)
  forgedSchedule.jobs.push({
    job_id: 'proof-verification:authz-object-level:ghost',
    kind: 'PROOF',
    state: 'PENDING',
    candidate_ids: ['authz-object-level:ghost'],
  })
  assert.ok(hasCode(
    validateRunTransition(running, forgedSchedule),
    'ILLEGAL_JOB_SCHEDULE',
  ))

  const manufacturedCoverage = structuredClone(running)
  manufacturedCoverage.coverage.examined = ['src/routes/invoices.ts']
  manufacturedCoverage.coverage.lenses = [{
    lens: 'web-and-api',
    status: 'RAN',
    examined_paths: ['src/routes/invoices.ts'],
  }]
  const manufactured = validateRunTransition(running, manufacturedCoverage)
  assert.equal(manufactured.valid, false)
  assert.ok(hasCode(manufactured, 'EXAMINED_COVERAGE_NOT_JOB_BACKED'))
  assert.ok(hasCode(manufactured, 'LENS_COVERAGE_ADDED'))

  const covered = structuredClone(manufacturedCoverage)
  const rewound = structuredClone(covered)
  rewound.coverage.examined = []
  rewound.coverage.lenses[0] = {
    lens: 'web-and-api',
    status: 'NOT_ASSESSED',
    examined_paths: [],
    reason: 'coverage was reset',
  }
  const regressed = validateRunTransition(covered, rewound)
  assert.equal(regressed.valid, false)
  assert.ok(hasCode(regressed, 'EXAMINED_COVERAGE_REMOVED'))
  assert.ok(hasCode(regressed, 'LENS_COVERAGE_STATUS_REWRITTEN'))
  assert.ok(hasCode(regressed, 'LENS_EXAMINED_PATH_REMOVED'))

  const reopened = {
    ...structuredClone(completedRun()),
    state: 'RUNNING',
    phase: 'COMPLETENESS',
  }
  const terminalBypass = validateRunTransition(completedRun(), reopened)
  assert.equal(terminalBypass.valid, false)
  assert.ok(hasCode(terminalBypass, 'ILLEGAL_RUN_STATE_TRANSITION'))

  const injected = structuredClone(completedRun())
  injected.findings.push(stageOne({
    candidate_id: 'authz-object-level:late-injection',
  }))
  const terminalInjection = validateRunTransition(completedRun(), injected)
  assert.equal(terminalInjection.valid, false)
  assert.ok(
    hasCode(terminalInjection, 'TERMINAL_RUN_MUTATION')
      || hasCode(terminalInjection, 'FINDING_ADDED_TO_TERMINAL_RUN'),
  )
})

test('run transition indexes job-backed examined paths without repeated linear scans', () => {
  const paths = Array.from(
    { length: 4096 },
    (_, index) => `src/generated/file-${String(index).padStart(4, '0')}.ts`,
  )
  const running = completedRun({
    state: 'RUNNING',
    phase: 'FANOUT',
    findings: [],
    scope: {
      included_paths: paths,
      excluded_paths: [],
    },
    activated_lenses: ['web-and-api'],
    jobs: [{
      job_id: 'lens:web-and-api',
      kind: 'LENS',
      lens: 'web-and-api',
      state: 'RUNNING',
    }],
    coverage: {
      inventory: paths,
      examined: [],
      unexamined: [],
      lenses: [{
        lens: 'web-and-api',
        status: 'NOT_ASSESSED',
        examined_paths: [],
        reason: 'audit job has not run',
      }],
      gaps: [],
    },
    store_profiles: [],
    artifacts: {},
  })
  delete running.completed_at

  const completedPaths = new Proxy([...paths], {
    get(target, property, receiver) {
      if (property === 'includes') {
        throw new Error('examined path validation must use a pre-indexed set')
      }
      return Reflect.get(target, property, receiver)
    },
  })
  const completed = structuredClone(running)
  completed.jobs[0].state = 'SUCCEEDED'
  completed.jobs[0].input_sha256 = SHA_A
  completed.jobs[0].producer = {
    name: 'unit-test-provider',
    version: '1.0.0',
    instance_id: 'unit-test-provider:instance-1',
  }
  completed.coverage.examined = [...paths]
  completed.coverage.lenses[0] = {
    lens: 'web-and-api',
    status: 'RAN',
    examined_paths: completedPaths,
  }

  const validation = validateRunTransition(running, completed)
  assert.equal(validation.valid, true, JSON.stringify(validation.errors, null, 2))
})

test('a direct-to-terminal transition cannot batch multiple provider results', () => {
  const previous = completedRun({
    state: 'RUNNING',
    phase: 'REPORT',
    activated_lenses: ['web-and-api', 'business-logic'],
    jobs: [
      {
        job_id: 'lens:web-and-api',
        kind: 'LENS',
        lens: 'web-and-api',
        state: 'RUNNING',
        candidate_ids: [],
      },
      {
        job_id: 'lens:business-logic',
        kind: 'LENS',
        lens: 'business-logic',
        state: 'RUNNING',
        candidate_ids: [],
      },
      {
        job_id: 'report:final',
        kind: 'REPORT',
        state: 'RUNNING',
      },
    ],
    coverage: {
      inventory: ['src/routes/invoices.ts'],
      examined: ['src/routes/invoices.ts'],
      unexamined: [],
      lenses: [
        {
          lens: 'web-and-api',
          status: 'RAN',
          examined_paths: ['src/routes/invoices.ts'],
        },
        {
          lens: 'business-logic',
          status: 'RAN',
          examined_paths: ['src/routes/invoices.ts'],
        },
      ],
      gaps: [],
    },
    findings: [],
  })
  delete previous.completed_at

  const next = structuredClone(previous)
  next.state = 'COMPLETED'
  next.phase = 'FINALIZED'
  next.completed_at = '2026-07-28T10:10:00Z'
  for (const job of next.jobs) {
    job.state = 'SUCCEEDED'
    if (job.kind === 'REPORT') continue
    job.input_sha256 = SHA_A
    job.producer = {
      name: 'unit-test-provider',
      version: '1.0.0',
      instance_id: `unit-test-provider:${job.lens}`,
    }
  }

  assert.equal(
    validateRun(previous).valid,
    true,
    JSON.stringify(validateRun(previous).errors, null, 2),
  )
  assert.equal(
    validateRun(next).valid,
    true,
    JSON.stringify(validateRun(next).errors, null, 2),
  )
  const validation = validateRunTransition(previous, next)
  assert.equal(validation.valid, false)
  assert.ok(hasCode(validation, 'COMPOUND_PROVIDER_RESULT_TRANSITION'))
})

test('a later transition cannot append a store profile without a database result', () => {
  const previous = completedRun({
    state: 'RUNNING',
    phase: 'FANOUT',
    activated_lenses: ['database-and-data-stores', 'web-and-api'],
    jobs: [
      {
        job_id: 'lens:database-and-data-stores',
        kind: 'LENS',
        lens: 'database-and-data-stores',
        state: 'SUCCEEDED',
        candidate_ids: [],
      },
      {
        job_id: 'lens:web-and-api',
        kind: 'LENS',
        lens: 'web-and-api',
        state: 'RUNNING',
        candidate_ids: [],
      },
    ],
    coverage: {
      inventory: ['src/routes/invoices.ts'],
      examined: ['src/routes/invoices.ts'],
      unexamined: [],
      lenses: [
        {
          lens: 'database-and-data-stores',
          status: 'RAN',
          examined_paths: ['src/routes/invoices.ts'],
        },
        {
          lens: 'web-and-api',
          status: 'NOT_ASSESSED',
          examined_paths: [],
          reason: 'the web lens result has not been received',
        },
      ],
      gaps: [],
    },
    store_profiles: [notAssessedDatabaseProfile()],
    findings: [],
    artifacts: {},
  })
  delete previous.completed_at

  const next = structuredClone(previous)
  next.store_profiles.push(notAssessedDatabaseProfile({
    store_context: { store_id: 'billing-primary' },
  }))

  assert.equal(
    validateRun(previous).valid,
    true,
    JSON.stringify(validateRun(previous).errors, null, 2),
  )
  assert.equal(
    validateRun(next).valid,
    true,
    JSON.stringify(validateRun(next).errors, null, 2),
  )
  const validation = validateRunTransition(previous, next)
  assert.equal(validation.valid, false)
  assert.ok(hasCode(validation, 'STORE_PROFILE_DELTA_NOT_JOB_BOUND'))
})

test('run merge lineage must resolve within the topic and cannot cycle', () => {
  const survivor = confirmed()
  const merged = {
    ...confirmed({
      candidate_id: 'authz-object-level:b82d1190',
      location: ['src/routes/invoice-export.ts:31'],
    }),
    triage_disposition: 'merged',
    merged_into_candidate_id: survivor.candidate_id,
  }
  const run = completedRun({
    findings: [survivor, merged],
    jobs: [
      {
        ...completedRun().jobs[0],
        candidate_ids: [survivor.candidate_id, merged.candidate_id],
      },
      completedRun().jobs[1],
    ],
  })
  assert.equal(finalizeRun(run).findings.length, 2)

  const missingTarget = completedRun({
    findings: [
      {
        ...merged,
        merged_into_candidate_id: 'authz-object-level:missing',
      },
    ],
  })
  const validation = validateRun(missingTarget)
  assert.equal(validation.valid, false)
  assert.ok(hasCode(validation, 'MISSING_MERGE_TARGET'))
})

test('attack-chain component graphs cannot contain cycles', () => {
  const leftId = 'authz-object-level:chain-left'
  const rightId = 'authz-object-level:chain-right'
  const left = confirmed({
    candidate_id: leftId,
    triage_disposition: 'elevated',
    raised_by: 'attack-chaining',
    component_finding_ids: [rightId, leftId],
  })
  const right = confirmed({
    candidate_id: rightId,
    triage_disposition: 'elevated',
    raised_by: 'attack-chaining',
    component_finding_ids: [leftId, rightId],
  })
  const current = completedRun({
    findings: [left, right],
    jobs: [
      {
        ...completedRun().jobs[0],
        candidate_ids: [leftId, rightId],
      },
      completedRun().jobs[1],
    ],
  })
  const validation = validateRun(current)
  assert.equal(validation.valid, false)
  assert.ok(hasCode(validation, 'CHAIN_CYCLE'))
})

test('run job and error identities are unique', () => {
  const base = completedRun()
  const current = completedRun({
    jobs: [base.jobs[0], base.jobs[0], base.jobs[1]],
    errors: [
      {
        error_id: 'provider:error:1',
        phase: 'FANOUT',
        code: 'PROVIDER_ERROR',
        message: 'first',
        recoverable: true,
      },
      {
        error_id: 'provider:error:1',
        phase: 'FANOUT',
        code: 'PROVIDER_ERROR',
        message: 'second',
        recoverable: true,
      },
    ],
    state: 'COMPLETE_WITH_GAPS',
  })
  const validation = validateRun(current)
  assert.ok(hasCode(validation, 'DUPLICATE_JOB_ID'))
  assert.ok(hasCode(validation, 'DUPLICATE_ERROR_ID'))
})
