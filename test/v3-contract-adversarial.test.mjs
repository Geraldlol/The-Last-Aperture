import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import {
  mkdir,
  mkdtemp,
  rm,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  after,
  before,
  test,
} from 'node:test'
import Ajv2020 from 'ajv/dist/2020.js'
import {
  databaseConformanceEvidenceSchema,
  databaseDiscoverySchema,
  findingSchema,
  runSchema,
  storeContributionSchema,
  storeProfileSchema,
  validateRun,
  validateRunTransition,
} from '../scripts/lib/contracts.mjs'
import { refreshCategoryDenominators } from '../scripts/lib/coverage-model.mjs'
import {
  applyJobResult,
  beginJob,
} from '../scripts/lib/job-protocol.mjs'
import { createRunPlan } from '../scripts/lib/run-engine.mjs'

const CREATED_AT = new Date('2026-07-29T16:00:00.000Z')
const DOMAIN_LENS = 'v3-adversarial-domain'
const RESULT_DIGEST = 'a'.repeat(64)
const UNKNOWN_GAP_ID = `coverage-gap:sha256:${'f'.repeat(64)}`

let fixtureRoot
let plannedRun
let plannedSidecars

const rawSchemaAjv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})
rawSchemaAjv.addSchema(findingSchema)
rawSchemaAjv.addSchema(storeProfileSchema)
rawSchemaAjv.addSchema(storeContributionSchema)
rawSchemaAjv.addSchema(databaseDiscoverySchema)
rawSchemaAjv.addSchema(databaseConformanceEvidenceSchema)
rawSchemaAjv.addSchema(runSchema)
const validateRawRunSchema = rawSchemaAjv.getSchema(runSchema.$id)

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value)
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`
  }
  if (value !== null && typeof value === 'object') {
    return `{${
      Object.keys(value)
        .filter((key) => value[key] !== undefined)
        .sort((left, right) => left.localeCompare(right, 'en'))
        .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
        .join(',')
    }}`
  }
  throw new TypeError(`cannot canonicalize ${typeof value}`)
}

function coverageMeasurementSha256(measurement) {
  const material = {
    round: measurement.round,
    applicable_lens_file_pairs: measurement.applicable_lens_file_pairs,
    examined_lens_file_pairs: measurement.examined_lens_file_pairs,
    uncovered_lens_file_pairs: measurement.uncovered_lens_file_pairs,
    uncovered_shards: measurement.uncovered_shards,
  }
  return createHash('sha256')
    .update(canonicalJson(material), 'utf8')
    .digest('hex')
}

function freshRun() {
  return structuredClone(plannedRun)
}

function errorCodes(validation) {
  return new Set(validation.errors.map(({ code }) => code))
}

function assertRejected(run, expectedCodes) {
  const validation = validateRun(run)
  assert.equal(
    validation.valid,
    false,
    'forged v3 run unexpectedly satisfied the contract',
  )
  const codes = errorCodes(validation)
  for (const code of expectedCodes) {
    assert.ok(
      codes.has(code),
      `expected ${code}; received:\n${JSON.stringify(validation.errors, null, 2)}`,
    )
  }
  return validation
}

function firstInitialShard(run) {
  const row = run.coverage.shards[0]
  assert.ok(row, 'fixture must produce an initial coverage shard')
  return row
}

function rewriteShardEverywhere(run, row, mutate) {
  mutate(row.shard)
  for (const job of run.jobs) {
    if (
      job.job_id === row.job_id
      || (
        job.kind === 'LENS'
        && job.parent_job_id === row.job_id
      )
    ) {
      assert.ok(job.shard, `expected ${job.job_id} to retain shard metadata`)
      mutate(job.shard)
    }
  }
}

async function writeFixture(root) {
  const repository = join(root, 'repository')
  const lenses = join(root, 'lenses')
  await Promise.all([
    mkdir(join(repository, 'src'), { recursive: true }),
    mkdir(join(repository, 'tests'), { recursive: true }),
    mkdir(join(repository, 'docs'), { recursive: true }),
    mkdir(join(repository, 'assets'), { recursive: true }),
    mkdir(lenses, { recursive: true }),
  ])

  await Promise.all([
    writeFile(join(repository, 'src', 'a.js'), 'export const a = 1\n'),
    writeFile(join(repository, 'src', 'b.js'), 'export const b = 2\n'),
    writeFile(
      join(repository, 'src', 'db.js'),
      [
        "import pg from 'pg'",
        'const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL })',
        "export const loadUser = (id) => pool.query('select * from users where id = $1', [id])",
        '',
      ].join('\n'),
    ),
    writeFile(
      join(repository, 'src', 'client.generated.js'),
      '// @generated\nexport const generated = true\n',
    ),
    writeFile(
      join(repository, 'package.json'),
      `${JSON.stringify({
        name: 'v3-contract-fixture',
        private: true,
        dependencies: { pg: '8.16.3' },
      }, null, 2)}\n`,
    ),
    writeFile(join(repository, 'tests', 'app.test.js'), 'export const testOnly = true\n'),
    writeFile(join(repository, 'docs', 'README.md'), '# Fixture\n'),
    writeFile(
      join(repository, 'assets', 'opaque.bin'),
      Buffer.from([0, 1, 2, 3, 4]),
    ),
    writeFile(join(lenses, `${DOMAIN_LENS}.md`), `---
name: ${DOMAIN_LENS}
title: V3 adversarial coverage domain
runs_in: fanout
activates_on:
  paths: ["src/**"]
  signals: []
owns: [v3-contract-coverage]
defers: {}
---

## Scope

Exercise v3 sharding and closure invariants.
`),
    writeFile(join(lenses, 'triage.md'), `---
name: v3-adversarial-triage
title: V3 adversarial triage
runs_in: triage
activates_on:
  paths: []
  signals: []
owns: []
defers: {}
---

## Scope

Exercise preplanned closure triage.
`),
    writeFile(join(lenses, 'completeness.md'), `---
name: completeness
title: Coverage completeness
runs_in: triage
activates_on:
  paths: []
  signals: []
owns: []
defers: {}
---

## Scope

Measure coverage closure.
`),
  ])

  return { repository, lenses }
}

before(async () => {
  fixtureRoot = await mkdtemp(join(tmpdir(), 'red-team-v3-contracts-'))
  const { repository, lenses } = await writeFixture(fixtureRoot)
  const plan = await createRunPlan({
    targetRoot: repository,
    lensDirectory: lenses,
    createdAt: CREATED_AT,
    requireSourceClosure: true,
    maxClosureRounds: 2,
    shardOptions: {
      maxFiles: 2,
      maxBytes: 512,
    },
  })
  plannedRun = plan.run
  plannedSidecars = plan.jobSidecars
})

after(async () => {
  if (fixtureRoot) await rm(fixtureRoot, { recursive: true, force: true })
})

test('an untouched controller-created v7 plan satisfies the run contract', () => {
  assert.equal(plannedRun.schema_version, '7.0.0')
  assert.ok(plannedRun.coverage.shards.length >= 2)
  assert.ok(plannedRun.database_discovery.nodes.length > 0)

  const validation = validateRun(freshRun())
  assert.equal(
    validation.valid,
    true,
    JSON.stringify(validation.errors, null, 2),
  )
})

test('the raw v3 run schema rejects a malformed database discovery graph', () => {
  const run = freshRun()
  run.database_discovery = { totally: 'invalid' }

  assert.equal(validateRawRunSchema(run), false)
  assert.ok(
    validateRawRunSchema.errors.some(({ instancePath }) =>
      instancePath.startsWith('/database_discovery')),
    JSON.stringify(validateRawRunSchema.errors, null, 2),
  )
})

test('typed file and byte denominators are recomputed instead of trusted', async (t) => {
  await t.test('forged aggregate byte total', () => {
    const run = freshRun()
    const canonical = run.coverage.denominators.find(
      ({ class: coverageClass }) => coverageClass === 'CANONICAL_SOURCE',
    )
    assert.ok(canonical)
    canonical.bytes_total += 1

    assertRejected(run, ['COVERAGE_DENOMINATOR_MISMATCH'])
  })

  await t.test('forged typed inventory byte count', () => {
    const run = freshRun()
    const record = run.coverage.inventory_records.find(
      ({ coverage_class: coverageClass }) =>
        coverageClass === 'CANONICAL_SOURCE',
    )
    assert.ok(record)
    record.size += 1

    assertRejected(run, ['COVERAGE_DENOMINATOR_MISMATCH'])
  })
})

test('coverage class and legacy category cannot conflict', () => {
  const run = freshRun()
  const record = run.coverage.inventory_records.find(
    ({ coverage_class: coverageClass }) =>
      coverageClass === 'CANONICAL_SOURCE',
  )
  assert.ok(record)
  record.category = 'docs'

  assertRejected(run, ['COVERAGE_INVENTORY_RECORD_INVALID'])
})

test('shard scope, digest, count, and whole-shard retry metadata are sealed', async (t) => {
  await t.test('scope removal', () => {
    const run = freshRun()
    const row = firstInitialShard(run)
    row.scoped_files = row.scoped_files.slice(1)

    assertRejected(run, ['COVERAGE_SHARD_METADATA_INVALID'])
  })

  await t.test('correlated digest rewrite', () => {
    const run = freshRun()
    const row = firstInitialShard(run)
    rewriteShardEverywhere(run, row, (shard) => {
      shard.scope_sha256 = '0'.repeat(64)
    })

    assertRejected(run, ['COVERAGE_SHARD_METADATA_INVALID'])
  })

  await t.test('correlated count rewrite', () => {
    const run = freshRun()
    const row = firstInitialShard(run)
    rewriteShardEverywhere(run, row, (shard) => {
      shard.count += 1
    })

    assertRejected(run, ['COVERAGE_SHARD_SEQUENCE_INVALID'])
  })

  await t.test('retry narrowed away from its parent shard', () => {
    const run = freshRun()
    const row = firstInitialShard(run)
    const retry = run.jobs.find((job) =>
      job.kind === 'LENS'
      && job.closure_round === 1
      && job.parent_job_id === row.job_id)
    assert.ok(retry)
    retry.shard.file_count -= 1

    assertRejected(run, ['COVERAGE_RETRY_TEMPLATE_MISSING'])
  })
})

test('structured and resolved coverage gap IDs cannot be invented', async (t) => {
  await t.test('invented structured gap identity', () => {
    const run = freshRun()
    const path = run.coverage.inventory_records[0].path
    run.coverage.gaps.push({
      area: `${DOMAIN_LENS}:${path}`,
      reason: 'forged lens/file omission',
      gap_id: UNKNOWN_GAP_ID,
      kind: 'LENS_FILE',
      lens: DOMAIN_LENS,
      path,
    })

    assertRejected(run, ['COVERAGE_GAP_ID_INVALID'])
  })

  await t.test('resolution for a gap absent from history', () => {
    const run = freshRun()
    run.coverage.resolved_gap_ids.push(UNKNOWN_GAP_ID)

    assertRejected(run, ['COVERAGE_GAP_RESOLUTION_UNKNOWN'])
  })

  await t.test('a schema-valid gap whose identity cannot be derived', () => {
    const run = freshRun()
    run.coverage.gaps.push({
      area: `${DOMAIN_LENS}:C:/outside/repository.js`,
      reason: 'hand-edited absolute inventory path',
      gap_id: UNKNOWN_GAP_ID,
      kind: 'LENS_FILE',
      lens: DOMAIN_LENS,
      path: 'C:/outside/repository.js',
    })
    assert.ok(
      validateRawRunSchema(run),
      `run.schema.json must still accept the gap:\n${
        JSON.stringify(validateRawRunSchema.errors, null, 2)}`,
    )

    let validation
    assert.doesNotThrow(
      () => {
        validation = validateRun(run)
      },
      'validateRun must reject a semantically invalid gap, not raise out of the validator',
    )
    assert.equal(validation.valid, false)
    assert.ok(errorCodes(validation).has('COVERAGE_GAP_INVALID'))
  })
})

test('a self-consistent forged CONVERGED measurement hash is remeasured', () => {
  const run = freshRun()
  const applicable = run.coverage.lenses.reduce(
    (total, row) => total + (row.applicable_paths?.length ?? 0),
    0,
  )
  assert.ok(applicable > 0)

  const forged = {
    round: 0,
    status: 'CONVERGED',
    applicable_lens_file_pairs: applicable,
    examined_lens_file_pairs: applicable,
    uncovered_lens_file_pairs: 0,
    uncovered_shards: [],
  }
  forged.measurement_sha256 = coverageMeasurementSha256(forged)
  run.coverage.closure.round = 0
  run.coverage.closure.status = 'CONVERGED'
  run.coverage.closure.history = [forged]

  const validation = assertRejected(
    run,
    ['COVERAGE_CLOSURE_TERMINAL_INVALID'],
  )
  assert.equal(
    errorCodes(validation).has('COVERAGE_MEASUREMENT_DIGEST_INVALID'),
    false,
    'the forged hash should be internally valid so fresh remeasurement is what rejects it',
  )
})

test('a successful shard cannot inflate coverage with another shard path', () => {
  const run = freshRun()
  const domainCoverage = run.coverage.lenses.find(
    ({ lens }) => lens === DOMAIN_LENS,
  )
  assert.ok(domainCoverage)
  const shard = run.coverage.shards.find(({ lens, scoped_files: scopedFiles }) =>
    lens === DOMAIN_LENS
    && domainCoverage.applicable_paths.some((path) => !scopedFiles.includes(path)))
  assert.ok(shard, 'fixture must produce at least two domain-lens shards')
  const sidecar = plannedSidecars.find(
    ({ job_id: jobId }) => jobId === shard.job_id,
  )
  assert.ok(sidecar)
  const outsidePath = domainCoverage.applicable_paths.find(
    (path) => !sidecar.scoped_files.includes(path),
  )
  assert.ok(outsidePath)

  const running = beginJob(run, shard.job_id)
  const legitimate = applyJobResult(running, {
    schema_version: '1.0.0',
    run_id: running.run_id,
    job_id: shard.job_id,
    input_sha256: RESULT_DIGEST,
    producer: {
      name: 'adversarial-transition-test',
      version: '1.0.0',
      instance_id: 'adversarial-transition-test:1',
    },
    state: 'SUCCEEDED',
    examined_files: [...sidecar.scoped_files],
    findings: [],
    coverage_gaps: [],
  }, {
    expectedPacketSha256: RESULT_DIGEST,
    sidecar,
  })
  const forged = structuredClone(legitimate)
  forged.coverage.examined = [...new Set([
    ...forged.coverage.examined,
    outsidePath,
  ])].sort((left, right) => left.localeCompare(right, 'en'))
  forged.coverage.unexamined = forged.coverage.unexamined.filter(
    ({ path }) => path !== outsidePath,
  )
  const forgedRow = forged.coverage.lenses.find(
    ({ lens }) => lens === DOMAIN_LENS,
  )
  forgedRow.examined_paths = [...new Set([
    ...forgedRow.examined_paths,
    outsidePath,
  ])].sort((left, right) => left.localeCompare(right, 'en'))
  refreshCategoryDenominators(forged.coverage)

  const validation = validateRunTransition(running, forged)
  assert.equal(validation.valid, false)
  const codes = errorCodes(validation)
  assert.ok(codes.has('LENS_EXAMINED_PATH_OUTSIDE_JOB_SCOPE'))
  assert.ok(codes.has('EXAMINED_COVERAGE_NOT_JOB_BACKED'))
})

test('terminal v3 coverage cannot be supported only by skipped LENS jobs', () => {
  const run = freshRun()
  const row = run.coverage.lenses.find(
    ({ lens, applicable_paths: applicablePaths }) =>
      lens === DOMAIN_LENS && applicablePaths.length > 0,
  )
  assert.ok(row)
  const [path] = row.applicable_paths
  row.examined_paths = [path]
  run.coverage.examined = [path]
  run.coverage.unexamined = run.coverage.unexamined.filter(
    (entry) => entry.path !== path,
  )
  refreshCategoryDenominators(run.coverage)
  run.jobs = run.jobs.map((job) => ({
    ...job,
    state: 'SKIPPED',
    reason: 'forged terminal disposition',
  }))
  run.jobs.push({
    job_id: 'report:final',
    kind: 'REPORT',
    state: 'SUCCEEDED',
  })
  run.state = 'COMPLETE_WITH_GAPS'
  run.phase = 'FINALIZED'
  run.completed_at = '2026-07-29T17:00:00.000Z'
  run.artifacts.report = { path: 'report.md', sha256: RESULT_DIGEST }
  run.artifacts.sarif = { path: 'results.sarif', sha256: RESULT_DIGEST }
  run.artifacts.coverage = { path: 'coverage.json', sha256: RESULT_DIGEST }

  assertRejected(run, [
    'TERMINAL_LENS_COVERAGE_NOT_SUCCESSFUL_JOB_SCOPED',
    'TERMINAL_EXAMINED_COVERAGE_NOT_SUCCESSFUL_JOB_SCOPED',
  ])
})

test('database discovery rejects structural tampering and secret-bearing output', async (t) => {
  await t.test('a custom pack without the database lens keeps each store gap open', () => {
    const run = freshRun()
    assert.equal(
      run.jobs.some(({ lens }) => lens === 'database-and-data-stores'),
      false,
    )
    const storeId = run.database_discovery.store_candidates[0]?.store_id
    assert.ok(storeId)
    run.coverage.gaps = run.coverage.gaps.filter(
      ({ area }) => area !== `store:${storeId}`,
    )

    assertRejected(run, ['DATABASE_STORE_WITHOUT_LENS_GAP_MISSING'])
  })

  await t.test('tampered graph statistics and digest', () => {
    const run = freshRun()
    run.database_discovery.stats.node_count += 1

    assertRejected(run, ['DATABASE_DISCOVERY_INVALID'])
  })

  await t.test('credential-bearing URI smuggled into an otherwise typed node', () => {
    const run = freshRun()
    assert.ok(run.database_discovery.nodes[0])
    run.database_discovery.nodes[0].label =
      'postgresql://audit-user:super-secret@database.internal/app'

    const validation = assertRejected(run, ['DATABASE_DISCOVERY_INVALID'])
    assert.ok(
      validation.errors.some(({ message }) =>
        /credential-bearing URI|literal URI/.test(message)),
      JSON.stringify(validation.errors, null, 2),
    )
  })
})
