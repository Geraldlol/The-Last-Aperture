import assert from 'node:assert/strict'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import {
  advanceRun,
  applyJobResult,
  beginJob,
  buildFinalizedRun,
  compareTriageJobs,
} from '../scripts/lib/job-protocol.mjs'
import { createRunPlan } from '../scripts/lib/run-engine.mjs'
import {
  finalizedFanoutLensRows,
  sourceClosureGaps as closureSourceClosureGaps,
} from '../scripts/lib/coverage-closure.mjs'
import { sourceClosureGaps as modelSourceClosureGaps } from '../scripts/lib/coverage-model.mjs'

const INPUT_SHA256 = 'a'.repeat(64)
const CREATED_AT = new Date('2026-07-29T12:00:00.000Z')
const DOMAIN_LENS = 'closure-domain'

function providerResult(run, jobId, examinedFiles = [], overrides = {}) {
  return {
    schema_version: '1.0.0',
    run_id: run.run_id,
    job_id: jobId,
    input_sha256: INPUT_SHA256,
    producer: {
      name: 'coverage-closure-test',
      version: '1.0.0',
      instance_id: 'coverage-closure-test:instance-1',
    },
    state: 'SUCCEEDED',
    examined_files: examinedFiles,
    findings: [],
    coverage_gaps: [],
    ...overrides,
  }
}

function sidecarFor(plan, jobId) {
  const sidecar = plan.jobSidecars.find((candidate) => candidate.job_id === jobId)
  assert.ok(sidecar, `expected a sealed sidecar for ${jobId}`)
  return sidecar
}

function completeJob(run, plan, jobId, examinedFiles = [], resultOverrides = {}) {
  const started = beginJob(run, jobId)
  const job = started.jobs.find((candidate) => candidate.job_id === jobId)
  const sidecar = job.kind === 'LENS' ? sidecarFor(plan, jobId) : undefined
  const findings = resultOverrides.findings ?? []
  const topicAssessments = (
    job.kind === 'LENS'
    && !Object.hasOwn(resultOverrides, 'topic_assessments')
  )
    ? (sidecar.topic_obligations ?? []).map((topic) => {
        const topicFindings = findings.filter((finding) => finding.topic === topic)
        return topicFindings.length > 0
          ? {
              topic,
              disposition: 'finding',
              reason: 'The closure fixture reported a finding for this topic.',
              finding_ids: topicFindings.map(({ candidate_id: candidateId }) => candidateId),
            }
          : {
              topic,
              disposition: 'examined-clean',
              reason: 'The closure fixture assessed this topic in the bounded shard.',
              evidence: ['The fixture provider completed its bounded topic check.'],
              ...(examinedFiles.length > 0 ? { evidence_paths: examinedFiles } : {}),
            }
      })
    : resultOverrides.topic_assessments
  return applyJobResult(started, providerResult(
    started,
    jobId,
    examinedFiles,
    {
      ...resultOverrides,
      ...(topicAssessments === undefined ? {} : { topic_assessments: topicAssessments }),
    },
  ), {
    expectedPacketSha256: INPUT_SHA256,
    ...(sidecar ? { sidecar } : {}),
  })
}

function closureFinding(overrides = {}) {
  return {
    candidate_id: 'coverage-closure:retry-replay',
    lens: DOMAIN_LENS,
    topic: 'coverage-closure',
    title: 'Retry shard retains a vulnerable authorization path',
    claimed_impact_severity: 'High',
    location: ['src/a.js:1'],
    evidence: 'aaaa',
    attack: 'Reach the authorization path with a cross-tenant identifier',
    impact: 'Read data belonging to another tenant',
    reachable_from: 'GET /objects/:id',
    confidence: 'High',
    proof_plan: 'Exercise two tenant identities and assert cross-tenant refusal',
    ...overrides,
  }
}

function advanceOnce(run) {
  const advanced = advanceRun(run)
  assert.equal(advanced.advanced, true)
  return advanced.run
}

function completeInitialFanout(run, plan, omissions = new Map()) {
  let next = run
  for (const shard of plan.run.coverage.shards) {
    const omitted = new Set(omissions.get(shard.job_id) ?? [])
    next = completeJob(
      next,
      plan,
      shard.job_id,
      shard.scoped_files.filter((path) => !omitted.has(path)),
    )
  }
  return next
}

function reachBaseCompleteness(run, plan) {
  let next = advanceOnce(run)
  assert.equal(next.phase, 'TRIAGE')
  for (const job of next.jobs.filter((candidate) =>
    candidate.kind === 'TRIAGE' && candidate.closure_round === undefined)) {
    next = completeJob(next, plan, job.job_id)
  }
  next = advanceOnce(next)
  assert.equal(next.phase, 'PROOF')
  next = advanceOnce(next)
  assert.equal(next.phase, 'PATCH')
  next = advanceOnce(next)
  assert.equal(next.phase, 'REPORT')
  next = advanceOnce(next)
  assert.equal(next.phase, 'COMPLETENESS')
  return next
}

function measureBaseClosure(run, plan) {
  const baseCompleteness = run.jobs.find((job) =>
    job.kind === 'COMPLETENESS' && job.closure_round === undefined)
  assert.ok(baseCompleteness)
  let next = completeJob(run, plan, baseCompleteness.job_id)
  next = advanceOnce(next)
  return next
}

function asLegacyV2Run(plan) {
  const run = structuredClone(plan.run)
  run.schema_version = '2.0.0'
  delete run.database_discovery
  run.jobs = run.jobs.filter((job) => job.closure_round === undefined)
  for (const field of [
    'model_version',
    'policy',
    'inventory_records',
    'denominators',
    'shards',
    'closure',
    'resolved_gap_ids',
  ]) {
    delete run.coverage[field]
  }
  for (const row of run.coverage.lenses) delete row.applicable_paths
  return run
}

async function writeFixture(root) {
  const repository = join(root, 'repository')
  const lenses = join(root, 'lenses')
  await mkdir(join(repository, 'src'), { recursive: true })
  await mkdir(lenses, { recursive: true })

  await Promise.all([
    writeFile(join(repository, 'src', 'a.js'), 'aaaa'),
    writeFile(join(repository, 'src', 'b.js'), 'bbbbbb'),
    writeFile(join(repository, 'src', 'c.js'), 'ccccccc'),
    writeFile(join(lenses, 'closure-domain.md'), `---
name: ${DOMAIN_LENS}
title: Coverage closure domain
runs_in: fanout
activates_on:
  paths: ["src/**"]
  signals: []
owns: [coverage-closure]
defers: {}
---

## Scope

Exercise bounded coverage closure.
`),
    writeFile(join(lenses, 'triage.md'), `---
name: closure-triage
title: Coverage closure triage
runs_in: triage
activates_on:
  paths: []
  signals: []
owns: []
defers: {}
---

## Scope

Exercise retry-round triage.
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

async function writeTruncatedScopeFixture(root) {
  const repository = join(root, 'repository')
  const lenses = join(root, 'lenses')
  await mkdir(join(repository, 'src'), { recursive: true })
  await mkdir(lenses, { recursive: true })
  const dependencyPaths = Array.from(
    { length: 257 },
    (_, index) => `dependency-${String(index + 1).padStart(3, '0')}.js`,
  )
  await Promise.all([
    writeFile(
      join(repository, 'src', 'entry.js'),
      dependencyPaths.map((path) => `import './${path}'`).join('\n'),
    ),
    ...dependencyPaths.map((path) =>
      writeFile(join(repository, 'src', path), 'export const dependency = true\n')),
    writeFile(join(lenses, 'bounded-domain.md'), `---
name: bounded-domain
title: Bounded dependency domain
runs_in: fanout
activates_on:
  paths: ["src/entry.js"]
  signals: []
owns: [bounded-dependency-scope]
defers: {}
---

## Scope

Exercise bounded dependency expansion.
`),
  ])
  return { repository, lenses }
}

test('a truncated dependency expansion creates one explicit coverage gap per lens', async () => {
  const fixtureRoot = await mkdtemp(join(tmpdir(), 'red-team-truncated-scope-'))
  try {
    const { repository, lenses } = await writeTruncatedScopeFixture(fixtureRoot)
    const plan = await createRunPlan({
      targetRoot: repository,
      lensDirectory: lenses,
      createdAt: CREATED_AT,
      maxClosureRounds: 0,
    })
    const lensJobs = plan.activation.jobs.filter(({ lens }) => lens === 'bounded-domain')
    assert.ok(lensJobs.length > 1, 'fixture should produce multiple bounded shards')
    assert.ok(lensJobs.every((job) => job.scope_expansion?.truncated === true))
    assert.deepEqual(
      plan.run.coverage.gaps.filter(({ area }) => area === 'lens:bounded-domain'),
      [{
        area: 'lens:bounded-domain',
        reason: 'bounded dependency scope expansion truncated at depth 2 or 257 files',
      }],
    )
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true })
  }
})

test('v3 preplanned closure retries one omitted obligation and converges strictly', async () => {
  const fixtureRoot = await mkdtemp(join(tmpdir(), 'red-team-coverage-closure-'))
  try {
    const { repository, lenses } = await writeFixture(fixtureRoot)
    const options = {
      targetRoot: repository,
      lensDirectory: lenses,
      createdAt: CREATED_AT,
      requireSourceClosure: true,
      maxClosureRounds: 2,
      shardOptions: {
        maxFiles: 2,
        maxBytes: 10,
      },
    }
    const plan = await createRunPlan(options)
    const repeatedPlan = await createRunPlan(options)

    const initialShards = plan.run.coverage.shards
    assert.deepEqual(repeatedPlan.run.coverage.shards, initialShards)
    assert.deepEqual(
      initialShards.map(({ scoped_files: scopedFiles, shard }) => ({
        scoped_files: scopedFiles,
        index: shard.index,
        count: shard.count,
        file_count: shard.file_count,
        byte_count: shard.byte_count,
        max_files: shard.max_files,
        max_bytes: shard.max_bytes,
      })),
      [
        {
          scoped_files: ['src/a.js', 'src/b.js'],
          index: 1,
          count: 2,
          file_count: 2,
          byte_count: 10,
          max_files: 2,
          max_bytes: 10,
        },
        {
          scoped_files: ['src/c.js'],
          index: 2,
          count: 2,
          file_count: 1,
          byte_count: 7,
          max_files: 2,
          max_bytes: 10,
        },
      ],
    )

    const omittedShard = initialShards[1]
    const omittedPath = omittedShard.scoped_files[0]
    const retryJobId = plan.run.jobs.find((job) =>
      job.kind === 'LENS'
      && job.closure_round === 1
      && job.parent_job_id === omittedShard.job_id)?.job_id
    assert.ok(retryJobId, 'expected the omitted shard to have a sealed retry')
    assert.equal(
      plan.run.jobs.find(({ job_id: jobId }) => jobId === retryJobId).state,
      'DORMANT',
    )
    assert.deepEqual(
      sidecarFor(plan, retryJobId).scoped_files,
      omittedShard.scoped_files,
    )
    const unusedTemplateIds = plan.run.jobs
      .filter((job) =>
        job.state === 'DORMANT'
        && (
          job.closure_round === 2
          || (
            job.kind === 'LENS'
            && job.closure_round === 1
            && job.job_id !== retryJobId
          )
        ))
      .map(({ job_id: jobId }) => jobId)
    assert.ok(unusedTemplateIds.length > 0)

    let run = completeInitialFanout(
      plan.run,
      plan,
      new Map([[omittedShard.job_id, omittedShard.scoped_files]]),
    )

    assert.equal(run.coverage.gaps.length, 1)
    const [stableGap] = run.coverage.gaps
    assert.deepEqual(
      {
        kind: stableGap.kind,
        lens: stableGap.lens,
        path: stableGap.path,
        area: stableGap.area,
      },
      {
        kind: 'LENS_FILE',
        lens: DOMAIN_LENS,
        path: omittedPath,
        area: `lens:${DOMAIN_LENS}:${omittedPath}`,
      },
    )
    assert.match(stableGap.gap_id, /^coverage-gap:sha256:[a-f0-9]{64}$/)
    assert.deepEqual(run.coverage.resolved_gap_ids, [])

    run = advanceOnce(run)
    assert.equal(run.phase, 'TRIAGE')
    for (const job of run.jobs.filter((candidate) =>
      candidate.kind === 'TRIAGE' && candidate.closure_round === undefined)) {
      run = completeJob(run, plan, job.job_id)
    }
    run = advanceOnce(run)
    assert.equal(run.phase, 'PROOF')
    run = advanceOnce(run)
    assert.equal(run.phase, 'PATCH')
    run = advanceOnce(run)
    assert.equal(run.phase, 'REPORT')
    run = advanceOnce(run)
    assert.equal(run.phase, 'COMPLETENESS')

    const baseCompleteness = run.jobs.find((job) =>
      job.kind === 'COMPLETENESS' && job.closure_round === undefined)
    assert.ok(baseCompleteness)
    assert.equal(
      run.jobs.find(({ job_id: jobId }) => jobId === retryJobId).state,
      'DORMANT',
    )
    assert.deepEqual(run.coverage.closure.history, [])

    run = completeJob(run, plan, baseCompleteness.job_id)
    assert.equal(
      run.jobs.find(({ job_id: jobId }) => jobId === retryJobId).state,
      'DORMANT',
    )
    assert.deepEqual(run.coverage.closure.history, [])

    run = advanceOnce(run)
    assert.equal(run.phase, 'COMPLETENESS')
    assert.equal(run.coverage.closure.status, 'REQUEUED')
    assert.equal(run.coverage.closure.round, 1)
    assert.deepEqual(
      run.coverage.closure.history.map((measurement) => ({
        round: measurement.round,
        status: measurement.status,
        uncovered_lens_file_pairs: measurement.uncovered_lens_file_pairs,
        uncovered_jobs: measurement.uncovered_shards.map(({ job_id: jobId }) => jobId),
      })),
      [{
        round: 0,
        status: 'REQUEUED',
        uncovered_lens_file_pairs: 1,
        uncovered_jobs: [omittedShard.job_id],
      }],
    )
    assert.equal(
      run.jobs.find(({ job_id: jobId }) => jobId === retryJobId).state,
      'PENDING',
    )
    assert.deepEqual(
      run.jobs
        .filter((job) =>
          job.kind === 'LENS'
          && job.closure_round === 1
          && job.state === 'PENDING')
        .map(({ job_id: jobId }) => jobId),
      [retryJobId],
    )
    assert.deepEqual(
      sidecarFor(plan, retryJobId).scoped_files,
      omittedShard.scoped_files,
      'the retry must reuse the whole sealed shard, not a residual file subset',
    )

    run = completeJob(run, plan, retryJobId, [omittedPath])
    assert.equal(run.coverage.gaps.length, 1)
    assert.equal(run.coverage.gaps[0].gap_id, stableGap.gap_id)
    assert.deepEqual(run.coverage.resolved_gap_ids, [stableGap.gap_id])
    assert.ok(run.coverage.examined.includes(omittedPath))
    assert.ok(
      run.coverage.lenses
        .find(({ lens }) => lens === DOMAIN_LENS)
        .examined_paths.includes(omittedPath),
    )

    run = advanceOnce(run)
    const roundOneTriage = run.jobs.filter((job) =>
      job.kind === 'TRIAGE' && job.closure_round === 1)
    assert.ok(roundOneTriage.length > 0)
    assert.ok(roundOneTriage.every(({ state }) => state === 'PENDING'))
    for (const job of roundOneTriage) {
      run = completeJob(run, plan, job.job_id)
    }

    run = advanceOnce(run)
    const roundOneCompleteness = run.jobs.find((job) =>
      job.kind === 'COMPLETENESS' && job.closure_round === 1)
    assert.ok(roundOneCompleteness)
    assert.equal(roundOneCompleteness.state, 'PENDING')
    assert.equal(run.coverage.closure.status, 'MEASURING')

    run = completeJob(run, plan, roundOneCompleteness.job_id)
    run = advanceOnce(run)
    assert.equal(run.coverage.closure.status, 'CONVERGED')
    assert.equal(run.coverage.closure.uncovered_lens_file_pairs, 0)
    assert.deepEqual(
      run.coverage.closure.history.map(({ round, status }) => ({ round, status })),
      [
        { round: 0, status: 'REQUEUED' },
        { round: 1, status: 'CONVERGED' },
      ],
    )
    assert.ok(run.jobs.every(({ state }) => state !== 'DORMANT'))
    for (const jobId of unusedTemplateIds) {
      const unused = run.jobs.find((job) => job.job_id === jobId)
      assert.equal(unused.state, 'SKIPPED', jobId)
      assert.match(unused.reason, /coverage converged at round 1/)
    }

    const missingFile = structuredClone(run)
    missingFile.coverage.examined = missingFile.coverage.examined
      .filter((path) => path !== omittedPath)
    assert.throws(
      () => buildFinalizedRun(missingFile),
      new RegExp(
        `source closure is required, but 1 canonical source coverage obligation remains: ${omittedPath.replace('.', '\\.')}`,
      ),
    )

    const missingLensPair = structuredClone(run)
    const domainCoverage = missingLensPair.coverage.lenses
      .find(({ lens }) => lens === DOMAIN_LENS)
    domainCoverage.examined_paths = domainCoverage.examined_paths
      .filter((path) => path !== omittedPath)
    assert.throws(
      () => buildFinalizedRun(missingLensPair),
      new RegExp(
        `source closure is required, but 1 canonical source coverage obligation remains: ${DOMAIN_LENS}:${omittedPath.replace('.', '\\.')}`,
      ),
    )

    const finalized = buildFinalizedRun(run, {
      completedAt: new Date('2026-07-29T12:05:00.000Z'),
    })
    assert.equal(finalized.run.state, 'COMPLETED')
    assert.equal(finalized.run.phase, 'FINALIZED')
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true })
  }
})

test('a dormant closure retry opens complete proof waves without crossing phase barriers', async () => {
  const fixtureRoot = await mkdtemp(join(tmpdir(), 'red-team-closure-proof-wave-'))
  try {
    const { repository, lenses } = await writeFixture(fixtureRoot)
    const plan = await createRunPlan({
      targetRoot: repository,
      lensDirectory: lenses,
      createdAt: CREATED_AT,
      maxClosureRounds: 1,
      shardOptions: {
        maxFiles: 2,
        maxBytes: 10,
      },
    })
    const omittedShard = plan.run.coverage.shards[0]
    const retryJob = plan.run.jobs.find((job) =>
      job.kind === 'LENS'
      && job.closure_round === 1
      && job.parent_job_id === omittedShard.job_id)
    assert.ok(retryJob)
    assert.equal(retryJob.state, 'DORMANT')

    let run = completeInitialFanout(
      plan.run,
      plan,
      new Map([[omittedShard.job_id, omittedShard.scoped_files]]),
    )
    run = reachBaseCompleteness(run, plan)
    run = measureBaseClosure(run, plan)
    assert.equal(
      run.jobs.find(({ job_id: jobId }) => jobId === retryJob.job_id).state,
      'PENDING',
    )

    const retryFindings = Array.from({ length: 4 }, (_, index) =>
      closureFinding({
        candidate_id: `coverage-closure:proof-wave-${index + 1}`,
        title: `Closure proof-wave candidate ${index + 1}`,
        location: [`${omittedShard.scoped_files[0]}:1`],
      }))
    run = completeJob(
      run,
      plan,
      retryJob.job_id,
      omittedShard.scoped_files,
      { findings: retryFindings },
    )
    run = advanceOnce(run)

    const roundTriage = run.jobs
      .filter((job) => job.kind === 'TRIAGE' && job.closure_round === 1)
      .sort(compareTriageJobs)
    assert.ok(roundTriage.length > 0)
    const triagedFindings = retryFindings.map((finding) => ({
      ...finding,
      effective_severity: 'Medium',
      triage_disposition: 'queued',
    }))
    for (const [index, job] of roundTriage.entries()) {
      run = completeJob(
        run,
        plan,
        job.job_id,
        [],
        index === 0 ? { findings: triagedFindings } : {},
      )
    }

    run = advanceOnce(run)
    const existenceJobs = run.jobs.filter((job) =>
      job.kind === 'PROOF'
      && job.closure_round === 1
      && job.job_id.startsWith('proof-existence:'))
    assert.equal(existenceJobs.length, retryFindings.length)
    assert.ok(existenceJobs.every(({ state }) => state === 'PENDING'))
    assert.equal(
      run.jobs.some((job) =>
        job.kind === 'PROOF'
        && job.closure_round === 1
        && job.job_id.startsWith('proof-verification:')),
      false,
    )

    for (const finding of [...triagedFindings].reverse()) {
      const jobId = `proof-existence:${finding.candidate_id}`
      run = completeJob(run, plan, jobId, [], {
        findings: [{
          ...finding,
          existence_check: {
            status: 'located',
            method: `Read ${finding.location[0]} and compare the evidence verbatim.`,
          },
        }],
      })
      const advanced = advanceRun(run)
      run = advanced.run
      const unfinished = run.jobs.some((job) =>
        job.kind === 'PROOF'
        && job.closure_round === 1
        && job.job_id.startsWith('proof-existence:')
        && job.state !== 'SUCCEEDED')
      assert.equal(advanced.advanced, !unfinished)
      if (unfinished) {
        assert.equal(
          run.jobs.some((job) =>
            job.kind === 'PROOF'
            && job.closure_round === 1
            && job.job_id.startsWith('proof-verification:')),
          false,
        )
      }
    }

    const verificationJobs = run.jobs.filter((job) =>
      job.kind === 'PROOF'
      && job.closure_round === 1
      && job.job_id.startsWith('proof-verification:'))
    assert.equal(verificationJobs.length, retryFindings.length)
    assert.ok(verificationJobs.every(({ state }) => state === 'PENDING'))
    assert.deepEqual(
      verificationJobs.map(({ candidate_ids: candidateIds }) => candidateIds),
      triagedFindings.map(({ candidate_id: candidateId }) => [candidateId]),
    )
    assert.doesNotThrow(() => beginJob(run, verificationJobs.at(-1).job_id))
    assert.ok(run.jobs.some((job) =>
      job.kind === 'LENS'
      && job.closure_round === 1
      && job.parent_job_id !== omittedShard.job_id
      && job.state === 'DORMANT'))
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true })
  }
})

test('closure LENS retry records an exact Stage-1 replay without rewriting accumulated proof', async () => {
  const fixtureRoot = await mkdtemp(join(tmpdir(), 'red-team-finding-replay-'))
  try {
    const { repository, lenses } = await writeFixture(fixtureRoot)
    const plan = await createRunPlan({
      targetRoot: repository,
      lensDirectory: lenses,
      createdAt: CREATED_AT,
      maxClosureRounds: 1,
      shardOptions: {
        maxFiles: 2,
        maxBytes: 10,
      },
    })
    const initialShard = plan.run.coverage.shards.find(
      ({ scoped_files: scopedFiles }) =>
        scopedFiles.includes('src/a.js') && scopedFiles.includes('src/b.js'),
    )
    assert.ok(initialShard)
    const retryJob = plan.run.jobs.find((job) =>
      job.kind === 'LENS'
      && job.closure_round === 1
      && job.parent_job_id === initialShard.job_id)
    assert.ok(retryJob)

    let run = plan.run
    for (const shard of plan.run.coverage.shards) {
      if (shard.job_id === initialShard.job_id) {
        run = completeJob(run, plan, shard.job_id, ['src/a.js'], {
          findings: [closureFinding()],
        })
      } else {
        run = completeJob(run, plan, shard.job_id, shard.scoped_files)
      }
    }

    run = advanceOnce(run)
    assert.equal(run.phase, 'TRIAGE')
    let triaged = false
    const triagedClaim = closureFinding({
      effective_severity: 'High',
      triage_disposition: 'queued',
    })
    const triagedFinding = {
      ...triagedClaim,
      triage_authority: 'UNAUTHENTICATED_PROVIDER_ASSERTION',
    }
    for (const job of run.jobs.filter((candidate) =>
      candidate.kind === 'TRIAGE' && candidate.closure_round === undefined)) {
      run = completeJob(run, plan, job.job_id, [], triaged
        ? {}
        : { findings: [triagedClaim] })
      triaged = true
    }
    assert.equal(triaged, true)
    assert.deepEqual(run.findings, [triagedFinding])

    run = advanceOnce(run)
    assert.equal(run.phase, 'PROOF')
    const candidateId = closureFinding().candidate_id
    const existenceFinding = {
      ...triagedFinding,
      existence_check: {
        status: 'located',
        method: 'Read src/a.js:1 and compare the bounded evidence verbatim.',
      },
    }
    run = completeJob(
      run,
      plan,
      `proof-existence:${candidateId}`,
      [],
      { findings: [existenceFinding] },
    )
    run = advanceOnce(run)
    assert.equal(run.phase, 'PROOF')
    const provedClaim = {
      ...existenceFinding,
      effective_severity: 'Medium',
      proof_tier: 'T0',
      verification_status: 'UNPROVEN',
      blocking_reason: 'Static coverage closure cannot execute a two-tenant harness.',
    }
    const provedFinding = {
      ...provedClaim,
      verification_authority: 'UNAUTHENTICATED_PROVIDER_ASSERTION',
    }
    run = completeJob(
      run,
      plan,
      `proof-verification:${candidateId}`,
      [],
      { findings: [provedClaim] },
    )
    run = advanceOnce(run)
    assert.equal(run.phase, 'PATCH')
    run = advanceOnce(run)
    assert.equal(run.phase, 'REPORT')
    run = advanceOnce(run)
    assert.equal(run.phase, 'COMPLETENESS')
    run = completeJob(
      run,
      plan,
      run.jobs.find((job) =>
        job.kind === 'COMPLETENESS' && job.closure_round === undefined).job_id,
    )
    run = advanceOnce(run)
    assert.equal(
      run.jobs.find(({ job_id: jobId }) => jobId === retryJob.job_id).state,
      'PENDING',
    )

    const started = beginJob(run, retryJob.job_id)
    const replayFiles = sidecarFor(plan, retryJob.job_id).scoped_files
    for (const changedReplay of [
      closureFinding({ title: 'Changed claim text must not collide' }),
      closureFinding({ location: ['src/b.js:1'] }),
    ]) {
      assert.throws(
        () => applyJobResult(
          started,
          providerResult(started, retryJob.job_id, replayFiles, {
            findings: [changedReplay],
            topic_assessments: [{
              topic: 'coverage-closure',
              disposition: 'finding',
              reason: 'The retry observed the existing closure finding.',
              finding_ids: [changedReplay.candidate_id],
            }],
          }),
          {
            expectedPacketSha256: INPUT_SHA256,
            sidecar: sidecarFor(plan, retryJob.job_id),
          },
        ),
        /must exactly replay the immutable Stage-1 claim/,
      )
    }

    const accepted = applyJobResult(
      started,
      providerResult(started, retryJob.job_id, replayFiles, {
        findings: [closureFinding()],
        topic_assessments: [{
          topic: 'coverage-closure',
          disposition: 'finding',
          reason: 'The retry observed the existing closure finding.',
          finding_ids: [closureFinding().candidate_id],
        }],
      }),
      {
        expectedPacketSha256: INPUT_SHA256,
        sidecar: sidecarFor(plan, retryJob.job_id),
      },
    )
    assert.deepEqual(accepted.findings, [provedFinding])
    assert.deepEqual(
      accepted.jobs.find(({ job_id: jobId }) => jobId === retryJob.job_id)
        .candidate_ids,
      [closureFinding().candidate_id],
      'the terminal job must retain the candidate IDs authenticated by its result',
    )
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true })
  }
})

test('zero-round closure reports exhaustion and strict source closure refuses finalization', async () => {
  const fixtureRoot = await mkdtemp(join(tmpdir(), 'red-team-zero-round-closure-'))
  try {
    const { repository, lenses } = await writeFixture(fixtureRoot)
    const common = {
      targetRoot: repository,
      lensDirectory: lenses,
      createdAt: CREATED_AT,
      maxClosureRounds: 0,
      shardOptions: {
        maxFiles: 2,
        maxBytes: 10,
      },
    }

    const strictPlan = await createRunPlan({
      ...common,
      requireSourceClosure: true,
    })
    assert.equal(strictPlan.run.coverage.closure.max_rounds, 0)
    assert.equal(
      strictPlan.run.jobs.some((job) => job.closure_round !== undefined),
      false,
      'a zero retry budget must not create unusable closure templates',
    )
    const strictOmittedShard = strictPlan.run.coverage.shards.at(-1)
    let strictRun = completeInitialFanout(
      strictPlan.run,
      strictPlan,
      new Map([[
        strictOmittedShard.job_id,
        strictOmittedShard.scoped_files,
      ]]),
    )
    strictRun = reachBaseCompleteness(strictRun, strictPlan)
    strictRun = measureBaseClosure(strictRun, strictPlan)

    assert.equal(strictRun.coverage.closure.status, 'BUDGET_EXHAUSTED')
    assert.equal(strictRun.coverage.closure.round, 0)
    assert.equal(strictRun.coverage.closure.uncovered_lens_file_pairs, 1)
    assert.deepEqual(
      strictRun.coverage.closure.history.map((measurement) => ({
        round: measurement.round,
        status: measurement.status,
        uncovered_lens_file_pairs: measurement.uncovered_lens_file_pairs,
      })),
      [{
        round: 0,
        status: 'BUDGET_EXHAUSTED',
        uncovered_lens_file_pairs: 1,
      }],
    )
    assert.throws(
      () => buildFinalizedRun(strictRun),
      /source closure is required, but coverage ended BUDGET_EXHAUSTED/,
    )

    const permissivePlan = await createRunPlan({
      ...common,
      requireSourceClosure: false,
    })
    const permissiveOmittedShard = permissivePlan.run.coverage.shards.at(-1)
    let permissiveRun = completeInitialFanout(
      permissivePlan.run,
      permissivePlan,
      new Map([[
        permissiveOmittedShard.job_id,
        permissiveOmittedShard.scoped_files,
      ]]),
    )
    permissiveRun = reachBaseCompleteness(permissiveRun, permissivePlan)
    permissiveRun = measureBaseClosure(permissiveRun, permissivePlan)
    const finalized = buildFinalizedRun(permissiveRun, {
      completedAt: new Date('2026-07-29T12:06:00.000Z'),
    })
    assert.equal(finalized.run.state, 'COMPLETE_WITH_GAPS')
    assert.equal(
      finalized.run.coverage.closure.status,
      'BUDGET_EXHAUSTED',
      'exhaustion must remain explicit in the finalized evidence',
    )
    assert.equal(finalized.run.coverage.closure.uncovered_shards.length, 1)
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true })
  }
})

test('legacy v2 runs retain their non-recursive completeness lifecycle', async () => {
  const fixtureRoot = await mkdtemp(join(tmpdir(), 'red-team-v2-closure-compat-'))
  try {
    const { repository, lenses } = await writeFixture(fixtureRoot)
    const plan = await createRunPlan({
      targetRoot: repository,
      lensDirectory: lenses,
      createdAt: CREATED_AT,
      maxClosureRounds: 2,
      shardOptions: {
        maxFiles: 2,
        maxBytes: 10,
      },
    })
    let run = asLegacyV2Run(plan)

    run = completeInitialFanout(run, plan)
    run = reachBaseCompleteness(run, plan)
    const baseCompleteness = run.jobs.find((job) =>
      job.kind === 'COMPLETENESS' && job.closure_round === undefined)
    run = completeJob(run, plan, baseCompleteness.job_id)

    assert.deepEqual(advanceRun(run), { advanced: false, run })
    assert.equal(run.coverage.closure, undefined)
    assert.equal(run.jobs.some((job) => job.state === 'DORMANT'), false)

    const finalized = buildFinalizedRun(run, {
      completedAt: new Date('2026-07-29T12:07:00.000Z'),
    })
    assert.equal(finalized.run.schema_version, '2.0.0')
    assert.equal(finalized.run.state, 'COMPLETED')
    assert.equal(finalized.run.phase, 'FINALIZED')
    assert.equal(finalized.run.coverage.closure, undefined)
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true })
  }
})

test('the contract layer and the controller share one source-closure predicate', () => {
  assert.equal(closureSourceClosureGaps, modelSourceClosureGaps)
})

test('an unexamined canonical source file no lens claims is a source-closure gap', () => {
  const coverage = {
    model_version: '2.0.0',
    policy: {},
    denominators: [],
    shards: [],
    closure: { status: 'CONVERGED' },
    inventory_records: [
      { path: 'src/claimed.js', coverage_class: 'CANONICAL_SOURCE' },
      { path: 'src/unclaimed.js', coverage_class: 'CANONICAL_SOURCE' },
    ],
    examined: ['src/claimed.js'],
    lenses: [{
      lens: 'web-and-api',
      status: 'RAN',
      applicable_paths: ['src/claimed.js'],
      examined_paths: ['src/claimed.js'],
    }],
  }

  assert.deepEqual(closureSourceClosureGaps(coverage), [
    { kind: 'canonical-source-file', path: 'src/unclaimed.js' },
  ])
})

test('source closure does not fail open on a coverage object that misses the modeled shape', () => {
  const coverage = {
    inventory_records: [
      { path: 'src/unexamined.js', coverage_class: 'CANONICAL_SOURCE' },
    ],
    examined: [],
    lenses: [],
  }

  assert.equal(closureSourceClosureGaps(coverage).length, 1)
})

test('terminal lens rows are reconciled from their own obligations, not the coverage duck type', () => {
  const run = {
    coverage: {
      lenses: [
        {
          lens: 'web-and-api',
          status: 'RAN',
          applicable_paths: ['src/a.js', 'src/b.js'],
          examined_paths: ['src/a.js'],
        },
        {
          lens: 'legacy-lens',
          status: 'RAN',
          examined_paths: ['src/a.js'],
        },
      ],
    },
    jobs: [
      { job_id: 'lens:web-and-api', kind: 'LENS', lens: 'web-and-api', state: 'SUCCEEDED' },
      { job_id: 'lens:legacy-lens', kind: 'LENS', lens: 'legacy-lens', state: 'SUCCEEDED' },
    ],
  }

  const rows = finalizedFanoutLensRows(run)
  assert.equal(rows[0].status, 'NOT_ASSESSED')
  assert.equal(rows[1].status, 'RAN')
})

test('finalizing one lens leaves other pending semantic obligations untouched', () => {
  const run = {
    coverage: {
      lenses: [
        {
          lens: 'cloud-and-iac',
          status: 'RAN',
          applicable_paths: [],
          examined_paths: [],
        },
        {
          lens: 'cicd-and-supply-chain',
          status: 'NOT_ASSESSED',
          applicable_paths: [],
          examined_paths: [],
          reason: 'audit job has not run',
        },
      ],
    },
    jobs: [
      {
        job_id: 'lens:cloud-and-iac',
        kind: 'LENS',
        lens: 'cloud-and-iac',
        state: 'SUCCEEDED',
        topic_obligations: ['container-image-content'],
        topic_assessments: [{
          topic: 'container-image-content',
          disposition: 'examined-clean',
          reason: 'The acquired image was assessed.',
          evidence: ['No unexpected content was present.'],
        }],
      },
      {
        job_id: 'lens:cicd-and-supply-chain',
        kind: 'LENS',
        lens: 'cicd-and-supply-chain',
        state: 'PENDING',
        topic_obligations: ['artifact-signing-and-provenance-emission'],
        topic_assessments: [],
      },
    ],
  }

  const rows = finalizedFanoutLensRows(run)
  assert.equal(rows[0].status, 'RAN')
  assert.equal(rows[1].status, 'NOT_ASSESSED')
  assert.equal(rows[1].reason, 'audit job has not run')
})
