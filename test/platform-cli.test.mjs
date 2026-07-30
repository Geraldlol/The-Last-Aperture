import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import {
  cp,
  lstat,
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  symlink,
  truncate,
  writeFile,
} from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { tmpdir } from 'node:os'
import { artifactKeyToken } from '../scripts/lib/artifact-names.mjs'
import {
  createRunPlan,
  writeRunPlanBundle,
} from '../scripts/lib/run-engine.mjs'
import { measureCoverageClosure } from '../scripts/lib/coverage-model.mjs'
import {
  MAX_BUNDLE_ARTIFACT_BYTES,
  MAX_RUN_MANIFEST_BYTES,
} from '../scripts/lib/resource-limits.mjs'
import { preparedResultRetentionBytes } from '../scripts/audit.mjs'

const CLI = resolve('scripts/audit.mjs')

test('batch retention accounting includes intermediate run manifests', () => {
  assert.equal(
    preparedResultRetentionBytes({
      canonicalResult: 'result',
      serializedRun: 'manifest-state',
    }),
    Buffer.byteLength('result') + Buffer.byteLength('manifest-state'),
  )
})

async function withCliRepository(callback) {
  const root = await mkdtemp(join(tmpdir(), 'red-team-cli-target-'))
  const output = await mkdtemp(join(tmpdir(), 'red-team-cli-output-'))
  try {
    await mkdir(join(root, 'src'), { recursive: true })
    await writeFile(join(root, 'src', 'app.js'), 'const express = require("express")\n')
    await writeFile(join(root, 'package.json'), JSON.stringify({
      scripts: {
        preinstall: 'node -e "require(\'fs\').writeFileSync(\'EXECUTED\', \'bad\')"',
      },
    }))
    await callback({ root, output })
  } finally {
    await rm(root, { recursive: true, force: true })
    await rm(output, { recursive: true, force: true })
  }
}

async function planBundle(root, output) {
  execFileSync(
    process.execPath,
    [CLI, 'plan', root, '--out', output],
    { encoding: 'utf8' },
  )
  const directories = (await readdir(output, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory())
  assert.equal(directories.length, 1)
  return join(output, directories[0].name)
}

function successfulProviderResult(next, job, overrides = {}) {
  return {
    schema_version: '1.0.0',
    run_id: next.run_id,
    job_id: job.job_id,
    input_sha256: job.packet_sha256,
    producer: {
      name: 'test-provider',
      version: '1.0.0',
      instance_id: 'test-provider:bounded-cli',
    },
    state: 'SUCCEEDED',
    examined_files: job.scoped_files,
    findings: [],
    coverage_gaps: [],
    ...overrides,
  }
}

function benchmarkFinding() {
  return {
    candidate_id: 'authz-object-level:benchmark-binding',
    lens: 'web-and-api',
    topic: 'authz-object-level',
    title: 'Benchmark binding candidate',
    claimed_impact_severity: 'Low',
    location: ['src/app.js:1'],
    evidence: 'const value = repository.lookup(request.params.id)',
    attack: 'Request another subject identifier',
    impact: 'Reads one record outside the caller scope',
    reachable_from: 'GET /records/:id',
    confidence: 'High',
    proof_plan: 'Run the two-subject authorization oracle',
    effective_severity: 'Low',
    triage_disposition: 'queued',
    existence_check: {
      status: 'located',
      method: 'Read src/app.js and locate the lookup',
    },
    proof_tier: 'T3',
    verification_status: 'UNPROVEN',
    blocking_reason: 'No authorized runtime oracle was available',
  }
}

async function createDirectoryLink(target, path) {
  await symlink(target, path, process.platform === 'win32' ? 'junction' : 'dir')
}

test('CLI help exposes only explicit platform commands', () => {
  const output = execFileSync(process.execPath, [CLI, 'help'], { encoding: 'utf8' })
  assert.match(output, /^red-team-audit 0\.4\.0/m)
  assert.match(output, /red-team-audit plan/)
  assert.match(output, /--max-shard-files <count>/)
  assert.match(output, /--max-shard-bytes <bytes>/)
  assert.match(output, /--max-closure-rounds <count>/)
  assert.match(output, /--require-source-closure/)
  assert.match(output, /red-team-audit ingest-batch/)
  assert.match(output, /red-team-audit unlock/)
  assert.match(output, /red-team-audit validate/)
  assert.match(output, /red-team-audit benchmark/)
  assert.match(output, /never executes repository code/i)
})

test('CLI rejects unknown, duplicate, valued-flag, and extra arguments', () => {
  const cases = [
    {
      argv: ['validate', 'run.json', '--jsno'],
      pattern: /unknown option --jsno for validate/i,
    },
    {
      argv: ['report', 'run.json', '--out', 'one.md', '--out', 'two.md'],
      pattern: /duplicate option --out/i,
    },
    {
      argv: ['validate', 'run.json', '--json', 'true'],
      pattern: /--json is a flag and does not accept a value/i,
    },
    {
      argv: ['next', 'run.json', 'ignored.json'],
      pattern: /next expects exactly 1 positional argument; received 2/i,
    },
    {
      argv: ['ingest-batch', 'run-only'],
      pattern: /ingest-batch expects at least 2 positional arguments; received 1/i,
    },
  ]

  for (const { argv, pattern } of cases) {
    const result = spawnSync(process.execPath, [CLI, ...argv], {
      encoding: 'utf8',
    })
    assert.equal(result.status, 1, argv.join(' '))
    assert.match(result.stderr, pattern, argv.join(' '))
  }
})

test('CLI coverage controls produce schema-valid deterministic bounded shards', async () => {
  await withCliRepository(async ({ root, output }) => {
    const repeatedOutput = await mkdtemp(join(tmpdir(), 'red-team-cli-output-repeat-'))
    try {
      await mkdir(join(root, 'routes'), { recursive: true })
      await Promise.all([
        writeFile(join(root, 'routes', 'a.js'), `export const a = "${'a'.repeat(160)}"\n`),
        writeFile(join(root, 'routes', 'b.js'), `export const b = "${'b'.repeat(160)}"\n`),
        writeFile(join(root, 'routes', 'c.js'), `export const c = "${'c'.repeat(160)}"\n`),
      ])

      const coverageArguments = [
        '--max-shard-files', '2',
        '--max-shard-bytes', '256',
        '--max-closure-rounds', '0',
        '--require-source-closure',
      ]
      const createBundle = async (outputParent) => {
        execFileSync(
          process.execPath,
          [CLI, 'plan', root, '--out', outputParent, ...coverageArguments],
          { encoding: 'utf8' },
        )
        const directories = (await readdir(outputParent, { withFileTypes: true }))
          .filter((entry) => entry.isDirectory())
        assert.equal(directories.length, 1)
        return join(outputParent, directories[0].name)
      }

      const firstBundle = await createBundle(output)
      const secondBundle = await createBundle(repeatedOutput)
      const first = JSON.parse(await readFile(join(firstBundle, 'run.json'), 'utf8'))
      const second = JSON.parse(await readFile(join(secondBundle, 'run.json'), 'utf8'))

      assert.deepEqual(first.coverage.policy, {
        require_source_closure: true,
        max_shard_files: 2,
        max_shard_bytes: 256,
        max_requeue_rounds: 0,
      })
      assert.equal(first.coverage.closure.required_source_closure, true)
      assert.equal(first.coverage.closure.max_rounds, 0)
      assert.ok(first.coverage.shards.length > 1)
      assert.ok(first.coverage.shards.every(({ scoped_files: scopedFiles, shard }) =>
        scopedFiles.length === shard.file_count
        && shard.file_count <= 2
        && shard.byte_count <= 256
        && shard.max_files === 2
        && shard.max_bytes === 256))
      assert.deepEqual(second.coverage.shards, first.coverage.shards)
      assert.equal(
        first.jobs.some(({ closure_round: closureRound }) => closureRound !== undefined),
        false,
      )

      const validation = execFileSync(
        process.execPath,
        [CLI, 'validate', firstBundle],
        { encoding: 'utf8' },
      )
      assert.match(validation, /^VALID:/)
    } finally {
      await rm(repeatedOutput, { recursive: true, force: true })
    }
  })
})

test('CLI rejects forged convergence after immutable lens applicability is narrowed', async () => {
  await withCliRepository(async ({ root, output }) => {
    const bundle = await planBundle(root, output)
    const runPath = join(bundle, 'run.json')
    const run = JSON.parse(await readFile(runPath, 'utf8'))
    const originalApplicablePairs = run.coverage.lenses.reduce(
      (total, row) => total + row.applicable_paths.length,
      0,
    )
    assert.ok(originalApplicablePairs > 0)

    for (const row of run.coverage.lenses) row.applicable_paths = []
    const measurement = measureCoverageClosure(run.coverage, 0)
    const converged = {
      ...measurement,
      status: 'CONVERGED',
    }
    run.coverage.closure = {
      ...run.coverage.closure,
      ...converged,
      history: [converged],
    }
    await writeFile(runPath, `${JSON.stringify(run, null, 2)}\n`)

    const result = spawnSync(process.execPath, [CLI, 'validate', bundle], {
      encoding: 'utf8',
    })
    assert.equal(result.status, 1)
    assert.match(
      result.stderr,
      /immutable plan fields do not match coverage-plan\.json/i,
    )
  })
})

test('CLI coverage controls reject invalid, duplicate, and valued-flag inputs', async () => {
  await withCliRepository(async ({ root, output }) => {
    const cases = [
      {
        options: ['--max-shard-files', '0'],
        pattern: /--max-shard-files must be a positive integer/i,
      },
      {
        options: ['--max-shard-bytes', '1.5'],
        pattern: /--max-shard-bytes must be a positive integer/i,
      },
      {
        options: ['--max-closure-rounds', '-1'],
        pattern: /--max-closure-rounds must be a non-negative integer/i,
      },
      {
        options: ['--max-shard-files', '2', '--max-shard-files', '3'],
        pattern: /duplicate option --max-shard-files/i,
      },
      {
        options: ['--max-closure-rounds', '0', '--max-closure-rounds', '1'],
        pattern: /duplicate option --max-closure-rounds/i,
      },
      {
        options: ['--require-source-closure', '--require-source-closure'],
        pattern: /duplicate option --require-source-closure/i,
      },
      {
        options: ['--require-source-closure', 'true'],
        pattern: /--require-source-closure is a flag and does not accept a value/i,
      },
    ]

    for (const [index, { options, pattern }] of cases.entries()) {
      const candidateOutput = join(output, `invalid-${index}`)
      const result = spawnSync(
        process.execPath,
        [CLI, 'plan', root, '--out', candidateOutput, ...options],
        { encoding: 'utf8' },
      )
      assert.equal(result.status, 1, options.join(' '))
      assert.match(result.stderr, pattern, options.join(' '))
    }
  })
})

test('CLI plan produces a valid fail-closed bundle without running package scripts', async () => {
  await withCliRepository(async ({ root, output }) => {
    const stdout = execFileSync(
      process.execPath,
      [CLI, 'plan', root, '--out', output],
      { encoding: 'utf8' },
    )
    assert.match(stdout, /State: PLANNED/)
    assert.match(stdout, /not a clean result/i)

    const directories = await readdir(output)
    assert.equal(directories.length, 1)
    const bundle = join(output, directories[0])
    const runPath = join(bundle, 'run.json')
    const run = JSON.parse(await readFile(runPath, 'utf8'))
    assert.equal(run.state, 'PLANNED')
    assert.equal(run.capability_mode, 'STATIC')
    assert.equal(run.repository.dirty, 'unknown')
    assert.equal(await readFile(join(root, 'package.json'), 'utf8').then(
      (text) => text.includes('preinstall'),
    ), true)
    await assert.rejects(readFile(join(root, 'EXECUTED'), 'utf8'))

    const validation = execFileSync(
      process.execPath,
      [CLI, 'validate', bundle],
      { encoding: 'utf8' },
    )
    assert.match(validation, /^VALID:/)

    const next = JSON.parse(execFileSync(
      process.execPath,
      [CLI, 'next', bundle],
      { encoding: 'utf8' },
    ))
    assert.ok(next.pending_jobs.length > 0)
    assert.ok(next.pending_jobs.every(({ kind }) => kind === 'LENS'))
    const firstJob = next.pending_jobs[0]
    const resultPath = join(output, 'provider-result.json')
    await writeFile(resultPath, JSON.stringify({
      schema_version: '1.0.0',
      run_id: next.run_id,
      job_id: firstJob.job_id,
      input_sha256: firstJob.packet_sha256,
      producer: {
        name: 'test-provider',
        version: '1.0.0',
        instance_id: 'test-provider:instance-1',
      },
      state: 'SUCCEEDED',
      examined_files: firstJob.scoped_files,
      findings: [],
      coverage_gaps: [],
    }))
    const ingest = execFileSync(
      process.execPath,
      [CLI, 'ingest', bundle, resultPath],
      { encoding: 'utf8' },
    )
    assert.match(ingest, /Accepted/)
    const afterIngest = JSON.parse(await readFile(runPath, 'utf8'))
    assert.equal(
      afterIngest.jobs.find(({ job_id }) => job_id === firstJob.job_id).state,
      'SUCCEEDED',
    )
    assert.equal(
      afterIngest.jobs.find(({ job_id }) => job_id === firstJob.job_id)
        .producer.instance_id,
      'test-provider:instance-1',
    )
    assert.ok(Object.keys(afterIngest.artifacts).some((name) => name.startsWith('result_')))

    const report = execFileSync(
      process.execPath,
      [CLI, 'report', bundle],
      { encoding: 'utf8' },
    )
    assert.match(report, /not a clean audit result/i)
    assert.match(report, /audit job has not run/)

    const resultArtifact = Object.entries(afterIngest.artifacts)
      .find(([name]) => name.startsWith('result_'))[1]
    const resultArtifactPath = join(bundle, resultArtifact.path)
    const committedResult = await readFile(resultArtifactPath, 'utf8')
    await writeFile(resultArtifactPath, `${committedResult.trimEnd()} `)
    const tampered = spawnSync(process.execPath, [CLI, 'validate', bundle], {
      encoding: 'utf8',
    })
    assert.equal(tampered.status, 1)
    assert.match(tampered.stderr, /artifact digest mismatch/i)
    await writeFile(resultArtifactPath, committedResult)

    const abort = execFileSync(
      process.execPath,
      [CLI, 'abort', bundle, '--reason', 'operator safety stop'],
      { encoding: 'utf8' },
    )
    assert.match(abort, /Aborted/)
    const aborted = JSON.parse(await readFile(runPath, 'utf8'))
    assert.equal(aborted.state, 'ABORTED')
    assert.equal(aborted.phase, 'FINALIZED')
    assert.equal(aborted.errors.at(-1).code, 'OPERATOR_ABORT')
  })
})

test('plan bundle publication removes its verified staging directory after a late failure', async () => {
  await withCliRepository(async ({ root, output }) => {
    const plan = await createRunPlan({
      targetRoot: root,
      lensDirectory: resolve('skills/red-team-audit/lenses'),
      createdAt: new Date('2026-07-29T15:00:00.000Z'),
    })
    plan.run.publication_fault = 1n

    await assert.rejects(
      writeRunPlanBundle(plan, output),
      /BigInt|serialize/i,
    )
    assert.deepEqual(await readdir(output), [])
  })
})

test('plan bundle publication fails closed without replacing an existing final directory', async () => {
  await withCliRepository(async ({ root, output }) => {
    const plan = await createRunPlan({
      targetRoot: root,
      lensDirectory: resolve('skills/red-team-audit/lenses'),
      createdAt: new Date('2026-07-29T15:01:00.000Z'),
    })
    const finalDirectory = join(
      output,
      plan.run.run_id.replaceAll(':', '_'),
    )
    await mkdir(finalDirectory)
    const sentinel = join(finalDirectory, 'existing.txt')
    await writeFile(sentinel, 'preserve me')

    await assert.rejects(
      writeRunPlanBundle(plan, output),
      /run bundle already exists/i,
    )
    assert.equal(await readFile(sentinel, 'utf8'), 'preserve me')
    assert.deepEqual(await readdir(output), [
      plan.run.run_id.replaceAll(':', '_'),
    ])
  })
})

test('CLI capacity rejection does not create its requested output directory', async () => {
  await withCliRepository(async ({ root, output }) => {
    await Promise.all(Array.from({ length: 500 }, (_, index) => writeFile(
      join(root, 'src', `route-${String(index).padStart(3, '0')}.js`),
      'module.exports = require("express").Router()\n',
    )))
    const rejectedOutput = join(output, 'capacity-rejected')
    const result = spawnSync(
      process.execPath,
      [
        CLI,
        'plan',
        root,
        '--out',
        rejectedOutput,
        '--max-shard-files',
        '1',
        '--max-closure-rounds',
        '32',
      ],
      { encoding: 'utf8' },
    )

    assert.equal(result.status, 1)
    assert.match(result.stderr, /bounded bundle capacity/i)
    await assert.rejects(lstat(rejectedOutput), { code: 'ENOENT' })
  })
})

test('CLI plan refuses a linked output parent', async () => {
  await withCliRepository(async ({ root, output }) => {
    const actualOutput = join(output, 'actual-output')
    const linkedOutput = join(output, 'linked-output')
    await mkdir(actualOutput)
    await createDirectoryLink(actualOutput, linkedOutput)
    for (const candidate of [
      linkedOutput,
      join(linkedOutput, 'must-not-exist', 'nested-output'),
    ]) {
      const result = spawnSync(
        process.execPath,
        [CLI, 'plan', root, '--out', candidate],
        { encoding: 'utf8' },
      )
      assert.equal(result.status, 1)
      assert.match(result.stderr, /symbolic link|reparse point/i)
      assert.deepEqual(await readdir(actualOutput), [])
    }
  })
})

test('CLI rejects a custom output directory inside the audited repository before creating it', async () => {
  await withCliRepository(async ({ root }) => {
    const customOutput = join(root, 'custom-runs')
    const result = spawnSync(
      process.execPath,
      [CLI, 'plan', root, '--out', customOutput],
      { encoding: 'utf8' },
    )
    assert.equal(result.status, 1)
    assert.match(result.stderr, /custom --out directory must be outside/i)
    await assert.rejects(lstat(customOutput), { code: 'ENOENT' })
  })
})

test('CLI never writes a sealed exact-byte archive to the default in-target output', async () => {
  await withCliRepository(async ({ root }) => {
    const result = spawnSync(
      process.execPath,
      [CLI, 'plan', '.', '--seal-source'],
      { cwd: root, encoding: 'utf8' },
    )
    assert.equal(result.status, 1)
    assert.match(
      result.stderr,
      /--seal-source.*sensitive exact-byte archive.*outside the audited repository/is,
    )
    await assert.rejects(lstat(join(root, '.audit-runs')), { code: 'ENOENT' })
  })
})

test('CLI rejects a provider result replayed against the wrong dispatch packet', async () => {
  await withCliRepository(async ({ root, output }) => {
    execFileSync(
      process.execPath,
      [CLI, 'plan', root, '--out', output],
      { encoding: 'utf8' },
    )
    const [directory] = await readdir(output)
    const bundle = join(output, directory)
    const next = JSON.parse(execFileSync(
      process.execPath,
      [CLI, 'next', bundle],
      { encoding: 'utf8' },
    ))
    const job = next.pending_jobs[0]
    const resultPath = join(output, 'replayed-result.json')
    await writeFile(resultPath, JSON.stringify({
      schema_version: '1.0.0',
      run_id: next.run_id,
      job_id: job.job_id,
      input_sha256: '0'.repeat(64),
      producer: {
        name: 'test-provider',
        version: '1.0.0',
        instance_id: 'test-provider:replay',
      },
      state: 'SUCCEEDED',
      examined_files: job.scoped_files,
      findings: [],
      coverage_gaps: [],
    }))
    const replay = spawnSync(
      process.execPath,
      [CLI, 'ingest', bundle, resultPath],
      { encoding: 'utf8' },
    )
    assert.equal(replay.status, 1)
    assert.match(replay.stderr, /not bound to the current dispatch packet/i)
  })
})

test('CLI batch ingest accepts serial results and stops durably on the first failure', async () => {
  await withCliRepository(async ({ root, output }) => {
    await writeFile(join(root, 'Dockerfile'), 'FROM node:22-alpine\n')
    execFileSync(
      process.execPath,
      [
        CLI,
        'plan',
        root,
        '--out',
        output,
        '--max-shard-files',
        '1',
      ],
      { encoding: 'utf8' },
    )
    const [directory] = await readdir(output)
    const bundle = join(output, directory)
    const runPath = join(bundle, 'run.json')
    const firstWave = JSON.parse(execFileSync(
      process.execPath,
      [CLI, 'next', bundle],
      { encoding: 'utf8' },
    ))
    assert.ok(firstWave.pending_jobs.length >= 5)

    const firstPaths = []
    for (const [index, job] of firstWave.pending_jobs.slice(0, 2).entries()) {
      const resultPath = join(output, `batch-accepted-${index + 1}.json`)
      await writeFile(
        resultPath,
        JSON.stringify(successfulProviderResult(firstWave, job)),
      )
      firstPaths.push(resultPath)
    }
    const accepted = execFileSync(
      process.execPath,
      [CLI, 'ingest-batch', bundle, ...firstPaths],
      { encoding: 'utf8' },
    )
    assert.match(accepted, /Batch accepted 2 results/)

    const afterAccepted = JSON.parse(await readFile(runPath, 'utf8'))
    for (const job of firstWave.pending_jobs.slice(0, 2)) {
      assert.equal(
        afterAccepted.jobs.find(({ job_id: jobId }) => jobId === job.job_id).state,
        'SUCCEEDED',
      )
    }

    const secondWave = JSON.parse(execFileSync(
      process.execPath,
      [CLI, 'next', bundle],
      { encoding: 'utf8' },
    ))
    assert.ok(secondWave.pending_jobs.length >= 3)
    const [durableJob, rejectedJob, unattemptedJob] = secondWave.pending_jobs
    const durablePath = join(output, 'batch-durable-before-failure.json')
    const rejectedPath = join(output, 'batch-rejected.json')
    const unattemptedPath = join(output, 'batch-unattempted.json')
    await Promise.all([
      writeFile(
        durablePath,
        JSON.stringify(successfulProviderResult(secondWave, durableJob)),
      ),
      writeFile(
        rejectedPath,
        JSON.stringify(successfulProviderResult(secondWave, rejectedJob, {
          input_sha256: '0'.repeat(64),
        })),
      ),
      writeFile(
        unattemptedPath,
        JSON.stringify(successfulProviderResult(secondWave, unattemptedJob)),
      ),
    ])

    const stopped = spawnSync(
      process.execPath,
      [
        CLI,
        'ingest-batch',
        bundle,
        durablePath,
        rejectedPath,
        unattemptedPath,
      ],
      { encoding: 'utf8' },
    )
    assert.equal(stopped.status, 1)
    assert.match(stopped.stdout, /Accepted .*: SUCCEEDED/)
    assert.match(
      stopped.stderr,
      /stopped at result 2 .* after accepting 1: .*not bound to the current dispatch packet/is,
    )

    const afterFailure = JSON.parse(await readFile(runPath, 'utf8'))
    assert.equal(
      afterFailure.jobs.find(
        ({ job_id: jobId }) => jobId === durableJob.job_id,
      ).state,
      'SUCCEEDED',
    )
    for (const job of [rejectedJob, unattemptedJob]) {
      assert.equal(
        afterFailure.jobs.find(({ job_id: jobId }) => jobId === job.job_id).state,
        'PENDING',
      )
    }
  })
})

test('CLI bounds provider result bytes and collection cardinality before mutation', async () => {
  await withCliRepository(async ({ root, output }) => {
    const bundle = await planBundle(root, output)
    const runPath = join(bundle, 'run.json')
    const originalRun = await readFile(runPath, 'utf8')
    const next = JSON.parse(execFileSync(
      process.execPath,
      [CLI, 'next', bundle],
      { encoding: 'utf8' },
    ))
    const job = next.pending_jobs[0]

    const oversizedPath = join(output, 'oversized-result.json')
    await writeFile(oversizedPath, Buffer.alloc((8 * 1024 * 1024) + 1, 0x20))
    const oversized = spawnSync(
      process.execPath,
      [CLI, 'ingest', bundle, oversizedPath],
      { encoding: 'utf8' },
    )
    assert.equal(oversized.status, 1)
    assert.match(oversized.stderr, /provider result JSON exceeds the 8388608-byte input limit/i)
    assert.equal(await readFile(runPath, 'utf8'), originalRun)

    const cardinalityPath = join(output, 'over-cardinality-result.json')
    await writeFile(cardinalityPath, JSON.stringify(successfulProviderResult(next, job, {
      coverage_gaps: Array.from({ length: 4097 }, (_, index) => ({
        area: `bounded-area-${index}`,
        reason: 'bounded test gap',
      })),
    })))
    const cardinality = spawnSync(
      process.execPath,
      [CLI, 'ingest', bundle, cardinalityPath],
      { encoding: 'utf8' },
    )
    assert.equal(cardinality.status, 1)
    assert.match(cardinality.stderr, /more than 4096 items|maxItems/i)
    assert.equal(await readFile(runPath, 'utf8'), originalRun)
  })
})

test('CLI bounds run manifests and streams bounded bundle artifact verification', async () => {
  await withCliRepository(async ({ root, output }) => {
    const oversizedRun = join(output, 'oversized-run.json')
    await writeFile(oversizedRun, '{}')
    await truncate(oversizedRun, MAX_RUN_MANIFEST_BYTES + 1)
    const rejectedRun = spawnSync(
      process.execPath,
      [CLI, 'validate', oversizedRun],
      { encoding: 'utf8' },
    )
    assert.equal(rejectedRun.status, 1)
    assert.match(rejectedRun.stderr, /run manifest exceeds.*input limit/i)

    await rm(oversizedRun)
    const bundle = await planBundle(root, output)
    const inventoryPath = join(bundle, 'inventory.json')
    await truncate(inventoryPath, MAX_BUNDLE_ARTIFACT_BYTES + 1)
    const rejectedArtifact = spawnSync(
      process.execPath,
      [CLI, 'validate', bundle],
      { encoding: 'utf8' },
    )
    assert.equal(rejectedArtifact.status, 1)
    assert.match(
      rejectedArtifact.stderr,
      /inventory\.json exceeds.*verification limit/i,
    )
  })
})

test('CLI rejects a linked bundle directory during artifact reads', async () => {
  await withCliRepository(async ({ root, output }) => {
    const bundle = await planBundle(root, output)
    const jobsPath = join(bundle, 'jobs')
    const escapedJobsPath = join(output, 'escaped-jobs')
    await rename(jobsPath, escapedJobsPath)
    await createDirectoryLink(escapedJobsPath, jobsPath)

    const result = spawnSync(process.execPath, [CLI, 'next', bundle], {
      encoding: 'utf8',
    })
    assert.equal(result.status, 1)
    assert.match(result.stderr, /symbolic link|reparse point|canonical root/i)
  })
})

test('CLI rejects a linked results directory before writing provider evidence', async () => {
  await withCliRepository(async ({ root, output }) => {
    const bundle = await planBundle(root, output)
    const runPath = join(bundle, 'run.json')
    const originalRun = await readFile(runPath, 'utf8')
    const next = JSON.parse(execFileSync(
      process.execPath,
      [CLI, 'next', bundle],
      { encoding: 'utf8' },
    ))
    const job = next.pending_jobs[0]
    const escapedResultsPath = join(output, 'escaped-results')
    await mkdir(escapedResultsPath)
    await createDirectoryLink(escapedResultsPath, join(bundle, 'results'))
    const resultPath = join(output, 'provider-result-for-linked-output.json')
    await writeFile(
      resultPath,
      JSON.stringify(successfulProviderResult(next, job)),
    )

    const result = spawnSync(
      process.execPath,
      [CLI, 'ingest', bundle, resultPath],
      { encoding: 'utf8' },
    )
    assert.equal(result.status, 1)
    assert.match(result.stderr, /symbolic link|reparse point|canonical root/i)
    assert.deepEqual(await readdir(escapedResultsPath), [])
    assert.equal(await readFile(runPath, 'utf8'), originalRun)
  })
})

test('CLI unlock removes only a stale parsed-PID lock', async () => {
  await withCliRepository(async ({ root, output }) => {
    const bundle = await planBundle(root, output)
    const lockPath = join(bundle, 'run.json.lock')
    const recoveryPath = `${lockPath}.recovery`
    await writeFile(lockPath, JSON.stringify({
      pid: process.pid,
      created_at: new Date().toISOString(),
      token: 'live-owner-token-0000000000000000',
    }))

    const live = spawnSync(process.execPath, [CLI, 'unlock', bundle], {
      encoding: 'utf8',
    })
    assert.equal(live.status, 1)
    assert.match(live.stderr, new RegExp(`live PID ${process.pid}`, 'i'))
    assert.equal((await lstat(lockPath)).isFile(), true)

    for (const malformed of ['', '{"pid":']) {
      await writeFile(lockPath, malformed)
      const blockedByMalformed = spawnSync(
        process.execPath,
        [CLI, 'abort', bundle, '--reason', 'malformed lock must fail closed'],
        { encoding: 'utf8' },
      )
      assert.equal(blockedByMalformed.status, 1)
      assert.match(blockedByMalformed.stderr, /run is locked/i)

      const recoveredMalformed = execFileSync(
        process.execPath,
        [CLI, 'unlock', bundle],
        { encoding: 'utf8' },
      )
      assert.match(recoveredMalformed, /Removed stable malformed run lock/i)
      await assert.rejects(lstat(lockPath), { code: 'ENOENT' })
    }

    const stalePid = 2147483646
    assert.throws(() => process.kill(stalePid, 0), { code: 'ESRCH' })
    await writeFile(lockPath, JSON.stringify({
      pid: stalePid,
      created_at: '2000-01-01T00:00:00.000Z',
      token: 'stale-owner-token-000000000000000',
    }))
    const blocked = spawnSync(
      process.execPath,
      [CLI, 'abort', bundle, '--reason', 'bounded stale-lock test'],
      { encoding: 'utf8' },
    )
    assert.equal(blocked.status, 1)
    assert.match(blocked.stderr, /run is locked[\s\S]*red-team-audit unlock/i)

    await writeFile(recoveryPath, JSON.stringify({
      pid: stalePid,
      created_at: '2000-01-01T00:00:00.000Z',
      token: 'crashed-recovery-token-0000000000000',
    }))
    const unlocked = execFileSync(
      process.execPath,
      [CLI, 'unlock', bundle],
      { encoding: 'utf8' },
    )
    assert.match(unlocked, new RegExp(`Removed stale run lock for PID ${stalePid}`))
    await assert.rejects(lstat(lockPath), { code: 'ENOENT' })
    await assert.rejects(lstat(recoveryPath), { code: 'ENOENT' })

    const aborted = execFileSync(
      process.execPath,
      [CLI, 'abort', bundle, '--reason', 'bounded stale-lock test'],
      { encoding: 'utf8' },
    )
    assert.match(aborted, /Aborted/)
  })
})

test('CLI benchmark derives its denominator and schema-invalid count', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'red-team-benchmark-'))
  try {
    const inputPath = join(directory, 'evaluation.json')
    const scorecardPath = join(directory, 'scorecard.json')
    await writeFile(inputPath, JSON.stringify({
      primary_run_id: 'repeat:1',
      observedFindings: [{
        case_id: 'V-001',
        finding: { candidate_id: 'malformed' },
      }],
      caseOutcomes: [],
      repeatedRuns: [
        { run_id: 'repeat:1', findings: [] },
        { run_id: 'repeat:2', findings: [] },
      ],
    }))
    const result = spawnSync(
      process.execPath,
      [CLI, 'benchmark', inputPath, '--out', scorecardPath],
      { encoding: 'utf8' },
    )
    assert.equal(result.status, 2)
    const scorecard = JSON.parse(await readFile(scorecardPath, 'utf8'))
    assert.equal(scorecard.provenance.case_manifest.cases, 64)
    assert.deepEqual(
      {
        run_id: scorecard.provenance.primary_run.run_id,
        count: scorecard.provenance.primary_run.normalized_finding_count,
        bound: scorecard.provenance.primary_run.bound_to_repeated_run,
      },
      { run_id: 'repeat:1', count: 0, bound: true },
    )
    assert.match(
      scorecard.provenance.primary_run.normalized_finding_set_sha256,
      /^[a-f0-9]{64}$/,
    )
    assert.equal(scorecard.metrics.counts.schema_invalid, 1)
    assert.equal(scorecard.invalid_records.length, 1)

    await writeFile(inputPath, JSON.stringify({
      expectedCases: [],
      observedFindings: [],
      repeatedRuns: [],
    }))
    const spoofed = spawnSync(
      process.execPath,
      [CLI, 'benchmark', inputPath],
      { encoding: 'utf8' },
    )
    assert.equal(spoofed.status, 1)
    assert.match(spoofed.stderr, /controller-derived/i)
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
})

test('CLI benchmark rejects capability observations not bound to the primary repeated run', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'red-team-benchmark-binding-'))
  try {
    const inputPath = join(directory, 'evaluation.json')
    await writeFile(inputPath, JSON.stringify({
      primary_run_id: 'repeat:primary',
      observedFindings: [{
        case_id: 'V-001',
        finding: benchmarkFinding(),
      }],
      caseOutcomes: [],
      repeatedRuns: [{
        run_id: 'repeat:primary',
        findings: [],
      }],
    }))
    const mismatched = spawnSync(
      process.execPath,
      [CLI, 'benchmark', inputPath],
      { encoding: 'utf8' },
    )
    assert.equal(mismatched.status, 1)
    assert.match(
      mismatched.stderr,
      /observedFindings must exactly match repeated run "repeat:primary"/,
    )

    await writeFile(
      inputPath,
      Buffer.alloc((16 * 1024 * 1024) + 1, 0x20),
    )
    const oversized = spawnSync(
      process.execPath,
      [CLI, 'benchmark', inputPath],
      { encoding: 'utf8' },
    )
    assert.equal(oversized.status, 1)
    assert.match(
      oversized.stderr,
      /benchmark evaluation JSON exceeds the 16777216-byte input limit/i,
    )
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
})

test('CLI validation rejects malformed run records', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'red-team-invalid-run-'))
  try {
    const path = join(directory, 'run.json')
    await writeFile(path, '{"state":"COMPLETED"}\n')
    const result = spawnSync(process.execPath, [CLI, 'validate', path], {
      encoding: 'utf8',
    })
    assert.equal(result.status, 1)
    assert.match(result.stderr, /INVALID:/)
    assert.match(result.stderr, /required/)
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
})

test('CLI refuses a lens sidecar whose committed digest no longer matches', async () => {
  await withCliRepository(async ({ root, output }) => {
    execFileSync(
      process.execPath,
      [CLI, 'plan', root, '--out', output],
      { encoding: 'utf8' },
    )
    const [directory] = await readdir(output)
    const bundle = join(output, directory)
    const run = JSON.parse(await readFile(join(bundle, 'run.json'), 'utf8'))
    const job = run.jobs.find(({ kind, state }) => kind === 'LENS' && state === 'PENDING')
    const artifact = run.artifacts[
      `job_${artifactKeyToken(job.job_id).toLowerCase()}`
    ]
    await writeFile(join(bundle, artifact.path), '{"scoped_files":["src/app.js"]}\n')

    const result = spawnSync(process.execPath, [CLI, 'next', bundle], {
      encoding: 'utf8',
    })
    assert.equal(result.status, 1)
    assert.match(result.stderr, /artifact digest mismatch/i)
  })
})

test('CLI refuses to mix provider work across repository snapshots', async () => {
  await withCliRepository(async ({ root, output }) => {
    execFileSync(
      process.execPath,
      [CLI, 'plan', root, '--out', output],
      { encoding: 'utf8' },
    )
    const [directory] = await readdir(output)
    const bundle = join(output, directory)
    await writeFile(join(root, 'src', 'app.js'), 'const changed = true\n')

    const result = spawnSync(process.execPath, [CLI, 'next', bundle], {
      encoding: 'utf8',
    })
    assert.equal(result.status, 1)
    assert.match(result.stderr, /repository snapshot changed after planning/i)
  })
})

test('historical bundles remain reportable while active dispatch requires the current lens pack', async () => {
  await withCliRepository(async ({ root, output }) => {
    const historicalLenses = join(output, 'historical-lenses')
    await cp(resolve('skills/red-team-audit/lenses'), historicalLenses, {
      recursive: true,
    })
    const historicalLens = join(historicalLenses, 'web-and-api.md')
    await writeFile(
      historicalLens,
      `${await readFile(historicalLens, 'utf8')}\n<!-- historical test pack -->\n`,
    )
    const plan = await createRunPlan({
      targetRoot: root,
      lensDirectory: historicalLenses,
      createdAt: new Date('2026-07-29T12:00:00.000Z'),
    })
    const written = await writeRunPlanBundle(plan, join(output, 'bundles'))

    const report = execFileSync(
      process.execPath,
      [CLI, 'report', written.directory],
      { encoding: 'utf8' },
    )
    assert.match(report, /not a clean audit result/i)

    const active = spawnSync(
      process.execPath,
      [CLI, 'next', written.directory],
      { encoding: 'utf8' },
    )
    assert.equal(active.status, 1)
    assert.match(active.stderr, /trusted lens pack changed after planning/i)
  })
})

test('CLI report preflights all exclusive outputs before creating either file', async () => {
  await withCliRepository(async ({ root, output }) => {
    const bundle = await planBundle(root, output)
    const sharedPath = join(output, 'shared-report-output')
    const aliased = spawnSync(
      process.execPath,
      [CLI, 'report', bundle, '--out', sharedPath, '--sarif', sharedPath],
      { encoding: 'utf8' },
    )
    assert.equal(aliased.status, 1)
    assert.match(aliased.stderr, /resolve to the same output path/i)
    await assert.rejects(lstat(sharedPath), { code: 'ENOENT' })

    const markdownPath = join(output, 'report-that-must-not-be-created.md')
    const sarifPath = join(output, 'existing-results.sarif')
    await writeFile(sarifPath, 'existing-sarif-sentinel')
    const existing = spawnSync(
      process.execPath,
      [CLI, 'report', bundle, '--out', markdownPath, '--sarif', sarifPath],
      { encoding: 'utf8' },
    )
    assert.equal(existing.status, 1)
    assert.match(existing.stderr, /--sarif output already exists/i)
    assert.equal(existing.stdout, '')
    assert.equal(await readFile(sarifPath, 'utf8'), 'existing-sarif-sentinel')
    await assert.rejects(lstat(markdownPath), { code: 'ENOENT' })
  })
})

test('CLI report keeps streamed Markdown stdout free of SARIF status messages', async () => {
  await withCliRepository(async ({ root, output }) => {
    const bundle = await planBundle(root, output)
    const sarifPath = join(output, 'streamed-report.sarif')
    const result = spawnSync(
      process.execPath,
      [CLI, 'report', bundle, '--sarif', sarifPath],
      { encoding: 'utf8' },
    )
    assert.equal(result.status, 0)
    assert.match(result.stdout, /^# Red Team Audit Report/m)
    assert.doesNotMatch(result.stdout, /\bWrote\b/)
    assert.match(result.stderr, new RegExp(`Wrote .*${sarifPath.split(/[\\/]/).at(-1)}`))
    const sarif = JSON.parse(await readFile(sarifPath, 'utf8'))
    assert.equal(sarif.version, '2.1.0')
  })
})

test('CLI accepts an explicitly supplied external Rules of Engagement file', async () => {
  await withCliRepository(async ({ root, output }) => {
    const policyPath = join(output, 'roe.json')
    await writeFile(policyPath, JSON.stringify({
      schema_version: '1.0',
      policy_id: 'cli-static-test',
      mode: 'static',
      workspace_root: resolve(root),
      capabilities: {
        read_file: { enabled: true, roots: ['src'] },
        write_file: { enabled: false, roots: [] },
        execute: { enabled: false, commands: [] },
        network: { enabled: false, destinations: [] },
      },
    }))

    const stdout = execFileSync(
      process.execPath,
      [CLI, 'plan', root, '--out', output, '--roe', policyPath],
      { encoding: 'utf8' },
    )
    assert.match(stdout, /State: PLANNED/)
    const directories = (await readdir(output, { withFileTypes: true }))
      .filter((entry) => entry.isDirectory())
    assert.equal(directories.length, 1)
    const policy = JSON.parse(await readFile(
      join(output, directories[0].name, 'policy.json'),
      'utf8',
    ))
    assert.equal(policy.policy_id, 'cli-static-test')
    assert.equal(policy.policy_source, 'external')
    const inventory = JSON.parse(await readFile(
      join(output, directories[0].name, 'inventory.json'),
      'utf8',
    ))
    assert.deepEqual(inventory.entries.map(({ path }) => path), ['src/app.js'])
    assert.ok(inventory.excluded.some(
      ({ reason }) => reason === 'policy-read-roots:src',
    ))
  })
})

test('CLI rejects a lexically external Rules of Engagement path that resolves into the target', async () => {
  await withCliRepository(async ({ root, output }) => {
    const policyPath = join(root, 'untrusted-roe.json')
    await writeFile(policyPath, JSON.stringify({
      schema_version: '1.0',
      policy_id: 'target-authored-policy',
      mode: 'static',
      workspace_root: resolve(root),
      capabilities: {
        read_file: { enabled: true, roots: ['src'] },
        write_file: { enabled: false, roots: [] },
        execute: { enabled: false, commands: [] },
        network: { enabled: false, destinations: [] },
      },
    }))
    const linkedRoot = join(output, 'target-link')
    await createDirectoryLink(root, linkedRoot)

    const result = spawnSync(
      process.execPath,
      [CLI, 'plan', root, '--out', output, '--roe', join(linkedRoot, 'untrusted-roe.json')],
      { encoding: 'utf8' },
    )
    assert.equal(result.status, 1)
    assert.match(
      result.stderr,
      /symbolic link|reparse point|outside the untrusted target repository/i,
    )

    const dotDotNamedPolicy = join(root, '..policy.json')
    await writeFile(dotDotNamedPolicy, await readFile(policyPath, 'utf8'))
    const direct = spawnSync(
      process.execPath,
      [CLI, 'plan', root, '--out', output, '--roe', dotDotNamedPolicy],
      { encoding: 'utf8' },
    )
    assert.equal(direct.status, 1)
    assert.match(direct.stderr, /outside the untrusted target repository/i)
  })
})

test('default in-repository run output does not create false snapshot drift', async () => {
  await withCliRepository(async ({ root }) => {
    execFileSync(process.execPath, [CLI, 'plan', '.'], {
      cwd: root,
      encoding: 'utf8',
    })
    const output = join(root, '.audit-runs')
    const [directory] = await readdir(output)
    const next = JSON.parse(execFileSync(
      process.execPath,
      [CLI, 'next', join(output, directory)],
      { cwd: root, encoding: 'utf8' },
    ))
    assert.ok(next.pending_jobs.length > 0)
  })
})
