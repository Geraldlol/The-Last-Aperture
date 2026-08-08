import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { generateKeyPairSync } from 'node:crypto'
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
import { publishTransparencyCommand } from '../scripts/audit.mjs'
import {
  canonicalAttestationBytes,
  createTransparencyConsistencyProof,
  createTransparencyInclusionReceipt,
  projectTransparencySignedCheckpoint,
  transparencyLeafHash,
  transparencyNodeHash,
} from '../scripts/lib/transparency-log-contracts.mjs'
import {
  openTransparencyCheckpointJournal,
} from '../scripts/lib/transparency-checkpoint-journal.mjs'
import {
  createRunPlan,
  writeRunPlanBundle,
} from '../scripts/lib/run-engine.mjs'
import { measureCoverageClosure } from '../scripts/lib/coverage-model.mjs'
import {
  MAX_BUNDLE_ARTIFACT_BYTES,
  MAX_RUN_MANIFEST_BYTES,
} from '../scripts/lib/resource-limits.mjs'
const CLI = resolve('scripts/audit.mjs')

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

function writeEd25519KeyPair(privateKeyPath, publicKeyPath) {
  const keys = generateKeyPairSync('ed25519', {
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  })
  return Promise.all([
    writeFile(privateKeyPath, keys.privateKey, { mode: 0o600 }),
    writeFile(publicKeyPath, keys.publicKey, { mode: 0o600 }),
  ])
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
  assert.match(output, /^red-team-audit 0\.11\.0/m)
  assert.match(output, /red-team-audit plan/)
  assert.match(output, /--max-shard-files <count>/)
  assert.match(output, /--max-shard-bytes <bytes>/)
  assert.match(output, /--max-closure-rounds <count>/)
  assert.match(output, /--require-source-closure/)
  assert.match(output, /--database-conformance <complete-bundle>/)
  assert.match(output, /red-team-audit ingest-batch/)
  assert.match(output, /red-team-audit run-remote/)
  assert.match(output, /red-team-audit unlock/)
  assert.match(output, /red-team-audit attest/)
  assert.match(output, /red-team-audit publish/)
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

test('CLI attests a terminal run and verifies its exact external trust root', async () => {
  await withCliRepository(async ({ root, output }) => {
    const bundle = await planBundle(root, output)
    const privateKeyPath = join(output, 'root-private.pem')
    const publicKeyPath = join(output, 'root-public.pem')
    const attestationPath = join(output, 'root-attestation.json')
    await writeEd25519KeyPair(privateKeyPath, publicKeyPath)

    execFileSync(
      process.execPath,
      [CLI, 'abort', bundle, '--reason', 'terminal attestation test'],
      { encoding: 'utf8' },
    )
    const attested = execFileSync(
      process.execPath,
      [
        CLI,
        'attest',
        bundle,
        '--signing-key',
        privateKeyPath,
        '--out',
        attestationPath,
      ],
      { encoding: 'utf8' },
    )
    assert.match(attested, /Root SHA-256: [a-f0-9]{64}/)
    assert.match(attested, /Signing key: ed25519:[a-f0-9]{64}/)

    const anchored = execFileSync(
      process.execPath,
      [
        CLI,
        'validate',
        bundle,
        '--root-attestation',
        attestationPath,
        '--root-public-key',
        publicKeyPath,
      ],
      { encoding: 'utf8' },
    )
    assert.match(anchored, /Root authenticity: VERIFIED/)

    const anchoredReport = execFileSync(
      process.execPath,
      [
        CLI,
        'report',
        bundle,
        '--root-attestation',
        attestationPath,
        '--root-public-key',
        publicKeyPath,
      ],
      { encoding: 'utf8' },
    )
    assert.match(anchoredReport, /# Red Team Audit Report/)

    const unanchored = execFileSync(
      process.execPath,
      [CLI, 'validate', bundle],
      { encoding: 'utf8' },
    )
    assert.match(unanchored, /Root authenticity: UNANCHORED/)

    const runPath = join(bundle, 'run.json')
    const originalRun = await readFile(runPath, 'utf8')
    await writeFile(runPath, `${originalRun}\n`)
    const replaced = spawnSync(
      process.execPath,
      [
        CLI,
        'validate',
        bundle,
        '--root-attestation',
        attestationPath,
        '--root-public-key',
        publicKeyPath,
      ],
      { encoding: 'utf8' },
    )
    assert.equal(replaced.status, 1)
    assert.match(
      replaced.stderr,
      /attestation does not describe the exact loaded run manifest/i,
    )
  })
})

test('CLI root attestation fails closed on active runs, partial pins, and in-bundle output', async () => {
  await withCliRepository(async ({ root, output }) => {
    const bundle = await planBundle(root, output)
    const privateKeyPath = join(output, 'root-private.pem')
    const publicKeyPath = join(output, 'root-public.pem')
    await writeEd25519KeyPair(privateKeyPath, publicKeyPath)

    const active = spawnSync(
      process.execPath,
      [
        CLI,
        'attest',
        bundle,
        '--signing-key',
        privateKeyPath,
        '--out',
        join(output, 'active-attestation.json'),
      ],
      { encoding: 'utf8' },
    )
    assert.equal(active.status, 1)
    assert.match(active.stderr, /only a terminal FINALIZED run/i)

    const partialPin = spawnSync(
      process.execPath,
      [
        CLI,
        'validate',
        bundle,
        '--root-public-key',
        publicKeyPath,
      ],
      { encoding: 'utf8' },
    )
    assert.equal(partialPin.status, 1)
    assert.match(
      partialPin.stderr,
      /--root-attestation and --root-public-key must be supplied together/i,
    )

    execFileSync(
      process.execPath,
      [CLI, 'abort', bundle, '--reason', 'finish negative test'],
      { encoding: 'utf8' },
    )
    const internalOutput = spawnSync(
      process.execPath,
      [
        CLI,
        'attest',
        bundle,
        '--signing-key',
        privateKeyPath,
        '--out',
        join(bundle, 'root-attestation.json'),
      ],
      { encoding: 'utf8' },
    )
    assert.equal(internalOutput.status, 1)
    assert.match(
      internalOutput.stderr,
      /output must be outside the run bundle and target repository/i,
    )
  })
})

async function pathExists(path) {
  try {
    await lstat(path)
    return true
  } catch (error) {
    if (error.code === 'ENOENT') return false
    throw error
  }
}

async function prepareTransparencyContinuityFixture(root, output) {
  const bundle = await planBundle(root, output)
  const rootPrivateKeyPath = join(output, 'continuity-root-private.pem')
  const rootPublicKeyPath = join(output, 'continuity-root-public.pem')
  const rootAttestationPath = join(output, 'continuity-root-attestation.json')
  const logPublicKeyPath = join(output, 'continuity-log-public.pem')
  const config10Path = join(output, 'transparency-config-1.0.json')
  const config11Path = join(output, 'transparency-config-1.1.json')
  await writeEd25519KeyPair(rootPrivateKeyPath, rootPublicKeyPath)
  const logKeys = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })
  await writeFile(logPublicKeyPath, logKeys.publicKey, { mode: 0o600 })
  const limits = {
    request_timeout_ms: 30000,
    max_clock_skew_ms: 30000,
    max_request_bytes: 262144,
    max_response_bytes: 262144,
  }
  const commonConfig = {
    protocol: 'transparency-log-v1',
    log_url: 'https://log.example/v1/entries',
    log_origin: 'audit-log.example/v1',
    log_public_key_path: logPublicKeyPath,
    tls_spki_sha256: 'a'.repeat(64),
    limits,
  }
  await Promise.all([
    writeFile(config10Path, JSON.stringify({
      schema_version: '1.0.0',
      ...commonConfig,
    })),
    writeFile(config11Path, JSON.stringify({
      schema_version: '1.1.0',
      ...commonConfig,
      consistency_url: 'https://log.example/v1/consistency',
    })),
  ])

  execFileSync(
    process.execPath,
    [CLI, 'abort', bundle, '--reason', 'terminal continuity test'],
    { encoding: 'utf8' },
  )
  execFileSync(
    process.execPath,
    [
      CLI,
      'attest',
      bundle,
      '--signing-key',
      rootPrivateKeyPath,
      '--out',
      rootAttestationPath,
    ],
    { encoding: 'utf8' },
  )

  const attestation = JSON.parse(await readFile(rootAttestationPath, 'utf8'))
  const firstLeaf = transparencyLeafHash(canonicalAttestationBytes(attestation))
  const appendedLeaf = transparencyLeafHash(
    Buffer.from('independent appended transparency entry', 'utf8'),
  )
  const laterLeaf = transparencyLeafHash(
    Buffer.from('later independent transparency entry', 'utf8'),
  )
  const forkLeaf = transparencyLeafHash(
    Buffer.from('conflicting appended transparency entry', 'utf8'),
  )
  const issuedAt = Date.now()
  const firstReceipt = createTransparencyInclusionReceipt({
    attestation,
    leafIndex: 0,
    treeSize: 1,
    inclusionPath: [],
    rootHash: firstLeaf,
    origin: commonConfig.log_origin,
    privateKeyBytes: logKeys.privateKey,
    issuedAt: new Date(issuedAt - 3000),
  })
  const secondReceipt = createTransparencyInclusionReceipt({
    attestation,
    leafIndex: 0,
    treeSize: 2,
    inclusionPath: [appendedLeaf],
    rootHash: transparencyNodeHash(firstLeaf, appendedLeaf),
    origin: commonConfig.log_origin,
    privateKeyBytes: logKeys.privateKey,
    issuedAt: new Date(issuedAt - 2000),
  })
  const thirdReceipt = createTransparencyInclusionReceipt({
    attestation,
    leafIndex: 0,
    treeSize: 3,
    inclusionPath: [appendedLeaf, laterLeaf],
    rootHash: transparencyNodeHash(
      transparencyNodeHash(firstLeaf, appendedLeaf),
      laterLeaf,
    ),
    origin: commonConfig.log_origin,
    privateKeyBytes: logKeys.privateKey,
    issuedAt: new Date(issuedAt - 1000),
  })
  const forkReceipt = createTransparencyInclusionReceipt({
    attestation,
    leafIndex: 0,
    treeSize: 2,
    inclusionPath: [forkLeaf],
    rootHash: transparencyNodeHash(firstLeaf, forkLeaf),
    origin: commonConfig.log_origin,
    privateKeyBytes: logKeys.privateKey,
    issuedAt: new Date(issuedAt - 1000),
  })
  const firstCheckpoint = projectTransparencySignedCheckpoint(firstReceipt)
  const secondCheckpoint = projectTransparencySignedCheckpoint(secondReceipt)
  const thirdCheckpoint = projectTransparencySignedCheckpoint(thirdReceipt)
  const validConsistencyProof = createTransparencyConsistencyProof({
    firstCheckpoint,
    secondCheckpoint,
    consistencyPath: [appendedLeaf],
  })
  const forkConsistencyProof = createTransparencyConsistencyProof({
    firstCheckpoint,
    secondCheckpoint: projectTransparencySignedCheckpoint(forkReceipt),
    consistencyPath: [forkLeaf],
  })
  const firstToThirdConsistencyProof = createTransparencyConsistencyProof({
    firstCheckpoint,
    secondCheckpoint: thirdCheckpoint,
    consistencyPath: [appendedLeaf, laterLeaf],
  })
  const secondToThirdConsistencyProof = createTransparencyConsistencyProof({
    firstCheckpoint: secondCheckpoint,
    secondCheckpoint: thirdCheckpoint,
    consistencyPath: [laterLeaf],
  })

  return {
    bundle,
    rootPublicKeyPath,
    rootAttestationPath,
    logPublicKeyPath,
    config10Path,
    config11Path,
    firstReceipt,
    secondReceipt,
    thirdReceipt,
    forkReceipt,
    validConsistencyProof,
    forkConsistencyProof,
    firstToThirdConsistencyProof,
    secondToThirdConsistencyProof,
    firstCheckpoint,
    secondCheckpoint,
    thirdCheckpoint,
  }
}

function continuityPublishOptions(fixture, out, journal, additions = {}) {
  return {
    'root-attestation': fixture.rootAttestationPath,
    'root-public-key': fixture.rootPublicKeyPath,
    out,
    ...(journal === undefined
      ? {}
      : { 'transparency-checkpoint-journal': journal }),
    ...additions,
  }
}

test('CLI publishes and offline-verifies an external transparency inclusion receipt', async () => {
  await withCliRepository(async ({ root, output }) => {
    const bundle = await planBundle(root, output)
    const rootPrivateKeyPath = join(output, 'root-private.pem')
    const rootPublicKeyPath = join(output, 'root-public.pem')
    const rootAttestationPath = join(output, 'root-attestation.json')
    const logPublicKeyPath = join(output, 'log-public.pem')
    const configPath = join(output, 'transparency-config.json')
    const receiptPath = join(output, 'inclusion-receipt.json')
    await writeEd25519KeyPair(rootPrivateKeyPath, rootPublicKeyPath)
    const logKeys = generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    })
    await writeFile(logPublicKeyPath, logKeys.publicKey, { mode: 0o600 })
    await writeFile(configPath, JSON.stringify({
      schema_version: '1.0.0',
      protocol: 'transparency-log-v1',
      log_url: 'https://log.example/v1/entries',
      log_origin: 'audit-log.example/v1',
      log_public_key_path: logPublicKeyPath,
      tls_spki_sha256: 'a'.repeat(64),
      limits: {
        request_timeout_ms: 30000,
        max_clock_skew_ms: 30000,
        max_request_bytes: 262144,
        max_response_bytes: 262144,
      },
    }))

    execFileSync(
      process.execPath,
      [CLI, 'abort', bundle, '--reason', 'terminal transparency test'],
      { encoding: 'utf8' },
    )
    execFileSync(
      process.execPath,
      [
        CLI,
        'attest',
        bundle,
        '--signing-key',
        rootPrivateKeyPath,
        '--out',
        rootAttestationPath,
      ],
      { encoding: 'utf8' },
    )

    await publishTransparencyCommand(
      [bundle, configPath],
      {
        'root-attestation': rootAttestationPath,
        'root-public-key': rootPublicKeyPath,
        out: receiptPath,
      },
      {
        submitTransparencyLogEntry: async ({ attestation }) => {
          const leafHash = transparencyLeafHash(
            canonicalAttestationBytes(attestation),
          )
          const receipt = createTransparencyInclusionReceipt({
            attestation,
            leafIndex: 0,
            treeSize: 1,
            inclusionPath: [],
            rootHash: leafHash,
            origin: 'audit-log.example/v1',
            privateKeyBytes: logKeys.privateKey,
            issuedAt: new Date(Date.now() - 1000),
          })
          return { receipt }
        },
      },
    )

    const verified = execFileSync(
      process.execPath,
      [
        CLI,
        'validate',
        bundle,
        '--root-attestation',
        rootAttestationPath,
        '--root-public-key',
        rootPublicKeyPath,
        '--transparency-receipt',
        receiptPath,
        '--transparency-log-public-key',
        logPublicKeyPath,
        '--transparency-log-origin',
        'audit-log.example/v1',
      ],
      { encoding: 'utf8' },
    )
    assert.match(verified, /Root authenticity: VERIFIED/)
    assert.match(
      verified,
      /Transparency inclusion: VERIFIED \(audit-log\.example\/v1, tree 1, leaf 0\)/,
    )

    const partialPin = spawnSync(
      process.execPath,
      [
        CLI,
        'validate',
        bundle,
        '--root-attestation',
        rootAttestationPath,
        '--root-public-key',
        rootPublicKeyPath,
        '--transparency-receipt',
        receiptPath,
      ],
      { encoding: 'utf8' },
    )
    assert.equal(partialPin.status, 1)
    assert.match(
      partialPin.stderr,
      /--transparency-receipt, --transparency-log-public-key, and --transparency-log-origin must be supplied together/i,
    )
  })
})

test('CLI explicitly initializes and advances external transparency continuity before receipt output', async () => {
  await withCliRepository(async ({ root, output }) => {
    const fixture = await prepareTransparencyContinuityFixture(root, output)
    const journalPath = join(output, 'continuity-journal')
    const baselineReceiptPath = join(output, 'continuity-baseline-receipt.json')
    let consistencyRequests = 0
    const baseline = await publishTransparencyCommand(
      [fixture.bundle, fixture.config11Path],
      continuityPublishOptions(
        fixture,
        baselineReceiptPath,
        journalPath,
        { 'initialize-transparency-checkpoint-journal': true },
      ),
      {
        submitTransparencyLogEntry: async () => ({
          receipt: fixture.firstReceipt,
        }),
        submitTransparencyConsistencyRequest: async () => {
          consistencyRequests += 1
          throw new Error('baseline must not request a consistency proof')
        },
      },
    )

    assert.equal(consistencyRequests, 0)
    assert.equal(baseline.continuity.status, 'NOT_VERIFIED')
    assert.equal(baseline.continuity.claim, 'CHECKPOINT_BASELINE_ONLY')
    assert.equal(baseline.continuity.consistency, 'NOT_VERIFIED')
    assert.deepEqual(
      JSON.parse(await readFile(baselineReceiptPath, 'utf8')),
      fixture.firstReceipt,
    )
    const baselineRecordPath = join(
      journalPath,
      '0000000000000000.checkpoint-journal.json',
    )
    const baselineRecord = JSON.parse(await readFile(baselineRecordPath, 'utf8'))
    assert.equal(baselineRecord.sequence, 0)
    assert.equal(baselineRecord.previous_record_sha256, null)
    assert.equal(baselineRecord.consistency_proof, null)
    assert.deepEqual(baselineRecord.checkpoint, fixture.firstCheckpoint)

    const advancedReceiptPath = join(output, 'continuity-advanced-receipt.json')
    const ordering = []
    const advanced = await publishTransparencyCommand(
      [fixture.bundle, fixture.config11Path],
      continuityPublishOptions(fixture, advancedReceiptPath, journalPath),
      {
        submitTransparencyLogEntry: async () => {
          ordering.push('publication')
          return { receipt: fixture.secondReceipt }
        },
        submitTransparencyConsistencyRequest: async ({
          config,
          requestDocument,
          expectedFirstCheckpoint,
          expectedSecondCheckpoint,
        }) => {
          assert.equal(await pathExists(advancedReceiptPath), false)
          assert.equal(config.consistency_url, 'https://log.example/v1/consistency')
          assert.deepEqual(requestDocument, {
            schema_version: '1.0.0',
            protocol: 'transparency-log-consistency-v1',
            kind: 'red-team-audit/transparency-consistency-request',
            first_tree_size: 1,
            second_tree_size: 2,
          })
          assert.deepEqual(expectedFirstCheckpoint, fixture.firstCheckpoint)
          assert.deepEqual(expectedSecondCheckpoint, fixture.secondCheckpoint)
          assert.deepEqual(
            (await readdir(journalPath))
              .filter((name) => name.endsWith('.checkpoint-journal.json')),
            ['0000000000000000.checkpoint-journal.json'],
          )
          ordering.push('proof')
          return { proof: fixture.validConsistencyProof }
        },
        openTransparencyCheckpointJournal: async (options) => {
          const journal = await openTransparencyCheckpointJournal(options)
          return {
            load: (...args) => journal.load(...args),
            advance: async (advanceOptions) => {
              const result = await journal.advance(advanceOptions)
              if (advanceOptions.consistencyProof !== undefined) {
                assert.equal(await pathExists(advancedReceiptPath), false)
                ordering.push('journal')
              }
              return result
            },
            continuityForCheckpoint: (...args) =>
              journal.continuityForCheckpoint(...args),
            close: (...args) => journal.close(...args),
          }
        },
      },
    )

    assert.deepEqual(ordering, ['publication', 'proof', 'journal'])
    assert.equal(advanced.continuity.status, 'VERIFIED')
    assert.equal(
      advanced.continuity.claim,
      'CONSISTENT_WITH_EXTERNALLY_RETAINED_CHECKPOINT',
    )
    assert.equal(
      advanced.continuity.consistency,
      'CONSISTENT_WITH_EXTERNALLY_RETAINED_CHECKPOINT',
    )
    assert.deepEqual(
      JSON.parse(await readFile(advancedReceiptPath, 'utf8')),
      fixture.secondReceipt,
    )
    const advancedRecord = JSON.parse(await readFile(join(
      journalPath,
      '0000000000000001.checkpoint-journal.json',
    ), 'utf8'))
    assert.equal(advancedRecord.sequence, 1)
    assert.match(advancedRecord.previous_record_sha256, /^[a-f0-9]{64}$/)
    assert.deepEqual(advancedRecord.checkpoint, fixture.secondCheckpoint)
    assert.deepEqual(
      advancedRecord.consistency_proof,
      fixture.validConsistencyProof,
    )

    const offlineJournalNames = (await readdir(journalPath)).sort()
    await rename(fixture.config11Path, `${fixture.config11Path}.offline`)
    const verificationArguments = [
      fixture.bundle,
      '--root-attestation',
      fixture.rootAttestationPath,
      '--root-public-key',
      fixture.rootPublicKeyPath,
      '--transparency-receipt',
      advancedReceiptPath,
      '--transparency-log-public-key',
      fixture.logPublicKeyPath,
      '--transparency-log-origin',
      'audit-log.example/v1',
      '--transparency-checkpoint-journal',
      journalPath,
    ]
    const validated = spawnSync(
      process.execPath,
      [CLI, 'validate', ...verificationArguments, '--json'],
      { encoding: 'utf8' },
    )
    assert.equal(validated.status, 0, validated.stderr)
    const validation = JSON.parse(validated.stdout)
    assert.equal(validation.valid, true)
    assert.equal(validation.transparency_inclusion.status, 'VERIFIED')
    assert.equal(
      validation.transparency_inclusion.consistency,
      'CONSISTENT_WITH_EXTERNALLY_RETAINED_CHECKPOINT',
    )
    assert.equal(
      validation.transparency_inclusion.continuity.claim,
      'CONSISTENT_WITH_EXTERNALLY_RETAINED_CHECKPOINT',
    )

    const reported = spawnSync(
      process.execPath,
      [CLI, 'report', ...verificationArguments],
      { encoding: 'utf8' },
    )
    assert.equal(reported.status, 0, reported.stderr)
    assert.match(reported.stdout, /# Red Team Audit Report/)
    assert.match(
      reported.stderr,
      /Checkpoint continuity: CONSISTENT_WITH_EXTERNALLY_RETAINED_CHECKPOINT/,
    )
    assert.deepEqual((await readdir(journalPath)).sort(), offlineJournalNames)
  })
})

test('CLI republishes when a concurrent journal advance omits its first receipt checkpoint', async () => {
  await withCliRepository(async ({ root, output }) => {
    const fixture = await prepareTransparencyContinuityFixture(root, output)
    const journalPath = join(output, 'concurrent-ahead-journal')
    await publishTransparencyCommand(
      [fixture.bundle, fixture.config11Path],
      continuityPublishOptions(
        fixture,
        join(output, 'concurrent-ahead-baseline.json'),
        journalPath,
        { 'initialize-transparency-checkpoint-journal': true },
      ),
      {
        submitTransparencyLogEntry: async () => ({
          receipt: fixture.firstReceipt,
        }),
      },
    )

    const competingJournal = await openTransparencyCheckpointJournal({
      directory: journalPath,
      expectedOrigin: 'audit-log.example/v1',
      publicKeyBytes: await readFile(fixture.logPublicKeyPath),
      maxClockSkewMs: 30000,
    })
    try {
      await competingJournal.advance({
        expectedHead: fixture.firstCheckpoint,
        checkpoint: fixture.thirdCheckpoint,
        consistencyProof: fixture.firstToThirdConsistencyProof,
      })
    } finally {
      await competingJournal.close()
    }
    const journalNamesBefore = (await readdir(journalPath)).sort()

    const receiptPath = join(output, 'concurrent-ahead-receipt.json')
    let publications = 0
    let consistencyRequests = 0
    const result = await publishTransparencyCommand(
      [fixture.bundle, fixture.config11Path],
      continuityPublishOptions(fixture, receiptPath, journalPath),
      {
        submitTransparencyLogEntry: async () => {
          publications += 1
          if (publications === 1) return { receipt: fixture.secondReceipt }
          if (publications === 2) return { receipt: fixture.thirdReceipt }
          throw new Error('publication must converge after one idempotent retry')
        },
        submitTransparencyConsistencyRequest: async () => {
          consistencyRequests += 1
          throw new Error('an ahead journal must not request a reverse proof')
        },
      },
    )

    assert.equal(publications, 2)
    assert.equal(consistencyRequests, 0)
    assert.equal(result.continuity.status, 'VERIFIED')
    assert.equal(
      result.continuity.claim,
      'CONSISTENT_WITH_EXTERNALLY_RETAINED_CHECKPOINT',
    )
    assert.deepEqual(
      JSON.parse(await readFile(receiptPath, 'utf8')),
      fixture.thirdReceipt,
    )
    assert.deepEqual((await readdir(journalPath)).sort(), journalNamesBefore)
  })
})

test('CLI preserves a historical checkpoint fork classification without republishing', async () => {
  await withCliRepository(async ({ root, output }) => {
    const fixture = await prepareTransparencyContinuityFixture(root, output)
    const journalPath = join(output, 'historical-fork-journal')
    await publishTransparencyCommand(
      [fixture.bundle, fixture.config11Path],
      continuityPublishOptions(
        fixture,
        join(output, 'historical-fork-baseline.json'),
        journalPath,
        { 'initialize-transparency-checkpoint-journal': true },
      ),
      {
        submitTransparencyLogEntry: async () => ({
          receipt: fixture.firstReceipt,
        }),
      },
    )

    const retainedJournal = await openTransparencyCheckpointJournal({
      directory: journalPath,
      expectedOrigin: 'audit-log.example/v1',
      publicKeyBytes: await readFile(fixture.logPublicKeyPath),
      maxClockSkewMs: 30000,
    })
    try {
      await retainedJournal.advance({
        expectedHead: fixture.firstCheckpoint,
        checkpoint: fixture.secondCheckpoint,
        consistencyProof: fixture.validConsistencyProof,
      })
      await retainedJournal.advance({
        expectedHead: fixture.secondCheckpoint,
        checkpoint: fixture.thirdCheckpoint,
        consistencyProof: fixture.secondToThirdConsistencyProof,
      })
    } finally {
      await retainedJournal.close()
    }
    const journalNamesBefore = (await readdir(journalPath)).sort()
    const receiptPath = join(output, 'historical-fork-receipt.json')
    let publications = 0

    await assert.rejects(
      publishTransparencyCommand(
        [fixture.bundle, fixture.config11Path],
        continuityPublishOptions(fixture, receiptPath, journalPath),
        {
          submitTransparencyLogEntry: async () => {
            publications += 1
            if (publications > 1) {
              throw new Error('a confirmed historical fork must not be retried')
            }
            return { receipt: fixture.forkReceipt }
          },
        },
      ),
      (error) => {
        assert.equal(
          error.code,
          'TRANSPARENCY_CHECKPOINT_JOURNAL_FORK',
        )
        assert.match(
          error.message,
          /publication may already be durable.*conflicts with the journal root at the same tree size/is,
        )
        return true
      },
    )

    assert.equal(publications, 1)
    assert.equal(await pathExists(receiptPath), false)
    assert.deepEqual((await readdir(journalPath)).sort(), journalNamesBefore)
  })
})

test('CLI continuity flags and failed proofs leave the external journal and receipt output unchanged', async () => {
  await withCliRepository(async ({ root, output }) => {
    const fixture = await prepareTransparencyContinuityFixture(root, output)
    let unexpectedPublications = 0
    const rejectBeforePublication = {
      submitTransparencyLogEntry: async () => {
        unexpectedPublications += 1
        return { receipt: fixture.firstReceipt }
      },
    }

    const initWithoutJournalOutput = join(output, 'init-without-journal.json')
    await assert.rejects(
      publishTransparencyCommand(
        [fixture.bundle, fixture.config11Path],
        continuityPublishOptions(
          fixture,
          initWithoutJournalOutput,
          undefined,
          { 'initialize-transparency-checkpoint-journal': true },
        ),
        rejectBeforePublication,
      ),
      /--initialize-transparency-checkpoint-journal requires --transparency-checkpoint-journal/i,
    )
    assert.equal(await pathExists(initWithoutJournalOutput), false)

    const legacyJournalPath = join(output, 'legacy-config-journal')
    const legacyOutput = join(output, 'legacy-config-receipt.json')
    await assert.rejects(
      publishTransparencyCommand(
        [fixture.bundle, fixture.config10Path],
        continuityPublishOptions(
          fixture,
          legacyOutput,
          legacyJournalPath,
          { 'initialize-transparency-checkpoint-journal': true },
        ),
        rejectBeforePublication,
      ),
      /requires a version 1\.1 transparency configuration with consistency_url/i,
    )
    assert.equal(await pathExists(legacyOutput), false)
    assert.equal(await pathExists(legacyJournalPath), false)

    const journalPath = join(output, 'failure-continuity-journal')
    const missingInitOutput = join(output, 'missing-init-receipt.json')
    await assert.rejects(
      publishTransparencyCommand(
        [fixture.bundle, fixture.config11Path],
        continuityPublishOptions(fixture, missingInitOutput, journalPath),
        rejectBeforePublication,
      ),
      /checkpoint journal is empty.*--initialize-transparency-checkpoint-journal/i,
    )
    assert.equal(unexpectedPublications, 0)
    assert.equal(await pathExists(missingInitOutput), false)
    assert.deepEqual(await readdir(journalPath), [])

    const baselineOutput = join(output, 'failure-baseline-receipt.json')
    await publishTransparencyCommand(
      [fixture.bundle, fixture.config11Path],
      continuityPublishOptions(
        fixture,
        baselineOutput,
        journalPath,
        { 'initialize-transparency-checkpoint-journal': true },
      ),
      {
        submitTransparencyLogEntry: async () => ({
          receipt: fixture.firstReceipt,
        }),
      },
    )
    const baselineRecordPath = join(
      journalPath,
      '0000000000000000.checkpoint-journal.json',
    )
    const baselineBytes = await readFile(baselineRecordPath)
    const baselineNames = (await readdir(journalPath)).sort()
    const poisonedOutput = join(journalPath, 'receipt-must-not-live-here.json')
    await assert.rejects(
      publishTransparencyCommand(
        [fixture.bundle, fixture.config11Path],
        continuityPublishOptions(fixture, poisonedOutput, journalPath),
        rejectBeforePublication,
      ),
      /receipt output must be outside the checkpoint journal directory/i,
    )
    assert.equal(unexpectedPublications, 0)
    assert.equal(await pathExists(poisonedOutput), false)
    const truncatedProof = {
      ...structuredClone(fixture.validConsistencyProof),
      consistency_path: [],
    }
    const failures = [
      {
        label: 'unavailable',
        pattern: /publication may already be durable.*consistency transport failed/is,
        submit: async () => {
          throw new Error('consistency transport failed')
        },
      },
      {
        label: 'truncated',
        pattern: /not a valid consistency proof/i,
        submit: async () => ({ proof: truncatedProof }),
      },
      {
        label: 'fork',
        pattern: /proof does not bind the expected and proposed checkpoints/i,
        submit: async () => ({ proof: fixture.forkConsistencyProof }),
      },
    ]

    for (const failure of failures) {
      const failedOutput = join(output, `${failure.label}-receipt.json`)
      await assert.rejects(
        publishTransparencyCommand(
          [fixture.bundle, fixture.config11Path],
          continuityPublishOptions(fixture, failedOutput, journalPath),
          {
            submitTransparencyLogEntry: async () => ({
              receipt: fixture.secondReceipt,
            }),
            submitTransparencyConsistencyRequest: failure.submit,
          },
        ),
        failure.pattern,
        failure.label,
      )
      assert.equal(await pathExists(failedOutput), false, failure.label)
      assert.deepEqual(
        (await readdir(journalPath)).sort(),
        baselineNames,
        failure.label,
      )
      assert.deepEqual(
        await readFile(baselineRecordPath),
        baselineBytes,
        failure.label,
      )
    }
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

test('CLI requires sealed source for remote_static planning', async () => {
  await withCliRepository(async ({ root, output }) => {
    const policyPath = join(output, 'remote-static-roe.json')
    await writeFile(policyPath, JSON.stringify({
      schema_version: '1.0',
      policy_id: 'cli-remote-static-test',
      mode: 'remote_static',
      workspace_root: resolve(root),
      capabilities: {
        read_file: { enabled: true, roots: ['src'] },
        write_file: { enabled: false, roots: [] },
        execute: { enabled: false, commands: [] },
        network: {
          enabled: true,
          destinations: [{
            scheme: 'https',
            host: 'gateway.example.test',
            ports: [443],
            path_prefix: '/v1/audit',
          }],
        },
      },
    }))

    const unsealed = spawnSync(
      process.execPath,
      [CLI, 'plan', root, '--out', output, '--roe', policyPath],
      { encoding: 'utf8' },
    )
    assert.equal(unsealed.status, 1)
    assert.match(unsealed.stderr, /remote_static.*require --seal-source/i)

    const sealed = spawnSync(
      process.execPath,
      [
        CLI,
        'plan',
        root,
        '--out',
        output,
        '--roe',
        policyPath,
        '--seal-source',
      ],
      { encoding: 'utf8' },
    )
    assert.equal(sealed.status, 0, sealed.stderr)
    assert.match(sealed.stdout, /Source snapshot: SEALED/)
  })
})

test('CLI verifies external Rules of Engagement roots after canonical normalization', async () => {
  await withCliRepository(async ({ root, output }) => {
    const policyPath = join(output, 'roe-multi-root.json')
    await writeFile(policyPath, JSON.stringify({
      schema_version: '1.0',
      policy_id: 'cli-multi-root-test',
      mode: 'static',
      workspace_root: resolve(root),
      capabilities: {
        read_file: { enabled: true, roots: ['src', 'package.json'] },
        write_file: { enabled: false, roots: [] },
        execute: { enabled: false, commands: [] },
        network: { enabled: false, destinations: [] },
      },
    }))

    execFileSync(
      process.execPath,
      [CLI, 'plan', root, '--out', output, '--roe', policyPath],
      { encoding: 'utf8' },
    )
    const [directory] = (await readdir(output, { withFileTypes: true }))
      .filter((entry) => entry.isDirectory())
    const bundle = join(output, directory.name)
    const inventory = JSON.parse(await readFile(join(bundle, 'inventory.json'), 'utf8'))
    assert.deepEqual(
      inventory.entries.map(({ path }) => path),
      ['package.json', 'src/app.js'],
    )

    const next = JSON.parse(execFileSync(
      process.execPath,
      [CLI, 'next', bundle],
      { encoding: 'utf8' },
    ))
    assert.ok(next.pending_jobs.length > 0)
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
