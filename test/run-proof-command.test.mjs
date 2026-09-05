import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import {
  advanceRun,
  applyJobResult,
  beginJob,
} from '../scripts/lib/job-protocol.mjs'
import { normalizePolicy } from '../scripts/lib/policy.mjs'
import {
  createRunPlan,
  stableJson,
  writeRunPlanBundle,
} from '../scripts/lib/run-engine.mjs'
import {
  pendingJobsForCurrentPhase,
  runProofCommand,
  spawnProofCommand,
} from '../scripts/audit.mjs'
import { CONTROLLER_DOCKER_RUNTIME } from '../scripts/lib/proof-docker-runner.mjs'

const WORKSPACE = process.cwd()
const RESULT_INPUT_SHA256 = 'a'.repeat(64)

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

async function runProofInternally(bundle, configPath) {
  let rendered = null
  await runProofCommand([bundle, configPath], {}, {
    spawn: spawnProofCommand,
    output(value) {
      rendered = value
    },
  })
  return JSON.parse(rendered)
}

function writeWorkerConfig(directory, overrides = {}) {
  const path = join(directory, 'proof-worker.json')
  writeFileSync(path, JSON.stringify({
    schema_version: '1.0.0',
    protocol: 'docker-proof-v1',
    runtime_path: CONTROLLER_DOCKER_RUNTIME,
    image: `sha256:${'b'.repeat(64)}`,
    dependency_manifest_sha256: 'c'.repeat(64),
    limits: {
      wall_time_ms: 120_000,
      docker_command_timeout_ms: 30_000,
      max_source_bytes: 64 * 1024 * 1024,
      max_output_bytes: 1024 * 1024,
      memory_bytes: 512 * 1024 * 1024,
      cpus: 1,
      pids: 128,
      nofile: 256,
      tmpfs_bytes: 128 * 1024 * 1024,
    },
    ...overrides,
  }))
  return path
}

function promoteToV2(configPath) {
  const config = JSON.parse(readFileSync(configPath, 'utf8'))
  const next = {
    ...config,
    schema_version: '2.0.0',
    strategy: { id: 'exact.reproducer', version: '1.0.0' },
    oracle: {
      id: 'security-test-exit-differential',
      attack_exit_codes: [1],
      control_exit_codes: [0],
    },
    limits: { timeout_ms: 2_000, kill_grace_ms: 10, max_output_bytes: 4_096 },
    reproducer: { path: config.proof_files[0].path, format: 'test-harness' },
  }
  writeFileSync(configPath, JSON.stringify(next))
  return next
}

async function planStatic() {
  const out = mkdtempSync(join(tmpdir(), 'rta-rp-'))
  const plan = await createRunPlan({
    targetRoot: join(WORKSPACE, 'fixtures', 'vulnerable'),
    lensDirectory: join(WORKSPACE, 'skills', 'red-team-audit', 'lenses'),
    sealSource: true,
  })
  return (await writeRunPlanBundle(plan, out)).directory
}

function proofConfig(overrides = {}) {
  return {
    schema_version: '1.0.0',
    job_id: 'proof-verification:cand:web:001',
    proof_files: [{ path: 'test/security/a.test.mjs', contents: 'a\n' }],
    command: { program: 'npm', args: ['test'] },
    destination_guard: { installed: false },
    ...overrides,
  }
}

function writeConfig(directory, config = proofConfig()) {
  const path = join(directory, 'proof.json')
  writeFileSync(path, JSON.stringify(config))
  return path
}

function advanceUntilBlocked(run) {
  let current = run
  while (current.state === 'RUNNING') {
    const advanced = advanceRun(current)
    if (!advanced.advanced) break
    current = advanced.run
  }
  return current
}

function succeededResult(run, job, overrides = {}) {
  return {
    schema_version: '1.0.0',
    run_id: run.run_id,
    job_id: job.job_id,
    input_sha256: RESULT_INPUT_SHA256,
    producer: {
      name: 'run-proof-command-test',
      version: '1.0.0',
      instance_id: 'run-proof-command-test:instance-1',
    },
    state: 'SUCCEEDED',
    examined_files: [],
    findings: [],
    coverage_gaps: [],
    ...overrides,
  }
}

function assessedTopics(sidecar, findings) {
  return (sidecar.topic_obligations ?? []).map((topic) => {
    const topicFindings = findings.filter((finding) => finding.topic === topic)
    if (topicFindings.length > 0) {
      return {
        topic,
        disposition: 'finding',
        reason: 'The proof fixture reports a finding for this owned topic.',
        finding_ids: topicFindings.map((finding) => finding.candidate_id),
      }
    }
    return {
      topic,
      disposition: 'examined-clean',
      reason: 'The proof fixture examined the complete sealed file scope for this topic.',
      evidence: ['All files assigned to the job were examined without identifying a finding.'],
      evidence_paths: sidecar.scoped_files,
    }
  })
}

function readJobSidecar(bundle, jobId) {
  for (const filename of readdirSync(join(bundle, 'jobs'))) {
    const sidecar = JSON.parse(readFileSync(join(bundle, 'jobs', filename), 'utf8'))
    if (sidecar.job_id === jobId) return sidecar
  }
  throw new Error(`missing sidecar for ${jobId}`)
}

function stageOneFinding() {
  return {
    candidate_id: 'authz-object-level:proofreceipt',
    lens: 'web-and-api',
    topic: 'authz-object-level',
    title: 'Invoice route loads another tenant by identifier',
    claimed_impact_severity: 'High',
    location: ['src/routes/invoices.ts:2'],
    cwe: 'CWE-639',
    evidence: 'const invoice = await repo.findById(req.params.id)',
    attack: 'Request another tenant invoice while authenticated as a different tenant',
    impact: 'Reads another tenant invoice',
    reachable_from: 'GET /api/invoices/:id',
    confidence: 'High',
    proof_plan: 'Run an attack assertion and a separate passing control in a disposable mirror',
  }
}

async function proofReadyBundle() {
  const target = mkdtempSync(join(tmpdir(), 'rta-proof-target-'))
  mkdirSync(join(target, 'src', 'routes'), { recursive: true })
  writeFileSync(
    join(target, 'src', 'routes', 'invoices.ts'),
    '// vulnerable fixture\nconst invoice = await repo.findById(req.params.id)\n',
  )

  const output = mkdtempSync(join(tmpdir(), 'rta-proof-run-'))
  const policy = normalizePolicy({
    schema_version: '1.0',
    policy_id: 'run-proof-command-test',
    mode: 'test',
    workspace_root: target,
    capabilities: {
      read_file: { enabled: true, roots: ['.'] },
      write_file: { enabled: true, roots: ['test/security'] },
      execute: {
        enabled: true,
        commands: [
          { program: 'node', args: ['test/security/attack.mjs'] },
          { program: 'node', args: ['test/security/control.mjs'] },
        ],
      },
      network: { enabled: false, destinations: [] },
    },
  }, { workspaceRoot: target, policySource: 'external' })
  const plan = await createRunPlan({
    targetRoot: target,
    lensDirectory: join(WORKSPACE, 'skills', 'red-team-audit', 'lenses'),
    policy,
    sealSource: true,
  })

  const { directory: bundle } = await writeRunPlanBundle(plan, output)
  const runPath = join(bundle, 'run.json')
  let run = JSON.parse(readFileSync(runPath, 'utf8'))
  const stageOne = stageOneFinding()

  while (run.phase === 'RECON' || run.phase === 'FANOUT') {
    const pending = pendingJobsForCurrentPhase(run)
    assert.ok(pending.length > 0, 'proof setup must have runnable fan-out jobs')
    for (const job of pending) {
      const sidecar = readJobSidecar(bundle, job.job_id)
      const findings = job.lens === 'web-and-api' ? [stageOne] : []
      run = beginJob(run, job.job_id)
      run = applyJobResult(run, succeededResult(run, job, {
        examined_files: sidecar.scoped_files,
        findings,
        topic_assessments: assessedTopics(sidecar, findings),
      }), {
        expectedPacketSha256: RESULT_INPUT_SHA256,
        sidecar,
      })
    }
    run = advanceUntilBlocked(run)
  }

  while (run.phase === 'TRIAGE') {
    const [job] = pendingJobsForCurrentPhase(run)
    assert.ok(job, 'proof setup must have a runnable triage job')
    const sidecar = readJobSidecar(bundle, job.job_id)
    const findings = job.lens === 'business-logic'
      ? [{
          ...stageOne,
          effective_severity: 'High',
          triage_disposition: 'queued',
        }]
      : []
    run = beginJob(run, job.job_id)
    run = applyJobResult(run, succeededResult(run, job, { findings }), {
      expectedPacketSha256: RESULT_INPUT_SHA256,
      sidecar,
    })
    run = advanceUntilBlocked(run)
  }

  while (
    run.phase === 'PROOF'
    && pendingJobsForCurrentPhase(run)
      .some(({ job_id: jobId }) => jobId.startsWith('proof-existence:'))
  ) {
    for (const job of pendingJobsForCurrentPhase(run)) {
      const finding = run.findings.find(
        ({ candidate_id: candidateId }) => job.candidate_ids.includes(candidateId),
      )
      run = beginJob(run, job.job_id)
      run = applyJobResult(run, succeededResult(run, job, {
        findings: [{
          ...finding,
          existence_check: {
            status: 'located',
            method: 'matched the cited source line in the sealed repository snapshot',
          },
        }],
      }), { expectedPacketSha256: RESULT_INPUT_SHA256 })
    }
    run = advanceUntilBlocked(run)
  }

  const [verificationJob] = pendingJobsForCurrentPhase(run)
  assert.match(verificationJob.job_id, /^proof-verification:/)
  writeFileSync(runPath, stableJson(run))

  const configPath = writeConfig(output, proofConfig({
    job_id: verificationJob.job_id,
    proof_files: [
      {
        path: 'test/security/attack.mjs',
        contents: "process.stderr.write('attack reproduced\\n'); process.exit(1)\n",
      },
      {
        path: 'test/security/control.mjs',
        contents: "process.stdout.write('control valid\\n')\n",
      },
    ],
    command: { program: 'node', args: ['test/security/attack.mjs'] },
    control_command: { program: 'node', args: ['test/security/control.mjs'] },
    destination_guard: { installed: true },
  }))
  return { bundle, configPath, jobId: verificationJob.job_id, runPath, target }
}

test('run-proof is registered and documented', () => {
  const help = execFileSync(process.execPath, ['scripts/audit.mjs', '--help'], {
    encoding: 'utf8',
  })
  assert.match(
    help,
    /run-proof <run\.json\|bundle-directory> <proof-config\.json> --worker <proof-worker\.json>/,
  )
  assert.doesNotMatch(help, /run-proof[^\n]*\[DISABLED\]/)
  assert.match(help, /network-denied Docker proof worker/i)
})

test('run-proof rejects an unknown option', () => {
  assert.throws(
    () => execFileSync(process.execPath, [
      'scripts/audit.mjs', 'run-proof', 'x', 'y', '--shell', 'sh',
    ], { stdio: 'pipe' }),
    /unknown option --shell/,
  )
})

test('run-proof refuses a STATIC run', async () => {
  const bundle = await planStatic()
  const configPath = writeConfig(mkdtempSync(join(tmpdir(), 'rta-rpc-')))
  assert.throws(
    () => execFileSync(process.execPath, [
      'scripts/audit.mjs', 'run-proof', bundle, configPath,
    ], { stdio: 'pipe' }),
    /requires a TEST_EXECUTION run/i,
  )
})

test('run-proof refuses a malformed proof configuration', async () => {
  const { bundle } = await proofReadyBundle()
  const directory = mkdtempSync(join(tmpdir(), 'rta-rpc-'))
  const configPath = writeConfig(directory, proofConfig({ proof_files: [] }))
  assert.throws(
    () => execFileSync(process.execPath, [
      'scripts/audit.mjs', 'run-proof', bundle, configPath,
    ], { stdio: 'pipe' }),
    /proof configuration is invalid/i,
  )
})

test('public run-proof requires a v2 proof and an external worker configuration', async () => {
  const { bundle, configPath } = await proofReadyBundle()
  await assert.rejects(
    () => runProofCommand([bundle, configPath]),
    /public run-proof requires a v2 proof configuration/i,
  )
  promoteToV2(configPath)
  await assert.rejects(
    () => runProofCommand([bundle, configPath]),
    /--worker <proof-worker\.json>/i,
  )
})

test('public run-proof executes sealed bytes through the Docker worker and binds its receipt', async () => {
  const { bundle, configPath, jobId, target } = await proofReadyBundle()
  const config = promoteToV2(configPath)
  const workerPath = writeWorkerConfig(dirname(configPath))
  const calls = []
  let rendered
  await runProofCommand([bundle, configPath], { worker: workerPath }, {
    dockerProof: async (input) => {
      calls.push(input)
      assert.equal(existsSync(join(input.sourceRoot, 'src', 'routes', 'invoices.ts')), true)
      assert.equal(input.sourceRoot.startsWith(target), false)
      const control = input.args.at(-1) === 'control.mjs'
      return {
        code: control ? 0 : 1,
        signal: null,
        timed_out: false,
        spawn_error: false,
        duration_ms: 5,
        stdout: '',
        stderr: '',
        stdout_bytes: 7,
        stdout_sha256: 'd'.repeat(64),
        stdout_truncated: false,
        stderr_bytes: 0,
        stderr_sha256: sha256(''),
        stderr_truncated: false,
        output_omitted: true,
        sandbox: {
          backend: 'OCI_DOCKER',
          worker_config_sha256: 'e'.repeat(64),
          image: `sha256:${'b'.repeat(64)}`,
          network_mode: 'none',
          mounts: [],
          environment: 'controller-minimal',
          cleanup_verified: true,
        },
      }
    },
    output(value) {
      rendered = JSON.parse(value)
    },
  })

  assert.equal(calls.length, 2)
  assert.deepEqual(calls.map(({ args }) => args), [
    config.command.args,
    config.control_command.args,
  ])
  assert.equal(rendered.job_id, jobId)
  const receipt = JSON.parse(readFileSync(
    join(bundle, ...rendered.receipt.path.split('/')),
    'utf8',
  ))
  assert.equal(receipt.proof_worker.protocol, 'docker-proof-v1')
  assert.match(receipt.proof_worker.config_sha256, /^[a-f0-9]{64}$/)
  assert.equal(receipt.outcome.demonstration.output_omitted, true)
  assert.equal(JSON.stringify(receipt).includes('attack reproduced'), false)
})

test('internal proof controller persists and hashes a canonical receipt before committing the proof result', async () => {
  const { bundle, configPath, jobId, runPath } = await proofReadyBundle()

  const output = await runProofInternally(bundle, configPath)

  assert.equal(output.job_id, jobId)
  assert.deepEqual(output.evidence.artifact, output.receipt)
  const receiptPath = join(bundle, ...output.receipt.path.split('/'))
  assert.equal(existsSync(receiptPath), true)
  const receiptBytes = readFileSync(receiptPath)
  assert.equal(sha256(receiptBytes), output.receipt.sha256)

  const receipt = JSON.parse(receiptBytes.toString('utf8'))
  const config = JSON.parse(readFileSync(configPath, 'utf8'))
  assert.equal(receiptBytes.toString('utf8'), stableJson(receipt))
  assert.equal(receipt.schema_version, '1.0.0')
  assert.equal(receipt.kind, 'red-team-audit/proof-receipt')
  assert.equal(receipt.job_id, jobId)
  assert.equal(receipt.proof_configuration.sha256, sha256(stableJson(config, 0)))
  assert.equal(receipt.outcome.demonstration.code, 1)
  assert.equal(receipt.outcome.control.code, 0)
  assert.equal('stdout' in receipt.outcome.demonstration, false)
  assert.equal('stderr' in receipt.outcome.demonstration, false)
  assert.equal(receipt.outcome.demonstration.stderr_bytes, 18)
  assert.equal(
    receipt.outcome.demonstration.stderr_sha256,
    sha256('attack reproduced\n'),
  )
  assert.equal(receipt.evidence.verification_status, 'CONFIRMED')

  const persisted = JSON.parse(readFileSync(runPath, 'utf8'))
  const job = persisted.jobs.find(({ job_id: persistedJobId }) => persistedJobId === jobId)
  const finding = persisted.findings.find(
    ({ candidate_id: candidateId }) => candidateId === 'authz-object-level:proofreceipt',
  )
  assert.equal(job.state, 'SUCCEEDED')
  assert.equal(job.input_sha256, receipt.input_sha256)
  assert.equal(job.producer.name, 'red-team-audit-proof-controller')
  assert.equal(persisted.phase, 'COMPLETENESS')
  assert.deepEqual(finding.artifact, output.receipt)
  assert.ok(Object.values(persisted.artifacts).some(
    (artifact) => artifact.path === output.receipt.path
      && artifact.sha256 === output.receipt.sha256,
  ))

  const report = execFileSync(process.execPath, [
    'scripts/audit.mjs', 'report', bundle,
  ], { encoding: 'utf8' })
  assert.match(report, /Invoice route loads another tenant by identifier/)
  assert.match(report, /CONFIRMED/)
})

test('internal proof controller keeps a legacy demonstration-only configuration readable', async () => {
  const { bundle, configPath, runPath } = await proofReadyBundle()
  const { control_command: _controlCommand, ...config } = JSON.parse(
    readFileSync(configPath, 'utf8'),
  )
  writeFileSync(configPath, JSON.stringify(config))

  const output = await runProofInternally(bundle, configPath)

  assert.equal(output.evidence.verification_status, 'UNPROVEN')
  const persisted = JSON.parse(readFileSync(runPath, 'utf8'))
  assert.equal(persisted.findings[0].verification_status, 'UNPROVEN')
  const receipt = JSON.parse(readFileSync(
    join(bundle, ...output.receipt.path.split('/')),
    'utf8',
  ))
  assert.equal(receipt.outcome.control, null)
})

test('internal proof controller persists a timed-out demonstration as inconclusive', async () => {
  const { bundle, configPath, runPath } = await proofReadyBundle()
  const config = JSON.parse(readFileSync(configPath, 'utf8'))
  writeFileSync(configPath, JSON.stringify({
    ...config,
    proof_files: config.proof_files.map((file, index) => index === 0
      ? { ...file, contents: 'setInterval(() => {}, 1000)\n' }
      : file),
    limits: {
      timeout_ms: 100,
      kill_grace_ms: 50,
      max_output_bytes: 1024,
    },
  }))

  const output = await runProofInternally(bundle, configPath)

  assert.equal(output.evidence.verification_status, 'INCONCLUSIVE')
  assert.match(output.evidence.reason, /timed out/i)
  const persisted = JSON.parse(readFileSync(runPath, 'utf8'))
  assert.equal(persisted.findings[0].verification_status, 'INCONCLUSIVE')
})

test('run-proof rejects a proof configuration that is not the current pending verification job', async () => {
  const { bundle, configPath } = await proofReadyBundle()
  const config = JSON.parse(readFileSync(configPath, 'utf8'))
  writeFileSync(configPath, JSON.stringify({
    ...config,
    job_id: 'proof-verification:authz-object-level:not-current',
  }))
  let spawnCalls = 0

  await assert.rejects(
    () => runProofCommand([bundle, configPath], {}, {
      spawn: async () => {
        spawnCalls += 1
        return { code: 1, stdout: '', stderr: 'must not execute' }
      },
    }),
    /current pending proof-verification job/,
  )
  assert.equal(spawnCalls, 0)
  assert.equal(existsSync(join(bundle, 'proofs')), false)
})

test('run-proof revalidates the repository snapshot before starting proof commands', async () => {
  const { bundle, configPath, target } = await proofReadyBundle()
  writeFileSync(
    join(target, 'src', 'routes', 'invoices.ts'),
    '// changed after planning\nconst invoice = await repo.findById(req.params.id)\n',
  )
  let spawnCalls = 0

  await assert.rejects(
    () => runProofCommand([bundle, configPath], {}, {
      spawn: async () => {
        spawnCalls += 1
        return { code: 1, stdout: '', stderr: 'must not execute' }
      },
    }),
    /repository snapshot changed after planning/,
  )
  assert.equal(spawnCalls, 0)
  assert.equal(existsSync(join(bundle, 'proofs')), false)
})
