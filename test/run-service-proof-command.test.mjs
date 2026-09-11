import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'

import * as audit from '../scripts/audit.mjs'
import {
  advanceRun,
  applyJobResult,
  beginJob,
} from '../scripts/lib/job-protocol.mjs'
import { normalizePolicy } from '../scripts/lib/policy.mjs'
import {
  CONTROLLER_DOCKER_RUNTIME,
  normalizeProofWorkerConfig,
  proofDependencyManifestDigest,
  proofSourceTreeDigest,
  proofWorkerConfigDigest,
  serviceProofControllerBudget,
} from '../scripts/lib/proof-docker-runner.mjs'
import {
  leaseServiceProofAttempt,
  markServiceProofAttemptStarted,
} from '../scripts/lib/attempts.mjs'
import {
  createRunPlan,
  stableJson,
  writeRunPlanBundle,
} from '../scripts/lib/run-engine.mjs'

const WORKSPACE = process.cwd()
const RESULT_INPUT_SHA256 = 'a'.repeat(64)
const PORT = 31_337

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function command(path) {
  return { program: 'node', args: [path] }
}

function serviceProofConfig(jobId, overrides = {}) {
  return {
    schema_version: '3.0.0',
    job_id: jobId,
    proof_files: [
      {
        path: 'test/security/service.mjs',
        contents: '/* reads RTA_SERVICE_HOST and RTA_SERVICE_PORT */\n',
      },
      {
        path: 'test/security/attack.mjs',
        contents: '/* attack through controller-supplied loopback */\n',
      },
      {
        path: 'test/security/control.mjs',
        contents: '/* control through controller-supplied loopback */\n',
      },
    ],
    service: {
      protocol: 'loopback-tcp-v1',
      command: command('test/security/service.mjs'),
      port: PORT,
      startup_timeout_ms: 5_000,
      probe_interval_ms: 25,
    },
    command: command('test/security/attack.mjs'),
    control_command: command('test/security/control.mjs'),
    strategy: { id: 'loopback.http.reproducer', version: '1.0.0' },
    oracle: {
      id: 'security-test-exit-differential',
      attack_exit_codes: [1],
      control_exit_codes: [0],
    },
    limits: {
      timeout_ms: 2_000,
      kill_grace_ms: 50,
      max_output_bytes: 4_096,
    },
    reproducer: {
      path: 'test/security/attack.mjs',
      format: 'test-harness',
    },
    destination_guard: { installed: true },
    ...overrides,
  }
}

function writeWorkerConfig(directory, dependencyManifestSha256) {
  const path = join(directory, 'proof-worker.json')
  writeFileSync(path, JSON.stringify({
    schema_version: '1.0.0',
    protocol: 'docker-proof-v1',
    runtime_path: CONTROLLER_DOCKER_RUNTIME,
    image: `sha256:${'b'.repeat(64)}`,
    dependency_manifest_sha256: dependencyManifestSha256,
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
  }))
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
      name: 'run-service-proof-command-test',
      version: '1.0.0',
      instance_id: 'run-service-proof-command-test:instance-1',
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
        reason: 'The local-service fixture reports one bounded candidate.',
        finding_ids: topicFindings.map((finding) => finding.candidate_id),
      }
    }
    return {
      topic,
      disposition: 'examined-clean',
      reason: 'The fixture examined the complete sealed file scope.',
      evidence: ['All files assigned to the job were examined.'],
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
    candidate_id: 'authz-object-level:serviceproof',
    lens: 'web-and-api',
    topic: 'authz-object-level',
    title: 'Loopback service exposes another tenant record',
    claimed_impact_severity: 'High',
    location: ['src/server.js:2'],
    cwe: 'CWE-639',
    evidence: 'const record = repository.load(request.params.id)',
    attack: 'Request another tenant record through the disposable local service',
    impact: 'Reads another tenant record',
    reachable_from: 'GET /records/:id',
    confidence: 'High',
    proof_plan: 'Boot two fresh local services and run an attack/control differential',
  }
}

async function proofReadyBundle({ createdAt = new Date() } = {}) {
  const target = mkdtempSync(join(tmpdir(), 'rta-service-target-'))
  const output = mkdtempSync(join(tmpdir(), 'rta-service-run-'))
  mkdirSync(join(target, 'src'), { recursive: true })
  writeFileSync(
    join(target, 'src', 'server.js'),
    '// vulnerable fixture\nconst record = repository.load(request.params.id)\n',
  )
  const packageJson = Buffer.from('{"name":"service-proof-fixture"}\n')
  const packageLock = Buffer.from(JSON.stringify({
    name: 'service-proof-fixture',
    lockfileVersion: 3,
    packages: {},
  }))
  writeFileSync(join(target, 'package.json'), packageJson)
  writeFileSync(join(target, 'package-lock.json'), packageLock)

  const policy = normalizePolicy({
    schema_version: '1.0',
    policy_id: 'run-service-proof-command-test',
    mode: 'local_dynamic',
    workspace_root: target,
    capabilities: {
      read_file: { enabled: true, roots: ['.'] },
      write_file: { enabled: true, roots: ['test/security'] },
      execute: {
        enabled: true,
        commands: [
          command('test/security/service.mjs'),
          command('test/security/attack.mjs'),
          command('test/security/control.mjs'),
        ],
      },
      network: {
        enabled: true,
        destinations: [{
          scheme: 'http',
          host: '127.0.0.1',
          ports: [PORT],
          path_prefix: '/',
        }],
      },
    },
  }, { workspaceRoot: target, policySource: 'external' })
  const plan = await createRunPlan({
    targetRoot: target,
    lensDirectory: join(WORKSPACE, 'skills', 'last-aperture', 'lenses'),
    policy,
    createdAt,
    sealSource: true,
  })
  const { directory: bundle } = await writeRunPlanBundle(plan, output)
  const runPath = join(bundle, 'run.json')
  let run = JSON.parse(readFileSync(runPath, 'utf8'))
  const stageOne = stageOneFinding()

  while (run.phase === 'RECON' || run.phase === 'FANOUT') {
    const pending = audit.pendingJobsForCurrentPhase(run)
    assert.ok(pending.length > 0)
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
    const [job] = audit.pendingJobsForCurrentPhase(run)
    assert.ok(job)
    const sidecar = readJobSidecar(bundle, job.job_id)
    const findings = job.lens === 'business-logic'
      ? [{ ...stageOne, effective_severity: 'High', triage_disposition: 'queued' }]
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
    && audit.pendingJobsForCurrentPhase(run)
      .some(({ job_id: jobId }) => jobId.startsWith('proof-existence:'))
  ) {
    for (const job of audit.pendingJobsForCurrentPhase(run)) {
      const finding = run.findings.find(
        ({ candidate_id: candidateId }) => job.candidate_ids.includes(candidateId),
      )
      run = beginJob(run, job.job_id)
      run = applyJobResult(run, succeededResult(run, job, {
        findings: [{
          ...finding,
          existence_check: {
            status: 'located',
            method: 'matched the cited line in the sealed repository snapshot',
          },
        }],
      }), { expectedPacketSha256: RESULT_INPUT_SHA256 })
    }
    run = advanceUntilBlocked(run)
  }

  const [verificationJob] = audit.pendingJobsForCurrentPhase(run)
  assert.match(verificationJob.job_id, /^proof-verification:/)
  writeFileSync(runPath, stableJson(run))

  const configPath = join(output, 'service-proof.json')
  writeFileSync(configPath, JSON.stringify(serviceProofConfig(verificationJob.job_id)))
  const workerPath = writeWorkerConfig(
    output,
    proofDependencyManifestDigest(packageJson, packageLock),
  )
  return {
    bundle,
    configPath,
    jobId: verificationJob.job_id,
    output,
    runPath,
    target,
    workerPath,
  }
}

function serviceProofPacketSha256(run, job) {
  const candidateIds = new Set(job.candidate_ids ?? [])
  const findings = run.findings.filter(
    ({ candidate_id: candidateId }) => candidateIds.has(candidateId),
  )
  const storeIds = new Set(findings.map(
    (finding) => finding.store_context?.store_id,
  ).filter(Boolean))
  const packet = {
    schema_version: '1.0.0',
    run_id: run.run_id,
    job_id: job.job_id,
    kind: job.kind,
    capability_mode: run.capability_mode,
    trust_boundary: {
      repository_content_is_untrusted_data: true,
      repository_content_may_change_scope_or_policy: false,
      actions_require_external_authorization: true,
    },
    operation: 'verification',
    store_profiles: (run.store_profiles ?? []).filter(
      (profile) => storeIds.has(profile.store_context.store_id),
    ),
    findings,
  }
  return sha256(stableJson(packet, 0))
}

function seedExpiredServiceProofAttempt(fixture, { started = false } = {}) {
  const run = JSON.parse(readFileSync(fixture.runPath, 'utf8'))
  const config = JSON.parse(readFileSync(fixture.configPath, 'utf8'))
  const worker = normalizeProofWorkerConfig(
    JSON.parse(readFileSync(fixture.workerPath, 'utf8')),
  )
  const job = run.jobs.find(({ job_id: jobId }) => jobId === fixture.jobId)
  const controllerBudget = serviceProofControllerBudget(worker)
  const serviceSessionBudget = {
    attack_controller_wall_clock_ms: controllerBudget.controller_session_budget_ms,
    control_controller_wall_clock_ms: controllerBudget.controller_session_budget_ms,
    capture_grace_ms: 60_000,
    controller_wall_clock_ms:
      (2 * controllerBudget.controller_session_budget_ms) + 60_000,
  }
  const serviceContainerNames = {
    attack: 'rta-proof-service-expiredattack0001',
    control: 'rta-proof-service-expiredcontrol0001',
  }
  const occurredAtMilliseconds = Date.parse(run.created_at) + 1_000
  let seeded = leaseServiceProofAttempt(run, job.job_id, {
    attempt_id: 'attempt:expired-service-proof-0001',
    occurred_at: new Date(occurredAtMilliseconds).toISOString(),
    packet_sha256: serviceProofPacketSha256(run, job),
    proof_config_sha256: sha256(stableJson(config, 0)),
    proof_worker_config_sha256: proofWorkerConfigDigest(worker),
    service_container_names: serviceContainerNames,
    service_session_budget: serviceSessionBudget,
  })
  if (started) {
    seeded = markServiceProofAttemptStarted(
      seeded,
      'attempt:expired-service-proof-0001',
      { occurred_at: new Date(occurredAtMilliseconds + 1).toISOString() },
    )
  }
  writeFileSync(fixture.runPath, stableJson(seeded))
  return {
    config,
    expiresAt: seeded.attempt_events[0].expires_at,
    serviceContainerNames,
    worker,
  }
}

function serviceObservation(role, code, worker, sourceTreeSha256) {
  const controllerBudget = serviceProofControllerBudget(worker)
  return {
    code,
    signal: null,
    timed_out: false,
    spawn_error: false,
    duration_ms: 12,
    stdout: '',
    stderr: '',
    stdout_bytes: 0,
    stdout_sha256: sha256(''),
    stdout_truncated: false,
    stderr_bytes: 0,
    stderr_sha256: sha256(''),
    stderr_truncated: false,
    output_omitted: true,
    sandbox: {
      backend: 'OCI_DOCKER',
      worker_config_sha256: proofWorkerConfigDigest(worker),
      runtime_version: '29.5.3',
      image: worker.image,
      container_id: (role === 'control' ? 'c' : 'd').repeat(64),
      network_mode: 'none',
      mounts: [],
      environment: 'controller-minimal',
      cleanup_verified: true,
      untrusted_extension: 'receipt-must-drop-this',
      service: {
        protocol: 'loopback-tcp-v1',
        host: '127.0.0.1',
        port: PORT,
        supervisor_ttl_ms: worker.limits.wall_time_ms,
        ...controllerBudget,
        pre_boot_closed: true,
        pre_probe_ready: true,
        post_probe_ready: true,
        source_immutable: true,
        source_tree_sha256: sourceTreeSha256,
        runtime_root: '/work/runtime',
        output_omitted: true,
        untrusted_extension: 'nested-receipt-must-drop-this',
      },
    },
  }
}

async function serviceObservationForInput(role, code, input) {
  const sourceTreeSha256 = await proofSourceTreeDigest(
    input.sourceRoot,
    input.config.limits.max_source_bytes,
  )
  return serviceObservation(role, code, input.config, sourceTreeSha256)
}

function runServiceProofCommand() {
  assert.equal(
    typeof audit.runServiceProofCommand,
    'function',
    'audit.mjs must export the public run-service-proof controller',
  )
  return audit.runServiceProofCommand
}

function cleanFixture(fixture) {
  rmSync(fixture.target, { recursive: true, force: true })
  rmSync(fixture.output, { recursive: true, force: true })
}

test('run-service-proof binds v3, sealed source, exact policy commands, and two service sessions', async () => {
  const fixture = await proofReadyBundle()
  try {
    const calls = []
    let rendered
    await runServiceProofCommand()(
      [fixture.bundle, fixture.configPath],
      { worker: fixture.workerPath },
      {
        dockerServiceProof: async (input) => {
          calls.push(input)
          assert.equal(input.sourceRoot.startsWith(fixture.target), false)
          assert.equal(existsSync(join(input.sourceRoot, 'src', 'server.js')), true)
          assert.deepEqual(input.service, serviceProofConfig(fixture.jobId).service)
          const role = input.args.at(-1).endsWith('/control.mjs') ? 'control' : 'attack'
          return serviceObservationForInput(role, role === 'control' ? 0 : 1, input)
        },
        output(value) {
          rendered = JSON.parse(value)
        },
      },
    )

    assert.equal(calls.length, 2)
    assert.deepEqual(calls.map(({ args }) => args), [
      ['test/security/attack.mjs'],
      ['test/security/control.mjs'],
    ])
    assert.notEqual(
      calls[0].containerName,
      calls[1].containerName,
      'attack and control must be assigned distinct fresh container names',
    )
    assert.equal(rendered.job_id, fixture.jobId)
    assert.equal(rendered.evidence.proof_tier, 'T2')
    assert.equal(rendered.evidence.verification_status, 'UNPROVEN')
    assert.match(
      rendered.evidence.blocking_reason,
      /no controller-authenticated semantic oracle/i,
    )

    const receipt = JSON.parse(readFileSync(
      join(fixture.bundle, ...rendered.receipt.path.split('/')),
      'utf8',
    ))
    assert.equal(receipt.kind, 'red-team-audit/proof-receipt')
    assert.equal(receipt.proof_configuration.schema_version, '3.0.0')
    assert.deepEqual(receipt.proof_configuration.service, {
      protocol: 'loopback-tcp-v1',
      command: {
        program: 'node',
        args_count: 1,
        args_sha256: sha256(stableJson(['test/security/service.mjs'], 0)),
      },
      port: PORT,
      startup_timeout_ms: 5_000,
      probe_interval_ms: 25,
    })
    assert.equal('args' in receipt.proof_configuration.command, false)
    assert.equal('args' in receipt.proof_configuration.control_command, false)
    assert.equal('args' in receipt.proof_configuration.service.command, false)
    assert.equal(receipt.proof_worker.protocol, 'docker-proof-v1')
    assert.equal(receipt.proof_worker.wall_time_ms, 120_000)
    assert.equal(
      receipt.outcome.demonstration.sandbox.worker_config_sha256,
      receipt.proof_worker.config_sha256,
    )
    assert.equal(
      receipt.outcome.control.sandbox.worker_config_sha256,
      receipt.proof_worker.config_sha256,
    )
    assert.equal(receipt.outcome.demonstration.sandbox.image, receipt.proof_worker.image)
    assert.equal(receipt.outcome.control.sandbox.image, receipt.proof_worker.image)
    assert.equal(receipt.outcome.demonstration.sandbox.service.pre_boot_closed, true)
    assert.equal(receipt.outcome.demonstration.sandbox.service.pre_probe_ready, true)
    assert.equal(receipt.outcome.demonstration.sandbox.service.post_probe_ready, true)
    assert.equal(receipt.outcome.control.sandbox.service.pre_boot_closed, true)
    assert.equal(receipt.outcome.control.sandbox.service.pre_probe_ready, true)
    assert.equal(receipt.outcome.control.sandbox.service.post_probe_ready, true)
    assert.match(receipt.repository_snapshot.proof_worktree_sha256, /^[a-f0-9]{64}$/)
    for (const observation of [
      receipt.outcome.demonstration,
      receipt.outcome.control,
    ]) {
      assert.equal(observation.sandbox.service.source_immutable, true)
      assert.equal(
        observation.sandbox.service.source_tree_sha256,
        receipt.repository_snapshot.proof_worktree_sha256,
      )
      assert.equal(observation.sandbox.service.runtime_root, '/work/runtime')
    }
    assert.equal('untrusted_extension' in receipt.outcome.demonstration.sandbox, false)
    assert.equal(
      'untrusted_extension' in receipt.outcome.demonstration.sandbox.service,
      false,
    )
    assert.notEqual(
      receipt.outcome.demonstration.sandbox.container_id,
      receipt.outcome.control.sandbox.container_id,
    )
    assert.equal(JSON.stringify(receipt).includes('attack through'), false)

    const persisted = JSON.parse(readFileSync(fixture.runPath, 'utf8'))
    const finding = persisted.findings.find(
      ({ candidate_id: candidateId }) => candidateId === 'authz-object-level:serviceproof',
    )
    assert.equal(finding.proof_tier, 'T2')
    assert.equal(finding.verification_status, 'UNPROVEN')
    assert.equal(finding.effective_severity, 'Medium')
    await audit.verifyControlBundle(fixture.bundle, persisted, {
      requireCurrentLensPack: true,
    })
  } finally {
    cleanFixture(fixture)
  }
})

test('run-service-proof downgrades a session whose source digest mismatches the controller worktree', async () => {
  const fixture = await proofReadyBundle()
  try {
    let rendered
    await runServiceProofCommand()(
      [fixture.bundle, fixture.configPath],
      { worker: fixture.workerPath },
      {
        dockerServiceProof: async (input) => {
          const role = input.args.at(-1).endsWith('/control.mjs') ? 'control' : 'attack'
          const observation = await serviceObservationForInput(
            role,
            role === 'control' ? 0 : 1,
            input,
          )
          if (role === 'control') {
            observation.sandbox.service.source_tree_sha256 =
              observation.sandbox.service.source_tree_sha256 === 'f'.repeat(64)
                ? 'e'.repeat(64)
                : 'f'.repeat(64)
          }
          return observation
        },
        output(value) {
          rendered = JSON.parse(value)
        },
      },
    )

    assert.equal(rendered.evidence.proof_tier, 'T0')
    assert.equal(rendered.evidence.verification_status, 'UNPROVEN')
    assert.match(rendered.evidence.blocking_reason, /controller-computed proof worktree digest/i)

    const receipt = JSON.parse(readFileSync(
      join(fixture.bundle, ...rendered.receipt.path.split('/')),
      'utf8',
    ))
    assert.equal(
      receipt.outcome.demonstration.sandbox.service.source_tree_sha256,
      receipt.repository_snapshot.proof_worktree_sha256,
    )
    assert.notEqual(
      receipt.outcome.control.sandbox.service.source_tree_sha256,
      receipt.repository_snapshot.proof_worktree_sha256,
    )
    assert.equal(receipt.outcome.control.sandbox.service.source_immutable, true)
    assert.equal(receipt.outcome.control.sandbox.service.runtime_root, '/work/runtime')

    const persisted = JSON.parse(readFileSync(fixture.runPath, 'utf8'))
    const finding = persisted.findings.find(
      ({ candidate_id: candidateId }) => candidateId === 'authz-object-level:serviceproof',
    )
    assert.equal(finding.proof_tier, 'T0')
    assert.equal(finding.verification_status, 'UNPROVEN')
  } finally {
    cleanFixture(fixture)
  }
})

test('run-service-proof rejects any boot/attack/control command outside the sealed policy', async () => {
  const fixture = await proofReadyBundle()
  try {
    const config = JSON.parse(readFileSync(fixture.configPath, 'utf8'))
    config.proof_files.push({
      path: 'test/security/unlisted-service.mjs',
      contents: '// must never boot\n',
    })
    config.service.command = command('test/security/unlisted-service.mjs')
    writeFileSync(fixture.configPath, JSON.stringify(config))
    let dockerCalls = 0
    await assert.rejects(
      runServiceProofCommand()(
        [fixture.bundle, fixture.configPath],
        { worker: fixture.workerPath },
        { dockerServiceProof: async () => { dockerCalls += 1 } },
      ),
      /service boot command.*not authorized|not authorized.*service boot command/i,
    )
    assert.equal(dockerCalls, 0)
    assert.equal(existsSync(join(fixture.bundle, 'proofs')), false)
  } finally {
    cleanFixture(fixture)
  }
})

test('startup failure is durably recorded as UNPROVEN after verified cleanup', async () => {
  const fixture = await proofReadyBundle()
  try {
    let calls = 0
    let rendered
    await runServiceProofCommand()(
      [fixture.bundle, fixture.configPath],
      { worker: fixture.workerPath },
      {
        dockerServiceProof: async () => {
          calls += 1
          const error = new Error('loopback service did not become ready before startup timeout')
          error.code = 'SERVICE_PROOF_STARTUP_TIMEOUT'
          error.evidence = {
            verification_status: 'UNPROVEN',
            blocking_reason: 'fixed loopback TCP readiness did not succeed',
            cleanup_verified: true,
            lifecycle_phase: 'startup',
          }
          throw error
        },
        output(value) {
          rendered = JSON.parse(value)
        },
      },
    )

    assert.equal(calls, 1)
    assert.equal(rendered.evidence.verification_status, 'UNPROVEN')
    assert.notEqual(rendered.evidence.proof_tier, 'T2')
    assert.match(rendered.evidence.blocking_reason, /loopback TCP readiness/i)
    const receipt = JSON.parse(readFileSync(
      join(fixture.bundle, ...rendered.receipt.path.split('/')),
      'utf8',
    ))
    assert.equal(receipt.evidence.verification_status, 'UNPROVEN')
    assert.equal(receipt.outcome.failure.code, 'SERVICE_PROOF_STARTUP_TIMEOUT')
    assert.equal(receipt.outcome.failure.cleanup_verified, true)
    assert.equal(receipt.outcome.demonstration, null)
    assert.equal(receipt.outcome.control, null)

    const persisted = JSON.parse(readFileSync(fixture.runPath, 'utf8'))
    const job = persisted.jobs.find(({ job_id: jobId }) => jobId === fixture.jobId)
    const finding = persisted.findings.find(
      ({ candidate_id: candidateId }) => candidateId === 'authz-object-level:serviceproof',
    )
    assert.equal(job.state, 'SUCCEEDED')
    assert.equal(finding.verification_status, 'UNPROVEN')
    assert.notEqual(finding.proof_tier, 'T2')
    assert.equal(finding.effective_severity, 'Medium')
  } finally {
    cleanFixture(fixture)
  }
})

test('run-service-proof command lock fences even an expired takeover while its controller is live', async () => {
  const fixture = await proofReadyBundle()
  let releaseFirst
  const firstGate = new Promise((resolve) => { releaseFirst = resolve })
  let reportFirstDispatch
  const firstDispatch = new Promise((resolve) => { reportFirstDispatch = resolve })
  try {
    let firstCalls = 0
    const firstRun = runServiceProofCommand()(
      [fixture.bundle, fixture.configPath],
      { worker: fixture.workerPath },
      {
        dockerServiceProof: async (input) => {
          firstCalls += 1
          const persisted = JSON.parse(readFileSync(fixture.runPath, 'utf8'))
          const state = persisted.jobs.find(
            ({ job_id: jobId }) => jobId === fixture.jobId,
          )?.state
          if (firstCalls === 1) {
            reportFirstDispatch(state)
            await firstGate
          }
          const role = input.args.at(-1).endsWith('/control.mjs') ? 'control' : 'attack'
          return serviceObservationForInput(role, role === 'control' ? 0 : 1, input)
        },
        output() {},
      },
    )

    assert.equal(await firstDispatch, 'RUNNING')
    let competingDockerCalls = 0
    let competingCleanupCalls = 0
    try {
      await assert.rejects(
        runServiceProofCommand()(
          [fixture.bundle, fixture.configPath],
          { worker: fixture.workerPath },
          {
            serviceProofNow: () => '2099-09-04T10:00:00.000Z',
            cleanupServiceProofContainers: async () => {
              competingCleanupCalls += 1
              throw new Error('a live controller lock must prevent takeover cleanup')
            },
            dockerServiceProof: async () => {
              competingDockerCalls += 1
              throw new Error('a competing caller must never reach Docker')
            },
          },
        ),
        /controller PID \d+ is active; refusing concurrent or expired-lease takeover/i,
      )
    } finally {
      releaseFirst()
    }
    await firstRun
    assert.equal(firstCalls, 2)
    assert.equal(competingDockerCalls, 0)
    assert.equal(competingCleanupCalls, 0)
  } finally {
    releaseFirst?.()
    cleanFixture(fixture)
  }
})

test('run-service-proof atomically recovers a dead controller command lock', async () => {
  const fixture = await proofReadyBundle()
  const lockPath = `${fixture.runPath}.service-proof.lock`
  const deadPid = 987_654_321
  try {
    writeFileSync(lockPath, stableJson({
      pid: deadPid,
      created_at: '2026-09-04T10:00:00.000Z',
      token: 'dead-controller-token-0000000000000001',
    }))
    let processChecks = 0
    let dockerCalls = 0
    await runServiceProofCommand()(
      [fixture.bundle, fixture.configPath],
      { worker: fixture.workerPath },
      {
        serviceProofProcessIsAlive(pid) {
          processChecks += 1
          assert.equal(pid, deadPid)
          return false
        },
        dockerServiceProof: async (input) => {
          dockerCalls += 1
          const role = input.args.at(-1).endsWith('/control.mjs') ? 'control' : 'attack'
          return serviceObservationForInput(role, role === 'control' ? 0 : 1, input)
        },
        output() {},
      },
    )
    assert.equal(processChecks, 2)
    assert.equal(dockerCalls, 2)
    assert.equal(existsSync(lockPath), false)
    assert.equal(existsSync(`${lockPath}.recovery`), false)
  } finally {
    rmSync(lockPath, { force: true })
    rmSync(`${lockPath}.recovery`, { force: true })
    cleanFixture(fixture)
  }
})

test('an attempt that expires during host preparation is fenced before Docker dispatch', async () => {
  const fixture = await proofReadyBundle()
  try {
    let dockerCalls = 0
    await assert.rejects(
      runServiceProofCommand()(
        [fixture.bundle, fixture.configPath],
        { worker: fixture.workerPath },
        {
          serviceProofDispatchNow: () => '2099-09-04T10:00:00.000Z',
          dockerServiceProof: async () => {
            dockerCalls += 1
            throw new Error('an expired attempt must not reach Docker')
          },
        },
      ),
      (error) => error?.code === 'SERVICE_PROOF_ATTEMPT_EXPIRED_BEFORE_DISPATCH',
    )
    assert.equal(dockerCalls, 0)
    const persisted = JSON.parse(readFileSync(fixture.runPath, 'utf8'))
    assert.equal(persisted.attempt_events.at(-1).event, 'FAILED')
    assert.equal(persisted.attempt_events.at(-1).recoverable, false)
    assert.equal(persisted.state, 'FAILED')
  } finally {
    cleanFixture(fixture)
  }
})

test('cleanup-unverified and untyped controller failures are durably FAILED without raw diagnostics', async () => {
  for (const scenario of [
    {
      expectedCode: 'SERVICE_PROOF_CLEANUP_UNVERIFIED',
      configure(error) {
        error.code = 'SERVICE_PROOF_CLEANUP_UNVERIFIED'
        error.evidence = { cleanup_verified: false }
      },
    },
    {
      expectedCode: 'SERVICE_PROOF_CONTROLLER_FAILED',
      configure() {},
    },
  ]) {
    const fixture = await proofReadyBundle()
    const secret = `raw-target-diagnostic-${scenario.expectedCode}`
    try {
      await assert.rejects(
        runServiceProofCommand()(
          [fixture.bundle, fixture.configPath],
          { worker: fixture.workerPath },
          {
            dockerServiceProof: async () => {
              const error = new Error(secret)
              scenario.configure(error)
              throw error
            },
          },
        ),
        new RegExp(secret),
      )

      const persistedText = readFileSync(fixture.runPath, 'utf8')
      const persisted = JSON.parse(persistedText)
      const job = persisted.jobs.find(({ job_id: jobId }) => jobId === fixture.jobId)
      const error = persisted.errors.find(({ job_id: jobId }) => jobId === fixture.jobId)
      assert.equal(job.state, 'FAILED')
      assert.equal(error.code, scenario.expectedCode)
      assert.match(error.message, /service-proof (?:execution stopped|controller failed)/i)
      assert.equal(persistedText.includes(secret), false)
      assert.equal(persisted.state, 'FAILED')
      assert.equal(existsSync(join(fixture.bundle, 'proofs')), false)
    } finally {
      cleanFixture(fixture)
    }
  }
})

test('mirror-temp creation failure removes sealed source and aggregates cleanup failure before lease', async () => {
  const fixture = await proofReadyBundle()
  const creationSecret = 'mirror-temp-creation-secret'
  const cleanupSecret = 'sealed-source-acquisition-cleanup-secret'
  const cleanupPaths = []
  let dockerCalls = 0
  try {
    let caught
    try {
      await runServiceProofCommand()(
        [fixture.bundle, fixture.configPath],
        { worker: fixture.workerPath },
        {
          createServiceProofMirrorTemporaryDirectory: async () => {
            throw new Error(creationSecret)
          },
          dockerServiceProof: async () => {
            dockerCalls += 1
            throw new Error('Docker must not run after mirror-temp creation fails')
          },
          removeHostTemporaryDirectory: async (path, options) => {
            cleanupPaths.push(path)
            rmSync(path, options)
            throw new Error(cleanupSecret)
          },
        },
      )
    } catch (error) {
      caught = error
    }

    assert.ok(caught instanceof AggregateError)
    assert.equal(caught.code, 'SERVICE_PROOF_HOST_TEMP_CLEANUP_FAILED')
    assert.deepEqual(
      caught.errors.map((error) => error.message),
      [creationSecret, cleanupSecret],
    )
    assert.equal(dockerCalls, 0)
    assert.equal(cleanupPaths.length, 1)
    assert.match(cleanupPaths[0], /red-team-audit-sealed-proof-/)
    assert.equal(existsSync(cleanupPaths[0]), false)

    const persistedText = readFileSync(fixture.runPath, 'utf8')
    const persisted = JSON.parse(persistedText)
    const job = persisted.jobs.find(({ job_id: jobId }) => jobId === fixture.jobId)
    assert.equal(job.state, 'PENDING')
    assert.equal(
      persisted.errors.some(({ job_id: jobId }) => jobId === fixture.jobId),
      false,
    )
    for (const secret of [creationSecret, cleanupSecret]) {
      assert.equal(persistedText.includes(secret), false)
    }
  } finally {
    cleanFixture(fixture)
  }
})

test('a first host-temp removal failure still attempts both removals and durably fails the job', async () => {
  const fixture = await proofReadyBundle()
  const cleanupSecret = 'first-host-temp-cleanup-secret'
  const removals = []
  try {
    let calls = 0
    let caught
    try {
      await runServiceProofCommand()(
        [fixture.bundle, fixture.configPath],
        { worker: fixture.workerPath },
        {
          dockerServiceProof: async (input) => {
            calls += 1
            const role = calls === 1 ? 'attack' : 'control'
            return serviceObservationForInput(role, role === 'control' ? 0 : 1, input)
          },
          removeHostTemporaryDirectory: async (path, options) => {
            removals.push(path)
            rmSync(path, options)
            if (removals.length === 1) throw new Error(cleanupSecret)
          },
        },
      )
    } catch (error) {
      caught = error
    }

    assert.ok(caught instanceof AggregateError)
    assert.equal(caught.code, 'SERVICE_PROOF_HOST_TEMP_CLEANUP_FAILED')
    assert.equal(caught.errors.some((error) => error.message === cleanupSecret), true)
    assert.equal(removals.length, 2)
    assert.equal(new Set(removals).size, 2)

    const persistedText = readFileSync(fixture.runPath, 'utf8')
    const persisted = JSON.parse(persistedText)
    const job = persisted.jobs.find(({ job_id: jobId }) => jobId === fixture.jobId)
    const runError = persisted.errors.find(({ job_id: jobId }) => jobId === fixture.jobId)
    assert.equal(job.state, 'FAILED')
    assert.equal(persisted.state, 'FAILED')
    assert.equal(runError.code, 'SERVICE_PROOF_HOST_TEMP_CLEANUP_FAILED')
    assert.equal(persistedText.includes(cleanupSecret), false)
    assert.equal(existsSync(join(fixture.bundle, 'proofs')), false)
  } finally {
    cleanFixture(fixture)
  }
})

test('execution and both host-temp removal failures are retained while persistence stays sanitized', async () => {
  const fixture = await proofReadyBundle()
  const executionSecret = 'service-proof-execution-secret'
  const cleanupSecrets = [
    'mirror-host-temp-cleanup-secret',
    'sealed-source-host-temp-cleanup-secret',
  ]
  const removals = []
  try {
    let caught
    try {
      await runServiceProofCommand()(
        [fixture.bundle, fixture.configPath],
        { worker: fixture.workerPath },
        {
          dockerServiceProof: async () => {
            throw new Error(executionSecret)
          },
          removeHostTemporaryDirectory: async (path, options) => {
            const cleanupSecret = cleanupSecrets[removals.length]
            removals.push(path)
            rmSync(path, options)
            throw new Error(cleanupSecret)
          },
        },
      )
    } catch (error) {
      caught = error
    }

    assert.ok(caught instanceof AggregateError)
    assert.equal(caught.code, 'SERVICE_PROOF_HOST_TEMP_CLEANUP_FAILED')
    assert.deepEqual(
      caught.errors.map((error) => error.message),
      [executionSecret, ...cleanupSecrets],
    )
    assert.equal(removals.length, 2)
    assert.equal(new Set(removals).size, 2)

    const persistedText = readFileSync(fixture.runPath, 'utf8')
    const persisted = JSON.parse(persistedText)
    const job = persisted.jobs.find(({ job_id: jobId }) => jobId === fixture.jobId)
    const runError = persisted.errors.find(({ job_id: jobId }) => jobId === fixture.jobId)
    assert.equal(job.state, 'FAILED')
    assert.equal(persisted.state, 'FAILED')
    assert.equal(runError.code, 'SERVICE_PROOF_HOST_TEMP_CLEANUP_FAILED')
    for (const secret of [executionSecret, ...cleanupSecrets]) {
      assert.equal(persistedText.includes(secret), false)
    }
    assert.equal(existsSync(join(fixture.bundle, 'proofs')), false)
  } finally {
    cleanFixture(fixture)
  }
})

test('cleanup-verified execution failure keeps hash-only attack and control observations in a T0 receipt', async () => {
  const fixture = await proofReadyBundle()
  const secret = 'raw-control-output-must-not-enter-the-receipt'
  try {
    let calls = 0
    let rendered
    await runServiceProofCommand()(
      [fixture.bundle, fixture.configPath],
      { worker: fixture.workerPath },
      {
        dockerServiceProof: async (input) => {
          calls += 1
          if (calls === 1) return serviceObservationForInput('attack', 1, input)
          const error = new Error(secret)
          error.code = 'SERVICE_PROOF_EXECUTION_UNPROVEN'
          error.evidence = {
            verification_status: 'UNPROVEN',
            cleanup_verified: true,
          }
          error.partial_result = {
            ...await serviceObservationForInput('control', 0, input),
            stdout: secret,
            stdout_bytes: Buffer.byteLength(secret),
            stdout_sha256: sha256(secret),
          }
          throw error
        },
        output(value) {
          rendered = JSON.parse(value)
        },
      },
    )

    assert.equal(calls, 2)
    assert.equal(rendered.evidence.proof_tier, 'T0')
    assert.equal(rendered.evidence.verification_status, 'UNPROVEN')
    const receiptText = readFileSync(
      join(fixture.bundle, ...rendered.receipt.path.split('/')),
      'utf8',
    )
    const receipt = JSON.parse(receiptText)
    assert.equal(receipt.outcome.failure.code, 'SERVICE_PROOF_EXECUTION_UNPROVEN')
    assert.equal(receipt.outcome.failure.cleanup_verified, true)
    assert.equal(receipt.outcome.demonstration.code, 1)
    assert.equal(receipt.outcome.control.code, 0)
    assert.equal(receipt.outcome.control.stdout_bytes, Buffer.byteLength(secret))
    assert.equal(receipt.outcome.control.stdout_sha256, sha256(secret))
    assert.equal(receiptText.includes(secret), false)

    const persisted = JSON.parse(readFileSync(fixture.runPath, 'utf8'))
    const job = persisted.jobs.find(({ job_id: jobId }) => jobId === fixture.jobId)
    assert.equal(job.state, 'SUCCEEDED')
    const finding = persisted.findings.find(
      ({ candidate_id: candidateId }) => candidateId === 'authz-object-level:serviceproof',
    )
    assert.equal(finding.proof_tier, 'T0')
    assert.equal(finding.verification_status, 'UNPROVEN')
  } finally {
    cleanFixture(fixture)
  }
})

test('expired LEASED service proof retries without cleanup and commits a fresh lease', async () => {
  const fixture = await proofReadyBundle({
    createdAt: new Date(Date.now() - (2 * 60 * 60 * 1_000)),
  })
  try {
    const seeded = seedExpiredServiceProofAttempt(fixture)
    let cleanupCalls = 0
    const dockerContainerNames = []
    let rendered

    await runServiceProofCommand()(
      [fixture.bundle, fixture.configPath],
      { worker: fixture.workerPath },
      {
        serviceProofNow: () => new Date(
          Date.parse(seeded.expiresAt) + 1,
        ).toISOString(),
        cleanupServiceProofContainers: async () => {
          cleanupCalls += 1
          throw new Error('an expired LEASED attempt must not reach Docker cleanup')
        },
        dockerServiceProof: async (input) => {
          dockerContainerNames.push(input.containerName)
          const role = input.args.at(-1).endsWith('/control.mjs') ? 'control' : 'attack'
          return serviceObservationForInput(role, role === 'control' ? 0 : 1, input)
        },
        output(value) {
          rendered = JSON.parse(value)
        },
      },
    )

    assert.equal(cleanupCalls, 0)
    assert.equal(dockerContainerNames.length, 2)
    assert.notEqual(dockerContainerNames[0], dockerContainerNames[1])
    for (const name of dockerContainerNames) {
      assert.notEqual(name, seeded.serviceContainerNames.attack)
      assert.notEqual(name, seeded.serviceContainerNames.control)
    }
    const persisted = JSON.parse(readFileSync(fixture.runPath, 'utf8'))
    assert.deepEqual(
      persisted.attempt_events.map(({ event }) => event),
      ['LEASED', 'FAILED', 'LEASED', 'STARTED', 'RESULT_CAPTURED', 'VALIDATED', 'COMMITTED'],
    )
    assert.equal(persisted.attempt_events[1].recoverable, true)
    assert.equal(rendered.resumed, false)
    await audit.verifyControlBundle(fixture.bundle, persisted, {
      requireCurrentLensPack: true,
    })
  } finally {
    cleanFixture(fixture)
  }
})

test('expired STARTED service proof authenticates exact cleanup inputs before a fresh retry', async () => {
  const fixture = await proofReadyBundle({
    createdAt: new Date(Date.now() - (2 * 60 * 60 * 1_000)),
  })
  try {
    const seeded = seedExpiredServiceProofAttempt(fixture, { started: true })
    const cleanupInputs = []
    const dockerContainerNames = []

    await runServiceProofCommand()(
      [fixture.bundle, fixture.configPath],
      { worker: fixture.workerPath },
      {
        serviceProofNow: () => new Date(
          Date.parse(seeded.expiresAt) + 1,
        ).toISOString(),
        cleanupServiceProofContainers: async (input) => {
          cleanupInputs.push(input)
          return {
            service_container_names: input.serviceContainerNames,
            cleanup_verified: true,
          }
        },
        dockerServiceProof: async (input) => {
          dockerContainerNames.push(input.containerName)
          const role = input.args.at(-1).endsWith('/control.mjs') ? 'control' : 'attack'
          return serviceObservationForInput(role, role === 'control' ? 0 : 1, input)
        },
        output() {},
      },
    )

    assert.equal(cleanupInputs.length, 1)
    assert.deepEqual(cleanupInputs[0].serviceContainerNames, seeded.serviceContainerNames)
    assert.deepEqual(cleanupInputs[0].config, seeded.worker)
    assert.deepEqual(cleanupInputs[0].service, seeded.config.service)
    assert.deepEqual(cleanupInputs[0].limits, seeded.config.limits)
    assert.equal(dockerContainerNames.length, 2)
    assert.notEqual(dockerContainerNames[0], dockerContainerNames[1])
    for (const name of dockerContainerNames) {
      assert.notEqual(name, seeded.serviceContainerNames.attack)
      assert.notEqual(name, seeded.serviceContainerNames.control)
    }
    const persisted = JSON.parse(readFileSync(fixture.runPath, 'utf8'))
    assert.deepEqual(
      persisted.attempt_events.map(({ event }) => event),
      ['LEASED', 'STARTED', 'FAILED', 'LEASED', 'STARTED', 'RESULT_CAPTURED', 'VALIDATED', 'COMMITTED'],
    )
    assert.equal(persisted.attempt_events[2].recoverable, true)
  } finally {
    cleanFixture(fixture)
  }
})

test('expired STARTED cleanup ambiguity terminalizes without Docker re-execution', async () => {
  const fixture = await proofReadyBundle({
    createdAt: new Date(Date.now() - (2 * 60 * 60 * 1_000)),
  })
  try {
    const seeded = seedExpiredServiceProofAttempt(fixture, { started: true })
    let cleanupCalls = 0
    let dockerCalls = 0
    const cleanupError = Object.assign(new Error('raw cleanup ambiguity'), {
      code: 'SERVICE_PROOF_RECOVERY_CLEANUP_UNVERIFIED',
      cleanup_verified: false,
      evidence: {
        verification_status: 'UNPROVEN',
        cleanup_verified: false,
      },
    })

    await assert.rejects(
      runServiceProofCommand()(
        [fixture.bundle, fixture.configPath],
        { worker: fixture.workerPath },
        {
          serviceProofNow: () => new Date(
            Date.parse(seeded.expiresAt) + 1,
          ).toISOString(),
          cleanupServiceProofContainers: async (input) => {
            cleanupCalls += 1
            assert.deepEqual(input.serviceContainerNames, seeded.serviceContainerNames)
            throw cleanupError
          },
          dockerServiceProof: async () => {
            dockerCalls += 1
            throw new Error('cleanup ambiguity must prevent Docker re-execution')
          },
        },
      ),
      (error) => error === cleanupError,
    )

    assert.equal(cleanupCalls, 1)
    assert.equal(dockerCalls, 0)
    const persistedText = readFileSync(fixture.runPath, 'utf8')
    const persisted = JSON.parse(persistedText)
    const job = persisted.jobs.find(({ job_id: jobId }) => jobId === fixture.jobId)
    assert.equal(job.state, 'FAILED')
    assert.equal(persisted.state, 'FAILED')
    assert.deepEqual(
      persisted.attempt_events.map(({ event }) => event),
      ['LEASED', 'STARTED', 'FAILED'],
    )
    assert.equal(persisted.attempt_events.at(-1).recoverable, false)
    assert.equal(persistedText.includes('raw cleanup ambiguity'), false)
  } finally {
    cleanFixture(fixture)
  }
})

test('expired STARTED recovery rejects unresolved, false, or wrong-name cleanup attestations', async () => {
  for (const cleanupResult of [
    undefined,
    { cleanup_verified: false },
    {
      cleanup_verified: true,
      service_container_names: {
        attack: 'rta-proof-service-attack-wrong-0001',
        control: 'rta-proof-service-control-wrong-0001',
      },
    },
  ]) {
    const fixture = await proofReadyBundle({
      createdAt: new Date(Date.now() - (2 * 60 * 60 * 1_000)),
    })
    try {
      const seeded = seedExpiredServiceProofAttempt(fixture, { started: true })
      let dockerCalls = 0
      await assert.rejects(
        runServiceProofCommand()(
          [fixture.bundle, fixture.configPath],
          { worker: fixture.workerPath },
          {
            serviceProofNow: () => new Date(
              Date.parse(seeded.expiresAt) + 1,
            ).toISOString(),
            cleanupServiceProofContainers: async () => cleanupResult,
            dockerServiceProof: async () => {
              dockerCalls += 1
              throw new Error('invalid cleanup attestation must prevent Docker re-execution')
            },
          },
        ),
        (error) => error?.code === 'SERVICE_PROOF_RECOVERY_CLEANUP_UNVERIFIED',
      )
      assert.equal(dockerCalls, 0)
      const persisted = JSON.parse(readFileSync(fixture.runPath, 'utf8'))
      assert.equal(persisted.attempt_events.at(-1).event, 'FAILED')
      assert.equal(persisted.attempt_events.at(-1).recoverable, false)
      assert.equal(persisted.attempt_events.at(-1).cleanup_verified, false)
      assert.equal(persisted.state, 'FAILED')
    } finally {
      cleanFixture(fixture)
    }
  }
})

test('a crash after RESULT_CAPTURED resumes the exact receipt without a second Docker launch', async () => {
  const fixture = await proofReadyBundle()
  try {
    let firstDockerCalls = 0
    const simulatedCrash = new Error('simulated controller crash after RESULT_CAPTURED')
    await assert.rejects(
      runServiceProofCommand()(
        [fixture.bundle, fixture.configPath],
        { worker: fixture.workerPath },
        {
          dockerServiceProof: async (input) => {
            firstDockerCalls += 1
            const role = input.args.at(-1).endsWith('/control.mjs') ? 'control' : 'attack'
            return serviceObservationForInput(role, role === 'control' ? 0 : 1, input)
          },
          completeServiceProofAttempt: async () => {
            throw simulatedCrash
          },
        },
      ),
      (error) => error === simulatedCrash,
    )
    assert.equal(firstDockerCalls, 2)

    const captured = JSON.parse(readFileSync(fixture.runPath, 'utf8'))
    assert.equal(captured.attempt_events.at(-1).event, 'RESULT_CAPTURED')
    const capturedAttemptId = captured.attempt_events[0].attempt_id
    const capturedArtifactKey = captured.attempt_events.at(-1).execution_artifact_key
    const capturedReceipt = structuredClone(captured.artifacts[capturedArtifactKey])
    const capturedReceiptText = readFileSync(
      join(fixture.bundle, ...capturedReceipt.path.split('/')),
      'utf8',
    )

    let secondDockerCalls = 0
    let rendered
    await runServiceProofCommand()(
      [fixture.bundle, fixture.configPath],
      { worker: fixture.workerPath },
      {
        dockerServiceProof: async () => {
          secondDockerCalls += 1
          throw new Error('RESULT_CAPTURED resume must not launch Docker')
        },
        output(value) {
          rendered = JSON.parse(value)
        },
      },
    )

    assert.equal(secondDockerCalls, 0)
    assert.equal(rendered.resumed, true)
    assert.equal(rendered.attempt_id, capturedAttemptId)
    assert.deepEqual(rendered.receipt, capturedReceipt)
    assert.equal(
      readFileSync(join(fixture.bundle, ...rendered.receipt.path.split('/')), 'utf8'),
      capturedReceiptText,
    )
    const committed = JSON.parse(readFileSync(fixture.runPath, 'utf8'))
    assert.deepEqual(
      committed.attempt_events.map(({ event }) => event),
      ['LEASED', 'STARTED', 'RESULT_CAPTURED', 'VALIDATED', 'COMMITTED'],
    )
    const job = committed.jobs.find(({ job_id: jobId }) => jobId === fixture.jobId)
    assert.equal(job.state, 'SUCCEEDED')
    assert.equal(job.attempt_id, capturedAttemptId)
    await audit.verifyControlBundle(fixture.bundle, committed, {
      requireCurrentLensPack: true,
    })
  } finally {
    cleanFixture(fixture)
  }
})
