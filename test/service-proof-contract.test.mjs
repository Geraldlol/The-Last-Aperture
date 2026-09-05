import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { execFileSync, spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

import Ajv2020 from 'ajv/dist/2020.js'
import { proofEvidence } from '../scripts/lib/proof-evidence.mjs'

const CLI = resolve('scripts/audit.mjs')
const PROOF_SCHEMA = resolve('schemas/proof-config.schema.json')

function command(path) {
  return { program: 'node', args: [path] }
}

function serviceProofConfig(overrides = {}) {
  return {
    schema_version: '3.0.0',
    job_id: 'proof-verification:service-proof-contract',
    proof_files: [
      { path: 'test/security/service.mjs', contents: '// service fixture\n' },
      { path: 'test/security/attack.mjs', contents: '// attack fixture\n' },
      { path: 'test/security/control.mjs', contents: '// control fixture\n' },
    ],
    service: {
      protocol: 'loopback-tcp-v1',
      command: command('test/security/service.mjs'),
      port: 31_337,
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

async function proofExecutionModule() {
  return import('../scripts/lib/proof-execution.mjs')
}

test('proof config v3 is a strict service-proof contract with fixed TCP health', async () => {
  assert.equal(
    existsSync(PROOF_SCHEMA),
    true,
    'schemas/proof-config.schema.json must remain the public proof contract',
  )
  const schema = JSON.parse(readFileSync(PROOF_SCHEMA, 'utf8'))
  const validate = new Ajv2020({ strict: true, allErrors: true }).compile(schema)
  assert.equal(validate(serviceProofConfig()), true, JSON.stringify(validate.errors))

  for (const mutate of [
    (value) => { value.service.command.program = 'sh' },
    (value) => { value.command.program = 'powershell' },
    (value) => { value.control_command.program = 'bash' },
    (value) => { value.service.protocol = 'http-health-v1' },
    (value) => { value.service.port = 0 },
    (value) => { value.service.port = 65_536 },
    (value) => { value.service.startup_timeout_ms = 99 },
    (value) => { value.service.probe_interval_ms = 0 },
    (value) => { value.service.host = '0.0.0.0' },
    (value) => { value.service.origin = 'http://example.test' },
    (value) => { value.service.health_command = command('test/security/health.mjs') },
    (value) => { value.authorization_confirmed = true },
    (value) => { value.attest_authorized = true },
  ]) {
    const invalid = structuredClone(serviceProofConfig())
    mutate(invalid)
    assert.equal(validate(invalid), false, JSON.stringify(invalid))
  }
})

test('proof validation binds v3 service, attack, control, and oracle semantics', async () => {
  const { assertValidProofConfig } = await proofExecutionModule()
  const normalized = assertValidProofConfig(serviceProofConfig())
  assert.equal(normalized.schema_version, '3.0.0')
  assert.equal(normalized.service.protocol, 'loopback-tcp-v1')
  assert.equal(normalized.service.port, 31_337)

  const overlappingOracle = serviceProofConfig()
  overlappingOracle.oracle.control_exit_codes = [1]
  assert.throws(
    () => assertValidProofConfig(overlappingOracle),
    /attack and control oracle exit codes must be disjoint/i,
  )
})

test('run-service-proof is public and has no repeated authorization input', () => {
  const help = execFileSync(process.execPath, [CLI, '--help'], { encoding: 'utf8' })
  assert.match(
    help,
    /run-service-proof <run\.json\|bundle-directory> <service-proof-config\.json> --worker <proof-worker\.json>/,
  )
  assert.doesNotMatch(help, /run-service-proof[^\n]*\[DISABLED\]/)
  assert.doesNotMatch(
    help,
    /run-service-proof[^\n]*(?:authori[sz]|confirm|consent|attest|rules.of.engagement)/i,
  )

  for (const flag of [
    '--authorization-confirmed',
    '--confirm-authorization-current',
    '--attest-authorized',
  ]) {
    const result = spawnSync(process.execPath, [
      CLI,
      'run-service-proof',
      'missing-bundle',
      'missing-service-proof.json',
      '--worker',
      'missing-worker.json',
      flag,
    ], { encoding: 'utf8' })
    assert.equal(result.status, 1)
    assert.match(result.stderr, new RegExp(`unknown option ${flag}`, 'i'))
    assert.doesNotMatch(result.stderr, /authorization (?:is )?required|provide.*authorization/i)
  }
})

test('local_dynamic planning is activated for a sealed T2 bundle', () => {
  const target = mkdtempSync(join(tmpdir(), 'rta-service-plan-target-'))
  const output = mkdtempSync(join(tmpdir(), 'rta-service-plan-output-'))
  try {
    mkdirSync(join(target, 'src'), { recursive: true })
    writeFileSync(join(target, 'src', 'server.js'), '// local service target\n')
    writeFileSync(join(target, 'package.json'), '{"name":"service-proof-target"}\n')
    writeFileSync(join(target, 'package-lock.json'), JSON.stringify({
      name: 'service-proof-target',
      lockfileVersion: 3,
      packages: {},
    }))
    const policyPath = join(output, 'local-dynamic-policy.json')
    writeFileSync(policyPath, JSON.stringify({
      schema_version: '1.0',
      policy_id: 'service-proof-local-dynamic',
      mode: 'local_dynamic',
      workspace_root: resolve(target),
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
            ports: [31_337],
            path_prefix: '/',
          }],
        },
      },
    }))

    const result = spawnSync(process.execPath, [
      CLI,
      'plan',
      target,
      '--out',
      output,
      '--roe',
      policyPath,
      '--seal-source',
    ], { encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr)
    assert.doesNotMatch(result.stderr, /authorization/i)
    const bundles = readdirSync(output, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
    assert.equal(bundles.length, 1)
    const run = JSON.parse(readFileSync(join(output, bundles[0].name, 'run.json'), 'utf8'))
    assert.equal(run.capability_mode, 'LOCAL_DYNAMIC')
    assert.ok(run.source_snapshot)
  } finally {
    rmSync(target, { recursive: true, force: true })
    rmSync(output, { recursive: true, force: true })
  }
})

const EMPTY_SHA256 = createHash('sha256').digest('hex')
const EXPECTED_WORKER_CONFIG_SHA256 = 'a'.repeat(64)
const EXPECTED_WORKER_IMAGE = `sha256:${'b'.repeat(64)}`
const EXPECTED_WORKER_WALL_TIME_MS = 120_000
const EXPECTED_CONTROLLER_ACTIVE_BUDGET_MS = 2_520_000
const EXPECTED_CONTROLLER_CLEANUP_RESERVE_MS = 720_000
const EXPECTED_CONTROLLER_SESSION_BUDGET_MS = 3_240_000
const EXPECTED_PROOF_WORKTREE_SHA256 = 'e'.repeat(64)

function serviceProofContext(overrides = {}) {
  return {
    ruleSixApplicable: true,
    proofWorker: {
      config_sha256: EXPECTED_WORKER_CONFIG_SHA256,
      image: EXPECTED_WORKER_IMAGE,
      wall_time_ms: EXPECTED_WORKER_WALL_TIME_MS,
      controller_session_budget_ms: EXPECTED_CONTROLLER_SESSION_BUDGET_MS,
      controller_active_budget_ms: EXPECTED_CONTROLLER_ACTIVE_BUDGET_MS,
      controller_cleanup_reserve_ms: EXPECTED_CONTROLLER_CLEANUP_RESERVE_MS,
    },
    proofWorktreeSha256: EXPECTED_PROOF_WORKTREE_SHA256,
    ...overrides,
  }
}

function serviceProcessObservation(role, code) {
  return {
    code,
    signal: null,
    timed_out: false,
    spawn_error: false,
    duration_ms: 7,
    stdout: '',
    stderr: '',
    stdout_bytes: 0,
    stdout_sha256: EMPTY_SHA256,
    stdout_truncated: false,
    stderr_bytes: 0,
    stderr_sha256: EMPTY_SHA256,
    stderr_truncated: false,
    output_omitted: true,
    sandbox: {
      backend: 'OCI_DOCKER',
      worker_config_sha256: EXPECTED_WORKER_CONFIG_SHA256,
      image: EXPECTED_WORKER_IMAGE,
      container_id: (role === 'attack' ? 'c' : 'd').repeat(64),
      network_mode: 'none',
      mounts: [],
      environment: 'controller-minimal',
      cleanup_verified: true,
      service: {
        protocol: 'loopback-tcp-v1',
        host: '127.0.0.1',
        port: 31_337,
        supervisor_ttl_ms: EXPECTED_WORKER_WALL_TIME_MS,
        controller_session_budget_ms: EXPECTED_CONTROLLER_SESSION_BUDGET_MS,
        controller_active_budget_ms: EXPECTED_CONTROLLER_ACTIVE_BUDGET_MS,
        controller_cleanup_reserve_ms: EXPECTED_CONTROLLER_CLEANUP_RESERVE_MS,
        pre_boot_closed: true,
        pre_probe_ready: true,
        post_probe_ready: true,
        source_immutable: true,
        source_tree_sha256: EXPECTED_PROOF_WORKTREE_SHA256,
        runtime_root: '/work/runtime',
        output_omitted: true,
      },
    },
  }
}

function validServiceOutcome(attackCode = 0) {
  return {
    demonstration: serviceProcessObservation('attack', attackCode),
    control: serviceProcessObservation('control', 0),
    remediation: null,
  }
}

test('T2 lifecycle evidence remains semantically unproven without an enrolled oracle', () => {
  const context = serviceProofContext()
  const notReproduced = proofEvidence(validServiceOutcome(0), serviceProofConfig(), context)
  assert.equal(notReproduced.proof_tier, 'T2')
  assert.equal(notReproduced.verification_status, 'UNPROVEN')
  assert.match(notReproduced.blocking_reason, /no controller-authenticated semantic oracle/i)
  const confirmed = proofEvidence(validServiceOutcome(1), serviceProofConfig(), context)
  assert.equal(confirmed.proof_tier, 'T2')
  assert.equal(confirmed.verification_status, 'UNPROVEN')
  assert.match(confirmed.blocking_reason, /no controller-authenticated semantic oracle/i)

  const mutations = [
    (outcome) => { outcome.demonstration.sandbox.cleanup_verified = false },
    (outcome) => { outcome.control.sandbox.cleanup_verified = false },
    (outcome) => { outcome.demonstration.sandbox.network_mode = 'bridge' },
    (outcome) => { outcome.control.sandbox.mounts = ['C:\\host:/work'] },
    (outcome) => { outcome.demonstration.sandbox.service.pre_boot_closed = false },
    (outcome) => { outcome.control.sandbox.service.pre_probe_ready = false },
    (outcome) => { outcome.demonstration.sandbox.service.post_probe_ready = false },
    (outcome) => { delete outcome.control.sandbox.service.post_probe_ready },
    (outcome) => {
      outcome.control.sandbox.container_id = outcome.demonstration.sandbox.container_id
    },
  ]
  for (const mutate of mutations) {
    const outcome = validServiceOutcome(0)
    mutate(outcome)
    const evidence = proofEvidence(outcome, serviceProofConfig(), context)
    assert.equal(evidence.verification_status, 'UNPROVEN')
    assert.notEqual(evidence.proof_tier, 'T2')
    assert.match(
      evidence.blocking_reason ?? evidence.reason,
      /service|session|cleanup|network|mount|readiness|fresh/i,
    )
  }
})

test('T2 lifecycle binds nested output omission and the exact worker supervisor TTL', () => {
  for (const mutate of [
    (outcome) => { outcome.demonstration.sandbox.service.output_omitted = false },
    (outcome) => { delete outcome.control.sandbox.service.output_omitted },
    (outcome) => { outcome.demonstration.sandbox.service.supervisor_ttl_ms = 119_999 },
    (outcome) => { outcome.control.sandbox.service.supervisor_ttl_ms = '120000' },
  ]) {
    const outcome = validServiceOutcome(1)
    mutate(outcome)
    const evidence = proofEvidence(outcome, serviceProofConfig(), serviceProofContext())
    assert.equal(evidence.proof_tier, 'T0')
    assert.equal(evidence.verification_status, 'UNPROVEN')
    assert.match(evidence.blocking_reason, /output omission|supervisor TTL|worker wall time/i)
  }
})

test('T2 lifecycle binds each session to one truthful cumulative controller deadline', () => {
  const contextMutations = [
    (context) => { delete context.proofWorker.controller_session_budget_ms },
    (context) => { context.proofWorker.controller_session_budget_ms -= 1 },
    (context) => { context.proofWorker.controller_active_budget_ms = 119_999 },
    (context) => { context.proofWorker.controller_cleanup_reserve_ms = '720000' },
  ]
  for (const mutate of contextMutations) {
    const context = serviceProofContext()
    mutate(context)
    const evidence = proofEvidence(validServiceOutcome(1), serviceProofConfig(), context)
    assert.equal(evidence.proof_tier, 'T0')
    assert.match(evidence.blocking_reason, /worker|controller/i)
  }

  for (const mutate of [
    (outcome) => { delete outcome.demonstration.sandbox.service.controller_session_budget_ms },
    (outcome) => { outcome.control.sandbox.service.controller_active_budget_ms -= 1 },
    (outcome) => { outcome.demonstration.sandbox.service.controller_cleanup_reserve_ms = null },
  ]) {
    const outcome = validServiceOutcome(1)
    mutate(outcome)
    const evidence = proofEvidence(outcome, serviceProofConfig(), serviceProofContext())
    assert.equal(evidence.proof_tier, 'T0')
    assert.match(evidence.blocking_reason, /cumulative controller deadline/i)
  }
})

test('T2 classification binds both sessions to the controller-computed proof worktree', () => {
  const missingExpected = serviceProofContext()
  delete missingExpected.proofWorktreeSha256
  const withoutExpected = proofEvidence(
    validServiceOutcome(1),
    serviceProofConfig(),
    missingExpected,
  )
  assert.equal(withoutExpected.proof_tier, 'T0')
  assert.equal(withoutExpected.verification_status, 'UNPROVEN')
  assert.match(withoutExpected.blocking_reason, /controller-computed proof worktree/i)

  for (const mutate of [
    (outcome) => { outcome.demonstration.sandbox.service.source_immutable = false },
    (outcome) => { delete outcome.control.sandbox.service.source_immutable },
    (outcome) => { outcome.demonstration.sandbox.service.source_tree_sha256 = 'f'.repeat(64) },
    (outcome) => { delete outcome.control.sandbox.service.source_tree_sha256 },
    (outcome) => { outcome.demonstration.sandbox.service.runtime_root = '/work' },
    (outcome) => { delete outcome.control.sandbox.service.runtime_root },
  ]) {
    const outcome = validServiceOutcome(1)
    mutate(outcome)
    const evidence = proofEvidence(outcome, serviceProofConfig(), serviceProofContext())
    assert.equal(evidence.proof_tier, 'T0')
    assert.equal(evidence.verification_status, 'UNPROVEN')
    assert.match(evidence.blocking_reason, /source|worktree|runtime scratch/i)
  }
})

test('T2 classification binds both sessions to the controller-selected receipt worker', () => {
  const context = serviceProofContext()

  const noExpectedWorker = proofEvidence(
    validServiceOutcome(1),
    serviceProofConfig(),
    { ruleSixApplicable: true },
  )
  assert.equal(noExpectedWorker.proof_tier, 'T0')
  assert.equal(noExpectedWorker.verification_status, 'UNPROVEN')
  assert.match(noExpectedWorker.blocking_reason, /controller-selected.*worker|receipt worker/i)

  for (const invalidWallTime of [undefined, '120000', 999, 3_600_001]) {
    const invalidContext = serviceProofContext()
    if (invalidWallTime === undefined) delete invalidContext.proofWorker.wall_time_ms
    else invalidContext.proofWorker.wall_time_ms = invalidWallTime
    const evidence = proofEvidence(validServiceOutcome(1), serviceProofConfig(), invalidContext)
    assert.equal(evidence.proof_tier, 'T0')
    assert.equal(evidence.verification_status, 'UNPROVEN')
    assert.match(evidence.blocking_reason, /controller-selected.*worker|receipt worker/i)
  }

  for (const field of ['config_sha256', 'image']) {
    const invalidContext = serviceProofContext()
    const outcome = validServiceOutcome(1)
    const invalidValue = [invalidContext.proofWorker[field]]
    invalidContext.proofWorker[field] = invalidValue
    const sandboxField = field === 'config_sha256' ? 'worker_config_sha256' : field
    outcome.demonstration.sandbox[sandboxField] = invalidValue
    outcome.control.sandbox[sandboxField] = invalidValue
    const evidence = proofEvidence(outcome, serviceProofConfig(), invalidContext)
    assert.equal(evidence.proof_tier, 'T0')
    assert.equal(evidence.verification_status, 'UNPROVEN')
    assert.match(evidence.blocking_reason, /controller-selected.*worker|receipt worker/i)
  }

  for (const mutate of [
    (worker) => { worker.config_sha256 = [EXPECTED_WORKER_CONFIG_SHA256] },
    (worker) => { worker.image = [EXPECTED_WORKER_IMAGE] },
  ]) {
    const invalidContext = serviceProofContext()
    mutate(invalidContext.proofWorker)
    const evidence = proofEvidence(validServiceOutcome(1), serviceProofConfig(), invalidContext)
    assert.equal(evidence.proof_tier, 'T0')
    assert.equal(evidence.verification_status, 'UNPROVEN')
    assert.match(evidence.blocking_reason, /controller-selected.*worker|receipt worker/i)
  }

  for (const mutate of [
    (outcome) => {
      outcome.demonstration.sandbox.worker_config_sha256 = 'f'.repeat(64)
      outcome.control.sandbox.worker_config_sha256 = 'f'.repeat(64)
    },
    (outcome) => {
      outcome.demonstration.sandbox.image = `sha256:${'e'.repeat(64)}`
      outcome.control.sandbox.image = `sha256:${'e'.repeat(64)}`
    },
  ]) {
    const outcome = validServiceOutcome(1)
    mutate(outcome)
    const evidence = proofEvidence(outcome, serviceProofConfig(), context)
    assert.equal(evidence.proof_tier, 'T0')
    assert.equal(evidence.verification_status, 'UNPROVEN')
    assert.match(evidence.blocking_reason, /controller-selected.*worker|receipt worker/i)
  }
})

test('timed-out, signaled, spawn-failed, or truncated sessions never claim T2', () => {
  for (const mutate of [
    (outcome) => { outcome.demonstration.timed_out = true },
    (outcome) => { outcome.demonstration.signal = 'SIGKILL' },
    (outcome) => { outcome.control.spawn_error = true },
    (outcome) => { outcome.demonstration.stdout_truncated = true },
    (outcome) => { outcome.control.stderr_truncated = true },
    (outcome) => { delete outcome.demonstration.timed_out },
    (outcome) => { delete outcome.control.stdout_truncated },
    (outcome) => { delete outcome.demonstration.stderr_sha256 },
    (outcome) => { outcome.control.code = null },
  ]) {
    const outcome = validServiceOutcome(1)
    mutate(outcome)
    const evidence = proofEvidence(outcome, serviceProofConfig(), serviceProofContext())
    assert.notEqual(evidence.proof_tier, 'T2')
    assert.equal(evidence.verification_status, 'UNPROVEN')
    assert.match(
      evidence.blocking_reason,
      /timed out|signal|start|output|truncat|complete|metadata|record/i,
    )
  }
})

test('T2 process observations require strict bounded scalar and digest shapes', () => {
  const mutations = [
    (result) => { result.code = '1' },
    (result) => { result.code = 1.5 },
    (result) => { result.code = -1 },
    (result) => { result.code = 256 },
    (result) => { result.duration_ms = '7' },
    (result) => { result.duration_ms = 1.5 },
    (result) => { result.duration_ms = -1 },
    (result) => { result.duration_ms = 2_001 },
    (result) => { result.timed_out = 0 },
    (result) => { result.spawn_error = 'false' },
    (result) => { result.signal = undefined },
    (result) => { result.stdout = undefined },
    (result) => { result.stderr = null },
    (result) => { result.stdout_bytes = '0' },
    (result) => { result.stderr_bytes = 0.5 },
    (result) => { result.stdout_bytes = -1 },
    (result) => { result.stdout_bytes = 4_097 },
    (result) => {
      result.stdout_bytes = 2_048
      result.stderr_bytes = 2_049
    },
    (result) => { result.stdout_sha256 = 'A'.repeat(64) },
    (result) => { result.stderr_sha256 = 'a'.repeat(63) },
    (result) => { result.stdout_sha256 = 'f'.repeat(64) },
    (result) => { result.stdout_sha256 = [EMPTY_SHA256] },
    (result) => { result.stdout_truncated = 0 },
    (result) => { result.stderr_truncated = 'false' },
    (result) => { result.output_omitted = 1 },
    (result) => { result.sandbox.cleanup_verified = 1 },
    (result) => {
      result.sandbox.worker_config_sha256 = [EXPECTED_WORKER_CONFIG_SHA256]
    },
    (result) => { result.sandbox.image = [EXPECTED_WORKER_IMAGE] },
    (result) => { result.sandbox.container_id = [result.sandbox.container_id] },
    (result) => { result.sandbox.service.pre_boot_closed = 1 },
  ]

  for (const mutate of mutations) {
    const outcome = validServiceOutcome(1)
    mutate(outcome.demonstration)
    const evidence = proofEvidence(outcome, serviceProofConfig(), serviceProofContext())
    assert.equal(evidence.proof_tier, 'T0')
    assert.equal(evidence.verification_status, 'UNPROVEN')
    assert.match(
      evidence.blocking_reason,
      /service session|metadata|output|process state|cleanup|port closed/i,
    )
  }
})
