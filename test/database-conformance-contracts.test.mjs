import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  databaseConformanceManifest,
  validateDatabaseConformanceConfig,
  validateDatabaseConformanceEvidence,
  validateDatabaseConformanceManifest,
  validateDatabaseConformanceResult,
  validateDatabaseConformanceRun,
} from '../scripts/lib/database-conformance-contracts.mjs'

const HASH = 'a'.repeat(64)
const OTHER_HASH = 'b'.repeat(64)

function clone(value) {
  return structuredClone(value)
}

function validConfig() {
  return {
    schema_version: '1.0.0',
    protocol: 'docker-database-lab-v1',
    runtime_path: process.platform === 'win32'
      ? 'C:\\Program Files\\Docker\\docker.exe'
      : '/usr/bin/docker',
    acknowledge_local_dynamic: true,
    limits: {
      wall_time_ms: 600_000,
      docker_command_timeout_ms: 30_000,
      startup_timeout_ms: 120_000,
      memory_bytes: 1_073_741_824,
      cpus: 2,
      pids: 256,
      nofile: 1024,
      tmpfs_bytes: 536_870_912,
      max_output_bytes: 8_388_608,
    },
  }
}

function validResult(engineId = 'postgresql-18.4') {
  const engine = databaseConformanceManifest.engines.find(
    ({ engine_id: candidate }) => candidate === engineId,
  )
  const now = '2026-07-30T14:00:00.000Z'
  return {
    schema_version: '1.0.0',
    protocol: 'docker-database-lab-v1',
    assurance_scope: 'CONTROLLER_OBSERVED_DISPOSABLE_ENGINE_BEHAVIOR',
    target_deployment_proven: false,
    run_id: 'db-lab:2026-07-30T14:00:00.000Z:abcdef123456',
    engine_id: engine.engine_id,
    adapter_id: engine.adapter_id,
    state: 'PASSED',
    started_at: now,
    completed_at: now,
    backend: {
      type: 'OCI_DOCKER',
      context: 'default',
      runtime_version: '29.5.3',
      requested_image: engine.image,
      image_id: `sha256:${HASH}`,
      repo_digests: [engine.image],
      platform: {
        os: 'linux',
        architecture: 'amd64',
      },
      container_name: 'rta-db-lab-abcdef123456-postgresql',
      container_id: HASH,
      security_profile: 'database-lab-v1',
    },
    server: {
      product: engine.product,
      version: engine.adapter_id === 'postgresql' ? '18.4' : '8.4.10',
    },
    scenarios: engine.scenario_rules.map((binding) => ({
      scenario_id: binding.scenario_id,
      state: 'PASSED',
      adapter_rule_ids: [...binding.adapter_rule_ids],
      checks: [{
        check_id: `${binding.scenario_id}.oracle`,
        state: 'PASSED',
        observation: 'Synthetic positive and negative controls matched.',
        evidence_sha256: HASH,
      }],
    })),
    transcript: [{
      step: 'synthetic.oracle',
      code: 0,
      stdout: 'ok',
      stderr: '',
    }],
    transcript_sha256:
      '8a7d805fd9956563e451e1ebfc8efbbb3c87634fd3831346f19d1f7720cae2e9',
    cleanup: {
      attempted: true,
      container_absent: true,
      verified_at: now,
    },
    gaps: [],
  }
}

function validRun(result = validResult()) {
  return {
    schema_version: '1.0.0',
    protocol: 'docker-database-lab-v1',
    tool: {
      name: 'red-team-audit-database-conformance',
      version: '0.7.0',
    },
    run_id: result.run_id,
    state: 'COMPLETE',
    capability_mode: 'LOCAL_DYNAMIC',
    assurance_scope: 'DISPOSABLE_REFERENCE_ENGINE_BEHAVIOR_ONLY',
    created_at: result.started_at,
    started_at: result.started_at,
    completed_at: result.completed_at,
    manifest: {
      path: 'manifest.json',
      sha256: HASH,
      size: 100,
    },
    requested_engine_ids: [result.engine_id],
    results: [{
      engine_id: result.engine_id,
      state: result.state,
      artifact: {
        path: `results/${result.engine_id}.json`,
        sha256: OTHER_HASH,
        size: 1000,
      },
    }],
    artifacts: [{
      path: 'manifest.json',
      sha256: HASH,
      size: 100,
    }, {
      path: `results/${result.engine_id}.json`,
      sha256: OTHER_HASH,
      size: 1000,
    }],
    root_sha256: HASH,
    gaps: [],
  }
}

function validEvidence() {
  const results = [
    validResult('mysql-8.4.10'),
    validResult('postgresql-18.4'),
  ]
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/database-conformance-evidence',
    assurance_scope: 'CONTROLLER_OBSERVED_DISPOSABLE_ENGINE_BEHAVIOR',
    target_deployment_proven: false,
    root_authenticity: 'UNANCHORED',
    source: {
      run_id: results[0].run_id,
      state: 'COMPLETE',
      root_sha256: HASH,
      created_at: results[0].started_at,
      completed_at: results[0].completed_at,
    },
    engines: results.map((result) => ({
      engine_id: result.engine_id,
      adapter_id: result.adapter_id,
      product: result.server.product,
      server_version: result.server.version,
      requested_image: result.backend.requested_image,
      image_id: result.backend.image_id,
      result_sha256: OTHER_HASH,
      state: 'PASSED',
      scenarios: result.scenarios.map((scenario) => ({
        scenario_id: scenario.scenario_id,
        state: scenario.state,
        adapter_rule_ids: [...scenario.adapter_rule_ids],
      })),
    })),
  }
}

test('the shipped conformance manifest binds two engines to all eight scenarios', () => {
  const validation = validateDatabaseConformanceManifest(databaseConformanceManifest)
  assert.deepEqual(validation.errors, [])
  assert.equal(databaseConformanceManifest.engines.length, 2)
  assert.equal(databaseConformanceManifest.scenarios.length, 8)
  for (const engine of databaseConformanceManifest.engines) {
    assert.equal(engine.scenario_rules.length, 8)
    assert.match(engine.image, /@sha256:[a-f0-9]{64}$/)
  }
})

test('manifest validation rejects mutable images and invented adapter rules', () => {
  const mutable = clone(databaseConformanceManifest)
  mutable.engines[0].image = 'postgres:18.4-bookworm'
  assert.equal(validateDatabaseConformanceManifest(mutable).valid, false)

  const invented = clone(databaseConformanceManifest)
  invented.engines[0].scenario_rules[0].adapter_rule_ids = [
    'db.authorization.postgresql.invented-rule',
  ]
  assert.ok(validateDatabaseConformanceManifest(invented).errors.some(
    ({ code }) => code === 'DATABASE_CONFORMANCE_UNKNOWN_ADAPTER_RULE',
  ))
})

test('trusted configuration requires explicit local-dynamic acknowledgement and bounded limits', () => {
  assert.equal(validateDatabaseConformanceConfig(validConfig()).valid, true)

  const relative = validConfig()
  relative.runtime_path = 'docker'
  assert.equal(validateDatabaseConformanceConfig(relative).valid, false)

  const noAcknowledgement = validConfig()
  noAcknowledgement.acknowledge_local_dynamic = false
  assert.equal(validateDatabaseConformanceConfig(noAcknowledgement).valid, false)

  const unbounded = validConfig()
  unbounded.limits.tmpfs_bytes = unbounded.limits.memory_bytes + 1
  assert.ok(validateDatabaseConformanceConfig(unbounded).errors.some(
    ({ code }) => code === 'DATABASE_CONFORMANCE_TMPFS_EXCEEDS_MEMORY',
  ))
})

test('result validation binds image, version, scenarios, rules, and derived states', () => {
  const result = validResult()
  assert.deepEqual(validateDatabaseConformanceResult(result).errors, [])

  const wrongImage = clone(result)
  wrongImage.backend.requested_image =
    `postgres@sha256:${'c'.repeat(64)}`
  assert.ok(validateDatabaseConformanceResult(wrongImage).errors.some(
    ({ code }) => code === 'DATABASE_CONFORMANCE_RESULT_IMAGE_MISMATCH',
  ))

  const wrongVersion = clone(result)
  wrongVersion.server.version = '17.10'
  assert.ok(validateDatabaseConformanceResult(wrongVersion).errors.some(
    ({ code }) => code === 'DATABASE_CONFORMANCE_SERVER_VERSION_DRIFT',
  ))

  const missingScenario = clone(result)
  missingScenario.scenarios.pop()
  assert.equal(validateDatabaseConformanceResult(missingScenario).valid, false)

  const forgedRule = clone(result)
  forgedRule.scenarios[0].adapter_rule_ids = [
    'db.authorization.postgresql.rls-bypass',
  ]
  assert.ok(validateDatabaseConformanceResult(forgedRule).errors.some(
    ({ code }) => code === 'DATABASE_CONFORMANCE_RESULT_RULE_DRIFT',
  ))
})

test('a failed check or ambiguous cleanup cannot be reported as passed', () => {
  const failedCheck = validResult()
  failedCheck.scenarios[0].checks[0].state = 'FAILED'
  assert.ok(validateDatabaseConformanceResult(failedCheck).errors.some(
    ({ code }) => code === 'DATABASE_CONFORMANCE_SCENARIO_STATE_MISMATCH',
  ))

  const cleanup = validResult()
  cleanup.cleanup.container_absent = false
  assert.ok(validateDatabaseConformanceResult(cleanup).errors.some(
    ({ code }) => code === 'DATABASE_CONFORMANCE_RESULT_STATE_MISMATCH',
  ))
})

test('terminal run state cannot overclaim missing or failed engine results', () => {
  const run = validRun()
  assert.deepEqual(validateDatabaseConformanceRun(run).errors, [])

  const missing = clone(run)
  missing.requested_engine_ids.push('mysql-8.4.10')
  assert.ok(validateDatabaseConformanceRun(missing).errors.some(
    ({ code }) => code === 'DATABASE_CONFORMANCE_COMPLETE_OVERCLAIM',
  ))

  const failed = clone(run)
  failed.results[0].state = 'FAILED'
  assert.ok(validateDatabaseConformanceRun(failed).errors.some(
    ({ code }) => code === 'DATABASE_CONFORMANCE_COMPLETE_OVERCLAIM',
  ))
})

test('attachable evidence cannot claim target proof or drift engine semantics', () => {
  const evidence = validEvidence()
  assert.equal(validateDatabaseConformanceEvidence(evidence).valid, true)

  const targetOverclaim = clone(evidence)
  targetOverclaim.target_deployment_proven = true
  assert.equal(validateDatabaseConformanceEvidence(targetOverclaim).valid, false)

  const duplicateEngine = clone(evidence)
  duplicateEngine.engines[1].engine_id = duplicateEngine.engines[0].engine_id
  assert.ok(validateDatabaseConformanceEvidence(duplicateEngine).errors.some(
    ({ code }) => code === 'DATABASE_CONFORMANCE_EVIDENCE_ENGINE_DRIFT',
  ))

  const ruleDrift = clone(evidence)
  ruleDrift.engines[0].scenarios[0].adapter_rule_ids = [
    'db.authorization.mysql.invented',
  ]
  assert.ok(validateDatabaseConformanceEvidence(ruleDrift).errors.some(
    ({ code }) => code === 'DATABASE_CONFORMANCE_EVIDENCE_RULE_DRIFT',
  ))
})
