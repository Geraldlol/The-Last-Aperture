import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import {
  databaseConformanceReportPath,
  loadDatabaseConformanceEvidence,
  planDatabaseConformance,
  renderDatabaseConformanceReport,
  runDatabaseConformanceBundle,
  unlockDatabaseConformanceBundle,
  validateDatabaseConformanceBundle,
} from '../scripts/lib/database-conformance-controller.mjs'
import { databaseConformanceManifest } from '../scripts/lib/database-conformance-contracts.mjs'
import {
  conformanceCheck,
  scenarioResult,
} from '../scripts/lib/database-conformance-runner.mjs'
import {
  createRunPlan,
  writeRunPlanBundle,
} from '../scripts/lib/run-engine.mjs'
import { renderMarkdownReport } from '../scripts/lib/report.mjs'

async function temporaryParent(t) {
  const parent = await mkdtemp(join(tmpdir(), 'rta-database-lab-test-'))
  t.after(() => rm(parent, { recursive: true, force: true }))
  return parent
}

test('planning writes an immutable outside-project bundle that validates', async (t) => {
  const parent = await temporaryParent(t)
  const out = join(parent, 'bundle')
  const planned = await planDatabaseConformance({
    out,
    now: () => new Date('2026-07-30T14:00:00.000Z'),
    randomBytesImpl: () => Buffer.from('abcdef123456', 'hex'),
  })
  assert.equal(planned.directory, resolve(out))
  assert.equal(planned.run.state, 'PLANNED')
  assert.deepEqual(planned.run.requested_engine_ids, [
    'mysql-8.4.10',
    'postgresql-18.4',
  ])
  assert.deepEqual(planned.run.gaps, [])
  const validation = await validateDatabaseConformanceBundle(out)
  assert.deepEqual(validation.errors, [])
  assert.equal(validation.valid, true)
  assert.equal(validation.root_authenticity.status, 'UNANCHORED')
  await assert.rejects(
    databaseConformanceReportPath(out),
    /report has not been generated/,
  )
})

test('a subset plan preserves the omitted engine as a named gap', async (t) => {
  const parent = await temporaryParent(t)
  const planned = await planDatabaseConformance({
    out: join(parent, 'subset'),
    engineIds: ['postgresql-18.4'],
  })
  assert.deepEqual(planned.run.requested_engine_ids, ['postgresql-18.4'])
  assert.equal(planned.run.gaps.length, 1)
  assert.equal(planned.run.gaps[0].area, 'engine:mysql-8.4.10')
})

test('planning refuses to place a mutable execution bundle inside the project', async () => {
  await assert.rejects(
    planDatabaseConformance({
      out: resolve('database-conformance', 'forbidden-run'),
    }),
    /must be written outside the project tree/,
  )
})

test('planning rejects an external path whose ancestor aliases the project', async (t) => {
  const parent = await temporaryParent(t)
  const alias = join(parent, 'project-alias')
  try {
    await symlink(
      resolve('.'),
      alias,
      process.platform === 'win32' ? 'junction' : 'dir',
    )
  } catch (error) {
    if (process.platform === 'win32' && error.code === 'EPERM') {
      t.skip('creating a directory alias requires Windows developer mode')
      return
    }
    throw error
  }

  await assert.rejects(
    planDatabaseConformance({
      out: join(alias, 'database-conformance', 'aliased-forbidden-run'),
    }),
    /must be written outside the project tree/,
  )
})

test('validation detects a modified manifest artifact', async (t) => {
  const parent = await temporaryParent(t)
  const out = join(parent, 'tampered')
  await planDatabaseConformance({ out })
  const manifestPath = join(out, 'manifest.json')
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'))
  manifest.engines[0].product = 'Forged Database'
  await writeFile(manifestPath, `${JSON.stringify(manifest)}\n`)

  const validation = await validateDatabaseConformanceBundle(out)
  assert.equal(validation.valid, false)
  assert.ok(validation.errors.some(
    ({ code }) => code === 'DATABASE_CONFORMANCE_ARTIFACT_DIGEST_MISMATCH',
  ))
})

function trustedConfig() {
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

function fakeEngineResult({ runId, engineId, failed = false }) {
  const selected = databaseConformanceManifest.engines.find(
    ({ engine_id: candidate }) => candidate === engineId,
  )
  const scenarios = selected.scenario_rules.map((binding, index) =>
    scenarioResult(binding, [
      conformanceCheck(
        `${binding.scenario_id}.oracle`,
        failed && index === 0 ? 'FAILED' : 'PASSED',
        failed && index === 0
          ? 'Synthetic negative control did not deny.'
          : 'Synthetic positive and negative controls matched.',
      ),
    ]))
  return {
    schema_version: '1.0.0',
    protocol: 'docker-database-lab-v1',
    assurance_scope: 'CONTROLLER_OBSERVED_DISPOSABLE_ENGINE_BEHAVIOR',
    target_deployment_proven: false,
    run_id: runId,
    engine_id: engineId,
    adapter_id: selected.adapter_id,
    state: failed ? 'FAILED' : 'PASSED',
    started_at: '2026-07-30T14:00:00.000Z',
    completed_at: '2026-07-30T14:00:00.000Z',
    backend: {
      type: 'OCI_DOCKER',
      context: 'default',
      runtime_version: '29.5.3',
      requested_image: selected.image,
      image_id: `sha256:${'a'.repeat(64)}`,
      repo_digests: [selected.image],
      platform: {
        os: 'linux',
        architecture: 'amd64',
      },
      container_name: `rta-db-lab-abcdef123456-${selected.adapter_id}`,
      container_id: 'b'.repeat(64),
      security_profile: 'database-lab-v1',
    },
    server: {
      product: selected.product,
      version: selected.adapter_id === 'postgresql' ? '18.4' : '8.4.10',
    },
    scenarios,
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
      verified_at: '2026-07-30T14:00:00.000Z',
    },
    gaps: [],
  }
}

test('a complete two-engine run writes durable results, report, and root manifest', async (t) => {
  const parent = await temporaryParent(t)
  const out = join(parent, 'complete')
  await planDatabaseConformance({
    out,
    now: () => new Date('2026-07-30T14:00:00.000Z'),
    randomBytesImpl: () => Buffer.from('abcdef123456', 'hex'),
  })
  const run = await runDatabaseConformanceBundle({
    bundle: out,
    config: trustedConfig(),
    now: () => new Date('2026-07-30T14:00:00.000Z'),
    runEngineImpl: async ({ runId, engineId }) =>
      fakeEngineResult({ runId, engineId }),
  })
  assert.equal(run.state, 'COMPLETE')
  assert.equal(run.results.length, 2)
  assert.equal(run.artifacts.length, 4)
  assert.match(run.root_sha256, /^[a-f0-9]{64}$/)

  const validation = await validateDatabaseConformanceBundle(out)
  assert.deepEqual(validation.errors, [])
  const reportPath = await databaseConformanceReportPath(out)
  const report = await readFile(reportPath, 'utf8')
  assert.match(report, /PostgreSQL 18\.4/)
  assert.match(report, /MySQL 8\.4\.10/)
  assert.match(report, /Reference-engine behavior is not target deployment proof/)
  const evidence = await loadDatabaseConformanceEvidence(out)
  assert.equal(evidence.target_deployment_proven, false)
  assert.equal(evidence.root_authenticity, 'UNANCHORED')
  assert.deepEqual(
    evidence.engines.map(({ engine_id: engineId }) => engineId),
    ['mysql-8.4.10', 'postgresql-18.4'],
  )

  const target = join(parent, 'audit-target')
  await mkdir(target)
  await writeFile(join(target, 'package.json'), '{"name":"audit-target"}\n')
  const auditPlan = await createRunPlan({
    targetRoot: target,
    databaseConformanceEvidence: evidence,
  })
  const written = await writeRunPlanBundle(
    auditPlan,
    join(parent, 'audit-runs'),
  )
  assert.equal(auditPlan.run.schema_version, '6.0.0')
  assert.deepEqual(auditPlan.run.database_conformance, evidence)
  assert.equal(
    JSON.parse(await readFile(
      join(written.directory, 'database-conformance.json'),
      'utf8',
    )).source.root_sha256,
    run.root_sha256,
  )
  assert.match(
    renderMarkdownReport(auditPlan.run),
    /They do not elevate any target finding, proof tier/,
  )
  const cliSummary = JSON.parse(execFileSync(
    process.execPath,
    [
      resolve('scripts/audit.mjs'),
      'plan',
      target,
      '--out',
      join(parent, 'cli-audit-runs'),
      '--database-conformance',
      out,
      '--json',
    ],
    {
      encoding: 'utf8',
      windowsHide: true,
    },
  ))
  const cliRun = JSON.parse(await readFile(
    join(cliSummary.bundle, 'run.json'),
    'utf8',
  ))
  assert.deepEqual(cliRun.database_conformance, evidence)
  assert.match(execFileSync(
    process.execPath,
    [resolve('scripts/audit.mjs'), 'validate', cliSummary.bundle],
    {
      encoding: 'utf8',
      windowsHide: true,
    },
  ), /Root authenticity: UNANCHORED/)
  await assert.rejects(
    runDatabaseConformanceBundle({
      bundle: out,
      config: trustedConfig(),
      runEngineImpl: async () => {
        throw new Error('must not execute')
      },
    }),
    /already COMPLETE/,
  )
})

test('an engine oracle failure is durable FAILED evidence, not an aborted run', async (t) => {
  const parent = await temporaryParent(t)
  const out = join(parent, 'failed')
  await planDatabaseConformance({
    out,
    engineIds: ['postgresql-18.4'],
    now: () => new Date('2026-07-30T14:00:00.000Z'),
    randomBytesImpl: () => Buffer.from('abcdef123456', 'hex'),
  })
  const run = await runDatabaseConformanceBundle({
    bundle: out,
    config: {
      ...trustedConfig(),
      engine_ids: ['postgresql-18.4'],
    },
    now: () => new Date('2026-07-30T14:00:00.000Z'),
    runEngineImpl: async ({ runId, engineId }) =>
      fakeEngineResult({ runId, engineId, failed: true }),
  })
  assert.equal(run.state, 'FAILED')
  assert.equal(run.results[0].state, 'FAILED')
  assert.equal((await validateDatabaseConformanceBundle(out)).valid, true)
  await assert.rejects(
    loadDatabaseConformanceEvidence(out),
    /only a COMPLETE two-engine conformance run may be attached/,
  )
})

test('an infrastructure failure finalizes an auditable ABORTED bundle', async (t) => {
  const parent = await temporaryParent(t)
  const out = join(parent, 'aborted')
  await planDatabaseConformance({
    out,
    engineIds: ['postgresql-18.4'],
    now: () => new Date('2026-07-30T14:00:00.000Z'),
    randomBytesImpl: () => Buffer.from('abcdef123456', 'hex'),
  })
  await assert.rejects(
    runDatabaseConformanceBundle({
      bundle: out,
      config: {
        ...trustedConfig(),
        engine_ids: ['postgresql-18.4'],
      },
      now: () => new Date('2026-07-30T14:00:00.000Z'),
      runEngineImpl: async () => {
        throw Object.assign(new Error('Docker daemon unavailable'), {
          code: 'DATABASE_CONFORMANCE_DOCKER_UNAVAILABLE',
        })
      },
    }),
    /run aborted/,
  )
  const persisted = JSON.parse(await readFile(join(out, 'run.json'), 'utf8'))
  assert.equal(persisted.state, 'ABORTED')
  assert.match(persisted.gaps.at(-1).reason, /Docker daemon unavailable/)
  assert.equal((await validateDatabaseConformanceBundle(out)).valid, true)
})

test('a bundle lock rejects concurrent execution and is released afterward', async (t) => {
  const parent = await temporaryParent(t)
  const out = join(parent, 'locked')
  await planDatabaseConformance({
    out,
    engineIds: ['postgresql-18.4'],
  })
  let releaseEngine
  let signalStarted
  const started = new Promise((resolveStarted) => {
    signalStarted = resolveStarted
  })
  const first = runDatabaseConformanceBundle({
    bundle: out,
    config: {
      ...trustedConfig(),
      engine_ids: ['postgresql-18.4'],
    },
    runEngineImpl: async ({ runId, engineId }) => {
      signalStarted()
      await new Promise((resolveEngine) => {
        releaseEngine = resolveEngine
      })
      return fakeEngineResult({ runId, engineId })
    },
  })
  await started
  await assert.rejects(
    runDatabaseConformanceBundle({
      bundle: out,
      config: {
        ...trustedConfig(),
        engine_ids: ['postgresql-18.4'],
      },
      runEngineImpl: async () => {
        throw new Error('must not execute')
      },
    }),
    /already locked/,
  )
  releaseEngine()
  assert.equal((await first).state, 'COMPLETE_WITH_GAPS')
  assert.equal((await validateDatabaseConformanceBundle(out)).valid, true)
})

test('stale lock recovery refuses live owners and removes only an unchanged dead lock', async (t) => {
  const parent = await temporaryParent(t)
  const out = join(parent, 'stale-lock')
  await planDatabaseConformance({ out })
  const lockPath = join(out, '.database-conformance.lock')
  const lockRecord = (pid) => `${JSON.stringify({
    schema_version: '1.0.0',
    pid,
    acquired_at: '2026-07-30T14:00:00.000Z',
    nonce: 'a'.repeat(32),
  })}\n`

  await writeFile(lockPath, lockRecord(process.pid), { flag: 'wx' })
  await assert.rejects(
    unlockDatabaseConformanceBundle(out),
    /still active/,
  )
  await rm(lockPath)

  await writeFile(lockPath, lockRecord(2_147_483_647), { flag: 'wx' })
  const unlocked = await unlockDatabaseConformanceBundle(out)
  assert.equal(unlocked.removed_pid, 2_147_483_647)
  await assert.rejects(readFile(lockPath), /ENOENT/)
})

test('lab Markdown neutralizes engine and failure text', () => {
  const result = fakeEngineResult({
    runId: 'db-lab:2026-07-30T14:00:00.000Z:abcdef123456',
    engineId: 'postgresql-18.4',
  })
  result.server.version = '18.4 | <script>alert(1)</script>'
  const report = renderDatabaseConformanceReport({
    run_id: result.run_id,
    state: 'FAILED',
    gaps: [{
      area: 'failure | area',
      reason: '<img src=x onerror=alert(1)>',
    }],
  }, [result])
  assert.doesNotMatch(report, /<script>|<img/)
  assert.match(report, /18\.4 &#124; &lt;script&gt;/)
  assert.match(report, /failure &#124; area/)
})
