import { after, before, test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { spawn, execFileSync, spawnSync } from 'node:child_process'
import { generateKeyPairSync } from 'node:crypto'
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { join, resolve } from 'node:path'

import { runProviderCommand } from '../scripts/audit.mjs'
import { leaseProviderAttempt } from '../scripts/lib/attempts.mjs'
import { runProviderBroker } from '../scripts/lib/provider-runner.mjs'
import { hashAttemptEvent, validateRun } from '../scripts/lib/contracts.mjs'
import {
  createRunPlan,
  stableJson,
  writeRunPlanBundle,
} from '../scripts/lib/run-engine.mjs'

const SHA_A = 'a'.repeat(64)
const ADAPTER_PATH = fileURLToPath(new URL(
  '../providers/reference-byte-consumer/adapter.mjs',
  import.meta.url,
))
const NODE_24_REQUIRED = Number(process.versions.node.split('.')[0]) < 24
  ? 'observed runner requires Node.js 24+'
  : false

function providerConfig(runtimePath, signingKeyPath) {
  return {
    schema_version: '1.0.0',
    protocol: 'docker-stdio-v1',
    runtime_path: runtimePath,
    image: `sha256:${SHA_A}`,
    receipt_signing_private_key_path: signingKeyPath,
    limits: {
      wall_time_ms: 30_000,
      docker_command_timeout_ms: 10_000,
      idle_timeout_ms: 10_000,
      delivery_timeout_ms: 10_000,
      max_deliveries: 256,
      max_file_bytes: 1024 * 1024,
      max_total_delivery_bytes: 32 * 1024 * 1024,
      max_stdout_bytes: 8 * 1024 * 1024,
      max_stderr_bytes: 1024 * 1024,
      max_frame_bytes: 2 * 1024 * 1024,
      memory_bytes: 128 * 1024 * 1024,
      cpus: 0.5,
      pids: 32,
      nofile: 64,
      tmpfs_bytes: 16 * 1024 * 1024,
    },
  }
}

async function runReferenceProvider({ config, packet, artifacts, containerName }) {
  const child = spawn(process.execPath, [ADAPTER_PATH], {
    shell: false,
    windowsHide: true,
    stdio: ['pipe', 'pipe', 'pipe'],
  })
  const stderr = []
  child.stderr.on('data', (chunk) => stderr.push(Buffer.from(chunk)))
  const exitPromise = new Promise((resolveExit, rejectExit) => {
    child.once('error', rejectExit)
    child.once('close', (code, signal) => resolveExit({ code, signal }))
  })
  let execution
  try {
    execution = await runProviderBroker({
      readable: child.stdout,
      writable: child.stdin,
      packet,
      artifacts,
      config,
      backend: {
        type: 'OCI_DOCKER',
        runtime_path: config.runtime_path,
        runtime_version: process.version,
        context: 'default',
        image: config.image,
        container_name: containerName,
        container_id: SHA_A,
        security_profile: 'builtin',
      },
    })
  } finally {
    child.stdin.end()
  }
  const exit = await exitPromise
  assert.deepEqual(
    exit,
    { code: 0, signal: null },
    Buffer.concat(stderr).toString('utf8'),
  )
  return execution
}

test('run schema admits 7.0.0', () => {
  const schema = JSON.parse(readFileSync('schemas/run.schema.json', 'utf8'))
  assert.ok(schema.properties.schema_version.enum.includes('7.0.0'))
})

test('run schema declares existence_verifications', () => {
  const schema = JSON.parse(readFileSync('schemas/run.schema.json', 'utf8'))
  assert.ok(schema.properties.existence_verifications)
})

function walkFiles(dir, predicate, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) walkFiles(full, predicate, out)
    else if (predicate(entry.name)) out.push(full)
  }
  return out
}

function collectVersionEnums(node, path, out) {
  if (Array.isArray(node)) {
    node.forEach((v, i) => collectVersionEnums(v, `${path}[${i}]`, out))
    return
  }
  if (node && typeof node === 'object') {
    for (const [key, value] of Object.entries(node)) {
      if (
        key === 'enum'
        && Array.isArray(value)
        && value.some((entry) => typeof entry === 'string' && /^\d+\.0\.0$/.test(entry))
      ) {
        out.push({ path: `${path}.${key}`, values: value })
      }
      collectVersionEnums(value, `${path}.${key}`, out)
    }
  }
}

test('every schema version enum that reaches 6.0.0 also reaches 7.0.0', () => {
  const files = walkFiles('schemas', (name) => name.endsWith('.json'))
  assert.ok(files.length > 0, 'expected to find schema files under schemas/')
  const offenders = []
  for (const file of files) {
    const doc = JSON.parse(readFileSync(file, 'utf8'))
    const enums = []
    collectVersionEnums(doc, '$', enums)
    for (const { path, values } of enums) {
      if (values.includes('6.0.0') && !values.includes('7.0.0')) {
        offenders.push(`${file}${path.slice(1)}: ${JSON.stringify(values)}`)
      }
    }
  }
  assert.deepEqual(offenders, [])
})

test('no version gate anywhere in scripts stops at 6.0.0, array or equality form', () => {
  const files = walkFiles('scripts', (name) => name.endsWith('.mjs'))
  assert.ok(files.length > 0, 'expected to find .mjs files under scripts/')
  const offenders = []
  for (const file of files) {
    const source = readFileSync(file, 'utf8')

    // Array/Set-literal membership gates, tolerant of arrays wrapped across lines.
    const arrayPattern = /\[[^\]]*'6\.0\.0'[^\]]*\]/g
    for (const [array] of source.matchAll(arrayPattern)) {
      if (!array.includes('7.0.0')) {
        offenders.push(`${file}: array gate stops at 6.0.0 -> ${array}`)
      }
    }

    // Equality/inequality gates, e.g. `run.schema_version === '6.0.0'`.
    const equalityPattern = /[!=]==\s*'6\.0\.0'/g
    for (const match of source.matchAll(equalityPattern)) {
      const lineStart = source.lastIndexOf('\n', match.index) + 1
      const nextNewline = source.indexOf('\n', match.index)
      const lineEnd = nextNewline === -1 ? source.length : nextNewline
      const line = source.slice(lineStart, lineEnd).trim()
      if (!line.includes('7.0.0')) {
        offenders.push(`${file}: equality gate stops at 6.0.0 -> ${line}`)
      }
    }
  }
  assert.deepEqual(offenders, [])
})

test('a 7.0.0 run survives plan through finalize to a terminal state', {
  skip: NODE_24_REQUIRED,
  timeout: 120_000,
}, async () => {
  const root = await mkdtemp(join(tmpdir(), 'rta-existence-schema-target-'))
  const output = await mkdtemp(join(tmpdir(), 'rta-existence-schema-output-'))
  try {
    await mkdir(join(root, 'docs'))
    await writeFile(
      join(root, 'docs', 'notes.txt'),
      'A small inert text fixture with no executable application surface.\n',
    )
    const plan = await createRunPlan({
      targetRoot: root,
      lensDirectory: resolve('skills/red-team-audit/lenses'),
      sealSource: true,
      createdAt: new Date('2026-08-03T09:00:00.000Z'),
    })
    assert.equal(plan.run.schema_version, '7.0.0')
    const written = await writeRunPlanBundle(plan, join(output, 'bundles'))

    const { privateKey } = generateKeyPairSync('ed25519')
    const signingKeyPath = join(output, 'receipt-signing-key.pem')
    const configPath = join(output, 'provider-config.json')
    await writeFile(
      signingKeyPath,
      privateKey.export({ type: 'pkcs8', format: 'pem' }),
      { mode: 0o600 },
    )
    await writeFile(
      configPath,
      stableJson(providerConfig(process.execPath, signingKeyPath)),
    )

    let executions = 0
    while (executions < 64) {
      const run = JSON.parse(await readFile(written.runPath, 'utf8'))
      const pendingProviderWork = run.jobs.some(({ kind, state }) => (
        state === 'PENDING'
        && ['LENS', 'TRIAGE', 'PROOF', 'COMPLETENESS'].includes(kind)
      ))
      if (!pendingProviderWork) break
      await runProviderCommand(
        [written.directory, configPath],
        {},
        { providerRunner: runReferenceProvider },
      )
      executions += 1
    }
    assert.ok(executions > 0 && executions < 64)

    const readyRun = await readFile(written.runPath, 'utf8')
    const lockPath = `${written.runPath}.lock`
    await writeFile(lockPath, stableJson({
      pid: process.pid,
      created_at: new Date().toISOString(),
      token: 'finalize-race-regression-lock-token',
    }))
    const lockedFinalize = spawnSync(
      process.execPath,
      [resolve('scripts/audit.mjs'), 'finalize', written.directory],
      { encoding: 'utf8' },
    )
    assert.equal(lockedFinalize.status, 1)
    assert.match(lockedFinalize.stderr, /run is locked/i)
    assert.equal(await readFile(written.runPath, 'utf8'), readyRun)
    for (const artifact of ['coverage.json', 'report.md', 'results.sarif']) {
      await assert.rejects(readFile(join(written.directory, artifact)), { code: 'ENOENT' })
    }
    await rm(lockPath)

    const conflictingReportPath = join(written.directory, 'report.md')
    await writeFile(conflictingReportPath, 'stale conflicting report\n')
    const conflictingFinalize = spawnSync(
      process.execPath,
      [resolve('scripts/audit.mjs'), 'finalize', written.directory],
      { encoding: 'utf8' },
    )
    assert.equal(conflictingFinalize.status, 1)
    assert.match(conflictingFinalize.stderr, /conflicting artifact report\.md/i)
    assert.equal(await readFile(written.runPath, 'utf8'), readyRun)
    assert.equal(await readFile(conflictingReportPath, 'utf8'), 'stale conflicting report\n')
    for (const artifact of ['coverage.json', 'results.sarif']) {
      await assert.rejects(readFile(join(written.directory, artifact)), { code: 'ENOENT' })
    }
    await rm(conflictingReportPath)

    execFileSync(
      process.execPath,
      [resolve('scripts/audit.mjs'), 'finalize', written.directory],
      { encoding: 'utf8' },
    )
    const finalRun = JSON.parse(await readFile(written.runPath, 'utf8'))
    assert.equal(finalRun.schema_version, '7.0.0')
    assert.equal(finalRun.phase, 'FINALIZED')
    assert.ok(['COMPLETED', 'COMPLETE_WITH_GAPS'].includes(finalRun.state))

    const committedReport = await readFile(join(written.directory, 'report.md'), 'utf8')
    await rm(join(written.directory, 'report.md'))
    const repaired = execFileSync(
      process.execPath,
      [resolve('scripts/audit.mjs'), 'finalize', written.directory],
      { encoding: 'utf8' },
    )
    assert.match(repaired, /Verified final artifacts/)
    assert.equal(
      await readFile(join(written.directory, 'report.md'), 'utf8'),
      committedReport,
    )

    const validation = execFileSync(
      process.execPath,
      [resolve('scripts/audit.mjs'), 'validate', written.directory],
      { encoding: 'utf8' },
    )
    assert.match(validation, /^VALID:/)
  } finally {
    await rm(root, { recursive: true, force: true })
    await rm(output, { recursive: true, force: true })
  }
})

let existenceFixtureRoot
let existenceBaseRun

before(async () => {
  existenceFixtureRoot = await mkdtemp(join(tmpdir(), 'rta-existence-verifications-'))
  await mkdir(join(existenceFixtureRoot, 'docs'), { recursive: true })
  await writeFile(
    join(existenceFixtureRoot, 'docs', 'notes.txt'),
    'A small inert text fixture with no executable application surface.\n',
  )
  const plan = await createRunPlan({
    targetRoot: existenceFixtureRoot,
    lensDirectory: resolve('skills/red-team-audit/lenses'),
    sealSource: true,
    createdAt: new Date('2026-08-03T10:00:00.000Z'),
  })
  existenceBaseRun = plan.run
})

after(async () => {
  if (existenceFixtureRoot) await rm(existenceFixtureRoot, { recursive: true, force: true })
})

function sampleExistenceVerification() {
  return {
    candidate_id: 'authz-object-level:sample',
    outcome: 'NOT_APPLICABLE',
    quote_results: [],
    absence_results: [],
  }
}

test('a 7.0.0 run carrying existence_verifications validates', () => {
  const run = structuredClone(existenceBaseRun)
  assert.equal(run.schema_version, '7.0.0')
  run.existence_verifications = [sampleExistenceVerification()]
  const validation = validateRun(run)
  assert.equal(validation.valid, true, JSON.stringify(validation.errors, null, 2))
})

test('a 6.0.0 run carrying existence_verifications does not validate', () => {
  const run = structuredClone(existenceBaseRun)
  run.schema_version = '6.0.0'
  run.existence_verifications = [sampleExistenceVerification()]
  const validation = validateRun(run)
  assert.equal(validation.valid, false)
  assert.ok(
    validation.errors.some(({ code, instancePath }) =>
      code === 'SCHEMA_ENUM' && instancePath === '/schema_version'),
    `expected a SCHEMA_ENUM error on /schema_version; received:\n${
      JSON.stringify(validation.errors, null, 2)}`,
  )
})

test('a 6.0.0 run without existence_verifications still validates', () => {
  const run = structuredClone(existenceBaseRun)
  run.schema_version = '6.0.0'
  assert.equal('existence_verifications' in run, false)
  const validation = validateRun(run)
  assert.equal(validation.valid, true, JSON.stringify(validation.errors, null, 2))
})

test('a LEASED attempt without a declared backend is rejected; with one it is not', () => {
  const base = structuredClone(existenceBaseRun)
  const leased = leaseProviderAttempt(base, 'lens:ai-generated-code', {
    attempt_id: 'attempt:existence-backend-test-0001',
    occurred_at: '2026-08-03T10:05:00Z',
    expires_at: '2026-08-03T10:06:00Z',
    nonce: 'a'.repeat(64),
    packet_sha256: 'b'.repeat(64),
    provider_config_sha256: 'c'.repeat(64),
    sandbox_policy_sha256: 'd'.repeat(64),
    container_name: 'rta-existence-backend-test',
    budgets: {
      wall_clock_ms: 30_000,
      max_requests: 10,
      max_bytes: 1024,
    },
  })
  assert.equal(leased.attempt_events.at(-1).backend, 'SEALED_CONTAINER')
  assert.equal(
    validateRun(leased).errors.some(({ code }) => code === 'ATTEMPT_BACKEND_MISSING'),
    false,
  )

  const stripped = structuredClone(leased)
  const event = stripped.attempt_events.at(-1)
  delete event.backend
  event.event_sha256 = hashAttemptEvent(event)
  assert.ok(
    validateRun(stripped).errors.some(({ code }) => code === 'ATTEMPT_BACKEND_MISSING'),
    `expected ATTEMPT_BACKEND_MISSING; received:\n${
      JSON.stringify(validateRun(stripped).errors, null, 2)}`,
  )
})
