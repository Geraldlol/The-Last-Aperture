import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { spawn, execFileSync } from 'node:child_process'
import { generateKeyPairSync } from 'node:crypto'
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { join, resolve } from 'node:path'

import { runProviderCommand } from '../scripts/audit.mjs'
import { runProviderBroker } from '../scripts/lib/provider-runner.mjs'
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

test('no version gate in scripts stops at 6.0.0', () => {
  const files = ['scripts/audit.mjs', 'scripts/lib/contracts.mjs',
    'scripts/lib/job-protocol.mjs', 'scripts/lib/attempts.mjs']
  const offenders = []
  for (const file of files) {
    const source = readFileSync(file, 'utf8')
    const pattern = /\[[^\]\n]*'6\.0\.0'[^\]\n]*\]/g
    for (const [array] of source.matchAll(pattern)) {
      if (!array.includes('7.0.0')) offenders.push(`${file}: ${array}`)
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

    execFileSync(
      process.execPath,
      [resolve('scripts/audit.mjs'), 'finalize', written.directory],
      { encoding: 'utf8' },
    )
    const finalRun = JSON.parse(await readFile(written.runPath, 'utf8'))
    assert.equal(finalRun.schema_version, '7.0.0')
    assert.equal(finalRun.phase, 'FINALIZED')
    assert.ok(['COMPLETED', 'COMPLETE_WITH_GAPS'].includes(finalRun.state))

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
