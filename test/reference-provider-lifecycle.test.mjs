import { spawn, execFileSync } from 'node:child_process'
import { generateKeyPairSync } from 'node:crypto'
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { join, resolve } from 'node:path'
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { runProviderCommand } from '../scripts/audit.mjs'
import { runProviderBroker } from '../scripts/lib/provider-runner.mjs'
import { renderMarkdownReport } from '../scripts/lib/report.mjs'
import {
  createRunPlan,
  stableJson,
  writeRunPlanBundle,
} from '../scripts/lib/run-engine.mjs'

const SHA_A = 'a'.repeat(64)
const SHA_B = 'b'.repeat(64)
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
        container_id: SHA_B,
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

test('reference provider drives a sealed no-candidate run through the full observed lifecycle', {
  skip: NODE_24_REQUIRED,
  timeout: 120_000,
}, async () => {
  const root = await mkdtemp(join(tmpdir(), 'rta-reference-lifecycle-target-'))
  const output = await mkdtemp(join(tmpdir(), 'rta-reference-lifecycle-output-'))
  try {
    await mkdir(join(root, 'docs'))
    await writeFile(
      join(root, 'docs', 'notes.txt'),
      'A small inert text fixture with no executable application surface.\n',
    )
    const plan = await createRunPlan({
      targetRoot: root,
      lensDirectory: resolve('skills/last-aperture/lenses'),
      sealSource: true,
      createdAt: new Date('2026-07-29T09:00:00.000Z'),
    })
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
    assert.ok(executions > 2 && executions < 64)

    const beforeFinalize = JSON.parse(await readFile(written.runPath, 'utf8'))
    assert.equal(beforeFinalize.phase, 'COMPLETENESS')
    assert.equal(
      beforeFinalize.jobs
        .filter(({ kind }) => ['LENS', 'TRIAGE', 'COMPLETENESS'].includes(kind))
        .every(({ state }) => ['SUCCEEDED', 'SKIPPED'].includes(state)),
      true,
    )
    assert.equal(beforeFinalize.findings.length, 0)

    execFileSync(
      process.execPath,
      [resolve('scripts/audit.mjs'), 'finalize', written.directory],
      { encoding: 'utf8' },
    )
    const finalRun = JSON.parse(await readFile(written.runPath, 'utf8'))
    assert.equal(finalRun.state, 'COMPLETE_WITH_GAPS')
    assert.equal(finalRun.phase, 'FINALIZED')
    assert.equal(finalRun.findings.length, 0)
    assert.equal(
      finalRun.jobs
        .filter(({ kind, state }) => (
          state === 'SUCCEEDED'
          && ['LENS', 'TRIAGE', 'COMPLETENESS'].includes(kind)
        ))
        .every(
          ({ coverage_authority: authority }) =>
            authority === 'CONTROLLER_OBSERVED_CONSUMPTION',
        ),
      true,
    )
    assert.match(renderMarkdownReport(finalRun), /NO_FINDINGS_REPORTED/)
    assert.ok(
      finalRun.coverage.gaps.some(({ reason }) =>
        /performs no semantic vulnerability analysis/.test(reason)),
    )
  } finally {
    await rm(root, { recursive: true, force: true })
    await rm(output, { recursive: true, force: true })
  }
})
