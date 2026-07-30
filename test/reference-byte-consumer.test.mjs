import { spawn } from 'node:child_process'
import assert from 'node:assert/strict'
import { fileURLToPath } from 'node:url'
import { test } from 'node:test'
import { runProviderBroker } from '../scripts/lib/provider-runner.mjs'
import {
  providerArtifacts,
  providerBackend,
  providerConfig,
  providerPacket,
} from './helpers/provider-fixtures.mjs'

const ADAPTER_PATH = fileURLToPath(new URL(
  '../providers/reference-byte-consumer/adapter.mjs',
  import.meta.url,
))

function deterministicRandomSource() {
  let call = 0
  return (size) => {
    call += 1
    const bytes = Buffer.alloc(size, 0x5a)
    bytes.writeUInt32BE(call, Math.max(0, size - 4))
    return bytes
  }
}

async function runReferenceAdapter(packet) {
  const child = spawn(process.execPath, [ADAPTER_PATH], {
    shell: false,
    windowsHide: true,
    stdio: ['pipe', 'pipe', 'pipe'],
  })
  const stderr = []
  child.stderr.on('data', (chunk) => stderr.push(Buffer.from(chunk)))
  const exitPromise = new Promise((resolve, reject) => {
    child.once('error', reject)
    child.once('close', (code, signal) => resolve({ code, signal }))
  })

  let execution
  try {
    execution = await runProviderBroker({
      readable: child.stdout,
      writable: child.stdin,
      packet,
      artifacts: providerArtifacts(),
      config: providerConfig(),
      backend: providerBackend(),
      randomBytesImpl: deterministicRandomSource(),
    })
  } finally {
    child.stdin.end()
  }

  const exit = await exitPromise
  const stderrText = Buffer.concat(stderr).toString('utf8')
  assert.deepEqual(
    exit,
    { code: 0, signal: null },
    `reference adapter exited unexpectedly: ${stderrText}`,
  )
  assert.equal(stderrText, '')
  return execution
}

function assertBothArtifactsConsumed(execution) {
  assert.equal(execution.receipt.semantic_analysis_proven, false)
  assert.equal(
    execution.receipt.receipt_scope,
    'BYTE_DELIVERY_AND_CHALLENGE_CONSUMPTION_ONLY',
  )
  assert.deepEqual(
    execution.receipt.deliveries.map((delivery) => ({
      kind: delivery.artifact_kind,
      logicalName: delivery.logical_name,
      states: delivery.events.map(({ state }) => state),
    })),
    [
      {
        kind: 'FILE',
        logicalName: 'src/app.js',
        states: ['DELIVERED', 'CONSUMED'],
      },
      {
        kind: 'CONTROL',
        logicalName: 'lens:web-and-api@1.0.0',
        states: ['DELIVERED', 'CONSUMED'],
      },
    ],
  )
  for (const delivery of execution.receipt.deliveries) {
    const consumed = delivery.events[1]
    assert.match(consumed.challenge_hmac_sha256, /^[a-f0-9]{64}$/)
    assert.equal(consumed.hmac_algorithm, 'HMAC-SHA256')
  }
}

test('reference adapter consumes FILE and CONTROL bytes but reports its semantic coverage gap', async () => {
  const execution = await runReferenceAdapter(providerPacket())

  assertBothArtifactsConsumed(execution)
  assert.equal(execution.job_result.state, 'SUCCEEDED')
  assert.deepEqual(execution.job_result.examined_files, ['src/app.js'])
  assert.deepEqual(execution.job_result.findings, [])
  assert.deepEqual(execution.job_result.coverage_gaps, [{
    area: 'lens:web-and-api',
    reason:
      'reference-byte-consumer verifies broker conformance only and performs no semantic vulnerability analysis',
  }])
  assert.equal(execution.job_result.error, undefined)
})

test('reference adapter can close an empty triage denominator without making a semantic claim', async () => {
  const execution = await runReferenceAdapter(providerPacket({
    job_id: 'triage:all',
    kind: 'TRIAGE',
    findings: [],
  }))

  assertBothArtifactsConsumed(execution)
  assert.equal(execution.job_result.state, 'SUCCEEDED')
  assert.deepEqual(execution.job_result.findings, [])
  assert.equal(execution.job_result.coverage_gaps.length, 1)
  assert.match(
    execution.job_result.coverage_gaps[0].reason,
    /performs no semantic vulnerability analysis/,
  )
})

test('reference adapter fails closed for semantic job kinds', async (t) => {
  const cases = [
    {
      name: 'triage',
      packet: providerPacket({
        job_id: 'triage:all',
        kind: 'TRIAGE',
        findings: [{ candidate_id: 'candidate:requires-semantic-triage' }],
      }),
    },
    {
      name: 'proof',
      packet: providerPacket({
        job_id: 'proof:finding-1',
        kind: 'PROOF',
      }),
    },
    {
      name: 'database lens',
      packet: providerPacket({
        job_id: 'lens:database-and-data-stores',
        kind: 'LENS',
        lens: 'database-and-data-stores',
      }),
    },
  ]

  for (const { name, packet } of cases) {
    await t.test(name, async () => {
      const execution = await runReferenceAdapter(packet)

      assertBothArtifactsConsumed(execution)
      assert.equal(execution.job_result.state, 'FAILED')
      assert.deepEqual(execution.job_result.findings, [])
      assert.deepEqual(execution.job_result.error, {
        code: 'REFERENCE_ADAPTER_NO_SEMANTIC_ANALYZER',
        message:
          'this reference adapter cannot triage findings, prove findings, or inventory database semantics',
        recoverable: false,
      })
      assert.equal(execution.job_result.coverage_gaps.length, 1)
      assert.match(
        execution.job_result.coverage_gaps[0].reason,
        /performs no semantic vulnerability analysis/,
      )
    })
  }
})
