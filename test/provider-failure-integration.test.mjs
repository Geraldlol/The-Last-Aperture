import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign as signBytes,
} from 'node:crypto'
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  runProviderCommand,
  verifyControlBundle,
} from '../scripts/audit.mjs'
import {
  failProviderAttempt,
  hashAttemptEvent,
  leaseProviderAttempt,
  markProviderAttemptStarted,
  recordProviderResultCaptured,
  recordProviderResultValidated,
} from '../scripts/lib/attempts.mjs'
import {
  createRunPlan,
  stableJson,
  writeRunPlanBundle,
} from '../scripts/lib/run-engine.mjs'
import { buildDockerCreateArgs } from '../scripts/lib/provider-runner.mjs'

const SHA_A = 'a'.repeat(64)
const SHA_B = 'b'.repeat(64)
const SHA_C = 'c'.repeat(64)
const NODE_24_REQUIRED = Number(process.versions.node.split('.')[0]) < 24
  ? 'observed runner requires Node.js 24+'
  : false

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function controllerKeyId(key) {
  const spki = createPublicKey(key).export({
    type: 'spki',
    format: 'der',
  })
  return `ed25519:${sha256(spki)}`
}

function providerConfigBindingSha256(config, keyId) {
  return sha256(stableJson({
    provider_config: config,
    receipt_signing_key_id: keyId,
  }, 0))
}

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
      max_deliveries: 100,
      max_file_bytes: 1024 * 1024,
      max_total_delivery_bytes: 16 * 1024 * 1024,
      max_stdout_bytes: 4 * 1024 * 1024,
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

function fakeExecution({ config, packet, artifacts, containerName }) {
  const deliveries = artifacts.map((artifact, index) => ({
    delivery_id: `deliveryopaqueidentifier${String(index).padStart(4, '0')}`,
    artifact_id: artifact.artifact_id,
    artifact_kind: artifact.kind,
    logical_name: artifact.logical_name,
    expected_sha256: artifact.sha256,
    size: artifact.size,
    events: [
      {
        state: 'DELIVERED',
        observed_at: '2026-07-29T10:00:01.000Z',
        bytes_sent: artifact.size,
        transport_sha256: artifact.sha256,
      },
      {
        state: 'CONSUMED',
        observed_at: '2026-07-29T10:00:02.000Z',
        challenge_base64: Buffer.alloc(32, index).toString('base64'),
        hmac_algorithm: 'HMAC-SHA256',
        hmac_domain: 'red-team-audit/provider-delivery/v1',
        challenge_hmac_sha256: SHA_C,
      },
    ],
  }))
  return {
    schema_version: '1.0.0',
    protocol: 'docker-stdio-v1',
    job_result: {
      schema_version: '1.0.0',
      run_id: packet.run_id,
      job_id: packet.job_id,
      input_sha256: packet.packet_sha256,
      producer: {
        name: 'failure-integration-fixture-provider',
        version: '1.0.0',
        instance_id: 'fixture:provider-failure-1',
      },
      state: 'SUCCEEDED',
      examined_files: artifacts
        .filter(({ kind }) => kind === 'FILE')
        .map(({ logical_name: logicalName }) => logicalName),
      findings: [],
      coverage_gaps: [],
    },
    receipt: {
      schema_version: '1.0.0',
      observer: 'red-team-audit-controller',
      receipt_scope: 'BYTE_DELIVERY_AND_CHALLENGE_CONSUMPTION_ONLY',
      semantic_analysis_proven: false,
      run_id: packet.run_id,
      job_id: packet.job_id,
      packet_sha256: packet.packet_sha256,
      session_id: 'sessionopaqueidentifier01',
      started_at: '2026-07-29T10:00:00.000Z',
      completed_at: '2026-07-29T10:00:03.000Z',
      backend: {
        type: 'OCI_DOCKER',
        runtime_path: config.runtime_path,
        runtime_version: 'fixture-1.0',
        context: 'default',
        image: config.image,
        container_name: containerName,
        container_id: SHA_B,
        security_profile: 'builtin',
      },
      deliveries,
      transcript_sha256: SHA_C,
    },
  }
}

async function createProviderFixture(label) {
  const root = await mkdtemp(join(tmpdir(), `rta-${label}-target-`))
  const output = await mkdtemp(join(tmpdir(), `rta-${label}-output-`))
  await mkdir(join(root, 'src'))
  await writeFile(
    join(root, 'src', 'app.js'),
    'export const providerFailureFixture = true\n',
  )
  await writeFile(
    join(root, 'package.json'),
    '{"name":"provider-failure-fixture","type":"module"}\n',
  )
  const plan = await createRunPlan({
    targetRoot: root,
    lensDirectory: resolve('skills/last-aperture/lenses'),
    sealSource: true,
    createdAt: new Date('2026-07-29T09:59:00.000Z'),
  })
  const written = await writeRunPlanBundle(plan, join(output, 'bundles'))
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  const signingKeyPath = join(output, 'receipt-signing-key.pem')
  const publicKeyPath = join(output, 'receipt-public-key.pem')
  const configPath = join(output, 'provider-config.json')
  const config = providerConfig(process.execPath, signingKeyPath)
  const keyId = controllerKeyId(privateKey)
  await writeFile(
    signingKeyPath,
    privateKey.export({ type: 'pkcs8', format: 'pem' }),
    { mode: 0o600 },
  )
  await writeFile(
    publicKeyPath,
    publicKey.export({ type: 'spki', format: 'pem' }),
  )
  await writeFile(configPath, stableJson(config))
  return {
    root,
    output,
    written,
    privateKey,
    publicKey,
    publicKeyPath,
    keyId,
    config,
    configSha256: providerConfigBindingSha256(config, keyId),
    configPath,
    async cleanup() {
      await rm(root, { recursive: true, force: true })
      await rm(output, { recursive: true, force: true })
    },
  }
}

async function seedDurableExecutionState(
  fixture,
  state = 'RESULT_CAPTURED',
) {
  const initial = JSON.parse(await readFile(fixture.written.runPath, 'utf8'))
  let seedLaunches = 0
  await runProviderCommand(
    [fixture.written.directory, fixture.configPath],
    {},
    {
      providerRunner: async (options) => {
        seedLaunches += 1
        return fakeExecution(options)
      },
    },
  )
  assert.equal(seedLaunches, 1)
  const committed = JSON.parse(await readFile(fixture.written.runPath, 'utf8'))
  const leaseEvent = committed.attempt_events.find(
    ({ event }) => event === 'LEASED',
  )
  const startedEvent = committed.attempt_events.find(
    ({ event }) => event === 'STARTED',
  )
  const capturedEvent = committed.attempt_events.find(
    ({ event }) => event === 'RESULT_CAPTURED',
  )
  const validatedEvent = committed.attempt_events.find(
    ({ event }) => event === 'VALIDATED',
  )
  assert.ok(leaseEvent)
  assert.ok(startedEvent)
  assert.ok(capturedEvent)
  assert.ok(validatedEvent)

  let durable = leaseProviderAttempt(initial, leaseEvent.job_id, {
    attempt_id: leaseEvent.attempt_id,
    occurred_at: leaseEvent.occurred_at,
    expires_at: leaseEvent.expires_at,
    nonce: leaseEvent.nonce,
    packet_sha256: leaseEvent.packet_sha256,
    provider_config_sha256: leaseEvent.provider_config_sha256,
    sandbox_policy_sha256: leaseEvent.sandbox_policy_sha256,
    container_name: leaseEvent.container_name,
    budgets: leaseEvent.budgets,
  })
  durable = markProviderAttemptStarted(durable, leaseEvent.attempt_id, {
    occurred_at: startedEvent.occurred_at,
  })
  const executionArtifact =
    committed.artifacts[capturedEvent.execution_artifact_key]
  durable = recordProviderResultCaptured(
    durable,
    leaseEvent.attempt_id,
    {
      occurred_at: capturedEvent.occurred_at,
      execution_artifact_key: capturedEvent.execution_artifact_key,
      execution_artifact: executionArtifact,
      receipt_sha256: capturedEvent.receipt_sha256,
    },
  )
  if (state === 'VALIDATED') {
    durable = recordProviderResultValidated(
      durable,
      leaseEvent.attempt_id,
      { occurred_at: validatedEvent.occurred_at },
    )
  } else if (state !== 'RESULT_CAPTURED') {
    throw new Error(`unsupported durable fixture state ${state}`)
  }
  assert.deepEqual(
    durable.attempt_events,
    committed.attempt_events.slice(0, durable.attempt_events.length),
  )
  await writeFile(fixture.written.runPath, stableJson(durable))
  return {
    initial,
    committed,
    durable,
    attemptId: leaseEvent.attempt_id,
    jobId: leaseEvent.job_id,
    executionArtifact,
    executionPath: join(
      fixture.written.directory,
      ...executionArtifact.path.split('/'),
    ),
  }
}

function rehashAttemptHistory(run) {
  let previousEventSha256 = null
  for (const event of run.attempt_events) {
    event.previous_event_sha256 = previousEventSha256
    event.event_sha256 = hashAttemptEvent(event)
    previousEventSha256 = event.event_sha256
  }
  return run
}

async function rewriteExecutionEnvelope(
  fixture,
  seeded,
  run,
  mutate,
) {
  const envelope = JSON.parse(
    await readFile(seeded.executionPath, 'utf8'),
  )
  mutate(envelope)
  envelope.controller.provider_execution_sha256 = sha256(
    stableJson(envelope.provider_execution, 0),
  )
  envelope.controller.receipt_sha256 = sha256(
    stableJson(envelope.provider_execution.receipt, 0),
  )
  const { signature: _discarded, ...unsigned } = envelope
  envelope.signature.value_base64 = signBytes(
    null,
    Buffer.from(stableJson(unsigned, 0), 'utf8'),
    fixture.privateKey,
  ).toString('base64')
  const content = stableJson(envelope)
  const digest = sha256(content)
  const candidate = structuredClone(run)
  candidate.artifacts[
    candidate.attempt_events.find(
      ({ event }) => event === 'RESULT_CAPTURED',
    ).execution_artifact_key
  ].sha256 = digest
  for (const event of candidate.attempt_events) {
    if (event.execution_artifact_sha256 !== undefined) {
      event.execution_artifact_sha256 = digest
      event.receipt_sha256 = envelope.controller.receipt_sha256
    }
  }
  rehashAttemptHistory(candidate)
  await writeFile(seeded.executionPath, content)
  return candidate
}

function assertRecoverableFailure(run, messagePattern) {
  const failure = run.attempt_events.at(-1)
  assert.equal(failure.event, 'FAILED')
  assert.equal(failure.recoverable, true)
  assert.match(failure.reason, messagePattern)
  const job = run.jobs.find(({ job_id: jobId }) => jobId === failure.job_id)
  assert.ok(job)
  assert.equal(job.state, 'PENDING')
  assert.equal(job.coverage_authority, undefined)
  assert.equal(job.attempt_id, undefined)
  assert.equal(job.receipt_sha256, undefined)
  assert.equal(
    Object.keys(run.artifacts).some((key) => key.startsWith('execution_')),
    false,
  )
  return failure
}

async function assertSignedFailureEvidence(
  fixture,
  run,
  failure,
  { partialReceipt, recoverable = true },
) {
  assert.match(failure.failure_artifact_key, /^failure_[a-z0-9_-]+$/)
  assert.match(failure.failure_artifact_sha256, /^[a-f0-9]{64}$/)
  const artifact = run.artifacts[failure.failure_artifact_key]
  assert.ok(artifact)
  assert.equal(artifact.sha256, failure.failure_artifact_sha256)
  const content = await readFile(
    join(fixture.written.directory, ...artifact.path.split('/')),
  )
  assert.equal(sha256(content), failure.failure_artifact_sha256)
  const envelope = JSON.parse(content.toString('utf8'))
  assert.equal(envelope.authority, 'CONTROLLER_OBSERVED_FAILURE')
  assert.equal(envelope.controller.attempt_id, failure.attempt_id)
  assert.equal(
    envelope.controller.failure_sha256,
    sha256(stableJson(envelope.failure, 0)),
  )
  assert.equal(envelope.failure.recoverable, recoverable)
  assert.equal(envelope.signature.algorithm, 'Ed25519')
  assert.match(envelope.signature.value_base64, /^[A-Za-z0-9+/]{86}==$/)
  const lease = run.attempt_events.find(
    ({ attempt_id: attemptId, event }) =>
      attemptId === failure.attempt_id && event === 'LEASED',
  )
  assert.ok(lease)
  if (partialReceipt) {
    const receipt = envelope.failure.partial_receipt
    assert.ok(receipt)
    assert.equal(receipt.run_id, run.run_id)
    assert.equal(receipt.job_id, failure.job_id)
    assert.equal(receipt.packet_sha256, lease.packet_sha256)
    assert.equal(receipt.backend.container_name, lease.container_name)
    assert.equal(
      envelope.controller.partial_receipt_sha256,
      sha256(stableJson(receipt, 0)),
    )
    assert.equal(
      failure.partial_receipt_sha256,
      envelope.controller.partial_receipt_sha256,
    )
  } else {
    assert.equal(envelope.failure.partial_receipt, undefined)
    assert.equal(envelope.controller.partial_receipt_sha256, undefined)
    assert.equal(failure.partial_receipt_sha256, undefined)
  }
  await verifyControlBundle(fixture.written.directory, run, {
    pinnedReceiptKeyId: fixture.keyId,
  })
  return envelope
}

test('run-provider durably fails and requeues when required controls were not consumed', {
  skip: NODE_24_REQUIRED,
}, async () => {
  const fixture = await createProviderFixture('provider-control-omission')
  try {
    await assert.rejects(
      runProviderCommand(
        [fixture.written.directory, fixture.configPath],
        {},
        {
          providerRunner: async (options) => {
            const execution = fakeExecution(options)
            execution.receipt.deliveries = execution.receipt.deliveries
              .filter(({ artifact_kind: kind }) => kind !== 'CONTROL')
            return execution
          },
        },
      ),
      /provider did not consume required sealed controls/,
    )

    const run = JSON.parse(await readFile(fixture.written.runPath, 'utf8'))
    assert.deepEqual(
      run.attempt_events.map(({ event }) => event),
      ['LEASED', 'STARTED', 'FAILED'],
    )
    const failure = assertRecoverableFailure(
      run,
      /provider execution failed: provider did not consume required sealed controls/,
    )
    const envelope = await assertSignedFailureEvidence(
      fixture,
      run,
      failure,
      { partialReceipt: true },
    )
    assert.ok(envelope.failure.partial_receipt.deliveries.length > 0)
    assert.equal(
      envelope.failure.partial_receipt.deliveries.some(
        ({ artifact_kind: kind }) => kind === 'CONTROL',
      ),
      false,
    )

    const tamperedRun = structuredClone(run)
    const tamperedEnvelope = structuredClone(envelope)
    tamperedEnvelope.failure.partial_receipt.job_id = 'job:wrong-binding-test'
    tamperedEnvelope.controller.partial_receipt_sha256 = sha256(stableJson(
      tamperedEnvelope.failure.partial_receipt,
      0,
    ))
    tamperedEnvelope.controller.failure_sha256 = sha256(stableJson(
      tamperedEnvelope.failure,
      0,
    ))
    const { signature, ...unsigned } = tamperedEnvelope
    tamperedEnvelope.signature = {
      ...signature,
      value_base64: signBytes(
        null,
        Buffer.from(stableJson(unsigned, 0), 'utf8'),
        fixture.privateKey,
      ).toString('base64'),
    }
    const tamperedContent = stableJson(tamperedEnvelope)
    const tamperedDigest = sha256(tamperedContent)
    const tamperedArtifact = tamperedRun.artifacts[failure.failure_artifact_key]
    tamperedArtifact.sha256 = tamperedDigest
    const tamperedFailure = tamperedRun.attempt_events.at(-1)
    tamperedFailure.failure_artifact_sha256 = tamperedDigest
    tamperedFailure.partial_receipt_sha256 =
      tamperedEnvelope.controller.partial_receipt_sha256
    tamperedFailure.event_sha256 = hashAttemptEvent(tamperedFailure)
    await writeFile(
      join(
        fixture.written.directory,
        ...tamperedArtifact.path.split('/'),
      ),
      tamperedContent,
    )
    await assert.rejects(
      verifyControlBundle(fixture.written.directory, tamperedRun),
      /controller failure partial receipt does not bind its attempt/,
    )
  } finally {
    await fixture.cleanup()
  }
})

test('run-provider durably fails and requeues when the provider runner throws', {
  skip: NODE_24_REQUIRED,
}, async () => {
  const fixture = await createProviderFixture('provider-runner-crash')
  try {
    await assert.rejects(
      runProviderCommand(
        [fixture.written.directory, fixture.configPath],
        {},
        {
          providerRunner: async (options) => {
            const execution = fakeExecution(options)
            const error = new Error('simulated provider process crash')
            error.code = 'PROVIDER_PROTOCOL_VIOLATION'
            error.stderr = 'bounded provider stderr evidence'
            error.partial_receipt = {
              ...execution.receipt,
              deliveries: [{
                ...execution.receipt.deliveries[0],
                events: [execution.receipt.deliveries[0].events[0]],
              }],
            }
            throw error
          },
        },
      ),
      /simulated provider process crash/,
    )

    const run = JSON.parse(await readFile(fixture.written.runPath, 'utf8'))
    assert.deepEqual(
      run.attempt_events.map(({ event }) => event),
      ['LEASED', 'STARTED', 'FAILED'],
    )
    const failure = assertRecoverableFailure(
      run,
      /provider execution failed: simulated provider process crash/,
    )
    const envelope = await assertSignedFailureEvidence(
      fixture,
      run,
      failure,
      { partialReceipt: true },
    )
    assert.equal(envelope.failure.code, 'PROVIDER_PROTOCOL_VIOLATION')
    assert.equal(envelope.failure.stderr, 'bounded provider stderr evidence')
    assert.equal(envelope.failure.partial_receipt.deliveries.length, 1)
    assert.equal(
      envelope.failure.partial_receipt.deliveries[0].events.length,
      1,
    )
  } finally {
    await fixture.cleanup()
  }
})

test('unverified Docker cleanup is signed, nonrecoverable, and cannot requeue', {
  skip: NODE_24_REQUIRED,
}, async () => {
  const fixture = await createProviderFixture('provider-cleanup-unverified')
  try {
    await assert.rejects(
      runProviderCommand(
        [fixture.written.directory, fixture.configPath],
        {},
        {
          providerRunner: async (options) => {
            const execution = fakeExecution(options)
            const cleanupError = new Error(
              'could not prove the exact provider container absent after cleanup',
            )
            cleanupError.code = 'PROVIDER_CLEANUP_UNVERIFIED'
            cleanupError.stderr = 'bounded cleanup diagnostic'
            const error = new Error('ambiguous Docker create failure')
            error.code = 'PROVIDER_DOCKER_COMMAND_FAILED'
            error.cleanup_error = cleanupError
            error.partial_receipt = execution.receipt
            throw error
          },
        },
      ),
      /ambiguous Docker create failure/,
    )

    const run = JSON.parse(await readFile(fixture.written.runPath, 'utf8'))
    const failure = run.attempt_events.at(-1)
    assert.equal(failure.event, 'FAILED')
    assert.equal(failure.recoverable, false)
    const job = run.jobs.find(({ job_id: jobId }) => jobId === failure.job_id)
    assert.ok(job)
    assert.equal(job.state, 'FAILED')
    assert.equal(job.attempt_id, undefined)
    assert.equal(job.coverage_authority, undefined)
    assert.equal(run.state, 'FAILED')
    assert.equal(run.phase, 'FINALIZED')
    assert.match(run.completed_at, /Z$/)
    assert.equal(
      run.jobs.every(({ state }) => ['SUCCEEDED', 'SKIPPED', 'FAILED'].includes(state)),
      true,
    )
    assert.deepEqual(run.errors.at(-1), {
      error_id: 'provider-cleanup:1',
      phase: 'FINALIZED',
      code: 'PROVIDER_CLEANUP_UNVERIFIED',
      message:
        'provider execution failed: ambiguous Docker create failure',
      recoverable: false,
      job_id: failure.job_id,
    })

    const envelope = await assertSignedFailureEvidence(
      fixture,
      run,
      failure,
      { partialReceipt: true, recoverable: false },
    )
    assert.equal(envelope.failure.code, 'PROVIDER_DOCKER_COMMAND_FAILED')
    assert.deepEqual(envelope.failure.cleanup_error, {
      code: 'PROVIDER_CLEANUP_UNVERIFIED',
      message:
        'could not prove the exact provider container absent after cleanup',
      stderr: 'bounded cleanup diagnostic',
    })

    let secondProviderCalled = false
    await assert.rejects(
      runProviderCommand(
        [fixture.written.directory, fixture.configPath],
        {},
        {
          providerRunner: async () => {
            secondProviderCalled = true
            throw new Error('terminal cleanup circuit breaker was bypassed')
          },
        },
      ),
      /no provider job ready for observed execution/,
    )
    assert.equal(secondProviderCalled, false)

    const tamperedRun = structuredClone(run)
    const tamperedEnvelope = structuredClone(envelope)
    tamperedEnvelope.failure.recoverable = true
    delete tamperedEnvelope.failure.cleanup_error
    tamperedEnvelope.controller.failure_sha256 = sha256(stableJson(
      tamperedEnvelope.failure,
      0,
    ))
    const { signature, ...unsigned } = tamperedEnvelope
    tamperedEnvelope.signature = {
      ...signature,
      value_base64: signBytes(
        null,
        Buffer.from(stableJson(unsigned, 0), 'utf8'),
        fixture.privateKey,
      ).toString('base64'),
    }
    const tamperedContent = stableJson(tamperedEnvelope)
    const tamperedDigest = sha256(tamperedContent)
    const tamperedArtifact = tamperedRun.artifacts[failure.failure_artifact_key]
    tamperedArtifact.sha256 = tamperedDigest
    const tamperedFailure = tamperedRun.attempt_events.at(-1)
    tamperedFailure.failure_artifact_sha256 = tamperedDigest
    tamperedFailure.event_sha256 = hashAttemptEvent(tamperedFailure)
    await writeFile(
      join(
        fixture.written.directory,
        ...tamperedArtifact.path.split('/'),
      ),
      tamperedContent,
    )
    await assert.rejects(
      verifyControlBundle(fixture.written.directory, tamperedRun),
      /failure envelope recoverability differs from its FAILED event/,
    )
  } finally {
    await fixture.cleanup()
  }
})

test('run-provider durably fails and requeues when capture fails after a valid execution', {
  skip: NODE_24_REQUIRED,
}, async () => {
  const fixture = await createProviderFixture('provider-capture-failure')
  try {
    await writeFile(
      join(fixture.written.directory, 'executions'),
      'regular file deliberately blocks the execution artifact directory\n',
    )
    let providerReturned = false
    await assert.rejects(
      runProviderCommand(
        [fixture.written.directory, fixture.configPath],
        {},
        {
          providerRunner: async (options) => {
            const execution = fakeExecution(options)
            providerReturned = true
            return execution
          },
        },
      ),
      /bundle path is not a directory: executions/,
    )

    assert.equal(providerReturned, true)
    const run = JSON.parse(await readFile(fixture.written.runPath, 'utf8'))
    assert.deepEqual(
      run.attempt_events.map(({ event }) => event),
      ['LEASED', 'STARTED', 'FAILED'],
    )
    const failure = assertRecoverableFailure(
      run,
      /bundle path is not a directory: executions/,
    )
    const envelope = await assertSignedFailureEvidence(
      fixture,
      run,
      failure,
      { partialReceipt: true },
    )
    assert.ok(envelope.failure.partial_receipt.deliveries.length > 0)
  } finally {
    await fixture.cleanup()
  }
})

test('run-provider cleans and fails a stale STARTED attempt before retrying', {
  skip: NODE_24_REQUIRED,
}, async () => {
  const fixture = await createProviderFixture('provider-stale-started')
  try {
    const initial = JSON.parse(await readFile(fixture.written.runPath, 'utf8'))
    const pendingJob = initial.jobs.find(
      ({ kind, state }) => kind === 'LENS' && state === 'PENDING',
    )
    assert.ok(pendingJob)
    const staleAttemptId = 'attempt:stale-started-integration-fixture'
    const staleContainerName = 'rta-provider-stale-started-fixture'
    const staleSandboxPolicySha256 = sha256(stableJson({
      backend: 'OCI_DOCKER',
      argv: buildDockerCreateArgs(fixture.config, staleContainerName),
    }, 0))
    const leased = leaseProviderAttempt(initial, pendingJob.job_id, {
      attempt_id: staleAttemptId,
      packet_sha256: SHA_C,
      provider_config_sha256: fixture.configSha256,
      sandbox_policy_sha256: staleSandboxPolicySha256,
      container_name: staleContainerName,
      budgets: {
        wall_clock_ms: fixture.config.limits.wall_time_ms,
        max_requests: fixture.config.limits.max_deliveries,
        max_bytes: fixture.config.limits.max_total_delivery_bytes,
      },
      occurred_at: '2026-07-29T10:00:00.000Z',
      expires_at: '2026-07-29T10:01:00.000Z',
    })
    const started = markProviderAttemptStarted(leased, staleAttemptId, {
      occurred_at: '2026-07-29T10:00:01.000Z',
    })
    await writeFile(fixture.written.runPath, stableJson(started))

    const cleanupCalls = []
    await assert.rejects(
      runProviderCommand(
        [fixture.written.directory, fixture.configPath],
        {},
        {
          cleanupProviderContainer: async (options) => {
            cleanupCalls.push(options)
          },
          providerRunner: async () => {
            throw new Error('simulated retry crash')
          },
        },
      ),
      /simulated retry crash/,
    )

    assert.deepEqual(cleanupCalls, [{
      config: fixture.config,
      containerName: staleContainerName,
    }])
    const run = JSON.parse(await readFile(fixture.written.runPath, 'utf8'))
    assert.deepEqual(
      run.attempt_events.map(({ event }) => event),
      ['LEASED', 'STARTED', 'FAILED', 'LEASED', 'STARTED', 'FAILED'],
    )
    const staleFailure = run.attempt_events[2]
    assert.equal(staleFailure.attempt_id, staleAttemptId)
    assert.equal(staleFailure.recoverable, true)
    assert.match(
      staleFailure.reason,
      /provider attempt expired: attempt lease expired at .* before the prior controller captured a result/,
    )
    const staleEnvelope = await assertSignedFailureEvidence(
      fixture,
      run,
      staleFailure,
      { partialReceipt: false },
    )
    assert.equal(staleEnvelope.failure.code, 'PROVIDER_ATTEMPT_EXPIRED')
    assert.equal(staleEnvelope.failure.recoverable, true)
    const retryFailure = assertRecoverableFailure(
      run,
      /provider execution failed: simulated retry crash/,
    )
    assert.notEqual(retryFailure.attempt_id, staleAttemptId)
    assert.equal(
      run.jobs.find(({ job_id: jobId }) => jobId === pendingJob.job_id)?.state,
      'PENDING',
    )
  } finally {
    await fixture.cleanup()
  }
})

test('stale cleanup without verified absence is signed and not retried', {
  skip: NODE_24_REQUIRED,
}, async () => {
  const fixture = await createProviderFixture('provider-stale-cleanup-failure')
  try {
    const initial = JSON.parse(await readFile(fixture.written.runPath, 'utf8'))
    const pendingJob = initial.jobs.find(
      ({ kind, state }) => kind === 'LENS' && state === 'PENDING',
    )
    assert.ok(pendingJob)
    const attemptId = 'attempt:stale-cleanup-failure-fixture'
    const containerName = 'rta-provider-stale-cleanup-failure'
    const sandboxPolicySha256 = sha256(stableJson({
      backend: 'OCI_DOCKER',
      argv: buildDockerCreateArgs(fixture.config, containerName),
    }, 0))
    const leased = leaseProviderAttempt(initial, pendingJob.job_id, {
      attempt_id: attemptId,
      packet_sha256: SHA_C,
      provider_config_sha256: fixture.configSha256,
      sandbox_policy_sha256: sandboxPolicySha256,
      container_name: containerName,
      budgets: {
        wall_clock_ms: fixture.config.limits.wall_time_ms,
        max_requests: fixture.config.limits.max_deliveries,
        max_bytes: fixture.config.limits.max_total_delivery_bytes,
      },
      occurred_at: '2026-07-29T10:00:00.000Z',
      expires_at: '2026-07-29T10:01:00.000Z',
    })
    const started = markProviderAttemptStarted(leased, attemptId, {
      occurred_at: '2026-07-29T10:00:01.000Z',
    })
    await writeFile(fixture.written.runPath, stableJson(started))

    let providerCalled = false
    await assert.rejects(
      runProviderCommand(
        [fixture.written.directory, fixture.configPath],
        {},
        {
          cleanupProviderContainer: async () => {
            const error = new Error(
              'could not prove the exact provider container absent after cleanup',
            )
            error.code = 'PROVIDER_CLEANUP_UNVERIFIED'
            error.stderr = 'post-inspection daemon query failed'
            throw error
          },
          providerRunner: async () => {
            providerCalled = true
            throw new Error('provider must not be retried')
          },
        },
      ),
      /could not prove the exact provider container absent/,
    )
    assert.equal(providerCalled, false)

    const run = JSON.parse(await readFile(fixture.written.runPath, 'utf8'))
    assert.deepEqual(
      run.attempt_events.map(({ event }) => event),
      ['LEASED', 'STARTED', 'FAILED'],
    )
    const failure = run.attempt_events.at(-1)
    assert.equal(failure.attempt_id, attemptId)
    assert.equal(failure.recoverable, false)
    assert.equal(
      run.jobs.find(({ job_id: jobId }) => jobId === pendingJob.job_id)?.state,
      'FAILED',
    )
    assert.equal(run.state, 'FAILED')
    assert.equal(run.phase, 'FINALIZED')
    assert.equal(
      run.jobs.some(({ state }) => ['PENDING', 'RUNNING'].includes(state)),
      false,
    )
    assert.equal(run.errors.at(-1).code, 'PROVIDER_CLEANUP_UNVERIFIED')
    assert.equal(run.errors.at(-1).recoverable, false)
    const envelope = await assertSignedFailureEvidence(
      fixture,
      run,
      failure,
      { partialReceipt: false, recoverable: false },
    )
    assert.equal(
      envelope.failure.cleanup_error.code,
      'PROVIDER_CLEANUP_UNVERIFIED',
    )
    assert.equal(
      envelope.failure.cleanup_error.stderr,
      'post-inspection daemon query failed',
    )
  } finally {
    await fixture.cleanup()
  }
})

test('run-provider refuses to steal or clean an unexpired active attempt', {
  skip: NODE_24_REQUIRED,
}, async () => {
  const fixture = await createProviderFixture('provider-live-attempt')
  try {
    const initial = JSON.parse(await readFile(fixture.written.runPath, 'utf8'))
    const pendingJob = initial.jobs.find(
      ({ kind, state }) => kind === 'LENS' && state === 'PENDING',
    )
    assert.ok(pendingJob)
    const attemptId = 'attempt:live-started-integration-fixture'
    const containerName = 'rta-provider-live-started-fixture'
    const occurredAt = new Date().toISOString()
    const expiresAt = new Date(Date.now() + 120_000).toISOString()
    const sandboxPolicySha256 = sha256(stableJson({
      backend: 'OCI_DOCKER',
      argv: buildDockerCreateArgs(fixture.config, containerName),
    }, 0))
    const leased = leaseProviderAttempt(initial, pendingJob.job_id, {
      attempt_id: attemptId,
      packet_sha256: SHA_C,
      provider_config_sha256: sha256(stableJson(fixture.config, 0)),
      sandbox_policy_sha256: sandboxPolicySha256,
      container_name: containerName,
      budgets: {
        wall_clock_ms: fixture.config.limits.wall_time_ms,
        max_requests: fixture.config.limits.max_deliveries,
        max_bytes: fixture.config.limits.max_total_delivery_bytes,
      },
      occurred_at: occurredAt,
      expires_at: expiresAt,
    })
    const started = markProviderAttemptStarted(leased, attemptId, {
      occurred_at: occurredAt,
    })
    await writeFile(fixture.written.runPath, stableJson(started))

    let cleanupCalled = false
    let runnerCalled = false
    await assert.rejects(
      runProviderCommand(
        [fixture.written.directory, fixture.configPath],
        {},
        {
          cleanupProviderContainer: async () => {
            cleanupCalled = true
          },
          providerRunner: async () => {
            runnerCalled = true
            throw new Error('must not launch')
          },
        },
      ),
      /active until .*refusing to steal its lease or clean its container/,
    )

    assert.equal(cleanupCalled, false)
    assert.equal(runnerCalled, false)
    const unchanged = JSON.parse(await readFile(fixture.written.runPath, 'utf8'))
    assert.deepEqual(unchanged.attempt_events, started.attempt_events)
    assert.equal(
      unchanged.jobs.find(({ job_id: jobId }) => jobId === pendingJob.job_id)?.state,
      'RUNNING',
    )
  } finally {
    await fixture.cleanup()
  }
})

test('two controllers racing the lease CAS authorize exactly one launch', {
  skip: NODE_24_REQUIRED,
}, async () => {
  const fixture = await createProviderFixture('provider-lease-cas-race')
  try {
    let beforeLeaseArrivals = 0
    let releaseBeforeLease
    const beforeLeaseGate = new Promise((resolveGate) => {
      releaseBeforeLease = resolveGate
    })
    const settledControllers = new Set()
    let winningController
    let releaseWinner
    const loserSettled = new Promise((resolveLoser) => {
      releaseWinner = resolveLoser
    })
    const maybeReleaseWinner = () => {
      if (
        winningController !== undefined
        && [...settledControllers].some((id) => id !== winningController)
      ) {
        releaseWinner()
      }
    }
    let launchCount = 0
    let cleanupCount = 0
    const invoke = (controllerId) => {
      const promise = runProviderCommand(
        [fixture.written.directory, fixture.configPath],
        {},
        {
          beforeLeasePersist: async () => {
            beforeLeaseArrivals += 1
            if (beforeLeaseArrivals === 2) releaseBeforeLease()
            await beforeLeaseGate
          },
          afterLeasePersist: async () => {
            winningController = controllerId
            maybeReleaseWinner()
            await loserSettled
          },
          cleanupProviderContainer: async () => {
            cleanupCount += 1
          },
          providerRunner: async (options) => {
            launchCount += 1
            return fakeExecution(options)
          },
        },
      )
      return promise.finally(() => {
        settledControllers.add(controllerId)
        maybeReleaseWinner()
      })
    }

    const results = await Promise.allSettled([
      invoke('controller-a'),
      invoke('controller-b'),
    ])
    assert.equal(
      results.filter(({ status }) => status === 'fulfilled').length,
      1,
    )
    assert.equal(
      results.filter(({ status }) => status === 'rejected').length,
      1,
    )
    assert.match(
      results.find(({ status }) => status === 'rejected').reason.message,
      /run is locked by another update|run changed concurrently/,
    )
    assert.equal(launchCount, 1)
    assert.equal(cleanupCount, 0)

    const run = JSON.parse(await readFile(fixture.written.runPath, 'utf8'))
    assert.deepEqual(
      run.attempt_events.map(({ event }) => event),
      ['LEASED', 'STARTED', 'RESULT_CAPTURED', 'VALIDATED', 'COMMITTED'],
    )
    assert.equal(
      new Set(run.attempt_events.map(
        ({ attempt_id: attemptId }) => attemptId,
      )).size,
      1,
    )
  } finally {
    await fixture.cleanup()
  }
})

test('run-provider resumes durable captured and validated results without relaunch', {
  skip: NODE_24_REQUIRED,
}, async (t) => {
  for (const durableState of ['RESULT_CAPTURED', 'VALIDATED']) {
    await t.test(durableState, async () => {
      const fixture = await createProviderFixture(
        `provider-resume-${durableState.toLowerCase()}`,
      )
      try {
        const seeded = await seedDurableExecutionState(
          fixture,
          durableState,
        )
        let launchCount = 0
        let cleanupCount = 0
        await runProviderCommand(
          [fixture.written.directory, fixture.configPath],
          {},
          {
            cleanupProviderContainer: async () => {
              cleanupCount += 1
            },
            providerRunner: async () => {
              launchCount += 1
              throw new Error('durable result resume must not relaunch')
            },
          },
        )
        assert.equal(launchCount, 0)
        assert.equal(cleanupCount, 0)

        const run = JSON.parse(
          await readFile(fixture.written.runPath, 'utf8'),
        )
        assert.deepEqual(
          run.attempt_events.map(({ event }) => event),
          [
            'LEASED',
            'STARTED',
            'RESULT_CAPTURED',
            'VALIDATED',
            'COMMITTED',
          ],
        )
        assert.equal(
          run.attempt_events.filter(
            ({ event }) => event === 'COMMITTED',
          ).length,
          1,
        )
        assert.equal(
          new Set(run.attempt_events.map(
            ({ attempt_id: attemptId }) => attemptId,
          )).size,
          1,
        )
        assert.equal(
          Object.keys(run.artifacts).filter(
            (key) => key.startsWith('execution_'),
          ).length,
          1,
        )
        await verifyControlBundle(fixture.written.directory, run, {
          pinnedReceiptKeyId: fixture.keyId,
        })
      } finally {
        await fixture.cleanup()
      }
    })
  }
})

test('captured resume refuses signing-key rotation before mutating the run', {
  skip: NODE_24_REQUIRED,
}, async () => {
  const fixture = await createProviderFixture('provider-resume-key-rotation')
  try {
    const seeded = await seedDurableExecutionState(
      fixture,
      'RESULT_CAPTURED',
    )
    const { privateKey: rotatedPrivateKey } = generateKeyPairSync('ed25519')
    await writeFile(
      join(fixture.output, 'receipt-signing-key.pem'),
      rotatedPrivateKey.export({ type: 'pkcs8', format: 'pem' }),
      { mode: 0o600 },
    )
    let launchCount = 0
    let cleanupCount = 0
    await assert.rejects(
      runProviderCommand(
        [fixture.written.directory, fixture.configPath],
        {},
        {
          cleanupProviderContainer: async () => {
            cleanupCount += 1
          },
          providerRunner: async () => {
            launchCount += 1
            throw new Error('rotated-key resume must not relaunch')
          },
        },
      ),
      /controller execution signing key identity is not trusted/,
    )
    assert.equal(launchCount, 0)
    assert.equal(cleanupCount, 0)
    const unchanged = JSON.parse(
      await readFile(fixture.written.runPath, 'utf8'),
    )
    assert.deepEqual(unchanged, seeded.durable)
    await verifyControlBundle(
      fixture.written.directory,
      unchanged,
      { pinnedReceiptKeyId: fixture.keyId },
    )
  } finally {
    await fixture.cleanup()
  }
})

test('retry refuses signing-key rotation after recoverable signed failure evidence', {
  skip: NODE_24_REQUIRED,
}, async () => {
  const fixture = await createProviderFixture('provider-retry-key-rotation')
  try {
    await assert.rejects(
      runProviderCommand(
        [fixture.written.directory, fixture.configPath],
        {},
        {
          providerRunner: async () => {
            throw new Error('seed signed retry evidence')
          },
        },
      ),
      /seed signed retry evidence/,
    )
    const failed = JSON.parse(
      await readFile(fixture.written.runPath, 'utf8'),
    )
    assert.equal(failed.attempt_events.at(-1).event, 'FAILED')
    assert.ok(failed.attempt_events.at(-1).failure_artifact_key)

    const { privateKey: rotatedPrivateKey } = generateKeyPairSync('ed25519')
    await writeFile(
      join(fixture.output, 'receipt-signing-key.pem'),
      rotatedPrivateKey.export({ type: 'pkcs8', format: 'pem' }),
      { mode: 0o600 },
    )
    let launchCount = 0
    let cleanupCount = 0
    await assert.rejects(
      runProviderCommand(
        [fixture.written.directory, fixture.configPath],
        {},
        {
          cleanupProviderContainer: async () => {
            cleanupCount += 1
          },
          providerRunner: async () => {
            launchCount += 1
            throw new Error('rotated retry must not launch')
          },
        },
      ),
      /controller failure signing key identity is not trusted/,
    )
    assert.equal(launchCount, 0)
    assert.equal(cleanupCount, 0)
    const unchanged = JSON.parse(
      await readFile(fixture.written.runPath, 'utf8'),
    )
    assert.deepEqual(unchanged, failed)
    await verifyControlBundle(
      fixture.written.directory,
      unchanged,
      { pinnedReceiptKeyId: fixture.keyId },
    )
  } finally {
    await fixture.cleanup()
  }
})

test('retry rejects prior history re-signed under an untrusted embedded key', {
  skip: NODE_24_REQUIRED,
}, async () => {
  const fixture = await createProviderFixture('provider-resigned-history')
  try {
    await assert.rejects(
      runProviderCommand(
        [fixture.written.directory, fixture.configPath],
        {},
        {
          providerRunner: async () => {
            throw new Error('seed history for re-sign replay')
          },
        },
      ),
      /seed history for re-sign replay/,
    )
    const candidate = JSON.parse(
      await readFile(fixture.written.runPath, 'utf8'),
    )
    const failedEvent = candidate.attempt_events.at(-1)
    const artifact = candidate.artifacts[failedEvent.failure_artifact_key]
    const artifactPath = join(
      fixture.written.directory,
      ...artifact.path.split('/'),
    )
    const envelope = JSON.parse(await readFile(artifactPath, 'utf8'))
    const {
      privateKey: attackerPrivateKey,
      publicKey: attackerPublicKey,
    } = generateKeyPairSync('ed25519')
    const attackerSpki = attackerPublicKey.export({
      type: 'spki',
      format: 'der',
    })
    envelope.controller.key_id = `ed25519:${sha256(attackerSpki)}`
    envelope.controller.public_key_spki_base64 =
      attackerSpki.toString('base64')
    const { signature: _discarded, ...unsigned } = envelope
    envelope.signature.value_base64 = signBytes(
      null,
      Buffer.from(stableJson(unsigned, 0), 'utf8'),
      attackerPrivateKey,
    ).toString('base64')
    const content = stableJson(envelope)
    const digest = sha256(content)
    artifact.sha256 = digest
    failedEvent.failure_artifact_sha256 = digest
    rehashAttemptHistory(candidate)
    await writeFile(artifactPath, content)
    await writeFile(fixture.written.runPath, stableJson(candidate))

    let launchCount = 0
    let cleanupCount = 0
    await assert.rejects(
      runProviderCommand(
        [fixture.written.directory, fixture.configPath],
        {},
        {
          cleanupProviderContainer: async () => {
            cleanupCount += 1
          },
          providerRunner: async () => {
            launchCount += 1
            throw new Error('re-signed history must not launch')
          },
        },
      ),
      /controller failure signing key identity is not trusted/,
    )
    assert.equal(launchCount, 0)
    assert.equal(cleanupCount, 0)
    const unchanged = JSON.parse(
      await readFile(fixture.written.runPath, 'utf8'),
    )
    assert.deepEqual(unchanged, candidate)
  } finally {
    await fixture.cleanup()
  }
})

test('all captured execution states reject re-signed cross-attempt replay', {
  skip: NODE_24_REQUIRED,
}, async (t) => {
  for (const state of ['RESULT_CAPTURED', 'CAPTURED_THEN_FAILED']) {
    await t.test(state, async (stateTest) => {
      const fixture = await createProviderFixture(
        `provider-envelope-binding-${state.toLowerCase()}`,
      )
      try {
        const seeded = await seedDurableExecutionState(
          fixture,
          'RESULT_CAPTURED',
        )
        const originalContent = await readFile(
          seeded.executionPath,
          'utf8',
        )
        let run = seeded.durable
        if (state === 'CAPTURED_THEN_FAILED') {
          run = failProviderAttempt(run, seeded.attemptId, {
            occurred_at: new Date().toISOString(),
            reason: 'controller crashed after durable capture',
            recoverable: true,
          })
        }
        await verifyControlBundle(
          fixture.written.directory,
          run,
          { pinnedReceiptKeyId: fixture.keyId },
        )
        const mutations = [
          {
            name: 'wrong run',
            mutate: (envelope) => {
              envelope.provider_execution.job_result.run_id =
                'run:cross-attempt-replay'
              envelope.provider_execution.receipt.run_id =
                'run:cross-attempt-replay'
            },
          },
          {
            name: 'wrong job',
            mutate: (envelope) => {
              envelope.provider_execution.job_result.job_id =
                'lens:cross-attempt-replay'
              envelope.provider_execution.receipt.job_id =
                'lens:cross-attempt-replay'
            },
          },
          {
            name: 'wrong packet',
            mutate: (envelope) => {
              envelope.provider_execution.job_result.input_sha256 =
                'f'.repeat(64)
              envelope.provider_execution.receipt.packet_sha256 =
                'f'.repeat(64)
            },
          },
          {
            name: 'wrong container',
            mutate: (envelope) => {
              envelope.provider_execution.receipt.backend.container_name =
                'rta-provider-cross-attempt-replay'
            },
          },
        ]
        for (const { name, mutate } of mutations) {
          await stateTest.test(name, async () => {
            const candidate = await rewriteExecutionEnvelope(
              fixture,
              seeded,
              run,
              mutate,
            )
            await assert.rejects(
              verifyControlBundle(
                fixture.written.directory,
                candidate,
                { pinnedReceiptKeyId: fixture.keyId },
              ),
              /provider payload does not bind its run and attempt/,
            )
            await writeFile(seeded.executionPath, originalContent)
          })
        }
      } finally {
        await fixture.cleanup()
      }
    })
  }
})
