import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  cleanupDockerProviderContainer,
  runDockerProvider,
} from '../scripts/lib/provider-runner.mjs'
import {
  providerArtifacts,
  providerConfig,
  providerPacket,
} from '../test/helpers/provider-fixtures.mjs'

const runtimePath = process.env.RTA_DOCKER_RUNTIME
const image = process.env.RTA_PROVIDER_IMAGE
const enabled = runtimePath !== undefined && image !== undefined
const HOST_SECRET_CANARY = 'RTA_DOCKER_CONFORMANCE_HOST_SECRET'
const TIMEOUT_CONFORMANCE_JOB = 'lens:docker-timeout-conformance'

test('real Docker backend proves hostile isolation, brokers sealed bytes, and cleans timeouts', {
  skip: enabled
    ? false
    : 'use the explicit release-conformance launcher with enrolled Docker runtime and image',
  timeout: 120_000,
}, async () => {
  const config = providerConfig({
    runtime_path: runtimePath,
    image,
    limits: {
      wall_time_ms: 30_000,
      docker_command_timeout_ms: 30_000,
      idle_timeout_ms: 10_000,
      delivery_timeout_ms: 10_000,
    },
  })

  const previousCanary = process.env[HOST_SECRET_CANARY]
  process.env[HOST_SECRET_CANARY] = 'must-not-cross-the-container-boundary'
  let execution
  try {
    execution = await runDockerProvider({
      config,
      packet: providerPacket(),
      artifacts: providerArtifacts(),
    })
  } finally {
    if (previousCanary === undefined) delete process.env[HOST_SECRET_CANARY]
    else process.env[HOST_SECRET_CANARY] = previousCanary
  }

  assert.equal(execution.job_result.state, 'SUCCEEDED')
  assert.equal(
    execution.job_result.producer.instance_id,
    'reference-byte-consumer:docker-isolation-probes-v1',
  )
  assert.deepEqual(execution.job_result.examined_files, ['src/app.js'])
  assert.equal(execution.receipt.backend.type, 'OCI_DOCKER')
  assert.equal(execution.receipt.backend.runtime_path, runtimePath)
  assert.equal(execution.receipt.backend.image, image)
  assert.equal(execution.receipt.backend.context, 'default')
  assert.equal(execution.receipt.backend.security_profile, 'builtin')
  assert.equal(execution.receipt.semantic_analysis_proven, false)
  assert.deepEqual(
    execution.receipt.deliveries.map((delivery) => ({
      kind: delivery.artifact_kind,
      states: delivery.events.map(({ state }) => state),
    })),
    [
      { kind: 'FILE', states: ['DELIVERED', 'CONSUMED'] },
      { kind: 'CONTROL', states: ['DELIVERED', 'CONSUMED'] },
    ],
  )

  const timeoutContainer = 'rta-provider-timeout-conformance'
  const timeoutConfig = providerConfig({
    runtime_path: runtimePath,
    image,
    limits: {
      wall_time_ms: 30_000,
      docker_command_timeout_ms: 30_000,
      idle_timeout_ms: 4_000,
      delivery_timeout_ms: 4_000,
    },
  })
  let timeoutError
  await assert.rejects(
    runDockerProvider({
      config: timeoutConfig,
      packet: providerPacket({ job_id: TIMEOUT_CONFORMANCE_JOB }),
      artifacts: providerArtifacts(),
      containerName: timeoutContainer,
    }),
    (error) => {
      timeoutError = error
      return error?.code === 'PROVIDER_IDLE_TIMEOUT'
    },
  )
  assert.equal(timeoutError.partial_receipt.job_id, TIMEOUT_CONFORMANCE_JOB)
  assert.equal(
    timeoutError.partial_receipt.backend.container_name,
    timeoutContainer,
  )
  assert.deepEqual(timeoutError.partial_receipt.deliveries, [])
  assert.deepEqual(
    await cleanupDockerProviderContainer({
      config: timeoutConfig,
      containerName: timeoutContainer,
    }),
    { absent: true },
  )
})
