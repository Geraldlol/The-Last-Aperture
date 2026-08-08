import { test } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { PassThrough } from 'node:stream'
import {
  assertHardenedDockerInspection,
  buildDockerCleanupArgs,
  cleanupDockerProviderContainer,
  computeConsumptionHmac,
  normalizeProviderArtifacts,
  ProviderRunnerError,
  runDockerProvider,
  runProviderBroker,
} from '../scripts/lib/provider-runner.mjs'
import {
  createFakeDockerSpawn,
  FILE_ARTIFACT_ID,
  jsonLines,
  providerArtifacts,
  providerBackend,
  providerConfig,
  providerPacket,
  runHonestProvider,
  sendJsonLine,
  successfulJobResult,
} from './helpers/provider-fixtures.mjs'

function deterministicRandomBytes(size) {
  return Buffer.alloc(size, 0x5a)
}

function brokerHarness(config = providerConfig()) {
  const providerStdout = new PassThrough()
  const providerStdin = new PassThrough()
  providerStdin.on('error', () => {})
  const broker = runProviderBroker({
    readable: providerStdout,
    writable: providerStdin,
    packet: providerPacket(),
    artifacts: providerArtifacts(),
    config,
    backend: providerBackend(),
    randomBytesImpl: deterministicRandomBytes,
  })
  return {
    broker,
    providerStdin,
    providerStdout,
  }
}

function artifactConsumedFrame(delivery) {
  const challenge = Buffer.from(delivery.challenge_base64, 'base64')
  const bytes = Buffer.from(delivery.content_base64, 'base64')
  return {
    type: 'artifact_consumed',
    schema_version: '1.0.0',
    session_id: delivery.session_id,
    delivery_id: delivery.delivery_id,
    artifact_id: delivery.artifact_id,
    challenge_hmac_sha256: computeConsumptionHmac({
      challenge,
      jobId: providerPacket().job_id,
      artifactId: delivery.artifact_id,
      size: delivery.size,
      bytes,
    }),
  }
}

async function holdEventLoopFor(promise, milliseconds) {
  const guard = setTimeout(() => {}, milliseconds)
  try {
    return await promise
  } finally {
    clearTimeout(guard)
  }
}

function hostileStartChild(onStart) {
  const child = new EventEmitter()
  child.stdin = new PassThrough()
  child.stdout = new PassThrough()
  child.stderr = new PassThrough()
  child.stdin.on('error', () => {})
  let closed = false
  const close = (code, signal) => {
    if (closed) return
    closed = true
    child.stdout.end()
    child.stderr.end()
    child.emit('close', code, signal)
  }
  child.kill = (signal = 'SIGTERM') => {
    queueMicrotask(() => close(null, signal))
    return true
  }
  queueMicrotask(() => onStart(child, close))
  return child
}

function completedDockerCommand(stdout = '', code = 0, stderr = '') {
  const child = new EventEmitter()
  child.stdin = null
  child.stdout = new PassThrough()
  child.stderr = new PassThrough()
  child.kill = () => true
  queueMicrotask(() => {
    if (stdout) child.stdout.write(stdout)
    if (stderr) child.stderr.write(stderr)
    child.stdout.end()
    child.stderr.end()
    child.emit('close', code, null)
  })
  return child
}

test('broker delivers only requested bytes and records DELIVERED then CONSUMED', async () => {
  const providerStdout = new PassThrough()
  const providerStdin = new PassThrough()
  const broker = runProviderBroker({
    readable: providerStdout,
    writable: providerStdin,
    packet: providerPacket(),
    artifacts: providerArtifacts(),
    config: providerConfig(),
    backend: providerBackend(),
    randomBytesImpl: deterministicRandomBytes,
  })
  const provider = runHonestProvider({
    stdin: providerStdin,
    stdout: providerStdout,
  })
  const [execution] = await Promise.all([broker, provider])

  assert.deepEqual(
    execution.receipt.deliveries[0].events.map(({ state }) => state),
    ['DELIVERED', 'CONSUMED'],
  )
  assert.equal(execution.receipt.deliveries[0].logical_name, 'src/app.js')
  assert.equal(execution.receipt.deliveries[0].artifact_kind, 'FILE')
  assert.equal(execution.receipt.semantic_analysis_proven, false)
  assert.deepEqual(execution.job_result.examined_files, ['src/app.js'])
})

test('broker rejects an artifact ID outside the controller allowlist', async () => {
  const providerStdout = new PassThrough()
  const providerStdin = new PassThrough()
  const broker = runProviderBroker({
    readable: providerStdout,
    writable: providerStdin,
    packet: providerPacket(),
    artifacts: providerArtifacts(),
    config: providerConfig(),
    backend: providerBackend(),
    randomBytesImpl: deterministicRandomBytes,
  })
  const provider = (async () => {
    for await (const frame of jsonLines(providerStdin)) {
      if (frame.type !== 'provider_start') continue
      sendJsonLine(providerStdout, {
        type: 'artifact_request',
        schema_version: '1.0.0',
        session_id: frame.session_id,
        artifact_id: 'unauthorizedopaque0001',
      })
      return
    }
  })()
  await assert.rejects(
    Promise.all([broker, provider]),
    (error) => (
      error instanceof ProviderRunnerError
      && error.code === 'PROVIDER_UNAUTHORIZED_ARTIFACT'
      && error.partial_receipt.semantic_analysis_proven === false
    ),
  )
})

test('broker rejects a fabricated consumption acknowledgement', async () => {
  const providerStdout = new PassThrough()
  const providerStdin = new PassThrough()
  const broker = runProviderBroker({
    readable: providerStdout,
    writable: providerStdin,
    packet: providerPacket(),
    artifacts: providerArtifacts(),
    config: providerConfig(),
    backend: providerBackend(),
    randomBytesImpl: deterministicRandomBytes,
  })
  const provider = runHonestProvider({
    stdin: providerStdin,
    stdout: providerStdout,
    transformHmac: () => '0'.repeat(64),
  })
  await assert.rejects(
    Promise.all([broker, provider]),
    (error) => (
      error instanceof ProviderRunnerError
      && error.code === 'PROVIDER_CONSUMPTION_CHALLENGE_FAILED'
      && error.partial_receipt.deliveries[0].events[0].state === 'DELIVERED'
      && error.partial_receipt.deliveries[0].events.length === 1
    ),
  )
})

test('Docker runner uses the exact trusted executable without a shell and always cleans up', async () => {
  const config = providerConfig()
  const fake = createFakeDockerSpawn(config)
  const execution = await runDockerProvider({
    config,
    packet: providerPacket(),
    artifacts: providerArtifacts(),
    spawnImpl: fake.spawnImpl,
    randomBytesImpl: deterministicRandomBytes,
    randomUUIDImpl: () => '12345678-1234-1234-1234-1234567890ab',
  })

  assert.equal(execution.receipt.backend.container_id, fake.containerId)
  assert.ok(fake.calls.length >= 8)
  for (const call of fake.calls) {
    assert.equal(call.executable, config.runtime_path)
    assert.equal(call.options.shell, false)
    assert.deepEqual(call.args.slice(0, 2), ['--context', 'default'])
    assert.equal(call.options.env.DOCKER_HOST, undefined)
    assert.equal(call.options.env.DOCKER_CONTEXT, undefined)
  }

  const create = fake.calls.find(({ args }) => args.includes('create'))
  assert.ok(create)
  assert.equal(create.args.includes('--pull=never'), true)
  assert.equal(create.args.includes('--network=none'), true)
  assert.equal(create.args.includes('--read-only'), true)
  assert.equal(create.args.includes('--cap-drop=ALL'), true)
  assert.equal(
    create.args.some((value) => value.startsWith('--volume=')),
    false,
  )
  assert.equal(
    JSON.stringify(fake.calls).includes(config.receipt_signing_private_key_path),
    false,
  )

  const cleanupCalls = fake.calls.filter(
    ({ args }) => args.includes('kill') || args.includes('rm'),
  )
  assert.equal(cleanupCalls.length, 2)
  assert.ok(cleanupCalls.every(({ args }) => args.includes(fake.containerName)))
  assert.ok(cleanupCalls.some(({ args }) => args.includes('--signal=KILL')))
  assert.ok(cleanupCalls.some(({ args }) => args.includes('--volumes')))
})

test('Docker runner preserves an unverified orphan after ambiguous create failure', async () => {
  const config = providerConfig()
  const fake = createFakeDockerSpawn(config, {
    createCode: 1,
    createLeavesContainer: true,
    removeCode: 1,
    removeLeavesContainer: true,
  })

  await assert.rejects(
    runDockerProvider({
      config,
      packet: providerPacket(),
      artifacts: providerArtifacts(),
      spawnImpl: fake.spawnImpl,
      randomBytesImpl: deterministicRandomBytes,
      randomUUIDImpl: () => '12345678-1234-1234-1234-1234567890ab',
    }),
    (error) => (
      error instanceof ProviderRunnerError
      && error.code === 'PROVIDER_DOCKER_COMMAND_FAILED'
      && error.cleanup_error instanceof ProviderRunnerError
      && error.cleanup_error.code === 'PROVIDER_CLEANUP_UNVERIFIED'
      && error.cleanup_error.container_absence_verified === false
      && error.cleanup_error.container_name === fake.containerName
    ),
  )
  assert.equal(fake.containerExists, true)
  assert.equal(
    fake.calls.some(({ args }) => (
      args.includes('container')
      && args.includes('inspect')
      && args.includes(fake.containerName)
    )),
    true,
  )
})

test('Docker runner rejects a successful execution when cleanup remains unverified', async () => {
  const config = providerConfig()
  const fake = createFakeDockerSpawn(config, {
    removeCode: 1,
    removeLeavesContainer: true,
  })

  await assert.rejects(
    runDockerProvider({
      config,
      packet: providerPacket(),
      artifacts: providerArtifacts(),
      spawnImpl: fake.spawnImpl,
      randomBytesImpl: deterministicRandomBytes,
      randomUUIDImpl: () => '12345678-1234-1234-1234-1234567890ab',
    }),
    (error) => (
      error instanceof ProviderRunnerError
      && error.code === 'PROVIDER_CLEANUP_UNVERIFIED'
      && error.container_absence_verified === false
      && error.partial_receipt?.deliveries.length === 1
      && error.partial_receipt.deliveries[0].events.length === 2
    ),
  )
  assert.equal(fake.containerExists, true)
})

test('Docker runner accepts nonzero removal only after exact-name absence is proven', async () => {
  const config = providerConfig()
  const fake = createFakeDockerSpawn(config, {
    createSpawnFailure: true,
    removeCode: 1,
    removeLeavesContainer: false,
  })

  await assert.rejects(
    runDockerProvider({
      config,
      packet: providerPacket(),
      artifacts: providerArtifacts(),
      spawnImpl: fake.spawnImpl,
      randomBytesImpl: deterministicRandomBytes,
      randomUUIDImpl: () => '12345678-1234-1234-1234-1234567890ab',
    }),
    (error) => (
      error instanceof ProviderRunnerError
      && error.code === 'PROVIDER_DOCKER_SPAWN_FAILED'
      && error.cleanup_error === undefined
    ),
  )
  assert.equal(fake.containerExists, false)
  assert.equal(
    fake.calls.some(({ args }) => (
      args.includes('container')
      && args.includes('ls')
      && args.includes(`--filter=name=^/${fake.containerName}$`)
    )),
    true,
  )
})

test('Docker create nonzero remains ambiguous after present-time absence proof', async () => {
  const config = providerConfig()
  const fake = createFakeDockerSpawn(config, {
    createCode: 1,
    createLeavesContainer: false,
    removeCode: 1,
    removeLeavesContainer: false,
  })

  await assert.rejects(
    runDockerProvider({
      config,
      packet: providerPacket(),
      artifacts: providerArtifacts(),
      spawnImpl: fake.spawnImpl,
      randomBytesImpl: deterministicRandomBytes,
      randomUUIDImpl: () => '12345678-1234-1234-1234-1234567890ab',
    }),
    (error) => (
      error instanceof ProviderRunnerError
      && error.code === 'PROVIDER_DOCKER_COMMAND_FAILED'
      && error.cleanup_error?.code === 'PROVIDER_CREATE_OUTCOME_UNVERIFIED'
      && error.cleanup_error.container_absence_verified === true
      && error.cleanup_error.create_outcome_verified === false
    ),
  )
  assert.equal(fake.containerExists, false)
})

test('Docker runner treats timed-out create as nonrecoverable despite present-time absence', async () => {
  const config = providerConfig({
    limits: {
      docker_command_timeout_ms: 1000,
    },
  })
  const fake = createFakeDockerSpawn(config, {
    createTimeout: true,
    createLeavesContainer: false,
    removeCode: 1,
    removeLeavesContainer: false,
  })

  await assert.rejects(
    holdEventLoopFor(
      runDockerProvider({
        config,
        packet: providerPacket(),
        artifacts: providerArtifacts(),
        spawnImpl: fake.spawnImpl,
        randomBytesImpl: deterministicRandomBytes,
        randomUUIDImpl: () => '12345678-1234-1234-1234-1234567890ab',
      }),
      2000,
    ),
    (error) => (
      error instanceof ProviderRunnerError
      && error.code === 'PROVIDER_DOCKER_COMMAND_TIMEOUT'
      && error.cleanup_error?.code === 'PROVIDER_CREATE_OUTCOME_UNVERIFIED'
      && error.cleanup_error.container_absence_verified === true
      && error.cleanup_error.create_outcome_verified === false
    ),
  )
  assert.equal(fake.containerExists, false)
  assert.equal(
    fake.calls.some(({ args }) => (
      args.includes('container')
      && args.includes('ls')
      && args.includes(`--filter=name=^/${fake.containerName}$`)
    )),
    true,
  )
})

test('Docker attach failure is consumed and exact cleanup completes before rejection', async () => {
  const config = providerConfig()
  const fake = createFakeDockerSpawn(config)
  const spawnImpl = (executable, args, options) => {
    if (!args.includes('start')) {
      return fake.spawnImpl(executable, args, options)
    }
    const child = new EventEmitter()
    child.stdin = new PassThrough()
    child.stdout = new PassThrough()
    child.stderr = new PassThrough()
    child.stdin.on('error', () => {})
    let closed = false
    child.kill = (signal = 'SIGKILL') => {
      queueMicrotask(() => {
        if (closed) return
        closed = true
        child.stdout.end()
        child.stderr.end()
        child.emit('close', null, signal)
      })
      return true
    }
    queueMicrotask(() => child.emit('error', new Error('attach transport failed')))
    return child
  }

  await assert.rejects(
    runDockerProvider({
      config,
      packet: providerPacket(),
      artifacts: providerArtifacts(),
      spawnImpl,
      randomBytesImpl: deterministicRandomBytes,
      randomUUIDImpl: () => '12345678-1234-1234-1234-1234567890ab',
    }),
    (error) => (
      error instanceof ProviderRunnerError
      && ['PROVIDER_ABORTED', 'PROVIDER_DOCKER_SPAWN_FAILED']
        .includes(error.code)
      && error.cleanup_error === undefined
    ),
  )
  assert.equal(fake.containerExists, false)
  assert.equal(
    fake.calls.some(({ args }) => (
      args.includes('container')
      && args.includes('ls')
      && args.includes(`--filter=name=^/${fake.containerName}$`)
    )),
    true,
  )
})

test('standalone cleanup rejects ambiguous inspect failure without positive absence proof', async () => {
  const config = providerConfig()
  const containerName = 'rta-provider-ambiguous-cleanup-test'
  const spawnImpl = (_executable, args) => {
    if (args.includes('context') && args.includes('inspect')) {
      return completedDockerCommand(
        `${JSON.stringify('npipe:////./pipe/docker_engine')}\n`,
      )
    }
    if (args.includes('container') && args.includes('inspect')) {
      return completedDockerCommand('', 1, 'container inspect unavailable')
    }
    if (args.includes('container') && args.includes('ls')) {
      return completedDockerCommand('', 1, 'daemon query unavailable')
    }
    throw new Error(`unexpected cleanup argv: ${JSON.stringify(args)}`)
  }

  await assert.rejects(
    cleanupDockerProviderContainer({
      config,
      containerName,
      spawnImpl,
    }),
    (error) => (
      error instanceof ProviderRunnerError
      && error.code === 'PROVIDER_CLEANUP_UNVERIFIED'
      && error.container_name === containerName
      && error.container_absence_verified === false
      && /daemon query unavailable/.test(error.stderr)
    ),
  )
})

test('broker permits only one outstanding artifact request', async () => {
  const providerStdout = new PassThrough()
  const providerStdin = new PassThrough()
  const broker = runProviderBroker({
    readable: providerStdout,
    writable: providerStdin,
    packet: providerPacket(),
    artifacts: providerArtifacts(),
    config: providerConfig(),
    backend: providerBackend(),
    randomBytesImpl: deterministicRandomBytes,
  })
  const provider = (async () => {
    for await (const frame of jsonLines(providerStdin)) {
      if (frame.type === 'provider_start') {
        for (const artifactId of [FILE_ARTIFACT_ID, 'controlartifactopaque01']) {
          sendJsonLine(providerStdout, {
            type: 'artifact_request',
            schema_version: '1.0.0',
            session_id: frame.session_id,
            artifact_id: artifactId,
          })
        }
      }
    }
  })()
  await assert.rejects(
    Promise.all([broker, provider]),
    (error) => (
      error instanceof ProviderRunnerError
      && error.code === 'PROVIDER_PROTOCOL_VIOLATION'
      && /second artifact/i.test(error.message)
    ),
  )
})

test('broker rejects a consumption acknowledgement before any artifact request', async () => {
  const harness = brokerHarness()
  const provider = (async () => {
    for await (const frame of jsonLines(harness.providerStdin)) {
      if (frame.type !== 'provider_start') continue
      sendJsonLine(harness.providerStdout, {
        type: 'artifact_consumed',
        schema_version: '1.0.0',
        session_id: frame.session_id,
        delivery_id: 'deliveryopaque0000001',
        artifact_id: FILE_ARTIFACT_ID,
        challenge_hmac_sha256: '0'.repeat(64),
      })
      harness.providerStdout.end()
      return
    }
  })()

  await assert.rejects(
    harness.broker,
    (error) => (
      error instanceof ProviderRunnerError
      && error.code === 'PROVIDER_PROTOCOL_VIOLATION'
      && /outstanding delivery/i.test(error.message)
      && error.partial_receipt.deliveries.length === 0
    ),
  )
  await provider
})

test('broker rejects a duplicate request after the first delivery was consumed', async () => {
  const harness = brokerHarness()
  const provider = (async () => {
    for await (const frame of jsonLines(harness.providerStdin)) {
      if (frame.type === 'provider_start') {
        sendJsonLine(harness.providerStdout, {
          type: 'artifact_request',
          schema_version: '1.0.0',
          session_id: frame.session_id,
          artifact_id: FILE_ARTIFACT_ID,
        })
        continue
      }
      if (frame.type !== 'artifact_delivery') continue
      sendJsonLine(harness.providerStdout, artifactConsumedFrame(frame))
      sendJsonLine(harness.providerStdout, {
        type: 'artifact_request',
        schema_version: '1.0.0',
        session_id: frame.session_id,
        artifact_id: FILE_ARTIFACT_ID,
      })
      harness.providerStdout.end()
      return
    }
  })()

  await assert.rejects(
    harness.broker,
    (error) => (
      error instanceof ProviderRunnerError
      && error.code === 'PROVIDER_PROTOCOL_VIOLATION'
      && /same artifact more than once/i.test(error.message)
      && error.partial_receipt.deliveries[0].events.length === 2
    ),
  )
  await provider
})

test('broker rejects a duplicate acknowledgement after consumption', async () => {
  const harness = brokerHarness()
  const provider = (async () => {
    for await (const frame of jsonLines(harness.providerStdin)) {
      if (frame.type === 'provider_start') {
        sendJsonLine(harness.providerStdout, {
          type: 'artifact_request',
          schema_version: '1.0.0',
          session_id: frame.session_id,
          artifact_id: FILE_ARTIFACT_ID,
        })
        continue
      }
      if (frame.type !== 'artifact_delivery') continue
      const acknowledgement = artifactConsumedFrame(frame)
      sendJsonLine(harness.providerStdout, acknowledgement)
      sendJsonLine(harness.providerStdout, acknowledgement)
      harness.providerStdout.end()
      return
    }
  })()

  await assert.rejects(
    harness.broker,
    (error) => (
      error instanceof ProviderRunnerError
      && error.code === 'PROVIDER_PROTOCOL_VIOLATION'
      && /outstanding delivery/i.test(error.message)
      && error.partial_receipt.deliveries[0].events.length === 2
    ),
  )
  await provider
})

test('broker rejects a terminal result reordered before delivery acknowledgement', async () => {
  const packet = providerPacket()
  const harness = brokerHarness()
  const provider = (async () => {
    for await (const frame of jsonLines(harness.providerStdin)) {
      if (frame.type === 'provider_start') {
        sendJsonLine(harness.providerStdout, {
          type: 'artifact_request',
          schema_version: '1.0.0',
          session_id: frame.session_id,
          artifact_id: FILE_ARTIFACT_ID,
        })
        continue
      }
      if (frame.type !== 'artifact_delivery') continue
      sendJsonLine(harness.providerStdout, {
        type: 'job_result',
        schema_version: '1.0.0',
        session_id: frame.session_id,
        result: successfulJobResult(packet),
      })
      harness.providerStdout.end()
      return
    }
  })()

  await assert.rejects(
    harness.broker,
    (error) => (
      error instanceof ProviderRunnerError
      && error.code === 'PROVIDER_PROTOCOL_VIOLATION'
      && /before the outstanding delivery was consumed/i.test(error.message)
      && error.partial_receipt.deliveries[0].events.length === 1
    ),
  )
  await provider
})

test('broker rejects malformed provider JSON without accepting a result', async () => {
  const harness = brokerHarness()
  const provider = (async () => {
    for await (const frame of jsonLines(harness.providerStdin)) {
      if (frame.type !== 'provider_start') continue
      harness.providerStdout.end('{"type": definitely-not-json}\n')
      return
    }
  })()

  await assert.rejects(
    harness.broker,
    (error) => (
      error instanceof ProviderRunnerError
      && error.code === 'PROVIDER_PROTOCOL_VIOLATION'
      && /invalid JSONL/i.test(error.message)
      && error.partial_receipt.deliveries.length === 0
    ),
  )
  await provider
})

test('broker rejects both terminated and unterminated oversized stdout frames', async (t) => {
  for (const [name, terminator] of [
    ['terminated', '\n'],
    ['unterminated', ''],
  ]) {
    await t.test(name, async () => {
      const config = providerConfig({
        limits: {
          max_frame_bytes: 16384,
          max_stdout_bytes: 32768,
        },
      })
      const harness = brokerHarness(config)
      const provider = (async () => {
        for await (const frame of jsonLines(harness.providerStdin)) {
          if (frame.type !== 'provider_start') continue
          harness.providerStdout.end(`${'x'.repeat(16385)}${terminator}`)
          return
        }
      })()

      await assert.rejects(
        harness.broker,
        (error) => (
          error instanceof ProviderRunnerError
          && error.code === 'PROVIDER_FRAME_LIMIT'
          && error.partial_receipt.deliveries.length === 0
        ),
      )
      await provider
    })
  }
})

test('broker rejects aggregate provider stdout beyond its byte budget', async () => {
  const config = providerConfig({
    limits: {
      max_frame_bytes: 16384,
      max_stdout_bytes: 16384,
    },
  })
  const harness = brokerHarness(config)
  const provider = (async () => {
    for await (const frame of jsonLines(harness.providerStdin)) {
      if (frame.type !== 'provider_start') continue
      harness.providerStdout.end(Buffer.alloc(16385, 0x78))
      return
    }
  })()

  await assert.rejects(
    harness.broker,
    (error) => (
      error instanceof ProviderRunnerError
      && error.code === 'PROVIDER_STDOUT_LIMIT'
      && error.partial_receipt.deliveries.length === 0
    ),
  )
  await provider
})

test('broker fails closed when provider stdout stays idle', async () => {
  const config = providerConfig({
    limits: {
      wall_time_ms: 4000,
      idle_timeout_ms: 1000,
      delivery_timeout_ms: 3000,
    },
  })
  const harness = brokerHarness(config)

  await assert.rejects(
    holdEventLoopFor(harness.broker, 2000),
    (error) => (
      error instanceof ProviderRunnerError
      && error.code === 'PROVIDER_IDLE_TIMEOUT'
      && error.partial_receipt.deliveries.length === 0
    ),
  )
})

test('incomplete slow-drip stdout does not reset the complete-frame idle deadline', async () => {
  const config = providerConfig({
    limits: {
      wall_time_ms: 4000,
      idle_timeout_ms: 1000,
      delivery_timeout_ms: 3000,
    },
  })
  const harness = brokerHarness(config)
  let dripTimer
  const provider = (async () => {
    for await (const frame of jsonLines(harness.providerStdin)) {
      if (frame.type !== 'provider_start') continue
      dripTimer = setInterval(() => {
        if (!harness.providerStdout.destroyed) harness.providerStdout.write('x')
      }, 150)
      return
    }
  })()

  try {
    await assert.rejects(
      holdEventLoopFor(harness.broker, 2000),
      (error) => (
        error instanceof ProviderRunnerError
        && error.code === 'PROVIDER_IDLE_TIMEOUT'
      ),
    )
    await provider
  } finally {
    clearInterval(dripTimer)
  }
})

test('broker times out a delivered artifact that is never acknowledged', async () => {
  const config = providerConfig({
    limits: {
      wall_time_ms: 4000,
      idle_timeout_ms: 3000,
      delivery_timeout_ms: 1000,
    },
  })
  const harness = brokerHarness(config)
  const delivered = (async () => {
    for await (const frame of jsonLines(harness.providerStdin)) {
      if (frame.type === 'provider_start') {
        sendJsonLine(harness.providerStdout, {
          type: 'artifact_request',
          schema_version: '1.0.0',
          session_id: frame.session_id,
          artifact_id: FILE_ARTIFACT_ID,
        })
        continue
      }
      if (frame.type === 'artifact_delivery') return
    }
  })()

  await assert.rejects(
    holdEventLoopFor(harness.broker, 2000),
    (error) => (
      error instanceof ProviderRunnerError
      && error.code === 'PROVIDER_DELIVERY_TIMEOUT'
      && error.partial_receipt.deliveries[0].events.length === 1
      && error.partial_receipt.deliveries[0].events[0].state === 'DELIVERED'
    ),
  )
  await delivered
})

test('broker preserves a partial receipt when execution is externally aborted', async () => {
  const config = providerConfig()
  const providerStdout = new PassThrough()
  const providerStdin = new PassThrough()
  providerStdin.on('error', () => {})
  const abortController = new AbortController()
  const abortReason = new Error('controller shutdown')
  abortController.abort(abortReason)

  await assert.rejects(
    runProviderBroker({
      readable: providerStdout,
      writable: providerStdin,
      packet: providerPacket(),
      artifacts: providerArtifacts(),
      config,
      backend: providerBackend(),
      signal: abortController.signal,
      randomBytesImpl: deterministicRandomBytes,
    }),
    (error) => (
      error instanceof ProviderRunnerError
      && error.code === 'PROVIDER_ABORTED'
      && error.cause === abortReason
      && error.partial_receipt.deliveries.length === 0
    ),
  )
})

test('Docker runner bounds provider stderr and still removes the exact container', async () => {
  const config = providerConfig({
    limits: {
      max_stderr_bytes: 1024,
    },
  })
  const fake = createFakeDockerSpawn(config)
  const spawnImpl = (executable, args, options) => {
    if (args.includes('start')) {
      return hostileStartChild((child) => {
        child.stderr.write(Buffer.alloc(config.limits.max_stderr_bytes + 1, 0x78))
      })
    }
    return fake.spawnImpl(executable, args, options)
  }

  await assert.rejects(
    runDockerProvider({
      config,
      packet: providerPacket(),
      artifacts: providerArtifacts(),
      spawnImpl,
      randomBytesImpl: deterministicRandomBytes,
      randomUUIDImpl: () => '12345678-1234-1234-1234-1234567890ab',
    }),
    (error) => (
      error instanceof ProviderRunnerError
      && error.code === 'PROVIDER_STDERR_LIMIT'
      && error.stderr.length === config.limits.max_stderr_bytes
    ),
  )

  const cleanupCalls = fake.calls.filter(
    ({ args }) => args.includes('kill') || args.includes('rm'),
  )
  assert.equal(cleanupCalls.length, 2)
  assert.ok(cleanupCalls.every(({ args }) => args.includes(fake.containerName)))
})

test('Docker control-plane command output is killed at its fixed byte limit', async () => {
  let killedWith
  const spawnImpl = () => {
    const child = new EventEmitter()
    child.stdin = null
    child.stdout = new PassThrough()
    child.stderr = new PassThrough()
    child.kill = (signal) => {
      killedWith = signal
      return true
    }
    queueMicrotask(() => {
      child.stdout.write(Buffer.alloc((2 * 1024 * 1024) + 1, 0x78))
    })
    return child
  }

  await assert.rejects(
    runDockerProvider({
      config: providerConfig(),
      packet: providerPacket(),
      artifacts: providerArtifacts(),
      spawnImpl,
      randomBytesImpl: deterministicRandomBytes,
      randomUUIDImpl: () => '12345678-1234-1234-1234-1234567890ab',
    }),
    (error) => (
      error instanceof ProviderRunnerError
      && error.code === 'PROVIDER_DOCKER_OUTPUT_LIMIT'
    ),
  )
  assert.equal(killedWith, 'SIGKILL')
})

test('broker stream error guards outlive the call for the child lifetime', async () => {
  const control = new PassThrough()
  control.end('drained\n')
  for await (const chunk of control) {
    assert.ok(chunk)
  }
  const runtimeGuards = control.listenerCount('error')

  const harness = brokerHarness()
  await runHonestProvider({
    stdin: harness.providerStdin,
    stdout: harness.providerStdout,
  })
  const execution = await harness.broker
  assert.equal(execution.job_result.state, 'SUCCEEDED')
  assert.equal(harness.providerStdout.listenerCount('error'), runtimeGuards + 1)
  harness.providerStdout.emit('error', new Error('late attach teardown'))
  harness.providerStdin.emit('error', new Error('late attach teardown'))
})

test('CONTROL artifact names cannot escape a gateway materialization root', () => {
  const limits = providerConfig().limits
  const controlArtifact = (logicalName) => [{
    artifact_id: 'controlartifactopaque01',
    kind: 'CONTROL',
    logical_name: logicalName,
    bytes: Buffer.from('* * * * * root id\n'),
  }]
  for (const logicalName of [
    '../../../../etc/cron.d/x',
    '/etc/cron.d/x',
    'C:/windows/system32/x',
    'controls\\x',
    'controls/./x',
    'controls//x',
    'controls/',
  ]) {
    assert.throws(
      () => normalizeProviderArtifacts(controlArtifact(logicalName), limits),
      (error) => (
        error instanceof ProviderRunnerError
        && error.code === 'PROVIDER_ARTIFACT_INVALID'
      ),
      logicalName,
    )
  }
  assert.equal(
    normalizeProviderArtifacts(
      controlArtifact('lens:web-and-api@1.0.0'),
      limits,
    )[0].logical_name,
    'lens:web-and-api@1.0.0',
  )
})

test('container names exclude Docker name-filter regex metacharacters', () => {
  assert.throws(
    () => buildDockerCleanupArgs('rta-provider-a.bcdefgh'),
    (error) => (
      error instanceof ProviderRunnerError
      && error.code === 'PROVIDER_CONTAINER_NAME_INVALID'
    ),
  )
  assert.equal(
    buildDockerCleanupArgs('rta-provider-abcdefgh').kill.at(-1),
    'rta-provider-abcdefgh',
  )
})

function hardenedLinuxInspection(config, containerName) {
  return {
    Id: 'b'.repeat(64),
    Name: `/${containerName}`,
    Platform: 'linux',
    Mounts: [],
    Config: {
      User: '65532:65532',
      WorkingDir: '/work',
      OpenStdin: true,
      Tty: false,
      AttachStdout: true,
      AttachStderr: true,
      Env: [
        'HTTP_PROXY=',
        'HTTPS_PROXY=',
        'NO_PROXY=',
        'ALL_PROXY=',
        'http_proxy=',
        'https_proxy=',
        'no_proxy=',
        'all_proxy=',
      ],
      Volumes: null,
      Healthcheck: { Test: ['NONE'] },
    },
    HostConfig: {
      NetworkMode: 'none',
      ReadonlyRootfs: true,
      Privileged: false,
      CapAdd: null,
      CapDrop: ['ALL'],
      SecurityOpt: ['no-new-privileges=true', 'seccomp=builtin'],
      PidsLimit: config.limits.pids,
      Memory: config.limits.memory_bytes,
      MemorySwap: config.limits.memory_bytes,
      NanoCpus: Math.round(config.limits.cpus * 1_000_000_000),
      Ulimits: [{
        Name: 'nofile',
        Soft: config.limits.nofile,
        Hard: config.limits.nofile,
      }],
      IpcMode: 'none',
      PidMode: 'private',
      UsernsMode: '',
      CgroupnsMode: 'private',
      Sysctls: {},
      GroupAdd: null,
      AppArmorProfile: 'docker-default',
      Runtime: 'runc',
      Isolation: '',
      MaskedPaths: [
        '/proc/asound',
        '/proc/acpi',
        '/proc/kcore',
        '/proc/keys',
        '/proc/latency_stats',
        '/proc/timer_list',
        '/proc/sched_debug',
        '/proc/scsi',
        '/sys/firmware',
        '/sys/devices/virtual/powercap',
      ],
      ReadonlyPaths: [
        '/proc/bus',
        '/proc/fs',
        '/proc/irq',
        '/proc/sys',
        '/proc/sysrq-trigger',
      ],
      LogConfig: { Type: 'none', Config: {} },
      RestartPolicy: { Name: 'no', MaximumRetryCount: 0 },
      Binds: null,
      Mounts: [],
      VolumesFrom: null,
      Devices: [],
      DeviceRequests: null,
      Links: null,
      ExtraHosts: null,
      PortBindings: {},
      PublishAllPorts: false,
      Tmpfs: {
        '/work': `rw,noexec,nosuid,nodev,size=${config.limits.tmpfs_bytes},mode=0700,uid=65532,gid=65532`,
      },
    },
  }
}

test('hardened inspection proves the escape-relevant kernel surface', () => {
  const config = providerConfig()
  const containerName = 'rta-provider-kernel-surface'
  assert.equal(
    assertHardenedDockerInspection(
      hardenedLinuxInspection(config, containerName),
      config,
      containerName,
    ),
    'b'.repeat(64),
  )

  for (const [field, weaken] of [
    ['MaskedPaths', (host) => {
      host.MaskedPaths = host.MaskedPaths.filter((path) => path !== '/proc/kcore')
    }],
    ['MaskedPaths absent', (host) => { delete host.MaskedPaths }],
    ['ReadonlyPaths', (host) => {
      host.ReadonlyPaths = host.ReadonlyPaths
        .filter((path) => path !== '/proc/sysrq-trigger')
    }],
    ['UsernsMode', (host) => { host.UsernsMode = 'host' }],
    ['CgroupnsMode', (host) => { host.CgroupnsMode = 'host' }],
    ['Sysctls', (host) => { host.Sysctls = { 'kernel.domainname': 'escape' } }],
    ['GroupAdd', (host) => { host.GroupAdd = ['docker'] }],
    ['AppArmorProfile', (host) => { host.AppArmorProfile = 'unconfined' }],
    ['Runtime', (host) => { host.Runtime = 'nvidia' }],
    ['Isolation', (host) => { host.Isolation = 'process' }],
  ]) {
    const inspection = hardenedLinuxInspection(config, containerName)
    weaken(inspection.HostConfig)
    assert.throws(
      () => assertHardenedDockerInspection(inspection, config, containerName),
      (error) => (
        error instanceof ProviderRunnerError
        && error.code === 'PROVIDER_DOCKER_PROFILE_MISMATCH'
      ),
      field,
    )
  }

  const withoutLinuxFields = hardenedLinuxInspection(config, containerName)
  delete withoutLinuxFields.Platform
  for (const field of [
    'MaskedPaths',
    'ReadonlyPaths',
    'UsernsMode',
    'CgroupnsMode',
    'Sysctls',
    'GroupAdd',
    'AppArmorProfile',
    'Runtime',
    'Isolation',
  ]) {
    delete withoutLinuxFields.HostConfig[field]
  }
  assert.equal(
    assertHardenedDockerInspection(withoutLinuxFields, config, containerName),
    'b'.repeat(64),
  )
})

test('the provider wall-time budget, not one Docker command slot, bounds the attach', async () => {
  const config = providerConfig({
    limits: {
      wall_time_ms: 5000,
      docker_command_timeout_ms: 1000,
      idle_timeout_ms: 4000,
      delivery_timeout_ms: 4000,
    },
  })
  const fake = createFakeDockerSpawn(config)
  const spawnImpl = (executable, args, options) => {
    if (!args.includes('start')) {
      return fake.spawnImpl(executable, args, options)
    }
    return hostileStartChild((child, close) => {
      setTimeout(async () => {
        await runHonestProvider({ stdin: child.stdin, stdout: child.stdout })
        close(0, null)
      }, config.limits.docker_command_timeout_ms + 400)
    })
  }

  const execution = await holdEventLoopFor(
    runDockerProvider({
      config,
      packet: providerPacket(),
      artifacts: providerArtifacts(),
      spawnImpl,
      randomBytesImpl: deterministicRandomBytes,
      randomUUIDImpl: () => '12345678-1234-1234-1234-1234567890ab',
    }),
    4000,
  )
  assert.equal(execution.job_result.state, 'SUCCEEDED')
  assert.equal(execution.receipt.deliveries.length, 1)
  assert.equal(fake.containerExists, false)
})

test('a stuck attach client is reported beside the broker failure it caused', async () => {
  const config = providerConfig({ limits: { docker_command_timeout_ms: 1000 } })
  const fake = createFakeDockerSpawn(config)
  const spawnImpl = (executable, args, options) => {
    if (!args.includes('start')) {
      return fake.spawnImpl(executable, args, options)
    }
    const child = new EventEmitter()
    child.stdin = new PassThrough()
    child.stdout = new PassThrough()
    child.stderr = new PassThrough()
    child.stdin.on('error', () => {})
    child.kill = () => true
    queueMicrotask(() => child.stdout.write('not-a-protocol-frame\n'))
    return child
  }

  await assert.rejects(
    holdEventLoopFor(
      runDockerProvider({
        config,
        packet: providerPacket(),
        artifacts: providerArtifacts(),
        spawnImpl,
        randomBytesImpl: deterministicRandomBytes,
        randomUUIDImpl: () => '12345678-1234-1234-1234-1234567890ab',
      }),
      3000,
    ),
    (error) => (
      error instanceof ProviderRunnerError
      && error.code === 'PROVIDER_PROTOCOL_VIOLATION'
      && error.exit_error?.code === 'PROVIDER_DOCKER_EXIT_TIMEOUT'
    ),
  )
  assert.equal(fake.containerExists, false)
})
