import assert from 'node:assert/strict'
import { test } from 'node:test'
import { EventEmitter } from 'node:events'
import { createHash } from 'node:crypto'
import {
  assertHardenedDatabaseContainerInspection,
  assertLocalDatabaseDockerContextHost,
  assertSafeDatabaseImageInspection,
  buildDatabaseDockerCreateArgs,
  conformanceCheck,
  databaseConformanceContainerName,
  databaseDockerCreateEnvironment,
  runDatabaseConformanceEngine,
  runDatabaseDockerCommand,
  scenarioResult,
} from '../scripts/lib/database-conformance-runner.mjs'
import { recordReadiness } from '../scripts/lib/database-conformance-scenarios.mjs'
import { databaseConformanceManifest } from '../scripts/lib/database-conformance-contracts.mjs'

const RUN_ID = 'db-lab:2026-07-30T14:00:00.000Z:abcdef123456'
const IMAGE_ID = `sha256:${'a'.repeat(64)}`
const CONTAINER_ID = 'b'.repeat(64)

function config() {
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

function engine(engineId = 'postgresql-18.4') {
  return databaseConformanceManifest.engines.find(
    ({ engine_id: candidate }) => candidate === engineId,
  )
}

function expectedPaths(engineId) {
  return engineId === 'postgresql-18.4'
    ? ['/var/lib/postgresql', '/var/run/postgresql', '/tmp']
    : ['/var/lib/mysql', '/var/lib/mysql-files', '/var/run/mysqld', '/tmp']
}

function hardenedInspection(engineId = 'postgresql-18.4') {
  const selected = engine(engineId)
  const containerName = databaseConformanceContainerName(RUN_ID, engineId)
  const tmpfs = Object.fromEntries(expectedPaths(engineId).map((path, index) => [
    path,
    `rw,noexec,nosuid,nodev,size=${index === 0 ? 536_870_912 : 67_108_864},` +
      `mode=${path === '/tmp' ? '1770' : '0700'},uid=999,gid=999`,
  ]))
  return {
    Id: CONTAINER_ID,
    Name: `/${containerName}`,
    Image: IMAGE_ID,
    Config: {
      User: engineId === 'postgresql-18.4' ? 'postgres:postgres' : 'mysql:mysql',
      Labels: {
        'dev.red-team-audit.owner': 'database-conformance',
        'dev.red-team-audit.run-id': RUN_ID,
        'dev.red-team-audit.engine-id': engineId,
      },
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
      Healthcheck: {
        Test: ['NONE'],
      },
      Image: selected.image,
    },
    HostConfig: {
      NetworkMode: 'none',
      ReadonlyRootfs: true,
      Privileged: false,
      CapAdd: null,
      CapDrop: ['ALL'],
      SecurityOpt: ['no-new-privileges=true', 'seccomp=builtin'],
      PidsLimit: 256,
      Memory: 1_073_741_824,
      MemorySwap: 1_073_741_824,
      NanoCpus: 2_000_000_000,
      Ulimits: [{
        Name: 'nofile',
        Soft: 1024,
        Hard: 1024,
      }],
      IpcMode: 'private',
      PidMode: '',
      LogConfig: {
        Type: 'none',
      },
      RestartPolicy: {
        Name: 'no',
      },
      Binds: null,
      Mounts: null,
      VolumesFrom: null,
      Devices: null,
      DeviceRequests: null,
      Links: null,
      ExtraHosts: null,
      PortBindings: {},
      PublishAllPorts: false,
      Tmpfs: tmpfs,
    },
    Mounts: expectedPaths(engineId).map((Destination) => ({
      Type: 'tmpfs',
      Destination,
      RW: true,
    })),
  }
}

test('database create arguments enforce the isolated bounded profile', () => {
  for (const selected of databaseConformanceManifest.engines) {
    const containerName = databaseConformanceContainerName(RUN_ID, selected.engine_id)
    const args = buildDatabaseDockerCreateArgs({
      engine: selected,
      config: config(),
      runId: RUN_ID,
      containerName,
      secret: 'synthetic-secret',
    })
    assert.deepEqual(args.slice(0, 3), ['--context', 'default', 'create'])
    for (const required of [
      '--pull=never',
      '--network=none',
      '--read-only',
      '--cap-drop=ALL',
      '--security-opt=no-new-privileges=true',
      '--security-opt=seccomp=builtin',
      '--ipc=private',
      '--log-driver=none',
      '--restart=no',
      '--no-healthcheck',
    ]) {
      assert.ok(args.includes(required), `${selected.engine_id} lacks ${required}`)
    }
    assert.ok(args.includes(selected.image))
    assert.equal(args.some((value) => value.startsWith('--volume=')), false)
    assert.equal(args.some((value) => value.startsWith('--mount=')), false)
    assert.equal(args.some((value) => value.startsWith('--publish=')), false)
    for (const proxy of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY']) {
      assert.ok(args.includes(`--env=${proxy}=`))
    }
  }
})

test('only local Docker context endpoints are accepted', () => {
  assert.equal(assertLocalDatabaseDockerContextHost('unix:///var/run/docker.sock'),
    'unix:///var/run/docker.sock')
  assert.equal(assertLocalDatabaseDockerContextHost('npipe:////./pipe/docker_engine'),
    'npipe:////./pipe/docker_engine')
  assert.throws(
    () => assertLocalDatabaseDockerContextHost('tcp://docker.example:2376'),
    /must use a local unix:\/\/ or npipe:\/\//,
  )
})

test('image inspection binds the exact digest and permits only planned data volumes', () => {
  const selected = engine()
  const identity = assertSafeDatabaseImageInspection({
    Id: IMAGE_ID,
    Os: 'linux',
    Architecture: 'amd64',
    RepoDigests: [selected.image],
    Config: {
      Volumes: {
        '/var/lib/postgresql': {},
      },
    },
  }, selected)
  assert.equal(identity.imageId, IMAGE_ID)

  assert.throws(() => assertSafeDatabaseImageInspection({
    Id: IMAGE_ID,
    Os: 'linux',
    Architecture: 'amd64',
    RepoDigests: [selected.image],
    Config: {
      Volumes: {
        '/host-secrets': {},
      },
    },
  }, selected), /volume outside the controller-owned tmpfs set/)
})

test('container inspection rejects network, mount, identity, and cleanup-profile drift', () => {
  const selected = engine()
  const containerName = databaseConformanceContainerName(RUN_ID, selected.engine_id)
  assert.equal(assertHardenedDatabaseContainerInspection({
    inspection: hardenedInspection(),
    engine: selected,
    config: config(),
    runId: RUN_ID,
    containerName,
    imageId: IMAGE_ID,
  }), CONTAINER_ID)

  for (const mutate of [
    (value) => { value.HostConfig.NetworkMode = 'bridge' },
    (value) => { value.HostConfig.Binds = ['C:\\secrets:/secrets:ro'] },
    (value) => { value.HostConfig.PortBindings = { '5432/tcp': [{}] } },
    (value) => { value.HostConfig.CapDrop = [] },
    (value) => { value.Config.Labels['dev.red-team-audit.run-id'] = 'other-run' },
    (value) => { value.Mounts.push({ Type: 'bind', Destination: '/host', RW: false }) },
  ]) {
    const forged = structuredClone(hardenedInspection())
    mutate(forged)
    assert.throws(() => assertHardenedDatabaseContainerInspection({
      inspection: forged,
      engine: selected,
      config: config(),
      runId: RUN_ID,
      containerName,
      imageId: IMAGE_ID,
    }))
  }
})

function fakeDocker({ stale = false, refuseRemoval = false } = {}) {
  let exists = stale
  let removals = 0
  const selected = engine()
  const inspection = () => hardenedInspection()
  return {
    get removals() {
      return removals
    },
    async command(args) {
      const operation = args[2]
      if (operation === 'context') {
        return {
          code: 0,
          signal: null,
          stdout: `${JSON.stringify('npipe:////./pipe/docker_engine')}\n`,
          stderr: '',
        }
      }
      if (operation === 'version') {
        return {
          code: 0,
          signal: null,
          stdout: `${JSON.stringify('29.5.3')}\n`,
          stderr: '',
        }
      }
      if (operation === 'image') {
        return {
          code: 0,
          signal: null,
          stdout: `${JSON.stringify({
            Id: IMAGE_ID,
            Os: 'linux',
            Architecture: 'amd64',
            RepoDigests: [selected.image],
            Config: {
              Volumes: {
                '/var/lib/postgresql': {},
              },
            },
          })}\n`,
          stderr: '',
        }
      }
      if (operation === 'create') {
        exists = true
        return {
          code: 0,
          signal: null,
          stdout: `${CONTAINER_ID}\n`,
          stderr: '',
        }
      }
      if (operation !== 'container') throw new Error(`unexpected Docker args ${args}`)
      const subcommand = args[3]
      if (subcommand === 'inspect') {
        return exists
          ? {
              code: 0,
              signal: null,
              stdout: `${JSON.stringify(inspection())}\n`,
              stderr: '',
            }
          : {
              code: 1,
              signal: null,
              stdout: '',
              stderr: 'No such container',
            }
      }
      if (subcommand === 'ls') {
        return {
          code: 0,
          signal: null,
          stdout: exists ? `${CONTAINER_ID}\n` : '',
          stderr: '',
        }
      }
      if (subcommand === 'start' || subcommand === 'kill') {
        return {
          code: 0,
          signal: null,
          stdout: '',
          stderr: '',
        }
      }
      if (subcommand === 'rm') {
        removals += 1
        if (!refuseRemoval) exists = false
        return {
          code: 0,
          signal: null,
          stdout: '',
          stderr: '',
        }
      }
      throw new Error(`unexpected Docker subcommand ${subcommand}`)
    },
  }
}

async function fakeScenarios({ engine: selected }) {
  const transcript = [{
    step: 'synthetic.oracle',
    code: 0,
    stdout: 'ok',
    stderr: '',
  }]
  return {
    serverVersion: '18.4',
    scenarios: selected.scenario_rules.map((binding) => scenarioResult(binding, [
      conformanceCheck(
        `${binding.scenario_id}.oracle`,
        'PASSED',
        'Synthetic positive and negative controls matched.',
      ),
    ])),
    transcript,
    transcript_sha256:
      '8a7d805fd9956563e451e1ebfc8efbbb3c87634fd3831346f19d1f7720cae2e9',
    gaps: [],
  }
}

test('engine lifecycle records controller-observed results and verifies cleanup', async () => {
  const docker = fakeDocker()
  const result = await runDatabaseConformanceEngine({
    runId: RUN_ID,
    engineId: 'postgresql-18.4',
    config: config(),
    executeScenarios: fakeScenarios,
    commandImpl: docker.command,
    now: () => new Date('2026-07-30T14:00:00.000Z'),
    randomBytesImpl: () => Buffer.alloc(24, 1),
  })
  assert.equal(result.state, 'PASSED')
  assert.equal(result.assurance_scope,
    'CONTROLLER_OBSERVED_DISPOSABLE_ENGINE_BEHAVIOR')
  assert.equal(result.target_deployment_proven, false)
  assert.equal(result.cleanup.container_absent, true)
  assert.equal(result.scenarios.length, 8)
  assert.equal(docker.removals, 1)
})

test('engine lifecycle recovers only its exact stale labeled container', async () => {
  const docker = fakeDocker({ stale: true })
  const result = await runDatabaseConformanceEngine({
    runId: RUN_ID,
    engineId: 'postgresql-18.4',
    config: config(),
    executeScenarios: fakeScenarios,
    commandImpl: docker.command,
    now: () => new Date('2026-07-30T14:00:00.000Z'),
    randomBytesImpl: () => Buffer.alloc(24, 2),
  })
  assert.equal(result.state, 'PASSED')
  assert.equal(docker.removals, 2)
})

test('engine lifecycle fails closed when Docker cannot prove cleanup', async () => {
  const docker = fakeDocker({ refuseRemoval: true })
  await assert.rejects(
    runDatabaseConformanceEngine({
      runId: RUN_ID,
      engineId: 'postgresql-18.4',
      config: config(),
      executeScenarios: fakeScenarios,
      commandImpl: docker.command,
      now: () => new Date('2026-07-30T14:00:00.000Z'),
      randomBytesImpl: () => Buffer.alloc(24, 3),
    }),
    /could not remove its exact stale conformance container|did not prove.*absent/i,
  )
})

test('engine lifecycle enforces one hard wall-time budget across commands', async () => {
  const docker = fakeDocker()
  let tick = 0
  await assert.rejects(
    runDatabaseConformanceEngine({
      runId: RUN_ID,
      engineId: 'postgresql-18.4',
      config: {
        ...config(),
        limits: {
          ...config().limits,
          wall_time_ms: 120_000,
        },
      },
      executeScenarios: fakeScenarios,
      commandImpl: docker.command,
      monotonicNow: () => {
        tick += 80_000
        return tick
      },
      now: () => new Date('2026-07-30T14:00:00.000Z'),
      randomBytesImpl: () => Buffer.alloc(24, 4),
    }),
    /wall-time limit/i,
  )
})

function fakeChildProcess(code = 0) {
  const child = new EventEmitter()
  child.stdout = new EventEmitter()
  child.stderr = new EventEmitter()
  child.stdin = Object.assign(new EventEmitter(), { end() {} })
  child.kill = () => {}
  setImmediate(() => child.emit('close', code, null))
  return child
}

async function settle(rounds = 32) {
  for (let index = 0; index < rounds; index += 1) {
    await new Promise((resolve) => {
      setImmediate(resolve)
    })
  }
}

test('lab secrets reach the container through the environment, never through argv', () => {
  const secret = 'unit-test-lab-secret'
  for (const selected of databaseConformanceManifest.engines) {
    const args = buildDatabaseDockerCreateArgs({
      engine: selected,
      config: config(),
      runId: RUN_ID,
      containerName: databaseConformanceContainerName(RUN_ID, selected.engine_id),
      secret,
    })
    const key = selected.engine_id === 'postgresql-18.4'
      ? 'POSTGRES_PASSWORD'
      : 'MYSQL_ROOT_PASSWORD'

    assert.equal(
      args.some((value) => value.includes(secret)),
      false,
      `${selected.engine_id} leaked its secret into argv`,
    )
    assert.ok(args.includes(`--env=${key}`))
    assert.deepEqual(
      databaseDockerCreateEnvironment({ engine: selected, secret }),
      { [key]: secret },
    )
  }
})

test('the Docker child process receives the lab secret in its own environment', async () => {
  let observed
  const spawnImpl = (runtimePath, args, options) => {
    observed = options.env
    return fakeChildProcess()
  }

  const result = await runDatabaseDockerCommand({
    runtimePath: '/usr/bin/docker',
    args: ['--context', 'default', 'create'],
    spawnImpl,
    timeoutMs: 5_000,
    maxOutputBytes: 4_096,
    secretEnvironment: { POSTGRES_PASSWORD: 'unit-test-lab-secret' },
  })

  assert.equal(result.code, 0)
  assert.equal(observed.POSTGRES_PASSWORD, 'unit-test-lab-secret')

  await runDatabaseDockerCommand({
    runtimePath: '/usr/bin/docker',
    args: ['--context', 'default', 'version'],
    spawnImpl,
    timeoutMs: 5_000,
    maxOutputBytes: 4_096,
  })
  assert.equal(Object.hasOwn(observed, 'POSTGRES_PASSWORD'), false)
})

test('recorded evidence digests exactly the observation the result retains', () => {
  const truncated = conformanceCheck('db.long.evidence', 'PASSED', 'x'.repeat(4_096))
  assert.equal(truncated.observation.length, 2_048)
  assert.equal(
    truncated.evidence_sha256,
    createHash('sha256').update(Buffer.from(truncated.observation, 'utf8')).digest('hex'),
  )

  const empty = conformanceCheck('db.empty.evidence', 'PASSED', '   \r\n  ')
  assert.equal(
    empty.evidence_sha256,
    createHash('sha256').update(Buffer.from(empty.observation, 'utf8')).digest('hex'),
  )
})

test('an interrupt removes the exact container once and re-raises the signal', async () => {
  const docker = fakeDocker()
  const baseline = Object.fromEntries(
    ['SIGINT', 'SIGTERM'].map((signal) => [signal, process.listeners(signal)]),
  )
  const raised = []
  const realKill = process.kill.bind(process)
  process.kill = (pid, signal) => {
    raised.push(signal)
  }

  try {
    const result = await runDatabaseConformanceEngine({
      runId: RUN_ID,
      engineId: 'postgresql-18.4',
      config: config(),
      executeScenarios: async (options) => {
        const installed = ['SIGINT', 'SIGTERM'].map((signal) =>
          process.listeners(signal).filter((listener) =>
            !baseline[signal].includes(listener)))
        assert.deepEqual(installed.map((listeners) => listeners.length), [1, 1])
        for (const listeners of installed) listeners[0]()
        installed[0][0]()
        await settle(8)
        return fakeScenarios(options)
      },
      commandImpl: docker.command,
      now: () => new Date('2026-07-30T14:00:00.000Z'),
      randomBytesImpl: () => Buffer.alloc(24, 5),
    })

    await settle()
    assert.equal(result.cleanup.container_absent, true)
    assert.equal(docker.removals, 1)
    assert.deepEqual(raised, ['SIGINT'])
  } finally {
    process.kill = realKill
  }

  for (const signal of ['SIGINT', 'SIGTERM']) {
    assert.deepEqual(process.listeners(signal), baseline[signal])
  }
})

test('readiness polling is bounded to a recorded slice of the transcript budget', () => {
  const poll = (index) => ({
    step: 'postgresql-18.4.readiness',
    code: index % 2,
    stdout: `poll-${index}`,
    stderr: '',
  })

  const bounded = { transcript: [], gaps: [] }
  recordReadiness({
    ...bounded,
    polls: Array.from({ length: 600 }, (_, index) => poll(index)),
    label: 'postgresql-18.4',
  })
  assert.equal(bounded.transcript.length, 32)
  assert.equal(bounded.transcript[0].stdout, 'poll-0')
  assert.equal(bounded.transcript[7].stdout, 'poll-7')
  assert.equal(bounded.transcript[8].stdout, 'poll-576')
  assert.equal(bounded.transcript.at(-1).stdout, 'poll-599')
  assert.equal(bounded.gaps.length, 1)
  assert.equal(bounded.gaps[0].area, 'postgresql-18.4 readiness')
  assert.match(bounded.gaps[0].reason, /600 readiness polls exceeded/)

  const unbounded = { transcript: [], gaps: [] }
  recordReadiness({
    ...unbounded,
    polls: Array.from({ length: 32 }, (_, index) => poll(index)),
    label: 'postgresql-18.4',
  })
  assert.equal(unbounded.transcript.length, 32)
  assert.deepEqual(unbounded.gaps, [])
})
