import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  assertHardenedDatabaseContainerInspection,
  assertLocalDatabaseDockerContextHost,
  assertSafeDatabaseImageInspection,
  buildDatabaseDockerCreateArgs,
  conformanceCheck,
  databaseConformanceContainerName,
  runDatabaseConformanceEngine,
  scenarioResult,
} from '../scripts/lib/database-conformance-runner.mjs'
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
