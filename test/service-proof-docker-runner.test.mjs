import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import * as proofDocker from '../scripts/lib/proof-docker-runner.mjs'

const {
  CONTROLLER_DOCKER_RUNTIME,
  SERVICE_PROOF_SUPERVISOR_SOURCE,
  normalizeProofWorkerConfig,
  proofDependencyManifestDigest,
  proofWorkerConfigDigest,
} = proofDocker

test('create-bound service supervisor is syntactically valid controller code', () => {
  assert.doesNotThrow(() => new Function(SERVICE_PROOF_SUPERVISOR_SOURCE))
})

const IMAGE = `sha256:${'a'.repeat(64)}`
const EMPTY_SHA256 = createHash('sha256').digest('hex')
const DEPENDENCY_MANIFEST_SHA256 = proofDependencyManifestDigest(
  readFileSync(new URL('../package.json', import.meta.url)),
  readFileSync(new URL('../package-lock.json', import.meta.url)),
)
const PORT = 31_337
const SOURCE_ROOT = mkdtempSync(join(tmpdir(), 'rta-service-proof-source-'))
mkdirSync(join(SOURCE_ROOT, 'test', 'security'), { recursive: true })
for (const name of ['package.json', 'package-lock.json']) {
  writeFileSync(
    join(SOURCE_ROOT, name),
    readFileSync(new URL(`../${name}`, import.meta.url)),
  )
}
for (const name of ['service.mjs', 'attack.mjs', 'control.mjs']) {
  writeFileSync(join(SOURCE_ROOT, 'test', 'security', name), `// ${name}\n`)
}

function workerConfig(overrides = {}) {
  return {
    schema_version: '1.0.0',
    protocol: 'docker-proof-v1',
    runtime_path: CONTROLLER_DOCKER_RUNTIME,
    image: IMAGE,
    dependency_manifest_sha256: DEPENDENCY_MANIFEST_SHA256,
    limits: {
      wall_time_ms: 120_000,
      docker_command_timeout_ms: 30_000,
      max_source_bytes: 64 * 1024 * 1024,
      max_output_bytes: 1024 * 1024,
      memory_bytes: 512 * 1024 * 1024,
      cpus: 1,
      pids: 128,
      nofile: 256,
      tmpfs_bytes: 128 * 1024 * 1024,
    },
    ...overrides,
  }
}

function targetCommand(path) {
  return { program: 'node', args: [path] }
}

function serviceConfig(overrides = {}) {
  return {
    protocol: 'loopback-tcp-v1',
    command: targetCommand('test/security/service.mjs'),
    port: PORT,
    startup_timeout_ms: 5_000,
    probe_interval_ms: 25,
    ...overrides,
  }
}

function proofLimits(overrides = {}) {
  return {
    timeout_ms: 2_000,
    kill_grace_ms: 50,
    max_output_bytes: 4_096,
    ...overrides,
  }
}

function observation(code = 0, overrides = {}) {
  return {
    code,
    signal: null,
    timed_out: false,
    spawn_error: false,
    duration_ms: 4,
    stdout: '',
    stderr: '',
    stdout_bytes: 0,
    stdout_sha256: EMPTY_SHA256,
    stdout_truncated: false,
    stderr_bytes: 0,
    stderr_sha256: EMPTY_SHA256,
    stderr_truncated: false,
    output_omitted: true,
    ...overrides,
  }
}

function serviceRunner() {
  assert.equal(
    typeof proofDocker.runDockerServiceProofCommand,
    'function',
    'proof-docker-runner must export the public T2 service-aware command runner',
  )
  return proofDocker.runDockerServiceProofCommand
}

function hardenedInspection(worker, name, id, createArgs) {
  const imageIndex = createArgs.indexOf(worker.image)
  assert.ok(imageIndex >= 0, 'service container create must use the configured image')
  const serviceEnvironment = createArgs
    .filter((arg) => /^--env=RTA_SERVICE_(?:HOST|PORT)=/.test(arg))
    .map((arg) => arg.slice('--env='.length))
  const user = createArgs.find((arg) => arg.startsWith('--user='))?.slice('--user='.length)
  const workdir = createArgs.find((arg) => arg.startsWith('--workdir='))?.slice('--workdir='.length)
  const workTmpfs = createArgs.find((arg) => arg.startsWith('--tmpfs=/work:'))
    ?.slice('--tmpfs=/work:'.length)
  const configuredEnvironment = createArgs
    .filter((arg) => arg.startsWith('--env='))
    .map((arg) => arg.slice('--env='.length))
  const configuredLabels = Object.fromEntries(createArgs
    .filter((arg) => arg.startsWith('--label='))
    .map((arg) => {
      const entry = arg.slice('--label='.length)
      const separator = entry.indexOf('=')
      return [entry.slice(0, separator), entry.slice(separator + 1)]
    }))
  return {
    Id: id,
    Name: `/${name}`,
    Image: worker.image,
    Platform: 'linux',
    Config: {
      User: user,
      WorkingDir: workdir,
      OpenStdin: true,
      Tty: false,
      AttachStdout: true,
      AttachStderr: true,
      Volumes: null,
      Entrypoint: ['/usr/local/bin/node'],
      Cmd: createArgs.slice(imageIndex + 1),
      Healthcheck: { Test: ['NONE'] },
      Labels: configuredLabels,
      Env: [
        'NODE_VERSION=22.0.0',
        'YARN_VERSION=1.22.22',
        ...configuredEnvironment,
        ...serviceEnvironment,
      ],
    },
    HostConfig: {
      NetworkMode: 'none',
      ReadonlyRootfs: true,
      Privileged: false,
      CapAdd: null,
      CapDrop: ['ALL'],
      SecurityOpt: ['no-new-privileges=true', 'seccomp=builtin'],
      PidsLimit: 128,
      Memory: 512 * 1024 * 1024,
      MemorySwap: 512 * 1024 * 1024,
      NanoCpus: 1_000_000_000,
      Ulimits: [{ Name: 'nofile', Soft: 256, Hard: 256 }],
      IpcMode: 'none',
      PidMode: '',
      UsernsMode: '',
      CgroupnsMode: '',
      Sysctls: null,
      GroupAdd: null,
      AppArmorProfile: 'docker-default',
      Runtime: 'runc',
      Isolation: '',
      MaskedPaths: ['/proc/acpi', '/proc/kcore', '/proc/keys', '/proc/scsi', '/sys/firmware'],
      ReadonlyPaths: ['/proc/bus', '/proc/fs', '/proc/irq', '/proc/sys', '/proc/sysrq-trigger'],
      LogConfig: { Type: 'none' },
      RestartPolicy: { Name: 'no' },
      Binds: null,
      Mounts: null,
      VolumesFrom: null,
      Devices: null,
      DeviceRequests: null,
      Links: null,
      ExtraHosts: null,
      PortBindings: null,
      PublishAllPorts: false,
      AutoRemove: true,
      Init: true,
      Tmpfs: {
        '/work': workTmpfs,
      },
    },
    Mounts: [{ Type: 'tmpfs', Destination: '/work', Source: '', RW: true }],
    State: {
      Status: 'created',
      Running: false,
      Paused: false,
      Restarting: false,
      OOMKilled: false,
      Dead: false,
      ExitCode: 0,
    },
    NetworkSettings: {
      Networks: { none: {} },
      Ports: {},
    },
  }
}

function containerNameFromCreate(args) {
  const value = args.find((arg) => arg.startsWith('--name='))
  if (!value) throw new Error(`create omitted --name: ${args.join(' ')}`)
  return value.slice('--name='.length)
}

function commandKind(args) {
  const joined = args.join(' ')
  if (args.includes('create')) return 'controller'
  if (args.includes('/bin/touch') || /service[^ ]*marker/i.test(joined)) return 'marker'
  if (joined.includes('test/security/attack.mjs')) return 'attack'
  if (joined.includes('test/security/control.mjs')) return 'control'
  if (
    args.includes('container')
    && args.includes('exec')
    && args.includes('--user=65534:65534')
    && joined.includes('127.0.0.1')
    && joined.includes(String(PORT))
  ) return 'health'
  return 'controller'
}

function fakeDocker(worker, {
  cleanupRemoves = true,
  createError,
  createLeavesContainer = false,
  healthCodes,
  copiedManifestSha256 = worker.dependency_manifest_sha256,
  inspectionMutator,
  preexisting = false,
  stateInspectionErrorAfterCreate,
  worktreeDigests,
  workerManifestSha256 = worker.dependency_manifest_sha256,
} = {}) {
  const calls = []
  const containers = new Map()
  let nextId = 1
  let healthIndex = 0
  let worktreeIndex = 0
  let createAttempted = false

  const containerEntryForTarget = (target) => containers.has(target)
    ? [target, containers.get(target)]
    : [...containers.entries()].find(([, container]) => container.id === target)
  const containerForTarget = (target) => containerEntryForTarget(target)?.[1]

  const replyForTargetCommand = (args) => {
    const kind = commandKind(args)
    if (kind === 'health') {
      const code = healthCodes
        ? (healthCodes[healthIndex] ?? healthCodes.at(-1))
        : [1, 0, 0][healthIndex % 3]
      healthIndex += 1
      return observation(code)
    }
    if (kind === 'attack') return observation(1)
    if (kind === 'control') return observation(0)
    return observation(0)
  }

  const command = async (args, options = {}) => {
    const call = { type: 'command', args, options, kind: commandKind(args) }
    calls.push(call)
    const joined = args.join(' ')
    if (joined.includes('context inspect')) {
      return { code: 0, signal: null, stdout: '"npipe:////./pipe/docker_engine"\n', stderr: '' }
    }
    if (joined.includes('version --format')) {
      return { code: 0, signal: null, stdout: '"29.5.3"\n', stderr: '' }
    }
    if (joined.includes('image inspect')) {
      return {
        code: 0,
        signal: null,
        stdout: `${JSON.stringify({
          Id: worker.image,
          Os: 'linux',
          Config: { Labels: { 'dev.red-team-audit.proof-worker': worker.protocol } },
        })}\n`,
        stderr: '',
      }
    }
    if (args.includes('create')) {
      const name = containerNameFromCreate(args)
      const id = String(nextId).padStart(64, 'c')
      nextId += 1
      const inspection = hardenedInspection(worker, name, id, args)
      inspectionMutator?.(inspection, { phase: 'created', name })
      createAttempted = true
      if (createError) {
        if (createLeavesContainer) {
          containers.set(name, { exists: true, id, inspection })
        }
        throw createError
      }
      containers.set(name, { exists: true, id, inspection })
      return { code: 0, signal: null, stdout: `${id}\n`, stderr: '' }
    }
    if (joined.includes('container inspect')) {
      const target = args.at(-1)
      if (createAttempted && stateInspectionErrorAfterCreate) {
        throw stateInspectionErrorAfterCreate
      }
      if (!createAttempted && preexisting) {
        return {
          code: 0,
          signal: null,
          stdout: `${JSON.stringify({ Name: `/${target}` })}\n`,
          stderr: '',
        }
      }
      const entry = containerEntryForTarget(target)
      const name = entry?.[0] ?? target
      const container = entry?.[1]
      if (container?.exists) {
        inspectionMutator?.(container.inspection, {
          phase: container.inspection.State.Running ? 'running' : 'created',
          name,
        })
        call.inspection = structuredClone(container.inspection)
      }
      return container?.exists
        ? {
            code: 0,
            signal: null,
            stdout: `${JSON.stringify(container.inspection)}\n`,
            stderr: '',
          }
        : { code: 1, signal: null, stdout: '', stderr: 'No such container' }
    }
    if (joined.includes('container ls')) {
      const nameFilter = args.find((arg) => arg.startsWith('--filter=name=^/'))
      const idFilter = args.find((arg) => arg.startsWith('--filter=id='))
      const name = nameFilter?.slice('--filter=name=^/'.length, -1)
      const id = idFilter?.slice('--filter=id='.length)
      const container = id === undefined ? containers.get(name) : containerForTarget(id)
      return {
        code: 0,
        signal: null,
        stdout: container?.exists
          ? `${JSON.stringify(id === undefined ? name : container.id)}\n`
          : '',
        stderr: '',
      }
    }
    if (args.includes('/opt/rta/package-lock.json')) {
      return { code: 0, signal: null, stdout: workerManifestSha256, stderr: '' }
    }
    if (args.includes('/work/repo/package-lock.json')) {
      return { code: 0, signal: null, stdout: copiedManifestSha256, stderr: '' }
    }
    if (args.some((arg) => (
      typeof arg === 'string'
      && arg.includes('red-team-audit/proof-worktree-manifest/v1')
    ))) {
      const expected = await proofDocker.proofSourceTreeDigest(
        SOURCE_ROOT,
        worker.limits.max_source_bytes,
      )
      const digest = worktreeDigests
        ? (worktreeDigests[worktreeIndex] ?? worktreeDigests.at(-1))
        : expected
      worktreeIndex += 1
      return { code: 0, signal: null, stdout: digest, stderr: '' }
    }
    if (args.includes('start')) {
      const container = containerForTarget(args.at(-1))
      if (container) {
        container.inspection.State.Status = 'running'
        container.inspection.State.Running = true
      }
      return { code: 0, signal: null, stdout: '', stderr: '' }
    }
    if (args.includes('rm')) {
      const container = containerForTarget(args.at(-1))
      if (container && cleanupRemoves) container.exists = false
      return { code: 0, signal: null, stdout: '', stderr: '' }
    }
    if (commandKind(args) !== 'controller') {
      const result = replyForTargetCommand(args)
      call.result_code = result.code
      return result
    }
    return { code: 0, signal: null, stdout: '', stderr: '' }
  }

  const execute = async (args, options = {}) => {
    const call = { type: 'execute', args, options, kind: commandKind(args) }
    calls.push(call)
    const result = replyForTargetCommand(args)
    call.result_code = result.code
    return result
  }

  const transfer = async (options = {}) => {
    calls.push({ type: 'transfer', args: [], options, kind: 'transfer' })
    return { archive_bytes: 4_096 }
  }

  return { calls, command, containers, execute, transfer }
}

function runnerInput(worker, fake, {
  args = ['test/security/attack.mjs'],
  containerName = 'rta-proof-service-attack0001',
  program = 'node',
  overrides = {},
} = {}) {
  return {
    config: worker,
    sourceRoot: SOURCE_ROOT,
    service: serviceConfig(),
    program,
    args,
    limits: proofLimits(),
    command: fake.command,
    execute: fake.execute,
    transfer: fake.transfer,
    containerName,
    sleep: async () => {},
    ...overrides,
  }
}

async function recoveryInspectionFixtures(worker, serviceContainerNames) {
  const inspections = new Map()
  for (const [index, containerName] of Object.values(serviceContainerNames).entries()) {
    const fake = fakeDocker(worker)
    await serviceRunner()(runnerInput(worker, fake, {
      containerName,
      overrides: {
        service: serviceConfig({ startup_timeout_ms: 500 }),
        limits: proofLimits({ timeout_ms: 500 }),
      },
    }))
    const inspection = structuredClone(fake.containers.get(containerName).inspection)
    inspection.Id = String(index + 1).padStart(64, 'a')
    inspections.set(containerName, inspection)
  }
  return inspections
}

test('service proof uses one immutable worker binding in two fresh isolated containers', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig())
  const fake = fakeDocker(worker)

  const control = await run(runnerInput(worker, fake, {
    args: ['test/security/control.mjs'],
    containerName: 'rta-proof-service-control001',
  }))
  const attack = await run(runnerInput(worker, fake, {
    args: ['test/security/attack.mjs'],
    containerName: 'rta-proof-service-attack0001',
  }))

  assert.equal(control.code, 0)
  assert.equal(attack.code, 1)
  const creates = fake.calls.filter(({ args }) => args.includes('create'))
  assert.equal(creates.length, 2)
  assert.notEqual(containerNameFromCreate(creates[0].args), containerNameFromCreate(creates[1].args))
  for (const { args } of creates) {
    const containerName = containerNameFromCreate(args)
    assert.equal(args.includes('--pull=never'), true)
    assert.equal(args.includes('--rm'), true)
    assert.equal(args.includes('--network=none'), true)
    assert.equal(args.includes('--read-only'), true)
    assert.equal(args.includes('--cap-drop=ALL'), true)
    assert.equal(args.includes('--security-opt=no-new-privileges=true'), true)
    assert.equal(args.includes(IMAGE), true)
    assert.equal(args.includes('--user=65534:65534'), true)
    assert.equal(args.includes('--workdir=/'), true)
    assert.equal(
      args.includes(`--label=dev.red-team-audit.service-proof.container-name=${containerName}`),
      true,
    )
    assert.equal(
      args.includes('--label=dev.red-team-audit.service-proof.protocol=loopback-tcp-v1'),
      true,
    )
    assert.equal(
      args.includes(
        `--label=dev.red-team-audit.service-proof.worker-config-sha256=${proofWorkerConfigDigest(worker)}`,
      ),
      true,
    )
    assert.equal(
      args.some((arg) => arg.startsWith('--tmpfs=/work:') && arg.includes('mode=0711')),
      true,
    )
    assert.equal(args.some((arg) => /(?:^|-)mount=|(?:^|-)volume=|^-v(?:=|$)/.test(arg)), false)
    assert.equal(args.some((arg) => /publish|^-p(?:=|$)/.test(arg)), false)
  }
  for (const result of [control, attack]) {
    assert.equal(result.sandbox.worker_config_sha256, proofWorkerConfigDigest(worker))
    assert.equal(result.sandbox.image, worker.image)
    assert.equal(result.sandbox.network_mode, 'none')
    assert.deepEqual(result.sandbox.mounts, [])
    assert.equal(result.sandbox.cleanup_verified, true)
    assert.equal(result.sandbox.service.protocol, 'loopback-tcp-v1')
    assert.equal(result.sandbox.service.host, '127.0.0.1')
    assert.equal(result.sandbox.service.port, PORT)
    assert.equal(result.sandbox.service.pre_boot_closed, true)
    assert.equal(result.sandbox.service.pre_probe_ready, true)
    assert.equal(result.sandbox.service.post_probe_ready, true)
  }

  const firstCreate = fake.calls.findIndex(({ args }) => args.includes('create'))
  const firstRemoval = fake.calls.findIndex(({ args }) => args.includes('rm'))
  const secondCreate = fake.calls.findIndex(
    ({ args }, index) => index > firstCreate && args.includes('create'),
  )
  assert.ok(firstRemoval >= 0 && firstRemoval < secondCreate)
})

test('a create-bound supervisor gates boot and all readiness probes stay on loopback', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig())
  const fake = fakeDocker(worker)
  const result = await run(runnerInput(worker, fake))

  const [create] = fake.calls.filter(({ args }) => args.includes('create'))
  assert.ok(create)
  assert.equal(create.args.includes('--init'), true)
  assert.equal(create.args.includes('--rm'), true)
  assert.equal(create.args.includes('--network=none'), true)
  assert.equal(create.args.includes('--env=RTA_SERVICE_HOST=127.0.0.1'), true)
  assert.equal(create.args.includes(`--env=RTA_SERVICE_PORT=${PORT}`), true)
  assert.equal(create.args.join(' ').includes('test/security/service.mjs'), true)
  assert.match(create.args.join(' '), /marker/i)
  assert.match(create.args.join(' '), /(?:ttl|timeout)/i)
  assert.equal(create.args.includes('--detach'), false)
  assert.equal(result.sandbox.service.supervisor_ttl_ms <= worker.limits.wall_time_ms, true)
  assert.equal(
    result.sandbox.service.supervisor_ttl_ms
      >= serviceConfig().startup_timeout_ms + proofLimits().timeout_ms,
    true,
  )
  const createdContainer = fake.containers.get(containerNameFromCreate(create.args))
  const imageIndex = create.args.indexOf(worker.image)
  assert.deepEqual(createdContainer.inspection.Config.Cmd, create.args.slice(imageIndex + 1))

  const [marker] = fake.calls.filter(({ kind }) => kind === 'marker')
  assert.ok(marker, 'one controller marker must trigger the create-bound service child')
  assert.ok(fake.calls.indexOf(marker) > fake.calls.findIndex(
    ({ args }) => args.includes('/work/repo/package-lock.json'),
  ))

  const health = fake.calls.filter(({ kind }) => kind === 'health')
  const attack = fake.calls.filter(({ kind }) => kind === 'attack')
  assert.equal(
    health.length,
    3,
    'CLOSED before boot, READY before target probe, and READY after target probe',
  )
  assert.equal(attack.length, 1)
  assert.equal(health[0].result_code, 1)
  assert.equal(health[1].result_code, 0)
  assert.equal(health[2].result_code, 0)
  assert.ok(fake.calls.indexOf(health[0]) < fake.calls.indexOf(marker))
  assert.ok(fake.calls.indexOf(marker) < fake.calls.indexOf(health[1]))
  assert.ok(fake.calls.indexOf(health[1]) < fake.calls.indexOf(attack[0]))
  assert.ok(fake.calls.indexOf(attack[0]) < fake.calls.indexOf(health[2]))
  for (const probe of health) {
    assert.equal(probe.args.includes('container'), true)
    assert.equal(probe.args.includes('exec'), true)
    assert.equal(probe.args.includes('--user=65534:65534'), true)
    assert.equal(probe.args.includes('--workdir=/'), true)
    assert.equal(probe.args.join(' ').includes('127.0.0.1'), true)
    assert.equal(probe.args.join(' ').includes(String(PORT)), true)
    assert.equal(probe.args.join(' ').includes('test/security/'), false)
    assert.equal(probe.options.maxOutputBytes <= proofLimits().max_output_bytes, true)
  }
  assert.equal(attack[0].args.includes('--env=RTA_SERVICE_HOST=127.0.0.1'), true)
  assert.equal(attack[0].args.includes(`--env=RTA_SERVICE_PORT=${PORT}`), true)
  assert.equal(
    fake.calls.some(({ args }) => args.some((arg) => /https?:\/\/(?!127\.0\.0\.1)/i.test(arg))),
    false,
  )

  const runningInspections = fake.calls.filter(
    ({ inspection }) => inspection?.State?.Running === true,
  )
  assert.ok(runningInspections.length >= 3, 'runner must reinspect after start and before probes')
  for (const { inspection } of runningInspections) {
    assert.equal(inspection.HostConfig.NetworkMode, 'none')
    assert.deepEqual(Object.keys(inspection.NetworkSettings.Networks), ['none'])
    assert.deepEqual(inspection.NetworkSettings.Ports, {})
    assert.equal(inspection.HostConfig.PortBindings, null)
  }
})

test('a service port that is open before the boot marker fails closed', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig())
  const fake = fakeDocker(worker, { healthCodes: [0] })
  let caught
  try {
    await run(runnerInput(worker, fake))
  } catch (error) {
    caught = error
  }
  assert.ok(caught)
  assert.match(caught.code, /^SERVICE_PROOF_PRE_BOOT_/)
  assert.equal(caught.evidence.verification_status, 'UNPROVEN')
  assert.match(caught.evidence.blocking_reason, /open before|pre-boot|closed/i)
  assert.equal(fake.calls.some(({ kind }) => kind === 'marker'), false)
  assert.equal(fake.calls.some(({ kind }) => kind === 'attack'), false)
  assert.equal(fake.calls.some(({ args }) => args.includes('rm')), true)
})

test('a wildcard-bound listener never qualifies as loopback readiness', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig())
  const fake = fakeDocker(worker, { healthCodes: [1, 3] })
  let caught
  try {
    await run(runnerInput(worker, fake))
  } catch (error) {
    caught = error
  }
  assert.ok(caught)
  assert.equal(caught.code, 'SERVICE_PROOF_STARTUP_BINDING_INVALID')
  assert.equal(caught.evidence.verification_status, 'UNPROVEN')
  assert.match(caught.evidence.blocking_reason, /literal IPv4 loopback|binding/i)
  assert.equal(
    fake.calls.some(({ kind, result_code: resultCode }) => kind === 'health' && resultCode === 3),
    true,
  )
  assert.equal(fake.calls.some(({ kind }) => kind === 'attack'), false)
  assert.equal(fake.calls.some(({ args }) => args.includes('rm')), true)
})

test('runtime or network inspection drift blocks probes and proves cleanup', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig())
  for (const mutate of [
    (inspection, { phase }) => {
      if (phase === 'running') inspection.HostConfig.NetworkMode = 'bridge'
    },
    (inspection, { phase }) => {
      if (phase === 'running') inspection.NetworkSettings.Networks = { bridge: {} }
    },
    (inspection, { phase }) => {
      if (phase === 'running') inspection.State.Running = false
    },
  ]) {
    const fake = fakeDocker(worker, { inspectionMutator: mutate })
    await assert.rejects(
      run(runnerInput(worker, fake)),
      /network|running|profile mismatch/i,
    )
    assert.equal(fake.calls.some(({ kind }) => kind === 'health'), false)
    assert.equal(fake.calls.some(({ kind }) => kind === 'attack'), false)
    assert.equal(fake.calls.some(({ args }) => args.includes('rm')), true)
  }
})

test('service proof applies hard startup, runtime, output, and wall-time bounds', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig({
    limits: {
      ...workerConfig().limits,
      wall_time_ms: 10_000,
      max_output_bytes: 8_192,
    },
  }))
  const fake = fakeDocker(worker)
  await run(runnerInput(worker, fake, {
    overrides: {
      service: serviceConfig({ startup_timeout_ms: 900, probe_interval_ms: 20 }),
      limits: proofLimits({ timeout_ms: 700, max_output_bytes: 2_048 }),
    },
  }))

  const health = fake.calls.filter(({ kind }) => kind === 'health')
  const target = fake.calls.find(({ kind }) => kind === 'attack')
  assert.equal(health.length, 3)
  for (const call of health) {
    assert.equal(call.options.timeoutMs <= 900, true)
    assert.equal(call.options.maxOutputBytes <= 2_048, true)
  }
  assert.equal(target.options.timeoutMs <= 700, true)
  assert.equal(target.options.maxOutputBytes <= 2_048, true)
  for (const transfer of fake.calls.filter(({ type }) => type === 'transfer')) {
    assert.equal(transfer.options.timeoutMs <= worker.limits.docker_command_timeout_ms, true)
    assert.equal(transfer.options.maxSourceBytes, worker.limits.max_source_bytes)
  }
})

test('service proof publishes one deterministic cumulative controller-session budget', async () => {
  assert.equal(typeof proofDocker.serviceProofControllerBudget, 'function')
  const worker = normalizeProofWorkerConfig(workerConfig({
    limits: {
      ...workerConfig().limits,
      wall_time_ms: 1_000,
      docker_command_timeout_ms: 1_000,
    },
  }))

  assert.deepEqual(proofDocker.serviceProofControllerBudget(worker), {
    controller_session_budget_ms: 27_000,
    controller_active_budget_ms: 21_000,
    controller_cleanup_reserve_ms: 6_000,
  })

  const fake = fakeDocker(worker)
  const result = await serviceRunner()(runnerInput(worker, fake, {
    overrides: {
      service: serviceConfig({ startup_timeout_ms: 500 }),
      limits: proofLimits({ timeout_ms: 500 }),
    },
  }))
  assert.equal(result.sandbox.service.controller_session_budget_ms, 27_000)
  assert.equal(result.sandbox.service.controller_active_budget_ms, 21_000)
  assert.equal(result.sandbox.service.controller_cleanup_reserve_ms, 6_000)
})

test('cumulative controller exhaustion stops dispatch and preserves its teardown reserve', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig({
    limits: {
      ...workerConfig().limits,
      wall_time_ms: 1_000,
      docker_command_timeout_ms: 1_000,
    },
  }))
  const budget = proofDocker.serviceProofControllerBudget(worker)
  const fake = fakeDocker(worker)
  let clock = 0
  let preBootObserved = false

  const command = async (args, options = {}) => {
    const result = await fake.command(args, options)
    if (clock >= budget.controller_active_budget_ms) clock += 900
    return result
  }
  const execute = async (args, options = {}) => {
    const result = await fake.execute(args, options)
    if (!preBootObserved && commandKind(args) === 'health') {
      preBootObserved = true
      clock = budget.controller_active_budget_ms
    }
    return result
  }

  let caught
  try {
    await run(runnerInput(worker, fake, {
      overrides: {
        service: serviceConfig({ startup_timeout_ms: 500 }),
        limits: proofLimits({ timeout_ms: 500 }),
        command,
        execute,
        monotonicNow: () => clock,
      },
    }))
  } catch (error) {
    caught = error
  }

  assert.ok(caught)
  assert.equal(caught.code, 'SERVICE_PROOF_WALL_TIMEOUT')
  assert.equal(caught.evidence.cleanup_verified, true)
  assert.equal(fake.calls.some(({ kind }) => kind === 'marker'), false)
  assert.equal(fake.calls.some(({ kind }) => kind === 'attack'), false)
  const cleanup = fake.calls.filter(({ args }) => (
    args.includes('kill')
    || args.includes('rm')
    || (clock > budget.controller_active_budget_ms && args.includes('container'))
  ))
  assert.equal(fake.calls.some(({ args }) => args.includes('rm')), true)
  for (const call of cleanup) {
    assert.equal(Number.isInteger(call.options.timeoutMs), true)
    assert.equal(call.options.timeoutMs > 0, true)
    assert.equal(call.options.timeoutMs <= worker.limits.docker_command_timeout_ms, true)
  }
  assert.equal(clock, budget.controller_active_budget_ms + 5_400)
  assert.equal(clock < budget.controller_session_budget_ms, true)
})

test('controller deadline exhaustion during teardown remains cleanup-unverified', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig({
    limits: {
      ...workerConfig().limits,
      wall_time_ms: 1_000,
      docker_command_timeout_ms: 1_000,
    },
  }))
  const budget = proofDocker.serviceProofControllerBudget(worker)
  const fake = fakeDocker(worker)
  let clock = 0
  let preBootObserved = false
  let cleanupStarted = false

  const command = async (args, options = {}) => {
    if (cleanupStarted) {
      const result = await fake.command(args, options)
      clock = budget.controller_session_budget_ms
      return result
    }
    const result = await fake.command(args, options)
    if (args.includes('kill')) cleanupStarted = true
    return result
  }
  const execute = async (args, options = {}) => {
    const result = await fake.execute(args, options)
    if (!preBootObserved && commandKind(args) === 'health') {
      preBootObserved = true
      clock = budget.controller_active_budget_ms
    }
    return result
  }

  await assert.rejects(
    run(runnerInput(worker, fake, {
      overrides: {
        service: serviceConfig({ startup_timeout_ms: 500 }),
        limits: proofLimits({ timeout_ms: 500 }),
        command,
        execute,
        monotonicNow: () => clock,
      },
    })),
    (error) => (
      error?.code === 'SERVICE_PROOF_CLEANUP_UNVERIFIED'
      && error?.evidence?.cleanup_verified === false
      && error?.primary_error?.code === 'SERVICE_PROOF_WALL_TIMEOUT'
    ),
  )
  assert.equal(fake.calls.some(({ kind }) => kind === 'attack'), false)
})

test('a cleanup verification operation returning at the deadline cannot report cleanup verified', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig({
    limits: {
      ...workerConfig().limits,
      wall_time_ms: 1_000,
      docker_command_timeout_ms: 1_000,
    },
  }))
  const budget = proofDocker.serviceProofControllerBudget(worker)
  const fake = fakeDocker(worker)
  let clock = 0
  let cleanupStarted = false

  const command = async (args, options = {}) => {
    const result = await fake.command(args, options)
    if (args.includes('kill')) cleanupStarted = true
    if (cleanupStarted && args.includes('container') && args.includes('ls')) {
      clock = budget.controller_session_budget_ms
    }
    return result
  }

  await assert.rejects(
    run(runnerInput(worker, fake, {
      overrides: {
        service: serviceConfig({ startup_timeout_ms: 500 }),
        limits: proofLimits({ timeout_ms: 500 }),
        command,
        monotonicNow: () => clock,
      },
    })),
    (error) => (
      error?.code === 'SERVICE_PROOF_CLEANUP_UNVERIFIED'
      && error?.evidence?.cleanup_verified === false
    ),
  )
  assert.equal(fake.calls.some(({ args }) => args.includes('rm')), true)
})

test('normal Docker-config removal returning at the session deadline cannot report success', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig({
    limits: {
      ...workerConfig().limits,
      wall_time_ms: 1_000,
      docker_command_timeout_ms: 1_000,
    },
  }))
  const budget = proofDocker.serviceProofControllerBudget(worker)
  const fake = fakeDocker(worker)
  let clock = 0

  await assert.rejects(
    run(runnerInput(worker, fake, {
      overrides: {
        service: serviceConfig({ startup_timeout_ms: 500 }),
        limits: proofLimits({ timeout_ms: 500 }),
        monotonicNow: () => clock,
        removeDockerConfigRoot: async (path) => {
          rmSync(path, { recursive: true, force: true })
          clock = budget.controller_session_budget_ms
        },
      },
    })),
    (error) => (
      error?.code === 'SERVICE_PROOF_CONTROLLER_TEMP_CLEANUP_FAILED'
      && error?.evidence?.cleanup_verified === false
    ),
  )
})

test('recovery cleanup proves both exact leased containers absent under one deadline', async () => {
  assert.equal(typeof proofDocker.cleanupDockerServiceProofContainers, 'function')
  const worker = normalizeProofWorkerConfig(workerConfig({
    limits: {
      ...workerConfig().limits,
      wall_time_ms: 1_000,
      docker_command_timeout_ms: 1_000,
    },
  }))
  const serviceContainerNames = {
    attack: 'rta-proof-service-recoveryattack1',
    control: 'rta-proof-service-recoverycontrol1',
  }
  const inspections = await recoveryInspectionFixtures(worker, serviceContainerNames)
  const present = new Set(Object.values(serviceContainerNames))
  const namesById = new Map([...inspections].map(([name, inspection]) => [inspection.Id, name]))
  const calls = []
  let clock = 0
  let removedConfigRoot
  const command = async (args, options = {}) => {
    const joined = args.join(' ')
    const nameFilter = args.find((arg) => arg.startsWith('--filter=name=^/'))
    const idFilter = args.find((arg) => arg.startsWith('--filter=id='))
    const target = args.at(-1)
    const name = nameFilter
      ? nameFilter.slice('--filter=name=^/'.length, -1)
      : namesById.get(target) ?? target
    calls.push({ args, options, at: clock })
    let outcome = { code: 0, signal: null, stdout: '', stderr: '' }
    if (joined.includes('context inspect')) {
      outcome = {
        code: 0,
        signal: null,
        stdout: '"npipe:////./pipe/docker_engine"\n',
        stderr: '',
      }
    } else if (args.includes('rm')) {
      present.delete(namesById.get(target) ?? target)
    } else if (args.includes('inspect')) {
      outcome = present.has(name)
        ? {
            code: 0,
            signal: null,
            stdout: `${JSON.stringify(inspections.get(name))}\n`,
            stderr: '',
          }
        : { code: 1, signal: null, stdout: '', stderr: 'No such container' }
    } else if (args.includes('ls')) {
      const listedId = idFilter?.slice('--filter=id='.length)
      outcome = {
        code: 0,
        signal: null,
        stdout: listedId && present.has(namesById.get(listedId))
          ? `${JSON.stringify(listedId)}\n`
          : (!idFilter && present.has(name) ? `${JSON.stringify(name)}\n` : ''),
        stderr: '',
      }
    }
    const callNumber = calls.length
    if (callNumber <= 14) clock += callNumber === 14 ? 1_500 : 1_000
    return outcome
  }

  const result = await proofDocker.cleanupDockerServiceProofContainers({
    config: worker,
    serviceContainerNames,
    service: serviceConfig({ startup_timeout_ms: 500 }),
    limits: proofLimits({ timeout_ms: 500 }),
    command,
    monotonicNow: () => clock,
    removeDockerConfigRoot: async (path) => {
      removedConfigRoot = path
      rmSync(path, { recursive: true, force: true })
    },
  })

  assert.deepEqual(result.service_container_names, serviceContainerNames)
  assert.equal(result.cleanup_verified, true)
  assert.equal(result.controller_cleanup_budget_ms, 15_000)
  assert.deepEqual([...present], [])
  assert.equal(typeof removedConfigRoot, 'string')
  assert.equal(calls.length, 15)
  assert.equal(calls[0].args.join(' ').includes('context inspect default'), true)
  for (const name of Object.values(serviceContainerNames)) {
    const id = inspections.get(name).Id
    assert.equal(calls.some(({ args }) => args.includes('kill') && args.includes(id)), true)
    assert.equal(calls.some(({ args }) => args.includes('rm') && args.includes(id)), true)
    assert.equal(calls.some(({ args }) => args.includes('kill') && args.includes(name)), false)
    assert.equal(calls.some(({ args }) => args.includes('rm') && args.includes(name)), false)
    assert.equal(calls.some(({ args }) => args.includes('inspect') && args.includes(name)), true)
    assert.equal(calls.some(({ args }) => args.includes('inspect') && args.includes(id)), true)
    assert.equal(
      calls.some(({ args }) => args.includes('--no-trunc') && args.includes(`--filter=id=${id}`)),
      true,
    )
    assert.equal(
      calls.some(({ args }) => args.includes('ls') && args.some((arg) => arg.includes(name))),
      true,
    )
  }
  for (const { options } of calls) {
    assert.equal(Number.isInteger(options.timeoutMs) && options.timeoutMs > 0, true)
    assert.equal(options.timeoutMs <= worker.limits.docker_command_timeout_ms, true)
  }
  assert.equal(calls.at(-1).options.timeoutMs, 500)
})

test('recovery Docker-config removal returning at its deadline cannot attest cleanup', async () => {
  const worker = normalizeProofWorkerConfig(workerConfig({
    limits: {
      ...workerConfig().limits,
      wall_time_ms: 1_000,
      docker_command_timeout_ms: 1_000,
    },
  }))
  const serviceContainerNames = {
    attack: 'rta-proof-service-recoverytempattack1',
    control: 'rta-proof-service-recoverytempcontrol1',
  }
  let clock = 0

  await assert.rejects(
    proofDocker.cleanupDockerServiceProofContainers({
      config: worker,
      serviceContainerNames,
      service: serviceConfig({ startup_timeout_ms: 500 }),
      limits: proofLimits({ timeout_ms: 500 }),
      monotonicNow: () => clock,
      command: async (args) => {
        if (args.join(' ').includes('context inspect')) {
          return {
            code: 0,
            signal: null,
            stdout: '"npipe:////./pipe/docker_engine"\n',
            stderr: '',
          }
        }
        if (args.includes('inspect')) {
          return { code: 1, signal: null, stdout: '', stderr: 'No such container' }
        }
        return { code: 0, signal: null, stdout: '', stderr: '' }
      },
      removeDockerConfigRoot: async (path) => {
        rmSync(path, { recursive: true, force: true })
        clock = 15_000
      },
    }),
    (error) => (
      error?.code === 'SERVICE_PROOF_RECOVERY_CLEANUP_UNVERIFIED'
      && error?.evidence?.cleanup_verified === false
    ),
  )
})

test('recovery cleanup rejects when its final absence query returns at the deadline', async () => {
  const worker = normalizeProofWorkerConfig(workerConfig({
    limits: {
      ...workerConfig().limits,
      wall_time_ms: 1_000,
      docker_command_timeout_ms: 1_000,
    },
  }))
  const serviceContainerNames = {
    attack: 'rta-proof-service-recoverydeadlineattack1',
    control: 'rta-proof-service-recoverydeadlinecontrol1',
  }
  const inspections = await recoveryInspectionFixtures(worker, serviceContainerNames)
  const namesById = new Map([...inspections].map(([name, inspection]) => [inspection.Id, name]))
  const present = new Set(Object.values(serviceContainerNames))
  let clock = 0

  await assert.rejects(
    proofDocker.cleanupDockerServiceProofContainers({
      config: worker,
      serviceContainerNames,
      service: serviceConfig({ startup_timeout_ms: 500 }),
      limits: proofLimits({ timeout_ms: 500 }),
      monotonicNow: () => clock,
      command: async (args) => {
        const joined = args.join(' ')
        const nameFilter = args.find((arg) => arg.startsWith('--filter=name=^/'))
        const idFilter = args.find((arg) => arg.startsWith('--filter=id='))
        const target = args.at(-1)
        const name = nameFilter
          ? nameFilter.slice('--filter=name=^/'.length, -1)
          : namesById.get(target) ?? target
        let outcome = { code: 0, signal: null, stdout: '', stderr: '' }
        if (joined.includes('context inspect')) {
          outcome = {
            code: 0,
            signal: null,
            stdout: '"npipe:////./pipe/docker_engine"\n',
            stderr: '',
          }
        } else if (args.includes('rm')) {
          present.delete(namesById.get(target))
        } else if (args.includes('inspect')) {
          outcome = present.has(name)
            ? {
                code: 0,
                signal: null,
                stdout: `${JSON.stringify(inspections.get(name))}\n`,
                stderr: '',
              }
            : { code: 1, signal: null, stdout: '', stderr: 'No such container' }
        } else if (args.includes('ls')) {
          const listedId = idFilter?.slice('--filter=id='.length)
          outcome = {
            code: 0,
            signal: null,
            stdout: listedId && present.has(namesById.get(listedId))
              ? `${JSON.stringify(listedId)}\n`
              : (!idFilter && present.has(name) ? `${JSON.stringify(name)}\n` : ''),
            stderr: '',
          }
          if (nameFilter?.includes(serviceContainerNames.control)) clock = 15_000
        }
        return outcome
      },
      removeDockerConfigRoot: async (path) => {
        rmSync(path, { recursive: true, force: true })
      },
    }),
    (error) => (
      error?.code === 'SERVICE_PROOF_RECOVERY_CLEANUP_UNVERIFIED'
      && error?.cleanup_verified === false
    ),
  )
})

test('recovery cleanup attempts both containers and retains every ambiguity cause', async () => {
  const worker = normalizeProofWorkerConfig(workerConfig())
  const serviceContainerNames = {
    attack: 'rta-proof-service-recoveryattack2',
    control: 'rta-proof-service-recoverycontrol2',
  }
  const inspections = await recoveryInspectionFixtures(worker, serviceContainerNames)
  const namesById = new Map([...inspections].map(([name, inspection]) => [inspection.Id, name]))
  const present = new Set(Object.values(serviceContainerNames))
  const inspectCounts = new Map()
  const calls = []
  let configRoot
  const verificationCause = 'attack exact-absence inspection was ambiguous'
  const configCause = 'recovery Docker config root could not be removed'

  let caught
  try {
    await proofDocker.cleanupDockerServiceProofContainers({
      config: worker,
      serviceContainerNames,
      service: serviceConfig({ startup_timeout_ms: 500 }),
      limits: proofLimits({ timeout_ms: 500 }),
      command: async (args, options = {}) => {
        calls.push({ args, options })
        const joined = args.join(' ')
        const nameFilter = args.find((arg) => arg.startsWith('--filter=name=^/'))
        const name = nameFilter
          ? nameFilter.slice('--filter=name=^/'.length, -1)
          : args.at(-1)
        if (joined.includes('context inspect')) {
          return {
            code: 0,
            signal: null,
            stdout: '"npipe:////./pipe/docker_engine"\n',
            stderr: '',
          }
        }
        if (args.includes('inspect')) {
          const count = (inspectCounts.get(name) ?? 0) + 1
          inspectCounts.set(name, count)
          if (name === serviceContainerNames.attack && count > 1) {
            throw new Error(verificationCause)
          }
          return present.has(name)
            ? {
                code: 0,
                signal: null,
                stdout: `${JSON.stringify(inspections.get(name))}\n`,
                stderr: '',
              }
            : { code: 1, signal: null, stdout: '', stderr: 'No such container' }
        }
        if (args.includes('rm')) {
          const removedName = namesById.get(name)
          if (removedName !== serviceContainerNames.attack) present.delete(removedName)
        }
        if (args.includes('ls')) {
          return {
            code: 0,
            signal: null,
            stdout: present.has(name) ? `${JSON.stringify(name)}\n` : '',
            stderr: '',
          }
        }
        return { code: 0, signal: null, stdout: '', stderr: '' }
      },
      removeDockerConfigRoot: async (path) => {
        configRoot = path
        throw new Error(configCause)
      },
    })
  } catch (error) {
    caught = error
  } finally {
    if (configRoot) rmSync(configRoot, { recursive: true, force: true })
  }

  assert.ok(caught instanceof AggregateError)
  assert.equal(caught.code, 'SERVICE_PROOF_RECOVERY_CLEANUP_UNVERIFIED')
  assert.equal(caught.cleanup_verified, false)
  assert.equal(caught.evidence.cleanup_verified, false)
  assert.equal(
    calls.some(({ args }) => (
      args.includes('kill') && args.includes(inspections.get(serviceContainerNames.control).Id)
    )),
    true,
  )
  assert.equal(
    calls.some(({ args }) => (
      args.includes('ls')
      && args.some((arg) => arg.includes(serviceContainerNames.control))
    )),
    true,
  )
  const retained = []
  const collectMessages = (error) => {
    retained.push(error.message)
    if (error instanceof AggregateError) {
      for (const cause of error.errors) collectMessages(cause)
    }
  }
  collectMessages(caught)
  assert.equal(retained.some((message) => message.includes(verificationCause)), true)
  assert.equal(retained.some((message) => message.includes(configCause)), true)
})

test('recovery leaves a same-name container untouched when immutable identity drifts', async () => {
  const worker = normalizeProofWorkerConfig(workerConfig())
  const serviceContainerNames = {
    attack: 'rta-proof-service-recoveryattack4',
    control: 'rta-proof-service-recoverycontrol4',
  }
  const expected = await recoveryInspectionFixtures(worker, serviceContainerNames)
  const mutations = [
    (inspection) => {
      inspection.Config.Labels['dev.red-team-audit.service-proof.container-name'] =
        'rta-proof-service-unrelated0004'
    },
    (inspection) => { inspection.Image = `sha256:${'f'.repeat(64)}` },
    (inspection) => { inspection.HostConfig.NetworkMode = 'bridge' },
    (inspection) => {
      inspection.Mounts.push({
        Type: 'bind',
        Destination: '/host',
        Source: '/tmp/unrelated',
        RW: true,
      })
    },
    (inspection) => { inspection.Config.Cmd.push('unleased-command-argument') },
    (inspection) => {
      inspection.Config.Env = inspection.Config.Env.map((entry) => (
        entry.startsWith('RTA_SERVICE_PORT=') ? 'RTA_SERVICE_PORT=31338' : entry
      ))
    },
  ]

  for (const mutate of mutations) {
    const inspections = new Map([...expected].map(([name, inspection]) => (
      [name, structuredClone(inspection)]
    )))
    mutate(inspections.get(serviceContainerNames.attack))
    const calls = []
    let caught
    try {
      await proofDocker.cleanupDockerServiceProofContainers({
        config: worker,
        serviceContainerNames,
        service: serviceConfig({ startup_timeout_ms: 500 }),
        limits: proofLimits({ timeout_ms: 500 }),
        command: async (args, options = {}) => {
          calls.push({ args, options })
          if (args.join(' ').includes('context inspect')) {
            return {
              code: 0,
              signal: null,
              stdout: '"npipe:////./pipe/docker_engine"\n',
              stderr: '',
            }
          }
          if (args.includes('inspect')) {
            const name = args.at(-1)
            return {
              code: 0,
              signal: null,
              stdout: `${JSON.stringify(inspections.get(name))}\n`,
              stderr: '',
            }
          }
          throw new Error('identity rejection must precede destructive recovery')
        },
      })
    } catch (error) {
      caught = error
    }

    assert.equal(caught?.code, 'SERVICE_PROOF_RECOVERY_CLEANUP_UNVERIFIED')
    assert.equal(calls[0].args.join(' ').includes('context inspect default'), true)
    assert.equal(calls.some(({ args }) => args.includes('kill') || args.includes('rm')), false)
  }
})

test('recovery rejects a non-local default Docker context before container inspection', async () => {
  const worker = normalizeProofWorkerConfig(workerConfig())
  const serviceContainerNames = {
    attack: 'rta-proof-service-recoveryattack5',
    control: 'rta-proof-service-recoverycontrol5',
  }
  const calls = []

  await assert.rejects(
    proofDocker.cleanupDockerServiceProofContainers({
      config: worker,
      serviceContainerNames,
      service: serviceConfig({ startup_timeout_ms: 500 }),
      limits: proofLimits({ timeout_ms: 500 }),
      command: async (args, options = {}) => {
        calls.push({ args, options })
        return {
          code: 0,
          signal: null,
          stdout: '"tcp://remote.example:2376"\n',
          stderr: '',
        }
      },
    }),
    (error) => error?.code === 'SERVICE_PROOF_RECOVERY_CLEANUP_UNVERIFIED',
  )
  assert.equal(calls.length, 1)
  assert.equal(calls[0].args.join(' ').includes('context inspect default'), true)
  assert.equal(calls.some(({ args }) => args.includes('kill') || args.includes('rm')), false)
})

test('recovery cleanup rejects non-exact or aliased container-name bindings', async () => {
  const worker = normalizeProofWorkerConfig(workerConfig())
  let dispatches = 0
  for (const serviceContainerNames of [
    { attack: 'rta-proof-service-recoveryattack3' },
    {
      attack: 'rta-proof-service-recoveryattack3',
      control: 'rta-proof-service-recoveryattack3',
    },
    {
      attack: 'rta-proof-service-recoveryattack3',
      control: 'rta-proof-service-recoverycontrol3',
      extra: 'rta-proof-service-recoveryextra003',
    },
  ]) {
    await assert.rejects(
      proofDocker.cleanupDockerServiceProofContainers({
        config: worker,
        serviceContainerNames,
        command: async () => {
          dispatches += 1
          return { code: 0, signal: null, stdout: '', stderr: '' }
        },
      }),
      /container names|distinct|exact/i,
    )
  }
  assert.equal(dispatches, 0)
})

test('startup marker, reinspection, and readiness probe use only the remaining deadline', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig())
  const fake = fakeDocker(worker)
  const startupCalls = []
  let clock = 0
  let markerSeen = false
  let readinessObserved = false

  const command = async (args, options = {}) => {
    const kind = commandKind(args)
    const isStartupInspection = markerSeen
      && !readinessObserved
      && args.includes('container')
      && args.includes('inspect')
    if (kind === 'marker' || isStartupInspection) {
      startupCalls.push({
        kind: kind === 'marker' ? 'marker' : 'reinspection',
        at: clock,
        timeoutMs: options.timeoutMs,
      })
    }
    const result = await fake.command(args, options)
    if (kind === 'marker') {
      markerSeen = true
      clock = 25
    } else if (isStartupInspection) {
      clock = 55
    }
    return result
  }
  const execute = async (args, options = {}) => {
    const result = await fake.execute(args, options)
    if (markerSeen && !readinessObserved && commandKind(args) === 'health') {
      startupCalls.push({ kind: 'probe', at: clock, timeoutMs: options.timeoutMs })
      clock = 70
      readinessObserved = true
    }
    return result
  }

  await run(runnerInput(worker, fake, {
    overrides: {
      service: serviceConfig({ startup_timeout_ms: 100, probe_interval_ms: 10 }),
      command,
      execute,
      monotonicNow: () => clock,
    },
  }))

  assert.deepEqual(startupCalls.map(({ kind }) => kind), [
    'marker',
    'reinspection',
    'probe',
  ])
  for (const { at, timeoutMs } of startupCalls) {
    assert.equal(Number.isInteger(timeoutMs) && timeoutMs > 0, true)
    assert.equal(timeoutMs <= 100 - at, true)
  }
})

test('readiness observed at or after the startup deadline is rejected before target execution', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig())
  const fake = fakeDocker(worker, { healthCodes: [1, 0] })
  let clock = 0
  let healthCount = 0
  let caught

  try {
    await run(runnerInput(worker, fake, {
      overrides: {
        service: serviceConfig({ startup_timeout_ms: 100, probe_interval_ms: 10 }),
        monotonicNow: () => clock,
        execute: async (args, options = {}) => {
          const result = await fake.execute(args, options)
          if (commandKind(args) === 'health') {
            healthCount += 1
            if (healthCount === 2) clock = 100
          }
          return result
        },
      },
    }))
  } catch (error) {
    caught = error
  }

  assert.ok(caught)
  assert.equal(caught.code, 'SERVICE_PROOF_STARTUP_READINESS_TIMEOUT')
  assert.equal(caught.evidence.cleanup_verified, true)
  assert.equal(fake.calls.some(({ kind }) => kind === 'attack'), false)
  assert.equal(fake.calls.some(({ args }) => args.includes('rm')), true)
})

test('readiness polling caps sleep to the remaining startup deadline', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig())
  const fake = fakeDocker(worker, { healthCodes: [1, 1, 0] })
  const sleeps = []
  let clock = 0
  let healthCount = 0

  await assert.rejects(
    run(runnerInput(worker, fake, {
      overrides: {
        service: serviceConfig({ startup_timeout_ms: 100, probe_interval_ms: 80 }),
        monotonicNow: () => clock,
        execute: async (args, options = {}) => {
          const result = await fake.execute(args, options)
          if (commandKind(args) === 'health') {
            healthCount += 1
            if (healthCount === 2) clock = 75
          }
          return result
        },
        sleep: async (milliseconds) => {
          sleeps.push(milliseconds)
          clock += milliseconds
        },
      },
    })),
    (error) => error?.code === 'SERVICE_PROOF_STARTUP_READINESS_TIMEOUT',
  )
  assert.deepEqual(sleeps, [25])
  assert.equal(fake.calls.some(({ kind }) => kind === 'attack'), false)
})

test('service execution never inherits ambient credentials into Docker or container argv', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig())
  const fake = fakeDocker(worker)
  const prior = new Map()
  const secrets = {
    AWS_SECRET_ACCESS_KEY: 'ambient-aws-secret',
    DATABASE_URL: 'postgres://ambient-secret@example.test/db',
    GITHUB_TOKEN: 'ambient-github-token',
    SALESFORCE_ACCESS_TOKEN: 'ambient-salesforce-token',
  }
  for (const [key, value] of Object.entries(secrets)) {
    prior.set(key, process.env[key])
    process.env[key] = value
  }
  try {
    await run(runnerInput(worker, fake))
  } finally {
    for (const [key, value] of prior) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
  }

  const serializedCalls = JSON.stringify(fake.calls)
  for (const [key, value] of Object.entries(secrets)) {
    assert.equal(serializedCalls.includes(key), false)
    assert.equal(serializedCalls.includes(value), false)
  }
  for (const { args } of fake.calls) {
    assert.equal(args.some((arg) => /^--env(?:-file)?$/.test(arg)), false)
    assert.equal(args.some((arg) => /AWS_|DATABASE_URL|GITHUB_TOKEN|SALESFORCE/i.test(arg)), false)
  }
})

test('startup failure remains UNPROVEN, skips the target probe, and proves teardown', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig())
  const fake = fakeDocker(worker, { healthCodes: [1, 1, 1, 1] })
  let tick = 0
  let caught
  try {
    await run(runnerInput(worker, fake, {
      overrides: {
        service: serviceConfig({ startup_timeout_ms: 100, probe_interval_ms: 1 }),
        monotonicNow: () => {
          tick += 60
          return tick
        },
      },
    }))
  } catch (error) {
    caught = error
  }
  assert.ok(caught)
  assert.match(caught.message, /startup|readiness|health/i)
  assert.match(caught.code, /^SERVICE_PROOF_STARTUP_/)
  assert.equal(caught.evidence.verification_status, 'UNPROVEN')
  assert.match(caught.evidence.blocking_reason, /loopback.*readiness|startup/i)
  assert.equal(caught.evidence.cleanup_verified, true)
  assert.equal(fake.calls.some(({ kind }) => kind === 'attack'), false)
  assert.equal(fake.calls.some(({ kind }) => kind === 'control'), false)
  assert.equal(fake.calls.some(({ args }) => args.includes('kill')), true)
  assert.equal(fake.calls.some(({ args }) => args.includes('rm')), true)
  assert.equal([...fake.containers.values()].every(({ exists }) => !exists), true)
})

test('post-probe health loss cannot become T2 confirmation and still cleans up', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig())
  const fake = fakeDocker(worker, { healthCodes: [1, 0, 1] })
  let caught
  try {
    await run(runnerInput(worker, fake))
  } catch (error) {
    caught = error
  }
  assert.ok(caught)
  assert.match(caught.code, /^SERVICE_PROOF_POST_PROBE_/)
  assert.equal(caught.evidence.verification_status, 'UNPROVEN')
  assert.equal(caught.evidence.cleanup_verified, true)
  assert.equal(caught.partial_result.code, 1)
  assert.equal(caught.partial_result.stdout, '')
  assert.equal(caught.partial_result.stderr, '')
  assert.equal(caught.partial_result.output_omitted, true)
  assert.equal(fake.calls.filter(({ kind }) => kind === 'attack').length, 1)
  assert.equal(fake.calls.some(({ args }) => args.includes('kill')), true)
  assert.equal(fake.calls.some(({ args }) => args.includes('rm')), true)
})

test('unverified container cleanup fails closed and never falls back to the host', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig())
  const fake = fakeDocker(worker, { cleanupRemoves: false })
  let hostFallbacks = 0
  await assert.rejects(
    run(runnerInput(worker, fake, {
      overrides: {
        hostSpawn: () => {
          hostFallbacks += 1
          throw new Error('host execution forbidden')
        },
      },
    })),
    /could not prove.*container absent|remained after cleanup/i,
  )
  assert.equal(hostFallbacks, 0)
  assert.equal(fake.calls.some(({ args }) => args.includes('--signal=KILL')), true)
  assert.equal(fake.calls.some(({ args }) => args.includes('--force')), true)
  assert.equal(fake.calls.some(({ args }) => args.includes('--volumes')), true)
})

test('normal cleanup never deletes or clears a same-name replacement container', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig())
  const fake = fakeDocker(worker)
  const containerName = 'rta-proof-service-replacement0001'
  const replacementId = 'd'.repeat(64)
  let originalId
  let replaced = false

  const command = async (args, options = {}) => {
    if (!replaced && args.includes('kill')) {
      const original = fake.containers.get(containerName)
      originalId = original.id
      const inspection = structuredClone(original.inspection)
      inspection.Id = replacementId
      fake.containers.set(containerName, {
        exists: true,
        id: replacementId,
        inspection,
      })
      replaced = true
    }
    return fake.command(args, options)
  }

  let caught
  try {
    await run(runnerInput(worker, fake, {
      containerName,
      overrides: { command },
    }))
  } catch (error) {
    caught = error
  }

  assert.ok(caught)
  assert.equal(caught.code, 'SERVICE_PROOF_CLEANUP_UNVERIFIED')
  assert.equal(caught.evidence.cleanup_verified, false)
  assert.equal(fake.containers.get(containerName).exists, true)
  assert.equal(fake.containers.get(containerName).id, replacementId)
  const destructive = fake.calls.filter(({ args }) => args.includes('kill') || args.includes('rm'))
  assert.equal(destructive.length, 2)
  for (const { args } of destructive) {
    assert.equal(args.at(-1), originalId)
    assert.notEqual(args.at(-1), containerName)
    assert.notEqual(args.at(-1), replacementId)
  }
})

test('normal cleanup cannot clear a renamed original when immutable-ID removal fails', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig())
  const fake = fakeDocker(worker, { cleanupRemoves: false })
  const containerName = 'rta-proof-service-renamedoriginal1'
  const renamedName = 'rta-proof-service-renamedoriginal2'
  let originalId
  let renamed = false

  const command = async (args, options = {}) => {
    if (!renamed && args.includes('kill')) {
      const original = fake.containers.get(containerName)
      originalId = original.id
      original.inspection.Name = `/${renamedName}`
      fake.containers.delete(containerName)
      fake.containers.set(renamedName, original)
      renamed = true
    }
    const result = await fake.command(args, options)
    if (
      renamed
      && args.includes('container')
      && args.includes('inspect')
      && args.at(-1) === originalId
    ) {
      return {
        code: 0,
        signal: null,
        stdout: `${JSON.stringify(fake.containers.get(renamedName).inspection)}\n`,
        stderr: '',
      }
    }
    if (renamed && (args.includes('kill') || args.includes('rm'))) {
      return { ...result, code: 1, stderr: 'immutable-ID removal failed' }
    }
    return result
  }

  await assert.rejects(
    run(runnerInput(worker, fake, {
      containerName,
      overrides: { command },
    })),
    (error) => (
      error?.code === 'SERVICE_PROOF_CLEANUP_UNVERIFIED'
      && error?.evidence?.cleanup_verified === false
    ),
  )

  assert.equal(fake.containers.get(renamedName).exists, true)
  assert.equal(fake.containers.get(renamedName).id, originalId)
  assert.equal(
    fake.calls.some(({ args }) => args.includes('inspect') && args.at(-1) === originalId),
    true,
  )
})

test('normal cleanup follows the create-returned immutable ID when the leased name disappears', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig())
  const fake = fakeDocker(worker)
  const containerName = 'rta-proof-service-createwindow1'
  const renamedName = 'rta-proof-service-createwindow2'
  let originalId

  const command = async (args, options = {}) => {
    const result = await fake.command(args, options)
    if (args.includes('create')) {
      const original = fake.containers.get(containerName)
      originalId = original.id
      original.inspection.Name = `/${renamedName}`
      fake.containers.delete(containerName)
      fake.containers.set(renamedName, original)
    }
    return result
  }

  await assert.rejects(
    run(runnerInput(worker, fake, {
      containerName,
      overrides: { command },
    })),
    (error) => (
      error?.code === 'SERVICE_PROOF_EXECUTION_UNPROVEN'
      && error?.evidence?.cleanup_verified === true
    ),
  )

  assert.equal(fake.containers.get(renamedName).exists, false)
  const destructive = fake.calls.filter(({ args }) => args.includes('kill') || args.includes('rm'))
  assert.equal(destructive.length, 2)
  for (const { args } of destructive) {
    assert.equal(args.at(-1), originalId)
    assert.notEqual(args.at(-1), containerName)
    assert.notEqual(args.at(-1), renamedName)
  }
  assert.equal(
    fake.calls.some(({ args }) =>
      args.includes('--no-trunc') && args.includes(`--filter=id=${originalId}`)),
    true,
  )
})

test('confirmed create without any trusted immutable ID cannot clear on name absence', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig())
  const fake = fakeDocker(worker)
  const containerName = 'rta-proof-service-untrustedid1'
  const renamedName = 'rta-proof-service-untrustedid2'

  const command = async (args, options = {}) => {
    const result = await fake.command(args, options)
    if (args.includes('create')) {
      const original = fake.containers.get(containerName)
      original.inspection.Name = `/${renamedName}`
      fake.containers.delete(containerName)
      fake.containers.set(renamedName, original)
      return { ...result, stdout: 'not-a-container-id\n' }
    }
    return result
  }

  await assert.rejects(
    run(runnerInput(worker, fake, {
      containerName,
      overrides: { command },
    })),
    (error) => (
      error?.code === 'SERVICE_PROOF_CLEANUP_UNVERIFIED'
      && error?.evidence?.cleanup_verified === false
    ),
  )

  assert.equal(fake.containers.get(renamedName).exists, true)
  assert.equal(
    fake.calls.some(({ args }) =>
      (args.includes('kill') || args.includes('rm')) && args.at(-1) === containerName),
    false,
  )
})

test('cleanup authenticates a strict immutable ID when create output has no trusted ID', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig())
  const fake = fakeDocker(worker)
  const containerName = 'rta-proof-service-missingid0001'
  let inspectedId

  const command = async (args, options = {}) => {
    const result = await fake.command(args, options)
    if (args.includes('create')) {
      inspectedId = fake.containers.get(containerName).id
      return { ...result, stdout: 'not-a-container-id\n' }
    }
    return result
  }

  await assert.rejects(
    run(runnerInput(worker, fake, {
      containerName,
      overrides: { command },
    })),
    (error) => (
      error?.code === 'SERVICE_PROOF_EXECUTION_UNPROVEN'
      && error?.evidence?.cleanup_verified === true
    ),
  )

  const destructive = fake.calls.filter(({ args }) => args.includes('kill') || args.includes('rm'))
  assert.equal(destructive.length, 2)
  for (const { args } of destructive) assert.equal(args.at(-1), inspectedId)
  assert.equal(
    fake.calls.some(({ args }) => args.includes('inspect') && args.at(-1) === inspectedId),
    true,
  )
  assert.equal(
    fake.calls.some(({ args }) => (
      args.includes('--no-trunc') && args.includes(`--filter=id=${inspectedId}`)
    )),
    true,
  )
  assert.equal(fake.containers.get(containerName).exists, false)
})

test('controller config-root removal failure prevents success after container cleanup', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig())
  const fake = fakeDocker(worker)
  const removalSecret = 'controller-config-root-removal-secret'
  let controllerConfigRoot
  let containerCleanupFinished = false
  let caught
  try {
    try {
      await run(runnerInput(worker, fake, {
        overrides: {
          removeDockerConfigRoot: async (path) => {
            controllerConfigRoot = path
            containerCleanupFinished = fake.calls.some(({ args }) => args.includes('rm'))
              && fake.calls.some(({ args }) => args.includes('kill'))
            throw new Error(removalSecret)
          },
        },
      }))
    } catch (error) {
      caught = error
    }

    assert.ok(caught instanceof AggregateError)
    assert.equal(caught.code, 'SERVICE_PROOF_CONTROLLER_TEMP_CLEANUP_FAILED')
    assert.equal(caught.evidence.cleanup_verified, false)
    assert.equal(containerCleanupFinished, true)
    assert.equal(caught.errors.length, 1)
    assert.equal(caught.errors[0].message, removalSecret)
    assert.equal(caught.message.includes(removalSecret), false)
    assert.equal(caught.message.includes(controllerConfigRoot), false)
  } finally {
    if (controllerConfigRoot) {
      rmSync(controllerConfigRoot, { recursive: true, force: true })
    }
  }
})

test('controller config-root failure retains prior execution and container-cleanup causes', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig())
  const fake = fakeDocker(worker, {
    cleanupRemoves: false,
    healthCodes: [0],
  })
  const removalSecret = 'controller-config-root-removal-with-prior-causes'
  let controllerConfigRoot
  let caught
  try {
    try {
      await run(runnerInput(worker, fake, {
        overrides: {
          removeDockerConfigRoot: async (path) => {
            controllerConfigRoot = path
            throw new Error(removalSecret)
          },
        },
      }))
    } catch (error) {
      caught = error
    }

    assert.ok(caught instanceof AggregateError)
    assert.equal(caught.code, 'SERVICE_PROOF_CONTROLLER_TEMP_CLEANUP_FAILED')
    assert.equal(caught.evidence.cleanup_verified, false)
    assert.equal(caught.errors.length, 3)
    assert.match(caught.errors[0].message, /open.*before boot|proven closed/i)
    assert.match(caught.errors[1].message, /could not prove.*container absent/i)
    assert.equal(caught.errors[2].message, removalSecret)
    assert.equal(caught.message.includes(removalSecret), false)
    assert.equal(fake.calls.some(({ args }) => args.includes('--force')), true)
    assert.equal(fake.calls.some(({ args }) => args.includes('--volumes')), true)
  } finally {
    if (controllerConfigRoot) {
      rmSync(controllerConfigRoot, { recursive: true, force: true })
    }
  }
})

test('terminal Docker create failure is cleanup-verified only after exact absence proof', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig())
  const createError = new Error('Docker create returned a terminal rejection')
  createError.docker_outcome = 'TERMINAL'
  const fake = fakeDocker(worker, { createError })

  await assert.rejects(
    run(runnerInput(worker, fake)),
    (error) => (
      error?.code === 'SERVICE_PROOF_EXECUTION_UNPROVEN'
      && error?.evidence?.cleanup_verified === true
    ),
  )

  const createIndex = fake.calls.findIndex(({ args }) => args.includes('create'))
  const postCreateInspections = fake.calls.filter(
    ({ args }, index) => index > createIndex && args.includes('container') && args.includes('inspect'),
  )
  const postCreateListings = fake.calls.filter(
    ({ args }, index) => index > createIndex && args.includes('container') && args.includes('ls'),
  )
  assert.equal(postCreateInspections.length, 1)
  assert.equal(postCreateListings.length, 1)
  assert.equal(fake.calls.some(({ args }) => args.includes('kill')), false)
  assert.equal(fake.calls.some(({ args }) => args.includes('rm')), false)
})

test('terminal Docker create failure stays cleanup-unverified on inspect ambiguity or presence', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig())
  for (const failure of [
    { stateInspectionErrorAfterCreate: new Error('Docker inspect outcome is ambiguous') },
    { createLeavesContainer: true },
  ]) {
    const createError = new Error('Docker create returned a terminal rejection')
    createError.docker_outcome = 'TERMINAL'
    const fake = fakeDocker(worker, { createError, ...failure })

    await assert.rejects(
      run(runnerInput(worker, fake)),
      (error) => (
        error?.code === 'SERVICE_PROOF_CLEANUP_UNVERIFIED'
        && error?.evidence?.cleanup_verified !== true
      ),
    )
    assert.equal(fake.calls.some(({ args }) => args.includes('kill')), false)
    assert.equal(fake.calls.some(({ args }) => args.includes('rm')), false)
  }
})

test('a preexisting service-proof container is never adopted or removed', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig())
  const fake = fakeDocker(worker, { preexisting: true })

  await assert.rejects(
    run(runnerInput(worker, fake)),
    /already exists/i,
  )
  assert.equal(fake.calls.some(({ args }) => args.includes('create')), false)
  assert.equal(fake.calls.some(({ args }) => args.includes('kill')), false)
  assert.equal(fake.calls.some(({ args }) => args.includes('rm')), false)
})

test('image or dependency-manifest drift prevents boot and still verifies cleanup', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig())
  for (const mismatch of [
    { workerManifestSha256: 'd'.repeat(64) },
    { copiedManifestSha256: 'e'.repeat(64) },
  ]) {
    const fake = fakeDocker(worker, mismatch)
    await assert.rejects(
      run(runnerInput(worker, fake)),
      /dependency manifest.*does not match/i,
    )
    assert.equal(fake.calls.some(({ kind }) => kind === 'marker'), false)
    assert.equal(fake.calls.some(({ kind }) => kind === 'attack'), false)
    assert.equal(fake.calls.some(({ args }) => args.includes('rm')), true)
  }
})

test('the complete copied worktree is attested before boot, before attack, and after attack', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig())
  const fake = fakeDocker(worker)

  await run(runnerInput(worker, fake))

  const attestations = fake.calls.filter(({ args }) => args.some((arg) => (
    typeof arg === 'string'
    && arg.includes('red-team-audit/proof-worktree-manifest/v1')
  )))
  const marker = fake.calls.findIndex(({ kind }) => kind === 'marker')
  const attack = fake.calls.findIndex(({ kind }) => kind === 'attack')
  const seal = fake.calls.findIndex(({ args }) => args.includes('a-w,a+rX'))
  assert.equal(attestations.length, 3)
  assert.ok(seal >= 0 && seal < fake.calls.indexOf(attestations[0]))
  assert.ok(fake.calls.indexOf(attestations[0]) < marker)
  assert.ok(marker < fake.calls.indexOf(attestations[1]))
  assert.ok(fake.calls.indexOf(attestations[1]) < attack)
  assert.ok(attack < fake.calls.indexOf(attestations[2]))
  for (const attestation of attestations) {
    assert.equal(attestation.args.includes('--user=65532:65532'), true)
    assert.equal(attestation.args.includes('--workdir=/'), true)
  }
  const attackCall = fake.calls[attack]
  assert.equal(attackCall.args.includes('--user=65534:65534'), true)
  assert.equal(attackCall.args.includes('--env=HOME=/work/runtime'), true)
  assert.equal(attackCall.args.includes('--env=TMPDIR=/work/runtime'), true)
})

test('service mutation of sealed source before the attack fails closed', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig())
  const expected = await proofDocker.proofSourceTreeDigest(
    SOURCE_ROOT,
    worker.limits.max_source_bytes,
  )
  const fake = fakeDocker(worker, {
    worktreeDigests: [expected, 'f'.repeat(64)],
  })

  await assert.rejects(
    run(runnerInput(worker, fake)),
    (error) => (
      error?.code === 'SERVICE_PROOF_SOURCE_INTEGRITY_MISMATCH'
      && error?.evidence?.cleanup_verified === true
    ),
  )
  assert.equal(fake.calls.some(({ kind }) => kind === 'attack'), false)
  assert.equal(fake.calls.some(({ args }) => args.includes('rm')), true)
})

test('attack mutation of sealed source is detected and cannot yield a successful proof', async () => {
  const run = serviceRunner()
  const worker = normalizeProofWorkerConfig(workerConfig())
  const expected = await proofDocker.proofSourceTreeDigest(
    SOURCE_ROOT,
    worker.limits.max_source_bytes,
  )
  const fake = fakeDocker(worker, {
    worktreeDigests: [expected, expected, 'e'.repeat(64)],
  })

  await assert.rejects(
    run(runnerInput(worker, fake)),
    (error) => (
      error?.code === 'SERVICE_PROOF_SOURCE_INTEGRITY_MISMATCH'
      && error?.partial_result?.code === 1
      && error?.evidence?.cleanup_verified === true
    ),
  )
  assert.equal(fake.calls.filter(({ kind }) => kind === 'attack').length, 1)
  assert.equal(fake.calls.some(({ args }) => args.includes('rm')), true)
})
