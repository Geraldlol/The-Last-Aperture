import { test } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { readFileSync } from 'node:fs'
import { PassThrough } from 'node:stream'

import {
  assertHardenedProofInspection,
  buildProofDockerCreateArgs,
  CONTROLLER_ARCHIVE_RUNTIME,
  CONTROLLER_DOCKER_RUNTIME,
  normalizeProofWorkerConfig,
  proofDependencyManifestDigest,
  proofWorkerConfigDigest,
  runDockerProofCommand,
  transferProofSourceArchive,
} from '../scripts/lib/proof-docker-runner.mjs'

const IMAGE = `sha256:${'a'.repeat(64)}`
const DEPENDENCY_MANIFEST_SHA256 = proofDependencyManifestDigest(
  readFileSync(new URL('../package.json', import.meta.url)),
  readFileSync(new URL('../package-lock.json', import.meta.url)),
)

function config(overrides = {}) {
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

function hardenedInspection(worker, name, overrides = {}) {
  const inspection = {
    Id: 'c'.repeat(64),
    Name: `/${name}`,
    Image: worker.image,
    Platform: 'linux',
    Config: {
      User: '65532:65532',
      WorkingDir: '/work',
      OpenStdin: true,
      Tty: false,
      AttachStdout: true,
      AttachStderr: true,
      Volumes: null,
      Entrypoint: ['/usr/local/bin/node'],
      Cmd: ['-e', 'setInterval(() => {}, 1 << 30)'],
      Healthcheck: { Test: ['NONE'] },
      Env: [
        'HOME=/work',
        'TMPDIR=/work',
        'NO_COLOR=1',
        'CI=1',
        'NODE_VERSION=22.0.0',
        'YARN_VERSION=1.22.22',
        'PATH=/opt/rta/node_modules/.bin:/usr/local/bin:/usr/bin:/bin',
        'HTTP_PROXY=', 'HTTPS_PROXY=', 'NO_PROXY=', 'ALL_PROXY=',
        'http_proxy=', 'https_proxy=', 'no_proxy=', 'all_proxy=',
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
      Tmpfs: {
        '/work': 'rw,noexec,nosuid,nodev,size=134217728,mode=0700,uid=65532,gid=65532',
      },
    },
    Mounts: [{ Type: 'tmpfs', Destination: '/work', Source: '', RW: true }],
  }
  return Object.assign(inspection, overrides)
}

test('proof worker configuration requires an immutable image and bounded local runtime', () => {
  const normalized = normalizeProofWorkerConfig(config())
  assert.equal(normalized.image, IMAGE)
  assert.match(proofWorkerConfigDigest(normalized), /^[a-f0-9]{64}$/)
  assert.equal(Object.isFrozen(normalized.limits), true)
  assert.throws(() => { normalized.limits.pids = 999 }, TypeError)

  assert.throws(
    () => normalizeProofWorkerConfig(config({ image: 'node:latest' })),
    /proof worker configuration is invalid/i,
  )
  assert.throws(
    () => normalizeProofWorkerConfig(config({ runtime_path: 'docker' })),
    /proof worker configuration is invalid/i,
  )
  for (const runtimePath of [
    `"${CONTROLLER_DOCKER_RUNTIME}"`,
    `${CONTROLLER_DOCKER_RUNTIME} --context attacker`,
    `${CONTROLLER_DOCKER_RUNTIME}\n--host=tcp://attacker`,
  ]) {
    assert.throws(
      () => normalizeProofWorkerConfig(config({ runtime_path: runtimePath })),
      /runtime_path/i,
    )
  }
})

test('proof worker create arguments enforce the no-network no-mount profile', () => {
  const args = buildProofDockerCreateArgs(
    normalizeProofWorkerConfig(config()),
    'rta-proof-12345678',
  )
  assert.deepEqual(args.slice(0, 2), ['--context', 'default'])
  for (const expected of [
    '--pull=never',
    '--network=none',
    '--read-only',
    '--cap-drop=ALL',
    '--security-opt=no-new-privileges=true',
    '--security-opt=seccomp=builtin',
    '--user=65532:65532',
    '--ipc=none',
    '--log-driver=none',
    '--entrypoint=/usr/local/bin/node',
  ]) {
    assert.equal(args.includes(expected), true, expected)
  }
  assert.equal(args.some((arg) => /(?:^|-)mount=|(?:^|-)volume=|^-v(?:=|$)/.test(arg)), false)
  assert.equal(args.includes(IMAGE), true)

  const maximums = config()
  maximums.limits.wall_time_ms = 3_600_000
  maximums.limits.max_output_bytes = 128 * 1024 * 1024
  assert.doesNotThrow(() => buildProofDockerCreateArgs(
    normalizeProofWorkerConfig(maximums),
    'rta-proof-87654321',
  ))
})

test('proof inspection rejects network, mounts, root, or image drift', () => {
  const worker = normalizeProofWorkerConfig(config())
  const name = 'rta-proof-12345678'
  const inspection = hardenedInspection(worker, name)

  assert.equal(assertHardenedProofInspection(inspection, worker, name), inspection.Id)
  for (const mutate of [
    (copy) => { copy.HostConfig.NetworkMode = 'bridge' },
    (copy) => { copy.HostConfig.Binds = ['C:\\host:/work'] },
    (copy) => { copy.Config.User = '0:0' },
    (copy) => { copy.Image = `sha256:${'d'.repeat(64)}` },
  ]) {
    const copy = structuredClone(inspection)
    mutate(copy)
    assert.throws(
      () => assertHardenedProofInspection(copy, worker, name),
      /proof Docker profile mismatch/i,
    )
  }
})

function fakeDocker(worker, {
  cleanupRemoves = true,
  copiedManifestSha256 = worker.dependency_manifest_sha256,
  createError,
  failKill = false,
  imageInspectionMutator,
  inspectionMutator,
  preexisting = false,
  targetResult,
  workerManifestSha256 = worker.dependency_manifest_sha256,
} = {}) {
  const calls = []
  const name = 'rta-proof-1234567890abcdef'
  const inspection = hardenedInspection(worker, name)
  inspectionMutator?.(inspection)
  const imageInspection = {
    Id: worker.image,
    Os: 'linux',
    Config: {
      Labels: { 'dev.red-team-audit.proof-worker': worker.protocol },
    },
  }
  imageInspectionMutator?.(imageInspection)
  let created = false
  const command = async (args, options = {}) => {
    calls.push({ type: 'command', args, options })
    const joined = args.join(' ')
    if (joined.includes('context inspect')) {
      return { code: 0, stdout: '"npipe:////./pipe/docker_engine"\n', stderr: '' }
    }
    if (joined.includes('version --format')) {
      return { code: 0, stdout: '"29.5.3"\n', stderr: '' }
    }
    if (joined.includes('image inspect')) {
      return {
        code: 0,
        stdout: `${JSON.stringify(imageInspection)}\n`,
        stderr: '',
      }
    }
    if (args.includes('create')) {
      if (createError) throw createError
      created = true
      return { code: 0, stdout: `${inspection.Id}\n`, stderr: '' }
    }
    if (joined.includes('container inspect')) {
      return created || preexisting
        ? { code: 0, stdout: `${JSON.stringify(inspection)}\n`, stderr: '' }
        : { code: 1, stdout: '', stderr: 'No such container' }
    }
    if (joined.includes('container ls')) {
      return {
        code: 0,
        stdout: created || preexisting ? `${JSON.stringify(name)}\n` : '',
        stderr: '',
      }
    }
    if (args.includes('/opt/rta/package-lock.json')) {
      return { code: 0, stdout: workerManifestSha256, stderr: '' }
    }
    if (args.includes('/work/repo/package-lock.json')) {
      return { code: 0, stdout: copiedManifestSha256, stderr: '' }
    }
    if (args.includes('kill') && failKill) {
      throw new Error('simulated kill transport failure')
    }
    if (args.includes('rm') && cleanupRemoves) {
      created = false
      preexisting = false
    }
    return { code: 0, stdout: '', stderr: '' }
  }
  const execute = async (args, options = {}) => {
    calls.push({ type: 'execute', args, options })
    return targetResult ?? {
      code: 1,
      signal: null,
      timed_out: false,
      spawn_error: false,
      duration_ms: 12,
      stdout: '',
      stderr: '',
      stdout_bytes: 25,
      stdout_sha256: 'd'.repeat(64),
      stdout_truncated: false,
      stderr_bytes: 0,
      stderr_sha256: 'e'.repeat(64),
      stderr_truncated: false,
      output_omitted: true,
    }
  }
  const transfer = async (options = {}) => {
    calls.push({ type: 'transfer', args: [], options })
    return { archive_bytes: 4096 }
  }
  return { calls, command, execute, name, transfer }
}

test('Docker proof execution streams sealed bytes into tmpfs without a host mount and cleans the container', async () => {
  const worker = normalizeProofWorkerConfig(config())
  const fake = fakeDocker(worker)
  const result = await runDockerProofCommand({
    config: worker,
    sourceRoot: process.cwd(),
    program: 'node',
    args: ['test/security/attack.mjs'],
    limits: { timeout_ms: 1_000, kill_grace_ms: 10, max_output_bytes: 4_096 },
    command: fake.command,
    execute: fake.execute,
    transfer: fake.transfer,
    containerName: fake.name,
  })

  assert.equal(result.code, 1)
  assert.equal(result.stdout, '')
  assert.equal(result.output_omitted, true)
  assert.equal(result.sandbox.cleanup_verified, true)
  assert.equal(result.sandbox.network_mode, 'none')
  const transfer = fake.calls.find(({ type }) => type === 'transfer')
  assert.equal(transfer.options.sourceRoot, process.cwd())
  assert.equal(transfer.options.dockerRuntimePath, CONTROLLER_DOCKER_RUNTIME)
  assert.equal(fake.calls.some(({ args }) => args.includes('cp')), false)
  const mkdir = fake.calls.find(({ args }) => args.includes('/bin/mkdir'))
  assert.equal(mkdir.args.includes('--mode=0700'), true)
  const chmod = fake.calls.find(({ args }) => args.includes('/bin/chmod'))
  assert.deepEqual(chmod.args.slice(-3), ['-R', 'u+rwX', '/work/repo'])
  assert.equal(fake.calls.some(({ args }) => args.includes('/bin/chown')), false)
  assert.equal(fake.calls.some(({ args }) => args.some((arg) => /^-v|--mount/.test(arg))), false)
  assert.equal(fake.calls.some(({ args }) => args.includes('--signal=KILL')), true)
  assert.equal(fake.calls.some(({ args }) => args.includes('--volumes')), true)
})

test('source archive transfer is a shell-free binary pipe between fixed runtimes', async () => {
  const calls = []
  const extracted = []
  const archive = Buffer.from('binary\0archive\r\nbytes', 'utf8')
  const spawnImpl = (executable, args, options) => {
    calls.push({ executable, args, options })
    const child = new EventEmitter()
    child.stdout = new PassThrough()
    child.stderr = new PassThrough()
    child.stdin = new PassThrough()
    child.kill = () => true
    if (executable === CONTROLLER_DOCKER_RUNTIME) {
      child.stdin.on('data', (chunk) => extracted.push(Buffer.from(chunk)))
      child.stdin.once('finish', () => queueMicrotask(() => child.emit('close', 0, null)))
    } else {
      queueMicrotask(() => {
        child.stdout.end(archive)
        child.stderr.end()
        child.emit('close', 0, null)
      })
    }
    return child
  }

  const result = await transferProofSourceArchive({
    containerName: 'rta-proof-12345678',
    dockerRuntimePath: CONTROLLER_DOCKER_RUNTIME,
    sourceRoot: process.cwd(),
    dockerConfigRoot: undefined,
    maxSourceBytes: 1024 * 1024,
    timeoutMs: 1_000,
    spawnImpl,
  })

  assert.equal(result.archive_bytes, archive.length)
  assert.deepEqual(Buffer.concat(extracted), archive)
  assert.equal(calls.length, 2)
  assert.equal(calls[0].executable, CONTROLLER_DOCKER_RUNTIME)
  assert.equal(calls[0].options.shell, false)
  assert.deepEqual(calls[0].args.slice(-5), ['/bin/tar', '-xf', '-', '-C', '/work/repo'])
  assert.equal(calls[0].args.includes('--interactive'), true)
  assert.equal(calls[0].args.includes('--user=65532:65532'), true)
  assert.equal(calls[1].executable, CONTROLLER_ARCHIVE_RUNTIME)
  assert.deepEqual(calls[1].args, ['-cf', '-', '.'])
  assert.equal(calls[1].options.cwd, process.cwd())
  assert.equal(calls[1].options.shell, false)
})

test('source and immutable worker dependency manifests must match the configured digest', async () => {
  const sourceMismatch = normalizeProofWorkerConfig(config({
    dependency_manifest_sha256: 'd'.repeat(64),
  }))
  const sourceFake = fakeDocker(sourceMismatch)
  await assert.rejects(
    runDockerProofCommand({
      config: sourceMismatch,
      sourceRoot: process.cwd(),
      program: 'node',
      args: ['test/security/attack.mjs'],
      command: sourceFake.command,
      execute: sourceFake.execute,
      containerName: sourceFake.name,
    }),
    /source dependency manifest.*does not match/i,
  )
  assert.equal(sourceFake.calls.length, 0)

  const worker = normalizeProofWorkerConfig(config())
  for (const mismatch of [
    { workerManifestSha256: 'd'.repeat(64) },
    { copiedManifestSha256: 'e'.repeat(64) },
  ]) {
    const fake = fakeDocker(worker, mismatch)
    await assert.rejects(
      runDockerProofCommand({
        config: worker,
        sourceRoot: process.cwd(),
        program: 'node',
        args: ['test/security/attack.mjs'],
        command: fake.command,
        execute: fake.execute,
        transfer: fake.transfer,
        containerName: fake.name,
      }),
      /dependency manifest.*does not match/i,
    )
    assert.equal(fake.calls.some(({ type }) => type === 'execute'), false)
    assert.equal(fake.calls.some(({ args }) => args.includes('--volumes')), true)
  }
})

test('worker image protocol label is part of immutable image validation', async () => {
  const worker = normalizeProofWorkerConfig(config())
  const fake = fakeDocker(worker, {
    imageInspectionMutator(inspection) {
      inspection.Config.Labels['dev.red-team-audit.proof-worker'] = 'wrong-protocol'
    },
  })
  await assert.rejects(
    runDockerProofCommand({
      config: worker,
      sourceRoot: process.cwd(),
      program: 'node',
      args: ['test/security/attack.mjs'],
      command: fake.command,
      execute: fake.execute,
      containerName: fake.name,
    }),
    /worker image protocol label/i,
  )
  assert.equal(fake.calls.some(({ args }) => args.includes('create')), false)
})

test('a pre-existing exact-name container is never adopted or removed', async () => {
  const worker = normalizeProofWorkerConfig(config())
  const fake = fakeDocker(worker, { preexisting: true })
  await assert.rejects(
    runDockerProofCommand({
      config: worker,
      sourceRoot: process.cwd(),
      program: 'node',
      args: ['test/security/attack.mjs'],
      command: fake.command,
      execute: fake.execute,
      containerName: fake.name,
    }),
    /already exists/i,
  )
  assert.equal(fake.calls.some(({ args }) => args.includes('create')), false)
  assert.equal(fake.calls.some(({ args }) => args.includes('kill')), false)
  assert.equal(fake.calls.some(({ args }) => args.includes('rm')), false)
})

test('cleanup continues through kill failure but fails closed when absence is unproven', async () => {
  const worker = normalizeProofWorkerConfig(config())
  const recovered = fakeDocker(worker, { failKill: true })
  const result = await runDockerProofCommand({
    config: worker,
    sourceRoot: process.cwd(),
    program: 'node',
    args: ['test/security/attack.mjs'],
    command: recovered.command,
    execute: recovered.execute,
    transfer: recovered.transfer,
    containerName: recovered.name,
  })
  assert.equal(result.sandbox.cleanup_verified, true)
  assert.equal(recovered.calls.some(({ args }) => args.includes('rm')), true)

  const retained = fakeDocker(worker, { cleanupRemoves: false })
  await assert.rejects(
    runDockerProofCommand({
      config: worker,
      sourceRoot: process.cwd(),
      program: 'node',
      args: ['test/security/attack.mjs'],
      command: retained.command,
      execute: retained.execute,
      transfer: retained.transfer,
      containerName: retained.name,
    }),
    /could not prove.*container absent|remained after cleanup/i,
  )
})

test('an indeterminate create outcome is never reported as verified cleanup', async () => {
  const worker = normalizeProofWorkerConfig(config())
  const fake = fakeDocker(worker, { createError: new Error('create client disappeared') })
  await assert.rejects(
    runDockerProofCommand({
      config: worker,
      sourceRoot: process.cwd(),
      program: 'node',
      args: ['test/security/attack.mjs'],
      command: fake.command,
      execute: fake.execute,
      containerName: fake.name,
    }),
    /create did not reach a confirmed terminal outcome/i,
  )
  assert.equal(fake.calls.some(({ args }) => args.includes('rm')), true)
})

function synchronouslyFailingChild(message) {
  const stdout = new EventEmitter()
  const stderr = new EventEmitter()
  const child = {
    stdout,
    stderr,
    kill() { return true },
    once(event, listener) {
      if (event === 'error') listener(new Error(message))
      return child
    },
  }
  return child
}

test('Docker child errors cannot race timer initialization', async () => {
  const worker = normalizeProofWorkerConfig(config())
  await assert.rejects(
    runDockerProofCommand({
      config: worker,
      sourceRoot: process.cwd(),
      program: 'node',
      args: ['test/security/attack.mjs'],
      spawnImpl: () => synchronouslyFailingChild('control spawn failed'),
    }),
    /could not start the controller Docker runtime: control spawn failed/i,
  )

  const fake = fakeDocker(worker)
  const result = await runDockerProofCommand({
    config: worker,
    sourceRoot: process.cwd(),
    program: 'node',
    args: ['test/security/attack.mjs'],
    command: fake.command,
    transfer: fake.transfer,
    spawnImpl: () => synchronouslyFailingChild('target spawn failed'),
    containerName: fake.name,
  })
  assert.equal(result.code, 127)
  assert.equal(result.spawn_error, true)
  assert.equal(result.sandbox.cleanup_verified, true)
})

test('inspection drift refuses target execution and still verifies cleanup', async () => {
  const worker = normalizeProofWorkerConfig(config())
  const fake = fakeDocker(worker, {
    inspectionMutator(inspection) {
      inspection.HostConfig.NetworkMode = 'bridge'
    },
  })
  await assert.rejects(
    runDockerProofCommand({
      config: worker,
      sourceRoot: process.cwd(),
      program: 'node',
      args: ['test/security/attack.mjs'],
      limits: { timeout_ms: 1_000, kill_grace_ms: 10, max_output_bytes: 4_096 },
      command: fake.command,
      execute: fake.execute,
      containerName: fake.name,
    }),
    /network mode|profile mismatch/i,
  )
  assert.equal(fake.calls.some(({ type }) => type === 'execute'), false)
  assert.equal(fake.calls.some(({ args }) => args.includes('--volumes')), true)
})

test('proof worker maps only controller-owned Node executables', async () => {
  const worker = normalizeProofWorkerConfig(config())
  const fake = fakeDocker(worker)
  await assert.rejects(
    runDockerProofCommand({
      config: worker,
      sourceRoot: process.cwd(),
      program: 'curl',
      args: ['https://example.test'],
      command: fake.command,
      execute: fake.execute,
      containerName: fake.name,
    }),
    /unsupported proof program/i,
  )
  assert.equal(fake.calls.length, 0)
})
