import { EventEmitter } from 'node:events'
import { PassThrough } from 'node:stream'
import {
  computeConsumptionHmac,
} from '../../scripts/lib/provider-runner.mjs'

export const SHA_A = 'a'.repeat(64)
export const SHA_B = 'b'.repeat(64)
export const FILE_ARTIFACT_ID = 'fileartifactopaque0001'
export const CONTROL_ARTIFACT_ID = 'controlartifactopaque01'

export function providerConfig(overrides = {}) {
  const base = {
    schema_version: '1.0.0',
    protocol: 'docker-stdio-v1',
    runtime_path: '/trusted/bin/docker',
    image: `audit-provider@sha256:${SHA_A}`,
    receipt_signing_private_key_path: '/trusted/keys/receipt-ed25519.pem',
    limits: {
      wall_time_ms: 5000,
      docker_command_timeout_ms: 2000,
      idle_timeout_ms: 2000,
      delivery_timeout_ms: 2000,
      max_deliveries: 16,
      max_file_bytes: 1024,
      max_total_delivery_bytes: 8192,
      max_stdout_bytes: 65536,
      max_stderr_bytes: 8192,
      max_frame_bytes: 16384,
      memory_bytes: 67108864,
      cpus: 0.5,
      pids: 32,
      nofile: 64,
      tmpfs_bytes: 1048576,
    },
  }
  return {
    ...base,
    ...overrides,
    limits: {
      ...base.limits,
      ...(overrides.limits ?? {}),
    },
  }
}

export function providerPacket(overrides = {}) {
  return {
    schema_version: '1.0.0',
    run_id: 'run:provider-test',
    job_id: 'lens:web-and-api',
    kind: 'LENS',
    lens: 'web-and-api',
    capability_mode: 'STATIC',
    packet_sha256: SHA_B,
    repository_root: 'C:/secret/target',
    lens_file: 'C:/trusted/lenses/web-and-api.md',
    scoped_files: ['src/app.js'],
    owned_topics: ['authz-object-level'],
    known_topics: ['authz-object-level'],
    ...overrides,
  }
}

export function providerArtifacts(fileBytes = Buffer.from('const answer = 42\n')) {
  return [
    {
      artifact_id: FILE_ARTIFACT_ID,
      kind: 'FILE',
      logical_name: 'src/app.js',
      bytes: fileBytes,
    },
    {
      artifact_id: CONTROL_ARTIFACT_ID,
      kind: 'CONTROL',
      logical_name: 'lens:web-and-api@1.0.0',
      bytes: Buffer.from('# Trusted web lens\n'),
    },
  ]
}

export function providerBackend(overrides = {}) {
  return {
    type: 'OCI_DOCKER',
    runtime_path: '/trusted/bin/docker',
    runtime_version: '99.0.0',
    context: 'default',
    image: `audit-provider@sha256:${SHA_A}`,
    container_name: 'rta-provider-123456781234123412341234567890ab',
    container_id: SHA_B,
    security_profile: 'builtin',
    ...overrides,
  }
}

export function successfulJobResult(packet = providerPacket(), overrides = {}) {
  return {
    schema_version: '1.0.0',
    run_id: packet.run_id,
    job_id: packet.job_id,
    input_sha256: packet.packet_sha256,
    producer: {
      name: 'fixture-provider',
      version: '1.0.0',
      instance_id: 'fixture-provider:instance-1',
    },
    state: 'SUCCEEDED',
    examined_files: ['src/app.js'],
    findings: [],
    coverage_gaps: [],
    ...overrides,
  }
}

export async function* jsonLines(stream) {
  let buffered = Buffer.alloc(0)
  for await (const chunkValue of stream) {
    const chunk = Buffer.isBuffer(chunkValue) ? chunkValue : Buffer.from(chunkValue)
    buffered = Buffer.concat([buffered, chunk])
    while (true) {
      const newline = buffered.indexOf(0x0a)
      if (newline < 0) break
      const line = buffered.subarray(0, newline)
      buffered = buffered.subarray(newline + 1)
      yield JSON.parse(line.toString('utf8'))
    }
  }
  if (buffered.length !== 0) throw new Error('unterminated fixture JSONL')
}

export function sendJsonLine(stream, value) {
  stream.write(`${JSON.stringify(value)}\n`)
}

export async function runHonestProvider({
  stdin,
  stdout,
  artifactId = FILE_ARTIFACT_ID,
  resultOverrides = {},
  transformHmac = (value) => value,
}) {
  for await (const frame of jsonLines(stdin)) {
    if (frame.type === 'provider_start') {
      sendJsonLine(stdout, {
        type: 'artifact_request',
        schema_version: '1.0.0',
        session_id: frame.session_id,
        artifact_id: artifactId,
      })
      continue
    }
    if (frame.type !== 'artifact_delivery') continue
    const challenge = Buffer.from(frame.challenge_base64, 'base64')
    const bytes = Buffer.from(frame.content_base64, 'base64')
    const challengeHmac = computeConsumptionHmac({
      challenge,
      jobId: frame.artifact_id === artifactId
        ? 'lens:web-and-api'
        : 'lens:web-and-api',
      artifactId: frame.artifact_id,
      size: frame.size,
      bytes,
    })
    sendJsonLine(stdout, {
      type: 'artifact_consumed',
      schema_version: '1.0.0',
      session_id: frame.session_id,
      delivery_id: frame.delivery_id,
      artifact_id: frame.artifact_id,
      challenge_hmac_sha256: transformHmac(challengeHmac),
    })
    const packet = providerPacket()
    sendJsonLine(stdout, {
      type: 'job_result',
      schema_version: '1.0.0',
      session_id: frame.session_id,
      result: successfulJobResult(packet, resultOverrides),
    })
    stdout.end()
    return
  }
}

function commandChild(output, code = 0, errorOutput = '') {
  const child = new EventEmitter()
  child.stdin = null
  child.stdout = new PassThrough()
  child.stderr = new PassThrough()
  child.kill = () => true
  queueMicrotask(() => {
    if (output) child.stdout.write(output)
    if (errorOutput) child.stderr.write(errorOutput)
    child.stdout.end()
    child.stderr.end()
    child.emit('close', code, null)
  })
  return child
}

function hangingCommandChild() {
  const child = new EventEmitter()
  child.stdin = null
  child.stdout = new PassThrough()
  child.stderr = new PassThrough()
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
  return child
}

function spawnFailureCommandChild() {
  const child = new EventEmitter()
  child.stdin = null
  child.stdout = new PassThrough()
  child.stderr = new PassThrough()
  child.kill = () => true
  queueMicrotask(() => {
    const error = new Error('trusted Docker runtime could not be spawned')
    error.code = 'ENOENT'
    child.emit('error', error)
  })
  return child
}

function hardenedInspection(config, containerName, containerId) {
  return {
    Id: containerId,
    Name: `/${containerName}`,
    Mounts: [],
    Config: {
      User: '65532:65532',
      WorkingDir: '/work',
      OpenStdin: true,
      Tty: false,
      AttachStdout: true,
      AttachStderr: true,
      Env: [
        'HOME=/work',
        'TMPDIR=/work',
        'NO_COLOR=1',
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

export function createFakeDockerSpawn(config, behavior = {}) {
  const calls = []
  const containerId = SHA_B
  let containerName
  let containerExists = false

  const spawnImpl = (executable, args, options) => {
    calls.push({ executable, args: [...args], options })
    if (args.includes('context') && args.includes('inspect')) {
      return commandChild(`${JSON.stringify('npipe:////./pipe/docker_engine')}\n`)
    }
    if (args.includes('version')) {
      return commandChild(`${JSON.stringify('99.0.0')}\n`)
    }
    if (args.includes('image') && args.includes('inspect')) {
      return commandChild(`${JSON.stringify({ Config: { Volumes: null } })}\n`)
    }
    if (args.includes('create')) {
      containerName = args
        .find((value) => value.startsWith('--name='))
        .slice('--name='.length)
      if (behavior.createSpawnFailure === true) {
        containerExists = false
        return spawnFailureCommandChild()
      }
      if (behavior.createTimeout === true) {
        containerExists = behavior.createLeavesContainer === true
        return hangingCommandChild()
      }
      const createCode = behavior.createCode ?? 0
      containerExists = createCode === 0 || behavior.createLeavesContainer === true
      if (createCode !== 0) {
        return commandChild(
          '',
          createCode,
          behavior.createStderr ?? 'ambiguous Docker create failure',
        )
      }
      return commandChild(`${containerId}\n`)
    }
    if (args.includes('container') && args.includes('inspect')) {
      if (!containerExists) {
        return commandChild(
          '',
          1,
          `Error response from daemon: No such container: ${containerName}`,
        )
      }
      return commandChild(
        `${JSON.stringify(hardenedInspection(config, containerName, containerId))}\n`,
      )
    }
    if (args.includes('container') && args.includes('ls')) {
      return commandChild(
        containerExists ? `${JSON.stringify(containerName)}\n` : '',
      )
    }
    if (args.includes('start')) {
      const child = new EventEmitter()
      child.stdin = new PassThrough()
      child.stdout = new PassThrough()
      child.stderr = new PassThrough()
      child.kill = () => true
      queueMicrotask(async () => {
        try {
          await runHonestProvider({
            stdin: child.stdin,
            stdout: child.stdout,
          })
          child.stderr.end()
          child.emit('close', 0, null)
        } catch (error) {
          child.stderr.end(String(error))
          child.stdout.destroy(error)
          child.emit('close', 1, null)
        }
      })
      return child
    }
    if (args.includes('kill')) {
      return commandChild('')
    }
    if (args.includes('rm')) {
      const removeCode = behavior.removeCode ?? 0
      if (behavior.removeLeavesContainer !== true) containerExists = false
      return commandChild(
        '',
        removeCode,
        removeCode === 0
          ? ''
          : (behavior.removeStderr ?? 'Docker remove failed'),
      )
    }
    throw new Error(`unexpected fake Docker argv: ${JSON.stringify(args)}`)
  }
  return {
    calls,
    containerId,
    spawnImpl,
    get containerName() {
      return containerName
    },
    get containerExists() {
      return containerExists
    },
  }
}
