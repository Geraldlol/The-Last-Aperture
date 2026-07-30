import { spawn as nodeSpawn } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'
import {
  assertValidDatabaseConformanceConfig,
  assertValidDatabaseConformanceResult,
  databaseConformanceManifest,
} from './database-conformance-contracts.mjs'
import { compareCanonicalStrings } from './canonical-order.mjs'

const SHA256_PATTERN = /^[a-f0-9]{64}$/
const IMAGE_ID_PATTERN = /^sha256:[a-f0-9]{64}$/
const CONTAINER_NAME_PATTERN = /^[a-z0-9][a-z0-9_.-]{7,127}$/
const PROXY_KEYS = [
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'NO_PROXY',
  'ALL_PROXY',
  'http_proxy',
  'https_proxy',
  'no_proxy',
  'all_proxy',
]

const ENGINE_RUNTIME = Object.freeze({
  'postgresql-18.4': Object.freeze({
    user: 'postgres:postgres',
    dataPaths: Object.freeze([
      '/var/lib/postgresql',
      '/var/run/postgresql',
      '/tmp',
    ]),
    environment(secret) {
      return {
        POSTGRES_PASSWORD: secret,
        POSTGRES_DB: 'rta_lab',
        PGDATA: '/var/lib/postgresql/18/docker',
      }
    },
    command: Object.freeze([
      'postgres',
      '-c',
      'wal_level=logical',
      '-c',
      'max_wal_senders=4',
      '-c',
      'max_replication_slots=4',
    ]),
  }),
  'mysql-8.4.10': Object.freeze({
    user: 'mysql:mysql',
    dataPaths: Object.freeze([
      '/var/lib/mysql',
      '/var/lib/mysql-files',
      '/var/run/mysqld',
      '/tmp',
    ]),
    environment(secret) {
      return {
        MYSQL_ROOT_PASSWORD: secret,
        MYSQL_DATABASE: 'rta_lab',
      }
    },
    command: Object.freeze([
      'mysqld',
      '--log-bin=binlog',
      '--server-id=1',
      '--binlog-format=ROW',
      '--secure-file-priv=/var/lib/mysql-files',
      '--local-infile=OFF',
    ]),
  }),
})

export class DatabaseConformanceRunnerError extends Error {
  constructor(code, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'DatabaseConformanceRunnerError'
    this.code = code
    if (options.stderr) this.stderr = options.stderr
    if (options.details) this.details = options.details
  }
}

function runnerError(code, message, options) {
  return new DatabaseConformanceRunnerError(code, message, options)
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function sanitizeDiagnostic(value) {
  return String(value)
    .replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g, '')
    .replace(/\x1b(?:[@-_]|\[[0-?]*[ -/]*[@-~])/g, '')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '\uFFFD')
}

function sanitizedDockerEnvironment() {
  const environment = { ...process.env }
  for (const key of [
    'DOCKER_HOST',
    'DOCKER_CONTEXT',
    'DOCKER_TLS',
    'DOCKER_TLS_VERIFY',
    'DOCKER_CERT_PATH',
    ...PROXY_KEYS,
  ]) {
    delete environment[key]
  }
  return environment
}

export async function runDatabaseDockerCommand({
  runtimePath,
  args,
  spawnImpl = nodeSpawn,
  timeoutMs,
  maxOutputBytes,
  input,
  allowNonZero = false,
}) {
  const child = spawnImpl(runtimePath, args, {
    shell: false,
    windowsHide: true,
    stdio: ['pipe', 'pipe', 'pipe'],
    env: sanitizedDockerEnvironment(),
  })
  const stdout = []
  const stderr = []
  let stdoutBytes = 0
  let stderrBytes = 0

  return await new Promise((resolve, reject) => {
    let settled = false
    let timer
    const finish = (callback) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      callback()
    }
    const fail = (code, message, cause) => finish(() => reject(runnerError(
      code,
      message,
      {
        cause,
        stderr: sanitizeDiagnostic(Buffer.concat(stderr).toString('utf8')),
      },
    )))
    const capture = (target, isStdout) => (chunkValue) => {
      const chunk = Buffer.isBuffer(chunkValue) ? chunkValue : Buffer.from(chunkValue)
      if (isStdout) stdoutBytes += chunk.length
      else stderrBytes += chunk.length
      if (stdoutBytes + stderrBytes > maxOutputBytes) {
        child.kill?.('SIGKILL')
        fail(
          'DATABASE_CONFORMANCE_DOCKER_OUTPUT_LIMIT',
          'Docker command exceeded the combined output limit',
        )
        return
      }
      target.push(chunk)
    }
    child.stdout?.on('data', capture(stdout, true))
    child.stderr?.on('data', capture(stderr, false))
    child.stdin?.on('error', (error) => fail(
      'DATABASE_CONFORMANCE_DOCKER_STDIN_FAILED',
      'could not write bounded input to the trusted Docker runtime',
      error,
    ))
    child.once('error', (error) => fail(
      'DATABASE_CONFORMANCE_DOCKER_SPAWN_FAILED',
      'could not start the trusted Docker runtime',
      error,
    ))
    child.once('close', (code, signal) => finish(() => {
      const stdoutText = Buffer.concat(stdout).toString('utf8')
      const stderrText = sanitizeDiagnostic(Buffer.concat(stderr).toString('utf8'))
      if (code !== 0 && !allowNonZero) {
        reject(runnerError(
          'DATABASE_CONFORMANCE_DOCKER_COMMAND_FAILED',
          `Docker command failed with code ${String(code)} signal ${String(signal)}`,
          { stderr: stderrText },
        ))
        return
      }
      resolve({
        code,
        signal,
        stdout: stdoutText,
        stderr: stderrText,
      })
    }))
    timer = setTimeout(() => {
      child.kill?.('SIGKILL')
      fail(
        'DATABASE_CONFORMANCE_DOCKER_COMMAND_TIMEOUT',
        `Docker command exceeded its ${timeoutMs}ms timeout`,
      )
    }, timeoutMs)
    timer.unref?.()

    if (input === undefined) {
      child.stdin?.end()
    } else {
      child.stdin?.end(Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'utf8'))
    }
  })
}

function parseDockerJson(text, label) {
  try {
    return JSON.parse(String(text).trim())
  } catch (error) {
    throw runnerError(
      'DATABASE_CONFORMANCE_DOCKER_JSON_INVALID',
      `${label} did not return one valid JSON value`,
      { cause: error },
    )
  }
}

function assertion(condition, code, message) {
  if (!condition) throw runnerError(code, message)
}

function emptyOrAbsent(value) {
  return value === undefined
    || value === null
    || (Array.isArray(value) && value.length === 0)
    || (
      typeof value === 'object'
      && !Array.isArray(value)
      && Object.keys(value).length === 0
    )
}

export function assertLocalDatabaseDockerContextHost(value) {
  assertion(
    typeof value === 'string' && /^(?:unix|npipe):\/\//.test(value),
    'DATABASE_CONFORMANCE_DOCKER_CONTEXT_NOT_LOCAL',
    'Docker default context must use a local unix:// or npipe:// endpoint',
  )
  return value
}

function engineDefinition(engineId, manifest = databaseConformanceManifest) {
  const engine = manifest.engines.find(({ engine_id: candidate }) => candidate === engineId)
  const runtime = ENGINE_RUNTIME[engineId]
  if (!engine || !runtime) {
    throw runnerError(
      'DATABASE_CONFORMANCE_ENGINE_UNSUPPORTED',
      `engine ${JSON.stringify(engineId)} is absent from the v1 lab`,
    )
  }
  return { ...engine, runtime }
}

function tmpfsOption(path, size, mode = '0700') {
  return `${path}:rw,noexec,nosuid,nodev,size=${size},mode=${mode},uid=999,gid=999`
}

function containerLabels(runId, engineId) {
  return {
    'dev.red-team-audit.owner': 'database-conformance',
    'dev.red-team-audit.run-id': runId,
    'dev.red-team-audit.engine-id': engineId,
  }
}

export function databaseConformanceContainerName(runId, engineId) {
  const suffix = runId.split(':').at(-1)
  const engineToken = engineId.replaceAll(/[^a-z0-9]+/g, '-')
  const name = `rta-db-lab-${suffix}-${engineToken}`
  assertion(
    CONTAINER_NAME_PATTERN.test(name),
    'DATABASE_CONFORMANCE_CONTAINER_NAME_INVALID',
    'derived database conformance container name is invalid',
  )
  return name
}

export function buildDatabaseDockerCreateArgs({
  engine,
  config,
  runId,
  containerName,
  secret,
}) {
  assertValidDatabaseConformanceConfig(config)
  assertion(
    CONTAINER_NAME_PATTERN.test(containerName),
    'DATABASE_CONFORMANCE_CONTAINER_NAME_INVALID',
    'database conformance container name is invalid',
  )
  const definition = engineDefinition(engine.engine_id)
  const labels = containerLabels(runId, engine.engine_id)
  const auxiliaryTmpfsBytes = Math.min(config.limits.tmpfs_bytes, 64 * 1024 * 1024)
  const tmpfs = definition.runtime.dataPaths.map((path, index) =>
    tmpfsOption(
      path,
      index === 0 ? config.limits.tmpfs_bytes : auxiliaryTmpfsBytes,
      path === '/tmp' ? '1770' : '0700',
    ))
  const environment = {
    ...definition.runtime.environment(secret),
    HOME: '/tmp',
    TMPDIR: '/tmp',
    NO_COLOR: '1',
    ...Object.fromEntries(PROXY_KEYS.map((key) => [key, ''])),
  }
  return [
    '--context',
    'default',
    'create',
    `--name=${containerName}`,
    '--pull=never',
    '--network=none',
    '--read-only',
    '--cap-drop=ALL',
    '--security-opt=no-new-privileges=true',
    '--security-opt=seccomp=builtin',
    `--user=${definition.runtime.user}`,
    `--pids-limit=${config.limits.pids}`,
    `--memory=${config.limits.memory_bytes}`,
    `--memory-swap=${config.limits.memory_bytes}`,
    `--cpus=${String(config.limits.cpus)}`,
    `--ulimit=nofile=${config.limits.nofile}:${config.limits.nofile}`,
    '--ipc=private',
    '--shm-size=67108864',
    '--log-driver=none',
    '--restart=no',
    '--no-healthcheck',
    ...Object.entries(labels).map(([key, value]) => `--label=${key}=${value}`),
    ...tmpfs.map((value) => `--tmpfs=${value}`),
    ...Object.entries(environment).map(([key, value]) => `--env=${key}=${value}`),
    engine.image,
    ...definition.runtime.command,
  ]
}

export function assertSafeDatabaseImageInspection(inspection, engine) {
  assertion(
    inspection && typeof inspection === 'object' && !Array.isArray(inspection),
    'DATABASE_CONFORMANCE_IMAGE_INSPECTION_INVALID',
    'Docker image inspection must be an object',
  )
  assertion(
    IMAGE_ID_PATTERN.test(inspection.Id ?? ''),
    'DATABASE_CONFORMANCE_IMAGE_ID_INVALID',
    'Docker image inspection is missing an immutable image ID',
  )
  assertion(
    inspection.Os === 'linux' && ['amd64', 'arm64'].includes(inspection.Architecture),
    'DATABASE_CONFORMANCE_IMAGE_PLATFORM_UNSUPPORTED',
    'database conformance images must be Linux amd64 or arm64',
  )
  assertion(
    Array.isArray(inspection.RepoDigests)
      && inspection.RepoDigests.includes(engine.image),
    'DATABASE_CONFORMANCE_IMAGE_DIGEST_MISMATCH',
    'local image does not expose the exact manifest repository digest',
  )
  const definition = engineDefinition(engine.engine_id)
  const declaredVolumes = Object.keys(inspection.Config?.Volumes ?? {})
  assertion(
    declaredVolumes.every((path) => definition.runtime.dataPaths.includes(path)),
    'DATABASE_CONFORMANCE_IMAGE_VOLUME_UNEXPECTED',
    'database image declares a volume outside the controller-owned tmpfs set',
  )
  return {
    imageId: inspection.Id,
    repoDigests: [...inspection.RepoDigests].sort(compareCanonicalStrings),
    platform: {
      os: inspection.Os,
      architecture: inspection.Architecture,
    },
  }
}

function parseEnvironment(entries = []) {
  return new Map(entries.map((entry) => {
    const separator = entry.indexOf('=')
    return separator < 0
      ? [entry, undefined]
      : [entry.slice(0, separator), entry.slice(separator + 1)]
  }))
}

function tmpfsOptionSet(value) {
  return new Set(String(value ?? '').split(',').filter(Boolean))
}

export function assertHardenedDatabaseContainerInspection({
  inspection,
  engine,
  config,
  runId,
  containerName,
  imageId,
}) {
  const definition = engineDefinition(engine.engine_id)
  assertion(
    inspection && typeof inspection === 'object' && !Array.isArray(inspection),
    'DATABASE_CONFORMANCE_CONTAINER_INSPECTION_INVALID',
    'Docker container inspection must be an object',
  )
  assertion(
    SHA256_PATTERN.test(inspection.Id ?? ''),
    'DATABASE_CONFORMANCE_CONTAINER_ID_INVALID',
    'container inspection is missing a full immutable ID',
  )
  assertion(
    inspection.Name === `/${containerName}` || inspection.Name === containerName,
    'DATABASE_CONFORMANCE_CONTAINER_NAME_MISMATCH',
    'container inspection returned the wrong name',
  )
  assertion(
    inspection.Image === imageId,
    'DATABASE_CONFORMANCE_CONTAINER_IMAGE_MISMATCH',
    'container image identity differs from the inspected pinned image',
  )
  const expectedLabels = containerLabels(runId, engine.engine_id)
  for (const [key, value] of Object.entries(expectedLabels)) {
    assertion(
      inspection.Config?.Labels?.[key] === value,
      'DATABASE_CONFORMANCE_CONTAINER_LABEL_MISMATCH',
      `container label ${key} does not bind the planned run and engine`,
    )
  }

  const host = inspection.HostConfig ?? {}
  const container = inspection.Config ?? {}
  assertion(host.NetworkMode === 'none', 'DATABASE_CONFORMANCE_NETWORK_ENABLED',
    'container network mode is not none')
  assertion(host.ReadonlyRootfs === true, 'DATABASE_CONFORMANCE_ROOTFS_WRITABLE',
    'container root filesystem is not read-only')
  assertion(host.Privileged === false, 'DATABASE_CONFORMANCE_PRIVILEGED',
    'container is privileged')
  assertion(emptyOrAbsent(host.CapAdd), 'DATABASE_CONFORMANCE_CAPABILITY_ADDED',
    'container has added Linux capabilities')
  assertion(
    Array.isArray(host.CapDrop) && host.CapDrop.includes('ALL'),
    'DATABASE_CONFORMANCE_CAPABILITIES_NOT_DROPPED',
    'container does not drop all Linux capabilities',
  )
  assertion(
    Array.isArray(host.SecurityOpt)
      && host.SecurityOpt.includes('no-new-privileges=true')
      && host.SecurityOpt.includes('seccomp=builtin'),
    'DATABASE_CONFORMANCE_SECURITY_PROFILE_DRIFT',
    'container does not enforce no-new-privileges and builtin seccomp',
  )
  assertion(host.PidsLimit === config.limits.pids, 'DATABASE_CONFORMANCE_PIDS_DRIFT',
    'container PID limit drifted')
  assertion(host.Memory === config.limits.memory_bytes, 'DATABASE_CONFORMANCE_MEMORY_DRIFT',
    'container memory limit drifted')
  assertion(host.MemorySwap === config.limits.memory_bytes,
    'DATABASE_CONFORMANCE_SWAP_DRIFT', 'container memory-swap limit drifted')
  assertion(
    host.NanoCpus === Math.round(config.limits.cpus * 1_000_000_000),
    'DATABASE_CONFORMANCE_CPU_DRIFT',
    'container CPU limit drifted',
  )
  const nofile = (host.Ulimits ?? []).find(({ Name }) => Name === 'nofile')
  assertion(
    nofile?.Soft === config.limits.nofile && nofile?.Hard === config.limits.nofile,
    'DATABASE_CONFORMANCE_NOFILE_DRIFT',
    'container nofile limit drifted',
  )
  assertion(host.IpcMode === 'private', 'DATABASE_CONFORMANCE_IPC_DRIFT',
    'container IPC namespace is not private')
  assertion(
    host.PidMode === 'private' || host.PidMode === '',
    'DATABASE_CONFORMANCE_PID_NAMESPACE_DRIFT',
    'container PID namespace is not private',
  )
  assertion(host.LogConfig?.Type === 'none', 'DATABASE_CONFORMANCE_LOGGING_ENABLED',
    'container logging driver is not none')
  assertion(host.RestartPolicy?.Name === 'no', 'DATABASE_CONFORMANCE_RESTART_ENABLED',
    'container restart policy is not disabled')
  for (const [value, code, message] of [
    [host.Binds, 'DATABASE_CONFORMANCE_BIND_MOUNT', 'container has host bind mounts'],
    [host.Mounts, 'DATABASE_CONFORMANCE_CONFIGURED_MOUNT', 'container has configured mounts'],
    [host.VolumesFrom, 'DATABASE_CONFORMANCE_VOLUMES_FROM', 'container inherits volumes'],
    [host.Devices, 'DATABASE_CONFORMANCE_DEVICE', 'container has host devices'],
    [host.DeviceRequests, 'DATABASE_CONFORMANCE_DEVICE_REQUEST', 'container requests devices'],
    [host.Links, 'DATABASE_CONFORMANCE_LINK', 'container has legacy links'],
    [host.ExtraHosts, 'DATABASE_CONFORMANCE_EXTRA_HOST', 'container has injected hosts'],
    [host.PortBindings, 'DATABASE_CONFORMANCE_PORT_PUBLISHED', 'container publishes ports'],
  ]) {
    assertion(emptyOrAbsent(value), code, message)
  }
  assertion(host.PublishAllPorts === false, 'DATABASE_CONFORMANCE_PORTS_ALL',
    'container publishes image ports')

  const expectedPaths = new Set(definition.runtime.dataPaths)
  const actualTmpfs = Object.keys(host.Tmpfs ?? {})
  assertion(
    actualTmpfs.length === expectedPaths.size
      && actualTmpfs.every((path) => expectedPaths.has(path)),
    'DATABASE_CONFORMANCE_TMPFS_SET_DRIFT',
    'container tmpfs destinations differ from the engine profile',
  )
  for (const path of expectedPaths) {
    const options = tmpfsOptionSet(host.Tmpfs[path])
    for (const required of ['rw', 'noexec', 'nosuid', 'nodev', 'uid=999', 'gid=999']) {
      assertion(
        options.has(required),
        'DATABASE_CONFORMANCE_TMPFS_PROFILE_DRIFT',
        `container tmpfs ${path} is missing ${required}`,
      )
    }
  }
  assertion(
    Array.isArray(inspection.Mounts)
      && inspection.Mounts.every((mount) =>
        mount?.Type === 'tmpfs'
        && expectedPaths.has(mount.Destination)
        && mount.RW !== false),
    'DATABASE_CONFORMANCE_RUNTIME_MOUNT_DRIFT',
    'container runtime mounts include a non-tmpfs or unexpected destination',
  )
  assertion(container.User === definition.runtime.user,
    'DATABASE_CONFORMANCE_USER_DRIFT', 'container user differs from the engine profile')
  assertion(container.Healthcheck?.Test?.[0] === 'NONE',
    'DATABASE_CONFORMANCE_HEALTHCHECK_ENABLED', 'container healthcheck is not disabled')
  const environment = parseEnvironment(container.Env)
  for (const key of PROXY_KEYS) {
    assertion(environment.get(key) === '', 'DATABASE_CONFORMANCE_PROXY_INHERITED',
      `container proxy environment ${key} is not empty`)
  }
  return inspection.Id
}

function canonicalEvidence(value) {
  const normalized = String(value).replaceAll(/\r\n/g, '\n').trim()
  return {
    observation: normalized.slice(0, 2048) || 'No command output; exit status was the evidence.',
    evidence_sha256: sha256(Buffer.from(normalized, 'utf8')),
  }
}

export function conformanceCheck(checkId, state, evidence) {
  return {
    check_id: checkId,
    state,
    ...canonicalEvidence(evidence),
  }
}

export function scenarioResult(binding, checks) {
  const states = checks.map(({ state }) => state)
  return {
    scenario_id: binding.scenario_id,
    state: states.includes('FAILED')
      ? 'FAILED'
      : states.includes('NOT_ASSESSED')
        ? 'NOT_ASSESSED'
        : 'PASSED',
    adapter_rule_ids: [...binding.adapter_rule_ids],
    checks,
  }
}

function resultState(scenarios, gaps, containerAbsent) {
  if (!containerAbsent || scenarios.some(({ state }) => state === 'FAILED')) return 'FAILED'
  if (gaps.length > 0 || scenarios.some(({ state }) => state === 'NOT_ASSESSED')) {
    return 'COMPLETE_WITH_GAPS'
  }
  return 'PASSED'
}

function timestamp(now) {
  const value = now()
  const date = value instanceof Date ? value : new Date(value)
  if (!Number.isFinite(date.getTime())) {
    throw runnerError(
      'DATABASE_CONFORMANCE_CLOCK_INVALID',
      'database conformance clock returned an invalid time',
    )
  }
  return date.toISOString()
}

function randomSecret(randomBytesImpl) {
  const bytes = randomBytesImpl(24)
  if (!Buffer.isBuffer(bytes) || bytes.length !== 24) {
    throw runnerError(
      'DATABASE_CONFORMANCE_RANDOM_INVALID',
      'database secret source must return exactly 24 bytes',
    )
  }
  return bytes.toString('base64url')
}

async function inspectExactContainer(command, containerName) {
  const result = await command([
    '--context',
    'default',
    'container',
    'inspect',
    '--format',
    '{{json .}}',
    containerName,
  ], { allowNonZero: true })
  if (result.code === 0) {
    return { state: 'PRESENT', inspection: parseDockerJson(
      result.stdout,
      'Docker container inspection',
    ) }
  }
  const listing = await command([
    '--context',
    'default',
    'container',
    'ls',
    '--all',
    '--no-trunc',
    '--filter',
    `name=^/${containerName}$`,
    '--format',
    '{{.ID}}',
  ])
  if (!listing.stdout.trim()) return { state: 'ABSENT' }
  throw runnerError(
    'DATABASE_CONFORMANCE_CONTAINER_INSPECTION_AMBIGUOUS',
    'exact container exists but Docker inspection did not return its identity',
    { stderr: result.stderr },
  )
}

async function removeExactContainer({
  command,
  containerName,
  engine,
  config,
  runId,
  imageId,
}) {
  const before = await inspectExactContainer(command, containerName)
  if (before.state === 'ABSENT') return true
  assertHardenedDatabaseContainerInspection({
    inspection: before.inspection,
    engine,
    config,
    runId,
    containerName,
    imageId,
  })
  await command([
    '--context',
    'default',
    'container',
    'kill',
    '--signal=KILL',
    containerName,
  ], { allowNonZero: true })
  await command([
    '--context',
    'default',
    'container',
    'rm',
    '--force',
    '--volumes',
    containerName,
  ])
  const after = await inspectExactContainer(command, containerName)
  return after.state === 'ABSENT'
}

export async function runDatabaseConformanceEngine({
  runId,
  engineId,
  config,
  executeScenarios,
  spawnImpl = nodeSpawn,
  commandImpl,
  now = () => new Date(),
  randomBytesImpl = randomBytes,
  monotonicNow = () => Date.now(),
}) {
  assertValidDatabaseConformanceConfig(config)
  const engine = engineDefinition(engineId)
  const containerName = databaseConformanceContainerName(runId, engineId)
  const secret = randomSecret(randomBytesImpl)
  const startedAt = timestamp(now)
  const deadline = monotonicNow() + config.limits.wall_time_ms
  const rawCommand = commandImpl ?? (async (args, overrides = {}) =>
    runDatabaseDockerCommand({
      runtimePath: config.runtime_path,
      args,
      spawnImpl,
      timeoutMs: config.limits.docker_command_timeout_ms,
      maxOutputBytes: config.limits.max_output_bytes,
      ...overrides,
    }))
  const command = async (args, overrides = {}) => {
    const remaining = Math.floor(deadline - monotonicNow())
    assertion(
      remaining > 0,
      'DATABASE_CONFORMANCE_WALL_TIME_EXCEEDED',
      `database conformance engine exceeded its ${config.limits.wall_time_ms}ms wall-time limit`,
    )
    return rawCommand(args, {
      ...overrides,
      timeoutMs: Math.min(
        overrides.timeoutMs ?? config.limits.docker_command_timeout_ms,
        remaining,
      ),
    })
  }

  let imageIdentity
  let containerId
  let runtimeVersion
  let serverVersion
  let scenarioExecution
  let cleanupAbsent = false
  let primaryError

  try {
    const context = await command([
      '--context',
      'default',
      'context',
      'inspect',
      'default',
      '--format',
      '{{json .Endpoints.docker.Host}}',
    ])
    assertLocalDatabaseDockerContextHost(
      parseDockerJson(context.stdout, 'Docker context inspection'),
    )
    const version = await command([
      '--context',
      'default',
      'version',
      '--format',
      '{{json .Server.Version}}',
    ])
    runtimeVersion = parseDockerJson(version.stdout, 'Docker server version inspection')
    assertion(
      typeof runtimeVersion === 'string' && runtimeVersion.length > 0,
      'DATABASE_CONFORMANCE_DOCKER_VERSION_INVALID',
      'Docker server version inspection returned no version',
    )
    const image = await command([
      '--context',
      'default',
      'image',
      'inspect',
      '--format',
      '{{json .}}',
      engine.image,
    ])
    imageIdentity = assertSafeDatabaseImageInspection(
      parseDockerJson(image.stdout, 'Docker image inspection'),
      engine,
    )
    let before = await inspectExactContainer(command, containerName)
    if (before.state === 'PRESENT') {
      const recovered = await removeExactContainer({
        command,
        containerName,
        engine,
        config,
        runId,
        imageId: imageIdentity.imageId,
      })
      assertion(
        recovered,
        'DATABASE_CONFORMANCE_RECOVERY_UNVERIFIED',
        'the controller could not remove its exact stale conformance container',
      )
      before = await inspectExactContainer(command, containerName)
    }
    assertion(
      before.state === 'ABSENT',
      'DATABASE_CONFORMANCE_CONTAINER_NAME_OCCUPIED',
      'planned database conformance container name already exists',
    )
    const created = await command(buildDatabaseDockerCreateArgs({
      engine,
      config,
      runId,
      containerName,
      secret,
    }))
    containerId = created.stdout.trim()
    assertion(
      SHA256_PATTERN.test(containerId),
      'DATABASE_CONFORMANCE_CREATE_ID_INVALID',
      'Docker create did not return a full immutable container ID',
    )
    const inspected = await inspectExactContainer(command, containerName)
    assertion(
      inspected.state === 'PRESENT',
      'DATABASE_CONFORMANCE_CONTAINER_MISSING_AFTER_CREATE',
      'container disappeared after Docker create',
    )
    const inspectedId = assertHardenedDatabaseContainerInspection({
      inspection: inspected.inspection,
      engine,
      config,
      runId,
      containerName,
      imageId: imageIdentity.imageId,
    })
    assertion(
      inspectedId === containerId,
      'DATABASE_CONFORMANCE_CONTAINER_ID_MISMATCH',
      'container identity changed between create and inspect',
    )
    await command([
      '--context',
      'default',
      'container',
      'start',
      containerName,
    ])
    scenarioExecution = await executeScenarios({
      engine,
      config,
      containerName,
      secret,
      command,
    })
    serverVersion = scenarioExecution.serverVersion
    assertion(
      new RegExp(engine.expected_server_version_pattern).test(serverVersion),
      'DATABASE_CONFORMANCE_SERVER_VERSION_DRIFT',
      `observed ${engine.product} version does not match the manifest gate`,
    )
  } catch (error) {
    primaryError = error instanceof DatabaseConformanceRunnerError
      ? error
      : runnerError(
        'DATABASE_CONFORMANCE_EXECUTION_FAILED',
        'database conformance engine execution failed',
        { cause: error },
      )
  } finally {
    if (imageIdentity) {
      try {
        cleanupAbsent = await removeExactContainer({
          command: rawCommand,
          containerName,
          engine,
          config,
          runId,
          imageId: imageIdentity.imageId,
        })
      } catch (cleanupError) {
        if (!primaryError) {
          primaryError = cleanupError instanceof DatabaseConformanceRunnerError
            ? cleanupError
            : runnerError(
              'DATABASE_CONFORMANCE_CLEANUP_FAILED',
              'database conformance cleanup failed',
              { cause: cleanupError },
            )
        } else {
          primaryError.details = [
            ...(primaryError.details ?? []),
            {
              code: cleanupError.code ?? 'DATABASE_CONFORMANCE_CLEANUP_FAILED',
              message: cleanupError.message,
            },
          ]
        }
      }
    }
  }

  if (primaryError) throw primaryError
  assertion(
    monotonicNow() <= deadline,
    'DATABASE_CONFORMANCE_WALL_TIME_EXCEEDED',
    `database conformance engine exceeded its ${config.limits.wall_time_ms}ms wall-time limit`,
  )
  assertion(
    cleanupAbsent,
    'DATABASE_CONFORMANCE_CLEANUP_UNVERIFIED',
    'Docker did not prove the exact conformance container absent',
  )
  const completedAt = timestamp(now)
  const transcriptSha256 = scenarioExecution.transcript_sha256
    ?? sha256(Buffer.from(JSON.stringify(scenarioExecution.scenarios), 'utf8'))
  const gaps = scenarioExecution.gaps ?? []
  const result = {
    schema_version: '1.0.0',
    protocol: 'docker-database-lab-v1',
    assurance_scope: 'CONTROLLER_OBSERVED_DISPOSABLE_ENGINE_BEHAVIOR',
    target_deployment_proven: false,
    run_id: runId,
    engine_id: engine.engine_id,
    adapter_id: engine.adapter_id,
    state: resultState(scenarioExecution.scenarios, gaps, cleanupAbsent),
    started_at: startedAt,
    completed_at: completedAt,
    backend: {
      type: 'OCI_DOCKER',
      context: 'default',
      runtime_version: runtimeVersion,
      requested_image: engine.image,
      image_id: imageIdentity.imageId,
      repo_digests: imageIdentity.repoDigests,
      platform: imageIdentity.platform,
      container_name: containerName,
      container_id: containerId,
      security_profile: 'database-lab-v1',
    },
    server: {
      product: engine.product,
      version: serverVersion,
    },
    scenarios: scenarioExecution.scenarios,
    transcript: scenarioExecution.transcript,
    transcript_sha256: transcriptSha256,
    cleanup: {
      attempted: true,
      container_absent: cleanupAbsent,
      verified_at: completedAt,
    },
    gaps,
  }
  return assertValidDatabaseConformanceResult(result)
}
