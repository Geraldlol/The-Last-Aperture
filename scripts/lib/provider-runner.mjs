import { spawn as nodeSpawn } from 'node:child_process'
import {
  createHash,
  createHmac,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto'
import { TextDecoder } from 'node:util'
import {
  assertValidProviderConfig,
  assertValidProviderExecution,
} from './provider-contracts.mjs'

export const PROVIDER_PROTOCOL = 'docker-stdio-v1'
export const CONSUMPTION_HMAC_DOMAIN = 'red-team-audit/provider-delivery/v1'

const OPAQUE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{15,127}$/
// Container names are interpolated into Docker's `name` regex filter, so the
// charset must stay free of regex metacharacters.
const CONTAINER_NAME_PATTERN = /^[a-z0-9][a-z0-9_-]{7,127}$/
const SHA256_PATTERN = /^[a-f0-9]{64}$/
const COMMON_PACKET_FIELDS = new Set([
  'schema_version',
  'run_id',
  'job_id',
  'kind',
  'lens',
  'phase',
  'capability_mode',
  'packet_sha256',
  'snapshot_id',
  'operation',
  'activated',
  'activation',
  'lens_digest',
  'scoped_files',
  'shard',
  'matches',
  'owned_topics',
  'known_topics',
  'topic_obligations',
  'store_profiles',
  'evidence',
  'database_discovery',
  'database_store_ids',
  'profile_authority_store_ids',
  'database_conformance',
  'findings',
  'coverage',
  'completeness_inputs',
  'candidate_ids',
])
// Docker's default mask lists grow between daemon versions, so these assert the
// subset whose absence is directly escape-relevant rather than exact equality.
const MASKED_KERNEL_PATHS = [
  '/proc/acpi',
  '/proc/kcore',
  '/proc/keys',
  '/proc/scsi',
  '/sys/firmware',
]
const READONLY_KERNEL_PATHS = [
  '/proc/bus',
  '/proc/fs',
  '/proc/irq',
  '/proc/sys',
  '/proc/sysrq-trigger',
]

export class ProviderRunnerError extends Error {
  constructor(code, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'ProviderRunnerError'
    this.code = code
    if (options.partialReceipt) this.partial_receipt = options.partialReceipt
    if (options.stderr) this.stderr = options.stderr
    if (options.details) this.details = options.details
  }
}

function runnerError(code, message, options = {}) {
  return new ProviderRunnerError(code, message, options)
}

function jsonClone(value, label) {
  try {
    return JSON.parse(JSON.stringify(value))
  } catch (error) {
    throw runnerError(
      'PROVIDER_NON_JSON_VALUE',
      `${label} must contain only finite JSON values`,
      { cause: error },
    )
  }
}

function own(object, key) {
  return object !== null
    && typeof object === 'object'
    && Object.prototype.hasOwnProperty.call(object, key)
}

function requireString(value, label, pattern) {
  if (typeof value !== 'string' || value.length === 0 || (pattern && !pattern.test(value))) {
    throw runnerError('PROVIDER_PROTOCOL_VIOLATION', `${label} is invalid`)
  }
  return value
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function timestamp(now) {
  const value = now()
  const date = value instanceof Date ? value : new Date(value)
  if (!Number.isFinite(date.getTime())) {
    throw runnerError('PROVIDER_CLOCK_INVALID', 'provider runner clock returned an invalid time')
  }
  return date.toISOString()
}

function generatedOpaqueId(randomBytesImpl, byteLength, label) {
  const bytes = randomBytesImpl(byteLength)
  if (!Buffer.isBuffer(bytes) || bytes.length !== byteLength) {
    throw runnerError(
      'PROVIDER_RANDOM_SOURCE_INVALID',
      `${label} random source must return exactly ${byteLength} bytes`,
    )
  }
  const value = `o${bytes.toString('base64url')}`
  if (!OPAQUE_ID_PATTERN.test(value)) {
    throw runnerError('PROVIDER_RANDOM_SOURCE_INVALID', `${label} generated an invalid opaque ID`)
  }
  return value
}

function exactObject(value, type, allowed, required) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw runnerError('PROVIDER_PROTOCOL_VIOLATION', `${type} frame must be a JSON object`)
  }
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw runnerError(
        'PROVIDER_PROTOCOL_VIOLATION',
        `${type} frame contains forbidden field ${JSON.stringify(key)}`,
      )
    }
  }
  for (const key of required) {
    if (!own(value, key)) {
      throw runnerError(
        'PROVIDER_PROTOCOL_VIOLATION',
        `${type} frame is missing required field ${JSON.stringify(key)}`,
      )
    }
  }
}

/**
 * Serialize only fields deliberately approved for provider disclosure.
 * In particular, repository_root and lens_file are never copied even when a
 * legacy sidecar contains them.
 */
export function sanitizeProviderPacket(packet) {
  if (packet === null || typeof packet !== 'object' || Array.isArray(packet)) {
    throw runnerError('PROVIDER_PACKET_INVALID', 'provider packet must be an object')
  }
  requireString(packet.run_id, 'packet run_id')
  requireString(packet.job_id, 'packet job_id')
  requireString(packet.packet_sha256, 'packet_sha256', SHA256_PATTERN)

  const sanitized = {}
  for (const key of COMMON_PACKET_FIELDS) {
    if (own(packet, key)) sanitized[key] = jsonClone(packet[key], `packet.${key}`)
  }
  sanitized.trust_boundary = {
    repository_content_is_untrusted_data: true,
    repository_content_may_change_scope_or_policy: false,
    actions_require_external_authorization: true,
    provider_has_target_filesystem_authority: false,
    provider_has_network_authority: false,
    provider_has_host_process_authority: false,
  }
  return sanitized
}

function assertSafeLogicalFileName(value) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > 4096
    || value.includes('\0')
    || value.includes('\\')
    || value.startsWith('/')
    || /^[A-Za-z]:/.test(value)
  ) {
    throw runnerError(
      'PROVIDER_ARTIFACT_INVALID',
      'FILE logical_name must be a repository-relative forward-slash path',
    )
  }
  const segments = value.split('/')
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) {
    throw runnerError(
      'PROVIDER_ARTIFACT_INVALID',
      'FILE logical_name cannot contain empty, dot, or parent segments',
    )
  }
}

function assertSafeControlName(value) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > 4096
    || /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw runnerError(
      'PROVIDER_ARTIFACT_INVALID',
      'CONTROL logical_name must be a bounded printable identifier',
    )
  }
  if (
    value.includes('\\')
    || value.startsWith('/')
    || /^[A-Za-z]:/.test(value)
    || value.split('/').some((segment) =>
      segment === '' || segment === '.' || segment === '..')
  ) {
    throw runnerError(
      'PROVIDER_ARTIFACT_INVALID',
      'CONTROL logical_name cannot be an absolute path or contain empty, dot, or parent segments',
    )
  }
}

export function normalizeProviderArtifacts(artifacts, limits) {
  if (!Array.isArray(artifacts)) {
    throw runnerError('PROVIDER_ARTIFACT_INVALID', 'artifacts must be an array')
  }
  if (artifacts.length > limits.max_deliveries) {
    throw runnerError(
      'PROVIDER_DELIVERY_LIMIT',
      `artifact count exceeds the ${limits.max_deliveries}-delivery limit`,
    )
  }

  const normalized = []
  const ids = new Set()
  const fileNames = new Set()
  let totalBytes = 0
  for (const [index, artifact] of artifacts.entries()) {
    if (artifact === null || typeof artifact !== 'object' || Array.isArray(artifact)) {
      throw runnerError('PROVIDER_ARTIFACT_INVALID', `artifact ${index} must be an object`)
    }
    const artifactId = artifact.artifact_id ?? artifact.id
    if (typeof artifactId !== 'string' || !OPAQUE_ID_PATTERN.test(artifactId)) {
      throw runnerError(
        'PROVIDER_ARTIFACT_INVALID',
        `artifact ${index} must have an opaque artifact_id`,
      )
    }
    if (ids.has(artifactId)) {
      throw runnerError('PROVIDER_ARTIFACT_INVALID', `duplicate artifact_id ${artifactId}`)
    }
    ids.add(artifactId)

    const kind = String(artifact.kind ?? '').toUpperCase()
    if (kind !== 'FILE' && kind !== 'CONTROL') {
      throw runnerError(
        'PROVIDER_ARTIFACT_INVALID',
        `artifact ${artifactId} kind must be FILE or CONTROL`,
      )
    }
    const logicalName = artifact.logical_name
    if (kind === 'FILE') {
      assertSafeLogicalFileName(logicalName)
      if (fileNames.has(logicalName)) {
        throw runnerError(
          'PROVIDER_ARTIFACT_INVALID',
          `duplicate FILE logical_name ${logicalName}`,
        )
      }
      fileNames.add(logicalName)
    } else {
      assertSafeControlName(logicalName)
    }

    if (!Buffer.isBuffer(artifact.bytes)) {
      throw runnerError(
        'PROVIDER_ARTIFACT_INVALID',
        `artifact ${artifactId} bytes must be a Buffer`,
      )
    }
    if (artifact.bytes.length > limits.max_file_bytes) {
      throw runnerError(
        'PROVIDER_DELIVERY_LIMIT',
        `artifact ${artifactId} exceeds the ${limits.max_file_bytes}-byte limit`,
      )
    }
    totalBytes += artifact.bytes.length
    if (totalBytes > limits.max_total_delivery_bytes) {
      throw runnerError(
        'PROVIDER_DELIVERY_LIMIT',
        `artifacts exceed the ${limits.max_total_delivery_bytes}-byte total limit`,
      )
    }

    const digest = sha256(artifact.bytes)
    if (
      artifact.sha256 !== undefined
      && (
        typeof artifact.sha256 !== 'string'
        || artifact.sha256.toLowerCase() !== digest
      )
    ) {
      throw runnerError(
        'PROVIDER_ARTIFACT_DIGEST_MISMATCH',
        `artifact ${artifactId} bytes do not match its declared sha256`,
      )
    }
    normalized.push({
      artifact_id: artifactId,
      kind,
      logical_name: logicalName,
      bytes: Buffer.from(artifact.bytes),
      size: artifact.bytes.length,
      sha256: digest,
    })
  }
  return normalized
}

export function computeConsumptionHmac({
  challenge,
  jobId,
  artifactId,
  size,
  bytes,
}) {
  if (!Buffer.isBuffer(challenge) || challenge.length !== 32) {
    throw runnerError('PROVIDER_CHALLENGE_INVALID', 'challenge must contain exactly 32 bytes')
  }
  if (!Buffer.isBuffer(bytes) || bytes.length !== size) {
    throw runnerError(
      'PROVIDER_CHALLENGE_INVALID',
      'HMAC bytes must match the declared artifact size',
    )
  }
  return createHmac('sha256', challenge)
    .update(CONSUMPTION_HMAC_DOMAIN, 'utf8')
    .update('\0', 'utf8')
    .update(jobId, 'utf8')
    .update('\0', 'utf8')
    .update(artifactId, 'utf8')
    .update('\0', 'utf8')
    .update(String(size), 'utf8')
    .update('\0', 'utf8')
    .update(bytes)
    .digest('hex')
}

function assertContainerName(containerName) {
  if (!CONTAINER_NAME_PATTERN.test(containerName)) {
    throw runnerError('PROVIDER_CONTAINER_NAME_INVALID', 'invalid generated container name')
  }
}

function dockerPrefix() {
  return ['--context', 'default']
}

function normalizeDockerExecutionIdentity(value = {}) {
  const identity = {
    user: value.user ?? '65532:65532',
    workdir: value.workdir ?? '/work',
    workTmpfsMode: value.workTmpfsMode ?? '0700',
  }
  if (Object.keys(value).some((key) => !['user', 'workdir', 'workTmpfsMode'].includes(key))) {
    throw runnerError(
      'PROVIDER_CONTAINER_IDENTITY_INVALID',
      'container execution identity contains an unknown field',
    )
  }
  const userMatch = /^(\d+):(\d+)$/.exec(identity.user)
  if (
    !userMatch
    || Number(userMatch[1]) === 0
    || Number(userMatch[2]) === 0
  ) {
    throw runnerError(
      'PROVIDER_CONTAINER_IDENTITY_INVALID',
      'container execution identity must be an exact non-root numeric UID and GID',
    )
  }
  if (!['/', '/work'].includes(identity.workdir)) {
    throw runnerError(
      'PROVIDER_CONTAINER_IDENTITY_INVALID',
      'container execution workdir must be controller-owned',
    )
  }
  if (!/^0[0-7]{3}$/.test(identity.workTmpfsMode)) {
    throw runnerError(
      'PROVIDER_CONTAINER_IDENTITY_INVALID',
      'container tmpfs mode must be an exact octal mode',
    )
  }
  const mode = Number.parseInt(identity.workTmpfsMode, 8)
  if ((mode & 0o066) !== 0) {
    throw runnerError(
      'PROVIDER_CONTAINER_IDENTITY_INVALID',
      'container tmpfs may not grant group or other read/write access',
    )
  }
  return identity
}

export function buildDockerCreateArgs(config, containerName, executionIdentity = {}) {
  assertValidProviderConfig(config)
  assertContainerName(containerName)
  const limits = config.limits
  const identity = normalizeDockerExecutionIdentity(executionIdentity)
  return [
    ...dockerPrefix(),
    'create',
    `--name=${containerName}`,
    '--pull=never',
    '--network=none',
    '--read-only',
    '--cap-drop=ALL',
    '--security-opt=no-new-privileges=true',
    '--security-opt=seccomp=builtin',
    `--user=${identity.user}`,
    `--pids-limit=${limits.pids}`,
    `--memory=${limits.memory_bytes}`,
    `--memory-swap=${limits.memory_bytes}`,
    `--cpus=${String(limits.cpus)}`,
    `--ulimit=nofile=${limits.nofile}:${limits.nofile}`,
    `--tmpfs=/work:rw,noexec,nosuid,nodev,size=${limits.tmpfs_bytes},mode=${identity.workTmpfsMode},uid=65532,gid=65532`,
    `--workdir=${identity.workdir}`,
    '--ipc=none',
    '--log-driver=none',
    '--no-healthcheck',
    '--interactive',
    '--attach=stdout',
    '--attach=stderr',
    '--env=HOME=/work',
    '--env=TMPDIR=/work',
    '--env=NO_COLOR=1',
    '--env=HTTP_PROXY=',
    '--env=HTTPS_PROXY=',
    '--env=NO_PROXY=',
    '--env=ALL_PROXY=',
    '--env=http_proxy=',
    '--env=https_proxy=',
    '--env=no_proxy=',
    '--env=all_proxy=',
    config.image,
  ]
}

export function buildDockerStartArgs(containerName) {
  assertContainerName(containerName)
  return [
    ...dockerPrefix(),
    'start',
    '--attach',
    '--interactive',
    containerName,
  ]
}

export function buildDockerCleanupArgs(containerName) {
  assertContainerName(containerName)
  return {
    kill: [
      ...dockerPrefix(),
      'container',
      'kill',
      '--signal=KILL',
      containerName,
    ],
    remove: [
      ...dockerPrefix(),
      'container',
      'rm',
      '--force',
      '--volumes',
      containerName,
    ],
  }
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

function inspectAssertion(condition, message) {
  if (!condition) {
    throw runnerError('PROVIDER_DOCKER_PROFILE_MISMATCH', message)
  }
}

export function assertLocalDockerContextHost(value) {
  inspectAssertion(
    typeof value === 'string' && /^(?:unix|npipe):\/\//.test(value),
    'Docker default context must use a local unix:// or npipe:// endpoint',
  )
  return value
}

export function assertSafeDockerImageInspection(inspection) {
  inspectAssertion(
    inspection !== null && typeof inspection === 'object' && !Array.isArray(inspection),
    'Docker image inspection must be an object',
  )
  inspectAssertion(
    emptyOrAbsent(inspection.Config?.Volumes),
    'provider image declares persistent volumes',
  )
  return inspection
}

function tmpfsOptions(value) {
  return new Set(String(value ?? '').split(',').filter(Boolean))
}

export function assertHardenedDockerInspection(
  inspection,
  config,
  containerName,
  executionIdentity = {},
) {
  assertValidProviderConfig(config)
  assertContainerName(containerName)
  const identity = normalizeDockerExecutionIdentity(executionIdentity)
  inspectAssertion(
    inspection !== null && typeof inspection === 'object' && !Array.isArray(inspection),
    'Docker container inspection must be an object',
  )
  inspectAssertion(SHA256_PATTERN.test(inspection.Id ?? ''), 'container ID is not immutable')
  inspectAssertion(
    inspection.Name === `/${containerName}` || inspection.Name === containerName,
    'container inspection returned the wrong named container',
  )

  const host = inspection.HostConfig ?? {}
  const container = inspection.Config ?? {}
  inspectAssertion(host.NetworkMode === 'none', 'container network mode is not none')
  inspectAssertion(host.ReadonlyRootfs === true, 'container root filesystem is not read-only')
  inspectAssertion(host.Privileged === false, 'container is privileged')
  inspectAssertion(emptyOrAbsent(host.CapAdd), 'container has added Linux capabilities')
  inspectAssertion(
    Array.isArray(host.CapDrop) && host.CapDrop.includes('ALL'),
    'container does not drop all Linux capabilities',
  )
  inspectAssertion(
    Array.isArray(host.SecurityOpt)
      && host.SecurityOpt.includes('no-new-privileges=true')
      && host.SecurityOpt.includes('seccomp=builtin'),
    'container security options do not enforce no-new-privileges and builtin seccomp',
  )
  inspectAssertion(host.PidsLimit === config.limits.pids, 'container PID limit drifted')
  inspectAssertion(host.Memory === config.limits.memory_bytes, 'container memory limit drifted')
  inspectAssertion(
    host.MemorySwap === config.limits.memory_bytes,
    'container memory-swap limit drifted',
  )
  inspectAssertion(
    host.NanoCpus === Math.round(config.limits.cpus * 1_000_000_000),
    'container CPU limit drifted',
  )
  const nofile = Array.isArray(host.Ulimits)
    ? host.Ulimits.find(({ Name }) => Name === 'nofile')
    : undefined
  inspectAssertion(
    nofile?.Soft === config.limits.nofile && nofile?.Hard === config.limits.nofile,
    'container nofile limit drifted',
  )
  inspectAssertion(host.IpcMode === 'none', 'container IPC namespace is not isolated')
  inspectAssertion(
    host.PidMode === 'private' || host.PidMode === '',
    'container PID namespace is not private',
  )
  inspectAssertion(
    host.UsernsMode !== 'host',
    'container opts out of the daemon user-namespace configuration',
  )
  inspectAssertion(
    host.CgroupnsMode !== 'host',
    'container shares the host cgroup namespace',
  )
  inspectAssertion(emptyOrAbsent(host.Sysctls), 'container sets kernel sysctls')
  inspectAssertion(
    emptyOrAbsent(host.GroupAdd),
    'container has added supplementary groups',
  )
  inspectAssertion(
    host.AppArmorProfile !== 'unconfined',
    'container runs with an unconfined AppArmor profile',
  )
  inspectAssertion(
    host.Runtime === undefined
      || host.Runtime === null
      || host.Runtime === ''
      || host.Runtime === 'runc',
    'container does not use the stock runc runtime',
  )
  inspectAssertion(
    host.Isolation === undefined
      || host.Isolation === null
      || host.Isolation === ''
      || host.Isolation === 'default',
    'container uses a platform isolation mode outside the hardened profile',
  )
  if (
    inspection.Platform === 'linux'
    || Array.isArray(host.MaskedPaths)
    || Array.isArray(host.ReadonlyPaths)
  ) {
    const masked = new Set(Array.isArray(host.MaskedPaths) ? host.MaskedPaths : [])
    inspectAssertion(
      MASKED_KERNEL_PATHS.every((path) => masked.has(path)),
      'container does not mask the escape-relevant /proc and /sys kernel surface',
    )
    const readOnly = new Set(
      Array.isArray(host.ReadonlyPaths) ? host.ReadonlyPaths : [],
    )
    inspectAssertion(
      READONLY_KERNEL_PATHS.every((path) => readOnly.has(path)),
      'container does not keep the default /proc kernel paths read-only',
    )
  }
  inspectAssertion(host.LogConfig?.Type === 'none', 'container logging driver is not none')
  inspectAssertion(
    host.RestartPolicy?.Name === 'no',
    'container restart policy is not disabled',
  )
  inspectAssertion(emptyOrAbsent(host.Binds), 'container has host bind mounts')
  inspectAssertion(emptyOrAbsent(host.Mounts), 'container has configured host mounts')
  inspectAssertion(emptyOrAbsent(host.VolumesFrom), 'container inherits another volume namespace')
  inspectAssertion(emptyOrAbsent(host.Devices), 'container has additional host devices')
  inspectAssertion(emptyOrAbsent(host.DeviceRequests), 'container has host device requests')
  inspectAssertion(emptyOrAbsent(host.Links), 'container has legacy network links')
  inspectAssertion(emptyOrAbsent(host.ExtraHosts), 'container has injected host mappings')
  inspectAssertion(emptyOrAbsent(host.PortBindings), 'container has published ports')
  inspectAssertion(host.PublishAllPorts === false, 'container publishes image ports')
  inspectAssertion(Array.isArray(inspection.Mounts), 'container mounts are not inspectable')
  inspectAssertion(
    inspection.Mounts.every((mount) => (
      mount?.Type === 'tmpfs'
      && mount?.Destination === '/work'
      && (mount?.Source === '' || mount?.Source === undefined)
      && mount?.RW !== false
    )),
    'container inspection reports a mount other than the fixed /work tmpfs',
  )
  inspectAssertion(
    inspection.Mounts.length <= 1,
    'container inspection reports duplicate /work tmpfs mounts',
  )

  const requiredTmpfs = new Set([
    'rw',
    'noexec',
    'nosuid',
    'nodev',
    `size=${config.limits.tmpfs_bytes}`,
    `mode=${identity.workTmpfsMode}`,
    'uid=65532',
    'gid=65532',
  ])
  const actualTmpfs = tmpfsOptions(host.Tmpfs?.['/work'])
  inspectAssertion(
    [...requiredTmpfs].every((option) => actualTmpfs.has(option)),
    'container /work tmpfs does not match the hardened profile',
  )
  for (const [prefix, expected] of [
    ['mode=', `mode=${identity.workTmpfsMode}`],
    ['uid=', 'uid=65532'],
    ['gid=', 'gid=65532'],
  ]) {
    const values = [...actualTmpfs].filter((option) => option.startsWith(prefix))
    inspectAssertion(
      values.length === 1 && values[0] === expected,
      `container /work tmpfs has an ambiguous ${prefix.slice(0, -1)} setting`,
    )
  }

  inspectAssertion(container.User === identity.user, 'container user is not the fixed non-root identity')
  inspectAssertion(container.WorkingDir === identity.workdir, 'container workdir drifted')
  inspectAssertion(container.OpenStdin === true, 'container stdin is not attached')
  inspectAssertion(container.Tty === false, 'container unexpectedly allocates a TTY')
  inspectAssertion(container.AttachStdout === true, 'container stdout is not attached')
  inspectAssertion(container.AttachStderr === true, 'container stderr is not attached')
  inspectAssertion(emptyOrAbsent(container.Volumes), 'container declares persistent volumes')
  inspectAssertion(
    container.Healthcheck?.Test?.[0] === 'NONE',
    'container healthcheck execution is not disabled',
  )
  const environment = new Map(
    (container.Env ?? []).map((entry) => {
      const separator = entry.indexOf('=')
      return separator < 0
        ? [entry, undefined]
        : [entry.slice(0, separator), entry.slice(separator + 1)]
    }),
  )
  for (const key of [
    'HTTP_PROXY',
    'HTTPS_PROXY',
    'NO_PROXY',
    'ALL_PROXY',
    'http_proxy',
    'https_proxy',
    'no_proxy',
    'all_proxy',
  ]) {
    inspectAssertion(
      environment.get(key) === '',
      `container proxy environment ${key} is not empty`,
    )
  }
  return inspection.Id
}

function transcriptUpdate(hash, direction, line) {
  hash.update(direction, 'ascii')
  hash.update('\0', 'ascii')
  hash.update(String(line.length), 'ascii')
  hash.update('\0', 'ascii')
  hash.update(line)
  hash.update('\n', 'ascii')
}

function transcriptDigest(hash) {
  return hash.copy().digest('hex')
}

function partialReceipt({
  packet,
  sessionId,
  startedAt,
  now,
  backend,
  deliveries,
  transcript,
}) {
  return {
    schema_version: '1.0.0',
    observer: 'red-team-audit-controller',
    receipt_scope: 'BYTE_DELIVERY_AND_CHALLENGE_CONSUMPTION_ONLY',
    semantic_analysis_proven: false,
    run_id: packet.run_id,
    job_id: packet.job_id,
    packet_sha256: packet.packet_sha256.toLowerCase(),
    session_id: sessionId,
    started_at: startedAt,
    completed_at: timestamp(now),
    backend: jsonClone(backend, 'backend receipt'),
    deliveries: jsonClone(deliveries, 'partial deliveries'),
    transcript_sha256: transcriptDigest(transcript),
  }
}

async function writeJsonLine(writable, value, maxFrameBytes, transcript) {
  let line
  try {
    line = Buffer.from(JSON.stringify(value), 'utf8')
  } catch (error) {
    throw runnerError(
      'PROVIDER_FRAME_ENCODING_FAILED',
      'controller could not encode a provider protocol frame',
      { cause: error },
    )
  }
  if (line.length > maxFrameBytes) {
    throw runnerError(
      'PROVIDER_FRAME_LIMIT',
      `controller frame exceeds the ${maxFrameBytes}-byte frame limit`,
    )
  }
  const framed = Buffer.concat([line, Buffer.from('\n')])
  await new Promise((resolve, reject) => {
    const onError = (error) => {
      writable.off('error', onError)
      reject(error)
    }
    writable.once('error', onError)
    writable.write(framed, (error) => {
      writable.off('error', onError)
      if (error) reject(error)
      else resolve()
    })
  })
  transcriptUpdate(transcript, 'controller', line)
}

function endWritable(writable) {
  if (!writable.destroyed && !writable.writableEnded) writable.end()
}

function parseJsonLine(line, decoder) {
  let text
  try {
    text = decoder.decode(line)
  } catch (error) {
    throw runnerError(
      'PROVIDER_PROTOCOL_VIOLATION',
      'provider stdout contains invalid UTF-8',
      { cause: error },
    )
  }
  let value
  try {
    value = JSON.parse(text)
  } catch (error) {
    throw runnerError(
      'PROVIDER_PROTOCOL_VIOLATION',
      'provider stdout contains invalid JSONL',
      { cause: error },
    )
  }
  return value
}

function compareHexDigest(expected, actual) {
  if (!SHA256_PATTERN.test(actual)) return false
  const expectedBytes = Buffer.from(expected, 'hex')
  const actualBytes = Buffer.from(actual, 'hex')
  return timingSafeEqual(expectedBytes, actualBytes)
}

/**
 * Run the capability broker over provider stdout/stdin. Provider output is
 * protocol-only JSONL; repository and control bytes travel only in response to
 * one authorized opaque ID request at a time.
 */
export async function runProviderBroker(options) {
  const {
    readable,
    writable,
    packet: rawPacket,
    artifacts: rawArtifacts,
    config,
    backend,
    signal,
    now = () => new Date(),
    randomBytesImpl = randomBytes,
  } = options
  assertValidProviderConfig(config)
  if (!readable || typeof readable[Symbol.asyncIterator] !== 'function') {
    throw runnerError('PROVIDER_STREAM_INVALID', 'provider stdout must be an async readable stream')
  }
  if (!writable || typeof writable.write !== 'function') {
    throw runnerError('PROVIDER_STREAM_INVALID', 'provider stdin must be a writable stream')
  }
  if (
    backend === null
    || typeof backend !== 'object'
    || Array.isArray(backend)
    || backend.type !== 'OCI_DOCKER'
    || backend.runtime_path !== config.runtime_path
    || backend.context !== 'default'
    || backend.image !== config.image
    || !CONTAINER_NAME_PATTERN.test(backend.container_name ?? '')
    || !SHA256_PATTERN.test(backend.container_id ?? '')
    || backend.security_profile !== 'builtin'
  ) {
    throw runnerError(
      'PROVIDER_BACKEND_INVALID',
      'broker backend metadata must match the trusted Docker configuration',
    )
  }

  const packet = sanitizeProviderPacket(rawPacket)
  const artifacts = normalizeProviderArtifacts(rawArtifacts, config.limits)
  const artifactIndex = new Map(artifacts.map((artifact) => [artifact.artifact_id, artifact]))
  const sessionId = generatedOpaqueId(randomBytesImpl, 24, 'session')
  const startedAt = timestamp(now)
  const transcript = createHash('sha256')
  const deliveries = []
  const deliveredIds = new Set()
  const decoder = new TextDecoder('utf-8', { fatal: true })
  let outstanding
  let result
  let buffered = Buffer.alloc(0)
  let stdoutBytes = 0
  let deliveryBytes = 0
  let wallTimer
  let idleTimer
  let deliveryTimer
  let abortListener
  // Both guards outlive this call on purpose: the caller keeps using the child
  // stdio after the broker returns, and destroy(error) emits 'error' later.
  const readableErrorGuard = () => {}
  const writableErrorGuard = () => {}
  readable.on?.('error', readableErrorGuard)
  writable.on?.('error', writableErrorGuard)

  const receiptSnapshot = () => partialReceipt({
    packet,
    sessionId,
    startedAt,
    now,
    backend,
    deliveries,
    transcript,
  })

  const abortStreams = (error) => {
    if (!readable.destroyed) readable.destroy(error)
    if (!writable.destroyed) writable.destroy(error)
  }
  const timedError = (code, message) => {
    abortStreams(runnerError(code, message, { partialReceipt: receiptSnapshot() }))
  }
  const signalError = () => {
    if (signal?.reason instanceof ProviderRunnerError) {
      if (!signal.reason.partial_receipt) {
        signal.reason.partial_receipt = receiptSnapshot()
      }
      return signal.reason
    }
    return runnerError(
      'PROVIDER_ABORTED',
      'provider execution was aborted',
      { cause: signal?.reason, partialReceipt: receiptSnapshot() },
    )
  }
  const armIdleTimer = () => {
    clearTimeout(idleTimer)
    idleTimer = setTimeout(
      () => timedError(
        'PROVIDER_IDLE_TIMEOUT',
        `provider emitted no complete protocol progress for ${config.limits.idle_timeout_ms}ms`,
      ),
      config.limits.idle_timeout_ms,
    )
    idleTimer.unref?.()
  }
  const armDeliveryTimer = () => {
    clearTimeout(deliveryTimer)
    deliveryTimer = setTimeout(
      () => timedError(
        'PROVIDER_DELIVERY_TIMEOUT',
        `provider did not consume a delivery within ${config.limits.delivery_timeout_ms}ms`,
      ),
      config.limits.delivery_timeout_ms,
    )
    deliveryTimer.unref?.()
  }

  try {
    if (signal?.aborted) {
      throw signalError()
    }
    if (signal) {
      abortListener = () => abortStreams(signalError())
      signal.addEventListener('abort', abortListener, { once: true })
    }

    wallTimer = setTimeout(
      () => timedError(
        'PROVIDER_WALL_TIMEOUT',
        `provider exceeded the ${config.limits.wall_time_ms}ms wall-time limit`,
      ),
      config.limits.wall_time_ms,
    )
    wallTimer.unref?.()
    armIdleTimer()

    await writeJsonLine(writable, {
      type: 'provider_start',
      schema_version: '1.0.0',
      protocol: PROVIDER_PROTOCOL,
      session_id: sessionId,
      packet,
      allowed_artifacts: artifacts.map((artifact) => ({
        artifact_id: artifact.artifact_id,
        kind: artifact.kind,
        logical_name: artifact.logical_name,
        size: artifact.size,
        sha256: artifact.sha256,
      })),
      receipt_scope: 'BYTE_DELIVERY_AND_CHALLENGE_CONSUMPTION_ONLY',
      semantic_analysis_proven: false,
    }, config.limits.max_frame_bytes, transcript)

    const handleMessage = async (message) => {
      if (result !== undefined) {
        throw runnerError(
          'PROVIDER_PROTOCOL_VIOLATION',
          'provider emitted output after its terminal job_result frame',
        )
      }
      requireString(message?.type, 'frame type')

      if (message.type === 'artifact_request') {
        exactObject(
          message,
          'artifact_request',
          new Set(['type', 'schema_version', 'session_id', 'artifact_id']),
          ['type', 'schema_version', 'session_id', 'artifact_id'],
        )
        if (message.schema_version !== '1.0.0' || message.session_id !== sessionId) {
          throw runnerError(
            'PROVIDER_PROTOCOL_VIOLATION',
            'artifact_request is not bound to this protocol session',
          )
        }
        if (outstanding) {
          throw runnerError(
            'PROVIDER_PROTOCOL_VIOLATION',
            'provider requested a second artifact before consuming the first',
          )
        }
        const artifact = artifactIndex.get(message.artifact_id)
        if (!artifact) {
          throw runnerError(
            'PROVIDER_UNAUTHORIZED_ARTIFACT',
            'provider requested an artifact ID outside the controller allowlist',
          )
        }
        if (deliveredIds.has(artifact.artifact_id)) {
          throw runnerError(
            'PROVIDER_PROTOCOL_VIOLATION',
            'provider requested the same artifact more than once',
          )
        }
        if (deliveries.length >= config.limits.max_deliveries) {
          throw runnerError('PROVIDER_DELIVERY_LIMIT', 'provider exceeded max_deliveries')
        }
        if (deliveryBytes + artifact.size > config.limits.max_total_delivery_bytes) {
          throw runnerError(
            'PROVIDER_DELIVERY_LIMIT',
            'provider exceeded max_total_delivery_bytes',
          )
        }

        const challenge = randomBytesImpl(32)
        if (!Buffer.isBuffer(challenge) || challenge.length !== 32) {
          throw runnerError(
            'PROVIDER_RANDOM_SOURCE_INVALID',
            'delivery challenge source must return exactly 32 bytes',
          )
        }
        const deliveryId = generatedOpaqueId(randomBytesImpl, 18, 'delivery')
        const expectedHmac = computeConsumptionHmac({
          challenge,
          jobId: packet.job_id,
          artifactId: artifact.artifact_id,
          size: artifact.size,
          bytes: artifact.bytes,
        })
        const receiptDelivery = {
          delivery_id: deliveryId,
          artifact_id: artifact.artifact_id,
          artifact_kind: artifact.kind,
          logical_name: artifact.logical_name,
          expected_sha256: artifact.sha256,
          size: artifact.size,
          events: [],
        }
        outstanding = {
          artifact,
          challenge,
          deliveryId,
          expectedHmac,
          receiptDelivery,
        }
        await writeJsonLine(writable, {
          type: 'artifact_delivery',
          schema_version: '1.0.0',
          session_id: sessionId,
          delivery_id: deliveryId,
          artifact_id: artifact.artifact_id,
          kind: artifact.kind,
          logical_name: artifact.logical_name,
          size: artifact.size,
          sha256: artifact.sha256,
          challenge_base64: challenge.toString('base64'),
          hmac_algorithm: 'HMAC-SHA256',
          hmac_domain: CONSUMPTION_HMAC_DOMAIN,
          content_base64: artifact.bytes.toString('base64'),
        }, config.limits.max_frame_bytes, transcript)
        receiptDelivery.events.push({
          state: 'DELIVERED',
          observed_at: timestamp(now),
          bytes_sent: artifact.size,
          transport_sha256: artifact.sha256,
        })
        deliveries.push(receiptDelivery)
        deliveredIds.add(artifact.artifact_id)
        deliveryBytes += artifact.size
        armDeliveryTimer()
        return
      }

      if (message.type === 'artifact_consumed') {
        exactObject(
          message,
          'artifact_consumed',
          new Set([
            'type',
            'schema_version',
            'session_id',
            'delivery_id',
            'artifact_id',
            'challenge_hmac_sha256',
          ]),
          [
            'type',
            'schema_version',
            'session_id',
            'delivery_id',
            'artifact_id',
            'challenge_hmac_sha256',
          ],
        )
        if (
          message.schema_version !== '1.0.0'
          || message.session_id !== sessionId
          || !outstanding
          || message.delivery_id !== outstanding.deliveryId
          || message.artifact_id !== outstanding.artifact.artifact_id
        ) {
          throw runnerError(
            'PROVIDER_PROTOCOL_VIOLATION',
            'artifact_consumed does not match the outstanding delivery',
          )
        }
        if (!compareHexDigest(outstanding.expectedHmac, message.challenge_hmac_sha256)) {
          throw runnerError(
            'PROVIDER_CONSUMPTION_CHALLENGE_FAILED',
            'artifact consumption HMAC did not verify',
          )
        }
        clearTimeout(deliveryTimer)
        outstanding.receiptDelivery.events.push({
          state: 'CONSUMED',
          observed_at: timestamp(now),
          challenge_base64: outstanding.challenge.toString('base64'),
          hmac_algorithm: 'HMAC-SHA256',
          hmac_domain: CONSUMPTION_HMAC_DOMAIN,
          challenge_hmac_sha256: message.challenge_hmac_sha256,
        })
        outstanding = undefined
        return
      }

      if (message.type === 'job_result') {
        exactObject(
          message,
          'job_result',
          new Set(['type', 'schema_version', 'session_id', 'result']),
          ['type', 'schema_version', 'session_id', 'result'],
        )
        if (message.schema_version !== '1.0.0' || message.session_id !== sessionId) {
          throw runnerError(
            'PROVIDER_PROTOCOL_VIOLATION',
            'job_result is not bound to this protocol session',
          )
        }
        if (outstanding) {
          throw runnerError(
            'PROVIDER_PROTOCOL_VIOLATION',
            'job_result arrived before the outstanding delivery was consumed',
          )
        }
        if (
          message.result?.run_id !== packet.run_id
          || message.result?.job_id !== packet.job_id
          || message.result?.input_sha256?.toLowerCase() !== packet.packet_sha256.toLowerCase()
        ) {
          throw runnerError(
            'PROVIDER_RESULT_BINDING_MISMATCH',
            'job_result does not match the sanitized packet identity',
          )
        }
        result = message.result
        clearTimeout(deliveryTimer)
        endWritable(writable)
        return
      }

      throw runnerError(
        'PROVIDER_PROTOCOL_VIOLATION',
        `unsupported provider frame type ${JSON.stringify(message.type)}`,
      )
    }

    for await (const chunkValue of readable) {
      const chunk = Buffer.isBuffer(chunkValue)
        ? chunkValue
        : Buffer.from(chunkValue)
      stdoutBytes += chunk.length
      if (stdoutBytes > config.limits.max_stdout_bytes) {
        throw runnerError(
          'PROVIDER_STDOUT_LIMIT',
          `provider stdout exceeded ${config.limits.max_stdout_bytes} bytes`,
        )
      }
      buffered = Buffer.concat([buffered, chunk])
      while (true) {
        const newline = buffered.indexOf(0x0a)
        if (newline < 0) break
        const line = buffered.subarray(0, newline)
        buffered = buffered.subarray(newline + 1)
        if (line.length === 0 || line[line.length - 1] === 0x0d) {
          throw runnerError(
            'PROVIDER_PROTOCOL_VIOLATION',
            'provider stdout must contain non-empty LF-delimited JSON frames',
          )
        }
        if (line.length > config.limits.max_frame_bytes) {
          throw runnerError(
            'PROVIDER_FRAME_LIMIT',
            `provider frame exceeded ${config.limits.max_frame_bytes} bytes`,
          )
        }
        transcriptUpdate(transcript, 'provider', line)
        await handleMessage(parseJsonLine(line, decoder))
        armIdleTimer()
      }
      if (buffered.length > config.limits.max_frame_bytes) {
        throw runnerError(
          'PROVIDER_FRAME_LIMIT',
          `provider frame exceeded ${config.limits.max_frame_bytes} bytes`,
        )
      }
    }

    if (buffered.length !== 0) {
      throw runnerError(
        'PROVIDER_PROTOCOL_VIOLATION',
        'provider stdout ended with an unterminated JSONL frame',
      )
    }
    if (result === undefined) {
      throw runnerError(
        'PROVIDER_RESULT_MISSING',
        'provider stdout ended without a terminal job_result frame',
      )
    }

    const execution = {
      schema_version: '1.0.0',
      protocol: PROVIDER_PROTOCOL,
      job_result: jsonClone(result, 'provider job_result'),
      receipt: partialReceipt({
        packet,
        sessionId,
        startedAt,
        now,
        backend,
        deliveries,
        transcript,
      }),
    }
    return assertValidProviderExecution(execution)
  } catch (error) {
    endWritable(writable)
    if (error instanceof ProviderRunnerError) {
      if (!error.partial_receipt) error.partial_receipt = receiptSnapshot()
      throw error
    }
    throw runnerError(
      'PROVIDER_BROKER_FAILED',
      'provider broker failed',
      { cause: error, partialReceipt: receiptSnapshot() },
    )
  } finally {
    clearTimeout(wallTimer)
    clearTimeout(idleTimer)
    clearTimeout(deliveryTimer)
    if (signal && abortListener) signal.removeEventListener('abort', abortListener)
  }
}

function sanitizedDockerEnvironment() {
  const environment = { ...process.env }
  for (const key of [
    'DOCKER_HOST',
    'DOCKER_CONTEXT',
    'DOCKER_TLS',
    'DOCKER_TLS_VERIFY',
    'DOCKER_CERT_PATH',
  ]) {
    delete environment[key]
  }
  return environment
}

function dockerSpawnOptions(stdio) {
  return {
    shell: false,
    windowsHide: true,
    stdio,
    env: sanitizedDockerEnvironment(),
  }
}

function sanitizeDiagnostic(value) {
  return String(value)
    .replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g, '')
    .replace(/\x1b(?:[@-_]|\[[0-?]*[ -/]*[@-~])/g, '')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '\uFFFD')
}

async function runDockerCommand({
  runtimePath,
  args,
  spawnImpl,
  timeoutMs,
  maxStdoutBytes = 2 * 1024 * 1024,
  maxStderrBytes = 1024 * 1024,
  allowNonZero = false,
}) {
  const child = spawnImpl(
    runtimePath,
    args,
    dockerSpawnOptions(['ignore', 'pipe', 'pipe']),
  )
  let stdoutBytes = 0
  let stderrBytes = 0
  const stdout = []
  const stderr = []

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
    const onData = (target, limit, setTotal) => (chunkValue) => {
      const chunk = Buffer.isBuffer(chunkValue) ? chunkValue : Buffer.from(chunkValue)
      const total = setTotal(chunk.length)
      if (total > limit) {
        child.kill?.('SIGKILL')
        fail('PROVIDER_DOCKER_OUTPUT_LIMIT', 'Docker command exceeded its output limit')
        return
      }
      target.push(chunk)
    }
    child.stdout?.on('data', onData(stdout, maxStdoutBytes, (bytes) => {
      stdoutBytes += bytes
      return stdoutBytes
    }))
    child.stderr?.on('data', onData(stderr, maxStderrBytes, (bytes) => {
      stderrBytes += bytes
      return stderrBytes
    }))
    child.once('error', (error) => fail(
      'PROVIDER_DOCKER_SPAWN_FAILED',
      'could not start the trusted Docker runtime',
      error,
    ))
    child.once('close', (code, signal) => finish(() => {
      const stderrText = sanitizeDiagnostic(Buffer.concat(stderr).toString('utf8'))
      if (code !== 0 && !allowNonZero) {
        reject(runnerError(
          'PROVIDER_DOCKER_COMMAND_FAILED',
          `Docker command failed with code ${String(code)} signal ${String(signal)}`,
          { stderr: stderrText },
        ))
        return
      }
      resolve({
        code,
        signal,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: stderrText,
      })
    }))
    timer = setTimeout(() => {
      child.kill?.('SIGKILL')
      fail(
        'PROVIDER_DOCKER_COMMAND_TIMEOUT',
        `Docker command exceeded its ${timeoutMs}ms timeout`,
      )
    }, timeoutMs)
    timer.unref?.()
  })
}

function parseDockerJson(text, label) {
  try {
    return JSON.parse(text.trim())
  } catch (error) {
    throw runnerError(
      'PROVIDER_DOCKER_INSPECTION_INVALID',
      `${label} did not return valid JSON`,
      { cause: error },
    )
  }
}

function parseDockerJsonLines(text, label) {
  const values = []
  for (const [index, line] of text.split(/\r?\n/).entries()) {
    if (line.length === 0) continue
    values.push(parseDockerJson(line, `${label} line ${index + 1}`))
  }
  return values
}

async function inspectExactDockerContainer(command, containerName) {
  const inspectionResult = await command([
    ...dockerPrefix(),
    'container',
    'inspect',
    '--format',
    '{{json .}}',
    containerName,
  ], { allowNonZero: true })
  if (inspectionResult.code === 0) {
    const inspection = parseDockerJson(
      inspectionResult.stdout,
      'Docker container inspection',
    )
    inspectAssertion(
      inspection?.Name === `/${containerName}`
        || inspection?.Name === containerName,
      'container inspection returned the wrong named container',
    )
    return { state: 'PRESENT', inspection }
  }

  // A nonzero `container inspect` can also mean daemon or transport failure.
  // Require a second, successful, exact-name daemon query before treating the
  // container as absent.
  const listingResult = await command([
    ...dockerPrefix(),
    'container',
    'ls',
    '--all',
    '--no-trunc',
    `--filter=name=^/${containerName}$`,
    '--format',
    '{{json .Names}}',
  ])
  const names = parseDockerJsonLines(
    listingResult.stdout,
    'Docker exact-name container listing',
  )
  inspectAssertion(
    names.every((name) => (
      name === containerName || name === `/${containerName}`
    )),
    'Docker exact-name listing returned an unexpected container',
  )
  return names.length === 0
    ? { state: 'ABSENT' }
    : { state: 'PRESENT' }
}

function cleanupDiagnostic(stage, value) {
  const code = value?.code === undefined ? '' : ` code=${String(value.code)}`
  const message = value?.message ? ` ${String(value.message)}` : ''
  const stderr = value?.stderr ? ` ${String(value.stderr)}` : ''
  return sanitizeDiagnostic(`${stage}:${code}${message}${stderr}`).trim()
}

function unverifiedCleanupError(containerName, diagnostics) {
  const error = runnerError(
    'PROVIDER_CLEANUP_UNVERIFIED',
    'could not prove the exact provider container absent after cleanup',
    {
      stderr: diagnostics
        .filter(Boolean)
        .join('\n')
        .slice(0, 65_536),
    },
  )
  error.container_name = containerName
  error.container_absence_verified = false
  return error
}

function unverifiedCreateOutcomeError(containerName, primaryError) {
  const error = runnerError(
    'PROVIDER_CREATE_OUTCOME_UNVERIFIED',
    'Docker create did not reach a confirmed terminal outcome; present-time absence cannot exclude a late daemon-side create',
    {
      stderr: cleanupDiagnostic('create', primaryError).slice(0, 65_536),
    },
  )
  error.container_name = containerName
  error.container_absence_verified = true
  error.create_outcome_verified = false
  return error
}

async function removeExactDockerContainer(command, containerName) {
  const cleanup = buildDockerCleanupArgs(containerName)
  const diagnostics = []
  try {
    const killed = await command(cleanup.kill, { allowNonZero: true })
    if (killed.code !== 0) {
      diagnostics.push(cleanupDiagnostic('kill', killed))
    }
  } catch (error) {
    diagnostics.push(cleanupDiagnostic('kill', error))
  }
  try {
    const removed = await command(cleanup.remove, { allowNonZero: true })
    if (removed.code !== 0) {
      diagnostics.push(cleanupDiagnostic('remove', removed))
    }
  } catch (error) {
    diagnostics.push(cleanupDiagnostic('remove', error))
  }

  let postCleanup
  try {
    postCleanup = await inspectExactDockerContainer(command, containerName)
  } catch (error) {
    diagnostics.push(cleanupDiagnostic('post-inspection', error))
    throw unverifiedCleanupError(containerName, diagnostics)
  }
  if (postCleanup.state !== 'ABSENT') {
    diagnostics.push('post-inspection: exact container is still present')
    throw unverifiedCleanupError(containerName, diagnostics)
  }
  return { absent: true }
}

function createStderrMonitor(stream, limit, abortController) {
  const chunks = []
  let bytes = 0
  let limitExceeded = false
  stream?.on('data', (chunkValue) => {
    const chunk = Buffer.isBuffer(chunkValue) ? chunkValue : Buffer.from(chunkValue)
    const remaining = Math.max(0, limit - bytes)
    if (remaining > 0) chunks.push(chunk.subarray(0, remaining))
    bytes += chunk.length
    if (!limitExceeded && bytes > limit) {
      limitExceeded = true
      abortController.abort(runnerError(
        'PROVIDER_STDERR_LIMIT',
        `provider stderr exceeded ${limit} bytes`,
      ))
    }
  })
  stream?.on('error', (error) => abortController.abort(runnerError(
    'PROVIDER_STDERR_FAILED',
    'provider stderr stream failed',
    { cause: error },
  )))
  return () => sanitizeDiagnostic(Buffer.concat(chunks).toString('utf8'))
}

function waitForChildExit(child, timeoutMs) {
  let rearm = () => {}
  const exited = new Promise((resolve, reject) => {
    let settled = false
    let timer
    const finish = (callback) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      callback()
    }
    const arm = (limitMs) => {
      clearTimeout(timer)
      timer = setTimeout(() => {
        child.kill?.('SIGKILL')
        finish(() => reject(runnerError(
          'PROVIDER_DOCKER_EXIT_TIMEOUT',
          `Docker attach process did not exit within ${limitMs}ms`,
        )))
      }, limitMs)
      timer.unref?.()
    }
    rearm = (limitMs) => {
      if (!settled) arm(limitMs)
    }
    child.once('error', (error) => finish(() => reject(runnerError(
      'PROVIDER_DOCKER_SPAWN_FAILED',
      'could not attach to the provider container',
      { cause: error },
    ))))
    child.once('close', (code, signal) => finish(() => resolve({ code, signal })))
    arm(timeoutMs)
  })
  return { exited, rearm }
}

export async function cleanupDockerProviderContainer(options) {
  const {
    config,
    containerName,
    spawnImpl = nodeSpawn,
  } = options
  assertValidProviderConfig(config)
  assertContainerName(containerName)
  const command = (args, overrides = {}) => runDockerCommand({
    runtimePath: config.runtime_path,
    args,
    spawnImpl,
    timeoutMs: config.limits.docker_command_timeout_ms,
    ...overrides,
  })
  try {
    const contextResult = await command([
      ...dockerPrefix(),
      'context',
      'inspect',
      'default',
      '--format',
      '{{json .Endpoints.docker.Host}}',
    ])
    assertLocalDockerContextHost(
      parseDockerJson(contextResult.stdout, 'Docker context inspection'),
    )
    const before = await inspectExactDockerContainer(command, containerName)
    if (before.state === 'ABSENT') return { absent: true }
    assertHardenedDockerInspection(before.inspection, config, containerName)
    await removeExactDockerContainer(command, containerName)
    return { absent: false, removed: true }
  } catch (error) {
    if (error?.code === 'PROVIDER_CLEANUP_UNVERIFIED') throw error
    throw unverifiedCleanupError(
      containerName,
      [cleanupDiagnostic('cleanup-inspection', error)],
    )
  }
}

/**
 * Launch one immutable provider image through an explicitly trusted Docker CLI
 * path. All child-process calls use argv arrays with shell:false. The exact
 * generated container is killed and removed before this function returns.
 */
export async function runDockerProvider(options) {
  const {
    config,
    packet,
    artifacts,
    spawnImpl = nodeSpawn,
    now = () => new Date(),
    randomBytesImpl = randomBytes,
    randomUUIDImpl = randomUUID,
    containerName: configuredContainerName,
  } = options
  assertValidProviderConfig(config)

  let containerName = configuredContainerName
  if (containerName === undefined) {
    const uuid = randomUUIDImpl()
    if (typeof uuid !== 'string' || !/^[a-f0-9-]{36}$/i.test(uuid)) {
      throw runnerError('PROVIDER_RANDOM_SOURCE_INVALID', 'invalid container UUID')
    }
    containerName = `rta-provider-${uuid.replaceAll('-', '').toLowerCase()}`
  }
  assertContainerName(containerName)
  const command = (args, overrides = {}) => runDockerCommand({
    runtimePath: config.runtime_path,
    args,
    spawnImpl,
    timeoutMs: config.limits.docker_command_timeout_ms,
    ...overrides,
  })

  let createAttempted = false
  let createOutcomeConfirmed = false
  let startChild
  let startExitOutcome
  let startExitObserved = false
  let execution
  let primaryError
  let cleanupError
  let createOutcomeUnverified = false
  let stderrText = () => ''

  try {
    const contextResult = await command([
      ...dockerPrefix(),
      'context',
      'inspect',
      'default',
      '--format',
      '{{json .Endpoints.docker.Host}}',
    ])
    const contextHost = parseDockerJson(contextResult.stdout, 'Docker context inspection')
    assertLocalDockerContextHost(contextHost)

    const versionResult = await command([
      ...dockerPrefix(),
      'version',
      '--format',
      '{{json .Server.Version}}',
    ])
    const runtimeVersion = parseDockerJson(versionResult.stdout, 'Docker version inspection')
    inspectAssertion(
      typeof runtimeVersion === 'string' && runtimeVersion.length > 0,
      'Docker server version is missing',
    )

    const imageResult = await command([
      ...dockerPrefix(),
      'image',
      'inspect',
      '--format',
      '{{json .}}',
      config.image,
    ])
    assertSafeDockerImageInspection(
      parseDockerJson(imageResult.stdout, 'Docker image inspection'),
    )

    createAttempted = true
    const createResult = await command(buildDockerCreateArgs(config, containerName))
    createOutcomeConfirmed = true
    const createdId = createResult.stdout.trim()
    if (!SHA256_PATTERN.test(createdId)) {
      throw runnerError(
        'PROVIDER_DOCKER_CREATE_INVALID',
        'Docker create did not return a full immutable container ID',
      )
    }
    const inspectResult = await command([
      ...dockerPrefix(),
      'container',
      'inspect',
      '--format',
      '{{json .}}',
      containerName,
    ])
    const inspection = parseDockerJson(inspectResult.stdout, 'Docker container inspection')
    const inspectedId = assertHardenedDockerInspection(
      inspection,
      config,
      containerName,
    )
    if (inspectedId !== createdId) {
      throw runnerError(
        'PROVIDER_DOCKER_ID_MISMATCH',
        'Docker container identity changed between create and inspect',
      )
    }

    startChild = spawnImpl(
      config.runtime_path,
      buildDockerStartArgs(containerName),
      dockerSpawnOptions(['pipe', 'pipe', 'pipe']),
    )
    const abortController = new AbortController()
    startChild.once('error', (error) => abortController.abort(error))
    stderrText = createStderrMonitor(
      startChild.stderr,
      config.limits.max_stderr_bytes,
      abortController,
    )
    // The provider's own work is bounded by wall_time_ms, and the broker arms
    // that timer after this spawn, so the attach client must outlive it by one
    // Docker command slot or our SIGKILL preempts PROVIDER_WALL_TIMEOUT.
    const startExit = waitForChildExit(
      startChild,
      config.limits.wall_time_ms + config.limits.docker_command_timeout_ms,
    )
    startExitOutcome = startExit.exited.then(
      (exit) => ({ exit }),
      (error) => ({ error }),
    )
    try {
      execution = await runProviderBroker({
        readable: startChild.stdout,
        writable: startChild.stdin,
        packet,
        artifacts,
        config,
        backend: {
          type: 'OCI_DOCKER',
          runtime_path: config.runtime_path,
          runtime_version: runtimeVersion,
          context: 'default',
          image: config.image,
          container_name: containerName,
          container_id: createdId,
          security_profile: 'builtin',
        },
        signal: abortController.signal,
        now,
        randomBytesImpl,
      })
    } finally {
      startExit.rearm(config.limits.docker_command_timeout_ms)
    }
    const exitOutcome = await startExitOutcome
    startExitObserved = true
    if (exitOutcome.error) throw exitOutcome.error
    const { exit } = exitOutcome
    if (exit.code !== 0) {
      throw runnerError(
        'PROVIDER_PROCESS_FAILED',
        `provider container exited with code ${String(exit.code)} signal ${String(exit.signal)}`,
        { stderr: stderrText() },
      )
    }
  } catch (error) {
    primaryError = error instanceof ProviderRunnerError
      ? error
      : runnerError('PROVIDER_EXECUTION_FAILED', 'provider execution failed', { cause: error })
    createOutcomeUnverified = (
      createAttempted
      && !createOutcomeConfirmed
      && [
        'PROVIDER_DOCKER_COMMAND_FAILED',
        'PROVIDER_DOCKER_COMMAND_TIMEOUT',
        'PROVIDER_DOCKER_OUTPUT_LIMIT',
      ].includes(primaryError.code)
    )
  } finally {
    startChild?.stdin?.end()
    if (createAttempted) {
      try {
        await removeExactDockerContainer(command, containerName)
        if (createOutcomeUnverified) {
          cleanupError = unverifiedCreateOutcomeError(
            containerName,
            primaryError,
          )
        }
      } catch (error) {
        cleanupError = error instanceof ProviderRunnerError
          ? error
          : runnerError('PROVIDER_CLEANUP_FAILED', 'provider cleanup failed', { cause: error })
      }
    }
    startChild?.kill?.('SIGKILL')
    if (startExitOutcome && !startExitObserved) {
      const exitOutcome = await startExitOutcome
      startExitObserved = true
      if (exitOutcome.error) {
        if (primaryError) primaryError.exit_error = exitOutcome.error
        else primaryError = exitOutcome.error
      }
    }
  }

  if (primaryError) {
    if (!primaryError.stderr) primaryError.stderr = stderrText()
    if (!primaryError.partial_receipt && execution?.receipt) {
      primaryError.partial_receipt = execution.receipt
    }
    if (cleanupError) primaryError.cleanup_error = cleanupError
    throw primaryError
  }
  if (cleanupError) {
    if (execution?.receipt) cleanupError.partial_receipt = execution.receipt
    throw cleanupError
  }
  return execution
}
