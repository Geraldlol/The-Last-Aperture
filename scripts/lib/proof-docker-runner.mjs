import { spawn as nodeSpawn } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { createReadStream, readFileSync } from 'node:fs'
import { lstat, mkdtemp, readFile, readdir, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { isAbsolute, join, relative, sep } from 'node:path'
import { performance } from 'node:perf_hooks'

import Ajv2020 from 'ajv/dist/2020.js'

import {
  assertHardenedDockerInspection,
  assertLocalDockerContextHost,
  buildDockerCreateArgs,
} from './provider-runner.mjs'

const PROOF_WORKER_SCHEMA_URL = new URL(
  '../../schemas/proof-worker.schema.json',
  import.meta.url,
)
const validateProofWorkerSchema = new Ajv2020({ strict: true, allErrors: true })
  .compile(JSON.parse(readFileSync(PROOF_WORKER_SCHEMA_URL, 'utf8')))

export const PROOF_HOLD_SOURCE = 'setInterval(() => {}, 1 << 30)'
export const PROOF_CONTAINER_PATH =
  '/opt/rta/node_modules/.bin:/usr/local/bin:/usr/bin:/bin'
const DOCKER_PREFIX = ['--context', 'default']
const CONTAINER_NAME = /^rta-proof-[a-z0-9][a-z0-9-]{7,64}$/
const CONTAINER_ID = /^[a-f0-9]{64}$/
const FIXED_PROGRAMS = Object.freeze({
  node: '/usr/local/bin/node',
  npm: '/usr/local/bin/npm',
})
const PROOF_WORKER_LABEL = 'dev.red-team-audit.proof-worker'
const SERVICE_PROOF_PROTOCOL = 'loopback-tcp-v1'
const SERVICE_PROOF_CONTAINER_NAME_LABEL =
  'dev.red-team-audit.service-proof.container-name'
const SERVICE_PROOF_PROTOCOL_LABEL = 'dev.red-team-audit.service-proof.protocol'
const SERVICE_PROOF_WORKER_CONFIG_LABEL =
  'dev.red-team-audit.service-proof.worker-config-sha256'
const SERVICE_HOST = '127.0.0.1'
const SERVICE_MARKER_PATH = '/work/.rta-start-marker'
const SERVICE_RUNTIME_ROOT = '/work/runtime'
const SERVICE_STAGING_USER = '65532:65532'
const SERVICE_RUNTIME_USER = '65534:65534'
const SERVICE_PROOF_SETUP_DOCKER_SLOTS = 20
const SERVICE_PROOF_CLEANUP_DOCKER_SLOTS = 6
const SERVICE_PROOF_RECOVERY_DOCKER_SLOTS = 15
const SERVICE_CONTAINER_IDENTITY = Object.freeze({
  user: SERVICE_RUNTIME_USER,
  workdir: '/',
  workTmpfsMode: '0711',
})
export const SERVICE_PROOF_SUPERVISOR_SOURCE = [
  'const {existsSync}=require("node:fs")',
  'const {spawn}=require("node:child_process")',
  'const marker=process.argv[1]',
  'const ttlMs=Number(process.argv[2])',
  'const cwd=process.argv[3]',
  'const program=process.argv[4]',
  'const args=process.argv.slice(5)',
  'let child=null',
  'const ttl=setTimeout(()=>process.exit(124),ttlMs)',
  'const poll=setInterval(()=>{',
  'if(!existsSync(marker))return',
  'clearInterval(poll)',
  'child=spawn(program,args,{cwd,shell:false,stdio:"ignore",env:{',
  `HOME:${JSON.stringify(SERVICE_RUNTIME_ROOT)},TMPDIR:${JSON.stringify(SERVICE_RUNTIME_ROOT)},`,
  `XDG_CACHE_HOME:${JSON.stringify(`${SERVICE_RUNTIME_ROOT}/.cache`)},npm_config_cache:${JSON.stringify(`${SERVICE_RUNTIME_ROOT}/.npm`)},`,
  `CI:"1",NO_COLOR:"1",PATH:${JSON.stringify(PROOF_CONTAINER_PATH)},`,
  `RTA_SERVICE_HOST:${JSON.stringify(SERVICE_HOST)},RTA_SERVICE_PORT:process.env.RTA_SERVICE_PORT,`,
  'HTTP_PROXY:"",HTTPS_PROXY:"",NO_PROXY:"",ALL_PROXY:"",',
  'http_proxy:"",https_proxy:"",no_proxy:"",all_proxy:""',
  '}})',
  'child.once("error",()=>process.exit(127))',
  'child.once("exit",(code)=>{clearTimeout(ttl);process.exit(code??1)})',
  '},10)',
  'const stop=()=>{clearInterval(poll);child?.kill("SIGKILL");process.exit(143)}',
  'process.once("SIGTERM",stop)',
  'process.once("SIGINT",stop)',
].join('\n')
const LOOPBACK_PROBE_SOURCE = [
  'const {readFileSync}=require("node:fs")',
  'const net=require("node:net")',
  'const host=process.argv[1]',
  'const port=Number(process.argv[2])',
  'const timeoutMs=Number(process.argv[3])',
  'const listeners=[]',
  'for(const path of ["/proc/net/tcp","/proc/net/tcp6"]){',
  'let text=""',
  'try{text=readFileSync(path,"utf8")}catch{process.exit(2)}',
  'for(const line of text.trim().split(/\\n/).slice(1)){',
  'const fields=line.trim().split(/\\s+/)',
  'if(fields.length<4||fields[3]!=="0A")continue',
  'const [address,portHex]=fields[1].split(":")',
  'if(Number.parseInt(portHex,16)===port)listeners.push({path,address})',
  '}',
  '}',
  'if(listeners.length===0)process.exit(1)',
  'if(listeners.length!==1||listeners[0].path!=="/proc/net/tcp"||listeners[0].address!=="0100007F")process.exit(3)',
  'let settled=false',
  'let timer',
  'const socket=net.createConnection({host,port})',
  'const finish=(code)=>{if(settled)return;settled=true;if(timer)clearTimeout(timer);socket.destroy();process.exit(code)}',
  'socket.once("connect",()=>finish(0))',
  'socket.once("error",()=>finish(2))',
  'timer=setTimeout(()=>finish(2),timeoutMs)',
].join(';')
const DEPENDENCY_MANIFEST_DOMAIN =
  'red-team-audit/proof-dependency-manifest/v1\0'
const DEPENDENCY_MANIFEST_FILES = Object.freeze([
  'package.json',
  'package-lock.json',
])
const PROOF_WORKTREE_MANIFEST_DOMAIN =
  'red-team-audit/proof-worktree-manifest/v1\0'
const DEPENDENCY_MANIFEST_HASH_SOURCE = [
  'const {createHash}=require("node:crypto")',
  'const {readFileSync}=require("node:fs")',
  'const h=createHash("sha256")',
  `h.update(${JSON.stringify(DEPENDENCY_MANIFEST_DOMAIN)},"utf8")`,
  `for(const [name,path] of ${JSON.stringify(DEPENDENCY_MANIFEST_FILES)}.map((name,index)=>[name,process.argv[index+1]])){`,
  'const bytes=readFileSync(path)',
  'h.update(name,"utf8").update("\\0","utf8")',
  'h.update(String(bytes.length),"ascii").update("\\0","utf8")',
  'h.update(bytes).update("\\0","utf8")',
  '}',
  'process.stdout.write(h.digest("hex"))',
].join(';')
const PROOF_WORKTREE_MANIFEST_SOURCE = [
  'const {createHash}=require("node:crypto")',
  'const {createReadStream,readlinkSync}=require("node:fs")',
  'const {lstat,readdir}=require("node:fs/promises")',
  'const {join}=require("node:path")',
  `const domain=${JSON.stringify(PROOF_WORKTREE_MANIFEST_DOMAIN)}`,
  'const root=process.argv[1]',
  'const expectedUid=Number(process.argv[2])',
  'const allowedLink="node_modules"',
  'const allowedTarget="/opt/rta/node_modules"',
  'const entries=[]',
  'const compare=(a,b)=>Buffer.compare(Buffer.from(a.path,"utf8"),Buffer.from(b.path,"utf8"))',
  'async function walk(directory,prefix=""){',
  'for(const entry of await readdir(directory,{withFileTypes:true})){',
  'const path=prefix?`${prefix}/${entry.name}`:entry.name',
  'const absolute=join(directory,entry.name)',
  'const stat=await lstat(absolute)',
  'if(path===allowedLink){',
  'if(!stat.isSymbolicLink()||readlinkSync(absolute)!==allowedTarget||stat.uid!==expectedUid)throw new Error("invalid controller dependency link")',
  'continue',
  '}',
  'if(stat.isSymbolicLink())throw new Error("worktree contains a symbolic link")',
  'if(stat.uid!==expectedUid)throw new Error("worktree owner drifted")',
  'if((stat.mode&0o222)!==0)throw new Error("worktree is writable")',
  'if(stat.isDirectory()){entries.push({type:"D",path,absolute,size:0});await walk(absolute,path);continue}',
  'if(!stat.isFile())throw new Error("worktree contains a special file")',
  'entries.push({type:"F",path,absolute,size:stat.size})',
  '}',
  '}',
  '(async()=>{',
  'const rootStat=await lstat(root)',
  'if(!rootStat.isDirectory()||rootStat.isSymbolicLink()||rootStat.uid!==expectedUid||(rootStat.mode&0o222)!==0)throw new Error("worktree root is not sealed")',
  'await walk(root)',
  'entries.sort(compare)',
  'const hash=createHash("sha256").update(domain,"utf8")',
  'for(const entry of entries){',
  'const pathBytes=Buffer.from(entry.path,"utf8")',
  'hash.update(entry.type,"ascii").update("\\0","utf8")',
  'hash.update(String(pathBytes.length),"ascii").update("\\0","utf8").update(pathBytes).update("\\0","utf8")',
  'if(entry.type==="F"){',
  'hash.update(String(entry.size),"ascii").update("\\0","utf8")',
  'let observed=0',
  'for await(const chunk of createReadStream(entry.absolute)){observed+=chunk.length;hash.update(chunk)}',
  'if(observed!==entry.size)throw new Error("worktree changed while hashing")',
  'hash.update("\\0","utf8")',
  '}',
  '}',
  'process.stdout.write(hash.digest("hex"))',
  '})().catch(()=>process.exit(2))',
].join(';')

export const CONTROLLER_DOCKER_RUNTIME = process.platform === 'win32'
  ? 'C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe'
  : '/usr/bin/docker'
export const CONTROLLER_ARCHIVE_RUNTIME = process.platform === 'win32'
  ? 'C:\\Windows\\System32\\tar.exe'
  : '/usr/bin/tar'

function stable(value) {
  if (Array.isArray(value)) return value.map(stable)
  if (value === null || typeof value !== 'object') return value
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, stable(value[key])]),
  )
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child)
    Object.freeze(value)
  }
  return value
}

export function proofDependencyManifestDigest(packageJson, packageLock) {
  const manifests = [packageJson, packageLock].map((value, index) => {
    if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
      throw new TypeError(`${DEPENDENCY_MANIFEST_FILES[index]} must be bytes`)
    }
    return Buffer.from(value)
  })
  const hash = createHash('sha256').update(DEPENDENCY_MANIFEST_DOMAIN, 'utf8')
  for (const [index, bytes] of manifests.entries()) {
    hash.update(DEPENDENCY_MANIFEST_FILES[index], 'utf8')
    hash.update('\0', 'utf8')
    hash.update(String(bytes.length), 'ascii')
    hash.update('\0', 'utf8')
    hash.update(bytes)
    hash.update('\0', 'utf8')
  }
  return hash.digest('hex')
}

function compareUtf8Paths(left, right) {
  return Buffer.compare(
    Buffer.from(left.path, 'utf8'),
    Buffer.from(right.path, 'utf8'),
  )
}

function updateWorktreeEntryHeader(hash, entry) {
  const pathBytes = Buffer.from(entry.path, 'utf8')
  hash.update(entry.type, 'ascii')
  hash.update('\0', 'utf8')
  hash.update(String(pathBytes.length), 'ascii')
  hash.update('\0', 'utf8')
  hash.update(pathBytes)
  hash.update('\0', 'utf8')
  if (entry.type === 'F') {
    hash.update(String(entry.size), 'ascii')
    hash.update('\0', 'utf8')
  }
}

/**
 * Hash every regular file and directory in the controller-materialized proof
 * tree. Metadata is deliberately excluded so the same sealed bytes have one
 * digest on Windows and Linux; links and special files are never executable
 * proof input.
 */
export async function proofSourceTreeDigest(sourceRoot, maxSourceBytes) {
  if (typeof sourceRoot !== 'string' || !isAbsolute(sourceRoot)) {
    throw new Error('proof sourceRoot must be an absolute local directory')
  }
  if (!Number.isSafeInteger(maxSourceBytes) || maxSourceBytes < 1) {
    throw new Error('proof max_source_bytes must be a positive safe integer')
  }
  const rootStat = await lstat(sourceRoot)
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    throw new Error('proof sourceRoot must be a regular local directory')
  }

  const entries = []
  let totalBytes = 0
  const walk = async (directory, prefix = '') => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = prefix ? `${prefix}/${entry.name}` : entry.name
      const absolute = join(directory, entry.name)
      const stat = await lstat(absolute)
      if (stat.isSymbolicLink()) {
        throw new Error(`proof source contains a symbolic link or reparse point: ${path}`)
      }
      if (stat.isDirectory()) {
        entries.push({ type: 'D', path, absolute, size: 0 })
        await walk(absolute, path)
        continue
      }
      if (!stat.isFile()) {
        throw new Error(`proof source contains a special file: ${path}`)
      }
      totalBytes += stat.size
      if (totalBytes > maxSourceBytes) {
        throw new Error('proof source tree exceeds max_source_bytes')
      }
      entries.push({ type: 'F', path, absolute, size: stat.size })
    }
  }
  await walk(sourceRoot)
  entries.sort(compareUtf8Paths)

  const hash = createHash('sha256').update(PROOF_WORKTREE_MANIFEST_DOMAIN, 'utf8')
  for (const entry of entries) {
    updateWorktreeEntryHeader(hash, entry)
    if (entry.type !== 'F') continue
    let observedBytes = 0
    for await (const chunk of createReadStream(entry.absolute)) {
      observedBytes += chunk.length
      hash.update(chunk)
    }
    if (observedBytes !== entry.size) {
      throw new Error(`proof source changed while hashing: ${entry.path}`)
    }
    hash.update('\0', 'utf8')
  }
  return hash.digest('hex')
}

function providerProfile(config) {
  return {
    schema_version: '1.0.0',
    protocol: 'docker-stdio-v1',
    runtime_path: config.runtime_path,
    image: config.image,
    limits: {
      wall_time_ms: config.limits.wall_time_ms,
      docker_command_timeout_ms: Math.min(
        config.limits.docker_command_timeout_ms,
        config.limits.wall_time_ms,
      ),
      idle_timeout_ms: Math.min(config.limits.wall_time_ms, 300_000),
      delivery_timeout_ms: Math.min(config.limits.wall_time_ms, 300_000),
      max_deliveries: 1,
      // The proof route uses `docker cp`, not the provider framing protocol.
      // Keep these schema-only fields minimal so they cannot imply delivery
      // authority that this worker never exercises.
      max_file_bytes: 1,
      max_total_delivery_bytes: 1,
      max_stdout_bytes: Math.max(64 * 1_024, config.limits.max_output_bytes),
      max_stderr_bytes: Math.min(config.limits.max_output_bytes, 16 * 1024 * 1024),
      max_frame_bytes: Math.min(
        Math.max(64 * 1_024, config.limits.max_output_bytes),
        96 * 1024 * 1024,
      ),
      memory_bytes: config.limits.memory_bytes,
      cpus: config.limits.cpus,
      pids: config.limits.pids,
      nofile: config.limits.nofile,
      tmpfs_bytes: config.limits.tmpfs_bytes,
    },
  }
}

export function normalizeProofWorkerConfig(value) {
  if (!validateProofWorkerSchema(value)) {
    const detail = validateProofWorkerSchema.errors
      .map((error) => `${error.instancePath || '/'} ${error.message}`)
      .join('; ')
    throw new Error(`proof worker configuration is invalid: ${detail}`)
  }
  if (value.limits.tmpfs_bytes < value.limits.max_source_bytes) {
    throw new Error(
      'proof worker configuration is invalid: tmpfs_bytes must cover max_source_bytes',
    )
  }
  if (value.runtime_path !== CONTROLLER_DOCKER_RUNTIME) {
    throw new Error(
      `proof worker configuration is invalid: runtime_path must equal ${CONTROLLER_DOCKER_RUNTIME}`,
    )
  }
  return deepFreeze(structuredClone(value))
}

export function proofWorkerConfigDigest(config) {
  const normalized = normalizeProofWorkerConfig(config)
  return createHash('sha256')
    .update(`${JSON.stringify(stable(normalized))}\n`)
    .digest('hex')
}

export function serviceProofControllerBudget(config) {
  const normalized = normalizeProofWorkerConfig(config)
  const dockerSlotMs = Math.min(
    normalized.limits.docker_command_timeout_ms,
    normalized.limits.wall_time_ms,
  )
  const controllerSetupBudgetMs = SERVICE_PROOF_SETUP_DOCKER_SLOTS * dockerSlotMs
  const controllerCleanupReserveMs = SERVICE_PROOF_CLEANUP_DOCKER_SLOTS * dockerSlotMs
  const controllerActiveBudgetMs = controllerSetupBudgetMs
    + normalized.limits.wall_time_ms
  return deepFreeze({
    controller_session_budget_ms: controllerActiveBudgetMs
      + controllerCleanupReserveMs,
    controller_active_budget_ms: controllerActiveBudgetMs,
    controller_cleanup_reserve_ms: controllerCleanupReserveMs,
  })
}

export function buildProofDockerCreateArgs(config, containerName) {
  const normalized = normalizeProofWorkerConfig(config)
  const args = buildDockerCreateArgs(providerProfile(normalized), containerName)
  const image = args.pop()
  return [
    ...args,
    '--env=CI=1',
    `--env=PATH=${PROOF_CONTAINER_PATH}`,
    '--entrypoint=/usr/local/bin/node',
    image,
    '-e',
    PROOF_HOLD_SOURCE,
  ]
}

function normalizeServiceProofInput(service, limits, worker) {
  if (service === null || typeof service !== 'object' || Array.isArray(service)) {
    throw new Error('service proof configuration is invalid: service must be an object')
  }
  const serviceKeys = Object.keys(service)
  const allowedServiceKeys = new Set([
    'protocol', 'command', 'port', 'startup_timeout_ms', 'probe_interval_ms',
  ])
  if (serviceKeys.some((key) => !allowedServiceKeys.has(key))) {
    throw new Error('service proof configuration is invalid: service contains an unknown field')
  }
  if (service.protocol !== SERVICE_PROOF_PROTOCOL) {
    throw new Error(`service proof configuration is invalid: protocol must be ${SERVICE_PROOF_PROTOCOL}`)
  }
  if (
    service.command === null
    || typeof service.command !== 'object'
    || Array.isArray(service.command)
    || Object.keys(service.command).some((key) => !['program', 'args'].includes(key))
  ) {
    throw new Error('service proof configuration is invalid: service command must be exact')
  }
  const serviceProgram = FIXED_PROGRAMS[service.command.program]
  if (!serviceProgram) {
    throw new Error(
      `unsupported service proof program ${JSON.stringify(service.command.program)}`,
    )
  }
  if (
    !Array.isArray(service.command.args)
    || service.command.args.some((arg) => typeof arg !== 'string')
  ) {
    throw new Error('service proof command args must be strings')
  }
  if (!Number.isInteger(service.port) || service.port < 1_024 || service.port > 65_535) {
    throw new Error('service proof configuration is invalid: port must be from 1024 through 65535')
  }
  if (
    !Number.isInteger(service.startup_timeout_ms)
    || service.startup_timeout_ms < 100
    || service.startup_timeout_ms > 120_000
  ) {
    throw new Error(
      'service proof configuration is invalid: startup_timeout_ms must be from 100 through 120000',
    )
  }
  if (
    !Number.isInteger(service.probe_interval_ms)
    || service.probe_interval_ms < 1
    || service.probe_interval_ms > 10_000
    || service.probe_interval_ms > service.startup_timeout_ms
  ) {
    throw new Error(
      'service proof configuration is invalid: probe_interval_ms must be from 1 through 10000 and no greater than startup_timeout_ms',
    )
  }
  if (
    limits === null
    || typeof limits !== 'object'
    || Array.isArray(limits)
    || !Number.isInteger(limits.timeout_ms)
    || limits.timeout_ms < 100
    || !Number.isInteger(limits.max_output_bytes)
    || limits.max_output_bytes < 1
  ) {
    throw new Error('service proof configuration is invalid: proof limits are invalid')
  }
  if (service.startup_timeout_ms + limits.timeout_ms > worker.limits.wall_time_ms) {
    throw new Error(
      'service proof configuration is invalid: startup and proof timeouts exceed worker wall time',
    )
  }
  return deepFreeze({
    service: structuredClone(service),
    serviceProgram,
    supervisorTtlMs: worker.limits.wall_time_ms,
  })
}

function buildServiceProofDockerCreateArgs(
  config,
  containerName,
  normalizedService,
) {
  const normalized = normalizeProofWorkerConfig(config)
  const args = buildDockerCreateArgs(
    providerProfile(normalized),
    containerName,
    SERVICE_CONTAINER_IDENTITY,
  ).map((arg) => {
    if (arg === '--env=HOME=/work') return `--env=HOME=${SERVICE_RUNTIME_ROOT}`
    if (arg === '--env=TMPDIR=/work') return `--env=TMPDIR=${SERVICE_RUNTIME_ROOT}`
    return arg
  })
  const image = args.pop()
  const { service, serviceProgram, supervisorTtlMs } = normalizedService
  return [
    ...args,
    `--label=${SERVICE_PROOF_CONTAINER_NAME_LABEL}=${containerName}`,
    `--label=${SERVICE_PROOF_PROTOCOL_LABEL}=${SERVICE_PROOF_PROTOCOL}`,
    `--label=${SERVICE_PROOF_WORKER_CONFIG_LABEL}=${proofWorkerConfigDigest(normalized)}`,
    '--init',
    '--rm',
    '--env=CI=1',
    `--env=PATH=${PROOF_CONTAINER_PATH}`,
    `--env=XDG_CACHE_HOME=${SERVICE_RUNTIME_ROOT}/.cache`,
    `--env=npm_config_cache=${SERVICE_RUNTIME_ROOT}/.npm`,
    `--env=RTA_SERVICE_HOST=${SERVICE_HOST}`,
    `--env=RTA_SERVICE_PORT=${service.port}`,
    '--entrypoint=/usr/local/bin/node',
    image,
    '-e',
    SERVICE_PROOF_SUPERVISOR_SOURCE,
    SERVICE_MARKER_PATH,
    String(supervisorTtlMs),
    '/work/repo',
    serviceProgram,
    ...service.command.args,
  ]
}

function assertHardenedServiceProofInspection(
  inspection,
  config,
  containerName,
  expectedCommand,
  expectedPort,
  { running = false } = {},
) {
  const normalized = normalizeProofWorkerConfig(config)
  let containerId
  try {
    containerId = assertHardenedDockerInspection(
      inspection,
      providerProfile(normalized),
      containerName,
      SERVICE_CONTAINER_IDENTITY,
    )
  } catch (error) {
    fail(error.message)
  }
  if (inspection.Image !== normalized.image) fail('container image identity drifted')
  const labels = inspection.Config?.Labels
  if (
    labels === null
    || typeof labels !== 'object'
    || Array.isArray(labels)
    || labels[SERVICE_PROOF_CONTAINER_NAME_LABEL] !== containerName
    || labels[SERVICE_PROOF_PROTOCOL_LABEL] !== SERVICE_PROOF_PROTOCOL
    || labels[SERVICE_PROOF_WORKER_CONFIG_LABEL] !== proofWorkerConfigDigest(normalized)
  ) {
    fail('service proof recovery identity labels drifted')
  }
  if (
    JSON.stringify(inspection.Config?.Entrypoint) !== JSON.stringify(['/usr/local/bin/node'])
    || JSON.stringify(inspection.Config?.Cmd) !== JSON.stringify(expectedCommand)
  ) {
    fail('controller service supervisor command drifted')
  }
  if (inspection.HostConfig?.Init !== true) {
    fail('container init supervisor is not enabled')
  }
  const environment = environmentMap(inspection.Config?.Env)
  if (environment.get('CI') !== '1') fail('CI environment is not fixed')
  if (environment.get('PATH') !== PROOF_CONTAINER_PATH) {
    fail('container executable path is not controller-owned')
  }
  if (environment.get('RTA_SERVICE_HOST') !== SERVICE_HOST) {
    fail('service host is not fixed to literal loopback')
  }
  if (environment.get('RTA_SERVICE_PORT') !== String(expectedPort)) {
    fail('service port does not match the sealed service configuration')
  }
  if (
    environment.get('HOME') !== SERVICE_RUNTIME_ROOT
    || environment.get('TMPDIR') !== SERVICE_RUNTIME_ROOT
    || environment.get('XDG_CACHE_HOME') !== `${SERVICE_RUNTIME_ROOT}/.cache`
    || environment.get('npm_config_cache') !== `${SERVICE_RUNTIME_ROOT}/.npm`
  ) {
    fail('service runtime paths are not confined to controller-owned scratch space')
  }
  if (inspection.HostConfig?.AutoRemove !== true) {
    fail('service proof container auto-removal is not enabled')
  }
  const allowedEnvironment = new Set([
    'ALL_PROXY', 'CI', 'HOME', 'HTTP_PROXY', 'HTTPS_PROXY', 'NODE_VERSION',
    'NO_COLOR', 'NO_PROXY', 'PATH', 'RTA_SERVICE_HOST', 'RTA_SERVICE_PORT',
    'TMPDIR', 'XDG_CACHE_HOME', 'YARN_VERSION', 'all_proxy', 'http_proxy',
    'https_proxy', 'no_proxy', 'npm_config_cache',
  ])
  for (const key of environment.keys()) {
    if (!allowedEnvironment.has(key)) fail(`image environment contains forbidden key ${key}`)
  }
  if (running) {
    const state = inspection.State ?? {}
    if (
      state.Running !== true
      || state.Paused === true
      || state.Restarting === true
      || state.Dead === true
      || state.OOMKilled === true
    ) {
      fail('service proof container is not in the expected running state')
    }
    const networks = Object.keys(inspection.NetworkSettings?.Networks ?? {})
    if (networks.length !== 1 || networks[0] !== 'none') {
      fail('service proof container has a network other than none')
    }
    if (Object.keys(inspection.NetworkSettings?.Ports ?? {}).length !== 0) {
      fail('service proof container exposes a port')
    }
  }
  return containerId
}

function fail(message) {
  throw new Error(`proof Docker profile mismatch: ${message}`)
}

function environmentMap(entries) {
  return new Map((entries ?? []).map((entry) => {
    const separator = entry.indexOf('=')
    return separator < 0
      ? [entry, undefined]
      : [entry.slice(0, separator), entry.slice(separator + 1)]
  }))
}

export function assertHardenedProofInspection(inspection, config, containerName) {
  const normalized = normalizeProofWorkerConfig(config)
  let containerId
  try {
    containerId = assertHardenedDockerInspection(
      inspection,
      providerProfile(normalized),
      containerName,
    )
  } catch (error) {
    fail(error.message)
  }
  if (inspection.Image !== normalized.image) fail('container image identity drifted')
  if (
    JSON.stringify(inspection.Config?.Entrypoint) !== JSON.stringify(['/usr/local/bin/node'])
    || JSON.stringify(inspection.Config?.Cmd) !== JSON.stringify(['-e', PROOF_HOLD_SOURCE])
  ) {
    fail('controller hold entrypoint drifted')
  }
  const environment = environmentMap(inspection.Config?.Env)
  if (environment.get('CI') !== '1') fail('CI environment is not fixed')
  if (environment.get('PATH') !== PROOF_CONTAINER_PATH) {
    fail('container executable path is not controller-owned')
  }
  const allowedEnvironment = new Set([
    'ALL_PROXY', 'CI', 'HOME', 'HTTP_PROXY', 'HTTPS_PROXY', 'NODE_VERSION',
    'NO_COLOR', 'NO_PROXY', 'PATH', 'TMPDIR', 'YARN_VERSION', 'all_proxy',
    'http_proxy', 'https_proxy', 'no_proxy',
  ])
  for (const key of environment.keys()) {
    if (!allowedEnvironment.has(key)) fail(`image environment contains forbidden key ${key}`)
  }
  return containerId
}

function parseJson(text, label) {
  try {
    return JSON.parse(String(text).trim())
  } catch (error) {
    throw new Error(`${label} did not return valid JSON: ${error.message}`)
  }
}

function sanitizedDockerEnvironment(dockerConfigRoot) {
  const environment = {}
  for (const key of [
    'COMSPEC', 'PATH', 'PATHEXT', 'SystemRoot', 'SYSTEMROOT', 'TEMP', 'TMP',
    'WINDIR', 'windir',
  ]) {
    if (process.env[key] !== undefined) environment[key] = process.env[key]
  }
  environment.DOCKER_CONFIG = dockerConfigRoot
  for (const key of [
    'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'ALL_PROXY',
    'http_proxy', 'https_proxy', 'no_proxy', 'all_proxy',
  ]) environment[key] = ''
  return environment
}

function sanitizeDiagnostic(value) {
  return String(value)
    .replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g, '')
    .replace(/\x1b(?:[@-_]|\[[0-?]*[ -/]*[@-~])/g, '')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '\uFFFD')
}

function dockerControlError(message, outcome) {
  const error = new Error(message)
  error.docker_outcome = outcome
  return error
}

async function runDockerCli(runtimePath, args, options = {}) {
  const {
    allowNonZero = false,
    cwd,
    dockerConfigRoot,
    maxOutputBytes = 1024 * 1024,
    spawnImpl = nodeSpawn,
    timeoutMs = 30_000,
  } = options
  return await new Promise((resolve, reject) => {
    let child
    try {
      child = spawnImpl(runtimePath, args, {
        cwd,
        shell: false,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
        env: sanitizedDockerEnvironment(dockerConfigRoot),
      })
    } catch (error) {
      reject(dockerControlError(
        `could not start the controller Docker runtime: ${error.message}`,
        'NOT_STARTED',
      ))
      return
    }
    const stdout = []
    const stderr = []
    let stdoutBytes = 0
    let stderrBytes = 0
    let settled = false
    let timer
    const finish = (callback) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      callback()
    }
    const collect = (target, name) => (chunkValue) => {
      const chunk = Buffer.isBuffer(chunkValue) ? chunkValue : Buffer.from(chunkValue)
      if (name === 'stdout') stdoutBytes += chunk.length
      else stderrBytes += chunk.length
      if (stdoutBytes + stderrBytes > maxOutputBytes) {
        child.kill?.('SIGKILL')
        finish(() => reject(dockerControlError(
          'Docker control command exceeded its output limit',
          'UNKNOWN',
        )))
        return
      }
      target.push(chunk)
    }
    child.stdout.on('data', collect(stdout, 'stdout'))
    child.stderr.on('data', collect(stderr, 'stderr'))
    child.once('error', (error) => finish(() => reject(dockerControlError(
      `could not start the controller Docker runtime: ${error.message}`,
      'NOT_STARTED',
    ))))
    child.once('close', (code, signal) => finish(() => {
      const stderrText = sanitizeDiagnostic(Buffer.concat(stderr).toString('utf8'))
      if (code !== 0 && !allowNonZero) {
        reject(dockerControlError(
          `Docker control command failed with code ${String(code)} `
          + `signal ${String(signal)}: ${stderrText}`,
          'TERMINAL',
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
    if (settled) return
    timer = setTimeout(() => {
      child.kill?.('SIGKILL')
      finish(() => reject(dockerControlError(
        `Docker control command exceeded its ${timeoutMs}ms timeout`,
        'UNKNOWN',
      )))
    }, timeoutMs)
    timer.unref?.()
  })
}

function emptyDigest() {
  return createHash('sha256').digest('hex')
}

async function runBoundedDockerTarget(runtimePath, args, options = {}) {
  const {
    dockerConfigRoot,
    maxOutputBytes,
    spawnImpl = nodeSpawn,
    timeoutMs,
  } = options
  const started = Date.now()
  return await new Promise((resolve) => {
    let child
    const stdoutHash = createHash('sha256')
    const stderrHash = createHash('sha256')
    let stdoutBytes = 0
    let stderrBytes = 0
    let settled = false
    let stdoutTruncated = false
    let stderrTruncated = false
    let timer
    const finish = (result) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      child?.kill?.('SIGKILL')
      resolve({
        code: result.code,
        signal: result.signal ?? null,
        timed_out: result.timed_out === true,
        spawn_error: result.spawn_error === true,
        duration_ms: Date.now() - started,
        stdout: '',
        stderr: '',
        stdout_bytes: stdoutBytes,
        stdout_sha256: stdoutBytes === 0 ? emptyDigest() : stdoutHash.digest('hex'),
        stdout_truncated: stdoutTruncated,
        stderr_bytes: stderrBytes,
        stderr_sha256: stderrBytes === 0 ? emptyDigest() : stderrHash.digest('hex'),
        stderr_truncated: stderrTruncated,
        output_omitted: true,
      })
    }
    try {
      child = spawnImpl(runtimePath, args, {
        shell: false,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
        env: sanitizedDockerEnvironment(dockerConfigRoot),
      })
    } catch {
      finish({ code: 127, spawn_error: true })
      return
    }
    const observe = (hash, name) => (chunkValue) => {
      if (settled) return
      const chunk = Buffer.isBuffer(chunkValue) ? chunkValue : Buffer.from(chunkValue)
      hash.update(chunk)
      if (name === 'stdout') stdoutBytes += chunk.length
      else stderrBytes += chunk.length
      if (stdoutBytes + stderrBytes > maxOutputBytes) {
        if (name === 'stdout') stdoutTruncated = true
        else stderrTruncated = true
        finish({ code: 125, signal: 'SIGKILL' })
      }
    }
    child.stdout.on('data', observe(stdoutHash, 'stdout'))
    child.stderr.on('data', observe(stderrHash, 'stderr'))
    child.once('error', () => finish({ code: 127, spawn_error: true }))
    child.once('close', (code, signal) => finish({ code: code ?? 1, signal }))
    if (settled) return
    timer = setTimeout(() => finish({
      code: 124,
      signal: 'SIGKILL',
      timed_out: true,
    }), timeoutMs)
    timer.unref?.()
  })
}

/**
 * Stream a controller-created relative archive into the already-inspected
 * container tmpfs. Both executables and every argument are fixed or validated;
 * no shell, host mount, or daemon-side `docker cp` path is involved.
 */
export async function transferProofSourceArchive(options) {
  const {
    containerName,
    dockerConfigRoot,
    dockerRuntimePath,
    maxSourceBytes,
    sourceRoot,
    spawnImpl = nodeSpawn,
    timeoutMs,
  } = options
  if (!CONTAINER_NAME.test(containerName)) throw new Error('invalid proof container name')
  if (dockerRuntimePath !== CONTROLLER_DOCKER_RUNTIME) {
    throw new Error('proof archive transfer requires the controller Docker runtime')
  }
  if (typeof sourceRoot !== 'string' || !isAbsolute(sourceRoot)) {
    throw new Error('proof archive source must be an absolute local directory')
  }
  const maxArchiveBytes = Math.min(
    maxSourceBytes + 64 * 1024 * 1024,
    1024 * 1024 * 1024,
  )
  const stderrLimit = 64 * 1024
  return await new Promise((resolve, reject) => {
    let archiver
    let extractor
    let archiveBytes = 0
    let extractorStdoutBytes = 0
    let stderrBytes = 0
    let archiverExit
    let extractorExit
    let settled = false
    let timer
    const stop = () => {
      archiver?.stdout?.unpipe?.(extractor?.stdin)
      extractor?.stdin?.destroy?.()
      archiver?.kill?.('SIGKILL')
      extractor?.kill?.('SIGKILL')
    }
    const failTransfer = (message) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      stop()
      reject(new Error(message))
    }
    const maybeFinish = () => {
      if (settled || !archiverExit || !extractorExit) return
      if (
        archiverExit.code !== 0
        || extractorExit.code !== 0
        || extractorStdoutBytes !== 0
      ) {
        failTransfer('bounded proof source archive transfer failed')
        return
      }
      settled = true
      clearTimeout(timer)
      resolve({ archive_bytes: archiveBytes })
    }
    const childOptions = (stdio, environment, cwd) => ({
      cwd,
      shell: false,
      windowsHide: true,
      stdio,
      env: environment,
    })
    try {
      extractor = spawnImpl(
        dockerRuntimePath,
        [
          ...DOCKER_PREFIX,
          'container', 'exec', '--interactive', '--user=65532:65532',
          containerName,
          '/bin/tar', '-xf', '-', '-C', '/work/repo',
        ],
        childOptions(
          ['pipe', 'pipe', 'pipe'],
          sanitizedDockerEnvironment(dockerConfigRoot),
        ),
      )
      extractor.stdout.on('data', (chunkValue) => {
        const chunk = Buffer.isBuffer(chunkValue) ? chunkValue : Buffer.from(chunkValue)
        extractorStdoutBytes += chunk.length
        if (extractorStdoutBytes > stderrLimit) {
          failTransfer('proof archive extractor exceeded its output limit')
        }
      })
      extractor.stderr.on('data', (chunkValue) => {
        const chunk = Buffer.isBuffer(chunkValue) ? chunkValue : Buffer.from(chunkValue)
        stderrBytes += chunk.length
        if (stderrBytes > stderrLimit) {
          failTransfer('proof archive transfer exceeded its diagnostic limit')
        }
      })
      extractor.once('error', () => failTransfer('could not start proof archive extractor'))
      extractor.once('close', (code, signal) => {
        extractorExit = { code, signal }
        maybeFinish()
      })
      if (settled) return

      archiver = spawnImpl(
        CONTROLLER_ARCHIVE_RUNTIME,
        ['-cf', '-', '.'],
        childOptions(
          ['ignore', 'pipe', 'pipe'],
          sanitizedDockerEnvironment(dockerConfigRoot),
          sourceRoot,
        ),
      )
      archiver.stdout.on('data', (chunkValue) => {
        const chunk = Buffer.isBuffer(chunkValue) ? chunkValue : Buffer.from(chunkValue)
        archiveBytes += chunk.length
        if (archiveBytes > maxArchiveBytes) {
          failTransfer('proof source archive exceeded its bounded size')
        }
      })
      archiver.stderr.on('data', (chunkValue) => {
        const chunk = Buffer.isBuffer(chunkValue) ? chunkValue : Buffer.from(chunkValue)
        stderrBytes += chunk.length
        if (stderrBytes > stderrLimit) {
          failTransfer('proof archive transfer exceeded its diagnostic limit')
        }
      })
      archiver.once('error', () => failTransfer('could not start controller archive runtime'))
      archiver.once('close', (code, signal) => {
        archiverExit = { code, signal }
        maybeFinish()
      })
      extractor.stdin.once('error', () => {
        if (!extractorExit) failTransfer('proof archive extractor input failed')
      })
      archiver.stdout.once('error', () => failTransfer('proof archive output failed'))
      archiver.stdout.pipe(extractor.stdin)
      if (settled) return
      timer = setTimeout(() => {
        failTransfer(`proof archive transfer exceeded its ${timeoutMs}ms timeout`)
      }, timeoutMs)
      timer.unref?.()
    } catch {
      failTransfer('could not start bounded proof archive transfer')
    }
  })
}

function parseJsonLines(text, label) {
  const values = []
  for (const [index, line] of String(text).split(/\r?\n/).entries()) {
    if (line.length === 0) continue
    values.push(parseJson(line, `${label} line ${index + 1}`))
  }
  return values
}

async function exactContainerState(command, containerName) {
  const inspected = await command([
    ...DOCKER_PREFIX,
    'container', 'inspect', '--format', '{{json .}}', containerName,
  ], { allowNonZero: true })
  if (inspected.code === 0) {
    const inspection = parseJson(inspected.stdout, 'Docker exact container inspection')
    if (inspection?.Name !== containerName && inspection?.Name !== `/${containerName}`) {
      fail('exact container inspection returned the wrong name')
    }
    return 'PRESENT'
  }
  const listed = await command([
    ...DOCKER_PREFIX,
    'container', 'ls', '--all', '--no-trunc',
    `--filter=name=^/${containerName}$`, '--format', '{{json .Names}}',
  ])
  const names = parseJsonLines(listed.stdout, 'Docker exact container listing')
  if (names.some((name) => name !== containerName && name !== `/${containerName}`)) {
    fail('exact container listing returned an unexpected name')
  }
  return names.length === 0 ? 'ABSENT' : 'PRESENT'
}

async function verifyAbsent(command, containerName) {
  if (await exactContainerState(command, containerName) !== 'ABSENT') {
    fail('container remained after cleanup')
  }
}

async function exactContainerIdState(command, immutableContainerId) {
  if (!CONTAINER_ID.test(immutableContainerId)) {
    fail('immutable proof container ID is invalid')
  }
  const inspected = await command([
    ...DOCKER_PREFIX,
    'container', 'inspect', '--format', '{{json .}}', immutableContainerId,
  ], { allowNonZero: true })
  if (inspected.code === 0) {
    const inspection = parseJson(inspected.stdout, 'Docker immutable container inspection')
    if (inspection?.Id !== immutableContainerId) {
      fail('immutable container inspection returned the wrong ID')
    }
    return 'PRESENT'
  }
  const listed = await command([
    ...DOCKER_PREFIX,
    'container', 'ls', '--all', '--no-trunc',
    `--filter=id=${immutableContainerId}`, '--format', '{{json .ID}}',
  ])
  const ids = parseJsonLines(listed.stdout, 'Docker immutable container listing')
  if (ids.some((id) => id !== immutableContainerId)) {
    fail('immutable container listing returned an unexpected ID')
  }
  return ids.length === 0 ? 'ABSENT' : 'PRESENT'
}

async function verifyCleanupIdentitiesAbsent(command, containerName, immutableContainerId) {
  const failures = []
  if (immutableContainerId !== undefined && immutableContainerId !== null) {
    try {
      if (await exactContainerIdState(command, immutableContainerId) !== 'ABSENT') {
        fail('immutable container remained after cleanup')
      }
    } catch (error) {
      failures.push(error)
    }
  }
  try {
    await verifyAbsent(command, containerName)
  } catch (error) {
    failures.push(error)
  }
  if (failures.length > 0) {
    throw new AggregateError(
      failures,
      'immutable container ID and leased name absence could not both be verified',
    )
  }
}

async function assertInitiallyAbsent(command, containerName) {
  if (await exactContainerState(command, containerName) !== 'ABSENT') {
    fail('an exact-name proof container already exists')
  }
}

async function cleanupContainer(command, containerName, immutableContainerId) {
  if (immutableContainerId !== undefined && !CONTAINER_ID.test(immutableContainerId)) {
    fail('immutable proof container ID is required for ID-bound cleanup')
  }
  const cleanupTarget = immutableContainerId ?? containerName
  const cleanupFailures = []
  for (const args of [
    [...DOCKER_PREFIX, 'container', 'kill', '--signal=KILL', cleanupTarget],
    [...DOCKER_PREFIX, 'container', 'rm', '--force', '--volumes', cleanupTarget],
  ]) {
    try {
      const outcome = await command(args, { allowNonZero: true })
      if (outcome.code !== 0) cleanupFailures.push(args.includes('kill') ? 'kill' : 'remove')
    } catch {
      cleanupFailures.push(args.includes('kill') ? 'kill' : 'remove')
    }
  }
  try {
    await verifyCleanupIdentitiesAbsent(command, containerName, immutableContainerId)
  } catch (error) {
    const stages = cleanupFailures.length === 0
      ? ''
      : ` after ${cleanupFailures.join(' and ')} failure`
    const cleanupError = new Error(
      `could not prove the exact proof container absent after cleanup${stages}: ${error.message}`,
    )
    cleanupError.container_name = containerName
    cleanupError.cleanup_verified = false
    throw cleanupError
  }
}

function normalizeServiceProofContainerNames(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('service proof recovery container names must be an exact object')
  }
  const keys = Object.keys(value).sort()
  if (keys.length !== 2 || keys[0] !== 'attack' || keys[1] !== 'control') {
    throw new Error('service proof recovery container names must contain exactly attack and control')
  }
  if (!CONTAINER_NAME.test(value.attack) || !CONTAINER_NAME.test(value.control)) {
    throw new Error('service proof recovery container names are invalid')
  }
  if (value.attack === value.control) {
    throw new Error('service proof recovery container names must be distinct')
  }
  return deepFreeze({ attack: value.attack, control: value.control })
}

function recoveryCleanupStageError(stage, containerName, outcome) {
  const error = new Error(
    `service proof recovery ${stage} did not report success for the exact container`,
  )
  error.container_name = containerName
  error.lifecycle_phase = stage
  error.docker_outcome = outcome?.docker_outcome
    ?? (Number.isInteger(outcome?.code) ? 'TERMINAL' : 'UNKNOWN')
  return error
}

async function inspectRecoveryContainer(
  command,
  containerName,
  config,
  normalizedService,
) {
  const inspected = await command([
    ...DOCKER_PREFIX,
    'container', 'inspect', '--format', '{{json .}}', containerName,
  ], { allowNonZero: true })
  if (inspected.code === 0) {
    const inspection = parseJson(
      inspected.stdout,
      'Docker service-proof recovery container inspection',
    )
    const createArgs = buildServiceProofDockerCreateArgs(
      config,
      containerName,
      normalizedService,
    )
    const imageIndex = createArgs.indexOf(config.image)
    const expectedSupervisorCommand = createArgs.slice(imageIndex + 1)
    return {
      containerName,
      containerId: assertHardenedServiceProofInspection(
        inspection,
        config,
        containerName,
        expectedSupervisorCommand,
        normalizedService.service.port,
      ),
    }
  }
  const listed = await command([
    ...DOCKER_PREFIX,
    'container', 'ls', '--all', '--no-trunc',
    `--filter=name=^/${containerName}$`, '--format', '{{json .Names}}',
  ])
  const names = parseJsonLines(
    listed.stdout,
    'Docker service-proof recovery exact container listing',
  )
  if (names.some((name) => name !== containerName && name !== `/${containerName}`)) {
    fail('service-proof recovery listing returned an unexpected name')
  }
  if (names.length > 0) {
    fail('exact-name recovery container exists but its immutable identity was not inspectable')
  }
  return { containerName, containerId: null }
}

async function cleanupRecoveryContainer(command, containerName, containerId) {
  const stageFailures = []
  if (containerId !== null) {
    for (const [stage, args] of [
      ['kill', [...DOCKER_PREFIX, 'container', 'kill', '--signal=KILL', containerId]],
      ['remove', [
        ...DOCKER_PREFIX, 'container', 'rm', '--force', '--volumes', containerId,
      ]],
    ]) {
      try {
        const outcome = await command(args, { allowNonZero: true })
        if (outcome.code !== 0) {
          stageFailures.push(recoveryCleanupStageError(stage, containerName, outcome))
        }
      } catch (error) {
        const cause = error instanceof Error ? error : new Error(String(error))
        cause.container_name ??= containerName
        cause.lifecycle_phase ??= stage
        stageFailures.push(cause)
      }
    }
  }
  try {
    await verifyCleanupIdentitiesAbsent(command, containerName, containerId)
  } catch (error) {
    const cause = error instanceof Error ? error : new Error(String(error))
    cause.container_name ??= containerName
    cause.lifecycle_phase ??= 'verify_absent'
    const failure = new AggregateError(
      [...stageFailures, cause],
      'service proof recovery could not prove one exact container absent',
    )
    failure.container_name = containerName
    failure.cleanup_verified = false
    throw failure
  }
}

function serviceProofRecoveryCleanupFailure(causes) {
  const failure = new AggregateError(
    causes.map((cause) => cause instanceof Error ? cause : new Error(String(cause))),
    'service proof recovery cleanup could not be verified',
  )
  failure.code = 'SERVICE_PROOF_RECOVERY_CLEANUP_UNVERIFIED'
  failure.cleanup_verified = false
  failure.evidence = {
    verification_status: 'UNPROVEN',
    blocking_reason: 'service proof recovery cleanup could not be verified',
    cleanup_verified: false,
  }
  return failure
}

/**
 * Recover an expired two-container service-proof attempt. Both exact leased
 * names are always processed, and each must be positively absent before the
 * recovery controller may issue a replacement lease.
 */
export async function cleanupDockerServiceProofContainers(options) {
  const config = normalizeProofWorkerConfig(options?.config)
  const serviceContainerNames = normalizeServiceProofContainerNames(
    options?.serviceContainerNames,
  )
  const normalizedService = normalizeServiceProofInput(
    options?.service,
    options?.limits,
    config,
  )
  if (options.command !== undefined && typeof options.command !== 'function') {
    throw new TypeError('command must be a function')
  }
  if (
    options.removeDockerConfigRoot !== undefined
    && typeof options.removeDockerConfigRoot !== 'function'
  ) {
    throw new TypeError('removeDockerConfigRoot must be a function')
  }
  const monotonicNow = options.monotonicNow ?? (() => performance.now())
  const removeDockerConfigRoot = options.removeDockerConfigRoot ?? rm
  const dockerSlotMs = Math.min(
    config.limits.docker_command_timeout_ms,
    config.limits.wall_time_ms,
  )
  const controllerCleanupBudgetMs = SERVICE_PROOF_RECOVERY_DOCKER_SLOTS
    * dockerSlotMs
  const causes = []
  let dockerConfigRoot
  let cleanupDeadline
  try {
    dockerConfigRoot = await mkdtemp(join(tmpdir(), 'rta-proof-docker-recovery-'))
    const baseCommand = options.command ?? ((args, overrides = {}) => runDockerCli(
      config.runtime_path,
      args,
      {
        dockerConfigRoot,
        spawnImpl: options.spawnImpl,
        timeoutMs: dockerSlotMs,
        ...overrides,
      },
    ))
    const cleanupStartedAt = serviceProofMonotonicNow(monotonicNow)
    cleanupDeadline = cleanupStartedAt + controllerCleanupBudgetMs
    const command = async (args, overrides = {}) => {
      const timeoutMs = boundedServiceControllerTimeout(
        overrides.timeoutMs,
        dockerSlotMs,
        cleanupDeadline,
        monotonicNow,
      )
      return settleWithinServiceControllerDeadline(
        () => baseCommand(args, { ...overrides, timeoutMs }),
        cleanupDeadline,
        monotonicNow,
      )
    }
    const context = await command([
      ...DOCKER_PREFIX, 'context', 'inspect', 'default',
      '--format', '{{json .Endpoints.docker.Host}}',
    ])
    assertLocalDockerContextHost(parseJson(
      context.stdout,
      'Docker service-proof recovery context inspection',
    ))
    const authenticatedContainers = []
    const identityFailures = []
    for (const containerName of [
      serviceContainerNames.attack,
      serviceContainerNames.control,
    ]) {
      try {
        authenticatedContainers.push(await inspectRecoveryContainer(
          command,
          containerName,
          config,
          normalizedService,
        ))
      } catch (error) {
        identityFailures.push(error)
      }
    }
    if (identityFailures.length > 0) {
      causes.push(...identityFailures)
    } else {
      for (const { containerName, containerId } of authenticatedContainers) {
        try {
          await cleanupRecoveryContainer(command, containerName, containerId)
        } catch (error) {
          causes.push(error)
        }
      }
    }
  } catch (error) {
    causes.push(error)
  } finally {
    if (dockerConfigRoot) {
      try {
        const removeConfigRoot = () => removeDockerConfigRoot(
          dockerConfigRoot,
          { recursive: true, force: true },
        )
        if (cleanupDeadline === undefined) {
          await removeConfigRoot()
        } else {
          await settleWithinServiceControllerDeadline(
            removeConfigRoot,
            cleanupDeadline,
            monotonicNow,
          )
        }
      } catch (error) {
        causes.push(error)
      }
    }
  }
  if (causes.length > 0) throw serviceProofRecoveryCleanupFailure(causes)
  return deepFreeze({
    service_container_names: structuredClone(serviceContainerNames),
    controller_cleanup_budget_ms: controllerCleanupBudgetMs,
    cleanup_verified: true,
  })
}

async function verifyFailedCreateAbsent(command, containerName) {
  try {
    await verifyAbsent(command, containerName)
  } catch (error) {
    const cleanupError = new Error(
      'could not prove the exact proof container absent after failed Docker create: '
      + error.message,
    )
    cleanupError.container_name = containerName
    cleanupError.cleanup_verified = false
    throw cleanupError
  }
}

async function sourceDependencyManifestDigest(sourceRoot, maxSourceBytes) {
  if (typeof sourceRoot !== 'string' || !isAbsolute(sourceRoot)) {
    throw new Error('proof sourceRoot must be an absolute local directory')
  }
  const rootStat = await lstat(sourceRoot)
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    throw new Error('proof sourceRoot must be a regular local directory')
  }
  const bytes = []
  let totalBytes = 0
  for (const name of DEPENDENCY_MANIFEST_FILES) {
    const path = join(sourceRoot, name)
    const fileStat = await lstat(path)
    if (!fileStat.isFile() || fileStat.isSymbolicLink()) {
      throw new Error(`proof source ${name} must be a regular file`)
    }
    totalBytes += fileStat.size
    if (totalBytes > maxSourceBytes) {
      throw new Error('proof dependency manifests exceed max_source_bytes')
    }
    bytes.push(await readFile(path))
  }
  return proofDependencyManifestDigest(...bytes)
}

function dependencyManifestHashArgs(containerName, paths) {
  return [
    ...DOCKER_PREFIX,
    'container', 'exec',
    '--user=65532:65532',
    containerName,
    '/usr/local/bin/node',
    '--input-type=commonjs',
    '-e',
    DEPENDENCY_MANIFEST_HASH_SOURCE,
    ...paths,
  ]
}

async function assertContainerDependencyManifest(
  command,
  containerName,
  paths,
  expectedDigest,
  label,
) {
  const result = await command(dependencyManifestHashArgs(containerName, paths))
  if (result.stdout !== expectedDigest) {
    fail(`${label} dependency manifest does not match the configured digest`)
  }
}

function proofWorktreeManifestArgs(containerName) {
  return [
    ...DOCKER_PREFIX,
    'container', 'exec',
    `--user=${SERVICE_STAGING_USER}`,
    '--workdir=/',
    containerName,
    '/usr/local/bin/node',
    '--input-type=commonjs',
    '-e',
    PROOF_WORKTREE_MANIFEST_SOURCE,
    '/work/repo',
    '65532',
  ]
}

async function assertContainerProofWorktree(
  command,
  containerName,
  expectedDigest,
  timeoutMs,
) {
  let result
  try {
    result = await command(
      proofWorktreeManifestArgs(containerName),
      { timeoutMs },
    )
  } catch {
    throw serviceProofFailure(
      'SERVICE_PROOF_SOURCE_INTEGRITY_MISMATCH',
      'sealed proof source integrity could not be verified',
    )
  }
  if (result.stdout !== expectedDigest) {
    throw serviceProofFailure(
      'SERVICE_PROOF_SOURCE_INTEGRITY_MISMATCH',
      'sealed proof source integrity did not match the controller manifest',
    )
  }
}

function unverifiedCreateOutcomeError(containerName) {
  const error = new Error(
    'Docker create did not reach a confirmed terminal outcome; '
    + 'present-time absence cannot exclude a late proof-container create',
  )
  error.container_name = containerName
  error.cleanup_verified = false
  error.create_outcome_verified = false
  return error
}

function unverifiedCreatedContainerIdentityError(containerName) {
  const error = new Error(
    'Docker create succeeded without a trusted immutable container ID; '
    + 'leased-name absence cannot exclude a renamed proof container',
  )
  error.container_name = containerName
  error.cleanup_verified = false
  error.container_identity_verified = false
  return error
}

/**
 * Execute one exact proof command in a fresh, network-denied container.
 * `sourceRoot` contains controller-materialized sealed bytes only. Docker copies
 * those bytes into tmpfs; the host directory is never mounted into the worker.
 */
export async function runDockerProofCommand(options) {
  const config = normalizeProofWorkerConfig(options.config)
  const fixedProgram = FIXED_PROGRAMS[options.program]
  if (!fixedProgram) {
    throw new Error(`unsupported proof program ${JSON.stringify(options.program)}`)
  }
  if (!Array.isArray(options.args) || options.args.some((arg) => typeof arg !== 'string')) {
    throw new Error('proof command args must be strings')
  }
  const containerName = options.containerName
    ?? `rta-proof-${randomUUID().replaceAll('-', '').toLowerCase()}`
  if (!CONTAINER_NAME.test(containerName)) throw new Error('invalid proof container name')
  const sourceManifestDigest = await sourceDependencyManifestDigest(
    options.sourceRoot,
    config.limits.max_source_bytes,
  )
  if (sourceManifestDigest !== config.dependency_manifest_sha256) {
    throw new Error(
      'source dependency manifest does not match the configured worker digest',
    )
  }
  let dockerConfigRoot
  const injected = typeof options.command === 'function'
  if (!injected) dockerConfigRoot = await mkdtemp(join(tmpdir(), 'rta-proof-docker-'))
  const command = options.command ?? ((args, overrides = {}) => runDockerCli(
    config.runtime_path,
    args,
    {
      dockerConfigRoot,
      spawnImpl: options.spawnImpl,
      timeoutMs: config.limits.docker_command_timeout_ms,
      ...overrides,
    },
  ))
  const execute = options.execute ?? ((args, overrides = {}) => runBoundedDockerTarget(
    config.runtime_path,
    args,
    {
      dockerConfigRoot,
      maxOutputBytes: Math.min(
        config.limits.max_output_bytes,
        options.limits?.max_output_bytes ?? config.limits.max_output_bytes,
      ),
      timeoutMs: Math.min(
        config.limits.wall_time_ms,
        options.limits?.timeout_ms ?? config.limits.wall_time_ms,
      ),
      spawnImpl: options.spawnImpl,
      ...overrides,
    },
  ))
  const transfer = options.transfer ?? transferProofSourceArchive
  let createAttempted = false
  let createOutcomeConfirmed = false
  let createOutcomeUnknown = false
  let result
  let primaryError
  let cleanupError
  let containerId
  try {
    const context = await command([
      ...DOCKER_PREFIX, 'context', 'inspect', 'default',
      '--format', '{{json .Endpoints.docker.Host}}',
    ])
    assertLocalDockerContextHost(parseJson(context.stdout, 'Docker context inspection'))
    const version = await command([
      ...DOCKER_PREFIX, 'version', '--format', '{{json .Server.Version}}',
    ])
    const runtimeVersion = parseJson(version.stdout, 'Docker version inspection')
    if (typeof runtimeVersion !== 'string' || runtimeVersion.length === 0) {
      fail('Docker server version is missing')
    }
    const image = parseJson((await command([
      ...DOCKER_PREFIX, 'image', 'inspect', '--format', '{{json .}}', config.image,
    ])).stdout, 'Docker image inspection')
    if (image?.Id !== config.image || image?.Os !== 'linux') {
      fail('worker image is not the configured immutable Linux image')
    }
    if (image.Config?.Labels?.[PROOF_WORKER_LABEL] !== config.protocol) {
      fail('worker image protocol label does not match the configured protocol')
    }
    if (image.Config?.Volumes && Object.keys(image.Config.Volumes).length > 0) {
      fail('worker image declares persistent volumes')
    }

    await assertInitiallyAbsent(command, containerName)
    createAttempted = true
    let created
    try {
      created = await command(buildProofDockerCreateArgs(config, containerName))
      createOutcomeConfirmed = true
    } catch (error) {
      createOutcomeUnknown = !['NOT_STARTED', 'TERMINAL'].includes(
        error?.docker_outcome,
      )
      throw error
    }
    containerId = String(created.stdout).trim()
    if (!CONTAINER_ID.test(containerId)) fail('Docker create returned an invalid container ID')
    const inspection = parseJson((await command([
      ...DOCKER_PREFIX, 'container', 'inspect', '--format', '{{json .}}', containerName,
    ])).stdout, 'Docker container inspection')
    if (assertHardenedProofInspection(inspection, config, containerName) !== containerId) {
      fail('container identity changed after create')
    }

    await command([...DOCKER_PREFIX, 'container', 'start', containerName])
    await assertContainerDependencyManifest(
      command,
      containerName,
      ['/opt/rta/package.json', '/opt/rta/package-lock.json'],
      config.dependency_manifest_sha256,
      'worker image',
    )
    await command([
      ...DOCKER_PREFIX, 'container', 'exec', '--user=65532:65532', containerName,
      '/bin/mkdir', '--mode=0700', '/work/repo',
    ])
    await transfer({
      containerName,
      dockerConfigRoot,
      dockerRuntimePath: config.runtime_path,
      maxSourceBytes: config.limits.max_source_bytes,
      sourceRoot: options.sourceRoot,
      spawnImpl: options.spawnImpl,
      timeoutMs: config.limits.docker_command_timeout_ms,
    })
    await command([
      ...DOCKER_PREFIX, 'container', 'exec', '--user=65532:65532', containerName,
      '/bin/chmod', '-R', 'u+rwX', '/work/repo',
    ])
    await command([
      ...DOCKER_PREFIX, 'container', 'exec', '--user=65532:65532', containerName,
      '/bin/ln', '-s', '/opt/rta/node_modules', '/work/repo/node_modules',
    ])
    await assertContainerDependencyManifest(
      command,
      containerName,
      ['/work/repo/package.json', '/work/repo/package-lock.json'],
      config.dependency_manifest_sha256,
      'copied source',
    )
    result = await execute([
      ...DOCKER_PREFIX,
      'container', 'exec',
      '--workdir=/work/repo',
      '--user=65532:65532',
      '--env=HOME=/work',
      '--env=TMPDIR=/work',
      '--env=CI=1',
      '--env=NO_COLOR=1',
      containerName,
      fixedProgram,
      ...options.args,
    ])
    result.sandbox = {
      backend: 'OCI_DOCKER',
      worker_config_sha256: proofWorkerConfigDigest(config),
      runtime_version: runtimeVersion,
      image: config.image,
      container_id: containerId,
      network_mode: 'none',
      mounts: [],
      environment: 'controller-minimal',
      cleanup_verified: false,
    }
  } catch (error) {
    primaryError = error
  } finally {
    if (createAttempted && (createOutcomeConfirmed || createOutcomeUnknown)) {
      try {
        await cleanupContainer(command, containerName)
      } catch (error) {
        cleanupError = error
      }
      if (createOutcomeUnknown && !cleanupError) {
        cleanupError = unverifiedCreateOutcomeError(containerName)
      }
    }
    if (dockerConfigRoot) {
      await rm(dockerConfigRoot, { recursive: true, force: true })
    }
  }
  if (cleanupError) {
    if (primaryError) cleanupError.primary_error = primaryError
    throw cleanupError
  }
  if (primaryError) throw primaryError
  result.sandbox.cleanup_verified = true
  return result
}

function serviceProofFailure(code, message) {
  const error = new Error(message)
  error.code = code
  error.evidence = {
    verification_status: 'UNPROVEN',
    blocking_reason: message,
    cleanup_verified: false,
  }
  return error
}

function serviceStartupTimeoutFailure() {
  return serviceProofFailure(
    'SERVICE_PROOF_STARTUP_READINESS_TIMEOUT',
    'service proof loopback readiness did not succeed before the startup timeout',
  )
}

function serviceProofWallTimeoutFailure() {
  return serviceProofFailure(
    'SERVICE_PROOF_WALL_TIMEOUT',
    'service proof exceeded its cumulative controller-session wall-clock budget',
  )
}

function serviceProofMonotonicNow(monotonicNow) {
  const now = monotonicNow()
  if (!Number.isFinite(now)) {
    throw serviceProofFailure(
      'SERVICE_PROOF_WALL_CLOCK_INVALID',
      'service proof controller clock did not return a finite monotonic value',
    )
  }
  return now
}

function remainingServiceControllerMs(deadline, monotonicNow) {
  const remaining = Math.floor(deadline - serviceProofMonotonicNow(monotonicNow))
  if (remaining <= 0) throw serviceProofWallTimeoutFailure()
  return remaining
}

async function settleWithinServiceControllerDeadline(operation, deadline, monotonicNow) {
  let result
  try {
    result = await operation()
  } catch (error) {
    remainingServiceControllerMs(deadline, monotonicNow)
    throw error
  }
  remainingServiceControllerMs(deadline, monotonicNow)
  return result
}

function boundedServiceControllerTimeout(
  requestedTimeoutMs,
  defaultTimeoutMs,
  deadline,
  monotonicNow,
) {
  const requested = Number.isFinite(requestedTimeoutMs)
    ? Math.max(1, Math.floor(requestedTimeoutMs))
    : defaultTimeoutMs
  return Math.max(1, Math.min(
    requested,
    defaultTimeoutMs,
    remainingServiceControllerMs(deadline, monotonicNow),
  ))
}

function remainingServiceStartupMs(deadline, monotonicNow) {
  const now = monotonicNow()
  if (!Number.isFinite(now)) {
    throw serviceProofFailure(
      'SERVICE_PROOF_STARTUP_CLOCK_INVALID',
      'service proof startup clock did not return a finite monotonic value',
    )
  }
  const remaining = Math.floor(deadline - now)
  if (remaining <= 0) throw serviceStartupTimeoutFailure()
  return remaining
}

function typedServiceProofFailure(error, fallbackCode) {
  const typed = error instanceof Error ? error : new Error(String(error))
  if (typeof typed.code !== 'string' || !typed.code.startsWith('SERVICE_PROOF_')) {
    if (typeof typed.code === 'string') typed.cause_code = typed.code
    typed.code = fallbackCode
  }
  if (
    typed.evidence === null
    || typeof typed.evidence !== 'object'
    || Array.isArray(typed.evidence)
  ) {
    typed.evidence = {
      verification_status: 'UNPROVEN',
      blocking_reason: typed.message,
      cleanup_verified: false,
    }
  }
  return typed
}

function controllerTempCleanupFailure(removalError, primaryError, cleanupError) {
  const removalCause = removalError instanceof Error
    ? removalError
    : new Error(String(removalError))
  const causes = [primaryError, cleanupError, removalCause].filter(Boolean)
  const failure = new AggregateError(
    causes,
    'controller Docker configuration temporary-directory cleanup could not be verified',
  )
  failure.code = 'SERVICE_PROOF_CONTROLLER_TEMP_CLEANUP_FAILED'
  failure.cleanup_verified = false
  failure.evidence = {
    verification_status: 'UNPROVEN',
    blocking_reason: 'controller temporary-directory cleanup could not be verified',
    cleanup_verified: false,
  }
  if (primaryError) failure.primary_error = primaryError
  if (cleanupError) failure.container_cleanup_error = cleanupError
  return failure
}

function attachPartialServiceResult(error, result) {
  if (
    result === null
    || result === undefined
    || error === null
    || (typeof error !== 'object' && typeof error !== 'function')
  ) return
  error.partial_result = {
    ...structuredClone(result),
    stdout: '',
    stderr: '',
    output_omitted: true,
  }
}

function loopbackProbeArgs(containerName, port, probeTimeoutMs) {
  return [
    ...DOCKER_PREFIX,
    'container', 'exec',
    '--user=65534:65534',
    '--workdir=/',
    containerName,
    '/usr/local/bin/node',
    '-e',
    LOOPBACK_PROBE_SOURCE,
    SERVICE_HOST,
    String(port),
    String(probeTimeoutMs),
  ]
}

function targetServiceCommandArgs(containerName, fixedProgram, args, port) {
  return [
    ...DOCKER_PREFIX,
    'container', 'exec',
    '--workdir=/work/repo',
    `--user=${SERVICE_RUNTIME_USER}`,
    `--env=HOME=${SERVICE_RUNTIME_ROOT}`,
    `--env=TMPDIR=${SERVICE_RUNTIME_ROOT}`,
    `--env=XDG_CACHE_HOME=${SERVICE_RUNTIME_ROOT}/.cache`,
    `--env=npm_config_cache=${SERVICE_RUNTIME_ROOT}/.npm`,
    '--env=CI=1',
    '--env=NO_COLOR=1',
    `--env=RTA_SERVICE_HOST=${SERVICE_HOST}`,
    `--env=RTA_SERVICE_PORT=${port}`,
    containerName,
    fixedProgram,
    ...args,
  ]
}

async function inspectRunningServiceContainer(
  command,
  containerName,
  config,
  expectedCommand,
  expectedPort,
  expectedContainerId,
  timeoutMs,
) {
  const inspection = parseJson((await command([
    ...DOCKER_PREFIX, 'container', 'inspect', '--format', '{{json .}}', containerName,
  ], timeoutMs === undefined ? {} : { timeoutMs })).stdout,
  'Docker running service container inspection')
  if (
    assertHardenedServiceProofInspection(
      inspection,
      config,
      containerName,
      expectedCommand,
      expectedPort,
      { running: true },
    ) !== expectedContainerId
  ) {
    fail('service proof container identity changed while running')
  }
}

/**
 * Execute one exact proof command against a service booted inside the same
 * fresh, network-none container. The controller PID1 waits on a marker until
 * source custody and manifest checks finish; only then may it start the sealed
 * service command. Attack and control callers invoke this function separately,
 * so they never share service state.
 */
export async function runDockerServiceProofCommand(options) {
  const config = normalizeProofWorkerConfig(options.config)
  const fixedProgram = FIXED_PROGRAMS[options.program]
  if (!fixedProgram) {
    throw new Error(`unsupported proof program ${JSON.stringify(options.program)}`)
  }
  if (!Array.isArray(options.args) || options.args.some((arg) => typeof arg !== 'string')) {
    throw new Error('proof command args must be strings')
  }
  const normalizedService = normalizeServiceProofInput(
    options.service,
    options.limits,
    config,
  )
  const { service, supervisorTtlMs } = normalizedService
  const containerName = options.containerName
    ?? `rta-proof-service-${randomUUID().replaceAll('-', '').toLowerCase()}`
  if (!CONTAINER_NAME.test(containerName)) throw new Error('invalid proof container name')
  const sourceManifestDigest = await sourceDependencyManifestDigest(
    options.sourceRoot,
    config.limits.max_source_bytes,
  )
  if (sourceManifestDigest !== config.dependency_manifest_sha256) {
    throw new Error(
      'source dependency manifest does not match the configured worker digest',
    )
  }
  const sourceTreeDigest = await proofSourceTreeDigest(
    options.sourceRoot,
    config.limits.max_source_bytes,
  )

  const createArgs = buildServiceProofDockerCreateArgs(
    config,
    containerName,
    normalizedService,
  )
  const imageIndex = createArgs.indexOf(config.image)
  const expectedSupervisorCommand = createArgs.slice(imageIndex + 1)
  const maxOutputBytes = Math.min(
    config.limits.max_output_bytes,
    options.limits.max_output_bytes,
  )
  const probeTimeoutMs = Math.max(1, Math.min(
    1_000,
    service.startup_timeout_ms,
    config.limits.docker_command_timeout_ms,
  ))
  const monotonicNow = options.monotonicNow ?? (() => performance.now())
  const baseSleep = options.sleep ?? ((milliseconds) => new Promise((resolve) => {
    setTimeout(resolve, milliseconds)
  }))

  let dockerConfigRoot
  const injected = typeof options.command === 'function'
  if (
    options.removeDockerConfigRoot !== undefined
    && typeof options.removeDockerConfigRoot !== 'function'
  ) {
    throw new TypeError('removeDockerConfigRoot must be a function')
  }
  const removeDockerConfigRoot = options.removeDockerConfigRoot ?? rm
  if (!injected || options.removeDockerConfigRoot) {
    dockerConfigRoot = await mkdtemp(join(tmpdir(), 'rta-proof-docker-'))
  }
  const baseCommand = options.command ?? ((args, overrides = {}) => runDockerCli(
    config.runtime_path,
    args,
    {
      dockerConfigRoot,
      spawnImpl: options.spawnImpl,
      timeoutMs: Math.min(
        config.limits.docker_command_timeout_ms,
        config.limits.wall_time_ms,
      ),
      ...overrides,
    },
  ))
  const baseExecute = options.execute ?? ((args, overrides = {}) => runBoundedDockerTarget(
    config.runtime_path,
    args,
    {
      dockerConfigRoot,
      maxOutputBytes,
      timeoutMs: Math.min(config.limits.wall_time_ms, options.limits.timeout_ms),
      spawnImpl: options.spawnImpl,
      ...overrides,
    },
  ))
  const baseTransfer = options.transfer ?? transferProofSourceArchive
  const controllerBudget = serviceProofControllerBudget(config)
  const controllerStartedAt = serviceProofMonotonicNow(monotonicNow)
  const controllerActiveDeadline = controllerStartedAt
    + controllerBudget.controller_active_budget_ms
  const controllerSessionDeadline = controllerStartedAt
    + controllerBudget.controller_session_budget_ms
  const dockerOperationTimeoutMs = Math.min(
    config.limits.docker_command_timeout_ms,
    config.limits.wall_time_ms,
  )
  let controllerCleanupPhase = false
  const controllerDeadline = () => (
    controllerCleanupPhase ? controllerSessionDeadline : controllerActiveDeadline
  )
  const command = async (args, overrides = {}) => {
    const deadline = controllerDeadline()
    const timeoutMs = boundedServiceControllerTimeout(
      overrides.timeoutMs,
      dockerOperationTimeoutMs,
      deadline,
      monotonicNow,
    )
    return settleWithinServiceControllerDeadline(
      () => baseCommand(args, { ...overrides, timeoutMs }),
      deadline,
      monotonicNow,
    )
  }
  const execute = async (args, overrides = {}) => {
    const deadline = controllerDeadline()
    const timeoutMs = boundedServiceControllerTimeout(
      overrides.timeoutMs,
      Math.min(config.limits.wall_time_ms, options.limits.timeout_ms),
      deadline,
      monotonicNow,
    )
    return settleWithinServiceControllerDeadline(
      () => baseExecute(args, { ...overrides, timeoutMs }),
      deadline,
      monotonicNow,
    )
  }
  const transfer = async (transferOptions = {}) => {
    const deadline = controllerDeadline()
    const timeoutMs = boundedServiceControllerTimeout(
      transferOptions.timeoutMs,
      dockerOperationTimeoutMs,
      deadline,
      monotonicNow,
    )
    return settleWithinServiceControllerDeadline(
      () => baseTransfer({ ...transferOptions, timeoutMs }),
      deadline,
      monotonicNow,
    )
  }
  const sleep = async (milliseconds) => {
    const deadline = controllerActiveDeadline
    const boundedMilliseconds = Math.min(
      Math.max(1, Math.floor(milliseconds)),
      remainingServiceControllerMs(deadline, monotonicNow),
    )
    return settleWithinServiceControllerDeadline(
      () => baseSleep(boundedMilliseconds),
      deadline,
      monotonicNow,
    )
  }

  const probe = (budgetMs = service.startup_timeout_ms) => {
    const boundedBudgetMs = Math.max(1, Math.floor(Math.min(
      service.startup_timeout_ms,
      budgetMs,
    )))
    const boundedProbeTimeoutMs = Math.min(probeTimeoutMs, boundedBudgetMs)
    return execute(
      loopbackProbeArgs(containerName, service.port, boundedProbeTimeoutMs),
      {
        timeoutMs: Math.min(boundedBudgetMs, boundedProbeTimeoutMs + 250),
        maxOutputBytes,
      },
    )
  }
  const recheck = (containerId, timeoutMs) => inspectRunningServiceContainer(
    command,
    containerName,
    config,
    expectedSupervisorCommand,
    service.port,
    containerId,
    timeoutMs,
  )

  let createAttempted = false
  let createOutcomeConfirmed = false
  let createOutcomeUnknown = false
  let result
  let primaryError
  let cleanupError
  let controllerTempError
  let cleanupVerified = false
  let containerId
  let reportedContainerId
  let runtimeVersion
  try {
    const context = await command([
      ...DOCKER_PREFIX, 'context', 'inspect', 'default',
      '--format', '{{json .Endpoints.docker.Host}}',
    ])
    assertLocalDockerContextHost(parseJson(context.stdout, 'Docker context inspection'))
    const version = await command([
      ...DOCKER_PREFIX, 'version', '--format', '{{json .Server.Version}}',
    ])
    runtimeVersion = parseJson(version.stdout, 'Docker version inspection')
    if (typeof runtimeVersion !== 'string' || runtimeVersion.length === 0) {
      fail('Docker server version is missing')
    }
    const image = parseJson((await command([
      ...DOCKER_PREFIX, 'image', 'inspect', '--format', '{{json .}}', config.image,
    ])).stdout, 'Docker image inspection')
    if (image?.Id !== config.image || image?.Os !== 'linux') {
      fail('worker image is not the configured immutable Linux image')
    }
    if (image.Config?.Labels?.[PROOF_WORKER_LABEL] !== config.protocol) {
      fail('worker image protocol label does not match the configured protocol')
    }
    if (image.Config?.Volumes && Object.keys(image.Config.Volumes).length > 0) {
      fail('worker image declares persistent volumes')
    }

    await assertInitiallyAbsent(command, containerName)
    createAttempted = true
    let created
    try {
      created = await command(createArgs)
      createOutcomeConfirmed = true
    } catch (error) {
      createOutcomeUnknown = !['NOT_STARTED', 'TERMINAL'].includes(
        error?.docker_outcome,
      )
      throw error
    }
    reportedContainerId = String(created.stdout).trim()
    if (!CONTAINER_ID.test(reportedContainerId)) {
      reportedContainerId = undefined
      fail('Docker create returned an invalid container ID')
    }
    const createdInspection = parseJson((await command([
      ...DOCKER_PREFIX, 'container', 'inspect', '--format', '{{json .}}', containerName,
    ])).stdout, 'Docker service container inspection')
    const inspectedContainerId = assertHardenedServiceProofInspection(
      createdInspection,
      config,
      containerName,
      expectedSupervisorCommand,
      service.port,
    )
    if (inspectedContainerId !== reportedContainerId) {
      fail('container identity changed after create')
    }
    containerId = inspectedContainerId

    await command([...DOCKER_PREFIX, 'container', 'start', containerName])
    await assertContainerDependencyManifest(
      command,
      containerName,
      ['/opt/rta/package.json', '/opt/rta/package-lock.json'],
      config.dependency_manifest_sha256,
      'worker image',
    )
    await command([
      ...DOCKER_PREFIX, 'container', 'exec', '--user=65532:65532', containerName,
      '/bin/mkdir', '--mode=0700', '/work/repo',
    ])
    await command([
      ...DOCKER_PREFIX, 'container', 'exec', `--user=${SERVICE_STAGING_USER}`, containerName,
      '/bin/mkdir', '--mode=0777', SERVICE_RUNTIME_ROOT,
    ])
    await command([
      ...DOCKER_PREFIX, 'container', 'exec', `--user=${SERVICE_STAGING_USER}`, containerName,
      '/bin/chmod', '0777', SERVICE_RUNTIME_ROOT,
    ])
    await transfer({
      containerName,
      dockerConfigRoot,
      dockerRuntimePath: config.runtime_path,
      maxSourceBytes: config.limits.max_source_bytes,
      sourceRoot: options.sourceRoot,
      spawnImpl: options.spawnImpl,
      timeoutMs: Math.min(
        config.limits.docker_command_timeout_ms,
        config.limits.wall_time_ms,
      ),
    })
    await command([
      ...DOCKER_PREFIX, 'container', 'exec', '--user=65532:65532', containerName,
      '/bin/chmod', '-R', 'u+rwX', '/work/repo',
    ])
    await command([
      ...DOCKER_PREFIX, 'container', 'exec', '--user=65532:65532', containerName,
      '/bin/ln', '-s', '/opt/rta/node_modules', '/work/repo/node_modules',
    ])
    await assertContainerDependencyManifest(
      command,
      containerName,
      ['/work/repo/package.json', '/work/repo/package-lock.json'],
      config.dependency_manifest_sha256,
      'copied source',
    )

    await command([
      ...DOCKER_PREFIX, 'container', 'exec', `--user=${SERVICE_STAGING_USER}`, containerName,
      '/bin/chmod', '-R', 'a-w,a+rX', '/work/repo',
    ])
    await assertContainerProofWorktree(
      command,
      containerName,
      sourceTreeDigest,
      config.limits.docker_command_timeout_ms,
    )

    await recheck(containerId)
    const preBoot = await probe()
    if (preBoot.code !== 1 || preBoot.timed_out || preBoot.spawn_error) {
      throw serviceProofFailure(
        'SERVICE_PROOF_PRE_BOOT_PORT_OPEN',
        'service proof loopback port was open or could not be proven closed before boot',
      )
    }

    const readinessDeadline = monotonicNow() + service.startup_timeout_ms
    const markerBudgetMs = remainingServiceStartupMs(readinessDeadline, monotonicNow)
    await command([
      ...DOCKER_PREFIX, 'container', 'exec', `--user=${SERVICE_STAGING_USER}`, containerName,
      '/bin/touch', SERVICE_MARKER_PATH,
    ], {
      timeoutMs: Math.min(config.limits.docker_command_timeout_ms, markerBudgetMs),
    })

    let ready = false
    while (!ready) {
      const recheckBudgetMs = remainingServiceStartupMs(
        readinessDeadline,
        monotonicNow,
      )
      await recheck(
        containerId,
        Math.min(config.limits.docker_command_timeout_ms, recheckBudgetMs),
      )
      const probeBudgetMs = remainingServiceStartupMs(readinessDeadline, monotonicNow)
      const readiness = await probe(probeBudgetMs)
      const remainingAfterProbeMs = remainingServiceStartupMs(
        readinessDeadline,
        monotonicNow,
      )
      if (readiness.code === 3) {
        throw serviceProofFailure(
          'SERVICE_PROOF_STARTUP_BINDING_INVALID',
          'service proof listener was not bound exclusively to literal IPv4 loopback',
        )
      }
      ready = readiness.code === 0
        && readiness.timed_out !== true
        && readiness.spawn_error !== true
      if (ready) break
      await sleep(Math.min(service.probe_interval_ms, remainingAfterProbeMs))
    }

    await recheck(containerId)
    await assertContainerProofWorktree(
      command,
      containerName,
      sourceTreeDigest,
      config.limits.docker_command_timeout_ms,
    )
    result = await execute(
      targetServiceCommandArgs(
        containerName,
        fixedProgram,
        options.args,
        service.port,
      ),
      {
        timeoutMs: Math.min(config.limits.wall_time_ms, options.limits.timeout_ms),
        maxOutputBytes,
      },
    )
    await assertContainerProofWorktree(
      command,
      containerName,
      sourceTreeDigest,
      config.limits.docker_command_timeout_ms,
    )
    await recheck(containerId)
    const postProbe = await probe()
    if (postProbe.code === 3) {
      throw serviceProofFailure(
        'SERVICE_PROOF_POST_PROBE_BINDING_INVALID',
        'service proof listener was no longer bound exclusively to literal IPv4 loopback',
      )
    }
    if (
      postProbe.code !== 0
      || postProbe.timed_out === true
      || postProbe.spawn_error === true
    ) {
      throw serviceProofFailure(
        'SERVICE_PROOF_POST_PROBE_NOT_READY',
        'service proof loopback readiness was lost after the target probe',
      )
    }
    result.sandbox = {
      backend: 'OCI_DOCKER',
      worker_config_sha256: proofWorkerConfigDigest(config),
      runtime_version: runtimeVersion,
      image: config.image,
      container_id: containerId,
      network_mode: 'none',
      mounts: [],
      environment: 'controller-minimal',
      service: {
        protocol: service.protocol,
        host: SERVICE_HOST,
        port: service.port,
        supervisor_ttl_ms: supervisorTtlMs,
        controller_session_budget_ms: controllerBudget.controller_session_budget_ms,
        controller_active_budget_ms: controllerBudget.controller_active_budget_ms,
        controller_cleanup_reserve_ms: controllerBudget.controller_cleanup_reserve_ms,
        pre_boot_closed: true,
        pre_probe_ready: true,
        post_probe_ready: true,
        source_immutable: true,
        source_tree_sha256: sourceTreeDigest,
        runtime_root: SERVICE_RUNTIME_ROOT,
        output_omitted: true,
      },
      cleanup_verified: false,
    }
  } catch (error) {
    primaryError = typedServiceProofFailure(
      error,
      'SERVICE_PROOF_EXECUTION_UNPROVEN',
    )
  } finally {
    controllerCleanupPhase = true
    if (createAttempted) {
      try {
        if (createOutcomeConfirmed || createOutcomeUnknown) {
          // A strict ID returned by our successful create is an immutable
          // cleanup handle even when the first name-based inspection races a
          // rename. Never let later leased-name absence discard that handle.
          let cleanupContainerId = containerId ?? reportedContainerId
          if (cleanupContainerId === undefined) {
            const authenticated = await inspectRecoveryContainer(
              command,
              containerName,
              config,
              normalizedService,
            )
            cleanupContainerId = authenticated.containerId
          }
          if (cleanupContainerId !== null) {
            await cleanupContainer(command, containerName, cleanupContainerId)
          } else if (createOutcomeConfirmed) {
            throw unverifiedCreatedContainerIdentityError(containerName)
          }
        } else {
          await verifyFailedCreateAbsent(command, containerName)
        }
        cleanupVerified = true
      } catch (error) {
        cleanupError = typedServiceProofFailure(
          error,
          'SERVICE_PROOF_CLEANUP_UNVERIFIED',
        )
      }
      if (createOutcomeUnknown && !cleanupError) {
        cleanupError = typedServiceProofFailure(
          unverifiedCreateOutcomeError(containerName),
          'SERVICE_PROOF_CREATE_OUTCOME_UNVERIFIED',
        )
      }
    }
    if (dockerConfigRoot) {
      try {
        await settleWithinServiceControllerDeadline(
          () => removeDockerConfigRoot(
            dockerConfigRoot,
            { recursive: true, force: true },
          ),
          controllerSessionDeadline,
          monotonicNow,
        )
      } catch (error) {
        controllerTempError = controllerTempCleanupFailure(
          error,
          primaryError,
          cleanupError,
        )
      }
    }
  }
  if (controllerTempError) throw controllerTempError
  if (cleanupError) {
    attachPartialServiceResult(cleanupError, result)
    if (primaryError) cleanupError.primary_error = primaryError
    throw cleanupError
  }
  if (primaryError) {
    attachPartialServiceResult(primaryError, result)
    primaryError.evidence.cleanup_verified = cleanupVerified
    throw primaryError
  }
  result.sandbox.cleanup_verified = true
  return result
}
