import { spawn } from 'node:child_process'
import { accessSync, constants as fsConstants, existsSync, readFileSync, statSync } from 'node:fs'
import { open, realpath, stat } from 'node:fs/promises'
import { delimiter, dirname, isAbsolute, join, resolve } from 'node:path'
import { createHash } from 'node:crypto'
import { runWindowsJobProcess, sanitizedProcessEnvironment } from './reverse-process.mjs'

// On Windows many CLIs ship only as a .cmd/.bat shim, which execFile cannot
// launch without `shell: true` — and this runner never uses a shell, because a
// shell turns an argument vector back into an injectable string.
const SHELL_SHIM_EXTENSIONS = ['.cmd', '.bat']
const MAX_SHIM_BYTES = 64 * 1024
const MAX_CLI_IDENTITY_BYTES = 256 * 1024 * 1024
const CLI_IDENTITY_READ_BYTES = 64 * 1024
const MAX_CLI_IDENTITY_CACHE_ENTRIES = 128
const cliIdentityDigestCache = new Map()
const CLI_PROBE_TIMEOUT_MS = 15_000
const CLI_PROBE_OUTPUT_CAPS = Object.freeze({
  maxStdoutBytes: 64 * 1024,
  maxStderrBytes: 16 * 1024,
  maxTotalOutputBytes: 64 * 1024,
})

function findShellShim(name, env) {
  if (process.platform !== 'win32') return null
  const path = env?.PATH ?? env?.Path ?? ''
  for (const directory of String(path).split(delimiter)) {
    if (!directory) continue
    for (const extension of SHELL_SHIM_EXTENSIONS) {
      const candidate = join(directory, `${name}${extension}`)
      if (existsSync(candidate)) return candidate
    }
  }
  return null
}

/**
 * An npm-generated `.cmd` shim is a wrapper whose last line names exactly the
 * node invocation it performs:
 *
 *   ... & "%_prog%" --no-deprecation "%dp0%\node_modules\pkg\bin\run.js" %*
 *
 * Reading that line lets the CLI be launched as `node <flags> <entry> <args>`
 * with no shell at all — strictly safer than `shell: true`, because the
 * argument vector is never re-parsed as a command string.
 *
 * Fail-closed by construction: anything that does not match this exact shape,
 * or whose entry script is not on disk, resolves to null and the caller keeps
 * refusing. It is not a general `.bat` interpreter and must not become one.
 *
 * Trust: this executes the script the shim points at. That is the same script
 * the shim itself would have run, so it introduces no boundary that invoking
 * the CLI did not already cross — an attacker who can rewrite entries on your
 * PATH already decides what `sf` means.
 */
export function resolveNodeShim(shimPath) {
  let text
  try {
    if (statSync(shimPath).size > MAX_SHIM_BYTES) return null
    text = readFileSync(shimPath, 'utf8')
  } catch {
    return null
  }

  const invocation = /"%_prog%"([^\r\n]*?)%\*/.exec(text)
  if (!invocation) return null

  const directory = dirname(shimPath)
  const tokens = [...invocation[1].matchAll(/"([^"]+)"|(\S+)/g)]
    .map((match) => (match[1] ?? match[2]).replaceAll('%dp0%', directory))
  if (tokens.length === 0) return null

  const entry = tokens.find((token) => /\.[cm]?js$/i.test(token))
  if (!entry || !existsSync(entry)) return null
  // Every token before the entry is a node flag; a stray %VAR% means the shim
  // depends on shell expansion we are deliberately not performing.
  if (tokens.some((token) => token.includes('%'))) return null

  return { file: process.execPath, prefixArgs: tokens }
}

export const DEFAULT_CLI_LIMITS = Object.freeze({
  timeoutMs: 120000,
  maxStdoutBytes: 256 * 1024 * 1024,
  maxStderrBytes: 16 * 1024 * 1024,
  maxTotalOutputBytes: 256 * 1024 * 1024,
  maxCommands: 64,
  maxObjects: 4096,
})

export class CliUnavailableError extends Error {
  constructor(name, reason) {
    super(`${name} not found on PATH: ${reason}`)
    this.name = 'CliUnavailableError'
    this.cli = name
    this.reason = reason
  }
}

export class ImpactCapExceededError extends Error {
  constructor(dimension, value, cap) {
    super(`acquisition halted: ${dimension} reached ${value}, above its cap of ${cap}`)
    this.name = 'ImpactCapExceededError'
    this.dimension = dimension
    this.value = value
    this.cap = cap
  }
}

function assertNonNegativeSafeInteger(value, label, { positive = false } = {}) {
  if (!Number.isSafeInteger(value) || value < (positive ? 1 : 0)) {
    throw new RangeError(`${label} must be a ${positive ? 'positive' : 'non-negative'} safe integer`)
  }
  return value
}

export function validateCliLimits(limits) {
  const effective = { ...DEFAULT_CLI_LIMITS, ...limits }
  assertNonNegativeSafeInteger(effective.timeoutMs, 'timeoutMs', { positive: true })
  for (const name of [
    'maxStdoutBytes',
    'maxStderrBytes',
    'maxTotalOutputBytes',
    'maxCommands',
    'maxObjects',
  ]) {
    assertNonNegativeSafeInteger(effective[name], name)
  }
  return effective
}

/**
 * Commands executed, bytes read, and distinct objects touched, each capped.
 * These exist for read-only classes too: an unbounded read against production
 * is an availability risk regardless of intent.
 */
export class ImpactCounters {
  constructor({ maxCommands, maxObjects, maxBytes }) {
    assertNonNegativeSafeInteger(maxCommands, 'maxCommands')
    assertNonNegativeSafeInteger(maxObjects, 'maxObjects')
    assertNonNegativeSafeInteger(maxBytes, 'maxBytes')
    this.caps = { commands: maxCommands, objects_touched: maxObjects, bytes_read: maxBytes }
    this.counters = { commands: 0, bytes_read: 0, objects_touched: 0 }
  }

  record({ commands = 0, bytes = 0, objects = 0 } = {}) {
    this.assertCanRecord({ commands, bytes, objects })
    this.counters.commands += commands
    this.counters.bytes_read += bytes
    this.counters.objects_touched += objects
    return this
  }

  recordReadCapViolation(bytes) {
    assertNonNegativeSafeInteger(bytes, 'bytes')
    const remaining = this.caps.bytes_read - this.counters.bytes_read
    if (bytes <= remaining) {
      this.counters.bytes_read += bytes
      return this
    }
    // A pipe read can cross a configured cap by one OS-delivered chunk. Keep a
    // bounded cap+1 sentinel so failure evidence cannot claim that zero bytes
    // were read, without retaining or accounting an attacker-sized value.
    this.counters.bytes_read = this.caps.bytes_read === Number.MAX_SAFE_INTEGER
      ? Number.MAX_SAFE_INTEGER
      : this.caps.bytes_read + 1
    return this
  }

  recordObjectCapViolation(objects) {
    assertNonNegativeSafeInteger(objects, 'objects')
    const observed = this.counters.objects_touched + objects
    if (observed <= this.caps.objects_touched) {
      this.counters.objects_touched = observed
      return this
    }
    // Collection observers stop the producer at the first object beyond the
    // bound. Retain only a bounded cap+1 sentinel, just as byte-limit failures
    // do, so the durable impact record cannot claim that no objects were seen.
    this.counters.objects_touched = this.caps.objects_touched === Number.MAX_SAFE_INTEGER
      ? Number.MAX_SAFE_INTEGER
      : this.caps.objects_touched + 1
    return this
  }

  assertCanRecord({ commands = 0, bytes = 0, objects = 0 } = {}) {
    assertNonNegativeSafeInteger(commands, 'commands')
    assertNonNegativeSafeInteger(bytes, 'bytes')
    assertNonNegativeSafeInteger(objects, 'objects')
    const next = {
      commands: this.counters.commands + commands,
      bytes_read: this.counters.bytes_read + bytes,
      objects_touched: this.counters.objects_touched + objects,
    }
    for (const [dimension, value] of Object.entries(next)) {
      const cap = this.caps[dimension]
      if (value > cap) {
        throw new ImpactCapExceededError(dimension, value, cap)
      }
    }
    return this
  }

  assertWithinCaps() {
    for (const [dimension, value] of Object.entries(this.counters)) {
      const cap = this.caps[dimension]
      if (value > cap) {
        throw new ImpactCapExceededError(dimension, value, cap)
      }
    }
    return this
  }

  snapshot() {
    return { ...this.counters, caps: { ...this.caps } }
  }
}

// The default resolver runs the named binary as it stands on PATH. Tests
// inject a resolver so a stub process can stand in without a shell — a .cmd
// shim would require `shell: true`, which this runner never uses.
function executableCandidate(path) {
  try {
    if (!statSync(path).isFile()) return null
    if (process.platform !== 'win32') accessSync(path, fsConstants.X_OK)
    return resolve(path)
  } catch {
    return null
  }
}

function resolveNativeExecutable(name, env) {
  const direct = isAbsolute(name) || /[\\/]/.test(name)
  const directories = direct ? [''] : String(env?.PATH ?? env?.Path ?? '').split(delimiter)
  const extensions = process.platform === 'win32'
    ? (/\.[A-Za-z0-9]+$/.test(name) ? [''] : ['.exe', '.com'])
    : ['']
  for (const directory of directories) {
    const base = direct ? name : join(String(directory).replace(/^"|"$/g, ''), name)
    for (const extension of extensions) {
      const found = executableCandidate(`${base}${extension}`)
      if (found) return found
    }
  }
  return null
}

const identityResolver = (file, args, env) => ({
  file: resolveNativeExecutable(file, env) ?? file,
  args,
})

function sameFileSnapshot(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs
}

function identityMismatch() {
  const error = new Error('CLI executable identity no longer matches the immutable plan')
  error.code = 'EVIDENCE_CLI_IDENTITY_MISMATCH'
  return error
}

function invocationFileMetadata(metadata) {
  return {
    device: String(metadata.dev),
    inode: String(metadata.ino),
    size: Number(metadata.size),
    mtime_ns: String(metadata.mtimeNs),
    ctime_ns: String(metadata.ctimeNs),
  }
}

async function fingerprintInvocationFile(path, remainingBytes) {
  const requestedPath = resolve(path)
  const canonicalPath = await realpath(requestedPath)
  const before = await stat(canonicalPath, { bigint: true })
  if (!before.isFile()) throw new Error(`CLI identity path is not a regular file: ${requestedPath}`)
  if (before.size > BigInt(remainingBytes)) {
    throw new RangeError(
      `CLI invocation identity exceeds its aggregate bound of ${MAX_CLI_IDENTITY_BYTES} bytes`,
    )
  }
  const size = Number(before.size)
  const metadata = invocationFileMetadata(before)
  const cacheKey = JSON.stringify([canonicalPath, metadata])
  const cachedDigest = cliIdentityDigestCache.get(cacheKey)
  if (cachedDigest !== undefined) {
    const after = await stat(canonicalPath, { bigint: true })
    if (sameFileSnapshot(before, after) && await realpath(requestedPath) === canonicalPath) {
      return {
        requested_path: requestedPath,
        canonical_path: canonicalPath,
        ...metadata,
        sha256: cachedDigest,
      }
    }
    throw identityMismatch()
  }
  const handle = await open(
    canonicalPath,
    fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0),
  )
  const hash = createHash('sha256')
  const chunk = Buffer.allocUnsafe(Math.min(CLI_IDENTITY_READ_BYTES, Math.max(1, size)))
  try {
    const openedBefore = await handle.stat({ bigint: true })
    if (!openedBefore.isFile() || !sameFileSnapshot(before, openedBefore)) throw identityMismatch()
    let offset = 0
    while (offset < size) {
      const wanted = Math.min(chunk.length, size - offset)
      const { bytesRead } = await handle.read(chunk, 0, wanted, offset)
      if (bytesRead < 1) throw identityMismatch()
      hash.update(chunk.subarray(0, bytesRead))
      offset += bytesRead
    }
    const openedAfter = await handle.stat({ bigint: true })
    const after = await stat(canonicalPath, { bigint: true })
    if (!sameFileSnapshot(openedBefore, openedAfter) || !sameFileSnapshot(openedAfter, after)) {
      throw identityMismatch()
    }
    if (await realpath(requestedPath) !== canonicalPath) throw identityMismatch()
  } finally {
    chunk.fill(0)
    await handle.close()
  }
  const digest = hash.digest('hex')
  cliIdentityDigestCache.set(cacheKey, digest)
  if (cliIdentityDigestCache.size > MAX_CLI_IDENTITY_CACHE_ENTRIES) {
    cliIdentityDigestCache.delete(cliIdentityDigestCache.keys().next().value)
  }
  return {
    requested_path: requestedPath,
    canonical_path: canonicalPath,
    ...metadata,
    sha256: digest,
  }
}

async function invocationFileCandidates(invocation) {
  const candidates = [{ role: 'executable', index: null, path: invocation.file }]
  for (const [index, value] of invocation.argument_prefix.entries()) {
    if (typeof value !== 'string' || value === '' || value.startsWith('-')) continue
    const candidate = resolve(value)
    try {
      if (!(await stat(candidate)).isFile()) continue
    } catch (error) {
      if (error?.code === 'ENOENT' || error?.code === 'ENOTDIR') continue
      throw error
    }
    candidates.push({ role: 'argument', index, path: candidate })
  }
  return candidates
}

/**
 * Bind the executable plus every existing file named by its fixed argument
 * prefix. This covers interpreter-backed CLIs without guessing one language's
 * script extension, and keeps the total identity read bounded.
 */
export async function captureCliInvocationIdentity(invocation, {
  maxBytes = MAX_CLI_IDENTITY_BYTES,
} = {}) {
  if (invocation === null || typeof invocation !== 'object' || Array.isArray(invocation)
    || typeof invocation.file !== 'string' || !Array.isArray(invocation.argument_prefix)) {
    throw new TypeError('CLI invocation identity needs one executable and argument prefix')
  }
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    throw new RangeError('CLI invocation identity maxBytes must be a positive safe integer')
  }
  const candidates = await invocationFileCandidates(invocation)

  const files = []
  const cached = new Map()
  let totalBytes = 0
  for (const candidate of candidates) {
    const resolvedPath = resolveNativeExecutable(candidate.path, sanitizedProcessEnvironment())
      ?? candidate.path
    const cacheKey = resolve(resolvedPath)
    let fingerprint = cached.get(cacheKey)
    if (!fingerprint) {
      fingerprint = await fingerprintInvocationFile(resolvedPath, maxBytes - totalBytes)
      cached.set(cacheKey, fingerprint)
      totalBytes += fingerprint.size
    }
    files.push({ role: candidate.role, index: candidate.index, ...fingerprint })
  }
  return Object.freeze({
    schema_version: 1,
    total_bytes: totalBytes,
    files: Object.freeze(files.map((file) => Object.freeze(file))),
  })
}

function assertExpectedInvocationIdentity(actual, expected) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw identityMismatch()
}

async function assertCurrentInvocationSnapshot(invocation, expected) {
  if (expected?.schema_version !== 1 || !Array.isArray(expected.files)) throw identityMismatch()
  const candidates = await invocationFileCandidates(invocation)
  if (candidates.length !== expected.files.length) throw identityMismatch()
  for (let index = 0; index < candidates.length; index += 1) {
    const candidate = candidates[index]
    const sealed = expected.files[index]
    const resolvedPath = resolveNativeExecutable(candidate.path, sanitizedProcessEnvironment())
      ?? candidate.path
    const requestedPath = resolve(resolvedPath)
    const canonicalPath = await realpath(requestedPath)
    const metadata = await stat(canonicalPath, { bigint: true })
    if (!metadata.isFile()
      || candidate.role !== sealed.role
      || candidate.index !== sealed.index
      || requestedPath !== sealed.requested_path
      || canonicalPath !== sealed.canonical_path
      || JSON.stringify(invocationFileMetadata(metadata)) !== JSON.stringify({
        device: sealed.device,
        inode: sealed.inode,
        size: sealed.size,
        mtime_ns: sealed.mtime_ns,
        ctime_ns: sealed.ctime_ns,
      })) {
      throw identityMismatch()
    }
  }
}

/**
 * Resolves a CLI that exists only as an npm shim into a direct node
 * invocation. Returns null when there is no shim, or when the shim is not one
 * this resolver understands — in which case the caller keeps refusing, and
 * `shimPath` still lets it say why.
 */
function resolveShimInvocation(name, args, env) {
  const shimPath = findShellShim(name, env)
  if (!shimPath) return { shimPath: null, resolved: null }
  const shim = resolveNodeShim(shimPath)
  if (!shim) return { shimPath, resolved: null }
  return { shimPath, resolved: { file: shim.file, args: [...shim.prefixArgs, ...args] } }
}

async function spawnBoundedWindows(file, args, options, caps, stdoutObserver) {
  let result
  try {
    result = await runWindowsJobProcess({
      file,
      args,
      cwd: options.cwd ?? process.cwd(),
      env: options.env,
      timeoutMs: options.timeout,
      maxOutputBytes: caps.maxTotalOutputBytes,
      maxStdoutBytes: caps.maxStdoutBytes,
      maxStderrBytes: caps.maxStderrBytes,
      stdoutObserver,
    })
  } catch (error) {
    return {
      error,
      stdout: Buffer.isBuffer(error?.capturedStdout) ? error.capturedStdout : Buffer.alloc(0),
      stderr: Buffer.isBuffer(error?.capturedStderr) ? error.capturedStderr : Buffer.alloc(0),
      termination_confirmed: false,
      supervision_mode: 'WINDOWS_JOB_OBJECT',
    }
  }
  if (result.spawn_error) {
    const error = new Error('Windows Job Object supervision could not start the CLI')
    error.code = isAbsolute(file) ? 'EVIDENCE_CLI_SUPERVISION_FAILED' : 'ENOENT'
    return {
      error, stdout: result.stdout, stderr: result.stderr,
      termination_confirmed: false, supervision_mode: 'WINDOWS_JOB_OBJECT',
    }
  }
  if (!result.termination_confirmed) {
    const error = new Error('CLI process-tree termination could not be confirmed')
    error.code = 'EVIDENCE_CLI_TERMINATION_UNCONFIRMED'
    error.killed = true
    return {
      error, stdout: result.stdout, stderr: result.stderr,
      termination_confirmed: false, supervision_mode: 'WINDOWS_JOB_OBJECT',
    }
  }
  if (result.output_limit_exceeded) {
    let dimension = 'output_bytes'
    let cap = caps.maxTotalOutputBytes
    if (result.stdout.length + result.stderr.length >= caps.maxTotalOutputBytes) {
      dimension = 'output_bytes'
      cap = caps.maxTotalOutputBytes
    } else if (result.stdout.length >= caps.maxStdoutBytes) {
      dimension = 'stdout_bytes'
      cap = caps.maxStdoutBytes
    } else if (result.stderr.length >= caps.maxStderrBytes) {
      dimension = 'stderr_bytes'
      cap = caps.maxStderrBytes
    }
    const error = new ImpactCapExceededError(dimension, cap + 1, cap)
    Object.defineProperty(error, 'observedOutputBytes', {
      value: Math.min(Number.MAX_SAFE_INTEGER, result.stdout.length + result.stderr.length + 1),
      configurable: true,
    })
    return {
      error,
      stdout: result.stdout,
      stderr: result.stderr,
      termination_confirmed: result.termination_confirmed,
      supervision_mode: 'WINDOWS_JOB_OBJECT',
    }
  }
  if (result.timed_out) {
    const error = new Error(`command timed out after ${options.timeout}ms`)
    error.killed = true
    return {
      error, stdout: result.stdout, stderr: result.stderr,
      termination_confirmed: result.termination_confirmed,
      supervision_mode: 'WINDOWS_JOB_OBJECT',
    }
  }
  const error = result.code === 0 ? null : Object.assign(
    new Error(`command exited ${result.code}`),
    { code: result.code, signal: null, killed: false },
  )
  return {
    error, stdout: result.stdout, stderr: result.stderr,
    termination_confirmed: result.termination_confirmed,
    supervision_mode: 'WINDOWS_JOB_OBJECT',
  }
}

function spawnBoundedAsync(file, args, options, caps, stdoutObserver) {
  if (process.platform === 'win32') {
    return spawnBoundedWindows(file, args, options, caps, stdoutObserver)
  }
  return new Promise((resolve) => {
    let child
    try {
      child = spawn(file, args, {
        env: options.env,
        cwd: options.cwd,
        shell: false,
        windowsHide: true,
        detached: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      })
    } catch (error) {
      resolve({ error, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) })
      return
    }

    const stdout = []
    const stderr = []
    let stdoutBytes = 0
    let stderrBytes = 0
    let terminalError = null
    let completed = false
    let postTerminationTimer
    let terminationConfirmed = true

    const killTree = () => {
      try {
        if (Number.isSafeInteger(child.pid) && child.pid > 0) {
          process.kill(-child.pid, 'SIGKILL')
          return
        }
      } catch (error) {
        if (error?.code === 'ESRCH') return
      }
      try { child.kill('SIGKILL') } catch {}
    }

    const settle = (code, signal) => {
      if (completed) return
      completed = true
      clearTimeout(timeout)
      clearTimeout(postTerminationTimer)
      child.stdout.removeAllListeners('data')
      child.stderr.removeAllListeners('data')
      child.stdout.destroy()
      child.stderr.destroy()
      child.unref()
      const error = terminalError ?? (code === 0 ? null : Object.assign(
        new Error(`command exited ${code ?? signal}`),
        { code, signal, killed: signal !== null },
      ))
      resolve({
        error,
        stdout: Buffer.concat(stdout, stdoutBytes),
        stderr: Buffer.concat(stderr, stderrBytes),
        termination_confirmed: terminationConfirmed,
        supervision_mode: 'POSIX_PROCESS_GROUP',
      })
    }

    const terminate = () => {
      killTree()
      postTerminationTimer ??= setTimeout(() => {
        terminationConfirmed = false
        if (terminalError === null) {
          terminalError = Object.assign(
            new Error('POSIX process-group cleanup could not be confirmed before the bounded deadline'),
            {
              code: 'EVIDENCE_CLI_TERMINATION_UNCONFIRMED',
              killed: true,
              termination_confirmed: false,
            },
          )
        } else {
          Object.defineProperty(terminalError, 'termination_confirmed', {
            value: false,
            configurable: true,
          })
        }
        settle(null, 'SIGKILL')
      }, 5_000)
    }

    const haltForCap = (dimension, value, cap, observedOutputBytes) => {
      if (terminalError) return
      terminalError = new ImpactCapExceededError(dimension, value, cap)
      Object.defineProperty(terminalError, 'observedOutputBytes', {
        value: observedOutputBytes,
        configurable: true,
      })
      terminate()
    }
    const collect = (destination, chunk, stream) => {
      if (terminalError) return
      const bytes = Buffer.byteLength(chunk)
      const nextStream = (stream === 'stdout' ? stdoutBytes : stderrBytes) + bytes
      const nextTotal = stdoutBytes + stderrBytes + bytes
      const streamCap = stream === 'stdout' ? caps.maxStdoutBytes : caps.maxStderrBytes
      if (nextStream > streamCap) {
        haltForCap(`${stream}_bytes`, nextStream, streamCap, nextTotal)
        return
      }
      if (nextTotal > caps.maxTotalOutputBytes) {
        haltForCap('output_bytes', nextTotal, caps.maxTotalOutputBytes, nextTotal)
        return
      }
      destination.push(Buffer.from(chunk))
      if (stream === 'stdout') stdoutBytes = nextStream
      else stderrBytes = nextStream
      if (stream === 'stdout' && typeof stdoutObserver === 'function') {
        try {
          stdoutObserver(chunk)
        } catch (error) {
          terminalError = error
          terminate()
          return
        }
      }
    }

    child.stdout.on('data', (chunk) => collect(stdout, chunk, 'stdout'))
    child.stderr.on('data', (chunk) => collect(stderr, chunk, 'stderr'))
    child.on('error', (error) => {
      terminalError ??= error
    })

    const timeout = setTimeout(() => {
      if (terminalError) return
      const error = new Error(`command timed out after ${options.timeout}ms`)
      error.killed = true
      terminalError = error
      terminate()
    }, options.timeout)

    child.on('exit', () => {
      // A CLI leader is not allowed to leave helpers running after it exits.
      // Killing the detached group here also closes inherited stdout/stderr
      // handles so the close event cannot hang behind a descendant.
      terminate()
    })
    child.on('close', (code, signal) => settle(code, signal))
  })
}

function runCliProbeInvocation(resolved, env) {
  return spawnBoundedAsync(
    resolved.file,
    resolved.args,
    {
      env,
      timeout: CLI_PROBE_TIMEOUT_MS,
      shell: false,
      windowsHide: true,
    },
    CLI_PROBE_OUTPUT_CAPS,
  )
}

function consumeProbeVersion(result, includeVersion) {
  let version = null
  if (includeVersion) {
    const text = result.stdout.toString('utf8').trim()
    version = text === '' ? null : text.split('\n')[0]
  }
  result.stdout.fill(0)
  result.stderr.fill(0)
  return version
}

/**
 * Probes without throwing. An absent CLI is a fact the caller records as a
 * coverage gap, not an exception it has to catch to stay honest — and
 * "the tool was missing" must never be able to read as "the target was safe".
 */
export async function probeCli(name, {
  versionArgs = ['--version'],
  env = process.env,
  resolver = identityResolver,
  includeVersion = false,
  expectedInvocationIdentity,
} = {}) {
  if (typeof includeVersion !== 'boolean') throw new TypeError('includeVersion must be a boolean')
  const probeEnvironment = sanitizedProcessEnvironment(env)
  const resolved = resolver(name, versionArgs, probeEnvironment)
  const invocation = {
    file: resolved.file,
    argument_prefix: resolved.args.slice(0, Math.max(0, resolved.args.length - versionArgs.length)),
  }
  try {
    invocation.identity = await captureCliInvocationIdentity(invocation)
    if (expectedInvocationIdentity !== undefined) {
      assertExpectedInvocationIdentity(invocation.identity, expectedInvocationIdentity)
    }
  } catch (error) {
    if (error?.code !== 'ENOENT' && error?.code !== 'ENOTDIR') throw error
  }
  const first = await runCliProbeInvocation(resolved, probeEnvironment)
  const { error } = first
  if (error && (error.code === 'ENOENT' || error.code === 'EACCES')) {
    consumeProbeVersion(first, false)
    const { shimPath, resolved: viaShim } = resolveShimInvocation(name, versionArgs, probeEnvironment)
    if (viaShim) {
      const shimInvocation = {
        file: viaShim.file,
        argument_prefix: viaShim.args.slice(0, Math.max(0, viaShim.args.length - versionArgs.length)),
      }
      shimInvocation.identity = await captureCliInvocationIdentity(shimInvocation)
      if (expectedInvocationIdentity !== undefined) {
        assertExpectedInvocationIdentity(shimInvocation.identity, expectedInvocationIdentity)
      }
      const retry = await runCliProbeInvocation(viaShim, probeEnvironment)
      if (!retry.error) {
        return {
          name,
          present: true,
          version: consumeProbeVersion(retry, includeVersion),
          reason: null,
          via_node_shim: shimPath,
          invocation: {
            file: viaShim.file,
            argument_prefix: viaShim.args.slice(0, Math.max(0, viaShim.args.length - versionArgs.length)),
            identity: shimInvocation.identity,
          },
        }
      }
      if (retry.error?.code === 'EVIDENCE_CLI_TERMINATION_UNCONFIRMED') {
        consumeProbeVersion(retry, false)
        return {
          name,
          present: false,
          version: null,
          reason: `${retry.supervision_mode ?? 'process supervision'} cleanup could not be confirmed; `
            + 'an external process may remain',
          supervision_mode: retry.supervision_mode ?? null,
          termination_confirmed: false,
        }
      }
      // Resolved, then failed. That is a different fault from an unparseable
      // shim and sends an operator somewhere else entirely, so say which.
      consumeProbeVersion(retry, false)
      return {
        name,
        present: false,
        version: null,
        reason: `${name} resolved through its npm shim at ${shimPath}, but the version `
          + `probe ${retry.error.killed ? 'timed out' : `exited ${retry.error.code}`}`,
      }
    }
    if (shimPath) {
      return {
        name,
        present: false,
        version: null,
        reason: `${name} is installed at ${shimPath} as a shell shim this controller `
          + 'cannot resolve to a direct node invocation, and it never spawns a shell; '
          + 'supply a native executable on PATH',
      }
    }
    return { name, present: false, version: null, reason: `${error.code}: not found on PATH` }
  }
  if (error?.code === 'EVIDENCE_CLI_TERMINATION_UNCONFIRMED') {
    consumeProbeVersion(first, false)
    return {
      name,
      present: false,
      version: null,
      reason: `${first.supervision_mode ?? 'process supervision'} cleanup could not be confirmed; `
        + 'an external process may remain',
      supervision_mode: first.supervision_mode ?? null,
      termination_confirmed: false,
    }
  }
  if (error && error.killed) {
    consumeProbeVersion(first, false)
    return { name, present: false, version: null, reason: 'version probe timed out' }
  }
  if (error) {
    consumeProbeVersion(first, false)
    return {
      name,
      present: false,
      version: null,
      reason: `version probe failed (${error.code ?? error.signal ?? error.message ?? 'unknown error'})`,
    }
  }
  return {
    name,
    present: true,
    // Version stdout is provider-controlled. Callers that intend to display
    // it can opt in; durable evidence plans default to retaining no bytes from
    // this otherwise successful exfiltration channel.
    version: consumeProbeVersion(first, includeVersion),
    reason: null,
    invocation,
  }
}

export async function runBoundedCli({
  name,
  args,
  limits = DEFAULT_CLI_LIMITS,
  env = process.env,
  cwd,
  counters,
  resolver = identityResolver,
  stdoutObserver,
  expectedInvocationIdentity,
  verifiedInvocationIdentity,
  beforeDispatch,
}) {
  // A registry reference or a resource name is untrusted input. execFile with
  // an argument array has no shell to inject into; a command string would.
  if (!Array.isArray(args)) throw new TypeError('args must be an array; this runner never spawns a shell')

  const effectiveLimits = validateCliLimits(limits)
  const tracked = counters ?? new ImpactCounters({
    maxCommands: effectiveLimits.maxCommands,
    maxObjects: effectiveLimits.maxObjects,
    maxBytes: effectiveLimits.maxTotalOutputBytes,
  })
  if (beforeDispatch !== undefined && typeof beforeDispatch !== 'function') {
    throw new TypeError('beforeDispatch must be a function')
  }
  tracked.assertCanRecord({ commands: 1 })
  const remainingBytes = tracked.caps.bytes_read - tracked.counters.bytes_read
  const outputCaps = {
    maxStdoutBytes: Math.min(effectiveLimits.maxStdoutBytes, remainingBytes),
    maxStderrBytes: Math.min(effectiveLimits.maxStderrBytes, remainingBytes),
    maxTotalOutputBytes: Math.min(effectiveLimits.maxTotalOutputBytes, remainingBytes),
  }

  const spawnOptions = {
    env,
    cwd,
    timeout: effectiveLimits.timeoutMs,
    shell: false,
    windowsHide: true,
  }
  const resolved = resolver(name, args, env)
  let identityContentBytesRead = 0
  const invocation = {
    file: resolved.file,
    argument_prefix: resolved.args.slice(0, Math.max(0, resolved.args.length - args.length)),
  }
  if (verifiedInvocationIdentity !== undefined) {
    await assertCurrentInvocationSnapshot(invocation, verifiedInvocationIdentity)
  } else if (expectedInvocationIdentity !== undefined) {
    const invocationIdentity = await captureCliInvocationIdentity({
      file: invocation.file,
      argument_prefix: invocation.argument_prefix,
    })
    identityContentBytesRead += invocationIdentity.total_bytes
    assertExpectedInvocationIdentity(invocationIdentity, expectedInvocationIdentity)
  }
  await beforeDispatch?.()
  tracked.record({ commands: 1 })
  let { error, stdout, stderr, termination_confirmed: terminationConfirmed,
    supervision_mode: supervisionMode } = await spawnBoundedAsync(
    resolved.file,
    resolved.args,
    spawnOptions,
    outputCaps,
    stdoutObserver,
  )

  // A CLI installed only as an npm shim is launched as the node invocation the
  // shim declares. Still no shell: the argument vector is passed through, never
  // re-parsed as a command string.
  if (error && (error.code === 'ENOENT' || error.code === 'EACCES')) {
    const { shimPath, resolved: viaShim } = resolveShimInvocation(name, args, env)
    if (viaShim) {
      if (expectedInvocationIdentity !== undefined) {
        const invocationIdentity = await captureCliInvocationIdentity({
          file: viaShim.file,
          argument_prefix: viaShim.args.slice(0, Math.max(0, viaShim.args.length - args.length)),
        })
        assertExpectedInvocationIdentity(invocationIdentity, expectedInvocationIdentity)
      }
      ({ error, stdout, stderr, termination_confirmed: terminationConfirmed,
        supervision_mode: supervisionMode } = await spawnBoundedAsync(
        viaShim.file,
        viaShim.args,
        spawnOptions,
        outputCaps,
        stdoutObserver,
      ))
    } else if (shimPath) {
      throw new CliUnavailableError(
        name,
        `installed at ${shimPath} as a shell shim this controller cannot resolve to a `
        + 'direct node invocation, and it never spawns a shell',
      )
    }
  }
  if (error && (error.code === 'ENOENT' || error.code === 'EACCES')) {
    throw new CliUnavailableError(name, `${error.code}: not found on PATH`)
  }
  if (error instanceof ImpactCapExceededError) {
    const acceptedBytes = stdout.length + stderr.length
    const observedBytes = Number.isSafeInteger(error.observedOutputBytes)
      ? error.observedOutputBytes
      : acceptedBytes
    if (observedBytes > 0) tracked.recordReadCapViolation(observedBytes)
    if (error.dimension === 'objects_touched') tracked.recordObjectCapViolation(error.value)
    Object.defineProperties(error, {
      command_dispatched: { value: true, configurable: true },
      supervision_mode: {
        value: supervisionMode ?? (process.platform === 'win32'
          ? 'WINDOWS_JOB_OBJECT'
          : 'POSIX_PROCESS_GROUP'),
        configurable: true,
      },
      termination_confirmed: {
        value: terminationConfirmed !== false,
        configurable: true,
      },
    })
    stdout.fill(0)
    stderr.fill(0)
    throw error
  }
  tracked.record({ bytes: stdout.length + stderr.length })

  return {
    stdout,
    stderr: stderr.toString('utf8'),
    code: error === null || error === undefined
      ? 0
      : Number.isInteger(error.code) ? error.code : (error.killed ? 124 : 1),
    failure_code: typeof error?.code === 'string' ? error.code : null,
    termination_confirmed: terminationConfirmed !== false,
    supervision_mode: supervisionMode ?? (process.platform === 'win32'
      ? 'WINDOWS_JOB_OBJECT'
      : 'POSIX_PROCESS_GROUP'),
    identity_content_bytes_read: identityContentBytesRead,
    counters: tracked.snapshot(),
  }
}
