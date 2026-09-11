import { spawn as nodeSpawn } from 'node:child_process'
import { randomBytes, createHash } from 'node:crypto'
import { constants } from 'node:fs'
import {
  lstat as nodeLstat,
  mkdtemp,
  open,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, extname, isAbsolute, join, relative, resolve, win32 } from 'node:path'
import { fileURLToPath } from 'node:url'

const POST_TERMINATION_TIMEOUT_MS = 5_000
const LOG_POLL_INTERVAL_MS = 100
const WINDOWS_HELPER_OUTPUT_BYTES = 64 * 1024
const WINDOWS_HELPER_GRACE_MS = 20_000
const WINDOWS_HELPER_RESULT_BYTES = 64 * 1024
const WINDOWS_JOB_REQUEST_VERSION = '1.1.0'
const OPEN_READ_FLAGS = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)

export const WINDOWS_JOB_HELPER_PATH = fileURLToPath(
  new URL('../windows/job-supervisor.ps1', import.meta.url),
)
export const WINDOWS_GHIDRA_BATCH_BRIDGE_PATH = fileURLToPath(
  new URL('../windows/launch-ghidra-fixed.cmd', import.meta.url),
)

const ENVIRONMENT_ALLOWLIST = Object.freeze([
  'JAVA_HOME',
  'JDK_HOME',
  'LANG',
  'LC_ALL',
  'PATH',
  'Path',
  'PATHEXT',
  'SystemRoot',
  'SYSTEMROOT',
  'TEMP',
  'TMP',
  'TMPDIR',
  'WINDIR',
])

export function sanitizedProcessEnvironment(source = process.env) {
  const result = {}
  const seen = new Set()
  for (const key of ENVIRONMENT_ALLOWLIST) {
    if (typeof source[key] !== 'string') continue
    const identity = process.platform === 'win32' ? key.toLowerCase() : key
    if (seen.has(identity)) continue
    seen.add(identity)
    result[key] = source[key]
  }
  return result
}

function bytes(value) {
  return Buffer.isBuffer(value) ? value : Buffer.from(value)
}

function positivePid(value) {
  return Number.isSafeInteger(value) && value > 0 ? value : null
}

function missingProcessGroup(error) {
  return error?.code === 'ESRCH'
}

function missingFile(error) {
  return error?.code === 'ENOENT'
}

function assertStopMarkerPath(path, platform = process.platform) {
  if (path === undefined || path === null) return null
  if (typeof path !== 'string') throw new TypeError('stop marker path must be one absolute local path')
  const absolute = platform === 'win32' ? win32.isAbsolute(path) : isAbsolute(path)
  if (!absolute || path.includes('\u0000')
    || (platform === 'win32' && path.startsWith('\\\\'))
    || (platform !== 'win32' && path.startsWith('//'))) {
    throw new TypeError('stop marker path must be one absolute local path')
  }
  return path
}

async function stopMarkerExists(path, lstatImpl = nodeLstat) {
  if (path === null) return false
  try {
    await lstatImpl(path, { bigint: true })
    return true
  } catch (error) {
    if (missingFile(error)) return false
    throw error
  }
}

function stoppedBeforeStartResult(platform, startedAt) {
  return Object.freeze({
    code: null,
    signal: null,
    timed_out: false,
    stop_requested: true,
    output_limit_exceeded: false,
    log_limit_exceeded: false,
    log_integrity_failed: false,
    log_bytes: 0,
    spawn_error: false,
    started: false,
    termination_confirmed: true,
    supervision: platform === 'win32' ? 'WINDOWS_JOB_OBJECT' : 'POSIX_PROCESS_GROUP',
    duration_ms: Math.max(0, Date.now() - startedAt),
    stdout: Buffer.alloc(0),
    stderr: Buffer.alloc(0),
  })
}

export function isWindowsBatchLauncher(path) {
  return ['.bat', '.cmd'].includes(extname(path).toLowerCase())
}

function pathKey(value) {
  return process.platform === 'win32' ? value.toLowerCase() : value
}

function samePath(left, right) {
  return pathKey(resolve(left)) === pathKey(resolve(right))
}

function inside(parent, child) {
  const nested = relative(parent, child)
  return nested !== '' && nested !== '..' && !nested.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) && !isAbsolute(nested)
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino
}

async function fixedFileHash(path, maximumBytes = 1024 * 1024) {
  const metadata = await nodeLstat(path, { bigint: true })
  if (
    !metadata.isFile()
    || metadata.isSymbolicLink()
    || (metadata.nlink !== 1 && metadata.nlink !== 1n)
    || metadata.size < 1n
    || metadata.size > BigInt(maximumBytes)
  ) throw new Error('Windows job adapter file is not one bounded regular file')
  const handle = await open(path, OPEN_READ_FLAGS)
  try {
    const heldBefore = await handle.stat({ bigint: true })
    if (!sameIdentity(metadata, heldBefore) || heldBefore.size !== metadata.size) {
      throw new Error('Windows job adapter file identity changed before reading')
    }
    const digest = createHash('sha256')
    const buffer = Buffer.allocUnsafe(64 * 1024)
    let position = 0
    while (position < Number(heldBefore.size)) {
      const wanted = Math.min(buffer.length, Number(heldBefore.size) - position)
      const { bytesRead } = await handle.read(buffer, 0, wanted, position)
      if (bytesRead === 0) break
      digest.update(buffer.subarray(0, bytesRead))
      position += bytesRead
    }
    const heldAfter = await handle.stat({ bigint: true })
    if (position !== Number(heldBefore.size) || !sameIdentity(heldBefore, heldAfter) || heldBefore.size !== heldAfter.size) {
      throw new Error('Windows job adapter file changed while reading')
    }
    return `${heldBefore.size}:${digest.digest('hex')}`
  } finally {
    await handle.close()
  }
}

async function readBoundedFile(path, maximumBytes, { required = true } = {}) {
  let metadata
  try {
    metadata = await nodeLstat(path, { bigint: true })
  } catch (error) {
    if (!required && missingFile(error)) return Buffer.alloc(0)
    throw error
  }
  if (
    !metadata.isFile()
    || metadata.isSymbolicLink()
    || (metadata.nlink !== 1 && metadata.nlink !== 1n)
    || metadata.size > BigInt(maximumBytes)
  ) throw new Error('Windows job adapter output is not one bounded regular file')
  const handle = await open(path, OPEN_READ_FLAGS)
  try {
    const heldBefore = await handle.stat({ bigint: true })
    if (!sameIdentity(metadata, heldBefore) || heldBefore.size !== metadata.size) {
      throw new Error('Windows job adapter output identity changed before reading')
    }
    const size = Number(heldBefore.size)
    const output = Buffer.alloc(size + 1)
    let position = 0
    while (position < output.length) {
      const { bytesRead } = await handle.read(output, position, output.length - position, position)
      if (bytesRead === 0) break
      position += bytesRead
    }
    const heldAfter = await handle.stat({ bigint: true })
    if (position !== size || !sameIdentity(heldBefore, heldAfter) || heldBefore.size !== heldAfter.size) {
      throw new Error('Windows job adapter output changed while reading')
    }
    return output.subarray(0, size)
  } finally {
    await handle.close()
  }
}

function exactObject(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const actual = Object.keys(value).sort()
  const expected = [...fields].sort()
  return actual.length === expected.length && actual.every((field, index) => field === expected[index])
}

function windowsSystemTool(environment, name) {
  const root = environment.SystemRoot ?? environment.SYSTEMROOT ?? environment.WINDIR
  if (
    typeof root !== 'string'
    || !win32.isAbsolute(root)
    || root.startsWith('\\\\')
    || root.includes('\u0000')
  ) throw new Error('Windows system root is unavailable for job supervision')
  return win32.join(root, 'System32', name)
}

function prepareWindowsTarget(file, args, environment) {
  if (!isWindowsBatchLauncher(file)) return { file, args, environment, batchBridge: null, adapterFiles: [] }
  if (
    typeof file !== 'string'
    || !win32.isAbsolute(file)
    || file.startsWith('\\\\')
    || /["\u0000-\u001f\u007f-\u009f]/u.test(file)
    || args.length !== 19
    || args.some((argument) => (
      typeof argument !== 'string'
      || argument.length > 4_096
      || /["\u0000-\u001f\u007f-\u009f]/u.test(argument)
    ))
  ) throw new Error('Windows batch launch requires the safe fixed 19-argument Ghidra profile')
  const targetEnvironment = { ...environment, LAST_APERTURE_BATCH_LAUNCHER: file }
  for (const [index, argument] of args.entries()) {
    targetEnvironment[`LAST_APERTURE_BATCH_ARG_${String(index).padStart(2, '0')}`] = argument
  }
  return {
    file: windowsSystemTool(environment, 'cmd.exe'),
    args: [],
    environment: targetEnvironment,
    batchBridge: WINDOWS_GHIDRA_BATCH_BRIDGE_PATH,
    adapterFiles: [WINDOWS_GHIDRA_BATCH_BRIDGE_PATH],
  }
}

function failedWindowsResult(startedAt, { targetMayHaveStarted = false } = {}) {
  return Object.freeze({
    code: null,
    signal: null,
    timed_out: false,
    stop_requested: false,
    output_limit_exceeded: false,
    log_limit_exceeded: false,
    log_integrity_failed: false,
    log_bytes: 0,
    spawn_error: true,
    started: targetMayHaveStarted,
    termination_confirmed: false,
    supervision: 'WINDOWS_JOB_OBJECT',
    duration_ms: Math.max(0, Date.now() - startedAt),
    stdout: Buffer.alloc(0),
    stderr: Buffer.alloc(0),
  })
}

async function invokeWindowsHelper({ file, args, cwd, env, timeoutMs }) {
  let child
  try {
    child = nodeSpawn(file, args, {
      cwd,
      env,
      shell: false,
      windowsHide: true,
      detached: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
  } catch {
    return { code: null, failed: true }
  }
  if (!child || typeof child.once !== 'function') return { code: null, failed: true }
  return await new Promise((resolveResult) => {
    let settled = false
    let captured = 0
    let failed = false
    let timedOut = false
    let timer
    let killTimer
    const capture = (value) => {
      if (settled || failed) return
      const length = bytes(value).length
      if (length > WINDOWS_HELPER_OUTPUT_BYTES - captured) {
        failed = true
        try { child.kill?.('SIGKILL') } catch {}
        killTimer = setTimeout(() => finish(null), 5_000)
      } else {
        captured += length
      }
    }
    const finish = (code) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      clearTimeout(killTimer)
      resolveResult({ code, failed, timedOut })
    }
    child.stdout?.on('data', capture)
    child.stderr?.on('data', capture)
    child.once('error', () => {
      failed = true
      finish(null)
    })
    child.once('close', (code) => finish(code))
    timer = setTimeout(() => {
      timedOut = true
      failed = true
      try { child.kill?.('SIGKILL') } catch {}
      killTimer = setTimeout(() => finish(null), 5_000)
    }, timeoutMs)
  })
}

async function cleanupAdapterDirectory(path, expectedIdentity) {
  const temporaryRoot = resolve(tmpdir())
  const absolute = resolve(path)
  if (!inside(temporaryRoot, absolute)) return false
  try {
    const metadata = await nodeLstat(absolute, { bigint: true })
    const canonical = await realpath(absolute)
    if (!metadata.isDirectory() || metadata.isSymbolicLink() || !sameIdentity(metadata, expectedIdentity) || !samePath(canonical, absolute)) return false
    await rm(absolute, { recursive: true, force: false })
    try {
      await nodeLstat(absolute)
      return false
    } catch (error) {
      return missingFile(error)
    }
  } catch {
    return false
  }
}

export async function runWindowsJobProcess({
  file,
  args,
  cwd,
  env,
  timeoutMs,
  maxOutputBytes,
  logPaths = [],
  maxLogBytes = maxOutputBytes,
  stopMarkerPath,
}, internals = {}) {
  const startedAt = Date.now()
  let adapterDirectory
  let adapterIdentity
  let targetMayHaveStarted = false
  try {
    const target = prepareWindowsTarget(file, args, env)
    const fixedFiles = [WINDOWS_JOB_HELPER_PATH, ...target.adapterFiles]
    const hashesBefore = await Promise.all(fixedFiles.map((path) => fixedFileHash(path)))
    adapterDirectory = await mkdtemp(join(tmpdir(), 'last-aperture-job-'))
    adapterIdentity = await nodeLstat(adapterDirectory, { bigint: true })
    const canonicalAdapterDirectory = await realpath(adapterDirectory)
    if (!adapterIdentity.isDirectory() || adapterIdentity.isSymbolicLink() || !samePath(canonicalAdapterDirectory, adapterDirectory)) {
      throw new Error('Windows job adapter scratch identity is invalid')
    }
    const requestPath = join(adapterDirectory, 'request.json')
    const resultPath = join(adapterDirectory, 'result.json')
    const stdoutPath = join(adapterDirectory, 'stdout.bin')
    const stderrPath = join(adapterDirectory, 'stderr.bin')
    const requestNonce = randomBytes(32).toString('hex')
    const request = {
      schema_version: WINDOWS_JOB_REQUEST_VERSION,
      request_nonce: requestNonce,
      file: target.file,
      args: target.args,
      batch_bridge: target.batchBridge,
      cwd,
      env: target.environment,
      timeout_ms: timeoutMs,
      max_output_bytes: maxOutputBytes,
      log_paths: logPaths,
      max_log_bytes: maxLogBytes,
      stop_marker_path: assertStopMarkerPath(stopMarkerPath, 'win32'),
      stdout_path: stdoutPath,
      stderr_path: stderrPath,
    }
    await writeFile(requestPath, `${JSON.stringify(request)}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 })
    const powerShellPath = windowsSystemTool(env, win32.join('WindowsPowerShell', 'v1.0', 'powershell.exe'))
    targetMayHaveStarted = true
    const helperResult = await (internals.invokeWindowsHelperImpl ?? invokeWindowsHelper)({
      file: powerShellPath,
      args: [
        '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', WINDOWS_JOB_HELPER_PATH,
        '-RequestPath', requestPath,
        '-ResultPath', resultPath,
      ],
      cwd: dirname(WINDOWS_JOB_HELPER_PATH),
      env: sanitizedProcessEnvironment(env),
      timeoutMs: timeoutMs + WINDOWS_HELPER_GRACE_MS,
    })
    const hashesAfter = await Promise.all(fixedFiles.map((path) => fixedFileHash(path)))
    if (hashesAfter.some((hash, index) => hash !== hashesBefore[index])) throw new Error('Windows job adapter changed during execution')
    if (helperResult.failed || ![0, 1].includes(helperResult.code)) throw new Error('Windows job helper did not close normally')
    const resultBytes = await readBoundedFile(resultPath, WINDOWS_HELPER_RESULT_BYTES)
    let structured
    try {
      structured = JSON.parse(resultBytes.toString('utf8'))
    } catch {
      throw new Error('Windows job helper returned malformed JSON')
    }
    if (!exactObject(structured, [
      'code', 'duration_ms', 'log_bytes', 'log_integrity_failed', 'log_limit_exceeded',
      'output_limit_exceeded', 'request_nonce', 'schema_version', 'spawn_error',
      'stop_requested', 'supervision', 'termination_confirmed', 'timed_out',
    ]) || structured.schema_version !== WINDOWS_JOB_REQUEST_VERSION
      || structured.request_nonce !== requestNonce
      || structured.supervision !== 'WINDOWS_JOB_OBJECT'
      || !(structured.code === null || Number.isSafeInteger(structured.code))
      || !Number.isSafeInteger(structured.duration_ms) || structured.duration_ms < 0
      || !Number.isSafeInteger(structured.log_bytes) || structured.log_bytes < 0 || structured.log_bytes > maxLogBytes
      || ['log_integrity_failed', 'log_limit_exceeded', 'output_limit_exceeded', 'spawn_error', 'stop_requested', 'termination_confirmed', 'timed_out']
        .some((field) => typeof structured[field] !== 'boolean')
      || (helperResult.code === 1) !== structured.spawn_error
      || (structured.spawn_error && (structured.code !== null || structured.termination_confirmed))
      || (structured.timed_out && structured.code !== null)) {
      throw new Error('Windows job helper returned an invalid result')
    }
    const stdout = await readBoundedFile(stdoutPath, maxOutputBytes, { required: structured.spawn_error !== true })
    const stderr = await readBoundedFile(stderrPath, maxOutputBytes - stdout.length, { required: structured.spawn_error !== true })
    if (stdout.length + stderr.length > maxOutputBytes) throw new Error('Windows job helper exceeded the combined output limit')
    let terminationConfirmed = structured.termination_confirmed === true
    if (terminationConfirmed) {
      terminationConfirmed = await cleanupAdapterDirectory(adapterDirectory, adapterIdentity)
    }
    return Object.freeze({
      code: structured.code,
      signal: null,
      timed_out: structured.timed_out,
      stop_requested: structured.stop_requested,
      output_limit_exceeded: structured.output_limit_exceeded,
      log_limit_exceeded: structured.log_limit_exceeded,
      log_integrity_failed: structured.log_integrity_failed,
      log_bytes: structured.log_bytes,
      spawn_error: structured.spawn_error,
      started: structured.spawn_error !== true,
      termination_confirmed: terminationConfirmed,
      supervision: structured.supervision,
      duration_ms: structured.duration_ms,
      stdout,
      stderr,
    })
  } catch {
    if (adapterDirectory !== undefined && adapterIdentity !== undefined) {
      try { await cleanupAdapterDirectory(adapterDirectory, adapterIdentity) } catch {}
    }
    return failedWindowsResult(startedAt, { targetMayHaveStarted })
  }
}

/**
 * Run one native process with an exact combined stdout/stderr budget.
 *
 * POSIX children start in a detached process group. Windows children use the
 * repository-owned Job Object helper, which atomically assigns a suspended
 * process to a kill-on-close job before resuming it. Injected child-process
 * implementations use the conservative child-only fallback.
 */
export async function runSupervisedProcess({
  file,
  args,
  cwd,
  env,
  timeoutMs,
  maxOutputBytes,
  logPaths = [],
  maxLogBytes = maxOutputBytes,
  stopMarkerPath,
}, internals = {}) {
  const startedAt = Date.now()
  const {
    platform = process.platform,
    spawnImpl = nodeSpawn,
    lstatImpl = nodeLstat,
    processKillImpl = process.kill.bind(process),
    postTerminationTimeoutMs = POST_TERMINATION_TIMEOUT_MS,
    logPollIntervalMs = LOG_POLL_INTERVAL_MS,
    stopPollIntervalMs = 50,
    windowsJobRunnerImpl = runWindowsJobProcess,
  } = internals
  if (!Number.isSafeInteger(stopPollIntervalMs) || stopPollIntervalMs < 10 || stopPollIntervalMs > 1_000) {
    throw new TypeError('stop marker poll interval is outside process supervision bounds')
  }
  const markerPath = assertStopMarkerPath(stopMarkerPath, platform)
  if (markerPath !== null && await stopMarkerExists(markerPath, lstatImpl)) {
    return stoppedBeforeStartResult(platform, startedAt)
  }
  if (platform === 'win32' && !Object.hasOwn(internals, 'spawnImpl')) {
    const request = {
      file,
      args,
      cwd,
      env,
      timeoutMs,
      maxOutputBytes,
      logPaths,
      maxLogBytes,
    }
    if (markerPath !== null) request.stopMarkerPath = markerPath
    return await windowsJobRunnerImpl(request)
  }
  const stdout = []
  const stderr = []
  let capturedBytes = 0
  let timedOut = false
  let outputLimitExceeded = false
  let logLimitExceeded = false
  let logIntegrityFailed = false
  let logBytes = 0
  let stopRequested = false
  let started = false
  let child

  child = spawnImpl(file, [...args], {
    cwd,
    env,
    shell: false,
    windowsHide: true,
    detached: platform !== 'win32',
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  if (!child || typeof child.once !== 'function') {
    throw new TypeError('spawn implementation did not return a child process')
  }

  const pid = positivePid(child.pid)
  const supervision = platform === 'win32'
    ? 'WINDOWS_CHILD_ONLY'
    : 'POSIX_PROCESS_GROUP'

  return await new Promise((resolve) => {
    let settled = false
    let finalizing = false
    let spawnError = false
    let terminationRequested = false
    let timeoutTimer
    let postTerminationTimer
    let logTimer
    let logInspectionPromise
    let stopTimer
    let stopInspectionPromise

    const finish = (code, signal, terminationConfirmed) => {
      if (settled) return
      settled = true
      clearTimeout(timeoutTimer)
      clearTimeout(postTerminationTimer)
      clearInterval(logTimer)
      clearInterval(stopTimer)
      resolve(Object.freeze({
        code,
        signal,
        timed_out: timedOut,
        stop_requested: stopRequested,
        output_limit_exceeded: outputLimitExceeded,
        log_limit_exceeded: logLimitExceeded,
        log_integrity_failed: logIntegrityFailed,
        log_bytes: logBytes,
        spawn_error: spawnError,
        started,
        termination_confirmed: terminationConfirmed,
        supervision,
        duration_ms: Math.max(0, Date.now() - startedAt),
        stdout: Buffer.concat(stdout),
        stderr: Buffer.concat(stderr),
      }))
    }

    const groupAbsent = () => {
      if (platform === 'win32' || pid === null) return false
      try {
        processKillImpl(-pid, 0)
        return false
      } catch (error) {
        return missingProcessGroup(error)
      }
    }

    const signalTree = () => {
      if (platform !== 'win32' && pid !== null) {
        try {
          processKillImpl(-pid, 'SIGKILL')
          return
        } catch (error) {
          if (missingProcessGroup(error)) return
        }
      }
      try {
        child.kill?.('SIGKILL')
      } catch {
        // The bounded confirmation phase below keeps this failure honest.
      }
    }

    const requestTermination = () => {
      if (terminationRequested || settled) return
      terminationRequested = true
      clearTimeout(timeoutTimer)
      signalTree()
      if (!finalizing) {
        postTerminationTimer = setTimeout(
          () => finish(null, 'SIGKILL', false),
          postTerminationTimeoutMs,
        )
      }
    }

    const inspectStopMarker = async () => {
      if (markerPath === null || settled || stopRequested) return
      if (stopInspectionPromise) return await stopInspectionPromise
      stopInspectionPromise = (async () => {
        try {
          if (!await stopMarkerExists(markerPath, lstatImpl)) return
        } catch {
          // A marker that cannot be inspected must fail closed and stop the tree.
        } finally {
          stopInspectionPromise = undefined
        }
        stopRequested = true
        requestTermination()
      })()
      return await stopInspectionPromise
    }

    const inspectLogs = async () => {
      if (logPaths.length === 0 || settled) return
      if (logInspectionPromise) return await logInspectionPromise
      logInspectionPromise = (async () => {
        try {
          let total = 0n
          for (const path of logPaths) {
            let metadata
            try {
              metadata = await lstatImpl(path, { bigint: true })
            } catch (error) {
              if (missingFile(error)) continue
              logIntegrityFailed = true
              requestTermination()
              return
            }
            if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.nlink !== 1 && metadata.nlink !== 1n)) {
              logIntegrityFailed = true
              requestTermination()
              return
            }
            total += BigInt(metadata.size)
            if (total > BigInt(maxLogBytes)) {
              logLimitExceeded = true
              requestTermination()
              break
            }
          }
          logBytes = total > BigInt(Number.MAX_SAFE_INTEGER)
            ? Number.MAX_SAFE_INTEGER
            : Number(total)
        } finally {
          logInspectionPromise = undefined
        }
      })()
      return await logInspectionPromise
    }

    const finalizeAfterClose = async (code, signal) => {
      if (settled || finalizing) return
      finalizing = true
      clearTimeout(timeoutTimer)
      clearTimeout(postTerminationTimer)
      await inspectLogs()

      let terminationConfirmed = false
      if (platform !== 'win32' && pid !== null) {
        if (!groupAbsent()) {
          terminationRequested = true
          signalTree()
          const deadline = Date.now() + postTerminationTimeoutMs
          while (!groupAbsent() && Date.now() < deadline) {
            await new Promise((resolveWait) => setTimeout(resolveWait, 10))
          }
        }
        terminationConfirmed = !spawnError && groupAbsent()
      }
      finish(code, signal, terminationConfirmed)
    }

    const capture = (target) => (chunkValue) => {
      if (settled || outputLimitExceeded) return
      const chunk = bytes(chunkValue)
      const remaining = maxOutputBytes - capturedBytes
      if (remaining > 0) {
        const bounded = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk
        target.push(bounded)
        capturedBytes += bounded.length
      }
      if (chunk.length > remaining) {
        outputLimitExceeded = true
        requestTermination()
      }
    }

    child.stdout?.on('data', capture(stdout))
    child.stderr?.on('data', capture(stderr))
    child.once('spawn', () => { started = true })
    child.once('error', () => {
      spawnError = true
      if (pid === null) {
        finish(null, null, false)
      } else {
        requestTermination()
      }
    })
    child.once('close', (code, signal) => {
      void finalizeAfterClose(code, signal)
    })

    timeoutTimer = setTimeout(() => {
      timedOut = true
      requestTermination()
    }, timeoutMs)
    if (logPaths.length > 0) {
      logTimer = setInterval(() => { void inspectLogs() }, logPollIntervalMs)
      logTimer.unref?.()
    }
    if (markerPath !== null) {
      stopTimer = setInterval(() => { void inspectStopMarker() }, stopPollIntervalMs)
      stopTimer.unref?.()
      void inspectStopMarker()
    }
  })
}
