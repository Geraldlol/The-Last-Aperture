import { isAbsolute, resolve, extname } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  runSupervisedProcess,
  sanitizedProcessEnvironment,
} from './reverse-process.mjs'

export const FRIDA_PROFILE_ID = 'native-call-trace-v1'

const OUTPUT_PREFIX = '[last-aperture:frida] '
const BUNDLED_AGENT_PATH = fileURLToPath(
  new URL('../frida/native-call-trace-v1.js', import.meta.url),
)
const MAX_DURATION_SECONDS = 300
const MAX_TRACE_EVENTS = 10_000
const MAX_OUTPUT_BYTES = 64 * 1024 * 1024
const MAX_RUNNER_TIMEOUT_MS = 310_000
const FRAME_NONCE_PATTERN = /^[a-f0-9]{64}$/
const UNSAFE_TEXT_PATTERN = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/

function fail(message, code = 'FRIDA_INPUT_INVALID') {
  const error = new Error(message)
  error.name = 'ReverseFridaError'
  error.code = code
  throw error
}

function localAbsolutePath(value, label) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > 4096
    || UNSAFE_TEXT_PATTERN.test(value)
    || !isAbsolute(value)
    || /^(?:\\\\|\/\/)/.test(value)
  ) fail(`${label} must be one absolute local filesystem path`)
  return resolve(value)
}

function boundedText(value, label, maxLength, code = 'FRIDA_INPUT_INVALID') {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > maxLength
    || value.trim() !== value
    || UNSAFE_TEXT_PATTERN.test(value)
  ) fail(`${label} must be bounded printable text`, code)
  return value
}

function boundedFrameNonce(value, label = 'Frida frame nonce') {
  if (typeof value !== 'string' || !FRAME_NONCE_PATTERN.test(value)) {
    fail(`${label} must be 32 random bytes encoded as lowercase hexadecimal`)
  }
  return value
}

function boundedInteger(value, label, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${label} must be an integer from ${minimum} through ${maximum}`)
  }
  return value
}

function exactKeys(value, keys) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const actual = Object.keys(value).sort()
  const expected = [...keys].sort()
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index])
}

function sameStringArray(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index])
}

export function buildFridaArguments({
  binaryPath,
  agentPath,
  moduleName,
  symbolName,
  durationSeconds,
  maxEvents,
  frameNonce,
} = {}) {
  const binary = localAbsolutePath(binaryPath, 'Frida binary target')
  const agent = localAbsolutePath(agentPath, 'Frida agent')
  if (extname(agent).toLowerCase() !== '.js' || agent !== resolve(BUNDLED_AGENT_PATH)) {
    fail(`Frida agent must be the bundled ${FRIDA_PROFILE_ID}.js profile`)
  }
  const module = boundedText(moduleName, 'Frida module name', 256)
  const symbol = boundedText(symbolName, 'Frida symbol name', 512)
  const duration = boundedInteger(
    durationSeconds,
    'Frida duration seconds',
    1,
    MAX_DURATION_SECONDS,
  )
  const eventLimit = boundedInteger(maxEvents, 'Frida maximum events', 1, MAX_TRACE_EVENTS)
  const nonce = boundedFrameNonce(frameNonce)
  const parameters = JSON.stringify({
    profileId: FRIDA_PROFILE_ID,
    moduleName: module,
    symbolName: symbol,
    durationSeconds: duration,
    maxEvents: eventLimit,
    frameNonce: nonce,
  })

  return Object.freeze([
    '-q',
    '--no-auto-reload',
    '--exit-on-error',
    '--kill-on-exit',
    '-t', String(duration + 1),
    '-P', parameters,
    '-l', agent,
    '-f', binary,
  ])
}

function parseAndValidateArguments(args) {
  if (!Array.isArray(args) || args.some((value) => typeof value !== 'string')) {
    fail('Frida runner requires the fixed argument vector')
  }
  if (args.length !== 12) fail('Frida runner refuses raw or widened arguments')
  let parameters
  try {
    parameters = JSON.parse(args[7])
  } catch {
    fail('Frida runner parameters are not valid JSON')
  }
  if (!exactKeys(parameters, [
    'profileId',
    'moduleName',
    'symbolName',
    'durationSeconds',
    'maxEvents',
    'frameNonce',
  ]) || parameters.profileId !== FRIDA_PROFILE_ID) {
    fail('Frida runner requires the fixed profile parameter shape')
  }
  const expected = buildFridaArguments({
    binaryPath: args[11],
    agentPath: args[9],
    moduleName: parameters.moduleName,
    symbolName: parameters.symbolName,
    durationSeconds: parameters.durationSeconds,
    maxEvents: parameters.maxEvents,
    frameNonce: parameters.frameNonce,
  })
  if (!sameStringArray(args, expected)) {
    fail('Frida runner requires the exact fixed local-spawn argument vector')
  }
  return parameters
}

function validateEvent(value, expectedFrameNonce) {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || value.schema_version !== '1.0.0'
    || value.profile_id !== FRIDA_PROFILE_ID
    || value.frame_nonce !== expectedFrameNonce
    || !Number.isSafeInteger(value.observed_at_ms)
    || value.observed_at_ms < 0
  ) fail('Frida output contains an invalid profile event', 'FRIDA_OUTPUT_INVALID')

  const common = ['schema_version', 'profile_id', 'frame_nonce', 'observed_at_ms', 'event']
  if (value.event === 'ready') {
    if (
      !exactKeys(value, [...common, 'module_name', 'symbol_name', 'module_relative_offset'])
      || !boundedText(value.module_name, 'Frida ready module name', 256, 'FRIDA_OUTPUT_INVALID')
      || !boundedText(value.symbol_name, 'Frida ready symbol name', 512, 'FRIDA_OUTPUT_INVALID')
      || typeof value.module_relative_offset !== 'string'
      || value.module_relative_offset.length > 34
      || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/.test(value.module_relative_offset)
    ) fail('Frida ready event contains invalid or unknown fields', 'FRIDA_OUTPUT_INVALID')
  } else if (value.event === 'enter' || value.event === 'leave') {
    if (
      !exactKeys(value, [...common, 'sequence', 'thread_id'])
      || !Number.isSafeInteger(value.sequence)
      || value.sequence < 1
      || !Number.isSafeInteger(value.thread_id)
      || value.thread_id < 0
    ) fail('Frida trace event contains invalid or unknown fields', 'FRIDA_OUTPUT_INVALID')
  } else if (value.event === 'complete') {
    if (
      !exactKeys(value, [...common, 'events_emitted', 'truncated'])
      || !Number.isSafeInteger(value.events_emitted)
      || value.events_emitted < 0
      || typeof value.truncated !== 'boolean'
    ) fail('Frida complete event contains invalid or unknown fields', 'FRIDA_OUTPUT_INVALID')
  } else {
    fail('Frida output contains an unknown event kind', 'FRIDA_OUTPUT_INVALID')
  }
  return value
}

export function parseFridaOutput(text, { maxEvents, maxBytes, expectedFrameNonce } = {}) {
  const eventLimit = boundedInteger(maxEvents, 'Frida maximum events', 1, MAX_TRACE_EVENTS)
  const byteLimit = boundedInteger(maxBytes, 'Frida output byte limit', 1, MAX_OUTPUT_BYTES)
  const frameNonce = boundedFrameNonce(expectedFrameNonce, 'Expected Frida frame nonce')
  if (typeof text !== 'string' && !Buffer.isBuffer(text)) {
    fail('Frida output must be text or bytes', 'FRIDA_OUTPUT_INVALID')
  }
  const bytes = Buffer.isBuffer(text) ? text : Buffer.from(text, 'utf8')
  if (bytes.length > byteLimit) {
    fail('Frida output exceeds its byte limit', 'FRIDA_OUTPUT_TOO_LARGE')
  }
  const source = bytes.toString('utf8')
  const events = []
  let ignoredLines = 0
  let ready = false
  let complete = false
  let traceEvents = 0
  let truncated = false
  let previousObservedAt = -1
  let observationStart
  let observationEnd

  for (const line of source.split(/\r?\n/)) {
    if (line.length === 0) continue
    if (UNSAFE_TEXT_PATTERN.test(line)) {
      fail('Frida output contains control or bidirectional formatting text', 'FRIDA_OUTPUT_INVALID')
    }
    if (!line.startsWith(OUTPUT_PREFIX)) {
      ignoredLines += 1
      continue
    }
    if (complete) fail('Frida output contains events after complete', 'FRIDA_OUTPUT_INVALID')
    let parsed
    try {
      parsed = JSON.parse(line.slice(OUTPUT_PREFIX.length))
    } catch {
      fail('Frida output contains malformed framed JSON', 'FRIDA_OUTPUT_INVALID')
    }
    const value = validateEvent(parsed, frameNonce)
    if (value.observed_at_ms < previousObservedAt) {
      fail('Frida event observation times must be nondecreasing', 'FRIDA_OUTPUT_INVALID')
    }
    previousObservedAt = value.observed_at_ms
    observationStart ??= value.observed_at_ms
    observationEnd = value.observed_at_ms
    if (value.event === 'ready') {
      if (ready || events.length !== 0) {
        fail('Frida ready event must be first and unique', 'FRIDA_OUTPUT_INVALID')
      }
      ready = true
    } else if (value.event === 'enter' || value.event === 'leave') {
      if (!ready || value.sequence !== traceEvents + 1) {
        fail('Frida trace event sequence is invalid', 'FRIDA_OUTPUT_INVALID')
      }
      traceEvents += 1
      if (traceEvents > eventLimit) {
        fail('Frida trace event limit exceeded', 'FRIDA_OUTPUT_TOO_LARGE')
      }
    } else {
      if (!ready || value.events_emitted !== traceEvents) {
        fail('Frida complete event does not match emitted events', 'FRIDA_OUTPUT_INVALID')
      }
      complete = true
      truncated = value.truncated
    }
    events.push(value)
  }
  if (!ready || !complete) {
    fail('Frida output is missing ready or complete event', 'FRIDA_OUTPUT_INVALID')
  }
  return {
    profile_id: FRIDA_PROFILE_ID,
    ready,
    complete,
    trace_events: traceEvents,
    truncated,
    ignored_lines: ignoredLines,
    observation_window_ms: { start: observationStart, end: observationEnd },
    events,
  }
}

async function defaultSpawnImpl(file, args, options) {
  const result = await runSupervisedProcess({
    file,
    args,
    cwd: options.cwd,
    env: options.env,
    timeoutMs: options.timeout,
    maxOutputBytes: options.maxBuffer,
  })
  return {
    code: result.code,
    stdout: result.stdout,
    stderr: result.stderr,
    timedOut: result.timed_out,
    outputLimitExceeded: result.output_limit_exceeded,
    spawnError: result.spawn_error,
    terminationConfirmed: result.termination_confirmed,
    supervision: result.supervision,
  }
}

export async function runFridaTrace({
  fridaPath,
  args,
  cwd,
  timeoutMs,
  maxOutputBytes,
  spawnImpl = defaultSpawnImpl,
} = {}) {
  const executable = localAbsolutePath(fridaPath, 'Frida executable')
  if (['.bat', '.cmd', '.ps1'].includes(extname(executable).toLowerCase())) {
    fail('Frida executable must be a native executable; shell wrappers are refused')
  }
  const workingDirectory = localAbsolutePath(cwd, 'Frida working directory')
  const parameters = parseAndValidateArguments(args)
  const timeout = boundedInteger(timeoutMs, 'Frida runner timeout', 1, MAX_RUNNER_TIMEOUT_MS)
  const outputLimit = boundedInteger(
    maxOutputBytes,
    'Frida output byte limit',
    1,
    MAX_OUTPUT_BYTES,
  )
  const cliTimeoutMs = (parameters.durationSeconds + 1) * 1000
  if (timeout < cliTimeoutMs) {
    fail('Frida runner timeout must cover the fixed quiet-mode duration')
  }
  if (typeof spawnImpl !== 'function') fail('Frida spawn implementation is required')

  const result = await spawnImpl(executable, args, {
    cwd: workingDirectory,
    env: sanitizedProcessEnvironment(),
    timeout,
    maxBuffer: outputLimit,
    shell: false,
    windowsHide: true,
    killSignal: 'SIGKILL',
  })
  if (result === null || typeof result !== 'object' || Array.isArray(result)) {
    fail('Frida process returned an invalid result', 'FRIDA_PROCESS_INVALID')
  }
  const stdout = Buffer.isBuffer(result.stdout)
    ? result.stdout
    : Buffer.from(String(result.stdout ?? ''), 'utf8')
  const stderr = Buffer.isBuffer(result.stderr)
    ? result.stderr
    : Buffer.from(String(result.stderr ?? ''), 'utf8')
  if (stdout.length + stderr.length > outputLimit || result.outputLimitExceeded === true) {
    fail('Frida process output exceeds its combined byte limit', 'FRIDA_OUTPUT_TOO_LARGE')
  }
  if (result.timedOut === true) fail('Frida trace timed out', 'FRIDA_PROCESS_TIMEOUT')
  if (result.spawnError === true) fail('Frida process could not be started', 'FRIDA_PROCESS_FAILED')
  if (!Number.isSafeInteger(result.code)) {
    fail('Frida process returned an invalid exit code', 'FRIDA_PROCESS_INVALID')
  }
  if (result.code !== 0) {
    fail(`Frida exited with code ${result.code}`, 'FRIDA_PROCESS_FAILED')
  }
  if (result.terminationConfirmed !== true) {
    fail('Frida process-tree termination was not confirmed', 'FRIDA_TERMINATION_UNCONFIRMED')
  }
  const parsed = parseFridaOutput(stdout, {
    maxEvents: parameters.maxEvents,
    maxBytes: outputLimit,
    expectedFrameNonce: parameters.frameNonce,
  })
  const ready = parsed.events[0]
  if (
    ready?.event !== 'ready'
    || ready.module_name !== parameters.moduleName
    || ready.symbol_name !== parameters.symbolName
  ) {
    fail(
      'Frida ready module or symbol does not match the requested fixed trace',
      'FRIDA_OUTPUT_MISMATCH',
    )
  }
  return {
    ...parsed,
    process_exit_code: result.code,
    stderr_bytes: stderr.length,
  }
}

export {
  FRIDA_TRACE_PLAN_KIND,
  FRIDA_V2_AGENT_PATH,
  FRIDA_V2_PROFILE_ID,
  assertValidFridaTracePlan,
  buildFridaTracePlanArguments,
  canonicalFridaTracePlan,
  digestFridaTracePlan,
  parseFridaTracePlanOutput,
  runFridaTracePlan,
} from './reverse-frida-v2.mjs'
