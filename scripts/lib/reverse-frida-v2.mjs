import { createHash } from 'node:crypto'
import { extname, isAbsolute, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  runSupervisedProcess,
  sanitizedProcessEnvironment,
} from './reverse-process.mjs'
import { stableJson } from './run-engine.mjs'

export const FRIDA_V2_PROFILE_ID = 'native-call-trace-v2'
export const FRIDA_TRACE_PLAN_KIND = 'red-team-audit/frida-trace-plan'
export const FRIDA_V2_AGENT_PATH = fileURLToPath(
  new URL('../frida/native-call-trace-v2.js', import.meta.url),
)

const OUTPUT_PREFIX = '[last-aperture:frida] '
const MAX_DURATION_SECONDS = 300
const MAX_TRACE_EVENTS = 9_000
const MAX_HOOKS = 256
const MAX_OUTPUT_BYTES = 64 * 1024 * 1024
const MAX_RUNNER_TIMEOUT_MS = 310_000
const FRAME_NONCE_PATTERN = /^[a-f0-9]{64}$/u
const HASH_PATTERN = /^[a-f0-9]{64}$/u
const HOOK_ID_PATTERN = /^[A-Za-z][A-Za-z0-9._:-]{0,127}$/u
const APP_IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/u
const DEVICE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u
const ADDRESS_PATTERN = /^0x(?:0|[1-9a-f][0-9a-f]{0,15})$/u
const NONZERO_ADDRESS_PATTERN = /^0x[1-9a-f][0-9a-f]{0,15}$/u
const UNSAFE_TEXT_PATTERN = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u
const ARTIFACT_KINDS = new Set(['native-executable', 'shared-library', 'application-package'])
const TARGET_MODES = new Set([
  'local-spawn',
  'local-pid',
  'local-name',
  'usb-pid',
  'usb-name',
  'usb-app-identifier',
  'device-pid',
  'device-name',
  'device-app-identifier',
])
const SCALAR_CODECS = new Set([
  'pointer', 'int8', 'uint8', 'int16', 'uint16', 'int32', 'uint32',
  'int64', 'uint64', 'bool',
])
const MEMORY_CODECS = new Set(['utf8', 'utf16', 'bytes'])
const RETENTIONS = new Set(['raw', 'sha256', 'metadata'])
const MAX_CAPTURE_DESCRIPTORS = 256
const MAX_CAPTURE_RECORDS = 10_000
const MAX_CAPTURE_BYTES_TOTAL = 8 * 1024 * 1024
const MAX_FRAME_CAPTURE_BYTES = 65_536
const MAX_PARAMETER_BYTES = 64 * 1024
const MAX_WINDOWS_ARGUMENT_CHARS = 28_000

function fail(message, code = 'FRIDA_INPUT_INVALID') {
  const error = new Error(message)
  error.name = 'ReverseFridaError'
  error.code = code
  throw error
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

function localAbsolutePath(value, label) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > 4096
    || value.trim() !== value
    || UNSAFE_TEXT_PATTERN.test(value)
    || !isAbsolute(value)
    || /^(?:\\\\|\/\/)/u.test(value)
  ) fail(`${label} must be one absolute local filesystem path`)
  return resolve(value)
}

function relativeArtifactPath(value) {
  if (
    typeof value !== 'string'
    || value.length < 1
    || value.length > 2048
    || value.trim() !== value
    || UNSAFE_TEXT_PATTERN.test(value)
    || isAbsolute(value)
  ) fail('Frida plan artifact path must be one contained relative path')
  const parts = value.split(/[\\/]/u)
  if (parts.some((part) => part === '' || part === '.' || part === '..' || part.includes(':'))) {
    fail('Frida plan artifact path must be one contained relative path without traversal')
  }
  return parts.join('/')
}

function boundedText(value, label, maximum) {
  if (
    typeof value !== 'string'
    || value.length < 1
    || value.length > maximum
    || value.trim() !== value
    || value.startsWith('-')
    || UNSAFE_TEXT_PATTERN.test(value)
  ) fail(`${label} must be bounded printable text and cannot begin with a flag prefix`)
  return value
}

function boundedInteger(value, label, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${label} must be an integer from ${minimum} through ${maximum}`)
  }
  return value
}

function boundedHash(value, label) {
  if (typeof value !== 'string' || !HASH_PATTERN.test(value)) {
    fail(`${label} must be a lowercase SHA-256 digest`)
  }
  return value
}

function boundedFrameNonce(value) {
  if (typeof value !== 'string' || !FRAME_NONCE_PATTERN.test(value)) {
    fail('Frida frame nonce must be 32 random bytes encoded as lowercase hexadecimal')
  }
  return value
}

function validateArtifact(value) {
  if (!exactKeys(value, ['kind', 'lab_root', 'path'])) {
    fail('Frida plan artifact contains a missing or unknown field')
  }
  localAbsolutePath(value.lab_root, 'Frida plan artifact lab root')
  relativeArtifactPath(value.path)
  if (!ARTIFACT_KINDS.has(value.kind)) fail('Frida plan artifact kind is unsupported')
}

function validateTarget(target, artifactKind) {
  if (!target || typeof target !== 'object' || Array.isArray(target) || !TARGET_MODES.has(target.mode)) {
    fail('Frida plan target mode is unsupported')
  }
  if (target.mode === 'local-spawn') {
    if (!exactKeys(target, ['mode'])) fail('Frida local-spawn target contains an unknown field')
    if (artifactKind !== 'native-executable') {
      fail('Frida local-spawn target requires a native-executable artifact copy')
    }
    return
  }
  if (target.mode.endsWith('-pid')) {
    const fields = target.mode.startsWith('device-') ? ['device_id', 'mode', 'pid'] : ['mode', 'pid']
    if (!exactKeys(target, fields)) fail('Frida PID target contains a missing or unknown field')
    boundedInteger(target.pid, 'Frida target PID', 1, 2_147_483_647)
  } else if (target.mode.endsWith('-name')) {
    const fields = target.mode.startsWith('device-') ? ['device_id', 'mode', 'name'] : ['mode', 'name']
    if (!exactKeys(target, fields)) fail('Frida name target contains a missing or unknown field')
    boundedText(target.name, 'Frida target name', 512)
  } else {
    const fields = target.mode.startsWith('device-')
      ? ['app_identifier', 'device_id', 'mode']
      : ['app_identifier', 'mode']
    if (!exactKeys(target, fields)) fail('Frida application target contains a missing or unknown field')
    if (typeof target.app_identifier !== 'string' || !APP_IDENTIFIER_PATTERN.test(target.app_identifier)) {
      fail('Frida application identifier is invalid')
    }
  }
  if (target.mode.startsWith('device-')) {
    if (typeof target.device_id !== 'string' || !DEVICE_ID_PATTERN.test(target.device_id)) {
      fail('Frida device identifier is invalid')
    }
  }
}

function validateResolver(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('Frida hook resolver must be an object')
  }
  if (value.kind === 'export') {
    if (!exactKeys(value, ['export_name', 'kind', 'module_name'])) {
      fail('Frida export resolver contains a missing or unknown field')
    }
    boundedText(value.module_name, 'Frida resolver module name', 256)
    boundedText(value.export_name, 'Frida resolver export name', 512)
  } else if (value.kind === 'module-offset') {
    if (!exactKeys(value, ['kind', 'module_name', 'offset'])) {
      fail('Frida module-offset resolver contains a missing or unknown field')
    }
    boundedText(value.module_name, 'Frida resolver module name', 256)
    if (typeof value.offset !== 'string' || !ADDRESS_PATTERN.test(value.offset)) {
      fail('Frida resolver module offset is invalid')
    }
  } else if (value.kind === 'absolute') {
    if (!exactKeys(value, ['address', 'kind'])
      || typeof value.address !== 'string'
      || !NONZERO_ADDRESS_PATTERN.test(value.address)) {
      fail('Frida absolute resolver is invalid')
    }
  } else if (value.kind === 'debug-symbol') {
    if (!exactKeys(value, ['kind', 'module_name', 'symbol_name'])) {
      fail('Frida debug-symbol resolver contains a missing or unknown field')
    }
    boundedText(value.module_name, 'Frida resolver module name', 256)
    boundedText(value.symbol_name, 'Frida resolver debug symbol', 512)
  } else {
    fail('Frida hook resolver kind is unsupported')
  }
}

function validateLength(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('Frida memory capture length must be an object')
  }
  if (value.kind === 'fixed') {
    if (!exactKeys(value, ['bytes', 'kind'])) {
      fail('Frida fixed capture length contains a missing or unknown field')
    }
    boundedInteger(value.bytes, 'Frida fixed capture bytes', 1, 65_536)
  } else if (value.kind === 'argument') {
    if (!exactKeys(value, ['index', 'kind', 'max_bytes'])) {
      fail('Frida argument-derived capture length contains a missing or unknown field')
    }
    boundedInteger(value.index, 'Frida length argument index', 0, 31)
    boundedInteger(value.max_bytes, 'Frida capture maximum bytes', 1, 65_536)
  } else {
    fail('Frida memory capture length kind is unsupported')
  }
}

function validateCapture(value, { argument }) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('Frida capture descriptor must be an object')
  }
  const codec = value.codec
  const memory = MEMORY_CODECS.has(codec)
  if (!memory && !SCALAR_CODECS.has(codec)) fail('Frida capture codec is unsupported')
  const expected = [
    'capture_id', 'codec', 'retention',
    ...(argument ? ['index'] : []),
    ...(argument && Object.hasOwn(value, 'phase') ? ['phase'] : []),
    ...(memory ? ['length'] : []),
  ]
  if (!exactKeys(value, expected)) {
    fail('Frida capture descriptor contains a missing or unknown field')
  }
  if (typeof value.capture_id !== 'string' || !HOOK_ID_PATTERN.test(value.capture_id)) {
    fail('Frida capture ID is invalid')
  }
  if (!RETENTIONS.has(value.retention)) fail('Frida capture retention is unsupported')
  if (argument) boundedInteger(value.index, 'Frida capture argument index', 0, 31)
  if (argument && value.phase !== undefined && !['enter', 'leave'].includes(value.phase)) {
    fail('Frida argument capture phase must be enter or leave')
  }
  if (memory) validateLength(value.length)
}

function argumentCapturePhase(capture) {
  return capture.phase ?? 'enter'
}

function validateCaptureSet(value) {
  if (!exactKeys(value, ['arguments', 'return_value'])
    || !Array.isArray(value.arguments)
    || value.arguments.length > 32) {
    fail('Frida hook capture set is invalid')
  }
  const ids = new Set()
  for (const capture of value.arguments) {
    validateCapture(capture, { argument: true })
    if (ids.has(capture.capture_id)) fail('Frida capture IDs must be unique within a hook')
    ids.add(capture.capture_id)
  }
  if (value.return_value !== null) {
    validateCapture(value.return_value, { argument: false })
    if (ids.has(value.return_value.capture_id)) fail('Frida capture IDs must be unique within a hook')
  }
}

function encodeLength(length) {
  return length.kind === 'fixed'
    ? ['f', length.bytes]
    : ['a', length.index, length.max_bytes]
}

function encodeResolver(resolver) {
  if (resolver.kind === 'export') return ['e', resolver.module_name, resolver.export_name]
  if (resolver.kind === 'module-offset') return ['o', resolver.module_name, resolver.offset]
  if (resolver.kind === 'absolute') return ['a', resolver.address]
  return ['d', resolver.module_name, resolver.symbol_name]
}

function encodeArgumentCapture(capture) {
  return [
    capture.capture_id,
    capture.index,
    capture.codec,
    capture.retention,
    MEMORY_CODECS.has(capture.codec) ? encodeLength(capture.length) : null,
    argumentCapturePhase(capture) === 'enter' ? 'e' : 'l',
  ]
}

function encodeReturnCapture(capture) {
  return [
    capture.capture_id,
    capture.codec,
    capture.retention,
    MEMORY_CODECS.has(capture.codec) ? encodeLength(capture.length) : null,
  ]
}

function encodeHooks(plan) {
  return plan.hooks.map((hook) => ([
    hook.hook_id,
    encodeResolver(hook.resolver),
    hook.capture.arguments.map(encodeArgumentCapture),
    hook.capture.return_value === null ? null : encodeReturnCapture(hook.capture.return_value),
  ]))
}

function windowsArgumentLength(value) {
  if (!/[\s"]/u.test(value)) return value.length
  let length = 2
  let backslashes = 0
  for (const character of value) {
    if (character === '\\') {
      backslashes += 1
    } else if (character === '"') {
      length += (backslashes * 2) + 2
      backslashes = 0
    } else {
      length += backslashes + 1
      backslashes = 0
    }
  }
  return length + (backslashes * 2)
}

function assertBoundedNativeCommandLine(args) {
  const length = args.reduce((sum, value) => sum + windowsArgumentLength(value), 0) + args.length - 1
  if (length > MAX_WINDOWS_ARGUMENT_CHARS) {
    fail('Frida typed arguments exceed the reserved native Windows command-line limit')
  }
}

function captureMaximumBytes(capture) {
  if (capture.retention === 'metadata') return 0
  if (MEMORY_CODECS.has(capture.codec)) {
    return capture.length.kind === 'fixed' ? capture.length.bytes : capture.length.max_bytes
  }
  return 32
}

export function assertValidFridaTracePlan(value) {
  if (!exactKeys(value, [
    'artifact', 'hooks', 'kind', 'limits', 'profile_id', 'schema_version', 'target',
  ])) fail('Frida trace plan contains a missing or unknown field')
  if (
    value.schema_version !== '1.0.0'
    || value.kind !== FRIDA_TRACE_PLAN_KIND
    || value.profile_id !== FRIDA_V2_PROFILE_ID
  ) fail('Frida trace plan version, kind, or profile is invalid')
  validateArtifact(value.artifact)
  validateTarget(value.target, value.artifact.kind)
  if (!Array.isArray(value.hooks) || value.hooks.length < 1 || value.hooks.length > MAX_HOOKS) {
    fail(`Frida trace plan requires one through ${MAX_HOOKS} hooks`)
  }
  const hookIds = new Set()
  const resolvers = new Set()
  let captureDescriptors = 0
  for (const hook of value.hooks) {
    if (!exactKeys(hook, ['capture', 'hook_id', 'resolver'])) {
      fail('Frida hook contains a missing or unknown field')
    }
    if (typeof hook.hook_id !== 'string' || !HOOK_ID_PATTERN.test(hook.hook_id)) {
      fail('Frida hook ID is invalid')
    }
    validateResolver(hook.resolver)
    validateCaptureSet(hook.capture)
    captureDescriptors += hook.capture.arguments.length + (hook.capture.return_value === null ? 0 : 1)
    if (hookIds.has(hook.hook_id)) fail('Frida hook IDs must be unique')
    const target = stableJson(hook.resolver, 0)
    if (resolvers.has(target)) fail('Frida hook resolvers must be unique')
    hookIds.add(hook.hook_id)
    resolvers.add(target)
  }
  if (captureDescriptors > MAX_CAPTURE_DESCRIPTORS) {
    fail(`Frida trace plan exceeds ${MAX_CAPTURE_DESCRIPTORS} capture descriptors`)
  }
  if (!exactKeys(value.limits, [
    'duration_seconds', 'max_capture_bytes_total', 'max_capture_records',
    'max_events', 'max_frame_capture_bytes',
  ])) {
    fail('Frida trace plan limits contain a missing or unknown field')
  }
  boundedInteger(value.limits.duration_seconds, 'Frida duration seconds', 1, MAX_DURATION_SECONDS)
  boundedInteger(value.limits.max_events, 'Frida maximum events', 1, MAX_TRACE_EVENTS)
  boundedInteger(value.limits.max_capture_records, 'Frida maximum capture records', 1, MAX_CAPTURE_RECORDS)
  boundedInteger(value.limits.max_capture_bytes_total, 'Frida total capture byte limit', 1, MAX_CAPTURE_BYTES_TOTAL)
  boundedInteger(value.limits.max_frame_capture_bytes, 'Frida per-frame capture byte limit', 1, MAX_FRAME_CAPTURE_BYTES)
  for (const hook of value.hooks) {
    const enterMaximum = hook.capture.arguments
      .filter((capture) => argumentCapturePhase(capture) === 'enter')
      .reduce((sum, capture) => sum + captureMaximumBytes(capture), 0)
    const leaveArgumentMaximum = hook.capture.arguments
      .filter((capture) => argumentCapturePhase(capture) === 'leave')
      .reduce((sum, capture) => sum + captureMaximumBytes(capture), 0)
    const returnMaximum = hook.capture.return_value === null ? 0 : captureMaximumBytes(hook.capture.return_value)
    if (enterMaximum > value.limits.max_frame_capture_bytes
      || leaveArgumentMaximum + returnMaximum > value.limits.max_frame_capture_bytes) {
      fail('Frida capture descriptors exceed the per-frame capture byte limit')
    }
  }
  return value
}

export function canonicalFridaTracePlan(value) {
  assertValidFridaTracePlan(value)
  return stableJson(value, 2)
}

export function digestFridaTracePlan(value) {
  assertValidFridaTracePlan(value)
  return createHash('sha256').update(stableJson(value, 0)).digest('hex')
}

function targetArguments(target, artifactPath) {
  switch (target.mode) {
    case 'local-spawn': return ['-f', artifactPath]
    case 'local-pid': return ['-p', String(target.pid)]
    case 'local-name': return ['-n', target.name]
    case 'usb-pid': return ['-U', '-p', String(target.pid)]
    case 'usb-name': return ['-U', '-n', target.name]
    case 'usb-app-identifier': return ['-U', '-N', target.app_identifier]
    case 'device-pid': return ['-D', target.device_id, '-p', String(target.pid)]
    case 'device-name': return ['-D', target.device_id, '-n', target.name]
    case 'device-app-identifier': return ['-D', target.device_id, '-N', target.app_identifier]
    default: fail('Frida plan target mode is unsupported')
  }
}

export function buildFridaTracePlanArguments({
  plan,
  artifactPath,
  artifactSha256,
  agentPath,
  frameNonce,
} = {}) {
  assertValidFridaTracePlan(plan)
  const artifact = localAbsolutePath(artifactPath, 'Frida local artifact copy')
  const agent = localAbsolutePath(agentPath, 'Frida v2 agent')
  if (extname(agent).toLowerCase() !== '.js' || agent !== resolve(FRIDA_V2_AGENT_PATH)) {
    fail(`Frida agent must be the bundled ${FRIDA_V2_PROFILE_ID}.js profile`)
  }
  const artifactHash = boundedHash(artifactSha256, 'Frida local artifact digest')
  const nonce = boundedFrameNonce(frameNonce)
  const parameters = JSON.stringify({
    profileId: FRIDA_V2_PROFILE_ID,
    planSha256: digestFridaTracePlan(plan),
    artifactSha256: artifactHash,
    targetMode: plan.target.mode,
    hooks: encodeHooks(plan),
    durationSeconds: plan.limits.duration_seconds,
    maxEvents: plan.limits.max_events,
    maxCaptureRecords: plan.limits.max_capture_records,
    maxCaptureBytesTotal: plan.limits.max_capture_bytes_total,
    maxFrameCaptureBytes: plan.limits.max_frame_capture_bytes,
    frameNonce: nonce,
  })
  if (Buffer.byteLength(parameters, 'utf8') > MAX_PARAMETER_BYTES) {
    fail('Frida typed parameters exceed the native command-line byte limit')
  }
  const args = [
    '-q',
    '--no-auto-reload',
    '--exit-on-error',
    ...(plan.target.mode === 'local-spawn' ? ['--kill-on-exit'] : []),
    '-t', String(plan.limits.duration_seconds + 1),
    '-P', parameters,
    '-l', agent,
    ...targetArguments(plan.target, artifact),
  ]
  assertBoundedNativeCommandLine(args)
  return Object.freeze(args)
}

function parametersFromArguments(args) {
  if (!Array.isArray(args) || args.some((value) => typeof value !== 'string')) {
    fail('Frida v2 runner requires one exact argument vector')
  }
  const parameterIndexes = args.flatMap((value, index) => value === '-P' ? [index] : [])
  if (parameterIndexes.length !== 1 || parameterIndexes[0] === args.length - 1) {
    fail('Frida v2 runner requires one fixed parameter object')
  }
  let value
  try {
    value = JSON.parse(args[parameterIndexes[0] + 1])
  } catch {
    fail('Frida v2 runner parameters are not valid JSON')
  }
  if (!exactKeys(value, [
    'artifactSha256', 'durationSeconds', 'frameNonce', 'hooks', 'maxEvents',
    'maxCaptureBytesTotal', 'maxCaptureRecords', 'maxFrameCaptureBytes',
    'planSha256', 'profileId', 'targetMode',
  ])) fail('Frida v2 runner parameters contain a missing or unknown field')
  return value
}

function validateRunnerArguments(args, { plan, artifactPath, artifactSha256 }) {
  const parameters = parametersFromArguments(args)
  const expected = buildFridaTracePlanArguments({
    plan,
    artifactPath,
    artifactSha256,
    agentPath: FRIDA_V2_AGENT_PATH,
    frameNonce: parameters.frameNonce,
  })
  if (!sameStringArray(args, expected)) {
    fail('Frida v2 runner refuses altered, raw, or widened arguments')
  }
  return parameters
}

function validateCommonEvent(value, expected) {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || value.schema_version !== '1.0.0'
    || value.profile_id !== FRIDA_V2_PROFILE_ID
    || value.frame_nonce !== expected.frameNonce
    || value.plan_sha256 !== expected.planSha256
    || value.artifact_sha256 !== expected.artifactSha256
    || value.target_mode !== expected.targetMode
    || !Number.isSafeInteger(value.observed_at_ms)
    || value.observed_at_ms < 0
  ) fail('Frida v2 output contains an unbound or invalid profile frame', 'FRIDA_OUTPUT_INVALID')
}

function canonicalBase64(value) {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) {
    return false
  }
  return Buffer.from(value, 'base64').toString('base64') === value
}

function validatePointerMetadata(value, retention) {
  if (!exactKeys(value, [
    'address', 'is_null', 'module_name', 'module_relative_offset', 'protection',
  ]) || typeof value.is_null !== 'boolean'
    || (value.address !== null && (typeof value.address !== 'string' || !ADDRESS_PATTERN.test(value.address)))
    || (value.module_name !== null
      && (typeof value.module_name !== 'string' || value.module_name.length < 1 || value.module_name.length > 256 || UNSAFE_TEXT_PATTERN.test(value.module_name)))
    || (value.module_relative_offset !== null
      && (typeof value.module_relative_offset !== 'string' || !ADDRESS_PATTERN.test(value.module_relative_offset)))
    || (value.protection !== null
      && (typeof value.protection !== 'string' || !/^[r-][w-][x-]$/u.test(value.protection)))) {
    fail('Frida pointer metadata is invalid', 'FRIDA_OUTPUT_INVALID')
  }
  if ((retention === 'raw') !== (value.address !== null)
    || (value.is_null && (value.module_name !== null || value.module_relative_offset !== null || value.protection !== null))) {
    fail('Frida pointer metadata retention is inconsistent', 'FRIDA_OUTPUT_INVALID')
  }
}

function scalarWidth(codec, capturedBytes) {
  if (codec === 'pointer') return capturedBytes === 4 || capturedBytes === 8
  if (codec === 'int8' || codec === 'uint8' || codec === 'bool') return capturedBytes === 1
  if (codec === 'int16' || codec === 'uint16') return capturedBytes === 2
  if (codec === 'int32' || codec === 'uint32') return capturedBytes === 4
  return capturedBytes === 8
}

function integerInRange(value, codec) {
  const ranges = {
    int8: [-128, 127], uint8: [0, 255], int16: [-32768, 32767],
    uint16: [0, 65535], int32: [-2147483648, 2147483647], uint32: [0, 4294967295],
  }
  const [minimum, maximum] = ranges[codec]
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum
}

function validateCaptureOutcome(value) {
  if (!exactKeys(value, [
    'capture_id', 'captured_bytes', 'codec', 'error_code', 'pointer',
    'requested_bytes', 'retention', 'status', 'truncated', 'truncation_reason',
    'value', 'value_encoding',
  ]) || typeof value.capture_id !== 'string' || !HOOK_ID_PATTERN.test(value.capture_id)
    || (!SCALAR_CODECS.has(value.codec) && !MEMORY_CODECS.has(value.codec))
    || !RETENTIONS.has(value.retention)
    || !['CAPTURED', 'READ_FAILED'].includes(value.status)
    || (value.pointer !== null && (typeof value.pointer !== 'object' || Array.isArray(value.pointer)))
    || (value.requested_bytes !== null
      && (!Number.isSafeInteger(value.requested_bytes) || value.requested_bytes < 0 || value.requested_bytes > 4_294_967_295))
    || !Number.isSafeInteger(value.captured_bytes)
    || value.captured_bytes < 0
    || value.captured_bytes > 65_536
    || typeof value.truncated !== 'boolean'
    || (value.truncation_reason !== null
      && !['DECLARED_MAX', 'RANGE_BOUNDARY', 'SESSION_BUDGET', 'FRAME_BUDGET'].includes(value.truncation_reason))
    || (value.truncated !== (value.truncation_reason !== null))
    || !['none', 'base64', 'number', 'decimal', 'boolean', 'pointer', 'sha256'].includes(value.value_encoding)
    || (value.error_code !== null && !['NULL_POINTER', 'LENGTH_READ_FAILED', 'MEMORY_READ_FAILED', 'VALUE_CONVERSION_FAILED', 'CAPTURE_BUDGET_EXHAUSTED'].includes(value.error_code))) {
    fail('Frida capture outcome is invalid', 'FRIDA_OUTPUT_INVALID')
  }
  if (value.pointer !== null) validatePointerMetadata(value.pointer, value.retention)
  if (value.status === 'READ_FAILED') {
    if (value.error_code === null || value.value !== null || value.value_encoding !== 'none' || value.captured_bytes !== 0) {
      fail('Frida failed capture outcome is inconsistent', 'FRIDA_OUTPUT_INVALID')
    }
    return value
  }
  if (value.error_code !== null) fail('Frida captured outcome cannot carry an error', 'FRIDA_OUTPUT_INVALID')
  if (value.retention === 'metadata') {
    if (value.value !== null || value.value_encoding !== 'none' || value.captured_bytes !== 0) {
      fail('Frida metadata-only capture retained a value', 'FRIDA_OUTPUT_INVALID')
    }
  } else if (value.retention === 'sha256') {
    if (value.value_encoding !== 'sha256' || typeof value.value !== 'string' || !HASH_PATTERN.test(value.value)) {
      fail('Frida digest capture is invalid', 'FRIDA_OUTPUT_INVALID')
    }
    if (SCALAR_CODECS.has(value.codec) && !scalarWidth(value.codec, value.captured_bytes)) {
      fail('Frida scalar digest width is invalid', 'FRIDA_OUTPUT_INVALID')
    }
  } else if (MEMORY_CODECS.has(value.codec)) {
    if (value.value_encoding !== 'base64' || !canonicalBase64(value.value)
      || Buffer.from(value.value, 'base64').length !== value.captured_bytes) {
      fail('Frida byte capture is not canonical base64', 'FRIDA_OUTPUT_INVALID')
    }
  } else if (value.codec === 'pointer') {
    if (value.value_encoding !== 'pointer'
      || typeof value.value !== 'string'
      || !ADDRESS_PATTERN.test(value.value)
      || value.pointer?.address !== value.value) {
      fail('Frida pointer capture is invalid', 'FRIDA_OUTPUT_INVALID')
    }
  } else if (value.codec === 'bool') {
    if (value.value_encoding !== 'boolean' || typeof value.value !== 'boolean' || value.captured_bytes !== 1) {
      fail('Frida boolean capture is invalid', 'FRIDA_OUTPUT_INVALID')
    }
  } else if (value.codec === 'int64' || value.codec === 'uint64') {
    let integer
    try { integer = BigInt(value.value) } catch { integer = null }
    const minimum = value.codec === 'int64' ? -(2n ** 63n) : 0n
    const maximum = value.codec === 'int64' ? (2n ** 63n) - 1n : (2n ** 64n) - 1n
    if (value.value_encoding !== 'decimal' || typeof value.value !== 'string'
      || !/^-?(?:0|[1-9][0-9]*)$/u.test(value.value)
      || integer === null || integer < minimum || integer > maximum || value.captured_bytes !== 8) {
      fail('Frida 64-bit integer capture is invalid', 'FRIDA_OUTPUT_INVALID')
    }
  } else if (value.value_encoding !== 'number'
    || !integerInRange(value.value, value.codec)
    || !scalarWidth(value.codec, value.captured_bytes)) {
    fail('Frida integer capture is invalid', 'FRIDA_OUTPUT_INVALID')
  }
  if (MEMORY_CODECS.has(value.codec)) {
    if (value.pointer === null || value.requested_bytes === null) {
      fail('Frida memory capture metadata is incomplete', 'FRIDA_OUTPUT_INVALID')
    }
  } else if (value.requested_bytes !== null) {
    fail('Frida scalar capture cannot carry a byte length', 'FRIDA_OUTPUT_INVALID')
  }
  return value
}

function validateV2Event(value, expected) {
  validateCommonEvent(value, expected)
  const common = [
    'artifact_sha256', 'event', 'frame_nonce', 'observed_at_ms', 'plan_sha256',
    'profile_id', 'schema_version', 'target_mode',
  ]
  if (value.event === 'session-ready') {
    if (!exactKeys(value, [...common, 'hooks_expected'])
      || value.hooks_expected !== expected.hooks.length) {
      fail('Frida v2 session-ready frame is invalid', 'FRIDA_OUTPUT_INVALID')
    }
  } else if (value.event === 'hook-ready') {
    if (!exactKeys(value, [
      ...common, 'hook_id', 'module_name', 'module_relative_offset', 'resolved_address',
      'resolver_kind', 'symbol_name',
    ]) || !['export', 'module-offset', 'absolute', 'debug-symbol'].includes(value.resolver_kind)
      || (value.module_name !== null && (typeof value.module_name !== 'string' || value.module_name.length > 256))
      || (value.symbol_name !== null && (typeof value.symbol_name !== 'string' || value.symbol_name.length > 512))
      || (value.module_relative_offset !== null
        && (typeof value.module_relative_offset !== 'string' || !ADDRESS_PATTERN.test(value.module_relative_offset)))
      || typeof value.resolved_address !== 'string'
      || !ADDRESS_PATTERN.test(value.resolved_address)) {
      fail('Frida v2 hook-ready frame is invalid', 'FRIDA_OUTPUT_INVALID')
    }
  } else if (value.event === 'enter' || value.event === 'leave') {
    if (!exactKeys(value, [...common, 'call_id', 'captures', 'hook_id', 'sequence', 'thread_id'])
      || !Number.isSafeInteger(value.call_id) || value.call_id < 1
      || !Number.isSafeInteger(value.sequence) || value.sequence < 1
      || !Number.isSafeInteger(value.thread_id) || value.thread_id < 0
      || !Array.isArray(value.captures)
      || value.captures.length > 33) {
      fail('Frida v2 call frame is invalid', 'FRIDA_OUTPUT_INVALID')
    }
    value.captures.forEach(validateCaptureOutcome)
  } else if (value.event === 'complete') {
    if (!exactKeys(value, [
      ...common, 'capture_attempts', 'capture_failures', 'capture_truncations',
      'captured_payload_bytes', 'events_emitted', 'hooks_detached', 'hooks_ready', 'truncated',
    ]) || !Number.isSafeInteger(value.events_emitted) || value.events_emitted < 0
      || !Number.isSafeInteger(value.hooks_ready) || value.hooks_ready < 0
      || !Number.isSafeInteger(value.hooks_detached) || value.hooks_detached < 0
      || !Number.isSafeInteger(value.capture_attempts) || value.capture_attempts < 0
      || !Number.isSafeInteger(value.capture_failures) || value.capture_failures < 0
      || !Number.isSafeInteger(value.capture_truncations) || value.capture_truncations < 0
      || !Number.isSafeInteger(value.captured_payload_bytes) || value.captured_payload_bytes < 0
      || typeof value.truncated !== 'boolean') {
      fail('Frida v2 complete frame is invalid', 'FRIDA_OUTPUT_INVALID')
    }
  } else {
    fail('Frida v2 output contains an unknown frame kind', 'FRIDA_OUTPUT_INVALID')
  }
  return value
}

function hookReadyMatchesResolver(value, resolver) {
  if (value.resolver_kind !== resolver.kind) return false
  if (resolver.kind === 'export') {
    return value.module_name === resolver.module_name
      && value.symbol_name === resolver.export_name
      && value.module_relative_offset !== null
  }
  if (resolver.kind === 'module-offset') {
    return value.module_name === resolver.module_name
      && value.symbol_name === null
      && value.module_relative_offset === resolver.offset
  }
  if (resolver.kind === 'absolute') {
    return value.symbol_name === null && value.resolved_address === resolver.address
  }
  return value.module_name === resolver.module_name
    && value.symbol_name === resolver.symbol_name
    && value.module_relative_offset !== null
}

function validateOutcomesAgainstPlan(outcomes, descriptors) {
  if (outcomes.length !== descriptors.length) {
    fail('Frida capture outcomes do not match the declared capture set', 'FRIDA_OUTPUT_MISMATCH')
  }
  let failures = 0
  let truncations = 0
  for (const [index, outcome] of outcomes.entries()) {
    const descriptor = descriptors[index]
    if (outcome.capture_id !== descriptor.capture_id
      || outcome.codec !== descriptor.codec
      || outcome.retention !== descriptor.retention) {
      fail('Frida capture outcome does not match its declared descriptor', 'FRIDA_OUTPUT_MISMATCH')
    }
    if (outcome.status === 'READ_FAILED') failures += 1
    if (outcome.truncated) truncations += 1
    if (MEMORY_CODECS.has(descriptor.codec) && outcome.status === 'CAPTURED') {
      const maximum = descriptor.length.kind === 'fixed'
        ? descriptor.length.bytes
        : descriptor.length.max_bytes
      if (outcome.requested_bytes === null
        || outcome.captured_bytes > maximum
        || (outcome.requested_bytes > maximum && outcome.truncated !== true)
        || (descriptor.length.kind === 'fixed' && outcome.requested_bytes !== descriptor.length.bytes)
        || (descriptor.retention !== 'metadata'
          && (outcome.captured_bytes > Math.min(outcome.requested_bytes, maximum)
            || (outcome.captured_bytes < Math.min(outcome.requested_bytes, maximum) && outcome.truncated !== true)))) {
        fail('Frida memory capture bounds do not match the plan', 'FRIDA_OUTPUT_INVALID')
      }
    }
  }
  return { attempts: outcomes.length, failures, truncations }
}

export function parseFridaTracePlanOutput(text, {
  plan,
  artifactSha256,
  expectedFrameNonce,
  maxBytes,
} = {}) {
  assertValidFridaTracePlan(plan)
  const byteLimit = boundedInteger(maxBytes, 'Frida output byte limit', 1, MAX_OUTPUT_BYTES)
  const expected = {
    frameNonce: boundedFrameNonce(expectedFrameNonce),
    planSha256: digestFridaTracePlan(plan),
    artifactSha256: boundedHash(artifactSha256, 'Frida local artifact digest'),
    targetMode: plan.target.mode,
    hooks: plan.hooks,
  }
  if (typeof text !== 'string' && !Buffer.isBuffer(text)) {
    fail('Frida output must be text or bytes', 'FRIDA_OUTPUT_INVALID')
  }
  const bytes = Buffer.isBuffer(text) ? text : Buffer.from(text, 'utf8')
  if (bytes.length > byteLimit) fail('Frida output exceeds its byte limit', 'FRIDA_OUTPUT_TOO_LARGE')
  const events = []
  const activeCalls = new Map()
  const usedCallIds = new Set()
  let ignoredLines = 0
  let previousObservedAt = -1
  let observationStart
  let observationEnd
  let sessionReady = false
  let hooksReady = 0
  let traceEvents = 0
  let complete = false
  let truncated = false
  let nextCallId = 1
  let captureAttempts = 0
  let captureFailures = 0
  let captureTruncations = 0
  let capturedPayloadBytes = 0

  for (const line of bytes.toString('utf8').split(/\r?\n/u)) {
    if (line.length === 0) continue
    if (UNSAFE_TEXT_PATTERN.test(line)) {
      fail('Frida output contains control or bidirectional formatting text', 'FRIDA_OUTPUT_INVALID')
    }
    if (!line.startsWith(OUTPUT_PREFIX)) {
      ignoredLines += 1
      continue
    }
    if (complete) fail('Frida v2 output contains frames after complete', 'FRIDA_OUTPUT_INVALID')
    let parsed
    try {
      parsed = JSON.parse(line.slice(OUTPUT_PREFIX.length))
    } catch {
      fail('Frida output contains malformed framed JSON', 'FRIDA_OUTPUT_INVALID')
    }
    const value = validateV2Event(parsed, expected)
    if (value.observed_at_ms < previousObservedAt) {
      fail('Frida frame observation times must be nondecreasing', 'FRIDA_OUTPUT_INVALID')
    }
    previousObservedAt = value.observed_at_ms
    observationStart ??= value.observed_at_ms
    observationEnd = value.observed_at_ms

    if (value.event === 'session-ready') {
      if (sessionReady || events.length !== 0) {
        fail('Frida session-ready frame must be first and unique', 'FRIDA_OUTPUT_INVALID')
      }
      sessionReady = true
    } else if (value.event === 'hook-ready') {
      if (!sessionReady || hooksReady >= plan.hooks.length || traceEvents > 0) {
        fail('Frida hook-ready lifecycle order is invalid', 'FRIDA_OUTPUT_INVALID')
      }
      const hook = plan.hooks[hooksReady]
      if (value.hook_id !== hook.hook_id
        || !hookReadyMatchesResolver(value, hook.resolver)) {
        fail('Frida hook-ready frame does not match the declared hook order', 'FRIDA_OUTPUT_MISMATCH')
      }
      hooksReady += 1
    } else if (value.event === 'enter' || value.event === 'leave') {
      if (hooksReady !== plan.hooks.length || value.sequence !== traceEvents + 1) {
        fail('Frida call frame lifecycle or sequence is invalid', 'FRIDA_OUTPUT_INVALID')
      }
      const hook = plan.hooks.find(({ hook_id: hookId }) => hookId === value.hook_id)
      if (!hook) fail('Frida call frame names an undeclared hook', 'FRIDA_OUTPUT_MISMATCH')
      const descriptors = value.event === 'enter'
        ? hook.capture.arguments.filter((capture) => argumentCapturePhase(capture) === 'enter')
        : [
            ...hook.capture.arguments.filter((capture) => argumentCapturePhase(capture) === 'leave'),
            ...(hook.capture.return_value === null ? [] : [hook.capture.return_value]),
          ]
      const captureCounts = validateOutcomesAgainstPlan(value.captures, descriptors)
      captureAttempts += captureCounts.attempts
      captureFailures += captureCounts.failures
      captureTruncations += captureCounts.truncations
      capturedPayloadBytes += value.captures.reduce((sum, outcome) => sum + outcome.captured_bytes, 0)
      if (capturedPayloadBytes > plan.limits.max_capture_bytes_total) {
        fail('Frida total captured payload exceeds the plan limit', 'FRIDA_OUTPUT_TOO_LARGE')
      }
      traceEvents += 1
      if (traceEvents > plan.limits.max_events) {
        fail('Frida trace event limit exceeded', 'FRIDA_OUTPUT_TOO_LARGE')
      }
      if (value.event === 'enter') {
        if (value.call_id !== nextCallId || usedCallIds.has(value.call_id)) {
          fail('Frida enter frame call ID is invalid', 'FRIDA_OUTPUT_INVALID')
        }
        nextCallId += 1
        usedCallIds.add(value.call_id)
        activeCalls.set(value.call_id, { hookId: value.hook_id, threadId: value.thread_id })
      } else {
        const active = activeCalls.get(value.call_id)
        if (!active || active.hookId !== value.hook_id || active.threadId !== value.thread_id) {
          fail('Frida leave frame does not match an active call', 'FRIDA_OUTPUT_INVALID')
        }
        activeCalls.delete(value.call_id)
      }
    } else {
      if (!sessionReady
        || hooksReady !== plan.hooks.length
        || value.hooks_ready !== hooksReady
        || value.hooks_detached !== hooksReady
        || value.events_emitted !== traceEvents
        || value.capture_attempts !== captureAttempts
        || value.capture_failures !== captureFailures
        || value.capture_truncations !== captureTruncations
        || value.captured_payload_bytes !== capturedPayloadBytes
        || value.capture_attempts > plan.limits.max_capture_records
        || (activeCalls.size > 0 && value.truncated !== true)) {
        fail('Frida complete frame does not match the traced lifecycle', 'FRIDA_OUTPUT_INVALID')
      }
      complete = true
      truncated = value.truncated
    }
    events.push(value)
  }
  if (!sessionReady || hooksReady !== plan.hooks.length || !complete) {
    fail('Frida output is missing its complete hook lifecycle', 'FRIDA_OUTPUT_INVALID')
  }
  return {
    profile_id: FRIDA_V2_PROFILE_ID,
    session_ready: true,
    hooks_ready: hooksReady,
    complete: true,
    trace_events: traceEvents,
    capture_attempts: captureAttempts,
    capture_failures: captureFailures,
    capture_truncations: captureTruncations,
    captured_payload_bytes: capturedPayloadBytes,
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

export async function runFridaTracePlan({
  fridaPath,
  args,
  plan,
  artifactPath,
  artifactSha256,
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
  const parameters = validateRunnerArguments(args, { plan, artifactPath, artifactSha256 })
  const timeout = boundedInteger(timeoutMs, 'Frida runner timeout', 1, MAX_RUNNER_TIMEOUT_MS)
  const outputLimit = boundedInteger(maxOutputBytes, 'Frida output byte limit', 1, MAX_OUTPUT_BYTES)
  if (timeout < (parameters.durationSeconds + 1) * 1000) {
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
  const stdout = Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.from(String(result.stdout ?? ''), 'utf8')
  const stderr = Buffer.isBuffer(result.stderr) ? result.stderr : Buffer.from(String(result.stderr ?? ''), 'utf8')
  if (stdout.length + stderr.length > outputLimit || result.outputLimitExceeded === true) {
    fail('Frida process output exceeds its combined byte limit', 'FRIDA_OUTPUT_TOO_LARGE')
  }
  if (result.timedOut === true) fail('Frida trace timed out', 'FRIDA_PROCESS_TIMEOUT')
  if (result.spawnError === true) fail('Frida process could not be started', 'FRIDA_PROCESS_FAILED')
  if (!Number.isSafeInteger(result.code)) fail('Frida process returned an invalid exit code', 'FRIDA_PROCESS_INVALID')
  if (result.code !== 0) fail(`Frida exited with code ${result.code}`, 'FRIDA_PROCESS_FAILED')
  if (result.terminationConfirmed !== true) {
    fail('Frida process-tree termination was not confirmed', 'FRIDA_TERMINATION_UNCONFIRMED')
  }
  const parsed = parseFridaTracePlanOutput(stdout, {
    plan,
    artifactSha256,
    expectedFrameNonce: parameters.frameNonce,
    maxBytes: outputLimit,
  })
  return {
    ...parsed,
    process_exit_code: result.code,
    stderr_bytes: stderr.length,
    termination_confirmed: true,
  }
}
