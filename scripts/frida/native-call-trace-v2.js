'use strict'

const PROFILE_ID = 'native-call-trace-v2'
const OUTPUT_PREFIX = '[last-aperture:frida] '
const MAX_DURATION_SECONDS = 300
const MAX_EVENTS = 9000
const MAX_HOOKS = 256
const MAX_CAPTURE_BYTES = 65536
const HASH_PATTERN = /^[a-f0-9]{64}$/
const ID_PATTERN = /^[A-Za-z][A-Za-z0-9._:-]{0,127}$/
const ADDRESS_PATTERN = /^0x(?:0|[1-9a-f][0-9a-f]{0,15})$/
const NONZERO_ADDRESS_PATTERN = /^0x[1-9a-f][0-9a-f]{0,15}$/
const UNSAFE_TEXT_PATTERN = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/
const SCALAR_CODECS = new Set(['pointer', 'int8', 'uint8', 'int16', 'uint16', 'int32', 'uint32', 'int64', 'uint64', 'bool'])
const MEMORY_CODECS = new Set(['utf8', 'utf16', 'bytes'])
const RETENTIONS = new Set(['raw', 'sha256', 'metadata'])

function exactKeys(value, expected) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const actual = Object.keys(value).sort()
  const wanted = expected.slice().sort()
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index])
}

function boundedText(value, maximum) {
  return typeof value === 'string' && value.length > 0 && value.length <= maximum
    && value.trim() === value && !value.startsWith('-') && !UNSAFE_TEXT_PATTERN.test(value)
}

function validLength(length) {
  return (exactKeys(length, ['bytes', 'kind']) && length.kind === 'fixed'
      && Number.isInteger(length.bytes) && length.bytes >= 1 && length.bytes <= MAX_CAPTURE_BYTES)
    || (exactKeys(length, ['index', 'kind', 'max_bytes']) && length.kind === 'argument'
      && Number.isInteger(length.index) && length.index >= 0 && length.index <= 31
      && Number.isInteger(length.max_bytes) && length.max_bytes >= 1 && length.max_bytes <= MAX_CAPTURE_BYTES)
}

function validCapture(capture, argument) {
  if (capture === null || typeof capture !== 'object' || Array.isArray(capture)) return false
  const memory = MEMORY_CODECS.has(capture.codec)
  if (!memory && !SCALAR_CODECS.has(capture.codec)) return false
  const fields = ['capture_id', 'codec', 'retention', ...(argument ? ['index', 'phase'] : []), ...(memory ? ['length'] : [])]
  return exactKeys(capture, fields) && ID_PATTERN.test(capture.capture_id)
    && RETENTIONS.has(capture.retention)
    && (!argument || Number.isInteger(capture.index) && capture.index >= 0 && capture.index <= 31)
    && (!argument || capture.phase === 'enter' || capture.phase === 'leave')
    && (!memory || validLength(capture.length))
}

function validResolver(resolver) {
  if (resolver === null || typeof resolver !== 'object' || Array.isArray(resolver)) return false
  if (resolver.kind === 'export') {
    return exactKeys(resolver, ['export_name', 'kind', 'module_name'])
      && boundedText(resolver.module_name, 256) && boundedText(resolver.export_name, 512)
  }
  if (resolver.kind === 'module-offset') {
    return exactKeys(resolver, ['kind', 'module_name', 'offset'])
      && boundedText(resolver.module_name, 256) && ADDRESS_PATTERN.test(resolver.offset)
  }
  if (resolver.kind === 'absolute') return exactKeys(resolver, ['address', 'kind']) && NONZERO_ADDRESS_PATTERN.test(resolver.address)
  if (resolver.kind === 'debug-symbol') {
    return exactKeys(resolver, ['kind', 'module_name', 'symbol_name'])
      && boundedText(resolver.module_name, 256) && boundedText(resolver.symbol_name, 512)
  }
  return false
}

function decodeLength(value) {
  if (!Array.isArray(value)) return { invalid: true }
  if (value.length === 2 && value[0] === 'f') return { kind: 'fixed', bytes: value[1] }
  if (value.length === 3 && value[0] === 'a') return { kind: 'argument', index: value[1], max_bytes: value[2] }
  return { invalid: true }
}

function decodeResolver(value) {
  if (!Array.isArray(value)) return { invalid: true }
  if (value.length === 3 && value[0] === 'e') return { kind: 'export', module_name: value[1], export_name: value[2] }
  if (value.length === 3 && value[0] === 'o') return { kind: 'module-offset', module_name: value[1], offset: value[2] }
  if (value.length === 2 && value[0] === 'a') return { kind: 'absolute', address: value[1] }
  if (value.length === 3 && value[0] === 'd') return { kind: 'debug-symbol', module_name: value[1], symbol_name: value[2] }
  return { invalid: true }
}

function decodeArgumentCapture(value) {
  if (!Array.isArray(value) || value.length !== 6 || !['e', 'l'].includes(value[5])) return { invalid: true }
  const capture = {
    capture_id: value[0], index: value[1], codec: value[2], retention: value[3],
    phase: value[5] === 'e' ? 'enter' : 'leave',
  }
  if (value[4] !== null) capture.length = decodeLength(value[4])
  return capture
}

function decodeReturnCapture(value) {
  if (!Array.isArray(value) || value.length !== 4) return { invalid: true }
  const capture = { capture_id: value[0], codec: value[1], retention: value[2] }
  if (value[3] !== null) capture.length = decodeLength(value[3])
  return capture
}

function decodeHook(value) {
  if (!Array.isArray(value) || value.length !== 4 || !Array.isArray(value[2])) return { invalid: true }
  return {
    hookId: value[0],
    resolver: decodeResolver(value[1]),
    capture: {
      arguments: value[2].map(decodeArgumentCapture),
      returnValue: value[3] === null ? null : decodeReturnCapture(value[3]),
    },
  }
}

function validHook(hook, ids, resolvers) {
  if (!exactKeys(hook, ['capture', 'hookId', 'resolver']) || !ID_PATTERN.test(hook.hookId)
    || !validResolver(hook.resolver) || !exactKeys(hook.capture, ['arguments', 'returnValue'])
    || !Array.isArray(hook.capture.arguments) || hook.capture.arguments.length > 32
    || !hook.capture.arguments.every((capture) => validCapture(capture, true))
    || (hook.capture.returnValue !== null && !validCapture(hook.capture.returnValue, false))) return false
  const captureIds = hook.capture.arguments.map((capture) => capture.capture_id)
  if (hook.capture.returnValue !== null) captureIds.push(hook.capture.returnValue.capture_id)
  const resolverKey = JSON.stringify(hook.resolver)
  if (new Set(captureIds).size !== captureIds.length || ids.has(hook.hookId) || resolvers.has(resolverKey)) return false
  ids.add(hook.hookId)
  resolvers.add(resolverKey)
  return true
}

function loadConfiguration(parametersValue) {
  const parameters = parametersValue
  if (!exactKeys(parameters, [
    'profileId', 'planSha256', 'artifactSha256', 'targetMode', 'hooks',
    'durationSeconds', 'maxEvents', 'maxCaptureRecords', 'maxCaptureBytesTotal',
    'maxFrameCaptureBytes', 'frameNonce',
  ])) {
    throw new Error('invalid typed profile parameters')
  }
  if (parameters.profileId !== PROFILE_ID || !HASH_PATTERN.test(parameters.planSha256)
    || !HASH_PATTERN.test(parameters.artifactSha256) || !boundedText(parameters.targetMode, 64)
    || !HASH_PATTERN.test(parameters.frameNonce) || !Array.isArray(parameters.hooks)
    || parameters.hooks.length < 1 || parameters.hooks.length > MAX_HOOKS
    || !Number.isInteger(parameters.durationSeconds) || parameters.durationSeconds < 1 || parameters.durationSeconds > MAX_DURATION_SECONDS
    || !Number.isInteger(parameters.maxEvents) || parameters.maxEvents < 1 || parameters.maxEvents > MAX_EVENTS
    || !Number.isInteger(parameters.maxCaptureRecords) || parameters.maxCaptureRecords < 1 || parameters.maxCaptureRecords > 10000
    || !Number.isInteger(parameters.maxCaptureBytesTotal) || parameters.maxCaptureBytesTotal < 1 || parameters.maxCaptureBytesTotal > 8388608
    || !Number.isInteger(parameters.maxFrameCaptureBytes) || parameters.maxFrameCaptureBytes < 1 || parameters.maxFrameCaptureBytes > 65536) {
    throw new Error('invalid typed profile parameter values')
  }
  const hooks = parameters.hooks.map(decodeHook)
  const ids = new Set()
  const resolvers = new Set()
  if (!hooks.every((hook) => validHook(hook, ids, resolvers))) throw new Error('invalid typed hook parameters')
  return { ...parameters, hooks }
}

let configuration = null
let lastObservedAt = 0

function emit(value) {
  const observedAt = Math.max(lastObservedAt, Date.now())
  lastObservedAt = observedAt
  console.log(`${OUTPUT_PREFIX}${JSON.stringify({
    schema_version: '1.0.0', profile_id: PROFILE_ID, frame_nonce: configuration.frameNonce,
    plan_sha256: configuration.planSha256, artifact_sha256: configuration.artifactSha256,
    target_mode: configuration.targetMode, ...value, observed_at_ms: observedAt,
  })}`)
}

function moduleForName(name) {
  const mainModule = Process.mainModule
  return name === '<main>' || name === mainModule.name ? mainModule : Process.getModuleByName(name)
}

function moduleMetadata(address) {
  const module = Process.findModuleByAddress(address)
  return module === null ? { moduleName: null, moduleRelativeOffset: null }
    : { moduleName: module.name, moduleRelativeOffset: address.sub(module.base).toString() }
}

function resolveHook(hook) {
  const resolver = hook.resolver
  if (resolver.kind === 'export') {
    const module = moduleForName(resolver.module_name)
    const address = module.findExportByName(resolver.export_name)
    if (address === null) throw new Error('requested exported symbol is unavailable')
    const moduleEnd = module.base.add(module.size)
    if (address.compare(module.base) < 0 || address.compare(moduleEnd) >= 0) throw new Error('requested exported symbol is outside the selected module')
    return { hook, address, moduleName: resolver.module_name, symbolName: resolver.export_name, moduleRelativeOffset: address.sub(module.base).toString() }
  }
  if (resolver.kind === 'module-offset') {
    const module = moduleForName(resolver.module_name)
    const address = module.base.add(ptr(resolver.offset))
    const moduleEnd = module.base.add(module.size)
    if (address.compare(module.base) < 0 || address.compare(moduleEnd) >= 0) throw new Error('requested module offset is outside the selected module')
    return { hook, address, moduleName: resolver.module_name, symbolName: null, moduleRelativeOffset: resolver.offset }
  }
  if (resolver.kind === 'absolute') {
    const address = ptr(resolver.address)
    if (address.isNull()) throw new Error('requested absolute address is null')
    return { hook, address, symbolName: null, ...moduleMetadata(address) }
  }
  const module = moduleForName(resolver.module_name)
  const moduleEnd = module.base.add(module.size)
  const matches = DebugSymbol.findFunctionsNamed(resolver.symbol_name).filter((address) => (
    address.compare(module.base) >= 0 && address.compare(moduleEnd) < 0
  ))
  if (matches.length !== 1) throw new Error('requested debug symbol is unavailable or ambiguous')
  const address = matches[0]
  return {
    hook, address, moduleName: resolver.module_name, symbolName: resolver.symbol_name,
    moduleRelativeOffset: address.sub(module.base).toString(),
  }
}

function initialize(parametersValue) {
  if (configuration !== null) throw new Error('typed profile was already initialized')
  configuration = loadConfiguration(parametersValue)
  const resolvedHooks = configuration.hooks.map(resolveHook)
for (const resolved of resolvedHooks) {
  const executableRange = Process.findRangeByAddress(resolved.address)
  if (executableRange === null || !executableRange.protection.includes('x')) {
    throw new Error('requested hook address is not in an executable memory range')
  }
}
emit({ event: 'session-ready', hooks_expected: resolvedHooks.length })
for (const resolved of resolvedHooks) {
  emit({
    event: 'hook-ready', hook_id: resolved.hook.hookId, resolver_kind: resolved.hook.resolver.kind,
    module_name: resolved.moduleName, symbol_name: resolved.symbolName,
    module_relative_offset: resolved.moduleRelativeOffset, resolved_address: resolved.address.toString(),
  })
}

let emittedEvents = 0
let nextCallId = 1
let truncated = false
let captureAttempts = 0
let captureFailures = 0
let captureTruncations = 0
let capturedPayloadBytes = 0
let frameCaptureBytes = 0
let reservedReturnCaptures = 0
const activeCalls = new Set()
const listeners = []

function arrayBufferToBase64(buffer) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  const bytes = new Uint8Array(buffer)
  let result = ''
  for (let index = 0; index < bytes.length; index += 3) {
    const first = bytes[index]
    const second = index + 1 < bytes.length ? bytes[index + 1] : 0
    const third = index + 2 < bytes.length ? bytes[index + 2] : 0
    const combined = first << 16 | second << 8 | third
    result += alphabet[(combined >>> 18) & 63]
    result += alphabet[(combined >>> 12) & 63]
    result += index + 1 < bytes.length ? alphabet[(combined >>> 6) & 63] : '='
    result += index + 2 < bytes.length ? alphabet[combined & 63] : '='
  }
  return result
}

function asciiBuffer(value) {
  const text = String(value)
  const buffer = new ArrayBuffer(text.length)
  const bytes = new Uint8Array(buffer)
  for (let index = 0; index < text.length; index += 1) bytes[index] = text.charCodeAt(index) & 0x7f
  return buffer
}

function capturedOutcome(capture, details) {
  captureAttempts += 1
  if (details.status === 'READ_FAILED') captureFailures += 1
  if (details.truncated) captureTruncations += 1
  capturedPayloadBytes += details.capturedBytes
  frameCaptureBytes += details.capturedBytes
  return {
    capture_id: capture.capture_id, codec: capture.codec, retention: capture.retention,
    status: details.status, pointer: details.pointer, requested_bytes: details.requestedBytes,
    captured_bytes: details.capturedBytes, truncated: details.truncated,
    truncation_reason: details.truncated ? details.truncationReason : null,
    value_encoding: details.valueEncoding, value: details.value, error_code: details.errorCode,
  }
}

function pointerMetadata(pointerValue, retention) {
  const isNull = pointerValue.isNull()
  const module = isNull ? null : Process.findModuleByAddress(pointerValue)
  const range = isNull ? null : Process.findRangeByAddress(pointerValue)
  return {
    is_null: isNull,
    address: retention === 'raw' ? pointerValue.toString() : null,
    module_name: module?.name ?? null,
    module_relative_offset: module === null ? null : pointerValue.sub(module.base).toString(),
    protection: range?.protection ?? null,
  }
}

function remainingCaptureBytes() {
  return Math.max(0, Math.min(
    configuration.maxCaptureBytesTotal - capturedPayloadBytes,
    configuration.maxFrameCaptureBytes - frameCaptureBytes,
  ))
}

function budgetTruncationReason() {
  return capturedPayloadBytes >= configuration.maxCaptureBytesTotal
    ? 'SESSION_BUDGET'
    : 'FRAME_BUDGET'
}

function failedCapture(capture, pointerValue, requestedBytes, truncatedValue, errorCode, truncationReason = null) {
  return capturedOutcome(capture, {
    status: 'READ_FAILED', pointer: pointerValue, requestedBytes, capturedBytes: 0,
    truncated: truncatedValue, truncationReason, valueEncoding: 'none', value: null, errorCode,
  })
}

function scalarValue(pointerValue, codec) {
  const unsigned = pointerValue.toUInt32()
  if (codec === 'pointer') return { encoding: 'pointer', value: pointerValue.toString(), bytes: Process.pointerSize }
  if (codec === 'bool') return { encoding: 'boolean', value: !pointerValue.isNull(), bytes: 1 }
  if (codec === 'int8') return { encoding: 'number', value: (unsigned & 0x80) === 0 ? unsigned & 0xff : (unsigned & 0xff) - 0x100, bytes: 1 }
  if (codec === 'uint8') return { encoding: 'number', value: unsigned & 0xff, bytes: 1 }
  if (codec === 'int16') return { encoding: 'number', value: (unsigned & 0x8000) === 0 ? unsigned & 0xffff : (unsigned & 0xffff) - 0x10000, bytes: 2 }
  if (codec === 'uint16') return { encoding: 'number', value: unsigned & 0xffff, bytes: 2 }
  if (codec === 'int32') return { encoding: 'number', value: pointerValue.toInt32(), bytes: 4 }
  if (codec === 'uint32') return { encoding: 'number', value: unsigned, bytes: 4 }
  if (codec === 'int64') return { encoding: 'decimal', value: int64(pointerValue.toString()).toString(), bytes: 8 }
  return { encoding: 'decimal', value: uint64(pointerValue.toString()).toString(), bytes: 8 }
}

function captureScalar(capture, pointerValue) {
  const pointerDetails = capture.codec === 'pointer' ? pointerMetadata(pointerValue, capture.retention) : null
  try {
    const scalar = scalarValue(pointerValue, capture.codec)
    if (capture.retention === 'metadata') return capturedOutcome(capture, { status: 'CAPTURED', pointer: pointerDetails, requestedBytes: null, capturedBytes: 0, truncated: false, truncationReason: null, valueEncoding: 'none', value: null, errorCode: null })
    if (capture.retention === 'sha256') {
      const bytes = asciiBuffer(scalar.value)
      if (remainingCaptureBytes() < bytes.byteLength) return failedCapture(capture, pointerDetails, null, true, 'CAPTURE_BUDGET_EXHAUSTED', budgetTruncationReason())
      return capturedOutcome(capture, { status: 'CAPTURED', pointer: pointerDetails, requestedBytes: null, capturedBytes: scalar.bytes, truncated: false, truncationReason: null, valueEncoding: 'sha256', value: Checksum.compute('sha256', bytes), errorCode: null })
    }
    if (remainingCaptureBytes() < scalar.bytes) return failedCapture(capture, pointerDetails, null, true, 'CAPTURE_BUDGET_EXHAUSTED', budgetTruncationReason())
    return capturedOutcome(capture, { status: 'CAPTURED', pointer: pointerDetails, requestedBytes: null, capturedBytes: scalar.bytes, truncated: false, truncationReason: null, valueEncoding: scalar.encoding, value: scalar.value, errorCode: null })
  } catch (_) {
    return failedCapture(capture, pointerDetails, null, false, 'VALUE_CONVERSION_FAILED')
  }
}

function captureMemory(capture, pointerValue, invocationArguments) {
  const pointerDetails = pointerMetadata(pointerValue, capture.retention)
  if (pointerValue.isNull()) return failedCapture(capture, pointerDetails, null, false, 'NULL_POINTER')
  let requestedBytes
  let maximumBytes
  try {
    if (capture.length.kind === 'fixed') {
      requestedBytes = capture.length.bytes
      maximumBytes = requestedBytes
    } else {
      requestedBytes = invocationArguments[capture.length.index].toUInt32()
      maximumBytes = capture.length.max_bytes
    }
  } catch (_) {
    return failedCapture(capture, pointerDetails, null, false, 'LENGTH_READ_FAILED')
  }
  const plannedBytes = Math.min(requestedBytes, maximumBytes)
  let truncationReason = requestedBytes > maximumBytes ? 'DECLARED_MAX' : null
  if (capture.retention === 'metadata') return capturedOutcome(capture, { status: 'CAPTURED', pointer: pointerDetails, requestedBytes, capturedBytes: 0, truncated: truncationReason !== null, truncationReason, valueEncoding: 'none', value: null, errorCode: null })
  const readableRange = Process.findRangeByAddress(pointerValue)
  if (readableRange === null || !readableRange.protection.includes('r')) {
    return failedCapture(capture, pointerDetails, requestedBytes, truncationReason !== null, 'MEMORY_READ_FAILED', truncationReason)
  }
  const rangeBytes = readableRange.base.add(readableRange.size).sub(pointerValue).toUInt32()
  const rangeBoundedBytes = Math.min(plannedBytes, rangeBytes)
  if (rangeBoundedBytes < plannedBytes && truncationReason === null) truncationReason = 'RANGE_BOUNDARY'
  const availableBytes = remainingCaptureBytes()
  const captureBytes = Math.min(rangeBoundedBytes, availableBytes)
  if (captureBytes < rangeBoundedBytes && truncationReason === null) truncationReason = budgetTruncationReason()
  const wasTruncated = truncationReason !== null
  if (captureBytes === 0 && plannedBytes > 0) return failedCapture(capture, pointerDetails, requestedBytes, true, 'CAPTURE_BUDGET_EXHAUSTED', truncationReason ?? budgetTruncationReason())
  try {
    const bytes = pointerValue.readVolatile(captureBytes)
    if (bytes === null) {
      return failedCapture(
        capture,
        pointerDetails,
        requestedBytes,
        wasTruncated,
        'MEMORY_READ_FAILED',
        truncationReason,
      )
    }
    return capturedOutcome(capture, {
      status: 'CAPTURED', pointer: pointerDetails, requestedBytes, capturedBytes: bytes.byteLength,
      truncated: wasTruncated, truncationReason, valueEncoding: capture.retention === 'sha256' ? 'sha256' : 'base64',
      value: capture.retention === 'sha256' ? Checksum.compute('sha256', bytes) : arrayBufferToBase64(bytes), errorCode: null,
    })
  } catch (_) {
    return failedCapture(capture, pointerDetails, requestedBytes, wasTruncated, 'MEMORY_READ_FAILED', truncationReason)
  }
}

function captureValue(capture, pointerValue, invocationArguments) {
  return MEMORY_CODECS.has(capture.codec) ? captureMemory(capture, pointerValue, invocationArguments) : captureScalar(capture, pointerValue)
}

function eventRoom(captureRecords) {
  if (emittedEvents < configuration.maxEvents
    && captureAttempts + reservedReturnCaptures + captureRecords <= configuration.maxCaptureRecords) {
    frameCaptureBytes = 0
    return true
  }
  truncated = true
  return false
}

function emitCall(kind, hookId, callId, threadId, captures) {
  emittedEvents += 1
  emit({ event: kind, hook_id: hookId, call_id: callId, sequence: emittedEvents, thread_id: threadId, captures })
}

for (const resolved of resolvedHooks) {
  listeners.push(Interceptor.attach(resolved.address, {
    onEnter(invocationArguments) {
      const enterCaptures = resolved.hook.capture.arguments.filter((capture) => capture.phase === 'enter')
      const leaveCaptures = resolved.hook.capture.arguments.filter((capture) => capture.phase === 'leave')
      const leaveRecords = leaveCaptures.length + (resolved.hook.capture.returnValue === null ? 0 : 1)
      const reservedRecords = enterCaptures.length + leaveRecords
      if (!eventRoom(reservedRecords)) return
      const callId = nextCallId
      nextCallId += 1
      this.lastApertureCallId = callId
      this.lastApertureArguments = Array.from(
        { length: 32 },
        (_, index) => invocationArguments[index],
      )
      activeCalls.add(callId)
      reservedReturnCaptures += leaveRecords
      const captures = enterCaptures.map((capture) => captureValue(
        capture,
        this.lastApertureArguments[capture.index],
        this.lastApertureArguments,
      ))
      emitCall('enter', resolved.hook.hookId, callId, this.threadId, captures)
    },
    onLeave(returnValue) {
      const callId = this.lastApertureCallId
      const leaveCaptures = resolved.hook.capture.arguments.filter((capture) => capture.phase === 'leave')
      const captureRecords = leaveCaptures.length + (resolved.hook.capture.returnValue === null ? 0 : 1)
      if (callId === undefined || !eventRoom(0)) return
      reservedReturnCaptures -= captureRecords
      const capture = resolved.hook.capture.returnValue
      const captures = [
        ...leaveCaptures.map((item) => captureValue(item, this.lastApertureArguments[item.index], this.lastApertureArguments)),
        ...(capture === null ? [] : [captureValue(capture, returnValue, this.lastApertureArguments)]),
      ]
      activeCalls.delete(callId)
      emitCall('leave', resolved.hook.hookId, callId, this.threadId, captures)
    },
  }))
}

setTimeout(() => {
  let hooksDetached = 0
  for (const listener of listeners) {
    listener.detach()
    hooksDetached += 1
  }
  if (activeCalls.size > 0) truncated = true
  emit({
    event: 'complete', hooks_ready: resolvedHooks.length, hooks_detached: hooksDetached,
    events_emitted: emittedEvents, capture_attempts: captureAttempts,
    capture_failures: captureFailures, capture_truncations: captureTruncations,
    captured_payload_bytes: capturedPayloadBytes, truncated,
  })
}, configuration.durationSeconds * 1000)
}

rpc.exports = {
  init(_stage, parametersValue) {
    initialize(parametersValue)
  },
}
