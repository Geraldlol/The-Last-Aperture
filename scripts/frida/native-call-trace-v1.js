'use strict'

const PROFILE_ID = 'native-call-trace-v1'
const OUTPUT_PREFIX = '[last-aperture:frida] '
const MAX_DURATION_SECONDS = 300
const MAX_EVENTS = 10000
const FRAME_NONCE_PATTERN = /^[a-f0-9]{64}$/
const UNSAFE_TEXT_PATTERN = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/

function exactKeys(value, expected) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const actual = Object.keys(value).sort()
  const wanted = expected.slice().sort()
  return actual.length === wanted.length
    && actual.every((key, index) => key === wanted[index])
}

function boundedText(value, maximum) {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= maximum
    && value.trim() === value
    && !UNSAFE_TEXT_PATTERN.test(value)
}

function emit(value) {
  console.log(`${OUTPUT_PREFIX}${JSON.stringify({
    schema_version: '1.0.0',
    profile_id: PROFILE_ID,
    frame_nonce: configuration.frameNonce,
    ...value,
    observed_at_ms: Date.now(),
  })}`)
}

function loadConfiguration(parametersValue) {
  const parameters = parametersValue
  if (!exactKeys(parameters, [
    'profileId',
    'moduleName',
    'symbolName',
    'durationSeconds',
    'maxEvents',
    'frameNonce',
  ])) throw new Error('invalid fixed profile parameters')
  if (
    parameters.profileId !== PROFILE_ID
    || !boundedText(parameters.moduleName, 256)
    || !boundedText(parameters.symbolName, 512)
    || !Number.isInteger(parameters.durationSeconds)
    || parameters.durationSeconds < 1
    || parameters.durationSeconds > MAX_DURATION_SECONDS
    || !Number.isInteger(parameters.maxEvents)
    || parameters.maxEvents < 1
    || parameters.maxEvents > MAX_EVENTS
    || typeof parameters.frameNonce !== 'string'
    || !FRAME_NONCE_PATTERN.test(parameters.frameNonce)
  ) throw new Error('invalid fixed profile parameter values')
  return parameters
}

let configuration = null

function initialize(parametersValue) {
  if (configuration !== null) throw new Error('fixed profile was already initialized')
  configuration = loadConfiguration(parametersValue)
  const mainModule = Process.mainModule
  const selectedModule = configuration.moduleName === '<main>'
    || configuration.moduleName === mainModule.name
    ? mainModule
    : Process.getModuleByName(configuration.moduleName)
  const targetAddress = selectedModule.findExportByName(configuration.symbolName)

  if (targetAddress === null) throw new Error('requested exported symbol is unavailable')
  const moduleEnd = selectedModule.base.add(selectedModule.size)
  if (
    targetAddress.compare(selectedModule.base) < 0
    || targetAddress.compare(moduleEnd) >= 0
  ) throw new Error('requested exported symbol is outside the selected module')

  let emittedEvents = 0
  let truncated = false

  function emitTraceEvent(kind, invocation) {
    if (emittedEvents >= configuration.maxEvents) {
      truncated = true
      return
    }
    emittedEvents += 1
    emit({
      event: kind,
      sequence: emittedEvents,
      thread_id: invocation.threadId,
    })
  }

  emit({
    event: 'ready',
    module_name: configuration.moduleName,
    symbol_name: configuration.symbolName,
    module_relative_offset: targetAddress.sub(selectedModule.base).toString(),
  })

  const listener = Interceptor.attach(targetAddress, {
    onEnter() {
      emitTraceEvent('enter', this)
    },
    onLeave() {
      emitTraceEvent('leave', this)
    },
  })

  setTimeout(() => {
    listener.detach()
    emit({
      event: 'complete',
      events_emitted: emittedEvents,
      truncated,
    })
  }, configuration.durationSeconds * 1000)
}

rpc.exports = {
  init(_stage, parametersValue) {
    initialize(parametersValue)
  },
}
