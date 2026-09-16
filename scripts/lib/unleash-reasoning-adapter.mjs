import { createHash } from 'node:crypto'

import {
  assertValidUnleashRoleRequest,
  assertValidUnleashSwarmBasis,
} from './unleash-swarm-contracts.mjs'
import { canonicalUnleashCampaignJson } from './unleash-campaign-storage.mjs'

const ID = /^[A-Za-z0-9][A-Za-z0-9._:/+-]{2,159}$/u
const SHA256 = /^[a-f0-9]{64}$/u
const ADAPTER_IDENTITY_FIELDS = [
  'adapter_id',
  'adapter_version',
  'adapter_config_sha256',
]
const ADAPTER_FIELDS = ['identity', 'invoke']
const LIMIT_FIELDS = [
  'wall_time_ms',
  'max_response_bytes',
  'max_frame_bytes',
  'max_frames',
]
const ARTIFACT_PAYLOAD_FIELDS = ['artifact_id', 'media_type', 'sha256', 'size', 'bytes']
const MEDIA_TYPE = /^[A-Za-z0-9][A-Za-z0-9!#$&^_.+\-/]{0,126}\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+\-]{0,126}$/u
const TYPED_ARRAY_BYTE_LENGTH = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength',
).get

export const UNLEASH_REASONING_ADAPTER_MAX_LIMITS = Object.freeze({
  wall_time_ms: 3_600_000,
  // Captures are embedded in a canonical campaign event as base64. This cap
  // leaves room for the request, receipt, bindings, and event digest below the
  // campaign storage's one-megabyte per-file limit.
  max_response_bytes: 655_360,
  max_frame_bytes: 262_144,
  max_frames: 1024,
  max_artifacts: 32,
  max_artifact_bytes: 4_194_304,
  max_total_artifact_bytes: 16_777_216,
})

export class UnleashReasoningAdapterError extends Error {
  constructor(code, message, { cause } = {}) {
    super(message, cause === undefined ? undefined : { cause })
    this.name = 'UnleashReasoningAdapterError'
    this.code = code
  }
}

function fail(code, message, cause) {
  throw new UnleashReasoningAdapterError(code, message, { cause })
}

function exactDataRecord(value, fields) {
  let prototype
  let descriptors
  try {
    prototype = Object.getPrototypeOf(value)
    descriptors = Object.getOwnPropertyDescriptors(value)
  } catch {
    return false
  }
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || ![Object.prototype, null].includes(prototype)
  ) return false
  const keys = Reflect.ownKeys(descriptors)
  return keys.length === fields.length
    && keys.every((key) => typeof key === 'string'
      && fields.includes(key)
      && descriptors[key].enumerable === true
      && Object.hasOwn(descriptors[key], 'value'))
}

function dataValues(value, fields, code = 'UNLEASH_REASONING_ADAPTER_INPUT_INVALID') {
  if (!exactDataRecord(value, fields)) {
    fail(code, 'reasoning adapter input must contain only the expected enumerable data fields')
  }
  const descriptors = Object.getOwnPropertyDescriptors(value)
  return Object.fromEntries(fields.map((field) => [field, descriptors[field].value]))
}

function deeplyFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const nested of Object.values(value)) deeplyFreeze(nested)
  return Object.freeze(value)
}

function safeJsonSnapshot(value, label) {
  try {
    return deeplyFreeze(JSON.parse(canonicalUnleashCampaignJson(value)))
  } catch (cause) {
    fail(
      'UNLEASH_REASONING_ADAPTER_INPUT_INVALID',
      `${label} must be bounded getter-free canonical plain JSON`,
      cause,
    )
  }
}

export function assertValidUnleashReasoningAdapterIdentity(value) {
  const identity = dataValues(value, ADAPTER_IDENTITY_FIELDS)
  if (
    typeof identity.adapter_id !== 'string'
    || !ID.test(identity.adapter_id)
    || typeof identity.adapter_version !== 'string'
    || !ID.test(identity.adapter_version)
    || typeof identity.adapter_config_sha256 !== 'string'
    || !SHA256.test(identity.adapter_config_sha256)
  ) {
    fail('UNLEASH_REASONING_ADAPTER_IDENTITY_INVALID', 'reasoning adapter identity is invalid')
  }
  return value
}

export function createUnleashReasoningAdapter(value) {
  const input = dataValues(value, ADAPTER_FIELDS)
  assertValidUnleashReasoningAdapterIdentity(input.identity)
  if (typeof input.invoke !== 'function') {
    fail('UNLEASH_REASONING_ADAPTER_INPUT_INVALID', 'reasoning adapter invoke must be a function')
  }
  const identity = deeplyFreeze(structuredClone(input.identity))
  return Object.freeze({ identity, invoke: input.invoke })
}

function assertAdapter(value) {
  const adapter = dataValues(value, ADAPTER_FIELDS)
  assertValidUnleashReasoningAdapterIdentity(adapter.identity)
  if (typeof adapter.invoke !== 'function' || !Object.isFrozen(value) || !Object.isFrozen(adapter.identity)) {
    fail('UNLEASH_REASONING_ADAPTER_INVALID', 'reasoning adapter must be created by the trusted adapter builder')
  }
  return adapter
}

function assertLimits(value, request) {
  const limits = dataValues(value, LIMIT_FIELDS, 'UNLEASH_REASONING_LIMITS_INVALID')
  for (const field of LIMIT_FIELDS) {
    if (!Number.isSafeInteger(limits[field]) || limits[field] < 1) {
      fail('UNLEASH_REASONING_LIMITS_INVALID', `${field} must be a positive safe integer`)
    }
  }
  if (
    limits.wall_time_ms > UNLEASH_REASONING_ADAPTER_MAX_LIMITS.wall_time_ms
    || limits.max_response_bytes > UNLEASH_REASONING_ADAPTER_MAX_LIMITS.max_response_bytes
    || limits.max_frame_bytes > UNLEASH_REASONING_ADAPTER_MAX_LIMITS.max_frame_bytes
    || limits.max_frames > UNLEASH_REASONING_ADAPTER_MAX_LIMITS.max_frames
    || limits.max_frame_bytes > limits.max_response_bytes
    || limits.max_response_bytes > request.limits.max_response_bytes
  ) fail('UNLEASH_REASONING_LIMITS_INVALID', 'reasoning adapter limits exceed the request or adapter bounds')
  return deeplyFreeze({ ...limits })
}

function assertAbortSignal(value) {
  if (value === undefined) return
  if (!(value instanceof AbortSignal)) {
    fail('UNLEASH_REASONING_ADAPTER_INPUT_INVALID', 'signal must be an AbortSignal')
  }
}

function dataMethod(value, key, label) {
  if (value === null || (typeof value !== 'object' && typeof value !== 'function')) return null
  let current = value
  try {
    while (current !== null) {
      const descriptor = Object.getOwnPropertyDescriptor(current, key)
      if (descriptor !== undefined) {
        if (!Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'function') {
          fail('UNLEASH_REASONING_STREAM_INVALID', `${label} must be a data method`)
        }
        return descriptor.value
      }
      current = Object.getPrototypeOf(current)
    }
  } catch (cause) {
    if (cause instanceof UnleashReasoningAdapterError) throw cause
    fail('UNLEASH_REASONING_STREAM_INVALID', `${label} could not be inspected safely`, cause)
  }
  return null
}

function byteArrayLength(value, code, message) {
  try {
    return Reflect.apply(TYPED_ARRAY_BYTE_LENGTH, value, [])
  } catch (cause) {
    fail(code, message, cause)
  }
}

function copyByteArray(value, byteLength, code, message) {
  try {
    return Buffer.copyBytesFrom(value, 0, byteLength)
  } catch (cause) {
    fail(code, message, cause)
  }
}

function frameByteLength(value) {
  if (typeof value === 'string') return Buffer.byteLength(value, 'utf8')
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return byteArrayLength(
      value,
      'UNLEASH_REASONING_FRAME_INVALID',
      'reasoning provider frame length could not be inspected safely',
    )
  }
  fail('UNLEASH_REASONING_FRAME_INVALID', 'reasoning provider frames must be strings or byte arrays')
}

function copyFrameBytes(value, byteLength) {
  return typeof value === 'string'
    ? Buffer.from(value, 'utf8')
    : copyByteArray(
        value,
        byteLength,
        'UNLEASH_REASONING_FRAME_INVALID',
        'reasoning provider frame could not be copied safely',
      )
}

function normalizeArtifactPayloads(value, request) {
  let descriptors
  let prototype
  try {
    descriptors = Object.getOwnPropertyDescriptors(value)
    prototype = Object.getPrototypeOf(value)
  } catch (cause) {
    fail('UNLEASH_REASONING_ARTIFACT_INVALID', 'artifact payloads could not be inspected safely', cause)
  }
  if (!Array.isArray(value) || prototype !== Array.prototype) {
    fail('UNLEASH_REASONING_ARTIFACT_INVALID', 'artifactPayloads must be a plain dense array')
  }
  const keys = Reflect.ownKeys(descriptors).filter((key) => key !== 'length')
  if (
    value.length !== request.artifacts.length
    || value.length > UNLEASH_REASONING_ADAPTER_MAX_LIMITS.max_artifacts
    || keys.length !== value.length
    || keys.some((key, index) => key !== String(index)
      || descriptors[key].enumerable !== true
      || !Object.hasOwn(descriptors[key], 'value'))
  ) fail('UNLEASH_REASONING_ARTIFACT_MISMATCH', 'artifact payloads must exactly cover the request manifest')

  const manifestById = new Map(request.artifacts.map((artifact) => [artifact.artifact_id, artifact]))
  const observedIds = new Set()
  const preflight = []
  let totalBytes = 0
  for (const key of keys) {
    const payload = dataValues(
      descriptors[key].value,
      ARTIFACT_PAYLOAD_FIELDS,
      'UNLEASH_REASONING_ARTIFACT_INVALID',
    )
    if (
      typeof payload.artifact_id !== 'string'
      || !ID.test(payload.artifact_id)
      || typeof payload.media_type !== 'string'
      || !MEDIA_TYPE.test(payload.media_type)
      || typeof payload.sha256 !== 'string'
      || !SHA256.test(payload.sha256)
      || !Number.isSafeInteger(payload.size)
      || payload.size < 1
      || !Buffer.isBuffer(payload.bytes)
      || observedIds.has(payload.artifact_id)
    ) fail('UNLEASH_REASONING_ARTIFACT_INVALID', 'artifact payload metadata or Buffer bytes are invalid')
    observedIds.add(payload.artifact_id)
    const manifest = manifestById.get(payload.artifact_id)
    const byteLength = byteArrayLength(
      payload.bytes,
      'UNLEASH_REASONING_ARTIFACT_INVALID',
      'artifact payload byte length could not be inspected safely',
    )
    if (
      payload.size > UNLEASH_REASONING_ADAPTER_MAX_LIMITS.max_artifact_bytes
      || byteLength > UNLEASH_REASONING_ADAPTER_MAX_LIMITS.max_artifact_bytes
    ) fail('UNLEASH_REASONING_ARTIFACT_LIMIT', 'artifact payload exceeds the per-artifact byte bound')
    if (
      manifest === undefined
      || payload.sha256 !== manifest.sha256
      || payload.size !== manifest.size
      || byteLength !== payload.size
    ) fail('UNLEASH_REASONING_ARTIFACT_MISMATCH', 'artifact payload bytes differ from the exact request manifest')
    totalBytes += byteLength
    if (totalBytes > UNLEASH_REASONING_ADAPTER_MAX_LIMITS.max_total_artifact_bytes) {
      fail('UNLEASH_REASONING_ARTIFACT_LIMIT', 'artifact payloads exceed the aggregate byte bound')
    }
    preflight.push({ payload, byteLength })
  }
  if (observedIds.size !== manifestById.size) {
    fail('UNLEASH_REASONING_ARTIFACT_MISMATCH', 'artifact payload IDs differ from the request manifest')
  }

  const snapshots = []
  for (const { payload, byteLength } of preflight) {
    const bytes = copyByteArray(
      payload.bytes,
      byteLength,
      'UNLEASH_REASONING_ARTIFACT_INVALID',
      'artifact payload bytes could not be copied safely',
    )
    const digest = createHash('sha256').update(bytes).digest('hex')
    if (bytes.length !== byteLength || digest !== payload.sha256) {
      fail('UNLEASH_REASONING_ARTIFACT_MISMATCH', 'artifact payload bytes differ from the exact request manifest')
    }
    snapshots.push({
      artifact_id: payload.artifact_id,
      media_type: payload.media_type,
      sha256: payload.sha256,
      size: payload.size,
      content_encoding: 'base64',
      content_base64: bytes.toString('base64'),
    })
  }
  return deeplyFreeze(snapshots.sort((left, right) => (
    left.artifact_id < right.artifact_id ? -1 : left.artifact_id > right.artifact_id ? 1 : 0
  )))
}

function iteratorResult(value) {
  if (!exactDataRecord(value, ['value', 'done'])) {
    fail('UNLEASH_REASONING_STREAM_INVALID', 'reasoning provider iterator results must be exact data records')
  }
  const descriptors = Object.getOwnPropertyDescriptors(value)
  if (typeof descriptors.done.value !== 'boolean') {
    fail('UNLEASH_REASONING_STREAM_INVALID', 'reasoning provider iterator result done flag is invalid')
  }
  return { done: descriptors.done.value, value: descriptors.value.value }
}

function reasonError(reason, fallbackCode, fallbackMessage) {
  return reason instanceof UnleashReasoningAdapterError
    ? reason
    : new UnleashReasoningAdapterError(fallbackCode, fallbackMessage, {
        cause: reason instanceof Error ? reason : undefined,
      })
}

async function collectResponse(source, limits, raceAbort) {
  const chunks = []
  let frameCount = 0
  let responseBytes = 0
  let iterator = null
  let complete = false

  const append = (frame) => {
    const nextFrameCount = frameCount + 1
    if (nextFrameCount > limits.max_frames) {
      fail('UNLEASH_REASONING_FRAME_LIMIT', 'reasoning provider exceeded max_frames')
    }
    const remainingResponseBytes = limits.max_response_bytes - responseBytes
    if (typeof frame === 'string') {
      if (frame.length > limits.max_frame_bytes) {
        fail('UNLEASH_REASONING_FRAME_LIMIT', 'reasoning provider frame exceeded max_frame_bytes')
      }
      if (frame.length > remainingResponseBytes) {
        fail('UNLEASH_REASONING_RESPONSE_LIMIT', 'reasoning provider exceeded max_response_bytes')
      }
    }
    const byteLength = frameByteLength(frame)
    if (byteLength > limits.max_frame_bytes) {
      fail('UNLEASH_REASONING_FRAME_LIMIT', 'reasoning provider frame exceeded max_frame_bytes')
    }
    if (byteLength > remainingResponseBytes) {
      fail('UNLEASH_REASONING_RESPONSE_LIMIT', 'reasoning provider exceeded max_response_bytes')
    }
    const bytes = copyFrameBytes(frame, byteLength)
    if (bytes.length !== byteLength) {
      fail('UNLEASH_REASONING_FRAME_INVALID', 'reasoning provider frame changed while it was copied')
    }
    frameCount = nextFrameCount
    responseBytes += byteLength
    chunks.push(bytes)
  }

  try {
    if (typeof source === 'string' || Buffer.isBuffer(source) || source instanceof Uint8Array) {
      append(source)
      complete = true
    } else {
      const iteratorFactory = dataMethod(source, Symbol.asyncIterator, 'async iterator')
      if (iteratorFactory === null) {
        fail('UNLEASH_REASONING_STREAM_INVALID', 'reasoning provider must return bytes or an async byte stream')
      }
      iterator = iteratorFactory.call(source)
      const next = dataMethod(iterator, 'next', 'async iterator next')
      if (next === null) fail('UNLEASH_REASONING_STREAM_INVALID', 'reasoning provider iterator has no next method')
      while (true) {
        const step = iteratorResult(await Promise.race([
          Promise.resolve().then(() => next.call(iterator)),
          raceAbort,
        ]))
        if (step.done) {
          complete = true
          break
        }
        append(step.value)
      }
    }
  } finally {
    if (!complete && iterator !== null) {
      const close = dataMethod(iterator, 'return', 'async iterator return')
      if (close !== null) Promise.resolve().then(() => close.call(iterator)).catch(() => {})
    }
  }
  if (responseBytes === 0) {
    fail('UNLEASH_REASONING_RESPONSE_EMPTY', 'reasoning provider returned an empty response')
  }
  return Buffer.concat(chunks, responseBytes)
}

export async function captureUnleashReasoningResponse(value) {
  const fields = value !== null
    && typeof value === 'object'
    && Object.prototype.hasOwnProperty.call(value, 'signal')
    ? ['adapter', 'basis', 'request', 'artifactPayloads', 'limits', 'signal']
    : ['adapter', 'basis', 'request', 'artifactPayloads', 'limits']
  const input = dataValues(value, fields)
  const adapter = assertAdapter(input.adapter)
  assertAbortSignal(input.signal)

  let basis
  let request
  try {
    basis = safeJsonSnapshot(input.basis, 'swarm basis')
    request = safeJsonSnapshot(input.request, 'role request')
    assertValidUnleashSwarmBasis(basis)
    assertValidUnleashRoleRequest(request, { basis })
  } catch (cause) {
    if (cause instanceof UnleashReasoningAdapterError) throw cause
    fail('UNLEASH_REASONING_REQUEST_INVALID', 'reasoning request or swarm basis is invalid', cause)
  }
  const limits = assertLimits(input.limits, request)
  const artifactPayloads = normalizeArtifactPayloads(input.artifactPayloads, request)
  if (input.signal?.aborted === true) {
    fail('UNLEASH_REASONING_ABORTED', 'reasoning provider dispatch was aborted before start', input.signal.reason)
  }

  const cancellation = new AbortController()
  let timeoutId
  let callerAbortListener
  let rejectAbort
  let timeoutExpired = false
  const raceAbort = new Promise((_, reject) => { rejectAbort = reject })
  const abortWith = (error) => {
    if (!cancellation.signal.aborted) cancellation.abort(error)
    rejectAbort(error)
  }
  if (input.signal !== undefined) {
    callerAbortListener = () => abortWith(reasonError(
      input.signal.reason,
      'UNLEASH_REASONING_ABORTED',
      'reasoning provider dispatch was aborted',
    ))
    input.signal.addEventListener('abort', callerAbortListener, { once: true })
  }
  timeoutId = setTimeout(() => {
    timeoutExpired = true
    abortWith(new UnleashReasoningAdapterError(
      'UNLEASH_REASONING_TIMEOUT',
      'reasoning provider exceeded wall_time_ms',
    ))
  }, limits.wall_time_ms)

  try {
    const context = Object.freeze({
      signal: cancellation.signal,
      limits,
      adapterIdentity: adapter.identity,
    })
    const envelope = deeplyFreeze({
      basis,
      request,
      artifact_payloads: artifactPayloads,
    })
    const source = await Promise.race([
      Promise.resolve().then(() => adapter.invoke(envelope, context)),
      raceAbort,
    ])
    const responseBytes = await collectResponse(source, limits, raceAbort)
    if (cancellation.signal.aborted) {
      throw cancellation.signal.reason
    }
    const responseSha256 = createHash('sha256').update(responseBytes).digest('hex')
    const transportReceipt = deeplyFreeze({
      schema_version: '1.0.0',
      kind: 'last-aperture/unleash-provider-transport-receipt',
      adapter_id: adapter.identity.adapter_id,
      adapter_version: adapter.identity.adapter_version,
      adapter_config_sha256: adapter.identity.adapter_config_sha256,
      request_id: request.request_id,
      request_sha256: request.request_sha256,
      response_sha256: responseSha256,
      scope: 'TRANSPORT_ONLY',
      semantic_analysis_proven: false,
    })
    return Object.freeze({ responseBytes, transportReceipt })
  } catch (cause) {
    if (cause instanceof UnleashReasoningAdapterError) throw cause
    if (timeoutExpired) {
      fail('UNLEASH_REASONING_TIMEOUT', 'reasoning provider exceeded wall_time_ms', cause)
    }
    if (input.signal?.aborted === true || cancellation.signal.aborted) {
      fail('UNLEASH_REASONING_ABORTED', 'reasoning provider dispatch was aborted', cause)
    }
    fail('UNLEASH_REASONING_TRANSPORT_FAILED', 'reasoning provider transport failed', cause)
  } finally {
    clearTimeout(timeoutId)
    if (callerAbortListener !== undefined) {
      input.signal.removeEventListener('abort', callerAbortListener)
    }
  }
}
