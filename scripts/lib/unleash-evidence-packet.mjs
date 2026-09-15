import { createHash } from 'node:crypto'
import { performance } from 'node:perf_hooks'

export const UNLEASH_EVIDENCE_LIMITS = Object.freeze({
  max_items: 32,
  max_source_bytes: 1_048_576,
  max_total_source_bytes: 4_194_304,
  max_receipt_bytes: 16_384,
  max_total_receipt_bytes: 65_536,
  max_packet_bytes: 131_072,
  max_verification_timeout_ms: 5000,
})

const SHA256 = /^[a-f0-9]{64}$/u
const TIMESTAMP = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u
const VERIFIER_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/u
const MEDIA_TYPES = new Set(['text/plain', 'application/json'])
const SOURCE_FIELDS = ['evidence_ref', 'source_sha256', 'source_bytes', 'media_type', 'receipt_sha256', 'verifier_id']
const PACKET_FIELDS = ['schema_version', 'kind', 'plan_sha256', 'created_at', 'sources', 'redaction', 'trust', 'packet_sha256']
const RECEIPT_FIELDS = ['authenticated', 'verifier_id', 'plan_sha256', 'evidence_ref', 'content_sha256', 'receipt_sha256']
const INPUT_VERIFICATION_MODES = new Set([
  'CALLBACK_VERIFIED_UNANCHORED',
  'LOCALLY_HASH_CHAIN_VERIFIED',
])

export class UnleashEvidencePacketError extends Error {
  constructor(code, message) {
    super(message)
    this.name = 'UnleashEvidencePacketError'
    this.code = code
  }
}

function fail(code, message) {
  throw new UnleashEvidencePacketError(code, message)
}

function record(value, fields) {
  if (value === null || typeof value !== 'object'
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    fail('UNLEASH_EVIDENCE_INVALID', 'evidence records must be plain data objects')
  }
  const descriptors = Object.getOwnPropertyDescriptors(value)
  const keys = Reflect.ownKeys(descriptors)
  if (keys.length !== fields.length || keys.some((key) => !fields.includes(key)
    || !Object.hasOwn(descriptors[key], 'value') || !descriptors[key].enumerable)) {
    fail('UNLEASH_EVIDENCE_INVALID', 'evidence records contain missing, unknown, or accessor fields')
  }
  return Object.fromEntries(keys.map((key) => [key, descriptors[key].value]))
}

function boundedArray(value) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype
    || value.length < 1 || value.length > UNLEASH_EVIDENCE_LIMITS.max_items) {
    fail('UNLEASH_EVIDENCE_INVALID', 'evidence array exceeds its item bounds')
  }
  const descriptors = Object.getOwnPropertyDescriptors(value)
  if (Reflect.ownKeys(descriptors).length !== value.length + 1) {
    fail('UNLEASH_EVIDENCE_INVALID', 'evidence arrays must be dense plain arrays')
  }
  return Array.from({ length: value.length }, (_, index) => {
    const descriptor = descriptors[index]
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
      fail('UNLEASH_EVIDENCE_INVALID', 'evidence arrays cannot contain accessors or holes')
    }
    return descriptor.value
  })
}

function sha256(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex')
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`
  }
  return JSON.stringify(value)
}

function frozen(value) {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) frozen(child)
    Object.freeze(value)
  }
  return value
}

function boundedText(value, maximum) {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum) {
    fail('UNLEASH_EVIDENCE_INVALID', 'evidence text exceeds its byte bounds')
  }
  const size = Buffer.byteLength(value, 'utf8')
  if (size > maximum) fail('UNLEASH_EVIDENCE_INVALID', 'evidence text exceeds its byte bounds')
  return size
}

function snapshotInput(value) {
  const input = record(value, ['plan_sha256', 'evidence'])
  if (typeof input.plan_sha256 !== 'string' || !SHA256.test(input.plan_sha256)) {
    fail('UNLEASH_EVIDENCE_INVALID', 'evidence must bind one valid plan digest')
  }
  let sourceBytes = 0
  let receiptBytes = 0
  const refs = new Set()
  const sources = boundedArray(input.evidence).map((item) => {
    const source = record(item, ['evidence_ref', 'media_type', 'content', 'receipt'])
    const size = boundedText(source.content, UNLEASH_EVIDENCE_LIMITS.max_source_bytes)
    receiptBytes += boundedText(source.receipt, UNLEASH_EVIDENCE_LIMITS.max_receipt_bytes)
    sourceBytes += size
    const digest = sha256(source.content)
    if (source.evidence_ref !== `evidence:sha256:${digest}` || refs.has(source.evidence_ref)
      || !MEDIA_TYPES.has(source.media_type)) {
      fail('UNLEASH_EVIDENCE_INVALID', 'evidence references, content binding, or media type are invalid')
    }
    refs.add(source.evidence_ref)
    return Object.freeze({ ...source, content_sha256: digest, source_bytes: size, receipt_sha256: sha256(source.receipt) })
  })
  if (sourceBytes > UNLEASH_EVIDENCE_LIMITS.max_total_source_bytes
    || receiptBytes > UNLEASH_EVIDENCE_LIMITS.max_total_receipt_bytes) {
    fail('UNLEASH_EVIDENCE_INVALID', 'evidence exceeds its cumulative byte bounds')
  }
  return { plan_sha256: input.plan_sha256, sources }
}

function verifierOptions(value) {
  const fields = ['now', 'verifierId', 'verifyEvidence']
  if (value && Object.hasOwn(value, 'verificationTimeoutMs')) fields.push('verificationTimeoutMs')
  if (value && Object.hasOwn(value, 'inputVerification')) fields.push('inputVerification')
  const options = record(value, fields)
  if (typeof options.verifyEvidence !== 'function' || typeof options.verifierId !== 'string'
    || !VERIFIER_ID.test(options.verifierId) || !(options.now instanceof Date)
    || !Number.isFinite(Date.prototype.getTime.call(options.now))) {
    fail('UNLEASH_EVIDENCE_VERIFIER_INVALID', 'a trusted verifier identity, callback, and valid observation time are required')
  }
  const timeout = options.verificationTimeoutMs ?? 1000
  const inputVerification = options.inputVerification ?? 'CALLBACK_VERIFIED_UNANCHORED'
  if (!INPUT_VERIFICATION_MODES.has(inputVerification)) {
    fail('UNLEASH_EVIDENCE_VERIFIER_INVALID', 'input verification mode is unavailable or overstates trust')
  }
  if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > UNLEASH_EVIDENCE_LIMITS.max_verification_timeout_ms) {
    fail('UNLEASH_EVIDENCE_VERIFIER_INVALID', 'verification deadline exceeds its bounds')
  }
  const createdAt = Date.prototype.toISOString.call(options.now)
  if (!TIMESTAMP.test(createdAt)) {
    fail('UNLEASH_EVIDENCE_VERIFIER_INVALID', 'observation time is outside the supported timestamp range')
  }
  return { ...options, created_at: createdAt, timeout, inputVerification }
}

async function authenticate(source, planSha256, options, deadline) {
  const cancellation = new AbortController()
  let expired = false
  let timer
  const request = Object.freeze({
    plan_sha256: planSha256,
    evidence_ref: source.evidence_ref,
    content_sha256: source.content_sha256,
    receipt_sha256: source.receipt_sha256,
    media_type: source.media_type,
    content: source.content,
    receipt: source.receipt,
    signal: cancellation.signal,
  })
  let result
  try {
    const remaining = deadline - performance.now()
    if (remaining <= 0) { expired = true; throw new Error() }
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => { expired = true; cancellation.abort(); reject(new Error()) }, remaining)
    })
    result = await Promise.race([
      Promise.resolve().then(() => options.verifyEvidence(request)),
      timeout,
    ])
    if (performance.now() >= deadline) { expired = true; cancellation.abort(); throw new Error() }
  } catch {
    fail(
      expired ? 'UNLEASH_EVIDENCE_VERIFICATION_TIMEOUT' : 'UNLEASH_EVIDENCE_VERIFICATION_FAILED',
      expired ? 'evidence verification exceeded its deadline' : 'evidence verification failed',
    )
  } finally {
    clearTimeout(timer)
  }
  const receipt = record(result, RECEIPT_FIELDS)
  if (receipt.authenticated !== true || receipt.verifier_id !== options.verifierId
    || receipt.plan_sha256 !== planSha256 || receipt.evidence_ref !== source.evidence_ref
    || receipt.content_sha256 !== source.content_sha256 || receipt.receipt_sha256 !== source.receipt_sha256) {
    fail('UNLEASH_EVIDENCE_RECEIPT_INVALID', 'verifier result does not authenticate the exact supplied evidence')
  }
}

/**
 * Offline metadata projection. The controller-owned callback checks the exact
 * receipt and plan/source binding according to the declared local mode. This
 * helper does not enroll a key or establish independent or semantic authority.
 * Content and receipt strings are supplied in memory and omitted in full.
 * A timed-out callback receives an abort signal; it must honor cancellation.
 */
export async function createUnleashEvidencePacket(input, dependencies) {
  const options = verifierOptions(dependencies)
  const snapshot = snapshotInput(input)
  const deadline = performance.now() + options.timeout
  for (const source of snapshot.sources) await authenticate(source, snapshot.plan_sha256, options, deadline)
  const body = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-evidence-packet',
    plan_sha256: snapshot.plan_sha256,
    created_at: options.created_at,
    sources: snapshot.sources.map((source) => ({
      evidence_ref: source.evidence_ref,
      source_sha256: source.content_sha256,
      source_bytes: source.source_bytes,
      media_type: source.media_type,
      receipt_sha256: source.receipt_sha256,
      verifier_id: options.verifierId,
    })).sort((left, right) => left.evidence_ref < right.evidence_ref ? -1 : left.evidence_ref > right.evidence_ref ? 1 : 0),
    redaction: { mode: 'METADATA_ONLY', payload_values_included: false },
    trust: {
      input_authentication: options.inputVerification,
      packet_authenticity: 'UNANCHORED',
      semantic_authority: 'NONE',
    },
  }
  const packet = { ...body, packet_sha256: sha256(canonicalJson(body)) }
  assertValidUnleashEvidencePacket(packet)
  return frozen(packet)
}

/** Checks structure and local digest only; it cannot reauthenticate exported packets. */
export function assertValidUnleashEvidencePacket(value) {
  const packet = record(value, PACKET_FIELDS)
  if (packet.schema_version !== '1.0.0' || packet.kind !== 'last-aperture/unleash-evidence-packet'
    || typeof packet.plan_sha256 !== 'string' || !SHA256.test(packet.plan_sha256)
    || typeof packet.packet_sha256 !== 'string' || !SHA256.test(packet.packet_sha256)
    || typeof packet.created_at !== 'string' || !TIMESTAMP.test(packet.created_at)
    || !Number.isFinite(Date.parse(packet.created_at))
    || new Date(packet.created_at).toISOString() !== packet.created_at) {
    fail('UNLEASH_EVIDENCE_PACKET_INVALID', 'evidence packet identity, digest, or time is invalid')
  }
  const redaction = record(packet.redaction, ['mode', 'payload_values_included'])
  const trust = record(packet.trust, ['input_authentication', 'packet_authenticity', 'semantic_authority'])
  if (redaction.mode !== 'METADATA_ONLY' || redaction.payload_values_included !== false
    || !INPUT_VERIFICATION_MODES.has(trust.input_authentication)
    || trust.packet_authenticity !== 'UNANCHORED' || trust.semantic_authority !== 'NONE') {
    fail('UNLEASH_EVIDENCE_PACKET_INVALID', 'evidence packet cannot carry payloads or promote authority')
  }
  let totalBytes = 0
  let previous = ''
  for (const item of boundedArray(packet.sources)) {
    const source = record(item, SOURCE_FIELDS)
    if (typeof source.source_sha256 !== 'string' || !SHA256.test(source.source_sha256)
      || source.evidence_ref !== `evidence:sha256:${source.source_sha256}` || source.evidence_ref <= previous
      || !Number.isSafeInteger(source.source_bytes) || source.source_bytes < 1
      || source.source_bytes > UNLEASH_EVIDENCE_LIMITS.max_source_bytes
      || !MEDIA_TYPES.has(source.media_type) || typeof source.receipt_sha256 !== 'string'
      || !SHA256.test(source.receipt_sha256) || typeof source.verifier_id !== 'string'
      || !VERIFIER_ID.test(source.verifier_id)) {
      fail('UNLEASH_EVIDENCE_PACKET_INVALID', 'evidence packet source metadata is invalid')
    }
    previous = source.evidence_ref
    totalBytes += source.source_bytes
  }
  const { packet_sha256: digest, ...body } = packet
  if (totalBytes > UNLEASH_EVIDENCE_LIMITS.max_total_source_bytes
    || Buffer.byteLength(canonicalJson(packet), 'utf8') > UNLEASH_EVIDENCE_LIMITS.max_packet_bytes
    || sha256(canonicalJson(body)) !== digest) {
    fail('UNLEASH_EVIDENCE_PACKET_INVALID', 'evidence packet bounds or digest verification failed')
  }
  return value
}
