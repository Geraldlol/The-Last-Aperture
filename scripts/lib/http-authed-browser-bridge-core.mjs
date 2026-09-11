import { Buffer } from 'node:buffer'
import { createHash, randomBytes as nodeRandomBytes, timingSafeEqual } from 'node:crypto'

import { compareCanonicalStrings } from './canonical-order.mjs'
import { sanitizeHttpAuthedHeaderNames } from './http-authed-response-metadata.mjs'
import {
  assertPageSessionAdapterAllowsRequest,
  normalizePageSessionAdapter,
  pageSessionAdapterSha256,
} from './page-session-adapter.mjs'

export const HTTP_AUTHED_BROWSER_BRIDGE_PROTOCOL =
  'red-team-audit/http-authed-browser-bridge'
export const HTTP_AUTHED_BROWSER_BRIDGE_SCHEMA_VERSION = '1.0.0'

const SESSION_PRIVATE = new WeakMap()
const EXTENSION_ID = /^[a-p]{32}$/
const IDENTIFIER = /^[A-Za-z0-9._:-]{1,128}$/
const NONCE = /^[A-Za-z0-9._~-]{16,128}$/
const HTTP_METHOD = /^[!#$%&'*+.^_`|~0-9A-Z-]{1,64}$/
const HTTP_FIELD_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/
const HEX_SHA256 = /^[a-f0-9]{64}$/
const BASE64URL_256 = /^[A-Za-z0-9_-]{43}$/
const MAX_RESPONSE_BYTES = 1024 * 1024
const MAX_REQUEST_BODY_BYTES = 16 * 1024 * 1024
const MAX_HEADER_VALUE_BYTES = 8 * 1024
const MAX_OBSERVED_HEADER_BYTES = 64 * 1024
const DEFAULT_PAIRING_TTL_MS = 5 * 60 * 1000
const FETCH_FORBIDDEN_METHODS = new Set(['CONNECT', 'TRACE', 'TRACK'])
const ALLOWED_REQUEST_HEADERS = new Set([
  'accept',
  'content-length',
  'content-type',
  'user-agent',
])
const OBSERVED_RESPONSE_VALUE_HEADERS = new Set([
  'allow',
  'content-encoding',
  'content-type',
  'link',
  'location',
])

export class HttpAuthedBrowserBridgeError extends Error {
  constructor(code, message, options = {}) {
    super(message)
    this.name = 'HttpAuthedBrowserBridgeError'
    this.code = code
    this.request_may_have_been_sent = options.requestMayHaveBeenSent === true
  }
}

function bridgeError(code, message, options) {
  return new HttpAuthedBrowserBridgeError(code, message, options)
}

function exactObject(value, keys, code, message) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype) {
    throw bridgeError(code, message)
  }
  const allowed = new Set(keys)
  if (Object.keys(value).some((key) => !allowed.has(key))) {
    throw bridgeError(code, message)
  }
  return value
}

function exactKeys(value, keys) {
  const actual = Object.keys(value).sort()
  const expected = [...keys].sort()
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index])
}

function currentTime(clock) {
  const value = clock()
  const milliseconds = value instanceof Date ? value.getTime() : value
  if (!Number.isFinite(milliseconds)) {
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_CLOCK_INVALID',
      'browser bridge clock returned an invalid time',
    )
  }
  return milliseconds
}

function isoTime(milliseconds) {
  return new Date(milliseconds).toISOString()
}

function exactRandomSecret(randomBytes) {
  let produced
  try {
    produced = randomBytes(32)
  } catch {
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_RANDOM_INVALID',
      'browser bridge random source failed',
    )
  }
  if (!(Buffer.isBuffer(produced) || produced instanceof Uint8Array)) {
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_RANDOM_INVALID',
      'browser bridge random source must return bytes',
    )
  }
  const secret = Buffer.from(produced)
  if (secret.length !== 32) {
    secret.fill(0)
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_RANDOM_INVALID',
      'browser bridge random source must return exactly 256 bits',
    )
  }
  return secret
}

function decodeSecret(value) {
  if (typeof value !== 'string' || !BASE64URL_256.test(value)) return null
  const decoded = Buffer.from(value, 'base64url')
  if (decoded.length !== 32 || decoded.toString('base64url') !== value) {
    decoded.fill(0)
    return null
  }
  return decoded
}

function secretMatches(expected, candidateValue) {
  const candidate = decodeSecret(candidateValue)
  if (candidate === null) return false
  try {
    return timingSafeEqual(expected, candidate)
  } finally {
    candidate.fill(0)
  }
}

function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex')
}

function validateExtensionId(value) {
  if (typeof value !== 'string' || !EXTENSION_ID.test(value)) {
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_EXTENSION_ID_INVALID',
      'browser bridge extension id must be one exact Chrome extension id',
    )
  }
  return value
}

function validateTargetOrigin(value) {
  let parsed
  try {
    parsed = new URL(value)
  } catch {
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_TARGET_ORIGIN_INVALID',
      'browser bridge target origin is invalid',
    )
  }
  if (
    parsed.protocol !== 'https:'
    || parsed.username !== ''
    || parsed.password !== ''
    || parsed.pathname !== '/'
    || parsed.search !== ''
    || parsed.hash !== ''
    || parsed.origin !== value
  ) {
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_TARGET_ORIGIN_INVALID',
      'browser bridge target origin must be one canonical HTTPS origin',
    )
  }
  return parsed.origin
}

function validateIdentifier(value, code, message) {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) {
    throw bridgeError(code, message)
  }
  return value
}

function validatePositiveDuration(value, label, maximum = 24 * 60 * 60 * 1000) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_LIMIT_INVALID',
      `${label} is invalid`,
    )
  }
  return value
}

function cloneWireEnvelope(value) {
  return structuredClone(value)
}

function validateRequestHeaders(value, body) {
  exactObject(
    value,
    [...ALLOWED_REQUEST_HEADERS],
    'HTTP_AUTHED_BROWSER_BRIDGE_HEADERS_INVALID',
    'browser-held session request headers are invalid',
  )
  const normalized = {}
  for (const [rawName, headerValue] of Object.entries(value)) {
    if (
      !HTTP_FIELD_NAME.test(rawName)
      || typeof headerValue !== 'string'
      || /[\r\n\0]/.test(headerValue)
      || Buffer.byteLength(headerValue, 'utf8') > MAX_HEADER_VALUE_BYTES
    ) {
      throw bridgeError(
        'HTTP_AUTHED_BROWSER_BRIDGE_HEADERS_INVALID',
        'browser-held session request headers are invalid',
      )
    }
    const name = rawName.toLowerCase()
    if (!ALLOWED_REQUEST_HEADERS.has(name) || Object.hasOwn(normalized, name)) {
      throw bridgeError(
        'HTTP_AUTHED_BROWSER_BRIDGE_SECRET_HEADER_REFUSED',
        'browser-held session requests allow only controller-owned content metadata',
      )
    }
    normalized[name] = headerValue
  }

  if (body === null) {
    if (normalized['content-length'] !== undefined || normalized['content-type'] !== undefined) {
      throw bridgeError(
        'HTTP_AUTHED_BROWSER_BRIDGE_HEADERS_INVALID',
        'body metadata is forbidden when no request body is present',
      )
    }
  } else {
    if (
      normalized['content-length'] !== String(body.length)
      || typeof normalized['content-type'] !== 'string'
      || normalized['content-type'].length === 0
    ) {
      throw bridgeError(
        'HTTP_AUTHED_BROWSER_BRIDGE_HEADERS_INVALID',
        'browser-held request body metadata does not match its bytes',
      )
    }
  }
  return Object.fromEntries(Object.entries(normalized).sort(([left], [right]) => (
    compareCanonicalStrings(left, right)
  )))
}

function validateRequest(input, targetOrigin, pageSessionAdapter, now) {
  exactObject(
    input,
    [
      'url',
      'method',
      'headers',
      'body',
      'timeoutMs',
      'maxResponseBytes',
      'tls',
      'beforeSend',
      'responseObserver',
    ],
    'HTTP_AUTHED_BROWSER_BRIDGE_REQUEST_INVALID',
    'browser-held session request is invalid',
  )
  if (typeof input.url !== 'string' || /(?:\\|%(?:25)*(?:2e|2f|5c))/i.test(input.url)) {
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_URL_INVALID',
      'browser-held session request URL is invalid',
    )
  }
  let parsed
  try {
    parsed = new URL(input.url)
  } catch {
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_URL_INVALID',
      'browser-held session request URL is invalid',
    )
  }
  if (
    parsed.protocol !== 'https:'
    || parsed.origin !== targetOrigin
    || parsed.username !== ''
    || parsed.password !== ''
    || parsed.hash !== ''
  ) {
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_ORIGIN_MISMATCH',
      'browser-held session request must remain on its sealed HTTPS origin',
    )
  }
  if (
    typeof input.method !== 'string'
    || !HTTP_METHOD.test(input.method)
    || FETCH_FORBIDDEN_METHODS.has(input.method)
  ) {
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_METHOD_INVALID',
      'browser-held session request method must be a canonical uppercase HTTP token',
    )
  }
  if (pageSessionAdapter !== null) {
    try {
      assertPageSessionAdapterAllowsRequest({
        adapter: pageSessionAdapter,
        origin: targetOrigin,
        method: input.method,
        pathAndQuery: `${parsed.pathname}${parsed.search}`,
        now,
      })
    } catch {
      throw bridgeError(
        'HTTP_AUTHED_BROWSER_BRIDGE_SESSION_ADAPTER_REFUSED',
        'page session adapter refused the prepared request',
      )
    }
  }
  if (!(input.body === null || Buffer.isBuffer(input.body))) {
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_BODY_INVALID',
      'browser-held session request body must be a Buffer or null',
    )
  }
  if (input.body?.length > MAX_REQUEST_BODY_BYTES) {
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_BODY_INVALID',
      'browser-held session request body exceeds its byte limit',
    )
  }
  if (input.body !== null && ['GET', 'HEAD'].includes(input.method)) {
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_BODY_INVALID',
      'browser-held session request method does not permit a Fetch body',
    )
  }
  const body = input.body === null ? null : Buffer.from(input.body)
  let headers
  try {
    headers = validateRequestHeaders(input.headers, body)
  } catch (error) {
    body?.fill(0)
    throw error
  }
  if (!Number.isSafeInteger(input.timeoutMs) || input.timeoutMs < 1000 || input.timeoutMs > 30000) {
    body?.fill(0)
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_TIMEOUT_INVALID',
      'browser-held session request timeout is invalid',
    )
  }
  if (
    !Number.isSafeInteger(input.maxResponseBytes)
    || input.maxResponseBytes < 0
    || input.maxResponseBytes > MAX_RESPONSE_BYTES
  ) {
    body?.fill(0)
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_RESPONSE_LIMIT_INVALID',
      'browser-held session response limit is invalid',
    )
  }
  if (
    !input.tls
    || Object.getPrototypeOf(input.tls) !== Object.prototype
    || !exactKeys(input.tls, ['mode'])
    || !['BROWSER_MANAGED', 'PKIX_HOSTNAME'].includes(input.tls.mode)
  ) {
    body?.fill(0)
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_TLS_POLICY_INVALID',
      'browser-held sessions require browser-managed TLS',
    )
  }
  if (input.beforeSend !== undefined && typeof input.beforeSend !== 'function') {
    body?.fill(0)
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_BEFORE_SEND_INVALID',
      'browser-held session pre-send verifier is invalid',
    )
  }
  if (input.responseObserver !== undefined && typeof input.responseObserver !== 'function') {
    body?.fill(0)
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_RESPONSE_OBSERVER_INVALID',
      'browser-held session response observer is invalid',
    )
  }
  return {
    parsed,
    pathAndQuery: `${parsed.pathname}${parsed.search}`,
    method: input.method,
    headers,
    body,
    timeoutMs: input.timeoutMs,
    maxResponseBytes: input.maxResponseBytes,
    beforeSend: input.beforeSend,
    responseObserver: input.responseObserver,
  }
}

function actionDigest({
  campaignId,
  actionId,
  actionNonce,
  documentNonce,
  targetOrigin,
  pathAndQuery,
  method,
  headers,
  bodySha256,
  bodyBytes,
  timeoutMs,
  maxResponseBytes,
  observeResponse,
  sessionAdapterSha256,
}) {
  const request = {
    origin: targetOrigin,
    path_and_query: pathAndQuery,
    method,
    headers: Object.entries(headers),
    body_sha256: bodySha256,
    body_bytes: bodyBytes,
    timeout_ms: timeoutMs,
    max_response_bytes: maxResponseBytes,
    observe_response: observeResponse,
  }
  const canonical = JSON.stringify({
    protocol: HTTP_AUTHED_BROWSER_BRIDGE_PROTOCOL,
    schema_version: HTTP_AUTHED_BROWSER_BRIDGE_SCHEMA_VERSION,
    campaign_id: campaignId,
    action_id: actionId,
    action_nonce: actionNonce,
    document_nonce: documentNonce,
    request,
    ...(sessionAdapterSha256 === null
      ? {}
      : { session_adapter_sha256: sessionAdapterSha256 }),
  })
  return sha256Hex(Buffer.from(canonical, 'utf8'))
}

function bindingEnvelope(current, type) {
  return {
    protocol: HTTP_AUTHED_BROWSER_BRIDGE_PROTOCOL,
    schema_version: HTTP_AUTHED_BROWSER_BRIDGE_SCHEMA_VERSION,
    type,
    campaign_id: current.campaignId,
    action_id: current.actionId,
    action_nonce: current.actionNonce,
    action_sha256: current.actionSha256,
    document_nonce: current.documentNonce,
    ...(current.sessionAdapterSha256 === null
      ? {}
      : { session_adapter_sha256: current.sessionAdapterSha256 }),
  }
}

const BINDING_KEYS = [
  'protocol',
  'schema_version',
  'type',
  'campaign_id',
  'action_id',
  'action_nonce',
  'action_sha256',
  'document_nonce',
]

function assertBinding(envelope, current, type, extraKeys = []) {
  const adapterKeys = current.sessionAdapterSha256 === null
    ? []
    : ['session_adapter_sha256']
  if (
    !envelope
    || Object.getPrototypeOf(envelope) !== Object.prototype
    || !exactKeys(envelope, [...BINDING_KEYS, ...adapterKeys, ...extraKeys])
    || envelope.protocol !== HTTP_AUTHED_BROWSER_BRIDGE_PROTOCOL
    || envelope.schema_version !== HTTP_AUTHED_BROWSER_BRIDGE_SCHEMA_VERSION
    || envelope.type !== type
    || envelope.campaign_id !== current.campaignId
    || envelope.action_id !== current.actionId
    || envelope.action_nonce !== current.actionNonce
    || envelope.action_sha256 !== current.actionSha256
    || envelope.document_nonce !== current.documentNonce
    || (current.sessionAdapterSha256 !== null
      && envelope.session_adapter_sha256 !== current.sessionAdapterSha256)
  ) {
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_BINDING_MISMATCH',
      'browser bridge message does not match the prepared action binding',
      { requestMayHaveBeenSent: current.requestMayHaveBeenSent },
    )
  }
}

function validateObservedHeaders(value) {
  if (!Array.isArray(value) || value.length > 256) {
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_RESULT_INVALID',
      'browser bridge result metadata is invalid',
      { requestMayHaveBeenSent: true },
    )
  }
  let totalBytes = 0
  const result = []
  const seen = new Set()
  for (const item of value) {
    if (
      !item
      || Object.getPrototypeOf(item) !== Object.prototype
      || !exactKeys(item, ['name', 'value_base64'])
      || typeof item.name !== 'string'
      || !HTTP_FIELD_NAME.test(item.name)
      || item.name !== item.name.toLowerCase()
      || !OBSERVED_RESPONSE_VALUE_HEADERS.has(item.name)
      || seen.has(item.name)
      || typeof item.value_base64 !== 'string'
      || item.value_base64.length > Math.ceil(MAX_HEADER_VALUE_BYTES / 3) * 4 + 4
      || (
        item.value_base64 !== ''
        && !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
          item.value_base64,
        )
      )
    ) {
      throw bridgeError(
        'HTTP_AUTHED_BROWSER_BRIDGE_RESULT_INVALID',
        'browser bridge result metadata is invalid',
        { requestMayHaveBeenSent: true },
      )
    }
    seen.add(item.name)
    const encoded = item.value_base64
    const bytes = Buffer.from(encoded, 'base64')
    try {
      const decoded = bytes.toString('utf8')
      const canonical = Buffer.from(decoded, 'utf8')
      const encodingMatches = bytes.length === canonical.length
        && timingSafeEqual(bytes, canonical)
        && bytes.toString('base64') === encoded
      canonical.fill(0)
      if (!encodingMatches || /[\r\n\0]/.test(decoded)) {
        throw bridgeError(
          'HTTP_AUTHED_BROWSER_BRIDGE_RESULT_INVALID',
          'browser bridge result metadata is invalid',
          { requestMayHaveBeenSent: true },
        )
      }
      const valueBytes = bytes.length
      totalBytes += Buffer.byteLength(item.name, 'ascii') + valueBytes
      if (valueBytes > MAX_HEADER_VALUE_BYTES || totalBytes > MAX_OBSERVED_HEADER_BYTES) {
        throw bridgeError(
          'HTTP_AUTHED_BROWSER_BRIDGE_RESULT_INVALID',
          'browser bridge result metadata exceeds its byte limit',
          { requestMayHaveBeenSent: true },
        )
      }
      result.push({ name: item.name, value: decoded })
    } finally {
      bytes.fill(0)
    }
  }
  return result
}

function decodeResponseBody(value, maximum, expectedBytes, required) {
  if (!required) {
    if (!(value === null || value === undefined)) {
      throw bridgeError(
        'HTTP_AUTHED_BROWSER_BRIDGE_RESULT_INVALID',
        'browser bridge returned an unrequested response body',
        { requestMayHaveBeenSent: true },
      )
    }
    return null
  }
  if (typeof value !== 'string' || value.length > Math.ceil(maximum / 3) * 4 + 4) {
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_RESULT_INVALID',
      'browser bridge response body encoding is invalid',
      { requestMayHaveBeenSent: true },
    )
  }
  if (value !== '' && !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_RESULT_INVALID',
      'browser bridge response body encoding is invalid',
      { requestMayHaveBeenSent: true },
    )
  }
  const body = Buffer.from(value, 'base64')
  if (body.length !== expectedBytes || body.length > maximum || body.toString('base64') !== value) {
    body.fill(0)
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_RESULT_INVALID',
      'browser bridge response body does not match its declared size',
      { requestMayHaveBeenSent: true },
    )
  }
  return body
}

function cleanCurrent(state) {
  const current = state.current
  if (current === null) return null
  current.requestBody?.fill(0)
  current.requestBody = null
  current.prepareEnvelope = null
  current.beforeSend = null
  current.responseObserver = null
  state.current = null
  return current
}

function rejectWaiter(current, error) {
  if (current?.timer !== undefined) current.clearTimer(current.timer)
  current?.waiter?.reject(error)
}

function resolveWaiter(current, result) {
  if (current?.timer !== undefined) current.clearTimer(current.timer)
  current?.waiter?.resolve(result)
}

function requireState(state, expected, code, message) {
  if (state.state !== expected) {
    throw bridgeError(code, message, {
      requestMayHaveBeenSent: state.requestMayHaveBeenSent,
    })
  }
}

export function createHttpAuthedBrowserBridgeSession({
  extensionId,
  targetOrigin,
  campaignId,
  pageSessionAdapter,
  clock = () => new Date(),
  randomBytes = nodeRandomBytes,
  setTimer = setTimeout,
  clearTimer = clearTimeout,
  pairingTtlMs = DEFAULT_PAIRING_TTL_MS,
} = {}) {
  const pinnedExtensionId = validateExtensionId(extensionId)
  const pinnedTargetOrigin = validateTargetOrigin(targetOrigin)
  const pinnedCampaignId = validateIdentifier(
    campaignId,
    'HTTP_AUTHED_BROWSER_BRIDGE_CAMPAIGN_INVALID',
    'browser bridge campaign id is invalid',
  )
  let pinnedPageSessionAdapter = null
  let pinnedPageSessionAdapterSha256 = null
  if (pageSessionAdapter !== undefined) {
    try {
      pinnedPageSessionAdapter = normalizePageSessionAdapter(pageSessionAdapter)
      pinnedPageSessionAdapterSha256 = pageSessionAdapterSha256(pinnedPageSessionAdapter)
    } catch {
      throw bridgeError(
        'HTTP_AUTHED_BROWSER_BRIDGE_SESSION_ADAPTER_INVALID',
        'browser bridge page session adapter is invalid',
      )
    }
    if (!pinnedPageSessionAdapter.target_constraints.some(({ origin }) => (
      origin === pinnedTargetOrigin
    ))) {
      throw bridgeError(
        'HTTP_AUTHED_BROWSER_BRIDGE_SESSION_ADAPTER_INVALID',
        'browser bridge page session adapter does not name the pinned target origin',
      )
    }
  }
  if (
    typeof clock !== 'function'
    || typeof randomBytes !== 'function'
    || typeof setTimer !== 'function'
    || typeof clearTimer !== 'function'
  ) {
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_DEPENDENCY_INVALID',
      'browser bridge dependency is invalid',
    )
  }
  validatePositiveDuration(pairingTtlMs, 'browser bridge pairing lifetime')
  const createdAt = currentTime(clock)
  const pairingSecret = exactRandomSecret(randomBytes)
  const state = {
    state: 'NEW',
    extensionId: pinnedExtensionId,
    extensionOrigin: `chrome-extension://${pinnedExtensionId}`,
    targetOrigin: pinnedTargetOrigin,
    campaignId: pinnedCampaignId,
    pageSessionAdapter: pinnedPageSessionAdapter,
    pageSessionAdapterSha256: pinnedPageSessionAdapterSha256,
    clock,
    randomBytes,
    setTimer,
    clearTimer,
    pairingSecret,
    pairingTaken: false,
    pairingExpiresAt: createdAt + pairingTtlMs,
    sessionSecret: null,
    tabId: null,
    documentNonce: null,
    current: null,
    requestMayHaveBeenSent: false,
    actionCounter: 0,
  }

  const session = {
    takePairingCode() {
      if (state.pairingTaken || state.pairingSecret === null || state.state !== 'NEW') {
        return undefined
      }
      if (currentTime(state.clock) > state.pairingExpiresAt) {
        state.pairingSecret.fill(0)
        state.pairingSecret = null
        return undefined
      }
      state.pairingTaken = true
      return state.pairingSecret.toString('base64url')
    },

    preview({ origin, capability } = {}) {
      requireState(
        state,
        'NEW',
        'HTTP_AUTHED_BROWSER_BRIDGE_PREVIEW_UNAVAILABLE',
        'browser bridge pairing preview is unavailable',
      )
      if (
        origin !== state.extensionOrigin
        || currentTime(state.clock) > state.pairingExpiresAt
        || state.pairingSecret === null
        || !secretMatches(state.pairingSecret, capability)
      ) {
        throw bridgeError(
          'HTTP_AUTHED_BROWSER_BRIDGE_PREVIEW_REFUSED',
          'browser bridge pairing preview was refused',
        )
      }
      return {
        protocol: HTTP_AUTHED_BROWSER_BRIDGE_PROTOCOL,
        schema_version: HTTP_AUTHED_BROWSER_BRIDGE_SCHEMA_VERSION,
        type: 'PREVIEW',
        target_origin: state.targetOrigin,
        campaign_grant_sha256: state.campaignId,
        extension_id: state.extensionId,
        expires_at: isoTime(state.pairingExpiresAt),
      }
    },

    open(input) {
      requireState(
        state,
        'NEW',
        'HTTP_AUTHED_BROWSER_BRIDGE_ALREADY_OPEN',
        'browser bridge pairing capability has already been consumed',
      )
      exactObject(
        input,
        ['origin', 'capability', 'campaignId', 'tabId', 'documentNonce'],
        'HTTP_AUTHED_BROWSER_BRIDGE_OPEN_INVALID',
        'browser bridge OPEN message is invalid',
      )
      if (
        input.origin !== state.extensionOrigin
        || input.campaignId !== state.campaignId
        || !Number.isSafeInteger(input.tabId)
        || input.tabId < 0
        || input.tabId > 2147483647
        || typeof input.documentNonce !== 'string'
        || !NONCE.test(input.documentNonce)
        || currentTime(state.clock) > state.pairingExpiresAt
        || state.pairingSecret === null
        || !secretMatches(state.pairingSecret, input.capability)
      ) {
        throw bridgeError(
          'HTTP_AUTHED_BROWSER_BRIDGE_OPEN_REFUSED',
          'browser bridge OPEN message was refused',
        )
      }

      const sessionSecret = exactRandomSecret(state.randomBytes)
      if (timingSafeEqual(sessionSecret, state.pairingSecret)) {
        const derived = createHash('sha256')
          .update(sessionSecret)
          .update('red-team-audit/browser-bridge/session', 'utf8')
          .digest()
        sessionSecret.fill(0)
        state.sessionSecret = derived
      } else {
        state.sessionSecret = sessionSecret
      }
      state.pairingSecret.fill(0)
      state.pairingSecret = null
      state.tabId = input.tabId
      state.documentNonce = input.documentNonce
      state.state = 'OPEN'
      state.requestMayHaveBeenSent = false
      return {
        protocol: HTTP_AUTHED_BROWSER_BRIDGE_PROTOCOL,
        schema_version: HTTP_AUTHED_BROWSER_BRIDGE_SCHEMA_VERSION,
        type: 'OPEN',
        campaign_id: state.campaignId,
        target_origin: state.targetOrigin,
        tab_id: state.tabId,
        document_nonce: state.documentNonce,
        session_capability: state.sessionSecret.toString('base64url'),
      }
    },

    authenticate({ origin, sessionCapability } = {}) {
      if (
        state.state === 'NEW'
        || state.state === 'CLOSED'
        || origin !== state.extensionOrigin
        || state.sessionSecret === null
        || !secretMatches(state.sessionSecret, sessionCapability)
      ) {
        throw bridgeError(
          'HTTP_AUTHED_BROWSER_BRIDGE_SESSION_REFUSED',
          'browser bridge session authentication was refused',
          { requestMayHaveBeenSent: state.requestMayHaveBeenSent },
        )
      }
      return true
    },

    prepare({ actionId, request } = {}) {
      requireState(
        state,
        'OPEN',
        'HTTP_AUTHED_BROWSER_BRIDGE_IN_FLIGHT',
        'browser bridge allows exactly one in-flight action',
      )
      const validatedActionId = validateIdentifier(
        actionId,
        'HTTP_AUTHED_BROWSER_BRIDGE_ACTION_ID_INVALID',
        'browser bridge action id is invalid',
      )
      const validated = validateRequest(
        request,
        state.targetOrigin,
        state.pageSessionAdapter,
        new Date(currentTime(state.clock)),
      )
      let actionNonceBytes
      try {
        actionNonceBytes = exactRandomSecret(state.randomBytes)
        const actionNonce = actionNonceBytes.toString('base64url')
        const bodySha256 = validated.body === null ? null : sha256Hex(validated.body)
        const observeResponse = validated.responseObserver !== undefined
        const digest = actionDigest({
          campaignId: state.campaignId,
          actionId: validatedActionId,
          actionNonce,
          documentNonce: state.documentNonce,
          targetOrigin: state.targetOrigin,
          pathAndQuery: validated.pathAndQuery,
          method: validated.method,
          headers: validated.headers,
          bodySha256,
          bodyBytes: validated.body?.length ?? 0,
          timeoutMs: validated.timeoutMs,
          maxResponseBytes: validated.maxResponseBytes,
          observeResponse,
          sessionAdapterSha256: state.pageSessionAdapterSha256,
        })
        const deadlineMs = currentTime(state.clock) + validated.timeoutMs
        const envelope = {
          protocol: HTTP_AUTHED_BROWSER_BRIDGE_PROTOCOL,
          schema_version: HTTP_AUTHED_BROWSER_BRIDGE_SCHEMA_VERSION,
          type: 'PREPARE',
          campaign_id: state.campaignId,
          action_id: validatedActionId,
          action_nonce: actionNonce,
          action_sha256: digest,
          document_nonce: state.documentNonce,
          deadline: isoTime(deadlineMs),
          request: {
            origin: state.targetOrigin,
            path_and_query: validated.pathAndQuery,
            method: validated.method,
            headers: { ...validated.headers },
            body_base64: validated.body === null ? null : validated.body.toString('base64'),
            body_sha256: bodySha256,
            body_bytes: validated.body?.length ?? 0,
            timeout_ms: validated.timeoutMs,
            max_response_bytes: validated.maxResponseBytes,
            observe_response: observeResponse,
          },
          ...(state.pageSessionAdapter === null
            ? {}
            : {
                session_adapter: structuredClone(state.pageSessionAdapter),
                session_adapter_sha256: state.pageSessionAdapterSha256,
              }),
        }
        state.current = {
          campaignId: state.campaignId,
          actionId: validatedActionId,
          actionNonce,
          actionSha256: digest,
          documentNonce: state.documentNonce,
          sessionAdapterSha256: state.pageSessionAdapterSha256,
          deadlineMs,
          maxResponseBytes: validated.maxResponseBytes,
          beforeSend: validated.beforeSend,
          responseObserver: validated.responseObserver,
          requestBody: validated.body,
          prepareEnvelope: envelope,
          delivered: false,
          requestMayHaveBeenSent: false,
          waiter: null,
          timer: undefined,
          clearTimer: state.clearTimer,
        }
        state.state = 'PREPARE'
        state.requestMayHaveBeenSent = false
        return cloneWireEnvelope(envelope)
      } catch (error) {
        validated.body?.fill(0)
        throw error
      } finally {
        actionNonceBytes?.fill(0)
      }
    },

    takePrepared() {
      requireState(
        state,
        'PREPARE',
        'HTTP_AUTHED_BROWSER_BRIDGE_PREPARE_UNAVAILABLE',
        'browser bridge has no prepared action available',
      )
      if (state.current.delivered) {
        throw bridgeError(
          'HTTP_AUTHED_BROWSER_BRIDGE_PREPARE_REPLAY',
          'browser bridge prepared action was already delivered',
        )
      }
      state.current.delivered = true
      return cloneWireEnvelope(state.current.prepareEnvelope)
    },

    acceptReady(envelope) {
      requireState(
        state,
        'PREPARE',
        'HTTP_AUTHED_BROWSER_BRIDGE_READY_UNEXPECTED',
        'browser bridge READY message is out of sequence',
      )
      assertBinding(envelope, state.current, 'READY')
      if (currentTime(state.clock) > state.current.deadlineMs) {
        throw bridgeError(
          'HTTP_AUTHED_BROWSER_BRIDGE_ACTION_EXPIRED',
          'browser bridge prepared action expired before READY',
        )
      }
      state.state = 'READY'
      return { ...bindingEnvelope(state.current, 'READY') }
    },

    async commit({ beforeSend } = {}) {
      requireState(
        state,
        'READY',
        'HTTP_AUTHED_BROWSER_BRIDGE_COMMIT_UNEXPECTED',
        'browser bridge COMMIT is out of sequence',
      )
      const verifier = beforeSend ?? state.current.beforeSend
      if (typeof verifier !== 'function') {
        throw bridgeError(
          'HTTP_AUTHED_BROWSER_BRIDGE_BEFORE_SEND_REQUIRED',
          'browser bridge COMMIT requires an immediate pre-send verifier',
        )
      }
      if (currentTime(state.clock) > state.current.deadlineMs) {
        throw bridgeError(
          'HTTP_AUTHED_BROWSER_BRIDGE_ACTION_EXPIRED',
          'browser bridge prepared action expired before COMMIT',
        )
      }
      try {
        await verifier()
      } catch {
        const error = bridgeError(
          'HTTP_AUTHED_BROWSER_BRIDGE_BEFORE_SEND_REJECTED',
          'browser bridge action was rejected immediately before COMMIT',
        )
        const current = cleanCurrent(state)
        state.state = 'OPEN'
        state.requestMayHaveBeenSent = false
        rejectWaiter(current, error)
        throw error
      }
      if (state.state !== 'READY' || state.current === null) {
        throw bridgeError(
          'HTTP_AUTHED_BROWSER_BRIDGE_COMMIT_CANCELLED',
          'browser bridge action was cancelled before COMMIT',
        )
      }
      state.state = 'COMMIT'
      state.current.requestMayHaveBeenSent = true
      state.requestMayHaveBeenSent = true
      return {
        ...bindingEnvelope(state.current, 'COMMIT'),
        committed_at: isoTime(currentTime(state.clock)),
      }
    },

    async acceptResult(envelope) {
      requireState(
        state,
        'COMMIT',
        'HTTP_AUTHED_BROWSER_BRIDGE_RESULT_UNEXPECTED',
        'browser bridge RESULT message is out of sequence',
      )
      assertBinding(
        envelope,
        state.current,
        'RESULT',
        ['outcome', 'response_truncated', 'response'],
      )
      const complete = envelope.outcome === 'OBSERVED'
        && envelope.response_truncated === false
      const bounded = envelope.outcome === 'RESPONSE_BOUNDED'
        && envelope.response_truncated === true
      const incomplete = envelope.outcome === 'OBSERVATION_INCOMPLETE'
        && envelope.response_truncated === false
      if (!complete && !bounded && !incomplete) {
        throw bridgeError(
          'HTTP_AUTHED_BROWSER_BRIDGE_RESULT_INVALID',
          'browser bridge result outcome is invalid',
          { requestMayHaveBeenSent: true },
        )
      }
      const response = envelope.response
      if (
        !response
        || Object.getPrototypeOf(response) !== Object.prototype
        || !exactKeys(response, [
          'status',
          'response_bytes',
          'response_header_names',
          'headers',
          'body_base64',
        ])
        || !Number.isSafeInteger(response.status)
        || response.status < 100
        || response.status > 599
        || !Number.isSafeInteger(response.response_bytes)
        || response.response_bytes < 0
        || response.response_bytes > state.current.maxResponseBytes
      ) {
        throw bridgeError(
          'HTTP_AUTHED_BROWSER_BRIDGE_RESULT_INVALID',
          'browser bridge result metadata is invalid',
          { requestMayHaveBeenSent: true },
        )
      }
      let headerNames
      if (
        !Array.isArray(response.response_header_names)
        || response.response_header_names.length > 256
        || new Set(response.response_header_names).size !== response.response_header_names.length
        || response.response_header_names.some((name) => (
          typeof name !== 'string'
          || name !== name.toLowerCase()
          || !HTTP_FIELD_NAME.test(name)
        ))
      ) {
        throw bridgeError(
          'HTTP_AUTHED_BROWSER_BRIDGE_RESULT_INVALID',
          'browser bridge response header-name metadata is invalid',
          { requestMayHaveBeenSent: true },
        )
      }
      try {
        headerNames = sanitizeHttpAuthedHeaderNames(response.response_header_names)
      } catch {
        throw bridgeError(
          'HTTP_AUTHED_BROWSER_BRIDGE_RESULT_INVALID',
          'browser bridge response header-name metadata is invalid',
          { requestMayHaveBeenSent: true },
        )
      }
      const observedHeaders = validateObservedHeaders(response.headers)
      if (observedHeaders.some(({ name }) => !response.response_header_names.includes(name))) {
        throw bridgeError(
          'HTTP_AUTHED_BROWSER_BRIDGE_RESULT_INVALID',
          'browser bridge response values do not match observed header-name metadata',
          { requestMayHaveBeenSent: true },
        )
      }
      const activeAction = state.current
      const observer = activeAction.responseObserver
      if (observer === undefined && observedHeaders.length !== 0) {
        throw bridgeError(
          'HTTP_AUTHED_BROWSER_BRIDGE_RESULT_INVALID',
          'browser bridge returned unrequested response header values',
          { requestMayHaveBeenSent: true },
        )
      }
      const body = decodeResponseBody(
        response.body_base64,
        state.current.maxResponseBytes,
        response.response_bytes,
        observer !== undefined,
      )
      const result = {
        status: response.status,
        responseBytes: response.response_bytes,
        responseHeaderNames: headerNames,
      }
      if (!complete) {
        body?.fill(0)
        const error = bridgeError(
          bounded
            ? 'HTTP_AUTHED_BROWSER_BRIDGE_RESPONSE_BOUNDED'
            : 'HTTP_AUTHED_BROWSER_BRIDGE_OBSERVATION_INCOMPLETE',
          bounded
            ? 'browser bridge response exceeded its observation limit'
            : 'browser bridge response observation ended before completion',
          { requestMayHaveBeenSent: true },
        )
        const current = cleanCurrent(state)
        state.state = 'FAILED'
        state.requestMayHaveBeenSent = true
        rejectWaiter(current, error)
        throw error
      }
      let observerFailed = false
      try {
        if (observer !== undefined) {
          await observer({
            status: response.status,
            headers: observedHeaders.map(({ name, value }) => ({ name, value })),
            bodyChunks: body === null ? [] : [Buffer.from(body)],
          })
        }
      } catch {
        observerFailed = true
      } finally {
        body?.fill(0)
      }
      if (state.state !== 'COMMIT' || state.current !== activeAction) {
        throw bridgeError(
          'HTTP_AUTHED_BROWSER_BRIDGE_RESULT_CANCELLED',
          'browser bridge result was cancelled while being observed',
          { requestMayHaveBeenSent: true },
        )
      }
      if (observerFailed) {
        const error = bridgeError(
          'HTTP_AUTHED_BROWSER_BRIDGE_RESPONSE_OBSERVER_FAILED',
          'browser bridge response observer failed',
          { requestMayHaveBeenSent: true },
        )
        const current = cleanCurrent(state)
        state.state = 'OPEN'
        state.requestMayHaveBeenSent = true
        rejectWaiter(current, error)
        throw error
      }

      state.state = 'RESULT'
      const current = cleanCurrent(state)
      state.state = 'OPEN'
      state.requestMayHaveBeenSent = false
      resolveWaiter(current, result)
      return result
    },

    close(_reason) {
      if (state.state === 'CLOSED') {
        return {
          state: 'CLOSED',
          request_may_have_been_sent: state.requestMayHaveBeenSent,
        }
      }
      const requestMayHaveBeenSent = state.requestMayHaveBeenSent === true
        || state.state === 'COMMIT'
        || state.current?.requestMayHaveBeenSent === true
      const error = bridgeError(
        'HTTP_AUTHED_BROWSER_BRIDGE_CLOSED',
        'browser bridge session closed',
        { requestMayHaveBeenSent },
      )
      const current = cleanCurrent(state)
      rejectWaiter(current, error)
      state.pairingSecret?.fill(0)
      state.pairingSecret = null
      state.sessionSecret?.fill(0)
      state.sessionSecret = null
      state.tabId = null
      state.documentNonce = null
      state.state = 'CLOSED'
      state.requestMayHaveBeenSent = requestMayHaveBeenSent
      return {
        state: 'CLOSED',
        request_may_have_been_sent: requestMayHaveBeenSent,
      }
    },

    snapshot() {
      return {
        protocol: HTTP_AUTHED_BROWSER_BRIDGE_PROTOCOL,
        schema_version: HTTP_AUTHED_BROWSER_BRIDGE_SCHEMA_VERSION,
        state: state.state,
        paired: !['NEW', 'CLOSED'].includes(state.state),
        request_may_have_been_sent: state.requestMayHaveBeenSent,
        in_flight: state.current === null
          ? null
          : {
              action_id: state.current.actionId,
              action_sha256: state.current.actionSha256,
            },
      }
    },
  }

  SESSION_PRIVATE.set(session, state)
  return Object.freeze(session)
}

function createDeferred() {
  let resolve
  let reject
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

export function createHttpAuthedBrowserBridgeTransport({
  session,
  actionIdFactory,
} = {}) {
  const state = SESSION_PRIVATE.get(session)
  if (state === undefined) {
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_SESSION_REQUIRED',
      'browser-held transport requires a browser bridge session',
    )
  }
  if (actionIdFactory !== undefined && typeof actionIdFactory !== 'function') {
    throw bridgeError(
      'HTTP_AUTHED_BROWSER_BRIDGE_DEPENDENCY_INVALID',
      'browser-held transport action id factory is invalid',
    )
  }

  return async function sendHttpAuthedThroughBrowser(request) {
    if (typeof request?.beforeSend !== 'function') {
      throw bridgeError(
        'HTTP_AUTHED_BROWSER_BRIDGE_BEFORE_SEND_REQUIRED',
        'browser-held transport requires an immediate pre-send verifier',
      )
    }
    state.actionCounter += 1
    const generatedActionId = actionIdFactory === undefined
      ? `browser-action-${state.actionCounter}`
      : actionIdFactory({ sequence: state.actionCounter })
    const prepared = session.prepare({ actionId: generatedActionId, request })
    const deferred = createDeferred()
    state.current.waiter = deferred
    state.current.timer = state.setTimer(() => {
      if (state.current?.actionId !== prepared.action_id) return
      const requestMayHaveBeenSent = state.current.requestMayHaveBeenSent === true
      const error = bridgeError(
        'HTTP_AUTHED_BROWSER_BRIDGE_TIMEOUT',
        'browser-held transport timed out waiting for the extension',
        { requestMayHaveBeenSent },
      )
      const current = cleanCurrent(state)
      if (requestMayHaveBeenSent) {
        state.pairingSecret?.fill(0)
        state.pairingSecret = null
        state.sessionSecret?.fill(0)
        state.sessionSecret = null
        state.tabId = null
        state.documentNonce = null
        state.state = 'CLOSED'
      } else {
        state.state = state.state === 'CLOSED' ? 'CLOSED' : 'OPEN'
      }
      state.requestMayHaveBeenSent = requestMayHaveBeenSent
      rejectWaiter(current, error)
    }, request.timeoutMs)
    return deferred.promise
  }
}

export function isHttpAuthedBrowserBridgeSession(value) {
  return SESSION_PRIVATE.has(value)
}
