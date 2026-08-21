import {
  abortHttpAuthedInjectedFetch,
  captureHttpAuthedDocument,
  clearHttpAuthedInjectedPreparation,
  executeHttpAuthedInjectedFetch,
  inspectHttpAuthedDocument,
  prepareHttpAuthedInjectedFetch,
} from './injected-fetch.mjs'

const PROTOCOL = 'red-team-audit/http-authed-browser-bridge'
const SCHEMA_VERSION = '1.0.0'
const PAIRING_HEADER = 'x-red-team-audit-pairing'
const SESSION_HEADER = 'x-red-team-audit-session'
const MAX_LOOPBACK_RESPONSE_BYTES = 24 * 1024 * 1024
const LOOPBACK_TIMEOUT_MS = 30_000
const MAX_RESPONSE_BYTES = 1024 * 1024
const ROUTES = Object.freeze({
  preview: '/v1/preview',
  open: '/v1/open',
  prepare: '/v1/prepare',
  ready: '/v1/ready',
  result: '/v1/result',
  close: '/v1/close',
})
const REQUEST_HEADER_NAMES = new Set([
  'accept',
  'content-length',
  'content-type',
  'user-agent',
])
const FETCH_FORBIDDEN_METHODS = new Set(['CONNECT', 'TRACE', 'TRACK'])

let activeSession = null

class BridgeFailure extends Error {
  constructor(code) {
    super(code)
    this.name = 'BridgeFailure'
    this.code = code
  }
}

function refuse(code) {
  throw new BridgeFailure(code)
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function exactKeys(value, keys) {
  if (!isObject(value)) return false
  const actual = Object.keys(value).sort()
  const expected = [...keys].sort()
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index])
}

function opaque(value, minimum = 1, maximum = 128) {
  return typeof value === 'string'
    && value.length >= minimum
    && value.length <= maximum
    && /^[A-Za-z0-9._:~-]+$/u.test(value)
}

function exactHttpsOrigin(value) {
  if (typeof value !== 'string' || value.length > 512) return false
  try {
    const parsed = new URL(value)
    return parsed.protocol === 'https:'
      && parsed.origin === value
      && parsed.pathname === '/'
      && parsed.search === ''
      && parsed.hash === ''
      && parsed.username === ''
      && parsed.password === ''
  } catch {
    return false
  }
}

function validPathAndQuery(value, origin) {
  if (
    typeof value !== 'string'
    || value.length < 1
    || value.length > 4096
    || !value.startsWith('/')
    || value.startsWith('//')
    || value.includes('#')
    || /(?:[\\\u0000-\u0020\u007f]|%(?:25)*(?:2e|2f|5c))/iu.test(value)
  ) return false
  try {
    const parsed = new URL(value, origin)
    return parsed.origin === origin && `${parsed.pathname}${parsed.search}` === value
  } catch {
    return false
  }
}

function bindingEnvelope(prepared, type) {
  return {
    protocol: PROTOCOL,
    schema_version: SCHEMA_VERSION,
    type,
    campaign_id: prepared.campaign_id,
    action_id: prepared.action_id,
    action_nonce: prepared.action_nonce,
    action_sha256: prepared.action_sha256,
    document_nonce: prepared.document_nonce,
  }
}

function sameBinding(value, prepared, type, extraKeys = []) {
  return exactKeys(value, [
    'protocol',
    'schema_version',
    'type',
    'campaign_id',
    'action_id',
    'action_nonce',
    'action_sha256',
    'document_nonce',
    ...extraKeys,
  ])
    && value.protocol === PROTOCOL
    && value.schema_version === SCHEMA_VERSION
    && value.type === type
    && value.campaign_id === prepared.campaign_id
    && value.action_id === prepared.action_id
    && value.action_nonce === prepared.action_nonce
    && value.action_sha256 === prepared.action_sha256
    && value.document_nonce === prepared.document_nonce
}

function stateSummary() {
  if (activeSession === null) return { attached: false }
  return {
    attached: true,
    origin: activeSession.origin,
    campaign_grant_sha256: activeSession.campaignGrantSha256,
    phase: activeSession.phase,
    actions_completed: activeSession.actionsCompleted,
    prepared: activeSession.prepared === null
      ? null
      : {
          method: activeSession.prepared.request.method,
          path_and_query: activeSession.prepared.request.path_and_query,
          action_binding_prefix: activeSession.prepared.action_sha256.slice(0, 12),
        },
    last_result: activeSession.lastResult,
    failure_code: activeSession.failureCode,
  }
}

async function activeTab() {
  const candidates = await chrome.tabs.query({ active: true, lastFocusedWindow: true })
  if (candidates.length !== 1 || !Number.isInteger(candidates[0].id)) {
    refuse('HTTP_AUTHED_BROWSER_TAB_UNAVAILABLE')
  }
  return candidates[0]
}

async function runInTab(tabId, func, args = []) {
  let executions
  try {
    executions = await chrome.scripting.executeScript({
      target: { tabId, frameIds: [0] },
      world: 'ISOLATED',
      func,
      args,
    })
  } catch {
    refuse('HTTP_AUTHED_BROWSER_INJECTION_REFUSED')
  }
  if (executions.length !== 1 || executions[0].result === undefined) {
    refuse('HTTP_AUTHED_BROWSER_INJECTION_REFUSED')
  }
  return executions[0].result
}

async function previewTab() {
  const tab = await activeTab()
  const observed = await runInTab(tab.id, () => globalThis.location.origin)
  if (!exactHttpsOrigin(observed)) refuse('HTTP_AUTHED_BROWSER_ORIGIN_INVALID')
  return { ok: true, origin: observed }
}

async function previewController(message) {
  if (
    activeSession !== null
    || !Number.isInteger(message.port)
    || message.port < 1024
    || message.port > 65535
    || !/^[A-Za-z0-9_-]{43}$/u.test(message.capability ?? '')
  ) refuse('HTTP_AUTHED_BROWSER_PREVIEW_INVALID')
  const tabPreview = await previewTab()
  const transient = {
    port: message.port,
    stopRequested: false,
    loopbackAbortController: null,
  }
  const preview = (await loopbackRequest(transient, {
    path: ROUTES.preview,
    method: 'GET',
    capability: { kind: 'pairing', value: message.capability },
    body: undefined,
  })).value
  if (
    !exactKeys(preview, [
      'protocol',
      'schema_version',
      'type',
      'target_origin',
      'campaign_grant_sha256',
      'extension_id',
      'expires_at',
    ])
    || preview.protocol !== PROTOCOL
    || preview.schema_version !== SCHEMA_VERSION
    || preview.type !== 'PREVIEW'
    || preview.target_origin !== tabPreview.origin
    || !/^[a-f0-9]{64}$/u.test(preview.campaign_grant_sha256 ?? '')
    || preview.extension_id !== chrome.runtime.id
    || typeof preview.expires_at !== 'string'
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(preview.expires_at)
  ) refuse('HTTP_AUTHED_BROWSER_PREVIEW_BINDING_MISMATCH')
  return {
    ok: true,
    origin: preview.target_origin,
    campaign_grant_sha256: preview.campaign_grant_sha256,
    expires_at: preview.expires_at,
  }
}

async function assertAttachedDocument(session) {
  const identity = await runInTab(session.tabId, inspectHttpAuthedDocument)
  if (
    !isObject(identity)
    || identity.target_origin !== session.origin
    || identity.document_nonce !== session.documentNonce
  ) refuse('HTTP_AUTHED_BROWSER_DOCUMENT_MISMATCH')
}

async function readBoundedJson(response) {
  const contentType = response.headers.get('content-type') ?? ''
  if (!contentType.toLowerCase().startsWith('application/json') || response.body === null) {
    refuse('HTTP_AUTHED_BROWSER_LOOPBACK_PROTOCOL_INVALID')
  }
  const reader = response.body.getReader()
  const decoder = new TextDecoder('utf-8', { fatal: true })
  let text = ''
  let bytes = 0
  try {
    while (true) {
      const part = await reader.read()
      if (part.done) break
      bytes += part.value.byteLength
      if (bytes > MAX_LOOPBACK_RESPONSE_BYTES) {
        await reader.cancel()
        refuse('HTTP_AUTHED_BROWSER_LOOPBACK_PROTOCOL_INVALID')
      }
      text += decoder.decode(part.value, { stream: true })
    }
    text += decoder.decode()
  } catch (error) {
    if (error instanceof BridgeFailure) throw error
    refuse('HTTP_AUTHED_BROWSER_LOOPBACK_PROTOCOL_INVALID')
  }
  try {
    const parsed = JSON.parse(text)
    if (!isObject(parsed)) refuse('HTTP_AUTHED_BROWSER_LOOPBACK_PROTOCOL_INVALID')
    return parsed
  } catch (error) {
    if (error instanceof BridgeFailure) throw error
    refuse('HTTP_AUTHED_BROWSER_LOOPBACK_PROTOCOL_INVALID')
  }
}

async function loopbackRequest(session, {
  path,
  method,
  capability,
  body,
  allowNoContent = false,
  requireJson = true,
}) {
  if (session.stopRequested && path !== ROUTES.close) {
    refuse('HTTP_AUTHED_BROWSER_STOPPED')
  }
  const controller = new AbortController()
  session.loopbackAbortController = controller
  const timeout = setTimeout(() => controller.abort(), LOOPBACK_TIMEOUT_MS)
  let response
  try {
    const authHeader = capability.kind === 'pairing' ? PAIRING_HEADER : SESSION_HEADER
    response = await fetch(`http://127.0.0.1:${session.port}${path}`, {
      method,
      headers: {
        [authHeader]: capability.value,
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      credentials: 'omit',
      redirect: 'error',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      signal: controller.signal,
    })
    if (allowNoContent && response.status === 204) return { status: 204, value: null, response }
    if (!response.ok) refuse('HTTP_AUTHED_BROWSER_LOOPBACK_REFUSED')
    if (!requireJson) return { status: response.status, value: null, response }
    return { status: response.status, value: await readBoundedJson(response), response }
  } catch (error) {
    if (error instanceof BridgeFailure) throw error
    refuse('HTTP_AUTHED_BROWSER_LOOPBACK_UNAVAILABLE')
  } finally {
    clearTimeout(timeout)
    if (session.loopbackAbortController === controller) session.loopbackAbortController = null
  }
}

function decodeCanonicalBase64(value, maximum) {
  if (typeof value !== 'string' || value.length > Math.ceil(maximum / 3) * 4 + 4) {
    refuse('HTTP_AUTHED_BROWSER_ACTION_INVALID')
  }
  if (value !== '' && !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) {
    refuse('HTTP_AUTHED_BROWSER_ACTION_INVALID')
  }
  let binary
  try {
    binary = atob(value)
  } catch {
    refuse('HTTP_AUTHED_BROWSER_ACTION_INVALID')
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0))
  if (bytes.byteLength > maximum) refuse('HTTP_AUTHED_BROWSER_ACTION_INVALID')
  return bytes
}

async function sha256Hex(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

function validateRequestHeaders(headers, bodyPresent, bodyBytes) {
  if (!isObject(headers) || Object.keys(headers).length > REQUEST_HEADER_NAMES.size) {
    refuse('HTTP_AUTHED_BROWSER_ACTION_INVALID')
  }
  const normalized = {}
  for (const [name, value] of Object.entries(headers)) {
    if (
      name !== name.toLowerCase()
      || !REQUEST_HEADER_NAMES.has(name)
      || typeof value !== 'string'
      || value.length > 8192
      || /[\u0000-\u001f\u007f]/u.test(value)
    ) refuse('HTTP_AUTHED_BROWSER_ACTION_INVALID')
    normalized[name] = value
  }
  if (bodyPresent) {
    if (
      normalized['content-length'] !== String(bodyBytes)
      || typeof normalized['content-type'] !== 'string'
      || normalized['content-type'].length === 0
    ) {
      refuse('HTTP_AUTHED_BROWSER_ACTION_INVALID')
    }
  } else if (normalized['content-length'] !== undefined || normalized['content-type'] !== undefined) {
    refuse('HTTP_AUTHED_BROWSER_ACTION_INVALID')
  }
  return Object.fromEntries(Object.entries(normalized).sort(([left], [right]) => left.localeCompare(right)))
}

async function validatePrepare(value, session) {
  if (!exactKeys(value, [
    'protocol',
    'schema_version',
    'type',
    'campaign_id',
    'action_id',
    'action_nonce',
    'action_sha256',
    'document_nonce',
    'deadline',
    'request',
  ])) refuse('HTTP_AUTHED_BROWSER_ACTION_INVALID')
  if (
    value.protocol !== PROTOCOL
    || value.schema_version !== SCHEMA_VERSION
    || value.type !== 'PREPARE'
    || value.campaign_id !== session.campaignGrantSha256
    || !opaque(value.action_id)
    || !/^[A-Za-z0-9_-]{43}$/u.test(value.action_nonce ?? '')
    || !/^[a-f0-9]{64}$/u.test(value.action_sha256 ?? '')
    || value.document_nonce !== session.documentNonce
    || typeof value.deadline !== 'string'
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value.deadline)
    || !exactKeys(value.request, [
      'origin',
      'path_and_query',
      'method',
      'headers',
      'body_base64',
      'body_sha256',
      'body_bytes',
      'timeout_ms',
      'max_response_bytes',
      'observe_response',
    ])
  ) refuse('HTTP_AUTHED_BROWSER_ACTION_INVALID')

  const request = value.request
  if (
    request.origin !== session.origin
    || !validPathAndQuery(request.path_and_query, session.origin)
    || !/^[!#$%&'*+.^_`|~0-9A-Z-]{1,64}$/u.test(request.method ?? '')
    || FETCH_FORBIDDEN_METHODS.has(request.method)
    || !Number.isInteger(request.body_bytes)
    || request.body_bytes < 0
    || request.body_bytes > 16 * 1024 * 1024
    || !Number.isInteger(request.timeout_ms)
    || request.timeout_ms < 1000
    || request.timeout_ms > 30_000
    || !Number.isInteger(request.max_response_bytes)
    || request.max_response_bytes < 0
    || request.max_response_bytes > MAX_RESPONSE_BYTES
    || typeof request.observe_response !== 'boolean'
  ) refuse('HTTP_AUTHED_BROWSER_ACTION_INVALID')

  let bodyBytes = new Uint8Array(0)
  const bodyPresent = request.body_base64 !== null
  try {
    if (bodyPresent) {
      if (!/^[a-f0-9]{64}$/u.test(request.body_sha256 ?? '')) {
        refuse('HTTP_AUTHED_BROWSER_ACTION_INVALID')
      }
      bodyBytes = decodeCanonicalBase64(request.body_base64, 16 * 1024 * 1024)
      if (
        bodyBytes.byteLength !== request.body_bytes
        || await sha256Hex(bodyBytes) !== request.body_sha256
      ) refuse('HTTP_AUTHED_BROWSER_ACTION_INVALID')
    } else if (request.body_sha256 !== null || request.body_bytes !== 0) {
      refuse('HTTP_AUTHED_BROWSER_ACTION_INVALID')
    }
    const headers = validateRequestHeaders(request.headers, bodyPresent, request.body_bytes)
    const canonical = JSON.stringify({
      protocol: PROTOCOL,
      schema_version: SCHEMA_VERSION,
      campaign_id: value.campaign_id,
      action_id: value.action_id,
      action_nonce: value.action_nonce,
      document_nonce: value.document_nonce,
      request: {
        origin: request.origin,
        path_and_query: request.path_and_query,
        method: request.method,
        headers: Object.entries(headers),
        body_sha256: request.body_sha256,
        body_bytes: request.body_bytes,
        timeout_ms: request.timeout_ms,
        max_response_bytes: request.max_response_bytes,
        observe_response: request.observe_response,
      },
    })
    if (await sha256Hex(new TextEncoder().encode(canonical)) !== value.action_sha256) {
      refuse('HTTP_AUTHED_BROWSER_ACTION_BINDING_MISMATCH')
    }
    return structuredClone(value)
  } finally {
    bodyBytes.fill(0)
  }
}

function injectedCommand(prepared, session) {
  const request = prepared.request
  const contentType = request.headers['content-type']
  return {
    protocol: PROTOCOL,
    schema_version: SCHEMA_VERSION,
    session_id: prepared.campaign_id,
    dispatch_id: prepared.action_nonce,
    target_origin: request.origin,
    document_nonce: prepared.document_nonce,
    action_binding_sha256: prepared.action_sha256,
    method: request.method,
    relative_url: request.path_and_query,
    body: request.body_base64 === null
      ? null
      : {
          encoding: 'base64',
          value: request.body_base64,
          sha256: request.body_sha256,
          byte_length: request.body_bytes,
          content_type: contentType,
        },
    headers: Object.entries(request.headers)
      .filter(([name]) => name === 'accept' || name === 'content-type')
      .map(([name, value]) => ({ name, value })),
    timeout_ms: request.timeout_ms,
    max_response_bytes: request.max_response_bytes,
    observe_response: request.observe_response,
  }
}

function validateExecution(result, prepared) {
  if (
    !isObject(result)
    || result.protocol !== PROTOCOL
    || result.schema_version !== SCHEMA_VERSION
    || result.session_id !== prepared.campaign_id
    || result.dispatch_id !== prepared.action_nonce
    || result.action_binding_sha256 !== prepared.action_sha256
    || result.outcome !== 'OBSERVED'
    || !Number.isInteger(result.status)
    || result.status < 100
    || result.status > 599
    || !Number.isInteger(result.bytes)
    || result.bytes < 0
    || result.bytes > prepared.request.max_response_bytes
    || !Array.isArray(result.header_names)
    || result.header_names.length > 256
    || result.header_names.some((name) => !/^[a-z-]{2,64}$/u.test(name))
    || result.redirected !== false
    || !isObject(result.response)
    || result.response.status !== result.status
    || result.response.response_bytes !== result.bytes
    || JSON.stringify(result.response.response_header_names) !== JSON.stringify(result.header_names)
    || !Array.isArray(result.response.headers)
    || result.response.headers.length > 256
  ) refuse('HTTP_AUTHED_BROWSER_RESULT_INVALID')
  const observed = prepared.request.observe_response
  if (!observed) {
    if (result.response.headers.length !== 0 || result.response.body_base64 !== null) {
      refuse('HTTP_AUTHED_BROWSER_RESULT_INVALID')
    }
  } else {
    const body = decodeCanonicalBase64(result.response.body_base64, prepared.request.max_response_bytes)
    if (body.byteLength !== result.bytes) refuse('HTTP_AUTHED_BROWSER_RESULT_INVALID')
    body.fill(0)
    let totalHeaderBytes = 0
    for (const header of result.response.headers) {
      if (
        !exactKeys(header, ['name', 'value_base64'])
        || !/^[!#$%&'*+.^_`|~0-9a-z-]{1,128}$/u.test(header.name ?? '')
      ) refuse('HTTP_AUTHED_BROWSER_RESULT_INVALID')
      const value = decodeCanonicalBase64(header.value_base64, 8192)
      totalHeaderBytes += header.name.length + value.byteLength
      value.fill(0)
      if (totalHeaderBytes > 65_536) refuse('HTTP_AUTHED_BROWSER_RESULT_INVALID')
    }
  }
  return result
}

async function executePrepared(session, prepared) {
  session.phase = 'PREPARED'
  session.prepared = prepared
  await assertAttachedDocument(session)
  await runInTab(session.tabId, prepareHttpAuthedInjectedFetch, [{
    target_origin: session.origin,
    document_nonce: session.documentNonce,
    action_binding_sha256: prepared.action_sha256,
  }])
  session.phase = 'READY'
  const committed = (await loopbackRequest(session, {
    path: ROUTES.ready,
    method: 'POST',
    capability: { kind: 'session', value: session.capability },
    body: bindingEnvelope(prepared, 'READY'),
  })).value
  if (
    !sameBinding(committed, prepared, 'COMMIT', ['committed_at'])
    || typeof committed.committed_at !== 'string'
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(committed.committed_at)
  ) refuse('HTTP_AUTHED_BROWSER_COMMIT_INVALID')
  if (session.stopRequested) refuse('HTTP_AUTHED_BROWSER_STOPPED')

  session.phase = 'COMMIT'
  let execution
  try {
    execution = await runInTab(
      session.tabId,
      executeHttpAuthedInjectedFetch,
      [injectedCommand(prepared, session)],
    )
  } catch {
    refuse('HTTP_AUTHED_BROWSER_DISPATCH_OUTCOME_UNCERTAIN')
  }
  validateExecution(execution, prepared)
  const resultEnvelope = {
    ...bindingEnvelope(prepared, 'RESULT'),
    outcome: 'RESPONSE',
    response: {
      status: execution.status,
      response_bytes: execution.bytes,
      response_header_names: execution.header_names,
      headers: execution.response.headers,
      body_base64: execution.response.body_base64,
    },
  }
  session.phase = 'RESULT'
  const accepted = (await loopbackRequest(session, {
    path: ROUTES.result,
    method: 'POST',
    capability: { kind: 'session', value: session.capability },
    body: resultEnvelope,
  })).value
  if (!exactKeys(accepted, ['protocol', 'schema_version', 'type', 'accepted'])
    || accepted.protocol !== PROTOCOL
    || accepted.schema_version !== SCHEMA_VERSION
    || accepted.type !== 'RESULT'
    || accepted.accepted !== true
  ) refuse('HTTP_AUTHED_BROWSER_RESULT_ACK_INVALID')

  session.actionsCompleted += 1
  session.lastResult = {
    status: execution.status,
    response_bytes: execution.bytes,
  }
  execution.response.headers.length = 0
  execution.response.body_base64 = null
  resultEnvelope.response.headers.length = 0
  resultEnvelope.response.body_base64 = null
  session.prepared = null
  session.phase = 'OPEN'
}

async function delay(milliseconds) {
  await new Promise((resolve) => setTimeout(resolve, milliseconds))
}

async function campaignLoop(session) {
  while (activeSession === session && !session.stopRequested && session.failureCode === null) {
    const preparedResponse = await loopbackRequest(session, {
      path: ROUTES.prepare,
      method: 'POST',
      capability: { kind: 'session', value: session.capability },
      body: undefined,
      allowNoContent: true,
    })
    if (preparedResponse.status === 204) {
      session.phase = 'OPEN'
      await delay(250)
      continue
    }
    const prepared = await validatePrepare(preparedResponse.value, session)
    await executePrepared(session, prepared)
  }
}

async function attach(message) {
  if (activeSession !== null) refuse('HTTP_AUTHED_BROWSER_ALREADY_ATTACHED')
  if (
    !Number.isInteger(message.port)
    || message.port < 1024
    || message.port > 65535
    || !/^[A-Za-z0-9_-]{43}$/u.test(message.capability ?? '')
    || !/^[a-f0-9]{64}$/u.test(message.campaign_grant_sha256 ?? '')
    || !exactHttpsOrigin(message.reviewed_origin)
  ) refuse('HTTP_AUTHED_BROWSER_ATTACH_INVALID')
  const tab = await activeTab()
  const identity = await runInTab(tab.id, captureHttpAuthedDocument)
  if (
    !isObject(identity)
    || identity.target_origin !== message.reviewed_origin
    || !opaque(identity.document_nonce, 16, 128)
  ) refuse('HTTP_AUTHED_BROWSER_ORIGIN_MISMATCH')

  const session = {
    port: message.port,
    capability: message.capability,
    tabId: tab.id,
    origin: identity.target_origin,
    documentNonce: identity.document_nonce,
    campaignGrantSha256: message.campaign_grant_sha256,
    phase: 'ATTACHING',
    prepared: null,
    actionsCompleted: 0,
    lastResult: null,
    failureCode: null,
    stopRequested: false,
    loopbackAbortController: null,
  }
  const openedResponse = await loopbackRequest(session, {
    path: ROUTES.open,
    method: 'POST',
    capability: { kind: 'pairing', value: session.capability },
    body: {
      protocol: PROTOCOL,
      schema_version: SCHEMA_VERSION,
      type: 'OPEN',
      campaign_id: session.campaignGrantSha256,
      target_origin: session.origin,
      tab_id: session.tabId,
      document_nonce: session.documentNonce,
    },
  })
  const opened = openedResponse.value
  if (
    !exactKeys(opened, [
      'protocol',
      'schema_version',
      'type',
      'campaign_id',
      'target_origin',
      'tab_id',
      'document_nonce',
      'session_capability',
    ])
    || opened.protocol !== PROTOCOL
    || opened.schema_version !== SCHEMA_VERSION
    || opened.type !== 'OPEN'
    || opened.campaign_id !== session.campaignGrantSha256
    || opened.target_origin !== session.origin
    || opened.tab_id !== session.tabId
    || opened.document_nonce !== session.documentNonce
  ) refuse('HTTP_AUTHED_BROWSER_OPEN_INVALID')
  const responseCapability = openedResponse.response.headers.get(SESSION_HEADER)
    ?? opened.session_capability
  if (!/^[A-Za-z0-9_-]{43}$/u.test(responseCapability ?? '')) {
    refuse('HTTP_AUTHED_BROWSER_SESSION_CAPABILITY_INVALID')
  }
  if (responseCapability !== opened.session_capability) {
    refuse('HTTP_AUTHED_BROWSER_SESSION_CAPABILITY_INVALID')
  }
  session.capability = responseCapability
  opened.session_capability = null
  session.phase = 'OPEN'
  activeSession = session
  void campaignLoop(session).catch((error) => {
    if (activeSession !== session || session.stopRequested) return
    session.failureCode = error instanceof BridgeFailure
      ? error.code
      : 'HTTP_AUTHED_BROWSER_CAMPAIGN_FAILED'
    session.phase = session.phase === 'COMMIT'
      ? 'OUTCOME_UNCERTAIN'
      : 'STOPPED'
  })
  return { ok: true, state: stateSummary() }
}

async function detach() {
  const session = activeSession
  if (session === null) return { ok: true, state: stateSummary() }
  session.stopRequested = true
  session.phase = 'STOPPING'
  session.loopbackAbortController?.abort()
  try {
    await runInTab(session.tabId, abortHttpAuthedInjectedFetch)
  } catch {
    // A closed or navigated tab already prevents further dispatch.
  }
  try {
    await loopbackRequest(session, {
      path: ROUTES.close,
      method: 'POST',
      capability: { kind: 'session', value: session.capability },
      body: {
        protocol: PROTOCOL,
        schema_version: SCHEMA_VERSION,
        type: 'CLOSE',
        campaign_id: session.campaignGrantSha256,
      },
      requireJson: false,
    })
  } catch {
    // Losing the loopback channel is itself a fail-closed stop signal.
  }
  try {
    await runInTab(session.tabId, clearHttpAuthedInjectedPreparation)
  } catch {
    // The worker capability is still discarded below.
  }
  session.capability = null
  session.prepared = null
  activeSession = null
  return { ok: true, state: stateSummary() }
}

async function route(message) {
  if (!isObject(message) || typeof message.type !== 'string') {
    refuse('HTTP_AUTHED_BROWSER_MESSAGE_INVALID')
  }
  switch (message.type) {
    case 'STATUS': return { ok: true, state: stateSummary() }
    case 'PREVIEW_TAB': return previewTab()
    case 'PREVIEW_CONTROLLER': return previewController(message)
    case 'ATTACH': return attach(message)
    case 'DETACH': return detach()
    default: refuse('HTTP_AUTHED_BROWSER_MESSAGE_INVALID')
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const popupUrl = chrome.runtime.getURL('popup.html')
  if (sender.id !== chrome.runtime.id || sender.url !== popupUrl) {
    sendResponse({ ok: false, error_code: 'HTTP_AUTHED_BROWSER_SENDER_REFUSED', state: stateSummary() })
    return false
  }
  void route(message).then(
    sendResponse,
    (error) => sendResponse({
      ok: false,
      error_code: error instanceof BridgeFailure ? error.code : 'HTTP_AUTHED_BROWSER_OPERATION_FAILED',
      state: stateSummary(),
    }),
  )
  return true
})
