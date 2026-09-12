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
const LOOPBACK_PERMISSION = 'http://127.0.0.1/*'
const PAIRING_HEADER = 'x-red-team-audit-pairing'
const SESSION_HEADER = 'x-red-team-audit-session'
const EXTENSION_HEADER = 'x-last-aperture-extension'
const BASE64URL_256 = /^[A-Za-z0-9_-]{43}$/u
const SHA256 = /^[a-f0-9]{64}$/u
const IDENTIFIER = /^[A-Za-z0-9._:-]{1,128}$/u
const DOCUMENT_NONCE = /^[A-Za-z0-9._~-]{16,128}$/u
// A 16 MiB sealed request body expands to about 21.34 MiB in base64. Keep the
// controller envelope bound large enough for that body plus bounded metadata.
const MAX_CONTROLLER_MESSAGE_BYTES = 24 * 1024 * 1024
const CONTROLLER_REQUEST_TIMEOUT_MS = 15_000
const DEFAULT_POLL_DELAY_MS = 100
const STORAGE_KEEPALIVE_MS = 20_000
const POPUP_KEEPALIVE_NAME = 'last-aperture-popup'
const RECOVERY_STORAGE_KEY = 'last_aperture_http_authed_recovery_v1'
const RECOVERY_PHASES = new Set(['OPEN', 'PREPARED', 'COMMIT'])
const intrinsicByteFill = Uint8Array.prototype.fill

class CompanionError extends Error {
  constructor(code) {
    super(code)
    this.name = 'LastApertureBrowserCompanionError'
    this.code = code
  }
}

function fail(code) {
  throw new CompanionError(code)
}

function eraseBytes(value) {
  try {
    if (value instanceof Uint8Array) Reflect.apply(intrinsicByteFill, value, [0])
  } catch {
    // Controller producers may detach or resize storage after handoff.
  }
}

function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function exact(value, fields) {
  if (!plain(value)) return false
  const actual = Object.keys(value).sort()
  const expected = [...fields].sort()
  return actual.length === expected.length
    && actual.every((field, index) => field === expected[index])
}

function controllerOrigin(port) {
  if (!Number.isSafeInteger(port) || port < 1024 || port > 65535) {
    fail('HTTP_AUTHED_BROWSER_CONTROLLER_PORT_INVALID')
  }
  return `http://127.0.0.1:${port}`
}

function assertPairingCode(value) {
  if (typeof value !== 'string' || !BASE64URL_256.test(value)) {
    fail('HTTP_AUTHED_BROWSER_PAIRING_INVALID')
  }
  return value
}

function assertCanonicalHttpsOrigin(value) {
  try {
    const parsed = new URL(value)
    if (
      parsed.protocol !== 'https:'
      || parsed.origin !== value
      || parsed.pathname !== '/'
      || parsed.search !== ''
      || parsed.hash !== ''
      || parsed.username !== ''
      || parsed.password !== ''
    ) fail('HTTP_AUTHED_BROWSER_TARGET_INVALID')
    return value
  } catch (error) {
    if (error instanceof CompanionError) throw error
    fail('HTTP_AUTHED_BROWSER_TARGET_INVALID')
  }
}

function assertControllerOrigin(value) {
  try {
    const parsed = new URL(value)
    const port = Number(parsed.port)
    if (
      parsed.protocol !== 'http:'
      || parsed.hostname !== '127.0.0.1'
      || parsed.username !== ''
      || parsed.password !== ''
      || parsed.pathname !== '/'
      || parsed.search !== ''
      || parsed.hash !== ''
      || controllerOrigin(port) !== value
    ) fail('HTTP_AUTHED_BROWSER_RECOVERY_INVALID')
    return value
  } catch (error) {
    if (error instanceof CompanionError) throw error
    fail('HTTP_AUTHED_BROWSER_RECOVERY_INVALID')
  }
}

function cancelReader(reader) {
  try {
    Promise.resolve(reader.cancel()).catch(() => {})
  } catch {
    // Cancellation is best-effort and must never extend the controller deadline.
  }
}

async function readJsonBounded(response, withinDeadline) {
  if (response.body === null) fail('HTTP_AUTHED_BROWSER_CONTROLLER_RESPONSE_INVALID')
  const reader = response.body.getReader()
  const declared = response.headers.get('content-length')
  const chunks = []
  let length = 0
  try {
    if (
      declared !== null
      && (!/^(?:0|[1-9][0-9]*)$/u.test(declared)
        || Number(declared) > MAX_CONTROLLER_MESSAGE_BYTES)
    ) fail('HTTP_AUTHED_BROWSER_CONTROLLER_RESPONSE_TOO_LARGE')
    while (true) {
      const pendingRead = Promise.resolve().then(() => reader.read())
      let part
      try {
        part = await withinDeadline(() => pendingRead)
      } catch (error) {
        pendingRead.then((latePart) => {
          eraseBytes(latePart?.value)
        }, () => {})
        throw error
      }
      if (part.done) {
        eraseBytes(part.value)
        break
      }
      if (!(part.value instanceof Uint8Array)) {
        fail('HTTP_AUTHED_BROWSER_CONTROLLER_RESPONSE_INVALID')
      }
      length += part.value.byteLength
      if (length > MAX_CONTROLLER_MESSAGE_BYTES) {
        eraseBytes(part.value)
        fail('HTTP_AUTHED_BROWSER_CONTROLLER_RESPONSE_TOO_LARGE')
      }
      chunks.push(part.value)
    }
    const bytes = new Uint8Array(length)
    let offset = 0
    for (const chunk of chunks) {
      bytes.set(chunk, offset)
      offset += chunk.byteLength
    }
    try {
      return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
    } catch {
      fail('HTTP_AUTHED_BROWSER_CONTROLLER_RESPONSE_INVALID')
    } finally {
      eraseBytes(bytes)
    }
  } catch (error) {
    cancelReader(reader)
    throw error
  } finally {
    for (const chunk of chunks) eraseBytes(chunk)
    chunks.length = 0
    length = 0
  }
}

function errorCode(error) {
  return typeof error?.code === 'string' && /^[A-Z0-9_]{3,128}$/u.test(error.code)
    ? error.code
    : 'HTTP_AUTHED_BROWSER_COMPANION_FAILED'
}

function validatePreview(value, extensionId) {
  if (
    !exact(value, [
      'protocol', 'schema_version', 'type', 'target_origin',
      'campaign_grant_sha256', 'extension_id', 'expires_at',
    ])
    || value.protocol !== PROTOCOL
    || value.schema_version !== SCHEMA_VERSION
    || value.type !== 'PREVIEW'
    || value.extension_id !== extensionId
    || !SHA256.test(value.campaign_grant_sha256 ?? '')
    || !Number.isFinite(Date.parse(value.expires_at))
  ) fail('HTTP_AUTHED_BROWSER_PREVIEW_INVALID')
  assertCanonicalHttpsOrigin(value.target_origin)
  return structuredClone(value)
}

function validateRecoveryRecord(value, extensionId) {
  if (
    !exact(value, [
      'protocol', 'schema_version', 'type', 'extension_id', 'phase',
      'bridge_origin', 'preview', 'tab_id', 'active_tab_origin', 'document_nonce',
    ])
    || value.protocol !== PROTOCOL
    || value.schema_version !== SCHEMA_VERSION
    || value.type !== 'SESSION_RECOVERY'
    || value.extension_id !== extensionId
    || !RECOVERY_PHASES.has(value.phase)
    || !Number.isSafeInteger(value.tab_id)
    || value.tab_id < 0
    || value.tab_id > 2147483647
    || typeof value.document_nonce !== 'string'
    || !DOCUMENT_NONCE.test(value.document_nonce)
  ) fail('HTTP_AUTHED_BROWSER_RECOVERY_INVALID')
  const preview = validatePreview(value.preview, extensionId)
  assertControllerOrigin(value.bridge_origin)
  assertCanonicalHttpsOrigin(value.active_tab_origin)
  if (value.active_tab_origin !== preview.target_origin) {
    fail('HTTP_AUTHED_BROWSER_RECOVERY_INVALID')
  }
  return {
    phase: value.phase,
    bridgeOrigin: value.bridge_origin,
    preview,
    tabId: value.tab_id,
    activeTabOrigin: value.active_tab_origin,
    documentNonce: value.document_nonce,
  }
}

function validateOpened(value, expected) {
  if (
    !exact(value, [
      'protocol', 'schema_version', 'type', 'campaign_id', 'target_origin',
      'tab_id', 'document_nonce', 'session_capability',
    ])
    || value.protocol !== PROTOCOL
    || value.schema_version !== SCHEMA_VERSION
    || value.type !== 'OPEN'
    || value.campaign_id !== expected.campaignId
    || value.target_origin !== expected.targetOrigin
    || value.tab_id !== expected.tabId
    || value.document_nonce !== expected.documentNonce
    || !BASE64URL_256.test(value.session_capability ?? '')
  ) fail('HTTP_AUTHED_BROWSER_OPEN_INVALID')
  return value
}

function binding(value) {
  const bound = {
    protocol: value.protocol,
    schema_version: value.schema_version,
    campaign_id: value.campaign_id,
    action_id: value.action_id,
    action_nonce: value.action_nonce,
    action_sha256: value.action_sha256,
    document_nonce: value.document_nonce,
  }
  if (value.session_adapter_sha256 !== undefined) {
    bound.session_adapter_sha256 = value.session_adapter_sha256
  }
  return bound
}

function validatePrepared(value, state) {
  const hasAdapter = plain(value)
    && (Object.hasOwn(value, 'session_adapter')
      || Object.hasOwn(value, 'session_adapter_sha256'))
  const keys = [
    'protocol', 'schema_version', 'type', 'campaign_id', 'action_id',
    'action_nonce', 'action_sha256', 'document_nonce', 'deadline', 'request',
    ...(hasAdapter ? ['session_adapter', 'session_adapter_sha256'] : []),
  ]
  if (
    !exact(value, keys)
    || value.protocol !== PROTOCOL
    || value.schema_version !== SCHEMA_VERSION
    || value.type !== 'PREPARE'
    || value.campaign_id !== state.preview.campaign_grant_sha256
    || value.document_nonce !== state.documentNonce
    || !IDENTIFIER.test(value.action_id ?? '')
    || !BASE64URL_256.test(value.action_nonce ?? '')
    || !SHA256.test(value.action_sha256 ?? '')
    || !Number.isFinite(Date.parse(value.deadline))
    || !plain(value.request)
    || value.request.origin !== state.preview.target_origin
    || (hasAdapter && (
      !plain(value.session_adapter)
      || !SHA256.test(value.session_adapter_sha256 ?? '')
    ))
  ) fail('HTTP_AUTHED_BROWSER_PREPARE_INVALID')
  return value
}

function validateCommit(value, prepared) {
  const expected = binding(prepared)
  if (
    !exact(value, [...Object.keys(expected), 'type', 'committed_at'])
    || value.type !== 'COMMIT'
    || !Number.isFinite(Date.parse(value.committed_at))
    || Object.entries(expected).some(([name, expectedValue]) => value[name] !== expectedValue)
  ) fail('HTTP_AUTHED_BROWSER_COMMIT_INVALID')
  return value
}

function injectedCommand(prepared, timeoutMs = prepared.request.timeout_ms) {
  const request = prepared.request
  if (!plain(request.headers)) fail('HTTP_AUTHED_BROWSER_PREPARE_INVALID')
  const headers = []
  for (const [name, value] of Object.entries(request.headers)) {
    const normalized = name.toLowerCase()
    if (!['accept', 'content-length', 'content-type', 'user-agent'].includes(normalized)) {
      fail('HTTP_AUTHED_BROWSER_PREPARE_INVALID')
    }
    if (['accept', 'content-type'].includes(normalized)) {
      headers.push({ name: normalized, value })
    }
  }
  const contentType = request.headers['content-type']
  const body = typeof request.body_base64 !== 'string'
    ? undefined
    : {
        encoding: 'base64',
        value: request.body_base64,
        byte_length: request.body_bytes,
        sha256: request.body_sha256,
        content_type: contentType,
      }
  return {
    protocol: PROTOCOL,
    schema_version: SCHEMA_VERSION,
    session_id: prepared.campaign_id,
    dispatch_id: prepared.action_id,
    target_origin: request.origin,
    document_nonce: prepared.document_nonce,
    action_binding_sha256: prepared.action_sha256,
    method: request.method,
    relative_url: request.path_and_query,
    headers,
    ...(body === undefined ? {} : { body }),
    timeout_ms: timeoutMs,
    deadline_epoch_ms: Date.parse(prepared.deadline),
    max_response_bytes: request.max_response_bytes,
    observe_response: request.observe_response,
    ...(prepared.session_adapter_sha256 === undefined
      ? {}
      : {
          session_adapter: structuredClone(prepared.session_adapter),
          session_adapter_sha256: prepared.session_adapter_sha256,
        }),
  }
}

export function createBrowserBridgeCompanion({
  chromeApi,
  fetchImpl = globalThis.fetch?.bind(globalThis),
  setTimer = globalThis.setTimeout?.bind(globalThis),
  clearTimer = globalThis.clearTimeout?.bind(globalThis),
  clock = Date.now,
  pollDelayMs = DEFAULT_POLL_DELAY_MS,
  autoPump = true,
} = {}) {
  const sessionStorage = chromeApi?.storage?.session
  if (
    !chromeApi?.runtime?.id
    || typeof chromeApi.permissions?.contains !== 'function'
    || typeof chromeApi.tabs?.query !== 'function'
    || typeof chromeApi.scripting?.executeScript !== 'function'
    || typeof sessionStorage?.get !== 'function'
    || typeof sessionStorage?.set !== 'function'
    || typeof sessionStorage?.remove !== 'function'
    || typeof sessionStorage?.setAccessLevel !== 'function'
    || typeof fetchImpl !== 'function'
    || typeof setTimer !== 'function'
    || typeof clearTimer !== 'function'
    || typeof clock !== 'function'
    || !Number.isSafeInteger(pollDelayMs)
    || pollDelayMs < 0
    || pollDelayMs > 10_000
  ) fail('HTTP_AUTHED_BROWSER_COMPANION_DEPENDENCY_INVALID')

  const state = {
    phase: 'IDLE',
    bridgeOrigin: null,
    pairingCode: null,
    preview: null,
    tabId: null,
    activeTabOrigin: null,
    documentNonce: null,
    sessionCapability: null,
    generation: 0,
    pumpPromise: null,
    lastError: null,
    lastStorageActivity: 0,
    storageReady: false,
  }

  let storageTail = Promise.resolve()
  let initializationPromise = null

  const clockMilliseconds = () => {
    const value = clock()
    if (!Number.isFinite(value)) fail('HTTP_AUTHED_BROWSER_CLOCK_INVALID')
    return value
  }

  const publicStatus = () => ({
    phase: state.phase,
    extension_id: chromeApi.runtime.id,
    preview: state.preview === null ? null : structuredClone(state.preview),
    active_tab_origin: state.activeTabOrigin,
    tab_id: state.tabId,
    last_error: state.lastError,
  })

  const storageOperation = (operation) => {
    const pending = storageTail.then(operation, operation)
    storageTail = pending.catch(() => {})
    return pending
  }

  const recoveryRecord = (phase) => ({
    protocol: PROTOCOL,
    schema_version: SCHEMA_VERSION,
    type: 'SESSION_RECOVERY',
    extension_id: chromeApi.runtime.id,
    phase,
    bridge_origin: state.bridgeOrigin,
    preview: structuredClone(state.preview),
    tab_id: state.tabId,
    active_tab_origin: state.activeTabOrigin,
    document_nonce: state.documentNonce,
  })

  const persistRecovery = async (phase, generation = state.generation) => {
    if (
      state.storageReady !== true
      || generation !== state.generation
      || !RECOVERY_PHASES.has(phase)
      || state.bridgeOrigin === null
      || state.preview === null
      || state.tabId === null
      || state.activeTabOrigin === null
      || state.documentNonce === null
    ) fail('HTTP_AUTHED_BROWSER_RECOVERY_STATE_INVALID')
    state.phase = phase
    const record = recoveryRecord(phase)
    try {
      await storageOperation(async () => {
        if (generation !== state.generation) return
        await sessionStorage.set({ [RECOVERY_STORAGE_KEY]: record })
        state.lastStorageActivity = clockMilliseconds()
      })
    } catch {
      state.storageReady = false
      fail('HTTP_AUTHED_BROWSER_RECOVERY_STORAGE_FAILED')
    }
    return generation === state.generation
  }

  const clearRecovery = async () => {
    try {
      await storageOperation(async () => {
        await sessionStorage.remove(RECOVERY_STORAGE_KEY)
        state.lastStorageActivity = clockMilliseconds()
      })
    } catch {
      state.storageReady = false
      fail('HTTP_AUTHED_BROWSER_RECOVERY_STORAGE_FAILED')
    }
  }

  const keepStorageAlive = async (generation) => {
    const current = clockMilliseconds()
    if (current - state.lastStorageActivity < STORAGE_KEEPALIVE_MS) return
    try {
      await storageOperation(async () => {
        if (generation !== state.generation) return
        await sessionStorage.get(RECOVERY_STORAGE_KEY)
        state.lastStorageActivity = clockMilliseconds()
      })
    } catch {
      state.storageReady = false
      fail('HTTP_AUTHED_BROWSER_RECOVERY_STORAGE_FAILED')
    }
  }

  const controllerRequest = async (path, {
    method = 'GET', pairingCode, sessionCapability, body,
    controllerBase = state.bridgeOrigin,
  } = {}) => {
    if (controllerBase === null || !/^\/v1\/[a-z]+$/u.test(path)) {
      fail('HTTP_AUTHED_BROWSER_CONTROLLER_REQUEST_INVALID')
    }
    assertControllerOrigin(controllerBase)
    const headers = { [EXTENSION_HEADER]: chromeApi.runtime.id }
    if (pairingCode !== undefined) headers[PAIRING_HEADER] = pairingCode
    if (sessionCapability !== undefined) headers[SESSION_HEADER] = sessionCapability
    if (body !== undefined) headers['content-type'] = 'application/json'
    const abortController = new AbortController()
    let timedOut = false
    let rejectDeadline
    const expiresAt = clockMilliseconds() + CONTROLLER_REQUEST_TIMEOUT_MS
    const deadline = new Promise((_resolve, reject) => {
      rejectDeadline = reject
    })
    // A supplied timer may invoke its callback before returning or throw after
    // doing so. Observe the deadline immediately so setup failure cannot create
    // an unhandled rejection in either case.
    void deadline.catch(() => {})
    let timeout
    try {
      timeout = setTimer(() => {
        timedOut = true
        abortController.abort()
        rejectDeadline(new Error('controller deadline exceeded'))
      }, CONTROLLER_REQUEST_TIMEOUT_MS)
    } catch {
      fail('HTTP_AUTHED_BROWSER_CONTROLLER_TIMER_FAILED')
    }
    const ensureDeadline = () => {
      if (!timedOut && clockMilliseconds() < expiresAt) return
      timedOut = true
      if (!abortController.signal.aborted) abortController.abort()
      throw new Error('controller deadline exceeded')
    }
    const withinDeadline = async (operation) => {
      ensureDeadline()
      const value = await Promise.race([Promise.resolve().then(operation), deadline])
      ensureDeadline()
      return value
    }
    try {
      const response = await withinDeadline(() => fetchImpl(`${controllerBase}${path}`, {
        method,
        headers,
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        cache: 'no-store',
        credentials: 'omit',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
        signal: abortController.signal,
      }))
      const responseMetadata = await withinDeadline(() => ({
        status: response?.status,
        ok: response?.ok,
      }))
      if (responseMetadata.status === 204) return { status: 204, value: null }
      const value = await withinDeadline(() => readJsonBounded(response, withinDeadline))
      if (!responseMetadata.ok) {
        const code = value?.error?.code
        fail(typeof code === 'string' && /^[A-Z0-9_]{3,128}$/u.test(code)
          ? code
          : 'HTTP_AUTHED_BROWSER_CONTROLLER_REJECTED')
      }
      const result = await withinDeadline(() => ({ status: responseMetadata.status, value }))
      return result
    } catch (error) {
      if (error instanceof CompanionError) throw error
      fail(timedOut
        ? 'HTTP_AUTHED_BROWSER_CONTROLLER_TIMEOUT'
        : 'HTTP_AUTHED_BROWSER_CONTROLLER_UNREACHABLE')
    } finally {
      try {
        clearTimer(timeout)
      } catch {
        // The exchange outcome is already authoritative. Timer cleanup cannot
        // replace a successful response or the primary timeout/fetch failure.
      }
    }
  }

  const executeIsolated = async (func, args = []) => {
    const results = await chromeApi.scripting.executeScript({
      target: { tabId: state.tabId },
      world: 'ISOLATED',
      func,
      args,
    })
    if (!Array.isArray(results) || results.length !== 1) {
      fail('HTTP_AUTHED_BROWSER_INJECTION_FAILED')
    }
    const injectedError = results[0]?.error
    if (injectedError !== undefined) {
      const rendered = typeof injectedError === 'string'
        ? injectedError
        : injectedError?.message
      const controlledCode = typeof rendered === 'string'
        ? rendered.match(/\bHTTP_AUTHED_BROWSER_[A-Z0-9_]{3,96}\b/u)?.[0]
        : undefined
      fail(controlledCode ?? 'HTTP_AUTHED_BROWSER_INJECTION_FAILED')
    }
    if (results[0]?.result === undefined) fail('HTTP_AUTHED_BROWSER_INJECTION_FAILED')
    return results[0].result
  }

  const reset = (lastError = null) => {
    state.generation += 1
    state.phase = 'IDLE'
    state.bridgeOrigin = null
    state.pairingCode = null
    state.preview = null
    state.tabId = null
    state.activeTabOrigin = null
    state.documentNonce = null
    state.sessionCapability = null
    state.pumpPromise = null
    state.lastError = lastError
  }

  const initialize = async () => {
    let stored
    try {
      await sessionStorage.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' })
      const values = await storageOperation(async () => {
        const result = await sessionStorage.get(RECOVERY_STORAGE_KEY)
        state.lastStorageActivity = clockMilliseconds()
        return result
      })
      stored = plain(values) ? values[RECOVERY_STORAGE_KEY] : undefined
      state.storageReady = true
    } catch {
      state.storageReady = false
      reset('HTTP_AUTHED_BROWSER_RECOVERY_STORAGE_FAILED')
      return
    }
    if (stored === undefined) return

    let recovered
    try {
      recovered = validateRecoveryRecord(stored, chromeApi.runtime.id)
    } catch {
      try { await clearRecovery() } catch {}
      reset('HTTP_AUTHED_BROWSER_RECOVERY_INVALID')
      return
    }

    state.phase = recovered.phase
    state.bridgeOrigin = recovered.bridgeOrigin
    state.preview = recovered.preview
    state.tabId = recovered.tabId
    state.activeTabOrigin = recovered.activeTabOrigin
    state.documentNonce = recovered.documentNonce
    state.sessionCapability = null
    let documentMatches = false
    try {
      const document = await executeIsolated(inspectHttpAuthedDocument)
      documentMatches = plain(document)
        && document.target_origin === recovered.preview.target_origin
        && document.document_nonce === recovered.documentNonce
    } catch {}
    try { await executeIsolated(abortHttpAuthedInjectedFetch) } catch {}
    try { await clearRecovery() } catch {}
    reset(!documentMatches
      ? 'HTTP_AUTHED_BROWSER_RECOVERY_DOCUMENT_MISMATCH'
      : (recovered.phase === 'OPEN'
          ? 'HTTP_AUTHED_BROWSER_RESTART_REATTACH_REQUIRED'
          : 'HTTP_AUTHED_BROWSER_RECOVERY_IN_FLIGHT_REFUSED'))
  }

  const ensureInitialized = () => {
    if (initializationPromise === null) initializationPromise = initialize()
    return initializationPromise
  }

  const closeSession = async ({ notifyController = true, error = null } = {}) => {
    state.generation += 1
    const snapshot = {
      bridgeOrigin: state.bridgeOrigin,
      sessionCapability: state.sessionCapability,
      campaignId: state.preview?.campaign_grant_sha256,
      tabId: state.tabId,
    }
    state.phase = 'CLOSING'
    try { await clearRecovery() } catch {}
    if (snapshot.tabId !== null) {
      try { await executeIsolated(abortHttpAuthedInjectedFetch) } catch {}
    }
    if (notifyController && snapshot.sessionCapability && snapshot.campaignId) {
      try {
        state.bridgeOrigin = snapshot.bridgeOrigin
        await controllerRequest('/v1/close', {
          method: 'POST',
          sessionCapability: snapshot.sessionCapability,
          body: {
            protocol: PROTOCOL,
            schema_version: SCHEMA_VERSION,
            type: 'CLOSE',
            campaign_id: snapshot.campaignId,
          },
        })
      } catch {}
    }
    reset(error)
    return publicStatus()
  }

  const preview = async ({ port, pairingCode }) => {
    await ensureInitialized()
    if (state.storageReady !== true) fail('HTTP_AUTHED_BROWSER_RECOVERY_STORAGE_FAILED')
    if (state.phase !== 'IDLE') fail('HTTP_AUTHED_BROWSER_SESSION_ALREADY_ACTIVE')
    const generation = state.generation
    const permission = await chromeApi.permissions.contains({ origins: [LOOPBACK_PERMISSION] })
    if (generation !== state.generation) fail('HTTP_AUTHED_BROWSER_OPERATION_CANCELLED')
    if (permission !== true) fail('HTTP_AUTHED_BROWSER_LOOPBACK_PERMISSION_REQUIRED')
    state.bridgeOrigin = controllerOrigin(port)
    state.pairingCode = assertPairingCode(pairingCode)
    const response = await controllerRequest('/v1/preview', { pairingCode: state.pairingCode })
    if (generation !== state.generation) fail('HTTP_AUTHED_BROWSER_OPERATION_CANCELLED')
    state.preview = validatePreview(response.value, chromeApi.runtime.id)
    state.phase = 'PREVIEWED'
    state.lastError = null
    return publicStatus()
  }

  const attach = async () => {
    await ensureInitialized()
    if (state.phase !== 'PREVIEWED' || state.preview === null || state.pairingCode === null) {
      fail('HTTP_AUTHED_BROWSER_PREVIEW_REQUIRED')
    }
    const generationAtStart = state.generation
    const bridgeOrigin = state.bridgeOrigin
    const previewAtStart = structuredClone(state.preview)
    const pairingCode = state.pairingCode
    const tabs = await chromeApi.tabs.query({ active: true, currentWindow: true })
    if (generationAtStart !== state.generation) fail('HTTP_AUTHED_BROWSER_OPERATION_CANCELLED')
    if (!Array.isArray(tabs) || tabs.length !== 1 || !Number.isSafeInteger(tabs[0]?.id)) {
      fail('HTTP_AUTHED_BROWSER_ACTIVE_TAB_INVALID')
    }
    let tabOrigin
    try {
      const tabUrl = new URL(tabs[0].url)
      if (tabUrl.protocol !== 'https:') fail('HTTP_AUTHED_BROWSER_ACTIVE_TAB_INVALID')
      tabOrigin = tabUrl.origin
    } catch (error) {
      if (error instanceof CompanionError) throw error
      fail('HTTP_AUTHED_BROWSER_ACTIVE_TAB_INVALID')
    }
    if (tabOrigin !== previewAtStart.target_origin) fail('HTTP_AUTHED_BROWSER_ACTIVE_TAB_MISMATCH')
    const tabId = tabs[0].id
    state.tabId = tabId
    state.activeTabOrigin = tabOrigin
    const document = await executeIsolated(captureHttpAuthedDocument)
    if (generationAtStart !== state.generation) fail('HTTP_AUTHED_BROWSER_OPERATION_CANCELLED')
    if (
      !plain(document)
      || document.target_origin !== previewAtStart.target_origin
      || typeof document.document_nonce !== 'string'
      || !DOCUMENT_NONCE.test(document.document_nonce)
    ) fail('HTTP_AUTHED_BROWSER_DOCUMENT_INVALID')
    const documentNonce = document.document_nonce
    state.documentNonce = documentNonce
    const response = await controllerRequest('/v1/open', {
      method: 'POST',
      pairingCode,
      controllerBase: bridgeOrigin,
      body: {
        protocol: PROTOCOL,
        schema_version: SCHEMA_VERSION,
        type: 'OPEN',
        campaign_id: previewAtStart.campaign_grant_sha256,
        target_origin: previewAtStart.target_origin,
        tab_id: tabId,
        document_nonce: documentNonce,
      },
    })
    const opened = validateOpened(response.value, {
      campaignId: previewAtStart.campaign_grant_sha256,
      targetOrigin: previewAtStart.target_origin,
      tabId,
      documentNonce,
    })
    if (generationAtStart !== state.generation) {
      try {
        await controllerRequest('/v1/close', {
          method: 'POST',
          sessionCapability: opened.session_capability,
          controllerBase: bridgeOrigin,
          body: {
            protocol: PROTOCOL,
            schema_version: SCHEMA_VERSION,
            type: 'CLOSE',
            campaign_id: previewAtStart.campaign_grant_sha256,
          },
        })
      } catch {}
      fail('HTTP_AUTHED_BROWSER_OPERATION_CANCELLED')
    }
    state.sessionCapability = opened.session_capability
    state.pairingCode = null
    state.phase = 'OPEN'
    const generation = ++state.generation
    try {
      await persistRecovery('OPEN', generation)
    } catch (error) {
      await closeSession({ error: errorCode(error) })
      throw error
    }
    if (generation !== state.generation) fail('HTTP_AUTHED_BROWSER_OPERATION_CANCELLED')
    if (autoPump) {
      state.pumpPromise = pump(generation).catch(async (error) => {
        await closeSession({ error: errorCode(error) })
      })
    }
    return publicStatus()
  }

  const runOneCycle = async (generation = state.generation) => {
    if (state.phase !== 'OPEN' || state.sessionCapability === null) {
      fail('HTTP_AUTHED_BROWSER_SESSION_NOT_OPEN')
    }
    const sessionCapability = state.sessionCapability
    const preparedResponse = await controllerRequest('/v1/prepare', {
      method: 'POST',
      sessionCapability,
    })
    if (generation !== state.generation || state.phase !== 'OPEN') return 'CLOSED'
    if (preparedResponse.status === 204) return 'IDLE'
    const prepared = validatePrepared(preparedResponse.value, state)
    state.phase = 'PREPARED'
    if (!await persistRecovery('PREPARED', generation)) return 'CLOSED'
    try {
      await executeIsolated(prepareHttpAuthedInjectedFetch, [{
        target_origin: prepared.request.origin,
        document_nonce: prepared.document_nonce,
        action_binding_sha256: prepared.action_sha256,
        ...(prepared.session_adapter_sha256 === undefined
          ? {}
          : { session_adapter_sha256: prepared.session_adapter_sha256 }),
      }])
      if (generation !== state.generation || state.phase !== 'PREPARED') return 'CLOSED'
      const readyResponse = await controllerRequest('/v1/ready', {
        method: 'POST',
        sessionCapability,
        body: { ...binding(prepared), type: 'READY' },
      })
      if (generation !== state.generation || state.phase !== 'PREPARED') return 'CLOSED'
      validateCommit(readyResponse.value, prepared)
      state.phase = 'COMMIT'
      if (!await persistRecovery('COMMIT', generation)) return 'CLOSED'
      if (generation !== state.generation || state.phase !== 'COMMIT') return 'CLOSED'
      const remainingMs = Math.min(
        prepared.request.timeout_ms,
        Math.floor(Date.parse(prepared.deadline) - clockMilliseconds()),
      )
      if (remainingMs < 100) fail('HTTP_AUTHED_BROWSER_ACTION_EXPIRED')
      const result = await executeIsolated(
        executeHttpAuthedInjectedFetch,
        [injectedCommand(prepared, remainingMs)],
      )
      if (generation !== state.generation || state.phase !== 'COMMIT') return 'CLOSED'
      if (
        plain(result)
        && exact(result, ['error_code', 'request_may_have_been_sent'])
        && /^HTTP_AUTHED_BROWSER_[A-Z0-9_]{3,96}$/u.test(result.error_code ?? '')
        && typeof result.request_may_have_been_sent === 'boolean'
      ) fail(result.error_code)
      const complete = result?.outcome === 'OBSERVED'
        && result?.response_truncated === false
      const bounded = result?.outcome === 'RESPONSE_BOUNDED'
        && result?.response_truncated === true
      const incomplete = result?.outcome === 'OBSERVATION_INCOMPLETE'
        && result?.response_truncated === false
      if (!plain(result)) {
        if (result === null) fail('HTTP_AUTHED_BROWSER_RESULT_NULL')
        if (Array.isArray(result)) fail('HTTP_AUTHED_BROWSER_RESULT_ARRAY')
        if (typeof result === 'string') fail('HTTP_AUTHED_BROWSER_RESULT_STRING')
        if (typeof result === 'number') fail('HTTP_AUTHED_BROWSER_RESULT_NUMBER')
        if (typeof result === 'boolean') fail('HTTP_AUTHED_BROWSER_RESULT_BOOLEAN')
        fail('HTTP_AUTHED_BROWSER_RESULT_INVALID')
      }
      if (result.action_binding_sha256 !== prepared.action_sha256) {
        fail('HTTP_AUTHED_BROWSER_RESULT_BINDING_INVALID')
      }
      if (result.session_adapter_sha256 !== prepared.session_adapter_sha256) {
        fail('HTTP_AUTHED_BROWSER_RESULT_ADAPTER_INVALID')
      }
      if (!plain(result.response)) fail('HTTP_AUTHED_BROWSER_RESULT_RESPONSE_INVALID')
      if (!complete && !bounded && !incomplete) {
        fail('HTTP_AUTHED_BROWSER_RESULT_OUTCOME_INVALID')
      }
      const response = structuredClone(result.response)
      if (!Object.hasOwn(response, 'body_base64')) response.body_base64 = null
      await controllerRequest('/v1/result', {
        method: 'POST',
        sessionCapability,
        body: {
          ...binding(prepared),
          type: 'RESULT',
          outcome: result.outcome,
          response_truncated: result.response_truncated,
          response,
        },
      })
      if (generation !== state.generation || state.phase !== 'COMMIT') return 'CLOSED'
      state.phase = 'OPEN'
      if (!await persistRecovery('OPEN', generation)) return 'CLOSED'
      return 'EXECUTED'
    } finally {
      try { await executeIsolated(clearHttpAuthedInjectedPreparation) } catch {}
    }
  }

  const delay = (milliseconds) => new Promise((resolve) => {
    setTimer(resolve, milliseconds)
  })

  async function pump(generation) {
    while (state.phase === 'OPEN' && generation === state.generation) {
      const result = await runOneCycle(generation)
      if (result === 'IDLE') {
        await keepStorageAlive(generation)
        await delay(pollDelayMs)
      }
    }
  }

  const handleMessage = async (message) => {
    if (!plain(message) || typeof message.type !== 'string') {
      fail('HTTP_AUTHED_BROWSER_MESSAGE_INVALID')
    }
    await ensureInitialized()
    if (message.type === 'LAST_APERTURE_STATUS') return publicStatus()
    if (message.type === 'LAST_APERTURE_PREVIEW') {
      if (!exact(message, ['type', 'port', 'pairing_code'])) {
        fail('HTTP_AUTHED_BROWSER_MESSAGE_INVALID')
      }
      return preview({ port: message.port, pairingCode: message.pairing_code })
    }
    if (message.type === 'LAST_APERTURE_ATTACH') {
      if (!exact(message, ['type'])) fail('HTTP_AUTHED_BROWSER_MESSAGE_INVALID')
      return attach()
    }
    if (message.type === 'LAST_APERTURE_CLOSE') {
      if (!exact(message, ['type'])) fail('HTTP_AUTHED_BROWSER_MESSAGE_INVALID')
      return closeSession()
    }
    fail('HTTP_AUTHED_BROWSER_MESSAGE_INVALID')
  }

  const install = () => {
    void ensureInitialized()
    chromeApi.runtime.onConnect?.addListener((port) => {
      if (
        port?.name !== POPUP_KEEPALIVE_NAME
        || (port.sender?.id !== undefined && port.sender.id !== chromeApi.runtime.id)
        || typeof port.onMessage?.addListener !== 'function'
        || typeof port.onDisconnect?.addListener !== 'function'
      ) {
        try { port?.disconnect?.() } catch {}
        return
      }
      port.onMessage.addListener((message) => {
        if (!exact(message, ['type']) || message.type !== 'KEEPALIVE') {
          try { port.disconnect() } catch {}
        }
      })
      port.onDisconnect.addListener(() => {})
    })
    chromeApi.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (sender?.id !== undefined && sender.id !== chromeApi.runtime.id) return false
      handleMessage(message).then(
        (value) => sendResponse({ ok: true, value }),
        (error) => sendResponse({ ok: false, error: errorCode(error) }),
      )
      return true
    })
  }

  return Object.freeze({
    attach,
    close: async () => {
      await ensureInitialized()
      return closeSession()
    },
    handleMessage,
    install,
    preview,
    runOneCycle: async () => {
      await ensureInitialized()
      return runOneCycle()
    },
    status: publicStatus,
  })
}

if (globalThis.chrome?.runtime?.onMessage) {
  createBrowserBridgeCompanion({ chromeApi: globalThis.chrome }).install()
}
