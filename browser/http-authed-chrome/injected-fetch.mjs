export function captureHttpAuthedDocument() {
  const STATE_KEY = '__red_team_audit_http_authed_bridge_v1__'
  if (globalThis.location?.protocol !== 'https:') {
    const error = new Error('the selected document is not an HTTPS origin')
    error.code = 'HTTP_AUTHED_BROWSER_ORIGIN_INVALID'
    throw error
  }
  const random = new Uint8Array(24)
  globalThis.crypto.getRandomValues(random)
  const documentNonce = globalThis.btoa(String.fromCharCode(...random))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/u, '')
  globalThis[STATE_KEY] = {
    document_nonce: documentNonce,
    prepared_action_binding_sha256: null,
  }
  return {
    target_origin: globalThis.location.origin,
    document_nonce: documentNonce,
  }
}

export function prepareHttpAuthedInjectedFetch(preparation) {
  const STATE_KEY = '__red_team_audit_http_authed_bridge_v1__'
  const fail = (code, message) => {
    const error = new Error(message)
    error.code = code
    throw error
  }
  const state = globalThis[STATE_KEY]
  if (
    preparation === null
    || typeof preparation !== 'object'
    || Array.isArray(preparation)
    || typeof state !== 'object'
    || state === null
  ) fail('HTTP_AUTHED_BROWSER_DOCUMENT_MISMATCH', 'the attached document is no longer active')
  if (globalThis.location.origin !== preparation.target_origin) {
    fail('HTTP_AUTHED_BROWSER_ORIGIN_MISMATCH', 'the active origin no longer matches the prepared origin')
  }
  if (state.document_nonce !== preparation.document_nonce) {
    fail('HTTP_AUTHED_BROWSER_DOCUMENT_MISMATCH', 'the active document no longer matches the attached document')
  }
  if (!/^[a-f0-9]{64}$/u.test(preparation.action_binding_sha256 ?? '')) {
    fail('HTTP_AUTHED_BROWSER_ACTION_INVALID', 'the prepared action binding is invalid')
  }
  state.prepared_action_binding_sha256 = preparation.action_binding_sha256
  return { prepared: true }
}

export function inspectHttpAuthedDocument() {
  const STATE_KEY = '__red_team_audit_http_authed_bridge_v1__'
  const state = globalThis[STATE_KEY]
  return {
    target_origin: globalThis.location?.origin ?? null,
    document_nonce: typeof state === 'object' && state !== null
      ? state.document_nonce
      : null,
  }
}

export function clearHttpAuthedInjectedPreparation() {
  const STATE_KEY = '__red_team_audit_http_authed_bridge_v1__'
  const state = globalThis[STATE_KEY]
  if (typeof state === 'object' && state !== null) {
    state.prepared_action_binding_sha256 = null
  }
  return { cleared: true }
}

export function abortHttpAuthedInjectedFetch() {
  const STATE_KEY = '__red_team_audit_http_authed_bridge_v1__'
  const state = globalThis[STATE_KEY]
  if (typeof state === 'object' && state !== null) {
    state.abort_controller?.abort()
    state.prepared_action_binding_sha256 = null
  }
  return { aborted: true }
}

export async function executeHttpAuthedInjectedFetch(command, suppliedRuntime = {}) {
  const STATE_KEY = '__red_team_audit_http_authed_bridge_v1__'
  const PROTOCOL = 'red-team-audit/http-authed-browser-bridge'
  const FETCH_FORBIDDEN_METHODS = new Set(['CONNECT', 'TRACE', 'TRACK'])
  const HEADER_ALLOWLIST = new Set(['accept', 'content-type'])
  const MAX_BODY_BYTES = 16_777_216
  const MAX_RESPONSE_BYTES = 1_048_576

  const failure = (code, message, requestMayHaveBeenSent = false) => {
    const error = new Error(message)
    error.code = code
    error.request_may_have_been_sent = requestMayHaveBeenSent
    return error
  }
  const invalid = () => {
    throw failure('HTTP_AUTHED_BROWSER_ACTION_INVALID', 'the prepared browser action is invalid')
  }
  const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value)
  const opaque = (value, maximum = 256) => (
    typeof value === 'string'
    && value.length >= 8
    && value.length <= maximum
    && !/[\u0000-\u001f\u007f]/u.test(value)
  )
  const exactOrigin = (value) => {
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
  const relativeUrl = (value, origin) => {
    if (
      typeof value !== 'string'
      || value.length < 1
      || value.length > 4096
      || !value.startsWith('/')
      || value.startsWith('//')
      || value.includes('#')
      || /(?:[\\\u0000-\u0020\u007f]|%(?:25)*(?:2e|2f|5c))/iu.test(value)
    ) return null
    try {
      const parsed = new URL(value, origin)
      return parsed.origin === origin && `${parsed.pathname}${parsed.search}` === value
        ? parsed.href
        : null
    } catch {
      return null
    }
  }
  const decodeBody = async (body) => {
    if (body === null) return { bytes: undefined, contentType: undefined }
    if (!isObject(body)) invalid()
    if (
      body.encoding !== 'base64'
      || typeof body.value !== 'string'
      || body.value.length > Math.ceil(MAX_BODY_BYTES / 3) * 4
      || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(body.value)
      || !Number.isInteger(body.byte_length)
      || body.byte_length < 0
      || body.byte_length > MAX_BODY_BYTES
      || !/^[a-f0-9]{64}$/u.test(body.sha256 ?? '')
      || typeof body.content_type !== 'string'
      || body.content_type.length < 3
      || body.content_type.length > 128
      || /[\u0000-\u001f\u007f]/u.test(body.content_type)
    ) invalid()
    let binary
    try {
      binary = globalThis.atob(body.value)
    } catch {
      invalid()
    }
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0))
    if (bytes.byteLength !== body.byte_length) invalid()
    const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes))
    const digestHex = Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('')
    if (digestHex !== body.sha256) invalid()
    return { bytes, contentType: body.content_type }
  }
  const requestHeaders = (entries, contentType) => {
    if (entries === undefined) entries = []
    if (!Array.isArray(entries) || entries.length > 16) invalid()
    const result = {}
    const seen = new Set()
    for (const entry of entries) {
      if (!isObject(entry) || typeof entry.name !== 'string' || typeof entry.value !== 'string') invalid()
      const name = entry.name.toLowerCase()
      if (
        name !== entry.name
        || !HEADER_ALLOWLIST.has(name)
        || seen.has(name)
        || entry.value.length > 1024
        || /[\u0000-\u001f\u007f]/u.test(entry.value)
      ) invalid()
      seen.add(name)
      result[name] = entry.value
    }
    if (contentType !== undefined) {
      if (seen.has('content-type') && result['content-type'] !== contentType) invalid()
      result['content-type'] = contentType
    }
    return result
  }
  const safeHeaderNames = (headers) => {
    const names = new Set()
    const retained = new Set([
      'allow',
      'cache-control',
      'content-length',
      'content-type',
      'etag',
      'last-modified',
      'location',
      'retry-after',
      'www-authenticate',
    ])
    for (const [name] of headers) names.add(retained.has(name.toLowerCase()) ? name.toLowerCase() : 'other')
    return [...names].sort()
  }
  const transientHeaders = (headers) => {
    const encoder = new TextEncoder()
    const fields = []
    let totalBytes = 0
    for (const [name, value] of headers) {
      const normalizedName = name.toLowerCase()
      const valueBytes = encoder.encode(value)
      totalBytes += valueBytes.byteLength
      if (
        fields.length >= 128
        || totalBytes > 65_536
        || !/^[!#$%&'*+.^_`|~0-9a-z-]{1,128}$/u.test(normalizedName)
        || valueBytes.byteLength > 8192
      ) {
        throw failure(
          'HTTP_AUTHED_BROWSER_RESPONSE_HEADERS_BOUNDED',
          'response header observation exceeded the transient bridge boundary',
          true,
        )
      }
      fields.push({ name: normalizedName, value_base64: bytesToBase64(valueBytes) })
    }
    return fields
  }
  const bytesToBase64 = (bytes) => {
    let binary = ''
    for (let offset = 0; offset < bytes.byteLength; offset += 32_768) {
      binary += String.fromCharCode(...bytes.subarray(offset, offset + 32_768))
    }
    return globalThis.btoa(binary)
  }

  if (!isObject(command) || command.protocol !== PROTOCOL || command.schema_version !== '1.0.0') invalid()
  if (
    !opaque(command.session_id)
    || !opaque(command.dispatch_id)
    || !opaque(command.document_nonce, 128)
    || !/^[a-f0-9]{64}$/u.test(command.action_binding_sha256 ?? '')
    || typeof command.method !== 'string'
    || !/^[!#$%&'*+.^_`|~0-9A-Z-]{1,64}$/u.test(command.method)
    || FETCH_FORBIDDEN_METHODS.has(command.method)
    || !exactOrigin(command.target_origin)
  ) invalid()

  const activeLocation = suppliedRuntime.location ?? globalThis.location
  if (activeLocation?.origin !== command.target_origin) {
    throw failure('HTTP_AUTHED_BROWSER_ORIGIN_MISMATCH', 'the active origin does not match the committed origin')
  }
  const bridgeState = globalThis[STATE_KEY]
  const documentNonce = suppliedRuntime.documentNonce ?? bridgeState?.document_nonce
  if (documentNonce !== command.document_nonce) {
    throw failure('HTTP_AUTHED_BROWSER_DOCUMENT_MISMATCH', 'the active document does not match the attached document')
  }
  const preparedBinding = suppliedRuntime.preparedActionBindingSha256
    ?? bridgeState?.prepared_action_binding_sha256
  if (preparedBinding !== command.action_binding_sha256) {
    throw failure('HTTP_AUTHED_BROWSER_ACTION_BINDING_MISMATCH', 'the committed action does not match the prepared action')
  }

  const url = relativeUrl(command.relative_url, command.target_origin)
  if (url === null) invalid()
  const { bytes: bodyBytes, contentType } = await decodeBody(command.body)
  if ((command.method === 'GET' || command.method === 'HEAD') && bodyBytes !== undefined) {
    bodyBytes.fill(0)
    invalid()
  }
  let headers
  try {
    headers = requestHeaders(command.headers, contentType)
  } catch (error) {
    bodyBytes?.fill(0)
    throw error
  }
  const timeoutMs = command.timeout_ms ?? 15_000
  const maxResponseBytes = command.max_response_bytes ?? MAX_RESPONSE_BYTES
  const observeResponse = command.observe_response ?? true
  if (
    !Number.isInteger(timeoutMs)
    || timeoutMs < 100
    || timeoutMs > 60_000
    || !Number.isInteger(maxResponseBytes)
    || maxResponseBytes < 0
    || maxResponseBytes > MAX_RESPONSE_BYTES
    || typeof observeResponse !== 'boolean'
  ) {
    bodyBytes?.fill(0)
    invalid()
  }

  if (isObject(bridgeState)) bridgeState.prepared_action_binding_sha256 = null
  const fetchImpl = suppliedRuntime.fetchImpl ?? globalThis.fetch.bind(globalThis)
  if (typeof fetchImpl !== 'function') invalid()
  const abortController = new AbortController()
  if (isObject(bridgeState)) bridgeState.abort_controller = abortController
  const timeout = globalThis.setTimeout(() => abortController.abort(), timeoutMs)
  const started = globalThis.performance?.now?.() ?? Date.now()
  let response
  try {
    response = await fetchImpl(url, {
      method: command.method,
      headers,
      ...(bodyBytes === undefined ? {} : { body: bodyBytes }),
      credentials: 'same-origin',
      redirect: 'error',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      mode: 'same-origin',
      signal: abortController.signal,
    })
  } catch {
    globalThis.clearTimeout(timeout)
    bodyBytes?.fill(0)
    if (isObject(bridgeState) && bridgeState.abort_controller === abortController) {
      bridgeState.abort_controller = null
    }
    throw failure(
      'HTTP_AUTHED_BROWSER_FETCH_FAILED',
      'the committed request failed after dispatch; it was not retried',
      true,
    )
  }

  let bytes = 0
  let truncated = false
  let bodyReadIncomplete = false
  const bodyChunks = []
  try {
    if (response.body !== null && command.method !== 'HEAD') {
      const reader = response.body.getReader()
      while (true) {
        const part = await reader.read()
        if (part.done) break
        const remaining = Math.max(0, maxResponseBytes - bytes)
        if (observeResponse && remaining > 0) bodyChunks.push(part.value.slice(0, remaining))
        bytes += Math.min(remaining, part.value.byteLength)
        if (part.value.byteLength > remaining) {
          truncated = true
          await reader.cancel()
          break
        }
      }
    }
  } catch {
    bodyReadIncomplete = true
  } finally {
    globalThis.clearTimeout(timeout)
    if (isObject(bridgeState) && bridgeState.abort_controller === abortController) {
      bridgeState.abort_controller = null
    }
  }

  const finished = globalThis.performance?.now?.() ?? Date.now()
  const capturedBody = new Uint8Array(observeResponse ? bytes : 0)
  let bodyOffset = 0
  for (const chunk of bodyChunks) {
    capturedBody.set(chunk, bodyOffset)
    bodyOffset += chunk.byteLength
  }
  try {
    const headerNames = safeHeaderNames(response.headers)
    const responseHeaders = observeResponse ? transientHeaders(response.headers) : []
    const bodyBase64 = observeResponse ? bytesToBase64(capturedBody) : null
    return {
      protocol: PROTOCOL,
      schema_version: '1.0.0',
      session_id: command.session_id,
      dispatch_id: command.dispatch_id,
      action_binding_sha256: command.action_binding_sha256,
      outcome: bodyReadIncomplete ? 'OBSERVATION_INCOMPLETE' : (truncated ? 'RESPONSE_BOUNDED' : 'OBSERVED'),
      status: Number.isInteger(response.status) ? response.status : null,
      bytes,
      response_truncated: truncated,
      header_names: headerNames,
      redirected: response.redirected === true,
      elapsed_ms: Math.max(0, Math.min(60_000, Math.round(finished - started))),
      response: {
        status: Number.isInteger(response.status) ? response.status : null,
        response_bytes: bytes,
        response_header_names: headerNames,
        headers: responseHeaders,
        body_base64: bodyBase64,
      },
    }
  } finally {
    bodyBytes?.fill(0)
    capturedBody.fill(0)
    for (const chunk of bodyChunks) chunk.fill(0)
  }
}
