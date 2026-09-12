export function captureHttpAuthedDocument() {
  const STATE_KEY = '__red_team_audit_http_authed_bridge_v1__'
  if (globalThis.location?.protocol !== 'https:') {
    const error = new Error('the selected document is not an HTTPS origin')
    error.code = 'HTTP_AUTHED_BROWSER_ORIGIN_INVALID'
    throw error
  }
  const random = new Uint8Array(24)
  globalThis.crypto.getRandomValues(random)
  let documentNonce
  try {
    documentNonce = globalThis.btoa(String.fromCharCode(...random))
      .replaceAll('+', '-')
      .replaceAll('/', '_')
      .replace(/=+$/u, '')
  } finally {
    random.fill(0)
  }
  globalThis[STATE_KEY] = {
    document_nonce: documentNonce,
    prepared_action_binding_sha256: null,
    prepared_session_adapter_sha256: null,
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
  if (!(
    preparation.session_adapter_sha256 === undefined
    || preparation.session_adapter_sha256 === null
    || /^[a-f0-9]{64}$/u.test(preparation.session_adapter_sha256 ?? '')
  )) fail('HTTP_AUTHED_BROWSER_ACTION_INVALID', 'the prepared session adapter binding is invalid')
  state.prepared_action_binding_sha256 = preparation.action_binding_sha256
  state.prepared_session_adapter_sha256 = preparation.session_adapter_sha256 ?? null
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
    state.prepared_session_adapter_sha256 = null
  }
  return { cleared: true }
}

export function abortHttpAuthedInjectedFetch() {
  const STATE_KEY = '__red_team_audit_http_authed_bridge_v1__'
  const state = globalThis[STATE_KEY]
  if (typeof state === 'object' && state !== null) {
    state.abort_controller?.abort()
    state.prepared_action_binding_sha256 = null
    state.prepared_session_adapter_sha256 = null
  }
  return { aborted: true }
}

export async function executeHttpAuthedInjectedFetch(command, suppliedRuntime = {}) {
  const browserDispatch = arguments.length === 1
  let validationStage = 'ENVELOPE'
  let cleanupBodyBytes = null
  let cleanupBridgeState = null
  let cleanupAbortController = null
  let cleanupHeaders = null
  let cleanupSessionCarrierName = null
  let requestMayHaveBeenSent = false
  const intrinsicByteFill = Uint8Array.prototype.fill
  const eraseBytes = (value) => {
    try {
      if (value instanceof Uint8Array) Reflect.apply(intrinsicByteFill, value, [0])
    } catch {
      // Target code may detach or resize any byte storage handed to Fetch.
    }
  }
  try {
  const STATE_KEY = '__red_team_audit_http_authed_bridge_v1__'
  const PROTOCOL = 'red-team-audit/http-authed-browser-bridge'
  const FETCH_FORBIDDEN_METHODS = new Set(['CONNECT', 'TRACE', 'TRACK'])
  const HEADER_ALLOWLIST = new Set(['accept', 'content-type'])
  const OBSERVABLE_RESPONSE_HEADERS = new Set([
    'allow',
    'content-encoding',
    'content-type',
    'link',
    'location',
  ])
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
  const ambiguousEncodedPath = (value) => {
    let current = value
    for (let pass = 0; pass < 8; pass += 1) {
      if (/%(?:2e|2f|5c)/iu.test(current)) return true
      if (!current.includes('%')) return false
      let decoded
      try { decoded = decodeURIComponent(current) } catch { return true }
      if (decoded === current) return false
      current = decoded
    }
    return current.includes('%')
  }
  const relativeUrl = (value, origin) => {
    if (
      typeof value !== 'string'
      || value.length < 1
      || value.length > 4096
      || !value.startsWith('/')
      || value.startsWith('//')
      || value.includes('#')
      || /[\\\u0000-\u0020\u007f]/u.test(value)
      || ambiguousEncodedPath(value.split('?', 1)[0])
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
    if (body === undefined || body === null) return { bytes: undefined, contentType: undefined }
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
    binary = null
    let digest = null
    let accepted = false
    try {
      if (bytes.byteLength !== body.byte_length) invalid()
      digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes))
      const digestHex = Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('')
      if (digestHex !== body.sha256) invalid()
      accepted = true
      return { bytes, contentType: body.content_type }
    } finally {
      eraseBytes(digest)
      if (!accepted) eraseBytes(bytes)
    }
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
  const boundedResponseHeaders = (headers) => {
    if (headers === null || typeof headers?.[Symbol.iterator] !== 'function') {
      throw failure(
        'HTTP_AUTHED_BROWSER_RESPONSE_HEADERS_BOUNDED',
        'response headers are not a bounded iterable collection',
        true,
      )
    }
    const encoder = new TextEncoder()
    const fields = []
    let totalBytes = 0
    for (const field of headers) {
      if (
        !Array.isArray(field)
        || field.length !== 2
        || typeof field[0] !== 'string'
        || typeof field[1] !== 'string'
      ) {
        throw failure(
          'HTTP_AUTHED_BROWSER_RESPONSE_HEADERS_BOUNDED',
          'response headers contain an invalid field',
          true,
        )
      }
      const normalizedName = field[0].toLowerCase()
      const valueBytes = encoder.encode(field[1])
      try {
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
        fields.push([normalizedName, field[1]])
      } finally {
        eraseBytes(valueBytes)
      }
    }
    return fields
  }
  const safeHeaderNames = (headers) => {
    const names = new Set()
    const retained = new Set([
      'allow',
      'cache-control',
      'content-encoding',
      'content-length',
      'content-type',
      'etag',
      'last-modified',
      'link',
      'location',
      'retry-after',
      'set-cookie',
      'www-authenticate',
    ])
    for (const [name] of headers) names.add(retained.has(name) ? name : 'other')
    return [...names].sort()
  }
  const transientHeaders = (headers) => {
    const encoder = new TextEncoder()
    const fields = []
    for (const [name, value] of headers) {
      if (!OBSERVABLE_RESPONSE_HEADERS.has(name)) continue
      const valueBytes = encoder.encode(value)
      try {
        fields.push({ name, value_base64: bytesToBase64(valueBytes) })
      } finally {
        eraseBytes(valueBytes)
      }
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
  const exactKeys = (value, keys) => {
    if (!isObject(value)) return false
    const actual = Object.keys(value).sort()
    const expected = [...keys].sort()
    return actual.length === expected.length
      && actual.every((key, index) => key === expected[index])
  }
  const adapterFailure = (code, message) => {
    throw failure(code, message)
  }
  const exactTimestamp = (value) => {
    const milliseconds = Date.parse(value)
    return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value
      ? milliseconds
      : null
  }
  const pathMatchesPrefix = (pathname, prefix) => (
    prefix === '/'
    || pathname === prefix
    || (prefix.endsWith('/')
      ? pathname.startsWith(prefix)
      : pathname.startsWith(`${prefix}/`))
  )
  const canonicalPathPrefix = (value) => {
    if (
      typeof value !== 'string'
      || value.length < 1
      || value.length > 2048
      || !value.startsWith('/')
      || value.startsWith('//')
      || value.includes('?')
      || value.includes('#')
      || /(?:[\\\u0000-\u0020\u007f*{}]|%(?:25)*(?:2e|2f|5c))/iu.test(value)
    ) return false
    try {
      const parsed = new URL(value, 'https://adapter.invalid')
      return parsed.origin === 'https://adapter.invalid'
        && parsed.pathname === value
        && parsed.search === ''
        && parsed.hash === ''
    } catch {
      return false
    }
  }
  const stableValue = (value) => {
    if (Array.isArray(value)) return value.map(stableValue)
    if (!isObject(value)) return value
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, stableValue(value[key])]),
    )
  }
  const digestAdapter = async (adapter) => {
    const bytes = new TextEncoder().encode(JSON.stringify(stableValue(adapter)))
    let digest = null
    try {
      digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes))
      return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('')
    } finally {
      eraseBytes(digest)
      eraseBytes(bytes)
    }
  }
  const validateSessionAdapter = async (adapter, expectedSha256, now, requestUrl) => {
    const forbiddenHeaders = new Set([
      '__proto__', 'accept', 'accept-charset', 'accept-encoding',
      'access-control-request-headers', 'access-control-request-method',
      'connection', 'constructor', 'content-length', 'content-type', 'cookie',
      'cookie2', 'date', 'dnt', 'expect', 'forwarded', 'host', 'keep-alive', 'origin',
      'permissions-policy', 'prototype',
      'proxy-authorization', 'proxy-connection', 'referer', 'referrer',
      'set-cookie', 'te', 'trailer', 'transfer-encoding', 'upgrade',
      'user-agent', 'via', 'x-http-method', 'x-http-method-override',
      'x-envoy-original-path', 'x-forwarded-for', 'x-forwarded-host',
      'x-forwarded-prefix', 'x-forwarded-uri', 'x-http-url-override',
      'x-last-aperture-extension', 'x-method-override',
      'x-original-uri', 'x-original-url', 'x-rewrite-uri', 'x-rewrite-url',
      'x-red-team-audit-pairing', 'x-red-team-audit-session',
    ])
    if (
      !exactKeys(adapter, [
        'schema_version', 'kind', 'adapter_id', 'source', 'carrier',
        'target_constraints', 'validity', 'limits',
      ])
      || adapter.schema_version !== '1.0.0'
      || adapter.kind !== 'last-aperture/page-session-adapter'
      || !/^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/u.test(adapter.adapter_id ?? '')
      || !exactKeys(adapter.source, ['type', 'area', 'key', 'extraction'])
      || adapter.source.type !== 'WEB_STORAGE'
      || !['LOCAL', 'SESSION'].includes(adapter.source.area)
      || typeof adapter.source.key !== 'string'
      || adapter.source.key.length < 1
      || adapter.source.key.length > 256
      || /[\u0000-\u001f\u007f]/u.test(adapter.source.key)
      || !isObject(adapter.source.extraction)
      || !exactKeys(adapter.carrier, [
        'type', 'name', ...(adapter.carrier?.prefix === undefined ? [] : ['prefix']),
      ])
      || adapter.carrier.type !== 'REQUEST_HEADER'
      || !/^[!#$%&'*+.^_`|~0-9a-z-]{1,128}$/u.test(adapter.carrier.name ?? '')
      || forbiddenHeaders.has(adapter.carrier.name)
      || adapter.carrier.name.startsWith('proxy-')
      || adapter.carrier.name.startsWith('sec-')
      || adapter.carrier.name.startsWith('x-forwarded-')
      || (adapter.carrier.prefix !== undefined && (
        typeof adapter.carrier.prefix !== 'string'
        || adapter.carrier.prefix.length > 256
        || /[\u0000-\u001f\u007f]/u.test(adapter.carrier.prefix)
      ))
      || !Array.isArray(adapter.target_constraints)
      || adapter.target_constraints.length < 1
      || adapter.target_constraints.length > 256
      || !exactKeys(adapter.validity, ['not_before', 'not_after'])
      || !exactKeys(adapter.limits, ['max_value_bytes'])
      || !Number.isInteger(adapter.limits.max_value_bytes)
      || adapter.limits.max_value_bytes < 1
      || adapter.limits.max_value_bytes > 8192
      || new TextEncoder().encode(adapter.carrier.prefix ?? '').byteLength
        + adapter.limits.max_value_bytes > 8192
      || !/^[a-f0-9]{64}$/u.test(expectedSha256 ?? '')
    ) adapterFailure('HTTP_AUTHED_BROWSER_SESSION_ADAPTER_INVALID', 'the page session adapter is invalid')

    const extraction = adapter.source.extraction
    if (extraction.mode === 'RAW') {
      if (!exactKeys(extraction, ['mode'])) {
        adapterFailure('HTTP_AUTHED_BROWSER_SESSION_ADAPTER_INVALID', 'the page session adapter extraction is invalid')
      }
    } else if (extraction.mode === 'JSON_POINTER') {
      if (
        !exactKeys(extraction, ['mode', 'pointer'])
        || typeof extraction.pointer !== 'string'
        || extraction.pointer.length < 1
        || extraction.pointer.length > 1024
        || !/^(?:\/(?:[^~/\u0000-\u001f\u007f]|~[01])*)+$/u.test(extraction.pointer)
      ) adapterFailure('HTTP_AUTHED_BROWSER_SESSION_ADAPTER_INVALID', 'the page session adapter extraction is invalid')
      const blocked = new Set(['__proto__', 'prototype', 'constructor'])
      const segments = extraction.pointer.slice(1).split('/').map((segment) => (
        segment.replaceAll('~1', '/').replaceAll('~0', '~')
      ))
      if (segments.some((segment) => blocked.has(segment))) {
        adapterFailure('HTTP_AUTHED_BROWSER_SESSION_ADAPTER_INVALID', 'the page session adapter extraction is invalid')
      }
    } else {
      adapterFailure('HTTP_AUTHED_BROWSER_SESSION_ADAPTER_INVALID', 'the page session adapter extraction is invalid')
    }

    const uniqueTargets = new Set()
    for (const constraint of adapter.target_constraints) {
      if (
        !exactKeys(constraint, ['origin', 'method', 'path_prefix'])
        || !exactOrigin(constraint.origin)
        || /[*{}?]/u.test(constraint.origin)
        || !/^[!#$%&'*+.^_`|~0-9A-Z-]{1,64}$/u.test(constraint.method ?? '')
        || FETCH_FORBIDDEN_METHODS.has(constraint.method)
        || !canonicalPathPrefix(constraint.path_prefix)
      ) adapterFailure('HTTP_AUTHED_BROWSER_SESSION_ADAPTER_INVALID', 'the page session adapter target is invalid')
      const identity = `${constraint.origin}\n${constraint.method}\n${constraint.path_prefix}`
      if (uniqueTargets.has(identity)) {
        adapterFailure('HTTP_AUTHED_BROWSER_SESSION_ADAPTER_INVALID', 'the page session adapter target is duplicated')
      }
      uniqueTargets.add(identity)
    }
    const notBefore = exactTimestamp(adapter.validity.not_before)
    const notAfter = exactTimestamp(adapter.validity.not_after)
    if (notBefore === null || notAfter === null || notAfter <= notBefore) {
      adapterFailure('HTTP_AUTHED_BROWSER_SESSION_ADAPTER_INVALID', 'the page session adapter validity is invalid')
    }
    if (now < notBefore) {
      adapterFailure('HTTP_AUTHED_BROWSER_SESSION_ADAPTER_NOT_YET_VALID', 'the page session adapter is not yet valid')
    }
    if (now > notAfter) {
      adapterFailure('HTTP_AUTHED_BROWSER_SESSION_ADAPTER_EXPIRED', 'the page session adapter has expired')
    }
    if (!adapter.target_constraints.some((constraint) => (
      constraint.origin === command.target_origin
      && constraint.method === command.method
      && pathMatchesPrefix(requestUrl.pathname, constraint.path_prefix)
    ))) {
      adapterFailure('HTTP_AUTHED_BROWSER_SESSION_ADAPTER_TARGET_REFUSED', 'the request is outside the page session adapter target')
    }
    if (await digestAdapter(adapter) !== expectedSha256) {
      adapterFailure('HTTP_AUTHED_BROWSER_SESSION_ADAPTER_BINDING_MISMATCH', 'the page session adapter does not match its binding')
    }
    return adapter
  }
  const readSessionValue = (adapter, runtime) => {
    const storage = adapter.source.area === 'LOCAL'
      ? (runtime.localStorage ?? globalThis.localStorage)
      : (runtime.sessionStorage ?? globalThis.sessionStorage)
    if (storage === null || typeof storage?.getItem !== 'function') {
      adapterFailure('HTTP_AUTHED_BROWSER_SESSION_ADAPTER_SOURCE_UNAVAILABLE', 'the declared web storage source is unavailable')
    }
    let raw
    try {
      raw = storage.getItem(adapter.source.key)
    } catch {
      adapterFailure('HTTP_AUTHED_BROWSER_SESSION_ADAPTER_SOURCE_UNAVAILABLE', 'the declared web storage source is unavailable')
    }
    if (typeof raw !== 'string') {
      adapterFailure('HTTP_AUTHED_BROWSER_SESSION_ADAPTER_VALUE_INVALID', 'the declared web storage value is absent or non-string')
    }
    let value = raw
    if (adapter.source.extraction.mode === 'JSON_POINTER') {
      let parsed
      try {
        parsed = JSON.parse(raw)
      } catch {
        adapterFailure('HTTP_AUTHED_BROWSER_SESSION_ADAPTER_VALUE_INVALID', 'the declared web storage value is not valid JSON')
      }
      const segments = adapter.source.extraction.pointer.slice(1).split('/').map((segment) => (
        segment.replaceAll('~1', '/').replaceAll('~0', '~')
      ))
      value = parsed
      for (const segment of segments) {
        if (
          value === null
          || typeof value !== 'object'
          || !Object.hasOwn(value, segment)
          || (Array.isArray(value) && !/^(?:0|[1-9][0-9]*)$/u.test(segment))
        ) adapterFailure('HTTP_AUTHED_BROWSER_SESSION_ADAPTER_VALUE_INVALID', 'the declared JSON pointer did not resolve')
        value = value[segment]
      }
    }
    if (typeof value !== 'string') {
      adapterFailure('HTTP_AUTHED_BROWSER_SESSION_ADAPTER_VALUE_INVALID', 'the extracted page session value is non-string')
    }
    const encoder = new TextEncoder()
    const valueBytes = encoder.encode(value)
    const carried = `${adapter.carrier.prefix ?? ''}${value}`
    const carriedBytes = encoder.encode(carried)
    try {
      if (
        valueBytes.byteLength < 1
        || valueBytes.byteLength > adapter.limits.max_value_bytes
        || carriedBytes.byteLength > 8192
        || /[\r\n\0]/u.test(carried)
      ) adapterFailure('HTTP_AUTHED_BROWSER_SESSION_ADAPTER_VALUE_BOUNDED', 'the page session value exceeds its declared boundary')
      const HeaderConstructor = runtime.Headers ?? globalThis.Headers
      if (typeof HeaderConstructor !== 'function') {
        adapterFailure('HTTP_AUTHED_BROWSER_SESSION_ADAPTER_VALUE_INVALID', 'the browser header validator is unavailable')
      }
      let headerProbe
      let roundTripped
      try {
        headerProbe = new HeaderConstructor()
        headerProbe.set(adapter.carrier.name, carried)
        roundTripped = headerProbe.get(adapter.carrier.name)
      } catch {
        adapterFailure('HTTP_AUTHED_BROWSER_SESSION_ADAPTER_VALUE_INVALID', 'the page session value is not an exact browser header value')
      } finally {
        try { headerProbe?.delete(adapter.carrier.name) } catch {}
      }
      if (roundTripped !== carried) {
        roundTripped = null
        adapterFailure('HTTP_AUTHED_BROWSER_SESSION_ADAPTER_VALUE_INVALID', 'the browser would normalize the page session value')
      }
      roundTripped = null
      return carried
    } finally {
      eraseBytes(valueBytes)
      eraseBytes(carriedBytes)
      raw = null
      value = null
    }
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

  validationStage = 'BINDING'
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

  validationStage = 'REQUEST_URL'
  const url = relativeUrl(command.relative_url, command.target_origin)
  if (url === null) invalid()
  validationStage = 'ADAPTER_PAIR'
  const hasSessionAdapter = command.session_adapter !== undefined
    || command.session_adapter_sha256 !== undefined
  if (hasSessionAdapter && (
    command.session_adapter === undefined
    || command.session_adapter_sha256 === undefined
  )) invalid()
  validationStage = command.body === null
    ? 'BODY_DECODE_NULL'
    : (Array.isArray(command.body)
        ? 'BODY_DECODE_ARRAY'
        : (typeof command.body === 'object' ? 'BODY_DECODE_OBJECT' : 'BODY_DECODE_TYPE'))
  const { bytes: bodyBytes, contentType } = await decodeBody(command.body)
  cleanupBodyBytes = bodyBytes ?? null
  validationStage = 'BODY_METHOD'
  if ((command.method === 'GET' || command.method === 'HEAD') && bodyBytes !== undefined) {
    eraseBytes(bodyBytes)
    invalid()
  }
  validationStage = 'HEADERS'
  let headers
  try {
    headers = requestHeaders(command.headers, contentType)
  } catch (error) {
    eraseBytes(bodyBytes)
    throw error
  }
  validationStage = 'LIMITS'
  const timeoutMs = command.timeout_ms ?? 15_000
  const deadlineEpochMs = command.deadline_epoch_ms
  const maxResponseBytes = command.max_response_bytes ?? MAX_RESPONSE_BYTES
  const observeResponse = command.observe_response ?? true
  if (
    !Number.isInteger(timeoutMs)
    || timeoutMs < 100
    || timeoutMs > 60_000
    || !Number.isSafeInteger(deadlineEpochMs)
    || deadlineEpochMs < 0
    || !Number.isInteger(maxResponseBytes)
    || maxResponseBytes < 0
    || maxResponseBytes > MAX_RESPONSE_BYTES
    || typeof observeResponse !== 'boolean'
  ) {
    eraseBytes(bodyBytes)
    invalid()
  }

  const currentPreparedBinding = suppliedRuntime.preparedActionBindingSha256
    ?? bridgeState?.prepared_action_binding_sha256
  if (currentPreparedBinding !== command.action_binding_sha256) {
    eraseBytes(bodyBytes)
    throw failure(
      'HTTP_AUTHED_BROWSER_OPERATION_CANCELLED',
      'the prepared action was cancelled before dispatch',
    )
  }
  const clockMilliseconds = suppliedRuntime.clockMilliseconds ?? Date.now
  if (typeof clockMilliseconds !== 'function') {
    eraseBytes(bodyBytes)
    invalid()
  }
  const deadlineRemainingMs = Math.floor(deadlineEpochMs - clockMilliseconds())
  if (!Number.isFinite(deadlineRemainingMs) || deadlineRemainingMs < 100) {
    eraseBytes(bodyBytes)
    throw failure(
      'HTTP_AUTHED_BROWSER_ACTION_EXPIRED',
      'the committed action expired before dispatch',
    )
  }
  const preparedSessionAdapterSha256 = Object.hasOwn(
    suppliedRuntime,
    'preparedSessionAdapterSha256',
  )
    ? suppliedRuntime.preparedSessionAdapterSha256
    : (bridgeState?.prepared_session_adapter_sha256 ?? null)
  if (
    (hasSessionAdapter && preparedSessionAdapterSha256 !== command.session_adapter_sha256)
    || (!hasSessionAdapter && preparedSessionAdapterSha256 !== null)
  ) {
    eraseBytes(bodyBytes)
    throw failure(
      'HTTP_AUTHED_BROWSER_SESSION_ADAPTER_BINDING_MISMATCH',
      'the committed page session adapter does not match the prepared action',
    )
  }
  const sessionAdapter = hasSessionAdapter
    ? await validateSessionAdapter(
        command.session_adapter,
        command.session_adapter_sha256,
        clockMilliseconds(),
        new URL(url),
      )
    : null
  const bindingAfterAdapterValidation = suppliedRuntime.preparedActionBindingSha256
    ?? bridgeState?.prepared_action_binding_sha256
  const adapterBindingAfterValidation = Object.hasOwn(
    suppliedRuntime,
    'preparedSessionAdapterSha256',
  )
    ? suppliedRuntime.preparedSessionAdapterSha256
    : (bridgeState?.prepared_session_adapter_sha256 ?? null)
  if (
    bindingAfterAdapterValidation !== command.action_binding_sha256
    || (hasSessionAdapter
      ? adapterBindingAfterValidation !== command.session_adapter_sha256
      : adapterBindingAfterValidation !== null)
  ) {
    eraseBytes(bodyBytes)
    throw failure(
      'HTTP_AUTHED_BROWSER_OPERATION_CANCELLED',
      'the prepared action was cancelled before session acquisition',
    )
  }
  const remainingAfterAdapterValidation = Math.floor(
    deadlineEpochMs - clockMilliseconds(),
  )
  if (!Number.isFinite(remainingAfterAdapterValidation) || remainingAfterAdapterValidation < 100) {
    eraseBytes(bodyBytes)
    throw failure(
      'HTTP_AUTHED_BROWSER_ACTION_EXPIRED',
      'the committed action expired before session acquisition',
    )
  }
  if (sessionAdapter !== null) {
    headers[sessionAdapter.carrier.name] = readSessionValue(sessionAdapter, suppliedRuntime)
    cleanupHeaders = headers
    cleanupSessionCarrierName = sessionAdapter.carrier.name
  }
  const currentBridgeState = globalThis[STATE_KEY]
  const finalPreparedBinding = suppliedRuntime.preparedActionBindingSha256
    ?? currentBridgeState?.prepared_action_binding_sha256
  const finalAdapterBinding = Object.hasOwn(suppliedRuntime, 'preparedSessionAdapterSha256')
    ? suppliedRuntime.preparedSessionAdapterSha256
    : (currentBridgeState?.prepared_session_adapter_sha256 ?? null)
  const finalDocumentNonce = suppliedRuntime.documentNonce
    ?? currentBridgeState?.document_nonce
  const finalDeadlineRemainingMs = Math.floor(deadlineEpochMs - clockMilliseconds())
  if (
    activeLocation?.origin !== command.target_origin
    || finalDocumentNonce !== command.document_nonce
    || finalPreparedBinding !== command.action_binding_sha256
    || (hasSessionAdapter
      ? finalAdapterBinding !== command.session_adapter_sha256
      : finalAdapterBinding !== null)
    || !Number.isFinite(finalDeadlineRemainingMs)
    || finalDeadlineRemainingMs < 100
  ) {
    eraseBytes(bodyBytes)
    throw failure(
      'HTTP_AUTHED_BROWSER_OPERATION_CANCELLED',
      'the prepared action changed during session acquisition',
    )
  }
  if (isObject(bridgeState)) bridgeState.prepared_action_binding_sha256 = null
  if (isObject(bridgeState)) bridgeState.prepared_session_adapter_sha256 = null
  let rejectDeadline
  let deadline
  let fetchImpl
  let abortController
  let started
  try {
    fetchImpl = suppliedRuntime.fetchImpl ?? globalThis.fetch.bind(globalThis)
    if (typeof fetchImpl !== 'function') invalid()
    abortController = new AbortController()
    cleanupBridgeState = isObject(bridgeState) ? bridgeState : null
    cleanupAbortController = abortController
    if (cleanupBridgeState !== null) cleanupBridgeState.abort_controller = abortController
    deadline = new Promise((_, reject) => { rejectDeadline = reject })
    // Page globals are target-controlled. Observe the deadline before timer
    // setup and keep the controller/header cleanup boundary active throughout.
    void deadline.catch(() => {})
    started = globalThis.performance?.now?.() ?? Date.now()
  } catch (error) {
    if (typeof error?.code === 'string' && error.code.startsWith('HTTP_AUTHED_BROWSER_')) {
      throw error
    }
    throw failure(
      'HTTP_AUTHED_BROWSER_FETCH_SETUP_FAILED',
      'the committed request could not initialize its browser transport',
    )
  }
  const committedTimeoutMs = Math.min(timeoutMs, finalDeadlineRemainingMs)
  const committedDeadline = started + committedTimeoutMs
  const deadlineError = failure(
    'HTTP_AUTHED_BROWSER_FETCH_FAILED',
    'the committed request exceeded its absolute deadline',
  )
  let timeout
  let timeoutCreated = false
  const clearDeadlineTimer = () => {
    if (!timeoutCreated) return
    timeoutCreated = false
    try {
      globalThis.clearTimeout(timeout)
    } catch {
      // The fetch outcome and transient cleanup remain authoritative.
    }
  }
  try {
    timeout = globalThis.setTimeout(
      () => {
        abortController.abort(deadlineError)
        rejectDeadline(deadlineError)
      },
      committedTimeoutMs,
    )
    timeoutCreated = true
  } catch {
    eraseBytes(bodyBytes)
    throw failure(
      'HTTP_AUTHED_BROWSER_FETCH_TIMER_FAILED',
      'the committed request could not start its deadline timer',
    )
  }
  const ensureDeadline = () => {
    const monotonicNow = globalThis.performance?.now?.() ?? Date.now()
    if (
      !abortController.signal.aborted
      && monotonicNow < committedDeadline
      && clockMilliseconds() < deadlineEpochMs
    ) return
    if (!abortController.signal.aborted) abortController.abort(deadlineError)
    throw deadlineError
  }
  const withinDeadline = async (operation) => {
    ensureDeadline()
    const value = await Promise.race([Promise.resolve().then(operation), deadline])
    ensureDeadline()
    return value
  }
  let response
  try {
    response = await withinDeadline(() => {
      requestMayHaveBeenSent = true
      deadlineError.request_may_have_been_sent = true
      return fetchImpl(url, {
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
    })
  } catch (error) {
    clearDeadlineTimer()
    eraseBytes(bodyBytes)
    if (error === deadlineError) throw error
    throw failure(
      'HTTP_AUTHED_BROWSER_FETCH_FAILED',
      requestMayHaveBeenSent
        ? 'the committed request failed after dispatch; it was not retried'
        : 'the committed request failed before dispatch',
      requestMayHaveBeenSent,
    )
  }

  let bytes = 0
  let truncated = false
  let bodyReadIncomplete = false
  const bodyChunks = []
  let responseReader = null
  try {
    if (response.body !== null && command.method !== 'HEAD') {
      responseReader = response.body.getReader()
      while (true) {
        const pendingRead = Promise.resolve().then(() => responseReader.read())
        let part
        try {
          part = await withinDeadline(() => pendingRead)
        } catch (error) {
          pendingRead.then((latePart) => {
            try {
              eraseBytes(latePart?.value)
            } catch {
              // Target-controlled late results cannot reject cleanup.
            }
          }, () => {})
          throw error
        }
        if (part.done) {
          eraseBytes(part.value)
          break
        }
        if (!(part.value instanceof Uint8Array)) {
          throw failure(
            'HTTP_AUTHED_BROWSER_RESPONSE_INVALID',
            'the committed request returned a non-byte response chunk',
            true,
          )
        }
        const remaining = Math.max(0, maxResponseBytes - bytes)
        if (observeResponse && remaining > 0) bodyChunks.push(part.value.slice(0, remaining))
        bytes += Math.min(remaining, part.value.byteLength)
        if (part.value.byteLength > remaining) {
          eraseBytes(part.value)
          truncated = true
          abortController.abort()
          try {
            Promise.resolve(responseReader.cancel()).catch(() => {})
          } catch {}
          break
        }
        eraseBytes(part.value)
      }
    }
  } catch {
    bodyReadIncomplete = true
    abortController.abort()
    if (responseReader !== null) {
      try {
        Promise.resolve(responseReader.cancel()).catch(() => {})
      } catch {}
    }
  } finally {
    clearDeadlineTimer()
  }

  const capturedBody = new Uint8Array(observeResponse ? bytes : 0)
  let bodyOffset = 0
  for (const chunk of bodyChunks) {
    capturedBody.set(chunk, bodyOffset)
    bodyOffset += chunk.byteLength
  }
  try {
    const boundedHeaders = boundedResponseHeaders(response.headers)
    const headerNames = safeHeaderNames(boundedHeaders)
    const responseHeaders = observeResponse ? transientHeaders(boundedHeaders) : []
    const bodyBase64 = observeResponse ? bytesToBase64(capturedBody) : null
    const responseStatus = response.status
    const status = Number.isInteger(responseStatus) ? responseStatus : null
    const redirected = response.redirected === true
    const finished = globalThis.performance?.now?.() ?? Date.now()
    if (!bodyReadIncomplete && !truncated) ensureDeadline()
    return {
      protocol: PROTOCOL,
      schema_version: '1.0.0',
      session_id: command.session_id,
      dispatch_id: command.dispatch_id,
      action_binding_sha256: command.action_binding_sha256,
      ...(sessionAdapter === null
        ? {}
        : { session_adapter_sha256: command.session_adapter_sha256 }),
      outcome: bodyReadIncomplete ? 'OBSERVATION_INCOMPLETE' : (truncated ? 'RESPONSE_BOUNDED' : 'OBSERVED'),
      status,
      bytes,
      response_truncated: truncated,
      header_names: headerNames,
      redirected,
      elapsed_ms: Math.max(0, Math.min(60_000, Math.round(finished - started))),
      response: {
        status,
        response_bytes: bytes,
        response_header_names: headerNames,
        headers: responseHeaders,
        body_base64: bodyBase64,
      },
    }
  } finally {
    eraseBytes(bodyBytes)
    eraseBytes(capturedBody)
    for (const chunk of bodyChunks) eraseBytes(chunk)
    bodyChunks.length = 0
    bytes = 0
  }
  } catch (error) {
    if (!browserDispatch) throw error
    let errorCode
    let errorClaimsSent = false
    try {
      errorCode = error?.code
    } catch {}
    try {
      errorClaimsSent = error?.request_may_have_been_sent === true
    } catch {}
    const deliveryAmbiguous = requestMayHaveBeenSent || errorClaimsSent
    const controlledCode = typeof errorCode === 'string'
      && /^HTTP_AUTHED_BROWSER_[A-Z0-9_]{3,96}$/u.test(errorCode)
      ? (errorCode === 'HTTP_AUTHED_BROWSER_ACTION_INVALID'
          ? `${errorCode}_${validationStage}`
          : errorCode)
      : (deliveryAmbiguous
          ? 'HTTP_AUTHED_BROWSER_FETCH_FAILED'
          : 'HTTP_AUTHED_BROWSER_INJECTION_FAILED')
    return {
      error_code: controlledCode,
      request_may_have_been_sent: deliveryAmbiguous,
    }
  } finally {
    try {
      if (cleanupHeaders !== null && cleanupSessionCarrierName !== null) {
        delete cleanupHeaders[cleanupSessionCarrierName]
      }
    } catch {}
    cleanupHeaders = null
    cleanupSessionCarrierName = null
    try {
      if (
        cleanupBridgeState !== null
        && cleanupBridgeState.abort_controller === cleanupAbortController
      ) cleanupBridgeState.abort_controller = null
    } catch {}
    cleanupBridgeState = null
    cleanupAbortController = null
    eraseBytes(cleanupBodyBytes)
    cleanupBodyBytes = null
  }
}
