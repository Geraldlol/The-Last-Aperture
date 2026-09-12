import { createHash } from 'node:crypto'

export const CAPTURED_REQUEST_KIND = 'red-team-audit/bounty-authz-request'

// Redacted before anything is persisted, so a bundle can be shared or attached
// to a report without carrying a live session.
export const SENSITIVE_HEADERS = new Set([
  'api-key',
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'x-access-token',
  'x-amz-security-token',
  'x-auth-token',
  'x-client-secret',
  'x-csrf-token',
  'x-goog-api-key',
  'x-mfa-code',
  'x-one-time-password',
  'x-otp',
  'x-pin',
  'x-xsrf-token',
  'x-session-token',
  'x-totp',
  'x-verification-code',
])

const REDACTED_VALUE = '<redacted>'
const SENSITIVE_FIELD_NAMES = new Set([
  'apikey',
  'accesskey',
  'accesskeyid',
  'assertion',
  'auth',
  'authentication',
  'authorization',
  'bearer',
  'clientsecret',
  'code',
  'cookie',
  'credential',
  'credentials',
  'csrf',
  'csrftoken',
  'idtoken',
  'jsessionid',
  'jwt',
  'key',
  'mfa',
  'mfacode',
  'otp',
  'password',
  'passwd',
  'passcode',
  'pin',
  'pwd',
  'refreshtoken',
  'relaystate',
  'samlrequest',
  'samlresponse',
  'secret',
  'session',
  'sessionid',
  'sessiontoken',
  'sid',
  'sig',
  'signature',
  'state',
  'ticket',
  'token',
  'totp',
  'verificationcode',
  'xsrf',
  'xsrftoken',
  'xamzcredential',
  'xamzsecuritytoken',
  'xamzsignature',
])
const SENSITIVE_SUFFIX_FIELDS = new Set([
  'accesskey',
  'apikey',
  'assertion',
  'cookie',
  'credential',
  'passcode',
  'passwd',
  'password',
  'relaystate',
  'samlrequest',
  'samlresponse',
  'secret',
  'signature',
  'state',
  'token',
])
const SENSITIVE_CODE_CONTEXTS = new Set([
  'auth',
  'auth0',
  'authentication',
  'authorization',
  'azuread',
  'cognito',
  'entra',
  'forgerock',
  'identity',
  'keycloak',
  'login',
  'oauth',
  'oauth2',
  'oidc',
  'okta',
  'onelogin',
  'ping',
  'pingidentity',
  'saml',
  'security',
  'signin',
  'sso',
  'vendor',
])
const MAX_SENSITIVE_VERSION_DIGITS = 8

function sensitiveSuffix(candidate) {
  const version = /v?([0-9]+)$/u.exec(candidate)
  if (version?.[1].length > MAX_SENSITIVE_VERSION_DIGITS) return true
  const stem = version === null ? candidate : candidate.slice(0, -version[0].length)
  if (stem.endsWith('code')) {
    const context = stem.slice(0, -'code'.length)
    for (const marker of SENSITIVE_CODE_CONTEXTS) {
      if (context.endsWith(marker)) return true
    }
  }
  for (const field of SENSITIVE_SUFFIX_FIELDS) {
    if (stem.endsWith(field)) return true
  }
  return false
}

function sensitiveFieldName(value) {
  let decoded = String(value)
  for (let pass = 0; decoded.includes('%') && pass < 8; pass += 1) {
    try { decoded = decodeURIComponent(decoded) } catch { return true }
  }
  if (decoded.includes('%')) return true
  const compact = decoded.toLowerCase().replace(/[^a-z0-9]/gu, '')
  const candidates = compact.startsWith('x') && compact.length > 1
    ? [compact, compact.slice(1)]
    : [compact]
  return candidates.some((candidate) => (
    SENSITIVE_FIELD_NAMES.has(candidate)
    || sensitiveSuffix(candidate)
    || /^(?:csrf|xsrf)/u.test(candidate)
  ))
}

export function isSensitiveHeaderName(value) {
  const name = String(value).toLowerCase()
  return SENSITIVE_HEADERS.has(name) || sensitiveFieldName(name)
}

function redactUrl(rawUrl) {
  if (/%(?![0-9a-f]{2})/iu.test(rawUrl)) {
    throw new Error('captured request must use valid URL percent encoding before redaction')
  }
  let parsed
  try {
    parsed = new URL(rawUrl)
  } catch (cause) {
    throw new Error('captured request URL must parse before redaction', { cause })
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('captured request URL must be HTTP or HTTPS before redaction')
  }
  const redacted = []
  if (parsed.username !== '' || parsed.password !== '') {
    redacted.push('<url-credentials>')
    parsed.username = ''
    parsed.password = ''
  }
  // Fragments never cross the HTTP boundary and may contain OAuth tokens.
  // Persisting them adds secret material without adding replay semantics.
  parsed.hash = ''
  for (const name of [...new Set(parsed.searchParams.keys())]) {
    if (!sensitiveFieldName(name)) continue
    redacted.push(name)
    parsed.searchParams.set(name, REDACTED_VALUE)
  }
  return { url: parsed.href, redacted: redacted.sort() }
}

function redactJsonValue(value, redacted, path = '', depth = 0) {
  if (depth > 32) {
    redacted.add(path || '<deep-body>')
    return REDACTED_VALUE
  }
  if (Array.isArray(value)) {
    return value.map((child, index) => {
      const childPath = `${path}[${index}]`
      if (child !== null && typeof child !== 'object') {
        redacted.add(childPath)
        return REDACTED_VALUE
      }
      return redactJsonValue(child, redacted, childPath, depth + 1)
    })
  }
  if (value === null || typeof value !== 'object') return value
  const result = {}
  for (const [name, child] of Object.entries(value)) {
    const childPath = path ? `${path}.${name}` : name
    if (sensitiveFieldName(name)) {
      redacted.add(childPath)
      result[name] = REDACTED_VALUE
    } else {
      result[name] = redactJsonValue(child, redacted, childPath, depth + 1)
    }
  }
  return result
}

function redactBody(rawBody, contentType) {
  if (typeof rawBody !== 'string') return { body: null, redacted: [] }
  const trimmed = rawBody.trimStart()
  const jsonLike = contentType.includes('json') || trimmed.startsWith('{') || trimmed.startsWith('[')
  if (jsonLike) {
    try {
      const redacted = new Set()
      const parsed = JSON.parse(rawBody)
      let transformed
      if (parsed !== null && typeof parsed !== 'object') {
        redacted.add('<unkeyed-json-body>')
        transformed = REDACTED_VALUE
      } else {
        transformed = redactJsonValue(parsed, redacted)
      }
      return {
        body: redacted.size === 0 ? rawBody : JSON.stringify(transformed),
        redacted: [...redacted].sort(),
      }
    } catch {
      return { body: null, redacted: ['<malformed-structured-body>'] }
    }
  }
  const formLike = contentType === 'application/x-www-form-urlencoded'
    || /(?:^|&)[^=&]+=/u.test(rawBody)
  if (formLike) {
    if (/%(?![0-9a-f]{2})/iu.test(rawBody)) {
      return { body: null, redacted: ['<malformed-structured-body>'] }
    }
    const form = new URLSearchParams(rawBody)
    const redacted = []
    for (const name of [...new Set(form.keys())]) {
      if (!sensitiveFieldName(name)) continue
      redacted.push(name)
      form.set(name, REDACTED_VALUE)
    }
    return { body: redacted.length === 0 ? rawBody : form.toString(), redacted: redacted.sort() }
  }
  // Opaque bodies cannot be proven credential-free. Persisting no bytes is the
  // only fail-closed redaction for formats whose fields cannot be identified.
  return { body: null, redacted: rawBody.length === 0 ? [] : ['<opaque-body>'] }
}

function lowerHeaders(headers) {
  const out = {}
  if (headers === null || typeof headers !== 'object') return out
  for (const [name, value] of Object.entries(headers)) {
    out[String(name).toLowerCase()] = String(value)
  }
  return out
}

function normalizedRedactionNames(raw, name) {
  if (!Object.hasOwn(raw, name)) return undefined
  if (
    !Array.isArray(raw[name])
    || raw[name].some((value) => typeof value !== 'string' || value.length === 0 || value.length > 1024)
  ) throw new Error(`captured request ${name} must be a bounded string array`)
  return [...new Set(raw[name])].sort()
}

export function normalizeCapturedRequest(raw) {
  if (raw === null || typeof raw !== 'object') {
    throw new Error('captured request must be an object')
  }
  const method = typeof raw.method === 'string' ? raw.method.toUpperCase() : null
  if (method === null || method.length === 0) {
    throw new Error('captured request is missing method')
  }
  if (typeof raw.url !== 'string' || raw.url.length === 0) {
    throw new Error('captured request is missing url')
  }
  const redactedHeaders = normalizedRedactionNames(raw, 'redacted_headers')
  const redactedQueryParameters = normalizedRedactionNames(raw, 'redacted_query_parameters')
  const redactedBodyFields = normalizedRedactionNames(raw, 'redacted_body_fields')
  return {
    kind: CAPTURED_REQUEST_KIND,
    request_id: typeof raw.request_id === 'string' ? raw.request_id : null,
    method,
    url: raw.url,
    headers: lowerHeaders(raw.headers),
    body: typeof raw.body === 'string' ? raw.body : null,
    owner_role: typeof raw.owner_role === 'string' ? raw.owner_role : null,
    ...(redactedHeaders === undefined ? {} : { redacted_headers: redactedHeaders }),
    ...(redactedQueryParameters === undefined ? {} : { redacted_query_parameters: redactedQueryParameters }),
    ...(redactedBodyFields === undefined ? {} : { redacted_body_fields: redactedBodyFields }),
  }
}

function harHeadersToObject(entries) {
  const out = {}
  if (!Array.isArray(entries)) return out
  for (const entry of entries) {
    if (typeof entry?.name !== 'string') continue
    // HTTP/2 pseudo-headers are transport detail, not request content.
    if (entry.name.startsWith(':')) continue
    out[entry.name.toLowerCase()] = String(entry.value ?? '')
  }
  return out
}

export function importHarEntries(har, { ownerRole }) {
  const requests = []
  const skipped = []
  const entries = har?.log?.entries
  if (!Array.isArray(entries)) {
    return { requests, skipped: [{ url: null, reason: 'har-has-no-entries' }] }
  }
  let index = 0
  for (const entry of entries) {
    index += 1
    const request = entry?.request
    if (request === null || typeof request !== 'object') {
      skipped.push({ url: null, reason: 'entry-has-no-request' })
      continue
    }
    const url = request.url
    if (typeof url !== 'string' || !/^https?:\/\//i.test(url)) {
      skipped.push({ url: typeof url === 'string' ? url : null, reason: 'not-an-http-url' })
      continue
    }
    requests.push(normalizeCapturedRequest({
      request_id: `har-${index}`,
      method: request.method,
      url,
      headers: harHeadersToObject(request.headers),
      body: typeof request.postData?.text === 'string' ? request.postData.text : null,
      // A HAR cannot know whose session it captured, so the owner is declared by
      // the operator at import time rather than guessed.
      owner_role: ownerRole,
    }))
  }
  return { requests, skipped }
}

export function redactRequest(request, { extraSensitive = [] } = {}) {
  const extra = new Set(extraSensitive.map((name) => String(name).toLowerCase()))
  const headers = {}
  const redacted = []
  for (const [name, value] of Object.entries(request.headers ?? {})) {
    if (isSensitiveHeaderName(name) || extra.has(name)) {
      redacted.push(name)
      continue
    }
    headers[name] = value
  }
  const contentType = String(headers['content-type'] ?? '').split(';', 1)[0].trim().toLowerCase()
  const redactedUrl = redactUrl(request.url)
  const redactedBody = redactBody(request.body, contentType)
  const inheritedHeaders = Array.isArray(request.redacted_headers) ? request.redacted_headers : []
  const inheritedQuery = Array.isArray(request.redacted_query_parameters) ? request.redacted_query_parameters : []
  const inheritedBody = Array.isArray(request.redacted_body_fields) ? request.redacted_body_fields : []
  return {
    ...request,
    url: redactedUrl.url,
    headers,
    body: redactedBody.body,
    redacted_headers: [...new Set([...inheritedHeaders, ...redacted])].sort(),
    redacted_query_parameters: [...new Set([...inheritedQuery, ...redactedUrl.redacted])].sort(),
    redacted_body_fields: [...new Set([...inheritedBody, ...redactedBody.redacted])].sort(),
  }
}

export function sanitizeCapturedRequest(request, options) {
  return redactRequest(normalizeCapturedRequest(request), options)
}

export function requestSignature(request) {
  let bodyKeys = ''
  if (typeof request.body === 'string' && request.body.length > 0) {
    try {
      const parsed = JSON.parse(request.body)
      if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
        bodyKeys = Object.keys(parsed).sort().join(',')
      }
    } catch {
      bodyKeys = `len:${request.body.length}`
    }
  }
  let path = request.url
  try {
    const parsed = new URL(request.url)
    // Query keys matter for identity; their values usually do not.
    const keys = [...parsed.searchParams.keys()].sort().join(',')
    path = `${parsed.origin}${parsed.pathname}?${keys}`
  } catch {
    // keep the raw url when it will not parse
  }
  return createHash('sha256')
    .update(`${request.method}\n${path}\n${bodyKeys}`)
    .digest('hex')
    .slice(0, 32)
}
