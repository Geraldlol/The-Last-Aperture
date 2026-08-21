import { createHash } from 'node:crypto'

export const CAPTURED_REQUEST_KIND = 'red-team-audit/bounty-authz-request'

// Redacted before anything is persisted, so a bundle can be shared or attached
// to a report without carrying a live session.
export const SENSITIVE_HEADERS = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'x-auth-token',
  'x-csrf-token',
  'x-xsrf-token',
  'x-session-token',
])

function lowerHeaders(headers) {
  const out = {}
  if (headers === null || typeof headers !== 'object') return out
  for (const [name, value] of Object.entries(headers)) {
    out[String(name).toLowerCase()] = String(value)
  }
  return out
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
  return {
    kind: CAPTURED_REQUEST_KIND,
    request_id: typeof raw.request_id === 'string' ? raw.request_id : null,
    method,
    url: raw.url,
    headers: lowerHeaders(raw.headers),
    body: typeof raw.body === 'string' ? raw.body : null,
    owner_role: typeof raw.owner_role === 'string' ? raw.owner_role : null,
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
    if (SENSITIVE_HEADERS.has(name) || extra.has(name)) {
      redacted.push(name)
      continue
    }
    headers[name] = value
  }
  return { ...request, headers, redacted_headers: redacted }
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
