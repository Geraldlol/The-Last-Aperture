import { createHash } from 'node:crypto'

// Dropped because they differ between two identical requests. Keeping any of
// them would make every comparison fail and the grinder silently find nothing.
export const VOLATILE_HEADERS = new Set([
  'date',
  'set-cookie',
  'etag',
  'last-modified',
  'age',
  'expires',
  'x-request-id',
  'x-trace-id',
  'x-correlation-id',
  'x-amzn-requestid',
  'x-runtime',
  'x-served-by',
  'x-timer',
  'cf-ray',
  'server-timing',
  'content-length',
  'keep-alive',
  'connection',
  'report-to',
  'nel',
])

// JSON keys whose values are machine noise rather than data.
const VOLATILE_KEY_PATTERN = /^(_?csrf(_?token)?|_token|token|nonce|request_?id|trace_?id|correlation_?id|timestamp|created_?at|updated_?at|expires_?at|iat|exp|jti|etag|session_?id)$/i

const UUID = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi
const ISO_TS = /\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b/g
const EPOCH = /\b\d{10,13}\b/g
const LONG_HEX = /\b[0-9a-f]{16,}\b/gi
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/u
const MAX_RESPONSE_HEADER_COUNT = 256
const MAX_RESPONSE_HEADER_VALUE_BYTES = 64 * 1024
const MAX_RESPONSE_HEADER_BYTES = 512 * 1024

function scrubText(text) {
  return text
    .replace(UUID, '<uuid>')
    .replace(ISO_TS, '<ts>')
    .replace(LONG_HEX, '<hex>')
    .replace(EPOCH, '<epoch>')
    .replace(/\s+/g, ' ')
    .trim()
}

function scrubJson(value) {
  if (Array.isArray(value)) return value.map(scrubJson)
  if (value === null || typeof value !== 'object') {
    // Strings get pattern scrubbing. Bare numbers deliberately do not, even ones
    // that look like epochs: a 10-digit identifier differing between two roles is
    // exactly the signal we are hunting, and masking it would manufacture a false
    // bypass. Numeric timestamps are caught by key name below, which is precise
    // where value-shape matching is reckless.
    return typeof value === 'string' ? scrubText(value) : value
  }
  const out = {}
  // Sorted so key order can never masquerade as a difference between roles.
  for (const key of Object.keys(value).sort()) {
    out[key] = VOLATILE_KEY_PATTERN.test(key) ? '<redacted>' : scrubJson(value[key])
  }
  return out
}

export function normalizeResponseBody(body, contentType) {
  if (typeof body !== 'string' || body.length === 0) return ''
  const isJson = typeof contentType === 'string' && contentType.includes('json')
  if (isJson) {
    try {
      return JSON.stringify(scrubJson(JSON.parse(body)))
    } catch {
      // A body that claims JSON and is not still needs comparing; fall through
      // to text rather than throwing away the observation.
    }
  }
  return scrubText(body)
}

function normalizeHeaders(headers) {
  const entries = []
  if (headers === null || headers === undefined) return entries
  const iterable = typeof headers.entries === 'function' ? headers.entries() : Object.entries(headers)
  let count = 0
  let totalBytes = 0
  for (const entry of iterable) {
    count += 1
    if (!Array.isArray(entry) || entry.length !== 2 || count > MAX_RESPONSE_HEADER_COUNT) {
      throw new TypeError('response headers exceeded the normalization limit')
    }
    const [name, value] = entry
    const key = String(name).toLowerCase()
    const rendered = String(value)
    const valueBytes = Buffer.byteLength(rendered, 'utf8')
    totalBytes += Buffer.byteLength(key, 'ascii') + valueBytes
    if (
      !HEADER_NAME.test(key)
      || valueBytes > MAX_RESPONSE_HEADER_VALUE_BYTES
      || totalBytes > MAX_RESPONSE_HEADER_BYTES
    ) {
      throw new TypeError('response headers exceeded the normalization limit')
    }
    if (VOLATILE_HEADERS.has(key)) continue
    entries.push([key, rendered])
  }
  entries.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
  return entries
}

function sha256(text) {
  return createHash('sha256').update(text).digest('hex')
}

export function normalizeResponse({ status, headers, body, contentType }) {
  const headerEntries = normalizeHeaders(headers)
  const resolvedType = contentType
    ?? headerEntries.find(([name]) => name === 'content-type')?.[1]
    ?? null
  const normalizedBody = normalizeResponseBody(body, resolvedType)
  return {
    status: status ?? null,
    headerDigest: sha256(JSON.stringify(headerEntries)),
    bodyDigest: sha256(normalizedBody),
    normalizedBody,
  }
}

// Status plus body only. Header sets legitimately differ between roles (a
// different cache directive, a different content-length) without indicating that
// the same data was served, so headers are recorded but not part of identity.
export function responseDigest(normalized) {
  return sha256(`${normalized.status}\n${normalized.bodyDigest}`)
}
