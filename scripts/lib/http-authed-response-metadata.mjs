const HTTP_FIELD_NAME = /^[!#$%&'*+.^_`|~0-9a-z-]+$/

export const HTTP_AUTHED_JSON_SHAPE_FAILURE_STAGE = 'JSON_SHAPE_OBSERVATION'

export const HTTP_AUTHED_RESPONSE_BYTE_BUCKETS = Object.freeze([
  'EMPTY',
  'LE_1_KIB',
  'LE_4_KIB',
  'LE_16_KIB',
  'LE_64_KIB',
  'LE_256_KIB',
  'LE_1_MIB',
])

const RESPONSE_BYTE_BUCKET_MAXIMUMS = Object.freeze([
  [0, 'EMPTY'],
  [1024, 'LE_1_KIB'],
  [4 * 1024, 'LE_4_KIB'],
  [16 * 1024, 'LE_16_KIB'],
  [64 * 1024, 'LE_64_KIB'],
  [256 * 1024, 'LE_256_KIB'],
  [1024 * 1024, 'LE_1_MIB'],
])

// Persist only fixed protocol classifications. A server can legally choose a
// token-shaped field name containing an identifier, so arbitrary names are as
// sensitive as values at this evidence boundary.
const PERSISTED_HEADER_CLASSES = new Set([
  'accept-ranges',
  'age',
  'allow',
  'cache-control',
  'connection',
  'content-encoding',
  'content-length',
  'content-security-policy',
  'content-type',
  'cross-origin-embedder-policy',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
  'date',
  'etag',
  'expires',
  'last-modified',
  'link',
  'location',
  'permissions-policy',
  'pragma',
  'referrer-policy',
  'retry-after',
  'server',
  'set-cookie',
  'strict-transport-security',
  'trailer',
  'transfer-encoding',
  'vary',
  'via',
  'warning',
  'www-authenticate',
  'x-content-type-options',
  'x-frame-options',
  'x-xss-protection',
])

export function sanitizeHttpAuthedHeaderNames(value) {
  if (!Array.isArray(value) || value.length > 256) {
    throw new TypeError('response header-name metadata is invalid')
  }
  const result = []
  for (const item of value) {
    const name = String(item).toLowerCase()
    if (!HTTP_FIELD_NAME.test(name)) {
      throw new TypeError('response header-name metadata is invalid')
    }
    const classification = PERSISTED_HEADER_CLASSES.has(name) ? name : 'other'
    if (!result.includes(classification)) result.push(classification)
  }
  return result
}

export function httpAuthedResponseByteBucket(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 1024 * 1024) {
    throw new TypeError('response byte metadata is outside its bounded range')
  }
  return RESPONSE_BYTE_BUCKET_MAXIMUMS.find(([maximum]) => value <= maximum)[1]
}

export function assertHttpAuthedResponseByteBucket(value) {
  if (!HTTP_AUTHED_RESPONSE_BYTE_BUCKETS.includes(value)) {
    throw new TypeError('response byte bucket is invalid')
  }
  return value
}
