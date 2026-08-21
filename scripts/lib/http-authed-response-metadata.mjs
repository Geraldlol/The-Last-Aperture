import { compareCanonicalStrings } from './canonical-order.mjs'

const HTTP_FIELD_NAME = /^[!#$%&'*+.^_`|~0-9a-z-]+$/

export const HTTP_AUTHED_JSON_SHAPE_FAILURE_STAGE = 'JSON_SHAPE_OBSERVATION'
export const HTTP_AUTHED_BOUNDED_PROFILE_FAILURE_STAGE =
  'BOUNDED_PROFILE_OBSERVATION'

export const HTTP_AUTHED_RESPONSE_OBSERVATION_FAILURE_STAGES = Object.freeze([
  HTTP_AUTHED_JSON_SHAPE_FAILURE_STAGE,
  HTTP_AUTHED_BOUNDED_PROFILE_FAILURE_STAGE,
])

const CREDIBLE_BUNDLE_PATH = /^\/assets\/bundle-[0-9]{8}_[0-9]{4}\.js$/u

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

export function sanitizeHttpAuthedBoundedResponseObservation(value, expectedDescriptor) {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
    || Object.keys(value).sort().join(',')
      !== 'bundle_paths,profile,profile_binding_sha256'
    || value.profile !== 'credible-bundle-src-v1'
    || !/^[a-f0-9]{64}$/u.test(value.profile_binding_sha256 ?? '')
    || !Array.isArray(value.bundle_paths)
    || value.bundle_paths.length > 4
  ) {
    throw new TypeError('bounded response-observation metadata is invalid')
  }
  if (
    expectedDescriptor !== undefined
    && (
      value.profile !== expectedDescriptor?.profile
      || value.profile_binding_sha256 !== expectedDescriptor?.profile_binding_sha256
    )
  ) {
    throw new TypeError('bounded response-observation metadata is not sealed by the action')
  }
  const paths = [...value.bundle_paths]
  if (
    new Set(paths).size !== paths.length
    || paths.some((path) => typeof path !== 'string' || !CREDIBLE_BUNDLE_PATH.test(path))
    // Locale-independent by rule: these paths are sealed and digested, so their
    // order must be identical on every host regardless of OS locale or ICU
    // version. CREDIBLE_BUNDLE_PATH restricts them to ASCII digits inside a fixed
    // prefix and suffix, where code-unit and collation order always agree, so no
    // already-sealed path set reorders under this change.
    || paths.some((path, index) => index > 0 && compareCanonicalStrings(paths[index - 1], path) >= 0)
  ) {
    throw new TypeError('bounded response-observation paths are invalid')
  }
  return {
    profile: value.profile,
    profile_binding_sha256: value.profile_binding_sha256,
    bundle_paths: paths,
  }
}
