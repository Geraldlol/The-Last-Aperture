import { createHash } from 'node:crypto'
import { compareCanonicalStrings } from './canonical-order.mjs'

const PROFILE_DEFINITIONS = Object.freeze({
  'cors-hostile-origin-get-v1': Object.freeze({
    method: 'GET',
    headers: Object.freeze({ origin: 'https://red-team-audit.invalid' }),
  }),
  'x-forwarded-for-loopback-v1': Object.freeze({
    method: 'GET',
    headers: Object.freeze({ 'x-forwarded-for': '127.0.0.1' }),
  }),
  'x-real-ip-loopback-v1': Object.freeze({
    method: 'GET',
    headers: Object.freeze({ 'x-real-ip': '127.0.0.1' }),
  }),
  'forwarded-loopback-https-v1': Object.freeze({
    method: 'GET',
    headers: Object.freeze({ forwarded: 'for=127.0.0.1;proto=https' }),
  }),
  'x-http-method-override-get-v1': Object.freeze({
    method: 'OPTIONS',
    headers: Object.freeze({ 'x-http-method-override': 'GET' }),
  }),
})

export const HTTP_RECON_REQUEST_HEADER_PROFILES = Object.freeze(
  Object.keys(PROFILE_DEFINITIONS).sort(compareCanonicalStrings),
)

function profileError(code, message) {
  const error = new Error(message)
  error.name = 'HttpReconRequestHeaderProfileError'
  error.code = code
  return error
}

function exactObject(value, label) {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw profileError('HTTP_RECON_HEADER_PROFILE_INVALID', `${label} must be an object`)
  }
  return value
}

function definitionFor(profile, method) {
  const definition = PROFILE_DEFINITIONS[profile]
  if (definition === undefined) {
    throw profileError(
      'HTTP_RECON_HEADER_PROFILE_UNKNOWN',
      'diagnostic request-header profile is not controller-defined',
    )
  }
  if (method !== definition.method) {
    throw profileError(
      'HTTP_RECON_HEADER_PROFILE_METHOD_MISMATCH',
      `diagnostic request-header profile requires method ${definition.method}`,
    )
  }
  return definition
}

function headerSetSha256(headers) {
  const entries = Object.entries(headers)
    .sort(([left], [right]) => compareCanonicalStrings(left, right))
  return createHash('sha256')
    .update('red-team-audit/http-recon-diagnostic-request-headers/v1\0', 'utf8')
    .update(JSON.stringify(entries), 'utf8')
    .digest('hex')
}

export function createHttpReconRequestHeaderDescriptor({ profile, method }) {
  const definition = definitionFor(profile, method)
  return {
    profile,
    names: Object.keys(definition.headers).sort(compareCanonicalStrings),
    header_set_sha256: headerSetSha256(definition.headers),
  }
}

export function resolveHttpReconRequestHeaders({ descriptor, method }) {
  exactObject(descriptor, 'diagnostic request-header descriptor')
  const keys = Object.keys(descriptor).sort(compareCanonicalStrings)
  if (JSON.stringify(keys) !== JSON.stringify(['header_set_sha256', 'names', 'profile'])) {
    throw profileError(
      'HTTP_RECON_HEADER_DESCRIPTOR_INVALID',
      'diagnostic request-header descriptor has unexpected fields',
    )
  }
  const expected = createHttpReconRequestHeaderDescriptor({
    profile: descriptor.profile,
    method,
  })
  if (
    descriptor.profile !== expected.profile
    || descriptor.header_set_sha256 !== expected.header_set_sha256
    || JSON.stringify(descriptor.names) !== JSON.stringify(expected.names)
  ) {
    throw profileError(
      'HTTP_RECON_HEADER_DESCRIPTOR_MISMATCH',
      'diagnostic request-header descriptor does not match its controller-owned profile',
    )
  }
  return { ...PROFILE_DEFINITIONS[descriptor.profile].headers }
}
