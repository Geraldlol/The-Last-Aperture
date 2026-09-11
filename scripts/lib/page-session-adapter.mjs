import { createHash } from 'node:crypto'
import { constants as fsConstants, readFileSync } from 'node:fs'
import { lstat, open } from 'node:fs/promises'
import { isAbsolute } from 'node:path'
import { fileURLToPath } from 'node:url'

import Ajv2020 from 'ajv/dist/2020.js'

import { compareCanonicalStrings } from './canonical-order.mjs'
import { assertLocalFilesystemEndpoint } from './filesystem-endpoint.mjs'

const SCHEMA_URL = new URL('../../schemas/page-session-adapter.schema.json', import.meta.url)
const MAX_DESCRIPTOR_BYTES = 128 * 1024
const OPEN_READ_ONLY_NO_FOLLOW = fsConstants.O_RDONLY
  | (typeof fsConstants.O_NOFOLLOW === 'number' ? fsConstants.O_NOFOLLOW : 0)
const FORBIDDEN_METHODS = new Set(['CONNECT', 'TRACE', 'TRACK'])
export const PAGE_SESSION_ROUTING_CARRIER_HEADERS = Object.freeze([
  'forwarded',
  'x-envoy-original-path',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-prefix',
  'x-forwarded-uri',
  'x-http-url-override',
  'x-original-uri',
  'x-original-url',
  'x-rewrite-uri',
  'x-rewrite-url',
])
const FORBIDDEN_CARRIER_HEADERS = new Set([
  'accept',
  'accept-charset',
  'accept-encoding',
  'access-control-request-headers',
  'access-control-request-method',
  'connection',
  'constructor',
  'content-length',
  'content-type',
  'cookie',
  'cookie2',
  'date',
  'dnt',
  'expect',
  'host',
  'keep-alive',
  'origin',
  'permissions-policy',
  'prototype',
  'proxy-authorization',
  'proxy-connection',
  'referer',
  'referrer',
  'set-cookie',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'user-agent',
  'via',
  '__proto__',
  'x-red-team-audit-pairing',
  'x-red-team-audit-session',
  'x-last-aperture-extension',
  'x-http-method',
  'x-http-method-override',
  'x-method-override',
  ...PAGE_SESSION_ROUTING_CARRIER_HEADERS,
])
const AMBIGUOUS_PATH = /(?:\\|%(?:25)*(?:2e|2f|5c))/iu
const WILDCARD_SYNTAX = /[*{}]/u
const BLOCKED_POINTER_SEGMENTS = new Set(['__proto__', 'prototype', 'constructor'])

export const pageSessionAdapterSchema = JSON.parse(
  readFileSync(fileURLToPath(SCHEMA_URL), 'utf8'),
)

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})
const validateSchema = ajv.compile(pageSessionAdapterSchema)

export class PageSessionAdapterError extends Error {
  constructor(code, message, details = [], options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'PageSessionAdapterError'
    this.code = code
    this.details = details
  }
}

function adapterError(code, message, details = [], options) {
  return new PageSessionAdapterError(code, message, details, options)
}

function normalizedSchemaErrors() {
  return (validateSchema.errors ?? []).map((error) => ({
    instancePath: error.instancePath || '/',
    keyword: error.keyword,
    message: error.message ?? 'schema validation failed',
  }))
}

function canonicalOrigin(value) {
  try {
    const parsed = new URL(value)
    return parsed.protocol === 'https:'
      && parsed.origin === value
      && parsed.username === ''
      && parsed.password === ''
      && parsed.pathname === '/'
      && parsed.search === ''
      && parsed.hash === ''
  } catch {
    return false
  }
}

function canonicalPathPrefix(value) {
  if (
    typeof value !== 'string'
    || !value.startsWith('/')
    || value.startsWith('//')
    || value.includes('#')
    || value.includes('?')
    || AMBIGUOUS_PATH.test(value)
    || WILDCARD_SYNTAX.test(value)
  ) return false
  try {
    const parsed = new URL(value, 'https://adapter.invalid')
    return parsed.origin === 'https://adapter.invalid'
      && parsed.search === ''
      && parsed.hash === ''
      && parsed.pathname === value
  } catch {
    return false
  }
}

function timestamp(value) {
  const milliseconds = Date.parse(value)
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value
    ? milliseconds
    : Number.NaN
}

function decodedPointerSegments(pointer) {
  return pointer.slice(1).split('/').map((segment) => (
    segment.replaceAll('~1', '/').replaceAll('~0', '~')
  ))
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue)
  if (value === null || typeof value !== 'object') return value
  return Object.fromEntries(
    Object.keys(value)
      .sort(compareCanonicalStrings)
      .map((key) => [key, stableValue(value[key])]),
  )
}

function assertSemantics(value) {
  if (!validateSchema(value)) {
    throw adapterError(
      'PAGE_SESSION_ADAPTER_INVALID',
      'page session adapter violates its declarative schema',
      normalizedSchemaErrors(),
    )
  }
  if (
    value.source.extraction.mode === 'JSON_POINTER'
      && decodedPointerSegments(value.source.extraction.pointer)
        .some((segment) => BLOCKED_POINTER_SEGMENTS.has(segment))
  ) {
    throw adapterError(
      'PAGE_SESSION_ADAPTER_INVALID',
      'page session adapter source must be an exact non-executable storage location',
    )
  }
  if (
    FORBIDDEN_CARRIER_HEADERS.has(value.carrier.name)
    || value.carrier.name.startsWith('proxy-')
    || value.carrier.name.startsWith('sec-')
    || value.carrier.name.startsWith('x-forwarded-')
    || Buffer.byteLength(value.carrier.prefix ?? '', 'utf8')
      + value.limits.max_value_bytes > 8192
  ) {
    throw adapterError(
      'PAGE_SESSION_ADAPTER_INVALID',
      'page session adapter carrier is unsafe or exceeds the request-header boundary',
    )
  }
  const notBefore = timestamp(value.validity.not_before)
  const notAfter = timestamp(value.validity.not_after)
  if (!Number.isFinite(notBefore) || !Number.isFinite(notAfter) || notAfter <= notBefore) {
    throw adapterError(
      'PAGE_SESSION_ADAPTER_INVALID',
      'page session adapter validity must be an increasing exact UTC interval',
    )
  }
  for (const constraint of value.target_constraints) {
    if (
      !canonicalOrigin(constraint.origin)
      || FORBIDDEN_METHODS.has(constraint.method)
      || !canonicalPathPrefix(constraint.path_prefix)
    ) {
      throw adapterError(
        'PAGE_SESSION_ADAPTER_INVALID',
        'page session adapter targets must be canonical HTTPS origin, method, and path constraints without wildcards',
      )
    }
  }
  return value
}

export function normalizePageSessionAdapter(value) {
  assertSemantics(value)
  return structuredClone(value)
}

export function canonicalPageSessionAdapter(value) {
  return JSON.stringify(stableValue(normalizePageSessionAdapter(value)))
}

export function pageSessionAdapterSha256(value) {
  return createHash('sha256').update(canonicalPageSessionAdapter(value), 'utf8').digest('hex')
}

function instantMilliseconds(value) {
  const milliseconds = value instanceof Date ? value.getTime() : Date.parse(value)
  if (!Number.isFinite(milliseconds)) {
    throw adapterError('PAGE_SESSION_ADAPTER_TIME_INVALID', 'page session adapter clock is invalid')
  }
  return milliseconds
}

export function assertPageSessionAdapterCurrent(adapter, now = new Date()) {
  assertSemantics(adapter)
  const current = instantMilliseconds(now)
  if (current < timestamp(adapter.validity.not_before)) {
    throw adapterError(
      'PAGE_SESSION_ADAPTER_NOT_YET_VALID',
      'page session adapter is not yet valid',
    )
  }
  if (current > timestamp(adapter.validity.not_after)) {
    throw adapterError('PAGE_SESSION_ADAPTER_EXPIRED', 'page session adapter has expired')
  }
  return adapter
}

function pathMatchesPrefix(pathname, prefix) {
  if (prefix === '/') return true
  return pathname === prefix
    || (prefix.endsWith('/')
      ? pathname.startsWith(prefix)
      : pathname.startsWith(`${prefix}/`))
}

export function assertPageSessionAdapterAllowsRequest({
  adapter,
  origin,
  method,
  pathAndQuery,
  now = new Date(),
} = {}) {
  assertPageSessionAdapterCurrent(adapter, now)
  if (
    !canonicalOrigin(origin)
    || typeof method !== 'string'
    || typeof pathAndQuery !== 'string'
    || pathAndQuery.length < 1
    || pathAndQuery.length > 4096
    || !pathAndQuery.startsWith('/')
    || pathAndQuery.startsWith('//')
    || pathAndQuery.includes('#')
    || AMBIGUOUS_PATH.test(pathAndQuery)
  ) {
    throw adapterError(
      'PAGE_SESSION_ADAPTER_TARGET_REFUSED',
      'page session adapter refused a non-canonical request target',
    )
  }
  let parsed
  try {
    parsed = new URL(pathAndQuery, origin)
  } catch {
    throw adapterError(
      'PAGE_SESSION_ADAPTER_TARGET_REFUSED',
      'page session adapter refused an invalid request target',
    )
  }
  if (
    parsed.origin !== origin
    || `${parsed.pathname}${parsed.search}` !== pathAndQuery
    || !adapter.target_constraints.some((constraint) => (
      constraint.origin === origin
      && constraint.method === method
      && pathMatchesPrefix(parsed.pathname, constraint.path_prefix)
    ))
  ) {
    throw adapterError(
      'PAGE_SESSION_ADAPTER_TARGET_REFUSED',
      'page session adapter refused a request outside its declared target constraints',
    )
  }
  return adapter
}

function declaredScopeRequests(scope) {
  const requests = []
  const add = (request) => {
    if (request?.method !== undefined && request?.url !== undefined) requests.push(request)
  }
  add(scope?.liveness?.credential_preflight)
  for (const action of scope?.requests ?? []) {
    add(action)
    add(action.before_read)
    add(action.after_read)
    add(action.rollback)
    add(action.rollback?.verification_read)
  }
  return requests
}

export function assertPageSessionAdapterCompatibleWithScope(adapter, scope) {
  assertSemantics(adapter)
  const authorized = scope?.authorization?.authorized_scope
  if (
    scope?.credential?.mode !== 'CHROME_ACTIVE_TAB_SESSION'
    || scope.credential.origin !== scope?.target?.origin
    || scope.credential.session_adapter === undefined
    || !Array.isArray(authorized?.origins)
    || !Array.isArray(authorized?.methods)
    || !Array.isArray(authorized?.path_prefixes)
    || pageSessionAdapterSha256(scope.credential.session_adapter)
      !== pageSessionAdapterSha256(adapter)
    || timestamp(adapter.validity.not_before) > timestamp(scope?.validity?.not_before)
    || timestamp(adapter.validity.not_after) < timestamp(
      scope?.validity?.cleanup_not_after ?? scope?.validity?.not_after,
    )
  ) {
    throw adapterError(
      'PAGE_SESSION_ADAPTER_SCOPE_MISMATCH',
      'page session adapter does not cover the sealed browser-session scope',
    )
  }
  for (const constraint of adapter.target_constraints) {
    if (
      !authorized.origins.includes(constraint.origin)
      || !authorized.methods.includes(constraint.method)
      || !authorized.path_prefixes.some((prefix) => (
        canonicalPathPrefix(prefix)
        && pathMatchesPrefix(constraint.path_prefix, prefix)
      ))
    ) {
      throw adapterError(
        'PAGE_SESSION_ADAPTER_SCOPE_MISMATCH',
        'page session adapter target constraints exceed the sealed authorization scope',
      )
    }
  }
  for (const request of declaredScopeRequests(scope)) {
    let parsed
    try {
      parsed = new URL(request.url)
    } catch {
      throw adapterError(
        'PAGE_SESSION_ADAPTER_SCOPE_MISMATCH',
        'page session adapter cannot cover an invalid sealed request',
      )
    }
    try {
      assertPageSessionAdapterAllowsRequest({
        adapter,
        origin: parsed.origin,
        method: request.method,
        pathAndQuery: `${parsed.pathname}${parsed.search}`,
        now: scope.validity.not_before,
      })
    } catch (cause) {
      throw adapterError(
        'PAGE_SESSION_ADAPTER_SCOPE_MISMATCH',
        'page session adapter does not cover every sealed request',
        [],
        { cause },
      )
    }
  }
  return adapter
}

function sameFile(left, right) {
  return left.size === right.size
    && left.mtimeMs === right.mtimeMs
    && left.ino === right.ino
    && left.dev === right.dev
}

export async function readPageSessionAdapterFile(
  path,
  { lstatImpl = lstat, openImpl = open } = {},
) {
  try {
    assertLocalFilesystemEndpoint(path, 'page session adapter')
  } catch (cause) {
    throw adapterError(
      'PAGE_SESSION_ADAPTER_PATH_INVALID',
      'page session adapter must be a local absolute JSON file',
      [],
      { cause },
    )
  }
  if (typeof path !== 'string' || !isAbsolute(path)) {
    throw adapterError(
      'PAGE_SESSION_ADAPTER_PATH_INVALID',
      'page session adapter must be a local absolute JSON file',
    )
  }
  let initial
  try {
    initial = await lstatImpl(path)
  } catch (cause) {
    throw adapterError(
      'PAGE_SESSION_ADAPTER_UNREADABLE',
      'page session adapter file cannot be read',
      [],
      { cause },
    )
  }
  if (
    !initial.isFile()
    || initial.isSymbolicLink()
    || initial.size < 1
    || initial.size > MAX_DESCRIPTOR_BYTES
  ) {
    throw adapterError(
      'PAGE_SESSION_ADAPTER_FILE_UNSAFE',
      'page session adapter must be a bounded regular non-symlink file',
    )
  }
  let handle
  let bytes
  try {
    handle = await openImpl(path, OPEN_READ_ONLY_NO_FOLLOW)
    const before = await handle.stat()
    if (!before.isFile() || !sameFile(initial, before)) {
      throw adapterError(
        'PAGE_SESSION_ADAPTER_FILE_CHANGED',
        'page session adapter changed before it was read',
      )
    }
    bytes = await handle.readFile()
    const after = await handle.stat()
    const pathAfter = await lstatImpl(path)
    if (
      !after.isFile()
      || !pathAfter.isFile()
      || pathAfter.isSymbolicLink()
      || !sameFile(before, after)
      || !sameFile(initial, pathAfter)
      || bytes.length !== after.size
      || bytes.length < 1
      || bytes.length > MAX_DESCRIPTOR_BYTES
    ) {
      throw adapterError(
        'PAGE_SESSION_ADAPTER_FILE_CHANGED',
        'page session adapter changed while it was read',
      )
    }
    let parsed
    try {
      parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
    } catch (cause) {
      throw adapterError(
        'PAGE_SESSION_ADAPTER_JSON_INVALID',
        'page session adapter must contain valid UTF-8 JSON',
        [],
        { cause },
      )
    }
    return normalizePageSessionAdapter(parsed)
  } catch (error) {
    if (error instanceof PageSessionAdapterError) throw error
    throw adapterError(
      'PAGE_SESSION_ADAPTER_UNREADABLE',
      'page session adapter file cannot be read safely',
      [],
      { cause: error },
    )
  } finally {
    bytes?.fill(0)
    try { await handle?.close() } catch {}
  }
}
