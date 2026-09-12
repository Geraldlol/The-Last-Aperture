import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'

const MAX_HEADER_COUNT = 128
const MAX_HEADER_VALUE_BYTES = 8 * 1024
const MAX_COOKIE_COUNT = 256
const MAX_COOKIE_VALUE_BYTES = 4 * 1024
const MAX_COOKIE_HEADER_BYTES = 32 * 1024
const MAX_QUERY_VALUES = 4096
const MAX_REQUEST_BYTES = 1024 * 1024
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024
const MAX_RESPONSE_CREDENTIAL_VALUES = 4096
const MAX_REDIRECTS = 5
const MAX_RETRIES = 3
const MAX_TIMEOUT_MS = 120_000
const intrinsicByteFill = Uint8Array.prototype.fill
const PLACEHOLDER = /\{(integer|uuid|hex|segment|value|\.\.\.)\}/gu
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/u
const COOKIE_VALUE = /^[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*$/u
const AUTOMATIC_RETRY_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])
const SEMANTIC_VALUE = /^[A-Za-z][A-Za-z0-9_.:-]{0,63}$/u
const SEMANTIC_NAME = /^(?:_method|action|command|do|event|method|mode|op|operation|submit|task|view)$/iu
const WRITE_ACTION = /^(?:add|approve|archive|assign|begin|cancel|close|commit|confirm|connect|create|delete|disable|disconnect|edit|enable|end|execute|import|insert|link|merge|move|patch|pay|post|publish|put|remove|reset|revoke|save|send|set|start|stop|submit|sync|update|upload|write)$/iu
const READ_ACTION = /^(?:browse|detail|download|export|fetch|find|get|index|list|load|lookup|open|preview|query|read|report|retrieve|search|show|view)$/iu
const READ_SHAPED_ACTION_SUFFIXES = new Set([
  'detail', 'details', 'history', 'list', 'preview', 'report', 'result', 'results', 'status',
])
const MAX_LAYERED_DECODE_PASSES = 32
const RESPONSE_CREDENTIAL_HEADERS = new Set([
  'api-key', 'authorization', 'cookie', 'location', 'proxy-authorization', 'set-cookie',
  'x-access-token', 'x-amz-security-token', 'x-api-key', 'x-auth-token',
  'x-client-secret', 'x-csrf-token', 'x-goog-api-key', 'x-session-token', 'x-xsrf-token',
  'x-mfa-code', 'x-one-time-password', 'x-otp', 'x-pin', 'x-totp', 'x-verification-code',
])
const SENSITIVE_HEADER_FIELDS = new Set([
  'accesskey', 'accesskeyid', 'apikey', 'assertion', 'auth', 'authentication',
  'authorization', 'bearer', 'clientsecret', 'code', 'cookie', 'credential',
  'credentials', 'csrf', 'csrftoken', 'idtoken', 'jsessionid', 'jwt', 'key', 'mfa',
  'mfacode', 'otp', 'password', 'passwd', 'passcode', 'pin', 'pwd', 'refreshtoken',
  'relaystate', 'samlrequest', 'samlresponse', 'secret', 'session', 'sessionid',
  'sessiontoken', 'sid', 'sig', 'signature', 'state', 'ticket', 'token', 'totp',
  'verificationcode', 'xsrf', 'xsrftoken', 'xamzcredential', 'xamzsecuritytoken',
  'xamzsignature',
])
const SENSITIVE_HEADER_SUFFIX_FIELDS = new Set([
  'accesskey', 'apikey', 'assertion', 'cookie', 'credential', 'passcode',
  'passwd', 'password', 'relaystate', 'samlrequest', 'samlresponse', 'secret',
  'signature', 'state', 'token',
])
const SENSITIVE_HEADER_CODE_CONTEXTS = new Set([
  'auth', 'auth0', 'authentication', 'authorization', 'azuread', 'cognito', 'entra',
  'forgerock', 'identity', 'keycloak', 'login', 'oauth', 'oauth2', 'oidc', 'okta',
  'onelogin', 'ping', 'pingidentity', 'saml', 'security', 'signin', 'sso', 'vendor',
])
const MAX_SENSITIVE_VERSION_DIGITS = 8
const FORBIDDEN_HEADERS = new Set([
  'connection', 'content-length', 'content-type', 'cookie', 'forwarded', 'host',
  'keep-alive', 'origin', 'proxy-authenticate', 'proxy-authorization', 'referer',
  'te', 'trailer', 'transfer-encoding', 'upgrade', 'via', 'x-forwarded-host',
  'x-forwarded-port', 'x-forwarded-proto', 'x-http-method',
  'x-http-method-override', 'x-method-override', 'x-original-url', 'x-rewrite-url',
])

function eraseBytes(value) {
  try {
    const bytes = value instanceof Uint8Array
      ? value
      : (value instanceof ArrayBuffer
          ? new Uint8Array(value)
          : (ArrayBuffer.isView(value)
              ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
              : null))
    if (bytes !== null) Reflect.apply(intrinsicByteFill, bytes, [0])
  } catch {
    // Producers may detach or resize handed-off storage. Cleanup cannot own settlement.
  }
}

function forbiddenHeader(name) {
  const lower = name.toLowerCase()
  return FORBIDDEN_HEADERS.has(lower)
    || lower.startsWith('sec-')
    || lower.startsWith('x-forwarded-')
    || lower.startsWith('x-original-')
    || lower.startsWith('x-rewrite-')
    || lower === 'x-envoy-original-path'
    || lower === 'x-http-url-override'
}

function sensitiveHeaderSuffix(candidate) {
  const version = /v?([0-9]+)$/u.exec(candidate)
  if (version?.[1].length > MAX_SENSITIVE_VERSION_DIGITS) return true
  const stem = version === null ? candidate : candidate.slice(0, -version[0].length)
  if (stem.endsWith('code')) {
    const context = stem.slice(0, -'code'.length)
    for (const marker of SENSITIVE_HEADER_CODE_CONTEXTS) {
      if (context.endsWith(marker)) return true
    }
  }
  for (const field of SENSITIVE_HEADER_SUFFIX_FIELDS) {
    if (stem.endsWith(field)) return true
  }
  return false
}

function sensitiveHeaderName(value) {
  const lower = String(value).toLowerCase()
  if (RESPONSE_CREDENTIAL_HEADERS.has(lower)) return true
  let decoded = lower
  for (let pass = 0; decoded.includes('%') && pass < 8; pass += 1) {
    try { decoded = decodeURIComponent(decoded) } catch { return true }
  }
  if (decoded.includes('%')) return true
  const compact = decoded.toLowerCase().replace(/[^a-z0-9]/gu, '')
  const candidates = compact.startsWith('x') && compact.length > 1
    ? [compact, compact.slice(1)]
    : [compact]
  return candidates.some((candidate) => (
    SENSITIVE_HEADER_FIELDS.has(candidate)
    || sensitiveHeaderSuffix(candidate)
    || /^(?:csrf|xsrf)/u.test(candidate)
  ))
}

function fail(code, message) {
  const error = new Error(message)
  error.name = 'GeneratedConnectorError'
  error.code = code
  throw error
}

function markRequestMayHaveBeenSent(error) {
  if (error !== null && typeof error === 'object' && Object.isExtensible(error)) {
    error.request_may_have_been_sent = true
    return error
  }
  const wrapped = new Error('connector request failed after transport invocation', { cause: error })
  wrapped.name = 'GeneratedConnectorError'
  wrapped.code = 'CONNECTOR_TRANSPORT_FAILED'
  wrapped.request_may_have_been_sent = true
  return wrapped
}

function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
}

function exact(value, fields, label) {
  if (!plain(value)) fail('CONNECTOR_PACKAGE_INVALID', `${label} must be an object`)
  const actual = Object.keys(value).sort()
  const expected = [...fields].sort()
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail('CONNECTOR_PACKAGE_INVALID', `${label} contains a missing or unknown field`)
  }
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function deepFreeze(value) {
  if (ArrayBuffer.isView(value)) return value
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value)
    for (const child of Object.values(value)) deepFreeze(child)
  }
  return value
}

function readPackageFile(name) {
  return readFileSync(new URL(`./${name}`, import.meta.url))
}

function loadPackage() {
  let manifest
  let descriptor
  try {
    manifest = JSON.parse(readPackageFile('manifest.json').toString('utf8'))
    descriptor = JSON.parse(readPackageFile('connector.json').toString('utf8'))
  } catch {
    fail('CONNECTOR_PACKAGE_INVALID', 'generated connector metadata is missing or invalid')
  }
  exact(manifest, [
    'schema_version', 'kind', 'generator_protocol', 'package_name', 'contract_id',
    'contract_sha256', 'generation_status', 'runtime_mode', 'network_during_generation',
    'content_sha256', 'files',
  ], 'connector manifest')
  if (
    manifest.schema_version !== '1.0.0'
    || manifest.kind !== 'last-aperture/generated-connector-manifest'
    || manifest.generator_protocol !== 'native-interaction-connector-generator-v1'
    || manifest.generation_status !== 'GENERATED_REVIEWABLE'
    || manifest.runtime_mode !== 'CONTRACT_BOUND'
    || manifest.network_during_generation !== 'NONE'
    || !/^interaction:[a-f0-9]{32}$/u.test(manifest.contract_id)
    || !/^[a-f0-9]{64}$/u.test(manifest.contract_sha256)
    || !/^[a-f0-9]{64}$/u.test(manifest.content_sha256)
    || !Array.isArray(manifest.files)
  ) fail('CONNECTOR_PACKAGE_INVALID', 'generated connector manifest is invalid')

  const expectedPaths = ['README.md', 'connector.json', 'index.mjs', 'package.json']
  const actualPaths = manifest.files.map((item) => item?.path)
  if (JSON.stringify(actualPaths) !== JSON.stringify(expectedPaths)) {
    fail('CONNECTOR_PACKAGE_INVALID', 'generated connector file inventory is invalid')
  }
  for (const item of manifest.files) {
    exact(item, ['path', 'sha256'], 'connector file record')
    if (!/^[a-f0-9]{64}$/u.test(item.sha256) || sha256(readPackageFile(item.path)) !== item.sha256) {
      fail('CONNECTOR_PACKAGE_INVALID', 'generated connector file digest does not match')
    }
  }
  const contentMaterial = manifest.files.map((item) => `${item.path}\u0000${item.sha256}`).join('\n')
  if (sha256(contentMaterial) !== manifest.content_sha256) {
    fail('CONNECTOR_PACKAGE_INVALID', 'generated connector content digest does not match')
  }

  exact(descriptor, [
    'schema_version', 'kind', 'protocol', 'status', 'runtime_mode', 'source_contract',
    'subjects', 'auth_flows', 'endpoints',
  ], 'connector descriptor')
  exact(descriptor.source_contract, [
    'contract_id', 'sha256', 'schema_version', 'protocol', 'generated_at', 'basis',
  ], 'source contract binding')
  if (
    descriptor.schema_version !== '1.0.0'
    || descriptor.kind !== 'last-aperture/generated-native-connector'
    || descriptor.protocol !== 'native-interaction-connector-v1'
    || descriptor.status !== 'GENERATED_REVIEWABLE'
    || descriptor.runtime_mode !== 'CONTRACT_BOUND'
    || descriptor.source_contract.contract_id !== manifest.contract_id
    || descriptor.source_contract.sha256 !== manifest.contract_sha256
    || !Array.isArray(descriptor.endpoints)
    || !Array.isArray(descriptor.auth_flows)
    || !plain(descriptor.subjects)
    || !Array.isArray(descriptor.subjects.origins)
  ) fail('CONNECTOR_PACKAGE_INVALID', 'generated connector descriptor is invalid')
  const endpointIds = descriptor.endpoints.map((item) => item?.endpoint_id)
  if (new Set(endpointIds).size !== endpointIds.length || endpointIds.some((id) => !/^endpoint:[a-f0-9]{32}$/u.test(id))) {
    fail('CONNECTOR_PACKAGE_INVALID', 'generated connector endpoint inventory is invalid')
  }
  for (const endpoint of descriptor.endpoints) {
    if (!descriptor.subjects.origins.includes(endpoint.origin)) {
      fail('CONNECTOR_PACKAGE_INVALID', 'generated connector endpoint origin is outside its source contract')
    }
  }
  return { manifest: deepFreeze(manifest), descriptor: deepFreeze(descriptor) }
}

const PACKAGE = loadPackage()
const ENDPOINT_BY_ID = new Map(PACKAGE.descriptor.endpoints.map((endpoint) => [endpoint.endpoint_id, endpoint]))

function boundedInteger(value, fallback, maximum, label) {
  const selected = value === undefined ? fallback : value
  if (!Number.isSafeInteger(selected) || selected < 0 || selected > maximum) {
    fail('CONNECTOR_OPTION_INVALID', `${label} is invalid`)
  }
  return selected
}

function assertRecord(value, label) {
  if (value === undefined) return {}
  if (!plain(value)) fail('CONNECTOR_INPUT_INVALID', `${label} must be an object`)
  if (Object.keys(value).length > MAX_QUERY_VALUES) fail('CONNECTOR_INPUT_INVALID', `${label} contains too many values`)
  for (const key of Object.keys(value)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      fail('CONNECTOR_INPUT_INVALID', `${label} contains an unsafe key`)
    }
  }
  return value
}

function scalarText(value, label, maximum = 16 * 1024) {
  if (!['string', 'number', 'boolean', 'bigint'].includes(typeof value)) {
    fail('CONNECTOR_INPUT_INVALID', `${label} must be a scalar value`)
  }
  const result = String(value)
  if (Buffer.byteLength(result, 'utf8') > maximum || /[\u0000\r\n]/u.test(result)) {
    fail('CONNECTOR_INPUT_INVALID', `${label} is invalid`)
  }
  return result
}

function semanticActionClass(value, { allowReadSuffix = true } = {}) {
  if (typeof value !== 'string') return null
  let decoded = value
  for (let pass = 0; pass < MAX_LAYERED_DECODE_PASSES; pass += 1) {
    let next
    try { next = decodeURIComponent(decoded) } catch { break }
    if (next === decoded) break
    decoded = next
  }
  try {
    if (decodeURIComponent(decoded) !== decoded) return 'OTHER_ACTION'
  } catch {}
  if (!SEMANTIC_VALUE.test(decoded)) return null
  const tokens = decoded.toLowerCase().split(/[^a-z0-9]+/u).filter(Boolean)
  if (allowReadSuffix && READ_SHAPED_ACTION_SUFFIXES.has(tokens.at(-1))) return 'READ_ACTION'
  if (tokens.some((token) => WRITE_ACTION.test(token))) return 'WRITE_ACTION'
  if (tokens.some((token) => READ_ACTION.test(token))) return 'READ_ACTION'
  return 'OTHER_ACTION'
}

function pathActionClass(pathname) {
  let read = false
  for (const part of pathname.split('/').filter(Boolean)) {
    const classification = semanticActionClass(part)
    if (classification === 'WRITE_ACTION') return 'WRITE_ACTION'
    if (classification === 'READ_ACTION') read = true
  }
  return read ? 'READ_ACTION' : 'NONE'
}

function assertPathActionClass(endpoint, pathname, code = 'CONNECTOR_INPUT_INVALID') {
  const classification = pathActionClass(pathname)
  if (
    classification === 'OTHER_ACTION'
    || !endpoint.request.path_action_classes.includes(classification)
  ) {
    fail(code, 'resolved path changes or leaves its action semantics unclassified')
  }
}

function assertSemanticClass(value, field, label) {
  if (!Array.isArray(field.semantic_classes) || field.semantic_classes.length === 0) {
    if (SEMANTIC_NAME.test(field.name ?? '')) {
      fail('CONNECTOR_INPUT_INVALID', `${label} leaves its action semantics unclassified`)
    }
    return
  }
  const classification = semanticActionClass(value, { allowReadSuffix: false })
  if (
    classification === null
    || classification === 'OTHER_ACTION'
    || !field.semantic_classes.includes(classification)
  ) {
    fail('CONNECTOR_INPUT_INVALID', `${label} changes or leaves its action semantics unclassified`)
  }
}

function assertSemanticValues(value, field, label, depth = 0) {
  if (typeof value === 'string') {
    assertSemanticClass(value, field, label)
    return
  }
  if (Array.isArray(value)) {
    if (depth > 16) fail('CONNECTOR_INPUT_INVALID', `${label} nesting is too deep`)
    if (value.length === 0 && actionBoundField(field)) {
      fail('CONNECTOR_INPUT_INVALID', `${label} leaves its action semantics unclassified`)
    }
    for (const child of value) assertSemanticValues(child, field, label, depth + 1)
    return
  }
  if (SEMANTIC_NAME.test(field.name ?? '')) {
    fail('CONNECTOR_INPUT_INVALID', `${label} leaves its action semantics unclassified`)
  }
}

function actionBoundField(field) {
  return SEMANTIC_NAME.test(field.name ?? '')
    || Array.isArray(field.semantic_classes) && field.semantic_classes.length > 0
}

function cookieValue(value, label) {
  const result = scalarText(value, label, MAX_COOKIE_VALUE_BYTES)
  if (!COOKIE_VALUE.test(result)) fail('CONNECTOR_INPUT_INVALID', `${label} is not a valid cookie value`)
  return result
}

function segment(value, label) {
  const result = scalarText(value, label, 2048)
  if (result.length === 0 || result === '.' || result === '..' || /[\\/%]/u.test(result)) {
    fail('CONNECTOR_INPUT_INVALID', `${label} is invalid`)
  }
  return encodeURIComponent(result)
}

function typedSegment(kind, value) {
  const text = scalarText(value, `path value for {${kind}}`, 2048)
  if (kind === 'integer' && !/^-?(?:0|[1-9][0-9]*)$/u.test(text)) {
    fail('CONNECTOR_INPUT_INVALID', 'integer path value does not match its observed type')
  }
  if (kind === 'uuid' && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(text)) {
    fail('CONNECTOR_INPUT_INVALID', 'UUID path value does not match its observed type')
  }
  if (kind === 'hex' && !/^[0-9a-f]{16,}$/iu.test(text)) {
    fail('CONNECTOR_INPUT_INVALID', 'hex path value does not match its observed type')
  }
  return segment(text, `path value for {${kind}}`)
}

function fillPath(pathTemplate, supplied) {
  const values = assertRecord(supplied, 'path values')
  const positions = new Map()
  const used = new Set()
  const path = pathTemplate.replace(PLACEHOLDER, (_match, kind) => {
    if (!Object.hasOwn(values, kind)) fail('CONNECTOR_INPUT_INVALID', `path value is required for {${kind}}`)
    used.add(kind)
    if (kind === '...') {
      const rest = Array.isArray(values[kind]) ? values[kind] : [values[kind]]
      if (rest.length < 1 || rest.length > 64) fail('CONNECTOR_INPUT_INVALID', 'rest path value is invalid')
      return rest.map((item) => segment(item, 'rest path value')).join('/')
    }
    const source = Array.isArray(values[kind]) ? values[kind] : [values[kind]]
    const index = positions.get(kind) ?? 0
    if (index >= source.length) fail('CONNECTOR_INPUT_INVALID', `another path value is required for {${kind}}`)
    positions.set(kind, index + 1)
    return typedSegment(kind, source[index])
  })
  for (const key of Object.keys(values)) {
    if (!used.has(key)) fail('CONNECTOR_INPUT_INVALID', 'an unused path value was supplied')
    const expected = positions.get(key)
    if (expected !== undefined && Array.isArray(values[key]) && values[key].length !== expected) {
      fail('CONNECTOR_INPUT_INVALID', 'too many path values were supplied')
    }
  }
  const parsed = new URL(path, 'https://connector.invalid')
  if (parsed.origin !== 'https://connector.invalid' || parsed.pathname !== path || parsed.search || parsed.hash) {
    fail('CONNECTOR_INPUT_INVALID', 'resolved path escaped its contract template')
  }
  return path
}

function pathMatcher(pathTemplate) {
  let source = '^'
  let cursor = 0
  for (const match of pathTemplate.matchAll(PLACEHOLDER)) {
    source += pathTemplate.slice(cursor, match.index).replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')
    const kind = match[1]
    source += kind === '...'
      ? '(?:[^/?#]+(?:/[^/?#]+)*)'
      : kind === 'integer'
        ? '-?(?:0|[1-9][0-9]*)'
        : kind === 'uuid'
          ? '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[1-5][0-9A-Fa-f]{3}-[89AaBb][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}'
          : kind === 'hex'
            ? '[0-9A-Fa-f]{16,}'
            : '[^/?#]+'
    cursor = match.index + match[0].length
  }
  source += pathTemplate.slice(cursor).replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')
  return new RegExp(`${source}$`, 'u')
}

function endpointForRedirect(sourceEndpoint, location, status) {
  if (location.username || location.password || location.hash) {
    fail('CONNECTOR_REDIRECT_REFUSED', 'response redirect contains user-info or a fragment')
  }
  const locationDestinations = sourceEndpoint.exchanges
    .filter((exchange) => exchange.response.status === status)
    .flatMap((exchange) => exchange.response.destinations)
    .filter((destination) => destination.source === 'LOCATION_HEADER')
  const allowedShapes = locationDestinations.filter((destination) => (
    destination.origin === location.origin
    && pathMatcher(destination.path_template).test(location.pathname)
    && redirectQueryMatches(destination.query_parameters, location)
  ))
  if (allowedShapes.length === 0) fail('CONNECTOR_REDIRECT_REFUSED', 'response redirect is outside the exact observed exchange')
  const method = (status === 303 && !['GET', 'HEAD'].includes(sourceEndpoint.method))
    || ((status === 301 || status === 302) && sourceEndpoint.method === 'POST')
    ? 'GET'
    : sourceEndpoint.method
  const allowedTemplates = new Set(allowedShapes.map((item) => item.path_template))
  const matches = PACKAGE.descriptor.endpoints.filter((item) => (
    item.origin === location.origin
    && item.method === method
    && allowedTemplates.has(item.path_template)
    && pathMatcher(item.path_template).test(location.pathname)
    && redirectQueryMatches(item.request.query_parameters, location)
  ))
  if (matches.length !== 1) fail('CONNECTOR_REDIRECT_REFUSED', 'response redirect does not resolve to one contract endpoint')
  return matches[0]
}

function matchesObservedType(value, type, textual) {
  if (type === 'unknown') return true
  if (type === 'null') return value === null || textual && typeof value === 'string' && /^(?:null|undefined)$/iu.test(value)
  if (type === 'array') return Array.isArray(value)
  if (type === 'object') return plain(value)
  if (type === 'boolean') return typeof value === 'boolean' || textual && typeof value === 'string' && /^(?:true|false)$/iu.test(value)
  if (type === 'integer') return Number.isSafeInteger(value) || textual && typeof value === 'string' && /^-?(?:0|[1-9][0-9]*)$/u.test(value)
  if (type === 'number') return typeof value === 'number' && Number.isFinite(value)
    || textual && typeof value === 'string' && /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/u.test(value)
  return type === 'string' && typeof value === 'string'
}

function assertObservedType(value, field, label, { textual = false } = {}) {
  if (!field.types.some((type) => matchesObservedType(value, type, textual))) {
    fail('CONNECTOR_INPUT_INVALID', `${label} does not match its observed type`)
  }
}

function redirectQueryMatches(fields, location) {
  const allowed = new Map(fields.map((field) => [field.name, field]))
  const present = new Set(location.searchParams.keys())
  if (fields.some((field) => actionBoundField(field) && !present.has(field.name))) return false
  return [...location.searchParams.entries()].every(([name, value]) => {
    const field = allowed.get(name)
    const semanticClass = semanticActionClass(value, { allowReadSuffix: false })
    return field !== undefined
      && field.types.some((type) => matchesObservedType(value, type, true))
      && (
        !Array.isArray(field.semantic_classes)
        || field.semantic_classes.length === 0
        || semanticClass !== 'OTHER_ACTION' && field.semantic_classes.includes(semanticClass)
      )
  })
}

function normalizeQuery(endpoint, supplied) {
  const values = assertRecord(supplied, 'query')
  const allowed = new Map(endpoint.request.query_parameters.map((item) => [item.name, item]))
  for (const field of allowed.values()) {
    const suppliedValue = values[field.name]
    if (
      actionBoundField(field)
      && (!Object.hasOwn(values, field.name)
        || suppliedValue === undefined
        || Array.isArray(suppliedValue) && suppliedValue.every((value) => value === undefined))
    ) {
      fail('CONNECTOR_INPUT_INVALID', 'query leaves observed action semantics unspecified')
    }
  }
  const result = new URLSearchParams()
  let count = 0
  for (const name of Object.keys(values).sort()) {
    const field = allowed.get(name)
    if (!field) fail('CONNECTOR_INPUT_INVALID', 'query contains an unobserved parameter')
    const items = Array.isArray(values[name]) ? values[name] : [values[name]]
    for (const value of items) {
      count += 1
      if (count > MAX_QUERY_VALUES) fail('CONNECTOR_INPUT_INVALID', 'query contains too many values')
      if (value !== undefined) {
        assertObservedType(value, field, 'query value', { textual: true })
        assertSemanticClass(String(value), field, 'query value')
        result.append(name, scalarText(value, 'query value'))
      }
    }
  }
  return result
}

function normalizeHeaders(supplied, { allowed, code = 'CONNECTOR_INPUT_INVALID', label = 'headers' } = {}) {
  const values = assertRecord(supplied, 'headers')
  if (Object.keys(values).length > MAX_HEADER_COUNT) fail('CONNECTOR_INPUT_INVALID', 'too many headers were supplied')
  const result = {}
  for (const name of Object.keys(values).sort()) {
    const lower = name.toLowerCase()
    if (!HEADER_NAME.test(name) || forbiddenHeader(lower)) {
      fail(code, `a forbidden ${label} header was supplied`)
    }
    if (!(allowed instanceof Set) || !allowed.has(lower)) {
      fail(code, `${label} contains an unobserved or undeclared header`)
    }
    const value = scalarText(values[name], 'header value', MAX_HEADER_VALUE_BYTES)
    result[lower] = value
  }
  return result
}

function callerHeaderNames(endpoint) {
  const credentialHeaders = carrierParts(endpoint).headers
  return new Set(endpoint.request.header_names.filter((name) => (
    !credentialHeaders.has(name) && !sensitiveHeaderName(name)
  )))
}

function normalizedFieldValues(value, prefix = '', result = []) {
  if (Array.isArray(value)) {
    const path = `${prefix}[]`
    for (const child of value) normalizedFieldValues(child, path, result)
    return result
  }
  if (!plain(value)) return result
  for (const [name, child] of Object.entries(value)) {
    if (name === '__proto__' || name === 'constructor' || name === 'prototype' || /[.\[\]]/u.test(name)) {
      fail('CONNECTOR_INPUT_INVALID', 'body contains an unsafe field name')
    }
    const path = prefix ? `${prefix}.${name}` : name
    result.push({ path, value: child })
    normalizedFieldValues(child, path, result)
  }
  return result
}

function cloneBody(value, ownedByteClones, depth = 0) {
  if (depth > 16) fail('CONNECTOR_INPUT_INVALID', 'body nesting is too deep')
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) return value
  if (value instanceof Uint8Array) {
    if (value.byteLength > MAX_REQUEST_BYTES) fail('CONNECTOR_INPUT_INVALID', 'request body is too large')
    const clone = new Uint8Array(value)
    ownedByteClones.add(clone)
    return clone
  }
  if (Array.isArray(value)) {
    if (value.length > 4096) fail('CONNECTOR_INPUT_INVALID', 'body array is too large')
    return value.map((item) => cloneBody(item, ownedByteClones, depth + 1))
  }
  const record = assertRecord(value, 'body')
  return Object.fromEntries(Object.entries(record).map(
    ([key, child]) => [key, cloneBody(child, ownedByteClones, depth + 1)],
  ))
}

function mergeBody(base, addition, ownedByteClones) {
  if (addition === undefined) return base
  if (base === undefined) return cloneBody(addition, ownedByteClones)
  if (!plain(base) || !plain(addition)) fail('CONNECTOR_INPUT_INVALID', 'credential body cannot merge with the request body')
  const result = cloneBody(base, ownedByteClones)
  for (const [key, value] of Object.entries(addition)) {
    result[key] = plain(result[key]) && plain(value)
      ? mergeBody(result[key], value, ownedByteClones)
      : cloneBody(value, ownedByteClones)
  }
  return result
}

function assertBodyShape(endpoint, body, { textual = false } = {}) {
  const allowed = new Map(endpoint.request.fields.map((item) => [item.path, item]))
  if (body === undefined) {
    if ([...allowed.values()].some(actionBoundField)) {
      fail('CONNECTOR_INPUT_INVALID', 'body leaves observed action semantics unspecified')
    }
    return
  }
  if (
    allowed.size > 0
    && !plain(body)
    && !(Array.isArray(body) && [...allowed.keys()].some((path) => path.startsWith('[]')))
  ) fail('CONNECTOR_INPUT_INVALID', 'body root does not match its observed object or array shape')
  const suppliedFields = normalizedFieldValues(body)
  const suppliedPaths = new Set(suppliedFields.map(({ path }) => path))
  if ([...allowed.values()].some((field) => actionBoundField(field) && !suppliedPaths.has(field.path))) {
    fail('CONNECTOR_INPUT_INVALID', 'body leaves observed action semantics unspecified')
  }
  for (const item of suppliedFields) {
    const field = allowed.get(item.path)
    if (!field) fail('CONNECTOR_INPUT_INVALID', 'body contains an unobserved field path')
    assertObservedType(item.value, field, 'body value', { textual })
    assertSemanticValues(item.value, field, 'body value')
  }
}

function encodeBody(endpoint, body, requestedContentType) {
  if (body === undefined) {
    assertBodyShape(endpoint, body)
    return { body: undefined, contentType: null }
  }
  const observed = endpoint.request.content_types
  const contentType = requestedContentType ?? observed[0]
  if (typeof contentType !== 'string' || !observed.includes(contentType)) {
    fail('CONNECTOR_INPUT_INVALID', 'request content type was not observed for this endpoint')
  }
  assertBodyShape(endpoint, body, {
    textual: contentType === 'application/x-www-form-urlencoded',
  })
  let encoded
  if (contentType === 'application/json' || contentType.endsWith('+json')) {
    encoded = JSON.stringify(body)
  } else if (contentType === 'application/x-www-form-urlencoded') {
    const record = assertRecord(body, 'form body')
    const params = new URLSearchParams()
    for (const name of Object.keys(record).sort()) {
      const items = Array.isArray(record[name]) ? record[name] : [record[name]]
      for (const value of items) params.append(name, scalarText(value, 'form value'))
    }
    encoded = params.toString()
  } else if (typeof body === 'string' || body instanceof Uint8Array) {
    encoded = body
  } else {
    fail('CONNECTOR_INPUT_INVALID', 'this observed content type requires a string or byte body')
  }
  if (Buffer.byteLength(encoded) > MAX_REQUEST_BYTES) fail('CONNECTOR_INPUT_INVALID', 'request body is too large')
  return { body: encoded, contentType }
}

function carrierParts(endpoint) {
  const result = { headers: new Set(), cookies: new Set(), body: new Set() }
  for (const carrier of endpoint.auth.request_carriers) {
    const separator = carrier.indexOf(':')
    const kind = carrier.slice(0, separator)
    if (kind === 'header') result.headers.add(carrier.slice(separator + 1))
    else if (kind === 'cookie') result.cookies.add(carrier.slice(separator + 1))
    else if (kind === 'body') result.body.add(carrier.slice(separator + 1))
  }
  return result
}

function validateCredentials(endpoint, supplied, ownedByteClones) {
  if (supplied === undefined || supplied === null) return { headers: {}, cookies: {}, body: undefined }
  if (!plain(supplied) || Object.keys(supplied).some((key) => !['body', 'cookies', 'headers'].includes(key))) {
    fail('CONNECTOR_CREDENTIAL_INVALID', 'credential provider result contains an unknown field')
  }
  const carriers = carrierParts(endpoint)
  const headers = normalizeHeaders(supplied.headers, {
    allowed: carriers.headers,
    code: 'CONNECTOR_CREDENTIAL_INVALID',
    label: 'credential provider',
  })
  const cookies = assertRecord(supplied.cookies, 'credential cookies')
  for (const name of Object.keys(cookies)) {
    if (!carriers.cookies.has(name)) fail('CONNECTOR_CREDENTIAL_INVALID', 'credential provider returned an undeclared cookie carrier')
  }
  if (Object.keys(cookies).length > MAX_COOKIE_COUNT) fail('CONNECTOR_CREDENTIAL_INVALID', 'credential provider returned too many cookies')
  for (const value of Object.values(cookies)) cookieValue(value, 'credential cookie value')
  const body = supplied.body === undefined
    ? undefined
    : cloneBody(supplied.body, ownedByteClones)
  if (body !== undefined) {
    if (!plain(body) && !Array.isArray(body)) {
      fail('CONNECTOR_CREDENTIAL_INVALID', 'credential body must map to a declared field carrier')
    }
    const fieldValues = normalizedFieldValues(body)
    if (carriers.body.size === 0 || fieldValues.length === 0) {
      fail('CONNECTOR_CREDENTIAL_INVALID', 'credential body must populate a declared field carrier')
    }
    for (const item of fieldValues) {
      const supportsPath = carriers.body.has(item.path)
        || [...carriers.body].some((carrier) => carrier.startsWith(`${item.path}.`) || carrier.startsWith(`${item.path}[]`))
      if (!supportsPath) fail('CONNECTOR_CREDENTIAL_INVALID', 'credential provider returned an undeclared body carrier')
    }
  }
  return { headers, cookies, body }
}

function splitSetCookie(value) {
  if (!value) return []
  return value.split(/,(?=\s*[^;,=\s]+=[^;,]*)/u).map((item) => item.trim()).filter(Boolean)
}

function setCookieValues(headers) {
  if (typeof headers?.getSetCookie === 'function') return headers.getSetCookie()
  if (typeof headers?.raw === 'function') return headers.raw()['set-cookie'] ?? []
  return splitSetCookie(headers?.get?.('set-cookie'))
}

function defaultCookiePath(pathname) {
  if (!pathname.startsWith('/') || pathname === '/') return '/'
  const index = pathname.lastIndexOf('/')
  return index <= 0 ? '/' : pathname.slice(0, index)
}

function cookiePathMatches(requestPath, cookiePath) {
  return requestPath === cookiePath
    || requestPath.startsWith(cookiePath) && (cookiePath.endsWith('/') || requestPath[cookiePath.length] === '/')
}

function rememberCookies(jars, endpoint, headers, requestUrl) {
  const allowed = new Set(endpoint.auth.response_cookie_names)
  if (allowed.size === 0) return
  const jar = jars.get(endpoint.origin) ?? new Map()
  const now = Date.now()
  const values = setCookieValues(headers)
  if (!Array.isArray(values) || values.length > MAX_COOKIE_COUNT) {
    fail('CONNECTOR_RESPONSE_INVALID', 'response established too many cookies')
  }
  for (const line of values) {
    if (typeof line !== 'string' || Buffer.byteLength(line, 'utf8') > MAX_HEADER_VALUE_BYTES) {
      fail('CONNECTOR_RESPONSE_INVALID', 'response cookie is invalid')
    }
    const [pair, ...attributes] = line.split(';')
    const separator = pair.indexOf('=')
    if (separator < 1) continue
    const name = pair.slice(0, separator).trim()
    const value = pair.slice(separator + 1).trim()
    if (!allowed.has(name) || !HEADER_NAME.test(name) || Buffer.byteLength(value, 'utf8') > MAX_COOKIE_VALUE_BYTES || !COOKIE_VALUE.test(value)) continue
    let path = defaultCookiePath(requestUrl.pathname)
    let secure = false
    let expiresAt = null
    let domainAccepted = true
    for (const item of attributes) {
      const maxAge = /^\s*max-age\s*=\s*(-?\d+)\s*$/iu.exec(item)
      if (maxAge) {
        const seconds = Number(maxAge[1])
        expiresAt = !Number.isFinite(seconds) || seconds <= 0 ? 0 : now + Math.min(seconds, 31_536_000) * 1000
        continue
      }
      const expires = /^\s*expires\s*=\s*(.+)\s*$/iu.exec(item)
      if (expires && expiresAt === null) {
        const parsed = Date.parse(expires[1])
        if (Number.isFinite(parsed)) expiresAt = parsed
        continue
      }
      const pathAttribute = /^\s*path\s*=\s*(.*)\s*$/iu.exec(item)
      if (pathAttribute) {
        if (pathAttribute[1].startsWith('/')) path = pathAttribute[1]
        continue
      }
      const domain = /^\s*domain\s*=\s*(.*)\s*$/iu.exec(item)
      if (domain) {
        const normalized = domain[1].trim().replace(/^\./u, '').toLowerCase()
        domainAccepted = normalized === requestUrl.hostname.toLowerCase()
        continue
      }
      if (/^\s*secure\s*$/iu.test(item)) secure = true
    }
    const key = `${name}\n${path}`
    if (!domainAccepted) continue
    if (expiresAt !== null && expiresAt <= now || value.length === 0) jar.delete(key)
    else jar.set(key, { name, value, path, secure, expires_at: expiresAt })
  }
  if (jar.size > MAX_COOKIE_COUNT) fail('CONNECTOR_RESPONSE_INVALID', 'response established too many cookies')
  if (jar.size === 0) jars.delete(endpoint.origin)
  else jars.set(endpoint.origin, jar)
}

function requestCookies(jars, endpoint, requestUrl, supplied) {
  const allowed = new Set(endpoint.auth.request_cookie_names)
  const result = {}
  const jar = jars.get(endpoint.origin)
  if (jar) {
    const now = Date.now()
    const selected = new Map()
    for (const [key, cookie] of jar) {
      if (cookie.expires_at !== null && cookie.expires_at <= now) {
        jar.delete(key)
        continue
      }
      if (
        allowed.has(cookie.name)
        && (!cookie.secure || requestUrl.protocol === 'https:')
        && cookiePathMatches(requestUrl.pathname, cookie.path)
        && (!selected.has(cookie.name) || selected.get(cookie.name).path.length < cookie.path.length)
      ) selected.set(cookie.name, cookie)
    }
    for (const cookie of selected.values()) result[cookie.name] = cookie.value
    if (jar.size === 0) jars.delete(endpoint.origin)
  }
  const provided = assertRecord(supplied, 'request cookies')
  for (const [name, value] of Object.entries(provided)) {
    if (!allowed.has(name)) fail('CONNECTOR_INPUT_INVALID', 'request cookie was not observed for this endpoint')
    result[name] = cookieValue(value, 'request cookie value')
  }
  if (Object.keys(result).length > MAX_COOKIE_COUNT) fail('CONNECTOR_INPUT_INVALID', 'too many request cookies were supplied')
  return result
}

function cookieHeader(cookies) {
  const value = Object.keys(cookies).sort().map((name) => `${name}=${cookies[name]}`).join('; ')
  if (Buffer.byteLength(value, 'utf8') > MAX_COOKIE_HEADER_BYTES) {
    fail('CONNECTOR_INPUT_INVALID', 'request cookie header is too large')
  }
  return value
}

function cancelReaderWithoutWaiting(reader) {
  try {
    Promise.resolve(reader.cancel()).catch(() => {})
  } catch {}
}

async function readResponse(response, { withinDeadline }) {
  const chunks = []
  let length = 0
  let reader = null
  let combined = null
  let completed = false
  try {
    if (response.body && typeof response.body.getReader === 'function') {
      reader = response.body.getReader()
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
        if (part?.done === true) {
          eraseBytes(part.value)
          break
        }
        if (!(part?.value instanceof Uint8Array)) {
          fail('CONNECTOR_RESPONSE_INVALID', 'response stream returned a non-byte chunk')
        }
        if (length + part.value.byteLength > MAX_RESPONSE_BYTES) {
          eraseBytes(part.value)
          fail('CONNECTOR_RESPONSE_INVALID', 'response body exceeded the size limit')
        }
        const retained = Buffer.from(part.value)
        chunks.push(retained)
        length += retained.byteLength
        eraseBytes(part.value)
      }
    } else {
      if (typeof response.arrayBuffer !== 'function') {
        fail('CONNECTOR_RESPONSE_INVALID', 'response body is not readable')
      }
      const pendingArrayBuffer = Promise.resolve().then(() => response.arrayBuffer())
      let arrayBuffer
      try {
        arrayBuffer = await withinDeadline(() => pendingArrayBuffer)
      } catch (error) {
        pendingArrayBuffer.then((lateBuffer) => {
          eraseBytes(lateBuffer)
        }, () => {})
        throw error
      }
      if (!(arrayBuffer instanceof ArrayBuffer) && !ArrayBuffer.isView(arrayBuffer)) {
        fail('CONNECTOR_RESPONSE_INVALID', 'response arrayBuffer returned a non-byte value')
      }
      const source = arrayBuffer instanceof ArrayBuffer
        ? new Uint8Array(arrayBuffer)
        : new Uint8Array(arrayBuffer.buffer, arrayBuffer.byteOffset, arrayBuffer.byteLength)
      try {
        if (source.byteLength > MAX_RESPONSE_BYTES) {
          fail('CONNECTOR_RESPONSE_INVALID', 'response body exceeded the size limit')
        }
        const retained = Buffer.from(source)
        chunks.push(retained)
        length += retained.byteLength
      } finally {
        eraseBytes(source)
      }
    }
    combined = Buffer.concat(chunks, length)
    const contentType = response.headers?.get?.('content-type')?.split(';', 1)[0]?.trim().toLowerCase() ?? null
    let data = null
    if (combined.length > 0) {
      if (contentType === 'application/json' || contentType?.endsWith('+json')) {
        try {
          data = JSON.parse(combined.toString('utf8'))
        } catch {
          fail('CONNECTOR_RESPONSE_INVALID', 'response declared JSON but contained invalid JSON')
        }
      } else if (contentType?.startsWith('text/') || contentType === 'application/x-www-form-urlencoded') {
        data = combined.toString('utf8')
      } else {
        data = new Uint8Array(combined)
      }
    }
    completed = true
    return { data, contentType }
  } finally {
    if (!completed && reader !== null) cancelReaderWithoutWaiting(reader)
    eraseBytes(combined)
    for (const chunk of chunks) eraseBytes(chunk)
    chunks.length = 0
    length = 0
  }
}

function projectResponseCredentials(endpoint, data) {
  const sensitivePaths = new Set(endpoint.auth.response_carriers
    .filter((carrier) => carrier.startsWith('body:'))
    .map((carrier) => carrier.slice('body:'.length)))
  if (sensitivePaths.size === 0 || data === null || typeof data !== 'object' || ArrayBuffer.isView(data)) {
    return { data, captures: [] }
  }
  const captures = []
  const visit = (value, prefix = '') => {
    if (Array.isArray(value)) return value.map((child) => visit(child, `${prefix}[]`))
    if (!plain(value)) return value
    const projected = {}
    for (const [name, child] of Object.entries(value)) {
      const path = prefix ? `${prefix}.${name}` : name
      if (sensitivePaths.has(path)) {
        if (captures.length >= MAX_RESPONSE_CREDENTIAL_VALUES) {
          fail('CONNECTOR_RESPONSE_INVALID', 'response contains too many credential values')
        }
        captures.push({ carrier: `body:${path}`, value: child })
        projected[name] = null
      } else {
        projected[name] = visit(child, path)
      }
    }
    return projected
  }
  return { data: visit(data), captures }
}

async function deliverResponseCredentials(receiver, endpoint, status, captures) {
  if (captures.length === 0 || receiver === undefined) return
  const context = deepFreeze({
    contractId: PACKAGE.manifest.contract_id,
    endpointId: endpoint.endpoint_id,
    origin: endpoint.origin,
    status,
    credentials: captures,
  })
  try {
    await receiver(context)
  } catch (error) {
    const wrapped = new Error('response credential receiver failed', { cause: error })
    wrapped.name = 'GeneratedConnectorError'
    wrapped.code = 'CONNECTOR_CREDENTIAL_RECEIVER_FAILED'
    throw wrapped
  }
}

function responseHeaders(headers, endpoint) {
  const result = {}
  if (!headers || typeof headers.entries !== 'function') return result
  const credentialHeaders = new Set([
    ...RESPONSE_CREDENTIAL_HEADERS,
    ...endpoint.auth.response_carriers
      .filter((carrier) => carrier.startsWith('header:'))
      .map((carrier) => carrier.slice('header:'.length).toLowerCase()),
  ])
  let count = 0
  for (const [name, value] of headers.entries()) {
    count += 1
    if (
      count > MAX_HEADER_COUNT
      || !HEADER_NAME.test(name)
      || Buffer.byteLength(value, 'utf8') > MAX_HEADER_VALUE_BYTES
    ) fail('CONNECTOR_RESPONSE_INVALID', 'response headers exceeded the connector bounds')
    const lower = name.toLowerCase()
    if (!credentialHeaders.has(lower) && !sensitiveHeaderName(lower)) result[lower] = value
  }
  return result
}

async function providerValue(provider, endpoint) {
  if (!provider) return undefined
  const context = deepFreeze({
    contractId: PACKAGE.manifest.contract_id,
    endpointId: endpoint.endpoint_id,
    origin: endpoint.origin,
    method: endpoint.method,
    pathTemplate: endpoint.path_template,
    requestCarriers: [...endpoint.auth.request_carriers],
    requestCookieNames: [...endpoint.auth.request_cookie_names],
    protocolRole: endpoint.protocol_role,
  })
  return provider(context)
}

function redirectLocation(response, currentUrl) {
  if (![301, 302, 303, 307, 308].includes(response.status)) return null
  const location = response.headers?.get?.('location')
  if (!location) return null
  if (Buffer.byteLength(location, 'utf8') > MAX_HEADER_VALUE_BYTES) {
    fail('CONNECTOR_REDIRECT_REFUSED', 'response redirect location is too large')
  }
  try { return new URL(location, currentUrl) } catch {
    fail('CONNECTOR_REDIRECT_REFUSED', 'response redirect location is invalid')
  }
}

function redirectedBody(status, sourceEndpoint, body) {
  if (
    (status === 303 && !['GET', 'HEAD'].includes(sourceEndpoint.method))
    || ((status === 301 || status === 302) && sourceEndpoint.method === 'POST')
  ) return undefined
  return body
}

export const manifest = PACKAGE.manifest
export const metadata = PACKAGE.descriptor
export const contractId = PACKAGE.manifest.contract_id
export const endpointIds = deepFreeze([...ENDPOINT_BY_ID.keys()].sort())
export const authFlows = PACKAGE.descriptor.auth_flows

export function createConnector({ credentialProvider, credentialReceiver, fetchImpl = globalThis.fetch } = {}) {
  if (credentialProvider !== undefined && typeof credentialProvider !== 'function') {
    fail('CONNECTOR_OPTION_INVALID', 'credentialProvider must be a function')
  }
  if (credentialReceiver !== undefined && typeof credentialReceiver !== 'function') {
    fail('CONNECTOR_OPTION_INVALID', 'credentialReceiver must be a function')
  }
  if (typeof fetchImpl !== 'function') fail('CONNECTOR_OPTION_INVALID', 'fetchImpl must be a function')
  const jars = new Map()

  async function request(endpointId, options = {}) {
    const ownedByteClones = new Set()
    let requestMayHaveBeenSent = false
    let timer
    let timerCreated = false
    try {
    if (!plain(options)) fail('CONNECTOR_OPTION_INVALID', 'request options must be an object')
    const optionNames = new Set([
      'body', 'contentType', 'cookies', 'headers', 'maxRedirects', 'maxRetries',
      'path', 'query', 'timeoutMs',
    ])
    if (Object.keys(options).some((name) => !optionNames.has(name))) {
      fail('CONNECTOR_OPTION_INVALID', 'request options contain an unknown field')
    }
    const initialEndpoint = ENDPOINT_BY_ID.get(endpointId)
    if (!initialEndpoint) fail('CONNECTOR_ENDPOINT_REFUSED', 'endpoint ID is outside this connector contract')
    const maxRedirects = boundedInteger(options.maxRedirects, 3, MAX_REDIRECTS, 'maxRedirects')
    const maxRetries = boundedInteger(options.maxRetries, 1, MAX_RETRIES, 'maxRetries')
    const timeoutMs = boundedInteger(options.timeoutMs, 30_000, MAX_TIMEOUT_MS, 'timeoutMs')
    if (timeoutMs === 0) fail('CONNECTOR_OPTION_INVALID', 'timeoutMs is invalid')
    const baseHeaders = normalizeHeaders(options.headers, { allowed: callerHeaderNames(initialEndpoint) })
    const baseCookies = assertRecord(options.cookies, 'request cookies')
    const initialOrigin = initialEndpoint.origin
    let endpoint = initialEndpoint
    let url = new URL(fillPath(endpoint.path_template, options.path), endpoint.origin)
    assertPathActionClass(endpoint, url.pathname)
    const query = normalizeQuery(endpoint, options.query)
    url.search = query.toString()
    let callerBody = options.body === undefined
      ? undefined
      : cloneBody(options.body, ownedByteClones)
    let redirects = 0
    let retries = 0
    let attempts = 0
    const controller = new AbortController()
    const clockNow = () => globalThis.performance?.now?.() ?? Date.now()
    const expiresAt = clockNow() + timeoutMs
    let rejectDeadline
    const deadline = new Promise((_resolve, reject) => { rejectDeadline = reject })
    // An ambient timer may invoke its callback before returning or throw after
    // doing so. Observe the deadline immediately so setup failure cannot leave
    // an unhandled rejection behind.
    void deadline.catch(() => {})
    const timeoutError = new Error('connector request timed out')
    timeoutError.name = 'GeneratedConnectorError'
    timeoutError.code = 'CONNECTOR_TIMEOUT'
    timeoutError.request_may_have_been_sent = false
    const ensureDeadline = () => {
      if (!controller.signal.aborted && clockNow() < expiresAt) return
      timeoutError.request_may_have_been_sent = requestMayHaveBeenSent
      if (!controller.signal.aborted) controller.abort(timeoutError)
      throw timeoutError
    }
    const withinDeadline = async (operation) => {
      ensureDeadline()
      const result = await Promise.race([Promise.resolve().then(operation), deadline])
      ensureDeadline()
      return result
    }
    const credentialProviderError = (error) => {
      if (error === timeoutError) return error
      const wrapped = new Error(requestMayHaveBeenSent
        ? 'connector credential provider failed after transport invocation'
        : 'connector credential provider failed')
      wrapped.name = 'GeneratedConnectorError'
      wrapped.code = requestMayHaveBeenSent
        ? 'CONNECTOR_TRANSPORT_FAILED'
        : 'CONNECTOR_CREDENTIAL_PROVIDER_FAILED'
      wrapped.request_may_have_been_sent = requestMayHaveBeenSent
      return wrapped
    }
    const preDispatchError = (error) => {
      if (error === timeoutError) return error
      if (requestMayHaveBeenSent) {
        if (error?.name === 'GeneratedConnectorError') return markRequestMayHaveBeenSent(error)
        const wrapped = new Error('connector preparation failed after transport invocation', { cause: error })
        wrapped.name = 'GeneratedConnectorError'
        wrapped.code = 'CONNECTOR_TRANSPORT_FAILED'
        return markRequestMayHaveBeenSent(wrapped)
      }
      if (error?.name === 'GeneratedConnectorError') {
        if (Object.isExtensible(error)) error.request_may_have_been_sent = false
        return error
      }
      const wrapped = new Error('connector credential provider failed', { cause: error })
      wrapped.name = 'GeneratedConnectorError'
      wrapped.code = 'CONNECTOR_CREDENTIAL_PROVIDER_FAILED'
      wrapped.request_may_have_been_sent = false
      return wrapped
    }

    try {
      try {
        timer = setTimeout(() => {
          timeoutError.request_may_have_been_sent = requestMayHaveBeenSent
          controller.abort(timeoutError)
          rejectDeadline(timeoutError)
        }, timeoutMs)
        timerCreated = true
      } catch {
        const timerError = new Error('connector request could not start its deadline timer')
        timerError.name = 'GeneratedConnectorError'
        timerError.code = 'CONNECTOR_TIMER_FAILED'
        timerError.request_may_have_been_sent = false
        throw timerError
      }
      while (true) {
        attempts += 1
        let providedCredentials
        try {
          providedCredentials = await withinDeadline(() => providerValue(credentialProvider, endpoint))
        } catch (error) {
          throw credentialProviderError(error)
        }
        let headers
        let encoded
        try {
          const suppliedCredentials = validateCredentials(
            endpoint,
            providedCredentials,
            ownedByteClones,
          )
          const allowedCallerHeaders = callerHeaderNames(endpoint)
          const callerHeaders = endpoint.origin === initialOrigin
            ? Object.fromEntries(Object.entries(baseHeaders).filter(([name]) => allowedCallerHeaders.has(name)))
            : {}
          headers = {
            ...callerHeaders,
            ...suppliedCredentials.headers,
          }
          const cookies = requestCookies(jars, endpoint, url, {
            ...(endpoint.origin === initialOrigin ? baseCookies : {}),
            ...suppliedCredentials.cookies,
          })
          if (Object.keys(cookies).length > 0) headers.cookie = cookieHeader(cookies)
          const mergedBody = mergeBody(callerBody, suppliedCredentials.body, ownedByteClones)
          if (mergedBody !== undefined && ['GET', 'HEAD'].includes(endpoint.method)) {
            fail('CONNECTOR_INPUT_INVALID', 'GET and HEAD endpoints cannot carry a request body')
          }
          encoded = encodeBody(endpoint, mergedBody, options.contentType)
          if (encoded.body instanceof Uint8Array) ownedByteClones.add(encoded.body)
          if (encoded.contentType !== null) headers['content-type'] = encoded.contentType
          if (Object.keys(headers).length > MAX_HEADER_COUNT) {
            fail('CONNECTOR_INPUT_INVALID', 'request contains too many headers')
          }
        } catch (error) {
          throw preDispatchError(error)
        }
        try {
          const response = await withinDeadline(() => {
            requestMayHaveBeenSent = true
            return fetchImpl(url, {
              method: endpoint.method,
              headers,
              body: ['GET', 'HEAD'].includes(endpoint.method) ? undefined : encoded.body,
              redirect: 'manual',
              signal: controller.signal,
            })
          })
          const responseView = await withinDeadline(() => {
            const status = response?.status
            const headers = response?.headers
            const body = response?.body
            const arrayBufferMethod = response?.arrayBuffer
            if (!Number.isSafeInteger(status) || status < 100 || status > 999) {
              fail('CONNECTOR_RESPONSE_INVALID', 'connector transport returned an invalid response')
            }
            return {
              status,
              headers,
              body,
              arrayBuffer: typeof arrayBufferMethod === 'function'
                ? arrayBufferMethod.bind(response)
                : undefined,
            }
          })
          await withinDeadline(() => rememberCookies(jars, endpoint, responseView.headers, url))

        if (
          (responseView.status === 429 || responseView.status >= 500)
          && retries < maxRetries
          && endpoint.retry === 'RETRY_SEQUENCE_OBSERVED'
          && endpoint.side_effect.classification === 'READ_CANDIDATE'
          && AUTOMATIC_RETRY_METHODS.has(endpoint.method)
        ) {
          retries += 1
          await withinDeadline(() => responseView.body?.cancel?.()).catch((error) => {
            if (error === timeoutError || controller.signal.aborted) throw error
          })
          continue
        }

        const location = await withinDeadline(() => redirectLocation(responseView, url))
        if (location !== null) {
          if (redirects >= maxRedirects) fail('CONNECTOR_REDIRECT_REFUSED', 'redirect limit exceeded')
          const nextEndpoint = await withinDeadline(
            () => endpointForRedirect(endpoint, location, responseView.status),
          )
          await withinDeadline(() => assertPathActionClass(
            nextEndpoint,
            location.pathname,
            'CONNECTOR_REDIRECT_REFUSED',
          ))
          const nextBody = redirectedBody(responseView.status, endpoint, callerBody)
          redirects += 1
          await withinDeadline(() => responseView.body?.cancel?.()).catch((error) => {
            if (error === timeoutError || controller.signal.aborted) throw error
          })
          endpoint = nextEndpoint
          url = location
          callerBody = nextBody
          continue
        }

        const parsed = await withinDeadline(() => readResponse(responseView, { withinDeadline }))
        const projected = await withinDeadline(
          () => projectResponseCredentials(endpoint, parsed.data),
        )
        await withinDeadline(
          () => deliverResponseCredentials(
            credentialReceiver,
            endpoint,
            responseView.status,
            projected.captures,
          ),
        )
        const visibleHeaders = await withinDeadline(
          () => responseHeaders(responseView.headers, endpoint),
        )
        const result = await withinDeadline(() => deepFreeze({
          endpointId: endpoint.endpoint_id,
          origin: endpoint.origin,
          pathTemplate: endpoint.path_template,
          status: responseView.status,
          ok: responseView.status >= 200 && responseView.status < 300,
          headers: visibleHeaders,
          contentType: parsed.contentType,
          data: projected.data,
          attempts,
          redirects,
          retries,
        }))
        return result
        } catch (error) {
          if (error === timeoutError) throw error
          if (controller.signal.aborted) {
            const timeout = new Error('connector request timed out')
            timeout.name = 'GeneratedConnectorError'
            timeout.code = 'CONNECTOR_TIMEOUT'
            timeout.request_may_have_been_sent = true
            throw timeout
          }
          if (error?.name === 'GeneratedConnectorError') {
            throw markRequestMayHaveBeenSent(error)
          }
          const wrapped = new Error('connector transport failed', { cause: error })
          wrapped.name = 'GeneratedConnectorError'
          wrapped.code = 'CONNECTOR_TRANSPORT_FAILED'
          wrapped.request_may_have_been_sent = true
          throw wrapped
        }
      }
    } finally {
      if (timerCreated) {
        try {
          clearTimeout(timer)
        } catch {
          // The request outcome is authoritative. Timer cleanup cannot
          // replace it or prevent transient request-body erasure.
        }
      }
    }
    } catch (error) {
      if (error?.name === 'GeneratedConnectorError') {
        if (requestMayHaveBeenSent) throw markRequestMayHaveBeenSent(error)
        if (Object.isExtensible(error)) error.request_may_have_been_sent = false
        throw error
      }
      const wrapped = new Error(
        requestMayHaveBeenSent
          ? 'connector request failed after transport invocation'
          : 'connector request preparation failed',
        { cause: error },
      )
      wrapped.name = 'GeneratedConnectorError'
      wrapped.code = requestMayHaveBeenSent
        ? 'CONNECTOR_TRANSPORT_FAILED'
        : 'CONNECTOR_PREPARATION_FAILED'
      wrapped.request_may_have_been_sent = requestMayHaveBeenSent
      throw wrapped
    } finally {
      for (const bytes of ownedByteClones) {
        eraseBytes(bytes)
      }
      ownedByteClones.clear()
    }
  }

  function clearCookies(origin) {
    if (origin === undefined) jars.clear()
    else if (!PACKAGE.descriptor.subjects.origins.includes(origin)) {
      fail('CONNECTOR_ENDPOINT_REFUSED', 'cookie origin is outside this connector contract')
    } else jars.delete(origin)
  }

  return Object.freeze({
    contractId,
    endpointIds,
    authFlows,
    request,
    clearCookies,
  })
}
