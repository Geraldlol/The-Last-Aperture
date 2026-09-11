import { createHash } from 'node:crypto'

import { legacyV1CredentialCookieName } from './reverse-v1-compat-semantics.mjs'
import { stableJson } from './run-engine.mjs'

export const WEB_SESSION_EVIDENCE_KIND = 'red-team-audit/web-session-evidence'
export const WEB_SESSION_EVIDENCE_PROTOCOL = 'web-session-evidence-v1'
export const WEB_SESSION_SOURCE_KINDS = Object.freeze(['BURP_XML', 'HAR'])

const HASH = /^[a-f0-9]{64}$/u
const HTTP_METHOD = /^[!#$%&'*+.^_`|~0-9A-Z-]{1,32}$/u
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9a-z-]{1,128}$/u
const FIELD_NAME = /^[A-Za-z0-9_$@.:[\]-]{1,128}$/u
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/u
const MAX_ENTRIES = 10_000
const MAX_FIELDS = 1_024
const MAX_PARAMETER_PAIRS = 4_096
const MAX_BODY_BYTES = 1024 * 1024
const MAX_HEADER_NAMES = 512
const MAX_COOKIE_NAMES = 512
const MAX_CREDENTIAL_CARRIERS = 2_048
const MAX_DESTINATIONS = 64
const MAX_AGGREGATE_METADATA_ITEMS = 100_000
const EVIDENCE_LIMITS = Object.freeze({
  max_aggregate_metadata_items: MAX_AGGREGATE_METADATA_ITEMS,
  max_body_bytes: MAX_BODY_BYTES,
  max_cookie_names: MAX_COOKIE_NAMES,
  max_credential_carriers: MAX_CREDENTIAL_CARRIERS,
  max_destinations: MAX_DESTINATIONS,
  max_entries: MAX_ENTRIES,
  max_fields: MAX_FIELDS,
  max_header_names: MAX_HEADER_NAMES,
  max_parameter_pairs: MAX_PARAMETER_PAIRS,
})
const VALUE_TYPES = new Set(['array', 'boolean', 'integer', 'null', 'number', 'object', 'string', 'unknown'])
const BODY_FORMATS = new Set(['FORM', 'JSON', 'MULTIPART', 'NONE', 'OPAQUE'])
const BODY_SHAPE_STATUSES = new Set(['MALFORMED', 'NOT_OBSERVED', 'OBSERVED', 'OMITTED_SIZE_LIMIT'])
const BYTE_BUCKETS = new Set(['EMPTY', 'LE_1_KIB', 'LE_4_KIB', 'LE_16_KIB', 'LE_64_KIB', 'LE_256_KIB', 'LE_1_MIB', 'OVER_1_MIB', 'UNKNOWN'])
const CREDENTIAL_HEADERS = new Set(['authorization', 'proxy-authorization', 'x-api-key', 'x-auth-token', 'x-csrf-token', 'x-session-token', 'x-xsrf-token'])
const CREDENTIAL_CARRIER = /^(?:body:[A-Za-z0-9_$@.:[\]-]{1,1024}|cookie:[A-Za-z0-9_$@.:[\]-]{1,128}|header:[!#$%&'*+.^_`|~0-9a-z-]{1,128})$/u
const SENSITIVE_NAME = /(?:api[_-]?key|auth|bearer|client[_-]?secret|connection|credential|csrf|jwt|login|pass(?:word|wd)?|secret|session|ssn|token|user(?:name)?|xsrf)/iu
const CREDENTIAL_COOKIE_TOKENS = new Set(['auth', 'authentication', 'bearer', 'credential', 'csrf', 'jwt', 'session', 'sid', 'token', 'xsrf'])
const CREDENTIAL_COOKIE_COMPOUND_TOKEN = /^(?:(?:auth|session)(?:cookie|id)?|(?:access|auth|bearer|csrf|id|refresh|session|xsrf)token|sessid)$/iu
const CREDENTIAL_COOKIE_EXACT = new Set(['aspxauth', 'connect.sid', 'fedauth', 'jsessionid', 'phpsessid'])
const SEMANTIC_NAME = /^(?:action|command|event|method|mode|op|operation|submit|task|view)$/iu
const SEMANTIC_VALUE = /^[A-Za-z][A-Za-z0-9_.:-]{0,63}$/u
const WRITE_ACTION = /^(?:add|approve|archive|assign|begin|cancel|close|commit|confirm|connect|create|delete|disable|disconnect|edit|enable|end|execute|import|insert|link|merge|move|patch|pay|post|publish|put|remove|reset|revoke|save|send|set|start|stop|submit|sync|update|upload|write)$/iu
const READ_ACTION = /^(?:browse|detail|download|export|fetch|find|get|index|list|load|lookup|open|preview|query|read|report|retrieve|search|show|view)$/iu
const PATH_ACTION_CLASSES = new Set(['NONE', 'OTHER_ACTION', 'READ_ACTION', 'WRITE_ACTION'])
const TEMPLATE_SEGMENTS = new Set(['{hex}', '{integer}', '{segment}', '{uuid}', '{value}'])
const DEFAULT_PATH_LITERALS = new Set([
  'api', 'auth', 'callback', 'login', 'logout', 'oauth', 'session', 'signin', 'signout', 'sso', 'token',
])
const REDACTED_FIELD_NAME = 'redacted_name'
const REDACTED_HEADER_NAME = 'x-redacted-name'
const SOURCE_KINDS = new Set(WEB_SESSION_SOURCE_KINDS)
const SCHEMA_VERSIONS = new Set(['1.0.0', '1.1.0'])

function fail(message) {
  const error = new Error(message)
  error.name = 'WebSessionEvidenceError'
  error.code = 'WEB_SESSION_EVIDENCE_INVALID'
  throw error
}

function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
}

function exact(value, fields, label) {
  if (!plain(value)) fail(`${label} must be an object`)
  const actual = Object.keys(value).sort()
  const expected = [...fields].sort()
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) fail(`${label} contains a missing or unknown field`)
}

function text(value, label, maximum = 2048) {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum || value.trim() !== value || CONTROL.test(value)) fail(`${label} must be bounded plain text`)
  return value
}

function name(value, label = 'field name') {
  if (typeof value !== 'string' || !FIELD_NAME.test(value) || CONTROL.test(value)) fail(`${label} is invalid`)
  return value
}

function valueLikeName(value) {
  return /^[^@]+@[^@]+$/u.test(value)
    || /^\d{3}-\d{2}-\d{4}$/u.test(value)
    || /^\d{4}-\d{2}-\d{2}$/u.test(value)
    || /^\d+(?:[.-]\d+){2,}$/u.test(value)
    || /^\d+$/u.test(value)
    || /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value)
    || /^[0-9a-f]{16,}$/iu.test(value)
    || /^(?=.{24,}$)(?=.*(?:\d|[_-]))[A-Za-z0-9_-]+={0,2}$/u.test(value)
    || /^(?:[A-Za-z0-9_-]{6,}\.){2}[A-Za-z0-9_-]{6,}$/u.test(value)
}

function sanitizedName(value, label = 'field name') {
  if (typeof value !== 'string') fail(`${label} is invalid`)
  return !FIELD_NAME.test(value) || CONTROL.test(value) || valueLikeName(value)
    ? REDACTED_FIELD_NAME
    : value
}

function credentialCookieName(value) {
  const normalized = value.toLowerCase().replace(/^[._-]+|[._-]+$/gu, '')
  if (CREDENTIAL_COOKIE_EXACT.has(normalized)) return true
  return normalized
    .split(/[._-]+/u)
    .some((token) => CREDENTIAL_COOKIE_TOKENS.has(token) || CREDENTIAL_COOKIE_COMPOUND_TOKEN.test(token))
}

function pathActionClass(pathname) {
  let read = false
  for (const segment of pathname.split('/').filter(Boolean)) {
    let decoded
    try { decoded = decodeURIComponent(segment) } catch { continue }
    if (!SEMANTIC_VALUE.test(decoded)) continue
    if (WRITE_ACTION.test(decoded)) return 'WRITE_ACTION'
    if (READ_ACTION.test(decoded)) read = true
  }
  if (read) return 'READ_ACTION'
  return 'NONE'
}

function pathContainsValueLikeName(path) {
  return path.split('.').some((part) => valueLikeName(part.replaceAll('[]', '')))
}

function lexical(left, right) {
  return left < right ? -1 : left > right ? 1 : 0
}

function unique(values) {
  return [...new Set(values)].sort(lexical)
}

function canonicalList(values, predicate = () => true) {
  return Array.isArray(values)
    && values.every(predicate)
    && values.every((value, index) => index === 0 || lexical(values[index - 1], value) < 0)
}

function origin(value) {
  text(value, 'target origin')
  let parsed
  try { parsed = new URL(value) } catch { fail('target origin is invalid') }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash || parsed.origin !== value) fail('target origin must be one canonical HTTP or HTTPS origin')
  return parsed.origin
}

function mediaType(value) {
  if (typeof value !== 'string') return null
  const result = value.split(';', 1)[0].trim().toLowerCase()
  return /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/u.test(result) ? result : null
}

function valueType(value) {
  if (value === null) return 'null'
  if (Array.isArray(value)) return 'array'
  if (plain(value)) return 'object'
  if (typeof value === 'boolean') return 'boolean'
  if (typeof value === 'number') return Number.isInteger(value) ? 'integer' : 'number'
  if (typeof value !== 'string') return 'unknown'
  if (/^(?:true|false)$/iu.test(value)) return 'boolean'
  if (/^-?(?:0|[1-9][0-9]*)$/u.test(value)) return 'integer'
  if (/^-?(?:0|[1-9][0-9]*)\.[0-9]+$/u.test(value)) return 'number'
  if (/^(?:null|undefined)$/iu.test(value)) return 'null'
  return 'string'
}

function bucket(value) {
  if (!Number.isFinite(value) || value < 0) return 'UNKNOWN'
  if (value === 0) return 'EMPTY'
  for (const [maximum, label] of [[1024, 'LE_1_KIB'], [4096, 'LE_4_KIB'], [16384, 'LE_16_KIB'], [65536, 'LE_64_KIB'], [262144, 'LE_256_KIB'], [MAX_BODY_BYTES, 'LE_1_MIB']]) if (value <= maximum) return label
  return 'OVER_1_MIB'
}

function templateSegment(segment, pathLiterals) {
  if (segment === '' || TEMPLATE_SEGMENTS.has(segment)) return segment
  if (/^-?[0-9]+$/u.test(segment)) return '{integer}'
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(segment)) return '{uuid}'
  if (/^[0-9a-f]{16,}$/iu.test(segment)) return '{hex}'
  if (/^(?=.{20,}$)[A-Za-z0-9_-]+={0,2}$/u.test(segment) || /%|@/u.test(segment)) return '{value}'
  if (/^v[0-9]+$/iu.test(segment) || DEFAULT_PATH_LITERALS.has(segment.toLowerCase()) || pathLiterals.has(segment)) return segment
  return '{segment}'
}

export function webPathTemplate(pathname, { pathLiterals = [] } = {}) {
  if (typeof pathname !== 'string' || !pathname.startsWith('/') || pathname.length > 2048 || CONTROL.test(pathname)) fail('web path is invalid')
  const declared = new Set(pathLiterals)
  return pathname.split('/').map((segment) => templateSegment(segment, declared)).join('/')
}

function parameters(values) {
  const found = new Map()
  let pairs = 0
  for (const [rawName, value] of values) {
    pairs += 1
    if (pairs > MAX_PARAMETER_PAIRS) fail('parameter pair limit exceeded')
    const fieldName = sanitizedName(rawName, 'parameter name')
    const item = found.get(fieldName) ?? { types: new Set(), semanticClasses: new Set() }
    item.types.add(valueType(value))
    if (SEMANTIC_NAME.test(fieldName) && typeof value === 'string' && SEMANTIC_VALUE.test(value)) {
      item.semanticClasses.add(WRITE_ACTION.test(value) ? 'WRITE_ACTION' : READ_ACTION.test(value) ? 'READ_ACTION' : 'OTHER_ACTION')
    }
    found.set(fieldName, item)
    if (found.size > MAX_FIELDS) fail('parameter field limit exceeded')
  }
  return [...found].map(([fieldName, item]) => ({
    name: fieldName,
    types: [...item.types].sort(lexical),
    sensitive: SENSITIVE_NAME.test(fieldName),
    semantic_classes: [...item.semanticClasses].sort(lexical),
  })).sort((a, b) => lexical(a.name, b.name))
}

function readHeaders(items) {
  if (items === undefined) return { names: [], values: new Map() }
  if (!Array.isArray(items) || items.length > MAX_HEADER_NAMES) fail('web capture headers are invalid')
  const names = []
  const values = new Map()
  for (const item of items) {
    if (!plain(item) || typeof item.name !== 'string') fail('web capture header is invalid')
    const rawName = item.name.toLowerCase()
    if (rawName.startsWith(':')) continue
    if (!HEADER_NAME.test(rawName)) fail('web capture header name is invalid')
    const fieldName = valueLikeName(rawName) ? REDACTED_HEADER_NAME : rawName
    names.push(fieldName)
    if (typeof item.value === 'string' && item.value.length <= 65536) values.set(fieldName, [...(values.get(fieldName) ?? []), item.value])
  }
  return { names: unique(names), values }
}

function readCookieNames(items, headerValues, response = false) {
  const result = new Set()
  const add = (value) => {
    result.add(sanitizedName(value, 'cookie name'))
    if (result.size > MAX_COOKIE_NAMES) fail('web capture cookie name limit exceeded')
  }
  if (items !== undefined) {
    if (!Array.isArray(items) || items.length > MAX_COOKIE_NAMES) fail('web capture cookies are invalid')
    for (const item of items) if (plain(item) && typeof item.name === 'string') add(item.name)
  }
  const header = response ? 'set-cookie' : 'cookie'
  for (const value of headerValues.get(header) ?? []) {
    for (const part of response ? [value.split(';', 1)[0]] : value.split(';')) {
      const separator = part.indexOf('=')
      const candidate = separator > 0 ? part.slice(0, separator).trim() : ''
      if (FIELD_NAME.test(candidate)) add(candidate)
    }
  }
  return [...result].sort(lexical)
}

function addField(map, path, fieldName, value) {
  if (map.size >= MAX_FIELDS && !map.has(path)) return false
  const item = map.get(path) ?? { name: fieldName, path, types: new Set(), sensitive: SENSITIVE_NAME.test(fieldName), semantic_classes: new Set() }
  item.types.add(valueType(value))
  if (typeof value === 'string' && SEMANTIC_NAME.test(fieldName) && SEMANTIC_VALUE.test(value)) item.semantic_classes.add(WRITE_ACTION.test(value) ? 'WRITE_ACTION' : READ_ACTION.test(value) ? 'READ_ACTION' : 'OTHER_ACTION')
  map.set(path, item)
  return true
}

function walkJson(value, map, state, path = '', depth = 0) {
  if (depth > 8) {
    if ((Array.isArray(value) && value.length > 0) || (plain(value) && Object.keys(value).length > 0)) state.truncated = true
    return
  }
  if (Array.isArray(value)) {
    if (value.length > 32) state.truncated = true
    for (const child of value.slice(0, 32)) walkJson(child, map, state, `${path}[]`, depth + 1)
    return
  }
  if (!plain(value)) return
  const entries = Object.entries(value)
  if (entries.length > MAX_FIELDS) state.truncated = true
  for (const [rawFieldName, child] of entries.slice(0, MAX_FIELDS)) {
    const fieldName = sanitizedName(rawFieldName)
    const childPath = path ? `${path}.${fieldName}` : fieldName
    if (childPath.length > 1024 || !addField(map, childPath, fieldName, child)) {
      state.truncated = true
      continue
    }
    walkJson(child, map, state, childPath, depth + 1)
  }
}

function finishFields(map) {
  return [...map.values()].map((item) => ({ ...item, types: [...item.types].sort(lexical), semantic_classes: [...item.semantic_classes].sort(lexical) })).sort((a, b) => lexical(a.path, b.path))
}

function body(postData, fallbackMime) {
  if (!plain(postData)) return { format: 'NONE', content_type: mediaType(fallbackMime), byte_bucket: 'EMPTY', shape_status: 'NOT_OBSERVED', fields_truncated: false, fields: [] }
  const mime = mediaType(postData.mimeType) ?? mediaType(fallbackMime)
  const rawText = typeof postData.text === 'string' ? postData.text : null
  const params = Array.isArray(postData.params) ? postData.params : null
  if (params !== null && params.length > MAX_PARAMETER_PAIRS) fail('body parameter pair limit exceeded')
  const declaredSize = Number.isFinite(postData.size) && postData.size >= 0
    ? postData.size
    : null
  let measured = declaredSize ?? (rawText === null ? 0 : Buffer.byteLength(rawText, 'utf8'))
  let format = 'OPAQUE'
  if (mime === 'application/json' || mime?.endsWith('+json')) format = 'JSON'
  else if (mime === 'application/x-www-form-urlencoded') format = 'FORM'
  else if (mime?.startsWith('multipart/')) format = 'MULTIPART'
  const fields = new Map()
  const state = { truncated: false }
  let shapeStatus = 'NOT_OBSERVED'
  if (format === 'JSON' && rawText !== null) {
    if (measured > MAX_BODY_BYTES) shapeStatus = 'OMITTED_SIZE_LIMIT'
    else {
      try {
        walkJson(JSON.parse(rawText), fields, state)
        shapeStatus = 'OBSERVED'
      } catch {
        shapeStatus = 'MALFORMED'
      }
    }
  } else if ((format === 'FORM' || format === 'MULTIPART') && params !== null) {
    shapeStatus = measured > MAX_BODY_BYTES ? 'OMITTED_SIZE_LIMIT' : 'OBSERVED'
    for (const item of params) {
      if (shapeStatus === 'OMITTED_SIZE_LIMIT') break
      if (rawText === null && declaredSize === null) {
        measured += Buffer.byteLength(String(item?.value ?? ''), 'utf8')
        if (measured > MAX_BODY_BYTES) {
          fields.clear()
          state.truncated = false
          shapeStatus = 'OMITTED_SIZE_LIMIT'
          break
        }
      }
      if (!plain(item) || typeof item.name !== 'string') continue
      const fieldName = sanitizedName(item.name, 'body field name')
      if (!addField(fields, fieldName, fieldName, typeof item.value === 'string' ? item.value : '')) state.truncated = true
    }
  } else if (format === 'FORM' && rawText !== null) {
    if (measured > MAX_BODY_BYTES) shapeStatus = 'OMITTED_SIZE_LIMIT'
    else {
      shapeStatus = 'OBSERVED'
      let pairs = 0
      for (const [rawFieldName, value] of new URLSearchParams(rawText)) {
        pairs += 1
        if (pairs > MAX_PARAMETER_PAIRS) fail('body parameter pair limit exceeded')
        const fieldName = sanitizedName(rawFieldName, 'body field name')
        if (!addField(fields, fieldName, fieldName, value)) state.truncated = true
      }
    }
  }
  return { format, content_type: mime, byte_bucket: bucket(measured), shape_status: shapeStatus, fields_truncated: state.truncated, fields: finishFields(fields) }
}

function responseBody(content) {
  if (!plain(content)) return { format: 'NONE', content_type: null, byte_bucket: 'UNKNOWN', shape_status: 'NOT_OBSERVED', fields_truncated: false, fields: [] }
  const mime = mediaType(content.mimeType)
  const rawText = typeof content.text === 'string' ? content.text : null
  const measured = Number.isFinite(content.size) && content.size >= 0 ? content.size : rawText === null ? null : Buffer.byteLength(rawText, 'utf8')
  const fields = new Map()
  const state = { truncated: false }
  let shapeStatus = 'NOT_OBSERVED'
  let format = measured === 0 ? 'NONE' : 'OPAQUE'
  if (mime === 'application/json' || mime?.endsWith('+json')) {
    format = 'JSON'
    if (rawText !== null) {
      if ((measured !== null && measured > MAX_BODY_BYTES) || Buffer.byteLength(rawText, 'utf8') > MAX_BODY_BYTES) shapeStatus = 'OMITTED_SIZE_LIMIT'
      else {
        try {
          walkJson(JSON.parse(rawText), fields, state)
          shapeStatus = 'OBSERVED'
        } catch {
          shapeStatus = 'MALFORMED'
        }
      }
    }
  }
  return { format, content_type: mime, byte_bucket: measured === null ? 'UNKNOWN' : bucket(measured), shape_status: shapeStatus, fields_truncated: state.truncated, fields: finishFields(fields) }
}

function responseDestinations(content, scope, pathLiterals, baseUrl) {
  if (!plain(content) || typeof content.text !== 'string' || Buffer.byteLength(content.text, 'utf8') > MAX_BODY_BYTES) return { values: [], truncated: false }
  const mime = mediaType(content.mimeType)
  if (!(mime === 'application/json' || mime?.endsWith('+json'))) return { values: [], truncated: false }
  let root
  try { root = JSON.parse(content.text) } catch { return { values: [], truncated: false } }
  const found = new Map()
  const state = { truncated: false }
  const visit = (value, path = '', depth = 0) => {
    if (depth > 8) {
      if ((Array.isArray(value) && value.length > 0) || (plain(value) && Object.keys(value).length > 0)) state.truncated = true
      return
    }
    if (Array.isArray(value)) {
      if (value.length > 32) state.truncated = true
      value.slice(0, 32).forEach((child) => visit(child, `${path}[]`, depth + 1))
      return
    }
    if (!plain(value)) return
    const entries = Object.entries(value)
    if (entries.length > MAX_FIELDS) state.truncated = true
    for (const [rawFieldName, child] of entries.slice(0, MAX_FIELDS)) {
      const fieldName = sanitizedName(rawFieldName)
      const fieldPath = path ? `${path}.${fieldName}` : fieldName
      if (fieldPath.length > 1024) {
        state.truncated = true
        continue
      }
      if (
        typeof child === 'string'
        && child.length > 0
        && child.length <= 8192
        && child.trim() === child
        && !CONTROL.test(child)
        && /(?:location|redirect|uri|url)$/iu.test(rawFieldName)
      ) {
        let parsed
        try { parsed = new URL(child, baseUrl) } catch { parsed = null }
        if (parsed && ['http:', 'https:'].includes(parsed.protocol) && scope.has(parsed.origin)) {
          const item = {
            field_path: fieldPath,
            origin: parsed.origin,
            path_template: webPathTemplate(parsed.pathname, { pathLiterals }),
            query_parameters: parameters(parsed.searchParams),
          }
          const key = `${item.field_path}\n${item.origin}\n${item.path_template}`
          if (found.has(key) || found.size < MAX_DESTINATIONS) found.set(key, item)
          else state.truncated = true
        }
      }
      visit(child, fieldPath, depth + 1)
    }
  }
  visit(root)
  return {
    values: [...found.values()].sort((a, b) => lexical(`${a.field_path}\n${a.origin}\n${a.path_template}`, `${b.field_path}\n${b.origin}\n${b.path_template}`)),
    truncated: state.truncated,
  }
}

function carriers(headerNames, cookies, bodyShape, cookieClassifier = credentialCookieName) {
  const result = unique([
    ...headerNames.filter((item) => CREDENTIAL_HEADERS.has(item)).map((item) => `header:${item}`),
    ...cookies.filter(cookieClassifier).map((item) => `cookie:${item}`),
    ...bodyShape.fields.filter((item) => item.sensitive).map((item) => `body:${item.path}`),
  ])
  if (result.length > MAX_CREDENTIAL_CARRIERS) fail('credential carrier limit exceeded')
  return result
}

function redirect(values, scope, pathLiterals, baseUrl) {
  const raw = values.at(-1)
  if (typeof raw !== 'string' || raw.length > 8192 || CONTROL.test(raw)) return null
  let parsed
  try { parsed = new URL(raw, baseUrl) } catch { return null }
  if (!scope.has(parsed.origin) || !['http:', 'https:'].includes(parsed.protocol)) return null
  return { origin: parsed.origin, path_template: webPathTemplate(parsed.pathname, { pathLiterals }), query_parameters: parameters(parsed.searchParams) }
}

function sanitizeEntry(entry, sequence, scope, sourceSha256, pathLiterals) {
  if (
    !plain(entry)
    || !plain(entry.request)
    || !plain(entry.response)
    || typeof entry.request.url !== 'string'
    || entry.request.url.length > 262_144
    || CONTROL.test(entry.request.url)
  ) return { skip: 'malformed' }
  let url
  try { url = new URL(entry.request.url) } catch { return { skip: 'non_http' } }
  if (!['http:', 'https:'].includes(url.protocol)) return { skip: 'non_http' }
  if (!scope.has(url.origin)) return { skip: 'off_scope' }
  const method = typeof entry.request.method === 'string' ? entry.request.method.toUpperCase() : ''
  if (!HTTP_METHOD.test(method)) return { skip: 'malformed' }
  const requestHeaders = readHeaders(entry.request.headers)
  const requestCookies = readCookieNames(entry.request.cookies, requestHeaders.values)
  const requestBody = body(entry.request.postData, requestHeaders.values.get('content-type')?.at(-1))
  const responseHeaders = readHeaders(entry.response.headers)
  const responseCookies = readCookieNames(entry.response.cookies, responseHeaders.values, true)
  const responseShape = responseBody(entry.response.content)
  const destinations = responseDestinations(entry.response.content, scope, pathLiterals, url)
  const status = Number(entry.response.status)
  if (!Number.isSafeInteger(status) || status < 0 || status > 999) return { skip: 'malformed' }
  const pathTemplate = webPathTemplate(url.pathname, { pathLiterals })
  const actionClass = pathActionClass(url.pathname)
  const observationId = createHash('sha256').update(`${sourceSha256}\n${sequence}\n${method}\n${url.origin}\n${pathTemplate}\n${actionClass}`).digest('hex').slice(0, 32)
  let observedAt = null
  if (typeof entry.startedDateTime === 'string' && !Number.isNaN(Date.parse(entry.startedDateTime))) observedAt = new Date(entry.startedDateTime).toISOString()
  const totalMs = Number(entry.time)
  return { value: {
    observation_id: `webobs:${observationId}`,
    sequence,
    observed_at: observedAt,
    request: {
      method,
      origin: url.origin,
      path_template: pathTemplate,
      path_action_class: actionClass,
      query_parameters: parameters(url.searchParams),
      header_names: requestHeaders.names,
      cookie_names: requestCookies,
      credential_carriers: carriers(requestHeaders.names, requestCookies, requestBody),
      body: requestBody,
    },
    response: {
      status,
      header_names: responseHeaders.names,
      cookie_names: responseCookies,
      credential_carriers: carriers(responseHeaders.names, responseCookies, responseShape),
      redirect: redirect(responseHeaders.values.get('location') ?? [], scope, pathLiterals, url),
      destinations: destinations.values,
      destinations_truncated: destinations.truncated,
      body: responseShape,
    },
    total_ms: Number.isFinite(totalMs) && totalMs >= 0 ? Math.min(Math.round(totalMs), 86_400_000) : null,
  } }
}

function assertParameter(item, label) {
  exact(item, ['name', 'semantic_classes', 'sensitive', 'types'], label)
  name(item.name, `${label} name`)
  if (valueLikeName(item.name)) fail(`${label} contains a value-like name`)
  if (item.sensitive !== SENSITIVE_NAME.test(item.name) || !canonicalList(item.types, (type) => VALUE_TYPES.has(type)) || item.types.length < 1 || item.types.length > VALUE_TYPES.size) fail(`${label} is invalid`)
  if (!canonicalList(item.semantic_classes, (value) => ['OTHER_ACTION', 'READ_ACTION', 'WRITE_ACTION'].includes(value)) || (!SEMANTIC_NAME.test(item.name) && item.semantic_classes.length > 0)) fail(`${label} semantic classes are invalid`)
}

function assertBody(item, label) {
  exact(item, ['byte_bucket', 'content_type', 'fields', 'fields_truncated', 'format', 'shape_status'], label)
  if (!BODY_FORMATS.has(item.format) || !BYTE_BUCKETS.has(item.byte_bucket) || !(item.content_type === null || (typeof item.content_type === 'string' && mediaType(item.content_type) === item.content_type))) fail(`${label} is invalid`)
  if (!BODY_SHAPE_STATUSES.has(item.shape_status) || typeof item.fields_truncated !== 'boolean') fail(`${label} shape status is invalid`)
  if (!Array.isArray(item.fields) || item.fields.length > MAX_FIELDS) fail(`${label} field limit exceeded`)
  if (item.shape_status !== 'OBSERVED' && (item.fields.length > 0 || item.fields_truncated)) fail(`${label} unavailable shape cannot contain fields`)
  if (item.shape_status === 'OBSERVED' && !['FORM', 'JSON', 'MULTIPART'].includes(item.format)) fail(`${label} observed shape format is invalid`)
  if (item.shape_status === 'OMITTED_SIZE_LIMIT' && item.byte_bucket !== 'OVER_1_MIB') fail(`${label} size omission does not match its byte bucket`)
  if (item.shape_status === 'MALFORMED' && item.format !== 'JSON') fail(`${label} malformed shape format is invalid`)
  for (const field of item.fields) {
    exact(field, ['name', 'path', 'semantic_classes', 'sensitive', 'types'], `${label} field`)
    name(field.name, `${label} field name`)
    text(field.path, `${label} field path`, 1024)
    if (valueLikeName(field.name) || pathContainsValueLikeName(field.path)) fail(`${label} field contains a value-like name`)
    if (field.sensitive !== SENSITIVE_NAME.test(field.name) || !canonicalList(field.types, (type) => VALUE_TYPES.has(type)) || field.types.length < 1 || field.types.length > VALUE_TYPES.size) fail(`${label} field is invalid`)
    if (!canonicalList(field.semantic_classes, (value) => ['OTHER_ACTION', 'READ_ACTION', 'WRITE_ACTION'].includes(value)) || (!SEMANTIC_NAME.test(field.name) && field.semantic_classes.length > 0)) fail(`${label} field semantic classes are invalid`)
  }
  if (!item.fields.every((field, index) => index === 0 || lexical(item.fields[index - 1].path, field.path) < 0)) fail(`${label} fields are not canonical`)
}

function assertCredentialCarriersMatchShape(item, schemaVersion, label) {
  const cookieClassifier = schemaVersion === '1.0.0'
    ? legacyV1CredentialCookieName
    : credentialCookieName
  const expected = carriers(item.header_names, item.cookie_names, item.body, cookieClassifier)
  if (JSON.stringify(item.credential_carriers) !== JSON.stringify(expected)) fail(`${label} credential carriers do not match its shape`)
}

function assertRequest(item, pathLiterals, schemaVersion) {
  exact(item, ['body', 'cookie_names', 'credential_carriers', 'header_names', 'method', 'origin', 'path_action_class', 'path_template', 'query_parameters'], 'web request')
  if (!HTTP_METHOD.test(item.method ?? '')) fail('web request method is invalid')
  origin(item.origin)
  if (webPathTemplate(item.path_template, { pathLiterals }) !== item.path_template) fail('web request path template is not canonical')
  if (!PATH_ACTION_CLASSES.has(item.path_action_class)) fail('web request path action class is invalid')
  const visibleActionClass = pathActionClass(item.path_template)
  if (visibleActionClass !== 'NONE' && visibleActionClass !== item.path_action_class) fail('web request path action class does not match its visible path')
  if (!Array.isArray(item.query_parameters) || item.query_parameters.length > MAX_FIELDS || !item.query_parameters.every((parameter, index) => index === 0 || lexical(item.query_parameters[index - 1].name, parameter.name) < 0)) fail('web request parameters are invalid')
  item.query_parameters.forEach((value) => assertParameter(value, 'web request parameter'))
  if (!canonicalList(item.header_names, (value) => HEADER_NAME.test(value) && !valueLikeName(value)) || item.header_names.length > MAX_HEADER_NAMES) fail('web request headers are invalid')
  if (!canonicalList(item.cookie_names) || item.cookie_names.length > MAX_COOKIE_NAMES) fail('web request cookies are invalid')
  item.cookie_names.forEach((value) => name(value, 'web request cookie'))
  if (item.cookie_names.some(valueLikeName)) fail('web request contains a value-like cookie name')
  if (!canonicalList(item.credential_carriers, (value) => CREDENTIAL_CARRIER.test(value)) || item.credential_carriers.length > MAX_CREDENTIAL_CARRIERS) fail('web request credential carriers are invalid')
  assertBody(item.body, 'web request body')
  assertCredentialCarriersMatchShape(item, schemaVersion, 'web request')
}

function assertRedirect(item, pathLiterals) {
  exact(item, ['origin', 'path_template', 'query_parameters'], 'web redirect')
  origin(item.origin)
  if (webPathTemplate(item.path_template, { pathLiterals }) !== item.path_template) fail('web redirect path template is not canonical')
  if (!Array.isArray(item.query_parameters) || item.query_parameters.length > MAX_FIELDS || !item.query_parameters.every((parameter, index) => index === 0 || lexical(item.query_parameters[index - 1].name, parameter.name) < 0)) fail('web redirect parameters are invalid')
  item.query_parameters.forEach((value) => assertParameter(value, 'web redirect parameter'))
}

function assertDestination(item, pathLiterals) {
  exact(item, ['field_path', 'origin', 'path_template', 'query_parameters'], 'web response destination')
  text(item.field_path, 'web response destination field', 1024)
  if (pathContainsValueLikeName(item.field_path)) fail('web response destination contains a value-like field name')
  assertRedirect({ origin: item.origin, path_template: item.path_template, query_parameters: item.query_parameters }, pathLiterals)
}

function assertResponse(item, pathLiterals, schemaVersion) {
  exact(item, ['body', 'cookie_names', 'credential_carriers', 'destinations', 'destinations_truncated', 'header_names', 'redirect', 'status'], 'web response')
  if (!Number.isSafeInteger(item.status) || item.status < 0 || item.status > 999) fail('web response status is invalid')
  if (!canonicalList(item.header_names, (value) => HEADER_NAME.test(value) && !valueLikeName(value)) || item.header_names.length > MAX_HEADER_NAMES) fail('web response headers are invalid')
  if (!canonicalList(item.cookie_names) || item.cookie_names.length > MAX_COOKIE_NAMES) fail('web response cookies are invalid')
  item.cookie_names.forEach((value) => name(value, 'web response cookie'))
  if (item.cookie_names.some(valueLikeName)) fail('web response contains a value-like cookie name')
  if (!canonicalList(item.credential_carriers, (value) => CREDENTIAL_CARRIER.test(value)) || item.credential_carriers.length > MAX_CREDENTIAL_CARRIERS) fail('web response credential carriers are invalid')
  if (item.redirect !== null) assertRedirect(item.redirect, pathLiterals)
  if (!Array.isArray(item.destinations) || item.destinations.length > MAX_DESTINATIONS || typeof item.destinations_truncated !== 'boolean') fail('web response destinations are invalid')
  item.destinations.forEach((value) => assertDestination(value, pathLiterals))
  if (!item.destinations.every((value, index) => index === 0 || lexical(`${item.destinations[index - 1].field_path}\n${item.destinations[index - 1].origin}\n${item.destinations[index - 1].path_template}`, `${value.field_path}\n${value.origin}\n${value.path_template}`) < 0)) fail('web response destinations are not canonical')
  assertBody(item.body, 'web response body')
  assertCredentialCarriersMatchShape(item, schemaVersion, 'web response')
}

function aggregateMetadataItems(entry) {
  let count = 1
    + entry.request.query_parameters.length
    + entry.request.header_names.length
    + entry.request.cookie_names.length
    + entry.request.credential_carriers.length
    + entry.request.body.fields.length
    + entry.response.header_names.length
    + entry.response.cookie_names.length
    + entry.response.credential_carriers.length
    + entry.response.destinations.length
    + entry.response.body.fields.length
  if (entry.response.redirect !== null) count += entry.response.redirect.query_parameters.length
  for (const destination of entry.response.destinations) count += destination.query_parameters.length
  return count
}

function evidenceGaps(entries, sourceKind) {
  const bodies = entries.flatMap((entry) => [entry.request.body, entry.response.body])
  const gaps = [{
    code: sourceKind === 'BURP_XML' ? 'BURP_XML_METADATA_ONLY' : 'HAR_METADATA_ONLY',
    message: 'The importer retains protocol shape and sequence, not values or proof of application semantics.',
  }]
  if (bodies.some((item) => item.fields_truncated)) gaps.push({ code: 'BODY_FIELDS_TRUNCATED', message: 'At least one body field inventory reached a structural traversal or field cap; its fields_truncated flag identifies the omission.' })
  if (bodies.some((item) => item.shape_status === 'OMITTED_SIZE_LIMIT')) gaps.push({ code: 'BODY_SHAPE_OMITTED_SIZE_LIMIT', message: 'At least one structured body exceeded the body byte limit and its field shape was omitted.' })
  if (bodies.some((item) => item.shape_status === 'MALFORMED')) gaps.push({ code: 'BODY_SHAPE_MALFORMED', message: 'At least one declared JSON body could not be parsed, so its field shape is unavailable.' })
  if (entries.some((entry) => entry.response.destinations_truncated)) gaps.push({ code: 'RESPONSE_DESTINATIONS_TRUNCATED', message: 'At least one response destination inventory reached a structural traversal or destination cap.' })
  return gaps
}

export function assertValidWebSessionEvidence(value) {
  exact(value, ['applied_to_audit_bundle', 'capture_id', 'entries', 'gaps', 'kind', 'limits', 'origins', 'path_literals', 'protocol', 'redaction', 'schema_version', 'security_verdict', 'skipped', 'source'], 'web session evidence')
  if (!SCHEMA_VERSIONS.has(value.schema_version) || value.kind !== WEB_SESSION_EVIDENCE_KIND || value.protocol !== WEB_SESSION_EVIDENCE_PROTOCOL) fail('web session evidence version or kind is invalid')
  if (!/^web:[a-f0-9]{32}$/u.test(value.capture_id ?? '')) fail('web session capture id is invalid')
  exact(value.source, ['kind', 'sha256'], 'web session source')
  if (!SOURCE_KINDS.has(value.source.kind) || !HASH.test(value.source.sha256 ?? '')) fail('web session source is invalid')
  if (value.schema_version === '1.0.0' && value.source.kind !== 'HAR') fail('web session evidence 1.0.0 supports HAR sources only')
  if (!canonicalList(value.origins) || value.origins.length < 1 || value.origins.length > 32) fail('web session origins are invalid')
  value.origins.forEach(origin)
  if (!canonicalList(value.path_literals, (item) => typeof item === 'string' && /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/u.test(item)) || value.path_literals.length > 128) fail('web session path literals are invalid')
  exact(value.limits, Object.keys(EVIDENCE_LIMITS), 'web session limits')
  if (Object.entries(EVIDENCE_LIMITS).some(([field, expected]) => value.limits[field] !== expected)) fail('web session limits are invalid')
  exact(value.redaction, ['body_values_removed', 'cookie_values_removed', 'header_values_removed', 'url_values_removed', 'value_like_names_masked'], 'web session redaction')
  if (Object.values(value.redaction).some((flag) => flag !== true)) fail('web session evidence must remove protocol values')
  exact(value.skipped, ['malformed', 'non_http', 'off_scope'], 'web session skipped counts')
  if (Object.values(value.skipped).some((count) => !Number.isSafeInteger(count) || count < 0 || count > MAX_ENTRIES)) fail('web session skipped counts are invalid')
  if (value.security_verdict !== 'NOT_ASSESSED') fail('web session evidence cannot claim a security verdict')
  if (value.applied_to_audit_bundle !== false) fail('web session evidence is not an audit bundle input')
  const expectedCaptureId = createHash('sha256').update(`${value.source.sha256}\n${value.origins.join('\n')}`).digest('hex').slice(0, 32)
  if (value.capture_id !== `web:${expectedCaptureId}`) fail('web session capture id does not match its source and scope')
  if (!Array.isArray(value.entries) || value.entries.length > MAX_ENTRIES) fail('web session entry limit exceeded')
  if (value.entries.length + Object.values(value.skipped).reduce((sum, count) => sum + count, 0) > MAX_ENTRIES) fail('web session retained and skipped counts exceed the source limit')
  let previous = 0
  let aggregateItems = 0
  const observationIds = new Set()
  for (const entry of value.entries) {
    exact(entry, ['observation_id', 'observed_at', 'request', 'response', 'sequence', 'total_ms'], 'web session entry')
    if (!/^webobs:[a-f0-9]{32}$/u.test(entry.observation_id ?? '') || !Number.isSafeInteger(entry.sequence) || entry.sequence <= previous || entry.sequence > MAX_ENTRIES || observationIds.has(entry.observation_id)) fail('web session entry identity or order is invalid')
    previous = entry.sequence
    observationIds.add(entry.observation_id)
    if (entry.observed_at !== null && (typeof entry.observed_at !== 'string' || Number.isNaN(Date.parse(entry.observed_at)) || new Date(entry.observed_at).toISOString() !== entry.observed_at)) fail('web session entry timestamp is invalid')
    if (!(entry.total_ms === null || (Number.isSafeInteger(entry.total_ms) && entry.total_ms >= 0 && entry.total_ms <= 86_400_000))) fail('web session duration is invalid')
    assertRequest(entry.request, value.path_literals, value.schema_version)
    assertResponse(entry.response, value.path_literals, value.schema_version)
    aggregateItems += aggregateMetadataItems(entry)
    if (aggregateItems > MAX_AGGREGATE_METADATA_ITEMS) fail('web session aggregate metadata item limit exceeded')
    if (!value.origins.includes(entry.request.origin)) fail('web request origin is outside the declared capture scope')
    if (entry.response.redirect !== null && !value.origins.includes(entry.response.redirect.origin)) fail('web redirect origin is outside the declared capture scope')
    if (entry.response.destinations.some((destination) => !value.origins.includes(destination.origin))) fail('web response destination is outside the declared capture scope')
    const expectedObservationId = createHash('sha256').update(`${value.source.sha256}\n${entry.sequence}\n${entry.request.method}\n${entry.request.origin}\n${entry.request.path_template}\n${entry.request.path_action_class}`).digest('hex').slice(0, 32)
    if (entry.observation_id !== `webobs:${expectedObservationId}`) fail('web observation id does not match its request')
  }
  if (!Array.isArray(value.gaps) || value.gaps.length > 256) fail('web session gaps are invalid')
  for (const gap of value.gaps) {
    exact(gap, ['code', 'message'], 'web session gap')
    if (!/^[A-Z][A-Z0-9_]{2,95}$/u.test(gap.code ?? '')) fail('web session gap code is invalid')
    text(gap.message, 'web session gap message')
  }
  if (JSON.stringify(value.gaps) !== JSON.stringify(evidenceGaps(value.entries, value.source.kind))) fail('web session gaps do not match its omissions')
  if (Buffer.byteLength(stableJson(value, 0), 'utf8') > 64 * 1024 * 1024) fail('web session evidence exceeds its byte limit')
  return value
}

export function importWebSessionEvidence(rawEntries, {
  sourceKind,
  sourceSha256,
  targetOrigins,
  pathLiterals = [],
} = {}) {
  if (!SOURCE_KINDS.has(sourceKind)) fail('web capture source kind is invalid')
  if (!HASH.test(sourceSha256 ?? '')) fail('web capture source sha256 is invalid')
  if (!Array.isArray(targetOrigins) || targetOrigins.length < 1 || targetOrigins.length > 32) fail('at least one target origin is required')
  const origins = unique(targetOrigins.map(origin))
  if (!Array.isArray(pathLiterals) || pathLiterals.length > 128 || pathLiterals.some((item) => typeof item !== 'string' || !/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/u.test(item))) fail('path literal declarations are invalid')
  const declaredPathLiterals = unique(pathLiterals)
  const scope = new Set(origins)
  if (!Array.isArray(rawEntries)) fail('web capture input is missing its entry list')
  if (rawEntries.length > MAX_ENTRIES) fail('web capture entry limit exceeded')
  const entries = []
  const skipped = { malformed: 0, non_http: 0, off_scope: 0 }
  rawEntries.forEach((entry, index) => {
    const result = sanitizeEntry(entry, index + 1, scope, sourceSha256, declaredPathLiterals)
    if (result.skip) skipped[result.skip] += 1
    else entries.push(result.value)
  })
  const captureId = createHash('sha256').update(`${sourceSha256}\n${origins.join('\n')}`).digest('hex').slice(0, 32)
  return assertValidWebSessionEvidence({
    schema_version: '1.1.0',
    kind: WEB_SESSION_EVIDENCE_KIND,
    protocol: WEB_SESSION_EVIDENCE_PROTOCOL,
    capture_id: `web:${captureId}`,
    source: { kind: sourceKind, sha256: sourceSha256 },
    origins,
    path_literals: declaredPathLiterals,
    limits: { ...EVIDENCE_LIMITS },
    redaction: { url_values_removed: true, header_values_removed: true, cookie_values_removed: true, body_values_removed: true, value_like_names_masked: true },
    entries,
    skipped,
    gaps: evidenceGaps(entries, sourceKind),
    security_verdict: 'NOT_ASSESSED',
    applied_to_audit_bundle: false,
  })
}

export function importWebHarEvidence(har, options = {}) {
  const rawEntries = har?.log?.entries
  if (!Array.isArray(rawEntries)) fail('HAR input is missing its entry list')
  return importWebSessionEvidence(rawEntries, { ...options, sourceKind: 'HAR' })
}

export function canonicalWebSessionEvidence(value) {
  assertValidWebSessionEvidence(value)
  return stableJson(value, 2)
}

export function digestWebSessionEvidence(value) {
  return createHash('sha256').update(canonicalWebSessionEvidence(value)).digest('hex')
}
