import { TextDecoder } from 'node:util'

const JSON_MEDIA_TYPE = /^application\/(?:json|[a-z0-9!#$&^_.+-]+\+json)$/
const SAFE_KEY_NAME = /^[A-Za-z_$@][A-Za-z0-9_$@.-]{0,127}$/
const SHAPE_TYPES = new Set(['array', 'boolean', 'null', 'number', 'object', 'string'])
const JSON_SHAPE_MODE = 'JSON_SHAPE_ONLY'
const ASPNET_D_JSON_SHAPE_MODE = 'ASPNET_D_JSON_SHAPE_ONLY'
const ASPNET_D_JSON_PROJECTION = 'ASPNET_D_JSON_STRING'
const MAX_JSON_BYTES = 1024 * 1024
const TYPE_ORDER = new Map([
  ['null', 0],
  ['boolean', 1],
  ['number', 2],
  ['string', 3],
  ['array', 4],
  ['object', 5],
])

export const HTTP_AUTHED_JSON_SHAPE_LIMITS = Object.freeze({
  maxDepth: 4,
  maxNodes: 4096,
  maxPaths: 512,
  maxKeys: 256,
})

export class HttpAuthedJsonShapeError extends Error {
  constructor(code, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'HttpAuthedJsonShapeError'
    this.code = code
  }
}

function shapeError(code, message, options) {
  return new HttpAuthedJsonShapeError(code, message, options)
}

function lexical(left, right) {
  if (left < right) return -1
  if (left > right) return 1
  return 0
}

function comparePaths(left, right) {
  const length = Math.min(left.length, right.length)
  for (let index = 0; index < length; index += 1) {
    const compared = lexical(left[index], right[index])
    if (compared !== 0) return compared
  }
  return left.length - right.length
}

function jsonType(value) {
  if (value === null) return 'null'
  if (Array.isArray(value)) return 'array'
  return typeof value
}

function mediaTypes(headers) {
  if (!Array.isArray(headers)) {
    throw shapeError(
      'HTTP_AUTHED_JSON_SHAPE_HEADERS_INVALID',
      'JSON shape observation received invalid response headers',
    )
  }
  const contentTypes = []
  const contentEncodings = []
  for (const header of headers) {
    if (
      header === null
      || typeof header !== 'object'
      || typeof header.name !== 'string'
      || typeof header.value !== 'string'
      || /[\r\n\0]/.test(header.name)
      || /[\r\n\0]/.test(header.value)
    ) {
      throw shapeError(
        'HTTP_AUTHED_JSON_SHAPE_HEADERS_INVALID',
        'JSON shape observation received invalid response headers',
      )
    }
    const name = header.name.toLowerCase()
    if (name === 'content-type') {
      contentTypes.push(header.value.split(';', 1)[0].trim().toLowerCase())
    } else if (name === 'content-encoding') {
      contentEncodings.push(header.value.trim().toLowerCase())
    }
  }
  return { contentTypes, contentEncodings }
}

function exactJsonMediaType(headers) {
  const { contentTypes, contentEncodings } = mediaTypes(headers)
  const claimsJson = contentTypes.some((value) => JSON_MEDIA_TYPE.test(value))
  if (!claimsJson) return false
  if (
    contentTypes.length !== 1
    || !JSON_MEDIA_TYPE.test(contentTypes[0])
    || contentEncodings.some((value) => value !== '' && value !== 'identity')
  ) {
    throw shapeError(
      'HTTP_AUTHED_JSON_SHAPE_REPRESENTATION_UNSUPPORTED',
      'claimed JSON response has an ambiguous or encoded representation',
    )
  }
  return true
}

function bodyBytes(bodyChunks) {
  if (!Array.isArray(bodyChunks)) {
    throw shapeError(
      'HTTP_AUTHED_JSON_SHAPE_BODY_INVALID',
      'JSON shape observation received invalid response bytes',
    )
  }
  const chunks = []
  let joined
  try {
    let total = 0
    for (const chunk of bodyChunks) {
      if (!(Buffer.isBuffer(chunk) || chunk instanceof Uint8Array)) {
        throw shapeError(
          'HTTP_AUTHED_JSON_SHAPE_BODY_INVALID',
          'JSON shape observation received invalid response bytes',
        )
      }
      const copy = Buffer.from(chunk)
      chunks.push(copy)
      total += copy.length
      if (total > MAX_JSON_BYTES) {
        throw shapeError(
          'HTTP_AUTHED_JSON_SHAPE_BODY_INVALID',
          'JSON shape observation exceeded its response byte boundary',
        )
      }
    }
    joined = Buffer.concat(chunks, total)
    return joined
  } finally {
    for (const chunk of chunks) chunk.fill(0)
  }
}

function parseJson(bytes) {
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    return JSON.parse(text)
  } catch (cause) {
    throw shapeError(
      'HTTP_AUTHED_JSON_SHAPE_PARSE_FAILED',
      'claimed JSON response could not be parsed for schema-only observation',
      { cause },
    )
  }
}

function pathKey(path) {
  return JSON.stringify(path)
}

function normalizedLimits(limits = {}) {
  if (limits === null || typeof limits !== 'object' || Array.isArray(limits)) {
    throw shapeError('HTTP_AUTHED_JSON_SHAPE_LIMIT_INVALID', 'JSON shape limits are invalid')
  }
  const result = { ...HTTP_AUTHED_JSON_SHAPE_LIMITS, ...limits }
  for (const [name, maximum] of [
    ['maxDepth', 8],
    ['maxNodes', 16384],
    ['maxPaths', 2048],
    ['maxKeys', 1024],
  ]) {
    if (!Number.isSafeInteger(result[name]) || result[name] < 1 || result[name] > maximum) {
      throw shapeError('HTTP_AUTHED_JSON_SHAPE_LIMIT_INVALID', 'JSON shape limits are invalid')
    }
  }
  return result
}

function normalizedSafeKeyNames(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 256) {
    throw shapeError(
      'HTTP_AUTHED_JSON_SHAPE_KEY_ALLOWLIST_INVALID',
      'JSON shape observation requires a bounded sealed key-name allowlist',
    )
  }
  const result = new Set()
  for (const key of value) {
    if (
      typeof key !== 'string'
      || !SAFE_KEY_NAME.test(key)
      || Buffer.byteLength(key, 'utf8') > 128
      || result.has(key)
    ) {
      throw shapeError(
        'HTTP_AUTHED_JSON_SHAPE_KEY_ALLOWLIST_INVALID',
        'JSON shape observation requires a bounded sealed key-name allowlist',
      )
    }
    result.add(key)
  }
  return result
}

function buildShape(root, limits, safeKeyNames, projection) {
  const keyNames = new Set()
  const paths = new Map()
  const stack = [{ value: root, path: [], depth: 0 }]
  let objectCount = 0
  let arrayCount = 0
  let omittedKeyCount = 0
  let visitedNodes = 0
  let maxDepthObserved = 0
  let truncated = false

  while (stack.length > 0) {
    if (visitedNodes >= limits.maxNodes) {
      truncated = true
      break
    }
    const current = stack.pop()
    visitedNodes += 1
    maxDepthObserved = Math.max(maxDepthObserved, current.depth)
    const type = jsonType(current.value)
    if (!SHAPE_TYPES.has(type)) {
      throw shapeError(
        'HTTP_AUTHED_JSON_SHAPE_VALUE_INVALID',
        'JSON shape observation encountered an unsupported value type',
      )
    }
    if (current.path.length > 0) {
      const identity = pathKey(current.path)
      if (!paths.has(identity)) {
        if (paths.size >= limits.maxPaths) {
          truncated = true
        } else {
          paths.set(identity, { path: [...current.path], types: new Set() })
        }
      }
      paths.get(identity)?.types.add(type)
    }

    if (type === 'object') objectCount += 1
    if (type === 'array') arrayCount += 1
    if (!['object', 'array'].includes(type)) continue
    if (current.depth >= limits.maxDepth) {
      if (
        (type === 'array' && current.value.length > 0)
        || (type === 'object' && Object.keys(current.value).length > 0)
      ) truncated = true
      continue
    }
    const entries = type === 'array'
      ? current.value.map((value) => ({ segment: '[]', value }))
      : Object.entries(current.value).map(([key, value]) => {
          const safe = safeKeyNames.has(key)
          if (!safe || (!keyNames.has(key) && keyNames.size >= limits.maxKeys)) {
            omittedKeyCount += 1
            truncated = true
            return { segment: '*', value }
          }
          keyNames.add(key)
          return { segment: key, value }
        })
    for (let index = entries.length - 1; index >= 0; index -= 1) {
      stack.push({
        value: entries[index].value,
        path: [...current.path, entries[index].segment],
        depth: current.depth + 1,
      })
    }
  }

  return {
    kind: 'red-team-audit/http-authed-json-shape',
    schema_version: projection === undefined ? '1.0.0' : '1.1.0',
    ...(projection === undefined ? {} : { projection }),
    root_type: jsonType(root),
    object_count: objectCount,
    array_count: arrayCount,
    key_names: [...keyNames].sort(lexical),
    value_types: [...paths.values()]
      .map(({ path, types }) => ({
        path,
        types: [...types].sort((left, right) => TYPE_ORDER.get(left) - TYPE_ORDER.get(right)),
      }))
      .sort((left, right) => comparePaths(left.path, right.path)),
    max_depth_observed: maxDepthObserved,
    omitted_key_count: omittedKeyCount,
    truncated,
  }
}

function exactKeys(value, expected) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const actual = Object.keys(value).sort(lexical)
  const wanted = [...expected].sort(lexical)
  return actual.length === wanted.length
    && actual.every((key, index) => key === wanted[index])
}

export function sanitizeHttpAuthedJsonShape(value, { safeKeyNames, mode } = {}) {
  const baseTopKeys = [
    'kind',
    'schema_version',
    'root_type',
    'object_count',
    'array_count',
    'key_names',
    'value_types',
    'max_depth_observed',
    'omitted_key_count',
    'truncated',
  ]
  const projected = value?.schema_version === '1.1.0'
  const expectedProjection = mode === undefined ? undefined : observationProjection(mode)
  const topKeys = projected ? [...baseTopKeys, 'projection'] : baseTopKeys
  if (
    !exactKeys(value, topKeys)
    || value.kind !== 'red-team-audit/http-authed-json-shape'
    || !['1.0.0', '1.1.0'].includes(value.schema_version)
    || (projected && value.projection !== ASPNET_D_JSON_PROJECTION)
    || (mode !== undefined && projected !== (expectedProjection !== undefined))
    || !SHAPE_TYPES.has(value.root_type)
    || !Number.isSafeInteger(value.object_count)
    || value.object_count < 0
    || value.object_count > 16384
    || !Number.isSafeInteger(value.array_count)
    || value.array_count < 0
    || value.array_count > 16384
    || !Number.isSafeInteger(value.max_depth_observed)
    || value.max_depth_observed < 0
    || value.max_depth_observed > 8
    || !Number.isSafeInteger(value.omitted_key_count)
    || value.omitted_key_count < 0
    || value.omitted_key_count > 16384
    || typeof value.truncated !== 'boolean'
    || !Array.isArray(value.key_names)
    || value.key_names.length > 1024
    || !Array.isArray(value.value_types)
    || value.value_types.length > 2048
  ) {
    throw shapeError('HTTP_AUTHED_JSON_SHAPE_INVALID', 'JSON shape metadata is invalid')
  }

  const keyNames = []
  for (const key of value.key_names) {
    if (
      typeof key !== 'string'
      || !SAFE_KEY_NAME.test(key)
      || Buffer.byteLength(key, 'utf8') > 128
      || keyNames.includes(key)
    ) {
      throw shapeError('HTTP_AUTHED_JSON_SHAPE_INVALID', 'JSON shape metadata is invalid')
    }
    keyNames.push(key)
  }
  keyNames.sort(lexical)
  const allowedKeys = safeKeyNames === undefined
    ? undefined
    : normalizedSafeKeyNames(safeKeyNames)
  if (allowedKeys !== undefined && keyNames.some((key) => !allowedKeys.has(key))) {
    throw shapeError('HTTP_AUTHED_JSON_SHAPE_INVALID', 'JSON shape metadata is invalid')
  }

  const valueTypes = []
  const seenPaths = new Set()
  for (const entry of value.value_types) {
    if (
      !exactKeys(entry, ['path', 'types'])
      || !Array.isArray(entry.path)
      || entry.path.length < 1
      || entry.path.length > 8
      || !Array.isArray(entry.types)
      || entry.types.length < 1
      || entry.types.length > SHAPE_TYPES.size
    ) {
      throw shapeError('HTTP_AUTHED_JSON_SHAPE_INVALID', 'JSON shape metadata is invalid')
    }
    const path = entry.path.map((segment) => {
      if (
        segment !== '[]'
        && segment !== '*'
        && (
          typeof segment !== 'string'
          || !SAFE_KEY_NAME.test(segment)
          || Buffer.byteLength(segment, 'utf8') > 128
        )
      ) {
        throw shapeError('HTTP_AUTHED_JSON_SHAPE_INVALID', 'JSON shape metadata is invalid')
      }
      if (
        allowedKeys !== undefined
        && segment !== '[]'
        && segment !== '*'
        && !allowedKeys.has(segment)
      ) {
        throw shapeError('HTTP_AUTHED_JSON_SHAPE_INVALID', 'JSON shape metadata is invalid')
      }
      return segment
    })
    const identity = pathKey(path)
    if (seenPaths.has(identity)) {
      throw shapeError('HTTP_AUTHED_JSON_SHAPE_INVALID', 'JSON shape metadata is invalid')
    }
    seenPaths.add(identity)
    const types = [...entry.types]
    if (new Set(types).size !== types.length || types.some((type) => !SHAPE_TYPES.has(type))) {
      throw shapeError('HTTP_AUTHED_JSON_SHAPE_INVALID', 'JSON shape metadata is invalid')
    }
    types.sort((left, right) => TYPE_ORDER.get(left) - TYPE_ORDER.get(right))
    valueTypes.push({ path, types })
  }
  valueTypes.sort((left, right) => comparePaths(left.path, right.path))

  return {
    kind: value.kind,
    schema_version: value.schema_version,
    ...(projected ? { projection: value.projection } : {}),
    root_type: value.root_type,
    object_count: value.object_count,
    array_count: value.array_count,
    key_names: keyNames,
    value_types: valueTypes,
    max_depth_observed: value.max_depth_observed,
    omitted_key_count: value.omitted_key_count,
    truncated: value.truncated,
  }
}

function observationProjection(mode) {
  if (mode === undefined || mode === JSON_SHAPE_MODE) return undefined
  if (mode === ASPNET_D_JSON_SHAPE_MODE) return ASPNET_D_JSON_PROJECTION
  throw shapeError(
    'HTTP_AUTHED_JSON_SHAPE_MODE_INVALID',
    'JSON shape observation mode is invalid',
  )
}

function parseAspNetDJson(value) {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || !exactKeys(value, ['d'])
    || typeof value.d !== 'string'
  ) {
    throw shapeError(
      'HTTP_AUTHED_JSON_SHAPE_ASPNET_ENVELOPE_INVALID',
      'ASP.NET JSON shape observation received an invalid envelope',
    )
  }
  if (Buffer.byteLength(value.d, 'utf8') > MAX_JSON_BYTES) {
    throw shapeError(
      'HTTP_AUTHED_JSON_SHAPE_ASPNET_D_INVALID',
      'ASP.NET JSON shape observation exceeded its inner JSON byte boundary',
    )
  }
  try {
    return JSON.parse(value.d)
  } catch {
    throw shapeError(
      'HTTP_AUTHED_JSON_SHAPE_ASPNET_D_PARSE_FAILED',
      'ASP.NET JSON shape observation could not parse the inner JSON value',
    )
  }
}

export function observeHttpAuthedJsonShape({
  headers,
  bodyChunks,
  limits,
  safeKeyNames,
  mode,
} = {}) {
  if (!exactJsonMediaType(headers)) return undefined
  const bytes = bodyBytes(bodyChunks)
  try {
    const projection = observationProjection(mode)
    const outer = parseJson(bytes)
    const parsed = projection === ASPNET_D_JSON_PROJECTION
      ? parseAspNetDJson(outer)
      : outer
    const allowedKeys = normalizedSafeKeyNames(safeKeyNames)
    return sanitizeHttpAuthedJsonShape(
      buildShape(parsed, normalizedLimits(limits), allowedKeys, projection),
      { safeKeyNames: [...allowedKeys], mode },
    )
  } finally {
    bytes.fill(0)
  }
}
