import { Buffer } from 'node:buffer'
import { TextDecoder } from 'node:util'

const HTTP_TOKEN = /^[!#$%&'*+.^_`|~0-9A-Z-]{1,64}$/
const TEST_CATEGORY = /^[a-z][a-z0-9_]{2,63}$/
const QUERY_NAME = /^[A-Za-z][A-Za-z0-9_.~-]{0,63}$/
const PATH_PARAMETER_NAME = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/
const SYNTHETIC_VALUE = /^SYNTHETIC_[A-Z0-9_-]{4,128}$/
const AMBIGUOUS_PATH_ENCODING = /(?:\\|%(?:25)*(?:2e|2f|5c))/i
const MAX_HEADER_VALUE_BYTES = 64 * 1024
const MAX_RESPONSE_BYTES = 1024 * 1024
// Response-derived write methods are hints, not executable actions. They need a
// predeclared mutation envelope (before/after reads, inverse, and countersignature)
// and therefore cannot be synthesized from untrusted response content.
const AUTOMATIC_SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])
const DISCOVERY_SOURCES = new Set([
  'allow_header',
  'html_forms',
  'html_links',
  'json_links',
  'link_header',
  'location_header',
  'openapi_paths',
  'sitemap_xml',
])
const SAFE_HEADER_NAMES = new Set([
  'allow',
  'content-encoding',
  'content-type',
  'link',
  'location',
])
const HTML_LINK_TAGS = new Set(['a', 'area', 'link'])
const HTML_RAW_TEXT_TAGS = new Set(['script', 'style'])
const JSON_LINK_FIELDS = new Set(['href', 'link', 'next', 'self', 'url'])
const JSON_IGNORED_CONTAINER_FIELDS = new Set(['example', 'examples'])
const OPENAPI_OPERATION_FIELDS = new Set([
  'delete',
  'get',
  'head',
  'options',
  'patch',
  'post',
  'put',
  'trace',
])

export class HttpAuthedDiscoveryError extends Error {
  constructor(code, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'HttpAuthedDiscoveryError'
    this.code = code
  }
}

function discoveryError(code, message, options) {
  return new HttpAuthedDiscoveryError(code, message, options)
}

function isPlainObject(value) {
  return value !== null
    && typeof value === 'object'
    && Object.getPrototypeOf(value) === Object.prototype
}

function assertOnlyKeys(value, allowed, label) {
  if (!isPlainObject(value)) {
    throw discoveryError(
      'HTTP_AUTHED_DISCOVERY_POLICY_INVALID',
      `${label} must be a plain object`,
    )
  }
  if (Object.keys(value).some((key) => !allowed.has(key))) {
    throw discoveryError(
      'HTTP_AUTHED_DISCOVERY_POLICY_INVALID',
      `${label} contains an unsupported field`,
    )
  }
}

function rawReferencePath(reference) {
  const withoutSuffix = reference.split(/[?#]/u, 1)[0]
  const absolute = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/]*(\/.*)?$/u.exec(withoutSuffix)
  if (absolute) return absolute[1] ?? '/'
  const schemeRelative = /^\/\/[^/]*(\/.*)?$/u.exec(withoutSuffix)
  if (schemeRelative) return schemeRelative[1] ?? '/'
  return withoutSuffix
}

function hasAmbiguousPath(reference) {
  const rawPath = rawReferencePath(reference)
  return AMBIGUOUS_PATH_ENCODING.test(rawPath)
    || rawPath.split('/').some((segment) => segment === '.' || segment === '..')
}

function validatePathPrefix(value) {
  return typeof value === 'string'
    && value.length >= 1
    && value.length <= 2048
    && value.startsWith('/')
    && !/[\u0000-\u001f\u007f?#]/u.test(value)
    && !hasAmbiguousPath(value)
}

function pathMatchesPrefix(pathname, prefix) {
  if (prefix === '/') return true
  if (prefix.endsWith('/')) return pathname.startsWith(prefix)
  return pathname === prefix || pathname.startsWith(`${prefix}/`)
}

function validatePolicy(policy) {
  assertOnlyKeys(policy, new Set([
    'candidate_methods',
    'enabled',
    'max_response_bytes',
    'origin',
    'path_prefixes',
    'sources',
    'synthetic_path_values',
    'synthetic_query_values',
    'test_category',
  ]), 'http-authed discovery policy')

  if (typeof policy.enabled !== 'boolean') {
    throw discoveryError(
      'HTTP_AUTHED_DISCOVERY_POLICY_INVALID',
      'discovery policy enabled must be boolean',
    )
  }

  let origin
  try {
    origin = new URL(policy.origin)
  } catch (cause) {
    throw discoveryError(
      'HTTP_AUTHED_DISCOVERY_POLICY_INVALID',
      'discovery policy origin must be a canonical HTTPS origin',
      { cause },
    )
  }
  if (
    origin.protocol !== 'https:'
    || origin.username !== ''
    || origin.password !== ''
    || origin.pathname !== '/'
    || origin.search !== ''
    || origin.hash !== ''
    || origin.origin !== policy.origin
  ) {
    throw discoveryError(
      'HTTP_AUTHED_DISCOVERY_POLICY_INVALID',
      'discovery policy origin must be a canonical HTTPS origin',
    )
  }

  if (
    !Array.isArray(policy.path_prefixes)
    || policy.path_prefixes.length === 0
    || new Set(policy.path_prefixes).size !== policy.path_prefixes.length
    || policy.path_prefixes.some((prefix) => !validatePathPrefix(prefix))
  ) {
    throw discoveryError(
      'HTTP_AUTHED_DISCOVERY_POLICY_INVALID',
      'discovery path prefixes must be unique canonical path prefixes',
    )
  }

  if (
    !Array.isArray(policy.sources)
    || new Set(policy.sources).size !== policy.sources.length
    || policy.sources.some((source) => !DISCOVERY_SOURCES.has(source))
  ) {
    throw discoveryError(
      'HTTP_AUTHED_DISCOVERY_POLICY_INVALID',
      'discovery sources must be unique supported source identifiers',
    )
  }

  if (
    !Array.isArray(policy.candidate_methods)
    || policy.candidate_methods.length === 0
    || new Set(policy.candidate_methods).size !== policy.candidate_methods.length
    || policy.candidate_methods.some((method) => !HTTP_TOKEN.test(method))
  ) {
    throw discoveryError(
      'HTTP_AUTHED_DISCOVERY_POLICY_INVALID',
      'discovery candidate methods must be unique canonical uppercase HTTP tokens',
    )
  }

  if (typeof policy.test_category !== 'string' || !TEST_CATEGORY.test(policy.test_category)) {
    throw discoveryError(
      'HTTP_AUTHED_DISCOVERY_POLICY_INVALID',
      'discovery test category must be a canonical category identifier',
    )
  }

  assertOnlyKeys(
    policy.synthetic_query_values,
    new Set(Object.keys(policy.synthetic_query_values ?? {})),
    'synthetic query value map',
  )
  for (const [name, value] of Object.entries(policy.synthetic_query_values)) {
    if (!QUERY_NAME.test(name) || typeof value !== 'string' || !SYNTHETIC_VALUE.test(value)) {
      throw discoveryError(
        'HTTP_AUTHED_DISCOVERY_POLICY_INVALID',
        'synthetic query substitutions must use safe names and explicit SYNTHETIC_ values',
      )
    }
  }

  assertOnlyKeys(
    policy.synthetic_path_values,
    new Set(Object.keys(policy.synthetic_path_values ?? {})),
    'synthetic path value map',
  )
  for (const [name, value] of Object.entries(policy.synthetic_path_values)) {
    if (
      !PATH_PARAMETER_NAME.test(name)
      || typeof value !== 'string'
      || !SYNTHETIC_VALUE.test(value)
    ) {
      throw discoveryError(
        'HTTP_AUTHED_DISCOVERY_POLICY_INVALID',
        'synthetic path substitutions must use safe names and explicit SYNTHETIC_ values',
      )
    }
  }

  if (
    !Number.isSafeInteger(policy.max_response_bytes)
    || policy.max_response_bytes < 0
    || policy.max_response_bytes > MAX_RESPONSE_BYTES
  ) {
    throw discoveryError(
      'HTTP_AUTHED_DISCOVERY_POLICY_INVALID',
      'discovery response byte bound must be between zero and one MiB',
    )
  }

  return {
    ...policy,
    origin: origin.origin,
    candidateMethodSet: new Set(policy.candidate_methods),
    sourceSet: new Set(policy.sources),
  }
}

function validateSourceAction(policy, action) {
  if (!isPlainObject(action) || typeof action.url !== 'string') {
    throw discoveryError(
      'HTTP_AUTHED_DISCOVERY_SOURCE_INVALID',
      'discovery source action must carry one exact URL',
    )
  }
  if (
    typeof action.method !== 'string'
    || !HTTP_TOKEN.test(action.method)
    || action.test_category !== policy.test_category
  ) {
    throw discoveryError(
      'HTTP_AUTHED_DISCOVERY_SOURCE_INVALID',
      'discovery source action method or category does not match the sealed policy',
    )
  }
  const normalized = normalizeReference(policy, action.url, action.url)
  if (!normalized.accepted) {
    throw discoveryError(
      'HTTP_AUTHED_DISCOVERY_SOURCE_INVALID',
      'discovery source action URL is outside the sealed persistence-safe scope',
    )
  }
  return { ...action, normalizedUrl: normalized.url }
}

function normalizeHeaders(headers) {
  if (!Array.isArray(headers)) {
    throw discoveryError(
      'HTTP_AUTHED_DISCOVERY_INPUT_INVALID',
      'discovery response headers must be an array',
    )
  }
  return headers.map((header) => {
    if (
      !isPlainObject(header)
      || typeof header.name !== 'string'
      || typeof header.value !== 'string'
    ) {
      throw discoveryError(
        'HTTP_AUTHED_DISCOVERY_INPUT_INVALID',
        'each discovery response header must contain a name and string value',
      )
    }
    const name = header.name.toLowerCase()
    if (!SAFE_HEADER_NAMES.has(name)) {
      throw discoveryError(
        'HTTP_AUTHED_DISCOVERY_HEADER_UNSAFE',
        'the discovery boundary accepts only explicitly safe response header names',
      )
    }
    if (Buffer.byteLength(header.value, 'utf8') > MAX_HEADER_VALUE_BYTES) {
      throw discoveryError(
        'HTTP_AUTHED_DISCOVERY_INPUT_INVALID',
        'a discovery response header exceeds its transient byte bound',
      )
    }
    return { name, value: header.value }
  })
}

function normalizeBodyChunks(bodyChunks) {
  if (!Array.isArray(bodyChunks)) {
    throw discoveryError(
      'HTTP_AUTHED_DISCOVERY_INPUT_INVALID',
      'discovery body chunks must be an array',
    )
  }
  return bodyChunks.map((chunk) => {
    if (!(Buffer.isBuffer(chunk) || chunk instanceof Uint8Array)) {
      throw discoveryError(
        'HTTP_AUTHED_DISCOVERY_INPUT_INVALID',
        'discovery body chunks must contain bytes',
      )
    }
    return Buffer.from(chunk)
  })
}

function normalizeReference(policy, reference, baseUrl) {
  if (
    typeof reference !== 'string'
    || reference.length === 0
    || Buffer.byteLength(reference, 'utf8') > 2048
    || /[\u0000-\u001f\u007f]/u.test(reference)
  ) {
    return { accepted: false, code: 'URL_INVALID' }
  }
  if (hasAmbiguousPath(reference)) {
    return { accepted: false, code: 'AMBIGUOUS_PATH' }
  }

  let parsed
  try {
    parsed = new URL(reference, baseUrl)
  } catch {
    return { accepted: false, code: 'URL_INVALID' }
  }
  if (parsed.protocol !== 'https:') return { accepted: false, code: 'URL_INVALID' }
  if (parsed.username !== '' || parsed.password !== '') {
    return { accepted: false, code: 'URL_CREDENTIALS_REFUSED' }
  }
  if (parsed.origin !== policy.origin) return { accepted: false, code: 'OFF_ORIGIN' }
  if (!policy.path_prefixes.some((prefix) => pathMatchesPrefix(parsed.pathname, prefix))) {
    return { accepted: false, code: 'PATH_OUT_OF_SCOPE' }
  }

  const query = [...parsed.searchParams.entries()]
  parsed.search = ''
  for (const [name] of query) {
    if (!Object.hasOwn(policy.synthetic_query_values, name)) {
      return { accepted: false, code: 'UNKNOWN_QUERY_PARAMETER' }
    }
    parsed.searchParams.append(name, policy.synthetic_query_values[name])
  }
  parsed.hash = ''
  return { accepted: true, url: parsed.href }
}

function candidateKey(candidate) {
  return JSON.stringify([
    candidate.kind,
    candidate.test_category,
    candidate.method,
    candidate.url,
    candidate.expected_effect,
  ])
}

function extractLinkHeaderReferences(value) {
  const references = []
  let cursor = 0
  while (cursor < value.length) {
    const opening = value.indexOf('<', cursor)
    if (opening < 0) break
    const closing = value.indexOf('>', opening + 1)
    if (closing < 0) break
    references.push(value.slice(opening + 1, closing).trim())
    cursor = closing + 1
  }
  return references
}

function findTagEnd(html, start) {
  let quote = null
  for (let index = start; index < html.length; index += 1) {
    const character = html[index]
    if (quote !== null) {
      if (character === quote) quote = null
      continue
    }
    if (character === '"' || character === "'") {
      quote = character
    } else if (character === '>') {
      return index
    }
  }
  return -1
}

function decodeHtmlAttribute(value) {
  return value
    .replaceAll('&amp;', '&')
    .replaceAll('&quot;', '"')
    .replaceAll('&#39;', "'")
    .replaceAll('&apos;', "'")
}

function attributesFromTag(tag) {
  const attributes = {}
  let cursor = 0
  while (cursor < tag.length && !/\s/u.test(tag[cursor])) cursor += 1
  while (cursor < tag.length) {
    while (cursor < tag.length && /[\s/]/u.test(tag[cursor])) cursor += 1
    const nameStart = cursor
    while (cursor < tag.length && !/[\s=/>]/u.test(tag[cursor])) cursor += 1
    if (cursor === nameStart) {
      cursor += 1
      continue
    }
    const name = tag.slice(nameStart, cursor).toLowerCase()
    while (cursor < tag.length && /\s/u.test(tag[cursor])) cursor += 1
    if (tag[cursor] !== '=') {
      if (!Object.hasOwn(attributes, name)) attributes[name] = null
      continue
    }
    cursor += 1
    while (cursor < tag.length && /\s/u.test(tag[cursor])) cursor += 1
    let value
    if (tag[cursor] === '"' || tag[cursor] === "'") {
      const quote = tag[cursor]
      cursor += 1
      const valueStart = cursor
      while (cursor < tag.length && tag[cursor] !== quote) cursor += 1
      value = tag.slice(valueStart, cursor)
      if (cursor < tag.length) cursor += 1
    } else {
      const valueStart = cursor
      while (cursor < tag.length && !/[\s>]/u.test(tag[cursor])) cursor += 1
      value = tag.slice(valueStart, cursor)
    }
    if (!Object.hasOwn(attributes, name)) attributes[name] = decodeHtmlAttribute(value)
  }
  return attributes
}

function extractHtmlDiscovery(html) {
  const links = []
  const forms = []
  const lower = html.toLowerCase()
  let cursor = 0
  while (cursor < html.length) {
    const opening = html.indexOf('<', cursor)
    if (opening < 0) break
    if (html.startsWith('<!--', opening)) {
      const commentEnd = html.indexOf('-->', opening + 4)
      cursor = commentEnd < 0 ? html.length : commentEnd + 3
      continue
    }
    const tagEnd = findTagEnd(html, opening + 1)
    if (tagEnd < 0) break
    let nameStart = opening + 1
    while (nameStart < tagEnd && /\s/u.test(html[nameStart])) nameStart += 1
    const closing = html[nameStart] === '/'
    if (closing) nameStart += 1
    const nameMatch = /^[A-Za-z][A-Za-z0-9:-]*/u.exec(html.slice(nameStart, tagEnd))
    const name = nameMatch?.[0].toLowerCase()
    if (!closing && name && HTML_RAW_TEXT_TAGS.has(name)) {
      const rawEnd = lower.indexOf(`</${name}`, tagEnd + 1)
      if (rawEnd < 0) break
      const closingEnd = findTagEnd(html, rawEnd + name.length + 2)
      cursor = closingEnd < 0 ? html.length : closingEnd + 1
      continue
    }
    if (!closing && name && HTML_LINK_TAGS.has(name)) {
      const attributes = attributesFromTag(html.slice(nameStart, tagEnd))
      if (typeof attributes.href === 'string') links.push(attributes.href)
    } else if (!closing && name === 'form') {
      const attributes = attributesFromTag(html.slice(nameStart, tagEnd))
      const explicitMethod = attributes.method
      const method = explicitMethod === undefined
        ? 'get'
        : typeof explicitMethod === 'string'
          ? explicitMethod.trim().toLowerCase()
          : ''
      forms.push({
        method,
        reference: typeof attributes.action === 'string' ? attributes.action : null,
      })
    }
    cursor = tagEnd + 1
  }
  return { forms, links }
}

function extractJsonLinkReferences(value) {
  const references = []
  const queue = [value]
  for (let index = 0; index < queue.length; index += 1) {
    const current = queue[index]
    if (Array.isArray(current)) {
      queue.push(...current)
      continue
    }
    if (!isPlainObject(current)) continue
    for (const [name, child] of Object.entries(current)) {
      if (JSON_LINK_FIELDS.has(name) && typeof child === 'string') {
        references.push(child)
      } else if (
        !JSON_IGNORED_CONTAINER_FIELDS.has(name)
        && child !== null
        && typeof child === 'object'
      ) {
        queue.push(child)
      }
    }
  }
  return references
}

function substituteOpenApiPath(policy, template) {
  if (typeof template !== 'string' || template.length === 0) {
    return { accepted: false, code: 'OPENAPI_PATH_TEMPLATE_INVALID' }
  }
  let missing = false
  let invalid = false
  const substituted = template.replace(/\{([^{}]*)\}/gu, (_match, name) => {
    if (!PATH_PARAMETER_NAME.test(name)) {
      invalid = true
      return ''
    }
    if (!Object.hasOwn(policy.synthetic_path_values, name)) {
      missing = true
      return ''
    }
    return policy.synthetic_path_values[name]
  })
  if (invalid || /[{}]/u.test(substituted)) {
    return { accepted: false, code: 'OPENAPI_PATH_TEMPLATE_INVALID' }
  }
  if (missing) return { accepted: false, code: 'UNKNOWN_PATH_PARAMETER' }
  return { accepted: true, reference: substituted }
}

function extractOpenApiOperations(policy, document) {
  if (
    !isPlainObject(document)
    || !(typeof document.openapi === 'string' || typeof document.swagger === 'string')
  ) {
    return { operations: [], documentInvalid: false }
  }
  if (!isPlainObject(document.paths)) {
    return { operations: [], documentInvalid: true }
  }
  const operations = []
  for (const [template, pathItem] of Object.entries(document.paths)) {
    if (!isPlainObject(pathItem)) continue
    const substituted = substituteOpenApiPath(policy, template)
    for (const [name, operation] of Object.entries(pathItem)) {
      if (!OPENAPI_OPERATION_FIELDS.has(name)) continue
      if (!isPlainObject(operation)) {
        operations.push({ code: 'OPENAPI_OPERATION_INVALID' })
      } else if (!substituted.accepted) {
        operations.push({ code: substituted.code })
      } else {
        operations.push({ method: name.toUpperCase(), reference: substituted.reference })
      }
    }
  }
  return { operations, documentInvalid: false }
}

function decodeXmlText(value) {
  return value
    .replaceAll('&amp;', '&')
    .replaceAll('&quot;', '"')
    .replaceAll('&apos;', "'")
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>')
}

function extractSitemapReferences(xml) {
  const withoutComments = xml.replace(/<!--[\s\S]*?-->/gu, '')
  const opening = withoutComments.match(/<(?:[A-Za-z][A-Za-z0-9_.-]*:)?loc(?:\s[^>]*)?>/giu) ?? []
  const closing = withoutComments.match(/<\/(?:[A-Za-z][A-Za-z0-9_.-]*:)?loc\s*>/giu) ?? []
  if (opening.length !== closing.length) return { references: [], invalid: true }
  const references = []
  const pattern = /<(?:[A-Za-z][A-Za-z0-9_.-]*:)?loc(?:\s[^>]*)?>([^<]*)<\/(?:[A-Za-z][A-Za-z0-9_.-]*:)?loc\s*>/giu
  for (const match of withoutComments.matchAll(pattern)) {
    references.push(decodeXmlText(match[1]).trim())
  }
  if (references.length !== opening.length) return { references: [], invalid: true }
  return { references, invalid: false }
}

function isJsonContentType(value) {
  return value === 'application/json' || value.endsWith('+json')
}

function isXmlContentType(value) {
  return value === 'application/xml'
    || value === 'text/xml'
    || value.endsWith('+xml')
}

function sortedCounts(counts) {
  return Object.fromEntries([...counts.entries()].sort(([left], [right]) => (
    left < right ? -1 : left > right ? 1 : 0
  )))
}

/**
 * Derive persistence-safe candidate drafts from one bounded HTTP response.
 *
 * The caller must provide only the explicitly safe header names accepted above.
 * Header values and response bytes are consumed transiently and never appear in
 * the returned value. Sequence allocation and durable deduplication belong to
 * the campaign ledger; this pure slice only deduplicates one response.
 */
export function discoverHttpAuthedCandidates({
  policy: policyInput,
  sourceAction: sourceActionInput,
  headers: headerInput = [],
  bodyChunks: bodyChunkInput = [],
}) {
  const policy = validatePolicy(policyInput)
  const sourceAction = validateSourceAction(policy, sourceActionInput)
  const headers = normalizeHeaders(headerInput)
  const bodyChunks = normalizeBodyChunks(bodyChunkInput)
  const candidates = []
  const seen = new Set()
  const rejected = new Map()
  let duplicateCount = 0

  const reject = (code) => rejected.set(code, (rejected.get(code) ?? 0) + 1)
  const addCandidate = (reference, method = 'GET') => {
    if (!HTTP_TOKEN.test(method)) {
      reject('METHOD_INVALID')
      return
    }
    if (!policy.candidateMethodSet.has(method)) {
      reject('METHOD_NOT_ALLOWED')
      return
    }
    if (!AUTOMATIC_SAFE_METHODS.has(method)) {
      reject('METHOD_REQUIRES_DECLARED_ACTION')
      return
    }
    const normalized = normalizeReference(policy, reference, sourceAction.normalizedUrl)
    if (!normalized.accepted) {
      reject(normalized.code)
      return
    }
    const candidate = {
      kind: 'probe',
      test_category: policy.test_category,
      method,
      url: normalized.url,
      expected_effect: 'none',
    }
    const key = candidateKey(candidate)
    if (seen.has(key)) {
      duplicateCount += 1
      return
    }
    seen.add(key)
    candidates.push(candidate)
  }

  if (policy.candidateMethodSet.has(sourceAction.method)) {
    seen.add(candidateKey({
      kind: 'probe',
      test_category: policy.test_category,
      method: sourceAction.method,
      url: sourceAction.normalizedUrl,
      expected_effect: 'none',
    }))
  }

  if (policy.enabled) {
    for (const { name, value } of headers) {
      if (name === 'link' && policy.sourceSet.has('link_header')) {
        for (const reference of extractLinkHeaderReferences(value)) addCandidate(reference)
      } else if (name === 'location' && policy.sourceSet.has('location_header')) {
        addCandidate(value.trim())
      } else if (name === 'allow' && policy.sourceSet.has('allow_header')) {
        for (const method of value.split(',').map((entry) => entry.trim()).filter(Boolean)) {
          addCandidate(sourceAction.url, method)
        }
      }
    }

    const htmlDiscoveryEnabled = policy.sourceSet.has('html_links')
      || policy.sourceSet.has('html_forms')
    const jsonDiscoveryEnabled = policy.sourceSet.has('json_links')
      || policy.sourceSet.has('openapi_paths')
    const xmlDiscoveryEnabled = policy.sourceSet.has('sitemap_xml')
    if (
      (htmlDiscoveryEnabled || jsonDiscoveryEnabled || xmlDiscoveryEnabled)
      && bodyChunks.length > 0
    ) {
      const bodyBytes = bodyChunks.reduce((total, chunk) => total + chunk.length, 0)
      const encodings = headers
        .filter(({ name }) => name === 'content-encoding')
        .map(({ value }) => value.trim().toLowerCase())
        .filter(Boolean)
      const contentTypes = headers
        .filter(({ name }) => name === 'content-type')
        .map(({ value }) => value.split(';', 1)[0].trim().toLowerCase())
        .filter(Boolean)

      if (bodyBytes > policy.max_response_bytes) {
        reject('BODY_LIMIT_EXCEEDED')
      } else if (encodings.some((encoding) => encoding !== 'identity')) {
        reject('CONTENT_ENCODING_UNSUPPORTED')
      } else if (contentTypes.length !== 1) {
        reject('CONTENT_TYPE_UNSUPPORTED')
      } else {
        const contentType = contentTypes[0]
        const parseHtml = htmlDiscoveryEnabled
          && ['text/html', 'application/xhtml+xml'].includes(contentType)
        const parseJson = jsonDiscoveryEnabled && isJsonContentType(contentType)
        const parseXml = xmlDiscoveryEnabled && isXmlContentType(contentType)
        if (!parseHtml && !parseJson && !parseXml) {
          reject('CONTENT_TYPE_UNSUPPORTED')
        } else {
          const body = Buffer.concat(bodyChunks, bodyBytes)
          let text = null
          try {
            text = new TextDecoder('utf-8', { fatal: true }).decode(body)
          } catch {
            reject('BODY_UTF8_INVALID')
          } finally {
            body.fill(0)
          }
          if (text !== null && parseHtml) {
            const html = extractHtmlDiscovery(text)
            if (policy.sourceSet.has('html_links')) {
              for (const reference of html.links) addCandidate(reference)
            }
            if (policy.sourceSet.has('html_forms')) {
              for (const form of html.forms) {
                if (form.method !== 'get') {
                  reject('FORM_METHOD_UNSAFE')
                } else {
                  addCandidate(form.reference ?? sourceAction.url, 'GET')
                }
              }
            }
          }

          if (text !== null && parseJson) {
            let document
            try {
              document = JSON.parse(text)
            } catch {
              reject('BODY_JSON_INVALID')
              document = undefined
            }
            if (document !== undefined) {
              if (policy.sourceSet.has('json_links')) {
                for (const reference of extractJsonLinkReferences(document)) {
                  addCandidate(reference)
                }
              }
              if (policy.sourceSet.has('openapi_paths')) {
                const openapi = extractOpenApiOperations(policy, document)
                if (openapi.documentInvalid) reject('OPENAPI_DOCUMENT_INVALID')
                for (const operation of openapi.operations) {
                  if (operation.code) {
                    reject(operation.code)
                  } else {
                    addCandidate(operation.reference, operation.method)
                  }
                }
              }
            }
          }

          if (text !== null && parseXml) {
            const sitemap = extractSitemapReferences(text)
            if (sitemap.invalid) {
              reject('BODY_XML_INVALID')
            } else {
              for (const reference of sitemap.references) addCandidate(reference)
            }
          }
        }
      }
    }
  }

  const rejectedByCode = sortedCounts(rejected)
  const rejectedCount = Object.values(rejectedByCode)
    .reduce((total, count) => total + count, 0)
  return {
    candidates,
    summary: {
      accepted_count: candidates.length,
      duplicate_count: duplicateCount,
      rejected_count: rejectedCount,
      rejected_by_code: rejectedByCode,
    },
  }
}
