import { importWebSessionEvidence } from './reverse-web-har.mjs'

const MAX_XML_BYTES = 64 * 1024 * 1024
const MAX_HTTP_MESSAGE_BYTES = 16 * 1024 * 1024
const MAX_HTTP_HEAD_BYTES = 64 * 1024
const MAX_XML_NODES = 250_000
const MAX_XML_DEPTH = 4
const MAX_ATTRIBUTES = 64
const MAX_ITEM_FIELDS = 64
const MAX_ITEMS = 10_000
const XML_NAME = /^[A-Za-z_][A-Za-z0-9._-]{0,63}$/u
const HTTP_METHOD = /^[!#$%&'*+.^_`|~0-9A-Z-]{1,32}$/u
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/u
const XML_FORBIDDEN_CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/u
const HTTP_HEAD_CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/u

function fail(message) {
  const error = new Error(message)
  error.name = 'BurpHttpItemsError'
  error.code = 'BURP_HTTP_ITEMS_INVALID'
  throw error
}

function xmlText(input) {
  let value
  if (Buffer.isBuffer(input) || input instanceof Uint8Array) {
    if (input.byteLength > MAX_XML_BYTES) fail('Burp XML exceeds its byte limit')
    try { value = new TextDecoder('utf-8', { fatal: true }).decode(input) } catch { fail('Burp XML must be valid UTF-8') }
  } else if (typeof input === 'string') {
    if (Buffer.byteLength(input, 'utf8') > MAX_XML_BYTES) fail('Burp XML exceeds its byte limit')
    value = input
  } else {
    fail('Burp XML input must be UTF-8 text or bytes')
  }
  if (value.charCodeAt(0) === 0xfeff) value = value.slice(1)
  if (XML_FORBIDDEN_CONTROL.test(value)) fail('Burp XML contains a forbidden control character')
  if (/<!\s*(?:DOCTYPE|ENTITY)\b/iu.test(value)) fail('Burp XML declarations and entities are forbidden')
  if (/<![^>]*\b(?:SYSTEM|PUBLIC)\b/iu.test(value)) fail('Burp XML external identifier declarations are forbidden')
  return value
}

function xmlCharacter(codePoint) {
  return codePoint === 0x09 || codePoint === 0x0a || codePoint === 0x0d
    || (codePoint >= 0x20 && codePoint <= 0xd7ff)
    || (codePoint >= 0xe000 && codePoint <= 0xfffd)
    || (codePoint >= 0x10000 && codePoint <= 0x10ffff)
}

function decodeEntities(value) {
  if (/&(?!#(?:[0-9]+|x[0-9a-f]+);|(?:amp|apos|gt|lt|quot);)/iu.test(value)) fail('Burp XML contains an unsupported or malformed entity reference')
  let malformed = false
  const decoded = value.replace(/&([^;]{1,32});/gu, (whole, name) => {
    const named = { amp: '&', apos: "'", gt: '>', lt: '<', quot: '"' }[name]
    if (named !== undefined) return named
    let codePoint
    if (/^#[0-9]+$/u.test(name)) codePoint = Number(name.slice(1))
    else if (/^#x[0-9a-f]+$/iu.test(name)) codePoint = Number.parseInt(name.slice(2), 16)
    else {
      malformed = true
      return whole
    }
    if (!Number.isSafeInteger(codePoint) || !xmlCharacter(codePoint)) {
      malformed = true
      return whole
    }
    return String.fromCodePoint(codePoint)
  })
  if (malformed) fail('Burp XML contains an unsupported or malformed entity reference')
  return decoded
}

function tagEnd(source, offset) {
  let quote = null
  for (let index = offset; index < source.length; index += 1) {
    const character = source[index]
    if (quote !== null) {
      if (character === quote) quote = null
      continue
    }
    if (character === '"' || character === "'") quote = character
    else if (character === '>') return index
    else if (character === '<') fail('Burp XML contains a malformed tag')
  }
  fail('Burp XML contains an unterminated tag')
}

function parseAttributes(source) {
  const attributes = Object.create(null)
  let offset = 0
  let count = 0
  while (offset < source.length) {
    const whitespace = source.slice(offset).match(/^\s+/u)
    if (whitespace) offset += whitespace[0].length
    if (offset === source.length) break
    const nameMatch = source.slice(offset).match(/^([A-Za-z_][A-Za-z0-9._-]{0,63})/u)
    if (!nameMatch) fail('Burp XML contains a malformed attribute name')
    const name = nameMatch[1]
    offset += name.length
    const beforeEquals = source.slice(offset).match(/^\s*/u)[0]
    offset += beforeEquals.length
    if (source[offset] !== '=') fail('Burp XML attribute is missing an equals sign')
    offset += 1
    offset += source.slice(offset).match(/^\s*/u)[0].length
    const quote = source[offset]
    if (quote !== '"' && quote !== "'") fail('Burp XML attribute value must be quoted')
    const end = source.indexOf(quote, offset + 1)
    if (end < 0) fail('Burp XML attribute value is unterminated')
    const value = decodeEntities(source.slice(offset + 1, end))
    if (value.length > 8192 || Object.hasOwn(attributes, name)) fail('Burp XML attribute is duplicated or too large')
    attributes[name] = value
    count += 1
    if (count > MAX_ATTRIBUTES) fail('Burp XML attribute limit exceeded')
    offset = end + 1
  }
  return attributes
}

function parseXml(input) {
  const source = xmlText(input)
  const roots = []
  const stack = []
  let nodes = 0
  let offset = 0
  let declarationSeen = false
  const appendText = (value, entities = true) => {
    if (stack.length === 0) {
      if (value.trim() !== '') fail('Burp XML contains text outside its document element')
      return
    }
    stack.at(-1).text.push(entities ? decodeEntities(value) : value)
  }
  while (offset < source.length) {
    const next = source.indexOf('<', offset)
    if (next < 0) {
      appendText(source.slice(offset))
      offset = source.length
      break
    }
    appendText(source.slice(offset, next))
    if (source.startsWith('<!--', next)) {
      const end = source.indexOf('-->', next + 4)
      if (end < 0 || source.slice(next + 4, end).includes('--')) fail('Burp XML comment is malformed')
      offset = end + 3
      continue
    }
    if (source.startsWith('<![CDATA[', next)) {
      if (stack.length === 0) fail('Burp XML CDATA must be inside an element')
      const end = source.indexOf(']]>', next + 9)
      if (end < 0) fail('Burp XML CDATA is unterminated')
      appendText(source.slice(next + 9, end), false)
      offset = end + 3
      continue
    }
    if (source.startsWith('<?', next)) {
      const end = source.indexOf('?>', next + 2)
      if (end < 0) fail('Burp XML processing instruction is unterminated')
      const instruction = source.slice(next + 2, end)
      if (declarationSeen || roots.length > 0 || stack.length > 0 || !/^xml(?:\s|$)/u.test(instruction)) fail('Burp XML processing instructions are forbidden')
      const attributes = parseAttributes(instruction.slice(3))
      if (
        Object.keys(attributes).some((name) => !['encoding', 'standalone', 'version'].includes(name))
        || attributes.version !== '1.0'
        || (attributes.encoding !== undefined && attributes.encoding.toUpperCase() !== 'UTF-8')
        || (attributes.standalone !== undefined && !['no', 'yes'].includes(attributes.standalone))
      ) fail('Burp XML declaration is unsupported')
      declarationSeen = true
      offset = end + 2
      continue
    }
    if (source.startsWith('<!', next)) fail('Burp XML declarations are forbidden')
    if (source.startsWith('</', next)) {
      const end = tagEnd(source, next + 2)
      const name = source.slice(next + 2, end).trim()
      if (!XML_NAME.test(name) || stack.length === 0 || stack.at(-1).name !== name) fail('Burp XML closing tag is malformed or mismatched')
      stack.pop()
      offset = end + 1
      continue
    }
    const end = tagEnd(source, next + 1)
    let inside = source.slice(next + 1, end)
    let selfClosing = false
    if (/\/\s*$/u.test(inside)) {
      selfClosing = true
      inside = inside.replace(/\/\s*$/u, '')
    }
    const nameMatch = inside.match(/^([A-Za-z_][A-Za-z0-9._-]{0,63})/u)
    if (!nameMatch) fail('Burp XML opening tag is malformed')
    const name = nameMatch[1]
    const node = { name, attributes: parseAttributes(inside.slice(name.length)), children: [], text: [] }
    nodes += 1
    if (nodes > MAX_XML_NODES) fail('Burp XML node limit exceeded')
    if (stack.length >= MAX_XML_DEPTH) fail('Burp XML depth limit exceeded')
    if (stack.length === 0) roots.push(node)
    else stack.at(-1).children.push(node)
    if (!selfClosing) stack.push(node)
    offset = end + 1
  }
  if (stack.length > 0 || roots.length !== 1 || roots[0].name !== 'items') fail('Burp XML must contain one closed items document element')
  return roots[0]
}

function leaf(node, label) {
  if (node.children.length > 0) fail(`${label} must not contain nested XML elements`)
  return node.text.join('')
}

function strictBase64(value, label) {
  const compact = value.replace(/\s/gu, '')
  if (
    compact.length === 0
    || compact.length % 4 !== 0
    || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(compact)
  ) fail(`${label} is not canonical base64`)
  const bytes = Buffer.from(compact, 'base64')
  if (bytes.toString('base64') !== compact) fail(`${label} is not canonical base64`)
  return bytes
}

function httpBytes(node, label, { allowEmpty = false } = {}) {
  const attributeNames = Object.keys(node.attributes)
  if (attributeNames.length !== 1 || attributeNames[0] !== 'base64' || !['true', 'false'].includes(node.attributes.base64)) fail(`${label} must declare one boolean base64 attribute`)
  const value = leaf(node, label)
  if (allowEmpty && value.trim() === '') return Buffer.alloc(0)
  const bytes = node.attributes.base64 === 'true' ? strictBase64(value, label) : Buffer.from(value, 'utf8')
  if (bytes.length === 0 || bytes.length > MAX_HTTP_MESSAGE_BYTES) fail(`${label} is empty or exceeds its byte limit`)
  return bytes
}

function findSeparator(bytes) {
  const crlf = bytes.indexOf(Buffer.from('\r\n\r\n'))
  if (crlf >= 0) return { offset: crlf, size: 4 }
  const lf = bytes.indexOf(Buffer.from('\n\n'))
  return lf >= 0 ? { offset: lf, size: 2 } : { offset: bytes.length, size: 0 }
}

function parseHttpMessage(bytes, label) {
  const separator = findSeparator(bytes)
  if (separator.offset > MAX_HTTP_HEAD_BYTES) fail(`${label} HTTP header block exceeds its byte limit`)
  const head = bytes.subarray(0, separator.offset).toString('latin1')
  if (HTTP_HEAD_CONTROL.test(head)) fail(`${label} HTTP header block contains a forbidden character`)
  const lines = head.split(/\r?\n/u)
  if (lines.length < 1 || lines[0].length === 0) fail(`${label} HTTP start line is missing`)
  const headers = []
  for (const line of lines.slice(1)) {
    if (line.includes('\r')) fail(`${label} HTTP header contains a bare carriage return`)
    if (/^[ \t]/u.test(line)) fail(`${label} HTTP header folding is forbidden`)
    const separatorOffset = line.indexOf(':')
    if (separatorOffset <= 0) fail(`${label} HTTP header is malformed`)
    const name = line.slice(0, separatorOffset)
    const value = line.slice(separatorOffset + 1).trim()
    if (!HEADER_NAME.test(name) || HTTP_HEAD_CONTROL.test(value)) fail(`${label} HTTP header is malformed`)
    headers.push({ name, value })
  }
  const body = separator.size === 0 ? Buffer.alloc(0) : bytes.subarray(separator.offset + separator.size)
  return { startLine: lines[0], headers, body }
}

function contentType(headers) {
  return headers.filter(({ name }) => name.toLowerCase() === 'content-type').at(-1)?.value
}

function utf8Body(bytes) {
  try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes) } catch { return null }
}

function effectivePort(url) {
  return url.port || (url.protocol === 'https:' ? '443' : '80')
}

function hostMatchesUrl(value, expected) {
  let actual
  try { actual = new URL(`${expected.protocol}//${value}`) } catch { return false }
  return !actual.username && !actual.password && actual.pathname === '/'
    && !actual.search && !actual.hash
    && actual.hostname.toLowerCase() === expected.hostname.toLowerCase()
    && effectivePort(actual) === effectivePort(expected)
}

function parseRequest(bytes, declaredUrl) {
  const message = parseHttpMessage(bytes, 'Burp request')
  const match = message.startLine.match(/^([^ ]+) ([^ ]+) HTTP\/[0-9]+(?:\.[0-9]+)?$/u)
  if (!match) fail('Burp request HTTP start line is malformed')
  const method = match[1].toUpperCase()
  if (!HTTP_METHOD.test(method)) fail('Burp request HTTP method is invalid')
  let url
  if (declaredUrl.length < 1 || declaredUrl.length > 262_144 || /[\u0000-\u001f\u007f-\u009f]/u.test(declaredUrl)) fail('Burp item URL is invalid')
  try { url = new URL(declaredUrl) } catch { fail('Burp item URL is invalid') }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash) fail('Burp item URL must be an HTTP or HTTPS URL without credentials or a fragment')
  const requestTarget = match[2]
  if (requestTarget.startsWith('/')) {
    if (requestTarget !== `${url.pathname}${url.search}`) fail('Burp request target does not match the item URL')
  } else {
    let absolute
    try { absolute = new URL(requestTarget) } catch { fail('Burp request target is unsupported') }
    if (!['http:', 'https:'].includes(absolute.protocol) || absolute.href !== url.href) fail('Burp absolute request target does not match the item URL')
  }
  const hosts = message.headers.filter(({ name }) => name.toLowerCase() === 'host')
  if (hosts.length > 1 || (hosts.length === 1 && !hostMatchesUrl(hosts[0].value, url))) fail('Burp request Host header does not match the item URL')
  const rawBody = utf8Body(message.body)
  return {
    method,
    url: url.href,
    headers: message.headers,
    cookies: [],
    ...(message.body.length === 0 ? {} : {
      postData: {
        mimeType: contentType(message.headers),
        size: message.body.length,
        ...(rawBody === null ? {} : { text: rawBody }),
      },
    }),
  }
}

function parseResponse(bytes) {
  const message = parseHttpMessage(bytes, 'Burp response')
  const match = message.startLine.match(/^HTTP\/[0-9]+(?:\.[0-9]+)? ([1-9][0-9]{2})(?: .*)?$/u)
  if (!match) fail('Burp response HTTP start line is malformed')
  const status = Number(match[1])
  const rawBody = utf8Body(message.body)
  return {
    status,
    headers: message.headers,
    cookies: [],
    content: {
      mimeType: contentType(message.headers),
      size: message.body.length,
      ...(rawBody === null ? {} : { text: rawBody }),
    },
  }
}

function emptyResponse() {
  return {
    status: 0,
    headers: [],
    cookies: [],
    content: {
      mimeType: '',
      size: 0,
    },
  }
}

function itemFields(item) {
  if (item.name !== 'item' || item.text.join('').trim() !== '' || item.children.length > MAX_ITEM_FIELDS) fail('Burp XML item structure is invalid')
  const fields = new Map()
  for (const child of item.children) {
    if (fields.has(child.name)) fail('Burp XML item contains a duplicate field')
    fields.set(child.name, child)
  }
  return fields
}

function requiredField(fields, name) {
  const node = fields.get(name)
  if (node === undefined) fail(`Burp XML item is missing its ${name} field`)
  return node
}

function parseItem(item) {
  const fields = itemFields(item)
  const declaredUrl = leaf(requiredField(fields, 'url'), 'Burp item URL').trim()
  const request = parseRequest(httpBytes(requiredField(fields, 'request'), 'Burp request'), declaredUrl)
  const responseBytes = fields.has('response')
    ? httpBytes(fields.get('response'), 'Burp response', { allowEmpty: true })
    : Buffer.alloc(0)
  const response = responseBytes.length === 0 ? emptyResponse() : parseResponse(responseBytes)

  const declaredMethod = leaf(requiredField(fields, 'method'), 'Burp item method').trim().toUpperCase()
  const declaredStatusText = fields.has('status')
    ? leaf(fields.get('status'), 'Burp item status').trim()
    : ''
  const declaredStatus = declaredStatusText === '' ? 0 : Number(declaredStatusText)
  if (declaredMethod !== request.method) fail('Burp item method does not match its raw HTTP request')
  if (!Number.isSafeInteger(declaredStatus) || declaredStatus !== response.status) fail('Burp item status does not match its raw HTTP response')

  const url = new URL(request.url)
  for (const [name, expected] of [
    ['protocol', url.protocol.slice(0, -1)],
    ['host', url.hostname],
    ['port', url.port || (url.protocol === 'https:' ? '443' : '80')],
  ]) if (fields.has(name) && leaf(fields.get(name), `Burp item ${name}`).trim().toLowerCase() !== expected.toLowerCase()) fail(`Burp item ${name} does not match its URL`)
  if (fields.has('path') && leaf(fields.get('path'), 'Burp item path').trim() !== `${url.pathname}${url.search}`) fail('Burp item path does not match its URL')

  let startedDateTime
  if (fields.has('time')) {
    const observed = leaf(fields.get('time'), 'Burp item time').trim()
    if (observed && !Number.isNaN(Date.parse(observed))) startedDateTime = new Date(observed).toISOString()
  }
  return {
    ...(startedDateTime === undefined ? {} : { startedDateTime }),
    request,
    response,
  }
}

export function importBurpHttpItemsEvidence(xml, options = {}) {
  const root = parseXml(xml)
  if (root.text.join('').trim() !== '' || root.children.some(({ name }) => name !== 'item')) fail('Burp XML items document contains unsupported structure')
  if (root.children.length > MAX_ITEMS) fail('Burp XML item limit exceeded')
  const entries = root.children.map(parseItem)
  return importWebSessionEvidence(entries, {
    ...options,
    sourceKind: 'BURP_XML',
  })
}
