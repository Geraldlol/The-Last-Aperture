// Insertion points are found by structure, never by guessing which string "looks
// like a parameter". Each carries hints so the payload selector can be narrow:
// firing a URL payload at a numeric id wastes a request and adds a result nobody
// should read.

const URL_LIKE = /^(?:https?:\/\/|\/\/)[^\s]+$/i
const HOSTNAME_LIKE = /^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/i
const NUMERIC = /^-?\d+$/
const PATH_LIKE = /^[./\\][^\s]*$|^[^\s]*\/[^\s]*$/
const TEMPLATE_LIKE = /[{}$<>]/

// Names that conventionally carry a URL. Combined with the value shape, this is
// what makes SSRF candidate selection precise instead of a spray.
const URL_PARAM_NAMES = /^(?:url|uri|target|dest|destination|redirect|redirect_uri|next|callback|callback_url|webhook|webhook_url|link|src|source|image|image_url|fetch|feed|proxy|forward|return|return_to|continue|domain|host|endpoint)$/i

export function classifyValueHints(name, value) {
  const hints = []
  const text = String(value ?? '')
  if (URL_LIKE.test(text)) hints.push('url-valued')
  else if (HOSTNAME_LIKE.test(text)) hints.push('hostname-valued')
  if (typeof name === 'string' && URL_PARAM_NAMES.test(name)) hints.push('url-named')
  if (NUMERIC.test(text)) hints.push('numeric')
  if (PATH_LIKE.test(text)) hints.push('path-like')
  if (TEMPLATE_LIKE.test(text)) hints.push('template-like')
  return hints
}

export function isSsrfCandidate(insertionPoint) {
  return insertionPoint.hints.includes('url-valued')
    || insertionPoint.hints.includes('url-named')
    || insertionPoint.hints.includes('hostname-valued')
}

function walkJson(value, pointer, visit) {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => walkJson(entry, `${pointer}/${index}`, visit))
    return
  }
  if (value !== null && typeof value === 'object') {
    for (const [key, entry] of Object.entries(value)) {
      walkJson(entry, `${pointer}/${key}`, visit)
    }
    return
  }
  visit(value, pointer)
}

const SKIP_HEADERS = new Set([
  'authorization', 'cookie', 'content-length', 'host', 'accept', 'accept-encoding',
  'accept-language', 'connection', 'user-agent', 'content-type',
])

export function findInsertionPoints(request) {
  const points = []

  let parsed = null
  try {
    parsed = new URL(request.url)
  } catch {
    parsed = null
  }

  if (parsed !== null) {
    for (const [name, value] of parsed.searchParams.entries()) {
      points.push({
        location: 'query',
        pointer: name,
        original: value,
        hints: classifyValueHints(name, value),
      })
    }
    const segments = parsed.pathname.split('/')
    segments.forEach((segment, index) => {
      if (segment.length === 0) return
      points.push({
        location: 'path',
        pointer: String(index),
        original: segment,
        hints: classifyValueHints(null, segment),
      })
    })
  }

  if (typeof request.body === 'string' && request.body.length > 0) {
    try {
      const body = JSON.parse(request.body)
      walkJson(body, '', (value, pointer) => {
        if (value === null || typeof value === 'object') return
        const name = pointer.split('/').pop()
        points.push({
          location: 'json',
          pointer: pointer === '' ? '/' : pointer,
          original: value,
          hints: classifyValueHints(name, value),
        })
      })
    } catch {
      // An opaque body is not fuzzed. Blind substitution in a payload we cannot
      // parse produces a corrupted request and a meaningless result.
    }
  }

  for (const [name, value] of Object.entries(request.headers ?? {})) {
    if (SKIP_HEADERS.has(name)) continue
    points.push({
      location: 'header',
      pointer: name,
      original: value,
      hints: classifyValueHints(name, value),
    })
  }

  return points
}

function setJsonPointer(root, pointer, nextValue) {
  if (pointer === '/' || pointer === '') return nextValue
  const parts = pointer.split('/').slice(1)
  const clone = structuredClone(root)
  let cursor = clone
  for (let index = 0; index < parts.length - 1; index += 1) {
    cursor = cursor[Array.isArray(cursor) ? Number.parseInt(parts[index], 10) : parts[index]]
  }
  const last = parts[parts.length - 1]
  cursor[Array.isArray(cursor) ? Number.parseInt(last, 10) : last] = nextValue
  return clone
}

export function applyPayload(request, insertionPoint, payload, { mode = 'replace' } = {}) {
  const value = mode === 'append' ? `${insertionPoint.original}${payload}` : payload

  if (insertionPoint.location === 'query' || insertionPoint.location === 'path') {
    const parsed = new URL(request.url)
    if (insertionPoint.location === 'query') {
      parsed.searchParams.set(insertionPoint.pointer, value)
    } else {
      const segments = parsed.pathname.split('/')
      segments[Number.parseInt(insertionPoint.pointer, 10)] = encodeURIComponent(value)
      parsed.pathname = segments.join('/')
    }
    return { ...request, url: parsed.toString() }
  }

  if (insertionPoint.location === 'header') {
    return { ...request, headers: { ...request.headers, [insertionPoint.pointer]: value } }
  }

  if (insertionPoint.location === 'json') {
    const body = JSON.parse(request.body)
    return { ...request, body: JSON.stringify(setJsonPointer(body, insertionPoint.pointer, value)) }
  }

  throw new Error(`unknown insertion location: ${insertionPoint.location}`)
}

export function describeInsertion(insertionPoint) {
  return `${insertionPoint.location}:${insertionPoint.pointer}`
}
