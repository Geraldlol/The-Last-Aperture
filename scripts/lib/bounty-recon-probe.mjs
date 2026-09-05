import { assertApproved } from './bounty-recon-gate.mjs'

const DEFAULT_TIMEOUT_MS = 12000
const MAX_TITLE_SCAN_BYTES = 64 * 1024

const TECH_HEADERS = [
  'server',
  'x-powered-by',
  'x-aspnet-version',
  'x-generator',
  'x-drupal-cache',
  'x-shopify-stage',
  'via',
]

export function extractTitle(html) {
  if (typeof html !== 'string' || html.length === 0) return null
  // Bounded scan: a hostile multi-megabyte response must not stall the sweep.
  const window = html.length > MAX_TITLE_SCAN_BYTES ? html.slice(0, MAX_TITLE_SCAN_BYTES) : html
  const match = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(window)
  if (match === null) return null
  const title = match[1].replace(/\s+/g, ' ').trim()
  return title.length === 0 ? null : title.slice(0, 512)
}

export function deriveTechHints(headers) {
  const hints = []
  if (headers === null || typeof headers !== 'object') return hints
  const get = typeof headers.get === 'function'
    ? (name) => headers.get(name)
    : (name) => headers[name]
  for (const name of TECH_HEADERS) {
    const value = get(name)
    if (typeof value === 'string' && value.length > 0) {
      hints.push(`${name}: ${value.slice(0, 96)}`)
    }
  }
  return hints
}

function intOrNull(value) {
  const parsed = Number.parseInt(value ?? '', 10)
  return Number.isInteger(parsed) ? parsed : null
}

export async function probeHost({
  approval,
  limiter,
  fetchImpl = fetch,
  timeoutMs = DEFAULT_TIMEOUT_MS,
}) {
  assertApproved(approval)
  if (typeof approval.userAgent !== 'string' || approval.userAgent.length === 0) {
    throw new Error('approval carries no user agent; the program mandates an identifying marker')
  }
  if (limiter === null || typeof limiter?.acquire !== 'function') {
    throw new Error('probeHost requires a rate limiter; the sealed limit is the authorization')
  }
  // Unconditional: there is no branch that reaches fetch without paying a token.
  await limiter.acquire()

  const base = { url: approval.url, status: null, server: null, title: null,
    content_type: null, content_length: null, location: null, tech_hints: [], error: null }
  try {
    const response = await fetchImpl(approval.url, {
      method: 'GET',
      // Redirects are recorded, never followed. Following them is how an open
      // redirect walks a scanner straight out of the sealed perimeter; the
      // target becomes a fresh candidate that must pass the gate on its own.
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
      headers: { 'User-Agent': approval.userAgent },
    })
    const headers = response.headers
    const contentType = headers?.get?.('content-type') ?? null
    let title = null
    if (typeof contentType === 'string' && contentType.includes('html')) {
      const body = await response.text().catch(() => '')
      title = extractTitle(body)
    }
    return {
      ...base,
      status: response.status,
      server: headers?.get?.('server') ?? null,
      title,
      content_type: contentType,
      content_length: intOrNull(headers?.get?.('content-length')),
      location: headers?.get?.('location') ?? null,
      tech_hints: deriveTechHints(headers),
    }
  } catch (error) {
    // A dead host is an observation, not a failure of the sweep.
    return { ...base, error: `${error.name}: ${error.message}`.slice(0, 512) }
  }
}
