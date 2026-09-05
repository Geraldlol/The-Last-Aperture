import { assertApproved, gateCandidates } from './bounty-recon-gate.mjs'
import { normalizeResponse } from './bounty-authz-normalize.mjs'
import { applyRole } from './bounty-authz-roles.mjs'

const DEFAULT_TIMEOUT_MS = 15000
const MAX_BODY_BYTES = 512 * 1024

// The grinder introduces no new egress path: it reuses the P1 chokepoint, so a
// captured request pointing outside the sealed perimeter is refused here exactly
// as a discovered host would be.
export function approveRequestTarget({ request, sealedScope }) {
  let parsed
  try {
    parsed = new URL(request.url)
  } catch {
    return { approval: null, refusal: { host: null, reason: 'candidate-unparsable', ruleId: 'none' } }
  }
  const port = parsed.port === '' ? (parsed.protocol === 'http:' ? 80 : 443) : Number.parseInt(parsed.port, 10)
  const { approved, refused } = gateCandidates({
    sealedScope,
    candidates: [{ kind: 'host', value: parsed.hostname }],
    port,
  })
  if (approved.length === 0) {
    return { approval: null, refusal: refused[0] }
  }
  return { approval: approved[0], refusal: null }
}

// Space and tab are the only separators an HTTP field value can carry, so they
// are the only token boundaries worth recognizing -- and naming them explicitly
// keeps this identical to the Python mirror, where a regex class would not be.
const isFieldSeparator = (character) => character === ' ' || character === '\t'

// Bounded on both sides, not merely present. A plain substring test silently
// skips the append whenever the marker occurs inside a larger token -- 'curl'
// within 'curl/8.4.0' is not the marker -- which sends unidentified traffic
// under a perimeter claiming to be identified.
function carriesMarkerToken(captured, marker) {
  let at = captured.indexOf(marker)
  while (at !== -1) {
    const startsToken = at === 0 || isFieldSeparator(captured[at - 1])
    const end = at + marker.length
    const endsToken = end === captured.length || isFieldSeparator(captured[end])
    if (startsToken && endsToken) return true
    at = captured.indexOf(marker, at + 1)
  }
  return false
}

// Already carrying the marker means a capture taken through our own proxy; a
// second copy would make the string drift further on every pass. Mirrored byte
// for byte by compose_user_agent in proxy/bounty_helpers.py, proven against
// fixtures/bounty/user-agent-cases.json.
export function composeUserAgent(captured, marker) {
  if (typeof captured !== 'string' || captured.trim().length === 0) return marker
  if (carriesMarkerToken(captured, marker)) return captured
  return `${captured} ${marker}`
}

export async function replayAsRole({
  request,
  role,
  sealedScope,
  limiter,
  fetchImpl = fetch,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  env = process.env,
}) {
  const { approval, refusal } = approveRequestTarget({ request, sealedScope })
  if (approval === null) {
    return {
      status: null,
      error: `out of scope: ${refusal.reason}`,
      refusal,
      normalized: null,
      role: role.id,
    }
  }
  assertApproved(approval)
  if (typeof limiter?.acquire !== 'function') {
    throw new Error('replayAsRole requires a rate limiter; the sealed limit is the authorization')
  }
  await limiter.acquire()

  let prepared
  try {
    prepared = applyRole(request, role, env)
  } catch (error) {
    // A missing credential must surface loudly rather than become a false denial.
    throw error
  }

  // A captured request carries the browser own User-Agent. The program mandates
  // an identifying marker so its logs can attribute the traffic, but a bare
  // marker is not a browser and bot protection answers one with a 403. So the
  // marker is APPENDED to what the capture carried: the request still looks like
  // the session it came from, and the marker is plainly there to be read. One
  // header value, not two headers, so the request stays unambiguous.
  let captured = null
  const headers = {}
  for (const [name, value] of Object.entries(prepared.headers)) {
    if (name.toLowerCase() === 'user-agent') {
      captured = value
      continue
    }
    headers[name] = value
  }
  headers['User-Agent'] = composeUserAgent(captured, approval.userAgent)

  try {
    const response = await fetchImpl(request.url, {
      method: request.method,
      headers,
      ...(prepared.body === null || request.method === 'GET' || request.method === 'HEAD'
        ? {}
        : { body: prepared.body }),
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
    })
    const contentType = response.headers?.get?.('content-type') ?? null
    let body = ''
    try {
      const text = await response.text()
      body = text.length > MAX_BODY_BYTES ? text.slice(0, MAX_BODY_BYTES) : text
    } catch {
      body = ''
    }
    return {
      status: response.status,
      error: null,
      refusal: null,
      role: role.id,
      contentType,
      normalized: normalizeResponse({
        status: response.status,
        headers: response.headers,
        body,
        contentType,
      }),
    }
  } catch (error) {
    return {
      status: null,
      error: `${error.name}: ${error.message}`.slice(0, 300),
      refusal: null,
      normalized: null,
      role: role.id,
    }
  }
}
