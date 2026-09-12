import { assertApproved, gateCandidates } from './bounty-recon-gate.mjs'
import { normalizeResponse } from './bounty-authz-normalize.mjs'
import { applyRole } from './bounty-authz-roles.mjs'
import { sanitizeCapturedRequest } from './bounty-authz-request.mjs'

const DEFAULT_TIMEOUT_MS = 15000
const MAX_BODY_BYTES = 512 * 1024

function cancelReaderWithoutWaiting(reader) {
  try {
    Promise.resolve(reader.cancel()).catch(() => {})
  } catch {}
}

function boundedUtf8(chunks, length) {
  const captured = Buffer.concat(chunks, length)
  let reencoded = null
  try {
    const decoded = captured.toString('utf8')
    if (Buffer.byteLength(decoded, 'utf8') <= MAX_BODY_BYTES) {
      return { body: decoded, truncated: false }
    }
    reencoded = Buffer.from(decoded, 'utf8')
    let end = MAX_BODY_BYTES
    while (end > 0 && (reencoded[end] & 0xc0) === 0x80) end -= 1
    return { body: reencoded.subarray(0, end).toString('utf8'), truncated: true }
  } finally {
    captured.fill(0)
    reencoded?.fill(0)
  }
}

function containsRedactedPlaceholder(request) {
  if (typeof request.body === 'string') {
    if (/<redacted>/iu.test(request.body)) return true
    const contentType = String(request.headers?.['content-type'] ?? '').toLowerCase()
    if (contentType.includes('json') || /^[\s\r\n]*[\[{]/u.test(request.body)) {
      try {
        const containsStructuredPlaceholder = (value, depth = 0) => {
          if (typeof value === 'string') return /<redacted>/iu.test(value)
          if (value === null || typeof value !== 'object') return false
          if (depth > 64) return true
          return Object.values(value).some((child) => (
            containsStructuredPlaceholder(child, depth + 1)
          ))
        }
        if (containsStructuredPlaceholder(JSON.parse(request.body))) return true
      } catch {
        // The capture normalizer handles malformed bodies; keep checking other carriers here.
      }
    }
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const form = new URLSearchParams(request.body)
      if ([...form.values()].some((value) => /<redacted>/iu.test(value))) return true
    }
  }
  try {
    const parsed = new URL(request.url)
    return [...parsed.searchParams.values()].some((value) => /<redacted>/iu.test(value))
  } catch {
    return false
  }
}

function unresolvedRedactedHeaders(request, role) {
  const redacted = new Set(role?.auth?.kind === 'none'
    ? []
    : (Array.isArray(request.redacted_headers) ? request.redacted_headers : []))
  for (const [name, value] of Object.entries(request.headers ?? {})) {
    if (/<redacted>/iu.test(String(value))) redacted.add(name)
  }
  const reconstructed = role?.auth?.kind === 'header'
    ? String(role.auth.name).toLowerCase()
    : role?.auth?.kind === 'cookie'
      ? 'cookie'
      : null
  return [...redacted]
    .map((name) => name.toLowerCase())
    .filter((name) => name !== reconstructed)
    .sort()
}

async function readBoundedResponseBody(response, { abortController, withinDeadline }) {
  if (response.body === null || response.body === undefined) {
    return { body: '', truncated: false }
  }
  if (typeof response.body.getReader !== 'function') {
    throw new TypeError('response body is not stream-readable')
  }
  const reader = response.body.getReader()
  const chunks = []
  let length = 0
  try {
    while (true) {
      const pendingRead = Promise.resolve().then(() => reader.read())
      let part
      try {
        part = await withinDeadline(() => pendingRead)
      } catch (error) {
        pendingRead.then((latePart) => {
          if (latePart?.value instanceof Uint8Array) latePart.value.fill(0)
        }, () => {})
        throw error
      }
      if (part.done) {
        if (part.value instanceof Uint8Array) part.value.fill(0)
        break
      }
      if (!(part.value instanceof Uint8Array)) {
        throw new TypeError('response stream returned a non-byte chunk')
      }
      const remaining = MAX_BODY_BYTES - length
      const overflow = part.value.byteLength > remaining
      if (remaining > 0) {
        const retained = part.value.byteLength > remaining
          ? part.value.subarray(0, remaining)
          : part.value
        chunks.push(Buffer.from(retained))
        length += retained.byteLength
      }
      part.value.fill(0)
      if (overflow) {
        abortController.abort(new Error('response body exceeded the size limit'))
        cancelReaderWithoutWaiting(reader)
        const decoded = boundedUtf8(chunks, length)
        return { body: decoded.body, truncated: true }
      }
    }
    return boundedUtf8(chunks, length)
  } catch (error) {
    cancelReaderWithoutWaiting(reader)
    throw error
  } finally {
    for (const chunk of chunks) chunk.fill(0)
    chunks.length = 0
    length = 0
  }
}

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
  onResponseSettled = null,
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
  let safeRequest
  try {
    safeRequest = sanitizeCapturedRequest(request)
  } catch {
    return {
      status: null,
      error: 'captured request could not be safely normalized and redacted before replay',
      refusal: null,
      normalized: null,
      role: role.id,
    }
  }
  if (
    (Array.isArray(safeRequest.redacted_query_parameters) && safeRequest.redacted_query_parameters.length > 0)
    || (Array.isArray(safeRequest.redacted_body_fields) && safeRequest.redacted_body_fields.length > 0)
    || containsRedactedPlaceholder(safeRequest)
  ) {
    return {
      status: null,
      error: 'captured query or body credentials were redacted; a transient site adapter is required before replay',
      refusal: null,
      normalized: null,
      role: role.id,
    }
  }
  const unresolvedHeaders = unresolvedRedactedHeaders(safeRequest, role)
  if (unresolvedHeaders.length > 0) {
    return {
      status: null,
      error: `captured header ${unresolvedHeaders[0]} was redacted and the selected role cannot reconstruct it; a transient site adapter is required before replay`,
      refusal: null,
      normalized: null,
      role: role.id,
    }
  }
  assertApproved(approval)
  if (typeof limiter?.acquire !== 'function') {
    throw new Error('replayAsRole requires a rate limiter; the sealed limit is the authorization')
  }
  if (onResponseSettled !== null && typeof onResponseSettled !== 'function') {
    throw new Error('onResponseSettled must be a function')
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) {
    throw new Error('replay timeout must be an integer from 1 through 120000 milliseconds')
  }
  await limiter.acquire()

  let prepared
  try {
    prepared = applyRole(safeRequest, role, env)
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

  const abortController = new AbortController()
  let timeoutReject
  let timedOut = false
  const clockNow = () => globalThis.performance?.now?.() ?? Date.now()
  const expiresAt = clockNow() + timeoutMs
  const timeoutError = new Error('bounty replay timed out')
  timeoutError.name = 'TimeoutError'
  const deadline = new Promise((resolve, reject) => { timeoutReject = reject })
  const timeout = setTimeout(() => {
    timedOut = true
    abortController.abort(timeoutError)
    timeoutReject(timeoutError)
  }, timeoutMs)
  const ensureDeadline = () => {
    if (!timedOut && clockNow() < expiresAt) return
    timedOut = true
    if (!abortController.signal.aborted) abortController.abort(timeoutError)
    throw timeoutError
  }
  const withinDeadline = async (operation) => {
    ensureDeadline()
    const result = await Promise.race([Promise.resolve().then(operation), deadline])
    ensureDeadline()
    return result
  }
  const settleFailureWithinBound = async (settlement) => {
    let rejectSettlement
    const settlementDeadline = new Promise((_resolve, reject) => { rejectSettlement = reject })
    const settlementTimeout = setTimeout(() => rejectSettlement(timeoutError), timeoutMs)
    try {
      await Promise.race([
        Promise.resolve().then(() => onResponseSettled(settlement)),
        settlementDeadline,
      ])
    } finally {
      clearTimeout(settlementTimeout)
    }
  }
  let response = null
  let responseSettled = false
  try {
    response = await withinDeadline(() => fetchImpl(prepared.url, {
      method: prepared.method,
      headers,
      ...(prepared.body === null || prepared.method === 'GET' || prepared.method === 'HEAD'
        ? {}
        : { body: prepared.body }),
      redirect: 'manual',
      signal: abortController.signal,
    }))
    const responseMetadata = await withinDeadline(() => ({
      status: response?.status,
      headers: response?.headers,
    }))
    const contentType = await withinDeadline(
      () => responseMetadata.headers?.get?.('content-type') ?? null,
    )
    const observed = await readBoundedResponseBody(response, { abortController, withinDeadline })
    const normalized = await withinDeadline(() => normalizeResponse({
      status: responseMetadata.status,
      headers: responseMetadata.headers,
      body: observed.body,
      contentType,
    }))
    if (onResponseSettled !== null) {
      responseSettled = true
      await withinDeadline(() => onResponseSettled({
        outcome: 'RETURNED', httpStatus: responseMetadata.status, errorName: null,
      }))
    }
    const result = await withinDeadline(() => ({
      status: responseMetadata.status,
      error: null,
      refusal: null,
      role: role.id,
      contentType,
      responseTruncated: observed.truncated,
      normalized,
    }))
    return result
  } catch (error) {
    if (response !== null && !responseSettled && onResponseSettled !== null) {
      responseSettled = true
      await settleFailureWithinBound({
        outcome: 'THREW',
        httpStatus: null,
        errorName: String(error?.name ?? 'Error').slice(0, 160),
      })
    }
    return {
      status: null,
      error: `${timedOut ? 'TimeoutError' : (error?.name ?? 'Error')}: ${error?.message ?? String(error)}`.slice(0, 300),
      refusal: null,
      normalized: null,
      role: role.id,
    }
  } finally {
    clearTimeout(timeout)
  }
}
