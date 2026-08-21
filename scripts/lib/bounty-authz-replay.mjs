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

  try {
    const response = await fetchImpl(request.url, {
      method: request.method,
      headers: prepared.headers,
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
