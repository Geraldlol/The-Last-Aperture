import { buildRegisterBody, decryptInteraction, unwrapAesKey } from './bounty-oob-crypto.mjs'

export const HOSTED_SERVERS = Object.freeze([
  'oast.fun',
  'oast.pro',
  'oast.site',
  'oast.live',
  'oast.online',
  'oast.me',
])

const HOSTED_SERVER_SET = new Set(HOSTED_SERVERS)

export function assertHostedServerAllowed(server) {
  if (typeof server !== 'string' || !HOSTED_SERVER_SET.has(server)) {
    throw new Error('hosted OOB server is not in the fixed hosted OOB server allowlist')
  }
  return server
}

const JSON_HEADERS = { 'Content-Type': 'application/json' }

async function requireOk(response, what) {
  if (response.ok) return response
  const body = await response.text().catch(() => '')
  throw new Error(`interactsh ${what} failed: HTTP ${response.status} ${body.slice(0, 200)}`)
}

export async function registerHostedSession({
  server,
  correlationId,
  secret,
  publicKeyBase64,
  fetchImpl = fetch,
}) {
  const allowedServer = assertHostedServerAllowed(server)
  const response = await fetchImpl(`https://${allowedServer}/register`, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: buildRegisterBody({ publicKeyBase64, secret, correlationId }),
    redirect: 'error',
  })
  await requireOk(response, 'register')
}

export async function pollHostedSession({
  server,
  correlationId,
  secret,
  privateKey,
  fetchImpl = fetch,
}) {
  const allowedServer = assertHostedServerAllowed(server)
  const response = await fetchImpl(
    `https://${allowedServer}/poll?id=${encodeURIComponent(correlationId)}&secret=${encodeURIComponent(secret)}`,
    { redirect: 'error' },
  )
  await requireOk(response, 'poll')
  const body = await response.json()
  if (!Array.isArray(body.data) || body.data.length === 0) return []
  if (typeof body.aes_key !== 'string') {
    throw new Error('interactsh poll returned data without an aes key')
  }
  const aesKey = unwrapAesKey({ privateKey, aesKeyBase64: body.aes_key })
  return body.data.map((dataBase64) => decryptInteraction({ aesKey, dataBase64 }))
}

export async function deregisterHostedSession({
  server,
  correlationId,
  secret,
  fetchImpl = fetch,
}) {
  const allowedServer = assertHostedServerAllowed(server)
  const response = await fetchImpl(`https://${allowedServer}/deregister`, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify({ 'correlation-id': correlationId, 'secret-key': secret }),
    redirect: 'error',
  })
  await requireOk(response, 'deregister')
}
