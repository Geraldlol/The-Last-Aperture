import { buildRegisterBody, decryptInteraction, unwrapAesKey } from './bounty-oob-crypto.mjs'

export const HOSTED_SERVERS = [
  'oast.fun',
  'oast.pro',
  'oast.site',
  'oast.live',
  'oast.online',
  'oast.me',
]

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
  const response = await fetchImpl(`https://${server}/register`, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: buildRegisterBody({ publicKeyBase64, secret, correlationId }),
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
  const response = await fetchImpl(
    `https://${server}/poll?id=${encodeURIComponent(correlationId)}&secret=${encodeURIComponent(secret)}`,
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
  const response = await fetchImpl(`https://${server}/deregister`, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify({ 'correlation-id': correlationId, 'secret-key': secret }),
  })
  await requireOk(response, 'deregister')
}
