export const OOB_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789'
export const CORRELATION_ID_LENGTH = 20
export const NONCE_LENGTH = 13

function pick(randomBytes, length) {
  const bytes = randomBytes(length)
  let out = ''
  for (let index = 0; index < length; index += 1) {
    out += OOB_ALPHABET[bytes[index] % OOB_ALPHABET.length]
  }
  return out
}

export function createCorrelationId(randomBytes) {
  return pick(randomBytes, CORRELATION_ID_LENGTH)
}

export function mintNonce(randomBytes) {
  return pick(randomBytes, NONCE_LENGTH)
}

export function buildPayloadHost({ correlationId, nonce, server }) {
  if (typeof correlationId !== 'string' || correlationId.length !== CORRELATION_ID_LENGTH) {
    throw new Error(`correlation id must be ${CORRELATION_ID_LENGTH} characters`)
  }
  if (typeof nonce !== 'string' || nonce.length !== NONCE_LENGTH) {
    throw new Error(`nonce must be ${NONCE_LENGTH} characters`)
  }
  if (typeof server !== 'string' || server.length === 0) {
    throw new Error('server is required')
  }
  return `${correlationId}${nonce}.${server}`.toLowerCase()
}

// Callback identifiers arrive in two shapes, and both must correlate.
//
// A hosted interactsh server reports `full-id` as the bare 33-character label
// with no domain attached ("<cid><nonce>"). Our own DNS listener sees the name
// the resolver actually asked for, which is a full FQDN
// ("<cid><nonce>.oob.example"), and a target may prepend further labels.
//
// So the domain suffix is stripped when present and simply absent otherwise.
// Requiring it -- as an earlier version did -- silently dropped every real
// hosted callback while every offline test still passed.
export function extractNonce({ host, correlationId, server }) {
  if (typeof host !== 'string' || host.length === 0) return null
  if (typeof correlationId !== 'string' || typeof server !== 'string') return null
  let normalized = host.toLowerCase()
  if (normalized.endsWith('.')) normalized = normalized.slice(0, -1)
  const suffix = `.${server.toLowerCase()}`
  if (normalized.endsWith(suffix)) {
    normalized = normalized.slice(0, -suffix.length)
  }
  const labels = normalized.split('.')
  const candidate = labels[labels.length - 1]
  if (candidate === undefined) return null
  if (candidate.length !== CORRELATION_ID_LENGTH + NONCE_LENGTH) return null
  if (!candidate.startsWith(correlationId.toLowerCase())) return null
  return candidate.slice(CORRELATION_ID_LENGTH)
}

export function createMintLedger() {
  return { schema_version: '1.0.0', mints: {} }
}

export function recordMint(ledger, mint) {
  const nonce = String(mint.nonce).toLowerCase()
  if (nonce.length !== NONCE_LENGTH) {
    throw new Error(`nonce must be ${NONCE_LENGTH} characters`)
  }
  if (Object.hasOwn(ledger.mints, nonce)) {
    throw new Error(`nonce already minted: ${nonce}`)
  }
  return {
    ...ledger,
    mints: {
      ...ledger.mints,
      [nonce]: {
        nonce,
        label: mint.label,
        requestId: mint.requestId,
        insertionPoint: mint.insertionPoint,
        role: mint.role,
        bugClass: mint.bugClass,
        mintedAt: mint.mintedAt,
      },
    },
  }
}

export function lookupMint(ledger, nonce) {
  if (typeof nonce !== 'string') return null
  return ledger.mints[nonce.toLowerCase()] ?? null
}
