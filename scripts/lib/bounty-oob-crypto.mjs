import {
  constants,
  createCipheriv,
  createDecipheriv,
  generateKeyPairSync,
  privateDecrypt,
} from 'node:crypto'

// Verified against oast.fun on 2026-08-21. The payload cipher is CTR, not CFB:
// CFB, OFB and CTR all derive their first keystream block from E(IV), so a wrong
// mode decrypts exactly 16 bytes correctly and then diverges. Re-probe a live
// server before changing any constant here.
export const INTERACTSH_CIPHER = 'aes-256-ctr'
export const INTERACTSH_IV_LENGTH = 16
export const INTERACTSH_OAEP_HASH = 'sha256'
export const INTERACTSH_RSA_MODULUS_BITS = 2048

export function generateSessionKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: INTERACTSH_RSA_MODULUS_BITS,
  })
  const pem = publicKey.export({ type: 'spki', format: 'pem' })
  return { publicKey, privateKey, publicKeyBase64: Buffer.from(pem).toString('base64') }
}

export function buildRegisterBody({ publicKeyBase64, secret, correlationId }) {
  return JSON.stringify({
    'public-key': publicKeyBase64,
    'secret-key': secret,
    'correlation-id': correlationId,
  })
}

export function unwrapAesKey({ privateKey, aesKeyBase64 }) {
  return privateDecrypt(
    { key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: INTERACTSH_OAEP_HASH },
    Buffer.from(aesKeyBase64, 'base64'),
  )
}

export function decryptInteraction({ aesKey, dataBase64 }) {
  const raw = Buffer.from(dataBase64, 'base64')
  if (raw.length <= INTERACTSH_IV_LENGTH) {
    throw new Error('interaction payload too short to carry an iv')
  }
  const decipher = createDecipheriv(INTERACTSH_CIPHER, aesKey, raw.subarray(0, INTERACTSH_IV_LENGTH))
  const plain = Buffer.concat([
    decipher.update(raw.subarray(INTERACTSH_IV_LENGTH)),
    decipher.final(),
  ]).toString('utf8')
  return JSON.parse(plain)
}

// Test-only inverse of decryptInteraction. Its existence is what lets the whole
// decryption path be exercised with no network and no live server.
export function sealInteractionForTest({ aesKey, interaction, iv }) {
  const cipher = createCipheriv(INTERACTSH_CIPHER, aesKey, iv)
  const body = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(interaction), 'utf8')),
    cipher.final(),
  ])
  return Buffer.concat([iv, body]).toString('base64')
}
