import { createHash, timingSafeEqual } from 'node:crypto'

export const MAX_HTTP_AUTHED_CREDENTIAL_BYTES = 64 * 1024
export const HTTP_AUTHED_STDIN_CREDENTIAL_REF = 'stdin:PIPE'

export class HttpAuthedCredentialError extends Error {
  constructor(code, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'HttpAuthedCredentialError'
    this.code = code
  }
}

function credentialError(code, message, options) {
  return new HttpAuthedCredentialError(code, message, options)
}

function copyBytes(value) {
  if (typeof value === 'string' || Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return Buffer.from(value)
  }
  throw credentialError(
    'HTTP_AUTHED_CREDENTIAL_BYTES_REQUIRED',
    'the credential source did not provide bytes',
  )
}

function assertOpaqueHeaderValue(bytes) {
  if (bytes.length < 1 || bytes.length > MAX_HTTP_AUTHED_CREDENTIAL_BYTES) {
    throw credentialError(
      'HTTP_AUTHED_CREDENTIAL_LENGTH_INVALID',
      'the credential must be non-empty and within the credential byte limit',
    )
  }
  for (const byte of bytes) {
    if (byte < 0x20 || byte > 0x7e || byte === 0x7f) {
      throw credentialError(
        'HTTP_AUTHED_CREDENTIAL_CHARACTERS_INVALID',
        'the credential must be one printable ASCII HTTP header value',
      )
    }
  }
  const text = bytes.toString('ascii')
  if (/^\s*(?:cookie|authorization)\s*:/i.test(text)) {
    throw credentialError(
      'HTTP_AUTHED_CREDENTIAL_HEADER_PREFIX_REFUSED',
      'supply only the request-header value, without its header name or colon',
    )
  }
}

function assertCredentialKindValue(bytes, kind) {
  const text = bytes.toString('ascii')
  if (kind === 'cookie') return
  if (kind === 'bearer') {
    if (/^Bearer\s+/i.test(text)) {
      throw credentialError(
        'HTTP_AUTHED_CREDENTIAL_SCHEME_PREFIX_REFUSED',
        'supply only the bearer token; the controller adds the authorization scheme',
      )
    }
    return
  }
  throw credentialError(
    'HTTP_AUTHED_CREDENTIAL_KIND_INVALID',
    'the sealed credential kind is unsupported',
  )
}

function bindingDigest(bytes) {
  return createHash('sha256').update(bytes).digest()
}

function assertBinding(bytes, expectedBindingSha256) {
  if (expectedBindingSha256 === undefined) return
  if (!/^[a-f0-9]{64}$/.test(expectedBindingSha256)) {
    bytes.fill(0)
    throw credentialError(
      'HTTP_AUTHED_CREDENTIAL_BINDING_INVALID',
      'the sealed credential binding is invalid',
    )
  }
  const actual = bindingDigest(bytes)
  const expected = Buffer.from(expectedBindingSha256, 'hex')
  const matches = timingSafeEqual(actual, expected)
  actual.fill(0)
  expected.fill(0)
  if (!matches) {
    bytes.fill(0)
    throw credentialError(
      'HTTP_AUTHED_CREDENTIAL_BINDING_MISMATCH',
      'the supplied credential does not match the sealed credential binding',
    )
  }
}

export async function resolveHttpAuthedCredential({
  credential,
  env = process.env,
  transientCredential,
  credentialInput,
  readStdin = readHttpAuthedCredentialFromStdin,
}) {
  const reference = credential?.ref ?? ''
  const envMatch = /^env:([A-Za-z_][A-Za-z0-9_]*)$/.exec(reference)
  let source
  let ownedSource
  if (transientCredential !== undefined && credentialInput !== undefined) {
    throw credentialError(
      'HTTP_AUTHED_CREDENTIAL_SOURCE_AMBIGUOUS',
      'exactly one transient credential source may be supplied',
    )
  }
  if (envMatch) {
    if (transientCredential !== undefined || credentialInput !== undefined) {
      throw credentialError(
        'HTTP_AUTHED_CREDENTIAL_SOURCE_MISMATCH',
        'the supplied credential source does not match the sealed credential reference',
      )
    }
    try {
      source = env?.[envMatch[1]]
    } catch {
      throw credentialError(
        'HTTP_AUTHED_CREDENTIAL_UNAVAILABLE',
        'the referenced environment credential is unavailable',
      )
    }
    if (typeof source !== 'string' || source.length === 0) {
      throw credentialError(
        'HTTP_AUTHED_CREDENTIAL_UNAVAILABLE',
        'the referenced environment credential is unavailable',
      )
    }
  } else if (reference === HTTP_AUTHED_STDIN_CREDENTIAL_REF) {
    if (transientCredential === undefined && credentialInput === undefined) {
      throw credentialError(
        'HTTP_AUTHED_CREDENTIAL_UNAVAILABLE',
        'the sealed transient credential must be supplied through redirected stdin',
      )
    }
    if (transientCredential !== undefined) {
      source = transientCredential
    } else {
      if (typeof readStdin !== 'function') {
        throw credentialError(
          'HTTP_AUTHED_CREDENTIAL_STDIN_INVALID',
          'credential stdin reader is unavailable',
        )
      }
      ownedSource = await readStdin(credentialInput)
      source = ownedSource
    }
  } else {
    throw credentialError(
      'HTTP_AUTHED_CREDENTIAL_RESOLVER_UNAVAILABLE',
      'no runtime resolver is available for the sealed credential reference',
    )
  }

  const bytes = copyBytes(source)
  try {
    assertOpaqueHeaderValue(bytes)
    assertCredentialKindValue(bytes, credential?.kind)
    assertBinding(bytes, credential?.binding_sha256)
    return bytes
  } catch (error) {
    bytes.fill(0)
    throw error
  } finally {
    if (Buffer.isBuffer(ownedSource)) ownedSource.fill(0)
  }
}

export async function readHttpAuthedCredentialFromStdin(stream = process.stdin) {
  if (stream?.isTTY === true) {
    throw credentialError(
      'HTTP_AUTHED_CREDENTIAL_STDIN_TTY_REFUSED',
      'credential stdin must be redirected; interactive terminal entry is refused',
    )
  }
  if (stream === null || typeof stream?.[Symbol.asyncIterator] !== 'function') {
    throw credentialError(
      'HTTP_AUTHED_CREDENTIAL_STDIN_INVALID',
      'credential stdin is unavailable',
    )
  }

  const chunks = []
  let combined
  try {
    let total = 0
    for await (const chunk of stream) {
      const copy = copyBytes(chunk)
      chunks.push(copy)
      total += copy.length
      if (total > MAX_HTTP_AUTHED_CREDENTIAL_BYTES + 2) {
        throw credentialError(
          'HTTP_AUTHED_CREDENTIAL_LENGTH_INVALID',
          'the credential exceeds the credential byte limit',
        )
      }
    }
    combined = Buffer.concat(chunks, total)
    let end = combined.length
    if (end > 0 && combined[end - 1] === 0x0a) {
      end -= 1
      if (end > 0 && combined[end - 1] === 0x0d) end -= 1
    }
    const credential = Buffer.from(combined.subarray(0, end))
    try {
      assertOpaqueHeaderValue(credential)
      return credential
    } catch (error) {
      credential.fill(0)
      throw error
    }
  } catch (cause) {
    if (cause instanceof HttpAuthedCredentialError) throw cause
    throw credentialError(
      'HTTP_AUTHED_CREDENTIAL_STDIN_READ_FAILED',
      'the redirected credential could not be read',
    )
  } finally {
    combined?.fill(0)
    for (const chunk of chunks) chunk.fill(0)
  }
}
