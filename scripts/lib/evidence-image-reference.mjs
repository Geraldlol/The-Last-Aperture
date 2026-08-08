const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/
const HOST_PATTERN = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*(:[0-9]{1,5})?$/
const REPOSITORY_PATTERN = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$/
const CREDENTIAL_REF_PATTERN = /^(?:env|file|keychain|vault):[A-Za-z0-9._/-]{1,256}$/

const CREDENTIAL_VALUE_PATTERNS = [
  /\b(?:password|passwd|secret|token|api[_-]?key)\s*[:=]/i,
  /\b[a-z]+:\/\/[^/\s:@]+:[^/\s@]+@/i,
  /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/,
  /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b/,
  /\beyJ[A-Za-z0-9_-]{8,}\./,
]

/**
 * A tag is not an identity. The same tag resolves differently tomorrow, which
 * makes a bundle unreproducible and every finding citing it uncheckable — and
 * exact re-verification is the one guarantee a bundle has that a repository
 * checkout does not.
 */
export function parsePinnedImageReference(value) {
  const reference = String(value).trim()
  const at = reference.lastIndexOf('@')
  if (at === -1) {
    throw new Error(
      `image reference must be digest-pinned as <repository>@sha256:<64 hex>: ${reference}`,
    )
  }
  const digest = reference.slice(at + 1)
  if (!DIGEST_PATTERN.test(digest)) {
    throw new Error(`image digest must match sha256:<64 hex>: ${digest}`)
  }
  const name = reference.slice(0, at)

  const slash = name.indexOf('/')
  const first = slash === -1 ? '' : name.slice(0, slash)
  const looksLikeHost = first.includes('.') || first.includes(':') || first === 'localhost'
  const registry = looksLikeHost ? first : 'docker.io'
  const repository = looksLikeHost ? name.slice(slash + 1) : name

  // A tag would sit in the repository half; catching it here rather than by
  // scanning the whole reference keeps a registry port (host:5000) legal.
  if (repository.includes(':')) {
    throw new Error(
      `a digest-pinned reference carries no tag; drop the tag from ${name}`,
    )
  }
  if (!HOST_PATTERN.test(registry)) throw new Error(`invalid registry host: ${registry}`)
  if (!REPOSITORY_PATTERN.test(repository)) throw new Error(`invalid repository name: ${repository}`)

  return {
    registry,
    repository,
    digest,
    canonical: `${looksLikeHost ? `${registry}/` : ''}${repository}@${digest}`,
  }
}

/**
 * Only a reference, never a value. The reference names where a credential
 * lives; the acquisition process resolves it at run time and it never lands
 * in a bundle, a log line, or an error message.
 */
export function sealCredentialRef(value) {
  const reference = String(value).trim()
  if (CREDENTIAL_VALUE_PATTERNS.some((pattern) => pattern.test(reference))) {
    throw new Error(
      'that looks like a credential value; supply a credential reference such as '
      + 'env:REGISTRY_TOKEN instead',
    )
  }
  if (!CREDENTIAL_REF_PATTERN.test(reference)) {
    throw new Error(
      'a credential reference names its resolver: env:, file:, keychain: or vault:',
    )
  }
  return { credential_ref: reference }
}

export function redactForLog(text) {
  return String(text)
    .replace(/([a-z]+:\/\/[^/\s:@]+):[^/\s@]+@/gi, '$1:[REDACTED]@')
    .replace(/\b(Bearer|Basic)\s+\S+/gi, '$1 [REDACTED]')
    .replace(/\b((?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*)\S+/gi, '$1[REDACTED]')
}
