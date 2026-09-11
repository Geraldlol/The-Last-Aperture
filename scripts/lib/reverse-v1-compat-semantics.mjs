// Frozen read-side semantics from the native-interaction and web-session
// evidence 1.0.0 release at c2a2903. These historical rules exist only to
// validate already-emitted 1.0.0 records. New imports and contracts must use
// their current target-neutral classifiers and schema 1.1.0.

const LEGACY_V1_AUTH_PATH = /(?:^|\/)(?:auth|callback|checkdatacenter|checklogin|login|logon|oauth|session|signin|signout|sso|token)(?:\/|$)/iu
const LEGACY_V1_CREDENTIAL_COOKIE_TOKENS = new Set([
  'auth', 'authentication', 'bearer', 'credential', 'csrf', 'jwt', 'session',
  'sid', 'token', 'xsrf',
])
const LEGACY_V1_CREDENTIAL_COOKIE_COMPOUND_TOKEN = /^(?:(?:auth|session)(?:cookie|id)?|(?:access|auth|bearer|csrf|id|refresh|xsrf)token|sessid)$/iu
const LEGACY_V1_CREDENTIAL_COOKIE_EXACT = new Set([
  'aspxauth', 'cbh', 'connect.sid', 'fedauth', 'jsessionid', 'phpsessid',
])

export function legacyV1AuthPath(value) {
  return LEGACY_V1_AUTH_PATH.test(value)
}

export function legacyV1CredentialCookieName(value) {
  const normalized = value.toLowerCase().replace(/^[._-]+|[._-]+$/gu, '')
  if (LEGACY_V1_CREDENTIAL_COOKIE_EXACT.has(normalized)) return true
  return normalized
    .split(/[._-]+/u)
    .some((token) => (
      LEGACY_V1_CREDENTIAL_COOKIE_TOKENS.has(token)
      || LEGACY_V1_CREDENTIAL_COOKIE_COMPOUND_TOKEN.test(token)
    ))
}
