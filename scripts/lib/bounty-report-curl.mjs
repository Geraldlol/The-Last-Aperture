// A report is a document handed to someone else. It must reproduce the finding
// and must not carry the researcher's live session, so credentials appear as
// shell variable references and never as values. The role registry already keeps
// secrets in environment variables, so the placeholder names the same variable
// the operator used -- the command is runnable by them and inert to everyone else.

import { SENSITIVE_HEADERS } from './bounty-authz-request.mjs'

// Single-quote for POSIX sh, escaping embedded single quotes the portable way.
export function shellQuote(value) {
  const text = String(value)
  return `'${text.replaceAll("'", `'\\''`)}'`
}

export function credentialPlaceholder(role) {
  if (role === null || role === undefined) return null
  if (role.auth?.kind === 'none') return null
  const variable = role.auth?.value_env
  return typeof variable === 'string' && variable.length > 0 ? `$${variable}` : '$CREDENTIAL'
}

// Headers worth reproducing: the ones that change how the request is routed or
// parsed. A full browser header dump makes a repro that nobody reads and that
// breaks when a User-Agent string ages out.
const REPRODUCIBLE_HEADERS = new Set([
  'content-type',
  'accept',
  'x-requested-with',
  'origin',
  'referer',
])

export function buildReproCurl({ request, role, includeHeaders = REPRODUCIBLE_HEADERS }) {
  const lines = [`curl -i -s -X ${String(request.method).toUpperCase()} \\`]

  for (const [name, value] of Object.entries(request.headers ?? {})) {
    if (SENSITIVE_HEADERS.has(name)) continue
    if (!includeHeaders.has(name)) continue
    lines.push(`  -H ${shellQuote(`${name}: ${value}`)} \\`)
  }

  const placeholder = credentialPlaceholder(role)
  if (placeholder !== null) {
    const kind = role.auth.kind
    const headerName = kind === 'cookie' ? 'Cookie' : role.auth.name
    const headerValue = kind === 'cookie'
      ? `${role.auth.name}=${placeholder}`
      : placeholder
    // Deliberately double-quoted so the shell expands the variable, and
    // deliberately a reference so the secret is never written down.
    lines.push(`  -H "${headerName}: ${headerValue}" \\`)
  }

  if (typeof request.body === 'string' && request.body.length > 0
      && !['GET', 'HEAD'].includes(String(request.method).toUpperCase())) {
    lines.push(`  --data-raw ${shellQuote(request.body)} \\`)
  }

  lines.push(`  ${shellQuote(request.url)}`)
  return lines.join('\n')
}

export function reproPreamble(roles) {
  const needed = roles
    .map((role) => credentialPlaceholder(role))
    .filter((placeholder) => placeholder !== null)
    .map((placeholder) => placeholder.slice(1))
  if (needed.length === 0) return null
  const unique = [...new Set(needed)]
  return [
    '# Set these to the session values for the accounts named below.',
    '# They are intentionally absent from this report.',
    ...unique.map((variable) => `export ${variable}='...'`),
  ].join('\n')
}

// Asserts the invariant rather than trusting it: a report that leaks a token is
// worse than no report, and this is the last gate before one is written.
export function assertNoSecretLeak(text, secrets) {
  for (const secret of secrets) {
    if (typeof secret !== 'string' || secret.length === 0) continue
    if (text.includes(secret)) {
      throw new Error('refusing to emit a report containing a credential value')
    }
  }
}
