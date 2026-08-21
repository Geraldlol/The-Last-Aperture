// Passive rules read responses we already have. No extra request, no risk, and
// the highest value-per-effort in the scanner.
//
// Two disciplines throughout:
//   1. High-confidence patterns only. A secret detector that fires on any
//      40-character string produces a triage flood and teaches the operator to
//      ignore it, which is worse than having none.
//   2. A match NEVER carries the matched secret. Findings get committed, shared,
//      and pasted into reports; copying a live key into one relocates the leak
//      instead of reporting it.

const SECRET_RULES = Object.freeze([
  { id: 'aws-access-key-id', label: 'AWS access key id', pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { id: 'google-api-key', label: 'Google API key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: 'slack-token', label: 'Slack token', pattern: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g },
  { id: 'stripe-live-key', label: 'Stripe live secret key', pattern: /\bsk_live_[0-9A-Za-z]{16,}\b/g },
  { id: 'github-token', label: 'GitHub token', pattern: /\bgh[pousr]_[0-9A-Za-z]{36,}\b/g },
  { id: 'private-key-block', label: 'PEM private key', pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g },
  { id: 'slack-webhook', label: 'Slack webhook URL', pattern: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Za-z_/-]{20,}/g },
  { id: 'jwt', label: 'JSON Web Token', pattern: /\beyJ[0-9A-Za-z_-]{10,}\.eyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\b/g },
])

const INTERNAL_HOST_RULES = Object.freeze([
  { id: 'internal-tld', label: 'internal hostname', pattern: /\b[a-z0-9][a-z0-9-]*\.(?:internal|intranet|corp|lan|localdomain)\b/gi },
  { id: 'rfc1918-address', label: 'RFC1918 address', pattern: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g },
  { id: 'cloud-metadata-address', label: 'cloud metadata endpoint', pattern: /\b(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)\b/g },
])

const ERROR_RULES = Object.freeze([
  { id: 'python-traceback', label: 'Python traceback', pattern: /Traceback \(most recent call last\)/ },
  { id: 'java-stack-trace', label: 'Java stack trace', pattern: /\bat [a-z0-9_.]+\.[A-Z][A-Za-z0-9_$]*\.[a-zA-Z0-9_$]+\([A-Za-z0-9_$]+\.java:\d+\)/ },
  { id: 'dotnet-stack-trace', label: '.NET stack trace', pattern: /\bat [A-Za-z0-9_.]+\+?[A-Za-z0-9_.]*\(.*\) in [A-Za-z]:\\/ },
  { id: 'php-error', label: 'PHP error or stack frame', pattern: /(?:Fatal error|Warning): .+ in \/[^\s]+ on line \d+|#\d+ \/(?:var|home|srv)\/[^\s(]+\(\d+\)/ },
  { id: 'node-stack-trace', label: 'Node stack trace', pattern: /\bat [A-Za-z0-9_.$]+ \((?:\/|[A-Za-z]:\\)[^)]*:\d+:\d+\)/ },
  { id: 'sql-error', label: 'SQL error', pattern: /\b(?:SQLSTATE\[|You have an error in your SQL syntax|Unclosed quotation mark after the character string|ORA-\d{5}|PG::SyntaxError|SQLiteException)/ },
  { id: 'rails-debug', label: 'Rails debug page', pattern: /Full Trace<\/a>|ActionController::RoutingError/ },
  { id: 'django-debug', label: 'Django debug page', pattern: /You're seeing this error because you have <code>DEBUG = True/ },
])

// Version-bearing headers only. A bare "Server: nginx" is not worth an
// operator's attention; "nginx/1.14.0" is, because it maps to advisories.
const DEBUG_HEADER_RULES = Object.freeze([
  { id: 'x-powered-by', header: 'x-powered-by', requireVersion: false },
  { id: 'x-aspnet-version', header: 'x-aspnet-version', requireVersion: false },
  { id: 'x-aspnetmvc-version', header: 'x-aspnetmvc-version', requireVersion: false },
  { id: 'x-debug-token', header: 'x-debug-token', requireVersion: false },
  { id: 'x-debug', header: 'x-debug', requireVersion: false },
  { id: 'x-runtime-version', header: 'x-runtime-version', requireVersion: false },
  { id: 'server-version', header: 'server', requireVersion: true },
  { id: 'via-version', header: 'via', requireVersion: true },
])

const VERSION_PATTERN = /\d+\.\d+/

// Never the value. Enough shape to recognise it again, nothing usable.
export function redactMatch(match) {
  const text = String(match)
  if (text.length <= 8) return `${text.slice(0, 2)}***`
  return `${text.slice(0, 4)}***${text.slice(-2)} (${text.length} chars)`
}

function scanPatterns(rules, text, kind) {
  const observations = []
  for (const rule of rules) {
    const pattern = new RegExp(rule.pattern.source, rule.pattern.flags.includes('g') ? rule.pattern.flags : `${rule.pattern.flags}g`)
    const seen = new Set()
    let match = pattern.exec(text)
    while (match !== null) {
      if (!seen.has(match[0])) {
        seen.add(match[0])
        observations.push({
          kind,
          rule_id: rule.id,
          label: rule.label,
          redacted: redactMatch(match[0]),
          occurrences: 1,
        })
      } else {
        const existing = observations.find((o) => o.rule_id === rule.id && o.redacted === redactMatch(match[0]))
        if (existing !== undefined) existing.occurrences += 1
      }
      if (match.index === pattern.lastIndex) pattern.lastIndex += 1
      match = pattern.exec(text)
    }
  }
  return observations
}

export function scanResponseBody(body) {
  if (typeof body !== 'string' || body.length === 0) return []
  return [
    ...scanPatterns(SECRET_RULES, body, 'secret'),
    ...scanPatterns(INTERNAL_HOST_RULES, body, 'internal-reference'),
    ...scanPatterns(ERROR_RULES, body, 'verbose-error'),
  ]
}

export function scanResponseHeaders(headers) {
  const observations = []
  if (headers === null || headers === undefined) return observations
  const get = typeof headers.get === 'function'
    ? (name) => headers.get(name)
    : (name) => headers[name]
  for (const rule of DEBUG_HEADER_RULES) {
    const value = get(rule.header)
    if (typeof value !== 'string' || value.length === 0) continue
    if (rule.requireVersion && !VERSION_PATTERN.test(value)) continue
    observations.push({
      kind: 'information-disclosure',
      rule_id: rule.id,
      label: `${rule.header} discloses ${rule.requireVersion ? 'a version' : 'implementation detail'}`,
      // Header values are not secrets, so they are recorded verbatim: the
      // version string is the whole point of the finding.
      value: value.slice(0, 128),
      occurrences: 1,
    })
  }
  return observations
}

export function scanResponse({ url, status, headers, body }) {
  const observations = [...scanResponseHeaders(headers), ...scanResponseBody(body)]
  return observations.map((observation) => ({ ...observation, url, status }))
}

export function summarizePassive(observations) {
  const byKind = {}
  for (const observation of observations) {
    byKind[observation.kind] = (byKind[observation.kind] ?? 0) + 1
  }
  return {
    total: observations.length,
    byKind,
    // Passive observations are leads, not findings. A disclosed version is not a
    // vulnerability, and calling it one is how a report gets closed as N/A.
    status: observations.length === 0 ? 'NOTHING_OBSERVED' : 'LEADS_OBSERVED',
  }
}
