import { isIP } from 'node:net'

export const MAX_CANDIDATE_LENGTH = 4096

const ALLOWED_SCHEMES = new Set(['http:', 'https:'])
const DEFAULT_PORTS = new Map([
  ['http:', 80],
  ['https:', 443],
])

function refuse(reason) {
  return { ok: false, reason }
}

function normalizeHost(hostname) {
  let host = hostname.toLowerCase()
  if (host.startsWith('[') && host.endsWith(']')) {
    host = host.slice(1, -1)
  }
  if (host.endsWith('.')) {
    host = host.slice(0, -1)
    if (host.endsWith('.')) return null
  }
  if (host.length === 0) return null
  return host
}

export function canonicalizeCandidate(rawUrl) {
  try {
    if (typeof rawUrl !== 'string' || rawUrl.length === 0) {
      return refuse('candidate-not-a-string')
    }
    if (rawUrl.length > MAX_CANDIDATE_LENGTH) {
      return refuse('candidate-too-long')
    }
    let parsed
    try {
      parsed = new URL(rawUrl)
    } catch {
      return refuse('candidate-unparsable')
    }
    if (!ALLOWED_SCHEMES.has(parsed.protocol)) {
      return refuse('scheme-not-http')
    }
    if (parsed.username !== '' || parsed.password !== '') {
      return refuse('candidate-carries-userinfo')
    }
    const host = normalizeHost(parsed.hostname)
    if (host === null) {
      return refuse('host-not-canonicalizable')
    }
    const ipVersion = isIP(host)
    const hostKind = ipVersion === 4 ? 'ipv4' : ipVersion === 6 ? 'ipv6' : 'domain'
    const port = parsed.port === ''
      ? DEFAULT_PORTS.get(parsed.protocol)
      : Number.parseInt(parsed.port, 10)
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return refuse('port-not-valid')
    }
    const path = parsed.pathname === '' ? '/' : parsed.pathname
    return { ok: true, target: { scheme: parsed.protocol, host, port, path, hostKind } }
  } catch {
    return refuse('candidate-canonicalization-failed')
  }
}
