import { createHash, X509Certificate } from 'node:crypto'
import { lookup as nodeDnsLookup } from 'node:dns'
import { request as nodeHttpsRequest } from 'node:https'
import { BlockList, isIP } from 'node:net'
import { performance } from 'node:perf_hooks'
import { checkServerIdentity } from 'node:tls'
import { PLATFORM_SERIES } from './version.mjs'
import {
  resolveHttpReconRequestHeaders,
} from './http-recon-request-headers.mjs'

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

export const HTTP_RECON_LIMITS = Object.freeze({
  default_timeout_ms: 10_000,
  max_timeout_ms: 60_000,
  default_response_bytes: 64 * 1024,
  max_response_bytes: 1024 * 1024,
  default_proof_body_bytes: 16 * 1024,
  max_proof_body_bytes: 64 * 1024,
  max_response_header_bytes: 16 * 1024,
  max_dns_answers: 64,
})

const FIXED_REQUEST_HEADERS = Object.freeze({
  accept: '*/*',
  'accept-encoding': 'identity',
  'cache-control': 'no-store',
  connection: 'close',
  'user-agent': `red-team-audit-http-recon/${PLATFORM_SERIES}`,
})

const SAFE_RESPONSE_HEADERS = new Set([
  'access-control-allow-credentials',
  'access-control-allow-headers',
  'access-control-allow-methods',
  'access-control-allow-origin',
  'access-control-expose-headers',
  'accept-ranges',
  'age',
  'allow',
  'cache-control',
  'content-encoding',
  'content-language',
  'content-length',
  'content-security-policy',
  'content-type',
  'cross-origin-embedder-policy',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
  'date',
  'etag',
  'expires',
  'last-modified',
  'location',
  'permissions-policy',
  'referrer-policy',
  'retry-after',
  'server',
  'strict-transport-security',
  'transfer-encoding',
  'vary',
  'via',
  'x-content-type-options',
  'x-frame-options',
])

const REDACTED_RESPONSE_HEADERS = new Set([
  'authentication-info',
  'location',
  'proxy-authenticate',
  'proxy-authentication-info',
  'set-cookie',
  'set-cookie2',
  'www-authenticate',
])

const NON_PUBLIC_IPV4 = new BlockList()
for (const [address, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
]) {
  NON_PUBLIC_IPV4.addSubnet(address, prefix, 'ipv4')
}

const NON_PUBLIC_IPV6 = new BlockList()
for (const [address, prefix] of [
  ['::', 96],
  ['::ffff:0:0', 96],
  ['64:ff9b::', 96],
  ['64:ff9b:1::', 48],
  ['100::', 64],
  ['2001::', 23],
  ['2001:db8::', 32],
  ['2002::', 16],
  ['3fff::', 20],
  ['5f00::', 16],
  ['fc00::', 7],
  ['fe80::', 10],
  ['fec0::', 10],
  ['ff00::', 8],
]) {
  NON_PUBLIC_IPV6.addSubnet(address, prefix, 'ipv6')
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function createError(code, message, options = {}) {
  return new HttpReconTransportError(code, message, options)
}

export class HttpReconTransportError extends Error {
  constructor(code, message, {
    cause,
    details,
    requestMayHaveBeenSent = false,
  } = {}) {
    super(message, cause === undefined ? undefined : { cause })
    this.name = 'HttpReconTransportError'
    this.code = code
    this.request_may_have_been_sent = requestMayHaveBeenSent
    if (details !== undefined) this.details = details
  }
}

const STOP_CODES = Object.freeze({
  REDIRECT: 'HTTP_RECON_REDIRECT',
  RATE_LIMITED: 'HTTP_RECON_RATE_LIMITED',
  SERVER_ERROR: 'HTTP_RECON_SERVER_ERROR',
})

export class HttpReconStopCondition extends HttpReconTransportError {
  constructor(condition, message, result) {
    super(STOP_CODES[condition] ?? 'HTTP_RECON_STOP_CONDITION', message, {
      details: {
        condition,
        status: result?.status,
        url: result?.url,
      },
      requestMayHaveBeenSent: true,
    })
    this.name = 'HttpReconStopCondition'
    this.condition = condition
    this.status = result?.status
    this.result = result
  }
}

function invalid(message) {
  return createError('HTTP_RECON_INVALID_REQUEST', message)
}

function assertPlainObject(value, label) {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw invalid(`${label} must be a plain object`)
  }
}

function assertOnlyKeys(value, allowed, label) {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw invalid(`${label} does not permit ${JSON.stringify(key)}`)
    }
  }
}

function assertBoundedInteger(value, label, fallback, maximum) {
  const candidate = value ?? fallback
  if (
    !Number.isSafeInteger(candidate)
    || candidate < 1
    || candidate > maximum
  ) {
    throw invalid(`${label} must be an integer from 1 through ${maximum}`)
  }
  return candidate
}

function assertAbortSignal(signal) {
  if (
    signal !== undefined
    && (
      signal === null
      || typeof signal.aborted !== 'boolean'
      || typeof signal.addEventListener !== 'function'
      || typeof signal.removeEventListener !== 'function'
    )
  ) {
    throw invalid('signal must be an AbortSignal')
  }
}

function normalizeSha256(value, label) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) {
    throw invalid(`${label} must be a lowercase SHA-256 hex digest`)
  }
  return value
}

function normalizePin(value) {
  return normalizeSha256(value, 'tlsSpkiSha256')
}

function parseRequestUrl(value) {
  if (
    typeof value !== 'string'
    || value === ''
    || value !== value.trim()
    || /[\u0000-\u0020\u007f]/.test(value)
  ) {
    throw invalid('url must be one exact, non-empty URL string')
  }
  let url
  try {
    url = new URL(value)
  } catch (cause) {
    throw createError('HTTP_RECON_URL_INVALID', 'url is not a valid URL', {
      cause,
    })
  }
  if (url.protocol !== 'https:') {
    throw createError(
      'HTTP_RECON_HTTPS_REQUIRED',
      'HTTP reconnaissance permits HTTPS URLs only',
    )
  }
  if (url.username !== '' || url.password !== '') {
    throw createError(
      'HTTP_RECON_URL_CREDENTIALS_DENIED',
      'HTTP reconnaissance URLs must not contain credentials',
    )
  }
  if (url.hash !== '') {
    throw createError(
      'HTTP_RECON_URL_FRAGMENT_DENIED',
      'HTTP reconnaissance URLs must not contain fragments',
    )
  }
  if (url.search !== '') {
    throw createError(
      'HTTP_RECON_URL_QUERY_DENIED',
      'HTTP reconnaissance URLs must not contain query parameters',
    )
  }
  if (url.port === '0') {
    throw createError(
      'HTTP_RECON_URL_PORT_DENIED',
      'HTTP reconnaissance URLs must not use port zero',
    )
  }
  const hostname = url.hostname.startsWith('[') && url.hostname.endsWith(']')
    ? url.hostname.slice(1, -1)
    : url.hostname
  if (isIP(hostname) !== 0) {
    throw createError(
      'HTTP_RECON_LITERAL_IP_DENIED',
      'HTTP reconnaissance rejects literal IP targets',
    )
  }
  if (
    hostname.endsWith('.')
    || hostname.includes('*')
    || url.pathname.includes('\\')
    || /%(?:2e|2f|5c)/i.test(url.pathname)
    || url.pathname.split('/').some((part) => part === '.' || part === '..')
  ) {
    throw createError(
      'HTTP_RECON_URL_SCOPE_INVALID',
      'HTTP reconnaissance URL contains an ambiguous or unsupported target form',
    )
  }
  if (value !== url.href) {
    throw createError(
      'HTTP_RECON_URL_NOT_CANONICAL',
      'HTTP reconnaissance URL must equal its canonical serialization',
    )
  }
  return { url, hostname }
}

export function isPublicHttpReconAddress(address) {
  const family = isIP(address)
  if (family === 0) return false
  return family === 4
    ? !NON_PUBLIC_IPV4.check(address, 'ipv4')
    : !NON_PUBLIC_IPV6.check(address, 'ipv6')
}

function abortError(timedOut, requestMayHaveBeenSent = false) {
  return createError(
    timedOut ? 'HTTP_RECON_TIMEOUT' : 'HTTP_RECON_ABORTED',
    timedOut
      ? 'HTTP reconnaissance request timed out'
      : 'HTTP reconnaissance request was stopped',
    { requestMayHaveBeenSent },
  )
}

function compareDnsAnswers(left, right) {
  if (left.family !== right.family) return left.family - right.family
  if (left.address < right.address) return -1
  if (left.address > right.address) return 1
  return 0
}

export function resolveHttpReconDns(hostname, {
  lookup = nodeDnsLookup,
  signal,
  timedOut = () => false,
} = {}) {
  if (
    typeof hostname !== 'string'
    || hostname === ''
    || isIP(hostname) !== 0
  ) {
    throw invalid('DNS hostname must be a non-literal hostname')
  }
  if (typeof lookup !== 'function') {
    throw invalid('dependencies.dnsLookup must be a function')
  }
  assertAbortSignal(signal)
  return new Promise((resolve, reject) => {
    let settled = false
    let abortListenerBindingAttempted = false
    const removeAbortListener = () => {
      if (!abortListenerBindingAttempted) return
      abortListenerBindingAttempted = false
      try {
        signal?.removeEventListener('abort', onAbort)
      } catch {
        // Listener cleanup cannot replace the DNS result or primary failure.
      }
    }
    const finish = (callback, value) => {
      if (settled) return
      settled = true
      removeAbortListener()
      callback(value)
    }
    const onAbort = () => finish(reject, abortError(timedOut()))
    if (signal?.aborted) {
      onAbort()
      return
    }
    if (signal !== undefined) {
      abortListenerBindingAttempted = true
      try {
        signal.addEventListener('abort', onAbort, { once: true })
      } catch (cause) {
        finish(reject, cause)
        return
      }
      if (settled) return
    }
    try {
      lookup(hostname, { all: true, verbatim: true }, (error, answers) => {
        if (settled) return
        if (error) {
          finish(reject, createError(
            'HTTP_RECON_DNS_FAILED',
            `DNS resolution failed for ${hostname}`,
            { cause: error },
          ))
          return
        }
        if (!Array.isArray(answers) || answers.length === 0) {
          finish(reject, createError(
            'HTTP_RECON_DNS_EMPTY',
            `DNS returned no addresses for ${hostname}`,
          ))
          return
        }
        if (answers.length > HTTP_RECON_LIMITS.max_dns_answers) {
          finish(reject, createError(
            'HTTP_RECON_DNS_ANSWER_LIMIT',
            `DNS returned too many addresses for ${hostname}`,
          ))
          return
        }
        const normalized = []
        const seen = new Set()
        for (const answer of answers) {
          const address = answer?.address
          const family = answer?.family === 'IPv4'
            ? 4
            : (answer?.family === 'IPv6' ? 6 : answer?.family)
          if (
            typeof address !== 'string'
            || ![4, 6].includes(family)
            || isIP(address) !== family
            || !isPublicHttpReconAddress(address)
          ) {
            finish(reject, createError(
              'HTTP_RECON_DNS_SCOPE_DENIED',
              `DNS for ${hostname} returned an invalid, reserved, or non-public address`,
            ))
            return
          }
          const key = `${family}:${address}`
          if (!seen.has(key)) {
            seen.add(key)
            normalized.push({ address, family })
          }
        }
        const selected = normalized[0]
        const canonicalAnswers = [...normalized].sort(compareDnsAnswers)
        finish(resolve, {
          selected,
          answers: canonicalAnswers.map((answer) => ({ ...answer })),
          answer_count: canonicalAnswers.length,
          answer_sha256: sha256(Buffer.from(JSON.stringify({
            hostname,
            answers: canonicalAnswers,
          }), 'utf8')),
        })
      })
    } catch (cause) {
      finish(reject, createError(
        'HTTP_RECON_DNS_FAILED',
        `DNS resolution failed for ${hostname}`,
        { cause },
      ))
    }
  })
}

function pinnedLookup(hostname, selected) {
  return (requestedHostname, options, callback) => {
    if (requestedHostname !== hostname) {
      callback(createError(
        'HTTP_RECON_DNS_REBIND_DENIED',
        'HTTPS attempted to resolve a hostname other than the authorized target',
      ))
      return
    }
    const family = typeof options === 'number'
      ? options
      : (options?.family ?? 0)
    if (family !== 0 && family !== selected.family) {
      callback(createError(
        'HTTP_RECON_DNS_FAMILY_MISMATCH',
        'HTTPS requested a family other than the pinned DNS answer',
      ))
      return
    }
    if (typeof options === 'object' && options?.all === true) {
      callback(null, [{ ...selected }])
      return
    }
    callback(null, selected.address, selected.family)
  }
}

export function createHttpReconIdentity(
  expectedSpkiSha256,
  onVerified = () => {},
) {
  const expected = expectedSpkiSha256 === undefined
    ? undefined
    : normalizePin(expectedSpkiSha256)
  if (typeof onVerified !== 'function') {
    throw invalid('TLS verification observer must be a function')
  }
  return (hostname, certificate) => {
    const hostnameError = checkServerIdentity(hostname, certificate)
    if (hostnameError) {
      return createError(
        'HTTP_RECON_TLS_HOSTNAME_MISMATCH',
        'HTTP reconnaissance TLS hostname validation failed',
        { cause: hostnameError },
      )
    }
    try {
      const x509 = new X509Certificate(certificate.raw)
      const spki = x509.publicKey.export({ type: 'spki', format: 'der' })
      const actual = sha256(spki)
      if (expected !== undefined && actual !== expected) {
        return createError(
          'HTTP_RECON_TLS_PIN_MISMATCH',
          'HTTP reconnaissance TLS SPKI pin did not match',
        )
      }
      onVerified({
        spki_sha256: actual,
        certificate_sha256: sha256(x509.raw),
        valid_from: x509.validFrom,
        valid_to: x509.validTo,
        verification_mode: expected === undefined
          ? 'PKIX_HOSTNAME'
          : 'PKIX_HOSTNAME_AND_SPKI_PIN',
      })
      return undefined
    } catch (cause) {
      return createError(
        'HTTP_RECON_TLS_CERTIFICATE_INVALID',
        'HTTP reconnaissance TLS certificate identity could not be recorded',
        { cause },
      )
    }
  }
}

export function createPinnedHttpReconIdentity(
  expectedSpkiSha256,
  onVerified = () => {},
) {
  return createHttpReconIdentity(
    normalizePin(expectedSpkiSha256),
    onVerified,
  )
}

function responseHeaderPairs(response) {
  if (
    Array.isArray(response?.rawHeaders)
    && response.rawHeaders.length % 2 === 0
  ) {
    const pairs = []
    for (let index = 0; index < response.rawHeaders.length; index += 2) {
      pairs.push([response.rawHeaders[index], response.rawHeaders[index + 1]])
    }
    return pairs
  }
  const pairs = []
  for (const [name, rawValue] of Object.entries(response?.headers ?? {})) {
    for (const value of Array.isArray(rawValue) ? rawValue : [rawValue]) {
      pairs.push([name, value])
    }
  }
  return pairs
}

function boundedUtf8(value, maxBytes) {
  const bytes = Buffer.from(String(value), 'utf8')
  if (bytes.length <= maxBytes) {
    return { value: bytes.toString('utf8'), truncated: false }
  }
  return {
    value: bytes.subarray(0, maxBytes).toString('utf8'),
    truncated: true,
  }
}

function projectResponseHeaders(response) {
  const headers = []
  const redacted = new Set()
  let omitted = 0
  let totalBytes = 0
  let truncated = false
  for (const [rawName, rawValue] of responseHeaderPairs(response)) {
    const name = String(rawName).toLowerCase()
    if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name)) {
      omitted += 1
      continue
    }
    if (!SAFE_RESPONSE_HEADERS.has(name) && !REDACTED_RESPONSE_HEADERS.has(name)) {
      omitted += 1
      continue
    }
    let value
    if (REDACTED_RESPONSE_HEADERS.has(name)) {
      value = '[REDACTED]'
      if (redacted.has(name)) continue
      redacted.add(name)
    } else {
      const bounded = boundedUtf8(rawValue, 1024)
      value = bounded.value
      truncated ||= bounded.truncated
    }
    const entryBytes = Buffer.byteLength(name) + Buffer.byteLength(value)
    if (
      totalBytes + entryBytes > HTTP_RECON_LIMITS.max_response_header_bytes
      || headers.length >= 64
    ) {
      omitted += 1
      truncated = true
      continue
    }
    totalBytes += entryBytes
    headers.push({ name, value })
  }
  return {
    headers,
    summary: {
      retained_bytes: totalBytes,
      omitted_count: omitted,
      redacted_names: [...redacted].sort(),
      truncated,
    },
  }
}

function exactHeaderValues(response, expectedName) {
  return responseHeaderPairs(response)
    .filter(([name]) => String(name).toLowerCase() === expectedName)
    .map(([, value]) => String(value).trim().toLowerCase())
}

function normalizeDependencies(dependencies) {
  if (dependencies === undefined) dependencies = {}
  assertPlainObject(dependencies, 'dependencies')
  assertOnlyKeys(
    dependencies,
    new Set(['dnsLookup', 'httpsRequest', 'clock']),
    'dependencies',
  )
  const lookup = dependencies.dnsLookup ?? nodeDnsLookup
  const request = dependencies.httpsRequest ?? nodeHttpsRequest
  if (typeof lookup !== 'function') {
    throw invalid('dependencies.dnsLookup must be a function')
  }
  if (typeof request !== 'function') {
    throw invalid('dependencies.httpsRequest must be a function')
  }
  const suppliedClock = dependencies.clock
  if (
    suppliedClock !== undefined
    && typeof suppliedClock !== 'function'
    && (
      suppliedClock === null
      || typeof suppliedClock !== 'object'
      || typeof suppliedClock.now !== 'function'
    )
  ) {
    throw invalid('dependencies.clock must be a function or clock object')
  }
  const now = typeof suppliedClock === 'function'
    ? suppliedClock
    : (suppliedClock?.now?.bind(suppliedClock) ?? (() => performance.now()))
  const customSetTimer = suppliedClock?.setTimeout
  const customClearTimer = suppliedClock?.clearTimeout
  if (
    (customSetTimer !== undefined || customClearTimer !== undefined)
    && (
      typeof customSetTimer !== 'function'
      || typeof customClearTimer !== 'function'
    )
  ) {
    throw invalid('dependencies.clock timer methods must be functions')
  }
  const setTimer = customSetTimer === undefined
    ? globalThis.setTimeout.bind(globalThis)
    : customSetTimer.bind(suppliedClock)
  const clearTimer = customClearTimer === undefined
    ? globalThis.clearTimeout.bind(globalThis)
    : customClearTimer.bind(suppliedClock)
  return { lookup, request, now, setTimer, clearTimer }
}

function readClock(now) {
  const value = now()
  if (!Number.isFinite(value)) {
    throw invalid('dependencies.clock returned a non-finite value')
  }
  return value
}

function duration(start, end) {
  if (start === undefined || end === undefined) return null
  return Math.max(0, end - start)
}

function tlsMetadata(socket, verified, hostname, selected) {
  const cipher = socket?.getCipher?.()
  return {
    server_name: hostname,
    peer_ip: selected.address,
    peer_family: selected.family,
    spki_sha256: verified.spki_sha256,
    certificate_sha256: verified.certificate_sha256,
    valid_from: verified.valid_from,
    valid_to: verified.valid_to,
    verification_mode: verified.verification_mode,
    protocol: socket?.getProtocol?.() ?? null,
    cipher: cipher?.standardName ?? cipher?.name ?? null,
    authorized: socket?.authorized === true,
  }
}

function safeDestroy(value, error) {
  try {
    value?.destroy?.(error)
  } catch {
    // Destruction is best effort after the result/error has been decided.
  }
}

function wrapRequestError(error, requestMayHaveBeenSent) {
  if (error instanceof HttpReconTransportError) {
    error.request_may_have_been_sent ||= requestMayHaveBeenSent
    return error
  }
  return createError(
    'HTTP_RECON_REQUEST_FAILED',
    'HTTP reconnaissance HTTPS request failed',
    { cause: error, requestMayHaveBeenSent },
  )
}

function validateOptions(options, mode) {
  assertPlainObject(options, 'HTTP reconnaissance options')
  const allowed = new Set([
    'url',
    'method',
    'tlsVerificationMode',
    'tlsSpkiSha256',
    'expectedDnsSha256',
    'timeoutMs',
    'maxResponseBytes',
    'signal',
    'beforeSend',
    'requestHeaderProfile',
    'dependencies',
  ])
  if (mode === 'proof') allowed.add('maxProofBodyBytes')
  assertOnlyKeys(options, allowed, 'HTTP reconnaissance options')
  const { url, hostname } = parseRequestUrl(options.url)
  if (!SAFE_METHODS.has(options.method)) {
    throw createError(
      'HTTP_RECON_METHOD_DENIED',
      'HTTP reconnaissance permits HEAD, GET, or OPTIONS only',
    )
  }
  const tlsSpkiSha256 = options.tlsSpkiSha256 === undefined
    ? undefined
    : normalizePin(options.tlsSpkiSha256)
  const tlsVerificationMode = options.tlsVerificationMode
  if (!['PKIX_HOSTNAME', 'PKIX_HOSTNAME_AND_SPKI_PIN'].includes(
    tlsVerificationMode,
  )) {
    throw invalid('tlsVerificationMode must explicitly select a supported TLS policy')
  }
  if (
    (tlsVerificationMode === 'PKIX_HOSTNAME' && tlsSpkiSha256 !== undefined)
    || (
      tlsVerificationMode === 'PKIX_HOSTNAME_AND_SPKI_PIN'
      && tlsSpkiSha256 === undefined
    )
  ) {
    throw invalid('tlsVerificationMode and tlsSpkiSha256 do not describe one policy')
  }
  if (mode === 'proof' && tlsVerificationMode !== 'PKIX_HOSTNAME_AND_SPKI_PIN') {
    throw invalid('target-control proof HTTPS requires an explicit SPKI-pinned TLS policy')
  }
  if (mode === 'proof' && options.requestHeaderProfile !== undefined) {
    throw invalid('target-control proof HTTPS does not permit diagnostic request-header profiles')
  }
  let requestHeaders = {}
  let requestHeaderProfile
  if (options.requestHeaderProfile !== undefined) {
    try {
      requestHeaders = resolveHttpReconRequestHeaders({
        descriptor: options.requestHeaderProfile,
        method: options.method,
      })
      requestHeaderProfile = structuredClone(options.requestHeaderProfile)
    } catch (cause) {
      throw createError(
        'HTTP_RECON_HEADER_PROFILE_INVALID',
        'diagnostic request-header profile failed controller validation',
        { cause },
      )
    }
  }
  const expectedDnsSha256 = options.expectedDnsSha256 === undefined
    ? undefined
    : normalizeSha256(options.expectedDnsSha256, 'expectedDnsSha256')
  const timeoutMs = assertBoundedInteger(
    options.timeoutMs,
    'timeoutMs',
    HTTP_RECON_LIMITS.default_timeout_ms,
    HTTP_RECON_LIMITS.max_timeout_ms,
  )
  const maxResponseBytes = assertBoundedInteger(
    options.maxResponseBytes,
    'maxResponseBytes',
    HTTP_RECON_LIMITS.default_response_bytes,
    HTTP_RECON_LIMITS.max_response_bytes,
  )
  const maxProofBodyBytes = mode === 'proof'
    ? assertBoundedInteger(
        options.maxProofBodyBytes,
        'maxProofBodyBytes',
        HTTP_RECON_LIMITS.default_proof_body_bytes,
        HTTP_RECON_LIMITS.max_proof_body_bytes,
      )
    : 0
  assertAbortSignal(options.signal)
  if (
    options.beforeSend !== undefined
    && typeof options.beforeSend !== 'function'
  ) {
    throw invalid('beforeSend must be a function')
  }
  return {
    requestedUrl: options.url,
    url,
    hostname,
    method: options.method,
    tlsVerificationMode,
    tlsSpkiSha256,
    expectedDnsSha256,
    timeoutMs,
    maxResponseBytes,
    maxProofBodyBytes,
    signal: options.signal,
    beforeSend: options.beforeSend,
    requestHeaders,
    requestHeaderProfile,
    dependencies: normalizeDependencies(options.dependencies),
  }
}

function statusCondition(status) {
  if (status >= 300 && status <= 399) return 'REDIRECT'
  if (status === 429) return 'RATE_LIMITED'
  if (status >= 500 && status <= 599) return 'SERVER_ERROR'
  return null
}

async function runHttps(options, mode) {
  const requestOptions = validateOptions(options, mode)
  const {
    lookup,
    request: makeRequest,
    now,
    setTimer,
    clearTimer,
  } = requestOptions.dependencies
  const startedAt = readClock(now)
  const controller = new AbortController()
  let timedOut = false
  let request
  let requestMayHaveBeenSent = false
  const forwardStop = () => controller.abort()
  if (requestOptions.signal?.aborted) {
    throw abortError(false)
  }
  let forwardStopBindingAttempted = false
  let timer
  let timerCreated = false

  try {
    if (requestOptions.signal !== undefined) {
      forwardStopBindingAttempted = true
      requestOptions.signal.addEventListener('abort', forwardStop, { once: true })
    }
    timer = setTimer(() => {
      timedOut = true
      controller.abort()
    }, requestOptions.timeoutMs)
    timerCreated = true
    const dnsStartedAt = readClock(now)
    const dns = await resolveHttpReconDns(requestOptions.hostname, {
      lookup,
      signal: controller.signal,
      timedOut: () => timedOut,
    })
    const dnsFinishedAt = readClock(now)
    if (controller.signal.aborted) {
      throw abortError(timedOut)
    }
    if (
      requestOptions.expectedDnsSha256 !== undefined
      && dns.answer_sha256 !== requestOptions.expectedDnsSha256
    ) {
      throw createError(
        'HTTP_RECON_DNS_PIN_MISMATCH',
        'DNS answers did not match the authorized proof observation',
      )
    }

    let tlsVerified
    let tlsVerifiedAt
    const verifyIdentity = createHttpReconIdentity(
      requestOptions.tlsSpkiSha256,
      (metadata) => {
        tlsVerified = metadata
        tlsVerifiedAt = readClock(now)
      },
    )
    const checkIdentity = (hostname, certificate) => {
      if (hostname !== requestOptions.hostname) {
        return createError(
          'HTTP_RECON_TLS_HOSTNAME_MISMATCH',
          'HTTPS attempted to validate a hostname other than the authorized target',
        )
      }
      return verifyIdentity(requestOptions.hostname, certificate)
    }
    const requestCreatedAt = readClock(now)

    return await new Promise((resolve, reject) => {
      let settled = false
      let response
      let socket
      let sendAt
      let firstByteAt
      let responseFinishedAt
      let beforeSendStartedAt
      let beforeSendFinishedAt
      const bodyHash = createHash('sha256')
      const retainedChunks = []
      let capturedSize = 0
      let retainedSize = 0
      let responseTruncated = false

      const cleanup = () => {
        controller.signal.removeEventListener('abort', onAbort)
      }
      const finishResolve = (value) => {
        if (settled) return
        settled = true
        cleanup()
        resolve(value)
      }
      const finishReject = (error) => {
        if (settled) return
        settled = true
        cleanup()
        reject(wrapRequestError(error, requestMayHaveBeenSent))
      }
      const onAbort = () => {
        const error = abortError(timedOut, requestMayHaveBeenSent)
        finishReject(error)
        safeDestroy(response, error)
        safeDestroy(request, error)
      }

      const timing = () => ({
        dns_ms: duration(dnsStartedAt, dnsFinishedAt),
        tls_handshake_ms: duration(requestCreatedAt, tlsVerifiedAt),
        before_send_ms: duration(beforeSendStartedAt, beforeSendFinishedAt),
        time_to_first_byte_ms: duration(sendAt, firstByteAt),
        total_ms: duration(startedAt, responseFinishedAt),
      })

      const resultFor = ({
        status,
        headerProjection,
        digest,
        bodyBytes,
        bodyTruncated,
        digestScope,
      }) => ({
        schema_version: '1.0.0',
        requested_url: requestOptions.requestedUrl,
        url: requestOptions.url.href,
        method: requestOptions.method,
        status,
        response_headers: headerProjection.headers,
        response_header_summary: headerProjection.summary,
        body: {
          bytes: bodyBytes,
          sha256: digest,
          size: capturedSize,
          retained_size: bodyBytes === null ? 0 : bodyBytes.length,
          retained: bodyBytes !== null,
          truncated: bodyTruncated,
          digest_scope: digestScope,
        },
        dns: {
          answer_sha256: dns.answer_sha256,
          answer_count: dns.answer_count,
          answers: dns.answers.map((answer) => ({ ...answer })),
          selected_ip: dns.selected.address,
          selected_family: dns.selected.family,
        },
        tls: tlsMetadata(
          socket,
          tlsVerified,
          requestOptions.hostname,
          dns.selected,
        ),
        timing: timing(),
        request_may_have_been_sent: requestMayHaveBeenSent,
      })

      const onSecureConnect = async () => {
        if (settled || controller.signal.aborted) return
        if (
          tlsVerified === undefined
          || socket?.encrypted !== true
          || socket?.authorized !== true
        ) {
          const error = createError(
            'HTTP_RECON_TLS_VERIFICATION_MISSING',
            'HTTPS connection did not complete trusted TLS verification',
          )
          finishReject(error)
          safeDestroy(request, error)
          return
        }
        try {
          beforeSendStartedAt = readClock(now)
          await requestOptions.beforeSend?.({
            requested_url: requestOptions.requestedUrl,
            url: requestOptions.url.href,
            method: requestOptions.method,
            request_headers: requestOptions.requestHeaderProfile ?? null,
            dns: {
              answer_sha256: dns.answer_sha256,
              answer_count: dns.answer_count,
              answers: dns.answers.map((answer) => ({ ...answer })),
              selected_ip: dns.selected.address,
              selected_family: dns.selected.family,
            },
            tls: tlsMetadata(
              socket,
              tlsVerified,
              requestOptions.hostname,
              dns.selected,
            ),
          })
          beforeSendFinishedAt = readClock(now)
        } catch (cause) {
          const error = createError(
            'HTTP_RECON_BEFORE_SEND_REJECTED',
            'HTTP reconnaissance was not sent because beforeSend rejected',
            { cause },
          )
          finishReject(error)
          safeDestroy(request, error)
          return
        }
        if (settled || controller.signal.aborted) return
        sendAt = readClock(now)
        requestMayHaveBeenSent = true
        try {
          request.end()
        } catch (error) {
          finishReject(error)
        }
      }

      const onResponse = (received) => {
        if (settled) {
          safeDestroy(received)
          return
        }
        response = received
        firstByteAt = readClock(now)
        const status = response.statusCode
        if (!Number.isSafeInteger(status) || status < 200 || status > 599) {
          const error = createError(
            'HTTP_RECON_STATUS_INVALID',
            'HTTP reconnaissance received an invalid final status',
            { requestMayHaveBeenSent },
          )
          finishReject(error)
          safeDestroy(response, error)
          safeDestroy(request, error)
          return
        }
        if (tlsVerified === undefined) {
          const error = createError(
            'HTTP_RECON_TLS_VERIFICATION_MISSING',
            'HTTPS response arrived without trusted TLS verification',
            { requestMayHaveBeenSent },
          )
          finishReject(error)
          safeDestroy(response, error)
          safeDestroy(request, error)
          return
        }
        const headerProjection = projectResponseHeaders(response)
        const contentEncodings = exactHeaderValues(response, 'content-encoding')
        if (
          contentEncodings.length > 1
          || contentEncodings.some((value) => value !== 'identity')
        ) {
          const error = createError(
            'HTTP_RECON_CONTENT_ENCODING_DENIED',
            'HTTP reconnaissance rejects transformed response bodies',
            { requestMayHaveBeenSent },
          )
          finishReject(error)
          safeDestroy(response, error)
          safeDestroy(request, error)
          return
        }
        const stopCondition = statusCondition(status)
        if (stopCondition !== null) {
          responseFinishedAt = readClock(now)
          const result = resultFor({
            status,
            headerProjection,
            digest: sha256(Buffer.alloc(0)),
            bodyBytes: null,
            bodyTruncated: true,
            digestScope: 'captured-prefix',
          })
          const error = new HttpReconStopCondition(
            stopCondition,
            `HTTP reconnaissance stopped on HTTP ${status}`,
            result,
          )
          finishReject(error)
          safeDestroy(response)
          safeDestroy(request)
          return
        }

        response.on('data', (chunkValue) => {
          if (settled) return
          const chunk = Buffer.from(chunkValue)
          const remaining = requestOptions.maxResponseBytes - capturedSize
          const accepted = chunk.subarray(0, Math.max(0, remaining))
          if (accepted.length > 0) {
            bodyHash.update(accepted)
            capturedSize += accepted.length
            if (mode === 'proof' && retainedSize < requestOptions.maxProofBodyBytes) {
              const retain = accepted.subarray(
                0,
                requestOptions.maxProofBodyBytes - retainedSize,
              )
              if (retain.length > 0) {
                retainedChunks.push(Buffer.from(retain))
                retainedSize += retain.length
              }
            }
          }
          if (accepted.length !== chunk.length) {
            responseTruncated = true
            responseFinishedAt = readClock(now)
            const retainedBody = mode === 'proof'
              ? Buffer.concat(retainedChunks, retainedSize)
              : null
            const result = resultFor({
              status,
              headerProjection,
              digest: bodyHash.digest('hex'),
              bodyBytes: retainedBody,
              bodyTruncated: true,
              digestScope: 'captured-prefix',
            })
            finishResolve(result)
            safeDestroy(response)
            safeDestroy(request)
          }
        })
        response.once('aborted', () => {
          if (settled) return
          finishReject(createError(
            'HTTP_RECON_RESPONSE_TRUNCATED',
            'HTTP reconnaissance response ended before completion',
            { requestMayHaveBeenSent },
          ))
        })
        response.once('error', (error) => {
          if (!settled) finishReject(error)
        })
        response.once('end', () => {
          if (settled) return
          if (response.complete === false) {
            finishReject(createError(
              'HTTP_RECON_RESPONSE_TRUNCATED',
              'HTTP reconnaissance response ended before completion',
              { requestMayHaveBeenSent },
            ))
            return
          }
          responseFinishedAt = readClock(now)
          const retainedBody = mode === 'proof'
            ? Buffer.concat(retainedChunks, retainedSize)
            : null
          const retentionTruncated = mode === 'proof'
            && retainedSize < capturedSize
          finishResolve(resultFor({
            status,
            headerProjection,
            digest: bodyHash.digest('hex'),
            bodyBytes: retainedBody,
            bodyTruncated: responseTruncated || retentionTruncated,
            digestScope: responseTruncated ? 'captured-prefix' : 'complete',
          }))
        })
      }

      controller.signal.addEventListener('abort', onAbort, { once: true })
      try {
        request = makeRequest(requestOptions.url, {
          method: requestOptions.method,
          agent: false,
          headers: {
            ...FIXED_REQUEST_HEADERS,
            ...requestOptions.requestHeaders,
            host: requestOptions.url.host,
          },
          checkServerIdentity: checkIdentity,
          lookup: pinnedLookup(requestOptions.hostname, dns.selected),
          family: dns.selected.family,
          autoSelectFamily: false,
          servername: requestOptions.hostname,
          rejectUnauthorized: true,
          minVersion: 'TLSv1.2',
          ALPNProtocols: ['http/1.1'],
          insecureHTTPParser: false,
          maxHeaderSize: HTTP_RECON_LIMITS.max_response_header_bytes,
          timeout: requestOptions.timeoutMs,
        })
      } catch (error) {
        finishReject(error)
        return
      }
      request.once('socket', (connectedSocket) => {
        socket = connectedSocket
        socket?.once?.('secureConnect', () => {
          void onSecureConnect()
        })
      })
      request.once('timeout', () => {
        timedOut = true
        controller.abort()
      })
      request.once('error', (error) => {
        if (!settled) finishReject(error)
      })
      request.once('response', onResponse)
    })
  } finally {
    try {
      if (timerCreated) {
        try {
          clearTimer(timer)
        } catch {
          // The network result or primary error is already authoritative.
        }
      }
    } finally {
      if (forwardStopBindingAttempted) {
        forwardStopBindingAttempted = false
        try {
          requestOptions.signal?.removeEventListener('abort', forwardStop)
        } catch {
          // Listener cleanup cannot replace the result or primary failure.
        }
      }
    }
  }
}

/**
 * Perform one exact, bodyless HTTPS probe. Response bytes are hashed while
 * streaming and are never retained in the returned observation.
 */
export function probeHttps(options) {
  return runHttps(options, 'probe')
}

/**
 * Fetch a target-control proof with a separate, hard-bounded body allowance.
 */
export function fetchHttpsProof(options) {
  return runHttps(options, 'proof')
}
