import { Buffer } from 'node:buffer'
import { lookup as nodeDnsLookup } from 'node:dns'
import { request as nodeHttpsRequest } from 'node:https'
import {
  httpAuthedAuthorizationEvidence,
  isHttpAuthedBrowserSessionCredential,
  sha256Hex,
  verifyHttpAuthedCandidate,
} from './http-authed-contracts.mjs'
import {
  createHttpReconIdentity,
  HttpReconTransportError,
  resolveHttpReconDns,
} from './http-recon-client.mjs'
import {
  HTTP_AUTHED_JSON_SHAPE_FAILURE_STAGE,
  httpAuthedResponseByteBucket,
  sanitizeHttpAuthedHeaderNames,
} from './http-authed-response-metadata.mjs'
import {
  observeHttpAuthedJsonShape,
  sanitizeHttpAuthedJsonShape,
} from './http-authed-json-shape.mjs'
import { PLATFORM_SERIES } from './version.mjs'

const MAX_CREDENTIAL_BYTES = 64 * 1024
const intrinsicByteFill = Uint8Array.prototype.fill
const OBSERVABLE_RESPONSE_HEADERS = new Set([
  'allow',
  'content-encoding',
  'content-type',
  'link',
  'location',
])

export class HttpAuthedClientError extends Error {
  constructor(code, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'HttpAuthedClientError'
    this.code = code
    this.request_may_have_been_sent = options.requestMayHaveBeenSent === true
  }
}

function clientError(code, message, options) {
  return new HttpAuthedClientError(code, message, options)
}

function eraseBytes(value) {
  try {
    if (value instanceof Uint8Array) Reflect.apply(intrinsicByteFill, value, [0])
  } catch {
    // Cleanup is best-effort. A dependency may detach or resize handed-off storage.
  }
}

function copyToOwnedBuffer(value) {
  let temporarySource
  let bytes
  let copied = false
  try {
    const source = typeof value === 'string'
      ? (temporarySource = Buffer.from(value))
      : value
    const storage = new ArrayBuffer(source.byteLength)
    bytes = Buffer.from(storage)
    bytes.set(source)
    copied = true
    return bytes
  } finally {
    eraseBytes(temporarySource)
    if (!copied) eraseBytes(bytes)
  }
}

function exactBytes(value, label, maxBytes, {
  minimum = 1,
  dedicated = false,
} = {}) {
  if (!(typeof value === 'string' || Buffer.isBuffer(value) || value instanceof Uint8Array)) {
    throw clientError('HTTP_AUTHED_BYTES_REQUIRED', `${label} must be supplied as bytes`)
  }
  const expectedByteLength = typeof value === 'string'
    ? Buffer.byteLength(value)
    : value.byteLength
  const invalidLength = () => clientError(
    'HTTP_AUTHED_BYTES_INVALID',
    `${label} must contain ${minimum} to ${maxBytes} bytes`,
  )
  if (
    !Number.isSafeInteger(expectedByteLength)
    || expectedByteLength < minimum
    || expectedByteLength > maxBytes
  ) {
    throw invalidLength()
  }
  const bytes = dedicated ? copyToOwnedBuffer(value) : Buffer.from(value)
  if (bytes.length !== expectedByteLength) {
    eraseBytes(bytes)
    throw invalidLength()
  }
  return bytes
}

function credentialHeaders(scope, credentialBytes) {
  if (sha256Hex(credentialBytes) !== scope.credential.binding_sha256) {
    throw clientError(
      'HTTP_AUTHED_CREDENTIAL_BINDING_MISMATCH',
      'credential value does not match the sealed credential binding digest',
    )
  }
  const value = credentialBytes.toString('utf8')
  if (scope.credential.kind === 'bearer') {
    return { authorization: `Bearer ${value}` }
  }
  if (scope.credential.kind === 'cookie') {
    return { cookie: value }
  }
  throw clientError('HTTP_AUTHED_CREDENTIAL_KIND_INVALID', 'unsupported credential kind')
}

function requestBody(action, supplied) {
  const metadata = action.request_body
  if (metadata === undefined) {
    if (supplied !== undefined) {
      throw clientError(
        'HTTP_AUTHED_BODY_UNEXPECTED',
        'request body bytes were supplied for an action with no sealed body metadata',
      )
    }
    return null
  }
  const bytes = exactBytes(
    supplied,
    'synthetic request body',
    16 * 1024 * 1024,
    { minimum: 0, dedicated: true },
  )
  if (bytes.length !== metadata.byte_length || sha256Hex(bytes) !== metadata.sha256) {
    eraseBytes(bytes)
    throw clientError(
      'HTTP_AUTHED_BODY_BINDING_MISMATCH',
      'synthetic request body length or digest does not match its sealed metadata',
    )
  }
  return bytes
}

function publicResponse(result, jsonShape, observation, jsonShapeObservationFailed) {
  if (
    !result
    || !Number.isSafeInteger(result.status)
    || result.status < 100
    || result.status > 599
    || !Number.isSafeInteger(result.responseBytes)
    || result.responseBytes < 0
    || !Array.isArray(result.responseHeaderNames)
  ) {
    throw clientError(
      'HTTP_AUTHED_TRANSPORT_RESULT_INVALID',
      'authenticated probe transport returned invalid response metadata',
    )
  }
  let headerNames
  try {
    headerNames = sanitizeHttpAuthedHeaderNames(result.responseHeaderNames)
  } catch {
    throw clientError(
      'HTTP_AUTHED_TRANSPORT_RESULT_INVALID',
      'authenticated probe transport returned an invalid response header name',
    )
  }
  if (jsonShapeObservationFailed === true) {
    if (observation === undefined || jsonShape !== undefined) {
      throw clientError(
        'HTTP_AUTHED_RESPONSE_OBSERVATION_STATE_INVALID',
        'authenticated response observation state is invalid',
        { requestMayHaveBeenSent: true },
      )
    }
    return {
      status: result.status,
      header_names: headerNames,
      response_byte_bucket: httpAuthedResponseByteBucket(result.responseBytes),
      failure_stage_code: HTTP_AUTHED_JSON_SHAPE_FAILURE_STAGE,
    }
  }
  const sanitizedShape = jsonShape === undefined
    ? undefined
    : sanitizeHttpAuthedJsonShape(jsonShape, {
        safeKeyNames: observation?.safe_key_names,
        mode: observation?.mode,
      })
  return {
    status: result.status,
    bytes: result.responseBytes,
    header_names: headerNames,
    ...(sanitizedShape === undefined
      ? {}
      : { json_shape: sanitizedShape }),
  }
}

function validateTransportRequest({
  url,
  method,
  headers,
  body,
  timeoutMs,
  maxResponseBytes,
  tls,
  beforeSend,
  responseObserver,
}) {
  if (typeof url !== 'string' || /(?:\\|%(?:25)*(?:2e|2f|5c))/i.test(url)) {
    throw clientError(
      'HTTP_AUTHED_URL_INVALID',
      'authenticated probe URL contains an ambiguous encoded separator or dot segment',
    )
  }
  let parsed
  try {
    parsed = new URL(url)
  } catch (cause) {
    throw clientError('HTTP_AUTHED_URL_INVALID', 'authenticated probe URL is invalid', { cause })
  }
  if (
    parsed.protocol !== 'https:'
    || parsed.username !== ''
    || parsed.password !== ''
    || parsed.hash !== ''
  ) {
    throw clientError(
      'HTTP_AUTHED_URL_INVALID',
      'authenticated probe transport requires HTTPS without URL credentials or fragments',
    )
  }
  if (typeof method !== 'string' || !/^[!#$%&'*+.^_`|~0-9A-Z-]{1,64}$/.test(method)) {
    throw clientError(
      'HTTP_AUTHED_METHOD_INVALID',
      'authenticated probe method must be a canonical uppercase HTTP token',
    )
  }
  if (method === 'CONNECT') {
    throw clientError(
      'HTTP_AUTHED_METHOD_UNSUPPORTED',
      'authenticated HTTPS probes refuse CONNECT tunnels before network I/O',
    )
  }
  if (!headers || Object.getPrototypeOf(headers) !== Object.prototype) {
    throw clientError('HTTP_AUTHED_HEADERS_INVALID', 'authenticated probe headers must be plain')
  }
  for (const [name, value] of Object.entries(headers)) {
    if (
      !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name)
      || typeof value !== 'string'
      || /[\r\n\0]/.test(value)
    ) {
      throw clientError('HTTP_AUTHED_HEADERS_INVALID', 'authenticated probe header is invalid')
    }
  }
  if (!(body === null || Buffer.isBuffer(body))) {
    throw clientError('HTTP_AUTHED_BODY_INVALID', 'authenticated probe body must be bytes or null')
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 30000) {
    throw clientError('HTTP_AUTHED_TIMEOUT_INVALID', 'authenticated probe timeout is invalid')
  }
  if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 0 || maxResponseBytes > 1048576) {
    throw clientError(
      'HTTP_AUTHED_RESPONSE_LIMIT_INVALID',
      'authenticated probe response limit is invalid',
    )
  }
  if (!tls || !['PKIX_HOSTNAME', 'PKIX_HOSTNAME_AND_SPKI_PIN'].includes(tls.mode)) {
    throw clientError('HTTP_AUTHED_TLS_POLICY_INVALID', 'authenticated probe TLS policy is invalid')
  }
  if (
    (tls.mode === 'PKIX_HOSTNAME' && tls.spki_sha256 !== undefined)
    || (
      tls.mode === 'PKIX_HOSTNAME_AND_SPKI_PIN'
      && !/^[a-f0-9]{64}$/.test(tls.spki_sha256 ?? '')
    )
  ) {
    throw clientError('HTTP_AUTHED_TLS_POLICY_INVALID', 'authenticated probe TLS pin is invalid')
  }
  if (beforeSend !== undefined && typeof beforeSend !== 'function') {
    throw clientError(
      'HTTP_AUTHED_BEFORE_SEND_INVALID',
      'authenticated probe beforeSend hook is invalid',
    )
  }
  if (responseObserver !== undefined && typeof responseObserver !== 'function') {
    throw clientError(
      'HTTP_AUTHED_RESPONSE_OBSERVER_INVALID',
      'authenticated probe response observer is invalid',
    )
  }
  return { parsed, body: body === null ? null : copyToOwnedBuffer(body) }
}

export function createHttpAuthedHttpsTransport({
  dnsLookup = nodeDnsLookup,
  httpsRequest = nodeHttpsRequest,
  setTimer = setTimeout,
  clearTimer = clearTimeout,
} = {}) {
  if (
    typeof dnsLookup !== 'function'
    || typeof httpsRequest !== 'function'
    || typeof setTimer !== 'function'
    || typeof clearTimer !== 'function'
  ) {
    throw clientError('HTTP_AUTHED_DEPENDENCY_INVALID', 'HTTPS transport dependency is invalid')
  }
  return async function sendHttpAuthedHttpsOnce(input) {
    const { parsed, body } = validateTransportRequest(input)
    const controller = new AbortController()
    let timedOut = false
    let request
    let timer
    let timerCreated = false
    try {
      timer = setTimer(() => {
        timedOut = true
        controller.abort()
        request?.destroy(clientError('HTTP_AUTHED_TIMEOUT', 'authenticated HTTPS probe timed out'))
      }, input.timeoutMs)
      timerCreated = true
      let dns
      try {
        dns = await resolveHttpReconDns(parsed.hostname, {
          lookup: dnsLookup,
          signal: controller.signal,
          timedOut: () => timedOut,
        })
      } catch (cause) {
        if (
          cause instanceof HttpReconTransportError
          && ['HTTP_RECON_ABORTED', 'HTTP_RECON_TIMEOUT'].includes(cause.code)
        ) {
          throw clientError(
            'HTTP_AUTHED_TIMEOUT',
            'authenticated HTTPS probe timed out',
            { cause },
          )
        }
        throw cause
      }
      if (controller.signal.aborted) {
        throw clientError('HTTP_AUTHED_TIMEOUT', 'authenticated HTTPS probe timed out')
      }
      const pinnedLookup = (hostname, _options, callback) => {
        if (hostname !== parsed.hostname) {
          callback(clientError(
            'HTTP_AUTHED_DNS_REBINDING_REFUSED',
            'HTTPS transport attempted a hostname outside the verified DNS binding',
          ))
          return
        }
        callback(null, dns.selected.address, dns.selected.family)
      }
      let tlsVerified = false
      const checkServerIdentity = createHttpReconIdentity(
        input.tls.spki_sha256,
        () => { tlsVerified = true },
      )

      return await new Promise((resolve, reject) => {
        let settled = false
        let requestMayHaveBeenSent = false
        let response
        let responseBytes = 0
        const observedBodyChunks = []
        const pendingObserverBodyChunks = []
        let observerInputBodyChunks
        let observerHandoffComplete = false
        const eraseObservedBodyChunks = () => {
          for (const chunk of observedBodyChunks) {
            eraseBytes(chunk)
          }
          observedBodyChunks.length = 0
        }
        const erasePendingObserverBodyChunks = () => {
          if (observerHandoffComplete) return
          for (const chunk of pendingObserverBodyChunks) {
            eraseBytes(chunk)
          }
          pendingObserverBodyChunks.length = 0
          observerInputBodyChunks = undefined
        }
        const finish = (callback, value) => {
          if (settled) return
          settled = true
          callback(value)
        }
        const fail = (error) => {
          const source = error instanceof Error
            ? error
            : clientError('HTTP_AUTHED_TRANSPORT_FAILED', 'authenticated HTTPS probe failed')
          const wrapped = clientError(
            source.code ?? 'HTTP_AUTHED_TRANSPORT_FAILED',
            source.message || 'authenticated HTTPS probe failed',
            { cause: source, requestMayHaveBeenSent },
          )
          eraseObservedBodyChunks()
          erasePendingObserverBodyChunks()
          finish(reject, wrapped)
        }
        const refuseProtocolSwitch = (_received, socket) => {
          socket?.destroy?.()
          request?.destroy?.()
          fail(clientError(
            'HTTP_AUTHED_PROTOCOL_SWITCH_REFUSED',
            'authenticated HTTPS probe refuses CONNECT tunnels and protocol upgrades',
          ))
        }

        try {
          request = httpsRequest(parsed, {
            method: input.method,
            headers: input.headers,
            agent: false,
            family: dns.selected.family,
            lookup: pinnedLookup,
            servername: parsed.hostname,
            rejectUnauthorized: true,
            minVersion: 'TLSv1.2',
            checkServerIdentity,
          })
        } catch (cause) {
          fail(clientError(
            'HTTP_AUTHED_TRANSPORT_FAILED',
            'authenticated HTTPS request could not be created',
            { cause },
          ))
          return
        }

        request.once('error', fail)
        request.once('connect', refuseProtocolSwitch)
        request.once('upgrade', refuseProtocolSwitch)
        request.once('socket', (socket) => {
          socket.once('secureConnect', async () => {
            if (settled || controller.signal.aborted) return
            if (socket.encrypted !== true || socket.authorized !== true || tlsVerified !== true) {
              fail(clientError(
                'HTTP_AUTHED_TLS_VERIFICATION_MISSING',
                'authenticated HTTPS probe did not complete trusted TLS verification',
              ))
              request.destroy()
              return
            }
            try {
              await input.beforeSend?.()
              if (settled || controller.signal.aborted) return
              requestMayHaveBeenSent = true
              request.end(body ?? undefined)
            } catch (cause) {
              fail(clientError(
                'HTTP_AUTHED_BEFORE_SEND_REJECTED',
                'authenticated HTTPS probe was rejected immediately before send',
                { cause },
              ))
              request.destroy()
            }
          })
        })
        request.once('response', (received) => {
          response = received
          if (
            !Number.isSafeInteger(response.statusCode)
            || response.statusCode < 100
            || response.statusCode > 599
          ) {
            fail(clientError('HTTP_AUTHED_STATUS_INVALID', 'HTTPS response status is invalid'))
            response.destroy()
            return
          }
          response.on('data', (chunk) => {
            if (settled) return
            responseBytes += Buffer.byteLength(chunk)
            if (responseBytes > input.maxResponseBytes) {
              const error = clientError(
                'HTTP_AUTHED_RESPONSE_LIMIT_EXCEEDED',
                'authenticated HTTPS response exceeded its per-response byte limit',
              )
              fail(error)
              response.destroy(error)
              request.destroy(error)
              return
            }
            if (input.responseObserver !== undefined) {
              observedBodyChunks.push(Buffer.from(chunk))
            }
          })
          response.once('error', fail)
          response.once('aborted', () => fail(clientError(
            'HTTP_AUTHED_RESPONSE_ABORTED',
            'authenticated HTTPS response ended before completion',
          )))
          response.once('end', () => {
            if (settled) return
            const rawHeaders = Array.isArray(response.rawHeaders) ? response.rawHeaders : []
            const responseHeaderNames = []
            const observableHeaders = []
            for (let index = 0; index < rawHeaders.length; index += 2) {
              const name = String(rawHeaders[index]).toLowerCase()
              responseHeaderNames.push(name)
              if (OBSERVABLE_RESPONSE_HEADERS.has(name)) {
                observableHeaders.push({ name, value: String(rawHeaders[index + 1] ?? '') })
              }
            }
            const complete = async () => {
              try {
                if (input.responseObserver !== undefined) {
                  for (const chunk of observedBodyChunks) {
                    pendingObserverBodyChunks.push(Buffer.from(chunk))
                  }
                  observerInputBodyChunks = [...pendingObserverBodyChunks]
                  await input.responseObserver({
                    status: response.statusCode,
                    headers: observableHeaders,
                    bodyChunks: observerInputBodyChunks,
                  })
                  if (settled) return
                  observerHandoffComplete = true
                  pendingObserverBodyChunks.length = 0
                  observerInputBodyChunks = undefined
                }
                finish(resolve, {
                  status: response.statusCode,
                  responseBytes,
                  responseHeaderNames: [...new Set(responseHeaderNames)],
                })
              } catch (error) {
                fail(clientError(
                  'HTTP_AUTHED_RESPONSE_OBSERVER_FAILED',
                  'authenticated response observation failed',
                  { cause: error, requestMayHaveBeenSent: true },
                ))
              } finally {
                erasePendingObserverBodyChunks()
                eraseObservedBodyChunks()
              }
            }
            void complete()
          })
        })
      })
    } finally {
      try {
        if (timerCreated) {
          try {
            clearTimer(timer)
          } catch {
            // The transport outcome is already authoritative. A faulty timer
            // cleanup dependency cannot turn a settled request into an unsent
            // failure or replace the primary timeout/transport error.
          }
        }
      } finally {
        eraseBytes(body)
      }
    }
  }
}

export async function dispatchHttpAuthedProbe({
  scope,
  action,
  expectedCampaignGrantSha256,
  credentialValue,
  requestBodyBytes,
  beforeSend,
  responseObserver,
  now = new Date(),
  transport = createHttpAuthedHttpsTransport(),
}) {
  const verified = verifyHttpAuthedCandidate({
    scope,
    action,
    expectedCampaignGrantSha256,
    now,
  })
  const authorizationEvidence = httpAuthedAuthorizationEvidence(scope)
  if (action.kind !== 'probe') {
    throw clientError(
      'HTTP_AUTHED_PROBE_KIND_REQUIRED',
      'the active probe dispatcher does not execute declared mutation actions',
    )
  }
  if (typeof transport !== 'function') {
    throw clientError(
      'HTTP_AUTHED_TRANSPORT_REQUIRED',
      'authenticated probe dispatch requires an explicit HTTPS transport',
    )
  }
  if (typeof beforeSend !== 'function') {
    throw clientError(
      'HTTP_AUTHED_BEFORE_SEND_REQUIRED',
      'authenticated live probe dispatch requires an immediate pre-send verifier',
    )
  }

  const browserSession = isHttpAuthedBrowserSessionCredential(scope.credential)
  if (browserSession && credentialValue !== undefined) {
    throw clientError(
      'HTTP_AUTHED_BROWSER_CREDENTIAL_EXPORT_REFUSED',
      'Chrome active-tab session dispatch must not receive exported credential bytes',
    )
  }
  const credentialBytes = browserSession
    ? undefined
    : exactBytes(
        credentialValue,
        'credential value',
        MAX_CREDENTIAL_BYTES,
      )
  let body
  try {
    body = requestBody(action, requestBodyBytes)
    const verifyImmediatelyBeforeSend = async () => {
      try {
        await beforeSend()
      } catch (cause) {
        throw clientError(
          'HTTP_AUTHED_BEFORE_SEND_REJECTED',
          'authenticated probe candidate or campaign authorization failed immediately before send',
          { cause },
        )
      }
    }
    const headers = {
      accept: '*/*',
      ...(browserSession
        ? {}
        : {
            'user-agent': `red-team-audit-http-authed/${PLATFORM_SERIES}`,
            ...credentialHeaders(scope, credentialBytes),
          }),
      ...(body === null
        ? {}
        : {
            'content-type': action.request_body.content_type,
            'content-length': String(body.length),
          }),
    }

    let transportResult
    let jsonShape
    let jsonShapeObservationFailed = false
    try {
      const observation = scope.response_observation
      const boundedResponseObserver = observation === undefined && responseObserver === undefined
        ? undefined
        : async (input) => {
          const observed = {
            status: input?.status,
            headers: Array.isArray(input?.headers)
              ? input.headers.filter((header) => (
                  header && OBSERVABLE_RESPONSE_HEADERS.has(header.name)
                ))
              : [],
            bodyChunks: Array.isArray(input?.bodyChunks) ? input.bodyChunks : [],
          }
          let handedOff = false
          try {
            if (observation !== undefined) {
              try {
                jsonShape = observeHttpAuthedJsonShape({
                  ...observed,
                  limits: { maxDepth: observation.max_depth },
                  safeKeyNames: observation.safe_key_names,
                  mode: observation.mode,
                })
              } catch {
                jsonShape = undefined
                jsonShapeObservationFailed = true
                return
              }
            }
            try {
              await responseObserver?.(observed)
              handedOff = responseObserver !== undefined
            } catch (cause) {
              throw clientError(
                'HTTP_AUTHED_RESPONSE_OBSERVER_FAILED',
                'authenticated response observation failed',
                { cause, requestMayHaveBeenSent: true },
              )
            }
          } finally {
            if (!handedOff) {
              for (const chunk of observed.bodyChunks) {
                eraseBytes(chunk)
              }
            }
          }
        }
      transportResult = await transport({
        url: action.url,
        method: action.method,
        headers,
        body,
        timeoutMs: scope.limits.request_timeout_ms,
        maxResponseBytes: scope.limits.max_response_bytes,
        tls: structuredClone(scope.target.tls),
        beforeSend: verifyImmediatelyBeforeSend,
        responseObserver: boundedResponseObserver,
      })
    } catch (cause) {
      if (cause instanceof HttpAuthedClientError) throw cause
      throw clientError(
        'HTTP_AUTHED_TRANSPORT_FAILED',
        'authenticated HTTPS probe transport failed',
        { cause },
      )
    }

    return {
      kind: 'red-team-audit/http-authed-probe-result',
      schema_version: jsonShapeObservationFailed
        ? '1.3.0'
        : scope.response_observation === undefined
        ? '1.0.0'
        : scope.response_observation.mode === 'ASPNET_D_JSON_SHAPE_ONLY'
          ? '1.2.0'
          : '1.1.0',
      authorization_mode: scope.authorization.mode,
      independently_verified: scope.authorization.independently_verified,
      authorization_assurance: authorizationEvidence.authorizationAssurance,
      authorization_nonclaim: authorizationEvidence.authorizationNonclaim,
      authorization_binding_sha256: verified.authorizationBindingSha256,
      campaign_grant_sha256: verified.campaignGrantSha256,
      action: {
        sequence: action.sequence,
        test_category: action.test_category,
        method: action.method,
      },
      response: publicResponse(
        transportResult,
        jsonShape,
        scope.response_observation,
        jsonShapeObservationFailed,
      ),
    }
  } finally {
    eraseBytes(credentialBytes)
    eraseBytes(body)
  }
}
