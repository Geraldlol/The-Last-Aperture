import { Buffer } from 'node:buffer'
import { createServer as nodeCreateServer } from 'node:http'

import {
  HTTP_AUTHED_BROWSER_BRIDGE_PROTOCOL,
  HTTP_AUTHED_BROWSER_BRIDGE_SCHEMA_VERSION,
  HttpAuthedBrowserBridgeError,
  createHttpAuthedBrowserBridgeSession,
  createHttpAuthedBrowserBridgeTransport,
} from './http-authed-browser-bridge-core.mjs'

export const HTTP_AUTHED_BROWSER_BRIDGE_PAIRING_HEADER =
  'x-red-team-audit-pairing'
export const HTTP_AUTHED_BROWSER_BRIDGE_SESSION_HEADER =
  'x-red-team-audit-session'
export const HTTP_AUTHED_BROWSER_BRIDGE_EXTENSION_HEADER =
  'x-last-aperture-extension'

const LOOPBACK_HOST = '127.0.0.1'
const DEFAULT_ATTACH_TIMEOUT_MS = 2 * 60 * 1000
const MAX_CONTROL_MESSAGE_BYTES = 16 * 1024
const MAX_RESULT_MESSAGE_BYTES = 2 * 1024 * 1024
const intrinsicByteFill = Uint8Array.prototype.fill
const ALLOWED_PREFLIGHT_HEADERS = new Set([
  'content-type',
  HTTP_AUTHED_BROWSER_BRIDGE_EXTENSION_HEADER,
  HTTP_AUTHED_BROWSER_BRIDGE_PAIRING_HEADER,
  HTTP_AUTHED_BROWSER_BRIDGE_SESSION_HEADER,
])
const ROUTES = new Map([
  ['/v1/preview', 'GET'],
  ['/v1/open', 'POST'],
  ['/v1/prepare', 'POST'],
  ['/v1/ready', 'POST'],
  ['/v1/result', 'POST'],
  ['/v1/close', 'POST'],
])

function serverError(code, message, options) {
  return new HttpAuthedBrowserBridgeError(code, message, options)
}

function eraseBytes(value) {
  try {
    if (value instanceof Uint8Array) Reflect.apply(intrinsicByteFill, value, [0])
  } catch {
    // HTTP dependencies may detach or resize handed-off byte storage.
  }
}

function exactKeys(value, keys) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype) return false
  const actual = Object.keys(value).sort()
  const expected = [...keys].sort()
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index])
}

function singleHeader(request, name) {
  const value = request.headers[name]
  return typeof value === 'string' ? value : undefined
}

function assertNoAmbientCredentials(request) {
  if (
    request.headers.cookie !== undefined
    || request.headers.authorization !== undefined
    || request.headers['proxy-authorization'] !== undefined
  ) {
    throw serverError(
      'HTTP_AUTHED_BROWSER_BRIDGE_AMBIENT_CREDENTIAL_REFUSED',
      'loopback browser bridge refuses ambient HTTP credentials',
    )
  }
}

function assertExtensionOrigin(request, expectedOrigin, expectedExtensionId) {
  const origin = singleHeader(request, 'origin')
  const isChromeExtensionFetch = origin === undefined
    && singleHeader(request, 'sec-fetch-site') === 'none'
    && singleHeader(request, 'sec-fetch-mode') === 'cors'
    && singleHeader(request, 'sec-fetch-dest') === 'empty'
  if (
    singleHeader(request, HTTP_AUTHED_BROWSER_BRIDGE_EXTENSION_HEADER) !== expectedExtensionId
    || (origin !== expectedOrigin && !isChromeExtensionFetch)
  ) {
    throw serverError(
      'HTTP_AUTHED_BROWSER_BRIDGE_ORIGIN_REFUSED',
      'loopback browser bridge request origin was refused',
    )
  }
}

function assertLoopbackHost(request, expectedAuthority) {
  if (singleHeader(request, 'host') !== expectedAuthority) {
    throw serverError(
      'HTTP_AUTHED_BROWSER_BRIDGE_HOST_REFUSED',
      'loopback browser bridge request host was refused',
    )
  }
}

function noStoreHeaders(response, extensionOrigin, includeCors) {
  response.setHeader('Cache-Control', 'no-store, max-age=0')
  response.setHeader('Pragma', 'no-cache')
  response.setHeader('Expires', '0')
  response.setHeader('X-Content-Type-Options', 'nosniff')
  response.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'")
  response.setHeader('Referrer-Policy', 'no-referrer')
  response.setHeader('Cross-Origin-Resource-Policy', 'cross-origin')
  if (includeCors) {
    response.setHeader('Access-Control-Allow-Origin', extensionOrigin)
    response.setHeader('Vary', 'Origin')
    response.setHeader(
      'Access-Control-Expose-Headers',
      HTTP_AUTHED_BROWSER_BRIDGE_SESSION_HEADER,
    )
  }
}

function endEmpty(response, status, extensionOrigin, includeCors = true) {
  noStoreHeaders(response, extensionOrigin, includeCors)
  response.statusCode = status
  response.end()
}

function endJson(response, status, value, extensionOrigin, includeCors = true) {
  const bytes = Buffer.from(JSON.stringify(value), 'utf8')
  let scrubbed = false
  const scrub = () => {
    if (scrubbed) return
    scrubbed = true
    eraseBytes(bytes)
  }
  response.once('finish', scrub)
  response.once('close', scrub)
  noStoreHeaders(response, extensionOrigin, includeCors)
  response.statusCode = status
  response.setHeader('Content-Type', 'application/json; charset=utf-8')
  response.setHeader('Content-Length', String(bytes.length))
  response.end(bytes)
}

function statusFor(error) {
  if (!(error instanceof HttpAuthedBrowserBridgeError)) return 500
  if (
    error.code.includes('ORIGIN_REFUSED')
    || error.code.includes('HOST_REFUSED')
    || error.code.includes('SESSION_REFUSED')
    || error.code.includes('PREVIEW_REFUSED')
    || error.code.includes('OPEN_REFUSED')
  ) return 403
  if (
    error.code.includes('UNEXPECTED')
    || error.code.includes('IN_FLIGHT')
    || error.code.includes('REPLAY')
    || error.code.includes('UNAVAILABLE')
  ) return 409
  if (error.code.includes('CLOSED')) return 410
  return 400
}

function endError(response, error, extensionOrigin, includeCors) {
  const code = error instanceof HttpAuthedBrowserBridgeError
    ? error.code
    : 'HTTP_AUTHED_BROWSER_BRIDGE_INTERNAL'
  endJson(response, statusFor(error), { error: { code } }, extensionOrigin, includeCors)
}

async function readJson(request, maximum) {
  const contentEncoding = singleHeader(request, 'content-encoding')
  if (contentEncoding !== undefined && contentEncoding.toLowerCase() !== 'identity') {
    throw serverError(
      'HTTP_AUTHED_BROWSER_BRIDGE_MESSAGE_INVALID',
      'loopback browser bridge message encoding is invalid',
    )
  }
  const contentType = singleHeader(request, 'content-type')
  if (contentType === undefined || contentType.split(';', 1)[0].trim() !== 'application/json') {
    throw serverError(
      'HTTP_AUTHED_BROWSER_BRIDGE_MESSAGE_INVALID',
      'loopback browser bridge accepts JSON control messages only',
    )
  }
  const declaredLength = singleHeader(request, 'content-length')
  if (
    declaredLength !== undefined
    && (!/^(?:0|[1-9][0-9]*)$/.test(declaredLength) || Number(declaredLength) > maximum)
  ) {
    throw serverError(
      'HTTP_AUTHED_BROWSER_BRIDGE_MESSAGE_TOO_LARGE',
      'loopback browser bridge message exceeds its byte limit',
    )
  }

  const chunks = []
  let length = 0
  let tooLarge = false
  try {
    await new Promise((resolve, reject) => {
      request.on('data', (chunk) => {
        const bytes = Buffer.from(chunk)
        if (tooLarge) {
          eraseBytes(bytes)
          return
        }
        length += bytes.length
        if (length > maximum) {
          tooLarge = true
          eraseBytes(bytes)
          for (const held of chunks) eraseBytes(held)
          chunks.length = 0
          return
        }
        chunks.push(bytes)
      })
      request.once('end', resolve)
      request.once('aborted', () => reject(serverError(
        'HTTP_AUTHED_BROWSER_BRIDGE_MESSAGE_ABORTED',
        'loopback browser bridge message ended early',
      )))
      request.once('error', () => reject(serverError(
        'HTTP_AUTHED_BROWSER_BRIDGE_MESSAGE_INVALID',
        'loopback browser bridge message could not be read',
      )))
    })
    if (tooLarge) {
      throw serverError(
        'HTTP_AUTHED_BROWSER_BRIDGE_MESSAGE_TOO_LARGE',
        'loopback browser bridge message exceeds its byte limit',
      )
    }
    const combined = Buffer.concat(chunks, length)
    try {
      if (combined.length === 0) {
        throw serverError(
          'HTTP_AUTHED_BROWSER_BRIDGE_MESSAGE_INVALID',
          'loopback browser bridge message must not be empty',
        )
      }
      try {
        return JSON.parse(combined.toString('utf8'))
      } catch (error) {
        if (error instanceof HttpAuthedBrowserBridgeError) throw error
        throw serverError(
          'HTTP_AUTHED_BROWSER_BRIDGE_MESSAGE_INVALID',
          'loopback browser bridge message is not valid JSON',
        )
      }
    } finally {
      eraseBytes(combined)
    }
  } finally {
    for (const chunk of chunks) eraseBytes(chunk)
  }
}

function authenticateSession(request, session, extensionOrigin, extensionId) {
  assertExtensionOrigin(request, extensionOrigin, extensionId)
  assertNoAmbientCredentials(request)
  session.authenticate({
    origin: extensionOrigin,
    sessionCapability: singleHeader(request, HTTP_AUTHED_BROWSER_BRIDGE_SESSION_HEADER),
  })
}

function handlePreflight(request, response, extensionOrigin, extensionId, routeMethod) {
  assertExtensionOrigin(request, extensionOrigin, extensionId)
  assertNoAmbientCredentials(request)
  if (singleHeader(request, 'access-control-request-method') !== routeMethod) {
    throw serverError(
      'HTTP_AUTHED_BROWSER_BRIDGE_PREFLIGHT_REFUSED',
      'loopback browser bridge preflight method was refused',
    )
  }
  const requestedHeaders = (singleHeader(request, 'access-control-request-headers') ?? '')
    .split(',')
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean)
  if (requestedHeaders.some((name) => !ALLOWED_PREFLIGHT_HEADERS.has(name))) {
    throw serverError(
      'HTTP_AUTHED_BROWSER_BRIDGE_PREFLIGHT_REFUSED',
      'loopback browser bridge preflight headers were refused',
    )
  }
  noStoreHeaders(response, extensionOrigin, true)
  response.statusCode = 204
  response.setHeader('Access-Control-Allow-Methods', routeMethod)
  response.setHeader(
    'Access-Control-Allow-Headers',
    [...ALLOWED_PREFLIGHT_HEADERS].join(', '),
  )
  response.setHeader('Access-Control-Max-Age', '0')
  response.end()
}

function listen(server, port) {
  return new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off('listening', onListening)
      reject(error)
    }
    const onListening = () => {
      server.off('error', onError)
      resolve()
    }
    server.once('error', onError)
    server.once('listening', onListening)
    server.listen({ host: LOOPBACK_HOST, port, exclusive: true })
  })
}

function closeServer(server, sockets) {
  return new Promise((resolve, reject) => {
    if (!server.listening) {
      for (const socket of sockets) socket.destroy()
      resolve()
      return
    }
    server.close((error) => {
      if (error) reject(error)
      else resolve()
    })
    server.closeAllConnections?.()
    for (const socket of sockets) socket.destroy()
  })
}

/**
 * Starts a capability-authenticated HTTP control plane on IPv4 loopback only.
 * Target cookies never enter this process: Chrome applies its current cookie
 * jar when the isolated injected function receives COMMIT.
 */
export async function createHttpAuthedBrowserBridgeServer({
  extensionId,
  targetOrigin,
  pageSessionAdapter,
  campaignId,
  campaignGrantSha256,
  attachTimeoutMs = DEFAULT_ATTACH_TIMEOUT_MS,
  pairingTtlMs,
  clock = () => new Date(),
  randomBytes,
  setTimer = setTimeout,
  clearTimer = clearTimeout,
  serverFactory = nodeCreateServer,
  port = 0,
  actionIdFactory,
} = {}) {
  const grant = campaignGrantSha256 ?? campaignId
  if (
    typeof serverFactory !== 'function'
    || typeof setTimer !== 'function'
    || typeof clearTimer !== 'function'
    || !Number.isSafeInteger(port)
    || port < 0
    || port > 65535
    || (port !== 0 && port < 1024)
    || !Number.isSafeInteger(attachTimeoutMs)
    || attachTimeoutMs < 1000
    || attachTimeoutMs > 5 * 60 * 1000
  ) {
    throw serverError(
      'HTTP_AUTHED_BROWSER_BRIDGE_SERVER_OPTIONS_INVALID',
      'loopback browser bridge server options are invalid',
    )
  }
  if (campaignGrantSha256 !== undefined && !/^[a-f0-9]{64}$/.test(campaignGrantSha256)) {
    throw serverError(
      'HTTP_AUTHED_BROWSER_BRIDGE_CAMPAIGN_INVALID',
      'loopback browser bridge campaign grant is invalid',
    )
  }

  const session = createHttpAuthedBrowserBridgeSession({
    extensionId,
    targetOrigin,
    pageSessionAdapter,
    campaignId: grant,
    clock,
    ...(randomBytes === undefined ? {} : { randomBytes }),
    setTimer,
    clearTimer,
    ...(pairingTtlMs === undefined ? {} : { pairingTtlMs }),
  })
  const extensionOrigin = `chrome-extension://${extensionId}`
  const pairingCode = session.takePairingCode()
  const preview = session.preview({ origin: extensionOrigin, capability: pairingCode })
  const transport = createHttpAuthedBrowserBridgeTransport({ session, actionIdFactory })
  const sockets = new Set()
  let bridgeOrigin
  let loopbackAuthority
  let attached = false
  let closed = false
  let pairingAvailable = true
  let transientPairingCode = pairingCode
  let attachWaiter
  let attachTimer

  const clearAttachTimer = () => {
    const timer = attachTimer
    attachTimer = undefined
    if (timer === undefined) return
    try {
      clearTimer(timer)
    } catch {
      // Waiter settlement and server/session cleanup remain authoritative.
    }
  }

  const resolveAttached = () => {
    attached = true
    const waiter = attachWaiter
    attachWaiter = undefined
    clearAttachTimer()
    waiter?.resolve({
      extension_id: extensionId,
      target_origin: targetOrigin,
      campaign_grant_sha256: grant,
    })
  }

  const server = serverFactory(async (request, response) => {
    let includeCors = false
    try {
      assertLoopbackHost(request, loopbackAuthority)
      const rawPath = request.url ?? ''
      if (!ROUTES.has(rawPath)) {
        endError(
          response,
          serverError('HTTP_AUTHED_BROWSER_BRIDGE_ROUTE_NOT_FOUND', 'bridge route not found'),
          extensionOrigin,
          false,
        )
        return
      }
      const requiredMethod = ROUTES.get(rawPath)
      if (request.method === 'OPTIONS') {
        handlePreflight(request, response, extensionOrigin, extensionId, requiredMethod)
        return
      }
      assertExtensionOrigin(request, extensionOrigin, extensionId)
      includeCors = true
      assertNoAmbientCredentials(request)
      if (request.method !== requiredMethod) {
        endEmpty(response, 405, extensionOrigin)
        return
      }

      if (rawPath === '/v1/preview') {
        const value = session.preview({
          origin: extensionOrigin,
          capability: singleHeader(request, HTTP_AUTHED_BROWSER_BRIDGE_PAIRING_HEADER),
        })
        endJson(response, 200, value, extensionOrigin)
        return
      }

      if (rawPath === '/v1/open') {
        const message = await readJson(request, MAX_CONTROL_MESSAGE_BYTES)
        if (!exactKeys(message, [
          'protocol',
          'schema_version',
          'type',
          'campaign_id',
          'target_origin',
          'tab_id',
          'document_nonce',
        ]) || (
          message.protocol !== HTTP_AUTHED_BROWSER_BRIDGE_PROTOCOL
          || message.schema_version !== HTTP_AUTHED_BROWSER_BRIDGE_SCHEMA_VERSION
          || message.type !== 'OPEN'
          || message.campaign_id !== grant
          || message.target_origin !== targetOrigin
        )) {
          throw serverError(
            'HTTP_AUTHED_BROWSER_BRIDGE_OPEN_INVALID',
            'loopback browser bridge OPEN message is invalid',
          )
        }
        const opened = session.open({
          origin: extensionOrigin,
          capability: singleHeader(request, HTTP_AUTHED_BROWSER_BRIDGE_PAIRING_HEADER),
          campaignId: message.campaign_id,
          tabId: message.tab_id,
          documentNonce: message.document_nonce,
        })
        pairingAvailable = false
        resolveAttached()
        endJson(response, 200, opened, extensionOrigin)
        return
      }

      authenticateSession(request, session, extensionOrigin, extensionId)

      if (rawPath === '/v1/prepare') {
        const state = session.snapshot().state
        if (state === 'OPEN') {
          endEmpty(response, 204, extensionOrigin)
          return
        }
        const prepared = session.takePrepared()
        endJson(response, 200, prepared, extensionOrigin)
        return
      }

      if (rawPath === '/v1/ready') {
        const message = await readJson(request, MAX_CONTROL_MESSAGE_BYTES)
        session.acceptReady(message)
        const committed = await session.commit()
        endJson(response, 200, committed, extensionOrigin)
        return
      }

      if (rawPath === '/v1/result') {
        const message = await readJson(request, MAX_RESULT_MESSAGE_BYTES)
        await session.acceptResult(message)
        endJson(response, 200, {
          protocol: HTTP_AUTHED_BROWSER_BRIDGE_PROTOCOL,
          schema_version: HTTP_AUTHED_BROWSER_BRIDGE_SCHEMA_VERSION,
          type: 'RESULT',
          accepted: true,
        }, extensionOrigin)
        return
      }

      const message = await readJson(request, MAX_CONTROL_MESSAGE_BYTES)
      if (!exactKeys(message, [
        'protocol',
        'schema_version',
        'type',
        'campaign_id',
      ]) || (
        message.protocol !== HTTP_AUTHED_BROWSER_BRIDGE_PROTOCOL
        || message.schema_version !== HTTP_AUTHED_BROWSER_BRIDGE_SCHEMA_VERSION
        || message.type !== 'CLOSE'
        || message.campaign_id !== grant
      )) {
        throw serverError(
          'HTTP_AUTHED_BROWSER_BRIDGE_CLOSE_INVALID',
          'loopback browser bridge CLOSE message is invalid',
        )
      }
      const closedState = session.close('extension requested close')
      endJson(response, 200, {
        protocol: HTTP_AUTHED_BROWSER_BRIDGE_PROTOCOL,
        schema_version: HTTP_AUTHED_BROWSER_BRIDGE_SCHEMA_VERSION,
        type: 'CLOSE',
        request_may_have_been_sent: closedState.request_may_have_been_sent,
      }, extensionOrigin)
    } catch (error) {
      if (!response.headersSent) endError(response, error, extensionOrigin, includeCors)
      else response.destroy()
    }
  })
  if (
    !server
    || typeof server.listen !== 'function'
    || typeof server.close !== 'function'
    || typeof server.on !== 'function'
    || typeof server.once !== 'function'
    || typeof server.off !== 'function'
    || typeof server.address !== 'function'
  ) {
    session.close('invalid server factory')
    throw serverError(
      'HTTP_AUTHED_BROWSER_BRIDGE_SERVER_INVALID',
      'loopback browser bridge server factory returned an invalid server',
    )
  }
  server.requestTimeout = 35_000
  server.headersTimeout = 10_000
  server.keepAliveTimeout = 5_000
  server.maxHeadersCount = 32
  server.maxRequestsPerSocket = 1_000
  server.maxConnections = 8
  server.on('connection', (socket) => {
    sockets.add(socket)
    socket.once('close', () => sockets.delete(socket))
  })

  try {
    await listen(server, port)
    const address = server.address()
    if (
      !address
      || typeof address !== 'object'
      || address.address !== LOOPBACK_HOST
      || !Number.isSafeInteger(address.port)
    ) {
      throw serverError(
        'HTTP_AUTHED_BROWSER_BRIDGE_BINDING_INVALID',
        'loopback browser bridge did not bind the exact IPv4 loopback address',
      )
    }
    bridgeOrigin = `http://${LOOPBACK_HOST}:${address.port}`
    loopbackAuthority = `${LOOPBACK_HOST}:${address.port}`
  } catch {
    session.close('server failed to bind')
    await closeServer(server, sockets).catch(() => {})
    throw serverError(
      'HTTP_AUTHED_BROWSER_BRIDGE_LISTEN_FAILED',
      'loopback browser bridge could not start',
    )
  }

  const bridge = {
    get pairing() {
      if (!pairingAvailable || closed) return undefined
      pairingAvailable = false
      const value = {
        protocol: HTTP_AUTHED_BROWSER_BRIDGE_PROTOCOL,
        schema_version: HTTP_AUTHED_BROWSER_BRIDGE_SCHEMA_VERSION,
        bridge_origin: bridgeOrigin,
        extension_id: extensionId,
        target_origin: preview.target_origin,
        campaign_grant_sha256: preview.campaign_grant_sha256,
        pairing_code: transientPairingCode,
        expires_at: preview.expires_at,
      }
      transientPairingCode = undefined
      return value
    },
    transport,
    async waitForAttach() {
      if (attached) {
        return {
          extension_id: extensionId,
          target_origin: targetOrigin,
          campaign_grant_sha256: grant,
        }
      }
      if (closed) {
        throw serverError(
          'HTTP_AUTHED_BROWSER_BRIDGE_CLOSED',
          'loopback browser bridge closed before Chrome attached',
        )
      }
      if (attachWaiter === undefined) {
        let resolve
        let reject
        const promise = new Promise((resolvePromise, rejectPromise) => {
          resolve = resolvePromise
          reject = rejectPromise
        })
        // Timer setup may call back synchronously or throw. Bind the callback
        // to this exact waiter so either behavior cannot strand or replace it.
        void promise.catch(() => {})
        const waiter = { promise, resolve, reject }
        attachWaiter = waiter
        let timer
        try {
          timer = setTimer(() => {
            if (attachWaiter !== waiter) return
            attachWaiter = undefined
            attachTimer = undefined
            waiter.reject(serverError(
              'HTTP_AUTHED_BROWSER_BRIDGE_ATTACH_TIMEOUT',
              'loopback browser bridge timed out waiting for Chrome to attach',
            ))
          }, attachTimeoutMs)
        } catch (cause) {
          if (attachWaiter === waiter) attachWaiter = undefined
          attachTimer = undefined
          throw serverError(
            'HTTP_AUTHED_BROWSER_BRIDGE_ATTACH_TIMER_FAILED',
            'loopback browser bridge could not start its attach deadline timer',
            { cause },
          )
        }
        if (attachWaiter === waiter) attachTimer = timer
        return promise
      }
      return attachWaiter.promise
    },
    async close() {
      if (closed) return
      closed = true
      clearAttachTimer()
      const attachError = serverError(
        'HTTP_AUTHED_BROWSER_BRIDGE_CLOSED',
        'loopback browser bridge closed before Chrome attached',
      )
      attachWaiter?.reject(attachError)
      attachWaiter = undefined
      session.close('controller closed bridge')
      transientPairingCode = undefined
      try {
        await closeServer(server, sockets)
      } catch {
        throw serverError(
          'HTTP_AUTHED_BROWSER_BRIDGE_CLOSE_FAILED',
          'loopback browser bridge server could not close cleanly',
        )
      }
    },
  }
  return Object.freeze(bridge)
}
