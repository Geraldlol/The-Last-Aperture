import { createServer as createHttpsServer } from 'node:https'

import { contentDigestHeader } from '../../scripts/lib/remote-gateway-contracts.mjs'
import { stableJson } from '../../scripts/lib/run-engine.mjs'

const DEFAULT_PATH = '/v1/entries'
const DEFAULT_CONSISTENCY_PATH = '/v1/consistency'
const DEFAULT_MAX_REQUEST_BYTES = 256 * 1024
const DEFAULT_MAX_HEADER_BYTES = 16 * 1024
const DEFAULT_MAX_HEADER_COUNT = 64

function errorResponse(statusCode, code, protocol = 'transparency-log-v1') {
  const body = Buffer.from(stableJson({
    schema_version: '1.0.0',
    protocol,
    error: { code },
  }, 0), 'utf8')
  return {
    statusCode,
    headers: {
      'content-type': 'application/json',
      'content-length': String(body.length),
      'content-digest': contentDigestHeader(body),
      'cache-control': 'no-store',
      'x-rta-protocol': protocol,
    },
    body,
  }
}

function writeResponse(response, result) {
  if (response.headersSent || response.destroyed) return
  response.writeHead(result.statusCode, result.headers)
  response.end(result.body)
}

function exactRequestHeaders(rawHeaders) {
  const headers = Object.create(null)
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index].toLowerCase()
    const value = rawHeaders[index + 1]
    if (headers[name] === undefined) {
      headers[name] = value
    } else if (Array.isArray(headers[name])) {
      headers[name].push(value)
    } else {
      headers[name] = [headers[name], value]
    }
  }
  return headers
}

function readRequestBody(request, maxRequestBytes) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let total = 0
    let settled = false
    const finish = (callback, value) => {
      if (settled) return
      settled = true
      callback(value)
    }
    request.on('data', (chunk) => {
      total += chunk.length
      if (total > maxRequestBytes) {
        const error = new Error(
          'reference transparency request exceeded maxRequestBytes',
        )
        error.code = 'TRANSPARENCY_REQUEST_TOO_LARGE'
        request.pause()
        finish(reject, error)
        return
      }
      chunks.push(Buffer.from(chunk))
    })
    request.once('aborted', () => {
      const error = new Error('reference transparency request was truncated')
      error.code = 'TRANSPARENCY_REQUEST_TRUNCATED'
      finish(reject, error)
    })
    request.once('error', (error) => finish(reject, error))
    request.once('end', () => finish(resolve, Buffer.concat(chunks)))
  })
}

export function createReferenceTransparencyHttpsServer({
  handler,
  consistencyHandler,
  tls,
  host = '127.0.0.1',
  port = 0,
  path = DEFAULT_PATH,
  consistencyPath = DEFAULT_CONSISTENCY_PATH,
  maxRequestBytes = DEFAULT_MAX_REQUEST_BYTES,
  maxHeaderBytes = DEFAULT_MAX_HEADER_BYTES,
  maxHeaderCount = DEFAULT_MAX_HEADER_COUNT,
  requestTimeoutMs = 30_000,
}) {
  if (typeof handler !== 'function') {
    throw new TypeError('reference transparency HTTPS server requires a handler')
  }
  if (
    consistencyHandler !== undefined
    && typeof consistencyHandler !== 'function'
  ) {
    throw new TypeError(
      'reference transparency HTTPS consistencyHandler must be a function when supplied',
    )
  }
  if (tls === null || typeof tls !== 'object' || Array.isArray(tls)) {
    throw new TypeError('reference transparency HTTPS server requires TLS options')
  }
  if (
    tls.pfx === undefined
    && (tls.key === undefined || tls.cert === undefined)
  ) {
    throw new TypeError(
      'reference transparency HTTPS server requires external TLS key/certificate material',
    )
  }
  if (
    tls.minVersion !== undefined
    && !['TLSv1.2', 'TLSv1.3'].includes(tls.minVersion)
  ) {
    throw new TypeError(
      'reference transparency HTTPS server minimum TLS version must be TLSv1.2 or TLSv1.3',
    )
  }
  if (
    typeof path !== 'string'
    || !path.startsWith('/')
    || path.includes('?')
    || path.includes('#')
  ) {
    throw new TypeError('reference transparency HTTPS path must be one exact absolute path')
  }
  if (
    consistencyHandler !== undefined
    && (
      typeof consistencyPath !== 'string'
      || !consistencyPath.startsWith('/')
      || consistencyPath.includes('?')
      || consistencyPath.includes('#')
      || consistencyPath === path
    )
  ) {
    throw new TypeError(
      'reference transparency HTTPS consistencyPath must be a distinct exact absolute path',
    )
  }
  if (
    !Number.isSafeInteger(maxRequestBytes)
    || maxRequestBytes < 4096
    || maxRequestBytes > 1024 * 1024
  ) {
    throw new TypeError('reference transparency maxRequestBytes must be between 4096 and 1048576')
  }
  if (
    !Number.isSafeInteger(requestTimeoutMs)
    || requestTimeoutMs < 1000
    || requestTimeoutMs > 300000
  ) {
    throw new TypeError('reference transparency requestTimeoutMs must be between 1000 and 300000')
  }
  if (
    !Number.isSafeInteger(maxHeaderBytes)
    || maxHeaderBytes < 4096
    || maxHeaderBytes > 64 * 1024
  ) {
    throw new TypeError('reference transparency maxHeaderBytes must be between 4096 and 65536')
  }
  if (
    !Number.isSafeInteger(maxHeaderCount)
    || maxHeaderCount < 8
    || maxHeaderCount > 1024
  ) {
    throw new TypeError('reference transparency maxHeaderCount must be between 8 and 1024')
  }

  const server = createHttpsServer({
    ...tls,
    minVersion: tls.minVersion ?? 'TLSv1.2',
    maxHeaderSize: maxHeaderBytes,
  }, async (request, response) => {
    response.setHeader('connection', 'close')
    const route = request.url === path
      ? { handler, protocol: 'transparency-log-v1' }
      : (
          consistencyHandler !== undefined
          && request.url === consistencyPath
            ? {
                handler: consistencyHandler,
                protocol: 'transparency-log-consistency-v1',
              }
            : null
        )
    if (route === null) {
      writeResponse(response, errorResponse(404, 'ENDPOINT_NOT_FOUND'))
      request.resume()
      return
    }
    let body
    try {
      body = await readRequestBody(request, maxRequestBytes)
    } catch (error) {
      const status = error.code === 'TRANSPARENCY_REQUEST_TOO_LARGE'
        ? 413
        : 400
      response.once('finish', () => request.destroy())
      writeResponse(
        response,
        errorResponse(
          status,
          error.code ?? 'REQUEST_READ_FAILED',
          route.protocol,
        ),
      )
      return
    }
    try {
      const result = await route.handler({
        method: request.method,
        headers: exactRequestHeaders(request.rawHeaders),
        body,
        remoteAddress: request.socket.remoteAddress,
      })
      writeResponse(response, result)
    } catch (error) {
      const requestError = String(error?.code ?? '')
        .startsWith('TRANSPARENCY_REQUEST_')
      writeResponse(
        response,
        errorResponse(
          requestError ? 400 : 500,
          requestError ? 'REQUEST_REJECTED' : 'INTERNAL_LOG_FAILURE',
          route.protocol,
        ),
      )
    }
  })
  server.requestTimeout = requestTimeoutMs
  server.headersTimeout = Math.min(requestTimeoutMs, 15_000)
  server.keepAliveTimeout = 1
  server.maxRequestsPerSocket = 1
  server.maxHeadersCount = maxHeaderCount

  let started = false
  return {
    server,
    async start() {
      if (started) throw new Error('reference transparency HTTPS server is already started')
      await new Promise((resolve, reject) => {
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
        server.listen({ host, port, exclusive: true })
      })
      started = true
      const address = server.address()
      return {
        host,
        port: address.port,
        path,
        url: `https://${host}:${address.port}${path}`,
        ...(consistencyHandler === undefined
          ? {}
          : {
              consistencyPath,
              consistencyUrl: `https://${host}:${address.port}${consistencyPath}`,
            }),
      }
    },
    async stop() {
      if (!started) return
      await new Promise((resolve, reject) => {
        server.close((error) => {
          if (error) reject(error)
          else resolve()
        })
        server.closeAllConnections?.()
      })
      started = false
    },
  }
}
