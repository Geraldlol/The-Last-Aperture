import { createServer } from 'node:http'

const DEFAULT_MAX_BODY_BYTES = 64 * 1024

export function hostFromHeader(hostHeader) {
  if (typeof hostHeader !== 'string' || hostHeader.length === 0) return null
  const withoutPort = hostHeader.startsWith('[')
    ? hostHeader.slice(0, hostHeader.indexOf(']') + 1)
    : hostHeader.split(':')[0]
  const host = withoutPort.toLowerCase()
  return host.length === 0 ? null : host
}

export function startHttpListener({
  port = 80,
  address = '0.0.0.0',
  onRequest,
  maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
}) {
  const server = createServer((request, response) => {
    const chunks = []
    let received = 0
    let truncated = false
    request.on('data', (chunk) => {
      const before = received
      received += chunk.length
      if (received > maxBodyBytes) {
        truncated = true
        const room = maxBodyBytes - before
        if (room > 0) chunks.push(chunk.subarray(0, room))
        return
      }
      chunks.push(chunk)
    })
    request.on('end', () => {
      onRequest?.({
        protocol: 'http',
        method: request.method,
        path: request.url,
        host: hostFromHeader(request.headers.host),
        headers: { ...request.headers },
        body: Buffer.concat(chunks).toString('utf8'),
        bodyTruncated: truncated,
        remoteAddress: request.socket.remoteAddress,
      })
      // A fixed body, never an echo. This listener is reachable by anyone who
      // learns the domain, so reflecting request content would turn our own
      // evidence collector into someone else's XSS vector.
      response.writeHead(200, { 'Content-Type': 'text/plain' })
      response.end('ok\n')
    })
  })
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, address, () => {
      resolve({
        port: server.address().port,
        close: () => new Promise((done) => server.close(done)),
      })
    })
  })
}
