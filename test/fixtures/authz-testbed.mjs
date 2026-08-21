import { randomUUID } from 'node:crypto'
import { createServer } from 'node:http'

// A three-role app with DELIBERATE, KNOWN authorization bugs. Its purpose is to
// give the grinder ground truth to be measured against, so a green test run means
// "found the planted bugs and left the clean endpoints alone" rather than
// "agreed with its own assumptions".
//
// Ground truth:
//   GET /api/me            correct  -> each role sees its own profile (DIFFERENT_CONTENT)
//   GET /api/orders/1      correct  -> alice's; others get 403 (ACCESS_DENIED)
//   GET /api/orders/2      BROKEN   -> alice's, but any authenticated role sees it
//   GET /api/admin/users   BROKEN   -> no check at all, anonymous included
//   GET /api/volatile      correct  -> fresh uuid + counter every call (UNPROVEN_VOLATILE)
//   GET /api/health        correct  -> public

const USERS = new Map([
  ['alice-token', { id: 'alice', role: 'user', name: 'Alice' }],
  ['bob-token', { id: 'bob', role: 'user', name: 'Bob' }],
  ['admin-token', { id: 'root', role: 'admin', name: 'Root' }],
])

const ORDERS = new Map([
  ['1', { id: '1', owner: 'alice', item: 'widget', total: 1200 }],
  ['2', { id: '2', owner: 'alice', item: 'gadget', total: 3400 }],
  // Bob's own order, for horizontal IDOR testing. Order 1's handler checks
  // ownership correctly, so alice must NOT be able to read order 5 through it.
  ['5', { id: '5', owner: 'bob', item: 'sprocket', total: 900 }],
])

function identify(request) {
  const auth = request.headers.authorization
  if (typeof auth !== 'string') return null
  const token = auth.replace(/^Bearer\s+/i, '').trim()
  return USERS.get(token) ?? null
}

function send(response, status, payload) {
  const body = JSON.stringify(payload)
  response.writeHead(status, {
    'Content-Type': 'application/json',
    // Deliberate noise on every response: a grinder that cannot see past these
    // will find nothing at all.
    'X-Request-Id': randomUUID(),
    Date: new Date().toUTCString(),
  })
  response.end(body)
}

export function startAuthzTestbed() {
  let volatileCounter = 0
  const server = createServer((request, response) => {
    const url = new URL(request.url, 'http://localhost')
    const user = identify(request)
    const path = url.pathname

    if (path === '/api/health') {
      return send(response, 200, { status: 'ok' })
    }

    if (path === '/api/volatile') {
      volatileCounter += 1
      // Genuinely different every call, and not maskable by normalization: the
      // counter is a plain integer under a non-temporal key.
      return send(response, 200, { nonce: randomUUID(), sequence: volatileCounter })
    }

    if (path === '/api/me') {
      if (user === null) return send(response, 401, { error: 'unauthenticated' })
      return send(response, 200, { id: user.id, name: user.name, role: user.role })
    }

    if (path === '/api/admin/users') {
      // PLANTED BUG: no authorization check whatsoever.
      return send(response, 200, {
        users: [...USERS.values()].map((u) => ({ id: u.id, role: u.role })),
      })
    }

    if (path === '/api/invoices') {
      // PLANTED BUG reachable only by identifier mutation: the referenced order
      // is looked up with no ownership check at all. Role replay alone tests
      // "can bob read the invoice for alice's order"; proving the other
      // direction -- alice reading bob's invoice -- requires substituting bob's
      // order id into alice's own request.
      const referenced = ORDERS.get(url.searchParams.get('order'))
      if (referenced === undefined) return send(response, 404, { error: 'not found' })
      if (user === null) return send(response, 401, { error: 'unauthenticated' })
      return send(response, 200, {
        invoice: `INV-${referenced.id}`,
        item: referenced.item,
        total: referenced.total,
        owner: referenced.owner,
      })
    }

    const orderMatch = /^\/api\/orders\/(\w+)$/.exec(path)
    if (orderMatch !== null) {
      const order = ORDERS.get(orderMatch[1])
      if (order === undefined) return send(response, 404, { error: 'not found' })
      if (user === null) return send(response, 401, { error: 'unauthenticated' })
      if (order.id === '2') {
        // PLANTED BUG: ownership is never checked for order 2.
        return send(response, 200, order)
      }
      if (order.owner !== user.id && user.role !== 'admin') {
        return send(response, 403, { error: 'forbidden' })
      }
      return send(response, 200, order)
    }

    return send(response, 404, { error: 'no route' })
  })

  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address()
      resolve({
        port,
        origin: `http://127.0.0.1:${port}`,
        close: () => new Promise((done) => server.close(done)),
      })
    })
  })
}

export const TESTBED_TOKENS = {
  alice: 'alice-token',
  bob: 'bob-token',
  admin: 'admin-token',
}

// What the grinder is expected to conclude, asserted by the controller tests.
export const TESTBED_GROUND_TRUTH = Object.freeze({
  '/api/orders/2': 'AUTHZ_BYPASS_CANDIDATE',
  '/api/admin/users': 'AUTHZ_BYPASS_CANDIDATE',
  '/api/orders/1': 'ACCESS_DENIED',
  '/api/me': 'DIFFERENT_CONTENT',
  '/api/volatile': 'UNPROVEN_VOLATILE',
})
