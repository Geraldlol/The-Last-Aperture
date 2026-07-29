// V-001 — VULNERABLE fixture. NOT RUNNABLE. Written from scratch.
//
// Bug class (exactly one): object-level authorization missing on a mutating route.
// Lens: web-and-api / topic `authz-object-level`
// Expected: Critical, CWE-639
//
// The defect is the ABSENCE of an ownership predicate on the load that precedes
// the write. `requireSession` answers "is this caller authenticated". Nothing in
// this file answers "may THIS caller reach THIS order". The read route below is
// scoped correctly, which is the point: a reviewer who checks the GET and stops
// clears the PATCH.
//
// There is no app.listen, no database, no route registration outside this module
// and no payload anywhere in the file. It cannot run.

import type { Request, Response } from 'express'
import { Router } from 'express'

// Stand-ins so the shape is readable. Neither talks to anything.
declare const Order: {
  findByPk(id: unknown, opts?: unknown): Promise<OrderRow | null>
  findOne(opts: unknown): Promise<OrderRow | null>
}
declare const auditTrail: { record(event: string, subject: string): Promise<void> }
declare function requireSession(req: Request, res: Response, next: () => void): void

interface OrderRow {
  id: string
  customerId: string
  internalNotes: string
  save(): Promise<void>
}

export const orders = Router()

// The READ path is scoped. `customerId` comes from the session, not the request.
orders.get('/api/orders/:id', requireSession, async (req, res) => {
  const order = await Order.findOne({
    where: { id: req.params.id, customerId: req.session.customerId },
  })
  if (!order) return res.status(404).json({ error: 'not found' })
  return res.json({ id: order.id, notes: order.internalNotes })
})

// The WRITE path is not. `findByPk` takes the caller's path segment and nothing
// ties the returned row to `req.session.customerId` — not here, not in a
// middleware on this router, not in a hook on the model. Any authenticated
// caller who knows or guesses an order id rewrites that order's notes.
//
// The 404 is a not-found check, not an authorization check. It fires only when
// the row is absent; it says nothing about who owns the row when it is present.
orders.patch('/api/orders/:id/notes', requireSession, async (req, res) => {
  const order = await Order.findByPk(req.params.id)
  if (!order) return res.status(404).json({ error: 'not found' })

  order.internalNotes = String(req.body.notes ?? '')
  await order.save()
  await auditTrail.record('order.notes.updated', order.id)

  return res.json({ id: order.id, notes: order.internalNotes })
})

// Same defect, second site: the bulk path reuses a different query builder and
// never re-checks ownership on any element of the list.
orders.post('/api/orders/bulk/close', requireSession, async (req, res) => {
  const ids: string[] = Array.isArray(req.body.ids) ? req.body.ids.map(String) : []
  const closed: string[] = []
  for (const id of ids) {
    const order = await Order.findByPk(id)
    if (!order) continue
    order.internalNotes = `${order.internalNotes}\nclosed`
    await order.save()
    closed.push(order.id)
  }
  return res.json({ closed })
})

declare module 'express' {
  interface Request {
    session: { customerId: string }
  }
}
