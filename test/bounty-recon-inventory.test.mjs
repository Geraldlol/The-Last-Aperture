import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  assertValidInventory,
  createInventory,
  inventorySummary,
  recordGap,
  recordHost,
  recordRefusal,
  recordZoneHint,
} from '../scripts/lib/bounty-recon-inventory.mjs'

const AT = '2026-08-21T10:00:00.000Z'

const fresh = () => createInventory({ engagementId: 'ywh-acme-2026-08', createdAt: AT })

test('a fresh inventory is schema valid and reports OBSERVED', () => {
  const inventory = fresh()
  assert.doesNotThrow(() => assertValidInventory(inventory))
  assert.equal(inventorySummary(inventory).status, 'OBSERVED')
})

test('records a host with its source and probe', () => {
  const inventory = recordHost(fresh(), {
    host: 'api.acme.example',
    port: 443,
    source: 'tls',
    observedAt: AT,
    probe: { url: 'https://api.acme.example/', status: 200, tech_hints: ['nginx'] },
  })
  assert.doesNotThrow(() => assertValidInventory(inventory))
  assert.equal(inventory.hosts.length, 1)
  assert.equal(inventory.hosts[0].probe.status, 200)
})

test('dedupes a host on host:port and unions its sources', () => {
  let inventory = recordHost(fresh(), { host: 'a.acme.example', port: 443, source: 'tls' })
  inventory = recordHost(inventory, { host: 'a.acme.example', port: 443, source: 'ctlog' })
  assert.equal(inventory.hosts.length, 1)
  assert.deepEqual(inventory.hosts[0].sources, ['tls', 'ctlog'])
})

test('the same host on a different port is a distinct entry', () => {
  let inventory = recordHost(fresh(), { host: 'a.acme.example', port: 443, source: 'tls' })
  inventory = recordHost(inventory, { host: 'a.acme.example', port: 8443, source: 'tls' })
  assert.equal(inventory.hosts.length, 2)
})

test('a later bare sighting never overwrites an earlier probed record', () => {
  let inventory = recordHost(fresh(), {
    host: 'a.acme.example', port: 443, source: 'tls',
    probe: { url: 'https://a.acme.example/', status: 200 },
  })
  inventory = recordHost(inventory, { host: 'a.acme.example', port: 443, source: 'ctlog' })
  assert.equal(inventory.hosts[0].probe.status, 200)
  assert.deepEqual(inventory.hosts[0].sources, ['tls', 'ctlog'])
})

test('a probe result fills in over a bare sighting', () => {
  let inventory = recordHost(fresh(), { host: 'a.acme.example', port: 443, source: 'ctlog' })
  inventory = recordHost(inventory, {
    host: 'a.acme.example', port: 443, source: 'probe',
    probe: { url: 'https://a.acme.example/', status: 403 },
  })
  assert.equal(inventory.hosts[0].probe.status, 403)
})

test('records and dedupes zone hints', () => {
  let inventory = recordZoneHint(fresh(), { zone: 'm.acme.example', source: 'tls' })
  inventory = recordZoneHint(inventory, { zone: 'm.acme.example', source: 'ctlog' })
  assert.equal(inventory.zone_hints.length, 1)
  assert.deepEqual(inventory.zone_hints[0].sources, ['tls', 'ctlog'])
})

test('retains refusals because they describe the perimeter', () => {
  let inventory = recordRefusal(fresh(), {
    host: 'other.example', reason: 'candidate-unlisted', ruleId: 'none',
  })
  inventory = recordRefusal(inventory, {
    host: 'other.example', reason: 'candidate-unlisted', ruleId: 'none',
  })
  assert.equal(inventory.refused.length, 1, 'identical refusals dedupe')
  assert.doesNotThrow(() => assertValidInventory(inventory))
})

test('a gap forces PARTIAL', () => {
  const inventory = recordGap(fresh(), {
    source: 'crt.sh', reason: 'http-502', detail: 'three consecutive attempts',
  })
  assert.doesNotThrow(() => assertValidInventory(inventory))
  const summary = inventorySummary(inventory)
  assert.equal(summary.status, 'PARTIAL')
  assert.equal(summary.gaps, 1)
})

test('finding hosts does not clear a gap', () => {
  // The trap this guards: a sweep that found plenty of surface still has an
  // incomplete picture if a source died, and must not read as clean.
  let inventory = recordGap(fresh(), { source: 'crt.sh', reason: 'http-502' })
  inventory = recordHost(inventory, { host: 'a.acme.example', port: 443, source: 'tls' })
  inventory = recordHost(inventory, { host: 'b.acme.example', port: 443, source: 'tls' })
  const summary = inventorySummary(inventory)
  assert.equal(summary.hosts, 2)
  assert.equal(summary.status, 'PARTIAL')
})

test('the schema has no COMPLETE status to reach for', () => {
  const inventory = fresh()
  const summary = inventorySummary(inventory)
  assert.notEqual(summary.status, 'COMPLETE')
  const withGap = recordGap(inventory, { source: 'x', reason: 'y' })
  assert.notEqual(inventorySummary(withGap).status, 'COMPLETE')
})

test('rejects an unknown top level property', () => {
  const inventory = { ...fresh(), surprise: true }
  assert.throws(() => assertValidInventory(inventory), /surprise|additional/)
})
