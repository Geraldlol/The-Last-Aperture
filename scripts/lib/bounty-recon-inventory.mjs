import { readFileSync } from 'node:fs'
import Ajv2020 from 'ajv/dist/2020.js'

const SCHEMA_URL = new URL('../../schemas/bounty-surface-inventory.schema.json', import.meta.url)

let compiledValidator = null

export function assertValidInventory(value) {
  if (compiledValidator === null) {
    const ajv = new Ajv2020({ allErrors: true, strict: false })
    compiledValidator = ajv.compile(JSON.parse(readFileSync(SCHEMA_URL, 'utf8')))
  }
  if (compiledValidator(value)) return
  const detail = (compiledValidator.errors ?? [])
    .map((error) => `${error.instancePath || '/'} ${error.message}`)
    .join('; ')
  throw new Error(`surface inventory failed schema validation: ${detail}`)
}

export function createInventory({ engagementId, createdAt }) {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/bounty-surface-inventory',
    engagement_id: engagementId,
    created_at: createdAt,
    hosts: [],
    zone_hints: [],
    refused: [],
    gaps: [],
  }
}

function mergeSources(existing, source) {
  return existing.includes(source) ? existing : [...existing, source]
}

// Richer means "carries a probe result at all", then "carries a status". A later
// bare sighting must never overwrite an earlier probed record.
function pickProbe(previous, next) {
  if (next === undefined || next === null) return previous
  if (previous === undefined || previous === null) return next
  if (previous.status === null || previous.status === undefined) return next
  return previous
}

export function recordHost(inventory, { host, port, source, observedAt, probe }) {
  const index = inventory.hosts.findIndex((entry) => entry.host === host && entry.port === port)
  if (index === -1) {
    const entry = { host, port, sources: [source] }
    if (observedAt !== undefined) entry.observed_at = observedAt
    if (probe !== undefined && probe !== null) entry.probe = probe
    return { ...inventory, hosts: [...inventory.hosts, entry] }
  }
  const previous = inventory.hosts[index]
  const merged = {
    ...previous,
    sources: mergeSources(previous.sources, source),
  }
  if (observedAt !== undefined) merged.observed_at = observedAt
  const chosen = pickProbe(previous.probe, probe)
  if (chosen !== undefined && chosen !== null) merged.probe = chosen
  const hosts = [...inventory.hosts]
  hosts[index] = merged
  return { ...inventory, hosts }
}

export function recordZoneHint(inventory, { zone, source }) {
  const index = inventory.zone_hints.findIndex((entry) => entry.zone === zone)
  if (index === -1) {
    return { ...inventory, zone_hints: [...inventory.zone_hints, { zone, sources: [source] }] }
  }
  const zoneHints = [...inventory.zone_hints]
  zoneHints[index] = {
    ...zoneHints[index],
    sources: mergeSources(zoneHints[index].sources, source),
  }
  return { ...inventory, zone_hints: zoneHints }
}

export function recordRefusal(inventory, refusal) {
  const already = inventory.refused.some(
    (entry) => entry.host === refusal.host && entry.reason === refusal.reason,
  )
  if (already) return inventory
  return {
    ...inventory,
    refused: [...inventory.refused, {
      host: refusal.host,
      reason: refusal.reason,
      ...(refusal.ruleId === undefined ? {} : { ruleId: refusal.ruleId }),
    }],
  }
}

export function recordGap(inventory, { source, reason, detail }) {
  return {
    ...inventory,
    gaps: [...inventory.gaps, {
      source,
      reason,
      ...(detail === undefined ? {} : { detail: String(detail).slice(0, 1024) }),
    }],
  }
}

export function inventorySummary(inventory) {
  return {
    hosts: inventory.hosts.length,
    zoneHints: inventory.zone_hints.length,
    refused: inventory.refused.length,
    gaps: inventory.gaps.length,
    // There is no COMPLETE. A sweep with a failed source cannot be reported as a
    // full picture of the surface, and the status string is chosen so nobody can
    // read it as one.
    status: inventory.gaps.length > 0 ? 'PARTIAL' : 'OBSERVED',
  }
}
