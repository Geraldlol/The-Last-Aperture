import { readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { classifyCandidate, dedupeCandidates } from './bounty-recon-candidate.mjs'
import { fetchCtLogNames } from './bounty-recon-ctlog.mjs'
import { gateCandidates } from './bounty-recon-gate.mjs'
import {
  assertValidInventory,
  createInventory,
  inventorySummary,
  recordGap,
  recordHost,
  recordRefusal,
  recordZoneHint,
} from './bounty-recon-inventory.mjs'
import { probeHost } from './bounty-recon-probe.mjs'
import { createRateLimiter } from './bounty-recon-ratelimit.mjs'
import { harvestTlsSans } from './bounty-recon-tls.mjs'

const INVENTORY_FILE = 'surface-inventory.json'
const SCOPE_FILE = 'scope.json'

export const RECON_SOURCES = ['tls', 'ctlog']

async function loadSealedScope(bundlePath) {
  return JSON.parse(await readFile(join(bundlePath, SCOPE_FILE), 'utf8'))
}

async function saveInventory(bundlePath, inventory) {
  assertValidInventory(inventory)
  await writeFile(join(bundlePath, INVENTORY_FILE), `${JSON.stringify(inventory, null, 2)}\n`, 'utf8')
}

async function loadInventory(bundlePath) {
  const inventory = JSON.parse(await readFile(join(bundlePath, INVENTORY_FILE), 'utf8'))
  assertValidInventory(inventory)
  return inventory
}

export async function runRecon({
  bundlePath,
  seeds,
  sources = RECON_SOURCES,
  now,
  fetchImpl = fetch,
  connectImpl,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  clock = () => Date.now(),
}) {
  if (!Array.isArray(seeds) || seeds.length === 0) {
    throw new Error('at least one --seed is required')
  }
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) {
    throw new Error('now must be a valid Date')
  }
  const scope = await loadSealedScope(bundlePath)
  // The rate limit comes from the sealed scope, never from a flag: a caller must
  // not be able to out-argue the program's stated limit.
  const limiter = createRateLimiter({
    ratePerSecond: scope.authorization.permissions.rate_limit_rps,
    now: clock,
    sleep,
  })

  let inventory = createInventory({
    engagementId: scope.engagement_id,
    createdAt: now.toISOString(),
  })

  const seedCandidates = dedupeCandidates(seeds.map(classifyCandidate).filter(Boolean))
  const gatedSeeds = gateCandidates({ sealedScope: scope, candidates: seedCandidates })
  for (const refusal of gatedSeeds.refused) {
    inventory = recordRefusal(inventory, refusal)
  }

  // Discovery: every name a source emits is a candidate, and every candidate is
  // re-gated before anything touches it.
  const discovered = []
  for (const approval of gatedSeeds.approved) {
    if (sources.includes('tls')) {
      const harvest = await harvestTlsSans({ approval, connectImpl })
      if (harvest.gap !== null) {
        inventory = recordGap(inventory, harvest.gap)
      }
      for (const name of harvest.names) discovered.push(name)
      inventory = recordHost(inventory, {
        host: approval.host,
        port: approval.port,
        source: 'seed',
        observedAt: now.toISOString(),
      })
    }
    if (sources.includes('ctlog')) {
      const ct = await fetchCtLogNames({ apex: approval.host, fetchImpl })
      if (ct.gap !== null) {
        inventory = recordGap(inventory, ct.gap)
      }
      for (const name of ct.names) discovered.push(name)
    }
  }

  const classified = dedupeCandidates(discovered.map(classifyCandidate).filter(Boolean))
  const zoneHints = classified.filter((candidate) => candidate.kind === 'zone_hint')
  for (const hint of zoneHints) {
    inventory = recordZoneHint(inventory, { zone: hint.value, source: 'tls' })
  }

  const gated = gateCandidates({
    sealedScope: scope,
    candidates: classified.filter((candidate) => candidate.kind === 'host'),
  })
  for (const refusal of gated.refused) {
    inventory = recordRefusal(inventory, refusal)
  }

  // Seeds are probed too. Relying on a seed turning up in its own certificate's
  // SAN list is incidental -- www.wikipedia.org does not appear in its own SANs,
  // so the most obviously interesting host in the sweep would silently get no
  // liveness data at all.
  const probeTargets = new Map()
  for (const approval of [...gatedSeeds.approved, ...gated.approved]) {
    probeTargets.set(`${approval.host}:${approval.port}`, approval)
  }

  for (const approval of probeTargets.values()) {
    const probe = await probeHost({ approval, limiter, fetchImpl })
    inventory = recordHost(inventory, {
      host: approval.host,
      port: approval.port,
      source: 'probe',
      observedAt: now.toISOString(),
      probe,
    })
  }

  await saveInventory(bundlePath, inventory)
  return { ...inventorySummary(inventory), rateLimitRps: scope.authorization.permissions.rate_limit_rps, paced: limiter.stats() }
}

export async function reconStatus({ bundlePath }) {
  const inventory = await loadInventory(bundlePath)
  return { ...inventorySummary(inventory), gapDetail: inventory.gaps }
}
