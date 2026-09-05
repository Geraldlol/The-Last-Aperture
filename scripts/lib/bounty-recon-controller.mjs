import { readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { assertScopeCurrent } from './bounty-contracts.mjs'
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
  if (!Array.isArray(seeds)) {
    throw new Error('seeds must be an array')
  }
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) {
    throw new Error('now must be a valid Date')
  }
  const scope = await loadSealedScope(bundlePath)
  // Before any candidate is gated, before any socket: an expired grant makes
  // every in-scope request unauthorized too.
  assertScopeCurrent({ scope, now })
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

  // The gate refuses every host when the scope seals no marker, so a bundle
  // sealed before the mandate stops the sweep before it reaches a socket. That
  // is a failed source, not a clean result: recorded once here as a gap, because
  // per-host refusals alone leave the summary reading OBSERVED with gaps=0 --
  // indistinguishable from a perimeter that is genuinely empty.
  const sealedMarker = scope.program?.required_user_agent
  if (typeof sealedMarker !== 'string' || sealedMarker.length === 0) {
    inventory = recordGap(inventory, {
      source: 'sealed-scope',
      reason: 'required-user-agent-missing',
      detail: 'the sealed scope declares no required_user_agent, so no candidate can be probed; reseal the bundle with --user-agent',
    })
  }

  // A sealed wildcard names a zone we hold. Asking a certificate log about it
  // sends nothing to the target, so it is a starting point in its own right --
  // which matters because a program granting *.zone without the apex leaves no
  // seedable entry to that zone at all. Names found are gated like any other.
  const wildcardZones = (scope.scope_rules?.allow ?? [])
    .filter((rule) => rule.host_kind === 'wildcard' && typeof rule.host === 'string')
    .map((rule) => rule.host)
  if (seeds.length === 0 && !(sources.includes('ctlog') && wildcardZones.length > 0)) {
    throw new Error('at least one --seed is required, or a sealed wildcard zone with the ctlog source')
  }

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
      for (const name of harvest.names) discovered.push({ name, source: 'tls' })
      inventory = recordHost(inventory, {
        host: approval.host,
        port: approval.port,
        source: 'seed',
        observedAt: now.toISOString(),
      })
    }
  }


  if (sources.includes('ctlog')) {
    const apexes = [...new Set([...gatedSeeds.approved.map((a) => a.host), ...wildcardZones])]
    for (const apex of apexes) {
      const ct = await fetchCtLogNames({ apex, fetchImpl })
      if (ct.gap !== null) {
        inventory = recordGap(inventory, ct.gap)
      }
      for (const name of ct.names) discovered.push({ name, source: 'ctlog' })
    }
  }

  // Classification collapses many names onto one candidate, so provenance is
  // carried alongside rather than inferred from it. The inventory is evidence: a
  // certificate-log observation recorded as 'tls' would claim a handshake that a
  // ctlog-only sweep never performs. A name both sources returned carries both.
  const sourcesByCandidate = new Map()
  const candidateKey = (candidate) => `${candidate.kind}:${candidate.value}`
  const classifiedAll = []
  for (const { name, source } of discovered) {
    const candidate = classifyCandidate(name)
    if (candidate === null) continue
    classifiedAll.push(candidate)
    const key = candidateKey(candidate)
    if (!sourcesByCandidate.has(key)) sourcesByCandidate.set(key, new Set())
    sourcesByCandidate.get(key).add(source)
  }
  // Sorted so a name two sources returned lands in the sealed inventory in the
  // same order on every run.
  const candidateSources = (candidate) =>
    [...(sourcesByCandidate.get(candidateKey(candidate)) ?? [])].sort()

  const classified = dedupeCandidates(classifiedAll)
  const zoneHints = classified.filter((candidate) => candidate.kind === 'zone_hint')
  for (const hint of zoneHints) {
    for (const source of candidateSources(hint)) {
      inventory = recordZoneHint(inventory, { zone: hint.value, source })
    }
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
