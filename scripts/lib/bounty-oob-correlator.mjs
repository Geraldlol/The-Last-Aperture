import { extractNonce, lookupMint } from './bounty-oob-payload.mjs'

export function normalizeInteraction(raw) {
  if (raw === null || typeof raw !== 'object') {
    throw new Error('interaction must be an object')
  }
  const protocol = raw.protocol
  if (typeof protocol !== 'string' || protocol.length === 0) {
    throw new Error('interaction is missing protocol')
  }
  const fullId = raw['full-id'] ?? raw['unique-id']
  if (typeof fullId !== 'string' || fullId.length === 0) {
    throw new Error('interaction is missing full-id')
  }
  return {
    protocol,
    fullId,
    qType: typeof raw['q-type'] === 'string' ? raw['q-type'] : null,
    remoteAddress: typeof raw['remote-address'] === 'string' ? raw['remote-address'] : null,
    observedAt: typeof raw.timestamp === 'string' ? raw.timestamp : null,
    rawRequest: typeof raw['raw-request'] === 'string' ? raw['raw-request'] : null,
    rawResponse: typeof raw['raw-response'] === 'string' ? raw['raw-response'] : null,
  }
}

export function correlateInteraction({ ledger, correlationId, server, interaction }) {
  const nonce = extractNonce({ host: interaction.fullId, correlationId, server })
  if (nonce === null) {
    return { matched: false, reason: 'host-not-ours', interaction }
  }
  const mint = lookupMint(ledger, nonce)
  if (mint === null) {
    return { matched: false, reason: 'nonce-not-in-ledger', interaction }
  }
  return { matched: true, nonce, mint, interaction }
}

export function summarizeCorrelation(results) {
  const byBugClass = {}
  let matched = 0
  for (const result of results) {
    if (!result.matched) continue
    matched += 1
    const bugClass = result.mint.bugClass ?? 'unknown'
    byBugClass[bugClass] = (byBugClass[bugClass] ?? 0) + 1
  }
  return {
    total: results.length,
    matched,
    unmatched: results.length - matched,
    byBugClass,
    // An absent callback is not evidence the target is sound. A blind vector that
    // produced no interaction is inconclusive, so the status says only what was
    // observed and never implies a negative result.
    status: results.length === 0 ? 'NO_INTERACTION_OBSERVED' : 'INTERACTIONS_OBSERVED',
  }
}
