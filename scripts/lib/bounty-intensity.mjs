// The sealed intensity tier, turned into behaviour every phase can consult.
//
// Until now `intensity` was validated at seal time and then never read, which
// made the HAM dial decorative in exactly the way the validity window was. This
// is the one place that maps a tier to numbers, so a phase cannot quietly invent
// its own interpretation.
//
// The invariant that makes any of this safe: intensity changes how hard we work
// INSIDE the sealed perimeter. It never widens scope, and it never exceeds the
// program's stated rate limit. Both are asserted in tests.

export const INTENSITY_TIERS = Object.freeze(['normal', 'aggressive', 'ham'])

const PROFILES = Object.freeze({
  normal: {
    tier: 'normal',
    // A sample, not a sweep. The daily driver should be cheap enough to run
    // often without thinking about it.
    probesPerInsertionPoint: 2,
    insertionPointCap: 8,
    requestCap: 50,
    concurrency: 1,
    earlyExitOnSignal: true,
    recurseOnDiscovery: false,
    compoundAttacks: false,
    exhaustiveRoleMatrix: false,
    classes: ['error-injection', 'passive'],
  },
  aggressive: {
    tier: 'aggressive',
    // Exhaustive within each class, still one class at a time.
    probesPerInsertionPoint: Number.POSITIVE_INFINITY,
    insertionPointCap: 64,
    requestCap: 500,
    concurrency: 2,
    earlyExitOnSignal: false,
    recurseOnDiscovery: false,
    compoundAttacks: false,
    exhaustiveRoleMatrix: true,
    classes: ['error-injection', 'ssrf-oob', 'passive'],
  },
  ham: {
    tier: 'ham',
    // Everything, everywhere, until it converges. No early exit, no sampling,
    // no ceiling other than the sealed rate limit.
    probesPerInsertionPoint: Number.POSITIVE_INFINITY,
    insertionPointCap: Number.POSITIVE_INFINITY,
    requestCap: Number.POSITIVE_INFINITY,
    concurrency: Number.POSITIVE_INFINITY,
    earlyExitOnSignal: false,
    recurseOnDiscovery: true,
    compoundAttacks: true,
    exhaustiveRoleMatrix: true,
    classes: ['error-injection', 'ssrf-oob', 'passive'],
  },
})

export function resolveIntensityProfile(scope) {
  const permissions = scope?.authorization?.permissions
  const tier = permissions?.intensity
  if (!INTENSITY_TIERS.includes(tier)) {
    throw new Error(`sealed scope carries no usable intensity tier (got ${JSON.stringify(tier)})`)
  }
  const profile = PROFILES[tier]
  const rateLimit = permissions.rate_limit_rps

  // Concurrency is clamped to the sealed rate limit, always. HAM asks for
  // unbounded parallelism; the program's stated limit is what it actually gets,
  // because that limit IS the authorization and no tier outranks it.
  const concurrency = Number.isInteger(rateLimit) && rateLimit > 0
    ? Math.max(1, Math.min(profile.concurrency, rateLimit))
    : 1

  return Object.freeze({ ...profile, concurrency, rateLimitRps: rateLimit })
}

// Applies the tier's caps to a work list, and says what it dropped. A silent
// truncation reads as "we covered everything" when we did not.
export function applyCap(items, cap, label) {
  if (!Number.isFinite(cap) || items.length <= cap) {
    return { items, dropped: 0, note: null }
  }
  const dropped = items.length - cap
  return {
    items: items.slice(0, cap),
    dropped,
    note: `${label}: covered ${cap} of ${items.length}, ${dropped} not examined at this intensity`,
  }
}

export function selectProbes(probes, profile) {
  return applyCap(probes, profile.probesPerInsertionPoint, 'probes per insertion point')
}

export function selectInsertionPoints(points, profile) {
  return applyCap(points, profile.insertionPointCap, 'insertion points')
}

export function selectRequests(requests, profile) {
  return applyCap(requests, profile.requestCap, 'requests')
}

export function describeIntensity(profile) {
  const unbounded = (value) => (Number.isFinite(value) ? String(value) : 'unbounded')
  return [
    `tier=${profile.tier}`,
    `probes/point=${unbounded(profile.probesPerInsertionPoint)}`,
    `points/request=${unbounded(profile.insertionPointCap)}`,
    `requests=${unbounded(profile.requestCap)}`,
    `concurrency=${profile.concurrency} (clamped to ${profile.rateLimitRps}/s)`,
    `earlyExit=${profile.earlyExitOnSignal}`,
    `recurse=${profile.recurseOnDiscovery}`,
  ].join(' ')
}
