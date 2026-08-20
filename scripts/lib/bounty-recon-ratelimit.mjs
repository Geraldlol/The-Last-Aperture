// A program's stated rate limit is not a performance knob: exceeding it puts the
// request outside the granted authorization, and it is the most common way an
// automated hunter gets removed from a program. So there is no bypass parameter,
// no burst allowance beyond a single token, and no fallback to the ambient clock.

export function createRateLimiter({ ratePerSecond, now, sleep }) {
  if (!Number.isInteger(ratePerSecond) || ratePerSecond < 1) {
    throw new Error('ratePerSecond must be a positive integer')
  }
  if (typeof now !== 'function') {
    throw new Error('now must be an injected function returning milliseconds')
  }
  if (typeof sleep !== 'function') {
    throw new Error('sleep must be an injected async function taking milliseconds')
  }

  const intervalMs = 1000 / ratePerSecond
  let nextAllowedAt = null
  let issued = 0
  let waitedMs = 0

  return {
    async acquire() {
      const current = now()
      if (nextAllowedAt !== null && current < nextAllowedAt) {
        const wait = nextAllowedAt - current
        waitedMs += wait
        await sleep(wait)
      }
      // Anchored to the moment the token is issued rather than to a running
      // schedule, so idling never banks credit for a later burst.
      nextAllowedAt = now() + intervalMs
      issued += 1
    },
    stats() {
      return { issued, waitedMs }
    },
  }
}
