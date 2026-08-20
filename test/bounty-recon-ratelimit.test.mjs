import assert from 'node:assert/strict'
import { test } from 'node:test'
import { createRateLimiter } from '../scripts/lib/bounty-recon-ratelimit.mjs'

// A virtual clock: sleep advances time instantly, so pacing is asserted exactly
// rather than by wall-clock tolerance.
function virtualClock() {
  let millis = 0
  return {
    now: () => millis,
    sleep: async (ms) => { millis += ms },
    advance: (ms) => { millis += ms },
    elapsed: () => millis,
  }
}

test('the first token is issued without waiting', async () => {
  const clock = virtualClock()
  const limiter = createRateLimiter({ ratePerSecond: 5, now: clock.now, sleep: clock.sleep })
  await limiter.acquire()
  assert.equal(clock.elapsed(), 0)
  assert.equal(limiter.stats().issued, 1)
})

test('paces subsequent tokens at the sealed rate', async () => {
  const clock = virtualClock()
  const limiter = createRateLimiter({ ratePerSecond: 5, now: clock.now, sleep: clock.sleep })
  for (let index = 0; index < 6; index += 1) await limiter.acquire()
  // 6 tokens at 5/sec: the first is free, the remaining 5 cost 200ms each
  assert.equal(clock.elapsed(), 1000)
  assert.equal(limiter.stats().issued, 6)
  assert.equal(limiter.stats().waitedMs, 1000)
})

test('a slower rate waits proportionally longer', async () => {
  const clock = virtualClock()
  const limiter = createRateLimiter({ ratePerSecond: 1, now: clock.now, sleep: clock.sleep })
  await limiter.acquire()
  await limiter.acquire()
  await limiter.acquire()
  assert.equal(clock.elapsed(), 2000)
})

test('time passing outside the limiter counts toward the next token', async () => {
  const clock = virtualClock()
  const limiter = createRateLimiter({ ratePerSecond: 2, now: clock.now, sleep: clock.sleep })
  await limiter.acquire()
  clock.advance(500)
  await limiter.acquire()
  // the 500ms interval already covers the 500ms this token needed
  assert.equal(clock.elapsed(), 500)
  assert.equal(limiter.stats().waitedMs, 0)
})

test('refuses a rate that is not a positive integer', () => {
  for (const bad of [0, -1, 1.5, '5', null, undefined, Number.NaN, Infinity]) {
    assert.throws(
      () => createRateLimiter({ ratePerSecond: bad, now: () => 0, sleep: async () => {} }),
      /positive integer/,
      String(bad),
    )
  }
})

test('refuses a missing clock so it can never fall back to the ambient one', () => {
  assert.throws(() => createRateLimiter({ ratePerSecond: 5 }), /now/)
  assert.throws(() => createRateLimiter({ ratePerSecond: 5, now: () => 0 }), /sleep/)
})

test('there is no burst allowance beyond a single token', async () => {
  const clock = virtualClock()
  const limiter = createRateLimiter({ ratePerSecond: 10, now: clock.now, sleep: clock.sleep })
  // idle a long while, which must not bank tokens
  clock.advance(60_000)
  await limiter.acquire()
  await limiter.acquire()
  assert.equal(clock.elapsed(), 60_100, 'second token still paid its 100ms')
})
