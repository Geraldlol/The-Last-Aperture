import assert from 'node:assert/strict'
import { test } from 'node:test'
import { gateCandidates } from '../scripts/lib/bounty-recon-gate.mjs'
import { createRateLimiter } from '../scripts/lib/bounty-recon-ratelimit.mjs'
import { deriveTechHints, extractTitle, probeHost } from '../scripts/lib/bounty-recon-probe.mjs'

function approvalFor(host) {
  const scope = {
    program: { required_user_agent: 'BugBounty-acme' },
    scope_rules: {
      allow: [{ rule_id: 'a1', host_kind: 'wildcard', host: 'acme.example' }],
      deny: [],
    },
  }
  const { approved } = gateCandidates({ sealedScope: scope, candidates: [{ kind: 'host', value: host }] })
  return approved[0]
}

function countingLimiter() {
  let calls = 0
  return { acquire: async () => { calls += 1 }, calls: () => calls }
}

const htmlResponse = (body, extra = {}) => new Response(body, {
  status: 200,
  headers: { 'content-type': 'text/html; charset=utf-8', ...extra },
})

test('extracts a title and collapses whitespace', () => {
  assert.equal(extractTitle('<html><head><title>  Acme\n  Admin </title>'), 'Acme Admin')
  assert.equal(extractTitle('<TITLE>Upper</TITLE>'), 'Upper')
  assert.equal(extractTitle('<title></title>'), null)
  assert.equal(extractTitle('no title here'), null)
  assert.equal(extractTitle(''), null)
  assert.equal(extractTitle(null), null)
})

test('caps the title scan so a huge response cannot stall the sweep', () => {
  const buried = `${'x'.repeat(200_000)}<title>Too Late</title>`
  assert.equal(extractTitle(buried), null)
  const early = `<title>Found</title>${'x'.repeat(200_000)}`
  assert.equal(extractTitle(early), 'Found')
})

test('derives tech hints from recognised headers', () => {
  const headers = new Headers({ server: 'nginx/1.24', 'x-powered-by': 'PHP/8.2' })
  const hints = deriveTechHints(headers)
  assert.equal(hints.length, 2)
  assert.ok(hints.some((h) => h.startsWith('server: nginx')))
  assert.ok(hints.some((h) => h.startsWith('x-powered-by: PHP')))
})

test('tech hints tolerate a plain object and an absent header bag', () => {
  assert.deepEqual(deriveTechHints({ server: 'apache' }), ['server: apache'])
  assert.deepEqual(deriveTechHints(null), [])
})

test('probes an approved host and records the response facts', async () => {
  const limiter = countingLimiter()
  const probe = await probeHost({
    approval: approvalFor('api.acme.example'),
    limiter,
    fetchImpl: async () => htmlResponse('<html><head><title>Acme API</title></head>', {
      server: 'nginx', 'content-length': '128',
    }),
  })
  assert.equal(probe.status, 200)
  assert.equal(probe.title, 'Acme API')
  assert.equal(probe.server, 'nginx')
  assert.equal(probe.content_length, 128)
  assert.equal(probe.error, null)
  assert.equal(limiter.calls(), 1, 'exactly one token per probe')
})

test('records a redirect without following it', async () => {
  let calls = 0
  const probe = await probeHost({
    approval: approvalFor('api.acme.example'),
    limiter: countingLimiter(),
    fetchImpl: async (url, init) => {
      calls += 1
      assert.equal(init.redirect, 'manual', 'redirects must not be followed')
      return new Response(null, { status: 302, headers: { location: 'https://evil.example/' } })
    },
  })
  assert.equal(calls, 1, 'no second request chasing the redirect')
  assert.equal(probe.status, 302)
  assert.equal(probe.location, 'https://evil.example/')
})

test('does not read a body for non-html content', async () => {
  let bodyRead = false
  const probe = await probeHost({
    approval: approvalFor('api.acme.example'),
    limiter: countingLimiter(),
    fetchImpl: async () => ({
      status: 200,
      headers: new Headers({ 'content-type': 'application/octet-stream' }),
      text: async () => { bodyRead = true; return 'x' },
    }),
  })
  assert.equal(bodyRead, false)
  assert.equal(probe.title, null)
})

test('a fetch failure is recorded as an observation, not thrown', async () => {
  const probe = await probeHost({
    approval: approvalFor('dead.acme.example'),
    limiter: countingLimiter(),
    fetchImpl: async () => { const e = new Error('connect ECONNREFUSED'); e.name = 'TypeError'; throw e },
  })
  assert.equal(probe.status, null)
  assert.match(probe.error, /ECONNREFUSED/)
})

test('refuses an unbranded target', async () => {
  await assert.rejects(
    () => probeHost({
      approval: { host: 'evil.example', url: 'https://evil.example/' },
      limiter: countingLimiter(),
      fetchImpl: async () => htmlResponse(''),
    }),
    /scope-approved/,
  )
})

test('refuses to run without a rate limiter', async () => {
  await assert.rejects(
    () => probeHost({ approval: approvalFor('api.acme.example'), fetchImpl: async () => htmlResponse('') }),
    /rate limiter/,
  )
  await assert.rejects(
    () => probeHost({ approval: approvalFor('api.acme.example'), limiter: {}, fetchImpl: async () => htmlResponse('') }),
    /rate limiter/,
  )
})

test('the limiter paces a batch of probes at the sealed rate', async () => {
  let millis = 0
  const limiter = createRateLimiter({
    ratePerSecond: 4,
    now: () => millis,
    sleep: async (ms) => { millis += ms },
  })
  const approval = approvalFor('api.acme.example')
  for (let index = 0; index < 5; index += 1) {
    await probeHost({ approval, limiter, fetchImpl: async () => htmlResponse('') })
  }
  assert.equal(millis, 1000, '5 probes at 4/sec cost 1000ms of paced time')
  assert.equal(limiter.stats().issued, 5)
})

test('it fetches only the approved url', async () => {
  const seen = []
  await probeHost({
    approval: approvalFor('api.acme.example'),
    limiter: countingLimiter(),
    fetchImpl: async (url) => { seen.push(String(url)); return htmlResponse('') },
  })
  assert.deepEqual(seen, ['https://api.acme.example/'])
})
