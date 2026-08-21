import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  redactMatch,
  scanResponse,
  scanResponseBody,
  scanResponseHeaders,
  summarizePassive,
} from '../scripts/lib/bounty-scan-passive.mjs'

const ruleIds = (observations) => observations.map((o) => o.rule_id).sort()

test('detects high-confidence secret shapes', () => {
  const found = scanResponseBody([
    'const a = "AKIAIOSFODNN7EXAMPLE";',
    'const g = "AIzaSyD-1234567890abcdefghijklmnopqrstu";',
    'const s = "xoxb-123456789012-abcdefghijklmnop";',
    'const k = "sk_live_abcdefghijklmnop1234";',
    'const t = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";',
    '-----BEGIN RSA PRIVATE KEY-----',
  ].join('\n'))
  assert.deepEqual(ruleIds(found), [
    'aws-access-key-id', 'github-token', 'google-api-key',
    'private-key-block', 'slack-token', 'stripe-live-key',
  ])
})

test('a detected secret is never carried in the observation', () => {
  // Findings get committed, shared, and pasted into reports. Copying a live key
  // into one relocates the leak instead of reporting it.
  const found = scanResponseBody('token = "AKIAIOSFODNN7EXAMPLE"')
  assert.equal(found.length, 1)
  assert.equal(JSON.stringify(found).includes('AKIAIOSFODNN7EXAMPLE'), false)
  assert.match(found[0].redacted, /^AKIA\*\*\*LE \(20 chars\)$/)
})

test('redaction keeps shape without keeping anything usable', () => {
  assert.equal(redactMatch('short'), 'sh***')
  assert.match(redactMatch('abcdefghijklmnop'), /^abcd\*\*\*op \(16 chars\)$/)
})

test('does not fire on ordinary long strings', () => {
  // The flood-avoidance property: a detector that matches any 40-char token
  // teaches the operator to ignore it.
  const benign = [
    'const hash = "d41d8cd98f00b204e9800998ecf8427e";',
    'const id = "550e8400-e29b-41d4-a716-446655440000";',
    'const css = "translate3d(0,0,0) rotateX(45deg) scale(1.5)";',
    'const b64 = "VGhpcyBpcyBqdXN0IGJhc2U2NCB0ZXh0IGhlcmU=";',
    'AKIA_NOT_A_KEY_BECAUSE_LOWERCASE_and_short',
  ].join('\n')
  assert.deepEqual(scanResponseBody(benign), [])
})

test('detects internal hostnames and private addresses', () => {
  const found = scanResponseBody([
    'upstream: api.internal',
    'db: 10.4.2.19',
    'cache: 192.168.1.50',
    'meta: 169.254.169.254',
  ].join('\n'))
  const ids = ruleIds(found)
  assert.ok(ids.includes('internal-tld'))
  assert.ok(ids.includes('rfc1918-address'))
  assert.ok(ids.includes('cloud-metadata-address'))
})

test('a public address is not reported as internal', () => {
  const found = scanResponseBody('cdn: 203.0.113.7 and 8.8.8.8 and 172.32.0.1')
  assert.equal(found.filter((o) => o.rule_id === 'rfc1918-address').length, 0)
})

test('detects verbose error output across common stacks', () => {
  const cases = [
    ['python-traceback', 'Traceback (most recent call last):\n  File "app.py"'],
    ['java-stack-trace', 'at com.acme.svc.OrderService.load(OrderService.java:88)'],
    ['php-error', 'Fatal error: Uncaught TypeError in /var/www/html/index.php on line 42'],
    ['node-stack-trace', 'at handler (/srv/app/routes.js:31:17)'],
    ['sql-error', 'You have an error in your SQL syntax; check the manual'],
    ['django-debug', "You're seeing this error because you have <code>DEBUG = True"],
  ]
  for (const [ruleId, body] of cases) {
    assert.ok(ruleIds(scanResponseBody(body)).includes(ruleId), ruleId)
  }
})

test('normal prose does not read as a stack trace', () => {
  assert.deepEqual(
    scanResponseBody('The order failed at checkout. Warning: your cart is empty.'),
    [],
  )
})

test('reports version-bearing headers and ignores bare ones', () => {
  const withVersion = scanResponseHeaders(new Headers({
    server: 'nginx/1.14.0', 'x-powered-by': 'PHP/8.2.1', 'x-aspnet-version': '4.0.30319',
  }))
  assert.equal(withVersion.length, 3)
  assert.ok(withVersion.some((o) => o.value.includes('nginx/1.14.0')))

  const bare = scanResponseHeaders(new Headers({ server: 'nginx' }))
  assert.equal(bare.length, 0, 'a bare server name is not worth an operator flag')
})

test('header values are recorded verbatim because the version is the finding', () => {
  const found = scanResponseHeaders({ 'x-powered-by': 'Express' })
  assert.equal(found[0].value, 'Express')
})

test('tolerates absent or empty headers and bodies', () => {
  assert.deepEqual(scanResponseHeaders(null), [])
  assert.deepEqual(scanResponseBody(''), [])
  assert.deepEqual(scanResponseBody(null), [])
})

test('scanResponse attaches the url and status to every observation', () => {
  const found = scanResponse({
    url: 'https://api.acme.example/app.js',
    status: 200,
    headers: { 'x-powered-by': 'Express' },
    body: 'key = "AKIAIOSFODNN7EXAMPLE"',
  })
  assert.equal(found.length, 2)
  assert.ok(found.every((o) => o.url === 'https://api.acme.example/app.js' && o.status === 200))
})

test('the summary calls passive results leads, never findings', () => {
  const empty = summarizePassive([])
  assert.equal(empty.status, 'NOTHING_OBSERVED')
  const some = summarizePassive(scanResponse({
    url: 'u', status: 200, headers: { server: 'nginx/1.14.0' }, body: '',
  }))
  assert.equal(some.status, 'LEADS_OBSERVED')
  assert.equal(some.byKind['information-disclosure'], 1)
  // A disclosed version is not a vulnerability; calling it one gets a report
  // closed as N/A and costs reputation.
  assert.equal(/FINDING|VULNERAB/i.test(some.status), false)
})

test('repeated identical matches collapse into one observation with a count', () => {
  const found = scanResponseBody('AKIAIOSFODNN7EXAMPLE and again AKIAIOSFODNN7EXAMPLE')
  assert.equal(found.length, 1)
  assert.equal(found[0].occurrences, 2)
})
