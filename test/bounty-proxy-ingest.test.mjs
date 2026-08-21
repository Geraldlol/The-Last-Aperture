import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  FLOW_KIND,
  flowsToAuthzRequests,
  ingestFlows,
  parseFlowLines,
  queryFlows,
} from '../scripts/lib/bounty-proxy-ingest.mjs'

// fileURLToPath, not .pathname: the repository lives under "Red Team", and
// .pathname leaves the space percent-encoded, which silently skipped the
// conformance check below rather than running it.
const REPO = fileURLToPath(new URL('..', import.meta.url))

function flow(overrides = {}) {
  return {
    kind: FLOW_KIND,
    schema_version: '1.0.0',
    observed_at: '2026-08-21T12:00:00.000Z',
    forwarded: true,
    scope_decision: 'ALLOW',
    scope_reason: 'allow-rule-matched',
    scope_rule_id: 'a1',
    request: {
      method: 'GET',
      url: 'https://api.acme.example/api/orders/2',
      headers: { accept: 'application/json' },
      redacted_headers: ['authorization'],
      body: null,
      body_truncated: false,
    },
    response: {
      status: 200,
      headers: { 'content-type': 'application/json' },
      redacted_headers: [],
      body: '{"id":"2"}',
      body_truncated: false,
    },
    ...overrides,
  }
}

const jsonl = (records) => `${records.map((r) => JSON.stringify(r)).join('\n')}\n`

async function bundleWith(records) {
  const dir = await mkdtemp(join(tmpdir(), 'bounty-proxy-'))
  await writeFile(join(dir, 'flows.jsonl'), jsonl(records), 'utf8')
  return dir
}

test('parses well formed flow lines and reports the rest', () => {
  const { flows, skipped } = parseFlowLines([
    JSON.stringify(flow()),
    'not json at all',
    JSON.stringify({ kind: 'something-else' }),
    JSON.stringify({ kind: FLOW_KIND, request: {} }),
    '',
  ].join('\n'))
  assert.equal(flows.length, 1)
  assert.deepEqual(skipped.map((s) => s.reason), ['not-json', 'not-a-bounty-flow', 'flow-missing-request'])
})

test('ingests flows into a queryable store', async () => {
  const dir = await bundleWith([
    flow(),
    flow({ request: { ...flow().request, url: 'https://api.acme.example/api/me' }, response: { ...flow().response, status: 403 } }),
  ])
  try {
    const result = await ingestFlows({ bundlePath: dir })
    assert.equal(result.ingested, 2)
    assert.equal(result.status, 'INGESTED')
    const all = queryFlows({ bundlePath: dir })
    assert.equal(all.length, 2)
    const forbidden = queryFlows({ bundlePath: dir, where: 'status = 403' })
    assert.equal(forbidden.length, 1)
    assert.match(forbidden[0].url, /\/api\/me$/)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('the store is queryable by host and decision', async () => {
  const dir = await bundleWith([
    flow(),
    flow({
      forwarded: false,
      scope_decision: 'DENY',
      scope_reason: 'candidate-unlisted',
      request: { ...flow().request, url: 'https://evil.example/x' },
      response: null,
    }),
  ])
  try {
    await ingestFlows({ bundlePath: dir })
    const denied = queryFlows({ bundlePath: dir, where: "scope_decision = 'DENY'" })
    assert.equal(denied.length, 1)
    assert.equal(denied[0].forwarded, 0, 'a denied flow was never forwarded')
    const byHost = queryFlows({ bundlePath: dir, where: "host = 'api.acme.example'" })
    assert.equal(byHost.length, 1)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('a missing capture file is reported, not thrown', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bounty-proxy-'))
  try {
    const result = await ingestFlows({ bundlePath: dir })
    assert.equal(result.status, 'NO_CAPTURE_FILE')
    assert.equal(result.ingested, 0)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('re-ingesting the same capture does not duplicate rows', async () => {
  const dir = await bundleWith([flow()])
  try {
    await ingestFlows({ bundlePath: dir })
    await ingestFlows({ bundlePath: dir })
    assert.equal(queryFlows({ bundlePath: dir }).length, 1)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('only forwarded in-scope flows become authz requests', async () => {
  const dir = await bundleWith([
    flow(),
    flow({ forwarded: false, scope_decision: 'DENY', request: { ...flow().request, url: 'https://evil.example/x' } }),
    flow({ forwarded: true, scope_decision: 'DENY', request: { ...flow().request, url: 'https://also-bad.example/x' } }),
  ])
  try {
    const result = await flowsToAuthzRequests({ bundlePath: dir, ownerRole: 'alice' })
    assert.equal(result.imported, 1, 'a blocked request is perimeter evidence, not something to replay')
    const stored = JSON.parse(await readFile(join(dir, 'authz-requests.json'), 'utf8'))
    assert.equal(stored.requests[0].owner_role, 'alice')
    assert.match(stored.requests[0].url, /api\.acme\.example/)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('captured requests are redacted on the way to the grinder', async () => {
  const dir = await bundleWith([flow({
    request: {
      ...flow().request,
      headers: { accept: 'application/json', authorization: 'Bearer leaked-value' },
    },
  })])
  try {
    await flowsToAuthzRequests({ bundlePath: dir, ownerRole: 'alice' })
    const raw = await readFile(join(dir, 'authz-requests.json'), 'utf8')
    assert.equal(raw.includes('leaked-value'), false)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('duplicate captured requests collapse by signature', async () => {
  const dir = await bundleWith([flow(), flow(), flow()])
  try {
    const result = await flowsToAuthzRequests({ bundlePath: dir, ownerRole: 'alice' })
    assert.equal(result.imported, 1, 'a browser polling the same endpoint is one request to replay')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

// --- the safety-critical piece ---

test('the Python scope kernel agrees with the Node one on every fixture', (t) => {
  // Two implementations of a security boundary are only safe once a machine
  // proves they agree. Skipped rather than failed when Python is absent, and the
  // skip is the recorded gap.
  let output
  try {
    output = execFileSync('py', [join(REPO, 'proxy', 'conformance.py')], {
      encoding: 'utf8', cwd: REPO, windowsHide: true,
    })
  } catch (error) {
    if (error.stdout) {
      const parsed = JSON.parse(error.stdout)
      assert.fail(`python kernel diverges on ${parsed.mismatches.length} case(s): ${
        parsed.mismatches.map((m) => `${m.case_id} got ${m.reason} want ${m.expected_reason}`).join('; ')
      }`)
    }
    t.skip('python interpreter not available; cross-language conformance not verified')
    return
  }
  const parsed = JSON.parse(output)
  assert.equal(parsed.implementation, 'python')
  assert.ok(parsed.total >= 35, 'the shared fixture suite was loaded')
  assert.deepEqual(parsed.mismatches, [], 'python and node must decide identically')
  assert.equal(parsed.matched, parsed.total)
})
