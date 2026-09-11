import assert from 'node:assert/strict'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { test } from 'node:test'

import {
  assertPageSessionAdapterAllowsRequest,
  assertPageSessionAdapterCompatibleWithScope,
  assertPageSessionAdapterCurrent,
  normalizePageSessionAdapter,
  PAGE_SESSION_ROUTING_CARRIER_HEADERS,
  pageSessionAdapterSha256,
  readPageSessionAdapterFile,
} from '../scripts/lib/page-session-adapter.mjs'

function adapter(overrides = {}) {
  return {
    schema_version: '1.0.0',
    kind: 'last-aperture/page-session-adapter',
    adapter_id: 'synthetic-session-adapter',
    source: {
      type: 'WEB_STORAGE',
      area: 'LOCAL',
      key: 'synthetic.session',
      extraction: { mode: 'RAW' },
    },
    carrier: {
      type: 'REQUEST_HEADER',
      name: 'authorization',
      prefix: 'Bearer ',
    },
    target_constraints: [{
      origin: 'https://app.example.test',
      method: 'GET',
      path_prefix: '/api',
    }],
    validity: {
      not_before: '2026-01-01T00:00:00.000Z',
      not_after: '2027-01-01T00:00:00.000Z',
    },
    limits: { max_value_bytes: 4096 },
    ...overrides,
  }
}

function scope(sessionAdapter = adapter()) {
  return {
    target: { origin: 'https://app.example.test' },
    authorization: {
      authorized_scope: {
        origins: ['https://app.example.test'],
        methods: ['GET'],
        path_prefixes: ['/api'],
      },
    },
    validity: {
      not_before: '2026-02-01T00:00:00.000Z',
      not_after: '2026-12-01T00:00:00.000Z',
    },
    liveness: {
      credential_preflight: {
        method: 'GET',
        url: 'https://app.example.test/api/session',
      },
    },
    requests: [{
      kind: 'probe',
      method: 'GET',
      url: 'https://app.example.test/api/items?limit=1',
    }],
    credential: {
      mode: 'CHROME_ACTIVE_TAB_SESSION',
      origin: 'https://app.example.test',
      session_adapter: sessionAdapter,
    },
  }
}

test('page session adapter normalizes a target-neutral bounded descriptor and has a stable digest', () => {
  const input = adapter()
  const normalized = normalizePageSessionAdapter(input)
  assert.deepEqual(normalized, input)
  assert.notEqual(normalized, input)
  assert.match(pageSessionAdapterSha256(input), /^[a-f0-9]{64}$/)
  assert.equal(pageSessionAdapterSha256(structuredClone(input)), pageSessionAdapterSha256(input))
  assert.equal(assertPageSessionAdapterCurrent(input, new Date('2026-06-01T00:00:00.000Z')), input)
  assert.equal(assertPageSessionAdapterAllowsRequest({
    adapter: input,
    origin: 'https://app.example.test',
    method: 'GET',
    pathAndQuery: '/api/items?limit=1',
    now: new Date('2026-06-01T00:00:00.000Z'),
  }), input)
  assert.equal(assertPageSessionAdapterCompatibleWithScope(input, scope(input)), input)
})

test('page session adapter accepts strict JSON pointer extraction without executable selectors', () => {
  const input = adapter({
    source: {
      type: 'WEB_STORAGE',
      area: 'SESSION',
      key: 'application.state',
      extraction: { mode: 'JSON_POINTER', pointer: '/auth/access~1token' },
    },
  })
  assert.deepEqual(normalizePageSessionAdapter(input).source, input.source)
  for (const forbidden of ['script', 'selector', 'transform', 'function', 'javascript']) {
    assert.equal(JSON.stringify(input).includes(`"${forbidden}"`), false)
  }
})

test('page session adapter rejects wildcards, cross-origin drift, unsafe carriers, and arbitrary fields', () => {
  const cases = [
    adapter({ target_constraints: [{ origin: 'https://*.example.test', method: 'GET', path_prefix: '/api' }] }),
    adapter({ target_constraints: [{ origin: 'https://app.example.test', method: 'GET', path_prefix: '/api/*' }] }),
    adapter({ carrier: { type: 'REQUEST_HEADER', name: 'cookie', prefix: '' } }),
    adapter({ carrier: { type: 'REQUEST_HEADER', name: 'sec-fetch-site', prefix: '' } }),
    adapter({ carrier: { type: 'REQUEST_HEADER', name: 'proxy-synthetic', prefix: '' } }),
    adapter({ carrier: { type: 'REQUEST_HEADER', name: 'accept-encoding', prefix: '' } }),
    adapter({ carrier: { type: 'REQUEST_HEADER', name: 'x-http-method-override', prefix: '' } }),
    ...PAGE_SESSION_ROUTING_CARRIER_HEADERS.map((name) => (
      adapter({ carrier: { type: 'REQUEST_HEADER', name, prefix: '' } })
    )),
    adapter({ carrier: { type: 'REQUEST_HEADER', name: 'Authorization', prefix: 'Bearer ' } }),
    adapter({ source: { ...adapter().source, transform: 'value.token' } }),
    adapter({ source: { ...adapter().source, extraction: { mode: 'JSON_POINTER', pointer: '/bad~2pointer' } } }),
    adapter({ limits: { max_value_bytes: 9000 } }),
  ]
  for (const value of cases) {
    assert.throws(() => normalizePageSessionAdapter(value), { code: 'PAGE_SESSION_ADAPTER_INVALID' })
  }

  assert.throws(() => assertPageSessionAdapterAllowsRequest({
    adapter: adapter(),
    origin: 'https://other.example.test',
    method: 'GET',
    pathAndQuery: '/api/items',
    now: new Date('2026-06-01T00:00:00.000Z'),
  }), { code: 'PAGE_SESSION_ADAPTER_TARGET_REFUSED' })
  assert.throws(() => assertPageSessionAdapterAllowsRequest({
    adapter: adapter(),
    origin: 'https://app.example.test',
    method: 'POST',
    pathAndQuery: '/api/items',
    now: new Date('2026-06-01T00:00:00.000Z'),
  }), { code: 'PAGE_SESSION_ADAPTER_TARGET_REFUSED' })
  assert.throws(() => assertPageSessionAdapterAllowsRequest({
    adapter: adapter(),
    origin: 'https://app.example.test',
    method: 'GET',
    pathAndQuery: '/outside',
    now: new Date('2026-06-01T00:00:00.000Z'),
  }), { code: 'PAGE_SESSION_ADAPTER_TARGET_REFUSED' })
})

test('page session adapter enforces its validity window and covers every declared scope request', () => {
  assert.throws(
    () => assertPageSessionAdapterCurrent(adapter(), new Date('2027-01-01T00:00:00.001Z')),
    { code: 'PAGE_SESSION_ADAPTER_EXPIRED' },
  )
  assert.throws(
    () => assertPageSessionAdapterCurrent(adapter(), new Date('2025-12-31T23:59:59.999Z')),
    { code: 'PAGE_SESSION_ADAPTER_NOT_YET_VALID' },
  )
  assert.throws(
    () => assertPageSessionAdapterCompatibleWithScope(
      adapter({ target_constraints: [{
        origin: 'https://app.example.test',
        method: 'GET',
        path_prefix: '/different',
      }] }),
      scope(),
    ),
    { code: 'PAGE_SESSION_ADAPTER_SCOPE_MISMATCH' },
  )
})

test('page session adapter file reader accepts only a stable bounded local regular JSON file', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'last-aperture-page-adapter-'))
  try {
    const file = join(directory, 'adapter.json')
    await writeFile(file, `${JSON.stringify(adapter())}\n`, { flag: 'wx' })
    assert.deepEqual(await readPageSessionAdapterFile(file), adapter())
    await assert.rejects(
      readPageSessionAdapterFile('relative.json'),
      { code: 'PAGE_SESSION_ADAPTER_PATH_INVALID' },
    )
    if (process.platform === 'win32') {
      await assert.rejects(
        readPageSessionAdapterFile('\\\\server\\share\\adapter.json'),
        { code: 'PAGE_SESSION_ADAPTER_PATH_INVALID' },
      )
    }
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
})
