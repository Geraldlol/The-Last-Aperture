import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { test } from 'node:test'

import { createBrowserBridgeCompanion } from '../browser/http-authed-chrome/service-worker.js'
import { pageSessionAdapterSha256 } from '../scripts/lib/page-session-adapter.mjs'

const EXTENSION_DIRECTORY = fileURLToPath(
  new URL('../browser/http-authed-chrome/', import.meta.url),
)
const PROTOCOL = 'red-team-audit/http-authed-browser-bridge'
const SCHEMA_VERSION = '1.0.0'
const EXTENSION_ID = 'abcdefghijklmnopabcdefghijklmnop'
const TARGET_ORIGIN = 'https://bounty.example.test'
const CAMPAIGN_ID = 'a'.repeat(64)
const DOCUMENT_NONCE = 'document-nonce-0123456789abcdef'
const PAIRING_CODE = 'p'.repeat(43)
const SESSION_CAPABILITY = 's'.repeat(43)
const ACTION_ID = `http-authed-action:${'b'.repeat(64)}`
const ACTION_NONCE = 'n'.repeat(43)
const ACTION_SHA256 = 'd'.repeat(64)

const PAGE_SESSION_ADAPTER = {
  schema_version: '1.0.0',
  kind: 'last-aperture/page-session-adapter',
  adapter_id: 'synthetic-page-session',
  source: {
    type: 'WEB_STORAGE',
    area: 'LOCAL',
    key: 'application.session',
    extraction: { mode: 'RAW' },
  },
  carrier: { type: 'REQUEST_HEADER', name: 'authorization', prefix: 'Bearer ' },
  target_constraints: [{
    origin: TARGET_ORIGIN,
    method: 'GET',
    path_prefix: '/approved',
  }],
  validity: {
    not_before: '2026-01-01T00:00:00.000Z',
    not_after: '2031-01-01T00:00:00.000Z',
  },
  limits: { max_value_bytes: 4096 },
}
const PAGE_SESSION_ADAPTER_SHA256 = pageSessionAdapterSha256(PAGE_SESSION_ADAPTER)

const jsonResponse = (value, status = 200) => {
  const body = JSON.stringify(value)
  return new Response(body, {
    status,
    headers: {
      'content-length': String(Buffer.byteLength(body)),
      'content-type': 'application/json',
    },
  })
}

const previewEnvelope = {
  protocol: PROTOCOL,
  schema_version: SCHEMA_VERSION,
  type: 'PREVIEW',
  target_origin: TARGET_ORIGIN,
  campaign_grant_sha256: CAMPAIGN_ID,
  extension_id: EXTENSION_ID,
  expires_at: '2030-01-01T00:00:00.000Z',
}

const openEnvelope = {
  protocol: PROTOCOL,
  schema_version: SCHEMA_VERSION,
  type: 'OPEN',
  campaign_id: CAMPAIGN_ID,
  target_origin: TARGET_ORIGIN,
  tab_id: 17,
  document_nonce: DOCUMENT_NONCE,
  session_capability: SESSION_CAPABILITY,
}

const prepareEnvelope = {
  protocol: PROTOCOL,
  schema_version: SCHEMA_VERSION,
  type: 'PREPARE',
  campaign_id: CAMPAIGN_ID,
  action_id: ACTION_ID,
  action_nonce: ACTION_NONCE,
  action_sha256: ACTION_SHA256,
  document_nonce: DOCUMENT_NONCE,
  deadline: '2030-01-01T00:00:00.000Z',
  request: {
    origin: TARGET_ORIGIN,
    path_and_query: '/approved?x=1',
    method: 'GET',
    headers: { accept: 'application/json' },
    body_base64: null,
    body_sha256: null,
    body_bytes: 0,
    timeout_ms: 10_000,
    max_response_bytes: 65_536,
    observe_response: true,
  },
}

const commitEnvelope = {
  protocol: PROTOCOL,
  schema_version: SCHEMA_VERSION,
  campaign_id: CAMPAIGN_ID,
  action_id: ACTION_ID,
  action_nonce: ACTION_NONCE,
  action_sha256: ACTION_SHA256,
  document_nonce: DOCUMENT_NONCE,
  type: 'COMMIT',
  committed_at: '2030-01-01T00:00:00.000Z',
}

function fakeChrome({
  permission = true,
  tabUrl = `${TARGET_ORIGIN}/app`,
  storageData = {},
  resultOverrides = {},
} = {}) {
  const injections = []
  const storageCalls = []
  const results = {
    captureHttpAuthedDocument: {
      target_origin: TARGET_ORIGIN,
      document_nonce: DOCUMENT_NONCE,
    },
    prepareHttpAuthedInjectedFetch: { prepared: true },
    executeHttpAuthedInjectedFetch: {
      outcome: 'OBSERVED',
      response_truncated: false,
      action_binding_sha256: ACTION_SHA256,
      response: {
        status: 200,
        response_bytes: 2,
        response_header_names: ['content-type'],
        headers: [{
          name: 'content-type',
          value_base64: Buffer.from('application/json').toString('base64'),
        }],
        body_base64: Buffer.from('{}').toString('base64'),
      },
    },
    inspectHttpAuthedDocument: {
      target_origin: TARGET_ORIGIN,
      document_nonce: DOCUMENT_NONCE,
    },
    clearHttpAuthedInjectedPreparation: { cleared: true },
    abortHttpAuthedInjectedFetch: { aborted: true },
    ...resultOverrides,
  }
  return {
    injections,
    storageCalls,
    storageData,
    api: {
      runtime: {
        id: EXTENSION_ID,
        onMessage: { addListener() {} },
      },
      permissions: {
        async contains(value) {
          assert.deepEqual(value, { origins: ['http://127.0.0.1/*'] })
          return permission
        },
      },
      storage: {
        session: {
          async setAccessLevel(value) {
            storageCalls.push({ operation: 'setAccessLevel', value: structuredClone(value) })
          },
          async get(key) {
            storageCalls.push({ operation: 'get', key })
            return Object.hasOwn(storageData, key)
              ? { [key]: structuredClone(storageData[key]) }
              : {}
          },
          async set(value) {
            storageCalls.push({ operation: 'set', value: structuredClone(value) })
            Object.assign(storageData, structuredClone(value))
          },
          async remove(key) {
            storageCalls.push({ operation: 'remove', key })
            delete storageData[key]
          },
        },
      },
      tabs: {
        async query(value) {
          assert.deepEqual(value, { active: true, currentWindow: true })
          return [{ id: 17, url: tabUrl }]
        },
      },
      scripting: {
        async executeScript(input) {
          injections.push(input)
          const value = results[input.func.name]
          assert.notEqual(value, undefined, `unexpected injection: ${input.func.name}`)
          return [{ frameId: 0, result: structuredClone(value) }]
        },
      },
    },
  }
}

test('Chrome bridge manifest has active-tab injection, ephemeral recovery, and optional loopback authority', async () => {
  const manifest = JSON.parse(await readFile(
    join(EXTENSION_DIRECTORY, 'manifest.json'),
    'utf8',
  ))

  assert.equal(manifest.manifest_version, 3)
  assert.equal(manifest.name, 'The Last Aperture Browser Bridge')
  assert.equal(manifest.version, '0.13.0')
  assert.equal(manifest.minimum_chrome_version, '110')
  assert.deepEqual(manifest.permissions, ['activeTab', 'scripting', 'storage'])
  assert.deepEqual(manifest.host_permissions, [])
  assert.deepEqual(manifest.optional_host_permissions, ['http://127.0.0.1/*'])
  assert.deepEqual(manifest.background, {
    service_worker: 'service-worker.js',
    type: 'module',
  })
  assert.equal(manifest.optional_permissions, undefined)
  assert.equal(manifest.externally_connectable, undefined)
  assert.equal(manifest.content_scripts, undefined)
  assert.equal(manifest.web_accessible_resources, undefined)
  assert.equal(manifest.action?.default_popup, 'popup.html')
  for (const forbidden of ['cookies', 'debugger', 'tabs', 'webRequest']) {
    assert.equal(manifest.permissions.includes(forbidden), false)
  }

  const extensionCsp = manifest.content_security_policy?.extension_pages ?? ''
  assert.match(extensionCsp, /(?:^|;)\s*script-src\s+'self'\s*(?:;|$)/)
  assert.doesNotMatch(extensionCsp, /unsafe-|https?:|\*/i)
})

test('Chrome bridge popup performs explicit pairing and never renders controller values as HTML', async () => {
  const [popup, source] = await Promise.all([
    readFile(join(EXTENSION_DIRECTORY, 'popup.html'), 'utf8'),
    readFile(join(EXTENSION_DIRECTORY, 'popup.js'), 'utf8'),
  ])

  assert.match(popup, /<form id="pairing-form">/)
  assert.match(popup, /id="controller-port"/)
  assert.match(popup, /id="pairing-code"[^>]+type="password"/)
  assert.match(popup, /id="attach"/)
  assert.match(popup, /id="close"/)
  assert.match(popup, /<script type="module" src="popup\.js"><\/script>/)
  assert.match(source, /chrome\.permissions\.request\(permission\)/)
  assert.match(source, /chrome\.runtime\.sendMessage\(message\)/)
  assert.match(source, /chrome\.runtime\.connect\(\{ name: 'last-aperture-popup' \}\)/)
  assert.match(source, /keepAlivePort\.postMessage\(\{ type: 'KEEPALIVE' \}\)/)
  assert.match(source, /LAST_APERTURE_PREVIEW/)
  assert.match(source, /LAST_APERTURE_ATTACH/)
  assert.match(source, /LAST_APERTURE_CLOSE/)
  assert.match(source, /LAST_APERTURE_STATUS/)
  assert.doesNotMatch(source, /innerHTML|outerHTML|eval\s*\(|new Function|chrome\.(?:cookies|debugger)/)
})

test('Chrome bridge companion completes preview, open, prepare, ready, result, and close', async () => {
  const chrome = fakeChrome()
  const requests = []
  const fetchImpl = async (url, options) => {
    const parsed = new URL(url)
    const body = options.body === undefined ? null : JSON.parse(options.body)
    requests.push({ path: parsed.pathname, options, body })
    assert.equal(parsed.origin, 'http://127.0.0.1:4711')
    assert.equal(options.credentials, 'omit')
    assert.equal(options.redirect, 'error')
    assert.equal(options.cache, 'no-store')
    assert.equal(options.referrerPolicy, 'no-referrer')
    if (parsed.pathname === '/v1/preview') return jsonResponse(previewEnvelope)
    if (parsed.pathname === '/v1/open') return jsonResponse(openEnvelope)
    if (parsed.pathname === '/v1/prepare') return jsonResponse(prepareEnvelope)
    if (parsed.pathname === '/v1/ready') return jsonResponse(commitEnvelope)
    if (parsed.pathname === '/v1/result') return jsonResponse({ accepted: true })
    if (parsed.pathname === '/v1/close') return jsonResponse({ closed: true })
    assert.fail(`unexpected controller route: ${parsed.pathname}`)
  }
  const companion = createBrowserBridgeCompanion({
    chromeApi: chrome.api,
    fetchImpl,
    autoPump: false,
  })

  const preview = await companion.preview({ port: 4711, pairingCode: PAIRING_CODE })
  assert.equal(preview.phase, 'PREVIEWED')
  assert.equal(preview.preview.target_origin, TARGET_ORIGIN)
  assert.equal(JSON.stringify(preview).includes(PAIRING_CODE), false)

  const opened = await companion.attach()
  assert.equal(opened.phase, 'OPEN')
  assert.equal(opened.active_tab_origin, TARGET_ORIGIN)
  assert.equal(JSON.stringify(opened).includes(SESSION_CAPABILITY), false)
  const [storedOpen] = Object.values(chrome.storageData)
  assert.equal(storedOpen.phase, 'OPEN')
  assert.equal(Object.hasOwn(storedOpen, 'session_capability'), false)
  assert.equal(Object.hasOwn(storedOpen, 'pairing_code'), false)
  assert.equal(JSON.stringify(chrome.storageData).includes(SESSION_CAPABILITY), false)
  assert.equal(JSON.stringify(chrome.storageData).includes(PAIRING_CODE), false)
  assert.equal(await companion.runOneCycle(), 'EXECUTED')
  assert.equal(companion.status().phase, 'OPEN')
  const preparedInjection = chrome.injections.find(({ func }) => (
    func.name === 'prepareHttpAuthedInjectedFetch'
  ))
  const executedInjection = chrome.injections.find(({ func }) => (
    func.name === 'executeHttpAuthedInjectedFetch'
  ))
  assert.equal(Object.hasOwn(preparedInjection.args[0], 'session_adapter_sha256'), false)
  assert.equal(Object.hasOwn(executedInjection.args[0], 'body'), false)
  assert.equal((await companion.close()).phase, 'IDLE')

  assert.deepEqual(requests.map(({ path }) => path), [
    '/v1/preview',
    '/v1/open',
    '/v1/prepare',
    '/v1/ready',
    '/v1/result',
    '/v1/close',
  ])
  assert.equal(requests[0].options.headers['x-red-team-audit-pairing'], PAIRING_CODE)
  assert.equal(requests[1].options.headers['x-red-team-audit-pairing'], PAIRING_CODE)
  for (const request of requests) {
    assert.equal(request.options.headers['x-last-aperture-extension'], EXTENSION_ID)
  }
  for (const request of requests.slice(2)) {
    assert.equal(request.options.headers['x-red-team-audit-session'], SESSION_CAPABILITY)
  }
  assert.deepEqual(requests[1].body, {
    protocol: PROTOCOL,
    schema_version: SCHEMA_VERSION,
    type: 'OPEN',
    campaign_id: CAMPAIGN_ID,
    target_origin: TARGET_ORIGIN,
    tab_id: 17,
    document_nonce: DOCUMENT_NONCE,
  })
  assert.equal(requests[3].body.type, 'READY')
  assert.equal(requests[4].body.type, 'RESULT')
  assert.equal(requests[4].body.outcome, 'OBSERVED')
  assert.equal(requests[4].body.response_truncated, false)
  assert.deepEqual(chrome.storageData, {})

  assert.deepEqual(chrome.injections.map(({ func }) => func.name), [
    'captureHttpAuthedDocument',
    'prepareHttpAuthedInjectedFetch',
    'executeHttpAuthedInjectedFetch',
    'clearHttpAuthedInjectedPreparation',
    'abortHttpAuthedInjectedFetch',
  ])
  for (const injection of chrome.injections) {
    assert.deepEqual(injection.target, { tabId: 17 })
    assert.equal(injection.world, 'ISOLATED')
  }
  const command = chrome.injections[2].args[0]
  assert.equal(command.target_origin, TARGET_ORIGIN)
  assert.equal(command.relative_url, '/approved?x=1')
  assert.equal(command.action_binding_sha256, ACTION_SHA256)
  assert.equal(command.deadline_epoch_ms, Date.parse(prepareEnvelope.deadline))
  assert.equal(Object.hasOwn(command, 'credentials'), false)
})

test('Chrome bridge carries only a bound page adapter descriptor into the isolated dispatch', async () => {
  const pagePrepare = {
    ...structuredClone(prepareEnvelope),
    session_adapter: structuredClone(PAGE_SESSION_ADAPTER),
    session_adapter_sha256: PAGE_SESSION_ADAPTER_SHA256,
  }
  const pageCommit = {
    ...structuredClone(commitEnvelope),
    session_adapter_sha256: PAGE_SESSION_ADAPTER_SHA256,
  }
  const chrome = fakeChrome({
    resultOverrides: {
      executeHttpAuthedInjectedFetch: {
        outcome: 'OBSERVED',
        response_truncated: false,
        action_binding_sha256: ACTION_SHA256,
        session_adapter_sha256: PAGE_SESSION_ADAPTER_SHA256,
        response: {
          status: 200,
          response_bytes: 2,
          response_header_names: ['content-type'],
          headers: [{
            name: 'content-type',
            value_base64: Buffer.from('application/json').toString('base64'),
          }],
          body_base64: Buffer.from('{}').toString('base64'),
        },
      },
    },
  })
  const bodies = []
  const fetchImpl = async (url, options) => {
    const path = new URL(url).pathname
    if (options.body !== undefined) bodies.push(JSON.parse(options.body))
    if (path === '/v1/preview') return jsonResponse(previewEnvelope)
    if (path === '/v1/open') return jsonResponse(openEnvelope)
    if (path === '/v1/prepare') return jsonResponse(pagePrepare)
    if (path === '/v1/ready') return jsonResponse(pageCommit)
    if (path === '/v1/result') return jsonResponse({ accepted: true })
    if (path === '/v1/close') return jsonResponse({ closed: true })
    assert.fail(`unexpected controller route: ${path}`)
  }
  const companion = createBrowserBridgeCompanion({
    chromeApi: chrome.api,
    fetchImpl,
    autoPump: false,
  })
  await companion.preview({ port: 4711, pairingCode: PAIRING_CODE })
  await companion.attach()
  assert.equal(await companion.runOneCycle(), 'EXECUTED')
  await companion.close()

  const preparation = chrome.injections.find(({ func }) => (
    func.name === 'prepareHttpAuthedInjectedFetch'
  )).args[0]
  assert.equal(preparation.session_adapter_sha256, PAGE_SESSION_ADAPTER_SHA256)
  const command = chrome.injections.find(({ func }) => (
    func.name === 'executeHttpAuthedInjectedFetch'
  )).args[0]
  assert.deepEqual(command.session_adapter, PAGE_SESSION_ADAPTER)
  assert.equal(command.session_adapter_sha256, PAGE_SESSION_ADAPTER_SHA256)
  const ready = bodies.find(({ type }) => type === 'READY')
  const result = bodies.find(({ type }) => type === 'RESULT')
  assert.equal(ready.session_adapter_sha256, PAGE_SESSION_ADAPTER_SHA256)
  assert.equal(result.session_adapter_sha256, PAGE_SESSION_ADAPTER_SHA256)
  assert.doesNotMatch(JSON.stringify([chrome.injections, bodies]), /SYNTHETIC_PAGE_TOKEN/)
})

test('Chrome bridge refuses absent loopback permission and mismatched active origins before attachment', async () => {
  let fetchCalls = 0
  const missingPermission = fakeChrome({ permission: false })
  const deniedCompanion = createBrowserBridgeCompanion({
    chromeApi: missingPermission.api,
    fetchImpl: async () => { fetchCalls += 1 },
    autoPump: false,
  })
  await assert.rejects(
    deniedCompanion.preview({ port: 4711, pairingCode: PAIRING_CODE }),
    { code: 'HTTP_AUTHED_BROWSER_LOOPBACK_PERMISSION_REQUIRED' },
  )
  assert.equal(fetchCalls, 0)

  const mismatched = fakeChrome({ tabUrl: 'https://other.example.test/app' })
  const mismatchRequests = []
  const mismatchCompanion = createBrowserBridgeCompanion({
    chromeApi: mismatched.api,
    fetchImpl: async (url) => {
      mismatchRequests.push(new URL(url).pathname)
      return jsonResponse(previewEnvelope)
    },
    autoPump: false,
  })
  await mismatchCompanion.preview({ port: 4711, pairingCode: PAIRING_CODE })
  await assert.rejects(
    mismatchCompanion.attach(),
    { code: 'HTTP_AUTHED_BROWSER_ACTIVE_TAB_MISMATCH' },
  )
  assert.deepEqual(mismatchRequests, ['/v1/preview'])
  assert.deepEqual(mismatched.injections, [])
})

test('Chrome bridge preserves bounded response outcomes for controller rejection', async () => {
  const chrome = fakeChrome({
    resultOverrides: {
      executeHttpAuthedInjectedFetch: {
        action_binding_sha256: ACTION_SHA256,
        outcome: 'RESPONSE_BOUNDED',
        response_truncated: true,
        response: {
          status: 200,
          response_bytes: 65_536,
          response_header_names: ['content-type'],
          headers: [{
            name: 'content-type',
            value_base64: Buffer.from('application/json').toString('base64'),
          }],
          body_base64: Buffer.alloc(65_536, 0x61).toString('base64'),
        },
      },
    },
  })
  let resultBody
  const fetchImpl = async (url, options) => {
    const path = new URL(url).pathname
    if (path === '/v1/preview') return jsonResponse(previewEnvelope)
    if (path === '/v1/open') return jsonResponse(openEnvelope)
    if (path === '/v1/prepare') return jsonResponse(prepareEnvelope)
    if (path === '/v1/ready') return jsonResponse(commitEnvelope)
    if (path === '/v1/result') {
      resultBody = JSON.parse(options.body)
      return jsonResponse({ accepted: true })
    }
    if (path === '/v1/close') return jsonResponse({ closed: true })
    assert.fail(`unexpected controller route: ${path}`)
  }
  const companion = createBrowserBridgeCompanion({
    chromeApi: chrome.api,
    fetchImpl,
    autoPump: false,
  })
  await companion.preview({ port: 4711, pairingCode: PAIRING_CODE })
  await companion.attach()
  assert.equal(await companion.runOneCycle(), 'EXECUTED')
  assert.equal(resultBody.outcome, 'RESPONSE_BOUNDED')
  assert.equal(resultBody.response_truncated, true)
  assert.equal(resultBody.response.response_bytes, 65_536)
  await companion.close()
})

test('Chrome bridge cancellation while READY is pending cannot dispatch the target request', async () => {
  const chrome = fakeChrome()
  let readyStartedResolve
  let readyResponseResolve
  const readyStarted = new Promise((resolve) => { readyStartedResolve = resolve })
  const readyResponse = new Promise((resolve) => { readyResponseResolve = resolve })
  const fetchImpl = async (url) => {
    const path = new URL(url).pathname
    if (path === '/v1/preview') return jsonResponse(previewEnvelope)
    if (path === '/v1/open') return jsonResponse(openEnvelope)
    if (path === '/v1/prepare') return jsonResponse(prepareEnvelope)
    if (path === '/v1/ready') {
      readyStartedResolve()
      return readyResponse
    }
    if (path === '/v1/close') return jsonResponse({ closed: true })
    assert.fail(`unexpected controller route: ${path}`)
  }
  const companion = createBrowserBridgeCompanion({
    chromeApi: chrome.api,
    fetchImpl,
    autoPump: false,
  })
  await companion.preview({ port: 4711, pairingCode: PAIRING_CODE })
  await companion.attach()
  const cycle = companion.runOneCycle()
  await readyStarted
  await companion.close()
  readyResponseResolve(jsonResponse(commitEnvelope))
  assert.equal(await cycle, 'CLOSED')
  assert.equal(chrome.injections.some(({ func }) => (
    func.name === 'executeHttpAuthedInjectedFetch'
  )), false)
})

test('Chrome bridge detects a worker restart and fails closed without contacting the old port', async () => {
  const storageData = {}
  const firstChrome = fakeChrome({ storageData })
  const firstFetch = async (url) => {
    const path = new URL(url).pathname
    if (path === '/v1/preview') return jsonResponse(previewEnvelope)
    if (path === '/v1/open') return jsonResponse(openEnvelope)
    assert.fail(`unexpected controller route: ${path}`)
  }
  const first = createBrowserBridgeCompanion({
    chromeApi: firstChrome.api,
    fetchImpl: firstFetch,
    autoPump: false,
  })
  await first.preview({ port: 4711, pairingCode: PAIRING_CODE })
  await first.attach()
  assert.equal(Object.values(storageData)[0].phase, 'OPEN')
  const storedRecord = structuredClone(Object.values(storageData)[0])

  const restartedChrome = fakeChrome({ storageData })
  let loopbackCalls = 0
  const restarted = createBrowserBridgeCompanion({
    chromeApi: restartedChrome.api,
    fetchImpl: async () => {
      loopbackCalls += 1
      throw new Error('old loopback port must not be contacted')
    },
    autoPump: false,
  })
  const status = await restarted.handleMessage({ type: 'LAST_APERTURE_STATUS' })
  assert.equal(status.phase, 'IDLE')
  assert.equal(status.last_error, 'HTTP_AUTHED_BROWSER_RESTART_REATTACH_REQUIRED')
  assert.equal(loopbackCalls, 0)
  assert.deepEqual(storageData, {})
  assert.deepEqual(restartedChrome.injections.map(({ func }) => func.name), [
    'inspectHttpAuthedDocument',
    'abortHttpAuthedInjectedFetch',
  ])

  storageData.last_aperture_http_authed_recovery_v1 = {
    ...storedRecord,
    phase: 'COMMIT',
  }
  const inFlightChrome = fakeChrome({ storageData })
  const inFlight = createBrowserBridgeCompanion({
    chromeApi: inFlightChrome.api,
    fetchImpl: async () => {
      loopbackCalls += 1
      throw new Error('in-flight recovery must not contact the old port')
    },
    autoPump: false,
  })
  const inFlightStatus = await inFlight.handleMessage({ type: 'LAST_APERTURE_STATUS' })
  assert.equal(inFlightStatus.phase, 'IDLE')
  assert.equal(
    inFlightStatus.last_error,
    'HTTP_AUTHED_BROWSER_RECOVERY_IN_FLIGHT_REFUSED',
  )
  assert.equal(loopbackCalls, 0)
  assert.deepEqual(storageData, {})
})

test('Chrome bridge accepts the full 16 MiB sealed-body PREPARE envelope', async () => {
  const requestBody = Buffer.alloc(16 * 1024 * 1024, 0x61)
  const largePrepare = structuredClone(prepareEnvelope)
  largePrepare.request.method = 'POST'
  largePrepare.request.headers = {
    'content-length': String(requestBody.length),
    'content-type': 'application/octet-stream',
  }
  largePrepare.request.body_base64 = requestBody.toString('base64')
  largePrepare.request.body_sha256 = createHash('sha256').update(requestBody).digest('hex')
  largePrepare.request.body_bytes = requestBody.length
  const chrome = fakeChrome()
  const fetchImpl = async (url) => {
    const path = new URL(url).pathname
    if (path === '/v1/preview') return jsonResponse(previewEnvelope)
    if (path === '/v1/open') return jsonResponse(openEnvelope)
    if (path === '/v1/prepare') return jsonResponse(largePrepare)
    if (path === '/v1/ready') return jsonResponse(commitEnvelope)
    if (path === '/v1/result') return jsonResponse({ accepted: true })
    if (path === '/v1/close') return jsonResponse({ closed: true })
    assert.fail(`unexpected controller route: ${path}`)
  }
  const companion = createBrowserBridgeCompanion({
    chromeApi: chrome.api,
    fetchImpl,
    autoPump: false,
  })
  await companion.preview({ port: 4711, pairingCode: PAIRING_CODE })
  await companion.attach()
  assert.equal(await companion.runOneCycle(), 'EXECUTED')
  const injected = chrome.injections.find(({ func }) => (
    func.name === 'executeHttpAuthedInjectedFetch'
  ))
  assert.equal(injected.args[0].body.byte_length, requestBody.length)
  assert.equal(injected.args[0].body.value.length, largePrepare.request.body_base64.length)
  await companion.close()
  requestBody.fill(0)
})

test('Chrome bridge bounds every loopback controller exchange with an abort deadline', async () => {
  const chrome = fakeChrome()
  const timerDelays = []
  const cleared = []
  const companion = createBrowserBridgeCompanion({
    chromeApi: chrome.api,
    fetchImpl: async (_url, options) => new Promise((_resolve, reject) => {
      options.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true })
    }),
    setTimer(callback, delay) {
      timerDelays.push(delay)
      queueMicrotask(callback)
      return 37
    },
    clearTimer(handle) {
      cleared.push(handle)
    },
    autoPump: false,
  })
  await assert.rejects(
    companion.preview({ port: 4711, pairingCode: PAIRING_CODE }),
    { code: 'HTTP_AUTHED_BROWSER_CONTROLLER_TIMEOUT' },
  )
  assert.deepEqual(timerDelays, [15_000])
  assert.deepEqual(cleared, [37])
})

test('Chrome bridge refuses attachment when recovery storage cannot be checked', async () => {
  const chrome = fakeChrome()
  chrome.api.storage.session.get = async () => {
    throw new Error('synthetic storage failure')
  }
  let loopbackCalls = 0
  const companion = createBrowserBridgeCompanion({
    chromeApi: chrome.api,
    fetchImpl: async () => { loopbackCalls += 1 },
    autoPump: false,
  })
  await assert.rejects(
    companion.preview({ port: 4711, pairingCode: PAIRING_CODE }),
    { code: 'HTTP_AUTHED_BROWSER_RECOVERY_STORAGE_FAILED' },
  )
  assert.equal(loopbackCalls, 0)
})

test('Chrome bridge closes a newly opened controller session if recovery persistence fails', async () => {
  const chrome = fakeChrome()
  chrome.api.storage.session.set = async () => {
    throw new Error('synthetic storage failure')
  }
  const paths = []
  const companion = createBrowserBridgeCompanion({
    chromeApi: chrome.api,
    fetchImpl: async (url) => {
      const path = new URL(url).pathname
      paths.push(path)
      if (path === '/v1/preview') return jsonResponse(previewEnvelope)
      if (path === '/v1/open') return jsonResponse(openEnvelope)
      if (path === '/v1/close') return jsonResponse({ closed: true })
      assert.fail(`unexpected controller route: ${path}`)
    },
    autoPump: false,
  })
  await companion.preview({ port: 4711, pairingCode: PAIRING_CODE })
  await assert.rejects(
    companion.attach(),
    { code: 'HTTP_AUTHED_BROWSER_RECOVERY_STORAGE_FAILED' },
  )
  assert.deepEqual(paths, ['/v1/preview', '/v1/open', '/v1/close'])
  assert.equal(companion.status().phase, 'IDLE')
})

test('service worker imports the injected runtime and exposes only the six loopback routes', async () => {
  const source = await readFile(join(EXTENSION_DIRECTORY, 'service-worker.js'), 'utf8')

  for (const imported of [
    'abortHttpAuthedInjectedFetch',
    'captureHttpAuthedDocument',
    'clearHttpAuthedInjectedPreparation',
    'executeHttpAuthedInjectedFetch',
    'inspectHttpAuthedDocument',
    'prepareHttpAuthedInjectedFetch',
  ]) assert.match(source, new RegExp(`\\b${imported}\\b`))
  for (const route of ['/v1/preview', '/v1/open', '/v1/prepare', '/v1/ready', '/v1/result', '/v1/close']) {
    assert.match(source, new RegExp(route.replaceAll('/', '\\/')))
  }
  assert.match(source, /chromeApi\.tabs\.query/)
  assert.match(source, /chromeApi\.scripting\.executeScript/)
  assert.match(source, /world: 'ISOLATED'/)
  assert.doesNotMatch(source, /world: 'MAIN'/)
  assert.match(source, /http:\/\/127\.0\.0\.1/)
  assert.match(source, /sessionStorage\.setAccessLevel\(\{ accessLevel: 'TRUSTED_CONTEXTS' \}\)/)
  assert.doesNotMatch(source, /chromeApi\.(?:cookies|debugger|webRequest)|eval\s*\(|new Function/)
})
