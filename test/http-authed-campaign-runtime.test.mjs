import assert from 'node:assert/strict'
import { access, mkdir, mkdtemp, readFile, readdir, rm, unlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import {
  runHttpAuthedAttestedCampaign,
} from '../scripts/lib/http-authed-campaign-runtime.mjs'
import {
  openHttpAuthedCampaignLedger,
  requestHttpAuthedCampaignStop,
} from '../scripts/lib/http-authed-campaign-ledger.mjs'
import { main as httpAuthedMain } from '../scripts/http-authed.mjs'
import {
  canonicalJson,
  sha256Hex,
  verifyHttpAuthedAuthorization,
} from '../scripts/lib/http-authed-contracts.mjs'
import { attestedScope } from './helpers/http-authed-fixtures.mjs'

const NOW = new Date('2026-08-16T12:00:00.000Z')
const CREDENTIAL = 'synthetic-runtime-credential'

async function within(promise, milliseconds = 750) {
  let timer
  try {
    return await Promise.race([
      promise,
      new Promise((resolve, reject) => {
        timer = setTimeout(() => reject(new Error('synthetic startup stop timeout')), milliseconds)
      }),
    ])
  } finally {
    clearTimeout(timer)
  }
}

test('public CLI rejects retired written-authority routes and flags before any scoped I/O', async (t) => {
  const cases = [
    ['plan-written', '--scope', 'must-not-create-scope.json'],
    ['validate-written', '--scope', 'must-not-read-scope.json'],
    ['campaign-written', '--scope', 'must-not-read-scope.json'],
    ['plan-attested', '--authorization-document', 'must-not-read-authorization.txt'],
    ['plan-attested', '--approver-public-key', 'must-not-read-approver.pem'],
    ['campaign-attested', '--countersignature', 'must-not-read-countersignature.json'],
  ]
  let requestPlanReads = 0
  let credentialReads = 0
  let browserFactories = 0
  let sends = 0
  let stopRequests = 0

  for (const args of cases) {
    await t.test(`${args[0]} ${args[1] ?? ''}`.trim(), async () => {
      await assert.rejects(
        httpAuthedMain(args, {
          requestPlanLstat: async () => { requestPlanReads += 1 },
          requestPlanOpen: async () => { requestPlanReads += 1 },
          credentialInput: Symbol('must not be read for retired public route'),
          credentialStdinReader: async () => { credentialReads += 1; return CREDENTIAL },
          browserTransportFactory: async () => { browserFactories += 1 },
          transport: async () => { sends += 1 },
          requestCampaignStop: async () => { stopRequests += 1 },
          write: () => {},
        }),
        (error) => /supported http-authed command|does not support/.test(error.message)
          && error.code !== 'ENOENT',
      )
    })
  }

  assert.equal(requestPlanReads, 0)
  assert.equal(credentialReads, 0)
  assert.equal(browserFactories, 0)
  assert.equal(sends, 0)
  assert.equal(stopRequests, 0)
})

test('operator-attested campaign runtime binds protected transport, discovery, and durable ledger without repeat authorization', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-runtime-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const scope = attestedScope({ actionCount: 1 })
  scope.limits.min_interval_ms = 0
  scope.credential.binding_sha256 = sha256Hex(Buffer.from(CREDENTIAL))
  scope.authorization.authorized_scope.path_prefixes = ['/approved']
  scope.liveness.credential_preflight.url = `${scope.target.origin}/approved/whoami`
  scope.requests = [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'GET',
    url: `${scope.target.origin}/approved/seed`,
    expected_effect: 'none',
  }]
  scope.discovery = {
    enabled: true,
    origin: scope.target.origin,
    path_prefixes: ['/approved'],
    sources: ['location_header'],
    candidate_methods: ['GET'],
    test_category: 'api_security',
    synthetic_query_values: {},
    synthetic_path_values: {},
    max_response_bytes: scope.limits.max_response_bytes,
  }
  const verified = verifyHttpAuthedAuthorization({
    scope,
    now: NOW,
  })
  const scopePath = join(root, 'scope.json')
  const ledgerDirectory = join(root, 'ledger')
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  const calls = []

  const result = await runHttpAuthedAttestedCampaign({
    scopePath,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    ledgerDirectory,
    operatorId: scope.authorization.operator_id,
    env: { SYNTHETIC_TEST_CREDENTIAL: CREDENTIAL },
    clock: () => NOW,
    protectedTransport: async (request) => {
      await request.beforeSend()
      calls.push({
        method: request.method,
        url: request.url,
        userAgent: request.headers['user-agent'],
      })
      if (calls.length === 1) {
        await request.responseObserver?.({
          status: 200,
          headers: [{ name: 'location', value: '/approved/discovered' }],
          bodyChunks: [Buffer.from('TRANSIENT_RUNTIME_BODY_SENTINEL')],
        })
      } else {
        await request.responseObserver?.({ status: 200, headers: [], bodyChunks: [] })
      }
      return {
        status: 200,
        responseBytes: 0,
        responseHeaderNames: ['location', 'set-cookie'],
      }
    },
  })

  assert.equal(calls.length, 2)
  assert.equal(result.actions.completed, 2)
  assert.equal(calls[0].userAgent, 'red-team-audit-http-authed/0.12')
  assert.equal(result.actions.discovered, 1)
  assert.equal(result.ledger.terminal_actions, 2)
  assert.doesNotMatch(
    JSON.stringify(result),
    /peerstar-test|approved|TRANSIENT_RUNTIME_BODY_SENTINEL|synthetic-runtime-credential/i,
  )

  const replay = await runHttpAuthedAttestedCampaign({
    scopePath,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    ledgerDirectory,
    operatorId: scope.authorization.operator_id,
    trustedLedgerHead: {
      recordCount: result.ledger.record_count,
      headSha256: result.ledger.head_sha256,
    },
    env: { SYNTHETIC_TEST_CREDENTIAL: CREDENTIAL },
    clock: () => NOW,
    protectedTransport: async () => { throw new Error('trusted replay must send zero requests') },
  })
  assert.equal(replay.actions.completed, 0)
})

test('public CLI forwards a retained ledger head and rejects valid-prefix deletion before credential read or transport', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-cli-trusted-head-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const scope = attestedScope({ actionCount: 1 })
  scope.limits.min_interval_ms = 0
  scope.credential.ref = 'stdin:PIPE'
  scope.credential.binding_sha256 = sha256Hex(Buffer.from(CREDENTIAL))
  scope.authorization.permissions.mutation = false
  scope.requests = [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'GET',
    url: `${scope.target.origin}/trusted-head-probe`,
    expected_effect: 'none',
  }]
  const verified = verifyHttpAuthedAuthorization({ scope, now: NOW })
  const scopePath = join(root, 'scope.json')
  const ledgerDirectory = join(root, 'ledger')
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  const first = await runHttpAuthedAttestedCampaign({
    scopePath,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    ledgerDirectory,
    operatorId: scope.authorization.operator_id,
    fixedCampaignOnly: true,
    credentialInput: Symbol('initial redirected credential input'),
    credentialStdinReader: async () => CREDENTIAL,
    clock: () => NOW,
    protectedTransport: async (request) => {
      await request.beforeSend()
      return { status: 204, responseBytes: 0, responseHeaderNames: [] }
    },
  })
  const records = (await readdir(ledgerDirectory))
    .filter((name) => name.endsWith('.http-authed-campaign.json'))
    .sort()
  await unlink(join(ledgerDirectory, records.at(-1)))
  let credentialReads = 0
  let sends = 0

  await assert.rejects(
    httpAuthedMain([
      'campaign-attested',
      '--scope', scopePath,
      '--campaign-grant-sha256', verified.campaignGrantSha256,
      '--ledger', ledgerDirectory,
      '--operator-id', scope.authorization.operator_id,
      '--credential-stdin',
      '--trusted-ledger-record-count', String(first.ledger.record_count),
      '--trusted-ledger-head-sha256', first.ledger.head_sha256,
      '--json',
    ], {
      clock: () => NOW,
      credentialInput: Symbol('must not be read after ledger rollback'),
      credentialStdinReader: async () => { credentialReads += 1; return CREDENTIAL },
      transport: async () => { sends += 1 },
      write: () => {},
    }),
    (error) => error.code === 'HTTP_AUTHED_LEDGER_TRUSTED_HEAD_TRUNCATED',
  )
  assert.equal(credentialReads, 0)
  assert.equal(sends, 0)
})

test('trusted ledger mismatch rejects a browser campaign before companion creation or attach', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-browser-trusted-head-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const scope = attestedScope({ actionCount: 1 })
  scope.limits.min_interval_ms = 0
  scope.credential = {
    mode: 'CHROME_ACTIVE_TAB_SESSION',
    extension_id: 'abcdefghijklmnopabcdefghijklmnop',
    origin: scope.target.origin,
  }
  scope.authorization.permissions.mutation = false
  scope.requests = [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'GET',
    url: `${scope.target.origin}/browser-trusted-head-probe`,
    expected_effect: 'none',
  }]
  const verified = verifyHttpAuthedAuthorization({
    scope,
    now: NOW,
  })
  const scopePath = join(root, 'scope.json')
  const ledgerDirectory = join(root, 'ledger')
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  let browserFactories = 0
  let attaches = 0
  let sends = 0

  await assert.rejects(
    runHttpAuthedAttestedCampaign({
      scopePath,
      expectedCampaignGrantSha256: verified.campaignGrantSha256,
      ledgerDirectory,
      operatorId: scope.authorization.operator_id,
      fixedCampaignOnly: true,
      browserSessionRequested: true,
      trustedLedgerHead: { recordCount: 1, headSha256: 'f'.repeat(64) },
      clock: () => NOW,
      browserTransportFactory: async () => {
        browserFactories += 1
        return {
          pairing: { port: 43127, capability: 'h'.repeat(43) },
          waitForAttach: async () => { attaches += 1 },
          transport: async () => { sends += 1 },
          close: async () => {},
        }
      },
    }),
    (error) => error.code === 'HTTP_AUTHED_LEDGER_TRUSTED_HEAD_TRUNCATED',
  )
  assert.equal(browserFactories, 0)
  assert.equal(attaches, 0)
  assert.equal(sends, 0)
})

test('public CLI rejects either half of a trusted ledger head before campaign startup', async () => {
  const base = [
    'campaign-attested',
    '--scope', 'must-not-be-read-scope.json',
    '--campaign-grant-sha256', 'a'.repeat(64),
    '--ledger', 'must-not-be-opened-ledger',
    '--operator-id', 'must-not-start-operator',
  ]
  for (const incomplete of [
    ['--trusted-ledger-record-count', '1'],
    ['--trusted-ledger-head-sha256', 'b'.repeat(64)],
  ]) {
    let credentialReads = 0
    let sends = 0
    await assert.rejects(
      httpAuthedMain([...base, ...incomplete], {
        credentialInput: Symbol('must not be read for incomplete trusted head'),
        credentialStdinReader: async () => { credentialReads += 1; return CREDENTIAL },
        transport: async () => { sends += 1 },
        write: () => {},
      }),
      /trusted ledger checkpoint requires a positive record count and SHA-256 head digest/i,
    )
    assert.equal(credentialReads, 0)
    assert.equal(sends, 0)
  }
})

test('operator-attested campaign runtime dispatches a browser-held scope without exported credentials', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-browser-runtime-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const scope = attestedScope({ actionCount: 1 })
  scope.limits.min_interval_ms = 0
  scope.credential = {
    mode: 'CHROME_ACTIVE_TAB_SESSION',
    extension_id: 'abcdefghijklmnopabcdefghijklmnop',
    origin: scope.target.origin,
  }
  scope.authorization.permissions.mutation = false
  scope.requests = [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'GET',
    url: `${scope.target.origin}/browser-session-probe`,
    expected_effect: 'none',
  }]
  const verified = verifyHttpAuthedAuthorization({
    scope,
    now: NOW,
  })
  const scopePath = join(root, 'scope.json')
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  let sends = 0

  const result = await runHttpAuthedAttestedCampaign({
    scopePath,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    ledgerDirectory: join(root, 'ledger'),
    operatorId: scope.authorization.operator_id,
    browserSessionRequested: true,
    clock: () => NOW,
    protectedTransport: async (request) => {
      assert.deepEqual(request.headers, { accept: '*/*' })
      assert.equal(request.headers.cookie, undefined)
      assert.equal(request.headers.authorization, undefined)
      await request.beforeSend()
      sends += 1
      return { status: 200, responseBytes: 0, responseHeaderNames: [] }
    },
  })

  assert.equal(sends, 1)
  assert.equal(result.actions.completed, 1)
})

test('operator-attested campaign runtime requires an explicit matching browser execution mode', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-browser-mode-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const scope = attestedScope({ actionCount: 1 })
  scope.credential = {
    mode: 'CHROME_ACTIVE_TAB_SESSION',
    extension_id: 'abcdefghijklmnopabcdefghijklmnop',
    origin: scope.target.origin,
  }
  const verified = verifyHttpAuthedAuthorization({
    scope,
    now: NOW,
  })
  const scopePath = join(root, 'scope.json')
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  let sends = 0

  await assert.rejects(
    runHttpAuthedAttestedCampaign({
      scopePath,
      expectedCampaignGrantSha256: verified.campaignGrantSha256,
      ledgerDirectory: join(root, 'ledger'),
      operatorId: scope.authorization.operator_id,
      clock: () => NOW,
      protectedTransport: async () => { sends += 1 },
    }),
    (error) => error.code === 'HTTP_AUTHED_BROWSER_MODE_MISMATCH',
  )
  assert.equal(sends, 0)
})

test('browser campaign opens its stop ledger before attach and closes its bridge', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-browser-attach-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const scope = attestedScope({ actionCount: 1 })
  scope.limits.min_interval_ms = 0
  scope.credential = {
    mode: 'CHROME_ACTIVE_TAB_SESSION',
    extension_id: 'abcdefghijklmnopabcdefghijklmnop',
    origin: scope.target.origin,
  }
  scope.authorization.permissions.mutation = false
  scope.requests = [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'GET',
    url: `${scope.target.origin}/browser-session-probe`,
    expected_effect: 'none',
  }]
  const verified = verifyHttpAuthedAuthorization({
    scope,
    now: NOW,
  })
  const scopePath = join(root, 'scope.json')
  const ledgerDirectory = join(root, 'ledger')
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  let attached = 0
  let closed = 0
  let sends = 0
  let pairing

  const result = await runHttpAuthedAttestedCampaign({
    scopePath,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    ledgerDirectory,
    operatorId: scope.authorization.operator_id,
    browserSessionRequested: true,
    clock: () => NOW,
    browserTransportFactory: async (configuration) => {
      assert.equal(configuration.extensionId, scope.credential.extension_id)
      assert.equal(configuration.targetOrigin, scope.target.origin)
      assert.equal(configuration.campaignGrantSha256, verified.campaignGrantSha256)
      return {
        pairing: { port: 43123, capability: 'x'.repeat(43) },
        waitForAttach: async () => {
          await access(ledgerDirectory)
          await requestHttpAuthedCampaignStop({
            directory: ledgerDirectory,
            campaignGrantSha256: verified.campaignGrantSha256,
            operatorId: scope.authorization.operator_id,
            now: () => NOW,
          })
          attached += 1
        },
        transport: async (request) => {
          await request.beforeSend()
          sends += 1
          return { status: 200, responseBytes: 0, responseHeaderNames: [] }
        },
        close: async () => { closed += 1 },
      }
    },
    onBrowserPairing: async (value) => { pairing = value },
  })

  assert.deepEqual(pairing, { port: 43123, capability: 'x'.repeat(43) })
  assert.equal(attached, 1)
  assert.equal(closed, 1)
  assert.equal(sends, 0)
  assert.equal(result.actions.completed, 0)
  assert.equal(result.ledger.stopped, true)
  assert.equal(result.ledger.stop_reason, 'OPERATOR_REQUESTED')
})

test('operator stop interrupts browser transport creation and closes a session returned late', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-browser-stuck-factory-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const scope = attestedScope({ actionCount: 1 })
  scope.limits.min_interval_ms = 0
  scope.credential = {
    mode: 'CHROME_ACTIVE_TAB_SESSION',
    extension_id: 'abcdefghijklmnopabcdefghijklmnop',
    origin: scope.target.origin,
  }
  scope.authorization.permissions.mutation = false
  scope.requests = [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'GET',
    url: `${scope.target.origin}/browser-stuck-factory-probe`,
    expected_effect: 'none',
  }]
  const verified = verifyHttpAuthedAuthorization({
    scope,
    now: NOW,
  })
  const scopePath = join(root, 'scope.json')
  const ledgerDirectory = join(root, 'ledger')
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  let factoryStartedResolve
  const factoryStarted = new Promise((resolve) => { factoryStartedResolve = resolve })
  let resolveFactory
  const factoryResult = new Promise((resolve) => { resolveFactory = resolve })
  let lateCloseResolve
  const lateClose = new Promise((resolve) => { lateCloseResolve = resolve })
  let closes = 0
  let sends = 0

  const running = runHttpAuthedAttestedCampaign({
    scopePath,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    ledgerDirectory,
    operatorId: scope.authorization.operator_id,
    browserSessionRequested: true,
    clock: () => NOW,
    browserTransportFactory: async () => {
      factoryStartedResolve()
      return factoryResult
    },
  })
  await within(factoryStarted)
  await requestHttpAuthedCampaignStop({
    directory: ledgerDirectory,
    campaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    now: () => NOW,
  })
  const result = await within(running)

  resolveFactory({
    pairing: { port: 43125, capability: 'z'.repeat(43) },
    waitForAttach: async () => {},
    transport: async () => { sends += 1 },
    close: async () => {
      closes += 1
      lateCloseResolve()
    },
  })
  await within(lateClose)

  assert.equal(sends, 0)
  assert.equal(closes, 1)
  assert.equal(result.actions.completed, 0)
  assert.equal(result.ledger.stopped, true)
  assert.equal(result.ledger.stop_reason, 'OPERATOR_REQUESTED')
})

test('operator stop interrupts browser pairing and closes the created session exactly once', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-browser-stuck-pairing-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const scope = attestedScope({ actionCount: 1 })
  scope.limits.min_interval_ms = 0
  scope.credential = {
    mode: 'CHROME_ACTIVE_TAB_SESSION',
    extension_id: 'abcdefghijklmnopabcdefghijklmnop',
    origin: scope.target.origin,
  }
  scope.authorization.permissions.mutation = false
  scope.requests = [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'GET',
    url: `${scope.target.origin}/browser-stuck-pairing-probe`,
    expected_effect: 'none',
  }]
  const verified = verifyHttpAuthedAuthorization({
    scope,
    now: NOW,
  })
  const scopePath = join(root, 'scope.json')
  const ledgerDirectory = join(root, 'ledger')
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  let pairingStartedResolve
  const pairingStarted = new Promise((resolve) => { pairingStartedResolve = resolve })
  let attaches = 0
  let closes = 0
  let sends = 0

  const running = runHttpAuthedAttestedCampaign({
    scopePath,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    ledgerDirectory,
    operatorId: scope.authorization.operator_id,
    browserSessionRequested: true,
    clock: () => NOW,
    browserTransportFactory: async () => ({
      pairing: { port: 43126, capability: 'p'.repeat(43) },
      waitForAttach: async () => { attaches += 1 },
      transport: async () => { sends += 1 },
      close: async () => { closes += 1 },
    }),
    onBrowserPairing: async () => {
      pairingStartedResolve()
      return new Promise(() => {})
    },
  })
  await within(pairingStarted)
  await requestHttpAuthedCampaignStop({
    directory: ledgerDirectory,
    campaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    now: () => NOW,
  })
  const result = await within(running)

  assert.equal(attaches, 0)
  assert.equal(sends, 0)
  assert.equal(closes, 1)
  assert.equal(result.actions.completed, 0)
  assert.equal(result.ledger.stopped, true)
  assert.equal(result.ledger.stop_reason, 'OPERATOR_REQUESTED')
})

test('operator stop interrupts a browser attach that never resolves', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-browser-stuck-attach-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const scope = attestedScope({ actionCount: 1 })
  scope.limits.min_interval_ms = 0
  scope.credential = {
    mode: 'CHROME_ACTIVE_TAB_SESSION',
    extension_id: 'abcdefghijklmnopabcdefghijklmnop',
    origin: scope.target.origin,
  }
  scope.authorization.permissions.mutation = false
  scope.requests = [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'GET',
    url: `${scope.target.origin}/browser-stuck-attach-probe`,
    expected_effect: 'none',
  }]
  const verified = verifyHttpAuthedAuthorization({
    scope,
    now: NOW,
  })
  const scopePath = join(root, 'scope.json')
  const ledgerDirectory = join(root, 'ledger')
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  let attachStartedResolve
  const attachStarted = new Promise((resolve) => { attachStartedResolve = resolve })
  let closed = 0
  let sends = 0

  const running = runHttpAuthedAttestedCampaign({
    scopePath,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    ledgerDirectory,
    operatorId: scope.authorization.operator_id,
    browserSessionRequested: true,
    clock: () => NOW,
    browserTransportFactory: async () => ({
      pairing: { port: 43124, capability: 'y'.repeat(43) },
      waitForAttach: async () => {
        attachStartedResolve()
        return new Promise(() => {})
      },
      transport: async (request) => {
        await request.beforeSend()
        sends += 1
        return { status: 200, responseBytes: 0, responseHeaderNames: [] }
      },
      close: async () => { closed += 1 },
    }),
  })
  await within(attachStarted)
  await requestHttpAuthedCampaignStop({
    directory: ledgerDirectory,
    campaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    now: () => NOW,
  })
  const result = await within(running)

  assert.equal(sends, 0)
  assert.equal(closed, 1)
  assert.equal(result.ledger.stopped, true)
  assert.equal(result.ledger.stop_reason, 'OPERATOR_REQUESTED')
  assert.equal(result.actions.completed, 0)
})

test('operator stop interrupts a credential read that never resolves', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-stuck-credential-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const scope = attestedScope({ actionCount: 1 })
  scope.limits.min_interval_ms = 0
  scope.credential.ref = 'stdin:PIPE'
  scope.credential.binding_sha256 = sha256Hex(Buffer.from(CREDENTIAL))
  const verified = verifyHttpAuthedAuthorization({
    scope,
    now: NOW,
  })
  const scopePath = join(root, 'scope.json')
  const ledgerDirectory = join(root, 'ledger')
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  let credentialReadResolve
  const credentialRead = new Promise((resolve) => { credentialReadResolve = resolve })
  let sends = 0

  const running = runHttpAuthedAttestedCampaign({
    scopePath,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    ledgerDirectory,
    operatorId: scope.authorization.operator_id,
    clock: () => NOW,
    credentialInput: Symbol('synthetic blocked credential input'),
    credentialStdinReader: async () => {
      credentialReadResolve()
      return new Promise(() => {})
    },
    protectedTransport: async () => { sends += 1 },
  })
  await within(credentialRead)
  await requestHttpAuthedCampaignStop({
    directory: ledgerDirectory,
    campaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    now: () => NOW,
  })
  const result = await within(running)

  assert.equal(sends, 0)
  assert.equal(result.ledger.stopped, true)
  assert.equal(result.ledger.stop_reason, 'OPERATOR_REQUESTED')
  assert.equal(result.actions.completed, 0)
})

test('campaign-attested CLI executes a controller-governed active probe', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-runtime-cli-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const scope = attestedScope({ actionCount: 1 })
  scope.limits.min_interval_ms = 0
  scope.credential.binding_sha256 = sha256Hex(Buffer.from(CREDENTIAL))
  scope.authorization.permissions.mutation = true
  scope.requests = [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'PROPFIND',
    url: `${scope.target.origin}/SENSITIVE_SYNTHETIC_ROUTE`,
    expected_effect: 'none',
  }]
  scope.authorization.authorized_scope.methods.push('PROPFIND')
  const verified = verifyHttpAuthedAuthorization({ scope, now: NOW })
  const scopePath = join(root, 'scope.json')
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  let output = ''
  let sends = 0

  await httpAuthedMain([
    'campaign-attested',
    '--scope', scopePath,
    '--campaign-grant-sha256', verified.campaignGrantSha256,
    '--ledger', join(root, 'ledger'),
    '--operator-id', scope.authorization.operator_id,
    '--json',
  ], {
    clock: () => NOW,
    env: { SYNTHETIC_TEST_CREDENTIAL: CREDENTIAL },
    transport: async (request) => {
      sends += 1
      await request.beforeSend()
      return { status: 207, responseBytes: 0, responseHeaderNames: [] }
    },
    write: (value) => { output += value },
  })

  assert.equal(sends, 1)
  assert.equal(JSON.parse(output).actions.completed, 1)
  await access(join(root, 'ledger'))
})

test('public campaign executes sealed adaptive discovery through the controller', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-runtime-public-discovery-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const scope = attestedScope({ actionCount: 1 })
  scope.limits.min_interval_ms = 0
  scope.credential.binding_sha256 = sha256Hex(Buffer.from(CREDENTIAL))
  scope.authorization.permissions.mutation = false
  scope.authorization.authorized_scope.path_prefixes = ['/approved']
  scope.liveness.credential_preflight.url = `${scope.target.origin}/approved/whoami`
  scope.requests = [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'GET',
    url: `${scope.target.origin}/approved/discovery-seed`,
    expected_effect: 'none',
  }]
  scope.discovery = {
    enabled: true,
    origin: scope.target.origin,
    path_prefixes: [...scope.authorization.authorized_scope.path_prefixes],
    sources: ['location_header'],
    candidate_methods: ['GET'],
    test_category: 'api_security',
    synthetic_query_values: {},
    synthetic_path_values: {},
    max_response_bytes: scope.limits.max_response_bytes,
  }
  const verified = verifyHttpAuthedAuthorization({ scope, now: NOW })
  const scopePath = join(root, 'scope.json')
  const ledgerPath = join(root, 'ledger')
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  const calls = []
  let output = ''

  await httpAuthedMain([
      'campaign-attested',
      '--scope', scopePath,
      '--campaign-grant-sha256', verified.campaignGrantSha256,
      '--ledger', ledgerPath,
      '--operator-id', scope.authorization.operator_id,
      '--json',
    ], {
      clock: () => NOW,
      env: { SYNTHETIC_TEST_CREDENTIAL: CREDENTIAL },
      transport: async (request) => {
        await request.beforeSend()
        calls.push(request.url)
        await request.responseObserver?.({
          status: 200,
          headers: calls.length === 1
            ? [{ name: 'location', value: '/approved/discovered-endpoint' }]
            : [],
          bodyChunks: [],
        })
        return { status: 200, responseBytes: 0, responseHeaderNames: [] }
      },
      write: (value) => { output += value },
    })

  assert.equal(calls.length, 2)
  assert.equal(JSON.parse(output).actions.discovered, 1)
  await access(ledgerPath)
})

test('public campaign executes more than 256 sealed actions through the general controller', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-runtime-public-cap-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const scope = attestedScope({ actionCount: 257 })
  scope.limits.min_interval_ms = 0
  scope.credential.binding_sha256 = sha256Hex(Buffer.from(CREDENTIAL))
  scope.authorization.permissions.mutation = false
  scope.requests = Array.from({ length: 257 }, (_unused, index) => ({
    kind: 'probe',
    sequence: index + 1,
    test_category: 'api_security',
    method: 'GET',
    url: `${scope.target.origin}/sealed-probe-${index + 1}`,
    expected_effect: 'none',
  }))
  const verified = verifyHttpAuthedAuthorization({ scope, now: NOW })
  const scopePath = join(root, 'scope.json')
  const ledgerPath = join(root, 'ledger')
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  let sends = 0
  let output = ''

  await httpAuthedMain([
      'campaign-attested',
      '--scope', scopePath,
      '--campaign-grant-sha256', verified.campaignGrantSha256,
      '--ledger', ledgerPath,
      '--operator-id', scope.authorization.operator_id,
      '--json',
    ], {
      clock: () => NOW,
      env: { SYNTHETIC_TEST_CREDENTIAL: CREDENTIAL },
      transport: async (request) => {
        await request.beforeSend()
        sends += 1
        return { status: 200, responseBytes: 0, responseHeaderNames: [] }
      },
      write: (value) => { output += value },
    })

  assert.equal(sends, 257)
  assert.equal(JSON.parse(output).actions.completed, 257)
  await access(ledgerPath)
})

test('fixed campaigns ledger terminal response stops and send no later sealed action', async (t) => {
  const cases = [
    [401, 'CREDENTIAL_INVALID'],
    [403, 'CREDENTIAL_INVALID'],
    [302, 'UNEXPECTED_REDIRECT'],
    [429, 'LIMIT_REACHED'],
    [500, 'TARGET_HEALTH_DEGRADED'],
  ]

  for (const [status, reasonCode] of cases) {
    await t.test(`${status} -> ${reasonCode}`, async (t) => {
      const root = await mkdtemp(join(tmpdir(), `rta-http-authed-runtime-${status}-stop-`))
      t.after(() => rm(root, { recursive: true, force: true }))
      const scope = attestedScope({ actionCount: 1 })
      scope.limits.min_interval_ms = 0
      scope.credential.binding_sha256 = sha256Hex(Buffer.from(CREDENTIAL))
      scope.authorization.permissions.mutation = false
      scope.requests = Array.from({ length: 3 }, (_unused, index) => ({
        kind: 'probe',
        sequence: index + 1,
        test_category: 'api_security',
        method: 'GET',
        url: `${scope.target.origin}/status-${status}-stop-${index + 1}`,
        expected_effect: 'none',
      }))
      const verified = verifyHttpAuthedAuthorization({
        scope,
        now: NOW,
      })
      const scopePath = join(root, 'scope.json')
      const ledgerDirectory = join(root, 'ledger')
      await writeFile(scopePath, JSON.stringify(scope), 'utf8')
      let sends = 0

      const result = await runHttpAuthedAttestedCampaign({
        scopePath,
        expectedCampaignGrantSha256: verified.campaignGrantSha256,
        ledgerDirectory,
        operatorId: scope.authorization.operator_id,
        fixedCampaignOnly: true,
        env: { SYNTHETIC_TEST_CREDENTIAL: CREDENTIAL },
        clock: () => NOW,
        protectedTransport: async (request) => {
          await request.beforeSend()
          sends += 1
          return { status, responseBytes: 0, responseHeaderNames: [] }
        },
      })

      assert.equal(sends, 1)
      assert.equal(result.actions.completed, 1)
      assert.equal(result.ledger.stopped, true)
      const stopRecords = await Promise.all((await readdir(ledgerDirectory))
        .filter((name) => name.endsWith('.http-authed-campaign.json'))
        .map(async (name) => JSON.parse(await readFile(join(ledgerDirectory, name), 'utf8'))))
      assert.equal(
        stopRecords.some(({ event }) => (
          event.type === 'CAMPAIGN_STOPPED' && event.reason_code === reasonCode
        )),
        true,
      )
    })
  }
})

test('fixed campaign consumes an out-of-band stop request into its ledger before dispatch', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-runtime-operator-stop-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const scope = attestedScope({ actionCount: 1 })
  scope.limits.min_interval_ms = 0
  scope.credential.binding_sha256 = sha256Hex(Buffer.from(CREDENTIAL))
  scope.authorization.permissions.mutation = false
  scope.requests = [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'GET',
    url: `${scope.target.origin}/must-not-send-after-stop`,
    expected_effect: 'none',
  }]
  const verified = verifyHttpAuthedAuthorization({
    scope,
    now: NOW,
  })
  const scopePath = join(root, 'scope.json')
  const ledgerDirectory = join(root, 'ledger')
  await mkdir(ledgerDirectory)
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  const stopRequest = await requestHttpAuthedCampaignStop({
    directory: ledgerDirectory,
    campaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    now: () => NOW,
  })
  assert.equal(stopRequest.status, 'STOP_REQUESTED')
  const repeatedStop = await requestHttpAuthedCampaignStop({
    directory: ledgerDirectory,
    campaignGrantSha256: verified.campaignGrantSha256,
    operatorId: scope.authorization.operator_id,
    now: () => new Date(NOW.getTime() + 1_000),
  })
  assert.equal(repeatedStop.status, 'ALREADY_REQUESTED')
  await assert.rejects(
    requestHttpAuthedCampaignStop({
      directory: ledgerDirectory,
      campaignGrantSha256: 'f'.repeat(64),
      operatorId: scope.authorization.operator_id,
      now: () => NOW,
    }),
    (error) => error.code === 'HTTP_AUTHED_LEDGER_STOP_REQUEST_MISMATCH',
  )
  let sends = 0

  const result = await runHttpAuthedAttestedCampaign({
    scopePath,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    ledgerDirectory,
    operatorId: scope.authorization.operator_id,
    fixedCampaignOnly: true,
    env: { SYNTHETIC_TEST_CREDENTIAL: CREDENTIAL },
    clock: () => NOW,
    protectedTransport: async () => { sends += 1 },
  })

  assert.equal(sends, 0)
  assert.equal(result.actions.completed, 0)
  assert.equal(result.ledger.stopped, true)
  const stopRecords = await Promise.all((await readdir(ledgerDirectory))
    .filter((name) => name.endsWith('.http-authed-campaign.json'))
    .map(async (name) => JSON.parse(await readFile(join(ledgerDirectory, name), 'utf8'))))
  assert.equal(
    stopRecords.some(({ event }) => (
      event.type === 'CAMPAIGN_STOPPED' && event.reason_code === 'OPERATOR_REQUESTED'
    )),
    true,
  )
})

test('fixed campaign observes an out-of-band stop during its final request', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-runtime-live-stop-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const scope = attestedScope({ actionCount: 1 })
  scope.limits.min_interval_ms = 0
  scope.credential.binding_sha256 = sha256Hex(Buffer.from(CREDENTIAL))
  scope.authorization.permissions.mutation = false
  scope.requests = Array.from({ length: 1 }, (_unused, index) => ({
    kind: 'probe',
    sequence: index + 1,
    test_category: 'api_security',
    method: 'GET',
    url: `${scope.target.origin}/live-stop-${index + 1}`,
    expected_effect: 'none',
  }))
  const verified = verifyHttpAuthedAuthorization({
    scope,
    now: NOW,
  })
  const scopePath = join(root, 'scope.json')
  const ledgerDirectory = join(root, 'ledger')
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  let sends = 0

  const result = await runHttpAuthedAttestedCampaign({
    scopePath,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    ledgerDirectory,
    operatorId: scope.authorization.operator_id,
    fixedCampaignOnly: true,
    env: { SYNTHETIC_TEST_CREDENTIAL: CREDENTIAL },
    clock: () => NOW,
    protectedTransport: async (request) => {
      await request.beforeSend()
      sends += 1
      if (sends === 1) {
        await requestHttpAuthedCampaignStop({
          directory: ledgerDirectory,
          campaignGrantSha256: verified.campaignGrantSha256,
          operatorId: scope.authorization.operator_id,
          now: () => NOW,
        })
      }
      return { status: 200, responseBytes: 0, responseHeaderNames: [] }
    },
  })

  assert.equal(sends, 1)
  assert.equal(result.actions.completed, 1)
  assert.equal(result.ledger.stopped, true)
})

test('campaign-attested CLI executes a fixed campaign through a paired browser transport', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-browser-cli-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const scope = attestedScope({ actionCount: 1 })
  scope.limits.min_interval_ms = 0
  scope.credential = {
    mode: 'CHROME_ACTIVE_TAB_SESSION',
    extension_id: 'abcdefghijklmnopabcdefghijklmnop',
    origin: scope.target.origin,
  }
  scope.authorization.permissions.mutation = false
  scope.requests = [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'GET',
    url: `${scope.target.origin}/browser-session-probe`,
    expected_effect: 'none',
  }]
  const verified = verifyHttpAuthedAuthorization({ scope, now: NOW })
  const scopePath = join(root, 'scope.json')
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  let output = ''
  let pairingOutput = ''
  let attached = 0
  let browserFactories = 0
  let closed = 0

  await httpAuthedMain([
    'campaign-attested',
    '--scope', scopePath,
    '--campaign-grant-sha256', verified.campaignGrantSha256,
    '--ledger', join(root, 'ledger'),
    '--operator-id', scope.authorization.operator_id,
    '--credential-browser',
    '--json',
  ], {
    clock: () => NOW,
    browserTransportFactory: async () => {
      browserFactories += 1
      return {
        pairing: {
          bridge_origin: 'http://127.0.0.1:43123/',
          pairing_code: 'x'.repeat(43),
          target_origin: scope.target.origin,
          campaign_grant_sha256: verified.campaignGrantSha256,
        },
        waitForAttach: async () => { attached += 1 },
        transport: async (request) => {
          await request.beforeSend()
          return { status: 200, responseBytes: 0, responseHeaderNames: [] }
        },
        close: async () => { closed += 1 },
      }
    },
    browserPairingWrite: (value) => { pairingOutput += value },
    write: (value) => { output += value },
  })

  assert.equal(browserFactories, 1)
  assert.equal(attached, 1)
  assert.equal(closed, 1)
  assert.equal(JSON.parse(output).actions.completed, 1)
  assert.match(pairingOutput, /controller port: 43123/)
  await access(join(root, 'ledger'))
})

test('operator-attested campaign runtime executes a controller-authorized reversible mutation over protected transport', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-runtime-mutation-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const materials = join(root, 'materials')
  await mkdir(materials)
  const mutationBody = Buffer.alloc(64, 0x6d)
  const rollbackBody = Buffer.alloc(64, 0x72)
  const scope = attestedScope({ actionCount: 1 })
  scope.limits.min_interval_ms = 0
  scope.credential.binding_sha256 = sha256Hex(Buffer.from(CREDENTIAL))
  scope.requests[0].request_body.sha256 = sha256Hex(mutationBody)
  scope.requests[0].rollback.request_body.sha256 = sha256Hex(rollbackBody)
  const valueDigest = (value) => sha256Hex(Buffer.from(canonicalJson(value), 'utf8'))
  scope.requests[0].expected_mutation.before_digest = valueDigest('BEFORE_SENTINEL')
  scope.requests[0].expected_mutation.after_digest = valueDigest('AFTER_SENTINEL')
  scope.requests[0].rollback.expected_after_digest = valueDigest('BEFORE_SENTINEL')
  const verified = verifyHttpAuthedAuthorization({
    scope,
    now: NOW,
  })
  const ledgerDirectory = join(root, 'ledger')
  const bodyPath = (metadata) => join(
    materials,
    `body-${sha256Hex(Buffer.from(metadata.body_id, 'utf8'))}.bin`,
  )
  await Promise.all([
    writeFile(bodyPath(scope.requests[0].request_body), mutationBody),
    writeFile(bodyPath(scope.requests[0].rollback.request_body), rollbackBody),
  ])
  const scopePath = join(root, 'scope.json')
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  const bodies = [
    Buffer.alloc(0),
    Buffer.from('{"synthetic_marker":"BEFORE_SENTINEL","stable":"SAME"}'),
    Buffer.alloc(0),
    Buffer.from('{"synthetic_marker":"AFTER_SENTINEL","stable":"SAME"}'),
    Buffer.alloc(0),
    Buffer.from('{"synthetic_marker":"BEFORE_SENTINEL","stable":"SAME"}'),
  ]
  let call = 0

  const result = await runHttpAuthedAttestedCampaign({
    scopePath,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    ledgerDirectory,
    materialsDirectory: materials,
    operatorId: scope.authorization.operator_id,
    env: { SYNTHETIC_TEST_CREDENTIAL: CREDENTIAL },
    clock: () => NOW,
    protectedTransport: async (request) => {
      const index = call
      call += 1
      await request.beforeSend()
      await request.responseObserver?.({
        status: index === 2 ? 201 : 200,
        headers: [{ name: 'content-type', value: 'application/json' }],
        bodyChunks: [bodies[index]],
      })
      return {
        status: index === 2 ? 201 : 200,
        responseBytes: bodies[index].length,
        responseHeaderNames: ['content-type', 'set-cookie'],
      }
    },
  })

  assert.equal(call, 6)
  assert.equal(result.actions.completed, 1)
  assert.equal(result.actions.failed, 0)
  assert.doesNotMatch(JSON.stringify(result), /BEFORE_SENTINEL|AFTER_SENTINEL|SAME|credential/i)
  const ledgerText = (await Promise.all(
    (await readdir(ledgerDirectory))
      .filter((name) => name.endsWith('.json'))
      .map((name) => readFile(join(ledgerDirectory, name), 'utf8')),
  )).join('\n')
  assert.match(ledgerText, /AUTHORIZATION_CONSUMED/)
  assert.match(ledgerText, /dispatch_permit_sha256/)
  assert.doesNotMatch(ledgerText, /countersignature/i)
})

test('operator-attested runtime restarts an interrupted mutation after action expiry in cleanup-only mode', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-runtime-recovery-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const materials = join(root, 'materials')
  await mkdir(materials)
  const scope = attestedScope({ actionCount: 1 })
  scope.validity.cleanup_not_after = '2026-08-16T12:10:00.000Z'
  scope.limits.min_interval_ms = 0
  scope.credential.binding_sha256 = sha256Hex(Buffer.from(CREDENTIAL))
  const rollbackBody = Buffer.alloc(64, 0x72)
  scope.requests[0].rollback.request_body.sha256 = sha256Hex(rollbackBody)
  const beforeDigest = sha256Hex(Buffer.from(canonicalJson('BEFORE_SENTINEL'), 'utf8'))
  scope.requests[0].expected_mutation.before_digest = beforeDigest
  scope.requests[0].rollback.expected_after_digest = beforeDigest
  const verified = verifyHttpAuthedAuthorization({
    scope,
    now: NOW,
  })
  const ledgerDirectory = join(root, 'ledger')
  const interrupted = await openHttpAuthedCampaignLedger({
    directory: ledgerDirectory,
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
    independentlyVerified: scope.authorization.independently_verified,
    operatorId: scope.authorization.operator_id,
    initialize: true,
    now: () => NOW,
  })
  await interrupted.enqueueCandidate({
    candidateDraft: scope.requests[0],
    provenance: 'SEALED_PLAN',
  })
  const lease = await interrupted.leaseAction({
    candidateDraft: scope.requests[0],
    operatorId: scope.authorization.operator_id,
  })
  for (const phase of ['CREDENTIAL_PREFLIGHT', 'BEFORE_READ']) {
    await interrupted.markPreDispatch({
      actionId: lease.actionId,
      leaseId: lease.leaseId,
      phase,
      requestBindingSha256: sha256Hex(Buffer.from(`synthetic-runtime-${phase}`)),
    })
    await interrupted.markOutcome({
      actionId: lease.actionId,
      leaseId: lease.leaseId,
      phase,
      outcome: 'SETTLED',
      responseMetadata: {
        status: 200,
        bytes: 0,
        headerNames: ['content-type'],
        requestMayHaveBeenSent: true,
      },
    })
    if (phase === 'BEFORE_READ') {
      await interrupted.recordVerification({
        actionId: lease.actionId,
        leaseId: lease.leaseId,
        phase,
        valueMatch: true,
        contextMatch: true,
      })
    }
  }
  await interrupted.consumeAuthorization({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    nonce: 'synthetic-runtime-recovery-authorization-nonce-0001',
    dispatchPermitSha256: 'a'.repeat(64),
  })
  await interrupted.markPreDispatch({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'MUTATION',
    requestBindingSha256: 'b'.repeat(64),
  })
  await interrupted.close()

  const scopePath = join(root, 'scope.json')
  const rollbackPath = join(
    materials,
    `body-${sha256Hex(Buffer.from(scope.requests[0].rollback.request_body.body_id, 'utf8'))}.bin`,
  )
  await Promise.all([
    writeFile(scopePath, JSON.stringify(scope), 'utf8'),
    writeFile(rollbackPath, rollbackBody),
  ])
  const methods = []
  const result = await runHttpAuthedAttestedCampaign({
    scopePath,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    ledgerDirectory,
    materialsDirectory: materials,
    operatorId: scope.authorization.operator_id,
    env: { SYNTHETIC_TEST_CREDENTIAL: CREDENTIAL },
    clock: () => new Date('2026-08-16T12:05:00.000Z'),
    protectedTransport: async (request) => {
      await request.beforeSend()
      methods.push(request.method)
      const body = request.method === 'GET'
        ? Buffer.from('{"synthetic_marker":"BEFORE_SENTINEL"}')
        : Buffer.alloc(0)
      await request.responseObserver?.({
        status: 200,
        headers: [{ name: 'content-type', value: 'application/json' }],
        bodyChunks: [body],
      })
      return {
        status: 200,
        responseBytes: body.length,
        responseHeaderNames: ['content-type'],
      }
    },
  })

  assert.deepEqual(methods, ['PATCH', 'GET'])
  assert.equal(methods.includes('POST'), false)
  assert.equal(result.actions.uncertain, 1)
  assert.equal(result.ledger.stopped, true)
  assert.equal(result.ledger.terminal_actions, 1)
  assert.doesNotMatch(JSON.stringify(result), /BEFORE_SENTINEL|synthetic_marker|credential/i)

  const records = await Promise.all((await readdir(ledgerDirectory))
    .filter((name) => name.endsWith('.http-authed-campaign.json'))
    .sort()
    .map(async (name) => JSON.parse(await readFile(join(ledgerDirectory, name), 'utf8'))))
  const cleanupConfirmationIndex = records.findIndex(
    ({ event }) => event.type === 'CLEANUP_SESSION_CONFIRMED',
  )
  const rollbackPreDispatchIndex = records.findIndex(
    ({ event }) => event.type === 'REQUEST_PRE_DISPATCH' && event.phase === 'ROLLBACK',
  )
  const authorizationConsumed = records.find(
    ({ event }) => event.type === 'AUTHORIZATION_CONSUMED',
  )
  assert.equal(authorizationConsumed.event.dispatch_permit_sha256, 'a'.repeat(64))
  assert.equal(records.some(({ event }) => event.type === 'APPROVAL_CONSUMED'), false)
  assert.ok(cleanupConfirmationIndex >= 0)
  assert.ok(cleanupConfirmationIndex < rollbackPreDispatchIndex)
  assert.deepEqual(records[cleanupConfirmationIndex].event, {
    type: 'CLEANUP_SESSION_CONFIRMED',
    operator_id: scope.authorization.operator_id,
    authorization_mode: 'OPERATOR_ATTESTED_AUTHED',
    confirmation: 'CLEANUP_ONLY_CONFIRMED',
  })
  assert.equal(records.some(({ event }) => (
    event.type === 'CAMPAIGN_SESSION_CONFIRMED'
    && event.confirmation === 'CURRENT_AUTHORIZATION_CONFIRMED'
  )), false)
})

test('attested runtime reopens only an existing ledger after expiry and dispatches cleanup only', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-attested-recovery-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const materials = join(root, 'materials')
  await mkdir(materials)
  const scope = attestedScope({ actionCount: 1 })
  scope.authorization.mode = 'OPERATOR_ATTESTED_AUTHED'
  scope.authorization.attested_at = NOW.toISOString()
  scope.validity.cleanup_not_after = '2026-08-16T12:10:00.000Z'
  scope.limits.min_interval_ms = 0
  scope.credential = {
    ref: 'stdin:PIPE',
    kind: 'bearer',
    binding_sha256: sha256Hex(Buffer.from(CREDENTIAL)),
  }
  const rollbackBody = Buffer.alloc(64, 0x72)
  scope.requests[0].rollback.request_body.sha256 = sha256Hex(rollbackBody)
  const verified = verifyHttpAuthedAuthorization({ scope, now: NOW })
  const ledgerDirectory = join(root, 'ledger')
  const interrupted = await openHttpAuthedCampaignLedger({
    directory: ledgerDirectory,
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: scope.authorization.mode,
    independentlyVerified: scope.authorization.independently_verified,
    operatorId: scope.authorization.operator_id,
    initialize: true,
    now: () => NOW,
  })
  await interrupted.enqueueCandidate({
    candidateDraft: scope.requests[0],
    provenance: 'SEALED_PLAN',
  })
  const lease = await interrupted.leaseAction({
    candidateDraft: scope.requests[0],
    operatorId: scope.authorization.operator_id,
  })
  for (const phase of ['CREDENTIAL_PREFLIGHT', 'BEFORE_READ']) {
    await interrupted.markPreDispatch({
      actionId: lease.actionId,
      leaseId: lease.leaseId,
      phase,
      requestBindingSha256: sha256Hex(Buffer.from(`synthetic-attested-${phase}`)),
    })
    await interrupted.markOutcome({
      actionId: lease.actionId,
      leaseId: lease.leaseId,
      phase,
      outcome: 'SETTLED',
      responseMetadata: {
        status: 200,
        bytes: 0,
        headerNames: ['content-type'],
        requestMayHaveBeenSent: true,
      },
    })
    if (phase === 'BEFORE_READ') {
      await interrupted.recordVerification({
        actionId: lease.actionId,
        leaseId: lease.leaseId,
        phase,
        valueMatch: true,
        contextMatch: true,
      })
    }
  }
  await interrupted.consumeAuthorization({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    nonce: 'synthetic-attested-recovery-authorization-nonce-0001',
    dispatchPermitSha256: 'a'.repeat(64),
  })
  await interrupted.markPreDispatch({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'MUTATION',
    requestBindingSha256: 'b'.repeat(64),
  })
  await interrupted.close()

  const scopePath = join(root, 'scope.json')
  const rollbackPath = join(
    materials,
    `body-${sha256Hex(Buffer.from(scope.requests[0].rollback.request_body.body_id, 'utf8'))}.bin`,
  )
  await Promise.all([
    writeFile(scopePath, JSON.stringify(scope), 'utf8'),
    writeFile(rollbackPath, rollbackBody),
  ])
  const readLedgerRecords = async () => Promise.all((await readdir(ledgerDirectory))
    .filter((name) => name.endsWith('.http-authed-campaign.json'))
    .sort()
    .map(async (name) => JSON.parse(await readFile(join(ledgerDirectory, name), 'utf8'))))
  let credentialReads = 0
  const methods = []
  const result = await runHttpAuthedAttestedCampaign({
    scopePath,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    ledgerDirectory,
    materialsDirectory: materials,
    operatorId: scope.authorization.operator_id,
    credentialInput: Symbol('sealed attested cleanup credential'),
    credentialStdinReader: async () => {
      credentialReads += 1
      const recordsAtResolution = await readLedgerRecords()
      assert.ok(recordsAtResolution.some(({ event }) => (
        event.type === 'CLEANUP_SESSION_CONFIRMED'
        && event.confirmation === 'CLEANUP_ONLY_CONFIRMED'
      )))
      assert.equal(recordsAtResolution.some(({ event }) => (
        event.type === 'REQUEST_PRE_DISPATCH' && event.phase === 'ROLLBACK'
      )), false)
      return Buffer.from(CREDENTIAL)
    },
    clock: () => new Date('2026-08-16T12:05:00.000Z'),
    protectedTransport: async (request) => {
      await request.beforeSend()
      methods.push(request.method)
      const body = request.method === 'GET' ? Buffer.from('{}') : Buffer.alloc(0)
      await request.responseObserver?.({
        status: 200,
        headers: [{ name: 'content-type', value: 'application/json' }],
        bodyChunks: [body],
      })
      return {
        status: 200,
        responseBytes: body.length,
        responseHeaderNames: ['content-type'],
      }
    },
    mutationDependencies: {
      verifyObservation: async () => ({ valueMatch: true, contextMatch: false }),
    },
  })

  assert.equal(credentialReads, 1)
  assert.deepEqual(methods, ['PATCH', 'GET'])
  assert.equal(result.cleanup_only, true)
  assert.equal(result.authorization_mode, 'OPERATOR_ATTESTED_AUTHED')
  assert.equal(result.actions.discovered, 0)
  assert.equal(result.actions.uncertain, 1)

  const records = await readLedgerRecords()
  assert.equal(records.filter(({ event }) => event.type === 'CAMPAIGN_OPENED').length, 1)
  assert.equal(records.filter(({ event }) => event.type === 'CANDIDATE_ENQUEUED').length, 1)
  assert.equal(records.filter(({ event }) => event.type === 'ACTION_LEASED').length, 1)
  const cleanupConfirmationIndex = records.findIndex(
    ({ event }) => event.type === 'CLEANUP_SESSION_CONFIRMED',
  )
  const cleanupPreDispatches = records
    .filter(({ event }) => event.type === 'REQUEST_PRE_DISPATCH')
    .slice(-2)
    .map(({ event }) => event.phase)
  const rollbackPreDispatchIndex = records.findIndex(
    ({ event }) => event.type === 'REQUEST_PRE_DISPATCH' && event.phase === 'ROLLBACK',
  )
  const authorizationConsumed = records.find(
    ({ event }) => event.type === 'AUTHORIZATION_CONSUMED',
  )
  assert.equal(authorizationConsumed.event.dispatch_permit_sha256, 'a'.repeat(64))
  assert.equal(records.some(({ event }) => event.type === 'APPROVAL_CONSUMED'), false)
  assert.ok(cleanupConfirmationIndex >= 0)
  assert.ok(cleanupConfirmationIndex < rollbackPreDispatchIndex)
  assert.deepEqual(cleanupPreDispatches, ['ROLLBACK', 'ROLLBACK_VERIFY'])
  assert.deepEqual(records[cleanupConfirmationIndex].event, {
    type: 'CLEANUP_SESSION_CONFIRMED',
    operator_id: scope.authorization.operator_id,
    authorization_mode: 'OPERATOR_ATTESTED_AUTHED',
    confirmation: 'CLEANUP_ONLY_CONFIRMED',
  })
  assert.equal(records.some(({ event }) => event.type === 'CAMPAIGN_SESSION_CONFIRMED'), false)
})
