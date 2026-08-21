import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { access, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import {
  runHttpAuthedAttestedCampaign,
  runHttpAuthedWrittenCampaign,
} from '../scripts/lib/http-authed-campaign-runtime.mjs'
import { openHttpAuthedCampaignLedger } from '../scripts/lib/http-authed-campaign-ledger.mjs'
import { main as httpAuthedMain } from '../scripts/http-authed.mjs'
import {
  buildActionCountersignaturePayload,
  canonicalJson,
  httpAuthedCampaignLedgerBindingSha256,
  OPERATOR_ATTESTED_AUTHED_STATEMENT,
  sha256Hex,
  signHttpAuthedActionCountersignature,
  verifyHttpAuthedAuthorization,
  verifyHttpAuthedWrittenAuthorization,
} from '../scripts/lib/http-authed-contracts.mjs'
import {
  AUTHORIZATION_DOCUMENT,
  writtenScope,
} from './helpers/http-authed-fixtures.mjs'

const NOW = new Date('2026-08-16T12:00:00.000Z')
const CREDENTIAL = 'synthetic-runtime-credential'

test('written campaign runtime binds protected transport, discovery, and durable ledger', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-runtime-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const scope = writtenScope({ actionCount: 1 })
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
  const verified = verifyHttpAuthedWrittenAuthorization({
    scope,
    documentBytes: AUTHORIZATION_DOCUMENT,
    now: NOW,
  })
  const scopePath = join(root, 'scope.json')
  const documentPath = join(root, 'authorization.txt')
  const ledgerDirectory = join(root, 'ledger')
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  await writeFile(documentPath, AUTHORIZATION_DOCUMENT)
  const calls = []

  const result = await runHttpAuthedWrittenCampaign({
    scopePath,
    authorizationDocumentPath: documentPath,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    ledgerDirectory,
    operatorId: scope.authorization.operator_id,
    authorizationConfirmed: true,
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

  const replay = await runHttpAuthedWrittenCampaign({
    scopePath,
    authorizationDocumentPath: documentPath,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    ledgerDirectory,
    operatorId: scope.authorization.operator_id,
    authorizationConfirmed: true,
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

test('written campaign runtime dispatches a browser-held scope without exported credentials', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-browser-runtime-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const scope = writtenScope({ actionCount: 1 })
  scope.limits.min_interval_ms = 0
  scope.credential = {
    mode: 'CHROME_ACTIVE_TAB_SESSION',
    extension_id: 'abcdefghijklmnopabcdefghijklmnop',
    origin: scope.target.origin,
  }
  scope.authorization.permissions.mutation = false
  delete scope.approver
  scope.requests = [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'GET',
    url: `${scope.target.origin}/browser-session-probe`,
    expected_effect: 'none',
  }]
  const verified = verifyHttpAuthedWrittenAuthorization({
    scope,
    documentBytes: AUTHORIZATION_DOCUMENT,
    now: NOW,
  })
  const scopePath = join(root, 'scope.json')
  const documentPath = join(root, 'authorization.txt')
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  await writeFile(documentPath, AUTHORIZATION_DOCUMENT)
  let sends = 0

  const result = await runHttpAuthedWrittenCampaign({
    scopePath,
    authorizationDocumentPath: documentPath,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    ledgerDirectory: join(root, 'ledger'),
    operatorId: scope.authorization.operator_id,
    authorizationConfirmed: true,
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

test('written campaign runtime requires an explicit matching browser execution mode', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-browser-mode-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const scope = writtenScope({ actionCount: 1 })
  scope.credential = {
    mode: 'CHROME_ACTIVE_TAB_SESSION',
    extension_id: 'abcdefghijklmnopabcdefghijklmnop',
    origin: scope.target.origin,
  }
  const verified = verifyHttpAuthedWrittenAuthorization({
    scope,
    documentBytes: AUTHORIZATION_DOCUMENT,
    now: NOW,
  })
  const scopePath = join(root, 'scope.json')
  const documentPath = join(root, 'authorization.txt')
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  await writeFile(documentPath, AUTHORIZATION_DOCUMENT)
  let sends = 0

  await assert.rejects(
    runHttpAuthedWrittenCampaign({
      scopePath,
      authorizationDocumentPath: documentPath,
      expectedCampaignGrantSha256: verified.campaignGrantSha256,
      ledgerDirectory: join(root, 'ledger'),
      operatorId: scope.authorization.operator_id,
      authorizationConfirmed: true,
      clock: () => NOW,
      protectedTransport: async () => { sends += 1 },
    }),
    (error) => error.code === 'HTTP_AUTHED_BROWSER_MODE_MISMATCH',
  )
  assert.equal(sends, 0)
})

test('browser campaign attaches once before opening its ledger and closes its bridge', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-browser-attach-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const scope = writtenScope({ actionCount: 1 })
  scope.limits.min_interval_ms = 0
  scope.credential = {
    mode: 'CHROME_ACTIVE_TAB_SESSION',
    extension_id: 'abcdefghijklmnopabcdefghijklmnop',
    origin: scope.target.origin,
  }
  scope.authorization.permissions.mutation = false
  delete scope.approver
  scope.requests = [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'GET',
    url: `${scope.target.origin}/browser-session-probe`,
    expected_effect: 'none',
  }]
  const verified = verifyHttpAuthedWrittenAuthorization({
    scope,
    documentBytes: AUTHORIZATION_DOCUMENT,
    now: NOW,
  })
  const scopePath = join(root, 'scope.json')
  const documentPath = join(root, 'authorization.txt')
  const ledgerDirectory = join(root, 'ledger')
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  await writeFile(documentPath, AUTHORIZATION_DOCUMENT)
  let attached = 0
  let closed = 0
  let pairing

  const result = await runHttpAuthedWrittenCampaign({
    scopePath,
    authorizationDocumentPath: documentPath,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    ledgerDirectory,
    operatorId: scope.authorization.operator_id,
    authorizationConfirmed: true,
    browserSessionRequested: true,
    clock: () => NOW,
    browserTransportFactory: async (configuration) => {
      assert.equal(configuration.extensionId, scope.credential.extension_id)
      assert.equal(configuration.targetOrigin, scope.target.origin)
      assert.equal(configuration.campaignGrantSha256, verified.campaignGrantSha256)
      return {
        pairing: { port: 43123, capability: 'x'.repeat(43) },
        waitForAttach: async () => {
          await assert.rejects(access(ledgerDirectory), { code: 'ENOENT' })
          attached += 1
        },
        transport: async (request) => {
          await request.beforeSend()
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
  assert.equal(result.actions.completed, 1)
})

test('campaign-written CLI exposes the ledger-backed campaign without sensitive output', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-runtime-cli-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const scope = writtenScope({ actionCount: 1 })
  scope.limits.min_interval_ms = 0
  scope.credential.binding_sha256 = sha256Hex(Buffer.from(CREDENTIAL))
  scope.requests = [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'PROPFIND',
    url: `${scope.target.origin}/SENSITIVE_SYNTHETIC_ROUTE`,
    expected_effect: 'none',
  }]
  scope.authorization.authorized_scope.methods.push('PROPFIND')
  const verified = verifyHttpAuthedWrittenAuthorization({
    scope,
    documentBytes: AUTHORIZATION_DOCUMENT,
    now: NOW,
  })
  const scopePath = join(root, 'scope.json')
  const documentPath = join(root, 'authorization.txt')
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  await writeFile(documentPath, AUTHORIZATION_DOCUMENT)
  let output = ''
  let sends = 0

  await httpAuthedMain([
    'campaign-written',
    '--scope', scopePath,
    '--authorization-document', documentPath,
    '--campaign-grant-sha256', verified.campaignGrantSha256,
    '--ledger', join(root, 'ledger'),
    '--operator-id', scope.authorization.operator_id,
    '--confirm-authorization-current',
    '--json',
  ], {
    clock: () => NOW,
    env: { SYNTHETIC_TEST_CREDENTIAL: CREDENTIAL },
    transport: async (request) => {
      await request.beforeSend()
      sends += 1
      return { status: 207, responseBytes: 0, responseHeaderNames: ['set-cookie'] }
    },
    write: (value) => { output += value },
  })

  assert.equal(sends, 1)
  assert.equal(JSON.parse(output).actions.completed, 1)
  assert.doesNotMatch(output, /SENSITIVE_SYNTHETIC_ROUTE|peerstar-test|credential|set-cookie/i)
})

test('campaign-written CLI pairs one Chrome-held session without cookie input', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-browser-cli-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const scope = writtenScope({ actionCount: 1 })
  scope.limits.min_interval_ms = 0
  scope.credential = {
    mode: 'CHROME_ACTIVE_TAB_SESSION',
    extension_id: 'abcdefghijklmnopabcdefghijklmnop',
    origin: scope.target.origin,
  }
  scope.authorization.permissions.mutation = false
  delete scope.approver
  scope.requests = [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'GET',
    url: `${scope.target.origin}/browser-session-probe`,
    expected_effect: 'none',
  }]
  const verified = verifyHttpAuthedWrittenAuthorization({
    scope,
    documentBytes: AUTHORIZATION_DOCUMENT,
    now: NOW,
  })
  const scopePath = join(root, 'scope.json')
  const documentPath = join(root, 'authorization.txt')
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  await writeFile(documentPath, AUTHORIZATION_DOCUMENT)
  let output = ''
  let pairingOutput = ''
  let attached = 0

  await httpAuthedMain([
    'campaign-written',
    '--scope', scopePath,
    '--authorization-document', documentPath,
    '--campaign-grant-sha256', verified.campaignGrantSha256,
    '--ledger', join(root, 'ledger'),
    '--operator-id', scope.authorization.operator_id,
    '--confirm-authorization-current',
    '--credential-browser',
    '--json',
  ], {
    clock: () => NOW,
    browserTransportFactory: async () => ({
      pairing: {
        bridge_origin: 'http://127.0.0.1:43123',
        pairing_code: 'p'.repeat(43),
        target_origin: scope.target.origin,
        campaign_grant_sha256: verified.campaignGrantSha256,
      },
      waitForAttach: async () => { attached += 1 },
      transport: async (request) => {
        await request.beforeSend()
        return { status: 200, responseBytes: 0, responseHeaderNames: [] }
      },
      close: async () => {},
    }),
    browserPairingWrite: (value) => { pairingOutput += value },
    write: (value) => { output += value },
  })

  assert.equal(attached, 1)
  assert.equal(JSON.parse(output).actions.completed, 1)
  assert.match(pairingOutput, /controller port: 43123/)
  assert.match(pairingOutput, /one-time pairing capability: p{43}/)
  assert.match(pairingOutput, new RegExp(verified.campaignGrantSha256))
  assert.doesNotMatch(output, /p{43}|cookie|browser-session-probe/i)
})

test('written campaign runtime executes a signed reversible mutation over protected transport', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-runtime-mutation-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const materials = join(root, 'materials')
  await mkdir(materials)
  const mutationBody = Buffer.alloc(64, 0x6d)
  const rollbackBody = Buffer.alloc(64, 0x72)
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const publicDer = publicKey.export({ type: 'spki', format: 'der' })
  const scope = writtenScope({ actionCount: 1 })
  scope.limits.min_interval_ms = 0
  scope.credential.binding_sha256 = sha256Hex(Buffer.from(CREDENTIAL))
  scope.approver = {
    mechanism: 'ed25519_file',
    key_id: `ed25519:${sha256Hex(publicDer)}`,
    public_key: { format: 'spki_der_b64', value_base64: publicDer.toString('base64') },
    enrollment: {
      enrolled_by: 'Independent synthetic approver',
      enrolled_at: '2026-04-15T12:00:00.000Z',
      provenance: 'Synthetic test-only approver enrollment',
    },
  }
  scope.requests[0].request_body.sha256 = sha256Hex(mutationBody)
  scope.requests[0].rollback.request_body.sha256 = sha256Hex(rollbackBody)
  const valueDigest = (value) => sha256Hex(Buffer.from(canonicalJson(value), 'utf8'))
  scope.requests[0].expected_mutation.before_digest = valueDigest('BEFORE_SENTINEL')
  scope.requests[0].expected_mutation.after_digest = valueDigest('AFTER_SENTINEL')
  scope.requests[0].rollback.expected_after_digest = valueDigest('BEFORE_SENTINEL')
  const verified = verifyHttpAuthedWrittenAuthorization({
    scope,
    documentBytes: AUTHORIZATION_DOCUMENT,
    now: NOW,
  })
  const ledgerDirectory = join(root, 'ledger')
  const payload = buildActionCountersignaturePayload({
    action: scope.requests[0],
    planSha256: verified.campaignGrantSha256,
    campaignLedgerSha256: httpAuthedCampaignLedgerBindingSha256(ledgerDirectory),
    nonce: 'synthetic-runtime-mutation-nonce-0001',
    at: NOW.toISOString(),
  })
  const countersignature = signHttpAuthedActionCountersignature({
    payload,
    privateKeyBytes: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  })
  const bodyPath = (metadata) => join(
    materials,
    `body-${sha256Hex(Buffer.from(metadata.body_id, 'utf8'))}.bin`,
  )
  await Promise.all([
    writeFile(bodyPath(scope.requests[0].request_body), mutationBody),
    writeFile(bodyPath(scope.requests[0].rollback.request_body), rollbackBody),
    writeFile(join(materials, 'countersignature-1.json'), JSON.stringify(countersignature)),
  ])
  const scopePath = join(root, 'scope.json')
  const documentPath = join(root, 'authorization.txt')
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  await writeFile(documentPath, AUTHORIZATION_DOCUMENT)
  const bodies = [
    Buffer.alloc(0),
    Buffer.from('{"synthetic_marker":"BEFORE_SENTINEL","stable":"SAME"}'),
    Buffer.alloc(0),
    Buffer.from('{"synthetic_marker":"AFTER_SENTINEL","stable":"SAME"}'),
    Buffer.alloc(0),
    Buffer.from('{"synthetic_marker":"BEFORE_SENTINEL","stable":"SAME"}'),
  ]
  let call = 0

  const result = await runHttpAuthedWrittenCampaign({
    scopePath,
    authorizationDocumentPath: documentPath,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    ledgerDirectory,
    materialsDirectory: materials,
    operatorId: scope.authorization.operator_id,
    authorizationConfirmed: true,
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
})

test('written runtime restarts an interrupted mutation after action expiry in cleanup-only mode', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-http-authed-runtime-recovery-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const materials = join(root, 'materials')
  await mkdir(materials)
  const scope = writtenScope({ actionCount: 1 })
  scope.validity.cleanup_not_after = '2026-08-16T12:10:00.000Z'
  scope.limits.min_interval_ms = 0
  scope.credential.binding_sha256 = sha256Hex(Buffer.from(CREDENTIAL))
  const rollbackBody = Buffer.alloc(64, 0x72)
  scope.requests[0].rollback.request_body.sha256 = sha256Hex(rollbackBody)
  const beforeDigest = sha256Hex(Buffer.from(canonicalJson('BEFORE_SENTINEL'), 'utf8'))
  scope.requests[0].expected_mutation.before_digest = beforeDigest
  scope.requests[0].rollback.expected_after_digest = beforeDigest
  const verified = verifyHttpAuthedWrittenAuthorization({
    scope,
    documentBytes: AUTHORIZATION_DOCUMENT,
    now: NOW,
  })
  const ledgerDirectory = join(root, 'ledger')
  const interrupted = await openHttpAuthedCampaignLedger({
    directory: ledgerDirectory,
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationDocumentSha256: verified.authorizationDocumentSha256,
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
  await interrupted.consumeApproval({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    nonce: 'synthetic-runtime-recovery-nonce-0001',
    countersignatureBindingSha256: 'a'.repeat(64),
  })
  await interrupted.markPreDispatch({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'MUTATION',
    requestBindingSha256: 'b'.repeat(64),
  })
  await interrupted.close()

  const scopePath = join(root, 'scope.json')
  const documentPath = join(root, 'authorization.txt')
  const rollbackPath = join(
    materials,
    `body-${sha256Hex(Buffer.from(scope.requests[0].rollback.request_body.body_id, 'utf8'))}.bin`,
  )
  await Promise.all([
    writeFile(scopePath, JSON.stringify(scope), 'utf8'),
    writeFile(documentPath, AUTHORIZATION_DOCUMENT),
    writeFile(rollbackPath, rollbackBody),
  ])
  const methods = []
  const result = await runHttpAuthedWrittenCampaign({
    scopePath,
    authorizationDocumentPath: documentPath,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    ledgerDirectory,
    materialsDirectory: materials,
    operatorId: scope.authorization.operator_id,
    authorizationConfirmed: true,
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
  assert.ok(cleanupConfirmationIndex >= 0)
  assert.ok(cleanupConfirmationIndex < rollbackPreDispatchIndex)
  assert.deepEqual(records[cleanupConfirmationIndex].event, {
    type: 'CLEANUP_SESSION_CONFIRMED',
    operator_id: scope.authorization.operator_id,
    authorization_mode: 'WRITTEN_AUTHORIZATION_AUTHED',
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
  const scope = writtenScope({ actionCount: 1 })
  scope.authorization.mode = 'OPERATOR_ATTESTED_AUTHED'
  scope.authorization.statement = OPERATOR_ATTESTED_AUTHED_STATEMENT
  scope.authorization.attested_at = NOW.toISOString()
  delete scope.authorization.written_authorization_sha256
  delete scope.authorization.document_issuer
  delete scope.authorization.document_issued_at
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
  await interrupted.consumeApproval({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    nonce: 'synthetic-attested-recovery-nonce-0001',
    countersignatureBindingSha256: 'a'.repeat(64),
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
    authorizationConfirmed: true,
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
