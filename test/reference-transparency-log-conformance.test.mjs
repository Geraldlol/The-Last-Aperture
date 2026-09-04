import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import {
  createHash,
  generateKeyPairSync,
  X509Certificate,
} from 'node:crypto'
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { createServer as createHttpsServer } from 'node:https'

import {
  createReferenceTransparencyConsistencyHandler,
  createReferenceTransparencyLogHandler,
} from '../providers/reference-transparency-log/handler.mjs'
import { createReferenceTransparencyHttpsServer } from '../providers/reference-transparency-log/server.mjs'
import { openReferenceTransparencyLogStore } from '../providers/reference-transparency-log/store.mjs'
import { publishTransparencyCommand } from '../scripts/audit.mjs'
import {
  openTransparencyCheckpointJournal,
} from '../scripts/lib/transparency-checkpoint-journal.mjs'
import { contentDigestHeader } from '../scripts/lib/remote-gateway-contracts.mjs'
import { stableJson } from '../scripts/lib/run-engine.mjs'
import {
  createTransparencyConsistencyRequest,
  createTransparencyPublishRequest,
  projectTransparencySignedCheckpoint,
} from '../scripts/lib/transparency-log-contracts.mjs'
import {
  httpsTransparencyLogTransport,
  submitTransparencyConsistencyRequest,
} from '../scripts/lib/transparency-log-client.mjs'
import {
  REFERENCE_TLS_CERTIFICATE,
  REFERENCE_TLS_PASSPHRASE,
  REFERENCE_TLS_PFX,
} from './fixtures/reference-transparency-tls.mjs'

const CLI = resolve('scripts/audit.mjs')
const LOG_HOSTNAME = 'reference-log.example.test'
const LOG_ORIGIN = 'reference-log.example.test/v1'

function ed25519KeyPair() {
  return generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })
}

function tlsSpkiSha256() {
  const certificate = new X509Certificate(REFERENCE_TLS_CERTIFICATE)
  const spki = certificate.publicKey.export({ type: 'spki', format: 'der' })
  return createHash('sha256').update(spki).digest('hex')
}

function loopbackConformanceLookup(hostname, _options, callback) {
  assert.equal(hostname, LOG_HOSTNAME)
  callback(null, '127.0.0.1', 4)
}

async function createTerminalBundle({
  targetDirectory,
  bundleParent,
  rootPrivateKeyPath,
  attestationPath,
  marker,
}) {
  await mkdir(join(targetDirectory, 'src'), { recursive: true })
  await writeFile(
    join(targetDirectory, 'src', 'app.js'),
    `export const marker = ${JSON.stringify(marker)}\n`,
  )
  await writeFile(
    join(targetDirectory, 'package.json'),
    JSON.stringify({ name: `transparency-${marker}`, version: '1.0.0' }),
  )
  execFileSync(
    process.execPath,
    [CLI, 'plan', targetDirectory, '--out', bundleParent],
    { encoding: 'utf8', windowsHide: true },
  )
  const bundles = (await readdir(bundleParent, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory())
  assert.equal(bundles.length, 1)
  const bundle = join(bundleParent, bundles[0].name)
  execFileSync(
    process.execPath,
    [CLI, 'abort', bundle, '--reason', `terminal ${marker} fixture`],
    { encoding: 'utf8', windowsHide: true },
  )
  execFileSync(
    process.execPath,
    [
      CLI,
      'attest',
      bundle,
      '--signing-key',
      rootPrivateKeyPath,
      '--out',
      attestationPath,
    ],
    { encoding: 'utf8', windowsHide: true },
  )
  return bundle
}

async function startLog({
  stateDirectory,
  logPrivateKey,
  auditBundleDirectory,
  trustedCheckpoint,
}) {
  const store = await openReferenceTransparencyLogStore({
    directory: stateDirectory,
    origin: LOG_ORIGIN,
    privateKeyBytes: logPrivateKey,
    auditBundleDirectory,
    ...(trustedCheckpoint === undefined ? {} : { trustedCheckpoint }),
  })
  const handler = createReferenceTransparencyLogHandler({ store })
  const consistencyHandler = createReferenceTransparencyConsistencyHandler({
    store,
  })
  const service = createReferenceTransparencyHttpsServer({
    handler,
    consistencyHandler,
    tls: {
      pfx: REFERENCE_TLS_PFX,
      passphrase: REFERENCE_TLS_PASSPHRASE,
      minVersion: 'TLSv1.2',
    },
  })
  const address = await service.start()
  return { store, service, address }
}

async function startStaticConsistencyServer(body, { truncate = false } = {}) {
  const responseBody = Buffer.from(body)
  const server = createHttpsServer({
    pfx: REFERENCE_TLS_PFX,
    passphrase: REFERENCE_TLS_PASSPHRASE,
    minVersion: 'TLSv1.2',
  }, async (request, response) => {
    try {
      assert.equal(request.method, 'POST')
      assert.equal(request.url, '/v1/consistency')
      for await (const _chunk of request) {
        // Drain the exact client request before producing the test response.
      }
      response.writeHead(200, {
        'content-type': 'application/json',
        'content-length': String(responseBody.length),
        'content-digest': contentDigestHeader(responseBody),
        'cache-control': 'no-store',
        'x-rta-protocol': 'transparency-log-consistency-v1',
        connection: 'close',
      })
      if (!truncate) {
        response.end(responseBody)
        return
      }
      const partial = responseBody.subarray(0, responseBody.length - 16)
      response.write(partial, () => {
        if (response.socket) response.socket.end()
        else response.destroy()
      })
    } catch {
      response.destroy()
    }
  })
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen)
    server.listen({ host: '127.0.0.1', port: 0, exclusive: true }, () => {
      server.off('error', rejectListen)
      resolveListen()
    })
  })
  return {
    port: server.address().port,
    async stop() {
      await new Promise((resolveClose, rejectClose) => {
        server.close((error) => {
          if (error) rejectClose(error)
          else resolveClose()
        })
        server.closeAllConnections?.()
      })
    },
  }
}

async function startTruncatingLog(handler) {
  let observedStatus
  const server = createHttpsServer({
    pfx: REFERENCE_TLS_PFX,
    passphrase: REFERENCE_TLS_PASSPHRASE,
    minVersion: 'TLSv1.2',
  }, async (request, response) => {
    try {
      const chunks = []
      for await (const chunk of request) chunks.push(Buffer.from(chunk))
      const result = await handler({
        method: request.method,
        headers: request.headers,
        body: Buffer.concat(chunks),
      })
      observedStatus = result.statusCode
      response.writeHead(result.statusCode, {
        ...result.headers,
        connection: 'close',
      })
      const partial = result.body.subarray(0, result.body.length - 16)
      response.write(partial, () => {
        if (response.socket) response.socket.end()
        else response.destroy()
      })
    } catch {
      response.destroy()
    }
  })
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen)
    server.listen({ host: '127.0.0.1', port: 0, exclusive: true }, () => {
      server.off('error', rejectListen)
      resolveListen()
    })
  })
  return {
    port: server.address().port,
    observedStatus: () => observedStatus,
    async stop() {
      await new Promise((resolveClose, rejectClose) => {
        server.close((error) => {
          if (error) rejectClose(error)
          else resolveClose()
        })
        server.closeAllConnections?.()
      })
    },
  }
}

function trustedConfiguration({
  port,
  logPublicKeyPath,
  pin = tlsSpkiSha256(),
  consistencyPort,
}) {
  const withConsistency = Number.isSafeInteger(consistencyPort)
  return {
    schema_version: withConsistency ? '1.1.0' : '1.0.0',
    protocol: 'transparency-log-v1',
    log_url: `https://${LOG_HOSTNAME}:${port}/v1/entries`,
    ...(withConsistency
      ? {
          consistency_url:
            `https://${LOG_HOSTNAME}:${consistencyPort}/v1/consistency`,
        }
      : {}),
    log_origin: LOG_ORIGIN,
    log_public_key_path: logPublicKeyPath,
    tls_spki_sha256: pin,
    limits: {
      request_timeout_ms: 5000,
      max_clock_skew_ms: 300000,
      max_request_bytes: 262144,
      max_response_bytes: 262144,
    },
  }
}

function createConformanceTransport(statuses) {
  return async (request) => {
    const response = await httpsTransparencyLogTransport({
      ...request,
      lookup: loopbackConformanceLookup,
      ca: REFERENCE_TLS_CERTIFICATE,
    })
    statuses.push(response.statusCode)
    return response
  }
}

test('real HTTPS log persists, deduplicates, restarts, and verifies offline', async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), 'rta-transparency-e2e-'))
  const targetA = join(temporaryRoot, 'target-a')
  const targetB = join(temporaryRoot, 'target-b')
  const bundleParentA = join(temporaryRoot, 'bundles-a')
  const bundleParentB = join(temporaryRoot, 'bundles-b')
  const trustDirectory = join(temporaryRoot, 'external-trust')
  const stateDirectory = join(temporaryRoot, 'external-log-state')
  const validPrefixStateDirectory = join(
    temporaryRoot,
    'external-log-valid-prefix',
  )
  const forkStateDirectory = join(temporaryRoot, 'external-log-fork')
  const journalDirectory = join(temporaryRoot, 'external-checkpoint-journal')
  await Promise.all([
    mkdir(targetA),
    mkdir(targetB),
    mkdir(bundleParentA),
    mkdir(bundleParentB),
    mkdir(trustDirectory),
  ])

  const rootKeys = ed25519KeyPair()
  const logKeys = ed25519KeyPair()
  const rootPrivateKeyPath = join(trustDirectory, 'root-private.pem')
  const rootPublicKeyPath = join(trustDirectory, 'root-public.pem')
  const logPublicKeyPath = join(trustDirectory, 'log-public.pem')
  const attestationAPath = join(trustDirectory, 'root-attestation-a.json')
  const attestationBPath = join(trustDirectory, 'root-attestation-b.json')
  const configPath = join(trustDirectory, 'log-config.json')
  const badConfigPath = join(trustDirectory, 'wrong-pin-config.json')
  const receiptAPath = join(trustDirectory, 'receipt-a.json')
  const duplicateReceiptPath = join(trustDirectory, 'receipt-a-duplicate.json')
  const receiptBPath = join(trustDirectory, 'receipt-b.json')
  const truncatedReceiptPath = join(trustDirectory, 'receipt-truncated.json')
  const rejectedReceiptPath = join(trustDirectory, 'receipt-rejected.json')
  let running
  let truncatingLog
  let journal
  let forkStore
  let staticConsistencyServer

  try {
    await Promise.all([
      writeFile(rootPrivateKeyPath, rootKeys.privateKey, { mode: 0o600 }),
      writeFile(rootPublicKeyPath, rootKeys.publicKey, { mode: 0o600 }),
      writeFile(logPublicKeyPath, logKeys.publicKey, { mode: 0o600 }),
    ])
    const bundleA = await createTerminalBundle({
      targetDirectory: targetA,
      bundleParent: bundleParentA,
      rootPrivateKeyPath,
      attestationPath: attestationAPath,
      marker: 'alpha',
    })
    const bundleB = await createTerminalBundle({
      targetDirectory: targetB,
      bundleParent: bundleParentB,
      rootPrivateKeyPath,
      attestationPath: attestationBPath,
      marker: 'beta',
    })

    running = await startLog({
      stateDirectory,
      logPrivateKey: logKeys.privateKey,
      auditBundleDirectory: bundleA,
    })
    const firstStore = running.store
    await cp(stateDirectory, validPrefixStateDirectory, {
      recursive: true,
      errorOnExist: true,
      force: false,
    })
    let config = trustedConfiguration({
      port: running.address.port,
      logPublicKeyPath,
    })
    await writeFile(configPath, stableJson(config))

    const attestationA = JSON.parse(await readFile(attestationAPath, 'utf8'))
    const malformedBody = Buffer.from('{}\n', 'utf8')
    const malformedResponse = await httpsTransparencyLogTransport({
      config,
      body: malformedBody,
      headers: {
        'content-type': 'application/json',
        'content-length': String(malformedBody.length),
        'content-digest': contentDigestHeader(malformedBody),
        'x-rta-protocol': 'transparency-log-v1',
      },
      lookup: loopbackConformanceLookup,
      ca: REFERENCE_TLS_CERTIFICATE,
    })
    assert.equal(malformedResponse.statusCode, 400)

    const validRequestBody = Buffer.from(
      stableJson(createTransparencyPublishRequest(attestationA), 0),
      'utf8',
    )
    const digestMismatchResponse = await httpsTransparencyLogTransport({
      config,
      body: validRequestBody,
      headers: {
        'content-type': 'application/json',
        'content-length': String(validRequestBody.length),
        'content-digest': contentDigestHeader(Buffer.from('different')),
        'x-rta-protocol': 'transparency-log-v1',
      },
      lookup: loopbackConformanceLookup,
      ca: REFERENCE_TLS_CERTIFICATE,
    })
    assert.equal(digestMismatchResponse.statusCode, 400)
    const duplicateHeaderResponse = await httpsTransparencyLogTransport({
      config,
      body: validRequestBody,
      headers: {
        'content-type': 'application/json',
        'content-length': String(validRequestBody.length),
        'content-digest': contentDigestHeader(validRequestBody),
        'x-rta-protocol': [
          'transparency-log-v1',
          'transparency-log-v1',
        ],
      },
      lookup: loopbackConformanceLookup,
      ca: REFERENCE_TLS_CERTIFICATE,
    })
    assert.equal(duplicateHeaderResponse.statusCode, 400)
    assert.equal(firstStore.snapshot().tree_size, 0)

    const badConfig = trustedConfiguration({
      port: running.address.port,
      logPublicKeyPath,
      pin: '0'.repeat(64),
    })
    await writeFile(badConfigPath, stableJson(badConfig))
    await assert.rejects(
      publishTransparencyCommand(
        [bundleA, badConfigPath],
        {
          'root-attestation': attestationAPath,
          'root-public-key': rootPublicKeyPath,
          out: rejectedReceiptPath,
        },
        { transparencyTransport: createConformanceTransport([]) },
      ),
      /TLS certificate SPKI does not match/i,
    )
    await assert.rejects(readFile(rejectedReceiptPath), { code: 'ENOENT' })
    assert.equal(firstStore.snapshot().tree_size, 0)

    const statuses = []
    const transport = createConformanceTransport(statuses)
    const firstPublication = await publishTransparencyCommand(
      [bundleA, configPath],
      {
        'root-attestation': attestationAPath,
        'root-public-key': rootPublicKeyPath,
        out: receiptAPath,
      },
      { transparencyTransport: transport },
    )
    assert.equal(statuses.at(-1), 201)
    assert.equal(firstPublication.verification.tree_size, 1)
    assert.equal(firstStore.snapshot().tree_size, 1)

    const checkpointM = projectTransparencySignedCheckpoint(
      firstPublication.receipt,
    )
    journal = await openTransparencyCheckpointJournal({
      directory: journalDirectory,
      expectedOrigin: LOG_ORIGIN,
      publicKeyBytes: logKeys.publicKey,
      targetDirectory: targetA,
      auditBundleDirectory: bundleA,
      logStateDirectory: stateDirectory,
      maxClockSkewMs: 300000,
    })
    const anchoredM = await journal.advance({ checkpoint: checkpointM })
    assert.equal(anchoredM.created, true)
    assert.equal(anchoredM.sequence, 0)
    const baselineContinuity = await journal.continuityForCheckpoint(
      checkpointM,
    )
    assert.equal(baselineContinuity.status, 'NOT_VERIFIED')
    assert.equal(baselineContinuity.claim, 'CHECKPOINT_BASELINE_ONLY')

    await running.service.stop()
    await cp(stateDirectory, forkStateDirectory, {
      recursive: true,
      errorOnExist: true,
      force: false,
    })
    truncatingLog = await startTruncatingLog(
      createReferenceTransparencyLogHandler({ store: firstStore }),
    )
    config.log_url = `https://${LOG_HOSTNAME}:${truncatingLog.port}/v1/entries`
    await writeFile(configPath, stableJson(config))
    await assert.rejects(
      publishTransparencyCommand(
        [bundleB, configPath],
        {
          'root-attestation': attestationBPath,
          'root-public-key': rootPublicKeyPath,
          out: truncatedReceiptPath,
        },
        { transparencyTransport: transport },
      ),
      (error) => {
        assert.equal(error.code, 'TRANSPARENCY_LOG_RESPONSE_TRUNCATED')
        return true
      },
    )
    assert.equal(truncatingLog.observedStatus(), 201)
    assert.equal(firstStore.snapshot().tree_size, 2)
    await assert.rejects(readFile(truncatedReceiptPath), { code: 'ENOENT' })
    await truncatingLog.stop()
    truncatingLog = undefined
    await running.store.close()
    running = await startLog({
      stateDirectory,
      logPrivateKey: logKeys.privateKey,
      auditBundleDirectory: bundleA,
    })
    assert.notEqual(running.store, firstStore)
    assert.equal(running.store.snapshot().tree_size, 2)
    config = trustedConfiguration({
      port: running.address.port,
      consistencyPort: running.address.port,
      logPublicKeyPath,
    })
    await writeFile(configPath, stableJson(config))

    const duplicatePublication = await publishTransparencyCommand(
      [bundleA, configPath],
      {
        'root-attestation': attestationAPath,
        'root-public-key': rootPublicKeyPath,
        out: duplicateReceiptPath,
      },
      { transparencyTransport: transport },
    )
    assert.equal(statuses.at(-1), 200)
    assert.equal(duplicatePublication.verification.tree_size, 2)
    assert.equal(running.store.snapshot().tree_size, 2)

    const secondPublication = await publishTransparencyCommand(
      [bundleB, configPath],
      {
        'root-attestation': attestationBPath,
        'root-public-key': rootPublicKeyPath,
        out: receiptBPath,
      },
      { transparencyTransport: transport },
    )
    assert.equal(statuses.at(-1), 200)
    assert.equal(secondPublication.verification.tree_size, 2)
    assert.equal(running.store.snapshot().tree_size, 2)

    const checkpointN = projectTransparencySignedCheckpoint(
      duplicatePublication.receipt,
    )
    const consistencyRequest = createTransparencyConsistencyRequest({
      firstSize: checkpointM.checkpoint.tree_size,
      secondSize: checkpointN.checkpoint.tree_size,
    })
    const consistencyStatuses = []
    const consistencyResult = await submitTransparencyConsistencyRequest({
      config,
      requestDocument: consistencyRequest,
      logPublicKeyBytes: logKeys.publicKey,
      expectedFirstCheckpoint: checkpointM,
      expectedSecondCheckpoint: checkpointN,
      transport: createConformanceTransport(consistencyStatuses),
    })
    assert.equal(consistencyStatuses.at(-1), 200)
    assert.equal(
      consistencyResult.verification.relation,
      'APPEND_ONLY_EXTENSION',
    )

    forkStore = await openReferenceTransparencyLogStore({
      directory: forkStateDirectory,
      origin: LOG_ORIGIN,
      privateKeyBytes: logKeys.privateKey,
      auditBundleDirectory: bundleA,
    })
    const attestationB = JSON.parse(await readFile(attestationBPath, 'utf8'))
    const forkAttestation = structuredClone(attestationB)
    const replacement = forkAttestation.signature.startsWith('A') ? 'B' : 'A'
    forkAttestation.signature = `${replacement}${forkAttestation.signature.slice(1)}`
    await forkStore.publish(createTransparencyPublishRequest(forkAttestation))
    const forkProof = await forkStore.proveConsistency(consistencyRequest)
    assert.notEqual(
      forkProof.second_checkpoint.checkpoint.root_hash,
      checkpointN.checkpoint.root_hash,
    )
    await forkStore.close()
    forkStore = undefined

    staticConsistencyServer = await startStaticConsistencyServer(
      Buffer.from(stableJson(forkProof, 0), 'utf8'),
    )
    const forkConfig = trustedConfiguration({
      port: staticConsistencyServer.port,
      consistencyPort: staticConsistencyServer.port,
      logPublicKeyPath,
    })
    await assert.rejects(
      submitTransparencyConsistencyRequest({
        config: forkConfig,
        requestDocument: consistencyRequest,
        logPublicKeyBytes: logKeys.publicKey,
        expectedFirstCheckpoint: checkpointM,
        expectedSecondCheckpoint: checkpointN,
        transport: createConformanceTransport([]),
      }),
      /second checkpoint does not match/i,
    )
    assert.equal((await journal.load()).record_count, 1)
    await staticConsistencyServer.stop()
    staticConsistencyServer = undefined

    const invalidProof = structuredClone(consistencyResult.proof)
    assert.ok(invalidProof.consistency_path.length > 0)
    invalidProof.consistency_path[0] = '0'.repeat(64)
    staticConsistencyServer = await startStaticConsistencyServer(
      Buffer.from(stableJson(invalidProof, 0), 'utf8'),
    )
    const invalidConfig = trustedConfiguration({
      port: staticConsistencyServer.port,
      consistencyPort: staticConsistencyServer.port,
      logPublicKeyPath,
    })
    await assert.rejects(
      submitTransparencyConsistencyRequest({
        config: invalidConfig,
        requestDocument: consistencyRequest,
        logPublicKeyBytes: logKeys.publicKey,
        expectedFirstCheckpoint: checkpointM,
        expectedSecondCheckpoint: checkpointN,
        transport: createConformanceTransport([]),
      }),
      /consistency path does not prove|checkpoint roots/i,
    )
    assert.equal((await journal.load()).record_count, 1)
    await staticConsistencyServer.stop()
    staticConsistencyServer = undefined

    staticConsistencyServer = await startStaticConsistencyServer(
      Buffer.from(stableJson(consistencyResult.proof, 0), 'utf8'),
      { truncate: true },
    )
    const truncatedConfig = trustedConfiguration({
      port: staticConsistencyServer.port,
      consistencyPort: staticConsistencyServer.port,
      logPublicKeyPath,
    })
    await assert.rejects(
      submitTransparencyConsistencyRequest({
        config: truncatedConfig,
        requestDocument: consistencyRequest,
        logPublicKeyBytes: logKeys.publicKey,
        expectedFirstCheckpoint: checkpointM,
        expectedSecondCheckpoint: checkpointN,
        transport: createConformanceTransport([]),
      }),
      (error) => {
        assert.equal(error.code, 'TRANSPARENCY_LOG_RESPONSE_TRUNCATED')
        return true
      },
    )
    assert.equal((await journal.load()).record_count, 1)
    await staticConsistencyServer.stop()
    staticConsistencyServer = undefined

    const anchoredN = await journal.advance({
      expectedHead: checkpointM,
      checkpoint: checkpointN,
      consistencyProof: consistencyResult.proof,
    })
    assert.equal(anchoredN.created, true)
    assert.equal(anchoredN.sequence, 1)
    assert.equal(journal.snapshot().record_count, 2)

    await running.service.stop()
    await running.store.close()
    running = undefined

    const offlineContinuity = await journal.continuityForCheckpoint(
      checkpointN,
    )
    assert.equal(offlineContinuity.status, 'VERIFIED')
    assert.equal(
      offlineContinuity.claim,
      'CONSISTENT_WITH_EXTERNALLY_RETAINED_CHECKPOINT',
    )
    assert.equal(offlineContinuity.baseline_tree_size, 1)
    assert.equal(offlineContinuity.current_tree_size, 2)
    await journal.close()
    journal = undefined

    const offline = execFileSync(
      process.execPath,
      [
        CLI,
        'validate',
        bundleA,
        '--root-attestation',
        attestationAPath,
        '--root-public-key',
        rootPublicKeyPath,
        '--transparency-receipt',
        receiptAPath,
        '--transparency-log-public-key',
        logPublicKeyPath,
        '--transparency-log-origin',
        LOG_ORIGIN,
      ],
      { encoding: 'utf8', windowsHide: true },
    )
    assert.match(offline, /Root signature: VERIFIED WITH SUPPLIED KEY/)
    assert.match(
      offline,
      /Transparency inclusion: VERIFIED \(reference-log\.example\.test\/v1, tree 1, leaf 0\)/,
    )

    const offlineAnchored = execFileSync(
      process.execPath,
      [
        CLI,
        'validate',
        bundleA,
        '--root-attestation',
        attestationAPath,
        '--root-public-key',
        rootPublicKeyPath,
        '--transparency-receipt',
        duplicateReceiptPath,
        '--transparency-log-public-key',
        logPublicKeyPath,
        '--transparency-log-origin',
        LOG_ORIGIN,
        '--transparency-checkpoint-journal',
        journalDirectory,
      ],
      { encoding: 'utf8', windowsHide: true },
    )
    assert.match(offlineAnchored, /Root signature: VERIFIED WITH SUPPLIED KEY/)
    assert.match(
      offlineAnchored,
      /Transparency inclusion: VERIFIED \(reference-log\.example\.test\/v1, tree 2, leaf 0\)/,
    )
    assert.match(
      offlineAnchored,
      /Checkpoint continuity: CONSISTENT_WITH_EXTERNALLY_RETAINED_CHECKPOINT/,
    )

    await assert.rejects(
      startLog({
        stateDirectory: validPrefixStateDirectory,
        logPrivateKey: logKeys.privateKey,
        auditBundleDirectory: bundleA,
        trustedCheckpoint: checkpointM,
      }),
      (error) => {
        assert.equal(
          error.code,
          'REFERENCE_TRANSPARENCY_EXTERNAL_CHECKPOINT_ROLLBACK',
        )
        return true
      },
    )
  } finally {
    await staticConsistencyServer?.stop().catch(() => {})
    await forkStore?.close().catch(() => {})
    await journal?.close().catch(() => {})
    await truncatingLog?.stop().catch(() => {})
    await running?.service.stop().catch(() => {})
    await running?.store.close().catch(() => {})
    await rm(temporaryRoot, { recursive: true, force: true })
  }
})

test('real HTTPS adapter treats post-request dependency failures as internal', async () => {
  const service = createReferenceTransparencyHttpsServer({
    handler: async () => {
      const error = new Error('synthetic invalid store receipt')
      error.code = 'TRANSPARENCY_LOG_CONTRACT_INVALID'
      throw error
    },
    tls: {
      pfx: REFERENCE_TLS_PFX,
      passphrase: REFERENCE_TLS_PASSPHRASE,
    },
  })
  try {
    const address = await service.start()
    const config = trustedConfiguration({
      port: address.port,
      logPublicKeyPath: resolve('external-test-log-public.pem'),
    })
    const body = Buffer.from('{}\n', 'utf8')
    const response = await httpsTransparencyLogTransport({
      config,
      body,
      headers: {
        'content-type': 'application/json',
        'content-length': String(body.length),
        'content-digest': contentDigestHeader(body),
        'x-rta-protocol': 'transparency-log-v1',
      },
      lookup: loopbackConformanceLookup,
      ca: REFERENCE_TLS_CERTIFICATE,
    })
    assert.equal(response.statusCode, 500)
    assert.equal(JSON.parse(response.body.toString('utf8')).error.code, 'INTERNAL_LOG_FAILURE')
  } finally {
    await service.stop()
  }
})

test('HTTPS adapter requires external TLS material and a modern protocol floor', () => {
  const handler = async () => ({ statusCode: 204, headers: {}, body: Buffer.alloc(0) })
  assert.throws(
    () => createReferenceTransparencyHttpsServer({ handler, tls: {} }),
    /requires external TLS key\/certificate material/i,
  )
  assert.throws(
    () => createReferenceTransparencyHttpsServer({
      handler,
      tls: {
        pfx: REFERENCE_TLS_PFX,
        passphrase: REFERENCE_TLS_PASSPHRASE,
        minVersion: 'TLSv1.1',
      },
    }),
    /minimum TLS version must be TLSv1\.2 or TLSv1\.3/i,
  )
})
