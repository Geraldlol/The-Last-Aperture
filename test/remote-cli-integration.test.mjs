import { createHash, generateKeyPairSync } from 'node:crypto'
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  main,
  runRemoteCommand,
  verifyControlBundle,
} from '../scripts/audit.mjs'
import { createReferenceRemoteGateway } from '../providers/reference-remote-gateway/gateway.mjs'
import { normalizePolicy } from '../scripts/lib/policy.mjs'
import {
  createRunPlan,
  stableJson,
  writeRunPlanBundle,
} from '../scripts/lib/run-engine.mjs'
import { hashAttemptEvent } from '../scripts/lib/attempts.mjs'

const NOW = new Date('2026-07-30T18:01:00.000Z')
const SHA_A = 'a'.repeat(64)
const TRANSFORM = {
  id: 'transform:remote-cli-fixture',
  sha256: 'b'.repeat(64),
}

test('public run-remote refuses before reading caller-selected bundle or gateway files', async () => {
  await assert.rejects(
    () => main(['run-remote', 'missing-bundle', 'missing-gateway-config.json']),
    (error) => {
      assert.equal(error.code, 'REMOTE_GATEWAY_ENROLLMENT_REQUIRED')
      assert.match(error.message, /disabled before bundle or configuration access/i)
      return true
    },
  )
})

function remotePolicy(root) {
  return normalizePolicy({
    schema_version: '1.0',
    policy_id: 'remote-cli-fixture',
    mode: 'remote_static',
    workspace_root: root,
    capabilities: {
      read_file: { enabled: true, roots: ['.'] },
      write_file: { enabled: false, roots: [] },
      execute: { enabled: false, commands: [] },
      network: {
        enabled: true,
        destinations: [{
          scheme: 'https',
          host: 'gateway.example.test',
          ports: [443],
          path_prefix: '/v1/audit',
        }],
      },
    },
  }, {
    workspaceRoot: root,
    policySource: 'external',
  })
}

function remoteConfig(controllerKeyPath, gatewayKeyPath) {
  return {
    schema_version: '1.0.0',
    protocol: 'remote-gateway-v1',
    gateway_url: 'https://gateway.example.test/v1/audit',
    controller_signing_private_key_path: controllerKeyPath,
    gateway_public_key_path: gatewayKeyPath,
    tls_spki_sha256: SHA_A,
    prompt_transform: TRANSFORM,
    limits: {
      request_timeout_ms: 10_000,
      request_ttl_ms: 30_000,
      max_clock_skew_ms: 1_000,
      max_request_bytes: 8 * 1024 * 1024,
      max_response_bytes: 1024 * 1024,
      max_artifacts: 256,
      max_file_bytes: 1024 * 1024,
      max_total_artifact_bytes: 4 * 1024 * 1024,
    },
  }
}

test('run-remote durably binds one signed request and gateway acceptance', async () => {
  const root = await mkdtemp(join(tmpdir(), 'rta-remote-target-'))
  const output = await mkdtemp(join(tmpdir(), 'rta-remote-output-'))
  try {
    await mkdir(join(root, 'src'))
    await writeFile(
      join(root, 'src', 'app.js'),
      'export const remotelyReviewed = true\n',
    )
    await writeFile(
      join(root, 'src', 'replacement-\uFFFD.js'),
      'export const replacementNamedFile = true\n',
    )
    await writeFile(
      join(root, 'package.json'),
      '{"name":"remote-cli-fixture","type":"module"}\n',
    )
    const plan = await createRunPlan({
      targetRoot: root,
      lensDirectory: resolve('skills/last-aperture/lenses'),
      policy: remotePolicy(root),
      sealSource: true,
      createdAt: new Date('2026-07-30T18:00:00.000Z'),
    })
    const written = await writeRunPlanBundle(plan, join(output, 'bundles'))

    const controller = generateKeyPairSync('ed25519')
    const gateway = generateKeyPairSync('ed25519')
    const controllerKeyPath = join(output, 'controller-private.pem')
    const gatewayKeyPath = join(output, 'gateway-public.pem')
    const configPath = join(output, 'remote-config.json')
    await writeFile(
      controllerKeyPath,
      controller.privateKey.export({ type: 'pkcs8', format: 'pem' }),
      { mode: 0o600 },
    )
    await writeFile(
      gatewayKeyPath,
      gateway.publicKey.export({ type: 'spki', format: 'pem' }),
    )
    await writeFile(
      configPath,
      stableJson(remoteConfig(controllerKeyPath, gatewayKeyPath)),
    )

    let providerCalls = 0
    const gatewayHandler = createReferenceRemoteGateway({
      controllerPublicKeyBytes: controller.publicKey.export({
        type: 'spki',
        format: 'pem',
      }),
      gatewayPrivateKeyBytes: gateway.privateKey.export({
        type: 'pkcs8',
        format: 'pem',
      }),
      promptTransform: TRANSFORM,
      maxClockSkewMs: 1_000,
      maxRequestTtlMs: 30_000,
      provider: async ({ packet, artifacts }) => {
        providerCalls += 1
        if (providerCalls === 1) {
          throw new Error('ambiguous upstream fixture failure')
        }
        const upstreamRequestBytes = Buffer.from(stableJson({
          packet_sha256: packet.packet_sha256,
          artifact_sha256: artifacts.map(({ sha256 }) => sha256),
          transform: TRANSFORM,
        }, 0), 'utf8')
        return {
          upstreamRequestBytes,
          jobResult: {
            schema_version: '1.0.0',
            run_id: packet.run_id,
            job_id: packet.job_id,
            input_sha256: packet.packet_sha256,
            producer: {
              name: 'remote-cli-fixture',
              version: '1.0.0',
              instance_id: 'remote:cli-fixture',
            },
            state: 'SUCCEEDED',
            examined_files: artifacts
              .filter(({ kind }) => kind === 'FILE')
              .map(({ logical_name: logicalName }) => logicalName),
            findings: [],
            coverage_gaps: [],
          },
        }
      },
    })

    const dependencies = {
      now: () => new Date(NOW),
      transport: ({ body, headers }) => gatewayHandler({
        body,
        headers,
        now: new Date(NOW),
      }),
    }
    await assert.rejects(
      () => runRemoteCommand(
        [written.directory, configPath],
        {},
        dependencies,
      ),
      /ambiguous upstream fixture failure/,
    )
    const afterFailure = JSON.parse(await readFile(written.runPath, 'utf8'))
    const failed = afterFailure.attempt_events.find(
      ({ event }) => event === 'FAILED',
    )
    assert.equal(failed.recoverable, true)
    assert.equal(afterFailure.jobs[0].state, 'PENDING')

    await runRemoteCommand(
      [written.directory, configPath],
      {},
      dependencies,
    )

    assert.equal(providerCalls, 2)
    const run = JSON.parse(await readFile(written.runPath, 'utf8'))
    const leases = run.attempt_events.filter(({ event }) => event === 'LEASED')
    assert.equal(leases.length, 2)
    assert.notEqual(leases[0].request_id, leases[1].request_id)
    const committed = run.attempt_events.filter(
      ({ event }) => event === 'COMMITTED',
    )
    assert.equal(committed.length, 1)
    const job = run.jobs.find(
      ({ attempt_id: attemptId }) => attemptId === committed[0].attempt_id,
    )
    assert.equal(job.coverage_authority, 'REMOTE_REQUEST_ACCEPTED')
    assert.equal(job.state, 'SUCCEEDED')
    const lease = run.attempt_events.find(
      ({ attempt_id: attemptId, event }) =>
        attemptId === committed[0].attempt_id && event === 'LEASED',
    )
    assert.equal(lease.backend, 'REMOTE_GATEWAY')
    assert.ok(run.artifacts[lease.request_artifact_key])
    assert.ok(run.artifacts[job.execution_artifact_key])
    await verifyControlBundle(written.directory, run)

    const rotatedGateway = generateKeyPairSync('ed25519')
    const rotatedGatewayKeyPath = join(output, 'rotated-gateway-public.pem')
    await writeFile(
      rotatedGatewayKeyPath,
      rotatedGateway.publicKey.export({ type: 'spki', format: 'pem' }),
    )
    await writeFile(
      configPath,
      stableJson(remoteConfig(controllerKeyPath, rotatedGatewayKeyPath)),
    )
    await assert.rejects(
      () => runRemoteCommand(
        [written.directory, configPath],
        {},
        dependencies,
      ),
      /rotation require a new run/,
    )
    assert.equal(providerCalls, 2)

    const forged = structuredClone(run)
    const failedLease = leases[0]
    const requestArtifact = forged.artifacts[failedLease.request_artifact_key]
    const requestPath = join(written.directory, requestArtifact.path)
    const canonicalBytes = await readFile(requestPath)
    const replacementBytes = Buffer.from('\uFFFD', 'utf8')
    const replacementOffset = canonicalBytes.indexOf(replacementBytes)
    assert.notEqual(
      replacementOffset,
      -1,
      'remote request fixture must contain a canonical replacement character',
    )
    const malformedBytes = Buffer.concat([
      canonicalBytes.subarray(0, replacementOffset),
      Buffer.from([0xff]),
      canonicalBytes.subarray(replacementOffset + replacementBytes.length),
    ])
    const malformedDigest = createHash('sha256').update(malformedBytes).digest('hex')
    await writeFile(requestPath, malformedBytes)
    requestArtifact.sha256 = malformedDigest
    forged.attempt_events.find(
      ({ attempt_id: attemptId, event }) =>
        attemptId === failedLease.attempt_id && event === 'LEASED',
    ).request_artifact_sha256 = malformedDigest
    let previousEventSha256 = null
    for (const [index, event] of forged.attempt_events.entries()) {
      event.sequence = index + 1
      event.previous_event_sha256 = previousEventSha256
      event.event_sha256 = hashAttemptEvent(event)
      previousEventSha256 = event.event_sha256
    }
    await assert.rejects(
      () => verifyControlBundle(written.directory, forged),
      /remote request envelope JSON is invalid: .*not valid UTF-8/i,
    )
  } finally {
    await rm(root, { recursive: true, force: true })
    await rm(output, { recursive: true, force: true })
  }
})
