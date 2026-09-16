import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { basename, dirname, isAbsolute, join, relative, resolve, win32 } from 'node:path'
import { test } from 'node:test'

import {
  defaultUnleashRunsRoot,
  getUnleashCampaignStatus,
  resumeUnleashCampaign,
  stopUnleashCampaign,
  unleashTarget,
} from '../scripts/lib/unleash-controller.mjs'
import {
  createUnleashCampaignStorage,
  canonicalUnleashCampaignJson,
  openUnleashCampaignStorage,
} from '../scripts/lib/unleash-campaign-storage.mjs'
import { appendUnleashCampaignState } from '../scripts/lib/unleash-campaign-state.mjs'
import { createUnleashPlan, digestUnleashValue } from '../scripts/lib/unleash-contracts.mjs'
import { createUnleashDeploymentPolicy } from '../scripts/lib/unleash-policy.mjs'
import { createUnleashReasoningAdapter } from '../scripts/lib/unleash-reasoning-adapter.mjs'
import { createDefaultUnleashPlannerDependencies } from '../scripts/lib/unleash-registry.mjs'
import { createUnleashRoleRequest } from '../scripts/lib/unleash-swarm-contracts.mjs'
import { appendUnleashSwarmAttemptEvent } from '../scripts/lib/unleash-swarm-ledger.mjs'
import {
  requestHttpReconStop,
} from '../scripts/lib/http-recon-controller.mjs'

const TARGET = 'https://example.test/'
const NOW = '2026-09-15T09:30:00.000Z'
const SCRATCH_PREFIX = 'rta-unleash-controller-denial-'
const LEGACY_PROVIDER_PROFILE = Object.freeze({
  protocol_version: '1.0.0',
  proposal_kind: 'last-aperture/unleash-proposal',
})

test('Windows default campaign storage stays below LocalAppData even when the environment value is absent or invalid', () => {
  const home = 'C:\\Users\\fixture'
  const fallback = 'C:\\Users\\fixture\\AppData\\Local\\LastAperture\\campaigns'
  assert.equal(defaultUnleashRunsRoot({ platform: 'win32', localAppData: null, home }), fallback)
  assert.equal(defaultUnleashRunsRoot({ platform: 'win32', localAppData: 'relative', home }), fallback)
  assert.equal(
    defaultUnleashRunsRoot({ platform: 'win32', localAppData: 'D:\\Private\\Local', home }),
    'D:\\Private\\Local\\LastAperture\\campaigns',
  )
})

function deferred() {
  let resolvePromise
  const promise = new Promise((resolve) => { resolvePromise = resolve })
  return { promise, resolve: resolvePromise }
}

function runWindowsSecurityTool(executable, args) {
  const result = spawnSync(executable, args, { encoding: 'utf8', windowsHide: true })
  assert.equal(result.status, 0, result.stderr)
  return result.stdout
}

function secureWindowsTestDirectory(path) {
  if (process.platform !== 'win32') return
  const systemRoot = process.env.SystemRoot
  assert.equal(typeof systemRoot, 'string')
  const whoami = win32.join(systemRoot, 'System32', 'whoami.exe')
  const icacls = win32.join(systemRoot, 'System32', 'icacls.exe')
  const identity = runWindowsSecurityTool(whoami, ['/user', '/fo', 'csv', '/nh'])
  const sid = identity.match(/,"(S-[0-9-]+)"\s*$/u)?.[1]
  assert.match(sid ?? '', /^S-[0-9-]+$/u)
  runWindowsSecurityTool(icacls, [path, '/grant:r', `*${sid}:(OI)(CI)F`])
  runWindowsSecurityTool(icacls, [path, '/inheritance:r'])
  runWindowsSecurityTool(icacls, [
    path,
    '/grant:r',
    '*S-1-5-18:(OI)(CI)F',
    '*S-1-5-32-544:(OI)(CI)F',
  ])
}

function deploymentPolicy() {
  return createUnleashDeploymentPolicy({
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-deployment-policy',
    policy_id: 'policy:controller-denial-test',
    valid_from: '2026-09-15T09:00:00.000Z',
    valid_until: '2026-09-15T10:00:00.000Z',
    allowed_origins: ['https://example.test'],
    allowed_target_families: ['https'],
    allowed_effects: ['OBSERVE'],
    budgets: {
      max_actions: 4,
      max_parallel_actions: 1,
      max_duration_ms: 900_000,
      max_response_bytes: 1_048_576,
    },
    credential_references: ['credential:browser:primary'],
    revocation: { check_id: 'revocation:controller-denial-test', fail_mode: 'CLOSED' },
  })
}

function controllerProbe(calls) {
  return async (options) => {
    calls.push([options])
    const answers = [{ address: '93.184.216.34', family: 4 }]
    const dns = {
      answer_sha256: createHash('sha256').update(JSON.stringify({
        hostname: new URL(options.url).hostname,
        answers,
      })).digest('hex'),
      answer_count: 1,
      answers,
      selected_ip: '93.184.216.34',
      selected_family: 4,
    }
    const tls = {
      server_name: new URL(options.url).hostname,
      peer_ip: '93.184.216.34',
      peer_family: 4,
      spki_sha256: 'a'.repeat(64),
      certificate_sha256: 'c'.repeat(64),
      valid_from: 'Sep  1 00:00:00 2026 GMT',
      valid_to: 'Oct  1 00:00:00 2026 GMT',
      protocol: 'TLSv1.3',
      cipher: 'TLS_AES_256_GCM_SHA384',
      authorized: true,
      verification_mode: 'PKIX_HOSTNAME',
    }
    await options.beforeSend({
      url: options.url,
      method: options.method,
      request_headers: null,
      dns: structuredClone(dns),
      tls: structuredClone(tls),
    })
    const responseHeaders = [{ name: 'content-type', value: 'text/html' }]
    return {
      schema_version: '1.0.0',
      requested_url: options.url,
      url: options.url,
      method: options.method,
      status: 200,
      response_headers: responseHeaders,
      response_header_summary: {
        retained_bytes: Buffer.byteLength('content-type: text/html\r\n'),
        omitted_count: 0,
        redacted_names: [],
        truncated: false,
      },
      body: {
        bytes: null,
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        size: 0,
        retained_size: 0,
        retained: false,
        truncated: false,
        digest_scope: 'complete',
      },
      dns,
      tls,
      timing: {
        dns_ms: 1,
        tls_handshake_ms: 2,
        before_send_ms: 1,
        time_to_first_byte_ms: 3,
        total_ms: 7,
      },
      request_may_have_been_sent: true,
    }
  }
}

async function harness(t, overrides = {}) {
  const temporaryParent = resolve(tmpdir())
  const scratch = await mkdtemp(join(temporaryParent, SCRATCH_PREFIX))
  t.after(async () => {
    const cleanupPath = resolve(scratch)
    assert.equal(dirname(cleanupPath), temporaryParent)
    assert.ok(basename(cleanupPath).startsWith(SCRATCH_PREFIX))
    await rm(cleanupPath, { recursive: true, force: true })
  })
  const calls = []
  const stateWrites = []
  const evidenceCalls = []
  const runsRoot = join(scratch, 'LastAperture', 'campaigns')
  await mkdir(runsRoot, { recursive: true, mode: 0o700 })
  secureWindowsTestDirectory(runsRoot)
  const deps = {
    policy: deploymentPolicy(),
    unleashProviderProfile: LEGACY_PROVIDER_PROFILE,
    now: () => new Date(NOW),
    isRevoked: () => false,
    runsRoot,
    randomBytes: (size) => Buffer.alloc(size, 0x31),
    mkdir,
    createCampaignStorage: async (options) => {
      const storage = await createUnleashCampaignStorage(options)
      return Object.freeze({
        ...storage,
        replaceMutableJson: async (filename, value) => {
          if (typeof value?.status === 'string') stateWrites.push(structuredClone(value))
          return storage.replaceMutableJson(filename, value)
        },
      })
    },
    httpReconProbe: controllerProbe(calls),
    readVerifiedRecon: async (request) => {
      evidenceCalls.push({ bundle: request.bundle })
      const plan = JSON.parse(await readFile(join(dirname(request.bundle), 'campaign-plan.json'), 'utf8'))
      const authority = JSON.parse(await readFile(join(dirname(request.bundle), 'campaign-recon-authority.json'), 'utf8'))
      return {
        schema_version: '1.0.0',
        kind: 'last-aperture/verified-http-recon-evidence',
        run: {
          state: 'PROBE_PLAN_COMPLETE',
          run_id: 'run:controller-fixture',
          plan_sha256: '6'.repeat(64),
          authorization: authority,
          target: { origin: new URL(plan.target.canonical_locator).origin },
          actions: [{
            method: 'HEAD',
            url: plan.target.canonical_locator,
            safe_to_get: false,
          }],
          event_chain: { count: 3, last_sha256: '8'.repeat(64) },
        },
        observations: [{
          authority: structuredClone(authority),
          method: 'HEAD',
          url: plan.target.canonical_locator,
        }],
      }
    },
    ...overrides,
  }
  return { deps, calls, stateWrites, evidenceCalls, runsRoot }
}

async function runEntries(runsRoot) {
  try { return await readdir(runsRoot) } catch (error) {
    if (error.code === 'ENOENT') return []
    throw error
  }
}

async function completedCampaign(h) {
  return unleashTarget({ target: TARGET }, h.deps)
}

function emptySwarmLedgerState(basis) {
  const unsigned = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-swarm-attempt-ledger-state',
    basis_sha256: basis.basis_sha256,
    campaign_id: basis.campaign_id,
    event_count: 0,
    attempt_count: 0,
    response_bytes: 0,
    head_record_sha256: null,
    ledger_sha256: digestUnleashValue({
      basis_sha256: basis.basis_sha256,
      event_record_sha256s: [],
    }),
    updated_at: basis.recorded_at,
  }
  return { ...unsigned, state_sha256: digestUnleashValue(unsigned) }
}

function swarmMergeAtRound(merge, round) {
  const unsigned = { ...structuredClone(merge), round }
  delete unsigned.merge_sha256
  return { ...unsigned, merge_sha256: digestUnleashValue(unsigned) }
}

async function rewindToRunning(result, runsRoot) {
  const storage = await openUnleashCampaignStorage({
    runsRoot,
    campaignDirectory: basename(result.run_directory),
  })
  const event = await storage.readJson('campaign-event-000002.json')
  await rm(join(result.run_directory, 'campaign-event-000003.json'))
  await rm(join(result.run_directory, 'evidence-packet.json'))
  await rm(join(result.run_directory, 'https-recon-completion.json'))
  await storage.replaceMutableJson('campaign-state.json', event.state)
  return storage
}

test('rejects malformed intake before creating a campaign or calling transport', async (t) => {
  const h = await harness(t)
  for (const input of [
    undefined, null, [], TARGET, {}, { target: null }, { target: 42 },
    { target: '' }, { target: 'http://example.test/' },
    { target: 'https://example.test\\@other.test/' },
  ]) {
    await assert.rejects(async () => unleashTarget(input, h.deps))
    assert.equal(h.calls.length, 0)
    assert.deepEqual(await runEntries(h.runsRoot), [])
  }
})

test('rejects caller-selected output, profile, authority, credentials, and other intake fields', async (t) => {
  const h = await harness(t)
  for (const change of [
    { out: join(h.runsRoot, 'caller-selected') },
    { profile: 'caller-selected' },
    { statement: 'caller-supplied policy replacement' },
    { credentials: { token: 'synthetic-test-value' } },
    { policy: h.deps.policy },
    { allowed_origins: ['https://other.test'] },
    { provider: 'caller-selected' },
    { unknown: true },
  ]) {
    await assert.rejects(async () => unleashTarget({ target: TARGET, ...change }, h.deps))
    assert.equal(h.calls.length, 0)
    assert.deepEqual(await runEntries(h.runsRoot), [])
  }
})

test('denies expired, not-yet-valid, revoked, and off-origin requests before planning', async (t) => {
  for (const scenario of [
    { now: () => new Date('2026-09-15T10:00:00.000Z') },
    { now: () => new Date('2026-09-15T08:59:59.999Z') },
    { isRevoked: () => true },
    { target: 'https://other.test/' },
    { target: 'https://example.test.other.test/' },
    { target: 'https://example.test:444/' },
  ]) {
    const { target: suppliedTarget = TARGET, ...overrides } = scenario
    const h = await harness(t, overrides)
    await assert.rejects(async () => unleashTarget({ target: suppliedTarget }, h.deps))
    assert.equal(h.calls.length, 0)
    assert.deepEqual(await runEntries(h.runsRoot), [])
  }
})

test('fails closed before planning when revocation status is unavailable or indeterminate', async (t) => {
  for (const isRevoked of [
    undefined,
    () => undefined,
    () => 'false',
    () => { throw new Error('revocation source unavailable') },
  ]) {
    const h = await harness(t, { isRevoked })
    await assert.rejects(async () => unleashTarget({ target: TARGET }, h.deps))
    assert.equal(h.calls.length, 0)
    assert.deepEqual(await runEntries(h.runsRoot), [])
  }
})

test('loads controller-owned policy when the runtime supplies only a target', async (t) => {
  let loads = 0
  let checks = 0
  const loadedPolicy = deploymentPolicy()
  const h = await harness(t, {
    policy: undefined,
    isRevoked: undefined,
    loadPolicy: async () => {
      loads += 1
      return {
        policy: loadedPolicy,
        isRevoked: () => { checks += 1; return false },
      }
    },
  })
  const result = await unleashTarget({ target: TARGET }, h.deps)

  assert.equal(loads, 1)
  assert.ok(checks >= 2)
  assert.equal(h.calls.length, 1)
  assert.equal(result.target.canonical_locator, TARGET)
})

test('policy loading fails closed before campaign storage or transport', async (t) => {
  const h = await harness(t, {
    policy: undefined,
    isRevoked: undefined,
    loadPolicy: async () => { throw new Error('synthetic policy source unavailable') },
  })

  await assert.rejects(() => unleashTarget({ target: TARGET }, h.deps))

  assert.equal(h.calls.length, 0)
  assert.deepEqual(await runEntries(h.runsRoot), [])
})

test('blocks reconnaissance when OBSERVE is absent from deployment policy', async (t) => {
  const blockedInput = structuredClone(deploymentPolicy())
  blockedInput.allowed_effects = ['EXECUTE_PROOF']
  const h = await harness(t, {
    policy: createUnleashDeploymentPolicy(blockedInput),
  })

  await assert.rejects(() => unleashTarget({ target: TARGET }, h.deps))

  assert.equal(h.calls.length, 0)
  assert.deepEqual(await runEntries(h.runsRoot), [])
})

test('blocks an adapter whose sealed bounds exceed deployment policy budgets', async (t) => {
  for (const budgets of [
    { max_duration_ms: 899_999 },
    { max_response_bytes: 1_048_575 },
  ]) {
    const blockedInput = structuredClone(deploymentPolicy())
    Object.assign(blockedInput.budgets, budgets)
    const h = await harness(t, {
      policy: createUnleashDeploymentPolicy(blockedInput),
    })

    await assert.rejects(() => unleashTarget({ target: TARGET }, h.deps))
    assert.equal(h.calls.length, 0)
    assert.deepEqual(await runEntries(h.runsRoot), [])
  }
})

test('revocation after initial admission prevents dispatch and never records completion', async (t) => {
  let checks = 0
  const h = await harness(t, { isRevoked: () => { checks += 1; return checks > 1 } })

  await assert.rejects(async () => unleashTarget({ target: TARGET }, h.deps))

  assert.ok(checks >= 2, 'revocation must be checked again immediately before dispatch')
  assert.equal(h.calls.length, 0)
  assert.ok(h.stateWrites.every((state) => !state.status.startsWith('COMPLETE')))
})

test('detaches and freezes deployment policy before a revocation callback can mutate its source', async (t) => {
  const mutablePolicy = structuredClone(deploymentPolicy())
  let checks = 0
  const h = await harness(t, {
    policy: mutablePolicy,
    isRevoked: () => {
      checks += 1
      mutablePolicy.valid_until = '2026-09-15T09:30:00.001Z'
      mutablePolicy.allowed_origins = ['https://attacker.example.test']
      return false
    },
  })
  const result = await unleashTarget({ target: TARGET }, h.deps)

  assert.ok(checks >= 2)
  assert.equal(result.status, 'COMPLETE_WITH_GAPS', JSON.stringify(result))
  assert.equal(h.calls.length, 1)
  assert.equal(h.calls[0][0].url, TARGET)
})

test('mocked transport failure persists sanitized FAILED state and never records completion', async (t) => {
  const h = await harness(t)
  const marker = 'synthetic-private-diagnostic-marker'
  h.deps.httpReconProbe = async (options) => {
    h.calls.push([options])
    const failure = new Error(marker)
    failure.code = marker
    throw failure
  }
  const result = await unleashTarget({ target: TARGET }, h.deps)

  assert.equal(h.calls.length, 1)
  const relativeRun = relative(resolve(h.runsRoot), resolve(result.run_directory))
  assert.ok(relativeRun.length > 0 && relativeRun !== '..' && !relativeRun.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`))
  assert.equal(isAbsolute(relativeRun), false)
  const state = JSON.parse(await readFile(join(result.run_directory, 'campaign-state.json'), 'utf8'))
  assert.equal(state.status, 'FAILED', JSON.stringify(state))
  assert.deepEqual(state.completed_routes, [])
  assert.equal(typeof state.failure.code, 'string')
  assert.ok(state.failure.code.length > 0)
  assert.equal(typeof state.failure.message, 'string')
  assert.ok(state.failure.message.length > 0)
  assert.equal(JSON.stringify(state).includes(marker), false)
  assert.ok(h.stateWrites.length > 0, 'failure state must be persisted through the supplied writer')
  assert.ok(h.stateWrites.every((written) => !written.status.startsWith('COMPLETE')))
})

test('initial dispatch reconciles a thrown post-send attempt to OUTCOME_UNCERTAIN without replay', async (t) => {
  const h = await harness(t)
  const completedTransport = controllerProbe(h.calls)
  h.deps.httpReconProbe = async (options) => {
    await completedTransport(options)
    const failure = new Error('synthetic process interruption after durable pre-dispatch')
    failure.request_may_have_been_sent = true
    throw failure
  }

  const result = await unleashTarget({ target: TARGET }, h.deps)

  assert.equal(result.status, 'OUTCOME_UNCERTAIN')
  assert.equal(result.failure.code, 'UNLEASH_RECON_OUTCOME_UNCERTAIN')
  assert.match(result.failure.message, /not replayed/u)
  assert.equal(h.calls.length, 1)
})

test('initial dispatch projects a durable HTTP-recon STOPPED outcome', async (t) => {
  const h = await harness(t)
  h.deps.onHttpReconPlanned = async ({ bundle, authority }) => requestHttpReconStop({
    bundle,
    controllerPolicyAuthority: authority,
    reason: 'controller stop marker observed before send',
    now: h.deps.now,
  })

  const result = await unleashTarget({ target: TARGET }, h.deps)

  assert.equal(result.status, 'STOPPED')
  assert.equal(result.stop_reason, 'controller stop marker observed before send')
  assert.deepEqual(result.completed_routes, [])
  assert.equal(result.evidence_packet_path, null)
  assert.equal(h.calls.length, 0)
})

test('invalid recon evidence packet fails the campaign without recording route completion', async (t) => {
  const h = await harness(t, {
    readVerifiedRecon: async () => ({ invalid: true }),
  })

  let failure
  await assert.rejects(
    () => unleashTarget({ target: TARGET }, h.deps),
    (error) => { failure = error; return error.code === 'UNLEASH_REMOTE_ROUTE_FAILED' },
  )

  const state = JSON.parse(await readFile(join(failure.run_directory, 'campaign-state.json'), 'utf8'))
  assert.equal(state.status, 'FAILED')
  assert.deepEqual(state.completed_routes, [])
  assert.equal(state.evidence_packet_path, null)
  assert.equal(state.evidence_packet_sha256, null)
})

test('one target creates an app-owned plan and completes the first bounded remote route', async (t) => {
  let checks = 0
  const h = await harness(t, {
    isRevoked: () => { checks += 1; return false },
  })

  const result = await unleashTarget({ target: TARGET }, h.deps)

  assert.equal(h.calls.length, 1)
  assert.equal(h.calls[0][0].url, TARGET)
  assert.equal(h.calls[0][0].method, 'HEAD')
  assert.equal(h.calls[0][0].requestHeaderProfile, undefined)
  assert.ok(checks >= 2)
  const retainedRecon = JSON.parse(await readFile(join(result.run_directory, 'recon', 'run.json'), 'utf8'))
  assert.equal(result.status, 'COMPLETE_WITH_GAPS', JSON.stringify({ result, retainedRecon }))
  assert.match(result.campaign_id, /^campaign:sha256:[a-f0-9]{64}$/u)
  assert.match(result.plan_sha256, /^[a-f0-9]{64}$/u)
  assert.deepEqual(result.completed_routes, ['https-recon'])
  assert.match(result.evidence_packet_sha256, /^[a-f0-9]{64}$/u)
  assert.match(result.completion_receipt_sha256, /^[a-f0-9]{64}$/u)
  assert.equal(result.evidence_packet_path, join(result.run_directory, 'evidence-packet.json'))
  assert.equal(result.target.canonical_locator, TARGET)
  assert.equal(result.route_counts.total, 29)
  assert.ok(result.route_counts.unavailable > 0)
  assert.ok(result.route_counts.waiting > 0)
  assert.ok(result.gap_count > 0)
  assert.equal(result.run_directory.startsWith(resolve(h.runsRoot)), true)

  const plan = JSON.parse(await readFile(join(result.run_directory, 'campaign-plan.json'), 'utf8'))
  const state = JSON.parse(await readFile(join(result.run_directory, 'campaign-state.json'), 'utf8'))
  assert.equal(plan.plan_sha256, result.plan_sha256)
  assert.equal(state.status, result.status)
  assert.deepEqual(state.completed_routes, ['https-recon'])
  assert.equal(state.failure, null)
  assert.equal(state.recon_bundle, join(result.run_directory, 'recon'))
  assert.equal(state.evidence_packet_path, result.evidence_packet_path)
  assert.equal(state.evidence_packet_sha256, result.evidence_packet_sha256)
  assert.equal(state.completion_receipt_sha256, result.completion_receipt_sha256)
  const packet = JSON.parse(await readFile(result.evidence_packet_path, 'utf8'))
  const completion = JSON.parse(await readFile(join(result.run_directory, 'https-recon-completion.json'), 'utf8'))
  assert.equal(packet.packet_sha256, result.evidence_packet_sha256)
  assert.equal(packet.plan_sha256, result.plan_sha256)
  assert.equal(packet.redaction.payload_values_included, false)
  assert.equal(completion.completion_receipt.route_id, 'https-recon')
  assert.equal(completion.completion_receipt.evidence_ref, packet.sources[0].evidence_ref)
  assert.equal(completion.completion_receipt.completion_receipt_sha256, result.completion_receipt_sha256)
  assert.ok(h.evidenceCalls.length >= 3)
  assert.ok(h.evidenceCalls.every(({ bundle }) => bundle === join(result.run_directory, 'recon')))
})

test('retained authoritative completion survives derived packet publication failure and resumes without replay', async (t) => {
  const h = await harness(t)
  let rejectPacketPublication = true
  h.deps.createCampaignStorage = async (options) => {
    const storage = await createUnleashCampaignStorage(options)
    return Object.freeze({
      ...storage,
      writeImmutableJson: async (filename, value) => {
        if (filename === 'evidence-packet.json' && rejectPacketPublication) {
          const error = new Error('synthetic derived packet publication failure')
          error.code = 'EIO'
          throw error
        }
        return storage.writeImmutableJson(filename, value)
      },
    })
  }

  const interrupted = await unleashTarget({ target: TARGET }, h.deps)
  assert.equal(interrupted.status, 'RECONCILIATION_REQUIRED')
  assert.equal(interrupted.failure.code, 'UNLEASH_RECON_COMPLETION_PUBLICATION_INCOMPLETE')
  assert.equal(h.calls.length, 1)
  assert.equal(
    JSON.parse(await readFile(join(interrupted.run_directory, 'https-recon-completion.json'), 'utf8')).completion_receipt.kind,
    'last-aperture/unleash-route-completion-receipt',
  )
  await assert.rejects(
    readFile(join(interrupted.run_directory, 'evidence-packet.json'), 'utf8'),
    (error) => error.code === 'ENOENT',
  )

  rejectPacketPublication = false
  const resumed = await resumeUnleashCampaign({ bundle: interrupted.run_directory }, {
    ...h.deps,
    nextHttpReconAction: async () => { throw new Error('retained completion must not select another action') },
    runHttpReconAction: async () => { throw new Error('retained completion must not replay an action') },
  })
  assert.equal(resumed.status, 'COMPLETE_WITH_GAPS')
  assert.equal(h.calls.length, 1)
  assert.match(resumed.evidence_packet_sha256, /^[a-f0-9]{64}$/u)
  assert.match(resumed.completion_receipt_sha256, /^[a-f0-9]{64}$/u)
})

test('uninspectable completion inventory after terminal recon requires reconciliation instead of false failure', async (t) => {
  const h = await harness(t)
  let rejectCatchInventory = false
  h.deps.createCampaignStorage = async (options) => {
    const storage = await createUnleashCampaignStorage(options)
    return Object.freeze({
      ...storage,
      listJsonFilenames: async () => {
        if (rejectCatchInventory) {
          rejectCatchInventory = false
          const error = new Error('synthetic inventory read failure')
          error.code = 'EIO'
          throw error
        }
        return storage.listJsonFilenames()
      },
      writeImmutableJson: async (filename, value) => {
        if (filename === 'evidence-packet.json') {
          rejectCatchInventory = true
          const error = new Error('synthetic derived packet publication failure')
          error.code = 'EIO'
          throw error
        }
        return storage.writeImmutableJson(filename, value)
      },
    })
  }

  const interrupted = await unleashTarget({ target: TARGET }, h.deps)
  assert.equal(interrupted.status, 'RECONCILIATION_REQUIRED')
  assert.equal(interrupted.failure.code, 'UNLEASH_RECON_COMPLETION_INVENTORY_UNAVAILABLE')
  assert.equal(h.calls.length, 1)
  assert.equal(
    JSON.parse(await readFile(join(interrupted.run_directory, 'https-recon-completion.json'), 'utf8')).completion_receipt.route_id,
    'https-recon',
  )

  const resumed = await resumeUnleashCampaign({ bundle: interrupted.run_directory }, {
    ...h.deps,
    nextHttpReconAction: async () => { throw new Error('terminal recon must not select another action') },
    runHttpReconAction: async () => { throw new Error('terminal recon must not replay an action') },
  })
  assert.equal(resumed.status, 'COMPLETE_WITH_GAPS')
  assert.equal(h.calls.length, 1)
})

test('campaign status recovers the immutable event head and repairs a stale snapshot', async (t) => {
  const h = await harness(t)
  const result = await completedCampaign(h)
  const storage = await openUnleashCampaignStorage({
    runsRoot: h.runsRoot,
    campaignDirectory: basename(result.run_directory),
  })
  const stale = (await storage.readJson('campaign-event-000002.json')).state
  await storage.replaceMutableJson('campaign-state.json', stale)

  const status = await getUnleashCampaignStatus({ bundle: result.run_directory })

  assert.equal(status.status, 'COMPLETE_WITH_GAPS')
  assert.equal(status.revision, 3)
  assert.equal((await storage.readJson('campaign-state.json')).revision, 3)
})

test('campaign recovery rejects protocol-v2 swarm artifacts under a protocol-v1 state head', async (t) => {
  const h = await harness(t)
  const result = await completedCampaign(h)
  await writeFile(
    join(result.run_directory, 'swarm-attempt-ledger-state.json'),
    canonicalUnleashCampaignJson({ forged: true }),
    'utf8',
  )

  await assert.rejects(
    getUnleashCampaignStatus({ bundle: result.run_directory }),
    (error) => error.code === 'UNLEASH_CAMPAIGN_PROTOCOL_ARTIFACT_INVALID'
      && error.status === 'RECONCILIATION_REQUIRED',
  )
})

test('protocol-v2 status stays read-only while owned Resume repairs the exact ledger head', { timeout: 180_000 }, async (t) => {
  const h = await harness(t)
  delete h.deps.unleashProviderProfile
  h.deps.reasoningAdapters = [{
    roleId: 'attacker:perimeter',
    adapter: createUnleashReasoningAdapter({
      identity: {
        adapter_id: 'adapter:recovery-test-empty-response',
        adapter_version: '1.0.0',
        adapter_config_sha256: digestUnleashValue({ fixture: 'empty-response' }),
      },
      invoke: async ({ request }) => Buffer.from(JSON.stringify({
        schema_version: '1.0.0',
        kind: 'last-aperture/unleash-role-response',
        request_id: request.request_id,
        request_sha256: request.request_sha256,
        basis_sha256: request.basis_sha256,
        plan_sha256: request.plan_sha256,
        round: request.round,
        role_id: request.role_id,
        role_kind: request.role_kind,
        wave: request.wave,
        proposal: {
          schema_version: '1.0.0',
          kind: 'last-aperture/unleash-proposal',
          proposal_id: `proposal:recovery-test:r${request.round}`,
          plan_sha256: request.plan_sha256,
          provider_protocol_version: '2.0.0',
          candidates: [],
          actions: [],
        },
        challenges: [],
      }), 'utf8'),
    }),
  }]
  const result = await completedCampaign(h)
  const basisPath = join(result.run_directory, 'swarm-basis.json')
  const ledgerStatePath = join(result.run_directory, 'swarm-attempt-ledger-state.json')
  const basis = JSON.parse(await readFile(basisPath, 'utf8'))
  const eventNames = (await readdir(result.run_directory))
    .filter((filename) => /^swarm-attempt-event-[0-9]{6}\.json$/u.test(filename))
    .sort()
  assert.ok(eventNames.length > 1)

  await writeFile(
    ledgerStatePath,
    canonicalUnleashCampaignJson(emptySwarmLedgerState(basis)),
    'utf8',
  )
  await assert.rejects(
    getUnleashCampaignStatus(
      { bundle: result.run_directory },
      { now: h.deps.now },
    ),
    (error) => error.code === 'UNLEASH_SWARM_LEDGER_STATE_STALE'
      && error.status === 'RECONCILIATION_REQUIRED',
  )
  assert.equal((JSON.parse(await readFile(ledgerStatePath, 'utf8'))).event_count, 0)
  const repaired = await resumeUnleashCampaign(
    { bundle: result.run_directory },
    h.deps,
  )
  assert.equal(repaired.status, 'COMPLETE_WITH_GAPS')
  assert.equal((JSON.parse(await readFile(ledgerStatePath, 'utf8'))).event_count, eventNames.length)

  const eventDocuments = await Promise.all(eventNames.map(async (filename) => ({
    filename,
    event: JSON.parse(await readFile(join(result.run_directory, filename), 'utf8')),
  })))
  const committedDocument = eventDocuments.find(({ event }) => event.state === 'COMMITTED')
  assert.ok(committedDocument)
  const retainedLedgerState = JSON.parse(await readFile(ledgerStatePath, 'utf8'))
  const forgedCommitted = structuredClone(committedDocument.event)
  forgedCommitted.payload.merge_sha256 = 'f'.repeat(64)
  delete forgedCommitted.record_sha256
  forgedCommitted.record_sha256 = digestUnleashValue(forgedCommitted)
  await writeFile(
    join(result.run_directory, committedDocument.filename),
    canonicalUnleashCampaignJson(forgedCommitted),
    'utf8',
  )
  const forgedLedgerState = {
    ...retainedLedgerState,
    head_record_sha256: forgedCommitted.record_sha256,
    ledger_sha256: digestUnleashValue({
      basis_sha256: basis.basis_sha256,
      event_record_sha256s: eventDocuments.map(({ filename, event }) => (
        filename === committedDocument.filename ? forgedCommitted.record_sha256 : event.record_sha256
      )),
    }),
  }
  delete forgedLedgerState.state_sha256
  forgedLedgerState.state_sha256 = digestUnleashValue(forgedLedgerState)
  await writeFile(ledgerStatePath, canonicalUnleashCampaignJson(forgedLedgerState), 'utf8')
  await assert.rejects(
    getUnleashCampaignStatus({ bundle: result.run_directory }, { now: h.deps.now }),
    (error) => error.code === 'UNLEASH_SWARM_LEDGER_MERGE_DRIFT'
      && error.status === 'RECONCILIATION_REQUIRED',
  )
  await writeFile(
    join(result.run_directory, committedDocument.filename),
    canonicalUnleashCampaignJson(committedDocument.event),
    'utf8',
  )
  await writeFile(ledgerStatePath, canonicalUnleashCampaignJson(retainedLedgerState), 'utf8')

  const missingEventPath = join(result.run_directory, eventNames[0])
  const missingEvent = await readFile(missingEventPath, 'utf8')
  await rm(missingEventPath)
  await assert.rejects(
    getUnleashCampaignStatus({ bundle: result.run_directory }, { now: h.deps.now }),
    (error) => error.code === 'UNLEASH_SWARM_LEDGER_GAP'
      && error.status === 'RECONCILIATION_REQUIRED',
  )
  await writeFile(missingEventPath, missingEvent, 'utf8')

  const sourceRequest = eventDocuments[0].event.request
  const postTerminalRequest = createUnleashRoleRequest({
    basis,
    round: 2,
    roleId: 'attacker:perimeter',
    inputFrontierSha256: sourceRequest.input_frontier_sha256,
    inputChallengeSetSha256: sourceRequest.input_challenge_set_sha256,
    evidenceRefs: sourceRequest.evidence_refs,
    allowedToolIds: sourceRequest.allowed_tool_ids,
    artifacts: sourceRequest.artifacts,
  })
  const provider = JSON.parse(await readFile(
    join(result.run_directory, 'campaign-provider.json'),
    'utf8',
  ))
  const assignment = provider.assignments.find(({ role_id: roleId }) => roleId === 'attacker:perimeter')
  const adapterIdentity = {
    adapter_id: assignment.adapter_id,
    adapter_version: assignment.adapter_version,
    adapter_config_sha256: assignment.adapter_config_sha256,
  }
  const campaignStorage = await openUnleashCampaignStorage({
    runsRoot: h.runsRoot,
    campaignDirectory: basename(result.run_directory),
  })
  const ledgerStorage = {
    writeImmutableJson: campaignStorage.writeImmutableJson,
    replaceMutableJson: campaignStorage.replaceMutableJson,
    readJson: campaignStorage.readJson,
    listJsonFilenames: campaignStorage.listJsonFilenames,
  }
  const retainedCompletion = JSON.parse(await readFile(
    join(result.run_directory, 'swarm-completion.json'),
    'utf8',
  ))
  const leasedAt = new Date(Date.parse(retainedCompletion.completed_at) + 1_000)
  const failedAt = new Date(leasedAt.getTime() + 1_000)
  const attemptId = `attempt:sha256:${digestUnleashValue({ fixture: 'post-terminal-append' })}`
  const attemptLimits = eventDocuments.find(({ event }) => event.state === 'LEASED').event.payload.limits
  await appendUnleashSwarmAttemptEvent({
    basis,
    attemptId,
    request: postTerminalRequest,
    adapterIdentity,
    state: 'LEASED',
    occurredAt: leasedAt.toISOString(),
    payload: {
      expires_at: new Date(leasedAt.getTime() + attemptLimits.wall_time_ms).toISOString(),
      limits: attemptLimits,
    },
  }, { storage: ledgerStorage })
  const appended = await appendUnleashSwarmAttemptEvent({
    basis,
    attemptId,
    request: postTerminalRequest,
    adapterIdentity,
    state: 'FAILED',
    occurredAt: failedAt.toISOString(),
    payload: {
      reason_code: 'SYNTHETIC_POST_TERMINAL_APPEND',
      phase: 'LEASED',
      delivery: 'NOT_STARTED',
      detail_sha256: digestUnleashValue({ fixture: 'post-terminal-append-failure' }),
    },
  }, { storage: ledgerStorage })
  await assert.rejects(
    getUnleashCampaignStatus({ bundle: result.run_directory }, { now: h.deps.now }),
    (error) => error.code === 'UNLEASH_SWARM_COMPLETION_LEDGER_DRIFT'
      && error.status === 'RECONCILIATION_REQUIRED',
  )
  for (const event of appended.events.slice(eventNames.length)) {
    await rm(join(
      result.run_directory,
      `swarm-attempt-event-${String(event.sequence).padStart(6, '0')}.json`,
    ))
  }
  await writeFile(ledgerStatePath, canonicalUnleashCampaignJson(retainedLedgerState), 'utf8')

  const attackPath = join(result.run_directory, 'swarm-merge-r01-attack.json')
  const attack = JSON.parse(await readFile(attackPath, 'utf8'))
  await writeFile(
    attackPath,
    canonicalUnleashCampaignJson(swarmMergeAtRound(attack, 2)),
    'utf8',
  )
  await assert.rejects(
    getUnleashCampaignStatus({ bundle: result.run_directory }, { now: h.deps.now }),
    (error) => error.code === 'UNLEASH_SWARM_MERGE_FILENAME_DRIFT'
      && error.status === 'RECONCILIATION_REQUIRED',
  )
  await writeFile(attackPath, canonicalUnleashCampaignJson(attack), 'utf8')

  const review = JSON.parse(await readFile(
    join(result.run_directory, 'swarm-merge-r01-review.json'),
    'utf8',
  ))
  const roundTwo = swarmMergeAtRound(review, 2)
  const trailing = [
    join(result.run_directory, 'swarm-merge-r02-attack.json'),
    join(result.run_directory, 'swarm-merge-r02-review.json'),
  ]
  for (const filename of trailing) {
    await writeFile(filename, canonicalUnleashCampaignJson(roundTwo), 'utf8')
  }
  await assert.rejects(
    getUnleashCampaignStatus({ bundle: result.run_directory }, { now: h.deps.now }),
    (error) => error.code === 'UNLEASH_SWARM_MERGE_SEQUENCE_INVALID'
      && error.status === 'RECONCILIATION_REQUIRED',
  )
})

test('campaign status rejects a snapshot that references a truncated event chain', async (t) => {
  const h = await harness(t)
  const result = await completedCampaign(h)
  await rm(join(result.run_directory, 'campaign-event-000003.json'))

  await assert.rejects(
    getUnleashCampaignStatus({ bundle: result.run_directory }),
    (error) => error.code === 'UNLEASH_CAMPAIGN_CHAIN_TRUNCATED'
      && error.status === 'RECONCILIATION_REQUIRED',
  )
})

test('campaign status never reports COMPLETE when its typed completion envelope is missing', async (t) => {
  const h = await harness(t)
  const result = await completedCampaign(h)
  await rm(join(result.run_directory, 'https-recon-completion.json'))

  await assert.rejects(
    getUnleashCampaignStatus({ bundle: result.run_directory }),
    (error) => error.code === 'UNLEASH_COMPLETED_CAMPAIGN_EVIDENCE_INVALID'
      && error.status === 'RECONCILIATION_REQUIRED',
  )
})

test('campaign status never reports COMPLETE when its typed completion envelope is tampered', async (t) => {
  const h = await harness(t)
  const result = await completedCampaign(h)
  const path = join(result.run_directory, 'https-recon-completion.json')
  const completion = JSON.parse(await readFile(path, 'utf8'))
  completion.completion_receipt.recon_run_id = 'run:tampered-fixture'
  await writeFile(path, canonicalUnleashCampaignJson(completion), 'utf8')

  await assert.rejects(
    getUnleashCampaignStatus({ bundle: result.run_directory }),
    (error) => error.code === 'UNLEASH_COMPLETED_CAMPAIGN_EVIDENCE_INVALID'
      && error.status === 'RECONCILIATION_REQUIRED',
  )
})

test('campaign status rejects a self-consistent completed event that claims an unproved plan route', async (t) => {
  const h = await harness(t)
  const result = await completedCampaign(h)
  const plan = JSON.parse(await readFile(join(result.run_directory, 'campaign-plan.json'), 'utf8'))
  const otherRoute = plan.route_dispositions.find(({ route_id: routeId }) => routeId !== 'https-recon')?.route_id
  assert.equal(typeof otherRoute, 'string')
  const eventPath = join(result.run_directory, 'campaign-event-000003.json')
  const event = JSON.parse(await readFile(eventPath, 'utf8'))
  event.state.completed_routes = [otherRoute]
  event.state_sha256 = digestUnleashValue(event.state)
  await writeFile(eventPath, canonicalUnleashCampaignJson(event), 'utf8')
  await writeFile(
    join(result.run_directory, 'campaign-state.json'),
    canonicalUnleashCampaignJson(event.state),
    'utf8',
  )

  await assert.rejects(
    getUnleashCampaignStatus({ bundle: result.run_directory }),
    (error) => error.code === 'UNLEASH_COMPLETED_CAMPAIGN_EVIDENCE_INVALID'
      && error.status === 'RECONCILIATION_REQUIRED',
  )
})

test('a planned campaign stops in one durable transition without requiring recon authority', async (t) => {
  const h = await harness(t)
  const plannerDependencies = createDefaultUnleashPlannerDependencies({ policy: h.deps.policy })
  const plan = createUnleashPlan({ target: TARGET }, plannerDependencies)
  const campaignDirectory = `campaign-${'3'.repeat(24)}`
  const storage = await createUnleashCampaignStorage({
    runsRoot: h.runsRoot,
    campaignDirectory,
  })
  await storage.writeImmutableJson('campaign-plan.json', plan)
  await storage.writeImmutableJson('campaign-registry.json', plannerDependencies.registry)
  await storage.writeImmutableJson('campaign-provider.json', plannerDependencies.provider)
  const routeCounts = {
    total: plan.route_dispositions.length,
    ready: plan.route_dispositions.filter(({ disposition }) => disposition === 'READY').length,
    waiting: plan.route_dispositions.filter(({ disposition }) => disposition.startsWith('WAITING_')).length,
    unavailable: plan.route_dispositions.filter(({ disposition }) => disposition === 'UNAVAILABLE').length,
    not_applicable: plan.route_dispositions.filter(({ disposition }) => disposition === 'NOT_APPLICABLE').length,
    blocked: plan.route_dispositions.filter(({ disposition }) => disposition === 'BLOCKED_BY_POLICY').length,
  }
  const planned = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-state',
    revision: 1,
    updated_at: NOW,
    campaign_id: `campaign:sha256:${'3'.repeat(64)}`,
    status: 'PLANNED',
    run_directory: storage.campaign_directory,
    plan_sha256: plan.plan_sha256,
    target: structuredClone(plan.target),
    completed_routes: [],
    route_counts: routeCounts,
    gap_count: routeCounts.waiting + routeCounts.unavailable + routeCounts.blocked,
    recon_bundle: join(storage.campaign_directory, 'recon'),
    evidence_packet_path: null,
    evidence_packet_sha256: null,
    completion_receipt_sha256: null,
    stop_reason: null,
    failure: null,
  }
  await appendUnleashCampaignState({ storage, nextState: planned })

  const stopped = await stopUnleashCampaign({
    bundle: storage.campaign_directory,
    reason: 'stop before dispatch',
  }, { now: h.deps.now })

  assert.equal(stopped.status, 'STOPPED')
  assert.equal(stopped.revision, 2)
  assert.equal(stopped.stop_reason, 'stop before dispatch')
  assert.equal((await storage.readJson('campaign-event-000002.json')).state.status, 'STOPPED')
  assert.equal((await storage.listJsonFilenames()).includes('campaign-recon-authority.json'), false)
  assert.equal((await getUnleashCampaignStatus({ bundle: storage.campaign_directory })).status, 'STOPPED')
  assert.equal((await resumeUnleashCampaign({ bundle: storage.campaign_directory })).status, 'STOPPED')
})

test('a campaign stop gate closes RUNNING before the recon bundle exists and status never reports it runnable', async (t) => {
  const runningPublished = deferred()
  const releaseRunning = deferred()
  const gatePublished = deferred()
  const releaseStop = deferred()
  t.after(() => {
    releaseRunning.resolve()
    releaseStop.resolve()
  })
  const h = await harness(t, {
    createCampaignStorage: async (options) => {
      const storage = await createUnleashCampaignStorage(options)
      return Object.freeze({
        ...storage,
        replaceMutableJson: async (filename, value) => {
          const result = await storage.replaceMutableJson(filename, value)
          if (filename === 'campaign-state.json' && value?.status === 'RUNNING') {
            runningPublished.resolve()
            await releaseRunning.promise
          }
          return result
        },
      })
    },
  })
  const campaignPromise = unleashTarget({ target: TARGET }, h.deps)
  await runningPublished.promise
  const [campaignDirectory] = await runEntries(h.runsRoot)
  const bundle = join(h.runsRoot, campaignDirectory)

  const stopPromise = stopUnleashCampaign({
    bundle,
    reason: 'stop before nested planning',
  }, {
    now: h.deps.now,
    openCampaignStorage: async (options) => {
      const storage = await openUnleashCampaignStorage(options)
      return Object.freeze({
        ...storage,
        writeImmutableJson: async (filename, value) => {
          const result = await storage.writeImmutableJson(filename, value)
          if (filename === 'campaign-stop-request.json') {
            gatePublished.resolve()
            await releaseStop.promise
          }
          return result
        },
      })
    },
  })
  await gatePublished.promise

  const recovered = await resumeUnleashCampaign({ bundle }, { now: h.deps.now })
  assert.equal(recovered.status, 'STOPPED')
  assert.equal(recovered.stop_reason, 'stop before nested planning')
  assert.equal((await getUnleashCampaignStatus({ bundle }, { now: h.deps.now })).status, 'STOPPED')
  const gate = JSON.parse(await readFile(join(bundle, 'campaign-stop-request.json'), 'utf8'))
  assert.equal(gate.kind, 'last-aperture/unleash-stop-request')
  assert.equal(gate.campaign_id, recovered.campaign_id)

  releaseStop.resolve()
  const stopped = await stopPromise
  releaseRunning.resolve()
  const originalWorker = await campaignPromise
  assert.equal(stopped.status, 'STOPPED')
  assert.equal(originalWorker.status, 'STOPPED')
  assert.equal(h.calls.length, 0)
  await assert.rejects(
    readFile(join(bundle, 'recon', 'run.json'), 'utf8'),
    (error) => error.code === 'ENOENT',
  )
})

test('a missing previously planned recon bundle remains reconciliation-required after stop', async (t) => {
  const h = await harness(t)
  const completed = await completedCampaign(h)
  const storage = await rewindToRunning(completed, h.runsRoot)
  assert.equal((await storage.readJson('campaign-recon-planned.json')).kind, 'last-aperture/unleash-recon-planned')
  await rm(join(completed.run_directory, 'recon'), { recursive: true, force: true })
  const requestCountBeforeStop = h.calls.length

  const stopped = await stopUnleashCampaign({
    bundle: completed.run_directory,
    reason: 'missing attempted recon must remain uncertain',
  }, { now: h.deps.now })

  assert.equal(stopped.status, 'RECONCILIATION_REQUIRED')
  assert.equal(stopped.stop_reason, 'missing attempted recon must remain uncertain')
  assert.equal(stopped.failure.code, 'UNLEASH_RECON_BUNDLE_MISSING_AFTER_PLANNING')
  assert.match(stopped.failure.message, /delivery history cannot be proven/u)
  assert.equal(h.calls.length, requestCountBeforeStop)
  const status = await getUnleashCampaignStatus(
    { bundle: completed.run_directory },
    { now: h.deps.now },
  )
  assert.equal(status.kind, 'last-aperture/unleash-campaign-snapshot')
  assert.equal(status.status, stopped.status)
  assert.equal(status.revision, stopped.revision)
  assert.equal(status.stop_reason, stopped.stop_reason)
  assert.deepEqual(status.failure, stopped.failure)
  assert.match(status.snapshot_sha256, /^[a-f0-9]{64}$/u)
  assert.deepEqual(
    await resumeUnleashCampaign({ bundle: completed.run_directory }, { now: h.deps.now }),
    stopped,
  )
})

test('the campaign stop gate blocks a worker paused immediately before target dispatch', async (t) => {
  const probeEntered = deferred()
  const releaseProbe = deferred()
  const gatePublished = deferred()
  const releaseStop = deferred()
  t.after(() => {
    releaseProbe.resolve()
    releaseStop.resolve()
  })
  const h = await harness(t)
  const baseProbe = controllerProbe(h.calls)
  let completedTargetRequests = 0
  h.deps.httpReconProbe = async (options) => {
    probeEntered.resolve()
    await releaseProbe.promise
    const result = await baseProbe(options)
    completedTargetRequests += 1
    return result
  }
  const campaignPromise = unleashTarget({ target: TARGET }, h.deps)
  await probeEntered.promise
  const [campaignDirectory] = await runEntries(h.runsRoot)
  const bundle = join(h.runsRoot, campaignDirectory)

  const stopPromise = stopUnleashCampaign({
    bundle,
    reason: 'close the pre-dispatch window',
  }, {
    now: h.deps.now,
    openCampaignStorage: async (options) => {
      const storage = await openUnleashCampaignStorage(options)
      return Object.freeze({
        ...storage,
        writeImmutableJson: async (filename, value) => {
          const result = await storage.writeImmutableJson(filename, value)
          if (filename === 'campaign-stop-request.json') {
            gatePublished.resolve()
            await releaseStop.promise
          }
          return result
        },
      })
    },
  })
  await gatePublished.promise
  releaseProbe.resolve()
  const originalWorker = await campaignPromise
  releaseStop.resolve()
  const stopped = await stopPromise

  assert.equal(originalWorker.status, 'STOPPED')
  assert.equal(stopped.status, 'STOPPED')
  assert.equal(completedTargetRequests, 0)
  assert.equal((await getUnleashCampaignStatus({ bundle }, { now: h.deps.now })).status, 'STOPPED')
  const marker = JSON.parse(await readFile(join(bundle, 'recon', '.http-recon.stop'), 'utf8'))
  assert.equal(marker.reason, 'close the pre-dispatch window')
})

test('stop durably records intent, finalizes nested recon, and is idempotent after restart', async (t) => {
  const h = await harness(t)
  const result = await completedCampaign(h)
  await rewindToRunning(result, h.runsRoot)
  const stopCalls = []
  const finalizeCalls = []

  const stopped = await stopUnleashCampaign({
    bundle: result.run_directory,
    reason: 'operator requested bounded stop',
  }, {
    now: h.deps.now,
    requestHttpReconStop: async (request) => {
      const state = JSON.parse(await readFile(join(result.run_directory, 'campaign-state.json'), 'utf8'))
      const gate = JSON.parse(await readFile(join(result.run_directory, 'campaign-stop-request.json'), 'utf8'))
      assert.equal(state.status, 'RUNNING')
      assert.equal(gate.reason, 'operator requested bounded stop')
      assert.equal(gate.plan_sha256, state.plan_sha256)
      stopCalls.push(request)
      return { reason: request.reason }
    },
    finalizeHttpReconBundle: async (request) => {
      finalizeCalls.push(request)
      return { run: { state: 'STOPPED', stop: { reason: 'operator requested bounded stop' } } }
    },
  })

  assert.equal(stopped.status, 'STOPPED')
  assert.equal(stopped.revision, 4)
  assert.equal(stopCalls.length, 1)
  assert.equal(stopCalls[0].bundle, join(result.run_directory, 'recon'))
  assert.equal(stopCalls[0].reason, 'operator requested bounded stop')
  assert.equal(stopCalls[0].controllerPolicyAuthority.mode, 'CONTROLLER_DEPLOYMENT_POLICY')
  assert.equal(Object.hasOwn(stopCalls[0], 'operatorId'), false)
  assert.equal(finalizeCalls.length, 1)
  assert.equal(finalizeCalls[0].bundle, join(result.run_directory, 'recon'))
  const storage = await openUnleashCampaignStorage({
    runsRoot: h.runsRoot,
    campaignDirectory: basename(result.run_directory),
  })
  assert.equal((await storage.readJson('campaign-event-000003.json')).state.status, 'STOP_REQUESTED')
  assert.equal((await storage.readJson('campaign-event-000004.json')).state.status, 'STOPPED')

  const stoppedAgain = await stopUnleashCampaign({
    bundle: result.run_directory,
    reason: 'a later reason must not replace retained stop intent',
  }, {
    requestHttpReconStop: async () => { throw new Error('terminal stop must not republish') },
    finalizeHttpReconBundle: async () => { throw new Error('terminal stop must not refinalize') },
  })
  const resumedAgain = await resumeUnleashCampaign({ bundle: result.run_directory }, {
    requestHttpReconStop: async () => { throw new Error('terminal resume must not republish') },
    finalizeHttpReconBundle: async () => { throw new Error('terminal resume must not refinalize') },
  })
  assert.equal(stoppedAgain.status, stopped.status)
  assert.equal(stoppedAgain.revision, stopped.revision)
  assert.equal(stoppedAgain.stop_reason, stopped.stop_reason)
  assert.deepEqual(stoppedAgain.failure, stopped.failure)
  assert.deepEqual(resumedAgain, stopped)
  assert.equal((await storage.listJsonFilenames()).filter((name) => /^campaign-event-/u.test(name)).length, 4)
})

test('stop reuses the real durable HTTP marker and real nested finalizer after campaign restart', async (t) => {
  const h = await harness(t)
  const reason = 'durable nested stop survives campaign restart'
  h.deps.onHttpReconPlanned = async ({ bundle, authority }) => requestHttpReconStop({
    bundle,
    controllerPolicyAuthority: authority,
    reason,
    now: h.deps.now,
  })
  const initial = await unleashTarget({ target: TARGET }, h.deps)
  assert.equal(initial.status, 'STOPPED')
  assert.equal(h.calls.length, 0)

  const storage = await openUnleashCampaignStorage({
    runsRoot: h.runsRoot,
    campaignDirectory: basename(initial.run_directory),
  })
  const running = (await storage.readJson('campaign-event-000002.json')).state
  await rm(join(initial.run_directory, 'campaign-event-000003.json'))
  await storage.replaceMutableJson('campaign-state.json', running)

  const stopped = await getUnleashCampaignStatus(
    { bundle: initial.run_directory },
    { now: h.deps.now },
  )

  assert.equal(stopped.status, 'STOPPED')
  assert.equal(stopped.revision, 4)
  assert.equal(stopped.stop_reason, reason)
  assert.equal((await storage.readJson('campaign-event-000003.json')).state.status, 'STOP_REQUESTED')
  assert.equal((await storage.readJson('campaign-event-000004.json')).state.status, 'STOPPED')
  const marker = JSON.parse(await readFile(join(initial.run_directory, 'recon', '.http-recon.stop'), 'utf8'))
  const nestedRun = JSON.parse(await readFile(join(initial.run_directory, 'recon', 'run.json'), 'utf8'))
  assert.equal(marker.reason, reason)
  assert.equal(marker.controller_policy_authority.mode, 'CONTROLLER_DEPLOYMENT_POLICY')
  assert.equal(nestedRun.state, 'STOPPED')
  assert.equal(h.calls.length, 0)

  const stoppedAgain = await stopUnleashCampaign({
    bundle: initial.run_directory,
    reason: 'later stop must remain idempotent',
  }, { now: h.deps.now })
  assert.equal(stoppedAgain.status, stopped.status)
  assert.equal(stoppedAgain.revision, stopped.revision)
  assert.equal(stoppedAgain.stop_reason, stopped.stop_reason)
  assert.deepEqual(stoppedAgain.failure, stopped.failure)
})

test('restart reissues a retained stop marker and settles after finalization becomes available', async (t) => {
  const h = await harness(t)
  const result = await completedCampaign(h)
  await rewindToRunning(result, h.runsRoot)
  const stopCalls = []

  await assert.rejects(
    stopUnleashCampaign({
      bundle: result.run_directory,
      reason: 'retain this reason across restart',
    }, {
      now: h.deps.now,
      requestHttpReconStop: async (request) => { stopCalls.push(request) },
      finalizeHttpReconBundle: async () => { throw new Error('synthetic finalizer interruption') },
    }),
    (error) => error.code === 'UNLEASH_STOP_RECONCILIATION_REQUIRED'
      && error.status === 'STOP_REQUESTED'
      && error.run_directory === result.run_directory,
  )

  const storage = await openUnleashCampaignStorage({
    runsRoot: h.runsRoot,
    campaignDirectory: basename(result.run_directory),
  })
  assert.equal((await storage.readJson('campaign-state.json')).status, 'STOP_REQUESTED')
  assert.equal((await storage.readJson('campaign-event-000003.json')).state.stop_reason, 'retain this reason across restart')

  const resumed = await resumeUnleashCampaign({ bundle: result.run_directory }, {
    now: h.deps.now,
    requestHttpReconStop: async (request) => { stopCalls.push(request) },
    finalizeHttpReconBundle: async () => ({ run: { state: 'STOPPED' } }),
  })

  assert.equal(resumed.status, 'STOPPED')
  assert.equal(resumed.revision, 4)
  assert.equal(resumed.stop_reason, 'retain this reason across restart')
  assert.equal(stopCalls.length, 2)
  assert.deepEqual(stopCalls.map(({ reason }) => reason), [
    'retain this reason across restart',
    'retain this reason across restart',
  ])
  assert.equal((await storage.readJson('campaign-event-000004.json')).state.status, 'STOPPED')
})

test('stop projects an uncertain nested outcome without replay and remains terminal on resume', async (t) => {
  const h = await harness(t)
  const result = await completedCampaign(h)
  await rewindToRunning(result, h.runsRoot)
  let stopRequests = 0
  let finalizations = 0

  const stopped = await stopUnleashCampaign({
    bundle: result.run_directory,
    reason: 'stop while delivery state is ambiguous',
  }, {
    now: h.deps.now,
    requestHttpReconStop: async () => { stopRequests += 1 },
    finalizeHttpReconBundle: async () => {
      finalizations += 1
      return { run: { state: 'OUTCOME_UNCERTAIN' } }
    },
  })

  assert.equal(stopped.status, 'OUTCOME_UNCERTAIN')
  assert.equal(stopped.revision, 4)
  assert.equal(stopped.stop_reason, 'stop while delivery state is ambiguous')
  assert.equal(stopped.failure.code, 'UNLEASH_RECON_OUTCOME_UNCERTAIN')
  assert.match(stopped.failure.message, /not replayed/u)
  assert.equal(stopRequests, 1)
  assert.equal(finalizations, 1)

  const resumed = await resumeUnleashCampaign({ bundle: result.run_directory }, {
    requestHttpReconStop: async () => { stopRequests += 1 },
    finalizeHttpReconBundle: async () => { finalizations += 1 },
    nextHttpReconAction: async () => { throw new Error('uncertain outcome must not select another action') },
    runHttpReconAction: async () => { throw new Error('uncertain outcome must not replay an action') },
  })
  assert.deepEqual(resumed, stopped)
  assert.equal(stopRequests, 1)
  assert.equal(finalizations, 1)
})

test('resume preserves stop intent when completion verification first requires reconciliation', async (t) => {
  const h = await harness(t)
  const result = await completedCampaign(h)
  await rewindToRunning(result, h.runsRoot)
  let stopRequests = 0

  const unresolved = await stopUnleashCampaign({
    bundle: result.run_directory,
    reason: 'stop intent survives evidence reconciliation',
  }, {
    now: h.deps.now,
    requestHttpReconStop: async () => { stopRequests += 1 },
    finalizeHttpReconBundle: async () => ({ run: { state: 'PROBE_PLAN_COMPLETE' } }),
    readVerifiedRecon: async () => ({ invalid: true }),
  })
  assert.equal(unresolved.status, 'RECONCILIATION_REQUIRED')
  assert.equal(unresolved.stop_reason, 'stop intent survives evidence reconciliation')

  const resumed = await resumeUnleashCampaign({ bundle: result.run_directory }, {
    now: h.deps.now,
    requestHttpReconStop: async () => { stopRequests += 1 },
    finalizeHttpReconBundle: async () => ({ run: { state: 'STOPPED' } }),
    nextHttpReconAction: async () => { throw new Error('retained stop intent must prevent action selection') },
    runHttpReconAction: async () => { throw new Error('retained stop intent must prevent dispatch') },
  })

  assert.equal(resumed.status, 'STOPPED')
  assert.equal(resumed.revision, 6)
  assert.equal(resumed.stop_reason, 'stop intent survives evidence reconciliation')
  assert.equal(stopRequests, 2)
  const storage = await openUnleashCampaignStorage({
    runsRoot: h.runsRoot,
    campaignDirectory: basename(result.run_directory),
  })
  assert.equal((await storage.readJson('campaign-event-000005.json')).state.status, 'STOP_REQUESTED')
  assert.equal((await storage.readJson('campaign-event-000006.json')).state.status, 'STOPPED')
})

test('resume validates retained authority and finalizes existing recon without another send', async (t) => {
  const h = await harness(t)
  const result = await completedCampaign(h)
  await rewindToRunning(result, h.runsRoot)
  let sends = 0

  const resumed = await resumeUnleashCampaign({ bundle: result.run_directory }, {
    policy: h.deps.policy,
    isRevoked: h.deps.isRevoked,
    now: h.deps.now,
    finalizeHttpReconBundle: async () => ({ run: { state: 'PROBE_PLAN_COMPLETE' } }),
    nextHttpReconAction: async () => { throw new Error('must not select an action after finalization') },
    runHttpReconAction: async () => { sends += 1 },
    readVerifiedRecon: h.deps.readVerifiedRecon,
  })

  assert.equal(resumed.status, 'COMPLETE_WITH_GAPS')
  assert.equal(resumed.revision, 3)
  assert.equal(sends, 0)
})

test('resume recovers an authoritative completion envelope when packet publication was interrupted', async (t) => {
  const h = await harness(t)
  const result = await completedCampaign(h)
  const storage = await openUnleashCampaignStorage({
    runsRoot: h.runsRoot,
    campaignDirectory: basename(result.run_directory),
  })
  const running = (await storage.readJson('campaign-event-000002.json')).state
  const envelope = await storage.readJson('https-recon-completion.json')
  await rm(join(result.run_directory, 'campaign-event-000003.json'))
  await rm(join(result.run_directory, 'evidence-packet.json'))
  await storage.replaceMutableJson('campaign-state.json', running)

  const resumed = await resumeUnleashCampaign({ bundle: result.run_directory }, {
    policy: h.deps.policy,
    isRevoked: h.deps.isRevoked,
    now: h.deps.now,
    finalizeHttpReconBundle: async () => ({ run: { state: 'PROBE_PLAN_COMPLETE' } }),
    nextHttpReconAction: async () => { throw new Error('completed recon must not select an action') },
    runHttpReconAction: async () => { throw new Error('completed recon must not send an action') },
    readVerifiedRecon: h.deps.readVerifiedRecon,
  })

  assert.equal(resumed.status, 'COMPLETE_WITH_GAPS')
  assert.deepEqual(await storage.readJson('https-recon-completion.json'), envelope)
  assert.deepEqual(await storage.readJson('evidence-packet.json'), envelope.evidence_packet)
  assert.equal((await storage.readJson('campaign-event-000003.json')).state.status, 'COMPLETE_WITH_GAPS')
})

test('resume refuses a derived packet without its authoritative completion envelope', async (t) => {
  const h = await harness(t)
  const result = await completedCampaign(h)
  const storage = await openUnleashCampaignStorage({
    runsRoot: h.runsRoot,
    campaignDirectory: basename(result.run_directory),
  })
  const running = (await storage.readJson('campaign-event-000002.json')).state
  await rm(join(result.run_directory, 'campaign-event-000003.json'))
  await rm(join(result.run_directory, 'https-recon-completion.json'))
  await storage.replaceMutableJson('campaign-state.json', running)

  const resumed = await resumeUnleashCampaign({ bundle: result.run_directory }, {
    policy: h.deps.policy,
    isRevoked: h.deps.isRevoked,
    now: h.deps.now,
    finalizeHttpReconBundle: async () => ({ run: { state: 'PROBE_PLAN_COMPLETE' } }),
    nextHttpReconAction: async () => { throw new Error('completed recon must not select an action') },
    runHttpReconAction: async () => { throw new Error('completed recon must not send an action') },
    readVerifiedRecon: h.deps.readVerifiedRecon,
  })

  assert.equal(resumed.status, 'RECONCILIATION_REQUIRED')
  assert.equal(resumed.revision, 3)
  assert.equal(resumed.evidence_packet_path, null)
  assert.equal((await storage.readJson('campaign-event-000003.json')).state.status, 'RECONCILIATION_REQUIRED')
})

test('resume terminalizes ambiguous delivery and never selects or repeats the action', async (t) => {
  const h = await harness(t)
  const result = await completedCampaign(h)
  await rewindToRunning(result, h.runsRoot)
  let selections = 0
  let sends = 0

  const resumed = await resumeUnleashCampaign({ bundle: result.run_directory }, {
    policy: h.deps.policy,
    isRevoked: h.deps.isRevoked,
    now: h.deps.now,
    finalizeHttpReconBundle: async () => ({ run: { state: 'OUTCOME_UNCERTAIN' } }),
    nextHttpReconAction: async () => { selections += 1 },
    runHttpReconAction: async () => { sends += 1 },
  })

  assert.equal(resumed.status, 'OUTCOME_UNCERTAIN')
  assert.match(resumed.failure.message, /not replayed/u)
  assert.equal(selections, 0)
  assert.equal(sends, 0)
})

test('resume finalizes first and dispatches only an untouched pending recon action', async (t) => {
  const h = await harness(t)
  const result = await completedCampaign(h)
  await rewindToRunning(result, h.runsRoot)
  const operations = []
  let finalizeCount = 0
  const retainedActionId = JSON.parse(await readFile(
    join(result.run_directory, 'campaign-action-risk-preflight.json'),
    'utf8',
  )).action_id

  const resumed = await resumeUnleashCampaign({ bundle: result.run_directory }, {
    policy: h.deps.policy,
    isRevoked: h.deps.isRevoked,
    now: h.deps.now,
    finalizeHttpReconBundle: async () => {
      finalizeCount += 1
      operations.push(`finalize:${finalizeCount}`)
      if (finalizeCount === 1) {
        throw Object.assign(new Error('one pending action'), { code: 'HTTP_RECON_PLAN_INCOMPLETE' })
      }
      return { run: { state: 'PROBE_PLAN_COMPLETE' } }
    },
    nextHttpReconAction: async () => {
      operations.push('next')
      return { action_id: retainedActionId, state: 'PENDING' }
    },
    runHttpReconAction: async (request) => {
      operations.push('run')
      assert.equal(request.actionId, retainedActionId)
      assert.equal(request.controllerPolicyAuthority.mode, 'CONTROLLER_DEPLOYMENT_POLICY')
      assert.equal(typeof request.revalidateAuthority, 'function')
      assert.equal(Object.hasOwn(request, 'operatorId'), false)
    },
    readVerifiedRecon: h.deps.readVerifiedRecon,
  })

  assert.equal(resumed.status, 'COMPLETE_WITH_GAPS')
  assert.deepEqual(operations, ['finalize:1', 'next', 'run', 'finalize:2'])
})

test('resume reconciles a thrown recon attempt and never interprets it as retry permission', async (t) => {
  const h = await harness(t)
  const result = await completedCampaign(h)
  await rewindToRunning(result, h.runsRoot)
  const operations = []
  let finalizeCount = 0
  const retainedActionId = JSON.parse(await readFile(
    join(result.run_directory, 'campaign-action-risk-preflight.json'),
    'utf8',
  )).action_id

  const resumed = await resumeUnleashCampaign({ bundle: result.run_directory }, {
    policy: h.deps.policy,
    isRevoked: h.deps.isRevoked,
    now: h.deps.now,
    finalizeHttpReconBundle: async () => {
      finalizeCount += 1
      operations.push(`finalize:${finalizeCount}`)
      if (finalizeCount === 1) {
        throw Object.assign(new Error('one pending action'), { code: 'HTTP_RECON_PLAN_INCOMPLETE' })
      }
      return { run: { state: 'OUTCOME_UNCERTAIN' } }
    },
    nextHttpReconAction: async () => {
      operations.push('next')
      return { action_id: retainedActionId, state: 'PENDING' }
    },
    runHttpReconAction: async () => {
      operations.push('run')
      throw new Error('synthetic post-dispatch process interruption')
    },
  })

  assert.equal(resumed.status, 'OUTCOME_UNCERTAIN')
  assert.deepEqual(operations, ['finalize:1', 'next', 'run', 'finalize:2'])
})

test('controller surfaces ambiguous event publication without writing a mutable snapshot', async (t) => {
  const h = await harness(t)
  let storage
  h.deps.createCampaignStorage = async (options) => {
    storage = await createUnleashCampaignStorage(options)
    return Object.freeze({
      ...storage,
      writeImmutableJson: async (filename, value) => {
        if (filename === 'campaign-event-000001.json') {
          throw Object.assign(new Error('synthetic uncertain commit'), { code: 'SYNTHETIC_COMMIT_UNCERTAIN' })
        }
        return storage.writeImmutableJson(filename, value)
      },
    })
  }

  let failure
  await assert.rejects(
    unleashTarget({ target: TARGET }, h.deps),
    (error) => {
      failure = error
      return error.code === 'UNLEASH_CAMPAIGN_RECONCILIATION_REQUIRED'
        && error.status === 'RECONCILIATION_REQUIRED'
    },
  )

  await assert.rejects(
    storage.readJson('campaign-state.json'),
    (error) => error.code === 'UNLEASH_STORAGE_FILE_NOT_FOUND',
  )
  assert.equal(h.calls.length, 0)
  assert.equal(failure.run_directory, storage.campaign_directory)
})

test('resume checks current policy, registry, and revocation before reconciliation or send', async (t) => {
  const h = await harness(t)
  const result = await completedCampaign(h)
  await rewindToRunning(result, h.runsRoot)
  let finalized = 0

  await assert.rejects(
    resumeUnleashCampaign({ bundle: result.run_directory }, {
      policy: h.deps.policy,
      isRevoked: () => true,
      now: h.deps.now,
      finalizeHttpReconBundle: async () => { finalized += 1 },
    }),
  )

  assert.equal(finalized, 0)
})
