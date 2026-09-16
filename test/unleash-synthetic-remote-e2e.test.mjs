import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash, X509Certificate } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { mkdir, mkdtemp, readFile, readdir, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { basename, dirname, join, resolve, win32 } from 'node:path'
import { test } from 'node:test'

import { runEngageCli } from '../scripts/engage.mjs'
import {
  getUnleashCampaignStatus,
  ingestUnleashCandidateProposal,
  unleashTarget,
} from '../scripts/lib/unleash-controller.mjs'
import { digestUnleashValue } from '../scripts/lib/unleash-contracts.mjs'
import { createUnleashDeploymentPolicy } from '../scripts/lib/unleash-policy.mjs'
import {
  readVerifiedHttpReconEvidence,
  validateHttpReconBundle,
} from '../scripts/lib/http-recon-controller.mjs'
import { probeHttps } from '../scripts/lib/http-recon-client.mjs'
import { REFERENCE_TLS_CERTIFICATE } from './fixtures/reference-transparency-tls.mjs'

const TARGET = 'https://reference-log.example.test/authorized'
const HOSTNAME = new URL(TARGET).hostname
const NOW = '2026-09-15T09:30:00.000Z'
const PUBLIC_ANSWER = Object.freeze({ address: '93.184.216.34', family: 4 })
const SCRATCH_PREFIX = 'last-aperture-unleash-synthetic-e2e-'
const CERTIFICATE = new X509Certificate(REFERENCE_TLS_CERTIFICATE)
const CERTIFICATE_OBJECT = CERTIFICATE.toLegacyObject()
const CERTIFICATE_SHA256 = createHash('sha256').update(CERTIFICATE.raw).digest('hex')
const SPKI_SHA256 = createHash('sha256')
  .update(CERTIFICATE.publicKey.export({ type: 'spki', format: 'der' }))
  .digest('hex')

function rawHeaders(headers) {
  const output = []
  for (const [name, rawValue] of Object.entries(headers)) {
    const values = Array.isArray(rawValue) ? rawValue : [rawValue]
    for (const value of values) output.push(name, String(value))
  }
  return output
}

class SyntheticTlsSocket extends EventEmitter {
  constructor() {
    super()
    this.encrypted = true
    this.authorized = true
    this.remoteAddress = PUBLIC_ANSWER.address
  }

  getProtocol() {
    return 'TLSv1.3'
  }

  getCipher() {
    return { standardName: 'TLS_AES_256_GCM_SHA384' }
  }
}

class SyntheticResponse extends EventEmitter {
  constructor({ headers, socket }) {
    super()
    this.statusCode = 200
    this.headers = headers
    this.rawHeaders = rawHeaders(headers)
    this.complete = true
    this.socket = socket
    this.destroyed = false
  }

  destroy(error) {
    this.destroyed = true
    this.destroyError = error
  }
}

class SyntheticRequest extends EventEmitter {
  constructor(onEnd) {
    super()
    this.onEnd = onEnd
    this.endArguments = null
    this.destroyed = false
  }

  end(...args) {
    assert.equal(this.endArguments, null, 'synthetic target received a repeated request')
    this.endArguments = args
    this.onEnd()
  }

  destroy(error) {
    this.destroyed = true
    this.destroyError = error
  }
}

function createSyntheticRemoteTarget() {
  const state = {
    dnsCalls: 0,
    httpsCalls: 0,
    trace: [],
    request: null,
    response: null,
    requestUrl: null,
    requestOptions: null,
    pinnedLookup: null,
  }

  const dnsLookup = (hostname, options, callback) => {
    state.dnsCalls += 1
    state.dnsHostname = hostname
    state.dnsOptions = structuredClone(options)
    state.trace.push(`dns:${hostname}`)
    queueMicrotask(() => callback(null, [{ ...PUBLIC_ANSWER }]))
  }

  const httpsRequest = (url, options) => {
    state.httpsCalls += 1
    state.requestUrl = url
    state.requestOptions = options
    state.trace.push(`https:${options.method}:${url.href}`)
    const socket = new SyntheticTlsSocket()
    const emitResponse = () => {
      state.trace.push('request:end')
      queueMicrotask(() => {
        if (state.request.destroyed) return
        const response = new SyntheticResponse({
          headers: {
            'content-type': 'text/plain; charset=utf-8',
            'strict-transport-security': 'max-age=31536000',
          },
          socket,
        })
        state.response = response
        state.trace.push('response:200')
        state.request.emit('response', response)
        if (!response.destroyed) response.emit('end')
      })
    }
    const request = new SyntheticRequest(emitResponse)
    state.request = request
    queueMicrotask(() => {
      options.lookup(url.hostname, { family: options.family }, (error, address, family) => {
        state.pinnedLookup = { error, address, family }
        state.trace.push(`pinned:${family}:${address}`)
        if (error) {
          request.emit('error', error)
          return
        }
        request.emit('socket', socket)
        const identityError = options.checkServerIdentity(url.hostname, CERTIFICATE_OBJECT)
        state.trace.push(identityError === undefined ? 'identity:verified' : 'identity:rejected')
        if (identityError) {
          request.emit('error', identityError)
          return
        }
        state.trace.push('tls:secure-connect')
        socket.emit('secureConnect')
      })
    })
    return request
  }

  let clockValue = 0
  state.dependencies = {
    dnsLookup,
    httpsRequest,
    clock: () => {
      clockValue += 5
      return clockValue
    },
  }
  return state
}

function deploymentPolicy() {
  return createUnleashDeploymentPolicy({
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-deployment-policy',
    policy_id: 'policy:synthetic-remote-e2e',
    valid_from: '2026-09-15T09:00:00.000Z',
    valid_until: '2026-09-15T10:00:00.000Z',
    allowed_origins: [new URL(TARGET).origin],
    allowed_target_families: ['https'],
    allowed_effects: ['OBSERVE'],
    budgets: {
      max_actions: 4,
      max_parallel_actions: 1,
      max_duration_ms: 900_000,
      max_response_bytes: 1_048_576,
    },
    credential_references: ['credential:browser:synthetic-e2e'],
    revocation: { check_id: 'revocation:synthetic-remote-e2e', fail_mode: 'CLOSED' },
  })
}

function captureIo() {
  const stdout = []
  const stderr = []
  return {
    stdout: { write: (value) => { stdout.push(String(value)); return true } },
    stderr: { write: (value) => { stderr.push(String(value)); return true } },
    stdoutText: () => stdout.join(''),
    stderrText: () => stderr.join(''),
  }
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

test('candidate ingress rejects computed fields before storage or provider data access', async () => {
  let getterCalls = 0
  const input = { bundle: resolve('campaign-0123456789abcdef01234567') }
  Object.defineProperty(input, 'proposal', {
    enumerable: true,
    get() {
      getterCalls += 1
      throw new Error('must not execute')
    },
  })

  await assert.rejects(
    ingestUnleashCandidateProposal(input),
    (error) => error?.code === 'UNLEASH_CAMPAIGN_INPUT_INVALID',
  )
  assert.equal(getterCalls, 0)
})

test('engage unleash completes one synthetic remote HEAD through real controller evidence', async (t) => {
  const temporaryParent = resolve(tmpdir())
  const scratch = await mkdtemp(join(temporaryParent, SCRATCH_PREFIX))
  t.after(async () => {
    const cleanupPath = resolve(scratch)
    assert.equal(dirname(cleanupPath), temporaryParent)
    assert.ok(basename(cleanupPath).startsWith(SCRATCH_PREFIX))
    await rm(cleanupPath, { recursive: true, force: true })
  })

  const runsRoot = join(scratch, 'LastAperture', 'campaigns')
  await mkdir(runsRoot, { recursive: true, mode: 0o700 })
  secureWindowsTestDirectory(runsRoot)
  const synthetic = createSyntheticRemoteTarget()
  const io = captureIo()
  let revocationChecks = 0
  let controllerResult

  const code = await runEngageCli(['unleash', TARGET, '--json'], {
    unleashTarget: async (input) => {
      controllerResult = await unleashTarget(input, {
        policy: deploymentPolicy(),
        unleashProviderProfile: {
          protocol_version: '1.0.0',
          proposal_kind: 'last-aperture/unleash-proposal'
        },
        now: () => new Date(NOW),
        isRevoked: () => { revocationChecks += 1; return false },
        runsRoot,
        randomBytes: (size) => Buffer.alloc(size, 0x5a),
        mkdir,
        httpReconProbe: (options) => probeHttps({
          ...options,
          dependencies: synthetic.dependencies,
        }),
      })
      return controllerResult
    },
    ...io,
  })

  assert.equal(code, 0, io.stderrText())
  assert.equal(io.stderrText(), '')
  assert.deepEqual(JSON.parse(io.stdoutText()), controllerResult)
  assert.equal(controllerResult.status, 'COMPLETE_WITH_GAPS')
  assert.equal(controllerResult.target.canonical_locator, TARGET)
  assert.deepEqual(controllerResult.completed_routes, ['https-recon'])
  assert.ok(controllerResult.gap_count > 0)
  assert.ok(revocationChecks >= 3)

  assert.equal(synthetic.dnsCalls, 1)
  assert.equal(synthetic.httpsCalls, 1)
  assert.equal(synthetic.dnsHostname, HOSTNAME)
  assert.deepEqual(synthetic.dnsOptions, { all: true, verbatim: true })
  assert.equal(synthetic.requestUrl.href, TARGET)
  assert.equal(synthetic.requestOptions.method, 'HEAD')
  assert.equal(synthetic.requestOptions.agent, false)
  assert.equal(synthetic.requestOptions.servername, HOSTNAME)
  assert.equal(synthetic.requestOptions.rejectUnauthorized, true)
  assert.equal(synthetic.requestOptions.minVersion, 'TLSv1.2')
  assert.deepEqual(synthetic.requestOptions.ALPNProtocols, ['http/1.1'])
  assert.equal(synthetic.requestOptions.headers.host, HOSTNAME)
  assert.equal(synthetic.requestOptions.headers['accept-encoding'], 'identity')
  assert.deepEqual(synthetic.request.endArguments, [])
  assert.deepEqual(synthetic.pinnedLookup, {
    error: null,
    address: PUBLIC_ANSWER.address,
    family: PUBLIC_ANSWER.family,
  })
  assert.deepEqual(synthetic.trace, [
    `dns:${HOSTNAME}`,
    `https:HEAD:${TARGET}`,
    `pinned:${PUBLIC_ANSWER.family}:${PUBLIC_ANSWER.address}`,
    'identity:verified',
    'tls:secure-connect',
    'request:end',
    'response:200',
  ])

  const reconBundle = join(controllerResult.run_directory, 'recon')
  const run = JSON.parse(await readFile(join(reconBundle, 'run.json'), 'utf8'))
  assert.equal(run.state, 'PROBE_PLAN_COMPLETE')
  assert.equal(run.authorization.mode, 'CONTROLLER_DEPLOYMENT_POLICY')
  assert.equal(run.authorization.policy_id, 'policy:synthetic-remote-e2e')
  assert.equal(run.actions.length, 1)
  assert.equal(run.actions[0].method, 'HEAD')
  assert.equal(run.actions[0].url, TARGET)
  assert.equal(run.actions[0].safe_to_get, false)
  assert.equal(run.actions[0].state, 'COMMITTED')
  assert.equal(run.actions[0].attempt_count, 1)
  assert.equal(Object.hasOwn(run.actions[0], 'request_headers'), false)
  assert.equal(run.budget.probe_requests_used, 1)
  assert.equal(run.budget.response_bytes_used, 0)

  const events = (await readFile(join(reconBundle, 'events.jsonl'), 'utf8'))
    .trim()
    .split('\n')
    .map((line) => JSON.parse(line))
  assert.deepEqual(events.map(({ type }) => type), [
    'PLAN_CREATED',
    'ACTION_LEASED',
    'ACTION_REQUEST_PRE_DISPATCH',
    'ACTION_COMMITTED',
    'RUN_FINALIZED',
  ])
  assert.equal(events[2].details.method, 'HEAD')
  assert.equal(events[2].details.url, TARGET)
  assert.equal(events[2].details.transport_identity.resolved_ip, PUBLIC_ANSWER.address)

  const observation = JSON.parse(await readFile(
    join(reconBundle, ...run.actions[0].observation_path.split('/')),
    'utf8',
  ))
  assert.equal(observation.method, 'HEAD')
  assert.equal(observation.url, TARGET)
  assert.equal(observation.status_code, 200)
  assert.equal(observation.authority.policy_id, run.authorization.policy_id)
  assert.equal(observation.body.bytes, null)
  assert.equal(observation.body.size, 0)
  assert.equal(observation.body.retained, false)
  assert.equal(observation.body.digest_scope, 'complete')
  assert.deepEqual(observation.network.dns_answers, [{ ...PUBLIC_ANSWER }])
  assert.equal(observation.network.resolved_ip, PUBLIC_ANSWER.address)
  assert.equal(observation.network.tls_verification, 'PKIX_HOSTNAME')
  assert.equal(observation.network.peer_certificate_sha256, CERTIFICATE_SHA256)
  assert.equal(observation.network.peer_spki_sha256, SPKI_SHA256)
  assert.equal(observation.stop_condition, null)
  assert.deepEqual(observation.response_headers, [
    { name: 'content-type', value: 'text/plain; charset=utf-8' },
    { name: 'strict-transport-security', value: 'max-age=31536000' },
  ])

  const validation = await validateHttpReconBundle({
    bundle: reconBundle,
    now: () => new Date(NOW),
  })
  assert.deepEqual(validation.errors, [])
  assert.equal(validation.valid, true)
  assert.equal(validation.state, 'PROBE_PLAN_COMPLETE')
  const verified = await readVerifiedHttpReconEvidence({
    bundle: reconBundle,
    now: () => new Date(NOW),
  })
  assert.equal(verified.run.run_id, run.run_id)
  assert.equal(verified.observations.length, 1)
  assert.deepEqual(verified.observations[0], observation)

  const packet = JSON.parse(await readFile(controllerResult.evidence_packet_path, 'utf8'))
  const completion = JSON.parse(await readFile(
    join(controllerResult.run_directory, 'https-recon-completion.json'),
    'utf8',
  ))
  assert.equal(packet.packet_sha256, controllerResult.evidence_packet_sha256)
  assert.equal(packet.plan_sha256, controllerResult.plan_sha256)
  assert.equal(packet.trust.input_authentication, 'LOCALLY_HASH_CHAIN_VERIFIED')
  assert.equal(packet.redaction.payload_values_included, false)
  assert.equal(packet.sources.length, 1)
  assert.equal(packet.sources[0].verifier_id, 'verifier:last-aperture-http-recon')
  assert.equal(completion.evidence_packet.packet_sha256, packet.packet_sha256)
  assert.equal(completion.completion_receipt.route_id, 'https-recon')
  assert.equal(
    completion.completion_receipt.completion_receipt_sha256,
    controllerResult.completion_receipt_sha256,
  )

  const proposal = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-proposal',
    proposal_id: 'proposal:synthetic-remote-e2e',
    plan_sha256: controllerResult.plan_sha256,
    provider_protocol_version: '1.0.0',
    candidates: [{
      candidate_id: 'candidate:synthetic-header-review',
      title: 'Review retained security header metadata',
      hypothesis: 'The retained response metadata may indicate a header hardening gap.',
      invariant: 'A verified finding requires an independent attack and control oracle.',
      confidence: 'LOW',
      evidence_refs: [packet.sources[0].evidence_ref],
      competing_explanations: ['The bounded HEAD response may omit route-specific behavior.'],
    }],
    actions: [{
      action_id: 'action:synthetic-header-review',
      candidate_id: 'candidate:synthetic-header-review',
      tool_id: 'tool:https-recon',
      evidence_refs: [packet.sources[0].evidence_ref],
      parameters: { method: 'HEAD' },
      expected_observation: 'A separately verified response distinguishes a finding from a candidate.',
    }],
  }
  const frontier = await ingestUnleashCandidateProposal({
    bundle: controllerResult.run_directory,
    proposal,
  }, { now: () => new Date(NOW) })
  assert.equal(frontier.proposal_count, 1)
  assert.equal(frontier.candidate_count, 1)
  assert.equal(frontier.proposed_action_count, 1)
  assert.equal(frontier.candidates[0].state, 'CANDIDATE')
  assert.equal(frontier.actions[0].state, 'PROPOSED_INERT')
  assert.equal(frontier.actions[0].executable, false)

  const replay = await ingestUnleashCandidateProposal({
    bundle: controllerResult.run_directory,
    proposal: structuredClone(proposal),
  }, { now: () => new Date(NOW) })
  assert.deepEqual(replay, frontier)
  const campaignFiles = await readdir(controllerResult.run_directory)
  assert.deepEqual(
    campaignFiles.filter((name) => /^candidate-admission-/u.test(name)),
    ['candidate-admission-000001.json'],
  )
  await assert.rejects(
    ingestUnleashCandidateProposal({
      bundle: controllerResult.run_directory,
      proposal: {
        ...structuredClone(proposal),
        candidates: [{ ...structuredClone(proposal.candidates[0]), title: 'Changed content' }],
      },
    }, { now: () => new Date(NOW) }),
    (error) => error?.code === 'UNLEASH_CANDIDATE_PROPOSAL_COLLISION',
  )

  const status = await getUnleashCampaignStatus(
    { bundle: controllerResult.run_directory },
    { now: () => new Date(NOW) },
  )
  assert.equal(status.kind, 'last-aperture/unleash-campaign-snapshot')
  assert.equal(status.status, controllerResult.status)
  assert.equal(status.plan_sha256, controllerResult.plan_sha256)
  assert.deepEqual(status.completed_routes, controllerResult.completed_routes)
  assert.equal(status.progress.candidate_count, 1)
  assert.equal(status.progress.proposed_action_count, 1)
  assert.equal(status.candidates.items[0].state, 'CANDIDATE')
  assert.equal(status.findings.count, 0)
  assert.equal(status.findings.clearance, 'NOT_ESTABLISHED')
  assert.equal(status.trust.absence_of_vulnerabilities, 'NOT_ESTABLISHED')
  assert.equal(status.controls.stop.enabled, false)
  assert.equal(status.controls.resume.enabled, false)
  const { snapshot_sha256: snapshotSha256, ...snapshotBody } = status
  assert.equal(snapshotSha256, digestUnleashValue(snapshotBody))
  assert.deepEqual(
    await getUnleashCampaignStatus(
      { bundle: controllerResult.run_directory },
      { now: () => new Date(NOW) },
    ),
    status,
  )
  assert.equal(synthetic.dnsCalls, 1)
  assert.equal(synthetic.httpsCalls, 1)
})
