import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { basename, dirname, join, resolve, win32 } from 'node:path'
import test from 'node:test'

import {
  confirmUnleashActionRisk,
  getUnleashCampaignStatus,
  pauseUnleashCampaign,
  resumeUnleashCampaign,
  rollbackUnleashCampaign,
  stopUnleashCampaign,
  unleashTarget,
} from '../scripts/lib/unleash-controller.mjs'
import { assertValidHttpReconRun } from '../scripts/lib/http-recon-contracts.mjs'
import { canonicalUnleashCampaignJson } from '../scripts/lib/unleash-campaign-storage.mjs'
import { createUnleashDeploymentPolicy } from '../scripts/lib/unleash-policy.mjs'
import { createUnleashReasoningAdapter } from '../scripts/lib/unleash-reasoning-adapter.mjs'
import { UNLEASH_SWARM_ROLE_SET } from '../scripts/lib/unleash-swarm-contracts.mjs'

const TARGET = 'https://example.test/'
const SCRATCH_PREFIX = 'last-aperture-controller-v2-e2e-'

function digestText(value) {
  return createHash('sha256').update(value).digest('hex')
}

function clock(start = '2026-09-15T09:30:00.000Z') {
  let milliseconds = Date.parse(start)
  return () => {
    const value = new Date(milliseconds)
    milliseconds += 1
    return value
  }
}

function deploymentPolicy() {
  return createUnleashDeploymentPolicy({
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-deployment-policy',
    policy_id: 'policy:controller-v2-e2e',
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
    credential_references: [],
    revocation: { check_id: 'revocation:controller-v2-e2e', fail_mode: 'CLOSED' },
  })
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

function controllerProbe(calls) {
  return async (options) => {
    calls.push({ method: options.method, url: options.url })
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
    return {
      schema_version: '1.0.0',
      requested_url: options.url,
      url: options.url,
      method: options.method,
      status: 200,
      response_headers: [{ name: 'content-type', value: 'text/html' }],
      response_header_summary: {
        retained_bytes: Buffer.byteLength('content-type: text/html\r\n'),
        omitted_count: 0,
        redacted_names: [],
        truncated: false,
      },
      body: {
        bytes: null,
        sha256: digestText(''),
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

function verifiedReconReader(evidenceCalls) {
  return async ({ bundle }) => {
    evidenceCalls.push(bundle)
    const campaignDirectory = dirname(bundle)
    const plan = JSON.parse(await readFile(join(campaignDirectory, 'campaign-plan.json'), 'utf8'))
    const authority = JSON.parse(await readFile(
      join(campaignDirectory, 'campaign-recon-authority.json'),
      'utf8',
    ))
    return {
      schema_version: '1.0.0',
      kind: 'last-aperture/verified-http-recon-evidence',
      run: {
        state: 'PROBE_PLAN_COMPLETE',
        run_id: 'run:controller-v2-e2e',
        plan_sha256: '6'.repeat(64),
        authorization: authority,
        target: { origin: new URL(plan.target.canonical_locator).origin },
        actions: [{ method: 'HEAD', url: plan.target.canonical_locator, safe_to_get: false }],
        event_chain: { count: 3, last_sha256: '8'.repeat(64) },
      },
      observations: [{
        authority: structuredClone(authority),
        method: 'HEAD',
        url: plan.target.canonical_locator,
      }],
    }
  }
}

function storageError(code, message, cause) {
  const error = new Error(message, cause === undefined ? undefined : { cause })
  error.code = code
  return error
}

function temporaryCampaignStorage(runsRoot, campaignDirectory) {
  const campaignPath = join(runsRoot, campaignDirectory)
  let tail = Promise.resolve()
  const serialized = (operation) => {
    const result = tail.then(operation, operation)
    tail = result.catch(() => {})
    return result
  }
  return Object.freeze({
    runs_root: runsRoot,
    campaign_directory: campaignPath,
    writeImmutableJson(filename, value) {
      return serialized(async () => {
        try {
          await writeFile(
            join(campaignPath, filename),
            canonicalUnleashCampaignJson(value),
            { encoding: 'utf8', flag: 'wx', mode: 0o600 },
          )
        } catch (cause) {
          if (cause?.code === 'EEXIST') {
            throw storageError('UNLEASH_STORAGE_FILE_EXISTS', 'immutable campaign JSON exists', cause)
          }
          throw cause
        }
      })
    },
    replaceMutableJson(filename, value) {
      return serialized(() => writeFile(
        join(campaignPath, filename),
        canonicalUnleashCampaignJson(value),
        { encoding: 'utf8', mode: 0o600 },
      ))
    },
    readJson(filename) {
      return serialized(async () => {
        try {
          return JSON.parse(await readFile(join(campaignPath, filename), 'utf8'))
        } catch (cause) {
          if (cause?.code === 'ENOENT') {
            throw storageError('UNLEASH_STORAGE_FILE_NOT_FOUND', 'campaign JSON is missing', cause)
          }
          throw cause
        }
      })
    },
    listJsonFilenames() {
      return serialized(async () => (await readdir(campaignPath))
        .filter((filename) => filename.endsWith('.json'))
        .sort())
    },
  })
}

function temporaryStorageDependencies() {
  return {
    async createCampaignStorage({ runsRoot, campaignDirectory }) {
      await mkdir(join(runsRoot, campaignDirectory), { recursive: false, mode: 0o700 })
      return temporaryCampaignStorage(runsRoot, campaignDirectory)
    },
    async openCampaignStorage({ runsRoot, campaignDirectory }) {
      return temporaryCampaignStorage(runsRoot, campaignDirectory)
    },
  }
}

async function harness(t, { policy, reasoningAdapters } = {}) {
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
  const reconCalls = []
  const evidenceCalls = []
  const now = clock()
  return {
    reconCalls,
    evidenceCalls,
    deps: {
      policy: policy ?? deploymentPolicy(),
      isRevoked: () => false,
      runsRoot,
      now,
      randomBytes: (size) => Buffer.alloc(size, 0x42),
      httpReconProbe: controllerProbe(reconCalls),
      readVerifiedRecon: verifiedReconReader(evidenceCalls),
      ...temporaryStorageDependencies(),
      ...(reasoningAdapters === undefined ? {} : { reasoningAdapters }),
    },
  }
}

function parseControl(envelope) {
  const manifest = envelope.request.artifacts.find(({ kind }) => kind === 'CONTROL')
  assert.ok(manifest, 'BORG role request must carry the controller-owned frontier')
  const payload = envelope.artifact_payloads.find(
    ({ artifact_id: artifactId }) => artifactId === manifest.artifact_id,
  )
  assert.ok(payload, 'BORG role request must carry its bound control bytes')
  return JSON.parse(Buffer.from(payload.content_base64, 'base64').toString('utf8'))
}

function roleResponse(envelope) {
  const { request } = envelope
  const evidenceRef = request.evidence_refs[0]
  const duplicateSource = ['attacker:perimeter', 'attacker:api'].includes(request.role_id)
  const candidateId = `candidate:${request.role_id.replaceAll(':', '-')}:r${request.round}`
  const candidates = duplicateSource
    ? [{
        candidate_id: candidateId,
        title: request.role_id === 'attacker:perimeter'
          ? 'Potential implementation disclosure'
          : 'Implementation version may be exposed',
        hypothesis: 'The verified response may disclose a stable implementation version.',
        invariant: 'Production responses should not expose unnecessary exact implementation versions.',
        confidence: request.role_id === 'attacker:perimeter' ? 'HIGH' : 'LOW',
        evidence_refs: [evidenceRef],
        competing_explanations: ['The response token may be an edge compatibility marker.'],
      }]
    : []
  const actions = duplicateSource
    ? [{
        action_id: `action:${request.role_id.replaceAll(':', '-')}:r${request.round}`,
        candidate_id: candidateId,
        tool_id: request.allowed_tool_ids[0],
        evidence_refs: [evidenceRef],
        parameters: { method: 'HEAD' },
        expected_observation: 'A repeated controller observation distinguishes a stable disclosure.',
      }]
    : []
  const control = parseControl(envelope)
  const challengedCandidate = control.merge.candidates[0]?.candidate_id
  const challenges = request.wave === 'REVIEW' && challengedCandidate !== undefined
    ? [{
        challenge_id: `challenge:${request.role_id.replaceAll(':', '-')}:r${request.round}`,
        candidate_id: challengedCandidate,
        disposition: 'INSUFFICIENT_EVIDENCE',
        reason: 'One bounded observation cannot establish route-wide behavior.',
        evidence_refs: [evidenceRef],
        competing_explanations: ['A downstream route may remove the token.'],
      }]
    : []
  return {
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
      proposal_id: `proposal:${request.role_id.replaceAll(':', '-')}:r${request.round}`,
      plan_sha256: request.plan_sha256,
      provider_protocol_version: '2.0.0',
      candidates,
      actions,
    },
    challenges,
  }
}

function borgAssignments(metrics, { beforeResponse } = {}) {
  const identity = {
    adapter_id: 'adapter:controller-v2-e2e',
    adapter_version: '1.0.0',
    adapter_config_sha256: digestText('controller-v2-e2e-config'),
  }
  const adapter = createUnleashReasoningAdapter({
    identity,
    async invoke(envelope) {
      metrics.calls.push({
        role_id: envelope.request.role_id,
        round: envelope.request.round,
        wave: envelope.request.wave,
      })
      await beforeResponse?.(envelope)
      return Buffer.from(JSON.stringify(roleResponse(envelope)), 'utf8')
    },
  })
  return UNLEASH_SWARM_ROLE_SET.roles.map(({ role_id: roleId }) => ({ roleId, adapter }))
}

function nearLimitRoleResponse(envelope) {
  const response = roleResponse(envelope)
  response.proposal.actions = []
  response.challenges = []
  response.proposal.candidates = (
    envelope.request.round === 1
    && envelope.request.role_id === 'attacker:perimeter'
  )
    ? Array.from({ length: 25 }, (_, index) => {
        const label = String(index).padStart(3, '0')
        const padding = 'x'.repeat(2_300)
        return {
          candidate_id: `candidate:near-limit-${label}`,
          title: `Near-limit candidate ${label}`,
          hypothesis: `Near-limit hypothesis ${label} ${padding}`,
          invariant: `Near-limit invariant ${label} ${padding}`,
          confidence: 'MEDIUM',
          evidence_refs: [envelope.request.evidence_refs[0]],
          competing_explanations: [],
        }
      })
    : []
  return response
}

function nearLimitBorgAssignments(metrics) {
  const identity = {
    adapter_id: 'adapter:controller-v2-near-limit-e2e',
    adapter_version: '1.0.0',
    adapter_config_sha256: digestText('controller-v2-near-limit-e2e-config'),
  }
  const adapter = createUnleashReasoningAdapter({
    identity,
    async invoke(envelope) {
      metrics.calls += 1
      return Buffer.from(JSON.stringify(nearLimitRoleResponse(envelope)), 'utf8')
    },
  })
  return UNLEASH_SWARM_ROLE_SET.roles.map(({ role_id: roleId }) => ({ roleId, adapter }))
}

async function campaignFiles(runDirectory) {
  return (await readdir(runDirectory)).sort()
}

test('action-risk preflight blocks exact cautious dispatch until receipt-bound confirmation', { timeout: 180_000 }, async (t) => {
  const policyInput = structuredClone(deploymentPolicy())
  policyInput.detection = {
    noise_profile: 'CAUTIOUS',
    target_environment: 'PRODUCTION',
    risk_tolerance: 'LOW',
    confirmation_mode: 'REQUIRED',
  }
  const h = await harness(t, {
    policy: createUnleashDeploymentPolicy(policyInput),
  })
  const surfacedPreflights = []
  h.deps.onActionRiskPreflight = async (preflight) => {
    assert.deepEqual(h.reconCalls, [])
    surfacedPreflights.push(preflight)
  }

  const pending = await unleashTarget({ target: TARGET }, h.deps)
  const bundle = pending.run_directory
  assert.equal(pending.status, 'RUNNING')
  assert.equal(pending.detection.state, 'CONFIRMATION_REQUIRED')
  assert.equal(pending.detection.profile, 'cautious')
  assert.equal(
    pending.detection.detection_pattern_model_id,
    'last-aperture/generic-defender-detection-patterns',
  )
  assert.equal(pending.detection.detection_pattern_model_version, '1.0.0')
  assert.deepEqual(pending.detection.matched_pattern_ids, ['pattern:single-request'])
  assert.equal(pending.detection.methodology, 'HEURISTIC_UNCALIBRATED')
  assert.equal(
    pending.detection.control_signal_score_semantics,
    'RELATIVE_EXPOSURE_NOT_ALERT_PROBABILITY',
  )
  assert.equal(pending.detection.telemetry_coverage, 'UNKNOWN')
  assert.equal(pending.detection.collection_precondition, 'UNKNOWN')
  assert.deepEqual(h.reconCalls, [])
  assert.equal(surfacedPreflights.length, 1)
  assert.deepEqual(surfacedPreflights[0], pending.detection)

  const preflight = JSON.parse(await readFile(
    join(bundle, 'campaign-action-risk-preflight.json'),
    'utf8',
  ))
  assert.equal(preflight.action_id, pending.detection.action_id)
  assert.equal(preflight.receipt.assessment_sha256, pending.detection.assessment_sha256)
  assert.equal(preflight.receipt.assessment.operational_profile, 'cautious')
  assert.equal(preflight.receipt.assessment.controller_confirmation_required, true)
  assert.equal(preflight.receipt.profile_constraints_met, true)
  const beforeConfirmation = await getUnleashCampaignStatus({ bundle }, h.deps)
  assert.equal(beforeConfirmation.detection.state, 'CONFIRMATION_REQUIRED')
  assert.equal(beforeConfirmation.detection.confirmation_sha256, null)
  assert.deepEqual(h.reconCalls, [])

  await assert.rejects(
    () => confirmUnleashActionRisk({
      bundle,
      actionId: pending.detection.action_id,
      assessmentSha256: '0'.repeat(64),
      reason: 'reviewed exact action risk',
    }, h.deps),
    (error) => error?.code === 'UNLEASH_ACTION_RISK_CONFIRMATION_MISMATCH',
  )
  assert.deepEqual(h.reconCalls, [])

  const completed = await confirmUnleashActionRisk({
    bundle,
    actionId: pending.detection.action_id,
    assessmentSha256: pending.detection.assessment_sha256,
    reason: 'reviewed exact action and expected detection impact',
  }, h.deps)
  assert.equal(completed.status, 'COMPLETE_WITH_GAPS')
  assert.equal(surfacedPreflights.length, 2)
  assert.equal(surfacedPreflights[1].state, 'ADMITTED')
  assert.equal(surfacedPreflights[1].assessment_sha256, pending.detection.assessment_sha256)
  assert.deepEqual(h.reconCalls, [{ method: 'HEAD', url: TARGET }])

  const status = await getUnleashCampaignStatus({ bundle }, h.deps)
  assert.equal(status.detection.state, 'ADMITTED')
  assert.deepEqual(status.detection.matched_pattern_ids, ['pattern:single-request'])
  assert.equal(status.detection.confirmation_required, true)
  assert.match(status.detection.confirmation_sha256, /^[a-f0-9]{64}$/u)
  assert.equal(status.swarm.phase, 'SEALED')
  const confirmation = JSON.parse(await readFile(
    join(bundle, 'campaign-action-risk-confirmation.json'),
    'utf8',
  ))
  assert.equal(confirmation.action_id, pending.detection.action_id)
  assert.equal(
    confirmation.confirmation.assessment_sha256,
    pending.detection.assessment_sha256,
  )
  assert.equal(confirmation.confirmation.confirmed, true)
})

test('target-only controller runs and seals the protocol-v2 BORG lifecycle without replay', async (t) => {
  const metrics = { calls: [] }
  const h = await harness(t, { reasoningAdapters: borgAssignments(metrics) })

  const completed = await unleashTarget({ target: TARGET }, h.deps)

  assert.equal(completed.status, 'COMPLETE_WITH_GAPS')
  assert.equal(completed.target.canonical_locator, TARGET)
  assert.deepEqual(h.reconCalls, [{ method: 'HEAD', url: TARGET }])
  assert.equal(metrics.calls.length, 14)
  assert.deepEqual(new Set(metrics.calls.map(({ wave }) => wave)), new Set(['ATTACK', 'REVIEW']))
  assert.deepEqual(
    new Set(metrics.calls.map(({ role_id: roleId }) => roleId)),
    new Set(UNLEASH_SWARM_ROLE_SET.roles.map(({ role_id: roleId }) => roleId)),
  )
  assert.deepEqual(new Set(metrics.calls.map(({ round }) => round)), new Set([1, 2]))

  const firstStatus = await getUnleashCampaignStatus(
    { bundle: completed.run_directory },
    { now: h.deps.now },
  )
  assert.equal(firstStatus.schema_version, '2.0.0')
  assert.deepEqual(firstStatus.swarm.gaps.items, [])
  assert.equal(firstStatus.status, 'COMPLETE_WITH_GAPS')
  assert.equal(firstStatus.findings.count, 0)
  assert.deepEqual(firstStatus.findings.items, [])
  assert.equal(firstStatus.progress.verified_finding_count, 0)
  assert.equal(firstStatus.swarm.phase, 'SEALED')
  assert.equal(firstStatus.swarm.terminal_status, 'QUIESCENT')
  assert.equal(firstStatus.swarm.terminal_reason, 'FRONTIER_STABLE')
  assert.equal(firstStatus.swarm.hypotheses.count, 1)
  assert.equal(firstStatus.swarm.proposed_actions.count, 1)
  assert.equal(firstStatus.swarm.challenges.count, 1)
  assert.equal(firstStatus.candidates.count, 1)
  assert.equal(firstStatus.bindings.proposal_count, 1)
  assert.equal(firstStatus.bindings.candidate_count, 1)
  assert.equal(firstStatus.bindings.proposed_action_count, 1)
  assert.equal(firstStatus.swarm.proposed_actions.items[0].state, 'PROPOSED_INERT')
  assert.equal(firstStatus.swarm.proposed_actions.items[0].executable, false)
  assert.equal(firstStatus.swarm_completion_sha256, firstStatus.swarm.completion_sha256)
  assert.equal(firstStatus.swarm_completion_sha256, firstStatus.bindings.swarm_completion_sha256)
  assert.equal(firstStatus.candidate_frontier_sha256, firstStatus.bindings.candidate_frontier_sha256)
  assert.equal(
    firstStatus.candidate_frontier_head_sha256,
    firstStatus.bindings.candidate_frontier_head_sha256,
  )
  assert.equal(firstStatus.swarm.frontier_sha256, firstStatus.bindings.swarm_frontier_sha256)

  const files = await campaignFiles(completed.run_directory)
  assert.equal(files.filter((name) => /^candidate-admission-[0-9]{6}\.json$/u.test(name)).length, 1)
  assert.equal(files.includes('swarm-completion.json'), true)
  assert.equal(files.includes('swarm-terminal-fence.json'), true)
  assert.equal(
    JSON.parse(await readFile(join(completed.run_directory, 'swarm-terminal-fence.json'), 'utf8')).decision,
    'SEAL',
  )
  const retainedCompletion = JSON.parse(await readFile(
    join(completed.run_directory, 'swarm-completion.json'),
    'utf8',
  ))
  assert.equal(retainedCompletion.completion_sha256, firstStatus.swarm_completion_sha256)
  assert.equal(retainedCompletion.frontier_sha256, firstStatus.swarm.frontier_sha256)

  const callsBeforeReopen = metrics.calls.length
  const secondStatus = await getUnleashCampaignStatus(
    { bundle: completed.run_directory },
    { now: h.deps.now },
  )
  assert.equal(secondStatus.status, firstStatus.status)
  assert.equal(secondStatus.bindings.state_sha256, firstStatus.bindings.state_sha256)
  assert.equal(secondStatus.swarm_completion_sha256, firstStatus.swarm_completion_sha256)
  const resumed = await resumeUnleashCampaign(
    { bundle: completed.run_directory },
    { ...h.deps, isRevoked: () => true },
  )
  assert.equal(resumed.status, 'COMPLETE_WITH_GAPS')
  assert.equal(metrics.calls.length, callsBeforeReopen)
  assert.equal(h.reconCalls.length, 1)
})

test('carries a near-limit merged frontier through sealing, status, and recovery without replay', { timeout: 180_000 }, async (t) => {
  const metrics = { calls: 0 }
  const h = await harness(t, { reasoningAdapters: nearLimitBorgAssignments(metrics) })
  const completed = await unleashTarget({ target: TARGET }, h.deps)
  const bundle = completed.run_directory
  const completion = JSON.parse(await readFile(join(bundle, 'swarm-completion.json'), 'utf8'))
  const mergeNames = (await campaignFiles(bundle))
    .filter((filename) => /^swarm-merge-r[0-9]{2}-(?:attack|review)\.json$/u.test(filename))
  const finalMergeName = mergeNames.at(-1)
  const merge = JSON.parse(await readFile(join(bundle, finalMergeName), 'utf8'))
  const mergeBytes = Buffer.byteLength(canonicalUnleashCampaignJson(merge), 'utf8')
  const fence = JSON.parse(await readFile(join(bundle, 'swarm-terminal-fence.json'), 'utf8'))
  const admission = JSON.parse(await readFile(join(bundle, 'candidate-admission-000001.json'), 'utf8'))
  const firstStatus = await getUnleashCampaignStatus({ bundle }, { now: h.deps.now })
  const snapshotBytes = Buffer.byteLength(canonicalUnleashCampaignJson(firstStatus), 'utf8')

  assert.equal(completed.status, 'COMPLETE_WITH_GAPS')
  assert.equal(metrics.calls, 14)
  assert.equal(h.reconCalls.length, 1)
  assert.equal(merge.candidate_count, 25)
  assert.ok(262_144 - mergeBytes >= 0)
  assert.ok(262_144 - mergeBytes < 16_384)
  assert.equal(completion.merge_sha256, merge.merge_sha256)
  assert.equal(fence.decision, 'SEAL')
  assert.equal(fence.swarm_merge_sha256, merge.merge_sha256)
  assert.equal(admission.swarm_merge_sha256, merge.merge_sha256)
  assert.equal(firstStatus.swarm.merge_sha256, merge.merge_sha256)
  assert.equal(firstStatus.bindings.swarm_merge_sha256, merge.merge_sha256)
  assert.equal(firstStatus.swarm.hypotheses.count, 25)
  assert.equal(firstStatus.candidates.count, 25)
  assert.ok(snapshotBytes < 1_048_576)
  t.diagnostic(`near-limit merge bytes: ${mergeBytes}; snapshot bytes: ${snapshotBytes}`)

  await rm(join(bundle, 'candidate-frontier-state.json'))
  const callsBeforeRecovery = metrics.calls
  const reconCallsBeforeRecovery = h.reconCalls.length
  const recovered = await resumeUnleashCampaign({ bundle }, h.deps)
  const secondStatus = await getUnleashCampaignStatus({ bundle }, { now: h.deps.now })
  assert.equal(recovered.status, 'COMPLETE_WITH_GAPS')
  assert.equal(metrics.calls, callsBeforeRecovery)
  assert.equal(h.reconCalls.length, reconCallsBeforeRecovery)
  assert.equal(secondStatus.bindings.state_sha256, firstStatus.bindings.state_sha256)
  assert.equal(secondStatus.bindings.swarm_merge_sha256, merge.merge_sha256)
  assert.equal(secondStatus.bindings.candidate_frontier_sha256, firstStatus.bindings.candidate_frontier_sha256)
  assert.equal(secondStatus.swarm.hypotheses.sha256, firstStatus.swarm.hypotheses.sha256)
})

test('target-only default seals seven explicit adapter gaps and one empty admission', async (t) => {
  const h = await harness(t)

  const completed = await unleashTarget({ target: TARGET }, h.deps)
  const status = await getUnleashCampaignStatus(
    { bundle: completed.run_directory },
    { now: h.deps.now },
  )

  assert.equal(completed.status, 'COMPLETE_WITH_GAPS')
  assert.deepEqual(h.reconCalls, [{ method: 'HEAD', url: TARGET }])
  assert.equal(status.swarm.phase, 'SEALED')
  assert.equal(status.swarm.gaps.count, 7)
  assert.equal(status.swarm.gaps.state_count, 7)
  assert.equal(new Set(status.swarm.gaps.items.map(({ role_id: roleId }) => roleId)).size, 7)
  assert.equal(
    status.swarm.gaps.items.every(
      ({ reason_code: reasonCode }) => reasonCode === 'REASONING_ADAPTER_UNAVAILABLE',
    ),
    true,
  )
  assert.equal(status.swarm.hypotheses.count, 0)
  assert.equal(status.swarm.proposed_actions.count, 0)
  assert.equal(status.findings.count, 0)
  assert.equal(status.bindings.proposal_count, 1)
  assert.equal(status.bindings.candidate_count, 0)
  assert.equal(status.bindings.proposed_action_count, 0)

  const files = await campaignFiles(completed.run_directory)
  const admissions = files.filter((name) => /^candidate-admission-[0-9]{6}\.json$/u.test(name))
  assert.deepEqual(admissions, ['candidate-admission-000001.json'])
  const admission = JSON.parse(await readFile(join(completed.run_directory, admissions[0]), 'utf8'))
  assert.deepEqual(admission.proposal.candidates, [])
  assert.deepEqual(admission.proposal.actions, [])

  const callsBeforeResume = h.reconCalls.length
  assert.equal((await resumeUnleashCampaign(
    { bundle: completed.run_directory },
    h.deps,
  )).status, 'COMPLETE_WITH_GAPS')
  assert.equal(h.reconCalls.length, callsBeforeResume)

  const transientPublicationGaps = [
    ['campaign-state.json', 'UNLEASH_CAMPAIGN_SNAPSHOT_STALE'],
    ['swarm-attempt-ledger-state.json', 'UNLEASH_SWARM_LEDGER_STATE_STALE'],
    ['candidate-frontier-state.json', 'UNLEASH_CANDIDATE_FRONTIER_STATE_STALE'],
  ]
  for (const [targetFilename, code] of transientPublicationGaps) {
    let injected = false
    const retried = await getUnleashCampaignStatus({ bundle: completed.run_directory }, {
      ...h.deps,
      openCampaignStorage: async (options) => {
        const storage = await h.deps.openCampaignStorage(options)
        return Object.freeze({
          ...storage,
          readJson: async (filename) => {
            if (!injected && filename === targetFilename) {
              injected = true
              const cause = new Error(`injected ${code}`)
              cause.code = code
              throw cause
            }
            return storage.readJson(filename)
          },
        })
      },
    })
    assert.equal(injected, true)
    assert.equal(retried.status, 'COMPLETE_WITH_GAPS')
    assert.equal(retried.bindings.state_sha256, status.bindings.state_sha256)
  }

  const eventNames = (await campaignFiles(completed.run_directory))
    .filter((name) => /^campaign-event-[0-9]{6}\.json$/u.test(name))
  const eventStates = await Promise.all(eventNames.map(async (name) => (
    JSON.parse(await readFile(join(completed.run_directory, name), 'utf8')).state
  )))
  const staleRunningState = eventStates.find((state) => (
    state.status === 'RUNNING' && state.swarm_basis_sha256 === null
  ))
  assert.ok(staleRunningState)
  await writeFile(
    join(completed.run_directory, 'campaign-state.json'),
    canonicalUnleashCampaignJson(staleRunningState),
    'utf8',
  )
  const readOnlyStatus = await getUnleashCampaignStatus(
    { bundle: completed.run_directory },
    { now: h.deps.now },
  )
  assert.equal(readOnlyStatus.status, 'COMPLETE_WITH_GAPS')
  assert.equal(
    JSON.parse(await readFile(join(completed.run_directory, 'campaign-state.json'), 'utf8')).status,
    'RUNNING',
  )
  const repairedByOwnedResume = await resumeUnleashCampaign(
    { bundle: completed.run_directory },
    h.deps,
  )
  assert.equal(repairedByOwnedResume.status, 'COMPLETE_WITH_GAPS')
  assert.equal(
    JSON.parse(await readFile(join(completed.run_directory, 'campaign-state.json'), 'utf8')).status,
    'COMPLETE_WITH_GAPS',
  )
})

test('status verifies the basis-publication crash window and resume continues without replaying recon', { timeout: 180_000 }, async (t) => {
  const h = await harness(t)
  const completed = await unleashTarget({ target: TARGET }, h.deps)
  const bundle = completed.run_directory
  const names = await campaignFiles(bundle)
  const events = []
  for (const name of names.filter((entry) => /^campaign-event-[0-9]{6}\.json$/u.test(entry))) {
    events.push(JSON.parse(await readFile(join(bundle, name), 'utf8')))
  }
  const runningEvent = events.find(({ state }) => (
    state.status === 'RUNNING' && state.swarm_basis_sha256 === null
  ))
  assert.ok(runningEvent)

  for (const name of names) {
    const eventMatch = /^campaign-event-([0-9]{6})\.json$/u.exec(name)
    const laterCampaignEvent = eventMatch !== null
      && Number(eventMatch[1]) > runningEvent.state.revision
    const derivedSwarmArtifact = name === 'candidate-frontier-state.json'
      || name === 'swarm-attempt-ledger-state.json'
      || name === 'swarm-completion.json'
      || name === 'swarm-terminal-fence.json'
      || /^candidate-admission-[0-9]{6}\.json$/u.test(name)
      || /^swarm-attempt-event-[0-9]{6}\.json$/u.test(name)
      || /^swarm-merge-r[0-9]{2}-(?:attack|review)\.json$/u.test(name)
    if (laterCampaignEvent || derivedSwarmArtifact) await rm(join(bundle, name))
  }
  await writeFile(
    join(bundle, 'campaign-state.json'),
    canonicalUnleashCampaignJson(runningEvent.state),
    'utf8',
  )

  const callsBeforeStatus = h.reconCalls.length
  const status = await getUnleashCampaignStatus({ bundle }, { now: h.deps.now })
  assert.equal(status.kind, 'last-aperture/unleash-campaign-snapshot')
  assert.equal(status.status, 'RUNNING')
  assert.equal(status.swarm_basis_sha256, null)
  assert.equal(status.swarm.phase, 'BASIS_READY')
  assert.match(status.swarm.basis_sha256, /^[a-f0-9]{64}$/u)
  assert.equal(status.findings.count, 0)
  assert.equal(h.reconCalls.length, callsBeforeStatus)

  const resumed = await resumeUnleashCampaign({ bundle }, {
    ...h.deps,
    now: clock('2026-09-15T09:32:00.000Z'),
  })
  assert.equal(resumed.status, 'COMPLETE_WITH_GAPS')
  assert.equal(h.reconCalls.length, callsBeforeStatus)
})

test('two resumes before completion publication admit one owner and never replay recon', { timeout: 180_000 }, async (t) => {
  const h = await harness(t)
  const completed = await unleashTarget({ target: TARGET }, h.deps)
  const bundle = completed.run_directory
  const names = await campaignFiles(bundle)
  const events = []
  for (const name of names.filter((entry) => /^campaign-event-[0-9]{6}\.json$/u.test(entry))) {
    events.push(JSON.parse(await readFile(join(bundle, name), 'utf8')))
  }
  const runningEvent = events.find(({ state }) => (
    state.status === 'RUNNING' && state.swarm_basis_sha256 === null
  ))
  assert.ok(runningEvent)

  for (const name of names) {
    const eventMatch = /^campaign-event-([0-9]{6})\.json$/u.exec(name)
    const laterCampaignEvent = eventMatch !== null
      && Number(eventMatch[1]) > runningEvent.state.revision
    const completionOrSwarmArtifact = [
      'evidence-packet.json',
      'https-recon-completion.json',
      'swarm-basis.json',
    ].includes(name)
      || (name.startsWith('swarm-') && name !== 'swarm-owner-lock')
      || name.startsWith('candidate-')
    if (laterCampaignEvent || completionOrSwarmArtifact) await rm(join(bundle, name))
  }
  await writeFile(
    join(bundle, 'campaign-state.json'),
    canonicalUnleashCampaignJson(runningEvent.state),
    'utf8',
  )

  let announceVerification
  let releaseVerification
  const verificationStarted = new Promise((resolveStarted) => { announceVerification = resolveStarted })
  const release = new Promise((resolveRelease) => { releaseVerification = resolveRelease })
  t.after(() => releaseVerification())
  const baseReader = h.deps.readVerifiedRecon
  let verificationCalls = 0
  const recoveryDependencies = {
    ...h.deps,
    now: clock('2026-09-15T09:32:00.000Z'),
    readVerifiedRecon: async (input) => {
      verificationCalls += 1
      if (verificationCalls === 1) {
        announceVerification()
        await release
      }
      return baseReader(input)
    },
  }

  const firstResume = resumeUnleashCampaign({ bundle }, recoveryDependencies)
  await verificationStarted
  const deferredResume = await resumeUnleashCampaign({ bundle }, recoveryDependencies)
  assert.equal(deferredResume.status, 'RUNNING')
  assert.deepEqual(deferredResume.resume_control, {
    state: 'ACTIVE_SWARM_OWNER',
    takeover: 'DEFERRED_WHILE_EXCLUSIVE_OWNER_IS_LIVE',
  })
  assert.equal(verificationCalls, 1)
  assert.equal(h.reconCalls.length, 1)

  releaseVerification()
  const recovered = await firstResume
  assert.equal(recovered.status, 'COMPLETE_WITH_GAPS')
  assert.equal(verificationCalls >= 2, true)
  assert.equal(h.reconCalls.length, 1)
  assert.deepEqual(
    (await readdir(bundle)).filter((name) => name.startsWith('swarm-owner')),
    ['swarm-owner-lock'],
  )
  assert.deepEqual(await readdir(join(bundle, 'swarm-owner-lock')), [])
})

test('Pause at recon PRE_DISPATCH retains a proven-unsent action for one safe Resume', { timeout: 180_000 }, async (t) => {
  const h = await harness(t)
  const probeAttempts = []
  const baseProbe = controllerProbe(probeAttempts)
  let announcePreDispatch
  let releasePreDispatch
  const preDispatchReached = new Promise((resolveReached) => { announcePreDispatch = resolveReached })
  const release = new Promise((resolveRelease) => { releasePreDispatch = resolveRelease })
  let holdFirstAttempt = true
  let sentRequests = 0
  t.after(() => releasePreDispatch())
  h.deps.httpReconProbe = async (options) => baseProbe({
    ...options,
    beforeSend: async (details) => {
      if (holdFirstAttempt) {
        holdFirstAttempt = false
        announcePreDispatch()
        await release
      }
      await options.beforeSend(details)
      sentRequests += 1
    },
  })

  const activeCampaign = unleashTarget({ target: TARGET }, h.deps)
  await preDispatchReached
  const [campaignName] = (await readdir(h.deps.runsRoot))
    .filter((name) => name.startsWith('campaign-'))
  const bundle = join(h.deps.runsRoot, campaignName)
  const pauseRequest = await pauseUnleashCampaign({
    bundle,
    reason: 'pause while reconnaissance is proven not yet sent',
  }, {
    ...h.deps,
    pauseRandomBytes: (size) => Buffer.alloc(size, 0x54),
  })
  assert.equal(pauseRequest.pause.state, 'PAUSED')
  releasePreDispatch()

  const paused = await activeCampaign
  assert.equal(paused.pause.state, 'PAUSED')
  assert.equal(sentRequests, 0)
  assert.equal(probeAttempts.length, 1)
  const reconBundle = join(bundle, 'recon')
  const pausedRun = JSON.parse(await readFile(join(reconBundle, 'run.json'), 'utf8'))
  assert.equal(pausedRun.schema_version, '1.3.0')
  assert.equal(pausedRun.state, 'ACTIVE')
  assert.equal(pausedRun.actions[0].state, 'PAUSED_BEFORE_SEND')
  assert.equal(pausedRun.actions[0].attempt_count, 1)
  assert.equal(pausedRun.actions[0].sent_at, null)
  assert.equal(pausedRun.actions[0].completed_at, null)
  assert.equal(pausedRun.actions[0].error, null)
  assert.doesNotThrow(() => assertValidHttpReconRun(pausedRun))
  for (const legacyVersion of ['1.0.0', '1.1.0']) {
    const mislabeled = structuredClone(pausedRun)
    mislabeled.schema_version = legacyVersion
    assert.throws(
      () => assertValidHttpReconRun(mislabeled),
      (error) => error?.code === 'HTTP_RECON_SCHEMA_INVALID',
    )
  }
  const pausedEvents = (await readFile(join(reconBundle, 'events.jsonl'), 'utf8'))
    .trim().split('\n').map((line) => JSON.parse(line))
  assert.equal(pausedEvents.filter(({ type }) => type === 'ACTION_LEASED').length, 1)
  assert.equal(pausedEvents.filter(({ type }) => type === 'ACTION_PAUSED_BEFORE_SEND').length, 1)
  assert.equal(
    pausedEvents.find(({ type }) => type === 'ACTION_PAUSED_BEFORE_SEND').schema_version,
    '1.1.0',
  )
  assert.equal(
    pausedEvents.filter(({ type }) => type !== 'ACTION_PAUSED_BEFORE_SEND')
      .every(({ schema_version: schemaVersion }) => schemaVersion === '1.0.0'),
    true,
  )
  assert.equal(pausedEvents.some(({ type }) => type === 'ACTION_REQUEST_PRE_DISPATCH'), false)
  assert.equal(pausedEvents.some(({ type }) => type === 'ACTION_FAILED'), false)

  const resumed = await resumeUnleashCampaign({ bundle }, h.deps)
  assert.equal(resumed.status, 'COMPLETE_WITH_GAPS')
  assert.equal(sentRequests, 1)
  assert.equal(probeAttempts.length, 2)
  const completedRun = JSON.parse(await readFile(join(reconBundle, 'run.json'), 'utf8'))
  assert.equal(completedRun.schema_version, '1.3.0')
  assert.equal(completedRun.actions[0].state, 'COMMITTED')
  assert.equal(completedRun.actions[0].attempt_count, 1)
  const completedEvents = (await readFile(join(reconBundle, 'events.jsonl'), 'utf8'))
    .trim().split('\n').map((line) => JSON.parse(line))
  assert.equal(completedEvents.filter(({ type }) => type === 'ACTION_LEASED').length, 1)
  assert.equal(completedEvents.filter(({ type }) => type === 'ACTION_PAUSED_BEFORE_SEND').length, 1)
  assert.equal(completedEvents.filter(({ type }) => type === 'ACTION_REQUEST_PRE_DISPATCH').length, 1)
  assert.equal(completedEvents.filter(({ type }) => type === 'ACTION_COMMITTED').length, 1)
})

test('durable Pause quiesces active BORG work and owner-bound Resume completes without replay', { timeout: 180_000 }, async (t) => {
  const metrics = { calls: [] }
  let announceStarted
  let releaseResponses
  const started = new Promise((resolveStarted) => { announceStarted = resolveStarted })
  const release = new Promise((resolveRelease) => { releaseResponses = resolveRelease })
  t.after(() => releaseResponses())
  const assignments = borgAssignments(metrics, {
    async beforeResponse() {
      if (metrics.calls.length === 4) announceStarted()
      await release
    },
  })
  const h = await harness(t, { reasoningAdapters: assignments })

  const activeCampaign = unleashTarget({ target: TARGET }, h.deps)
  await started
  const campaignNames = (await readdir(h.deps.runsRoot))
    .filter((name) => name.startsWith('campaign-'))
  assert.equal(campaignNames.length, 1)
  const bundle = join(h.deps.runsRoot, campaignNames[0])
  const pauseReason = 'operator paused before additional provider dispatch'
  const pausedRequest = await pauseUnleashCampaign({ bundle, reason: pauseReason }, {
    ...h.deps,
    pauseRandomBytes: (size) => Buffer.alloc(size, 0x51),
  })

  assert.equal(pausedRequest.status, 'SWARMING')
  assert.deepEqual(pausedRequest.pause, {
    state: 'PAUSED',
    dispatch_open: false,
    reason: pauseReason,
    request_count: 1,
    acknowledgement_count: 0,
  })
  assert.deepEqual(pausedRequest.rollback, {
    enabled: true,
    state: 'AVAILABLE',
    request_count: 0,
    scope: ['NOT_YET_DISPATCHED', 'PROPOSED_INERT'],
    target_side_effects_reversed: false,
  })
  assert.equal(metrics.calls.length, 4)

  releaseResponses()
  const paused = await activeCampaign
  assert.equal(paused.status, 'SWARMING')
  assert.deepEqual(paused.pause, pausedRequest.pause)
  assert.deepEqual(paused.rollback, pausedRequest.rollback)
  assert.equal(metrics.calls.length, 4)
  assert.deepEqual(h.reconCalls, [{ method: 'HEAD', url: TARGET }])

  const pausedFiles = await campaignFiles(bundle)
  assert.equal(
    pausedFiles.filter((name) => /^campaign-pause-request-[a-f0-9]{64}\.json$/u.test(name)).length,
    1,
  )
  assert.equal(
    pausedFiles.filter((name) => /^campaign-pause-resume-[a-f0-9]{64}\.json$/u.test(name)).length,
    0,
  )
  assert.equal(
    pausedFiles.filter((name) => /^campaign-rollback-request-[a-f0-9]{64}\.json$/u.test(name)).length,
    0,
  )
  assert.equal(pausedFiles.includes('swarm-terminal-fence.json'), false)
  assert.equal(pausedFiles.includes('swarm-completion.json'), false)

  const resumed = await resumeUnleashCampaign({ bundle }, h.deps)
  assert.equal(resumed.status, 'COMPLETE_WITH_GAPS')
  assert.equal(metrics.calls.length, 14)
  assert.equal(
    new Set(metrics.calls.map(({ role_id: roleId, round, wave }) => `${roleId}:${round}:${wave}`)).size,
    metrics.calls.length,
  )
  assert.deepEqual(h.reconCalls, [{ method: 'HEAD', url: TARGET }])

  const status = await getUnleashCampaignStatus({ bundle }, { now: h.deps.now })
  assert.equal(status.status, 'COMPLETE_WITH_GAPS')
  assert.equal(status.swarm.phase, 'SEALED')
  assert.deepEqual(status.pause, {
    state: 'SETTLED',
    dispatch_open: false,
    reason: null,
    request_count: 1,
    acknowledgement_count: 1,
  })
  assert.deepEqual(status.rollback, {
    enabled: false,
    state: 'AVAILABLE',
    request_count: 0,
    scope: ['NOT_YET_DISPATCHED', 'PROPOSED_INERT'],
    target_side_effects_reversed: false,
  })
  const completedFiles = await campaignFiles(bundle)
  assert.equal(
    completedFiles.filter((name) => /^campaign-pause-request-[a-f0-9]{64}\.json$/u.test(name)).length,
    1,
  )
  assert.equal(
    completedFiles.filter((name) => /^campaign-pause-resume-[a-f0-9]{64}\.json$/u.test(name)).length,
    1,
  )
  assert.deepEqual(await readdir(join(bundle, 'swarm-owner-lock')), [])
})

test('Resume leaves a durable Pause unacknowledged when deployment authority is revoked', { timeout: 180_000 }, async (t) => {
  const metrics = { calls: [] }
  let announceStarted
  let releaseResponses
  const started = new Promise((resolveStarted) => { announceStarted = resolveStarted })
  const release = new Promise((resolveRelease) => { releaseResponses = resolveRelease })
  t.after(() => releaseResponses())
  const assignments = borgAssignments(metrics, {
    async beforeResponse() {
      if (metrics.calls.length === 4) announceStarted()
      await release
    },
  })
  const h = await harness(t, { reasoningAdapters: assignments })

  const activeCampaign = unleashTarget({ target: TARGET }, h.deps)
  await started
  const [campaignName] = (await readdir(h.deps.runsRoot))
    .filter((name) => name.startsWith('campaign-'))
  const bundle = join(h.deps.runsRoot, campaignName)
  await pauseUnleashCampaign({
    bundle,
    reason: 'retain the Pause while deployment authority is revoked',
  }, {
    ...h.deps,
    pauseRandomBytes: (size) => Buffer.alloc(size, 0x55),
  })
  releaseResponses()
  const paused = await activeCampaign
  assert.equal(paused.pause.state, 'PAUSED')
  assert.equal(paused.pause.acknowledgement_count, 0)
  const callsBeforeResume = metrics.calls.length

  await assert.rejects(
    resumeUnleashCampaign({ bundle }, {
      ...h.deps,
      isRevoked: () => true,
    }),
    { code: 'UNLEASH_POLICY_REVOKED' },
  )
  assert.equal(metrics.calls.length, callsBeforeResume)

  const status = await getUnleashCampaignStatus({ bundle }, { now: h.deps.now })
  assert.equal(status.pause.state, 'PAUSED')
  assert.equal(status.pause.dispatch_open, false)
  assert.equal(status.pause.acknowledgement_count, 0)
  const files = await campaignFiles(bundle)
  assert.equal(
    files.filter((name) => /^campaign-pause-resume-[a-f0-9]{64}\.json$/u.test(name)).length,
    0,
  )
  assert.deepEqual(await readdir(join(bundle, 'swarm-owner-lock')), [])
})

test('bounded rollback stops a quiesced Pause and records only local undispatched reversal', { timeout: 180_000 }, async (t) => {
  const metrics = { calls: [] }
  let announceStarted
  let releaseResponses
  const started = new Promise((resolveStarted) => { announceStarted = resolveStarted })
  const release = new Promise((resolveRelease) => { releaseResponses = resolveRelease })
  t.after(() => releaseResponses())
  const assignments = borgAssignments(metrics, {
    async beforeResponse() {
      if (metrics.calls.length === 4) announceStarted()
      await release
    },
  })
  const h = await harness(t, { reasoningAdapters: assignments })

  const activeCampaign = unleashTarget({ target: TARGET }, h.deps)
  await started
  const campaignNames = (await readdir(h.deps.runsRoot))
    .filter((name) => name.startsWith('campaign-'))
  assert.equal(campaignNames.length, 1)
  const bundle = join(h.deps.runsRoot, campaignNames[0])
  const pauseReason = 'operator paused before requesting bounded rollback'
  await pauseUnleashCampaign({ bundle, reason: pauseReason }, {
    ...h.deps,
    pauseRandomBytes: (size) => Buffer.alloc(size, 0x52),
  })
  releaseResponses()
  const paused = await activeCampaign
  assert.equal(paused.status, 'SWARMING')
  assert.equal(paused.pause.state, 'PAUSED')
  assert.equal(metrics.calls.length, 4)

  const rollbackReason = 'discard undispatched and inert proposed work'
  const rolledBack = await rollbackUnleashCampaign({ bundle, reason: rollbackReason }, h.deps)
  assert.equal(rolledBack.status, 'STOPPED')
  assert.equal(metrics.calls.length, 4)
  assert.deepEqual(h.reconCalls, [{ method: 'HEAD', url: TARGET }])
  assert.deepEqual(rolledBack.pause, {
    state: 'SETTLED',
    dispatch_open: false,
    reason: pauseReason,
    request_count: 1,
    acknowledgement_count: 0,
  })
  assert.deepEqual(rolledBack.rollback, {
    enabled: false,
    state: 'REQUESTED',
    request_count: 1,
    scope: ['NOT_YET_DISPATCHED', 'PROPOSED_INERT'],
    target_side_effects_reversed: false,
  })
  assert.equal(
    rolledBack.stop_reason,
    `Bounded local rollback cancelled future dispatch: ${rollbackReason}`,
  )

  const files = await campaignFiles(bundle)
  const pauseFiles = files.filter(
    (name) => /^campaign-pause-request-[a-f0-9]{64}\.json$/u.test(name),
  )
  const acknowledgementFiles = files.filter(
    (name) => /^campaign-pause-resume-[a-f0-9]{64}\.json$/u.test(name),
  )
  const rollbackFiles = files.filter(
    (name) => /^campaign-rollback-request-[a-f0-9]{64}\.json$/u.test(name),
  )
  assert.equal(pauseFiles.length, 1)
  assert.equal(acknowledgementFiles.length, 0)
  assert.equal(rollbackFiles.length, 1)
  const rollbackRecord = JSON.parse(await readFile(join(bundle, rollbackFiles[0]), 'utf8'))
  assert.deepEqual(rollbackRecord.scope, ['NOT_YET_DISPATCHED', 'PROPOSED_INERT'])
  assert.equal(rollbackRecord.target_side_effects_reversed, false)
  const terminalFence = JSON.parse(await readFile(
    join(bundle, 'swarm-terminal-fence.json'),
    'utf8',
  ))
  assert.equal(terminalFence.decision, 'STOP')

  const status = await getUnleashCampaignStatus({ bundle }, { now: h.deps.now })
  assert.equal(status.status, 'STOPPED')
  assert.deepEqual(status.pause, rolledBack.pause)
  assert.deepEqual(status.rollback, rolledBack.rollback)
  const callsBeforeResume = metrics.calls.length
  assert.equal((await resumeUnleashCampaign({ bundle }, h.deps)).status, 'STOPPED')
  assert.equal(metrics.calls.length, callsBeforeResume)
  assert.equal(h.reconCalls.length, 1)
})

test('Resume converts a retained rollback crash window into terminal Stop before reopening dispatch', { timeout: 180_000 }, async (t) => {
  const metrics = { calls: [] }
  let announceStarted
  let releaseResponses
  const started = new Promise((resolveStarted) => { announceStarted = resolveStarted })
  const release = new Promise((resolveRelease) => { releaseResponses = resolveRelease })
  t.after(() => releaseResponses())
  const assignments = borgAssignments(metrics, {
    async beforeResponse() {
      if (metrics.calls.length === 4) announceStarted()
      await release
    },
  })
  const h = await harness(t, { reasoningAdapters: assignments })

  const activeCampaign = unleashTarget({ target: TARGET }, h.deps)
  await started
  const [campaignName] = (await readdir(h.deps.runsRoot))
    .filter((name) => name.startsWith('campaign-'))
  const bundle = join(h.deps.runsRoot, campaignName)
  await pauseUnleashCampaign({
    bundle,
    reason: 'pause before fault-injected rollback publication',
  }, {
    ...h.deps,
    pauseRandomBytes: (size) => Buffer.alloc(size, 0x53),
  })
  releaseResponses()
  const paused = await activeCampaign
  assert.equal(paused.pause.state, 'PAUSED')
  assert.equal(metrics.calls.length, 4)

  const simulatedCrash = new Error('simulated crash after durable rollback publication')
  const openCampaignStorage = h.deps.openCampaignStorage
  let rollbackRetained = false
  await assert.rejects(
    rollbackUnleashCampaign({
      bundle,
      reason: 'retain rollback before simulated stop publication crash',
    }, {
      ...h.deps,
      openCampaignStorage: async (options) => {
        const storage = await openCampaignStorage(options)
        return Object.freeze({
          ...storage,
          writeImmutableJson: async (filename, value) => {
            const written = await storage.writeImmutableJson(filename, value)
            if (
              !rollbackRetained
              && /^campaign-rollback-request-[a-f0-9]{64}\.json$/u.test(filename)
            ) {
              rollbackRetained = true
              throw simulatedCrash
            }
            return written
          },
        })
      },
    }),
    (error) => error === simulatedCrash,
  )
  assert.equal(rollbackRetained, true)

  const interruptedFiles = await campaignFiles(bundle)
  assert.equal(
    interruptedFiles.filter((name) => /^campaign-rollback-request-[a-f0-9]{64}\.json$/u.test(name)).length,
    1,
  )
  assert.equal(
    interruptedFiles.filter((name) => /^campaign-pause-resume-[a-f0-9]{64}\.json$/u.test(name)).length,
    0,
  )
  assert.equal(interruptedFiles.includes('campaign-stop-request.json'), false)
  assert.equal(interruptedFiles.includes('swarm-terminal-fence.json'), false)

  const callsBeforeResume = metrics.calls.length
  const recovered = await resumeUnleashCampaign({ bundle }, h.deps)
  assert.equal(recovered.status, 'STOPPED')
  assert.equal(metrics.calls.length, callsBeforeResume)
  assert.deepEqual(h.reconCalls, [{ method: 'HEAD', url: TARGET }])
  assert.equal(
    recovered.stop_reason,
    'Bounded local rollback cancelled future dispatch: retain rollback before simulated stop publication crash',
  )

  const recoveredFiles = await campaignFiles(bundle)
  assert.equal(
    recoveredFiles.filter((name) => /^campaign-pause-resume-[a-f0-9]{64}\.json$/u.test(name)).length,
    0,
  )
  assert.equal(recoveredFiles.includes('campaign-stop-request.json'), true)
  const fence = JSON.parse(await readFile(join(bundle, 'swarm-terminal-fence.json'), 'utf8'))
  assert.equal(fence.decision, 'STOP')
  assert.equal(fence.reason, recovered.stop_reason)
  const status = await getUnleashCampaignStatus({ bundle }, { now: h.deps.now })
  assert.equal(status.pause.acknowledgement_count, 0)
  assert.equal(status.rollback.state, 'REQUESTED')
  assert.equal(status.rollback.target_side_effects_reversed, false)
})

test('a stop racing started BORG calls seals once without replay', { timeout: 180_000 }, async (t) => {
  const metrics = { calls: [] }
  let announceStarted
  let releaseResponses
  const started = new Promise((resolveStarted) => { announceStarted = resolveStarted })
  const release = new Promise((resolveRelease) => { releaseResponses = resolveRelease })
  t.after(() => releaseResponses())
  const assignments = borgAssignments(metrics, {
    async beforeResponse() {
      if (metrics.calls.length === 4) announceStarted()
      await release
    },
  })
  const h = await harness(t, { reasoningAdapters: assignments })
  const assertLiveControlsVisible = (summary) => {
    assert.equal(summary.detection.state, 'ADMITTED')
    assert.deepEqual(summary.pause, {
      state: 'RUNNING',
      dispatch_open: true,
      reason: null,
      request_count: 0,
      acknowledgement_count: 0,
    })
    assert.deepEqual(summary.rollback, {
      enabled: false,
      state: 'AVAILABLE',
      request_count: 0,
      scope: ['NOT_YET_DISPATCHED', 'PROPOSED_INERT'],
      target_side_effects_reversed: false,
    })
  }

  const unleash = unleashTarget({ target: TARGET }, h.deps)
  await started
  const campaignNames = (await readdir(h.deps.runsRoot))
    .filter((name) => name.startsWith('campaign-'))
  assert.equal(campaignNames.length, 1)
  const bundle = join(h.deps.runsRoot, campaignNames[0])
  const callsBeforeEarlyResume = metrics.calls.length
  const activeOwner = await resumeUnleashCampaign({ bundle }, h.deps)
  assert.equal(activeOwner.status, 'SWARMING')
  assert.deepEqual(activeOwner.resume_control, {
    state: 'ACTIVE_SWARM_OWNER',
    takeover: 'DEFERRED_WHILE_EXCLUSIVE_OWNER_IS_LIVE',
  })
  assertLiveControlsVisible(activeOwner)
  assert.equal(metrics.calls.length, callsBeforeEarlyResume)
  const delayedDependencies = { ...h.deps }
  const delayedResumes = await Promise.all([
    resumeUnleashCampaign({ bundle }, delayedDependencies),
    resumeUnleashCampaign({ bundle }, delayedDependencies),
  ])
  for (const delayedResume of delayedResumes) {
    assert.equal(delayedResume.status, 'SWARMING', JSON.stringify(delayedResume))
    assert.deepEqual(delayedResume.resume_control, {
      state: 'ACTIVE_SWARM_OWNER',
      takeover: 'DEFERRED_WHILE_EXCLUSIVE_OWNER_IS_LIVE',
    })
    assertLiveControlsVisible(delayedResume)
  }
  assert.equal(metrics.calls.length, callsBeforeEarlyResume)
  const stopped = await stopUnleashCampaign({
    bundle,
    reason: 'controller stop raced active BORG reasoning',
  }, h.deps)
  assert.equal(stopped.status, 'STOP_REQUESTED')
  assert.equal(stopped.stop_reason, 'controller stop raced active BORG reasoning')
  assert.deepEqual(stopped.stop_request, {
    state: 'DURABLY_RECORDED',
    requested_at: stopped.stop_request.requested_at,
    settlement: 'ACTIVE_SWARM_OWNER_PENDING',
  })
  assertLiveControlsVisible(stopped)

  const callsBeforeStatus = metrics.calls.length
  const pending = await getUnleashCampaignStatus({ bundle }, { now: h.deps.now })
  assert.equal(pending.status, 'STOP_REQUESTED')
  assert.equal(pending.swarm.phase, 'SWARMING')
  assert.equal(pending.stop_request.settlement, 'ACTIVE_SWARM_OWNER_PENDING')
  assertLiveControlsVisible(pending)
  assert.equal(metrics.calls.length, callsBeforeStatus)
  const delayedProjection = await getUnleashCampaignStatus({ bundle }, delayedDependencies)
  assert.equal(delayedProjection.status, 'STOP_REQUESTED')
  assert.equal(
    delayedProjection.stop_request.settlement,
    'ACTIVE_SWARM_OWNER_PENDING',
  )
  assertLiveControlsVisible(delayedProjection)
  assert.equal(metrics.calls.length, callsBeforeStatus)
  const pendingResume = await resumeUnleashCampaign({ bundle }, h.deps)
  assert.equal(pendingResume.status, 'STOP_REQUESTED')
  assert.equal(pendingResume.stop_request.settlement, 'ACTIVE_SWARM_OWNER_PENDING')
  assertLiveControlsVisible(pendingResume)
  assert.equal(metrics.calls.length, callsBeforeStatus)
  releaseResponses()

  const completed = await unleash
  assert.equal(completed.status, 'STOPPED')
  assert.equal(metrics.calls.length <= 4, true)
  assert.deepEqual(h.reconCalls, [{ method: 'HEAD', url: TARGET }])

  const status = await getUnleashCampaignStatus({ bundle }, { now: h.deps.now })
  assert.equal(status.status, 'STOPPED')
  assert.equal(status.swarm.phase, 'SEALED')
  assert.equal(status.swarm.terminal_status, 'STOPPED')
  assert.equal(status.controls.stop.state, 'SETTLED')
  assert.equal(status.findings.count, 0)
  assert.equal(
    (await campaignFiles(bundle))
      .filter((name) => /^candidate-admission-[0-9]{6}\.json$/u.test(name)).length,
    1,
  )

  const providerCallsBeforeResume = metrics.calls.length
  assert.equal((await resumeUnleashCampaign({ bundle }, h.deps)).status, 'STOPPED')
  assert.equal(metrics.calls.length, providerCallsBeforeResume)
  assert.equal(h.reconCalls.length, 1)
})

test('a late Stop wins the shared terminal fence before Seal and cannot be lost', { timeout: 180_000 }, async (t) => {
  const h = await harness(t)
  const createStorage = h.deps.createCampaignStorage
  let announceSealAttempt
  let releaseSealAttempt
  const sealAttempted = new Promise((resolveAttempted) => { announceSealAttempt = resolveAttempted })
  const release = new Promise((resolveRelease) => { releaseSealAttempt = resolveRelease })
  t.after(() => releaseSealAttempt())
  h.deps.createCampaignStorage = async (options) => {
    const storage = await createStorage(options)
    let paused = false
    return Object.freeze({
      ...storage,
      writeImmutableJson: async (filename, value) => {
        if (
          !paused
          && filename === 'swarm-terminal-fence.json'
          && value?.decision === 'SEAL'
        ) {
          paused = true
          announceSealAttempt()
          await release
        }
        return storage.writeImmutableJson(filename, value)
      },
    })
  }

  const campaign = unleashTarget({ target: TARGET }, h.deps)
  await sealAttempted
  const [campaignDirectory] = (await readdir(h.deps.runsRoot))
    .filter((name) => name.startsWith('campaign-'))
  const bundle = join(h.deps.runsRoot, campaignDirectory)
  const stop = await stopUnleashCampaign({
    bundle,
    reason: 'late deterministic Stop must win before Seal',
  }, h.deps)

  assert.equal(stop.status, 'STOP_REQUESTED')
  assert.equal(stop.stop_reason, 'late deterministic Stop must win before Seal')
  const fenceBeforeRelease = JSON.parse(await readFile(
    join(bundle, 'swarm-terminal-fence.json'),
    'utf8',
  ))
  assert.equal(fenceBeforeRelease.decision, 'STOP')
  assert.equal(fenceBeforeRelease.reason, stop.stop_reason)
  releaseSealAttempt()

  const terminal = await campaign
  assert.equal(terminal.status, 'STOPPED')
  assert.equal(terminal.stop_reason, stop.stop_reason)
  assert.equal((await resumeUnleashCampaign({ bundle }, h.deps)).status, 'STOPPED')
  assert.equal((await getUnleashCampaignStatus({ bundle }, { now: h.deps.now })).status, 'STOPPED')
  const fenceAfterSeal = JSON.parse(await readFile(join(bundle, 'swarm-terminal-fence.json'), 'utf8'))
  assert.deepEqual(fenceAfterSeal, fenceBeforeRelease)
  assert.equal(
    JSON.parse(await readFile(join(bundle, 'swarm-completion.json'), 'utf8')).status,
    'STOPPED',
  )
})

test('a rollback intent that loses the terminal fence to Seal remains a bounded nonclaim', { timeout: 180_000 }, async (t) => {
  const metrics = { calls: [] }
  const h = await harness(t, { reasoningAdapters: borgAssignments(metrics) })
  const createStorage = h.deps.createCampaignStorage
  const openStorage = h.deps.openCampaignStorage
  let announceOwnerAtSeal
  let allowSeal
  let announceSealWon
  let announceOwnerAfterSeal
  let allowOwnerFinish
  let announceStopAtFence
  const ownerAtSeal = new Promise((resolveAtSeal) => { announceOwnerAtSeal = resolveAtSeal })
  const releaseSeal = new Promise((resolveSeal) => { allowSeal = resolveSeal })
  const sealWon = new Promise((resolveWon) => { announceSealWon = resolveWon })
  const ownerAfterSeal = new Promise((resolveAfterSeal) => { announceOwnerAfterSeal = resolveAfterSeal })
  const releaseOwner = new Promise((resolveOwner) => { allowOwnerFinish = resolveOwner })
  const stopAtFence = new Promise((resolveAtFence) => { announceStopAtFence = resolveAtFence })
  t.after(() => {
    allowSeal()
    allowOwnerFinish()
  })
  h.deps.createCampaignStorage = async (options) => {
    const storage = await createStorage(options)
    let sealBlocked = false
    let completionBlocked = false
    return Object.freeze({
      ...storage,
      writeImmutableJson: async (filename, value) => {
        if (
          !sealBlocked
          && filename === 'swarm-terminal-fence.json'
          && value?.decision === 'SEAL'
        ) {
          sealBlocked = true
          announceOwnerAtSeal()
          await releaseSeal
          const written = await storage.writeImmutableJson(filename, value)
          announceSealWon()
          return written
        }
        if (!completionBlocked && filename === 'candidate-admission-000001.json') {
          completionBlocked = true
          announceOwnerAfterSeal()
          await releaseOwner
        }
        return storage.writeImmutableJson(filename, value)
      },
    })
  }
  h.deps.openCampaignStorage = async (options) => {
    const storage = await openStorage(options)
    return Object.freeze({
      ...storage,
      writeImmutableJson: async (filename, value) => {
        if (
          filename === 'swarm-terminal-fence.json'
          && value?.decision === 'STOP'
        ) {
          announceStopAtFence()
          await sealWon
        }
        return storage.writeImmutableJson(filename, value)
      },
    })
  }

  const campaign = unleashTarget({ target: TARGET }, h.deps)
  await ownerAtSeal
  const [campaignDirectory] = (await readdir(h.deps.runsRoot))
    .filter((name) => name.startsWith('campaign-'))
  const bundle = join(h.deps.runsRoot, campaignDirectory)
  const losingRollback = rollbackUnleashCampaign({
    bundle,
    reason: 'local rollback races the already prepared terminal Seal',
  }, {
    ...h.deps,
    pauseRandomBytes: (size) => Buffer.alloc(size, 0x55),
  })
  await stopAtFence
  const intentFiles = await campaignFiles(bundle)
  assert.equal(
    intentFiles.filter((name) => /^campaign-pause-request-[a-f0-9]{64}\.json$/u.test(name)).length,
    1,
  )
  assert.equal(
    intentFiles.filter((name) => /^campaign-rollback-request-[a-f0-9]{64}\.json$/u.test(name)).length,
    1,
  )
  assert.equal(intentFiles.includes('swarm-terminal-fence.json'), false)
  allowSeal()
  await sealWon
  await ownerAfterSeal

  const rollback = await losingRollback
  assert.equal(rollback.status, 'SWARMING')
  assert.equal(rollback.rollback.state, 'REQUESTED')
  assert.equal(rollback.rollback.target_side_effects_reversed, false)
  assert.equal(rollback.pause.acknowledgement_count, 0)
  const sealFence = JSON.parse(await readFile(join(bundle, 'swarm-terminal-fence.json'), 'utf8'))
  assert.equal(sealFence.decision, 'SEAL')
  await assert.rejects(
    readFile(join(bundle, 'campaign-stop-request.json'), 'utf8'),
    (error) => error?.code === 'ENOENT',
  )

  allowOwnerFinish()
  const terminal = await campaign
  assert.equal(terminal.status, 'COMPLETE_WITH_GAPS')
  assert.equal(terminal.stop_reason, null)
  const callsBeforeRecovery = metrics.calls.length
  const status = await getUnleashCampaignStatus({ bundle }, { now: h.deps.now })
  assert.equal(status.status, terminal.status)
  assert.equal(status.pause.acknowledgement_count, 0)
  assert.equal(status.rollback.state, 'REQUESTED')
  assert.equal(status.rollback.target_side_effects_reversed, false)
  const resumed = await resumeUnleashCampaign({ bundle }, h.deps)
  assert.equal(resumed.status, terminal.status)
  assert.equal(resumed.stop_reason, null)
  assert.equal(metrics.calls.length, callsBeforeRecovery)
  assert.deepEqual(
    JSON.parse(await readFile(join(bundle, 'swarm-terminal-fence.json'), 'utf8')),
    sealFence,
  )
  const settledFiles = await campaignFiles(bundle)
  assert.equal(
    settledFiles.filter((name) => /^campaign-pause-resume-[a-f0-9]{64}\.json$/u.test(name)).length,
    0,
  )
  assert.equal(settledFiles.includes('campaign-stop-request.json'), false)
})

test('a SEAL-winning terminal fence never reports a later Stop as accepted', { timeout: 180_000 }, async (t) => {
  const h = await harness(t)
  const createStorage = h.deps.createCampaignStorage
  let announceSealing
  let releaseSealing
  const sealing = new Promise((resolveSealing) => { announceSealing = resolveSealing })
  const release = new Promise((resolveRelease) => { releaseSealing = resolveRelease })
  t.after(() => releaseSealing())
  h.deps.createCampaignStorage = async (options) => {
    const storage = await createStorage(options)
    let paused = false
    return Object.freeze({
      ...storage,
      writeImmutableJson: async (filename, value) => {
        if (!paused && filename === 'candidate-admission-000001.json') {
          paused = true
          announceSealing()
          await release
        }
        return storage.writeImmutableJson(filename, value)
      },
    })
  }

  const campaign = unleashTarget({ target: TARGET }, h.deps)
  await sealing
  const [campaignDirectory] = (await readdir(h.deps.runsRoot))
    .filter((name) => name.startsWith('campaign-'))
  const bundle = join(h.deps.runsRoot, campaignDirectory)
  const fence = JSON.parse(await readFile(join(bundle, 'swarm-terminal-fence.json'), 'utf8'))
  assert.equal(fence.decision, 'SEAL')

  const lateStop = await stopUnleashCampaign({
    bundle,
    reason: 'this Stop arrives after the terminal linearization point',
  }, h.deps)
  assert.equal(lateStop.status, 'SWARMING')
  assert.deepEqual(lateStop.resume_control, {
    state: 'ACTIVE_SWARM_OWNER',
    takeover: 'DEFERRED_WHILE_EXCLUSIVE_OWNER_IS_LIVE',
  })
  await assert.rejects(
    readFile(join(bundle, 'campaign-stop-request.json'), 'utf8'),
    (error) => error?.code === 'ENOENT',
  )
  releaseSealing()

  const terminal = await campaign
  assert.equal(terminal.status, 'COMPLETE_WITH_GAPS')
  assert.equal(terminal.stop_reason, null)
  const repeated = await stopUnleashCampaign({
    bundle,
    reason: 'terminal campaigns remain terminal',
  }, h.deps)
  assert.equal(repeated.status, terminal.status)
  assert.equal(repeated.stop_reason, null)
  assert.deepEqual(
    JSON.parse(await readFile(join(bundle, 'swarm-terminal-fence.json'), 'utf8')),
    fence,
  )
})
