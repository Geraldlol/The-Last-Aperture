import { createHash, randomBytes as systemRandomBytes } from 'node:crypto'
import { mkdir as mkdirDefault } from 'node:fs/promises'
import { homedir } from 'node:os'
import { basename, dirname, isAbsolute, join, resolve } from 'node:path'

import { compareCanonicalStrings } from './canonical-order.mjs'
import {
  finalizeHttpReconBundle,
  goControllerPolicyHttpRecon,
  inspectControllerPolicyHttpReconStop,
  nextHttpReconAction,
  requestHttpReconStop,
  runControllerPolicyHttpReconAction,
} from './http-recon-controller.mjs'
import { CONTROLLER_DEPLOYMENT_POLICY_LIMITS } from './http-recon-contracts.mjs'
import {
  createUnleashCampaignStorage,
  defaultUnleashCampaignRunsRoot,
  openUnleashCampaignStorage,
} from './unleash-campaign-storage.mjs'
import {
  appendUnleashCampaignState,
  nextUnleashCampaignState,
  recoverUnleashCampaignState,
} from './unleash-campaign-state.mjs'
import {
  UNLEASH_CANDIDATE_FRONTIER_LIMITS,
  UNLEASH_CANDIDATE_FRONTIER_STATE_FILE,
  assertValidUnleashCandidateFrontierState,
  assertValidUnleashCandidateFrontierStateV2,
  createEmptyUnleashCandidateFrontier,
  createUnleashCandidateAdmission,
  getUnleashCandidateFrontierAdmissionReferences,
  previewUnleashCandidateFrontierAppend,
  reconcileUnleashCandidateFrontierState,
  reconcileUnleashCandidateFrontierStateV2,
  recoverUnleashCandidateFrontier,
  recoverUnleashCandidateFrontierV2,
  snapshotUnleashProviderProposal,
} from './unleash-candidate-frontier.mjs'
import {
  assertExactUnleashHttpsReconExecutionContract,
  assertSelfBoundUnleashPlan,
  assertValidUnleashPlan,
  assertValidUnleashProposal,
  createUnleashPlan,
  digestUnleashValue,
} from './unleash-contracts.mjs'
import {
  assertPolicyAllowsTarget,
  createUnleashDeploymentPolicy,
  projectUnleashPolicy,
  resolveUnleashDetectionPolicyBinding,
} from './unleash-policy.mjs'
import {
  assessUnleashActionRisk,
  assertUnleashActionRiskConfirmation,
  assertValidUnleashActionRiskReceipt,
  createUnleashActionRiskReceipt,
} from './unleash-action-risk-assessment.mjs'
import { loadUnleashControllerPolicy } from './unleash-policy-loader.mjs'
import {
  assertValidUnleashReconCompletion,
  createVerifiedReconCompletion,
  verifyUnleashReconCompletion,
} from './unleash-recon-evidence.mjs'
import { createDefaultUnleashPlannerDependencies } from './unleash-registry.mjs'
import { createUnleashProviderProfile } from './unleash-provider-profile.mjs'
import { createUnleashCampaignSnapshot } from './unleash-snapshot.mjs'
import {
  acknowledgeUnleashCampaignPause,
  readUnleashCampaignPauseControl,
  requestUnleashCampaignPause,
  requestUnleashLocalRollback,
} from './unleash-campaign-pause.mjs'
import {
  assertValidUnleashSwarmBasis,
  assertValidUnleashSwarmCompletion,
  createUnleashSwarmBasis,
} from './unleash-swarm-contracts.mjs'
import { assertValidUnleashSwarmMerge } from './unleash-swarm-merge.mjs'
import {
  UNLEASH_SWARM_BASIS_FILE,
  UnleashSwarmPause,
  runUnleashSwarmController,
} from './unleash-swarm-controller.mjs'
import {
  UNLEASH_SWARM_ATTEMPT_LEDGER_STATE_FILE,
  reconcileUnleashSwarmAttemptLedger,
  recoverUnleashSwarmAttemptLedger,
} from './unleash-swarm-ledger.mjs'
import {
  acquireUnleashSwarmOwner,
  assertUnleashSwarmOwner,
  bindUnleashSwarmOwnerStorage,
  inspectUnleashSwarmOwner,
  releaseUnleashSwarmOwner,
} from './unleash-swarm-owner.mjs'
import { sealUnleashSwarmCampaign } from './unleash-swarm-seal.mjs'

const INTAKE_FIELDS = ['target']
const RECON_AUTHORITY_FILE = 'campaign-recon-authority.json'
const RECON_PLANNED_FILE = 'campaign-recon-planned.json'
const ACTION_RISK_PREFLIGHT_FILE = 'campaign-action-risk-preflight.json'
const ACTION_RISK_CONFIRMATION_FILE = 'campaign-action-risk-confirmation.json'
const STOP_REQUEST_FILE = 'campaign-stop-request.json'
const SWARM_TERMINAL_FENCE_FILE = 'swarm-terminal-fence.json'
const ROLLBACK_STOP_REASON_PREFIX = 'Bounded local rollback cancelled future dispatch: '
const SWARM_ATTEMPT_EVENT_FILE = /^swarm-attempt-event-[0-9]{6}\.json$/u
const SWARM_MERGE_FILE = /^swarm-merge-r([0-9]{2})-(attack|review)\.json$/u
const REASONING_ASSIGNMENT_FIELDS = ['roleId', 'adapter']
const SWARM_OWNER_TOKEN = Symbol('unleash-swarm-owner-token')
const ENROLLED_ADAPTERS = Object.freeze({
  'adapter:last-aperture-http-recon': goControllerPolicyHttpRecon,
})

export class UnleashControllerError extends Error {
  constructor(code, message, { cause, runDirectory, status } = {}) {
    super(message, cause === undefined ? undefined : { cause })
    this.name = 'UnleashControllerError'
    this.code = code
    if (runDirectory !== undefined) this.run_directory = runDirectory
    if (status !== undefined) this.status = status
  }
}

function fail(code, message, options = {}) {
  throw new UnleashControllerError(code, message, options)
}

function errorChainHasCode(cause, code) {
  let current = cause
  for (let depth = 0; depth < 8 && current !== null && typeof current === 'object'; depth += 1) {
    if (current.code === code) return true
    current = current.cause
  }
  return false
}

function hasExactKeys(value, fields) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.keys(value).toSorted().join(',') === [...fields].toSorted().join(',')
}

function exactDataRecord(value, fields) {
  try {
    if (
      value === null
      || typeof value !== 'object'
      || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    ) return null
    const descriptors = Object.getOwnPropertyDescriptors(value)
    const keys = Reflect.ownKeys(descriptors)
    if (
      keys.length !== fields.length
      || keys.some((key) => (
        typeof key !== 'string'
        || !fields.includes(key)
        || descriptors[key].enumerable !== true
        || !Object.hasOwn(descriptors[key], 'value')
      ))
    ) return null
    return Object.fromEntries(fields.map((field) => [field, descriptors[field].value]))
  } catch {
    return null
  }
}

function controllerReasoningAssignments(dependencies) {
  const value = dependencies.reasoningAdapters
  if (value === undefined) return Object.freeze([])
  let descriptors
  try {
    descriptors = Object.getOwnPropertyDescriptors(value)
  } catch {
    fail('UNLEASH_REASONING_ADAPTERS_INVALID', 'controller reasoning adapter assignments could not be inspected safely')
  }
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    fail('UNLEASH_REASONING_ADAPTERS_INVALID', 'controller reasoning adapter assignments must be one plain dense array')
  }
  const keys = Reflect.ownKeys(descriptors).filter((key) => key !== 'length')
  if (
    keys.length !== value.length
    || keys.some((key, index) => key !== String(index)
      || descriptors[key].enumerable !== true
      || !Object.hasOwn(descriptors[key], 'value'))
  ) fail('UNLEASH_REASONING_ADAPTERS_INVALID', 'controller reasoning adapter assignments must be one plain dense array')
  const retained = []
  const roles = new Set()
  for (const key of keys) {
    const item = exactDataRecord(descriptors[key].value, REASONING_ASSIGNMENT_FIELDS)
    if (item === null || typeof item.roleId !== 'string' || roles.has(item.roleId)) {
      fail('UNLEASH_REASONING_ADAPTERS_INVALID', 'controller reasoning adapter assignment is missing, unknown, or duplicated')
    }
    let adapterDescriptors
    try {
      adapterDescriptors = Object.getOwnPropertyDescriptors(item.adapter)
    } catch {
      fail('UNLEASH_REASONING_ADAPTERS_INVALID', 'controller reasoning adapter could not be inspected safely')
    }
    if (
      item.adapter === null
      || typeof item.adapter !== 'object'
      || Reflect.ownKeys(adapterDescriptors).length !== 2
      || !Object.hasOwn(adapterDescriptors.identity ?? {}, 'value')
      || !Object.hasOwn(adapterDescriptors.invoke ?? {}, 'value')
      || typeof adapterDescriptors.invoke.value !== 'function'
    ) fail('UNLEASH_REASONING_ADAPTERS_INVALID', 'controller reasoning adapter has an invalid shape')
    roles.add(item.roleId)
    retained.push(Object.freeze({
      roleId: item.roleId,
      adapter: item.adapter,
      adapterIdentity: structuredClone(adapterDescriptors.identity.value),
    }))
  }
  return Object.freeze(retained)
}

function controllerProviderProfile(assignments, configured = undefined) {
  try {
    if (configured !== undefined) {
      if (assignments.length > 0) {
        throw new TypeError('a configured provider profile cannot be combined with reasoning adapter assignments')
      }
      const legacy = exactDataRecord(configured, ['protocol_version', 'proposal_kind'])
      if (
        legacy === null
        || legacy.protocol_version !== '1.0.0'
        || legacy.proposal_kind !== 'last-aperture/unleash-proposal'
      ) throw new TypeError('configured provider profile must be the exact legacy protocol-v1 test seam')
      return Object.freeze({ ...legacy })
    }
    return createUnleashProviderProfile({
      assignments: assignments.map(({ roleId, adapterIdentity }) => ({ roleId, adapterIdentity })),
    })
  } catch (cause) {
    throw new UnleashControllerError(
      'UNLEASH_REASONING_ADAPTERS_INVALID',
      'Controller reasoning adapter assignments cannot form the sealed BORG provider profile.',
      { cause },
    )
  }
}

function sameResolvedPath(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false
  const normalizedLeft = resolve(left)
  const normalizedRight = resolve(right)
  return process.platform === 'win32'
    ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
    : normalizedLeft === normalizedRight
}

export function defaultUnleashRunsRoot({
  platform = process.platform,
  localAppData = process.env.LOCALAPPDATA,
  home = homedir(),
} = {}) {
  return defaultUnleashCampaignRunsRoot({ platform, localAppData, home })
}

function sampleNow(now) {
  if (typeof now !== 'function') fail('UNLEASH_CONTROLLER_CLOCK_INVALID', 'controller clock must be a function')
  const value = now()
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    fail('UNLEASH_CONTROLLER_CLOCK_INVALID', 'controller clock must return a valid Date')
  }
  return value
}

function routeCounts(plan) {
  const counts = {
    total: plan.route_dispositions.length,
    ready: 0,
    waiting: 0,
    unavailable: 0,
    not_applicable: 0,
    blocked: 0,
  }
  for (const route of plan.route_dispositions) {
    if (route.disposition === 'READY') counts.ready += 1
    else if (['WAITING_FOR_MATERIAL', 'WAITING_FOR_DEPENDENCY'].includes(route.disposition)) counts.waiting += 1
    else if (route.disposition === 'UNAVAILABLE') counts.unavailable += 1
    else if (route.disposition === 'NOT_APPLICABLE') counts.not_applicable += 1
    else if (route.disposition === 'BLOCKED_BY_POLICY') counts.blocked += 1
  }
  return counts
}

function publicSummary(state) {
  const summary = {
    campaign_id: state.campaign_id,
    status: state.status,
    revision: state.revision,
    updated_at: state.updated_at,
    run_directory: state.run_directory,
    plan_sha256: state.plan_sha256,
    target: structuredClone(state.target),
    completed_routes: [...state.completed_routes],
    evidence_packet_path: state.evidence_packet_path,
    evidence_packet_sha256: state.evidence_packet_sha256,
    completion_receipt_sha256: state.completion_receipt_sha256,
    route_counts: structuredClone(state.route_counts),
    gap_count: state.gap_count,
    stop_reason: state.stop_reason,
    failure: structuredClone(state.failure),
  }
  if (state.schema_version === '2.0.0') {
    summary.swarm = {
      phase: state.status === 'SWARMING' ? 'SWARMING' : state.swarm_completion_sha256 === null ? 'NOT_SEALED' : 'SEALED',
      basis_sha256: state.swarm_basis_sha256,
      completion_sha256: state.swarm_completion_sha256,
      candidate_frontier_sha256: state.candidate_frontier_sha256,
      candidate_frontier_head_sha256: state.candidate_frontier_head_sha256,
      gap_count: state.swarm_gap_count,
    }
  }
  return Object.freeze(summary)
}

function protocolV2SwarmHasStarted(loaded) {
  return loaded.state.schema_version === '2.0.0'
    && (
      loaded.state.swarm_basis_sha256 !== null
      || loaded.inventory?.includes(UNLEASH_SWARM_BASIS_FILE)
      || loaded.inventory?.includes('https-recon-completion.json')
    )
}

function protocolV2SwarmOwnerInput(loaded) {
  return {
    campaignDirectory: loaded.storage.campaign_directory,
    campaignId: loaded.state.campaign_id,
    planSha256: loaded.plan.plan_sha256,
  }
}

async function inspectProtocolV2SwarmOwnership(loaded) {
  if (loaded.state.schema_version !== '2.0.0') {
    return Object.freeze({ state: 'AVAILABLE', owner: null })
  }
  return inspectUnleashSwarmOwner(protocolV2SwarmOwnerInput(loaded))
}

async function publicPendingStopSummary(loaded, gate, settlement) {
  const summary = await publicControlledCampaignSummary(loaded)
  return Object.freeze({
    ...summary,
    status: 'STOP_REQUESTED',
    stop_reason: gate.reason,
    stop_request: Object.freeze({
      state: 'DURABLY_RECORDED',
      requested_at: gate.requested_at,
      settlement,
    }),
  })
}

async function publicActiveSwarmOwnerSummary(loaded) {
  return Object.freeze({
    ...await publicControlledCampaignSummary(loaded),
    resume_control: Object.freeze({
      state: 'ACTIVE_SWARM_OWNER',
      takeover: 'DEFERRED_WHILE_EXCLUSIVE_OWNER_IS_LIVE',
    }),
  })
}

function isSwarmOwnerBusy(cause) {
  return cause?.code === 'UNLEASH_CAMPAIGN_SWARM_OWNER_BUSY'
}

function campaignIdentity(plan, nonce) {
  return `campaign:sha256:${digestUnleashValue({
    plan_sha256: plan.plan_sha256,
    nonce_sha256: createHash('sha256').update(nonce).digest('hex'),
  })}`
}

function controllerPolicyAuthority(policy, plan, admittedAt) {
  return Object.freeze({
    mode: 'CONTROLLER_DEPLOYMENT_POLICY',
    policy_id: policy.policy_id,
    policy_sha256: plan.policy_sha256,
    target_id: plan.target.target_id,
    effect: 'OBSERVE',
    admitted_at: admittedAt.toISOString(),
    revocation_check_id: policy.revocation.check_id,
  })
}

function controllerPolicyAdmission(authority) {
  const { mode, ...admission } = authority
  if (mode !== 'CONTROLLER_DEPLOYMENT_POLICY') {
    fail('UNLEASH_RECON_AUTHORITY_DRIFT', 'reconnaissance authority mode is invalid')
  }
  return Object.freeze(admission)
}

function failureChanges(code = 'UNLEASH_REMOTE_ROUTE_FAILED', message = 'The first remote route failed; inspect retained campaign evidence for details.') {
  return {
    status: 'FAILED',
    completed_routes: [],
    evidence_packet_path: null,
    evidence_packet_sha256: null,
    completion_receipt_sha256: null,
    failure: { code, message },
  }
}

function assertReconAdapterWithinPolicy(policy) {
  if (
    policy.budgets.max_actions < CONTROLLER_DEPLOYMENT_POLICY_LIMITS.max_probe_requests
    || policy.budgets.max_parallel_actions < CONTROLLER_DEPLOYMENT_POLICY_LIMITS.concurrency
    || policy.budgets.max_duration_ms < CONTROLLER_DEPLOYMENT_POLICY_LIMITS.max_wall_time_ms
    || policy.budgets.max_response_bytes < CONTROLLER_DEPLOYMENT_POLICY_LIMITS.max_aggregate_response_bytes
  ) {
    fail(
      'UNLEASH_ADAPTER_BUDGET_UNSUPPORTED',
      'deployment policy is tighter than the sealed HTTPS reconnaissance adapter',
    )
  }
}

function enrolledHttpsReconAdapter(registry) {
  const route = registry?.routes?.find(({ route_id: routeId }) => routeId === 'https-recon')
  if (route?.availability?.status !== 'AVAILABLE') {
    fail('UNLEASH_RECON_UNAVAILABLE', 'the HTTPS reconnaissance route is not available in the retained registry')
  }
  assertExactUnleashHttpsReconExecutionContract(route.execution_contract)
  const adapter = ENROLLED_ADAPTERS[route.execution_contract.adapter_id]
  if (adapter !== goControllerPolicyHttpRecon) {
    fail('UNLEASH_RECON_UNAVAILABLE', 'the retained HTTPS reconnaissance adapter is not enrolled in this controller build')
  }
  return adapter
}

function enrolledHttpReconRun(dependencies) {
  const probeImpl = dependencies.httpReconProbe
  if (probeImpl !== undefined && typeof probeImpl !== 'function') {
    fail('UNLEASH_RECON_DEPENDENCY_INVALID', 'HTTPS reconnaissance transport seam must be a function')
  }
  return probeImpl === undefined
    ? runControllerPolicyHttpReconAction
    : (request) => runControllerPolicyHttpReconAction({ ...request, probeImpl })
}

async function resolveControllerAuthority(dependencies) {
  let authority
  if (dependencies.policy !== undefined || dependencies.isRevoked !== undefined) {
    authority = { policy: dependencies.policy, isRevoked: dependencies.isRevoked }
  } else {
    const loadPolicy = dependencies.loadPolicy ?? loadUnleashControllerPolicy
    if (typeof loadPolicy !== 'function') {
      fail('UNLEASH_POLICY_LOADER_INVALID', 'controller policy loader is unavailable')
    }
    const loaded = await loadPolicy()
    if (loaded === null || typeof loaded !== 'object' || Array.isArray(loaded)) {
      fail('UNLEASH_POLICY_LOADER_INVALID', 'controller policy loader returned an invalid authority')
    }
    authority = { policy: loaded.policy, isRevoked: loaded.isRevoked }
  }
  return {
    policy: createUnleashDeploymentPolicy(authority.policy),
    isRevoked: authority.isRevoked,
  }
}

function assertPolicyPlanBinding(policy, plan) {
  return resolveUnleashDetectionPolicyBinding(policy, plan.policy_sha256)
}

function assertControllerPolicyAuthority(value, policy, plan) {
  const admittedAt = new Date(value?.admitted_at)
  if (
    !hasExactKeys(value, [
      'mode', 'policy_id', 'policy_sha256', 'target_id', 'effect', 'admitted_at',
      'revocation_check_id',
    ])
    || !Number.isFinite(admittedAt.getTime())
    || admittedAt.toISOString() !== value.admitted_at
    || digestUnleashValue(value) !== digestUnleashValue(
      controllerPolicyAuthority(policy, plan, admittedAt),
    )
  ) fail('UNLEASH_RECON_AUTHORITY_DRIFT', 'retained reconnaissance authority differs from the deployment policy and target plan')
  return value
}

function controllerPolicyRevalidator({ policy, plan, isRevoked, now, authority, loaded }) {
  const authoritySha256 = digestUnleashValue(
    assertControllerPolicyAuthority(authority, policy, plan),
  )
  const limitsSha256 = digestUnleashValue(CONTROLLER_DEPLOYMENT_POLICY_LIMITS)
  return async (request) => {
    await assertCampaignDispatchOpen(loaded)
    if (
      !hasExactKeys(request, ['phase', 'authority', 'canonical_target', 'limits', 'plan_sha256'])
      || !['PRE_EXECUTION', 'ACTION_LEASE', 'PRE_DISPATCH'].includes(request.phase)
      || request.canonical_target !== plan.target.canonical_locator
      || typeof request.plan_sha256 !== 'string'
      || !/^[a-f0-9]{64}$/u.test(request.plan_sha256)
      || digestUnleashValue(request.authority) !== authoritySha256
      || digestUnleashValue(request.limits) !== limitsSha256
    ) fail('UNLEASH_RECON_AUTHORITY_DRIFT', 'HTTPS reconnaissance requested execution outside its exact deployment-policy admission')
    assertPolicyPlanBinding(policy, plan)
    assertPolicyAllowsTarget(policy, plan.target, {
      now: sampleNow(now),
      isRevoked,
      effect: 'OBSERVE',
    })
    if (request.phase !== 'PRE_EXECUTION') {
      const planned = await readCampaignReconPlanned(loaded)
      if (planned === null) {
        fail('UNLEASH_ACTION_RISK_PREFLIGHT_MISSING', 'dispatch requires the retained planned-action receipt')
      }
      const riskAdmission = await ensureCampaignActionRiskAdmission(
        loaded,
        policy,
        planned.action_id,
        now,
      )
      if (!riskAdmission.admitted) {
        fail(
          'UNLEASH_ACTION_RISK_CONFIRMATION_REQUIRED',
          'The exact action-risk assessment requires explicit operator confirmation before dispatch.',
          { runDirectory: loaded.state.run_directory, status: 'AWAITING_CONFIRMATION' },
        )
      }
    }
    return true
  }
}

function assertCampaignStorage(storage, runsRoot, campaignDirectory) {
  if (
    storage === null
    || typeof storage !== 'object'
    || typeof storage.writeImmutableJson !== 'function'
    || typeof storage.replaceMutableJson !== 'function'
    || typeof storage.readJson !== 'function'
    || typeof storage.listJsonFilenames !== 'function'
    || !sameResolvedPath(storage.runs_root, runsRoot)
    || !sameResolvedPath(storage.campaign_directory, join(runsRoot, campaignDirectory))
  ) fail('UNLEASH_STORAGE_INVALID', 'campaign storage returned an invalid or rebound location')
  return storage
}

function campaignFailure(code, message) {
  return { code, message }
}

function assertCampaignStopRequest(value, loaded) {
  const requestedAt = new Date(value?.requested_at)
  if (
    !hasExactKeys(value, [
      'schema_version', 'kind', 'campaign_id', 'plan_sha256', 'policy_id',
      'policy_sha256', 'target_id', 'revocation_check_id', 'requested_at', 'reason',
    ])
    || value.schema_version !== '1.0.0'
    || value.kind !== 'last-aperture/unleash-stop-request'
    || value.campaign_id !== loaded.state.campaign_id
    || value.plan_sha256 !== loaded.plan.plan_sha256
    || value.policy_id !== loaded.plan.policy_id
    || value.policy_sha256 !== loaded.plan.policy_sha256
    || value.target_id !== loaded.plan.target.target_id
    || value.revocation_check_id !== loaded.plan.authority.revocation.check_id
    || !Number.isFinite(requestedAt.getTime())
    || requestedAt.toISOString() !== value.requested_at
    || typeof value.reason !== 'string'
    || value.reason.length < 1
    || value.reason.length > 1024
    || /[\u0000-\u001f\u007f]/u.test(value.reason)
  ) fail('UNLEASH_STOP_REQUEST_INVALID', 'campaign stop request is malformed or differs from its retained plan')
  return Object.freeze(structuredClone(value))
}

function createCampaignStopRequest(loaded, reason, requestedAt) {
  const request = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-stop-request',
    campaign_id: loaded.state.campaign_id,
    plan_sha256: loaded.plan.plan_sha256,
    policy_id: loaded.plan.policy_id,
    policy_sha256: loaded.plan.policy_sha256,
    target_id: loaded.plan.target.target_id,
    revocation_check_id: loaded.plan.authority.revocation.check_id,
    requested_at: requestedAt,
    reason,
  }
  return assertCampaignStopRequest(request, loaded)
}

async function readCampaignStopRequest(loaded) {
  try {
    return assertCampaignStopRequest(
      await loaded.storage.readJson(STOP_REQUEST_FILE),
      loaded,
    )
  } catch (cause) {
    if (cause?.code === 'UNLEASH_STORAGE_FILE_NOT_FOUND') return null
    throw cause
  }
}

function terminalFenceBody(loaded, {
  decision,
  recordedAt,
  reason = null,
  basis = null,
  result = null,
}) {
  return {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-swarm-terminal-fence',
    decision,
    campaign_id: loaded.state.campaign_id,
    plan_sha256: loaded.plan.plan_sha256,
    policy_id: loaded.plan.policy_id,
    policy_sha256: loaded.plan.policy_sha256,
    target_id: loaded.plan.target.target_id,
    revocation_check_id: loaded.plan.authority.revocation.check_id,
    recorded_at: recordedAt,
    reason,
    swarm_basis_sha256: basis?.basis_sha256 ?? null,
    swarm_merge_sha256: result?.merge?.merge_sha256 ?? null,
    swarm_ledger_sha256: result?.ledger?.ledger_sha256 ?? null,
    termination_sha256: result === null ? null : digestUnleashValue(result.termination),
    usage_sha256: result === null ? null : digestUnleashValue(result.usage),
    gaps_sha256: result === null ? null : digestUnleashValue(result.gaps),
  }
}

function assertProtocolV2SwarmTerminalFence(value, loaded) {
  const retained = value === null || typeof value !== 'object' || Array.isArray(value)
    ? null
    : structuredClone(value)
  const recordedAt = new Date(retained?.recorded_at)
  const expectedFields = [
    'schema_version', 'kind', 'decision', 'campaign_id', 'plan_sha256', 'policy_id',
    'policy_sha256', 'target_id', 'revocation_check_id', 'recorded_at', 'reason',
    'swarm_basis_sha256', 'swarm_merge_sha256', 'swarm_ledger_sha256',
    'termination_sha256', 'usage_sha256', 'gaps_sha256', 'fence_sha256',
  ]
  if (
    loaded.state.schema_version !== '2.0.0'
    || retained === null
    || !hasExactKeys(retained, expectedFields)
    || retained.schema_version !== '1.0.0'
    || retained.kind !== 'last-aperture/unleash-swarm-terminal-fence'
    || !['STOP', 'SEAL'].includes(retained.decision)
    || retained.campaign_id !== loaded.state.campaign_id
    || retained.plan_sha256 !== loaded.plan.plan_sha256
    || retained.policy_id !== loaded.plan.policy_id
    || retained.policy_sha256 !== loaded.plan.policy_sha256
    || retained.target_id !== loaded.plan.target.target_id
    || retained.revocation_check_id !== loaded.plan.authority.revocation.check_id
    || !Number.isFinite(recordedAt.getTime())
    || recordedAt.toISOString() !== retained.recorded_at
    || !/^[a-f0-9]{64}$/u.test(retained.fence_sha256 ?? '')
  ) fail('UNLEASH_SWARM_TERMINAL_FENCE_INVALID', 'swarm terminal fence is malformed or differs from its retained campaign authority')
  const { fence_sha256: fenceSha256, ...unsigned } = retained
  if (fenceSha256 !== digestUnleashValue(unsigned)) {
    fail('UNLEASH_SWARM_TERMINAL_FENCE_INVALID', 'swarm terminal fence digest changed')
  }
  const boundDigests = [
    retained.swarm_basis_sha256,
    retained.swarm_merge_sha256,
    retained.swarm_ledger_sha256,
    retained.termination_sha256,
    retained.usage_sha256,
    retained.gaps_sha256,
  ]
  if (retained.decision === 'STOP') {
    if (
      typeof retained.reason !== 'string'
      || retained.reason.length < 1
      || retained.reason.length > 1024
      || /[\u0000-\u001f\u007f]/u.test(retained.reason)
      || boundDigests.some((digest) => digest !== null)
    ) fail('UNLEASH_SWARM_TERMINAL_FENCE_INVALID', 'STOP fence must retain one bounded reason and no seal result')
  } else if (
    retained.reason !== null
    || boundDigests.some((digest) => typeof digest !== 'string' || !/^[a-f0-9]{64}$/u.test(digest))
  ) fail('UNLEASH_SWARM_TERMINAL_FENCE_INVALID', 'SEAL fence must bind one exact swarm result and no stop reason')
  return Object.freeze(retained)
}

function createProtocolV2SwarmTerminalFence(loaded, input) {
  const unsigned = terminalFenceBody(loaded, input)
  return assertProtocolV2SwarmTerminalFence({
    ...unsigned,
    fence_sha256: digestUnleashValue(unsigned),
  }, loaded)
}

async function readProtocolV2SwarmTerminalFence(loaded) {
  if (loaded.state.schema_version !== '2.0.0') return null
  try {
    return assertProtocolV2SwarmTerminalFence(
      await loaded.storage.readJson(SWARM_TERMINAL_FENCE_FILE),
      loaded,
    )
  } catch (cause) {
    if (cause?.code === 'UNLEASH_STORAGE_FILE_NOT_FOUND') return null
    throw cause
  }
}

async function publishProtocolV2SwarmTerminalFence(loaded, fence) {
  assertProtocolV2SwarmTerminalFence(fence, loaded)
  try {
    await loaded.storage.writeImmutableJson(SWARM_TERMINAL_FENCE_FILE, fence)
    return fence
  } catch (cause) {
    if (cause?.code !== 'UNLEASH_STORAGE_FILE_EXISTS') throw cause
    const retained = await readProtocolV2SwarmTerminalFence(loaded)
    if (retained === null) {
      fail('UNLEASH_SWARM_TERMINAL_FENCE_CHANGED', 'winning terminal fence disappeared before it could be verified')
    }
    return retained
  }
}

function stopRequestFromTerminalFence(loaded, fence) {
  if (fence?.decision !== 'STOP') return null
  return createCampaignStopRequest(loaded, fence.reason, fence.recorded_at)
}

function assertSealFenceBindsResult(fence, basis, result) {
  if (
    fence.decision !== 'SEAL'
    || fence.swarm_basis_sha256 !== basis.basis_sha256
    || fence.swarm_merge_sha256 !== result.merge.merge_sha256
    || fence.swarm_ledger_sha256 !== result.ledger.ledger_sha256
    || fence.termination_sha256 !== digestUnleashValue(result.termination)
    || fence.usage_sha256 !== digestUnleashValue(result.usage)
    || fence.gaps_sha256 !== digestUnleashValue(result.gaps)
  ) fail('UNLEASH_SWARM_TERMINAL_FENCE_DRIFT', 'winning SEAL fence differs from the exact recoverable swarm result')
  return fence
}

function assertSealFenceHasRecoverableArtifacts(fence, swarmArtifacts) {
  if (fence?.decision !== 'SEAL') return
  if (
    swarmArtifacts.swarmBasis === null
    || swarmArtifacts.swarmMerge === null
    || swarmArtifacts.swarmLedger === null
    || fence.swarm_basis_sha256 !== swarmArtifacts.swarmBasis.basis_sha256
    || fence.swarm_merge_sha256 !== swarmArtifacts.swarmMerge.merge_sha256
    || fence.swarm_ledger_sha256 !== swarmArtifacts.swarmLedger.ledger_sha256
  ) fail('UNLEASH_SWARM_TERMINAL_FENCE_DRIFT', 'SEAL fence lacks its exact recoverable basis, merge, or attempt ledger')
}

async function readEffectiveCampaignStopRequest(loaded) {
  const request = await readCampaignStopRequest(loaded)
  if (loaded.state.schema_version !== '2.0.0') return request
  const fence = await readProtocolV2SwarmTerminalFence(loaded)
  if (fence === null) return request
  if (fence.decision === 'SEAL') {
    if (request !== null) {
      fail('UNLEASH_SWARM_TERMINAL_FENCE_CONFLICT', 'a stop request conflicts with the retained SEAL fence')
    }
    return null
  }
  const fencedRequest = stopRequestFromTerminalFence(loaded, fence)
  if (request !== null && digestUnleashValue(request) !== digestUnleashValue(fencedRequest)) {
    fail('UNLEASH_SWARM_TERMINAL_FENCE_CONFLICT', 'retained stop request differs from the winning STOP fence')
  }
  return fencedRequest
}

async function retainCampaignStopRequest(loaded, request) {
  assertCampaignStopRequest(request, loaded)
  try {
    await loaded.storage.writeImmutableJson(STOP_REQUEST_FILE, request)
    return request
  } catch (cause) {
    if (cause?.code !== 'UNLEASH_STORAGE_FILE_EXISTS') throw cause
    const retained = await readCampaignStopRequest(loaded)
    if (digestUnleashValue(retained) !== digestUnleashValue(request)) {
      fail('UNLEASH_STOP_REQUEST_CHANGED', 'retained campaign stop request differs from the winning immutable stop intent')
    }
    return retained
  }
}

async function publishCampaignStopRequest(loaded, reason, now) {
  return retainCampaignStopRequest(
    loaded,
    createCampaignStopRequest(loaded, reason, sampleNow(now).toISOString()),
  )
}

async function claimProtocolV2StopFence(loaded, reason, now) {
  const retainedRequest = await readCampaignStopRequest(loaded)
  const request = retainedRequest ?? createCampaignStopRequest(
    loaded,
    reason,
    sampleNow(now).toISOString(),
  )
  const candidate = createProtocolV2SwarmTerminalFence(loaded, {
    decision: 'STOP',
    recordedAt: request.requested_at,
    reason: request.reason,
  })
  const winner = await publishProtocolV2SwarmTerminalFence(loaded, candidate)
  if (winner.decision === 'SEAL') {
    if (retainedRequest !== null) {
      fail('UNLEASH_SWARM_TERMINAL_FENCE_CONFLICT', 'a retained stop request cannot follow the winning SEAL fence')
    }
    return Object.freeze({ decision: 'SEAL', request: null, fence: winner })
  }
  const winningRequest = stopRequestFromTerminalFence(loaded, winner)
  await retainCampaignStopRequest(loaded, winningRequest)
  return Object.freeze({ decision: 'STOP', request: winningRequest, fence: winner })
}

function boundedRollbackStopReason(reason) {
  return ROLLBACK_STOP_REASON_PREFIX
    + reason.slice(0, 1024 - ROLLBACK_STOP_REASON_PREFIX.length)
}

async function recoverProtocolV2RollbackStop(loaded, now) {
  const pause = await readUnleashCampaignPauseControl({
    storage: loaded.storage,
    plan: loaded.plan,
    state: loaded.state,
  })
  const rollback = pause.rollbacks.at(-1)
  if (rollback === undefined) return null
  const claim = await claimProtocolV2StopFence(
    loaded,
    boundedRollbackStopReason(rollback.reason),
    now,
  )
  return claim
}

async function assertCampaignDispatchOpen(loaded) {
  const request = await readEffectiveCampaignStopRequest(loaded)
  if (request !== null) {
    fail(
      'UNLEASH_CAMPAIGN_STOP_REQUESTED',
      'The durable campaign stop gate is closed; target dispatch is forbidden.',
      { runDirectory: loaded.state.run_directory, status: 'STOP_REQUESTED' },
    )
  }
  if (loaded.state.schema_version === '2.0.0') {
    const pause = await readUnleashCampaignPauseControl({
      storage: loaded.storage,
      plan: loaded.plan,
      state: loaded.state,
    })
    if (!pause.dispatch_open) {
      fail(
        'UNLEASH_CAMPAIGN_PAUSED',
        'The durable campaign Pause gate is closed; target dispatch is forbidden.',
        { runDirectory: loaded.state.run_directory, status: 'PAUSED' },
      )
    }
  }
}

function assertCampaignReconPlanned(value, loaded) {
  const recordedAt = new Date(value?.recorded_at)
  if (
    !hasExactKeys(value, [
      'schema_version', 'kind', 'campaign_id', 'plan_sha256', 'recon_bundle',
      'action_id', 'authority_sha256', 'recorded_at',
    ])
    || value.schema_version !== '1.0.0'
    || value.kind !== 'last-aperture/unleash-recon-planned'
    || value.campaign_id !== loaded.state.campaign_id
    || value.plan_sha256 !== loaded.plan.plan_sha256
    || !sameResolvedPath(value.recon_bundle, loaded.state.recon_bundle)
    || typeof value.action_id !== 'string'
    || !/^http-recon-action:[a-f0-9]{64}$/u.test(value.action_id)
    || loaded.reconAuthority === null
    || value.authority_sha256 !== digestUnleashValue(loaded.reconAuthority)
    || !Number.isFinite(recordedAt.getTime())
    || recordedAt.toISOString() !== value.recorded_at
  ) fail('UNLEASH_RECON_PLANNED_INVALID', 'retained reconnaissance planning receipt differs from the campaign and authority')
  return Object.freeze(structuredClone(value))
}

async function readCampaignReconPlanned(loaded) {
  try {
    return assertCampaignReconPlanned(
      await loaded.storage.readJson(RECON_PLANNED_FILE),
      loaded,
    )
  } catch (cause) {
    if (cause?.code === 'UNLEASH_STORAGE_FILE_NOT_FOUND') return null
    throw cause
  }
}

async function publishCampaignReconPlanned(loaded, planned, now) {
  if (
    !sameResolvedPath(planned?.bundle, loaded.state.recon_bundle)
    || typeof planned?.action_id !== 'string'
    || digestUnleashValue(planned?.authority) !== digestUnleashValue(loaded.reconAuthority)
  ) fail('UNLEASH_RECON_PLANNED_INVALID', 'nested reconnaissance planning callback differs from the campaign authority')
  const receipt = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-recon-planned',
    campaign_id: loaded.state.campaign_id,
    plan_sha256: loaded.plan.plan_sha256,
    recon_bundle: loaded.state.recon_bundle,
    action_id: planned.action_id,
    authority_sha256: digestUnleashValue(loaded.reconAuthority),
    recorded_at: sampleNow(now).toISOString(),
  }
  assertCampaignReconPlanned(receipt, loaded)
  try {
    await loaded.storage.writeImmutableJson(RECON_PLANNED_FILE, receipt)
  } catch (cause) {
    if (cause?.code !== 'UNLEASH_STORAGE_FILE_EXISTS') throw cause
    const existing = await readCampaignReconPlanned(loaded)
    if (digestUnleashValue(existing) !== digestUnleashValue(receipt)) {
      fail('UNLEASH_RECON_PLANNED_CHANGED', 'nested reconnaissance planning receipt changed across recovery')
    }
  }
  return receipt
}

function httpsReconRiskFacts(plan) {
  return Object.freeze({
    tool_id: 'tool:https-recon',
    parameters: Object.freeze({ method: 'HEAD' }),
    target: plan.target.canonical_locator,
    effect: 'OBSERVE',
    volume: Object.freeze({
      request_count: 1,
      max_parallel_requests: 1,
      max_requests_per_minute: 1,
      minimum_interval_ms: 0,
    }),
  })
}

function assertCampaignActionRiskPreflight(value, loaded, policy = undefined) {
  const recordedAt = new Date(value?.recorded_at)
  if (
    !hasExactKeys(value, [
      'schema_version', 'kind', 'campaign_id', 'plan_sha256', 'policy_sha256',
      'target_id', 'policy_binding', 'profile_selection', 'action_id', 'receipt',
      'recorded_at', 'preflight_sha256',
    ])
    || value.schema_version !== '1.0.0'
    || value.kind !== 'last-aperture/unleash-action-risk-preflight'
    || value.campaign_id !== loaded.state.campaign_id
    || value.plan_sha256 !== loaded.plan.plan_sha256
    || value.policy_sha256 !== loaded.plan.policy_sha256
    || value.target_id !== loaded.plan.target.target_id
    || !['DETECTION_POLICY_BOUND', 'LEGACY_POLICY_DEFAULTED'].includes(value.policy_binding)
    || !hasExactKeys(value.profile_selection, [
      'configured_profile', 'operational_profile', 'selection_reason',
    ])
    || typeof value.action_id !== 'string'
    || !/^http-recon-action:[a-f0-9]{64}$/u.test(value.action_id)
    || !Number.isFinite(recordedAt.getTime())
    || recordedAt.toISOString() !== value.recorded_at
    || typeof value.preflight_sha256 !== 'string'
    || !/^[a-f0-9]{64}$/u.test(value.preflight_sha256)
  ) fail('UNLEASH_ACTION_RISK_PREFLIGHT_INVALID', 'action-risk preflight is malformed or differs from its campaign')
  try {
    assertValidUnleashActionRiskReceipt(value.receipt, { action_id: value.action_id })
  } catch (cause) {
    fail('UNLEASH_ACTION_RISK_PREFLIGHT_INVALID', 'action-risk receipt is invalid', { cause })
  }
  const { preflight_sha256: preflightSha256, ...unsigned } = value
  if (
    preflightSha256 !== digestUnleashValue(unsigned)
    || value.receipt.assessment.target !== loaded.plan.target.canonical_locator
    || value.receipt.assessment.tool_id !== 'tool:https-recon'
    || value.receipt.assessment.effect !== 'OBSERVE'
    || value.receipt.assessment.operational_profile
      !== value.profile_selection.operational_profile
  ) fail('UNLEASH_ACTION_RISK_PREFLIGHT_INVALID', 'action-risk preflight digest or action binding changed')
  if (policy !== undefined) {
    const binding = assertPolicyPlanBinding(policy, loaded.plan)
    const expectedAssessment = assessUnleashActionRisk(
      httpsReconRiskFacts(loaded.plan),
      binding.selection.operational_profile,
    )
    const expectedReceipt = createUnleashActionRiskReceipt({
      action_id: value.action_id,
      assessment: expectedAssessment,
    })
    if (
      value.policy_binding !== binding.binding
      || digestUnleashValue(value.profile_selection) !== digestUnleashValue(binding.selection)
      || digestUnleashValue(value.receipt) !== digestUnleashValue(expectedReceipt)
    ) fail('UNLEASH_ACTION_RISK_PREFLIGHT_DRIFT', 'action-risk preflight differs from the bound detection policy')
  }
  return Object.freeze(structuredClone(value))
}

async function readCampaignActionRiskPreflight(loaded, policy = undefined) {
  try {
    return assertCampaignActionRiskPreflight(
      await loaded.storage.readJson(ACTION_RISK_PREFLIGHT_FILE),
      loaded,
      policy,
    )
  } catch (cause) {
    if (cause?.code === 'UNLEASH_STORAGE_FILE_NOT_FOUND') return null
    throw cause
  }
}

function assertCampaignActionRiskConfirmation(value, loaded, preflight) {
  const confirmedAt = new Date(value?.confirmed_at)
  if (
    !hasExactKeys(value, [
      'schema_version', 'kind', 'campaign_id', 'plan_sha256', 'policy_sha256',
      'target_id', 'action_id', 'preflight_sha256', 'operator_reason',
      'confirmation', 'confirmed_at', 'confirmation_sha256',
    ])
    || value.schema_version !== '1.0.0'
    || value.kind !== 'last-aperture/unleash-action-risk-confirmation-record'
    || value.campaign_id !== loaded.state.campaign_id
    || value.plan_sha256 !== loaded.plan.plan_sha256
    || value.policy_sha256 !== loaded.plan.policy_sha256
    || value.target_id !== loaded.plan.target.target_id
    || value.action_id !== preflight.action_id
    || value.preflight_sha256 !== preflight.preflight_sha256
    || typeof value.operator_reason !== 'string'
    || value.operator_reason.length < 8
    || value.operator_reason.length > 1024
    || /[\u0000-\u001f\u007f]/u.test(value.operator_reason)
    || !Number.isFinite(confirmedAt.getTime())
    || confirmedAt.toISOString() !== value.confirmed_at
    || typeof value.confirmation_sha256 !== 'string'
    || !/^[a-f0-9]{64}$/u.test(value.confirmation_sha256)
  ) fail('UNLEASH_ACTION_RISK_CONFIRMATION_INVALID', 'action-risk confirmation is malformed or differs from its campaign')
  const { confirmation_sha256: confirmationSha256, ...unsigned } = value
  if (confirmationSha256 !== digestUnleashValue(unsigned)) {
    fail('UNLEASH_ACTION_RISK_CONFIRMATION_INVALID', 'action-risk confirmation digest changed')
  }
  try {
    assertUnleashActionRiskConfirmation({
      receipt: preflight.receipt,
      confirmation: value.confirmation,
    })
  } catch (cause) {
    fail('UNLEASH_ACTION_RISK_CONFIRMATION_INVALID', 'action-risk confirmation does not bind the exact receipt', { cause })
  }
  return Object.freeze(structuredClone(value))
}

async function readCampaignActionRiskConfirmation(loaded, preflight) {
  try {
    return assertCampaignActionRiskConfirmation(
      await loaded.storage.readJson(ACTION_RISK_CONFIRMATION_FILE),
      loaded,
      preflight,
    )
  } catch (cause) {
    if (cause?.code === 'UNLEASH_STORAGE_FILE_NOT_FOUND') return null
    throw cause
  }
}

async function ensureCampaignActionRiskAdmission(loaded, policy, actionId, now) {
  const binding = assertPolicyPlanBinding(policy, loaded.plan)
  let preflight = await readCampaignActionRiskPreflight(loaded, policy)
  if (preflight === null) {
    const assessment = assessUnleashActionRisk(
      httpsReconRiskFacts(loaded.plan),
      binding.selection.operational_profile,
    )
    const receipt = createUnleashActionRiskReceipt({ action_id: actionId, assessment })
    const unsigned = {
      schema_version: '1.0.0',
      kind: 'last-aperture/unleash-action-risk-preflight',
      campaign_id: loaded.state.campaign_id,
      plan_sha256: loaded.plan.plan_sha256,
      policy_sha256: loaded.plan.policy_sha256,
      target_id: loaded.plan.target.target_id,
      policy_binding: binding.binding,
      profile_selection: structuredClone(binding.selection),
      action_id: actionId,
      receipt,
      recorded_at: sampleNow(now).toISOString(),
    }
    const created = assertCampaignActionRiskPreflight({
      ...unsigned,
      preflight_sha256: digestUnleashValue(unsigned),
    }, loaded, policy)
    try {
      await loaded.storage.writeImmutableJson(ACTION_RISK_PREFLIGHT_FILE, created)
    } catch (cause) {
      if (cause?.code !== 'UNLEASH_STORAGE_FILE_EXISTS') throw cause
    }
    preflight = await readCampaignActionRiskPreflight(loaded, policy)
  }
  if (preflight.action_id !== actionId) {
    fail('UNLEASH_ACTION_RISK_PREFLIGHT_DRIFT', 'retained action-risk preflight belongs to a different action')
  }
  const confirmation = await readCampaignActionRiskConfirmation(loaded, preflight)
  try {
    assertUnleashActionRiskConfirmation({
      receipt: preflight.receipt,
      confirmation: confirmation?.confirmation ?? null,
    })
    return Object.freeze({ admitted: true, confirmation, preflight })
  } catch (cause) {
    if (cause?.code === 'UNLEASH_ACTION_RISK_CONFIRMATION_REQUIRED') {
      return Object.freeze({ admitted: false, confirmation: null, preflight })
    }
    fail('UNLEASH_ACTION_RISK_ADMISSION_BLOCKED', 'action-risk policy blocked action admission', { cause })
  }
}

function publicActionRiskSummary(admission) {
  if (admission?.preflight == null) {
    return Object.freeze({ state: 'NOT_ASSESSED' })
  }
  const { preflight, confirmation, admitted } = admission
  const assessment = preflight.receipt.assessment
  return Object.freeze({
    state: admitted ? 'ADMITTED' : 'CONFIRMATION_REQUIRED',
    action_id: preflight.action_id,
    profile: assessment.operational_profile,
    profile_selection: structuredClone(preflight.profile_selection),
    catalog_id: assessment.catalog_id,
    catalog_version: assessment.catalog_version,
    reviewed_at: assessment.reviewed_at,
    detection_pattern_model_id: assessment.detection_pattern_model_id,
    detection_pattern_model_version: assessment.detection_pattern_model_version,
    matched_pattern_ids: [...assessment.matched_pattern_ids],
    methodology: assessment.methodology,
    control_signal_score_semantics: assessment.control_signal_score_semantics,
    telemetry_coverage: assessment.telemetry_coverage,
    collection_precondition: assessment.collection_precondition,
    risk_score: assessment.risk_score,
    risk_level: assessment.risk_level,
    noise_score: assessment.noise_score,
    noise_level: assessment.noise_level,
    rationale: [...assessment.rationale],
    likely_impacts: structuredClone(assessment.likely_impacts),
    control_signals: structuredClone(assessment.control_signals),
    confirmation_required: assessment.controller_confirmation_required,
    confirmation_reasons: [...assessment.confirmation_reasons],
    assessment_sha256: preflight.receipt.assessment_sha256,
    receipt_sha256: preflight.receipt.receipt_sha256,
    preflight_sha256: preflight.preflight_sha256,
    confirmation_sha256: confirmation?.confirmation_sha256 ?? null,
  })
}

function publicPauseControlSummary(control) {
  if (control === undefined) return undefined
  return Object.freeze({
    state: control.state,
    dispatch_open: control.dispatch_open,
    reason: control.active_requests.at(-1)?.reason ?? null,
    request_count: control.request_count,
    acknowledgement_count: control.acknowledgement_count,
  })
}

function publicRollbackSummary(control) {
  if (control === undefined) return undefined
  return Object.freeze({
    enabled: control.state === 'PAUSED',
    state: control.rollback_request_count > 0 ? 'REQUESTED' : 'AVAILABLE',
    request_count: control.rollback_request_count,
    scope: Object.freeze(['NOT_YET_DISPATCHED', 'PROPOSED_INERT']),
    target_side_effects_reversed: false,
  })
}

function publicSummaryWithActionRisk(state, admission, pauseControl = undefined) {
  const summary = {
    ...publicSummary(state),
    detection: publicActionRiskSummary(admission),
  }
  if (pauseControl !== undefined) {
    summary.pause = publicPauseControlSummary(pauseControl)
    summary.rollback = publicRollbackSummary(pauseControl)
  }
  return Object.freeze(summary)
}

async function publicControlledCampaignSummary(loaded) {
  const preflight = await readCampaignActionRiskPreflight(loaded)
  const confirmation = preflight === null
    ? null
    : await readCampaignActionRiskConfirmation(loaded, preflight)
  const pause = loaded.state.schema_version === '2.0.0'
    ? await readUnleashCampaignPauseControl({
        storage: loaded.storage,
        plan: loaded.plan,
        state: loaded.state,
      })
    : undefined
  return publicSummaryWithActionRisk(loaded.state, preflight === null
    ? null
    : {
        admitted: !preflight.receipt.controller_confirmation_required || confirmation !== null,
        confirmation,
        preflight,
      }, pause)
}

function campaignReconPlannedCallback(loaded, dependencies, now, policy) {
  return async (planned) => {
    await publishCampaignReconPlanned(loaded, planned, now)
    const admission = await ensureCampaignActionRiskAdmission(
      loaded,
      policy,
      planned.action_id,
      now,
    )
    await dependencies.onActionRiskPreflight?.(publicActionRiskSummary(admission))
    if (!admission.admitted) {
      fail(
        'UNLEASH_ACTION_RISK_CONFIRMATION_REQUIRED',
        'The exact action-risk assessment requires explicit operator confirmation before dispatch.',
        { runDirectory: loaded.state.run_directory, status: 'AWAITING_CONFIRMATION' },
      )
    }
    await dependencies.onHttpReconPlanned?.(planned)
  }
}

function managementInput(input, fields) {
  if (!hasExactKeys(input, fields)) fail('UNLEASH_CAMPAIGN_INPUT_INVALID', 'campaign management input contains invalid fields')
  if (
    typeof input.bundle !== 'string'
    || input.bundle.length < 1
    || input.bundle.length > 4096
    || /[\u0000-\u001f\u007f]/u.test(input.bundle)
    || !isAbsolute(input.bundle)
    || resolve(input.bundle) !== input.bundle
  ) fail('UNLEASH_CAMPAIGN_INPUT_INVALID', 'campaign bundle must be one canonical absolute path')
  return input
}

function assertStatePlanBinding(state, plan, storage) {
  assertSelfBoundUnleashPlan(plan)
  const counts = routeCounts(plan)
  if (
    state.plan_sha256 !== plan.plan_sha256
    || !sameResolvedPath(state.run_directory, storage.campaign_directory)
    || !sameResolvedPath(state.recon_bundle, join(storage.campaign_directory, 'recon'))
    || digestUnleashValue(state.target) !== digestUnleashValue(plan.target)
    || digestUnleashValue(state.route_counts) !== digestUnleashValue(counts)
    || state.gap_count !== counts.waiting + counts.unavailable + counts.blocked
  ) fail('UNLEASH_CAMPAIGN_PLAN_DRIFT', 'campaign state differs from its retained self-bound plan')
}

function retainedPlanPolicy(plan) {
  return {
    schema_version: '1.0.0',
    policy_id: plan.policy_id,
    valid_from: plan.authority.valid_from,
    valid_until: plan.authority.valid_until,
    allowed_origins: [...plan.authority.allowed_origins],
    allowed_target_families: [...plan.authority.allowed_target_families],
    allowed_effects: [...plan.allowed_effects],
    budgets: structuredClone(plan.budgets),
    revocation: structuredClone(plan.authority.revocation),
    controller_policy_sha256: plan.policy_sha256,
  }
}

async function assertCompletedCampaignArtifacts(storage, state, plan, reconAuthority) {
  if (state.evidence_packet_sha256 === null) {
    return { completion: null, evidencePacket: null }
  }
  try {
    const completion = await storage.readJson('https-recon-completion.json')
    const packet = await storage.readJson('evidence-packet.json')
    assertValidUnleashReconCompletion(completion, { plan })
    if (
      digestUnleashValue(packet) !== digestUnleashValue(completion.evidence_packet)
      || packet.packet_sha256 !== state.evidence_packet_sha256
      || completion.completion_receipt.completion_receipt_sha256 !== state.completion_receipt_sha256
      || digestUnleashValue(completion.completion_receipt.authority) !== digestUnleashValue(reconAuthority)
      || state.completed_routes.length !== 1
      || state.completed_routes[0] !== completion.completion_receipt.route_id
    ) fail('UNLEASH_COMPLETED_CAMPAIGN_EVIDENCE_INVALID', 'completed campaign state differs from its retained packet or typed completion receipt')
    return { completion, evidencePacket: packet }
  } catch (cause) {
    throw new UnleashControllerError(
      'UNLEASH_COMPLETED_CAMPAIGN_EVIDENCE_INVALID',
      'Completed campaign evidence is missing, malformed, or no longer matches its state.',
      { cause, runDirectory: state.run_directory, status: 'RECONCILIATION_REQUIRED' },
    )
  }
}

async function assertBasisPublicationArtifacts(storage, plan, reconAuthority, basis, runDirectory) {
  try {
    const completion = await storage.readJson('https-recon-completion.json')
    const packet = await storage.readJson('evidence-packet.json')
    assertValidUnleashReconCompletion(completion, { plan })
    if (
      digestUnleashValue(packet) !== digestUnleashValue(completion.evidence_packet)
      || packet.packet_sha256 !== basis.evidence_packet_sha256
      || completion.completion_receipt.completion_receipt_sha256
        !== basis.completion_receipt_sha256
      || digestUnleashValue(completion.completion_receipt.authority)
        !== digestUnleashValue(reconAuthority)
    ) fail(
      'UNLEASH_SWARM_BASIS_EVIDENCE_INVALID',
      'basis-ready campaign differs from its retained verified reconnaissance evidence',
      { runDirectory, status: 'RECONCILIATION_REQUIRED' },
    )
    return completion
  } catch (cause) {
    if (cause?.code === 'UNLEASH_SWARM_BASIS_EVIDENCE_INVALID') throw cause
    throw new UnleashControllerError(
      'UNLEASH_SWARM_BASIS_EVIDENCE_INVALID',
      'The published swarm basis cannot be verified against retained reconnaissance evidence.',
      { cause, runDirectory, status: 'RECONCILIATION_REQUIRED' },
    )
  }
}

async function readCandidateFrontierState(storage) {
  try {
    return await storage.readJson(UNLEASH_CANDIDATE_FRONTIER_STATE_FILE)
  } catch (cause) {
    if (cause?.code === 'UNLEASH_STORAGE_FILE_NOT_FOUND') return null
    throw cause
  }
}

async function readOptionalCampaignJson(storage, filename) {
  try {
    return await storage.readJson(filename)
  } catch (cause) {
    if (cause?.code === 'UNLEASH_STORAGE_FILE_NOT_FOUND') return null
    throw cause
  }
}

function swarmMergeArtifactDescriptors(inventory) {
  return inventory
    .map((filename) => {
      const match = SWARM_MERGE_FILE.exec(filename)
      return match === null
        ? null
        : { filename, round: Number(match[1]), wave: match[2] }
    })
    .filter((descriptor) => descriptor !== null)
    .sort((left, right) => compareCanonicalStrings(left.filename, right.filename))
}

function assertProtocolV2SwarmSequence({ basis, provider, descriptors, ledger, completion }) {
  for (const [index, descriptor] of descriptors.entries()) {
    const expectedRound = Math.floor(index / 2) + 1
    const expectedWave = index % 2 === 0 ? 'attack' : 'review'
    if (
      descriptor.round !== expectedRound
      || descriptor.wave !== expectedWave
      || descriptor.round > basis.limits.max_rounds
    ) fail(
      'UNLEASH_SWARM_MERGE_SEQUENCE_INVALID',
      'retained swarm merge artifacts do not form one exact ATTACK then REVIEW prefix',
    )
    if (descriptor.merge.round !== descriptor.round) {
      fail(
        'UNLEASH_SWARM_MERGE_FILENAME_DRIFT',
        `retained ${descriptor.filename} does not bind its encoded round`,
      )
    }
  }

  if (descriptors.length > 0 && ledger === null) {
    fail('UNLEASH_SWARM_LEDGER_STATE_MISSING', 'retained swarm merges require their exact attempt ledger')
  }
  if (ledger !== null) {
    const mergeByWave = new Map(descriptors.map((descriptor) => [
      `${descriptor.round}:${descriptor.wave}`,
      descriptor.merge,
    ]))
    const roleById = new Map(basis.roles.map((role) => [role.role_id, role]))
    const assignmentByRole = new Map(provider.assignments.map((assignment) => [
      assignment.role_id,
      assignment,
    ]))
    for (const attempt of ledger.attempts) {
      const assignment = assignmentByRole.get(attempt.role_id)
      if (
        assignment?.availability !== 'AVAILABLE'
        || attempt.adapter_identity.adapter_id !== assignment.adapter_id
        || attempt.adapter_identity.adapter_version !== assignment.adapter_version
        || attempt.adapter_identity.adapter_config_sha256 !== assignment.adapter_config_sha256
      ) fail(
        'UNLEASH_SWARM_LEDGER_PROVIDER_DRIFT',
        'a retained provider attempt differs from its sealed available adapter assignment',
      )
      if (attempt.state !== 'COMMITTED') continue
      const wave = roleById.get(attempt.role_id)?.wave.toLowerCase()
      const merge = mergeByWave.get(`${attempt.round}:${wave}`)
      if (merge === undefined || merge.merge_sha256 !== attempt.merge_sha256) {
        fail(
          'UNLEASH_SWARM_LEDGER_MERGE_DRIFT',
          'a committed provider attempt does not bind the immutable merge for its exact round and wave',
        )
      }
    }
  }

  if (completion === null) return
  const roundsCompleted = completion.usage.rounds_completed
  const terminal = descriptors.at(-1)
  if (
    roundsCompleted < 1
    || descriptors.length !== roundsCompleted * 2
    || terminal?.round !== roundsCompleted
    || terminal.wave !== 'review'
    || terminal.merge.merge_sha256 !== completion.merge_sha256
  ) fail(
    'UNLEASH_SWARM_MERGE_SEQUENCE_INVALID',
    'swarm completion does not bind the exact terminal REVIEW merge sequence',
  )
  const ledgerBinding = completion.attempt_ledger
  if (
    ledger === null
    || ledgerBinding.event_count !== ledger.event_count
    || ledgerBinding.attempt_count !== ledger.attempt_count
    || ledgerBinding.head_record_sha256 !== ledger.head_record_sha256
    || ledgerBinding.ledger_sha256 !== ledger.ledger_sha256
    || ledger.events.filter(({ state }) => state === 'STARTED').length
      !== completion.usage.provider_calls_started
    || ledger.response_bytes !== completion.usage.response_bytes
    || ledger.events.some(({ occurred_at: occurredAt }) => (
      Date.parse(occurredAt) > Date.parse(completion.completed_at)
    ))
    || ledger.attempts.some((attempt) => (
      attempt.round > roundsCompleted
      || !['COMMITTED', 'FAILED'].includes(attempt.state)
    ))
  ) fail(
    'UNLEASH_SWARM_COMPLETION_LEDGER_DRIFT',
    'swarm completion usage or terminality differs from its recovered attempt ledger',
  )
  for (const attempt of ledger.attempts.filter(({ state }) => state === 'FAILED')) {
    const matchedGap = completion.gaps.some((gap) => (
      gap.round === attempt.round
      && gap.role_id === attempt.role_id
      && gap.state === 'FAILED_CLOSED'
      && gap.reason_code === attempt.failure.reason_code
      && gap.request_id === attempt.request_id
    ))
    if (!matchedGap) {
      fail(
        'UNLEASH_SWARM_COMPLETION_LEDGER_DRIFT',
        'a failed terminal attempt has no exact completion gap',
      )
    }
  }
}

async function recoverProtocolV2SwarmLedger({
  storage,
  basis,
  inventory,
  repairSnapshot,
  now,
  mergeCount,
  hasCompletion,
}) {
  const attemptEvents = inventory.filter((filename) => SWARM_ATTEMPT_EVENT_FILE.test(filename))
  const hasLedgerState = inventory.includes(UNLEASH_SWARM_ATTEMPT_LEDGER_STATE_FILE)
  if (!hasLedgerState && attemptEvents.length === 0) {
    if (mergeCount > 0 || hasCompletion) {
      fail('UNLEASH_SWARM_LEDGER_STATE_MISSING', 'swarm merge or completion exists without its attempt ledger')
    }
    return null
  }
  const ledgerStorage = {
    writeImmutableJson: storage.writeImmutableJson,
    replaceMutableJson: storage.replaceMutableJson,
    readJson: storage.readJson,
    listJsonFilenames: storage.listJsonFilenames,
  }
  for (let attempt = 0; attempt < 3; attempt += 1) {
    let ledger = await recoverUnleashSwarmAttemptLedger({ basis }, { storage: ledgerStorage })
    if (ledger.reconciliation === 'CURRENT') return ledger
    if (!repairSnapshot) {
      fail(
        'UNLEASH_SWARM_LEDGER_STATE_STALE',
        'swarm attempt ledger head requires repair before a stable snapshot can be returned',
      )
    }
    const latest = ledger.events.at(-1)?.occurred_at ?? basis.recorded_at
    const updatedAt = new Date(Math.max(sampleNow(now).getTime(), Date.parse(latest))).toISOString()
    ledger = await reconcileUnleashSwarmAttemptLedger(
      { basis, updatedAt },
      { storage: ledgerStorage },
    )
    if (ledger.reconciliation === 'CURRENT') return ledger
  }
  fail(
    'UNLEASH_SWARM_LEDGER_CHANGED',
    'swarm attempt ledger changed repeatedly during bounded head reconciliation',
  )
}

async function readProtocolV2SwarmArtifacts({
  storage,
  plan,
  registry,
  provider,
  state,
  recovered,
  inventory,
  repairSnapshot,
  now,
}) {
  if (state.schema_version !== '2.0.0') {
    return {
      basisState: null,
      swarmBasis: null,
      swarmMerge: null,
      swarmCompletion: null,
      swarmLedger: null,
    }
  }
  const swarmFiles = inventory.filter((filename) => (
    filename === UNLEASH_SWARM_BASIS_FILE
    || filename === 'swarm-completion.json'
    || filename === 'swarm-attempt-ledger-state.json'
    || /^swarm-attempt-event-[0-9]{6}\.json$/u.test(filename)
    || /^swarm-merge-r[0-9]{2}-(?:attack|review)\.json$/u.test(filename)
  ))
  if (state.swarm_basis_sha256 === null) {
    const basisPublicationPending = ['RUNNING', 'RECONCILIATION_REQUIRED'].includes(state.status)
      && swarmFiles.length === 1
      && swarmFiles[0] === UNLEASH_SWARM_BASIS_FILE
    if (!basisPublicationPending) {
      if (swarmFiles.length > 0) {
        fail('UNLEASH_SWARM_STATE_DRIFT', 'campaign retains swarm artifacts before its state admits a swarm basis')
      }
      return {
        basisState: null,
        swarmBasis: null,
        swarmMerge: null,
        swarmCompletion: null,
        swarmLedger: null,
      }
    }
  }
  const swarmBasis = await storage.readJson(UNLEASH_SWARM_BASIS_FILE)
  assertValidUnleashSwarmBasis(swarmBasis)
  const basisState = recovered.states[swarmBasis.campaign_state_revision - 1]
  if (
    basisState === undefined
    || basisState.schema_version !== '2.0.0'
    || basisState.status !== 'RUNNING'
    || digestUnleashValue(basisState) !== swarmBasis.campaign_state_sha256
    || (state.swarm_basis_sha256 !== null && state.swarm_basis_sha256 !== swarmBasis.basis_sha256)
    || swarmBasis.campaign_id !== state.campaign_id
    || swarmBasis.plan_sha256 !== plan.plan_sha256
    || swarmBasis.target_id !== plan.target.target_id
    || swarmBasis.registry_sha256 !== digestUnleashValue(registry)
    || swarmBasis.provider_profile_sha256 !== digestUnleashValue(provider)
    || (state.evidence_packet_sha256 !== null
      && swarmBasis.evidence_packet_sha256 !== state.evidence_packet_sha256)
    || (state.completion_receipt_sha256 !== null
      && swarmBasis.completion_receipt_sha256 !== state.completion_receipt_sha256)
  ) fail('UNLEASH_SWARM_BASIS_DRIFT', 'retained swarm basis differs from campaign history, plan, provider, registry, or evidence')

  const retainedCompletion = await readOptionalCampaignJson(storage, 'swarm-completion.json')
  if (retainedCompletion !== null) assertValidUnleashSwarmCompletion(retainedCompletion, { basis: swarmBasis })
  if (
    (state.swarm_completion_sha256 !== null && (
      retainedCompletion === null
      || retainedCompletion.completion_sha256 !== state.swarm_completion_sha256
    ))
    || (state.swarm_completion_sha256 === null
      && ['COMPLETE', 'COMPLETE_WITH_GAPS'].includes(state.status))
  ) fail('UNLEASH_SWARM_COMPLETION_DRIFT', 'campaign swarm completion is missing or differs from its terminal state')

  const mergeDescriptors = swarmMergeArtifactDescriptors(inventory)
  for (const descriptor of mergeDescriptors) {
    const first = await storage.readJson(descriptor.filename)
    const second = await storage.readJson(descriptor.filename)
    assertValidUnleashSwarmMerge(first, { basis: swarmBasis })
    assertValidUnleashSwarmMerge(second, { basis: swarmBasis })
    if (digestUnleashValue(first) !== digestUnleashValue(second)) {
      fail('UNLEASH_SWARM_MERGE_CHANGED', `retained ${descriptor.filename} changed while it was recovered`)
    }
    descriptor.merge = first
  }
  const swarmLedger = await recoverProtocolV2SwarmLedger({
    storage,
    basis: swarmBasis,
    inventory,
    repairSnapshot,
    now,
    mergeCount: mergeDescriptors.length,
    hasCompletion: retainedCompletion !== null,
  })
  assertProtocolV2SwarmSequence({
    basis: swarmBasis,
    provider,
    descriptors: mergeDescriptors,
    ledger: swarmLedger,
    completion: retainedCompletion,
  })
  let requiredMergeSha256 = retainedCompletion?.merge_sha256 ?? null
  const admissionNames = inventory.filter((filename) => /^candidate-admission-[0-9]{6}\.json$/u.test(filename)).sort()
  if (requiredMergeSha256 === null && admissionNames.length > 0) {
    requiredMergeSha256 = (await storage.readJson(admissionNames.at(-1))).swarm_merge_sha256 ?? null
  }
  const matchingMerge = requiredMergeSha256 === null
    ? null
    : [...mergeDescriptors].reverse()
      .find(({ merge }) => merge.merge_sha256 === requiredMergeSha256)?.merge ?? null
  const swarmMerge = requiredMergeSha256 === null
    ? (mergeDescriptors.at(-1)?.merge ?? null)
    : matchingMerge
  if (requiredMergeSha256 !== null && swarmMerge === null) {
    fail('UNLEASH_SWARM_MERGE_MISSING', 'candidate or completion seal references no retained immutable swarm merge')
  }
  if (retainedCompletion !== null && (
    swarmMerge === null
    || retainedCompletion.frontier_sha256 !== swarmMerge.frontier_sha256
    || retainedCompletion.challenge_set_sha256 !== swarmMerge.challenge_set_sha256
    || retainedCompletion.candidate_count !== swarmMerge.candidate_count
    || retainedCompletion.proposed_action_count !== swarmMerge.proposed_action_count
    || retainedCompletion.challenge_count !== swarmMerge.challenge_count
  )) fail('UNLEASH_SWARM_COMPLETION_DRIFT', 'retained swarm completion differs from its immutable final merge')
  return {
    basisState,
    swarmBasis,
    swarmMerge,
    swarmCompletion: retainedCompletion,
    swarmLedger,
  }
}

async function reconcileCandidateFrontierProjection({
  storage,
  frontier,
  campaignState,
  repairSnapshot,
  now,
}) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const retainedState = await readCandidateFrontierState(storage)
    const reconciliation = reconcileUnleashCandidateFrontierState({
      frontier,
      retainedState,
      campaignState,
      recordedAt: sampleNow(now),
    })
    if (reconciliation.status === 'CURRENT') return reconciliation.frontier_state
    if (!repairSnapshot) {
      fail(
        'UNLEASH_CANDIDATE_FRONTIER_STATE_STALE',
        'candidate frontier state requires repair before a stable snapshot can be returned',
      )
    }
    const beforeWrite = await readCandidateFrontierState(storage)
    const retainedSha256 = retainedState?.frontier_state_sha256 ?? null
    if ((beforeWrite?.frontier_state_sha256 ?? null) !== retainedSha256) continue
    try {
      await storage.replaceMutableJson(
        UNLEASH_CANDIDATE_FRONTIER_STATE_FILE,
        reconciliation.frontier_state,
      )
    } catch (cause) {
      if (attempt < 2 && ['UNLEASH_STORAGE_CHANGED', 'UNLEASH_STORAGE_WRITE_FAILED'].includes(cause?.code)) {
        continue
      }
      throw cause
    }
    const verified = await storage.readJson(UNLEASH_CANDIDATE_FRONTIER_STATE_FILE)
    assertValidUnleashCandidateFrontierState(verified, { frontier, campaignState })
    return verified
  }
  fail(
    'UNLEASH_CANDIDATE_FRONTIER_STATE_CHANGED',
    'candidate frontier state changed repeatedly while recovery attempted a bounded repair',
  )
}

async function reconcileCandidateFrontierProjectionV2({
  storage,
  frontier,
  basisState,
  campaignState,
  swarmBasis,
  swarmMerge,
  swarmCompletion,
  repairSnapshot,
  now,
}) {
  const context = {
    frontier,
    basisState,
    campaignState,
    swarmBasis,
    swarmMerge,
    swarmCompletion,
  }
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const retainedState = await readCandidateFrontierState(storage)
    const reconciliation = reconcileUnleashCandidateFrontierStateV2({
      ...context,
      retainedState,
      recordedAt: sampleNow(now),
    })
    if (reconciliation.status === 'CURRENT') return reconciliation.frontier_state
    if (!repairSnapshot) {
      fail(
        'UNLEASH_CANDIDATE_FRONTIER_STATE_STALE',
        'protocol-v2 candidate frontier state requires repair before a stable snapshot can be returned',
      )
    }
    const beforeWrite = await readCandidateFrontierState(storage)
    const retainedSha256 = retainedState?.frontier_state_sha256 ?? null
    if ((beforeWrite?.frontier_state_sha256 ?? null) !== retainedSha256) continue
    try {
      await storage.replaceMutableJson(
        UNLEASH_CANDIDATE_FRONTIER_STATE_FILE,
        reconciliation.frontier_state,
      )
    } catch (cause) {
      if (attempt < 2 && ['UNLEASH_STORAGE_CHANGED', 'UNLEASH_STORAGE_WRITE_FAILED'].includes(cause?.code)) {
        continue
      }
      throw cause
    }
    const verified = await storage.readJson(UNLEASH_CANDIDATE_FRONTIER_STATE_FILE)
    assertValidUnleashCandidateFrontierStateV2(verified, context)
    return verified
  }
  fail(
    'UNLEASH_CANDIDATE_FRONTIER_STATE_CHANGED',
    'protocol-v2 candidate frontier state changed repeatedly during bounded repair',
  )
}

async function openCampaignIdentity(input, dependencies) {
  managementInput(input, ['bundle'])
  const bundle = resolve(input.bundle)
  const runsRoot = dirname(bundle)
  const campaignDirectory = basename(bundle)
  const openStorage = dependencies.openCampaignStorage ?? openUnleashCampaignStorage
  if (typeof openStorage !== 'function') fail('UNLEASH_STORAGE_INVALID', 'campaign recovery storage is unavailable')
  const storage = assertCampaignStorage(
    await openStorage({ runsRoot, campaignDirectory }),
    runsRoot,
    campaignDirectory,
  )
  let recovered
  try {
    recovered = await recoverUnleashCampaignState({ storage, repairSnapshot: false })
  } catch (cause) {
    throw new UnleashControllerError(
      cause?.code ?? 'UNLEASH_CAMPAIGN_RECOVERY_FAILED',
      'The campaign state chain could not be recovered safely.',
      { cause, runDirectory: storage.campaign_directory, status: 'RECONCILIATION_REQUIRED' },
    )
  }
  const plan = await storage.readJson('campaign-plan.json')
  const registry = await storage.readJson('campaign-registry.json')
  const provider = await storage.readJson('campaign-provider.json')
  assertValidUnleashPlan(plan, {
    registry,
    provider,
    policy: retainedPlanPolicy(plan),
  })
  assertStatePlanBinding(recovered.state, plan, storage)
  return {
    storage,
    plan,
    registry,
    provider,
    state: recovered.state,
    recovered,
  }
}

async function openCampaign(input, dependencies, { repairSnapshot = true } = {}) {
  managementInput(input, ['bundle'])
  const bundle = resolve(input.bundle)
  const runsRoot = dirname(bundle)
  const campaignDirectory = basename(bundle)
  const openStorage = dependencies.openCampaignStorage ?? openUnleashCampaignStorage
  if (typeof openStorage !== 'function') fail('UNLEASH_STORAGE_INVALID', 'campaign recovery storage is unavailable')
  const storage = assertCampaignStorage(
    await openStorage({ runsRoot, campaignDirectory }),
    runsRoot,
    campaignDirectory,
  )
  let recovered
  try {
    recovered = await recoverUnleashCampaignState({ storage, repairSnapshot })
  } catch (cause) {
    throw new UnleashControllerError(
      cause?.code ?? 'UNLEASH_CAMPAIGN_RECOVERY_FAILED',
      'The campaign state chain could not be recovered safely.',
      { cause, runDirectory: storage.campaign_directory, status: 'RECONCILIATION_REQUIRED' },
    )
  }
  const plan = await storage.readJson('campaign-plan.json')
  const registry = await storage.readJson('campaign-registry.json')
  const provider = await storage.readJson('campaign-provider.json')
  assertValidUnleashPlan(plan, {
    registry,
    provider,
    policy: retainedPlanPolicy(plan),
  })
  assertStatePlanBinding(recovered.state, plan, storage)
  const retainedPolicy = retainedPlanPolicy(plan)
  const inventory = await storage.listJsonFilenames()
  const hasReconAuthority = inventory.includes(RECON_AUTHORITY_FILE)
  let reconAuthority = null
  if (hasReconAuthority) {
    reconAuthority = assertControllerPolicyAuthority(
      await storage.readJson(RECON_AUTHORITY_FILE),
      retainedPolicy,
      plan,
    )
  } else if (
    recovered.state.evidence_packet_sha256 !== null
    || ['RUNNING', 'SWARMING', 'STOP_REQUESTED', 'COMPLETE', 'COMPLETE_WITH_GAPS'].includes(recovered.state.status)
  ) {
    fail('UNLEASH_RECON_AUTHORITY_MISSING', 'campaign state requires a retained controller-policy reconnaissance authority')
  }
  const completedArtifacts = await assertCompletedCampaignArtifacts(
    storage,
    recovered.state,
    plan,
    reconAuthority,
  )
  let swarmArtifacts
  try {
    swarmArtifacts = await readProtocolV2SwarmArtifacts({
      storage,
      plan,
      registry,
      provider,
      state: recovered.state,
      recovered,
      inventory,
      repairSnapshot,
      now: dependencies.now ?? (() => new Date()),
    })
  } catch (cause) {
    throw new UnleashControllerError(
      cause?.code ?? 'UNLEASH_SWARM_RECOVERY_FAILED',
      'The protocol-v2 swarm artifacts could not be recovered safely.',
      {
        cause,
        runDirectory: recovered.state.run_directory,
        status: 'RECONCILIATION_REQUIRED',
      },
    )
  }
  try {
    const terminalFence = await readProtocolV2SwarmTerminalFence({
      storage,
      plan,
      state: recovered.state,
    })
    assertSealFenceHasRecoverableArtifacts(terminalFence, swarmArtifacts)
  } catch (cause) {
    throw new UnleashControllerError(
      cause?.code ?? 'UNLEASH_SWARM_TERMINAL_FENCE_INVALID',
      'The protocol-v2 terminal fence could not be bound to its recoverable swarm artifacts.',
      {
        cause,
        runDirectory: recovered.state.run_directory,
        status: 'RECONCILIATION_REQUIRED',
      },
    )
  }
  if (
    recovered.state.schema_version === '2.0.0'
    && recovered.state.swarm_basis_sha256 === null
    && swarmArtifacts.swarmBasis !== null
  ) {
    await assertBasisPublicationArtifacts(
      storage,
      plan,
      reconAuthority,
      swarmArtifacts.swarmBasis,
      recovered.state.run_directory,
    )
  }
  const candidateAdmissionNames = inventory
    .filter((filename) => /^candidate-admission-[0-9]{6}\.json$/u.test(filename))
    .sort()
  let candidateFrontier = null
  let candidateFrontierState = null
  try {
    if (recovered.state.schema_version === '1.0.0') {
      if (
        completedArtifacts.completion === null
        && (
          inventory.includes(UNLEASH_CANDIDATE_FRONTIER_STATE_FILE)
          || candidateAdmissionNames.length > 0
        )
      ) fail('UNLEASH_CANDIDATE_CAMPAIGN_NOT_COMPLETE', 'a non-complete protocol-v1 campaign cannot retain candidate admissions')
      candidateFrontier = completedArtifacts.completion === null
        ? createEmptyUnleashCandidateFrontier({ plan, campaignState: recovered.state })
        : await recoverUnleashCandidateFrontier({
            storage,
            plan,
            registry,
            provider,
            campaignState: recovered.state,
            evidencePacket: completedArtifacts.evidencePacket,
            completion: completedArtifacts.completion,
          })
      if (completedArtifacts.completion !== null) {
        candidateFrontierState = await reconcileCandidateFrontierProjection({
          storage,
          frontier: candidateFrontier,
          campaignState: recovered.state,
          repairSnapshot,
          now: dependencies.now ?? (() => new Date()),
        })
      }
    } else if (candidateAdmissionNames.length > 0) {
      if (
        completedArtifacts.completion === null
        || swarmArtifacts.basisState === null
        || swarmArtifacts.swarmBasis === null
        || swarmArtifacts.swarmMerge === null
      ) fail('UNLEASH_CANDIDATE_SWARM_CONTEXT_MISSING', 'protocol-v2 candidate admissions require exact recon, basis, and final merge artifacts')
      const sealedCompletion = recovered.state.swarm_completion_sha256 === null
        ? null
        : swarmArtifacts.swarmCompletion
      candidateFrontier = await recoverUnleashCandidateFrontierV2({
          storage,
          plan,
          registry,
          provider,
          basisState: swarmArtifacts.basisState,
          campaignState: recovered.state,
          evidencePacket: completedArtifacts.evidencePacket,
          completion: completedArtifacts.completion,
          swarmBasis: swarmArtifacts.swarmBasis,
          swarmMerge: swarmArtifacts.swarmMerge,
          swarmCompletion: sealedCompletion,
        })
      candidateFrontierState = await reconcileCandidateFrontierProjectionV2({
        storage,
        frontier: candidateFrontier,
        basisState: swarmArtifacts.basisState,
        campaignState: recovered.state,
        swarmBasis: swarmArtifacts.swarmBasis,
        swarmMerge: swarmArtifacts.swarmMerge,
        swarmCompletion: sealedCompletion,
        repairSnapshot,
        now: dependencies.now ?? (() => new Date()),
      })
    } else if (
      inventory.includes(UNLEASH_CANDIDATE_FRONTIER_STATE_FILE)
      || recovered.state.swarm_completion_sha256 !== null
      || swarmArtifacts.swarmCompletion !== null
    ) {
      fail('UNLEASH_CANDIDATE_V2_FINAL_MISSING', 'protocol-v2 completion or frontier state exists without its one final merged proposal admission')
    }
  } catch (cause) {
    throw new UnleashControllerError(
      cause?.code ?? 'UNLEASH_CANDIDATE_FRONTIER_INVALID',
      'The candidate frontier is missing, malformed, or no longer matches its completed campaign.',
      { cause, runDirectory: recovered.state.run_directory, status: 'RECONCILIATION_REQUIRED' },
    )
  }
  return {
    storage,
    plan,
    registry,
    provider,
    reconAuthority,
    state: recovered.state,
    recovered,
    completion: completedArtifacts.completion,
    evidencePacket: completedArtifacts.evidencePacket,
    basisState: swarmArtifacts.basisState,
    swarmBasis: swarmArtifacts.swarmBasis,
    swarmMerge: swarmArtifacts.swarmMerge,
    swarmCompletion: swarmArtifacts.swarmCompletion,
    swarmLedger: swarmArtifacts.swarmLedger,
    candidateFrontier,
    candidateFrontierState,
    inventory: await storage.listJsonFilenames(),
  }
}

const TRANSIENT_MANAGEMENT_READ_CODES = new Set([
  'UNLEASH_STORAGE_CHANGED',
  'UNLEASH_CAMPAIGN_STATE_CHANGED',
  'UNLEASH_CAMPAIGN_SNAPSHOT_STALE',
  'UNLEASH_SWARM_LEDGER_CHANGED',
  'UNLEASH_SWARM_LEDGER_STATE_STALE',
  'UNLEASH_CANDIDATE_FRONTIER_STATE_CHANGED',
  'UNLEASH_CANDIDATE_FRONTIER_STATE_STALE',
  'UNLEASH_SNAPSHOT_CHANGED',
])

function transientManagementRead(cause) {
  let current = cause
  for (let depth = 0; depth < 5 && current !== null && typeof current === 'object'; depth += 1) {
    if (TRANSIENT_MANAGEMENT_READ_CODES.has(current.code)) return true
    current = current.cause
  }
  return false
}

async function openCampaignForManagement(input, dependencies, options = undefined) {
  let lastCause
  for (let attempt = 0; attempt < 12; attempt += 1) {
    try {
      return await openCampaign(input, dependencies, options)
    } catch (cause) {
      if (!transientManagementRead(cause)) throw cause
      lastCause = cause
      await new Promise((resolveRetry) => setImmediate(resolveRetry))
    }
  }
  throw lastCause
}

async function openCampaignIdentityForManagement(input, dependencies) {
  let lastCause
  for (let attempt = 0; attempt < 12; attempt += 1) {
    try {
      return await openCampaignIdentity(input, dependencies)
    } catch (cause) {
      if (!transientManagementRead(cause)) throw cause
      lastCause = cause
      await new Promise((resolveRetry) => setImmediate(resolveRetry))
    }
  }
  throw lastCause
}

async function reopenCampaignForMutation(loaded, dependencies) {
  const owner = loaded[SWARM_OWNER_TOKEN]
  if (owner === undefined) {
    return openCampaign({ bundle: loaded.state.run_directory }, dependencies)
  }
  const openStorage = dependencies.openCampaignStorage ?? openUnleashCampaignStorage
  const ownedDependencies = {
    ...dependencies,
    openCampaignStorage: async (storageInput) => bindUnleashSwarmOwnerStorage(
      await openStorage(storageInput),
      owner,
    ),
  }
  const reopened = await openCampaign(
    { bundle: loaded.state.run_directory },
    ownedDependencies,
  )
  Object.defineProperty(reopened, SWARM_OWNER_TOKEN, {
    value: owner,
    configurable: false,
    enumerable: false,
    writable: false,
  })
  return reopened
}

async function readRetainedReconAuthority(loaded, policy) {
  if (loaded.reconAuthority !== null && loaded.reconAuthority !== undefined) {
    return assertControllerPolicyAuthority(loaded.reconAuthority, policy, loaded.plan)
  }
  let authority
  try {
    authority = await loaded.storage.readJson(RECON_AUTHORITY_FILE)
  } catch (cause) {
    throw new UnleashControllerError(
      'UNLEASH_RECON_AUTHORITY_MISSING',
      'The retained controller-policy reconnaissance authority is unavailable.',
      { cause, runDirectory: loaded.state.run_directory, status: 'RECONCILIATION_REQUIRED' },
    )
  }
  return assertControllerPolicyAuthority(authority, policy, loaded.plan)
}

async function appendState(storage, previousState, changes, now) {
  const next = previousState === null
    ? changes
    : nextUnleashCampaignState(previousState, changes, sampleNow(now).toISOString())
  try {
    return await appendUnleashCampaignState({ storage, previousState, nextState: next })
  } catch (cause) {
    throw new UnleashControllerError(
      cause?.code ?? 'UNLEASH_CAMPAIGN_STATE_WRITE_FAILED',
      cause?.code === 'UNLEASH_CAMPAIGN_RECONCILIATION_REQUIRED'
        ? 'Campaign state publication is ambiguous; reconcile storage before continuing.'
        : 'Campaign state was retained but its mutable projection is stale.',
      {
        cause,
        runDirectory: storage.campaign_directory,
        status: cause?.code === 'UNLEASH_CAMPAIGN_RECONCILIATION_REQUIRED'
          ? 'RECONCILIATION_REQUIRED'
          : undefined,
      },
    )
  }
}

export async function unleashTarget(intake, dependencies = {}) {
  if (!hasExactKeys(intake, INTAKE_FIELDS) || typeof intake.target !== 'string' || intake.target.length === 0) {
    fail('UNLEASH_INTAKE_INVALID', 'unleash accepts exactly one target descriptor')
  }
  const { policy, isRevoked } = await resolveControllerAuthority(dependencies)
  const reasoningAssignments = controllerReasoningAssignments(dependencies)
  const providerProfile = controllerProviderProfile(
    reasoningAssignments,
    dependencies.unleashProviderProfile,
  )
  const plannerDependencies = createDefaultUnleashPlannerDependencies({
    policy,
    provider: providerProfile,
  })
  const plan = createUnleashPlan({ target: intake.target }, plannerDependencies)
  const now = dependencies.now ?? (() => new Date())
  const firstAdmission = sampleNow(now)
  assertPolicyPlanBinding(policy, plan)
  assertPolicyAllowsTarget(policy, plan.target, {
    now: firstAdmission,
    isRevoked,
    effect: 'OBSERVE',
  })
  assertReconAdapterWithinPolicy(policy)

  const requestedRunsRoot = dependencies.runsRoot ?? defaultUnleashRunsRoot()
  if (typeof requestedRunsRoot !== 'string' || !isAbsolute(requestedRunsRoot)) {
    fail('UNLEASH_RUNS_ROOT_INVALID', 'campaign storage root must be absolute')
  }
  const runsRoot = resolve(requestedRunsRoot)
  if (runsRoot !== requestedRunsRoot) {
    fail('UNLEASH_RUNS_ROOT_INVALID', 'campaign storage root must be canonical')
  }
  const randomBytes = dependencies.randomBytes ?? systemRandomBytes
  if (typeof randomBytes !== 'function') fail('UNLEASH_RANDOM_INVALID', 'campaign nonce source must be a function')
  const nonce = randomBytes(16)
  if (!Buffer.isBuffer(nonce) || nonce.length !== 16) {
    fail('UNLEASH_RANDOM_INVALID', 'campaign nonce source must return exactly 16 bytes')
  }
  const campaignId = campaignIdentity(plan, nonce)
  const campaignDirectory = `campaign-${campaignId.slice(-24)}`
  const mkdir = dependencies.mkdir ?? mkdirDefault
  const createCampaignStorage = dependencies.createCampaignStorage ?? createUnleashCampaignStorage
  if (typeof mkdir !== 'function' || typeof createCampaignStorage !== 'function') {
    fail('UNLEASH_STORAGE_INVALID', 'campaign storage operations are unavailable')
  }
  await mkdir(runsRoot, { recursive: true, mode: 0o700 })
  let storage = assertCampaignStorage(
    await createCampaignStorage({ runsRoot, campaignDirectory }),
    runsRoot,
    campaignDirectory,
  )
  const runDirectory = storage.campaign_directory
  const reconBundle = join(runDirectory, 'recon')
  const counts = routeCounts(plan)
  const gapCount = counts.waiting + counts.unavailable + counts.blocked
  let state = {
    schema_version: plan.provider_protocol_version === '2.0.0' ? '2.0.0' : '1.0.0',
    kind: 'last-aperture/unleash-state',
    revision: 1,
    updated_at: firstAdmission.toISOString(),
    campaign_id: campaignId,
    status: 'PLANNED',
    run_directory: runDirectory,
    plan_sha256: plan.plan_sha256,
    target: structuredClone(plan.target),
    completed_routes: [],
    route_counts: counts,
    gap_count: gapCount,
    recon_bundle: reconBundle,
    evidence_packet_path: null,
    evidence_packet_sha256: null,
    completion_receipt_sha256: null,
    stop_reason: null,
    failure: null,
    ...(plan.provider_protocol_version === '2.0.0'
      ? {
          swarm_basis_sha256: null,
          swarm_completion_sha256: null,
          candidate_frontier_sha256: null,
          candidate_frontier_head_sha256: null,
          swarm_gap_count: 0,
        }
      : {}),
  }
  let initialOwner = null
  if (state.schema_version === '2.0.0') {
    const acquisition = await acquireUnleashSwarmOwner({
      campaignDirectory: runDirectory,
      campaignId,
      planSha256: plan.plan_sha256,
    }, { now })
    if (acquisition.state === 'BUSY') {
      fail(
        'UNLEASH_CAMPAIGN_SWARM_OWNER_BUSY',
        'A live exclusive controller already owns the newly created campaign.',
        { runDirectory, status: 'PLANNED' },
      )
    }
    initialOwner = acquisition.owner
    storage = bindUnleashSwarmOwnerStorage(storage, initialOwner)
  }
  let reconReachedTerminal = false
  const executeCampaign = async () => {
    try {
    await storage.writeImmutableJson('campaign-plan.json', plan)
    await storage.writeImmutableJson('campaign-registry.json', plannerDependencies.registry)
    await storage.writeImmutableJson('campaign-provider.json', plannerDependencies.provider)
    state = await appendState(storage, null, state, now)
    const dispatchAdmission = sampleNow(now)
    assertPolicyPlanBinding(policy, plan)
    assertPolicyAllowsTarget(policy, plan.target, {
      now: dispatchAdmission,
      isRevoked,
      effect: 'OBSERVE',
    })
    const goHttpRecon = enrolledHttpsReconAdapter(plannerDependencies.registry)
    const authority = controllerPolicyAuthority(policy, plan, dispatchAdmission)
    await storage.writeImmutableJson(RECON_AUTHORITY_FILE, authority)
    state = await appendState(storage, state, { status: 'RUNNING' }, now)
    const campaign = { storage, plan, state, reconAuthority: authority }
    if (initialOwner !== null) {
      Object.defineProperty(campaign, SWARM_OWNER_TOKEN, {
        value: initialOwner,
        configurable: false,
        enumerable: false,
        writable: false,
      })
    }
    const stopBeforePlanning = await readEffectiveCampaignStopRequest(campaign)
    if (stopBeforePlanning !== null) {
      state = (await retainTerminalStop(
        campaign,
        stopBeforePlanning.reason,
        dependencies,
        now,
      )).state
      return publicSummary(state)
    }
    const revalidateAuthority = controllerPolicyRevalidator({
      policy,
      plan,
      isRevoked,
      now,
      authority,
      loaded: campaign,
    })
    const baseRunAction = enrolledHttpReconRun(dependencies)
    let recon
    try {
      recon = await goHttpRecon({
        targetUrl: plan.target.canonical_locator,
        out: reconBundle,
        controllerPolicyAuthority: controllerPolicyAdmission(authority),
      revalidateAuthority,
      now,
      runImpl: baseRunAction,
      onPlanned: campaignReconPlannedCallback(campaign, dependencies, now, policy),
      })
    } catch (cause) {
      if (cause?.code === 'UNLEASH_ACTION_RISK_CONFIRMATION_REQUIRED') {
        const preflight = await readCampaignActionRiskPreflight(campaign, policy)
        return publicSummaryWithActionRisk(state, {
          admitted: false,
          confirmation: null,
          preflight,
        })
      }
      if (errorChainHasCode(cause, 'UNLEASH_CAMPAIGN_PAUSED')) {
        const preflight = await readCampaignActionRiskPreflight(campaign, policy)
        const confirmation = preflight === null
          ? null
          : await readCampaignActionRiskConfirmation(campaign, preflight)
        const pause = await readUnleashCampaignPauseControl({
          storage: campaign.storage,
          plan: campaign.plan,
          state: campaign.state,
        })
        return publicSummaryWithActionRisk(state, {
          admitted: preflight !== null && (
            !preflight.receipt.controller_confirmation_required || confirmation !== null
          ),
          confirmation,
          preflight,
        }, pause)
      }
      const retainedStop = await readEffectiveCampaignStopRequest(campaign)
      if (retainedStop !== null) {
        return publicSummary(await settleCampaignStopRequest(
          campaign,
          retainedStop,
          dependencies,
          now,
        ))
      }
      const reconciled = await reconcileInitialReconAttempt(
        { storage, plan, state },
        dependencies,
        now,
      )
      if (reconciled !== null) return publicSummary(reconciled)
      throw cause
    }
    if (!sameResolvedPath(recon?.bundle, reconBundle)) {
      fail('UNLEASH_RECON_RESULT_INVALID', 'HTTPS reconnaissance returned an invalid or incomplete result')
    }
    if (recon.state !== 'PROBE_PLAN_COMPLETE') {
      const reconciled = await reconcileInitialReconAttempt(
        { storage, plan, state },
        dependencies,
        now,
      )
      if (reconciled !== null) return publicSummary(reconciled)
      fail('UNLEASH_RECON_RESULT_INVALID', 'HTTPS reconnaissance returned an invalid or incomplete result')
    }
    reconReachedTerminal = true
    const completedCampaign = {
      storage,
      plan,
      registry: plannerDependencies.registry,
      provider: plannerDependencies.provider,
      state,
      reconAuthority: authority,
    }
    if (initialOwner !== null) {
      Object.defineProperty(completedCampaign, SWARM_OWNER_TOKEN, {
        value: initialOwner,
        configurable: false,
        enumerable: false,
        writable: false,
      })
    }
    state = await completeRecoveredRecon(completedCampaign, dependencies, now)
    const preflight = await readCampaignActionRiskPreflight(completedCampaign, policy)
    const confirmation = preflight === null
      ? null
      : await readCampaignActionRiskConfirmation(completedCampaign, preflight)
    const pause = state.schema_version === '2.0.0'
      ? await readUnleashCampaignPauseControl({
          storage: completedCampaign.storage,
          plan: completedCampaign.plan,
          state,
        })
      : undefined
    return publicSummaryWithActionRisk(state, {
      admitted: preflight !== null,
      confirmation,
      preflight,
    }, pause)
    } catch (cause) {
      if ([
        'UNLEASH_CAMPAIGN_RECONCILIATION_REQUIRED',
        'UNLEASH_CAMPAIGN_SNAPSHOT_STALE',
        'UNLEASH_CAMPAIGN_SWARM_OWNER_BUSY',
        'UNLEASH_SWARM_TERMINAL_FENCE_CONFLICT',
        'UNLEASH_SWARM_TERMINAL_FENCE_DRIFT',
        'UNLEASH_SWARM_TERMINAL_FENCE_INVALID',
      ].includes(cause?.code)) throw cause
      let retainedCompletion = false
      let completionInventoryUnavailable = false
      try {
        retainedCompletion = (await storage.listJsonFilenames()).includes('https-recon-completion.json')
      } catch {
        completionInventoryUnavailable = true
      }
      if (reconReachedTerminal && completionInventoryUnavailable) {
        state = await appendReconciliationRequired(
          { storage, plan, state },
          now,
          'UNLEASH_RECON_COMPLETION_INVENTORY_UNAVAILABLE',
          'Reconnaissance reported terminal completion, but retained completion artifacts could not be inspected; no action was replayed.',
        )
        return publicSummary(state)
      }
      if (retainedCompletion) {
        const loaded = {
          storage,
          plan,
          registry: plannerDependencies.registry,
          provider: plannerDependencies.provider,
          state,
        }
        if (initialOwner !== null) {
          Object.defineProperty(loaded, SWARM_OWNER_TOKEN, {
            value: initialOwner,
            configurable: false,
            enumerable: false,
            writable: false,
          })
        }
        try {
          return publicSummary(await completeRecoveredRecon(loaded, dependencies, now))
        } catch (recoveryCause) {
          if (recoveryCause?.code?.startsWith?.('UNLEASH_CAMPAIGN_')) throw recoveryCause
          state = await appendReconciliationRequired(
            loaded,
            now,
            'UNLEASH_RECON_COMPLETION_PUBLICATION_INCOMPLETE',
            'Authoritative reconnaissance completion was retained, but its derived campaign artifacts could not be published; no action was replayed.',
          )
          return publicSummary(state)
        }
      }
      try {
        state = await appendState(storage, state, failureChanges(), now)
      } catch (stateCause) {
        throw stateCause
      }
      if (cause instanceof UnleashControllerError && cause.run_directory === runDirectory) throw cause
      throw new UnleashControllerError(
        'UNLEASH_REMOTE_ROUTE_FAILED',
        'The target-only remote campaign failed after its plan was retained.',
        { cause, runDirectory },
      )
    }
  }
  let executionResult
  let executionFailure
  try {
    executionResult = await executeCampaign()
  } catch (cause) {
    executionFailure = cause
  }
  if (initialOwner !== null) {
    try {
      await releaseUnleashSwarmOwner(initialOwner)
    } catch (releaseFailure) {
      throw new UnleashControllerError(
        'UNLEASH_CAMPAIGN_SWARM_OWNER_RELEASE_FAILED',
        'The initial exclusive swarm owner could not be released by exact identity.',
        {
          cause: executionFailure === undefined
            ? releaseFailure
            : new AggregateError([executionFailure, releaseFailure]),
          runDirectory,
          status: 'RECONCILIATION_REQUIRED',
        },
      )
    }
  }
  if (executionFailure !== undefined) throw executionFailure
  return executionResult
}

function assertResumeAuthority(policy, isRevoked, plan, now, provider) {
  const plannerDependencies = createDefaultUnleashPlannerDependencies({ policy, provider })
  assertPolicyPlanBinding(policy, plan)
  assertValidUnleashPlan(plan, {
    ...plannerDependencies,
    policy: {
      ...plannerDependencies.policy,
      controller_policy_sha256: plan.policy_sha256,
    },
  })
  assertPolicyAllowsTarget(policy, plan.target, {
    now: sampleNow(now),
    isRevoked,
    effect: 'OBSERVE',
  })
  assertReconAdapterWithinPolicy(policy)
}

async function appendReconciliationRequired(loaded, now, code, message) {
  if (loaded.state.status === 'RECONCILIATION_REQUIRED') return loaded.state
  const hasVerifiedEvidence = loaded.state.evidence_packet_sha256 !== null
  return appendState(loaded.storage, loaded.state, {
    status: 'RECONCILIATION_REQUIRED',
    ...(hasVerifiedEvidence
      ? {}
      : {
          completed_routes: [],
          evidence_packet_path: null,
          evidence_packet_sha256: null,
          completion_receipt_sha256: null,
        }),
    failure: campaignFailure(code, message),
  }, now)
}

function reconVerificationDependencies(dependencies, now) {
  return {
    now,
    ...(dependencies.readVerifiedRecon === undefined
      ? {}
      : { readVerifiedRecon: dependencies.readVerifiedRecon }),
  }
}

async function persistVerifiedReconCompletion({ storage, bundle, plan, dependencies, now }) {
  const names = await storage.listJsonFilenames()
  const hasPacket = names.includes('evidence-packet.json')
  const hasEnvelope = names.includes('https-recon-completion.json')
  if (hasPacket && !hasEnvelope) {
    fail('UNLEASH_RECON_COMPLETION_PARTIAL', 'a derived evidence packet exists without its authoritative recon completion envelope')
  }
  let completion
  if (hasEnvelope) {
    completion = await storage.readJson('https-recon-completion.json')
    assertValidUnleashReconCompletion(completion, { plan })
    if (hasPacket) {
      const packet = await storage.readJson('evidence-packet.json')
      if (digestUnleashValue(packet) !== digestUnleashValue(completion.evidence_packet)) {
        fail('UNLEASH_RECON_COMPLETION_CHANGED', 'derived evidence packet differs from its authoritative completion envelope')
      }
    }
  } else {
    completion = await createVerifiedReconCompletion(
      { bundle, plan },
      reconVerificationDependencies(dependencies, now),
    )
    assertValidUnleashReconCompletion(completion, { plan })
    await storage.writeImmutableJson('https-recon-completion.json', completion)
  }
  if (hasEnvelope && !hasPacket) {
    completion = await verifyUnleashReconCompletion(
      { bundle, plan, completion },
      reconVerificationDependencies(dependencies, now),
    )
  }
  if (!hasPacket) {
    await storage.writeImmutableJson('evidence-packet.json', completion.evidence_packet)
  }
  assertValidUnleashReconCompletion(completion, { plan })
  const verified = await verifyUnleashReconCompletion(
    { bundle, plan, completion },
    reconVerificationDependencies(dependencies, now),
  )
  assertValidUnleashReconCompletion(verified, { plan })
  if (
    digestUnleashValue(verified.evidence_packet) !== digestUnleashValue(completion.evidence_packet)
    || digestUnleashValue(verified.completion_receipt) !== digestUnleashValue(completion.completion_receipt)
  ) fail('UNLEASH_RECON_COMPLETION_CHANGED', 'recon completion changed during controller re-verification')
  return verified
}

function monotonicCampaignDate(now, ...timestamps) {
  const sampled = sampleNow(now)
  const floor = Math.max(
    sampled.getTime(),
    ...timestamps.map((value) => Date.parse(value)).filter(Number.isFinite),
  )
  return new Date(floor)
}

function historicalSwarmBasisState(loaded, retainedBasis = null) {
  if (retainedBasis !== null) {
    const recovered = loaded.recovered?.states?.[retainedBasis.campaign_state_revision - 1]
    if (recovered !== undefined) return recovered
    if (loaded.state.revision === retainedBasis.campaign_state_revision) return loaded.state
    if (loaded.basisState?.revision === retainedBasis.campaign_state_revision) return loaded.basisState
  }
  if (loaded.state.status === 'RUNNING') return loaded.state
  const historical = [...(loaded.recovered?.states ?? [])]
    .reverse()
    .find((state) => state.schema_version === '2.0.0' && state.status === 'RUNNING')
  if (historical === undefined) {
    fail('UNLEASH_SWARM_BASIS_STATE_MISSING', 'protocol-v2 swarm requires its immutable historical RUNNING state')
  }
  return historical
}

async function retainProtocolV2SwarmBasis(loaded, completion, now) {
  const existing = await readOptionalCampaignJson(loaded.storage, UNLEASH_SWARM_BASIS_FILE)
  const basisState = historicalSwarmBasisState(loaded, existing)
  const recordedAt = existing === null
    ? monotonicCampaignDate(
        now,
        basisState.updated_at,
        completion.evidence_packet.created_at,
      ).toISOString()
    : existing.recorded_at
  const expected = createUnleashSwarmBasis({
    recordedAt,
    campaignId: basisState.campaign_id,
    campaignStateRevision: basisState.revision,
    campaignStateSha256: digestUnleashValue(basisState),
    planSha256: loaded.plan.plan_sha256,
    targetId: loaded.plan.target.target_id,
    registrySha256: digestUnleashValue(loaded.registry),
    providerProfileSha256: digestUnleashValue(loaded.provider),
    evidencePacketSha256: completion.evidence_packet.packet_sha256,
    completionReceiptSha256: completion.completion_receipt.completion_receipt_sha256,
    limits: loaded.provider.limits,
  })
  if (existing === null) {
    try {
      await loaded.storage.writeImmutableJson(UNLEASH_SWARM_BASIS_FILE, expected)
    } catch (cause) {
      if (cause?.code !== 'UNLEASH_STORAGE_FILE_EXISTS') throw cause
    }
  }
  const first = await loaded.storage.readJson(UNLEASH_SWARM_BASIS_FILE)
  const second = await loaded.storage.readJson(UNLEASH_SWARM_BASIS_FILE)
  assertValidUnleashSwarmBasis(first)
  assertValidUnleashSwarmBasis(second)
  if (
    digestUnleashValue(first) !== digestUnleashValue(second)
    || digestUnleashValue(first) !== digestUnleashValue(expected)
  ) fail('UNLEASH_SWARM_BASIS_CHANGED', 'immutable swarm basis changed or differs from its exact recon and campaign bindings')
  return { basis: first, basisState }
}

async function transitionToProtocolV2Swarm(loaded, completion, basis, now) {
  if (loaded.state.status === 'SWARMING') {
    if (
      loaded.state.swarm_basis_sha256 !== basis.basis_sha256
      || loaded.state.evidence_packet_sha256 !== completion.evidence_packet.packet_sha256
      || loaded.state.completion_receipt_sha256
        !== completion.completion_receipt.completion_receipt_sha256
    ) fail('UNLEASH_SWARM_STATE_DRIFT', 'SWARMING campaign state differs from its exact basis and verified recon')
    return loaded.state
  }
  if (!['RUNNING', 'RECONCILIATION_REQUIRED'].includes(loaded.state.status)) {
    fail('UNLEASH_SWARM_STATE_INVALID', `campaign cannot enter SWARMING from ${loaded.state.status}`)
  }
  const next = await appendState(loaded.storage, loaded.state, {
    status: 'SWARMING',
    completed_routes: ['https-recon'],
    evidence_packet_path: join(loaded.state.run_directory, 'evidence-packet.json'),
    evidence_packet_sha256: completion.evidence_packet.packet_sha256,
    completion_receipt_sha256: completion.completion_receipt.completion_receipt_sha256,
    swarm_basis_sha256: basis.basis_sha256,
    failure: null,
  }, now)
  loaded.state = next
  return next
}

async function executeProtocolV2SwarmAsOwner(loaded, completion, dependencies, now, owner) {
  const { policy, isRevoked } = await resolveControllerAuthority(dependencies)
  assertResumeAuthority(policy, isRevoked, loaded.plan, now, loaded.provider)
  const { basis, basisState } = await retainProtocolV2SwarmBasis(loaded, completion, now)
  await transitionToProtocolV2Swarm(loaded, completion, basis, now)
  const assignments = controllerReasoningAssignments(dependencies)
  const stopRequested = async () => (await readEffectiveCampaignStopRequest(loaded)) !== null
  const pauseRequested = async () => !(await readUnleashCampaignPauseControl({
    storage: loaded.storage,
    plan: loaded.plan,
    state: loaded.state,
  })).dispatch_open
  const authorityAvailable = async () => {
    try {
      assertPolicyAllowsTarget(policy, loaded.plan.target, {
        now: sampleNow(now),
        isRevoked,
        effect: 'OBSERVE',
      })
      return true
    } catch {
      return false
    }
  }
  const deadlineExceeded = () => (
    sampleNow(now).getTime() - Date.parse(basis.recorded_at)
      >= loaded.plan.budgets.max_duration_ms
  )
  const controllerDependencies = {
    storage: loaded.storage,
    now,
    stopRequested,
    pauseRequested,
    authorityAvailable,
    deadlineExceeded,
    assertExclusiveOwner: () => assertUnleashSwarmOwner(owner),
    ...(dependencies.readVerifiedRecon === undefined
      ? {}
      : { readVerifiedRecon: dependencies.readVerifiedRecon }),
    ...(dependencies.swarmSignal === undefined ? {} : { signal: dependencies.swarmSignal }),
  }
  const result = await runUnleashSwarmController({
    basis,
    plan: loaded.plan,
    bundle: loaded.state.recon_bundle,
    reconCompletion: completion,
    providerProfile: loaded.provider,
    adapters: assignments.map(({ roleId, adapter }) => ({ roleId, adapter })),
  }, controllerDependencies)
  const retainedStop = await readCampaignStopRequest(loaded)
  if (retainedStop === null && await pauseRequested()) throw new UnleashSwarmPause()
  const terminalFence = await publishProtocolV2SwarmTerminalFence(
    loaded,
    retainedStop === null
      ? createProtocolV2SwarmTerminalFence(loaded, {
          decision: 'SEAL',
          recordedAt: sampleNow(now).toISOString(),
          basis,
          result,
        })
      : createProtocolV2SwarmTerminalFence(loaded, {
          decision: 'STOP',
          recordedAt: retainedStop.requested_at,
          reason: retainedStop.reason,
        }),
  )
  if (terminalFence.decision === 'SEAL') {
    if (retainedStop !== null) {
      fail('UNLEASH_SWARM_TERMINAL_FENCE_CONFLICT', 'a retained stop request cannot follow the winning SEAL fence')
    }
    assertSealFenceBindsResult(terminalFence, basis, result)
  }
  const stopGate = terminalFence.decision === 'STOP'
    ? stopRequestFromTerminalFence(loaded, terminalFence)
    : null
  if (stopGate !== null) await retainCampaignStopRequest(loaded, stopGate)
  const termination = stopGate !== null && result.termination.decision !== 'STOPPED'
    ? Object.freeze({
        decision: 'STOPPED',
        reason: 'STOP_REQUESTED',
        stable: result.termination.stable,
        terminal: true,
      })
    : result.termination
  const sealed = await sealUnleashSwarmCampaign({
    plan: loaded.plan,
    registry: loaded.registry,
    provider: loaded.provider,
    basisState,
    campaignState: loaded.state,
    evidencePacket: completion.evidence_packet,
    completion,
    swarmBasis: basis,
    swarmMerge: result.merge,
    swarmLedger: result.ledger,
    termination,
    usage: result.usage,
    gaps: result.gaps,
    stopReason: termination.decision === 'STOPPED'
      ? (stopGate?.reason ?? 'Swarm execution was stopped by the controller.')
      : null,
  }, { storage: loaded.storage, now })
  loaded.state = sealed.campaignState
  loaded.basisState = basisState
  loaded.swarmBasis = basis
  loaded.swarmMerge = result.merge
  loaded.swarmCompletion = sealed.swarmCompletion
  loaded.candidateFrontier = sealed.frontier
  loaded.candidateFrontierState = sealed.frontierState
  return sealed.campaignState
}

async function runAndSealProtocolV2Swarm(loaded, completion, dependencies, now) {
  let owner = loaded[SWARM_OWNER_TOKEN]
  let acquiredHere = false
  if (owner === undefined) {
    const acquisition = await acquireUnleashSwarmOwner(
      protocolV2SwarmOwnerInput(loaded),
      { now },
    )
    if (acquisition.state === 'BUSY') {
      fail(
        'UNLEASH_CAMPAIGN_SWARM_OWNER_BUSY',
        'A live exclusive controller already owns this campaign swarm.',
        { runDirectory: loaded.state.run_directory, status: loaded.state.status },
      )
    }
    owner = acquisition.owner
    acquiredHere = true
  } else {
    await assertUnleashSwarmOwner(owner)
  }
  const originalStorage = loaded.storage
  let state
  let executionFailure
  try {
    if (acquiredHere) loaded.storage = bindUnleashSwarmOwnerStorage(originalStorage, owner)
    state = await executeProtocolV2SwarmAsOwner(loaded, completion, dependencies, now, owner)
  } catch (cause) {
    executionFailure = cause
  } finally {
    loaded.storage = originalStorage
  }
  if (acquiredHere) {
    try {
      await releaseUnleashSwarmOwner(owner)
    } catch (releaseFailure) {
      throw new UnleashControllerError(
        'UNLEASH_CAMPAIGN_SWARM_OWNER_RELEASE_FAILED',
        'The exclusive swarm owner could not be released by exact identity.',
        {
          cause: executionFailure === undefined
            ? releaseFailure
            : new AggregateError([executionFailure, releaseFailure]),
          runDirectory: loaded.state.run_directory,
          status: 'RECONCILIATION_REQUIRED',
        },
      )
    }
  }
  if (executionFailure?.code === 'UNLEASH_SWARM_PAUSED') return loaded.state
  if (executionFailure !== undefined) throw executionFailure
  return state
}

async function completeRecoveredReconAsOwner(loaded, dependencies, now) {
  loaded.registry ??= await loaded.storage.readJson('campaign-registry.json')
  loaded.provider ??= await loaded.storage.readJson('campaign-provider.json')
  const completion = await persistVerifiedReconCompletion({
    storage: loaded.storage,
    bundle: loaded.state.recon_bundle,
    plan: loaded.plan,
    dependencies,
    now,
  })
  if (loaded.state.schema_version === '2.0.0') {
    return runAndSealProtocolV2Swarm(loaded, completion, dependencies, now)
  }
  const packet = completion.evidence_packet
  const counts = routeCounts(loaded.plan)
  const state = await appendState(loaded.storage, loaded.state, {
    status: counts.waiting + counts.unavailable + counts.blocked === 0
      ? 'COMPLETE'
      : 'COMPLETE_WITH_GAPS',
    completed_routes: ['https-recon'],
    evidence_packet_path: join(loaded.state.run_directory, 'evidence-packet.json'),
    evidence_packet_sha256: packet.packet_sha256,
    completion_receipt_sha256: completion.completion_receipt.completion_receipt_sha256,
    failure: null,
  }, now)
  loaded.state = state
  return state
}

async function completeRecoveredRecon(loaded, dependencies, now) {
  if (
    loaded.state.schema_version !== '2.0.0'
    || loaded[SWARM_OWNER_TOKEN] !== undefined
  ) return completeRecoveredReconAsOwner(loaded, dependencies, now)

  const acquisition = await acquireUnleashSwarmOwner(
    protocolV2SwarmOwnerInput(loaded),
    { now },
  )
  if (acquisition.state === 'BUSY') {
    fail(
      'UNLEASH_CAMPAIGN_SWARM_OWNER_BUSY',
      'A live exclusive controller already owns protocol-v2 completion recovery.',
      { runDirectory: loaded.state.run_directory, status: loaded.state.status },
    )
  }
  const owner = acquisition.owner
  const originalStorage = loaded.storage
  let state
  let executionFailure
  try {
    loaded.storage = bindUnleashSwarmOwnerStorage(originalStorage, owner)
    Object.defineProperty(loaded, SWARM_OWNER_TOKEN, {
      value: owner,
      configurable: true,
      enumerable: false,
      writable: false,
    })
    state = await completeRecoveredReconAsOwner(loaded, dependencies, now)
  } catch (cause) {
    executionFailure = cause
  } finally {
    loaded.storage = originalStorage
    delete loaded[SWARM_OWNER_TOKEN]
  }
  try {
    await releaseUnleashSwarmOwner(owner)
  } catch (releaseFailure) {
    throw new UnleashControllerError(
      'UNLEASH_CAMPAIGN_SWARM_OWNER_RELEASE_FAILED',
      'The exclusive completion-recovery owner could not be released by exact identity.',
      {
        cause: executionFailure === undefined
          ? releaseFailure
          : new AggregateError([executionFailure, releaseFailure]),
        runDirectory: loaded.state.run_directory,
        status: 'RECONCILIATION_REQUIRED',
      },
    )
  }
  if (executionFailure !== undefined) throw executionFailure
  return state
}

async function terminalizeFromRecon(loaded, finalized, dependencies, now) {
  const reconState = finalized?.run?.state ?? finalized?.state
  if (reconState === 'PROBE_PLAN_COMPLETE') {
    try {
      return await completeRecoveredRecon(loaded, dependencies, now)
    } catch (cause) {
      if (cause?.code?.startsWith?.('UNLEASH_CAMPAIGN_')) throw cause
      loaded.state = await appendReconciliationRequired(
        loaded,
        now,
        'UNLEASH_RECON_COMPLETION_UNVERIFIED',
        'Reconnaissance completion artifacts could not be reverified; route completion was not recorded.',
      )
      return loaded.state
    }
  }
  if (reconState === 'STOPPED') {
    const reason = loaded.state.stop_reason
      ?? finalized?.run?.stop?.reason
      ?? 'HTTPS reconnaissance stopped during recovery.'
    loaded.state = await appendState(loaded.storage, loaded.state, {
      status: 'STOPPED',
      stop_reason: reason,
      failure: null,
    }, now)
    return loaded.state
  }
  if (reconState === 'OUTCOME_UNCERTAIN') {
    loaded.state = await appendState(loaded.storage, loaded.state, {
      status: 'OUTCOME_UNCERTAIN',
      failure: campaignFailure(
        'UNLEASH_RECON_OUTCOME_UNCERTAIN',
        'Durable pre-dispatch evidence has no settled network outcome; the action was not replayed.',
      ),
    }, now)
    return loaded.state
  }
  if (reconState === 'FAILED') {
    loaded.state = await appendState(loaded.storage, loaded.state, failureChanges(
      'UNLEASH_RECON_FAILED',
      'HTTPS reconnaissance recovered to a failed terminal state.',
    ), now)
    return loaded.state
  }
  return null
}

async function reconcileAfterReconAttempt(loaded, dependencies, now, finalizeRecon) {
  let finalized
  try {
    finalized = await finalizeRecon({ bundle: loaded.state.recon_bundle, now })
  } catch {
    loaded.state = await appendReconciliationRequired(
      loaded,
      now,
      'UNLEASH_RECON_POST_ATTEMPT_RECONCILIATION_FAILED',
      'A reconnaissance attempt did not return normally and durable outcome reconciliation failed; no action was replayed.',
    )
    return loaded.state
  }
  const terminal = await terminalizeFromRecon(loaded, finalized, dependencies, now)
  if (terminal !== null) return terminal
  loaded.state = await appendReconciliationRequired(
    loaded,
    now,
    'UNLEASH_RECON_POST_ATTEMPT_STATE_UNKNOWN',
    'A reconnaissance attempt recovered to an unknown state; no action was replayed.',
  )
  return loaded.state
}

async function reconcileInitialReconAttempt(loaded, dependencies, now) {
  const finalizeRecon = dependencies.finalizeHttpReconBundle ?? finalizeHttpReconBundle
  if (typeof finalizeRecon !== 'function') return null
  let finalized
  try {
    finalized = await finalizeRecon({
      bundle: join(loaded.storage.campaign_directory, 'recon'),
      now,
    })
  } catch (cause) {
    if (missingRecon(cause)) return null
    loaded.state = await appendReconciliationRequired(
      loaded,
      now,
      'UNLEASH_RECON_INITIAL_RECONCILIATION_FAILED',
      'The first reconnaissance attempt did not settle normally and its durable outcome could not be reconciled; no action was replayed.',
    )
    return loaded.state
  }
  const terminal = await terminalizeFromRecon(loaded, finalized, dependencies, now)
  if (terminal !== null) return terminal
  loaded.state = await appendReconciliationRequired(
    loaded,
    now,
    'UNLEASH_RECON_INITIAL_STATE_UNKNOWN',
    'The first reconnaissance attempt recovered to an unknown state; no action was replayed.',
  )
  return loaded.state
}

function missingRecon(cause) {
  let current = cause
  for (let depth = 0; depth < 8 && current !== null && typeof current === 'object'; depth += 1) {
    if (current.code === 'ENOENT' || current.code === 'HTTP_RECON_BUNDLE_NOT_FOUND') return true
    current = current.cause
  }
  return false
}

async function reconcileRequestedStop(
  loaded,
  dependencies,
  now,
  { stopMarkerRetained = false } = {},
) {
  const requestStop = dependencies.requestHttpReconStop ?? requestHttpReconStop
  const finalizeRecon = dependencies.finalizeHttpReconBundle ?? finalizeHttpReconBundle
  if (typeof requestStop !== 'function' || typeof finalizeRecon !== 'function') {
    fail('UNLEASH_RECON_UNAVAILABLE', 'HTTPS reconnaissance stop reconciliation is unavailable')
  }
  const retainedPolicy = retainedPlanPolicy(loaded.plan)
  const authority = await readRetainedReconAuthority(loaded, retainedPolicy)
  if (!stopMarkerRetained) {
    try {
      await requestStop({
        bundle: loaded.state.recon_bundle,
        controllerPolicyAuthority: authority,
        reason: loaded.state.stop_reason,
        now,
      })
    } catch (cause) {
      throw new UnleashControllerError(
        'UNLEASH_STOP_RECONCILIATION_REQUIRED',
        'The stop request is retained, but reconnaissance stop-marker publication requires reconciliation.',
        { cause, runDirectory: loaded.state.run_directory, status: 'STOP_REQUESTED' },
      )
    }
  }

  let finalized
  try {
    finalized = await finalizeRecon({
      bundle: loaded.state.recon_bundle,
      now,
    })
  } catch (cause) {
    throw new UnleashControllerError(
      'UNLEASH_STOP_RECONCILIATION_REQUIRED',
      'The stop marker is retained, but the reconnaissance outcome requires reconciliation.',
      { cause, runDirectory: loaded.state.run_directory, status: 'STOP_REQUESTED' },
    )
  }
  const terminal = await terminalizeFromRecon(loaded, finalized, dependencies, now)
  if (terminal !== null) return terminal
  throw new UnleashControllerError(
    'UNLEASH_STOP_RECONCILIATION_REQUIRED',
    'The stop marker is retained, but reconnaissance returned an unknown nonterminal outcome.',
    { runDirectory: loaded.state.run_directory, status: 'STOP_REQUESTED' },
  )
}

function isCampaignPublicationRace(cause) {
  return [
    'UNLEASH_CAMPAIGN_RECONCILIATION_REQUIRED',
    'UNLEASH_CAMPAIGN_SNAPSHOT_STALE',
  ].includes(cause?.code)
}

async function retainOuterStopIntent(loaded, reason, dependencies, now) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    if (['COMPLETE', 'COMPLETE_WITH_GAPS', 'STOPPED', 'OUTCOME_UNCERTAIN', 'FAILED'].includes(loaded.state.status)) {
      return loaded
    }
    if (loaded.state.status === 'STOP_REQUESTED') return loaded
    try {
      loaded.state = await appendState(loaded.storage, loaded.state, {
        status: 'STOP_REQUESTED',
        stop_reason: loaded.state.stop_reason ?? reason,
        failure: null,
      }, now)
      return loaded
    } catch (cause) {
      if (!isCampaignPublicationRace(cause)) throw cause
      loaded = await reopenCampaignForMutation(loaded, dependencies)
    }
  }
  fail(
    'UNLEASH_STOP_CONCURRENT_STATE_CHANGE',
    'The nested stop marker is retained, but concurrent campaign transitions prevented the outer stop projection.',
    { runDirectory: loaded.state.run_directory, status: 'RECONCILIATION_REQUIRED' },
  )
}

async function retainTerminalStop(loaded, reason, dependencies, now) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    if (['COMPLETE', 'COMPLETE_WITH_GAPS', 'STOPPED', 'OUTCOME_UNCERTAIN', 'FAILED'].includes(loaded.state.status)) {
      return loaded
    }
    try {
      loaded.state = await appendState(loaded.storage, loaded.state, {
        status: 'STOPPED',
        stop_reason: loaded.state.stop_reason ?? reason,
        failure: null,
      }, now)
      return loaded
    } catch (cause) {
      if (!isCampaignPublicationRace(cause)) throw cause
      loaded = await reopenCampaignForMutation(loaded, dependencies)
    }
  }
  fail(
    'UNLEASH_STOP_CONCURRENT_STATE_CHANGE',
    'The campaign stop gate is retained, but concurrent transitions prevented terminal stop projection.',
    { runDirectory: loaded.state.run_directory, status: 'RECONCILIATION_REQUIRED' },
  )
}

async function settleMissingReconStop(loaded, reason, dependencies, now) {
  const planned = await readCampaignReconPlanned(loaded)
  if (planned === null) {
    return (await retainTerminalStop(loaded, reason, dependencies, now)).state
  }
  if (
    loaded.state.status === 'RECONCILIATION_REQUIRED'
    && loaded.state.failure?.code === 'UNLEASH_RECON_BUNDLE_MISSING_AFTER_PLANNING'
    && loaded.state.stop_reason !== null
  ) return loaded.state
  loaded = await retainOuterStopIntent(loaded, reason, dependencies, now)
  if (['COMPLETE', 'COMPLETE_WITH_GAPS', 'STOPPED', 'OUTCOME_UNCERTAIN', 'FAILED'].includes(loaded.state.status)) {
    return loaded.state
  }
  loaded.state = await appendReconciliationRequired(
    loaded,
    now,
    'UNLEASH_RECON_BUNDLE_MISSING_AFTER_PLANNING',
    'The campaign stop gate is retained, but a previously planned reconnaissance bundle is missing; delivery history cannot be proven.',
  )
  return loaded.state
}

async function settleCampaignStopRequest(loaded, gate, dependencies, now) {
  let reason = loaded.state.stop_reason ?? gate.reason
  if (
    loaded.state.schema_version === '2.0.0'
    && (
      loaded.state.swarm_basis_sha256 !== null
      || loaded.inventory?.includes('https-recon-completion.json')
    )
  ) {
    return completeRecoveredRecon(loaded, dependencies, now)
  }
  if (loaded.reconAuthority === null) {
    return (await retainTerminalStop(loaded, reason, dependencies, now)).state
  }
  const retainedPolicy = retainedPlanPolicy(loaded.plan)
  const authority = await readRetainedReconAuthority(loaded, retainedPolicy)
  const inspectStop = dependencies.inspectControllerPolicyHttpReconStop
    ?? inspectControllerPolicyHttpReconStop
  const requestStop = dependencies.requestHttpReconStop ?? requestHttpReconStop
  if (typeof inspectStop !== 'function' || typeof requestStop !== 'function') {
    fail('UNLEASH_RECON_UNAVAILABLE', 'HTTPS reconnaissance stop reconciliation is unavailable')
  }
  let marker
  try {
    marker = await inspectStop({
      bundle: loaded.state.recon_bundle,
      controllerPolicyAuthority: authority,
    })
  } catch (cause) {
    if (missingRecon(cause)) {
      return settleMissingReconStop(loaded, reason, dependencies, now)
    }
    loaded = await retainOuterStopIntent(loaded, reason, dependencies, now)
    throw new UnleashControllerError(
      'UNLEASH_STOP_RECONCILIATION_REQUIRED',
      'The campaign stop gate is retained, but the reconnaissance bundle cannot be inspected safely.',
      { cause, runDirectory: loaded.state.run_directory, status: 'STOP_REQUESTED' },
    )
  }
  if (marker === null) {
    try {
      marker = await requestStop({
        bundle: loaded.state.recon_bundle,
        controllerPolicyAuthority: authority,
        reason,
        now,
      })
    } catch (cause) {
      if (missingRecon(cause)) {
        return settleMissingReconStop(loaded, reason, dependencies, now)
      }
      loaded = await retainOuterStopIntent(loaded, reason, dependencies, now)
      throw new UnleashControllerError(
        'UNLEASH_STOP_RECONCILIATION_REQUIRED',
        'The campaign stop gate is retained, but reconnaissance stop-marker publication requires reconciliation.',
        { cause, runDirectory: loaded.state.run_directory, status: 'STOP_REQUESTED' },
      )
    }
  }
  reason = typeof marker?.reason === 'string' ? marker.reason : reason
  loaded = await retainOuterStopIntent(loaded, reason, dependencies, now)
  if (['COMPLETE', 'COMPLETE_WITH_GAPS', 'STOPPED', 'OUTCOME_UNCERTAIN', 'FAILED'].includes(loaded.state.status)) {
    return loaded.state
  }
  return reconcileRequestedStop(
    loaded,
    dependencies,
    now,
    { stopMarkerRetained: true },
  )
}

async function recoverNestedStopMarker(loaded, dependencies, now) {
  if (
    loaded.reconAuthority === null
    || loaded.state.status === 'PLANNED'
    || loaded.state.status === 'STOP_REQUESTED'
    || loaded.state.stop_reason !== null
  ) return null
  const inspectStop = dependencies.inspectControllerPolicyHttpReconStop
    ?? inspectControllerPolicyHttpReconStop
  if (typeof inspectStop !== 'function') {
    fail('UNLEASH_RECON_UNAVAILABLE', 'HTTPS reconnaissance stop inspection is unavailable')
  }
  const retainedPolicy = retainedPlanPolicy(loaded.plan)
  const authority = await readRetainedReconAuthority(loaded, retainedPolicy)
  let marker
  try {
    marker = await inspectStop({
      bundle: loaded.state.recon_bundle,
      controllerPolicyAuthority: authority,
    })
  } catch (cause) {
    if (missingRecon(cause)) return null
    loaded.state = await appendReconciliationRequired(
      loaded,
      now,
      'UNLEASH_RECON_STOP_INSPECTION_FAILED',
      'The retained reconnaissance bundle could not be inspected for a durable stop marker; no action was dispatched.',
    )
    return loaded.state
  }
  if (marker === null) return null
  loaded = await retainOuterStopIntent(loaded, marker.reason, dependencies, now)
  if (['COMPLETE', 'COMPLETE_WITH_GAPS', 'STOPPED', 'OUTCOME_UNCERTAIN', 'FAILED'].includes(loaded.state.status)) {
    return loaded.state
  }
  return reconcileRequestedStop(
    loaded,
    dependencies,
    now,
    { stopMarkerRetained: true },
  )
}

function candidateAdmissionFilename(sequence) {
  return `candidate-admission-${String(sequence).padStart(6, '0')}.json`
}

function completedCandidateDependencies(loaded) {
  if (
    !['COMPLETE', 'COMPLETE_WITH_GAPS'].includes(loaded.state.status)
    || loaded.completion === null
    || loaded.evidencePacket === null
  ) {
    fail(
      'UNLEASH_CANDIDATE_CAMPAIGN_NOT_COMPLETE',
      'candidate proposals require a completed campaign with verified retained evidence',
    )
  }
  return {
    plan: loaded.plan,
    registry: loaded.registry,
    provider: loaded.provider,
    policy: retainedPlanPolicy(loaded.plan),
    completedRouteIds: loaded.state.completed_routes,
    evidenceReferences: loaded.evidencePacket.sources.map(({ evidence_ref: evidenceRef }) => evidenceRef),
  }
}

async function readCandidateAdmissionHeads(loaded, proposalId) {
  const references = getUnleashCandidateFrontierAdmissionReferences({
    frontier: loaded.candidateFrontier,
  })
  const matchingAdmission = references.find(({ proposal_id: retainedId }) => retainedId === proposalId) ?? null
  const previousReference = references.at(-1) ?? null
  if (previousReference === null) {
    return { previousAdmission: null, matchingAdmission }
  }
  const previousAdmission = await loaded.storage.readJson(
    candidateAdmissionFilename(previousReference.sequence),
  )
  if (
    previousAdmission?.sequence !== previousReference.sequence
    || previousAdmission?.admission_sha256 !== previousReference.admission_sha256
    || previousAdmission?.proposal_id !== previousReference.proposal_id
    || previousAdmission?.proposal_sha256 !== previousReference.proposal_sha256
  ) fail(
    'UNLEASH_CANDIDATE_ANCESTRY_CHANGED',
    'retained candidate admission head changed after frontier recovery',
  )
  return { previousAdmission, matchingAdmission }
}

function assertCandidateFrontierCanAdmit(frontier, proposal) {
  if (
    frontier.proposal_count >= UNLEASH_CANDIDATE_FRONTIER_LIMITS.max_admissions
    || frontier.candidate_count + proposal.candidates.length > UNLEASH_CANDIDATE_FRONTIER_LIMITS.max_candidates
    || frontier.proposed_action_count + proposal.actions.length > UNLEASH_CANDIDATE_FRONTIER_LIMITS.max_proposed_actions
  ) fail('UNLEASH_CANDIDATE_FRONTIER_BOUNDS', 'candidate proposal exceeds the campaign frontier bounds')

  const candidateIds = new Set(frontier.candidates.map(({ candidate_id: candidateId }) => candidateId))
  const actionIds = new Set(frontier.actions.map(({ action_id: actionId }) => actionId))
  const repeatedCandidate = proposal.candidates.find(({ candidate_id: candidateId }) => candidateIds.has(candidateId))
  if (repeatedCandidate !== undefined) {
    fail('UNLEASH_CANDIDATE_ID_COLLISION', `candidate ID is already retained: ${repeatedCandidate.candidate_id}`)
  }
  const repeatedAction = proposal.actions.find(({ action_id: actionId }) => actionIds.has(actionId))
  if (repeatedAction !== undefined) {
    fail('UNLEASH_CANDIDATE_ACTION_COLLISION', `proposed action ID is already retained: ${repeatedAction.action_id}`)
  }
}

export async function ingestUnleashCandidateProposal(input, dependencies = {}) {
  const retainedInput = exactDataRecord(input, ['bundle', 'proposal'])
  if (retainedInput === null) {
    fail('UNLEASH_CAMPAIGN_INPUT_INVALID', 'candidate admission input must contain exact data fields')
  }
  const bundle = retainedInput.bundle
  managementInput({ bundle }, ['bundle'])
  const now = dependencies.now ?? (() => new Date())
  let proposal = snapshotUnleashProviderProposal(retainedInput.proposal)
  let lastPublicationCause

  for (let attempt = 0; attempt < 3; attempt += 1) {
    const identity = await openCampaignIdentityForManagement({ bundle }, dependencies)
    if (identity.state.schema_version === '2.0.0') {
      fail(
        'UNLEASH_CANDIDATE_CONTROLLER_OWNED',
        'protocol-v2 candidate admission is controller-owned and accepts only the exact terminal BORG merge',
      )
    }
    const loaded = await openCampaign({ bundle }, dependencies)
    const proposalDependencies = completedCandidateDependencies(loaded)
    assertValidUnleashProposal(proposal, proposalDependencies)
    const proposalSha256 = digestUnleashValue(proposal)
    const { previousAdmission, matchingAdmission } = await readCandidateAdmissionHeads(
      loaded,
      proposal.proposal_id,
    )
    if (matchingAdmission !== null) {
      if (matchingAdmission.proposal_sha256 !== proposalSha256) {
        fail(
          'UNLEASH_CANDIDATE_PROPOSAL_COLLISION',
          `proposal ID is already bound to different content: ${proposal.proposal_id}`,
        )
      }
      return loaded.candidateFrontier
    }
    assertCandidateFrontierCanAdmit(loaded.candidateFrontier, proposal)

    const sequence = loaded.candidateFrontier.proposal_count + 1
    const admission = createUnleashCandidateAdmission({
      plan: loaded.plan,
      registry: loaded.registry,
      provider: loaded.provider,
      campaignState: loaded.state,
      evidencePacket: loaded.evidencePacket,
      completion: loaded.completion,
      previousAdmission,
      proposal,
      sequence,
      recordedAt: sampleNow(now),
    })
    previewUnleashCandidateFrontierAppend({
      frontier: loaded.candidateFrontier,
      admission,
    })
    proposal = admission.proposal
    try {
      await loaded.storage.writeImmutableJson(candidateAdmissionFilename(sequence), admission)
    } catch (cause) {
      lastPublicationCause = cause
      if (cause?.code === 'UNLEASH_STORAGE_FILE_EXISTS') continue
      try {
        const reconciled = await openCampaign({ bundle }, dependencies)
        const retained = await readCandidateAdmissionHeads(reconciled, proposal.proposal_id)
        if (retained.matchingAdmission?.proposal_sha256 === admission.proposal_sha256) {
          return reconciled.candidateFrontier
        }
      } catch {}
      throw new UnleashControllerError(
        'UNLEASH_CANDIDATE_PUBLICATION_UNCERTAIN',
        'Candidate admission publication could not be reconciled safely.',
        { cause, runDirectory: loaded.state.run_directory, status: 'RECONCILIATION_REQUIRED' },
      )
    }

    const verified = await openCampaign({ bundle }, dependencies)
    const retained = await readCandidateAdmissionHeads(verified, proposal.proposal_id)
    if (
      retained.matchingAdmission?.admission_sha256 !== admission.admission_sha256
      || retained.matchingAdmission.proposal_sha256 !== admission.proposal_sha256
    ) {
      fail(
        'UNLEASH_CANDIDATE_PUBLICATION_UNCERTAIN',
        'retained candidate admission differs from the exact published proposal',
        { runDirectory: loaded.state.run_directory, status: 'RECONCILIATION_REQUIRED' },
      )
    }
    return verified.candidateFrontier
  }

  throw new UnleashControllerError(
    'UNLEASH_CANDIDATE_CONCURRENT_UPDATE',
    'Candidate frontier changed repeatedly while this proposal was admitted.',
    {
      cause: lastPublicationCause,
      runDirectory: resolve(bundle),
      status: 'RECONCILIATION_REQUIRED',
    },
  )
}

function sameCampaignSnapshotSource(left, right) {
  return left.recovered.event_count === right.recovered.event_count
    && left.recovered.state_sha256 === right.recovered.state_sha256
    && (left.candidateFrontier?.frontier_sha256 ?? null)
      === (right.candidateFrontier?.frontier_sha256 ?? null)
    && (left.candidateFrontierState?.frontier_state_sha256 ?? null)
      === (right.candidateFrontierState?.frontier_state_sha256 ?? null)
    && (left.swarmBasis?.basis_sha256 ?? null) === (right.swarmBasis?.basis_sha256 ?? null)
    && (left.swarmMerge?.merge_sha256 ?? null) === (right.swarmMerge?.merge_sha256 ?? null)
    && (left.swarmCompletion?.completion_sha256 ?? null)
      === (right.swarmCompletion?.completion_sha256 ?? null)
    && (left.swarmLedger?.ledger_sha256 ?? null) === (right.swarmLedger?.ledger_sha256 ?? null)
    && (left.swarmLedger?.head_record_sha256 ?? null)
      === (right.swarmLedger?.head_record_sha256 ?? null)
    && digestUnleashValue(left.plan) === digestUnleashValue(right.plan)
    && digestUnleashValue(left.registry) === digestUnleashValue(right.registry)
    && digestUnleashValue(left.provider) === digestUnleashValue(right.provider)
    && left.inventory.join('\n') === right.inventory.join('\n')
}

async function snapshotLoadedCampaign(input, loaded, dependencies, now) {
  const snapshotStopGate = await readEffectiveCampaignStopRequest(loaded)
  if (
    snapshotStopGate !== null
    && ![
      'COMPLETE',
      'COMPLETE_WITH_GAPS',
      'STOPPED',
      'OUTCOME_UNCERTAIN',
      'FAILED',
      'RECONCILIATION_REQUIRED',
    ].includes(loaded.state.status)
  ) {
    fail('UNLEASH_SNAPSHOT_CHANGED', 'campaign stop state changed while its snapshot was being prepared')
  }
  const actionRiskPreflight = await readCampaignActionRiskPreflight(loaded)
  const actionRiskConfirmation = actionRiskPreflight === null
    ? null
    : await readCampaignActionRiskConfirmation(loaded, actionRiskPreflight)
  const pauseControl = loaded.state.schema_version === '2.0.0'
    ? await readUnleashCampaignPauseControl({
        storage: loaded.storage,
        plan: loaded.plan,
        state: loaded.state,
      })
    : undefined
  const snapshotInput = {
    capturedAt: sampleNow(now).toISOString(),
    plan: loaded.plan,
    state: loaded.state,
    stateEvents: loaded.recovered.events,
    registry: loaded.registry,
    frontier: loaded.candidateFrontier,
    detection: publicActionRiskSummary(actionRiskPreflight === null
      ? null
      : {
          admitted: actionRiskPreflight.receipt.controller_confirmation_required === false
            || actionRiskConfirmation !== null,
          confirmation: actionRiskConfirmation,
          preflight: actionRiskPreflight,
        }),
    ...(pauseControl === undefined
      ? {}
      : {
          campaignControl: {
            pause: publicPauseControlSummary(pauseControl),
            rollback: publicRollbackSummary(pauseControl),
          },
        }),
  }
  if (loaded.state.schema_version === '2.0.0') {
    Object.assign(snapshotInput, {
      basisState: loaded.basisState,
      swarmBasis: loaded.swarmBasis,
      swarmCompletion: loaded.state.swarm_completion_sha256 === null
        ? null
        : loaded.swarmCompletion,
      swarmMerge: loaded.swarmMerge,
    })
  }
  const snapshot = createUnleashCampaignSnapshot(snapshotInput)
  let verified
  try {
    verified = await openCampaign(input, dependencies, { repairSnapshot: false })
  } catch (cause) {
    if (!transientManagementRead(cause)) throw cause
    fail('UNLEASH_SNAPSHOT_CHANGED', 'campaign changed while its verified snapshot was being prepared')
  }
  if (!sameCampaignSnapshotSource(loaded, verified)) {
    fail('UNLEASH_SNAPSHOT_CHANGED', 'campaign changed while its verified snapshot was being prepared')
  }
  return snapshot
}

export async function getUnleashCampaignStatus(input, dependencies = {}) {
  const now = dependencies.now ?? (() => new Date())
  managementInput(input, ['bundle'])
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const identity = await openCampaignIdentityForManagement(input, dependencies)
    const identityGate = await readEffectiveCampaignStopRequest(identity)
    const identityTerminal = [
      'COMPLETE',
      'COMPLETE_WITH_GAPS',
      'STOPPED',
      'OUTCOME_UNCERTAIN',
      'FAILED',
      'RECONCILIATION_REQUIRED',
    ].includes(identity.state.status)
    if (
      identity.state.schema_version === '2.0.0'
      && identityGate !== null
      && !identityTerminal
    ) {
      const ownership = await inspectProtocolV2SwarmOwnership(identity)
      return await publicPendingStopSummary(
        identity,
        identityGate,
        ownership.state === 'ACTIVE'
          ? 'ACTIVE_SWARM_OWNER_PENDING'
          : 'NO_ACTIVE_OWNER_RESUME_AVAILABLE',
      )
    }
    let loaded
    try {
      loaded = await openCampaignForManagement(
        input,
        dependencies,
        identity.state.schema_version === '2.0.0' ? { repairSnapshot: false } : undefined,
      )
    } catch (cause) {
      if (
        identity.state.schema_version === '2.0.0'
        && transientManagementRead(cause)
        && (await inspectProtocolV2SwarmOwnership(identity)).state === 'ACTIVE'
      ) {
        const gate = await readEffectiveCampaignStopRequest(identity)
        return gate === null
          ? await publicActiveSwarmOwnerSummary(identity)
          : await publicPendingStopSummary(identity, gate, 'ACTIVE_SWARM_OWNER_PENDING')
      }
      throw cause
    }
    const gate = await readEffectiveCampaignStopRequest(loaded)
    const terminal = [
      'COMPLETE',
      'COMPLETE_WITH_GAPS',
      'STOPPED',
      'OUTCOME_UNCERTAIN',
      'FAILED',
      'RECONCILIATION_REQUIRED',
    ].includes(loaded.state.status)
    if (gate !== null && !terminal) {
      if (loaded.state.schema_version === '2.0.0') {
        const ownership = await inspectProtocolV2SwarmOwnership(loaded)
        return await publicPendingStopSummary(
          loaded,
          gate,
          ownership.state === 'ACTIVE'
            ? 'ACTIVE_SWARM_OWNER_PENDING'
            : 'NO_ACTIVE_OWNER_RESUME_AVAILABLE',
        )
      }
      await settleCampaignStopRequest(loaded, gate, dependencies, now)
      continue
    }
    const recoveredStop = loaded.state.schema_version === '2.0.0'
      ? null
      : await recoverNestedStopMarker(loaded, dependencies, now)
    if (recoveredStop !== null) continue
    try {
      return await snapshotLoadedCampaign(input, loaded, dependencies, now)
    } catch (cause) {
      if (cause?.code !== 'UNLEASH_SNAPSHOT_CHANGED') throw cause
    }
  }
  fail('UNLEASH_SNAPSHOT_CHANGED', 'campaign changed repeatedly while status was preparing a verified snapshot')
}

export const getUnleashCampaignSnapshot = getUnleashCampaignStatus

export async function pauseUnleashCampaign(input, dependencies = {}) {
  managementInput(input, ['bundle', 'reason'])
  if (
    typeof input.reason !== 'string'
    || input.reason.length < 1
    || input.reason.length > 1024
    || /[\u0000-\u001f\u007f]/u.test(input.reason)
  ) fail('UNLEASH_CAMPAIGN_INPUT_INVALID', 'campaign pause reason must be one bounded human-readable string')
  const loaded = await openCampaignForManagement({ bundle: input.bundle }, dependencies)
  if (loaded.state.schema_version !== '2.0.0') {
    fail('UNLEASH_PAUSE_PROTOCOL_UNSUPPORTED', 'durable Pause requires a protocol-v2 Unleash campaign')
  }
  await requestUnleashCampaignPause({
    storage: loaded.storage,
    plan: loaded.plan,
    state: loaded.state,
    reason: input.reason,
  }, {
    now: dependencies.now ?? (() => new Date()),
    randomBytes: dependencies.pauseRandomBytes ?? systemRandomBytes,
  })
  const reopened = await openCampaignForManagement({ bundle: input.bundle }, dependencies)
  return publicControlledCampaignSummary(reopened)
}

export async function rollbackUnleashCampaign(input, dependencies = {}) {
  managementInput(input, ['bundle', 'reason'])
  if (
    typeof input.reason !== 'string'
    || input.reason.length < 8
    || input.reason.length > 1024
    || /[\u0000-\u001f\u007f]/u.test(input.reason)
  ) fail('UNLEASH_CAMPAIGN_INPUT_INVALID', 'local rollback reason must be 8-1024 printable characters')
  let loaded = await openCampaignForManagement({ bundle: input.bundle }, dependencies)
  if (loaded.state.schema_version !== '2.0.0') {
    fail('UNLEASH_ROLLBACK_PROTOCOL_UNSUPPORTED', 'bounded local rollback requires a protocol-v2 Unleash campaign')
  }
  if (!['COMPLETE', 'COMPLETE_WITH_GAPS', 'STOPPED', 'OUTCOME_UNCERTAIN', 'FAILED'].includes(loaded.state.status)) {
    await requestUnleashCampaignPause({
      storage: loaded.storage,
      plan: loaded.plan,
      state: loaded.state,
      reason: `Rollback requested: ${input.reason}`,
    }, {
      now: dependencies.now ?? (() => new Date()),
      randomBytes: dependencies.pauseRandomBytes ?? systemRandomBytes,
    })
    loaded = await openCampaignForManagement({ bundle: input.bundle }, dependencies)
    await requestUnleashLocalRollback({
      storage: loaded.storage,
      plan: loaded.plan,
      state: loaded.state,
      reason: input.reason,
    }, { now: dependencies.now ?? (() => new Date()) })
    await stopUnleashCampaign({
      bundle: loaded.state.run_directory,
      reason: boundedRollbackStopReason(input.reason),
    }, dependencies)
    loaded = await openCampaignForManagement({ bundle: input.bundle }, dependencies)
  }
  return publicControlledCampaignSummary(loaded)
}

export async function confirmUnleashActionRisk(input, dependencies = {}) {
  const retained = exactDataRecord(input, [
    'bundle', 'actionId', 'assessmentSha256', 'reason',
  ])
  if (retained === null) {
    fail('UNLEASH_CAMPAIGN_INPUT_INVALID', 'action-risk confirmation requires exact bundle, actionId, assessmentSha256, and reason fields')
  }
  managementInput({ bundle: retained.bundle }, ['bundle'])
  if (
    typeof retained.actionId !== 'string'
    || !/^http-recon-action:[a-f0-9]{64}$/u.test(retained.actionId)
    || typeof retained.assessmentSha256 !== 'string'
    || !/^[a-f0-9]{64}$/u.test(retained.assessmentSha256)
    || typeof retained.reason !== 'string'
    || retained.reason.length < 8
    || retained.reason.length > 1024
    || /[\u0000-\u001f\u007f]/u.test(retained.reason)
  ) fail('UNLEASH_CAMPAIGN_INPUT_INVALID', 'action-risk confirmation fields are malformed')
  const loaded = await openCampaignForManagement({ bundle: retained.bundle }, dependencies)
  if (['COMPLETE', 'COMPLETE_WITH_GAPS', 'STOPPED', 'OUTCOME_UNCERTAIN', 'FAILED'].includes(loaded.state.status)) {
    fail('UNLEASH_ACTION_RISK_CONFIRMATION_NOT_APPLICABLE', 'terminal campaigns cannot accept a new action-risk confirmation')
  }
  const preflight = await readCampaignActionRiskPreflight(loaded)
  if (
    preflight === null
    || preflight.action_id !== retained.actionId
    || preflight.receipt.assessment_sha256 !== retained.assessmentSha256
    || preflight.receipt.controller_confirmation_required !== true
  ) fail('UNLEASH_ACTION_RISK_CONFIRMATION_MISMATCH', 'confirmation does not name the exact pending action-risk assessment')
  let confirmation = await readCampaignActionRiskConfirmation(loaded, preflight)
  if (confirmation === null) {
    const controllerConfirmation = {
      schema_version: '1.0.0',
      kind: 'last-aperture/unleash-action-risk-confirmation',
      action_id: preflight.action_id,
      assessment_sha256: preflight.receipt.assessment_sha256,
      receipt_sha256: preflight.receipt.receipt_sha256,
      confirmed: true,
    }
    assertUnleashActionRiskConfirmation({
      receipt: preflight.receipt,
      confirmation: controllerConfirmation,
    })
    const unsigned = {
      schema_version: '1.0.0',
      kind: 'last-aperture/unleash-action-risk-confirmation-record',
      campaign_id: loaded.state.campaign_id,
      plan_sha256: loaded.plan.plan_sha256,
      policy_sha256: loaded.plan.policy_sha256,
      target_id: loaded.plan.target.target_id,
      action_id: preflight.action_id,
      preflight_sha256: preflight.preflight_sha256,
      operator_reason: retained.reason,
      confirmation: controllerConfirmation,
      confirmed_at: sampleNow(dependencies.now ?? (() => new Date())).toISOString(),
    }
    const created = assertCampaignActionRiskConfirmation({
      ...unsigned,
      confirmation_sha256: digestUnleashValue(unsigned),
    }, loaded, preflight)
    try {
      await loaded.storage.writeImmutableJson(ACTION_RISK_CONFIRMATION_FILE, created)
    } catch (cause) {
      if (cause?.code !== 'UNLEASH_STORAGE_FILE_EXISTS') throw cause
    }
    confirmation = await readCampaignActionRiskConfirmation(loaded, preflight)
  }
  if (confirmation === null) {
    fail('UNLEASH_ACTION_RISK_CONFIRMATION_MISSING', 'action-risk confirmation was not retained')
  }
  return resumeUnleashCampaign({ bundle: loaded.state.run_directory }, dependencies)
}

export async function stopUnleashCampaign(input, dependencies = {}) {
  managementInput(input, ['bundle', 'reason'])
  if (
    typeof input.reason !== 'string'
    || input.reason.length < 1
    || input.reason.length > 1024
    || /[\u0000-\u001f\u007f]/u.test(input.reason)
  ) fail('UNLEASH_CAMPAIGN_INPUT_INVALID', 'campaign stop reason must be one bounded human-readable string')
  const identity = await openCampaignIdentityForManagement({ bundle: input.bundle }, dependencies)
  const loaded = identity.state.schema_version === '2.0.0'
    ? identity
    : await openCampaignForManagement({ bundle: input.bundle }, dependencies)
  if (['COMPLETE', 'COMPLETE_WITH_GAPS', 'STOPPED', 'OUTCOME_UNCERTAIN', 'FAILED'].includes(loaded.state.status)) {
    return publicSummary(loaded.state)
  }
  const now = dependencies.now ?? (() => new Date())
  if (loaded.state.schema_version === '2.0.0') {
    const claim = await claimProtocolV2StopFence(
      loaded,
      loaded.state.stop_reason ?? input.reason,
      now,
    )
    if (claim.decision === 'SEAL') {
      return resumeUnleashCampaign({ bundle: loaded.state.run_directory }, dependencies)
    }
    return resumeUnleashCampaign({ bundle: loaded.state.run_directory }, dependencies)
  }
  const gate = await publishCampaignStopRequest(
    loaded,
    loaded.state.stop_reason ?? input.reason,
    now,
  )
  return publicSummary(await settleCampaignStopRequest(loaded, gate, dependencies, now))
}

async function resumeOpenedUnleashCampaign(loaded, dependencies, now) {
  if (['COMPLETE', 'COMPLETE_WITH_GAPS', 'STOPPED', 'OUTCOME_UNCERTAIN', 'FAILED'].includes(loaded.state.status)) {
    return publicSummary(loaded.state)
  }
  const gate = await readEffectiveCampaignStopRequest(loaded)
  if (gate !== null) {
    try {
      return publicSummary(await settleCampaignStopRequest(loaded, gate, dependencies, now))
    } catch (cause) {
      if (!isSwarmOwnerBusy(cause)) throw cause
      return await publicPendingStopSummary(loaded, gate, 'ACTIVE_SWARM_OWNER_PENDING')
    }
  }
  const recoveredStop = protocolV2SwarmHasStarted(loaded)
    ? null
    : await recoverNestedStopMarker(loaded, dependencies, now)
  if (recoveredStop !== null) return publicSummary(recoveredStop)
  if (loaded.state.status === 'STOP_REQUESTED' || loaded.state.stop_reason !== null) {
    if (protocolV2SwarmHasStarted(loaded)) {
      try {
        return publicSummary(await completeRecoveredRecon(loaded, dependencies, now))
      } catch (cause) {
        if (!isSwarmOwnerBusy(cause)) throw cause
        return await publicActiveSwarmOwnerSummary(loaded)
      }
    }
    if (loaded.state.status !== 'STOP_REQUESTED') {
      loaded.state = await appendState(loaded.storage, loaded.state, {
        status: 'STOP_REQUESTED',
        failure: null,
      }, now)
    }
    try {
      loaded.state = await reconcileRequestedStop(loaded, dependencies, now)
      return publicSummary(loaded.state)
    } catch (cause) {
      if (!isSwarmOwnerBusy(cause)) throw cause
      return await publicActiveSwarmOwnerSummary(loaded)
    }
  }

  const { policy, isRevoked } = await resolveControllerAuthority(dependencies)
  assertResumeAuthority(policy, isRevoked, loaded.plan, now, loaded.provider)

  const finalizeRecon = dependencies.finalizeHttpReconBundle ?? finalizeHttpReconBundle
  const nextRecon = dependencies.nextHttpReconAction ?? nextHttpReconAction
  const runRecon = dependencies.runHttpReconAction ?? enrolledHttpReconRun(dependencies)
  if (typeof finalizeRecon !== 'function' || typeof nextRecon !== 'function' || typeof runRecon !== 'function') {
    fail('UNLEASH_RECON_UNAVAILABLE', 'HTTPS reconnaissance recovery controller is unavailable')
  }

  let finalized
  let needsPendingAction = false
  let reconMissing = false
  try {
    finalized = await finalizeRecon({ bundle: loaded.state.recon_bundle, now })
  } catch (cause) {
    if (cause?.code === 'HTTP_RECON_PLAN_INCOMPLETE') needsPendingAction = true
    else if (missingRecon(cause)) reconMissing = true
    else {
      loaded.state = await appendReconciliationRequired(
        loaded,
        now,
        'UNLEASH_RECON_RECOVERY_FAILED',
        'Existing reconnaissance artifacts could not be reconciled safely; no action was replayed.',
      )
      return publicSummary(loaded.state)
    }
  }
  if (finalized !== undefined) {
    let terminal
    try {
      terminal = await terminalizeFromRecon(loaded, finalized, dependencies, now)
    } catch (cause) {
      if (!isSwarmOwnerBusy(cause)) throw cause
      return await publicActiveSwarmOwnerSummary(loaded)
    }
    if (terminal !== null) return publicSummary(terminal)
    loaded.state = await appendReconciliationRequired(
      loaded,
      now,
      'UNLEASH_RECON_STATE_UNKNOWN',
      'Existing reconnaissance recovered to an unknown state; no action was replayed.',
    )
    return publicSummary(loaded.state)
  }

  if (reconMissing && loaded.state.status !== 'PLANNED') {
    loaded.state = await appendReconciliationRequired(
      loaded,
      now,
      'UNLEASH_RECON_BUNDLE_MISSING',
      'A campaign that may have dispatched has no retained reconnaissance bundle; no action was replayed.',
    )
    return publicSummary(loaded.state)
  }

  if (reconMissing) {
    const goHttpRecon = enrolledHttpsReconAdapter(loaded.registry)
    const admittedAt = sampleNow(now)
    assertResumeAuthority(policy, isRevoked, loaded.plan, () => admittedAt, loaded.provider)
    const authority = loaded.reconAuthority === null
      ? controllerPolicyAuthority(policy, loaded.plan, admittedAt)
      : assertControllerPolicyAuthority(loaded.reconAuthority, policy, loaded.plan)
    if (loaded.reconAuthority === null) {
      await loaded.storage.writeImmutableJson(RECON_AUTHORITY_FILE, authority)
      loaded.reconAuthority = authority
    }
    loaded.state = await appendState(loaded.storage, loaded.state, { status: 'RUNNING' }, now)
    const revalidateAuthority = controllerPolicyRevalidator({
      policy,
      plan: loaded.plan,
      isRevoked,
      now,
      authority,
      loaded,
    })
    try {
      finalized = await goHttpRecon({
        targetUrl: loaded.plan.target.canonical_locator,
        out: loaded.state.recon_bundle,
        controllerPolicyAuthority: controllerPolicyAdmission(authority),
        revalidateAuthority,
        now,
        runImpl: enrolledHttpReconRun(dependencies),
        onPlanned: campaignReconPlannedCallback(loaded, dependencies, now, policy),
      })
    } catch {
      return publicSummary(await reconcileAfterReconAttempt(
        loaded,
        dependencies,
        now,
        finalizeRecon,
      ))
    }
    if (finalized?.state !== 'PROBE_PLAN_COMPLETE' || !sameResolvedPath(finalized.bundle, loaded.state.recon_bundle)) {
      loaded.state = await appendReconciliationRequired(
        loaded,
        now,
        'UNLEASH_RECON_RESULT_INVALID',
        'Resumed HTTPS reconnaissance returned an invalid result; no further action was attempted.',
      )
      return publicSummary(loaded.state)
    }
    let terminal
    try {
      terminal = await terminalizeFromRecon(
        loaded,
        { state: 'PROBE_PLAN_COMPLETE' },
        dependencies,
        now,
      )
    } catch (cause) {
      if (!isSwarmOwnerBusy(cause)) throw cause
      return await publicActiveSwarmOwnerSummary(loaded)
    }
    return publicSummary(terminal)
  }

  if (needsPendingAction) {
    let action
    try { action = await nextRecon({ bundle: loaded.state.recon_bundle, now }) } catch {
      loaded.state = await appendReconciliationRequired(
        loaded,
        now,
        'UNLEASH_RECON_PENDING_ACTION_UNVERIFIED',
        'The pending reconnaissance action could not be proven unsent; no action was replayed.',
      )
      return publicSummary(loaded.state)
    }
    if (
      action === null
      || typeof action?.action_id !== 'string'
      || !['PENDING', 'PAUSED_BEFORE_SEND'].includes(action.state)
    ) {
      loaded.state = await appendReconciliationRequired(
        loaded,
        now,
        'UNLEASH_RECON_PENDING_ACTION_INVALID',
        'Recovery did not produce exactly one proven-unsent resumable action; no action was dispatched.',
      )
      return publicSummary(loaded.state)
    }
    if (loaded.state.status === 'PLANNED') {
      loaded.state = await appendState(loaded.storage, loaded.state, { status: 'RUNNING' }, now)
    }
    assertResumeAuthority(policy, isRevoked, loaded.plan, now, loaded.provider)
    const authority = await readRetainedReconAuthority(loaded, policy)
    const revalidateAuthority = controllerPolicyRevalidator({
      policy,
      plan: loaded.plan,
      isRevoked,
      now,
      authority,
      loaded,
    })
    const riskAdmission = await ensureCampaignActionRiskAdmission(
      loaded,
      policy,
      action.action_id,
      now,
    )
    await dependencies.onActionRiskPreflight?.(publicActionRiskSummary(riskAdmission))
    if (!riskAdmission.admitted) {
      return publicSummaryWithActionRisk(loaded.state, riskAdmission)
    }
    try {
      await runRecon({
        bundle: loaded.state.recon_bundle,
        actionId: action.action_id,
        controllerPolicyAuthority: authority,
        revalidateAuthority,
        now,
      })
    } catch (cause) {
      if (errorChainHasCode(cause, 'UNLEASH_CAMPAIGN_PAUSED')) {
        return publicControlledCampaignSummary(loaded)
      }
      return publicSummary(await reconcileAfterReconAttempt(
        loaded,
        dependencies,
        now,
        finalizeRecon,
      ))
    }
    return publicSummary(await reconcileAfterReconAttempt(
      loaded,
      dependencies,
      now,
      finalizeRecon,
    ))
  }

  loaded.state = await appendReconciliationRequired(
    loaded,
    now,
    'UNLEASH_RECON_RECOVERY_INCOMPLETE',
    'Reconnaissance recovery did not reach a terminal verified state; no further action was attempted.',
  )
  return publicSummary(loaded.state)
}

export async function resumeUnleashCampaign(input, dependencies = {}) {
  managementInput(input, ['bundle'])
  const now = dependencies.now ?? (() => new Date())
  let loaded = await openCampaignIdentityForManagement(input, dependencies)
  if (loaded.state.schema_version !== '2.0.0') {
    loaded = await openCampaignForManagement(input, dependencies)
    return resumeOpenedUnleashCampaign(loaded, dependencies, now)
  }

  const acquisition = await acquireUnleashSwarmOwner(
    protocolV2SwarmOwnerInput(loaded),
    { now },
  )
  if (acquisition.state === 'BUSY') {
    const gate = await readEffectiveCampaignStopRequest(loaded)
    return gate === null
      ? await publicActiveSwarmOwnerSummary(loaded)
      : await publicPendingStopSummary(loaded, gate, 'ACTIVE_SWARM_OWNER_PENDING')
  }

  const owner = acquisition.owner
  const openStorage = dependencies.openCampaignStorage ?? openUnleashCampaignStorage
  const ownedDependencies = {
    ...dependencies,
    openCampaignStorage: async (storageInput) => bindUnleashSwarmOwnerStorage(
      await openStorage(storageInput),
      owner,
    ),
  }
  let result
  let executionFailure
  try {
    loaded = await openCampaignForManagement(input, ownedDependencies)
    Object.defineProperty(loaded, SWARM_OWNER_TOKEN, {
      value: owner,
      configurable: false,
      enumerable: false,
      writable: false,
    })
    const rollbackClaim = await recoverProtocolV2RollbackStop(loaded, now)
    const stopGate = rollbackClaim?.request ?? await readEffectiveCampaignStopRequest(loaded)
    const terminal = ['COMPLETE', 'COMPLETE_WITH_GAPS', 'STOPPED', 'OUTCOME_UNCERTAIN', 'FAILED']
      .includes(loaded.state.status)
    if (stopGate === null && rollbackClaim?.decision !== 'SEAL' && !terminal) {
      const pauseBeforeResume = await readUnleashCampaignPauseControl({
        storage: loaded.storage,
        plan: loaded.plan,
        state: loaded.state,
      })
      if (pauseBeforeResume.active_requests.length > 0) {
        const { policy, isRevoked } = await resolveControllerAuthority(ownedDependencies)
        assertResumeAuthority(policy, isRevoked, loaded.plan, now, loaded.provider)
        const pause = await acknowledgeUnleashCampaignPause({
          storage: loaded.storage,
          plan: loaded.plan,
          state: loaded.state,
          ownerId: owner.owner_id,
        }, { now })
        if (!pause.dispatch_open) {
          result = await publicControlledCampaignSummary(loaded)
        }
      }
    }
    if (result === undefined) {
      result = await resumeOpenedUnleashCampaign(loaded, ownedDependencies, now)
    }
  } catch (cause) {
    executionFailure = cause
  }
  try {
    await releaseUnleashSwarmOwner(owner)
  } catch (releaseFailure) {
    throw new UnleashControllerError(
      'UNLEASH_CAMPAIGN_SWARM_OWNER_RELEASE_FAILED',
      'The resumed exclusive swarm owner could not be released by exact identity.',
      {
        cause: executionFailure === undefined
          ? releaseFailure
          : new AggregateError([executionFailure, releaseFailure]),
        runDirectory: loaded.state.run_directory,
        status: 'RECONCILIATION_REQUIRED',
      },
    )
  }
  if (executionFailure !== undefined) throw executionFailure
  return result
}
