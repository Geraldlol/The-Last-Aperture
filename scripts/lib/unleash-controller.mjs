import { createHash, randomBytes as systemRandomBytes } from 'node:crypto'
import { mkdir as mkdirDefault } from 'node:fs/promises'
import { homedir } from 'node:os'
import { basename, dirname, isAbsolute, join, resolve } from 'node:path'

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
  assertExactUnleashHttpsReconExecutionContract,
  assertSelfBoundUnleashPlan,
  assertValidUnleashPlan,
  createUnleashPlan,
  digestUnleashValue,
} from './unleash-contracts.mjs'
import {
  assertPolicyAllowsTarget,
  createUnleashDeploymentPolicy,
  projectUnleashPolicy,
} from './unleash-policy.mjs'
import { loadUnleashControllerPolicy } from './unleash-policy-loader.mjs'
import {
  assertValidUnleashReconCompletion,
  createVerifiedReconCompletion,
  verifyUnleashReconCompletion,
} from './unleash-recon-evidence.mjs'
import { createDefaultUnleashPlannerDependencies } from './unleash-registry.mjs'

const INTAKE_FIELDS = ['target']
const RECON_AUTHORITY_FILE = 'campaign-recon-authority.json'
const RECON_PLANNED_FILE = 'campaign-recon-planned.json'
const STOP_REQUEST_FILE = 'campaign-stop-request.json'
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

function hasExactKeys(value, fields) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.keys(value).toSorted().join(',') === [...fields].toSorted().join(',')
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
  return Object.freeze({
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
  })
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
  if (projectUnleashPolicy(policy).policy_sha256 !== plan.policy_sha256) {
    fail('UNLEASH_POLICY_PLAN_DRIFT', 'deployment policy no longer matches the retained campaign plan')
  }
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

async function publishCampaignStopRequest(loaded, reason, now) {
  const request = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-stop-request',
    campaign_id: loaded.state.campaign_id,
    plan_sha256: loaded.plan.plan_sha256,
    policy_id: loaded.plan.policy_id,
    policy_sha256: loaded.plan.policy_sha256,
    target_id: loaded.plan.target.target_id,
    revocation_check_id: loaded.plan.authority.revocation.check_id,
    requested_at: sampleNow(now).toISOString(),
    reason,
  }
  assertCampaignStopRequest(request, loaded)
  try {
    await loaded.storage.writeImmutableJson(STOP_REQUEST_FILE, request)
    return Object.freeze(structuredClone(request))
  } catch (cause) {
    if (cause?.code !== 'UNLEASH_STORAGE_FILE_EXISTS') throw cause
    return readCampaignStopRequest(loaded)
  }
}

async function assertCampaignDispatchOpen(loaded) {
  const request = await readCampaignStopRequest(loaded)
  if (request !== null) {
    fail(
      'UNLEASH_CAMPAIGN_STOP_REQUESTED',
      'The durable campaign stop gate is closed; target dispatch is forbidden.',
      { runDirectory: loaded.state.run_directory, status: 'STOP_REQUESTED' },
    )
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

function campaignReconPlannedCallback(loaded, dependencies, now) {
  return async (planned) => {
    await publishCampaignReconPlanned(loaded, planned, now)
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
  if (!['COMPLETE', 'COMPLETE_WITH_GAPS'].includes(state.status)) return
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
  } catch (cause) {
    throw new UnleashControllerError(
      'UNLEASH_COMPLETED_CAMPAIGN_EVIDENCE_INVALID',
      'Completed campaign evidence is missing, malformed, or no longer matches its state.',
      { cause, runDirectory: state.run_directory, status: 'RECONCILIATION_REQUIRED' },
    )
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
  } else if ([
    'RUNNING', 'STOP_REQUESTED', 'COMPLETE', 'COMPLETE_WITH_GAPS',
  ].includes(recovered.state.status)) {
    fail('UNLEASH_RECON_AUTHORITY_MISSING', 'campaign state requires a retained controller-policy reconnaissance authority')
  }
  await assertCompletedCampaignArtifacts(storage, recovered.state, plan, reconAuthority)
  return {
    storage,
    plan,
    registry,
    provider,
    reconAuthority,
    state: recovered.state,
    recovered,
  }
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
  const plannerDependencies = createDefaultUnleashPlannerDependencies({ policy })
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
  const storage = assertCampaignStorage(
    await createCampaignStorage({ runsRoot, campaignDirectory }),
    runsRoot,
    campaignDirectory,
  )
  const runDirectory = storage.campaign_directory
  const reconBundle = join(runDirectory, 'recon')
  await storage.writeImmutableJson('campaign-plan.json', plan)
  await storage.writeImmutableJson('campaign-registry.json', plannerDependencies.registry)
  await storage.writeImmutableJson('campaign-provider.json', plannerDependencies.provider)
  const counts = routeCounts(plan)
  const gapCount = counts.waiting + counts.unavailable + counts.blocked
  let state = {
    schema_version: '1.0.0',
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
  }
  state = await appendState(storage, null, state, now)

  let reconReachedTerminal = false
  try {
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
    const stopBeforePlanning = await readCampaignStopRequest(campaign)
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
      onPlanned: campaignReconPlannedCallback(campaign, dependencies, now),
      })
    } catch (cause) {
      const retainedStop = await readCampaignStopRequest(campaign)
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
    const completion = await persistVerifiedReconCompletion({
      storage,
      bundle: reconBundle,
      plan,
      dependencies,
      now,
    })
    const packet = completion.evidence_packet
    const evidencePacketPath = join(runDirectory, 'evidence-packet.json')
    state = await appendState(storage, state, {
      status: gapCount === 0 ? 'COMPLETE' : 'COMPLETE_WITH_GAPS',
      completed_routes: ['https-recon'],
      evidence_packet_path: evidencePacketPath,
      evidence_packet_sha256: packet.packet_sha256,
      completion_receipt_sha256: completion.completion_receipt.completion_receipt_sha256,
      failure: null,
    }, now)
    return publicSummary(state)
  } catch (cause) {
    if ([
      'UNLEASH_CAMPAIGN_RECONCILIATION_REQUIRED',
      'UNLEASH_CAMPAIGN_SNAPSHOT_STALE',
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
      const loaded = { storage, plan, state }
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

function assertResumeAuthority(policy, isRevoked, plan, now) {
  const plannerDependencies = createDefaultUnleashPlannerDependencies({ policy })
  assertValidUnleashPlan(plan, plannerDependencies)
  assertPolicyPlanBinding(policy, plan)
  assertPolicyAllowsTarget(policy, plan.target, {
    now: sampleNow(now),
    isRevoked,
    effect: 'OBSERVE',
  })
  assertReconAdapterWithinPolicy(policy)
}

async function appendReconciliationRequired(loaded, now, code, message) {
  if (loaded.state.status === 'RECONCILIATION_REQUIRED') return loaded.state
  return appendState(loaded.storage, loaded.state, {
    status: 'RECONCILIATION_REQUIRED',
    completed_routes: [],
    evidence_packet_path: null,
    evidence_packet_sha256: null,
    completion_receipt_sha256: null,
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

async function completeRecoveredRecon(loaded, dependencies, now) {
  const completion = await persistVerifiedReconCompletion({
    storage: loaded.storage,
    bundle: loaded.state.recon_bundle,
    plan: loaded.plan,
    dependencies,
    now,
  })
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
      loaded = await openCampaign({ bundle: loaded.state.run_directory }, dependencies)
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
      loaded = await openCampaign({ bundle: loaded.state.run_directory }, dependencies)
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

export async function getUnleashCampaignStatus(input, dependencies = {}) {
  let loaded = await openCampaign(input, dependencies)
  const now = dependencies.now ?? (() => new Date())
  const gate = await readCampaignStopRequest(loaded)
  if (gate !== null) {
    return publicSummary(await settleCampaignStopRequest(loaded, gate, dependencies, now))
  }
  const recoveredStop = await recoverNestedStopMarker(loaded, dependencies, now)
  if (recoveredStop !== null) return publicSummary(recoveredStop)
  return publicSummary(loaded.state)
}

export async function stopUnleashCampaign(input, dependencies = {}) {
  managementInput(input, ['bundle', 'reason'])
  if (
    typeof input.reason !== 'string'
    || input.reason.length < 1
    || input.reason.length > 1024
    || /[\u0000-\u001f\u007f]/u.test(input.reason)
  ) fail('UNLEASH_CAMPAIGN_INPUT_INVALID', 'campaign stop reason must be one bounded human-readable string')
  let loaded = await openCampaign({ bundle: input.bundle }, dependencies)
  if (['COMPLETE', 'COMPLETE_WITH_GAPS', 'STOPPED', 'OUTCOME_UNCERTAIN', 'FAILED'].includes(loaded.state.status)) {
    return publicSummary(loaded.state)
  }
  const now = dependencies.now ?? (() => new Date())
  const gate = await publishCampaignStopRequest(
    loaded,
    loaded.state.stop_reason ?? input.reason,
    now,
  )
  return publicSummary(await settleCampaignStopRequest(loaded, gate, dependencies, now))
}

export async function resumeUnleashCampaign(input, dependencies = {}) {
  const now = dependencies.now ?? (() => new Date())
  const loaded = await openCampaign(input, dependencies)
  if (['COMPLETE', 'COMPLETE_WITH_GAPS', 'STOPPED', 'OUTCOME_UNCERTAIN', 'FAILED'].includes(loaded.state.status)) {
    return publicSummary(loaded.state)
  }
  const gate = await readCampaignStopRequest(loaded)
  if (gate !== null) {
    return publicSummary(await settleCampaignStopRequest(loaded, gate, dependencies, now))
  }
  const recoveredStop = await recoverNestedStopMarker(loaded, dependencies, now)
  if (recoveredStop !== null) return publicSummary(recoveredStop)
  if (loaded.state.status === 'STOP_REQUESTED' || loaded.state.stop_reason !== null) {
    if (loaded.state.status !== 'STOP_REQUESTED') {
      loaded.state = await appendState(loaded.storage, loaded.state, {
        status: 'STOP_REQUESTED',
        failure: null,
      }, now)
    }
    loaded.state = await reconcileRequestedStop(loaded, dependencies, now)
    return publicSummary(loaded.state)
  }

  const { policy, isRevoked } = await resolveControllerAuthority(dependencies)
  assertResumeAuthority(policy, isRevoked, loaded.plan, now)

  const finalizeRecon = dependencies.finalizeHttpReconBundle ?? finalizeHttpReconBundle
  const nextRecon = dependencies.nextHttpReconAction ?? nextHttpReconAction
  const runRecon = dependencies.runHttpReconAction ?? runControllerPolicyHttpReconAction
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
    const terminal = await terminalizeFromRecon(loaded, finalized, dependencies, now)
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
    assertResumeAuthority(policy, isRevoked, loaded.plan, () => admittedAt)
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
        onPlanned: campaignReconPlannedCallback(loaded, dependencies, now),
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
    const terminal = await terminalizeFromRecon(
      loaded,
      { state: 'PROBE_PLAN_COMPLETE' },
      dependencies,
      now,
    )
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
    if (action === null || typeof action?.action_id !== 'string' || action.state !== 'PENDING') {
      loaded.state = await appendReconciliationRequired(
        loaded,
        now,
        'UNLEASH_RECON_PENDING_ACTION_INVALID',
        'Recovery did not produce exactly one untouched pending action; no action was replayed.',
      )
      return publicSummary(loaded.state)
    }
    if (loaded.state.status === 'PLANNED') {
      loaded.state = await appendState(loaded.storage, loaded.state, { status: 'RUNNING' }, now)
    }
    assertResumeAuthority(policy, isRevoked, loaded.plan, now)
    const authority = await readRetainedReconAuthority(loaded, policy)
    const revalidateAuthority = controllerPolicyRevalidator({
      policy,
      plan: loaded.plan,
      isRevoked,
      now,
      authority,
      loaded,
    })
    try {
      await runRecon({
        bundle: loaded.state.recon_bundle,
        actionId: action.action_id,
        controllerPolicyAuthority: authority,
        revalidateAuthority,
        now,
      })
    } catch {
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
