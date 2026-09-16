import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import Ajv2020 from 'ajv/dist/2020.js'

import {
  assertSelfBoundUnleashPlan,
  assertValidUnleashPlan,
  assertValidUnleashProposal,
  digestUnleashValue,
  unleashProposalSchema,
} from './unleash-contracts.mjs'
import { assertValidUnleashCampaignState } from './unleash-campaign-state.mjs'
import { canonicalUnleashCampaignJson } from './unleash-campaign-storage.mjs'
import { assertValidUnleashEvidencePacket } from './unleash-evidence-packet.mjs'
import { assertValidUnleashReconCompletion } from './unleash-recon-evidence.mjs'
import {
  assertValidUnleashSwarmBasis,
  assertValidUnleashSwarmCompletion,
} from './unleash-swarm-contracts.mjs'
import { assertValidUnleashSwarmMerge } from './unleash-swarm-merge.mjs'

const ADMISSION_SCHEMA_URL = new URL('../../schemas/unleash-candidate-admission.schema.json', import.meta.url)

export const unleashCandidateAdmissionSchema = JSON.parse(
  readFileSync(fileURLToPath(ADMISSION_SCHEMA_URL), 'utf8'),
)

export const UNLEASH_CANDIDATE_FRONTIER_LIMITS = Object.freeze({
  max_admissions: 256,
  max_candidates: 4096,
  max_proposed_actions: 4096,
})

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})
ajv.addSchema(unleashProposalSchema)
ajv.addSchema(unleashCandidateAdmissionSchema)
const validateAdmissionSchema = ajv.getSchema(unleashCandidateAdmissionSchema.$id)
const validateFrontierStateSchema = ajv.getSchema(
  `${unleashCandidateAdmissionSchema.$id}#/$defs/frontierState`,
)

const ADMISSION_FILENAME = /^candidate-admission-([0-9]{6})\.json$/u
export const UNLEASH_CANDIDATE_FRONTIER_STATE_FILE = 'candidate-frontier-state.json'
const MAX_CAMPAIGN_JSON_FILES = 10_000
const SHA256 = /^[a-f0-9]{64}$/u
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u
const CONTEXT_FIELDS = [
  'plan',
  'registry',
  'provider',
  'campaignState',
  'evidencePacket',
  'completion',
  'previousAdmission',
]
const CREATE_FIELDS = [...CONTEXT_FIELDS, 'proposal', 'sequence', 'recordedAt']
const RECOVER_FIELDS = CONTEXT_FIELDS.filter((field) => field !== 'previousAdmission').concat('storage')
const EMPTY_FIELDS = ['plan', 'campaignState']
const V2_CONTEXT_FIELDS = [
  'plan',
  'registry',
  'provider',
  'basisState',
  'campaignState',
  'evidencePacket',
  'completion',
  'swarmBasis',
  'swarmMerge',
  'swarmCompletion',
  'previousAdmission',
]
const V2_CREATE_FIELDS = [...V2_CONTEXT_FIELDS, 'proposal', 'sequence', 'recordedAt']
const V2_RECOVER_FIELDS = V2_CONTEXT_FIELDS
  .filter((field) => field !== 'previousAdmission')
  .concat('storage')
const V2_EMPTY_FIELDS = V2_CONTEXT_FIELDS.filter((field) => field !== 'previousAdmission')
const V2_PREVIEW_FIELDS = ['frontier', 'admission', 'campaignState', 'swarmMerge', 'swarmCompletion']
const FRONTIER_STATE_CONTEXT_FIELDS = ['frontier', 'campaignState']
const CREATE_FRONTIER_STATE_FIELDS = [...FRONTIER_STATE_CONTEXT_FIELDS, 'recordedAt']
const RECONCILE_FRONTIER_STATE_FIELDS = [
  ...FRONTIER_STATE_CONTEXT_FIELDS,
  'retainedState',
  'recordedAt',
]
const FRONTIER_FIELDS = [
  'schema_version',
  'kind',
  'campaign_id',
  'plan_sha256',
  'target_id',
  'campaign_state_revision',
  'campaign_state_sha256',
  'evidence_packet_sha256',
  'completion_receipt_sha256',
  'proposal_count',
  'candidate_count',
  'proposed_action_count',
  'head_admission_sha256',
  'candidates',
  'actions',
  'frontier_sha256',
]
const V2_FRONTIER_FIELDS = [...FRONTIER_FIELDS, 'swarm_basis_sha256', 'swarm_merge_sha256']
const V2_FRONTIER_STATE_CONTEXT_FIELDS = [
  'frontier',
  'basisState',
  'campaignState',
  'swarmBasis',
  'swarmMerge',
  'swarmCompletion',
]
const V2_CREATE_FRONTIER_STATE_FIELDS = [...V2_FRONTIER_STATE_CONTEXT_FIELDS, 'recordedAt']
const V2_RECONCILE_FRONTIER_STATE_FIELDS = [
  ...V2_FRONTIER_STATE_CONTEXT_FIELDS,
  'retainedState',
  'recordedAt',
]
const CANDIDATE_FIELDS = [
  'candidate_id',
  'state',
  'proposal_id',
  'proposal_sha256',
  'admission_sha256',
  'title',
  'hypothesis',
  'invariant',
  'provider_confidence',
  'evidence_refs',
  'competing_explanations',
  'proposed_action_ids',
  'candidate_sha256',
]
const ACTION_FIELDS = [
  'action_id',
  'state',
  'candidate_id',
  'proposal_id',
  'proposal_sha256',
  'admission_sha256',
  'tool_id',
  'evidence_refs',
  'parameters',
  'expected_observation',
  'executable',
  'action_sha256',
]
const PREVIEW_FIELDS = ['frontier', 'admission']
const PROVENANCE_FIELDS = ['frontier']
const trustedAdmissions = new WeakSet()
const frontierProvenance = new WeakMap()
const campaignChainProvenance = new WeakMap()
const BINDING_FIELDS = [
  'campaign_id',
  'campaign_state_revision',
  'campaign_state_sha256',
  'plan_sha256',
  'target_id',
  'evidence_packet_sha256',
  'completion_receipt_sha256',
  'provider_protocol_version',
  'provider_sha256',
]
const V2_BINDING_FIELDS = [...BINDING_FIELDS, 'swarm_basis_sha256', 'swarm_merge_sha256']

export class UnleashCandidateFrontierError extends Error {
  constructor(code, message, { cause } = {}) {
    super(message, cause === undefined ? undefined : { cause })
    this.name = 'UnleashCandidateFrontierError'
    this.code = code
  }
}

function fail(code, message, cause) {
  throw new UnleashCandidateFrontierError(code, message, { cause })
}

function exactRecord(value, fields) {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  ) return false
  const descriptors = Object.getOwnPropertyDescriptors(value)
  const keys = Reflect.ownKeys(descriptors)
  return keys.length === fields.length
    && keys.every((key) => typeof key === 'string'
      && fields.includes(key)
      && descriptors[key].enumerable
      && Object.hasOwn(descriptors[key], 'value'))
}

function frozenCopy(value) {
  const copy = structuredClone(value)
  const stack = [copy]
  while (stack.length > 0) {
    const current = stack.pop()
    if (current === null || typeof current !== 'object' || Object.isFrozen(current)) continue
    for (const child of Object.values(current)) stack.push(child)
    Object.freeze(current)
  }
  return copy
}

function safeCanonicalCopy(value, label) {
  try {
    return JSON.parse(canonicalUnleashCampaignJson(value))
  } catch (cause) {
    fail('UNLEASH_CANDIDATE_VALUE_INVALID', `${label} must be bounded canonical plain JSON`, cause)
  }
}

export function snapshotUnleashProviderProposal(value) {
  return frozenCopy(safeCanonicalCopy(value, 'provider proposal'))
}

function assertCanonicalTimestamp(value, label) {
  if (
    typeof value !== 'string'
    || !TIMESTAMP.test(value)
    || !Number.isFinite(Date.parse(value))
    || new Date(value).toISOString() !== value
  ) fail('UNLEASH_CANDIDATE_TIME_INVALID', `${label} must be one canonical UTC timestamp`)
}

function recordedAt(value) {
  if (!(value instanceof Date) || !Number.isFinite(Date.prototype.getTime.call(value))) {
    fail('UNLEASH_CANDIDATE_TIME_INVALID', 'recordedAt must be one valid Date')
  }
  const timestamp = Date.prototype.toISOString.call(value)
  assertCanonicalTimestamp(timestamp, 'recorded_at')
  return timestamp
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

function assertContext(value) {
  if (!exactRecord(value, CONTEXT_FIELDS)) {
    fail('UNLEASH_CANDIDATE_CONTEXT_INVALID', 'candidate admission requires exact retained campaign artifacts')
  }
  const {
    plan,
    registry,
    provider,
    campaignState,
    evidencePacket,
    completion,
  } = value
  assertValidUnleashCampaignState(campaignState)
  if (!['COMPLETE', 'COMPLETE_WITH_GAPS'].includes(campaignState.status)) {
    fail('UNLEASH_CANDIDATE_CAMPAIGN_NOT_COMPLETE', 'candidate admission requires a terminal evidence-complete campaign')
  }
  assertValidUnleashPlan(plan, {
    registry,
    provider,
    policy: retainedPlanPolicy(plan),
  })
  assertValidUnleashEvidencePacket(evidencePacket)
  assertValidUnleashReconCompletion(completion, { plan })
  const receipt = completion.completion_receipt
  const counts = routeCounts(plan)
  if (
    campaignState.campaign_id === undefined
    || campaignState.plan_sha256 !== plan.plan_sha256
    || digestUnleashValue(campaignState.target) !== digestUnleashValue(plan.target)
    || digestUnleashValue(campaignState.route_counts) !== digestUnleashValue(counts)
    || campaignState.gap_count !== counts.waiting + counts.unavailable + counts.blocked
    || campaignState.evidence_packet_sha256 !== evidencePacket.packet_sha256
    || campaignState.completion_receipt_sha256 !== receipt.completion_receipt_sha256
    || digestUnleashValue(completion.evidence_packet) !== digestUnleashValue(evidencePacket)
    || campaignState.completed_routes.length !== 1
    || campaignState.completed_routes[0] !== receipt.route_id
  ) fail('UNLEASH_CANDIDATE_CAMPAIGN_DRIFT', 'candidate admission artifacts do not describe one exact completed campaign')
  return value
}

function assertContextV2(value, { admitting = false } = {}) {
  if (!exactRecord(value, V2_CONTEXT_FIELDS)) {
    fail('UNLEASH_CANDIDATE_CONTEXT_INVALID', 'protocol-v2 candidate admission requires exact basis, campaign, swarm, and evidence artifacts')
  }
  const {
    plan,
    registry,
    provider,
    basisState,
    campaignState,
    evidencePacket,
    completion,
    swarmBasis,
    swarmMerge,
    swarmCompletion,
  } = value
  assertValidUnleashCampaignState(basisState)
  assertValidUnleashCampaignState(campaignState)
  if (
    basisState.schema_version !== '2.0.0'
    || basisState.status !== 'RUNNING'
    || campaignState.schema_version !== '2.0.0'
  ) fail('UNLEASH_CANDIDATE_SWARM_STATE_INVALID', 'protocol-v2 candidates require one historical RUNNING basis and one protocol-v2 campaign head')
  assertValidUnleashPlan(plan, {
    registry,
    provider,
    policy: retainedPlanPolicy(plan),
  })
  if (plan.provider_protocol_version !== '2.0.0') {
    fail('UNLEASH_CANDIDATE_PROTOCOL_INVALID', 'protocol-v2 candidate admission requires a protocol-v2 retained plan')
  }
  assertValidUnleashEvidencePacket(evidencePacket)
  assertValidUnleashReconCompletion(completion, { plan })
  assertValidUnleashSwarmBasis(swarmBasis)
  assertValidUnleashSwarmMerge(swarmMerge, { basis: swarmBasis })
  if (swarmCompletion !== null) {
    assertValidUnleashSwarmCompletion(swarmCompletion, { basis: swarmBasis })
  }
  const receipt = completion.completion_receipt
  const counts = routeCounts(plan)
  const commonStateBindingIsExact = basisState.campaign_id === campaignState.campaign_id
    && basisState.plan_sha256 === campaignState.plan_sha256
    && digestUnleashValue(basisState.target) === digestUnleashValue(campaignState.target)
    && basisState.plan_sha256 === plan.plan_sha256
    && digestUnleashValue(basisState.target) === digestUnleashValue(plan.target)
    && digestUnleashValue(basisState.route_counts) === digestUnleashValue(counts)
    && digestUnleashValue(campaignState.route_counts) === digestUnleashValue(counts)
  if (
    !commonStateBindingIsExact
    || campaignState.revision <= basisState.revision
    || Date.parse(campaignState.updated_at) < Date.parse(basisState.updated_at)
    || swarmBasis.campaign_id !== basisState.campaign_id
    || swarmBasis.campaign_state_revision !== basisState.revision
    || swarmBasis.campaign_state_sha256 !== digestUnleashValue(basisState)
    || swarmBasis.plan_sha256 !== plan.plan_sha256
    || swarmBasis.target_id !== plan.target.target_id
    || swarmBasis.registry_sha256 !== digestUnleashValue(registry)
    || swarmBasis.provider_protocol_version !== plan.provider_protocol_version
    || swarmBasis.provider_profile_sha256 !== digestUnleashValue(provider)
    || swarmBasis.evidence_packet_sha256 !== evidencePacket.packet_sha256
    || swarmBasis.completion_receipt_sha256 !== receipt.completion_receipt_sha256
    || swarmMerge.basis_sha256 !== swarmBasis.basis_sha256
    || swarmMerge.plan_sha256 !== plan.plan_sha256
    || digestUnleashValue(completion.evidence_packet) !== digestUnleashValue(evidencePacket)
    || campaignState.swarm_basis_sha256 !== swarmBasis.basis_sha256
    || campaignState.evidence_packet_sha256 !== evidencePacket.packet_sha256
    || campaignState.completion_receipt_sha256 !== receipt.completion_receipt_sha256
    || campaignState.completed_routes.length !== 1
    || campaignState.completed_routes[0] !== receipt.route_id
    || Date.parse(swarmBasis.recorded_at) < Date.parse(evidencePacket.created_at)
    || Date.parse(campaignState.updated_at) < Date.parse(swarmBasis.recorded_at)
  ) fail('UNLEASH_CANDIDATE_SWARM_BINDING_DRIFT', 'protocol-v2 candidate artifacts do not describe one exact swarm basis and campaign')
  if (admitting && (campaignState.status !== 'SWARMING' || swarmCompletion !== null)) {
    fail('UNLEASH_CANDIDATE_SWARM_SEALED', 'candidate admission is closed unless the exact campaign head is unsealed SWARMING')
  }
  if (swarmCompletion === null) {
    if (
      !['SWARMING', 'RECONCILIATION_REQUIRED'].includes(campaignState.status)
      || campaignState.swarm_completion_sha256 !== null
      || campaignState.candidate_frontier_sha256 !== null
      || campaignState.candidate_frontier_head_sha256 !== null
    ) fail('UNLEASH_CANDIDATE_SWARM_STATE_INVALID', 'an unsealed candidate frontier requires a SWARMING or recovery-required campaign head')
  } else {
    const terminalStatusMatches = swarmCompletion.status === 'STOPPED'
      ? campaignState.status === 'STOPPED'
      : ['COMPLETE', 'COMPLETE_WITH_GAPS'].includes(campaignState.status)
    if (
      !terminalStatusMatches
      || campaignState.swarm_completion_sha256 !== swarmCompletion.completion_sha256
      || campaignState.swarm_gap_count !== swarmCompletion.gaps.length
      || Date.parse(campaignState.updated_at) < Date.parse(swarmCompletion.completed_at)
      || swarmCompletion.merge_sha256 !== swarmMerge.merge_sha256
      || swarmCompletion.frontier_sha256 !== swarmMerge.frontier_sha256
      || swarmCompletion.challenge_set_sha256 !== swarmMerge.challenge_set_sha256
      || swarmCompletion.candidate_count !== swarmMerge.candidate_count
      || swarmCompletion.proposed_action_count !== swarmMerge.proposed_action_count
      || swarmCompletion.challenge_count !== swarmMerge.challenge_count
    ) fail('UNLEASH_CANDIDATE_SWARM_SEAL_INVALID', 'sealed candidate recovery requires the exact final swarm merge, completion, and campaign head')
  }
  return value
}

function assertFrontierStateContextV2(value) {
  if (!exactRecord(value, V2_FRONTIER_STATE_CONTEXT_FIELDS)) {
    fail('UNLEASH_CANDIDATE_CONTEXT_INVALID', 'protocol-v2 frontier state requires exact basis, campaign, swarm, and frontier artifacts')
  }
  const {
    basisState,
    campaignState,
    swarmBasis,
    swarmMerge,
    swarmCompletion,
  } = value
  assertValidUnleashCampaignState(basisState)
  assertValidUnleashCampaignState(campaignState)
  assertValidUnleashSwarmBasis(swarmBasis)
  assertValidUnleashSwarmMerge(swarmMerge, { basis: swarmBasis })
  if (swarmCompletion !== null) assertValidUnleashSwarmCompletion(swarmCompletion, { basis: swarmBasis })
  if (
    basisState.schema_version !== '2.0.0'
    || basisState.status !== 'RUNNING'
    || campaignState.schema_version !== '2.0.0'
    || campaignState.campaign_id !== basisState.campaign_id
    || campaignState.plan_sha256 !== basisState.plan_sha256
    || campaignState.target.target_id !== basisState.target.target_id
    || campaignState.revision <= basisState.revision
    || swarmBasis.campaign_id !== basisState.campaign_id
    || swarmBasis.campaign_state_revision !== basisState.revision
    || swarmBasis.campaign_state_sha256 !== digestUnleashValue(basisState)
    || swarmBasis.plan_sha256 !== basisState.plan_sha256
    || swarmBasis.target_id !== basisState.target.target_id
    || swarmMerge.basis_sha256 !== swarmBasis.basis_sha256
    || swarmMerge.plan_sha256 !== basisState.plan_sha256
    || campaignState.swarm_basis_sha256 !== swarmBasis.basis_sha256
    || campaignState.evidence_packet_sha256 !== swarmBasis.evidence_packet_sha256
    || campaignState.completion_receipt_sha256 !== swarmBasis.completion_receipt_sha256
    || Date.parse(campaignState.updated_at) < Date.parse(swarmBasis.recorded_at)
  ) fail('UNLEASH_CANDIDATE_SWARM_BINDING_DRIFT', 'protocol-v2 frontier state context differs from its immutable swarm basis')
  if (swarmCompletion === null) {
    if (
      campaignState.status !== 'SWARMING'
      || campaignState.swarm_completion_sha256 !== null
      || campaignState.candidate_frontier_sha256 !== null
      || campaignState.candidate_frontier_head_sha256 !== null
    ) fail('UNLEASH_CANDIDATE_SWARM_STATE_INVALID', 'unsealed protocol-v2 frontier state requires the exact SWARMING campaign head')
  } else if (
    !(swarmCompletion.status === 'STOPPED'
      ? campaignState.status === 'STOPPED'
      : ['COMPLETE', 'COMPLETE_WITH_GAPS'].includes(campaignState.status))
    || campaignState.swarm_completion_sha256 !== swarmCompletion.completion_sha256
    || campaignState.swarm_gap_count !== swarmCompletion.gaps.length
    || Date.parse(campaignState.updated_at) < Date.parse(swarmCompletion.completed_at)
    || swarmCompletion.merge_sha256 !== swarmMerge.merge_sha256
    || swarmCompletion.frontier_sha256 !== swarmMerge.frontier_sha256
    || swarmCompletion.challenge_set_sha256 !== swarmMerge.challenge_set_sha256
    || swarmCompletion.candidate_count !== swarmMerge.candidate_count
    || swarmCompletion.proposed_action_count !== swarmMerge.proposed_action_count
    || swarmCompletion.challenge_count !== swarmMerge.challenge_count
  ) fail('UNLEASH_CANDIDATE_SWARM_SEAL_INVALID', 'sealed protocol-v2 frontier state requires the exact final swarm merge and completion')
  return value
}

function assertProposal(proposal, context) {
  assertValidUnleashProposal(proposal, {
    plan: context.plan,
    registry: context.registry,
    provider: context.provider,
    policy: retainedPlanPolicy(context.plan),
    completedRouteIds: context.campaignState.completed_routes,
    evidenceReferences: context.evidencePacket.sources.map(({ evidence_ref: evidenceRef }) => evidenceRef),
  })
  return proposal
}

function assertFinalMergedProposalV2(proposal, context) {
  assertProposal(proposal, context)
  if (digestUnleashValue(proposal) !== digestUnleashValue(context.swarmMerge.proposal)) {
    fail('UNLEASH_CANDIDATE_V2_FINAL_MERGE_DRIFT', 'protocol-v2 admission must contain the exact final merged swarm proposal')
  }
  return proposal
}

function assertSchema(value) {
  if (!validateAdmissionSchema(value)) {
    const locations = (validateAdmissionSchema.errors ?? [])
      .slice(0, 8)
      .map(({ instancePath, message }) => `${instancePath || '/'}: ${message ?? 'schema validation failed'}`)
      .join('; ')
    fail('UNLEASH_CANDIDATE_ADMISSION_SCHEMA_INVALID', `candidate admission violates its exact schema; ${locations}`)
  }
}

function assertFrontierStateSchema(value) {
  if (!validateFrontierStateSchema(value)) {
    const locations = (validateFrontierStateSchema.errors ?? [])
      .slice(0, 8)
      .map(({ instancePath, message }) => `${instancePath || '/'}: ${message ?? 'schema validation failed'}`)
      .join('; ')
    fail('UNLEASH_CANDIDATE_FRONTIER_STATE_SCHEMA_INVALID', `candidate frontier state violates its exact schema; ${locations}`)
  }
}

function expectedBindings(context) {
  const { campaignState: state, plan, evidencePacket, completion } = context
  return {
    campaign_id: state.campaign_id,
    campaign_state_revision: state.revision,
    campaign_state_sha256: digestUnleashValue(state),
    plan_sha256: plan.plan_sha256,
    target_id: plan.target.target_id,
    evidence_packet_sha256: evidencePacket.packet_sha256,
    completion_receipt_sha256: completion.completion_receipt.completion_receipt_sha256,
    provider_protocol_version: plan.provider_protocol_version,
    provider_sha256: plan.provider_sha256,
  }
}

function expectedBindingsV2(context) {
  const {
    basisState,
    plan,
    evidencePacket,
    completion,
    swarmBasis,
  } = context
  return {
    campaign_id: basisState.campaign_id,
    campaign_state_revision: basisState.revision,
    campaign_state_sha256: digestUnleashValue(basisState),
    plan_sha256: plan.plan_sha256,
    target_id: plan.target.target_id,
    evidence_packet_sha256: evidencePacket.packet_sha256,
    completion_receipt_sha256: completion.completion_receipt.completion_receipt_sha256,
    provider_protocol_version: plan.provider_protocol_version,
    provider_sha256: plan.provider_sha256,
    swarm_basis_sha256: swarmBasis.basis_sha256,
    swarm_merge_sha256: context.swarmMerge.merge_sha256,
  }
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

function frontierFromUnsigned(unsigned) {
  return frozenCopy({
    ...unsigned,
    frontier_sha256: digestUnleashValue(unsigned),
  })
}

function registerFrontierProvenance(frontier, metadata) {
  frontierProvenance.set(frontier, frozenCopy(metadata))
  return frontier
}

export function createEmptyUnleashCandidateFrontier(input) {
  if (!exactRecord(input, EMPTY_FIELDS)) {
    fail('UNLEASH_CANDIDATE_INPUT_INVALID', 'empty candidate frontier requires one exact plan and campaign state')
  }
  const { plan, campaignState } = input
  assertSelfBoundUnleashPlan(plan)
  assertValidUnleashCampaignState(campaignState)
  if (['COMPLETE', 'COMPLETE_WITH_GAPS'].includes(campaignState.status)) {
    fail('UNLEASH_CANDIDATE_CAMPAIGN_COMPLETE', 'an evidence-complete campaign requires candidate frontier recovery')
  }
  const counts = routeCounts(plan)
  if (
    campaignState.plan_sha256 !== plan.plan_sha256
    || digestUnleashValue(campaignState.target) !== digestUnleashValue(plan.target)
    || digestUnleashValue(campaignState.route_counts) !== digestUnleashValue(counts)
    || campaignState.gap_count !== counts.waiting + counts.unavailable + counts.blocked
  ) fail('UNLEASH_CANDIDATE_CAMPAIGN_DRIFT', 'empty candidate frontier state differs from its retained plan')
  return registerFrontierProvenance(frontierFromUnsigned({
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-candidate-frontier',
    campaign_id: campaignState.campaign_id,
    plan_sha256: plan.plan_sha256,
    target_id: plan.target.target_id,
    campaign_state_revision: campaignState.revision,
    campaign_state_sha256: digestUnleashValue(campaignState),
    evidence_packet_sha256: null,
    completion_receipt_sha256: null,
    proposal_count: 0,
    candidate_count: 0,
    proposed_action_count: 0,
    head_admission_sha256: null,
    candidates: [],
    actions: [],
  }), { proposal_ids: [], admission_heads: [] })
}

function frontierBindingsV2(context) {
  const bindings = expectedBindingsV2(context)
  return {
    campaign_id: bindings.campaign_id,
    plan_sha256: bindings.plan_sha256,
    target_id: bindings.target_id,
    campaign_state_revision: bindings.campaign_state_revision,
    campaign_state_sha256: bindings.campaign_state_sha256,
    evidence_packet_sha256: bindings.evidence_packet_sha256,
    completion_receipt_sha256: bindings.completion_receipt_sha256,
  }
}

export function createEmptyUnleashCandidateFrontierV2(input) {
  if (!exactRecord(input, V2_EMPTY_FIELDS)) {
    fail('UNLEASH_CANDIDATE_INPUT_INVALID', 'empty protocol-v2 candidate frontier requires exact basis, campaign, swarm, and evidence artifacts')
  }
  const context = { ...input, previousAdmission: null }
  assertContextV2(context)
  const frontier = materializeFrontier(frontierBindingsV2(context), createProjectionAccumulator(), {
    schemaVersion: '2.0.0',
    swarmBasisSha256: context.swarmBasis.basis_sha256,
    swarmMergeSha256: context.swarmMerge.merge_sha256,
  })
  assertFrontierProjectionV2(frontier, context)
  campaignChainProvenance.set(input.campaignState, requireFrontierProvenance(frontier))
  return frontier
}

function assertAdmissionEnvelope(value) {
  const snapshot = frozenCopy(safeCanonicalCopy(value, 'candidate admission'))
  assertSchema(snapshot)
  if (
    snapshot.proposal_id !== snapshot.proposal.proposal_id
    || snapshot.plan_sha256 !== snapshot.proposal.plan_sha256
    || snapshot.provider_protocol_version !== snapshot.proposal.provider_protocol_version
    || snapshot.proposal_sha256 !== digestUnleashValue(snapshot.proposal)
    || snapshot.candidate_count !== snapshot.proposal.candidates.length
    || snapshot.proposed_action_count !== snapshot.proposal.actions.length
  ) fail('UNLEASH_CANDIDATE_PROPOSAL_DRIFT', 'candidate admission differs from its exact provider proposal')
  assertCanonicalTimestamp(snapshot.recorded_at, 'recorded_at')
  const candidateIds = new Set(snapshot.proposal.candidates.map(({ candidate_id: id }) => id))
  if (snapshot.proposal.actions.some(({ candidate_id: candidateId }) => !candidateIds.has(candidateId))) {
    fail('UNLEASH_CANDIDATE_PROPOSAL_DRIFT', 'candidate admission contains an action without its candidate')
  }
  const { admission_sha256: admissionSha256, ...unsigned } = snapshot
  if (!SHA256.test(admissionSha256) || admissionSha256 !== digestUnleashValue(unsigned)) {
    fail('UNLEASH_CANDIDATE_DIGEST_DRIFT', 'candidate admission digest does not match its exact content')
  }
  return snapshot
}

function assertAdmissionBody(value, context) {
  const snapshot = assertAdmissionEnvelope(value)
  if (snapshot.schema_version !== '1.0.0' || Object.hasOwn(snapshot, 'swarm_basis_sha256')) {
    fail('UNLEASH_CANDIDATE_PROTOCOL_INVALID', 'protocol-v1 admission validation cannot accept a protocol-v2 record')
  }
  const retained = assertContext(context)
  assertProposal(snapshot.proposal, retained)
  const bindings = expectedBindings(retained)
  if (BINDING_FIELDS.some((field) => snapshot[field] !== bindings[field])) {
    fail('UNLEASH_CANDIDATE_BINDING_DRIFT', 'candidate admission differs from its campaign, target, plan, provider, or evidence')
  }
  if (
    Date.parse(snapshot.recorded_at) < Date.parse(retained.campaignState.updated_at)
    || Date.parse(snapshot.recorded_at) < Date.parse(retained.evidencePacket.created_at)
  ) fail('UNLEASH_CANDIDATE_TIME_INVALID', 'candidate admission cannot predate its campaign evidence')
  return snapshot
}

function assertAdmissionBodyV2(value, context) {
  const snapshot = assertAdmissionEnvelope(value)
  if (snapshot.schema_version !== '2.0.0' || !Object.hasOwn(snapshot, 'swarm_basis_sha256')) {
    fail('UNLEASH_CANDIDATE_PROTOCOL_INVALID', 'protocol-v2 admission validation requires a strict protocol-v2 record')
  }
  const retained = assertContextV2(context)
  assertFinalMergedProposalV2(snapshot.proposal, retained)
  const bindings = expectedBindingsV2(retained)
  if (V2_BINDING_FIELDS.some((field) => snapshot[field] !== bindings[field])) {
    fail('UNLEASH_CANDIDATE_BINDING_DRIFT', 'protocol-v2 admission differs from its basis, campaign, target, plan, provider, or evidence')
  }
  if (
    Date.parse(snapshot.recorded_at) < Date.parse(retained.swarmBasis.recorded_at)
    || Date.parse(snapshot.recorded_at) < Date.parse(retained.evidencePacket.created_at)
    || (retained.swarmCompletion !== null
      && Date.parse(snapshot.recorded_at) > Date.parse(retained.swarmCompletion.completed_at))
  ) fail('UNLEASH_CANDIDATE_TIME_INVALID', 'protocol-v2 admission must fall within its exact unsealed swarm interval')
  return snapshot
}

function assertPreviousAdmission(value, previous, context, {
  assertBody = assertAdmissionBody,
  bindingFields = BINDING_FIELDS,
} = {}) {
  if (previous === null) {
    if (value.sequence !== 1 || value.previous_admission_sha256 !== null) {
      fail('UNLEASH_CANDIDATE_CHAIN_INVALID', 'the first candidate admission must start sequence 1 without a predecessor')
    }
    return
  }
  const snapshot = assertBody(previous, { ...context, previousAdmission: null })
  const previousSha256 = snapshot.admission_sha256
  const campaignChain = campaignChainProvenance.get(context.campaignState)
  const retainedHead = campaignChain?.admission_heads[snapshot.sequence - 1]
  const positionIsProven = campaignChain === undefined
    ? trustedAdmissions.has(previous)
    : (
      retainedHead?.sequence === snapshot.sequence
      && retainedHead.admission_sha256 === previousSha256
    )
  if (
    (snapshot.sequence === 1 && snapshot.previous_admission_sha256 !== null)
    || (snapshot.sequence > 1 && !positionIsProven)
    || value.sequence !== snapshot.sequence + 1
    || value.previous_admission_sha256 !== previousSha256
    || Date.parse(value.recorded_at) < Date.parse(snapshot.recorded_at)
    || bindingFields.some((field) => value[field] !== snapshot[field])
  ) fail('UNLEASH_CANDIDATE_CHAIN_INVALID', 'candidate admission does not extend the exact preceding chain head')
}

export function assertValidUnleashCandidateAdmission(value, context) {
  validatedAdmissionSnapshot(value, context)
  return value
}

function validatedAdmissionSnapshot(value, context) {
  const snapshot = assertAdmissionBody(value, context)
  assertPreviousAdmission(snapshot, context.previousAdmission, context)
  trustedAdmissions.add(snapshot)
  return snapshot
}

export function createUnleashCandidateAdmission(input) {
  if (!exactRecord(input, CREATE_FIELDS)) {
    fail('UNLEASH_CANDIDATE_INPUT_INVALID', 'candidate admission input contains missing or unexpected fields')
  }
  const context = Object.fromEntries(CONTEXT_FIELDS.map((field) => [field, input[field]]))
  assertContext(context)
  assertProposal(input.proposal, context)
  if (!Number.isSafeInteger(input.sequence)
    || input.sequence < 1
    || input.sequence > UNLEASH_CANDIDATE_FRONTIER_LIMITS.max_admissions) {
    fail('UNLEASH_CANDIDATE_SEQUENCE_INVALID', 'candidate admission sequence exceeds its fixed bounds')
  }
  const proposal = snapshotUnleashProviderProposal(input.proposal)
  const unsigned = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-candidate-admission',
    sequence: input.sequence,
    recorded_at: recordedAt(input.recordedAt),
    ...expectedBindings(context),
    proposal_id: proposal.proposal_id,
    proposal_sha256: digestUnleashValue(proposal),
    previous_admission_sha256: input.previousAdmission?.admission_sha256 ?? null,
    candidate_count: proposal.candidates.length,
    proposed_action_count: proposal.actions.length,
    disposition: {
      candidate_state: 'CANDIDATE',
      provider_authentication: 'UNVERIFIED',
      semantic_authority: 'NONE',
      proof_authority: 'NONE',
      actions_executable: false,
    },
    proposal,
  }
  const admission = {
    ...unsigned,
    admission_sha256: digestUnleashValue(unsigned),
  }
  safeCanonicalCopy(admission, 'candidate admission')
  assertValidUnleashCandidateAdmission(admission, context)
  const frozen = frozenCopy(admission)
  trustedAdmissions.add(frozen)
  return frozen
}

function validatedAdmissionSnapshotV2(value, context) {
  const snapshot = assertAdmissionBodyV2(value, context)
  assertPreviousAdmission(snapshot, context.previousAdmission, context, {
    assertBody: assertAdmissionBodyV2,
    bindingFields: V2_BINDING_FIELDS,
  })
  trustedAdmissions.add(snapshot)
  return snapshot
}

export function assertValidUnleashCandidateAdmissionV2(value, context) {
  validatedAdmissionSnapshotV2(value, context)
  return value
}

export function createUnleashCandidateAdmissionV2(input) {
  if (!exactRecord(input, V2_CREATE_FIELDS)) {
    fail('UNLEASH_CANDIDATE_INPUT_INVALID', 'protocol-v2 candidate admission input contains missing or unexpected fields')
  }
  const context = Object.fromEntries(V2_CONTEXT_FIELDS.map((field) => [field, input[field]]))
  assertContextV2(context, { admitting: true })
  assertFinalMergedProposalV2(input.proposal, context)
  if (input.sequence !== 1 || input.previousAdmission !== null) {
    fail('UNLEASH_CANDIDATE_V2_FINAL_ALREADY_ADMITTED', 'protocol-v2 admits exactly one final merged proposal at sequence 1')
  }
  const proposal = snapshotUnleashProviderProposal(input.proposal)
  const unsigned = {
    schema_version: '2.0.0',
    kind: 'last-aperture/unleash-candidate-admission',
    sequence: input.sequence,
    recorded_at: recordedAt(input.recordedAt),
    ...expectedBindingsV2(context),
    proposal_id: proposal.proposal_id,
    proposal_sha256: digestUnleashValue(proposal),
    previous_admission_sha256: input.previousAdmission?.admission_sha256 ?? null,
    candidate_count: proposal.candidates.length,
    proposed_action_count: proposal.actions.length,
    disposition: {
      candidate_state: 'CANDIDATE',
      provider_authentication: 'UNVERIFIED',
      semantic_authority: 'NONE',
      proof_authority: 'NONE',
      actions_executable: false,
    },
    proposal,
  }
  const admission = {
    ...unsigned,
    admission_sha256: digestUnleashValue(unsigned),
  }
  safeCanonicalCopy(admission, 'protocol-v2 candidate admission')
  assertValidUnleashCandidateAdmissionV2(admission, context)
  const frozen = frozenCopy(admission)
  trustedAdmissions.add(frozen)
  return frozen
}

function assertStorage(storage) {
  if (
    storage === null
    || typeof storage !== 'object'
    || typeof storage.readJson !== 'function'
    || typeof storage.listJsonFilenames !== 'function'
  ) fail('UNLEASH_CANDIDATE_STORAGE_INVALID', 'candidate frontier storage is unavailable')
  return storage
}

function compareIds(left, right) {
  return left < right ? -1 : left > right ? 1 : 0
}

function candidateProjection(candidate, admission, proposedActionIds) {
  const unsigned = {
    candidate_id: candidate.candidate_id,
    state: 'CANDIDATE',
    proposal_id: admission.proposal_id,
    proposal_sha256: admission.proposal_sha256,
    admission_sha256: admission.admission_sha256,
    title: candidate.title,
    hypothesis: candidate.hypothesis,
    invariant: candidate.invariant,
    provider_confidence: candidate.confidence,
    evidence_refs: [...candidate.evidence_refs].sort(compareIds),
    competing_explanations: [...candidate.competing_explanations].sort(compareIds),
    proposed_action_ids: [...proposedActionIds].sort(compareIds),
  }
  return { ...unsigned, candidate_sha256: digestUnleashValue(unsigned) }
}

function actionProjection(action, admission) {
  const unsigned = {
    action_id: action.action_id,
    state: 'PROPOSED_INERT',
    candidate_id: action.candidate_id,
    proposal_id: admission.proposal_id,
    proposal_sha256: admission.proposal_sha256,
    admission_sha256: admission.admission_sha256,
    tool_id: action.tool_id,
    evidence_refs: [...action.evidence_refs].sort(compareIds),
    parameters: structuredClone(action.parameters),
    expected_observation: action.expected_observation,
    executable: false,
  }
  return { ...unsigned, action_sha256: digestUnleashValue(unsigned) }
}

function digestWithout(value, field) {
  const unsigned = { ...value }
  delete unsigned[field]
  return digestUnleashValue(unsigned)
}

function sortedUniqueStrings(value) {
  if (!Array.isArray(value)) return false
  let previous = null
  for (const item of value) {
    if (typeof item !== 'string' || (previous !== null && item <= previous)) return false
    previous = item
  }
  return true
}

function assertCandidateProjection(candidate) {
  if (
    !exactRecord(candidate, CANDIDATE_FIELDS)
    || candidate.state !== 'CANDIDATE'
    || typeof candidate.candidate_id !== 'string'
    || typeof candidate.proposal_id !== 'string'
    || !SHA256.test(candidate.proposal_sha256)
    || !SHA256.test(candidate.admission_sha256)
    || typeof candidate.title !== 'string'
    || typeof candidate.hypothesis !== 'string'
    || typeof candidate.invariant !== 'string'
    || !['LOW', 'MEDIUM', 'HIGH'].includes(candidate.provider_confidence)
    || !sortedUniqueStrings(candidate.evidence_refs)
    || !sortedUniqueStrings(candidate.competing_explanations)
    || !sortedUniqueStrings(candidate.proposed_action_ids)
    || candidate.candidate_sha256 !== digestWithout(candidate, 'candidate_sha256')
  ) fail('UNLEASH_CANDIDATE_FRONTIER_INVALID', 'candidate frontier contains an invalid or unbound candidate projection')
}

function assertActionProjection(action) {
  if (
    !exactRecord(action, ACTION_FIELDS)
    || action.state !== 'PROPOSED_INERT'
    || typeof action.action_id !== 'string'
    || typeof action.candidate_id !== 'string'
    || typeof action.proposal_id !== 'string'
    || !SHA256.test(action.proposal_sha256)
    || !SHA256.test(action.admission_sha256)
    || typeof action.tool_id !== 'string'
    || !sortedUniqueStrings(action.evidence_refs)
    || action.parameters === null
    || typeof action.parameters !== 'object'
    || Array.isArray(action.parameters)
    || typeof action.expected_observation !== 'string'
    || action.executable !== false
    || action.action_sha256 !== digestWithout(action, 'action_sha256')
  ) fail('UNLEASH_CANDIDATE_FRONTIER_INVALID', 'candidate frontier contains an invalid or executable action projection')
}

function assertFrontierProjection(value, campaignState = null) {
  digestUnleashValue(value)
  if (
    !exactRecord(value, FRONTIER_FIELDS)
    || value.schema_version !== '1.0.0'
    || value.kind !== 'last-aperture/unleash-candidate-frontier'
    || typeof value.campaign_id !== 'string'
    || !SHA256.test(value.plan_sha256)
    || typeof value.target_id !== 'string'
    || !Number.isSafeInteger(value.campaign_state_revision)
    || !SHA256.test(value.campaign_state_sha256)
    || ![null, 'string'].includes(value.evidence_packet_sha256 === null ? null : typeof value.evidence_packet_sha256)
    || (value.evidence_packet_sha256 !== null && !SHA256.test(value.evidence_packet_sha256))
    || ![null, 'string'].includes(value.completion_receipt_sha256 === null ? null : typeof value.completion_receipt_sha256)
    || (value.completion_receipt_sha256 !== null && !SHA256.test(value.completion_receipt_sha256))
    || !Number.isSafeInteger(value.proposal_count)
    || value.proposal_count < 0
    || value.proposal_count > UNLEASH_CANDIDATE_FRONTIER_LIMITS.max_admissions
    || !Number.isSafeInteger(value.candidate_count)
    || value.candidate_count < 0
    || value.candidate_count > UNLEASH_CANDIDATE_FRONTIER_LIMITS.max_candidates
    || !Number.isSafeInteger(value.proposed_action_count)
    || value.proposed_action_count < 0
    || value.proposed_action_count > UNLEASH_CANDIDATE_FRONTIER_LIMITS.max_proposed_actions
    || !Array.isArray(value.candidates)
    || !Array.isArray(value.actions)
    || value.candidate_count !== value.candidates.length
    || value.proposed_action_count !== value.actions.length
    || (value.proposal_count === 0) !== (value.head_admission_sha256 === null)
    || (value.head_admission_sha256 !== null && !SHA256.test(value.head_admission_sha256))
    || value.frontier_sha256 !== digestWithout(value, 'frontier_sha256')
  ) fail('UNLEASH_CANDIDATE_FRONTIER_INVALID', 'candidate frontier is malformed or not self-bound')
  if (campaignState !== null) {
    assertValidUnleashCampaignState(campaignState)
    if (
      value.campaign_id !== campaignState.campaign_id
      || value.plan_sha256 !== campaignState.plan_sha256
      || value.target_id !== campaignState.target.target_id
      || value.campaign_state_revision !== campaignState.revision
      || value.campaign_state_sha256 !== digestUnleashValue(campaignState)
      || value.evidence_packet_sha256 !== campaignState.evidence_packet_sha256
      || value.completion_receipt_sha256 !== campaignState.completion_receipt_sha256
    ) fail('UNLEASH_CANDIDATE_FRONTIER_BINDING_DRIFT', 'candidate frontier differs from its retained campaign state')
  }
  assertFrontierProjectionItems(value)
  return value
}

function assertFrontierProjectionItems(value) {
  const candidates = new Map()
  const actions = new Map()
  for (const candidate of value.candidates) {
    assertCandidateProjection(candidate)
    if (candidates.has(candidate.candidate_id)) {
      fail('UNLEASH_CANDIDATE_ID_COLLISION', `candidate ID is repeated: ${candidate.candidate_id}`)
    }
    candidates.set(candidate.candidate_id, candidate)
  }
  for (const action of value.actions) {
    assertActionProjection(action)
    if (actions.has(action.action_id)) {
      fail('UNLEASH_CANDIDATE_ACTION_COLLISION', `proposed action ID is repeated: ${action.action_id}`)
    }
    actions.set(action.action_id, action)
  }
  if (
    !sortedUniqueStrings([...candidates.keys()])
    || !sortedUniqueStrings([...actions.keys()])
  ) fail('UNLEASH_CANDIDATE_FRONTIER_INVALID', 'candidate frontier projections are not in canonical ID order')
  for (const candidate of candidates.values()) {
    for (const actionId of candidate.proposed_action_ids) {
      const action = actions.get(actionId)
      if (
        action?.candidate_id !== candidate.candidate_id
        || action.proposal_id !== candidate.proposal_id
        || action.proposal_sha256 !== candidate.proposal_sha256
        || action.admission_sha256 !== candidate.admission_sha256
      ) fail('UNLEASH_CANDIDATE_FRONTIER_INVALID', `candidate ${candidate.candidate_id} references an unbound action`)
    }
  }
  for (const action of actions.values()) {
    if (!candidates.get(action.candidate_id)?.proposed_action_ids.includes(action.action_id)) {
      fail('UNLEASH_CANDIDATE_FRONTIER_INVALID', `proposed action ${action.action_id} is not bound back to its candidate`)
    }
  }
}

function assertFrontierProjectionV2(value, context = null) {
  digestUnleashValue(value)
  if (
    !exactRecord(value, V2_FRONTIER_FIELDS)
    || value.schema_version !== '2.0.0'
    || value.kind !== 'last-aperture/unleash-candidate-frontier'
    || typeof value.campaign_id !== 'string'
    || !SHA256.test(value.plan_sha256)
    || typeof value.target_id !== 'string'
    || !Number.isSafeInteger(value.campaign_state_revision)
    || !SHA256.test(value.campaign_state_sha256)
    || !SHA256.test(value.evidence_packet_sha256)
    || !SHA256.test(value.completion_receipt_sha256)
    || !SHA256.test(value.swarm_basis_sha256)
    || !SHA256.test(value.swarm_merge_sha256)
    || !Number.isSafeInteger(value.proposal_count)
    || value.proposal_count < 0
    || value.proposal_count > 1
    || !Number.isSafeInteger(value.candidate_count)
    || value.candidate_count < 0
    || value.candidate_count > UNLEASH_CANDIDATE_FRONTIER_LIMITS.max_candidates
    || !Number.isSafeInteger(value.proposed_action_count)
    || value.proposed_action_count < 0
    || value.proposed_action_count > UNLEASH_CANDIDATE_FRONTIER_LIMITS.max_proposed_actions
    || !Array.isArray(value.candidates)
    || !Array.isArray(value.actions)
    || value.candidate_count !== value.candidates.length
    || value.proposed_action_count !== value.actions.length
    || (value.proposal_count === 0) !== (value.head_admission_sha256 === null)
    || (value.head_admission_sha256 !== null && !SHA256.test(value.head_admission_sha256))
    || value.frontier_sha256 !== digestWithout(value, 'frontier_sha256')
  ) fail('UNLEASH_CANDIDATE_FRONTIER_INVALID', 'protocol-v2 candidate frontier is malformed or not self-bound')
  if (context !== null) {
    const isAdmissionContext = exactRecord(context, V2_CONTEXT_FIELDS)
    const retained = isAdmissionContext
      ? assertContextV2(context)
      : assertFrontierStateContextV2(context)
    const bindings = isAdmissionContext
      ? expectedBindingsV2(retained)
      : {
          campaign_id: retained.basisState.campaign_id,
          campaign_state_revision: retained.basisState.revision,
          campaign_state_sha256: digestUnleashValue(retained.basisState),
          plan_sha256: retained.basisState.plan_sha256,
          target_id: retained.basisState.target.target_id,
          evidence_packet_sha256: retained.swarmBasis.evidence_packet_sha256,
           completion_receipt_sha256: retained.swarmBasis.completion_receipt_sha256,
           swarm_basis_sha256: retained.swarmBasis.basis_sha256,
           swarm_merge_sha256: retained.swarmMerge.merge_sha256,
         }
    if (
      value.campaign_id !== bindings.campaign_id
      || value.plan_sha256 !== bindings.plan_sha256
      || value.target_id !== bindings.target_id
      || value.campaign_state_revision !== bindings.campaign_state_revision
      || value.campaign_state_sha256 !== bindings.campaign_state_sha256
      || value.evidence_packet_sha256 !== bindings.evidence_packet_sha256
      || value.completion_receipt_sha256 !== bindings.completion_receipt_sha256
      || value.swarm_basis_sha256 !== bindings.swarm_basis_sha256
      || value.swarm_merge_sha256 !== bindings.swarm_merge_sha256
    ) fail('UNLEASH_CANDIDATE_FRONTIER_BINDING_DRIFT', 'protocol-v2 candidate frontier differs from its immutable swarm basis')
    if (retained.swarmCompletion !== null && value.proposal_count !== 1) {
      fail('UNLEASH_CANDIDATE_V2_FINAL_MISSING', 'a sealed protocol-v2 swarm requires exactly one final merged proposal admission')
    }
    if (retained.swarmCompletion !== null && (
      retained.campaignState.candidate_frontier_sha256 !== value.frontier_sha256
      || retained.campaignState.candidate_frontier_head_sha256 !== value.head_admission_sha256
      || retained.swarmCompletion.candidate_count !== value.candidate_count
      || retained.swarmCompletion.proposed_action_count !== value.proposed_action_count
    )) fail('UNLEASH_CANDIDATE_SWARM_SEAL_INVALID', 'terminal campaign state or swarm completion differs from the recovered candidate frontier')
  }
  assertFrontierProjectionItems(value)
  return value
}

function requireFrontierProvenance(frontier) {
  const provenance = frontierProvenance.get(frontier)
  if (provenance === undefined) {
    fail('UNLEASH_CANDIDATE_FRONTIER_PROVENANCE_MISSING', 'candidate frontier lacks its validated admission provenance')
  }
  return provenance
}

export function getUnleashCandidateFrontierAdmissionReferences(input) {
  if (!exactRecord(input, PROVENANCE_FIELDS)) {
    fail('UNLEASH_CANDIDATE_INPUT_INVALID', 'candidate frontier provenance lookup requires one exact frontier')
  }
  if (input.frontier?.schema_version === '2.0.0') assertFrontierProjectionV2(input.frontier)
  else assertFrontierProjection(input.frontier)
  return frozenCopy(requireFrontierProvenance(input.frontier).admission_heads)
}

function createProjectionAccumulator(frontier = null) {
  const provenance = frontier === null
    ? { proposal_ids: [], admission_heads: [] }
    : requireFrontierProvenance(frontier)
  const candidates = frontier === null ? [] : frontier.candidates.map((candidate) => structuredClone(candidate))
  const actions = frontier === null ? [] : frontier.actions.map((action) => structuredClone(action))
  return {
    proposalCount: frontier?.proposal_count ?? 0,
    candidateCount: frontier?.candidate_count ?? 0,
    actionCount: frontier?.proposed_action_count ?? 0,
    headAdmissionSha256: frontier?.head_admission_sha256 ?? null,
    proposalIds: new Set(provenance.proposal_ids),
    candidateIds: new Set(candidates.map(({ candidate_id: id }) => id)),
    actionIds: new Set(actions.map(({ action_id: id }) => id)),
    admissionHeads: provenance.admission_heads.map((head) => structuredClone(head)),
    candidates,
    actions,
  }
}

function historicalFrontierAt(frontier, proposalCount) {
  const provenance = requireFrontierProvenance(frontier)
  const head = provenance.admission_heads[proposalCount - 1]
  if (head?.sequence !== proposalCount) {
    fail('UNLEASH_CANDIDATE_FRONTIER_ANCESTRY_INVALID', 'candidate frontier provenance does not contain the retained sequence')
  }
  const admitted = new Set(
    provenance.admission_heads
      .slice(0, proposalCount)
      .map(({ admission_sha256: admissionSha256 }) => admissionSha256),
  )
  const candidates = frontier.candidates
    .filter(({ admission_sha256: admissionSha256 }) => admitted.has(admissionSha256))
    .map((candidate) => structuredClone(candidate))
  const actions = frontier.actions
    .filter(({ admission_sha256: admissionSha256 }) => admitted.has(admissionSha256))
    .map((action) => structuredClone(action))
  if (candidates.length !== head.candidate_count || actions.length !== head.proposed_action_count) {
    fail('UNLEASH_CANDIDATE_FRONTIER_ANCESTRY_INVALID', 'candidate frontier provenance counts do not reconstruct its retained prefix')
  }
  const isV2 = frontier.schema_version === '2.0.0'
  const bindings = Object.fromEntries(FRONTIER_FIELDS
    .slice(2, 9)
    .map((field) => [field, frontier[field]]))
  return frontierFromUnsigned({
    schema_version: isV2 ? '2.0.0' : '1.0.0',
    kind: 'last-aperture/unleash-candidate-frontier',
    ...bindings,
    ...(isV2
      ? {
          swarm_basis_sha256: frontier.swarm_basis_sha256,
          swarm_merge_sha256: frontier.swarm_merge_sha256,
        }
      : {}),
    proposal_count: proposalCount,
    candidate_count: candidates.length,
    proposed_action_count: actions.length,
    head_admission_sha256: head.admission_sha256,
    candidates,
    actions,
  })
}

function appendProjectedAdmission(accumulator, admission) {
  if (
    admission.sequence !== accumulator.proposalCount + 1
    || admission.previous_admission_sha256 !== accumulator.headAdmissionSha256
  ) fail('UNLEASH_CANDIDATE_CHAIN_INVALID', 'candidate admission does not extend the exact projection accumulator head')
  if (accumulator.proposalIds.has(admission.proposal_id)) {
    fail('UNLEASH_CANDIDATE_PROPOSAL_COLLISION', `candidate proposal ID is repeated: ${admission.proposal_id}`)
  }
  accumulator.proposalIds.add(admission.proposal_id)
  const actionIdsByCandidate = new Map(admission.proposal.candidates.map(({ candidate_id: id }) => [id, []]))
  for (const action of admission.proposal.actions) {
    if (accumulator.actionIds.has(action.action_id)) {
      fail('UNLEASH_CANDIDATE_ACTION_COLLISION', `proposed action ID is repeated: ${action.action_id}`)
    }
    const candidateActions = actionIdsByCandidate.get(action.candidate_id)
    if (candidateActions === undefined) {
      fail('UNLEASH_CANDIDATE_PROPOSAL_DRIFT', `proposed action references an unknown candidate: ${action.candidate_id}`)
    }
    accumulator.actionIds.add(action.action_id)
    candidateActions.push(action.action_id)
    accumulator.actions.push(actionProjection(action, admission))
  }
  for (const candidate of admission.proposal.candidates) {
    if (accumulator.candidateIds.has(candidate.candidate_id)) {
      fail('UNLEASH_CANDIDATE_ID_COLLISION', `candidate ID is repeated: ${candidate.candidate_id}`)
    }
    accumulator.candidateIds.add(candidate.candidate_id)
    accumulator.candidates.push(candidateProjection(
      candidate,
      admission,
      actionIdsByCandidate.get(candidate.candidate_id),
    ))
  }
  accumulator.proposalCount += 1
  accumulator.candidateCount += admission.candidate_count
  accumulator.actionCount += admission.proposed_action_count
  accumulator.headAdmissionSha256 = admission.admission_sha256
  if (
    accumulator.proposalCount > UNLEASH_CANDIDATE_FRONTIER_LIMITS.max_admissions
    || accumulator.candidateCount > UNLEASH_CANDIDATE_FRONTIER_LIMITS.max_candidates
    || accumulator.actionCount > UNLEASH_CANDIDATE_FRONTIER_LIMITS.max_proposed_actions
  ) fail('UNLEASH_CANDIDATE_FRONTIER_BOUNDS', 'candidate frontier exceeds its cumulative admission, candidate, or action bound')
  accumulator.admissionHeads.push({
    sequence: admission.sequence,
    admission_sha256: admission.admission_sha256,
    proposal_id: admission.proposal_id,
    proposal_sha256: admission.proposal_sha256,
    candidate_count: accumulator.candidateCount,
    proposed_action_count: accumulator.actionCount,
  })
}

function materializeFrontier(bindings, accumulator, {
  schemaVersion = '1.0.0',
  swarmBasisSha256 = null,
  swarmMergeSha256 = null,
} = {}) {
  accumulator.candidates.sort((left, right) => compareIds(left.candidate_id, right.candidate_id))
  accumulator.actions.sort((left, right) => compareIds(left.action_id, right.action_id))
  try {
    const frontier = frontierFromUnsigned({
      schema_version: schemaVersion,
      kind: 'last-aperture/unleash-candidate-frontier',
      ...bindings,
      ...(schemaVersion === '2.0.0'
        ? {
            swarm_basis_sha256: swarmBasisSha256,
            swarm_merge_sha256: swarmMergeSha256,
          }
        : {}),
      proposal_count: accumulator.proposalCount,
      candidate_count: accumulator.candidateCount,
      proposed_action_count: accumulator.actionCount,
      head_admission_sha256: accumulator.headAdmissionSha256,
      candidates: accumulator.candidates,
      actions: accumulator.actions,
    })
    return registerFrontierProvenance(frontier, {
      proposal_ids: [...accumulator.proposalIds].sort(compareIds),
      admission_heads: accumulator.admissionHeads,
    })
  } catch (cause) {
    fail('UNLEASH_CANDIDATE_FRONTIER_BOUNDS', 'candidate frontier exceeds its canonical aggregate bound', cause)
  }
}

export function previewUnleashCandidateFrontierAppend(input) {
  if (!exactRecord(input, PREVIEW_FIELDS)) {
    fail('UNLEASH_CANDIDATE_INPUT_INVALID', 'candidate frontier preview requires one exact frontier and admission')
  }
  assertFrontierProjection(input.frontier)
  if (!trustedAdmissions.has(input.admission)) {
    fail('UNLEASH_CANDIDATE_ADMISSION_PROVENANCE_MISSING', 'candidate frontier preview requires a context-validated admission')
  }
  const admission = assertAdmissionEnvelope(input.admission)
  const bindingPairs = [
    ['campaign_id', 'campaign_id'],
    ['campaign_state_revision', 'campaign_state_revision'],
    ['campaign_state_sha256', 'campaign_state_sha256'],
    ['plan_sha256', 'plan_sha256'],
    ['target_id', 'target_id'],
    ['evidence_packet_sha256', 'evidence_packet_sha256'],
    ['completion_receipt_sha256', 'completion_receipt_sha256'],
  ]
  if (
    bindingPairs.some(([admissionField, frontierField]) => admission[admissionField] !== input.frontier[frontierField])
    || admission.sequence !== input.frontier.proposal_count + 1
    || admission.previous_admission_sha256 !== input.frontier.head_admission_sha256
  ) fail('UNLEASH_CANDIDATE_CHAIN_INVALID', 'candidate admission does not extend the exact projected frontier head')
  const accumulator = createProjectionAccumulator(input.frontier)
  appendProjectedAdmission(accumulator, admission)
  const bindings = Object.fromEntries(FRONTIER_FIELDS
    .slice(2, 9)
    .map((field) => [field, input.frontier[field]]))
  const preview = materializeFrontier(bindings, accumulator)
  assertFrontierProjection(preview)
  return preview
}

export function previewUnleashCandidateFrontierAppendV2(input) {
  if (!exactRecord(input, V2_PREVIEW_FIELDS)) {
    fail('UNLEASH_CANDIDATE_INPUT_INVALID', 'protocol-v2 candidate frontier preview requires exact frontier, admission, campaign head, and seal')
  }
  assertFrontierProjectionV2(input.frontier)
  assertValidUnleashCampaignState(input.campaignState)
  if (
    input.campaignState.schema_version !== '2.0.0'
    || input.campaignState.status !== 'SWARMING'
    || input.campaignState.campaign_id !== input.frontier.campaign_id
    || input.campaignState.plan_sha256 !== input.frontier.plan_sha256
    || input.campaignState.target.target_id !== input.frontier.target_id
    || input.campaignState.swarm_basis_sha256 !== input.frontier.swarm_basis_sha256
    || input.swarmCompletion !== null
  ) fail('UNLEASH_CANDIDATE_SWARM_SEALED', 'protocol-v2 candidate append requires the exact unsealed SWARMING campaign head')
  if (input.frontier.proposal_count !== 0) {
    fail('UNLEASH_CANDIDATE_V2_FINAL_ALREADY_ADMITTED', 'protocol-v2 candidate frontier already contains its one final merged proposal')
  }
  assertValidUnleashSwarmMerge(input.swarmMerge)
  if (
    input.swarmMerge.basis_sha256 !== input.frontier.swarm_basis_sha256
    || input.swarmMerge.merge_sha256 !== input.frontier.swarm_merge_sha256
  ) fail('UNLEASH_CANDIDATE_V2_FINAL_MERGE_DRIFT', 'protocol-v2 append differs from the frontier final swarm merge')
  if (!trustedAdmissions.has(input.admission)) {
    fail('UNLEASH_CANDIDATE_ADMISSION_PROVENANCE_MISSING', 'protocol-v2 candidate frontier preview requires a context-validated admission')
  }
  const admission = assertAdmissionEnvelope(input.admission)
  if (
    admission.schema_version !== '2.0.0'
    || admission.campaign_id !== input.frontier.campaign_id
    || admission.campaign_state_revision !== input.frontier.campaign_state_revision
    || admission.campaign_state_sha256 !== input.frontier.campaign_state_sha256
    || admission.plan_sha256 !== input.frontier.plan_sha256
    || admission.target_id !== input.frontier.target_id
    || admission.evidence_packet_sha256 !== input.frontier.evidence_packet_sha256
    || admission.completion_receipt_sha256 !== input.frontier.completion_receipt_sha256
    || admission.swarm_basis_sha256 !== input.frontier.swarm_basis_sha256
    || admission.swarm_merge_sha256 !== input.frontier.swarm_merge_sha256
    || digestUnleashValue(admission.proposal) !== digestUnleashValue(input.swarmMerge.proposal)
    || admission.sequence !== input.frontier.proposal_count + 1
    || admission.previous_admission_sha256 !== input.frontier.head_admission_sha256
  ) fail('UNLEASH_CANDIDATE_CHAIN_INVALID', 'protocol-v2 admission does not extend the exact projected swarm frontier head')
  const accumulator = createProjectionAccumulator(input.frontier)
  appendProjectedAdmission(accumulator, admission)
  const bindings = Object.fromEntries(FRONTIER_FIELDS
    .slice(2, 9)
    .map((field) => [field, input.frontier[field]]))
  const preview = materializeFrontier(bindings, accumulator, {
    schemaVersion: '2.0.0',
    swarmBasisSha256: input.frontier.swarm_basis_sha256,
    swarmMergeSha256: input.frontier.swarm_merge_sha256,
  })
  assertFrontierProjectionV2(preview)
  return preview
}

function expectedFrontierStateBindings(frontier, campaignState) {
  return {
    campaign_id: campaignState.campaign_id,
    campaign_state_revision: campaignState.revision,
    campaign_state_sha256: digestUnleashValue(campaignState),
    plan_sha256: campaignState.plan_sha256,
    target_id: campaignState.target.target_id,
    evidence_packet_sha256: campaignState.evidence_packet_sha256,
    completion_receipt_sha256: campaignState.completion_receipt_sha256,
    proposal_count: frontier.proposal_count,
    candidate_count: frontier.candidate_count,
    proposed_action_count: frontier.proposed_action_count,
    head_admission_sha256: frontier.head_admission_sha256,
    frontier_sha256: frontier.frontier_sha256,
  }
}

function assertFrontierStateEnvelope(value, campaignState) {
  const snapshot = frozenCopy(safeCanonicalCopy(value, 'candidate frontier state'))
  assertFrontierStateSchema(snapshot)
  if (
    snapshot.schema_version !== '1.0.0'
    || Object.hasOwn(snapshot, 'swarm_basis_sha256')
    || Object.hasOwn(snapshot, 'swarm_merge_sha256')
    || Object.hasOwn(snapshot, 'swarm_completion_sha256')
  ) fail('UNLEASH_CANDIDATE_PROTOCOL_INVALID', 'protocol-v1 frontier state cannot accept a protocol-v2 record')
  assertValidUnleashCampaignState(campaignState)
  assertCanonicalTimestamp(snapshot.updated_at, 'candidate frontier state updated_at')
  if (
    snapshot.campaign_id !== campaignState.campaign_id
    || snapshot.campaign_state_revision !== campaignState.revision
    || snapshot.campaign_state_sha256 !== digestUnleashValue(campaignState)
    || snapshot.plan_sha256 !== campaignState.plan_sha256
    || snapshot.target_id !== campaignState.target.target_id
    || snapshot.evidence_packet_sha256 !== campaignState.evidence_packet_sha256
    || snapshot.completion_receipt_sha256 !== campaignState.completion_receipt_sha256
  ) fail('UNLEASH_CANDIDATE_FRONTIER_STATE_BINDING_DRIFT', 'candidate frontier state differs from its retained campaign state')
  if (Date.parse(snapshot.updated_at) < Date.parse(campaignState.updated_at)) {
    fail('UNLEASH_CANDIDATE_TIME_INVALID', 'candidate frontier state cannot predate its retained campaign state')
  }
  const { frontier_state_sha256: frontierStateSha256, ...unsigned } = snapshot
  if (frontierStateSha256 !== digestUnleashValue(unsigned)) {
    fail('UNLEASH_CANDIDATE_FRONTIER_STATE_DIGEST_DRIFT', 'candidate frontier state digest does not match its exact content')
  }
  return snapshot
}

export function createUnleashCandidateFrontierState(input) {
  if (!exactRecord(input, CREATE_FRONTIER_STATE_FIELDS)) {
    fail('UNLEASH_CANDIDATE_INPUT_INVALID', 'candidate frontier state requires one exact frontier, campaign state, and timestamp')
  }
  assertFrontierProjection(input.frontier, input.campaignState)
  if (input.frontier.proposal_count === 0) {
    fail('UNLEASH_CANDIDATE_FRONTIER_STATE_EMPTY', 'a zero-admission frontier does not require retained head state')
  }
  const updatedAt = recordedAt(input.recordedAt)
  if (Date.parse(updatedAt) < Date.parse(input.campaignState.updated_at)) {
    fail('UNLEASH_CANDIDATE_TIME_INVALID', 'candidate frontier state cannot predate its retained campaign state')
  }
  const unsigned = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-candidate-frontier-state',
    updated_at: updatedAt,
    ...expectedFrontierStateBindings(input.frontier, input.campaignState),
  }
  const state = frozenCopy({
    ...unsigned,
    frontier_state_sha256: digestUnleashValue(unsigned),
  })
  assertValidUnleashCandidateFrontierState(state, {
    frontier: input.frontier,
    campaignState: input.campaignState,
  })
  return state
}

export function assertValidUnleashCandidateFrontierState(value, context) {
  if (!exactRecord(context, FRONTIER_STATE_CONTEXT_FIELDS)) {
    fail('UNLEASH_CANDIDATE_INPUT_INVALID', 'candidate frontier state validation requires one exact frontier and campaign state')
  }
  assertFrontierProjection(context.frontier, context.campaignState)
  const snapshot = assertFrontierStateEnvelope(value, context.campaignState)
  const bindings = expectedFrontierStateBindings(context.frontier, context.campaignState)
  if (Object.entries(bindings).some(([field, expected]) => snapshot[field] !== expected)) {
    fail('UNLEASH_CANDIDATE_FRONTIER_STATE_MISMATCH', 'candidate frontier state differs from the exact recovered frontier')
  }
  return value
}

export function reconcileUnleashCandidateFrontierState(input) {
  if (!exactRecord(input, RECONCILE_FRONTIER_STATE_FIELDS)) {
    fail('UNLEASH_CANDIDATE_INPUT_INVALID', 'candidate frontier state reconciliation requires exact retained inputs')
  }
  assertFrontierProjection(input.frontier, input.campaignState)
  requireFrontierProvenance(input.frontier)
  if (input.retainedState === null) {
    if (input.frontier.proposal_count === 0) {
      return frozenCopy({ status: 'CURRENT', frontier_state: null })
    }
    return frozenCopy({
      status: 'PUBLICATION_REQUIRED',
      frontier_state: createUnleashCandidateFrontierState({
        frontier: input.frontier,
        campaignState: input.campaignState,
        recordedAt: input.recordedAt,
      }),
    })
  }
  const retained = assertFrontierStateEnvelope(input.retainedState, input.campaignState)
  if (
    retained.proposal_count > input.frontier.proposal_count
    || retained.candidate_count > input.frontier.candidate_count
    || retained.proposed_action_count > input.frontier.proposed_action_count
  ) fail('UNLEASH_CANDIDATE_FRONTIER_TRUNCATED', 'retained candidate frontier state is ahead of the recovered admission chain')
  if (retained.proposal_count === input.frontier.proposal_count) {
    assertValidUnleashCandidateFrontierState(retained, {
      frontier: input.frontier,
      campaignState: input.campaignState,
    })
    return frozenCopy({ status: 'CURRENT', frontier_state: retained })
  }
  const retainedPrefix = historicalFrontierAt(input.frontier, retained.proposal_count)
  if (
    retained.head_admission_sha256 !== retainedPrefix.head_admission_sha256
    || retained.candidate_count !== retainedPrefix.candidate_count
    || retained.proposed_action_count !== retainedPrefix.proposed_action_count
    || retained.frontier_sha256 !== retainedPrefix.frontier_sha256
    || Date.parse(recordedAt(input.recordedAt)) < Date.parse(retained.updated_at)
  ) fail('UNLEASH_CANDIDATE_FRONTIER_ANCESTRY_INVALID', 'stale candidate frontier state is not an exact ancestor of the recovered chain')
  return frozenCopy({
    status: 'REPAIR_REQUIRED',
    frontier_state: createUnleashCandidateFrontierState({
      frontier: input.frontier,
      campaignState: input.campaignState,
      recordedAt: input.recordedAt,
    }),
  })
}

function expectedFrontierStateBindingsV2(context) {
  const {
    frontier,
    basisState,
    swarmBasis,
    swarmCompletion,
  } = context
  return {
    campaign_id: basisState.campaign_id,
    campaign_state_revision: basisState.revision,
    campaign_state_sha256: digestUnleashValue(basisState),
    plan_sha256: basisState.plan_sha256,
    target_id: basisState.target.target_id,
    evidence_packet_sha256: frontier.evidence_packet_sha256,
    completion_receipt_sha256: frontier.completion_receipt_sha256,
    swarm_basis_sha256: swarmBasis.basis_sha256,
    swarm_merge_sha256: context.swarmMerge.merge_sha256,
    swarm_completion_sha256: swarmCompletion?.completion_sha256 ?? null,
    proposal_count: frontier.proposal_count,
    candidate_count: frontier.candidate_count,
    proposed_action_count: frontier.proposed_action_count,
    head_admission_sha256: frontier.head_admission_sha256,
    frontier_sha256: frontier.frontier_sha256,
  }
}

function assertFrontierStateEnvelopeV2(value, context, { allowPriorUnsealed = false } = {}) {
  const snapshot = frozenCopy(safeCanonicalCopy(value, 'protocol-v2 candidate frontier state'))
  assertFrontierStateSchema(snapshot)
  if (snapshot.schema_version !== '2.0.0') {
    fail('UNLEASH_CANDIDATE_PROTOCOL_INVALID', 'protocol-v2 frontier state requires a strict protocol-v2 record')
  }
  const retained = assertFrontierStateContextV2(context)
  assertCanonicalTimestamp(snapshot.updated_at, 'protocol-v2 candidate frontier state updated_at')
  const completionSha256 = retained.swarmCompletion?.completion_sha256 ?? null
  if (
    snapshot.campaign_id !== retained.basisState.campaign_id
    || snapshot.campaign_state_revision !== retained.basisState.revision
    || snapshot.campaign_state_sha256 !== digestUnleashValue(retained.basisState)
    || snapshot.plan_sha256 !== retained.basisState.plan_sha256
    || snapshot.target_id !== retained.basisState.target.target_id
    || snapshot.evidence_packet_sha256 !== retained.swarmBasis.evidence_packet_sha256
    || snapshot.completion_receipt_sha256 !== retained.swarmBasis.completion_receipt_sha256
    || snapshot.swarm_basis_sha256 !== retained.swarmBasis.basis_sha256
    || snapshot.swarm_merge_sha256 !== retained.swarmMerge.merge_sha256
    || (snapshot.swarm_completion_sha256 !== completionSha256
      && !(allowPriorUnsealed && snapshot.swarm_completion_sha256 === null && completionSha256 !== null))
  ) fail('UNLEASH_CANDIDATE_FRONTIER_STATE_BINDING_DRIFT', 'protocol-v2 frontier state differs from its immutable swarm basis or seal')
  if (
    Date.parse(snapshot.updated_at) < Date.parse(retained.swarmBasis.recorded_at)
    || (snapshot.swarm_completion_sha256 !== null
      && Date.parse(snapshot.updated_at) < Date.parse(retained.swarmCompletion.completed_at))
  ) fail('UNLEASH_CANDIDATE_TIME_INVALID', 'protocol-v2 frontier state cannot predate its swarm basis or seal')
  const { frontier_state_sha256: frontierStateSha256, ...unsigned } = snapshot
  if (frontierStateSha256 !== digestUnleashValue(unsigned)) {
    fail('UNLEASH_CANDIDATE_FRONTIER_STATE_DIGEST_DRIFT', 'protocol-v2 frontier state digest does not match its exact content')
  }
  return snapshot
}

export function createUnleashCandidateFrontierStateV2(input) {
  if (!exactRecord(input, V2_CREATE_FRONTIER_STATE_FIELDS)) {
    fail('UNLEASH_CANDIDATE_INPUT_INVALID', 'protocol-v2 frontier state requires exact basis, campaign, swarm, frontier, and timestamp inputs')
  }
  const context = Object.fromEntries(V2_FRONTIER_STATE_CONTEXT_FIELDS.map((field) => [field, input[field]]))
  assertFrontierProjectionV2(input.frontier, context)
  if (input.frontier.proposal_count === 0 && input.swarmCompletion === null) {
    fail('UNLEASH_CANDIDATE_FRONTIER_STATE_EMPTY', 'an unsealed zero-admission protocol-v2 frontier does not require retained head state')
  }
  const updatedAt = recordedAt(input.recordedAt)
  if (
    Date.parse(updatedAt) < Date.parse(input.swarmBasis.recorded_at)
    || (input.swarmCompletion !== null
      && Date.parse(updatedAt) < Date.parse(input.swarmCompletion.completed_at))
  ) fail('UNLEASH_CANDIDATE_TIME_INVALID', 'protocol-v2 frontier state cannot predate its swarm basis or seal')
  const unsigned = {
    schema_version: '2.0.0',
    kind: 'last-aperture/unleash-candidate-frontier-state',
    updated_at: updatedAt,
    ...expectedFrontierStateBindingsV2(context),
  }
  const state = frozenCopy({
    ...unsigned,
    frontier_state_sha256: digestUnleashValue(unsigned),
  })
  assertValidUnleashCandidateFrontierStateV2(state, context)
  return state
}

export function assertValidUnleashCandidateFrontierStateV2(value, context) {
  if (!exactRecord(context, V2_FRONTIER_STATE_CONTEXT_FIELDS)) {
    fail('UNLEASH_CANDIDATE_INPUT_INVALID', 'protocol-v2 frontier state validation requires exact basis, campaign, swarm, and frontier inputs')
  }
  assertFrontierProjectionV2(context.frontier, context)
  const snapshot = assertFrontierStateEnvelopeV2(value, context)
  const bindings = expectedFrontierStateBindingsV2(context)
  if (Object.entries(bindings).some(([field, expected]) => snapshot[field] !== expected)) {
    fail('UNLEASH_CANDIDATE_FRONTIER_STATE_MISMATCH', 'protocol-v2 frontier state differs from the exact recovered frontier or swarm seal')
  }
  return value
}

export function reconcileUnleashCandidateFrontierStateV2(input) {
  if (!exactRecord(input, V2_RECONCILE_FRONTIER_STATE_FIELDS)) {
    fail('UNLEASH_CANDIDATE_INPUT_INVALID', 'protocol-v2 frontier reconciliation requires exact retained basis, campaign, swarm, and frontier inputs')
  }
  const context = Object.fromEntries(V2_FRONTIER_STATE_CONTEXT_FIELDS.map((field) => [field, input[field]]))
  assertFrontierProjectionV2(input.frontier, context)
  requireFrontierProvenance(input.frontier)
  const desiredStatus = input.swarmCompletion === null ? 'PUBLICATION_REQUIRED' : 'SEAL_REQUIRED'
  if (input.retainedState === null) {
    if (input.frontier.proposal_count === 0 && input.swarmCompletion === null) {
      return frozenCopy({ status: 'CURRENT', frontier_state: null })
    }
    return frozenCopy({
      status: desiredStatus,
      frontier_state: createUnleashCandidateFrontierStateV2({ ...context, recordedAt: input.recordedAt }),
    })
  }
  const retained = assertFrontierStateEnvelopeV2(input.retainedState, context, {
    allowPriorUnsealed: true,
  })
  if (retained.swarm_completion_sha256 !== null && (
    retained.proposal_count !== input.frontier.proposal_count
    || retained.candidate_count !== input.frontier.candidate_count
    || retained.proposed_action_count !== input.frontier.proposed_action_count
    || retained.head_admission_sha256 !== input.frontier.head_admission_sha256
    || retained.frontier_sha256 !== input.frontier.frontier_sha256
  )) fail('UNLEASH_CANDIDATE_SWARM_SEALED', 'a sealed protocol-v2 candidate frontier cannot be advanced or replaced')
  if (
    retained.proposal_count > input.frontier.proposal_count
    || retained.candidate_count > input.frontier.candidate_count
    || retained.proposed_action_count > input.frontier.proposed_action_count
  ) fail('UNLEASH_CANDIDATE_FRONTIER_TRUNCATED', 'retained protocol-v2 frontier state is ahead of the recovered admission chain')
  const sealChanged = retained.swarm_completion_sha256 === null && input.swarmCompletion !== null
  if (retained.proposal_count === input.frontier.proposal_count) {
    if (
      retained.candidate_count !== input.frontier.candidate_count
      || retained.proposed_action_count !== input.frontier.proposed_action_count
      || retained.head_admission_sha256 !== input.frontier.head_admission_sha256
      || retained.frontier_sha256 !== input.frontier.frontier_sha256
    ) fail('UNLEASH_CANDIDATE_FRONTIER_STATE_MISMATCH', 'protocol-v2 frontier state differs from the exact recovered frontier')
    if (!sealChanged) {
      assertValidUnleashCandidateFrontierStateV2(retained, context)
      return frozenCopy({ status: 'CURRENT', frontier_state: retained })
    }
    return frozenCopy({
      status: 'SEAL_REQUIRED',
      frontier_state: createUnleashCandidateFrontierStateV2({ ...context, recordedAt: input.recordedAt }),
    })
  }
  const retainedPrefix = historicalFrontierAt(input.frontier, retained.proposal_count)
  if (
    retained.head_admission_sha256 !== retainedPrefix.head_admission_sha256
    || retained.candidate_count !== retainedPrefix.candidate_count
    || retained.proposed_action_count !== retainedPrefix.proposed_action_count
    || retained.frontier_sha256 !== retainedPrefix.frontier_sha256
    || Date.parse(recordedAt(input.recordedAt)) < Date.parse(retained.updated_at)
  ) fail('UNLEASH_CANDIDATE_FRONTIER_ANCESTRY_INVALID', 'stale protocol-v2 frontier state is not an exact ancestor of the recovered chain')
  return frozenCopy({
    status: input.swarmCompletion === null ? 'REPAIR_REQUIRED' : 'SEAL_REQUIRED',
    frontier_state: createUnleashCandidateFrontierStateV2({ ...context, recordedAt: input.recordedAt }),
  })
}

function emptyFrontierBindings(context) {
  const bindings = expectedBindings(context)
  return {
    campaign_id: bindings.campaign_id,
    plan_sha256: bindings.plan_sha256,
    target_id: bindings.target_id,
    campaign_state_revision: bindings.campaign_state_revision,
    campaign_state_sha256: bindings.campaign_state_sha256,
    evidence_packet_sha256: bindings.evidence_packet_sha256,
    completion_receipt_sha256: bindings.completion_receipt_sha256,
  }
}

function snapshotRecoveryContext(input) {
  const labels = {
    plan: 'retained plan',
    registry: 'retained registry',
    provider: 'retained provider',
    campaignState: 'retained campaign state',
    evidencePacket: 'retained evidence packet',
    completion: 'retained completion',
  }
  const entries = Object.entries(labels).map(([field, label]) => [
    field,
    frozenCopy(safeCanonicalCopy(input[field], label)),
  ])
  return Object.freeze({ ...Object.fromEntries(entries), previousAdmission: null })
}

function snapshotRecoveryContextV2(input) {
  const labels = {
    plan: 'retained protocol-v2 plan',
    registry: 'retained protocol-v2 registry',
    provider: 'retained protocol-v2 provider',
    basisState: 'retained swarm basis state',
    campaignState: 'retained protocol-v2 campaign head',
    evidencePacket: 'retained protocol-v2 evidence packet',
    completion: 'retained protocol-v2 recon completion',
    swarmBasis: 'retained swarm basis',
    swarmMerge: 'retained final swarm merge',
    swarmCompletion: 'retained swarm completion',
  }
  const entries = Object.entries(labels).map(([field, label]) => [
    field,
    frozenCopy(safeCanonicalCopy(input[field], label)),
  ])
  return Object.freeze({ ...Object.fromEntries(entries), previousAdmission: null })
}

function parseAdmissionInventory(value) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    fail('UNLEASH_CANDIDATE_STORAGE_INVALID', 'candidate frontier inventory is invalid')
  }
  const descriptors = Object.getOwnPropertyDescriptors(value)
  if (
    !Number.isSafeInteger(value.length)
    || value.length > MAX_CAMPAIGN_JSON_FILES
    || Reflect.ownKeys(descriptors).length !== value.length + 1
  ) fail('UNLEASH_CANDIDATE_INVENTORY_INVALID', 'candidate frontier inventory exceeds its fixed bound or is sparse')
  const admissions = []
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)]
    if (
      descriptor === undefined
      || !descriptor.enumerable
      || !Object.hasOwn(descriptor, 'value')
      || typeof descriptor.value !== 'string'
    ) fail('UNLEASH_CANDIDATE_INVENTORY_INVALID', 'candidate frontier inventory contains a computed or non-filename value')
    const filename = descriptor.value
    const match = ADMISSION_FILENAME.exec(filename)
    if (match) admissions.push({ filename, sequence: Number.parseInt(match[1], 10) })
    else if (filename.startsWith('candidate-admission-')) {
      fail('UNLEASH_CANDIDATE_INVENTORY_INVALID', `candidate admission filename is malformed: ${filename}`)
    }
  }
  if (admissions.length > UNLEASH_CANDIDATE_FRONTIER_LIMITS.max_admissions) {
    fail('UNLEASH_CANDIDATE_FRONTIER_BOUNDS', 'candidate admission chain exceeds its fixed bound')
  }
  admissions.sort((left, right) => left.sequence - right.sequence)
  for (const [index, descriptor] of admissions.entries()) {
    const expectedSequence = index + 1
    if (
      descriptor.sequence !== expectedSequence
      || descriptor.filename !== `candidate-admission-${String(expectedSequence).padStart(6, '0')}.json`
    ) fail('UNLEASH_CANDIDATE_CHAIN_GAP', `candidate admission chain is gapped at sequence ${expectedSequence}`)
  }
  return admissions
}

function sameAdmissionInventory(left, right) {
  return left.length === right.length
    && left.every((descriptor, index) => descriptor.filename === right[index].filename)
}

async function assertAdmissionContentsUnchanged(
  storage,
  descriptors,
  contentDigests,
  context,
  validator = validatedAdmissionSnapshot,
) {
  let previous = null
  for (const [index, descriptor] of descriptors.entries()) {
    const replayed = validator(
      await storage.readJson(descriptor.filename),
      { ...context, previousAdmission: previous },
    )
    if (digestUnleashValue(replayed) !== contentDigests[index]) {
      fail('UNLEASH_CANDIDATE_FRONTIER_CHANGED', `candidate admission changed while the frontier was recovered: ${descriptor.filename}`)
    }
    previous = replayed
  }
}

export async function recoverUnleashCandidateFrontier(input) {
  if (!exactRecord(input, RECOVER_FIELDS)) {
    fail('UNLEASH_CANDIDATE_INPUT_INVALID', 'candidate frontier recovery requires exact storage and campaign artifacts')
  }
  const storage = assertStorage(input.storage)
  const context = snapshotRecoveryContext(input)
  assertContext(context)
  const descriptors = parseAdmissionInventory(await storage.listJsonFilenames())

  let previous = null
  const accumulator = createProjectionAccumulator()
  const admissionContentDigests = []
  for (const descriptor of descriptors) {
    const admission = validatedAdmissionSnapshot(
      await storage.readJson(descriptor.filename),
      { ...context, previousAdmission: previous },
    )
    admissionContentDigests.push(digestUnleashValue(admission))
    appendProjectedAdmission(accumulator, admission)
    previous = admission
  }
  const frontier = materializeFrontier(emptyFrontierBindings(context), accumulator)
  const middleDescriptors = parseAdmissionInventory(await storage.listJsonFilenames())
  if (!sameAdmissionInventory(descriptors, middleDescriptors)) {
    fail('UNLEASH_CANDIDATE_FRONTIER_CHANGED', 'candidate admission inventory changed while the frontier was recovered')
  }
  await assertAdmissionContentsUnchanged(storage, descriptors, admissionContentDigests, context)
  const finalDescriptors = parseAdmissionInventory(await storage.listJsonFilenames())
  if (!sameAdmissionInventory(descriptors, finalDescriptors)) {
    fail('UNLEASH_CANDIDATE_FRONTIER_CHANGED', 'candidate admission inventory changed while the frontier was recovered')
  }
  await assertAdmissionContentsUnchanged(storage, descriptors, admissionContentDigests, context)
  campaignChainProvenance.set(input.campaignState, requireFrontierProvenance(frontier))
  assertFrontierProjection(frontier, context.campaignState)
  return frontier
}

export async function recoverUnleashCandidateFrontierV2(input) {
  if (!exactRecord(input, V2_RECOVER_FIELDS)) {
    fail('UNLEASH_CANDIDATE_INPUT_INVALID', 'protocol-v2 candidate recovery requires exact storage, basis, campaign, swarm, and evidence artifacts')
  }
  const storage = assertStorage(input.storage)
  const context = snapshotRecoveryContextV2(input)
  assertContextV2(context)
  const descriptors = parseAdmissionInventory(await storage.listJsonFilenames())
  if (descriptors.length > 1) {
    fail('UNLEASH_CANDIDATE_V2_FINAL_ALREADY_ADMITTED', 'protocol-v2 recovery found more than one final merged proposal admission')
  }
  if (context.swarmCompletion !== null && descriptors.length !== 1) {
    fail('UNLEASH_CANDIDATE_V2_FINAL_MISSING', 'sealed protocol-v2 recovery requires exactly one final merged proposal admission')
  }
  let previous = null
  const accumulator = createProjectionAccumulator()
  const admissionContentDigests = []
  for (const descriptor of descriptors) {
    const admission = validatedAdmissionSnapshotV2(
      await storage.readJson(descriptor.filename),
      { ...context, previousAdmission: previous },
    )
    admissionContentDigests.push(digestUnleashValue(admission))
    appendProjectedAdmission(accumulator, admission)
    previous = admission
  }
  const frontier = materializeFrontier(frontierBindingsV2(context), accumulator, {
    schemaVersion: '2.0.0',
    swarmBasisSha256: context.swarmBasis.basis_sha256,
    swarmMergeSha256: context.swarmMerge.merge_sha256,
  })
  const middleDescriptors = parseAdmissionInventory(await storage.listJsonFilenames())
  if (!sameAdmissionInventory(descriptors, middleDescriptors)) {
    fail('UNLEASH_CANDIDATE_FRONTIER_CHANGED', 'protocol-v2 candidate admission inventory changed during recovery')
  }
  await assertAdmissionContentsUnchanged(
    storage,
    descriptors,
    admissionContentDigests,
    context,
    validatedAdmissionSnapshotV2,
  )
  const finalDescriptors = parseAdmissionInventory(await storage.listJsonFilenames())
  if (!sameAdmissionInventory(descriptors, finalDescriptors)) {
    fail('UNLEASH_CANDIDATE_FRONTIER_CHANGED', 'protocol-v2 candidate admission inventory changed during recovery')
  }
  await assertAdmissionContentsUnchanged(
    storage,
    descriptors,
    admissionContentDigests,
    context,
    validatedAdmissionSnapshotV2,
  )
  campaignChainProvenance.set(input.campaignState, requireFrontierProvenance(frontier))
  assertFrontierProjectionV2(frontier, context)
  return frontier
}
