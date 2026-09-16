import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import Ajv2020 from 'ajv/dist/2020.js'

import {
  assertSelfBoundUnleashPlan,
  digestUnleashValue,
} from './unleash-contracts.mjs'
import {
  assertUnleashCampaignStateTransition,
  assertValidUnleashCampaignState,
} from './unleash-campaign-state.mjs'
import { UNLEASH_ACTION_RISK_DETECTION_PATTERN_MODEL } from './unleash-action-risk-assessment.mjs'
import { canonicalUnleashCampaignJson } from './unleash-campaign-storage.mjs'
import {
  assertValidUnleashSwarmBasis,
  assertValidUnleashSwarmCompletion,
} from './unleash-swarm-contracts.mjs'
import { assertValidUnleashSwarmMerge } from './unleash-swarm-merge.mjs'

const SCHEMA_URL = new URL('../../schemas/unleash-snapshot.schema.json', import.meta.url)
export const unleashSnapshotSchema = JSON.parse(readFileSync(fileURLToPath(SCHEMA_URL), 'utf8'))

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})
const validateSnapshotSchema = ajv.compile(unleashSnapshotSchema)

const INPUT_FIELDS = ['capturedAt', 'frontier', 'plan', 'registry', 'state', 'stateEvents']
const INPUT_FIELDS_WITH_DETECTION = [...INPUT_FIELDS, 'detection']
const V2_INPUT_FIELDS = [
  'basisState', 'capturedAt', 'frontier', 'plan', 'registry', 'state',
  'stateEvents', 'swarmBasis', 'swarmCompletion', 'swarmMerge',
]
const V2_INPUT_FIELDS_WITH_DETECTION = [...V2_INPUT_FIELDS, 'detection']
const V2_INPUT_FIELDS_WITH_CONTROL = [...V2_INPUT_FIELDS, 'campaignControl']
const V2_INPUT_FIELDS_WITH_DETECTION_AND_CONTROL = [
  ...V2_INPUT_FIELDS, 'detection', 'campaignControl',
]
const EVENT_FIELDS = [
  'schema_version', 'kind', 'revision', 'recorded_at', 'previous_state_sha256',
  'state_sha256', 'state',
]
const FRONTIER_FIELDS = [
  'schema_version', 'kind', 'campaign_id', 'plan_sha256', 'target_id',
  'campaign_state_revision', 'campaign_state_sha256', 'evidence_packet_sha256',
  'completion_receipt_sha256', 'proposal_count', 'candidate_count',
  'proposed_action_count', 'head_admission_sha256', 'candidates', 'actions',
  'frontier_sha256',
]
const V2_FRONTIER_FIELDS = [...FRONTIER_FIELDS, 'swarm_basis_sha256', 'swarm_merge_sha256']
const CANDIDATE_FIELDS = [
  'candidate_id', 'state', 'candidate_sha256', 'proposal_id', 'proposal_sha256',
  'admission_sha256', 'title', 'hypothesis', 'invariant', 'provider_confidence',
  'evidence_refs', 'competing_explanations', 'proposed_action_ids',
]
const ACTION_FIELDS = [
  'action_id', 'state', 'action_sha256', 'candidate_id', 'proposal_id',
  'proposal_sha256', 'admission_sha256', 'tool_id', 'evidence_refs', 'parameters',
  'expected_observation', 'executable',
]
const SNAPSHOT_V2_FIELDS = [
  'swarm_basis_sha256', 'swarm_completion_sha256', 'candidate_frontier_sha256',
  'candidate_frontier_head_sha256', 'swarm_gap_count', 'swarm',
]
const SNAPSHOT_V2_BINDING_FIELDS = [
  'basis_state_revision', 'basis_state_sha256', 'swarm_basis_sha256',
  'swarm_merge_sha256', 'swarm_completion_sha256', 'swarm_frontier_sha256',
  'swarm_challenge_set_sha256', 'swarm_hypothesis_view_sha256',
  'swarm_action_view_sha256', 'swarm_challenge_view_sha256', 'swarm_gap_view_sha256',
]
const ROUTE_DISPOSITIONS = new Set([
  'READY', 'WAITING_FOR_MATERIAL', 'WAITING_FOR_DEPENDENCY', 'UNAVAILABLE',
  'NOT_APPLICABLE', 'BLOCKED_BY_POLICY',
])
const PLAN_GAPS = new Set([
  'WAITING_FOR_MATERIAL', 'WAITING_FOR_DEPENDENCY', 'UNAVAILABLE',
  'BLOCKED_BY_POLICY',
])
const TERMINAL = new Set([
  'COMPLETE', 'COMPLETE_WITH_GAPS', 'STOPPED', 'OUTCOME_UNCERTAIN', 'FAILED',
])
const RUNTIME_GAP = new Set([
  'STOPPED', 'OUTCOME_UNCERTAIN', 'FAILED', 'RECONCILIATION_REQUIRED',
])
const SHA256 = /^[a-f0-9]{64}$/u
const ID = /^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,159}$/u
const EVIDENCE_REF = /^evidence:sha256:[a-f0-9]{64}$/u
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u
const MAX_ITEMS = 4096

export class UnleashSnapshotError extends Error {
  constructor(code, message, details = []) {
    super(message)
    this.name = 'UnleashSnapshotError'
    this.code = code
    this.details = details
  }
}

function fail(code, message, details = []) {
  throw new UnleashSnapshotError(code, message, details)
}

function exactRecord(value, fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  try {
    if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) return false
    const descriptors = Object.getOwnPropertyDescriptors(value)
    const keys = Reflect.ownKeys(descriptors)
    return keys.length === fields.length
      && keys.every((key) => typeof key === 'string'
        && fields.includes(key)
        && descriptors[key].enumerable
        && Object.hasOwn(descriptors[key], 'value'))
  } catch {
    return false
  }
}

function deeplyFrozenCopy(value) {
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
    fail('UNLEASH_SNAPSHOT_VALUE_INVALID', `${label} must be bounded canonical plain JSON`, [cause?.code ?? 'UNKNOWN'])
  }
}

function canonicalTimestamp(value, label) {
  if (
    typeof value !== 'string'
    || !TIMESTAMP.test(value)
    || Number.isNaN(Date.parse(value))
    || new Date(value).toISOString() !== value
  ) fail('UNLEASH_SNAPSHOT_TIME_INVALID', `${label} must be one canonical UTC millisecond timestamp`)
  return value
}

function digestWithout(value, field) {
  const { [field]: _omitted, ...unsigned } = value
  return digestUnleashValue(unsigned)
}

function sameValue(left, right) {
  return digestUnleashValue(left) === digestUnleashValue(right)
}

function canonicalOrder(left, right) {
  if (left === right) return 0
  return left < right ? -1 : 1
}

function isSortedUnique(values) {
  return values.every((value, index) => index === 0 || canonicalOrder(values[index - 1], value) < 0)
}

function assertStringArray(value, { pattern = ID, maximum = MAX_ITEMS } = {}) {
  return Array.isArray(value)
    && value.length <= maximum
    && value.every((item) => typeof item === 'string' && pattern.test(item))
    && isSortedUnique(value)
}

function assertEvents(stateEvents, expectedState) {
  if (!Array.isArray(stateEvents) || stateEvents.length < 1 || stateEvents.length > MAX_ITEMS) {
    fail('UNLEASH_SNAPSHOT_EVENT_INVALID', 'snapshot state events must be one bounded non-empty array')
  }
  let previous = null
  const timeline = []
  for (const [index, event] of stateEvents.entries()) {
    const revision = index + 1
    if (
      !exactRecord(event, EVENT_FIELDS)
      || event.schema_version !== '1.0.0'
      || event.kind !== 'last-aperture/unleash-campaign-event'
      || event.revision !== revision
      || event.recorded_at !== event.state?.updated_at
      || event.state?.revision !== revision
      || event.state_sha256 !== digestUnleashValue(event.state)
      || event.previous_state_sha256 !== (previous === null ? null : digestUnleashValue(previous))
    ) fail('UNLEASH_SNAPSHOT_EVENT_INVALID', `campaign event ${revision} is not exactly bound to its state-chain position`)
    canonicalTimestamp(event.recorded_at, `campaign event ${revision} recorded_at`)
    try {
      assertUnleashCampaignStateTransition(previous, event.state)
    } catch (cause) {
      fail('UNLEASH_SNAPSHOT_EVENT_INVALID', `campaign event ${revision} contains an invalid state transition`, [cause?.code ?? 'UNKNOWN'])
    }
    previous = event.state
    timeline.push({
      revision,
      recorded_at: event.recorded_at,
      previous_state_sha256: event.previous_state_sha256,
      state_sha256: event.state_sha256,
      status: event.state.status,
      completed_routes: [...event.state.completed_routes],
      stop_reason: event.state.stop_reason,
      failure: structuredClone(event.state.failure),
    })
  }
  if (!sameValue(previous, expectedState)) {
    fail('UNLEASH_SNAPSHOT_HEAD_DRIFT', 'snapshot state differs from the verified event-chain head')
  }
  return timeline
}

function expectedRouteCounts(plan) {
  const counts = { total: plan.route_dispositions.length, ready: 0, waiting: 0, unavailable: 0, not_applicable: 0, blocked: 0 }
  for (const route of plan.route_dispositions) {
    if (route.disposition === 'READY') counts.ready += 1
    else if (route.disposition === 'WAITING_FOR_MATERIAL' || route.disposition === 'WAITING_FOR_DEPENDENCY') counts.waiting += 1
    else if (route.disposition === 'UNAVAILABLE') counts.unavailable += 1
    else if (route.disposition === 'NOT_APPLICABLE') counts.not_applicable += 1
    else if (route.disposition === 'BLOCKED_BY_POLICY') counts.blocked += 1
    else fail('UNLEASH_SNAPSHOT_PLAN_INVALID', `route ${route.route_id} has an unknown disposition`)
  }
  return counts
}

function assertPlanStateBinding(plan, state) {
  try {
    assertSelfBoundUnleashPlan(plan)
    assertValidUnleashCampaignState(state)
  } catch (cause) {
    fail('UNLEASH_SNAPSHOT_PLAN_INVALID', 'snapshot plan or campaign state is invalid', [cause?.code ?? 'UNKNOWN'])
  }
  const counts = expectedRouteCounts(plan)
  const routeById = new Map(plan.route_dispositions.map((route) => [route.route_id, route]))
  if (
    state.plan_sha256 !== plan.plan_sha256
    || !sameValue(state.target, plan.target)
    || !sameValue(state.route_counts, counts)
    || state.gap_count !== counts.waiting + counts.unavailable + counts.blocked
    || state.completed_routes.some((routeId) => routeById.get(routeId)?.disposition !== 'READY')
  ) fail('UNLEASH_SNAPSHOT_PLAN_DRIFT', 'campaign state differs from its retained self-bound plan')
}

function projectRoutes(plan, state, registry) {
  if (
    registry === null
    || typeof registry !== 'object'
    || Array.isArray(registry)
    || registry.schema_version !== '1.0.0'
    || registry.registry_version !== plan.registry_version
    || !Array.isArray(registry.routes)
    || registry.routes.length !== plan.route_dispositions.length
    || digestUnleashValue(registry) !== plan.registry_sha256
  ) fail('UNLEASH_SNAPSHOT_REGISTRY_DRIFT', 'retained registry differs from the plan registry binding')
  const completed = new Set(state.completed_routes)
  const seen = new Set()
  return registry.routes.map((route, index) => {
    const disposition = plan.route_dispositions[index]
    if (
      route === null
      || typeof route !== 'object'
      || Array.isArray(route)
      || typeof route.route_id !== 'string'
      || seen.has(route.route_id)
      || route.route_id !== disposition?.route_id
      || route.tool_id !== disposition.tool_id
      || route.parameter_schema_id !== disposition.parameter_schema_id
      || !ROUTE_DISPOSITIONS.has(disposition.disposition)
      || !Number.isSafeInteger(route.order)
      || !Array.isArray(route.target_families)
      || !Array.isArray(route.dependencies)
      || !Array.isArray(route.required_material)
      || route.availability === null
      || typeof route.availability !== 'object'
      || route.execution_contract === undefined
    ) fail('UNLEASH_SNAPSHOT_REGISTRY_DRIFT', `retained route ${index + 1} differs from its plan disposition`)
    seen.add(route.route_id)
    return {
      route_id: route.route_id,
      tool_id: route.tool_id,
      parameter_schema_id: route.parameter_schema_id,
      order: route.order,
      target_families: [...route.target_families],
      required_effect: route.required_effect,
      dependencies: [...route.dependencies],
      required_material: [...route.required_material],
      availability: structuredClone(route.availability),
      execution_contract_sha256: digestUnleashValue(route.execution_contract),
      plan_disposition: disposition.disposition,
      reason_code: disposition.reason_code,
      completed: completed.has(route.route_id),
    }
  })
}

function assertDigestBoundItem(value, fields, idField, digestField, expectedState) {
  if (
    !exactRecord(value, fields)
    || typeof value[idField] !== 'string'
    || !ID.test(value[idField])
    || value.state !== expectedState
    || !SHA256.test(value[digestField] ?? '')
    || value[digestField] !== digestWithout(value, digestField)
  ) fail('UNLEASH_SNAPSHOT_FRONTIER_INVALID', `candidate frontier ${idField} is invalid or not self-bound`)
}

function assertCandidate(candidate) {
  assertDigestBoundItem(candidate, CANDIDATE_FIELDS, 'candidate_id', 'candidate_sha256', 'CANDIDATE')
  if (
    !ID.test(candidate.proposal_id ?? '')
    || !SHA256.test(candidate.proposal_sha256 ?? '')
    || !SHA256.test(candidate.admission_sha256 ?? '')
    || typeof candidate.title !== 'string'
    || typeof candidate.hypothesis !== 'string'
    || typeof candidate.invariant !== 'string'
    || !['LOW', 'MEDIUM', 'HIGH'].includes(candidate.provider_confidence)
    || !assertStringArray(candidate.evidence_refs, { pattern: EVIDENCE_REF, maximum: 256 })
    || !assertStringArray(candidate.competing_explanations, { pattern: /^.{1,4096}$/u, maximum: 64 })
    || !assertStringArray(candidate.proposed_action_ids)
  ) fail('UNLEASH_SNAPSHOT_FRONTIER_INVALID', `candidate ${candidate.candidate_id} has invalid bounded fields`)
}

function assertAction(action) {
  assertDigestBoundItem(action, ACTION_FIELDS, 'action_id', 'action_sha256', 'PROPOSED_INERT')
  if (
    !ID.test(action.candidate_id ?? '')
    || !ID.test(action.proposal_id ?? '')
    || !ID.test(action.tool_id ?? '')
    || !SHA256.test(action.proposal_sha256 ?? '')
    || !SHA256.test(action.admission_sha256 ?? '')
    || !assertStringArray(action.evidence_refs, { pattern: EVIDENCE_REF, maximum: 256 })
    || (action.tool_id === 'tool:https-recon'
      && !sameValue(action.parameters, { method: 'HEAD' }))
    || action.parameters === null
    || typeof action.parameters !== 'object'
    || Array.isArray(action.parameters)
    || typeof action.expected_observation !== 'string'
    || action.executable !== false
  ) fail('UNLEASH_SNAPSHOT_FRONTIER_INVALID', `proposed action ${action.action_id} is invalid or executable`)
  try { digestUnleashValue(action.parameters) } catch {
    fail('UNLEASH_SNAPSHOT_FRONTIER_INVALID', `proposed action ${action.action_id} parameters are not bounded plain JSON`)
  }
}

function sameMergedCandidate(frontierCandidate, mergedCandidate) {
  return sameValue({
    candidate_id: frontierCandidate.candidate_id,
    state: frontierCandidate.state,
    title: frontierCandidate.title,
    hypothesis: frontierCandidate.hypothesis,
    invariant: frontierCandidate.invariant,
    provider_confidence: frontierCandidate.provider_confidence,
    evidence_refs: frontierCandidate.evidence_refs,
    competing_explanations: frontierCandidate.competing_explanations,
    proposed_action_ids: frontierCandidate.proposed_action_ids,
  }, {
    candidate_id: mergedCandidate.candidate_id,
    state: mergedCandidate.state,
    title: mergedCandidate.title,
    hypothesis: mergedCandidate.hypothesis,
    invariant: mergedCandidate.invariant,
    provider_confidence: mergedCandidate.provider_confidence,
    evidence_refs: mergedCandidate.evidence_refs,
    competing_explanations: mergedCandidate.competing_explanations,
    proposed_action_ids: mergedCandidate.proposed_action_ids,
  })
}

function sameMergedAction(frontierAction, mergedAction) {
  return sameValue({
    action_id: frontierAction.action_id,
    state: frontierAction.state,
    candidate_id: frontierAction.candidate_id,
    tool_id: frontierAction.tool_id,
    evidence_refs: frontierAction.evidence_refs,
    parameters: frontierAction.parameters,
    expected_observation: frontierAction.expected_observation,
    executable: frontierAction.executable,
  }, {
    action_id: mergedAction.action_id,
    state: mergedAction.state,
    candidate_id: mergedAction.candidate_id,
    tool_id: mergedAction.tool_id,
    evidence_refs: mergedAction.evidence_refs,
    parameters: mergedAction.parameters,
    expected_observation: mergedAction.expected_observation,
    executable: mergedAction.executable,
  })
}

function assertFrontier(frontier, plan, state, swarm = null) {
  const isV2 = swarm !== null
  const bindingState = isV2 ? swarm.basisState : state
  if (
    !exactRecord(frontier, isV2 ? V2_FRONTIER_FIELDS : FRONTIER_FIELDS)
    || frontier.schema_version !== (isV2 ? '2.0.0' : '1.0.0')
    || frontier.kind !== 'last-aperture/unleash-candidate-frontier'
    || frontier.campaign_id !== state.campaign_id
    || frontier.plan_sha256 !== plan.plan_sha256
    || frontier.target_id !== plan.target.target_id
    || frontier.campaign_state_revision !== bindingState.revision
    || frontier.campaign_state_sha256 !== digestUnleashValue(bindingState)
    || frontier.evidence_packet_sha256 !== (isV2 ? swarm.swarmBasis.evidence_packet_sha256 : state.evidence_packet_sha256)
    || frontier.completion_receipt_sha256 !== (isV2 ? swarm.swarmBasis.completion_receipt_sha256 : state.completion_receipt_sha256)
    || !Number.isSafeInteger(frontier.proposal_count)
    || frontier.proposal_count < 0
    || frontier.proposal_count > (isV2 ? 1 : MAX_ITEMS)
    || !Number.isSafeInteger(frontier.candidate_count)
    || !Number.isSafeInteger(frontier.proposed_action_count)
    || !Array.isArray(frontier.candidates)
    || !Array.isArray(frontier.actions)
    || frontier.candidate_count !== frontier.candidates.length
    || frontier.proposed_action_count !== frontier.actions.length
    || frontier.candidate_count > MAX_ITEMS
    || frontier.proposed_action_count > MAX_ITEMS
    || (frontier.proposal_count === 0) !== (frontier.head_admission_sha256 === null)
    || (frontier.proposal_count === 0 && (frontier.candidate_count !== 0 || frontier.proposed_action_count !== 0))
    || (frontier.head_admission_sha256 !== null && !SHA256.test(frontier.head_admission_sha256))
    || frontier.frontier_sha256 !== digestWithout(frontier, 'frontier_sha256')
    || !isSortedUnique(frontier.candidates.map(({ candidate_id: id }) => id))
    || !isSortedUnique(frontier.actions.map(({ action_id: id }) => id))
  ) fail('UNLEASH_SNAPSHOT_FRONTIER_INVALID', 'candidate frontier differs from the campaign head or its own digest')
  if (isV2 && (
    frontier.swarm_basis_sha256 !== swarm.swarmBasis.basis_sha256
    || frontier.swarm_merge_sha256 !== swarm.swarmMerge.merge_sha256
  )) fail('UNLEASH_SNAPSHOT_FRONTIER_INVALID', 'protocol-v2 candidate frontier differs from the exact swarm basis or merge')
  for (const candidate of frontier.candidates) assertCandidate(candidate)
  for (const action of frontier.actions) assertAction(action)
  const candidates = new Map(frontier.candidates.map((candidate) => [candidate.candidate_id, candidate]))
  const actions = new Map(frontier.actions.map((action) => [action.action_id, action]))
  for (const candidate of frontier.candidates) {
    for (const actionId of candidate.proposed_action_ids) {
      const action = actions.get(actionId)
      if (
        action?.candidate_id !== candidate.candidate_id
        || action.proposal_id !== candidate.proposal_id
        || action.proposal_sha256 !== candidate.proposal_sha256
        || action.admission_sha256 !== candidate.admission_sha256
      ) fail('UNLEASH_SNAPSHOT_FRONTIER_INVALID', `candidate ${candidate.candidate_id} references an unbound action`)
    }
  }
  for (const action of frontier.actions) {
    if (!candidates.get(action.candidate_id)?.proposed_action_ids.includes(action.action_id)) {
      fail('UNLEASH_SNAPSHOT_FRONTIER_INVALID', `proposed action ${action.action_id} is not bound back to its candidate`)
    }
  }
  const candidateStatuses = isV2
    ? ['SWARMING', 'RECONCILIATION_REQUIRED', 'COMPLETE', 'COMPLETE_WITH_GAPS', 'STOPPED']
    : ['SWARMING', 'COMPLETE', 'COMPLETE_WITH_GAPS']
  if (frontier.candidate_count > 0 && !candidateStatuses.includes(state.status)) {
    fail('UNLEASH_SNAPSHOT_FRONTIER_INVALID', 'provider candidates require verified reconnaissance evidence')
  }
  if (isV2 && frontier.proposal_count === 1) {
    if (
      frontier.candidate_count !== swarm.swarmMerge.candidate_count
      || frontier.proposed_action_count !== swarm.swarmMerge.proposed_action_count
      || frontier.candidates.some((candidate, index) => !sameMergedCandidate(candidate, swarm.swarmMerge.candidates[index]))
      || frontier.actions.some((action, index) => !sameMergedAction(action, swarm.swarmMerge.actions[index]))
    ) fail('UNLEASH_SNAPSHOT_FRONTIER_INVALID', 'admitted protocol-v2 candidate frontier differs from its final swarm merge')
  }
  if (isV2 && swarm.swarmCompletion !== null && frontier.proposal_count !== 1) {
    fail('UNLEASH_SNAPSHOT_FRONTIER_INVALID', 'sealed protocol-v2 swarm requires exactly one admitted merged proposal')
  }
  return frontier.candidates.map((candidate) => structuredClone(candidate))
}

function gapRecord(source, routeId, gapState, reasonCode) {
  const binding = { source, route_id: routeId, gap_state: gapState, reason_code: reasonCode }
  return { gap_id: `gap:sha256:${digestUnleashValue(binding)}`, ...binding }
}

function projectGaps(routes, state) {
  const gaps = []
  for (const route of routes) {
    if (PLAN_GAPS.has(route.plan_disposition)) {
      if (typeof route.reason_code !== 'string') {
        fail('UNLEASH_SNAPSHOT_PLAN_INVALID', `gap route ${route.route_id} lacks a reason code`)
      }
      gaps.push(gapRecord('PLAN', route.route_id, route.plan_disposition, route.reason_code))
    }
  }
  if (RUNTIME_GAP.has(state.status)) {
    const reason = state.status === 'STOPPED'
      ? 'CAMPAIGN_STOPPED_BEFORE_ROUTE_COMPLETION'
      : state.failure?.code ?? `CAMPAIGN_${state.status}`
    for (const route of routes) {
      if (route.plan_disposition === 'READY' && !route.completed) {
        gaps.push(gapRecord('RUNTIME', route.route_id, state.status, reason))
      }
    }
  }
  return gaps
}

function v2SwarmArtifactStage(input) {
  const values = [input.basisState, input.swarmBasis, input.swarmMerge, input.frontier, input.swarmCompletion]
  if (values.every((value) => value === null)) return 'NOT_STARTED'
  if (input.basisState === null || input.swarmBasis === null) {
    fail('UNLEASH_SNAPSHOT_SWARM_PARTIAL', 'protocol-v2 swarm basis state and basis must appear together')
  }
  if (input.swarmMerge === null) {
    if (input.frontier !== null || input.swarmCompletion !== null) {
      fail('UNLEASH_SNAPSHOT_SWARM_PARTIAL', 'candidate frontier or completion cannot precede the first swarm merge')
    }
    return 'BASIS_READY'
  }
  if (input.frontier === null) {
    if (input.swarmCompletion !== null) {
      fail('UNLEASH_SNAPSHOT_SWARM_PARTIAL', 'swarm completion requires the admitted candidate frontier')
    }
    return 'MERGED'
  }
  return input.swarmCompletion === null ? 'ADMITTED' : 'SEALED'
}

function assertV2SwarmInputs(input) {
  const {
    basisState,
    frontier,
    plan,
    registry,
    state,
    stateEvents,
    swarmBasis,
    swarmCompletion,
    swarmMerge,
  } = input
  const stage = v2SwarmArtifactStage(input)
  if (state.schema_version !== '2.0.0' || plan.provider_protocol_version !== '2.0.0') {
    fail('UNLEASH_SNAPSHOT_SWARM_PHASE_INVALID', 'protocol-v2 snapshot input requires a protocol-v2 campaign state and plan')
  }
  if (stage === 'NOT_STARTED') {
    if (
      ['SWARMING', 'COMPLETE', 'COMPLETE_WITH_GAPS'].includes(state.status)
      || state.swarm_basis_sha256 !== null
      || state.swarm_completion_sha256 !== null
      || state.candidate_frontier_sha256 !== null
      || state.candidate_frontier_head_sha256 !== null
      || state.swarm_gap_count !== 0
    ) fail('UNLEASH_SNAPSHOT_SWARM_PHASE_INVALID', 'pre-basis snapshot state cannot claim swarm progress or completion')
    return stage
  }
  try {
    assertValidUnleashCampaignState(basisState)
    assertValidUnleashSwarmBasis(swarmBasis)
    if (swarmMerge !== null) assertValidUnleashSwarmMerge(swarmMerge, { basis: swarmBasis })
    if (swarmCompletion !== null) {
      assertValidUnleashSwarmCompletion(swarmCompletion, { basis: swarmBasis })
    }
  } catch (cause) {
    fail('UNLEASH_SNAPSHOT_SWARM_INVALID', 'snapshot swarm artifacts are invalid', [cause?.code ?? 'UNKNOWN'])
  }
  assertPlanStateBinding(plan, basisState)
  const basisEvent = stateEvents[basisState.revision - 1]
  if (stage === 'BASIS_READY' && state.swarm_basis_sha256 === null) {
    const basisIsCurrent = state.status === 'RUNNING'
      && state.revision === basisState.revision
      && sameValue(state, basisState)
    const basisPrecedesReconciliation = state.status === 'RECONCILIATION_REQUIRED'
      && state.revision > basisState.revision
    if (
      basisState.schema_version !== '2.0.0'
      || basisState.status !== 'RUNNING'
      || basisEvent === undefined
      || !sameValue(basisEvent.state, basisState)
      || (!basisIsCurrent && !basisPrecedesReconciliation)
      || state.campaign_id !== basisState.campaign_id
      || swarmBasis.campaign_id !== basisState.campaign_id
      || swarmBasis.campaign_state_revision !== basisState.revision
      || swarmBasis.campaign_state_sha256 !== digestUnleashValue(basisState)
      || swarmBasis.plan_sha256 !== plan.plan_sha256
      || swarmBasis.target_id !== plan.target.target_id
      || swarmBasis.registry_sha256 !== plan.registry_sha256
      || swarmBasis.registry_sha256 !== digestUnleashValue(registry)
      || swarmBasis.provider_protocol_version !== plan.provider_protocol_version
      || swarmBasis.provider_profile_sha256 !== plan.provider_sha256
      || state.swarm_basis_sha256 !== null
      || state.swarm_completion_sha256 !== null
      || state.candidate_frontier_sha256 !== null
      || state.candidate_frontier_head_sha256 !== null
      || state.swarm_gap_count !== 0
      || Date.parse(swarmBasis.recorded_at) < Date.parse(basisState.updated_at)
    ) fail('UNLEASH_SNAPSHOT_SWARM_BINDING_DRIFT', 'basis-ready snapshot differs from the retained campaign chain, plan, or registry')
    return stage
  }
  if (
    basisState.schema_version !== '2.0.0'
    || basisState.status !== 'RUNNING'
    || basisEvent === undefined
    || !sameValue(basisEvent.state, basisState)
    || state.campaign_id !== basisState.campaign_id
    || state.revision <= basisState.revision
    || swarmBasis.campaign_id !== basisState.campaign_id
    || swarmBasis.campaign_state_revision !== basisState.revision
    || swarmBasis.campaign_state_sha256 !== digestUnleashValue(basisState)
    || swarmBasis.plan_sha256 !== plan.plan_sha256
    || swarmBasis.target_id !== plan.target.target_id
    || swarmBasis.registry_sha256 !== plan.registry_sha256
    || swarmBasis.registry_sha256 !== digestUnleashValue(registry)
    || swarmBasis.provider_protocol_version !== plan.provider_protocol_version
    || swarmBasis.provider_profile_sha256 !== plan.provider_sha256
    || swarmBasis.evidence_packet_sha256 !== state.evidence_packet_sha256
    || swarmBasis.completion_receipt_sha256 !== state.completion_receipt_sha256
    || state.swarm_basis_sha256 !== swarmBasis.basis_sha256
    || (swarmMerge !== null && (
      swarmMerge.basis_sha256 !== swarmBasis.basis_sha256
      || swarmMerge.plan_sha256 !== plan.plan_sha256
    ))
    || Date.parse(swarmBasis.recorded_at) < Date.parse(basisState.updated_at)
    || Date.parse(state.updated_at) < Date.parse(swarmBasis.recorded_at)
  ) fail('UNLEASH_SNAPSHOT_SWARM_BINDING_DRIFT', 'snapshot swarm artifacts differ from the retained campaign chain, plan, or registry')
  if (swarmCompletion === null) {
    if (
      !['SWARMING', 'RECONCILIATION_REQUIRED'].includes(state.status)
      || state.swarm_completion_sha256 !== null
      || state.candidate_frontier_sha256 !== null
      || state.candidate_frontier_head_sha256 !== null
      || (frontier !== null && frontier.proposal_count !== 1)
    ) fail('UNLEASH_SNAPSHOT_SWARM_PHASE_INVALID', 'an unsealed snapshot requires a SWARMING or recovery-required campaign head')
  } else if (
    (swarmCompletion.status === 'STOPPED'
      ? state.status !== 'STOPPED'
      : !['COMPLETE', 'COMPLETE_WITH_GAPS'].includes(state.status))
    || state.swarm_completion_sha256 !== swarmCompletion.completion_sha256
    || state.candidate_frontier_sha256 !== frontier.frontier_sha256
    || state.candidate_frontier_head_sha256 !== frontier.head_admission_sha256
    || state.swarm_gap_count !== swarmCompletion.gaps.length
    || swarmCompletion.merge_sha256 !== swarmMerge.merge_sha256
    || swarmCompletion.frontier_sha256 !== swarmMerge.frontier_sha256
    || swarmCompletion.challenge_set_sha256 !== swarmMerge.challenge_set_sha256
    || swarmCompletion.candidate_count !== swarmMerge.candidate_count
    || swarmCompletion.proposed_action_count !== swarmMerge.proposed_action_count
    || swarmCompletion.challenge_count !== swarmMerge.challenge_count
    || Date.parse(state.updated_at) < Date.parse(swarmCompletion.completed_at)
  ) fail('UNLEASH_SNAPSHOT_SWARM_SEAL_INVALID', 'sealed snapshot artifacts differ from the final swarm merge or terminal campaign head')
  return stage
}

function projectSwarm(input) {
  const stage = v2SwarmArtifactStage(input)
  if (stage === 'NOT_STARTED') {
    return {
      basis_sha256: null,
      merge_sha256: null,
      completion_sha256: null,
      frontier_sha256: null,
      challenge_set_sha256: null,
      limits: null,
      phase: 'NOT_STARTED',
      round: null,
      terminal_status: null,
      terminal_reason: null,
      usage: null,
      hypotheses: null,
      proposed_actions: null,
      challenges: null,
      gaps: null,
    }
  }
  const hypothesisItems = input.swarmMerge === null
    ? []
    : input.swarmMerge.candidates.map((candidate) => structuredClone(candidate))
  const actionItems = input.swarmMerge === null
    ? []
    : input.swarmMerge.actions.map((action) => structuredClone(action))
  const challengeItems = input.swarmMerge === null
    ? []
    : input.swarmMerge.challenges.map((challenge) => structuredClone(challenge))
  const gapItems = input.swarmCompletion === null
    ? []
    : input.swarmCompletion.gaps.map((gap) => structuredClone(gap))
  return {
    basis_sha256: input.swarmBasis.basis_sha256,
    merge_sha256: input.swarmMerge?.merge_sha256 ?? null,
    completion_sha256: input.swarmCompletion?.completion_sha256 ?? null,
    frontier_sha256: input.swarmMerge?.frontier_sha256 ?? null,
    challenge_set_sha256: input.swarmMerge?.challenge_set_sha256 ?? null,
    limits: structuredClone(input.swarmBasis.limits),
    phase: stage === 'BASIS_READY' && input.state.swarm_basis_sha256 === null
      ? 'BASIS_READY'
      : input.swarmCompletion === null ? 'SWARMING' : 'SEALED',
    round: input.swarmMerge?.round ?? null,
    terminal_status: input.swarmCompletion?.status ?? null,
    terminal_reason: input.swarmCompletion?.reason ?? null,
    usage: input.swarmCompletion === null ? null : structuredClone(input.swarmCompletion.usage),
    hypotheses: view(hypothesisItems),
    proposed_actions: view(actionItems),
    challenges: view(challengeItems),
    gaps: {
      state_count: input.state.swarm_gap_count,
      sealed: input.swarmCompletion !== null,
      ...view(gapItems),
    },
  }
}

function assertMergedHypothesis(candidate) {
  const identity = {
    hypothesis: candidate.hypothesis,
    invariant: candidate.invariant,
    evidence_refs: candidate.evidence_refs,
  }
  if (
    candidate.candidate_id !== `candidate:sha256:${digestUnleashValue(identity)}`
    || candidate.candidate_sha256 !== digestWithout(candidate, 'candidate_sha256')
    || candidate.state !== 'CANDIDATE'
    || !assertStringArray(candidate.evidence_refs, { pattern: EVIDENCE_REF, maximum: 256 })
    || !assertStringArray(candidate.competing_explanations, { pattern: /^.{1,4096}$/u, maximum: 64 })
    || !assertStringArray(candidate.proposed_action_ids)
  ) fail('UNLEASH_SNAPSHOT_SWARM_VIEW_DRIFT', 'swarm hypothesis is not a canonical inert candidate')
}

function assertMergedAction(action, candidateIds) {
  const identity = {
    candidate_id: action.candidate_id,
    tool_id: action.tool_id,
    evidence_refs: action.evidence_refs,
    parameters: action.parameters,
    expected_observation: action.expected_observation,
  }
  if (
    action.action_id !== `action:sha256:${digestUnleashValue(identity)}`
    || action.action_sha256 !== digestWithout(action, 'action_sha256')
    || action.state !== 'PROPOSED_INERT'
    || action.executable !== false
    || !candidateIds.has(action.candidate_id)
    || !assertStringArray(action.evidence_refs, { pattern: EVIDENCE_REF, maximum: 256 })
    || action.tool_id !== 'tool:https-recon'
    || !sameValue(action.parameters, { method: 'HEAD' })
  ) fail('UNLEASH_SNAPSHOT_SWARM_VIEW_DRIFT', 'swarm proposed action is not canonical, bound, and inert')
}

function assertMergedChallenge(challenge, candidateIds) {
  const identity = {
    candidate_id: challenge.candidate_id,
    disposition: challenge.disposition,
    reason: challenge.reason,
    evidence_refs: challenge.evidence_refs,
    competing_explanations: challenge.competing_explanations,
  }
  if (
    challenge.challenge_id !== `challenge:sha256:${digestUnleashValue(identity)}`
    || challenge.challenge_sha256 !== digestWithout(challenge, 'challenge_sha256')
    || !candidateIds.has(challenge.candidate_id)
    || !assertStringArray(challenge.evidence_refs, { pattern: EVIDENCE_REF, maximum: 256 })
    || !assertStringArray(challenge.competing_explanations, { pattern: /^.{1,4096}$/u, maximum: 64 })
  ) fail('UNLEASH_SNAPSHOT_SWARM_VIEW_DRIFT', 'swarm challenge is not canonical or candidate-bound')
}

function assertSwarmView(value) {
  const { swarm } = value
  if (swarm.phase === 'NOT_STARTED') {
    const nullSwarmFields = [
      'basis_sha256', 'merge_sha256', 'completion_sha256', 'frontier_sha256',
      'challenge_set_sha256', 'limits', 'round', 'terminal_status',
      'terminal_reason', 'usage', 'hypotheses', 'proposed_actions', 'challenges', 'gaps',
    ]
    const nullBindingFields = [
      'basis_state_revision', 'basis_state_sha256', 'swarm_basis_sha256',
      'swarm_merge_sha256', 'swarm_completion_sha256', 'swarm_frontier_sha256',
      'swarm_challenge_set_sha256', 'swarm_hypothesis_view_sha256',
      'swarm_action_view_sha256', 'swarm_challenge_view_sha256', 'swarm_gap_view_sha256',
    ]
    if (
      ['SWARMING', 'COMPLETE', 'COMPLETE_WITH_GAPS'].includes(value.status)
      || value.swarm_basis_sha256 !== null
      || value.swarm_completion_sha256 !== null
      || value.candidate_frontier_sha256 !== null
      || value.candidate_frontier_head_sha256 !== null
      || value.swarm_gap_count !== 0
      || value.bindings.candidate_frontier_sha256 !== null
      || value.bindings.candidate_frontier_head_sha256 !== null
      || value.bindings.candidate_count !== 0
      || value.bindings.proposal_count !== 0
      || value.bindings.proposed_action_count !== 0
      || value.candidates.count !== 0
      || nullSwarmFields.some((field) => swarm[field] !== null)
      || nullBindingFields.some((field) => value.bindings[field] !== null)
    ) fail('UNLEASH_SNAPSHOT_SWARM_VIEW_DRIFT', 'pre-basis snapshot claims swarm artifacts, views, or progress')
    return
  }
  const views = [swarm.hypotheses, swarm.proposed_actions, swarm.challenges]
  if (views.some((entry) => entry.count !== entry.items.length || entry.sha256 !== digestUnleashValue(entry.items))) {
    fail('UNLEASH_SNAPSHOT_SWARM_VIEW_DRIFT', 'swarm view count or digest is inconsistent')
  }
  if (
    swarm.gaps.count !== swarm.gaps.items.length
    || swarm.gaps.sha256 !== digestUnleashValue(swarm.gaps.items)
    || swarm.gaps.state_count !== value.swarm_gap_count
    || !isSortedUnique(swarm.hypotheses.items.map(({ candidate_id: id }) => id))
    || !isSortedUnique(swarm.proposed_actions.items.map(({ action_id: id }) => id))
    || !isSortedUnique(swarm.challenges.items.map(({ challenge_id: id }) => id))
    || !isSortedUnique(swarm.gaps.items.map(({ gap_id: id }) => id))
  ) fail('UNLEASH_SNAPSHOT_SWARM_VIEW_DRIFT', 'swarm views are not canonical or state-bound')
  const candidateIds = new Set(swarm.hypotheses.items.map(({ candidate_id: id }) => id))
  const actionIdsByCandidate = new Map()
  for (const candidate of swarm.hypotheses.items) assertMergedHypothesis(candidate)
  for (const action of swarm.proposed_actions.items) {
    assertMergedAction(action, candidateIds)
    const ids = actionIdsByCandidate.get(action.candidate_id) ?? []
    ids.push(action.action_id)
    actionIdsByCandidate.set(action.candidate_id, ids)
  }
  for (const candidate of swarm.hypotheses.items) {
    if (!sameValue(candidate.proposed_action_ids, actionIdsByCandidate.get(candidate.candidate_id) ?? [])) {
      fail('UNLEASH_SNAPSHOT_SWARM_VIEW_DRIFT', 'swarm hypothesis action projection is incomplete')
    }
  }
  for (const challenge of swarm.challenges.items) assertMergedChallenge(challenge, candidateIds)
  for (const gap of swarm.gaps.items) {
    const { gap_id: gapId, ...body } = gap
    if (gapId !== `gap:sha256:${digestUnleashValue(body)}`) {
      fail('UNLEASH_SNAPSHOT_SWARM_VIEW_DRIFT', 'swarm gap identifier is not self-bound')
    }
  }
  if (swarm.phase === 'BASIS_READY') {
    const basisTimeline = value.timeline.items[value.bindings.basis_state_revision - 1]
    const empty = digestUnleashValue([])
    if (
      !['RUNNING', 'RECONCILIATION_REQUIRED'].includes(value.status)
      || value.swarm_basis_sha256 !== null
      || value.swarm_completion_sha256 !== null
      || value.candidate_frontier_sha256 !== null
      || value.candidate_frontier_head_sha256 !== null
      || value.swarm_gap_count !== 0
      || swarm.basis_sha256 === null
      || swarm.limits === null
      || swarm.merge_sha256 !== null
      || swarm.completion_sha256 !== null
      || swarm.frontier_sha256 !== null
      || swarm.challenge_set_sha256 !== null
      || swarm.round !== null
      || swarm.terminal_status !== null
      || swarm.terminal_reason !== null
      || swarm.usage !== null
      || swarm.hypotheses.count !== 0
      || swarm.proposed_actions.count !== 0
      || swarm.challenges.count !== 0
      || swarm.gaps.count !== 0
      || swarm.gaps.state_count !== 0
      || swarm.gaps.sealed !== false
      || basisTimeline?.status !== 'RUNNING'
      || basisTimeline?.state_sha256 !== value.bindings.basis_state_sha256
      || value.bindings.swarm_basis_sha256 !== swarm.basis_sha256
      || value.bindings.swarm_merge_sha256 !== null
      || value.bindings.swarm_completion_sha256 !== null
      || value.bindings.swarm_frontier_sha256 !== null
      || value.bindings.swarm_challenge_set_sha256 !== null
      || value.bindings.swarm_hypothesis_view_sha256 !== empty
      || value.bindings.swarm_action_view_sha256 !== empty
      || value.bindings.swarm_challenge_view_sha256 !== empty
      || value.bindings.swarm_gap_view_sha256 !== empty
      || value.bindings.candidate_frontier_sha256 !== null
      || value.bindings.candidate_frontier_head_sha256 !== null
      || value.bindings.candidate_count !== 0
      || value.bindings.proposal_count !== 0
      || value.bindings.proposed_action_count !== 0
      || value.candidates.count !== 0
    ) fail('UNLEASH_SNAPSHOT_SWARM_VIEW_DRIFT', 'basis-ready snapshot claims unpublished swarm state, views, or completion')
    return
  }
  const sealed = swarm.phase === 'SEALED'
  const merged = swarm.merge_sha256 !== null
  const terminalReasonMatches = new Map([
    ['QUIESCENT', new Set(['FRONTIER_STABLE'])],
    ['BUDGET_EXHAUSTED', new Set(['MAX_ROUNDS', 'MAX_PROVIDER_CALLS', 'MAX_RESPONSE_BYTES', 'DEADLINE'])],
    ['STOPPED', new Set(['STOP_REQUESTED'])],
    ['POLICY_BLOCKED', new Set(['AUTHORITY_UNAVAILABLE'])],
  ])
  const basisTimeline = value.timeline.items[value.bindings.basis_state_revision - 1]
  if (
    (sealed && !['COMPLETE', 'COMPLETE_WITH_GAPS', 'STOPPED'].includes(value.status))
    || (!sealed && !['SWARMING', 'RECONCILIATION_REQUIRED'].includes(value.status))
    || (sealed && (swarm.terminal_status === 'STOPPED') !== (value.status === 'STOPPED'))
    || (!sealed && (
      value.swarm_completion_sha256 !== null
      || value.candidate_frontier_sha256 !== null
      || value.candidate_frontier_head_sha256 !== null
    ))
    || (sealed && (
      value.swarm_completion_sha256 === null
      || value.candidate_frontier_sha256 === null
      || value.candidate_frontier_head_sha256 === null
    ))
    || (sealed && (swarm.terminal_status === null || swarm.terminal_reason === null || swarm.usage === null))
    || (!sealed && (swarm.terminal_status !== null || swarm.terminal_reason !== null || swarm.usage !== null))
    || (sealed && !terminalReasonMatches.get(swarm.terminal_status)?.has(swarm.terminal_reason))
    || swarm.basis_sha256 === null
    || swarm.limits === null
    || (merged && (swarm.round === null || swarm.frontier_sha256 === null || swarm.challenge_set_sha256 === null))
    || (!merged && (swarm.round !== null || swarm.frontier_sha256 !== null || swarm.challenge_set_sha256 !== null))
    || swarm.hypotheses.count > swarm.limits.max_candidates
    || swarm.proposed_actions.count > swarm.limits.max_proposed_actions
    || (swarm.round !== null && swarm.round > swarm.limits.max_rounds)
    || (sealed && (
      swarm.usage.rounds_completed > swarm.limits.max_rounds
      || swarm.usage.provider_calls_started > swarm.limits.max_provider_calls
      || swarm.usage.response_bytes > swarm.limits.max_total_response_bytes
    ))
    || swarm.gaps.sealed !== sealed
    || (sealed && swarm.gaps.count !== swarm.gaps.state_count)
    || (!sealed && swarm.gaps.count !== 0)
    || basisTimeline?.status !== 'RUNNING'
    || basisTimeline?.state_sha256 !== value.bindings.basis_state_sha256
    || value.bindings.swarm_basis_sha256 !== value.swarm_basis_sha256
    || value.bindings.swarm_basis_sha256 !== swarm.basis_sha256
    || value.bindings.swarm_merge_sha256 !== swarm.merge_sha256
    || value.bindings.swarm_completion_sha256 !== value.swarm_completion_sha256
    || value.bindings.swarm_completion_sha256 !== swarm.completion_sha256
    || value.bindings.swarm_frontier_sha256 !== swarm.frontier_sha256
    || (merged && value.bindings.swarm_frontier_sha256 !== digestUnleashValue({
      candidates: swarm.hypotheses.items,
      actions: swarm.proposed_actions.items,
    }))
    || value.bindings.swarm_challenge_set_sha256 !== swarm.challenge_set_sha256
    || (merged && value.bindings.swarm_challenge_set_sha256 !== digestUnleashValue(swarm.challenges.items))
    || value.bindings.swarm_hypothesis_view_sha256 !== swarm.hypotheses.sha256
    || value.bindings.swarm_action_view_sha256 !== swarm.proposed_actions.sha256
    || value.bindings.swarm_challenge_view_sha256 !== swarm.challenges.sha256
    || value.bindings.swarm_gap_view_sha256 !== swarm.gaps.sha256
    || (sealed && swarm.round > Math.max(1, swarm.usage.rounds_completed))
    || (sealed && !merged)
  ) fail('UNLEASH_SNAPSHOT_SWARM_VIEW_DRIFT', 'swarm phase, usage, gaps, or bindings are inconsistent')
  const frontierAdmitted = value.bindings.candidate_frontier_sha256 !== null
  if (
    (frontierAdmitted && !merged)
    || (frontierAdmitted && value.bindings.proposal_count !== 1)
    || (!frontierAdmitted && (
      value.bindings.candidate_frontier_head_sha256 !== null
      || value.bindings.candidate_count !== 0
      || value.bindings.proposal_count !== 0
      || value.bindings.proposed_action_count !== 0
      || value.candidates.count !== 0
    ))
    || (frontierAdmitted && (
      value.candidates.count !== swarm.hypotheses.count
      || value.candidates.items.some((candidate, index) => !sameMergedCandidate(candidate, swarm.hypotheses.items[index]))
    ))
    || (sealed && (
      !frontierAdmitted
      || value.candidate_frontier_sha256 !== value.bindings.candidate_frontier_sha256
      || value.candidate_frontier_head_sha256 !== value.bindings.candidate_frontier_head_sha256
    ))
  ) fail('UNLEASH_SNAPSHOT_SWARM_VIEW_DRIFT', 'candidate projection differs from the admitted swarm frontier')
}

function controlsFor(state) {
  if (TERMINAL.has(state.status)) {
    return {
      stop: { enabled: false, state: 'SETTLED', reason: state.stop_reason },
      resume: { enabled: false, mode: 'NO_OP', authority_check: 'NOT_APPLICABLE' },
    }
  }
  const stopping = state.status === 'STOP_REQUESTED' || state.stop_reason !== null
  return {
    stop: {
      enabled: true,
      state: stopping ? 'REQUESTED' : 'AVAILABLE',
      reason: state.stop_reason,
    },
    resume: {
      enabled: true,
      mode: stopping
        ? 'STOP_RECONCILIATION_ONLY'
        : state.status === 'RECONCILIATION_REQUIRED' ? 'RECOVER' : 'CONTINUE',
      authority_check: stopping ? 'NOT_APPLICABLE' : 'REQUIRED_AT_EXECUTION',
    },
  }
}

function scoreLevel(score, thresholds) {
  for (const [maximum, level] of thresholds) {
    if (score < maximum) return level
  }
  return thresholds.at(-1)[1]
}

function assertDetectionSummary(value) {
  if (exactRecord(value, ['state']) && value.state === 'NOT_ASSESSED') return value
  const fields = [
    'state', 'action_id', 'profile', 'profile_selection', 'catalog_id',
    'catalog_version', 'reviewed_at', 'detection_pattern_model_id',
    'detection_pattern_model_version', 'matched_pattern_ids', 'methodology',
    'control_signal_score_semantics', 'telemetry_coverage',
    'collection_precondition', 'risk_score', 'risk_level', 'noise_score',
    'noise_level', 'rationale', 'likely_impacts', 'control_signals',
    'confirmation_required', 'confirmation_reasons', 'assessment_sha256',
    'receipt_sha256', 'preflight_sha256', 'confirmation_sha256',
  ]
  const controls = ['ENDPOINT', 'SIEM_LOGGING', 'NETWORK', 'CLOUD', 'IDENTITY', 'APPLICATION']
  const patternIds = UNLEASH_ACTION_RISK_DETECTION_PATTERN_MODEL.patterns
    .map(({ pattern_id: patternId }) => patternId)
  if (
    !exactRecord(value, fields)
    || !['ADMITTED', 'CONFIRMATION_REQUIRED'].includes(value.state)
    || value.profile_selection?.operational_profile !== value.profile
    || value.detection_pattern_model_id !== UNLEASH_ACTION_RISK_DETECTION_PATTERN_MODEL.model_id
    || value.detection_pattern_model_version !== UNLEASH_ACTION_RISK_DETECTION_PATTERN_MODEL.model_version
    || !Array.isArray(value.matched_pattern_ids)
    || value.matched_pattern_ids.length < 1
    || value.matched_pattern_ids.length > patternIds.length
    || new Set(value.matched_pattern_ids).size !== value.matched_pattern_ids.length
    || value.matched_pattern_ids.some((patternId) => !patternIds.includes(patternId))
    || value.matched_pattern_ids.join(',')
      !== patternIds.filter((patternId) => value.matched_pattern_ids.includes(patternId)).join(',')
    || value.methodology !== 'HEURISTIC_UNCALIBRATED'
    || value.control_signal_score_semantics !== 'RELATIVE_EXPOSURE_NOT_ALERT_PROBABILITY'
    || value.telemetry_coverage !== 'UNKNOWN'
    || value.collection_precondition !== 'UNKNOWN'
    || !Array.isArray(value.control_signals)
    || value.control_signals.map(({ control }) => control).join(',') !== controls.join(',')
    || !Array.isArray(value.likely_impacts)
    || value.likely_impacts.map(({ impact }) => impact).join(',')
      !== 'CONFIDENTIALITY,INTEGRITY,AVAILABILITY,OPERATIONAL_RESPONSE'
    || value.risk_level !== scoreLevel(value.risk_score, [
      [20, 'MINIMAL'], [40, 'LOW'], [60, 'MODERATE'], [80, 'HIGH'], [101, 'CRITICAL'],
    ])
    || value.noise_level !== scoreLevel(value.noise_score, [
      [20, 'MINIMAL'], [40, 'LOW'], [60, 'MODERATE'], [80, 'HIGH'], [101, 'VERY_HIGH'],
    ])
    || (value.state === 'CONFIRMATION_REQUIRED') !== (
      value.confirmation_required && value.confirmation_sha256 === null
    )
    || (value.state === 'ADMITTED' && value.confirmation_required
      && value.confirmation_sha256 === null)
  ) fail('UNLEASH_SNAPSHOT_DETECTION_INVALID', 'snapshot detection view is inconsistent')
  return value
}

function assertCampaignControlSummary(value) {
  const pauseFields = [
    'state', 'dispatch_open', 'reason', 'request_count', 'acknowledgement_count',
  ]
  const rollbackFields = [
    'enabled', 'state', 'request_count', 'scope', 'target_side_effects_reversed',
  ]
  if (
    !exactRecord(value, ['pause', 'rollback'])
    || !exactRecord(value.pause, pauseFields)
    || !exactRecord(value.rollback, rollbackFields)
    || !['RUNNING', 'PAUSED', 'SETTLED'].includes(value.pause.state)
    || value.pause.dispatch_open !== (value.pause.state === 'RUNNING')
    || (value.pause.reason !== null && (
      typeof value.pause.reason !== 'string'
      || value.pause.reason.length < 1
      || value.pause.reason.length > 1024
      || /[\u0000-\u001f\u007f]/u.test(value.pause.reason)
    ))
    || !Number.isSafeInteger(value.pause.request_count)
    || value.pause.request_count < 0
    || !Number.isSafeInteger(value.pause.acknowledgement_count)
    || value.pause.acknowledgement_count < 0
    || value.pause.acknowledgement_count > value.pause.request_count
    || value.rollback.enabled !== (value.pause.state === 'PAUSED')
    || !['AVAILABLE', 'REQUESTED'].includes(value.rollback.state)
    || !Number.isSafeInteger(value.rollback.request_count)
    || value.rollback.request_count < 0
    || value.rollback.request_count > value.pause.request_count
    || JSON.stringify(value.rollback.scope)
      !== JSON.stringify(['NOT_YET_DISPATCHED', 'PROPOSED_INERT'])
    || value.rollback.target_side_effects_reversed !== false
  ) fail('UNLEASH_SNAPSHOT_CONTROL_INVALID', 'snapshot Pause or rollback view is inconsistent')
  return value
}

function view(items) {
  return { count: items.length, sha256: digestUnleashValue(items), items }
}

function assertSnapshotSemantics(value) {
  const isV2 = value.schema_version === '2.0.0'
  const routes = value.routes.items
  const gaps = value.gaps.items
  const candidates = value.candidates.items
  const timeline = value.timeline.items
  assertDetectionSummary(value.detection)
  const hasPause = Object.hasOwn(value, 'pause')
  const hasRollback = Object.hasOwn(value, 'rollback')
  if (hasPause !== hasRollback || ((hasPause || hasRollback) && !isV2)) {
    fail('UNLEASH_SNAPSHOT_CONTROL_INVALID', 'snapshot Pause and rollback views must be paired on protocol-v2')
  }
  if (hasPause) assertCampaignControlSummary({ pause: value.pause, rollback: value.rollback })
  if (
    value.routes.count !== routes.length
    || value.routes.sha256 !== digestUnleashValue(routes)
    || value.gaps.count !== gaps.length
    || value.gaps.sha256 !== digestUnleashValue(gaps)
    || value.candidates.count !== candidates.length
    || value.candidates.state_counts.CANDIDATE !== candidates.length
    || value.candidates.sha256 !== digestUnleashValue(candidates)
    || value.findings.sha256 !== digestUnleashValue(value.findings.items)
    || value.timeline.count !== timeline.length
    || value.timeline.sha256 !== digestUnleashValue(timeline)
  ) fail('UNLEASH_SNAPSHOT_VIEW_DRIFT', 'snapshot view count or digest is inconsistent')
  if (!isSortedUnique(candidates.map(({ candidate_id: id }) => id))) {
    fail('UNLEASH_SNAPSHOT_VIEW_DRIFT', 'snapshot candidates are not in canonical unique order')
  }
  for (const candidate of candidates) assertCandidate(candidate)
  for (const gap of gaps) {
    const { gap_id: gapId, ...binding } = gap
    if (gapId !== `gap:sha256:${digestUnleashValue(binding)}`) {
      fail('UNLEASH_SNAPSHOT_VIEW_DRIFT', 'snapshot gap identifier is not self-bound')
    }
  }
  if (
    timeline.some((item, index) => (
      item.revision !== index + 1
      || item.previous_state_sha256 !== (index === 0 ? null : timeline[index - 1].state_sha256)
    ))
    || timeline.at(-1).revision !== value.revision
    || timeline.at(-1).recorded_at !== value.updated_at
    || timeline.at(-1).status !== value.status
    || timeline.at(-1).state_sha256 !== value.bindings.state_sha256
  ) fail('UNLEASH_SNAPSHOT_VIEW_DRIFT', 'snapshot timeline is not a contiguous projection of its bound state head')
  const counts = {
    total: routes.length,
    ready: routes.filter(({ plan_disposition: state }) => state === 'READY').length,
    waiting: routes.filter(({ plan_disposition: state }) => state === 'WAITING_FOR_MATERIAL' || state === 'WAITING_FOR_DEPENDENCY').length,
    unavailable: routes.filter(({ plan_disposition: state }) => state === 'UNAVAILABLE').length,
    not_applicable: routes.filter(({ plan_disposition: state }) => state === 'NOT_APPLICABLE').length,
    blocked: routes.filter(({ plan_disposition: state }) => state === 'BLOCKED_BY_POLICY').length,
  }
  const completed = routes.filter(({ completed }) => completed).map(({ route_id: routeId }) => routeId)
  const expectedGaps = projectGaps(routes, value)
  const open = ['PLANNED', 'RUNNING'].includes(value.status)
    ? routes.filter(({ completed: done, plan_disposition: state }) => !done && state === 'READY').length
    : 0
  if (
    !sameValue(counts, value.route_counts)
    || !sameValue(completed, value.completed_routes)
    || !sameValue(expectedGaps, gaps)
    || value.gap_count !== gaps.filter(({ source }) => source === 'PLAN').length
    || value.progress.route_total !== counts.total
    || value.progress.route_applicable !== counts.total - counts.not_applicable
    || value.progress.route_completed !== completed.length
    || value.progress.route_open !== open
    || value.progress.plan_gap_count !== value.gap_count
    || value.progress.current_gap_count !== gaps.length + (isV2 ? value.swarm_gap_count : 0)
    || value.progress.candidate_count !== candidates.length
    || value.progress.proposal_count !== value.bindings.proposal_count
    || value.progress.proposed_action_count !== value.bindings.proposed_action_count
    || value.progress.verified_finding_count !== value.findings.count
    || value.bindings.state_revision !== value.revision
    || value.bindings.state_event_count !== timeline.length
    || value.bindings.route_view_sha256 !== value.routes.sha256
    || value.bindings.gap_view_sha256 !== value.gaps.sha256
    || value.bindings.candidate_count !== candidates.length
    || value.bindings.candidate_view_sha256 !== value.candidates.sha256
    || value.bindings.finding_view_sha256 !== value.findings.sha256
    || value.bindings.timeline_sha256 !== value.timeline.sha256
    || !sameValue(value.controls, controlsFor(value))
  ) fail('UNLEASH_SNAPSHOT_VIEW_DRIFT', 'snapshot progress, controls, or source bindings are inconsistent')
  if (isV2) {
    assertSwarmView(value)
  } else if (
    value.bindings.candidate_frontier_sha256 === null
    || SNAPSHOT_V2_FIELDS.some((field) => Object.hasOwn(value, field))
    || SNAPSHOT_V2_BINDING_FIELDS.some((field) => Object.hasOwn(value.bindings, field))
  ) fail('UNLEASH_SNAPSHOT_VIEW_DRIFT', 'protocol-v1 snapshot contains protocol-v2 swarm fields')
}

export function assertValidUnleashCampaignSnapshot(value) {
  const snapshot = safeCanonicalCopy(value, 'campaign snapshot')
  if (!validateSnapshotSchema(snapshot)) {
    fail(
      'UNLEASH_SNAPSHOT_SCHEMA_INVALID',
      'campaign snapshot violates its strict schema',
      validateSnapshotSchema.errors ?? [],
    )
  }
  canonicalTimestamp(snapshot.captured_at, 'snapshot captured_at')
  canonicalTimestamp(snapshot.updated_at, 'snapshot updated_at')
  if (snapshot.snapshot_sha256 !== digestWithout(snapshot, 'snapshot_sha256')) {
    fail('UNLEASH_SNAPSHOT_DIGEST_DRIFT', 'campaign snapshot digest does not match its canonical content')
  }
  assertSnapshotSemantics(snapshot)
  return value
}

export function createUnleashCampaignSnapshot(input) {
  const v1Input = exactRecord(input, INPUT_FIELDS) || exactRecord(input, INPUT_FIELDS_WITH_DETECTION)
  const v2Input = exactRecord(input, V2_INPUT_FIELDS)
    || exactRecord(input, V2_INPUT_FIELDS_WITH_DETECTION)
    || exactRecord(input, V2_INPUT_FIELDS_WITH_CONTROL)
    || exactRecord(input, V2_INPUT_FIELDS_WITH_DETECTION_AND_CONTROL)
  if (!v1Input && !v2Input) {
    fail('UNLEASH_SNAPSHOT_INPUT_INVALID', 'snapshot builder accepts only verified plan, state, event, registry, frontier, and capture-time inputs')
  }
  const safeInput = safeCanonicalCopy(input, 'snapshot builder input')
  const isV2 = safeInput.state?.schema_version === '2.0.0'
  if ((isV2 && !v2Input) || (!isV2 && !v1Input)) {
    fail('UNLEASH_SNAPSHOT_INPUT_INVALID', 'snapshot builder input shape does not match its campaign protocol version')
  }
  if (!isV2 && safeInput.frontier === null) {
    fail('UNLEASH_SNAPSHOT_INPUT_INVALID', 'protocol-v1 snapshot requires its candidate frontier')
  }
  canonicalTimestamp(safeInput.capturedAt, 'snapshot capturedAt')
  assertPlanStateBinding(safeInput.plan, safeInput.state)
  const timelineItems = assertEvents(safeInput.stateEvents, safeInput.state)
  if (isV2) assertV2SwarmInputs(safeInput)
  const routeItems = projectRoutes(safeInput.plan, safeInput.state, safeInput.registry)
  const candidateItems = safeInput.frontier === null
    ? []
    : assertFrontier(
        safeInput.frontier,
        safeInput.plan,
        safeInput.state,
        isV2 ? safeInput : null,
      )
  const gapItems = projectGaps(routeItems, safeInput.state)
  const routes = view(routeItems)
  const gaps = view(gapItems)
  const candidates = {
    count: candidateItems.length,
    state_counts: { CANDIDATE: candidateItems.length },
    sha256: digestUnleashValue(candidateItems),
    items: candidateItems,
  }
  const findingItems = []
  const findings = {
    count: 0,
    source_status: 'NO_VERIFIED_RECORDS',
    clearance: 'NOT_ESTABLISHED',
    sha256: digestUnleashValue(findingItems),
    items: findingItems,
  }
  const timeline = view(timelineItems)
  const detection = safeInput.detection ?? { state: 'NOT_ASSESSED' }
  assertDetectionSummary(detection)
  if (safeInput.campaignControl !== undefined) assertCampaignControlSummary(safeInput.campaignControl)
  const swarm = isV2 ? projectSwarm(safeInput) : null
  const routeOpen = ['PLANNED', 'RUNNING'].includes(safeInput.state.status)
    ? routeItems.filter(({ completed, plan_disposition: disposition }) => !completed && disposition === 'READY').length
    : 0
  const unsigned = {
    schema_version: isV2 ? '2.0.0' : '1.0.0',
    kind: 'last-aperture/unleash-campaign-snapshot',
    captured_at: safeInput.capturedAt,
    campaign_id: safeInput.state.campaign_id,
    status: safeInput.state.status,
    revision: safeInput.state.revision,
    updated_at: safeInput.state.updated_at,
    run_directory: safeInput.state.run_directory,
    plan_sha256: safeInput.plan.plan_sha256,
    target: structuredClone(safeInput.state.target),
    completed_routes: [...safeInput.state.completed_routes],
    evidence_packet_path: safeInput.state.evidence_packet_path,
    evidence_packet_sha256: safeInput.state.evidence_packet_sha256,
    completion_receipt_sha256: safeInput.state.completion_receipt_sha256,
    route_counts: structuredClone(safeInput.state.route_counts),
    gap_count: safeInput.state.gap_count,
    stop_reason: safeInput.state.stop_reason,
    failure: structuredClone(safeInput.state.failure),
    ...(isV2
      ? {
          swarm_basis_sha256: safeInput.state.swarm_basis_sha256,
          swarm_completion_sha256: safeInput.state.swarm_completion_sha256,
          candidate_frontier_sha256: safeInput.state.candidate_frontier_sha256,
          candidate_frontier_head_sha256: safeInput.state.candidate_frontier_head_sha256,
          swarm_gap_count: safeInput.state.swarm_gap_count,
        }
      : {}),
    progress: {
      route_total: routeItems.length,
      route_applicable: routeItems.length - safeInput.state.route_counts.not_applicable,
      route_completed: safeInput.state.completed_routes.length,
      route_open: routeOpen,
      plan_gap_count: safeInput.state.gap_count,
      current_gap_count: gapItems.length + (isV2 ? safeInput.state.swarm_gap_count : 0),
      candidate_count: safeInput.frontier?.candidate_count ?? 0,
      proposal_count: safeInput.frontier?.proposal_count ?? 0,
      proposed_action_count: safeInput.frontier?.proposed_action_count ?? 0,
      verified_finding_count: 0,
      assessment_clearance: 'NOT_ESTABLISHED',
    },
    routes,
    gaps,
    candidates,
    findings,
    timeline,
    controls: controlsFor(safeInput.state),
    detection,
    ...(safeInput.campaignControl ?? {}),
    ...(isV2 ? { swarm } : {}),
    bindings: {
      state_revision: safeInput.state.revision,
      state_event_count: timelineItems.length,
      state_sha256: digestUnleashValue(safeInput.state),
      registry_sha256: safeInput.plan.registry_sha256,
      route_view_sha256: routes.sha256,
      gap_view_sha256: gaps.sha256,
      candidate_frontier_sha256: safeInput.frontier?.frontier_sha256 ?? null,
      candidate_frontier_head_sha256: safeInput.frontier?.head_admission_sha256 ?? null,
      candidate_count: safeInput.frontier?.candidate_count ?? 0,
      proposal_count: safeInput.frontier?.proposal_count ?? 0,
      proposed_action_count: safeInput.frontier?.proposed_action_count ?? 0,
      candidate_view_sha256: candidates.sha256,
      finding_view_sha256: findings.sha256,
      timeline_sha256: timeline.sha256,
      ...(isV2
        ? {
            basis_state_revision: safeInput.basisState?.revision ?? null,
            basis_state_sha256: safeInput.basisState === null ? null : digestUnleashValue(safeInput.basisState),
            swarm_basis_sha256: safeInput.swarmBasis?.basis_sha256 ?? null,
            swarm_merge_sha256: safeInput.swarmMerge?.merge_sha256 ?? null,
            swarm_completion_sha256: safeInput.swarmCompletion?.completion_sha256 ?? null,
            swarm_frontier_sha256: safeInput.swarmMerge?.frontier_sha256 ?? null,
            swarm_challenge_set_sha256: safeInput.swarmMerge?.challenge_set_sha256 ?? null,
            swarm_hypothesis_view_sha256: swarm.hypotheses?.sha256 ?? null,
            swarm_action_view_sha256: swarm.proposed_actions?.sha256 ?? null,
            swarm_challenge_view_sha256: swarm.challenges?.sha256 ?? null,
            swarm_gap_view_sha256: swarm.gaps?.sha256 ?? null,
          }
        : {}),
    },
    trust: {
      state_integrity: 'HASH_CHAIN_VERIFIED',
      snapshot_authenticity: 'UNANCHORED',
      provider_candidates: 'INERT_NOT_PROOF',
      finding_semantic_authority: 'NONE',
      absence_of_vulnerabilities: 'NOT_ESTABLISHED',
    },
  }
  const snapshot = { ...unsigned, snapshot_sha256: digestUnleashValue(unsigned) }
  assertValidUnleashCampaignSnapshot(snapshot)
  return deeplyFrozenCopy(snapshot)
}
