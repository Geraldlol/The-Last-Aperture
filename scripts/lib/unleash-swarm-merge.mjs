import { digestUnleashValue } from './unleash-contracts.mjs'
import { canonicalUnleashCampaignJson } from './unleash-campaign-storage.mjs'
import {
  UNLEASH_SWARM_PROTOCOL_VERSION,
  assertValidUnleashRoleResponse,
  assertValidUnleashSwarmBasis,
  assertValidUnleashSwarmMergeRecord,
} from './unleash-swarm-contracts.mjs'

const MERGE_INPUT_FIELDS = ['basis', 'round', 'previous', 'responses']
const MERGE_CONTEXT_FIELDS = ['basis']
const TERMINATION_INPUT_FIELDS = [
  'beforeFrontierSha256',
  'beforeChallengeSetSha256',
  'after',
  'roundsCompleted',
  'providerCallsStarted',
  'responseBytes',
  'pendingAttemptCount',
  'stopRequested',
  'authorityAvailable',
  'deadlineExceeded',
  'basis',
]
const CONFIDENCE_ORDER = Object.freeze({ LOW: 0, MEDIUM: 1, HIGH: 2 })
const SHA256 = /^[a-f0-9]{64}$/u
const MERGE_ARTIFACT_BUDGET_ERROR = 'UNLEASH_SWARM_MERGE_ARTIFACT_BUDGET_EXCEEDED'
const CANONICAL_BUDGET_ERRORS = new Set([
  MERGE_ARTIFACT_BUDGET_ERROR,
  'UNLEASH_STORAGE_JSON_BOUNDS',
  'UNLEASH_VALUE_TOO_LARGE',
])

export class UnleashSwarmMergeError extends Error {
  constructor(code, message, details = []) {
    super(message)
    this.name = 'UnleashSwarmMergeError'
    this.code = code
    this.details = details
  }
}

function fail(code, message, details = []) {
  throw new UnleashSwarmMergeError(code, message, details)
}

function isCanonicalBudgetFailure(cause) {
  if (CANONICAL_BUDGET_ERRORS.has(cause?.code)) return true
  if (Array.isArray(cause?.details) && cause.details.some((detail) => (
    typeof detail === 'string' && CANONICAL_BUDGET_ERRORS.has(detail)
  ))) return true
  return cause?.cause !== undefined && isCanonicalBudgetFailure(cause.cause)
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
        || !descriptors[key].enumerable
        || !Object.hasOwn(descriptors[key], 'value')
      ))
    ) return null
    return Object.fromEntries(fields.map((field) => [field, descriptors[field].value]))
  } catch {
    return null
  }
}

function safeCanonicalCopy(value, label) {
  try {
    return JSON.parse(canonicalUnleashCampaignJson(value))
  } catch (cause) {
    fail(
      'UNLEASH_SWARM_VALUE_INVALID',
      `${label} must be bounded canonical plain JSON without accessors`,
      [cause?.code ?? cause?.name ?? 'UNKNOWN'],
    )
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

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0
}

function sortedUnique(values, label, maximum = 4096) {
  if (!Array.isArray(values) || values.length > maximum || values.some((value) => typeof value !== 'string')) {
    fail('UNLEASH_SWARM_MERGE_INVALID', `${label} must be a bounded string array`)
  }
  const sorted = [...values].sort(compareStrings)
  if (new Set(sorted).size !== sorted.length) {
    fail('UNLEASH_SWARM_MERGE_INVALID', `${label} must contain unique values`)
  }
  return sorted
}

function isCanonicalSortedUnique(values) {
  return Array.isArray(values)
    && values.every((value, index) => typeof value === 'string'
      && (index === 0 || values[index - 1] < value))
}

function digestWithout(value, field) {
  const unsigned = { ...value }
  delete unsigned[field]
  return digestUnleashValue(unsigned)
}

function addSources(map, itemId, sourceRefs) {
  const existing = map.get(itemId) ?? new Set()
  for (const sourceRef of sourceRefs) existing.add(sourceRef)
  if (existing.size > 256) {
    fail('UNLEASH_SWARM_PROVENANCE_LIMIT', `provenance for ${itemId} exceeds its sealed bound`)
  }
  map.set(itemId, existing)
}

function sourceReference(response, responseSha256, sourceKind, sourceId) {
  return `source:sha256:${digestUnleashValue({
    request_id: response.request_id,
    request_sha256: response.request_sha256,
    role_id: response.role_id,
    response_sha256: responseSha256,
    source_kind: sourceKind,
    source_id: sourceId,
  })}`
}

function candidateIdentity(candidate) {
  return {
    hypothesis: candidate.hypothesis,
    invariant: candidate.invariant,
    evidence_refs: sortedUnique(candidate.evidence_refs, 'candidate evidence references', 256),
  }
}

function candidateId(candidate) {
  return `candidate:sha256:${digestUnleashValue(candidateIdentity(candidate))}`
}

function actionIdentity(action, canonicalCandidateId) {
  return {
    candidate_id: canonicalCandidateId,
    tool_id: action.tool_id,
    evidence_refs: sortedUnique(action.evidence_refs, 'action evidence references', 256),
    parameters: safeCanonicalCopy(action.parameters, 'action parameters'),
    expected_observation: action.expected_observation,
  }
}

function actionId(action, canonicalCandidateId) {
  return `action:sha256:${digestUnleashValue(actionIdentity(action, canonicalCandidateId))}`
}

function challengeIdentity(challenge) {
  return {
    candidate_id: challenge.candidate_id,
    disposition: challenge.disposition,
    reason: challenge.reason,
    evidence_refs: sortedUnique(challenge.evidence_refs, 'challenge evidence references', 256),
    competing_explanations: sortedUnique(
      challenge.competing_explanations,
      'challenge competing explanations',
      64,
    ),
  }
}

function challengeId(challenge) {
  return `challenge:sha256:${digestUnleashValue(challengeIdentity(challenge))}`
}

function conservativeConfidence(left, right) {
  return CONFIDENCE_ORDER[left] <= CONFIDENCE_ORDER[right] ? left : right
}

function mergeCandidate(existing, source) {
  if (existing === undefined) {
    return {
      candidate_id: candidateId(source),
      state: 'CANDIDATE',
      title: source.title,
      hypothesis: source.hypothesis,
      invariant: source.invariant,
      provider_confidence: source.confidence,
      evidence_refs: sortedUnique(source.evidence_refs, 'candidate evidence references', 256),
      competing_explanations: sortedUnique(
        source.competing_explanations,
        'candidate competing explanations',
        64,
      ),
      proposed_action_ids: [],
    }
  }
  const explanations = [...new Set([
    ...existing.competing_explanations,
    ...source.competing_explanations,
  ])].sort(compareStrings)
  if (explanations.length > 64) {
    fail('UNLEASH_SWARM_MERGE_LIMIT', 'candidate competing explanations exceed their bound')
  }
  return {
    ...existing,
    title: compareStrings(existing.title, source.title) <= 0 ? existing.title : source.title,
    provider_confidence: conservativeConfidence(existing.provider_confidence, source.confidence),
    competing_explanations: explanations,
  }
}

function itemWithDigest(value, digestField) {
  return { ...value, [digestField]: digestUnleashValue(value) }
}

function projectProposal(planSha256, candidates, actions, basisSha256) {
  const proposalCandidates = candidates.map((candidate) => ({
    candidate_id: candidate.candidate_id,
    title: candidate.title,
    hypothesis: candidate.hypothesis,
    invariant: candidate.invariant,
    confidence: candidate.provider_confidence,
    evidence_refs: [...candidate.evidence_refs],
    competing_explanations: [...candidate.competing_explanations],
  }))
  const proposalActions = actions.map((action) => ({
    action_id: action.action_id,
    candidate_id: action.candidate_id,
    tool_id: action.tool_id,
    evidence_refs: [...action.evidence_refs],
    parameters: structuredClone(action.parameters),
    expected_observation: action.expected_observation,
  }))
  const proposalIdentity = {
    basis_sha256: basisSha256,
    candidates: proposalCandidates,
    actions: proposalActions,
  }
  return {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-proposal',
    proposal_id: `proposal:sha256:${digestUnleashValue(proposalIdentity)}`,
    plan_sha256: planSha256,
    provider_protocol_version: UNLEASH_SWARM_PROTOCOL_VERSION,
    candidates: proposalCandidates,
    actions: proposalActions,
  }
}

function provenanceMap(entries, label) {
  const map = new Map()
  for (const entry of entries) {
    if (map.has(entry.item_id)) fail('UNLEASH_SWARM_PROVENANCE_INVALID', `${label} provenance IDs must be unique`)
    map.set(entry.item_id, new Set(sortedUnique(entry.source_refs, `${label} source references`, 256)))
  }
  return map
}

function projectProvenance(map) {
  return [...map.entries()]
    .sort(([left], [right]) => compareStrings(left, right))
    .map(([item_id, sources]) => ({ item_id, source_refs: [...sources].sort(compareStrings) }))
}

function changedCount(previousItems, currentItems, idField, digestField) {
  const before = new Map(previousItems.map((item) => [item[idField], item]))
  let changed = 0
  for (const item of currentItems) {
    const prior = before.get(item[idField])
    if (prior !== undefined && prior[digestField] !== item[digestField]) changed += 1
  }
  return changed
}

function newCount(previousItems, currentItems, idField) {
  const ids = new Set(previousItems.map((item) => item[idField]))
  return currentItems.filter((item) => !ids.has(item[idField])).length
}

function deriveUnleashSwarmMerge(input) {
  const retained = exactDataRecord(input, MERGE_INPUT_FIELDS)
  if (retained === null) {
    fail('UNLEASH_SWARM_INPUT_INVALID', 'swarm merge input must contain exact data fields')
  }
  const basis = safeCanonicalCopy(retained.basis, 'swarm merge basis')
  assertValidUnleashSwarmBasis(basis)
  if (!Number.isSafeInteger(retained.round) || retained.round < 1 || retained.round > basis.limits.max_rounds) {
    fail('UNLEASH_SWARM_ROUND_INVALID', 'swarm merge round is outside its sealed basis')
  }
  const responseInputs = safeCanonicalCopy(retained.responses, 'swarm merge responses')
  if (!Array.isArray(responseInputs) || responseInputs.length > basis.limits.max_provider_calls) {
    fail('UNLEASH_SWARM_INPUT_INVALID', 'swarm merge responses must be an array')
  }
  const responses = responseInputs.map((response) => {
    assertValidUnleashRoleResponse(response)
    return safeCanonicalCopy(response, 'role response')
  }).sort((left, right) => compareStrings(left.request_id, right.request_id))
  if (new Set(responses.map(({ request_id: id }) => id)).size !== responses.length) {
    fail('UNLEASH_SWARM_RESPONSE_INVALID', 'a role request may contribute at most one response to a merge')
  }
  if (new Set(responses.map(({ role_id: id }) => id)).size !== responses.length) {
    fail('UNLEASH_SWARM_RESPONSE_INVALID', 'a role may contribute at most one response to a merge')
  }
  if (responses.some((response) => (
    response.basis_sha256 !== basis.basis_sha256
    || response.plan_sha256 !== basis.plan_sha256
    || response.round !== retained.round
  ))) fail('UNLEASH_SWARM_RESPONSE_BINDING_DRIFT', 'role response differs from this merge basis or round')

  let previous = null
  if (retained.previous !== null) {
    assertValidUnleashSwarmMerge(retained.previous, { basis })
    previous = safeCanonicalCopy(retained.previous, 'previous swarm merge')
    if (previous.round > retained.round) {
      fail('UNLEASH_SWARM_ROUND_INVALID', 'a merge cannot move backward from its previous round')
    }
  }

  const candidates = new Map((previous?.candidates ?? []).map((candidate) => {
    const { candidate_sha256: _digest, ...unsigned } = candidate
    return [candidate.candidate_id, unsigned]
  }))
  const actions = new Map((previous?.actions ?? []).map((action) => {
    const { action_sha256: _digest, ...unsigned } = action
    return [action.action_id, unsigned]
  }))
  const challenges = new Map((previous?.challenges ?? []).map((challenge) => {
    const { challenge_sha256: _digest, ...unsigned } = challenge
    return [challenge.challenge_id, unsigned]
  }))
  const candidateSources = provenanceMap(previous?.provenance.candidates ?? [], 'candidate')
  const actionSources = provenanceMap(previous?.provenance.actions ?? [], 'action')
  const challengeSources = provenanceMap(previous?.provenance.challenges ?? [], 'challenge')

  for (const response of responses) {
    const responseSha256 = digestUnleashValue(response)
    const localCandidates = new Map()
    for (const source of response.proposal.candidates) {
      const canonicalId = candidateId(source)
      localCandidates.set(source.candidate_id, canonicalId)
      candidates.set(canonicalId, mergeCandidate(candidates.get(canonicalId), source))
      addSources(
        candidateSources,
        canonicalId,
        [sourceReference(response, responseSha256, 'CANDIDATE', source.candidate_id)],
      )
    }
    for (const source of response.proposal.actions) {
      const canonicalCandidateId = localCandidates.get(source.candidate_id)
      if (canonicalCandidateId === undefined) {
        fail('UNLEASH_SWARM_ACTION_INVALID', 'proposed action references no candidate in its response')
      }
      const canonicalId = actionId(source, canonicalCandidateId)
      const unsigned = {
        action_id: canonicalId,
        state: 'PROPOSED_INERT',
        ...actionIdentity(source, canonicalCandidateId),
        executable: false,
      }
      const existing = actions.get(canonicalId)
      if (existing !== undefined && digestUnleashValue(existing) !== digestUnleashValue(unsigned)) {
        fail('UNLEASH_SWARM_ACTION_COLLISION', 'content-addressed action ID collision')
      }
      actions.set(canonicalId, unsigned)
      addSources(actionSources, canonicalId, [sourceReference(response, responseSha256, 'ACTION', source.action_id)])
    }
    for (const source of response.challenges) {
      if (!candidates.has(source.candidate_id)) {
        fail('UNLEASH_SWARM_CHALLENGE_INVALID', 'challenge references a candidate outside the merged frontier')
      }
      const canonicalId = challengeId(source)
      const unsigned = { challenge_id: canonicalId, ...challengeIdentity(source) }
      const existing = challenges.get(canonicalId)
      if (existing !== undefined && digestUnleashValue(existing) !== digestUnleashValue(unsigned)) {
        fail('UNLEASH_SWARM_CHALLENGE_COLLISION', 'content-addressed challenge ID collision')
      }
      challenges.set(canonicalId, unsigned)
      addSources(challengeSources, canonicalId, [sourceReference(response, responseSha256, 'CHALLENGE', source.challenge_id)])
    }
  }

  if (candidates.size > basis.limits.max_candidates || actions.size > basis.limits.max_proposed_actions) {
    fail('UNLEASH_SWARM_MERGE_LIMIT', 'merged candidates or actions exceed the sealed basis limit')
  }
  const actionIdsByCandidate = new Map()
  for (const action of actions.values()) {
    if (!candidates.has(action.candidate_id)) {
      fail('UNLEASH_SWARM_ACTION_INVALID', 'merged action references a missing candidate')
    }
    const ids = actionIdsByCandidate.get(action.candidate_id) ?? []
    ids.push(action.action_id)
    actionIdsByCandidate.set(action.candidate_id, ids)
  }
  const mergedCandidates = [...candidates.values()]
    .map((candidate) => itemWithDigest({
      ...candidate,
      proposed_action_ids: (actionIdsByCandidate.get(candidate.candidate_id) ?? []).sort(compareStrings),
    }, 'candidate_sha256'))
    .sort((left, right) => compareStrings(left.candidate_id, right.candidate_id))
  const mergedActions = [...actions.values()]
    .map((action) => itemWithDigest(action, 'action_sha256'))
    .sort((left, right) => compareStrings(left.action_id, right.action_id))
  const mergedChallenges = [...challenges.values()]
    .map((challenge) => itemWithDigest(challenge, 'challenge_sha256'))
    .sort((left, right) => compareStrings(left.challenge_id, right.challenge_id))
  const provenance = {
    candidates: projectProvenance(candidateSources),
    actions: projectProvenance(actionSources),
    challenges: projectProvenance(challengeSources),
  }
  const previousCandidates = previous?.candidates ?? []
  const previousActions = previous?.actions ?? []
  const previousChallenges = previous?.challenges ?? []
  const delta = {
    new_candidate_count: newCount(previousCandidates, mergedCandidates, 'candidate_id'),
    changed_candidate_count: changedCount(previousCandidates, mergedCandidates, 'candidate_id', 'candidate_sha256'),
    new_action_count: newCount(previousActions, mergedActions, 'action_id'),
    changed_action_count: changedCount(previousActions, mergedActions, 'action_id', 'action_sha256'),
    new_challenge_count: newCount(previousChallenges, mergedChallenges, 'challenge_id'),
    changed_challenge_count: changedCount(previousChallenges, mergedChallenges, 'challenge_id', 'challenge_sha256'),
  }
  const unsigned = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-swarm-merge',
    basis_sha256: basis.basis_sha256,
    round: retained.round,
    plan_sha256: basis.plan_sha256,
    provider_protocol_version: UNLEASH_SWARM_PROTOCOL_VERSION,
    proposal: projectProposal(basis.plan_sha256, mergedCandidates, mergedActions, basis.basis_sha256),
    candidate_count: mergedCandidates.length,
    proposed_action_count: mergedActions.length,
    challenge_count: mergedChallenges.length,
    candidates: mergedCandidates,
    actions: mergedActions,
    challenges: mergedChallenges,
    provenance,
    frontier_sha256: digestUnleashValue({ candidates: mergedCandidates, actions: mergedActions }),
    challenge_set_sha256: digestUnleashValue(mergedChallenges),
    delta,
  }
  const merge = { ...unsigned, merge_sha256: digestUnleashValue(unsigned) }
  assertValidUnleashSwarmMerge(merge, { basis })
  return deeplyFrozenCopy(merge)
}

export function mergeUnleashSwarmResponses(input) {
  try {
    return deriveUnleashSwarmMerge(input)
  } catch (cause) {
    if (isCanonicalBudgetFailure(cause)) {
      fail(
        MERGE_ARTIFACT_BUDGET_ERROR,
        'swarm merge exceeds its sealed canonical JSON artifact budget',
        [cause?.code ?? 'CANONICAL_JSON_BOUND'],
      )
    }
    throw cause
  }
}

function assertProposalProjection(merge) {
  const expected = projectProposal(merge.plan_sha256, merge.candidates, merge.actions, merge.basis_sha256)
  if (digestUnleashValue(expected) !== digestUnleashValue(merge.proposal)) {
    fail('UNLEASH_SWARM_PROPOSAL_DRIFT', 'merged proposal is not the exact inert frontier projection')
  }
}

function assertItemDigests(merge) {
  const candidateIds = new Set(merge.candidates.map(({ candidate_id: id }) => id))
  const actionIds = new Set(merge.actions.map(({ action_id: id }) => id))
  for (const candidate of merge.candidates) {
    const expectedActionIds = merge.actions
      .filter(({ candidate_id: id }) => id === candidate.candidate_id)
      .map(({ action_id: id }) => id)
    if (
      candidate.candidate_id !== candidateId(candidate)
      || candidate.candidate_sha256 !== digestWithout(candidate, 'candidate_sha256')
      || candidate.state !== 'CANDIDATE'
      || !isCanonicalSortedUnique(candidate.evidence_refs)
      || !isCanonicalSortedUnique(candidate.competing_explanations)
      || !isCanonicalSortedUnique(candidate.proposed_action_ids)
      || candidate.proposed_action_ids.some((id) => !actionIds.has(id))
      || digestUnleashValue(candidate.proposed_action_ids) !== digestUnleashValue(expectedActionIds)
    ) fail('UNLEASH_SWARM_CANDIDATE_DRIFT', 'merged candidate identity, digest, state, or references changed')
  }
  for (const action of merge.actions) {
    if (
      action.action_id !== actionId(action, action.candidate_id)
      || action.action_sha256 !== digestWithout(action, 'action_sha256')
      || action.state !== 'PROPOSED_INERT'
      || action.executable !== false
      || !candidateIds.has(action.candidate_id)
      || !isCanonicalSortedUnique(action.evidence_refs)
    ) fail('UNLEASH_SWARM_ACTION_DRIFT', 'merged action identity, digest, inert state, or candidate binding changed')
    const candidate = merge.candidates.find(({ candidate_id: id }) => id === action.candidate_id)
    if (!candidate.proposed_action_ids.includes(action.action_id)) {
      fail('UNLEASH_SWARM_ACTION_DRIFT', 'merged action is absent from its candidate action projection')
    }
  }
  for (const challenge of merge.challenges) {
    if (
      challenge.challenge_id !== challengeId(challenge)
      || challenge.challenge_sha256 !== digestWithout(challenge, 'challenge_sha256')
      || !candidateIds.has(challenge.candidate_id)
      || !isCanonicalSortedUnique(challenge.evidence_refs)
      || !isCanonicalSortedUnique(challenge.competing_explanations)
    ) fail('UNLEASH_SWARM_CHALLENGE_DRIFT', 'merged challenge identity, digest, or candidate binding changed')
  }
}

function assertProvenance(merge) {
  const groups = [
    ['candidates', merge.candidates.map(({ candidate_id: id }) => id)],
    ['actions', merge.actions.map(({ action_id: id }) => id)],
    ['challenges', merge.challenges.map(({ challenge_id: id }) => id)],
  ]
  for (const [group, expectedIds] of groups) {
    const entries = merge.provenance[group]
    const ids = entries.map(({ item_id: id }) => id)
    if (
      !isCanonicalSortedUnique(ids)
      || digestUnleashValue(ids) !== digestUnleashValue(expectedIds)
      || entries.some(({ source_refs: sources }) => !isCanonicalSortedUnique(sources))
    ) fail('UNLEASH_SWARM_PROVENANCE_DRIFT', `${group} provenance no longer covers the exact merged items`)
  }
}

export function assertValidUnleashSwarmMerge(value, context = undefined) {
  assertValidUnleashSwarmMergeRecord(value, context)
  const merge = safeCanonicalCopy(value, 'swarm merge')
  if (context !== undefined) {
    const retained = exactDataRecord(context, MERGE_CONTEXT_FIELDS)
    if (retained === null) fail('UNLEASH_SWARM_INPUT_INVALID', 'merge validation context is invalid')
    assertValidUnleashSwarmBasis(retained.basis)
  }
  if (
    merge.candidate_count !== merge.candidates.length
    || merge.proposed_action_count !== merge.actions.length
    || merge.challenge_count !== merge.challenges.length
    || !isCanonicalSortedUnique(merge.candidates.map(({ candidate_id: id }) => id))
    || !isCanonicalSortedUnique(merge.actions.map(({ action_id: id }) => id))
    || !isCanonicalSortedUnique(merge.challenges.map(({ challenge_id: id }) => id))
  ) fail('UNLEASH_SWARM_MERGE_DRIFT', 'swarm merge counts or canonical ordering changed')
  assertItemDigests(merge)
  assertProvenance(merge)
  assertProposalProjection(merge)
  if (
    merge.frontier_sha256 !== digestUnleashValue({ candidates: merge.candidates, actions: merge.actions })
    || merge.challenge_set_sha256 !== digestUnleashValue(merge.challenges)
  ) fail('UNLEASH_SWARM_MERGE_DRIFT', 'swarm frontier or challenge-set digest changed')
  return value
}

function assertBoolean(value, label) {
  if (typeof value !== 'boolean') fail('UNLEASH_SWARM_TERMINATION_INVALID', `${label} must be boolean`)
}

function assertCounter(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail('UNLEASH_SWARM_TERMINATION_INVALID', `${label} must be a non-negative safe integer`)
  }
}

function termination(decision, reason, stable, terminal) {
  return deeplyFrozenCopy({ decision, reason, stable, terminal })
}

export function evaluateUnleashSwarmTermination(input) {
  const retained = exactDataRecord(input, TERMINATION_INPUT_FIELDS)
  if (retained === null) {
    fail('UNLEASH_SWARM_INPUT_INVALID', 'termination input must contain exact data fields')
  }
  if (!SHA256.test(retained.beforeFrontierSha256) || !SHA256.test(retained.beforeChallengeSetSha256)) {
    fail('UNLEASH_SWARM_TERMINATION_INVALID', 'termination inputs require canonical frontier digests')
  }
  const basis = safeCanonicalCopy(retained.basis, 'termination basis')
  assertValidUnleashSwarmBasis(basis)
  assertValidUnleashSwarmMerge(retained.after, { basis })
  const after = safeCanonicalCopy(retained.after, 'termination merge')
  const limits = basis.limits
  assertCounter(retained.roundsCompleted, 'roundsCompleted')
  assertCounter(retained.providerCallsStarted, 'providerCallsStarted')
  assertCounter(retained.responseBytes, 'responseBytes')
  assertCounter(retained.pendingAttemptCount, 'pendingAttemptCount')
  assertBoolean(retained.stopRequested, 'stopRequested')
  assertBoolean(retained.authorityAvailable, 'authorityAvailable')
  assertBoolean(retained.deadlineExceeded, 'deadlineExceeded')
  const stable = retained.beforeFrontierSha256 === after.frontier_sha256
    && retained.beforeChallengeSetSha256 === after.challenge_set_sha256
  if (retained.stopRequested) return termination('STOPPED', 'STOP_REQUESTED', stable, true)
  if (!retained.authorityAvailable) return termination('POLICY_BLOCKED', 'AUTHORITY_UNAVAILABLE', stable, true)
  if (retained.deadlineExceeded) return termination('BUDGET_EXHAUSTED', 'DEADLINE', stable, true)
  if (retained.pendingAttemptCount > 0) return termination('CONTINUE', 'ATTEMPTS_PENDING', stable, false)
  if (stable) return termination('QUIESCENT', 'FRONTIER_STABLE', true, true)
  if (retained.roundsCompleted >= limits.max_rounds) {
    return termination('BUDGET_EXHAUSTED', 'MAX_ROUNDS', false, true)
  }
  if (retained.providerCallsStarted >= limits.max_provider_calls) {
    return termination('BUDGET_EXHAUSTED', 'MAX_PROVIDER_CALLS', false, true)
  }
  if (retained.responseBytes >= limits.max_total_response_bytes) {
    return termination('BUDGET_EXHAUSTED', 'MAX_RESPONSE_BYTES', false, true)
  }
  return termination('CONTINUE', 'FRONTIER_CHANGED', false, false)
}
