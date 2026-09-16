import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { TextDecoder } from 'node:util'
import { fileURLToPath } from 'node:url'

import Ajv2020 from 'ajv/dist/2020.js'

import {
  digestUnleashValue,
  unleashProposalSchema,
} from './unleash-contracts.mjs'
import { canonicalUnleashCampaignJson } from './unleash-campaign-storage.mjs'

const SWARM_SCHEMA_URL = new URL('../../schemas/unleash-swarm.schema.json', import.meta.url)

export const unleashSwarmSchema = JSON.parse(
  readFileSync(fileURLToPath(SWARM_SCHEMA_URL), 'utf8'),
)

export const UNLEASH_SWARM_PROTOCOL_VERSION = '2.0.0'

const roleSetBody = {
  role_set_id: 'role-set:https-v1',
  roles: [
    { role_id: 'attacker:perimeter', role_kind: 'ATTACKER', wave: 'ATTACK', order: 10 },
    { role_id: 'attacker:identity', role_kind: 'ATTACKER', wave: 'ATTACK', order: 20 },
    { role_id: 'attacker:api', role_kind: 'ATTACKER', wave: 'ATTACK', order: 30 },
    { role_id: 'attacker:data', role_kind: 'ATTACKER', wave: 'ATTACK', order: 40 },
    { role_id: 'attacker:client', role_kind: 'ATTACKER', wave: 'ATTACK', order: 50 },
    { role_id: 'reviewer:exploit-falsifier', role_kind: 'REVIEWER', wave: 'REVIEW', order: 60 },
    { role_id: 'reviewer:skeptic', role_kind: 'REVIEWER', wave: 'REVIEW', order: 70 },
  ],
}

export const UNLEASH_SWARM_ROLE_SET = deeplyFrozenCopy({
  ...roleSetBody,
  role_set_sha256: digestUnleashValue(roleSetBody),
})

export const UNLEASH_SWARM_DEFAULT_LIMITS = deeplyFrozenCopy({
  max_rounds: 2,
  max_provider_calls: 14,
  max_parallel_provider_calls: 4,
  wall_time_ms_per_call: 60_000,
  max_response_bytes_per_call: 262_144,
  max_total_response_bytes: 4_194_304,
  max_merge_json_bytes: 262_144,
  max_candidates: 512,
  max_proposed_actions: 512,
})

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})
ajv.addSchema(unleashProposalSchema)
ajv.addSchema(unleashSwarmSchema)

function validator(definition) {
  return ajv.compile({ $ref: `${unleashSwarmSchema.$id}#/$defs/${definition}` })
}

const validateBasis = validator('basis')
const validateRoleRequest = validator('roleRequest')
const validateRoleResponse = validator('roleResponse')
const validateResponseCapture = validator('responseCapture')
const validateTransportReceipt = validator('transportReceipt')
const validateLimits = validator('limits')
const validateMerge = validator('merge')
const validateTermination = validator('termination')
const validateUsage = validator('usage')
const validateCompletion = validator('completion')

const SHA256 = /^[a-f0-9]{64}$/u
const ID = /^[A-Za-z0-9][A-Za-z0-9._:/+-]{2,159}$/u
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u
const EVIDENCE_REF = /^evidence:sha256:([a-f0-9]{64})$/u
const BASIS_INPUT_FIELDS = [
  'recordedAt',
  'campaignId',
  'campaignStateRevision',
  'campaignStateSha256',
  'planSha256',
  'targetId',
  'registrySha256',
  'providerProfileSha256',
  'evidencePacketSha256',
  'completionReceiptSha256',
  'limits',
]
const REQUEST_INPUT_FIELDS = [
  'basis',
  'round',
  'roleId',
  'inputFrontierSha256',
  'inputChallengeSetSha256',
  'evidenceRefs',
  'allowedToolIds',
  'artifacts',
]
const CAPTURE_INPUT_FIELDS = [
  'request',
  'adapterId',
  'adapterVersion',
  'adapterConfigSha256',
  'capturedAt',
  'responseBytes',
  'transportReceipt',
]
const COMPLETION_INPUT_FIELDS = [
  'basis',
  'completedAt',
  'termination',
  'merge',
  'attemptLedger',
  'gaps',
  'usage',
]
const RESPONSE_CONTEXT_FIELDS = ['request', 'knownCandidateIds']
const REQUEST_CONTEXT_FIELDS = ['basis']
const CAPTURE_CONTEXT_FIELDS = ['request']
const COMPLETION_CONTEXT_FIELDS = ['basis']
const ARTIFACT_FIELDS = ['artifact_id', 'kind', 'logical_name', 'sha256', 'size']
const GAP_INPUT_FIELDS = ['round', 'role_id', 'state', 'reason_code', 'request_id']
const ATTEMPT_LEDGER_BINDING_FIELDS = [
  'event_count',
  'attempt_count',
  'response_bytes',
  'head_record_sha256',
  'ledger_sha256',
]
const PROVENANCE_GROUPS = ['candidates', 'actions', 'challenges']
const TERMINATION_STABILITY = new Map([
  ['QUIESCENT/FRONTIER_STABLE', new Set([true])],
  ['BUDGET_EXHAUSTED/MAX_ROUNDS', new Set([false])],
  ['BUDGET_EXHAUSTED/MAX_PROVIDER_CALLS', new Set([false])],
  ['BUDGET_EXHAUSTED/MAX_RESPONSE_BYTES', new Set([false])],
  ['BUDGET_EXHAUSTED/DEADLINE', new Set([false, true])],
  ['STOPPED/STOP_REQUESTED', new Set([false, true])],
  ['POLICY_BLOCKED/AUTHORITY_UNAVAILABLE', new Set([false, true])],
])

export class UnleashSwarmContractError extends Error {
  constructor(code, message, details = []) {
    super(message)
    this.name = 'UnleashSwarmContractError'
    this.code = code
    this.details = details
  }
}

function fail(code, message, details = []) {
  throw new UnleashSwarmContractError(code, message, details)
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
      [cause?.code ?? 'UNKNOWN'],
    )
  }
}

function safeMergeCanonicalCopy(value) {
  try {
    const json = canonicalUnleashCampaignJson(value)
    return {
      merge: JSON.parse(json),
      bytes: Buffer.byteLength(json, 'utf8'),
    }
  } catch (cause) {
    if (cause?.code === 'UNLEASH_STORAGE_JSON_BOUNDS') {
      fail(
        'UNLEASH_SWARM_MERGE_ARTIFACT_BUDGET_EXCEEDED',
        'swarm merge exceeds the canonical JSON artifact bound',
        [cause.code],
      )
    }
    fail(
      'UNLEASH_SWARM_VALUE_INVALID',
      'swarm merge must be bounded canonical plain JSON without accessors',
      [cause?.code ?? 'UNKNOWN'],
    )
  }
}

function schemaErrors(validate) {
  return (validate.errors ?? []).map((error) => ({
    keyword: error.keyword,
    instance_path: error.instancePath || '/',
    message: error.message ?? 'schema validation failed',
    ...(typeof error.params?.additionalProperty === 'string'
      ? { field: error.params.additionalProperty }
      : {}),
  }))
}

function assertSchema(validate, value, label) {
  if (!validate(value)) {
    const details = schemaErrors(validate)
    fail('UNLEASH_SWARM_SCHEMA_INVALID', `${label} violates its strict schema`, details)
  }
  return value
}

function canonicalTimestamp(value, label) {
  if (
    typeof value !== 'string'
    || !TIMESTAMP.test(value)
    || Number.isNaN(Date.parse(value))
    || new Date(value).toISOString() !== value
  ) fail('UNLEASH_SWARM_TIME_INVALID', `${label} must be one canonical UTC timestamp`)
  return value
}

function digestWithout(value, field) {
  const unsigned = { ...value }
  delete unsigned[field]
  return digestUnleashValue(unsigned)
}

function sameValue(left, right) {
  return digestUnleashValue(left) === digestUnleashValue(right)
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0
}

function sortedUniqueStrings(values, label, { allowEmpty = true } = {}) {
  const retained = safeCanonicalCopy(values, label)
  if (!Array.isArray(retained) || (!allowEmpty && retained.length === 0)) {
    fail('UNLEASH_SWARM_INPUT_INVALID', `${label} must be a bounded array`)
  }
  const copy = retained.map((value) => {
    if (typeof value !== 'string') fail('UNLEASH_SWARM_INPUT_INVALID', `${label} must contain strings`)
    return value
  }).sort(compareStrings)
  if (new Set(copy).size !== copy.length) {
    fail('UNLEASH_SWARM_INPUT_INVALID', `${label} must contain unique values`)
  }
  return copy
}

function isCanonicalSortedUnique(values) {
  return Array.isArray(values)
    && values.every((value, index) => typeof value === 'string'
      && (index === 0 || values[index - 1] < value))
}

function assertLimits(value) {
  const limits = safeCanonicalCopy(value, 'swarm limits')
  assertSchema(validateLimits, limits, 'swarm limits')
  if (
    limits.max_parallel_provider_calls > limits.max_provider_calls
    || limits.max_response_bytes_per_call > limits.max_total_response_bytes
  ) fail('UNLEASH_SWARM_LIMIT_INVALID', 'swarm limits contain impossible concurrency or byte relationships')
  return limits
}

function roleFor(basis, roleId) {
  const role = basis.roles.find(({ role_id: candidate }) => candidate === roleId)
  if (role === undefined) fail('UNLEASH_SWARM_ROLE_INVALID', `role is outside the sealed role set: ${roleId}`)
  return role
}

export function createUnleashSwarmBasis(input) {
  const retained = exactDataRecord(input, BASIS_INPUT_FIELDS)
  if (retained === null) {
    fail('UNLEASH_SWARM_INPUT_INVALID', 'swarm basis input must contain exact data fields')
  }
  const snapshot = safeCanonicalCopy(retained, 'swarm basis input')
  const limits = assertLimits(snapshot.limits)
  const unsigned = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-swarm-basis',
    recorded_at: canonicalTimestamp(snapshot.recordedAt, 'basis recordedAt'),
    campaign_id: snapshot.campaignId,
    campaign_state_revision: snapshot.campaignStateRevision,
    campaign_state_sha256: snapshot.campaignStateSha256,
    plan_sha256: snapshot.planSha256,
    target_id: snapshot.targetId,
    registry_sha256: snapshot.registrySha256,
    provider_protocol_version: UNLEASH_SWARM_PROTOCOL_VERSION,
    provider_profile_sha256: snapshot.providerProfileSha256,
    evidence_packet_sha256: snapshot.evidencePacketSha256,
    completion_receipt_sha256: snapshot.completionReceiptSha256,
    role_set_id: UNLEASH_SWARM_ROLE_SET.role_set_id,
    role_set_sha256: UNLEASH_SWARM_ROLE_SET.role_set_sha256,
    roles: structuredClone(UNLEASH_SWARM_ROLE_SET.roles),
    limits,
  }
  const basis = { ...unsigned, basis_sha256: digestUnleashValue(unsigned) }
  assertValidUnleashSwarmBasis(basis)
  return deeplyFrozenCopy(basis)
}

export function assertValidUnleashSwarmBasis(value) {
  const basis = safeCanonicalCopy(value, 'swarm basis')
  assertSchema(validateBasis, basis, 'swarm basis')
  canonicalTimestamp(basis.recorded_at, 'basis recorded_at')
  assertLimits(basis.limits)
  if (
    !sameValue(
      { role_set_id: basis.role_set_id, roles: basis.roles },
      roleSetBody,
    )
    || basis.role_set_sha256 !== UNLEASH_SWARM_ROLE_SET.role_set_sha256
    || basis.basis_sha256 !== digestWithout(basis, 'basis_sha256')
  ) fail('UNLEASH_SWARM_BASIS_DRIFT', 'swarm basis differs from its controller role set or digest')
  return value
}

function normalizeArtifacts(value) {
  const retained = safeCanonicalCopy(value, 'role artifacts')
  if (!Array.isArray(retained) || retained.length < 1 || retained.length > 32) {
    fail('UNLEASH_SWARM_INPUT_INVALID', 'role artifacts must be a non-empty bounded array')
  }
  const artifacts = retained.map((item) => {
    const record = exactDataRecord(item, ARTIFACT_FIELDS)
    if (record === null) fail('UNLEASH_SWARM_INPUT_INVALID', 'role artifact contains missing or unknown fields')
    return safeCanonicalCopy(record, 'role artifact')
  }).sort((left, right) => compareStrings(left.artifact_id, right.artifact_id))
  if (
    new Set(artifacts.map(({ artifact_id: id }) => id)).size !== artifacts.length
    || new Set(artifacts.map(({ logical_name: name }) => name)).size !== artifacts.length
  ) fail('UNLEASH_SWARM_INPUT_INVALID', 'role artifacts must have unique IDs and logical names')
  return artifacts
}

function requestIdentity(value) {
  return {
    basis_sha256: value.basis_sha256,
    round: value.round,
    role_id: value.role_id,
    input_frontier_sha256: value.input_frontier_sha256,
    input_challenge_set_sha256: value.input_challenge_set_sha256,
  }
}

export function createUnleashRoleRequest(input) {
  const retained = exactDataRecord(input, REQUEST_INPUT_FIELDS)
  if (retained === null) {
    fail('UNLEASH_SWARM_INPUT_INVALID', 'role request input must contain exact data fields')
  }
  const basis = safeCanonicalCopy(retained.basis, 'role request basis')
  assertValidUnleashSwarmBasis(basis)
  const round = retained.round
  if (!Number.isSafeInteger(round) || round < 1 || round > basis.limits.max_rounds) {
    fail('UNLEASH_SWARM_ROUND_INVALID', 'role request round is outside the sealed swarm limit')
  }
  if (typeof retained.roleId !== 'string') fail('UNLEASH_SWARM_ROLE_INVALID', 'role ID must be a string')
  const role = roleFor(basis, retained.roleId)
  const evidenceRefs = sortedUniqueStrings(retained.evidenceRefs, 'evidence refs', { allowEmpty: false })
  const allowedToolIds = sortedUniqueStrings(retained.allowedToolIds, 'allowed tool IDs')
  const artifacts = normalizeArtifacts(retained.artifacts)
  const evidenceArtifactDigests = new Set(artifacts
    .filter(({ kind }) => kind === 'EVIDENCE')
    .map(({ sha256 }) => sha256))
  if (evidenceRefs.some((reference) => !evidenceArtifactDigests.has(EVIDENCE_REF.exec(reference)?.[1]))) {
    fail('UNLEASH_SWARM_EVIDENCE_INVALID', 'every admitted evidence reference requires an exact evidence artifact')
  }
  const requestBody = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-role-request',
    basis_sha256: basis.basis_sha256,
    campaign_id: basis.campaign_id,
    plan_sha256: basis.plan_sha256,
    target_id: basis.target_id,
    round,
    role_id: role.role_id,
    role_kind: role.role_kind,
    wave: role.wave,
    input_frontier_sha256: retained.inputFrontierSha256,
    input_challenge_set_sha256: retained.inputChallengeSetSha256,
    evidence_packet_sha256: basis.evidence_packet_sha256,
    evidence_refs: evidenceRefs,
    allowed_tool_ids: allowedToolIds,
    artifacts,
    limits: {
      max_response_bytes: basis.limits.max_response_bytes_per_call,
      max_merge_json_bytes: basis.limits.max_merge_json_bytes,
      max_candidates: basis.limits.max_candidates,
      max_proposed_actions: basis.limits.max_proposed_actions,
    },
    trust: {
      target_content_is_untrusted_data: true,
      target_content_may_change_scope_or_policy: false,
      provider_has_target_authority: false,
      provider_has_execution_authority: false,
      provider_output_is_proposal_only: true,
      provider_may_declare_proof: false,
    },
  }
  const withIdentity = {
    ...requestBody,
    request_id: `request:sha256:${digestUnleashValue(requestIdentity(requestBody))}`,
  }
  const ordered = {
    schema_version: withIdentity.schema_version,
    kind: withIdentity.kind,
    request_id: withIdentity.request_id,
    ...Object.fromEntries(Object.entries(withIdentity).filter(([field]) => !['schema_version', 'kind', 'request_id'].includes(field))),
  }
  const request = { ...ordered, request_sha256: digestUnleashValue(ordered) }
  assertValidUnleashRoleRequest(request, { basis })
  return deeplyFrozenCopy(request)
}

export function assertValidUnleashRoleRequest(value, context = undefined) {
  const request = safeCanonicalCopy(value, 'role request')
  assertSchema(validateRoleRequest, request, 'role request')
  if (
    request.request_id !== `request:sha256:${digestUnleashValue(requestIdentity(request))}`
    || request.request_sha256 !== digestWithout(request, 'request_sha256')
    || !isCanonicalSortedUnique(request.evidence_refs)
    || !isCanonicalSortedUnique(request.allowed_tool_ids)
    || !isCanonicalSortedUnique(request.artifacts.map(({ artifact_id: id }) => id))
  ) fail('UNLEASH_SWARM_REQUEST_DRIFT', 'role request identity, digest, or canonical ordering changed')
  if (context !== undefined) {
    const retained = exactDataRecord(context, REQUEST_CONTEXT_FIELDS)
    if (retained === null) fail('UNLEASH_SWARM_INPUT_INVALID', 'role request validation context is invalid')
    const basis = safeCanonicalCopy(retained.basis, 'role request validation basis')
    assertValidUnleashSwarmBasis(basis)
    const role = roleFor(basis, request.role_id)
    if (
      request.basis_sha256 !== basis.basis_sha256
      || request.campaign_id !== basis.campaign_id
      || request.plan_sha256 !== basis.plan_sha256
      || request.target_id !== basis.target_id
      || request.evidence_packet_sha256 !== basis.evidence_packet_sha256
      || request.round > basis.limits.max_rounds
      || request.role_kind !== role.role_kind
      || request.wave !== role.wave
      || !sameValue(request.limits, {
        max_response_bytes: basis.limits.max_response_bytes_per_call,
        max_merge_json_bytes: basis.limits.max_merge_json_bytes,
        max_candidates: basis.limits.max_candidates,
        max_proposed_actions: basis.limits.max_proposed_actions,
      })
    ) fail('UNLEASH_SWARM_REQUEST_BINDING_DRIFT', 'role request differs from its sealed swarm basis')
  }
  return value
}

function proposalReferences(proposal) {
  return [
    ...proposal.candidates.flatMap(({ evidence_refs: references }) => references),
    ...proposal.actions.flatMap(({ evidence_refs: references }) => references),
  ]
}

function hasSupportedActionContract(action) {
  return action.tool_id === 'tool:https-recon'
    && sameValue(action.parameters, { method: 'HEAD' })
}

function assertResponseSemantics(response, request = undefined, knownCandidateIds = undefined) {
  const role = UNLEASH_SWARM_ROLE_SET.roles.find(({ role_id: id }) => id === response.role_id)
  if (
    role === undefined
    || role.role_kind !== response.role_kind
    || role.wave !== response.wave
    || response.proposal.plan_sha256 !== response.plan_sha256
    || response.proposal.provider_protocol_version !== UNLEASH_SWARM_PROTOCOL_VERSION
  ) fail('UNLEASH_SWARM_RESPONSE_BINDING_DRIFT', 'role response differs from its role or proposal bindings')
  const candidateIds = response.proposal.candidates.map(({ candidate_id: id }) => id)
  const actionIds = response.proposal.actions.map(({ action_id: id }) => id)
  const challengeIds = response.challenges.map(({ challenge_id: id }) => id)
  if (
    new Set(candidateIds).size !== candidateIds.length
    || new Set(actionIds).size !== actionIds.length
    || new Set(challengeIds).size !== challengeIds.length
    || response.proposal.actions.some(({ candidate_id: id }) => !candidateIds.includes(id))
    || (response.role_kind === 'ATTACKER' && response.challenges.length !== 0)
  ) fail('UNLEASH_SWARM_RESPONSE_INVALID', 'role response contains duplicate, unbound, or unauthorized records')
  if (response.proposal.actions.some((action) => !hasSupportedActionContract(action))) {
    fail(
      'UNLEASH_SWARM_ACTION_CONTRACT_UNSUPPORTED',
      'protocol-v2 actions require the exact tool:https-recon HEAD parameter contract',
    )
  }
  if (request !== undefined) {
    const bindings = [
      ['request_id', 'request_id'],
      ['request_sha256', 'request_sha256'],
      ['basis_sha256', 'basis_sha256'],
      ['plan_sha256', 'plan_sha256'],
      ['round', 'round'],
      ['role_id', 'role_id'],
      ['role_kind', 'role_kind'],
      ['wave', 'wave'],
    ]
    if (bindings.some(([responseField, requestField]) => response[responseField] !== request[requestField])) {
      fail('UNLEASH_SWARM_RESPONSE_BINDING_DRIFT', 'role response does not bind the exact request')
    }
    const admittedEvidence = new Set(request.evidence_refs)
    const admittedTools = new Set(request.allowed_tool_ids)
    if (
      proposalReferences(response.proposal).some((reference) => !admittedEvidence.has(reference))
      || response.challenges.some(({ evidence_refs: references }) => references.some((reference) => !admittedEvidence.has(reference)))
      || response.proposal.actions.some(({ tool_id: toolId }) => !admittedTools.has(toolId))
      || response.proposal.candidates.length > request.limits.max_candidates
      || response.proposal.actions.length > request.limits.max_proposed_actions
    ) fail('UNLEASH_SWARM_RESPONSE_AUTHORITY_VIOLATION', 'role response references evidence or tools outside the request')
  }
  if (knownCandidateIds !== undefined) {
    const known = new Set(knownCandidateIds)
    if (response.challenges.some(({ candidate_id: candidateId }) => !known.has(candidateId))) {
      fail('UNLEASH_SWARM_CHALLENGE_INVALID', 'review challenge references a candidate outside the supplied frontier')
    }
  }
}

export function assertValidUnleashRoleResponse(value, context = undefined) {
  const response = safeCanonicalCopy(value, 'role response')
  assertSchema(validateRoleResponse, response, 'role response')
  let request
  let knownCandidateIds
  if (context !== undefined) {
    const retained = exactDataRecord(context, RESPONSE_CONTEXT_FIELDS)
    if (retained === null) fail('UNLEASH_SWARM_INPUT_INVALID', 'role response validation context is invalid')
    request = safeCanonicalCopy(retained.request, 'role response request')
    assertValidUnleashRoleRequest(request)
    knownCandidateIds = sortedUniqueStrings(retained.knownCandidateIds, 'known candidate IDs')
  }
  assertResponseSemantics(response, request, knownCandidateIds)
  return value
}

export function snapshotUnleashRoleResponse(value, context = undefined) {
  assertValidUnleashRoleResponse(value, context)
  return deeplyFrozenCopy(safeCanonicalCopy(value, 'role response'))
}

function sha256Bytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function assertTransportReceipt(
  receipt,
  request,
  adapterId,
  adapterVersion,
  adapterConfigSha256,
  responseSha256,
) {
  assertSchema(validateTransportReceipt, receipt, 'transport receipt')
  if (
    receipt.adapter_id !== adapterId
    || receipt.adapter_version !== adapterVersion
    || receipt.adapter_config_sha256 !== adapterConfigSha256
    || receipt.request_id !== request.request_id
    || receipt.request_sha256 !== request.request_sha256
    || receipt.response_sha256 !== responseSha256
    || receipt.scope !== 'TRANSPORT_ONLY'
    || receipt.semantic_analysis_proven !== false
  ) fail('UNLEASH_SWARM_TRANSPORT_RECEIPT_INVALID', 'transport receipt differs from the exact request and response bytes')
}

export function createUnleashRoleResponseCapture(input) {
  const retained = exactDataRecord(input, CAPTURE_INPUT_FIELDS)
  if (retained === null) {
    fail('UNLEASH_SWARM_INPUT_INVALID', 'response capture input must contain exact data fields')
  }
  const request = safeCanonicalCopy(retained.request, 'capture request')
  assertValidUnleashRoleRequest(request)
  if (!Buffer.isBuffer(retained.responseBytes)) {
    fail('UNLEASH_SWARM_CAPTURE_INVALID', 'response capture requires exact Buffer bytes')
  }
  const responseBytes = Buffer.from(retained.responseBytes)
  if (responseBytes.length < 1 || responseBytes.length > request.limits.max_response_bytes) {
    fail('UNLEASH_SWARM_CAPTURE_INVALID', 'provider response bytes exceed the request limit')
  }
  const responseSha256 = sha256Bytes(responseBytes)
  const receipt = safeCanonicalCopy(retained.transportReceipt, 'transport receipt')
  assertTransportReceipt(
    receipt,
    request,
    retained.adapterId,
    retained.adapterVersion,
    retained.adapterConfigSha256,
    responseSha256,
  )
  const unsigned = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-role-response-capture',
    captured_at: canonicalTimestamp(retained.capturedAt, 'capture capturedAt'),
    request_id: request.request_id,
    request_sha256: request.request_sha256,
    basis_sha256: request.basis_sha256,
    adapter_id: retained.adapterId,
    adapter_version: retained.adapterVersion,
    adapter_config_sha256: retained.adapterConfigSha256,
    response_bytes: responseBytes.length,
    response_sha256: responseSha256,
    content_encoding: 'base64',
    content_base64: responseBytes.toString('base64'),
    transport_receipt_sha256: digestUnleashValue(receipt),
    transport_receipt_scope: 'TRANSPORT_ONLY',
    semantic_analysis_proven: false,
    transport_receipt: receipt,
  }
  const capture = { ...unsigned, capture_sha256: digestUnleashValue(unsigned) }
  assertValidUnleashRoleResponseCapture(capture, { request })
  return deeplyFrozenCopy(capture)
}

export function assertValidUnleashRoleResponseCapture(value, context = undefined) {
  const capture = safeCanonicalCopy(value, 'response capture')
  assertSchema(validateResponseCapture, capture, 'response capture')
  canonicalTimestamp(capture.captured_at, 'capture captured_at')
  const bytes = Buffer.from(capture.content_base64, 'base64')
  if (
    bytes.toString('base64') !== capture.content_base64
    || bytes.length !== capture.response_bytes
    || sha256Bytes(bytes) !== capture.response_sha256
    || capture.transport_receipt_sha256 !== digestUnleashValue(capture.transport_receipt)
    || capture.capture_sha256 !== digestWithout(capture, 'capture_sha256')
  ) fail('UNLEASH_SWARM_CAPTURE_INVALID', 'response capture bytes, receipt, or digest changed')
  let request
  if (context !== undefined) {
    const retained = exactDataRecord(context, CAPTURE_CONTEXT_FIELDS)
    if (retained === null) fail('UNLEASH_SWARM_INPUT_INVALID', 'capture validation context is invalid')
    request = safeCanonicalCopy(retained.request, 'capture validation request')
    assertValidUnleashRoleRequest(request)
    if (
      capture.request_id !== request.request_id
      || capture.request_sha256 !== request.request_sha256
      || capture.basis_sha256 !== request.basis_sha256
      || capture.response_bytes > request.limits.max_response_bytes
    ) fail('UNLEASH_SWARM_CAPTURE_BINDING_DRIFT', 'response capture differs from its exact role request')
  } else {
    request = {
      request_id: capture.request_id,
      request_sha256: capture.request_sha256,
    }
  }
  assertTransportReceipt(
    capture.transport_receipt,
    request,
    capture.adapter_id,
    capture.adapter_version,
    capture.adapter_config_sha256,
    capture.response_sha256,
  )
  return value
}

export function decodeUnleashRoleResponseCapture(capture, context) {
  const retained = exactDataRecord(context, RESPONSE_CONTEXT_FIELDS)
  if (retained === null) fail('UNLEASH_SWARM_INPUT_INVALID', 'capture decode context is invalid')
  assertValidUnleashRoleResponseCapture(capture, { request: retained.request })
  const snapshot = safeCanonicalCopy(capture, 'response capture')
  let response
  try {
    const responseBytes = Buffer.from(snapshot.content_base64, 'base64')
    const responseText = new TextDecoder('utf-8', {
      fatal: true,
      ignoreBOM: true,
    }).decode(responseBytes)
    response = JSON.parse(responseText)
  } catch (cause) {
    fail('UNLEASH_SWARM_RESPONSE_INVALID', 'captured provider response is not JSON', [cause?.name ?? 'Error'])
  }
  assertValidUnleashRoleResponse(response, context)
  return deeplyFrozenCopy(response)
}

export function assertValidUnleashSwarmMergeRecord(value, context = undefined) {
  let basis = null
  if (context !== undefined) {
    const retained = exactDataRecord(context, COMPLETION_CONTEXT_FIELDS)
    if (retained === null) fail('UNLEASH_SWARM_INPUT_INVALID', 'merge validation context is invalid')
    basis = safeCanonicalCopy(retained.basis, 'merge validation basis')
    assertValidUnleashSwarmBasis(basis)
  }
  const snapshot = safeMergeCanonicalCopy(value)
  const merge = snapshot.merge
  if (basis !== null && snapshot.bytes > basis.limits.max_merge_json_bytes) {
    fail(
      'UNLEASH_SWARM_MERGE_ARTIFACT_BUDGET_EXCEEDED',
      'swarm merge exceeds the byte budget sealed into its basis',
      [{ actual_bytes: snapshot.bytes, max_bytes: basis.limits.max_merge_json_bytes }],
    )
  }
  assertSchema(validateMerge, merge, 'swarm merge')
  if (merge.actions.some((action) => !hasSupportedActionContract(action))) {
    fail(
      'UNLEASH_SWARM_ACTION_CONTRACT_UNSUPPORTED',
      'protocol-v2 merged actions require the exact tool:https-recon HEAD parameter contract',
    )
  }
  if (merge.merge_sha256 !== digestWithout(merge, 'merge_sha256')) {
    fail('UNLEASH_SWARM_MERGE_DRIFT', 'swarm merge digest changed')
  }
  if (basis !== null) {
    if (
      merge.basis_sha256 !== basis.basis_sha256
      || merge.plan_sha256 !== basis.plan_sha256
      || merge.round > basis.limits.max_rounds
      || merge.candidate_count > basis.limits.max_candidates
      || merge.proposed_action_count > basis.limits.max_proposed_actions
    ) fail('UNLEASH_SWARM_MERGE_BINDING_DRIFT', 'swarm merge differs from its sealed basis')
  }
  return value
}

function normalizeGap(value) {
  const retained = exactDataRecord(value, GAP_INPUT_FIELDS)
  if (retained === null) fail('UNLEASH_SWARM_INPUT_INVALID', 'swarm gap contains missing or unknown fields')
  const body = safeCanonicalCopy(retained, 'swarm gap')
  return { gap_id: `gap:sha256:${digestUnleashValue(body)}`, ...body }
}

function assertExactTerminationTuple(termination) {
  const allowed = TERMINATION_STABILITY.get(`${termination.decision}/${termination.reason}`)
  if (allowed === undefined || !allowed.has(termination.stable) || termination.terminal !== true) {
    fail(
      'UNLEASH_SWARM_TERMINATION_INVALID',
      'swarm termination decision, reason, stability, and terminal state are contradictory',
    )
  }
}

function assertExactCompletionTuple(completion) {
  if (!TERMINATION_STABILITY.has(`${completion.status}/${completion.reason}`)) {
    fail('UNLEASH_SWARM_COMPLETION_DRIFT', 'swarm completion status and reason are contradictory')
  }
}

function hasExactExhaustionUsage(status, reason, usage, basis) {
  if (status !== 'BUDGET_EXHAUSTED') return true
  if (reason === 'MAX_ROUNDS') return usage.rounds_completed === basis.limits.max_rounds
  if (reason === 'MAX_PROVIDER_CALLS') {
    return usage.provider_calls_started === basis.limits.max_provider_calls
  }
  if (reason === 'MAX_RESPONSE_BYTES') {
    return usage.response_bytes === basis.limits.max_total_response_bytes
  }
  return reason === 'DEADLINE'
}

function normalizeAttemptLedgerBinding(value, basis, usage) {
  const retained = exactDataRecord(value, ATTEMPT_LEDGER_BINDING_FIELDS)
  if (
    retained === null
    || !Number.isSafeInteger(retained.event_count)
    || retained.event_count < 0
    || retained.event_count > basis.limits.max_provider_calls * 5
    || !Number.isSafeInteger(retained.attempt_count)
    || retained.attempt_count < 0
    || retained.attempt_count > basis.limits.max_provider_calls
    || retained.attempt_count > retained.event_count
    || !Number.isSafeInteger(retained.response_bytes)
    || retained.response_bytes < 0
    || retained.response_bytes !== usage.response_bytes
    || (retained.event_count === 0
      ? retained.head_record_sha256 !== null
      : !SHA256.test(retained.head_record_sha256 ?? ''))
    || !SHA256.test(retained.ledger_sha256 ?? '')
  ) fail(
    'UNLEASH_SWARM_LEDGER_BINDING_INVALID',
    'swarm completion attempt-ledger binding is invalid or differs from usage',
  )
  return {
    event_count: retained.event_count,
    attempt_count: retained.attempt_count,
    head_record_sha256: retained.head_record_sha256,
    ledger_sha256: retained.ledger_sha256,
  }
}

export function createUnleashSwarmCompletion(input) {
  const retained = exactDataRecord(input, COMPLETION_INPUT_FIELDS)
  if (retained === null) {
    fail('UNLEASH_SWARM_INPUT_INVALID', 'swarm completion input must contain exact data fields')
  }
  const basis = safeCanonicalCopy(retained.basis, 'completion basis')
  const merge = safeCanonicalCopy(retained.merge, 'completion merge')
  const termination = safeCanonicalCopy(retained.termination, 'swarm termination')
  const usage = safeCanonicalCopy(retained.usage, 'swarm usage')
  assertValidUnleashSwarmBasis(basis)
  assertValidUnleashSwarmMergeRecord(merge, { basis })
  assertSchema(validateTermination, termination, 'swarm termination')
  assertExactTerminationTuple(termination)
  assertSchema(validateUsage, usage, 'swarm usage')
  if (
    usage.rounds_completed > basis.limits.max_rounds
    || usage.provider_calls_started > basis.limits.max_provider_calls
    || usage.response_bytes > basis.limits.max_total_response_bytes
    || merge.round > Math.max(1, usage.rounds_completed)
  ) fail('UNLEASH_SWARM_USAGE_INVALID', 'swarm completion usage exceeds its sealed limits')
  if (!hasExactExhaustionUsage(termination.decision, termination.reason, usage, basis)) {
    fail('UNLEASH_SWARM_USAGE_INVALID', 'swarm completion exhaustion reason does not match its exact sealed usage limit')
  }
  const attemptLedger = normalizeAttemptLedgerBinding(retained.attemptLedger, basis, usage)
  const completedAt = canonicalTimestamp(retained.completedAt, 'completion completedAt')
  if (Date.parse(completedAt) < Date.parse(basis.recorded_at)) {
    fail('UNLEASH_SWARM_TIME_INVALID', 'swarm completion cannot predate its basis')
  }
  const gapInputs = safeCanonicalCopy(retained.gaps, 'swarm gaps')
  if (!Array.isArray(gapInputs)) fail('UNLEASH_SWARM_INPUT_INVALID', 'swarm gaps must be an array')
  const gaps = gapInputs.map(normalizeGap).sort((left, right) => compareStrings(left.gap_id, right.gap_id))
  if (new Set(gaps.map(({ gap_id: id }) => id)).size !== gaps.length) {
    fail('UNLEASH_SWARM_INPUT_INVALID', 'swarm gaps must be unique')
  }
  const unsigned = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-swarm-completion',
    completed_at: completedAt,
    basis_sha256: basis.basis_sha256,
    campaign_id: basis.campaign_id,
    plan_sha256: basis.plan_sha256,
    status: termination.decision,
    reason: termination.reason,
    merge_sha256: merge.merge_sha256,
    frontier_sha256: merge.frontier_sha256,
    challenge_set_sha256: merge.challenge_set_sha256,
    candidate_count: merge.candidate_count,
    proposed_action_count: merge.proposed_action_count,
    challenge_count: merge.challenge_count,
    attempt_ledger: attemptLedger,
    usage,
    gaps,
  }
  const completion = { ...unsigned, completion_sha256: digestUnleashValue(unsigned) }
  assertValidUnleashSwarmCompletion(completion, { basis })
  return deeplyFrozenCopy(completion)
}

export function assertValidUnleashSwarmCompletion(value, context = undefined) {
  const completion = safeCanonicalCopy(value, 'swarm completion')
  assertSchema(validateCompletion, completion, 'swarm completion')
  assertExactCompletionTuple(completion)
  canonicalTimestamp(completion.completed_at, 'completion completed_at')
  if (
    completion.completion_sha256 !== digestWithout(completion, 'completion_sha256')
    || completion.attempt_ledger.attempt_count > completion.attempt_ledger.event_count
    || (completion.attempt_ledger.event_count === 0)
      !== (completion.attempt_ledger.head_record_sha256 === null)
    || !isCanonicalSortedUnique(completion.gaps.map(({ gap_id: id }) => id))
    || completion.gaps.some(({ gap_id: gapId, ...body }) => gapId !== `gap:sha256:${digestUnleashValue(body)}`)
  ) fail('UNLEASH_SWARM_COMPLETION_DRIFT', 'swarm completion gaps, ordering, or digest changed')
  if (context !== undefined) {
    const retained = exactDataRecord(context, COMPLETION_CONTEXT_FIELDS)
    if (retained === null) fail('UNLEASH_SWARM_INPUT_INVALID', 'completion validation context is invalid')
    const basis = safeCanonicalCopy(retained.basis, 'completion validation basis')
    assertValidUnleashSwarmBasis(basis)
    if (
      completion.basis_sha256 !== basis.basis_sha256
      || completion.campaign_id !== basis.campaign_id
      || completion.plan_sha256 !== basis.plan_sha256
      || Date.parse(completion.completed_at) < Date.parse(basis.recorded_at)
      || completion.usage.rounds_completed > basis.limits.max_rounds
      || completion.usage.provider_calls_started > basis.limits.max_provider_calls
      || completion.usage.response_bytes > basis.limits.max_total_response_bytes
      || completion.attempt_ledger.event_count > basis.limits.max_provider_calls * 5
      || completion.attempt_ledger.attempt_count > basis.limits.max_provider_calls
      || !hasExactExhaustionUsage(completion.status, completion.reason, completion.usage, basis)
    ) fail('UNLEASH_SWARM_COMPLETION_BINDING_DRIFT', 'swarm completion differs from its sealed basis')
  }
  return value
}

export const unleashSwarmProvenanceGroups = Object.freeze([...PROVENANCE_GROUPS])
