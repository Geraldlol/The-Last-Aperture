import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { isDeepStrictEqual } from 'node:util'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import {
  assertValidAdversarialPlan,
  digestAdversarialPlan,
  digestAdversarialTacticalAction,
} from './adversarial-validation-contracts.mjs'
import { stableJson } from './run-engine.mjs'

const EVIDENCE_SCHEMA_URL = new URL(
  '../../schemas/adversarial-evidence.schema.json',
  import.meta.url,
)
const SHA256_PATTERN = /^[a-f0-9]{64}$/
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{2,159}$/
const TERMINAL_ORACLE_STATUSES = new Set([
  'COMPLETED',
  'COMPLETED_WITH_BLOCKED_BRANCHES',
  'LIMIT_EXHAUSTED',
])
const ATTACK_RESULTS = new Set([
  'ATTACK_REPRODUCED',
  'ATTACK_NOT_REPRODUCED',
  'INCONCLUSIVE',
])
const CONTROL_RESULTS = new Set([
  'CONTROL_VALID',
  'CONTROL_INVALID',
  'INCONCLUSIVE',
])
const PUBLIC_ORACLE_RESULTS = new Map([
  ['ATTACK_REPRODUCED', 'CLAIMED_ATTACK_REPRODUCED'],
  ['ATTACK_NOT_REPRODUCED', 'CLAIMED_ATTACK_NOT_REPRODUCED'],
  ['CONTROL_VALID', 'CLAIMED_CONTROL_VALID'],
  ['CONTROL_INVALID', 'CLAIMED_CONTROL_INVALID'],
  ['INCONCLUSIVE', 'CLAIMED_INCONCLUSIVE'],
])
const MAX_JSON_DEPTH = 32
const MAX_JSON_NODES = 20_000
const MAX_PUBLIC_EVIDENCE_BYTES = 64 * 1024

export const adversarialEvidenceSchema = JSON.parse(
  readFileSync(fileURLToPath(EVIDENCE_SCHEMA_URL), 'utf8'),
)

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})
const validateEvidenceSchema = ajv.compile(adversarialEvidenceSchema)

export class AdversarialEvidenceError extends Error {
  constructor(code, message, details = []) {
    super(message)
    this.name = 'AdversarialEvidenceError'
    this.code = code
    this.details = details
  }
}

function fail(code, message, details = []) {
  throw new AdversarialEvidenceError(code, message, details)
}

function canonicalJson(value) {
  const rendered = stableJson(value, 0)
  return rendered.endsWith('\n') ? rendered.slice(0, -1) : rendered
}

function sha256Json(value) {
  return createHash('sha256')
    .update(Buffer.from(canonicalJson(value), 'utf8'))
    .digest('hex')
}

function sha256Text(value) {
  return createHash('sha256').update(String(value), 'utf8').digest('hex')
}

export function digestAdversarialOracleContract(plan) {
  return sha256Json({
    strategy_id: plan.strategy_id,
    oracle: plan.oracle,
  })
}

function canonicalBytes(value) {
  return Buffer.byteLength(canonicalJson(value), 'utf8')
}

// Observations cross an adapter boundary and can contain arbitrary target data.
// Reject executable object tricks before canonicalization; later code only reads
// a JSON snapshot, never the caller-owned value.
function assertPlainJson(root, label) {
  const active = new WeakSet()
  const stack = [{ value: root, path: '/', depth: 0 }]
  let nodes = 0

  while (stack.length > 0) {
    const entry = stack.pop()
    if (entry.exit) {
      active.delete(entry.value)
      continue
    }
    nodes += 1
    if (nodes > MAX_JSON_NODES) {
      fail('ADVERSARIAL_EVIDENCE_JSON_NODE_LIMIT', `${label} exceeds the JSON node limit`)
    }
    if (entry.depth > MAX_JSON_DEPTH) {
      fail('ADVERSARIAL_EVIDENCE_JSON_DEPTH_LIMIT', `${label} exceeds the JSON depth limit`)
    }
    const value = entry.value
    if (value === null || typeof value === 'string' || typeof value === 'boolean') continue
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) {
        fail('ADVERSARIAL_EVIDENCE_JSON_NUMBER_INVALID', `${label} contains a non-finite number`)
      }
      continue
    }
    if (typeof value !== 'object') {
      fail('ADVERSARIAL_EVIDENCE_JSON_TYPE_INVALID', `${label} must contain JSON data only`)
    }
    if (active.has(value)) {
      fail('ADVERSARIAL_EVIDENCE_JSON_CYCLE', `${label} contains a cyclic value`)
    }
    active.add(value)
    stack.push({ value, exit: true })

    const prototype = Object.getPrototypeOf(value)
    if (
      Array.isArray(value)
        ? prototype !== Array.prototype
        : prototype !== Object.prototype && prototype !== null
    ) {
      fail('ADVERSARIAL_EVIDENCE_JSON_PROTOTYPE_INVALID', `${label} must use ordinary JSON objects`)
    }
    if (Object.getOwnPropertySymbols(value).length > 0) {
      fail('ADVERSARIAL_EVIDENCE_JSON_SYMBOL_INVALID', `${label} cannot contain symbol keys`)
    }
    const descriptors = Object.getOwnPropertyDescriptors(value)
    const keys = Object.keys(value)
    if (Array.isArray(value) && keys.length !== value.length) {
      fail('ADVERSARIAL_EVIDENCE_JSON_ARRAY_INVALID', `${label} cannot contain sparse or named arrays`)
    }
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (Array.isArray(value) && key === 'length') continue
      if (!descriptor.enumerable || 'get' in descriptor || 'set' in descriptor) {
        fail(
          'ADVERSARIAL_EVIDENCE_JSON_PROPERTY_INVALID',
          `${label} cannot contain accessors or hidden properties at ${entry.path}${key}`,
        )
      }
      stack.push({
        value: descriptor.value,
        path: `${entry.path}${key}/`,
        depth: entry.depth + 1,
      })
    }
  }
}

function snapshotJson(value, label) {
  assertPlainJson(value, label)
  try {
    return JSON.parse(canonicalJson(value))
  } catch (error) {
    fail(
      'ADVERSARIAL_EVIDENCE_CANONICAL_JSON_INVALID',
      `${label} cannot be encoded as canonical JSON`,
      [error.message],
    )
  }
}

function deepFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value
  Object.freeze(value)
  for (const child of Object.values(value)) deepFreeze(child)
  return value
}

function assertInteger(value, label, { maximum }) {
  if (!Number.isInteger(value) || value < 0 || value > maximum) {
    fail('ADVERSARIAL_EVIDENCE_RUNTIME_ACCOUNTING_INVALID', `${label} is outside its finite bound`)
  }
  return value
}

function assertReceiptBound(receipt, plan, planSha256, label) {
  if (receipt === null || receipt === undefined) {
    fail(
      'ADVERSARIAL_EVIDENCE_AUTHORIZATION_REQUIRED',
      `${label} requires a controller-verified operator authorization receipt`,
    )
  }
  const requiredHashes = [
    receipt.authorization_sha256,
    receipt.plan_sha256,
    receipt.scope_revision_sha256,
    receipt.target_sha256,
  ]
  if (
    receipt.status !== 'CONTROLLER_VERIFIED'
    || receipt.authority_basis !== 'OPERATOR_DECLARATION_ACCEPTED_AS_FACT'
    || !requiredHashes.every((value) => SHA256_PATTERN.test(value ?? ''))
    || !ID_PATTERN.test(receipt.authorization_id ?? '')
    || !ID_PATTERN.test(receipt.operator_id ?? '')
    || receipt.plan_sha256 !== planSha256
    || receipt.engagement_id !== plan.engagement_id
    || receipt.scope_revision_sha256 !== plan.scope_revision_sha256
    || receipt.target_sha256 !== sha256Json(plan.target)
    || receipt.risk_class !== plan.risk_class
    || receipt.autonomy_profile !== plan.autonomy_profile
  ) {
    fail(
      'ADVERSARIAL_EVIDENCE_AUTHORIZATION_BINDING_MISMATCH',
      `${label} operator authorization receipt is not bound to the exact plan, scope, and target`,
    )
  }
  return receipt.authorization_sha256
}

function digestAction(plan, action, label) {
  const exact = Array.isArray(plan.actions)
    ? plan.actions.find(({ action_id: actionId }) => actionId === action.action_id)
    : undefined
  if (Array.isArray(plan.actions)) {
    if (exact === undefined || !isDeepStrictEqual(exact, action)) {
      fail(
        'ADVERSARIAL_EVIDENCE_ACTION_BINDING_MISMATCH',
        `${label} action is not an exact action from the sealed plan`,
      )
    }
    return sha256Json(action)
  }
  try {
    return digestAdversarialTacticalAction(action)
  } catch (error) {
    fail(
      'ADVERSARIAL_EVIDENCE_ACTION_BINDING_MISMATCH',
      `${label} adaptive action is not a canonical tactical action`,
      [error.code ?? error.message],
    )
  }
}

function missingObservation(label) {
  const digest = sha256Json({ status: 'MISSING', role: label })
  return {
    result: 'CLAIMED_MISSING',
    action_sha256: digest,
    observation_sha256: digest,
    oracle_contract_sha256: digest,
  }
}

function normalizeOracleEvaluation(plan, evaluation, observation, label) {
  if (
    evaluation.oracle_id !== plan.oracle.id
    || evaluation.target_identity_sha256 !== plan.target.identity_sha256
    || evaluation.oracle_contract_sha256 !== digestAdversarialOracleContract(plan)
    || evaluation.action === null
    || typeof evaluation.action !== 'object'
    || Array.isArray(evaluation.action)
  ) {
    fail(
      'ADVERSARIAL_EVIDENCE_ORACLE_BINDING_MISMATCH',
      `${label} is not bound to the sealed target and oracle`,
    )
  }
  const purpose = evaluation.action.purpose
  if (
    (purpose === 'attack' && !ATTACK_RESULTS.has(evaluation.result))
    || (purpose === 'control' && !CONTROL_RESULTS.has(evaluation.result))
  ) {
    fail(
      'ADVERSARIAL_EVIDENCE_ORACLE_RESULT_INVALID',
      `${label} has an oracle result that is invalid for its action purpose`,
    )
  }
  const actionSha256 = digestAction(plan, evaluation.action, label)
  return {
    purpose,
    public: {
      result: PUBLIC_ORACLE_RESULTS.get(evaluation.result),
      action_sha256: actionSha256,
      observation_sha256: sha256Json(observation),
      oracle_contract_sha256: evaluation.oracle_contract_sha256,
    },
  }
}

function normalizeExecution(plan, input, label, planSha256, authorizationRequired) {
  const execution = snapshotJson(input, label)
  if (!ID_PATTERN.test(execution.execution_id ?? '')) {
    fail('ADVERSARIAL_EVIDENCE_EXECUTION_ID_INVALID', `${label} needs a bounded execution id`)
  }
  const result = execution.runtime_result
  if (result === null || typeof result !== 'object' || Array.isArray(result)) {
    fail('ADVERSARIAL_EVIDENCE_RUNTIME_RESULT_INVALID', `${label} needs a runtime result`)
  }
  if (result.plan_sha256 !== planSha256) {
    fail(
      'ADVERSARIAL_EVIDENCE_PLAN_BINDING_MISMATCH',
      `${label} runtime result is not bound to the sealed plan`,
    )
  }
  if (typeof result.status !== 'string' || !/^[A-Z][A-Z0-9_]{2,63}$/.test(result.status)) {
    fail('ADVERSARIAL_EVIDENCE_RUNTIME_STATUS_INVALID', `${label} has an invalid terminal status`)
  }
  const considered = assertInteger(result.considered_actions, `${label} considered_actions`, {
    maximum: plan.limits.max_actions,
  })
  const dispatched = assertInteger(result.dispatched_actions, `${label} dispatched_actions`, {
    maximum: plan.limits.max_actions,
  })
  const aggregate = assertInteger(
    result.aggregate_output_bytes,
    `${label} aggregate_output_bytes`,
    { maximum: plan.limits.max_aggregate_output_bytes },
  )
  if (dispatched > considered) {
    fail(
      'ADVERSARIAL_EVIDENCE_RUNTIME_ACCOUNTING_INVALID',
      `${label} cannot dispatch more actions than it considered`,
    )
  }
  const authorizationSha256 = authorizationRequired
    ? assertReceiptBound(result.authorization_receipt, plan, planSha256, label)
    : null
  if (!Array.isArray(result.observations) || result.observations.length > plan.limits.max_actions) {
    fail(
      'ADVERSARIAL_EVIDENCE_OBSERVATIONS_INVALID',
      `${label} observations must fit within the sealed action budget`,
    )
  }
  if (result.observations.length > dispatched) {
    fail(
      'ADVERSARIAL_EVIDENCE_RUNTIME_ACCOUNTING_INVALID',
      `${label} cannot contain more observations than controller-recorded dispatches`,
    )
  }
  for (let index = 0; index < result.observations.length; index += 1) {
    if (canonicalBytes(result.observations[index]) > plan.limits.max_output_bytes) {
      fail(
        'ADVERSARIAL_EVIDENCE_OBSERVATION_TOO_LARGE',
        `${label} observation ${index} exceeds the sealed per-observation output limit`,
      )
    }
  }
  const evaluations = execution.oracle_evaluations ?? []
  if (!Array.isArray(evaluations) || evaluations.length > result.observations.length) {
    fail(
      'ADVERSARIAL_EVIDENCE_ORACLE_EVALUATIONS_INVALID',
      `${label} oracle evaluations must bind distinct recorded observations`,
    )
  }

  let attack = null
  let control = null
  const evaluatedIndexes = new Set()
  for (let index = 0; index < evaluations.length; index += 1) {
    const evaluation = evaluations[index]
    const observationIndex = evaluation?.observation_index
    if (
      !Number.isInteger(observationIndex)
      || observationIndex < 0
      || observationIndex >= result.observations.length
      || evaluatedIndexes.has(observationIndex)
    ) {
      fail(
        'ADVERSARIAL_EVIDENCE_ORACLE_EVALUATIONS_INVALID',
        `${label} oracle evaluation ${index} does not bind one distinct recorded observation`,
      )
    }
    evaluatedIndexes.add(observationIndex)
    const normalized = normalizeOracleEvaluation(
      plan,
      evaluation,
      result.observations[observationIndex],
      `${label} oracle evaluation ${index}`,
    )
    if (!['attack', 'control'].includes(normalized.purpose)) continue
    if (normalized.purpose === 'attack') {
      if (attack !== null) {
        fail(
          'ADVERSARIAL_EVIDENCE_ORACLE_OBSERVATION_DUPLICATE',
          `${label} contains multiple attack oracle observations`,
        )
      }
      attack = normalized.public
    } else {
      if (control !== null) {
        fail(
          'ADVERSARIAL_EVIDENCE_ORACLE_OBSERVATION_DUPLICATE',
          `${label} contains multiple control oracle observations`,
        )
      }
      control = normalized.public
    }
  }

  return {
    executionId: execution.execution_id,
    authorizationSha256,
    runtimeStatus: result.status,
    summary: {
      status: `CLAIMED_${result.status}`,
      execution_sha256: sha256Json(execution),
      considered_actions: considered,
      dispatched_actions: dispatched,
      aggregate_output_bytes: aggregate,
    },
    oracle: {
      attack: attack ?? missingObservation('attack'),
      control: control ?? missingObservation('control'),
    },
  }
}

function absentReplay() {
  const digest = sha256Json({ status: 'NOT_ATTEMPTED', role: 'replay' })
  return {
    executionId: null,
    authorizationSha256: null,
    runtimeStatus: 'NOT_ATTEMPTED',
    summary: {
      status: 'CLAIMED_NOT_ATTEMPTED',
      execution_sha256: digest,
      considered_actions: 0,
      dispatched_actions: 0,
      aggregate_output_bytes: 0,
    },
    oracle: {
      attack: missingObservation('replay-attack'),
      control: missingObservation('replay-control'),
    },
  }
}

function resultOf(primary, replay) {
  const primaryTerminal = TERMINAL_ORACLE_STATUSES.has(primary.runtimeStatus)
  const replayTerminal = TERMINAL_ORACLE_STATUSES.has(replay.runtimeStatus)
  const freshReplay = replay.executionId !== null
    && replay.executionId !== primary.executionId
    && replay.oracle.attack.action_sha256 === primary.oracle.attack.action_sha256
    && replay.oracle.control.action_sha256 === primary.oracle.control.action_sha256
    && replay.oracle.attack.oracle_contract_sha256 === primary.oracle.attack.oracle_contract_sha256
    && replay.oracle.control.oracle_contract_sha256 === primary.oracle.control.oracle_contract_sha256
  const controlsValid = primary.oracle.control.result === 'CLAIMED_CONTROL_VALID'
    && replay.oracle.control.result === 'CLAIMED_CONTROL_VALID'

  if (!primaryTerminal) {
    return { status: 'INCONCLUSIVE', reason: 'the primary execution did not reach an oracle-safe terminal state' }
  }
  if (primary.oracle.control.result !== 'CLAIMED_CONTROL_VALID') {
    return { status: 'INCONCLUSIVE', reason: 'the primary control was missing, invalid, or inconclusive' }
  }
  if (!replayTerminal || !freshReplay) {
    return { status: 'INCONCLUSIVE', reason: 'a fresh replay bound to the same actions and oracle contract was not established' }
  }
  if (!controlsValid) {
    return { status: 'INCONCLUSIVE', reason: 'the replay control was missing, invalid, or inconclusive' }
  }
  if (
    primary.oracle.attack.result === 'CLAIMED_ATTACK_REPRODUCED'
    && replay.oracle.attack.result === 'CLAIMED_ATTACK_REPRODUCED'
  ) {
    return { status: 'CLAIMED_CONFIRMED' }
  }
  if (
    primary.oracle.attack.result === 'CLAIMED_ATTACK_NOT_REPRODUCED'
    && replay.oracle.attack.result === 'CLAIMED_ATTACK_NOT_REPRODUCED'
  ) {
    return {
      status: 'CLAIMED_NOT_REPRODUCED',
      reason: 'the attack did not reproduce in either bound execution while both controls remained valid',
    }
  }
  return {
    status: 'INCONCLUSIVE',
    reason: 'the attack result was missing, inconclusive, or did not reproduce consistently',
  }
}

function replayStatus(replay, finding) {
  if (replay.executionId === null) return 'CLAIMED_NOT_ATTEMPTED'
  if (finding.status === 'CLAIMED_CONFIRMED') return 'CLAIMED_REPRODUCED_WITH_VALID_CONTROL'
  if (finding.status === 'CLAIMED_NOT_REPRODUCED') return 'CLAIMED_NOT_REPRODUCED_WITH_VALID_CONTROL'
  return 'CLAIMED_INCONCLUSIVE'
}

function proofTier(targetKind) {
  if (targetKind === 'repository') return 'T1'
  if (targetKind === 'local_service') return 'T2'
  return 'T4'
}

export function validateAdversarialEvidence(value) {
  const structuralErrors = (() => {
    try {
      assertPlainJson(value, 'adversarial evidence')
      if (canonicalBytes(value) > MAX_PUBLIC_EVIDENCE_BYTES) {
        return [{ code: 'DOCUMENT_SIZE_LIMIT', message: 'public evidence exceeds 64 KiB' }]
      }
      return []
    } catch (error) {
      return [{ code: error.code ?? 'DOCUMENT_INVALID', message: error.message }]
    }
  })()
  const errors = [...structuralErrors]
  if (errors.length === 0 && !validateEvidenceSchema(value)) {
    errors.push(...(validateEvidenceSchema.errors ?? []).map((error) => ({
      code: `SCHEMA_${String(error.keyword).toUpperCase()}`,
      instancePath: error.instancePath || '/',
      message: error.message ?? 'schema validation failed',
    })))
  }
  if (errors.length === 0) {
    const { evidence_sha256: _digest, ...content } = value
    if (sha256Json(content) !== value.evidence_sha256) {
      errors.push({
        code: 'EVIDENCE_DIGEST_MISMATCH',
        instancePath: '/evidence_sha256',
        message: 'evidence_sha256 does not match the canonical public evidence content',
      })
    }
  }
  return { valid: errors.length === 0, errors }
}

export function normalizeAdversarialEvidence({ plan: inputPlan, primary, replay = null } = {}) {
  const plan = snapshotJson(inputPlan, 'adversarial plan')
  assertValidAdversarialPlan(plan)
  const planSha256 = digestAdversarialPlan(plan)
  const authorizationRequired = plan.target.kind === 'live'
    || plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED'
  const normalizedPrimary = normalizeExecution(
    plan,
    primary,
    'primary execution',
    planSha256,
    authorizationRequired,
  )
  const normalizedReplay = replay === null
    ? absentReplay()
    : normalizeExecution(plan, replay, 'replay execution', planSha256, authorizationRequired)
  const findingResult = resultOf(normalizedPrimary, normalizedReplay)
  const authorizationMode = authorizationRequired
    ? 'CLAIMED_OPERATOR_AUTHORIZATION'
    : 'CLAIMED_AUTHORIZATION_NOT_REQUIRED'
  const receiptDigests = authorizationRequired
    ? [normalizedPrimary.authorizationSha256, normalizedReplay.authorizationSha256].filter(Boolean)
    : []
  const replayOracle = {
    status: replayStatus(normalizedReplay, findingResult),
    attack: normalizedReplay.oracle.attack,
    control: normalizedReplay.oracle.control,
  }
  const replaySha256 = sha256Json({
    execution: normalizedReplay.summary,
    oracle: replayOracle,
  })
  const core = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-evidence',
    candidate_id: plan.candidate_id,
    strategy_id: plan.strategy_id,
    provenance: {
      status: 'UNAUTHENTICATED_CALLER_ASSERTIONS',
      authenticity_established: false,
      custody_established: false,
    },
    target: {
      kind: plan.target.kind,
      target_id_sha256: sha256Text(plan.target.target_id),
      identity_sha256: plan.target.identity_sha256,
    },
    authorization: {
      mode: authorizationMode,
      scope_revision_sha256: plan.scope_revision_sha256,
      receipt_count: receiptDigests.length,
    },
    execution: {
      primary: normalizedPrimary.summary,
      replay: normalizedReplay.summary,
    },
    oracle: {
      oracle_id_sha256: sha256Text(plan.oracle.id),
      primary: normalizedPrimary.oracle,
      replay: replayOracle,
    },
    digests: {
      plan_sha256: planSha256,
      attack_sha256: sha256Json({
        primary: normalizedPrimary.oracle.attack,
        replay: normalizedReplay.oracle.attack,
      }),
      control_sha256: sha256Json({
        primary: normalizedPrimary.oracle.control,
        replay: normalizedReplay.oracle.control,
      }),
      target_sha256: sha256Json(plan.target),
      authorization_sha256: sha256Json({
        mode: authorizationMode,
        receipt_sha256: receiptDigests,
      }),
      limits_sha256: sha256Json(plan.limits),
      replay_sha256: replaySha256,
    },
    finding: {
      candidate_id: plan.candidate_id,
      proof_tier: proofTier(plan.target.kind),
      verification_status: findingResult.status,
      ...(findingResult.reason === undefined ? {} : { reason: findingResult.reason }),
      remediation: {
        status: 'NOT_ATTEMPTED',
        detail: 'no remediation evidence was supplied',
      },
    },
  }
  const evidence = {
    ...core,
    evidence_sha256: sha256Json(core),
  }
  const validation = validateAdversarialEvidence(evidence)
  if (!validation.valid) {
    fail(
      'ADVERSARIAL_EVIDENCE_OUTPUT_INVALID',
      'normalized adversarial evidence violated its public contract',
      validation.errors,
    )
  }
  return deepFreeze(evidence)
}

function assertNoSensitiveValue(text, values) {
  if (!Array.isArray(values)) {
    fail('ADVERSARIAL_EVIDENCE_SENSITIVE_VALUES_INVALID', 'sensitiveValues must be an array')
  }
  for (const value of values) {
    if (typeof value === 'string' && value.length > 0 && text.includes(value)) {
      fail(
        'ADVERSARIAL_EVIDENCE_PUBLIC_SECRET_LEAK',
        'refusing to emit adversarial evidence containing a sensitive value',
      )
    }
  }
}

export function renderAdversarialEvidenceMarkdown(evidence, { sensitiveValues = [] } = {}) {
  const validation = validateAdversarialEvidence(evidence)
  if (!validation.valid) {
    fail(
      'ADVERSARIAL_EVIDENCE_INVALID',
      'refusing to render invalid adversarial evidence',
      validation.errors,
    )
  }
  const lines = [
    '## Unauthenticated adversarial evidence claim',
    '',
    `Verification: \`${evidence.finding.verification_status}\`  `,
    `Provenance: \`${evidence.provenance.status}\`  `,
    `Proof tier: \`${evidence.finding.proof_tier}\`  `,
    `Target class: \`${evidence.target.kind}\`  `,
    `Authorization: \`${evidence.authorization.mode}\`  `,
    `Claimed primary execution: \`${evidence.execution.primary.status}\`  `,
    `Claimed attack oracle: \`${evidence.oracle.primary.attack.result}\`  `,
    `Claimed control oracle: \`${evidence.oracle.primary.control.result}\`  `,
    `Claimed fresh replay: \`${evidence.oracle.replay.status}\``,
    '',
    `Plan digest: \`${evidence.digests.plan_sha256}\`  `,
    `Attack digest: \`${evidence.digests.attack_sha256}\`  `,
    `Control digest: \`${evidence.digests.control_sha256}\`  `,
    `Target digest: \`${evidence.digests.target_sha256}\`  `,
    `Authorization digest: \`${evidence.digests.authorization_sha256}\`  `,
    `Limits digest: \`${evidence.digests.limits_sha256}\`  `,
    `Replay digest: \`${evidence.digests.replay_sha256}\`  `,
    `Evidence digest: \`${evidence.evidence_sha256}\``,
    '',
    ...(evidence.finding.reason === undefined
      ? []
      : [`Reason: ${evidence.finding.reason}`, '']),
    'Warning: this record normalizes caller-supplied assertions; it does not establish receipt authenticity, replay independence, or evidence custody.',
    'Raw requests, credential values, response headers, and response bodies are omitted here. Their retention in governed storage has not been established by this normalizer.',
  ]
  const report = lines.join('\n')
  assertNoSensitiveValue(report, sensitiveValues)
  return report
}
