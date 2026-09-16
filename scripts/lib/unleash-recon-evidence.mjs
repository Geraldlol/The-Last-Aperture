import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import Ajv2020 from 'ajv/dist/2020.js'

import { readVerifiedHttpReconEvidence } from './http-recon-controller.mjs'
import { stableJson } from './run-engine.mjs'
import {
  assertSelfBoundUnleashPlan,
  digestUnleashHttpsReconExecutionContract,
  digestUnleashValue,
  getUnleashHttpsReconExecutionContract,
} from './unleash-contracts.mjs'
import {
  assertValidUnleashEvidencePacket,
  createUnleashEvidencePacket,
} from './unleash-evidence-packet.mjs'

const SHA256 = /^[a-f0-9]{64}$/u
const INPUT_FIELDS = ['bundle', 'plan']
const COMPLETION_INPUT_FIELDS = ['bundle', 'completion', 'plan']
const COMPLETION_FIELDS = ['completion_receipt', 'evidence_packet']
const VERIFIED_FIELDS = ['schema_version', 'kind', 'run', 'observations']
const CONTROLLER_AUTHORITY_FIELDS = [
  'admitted_at',
  'effect',
  'mode',
  'policy_id',
  'policy_sha256',
  'revocation_check_id',
  'target_id',
]
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u
const VERIFIER_ID = 'verifier:last-aperture-http-recon'
const ROUTE_ID = 'https-recon'
const TOOL_ID = 'tool:https-recon'
const COMPLETION_SCHEMA_URL = new URL(
  '../../schemas/unleash-recon-completion-receipt.schema.json',
  import.meta.url,
)

export const unleashReconCompletionReceiptSchema = JSON.parse(
  readFileSync(fileURLToPath(COMPLETION_SCHEMA_URL), 'utf8'),
)
const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})
const validateCompletionReceipt = ajv.compile(unleashReconCompletionReceiptSchema)

export class UnleashReconEvidenceError extends Error {
  constructor(code, message) {
    super(message)
    this.name = 'UnleashReconEvidenceError'
    this.code = code
  }
}

function fail(code, message) {
  throw new UnleashReconEvidenceError(code, message)
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
  return keys.length === fields.length && keys.every((key) => (
    typeof key === 'string'
    && fields.includes(key)
    && descriptors[key].enumerable
    && Object.hasOwn(descriptors[key], 'value')
  ))
}

function sha256(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

function verificationContext(verified, plan, executionContract, observedAt) {
  const authority = structuredClone(verified.run.authorization)
  return {
    schema_version: '1.0.0',
    kind: 'last-aperture/http-recon-verification-context',
    route_id: ROUTE_ID,
    tool_id: TOOL_ID,
    execution_contract_sha256: digestUnleashHttpsReconExecutionContract(),
    adapter_id: executionContract.adapter_id,
    verifier_id: executionContract.verifier_id,
    run_id: verified.run.run_id,
    unleash_plan_sha256: plan.plan_sha256,
    unleash_registry_sha256: plan.registry_sha256,
    recon_plan_sha256: verified.run.plan_sha256,
    target_id: plan.target.target_id,
    target_url: plan.target.canonical_locator,
    policy_id: plan.policy_id,
    policy_sha256: plan.policy_sha256,
    authority,
    authority_sha256: digestUnleashValue(authority),
    state: verified.run.state,
    event_count: verified.run.event_chain.count,
    event_head_sha256: verified.run.event_chain.last_sha256,
    observed_at: observedAt.toISOString(),
  }
}

function assertControllerPolicyAuthority(value, plan, observedAt = null) {
  const admittedAt = Date.parse(value?.admitted_at ?? '')
  if (
    !exactRecord(value, CONTROLLER_AUTHORITY_FIELDS)
    || value.mode !== 'CONTROLLER_DEPLOYMENT_POLICY'
    || value.policy_id !== plan.policy_id
    || value.policy_sha256 !== plan.policy_sha256
    || value.target_id !== plan.target.target_id
    || value.effect !== 'OBSERVE'
    || value.revocation_check_id !== plan.authority.revocation.check_id
    || !TIMESTAMP.test(value.admitted_at ?? '')
    || !Number.isFinite(admittedAt)
    || admittedAt < Date.parse(plan.authority.valid_from)
    || admittedAt >= Date.parse(plan.authority.valid_until)
    || (observedAt !== null && admittedAt > observedAt.getTime())
  ) {
    fail(
      'UNLEASH_RECON_EVIDENCE_AUTHORITY_DRIFT',
      'verified HTTPS reconnaissance does not retain the exact admitted controller deployment policy authority',
    )
  }
  return value
}

function assertPlan(value) {
  try { assertSelfBoundUnleashPlan(value) } catch {
    fail('UNLEASH_RECON_EVIDENCE_INPUT_INVALID', 'recon evidence requires one valid self-bound unleash plan')
  }
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || !SHA256.test(value.plan_sha256 ?? '')
    || !SHA256.test(value.policy_sha256 ?? '')
    || value.target === null
    || typeof value.target !== 'object'
    || value.target.family !== 'https'
    || typeof value.target.canonical_locator !== 'string'
  ) fail('UNLEASH_RECON_EVIDENCE_INPUT_INVALID', 'recon evidence requires one bound unleash plan')
  let target
  try { target = new URL(value.target.canonical_locator) } catch {
    fail('UNLEASH_RECON_EVIDENCE_INPUT_INVALID', 'recon evidence plan target is invalid')
  }
  if (
    target.protocol !== 'https:'
    || target.href !== value.target.canonical_locator
    || target.username.length > 0
    || target.password.length > 0
    || target.search.length > 0
    || target.hash.length > 0
  ) fail('UNLEASH_RECON_EVIDENCE_INPUT_INVALID', 'recon evidence plan target is not canonical credential-free HTTPS')
  return { plan: value, target }
}

function assertPlanBoundRecon(verified, plan, target, observedAt) {
  const authority = assertControllerPolicyAuthority(
    verified.run.authorization,
    plan,
    observedAt,
  )
  const action = verified.run.actions?.[0]
  const observation = verified.observations[0]
  const observationAuthority = assertControllerPolicyAuthority(
    observation?.authority,
    plan,
    observedAt,
  )
  if (
    verified.run.target?.origin !== target.origin
    || !Array.isArray(verified.run.actions)
    || verified.run.actions.length !== 1
    || action?.method !== 'HEAD'
    || action?.url !== target.href
    || action?.safe_to_get !== false
    || Object.hasOwn(action ?? {}, 'request_headers')
    || verified.observations.length !== 1
    || observation?.method !== 'HEAD'
    || observation?.url !== target.href
    || digestUnleashValue(observationAuthority) !== digestUnleashValue(authority)
  ) fail('UNLEASH_RECON_EVIDENCE_PLAN_DRIFT', 'verified HTTPS reconnaissance does not bind the unleash target, controller authority, and sealed action')
}

function assertVerifiedRecon(value) {
  try { digestUnleashValue(value) } catch {
    fail('UNLEASH_RECON_EVIDENCE_INVALID', 'verified HTTPS reconnaissance evidence must be bounded plain JSON')
  }
  if (
    !exactRecord(value, VERIFIED_FIELDS)
    || value.schema_version !== '1.0.0'
    || value.kind !== 'last-aperture/verified-http-recon-evidence'
    || value.run === null
    || typeof value.run !== 'object'
    || Array.isArray(value.run)
    || value.run.state !== 'PROBE_PLAN_COMPLETE'
    || typeof value.run.run_id !== 'string'
    || !SHA256.test(value.run.plan_sha256 ?? '')
    || !exactRecord(value.run.authorization, CONTROLLER_AUTHORITY_FIELDS)
    || !Number.isSafeInteger(value.run.event_chain?.count)
    || value.run.event_chain.count < 1
    || !SHA256.test(value.run.event_chain?.last_sha256 ?? '')
    || !Array.isArray(value.observations)
    || value.observations.length < 1
  ) fail('UNLEASH_RECON_EVIDENCE_INVALID', 'verified HTTPS reconnaissance evidence is incomplete or invalid')
  return value
}

function evidenceProjection(verified, plan, executionContract, observedAt) {
  const content = stableJson(verified, 0)
  const context = stableJson(
    verificationContext(verified, plan, executionContract, observedAt),
    0,
  )
  const contentSha256 = sha256(content)
  return {
    content,
    context,
    content_sha256: contentSha256,
    evidence_ref: `evidence:sha256:${contentSha256}`,
    receipt_sha256: sha256(context),
    source_bytes: Buffer.byteLength(content, 'utf8'),
  }
}

function completionReceiptFor(verified, plan, executionContract, projection, observedAt) {
  const authority = structuredClone(verified.run.authorization)
  const unsigned = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-route-completion-receipt',
    route_id: ROUTE_ID,
    tool_id: TOOL_ID,
    execution_contract_sha256: digestUnleashHttpsReconExecutionContract(),
    adapter_id: executionContract.adapter_id,
    verifier_id: executionContract.verifier_id,
    recon_run_id: verified.run.run_id,
    recon_plan_sha256: verified.run.plan_sha256,
    recon_event_count: verified.run.event_chain.count,
    recon_event_head_sha256: verified.run.event_chain.last_sha256,
    unleash_plan_sha256: plan.plan_sha256,
    unleash_registry_sha256: plan.registry_sha256,
    target_id: plan.target.target_id,
    target_url: plan.target.canonical_locator,
    policy_id: plan.policy_id,
    policy_sha256: plan.policy_sha256,
    authority,
    authority_sha256: digestUnleashValue(authority),
    evidence_ref: projection.evidence_ref,
    evidence_receipt_sha256: projection.receipt_sha256,
    observed_at: observedAt.toISOString(),
  }
  return Object.freeze({
    ...unsigned,
    completion_receipt_sha256: digestUnleashValue(unsigned),
  })
}

function assertCompletionReceipt(value, plan, packet) {
  try { digestUnleashValue(value) } catch {
    fail('UNLEASH_RECON_COMPLETION_INVALID', 'recon completion receipt must be bounded plain JSON')
  }
  if (!validateCompletionReceipt(value)) {
    fail('UNLEASH_RECON_COMPLETION_INVALID', 'recon completion receipt violates its exact schema')
  }
  const executionContract = getUnleashHttpsReconExecutionContract()
  const source = packet.sources[0]
  const authority = assertControllerPolicyAuthority(value.authority, plan)
  const staticBindings = {
    route_id: ROUTE_ID,
    tool_id: TOOL_ID,
    execution_contract_sha256: digestUnleashHttpsReconExecutionContract(),
    adapter_id: executionContract.adapter_id,
    verifier_id: VERIFIER_ID,
    unleash_plan_sha256: plan.plan_sha256,
    unleash_registry_sha256: plan.registry_sha256,
    target_id: plan.target.target_id,
    target_url: plan.target.canonical_locator,
    policy_id: plan.policy_id,
    policy_sha256: plan.policy_sha256,
    authority_sha256: digestUnleashValue(authority),
    evidence_ref: source?.evidence_ref,
    evidence_receipt_sha256: source?.receipt_sha256,
    observed_at: packet.created_at,
  }
  if (Object.entries(staticBindings).some(([field, expected]) => value[field] !== expected)) {
    fail(
      'UNLEASH_RECON_COMPLETION_DRIFT',
      'recon completion differs from its plan, execution contract, verifier, policy, target, or evidence packet',
    )
  }
  const { completion_receipt_sha256: receiptSha256, ...unsigned } = value
  if (receiptSha256 !== digestUnleashValue(unsigned)) {
    fail('UNLEASH_RECON_COMPLETION_DRIFT', 'recon completion receipt digest does not match its exact content')
  }
  return value
}

function assertPacketProjection(packet, plan, projection) {
  assertValidUnleashEvidencePacket(packet)
  const source = packet.sources[0]
  if (
    packet.plan_sha256 !== plan.plan_sha256
    || packet.sources.length !== 1
    || packet.trust.input_authentication !== 'LOCALLY_HASH_CHAIN_VERIFIED'
    || source?.verifier_id !== VERIFIER_ID
    || source?.media_type !== 'application/json'
    || source?.evidence_ref !== projection.evidence_ref
    || source?.source_sha256 !== projection.content_sha256
    || source?.source_bytes !== projection.source_bytes
    || source?.receipt_sha256 !== projection.receipt_sha256
  ) {
    fail(
      'UNLEASH_RECON_COMPLETION_DRIFT',
      'recon evidence packet differs from the enrolled verifier and exact verified projection',
    )
  }
  return packet
}

function assertCompletionMatchesVerified(completion, verified, plan, target, observedAt) {
  assertPlanBoundRecon(verified, plan, target, observedAt)
  const executionContract = getUnleashHttpsReconExecutionContract()
  const projection = evidenceProjection(verified, plan, executionContract, observedAt)
  assertPacketProjection(completion.evidence_packet, plan, projection)
  const receipt = completion.completion_receipt
  if (
    receipt.recon_run_id !== verified.run.run_id
    || receipt.recon_plan_sha256 !== verified.run.plan_sha256
    || receipt.recon_event_count !== verified.run.event_chain.count
    || receipt.recon_event_head_sha256 !== verified.run.event_chain.last_sha256
    || receipt.authority_sha256 !== digestUnleashValue(verified.run.authorization)
    || digestUnleashValue(receipt.authority) !== digestUnleashValue(verified.run.authorization)
    || receipt.evidence_ref !== projection.evidence_ref
    || receipt.evidence_receipt_sha256 !== projection.receipt_sha256
  ) {
    fail(
      'UNLEASH_RECON_COMPLETION_DRIFT',
      'recon completion differs from the verified run, plan, event chain, or evidence projection',
    )
  }
  return completion
}

export function assertValidUnleashReconCompletion(value, dependencies = {}) {
  if (!exactRecord(dependencies, ['plan']) || !exactRecord(value, COMPLETION_FIELDS)) {
    fail('UNLEASH_RECON_COMPLETION_INVALID', 'recon completion must contain exactly one packet and receipt')
  }
  const { plan } = assertPlan(dependencies.plan)
  assertValidUnleashEvidencePacket(value.evidence_packet)
  if (
    value.evidence_packet.sources.length !== 1
    || value.evidence_packet.sources[0]?.verifier_id !== VERIFIER_ID
    || value.evidence_packet.sources[0]?.media_type !== 'application/json'
    || value.evidence_packet.trust.input_authentication !== 'LOCALLY_HASH_CHAIN_VERIFIED'
  ) {
    fail('UNLEASH_RECON_COMPLETION_INVALID', 'recon completion requires exactly one enrolled verifier source')
  }
  assertCompletionReceipt(value.completion_receipt, plan, value.evidence_packet)
  return value
}

function sampleNow(now) {
  if (typeof now !== 'function') fail('UNLEASH_RECON_EVIDENCE_CLOCK_INVALID', 'evidence clock must be a function')
  const value = now()
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    fail('UNLEASH_RECON_EVIDENCE_CLOCK_INVALID', 'evidence clock must return a valid Date')
  }
  return new Date(value.getTime())
}

async function buildVerifiedReconCompletion(input, dependencies = {}) {
  if (
    !exactRecord(input, INPUT_FIELDS)
    || typeof input.bundle !== 'string'
    || input.bundle.length < 1
  ) fail('UNLEASH_RECON_EVIDENCE_INPUT_INVALID', 'recon evidence requires one controller bundle and unleash plan')
  const { plan, target } = assertPlan(input.plan)
  const readVerifiedRecon = dependencies.readVerifiedRecon ?? readVerifiedHttpReconEvidence
  const createPacket = dependencies.createEvidencePacket ?? createUnleashEvidencePacket
  if (typeof readVerifiedRecon !== 'function' || typeof createPacket !== 'function') {
    fail('UNLEASH_RECON_EVIDENCE_DEPENDENCY_INVALID', 'recon evidence dependencies are unavailable')
  }
  const observedAt = sampleNow(dependencies.now ?? (() => new Date()))
  const fixedNow = () => new Date(observedAt.getTime())
  const executionContract = getUnleashHttpsReconExecutionContract()
  const first = assertVerifiedRecon(await readVerifiedRecon({ bundle: input.bundle, now: fixedNow }))
  assertPlanBoundRecon(first, plan, target, observedAt)
  const firstProjection = evidenceProjection(first, plan, executionContract, observedAt)
  let verificationCalls = 0
  const packet = await createPacket({
    plan_sha256: plan.plan_sha256,
    evidence: [{
      evidence_ref: firstProjection.evidence_ref,
      media_type: 'application/json',
      content: firstProjection.content,
      receipt: firstProjection.context,
    }],
  }, {
    now: observedAt,
    verifierId: VERIFIER_ID,
    inputVerification: 'LOCALLY_HASH_CHAIN_VERIFIED',
    verificationTimeoutMs: 5000,
    verifyEvidence: async (request) => {
      verificationCalls += 1
      if (verificationCalls !== 1) {
        fail('UNLEASH_RECON_EVIDENCE_CHANGED', 'enrolled recon evidence verifier was invoked more than once')
      }
      const second = assertVerifiedRecon(await readVerifiedRecon({ bundle: input.bundle, now: fixedNow }))
      assertPlanBoundRecon(second, plan, target, observedAt)
      const secondProjection = evidenceProjection(second, plan, executionContract, observedAt)
      if (
        request.plan_sha256 !== plan.plan_sha256
        || request.evidence_ref !== firstProjection.evidence_ref
        || request.content_sha256 !== firstProjection.content_sha256
        || request.receipt_sha256 !== firstProjection.receipt_sha256
        || request.content !== firstProjection.content
        || request.receipt !== firstProjection.context
        || secondProjection.content !== firstProjection.content
        || secondProjection.context !== firstProjection.context
      ) fail('UNLEASH_RECON_EVIDENCE_CHANGED', 'verified HTTPS reconnaissance evidence changed during packet creation')
      return {
        authenticated: true,
        verifier_id: VERIFIER_ID,
        plan_sha256: plan.plan_sha256,
        evidence_ref: request.evidence_ref,
        content_sha256: request.content_sha256,
        receipt_sha256: request.receipt_sha256,
      }
    },
  })
  if (verificationCalls !== 1) {
    fail('UNLEASH_RECON_COMPLETION_INVALID', 'recon evidence packet bypassed the enrolled verifier')
  }
  assertPacketProjection(packet, plan, firstProjection)
  const completion = Object.freeze({
    evidence_packet: packet,
    completion_receipt: completionReceiptFor(
      first,
      plan,
      executionContract,
      firstProjection,
      observedAt,
    ),
  })
  assertValidUnleashReconCompletion(completion, { plan })
  assertCompletionMatchesVerified(completion, first, plan, target, observedAt)
  return completion
}

export async function createVerifiedReconCompletion(input, dependencies = {}) {
  return buildVerifiedReconCompletion(input, dependencies)
}

/** Backward-compatible packet projection for callers that do not yet retain route receipts. */
export async function createVerifiedReconEvidencePacket(input, dependencies = {}) {
  const completion = await buildVerifiedReconCompletion(input, dependencies)
  return completion.evidence_packet
}

/**
 * Reauthenticates an exported completion against the retained controller bundle.
 * The controller should call this fixed verifier immediately before recording
 * the route as complete.
 */
export async function verifyUnleashReconCompletion(input, dependencies = {}) {
  if (
    !exactRecord(input, COMPLETION_INPUT_FIELDS)
    || typeof input.bundle !== 'string'
    || input.bundle.length < 1
  ) fail('UNLEASH_RECON_COMPLETION_INVALID', 'completion verification requires one bundle, plan, and completion')
  const { plan, target } = assertPlan(input.plan)
  const completion = assertValidUnleashReconCompletion(input.completion, { plan })
  const readVerifiedRecon = dependencies.readVerifiedRecon ?? readVerifiedHttpReconEvidence
  if (typeof readVerifiedRecon !== 'function') {
    fail('UNLEASH_RECON_EVIDENCE_DEPENDENCY_INVALID', 'recon evidence verifier is unavailable')
  }
  const observedAt = new Date(completion.completion_receipt.observed_at)
  const fixedNow = () => new Date(observedAt.getTime())
  const verified = assertVerifiedRecon(await readVerifiedRecon({
    bundle: input.bundle,
    now: fixedNow,
  }))
  assertCompletionMatchesVerified(completion, verified, plan, target, observedAt)
  return completion
}

/**
 * Reauthenticates the retained recon immediately before provider delivery and
 * returns the exact bytes behind the packet's metadata-only evidence source.
 */
export async function readVerifiedUnleashReconProviderArtifact(input, dependencies = {}) {
  if (
    !exactRecord(input, COMPLETION_INPUT_FIELDS)
    || typeof input.bundle !== 'string'
    || input.bundle.length < 1
  ) fail('UNLEASH_RECON_COMPLETION_INVALID', 'provider evidence projection requires one bundle, plan, and completion')
  const { plan, target } = assertPlan(input.plan)
  const completion = assertValidUnleashReconCompletion(input.completion, { plan })
  const readVerifiedRecon = dependencies.readVerifiedRecon ?? readVerifiedHttpReconEvidence
  if (typeof readVerifiedRecon !== 'function') {
    fail('UNLEASH_RECON_EVIDENCE_DEPENDENCY_INVALID', 'recon evidence verifier is unavailable')
  }
  const observedAt = new Date(completion.completion_receipt.observed_at)
  const fixedNow = () => new Date(observedAt.getTime())
  const verified = assertVerifiedRecon(await readVerifiedRecon({
    bundle: input.bundle,
    now: fixedNow,
  }))
  assertCompletionMatchesVerified(completion, verified, plan, target, observedAt)
  const projection = evidenceProjection(
    verified,
    plan,
    getUnleashHttpsReconExecutionContract(),
    observedAt,
  )
  const artifactId = `artifact:sha256:${projection.content_sha256}`
  return Object.freeze({
    artifact: Object.freeze({
      artifact_id: artifactId,
      kind: 'EVIDENCE',
      logical_name: 'https-recon/verified-evidence.json',
      sha256: projection.content_sha256,
      size: projection.source_bytes,
    }),
    payload: Object.freeze({
      artifact_id: artifactId,
      media_type: 'application/json',
      sha256: projection.content_sha256,
      size: projection.source_bytes,
      bytes: Buffer.from(projection.content, 'utf8'),
    }),
  })
}
