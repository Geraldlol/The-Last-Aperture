import { createHash } from 'node:crypto'
import {
  lstatSync,
  readFileSync,
  realpathSync,
} from 'node:fs'
import { isAbsolute, join, relative, resolve } from 'node:path'
import { performance } from 'node:perf_hooks'
import { fileURLToPath } from 'node:url'
import { TextDecoder } from 'node:util'
import Ajv2020 from 'ajv/dist/2020.js'
import fc from 'fast-check'
import {
  assertPlanWithinCurrentScope,
  assertValidAdversarialCurrentScope,
  digestAdversarialCurrentScope,
} from './adversarial-cli-contracts.mjs'
import { executeAdversarialCampaign } from './adversarial-runtime.mjs'
import { digestAdversarialPlan } from './adversarial-validation-contracts.mjs'
import { runStructuredFuzz } from './fuzz-strategy.mjs'
import { verifyBoundOperatorAuthorization } from './operator-authorization.mjs'
import { stableJson } from './run-engine.mjs'

const MANIFEST_SCHEMA_URL = new URL(
  '../../schemas/adversarial-controller-enrollment.schema.json',
  import.meta.url,
)
const MAX_CONTROLLER_DOCUMENT_BYTES = 1024 * 1024
const ENROLLMENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{2,79}$/

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})
const validateManifest = ajv.compile(JSON.parse(
  readFileSync(fileURLToPath(MANIFEST_SCHEMA_URL), 'utf8'),
))

export class AdversarialCliControllerError extends Error {
  constructor(code, message, details = [], options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'AdversarialCliControllerError'
    this.code = code
    this.details = details
  }
}

function fail(code, message, details = [], options = {}) {
  throw new AdversarialCliControllerError(code, message, details, options)
}

function canonicalJson(value) {
  const rendered = stableJson(value, 0)
  return rendered.endsWith('\n') ? rendered.slice(0, -1) : rendered
}

function deepFreezeJson(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreezeJson(child)
    Object.freeze(value)
  }
  return value
}

function assertPlainControllerJson(root, label) {
  const activeAncestors = new WeakSet()
  const stack = [{ value: root, depth: 0 }]
  let nodes = 0
  while (stack.length > 0) {
    const { value, depth, exit } = stack.pop()
    if (exit) {
      activeAncestors.delete(value)
      continue
    }
    nodes += 1
    if (nodes > 20_000 || depth > 32) {
      fail('ADVERSARIAL_PLAN_SNAPSHOT_INVALID', `${label} exceeds JSON depth or node limits`)
    }
    if (value === null || typeof value === 'string' || typeof value === 'boolean') continue
    if (typeof value === 'number' && Number.isFinite(value)) continue
    if (typeof value !== 'object') {
      fail('ADVERSARIAL_PLAN_SNAPSHOT_INVALID', `${label} contains non-JSON data`)
    }
    if (activeAncestors.has(value)) {
      fail('ADVERSARIAL_PLAN_SNAPSHOT_INVALID', `${label} contains a cycle`)
    }
    activeAncestors.add(value)
    stack.push({ value, depth, exit: true })
    const isArray = Array.isArray(value)
    const prototype = Object.getPrototypeOf(value)
    if ((!isArray && prototype !== Object.prototype && prototype !== null)
      || (isArray && prototype !== Array.prototype)
      || Object.getOwnPropertySymbols(value).length > 0) {
      fail('ADVERSARIAL_PLAN_SNAPSHOT_INVALID', `${label} must contain only plain JSON data`)
    }
    for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
      if (isArray && key === 'length') continue
      if (!descriptor.enumerable || 'get' in descriptor || 'set' in descriptor) {
        fail('ADVERSARIAL_PLAN_SNAPSHOT_INVALID', `${label} contains a hidden or accessor property`)
      }
      stack.push({ value: descriptor.value, depth: depth + 1 })
    }
  }
}

function snapshotControllerPlan(value) {
  assertPlainControllerJson(value, 'adversarial plan')
  try {
    const rendered = canonicalJson(value)
    if (Buffer.byteLength(rendered, 'utf8') > MAX_CONTROLLER_DOCUMENT_BYTES) {
      fail('ADVERSARIAL_PLAN_SNAPSHOT_INVALID', 'adversarial plan exceeds its controller byte limit')
    }
    const snapshot = JSON.parse(rendered)
    if (canonicalJson(snapshot) !== rendered) {
      fail('ADVERSARIAL_PLAN_SNAPSHOT_INVALID', 'adversarial plan changed during controller ingress')
    }
    return deepFreezeJson(snapshot)
  } catch (cause) {
    if (cause instanceof AdversarialCliControllerError) throw cause
    fail(
      'ADVERSARIAL_PLAN_SNAPSHOT_INVALID',
      'controller execution requires one JSON-serializable plan snapshot',
      [],
      { cause },
    )
  }
}

function digestJson(value) {
  return createHash('sha256').update(canonicalJson(value)).digest('hex')
}

function parseCurrentTime(value) {
  const current = value instanceof Date ? new Date(value.valueOf()) : new Date(value)
  if (Number.isNaN(current.valueOf())) {
    fail('ADVERSARIAL_CONTROLLER_TIME_INVALID', 'controller operation requires a real current time')
  }
  return current.valueOf()
}

function schemaErrors(errors = []) {
  return errors.map((error) => ({
    code: `SCHEMA_${String(error.keyword).toUpperCase()}`,
    instancePath: error.instancePath || '/',
    message: error.message ?? 'schema validation failed',
    params: error.params,
  }))
}

function assertCanonicalControllerFile(path, label, maxBytes = MAX_CONTROLLER_DOCUMENT_BYTES) {
  let stat
  try {
    stat = lstatSync(path)
  } catch (cause) {
    fail('ADVERSARIAL_CONTROLLER_ARTIFACT_UNAVAILABLE', `${label} is unavailable`, [], { cause })
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    fail('ADVERSARIAL_CONTROLLER_ARTIFACT_INVALID', `${label} must be a regular non-symlink file`)
  }
  if (stat.size > maxBytes) {
    fail('ADVERSARIAL_CONTROLLER_ARTIFACT_LIMIT', `${label} exceeds its byte limit`)
  }
  let rawBytes
  let parsed
  try {
    rawBytes = readFileSync(path)
    const rawText = new TextDecoder('utf-8', { fatal: true }).decode(rawBytes)
    parsed = JSON.parse(rawText)
  } catch (cause) {
    fail('ADVERSARIAL_CONTROLLER_ARTIFACT_INVALID', `${label} is not valid JSON`, [], { cause })
  }
  if (!rawBytes.equals(Buffer.from(canonicalJson(parsed), 'utf8'))) {
    fail(
      'ADVERSARIAL_CONTROLLER_ARTIFACT_NOT_CANONICAL',
      `${label} must use exact canonical JSON bytes`,
    )
  }
  return Object.freeze(parsed)
}

function assertDirectoryInside(root, path, label) {
  const rootReal = realpathSync(root)
  const pathReal = realpathSync(path)
  const rel = relative(rootReal, pathReal)
  if (rel === '' || rel.startsWith('..') || isAbsolute(rel)) {
    fail('ADVERSARIAL_CONTROLLER_PATH_INVALID', `${label} escaped the trusted controller root`)
  }
  if (!lstatSync(path).isDirectory() || lstatSync(path).isSymbolicLink()) {
    fail('ADVERSARIAL_CONTROLLER_PATH_INVALID', `${label} must be a regular directory`)
  }
  return pathReal
}

function assertManifest(value, enrollmentId) {
  if (!validateManifest(value)) {
    fail('ADVERSARIAL_ENROLLMENT_INVALID', 'controller enrollment manifest is invalid', schemaErrors(validateManifest.errors))
  }
  if (value.enrollment_id !== enrollmentId) {
    fail('ADVERSARIAL_ENROLLMENT_ID_MISMATCH', 'controller enrollment identifier does not match its directory')
  }
  if (value.status !== 'ACTIVE') {
    fail('ADVERSARIAL_ENROLLMENT_INACTIVE', `controller enrollment is ${value.status}`)
  }
  return value
}

function loadEnrollment({
  trustedControllerRoot,
  enrollmentId,
}) {
  if (typeof trustedControllerRoot !== 'string' || !isAbsolute(trustedControllerRoot)) {
    fail('ADVERSARIAL_CONTROLLER_ROOT_INVALID', 'trusted controller root must be an absolute host-provided path')
  }
  if (!ENROLLMENT_ID_PATTERN.test(enrollmentId ?? '')) {
    fail('ADVERSARIAL_ENROLLMENT_ID_INVALID', 'enrollment id contains unsafe path characters')
  }
  const root = resolve(trustedControllerRoot)
  const enrollmentsRoot = join(root, 'enrollments')
  const directory = join(enrollmentsRoot, enrollmentId)
  try {
    assertDirectoryInside(root, enrollmentsRoot, 'controller enrollment registry')
    assertDirectoryInside(enrollmentsRoot, directory, 'controller enrollment')
  } catch (error) {
    if (error instanceof AdversarialCliControllerError) throw error
    fail('ADVERSARIAL_ENROLLMENT_UNAVAILABLE', 'controller enrollment is unavailable', [], { cause: error })
  }

  const manifest = assertManifest(
    assertCanonicalControllerFile(join(directory, 'manifest.json'), 'controller enrollment manifest'),
    enrollmentId,
  )
  const scope = assertCanonicalControllerFile(join(directory, 'scope.json'), 'controller current scope')
  assertValidAdversarialCurrentScope(scope)
  if (digestAdversarialCurrentScope(scope) !== manifest.scope_sha256) {
    fail('ADVERSARIAL_ENROLLMENT_SCOPE_DIGEST_MISMATCH', 'current scope does not match the controller enrollment manifest')
  }
  if (scope.engagement_id !== manifest.engagement_id) {
    fail('ADVERSARIAL_ENROLLMENT_BINDING_MISMATCH', 'controller scope does not bind the enrolled engagement')
  }
  return Object.freeze({ manifest, scope, directory })
}

function assertExactObjectFields(value, fields, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail('ADVERSARIAL_ADAPTER_INPUT_INVALID', `${label} must be an object`)
  }
  const actual = Object.keys(value).sort()
  const expected = [...fields].sort()
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    fail('ADVERSARIAL_ADAPTER_INPUT_INVALID', `${label} contains missing or unknown fields`)
  }
}

function buildFuzzHarness(parameters) {
  assertExactObjectFields(parameters, [
    'arbitrary',
    'max_counterexample_bytes',
    'num_runs',
    'property',
    'seed',
    'timeout_ms',
  ], 'structured-fuzz parameters')
  if (!Number.isInteger(parameters.seed) || parameters.seed < -2147483648 || parameters.seed > 2147483647) {
    fail('ADVERSARIAL_ADAPTER_INPUT_INVALID', 'structured-fuzz seed must be a signed 32-bit integer')
  }
  if (!Number.isInteger(parameters.num_runs) || parameters.num_runs < 1 || parameters.num_runs > 100_000) {
    fail('ADVERSARIAL_ADAPTER_INPUT_INVALID', 'structured-fuzz num_runs must be between 1 and 100000')
  }
  if (!Number.isInteger(parameters.timeout_ms) || parameters.timeout_ms < 1 || parameters.timeout_ms > 900_000) {
    fail('ADVERSARIAL_ADAPTER_INPUT_INVALID', 'structured-fuzz timeout_ms is invalid')
  }
  if (!Number.isInteger(parameters.max_counterexample_bytes)
    || parameters.max_counterexample_bytes < 64
    || parameters.max_counterexample_bytes > 16 * 1024 * 1024) {
    fail('ADVERSARIAL_ADAPTER_INPUT_INVALID', 'structured-fuzz counterexample limit is invalid')
  }

  let arbitrary
  if (parameters.arbitrary?.kind === 'integer') {
    assertExactObjectFields(parameters.arbitrary, ['kind', 'max', 'min'], 'integer arbitrary')
    if (!Number.isSafeInteger(parameters.arbitrary.min)
      || !Number.isSafeInteger(parameters.arbitrary.max)
      || parameters.arbitrary.min > parameters.arbitrary.max) {
      fail('ADVERSARIAL_ADAPTER_INPUT_INVALID', 'integer arbitrary bounds are invalid')
    }
    arbitrary = fc.integer({ min: parameters.arbitrary.min, max: parameters.arbitrary.max })
  } else if (parameters.arbitrary?.kind === 'json-value') {
    assertExactObjectFields(parameters.arbitrary, ['kind'], 'JSON arbitrary')
    arbitrary = fc.jsonValue()
  } else {
    fail('ADVERSARIAL_ADAPTER_INPUT_INVALID', 'structured-fuzz arbitrary kind is not built in')
  }

  let property
  if (parameters.property?.kind === 'integer-less-than') {
    assertExactObjectFields(parameters.property, ['kind', 'value'], 'integer property')
    if (parameters.arbitrary.kind !== 'integer' || !Number.isSafeInteger(parameters.property.value)) {
      fail('ADVERSARIAL_ADAPTER_INPUT_INVALID', 'integer property requires integer data and threshold')
    }
    property = (value) => value < parameters.property.value
  } else if (parameters.property?.kind === 'integer-not-equal') {
    assertExactObjectFields(parameters.property, ['kind', 'value'], 'integer property')
    if (parameters.arbitrary.kind !== 'integer' || !Number.isSafeInteger(parameters.property.value)) {
      fail('ADVERSARIAL_ADAPTER_INPUT_INVALID', 'integer property requires integer data and comparison value')
    }
    property = (value) => value !== parameters.property.value
  } else if (parameters.property?.kind === 'json-canonical-roundtrip') {
    assertExactObjectFields(parameters.property, ['kind'], 'JSON property')
    if (parameters.arbitrary.kind !== 'json-value') {
      fail('ADVERSARIAL_ADAPTER_INPUT_INVALID', 'JSON roundtrip property requires JSON data')
    }
    property = (value) => canonicalJson(JSON.parse(JSON.stringify(value))) === canonicalJson(value)
  } else {
    fail('ADVERSARIAL_ADAPTER_INPUT_INVALID', 'structured-fuzz property kind is not built in')
  }
  return { arbitrary, property }
}

const structuredFuzzAdapter = Object.freeze({
  adapter_id: 'structured-fuzz/v1',
  target_kinds: Object.freeze(['repository', 'local_service']),
  operations: Object.freeze(['fuzz.structured']),
  validateAction(action, plan) {
    if (action.operation !== 'fuzz.structured') {
      fail('ADVERSARIAL_ADAPTER_OPERATION_UNSUPPORTED', `operation ${action.operation} is not supported by structured-fuzz/v1`)
    }
    const harness = buildFuzzHarness(action.parameters)
    if (action.parameters.timeout_ms > plan.limits.max_action_time_ms) {
      fail('ADVERSARIAL_ADAPTER_INPUT_INVALID', 'fuzz timeout exceeds the sealed action timeout')
    }
    return harness
  },
  async dispatch(action, plan) {
    const harness = this.validateAction(action, plan)
    const result = await runStructuredFuzz({
      executionDomain: plan.target.kind,
      arbitrary: harness.arbitrary,
      property: harness.property,
      seed: action.parameters.seed,
      numRuns: action.parameters.num_runs,
      timeoutMs: action.parameters.timeout_ms,
      maxCounterexampleBytes: action.parameters.max_counterexample_bytes,
    })
    return {
      schema_version: '1.0.0',
      kind: 'red-team-audit/structured-fuzz-observation',
      action_id: action.action_id,
      result,
      output_bytes: Buffer.byteLength(canonicalJson(result), 'utf8'),
      escalation_triggers: [],
    }
  },
})

function resolveBuiltInAdapter(plan, enrollment) {
  if (!enrollment.manifest.allowed_adapters.includes(plan.strategy_id)) {
    fail('ADVERSARIAL_ADAPTER_NOT_ENROLLED', 'plan strategy is not enrolled by the trusted controller')
  }
  const adapter = plan.strategy_id === structuredFuzzAdapter.adapter_id
    ? structuredFuzzAdapter
    : null
  if (!adapter) {
    fail('ADVERSARIAL_ADAPTER_UNAVAILABLE', 'no built-in adapter implements the enrolled strategy')
  }
  if (!adapter.target_kinds.includes(plan.target.kind)) {
    fail(
      plan.target.kind === 'live'
        ? 'ADVERSARIAL_LIVE_ADAPTER_UNAVAILABLE'
        : 'ADVERSARIAL_ADAPTER_TARGET_UNSUPPORTED',
      plan.target.kind === 'live'
        ? 'the verified operator statement was accepted as the authority fact, but generic live dispatch is technically unavailable because no trusted transport/provider adapter is enrolled; reauthorization cannot activate a missing route'
        : `adapter does not support target kind ${plan.target.kind}`,
    )
  }
  if (plan.autonomy_profile === 'L3_MAXIMUM_AUTHORIZED') {
    fail(
      'ADVERSARIAL_L3_CLI_CONTROL_PLANE_UNAVAILABLE',
      'the verified operator statement was accepted as the authority fact, but maximum-authority CLI execution is technically unavailable until controller-owned live preflight, a trusted append-only campaign ledger, and durable checkpoint services are enrolled; reauthorization cannot activate missing controller services',
    )
  }
  if (!Array.isArray(plan.actions)) {
    fail(
      'ADVERSARIAL_EXECUTION_SHAPE_UNSUPPORTED',
      'the built-in CLI adapter requires exact actions; deterministic generator and adaptive proposal providers are not enrolled',
    )
  }
  for (const action of plan.actions) adapter.validateAction(action, plan)
  return adapter
}

export function inspectControllerEnrollment({ trustedControllerRoot, enrollmentId, now = new Date() } = {}) {
  const enrollment = loadEnrollment({ trustedControllerRoot, enrollmentId })
  const current = parseCurrentTime(now)
  let scopeStatus = 'CURRENT'
  if (current < Date.parse(enrollment.scope.validity.not_before)) scopeStatus = 'NOT_YET_VALID'
  if (current >= Date.parse(enrollment.scope.validity.not_after)) scopeStatus = 'EXPIRED'
  return Object.freeze({
    status: enrollment.manifest.status,
    enrollment_id: enrollment.manifest.enrollment_id,
    engagement_id: enrollment.manifest.engagement_id,
    scope_sha256: enrollment.manifest.scope_sha256,
    scope_status: scopeStatus,
    allowed_adapters: [...enrollment.manifest.allowed_adapters],
  })
}

export async function executeEnrolledAdversarialCampaign({
  trustedControllerRoot,
  enrollmentId,
  plan,
  approval,
  operatorAuthorization,
  now = new Date(),
  clock: legacyClock,
  wallClock: inputWallClock,
  monotonicClock: inputMonotonicClock,
} = {}) {
  if (approval !== undefined && approval !== null) {
    fail(
      'ADVERSARIAL_SIGNED_APPROVAL_RETIRED',
      'legacy signed approval execution is retired; provide one operator authorization declaration',
    )
  }
  if (operatorAuthorization === undefined || operatorAuthorization === null) {
    fail(
      'ADVERSARIAL_AUTHORIZATION_REQUIRED',
      'execution requires one operator authorization declaration',
    )
  }
  const wallClock = inputWallClock ?? legacyClock ?? (() => Date.now())
  const monotonicClock = inputMonotonicClock ?? legacyClock ?? (() => performance.now())
  const campaignPlan = snapshotControllerPlan(plan)
  const enrollment = loadEnrollment({
    trustedControllerRoot,
    enrollmentId,
  })
  const enrolledManifestSha256 = digestJson(enrollment.manifest)
  assertPlanWithinCurrentScope({ plan: campaignPlan, currentScope: enrollment.scope, now })
  if (campaignPlan.engagement_id !== enrollment.manifest.engagement_id) {
    fail('ADVERSARIAL_ENROLLMENT_ENGAGEMENT_MISMATCH', 'plan is not part of the enrolled engagement')
  }
  const operatorAuthorizationReceipt = verifyBoundOperatorAuthorization({
    value: operatorAuthorization,
    planSha256: digestAdversarialPlan(campaignPlan),
    scopeRevisionSha256: campaignPlan.scope_revision_sha256,
    target: campaignPlan.target,
    now,
    notBefore: enrollment.scope.validity.not_before,
    notAfter: enrollment.scope.validity.not_after,
    fail: (code, message) => fail(`ADVERSARIAL_OPERATOR_AUTHORIZATION_${code}`, message),
  })
  const adapter = resolveBuiltInAdapter(campaignPlan, enrollment)

  const result = await executeAdversarialCampaign({
    plan: campaignPlan,
    operatorAuthorizationReceipt,
    now,
    wallClock,
    monotonicClock,
    dispatch: async (action, runtimeContext) => {
      const actionNow = new Date(runtimeContext.controller_wall_time_ms)
      const currentEnrollment = loadEnrollment({
        trustedControllerRoot,
        enrollmentId,
      })
      assertPlanWithinCurrentScope({
        plan: campaignPlan,
        currentScope: currentEnrollment.scope,
        now: actionNow,
      })
      if (digestJson(currentEnrollment.manifest) !== enrolledManifestSha256) {
        fail('ADVERSARIAL_ENROLLMENT_CHANGED', 'controller enrollment changed after authorization verification')
      }
      return adapter.dispatch(action, campaignPlan)
    },
  })
  return Object.freeze({
    ...result,
    plan_sha256: digestAdversarialPlan(campaignPlan),
    operator_authorization_receipt: operatorAuthorizationReceipt,
    enrollment_id: enrollmentId,
    authorization_mode: 'CONTROLLER_OPERATOR_ATTESTED',
    adapter_id: adapter.adapter_id,
  })
}
