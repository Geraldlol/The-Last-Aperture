import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { isIP } from 'node:net'
import { fileURLToPath } from 'node:url'

import Ajv2020 from 'ajv/dist/2020.js'

import { CONTROLLER_DEPLOYMENT_POLICY_LIMITS } from './http-recon-contracts.mjs'
import { stableJson } from './run-engine.mjs'

const INTENT_SCHEMA_URL = new URL('../../schemas/unleash-intent.schema.json', import.meta.url)
const PLAN_SCHEMA_URL = new URL('../../schemas/unleash-plan.schema.json', import.meta.url)
const PROPOSAL_SCHEMA_URL = new URL('../../schemas/unleash-proposal.schema.json', import.meta.url)

export const unleashIntentSchema = JSON.parse(readFileSync(fileURLToPath(INTENT_SCHEMA_URL), 'utf8'))
export const unleashPlanSchema = JSON.parse(readFileSync(fileURLToPath(PLAN_SCHEMA_URL), 'utf8'))
export const unleashProposalSchema = JSON.parse(readFileSync(fileURLToPath(PROPOSAL_SCHEMA_URL), 'utf8'))

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})
for (const schema of [unleashIntentSchema, unleashPlanSchema, unleashProposalSchema]) {
  ajv.addSchema(schema)
}

const validateIntentSchema = ajv.getSchema(unleashIntentSchema.$id)
const validatePlanSchema = ajv.getSchema(unleashPlanSchema.$id)
const validateProposalSchema = ajv.getSchema(unleashProposalSchema.$id)
const SHA256 = /^[a-f0-9]{64}$/u
const ID = /^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,159}$/u
const REASON_CODE = /^[A-Z][A-Z0-9_]*$/u
const EVIDENCE_REFERENCE = /^evidence:sha256:[a-f0-9]{64}$/u
const MAX_CANONICAL_BYTES = 2 * 1024 * 1024
const MAX_NESTING_DEPTH = 32
const MAX_JSON_NODES = 100_000
const PARAMETER_SCHEMA_NONE = 'parameters:none-v1'
const PARAMETER_SCHEMA_HTTPS_RECON_HEAD = 'parameters:https-recon-head-v1'
const REGISTERED_PARAMETER_SCHEMAS = new Set([
  PARAMETER_SCHEMA_NONE,
  PARAMETER_SCHEMA_HTTPS_RECON_HEAD,
])
const ROUTE_EXECUTION_CONTRACT_VERSION = '1.0.0'
const HTTPS_RECON_LIMIT_PROFILE_ID = 'limits:http-recon-controller-deployment-policy-v1'
const HTTPS_RECON_RECOVERY_MODE = 'RECONCILE_APPEND_ONLY_BUNDLE'
const HTTPS_RECON_ADAPTER_ID = 'adapter:last-aperture-http-recon'
const HTTPS_RECON_ADAPTER_VERSION = '1.0.0'
const HTTPS_RECON_OPERATION = 'CONTROLLER_DEPLOYMENT_POLICY_HEAD'
const HTTPS_RECON_OUTPUT_SCHEMA_ID = 'output:verified-http-recon-evidence-v1'
const HTTPS_RECON_VERIFIER_ID = 'verifier:last-aperture-http-recon'
const HTTPS_RECON_INVOCATION = Object.freeze({
  kind: 'ES_MODULE_EXPORT',
  runtime: 'node',
  module: 'scripts/lib/http-recon-controller.mjs',
  export_name: 'goControllerPolicyHttpRecon',
})

export class UnleashContractError extends Error {
  constructor(code, message, details = []) {
    super(message)
    this.name = 'UnleashContractError'
    this.code = code
    this.details = details
  }
}

function fail(code, message, details = []) {
  throw new UnleashContractError(code, message, details)
}

function normalizedSchemaErrors(errors = []) {
  return errors.map((error) => ({
    keyword: error.keyword,
    instance_path: error.instancePath || '/',
    message: error.message ?? 'schema validation failed',
    ...(
      typeof error.params?.additionalProperty === 'string'
        ? { field: error.params.additionalProperty }
        : {}
    ),
  }))
}

function assertSchema(validate, value, label) {
  if (!validate(value)) {
    const details = normalizedSchemaErrors(validate.errors)
    const fields = details.flatMap(({ field }) => field === undefined ? [] : [field])
    const locations = details
      .slice(0, 8)
      .map(({ instance_path: instancePath, message }) => `${instancePath}: ${message}`)
      .join('; ')
    fail(
      'UNLEASH_SCHEMA_INVALID',
      `${label} violates its schema${fields.length > 0 ? `; unknown or invalid field: ${fields.join(', ')}` : ''}; ${locations}`,
      details,
    )
  }
  return value
}

function assertPlainJson(value, label) {
  const seen = new Set()
  const stack = [{ value, depth: 0 }]
  let nodes = 0
  let estimatedBytes = 0
  while (stack.length > 0) {
    const current = stack.pop()
    nodes += 1
    if (nodes > MAX_JSON_NODES) fail('UNLEASH_JSON_INVALID', `${label} exceeds the maximum node count`)
    if (current.depth > MAX_NESTING_DEPTH) {
      fail('UNLEASH_JSON_INVALID', `${label} exceeds the maximum nesting depth`)
    }
    if (current.value === null || typeof current.value !== 'object') {
      if (
        typeof current.value === 'number'
        && !Number.isFinite(current.value)
      ) fail('UNLEASH_JSON_INVALID', `${label} contains a non-finite number`)
      if (
        typeof current.value === 'undefined'
        || typeof current.value === 'bigint'
        || typeof current.value === 'function'
        || typeof current.value === 'symbol'
      ) {
        fail('UNLEASH_JSON_INVALID', `${label} contains a non-JSON value`)
      }
      estimatedBytes += Buffer.byteLength(JSON.stringify(current.value), 'utf8')
      if (estimatedBytes > MAX_CANONICAL_BYTES) fail('UNLEASH_VALUE_TOO_LARGE', `${label} exceeds the canonical byte limit`)
      continue
    }
    if (seen.has(current.value)) fail('UNLEASH_JSON_INVALID', `${label} contains a cycle`)
    seen.add(current.value)
    const symbols = Object.getOwnPropertySymbols(current.value)
    if (symbols.length > 0) fail('UNLEASH_JSON_INVALID', `${label} contains symbol properties`)
    const descriptors = Object.getOwnPropertyDescriptors(current.value)
    if (!Array.isArray(current.value)) {
      const prototype = Object.getPrototypeOf(current.value)
      if (prototype !== Object.prototype && prototype !== null) {
        fail('UNLEASH_JSON_INVALID', `${label} must use plain JSON objects`)
      }
      for (const key of Object.keys(descriptors)) {
        const descriptor = descriptors[key]
        if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
          fail('UNLEASH_JSON_INVALID', `${label} contains a computed or hidden property`)
        }
        if (key === '__proto__' || key === 'prototype' || key === 'constructor') {
          fail('UNLEASH_JSON_INVALID', `${label} contains a prohibited object key`)
        }
        estimatedBytes += Buffer.byteLength(JSON.stringify(key), 'utf8') + 2
      }
    } else {
      let itemCount = 0
      for (const [key, descriptor] of Object.entries(descriptors)) {
        if (key === 'length') continue
        if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value') || !/^(?:0|[1-9][0-9]*)$/u.test(key)) {
          fail('UNLEASH_JSON_INVALID', `${label} contains a non-JSON array property`)
        }
        itemCount += 1
      }
      if (itemCount !== current.value.length) fail('UNLEASH_JSON_INVALID', `${label} contains a sparse array`)
    }
    estimatedBytes += 2 + Math.max(0, Object.keys(current.value).length - 1)
    if (estimatedBytes > MAX_CANONICAL_BYTES) fail('UNLEASH_VALUE_TOO_LARGE', `${label} exceeds the canonical byte limit`)
    for (const key of Object.keys(current.value)) {
      stack.push({ value: descriptors[key].value, depth: current.depth + 1 })
    }
  }
  return value
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

function canonicalUnleashJson(value) {
  assertPlainJson(value, 'unleash value')
  const rendered = stableJson(value, 0)
  if (Buffer.byteLength(rendered, 'utf8') > MAX_CANONICAL_BYTES) {
    fail('UNLEASH_VALUE_TOO_LARGE', 'unleash value exceeds the canonical byte limit')
  }
  return rendered.endsWith('\n') ? rendered.slice(0, -1) : rendered
}

export function digestUnleashValue(value) {
  return createHash('sha256').update(canonicalUnleashJson(value), 'utf8').digest('hex')
}

function httpsReconExecutionContract() {
  return {
    schema_version: ROUTE_EXECUTION_CONTRACT_VERSION,
    adapter_id: HTTPS_RECON_ADAPTER_ID,
    adapter_version: HTTPS_RECON_ADAPTER_VERSION,
    operation: HTTPS_RECON_OPERATION,
    parameter_schema_id: PARAMETER_SCHEMA_HTTPS_RECON_HEAD,
    limit_profile_id: HTTPS_RECON_LIMIT_PROFILE_ID,
    limits: structuredClone(CONTROLLER_DEPLOYMENT_POLICY_LIMITS),
    recovery_mode: HTTPS_RECON_RECOVERY_MODE,
    output_schema_id: HTTPS_RECON_OUTPUT_SCHEMA_ID,
    verifier_id: HTTPS_RECON_VERIFIER_ID,
    invocation: structuredClone(HTTPS_RECON_INVOCATION),
  }
}

/** The exact portable adapter contract admitted for the first Unleash route. */
export function getUnleashHttpsReconExecutionContract() {
  return deeplyFrozenCopy(httpsReconExecutionContract())
}

export function assertExactUnleashHttpsReconExecutionContract(value) {
  assertPlainJson(value, 'HTTPS reconnaissance execution contract')
  if (!sameCanonicalValue(value, httpsReconExecutionContract())) {
    fail(
      'UNLEASH_EXECUTION_CONTRACT_INVALID',
      'HTTPS reconnaissance execution contract differs from the enrolled adapter',
    )
  }
  return value
}

export function digestUnleashHttpsReconExecutionContract() {
  return digestUnleashValue(httpsReconExecutionContract())
}

function ambiguousEncodedPath(value) {
  let current = value
  for (let pass = 0; pass < 8; pass += 1) {
    if (/%(?:2e|2f|5c)/iu.test(current)) return true
    if (!current.includes('%')) return false
    let decoded
    try { decoded = decodeURIComponent(current) } catch { return true }
    if (decoded === current) return false
    current = decoded
  }
  return current.includes('%')
}

function canonicalHttpsLocator(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 4096) {
    fail('UNLEASH_TARGET_INVALID', 'target must be one bounded HTTPS descriptor')
  }
  if (value.includes('\\') || /[\u0000-\u0020\u007f]/u.test(value)) {
    fail('UNLEASH_TARGET_INVALID', 'target contains ambiguous or prohibited characters')
  }
  let target
  try { target = new URL(value) } catch {
    fail('UNLEASH_TARGET_INVALID', 'target must be one absolute HTTPS URL')
  }
  if (
    target.protocol !== 'https:'
    || target.hostname.length === 0
    || isIP(
      target.hostname.startsWith('[') && target.hostname.endsWith(']')
        ? target.hostname.slice(1, -1)
        : target.hostname,
    ) !== 0
    || target.username.length > 0
    || target.password.length > 0
    || target.hash.length > 0
    || target.search.length > 0
    || target.hostname.endsWith('.')
    || target.pathname.includes('%')
    || ambiguousEncodedPath(target.pathname)
  ) {
    fail('UNLEASH_TARGET_INVALID', 'target must be an unambiguous credential-free HTTPS hostname URL')
  }
  const canonical = target.href
  if (canonical.length > 4096) fail('UNLEASH_TARGET_INVALID', 'canonical target exceeds the target limit')
  return canonical
}

function normalizeTarget(intent) {
  assertSchema(validateIntentSchema, intent, 'unleash intent')
  const canonicalLocator = canonicalHttpsLocator(intent.target)
  const identity = { family: 'https', canonical_locator: canonicalLocator }
  const identitySha256 = digestUnleashValue(identity)
  return {
    ...identity,
    target_id: `target:sha256:${identitySha256}`,
    supplied_sha256: digestUnleashValue(intent.target),
  }
}

function assertId(value, label) {
  if (typeof value !== 'string' || !ID.test(value)) fail('UNLEASH_DEPENDENCY_INVALID', `${label} is invalid`)
  return value
}

function hasExactKeys(value, fields) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.keys(value).toSorted().join(',') === [...fields].toSorted().join(',')
}

function assertUniqueStrings(values, label, { pattern = ID, maximum = 1024 } = {}) {
  if (
    !Array.isArray(values)
    || values.length < 1
    || values.length > maximum
    || values.some((value) => typeof value !== 'string' || !pattern.test(value))
    || new Set(values).size !== values.length
  ) fail('UNLEASH_DEPENDENCY_INVALID', `${label} must contain unique bounded strings`)
  return values
}

function assertBudgets(value) {
  const fields = ['max_actions', 'max_parallel_actions', 'max_duration_ms', 'max_response_bytes']
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || Object.keys(value).toSorted().join(',') !== fields.toSorted().join(',')
    || fields.some((field) => !Number.isSafeInteger(value[field]) || value[field] < 1)
    || value.max_actions > 1_000_000
    || value.max_parallel_actions > 1024
    || value.max_duration_ms > 604_800_000
    || value.max_response_bytes > 1_073_741_824
  ) fail('UNLEASH_POLICY_INVALID', 'deployment policy budgets are invalid')
  return value
}

function sameCanonicalValue(left, right) {
  return canonicalUnleashJson(left) === canonicalUnleashJson(right)
}

function assertRouteInvocation(value, route) {
  if (value === null) {
    if (route.availability.status !== 'UNAVAILABLE') {
      fail('UNLEASH_REGISTRY_INVALID', `available route ${route.route_id} has no bound invocation`)
    }
    return
  }
  if (route.route_id === 'https-recon') {
    if (
      !hasExactKeys(value, ['kind', 'runtime', 'module', 'export_name'])
      || value.kind !== 'ES_MODULE_EXPORT'
      || value.runtime !== 'node'
      || value.module !== 'scripts/lib/http-recon-controller.mjs'
      || value.export_name !== 'goControllerPolicyHttpRecon'
    ) fail('UNLEASH_REGISTRY_INVALID', 'HTTPS reconnaissance programmatic invocation identity is invalid')
    return
  }
  if (
    route.availability.status !== 'AVAILABLE'
    || !hasExactKeys(value, ['runtime', 'entrypoint', 'argument_vector', 'shell'])
    || value.runtime !== 'node'
    || typeof value.entrypoint !== 'string'
    || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(value.entrypoint)
    || value.entrypoint.includes('..')
    || value.shell !== false
    || !Array.isArray(value.argument_vector)
    || value.argument_vector.length > 128
    || value.argument_vector.some((argument) => (
      typeof argument !== 'string'
      || argument.length > 512
      || /[\u0000-\u001f\u007f]/u.test(argument)
    ))
  ) fail('UNLEASH_REGISTRY_INVALID', `execution invocation for ${route.route_id} is invalid`)
}

function assertRouteExecutionContract(route, registryVersion) {
  const value = route.execution_contract
  if (
    !hasExactKeys(value, [
      'schema_version',
      'adapter_id',
      'adapter_version',
      'operation',
      'parameter_schema_id',
      'limit_profile_id',
      'limits',
      'recovery_mode',
      'output_schema_id',
      'verifier_id',
      'invocation',
    ])
    || value.schema_version !== ROUTE_EXECUTION_CONTRACT_VERSION
    || !ID.test(value.adapter_id ?? '')
    || !ID.test(value.adapter_version ?? '')
    || !ID.test(value.operation ?? '')
    || value.parameter_schema_id !== route.parameter_schema_id
    || !ID.test(value.recovery_mode ?? '')
    || (value.limit_profile_id !== null && !ID.test(value.limit_profile_id ?? ''))
    || (value.output_schema_id !== null && !ID.test(value.output_schema_id ?? ''))
    || (value.verifier_id !== null && !ID.test(value.verifier_id ?? ''))
  ) fail('UNLEASH_REGISTRY_INVALID', `execution contract for ${route.route_id} is invalid`)
  assertRouteInvocation(value.invocation, route)
  if (route.route_id === 'https-recon') {
    if (
      value.adapter_id !== HTTPS_RECON_ADAPTER_ID
      || value.adapter_version !== HTTPS_RECON_ADAPTER_VERSION
      || value.operation !== HTTPS_RECON_OPERATION
      || value.limit_profile_id !== HTTPS_RECON_LIMIT_PROFILE_ID
      || value.output_schema_id !== HTTPS_RECON_OUTPUT_SCHEMA_ID
      || value.verifier_id !== HTTPS_RECON_VERIFIER_ID
      || value.recovery_mode !== HTTPS_RECON_RECOVERY_MODE
      || !sameCanonicalValue(value.invocation, HTTPS_RECON_INVOCATION)
      || !sameCanonicalValue(value.limits, CONTROLLER_DEPLOYMENT_POLICY_LIMITS)
    ) fail('UNLEASH_REGISTRY_INVALID', 'HTTPS reconnaissance execution contract differs from the sealed adapter')
  } else if (
    value.adapter_id !== `adapter:last-aperture:${route.route_id}`
    || value.adapter_version !== registryVersion
    || value.operation !== route.route_id
    || value.limit_profile_id !== null
    || value.limits !== null
    || value.output_schema_id !== null
    || value.verifier_id !== null
  ) {
    fail('UNLEASH_REGISTRY_INVALID', `route ${route.route_id} names an unsupported execution identity`)
  }
}

function assertRegistry(registry) {
  assertPlainJson(registry, 'unleash registry')
  if (
    !hasExactKeys(registry, ['schema_version', 'registry_version', 'routes'])
    || registry.schema_version !== '1.0.0'
    || !ID.test(registry.registry_version ?? '')
    || !Array.isArray(registry.routes)
    || registry.routes.length < 1
    || registry.routes.length > 1024
  ) fail('UNLEASH_REGISTRY_INVALID', 'tool registry is invalid')
  const routeIds = new Set()
  const toolIds = new Set()
  let priorOrder = -1
  for (const route of registry.routes) {
    const baseFields = [
      'availability', 'execution_contract', 'order', 'parameter_schema_id', 'required_effect',
      'route_id', 'target_families', 'tool_id',
    ]
    const extendedFields = [...baseFields, 'dependencies', 'required_material']
    const actualFields = Object.keys(route ?? {}).toSorted().join(',')
    if (
      route === null
      || typeof route !== 'object'
      || Array.isArray(route)
      || ![
        baseFields.toSorted().join(','),
        extendedFields.toSorted().join(','),
      ].includes(actualFields)
      || !ID.test(route.route_id ?? '')
      || !ID.test(route.tool_id ?? '')
      || !Number.isSafeInteger(route.order)
      || route.order <= priorOrder
      || routeIds.has(route.route_id)
      || toolIds.has(route.tool_id)
      || !REGISTERED_PARAMETER_SCHEMAS.has(route.parameter_schema_id)
      || !ID.test(route.required_effect ?? '')
    ) fail('UNLEASH_REGISTRY_INVALID', 'tool registry route identity or order is invalid')
    assertUniqueStrings(route.target_families, `target families for ${route.route_id}`)
    if (Object.hasOwn(route, 'dependencies')) {
      if (!Array.isArray(route.dependencies) || route.dependencies.length > 1024) {
        fail('UNLEASH_REGISTRY_INVALID', `dependencies for ${route.route_id} are invalid`)
      }
      if (
        route.dependencies.some((dependency) => typeof dependency !== 'string' || !ID.test(dependency))
        || new Set(route.dependencies).size !== route.dependencies.length
      ) fail('UNLEASH_REGISTRY_INVALID', `dependencies for ${route.route_id} are invalid`)
      if (route.dependencies.some((dependency) => !routeIds.has(dependency))) {
        fail('UNLEASH_REGISTRY_INVALID', `dependencies for ${route.route_id} must name unique prior routes`)
      }
      if (!Array.isArray(route.required_material) || route.required_material.length > 1024) {
        fail('UNLEASH_REGISTRY_INVALID', `required material for ${route.route_id} is invalid`)
      }
      if (
        route.required_material.some((name) => typeof name !== 'string' || !ID.test(name))
        || new Set(route.required_material).size !== route.required_material.length
      ) fail('UNLEASH_REGISTRY_INVALID', `required material for ${route.route_id} is invalid`)
    }
    const availability = route.availability
    const availabilityFields = ['reason_code', 'status']
    if (
      availability === null
      || typeof availability !== 'object'
      || Array.isArray(availability)
      || Object.keys(availability).toSorted().join(',') !== availabilityFields.join(',')
      || !['AVAILABLE', 'UNAVAILABLE'].includes(availability.status)
      || (
        availability.status === 'AVAILABLE'
          ? availability.reason_code !== null
          : typeof availability.reason_code !== 'string' || !REASON_CODE.test(availability.reason_code)
      )
    ) fail('UNLEASH_REGISTRY_INVALID', `availability for ${route.route_id} is invalid`)
    assertRouteExecutionContract(route, registry.registry_version)
    routeIds.add(route.route_id)
    toolIds.add(route.tool_id)
    priorOrder = route.order
  }
  return registry
}

function assertPolicy(policy, targetFamily) {
  assertPlainJson(policy, 'unleash deployment policy')
  const baseFields = [
    'schema_version',
    'policy_id',
    'allowed_target_families',
    'allowed_effects',
    'allowed_origins',
    'budgets',
    'valid_from',
    'valid_until',
    'revocation',
  ]
  if (
    !(
      hasExactKeys(policy, baseFields)
      || hasExactKeys(policy, [...baseFields, 'controller_policy_sha256'])
    )
    || policy.schema_version !== '1.0.0'
    || !ID.test(policy.policy_id ?? '')
    || (
      Object.hasOwn(policy, 'controller_policy_sha256')
      && !SHA256.test(policy.controller_policy_sha256)
    )
  ) fail('UNLEASH_POLICY_INVALID', 'deployment policy is invalid')
  assertUniqueStrings(policy.allowed_target_families, 'allowed target families')
  assertUniqueStrings(policy.allowed_effects, 'allowed effects')
  assertUniqueStrings(policy.allowed_origins, 'allowed origins', { pattern: /^https:\/\/[^\s/]+(?::[0-9]+)?$/u })
  if (JSON.stringify(policy.allowed_origins) !== JSON.stringify([...policy.allowed_origins].toSorted())) {
    fail('UNLEASH_POLICY_INVALID', 'allowed origins must use canonical order')
  }
  for (const origin of policy.allowed_origins) {
    let parsed
    try { parsed = new URL(origin) } catch { fail('UNLEASH_POLICY_INVALID', 'allowed origins must be exact HTTPS origins') }
    if (parsed.protocol !== 'https:' || parsed.origin !== origin || parsed.href !== `${origin}/`) {
      fail('UNLEASH_POLICY_INVALID', 'allowed origins must be exact HTTPS origins')
    }
  }
  for (const [field, label] of [['valid_from', 'policy valid_from'], ['valid_until', 'policy valid_until']]) {
    const parsed = Date.parse(policy[field])
    if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== policy[field]) {
      fail('UNLEASH_POLICY_INVALID', `${label} must be one canonical timestamp`)
    }
  }
  if (Date.parse(policy.valid_from) >= Date.parse(policy.valid_until)) {
    fail('UNLEASH_POLICY_INVALID', 'policy validity window must be increasing')
  }
  if (
    !hasExactKeys(policy.revocation, ['check_id', 'fail_mode'])
    || !ID.test(policy.revocation.check_id ?? '')
    || policy.revocation.fail_mode !== 'CLOSED'
  ) fail('UNLEASH_POLICY_INVALID', 'policy revocation contract is invalid')
  assertBudgets(policy.budgets)
  if (!policy.allowed_target_families.includes(targetFamily)) {
    fail('UNLEASH_TARGET_BLOCKED', `deployment policy does not allow target family ${targetFamily}`)
  }
  return policy
}

function boundPolicyDigest(policy) {
  return policy.controller_policy_sha256 ?? digestUnleashValue(policy)
}

function authorityProjection(policy) {
  return {
    allowed_origins: [...policy.allowed_origins],
    allowed_target_families: [...policy.allowed_target_families],
    valid_from: policy.valid_from,
    valid_until: policy.valid_until,
    revocation: structuredClone(policy.revocation),
  }
}

function assertProvider(provider) {
  assertPlainJson(provider, 'unleash provider contract')
  if (
    !hasExactKeys(provider, ['protocol_version', 'proposal_kind'])
    || !ID.test(provider.protocol_version ?? '')
    || provider.proposal_kind !== 'last-aperture/unleash-proposal'
  ) fail('UNLEASH_PROVIDER_INVALID', 'provider protocol contract is invalid')
  return provider
}

function dispositionsFor(target, registry, policy) {
  const allowed = policy.allowed_target_families.includes(target.family)
  const controllerMaterial = target.family === 'https'
    ? new Set(['target_url', 'output_directory'])
    : new Set()
  return registry.routes.map((route) => {
    if (!route.target_families.includes(target.family)) {
      return {
        route_id: route.route_id,
        tool_id: route.tool_id,
        parameter_schema_id: route.parameter_schema_id,
        disposition: 'NOT_APPLICABLE',
        reason_code: 'TARGET_FAMILY_NOT_APPLICABLE',
      }
    }
    if (!allowed) {
      return {
        route_id: route.route_id,
        tool_id: route.tool_id,
        parameter_schema_id: route.parameter_schema_id,
        disposition: 'BLOCKED_BY_POLICY',
        reason_code: 'TARGET_FAMILY_BLOCKED_BY_POLICY',
      }
    }
    if (route.availability.status === 'UNAVAILABLE') {
      return {
        route_id: route.route_id,
        tool_id: route.tool_id,
        parameter_schema_id: route.parameter_schema_id,
        disposition: 'UNAVAILABLE',
        reason_code: route.availability.reason_code,
      }
    }
    if (!policy.allowed_effects.includes(route.required_effect)) {
      return {
        route_id: route.route_id,
        tool_id: route.tool_id,
        parameter_schema_id: route.parameter_schema_id,
        disposition: 'BLOCKED_BY_POLICY',
        reason_code: 'EFFECT_BLOCKED_BY_POLICY',
      }
    }
    if ((route.required_material ?? []).some((name) => !controllerMaterial.has(name))) {
      return {
        route_id: route.route_id,
        tool_id: route.tool_id,
        parameter_schema_id: route.parameter_schema_id,
        disposition: 'WAITING_FOR_MATERIAL',
        reason_code: 'REQUIRED_MATERIAL_MISSING',
      }
    }
    if ((route.dependencies ?? []).length > 0) {
      return {
        route_id: route.route_id,
        tool_id: route.tool_id,
        parameter_schema_id: route.parameter_schema_id,
        disposition: 'WAITING_FOR_DEPENDENCY',
        reason_code: 'DEPENDENCY_NOT_COMPLETE',
      }
    }
    return {
      route_id: route.route_id,
      tool_id: route.tool_id,
      parameter_schema_id: route.parameter_schema_id,
      disposition: 'READY',
      reason_code: null,
    }
  })
}

function dependenciesFor(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail('UNLEASH_DEPENDENCY_INVALID', 'unleash dependencies are required')
  }
  const registry = assertRegistry(value.registry)
  const provider = assertProvider(value.provider)
  return { registry, provider, policy: value.policy }
}

export function createUnleashPlan(intent, dependencyValues = {}) {
  const { registry, provider, policy: rawPolicy } = dependenciesFor(dependencyValues)
  const target = normalizeTarget(intent)
  const policy = assertPolicy(rawPolicy, target.family)
  if (!policy.allowed_origins.includes(new URL(target.canonical_locator).origin)) {
    fail('UNLEASH_TARGET_BLOCKED', 'deployment policy does not allow the target origin')
  }
  const unsigned = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-plan',
    target,
    registry_version: registry.registry_version,
    registry_sha256: digestUnleashValue(registry),
    policy_id: policy.policy_id,
    policy_sha256: boundPolicyDigest(policy),
    authority: authorityProjection(policy),
    provider_protocol_version: provider.protocol_version,
    provider_sha256: digestUnleashValue(provider),
    allowed_effects: [...policy.allowed_effects],
    budgets: structuredClone(policy.budgets),
    route_dispositions: dispositionsFor(target, registry, policy),
  }
  const plan = { ...unsigned, plan_sha256: digestUnleashValue(unsigned) }
  assertValidUnleashPlan(plan, dependencyValues)
  return deeplyFrozenCopy(plan)
}

export function assertSelfBoundUnleashPlan(value) {
  assertPlainJson(value, 'unleash plan')
  assertSchema(validatePlanSchema, value, 'unleash plan')
  const canonicalLocator = canonicalHttpsLocator(value.target.canonical_locator)
  if (canonicalLocator !== value.target.canonical_locator) {
    fail('UNLEASH_TARGET_INVALID', 'plan target locator is not canonical HTTPS')
  }
  const identitySha256 = digestUnleashValue({
    family: value.target.family,
    canonical_locator: value.target.canonical_locator,
  })
  if (value.target.target_id !== `target:sha256:${identitySha256}`) {
    fail('UNLEASH_TARGET_DIGEST_DRIFT', 'target identity digest does not match its canonical locator')
  }
  const targetOrigin = new URL(value.target.canonical_locator).origin
  if (
    !value.authority.allowed_origins.includes(targetOrigin)
    || !value.authority.allowed_target_families.includes(value.target.family)
    || Date.parse(value.authority.valid_from) >= Date.parse(value.authority.valid_until)
  ) fail('UNLEASH_POLICY_DRIFT', 'retained authority projection does not admit the bound target')
  const { plan_sha256: planSha256, ...unsigned } = value
  if (!SHA256.test(planSha256) || planSha256 !== digestUnleashValue(unsigned)) {
    fail('UNLEASH_PLAN_DIGEST_DRIFT', 'unleash plan digest does not match its canonical content')
  }
  return value
}

export function assertValidUnleashPlan(value, dependencyValues = {}) {
  assertSelfBoundUnleashPlan(value)
  const { registry, provider, policy: rawPolicy } = dependenciesFor(dependencyValues)
  const policy = assertPolicy(rawPolicy, value.target.family)
  const canonicalLocator = canonicalHttpsLocator(value.target.canonical_locator)
  if (canonicalLocator !== value.target.canonical_locator) {
    fail('UNLEASH_TARGET_INVALID', 'plan target locator is not canonical HTTPS')
  }
  const identitySha256 = digestUnleashValue({
    family: value.target.family,
    canonical_locator: value.target.canonical_locator,
  })
  if (value.target.target_id !== `target:sha256:${identitySha256}`) {
    fail('UNLEASH_TARGET_DIGEST_DRIFT', 'target identity digest does not match its canonical locator')
  }
  if (!policy.allowed_origins.includes(new URL(value.target.canonical_locator).origin)) {
    fail('UNLEASH_TARGET_BLOCKED', 'deployment policy does not allow the target origin')
  }
  const expectedBindings = {
    registry_version: registry.registry_version,
    registry_sha256: digestUnleashValue(registry),
    policy_id: policy.policy_id,
    policy_sha256: boundPolicyDigest(policy),
    provider_protocol_version: provider.protocol_version,
    provider_sha256: digestUnleashValue(provider),
  }
  for (const [field, expected] of Object.entries(expectedBindings)) {
    if (value[field] !== expected) fail('UNLEASH_BINDING_DRIFT', `${field} differs from the controller dependency`)
  }
  if (
    !sameCanonicalValue(value.budgets, policy.budgets)
    || !sameCanonicalValue(value.allowed_effects, policy.allowed_effects)
    || !sameCanonicalValue(value.authority, authorityProjection(policy))
  ) fail('UNLEASH_POLICY_DRIFT', 'plan policy projection differs from the bound deployment policy')
  const expectedDispositions = dispositionsFor(value.target, registry, policy)
  if (!sameCanonicalValue(value.route_dispositions, expectedDispositions)) {
    fail('UNLEASH_ROUTE_DISPOSITION_DRIFT', 'route disposition inventory differs from the frozen registry')
  }
  const routeIds = value.route_dispositions.map(({ route_id: routeId }) => routeId)
  if (new Set(routeIds).size !== routeIds.length || routeIds.length !== registry.routes.length) {
    fail('UNLEASH_ROUTE_DISPOSITION_INVALID', 'route disposition inventory is incomplete or duplicated')
  }
  const { plan_sha256: planSha256, ...unsigned } = value
  if (!SHA256.test(planSha256) || planSha256 !== digestUnleashValue(unsigned)) {
    fail('UNLEASH_PLAN_DIGEST_DRIFT', 'unleash plan digest does not match its canonical content')
  }
  return value
}

function assertUniqueIds(values, field, label) {
  const ids = values.map((value) => value[field])
  if (new Set(ids).size !== ids.length) fail('UNLEASH_PROPOSAL_INVALID', `${label} ids must be unique`)
  return new Set(ids)
}

function evidenceReferences(value) {
  return [
    ...value.candidates.flatMap(({ evidence_refs: refs }) => refs),
    ...value.actions.flatMap(({ evidence_refs: refs }) => refs),
  ]
}

function assertActionParameters(action, route) {
  if (route.parameter_schema_id === PARAMETER_SCHEMA_HTTPS_RECON_HEAD) {
    if (!hasExactKeys(action.parameters, ['method']) || action.parameters.method !== 'HEAD') {
      fail('UNLEASH_PROPOSAL_PARAMETERS_INVALID', 'HTTPS reconnaissance parameters must select only the sealed HEAD method')
    }
    return
  }
  if (route.parameter_schema_id === PARAMETER_SCHEMA_NONE) {
    if (!hasExactKeys(action.parameters, [])) {
      fail('UNLEASH_PROPOSAL_PARAMETERS_INVALID', `tool ${action.tool_id} does not accept provider-selected parameters`)
    }
    return
  }
  fail('UNLEASH_PROPOSAL_PARAMETERS_INVALID', `tool ${action.tool_id} has no registered parameter validator`)
}

export function assertValidUnleashProposal(value, dependencyValues = {}) {
  assertPlainJson(value, 'unleash proposal')
  assertSchema(validateProposalSchema, value, 'unleash proposal')
  const {
    plan,
    evidenceReferences: admittedEvidence,
    completedRouteIds,
    registry,
  } = dependencyValues
  if (plan === undefined) fail('UNLEASH_PROPOSAL_INVALID', 'proposal validation requires its bound plan')
  assertValidUnleashPlan(plan, dependencyValues)
  if (value.plan_sha256 !== plan.plan_sha256) {
    fail('UNLEASH_PROPOSAL_PLAN_DRIFT', 'proposal plan digest differs from the bound target plan')
  }
  if (value.provider_protocol_version !== plan.provider_protocol_version) {
    fail('UNLEASH_PROPOSAL_PROVIDER_DRIFT', 'proposal provider protocol differs from the bound plan')
  }
  const candidateIds = assertUniqueIds(value.candidates, 'candidate_id', 'candidate')
  assertUniqueIds(value.actions, 'action_id', 'action')
  if (!Array.isArray(completedRouteIds) && !(completedRouteIds instanceof Set)) {
    fail('UNLEASH_PROPOSAL_INVALID', 'controller-owned completed route ids are required for action admission')
  }
  const completed = [...completedRouteIds]
  const planRouteIds = new Set(plan.route_dispositions.map(({ route_id: routeId }) => routeId))
  if (
    completed.some((routeId) => typeof routeId !== 'string' || !planRouteIds.has(routeId))
    || new Set(completed).size !== completed.length
  ) fail('UNLEASH_PROPOSAL_INVALID', 'completed route ids must be unique routes from the bound plan')
  const completedSet = new Set(completed)
  const registryByTool = new Map(registry.routes.map((route) => [route.tool_id, route]))
  const planByTool = new Map(plan.route_dispositions.map((route) => [route.tool_id, route]))
  for (const action of value.actions) {
    if (!candidateIds.has(action.candidate_id)) {
      fail('UNLEASH_PROPOSAL_INVALID', `action ${action.action_id} references an unknown candidate`)
    }
    const disposition = planByTool.get(action.tool_id)
    const registeredRoute = registryByTool.get(action.tool_id)
    const dependenciesComplete = registeredRoute?.dependencies?.every((routeId) => completedSet.has(routeId)) ?? true
    const admitted = disposition?.disposition === 'READY'
      || (disposition?.disposition === 'WAITING_FOR_DEPENDENCY' && dependenciesComplete)
    if (!admitted || registeredRoute === undefined) {
      fail('UNLEASH_TOOL_NOT_REGISTERED', `tool ${action.tool_id} is not a ready registered tool for this target`)
    }
    assertActionParameters(action, disposition)
  }
  const references = evidenceReferences(value)
  if (references.some((reference) => !EVIDENCE_REFERENCE.test(reference))) {
    fail('UNLEASH_EVIDENCE_REFERENCE_INVALID', 'proposal contains a malformed evidence reference')
  }
  if (admittedEvidence === undefined && references.length > 0) {
    fail('UNLEASH_EVIDENCE_REFERENCE_INVALID', 'an admitted evidence set is required for every proposal reference')
  }
  if (admittedEvidence !== undefined) {
    if (!Array.isArray(admittedEvidence) && !(admittedEvidence instanceof Set)) {
      fail('UNLEASH_EVIDENCE_REFERENCE_INVALID', 'admitted evidence references must be an array or Set')
    }
    const admitted = new Set(admittedEvidence)
    const unknown = references.find((reference) => !admitted.has(reference))
    if (unknown !== undefined) {
      fail('UNLEASH_EVIDENCE_REFERENCE_UNKNOWN', `proposal evidence is not admitted by the controller: ${unknown}`)
    }
  }
  return value
}
