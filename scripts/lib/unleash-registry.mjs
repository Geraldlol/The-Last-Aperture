import { basename } from 'node:path'

import {
  ENGAGEMENT_ROUTE_REGISTRY_VERSION,
  getEngagementRouteRegistry,
} from './engagement-route-registry.mjs'
import { getUnleashHttpsReconExecutionContract } from './unleash-contracts.mjs'
import { projectUnleashPolicy } from './unleash-policy.mjs'
import { UNLEASH_PROVIDER_PROTOCOL } from './unleash-provider-profile.mjs'

export { UNLEASH_PROVIDER_PROTOCOL } from './unleash-provider-profile.mjs'

const ROUTE_REQUIRED_EFFECT = Object.freeze({
  'repository-audit': 'OBSERVE',
  'repository-t1-proof': 'EXECUTE_PROOF',
  'repository-t2-service-proof': 'EXECUTE_PROOF',
  'https-recon': 'OBSERVE',
  'authenticated-http-browser': 'AUTHENTICATED_REQUEST',
  'adversarial-validation': 'EXECUTE_PROOF',
  'bounty-perimeter': 'OBSERVE',
  'bounty-recon': 'PROBE',
  'bounty-authorization': 'AUTHENTICATED_REQUEST',
  'bounty-scan': 'PROBE',
  'bounty-oob': 'EXECUTE_PROOF',
  'bounty-proxy': 'OBSERVE',
  'web-live-metadata-import': 'OBSERVE',
  'web-capture-har-import': 'OBSERVE',
  'web-capture-burp-import': 'OBSERVE',
  'ghidra-analysis': 'OBSERVE',
  'frida-trace': 'PROBE',
  'evidence-artifact-acquisition': 'OBSERVE',
  'evidence-registry-acquisition': 'OBSERVE',
  'evidence-deployed-acquisition': 'OBSERVE',
  'evidence-runtime-acquisition': 'OBSERVE',
  'evidence-bundle-import': 'OBSERVE',
  'protocol-build': 'OBSERVE',
  'connector-generate': 'OBSERVE',
  'connector-verify': 'OBSERVE',
  'provider-execution': 'OBSERVE',
  'remote-provider-execution': 'OBSERVE',
  'transparency-publication': 'PUBLISH_EVIDENCE',
  'database-conformance': 'EXECUTE_PROOF',
})

const ROUTE_PARAMETER_SCHEMA = Object.freeze(Object.fromEntries(
  Object.keys(ROUTE_REQUIRED_EFFECT).map((routeId) => [
    routeId,
    routeId === 'https-recon'
      ? 'parameters:https-recon-head-v1'
      : 'parameters:none-v1',
  ]),
))

const ROUTE_EXECUTION_CONTRACT_VERSION = '1.0.0'

function portableInvocation(descriptor) {
  if (descriptor.invocation === null) return null
  const [entrypoint, ...argumentVector] = descriptor.invocation.argument_vector
  return {
    runtime: 'node',
    entrypoint: basename(entrypoint),
    argument_vector: argumentVector,
    shell: false,
  }
}

function executionContract(descriptor) {
  const isHttpsRecon = descriptor.id === 'https-recon'
  if (isHttpsRecon) return structuredClone(getUnleashHttpsReconExecutionContract())
  return {
    schema_version: ROUTE_EXECUTION_CONTRACT_VERSION,
    adapter_id: `adapter:last-aperture:${descriptor.id}`,
    adapter_version: ENGAGEMENT_ROUTE_REGISTRY_VERSION,
    operation: descriptor.id,
    parameter_schema_id: ROUTE_PARAMETER_SCHEMA[descriptor.id],
    limit_profile_id: null,
    limits: null,
    recovery_mode: descriptor.recovery_mode,
    output_schema_id: null,
    verifier_id: null,
    invocation: portableInvocation(descriptor),
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

export function buildUnleashToolRegistry() {
  const source = getEngagementRouteRegistry()
  if (
    Object.keys(ROUTE_REQUIRED_EFFECT).length !== source.length
    || source.some(({ id }) => ROUTE_REQUIRED_EFFECT[id] === undefined)
  ) throw new Error('unleash route effect registry is incomplete')
  const routes = source.map((descriptor) => ({
      route_id: descriptor.id,
      tool_id: `tool:${descriptor.id}`,
      parameter_schema_id: ROUTE_PARAMETER_SCHEMA[descriptor.id],
      order: descriptor.order,
      target_families: [...descriptor.applicability.target_kinds],
      required_effect: ROUTE_REQUIRED_EFFECT[descriptor.id],
      dependencies: [...descriptor.dependencies],
      required_material: [...descriptor.required_material],
      availability: { ...descriptor.availability },
      execution_contract: executionContract(descriptor),
    }))
  return deeplyFrozenCopy({
    schema_version: '1.0.0',
    registry_version: ENGAGEMENT_ROUTE_REGISTRY_VERSION,
    routes,
  })
}

export function createDefaultUnleashPlannerDependencies({
  policy,
  provider = UNLEASH_PROVIDER_PROTOCOL,
} = {}) {
  const plannerPolicy = policy?.kind === 'last-aperture/unleash-deployment-policy'
    ? (() => {
        const projection = projectUnleashPolicy(policy)
        return {
          schema_version: projection.schema_version,
          policy_id: projection.policy_id,
          valid_from: projection.valid_from,
          valid_until: projection.valid_until,
          allowed_origins: [...projection.allowed_origins],
          allowed_target_families: [...projection.allowed_target_families],
          allowed_effects: [...projection.allowed_effects],
          budgets: structuredClone(projection.budgets),
          revocation: structuredClone(projection.revocation),
          controller_policy_sha256: projection.policy_sha256,
        }
      })()
    : policy
  return deeplyFrozenCopy({
    registry: buildUnleashToolRegistry(),
    policy: plannerPolicy,
    provider,
  })
}
