import assert from 'node:assert/strict'
import { basename } from 'node:path'
import test from 'node:test'

import {
  ENGAGEMENT_ROUTE_REGISTRY_VERSION,
  getEngagementRouteRegistry,
} from '../scripts/lib/engagement-route-registry.mjs'
import {
  createUnleashPlan,
  getUnleashHttpsReconExecutionContract,
} from '../scripts/lib/unleash-contracts.mjs'
import {
  createUnleashDeploymentPolicy,
  projectUnleashPolicy,
} from '../scripts/lib/unleash-policy.mjs'
import {
  buildUnleashToolRegistry,
  createDefaultUnleashPlannerDependencies,
} from '../scripts/lib/unleash-registry.mjs'

const EXPECTED_EFFECTS = Object.freeze({
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

function expectedParameterSchema(routeId) {
  return routeId === 'https-recon'
    ? 'parameters:https-recon-head-v1'
    : 'parameters:none-v1'
}

function expectedExecutionContract(descriptor) {
  const isHttpsRecon = descriptor.id === 'https-recon'
  if (isHttpsRecon) return structuredClone(getUnleashHttpsReconExecutionContract())
  const [entrypoint, ...argumentVector] = descriptor.invocation?.argument_vector ?? []
  return {
    schema_version: '1.0.0',
    adapter_id: `adapter:last-aperture:${descriptor.id}`,
    adapter_version: ENGAGEMENT_ROUTE_REGISTRY_VERSION,
    operation: descriptor.id,
    parameter_schema_id: expectedParameterSchema(descriptor.id),
    limit_profile_id: null,
    limits: null,
    recovery_mode: descriptor.recovery_mode,
    output_schema_id: null,
    verifier_id: null,
    invocation: descriptor.invocation === null
      ? null
      : {
          runtime: 'node',
          entrypoint: basename(entrypoint),
          argument_vector: argumentVector,
          shell: false,
        },
  }
}

function deploymentPolicy() {
  return {
    schema_version: '1.0.0',
    policy_id: 'deployment-policy:default-test',
    valid_from: '2026-09-15T09:00:00.000Z',
    valid_until: '2026-09-15T10:00:00.000Z',
    allowed_origins: ['https://example.test'],
    allowed_target_families: ['https'],
    allowed_effects: ['OBSERVE'],
    budgets: {
      max_actions: 64,
      max_parallel_actions: 4,
      max_duration_ms: 300_000,
      max_response_bytes: 1_048_576,
    },
    revocation: { check_id: 'revocation:default-test', fail_mode: 'CLOSED' },
  }
}

test('projects every engagement route exactly once in the same order', () => {
  const source = getEngagementRouteRegistry()
  const registry = buildUnleashToolRegistry()

  assert.equal(registry.schema_version, '1.0.0')
  assert.equal(registry.registry_version, ENGAGEMENT_ROUTE_REGISTRY_VERSION)
  assert.equal(registry.routes.length, source.length)
  assert.equal(new Set(registry.routes.map(({ route_id: routeId }) => routeId)).size, source.length)
  assert.deepEqual(
    registry.routes.map(({ route_id: routeId }) => routeId),
    source.map(({ id }) => id),
  )

  for (const [index, descriptor] of source.entries()) {
    assert.deepEqual(registry.routes[index], {
      route_id: descriptor.id,
      tool_id: `tool:${descriptor.id}`,
      parameter_schema_id: expectedParameterSchema(descriptor.id),
      order: descriptor.order,
      target_families: descriptor.applicability.target_kinds,
      required_effect: EXPECTED_EFFECTS[descriptor.id],
      dependencies: descriptor.dependencies,
      required_material: descriptor.required_material,
      availability: descriptor.availability,
      execution_contract: expectedExecutionContract(descriptor),
    })
  }
})

test('binds portable execution identity and the exact sealed HTTPS limit profile', () => {
  const registry = buildUnleashToolRegistry()
  const route = registry.routes.find(({ route_id: routeId }) => routeId === 'https-recon')

  assert.deepEqual(route.execution_contract, expectedExecutionContract(
    getEngagementRouteRegistry().find(({ id }) => id === 'https-recon'),
  ))
  assert.equal(route.execution_contract.operation, 'CONTROLLER_DEPLOYMENT_POLICY_HEAD')
  assert.equal(
    route.execution_contract.limit_profile_id,
    'limits:http-recon-controller-deployment-policy-v1',
  )
  assert.deepEqual(route.execution_contract.invocation, {
    kind: 'ES_MODULE_EXPORT',
    runtime: 'node',
    module: 'scripts/lib/http-recon-controller.mjs',
    export_name: 'goControllerPolicyHttpRecon',
  })
  assert.equal(route.execution_contract.invocation.module.startsWith('scripts/lib/'), true)
  assert.equal(JSON.stringify(registry).includes(process.execPath), false)

  const dependencies = createDefaultUnleashPlannerDependencies({ policy: deploymentPolicy() })
  const altered = structuredClone(dependencies)
  altered.registry.routes.find(({ route_id: routeId }) => routeId === 'https-recon')
    .execution_contract.limits.max_probe_requests = 2
  assert.throws(
    () => createUnleashPlan({ target: 'https://example.test/' }, altered),
    /execution contract|sealed adapter|registry/i,
  )
})

test('creates default planner dependencies with the frozen registry and provider-neutral protocol', () => {
  const policy = deploymentPolicy()
  const dependencies = createDefaultUnleashPlannerDependencies({ policy })

  assert.deepEqual(dependencies.policy, policy)
  assert.deepEqual(dependencies.registry, buildUnleashToolRegistry())
  assert.equal(dependencies.registry.registry_version, ENGAGEMENT_ROUTE_REGISTRY_VERSION)
  assert.deepEqual(dependencies.provider, {
    protocol_version: '1.0.0',
    proposal_kind: 'last-aperture/unleash-proposal',
  })
})

test('plans the default HTTPS shot with complete ready, waiting, unavailable, and not-applicable states', () => {
  const dependencies = createDefaultUnleashPlannerDependencies({
    policy: deploymentPolicy(),
  })
  const plan = createUnleashPlan(
    { target: 'https://Example.test' },
    dependencies,
  )
  const source = getEngagementRouteRegistry()
  const routes = new Map(plan.route_dispositions.map((route) => [route.route_id, route]))

  assert.equal(plan.registry_version, ENGAGEMENT_ROUTE_REGISTRY_VERSION)
  assert.equal(routes.size, source.length)
  assert.deepEqual(
    plan.route_dispositions.map(({ route_id: routeId }) => routeId),
    source.map(({ id }) => id),
  )

  assert.deepEqual(routes.get('https-recon'), {
    route_id: 'https-recon',
    tool_id: 'tool:https-recon',
    parameter_schema_id: 'parameters:https-recon-head-v1',
    disposition: 'READY',
    reason_code: null,
  })

  for (const descriptor of source.filter((route) => (
    route.applicability.target_kinds.includes('repository')
    && !route.applicability.target_kinds.includes('https')
  ))) {
    assert.deepEqual(routes.get(descriptor.id), {
      route_id: descriptor.id,
      tool_id: `tool:${descriptor.id}`,
      parameter_schema_id: expectedParameterSchema(descriptor.id),
      disposition: 'NOT_APPLICABLE',
      reason_code: 'TARGET_FAMILY_NOT_APPLICABLE',
    })
  }

  for (const descriptor of source.filter((route) => (
    route.applicability.target_kinds.includes('https')
    && route.availability.status === 'UNAVAILABLE'
  ))) {
    assert.deepEqual(routes.get(descriptor.id), {
      route_id: descriptor.id,
      tool_id: `tool:${descriptor.id}`,
      parameter_schema_id: expectedParameterSchema(descriptor.id),
      disposition: 'UNAVAILABLE',
      reason_code: descriptor.availability.reason_code,
    })
  }

  assert.deepEqual(routes.get('authenticated-http-browser'), {
    route_id: 'authenticated-http-browser',
    tool_id: 'tool:authenticated-http-browser',
    parameter_schema_id: 'parameters:none-v1',
    disposition: 'BLOCKED_BY_POLICY',
    reason_code: 'EFFECT_BLOCKED_BY_POLICY',
  })

  for (const routeId of ['web-capture-har-import', 'web-capture-burp-import']) {
    assert.deepEqual(routes.get(routeId), {
      route_id: routeId,
      tool_id: `tool:${routeId}`,
      parameter_schema_id: 'parameters:none-v1',
      disposition: 'WAITING_FOR_MATERIAL',
      reason_code: 'REQUIRED_MATERIAL_MISSING',
    })
  }
})

test('binds a full controller-owned policy without exposing it as target intake', () => {
  const policy = createUnleashDeploymentPolicy({
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-deployment-policy',
    policy_id: 'policy:planner-integration',
    valid_from: '2026-09-15T00:00:00.000Z',
    valid_until: '2026-09-16T00:00:00.000Z',
    allowed_origins: ['https://example.test'],
    allowed_target_families: ['https'],
    allowed_effects: ['OBSERVE'],
    budgets: {
      max_actions: 64,
      max_parallel_actions: 4,
      max_duration_ms: 300_000,
      max_response_bytes: 1_048_576,
    },
    credential_references: [],
    revocation: { check_id: 'revocation:planner-integration', fail_mode: 'CLOSED' },
  })
  const dependencies = createDefaultUnleashPlannerDependencies({ policy })
  const plan = createUnleashPlan({ target: 'https://example.test/' }, dependencies)

  assert.equal(plan.policy_id, policy.policy_id)
  assert.equal(plan.policy_sha256, projectUnleashPolicy(policy).policy_sha256)
  assert.deepEqual(plan.budgets, policy.budgets)
  assert.deepEqual(plan.allowed_effects, policy.allowed_effects)
  assert.equal(Object.hasOwn(plan, 'credential_references'), false)
  assert.equal(JSON.stringify(plan).includes('credential:'), false)
})
