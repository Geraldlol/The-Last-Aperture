import assert from 'node:assert/strict'
import test from 'node:test'

import {
  assertValidUnleashPlan,
  assertValidUnleashProposal,
  createUnleashPlan,
  digestUnleashValue,
  getUnleashHttpsReconExecutionContract,
} from '../scripts/lib/unleash-contracts.mjs'
import { CONTROLLER_DEPLOYMENT_POLICY_LIMITS } from '../scripts/lib/http-recon-contracts.mjs'

const TARGET = 'https://Example.test'
const EVIDENCE_REFERENCE = `evidence:sha256:${'a'.repeat(64)}`

function executionContract(routeId, { available = true } = {}) {
  if (routeId === 'https-recon') {
    return structuredClone(getUnleashHttpsReconExecutionContract())
  }
  return {
    schema_version: '1.0.0',
    adapter_id: `adapter:last-aperture:${routeId}`,
    adapter_version: 'test-registry-v1',
    operation: routeId,
    parameter_schema_id: 'parameters:none-v1',
    limit_profile_id: null,
    limits: null,
    recovery_mode: 'RESTART_CREATE_ONLY',
    output_schema_id: null,
    verifier_id: null,
    invocation: available
      ? {
          runtime: 'node',
          entrypoint: `${routeId}.mjs`,
          argument_vector: [],
          shell: false,
        }
      : null,
  }
}

function dependencies() {
  return {
    registry: {
      schema_version: '1.0.0',
      registry_version: 'test-registry-v1',
      routes: [
        {
          route_id: 'https-recon',
          tool_id: 'tool:https-recon',
          parameter_schema_id: 'parameters:https-recon-head-v1',
          order: 10,
          target_families: ['https'],
          required_effect: 'OBSERVE',
          availability: { status: 'AVAILABLE', reason_code: null },
          execution_contract: executionContract('https-recon'),
        },
        {
          route_id: 'authenticated-http-browser',
          tool_id: 'tool:authenticated-http-browser',
          parameter_schema_id: 'parameters:none-v1',
          order: 20,
          target_families: ['https'],
          required_effect: 'AUTHENTICATED_REQUEST',
          availability: {
            status: 'UNAVAILABLE',
            reason_code: 'BROWSER_SESSION_NOT_CONNECTED',
          },
          execution_contract: executionContract('authenticated-http-browser', { available: false }),
        },
        {
          route_id: 'repository-audit',
          tool_id: 'tool:repository-audit',
          parameter_schema_id: 'parameters:none-v1',
          order: 30,
          target_families: ['repository'],
          required_effect: 'OBSERVE',
          availability: { status: 'AVAILABLE', reason_code: null },
          execution_contract: executionContract('repository-audit'),
        },
        {
          route_id: 'ghidra-analysis',
          tool_id: 'tool:ghidra-analysis',
          parameter_schema_id: 'parameters:none-v1',
          order: 40,
          target_families: ['artifact'],
          required_effect: 'OBSERVE',
          availability: { status: 'AVAILABLE', reason_code: null },
          execution_contract: executionContract('ghidra-analysis'),
        },
      ],
    },
    policy: {
      schema_version: '1.0.0',
      policy_id: 'deployment-policy:test',
      valid_from: '2026-09-15T09:00:00.000Z',
      valid_until: '2026-09-15T10:00:00.000Z',
      allowed_origins: ['https://example.test'],
      allowed_target_families: ['https'],
      allowed_effects: ['OBSERVE'],
      budgets: {
        max_actions: 32,
        max_parallel_actions: 4,
        max_duration_ms: 300_000,
        max_response_bytes: 1_048_576,
      },
      revocation: { check_id: 'revocation:test', fail_mode: 'CLOSED' },
    },
    provider: {
      protocol_version: '1.0.0',
      proposal_kind: 'last-aperture/unleash-proposal',
    },
  }
}

function createPlan() {
  return createUnleashPlan({ target: TARGET }, dependencies())
}

function validProposal(plan) {
  return {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-proposal',
    proposal_id: 'proposal:test-001',
    plan_sha256: plan.plan_sha256,
    provider_protocol_version: '1.0.0',
    candidates: [
      {
        candidate_id: 'candidate:test-open-redirect',
        title: 'Redirect destination may be attacker-controlled',
        hypothesis: 'The observed redirect parameter may accept an external HTTPS origin.',
        invariant: 'Redirect destinations must remain within the canonical target origin.',
        confidence: 'MEDIUM',
        evidence_refs: [EVIDENCE_REFERENCE],
        competing_explanations: ['The redirect may be allowlisted during execution.'],
      },
    ],
    actions: [
      {
        action_id: 'action:test-open-redirect-control',
        candidate_id: 'candidate:test-open-redirect',
        tool_id: 'tool:https-recon',
        evidence_refs: [EVIDENCE_REFERENCE],
        parameters: {
          method: 'HEAD',
        },
        expected_observation: 'A redirect response whose Location leaves the canonical origin.',
      },
    ],
  }
}

test('seals the HTTPS route to the controller deployment policy adapter identity', () => {
  const contract = getUnleashHttpsReconExecutionContract()

  assert.equal(contract.operation, 'CONTROLLER_DEPLOYMENT_POLICY_HEAD')
  assert.equal(contract.limit_profile_id, 'limits:http-recon-controller-deployment-policy-v1')
  assert.deepEqual(contract.limits, CONTROLLER_DEPLOYMENT_POLICY_LIMITS)
  assert.deepEqual(contract.invocation, {
    kind: 'ES_MODULE_EXPORT',
    runtime: 'node',
    module: 'scripts/lib/http-recon-controller.mjs',
    export_name: 'goControllerPolicyHttpRecon',
  })
})

test('creates one deterministic digest-bound plan from only an HTTPS target', () => {
  const firstDependencies = dependencies()
  const first = createUnleashPlan({ target: TARGET }, firstDependencies)
  const second = createUnleashPlan(
    { target: TARGET },
    structuredClone(firstDependencies),
  )

  assert.deepEqual(second, first)
  assert.equal(first.schema_version, '1.0.0')
  assert.equal(first.kind, 'last-aperture/unleash-plan')
  assert.equal(first.target.family, 'https')
  assert.equal(first.target.canonical_locator, 'https://example.test/')
  assert.match(first.target.target_id, /^target:sha256:[a-f0-9]{64}$/)
  assert.match(first.target.supplied_sha256, /^[a-f0-9]{64}$/)
  assert.equal(first.registry_version, firstDependencies.registry.registry_version)
  assert.equal(first.registry_sha256, digestUnleashValue(firstDependencies.registry))
  assert.equal(first.policy_sha256, digestUnleashValue(firstDependencies.policy))
  assert.equal(first.provider_protocol_version, firstDependencies.provider.protocol_version)
  assert.equal(first.provider_sha256, digestUnleashValue(firstDependencies.provider))
  assert.deepEqual(first.budgets, firstDependencies.policy.budgets)

  const { plan_sha256: planSha256, ...digestMaterial } = first
  assert.equal(planSha256, digestUnleashValue(digestMaterial))
  assert.doesNotThrow(() => assertValidUnleashPlan(first, firstDependencies))
})

test('records every registered route exactly once with an explicit disposition', () => {
  const injected = dependencies()
  const plan = createUnleashPlan({ target: TARGET }, injected)
  const routeIds = plan.route_dispositions.map(({ route_id: routeId }) => routeId)

  assert.equal(routeIds.length, injected.registry.routes.length)
  assert.equal(new Set(routeIds).size, injected.registry.routes.length)
  assert.deepEqual(
    [...routeIds].sort(),
    injected.registry.routes.map(({ route_id: routeId }) => routeId).sort(),
  )

  const routes = new Map(plan.route_dispositions.map((route) => [route.route_id, route]))
  assert.deepEqual(routes.get('https-recon'), {
    route_id: 'https-recon',
    tool_id: 'tool:https-recon',
    parameter_schema_id: 'parameters:https-recon-head-v1',
    disposition: 'READY',
    reason_code: null,
  })
  assert.deepEqual(routes.get('authenticated-http-browser'), {
    route_id: 'authenticated-http-browser',
    tool_id: 'tool:authenticated-http-browser',
    parameter_schema_id: 'parameters:none-v1',
    disposition: 'UNAVAILABLE',
    reason_code: 'BROWSER_SESSION_NOT_CONNECTED',
  })
  assert.deepEqual(routes.get('repository-audit'), {
    route_id: 'repository-audit',
    tool_id: 'tool:repository-audit',
    parameter_schema_id: 'parameters:none-v1',
    disposition: 'NOT_APPLICABLE',
    reason_code: 'TARGET_FAMILY_NOT_APPLICABLE',
  })
  assert.deepEqual(routes.get('ghidra-analysis'), {
    route_id: 'ghidra-analysis',
    tool_id: 'tool:ghidra-analysis',
    parameter_schema_id: 'parameters:none-v1',
    disposition: 'NOT_APPLICABLE',
    reason_code: 'TARGET_FAMILY_NOT_APPLICABLE',
  })
})

test('returns a deeply frozen plan and rejects a mutated clone as digest drift', () => {
  const injected = dependencies()
  const plan = createUnleashPlan({ target: TARGET }, injected)
  const original = structuredClone(plan)

  assert.equal(Object.isFrozen(plan), true)
  assert.equal(Object.isFrozen(plan.target), true)
  assert.equal(Object.isFrozen(plan.budgets), true)
  assert.equal(Object.isFrozen(plan.route_dispositions), true)
  assert.equal(Object.isFrozen(plan.route_dispositions[0]), true)
  assert.throws(() => {
    plan.target.canonical_locator = 'https://attacker.example/'
  }, TypeError)
  assert.deepEqual(plan, original)

  const tampered = structuredClone(plan)
  tampered.route_dispositions[0].disposition = 'UNAVAILABLE'
  assert.throws(
    () => assertValidUnleashPlan(tampered, injected),
    /digest|route disposition/i,
  )
  assert.deepEqual(plan, original)
})

test('accepts a plan-bound evidence-linked candidate and registered typed tool action', () => {
  const plan = createPlan()
  const proposal = validProposal(plan)

  assert.doesNotThrow(() => assertValidUnleashProposal(
    proposal,
    { plan, ...dependencies(), completedRouteIds: [], evidenceReferences: [EVIDENCE_REFERENCE] },
  ))
})

test('holds dependent tools until controller-owned prerequisite completion is supplied', () => {
  const injected = dependencies()
  const dependent = injected.registry.routes.find(({ route_id: routeId }) => routeId === 'authenticated-http-browser')
  dependent.availability = { status: 'AVAILABLE', reason_code: null }
  dependent.execution_contract = executionContract('authenticated-http-browser')
  dependent.required_effect = 'OBSERVE'
  dependent.dependencies = ['https-recon']
  dependent.required_material = []
  const plan = createUnleashPlan({ target: TARGET }, injected)
  const disposition = plan.route_dispositions.find(({ route_id: routeId }) => routeId === dependent.route_id)
  assert.deepEqual(disposition, {
    route_id: 'authenticated-http-browser',
    tool_id: 'tool:authenticated-http-browser',
    parameter_schema_id: 'parameters:none-v1',
    disposition: 'WAITING_FOR_DEPENDENCY',
    reason_code: 'DEPENDENCY_NOT_COMPLETE',
  })
  const proposal = validProposal(plan)
  proposal.actions[0].tool_id = dependent.tool_id
  proposal.actions[0].parameters = {}
  const baseDependencies = { plan, ...injected, evidenceReferences: [EVIDENCE_REFERENCE] }

  assert.throws(
    () => assertValidUnleashProposal(proposal, baseDependencies),
    /completed.*route|required|dependency/i,
  )
  assert.throws(
    () => assertValidUnleashProposal(proposal, { ...baseDependencies, completedRouteIds: [] }),
    /dependency|ready|completed/i,
  )
  assert.doesNotThrow(() => assertValidUnleashProposal(proposal, {
    ...baseDependencies,
    completedRouteIds: ['https-recon'],
  }))
})

test('rejects unknown, forward, and duplicate route dependencies', () => {
  for (const dependency of ['missing-route', 'authenticated-http-browser']) {
    const injected = dependencies()
    injected.registry.routes[0].dependencies = [dependency]
    injected.registry.routes[0].required_material = []
    assert.throws(
      () => createUnleashPlan({ target: TARGET }, injected),
      /dependenc|registry|prior/i,
    )
  }
  const injected = dependencies()
  injected.registry.routes[1].dependencies = ['https-recon', 'https-recon']
  injected.registry.routes[1].required_material = []
  assert.throws(
    () => createUnleashPlan({ target: TARGET }, injected),
    /dependenc|registry|duplicate/i,
  )
})

test('rejects computed and oversized provider values before schema traversal', () => {
  const plan = createPlan()
  const computed = validProposal(plan)
  let getterCalls = 0
  Object.defineProperty(computed.actions[0].parameters, 'method', {
    enumerable: true,
    get: () => { getterCalls += 1; return 'HEAD' },
  })
  assert.throws(
    () => assertValidUnleashProposal(computed, {
      plan,
      ...dependencies(),
      completedRouteIds: [],
      evidenceReferences: [EVIDENCE_REFERENCE],
    }),
    /computed|JSON/i,
  )
  assert.equal(getterCalls, 0)

  const oversized = validProposal(plan)
  oversized.untrusted_padding = 'x'.repeat(2 * 1024 * 1024)
  assert.throws(
    () => assertValidUnleashProposal(oversized, {
      plan,
      ...dependencies(),
      completedRouteIds: [],
      evidenceReferences: [EVIDENCE_REFERENCE],
    }),
    (error) => error.code === 'UNLEASH_VALUE_TOO_LARGE',
  )
})

test('rejects a proposal that selects an unregistered tool', () => {
  const plan = createPlan()
  const proposal = validProposal(plan)
  proposal.actions[0].tool_id = 'tool:provider-invented-shell'

  assert.throws(
    () => assertValidUnleashProposal(proposal, { plan, ...dependencies(), completedRouteIds: [] }),
    /tool|registered/i,
  )
})

test('rejects model-selected methods, paths, and query material for sealed HTTPS recon', () => {
  const plan = createPlan()
  for (const parameters of [
    { method: 'GET' },
    { method: 'HEAD', path: '/admin' },
    { method: 'HEAD', query: 'token=secret' },
    {},
  ]) {
    const proposal = validProposal(plan)
    proposal.actions[0].parameters = parameters
    assert.throws(
      () => assertValidUnleashProposal(
        proposal,
        { plan, ...dependencies(), completedRouteIds: [], evidenceReferences: [EVIDENCE_REFERENCE] },
      ),
      /parameter|method|schema|unknown|additional|required/i,
    )
  }
})

test('rejects a proposal that attempts to override the bound target', () => {
  const plan = createPlan()
  const proposal = validProposal(plan)
  proposal.target = {
    family: 'https',
    canonical_locator: 'https://attacker.example/',
  }

  assert.throws(
    () => assertValidUnleashProposal(proposal, { plan, ...dependencies(), completedRouteIds: [] }),
    /target|unknown|additional/i,
  )
})

test('rejects provider proof promotion', () => {
  const plan = createPlan()
  const proposal = validProposal(plan)
  proposal.candidates[0].proof_state = 'CONTROLLER_VERIFIED'

  assert.throws(
    () => assertValidUnleashProposal(proposal, { plan, ...dependencies(), completedRouteIds: [] }),
    /proof_state|proof|verified|unknown|additional/i,
  )
})

test('rejects unknown proposal fields', () => {
  const plan = createPlan()
  const proposal = validProposal(plan)
  proposal.actions[0].provider_command = 'curl https://attacker.example/'

  assert.throws(
    () => assertValidUnleashProposal(proposal, { plan, ...dependencies(), completedRouteIds: [] }),
    /provider_command|unknown|additional/i,
  )
})

test('rejects malformed evidence references', () => {
  const plan = createPlan()
  const proposal = validProposal(plan)
  proposal.candidates[0].evidence_refs = ['../../outside-campaign.json']

  assert.throws(
    () => assertValidUnleashProposal(proposal, { plan, ...dependencies(), completedRouteIds: [] }),
    /evidence/i,
  )
})

test('rejects ambiguous or credential-bearing target descriptors before planning', () => {
  for (const target of [
    'http://example.test/',
    'https://user:secret@example.test/',
    'https://example.test/#fragment',
    'https://example.test/path?token=secret',
    'https://example.test/path?X-Amz-Signature=secret',
    'https://example.test/%252e%252e/admin',
    'https://example.test/%63omponent',
    'https://example.test/%00',
    'https://example.test./component',
    'https://example.test\\@attacker.test/',
    'https://127.0.0.1/',
    'https://127.1/',
    'https://[2001:db8::1]/',
  ]) {
    assert.throws(
      () => createUnleashPlan({ target }, dependencies()),
      /target|https|ambiguous|credential/i,
      target,
    )
  }
})

test('rejects unrecognized controller dependency fields', () => {
  const policyInjection = dependencies()
  policyInjection.policy.credential_value = 'secret-that-must-not-enter-the-plan'
  assert.throws(
    () => createUnleashPlan({ target: TARGET }, policyInjection),
    /policy|unknown|field|invalid/i,
  )

  const providerInjection = dependencies()
  providerInjection.provider.shell = true
  assert.throws(
    () => createUnleashPlan({ target: TARGET }, providerInjection),
    /provider|unknown|field|invalid/i,
  )

  const registryInjection = dependencies()
  registryInjection.registry.provider_command = 'curl target'
  assert.throws(
    () => createUnleashPlan({ target: TARGET }, registryInjection),
    /registry|unknown|field|invalid/i,
  )
})

test('requires every proposal evidence reference to be admitted when an evidence set is supplied', () => {
  const plan = createPlan()
  const proposal = validProposal(plan)

  assert.doesNotThrow(() => assertValidUnleashProposal(
    proposal,
    { plan, ...dependencies(), completedRouteIds: [], evidenceReferences: [EVIDENCE_REFERENCE] },
  ))
  assert.throws(
    () => assertValidUnleashProposal(
      proposal,
      { plan, ...dependencies(), completedRouteIds: [], evidenceReferences: [] },
    ),
    /evidence.*not admitted|unknown/i,
  )
})

test('requires an admitted evidence set whenever a proposal names evidence', () => {
  const plan = createPlan()
  assert.throws(
    () => assertValidUnleashProposal(
      validProposal(plan),
      { plan, ...dependencies(), completedRouteIds: [] },
    ),
    /evidence.*required|admitted/i,
  )
})

test('rejects a resealed plan whose target locator is not canonical', () => {
  const injected = dependencies()
  const value = structuredClone(createPlan())
  value.target.canonical_locator = 'https://Example.test/'
  value.target.target_id = `target:sha256:${digestUnleashValue({
    family: value.target.family,
    canonical_locator: value.target.canonical_locator,
  })}`
  const { plan_sha256: ignored, ...unsigned } = value
  value.plan_sha256 = digestUnleashValue(unsigned)

  assert.throws(
    () => assertValidUnleashPlan(value, injected),
    /canonical|target/i,
  )
})
