import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  ENGAGEMENT_ROUTE_REGISTRY,
  ENGAGEMENT_ROUTE_REGISTRY_VERSION,
  buildEngagementRouteInvocation,
  getEngagementRouteRegistry,
  planEngagementRoutes,
} from '../scripts/lib/engagement-route-registry.mjs'

const EXPECTED_ROUTE_IDS = [
  'repository-audit',
  'repository-t1-proof',
  'repository-t2-service-proof',
  'https-recon',
  'authenticated-http-browser',
  'adversarial-validation',
  'bounty-perimeter',
  'bounty-recon',
  'bounty-authorization',
  'bounty-scan',
  'bounty-oob',
  'bounty-proxy',
  'web-live-metadata-import',
  'web-capture-har-import',
  'web-capture-burp-import',
  'ghidra-analysis',
  'frida-trace',
  'evidence-artifact-acquisition',
  'evidence-registry-acquisition',
  'evidence-deployed-acquisition',
  'evidence-runtime-acquisition',
  'evidence-bundle-import',
  'protocol-build',
  'connector-generate',
  'connector-verify',
  'provider-execution',
  'remote-provider-execution',
  'transparency-publication',
  'database-conformance',
]

test('registry is a deterministic target-neutral DAG with complete route metadata', () => {
  assert.equal(ENGAGEMENT_ROUTE_REGISTRY_VERSION, '2.0.0')
  assert.deepEqual(ENGAGEMENT_ROUTE_REGISTRY.map((route) => route.id), EXPECTED_ROUTE_IDS)
  assert.deepEqual(
    ENGAGEMENT_ROUTE_REGISTRY.map((route) => route.order),
    ENGAGEMENT_ROUTE_REGISTRY.map((route) => route.order).toSorted((left, right) => left - right),
  )

  const byId = new Map(ENGAGEMENT_ROUTE_REGISTRY.map((route) => [route.id, route]))
  assert.deepEqual(
    [...new Set(ENGAGEMENT_ROUTE_REGISTRY.flatMap((route) => route.applicability.target_kinds))].toSorted(),
    ['artifact', 'browser', 'device', 'https', 'process', 'repository'],
  )
  for (const route of ENGAGEMENT_ROUTE_REGISTRY) {
    assert.equal(typeof route.id, 'string')
    assert.equal(Number.isSafeInteger(route.order), true)
    assert.equal(Array.isArray(route.dependencies), true)
    assert.equal(Array.isArray(route.applicability.target_kinds), true)
    assert.equal(Array.isArray(route.required_material), true)
    assert.equal(typeof route.recovery_mode, 'string')
    assert.equal(typeof route.capability_id, 'string')
    assert.ok(['AVAILABLE', 'UNAVAILABLE'].includes(route.availability.status))
    if (route.availability.status === 'AVAILABLE') {
      assert.equal(route.availability.reason_code, null)
      assert.equal(typeof route.invocation.public_entrypoint, 'string')
      assert.equal(Array.isArray(route.invocation.argument_vector), true)
      assert.equal(route.invocation.shell, false)
    } else {
      assert.match(route.availability.reason_code, /^[A-Z][A-Z0-9_]+$/)
      assert.equal(route.invocation, null)
    }
    for (const dependency of route.dependencies) {
      assert.equal(byId.has(dependency), true, `${route.id} has an unknown dependency`)
      assert.equal(byId.get(dependency).order < route.order, true, `${route.id} is not topological`)
    }
  }

  const descriptorText = JSON.stringify(ENGAGEMENT_ROUTE_REGISTRY)
  assert.doesNotMatch(descriptorText, /portal\.example|C:\\\\targets|Bearer [A-Za-z0-9]/)
  assert.equal(Object.isFrozen(ENGAGEMENT_ROUTE_REGISTRY), true)
  assert.equal(Object.isFrozen(ENGAGEMENT_ROUTE_REGISTRY[0].dependencies), true)
  assert.equal(Object.isFrozen(ENGAGEMENT_ROUTE_REGISTRY[0].invocation.argument_vector), true)
})

test('registry snapshots are detached and cannot mutate the canonical route order', () => {
  const first = getEngagementRouteRegistry()
  const second = getEngagementRouteRegistry()
  assert.deepEqual(first, second)
  assert.notEqual(first, second)
  first[0].dependencies.push('made-up-route')
  first.reverse()
  assert.deepEqual(getEngagementRouteRegistry().map((route) => route.id), EXPECTED_ROUTE_IDS)
})

test('planner uses declared capability kinds and material names without inspecting target values', () => {
  const requiredForRecon = ENGAGEMENT_ROUTE_REGISTRY
    .find((route) => route.id === 'https-recon')
    .required_material
  const requiredForAuthenticated = ENGAGEMENT_ROUTE_REGISTRY
    .find((route) => route.id === 'authenticated-http-browser')
    .required_material

  const plans = planEngagementRoutes({
    targetKinds: ['browser'],
    availableMaterial: [...requiredForRecon, ...requiredForAuthenticated],
    completedRoutes: [],
  })
  const byId = new Map(plans.map((plan) => [plan.route_id, plan]))
  assert.equal(byId.get('repository-audit').status, 'NOT_APPLICABLE')
  assert.equal(byId.get('https-recon').status, 'READY')
  assert.equal(byId.get('authenticated-http-browser').status, 'WAITING_FOR_DEPENDENCY')
  assert.deepEqual(byId.get('authenticated-http-browser').waiting_for_routes, ['https-recon'])

  const afterRecon = planEngagementRoutes({
    targetKinds: ['browser'],
    availableMaterial: [...requiredForRecon, ...requiredForAuthenticated],
    completedRoutes: ['https-recon'],
  })
  assert.equal(afterRecon.find((plan) => plan.route_id === 'authenticated-http-browser').status, 'READY')

  assert.throws(
    () => planEngagementRoutes({ targetKinds: ['https://portal.example'] }),
    (error) => error?.code === 'ENGAGEMENT_ROUTE_TARGET_KIND_INVALID',
  )

  const artifactPlans = planEngagementRoutes({ targetKinds: ['artifact'] })
  assert.equal(artifactPlans.find((plan) => plan.route_id === 'ghidra-analysis').status, 'WAITING_FOR_MATERIAL')
  assert.equal(artifactPlans.find((plan) => plan.route_id === 'https-recon').status, 'NOT_APPLICABLE')

  for (const evidenceMaterial of ['web_evidence_paths', 'reverse_evidence_paths']) {
    const protocol = planEngagementRoutes({
      targetKinds: ['artifact'],
      availableMaterial: ['output_path', evidenceMaterial],
    }).find((plan) => plan.route_id === 'protocol-build')
    assert.equal(protocol.status, 'READY', evidenceMaterial)
  }
  const protocolWithoutEvidence = planEngagementRoutes({
    targetKinds: ['artifact'],
    availableMaterial: ['output_path'],
  }).find((plan) => plan.route_id === 'protocol-build')
  assert.equal(protocolWithoutEvidence.status, 'WAITING_FOR_MATERIAL')
  assert.deepEqual(protocolWithoutEvidence.missing_material, [
    'web_evidence_paths',
    'reverse_evidence_paths',
  ])
})

test('missing required material always produces WAITING_FOR_MATERIAL before dependency recovery', () => {
  const plans = planEngagementRoutes({
    targetKinds: ['browser'],
    availableMaterial: [],
    completedRoutes: [],
  })
  const authenticated = plans.find((plan) => plan.route_id === 'authenticated-http-browser')
  assert.equal(authenticated.status, 'WAITING_FOR_MATERIAL')
  assert.deepEqual(authenticated.missing_material, [
    'scope_path',
    'campaign_grant_sha256',
    'ledger_directory',
    'operator_id',
    'credential_transport',
  ])
  assert.deepEqual(authenticated.waiting_for_routes, [])
})

test('builders return fixed shell-free argument vectors for every public route without executing', () => {
  const fixtures = new Map([
    ['repository-audit', { repository_path: 'C:\\targets\\repo', output_directory: 'C:\\evidence\\repo' }],
    ['https-recon', { target_url: 'https://portal.example/', output_directory: 'C:\\evidence\\recon' }],
    ['authenticated-http-browser', {
      scope_path: 'C:\\evidence\\scope.json', campaign_grant_sha256: 'a'.repeat(64),
      ledger_directory: 'C:\\evidence\\ledger', operator_id: 'operator-1', credential_transport: 'browser',
    }],
    ['web-live-metadata-import', {
      recon_bundle_path: 'C:\\evidence\\recon',
      auth_scope_path: 'C:\\evidence\\scope.json',
      auth_ledger_directory: 'C:\\evidence\\ledger',
      target_origins: ['https://portal.example'],
      target_path_prefix: '/app',
      path_literals: ['app'],
      output_directory: 'C:\\evidence\\live',
    }],
    ['web-capture-har-import', {
      har_path: 'C:\\captures\\portal.har', target_origins: ['https://z.example', 'https://a.example'],
      target_path_prefix: '/app', output_path: 'C:\\evidence\\har.json',
      path_literals: ['users', 'api'],
    }],
    ['web-capture-burp-import', {
      burp_path: 'C:\\captures\\items.xml', target_origins: ['https://portal.example'],
      target_path_prefix: '/app/', output_path: 'C:\\evidence\\burp.json',
    }],
    ['ghidra-analysis', {
      lab_root: 'C:\\lab', binary_relative_path: 'bin/app.exe', artifact_kind: 'native-executable',
      ghidra_path: 'C:\\tools\\analyzeHeadless.bat', output_directory: 'C:\\evidence\\ghidra',
    }],
    ['frida-trace', {
      trace_plan_path: 'C:\\lab\\trace-plan.json', frida_path: 'C:\\tools\\frida.exe',
      output_directory: 'C:\\evidence\\frida',
    }],
    ['protocol-build', {
      web_evidence_paths: ['C:\\evidence\\z.json', 'C:\\evidence\\a.json'],
      reverse_evidence_paths: ['C:\\evidence\\native.json'], output_path: 'C:\\evidence\\protocol.json',
    }],
    ['connector-generate', {
      contract_path: 'C:\\evidence\\protocol.json', output_directory: 'C:\\evidence\\connector',
      package_name: '@example/portal-native',
    }],
    ['connector-verify', {
      package_directory: 'C:\\evidence\\connector', manifest_sha256: 'b'.repeat(64),
    }],
  ])

  assert.deepEqual(
    [...fixtures.keys()],
    ENGAGEMENT_ROUTE_REGISTRY
      .filter(({ availability }) => availability.status === 'AVAILABLE')
      .map(({ id }) => id),
    'every available route must have a public fixed-vector builder regression',
  )

  for (const routeId of fixtures.keys()) {
    const invocation = buildEngagementRouteInvocation(routeId, fixtures.get(routeId))
    assert.equal(typeof invocation.public_entrypoint, 'string')
    assert.equal(Array.isArray(invocation.arguments), true)
    assert.equal(invocation.arguments.every((argument) => typeof argument === 'string'), true)
    assert.equal(invocation.shell, false)
    assert.equal(Object.keys(invocation).toSorted().join(','), 'arguments,public_entrypoint,shell')
  }

  const har = buildEngagementRouteInvocation('web-capture-har-import', fixtures.get('web-capture-har-import'))
  assert.deepEqual(har.arguments.filter((argument) => argument.startsWith('https://')), [
    'https://a.example',
    'https://z.example',
  ])
  assert.deepEqual(har.arguments.slice(har.arguments.indexOf('--path-prefix'), har.arguments.indexOf('--path-prefix') + 2), [
    '--path-prefix',
    '/app',
  ])
  assert.deepEqual(
    buildEngagementRouteInvocation('protocol-build', fixtures.get('protocol-build')),
    buildEngagementRouteInvocation('protocol-build', {
      ...fixtures.get('protocol-build'),
      web_evidence_paths: ['C:\\evidence\\a.json', 'C:\\evidence\\z.json'],
    }),
  )
  const reverseOnlyProtocol = buildEngagementRouteInvocation('protocol-build', {
    reverse_evidence_paths: ['C:\\evidence\\native.json'],
    output_path: 'C:\\evidence\\protocol.json',
  })
  assert.equal(reverseOnlyProtocol.arguments.includes('--web-evidence'), false)
  assert.deepEqual(
    reverseOnlyProtocol.arguments.slice(
      reverseOnlyProtocol.arguments.indexOf('--reverse-evidence'),
      reverseOnlyProtocol.arguments.indexOf('--reverse-evidence') + 2,
    ),
    ['--reverse-evidence', 'C:\\evidence\\native.json'],
  )
  assert.throws(
    () => buildEngagementRouteInvocation('protocol-build', {
      output_path: 'C:\\evidence\\protocol.json',
    }),
    (error) => error?.code === 'ENGAGEMENT_ROUTE_MATERIAL_REQUIRED',
  )

  for (const targetPathPrefix of [
    'app', '//other.example/app', '/app/../admin', '/app?query=1', '/app%2fadmin',
    '/app/%252e%252e%252fadmin', '/app/%25252e%25252e%25252fadmin',
    '/app/%25%32%65%25%32%65%25%32%66admin',
  ]) {
    assert.throws(
      () => buildEngagementRouteInvocation('web-capture-har-import', {
        ...fixtures.get('web-capture-har-import'),
        target_path_prefix: targetPathPrefix,
      }),
      (error) => error?.code === 'ENGAGEMENT_ROUTE_MATERIAL_INVALID',
      targetPathPrefix,
    )
  }
})

test('authenticated route selects a credential transport flag and refuses credential values', () => {
  const material = {
    scope_path: 'scope.json', campaign_grant_sha256: 'a'.repeat(64), ledger_directory: 'ledger',
    operator_id: 'operator-1', credential_transport: 'stdin',
  }
  const invocation = buildEngagementRouteInvocation('authenticated-http-browser', material)
  assert.equal(invocation.arguments.includes('--credential-stdin'), true)
  assert.equal(invocation.arguments.includes('--credential-browser'), false)
  assert.equal(invocation.arguments.includes('stdin'), false)

  assert.throws(
    () => buildEngagementRouteInvocation('authenticated-http-browser', {
      ...material,
      credential_value: 'Bearer do-not-store-this',
    }),
    (error) => error?.code === 'ENGAGEMENT_ROUTE_MATERIAL_UNKNOWN',
  )
  assert.throws(
    () => buildEngagementRouteInvocation('authenticated-http-browser', {
      ...material,
      credential_transport: 'Bearer do-not-store-this',
    }),
    (error) => error?.code === 'ENGAGEMENT_ROUTE_MATERIAL_INVALID',
  )
})
