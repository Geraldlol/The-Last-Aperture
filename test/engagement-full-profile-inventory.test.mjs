import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import { CAPABILITY_REGISTRY } from '../scripts/lib/capabilities.mjs'
import {
  ENGAGEMENT_AUTHORIZED_CAPABILITIES,
} from '../scripts/lib/engagement-authority-profiles.mjs'
import {
  ENGAGEMENT_ROUTE_REGISTRY,
  buildEngagementRouteInvocation,
  planEngagementRoutes,
  renderEngagementSkillRouteInventory,
} from '../scripts/lib/engagement-route-registry.mjs'

const ROUTE_IDS = [
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

const UNAVAILABLE_ROUTES = new Set([
  'repository-t1-proof',
  'repository-t2-service-proof',
  'adversarial-validation',
  'bounty-perimeter',
  'bounty-recon',
  'bounty-authorization',
  'bounty-scan',
  'bounty-oob',
  'bounty-proxy',
  'evidence-artifact-acquisition',
  'evidence-registry-acquisition',
  'evidence-deployed-acquisition',
  'evidence-runtime-acquisition',
  'evidence-bundle-import',
  'provider-execution',
  'remote-provider-execution',
  'transparency-publication',
  'database-conformance',
])

test('full authority enumerates every packaged controller family and no phantom capability', () => {
  assert.deepEqual(ENGAGEMENT_ROUTE_REGISTRY.map(({ id }) => id), ROUTE_IDS)
  assert.deepEqual(
    ENGAGEMENT_AUTHORIZED_CAPABILITIES,
    [ROUTE_IDS[0], 'repository-agent-work', ...ROUTE_IDS.slice(1)],
  )

  const authoritySchema = JSON.parse(readFileSync('schemas/engagement-authority.schema.json', 'utf8'))
  const intakeSchema = JSON.parse(readFileSync('schemas/engagement-intake.schema.json', 'utf8'))
  for (const schema of [authoritySchema, intakeSchema]) {
    assert.deepEqual(
      schema.$defs.capabilities.items.enum,
      ENGAGEMENT_AUTHORIZED_CAPABILITIES,
    )
    assert.ok(schema.$defs.capabilities.maxItems >= ENGAGEMENT_AUTHORIZED_CAPABILITIES.length)
  }
})

test('route availability is explicit, capability-backed, and unavailable routes cannot dispatch', () => {
  const releaseCapabilities = new Map(CAPABILITY_REGISTRY.capabilities.map((item) => [item.id, item]))
  for (const route of ENGAGEMENT_ROUTE_REGISTRY) {
    const capability = releaseCapabilities.get(route.capability_id)
    assert.ok(capability, `${route.id} references an unknown release capability`)
    assert.ok(['AVAILABLE', 'UNAVAILABLE'].includes(route.availability.status))
    if (route.availability.status === 'AVAILABLE') {
      assert.match(capability.status, /^AVAILABLE(?:_NARROW)?$/)
      assert.equal(route.availability.reason_code, null)
      assert.notEqual(route.invocation, null)
    } else {
      assert.equal(UNAVAILABLE_ROUTES.has(route.id), true, route.id)
      assert.match(route.availability.reason_code, /^[A-Z][A-Z0-9_]{2,127}$/)
      assert.equal(route.invocation, null)
      assert.throws(
        () => buildEngagementRouteInvocation(route.id, {}),
        (error) => error?.code === 'ENGAGEMENT_ROUTE_UNAVAILABLE',
      )
    }
  }

  const plan = planEngagementRoutes({
    targetKinds: ['https'],
    availableMaterial: ENGAGEMENT_ROUTE_REGISTRY.flatMap((route) => route.required_material),
  })
  for (const route of ENGAGEMENT_ROUTE_REGISTRY.filter((item) => (
    item.applicability.target_kinds.includes('https') && item.availability.status === 'UNAVAILABLE'
  ))) {
    const state = plan.find(({ route_id: routeId }) => routeId === route.id)
    assert.equal(state.status, 'UNAVAILABLE', route.id)
    assert.equal(state.unavailable_reason, route.availability.reason_code, route.id)
    assert.deepEqual(state.missing_material, [], route.id)
  }
})

test('canonical skill inventory is rendered mechanically from routes and capability status', () => {
  const skill = readFileSync('skills/last-aperture/SKILL.md', 'utf8')
  const rendered = renderEngagementSkillRouteInventory(CAPABILITY_REGISTRY)
  assert.equal(skill.includes(rendered), true)
  assert.match(skill, /full.*enumerates every applicable registered route/is)
  assert.match(skill, /unavailable routes.*cannot dispatch/is)
})
