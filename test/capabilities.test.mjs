import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import {
  CAPABILITY_REGISTRY, capabilityRegistry, renderCapabilities,
  assessEnvironmentCoverage, renderCapabilityDocumentation, ENVIRONMENT_INVENTORY_LIMITS,
} from '../scripts/lib/capabilities.mjs'

test('release registry is deeply immutable and projections are detached', () => {
  assert.ok(Object.isFrozen(CAPABILITY_REGISTRY))
  assert.ok(Object.isFrozen(CAPABILITY_REGISTRY.capabilities))
  assert.ok(Object.isFrozen(CAPABILITY_REGISTRY.capabilities[0].commands))
  assert.throws(() => { CAPABILITY_REGISTRY.capabilities[0].status = 'UNAVAILABLE' }, TypeError)
  const projected = capabilityRegistry()
  projected.capabilities[0].commands.push('invented-route')
  assert.ok(!CAPABILITY_REGISTRY.capabilities[0].commands.includes('invented-route'))
  assert.equal(new Set(projected.capabilities.map((item) => item.id)).size, projected.capabilities.length)
})

test('release declarations distinguish integration, lifecycle, semantics, and unavailable runtimes', () => {
  const byId = new Map(CAPABILITY_REGISTRY.capabilities.map((item) => [item.id, item]))
  assert.equal(byId.get('review-integration').status, 'AVAILABLE')
  assert.equal(byId.get('source-analysis-provider').status, 'UNAVAILABLE')
  assert.equal(byId.get('t2-service-proof').status, 'AVAILABLE_NARROW')
  assert.match(byId.get('t2-service-proof').limitation, /UNPROVEN.*semantic oracle/)
  assert.equal(byId.get('semantic-oracle').status, 'UNAVAILABLE')
  for (const id of ['browser-execution', 'database-stack-execution', 'multi-runtime-execution', 'deployed-evidence-acquisition', 'generic-live']) {
    assert.equal(byId.get(id).status, 'UNAVAILABLE')
    assert.deepEqual(byId.get(id).commands, [])
  }
  assert.match(byId.get('https-recon').limitation, /not a comprehensive website assessment/)
  assert.match(renderCapabilities(), /Static checks do not inspect a Docker daemon/)
})

test('passive syntax checking is declared separately from semantic source analysis', () => {
  const byId = new Map(CAPABILITY_REGISTRY.capabilities.map((item) => [item.id, item]))
  assert.equal(byId.get('source-pattern-checks')?.status, 'AVAILABLE_NARROW')
  assert.ok(byId.get('source-pattern-checks').commands.includes('npm run audit:source-check'))
  assert.match(byId.get('source-pattern-checks').limitation, /UNPROVEN/)
  assert.equal(byId.get('source-analysis-provider').status, 'UNAVAILABLE')
})

test('filename-only environment assessment names mixed runtime gaps without claiming deployment evidence', () => {
  const assessment = assessEnvironmentCoverage([
    'server/package.json', 'web/playwright.config.ts', 'python/pyproject.toml',
    'api/server.csproj', 'pom.xml', 'go.mod', 'native/Cargo.toml',
    'compose.yml', 'db/migrations/001.sql', 'infra/main.tf',
  ])
  assert.equal(assessment.basis, 'RECORDED_FILENAMES_ONLY')
  assert.equal(assessment.deployment_evidence, 'NOT_ASSESSED')
  assert.equal(assessment.detected_profiles.length, 9)
  for (const item of assessment.detected_profiles) {
    assert.equal(item.execution_support, item.profile_id === 'node-npm' ? 'AVAILABLE_NARROW' : 'UNAVAILABLE')
  }
  assert.match(assessment.limitations.join(' '), /Source configuration does not establish deployed state/)
})

test('environment assessment bounds and deduplicates recorded evidence and leaves unknown profiles unknown', () => {
  const assessment = assessEnvironmentCoverage(['b.js', 'b.js', ...Array.from({ length: 20 }, (_, index) => `app/${index}.js`)])
  const node = assessment.detected_profiles.find((item) => item.profile_id === 'node-npm')
  assert.equal(node.matching_path_count, 21)
  assert.equal(node.matching_paths.length, ENVIRONMENT_INVENTORY_LIMITS.max_evidence_paths)
  assert.equal(assessment.inventory_path_count, 21)
  assert.equal(assessEnvironmentCoverage(['README.md']).detection_status, 'UNKNOWN')
  assert.equal(assessEnvironmentCoverage([]).deployment_evidence, 'NOT_ASSESSED')
  assert.equal(assessEnvironmentCoverage(['src\\main.py']).detected_profiles[0].matching_paths[0], 'src/main.py')
})

test('environment assessment refuses oversized, malformed, and escaping metadata without filesystem access', () => {
  for (const paths of [null, {}, [null], [''], ['../package.json'], ['C:\\target\\package.json'], ['/etc/passwd'], ['\\\\remote\\share'], ['a\n.py'], ['x'.repeat(4097)], Array(100001).fill('a')]) {
    assert.throws(() => assessEnvironmentCoverage(paths), /inventory/)
  }
  assert.throws(() => assessEnvironmentCoverage(Array(5000).fill('a'.repeat(4096))), /total character limit/)
})

test('capability documentation is generated from the exact public registry', async () => {
  const actual = await readFile(new URL('../docs/capabilities.md', import.meta.url), 'utf8')
  assert.equal(actual, renderCapabilityDocumentation())
})
