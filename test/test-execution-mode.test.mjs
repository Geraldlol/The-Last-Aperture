import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { normalizePolicy } from '../scripts/lib/policy.mjs'
import {
  createRunPlan,
  writeRunPlanBundle,
} from '../scripts/lib/run-engine.mjs'

const WORKSPACE = process.cwd()

function roe(overrides = {}) {
  return {
    schema_version: '1.0',
    policy_id: 'test-execution',
    mode: 'test',
    workspace_root: WORKSPACE,
    capabilities: {
      read_file: { enabled: true, roots: ['.'] },
      write_file: { enabled: true, roots: ['test/security'] },
      execute: { enabled: true, commands: [{ program: 'npm', args: ['test'] }] },
      network: { enabled: false, destinations: [] },
      ...overrides.capabilities,
    },
    ...overrides.top,
  }
}

const policyCodes = (document) => {
  try {
    normalizePolicy(document, { workspaceRoot: WORKSPACE, policySource: 'external' })
    return []
  } catch (error) {
    return (error.issues ?? []).map(({ code }) => code)
  }
}

test('a well-formed test policy normalizes', () => {
  assert.deepEqual(policyCodes(roe()), [])
})

test('test mode refuses network', () => {
  const codes = policyCodes(roe({
    capabilities: {
      network: {
        enabled: true,
        destinations: [{ scheme: 'https', host: 'example.com', ports: [443] }],
      },
    },
  }))
  assert.equal(codes.includes('TEST_MODE_CONTRADICTION'), true)
})

test('test mode requires execute', () => {
  const codes = policyCodes(roe({
    capabilities: { execute: { enabled: false, commands: [] } },
  }))
  assert.equal(codes.includes('TEST_MODE_CONTRADICTION'), true)
})

test('test mode requires write_file roots under a security leaf', () => {
  const codes = policyCodes(roe({
    capabilities: { write_file: { enabled: true, roots: ['src'] } },
  }))
  assert.equal(codes.includes('TEST_MODE_CONTRADICTION'), true)
})

test('the internal planning kernel yields TEST_EXECUTION for a test RoE', async () => {
  const out = mkdtempSync(join(tmpdir(), 'rta-te-'))
  const target = join(WORKSPACE, 'fixtures', 'vulnerable')
  const policy = normalizePolicy(
    { ...roe(), workspace_root: target },
    { workspaceRoot: target, policySource: 'external' },
  )
  const plan = await createRunPlan({
    targetRoot: target,
    lensDirectory: join(WORKSPACE, 'skills', 'red-team-audit', 'lenses'),
    policy,
    sealSource: true,
  })
  const { directory: bundle } = await writeRunPlanBundle(plan, out)
  const run = JSON.parse(readFileSync(join(bundle, 'run.json'), 'utf8'))
  assert.equal(run.capability_mode, 'TEST_EXECUTION')
  assert.equal(run.source_snapshot.kind, 'SOURCE')
})
