import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { normalizePolicy } from '../scripts/lib/policy.mjs'

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

test('a test RoE plans and yields TEST_EXECUTION', () => {
  const out = mkdtempSync(join(tmpdir(), 'rta-te-'))
  const roePath = join(out, 'roe.json')
  const target = join(WORKSPACE, 'fixtures', 'vulnerable')
  writeFileSync(roePath, JSON.stringify({ ...roe(), workspace_root: target }))
  execFileSync(process.execPath, [
    'scripts/audit.mjs', 'plan', 'fixtures/vulnerable',
    '--roe', roePath, '--seal-source', '--out', out,
  ], { stdio: 'pipe' })
  const bundle = join(out, readdirSync(out).find((name) => name.startsWith('run_')))
  const run = JSON.parse(readFileSync(join(bundle, 'run.json'), 'utf8'))
  assert.equal(run.capability_mode, 'TEST_EXECUTION')
})
