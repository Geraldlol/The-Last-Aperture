import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const WORKSPACE = process.cwd()

function planStatic() {
  const out = mkdtempSync(join(tmpdir(), 'rta-rp-'))
  execFileSync(process.execPath, [
    'scripts/audit.mjs', 'plan', 'fixtures/vulnerable', '--seal-source', '--out', out,
  ], { stdio: 'pipe' })
  return join(out, readdirSync(out).find((name) => name.startsWith('run_')))
}

function proofConfig(overrides = {}) {
  return {
    schema_version: '1.0.0',
    job_id: 'proof-verification:cand:web:001',
    proof_files: [{ path: 'test/security/a.test.mjs', contents: 'a\n' }],
    command: { program: 'npm', args: ['test'] },
    destination_guard: { installed: false },
    ...overrides,
  }
}

function writeConfig(directory, config = proofConfig()) {
  const path = join(directory, 'proof.json')
  writeFileSync(path, JSON.stringify(config))
  return path
}

test('run-proof is registered and documented', () => {
  const help = execFileSync(process.execPath, ['scripts/audit.mjs', '--help'], {
    encoding: 'utf8',
  })
  assert.match(help, /run-proof <run\.json\|bundle-directory> <proof-config\.json>/)
})

test('run-proof rejects an unknown option', () => {
  assert.throws(
    () => execFileSync(process.execPath, [
      'scripts/audit.mjs', 'run-proof', 'x', 'y', '--shell', 'sh',
    ], { stdio: 'pipe' }),
    /unknown option --shell/,
  )
})

test('run-proof refuses a STATIC run', () => {
  const bundle = planStatic()
  const configPath = writeConfig(mkdtempSync(join(tmpdir(), 'rta-rpc-')))
  assert.throws(
    () => execFileSync(process.execPath, [
      'scripts/audit.mjs', 'run-proof', bundle, configPath,
    ], { stdio: 'pipe' }),
    /TEST_EXECUTION/,
  )
})

test('run-proof refuses a malformed proof configuration', () => {
  const bundle = planStatic()
  const directory = mkdtempSync(join(tmpdir(), 'rta-rpc-'))
  const configPath = writeConfig(directory, proofConfig({ proof_files: [] }))
  assert.throws(
    () => execFileSync(process.execPath, [
      'scripts/audit.mjs', 'run-proof', bundle, configPath,
    ], { stdio: 'pipe' }),
    /proof configuration is invalid|TEST_EXECUTION/,
  )
})
