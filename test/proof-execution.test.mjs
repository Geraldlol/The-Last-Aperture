import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { executeProof } from '../scripts/lib/proof-execution.mjs'
import { normalizePolicy } from '../scripts/lib/policy.mjs'
import { inventoryRepository } from '../scripts/lib/inventory.mjs'

function makeTarget() {
  const root = mkdtempSync(join(tmpdir(), 'rta-pe-target-'))
  mkdirSync(join(root, 'src'), { recursive: true })
  writeFileSync(join(root, 'src', 'app.js'), 'export const x = 1\n')
  return root
}

const mirrorPath = () => join(mkdtempSync(join(tmpdir(), 'rta-pe-mirror-')), 'work')

const policyFor = (root) => normalizePolicy({
  schema_version: '1.0',
  policy_id: 'proof',
  mode: 'test',
  workspace_root: root,
  capabilities: {
    read_file: { enabled: true, roots: ['.'] },
    write_file: { enabled: true, roots: ['test/security'] },
    execute: {
      enabled: true,
      commands: [
        { program: 'npm', args: ['test'] },
        { program: 'npm', args: ['test', '--', 'control'] },
      ],
    },
    network: { enabled: false, destinations: [] },
  },
}, { workspaceRoot: root, policySource: 'external' })

const baseConfig = {
  schema_version: '1.0.0',
  job_id: 'proof-verification:cand:1',
  proof_files: [{ path: 'test/security/a.test.mjs', contents: 'a\n' }],
  command: { program: 'npm', args: ['test'] },
  destination_guard: { installed: false },
}

async function run(config, spawn, overrides = {}) {
  const targetRoot = overrides.targetRoot ?? makeTarget()
  const mirrorRoot = overrides.mirrorRoot ?? mirrorPath()
  const { treeDigest } = await inventoryRepository(targetRoot)
  return executeProof({
    targetRoot,
    mirrorRoot,
    expectedTreeDigest: treeDigest,
    policy: policyFor(targetRoot),
    config,
    spawn,
  })
}

test('a demonstration-only proof runs the command once', async () => {
  const calls = []
  const spawn = async (program, args, cwd) => {
    calls.push({ program, args, cwd })
    return { code: 1, stdout: 'assertion failed', stderr: '' }
  }
  const outcome = await run(baseConfig, spawn)
  assert.equal(calls.length, 1)
  assert.equal(calls[0].program, 'npm')
  assert.deepEqual(calls[0].args, ['test'])
  assert.equal(outcome.demonstration.code, 1)
  assert.equal(outcome.remediation, null)
})

test('a v2 proof runs a paired control after the attack', async () => {
  const calls = []
  const spawn = async (program, args, cwd, limits) => {
    calls.push({ program, args, cwd, limits })
    return args.at(-1) === 'control'
      ? { code: 0, stdout: 'control passed', stderr: '' }
      : { code: 1, stdout: 'attack reproduced', stderr: '' }
  }
  const outcome = await run({
    ...baseConfig,
    schema_version: '2.0.0',
    destination_guard: { installed: true, path: 'test/security/a.test.mjs' },
    strategy: { id: 'exact.reproducer', version: '1.0.0' },
    control_command: { program: 'npm', args: ['test', '--', 'control'] },
    oracle: {
      id: 'security-test-exit-differential',
      attack_exit_codes: [1],
      control_exit_codes: [0],
    },
    limits: { timeout_ms: 1_000, kill_grace_ms: 10, max_output_bytes: 4_096 },
    reproducer: { path: 'test/security/a.test.mjs', format: 'text' },
  }, spawn)
  assert.deepEqual(calls.map(({ args }) => args), [
    ['test'],
    ['test', '--', 'control'],
  ])
  assert.deepEqual(calls.map(({ limits }) => limits), [
    { timeout_ms: 1_000, kill_grace_ms: 10, max_output_bytes: 4_096 },
    { timeout_ms: 1_000, kill_grace_ms: 10, max_output_bytes: 4_096 },
  ])
  assert.equal(outcome.demonstration.code, 1)
  assert.equal(outcome.control.code, 0)
})

test('an unauthorized v2 control command is refused before the mirror is created', async () => {
  const targetRoot = makeTarget()
  const mirrorRoot = mirrorPath()
  let spawned = false
  await assert.rejects(
    () => run({
      ...baseConfig,
      schema_version: '2.0.0',
      destination_guard: { installed: true, path: 'test/security/a.test.mjs' },
      strategy: { id: 'exact.reproducer', version: '1.0.0' },
      control_command: { program: 'node', args: ['control.mjs'] },
      oracle: {
        id: 'security-test-exit-differential',
        attack_exit_codes: [1],
        control_exit_codes: [0],
      },
      limits: { timeout_ms: 1_000, kill_grace_ms: 10, max_output_bytes: 4_096 },
      reproducer: { path: 'test/security/a.test.mjs', format: 'text' },
    }, async () => {
      spawned = true
      return { code: 0, stdout: '', stderr: '' }
    }, { targetRoot, mirrorRoot }),
    /control command.*not authorized|not authorized.*control command/i,
  )
  assert.equal(spawned, false)
  assert.equal(existsSync(mirrorRoot), false)
})

test('a proof with a patch runs the command twice, patched only on the second', async () => {
  const seen = []
  const codes = [1, 0]
  const spawn = async (_program, _args, cwd) => {
    seen.push(readFileSync(join(cwd, 'src', 'app.js'), 'utf8'))
    return { code: codes.shift(), stdout: '', stderr: '' }
  }
  const outcome = await run({
    ...baseConfig,
    patch_files: [{ path: 'src/app.js', contents: 'export const x = 2\n' }],
  }, spawn)
  assert.equal(outcome.demonstration.code, 1)
  assert.equal(outcome.remediation.code, 0)
  assert.deepEqual(seen, ['export const x = 1\n', 'export const x = 2\n'])
})

test('a command absent from the allowlist is refused before anything is copied', async () => {
  const targetRoot = makeTarget()
  const mirrorRoot = mirrorPath()
  let spawned = false
  const spawn = async () => {
    spawned = true
    return { code: 0, stdout: '', stderr: '' }
  }
  await assert.rejects(
    () => run(
      { ...baseConfig, command: { program: 'curl', args: ['http://example.test'] } },
      spawn,
      { targetRoot, mirrorRoot },
    ),
    /not authorized/i,
  )
  assert.equal(spawned, false)
  assert.equal(existsSync(mirrorRoot), false, 'a refused command must leave no mirror')
})

test('a mutated target fails the digest re-check and retains the mirror', async () => {
  const targetRoot = makeTarget()
  const mirrorRoot = mirrorPath()
  const spawn = async () => {
    writeFileSync(join(targetRoot, 'src', 'app.js'), 'export const x = 99\n')
    return { code: 1, stdout: '', stderr: '' }
  }
  await assert.rejects(
    () => run(baseConfig, spawn, { targetRoot, mirrorRoot }),
    /tree digest changed/,
  )
  assert.equal(existsSync(mirrorRoot), true, 'the mirror survives a mutation failure')
})

test('owned paths are the files the audit introduced, not the whole copy', async () => {
  const spawn = async () => ({ code: 1, stdout: '', stderr: '' })
  const outcome = await run({
    ...baseConfig,
    patch_files: [{ path: 'src/app.js', contents: 'export const x = 2\n' }],
  }, spawn)
  assert.deepEqual(outcome.ownedPaths, ['src/app.js', 'test/security/a.test.mjs'])
})

test('the mirror is destroyed on success', async () => {
  const spawn = async () => ({ code: 1, stdout: '', stderr: '' })
  const outcome = await run(baseConfig, spawn)
  assert.equal(outcome.mirrorRetained, false)
  assert.equal(existsSync(outcome.mirrorRoot), false)
})
