import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import Ajv2020 from 'ajv/dist/2020.js'
import { assertValidProofConfig } from '../scripts/lib/proof-execution.mjs'

const schema = JSON.parse(readFileSync('schemas/proof-config.schema.json', 'utf8'))
const validate = new Ajv2020({ strict: true, allErrors: true }).compile(schema)

const config = (overrides = {}) => ({
  schema_version: '1.0.0',
  job_id: 'proof-verification:cand:web:001',
  proof_files: [{ path: 'test/security/authz.test.mjs', contents: 'x\n' }],
  command: { program: 'npm', args: ['test'] },
  destination_guard: { installed: false },
  ...overrides,
})

test('a minimal proof config validates', () => {
  assert.equal(validate(config()), true, JSON.stringify(validate.errors))
})

test('patch_files is optional', () => {
  assert.equal(
    validate(config({ patch_files: [{ path: 'src/a.js', contents: 'y\n' }] })),
    true,
    JSON.stringify(validate.errors),
  )
})

test('proof_files must be non-empty', () => {
  assert.equal(validate(config({ proof_files: [] })), false)
})

test('the job id must name a proof job', () => {
  assert.equal(validate(config({ job_id: 'lens:web-and-api' })), false)
})

test('unknown properties are rejected', () => {
  assert.equal(validate(config({ shell: 'bash -c whoami' })), false)
})

test('an absolute or escaping proof path is rejected', () => {
  assert.equal(validate(config({ proof_files: [{ path: '/etc/passwd', contents: 'x' }] })), false)
  assert.equal(validate(config({ proof_files: [{ path: '../x.js', contents: 'x' }] })), false)
  assert.equal(validate(config({ proof_files: [{ path: 'a/../../x.js', contents: 'x' }] })), false)
})

test('Windows absolute and UNC paths are rejected', () => {
  // The pattern originally allowed these: it only blocked a leading forward
  // slash, so a drive letter or a UNC prefix walked straight through on the
  // platform this most often runs on. materializeFiles would still have caught
  // them, but the schema is the contract.
  for (const path of ['C:/Windows/x', String.raw`C:\Windows\x`, String.raw`\\server\share`]) {
    assert.equal(
      validate(config({ proof_files: [{ path, contents: 'x' }] })),
      false,
      `${path} must be rejected`,
    )
  }
})

test('a backslash anywhere in a path is rejected', () => {
  assert.equal(
    validate(config({ proof_files: [{ path: String.raw`test\security\a.mjs`, contents: 'x' }] })),
    false,
  )
})

test('a filename containing dots but no traversal stays valid', () => {
  assert.equal(
    validate(config({ proof_files: [{ path: 'test/security/a..b.test.mjs', contents: 'x' }] })),
    true,
    JSON.stringify(validate.errors),
  )
})

test('a destination guard may name its harness', () => {
  assert.equal(
    validate(config({
      destination_guard: { installed: true, path: 'test/security/harness/destinations.py' },
    })),
    true,
    JSON.stringify(validate.errors),
  )
})

const v2Config = (overrides = {}) => ({
  ...config({
    schema_version: '2.0.0',
    destination_guard: {
      installed: true,
      path: 'test/security/harness/destinations.mjs',
    },
  }),
  strategy: { id: 'property.node.fast-check', version: '4.9.0' },
  control_command: { program: 'npm', args: ['test', '--', 'control'] },
  oracle: {
    id: 'security-test-exit-differential',
    attack_exit_codes: [1],
    control_exit_codes: [0],
  },
  limits: {
    timeout_ms: 30_000,
    kill_grace_ms: 1_000,
    max_output_bytes: 65_536,
  },
  reproducer: {
    path: 'test/security/authz.test.mjs',
    format: 'text',
  },
  ...overrides,
})

test('a v2 adversarial proof requires attack, control, oracle, strategy, limits, and reproducer', () => {
  assert.equal(validate(v2Config()), true, JSON.stringify(validate.errors))
  for (const field of ['strategy', 'control_command', 'oracle', 'limits', 'reproducer']) {
    const invalid = v2Config()
    delete invalid[field]
    assert.equal(validate(invalid), false, `${field} must be required by v2`)
  }
})

test('v2 accepts only a verification job and a declared destination guard', () => {
  assert.equal(
    validate(v2Config({ job_id: 'proof-existence:cand:web:001' })),
    false,
  )
  assert.equal(
    validate(v2Config({ destination_guard: { installed: false } })),
    false,
  )
})

test('v2 limits are bounded and fail closed', () => {
  for (const limits of [
    { timeout_ms: 0, kill_grace_ms: 1_000, max_output_bytes: 65_536 },
    { timeout_ms: 30_000, kill_grace_ms: 60_000, max_output_bytes: 65_536 },
    { timeout_ms: 30_000, kill_grace_ms: 1_000, max_output_bytes: 100_000_000 },
  ]) {
    assert.equal(validate(v2Config({ limits })), false, JSON.stringify(limits))
  }
})

test('semantic validation rejects overlapping proof/patch paths and an undeclared reproducer', () => {
  assert.throws(
    () => assertValidProofConfig(v2Config({
      patch_files: [{ path: 'test/security/authz.test.mjs', contents: 'patched\n' }],
    })),
    /overlap|disjoint/i,
  )
  assert.throws(
    () => assertValidProofConfig(v2Config({
      reproducer: { path: 'test/security/missing.txt', format: 'text' },
    })),
    /reproducer/i,
  )
})
