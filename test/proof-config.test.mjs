import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import Ajv2020 from 'ajv/dist/2020.js'

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
