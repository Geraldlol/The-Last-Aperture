import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { test } from 'node:test'
import {
  assertLocalFilesystemEndpoint,
  assertNoRemoteFilesystemArguments,
} from '../scripts/lib/filesystem-endpoint.mjs'

test('filesystem endpoint guard rejects UNC, slash-UNC, device, and object-manager syntax', () => {
  for (const value of [
    '\\\\host\\share\\bundle',
    '//host/share/bundle',
    '\\\\?\\C:\\bundle',
    '\\\\.\\pipe\\bundle',
    '\\??\\C:\\bundle',
  ]) {
    assert.throws(
      () => assertLocalFilesystemEndpoint(value),
      (error) => error?.code === 'FILESYSTEM_ENDPOINT_NOT_LOCAL',
      value,
    )
  }
})

test('filesystem endpoint guard permits ordinary local and relative paths', () => {
  for (const value of ['C:\\audit-runs\\bundle', '/var/tmp/audit', '.audit-runs']) {
    assert.equal(assertLocalFilesystemEndpoint(value), value)
  }
  assert.doesNotThrow(() => assertNoRemoteFilesystemArguments([
    'plan',
    'https://target.example/path',
    '--out',
    '.audit-runs',
  ]))
})

test('audit CLI rejects a UNC output before repository access', () => {
  const result = spawnSync(process.execPath, [
    'scripts/audit.mjs',
    'plan',
    'C:\\definitely-missing\\repository',
    '--out',
    '\\\\untrusted-host\\share\\bundle',
  ], { encoding: 'utf8', shell: false, windowsHide: true })
  assert.equal(result.status, 1)
  assert.match(result.stderr, /must be a local filesystem path/i)
  assert.doesNotMatch(result.stderr, /ENOENT|not found/i)
})

test('bounty CLI rejects a UNC policy path before reading it', () => {
  const result = spawnSync(process.execPath, [
    'scripts/bounty.mjs',
    'plan',
    '--policy-file',
    '\\\\untrusted-host\\share\\policy.txt',
  ], { encoding: 'utf8', shell: false, windowsHide: true })
  assert.equal(result.status, 1)
  assert.match(result.stderr, /must be a local filesystem path/i)
  assert.doesNotMatch(result.stderr, /ENOENT|not found/i)
})
