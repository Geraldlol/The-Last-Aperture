import assert from 'node:assert/strict'
import { test } from 'node:test'
import { spawnProofCommand } from '../scripts/audit.mjs'

test('proof process output is byte bounded without deadlocking the child', async () => {
  const result = await spawnProofCommand(
    process.execPath,
    ['-e', "process.stdout.write('x'.repeat(10000)); process.stderr.write('y'.repeat(10000))"],
    process.cwd(),
    { timeout_ms: 5_000, kill_grace_ms: 50, max_output_bytes: 1_024 },
  )
  assert.equal(result.code, 0)
  assert.equal(result.stdout_truncated, true)
  assert.equal(result.stderr_truncated, true)
  assert.ok(Buffer.byteLength(result.stdout) <= 1_024)
  assert.ok(Buffer.byteLength(result.stderr) <= 1_024)
})

test('proof process timeout terminates the child and records a bounded outcome', async () => {
  const started = Date.now()
  const result = await spawnProofCommand(
    process.execPath,
    ['-e', 'setInterval(() => {}, 1000)'],
    process.cwd(),
    { timeout_ms: 100, kill_grace_ms: 50, max_output_bytes: 1_024 },
  )
  assert.equal(result.timed_out, true)
  assert.equal(result.code, 124)
  assert.ok(Date.now() - started < 3_000, 'the timeout must not leave the child running')
})
