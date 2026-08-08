import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  CliUnavailableError,
  DEFAULT_CLI_LIMITS,
  ImpactCapExceededError,
  ImpactCounters,
  probeCli,
  runBoundedCli,
} from '../scripts/lib/evidence-cli-runner.mjs'
import { absentCliResolver, stubCli } from './helpers/stub-cli.mjs'

test('a present CLI probes with its version', async () => {
  const stub = await stubCli('crane', 'process.stdout.write("crane version 0.19.1\\n")')
  const probe = await probeCli('crane', { versionArgs: ['version'], resolver: stub.resolver })
  assert.equal(probe.present, true)
  assert.match(probe.version, /0\.19\.1/)
})

test('an absent CLI probes absent with a named reason, and never throws by itself', async () => {
  const probe = await probeCli('crane', {
    versionArgs: ['--version'],
    resolver: absentCliResolver,
  })
  assert.equal(probe.present, false)
  assert.equal(probe.version, null)
  assert.match(probe.reason, /not found|ENOENT/i)
})

test('a Windows shell shim is reported as a shim, not as a missing tool', async (t) => {
  if (process.platform !== 'win32') return t.skip('shell shims are a Windows concern')
  const { mkdtemp, writeFile } = await import('node:fs/promises')
  const { tmpdir } = await import('node:os')
  const { join, delimiter } = await import('node:path')
  const directory = await mkdtemp(join(tmpdir(), 'rta-shim-'))
  await writeFile(join(directory, 'rta-fake-cli.cmd'), '@echo off\r\necho 1.0.0\r\n')

  const probe = await probeCli('rta-fake-cli', {
    versionArgs: ['--version'],
    env: { ...process.env, PATH: `${directory}${delimiter}${process.env.PATH}` },
  })
  // Fail-closed is right, but "not found on PATH" would be a false reason for a
  // tool that is plainly installed, and an operator would act on it wrongly.
  assert.equal(probe.present, false)
  assert.match(probe.reason, /shell shim/i)
  assert.match(probe.reason, /rta-fake-cli\.cmd/)
  assert.equal(/not found on PATH/.test(probe.reason), false)
})

test('a missing dependency is a failure, never an empty success', async () => {
  await assert.rejects(
    () => runBoundedCli({ name: 'crane', args: ['pull'], resolver: absentCliResolver }),
    (error) => error instanceof CliUnavailableError && /not found/i.test(error.message),
  )
})

test('stdout is returned as bytes and the command is counted', async () => {
  const stub = await stubCli('crane', 'process.stdout.write("blob-bytes")')
  const result = await runBoundedCli({ name: 'crane', args: ['export'], resolver: stub.resolver })
  assert.equal(result.code, 0)
  assert.equal(result.stdout.toString('utf8'), 'blob-bytes')
  assert.equal(result.counters.commands, 1)
  assert.ok(result.counters.bytes_read > 0)
})

test('the argument vector reaches the process verbatim', async () => {
  const stub = await stubCli('kubectl', 'process.stdout.write(JSON.stringify(args))')
  const result = await runBoundedCli({
    name: 'kubectl',
    args: ['get', 'pods', '-n', 'clinical', '-o', 'json'],
    resolver: stub.resolver,
  })
  assert.deepEqual(
    JSON.parse(result.stdout.toString('utf8')),
    ['get', 'pods', '-n', 'clinical', '-o', 'json'],
  )
})

test('a non-zero exit is surfaced, not swallowed', async () => {
  const stub = await stubCli(
    'crane',
    'process.stderr.write("UNAUTHORIZED\\n"); process.exit(1)',
  )
  const result = await runBoundedCli({ name: 'crane', args: ['pull'], resolver: stub.resolver })
  assert.equal(result.code, 1)
  assert.match(result.stderr, /UNAUTHORIZED/)
})

test('impact counters halt acquisition at their caps', () => {
  const counters = new ImpactCounters({ maxCommands: 2, maxObjects: 3, maxBytes: 100 })
  counters.record({ commands: 1, bytes: 40, objects: 1 })
  counters.record({ commands: 1, bytes: 40, objects: 1 })
  assert.doesNotThrow(() => counters.assertWithinCaps())
  counters.record({ commands: 1, bytes: 0, objects: 0 })
  assert.throws(() => counters.assertWithinCaps(), ImpactCapExceededError)
})

test('the counter snapshot is what a bundle records', () => {
  const counters = new ImpactCounters({ maxCommands: 8, maxObjects: 8, maxBytes: 1024 })
  counters.record({ commands: 1, bytes: 12, objects: 2 })
  assert.deepEqual(counters.snapshot(), {
    commands: 1,
    bytes_read: 12,
    objects_touched: 2,
    caps: { commands: 8, bytes_read: 1024, objects_touched: 8 },
  })
})

test('the runner never accepts a shell string', async () => {
  await assert.rejects(
    () => runBoundedCli({ name: 'crane', args: 'pull registry/img && rm -rf /' }),
    /args must be an array/i,
  )
})

test('the default limits are bounded, not unbounded', () => {
  assert.ok(DEFAULT_CLI_LIMITS.timeoutMs > 0)
  assert.ok(DEFAULT_CLI_LIMITS.maxCommands > 0)
  assert.ok(DEFAULT_CLI_LIMITS.maxObjects > 0)
})
