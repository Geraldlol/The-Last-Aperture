import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  CliUnavailableError,
  DEFAULT_CLI_LIMITS,
  ImpactCapExceededError,
  ImpactCounters,
  probeCli,
  resolveNodeShim,
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

// An npm-generated .cmd shim, byte-for-byte the shape npm emits.
async function npmShim(name, scriptBody, { flags = '--no-deprecation' } = {}) {
  const { mkdtemp, writeFile, mkdir } = await import('node:fs/promises')
  const { tmpdir } = await import('node:os')
  const { join } = await import('node:path')
  const directory = await mkdtemp(join(tmpdir(), 'rta-shim-'))
  await mkdir(join(directory, 'node_modules', 'pkg', 'bin'), { recursive: true })
  const entry = join(directory, 'node_modules', 'pkg', 'bin', 'run.js')
  await writeFile(entry, scriptBody, 'utf8')
  await writeFile(
    join(directory, `${name}.cmd`),
    '@ECHO off\r\nGOTO start\r\n:find_dp0\r\nSET dp0=%~dp0\r\nEXIT /b\r\n:start\r\n'
    + 'SETLOCAL\r\nCALL :find_dp0\r\n\r\nIF EXIST "%dp0%\\node.exe" (\r\n'
    + '  SET "_prog=%dp0%\\node.exe"\r\n) ELSE (\r\n  SET "_prog=node"\r\n)\r\n\r\n'
    + `endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & "%_prog%" ${flags} `
    + '"%dp0%\\node_modules\\pkg\\bin\\run.js" %*\r\n',
    'utf8',
  )
  return { directory, entry }
}

test('an npm shim is resolved to a direct node invocation, with no shell', async (t) => {
  if (process.platform !== 'win32') return t.skip('shell shims are a Windows concern')
  const { delimiter } = await import('node:path')
  const shim = await npmShim(
    'rta-shimmed-cli',
    'process.stdout.write(process.argv.slice(2).join(" ") || "2.4.0")',
  )
  const env = { ...process.env, PATH: `${shim.directory}${delimiter}${process.env.PATH}` }

  const probe = await probeCli('rta-shimmed-cli', { versionArgs: ['--version'], env })
  assert.equal(probe.present, true)
  assert.equal(probe.version, '--version')
  assert.equal(probe.via_node_shim.endsWith('rta-shimmed-cli.cmd'), true)

  // The argument vector must survive verbatim — that is the whole reason the
  // shell is refused in the first place.
  const result = await runBoundedCli({
    name: 'rta-shimmed-cli',
    args: ['data', 'query', '-q', 'SELECT Id FROM Account WHERE Name = 1'],
    env,
  })
  assert.equal(result.code, 0)
  assert.equal(
    result.stdout.toString('utf8'),
    'data query -q SELECT Id FROM Account WHERE Name = 1',
  )
})

test('a shim that is not a resolvable node invocation is still refused', async (t) => {
  if (process.platform !== 'win32') return t.skip('shell shims are a Windows concern')
  const { mkdtemp, writeFile } = await import('node:fs/promises')
  const { tmpdir } = await import('node:os')
  const { join, delimiter } = await import('node:path')
  const directory = await mkdtemp(join(tmpdir(), 'rta-shim-'))
  await writeFile(join(directory, 'rta-opaque-cli.cmd'), '@echo off\r\necho 1.0.0\r\n')
  const env = { ...process.env, PATH: `${directory}${delimiter}${process.env.PATH}` }

  // Fail-closed, and the reason names the shim rather than claiming the tool is
  // missing — an operator would act on those two differently.
  const probe = await probeCli('rta-opaque-cli', { versionArgs: ['--version'], env })
  assert.equal(probe.present, false)
  assert.match(probe.reason, /shell shim/i)
  assert.match(probe.reason, /rta-opaque-cli\.cmd/)
  assert.equal(/not found on PATH/.test(probe.reason), false)

  await assert.rejects(
    () => runBoundedCli({ name: 'rta-opaque-cli', args: ['x'], env }),
    (error) => error instanceof CliUnavailableError && /shell shim/i.test(error.message),
  )
})

test('a shim that resolves but then fails says so, not "cannot resolve"', async (t) => {
  if (process.platform !== 'win32') return t.skip('shell shims are a Windows concern')
  const { delimiter } = await import('node:path')
  const shim = await npmShim('rta-failing-cli', 'process.exit(3)')
  const env = { ...process.env, PATH: `${shim.directory}${delimiter}${process.env.PATH}` }
  const probe = await probeCli('rta-failing-cli', { versionArgs: ['--version'], env })
  assert.equal(probe.present, false)
  assert.match(probe.reason, /resolved through its npm shim/i)
  assert.match(probe.reason, /exited 3/)
  // The two faults send an operator to different places.
  assert.equal(/cannot resolve/i.test(probe.reason), false)
})

test('a shim whose entry script is absent does not resolve', async (t) => {
  if (process.platform !== 'win32') return t.skip('shell shims are a Windows concern')
  const { rm } = await import('node:fs/promises')
  const { delimiter } = await import('node:path')
  const shim = await npmShim('rta-broken-cli', 'process.stdout.write("x")')
  await rm(shim.entry)
  const env = { ...process.env, PATH: `${shim.directory}${delimiter}${process.env.PATH}` }
  const probe = await probeCli('rta-broken-cli', { versionArgs: ['--version'], env })
  assert.equal(probe.present, false)
  assert.match(probe.reason, /shell shim/i)
})

test('shim resolution is not a general .bat interpreter', async () => {
  const { mkdtemp, writeFile } = await import('node:fs/promises')
  const { tmpdir } = await import('node:os')
  const { join } = await import('node:path')
  const directory = await mkdtemp(join(tmpdir(), 'rta-shim-'))
  // A shim that reaches for shell expansion we deliberately do not perform.
  const path = join(directory, 'evil.cmd')
  await writeFile(
    path,
    'endLocal & "%_prog%" "%dp0%\\node_modules\\pkg\\bin\\run.js" %SOMETHING% %*\r\n',
    'utf8',
  )
  assert.equal(resolveNodeShim(path), null)
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
