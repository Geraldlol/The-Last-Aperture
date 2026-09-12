import { test } from 'node:test'
import assert from 'node:assert/strict'
import { access, mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
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

function processExists(pid) {
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    if (error?.code === 'ESRCH') return false
    throw error
  }
}

test('a caller can explicitly retain a present CLI version', async () => {
  const stub = await stubCli('crane', 'process.stdout.write("crane version 0.19.1\\n")')
  const probe = await probeCli('crane', {
    versionArgs: ['version'],
    resolver: stub.resolver,
    includeVersion: true,
  })
  assert.equal(probe.present, true)
  assert.match(probe.version, /0\.19\.1/)
})

test('a probe discards provider-controlled version stdout by default', async () => {
  const secret = 'unclassified-version-channel-secret'
  const stub = await stubCli('crane', `process.stdout.write(process.env.PROBE_SECRET ?? 'absent')`)
  const probe = await probeCli('crane', {
    versionArgs: ['version'],
    resolver: stub.resolver,
    env: { ...process.env, PROBE_SECRET: secret },
  })
  assert.equal(probe.present, true)
  assert.equal(probe.version, null)
  assert.equal(JSON.stringify(probe).includes(secret), false)
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

test('a native CLI whose version probe exits nonzero is unavailable', async () => {
  const stub = await stubCli(
    'crane',
    'process.stdout.write("forged version 1.0.0\\n"); process.exit(3)',
  )
  const probe = await probeCli('crane', { versionArgs: ['version'], resolver: stub.resolver })
  assert.equal(probe.present, false)
  assert.equal(probe.version, null)
  assert.match(probe.reason, /version probe failed.*3/i)
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

  const probe = await probeCli('rta-shimmed-cli', {
    versionArgs: ['--version'], env, includeVersion: true,
  })
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

test('repeated dispatch rechecks a verified invocation snapshot without rereading executable bytes', async () => {
  const stub = await stubCli('crane', 'process.stdout.write("ok")')
  const probe = await probeCli('crane', { versionArgs: ['version'], resolver: stub.resolver })
  assert.ok(probe.invocation.identity.total_bytes > 0)
  for (let index = 0; index < 2; index += 1) {
    const result = await runBoundedCli({
      name: 'crane',
      args: ['read'],
      resolver: stub.resolver,
      verifiedInvocationIdentity: probe.invocation.identity,
    })
    assert.equal(result.code, 0)
    assert.equal(result.identity_content_bytes_read, 0)
  }
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
  assert.equal(result.counters.bytes_read, Buffer.byteLength('UNAUTHORIZED\n'))
})

test('the bounded runner terminates descendants when the CLI leader exits', async () => {
  const runRoot = await mkdtemp(join(tmpdir(), 'rta-cli-tree-'))
  const markerPath = join(runRoot, 'survived.marker')
  const pidPath = `${markerPath}.pid`
  const childCode = [
    "const { writeFileSync } = require('node:fs')",
    `setTimeout(() => writeFileSync(${JSON.stringify(markerPath)}, 'survived'), 700)`,
    'setInterval(() => {}, 1000)',
  ].join(';')
  const stub = await stubCli('tree-root', `
    const { spawn } = await import('node:child_process')
    const { writeFileSync } = await import('node:fs')
    const descendant = spawn(process.execPath, ['-e', ${JSON.stringify(childCode)}], { stdio: 'ignore' })
    descendant.unref()
    writeFileSync(${JSON.stringify(pidPath)}, String(descendant.pid))
    process.stdout.write('leader-exited')
  `)
  let descendantPid
  try {
    const result = await runBoundedCli({
      name: 'tree-root',
      args: [],
      resolver: stub.resolver,
      limits: { ...DEFAULT_CLI_LIMITS, timeoutMs: 5_000 },
    })
    assert.equal(result.stdout.toString('utf8'), 'leader-exited')
    assert.equal(result.termination_confirmed, true)
    assert.equal(
      result.supervision_mode,
      process.platform === 'win32' ? 'WINDOWS_JOB_OBJECT' : 'POSIX_PROCESS_GROUP',
    )
    descendantPid = Number.parseInt(await readFile(pidPath, 'utf8'), 10)
    assert.equal(Number.isSafeInteger(descendantPid) && descendantPid > 0, true)
    await new Promise((resolveWait) => setTimeout(resolveWait, 1_000))
    await assert.rejects(() => access(markerPath))
    assert.equal(processExists(descendantPid), false)
  } finally {
    if (descendantPid && processExists(descendantPid)) {
      try { process.kill(descendantPid, 'SIGKILL') } catch {}
    }
    await rm(runRoot, { recursive: true, force: true })
  }
})

test('a self-detached POSIX descendant holding output open settles as cleanup-unconfirmed', async (t) => {
  if (process.platform === 'win32') return t.skip('Windows Job Objects contain self-detached descendants')
  const runRoot = await mkdtemp(join(tmpdir(), 'rta-cli-escaped-session-'))
  const markerPath = join(runRoot, 'escaped.marker')
  const pidPath = join(runRoot, 'escaped.pid')
  const childCode = [
    "const { writeFileSync } = require('node:fs')",
    `setTimeout(() => writeFileSync(${JSON.stringify(markerPath)}, 'escaped'), 6500)`,
    'setInterval(() => {}, 1000)',
  ].join(';')
  const stub = await stubCli('escaped-session-root', `
    const { spawn } = await import('node:child_process')
    const { writeFileSync } = await import('node:fs')
    const escaped = spawn(process.execPath, ['-e', ${JSON.stringify(childCode)}], {
      detached: true,
      stdio: 'inherit',
    })
    escaped.unref()
    writeFileSync(${JSON.stringify(pidPath)}, String(escaped.pid))
  `)
  let escapedPid
  const started = Date.now()
  try {
    const result = await runBoundedCli({
      name: 'escaped-session-root',
      args: [],
      resolver: stub.resolver,
      limits: { ...DEFAULT_CLI_LIMITS, timeoutMs: 10_000 },
    })
    assert.equal(result.code, 124)
    assert.equal(result.failure_code, 'EVIDENCE_CLI_TERMINATION_UNCONFIRMED')
    assert.equal(result.termination_confirmed, false)
    assert.equal(result.supervision_mode, 'POSIX_PROCESS_GROUP')
    assert.ok(Date.now() - started < 6500)
    escapedPid = Number.parseInt(await readFile(pidPath, 'utf8'), 10)
    assert.equal(processExists(escapedPid), true)
    await assert.rejects(() => access(markerPath), /ENOENT/)
  } finally {
    if (escapedPid && processExists(escapedPid)) {
      try { process.kill(escapedPid, 'SIGKILL') } catch {}
    }
    await rm(runRoot, { recursive: true, force: true })
  }
})

test('a POSIX probe reports cleanup-unconfirmed instead of mislabeling it as a timeout', async (t) => {
  if (process.platform === 'win32') return t.skip('Windows Job Objects contain self-detached descendants')
  const runRoot = await mkdtemp(join(tmpdir(), 'rta-cli-escaped-probe-'))
  const pidPath = join(runRoot, 'escaped.pid')
  const childCode = 'setInterval(() => {}, 1000)'
  const stub = await stubCli('escaped-probe-root', `
    const { spawn } = await import('node:child_process')
    const { writeFileSync } = await import('node:fs')
    const escaped = spawn(process.execPath, ['-e', ${JSON.stringify(childCode)}], {
      detached: true,
      stdio: 'inherit',
    })
    escaped.unref()
    writeFileSync(${JSON.stringify(pidPath)}, String(escaped.pid))
  `)
  let escapedPid
  try {
    const probe = await probeCli('escaped-probe-root', {
      versionArgs: ['version'],
      resolver: stub.resolver,
    })
    assert.equal(probe.present, false)
    assert.equal(probe.termination_confirmed, false)
    assert.equal(probe.supervision_mode, 'POSIX_PROCESS_GROUP')
    assert.match(probe.reason, /POSIX_PROCESS_GROUP cleanup could not be confirmed.*may remain/i)
    escapedPid = Number.parseInt(await readFile(pidPath, 'utf8'), 10)
    assert.equal(processExists(escapedPid), true)
  } finally {
    if (escapedPid && processExists(escapedPid)) {
      try { process.kill(escapedPid, 'SIGKILL') } catch {}
    }
    await rm(runRoot, { recursive: true, force: true })
  }
})

test('an observer rejection records and then zeroes the bounded stdout prefix', async () => {
  const output = 'observed-before-object-cap'
  const stub = await stubCli('observer-cap', `process.stdout.write(${JSON.stringify(output)})`)
  const counters = new ImpactCounters({ maxCommands: 2, maxObjects: 1, maxBytes: 1024 })
  const observerError = new ImpactCapExceededError('objects_touched', 2, 1)
  await assert.rejects(
    () => runBoundedCli({
      name: 'observer-cap',
      args: [],
      resolver: stub.resolver,
      counters,
      stdoutObserver: () => { throw observerError },
    }),
    (error) => error === observerError,
  )
  assert.equal(counters.snapshot().bytes_read, Buffer.byteLength(output))
  if (Buffer.isBuffer(observerError.capturedStdout)) {
    assert.equal(observerError.capturedStdout.length, Buffer.byteLength(output))
    assert.equal(observerError.capturedStdout.every((byte) => byte === 0), true)
  }
})

test('impact counters halt acquisition at their caps', () => {
  const counters = new ImpactCounters({ maxCommands: 2, maxObjects: 3, maxBytes: 100 })
  counters.record({ commands: 1, bytes: 40, objects: 1 })
  counters.record({ commands: 1, bytes: 40, objects: 1 })
  assert.doesNotThrow(() => counters.assertWithinCaps())
  assert.throws(
    () => counters.record({ commands: 1, bytes: 0, objects: 0 }),
    ImpactCapExceededError,
  )
  assert.equal(counters.snapshot().commands, 2)
})

test('impact caps and increments must be finite non-negative safe integers', async () => {
  for (const invalid of [Number.NaN, Number.POSITIVE_INFINITY, -1, 1.5]) {
    assert.throws(
      () => new ImpactCounters({ maxCommands: invalid, maxObjects: 1, maxBytes: 1 }),
      /safe integer/i,
    )
  }

  const counters = new ImpactCounters({ maxCommands: 1, maxObjects: 1, maxBytes: 1 })
  assert.throws(() => counters.record({ bytes: Number.NaN }), /safe integer/i)
  assert.throws(() => counters.record({ objects: -1 }), /safe integer/i)

  let resolverCalls = 0
  await assert.rejects(
    () => runBoundedCli({
      name: 'crane',
      args: ['version'],
      limits: { maxStdoutBytes: Number.POSITIVE_INFINITY },
      resolver: () => {
        resolverCalls += 1
        throw new Error('must not resolve')
      },
    }),
    /maxStdoutBytes.*safe integer/i,
  )
  assert.equal(resolverCalls, 0)
})

test('an exhausted command budget refuses before resolver or process launch', async () => {
  const counters = new ImpactCounters({ maxCommands: 0, maxObjects: 1, maxBytes: 1024 })
  let resolverCalls = 0
  await assert.rejects(
    () => runBoundedCli({
      name: 'crane',
      args: ['version'],
      counters,
      resolver: () => {
        resolverCalls += 1
        throw new Error('must not resolve')
      },
    }),
    (error) => error instanceof ImpactCapExceededError && error.dimension === 'commands',
  )
  assert.equal(resolverCalls, 0)
})

test('stdout, stderr, and combined output are each halted at their byte caps', async () => {
  const stdout = await stubCli('stdout-cap', 'process.stdout.write("x".repeat(32))')
  const stdoutCounters = new ImpactCounters({ maxCommands: 2, maxObjects: 1, maxBytes: 64 })
  await assert.rejects(
    () => runBoundedCli({
      name: 'stdout-cap',
      args: [],
      resolver: stdout.resolver,
      counters: stdoutCounters,
      limits: { ...DEFAULT_CLI_LIMITS, maxStdoutBytes: 8, maxTotalOutputBytes: 64 },
    }),
    (error) => error instanceof ImpactCapExceededError
      && error.dimension === 'stdout_bytes'
      && error.observedOutputBytes >= 9,
  )
  assert.ok(stdoutCounters.snapshot().bytes_read >= 9)

  const stderr = await stubCli('stderr-cap', 'process.stderr.write("x".repeat(32))')
  const stderrCounters = new ImpactCounters({ maxCommands: 2, maxObjects: 1, maxBytes: 64 })
  await assert.rejects(
    () => runBoundedCli({
      name: 'stderr-cap',
      args: [],
      resolver: stderr.resolver,
      counters: stderrCounters,
      limits: { ...DEFAULT_CLI_LIMITS, maxStderrBytes: 8, maxTotalOutputBytes: 64 },
    }),
    (error) => error instanceof ImpactCapExceededError
      && error.dimension === 'stderr_bytes'
      && error.observedOutputBytes >= 9,
  )
  assert.ok(stderrCounters.snapshot().bytes_read >= 9)

  const combined = await stubCli(
    'combined-cap',
    'process.stdout.write("o".repeat(8)); process.stderr.write("e".repeat(8))',
  )
  const combinedCounters = new ImpactCounters({ maxCommands: 2, maxObjects: 1, maxBytes: 12 })
  await assert.rejects(
    () => runBoundedCli({
      name: 'combined-cap',
      args: [],
      resolver: combined.resolver,
      counters: combinedCounters,
      limits: {
        ...DEFAULT_CLI_LIMITS,
        maxStdoutBytes: 16,
        maxStderrBytes: 16,
        maxTotalOutputBytes: 12,
      },
    }),
    (error) => error instanceof ImpactCapExceededError
      && error.dimension === 'output_bytes'
      && error.observedOutputBytes >= 13,
  )
  assert.equal(combinedCounters.snapshot().bytes_read, 13)
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
  assert.ok(DEFAULT_CLI_LIMITS.maxStderrBytes > 0)
  assert.ok(DEFAULT_CLI_LIMITS.maxTotalOutputBytes > 0)
})
