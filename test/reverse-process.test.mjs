import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { access, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, win32 } from 'node:path'
import { PassThrough } from 'node:stream'
import { test } from 'node:test'

import {
  runSupervisedProcess,
  runWindowsJobProcess,
  sanitizedProcessEnvironment,
} from '../scripts/lib/reverse-process.mjs'

function childProcess({ stdout = '', stderr = '', delay = 0, pid = 424242 } = {}) {
  const child = new EventEmitter()
  child.pid = pid
  child.stdout = new PassThrough()
  child.stderr = new PassThrough()
  child.killSignals = []
  child.kill = (signal) => {
    child.killSignals.push(signal)
    return true
  }
  queueMicrotask(() => {
    child.stdout.end(stdout)
    child.stderr.end(stderr)
    setTimeout(() => child.emit('close', 0, null), delay)
  })
  return child
}

function absentGroupError() {
  return Object.assign(new Error('no such process group'), { code: 'ESRCH' })
}

test('POSIX supervision enforces one exact output budget and confirms the whole group is gone', async () => {
  const child = childProcess({ stdout: Buffer.alloc(80), stderr: Buffer.alloc(80), delay: 10 })
  let groupAlive = true
  let invocation
  const signals = []
  const result = await runSupervisedProcess({
    file: '/tool',
    args: [],
    cwd: '/work',
    env: {},
    timeoutMs: 1_000,
    maxOutputBytes: 100,
  }, {
    platform: 'linux',
    spawnImpl: (file, args, options) => {
      invocation = { file, args, options }
      return child
    },
    processKillImpl: (pid, signal) => {
      signals.push([pid, signal])
      if (signal === 0) {
        if (groupAlive) return true
        throw absentGroupError()
      }
      assert.equal(pid, -child.pid)
      assert.equal(signal, 'SIGKILL')
      groupAlive = false
      return true
    },
  })

  assert.equal(invocation.options.shell, false)
  assert.equal(invocation.options.detached, true)
  assert.equal(result.output_limit_exceeded, true)
  assert.equal(result.stdout.length + result.stderr.length, 100)
  assert.equal(result.supervision, 'POSIX_PROCESS_GROUP')
  assert.equal(result.termination_confirmed, true)
  assert.equal(signals.some(([pid, signal]) => pid === -child.pid && signal === 'SIGKILL'), true)
})

test('POSIX supervision kills descendants left behind after the leader closes', async () => {
  const child = childProcess()
  let groupAlive = true
  const result = await runSupervisedProcess({
    file: '/tool',
    args: [],
    cwd: '/work',
    env: {},
    timeoutMs: 1_000,
    maxOutputBytes: 100,
  }, {
    platform: 'darwin',
    spawnImpl: () => child,
    processKillImpl: (_pid, signal) => {
      if (signal === 0) {
        if (groupAlive) return true
        throw absentGroupError()
      }
      groupAlive = false
      return true
    },
  })
  assert.equal(result.termination_confirmed, true)
  assert.equal(groupAlive, false)
})

test('Windows child-only execution reports process-tree termination as unconfirmed', async () => {
  const child = childProcess()
  let invocation
  const result = await runSupervisedProcess({
    file: 'C:\\tool.exe',
    args: [],
    cwd: 'C:\\work',
    env: {},
    timeoutMs: 1_000,
    maxOutputBytes: 100,
  }, {
    platform: 'win32',
    spawnImpl: (file, args, options) => {
      invocation = { file, args, options }
      return child
    },
  })
  assert.equal(invocation.options.detached, false)
  assert.equal(result.supervision, 'WINDOWS_CHILD_ONLY')
  assert.equal(result.termination_confirmed, false)
})

test('Windows production supervision delegates the complete contract to the Job Object adapter', async () => {
  const request = {
    file: 'C:\\tool.exe',
    args: ['--fixed'],
    cwd: 'C:\\work',
    env: { SystemRoot: 'C:\\Windows' },
    timeoutMs: 1_000,
    maxOutputBytes: 100,
    logPaths: ['C:\\work\\tool.log'],
    maxLogBytes: 90,
  }
  const sentinel = Object.freeze({ supervision: 'WINDOWS_JOB_OBJECT' })
  let received
  const result = await runSupervisedProcess(request, {
    platform: 'win32',
    windowsJobRunnerImpl: async (value) => {
      received = value
      return sentinel
    },
  })

  assert.deepEqual(received, request)
  assert.equal(result, sentinel)
})

test('Windows Job Object request files never serialize the inherited target environment', {
  skip: process.platform !== 'win32',
}, async () => {
  const secret = 'job-request-must-not-persist-this-secret'
  const environment = { ...sanitizedProcessEnvironment(), JOB_REQUEST_SECRET: secret }
  let inspected = false
  const result = await runWindowsJobProcess({
    file: 'C:\\fixed-tool.exe',
    args: ['--version'],
    cwd: 'C:\\fixed-work',
    env: environment,
    timeoutMs: 1_000,
    maxOutputBytes: 4_096,
  }, {
    invokeWindowsHelperImpl: async (invocation) => {
      const requestPath = invocation.args[invocation.args.indexOf('-RequestPath') + 1]
      const resultPath = invocation.args[invocation.args.indexOf('-ResultPath') + 1]
      const requestText = await readFile(requestPath, 'utf8')
      const request = JSON.parse(requestText)
      assert.equal(Object.hasOwn(request, 'env'), false)
      assert.equal(requestText.includes(secret), false)
      assert.equal(invocation.env.JOB_REQUEST_SECRET, secret)
      await writeFile(request.stdout_path, Buffer.alloc(0))
      await writeFile(request.stderr_path, Buffer.alloc(0))
      await writeFile(resultPath, JSON.stringify({
        schema_version: '1.2.0',
        request_nonce: request.request_nonce,
        code: 0,
        timed_out: false,
        stop_requested: false,
        output_limit_exceeded: false,
        log_limit_exceeded: false,
        log_integrity_failed: false,
        log_bytes: 0,
        spawn_error: false,
        termination_confirmed: true,
        supervision: 'WINDOWS_JOB_OBJECT',
        duration_ms: 1,
      }))
      inspected = true
      return { code: 0, failed: false }
    },
  })
  assert.equal(inspected, true)
  assert.equal(result.code, 0)
  assert.equal(result.termination_confirmed, true)
})

function processExists(pid) {
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    if (error?.code === 'ESRCH') return false
    throw error
  }
}

function windowsPowerShell(environment) {
  return win32.join(
    environment.SystemRoot ?? environment.SYSTEMROOT ?? environment.WINDIR,
    'System32',
    'WindowsPowerShell',
    'v1.0',
    'powershell.exe',
  )
}

async function writeLongLivedProcessTreeFixture(root) {
  const scriptPath = join(root, 'long-lived-tree.mjs')
  await writeFile(scriptPath, [
    "import { spawn } from 'node:child_process'",
    "import { writeFileSync } from 'node:fs'",
    "process.on('SIGTERM', () => {})",
    "const childCode = \"process.on('SIGTERM', () => {}); setInterval(() => {}, 1000)\"",
    "const descendant = spawn(process.execPath, ['-e', childCode], { stdio: 'ignore' })",
    "writeFileSync(process.argv[2], JSON.stringify({ root: process.pid, descendant: descendant.pid }))",
    "process.stdout.write('tree-ready\\n')",
    'setInterval(() => {}, 1000)',
    '',
  ].join('\n'), 'utf8')
  return scriptPath
}

async function readJsonEventually(path, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      return JSON.parse(await readFile(path, 'utf8'))
    } catch (error) {
      if (error?.code !== 'ENOENT' && !(error instanceof SyntaxError)) throw error
    }
    await new Promise((resolve) => setTimeout(resolve, 25))
  }
  throw new Error(`timed out waiting for ${path}`)
}

async function processEventuallyAbsent(pid, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs
  while (processExists(pid) && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 25))
  }
  return !processExists(pid)
}

async function killFixtureProcesses(processes) {
  for (const pid of [processes?.root, processes?.descendant]) {
    if (!Number.isSafeInteger(pid) || !processExists(pid)) continue
    try { process.kill(pid, 'SIGKILL') } catch {}
  }
}

test('a pre-existing stop marker prevents the supervised process from starting', async () => {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-pre-stop-test-'))
  const stopMarkerPath = join(root, 'stop.json')
  await writeFile(stopMarkerPath, '{}\n', 'utf8')
  let spawnCalled = false
  try {
    const result = await runSupervisedProcess({
      file: process.execPath,
      args: ['--version'],
      cwd: root,
      env: sanitizedProcessEnvironment(),
      timeoutMs: 10_000,
      maxOutputBytes: 4_096,
      stopMarkerPath,
    }, {
      platform: process.platform,
      spawnImpl: () => {
        spawnCalled = true
        throw new Error('must not spawn')
      },
    })

    assert.equal(spawnCalled, false)
    assert.equal(result.stop_requested, true)
    assert.equal(result.started, false)
    assert.equal(result.termination_confirmed, true)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('a Windows helper result failure after launch remains a possibly-started outcome', async () => {
  const environment = {
    ...sanitizedProcessEnvironment(),
    SystemRoot: process.env.SystemRoot ?? 'C:\\Windows',
  }
  const result = await runWindowsJobProcess({
    file: process.execPath,
    args: ['--version'],
    cwd: tmpdir(),
    env: environment,
    timeoutMs: 10_000,
    maxOutputBytes: 4_096,
  }, {
    invokeWindowsHelperImpl: async () => ({ code: 0, failed: false, timedOut: false }),
  })

  assert.equal(result.spawn_error, true)
  assert.equal(result.started, true)
  assert.equal(result.termination_confirmed, false)
})

test('an unconfirmed Windows helper result still removes identity-bound provider-output scratch', async () => {
  const environment = {
    ...sanitizedProcessEnvironment(),
    SystemRoot: process.env.SystemRoot ?? 'C:\\Windows',
  }
  let adapterDirectory
  const secret = Buffer.from('provider-output-must-not-remain-on-disk')
  const result = await runWindowsJobProcess({
    file: process.execPath,
    args: ['--version'],
    cwd: tmpdir(),
    env: environment,
    timeoutMs: 10_000,
    maxOutputBytes: 4_096,
  }, {
    invokeWindowsHelperImpl: async (invocation) => {
      const requestPath = invocation.args[invocation.args.indexOf('-RequestPath') + 1]
      const resultPath = invocation.args[invocation.args.indexOf('-ResultPath') + 1]
      adapterDirectory = dirname(requestPath)
      const request = JSON.parse(await readFile(requestPath, 'utf8'))
      await writeFile(request.stdout_path, secret)
      await writeFile(request.stderr_path, secret)
      await writeFile(resultPath, JSON.stringify({
        schema_version: '1.2.0',
        request_nonce: request.request_nonce,
        code: null,
        timed_out: true,
        stop_requested: false,
        output_limit_exceeded: false,
        log_limit_exceeded: false,
        log_integrity_failed: false,
        log_bytes: 0,
        spawn_error: false,
        termination_confirmed: false,
        supervision: 'WINDOWS_JOB_OBJECT',
        duration_ms: 1,
      }))
      return { code: 0, failed: false }
    },
  })
  assert.equal(result.termination_confirmed, false)
  assert.equal(result.stdout.equals(secret), true)
  assert.equal(result.stderr.equals(secret), true)
  await assert.rejects(() => access(adapterDirectory))
})

test('POSIX timeout uses SIGKILL to remove a SIGTERM-resistant child and its descendant', {
  skip: process.platform === 'win32',
  timeout: 15_000,
}, async () => {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-posix-tree-timeout-'))
  const pidPath = join(root, 'tree.json')
  const scriptPath = await writeLongLivedProcessTreeFixture(root)
  let processes
  try {
    const startedAt = Date.now()
    const resultPromise = runSupervisedProcess({
      file: process.execPath,
      args: [scriptPath, pidPath],
      cwd: root,
      env: sanitizedProcessEnvironment(),
      timeoutMs: 3_000,
      maxOutputBytes: 4_096,
    })
    processes = await readJsonEventually(pidPath)
    process.kill(processes.root, 'SIGTERM')
    await new Promise((resolve) => setTimeout(resolve, 100))
    assert.equal(processExists(processes.root), true, 'fixture must ignore SIGTERM')

    const result = await resultPromise
    assert.equal(result.timed_out, true)
    assert.equal(result.stop_requested, false)
    assert.equal(result.termination_confirmed, true)
    assert.equal(await processEventuallyAbsent(processes.root), true)
    assert.equal(await processEventuallyAbsent(processes.descendant), true)
    assert.equal(Date.now() - startedAt < 10_000, true, 'termination must remain bounded')
  } finally {
    await killFixtureProcesses(processes)
    await rm(root, { recursive: true, force: true })
  }
})

test('a live stop marker terminates the supervised child and descendant tree', {
  timeout: 20_000,
}, async () => {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-tree-stop-test-'))
  const pidPath = join(root, 'tree.json')
  const stopMarkerPath = join(root, 'stop.json')
  const scriptPath = await writeLongLivedProcessTreeFixture(root)
  let processes
  try {
    const startedAt = Date.now()
    const resultPromise = runSupervisedProcess({
      file: process.execPath,
      args: [scriptPath, pidPath],
      cwd: root,
      env: sanitizedProcessEnvironment(),
      timeoutMs: 10_000,
      maxOutputBytes: 4_096,
      stopMarkerPath,
    })
    processes = await readJsonEventually(pidPath)
    await writeFile(stopMarkerPath, '{"stop":true}\n', { encoding: 'utf8', flag: 'wx' })

    const result = await resultPromise
    assert.equal(result.stop_requested, true, result.stderr.toString('utf8'))
    assert.equal(result.timed_out, false)
    assert.equal(result.started, true)
    assert.equal(result.termination_confirmed, true)
    assert.equal(await processEventuallyAbsent(processes.root), true)
    assert.equal(await processEventuallyAbsent(processes.descendant), true)
    assert.equal(Date.now() - startedAt < 10_000, true, 'stop completion must remain bounded')
  } finally {
    await killFixtureProcesses(processes)
    await rm(root, { recursive: true, force: true })
  }
})

test('Windows Job Object supervision enforces one exact stdout and stderr budget', {
  skip: process.platform !== 'win32',
}, async () => {
  const environment = sanitizedProcessEnvironment()
  const result = await runWindowsJobProcess({
    file: windowsPowerShell(environment),
    args: [
      '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
      '[Console]::Out.Write((\"o\" * 80)); [Console]::Error.Write((\"e\" * 80)); Start-Sleep -Seconds 30',
    ],
    cwd: tmpdir(),
    env: environment,
    timeoutMs: 10_000,
    maxOutputBytes: 100,
  })

  assert.equal(result.output_limit_exceeded, true)
  assert.equal(result.stdout.length + result.stderr.length, 100)
  assert.equal(result.timed_out, false)
  assert.equal(result.spawn_error, false)
  assert.equal(result.termination_confirmed, true)
  assert.equal(result.supervision, 'WINDOWS_JOB_OBJECT')
})

test('Windows Job Object supervision detects a log overrun when the target exits quickly', {
  skip: process.platform !== 'win32',
}, async () => {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-job-log-test-'))
  const logPath = join(root, 'tool.log')
  await writeFile(logPath, Buffer.alloc(200))

  try {
    const environment = sanitizedProcessEnvironment()
    const result = await runWindowsJobProcess({
      file: win32.join(
        environment.SystemRoot ?? environment.SYSTEMROOT ?? environment.WINDIR,
        'System32',
        'cmd.exe',
      ),
      args: ['/d', '/q', '/c', 'exit', '0'],
      cwd: root,
      env: environment,
      timeoutMs: 10_000,
      maxOutputBytes: 4_096,
      logPaths: [logPath],
      maxLogBytes: 100,
    })

    assert.equal(result.code === null || result.code === 0, true, result.stderr.toString('utf8'))
    assert.equal(result.log_limit_exceeded, true)
    assert.equal(result.log_integrity_failed, false)
    assert.equal(result.log_bytes, 100)
    assert.equal(result.spawn_error, false)
    assert.equal(result.termination_confirmed, true)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('Windows Job Object supervision terminates descendants after the root exits', {
  skip: process.platform !== 'win32',
}, async () => {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-job-test-'))
  const scriptPath = join(root, 'spawn-descendant.ps1')
  const pidPath = join(root, 'descendant.pid')
  let descendantPid
  await writeFile(scriptPath, [
    'param([string]$PidPath)',
    "$child = Start-Process -FilePath \"$env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30') -PassThru -WindowStyle Hidden",
    '[IO.File]::WriteAllText($PidPath, [string]$child.Id)',
    "[Console]::Out.WriteLine('root-exited')",
    'exit 0',
    '',
  ].join('\r\n'), 'utf8')

  try {
    const environment = sanitizedProcessEnvironment()
    const result = await runWindowsJobProcess({
      file: windowsPowerShell(environment),
      args: [
        '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', scriptPath, '-PidPath', pidPath,
      ],
      cwd: root,
      env: environment,
      timeoutMs: 10_000,
      maxOutputBytes: 4_096,
    })

    assert.equal(result.code, 0, result.stderr.toString('utf8'))
    assert.equal(result.spawn_error, false)
    assert.equal(result.termination_confirmed, true)
    assert.equal(result.supervision, 'WINDOWS_JOB_OBJECT')
    assert.match(result.stdout.toString('utf8'), /root-exited/)
    descendantPid = Number.parseInt(await readFile(pidPath, 'utf8'), 10)
    assert.equal(Number.isSafeInteger(descendantPid) && descendantPid > 0, true)
    assert.equal(processExists(descendantPid), false)
  } finally {
    if (descendantPid && processExists(descendantPid)) {
      try { process.kill(descendantPid, 'SIGKILL') } catch {}
    }
    await rm(root, { recursive: true, force: true })
  }
})

test('Windows Job Object timeout terminates the root and its long-lived descendant', {
  skip: process.platform !== 'win32',
}, async () => {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-job-timeout-test-'))
  const scriptPath = join(root, 'timeout-with-descendant.ps1')
  const pidPath = join(root, 'descendant.pid')
  let descendantPid
  await writeFile(scriptPath, [
    'param([string]$PidPath)',
    "$child = Start-Process -FilePath \"$env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30') -PassThru -WindowStyle Hidden",
    '[IO.File]::WriteAllText($PidPath, [string]$child.Id)',
    "[Console]::Out.WriteLine('descendant-started')",
    'Start-Sleep -Seconds 30',
    '',
  ].join('\r\n'), 'utf8')

  try {
    const environment = sanitizedProcessEnvironment()
    const result = await runWindowsJobProcess({
      file: windowsPowerShell(environment),
      args: [
        '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', scriptPath, '-PidPath', pidPath,
      ],
      cwd: root,
      env: environment,
      timeoutMs: 3_000,
      maxOutputBytes: 4_096,
    })

    assert.equal(result.code, null)
    assert.equal(result.timed_out, true, result.stderr.toString('utf8'))
    assert.equal(result.spawn_error, false)
    assert.equal(result.termination_confirmed, true)
    assert.equal(result.supervision, 'WINDOWS_JOB_OBJECT')
    assert.match(result.stdout.toString('utf8'), /descendant-started/)
    descendantPid = Number.parseInt(await readFile(pidPath, 'utf8'), 10)
    assert.equal(Number.isSafeInteger(descendantPid) && descendantPid > 0, true)
    assert.equal(processExists(descendantPid), false)
  } finally {
    if (descendantPid && processExists(descendantPid)) {
      try { process.kill(descendantPid, 'SIGKILL') } catch {}
    }
    await rm(root, { recursive: true, force: true })
  }
})

test('a child error remains unconfirmed even when the POSIX group later disappears', async () => {
  const child = new EventEmitter()
  child.pid = 424243
  child.stdout = new PassThrough()
  child.stderr = new PassThrough()
  child.kill = () => true
  queueMicrotask(() => {
    child.emit('error', new Error('child lifecycle error'))
    child.emit('close', 1, null)
  })
  const result = await runSupervisedProcess({
    file: '/tool',
    args: [],
    cwd: '/work',
    env: {},
    timeoutMs: 1_000,
    maxOutputBytes: 100,
  }, {
    platform: 'linux',
    spawnImpl: () => child,
    processKillImpl: (_pid, signal) => {
      if (signal === 0) throw absentGroupError()
      return true
    },
  })
  assert.equal(result.spawn_error, true)
  assert.equal(result.termination_confirmed, false)
})
