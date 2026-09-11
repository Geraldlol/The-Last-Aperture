import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, win32 } from 'node:path'
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
