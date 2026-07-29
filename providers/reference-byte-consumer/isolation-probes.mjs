import { spawn } from 'node:child_process'
import {
  closeSync,
  openSync,
  readFileSync,
} from 'node:fs'
import {
  chmod,
  readFile,
  readdir,
  rm,
  writeFile,
} from 'node:fs/promises'
import { createConnection } from 'node:net'
import { networkInterfaces } from 'node:os'

const HOST_SECRET_CANARY = 'RTA_DOCKER_CONFORMANCE_HOST_SECRET'
const ROOT_WRITE_PROBE = '/opt/red-team-audit/.rta-root-write-probe'
const NOEXEC_PROBE = '/work/.rta-noexec-probe'

function probeError(code) {
  const error = new Error(code)
  error.code = code
  return error
}

function assertProbe(condition, code) {
  if (!condition) throw probeError(code)
}

function requiredPositiveInteger(name) {
  const value = process.env[name]
  assertProbe(/^[1-9][0-9]*$/.test(value ?? ''), `INVALID_${name}`)
  return Number(value)
}

function requiredPositiveNumber(name) {
  const value = Number(process.env[name])
  assertProbe(Number.isFinite(value) && value > 0, `INVALID_${name}`)
  return value
}

async function readFirst(paths, code) {
  for (const path of paths) {
    try {
      return (await readFile(path, 'utf8')).trim()
    } catch (error) {
      if (error?.code !== 'ENOENT') throw probeError(code)
    }
  }
  throw probeError(code)
}

async function assertRootFilesystemReadOnly() {
  let wrote = false
  try {
    await writeFile(ROOT_WRITE_PROBE, 'must-not-persist\n', {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    })
    wrote = true
  } catch (error) {
    assertProbe(
      ['EACCES', 'EPERM', 'EROFS'].includes(error?.code),
      'ROOT_WRITE_PROBE_UNEXPECTED_ERROR',
    )
  }
  if (wrote) {
    await rm(ROOT_WRITE_PROBE, { force: true })
    throw probeError('ROOT_FILESYSTEM_WRITABLE')
  }
}

function childOutcome(command, args) {
  return new Promise((resolve) => {
    let settled = false
    let timer
    const finish = (value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve(value)
    }
    let child
    try {
      child = spawn(command, args, {
        shell: false,
        stdio: 'ignore',
      })
    } catch (error) {
      finish({ error })
      return
    }
    child.once('error', (error) => finish({ error }))
    child.once('exit', (code, signal) => finish({ code, signal }))
    timer = setTimeout(() => {
      child.kill('SIGKILL')
      finish({ error: probeError('CHILD_PROBE_TIMEOUT') })
    }, 2000)
  })
}

async function assertWorkTmpfsNoexec() {
  await writeFile(NOEXEC_PROBE, '#!/bin/sh\nexit 91\n', {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o700,
  })
  try {
    await chmod(NOEXEC_PROBE, 0o700)
    const outcome = await childOutcome(NOEXEC_PROBE, [])
    assertProbe(
      ['EACCES', 'EPERM'].includes(outcome.error?.code),
      'WORK_TMPFS_EXECUTABLE',
    )
  } finally {
    await rm(NOEXEC_PROBE, { force: true })
  }

  const mountInfo = await readFile('/proc/self/mountinfo', 'utf8')
  const workMount = mountInfo
    .split('\n')
    .find((line) => line.split(' ')[4] === '/work')
  assertProbe(workMount !== undefined, 'WORK_TMPFS_NOT_MOUNTED')
  const mountOptions = new Set(
    workMount
      .split(/\s+-\s+/, 2)
      .flatMap((part) => part.split(' '))
      .flatMap((part) => part.split(',')),
  )
  for (const option of ['noexec', 'nosuid', 'nodev']) {
    assertProbe(mountOptions.has(option), `WORK_TMPFS_MISSING_${option.toUpperCase()}`)
  }
}

function outboundConnectionOutcome() {
  return new Promise((resolve) => {
    let settled = false
    const socket = createConnection({
      host: '192.0.2.1',
      port: 9,
    })
    const finish = (value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.destroy()
      resolve(value)
    }
    const timer = setTimeout(() => finish({ timeout: true }), 1000)
    socket.once('connect', () => finish({ connected: true }))
    socket.once('error', (error) => finish({ error }))
  })
}

async function assertNetworkAbsent() {
  const interfaces = Object.values(networkInterfaces()).flat()
  assertProbe(
    interfaces.length > 0 && interfaces.every((entry) => entry?.internal === true),
    'NON_LOOPBACK_NETWORK_INTERFACE_PRESENT',
  )
  const outcome = await outboundConnectionOutcome()
  assertProbe(
    ['EACCES', 'ENETDOWN', 'ENETUNREACH', 'EHOSTUNREACH', 'EPERM']
      .includes(outcome.error?.code),
    outcome.connected
      ? 'OUTBOUND_NETWORK_CONNECTED'
      : 'OUTBOUND_NETWORK_NOT_FAIL_CLOSED',
  )
}

async function assertHostIsolation() {
  assertProbe(process.getuid?.() === 65532, 'PROVIDER_UID_DRIFT')
  assertProbe(process.getgid?.() === 65532, 'PROVIDER_GID_DRIFT')
  assertProbe(process.cwd() === '/work', 'PROVIDER_WORKDIR_DRIFT')
  assertProbe(process.pid === 1, 'HOST_PID_NAMESPACE_VISIBLE')
  assertProbe(
    !Object.hasOwn(process.env, HOST_SECRET_CANARY),
    'HOST_ENV_CANARY_VISIBLE',
  )

  const numericPids = (await readdir('/proc'))
    .filter((entry) => /^[1-9][0-9]*$/.test(entry))
  assertProbe(
    numericPids.length === 1 && numericPids[0] === '1',
    'HOST_PROCESS_NAMESPACE_VISIBLE',
  )
  const initCommand = await readFile('/proc/1/cmdline', 'utf8')
  assertProbe(
    initCommand.includes('/opt/red-team-audit/adapter.mjs'),
    'CONTAINER_INIT_IDENTITY_DRIFT',
  )
  const initEnvironment = await readFile('/proc/1/environ')
  assertProbe(
    !initEnvironment.includes(Buffer.from(`${HOST_SECRET_CANARY}=`)),
    'HOST_ENV_CANARY_VISIBLE_IN_PROC',
  )

  const status = await readFile('/proc/self/status', 'utf8')
  assertProbe(/^CapEff:\s+0+$/m.test(status), 'EFFECTIVE_CAPABILITIES_PRESENT')
  assertProbe(/^NoNewPrivs:\s+1$/m.test(status), 'NO_NEW_PRIVILEGES_DISABLED')
  assertProbe(/^Seccomp:\s+2$/m.test(status), 'SECCOMP_FILTER_DISABLED')
}

async function assertCgroupLimits(expected) {
  const pids = await readFirst(
    ['/sys/fs/cgroup/pids.max', '/sys/fs/cgroup/pids/pids.max'],
    'PIDS_CGROUP_UNREADABLE',
  )
  assertProbe(pids === String(expected.pids), 'PIDS_LIMIT_DRIFT')

  const memory = await readFirst(
    [
      '/sys/fs/cgroup/memory.max',
      '/sys/fs/cgroup/memory/memory.limit_in_bytes',
    ],
    'MEMORY_CGROUP_UNREADABLE',
  )
  assertProbe(memory === String(expected.memoryBytes), 'MEMORY_LIMIT_DRIFT')

  let quota
  let period
  try {
    const cpu = (await readFile('/sys/fs/cgroup/cpu.max', 'utf8'))
      .trim()
      .split(/\s+/)
    quota = Number(cpu[0])
    period = Number(cpu[1])
  } catch (error) {
    if (error?.code !== 'ENOENT') throw probeError('CPU_CGROUP_UNREADABLE')
    quota = Number(await readFirst(
      ['/sys/fs/cgroup/cpu/cpu.cfs_quota_us'],
      'CPU_CGROUP_UNREADABLE',
    ))
    period = Number(await readFirst(
      ['/sys/fs/cgroup/cpu/cpu.cfs_period_us'],
      'CPU_CGROUP_UNREADABLE',
    ))
  }
  assertProbe(
    Number.isFinite(quota)
      && Number.isFinite(period)
      && period > 0
      && Math.abs((quota / period) - expected.cpus) < 0.000001,
    'CPU_LIMIT_DRIFT',
  )
}

function assertOpenFileLimit(expectedNofile) {
  const limits = readFileSync('/proc/self/limits', 'utf8')
  const nofile = limits.match(/^Max open files\s+(\d+)\s+(\d+)/m)
  assertProbe(
    Number(nofile?.[1]) === expectedNofile
      && Number(nofile?.[2]) === expectedNofile,
    'NOFILE_LIMIT_DRIFT',
  )

  const descriptors = []
  let constrained = false
  try {
    for (let index = 0; index < expectedNofile + 32; index += 1) {
      try {
        descriptors.push(openSync('/dev/null', 'r'))
      } catch (error) {
        assertProbe(error?.code === 'EMFILE', 'NOFILE_PROBE_UNEXPECTED_ERROR')
        constrained = true
        break
      }
    }
  } finally {
    for (const descriptor of descriptors.reverse()) closeSync(descriptor)
  }
  assertProbe(constrained, 'NOFILE_LIMIT_NOT_ENFORCED')
}

function waitForSpawn(command, args) {
  return new Promise((resolve) => {
    let child
    let timer
    try {
      child = spawn(command, args, {
        shell: false,
        stdio: 'ignore',
      })
    } catch (error) {
      resolve({ error })
      return
    }
    let settled = false
    const finish = (value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve(value)
    }
    child.once('spawn', () => finish({ child }))
    child.once('error', (error) => finish({ error }))
    timer = setTimeout(() => {
      child.kill('SIGKILL')
      finish({ error: probeError('CHILD_SPAWN_TIMEOUT') })
    }, 2000)
  })
}

function waitForExit(child) {
  if (child.exitCode !== null || child.signalCode !== null) {
    return Promise.resolve(true)
  }
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), 2000)
    child.once('close', () => {
      clearTimeout(timer)
      resolve(true)
    })
  })
}

async function assertPidLimit(expectedPids) {
  const children = []
  let constrained = false
  try {
    for (let index = 0; index < expectedPids + 16; index += 1) {
      const outcome = await waitForSpawn('/bin/sleep', ['60'])
      if (outcome.error) {
        assertProbe(
          ['EAGAIN', 'ENOMEM'].includes(outcome.error.code),
          'PIDS_PROBE_UNEXPECTED_ERROR',
        )
        constrained = true
        break
      }
      children.push(outcome.child)
    }
  } finally {
    for (const child of children) child.kill('SIGKILL')
    const exited = await Promise.all(children.map(waitForExit))
    assertProbe(exited.every(Boolean), 'PIDS_PROBE_CHILD_CLEANUP_FAILED')
  }
  assertProbe(constrained, 'PIDS_LIMIT_NOT_ENFORCED')
}

export async function runReferenceIsolationProbes() {
  const expected = {
    memoryBytes: requiredPositiveInteger('RTA_CONFORMANCE_MEMORY_BYTES'),
    cpus: requiredPositiveNumber('RTA_CONFORMANCE_CPUS'),
    pids: requiredPositiveInteger('RTA_CONFORMANCE_PIDS'),
    nofile: requiredPositiveInteger('RTA_CONFORMANCE_NOFILE'),
  }
  await assertHostIsolation()
  await assertRootFilesystemReadOnly()
  await assertWorkTmpfsNoexec()
  await assertNetworkAbsent()
  await assertCgroupLimits(expected)
  assertOpenFileLimit(expected.nofile)
  await assertPidLimit(expected.pids)
}
