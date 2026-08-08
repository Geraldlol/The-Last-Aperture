import { execFile } from 'node:child_process'
import { existsSync } from 'node:fs'
import { delimiter, join } from 'node:path'

// On Windows many CLIs ship only as a .cmd/.bat shim, which execFile cannot
// launch without `shell: true` — and this runner never uses a shell. Refusing
// is the safe direction, but "not found on PATH" would be a false reason for a
// tool that is plainly installed, and an operator would act on it wrongly.
const SHELL_SHIM_EXTENSIONS = ['.cmd', '.bat']

function findShellShim(name, env) {
  if (process.platform !== 'win32') return null
  const path = env?.PATH ?? env?.Path ?? ''
  for (const directory of String(path).split(delimiter)) {
    if (!directory) continue
    for (const extension of SHELL_SHIM_EXTENSIONS) {
      const candidate = join(directory, `${name}${extension}`)
      if (existsSync(candidate)) return candidate
    }
  }
  return null
}

export const DEFAULT_CLI_LIMITS = Object.freeze({
  timeoutMs: 120000,
  maxStdoutBytes: 256 * 1024 * 1024,
  maxCommands: 64,
  maxObjects: 4096,
})

export class CliUnavailableError extends Error {
  constructor(name, reason) {
    super(`${name} not found on PATH: ${reason}`)
    this.name = 'CliUnavailableError'
    this.cli = name
    this.reason = reason
  }
}

export class ImpactCapExceededError extends Error {
  constructor(dimension, value, cap) {
    super(`acquisition halted: ${dimension} reached ${value}, above its cap of ${cap}`)
    this.name = 'ImpactCapExceededError'
    this.dimension = dimension
  }
}

/**
 * Commands executed, bytes read, and distinct objects touched, each capped.
 * These exist for read-only classes too: an unbounded read against production
 * is an availability risk regardless of intent.
 */
export class ImpactCounters {
  constructor({ maxCommands, maxObjects, maxBytes }) {
    this.caps = { commands: maxCommands, objects_touched: maxObjects, bytes_read: maxBytes }
    this.counters = { commands: 0, bytes_read: 0, objects_touched: 0 }
  }

  record({ commands = 0, bytes = 0, objects = 0 } = {}) {
    this.counters.commands += commands
    this.counters.bytes_read += bytes
    this.counters.objects_touched += objects
    return this
  }

  assertWithinCaps() {
    for (const [dimension, value] of Object.entries(this.counters)) {
      const cap = this.caps[dimension]
      if (typeof cap === 'number' && value > cap) {
        throw new ImpactCapExceededError(dimension, value, cap)
      }
    }
    return this
  }

  snapshot() {
    return { ...this.counters, caps: { ...this.caps } }
  }
}

// The default resolver runs the named binary as it stands on PATH. Tests
// inject a resolver so a stub process can stand in without a shell — a .cmd
// shim would require `shell: true`, which this runner never uses.
const identityResolver = (file, args) => ({ file, args })

function execFileAsync(file, args, options) {
  return new Promise((resolve) => {
    execFile(file, args, { ...options, encoding: 'buffer' }, (error, stdout, stderr) => {
      resolve({
        error,
        stdout: stdout ?? Buffer.alloc(0),
        stderr: (stderr ?? Buffer.alloc(0)).toString('utf8'),
      })
    })
  })
}

/**
 * Probes without throwing. An absent CLI is a fact the caller records as a
 * coverage gap, not an exception it has to catch to stay honest — and
 * "the tool was missing" must never be able to read as "the target was safe".
 */
export async function probeCli(name, {
  versionArgs = ['--version'],
  env = process.env,
  resolver = identityResolver,
} = {}) {
  const resolved = resolver(name, versionArgs)
  const { error, stdout } = await execFileAsync(resolved.file, resolved.args, {
    env,
    timeout: 15000,
    shell: false,
    windowsHide: true,
  })
  if (error && (error.code === 'ENOENT' || error.code === 'EACCES')) {
    const shim = findShellShim(name, env)
    if (shim) {
      return {
        name,
        present: false,
        version: null,
        reason: `${name} is installed at ${shim} as a shell shim, which this `
          + 'controller will not execute because it never spawns a shell; supply a '
          + 'native executable on PATH',
      }
    }
    return { name, present: false, version: null, reason: `${error.code}: not found on PATH` }
  }
  if (error && error.killed) {
    return { name, present: false, version: null, reason: 'version probe timed out' }
  }
  const text = stdout.toString('utf8').trim()
  return { name, present: true, version: text === '' ? null : text.split('\n')[0], reason: null }
}

export async function runBoundedCli({
  name,
  args,
  limits = DEFAULT_CLI_LIMITS,
  env = process.env,
  cwd,
  counters,
  resolver = identityResolver,
}) {
  // A registry reference or a resource name is untrusted input. execFile with
  // an argument array has no shell to inject into; a command string would.
  if (!Array.isArray(args)) throw new TypeError('args must be an array; this runner never spawns a shell')

  const resolved = resolver(name, args)
  const { error, stdout, stderr } = await execFileAsync(resolved.file, resolved.args, {
    env,
    cwd,
    timeout: limits.timeoutMs,
    maxBuffer: limits.maxStdoutBytes,
    shell: false,
    windowsHide: true,
  })
  if (error && (error.code === 'ENOENT' || error.code === 'EACCES')) {
    throw new CliUnavailableError(name, `${error.code}: not found on PATH`)
  }

  const tracked = counters ?? new ImpactCounters({
    maxCommands: limits.maxCommands,
    maxObjects: limits.maxObjects,
    maxBytes: limits.maxStdoutBytes,
  })
  tracked.record({ commands: 1, bytes: stdout.length }).assertWithinCaps()

  return {
    stdout,
    stderr,
    code: error === null || error === undefined
      ? 0
      : Number.isInteger(error.code) ? error.code : (error.killed ? 124 : 1),
    counters: tracked.snapshot(),
  }
}
