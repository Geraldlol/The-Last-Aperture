import { execFile } from 'node:child_process'
import { existsSync, readFileSync, statSync } from 'node:fs'
import { delimiter, dirname, join } from 'node:path'

// On Windows many CLIs ship only as a .cmd/.bat shim, which execFile cannot
// launch without `shell: true` — and this runner never uses a shell, because a
// shell turns an argument vector back into an injectable string.
const SHELL_SHIM_EXTENSIONS = ['.cmd', '.bat']
const MAX_SHIM_BYTES = 64 * 1024

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

/**
 * An npm-generated `.cmd` shim is a wrapper whose last line names exactly the
 * node invocation it performs:
 *
 *   ... & "%_prog%" --no-deprecation "%dp0%\node_modules\pkg\bin\run.js" %*
 *
 * Reading that line lets the CLI be launched as `node <flags> <entry> <args>`
 * with no shell at all — strictly safer than `shell: true`, because the
 * argument vector is never re-parsed as a command string.
 *
 * Fail-closed by construction: anything that does not match this exact shape,
 * or whose entry script is not on disk, resolves to null and the caller keeps
 * refusing. It is not a general `.bat` interpreter and must not become one.
 *
 * Trust: this executes the script the shim points at. That is the same script
 * the shim itself would have run, so it introduces no boundary that invoking
 * the CLI did not already cross — an attacker who can rewrite entries on your
 * PATH already decides what `sf` means.
 */
export function resolveNodeShim(shimPath) {
  let text
  try {
    if (statSync(shimPath).size > MAX_SHIM_BYTES) return null
    text = readFileSync(shimPath, 'utf8')
  } catch {
    return null
  }

  const invocation = /"%_prog%"([^\r\n]*?)%\*/.exec(text)
  if (!invocation) return null

  const directory = dirname(shimPath)
  const tokens = [...invocation[1].matchAll(/"([^"]+)"|(\S+)/g)]
    .map((match) => (match[1] ?? match[2]).replaceAll('%dp0%', directory))
  if (tokens.length === 0) return null

  const entry = tokens.find((token) => /\.[cm]?js$/i.test(token))
  if (!entry || !existsSync(entry)) return null
  // Every token before the entry is a node flag; a stray %VAR% means the shim
  // depends on shell expansion we are deliberately not performing.
  if (tokens.some((token) => token.includes('%'))) return null

  return { file: process.execPath, prefixArgs: tokens }
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

/**
 * Resolves a CLI that exists only as an npm shim into a direct node
 * invocation. Returns null when there is no shim, or when the shim is not one
 * this resolver understands — in which case the caller keeps refusing, and
 * `shimPath` still lets it say why.
 */
function resolveShimInvocation(name, args, env) {
  const shimPath = findShellShim(name, env)
  if (!shimPath) return { shimPath: null, resolved: null }
  const shim = resolveNodeShim(shimPath)
  if (!shim) return { shimPath, resolved: null }
  return { shimPath, resolved: { file: shim.file, args: [...shim.prefixArgs, ...args] } }
}

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
    const { shimPath, resolved: viaShim } = resolveShimInvocation(name, versionArgs, env)
    if (viaShim) {
      const retry = await execFileAsync(viaShim.file, viaShim.args, {
        env,
        timeout: 15000,
        shell: false,
        windowsHide: true,
      })
      if (!retry.error) {
        const retried = retry.stdout.toString('utf8').trim()
        return {
          name,
          present: true,
          version: retried === '' ? null : retried.split('\n')[0],
          reason: null,
          via_node_shim: shimPath,
        }
      }
      // Resolved, then failed. That is a different fault from an unparseable
      // shim and sends an operator somewhere else entirely, so say which.
      return {
        name,
        present: false,
        version: null,
        reason: `${name} resolved through its npm shim at ${shimPath}, but the version `
          + `probe ${retry.error.killed ? 'timed out' : `exited ${retry.error.code}`}`,
      }
    }
    if (shimPath) {
      return {
        name,
        present: false,
        version: null,
        reason: `${name} is installed at ${shimPath} as a shell shim this controller `
          + 'cannot resolve to a direct node invocation, and it never spawns a shell; '
          + 'supply a native executable on PATH',
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

  const spawnOptions = {
    env,
    cwd,
    timeout: limits.timeoutMs,
    maxBuffer: limits.maxStdoutBytes,
    shell: false,
    windowsHide: true,
  }
  const resolved = resolver(name, args)
  let { error, stdout, stderr } = await execFileAsync(resolved.file, resolved.args, spawnOptions)

  // A CLI installed only as an npm shim is launched as the node invocation the
  // shim declares. Still no shell: the argument vector is passed through, never
  // re-parsed as a command string.
  if (error && (error.code === 'ENOENT' || error.code === 'EACCES')) {
    const { shimPath, resolved: viaShim } = resolveShimInvocation(name, args, env)
    if (viaShim) {
      ({ error, stdout, stderr } = await execFileAsync(viaShim.file, viaShim.args, spawnOptions))
    } else if (shimPath) {
      throw new CliUnavailableError(
        name,
        `installed at ${shimPath} as a shell shim this controller cannot resolve to a `
        + 'direct node invocation, and it never spawns a shell',
      )
    }
  }
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
