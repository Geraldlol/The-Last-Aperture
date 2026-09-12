import { createHash } from 'node:crypto'
import { constants } from 'node:fs'
import { posix, win32 } from 'node:path'
import { lstat, mkdir, open, readFile, realpath, writeFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'

import {
  isWindowsBatchLauncher,
  runSupervisedProcess,
  sanitizedProcessEnvironment,
} from './reverse-process.mjs'
import { windowsJavaDevelopmentToolCandidates } from './windows-java-tool-candidates.mjs'

export { windowsJavaDevelopmentToolCandidates } from './windows-java-tool-candidates.mjs'

export const GHIDRA_PROFILE_ID = 'ghidra-headless-fixed-export-v1'

const EXPORTER_NAME = 'LastApertureExport.java'
export const GHIDRA_WINDOWS_AGENT_SOURCE_PATH = fileURLToPath(
  new URL('../ghidra/GhidraBundleLocationAgent.java.source', import.meta.url),
)
export const GHIDRA_WINDOWS_AGENT_MANIFEST_PATH = fileURLToPath(
  new URL('../ghidra/GhidraBundleLocationAgent.mf', import.meta.url),
)
const AGENT_BUILD_DIRECTORY = '.ghidra-agent'
const AGENT_SOURCE_NAME = 'GhidraBundleLocationAgent.java'
const AGENT_JAR_NAME = 'last-aperture-ghidra-agent.jar'
const MAX_AGENT_SOURCE_BYTES = 256 * 1024
const MAX_JAVA_TOOL_BYTES = 64 * 1024 * 1024
const MAX_AGENT_JAR_BYTES = 4 * 1024 * 1024
const MAX_TIMEOUT_SECONDS = 3_600
const MAX_TIMEOUT_MS = 30 * 60 * 1_000
const MAX_CPU = 64
const MAX_OUTPUT_BYTES = 64 * 1024 * 1024
const PROJECT_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/
const CONTROL_PATTERN = /[\u0000-\u001f\u007f-\u009f]/u
const WINDOWS_INVALID_PATH_PATTERN = /["<>|?*]/u
const ARGUMENT_OPTION_KEYS = Object.freeze([
  'projectDirectory',
  'projectName',
  'stagedBinary',
  'scriptDirectory',
  'exportPath',
  'logPath',
  'scriptLogPath',
  'timeoutSeconds',
  'maxCpu',
])
const RUN_OPTION_KEYS = Object.freeze([
  'launcherPath',
  'args',
  'cwd',
  'timeoutMs',
  'maxOutputBytes',
  'spawnImpl',
  'windowsCompatibilityAgent',
])
const OPEN_READ_FLAGS = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)
const preparedWindowsAgents = new WeakSet()

function processSucceeded(result) {
  return result?.code === 0
    && result.spawn_error !== true
    && result.timed_out !== true
    && result.output_limit_exceeded !== true
    && result.log_limit_exceeded !== true
    && result.log_integrity_failed !== true
    && result.termination_confirmed === true
}

function sameFile(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs
    && left.nlink === right.nlink
}

async function hashRegularFile(path, maximumBytes, label) {
  let metadata
  try {
    metadata = await lstat(path, { bigint: true })
  } catch (error) {
    fail('GHIDRA_JAVA_TOOL_UNAVAILABLE', `${label} is unavailable`, { cause: error })
  }
  if (
    !metadata.isFile()
    || metadata.isSymbolicLink()
    || (metadata.nlink !== 1n && metadata.nlink !== 1)
    || metadata.size < 1n
    || metadata.size > BigInt(maximumBytes)
  ) fail('GHIDRA_JAVA_TOOL_INVALID', `${label} must be one bounded regular file`)

  const canonical = await realpath(path)
  assertAbsoluteLocalPath(canonical, label)
  let handle
  try {
    handle = await open(canonical, OPEN_READ_FLAGS)
    const heldBefore = await handle.stat({ bigint: true })
    if (!sameFile(metadata, heldBefore)) fail('GHIDRA_JAVA_TOOL_CHANGED', `${label} changed before hashing`)
    const digest = createHash('sha256')
    const buffer = Buffer.allocUnsafe(64 * 1024)
    let position = 0
    while (position < Number(heldBefore.size)) {
      const wanted = Math.min(buffer.length, Number(heldBefore.size) - position)
      const { bytesRead } = await handle.read(buffer, 0, wanted, position)
      if (bytesRead < 1) break
      digest.update(buffer.subarray(0, bytesRead))
      position += bytesRead
    }
    const heldAfter = await handle.stat({ bigint: true })
    if (position !== Number(heldBefore.size) || !sameFile(heldBefore, heldAfter)) {
      fail('GHIDRA_JAVA_TOOL_CHANGED', `${label} changed while hashing`)
    }
    return Object.freeze({
      path: canonical,
      expected: Object.freeze({ sha256: digest.digest('hex'), size: Number(heldBefore.size) }),
    })
  } finally {
    await handle?.close()
  }
}

async function resolveJavaDevelopmentTool(environment, executable) {
  const candidates = windowsJavaDevelopmentToolCandidates(environment, executable)
  for (const candidate of candidates) {
    try {
      return await hashRegularFile(candidate, MAX_JAVA_TOOL_BYTES, executable)
    } catch (error) {
      if (error?.cause?.code === 'ENOENT' || error?.code === 'ENOENT') continue
      if (error?.code === 'GHIDRA_JAVA_TOOL_UNAVAILABLE' && error?.cause?.code === 'ENOENT') continue
      throw error
    }
  }
  fail('GHIDRA_JAVA_TOOL_UNAVAILABLE', `${executable} could not be resolved from JAVA_HOME, JDK_HOME, or PATH`)
}

function component(role, name, file) {
  return Object.freeze({
    role,
    name,
    sha256: file.expected.sha256,
    size_bytes: file.expected.size,
  })
}

function sameHash(left, right) {
  return left.expected.sha256 === right.expected.sha256
    && left.expected.size === right.expected.size
}

export async function prepareWindowsGhidraCompatibilityAgent({
  cwd,
  environment = sanitizedProcessEnvironment(),
  deadline,
  outputBudget,
}) {
  assertAbsoluteLocalPath(cwd, 'cwd')
  assertBoundedInteger(deadline, 'deadline', 1, Number.MAX_SAFE_INTEGER)
  assertBoundedInteger(outputBudget, 'outputBudget', 1, MAX_OUTPUT_BYTES)
  const [javac, jar] = await Promise.all([
    resolveJavaDevelopmentTool(environment, 'javac.exe'),
    resolveJavaDevelopmentTool(environment, 'jar.exe'),
  ])
  const buildDirectory = win32.join(cwd, AGENT_BUILD_DIRECTORY)
  const classesDirectory = win32.join(buildDirectory, 'classes')
  const sourcePath = win32.join(buildDirectory, AGENT_SOURCE_NAME)
  const jarPath = win32.join(buildDirectory, AGENT_JAR_NAME)
  const source = await readFile(GHIDRA_WINDOWS_AGENT_SOURCE_PATH)
  if (source.length < 1 || source.length > MAX_AGENT_SOURCE_BYTES) {
    fail('GHIDRA_AGENT_SOURCE_INVALID', 'the fixed Ghidra compatibility agent source is invalid')
  }
  await mkdir(buildDirectory, { recursive: false, mode: 0o700 })
  await mkdir(classesDirectory, { recursive: false, mode: 0o700 })
  await writeFile(sourcePath, source, { flag: 'wx', mode: 0o600 })

  let remainingOutput = outputBudget
  const runBuildStep = async (file, args) => {
    const remainingTime = deadline - Date.now()
    if (remainingTime < 1 || remainingOutput < 1) {
      fail('GHIDRA_AGENT_BUILD_FAILED', 'the Ghidra compatibility agent build exhausted its limits')
    }
    const result = await runSupervisedProcess({
      file,
      args,
      cwd: buildDirectory,
      env: environment,
      timeoutMs: remainingTime,
      maxOutputBytes: remainingOutput,
    })
    remainingOutput -= result.stdout.length + result.stderr.length
    if (!processSucceeded(result)) {
      fail('GHIDRA_AGENT_BUILD_FAILED', 'the fixed Ghidra compatibility agent could not be built')
    }
  }

  await runBuildStep(
    javac.path,
    ['-proc:none', '-d', classesDirectory, sourcePath],
  )
  await runBuildStep(
    jar.path,
    ['cfm', jarPath, GHIDRA_WINDOWS_AGENT_MANIFEST_PATH, '-C', classesDirectory, '.'],
  )
  const [javacAfter, jarAfter, agentJar] = await Promise.all([
    hashRegularFile(javac.path, MAX_JAVA_TOOL_BYTES, 'javac.exe'),
    hashRegularFile(jar.path, MAX_JAVA_TOOL_BYTES, 'jar.exe'),
    hashRegularFile(jarPath, MAX_AGENT_JAR_BYTES, 'generated Ghidra compatibility agent JAR'),
  ])
  if (!sameHash(javac, javacAfter) || !sameHash(jar, jarAfter)) {
    fail('GHIDRA_JAVA_TOOL_CHANGED', 'the Java build toolchain changed while the compatibility agent was built')
  }
  const prepared = Object.freeze({
    jarPath: agentJar.path,
    remainingOutput,
    provenance: Object.freeze([
      component('java-compiler', 'javac.exe', javac),
      component('java-archive-builder', 'jar.exe', jar),
      component('windows-compatibility-agent', AGENT_JAR_NAME, agentJar),
    ]),
    files: Object.freeze([javac, jar, agentJar]),
  })
  preparedWindowsAgents.add(prepared)
  return prepared
}

function fail(code, message, options = {}) {
  const error = new Error(message, options.cause ? { cause: options.cause } : undefined)
  error.name = 'GhidraHeadlessError'
  error.code = code
  throw error
}

function assertExactOptions(value, allowedKeys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('GHIDRA_OPTIONS_INVALID', `${label} must be an object`)
  }
  const allowed = new Set(allowedKeys)
  const unknown = Object.keys(value).filter((key) => !allowed.has(key))
  if (unknown.length > 0) {
    fail(
      'GHIDRA_PROFILE_OPTION_UNKNOWN',
      `unknown Ghidra profile option: ${unknown.sort().join(', ')}`,
    )
  }
}

function pathApi(platform) {
  return platform === 'win32' ? win32 : posix
}

function assertAbsoluteLocalPath(value, label, platform = process.platform) {
  if (
    typeof value !== 'string'
    || value.length < 1
    || value.length > 4_096
    || value.trim() !== value
    || CONTROL_PATTERN.test(value)
    || !pathApi(platform).isAbsolute(value)
  ) {
    fail('GHIDRA_PATH_INVALID', `${label} must be an absolute local path`)
  }

  if (platform === 'win32') {
    const normalized = value.replaceAll('/', '\\')
    if (
      normalized.startsWith('\\\\')
      || normalized.startsWith('\\\\?\\')
      || normalized.startsWith('\\\\.\\')
      || WINDOWS_INVALID_PATH_PATTERN.test(normalized)
    ) {
      fail('GHIDRA_PATH_INVALID', `${label} must be an absolute local path`)
    }
  } else if (value.startsWith('//')) {
    fail('GHIDRA_PATH_INVALID', `${label} must be an absolute local path`)
  }

  return value
}

function assertBoundedInteger(value, label, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(
      'GHIDRA_LIMIT_INVALID',
      `${label} must be an integer between ${minimum} and ${maximum}`,
    )
  }
  return value
}

function assertProjectName(value) {
  if (
    typeof value !== 'string'
    || !PROJECT_NAME_PATTERN.test(value)
    || value === '.'
    || value === '..'
  ) {
    fail(
      'GHIDRA_PROJECT_NAME_INVALID',
      'project name must be a bounded filename-safe identifier',
    )
  }
  return value
}

export function assertSupportedGhidraLauncher(
  launcherPath,
  { platform = process.platform } = {},
) {
  assertAbsoluteLocalPath(launcherPath, 'Ghidra launcher path', platform)
  if (platform === 'win32' && win32.extname(launcherPath).toLowerCase() === '.ps1') {
    fail(
      'GHIDRA_WINDOWS_LAUNCHER_UNSUPPORTED',
      'Windows PowerShell launchers are not supported as Ghidra entry points',
    )
  }
  return launcherPath
}

export function buildGhidraArguments(options) {
  assertExactOptions(options, ARGUMENT_OPTION_KEYS, 'Ghidra argument options')
  const {
    projectDirectory,
    projectName,
    stagedBinary,
    scriptDirectory,
    exportPath,
    logPath,
    scriptLogPath,
    timeoutSeconds,
    maxCpu,
  } = options

  assertAbsoluteLocalPath(projectDirectory, 'projectDirectory')
  assertProjectName(projectName)
  assertAbsoluteLocalPath(stagedBinary, 'stagedBinary')
  assertAbsoluteLocalPath(scriptDirectory, 'scriptDirectory')
  assertAbsoluteLocalPath(exportPath, 'exportPath')
  assertAbsoluteLocalPath(logPath, 'logPath')
  assertAbsoluteLocalPath(scriptLogPath, 'scriptLogPath')
  assertBoundedInteger(timeoutSeconds, 'timeoutSeconds', 1, MAX_TIMEOUT_SECONDS)
  assertBoundedInteger(maxCpu, 'maxCpu', 1, MAX_CPU)

  return Object.freeze([
    projectDirectory,
    projectName,
    '-import',
    stagedBinary,
    '-readOnly',
    '-deleteProject',
    '-analysisTimeoutPerFile',
    String(timeoutSeconds),
    '-max-cpu',
    String(maxCpu),
    '-scriptPath',
    scriptDirectory,
    '-postScript',
    EXPORTER_NAME,
    exportPath,
    '-log',
    logPath,
    '-scriptlog',
    scriptLogPath,
  ])
}

function canonicalIntegerArgument(value, label, minimum, maximum) {
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/.test(value)) {
    fail('GHIDRA_ARGUMENT_PROFILE_INVALID', `fixed Ghidra argument profile has invalid ${label}`)
  }
  const parsed = Number(value)
  assertBoundedInteger(parsed, label, minimum, maximum)
  return parsed
}

function assertFixedArguments(args) {
  if (!Array.isArray(args) || args.length !== 19 || args.some((value) => typeof value !== 'string')) {
    fail('GHIDRA_ARGUMENT_PROFILE_INVALID', 'args must match the fixed Ghidra argument profile')
  }

  let expected
  try {
    expected = buildGhidraArguments({
      projectDirectory: args[0],
      projectName: args[1],
      stagedBinary: args[3],
      scriptDirectory: args[11],
      exportPath: args[14],
      logPath: args[16],
      scriptLogPath: args[18],
      timeoutSeconds: canonicalIntegerArgument(
        args[7],
        'timeoutSeconds',
        1,
        MAX_TIMEOUT_SECONDS,
      ),
      maxCpu: canonicalIntegerArgument(args[9], 'maxCpu', 1, MAX_CPU),
    })
  } catch (error) {
    if (error?.code === 'GHIDRA_ARGUMENT_PROFILE_INVALID') throw error
    fail(
      'GHIDRA_ARGUMENT_PROFILE_INVALID',
      'args must match the fixed Ghidra argument profile',
      { cause: error },
    )
  }

  if (expected.some((value, index) => value !== args[index])) {
    fail('GHIDRA_ARGUMENT_PROFILE_INVALID', 'args must match the fixed Ghidra argument profile')
  }
  return args
}

export async function runGhidraHeadless(options) {
  assertExactOptions(options, RUN_OPTION_KEYS, 'Ghidra runner options')
  const {
    launcherPath,
    args,
    cwd,
    timeoutMs,
    maxOutputBytes,
    spawnImpl,
    windowsCompatibilityAgent,
  } = options

  assertSupportedGhidraLauncher(launcherPath)
  assertFixedArguments(args)
  assertAbsoluteLocalPath(cwd, 'cwd')
  assertBoundedInteger(timeoutMs, 'timeoutMs', 1, MAX_TIMEOUT_MS)
  assertBoundedInteger(maxOutputBytes, 'maxOutputBytes', 1, MAX_OUTPUT_BYTES)
  if (spawnImpl !== undefined && typeof spawnImpl !== 'function') {
    fail('GHIDRA_SPAWN_INVALID', 'spawnImpl must be a function')
  }
  const windowsBatchLauncher = process.platform === 'win32'
    && isWindowsBatchLauncher(launcherPath)
  if (windowsBatchLauncher && spawnImpl !== undefined) {
    fail(
      'GHIDRA_WINDOWS_JOB_ADAPTER_REQUIRED',
      'Windows batch Ghidra launchers must use the built-in Job Object adapter',
    )
  }
  if (windowsCompatibilityAgent !== undefined && (
    !windowsBatchLauncher
    || spawnImpl !== undefined
    || !preparedWindowsAgents.has(windowsCompatibilityAgent)
  )) {
    fail(
      'GHIDRA_WINDOWS_AGENT_INVALID',
      'windowsCompatibilityAgent must be an unmodified preparation returned by this module',
    )
  }

  try {
    const deadline = Date.now() + timeoutMs
    let remainingOutput = maxOutputBytes
    const environment = sanitizedProcessEnvironment()
    const paths = pathApi(process.platform)
    // Keep Ghidra's JDK selection, settings, and caches inside the controller-owned
    // working tree. This avoids an interactive JDK prompt and prevents headless
    // analysis from writing to the operator's profile.
    environment.XDG_CONFIG_HOME = paths.join(cwd, '.ghidra-config')
    environment.XDG_CACHE_HOME = paths.join(cwd, '.ghidra-cache')
    let agent = windowsCompatibilityAgent
    if (windowsBatchLauncher && spawnImpl === undefined) {
      if (agent === undefined) {
        agent = await prepareWindowsGhidraCompatibilityAgent({
          cwd,
          environment,
          deadline,
          outputBudget: remainingOutput,
        })
        remainingOutput = agent.remainingOutput
      }
      const jarBefore = await hashRegularFile(
        agent.jarPath,
        MAX_AGENT_JAR_BYTES,
        'generated Ghidra compatibility agent JAR',
      )
      if (!sameHash(jarBefore, agent.files[2])) {
        fail('GHIDRA_WINDOWS_AGENT_CHANGED', 'the generated compatibility agent changed before Ghidra launch')
      }
      environment.GHIDRA_HEADLESS_JAVA_OPTIONS = `"-javaagent:${agent.jarPath}"`
    }
    const remainingTime = deadline - Date.now()
    if (remainingTime < 1 || remainingOutput < 1) {
      fail('GHIDRA_LIMIT_EXHAUSTED', 'the fixed Ghidra run exhausted its limits before launch')
    }
    const result = await runSupervisedProcess({
      file: launcherPath,
      args,
      cwd,
      env: environment,
      timeoutMs: remainingTime,
      maxOutputBytes: remainingOutput,
      logPaths: [args[16], args[18]],
      maxLogBytes: maxOutputBytes,
    }, spawnImpl === undefined ? undefined : { spawnImpl })
    if (agent !== undefined) {
      const jarAfter = await hashRegularFile(
        agent.jarPath,
        MAX_AGENT_JAR_BYTES,
        'generated Ghidra compatibility agent JAR',
      )
      if (!sameHash(jarAfter, agent.files[2])) {
        fail('GHIDRA_WINDOWS_AGENT_CHANGED', 'the generated compatibility agent changed during Ghidra execution')
      }
    }
    return Object.freeze({
      profile_id: GHIDRA_PROFILE_ID,
      tool_components: agent?.provenance ?? Object.freeze([]),
      ...result,
    })
  } catch (error) {
    fail('GHIDRA_SPAWN_FAILED', 'could not start the configured Ghidra launcher', { cause: error })
  }
}
