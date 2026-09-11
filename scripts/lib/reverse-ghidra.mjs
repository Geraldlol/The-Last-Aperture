import { posix, win32 } from 'node:path'

import {
  isWindowsBatchLauncher,
  runSupervisedProcess,
  sanitizedProcessEnvironment,
} from './reverse-process.mjs'

export const GHIDRA_PROFILE_ID = 'ghidra-headless-fixed-export-v1'

const EXPORTER_NAME = 'LastApertureExport.java'
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
])

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
  } = options

  assertSupportedGhidraLauncher(launcherPath)
  assertFixedArguments(args)
  assertAbsoluteLocalPath(cwd, 'cwd')
  assertBoundedInteger(timeoutMs, 'timeoutMs', 1, MAX_TIMEOUT_MS)
  assertBoundedInteger(maxOutputBytes, 'maxOutputBytes', 1, MAX_OUTPUT_BYTES)
  if (spawnImpl !== undefined && typeof spawnImpl !== 'function') {
    fail('GHIDRA_SPAWN_INVALID', 'spawnImpl must be a function')
  }
  if (process.platform === 'win32' && isWindowsBatchLauncher(launcherPath) && spawnImpl !== undefined) {
    fail(
      'GHIDRA_WINDOWS_JOB_ADAPTER_REQUIRED',
      'Windows batch Ghidra launchers must use the built-in Job Object adapter',
    )
  }

  try {
    const result = await runSupervisedProcess({
      file: launcherPath,
      args,
      cwd,
      env: sanitizedProcessEnvironment(),
      timeoutMs,
      maxOutputBytes,
      logPaths: [args[16], args[18]],
      maxLogBytes: maxOutputBytes,
    }, spawnImpl === undefined ? undefined : { spawnImpl })
    return Object.freeze({
      profile_id: GHIDRA_PROFILE_ID,
      ...result,
    })
  } catch (error) {
    fail('GHIDRA_SPAWN_FAILED', 'could not start the configured Ghidra launcher', { cause: error })
  }
}
