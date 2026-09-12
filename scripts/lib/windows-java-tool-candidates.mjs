import { win32 } from 'node:path'

const CONTROL_PATTERN = /[\u0000-\u001f\u007f-\u009f]/u
const WINDOWS_INVALID_PATH_PATTERN = /["<>|?*]/u
const JAVA_TOOL_NAMES = new Set(['javac.exe', 'jar.exe'])

function pathError(label) {
  const error = new Error(`${label} must be an absolute local path`)
  error.name = 'GhidraHeadlessError'
  error.code = 'GHIDRA_PATH_INVALID'
  return error
}

function assertWindowsLocalPath(value, label) {
  if (
    typeof value !== 'string'
    || value.length < 1
    || value.length > 4_096
    || value.trim() !== value
    || CONTROL_PATTERN.test(value)
    || !win32.isAbsolute(value)
  ) throw pathError(label)

  const normalized = value.replaceAll('/', '\\')
  if (
    normalized.startsWith('\\\\')
    || normalized.startsWith('\\\\?\\')
    || normalized.startsWith('\\\\.\\')
    || WINDOWS_INVALID_PATH_PATTERN.test(normalized)
  ) throw pathError(label)
  return value
}

export function windowsJavaDevelopmentToolCandidates(environment, executable) {
  if (!environment || typeof environment !== 'object' || !JAVA_TOOL_NAMES.has(executable)) {
    throw new TypeError('Windows Java discovery requires an environment and one fixed JDK executable name')
  }
  const candidates = []
  for (const javaHome of [environment.JAVA_HOME, environment.JDK_HOME]) {
    if (typeof javaHome !== 'string' || javaHome.length < 1) continue
    assertWindowsLocalPath(javaHome, 'Java home')
    candidates.push(win32.join(javaHome, 'bin', executable))
  }

  for (const searchPath of [environment.Path, environment.PATH]) {
    if (typeof searchPath !== 'string' || searchPath.length < 1) continue
    for (const entry of searchPath.split(';')) {
      const unquoted = entry.length >= 2 && entry.startsWith('"') && entry.endsWith('"')
        ? entry.slice(1, -1)
        : entry
      if (unquoted.length < 1 || !win32.isAbsolute(unquoted)) continue
      try {
        assertWindowsLocalPath(unquoted, 'Java tool search path')
        candidates.push(win32.join(unquoted, executable))
      } catch {
        // Invalid PATH entries are not executable candidates.
      }
    }
  }

  const seen = new Set()
  return candidates.filter((candidate) => {
    const key = win32.normalize(candidate).toLowerCase()
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}
