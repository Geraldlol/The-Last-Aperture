import { realpathSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export function isMainModule(moduleUrl, argvPath = process.argv[1]) {
  if (!argvPath) return false
  try {
    return realpathSync.native(fileURLToPath(moduleUrl)) ===
      realpathSync.native(resolve(argvPath))
  } catch {
    return false
  }
}
