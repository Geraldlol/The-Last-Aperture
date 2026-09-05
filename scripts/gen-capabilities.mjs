import { readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { renderCapabilityDocumentation } from './lib/capabilities.mjs'
import { isMainModule } from './lib/main-module.mjs'

export async function generateCapabilities({ check = false, output = fileURLToPath(new URL('../docs/capabilities.md', import.meta.url)) } = {}) {
  const expected = renderCapabilityDocumentation()
  if (check) {
    const actual = await readFile(resolve(output), 'utf8')
    if (actual !== expected) throw new Error('capability documentation differs from the release registry; run node scripts/gen-capabilities.mjs')
  } else await writeFile(resolve(output), expected)
  return { checked: check, output }
}

if (isMainModule(import.meta.url)) {
  try {
    if (process.argv.slice(2).some((arg) => arg !== '--check')) throw new Error('usage: node scripts/gen-capabilities.mjs [--check]')
    const result = await generateCapabilities({ check: process.argv.includes('--check') })
    console.log(result.checked ? 'PASS: capability documentation matches the release registry.' : 'Generated docs/capabilities.md from the release registry.')
  } catch (error) {
    console.error(`ERROR: ${error.message}`)
    process.exitCode = 1
  }
}
