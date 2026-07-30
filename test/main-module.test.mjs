import assert from 'node:assert/strict'
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { isMainModule } from '../scripts/lib/main-module.mjs'

test('main-module detection fails closed without an argv entrypoint', () => {
  assert.equal(isMainModule(import.meta.url, null), false)
})

test('main-module detection accepts the physical entrypoint', () => {
  assert.equal(isMainModule(import.meta.url, fileURLToPath(import.meta.url)), true)
})

test('main-module detection resolves a linked installation path', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'rta-main-module-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))

  const physicalDirectory = join(root, 'physical')
  const linkedDirectory = join(root, 'installed')
  const entrypoint = join(physicalDirectory, 'entry.mjs')
  mkdirSync(physicalDirectory)
  writeFileSync(entrypoint, '')
  symlinkSync(
    physicalDirectory,
    linkedDirectory,
    process.platform === 'win32' ? 'junction' : 'dir',
  )

  assert.equal(
    isMainModule(pathToFileURL(entrypoint).href, join(linkedDirectory, 'entry.mjs')),
    true,
  )
})
