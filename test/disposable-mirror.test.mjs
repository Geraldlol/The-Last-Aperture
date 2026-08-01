import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  createMirror,
  materializeFiles,
  assertTargetUnchanged,
  destroyMirror,
  MirrorMutationError,
} from '../scripts/lib/disposable-mirror.mjs'
import { inventoryRepository } from '../scripts/lib/inventory.mjs'

function makeTarget() {
  const root = mkdtempSync(join(tmpdir(), 'rta-target-'))
  mkdirSync(join(root, 'src'), { recursive: true })
  writeFileSync(join(root, 'src', 'app.js'), 'export const x = 1\n')
  writeFileSync(join(root, 'package.json'), '{"name":"t","version":"1.0.0"}\n')
  return root
}

const mirrorPath = () => join(mkdtempSync(join(tmpdir(), 'rta-mirror-')), 'work')

test('the mirror reproduces the target byte for byte', async () => {
  const target = makeTarget()
  const mirror = mirrorPath()
  const { root } = await createMirror(target, mirror)
  assert.equal(root, mirror)
  assert.equal(readFileSync(join(mirror, 'src', 'app.js'), 'utf8'), 'export const x = 1\n')
  assert.equal(
    readFileSync(join(mirror, 'package.json'), 'utf8'),
    '{"name":"t","version":"1.0.0"}\n',
  )
})

test('the mirror carries .git so the previous-revision rule can run', async () => {
  const target = makeTarget()
  mkdirSync(join(target, '.git'), { recursive: true })
  writeFileSync(join(target, '.git', 'HEAD'), 'ref: refs/heads/main\n')
  const mirror = mirrorPath()
  await createMirror(target, mirror)
  assert.equal(existsSync(join(mirror, '.git', 'HEAD')), true)
})

test('materializeFiles writes into the mirror and returns sorted paths', async () => {
  const target = makeTarget()
  const mirror = mirrorPath()
  await createMirror(target, mirror)
  const written = await materializeFiles(mirror, [
    { path: 'test/security/b.test.mjs', contents: 'b\n' },
    { path: 'test/security/a.test.mjs', contents: 'a\n' },
  ])
  assert.deepEqual(written, ['test/security/a.test.mjs', 'test/security/b.test.mjs'])
  assert.equal(readFileSync(join(mirror, 'test', 'security', 'a.test.mjs'), 'utf8'), 'a\n')
  assert.equal(existsSync(join(target, 'test')), false)
})

test('materializeFiles refuses a path escaping the mirror', async () => {
  const target = makeTarget()
  const mirror = mirrorPath()
  await createMirror(target, mirror)
  await assert.rejects(
    () => materializeFiles(mirror, [{ path: '../escape.js', contents: 'x' }]),
    /escapes the mirror/,
  )
})

test('an unchanged target passes the digest re-check', async () => {
  const target = makeTarget()
  const { treeDigest } = await inventoryRepository(target)
  await assertTargetUnchanged(target, treeDigest)
})

test('a mutated target fails the digest re-check with both digests', async () => {
  const target = makeTarget()
  const { treeDigest } = await inventoryRepository(target)
  writeFileSync(join(target, 'src', 'app.js'), 'export const x = 2\n')
  await assert.rejects(
    () => assertTargetUnchanged(target, treeDigest),
    (error) => {
      assert.ok(error instanceof MirrorMutationError)
      assert.equal(error.expected, treeDigest)
      assert.notEqual(error.actual, treeDigest)
      return true
    },
  )
})

test('destroyMirror removes the tree', async () => {
  const target = makeTarget()
  const mirror = mirrorPath()
  await createMirror(target, mirror)
  await destroyMirror(mirror)
  assert.equal(existsSync(mirror), false)
})
