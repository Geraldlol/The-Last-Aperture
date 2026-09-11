import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  link,
  mkdir,
  mkdtemp,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import {
  DEFAULT_ENGAGEMENT_OUTPUT_LIMITS,
  ENGAGEMENT_OUTPUT_BINDING_KIND,
  ENGAGEMENT_OUTPUT_BINDING_SCHEMA_VERSION,
  EngagementOutputBindingError,
  bindEngagementOutput,
  canonicalEngagementOutputBinding,
  digestEngagementOutputBinding,
  verifyEngagementOutputBinding,
} from '../scripts/lib/engagement-output-binding.mjs'

async function fixture(t, name) {
  const parent = await mkdtemp(join(tmpdir(), `last-aperture-output-${name}-`))
  const route = join(parent, 'route')
  await mkdir(route)
  t.after(() => rm(parent, { recursive: true, force: true }))
  return { parent, route }
}

function clone(value) {
  return JSON.parse(JSON.stringify(value))
}

function rejectsCode(code) {
  return (error) => {
    assert.equal(error instanceof EngagementOutputBindingError, true)
    assert.equal(error.code, code)
    return true
  }
}

async function writeTree(route, order) {
  const output = join(route, 'output')
  await mkdir(output)
  for (const item of order) {
    if (item.kind === 'directory') await mkdir(join(output, item.path), { recursive: true })
    else await writeFile(join(output, item.path), item.content)
  }
}

test('a regular file is bound by route-relative path, size, and content digest', async (t) => {
  const { route } = await fixture(t, 'file')
  const bytes = Buffer.from([0, 1, 2, 3, 254, 255])
  await writeFile(join(route, 'report.bin'), bytes)

  const binding = await bindEngagementOutput({ routeDirectory: route, relativePath: 'report.bin' })

  assert.equal(binding.schema_version, ENGAGEMENT_OUTPUT_BINDING_SCHEMA_VERSION)
  assert.equal(binding.kind, ENGAGEMENT_OUTPUT_BINDING_KIND)
  assert.equal(binding.root_relative_path, 'report.bin')
  assert.equal(binding.root_kind, 'file')
  assert.equal(binding.entry_count, 1)
  assert.equal(binding.total_size_bytes, bytes.length)
  assert.deepEqual(binding.entries, [{
    relative_path: 'report.bin',
    entry_kind: 'file',
    size_bytes: bytes.length,
    sha256: createHash('sha256').update(bytes).digest('hex'),
  }])
  assert.match(binding.tree_sha256, /^[a-f0-9]{64}$/u)
  assert.match(digestEngagementOutputBinding(binding), /^[a-f0-9]{64}$/u)
  assert.equal(Object.isFrozen(binding), true)
  assert.equal(Object.isFrozen(binding.entries), true)
  const persisted = canonicalEngagementOutputBinding(binding)
  assert.equal(persisted.endsWith('\n'), true)
  assert.deepEqual(
    await verifyEngagementOutputBinding({ routeDirectory: route, binding: JSON.parse(persisted) }),
    binding,
  )
})

test('directory bindings are independent of creation order and host metadata', async (t) => {
  const left = await fixture(t, 'tree-left')
  const right = await fixture(t, 'tree-right')
  const forward = [
    { kind: 'directory', path: 'nested' },
    { kind: 'file', path: 'nested/b.txt', content: 'beta' },
    { kind: 'file', path: 'a.txt', content: 'alpha' },
    { kind: 'directory', path: 'empty' },
  ]
  const reverse = [
    { kind: 'directory', path: 'empty' },
    { kind: 'file', path: 'a.txt', content: 'alpha' },
    { kind: 'directory', path: 'nested' },
    { kind: 'file', path: 'nested/b.txt', content: 'beta' },
  ]
  await writeTree(left.route, forward)
  await writeTree(right.route, reverse)

  const leftBinding = await bindEngagementOutput({ routeDirectory: left.route, relativePath: 'output' })
  const rightBinding = await bindEngagementOutput({ routeDirectory: right.route, relativePath: 'output' })

  assert.deepEqual(leftBinding, rightBinding)
  assert.deepEqual(leftBinding.entries.map(({ relative_path: path }) => path), [
    'output',
    'output/a.txt',
    'output/empty',
    'output/nested',
    'output/nested/b.txt',
  ])
  assert.equal(leftBinding.entry_count, 5)
  assert.equal(leftBinding.total_size_bytes, 9)
  assert.equal(leftBinding.entries.find(({ relative_path: path }) => path === 'output/empty').size_bytes, 0)
  assert.deepEqual(
    await verifyEngagementOutputBinding({ routeDirectory: right.route, binding: leftBinding }),
    leftBinding,
    'the binding can verify an identical tree at the same route-relative location',
  )
})

test('verification detects content, membership, and existence changes', async (t) => {
  const { route } = await fixture(t, 'changed')
  await mkdir(join(route, 'output'))
  const file = join(route, 'output', 'result.txt')
  await writeFile(file, 'first')
  const binding = await bindEngagementOutput({ routeDirectory: route, relativePath: 'output' })

  await writeFile(file, 'other')
  await assert.rejects(
    verifyEngagementOutputBinding({ routeDirectory: route, binding }),
    rejectsCode('ENGAGEMENT_OUTPUT_BINDING_MISMATCH'),
  )

  await writeFile(file, 'first')
  await writeFile(join(route, 'output', 'extra.txt'), '')
  await assert.rejects(
    verifyEngagementOutputBinding({ routeDirectory: route, binding }),
    rejectsCode('ENGAGEMENT_OUTPUT_BINDING_MISMATCH'),
  )

  await rm(join(route, 'output'), { recursive: true })
  await assert.rejects(
    verifyEngagementOutputBinding({ routeDirectory: route, binding }),
    rejectsCode('ENGAGEMENT_OUTPUT_BINDING_MISMATCH'),
  )
})

test('bindings reject traversal, absolute, alternate-stream, and ambiguous path syntax before I/O', async (t) => {
  const { route } = await fixture(t, 'paths')
  const invalid = [
    '.',
    '../outside',
    'output/../outside',
    'output\\result',
    '/absolute',
    'C:/absolute',
    'output//result',
    'output/result:stream',
    'output/CON',
    'output/trailing.',
  ]
  for (const relativePath of invalid) {
    await assert.rejects(
      bindEngagementOutput({ routeDirectory: route, relativePath }),
      rejectsCode('ENGAGEMENT_OUTPUT_PATH_UNSAFE'),
      relativePath,
    )
  }
})

test('a symbolic-link or junction entry is never followed', async (t) => {
  const { parent, route } = await fixture(t, 'symlink')
  const output = join(route, 'output')
  const outside = join(parent, 'outside')
  await mkdir(output)
  await mkdir(outside)
  await writeFile(join(outside, 'secret.txt'), 'outside')
  try {
    await symlink(outside, join(output, 'alias'), process.platform === 'win32' ? 'junction' : 'dir')
  } catch (error) {
    if (error?.code === 'EPERM' || error?.code === 'EACCES') {
      t.skip('this host does not allow creating a test link')
      return
    }
    throw error
  }

  await assert.rejects(
    bindEngagementOutput({ routeDirectory: route, relativePath: 'output' }),
    (error) => {
      assert.equal(error instanceof EngagementOutputBindingError, true)
      assert.equal(
        ['ENGAGEMENT_OUTPUT_ENTRY_UNSAFE', 'ENGAGEMENT_OUTPUT_PATH_UNSAFE'].includes(error.code),
        true,
      )
      return true
    },
  )
})

test('a linked route ancestor is rejected before any output is read', async (t) => {
  const { parent } = await fixture(t, 'linked-route')
  const real = join(parent, 'real-route')
  const alias = join(parent, 'route-alias')
  await mkdir(join(real, 'output'), { recursive: true })
  await writeFile(join(real, 'output', 'result.txt'), 'result')
  try {
    await symlink(real, alias, process.platform === 'win32' ? 'junction' : 'dir')
  } catch (error) {
    if (error?.code === 'EPERM' || error?.code === 'EACCES') {
      t.skip('this host does not allow creating a test link')
      return
    }
    throw error
  }

  await assert.rejects(
    bindEngagementOutput({ routeDirectory: alias, relativePath: 'output' }),
    rejectsCode('ENGAGEMENT_OUTPUT_PATH_UNSAFE'),
  )
})

test('hard-linked files are rejected even when the other name is outside the output tree', async (t) => {
  const { route } = await fixture(t, 'hardlink')
  await mkdir(join(route, 'output'))
  const source = join(route, 'source.txt')
  await writeFile(source, 'shared')
  await link(source, join(route, 'output', 'linked.txt'))

  await assert.rejects(
    bindEngagementOutput({ routeDirectory: route, relativePath: 'output' }),
    rejectsCode('ENGAGEMENT_OUTPUT_ENTRY_UNSAFE'),
  )
})

test('entry and aggregate-byte limits fail closed and are persisted in valid bindings', async (t) => {
  const { route } = await fixture(t, 'limits')
  await mkdir(join(route, 'output'))
  await writeFile(join(route, 'output', 'one.txt'), '12')
  await writeFile(join(route, 'output', 'two.txt'), '345')

  await assert.rejects(
    bindEngagementOutput({
      routeDirectory: route,
      relativePath: 'output',
      limits: { maximumEntries: 2 },
    }),
    rejectsCode('ENGAGEMENT_OUTPUT_LIMIT_EXCEEDED'),
  )
  await assert.rejects(
    bindEngagementOutput({
      routeDirectory: route,
      relativePath: 'output',
      limits: { maximumTotalBytes: 4 },
    }),
    rejectsCode('ENGAGEMENT_OUTPUT_LIMIT_EXCEEDED'),
  )
  await assert.rejects(
    bindEngagementOutput({
      routeDirectory: route,
      relativePath: 'output',
      limits: { maximumEntries: DEFAULT_ENGAGEMENT_OUTPUT_LIMITS.maximumEntries + 1 },
    }),
    rejectsCode('ENGAGEMENT_OUTPUT_LIMIT_INVALID'),
  )

  const binding = await bindEngagementOutput({
    routeDirectory: route,
    relativePath: 'output',
    limits: { maximumEntries: 3, maximumTotalBytes: 5 },
  })
  const defaultBinding = await bindEngagementOutput({ routeDirectory: route, relativePath: 'output' })
  assert.deepEqual(binding.limits, { maximum_entries: 3, maximum_total_bytes: 5 })
  assert.equal(binding.entry_count, 3)
  assert.equal(binding.total_size_bytes, 5)
  assert.equal(binding.tree_sha256, defaultBinding.tree_sha256, 'scan policy does not alter the tree digest')
  assert.notEqual(
    digestEngagementOutputBinding(binding),
    digestEngagementOutputBinding(defaultBinding),
    'the full binding digest includes the enforced scan policy',
  )
})

test('tampered or structurally incoherent persisted bindings are rejected before traversal', async (t) => {
  const { route } = await fixture(t, 'tamper')
  await mkdir(join(route, 'output'))
  await writeFile(join(route, 'output', 'result.txt'), 'result')
  const binding = await bindEngagementOutput({ routeDirectory: route, relativePath: 'output' })

  const badTreeDigest = clone(binding)
  badTreeDigest.tree_sha256 = '0'.repeat(64)
  assert.throws(
    () => digestEngagementOutputBinding(badTreeDigest),
    rejectsCode('ENGAGEMENT_OUTPUT_BINDING_INVALID'),
  )

  const reordered = clone(binding)
  reordered.entries.reverse()
  await assert.rejects(
    verifyEngagementOutputBinding({ routeDirectory: route, binding: reordered }),
    rejectsCode('ENGAGEMENT_OUTPUT_BINDING_INVALID'),
  )

  const missingParent = clone(binding)
  missingParent.entries[0].entry_kind = 'file'
  await assert.rejects(
    verifyEngagementOutputBinding({ routeDirectory: route, binding: missingParent }),
    rejectsCode('ENGAGEMENT_OUTPUT_BINDING_INVALID'),
  )
})

test('socket, device, FIFO, and other non-regular entries are rejected', async (t) => {
  if (process.platform === 'win32') {
    t.skip('portable FIFO creation is unavailable on Windows')
    return
  }
  const { route } = await fixture(t, 'fifo')
  await mkdir(join(route, 'output'))
  const fifo = join(route, 'output', 'pipe')
  try {
    execFileSync('mkfifo', [fifo], { stdio: 'ignore' })
  } catch {
    t.skip('mkfifo is unavailable on this host')
    return
  }

  await assert.rejects(
    bindEngagementOutput({ routeDirectory: route, relativePath: 'output' }),
    rejectsCode('ENGAGEMENT_OUTPUT_ENTRY_UNSAFE'),
  )
})
