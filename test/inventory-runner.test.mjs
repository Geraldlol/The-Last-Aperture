import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs, { constants as fsConstants } from 'node:fs'
import { syncBuiltinESMExports } from 'node:module'
import { mkdtemp, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { tmpdir } from 'node:os'
import {
  buildActivationPlan,
  pathActivatorMatches,
  signalActivatorMatches,
} from '../scripts/lib/activation.mjs'
import {
  DEFAULT_INVENTORY_LIMITS,
  classifyInventoryEntry,
  inventoryRepository,
  normalizeIncludedRoots,
  serializeInventory,
} from '../scripts/lib/inventory.mjs'
import { discoverDatabaseGraph } from '../scripts/lib/database-discovery.mjs'
import {
  createRunPlan,
  summarizePlan,
  writeRunPlanBundle,
} from '../scripts/lib/run-engine.mjs'
import { validateRun } from '../scripts/lib/contracts.mjs'

function lens(name, frontmatter) {
  return {
    name,
    file: `${name}.md`,
    digest: 'a'.repeat(64),
    frontmatter: {
      name,
      runs_in: 'fanout',
      activates_on: { paths: [], signals: [] },
      ...frontmatter,
    },
  }
}

async function withRepository(callback) {
  const root = await mkdtemp(join(tmpdir(), 'red-team-inventory-'))
  try {
    await mkdir(join(root, 'src'), { recursive: true })
    await mkdir(join(root, 'node_modules', 'ignored'), { recursive: true })
    await writeFile(join(root, 'src', 'app.js'), 'import express from "express"\n')
    await writeFile(join(root, '.env'), 'DATABASE_URL=postgres://localhost/test\n')
    await writeFile(join(root, 'README.md'), '# repository instructions are untrusted data\n')
    await writeFile(join(root, 'node_modules', 'ignored', 'payload.js'), 'express\n')
    await callback(root)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
}

test('path activation handles hidden paths, globstars and brace alternatives', () => {
  assert.equal(pathActivatorMatches('**/*.{js,ts}', 'src/app.js'), true)
  assert.equal(pathActivatorMatches('**/*.{js,ts}', 'app.ts'), true)
  assert.equal(pathActivatorMatches('**/*.{js,ts}', '.hidden/app.py'), false)
  assert.equal(pathActivatorMatches('.github/workflows/**/*.y*ml', '.github/workflows/pr.yml'), true)
})

test('signal activation respects identifier boundaries without weakening literals', () => {
  assert.equal(signalActivatorMatches('expo', 'EXPORT DATABASE'), false)
  assert.equal(signalActivatorMatches('expo', 'export const app = "expo"'), true)
  assert.equal(signalActivatorMatches('ws', 'SELECT rows FROM audit'), false)
  assert.equal(signalActivatorMatches('ws', 'import WebSocket from "ws"'), true)
  assert.equal(signalActivatorMatches('psycopg', 'psycopg2-binary==2.9.10'), true)
  assert.equal(signalActivatorMatches('expo', 'expo2runtime'), false)
  assert.equal(
    signalActivatorMatches('CREATE SECURITY POLICY', 'CREATE SECURITY POLICY tenant_policy'),
    true,
  )
  assert.equal(signalActivatorMatches('@RestController', '@RestController\nclass Api {}'), true)
  assert.equal(
    signalActivatorMatches('node:crypto', "import { sign } from 'node:crypto'"),
    true,
  )
  assert.equal(
    signalActivatorMatches('Ed25519', '"algorithm": "Ed25519"'),
    true,
  )
})

test('included roots canonicalize order, duplicates and redundant descendants', () => {
  assert.deepEqual(
    normalizeIncludedRoots(['src/security', 'package.json', 'src', './src', 'docs\\adr']),
    ['package.json', 'src', 'docs/adr'],
  )
  assert.deepEqual(normalizeIncludedRoots(['src', '.']), ['.'])
})

test('inventory includes hidden files, excludes configured dependency trees and hashes inputs', async () => {
  await withRepository(async (root) => {
    const inventory = await inventoryRepository(root)
    assert.equal(inventory.complete, true)
    assert.deepEqual(
      inventory.entries.map(({ path }) => path),
      ['.env', 'README.md', 'src/app.js'],
    )
    assert.ok(inventory.entries.every(({ sha256 }) => /^[a-f0-9]{64}$/.test(sha256)))
    assert.deepEqual(inventory.excluded, [
      { path: 'node_modules/', reason: 'configured-directory-exclusion' },
    ])
    assert.match(inventory.treeDigest, /^[a-f0-9]{64}$/)
    assert.equal(JSON.stringify(serializeInventory(inventory)).includes('content'), false)
    assert.equal(JSON.stringify(serializeInventory(inventory)).includes('absolutePath'), false)
  })
})

test('inventory and database discovery share one locale-independent path order', async () => {
  const root = await mkdtemp(join(tmpdir(), 'red-team-inventory-order-'))
  try {
    await mkdir(join(root, 'frontend-app', 'dist'), { recursive: true })
    await Promise.all([
      writeFile(join(root, 'AUDIT_REPORT.md'), '# Audit\n'),
      writeFile(
        join(root, 'frontend-app', 'dist', 'app.js'),
        'export const app = true\n',
      ),
    ])

    const inventory = await inventoryRepository(root)
    const discovery = discoverDatabaseGraph(inventory)
    const inventoryPaths = inventory.entries.map(({ path }) => path)

    assert.deepEqual(inventoryPaths, [
      'AUDIT_REPORT.md',
      'frontend-app/dist/app.js',
    ])
    assert.deepEqual(
      discovery.path_scope.map(({ path }) => path),
      inventoryPaths,
    )
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('inventory categories are deterministic and ambiguous text defaults to canonical source', () => {
  assert.equal(
    classifyInventoryEntry({ path: 'src/app.ts', kind: 'text', content: 'export const app = 1' }),
    'canonical-source',
  )
  assert.equal(
    classifyInventoryEntry({ path: 'src/client.ts', kind: 'text', content: '// DO NOT EDIT - generated automatically' }),
    'generated-code',
  )
  assert.equal(
    classifyInventoryEntry({ path: 'test/app.spec.ts', kind: 'text', content: 'test("app", () => {})' }),
    'tests',
  )
  assert.equal(
    classifyInventoryEntry({ path: 'docs/security.md', kind: 'text', content: '# Security' }),
    'docs',
  )
  assert.equal(
    classifyInventoryEntry({ path: 'assets/blob.unknown', kind: 'binary' }),
    'binaries',
  )
  assert.equal(
    classifyInventoryEntry({ path: 'odd/no-extension', kind: 'unreadable' }),
    'canonical-source',
  )
})

test('activation is deterministic and uncovered text is an explicit incomplete gap', async () => {
  await withRepository(async (root) => {
    const inventory = await inventoryRepository(root)
    const plan = buildActivationPlan([
      lens('web', {
        activates_on: { paths: ['**/*.{js,ts}'], signals: ['express'] },
      }),
      lens('database', {
        activates_on: { paths: [], signals: ['DATABASE_URL'] },
      }),
      lens('always', {
        always_active: true,
      }),
      lens('triage', {
        runs_in: 'triage',
      }),
    ], inventory)

    assert.equal(plan.coverage.status, 'incomplete')
    assert.deepEqual(plan.coverage.unassigned_text_files, ['README.md'])
    assert.deepEqual(plan.active_lenses, ['always', 'database', 'web', 'triage'])
    assert.deepEqual(
      plan.jobs.find(({ lens: name }) => name === 'database').scoped_files,
      ['.env'],
    )
    assert.deepEqual(
      plan.jobs.find(({ lens: name }) => name === 'web').scoped_files,
      ['src/app.js'],
    )
    assert.equal(
      plan.jobs.find(({ lens: name }) => name === 'triage').phase,
      'triage',
    )
  })
})

test('oversized readable inputs cannot be silently counted as examined', async () => {
  const root = await mkdtemp(join(tmpdir(), 'red-team-inventory-limit-'))
  try {
    await writeFile(join(root, 'large.sql'), 'A'.repeat(65))
    const inventory = await inventoryRepository(root, { maxTextBytes: 64 })
    const plan = buildActivationPlan([
      lens('database', {
        activates_on: { paths: ['**/*.sql'], signals: [] },
      }),
    ], inventory)
    assert.deepEqual(inventory.entries[0], {
      path: 'large.sql',
      kind: 'too-large',
      category: 'canonical-source',
      coverage_class: 'CANONICAL_SOURCE',
      classification_reason: 'default:canonical-source',
      size: 65,
      examined: false,
      reason: 'larger-than-64-byte-static-limit',
    })
    assert.equal(plan.coverage.status, 'incomplete')
    assert.deepEqual(plan.coverage.unexamined, [{
      path: 'large.sql',
      kind: 'too-large',
      reason: 'larger-than-64-byte-static-limit',
    }])
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('oversized binary inputs are classified from a bounded prefix instead of source', async () => {
  const root = await mkdtemp(join(tmpdir(), 'red-team-inventory-large-binary-'))
  try {
    await writeFile(
      join(root, 'large.jpg'),
      Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0x00]), Buffer.alloc(61, 0x7f)]),
    )
    await writeFile(join(root, 'large.js'), 'A'.repeat(65))

    const inventory = await inventoryRepository(root, { maxTextBytes: 64 })
    const binary = inventory.entries.find(({ path }) => path === 'large.jpg')
    const source = inventory.entries.find(({ path }) => path === 'large.js')

    assert.deepEqual({
      path: binary.path,
      kind: binary.kind,
      category: binary.category,
      coverage_class: binary.coverage_class,
      classification_reason: binary.classification_reason,
      size: binary.size,
      examined: binary.examined,
      reason: binary.reason,
    }, {
      path: 'large.jpg',
      kind: 'binary',
      category: 'binaries',
      coverage_class: 'BINARY',
      classification_reason: 'kind:binary',
      size: 65,
      examined: false,
      reason: 'binary-content-not-decoded',
    })
    assert.deepEqual(source, {
      path: 'large.js',
      kind: 'too-large',
      category: 'canonical-source',
      coverage_class: 'CANONICAL_SOURCE',
      classification_reason: 'default:canonical-source',
      size: 65,
      examined: false,
      reason: 'larger-than-64-byte-static-limit',
    })
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('run planning reads text up to the selected work-shard byte limit by default', async () => {
  const root = await mkdtemp(join(tmpdir(), 'red-team-inventory-shard-limit-'))
  try {
    const sourceSize = DEFAULT_INVENTORY_LIMITS.maxTextBytes + 1
    await writeFile(join(root, 'large.js'), 'A'.repeat(sourceSize))

    const plan = await createRunPlan({
      targetRoot: root,
      lensDirectory: resolve('skills/last-aperture/lenses'),
      createdAt: new Date('2026-07-29T00:00:00.000Z'),
      shardOptions: {
        maxFiles: 64,
        maxBytes: sourceSize,
      },
    })
    const record = plan.run.coverage.inventory_records.find(
      ({ path }) => path === 'large.js',
    )

    assert.equal(record.kind, 'text')
    assert.equal(record.coverage_class, 'CANONICAL_SOURCE')
    assert.equal(record.size, sourceSize)
    assert.ok(plan.run.coverage.shards.some(
      ({ scoped_files: scopedFiles }) => scopedFiles.includes('large.js'),
    ))
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('inventory file quota stops deterministically with an explicit error', async () => {
  const root = await mkdtemp(join(tmpdir(), 'red-team-inventory-file-quota-'))
  try {
    await writeFile(join(root, 'a.js'), 'a')
    await writeFile(join(root, 'b.js'), 'b')
    await writeFile(join(root, 'c.js'), 'c')

    const first = await inventoryRepository(root, { maxInventoryFiles: 2 })
    const second = await inventoryRepository(root, { maxInventoryFiles: 2 })

    assert.equal(first.complete, false)
    assert.deepEqual(first.entries.map(({ path }) => path), ['a.js', 'b.js'])
    assert.deepEqual(first.errors, [{
      path: 'c.js',
      operation: 'quota',
      code: 'MAX_FILES_EXCEEDED',
      message: 'inventory stopped before this path because the 2-file limit was reached',
    }])
    assert.equal(first.treeDigest, second.treeDigest)
    assert.deepEqual(first.errors, second.errors)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('traversal quota bounds breadth-heavy empty directory trees', async () => {
  const root = await mkdtemp(join(tmpdir(), 'red-team-inventory-traversal-quota-'))
  try {
    for (const name of ['a', 'b', 'c', 'd']) {
      await mkdir(join(root, name))
    }

    const first = await inventoryRepository(root, { maxTraversalEntries: 3 })
    const second = await inventoryRepository(root, { maxTraversalEntries: 3 })

    assert.equal(first.complete, false)
    assert.deepEqual(first.entries, [])
    assert.deepEqual(first.errors, [{
      path: './',
      operation: 'quota',
      code: 'MAX_TRAVERSAL_ENTRIES_EXCEEDED',
      message: 'inventory stopped at this directory because the 3-traversal-entry limit was exceeded',
    }])
    assert.equal(first.treeDigest, second.treeDigest)
    assert.deepEqual(first.errors, second.errors)

    const plan = buildActivationPlan([
      lens('always', { always_active: true }),
    ], first)
    assert.equal(plan.coverage.status, 'incomplete')
    assert.deepEqual(plan.coverage.inventory_errors, first.errors)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('directory enumeration stops after one sentinel beyond the traversal quota', async () => {
  const root = await mkdtemp(join(tmpdir(), 'red-team-inventory-stream-quota-'))
  const realOpendir = fs.promises.opendir
  let readCalls = 0
  let closeCalls = 0

  fs.promises.opendir = async (path, ...rest) => {
    if (resolve(path) !== resolve(root)) return realOpendir(path, ...rest)
    return {
      async read() {
        readCalls += 1
        if (readCalls > 4) {
          throw new Error('enumeration read past the bounded sentinel')
        }
        return { name: `synthetic-${readCalls}.js` }
      },
      async close() {
        closeCalls += 1
      },
    }
  }
  syncBuiltinESMExports()

  try {
    const inventory = await inventoryRepository(root, { maxTraversalEntries: 3 })
    assert.equal(readCalls, 4)
    assert.equal(closeCalls, 1)
    assert.deepEqual(inventory.entries, [])
    assert.equal(inventory.errors[0]?.code, 'MAX_TRAVERSAL_ENTRIES_EXCEEDED')
  } finally {
    fs.promises.opendir = realOpendir
    syncBuiltinESMExports()
    await rm(root, { recursive: true, force: true })
  }
})

test('total byte quota creates an explicit unexamined gap and can use remaining capacity', async () => {
  const root = await mkdtemp(join(tmpdir(), 'red-team-inventory-byte-quota-'))
  try {
    await writeFile(join(root, 'a.js'), 'aaaa')
    await writeFile(join(root, 'b.js'), 'bbbb')
    await writeFile(join(root, 'c.js'), 'c')

    const inventory = await inventoryRepository(root, { maxInventoryBytes: 5 })

    assert.equal(inventory.complete, false)
    assert.deepEqual(
      inventory.entries.map(({ path, kind, examined, reason }) => ({
        path,
        kind,
        examined,
        reason,
      })),
      [
        { path: 'a.js', kind: 'text', examined: true, reason: null },
        {
          path: 'b.js',
          kind: 'quota-exceeded',
          examined: false,
          reason: 'total-inventory-byte-limit-5-bytes-exceeded',
        },
        { path: 'c.js', kind: 'text', examined: true, reason: null },
      ],
    )
    assert.deepEqual(inventory.errors, [{
      path: 'b.js',
      operation: 'quota',
      code: 'MAX_TOTAL_BYTES_EXCEEDED',
      message: 'reading this file would exceed the 5-byte total inventory limit',
    }])

    const plan = buildActivationPlan([
      lens('web', {
        activates_on: { paths: ['**/*.js'], signals: [] },
      }),
    ], inventory)
    assert.equal(plan.coverage.status, 'incomplete')
    assert.ok(plan.coverage.unexamined.some(({ path }) => path === 'b.js'))
    assert.ok(plan.coverage.inventory_errors.some(
      ({ code }) => code === 'MAX_TOTAL_BYTES_EXCEEDED',
    ))
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('directory depth quota is deterministic and reports the omitted subtree', async () => {
  const root = await mkdtemp(join(tmpdir(), 'red-team-inventory-depth-quota-'))
  try {
    await mkdir(join(root, 'one', 'two'), { recursive: true })
    await writeFile(join(root, 'one', 'two', 'deep.js'), 'deep')
    await writeFile(join(root, 'top.js'), 'top')

    const inventory = await inventoryRepository(root, { maxDirectoryDepth: 1 })

    assert.deepEqual(inventory.entries.map(({ path }) => path), ['top.js'])
    assert.deepEqual(inventory.errors, [{
      path: 'one/two/',
      operation: 'depth',
      code: 'MAX_DEPTH_EXCEEDED',
      message: 'inventory did not descend beyond the 1-directory depth limit',
    }])
    assert.equal(inventory.complete, false)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('inventory rejects a file replaced between lstat and open', async () => {
  const root = await mkdtemp(join(tmpdir(), 'red-team-inventory-target-race-'))
  const target = join(root, 'target.js')
  const original = join(root, 'original.js')
  const replacement = join(root, 'replacement.js')
  await writeFile(target, 'trusted\n')
  await writeFile(replacement, 'hostile\n')

  const realOpen = fs.promises.open
  let intercepted = false
  let observedFlags
  fs.promises.open = async (path, flags, ...rest) => {
    if (!intercepted && resolve(path) === resolve(target)) {
      intercepted = true
      observedFlags = flags
      await rename(target, original)
      await rename(replacement, target)
    }
    return realOpen(path, flags, ...rest)
  }
  syncBuiltinESMExports()

  try {
    const inventory = await inventoryRepository(root)
    assert.equal(intercepted, true)
    if (typeof fsConstants.O_NOFOLLOW === 'number') {
      assert.equal(observedFlags & fsConstants.O_NOFOLLOW, fsConstants.O_NOFOLLOW)
    }
    assert.deepEqual(
      inventory.entries.find(({ path }) => path === 'target.js'),
      {
        path: 'target.js',
        kind: 'unreadable',
        category: 'canonical-source',
        coverage_class: 'CANONICAL_SOURCE',
        classification_reason: 'default:canonical-source',
        size: 8,
        examined: false,
        reason: 'inventory-target-changed',
      },
    )
    assert.deepEqual(
      inventory.errors.find(({ path }) => path === 'target.js'),
      {
        path: 'target.js',
        operation: 'verify-open-file',
        code: 'TARGET_CHANGED',
        message: 'inventory target identity or metadata changed between lstat and open',
      },
    )
    assert.equal(inventory.complete, false)
  } finally {
    fs.promises.open = realOpen
    syncBuiltinESMExports()
    await rm(root, { recursive: true, force: true })
  }
})

test('inventory limits use bounded defaults and reject invalid overrides', async () => {
  await withRepository(async (root) => {
    const inventory = await inventoryRepository(root)
    assert.deepEqual(inventory.limits, {
      ...DEFAULT_INVENTORY_LIMITS,
      includedRoots: ['.'],
    })

    await assert.rejects(
      inventoryRepository(root, { maxInventoryFiles: -1 }),
      /maxInventoryFiles must be a non-negative safe integer/,
    )
    await assert.rejects(
      inventoryRepository(root, { maxInventoryFiles: 100_001 }),
      /maxInventoryFiles must be at most 100000/,
    )
    await assert.rejects(
      inventoryRepository(root, { maxInventoryBytes: Number.POSITIVE_INFINITY }),
      /maxInventoryBytes must be a non-negative safe integer/,
    )
    await assert.rejects(
      inventoryRepository(root, { maxTraversalEntries: -1 }),
      /maxTraversalEntries must be a non-negative safe integer/,
    )
  })
})

test('planning writes a provenance bundle without embedding repository contents', async () => {
  await withRepository(async (root) => {
    const output = await mkdtemp(join(tmpdir(), 'red-team-run-bundle-'))
    try {
      const plan = await createRunPlan({
        targetRoot: root,
        lensDirectory: resolve('skills/last-aperture/lenses'),
        createdAt: new Date('2026-07-28T20:00:00.000Z'),
      })
      const validation = validateRun(plan.run)
      assert.equal(validation.valid, true, JSON.stringify(validation.errors, null, 2))
      assert.deepEqual(
        plan.run.coverage.denominators.map(({ class: coverageClass }) => coverageClass),
        ['CANONICAL_SOURCE', 'GENERATED_CODE', 'TEST', 'DOCUMENTATION', 'BINARY'],
      )
      assert.ok(plan.run.coverage.denominators.every((row) =>
        row.files_total === row.files.length
        && row.files_total === row.paths.length
        && row.files_examined === 0
        && row.bytes_examined === 0
        && row.files_unexamined === row.files_total
        && row.bytes_unexamined === row.bytes_total))
      assert.ok(plan.run.coverage.inventory_records.every((record) =>
        typeof record.coverage_class === 'string'
        && typeof record.classification_reason === 'string'))
      const summary = summarizePlan(plan)
      assert.equal(plan.run.state, 'PLANNED')
      assert.equal(plan.run.capability_mode, 'STATIC')
      assert.equal(summary.files, 3)
      assert.ok(summary.active_fanout_lenses > 0)
      assert.match(plan.run.plan_digest, /^[a-f0-9]{64}$/)
      const inactiveLenses = plan.activation.jobs
        .filter(({ activated }) => !activated)
        .map(({ lens: lensName }) => lensName)
      assert.ok(inactiveLenses.length > 0)
      assert.ok(inactiveLenses.every((lensName) =>
        plan.run.coverage.lenses.find(({ lens }) => lens === lensName)?.status
          === 'NOT_TRIGGERED'))
      assert.ok(plan.run.coverage.lenses.every(
        ({ status }) => status !== 'NOT_APPLICABLE',
      ))

      const written = await writeRunPlanBundle(plan, output)
      const run = JSON.parse(await readFile(written.runPath, 'utf8'))
      const inventory = await readFile(join(written.directory, 'inventory.json'), 'utf8')
      assert.equal(run.run_id, plan.run.run_id)
      assert.ok(Object.hasOwn(run.artifacts, 'inventory'))
      assert.equal(run.artifacts.coverage_plan.path, 'coverage-plan.json')
      assert.deepEqual(
        JSON.parse(await readFile(join(written.directory, 'coverage-plan.json'), 'utf8')),
        plan.run.coverage,
      )
      await assert.rejects(
        readFile(join(written.directory, 'coverage.json'), 'utf8'),
        { code: 'ENOENT' },
      )
      assert.equal(inventory.includes('postgres://localhost/test'), false)
      assert.equal(inventory.includes('"content"'), false)
      assert.ok(run.jobs.some(({ state }) => state === 'PENDING'))
    } finally {
      await rm(output, { recursive: true, force: true })
    }
  })
})
