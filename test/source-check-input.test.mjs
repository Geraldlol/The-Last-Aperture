import assert from 'node:assert/strict'
import * as fs from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { tmpdir } from 'node:os'
import { test } from 'node:test'

import { readSourceCheckInputs, SOURCE_CHECK_INPUT_LIMITS } from '../scripts/lib/source-check-input.mjs'
import { isSourceCheckRelativePath } from '../scripts/lib/source-check-path.mjs'

async function fixture(t, entries = {}) {
  const root = await fs.mkdtemp(join(tmpdir(), 'rta-source-input-'))
  t.after(() => fs.rm(root, { recursive: true, force: true }))
  for (const [path, content] of Object.entries(entries)) {
    await fs.mkdir(join(root, ...path.split('/').slice(0, -1)), { recursive: true })
    await fs.writeFile(join(root, path), content)
  }
  return root
}

function forbiddenFilesystem() {
  let operations = 0
  return {
    fileSystem: new Proxy({}, { get: () => async () => { operations += 1; throw new Error('I/O forbidden') } }),
    operations: () => operations,
  }
}

test('reads only the explicit supported files as inert source and preserves caller order', async (t) => {
  const root = await fixture(t, { 'src/a.js': 'throw new Error("do not execute")', 'b.mjs': '', 'c.cjs': 'module.exports = 1', 'private.txt': 'DO_NOT_READ' })
  const opened = []
  const result = await readSourceCheckInputs({ root, files: ['c.cjs', 'src/a.js', 'b.mjs'], fileSystem: {
    ...fs, open: async (path, flags) => { opened.push(path); return fs.open(path, flags) },
  } })
  assert.deepEqual(result, [
    { path: 'c.cjs', source: 'module.exports = 1' },
    { path: 'src/a.js', source: 'throw new Error("do not execute")' },
    { path: 'b.mjs', source: '' },
  ])
  assert.equal(opened.length, 3)
  assert.ok(!opened.some((path) => path.endsWith('private.txt')))
})

test('shared pure path validation accepts Unicode filenames and the reader preserves valid UTF-8', async (t) => {
  const path = 'src/\u043f\u0440\u0438\u0432\u0456\u0442-\u96ea.js'
  const source = 'export const greeting = "\u041f\u0440\u0438\u0432\u0456\u0442 \u96ea";'
  const root = await fixture(t, { [path]: source })
  assert.equal(isSourceCheckRelativePath(path), true)
  assert.equal(isSourceCheckRelativePath('file with spaces.js'), true)
  const result = await readSourceCheckInputs({ root, files: [path] })
  assert.deepEqual(result, [{ path, source }])
})

test('validates every path before any I/O, including remote syntax and portable aliases', async () => {
  const badPaths = ['', '.', '..', '../a.js', 'a/../b.js', './a.js', 'a//b.js', '/a.js', 'a\\b.js',
    'C:/a.js', 'a.js:stream', '\\\\remote\\share\\a.js', '//remote/share/a.js', '\\??\\C:\\a.js',
    'a\n.js', 'a\u202e.js', 'a*.js', 'a?.js', 'NUL.js', 'nested/COM1.js', 'LPT².js',
    'CONIN$.js', 'folder./a.js', 'folder /a.js', 'a.js ', 'a.js.', 'x'.repeat(4097)]
  for (const path of badPaths) {
    assert.equal(isSourceCheckRelativePath(path), false, JSON.stringify(path))
    const blocked = forbiddenFilesystem()
    await assert.rejects(readSourceCheckInputs({ root: resolve('not-opened'), files: ['valid.js', path], fileSystem: blocked.fileSystem }),
      (error) => error.code === 'SOURCE_CHECK_INPUT_INVALID' && !error.message.includes(path === '' ? 'secret-marker' : path))
    assert.equal(blocked.operations(), 0, `unexpected I/O for ${JSON.stringify(path)}`)
  }
})

test('rejects invalid roots and invalid or duplicate batches before I/O', async () => {
  const batches = [undefined, null, [], 'a.js', ['a.js', 'a.js'], Array(101).fill('a.js'), ['a.js', null]]
  for (const files of batches) {
    const blocked = forbiddenFilesystem()
    await assert.rejects(readSourceCheckInputs({ root: resolve('not-opened'), files, fileSystem: blocked.fileSystem }), { code: 'SOURCE_CHECK_INPUT_INVALID' })
    assert.equal(blocked.operations(), 0)
  }
  for (const root of [undefined, 'relative', '//remote/share', '\\\\remote\\share', '\\??\\C:\\private', `${resolve('bad')}\n`]) {
    const blocked = forbiddenFilesystem()
    await assert.rejects(readSourceCheckInputs({ root, files: ['a.js'], fileSystem: blocked.fileSystem }), { code: 'SOURCE_CHECK_INPUT_INVALID' })
    assert.equal(blocked.operations(), 0)
  }
  if (process.platform === 'win32') {
    const blocked = forbiddenFilesystem()
    await assert.rejects(readSourceCheckInputs({ root: resolve('not-opened'), files: ['a.js', 'A.JS'], fileSystem: blocked.fileSystem }), { code: 'SOURCE_CHECK_INPUT_INVALID' })
    assert.equal(blocked.operations(), 0)
  }
})

test('unsupported languages are explicit gaps without opening or statting those files', async (t) => {
  const root = await fixture(t)
  const files = ['a.ts', 'b.tsx', 'c.jsx', 'secret.json', 'no-extension']
  const touched = []
  const result = await readSourceCheckInputs({ root, files, fileSystem: {
    ...fs,
    lstat: async (path) => { touched.push(path); return fs.lstat(path) },
    open: async () => { throw new Error('unsupported input must not be opened') },
  } })
  assert.deepEqual(result.map((item) => item.path), files)
  assert.ok(result.every((item) => item.gap.code === 'UNSUPPORTED_LANGUAGE' && !Object.hasOwn(item, 'source')))
  assert.ok(!touched.some((path) => files.some((file) => path === join(root, file))))
})

test('missing and nonregular sources produce fixed non-disclosing gaps', async (t) => {
  const root = await fixture(t, { 'private.js': 'synthetic-marker' })
  await fs.mkdir(join(root, 'directory.js'))
  const result = await readSourceCheckInputs({ root, files: ['missing.js', 'directory.js'] })
  assert.ok(result.every((item) => item.gap.code === 'SOURCE_UNREADABLE'))
  assert.ok(!JSON.stringify(result).includes(root))
  const fake = await readSourceCheckInputs({ root, files: ['private.js'], fileSystem: {
    ...fs, open: async () => { throw new Error('DO_NOT_DISCLOSE_INTERNAL_SECRET') },
  } })
  assert.ok(!JSON.stringify(fake).includes('DO_NOT_DISCLOSE_INTERNAL_SECRET'))
})

test('a bad root fails with a fixed batch error', async (t) => {
  const root = await fixture(t, { 'file.js': '' })
  for (const invalidRoot of [join(root, 'missing'), join(root, 'file.js')]) {
    await assert.rejects(readSourceCheckInputs({ root: invalidRoot, files: ['a.js'] }),
      (error) => error.code === 'SOURCE_CHECK_ROOT_UNREADABLE' && !error.message.includes(root))
  }
})

test('size cap permits the exact boundary and does not open an oversized file', async (t) => {
  const root = await fixture(t, { 'exact.js': ' '.repeat(SOURCE_CHECK_INPUT_LIMITS.max_file_bytes), 'large.js': ' '.repeat(SOURCE_CHECK_INPUT_LIMITS.max_file_bytes + 1) })
  const opened = []
  const result = await readSourceCheckInputs({ root, files: ['exact.js', 'large.js'], fileSystem: {
    ...fs, open: async (path, flags) => { opened.push(path); return fs.open(path, flags) },
  } })
  assert.equal(result[0].source.length, SOURCE_CHECK_INPUT_LIMITS.max_file_bytes)
  assert.equal(result[1].gap.code, 'SOURCE_TOO_LARGE')
  assert.ok(!opened.includes(join(root, 'large.js')))
})

test('aggregate cap refuses excess source before opening and retains explicit gaps', async (t) => {
  const count = SOURCE_CHECK_INPUT_LIMITS.max_total_bytes / SOURCE_CHECK_INPUT_LIMITS.max_file_bytes
  const entries = Object.fromEntries(Array.from({ length: count + 1 }, (_, index) => [`${index}.js`, ' '.repeat(SOURCE_CHECK_INPUT_LIMITS.max_file_bytes)]))
  const root = await fixture(t, entries)
  const opened = []
  const result = await readSourceCheckInputs({ root, files: Object.keys(entries), fileSystem: {
    ...fs, open: async (path, flags) => { opened.push(path); return fs.open(path, flags) },
  } })
  assert.equal(result.filter((item) => Object.hasOwn(item, 'source')).length, count)
  assert.equal(result.at(-1).gap.code, 'SOURCE_TOTAL_LIMIT')
  assert.equal(opened.length, count)
})

test('rejects invalid UTF-8 rather than replacing malformed source bytes', async (t) => {
  const root = await fixture(t, { 'bad.js': Buffer.from([0xc3, 0x28]), 'bom.js': Buffer.from([0xef, 0xbb, 0xbf, 0x31]) })
  const result = await readSourceCheckInputs({ root, files: ['bad.js', 'bom.js'] })
  assert.equal(result[0].gap.code, 'SOURCE_INVALID_UTF8')
  assert.equal(result[1].source.replace(/^\ufeff/, ''), '1')
})

test('refuses hard links without opening their source contents', async (t) => {
  const root = await fixture(t, { 'original.js': 'synthetic-marker' })
  await fs.link(join(root, 'original.js'), join(root, 'alias.js'))
  const result = await readSourceCheckInputs({ root, files: ['alias.js', 'original.js'], fileSystem: {
    ...fs, open: async () => { throw new Error('hard link must not be opened') },
  } })
  assert.ok(result.every((item) => item.gap.code === 'SOURCE_UNREADABLE'))
})

test('refuses linked roots and source parents before opening files', async (t) => {
  const root = await fixture(t, { 'real/a.js': 'synthetic-marker' })
  await fs.symlink(join(root, 'real'), join(root, 'alias'), process.platform === 'win32' ? 'junction' : 'dir')
  const fileSystem = { ...fs, open: async () => { throw new Error('linked input must not be opened') } }
  const result = await readSourceCheckInputs({ root, files: ['alias/a.js'], fileSystem })
  assert.equal(result[0].gap.code, 'SOURCE_UNREADABLE')
  await assert.rejects(readSourceCheckInputs({ root: join(root, 'alias'), files: ['a.js'], fileSystem }), { code: 'SOURCE_CHECK_ROOT_UNREADABLE' })
})

test('refuses a mocked final link and canonical path change without opening', async (t) => {
  const root = await fixture(t, { 'a.js': '1' })
  for (const kind of ['link', 'canonical']) {
    const fileSystem = {
      ...fs,
      lstat: async (path) => {
        const stat = await fs.lstat(path)
        if (path === join(root, 'a.js') && kind === 'link') stat.isSymbolicLink = () => true
        return stat
      },
      realpath: async (path) => path === join(root, 'a.js') && kind === 'canonical' ? join(root, 'different.js') : fs.realpath(path),
      open: async () => { throw new Error('unsafe source must not be opened') },
    }
    const [result] = await readSourceCheckInputs({ root, files: ['a.js'], fileSystem })
    assert.equal(result.gap.code, 'SOURCE_UNREADABLE')
  }
})

test('rejects changes before, during, and after reads and closes every opened handle', async (t) => {
  const root = await fixture(t, { 'a.js': 'const x = 1' })
  for (const change of ['before', 'after', 'endpoint', 'growth']) {
    let closed = 0
    let fileStats = 0
    const fileSystem = {
      ...fs,
      lstat: async (path) => {
        const stat = await fs.lstat(path)
        if (path === join(root, 'a.js')) {
          fileStats += 1
          if (change === 'endpoint' && fileStats > 1) stat.ino = 0
        }
        return stat
      },
      open: async (path, flags) => {
        const handle = await fs.open(path, flags)
        let handleStats = 0
        return {
          stat: async () => {
            const stat = await handle.stat()
            handleStats += 1
            if ((change === 'before' && handleStats === 1) || (change === 'after' && handleStats > 1)) stat.mtimeMs += 1
            return stat
          },
          read: async (buffer, offset, length, position) => {
            const result = await handle.read(buffer, offset, length, position)
            if (change === 'growth' && result.bytesRead === 0) { buffer[offset] = 0x20; return { bytesRead: 1, buffer } }
            return result
          },
          close: async () => { closed += 1; return handle.close() },
        }
      },
    }
    const [result] = await readSourceCheckInputs({ root, files: ['a.js'], fileSystem })
    assert.equal(result.gap?.code, 'SOURCE_UNREADABLE', change)
    assert.equal(closed, 1, change)
  }
})
