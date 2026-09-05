import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { parseSourceCheckArguments, inspectSourcePatterns, sourceCheckExitCode } from '../scripts/source-check.mjs'

test('source-check requires explicit scope and rejects ambiguous CLI options', () => {
  const root = resolve('.')
  assert.deepEqual(parseSourceCheckArguments(['--root', root, '--file', 'a.js', '--file', 'b.mjs', '--json']), {
    root, files: ['a.js', 'b.mjs'], json: true,
  })
  for (const args of [[], ['--root', root], ['--file', 'a.js'], ['--root', '.','--file', 'a.js'],
    ['--root', root, '--file', 'a.js', '--execute'], ['--root', root, '--root', root, '--file', 'a.js'],
    ['--root', root, '--file', 'a.js', '--json', '--json'], ['--root', '\\\\server\\share', '--file', 'a.js']]) {
    assert.throws(() => parseSourceCheckArguments(args))
  }
})

test('passive checker reports scope, limited observations and unread coverage without executing source', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-source-cli-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const source = 'throw new Error("SOURCE_MUST_NOT_EXECUTE");\nprocess.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";\n'
  await writeFile(join(root, 'app.js'), source)
  await writeFile(join(root, 'clean.js'), 'export const greeting = "hello";\n')
  await writeFile(join(root, 'app.ts'), 'UNREAD_TYPESCRIPT_MARKER')
  const before = await readdir(root)
  const report = await inspectSourcePatterns({ root, files: ['clean.js', 'app.ts', 'app.js'] })
  assert.equal(report.kind, 'red-team-audit/source-check')
  assert.equal(report.security_verdict, 'NOT_ASSESSED')
  assert.equal(report.target_execution, 'NOT_PERFORMED')
  assert.deepEqual(report.files.map((file) => file.path), ['app.js', 'app.ts', 'clean.js'])
  assert.equal(report.counts.requested_files, 3)
  assert.equal(report.counts.checked_files, 2)
  assert.equal(report.counts.not_assessed_files, 1)
  assert.equal(report.counts.observations, 1)
  assert.equal(sourceCheckExitCode(report), 3)
  assert.equal(report.files[0].observations[0].verification, 'UNPROVEN')
  assert.ok(report.files[0].observations[0].repair.acceptance_checks.length > 0)
  assert.doesNotMatch(JSON.stringify(report), /SOURCE_MUST_NOT_EXECUTE|UNREAD_TYPESCRIPT_MARKER/)
  assert.equal(JSON.stringify(report).includes(root), false)
  assert.deepEqual(await readdir(root), before)
  assert.equal(await readFile(join(root, 'app.js'), 'utf8'), source)

  const child = spawnSync(process.execPath, ['scripts/source-check.mjs', '--root', root, '--file', 'app.js', '--json'], {
    encoding: 'utf8', timeout: 10_000,
  })
  assert.equal(child.status, 2, child.stderr)
  assert.equal(JSON.parse(child.stdout).counts.observations, 1)
  assert.equal(child.stderr, '')
})

test('CLI exit codes distinguish observations, coverage gaps, and a completed narrow check', () => {
  assert.equal(sourceCheckExitCode({ counts: { observations: 0, gaps: 0 } }), 0)
  assert.equal(sourceCheckExitCode({ counts: { observations: 1, gaps: 0 } }), 2)
  assert.equal(sourceCheckExitCode({ counts: { observations: 0, gaps: 1 } }), 3)
})

test('Unicode source paths and a UTF-8 BOM preserve input identity through the complete checker', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rta-source-unicode-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const path = 'caf\u00e9.js'
  const bytes = Buffer.from('\ufeffexport const greeting = "hello";\n', 'utf8')
  await writeFile(join(root, path), bytes)
  const report = await inspectSourcePatterns({ root, files: [path] })
  assert.equal(report.files[0].path, path)
  assert.equal(report.files[0].status, 'CHECKED')
  assert.equal(report.files[0].source_sha256, createHash('sha256').update(bytes).digest('hex'))
})

test('source-check errors never echo rejected arguments or parser input', () => {
  const child = spawnSync(process.execPath, ['scripts/source-check.mjs', '--SECRET_ARGUMENT_MUST_NOT_ECHO'], {
    encoding: 'utf8', timeout: 10_000,
  })
  assert.equal(child.status, 1)
  assert.equal(child.stdout, '')
  assert.doesNotMatch(child.stderr, /SECRET_ARGUMENT_MUST_NOT_ECHO| at /)
  assert.match(child.stderr, /ERROR: source-check/)
})
