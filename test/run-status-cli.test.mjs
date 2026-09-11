import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtemp, mkdir, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

const CLI = resolve('scripts/audit.mjs')

function cli(...args) {
  return execFileSync(process.execPath, [CLI, ...args], { encoding: 'utf8' })
}

async function filesDigest(directory) {
  const result = {}
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name)
    result[entry.name] = entry.isDirectory()
      ? await filesDigest(path)
      : createHash('sha256').update(await readFile(path)).digest('hex')
  }
  return result
}

test('status CLI reports verified recorded state without writing, reading a removed target, or exposing packets', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'rta-status-cli-'))
  const target = join(workspace, 'target')
  const output = join(workspace, 'output')
  try {
    await mkdir(target)
    await writeFile(join(target, 'app.js'), 'export const fixture = "STATUS_SOURCE_BYTES_MUST_NOT_BE_PRINTED"\n')
    cli('plan', target, '--out', output)
    const dirs = await readdir(output)
    assert.equal(dirs.length, 1)
    const bundle = join(output, dirs[0])
    const before = await filesDigest(bundle)
    const document = JSON.parse(cli('status', bundle, '--json'))
    assert.equal(document.bundle_integrity, 'VERIFIED')
    assert.equal(document.root_authenticity, 'UNANCHORED')
    assert.equal(document.live_repository, 'NOT_CHECKED')
    assert.equal(document.state, 'PLANNED')
    assert.equal(document.phase, 'RECON')
    assert.equal(document.findings.status, 'NO_FINDINGS_REPORTED')
    assert.ok(document.jobs.pending_current_phase.total > 0)
    assert.equal(document.next_step.code, 'INSPECT_PENDING_WORK')
    assert.doesNotMatch(JSON.stringify(document), /STATUS_SOURCE_BYTES_MUST_NOT_BE_PRINTED|packet_sha256|scoped_files/)
    assert.match(cli('status', join(bundle, 'run.json')), /Bundle integrity: VERIFIED; root authenticity: UNANCHORED/)
    assert.deepEqual(await filesDigest(bundle), before)

    // Historical status is usable even after the target is moved elsewhere.
    await rename(target, join(workspace, 'moved-target'))
    const historical = JSON.parse(cli('status', bundle, '--json'))
    assert.equal(historical.target, target)
    assert.equal(historical.jobs.pending_current_phase.total, document.jobs.pending_current_phase.total)
    assert.deepEqual(await filesDigest(bundle), before)

    await writeFile(join(bundle, 'inventory.json'), '{}\n')
    const tampered = spawnSync(process.execPath, [CLI, 'status', bundle, '--json'], { encoding: 'utf8' })
    assert.equal(tampered.status, 1)
    assert.equal(tampered.stdout, '')
    assert.match(tampered.stderr, /artifact|hash|digest|inventory/i)
  } finally {
    await rm(workspace, { recursive: true, force: true })
  }
})

test('status CLI validates arguments before loading a bundle', () => {
  assert.match(cli('help'), /last-aperture status .*\[--json\]/)
  for (const args of [
    ['status'],
    ['status', 'missing', 'extra'],
    ['status', 'missing', '--out', 'somewhere'],
    ['status', 'missing', '--json', '--json'],
  ]) {
    const result = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' })
    assert.equal(result.status, 1)
    assert.doesNotMatch(result.stderr, /ENOENT/)
  }
})
