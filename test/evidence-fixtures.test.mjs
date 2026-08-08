import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { buildEvidenceFixtures } from '../scripts/gen-evidence-fixtures.mjs'
import { DEFAULT_NORMALIZER_LIMITS, normalizeOciLayout } from '../scripts/lib/oci-normalizer.mjs'

const FIXTURE_DIR = 'test/fixtures/evidence'

async function normalized(name) {
  return normalizeOciLayout(
    await readFile(join(FIXTURE_DIR, name)),
    DEFAULT_NORMALIZER_LIMITS,
  )
}

test('the committed fixtures are byte-identical to a fresh build', async () => {
  const out = await mkdtemp(join(tmpdir(), 'rta-fixtures-'))
  const built = await buildEvidenceFixtures(out)
  for (const [name, path] of Object.entries(built)) {
    const fresh = await readFile(path)
    const committed = await readFile(join(FIXTURE_DIR, `${name}-image.tar`))
    assert.ok(fresh.equals(committed), `${name} fixture has drifted from its builder`)
  }
})

test('the fixtures stay small enough to live in the repository', async () => {
  for (const name of ['vulnerable-image.tar', 'clean-image.tar']) {
    const bytes = await readFile(join(FIXTURE_DIR, name))
    assert.ok(bytes.length < 256 * 1024, `${name} is ${bytes.length} bytes; fixtures stay a few KB`)
  }
})

test('pattern 1: a real whiteout sits beside a file merely named like one', async () => {
  const image = await normalized('vulnerable-image.tar')
  const entries = image.layers.flatMap(({ entries: e }) => e)
  const real = entries.find(({ path }) => path.endsWith('.wh.build-secret.txt'))
  const impostor = entries.find(({ path }) => path.endsWith('.wh.audit-log.txt'))
  assert.equal(real.whiteout, true)
  assert.equal(real.mode, 0o600)
  assert.equal(impostor.whiteout, false)
  assert.equal(impostor.mode, 0o664)
  assert.ok(impostor.size > 0)
})

test('pattern 2: an orphan blob is surfaced', async () => {
  const image = await normalized('vulnerable-image.tar')
  assert.equal(image.orphan_blobs.length, 1)
})

test('pattern 3: the sibling outlier is visible in size and mtime', async () => {
  const image = await normalized('vulnerable-image.tar')
  const siblings = image.layers
    .flatMap(({ entries }) => entries)
    .filter(({ path }) => path.startsWith('var/lib/db/sbom/'))
  assert.ok(siblings.length >= 5)
  const sizes = new Set(siblings.map(({ size }) => size))
  const mtimes = new Set(siblings.map(({ mtime }) => mtime))
  assert.equal(sizes.size, 2, 'exactly one sibling deviates in size')
  assert.equal(mtimes.size, 2, 'exactly one sibling deviates in mtime')
})

test('pattern 4: the recursively encoded payload is present as content', async () => {
  const image = await normalized('vulnerable-image.tar')
  const entry = image.layers
    .flatMap(({ entries }) => entries)
    .find(({ path }) => path.endsWith('zsh-5.9r7.spdx.json'))
  assert.ok(entry)
  assert.ok(entry.size > 0)
})

test('pattern 5: the config history carries the planted secret', async () => {
  const image = await normalized('vulnerable-image.tar')
  const history = image.config.history.map(({ created_by: c }) => c).join('\n')
  assert.match(history, /FIXTURE-NOT-A-REAL-SECRET-config-history/)
})

test('the clean image plants nothing and is genuinely clean', async () => {
  const image = await normalized('clean-image.tar')
  const entries = image.layers.flatMap(({ entries: e }) => e)
  assert.equal(entries.some(({ path }) => path.includes('.wh.')), false)
  assert.equal(image.orphan_blobs.length, 0)
  assert.deepEqual(image.gaps, [])
  const siblings = entries.filter(({ path }) => path.startsWith('var/lib/db/sbom/'))
  assert.equal(new Set(siblings.map(({ size }) => size)).size, 1)
  assert.equal(new Set(siblings.map(({ mtime }) => mtime)).size, 1)
  assert.equal(
    image.config.history.some(({ created_by: c }) => /SECRET/i.test(c ?? '')),
    false,
  )
})

test('no fixture contains anything shaped like a real credential', async () => {
  for (const name of ['vulnerable-image.tar', 'clean-image.tar']) {
    const text = (await readFile(join(FIXTURE_DIR, name))).toString('latin1')
    for (const pattern of [/AKIA[0-9A-Z]{16}/, /-----BEGIN [A-Z ]*PRIVATE KEY-----/, /ghp_[A-Za-z0-9]{36}/]) {
      assert.equal(pattern.test(text), false, `${name} must not contain a credential-shaped string`)
    }
  }
})
