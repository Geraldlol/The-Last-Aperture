import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createArtifactAdapter } from '../scripts/lib/evidence-adapters/artifact.mjs'
import {
  parseEvidenceLocation,
  resolveEvidenceLocator,
  verifyEvidenceExistence,
} from '../scripts/lib/evidence-locator.mjs'

const adapter = createArtifactAdapter({ clock: () => '2026-08-08T14:22:10Z' })

async function bundle() {
  const out = join(await mkdtemp(join(tmpdir(), 'rta-locator-')), 'ev')
  const planned = await adapter.plan({
    evidence_id: 'peerstar-api-image',
    source_path: 'test/fixtures/evidence/vulnerable-image.tar',
    target_class: 'LAB',
    phi_scope: 'none',
  })
  const written = await adapter.run(planned, { out })
  return { directory: written.directory, id: 'peerstar-api-image' }
}

test('the two location forms are told apart without guessing', () => {
  assert.deepEqual(parseEvidenceLocation('peerstar-api-image:layer/00/build-secret.txt'), {
    evidence_id: 'peerstar-api-image',
    locator: 'layer/00/build-secret.txt',
  })
  assert.equal(parseEvidenceLocation('src/routes/invoices.ts:88'), null)
  assert.equal(parseEvidenceLocation('peerstar-api-image:88'), null)
})

test('a layer entry locator resolves to its bytes', async () => {
  const b = await bundle()
  const resolved = await resolveEvidenceLocator(b.directory, 'layer/00/build-secret.txt')
  assert.equal(resolved.kind, 'entry')
  assert.match(resolved.bytes.toString('utf8'), /FIXTURE-NOT-A-REAL-SECRET-layer-below-whiteout/)
})

test('a config history locator resolves to one element', async () => {
  const b = await bundle()
  const resolved = await resolveEvidenceLocator(b.directory, 'config/history[1]')
  assert.equal(resolved.kind, 'history')
  assert.match(resolved.bytes.toString('utf8'), /FIXTURE-NOT-A-REAL-SECRET-config-history/)
})

test('an orphan blob locator resolves to its record', async () => {
  const b = await bundle()
  const orphans = JSON.parse(
    (await resolveEvidenceLocator(b.directory, 'config/history[0]')).bytes.toString('utf8'),
  )
  assert.ok(orphans)
})

test('an unresolvable locator resolves to nothing rather than throwing', async () => {
  const b = await bundle()
  const resolved = await resolveEvidenceLocator(b.directory, 'layer/00/no-such-file')
  assert.equal(resolved.bytes, null)
  const outOfRange = await resolveEvidenceLocator(b.directory, 'config/history[99]')
  assert.equal(outOfRange.bytes, null)
})

test('an unrecognised locator form is fail-closed, not best-effort', async () => {
  const b = await bundle()
  const resolved = await resolveEvidenceLocator(b.directory, 'somewhere/in/the/image')
  assert.equal(resolved.kind, 'unknown')
  assert.equal(resolved.bytes, null)
})

test('located: the quoted evidence is present at the locator', async () => {
  const b = await bundle()
  const result = await verifyEvidenceExistence(
    {
      location: ['peerstar-api-image:layer/00/build-secret.txt'],
      evidence: 'FIXTURE-NOT-A-REAL-SECRET-layer-below-whiteout',
      evidence_context: { evidence_id: 'peerstar-api-image' },
    },
    new Map([[b.id, b.directory]]),
  )
  assert.equal(result.status, 'located')
  assert.match(result.method, /layer\/00\/build-secret\.txt/)
})

test('not_located: the bundle is absent from the run', async () => {
  const result = await verifyEvidenceExistence(
    {
      location: ['peerstar-api-image:layer/00/build-secret.txt'],
      evidence: 'anything',
      evidence_context: { evidence_id: 'peerstar-api-image' },
    },
    new Map(),
  )
  assert.equal(result.status, 'not_located')
  assert.match(result.method, /not present in this run/)
})

test('not_located: the locator does not resolve inside the bundle', async () => {
  const b = await bundle()
  const result = await verifyEvidenceExistence(
    {
      location: ['peerstar-api-image:layer/00/imaginary.txt'],
      evidence: 'anything',
      evidence_context: { evidence_id: 'peerstar-api-image' },
    },
    new Map([[b.id, b.directory]]),
  )
  assert.equal(result.status, 'not_located')
})

test('located with a contradicting observation: the premise is falsified', async () => {
  const b = await bundle()
  const result = await verifyEvidenceExistence(
    {
      location: ['peerstar-api-image:layer/00/build-secret.txt'],
      evidence: 'AKIA_SOMETHING_THAT_IS_NOT_THERE',
      evidence_context: { evidence_id: 'peerstar-api-image' },
    },
    new Map([[b.id, b.directory]]),
  )
  assert.equal(result.status, 'located')
  assert.ok(result.observed.length > 0)
  assert.equal(result.observed.includes('AKIA_SOMETHING_THAT_IS_NOT_THERE'), false)
})
