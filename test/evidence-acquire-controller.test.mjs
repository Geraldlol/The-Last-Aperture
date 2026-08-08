import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  finalizeAcquisition,
  planAcquisition,
  requestAcquisitionStop,
  runAcquisition,
  validateAcquisition,
} from '../scripts/lib/evidence-acquire-controller.mjs'

const SOURCE = 'test/fixtures/evidence/vulnerable-image.tar'

async function scratch() {
  return join(await mkdtemp(join(tmpdir(), 'rta-acquire-')), 'ev')
}

const request = {
  evidence_id: 'peerstar-api-image',
  source_path: SOURCE,
  target_class: 'LAB',
  phi_scope: 'none',
}

test('plan seals the request and acquires nothing', async () => {
  const out = await scratch()
  const planned = await planAcquisition({ adapterId: 'artifact', request, out })
  const onDisk = JSON.parse(await readFile(join(planned.directory, 'acquisition-plan.json'), 'utf8'))
  assert.equal(onDisk.adapter_id, 'artifact')
  assert.equal(onDisk.state, 'PLANNED')
  assert.match(onDisk.plan.evidence_context_seed.target_identity, /^sha256:/)
  await assert.rejects(() => readFile(join(planned.directory, 'manifest.json')))
})

test('run produces a bundle that validates and finalizes', async () => {
  const out = await scratch()
  await planAcquisition({ adapterId: 'artifact', request, out })
  const written = await runAcquisition({ bundle: out, operatorId: 'gmaida' })
  assert.match(written.root_sha256, /^[0-9a-f]{64}$/)
  assert.equal((await validateAcquisition(out)).valid, true)
  assert.equal((await finalizeAcquisition(out)).state, 'ACQUIRED')
})

test('an unlisted adapter selects inventory-only rather than being invented', async () => {
  const out = await scratch()
  await assert.rejects(
    () => planAcquisition({ adapterId: 'helm-museum', request, out }),
    /inventory-only|unknown adapter/i,
  )
})

test('stop is idempotent and blocks a later run', async () => {
  const out = await scratch()
  await planAcquisition({ adapterId: 'artifact', request, out })
  const first = await requestAcquisitionStop({ bundle: out, operatorId: 'gmaida', reason: 'scope change' })
  const second = await requestAcquisitionStop({ bundle: out, operatorId: 'gmaida', reason: 'scope change' })
  assert.equal(first.state, 'STOPPED')
  assert.equal(second.state, 'STOPPED')
  await assert.rejects(() => runAcquisition({ bundle: out, operatorId: 'gmaida' }), /stopped/i)
})

test('running twice on one plan is refused rather than silently re-acquiring', async () => {
  const out = await scratch()
  await planAcquisition({ adapterId: 'artifact', request, out })
  await runAcquisition({ bundle: out, operatorId: 'gmaida' })
  await assert.rejects(() => runAcquisition({ bundle: out, operatorId: 'gmaida' }), /already/i)
})

test('validate refuses a bundle whose payload was edited after acquisition', async () => {
  const out = await scratch()
  await planAcquisition({ adapterId: 'artifact', request, out })
  await runAcquisition({ bundle: out, operatorId: 'gmaida' })
  await writeFile(join(out, 'payload', 'orphan-blobs.json'), '[]')
  const validation = await validateAcquisition(out)
  assert.equal(validation.valid, false)
  assert.ok(validation.errors.some(({ code }) => code === 'PAYLOAD_DIGEST_MISMATCH'))
})

test('finalize refuses a bundle that does not verify', async () => {
  const out = await scratch()
  await planAcquisition({ adapterId: 'artifact', request, out })
  await runAcquisition({ bundle: out, operatorId: 'gmaida' })
  await writeFile(join(out, 'payload', 'orphan-blobs.json'), '[]')
  await assert.rejects(() => finalizeAcquisition(out), /uncertain provenance/i)
})
