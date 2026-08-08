import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { createRegistryAdapter } from '../scripts/lib/evidence-adapters/registry.mjs'
import { verifyEvidenceBundle } from '../scripts/lib/evidence-bundle.mjs'
import { runEvidenceAdapterConformance } from './helpers/evidence-adapter-conformance.mjs'
import { absentCliResolver, stubCli } from './helpers/stub-cli.mjs'

const DIGEST = 'sha256:9f2c1d0e4b6a8c3f5e7d9b1a3c5e7f9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c'
const REFERENCE = `registry.example.com/peerstar/api@${DIGEST}`
const FIXTURE = resolve('test/fixtures/evidence/vulnerable-image.tar').replaceAll('\\', '\\\\')

// The stub copies the committed fixture to wherever crane was told to write.
// Every registry test runs against these bytes; none touches a network.
async function craneStub() {
  return stubCli('crane', `
    if (args[0] === 'version') { process.stdout.write('0.19.1\\n') }
    else {
      const { copyFileSync } = await import('node:fs')
      copyFileSync('${FIXTURE}', args[args.length - 1])
    }
  `)
}

async function adapterWithStub() {
  const stub = await craneStub()
  return createRegistryAdapter({ clock: () => '2026-08-08T14:22:10Z', resolver: stub.resolver })
}

const REQUEST = {
  evidence_id: 'peerstar-api-image',
  image: REFERENCE,
  credential_ref: 'env:REGISTRY_TOKEN',
  target_class: 'NONPROD',
  phi_scope: 'none',
  attest_authorized: true,
  operator_id: 'gmaida',
  authorized_by: 'platform-lead',
  authorization_reference: 'JIRA-4417',
}

// The shared suite, unmodified, against the second real adapter.
runEvidenceAdapterConformance(await adapterWithStub(), { validPlanRequest: REQUEST })

test('plan pins the digest and never contacts the registry', async () => {
  const adapter = await adapterWithStub()
  const planned = await adapter.plan(REQUEST)
  assert.equal(planned.evidence_context_seed.target_identity, DIGEST)
  assert.equal(planned.evidence_context_seed.acquisition_mode, 'registry-pull')
  assert.equal(planned.image_reference, REFERENCE)
  assert.equal(planned.dependency.present, true)
})

test('plan refuses an unpinned reference', async () => {
  const adapter = await adapterWithStub()
  await assert.rejects(
    () => adapter.plan({ ...REQUEST, image: 'registry.example.com/peerstar/api:latest' }),
    /digest|pinned/i,
  )
})

test('plan refuses without attestation, because built-artifact via registry requires it', async () => {
  const adapter = await adapterWithStub()
  await assert.rejects(() => adapter.plan({ ...REQUEST, attest_authorized: false }), /attest/i)
})

test('plan fails when crane is absent rather than succeeding emptily', async () => {
  const adapter = createRegistryAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    resolver: absentCliResolver,
  })
  await assert.rejects(() => adapter.plan(REQUEST), /crane|not found|absent/i)
})

test('the sealed plan carries a credential reference and no credential value', async () => {
  const adapter = await adapterWithStub()
  const planned = await adapter.plan(REQUEST)
  assert.equal(planned.credential_ref, 'env:REGISTRY_TOKEN')
  assert.equal(JSON.stringify(planned).includes('REGISTRY_TOKEN='), false)
  await assert.rejects(
    () => adapter.plan({ ...REQUEST, credential_ref: 'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }),
    /credential value/i,
  )
})

test('run pulls once and produces a verifiable built-artifact bundle', async () => {
  const adapter = await adapterWithStub()
  const out = join(await mkdtemp(join(tmpdir(), 'rta-registry-')), 'ev')
  const written = await adapter.run(await adapter.plan(REQUEST), { out })
  assert.deepEqual((await verifyEvidenceBundle(written.directory)).errors, [])
  assert.equal(written.profile.evidence_context.evidence_class, 'built-artifact')
  assert.equal(written.profile.artifact_kind, 'oci-image')
  assert.equal(written.profile.coverage_state, 'COVERED')
  assert.equal(written.profile.attestation.operator_id, 'gmaida')
  assert.equal(written.profile.attestation.credential_ref, 'env:REGISTRY_TOKEN')
  assert.equal(written.profile.evidence_context.target_identity, DIGEST)
})

test('a pull that fails authentication is NOT_ASSESSED with a redacted reason', async () => {
  const stub = await stubCli('crane', `
    if (args[0] === 'version') { process.stdout.write('0.19.1\\n') }
    else {
      process.stderr.write('UNAUTHORIZED for https://ci:hunter2@registry.example.com\\n')
      process.exit(1)
    }
  `)
  const adapter = createRegistryAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    resolver: stub.resolver,
  })
  const out = join(await mkdtemp(join(tmpdir(), 'rta-registry-')), 'ev')
  const written = await adapter.run(await adapter.plan(REQUEST), { out })
  assert.equal(written.profile.coverage_state, 'NOT_ASSESSED')
  assert.equal(written.profile.files.length, 0)
  const reason = written.profile.coverage_gaps[0].reason
  assert.match(reason, /UNAUTHORIZED/)
  assert.equal(reason.includes('hunter2'), false)
})

test('impact counters are recorded on the bundle', async () => {
  const adapter = await adapterWithStub()
  const out = join(await mkdtemp(join(tmpdir(), 'rta-registry-')), 'ev')
  const written = await adapter.run(await adapter.plan(REQUEST), { out })
  const counters = JSON.parse(
    (await readFile(join(written.directory, 'payload', 'impact-counters.json'))).toString('utf8'),
  )
  assert.equal(counters.commands, 1)
  assert.ok(counters.bytes_read > 0)
})
