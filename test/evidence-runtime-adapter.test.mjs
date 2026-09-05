import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createRuntimeAdapter } from '../scripts/lib/evidence-adapters/runtime.mjs'
import { verifyEvidenceBundle } from '../scripts/lib/evidence-bundle.mjs'
import { readEvidenceIndex } from '../scripts/lib/evidence-packet.mjs'
import { createRunPlan } from '../scripts/lib/run-engine.mjs'
import { runEvidenceAdapterConformance } from './helpers/evidence-adapter-conformance.mjs'
import { stubCli } from './helpers/stub-cli.mjs'

const ENV_KEYS = 'DB_PASSWORD=hunter2\nPATIENT_EXPORT=Rosa Lee\nPATH=/usr/bin\n'

async function kubectlStub(body = ENV_KEYS) {
  return stubCli('kubectl', `
    if (args[0] === 'version') { process.stdout.write('v1.29.4\\n') }
    else { process.stdout.write(${JSON.stringify(body)}) }
  `)
}

async function adapterWithStub(body) {
  const stub = await kubectlStub(body)
  return createRuntimeAdapter({ clock: () => '2026-08-08T14:22:10Z', resolver: stub.resolver })
}

const REQUEST = {
  evidence_id: 'prod-api-pod',
  context: 'peerstar-prod',
  namespace: 'clinical',
  pod: 'api-0',
  container: 'api',
  operations: [{ operation_id: 'runtime.env-keys', params: {} }],
  target_class: 'PRODUCTION',
  acknowledge_production: true,
  phi_scope: 'possible',
  attest_authorized: true,
  operator_id: 'gmaida',
  authorized_by: 'security-lead',
  authorization_reference: 'JIRA-4419',
}

// The shared suite needs a run() that does not demand the per-run confirmation,
// so it exercises the adapter through the same path the controller uses.
const conformanceAdapter = await adapterWithStub()
runEvidenceAdapterConformance(
  {
    ...conformanceAdapter,
    run: (planned, options) =>
      conformanceAdapter.run(planned, { ...options, authorizationConfirmed: true }),
  },
  { validPlanRequest: REQUEST },
)

test('the adapter declares the highest-precedence class', async () => {
  const adapter = await adapterWithStub()
  assert.equal(adapter.describe().evidence_class, 'live-runtime')
})

test('plan binds one named container and refuses a cluster-wide operation', async () => {
  const adapter = await adapterWithStub()
  const planned = await adapter.plan(REQUEST)
  assert.deepEqual(planned.operations[0].args.slice(0, 6), [
    'exec', '-n', 'clinical', 'api-0', '-c', 'api',
  ])
  await assert.rejects(
    () => adapter.plan({
      ...REQUEST,
      operations: [{ operation_id: 'k8s.resources', params: { kind: 'pods', namespace: 'clinical' } }],
    }),
    /runtime\./i,
  )
})

test('plan accepts a THIRD_PARTY read-only operation with an explicit interim acknowledgment', async () => {
  const adapter = await adapterWithStub()
  const planned = await adapter.plan({
    ...REQUEST,
    target_class: 'THIRD_PARTY',
    acknowledge_third_party: true,
  })
  assert.equal(planned.target_class, 'THIRD_PARTY')
  assert.deepEqual(planned.operations[0].args.slice(0, 6), [
    'exec', '-n', 'clinical', 'api-0', '-c', 'api',
  ])
})

test('plan refuses THIRD_PARTY without the explicit interim acknowledgment', async () => {
  const adapter = await adapterWithStub()
  await assert.rejects(
    () => adapter.plan({ ...REQUEST, target_class: 'THIRD_PARTY' }),
    /THIRD_PARTY|acknowledge-third-party/i,
  )
})

test('run refuses without a current authorization confirmation', async () => {
  const adapter = await adapterWithStub()
  const out = join(await mkdtemp(join(tmpdir(), 'rta-runtime-')), 'ev')
  const planned = await adapter.plan(REQUEST)
  await assert.rejects(
    () => adapter.run(planned, { out }),
    /confirm-authorization-current|authorization/i,
  )
})

test('run rejects truthy non-boolean authorization confirmations', async () => {
  const adapter = await adapterWithStub()
  const planned = await adapter.plan(REQUEST)
  for (const authorizationConfirmed of ['yes', {}]) {
    const out = join(await mkdtemp(join(tmpdir(), 'rta-runtime-')), 'ev')
    await assert.rejects(
      () => adapter.run(planned, { out, authorizationConfirmed }),
      /confirm-authorization-current|authorization/i,
    )
  }
})

test('run with a current confirmation produces a verifiable bundle', async () => {
  const adapter = await adapterWithStub()
  const out = join(await mkdtemp(join(tmpdir(), 'rta-runtime-')), 'ev')
  const written = await adapter.run(
    await adapter.plan(REQUEST),
    { out, authorizationConfirmed: true },
  )
  assert.deepEqual((await verifyEvidenceBundle(written.directory)).errors, [])
  assert.equal(written.profile.evidence_context.evidence_class, 'live-runtime')
  assert.equal(written.profile.coverage_state, 'COVERED')
  const index = await readEvidenceIndex(written.directory)
  assert.equal(index.locator_index_kind, 'unsupported')
  assert.match(index.unsupported_reason, /provider evidence-byte delivery/i)
})

test('a real runtime bundle remains an explicit audit gap until bytes are delivered', async () => {
  const adapter = await adapterWithStub()
  const out = join(await mkdtemp(join(tmpdir(), 'rta-runtime-plan-')), 'ev')
  const written = await adapter.run(
    await adapter.plan(REQUEST),
    { out, authorizationConfirmed: true },
  )
  const repository = await mkdtemp(join(tmpdir(), 'rta-runtime-repo-'))
  await writeFile(
    join(repository, 'server.js'),
    "import express from 'express'\nexpress().listen(3000)\n",
    'utf8',
  )
  const plan = await createRunPlan({
    targetRoot: repository,
    evidenceBundles: [{
      evidence_id: written.profile.evidence_context.evidence_id,
      evidence_class: written.profile.evidence_context.evidence_class,
      adapter_id: written.profile.evidence_context.adapter_id,
      evidence_context: written.profile.evidence_context,
      coverage_state: written.profile.coverage_state,
      phi_bearing: written.profile.phi_bearing,
      root_sha256: written.root_sha256,
      directory: written.directory,
    }],
  })
  const cells = plan.run.evidence_coverage.cells.filter(
    ({ lens, evidence_class: evidenceClass }) =>
      lens === 'web-and-api' && evidenceClass === 'live-runtime',
  )
  assert.ok(cells.length > 0)
  assert.ok(cells.every(({ state }) => state === 'NOT_ASSESSED'))
  const sidecarEvidence = plan.jobSidecars
    .flatMap(({ evidence = [] }) => evidence)
    .find(({ evidence_context: context }) => context.evidence_id === 'prod-api-pod')
  assert.equal(sidecarEvidence.locator_index_kind, 'unsupported')
})

test('metadata-only drops every value even when the command returned them', async () => {
  const adapter = await adapterWithStub()
  const out = join(await mkdtemp(join(tmpdir(), 'rta-runtime-')), 'ev')
  const written = await adapter.run(
    await adapter.plan(REQUEST),
    { out, authorizationConfirmed: true },
  )
  const text = (await readFile(
    join(written.directory, 'payload', 'observations', '00.txt'),
  )).toString('utf8')
  assert.match(text, /PATIENT_EXPORT/)
  assert.equal(text.includes('Rosa Lee'), false)
  assert.equal(text.includes('hunter2'), false)
})

test('a read that fails inside the container is a named gap', async () => {
  const stub = await stubCli('kubectl', `
    if (args[0] === 'version') { process.stdout.write('v1.29.4\\n') }
    else {
      process.stderr.write('cat: /etc/shadow: Permission denied\\n')
      process.exit(1)
    }
  `)
  const adapter = createRuntimeAdapter({ clock: () => '2026-08-08T14:22:10Z', resolver: stub.resolver })
  const out = join(await mkdtemp(join(tmpdir(), 'rta-runtime-')), 'ev')
  const written = await adapter.run(
    await adapter.plan({
      ...REQUEST,
      operations: [{ operation_id: 'runtime.read-file', params: { path: '/etc/shadow' } }],
    }),
    { out, authorizationConfirmed: true },
  )
  assert.equal(written.profile.coverage_state, 'NOT_ASSESSED')
  assert.ok(written.profile.coverage_gaps.some(({ reason }) => /Permission denied/.test(reason)))
})

test('phi_scope confirmed without acknowledgment cannot capture contents', async () => {
  const adapter = await adapterWithStub()
  await assert.rejects(
    () => adapter.plan({ ...REQUEST, phi_scope: 'confirmed', capture_contents: true }),
    /acknowledg/i,
  )
})

test('a phi_bearing acquisition marks the bundle', async () => {
  const adapter = await adapterWithStub()
  const out = join(await mkdtemp(join(tmpdir(), 'rta-runtime-')), 'ev')
  const written = await adapter.run(
    await adapter.plan({
      ...REQUEST,
      phi_scope: 'confirmed',
      capture_contents: true,
      acknowledge_phi: true,
    }),
    { out, authorizationConfirmed: true },
  )
  assert.equal(written.profile.phi_bearing, true)
  assert.equal(written.profile.phi_scope, 'confirmed')
})
