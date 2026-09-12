import { test } from 'node:test'
import assert from 'node:assert/strict'
import { access, mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createDeployedAdapter } from '../scripts/lib/evidence-adapters/deployed.mjs'
import { verifyEvidenceBundle } from '../scripts/lib/evidence-bundle.mjs'
import { readEvidenceIndex } from '../scripts/lib/evidence-packet.mjs'
import { createRunPlan } from '../scripts/lib/run-engine.mjs'
import { runEvidenceAdapterConformance } from './helpers/evidence-adapter-conformance.mjs'
import { absentCliResolver, stubCli } from './helpers/stub-cli.mjs'

const SECRET_JSON = JSON.stringify({
  apiVersion: 'v1',
  kind: 'List',
  items: [{
    apiVersion: 'v1',
    kind: 'Secret',
    metadata: { name: 'patient-db', namespace: 'clinical' },
    data: { DB_PASSWORD: 'aHVudGVyMg==', PATIENT_EXPORT: 'TXJzIFJvc2EgTGVl' },
  }],
})

async function kubectlStub(body = SECRET_JSON) {
  return stubCli('kubectl', `
    if (args[0] === 'version') { process.stdout.write('v1.29.4\\n') }
    else { process.stdout.write(${JSON.stringify(body)}) }
  `)
}

async function adapterWithStub(body) {
  const stub = await kubectlStub(body)
  return createDeployedAdapter({ clock: () => '2026-08-08T14:22:10Z', resolver: stub.resolver })
}

const REQUEST = {
  evidence_id: 'prod-cluster',
  context: 'reference-production',
  operations: [{ operation_id: 'k8s.resources', params: { kind: 'secrets', namespace: 'clinical' } }],
  target_class: 'PRODUCTION',
  acknowledge_production: true,
  phi_scope: 'possible',
  attest_authorized: true,
  operator_id: 'gmaida',
  authorized_by: 'security-lead',
  authorization_reference: 'JIRA-4418',
}

runEvidenceAdapterConformance(await adapterWithStub(), { validPlanRequest: REQUEST })

test('invalid object limits fail before any executable resolver is consulted', () => {
  let resolverCalls = 0
  assert.throws(
    () => createDeployedAdapter({
      limits: { maxObjects: Number.NaN },
      resolver: () => {
        resolverCalls += 1
        throw new Error('must not resolve')
      },
    }),
    /maxObjects.*non-negative safe integer/i,
  )
  assert.equal(resolverCalls, 0)
})

test('Salesforce query records are individually counted and captured', async () => {
  const stub = await stubCli('sf', `
    if (args[0] === 'version') process.stdout.write('@salesforce/cli/2.100.0 win32-x64 node-v24\\n')
    else process.stdout.write(JSON.stringify({ status: 0, result: { records: [
      { attributes: { type: 'Account' }, Id: '001A' },
      { attributes: { type: 'Account' }, Id: '001B' },
    ] } }))
  `)
  const adapter = createDeployedAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    resolver: stub.resolver,
    limits: { maxObjects: 64 },
  })
  const planned = await adapter.plan({
    ...REQUEST,
    target_class: 'LAB',
    acknowledge_production: false,
    phi_scope: 'none',
    operations: [{
      operation_id: 'sf.query',
      params: { alias: 'sandbox', soql: 'SELECT Id FROM Account' },
    }],
  })
  const out = join(await mkdtemp(join(tmpdir(), 'rta-deployed-sf-records-')), 'ev')
  const written = await adapter.run(planned, { out })
  assert.equal(written.profile.coverage_state, 'COVERED')
  const counters = JSON.parse(await readFile(join(out, 'payload', 'impact-counters.json'), 'utf8'))
  assert.equal(counters.objects_touched, 2)
  const operations = JSON.parse(await readFile(join(out, 'payload', 'operations.json'), 'utf8'))
  assert.equal(operations[0].objects, 2)
  assert.equal((await readFile(join(out, 'payload', 'objects', '00', '1.json'), 'utf8')).includes('001B'), true)
})

test('plan seals the operation list and probes kubectl without running anything', async () => {
  const adapter = await adapterWithStub()
  const planned = await adapter.plan(REQUEST)
  assert.equal(planned.evidence_context_seed.evidence_class, 'deployed-state')
  assert.equal(planned.evidence_context_seed.acquisition_mode, 'read-only-query')
  assert.equal(planned.operations.length, 1)
  assert.deepEqual(planned.operations[0].args, ['get', 'secrets', '-n', 'clinical', '-o', 'json'])
  assert.equal(planned.dependency.present, true)
})

test('plan refuses an operation outside the allowlist', async () => {
  const adapter = await adapterWithStub()
  await assert.rejects(
    () => adapter.plan({
      ...REQUEST,
      operations: [{ operation_id: 'k8s.delete', params: { kind: 'ns' } }],
    }),
    /not allowlisted/i,
  )
})

test('plan refuses PRODUCTION without an explicit acknowledgment', async () => {
  const adapter = await adapterWithStub()
  await assert.rejects(
    () => adapter.plan({ ...REQUEST, acknowledge_production: false }),
    /PRODUCTION|acknowledg/i,
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
  assert.deepEqual(planned.authorization_gate, {
    mode: 'INTERIM_OPERATOR_ACKNOWLEDGED_THIRD_PARTY',
    attest_authorized: true,
    acknowledge_production: true,
    acknowledge_third_party: true,
  })
  assert.deepEqual(planned.operations[0].args, [
    'get', 'secrets', '-n', 'clinical', '-o', 'json',
  ])
})

test('plan refuses THIRD_PARTY without the explicit interim acknowledgment', async () => {
  const adapter = await adapterWithStub()
  await assert.rejects(
    () => adapter.plan({ ...REQUEST, target_class: 'THIRD_PARTY' }),
    /THIRD_PARTY|acknowledge-third-party/i,
  )
})

test('arbitrary signed_authorization truthiness cannot replace the interim acknowledgment', async () => {
  const adapter = await adapterWithStub()
  await assert.rejects(
    () => adapter.plan({
      ...REQUEST,
      target_class: 'THIRD_PARTY',
      signed_authorization: {},
    }),
    /THIRD_PARTY|acknowledge-third-party/i,
  )
})

test('run revalidates the sealed THIRD_PARTY acknowledgment after plan tampering', async () => {
  const adapter = await adapterWithStub()
  const planned = await adapter.plan(REQUEST)
  planned.target_class = 'THIRD_PARTY'
  const out = join(await mkdtemp(join(tmpdir(), 'rta-deployed-')), 'ev')
  await assert.rejects(
    () => adapter.run(planned, { out }),
    /sealed THIRD_PARTY acknowledgment/i,
  )
})

test('plan refuses without attestation, because deployed-state floors it', async () => {
  const adapter = await adapterWithStub()
  await assert.rejects(() => adapter.plan({ ...REQUEST, attest_authorized: false }), /attest/i)
})

test('an absent kubectl fails at plan time rather than succeeding emptily', async () => {
  const adapter = createDeployedAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    resolver: absentCliResolver,
  })
  await assert.rejects(() => adapter.plan(REQUEST), /kubectl|absent|not found/i)
})

test('run acquires the objects and the bundle verifies', async () => {
  const adapter = await adapterWithStub()
  const out = join(await mkdtemp(join(tmpdir(), 'rta-deployed-')), 'ev')
  const written = await adapter.run(await adapter.plan(REQUEST), { out })
  assert.deepEqual((await verifyEvidenceBundle(written.directory)).errors, [])
  assert.equal(written.profile.evidence_context.evidence_class, 'deployed-state')
  assert.equal(written.profile.coverage_state, 'COVERED')
  assert.equal(Object.hasOwn(written.profile, 'artifact_kind'), false)
  const index = await readEvidenceIndex(written.directory)
  assert.equal(index.locator_index_kind, 'unsupported')
  assert.match(index.unsupported_reason, /provider evidence-byte delivery/i)
})

test('a real deployed bundle remains an explicit audit gap until bytes are delivered', async () => {
  const adapter = await adapterWithStub()
  const out = join(await mkdtemp(join(tmpdir(), 'rta-deployed-plan-')), 'ev')
  const written = await adapter.run(await adapter.plan(REQUEST), { out })
  const repository = await mkdtemp(join(tmpdir(), 'rta-deployed-repo-'))
  await writeFile(join(repository, 'Dockerfile'), 'FROM node:20-alpine\n', 'utf8')
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
      lens === 'cloud-and-iac' && evidenceClass === 'deployed-state',
  )
  assert.ok(cells.length > 0)
  assert.ok(cells.every(({ state }) => state === 'NOT_ASSESSED'))
  const sidecarEvidence = plan.jobSidecars
    .flatMap(({ evidence = [] }) => evidence)
    .find(({ evidence_context: context }) => context.evidence_id === 'prod-cluster')
  assert.equal(sidecarEvidence.locator_index_kind, 'unsupported')
})

test('phi_scope possible captures key names and shapes but no values', async () => {
  const adapter = await adapterWithStub()
  const out = join(await mkdtemp(join(tmpdir(), 'rta-deployed-')), 'ev')
  const written = await adapter.run(await adapter.plan(REQUEST), { out })
  assert.equal(written.profile.phi_bearing, false)

  const bytes = await readFile(join(written.directory, 'payload', 'objects', '00', '0.json'))
  const text = bytes.toString('utf8')
  assert.match(text, /PATIENT_EXPORT/)
  assert.equal(text.includes('TXJzIFJvc2EgTGVl'), false)
  assert.equal(text.includes('aHVudGVyMg=='), false)
})

test('phi_scope none captures contents in full and marks nothing', async () => {
  const adapter = await adapterWithStub()
  const out = join(await mkdtemp(join(tmpdir(), 'rta-deployed-')), 'ev')
  const written = await adapter.run(
    await adapter.plan({ ...REQUEST, phi_scope: 'none' }),
    { out },
  )
  const text = (await readFile(
    join(written.directory, 'payload', 'objects', '00', '0.json'),
  )).toString('utf8')
  assert.match(text, /TXJzIFJvc2EgTGVl/)
  assert.equal(written.profile.phi_bearing, false)
})

test('unparsed output is PARTIAL with the unparsed portion named', async () => {
  const adapter = await adapterWithStub('not json at all')
  const out = join(await mkdtemp(join(tmpdir(), 'rta-deployed-')), 'ev')
  const written = await adapter.run(await adapter.plan(REQUEST), { out })
  assert.equal(written.profile.coverage_state, 'NOT_ASSESSED')
  assert.ok(written.profile.coverage_gaps.some(({ reason }) => /pars/i.test(reason)))
})

test('impact counters halt acquisition when a cap is exceeded', async () => {
  const stub = await kubectlStub()
  const adapter = createDeployedAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    resolver: stub.resolver,
    limits: { maxCommands: 1, maxObjects: 1 },
  })
  const out = join(await mkdtemp(join(tmpdir(), 'rta-deployed-')), 'ev')
  const planned = await adapter.plan({
    ...REQUEST,
    operations: [
      { operation_id: 'k8s.resource', params: { kind: 'secrets', name: 'a', namespace: 'clinical' } },
      { operation_id: 'k8s.resource', params: { kind: 'secrets', name: 'b', namespace: 'clinical' } },
    ],
  })
  const written = await adapter.run(planned, { out })
  assert.equal(written.profile.coverage_state, 'PARTIAL')
  assert.ok(written.profile.coverage_gaps.some(({ reason }) => /cap/i.test(reason)))
})

test('collection object caps use the observed item count, not the allowlist estimate', async () => {
  const body = JSON.stringify({
    apiVersion: 'v1',
    kind: 'List',
    items: Array.from({ length: 65 }, (_unused, index) => ({
      apiVersion: 'v1',
      kind: 'Pod',
      metadata: { name: `synthetic-${index}`, namespace: 'clinical' },
    })),
  })
  const stub = await kubectlStub(body)
  const adapter = createDeployedAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    resolver: stub.resolver,
    limits: { maxObjects: 64 },
  })
  const out = join(await mkdtemp(join(tmpdir(), 'rta-deployed-')), 'ev')
  const planned = await adapter.plan({
    ...REQUEST,
    operations: [{ operation_id: 'k8s.resources', params: { kind: 'pods', namespace: 'clinical' } }],
  })
  const written = await adapter.run(planned, { out })
  assert.equal(written.profile.coverage_state, 'NOT_ASSESSED')
  assert.ok(written.profile.coverage_gaps.some(({ reason }) => /object|cap/i.test(reason)))
})

test('a collection producer is terminated at cap plus one before it completes its response', async () => {
  const root = await mkdtemp(join(tmpdir(), 'rta-deployed-stream-cap-'))
  const completed = join(root, 'completed.txt')
  const stub = await stubCli('kubectl', `
    if (args[0] === 'version') process.stdout.write('v1.29.4\\n')
    else if (args.includes('first')) {
      process.stdout.write(JSON.stringify({ apiVersion: 'v1', kind: 'Pod', metadata: { name: 'first' } }))
    }
    else {
      process.stdout.write('{"items":[')
      for (let index = 0; index < 70; index += 1) {
        if (index > 0) process.stdout.write(',')
        process.stdout.write(JSON.stringify({ metadata: { name: 'item-' + index } }))
        await new Promise((resolve) => setTimeout(resolve, 3))
      }
      process.stdout.write(']}')
      ;(await import('node:fs')).writeFileSync(${JSON.stringify(completed)}, 'complete')
    }
  `)
  const adapter = createDeployedAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    resolver: stub.resolver,
    limits: { maxObjects: 65 },
  })
  const out = join(root, 'ev')
  const planned = await adapter.plan({
    ...REQUEST,
    operations: [
      { operation_id: 'k8s.resource', params: { kind: 'pods', name: 'first', namespace: 'clinical' } },
      { operation_id: 'k8s.resources', params: { kind: 'pods', namespace: 'clinical' } },
    ],
  })
  const written = await adapter.run(planned, { out })
  assert.equal(written.profile.coverage_state, 'PARTIAL')
  assert.ok(written.profile.coverage_gaps.some(({ reason }) => /objects_touched|object.*cap/i.test(reason)))
  const counters = JSON.parse(await readFile(join(out, 'payload', 'impact-counters.json'), 'utf8'))
  assert.equal(counters.objects_touched, 66)
  const operations = JSON.parse(await readFile(join(out, 'payload', 'operations.json'), 'utf8'))
  assert.equal(operations.length, 2)
  assert.equal(operations[0].operation_id, 'k8s.resource')
  assert.equal(operations[0].exit_code, 0)
  assert.equal(operations[0].objects, 1)
  assert.equal(operations[1].operation_id, 'k8s.resources')
  assert.equal(operations[1].exit_code, null)
  assert.equal(operations[1].failure_code, 'IMPACT_CAP_EXCEEDED')
  assert.equal(operations[1].outcome, 'IMPACT_CAP_EXCEEDED')
  assert.equal(typeof operations[1].termination_confirmed, 'boolean')
  assert.equal(operations[1].objects, 65)
  assert.equal(operations[1].impact_dimension, 'objects_touched')
  assert.equal(operations[1].operation_cap, 64)
  assert.equal(operations[1].observed_value, 65)
  await assert.rejects(() => access(completed))
})

test('a stop request halts the loop before the next operation', async () => {
  const stub = await kubectlStub()
  const adapter = createDeployedAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    resolver: stub.resolver,
  })
  const out = join(await mkdtemp(join(tmpdir(), 'rta-deployed-')), 'ev')
  const planned = await adapter.plan({
    ...REQUEST,
    operations: Array.from({ length: 4 }, (_unused, index) => ({
      operation_id: 'k8s.resource',
      params: { kind: 'secrets', name: `s${index}`, namespace: 'clinical' },
    })),
  })
  let calls = 0
  const written = await adapter.run(planned, {
    out,
    shouldStop: () => {
      calls += 1
      return calls > 2
    },
  })
  assert.equal(written.profile.coverage_state, 'PARTIAL')
  assert.ok(written.profile.coverage_gaps.some(({ reason }) => /stopped by the operator/i.test(reason)))
  const executed = JSON.parse(
    (await readFile(join(written.directory, 'payload', 'operations.json'))).toString('utf8'),
  )
  assert.equal(executed.length, 2, 'the loop must stop rather than run every planned operation')
})
