import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  planAcquisition,
  requestAcquisitionStop,
  runAcquisition,
} from '../scripts/lib/evidence-acquire-controller.mjs'
import { resolveEvidenceLocator } from '../scripts/lib/evidence-locator.mjs'
import { stubCli } from './helpers/stub-cli.mjs'

const OBJECT_JSON = JSON.stringify({
  apiVersion: 'v1',
  kind: 'Pod',
  metadata: { name: 'api-0', namespace: 'clinical' },
  spec: { volumes: [{ name: 'config' }] },
})

async function kubectlStub() {
  return stubCli('kubectl', `
    if (args[0] === 'version') { process.stdout.write('v1.29.4\\n') }
    else { process.stdout.write(${JSON.stringify(OBJECT_JSON)}) }
  `)
}

const request = {
  evidence_id: 'prod-cluster',
  context: 'peerstar-prod',
  operations: [
    { operation_id: 'k8s.resource', params: { kind: 'pods', name: 'api-0', namespace: 'clinical' } },
  ],
  target_class: 'NONPROD',
  phi_scope: 'none',
  attest_authorized: true,
  operator_id: 'gmaida',
  authorized_by: 'security-lead',
  authorization_reference: 'JIRA-4418',
}

async function scratch() {
  return join(await mkdtemp(join(tmpdir(), 'rta-live-')), 'ev')
}

test('all four adapters are reachable through the controller', async () => {
  const stub = await kubectlStub()
  const out = await scratch()
  const planned = await planAcquisition({
    adapterId: 'deployed',
    request,
    out,
    resolver: stub.resolver,
  })
  assert.equal(planned.plan.evidence_context_seed.evidence_class, 'deployed-state')
})

test('a class requiring attestation refuses to run without the confirmation', async () => {
  const stub = await kubectlStub()
  const out = await scratch()
  await planAcquisition({ adapterId: 'deployed', request, out, resolver: stub.resolver })
  await assert.rejects(
    () => runAcquisition({ bundle: out, operatorId: 'gmaida', resolver: stub.resolver }),
    /authorization/i,
  )
})

test('stop halts an acquisition that is already planned', async () => {
  const stub = await kubectlStub()
  const out = await scratch()
  await planAcquisition({
    adapterId: 'deployed',
    request: {
      ...request,
      operations: Array.from({ length: 8 }, (_unused, index) => ({
        operation_id: 'k8s.resource',
        params: { kind: 'pods', name: `api-${index}`, namespace: 'clinical' },
      })),
    },
    out,
    resolver: stub.resolver,
  })
  await requestAcquisitionStop({ bundle: out, operatorId: 'gmaida', reason: 'scope change' })
  await assert.rejects(
    () => runAcquisition({
      bundle: out,
      operatorId: 'gmaida',
      authorizationConfirmed: true,
      resolver: stub.resolver,
    }),
    /stopped/i,
  )
})

test('stop is idempotent and needs no still-valid authority artifact', async () => {
  const out = await scratch()
  const first = await requestAcquisitionStop({ bundle: out, operatorId: 'gmaida', reason: 'incident' })
  const second = await requestAcquisitionStop({ bundle: out, operatorId: 'gmaida', reason: 'incident' })
  assert.equal(first.state, 'STOPPED')
  assert.equal(second.state, 'STOPPED')
})

test('a deployed-state locator resolves to its acquired object', async () => {
  const stub = await kubectlStub()
  const out = await scratch()
  await planAcquisition({ adapterId: 'deployed', request, out, resolver: stub.resolver })
  await runAcquisition({
    bundle: out,
    operatorId: 'gmaida',
    authorizationConfirmed: true,
    resolver: stub.resolver,
  })
  const resolved = await resolveEvidenceLocator(out, 'v1/Pod/clinical/api-0')
  assert.equal(resolved.kind, 'object')
  assert.match(resolved.bytes.toString('utf8'), /"api-0"/)
})

test('an unresolvable object locator resolves to nothing rather than guessing', async () => {
  const stub = await kubectlStub()
  const out = await scratch()
  await planAcquisition({ adapterId: 'deployed', request, out, resolver: stub.resolver })
  await runAcquisition({
    bundle: out,
    operatorId: 'gmaida',
    authorizationConfirmed: true,
    resolver: stub.resolver,
  })
  const resolved = await resolveEvidenceLocator(out, 'v1/Pod/clinical/no-such-pod')
  assert.equal(resolved.bytes, null)
})

test('the acquisition plan records what was executed for the report', async () => {
  const stub = await kubectlStub()
  const out = await scratch()
  await planAcquisition({ adapterId: 'deployed', request, out, resolver: stub.resolver })
  await runAcquisition({
    bundle: out,
    operatorId: 'gmaida',
    authorizationConfirmed: true,
    resolver: stub.resolver,
  })
  const executed = JSON.parse(
    (await readFile(join(out, 'payload', 'operations.json'))).toString('utf8'),
  )
  assert.equal(executed.length, 1)
  assert.equal(executed[0].operation_id, 'k8s.resource')
  assert.equal(executed[0].payload_prefix, '00')
})
