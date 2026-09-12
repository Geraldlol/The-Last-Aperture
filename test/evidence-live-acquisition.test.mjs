import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  planAcquisition,
  requestAcquisitionStop,
  runAcquisition,
} from '../scripts/lib/evidence-acquire-controller.mjs'
import { main as acquireMain } from '../scripts/acquire.mjs'
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
  context: 'reference-production',
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

const PUBLIC_ACQUISITION_COMMANDS = Object.freeze([
  'plan',
  'run',
  'finalize',
  'validate',
  'stop',
])

function disabledCliCases(adapter) {
  return [
    ...PUBLIC_ACQUISITION_COMMANDS.map((command) => [adapter, command]),
    [adapter, 'future-command', '--caller-path', '\\\\host\\share\\target'],
    [adapter, 'plan', '--source', '\\\\host\\share\\artifact.tar'],
    [adapter, 'run', '--confirm-authorization-current'],
    [
      adapter,
      'run',
      `C:\\forged\\${adapter}-acquisition`,
      '--operator-id',
      'gmaida',
      '--confirm-authorization-current',
    ],
    [adapter, 'finalize', 'C:\\forged\\bundle'],
    [adapter, 'validate', 'C:\\forged\\bundle'],
    [
      adapter,
      'stop',
      'C:\\forged\\bundle',
      '--operator-id',
      'gmaida',
      '--reason',
      'test stop',
    ],
  ]
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

test('every public acquisition command refuses every adapter name before controllers are touched', async () => {
  const adapters = ['artifact', 'registry', 'deployed', 'runtime', 'spoofed-live-adapter']
  const invocations = adapters.flatMap(disabledCliCases)

  for (const argv of invocations) {
    const calls = []
    const forbidden = (name) => async () => {
      calls.push(name)
      throw new Error(`${name} must not be invoked`)
    }
    await assert.rejects(
      () => acquireMain(argv, {
        planAcquisitionImpl: forbidden('plan'),
        runAcquisitionImpl: forbidden('run'),
        finalizeAcquisitionImpl: forbidden('finalize'),
        validateAcquisitionImpl: forbidden('validate'),
        requestAcquisitionStopImpl: forbidden('stop'),
      }),
      (error) => error?.code === 'ACQUIRE_LIVE_IO_DISABLED'
        && /before argument parsing, controller loading, acquisition-plan, filesystem/i
          .test(error.message),
      argv.join(' '),
    )
    assert.deepEqual(calls, [], argv.join(' '))
  }
})

test('the acquisition executable refuses missing and forged plans for every adapter name', () => {
  for (const adapter of ['artifact', 'registry', 'deployed', 'runtime', 'spoofed-live-adapter']) {
    for (const args of disabledCliCases(adapter)) {
      const refused = spawnSync(process.execPath, ['scripts/acquire.mjs', ...args], {
        encoding: 'utf8',
        shell: false,
        windowsHide: true,
      })
      assert.equal(refused.status, 1, args.join(' '))
      assert.match(
        refused.stderr,
        /\S+ is disabled before argument parsing, controller loading/i,
        args.join(' '),
      )
      assert.doesNotMatch(
        refused.stderr,
        /ENOENT|expects 1 positional|requires --operator-id|node:internal/i,
        args.join(' '),
      )
    }
  }
})

test('a class requiring attestation refuses to run without the confirmation', async () => {
  const stub = await kubectlStub()
  const out = await scratch()
  const planned = await planAcquisition({ adapterId: 'deployed', request, out, resolver: stub.resolver })
  await assert.rejects(
    () => runAcquisition({
      bundle: out,
      expectedAdapterId: 'deployed',
      expectedPlanSha256: planned.plan_sha256,
      operatorId: 'gmaida',
      resolver: stub.resolver,
    }),
    /authorization/i,
  )
})

test('a persisted live command changed after approval is rejected before CLI resolution', async () => {
  const stub = await kubectlStub()
  const out = await scratch()
  const planned = await planAcquisition({ adapterId: 'deployed', request, out, resolver: stub.resolver })
  const path = join(out, 'acquisition-plan.json')
  const record = JSON.parse(await readFile(path, 'utf8'))
  record.plan.operations[0].args[0] = 'delete'
  await writeFile(path, `${JSON.stringify(record, null, 2)}\n`)
  let resolverCalls = 0
  await assert.rejects(
    () => runAcquisition({
      bundle: out,
      expectedAdapterId: 'deployed',
      expectedPlanSha256: planned.plan_sha256,
      operatorId: 'gmaida',
      authorizationConfirmed: true,
      resolver: (...args) => {
        resolverCalls += 1
        return stub.resolver(...args)
      },
    }),
    (error) => error?.code === 'ACQUISITION_PLAN_DIGEST_MISMATCH',
  )
  assert.equal(resolverCalls, 0)
})

test('the controller rejects truthy non-boolean current-authorization confirmations', async () => {
  const stub = await kubectlStub()
  for (const authorizationConfirmed of ['yes', {}]) {
    const out = await scratch()
    const planned = await planAcquisition({ adapterId: 'deployed', request, out, resolver: stub.resolver })
    await assert.rejects(
      () => runAcquisition({
        bundle: out,
        expectedAdapterId: 'deployed',
        expectedPlanSha256: planned.plan_sha256,
        operatorId: 'gmaida',
        authorizationConfirmed,
        resolver: stub.resolver,
      }),
      /authorization/i,
    )
  }
})

test('stop halts an acquisition that is already planned', async () => {
  const stub = await kubectlStub()
  const out = await scratch()
  const planned = await planAcquisition({
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
      expectedAdapterId: 'deployed',
      expectedPlanSha256: planned.plan_sha256,
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
  const planned = await planAcquisition({ adapterId: 'deployed', request, out, resolver: stub.resolver })
  await runAcquisition({
    bundle: out,
    expectedAdapterId: 'deployed',
    expectedPlanSha256: planned.plan_sha256,
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
  const planned = await planAcquisition({ adapterId: 'deployed', request, out, resolver: stub.resolver })
  await runAcquisition({
    bundle: out,
    expectedAdapterId: 'deployed',
    expectedPlanSha256: planned.plan_sha256,
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
  const planned = await planAcquisition({ adapterId: 'deployed', request, out, resolver: stub.resolver })
  await runAcquisition({
    bundle: out,
    expectedAdapterId: 'deployed',
    expectedPlanSha256: planned.plan_sha256,
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
  const receipt = JSON.parse(await readFile(join(out, 'execution-receipt.json'), 'utf8'))
  assert.deepEqual(receipt.run_authorization, {
    mode: 'OPERATOR_ATTESTED',
    current_authorization_confirmed: true,
    third_party_acknowledged: false,
    confirmed_by: 'gmaida',
  })
})
