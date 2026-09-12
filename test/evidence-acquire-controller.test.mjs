import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { access, cp, copyFile, link, mkdir, mkdtemp, readFile, rename, rm, unlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import {
  acquisitionPlanDigest,
  finalizeAcquisition,
  isAcquisitionStopped,
  planAcquisition,
  requestAcquisitionStop,
  runAcquisition,
  validateAcquisition,
} from '../scripts/lib/evidence-acquire-controller.mjs'
import { stubCli } from './helpers/stub-cli.mjs'

const SOURCE = 'test/fixtures/evidence/vulnerable-image.tar'

async function scratch() {
  return join(await mkdtemp(join(tmpdir(), 'rta-acquire-')), 'ev')
}

async function waitForFile(path) {
  const deadline = Date.now() + 3000
  while (Date.now() < deadline) {
    try {
      await access(path)
      return
    } catch {
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 10))
    }
  }
  throw new Error(`timed out waiting for ${path}`)
}

const request = {
  evidence_id: 'sample-api-image',
  source_path: SOURCE,
  target_class: 'LAB',
  phi_scope: 'none',
}

function trustedFinalizeOptions(planned, writtenOrDigest = 'f'.repeat(64)) {
  return {
    expectedAdapterId: 'artifact',
    expectedPlanSha256: planned.plan_sha256,
    expectedReceiptSha256: typeof writtenOrDigest === 'string'
      ? writtenOrDigest
      : writtenOrDigest.execution_receipt_sha256,
  }
}

function syntheticLock(nonce, pid = process.pid) {
  return JSON.stringify({
    acquired_at: '2026-09-12T12:00:00.000Z',
    nonce,
    pid,
    schema_version: '1.0.0',
  })
}

async function deadProcessId() {
  const child = spawn(process.execPath, ['--eval', 'setInterval(() => {}, 1_000)'], {
    stdio: 'ignore',
    windowsHide: true,
  })
  const exited = new Promise((resolveExit, rejectExit) => {
    child.once('error', rejectExit)
    child.once('exit', (code, signal) => resolveExit({ code, signal }))
  })
  const pid = child.pid
  assert.equal(Number.isSafeInteger(pid), true)
  assert.equal(child.kill(), true)
  await exited
  return pid
}

test('plan seals the request and acquires nothing', async () => {
  const out = await scratch()
  const planned = await planAcquisition({ adapterId: 'artifact', request, out })
  const onDisk = JSON.parse(await readFile(join(planned.directory, 'acquisition-plan.json'), 'utf8'))
  assert.equal(onDisk.adapter_id, 'artifact')
  assert.equal(onDisk.schema, 'evidence-acquisition-plan-v2')
  assert.equal(onDisk.plan_sha256, planned.plan_sha256)
  assert.match(planned.plan_sha256, /^[a-f0-9]{64}$/)
  assert.match(onDisk.plan.evidence_context_seed.target_identity, /^sha256:/)
  assert.equal(onDisk.plan.source_integrity.algorithm, 'sha256')
  assert.match(onDisk.plan.source_integrity.sha256, /^[a-f0-9]{64}$/)
  assert.ok(Number.isSafeInteger(onDisk.plan.source_integrity.size_bytes))
  assert.equal(onDisk.adapter_profile.adapter_version, '1.0.0')
  const state = JSON.parse(await readFile(join(planned.directory, 'acquisition-state.json'), 'utf8'))
  assert.equal(state.state, 'PLANNED')
  await assert.rejects(() => readFile(join(planned.directory, 'manifest.json')))
})

test('run produces a bundle that validates and finalizes', async () => {
  const out = await scratch()
  const planned = await planAcquisition({ adapterId: 'artifact', request, out })
  const written = await runAcquisition({
    bundle: out,
    expectedAdapterId: 'artifact',
    expectedPlanSha256: planned.plan_sha256,
    operatorId: 'gmaida',
  })
  assert.match(written.root_sha256, /^[0-9a-f]{64}$/)
  const state = JSON.parse(await readFile(join(out, 'acquisition-state.json'), 'utf8'))
  const receipt = JSON.parse(await readFile(join(out, 'execution-receipt.json'), 'utf8'))
  assert.match(state.run_nonce, /^[0-9a-f-]{36}$/)
  assert.equal(receipt.run_nonce, state.run_nonce)
  assert.equal(written.execution_receipt_sha256, receipt.receipt_sha256)
  assert.equal((await validateAcquisition(out)).valid, true)
  assert.equal((await finalizeAcquisition(out, trustedFinalizeOptions(planned, written))).state, 'ACQUIRED')
})

test('a post-receipt state-publication fault stays RUNNING and cannot trust its on-disk digest', async () => {
  const root = await mkdtemp(join(tmpdir(), 'rta-acquire-receipt-window-'))
  const stub = await stubCli('kubectl', `
    if (args[0] === 'version') process.stdout.write('v1.31.0\\n')
    else {
      process.stdout.write(JSON.stringify({ apiVersion: 'v1', kind: 'Pod', metadata: { name: 'api-0' } }))
    }
  `)
  const out = join(root, 'ev')
  const liveRequest = {
    evidence_id: 'receipt-window', context: 'lab', target_class: 'LAB', phi_scope: 'none',
    operator_id: 'gmaida', authorized_by: 'lead', authorization_reference: 'T-RECEIPT-WINDOW',
    attest_authorized: true,
    operations: [{
      operation_id: 'k8s.resource',
      params: { kind: 'pods', name: 'api-0', namespace: 'default' },
    }],
  }
  const planned = await planAcquisition({
    adapterId: 'deployed', request: liveRequest, out, resolver: stub.resolver,
  })
  const statePath = join(out, 'acquisition-state.json')
  const publicationFault = new Error('simulated termination after durable receipt publication')
  const running = runAcquisition({
    bundle: out,
    expectedAdapterId: 'deployed',
    expectedPlanSha256: planned.plan_sha256,
    operatorId: 'gmaida',
    authorizationConfirmed: true,
    resolver: stub.resolver,
  }, {
    afterReceiptPublished: () => { throw publicationFault },
  })
  await assert.rejects(
    () => running,
    (error) => error === publicationFault,
  )
  const interrupted = JSON.parse(await readFile(statePath, 'utf8'))
  const receipt = JSON.parse(await readFile(join(out, 'execution-receipt.json'), 'utf8'))
  assert.equal(interrupted.state, 'RUNNING')
  assert.match(receipt.receipt_sha256, /^[a-f0-9]{64}$/)

  await assert.rejects(
    () => finalizeAcquisition(out, {
      expectedAdapterId: 'deployed',
      expectedPlanSha256: planned.plan_sha256,
      // This value was recovered from disk after the failed run; the run never
      // returned it through the caller's trust channel.
      expectedReceiptSha256: receipt.receipt_sha256,
    }),
    (error) => error?.code === 'ACQUISITION_RUN_INCOMPLETE'
      && /never returned a caller-trusted receipt digest/i.test(error.message),
  )
  assert.equal(JSON.parse(await readFile(statePath, 'utf8')).state, 'RUNNING')
})

test('finalize requires caller-pinned adapter, plan, and trusted receipt digests before reading files', async () => {
  const missing = 'C:\\definitely-missing\\forged-acquisition'
  await assert.rejects(
    () => finalizeAcquisition(missing),
    (error) => error?.code === 'ACQUISITION_EXPECTED_ADAPTER_REQUIRED',
  )
  await assert.rejects(
    () => finalizeAcquisition(missing, { expectedAdapterId: 'artifact' }),
    (error) => error?.code === 'ACQUISITION_EXPECTED_PLAN_DIGEST_REQUIRED',
  )
  await assert.rejects(
    () => finalizeAcquisition(missing, {
      expectedAdapterId: 'artifact', expectedPlanSha256: 'a'.repeat(64),
    }),
    (error) => error?.code === 'ACQUISITION_EXPECTED_RECEIPT_DIGEST_REQUIRED',
  )
})

test('run requires a caller-pinned adapter before reading a plan', async () => {
  await assert.rejects(
    () => runAcquisition({
      bundle: 'C:\\definitely-missing\\forged-acquisition',
      operatorId: 'gmaida',
    }),
    (error) => error?.code === 'ACQUISITION_EXPECTED_ADAPTER_REQUIRED'
      && /before reading a plan/i.test(error.message),
  )
})

test('run requires a caller-pinned immutable plan digest before reading a plan', async () => {
  await assert.rejects(
    () => runAcquisition({
      bundle: 'C:\\definitely-missing\\forged-acquisition',
      expectedAdapterId: 'artifact',
      operatorId: 'gmaida',
    }),
    (error) => error?.code === 'ACQUISITION_EXPECTED_PLAN_DIGEST_REQUIRED'
      && /before reading a plan/i.test(error.message),
  )
})

test('run rejects a plan changed after caller approval even when its stored digest is replaced', async () => {
  const out = await scratch()
  const planned = await planAcquisition({ adapterId: 'artifact', request, out })
  const path = join(out, 'acquisition-plan.json')
  const record = JSON.parse(await readFile(path, 'utf8'))
  record.plan.source_path = 'C:\\forged\\replacement.tar'
  record.plan_sha256 = 'a'.repeat(64)
  await writeFile(path, `${JSON.stringify(record, null, 2)}\n`)
  await assert.rejects(
    () => runAcquisition({
      bundle: out,
      expectedAdapterId: 'artifact',
      expectedPlanSha256: planned.plan_sha256,
      operatorId: 'gmaida',
    }),
    (error) => error?.code === 'ACQUISITION_PLAN_DIGEST_MISMATCH',
  )
})

test('run rejects adapter mismatch before a live resolver or adapter can run', async () => {
  const out = await scratch()
  const planned = await planAcquisition({ adapterId: 'artifact', request, out })
  let resolverCalls = 0
  await assert.rejects(
    () => runAcquisition({
      bundle: out,
      expectedAdapterId: 'deployed',
      expectedPlanSha256: planned.plan_sha256,
      operatorId: 'gmaida',
      resolver: async () => {
        resolverCalls += 1
        throw new Error('resolver must not run')
      },
    }),
    (error) => error?.code === 'ACQUISITION_ADAPTER_MISMATCH',
  )
  assert.equal(resolverCalls, 0)
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
  const planned = await planAcquisition({ adapterId: 'artifact', request, out })
  const first = await requestAcquisitionStop({ bundle: out, operatorId: 'gmaida', reason: 'scope change' })
  const second = await requestAcquisitionStop({ bundle: out, operatorId: 'gmaida', reason: 'scope change' })
  assert.equal(first.state, 'STOPPED')
  assert.equal(second.state, 'STOPPED')
  await assert.rejects(
    () => runAcquisition({
      bundle: out,
      expectedAdapterId: 'artifact',
      expectedPlanSha256: planned.plan_sha256,
      operatorId: 'gmaida',
    }),
    /stopped/i,
  )
})

test('a malformed stop marker fails closed instead of resuming acquisition', async () => {
  const out = await scratch()
  const planned = await planAcquisition({ adapterId: 'artifact', request, out })
  await writeFile(join(out, 'acquisition-stop.json'), '{')
  await assert.rejects(() => isAcquisitionStopped(out), /stop.*invalid|unparseable/i)
  await assert.rejects(
    () => runAcquisition({
      bundle: out,
      expectedAdapterId: 'artifact',
      expectedPlanSha256: planned.plan_sha256,
      operatorId: 'gmaida',
    }),
    /stop.*invalid|unparseable/i,
  )
})

test('stop publication never overwrites a hard-linked outside file', async () => {
  const root = await mkdtemp(join(tmpdir(), 'rta-acquire-stop-link-'))
  const out = join(root, 'ev')
  const outside = join(root, 'outside.json')
  await mkdir(out)
  await writeFile(outside, 'outside')
  await link(outside, join(out, 'acquisition-stop.json'))
  await assert.rejects(
    () => requestAcquisitionStop({ bundle: out, operatorId: 'gmaida', reason: 'scope change' }),
    /unsafe|linked|stop/i,
  )
  assert.equal(await readFile(outside, 'utf8'), 'outside')
})

test('a hard-linked plan is rejected before any adapter dispatch', async () => {
  const out = await scratch()
  const planned = await planAcquisition({ adapterId: 'artifact', request, out })
  const planPath = join(out, 'acquisition-plan.json')
  const outside = join(await mkdtemp(join(tmpdir(), 'rta-acquire-plan-link-')), 'outside.json')
  await writeFile(outside, await readFile(planPath))
  await unlink(planPath)
  await link(outside, planPath)
  await assert.rejects(
    () => runAcquisition({
      bundle: out,
      expectedAdapterId: 'artifact',
      expectedPlanSha256: planned.plan_sha256,
      operatorId: 'gmaida',
    }),
    /regular, unlinked|unsafe/i,
  )
})

test('running twice on one plan is refused rather than silently re-acquiring', async () => {
  const out = await scratch()
  const planned = await planAcquisition({ adapterId: 'artifact', request, out })
  await runAcquisition({ bundle: out, expectedAdapterId: 'artifact', expectedPlanSha256: planned.plan_sha256, operatorId: 'gmaida' })
  await assert.rejects(
    () => runAcquisition({ bundle: out, expectedAdapterId: 'artifact', expectedPlanSha256: planned.plan_sha256, operatorId: 'gmaida' }),
    /already/i,
  )
})

test('two concurrent runs serialize before target dispatch', async () => {
  const root = await mkdtemp(join(tmpdir(), 'rta-acquire-race-'))
  const calls = join(root, 'calls.txt')
  const stub = await stubCli('kubectl', `
    if (args[0] === 'version') process.stdout.write('v1.31.0\\n')
    else {
      (await import('node:fs')).appendFileSync(${JSON.stringify(calls)}, 'x')
      process.stdout.write(JSON.stringify({ apiVersion: 'v1', kind: 'Pod', metadata: { name: 'api-0' } }))
    }
  `)
  const out = join(root, 'ev')
  const liveRequest = {
    evidence_id: 'race', context: 'lab', target_class: 'LAB', phi_scope: 'none',
    operator_id: 'gmaida', authorized_by: 'lead', authorization_reference: 'T-1',
    attest_authorized: true,
    operations: [{ operation_id: 'k8s.resource', params: { kind: 'pods', name: 'api-0', namespace: 'default' } }],
  }
  const planned = await planAcquisition({ adapterId: 'deployed', request: liveRequest, out, resolver: stub.resolver })
  const results = await Promise.allSettled([1, 2].map(() => runAcquisition({
    bundle: out,
    expectedAdapterId: 'deployed',
    expectedPlanSha256: planned.plan_sha256,
    operatorId: 'gmaida',
    authorizationConfirmed: true,
    resolver: stub.resolver,
  })))
  assert.equal(results.filter(({ status }) => status === 'fulfilled').length, 1)
  assert.equal((await readFile(calls, 'utf8')).length, 1)
})

test('a killed acquisition owner leaves a reclaimable complete lock', async () => {
  const root = await mkdtemp(join(tmpdir(), 'rta-acquire-dead-lock-'))
  const out = join(root, 'ev')
  const marker = join(root, 'lock-held.txt')
  const planned = await planAcquisition({ adapterId: 'artifact', request, out })
  const controller = new URL('../scripts/lib/evidence-acquire-controller.mjs', import.meta.url).href
  const childSource = `
    const { writeFile } = await import('node:fs/promises')
    const { runAcquisition } = await import(${JSON.stringify(controller)})
    const keepAlive = setInterval(() => {}, 1_000)
    try {
      await runAcquisition(${JSON.stringify({
    bundle: out,
    expectedAdapterId: 'artifact',
    expectedPlanSha256: planned.plan_sha256,
    operatorId: 'crash-owner',
  })}, {
      lockFaultInjector: async (phase) => {
        if (phase !== 'after-acquisition-lock-acquired') return
        await writeFile(${JSON.stringify(marker)}, 'held')
        await new Promise(() => {})
      },
    })
    } finally {
      clearInterval(keepAlive)
    }
  `
  const child = spawn(process.execPath, ['--input-type=module', '--eval', childSource], {
    cwd: process.cwd(),
    stdio: ['ignore', 'ignore', 'pipe'],
    windowsHide: true,
  })
  let stderr = ''
  child.stderr.setEncoding('utf8')
  child.stderr.on('data', (chunk) => { stderr += chunk })
  const exited = new Promise((resolveExit, rejectExit) => {
    child.once('error', rejectExit)
    child.once('exit', (code, signal) => resolveExit({ code, signal }))
  })
  try {
    await waitForFile(marker)
    assert.equal(child.kill(), true)
    await exited
    const recovery = await Promise.allSettled(Array.from({ length: 12 }, (_unused, index) =>
      runAcquisition({
        bundle: out,
        expectedAdapterId: 'artifact',
        expectedPlanSha256: planned.plan_sha256,
        operatorId: `recovery-owner-${index}`,
      })))
    const completed = recovery.filter(({ status }) => status === 'fulfilled')
    assert.equal(completed.length, 1)
    assert.match(completed[0].value.execution_receipt_sha256, /^[a-f0-9]{64}$/)
  } catch (error) {
    if (child.exitCode === null && child.signalCode === null) child.kill()
    await exited.catch(() => {})
    assert.fail(`${error.stack ?? error}\nchild stderr:\n${stderr}`)
  }
})

test('a dead two-link publication crash tail is reclaimed without changing its private sibling', async () => {
  const root = await mkdtemp(join(tmpdir(), 'rta-acquire-dead-link-tail-'))
  const out = join(root, 'ev')
  const lockPath = join(out, '.acquisition-lock')
  const privateTail = join(root, '.last-aperture-acquisition-lock-crash-tail.tmp')
  const planned = await planAcquisition({ adapterId: 'artifact', request, out })
  const deadPid = await deadProcessId()
  const deadOwner = syntheticLock('44444444-4444-4444-8444-444444444444', deadPid)
  await writeFile(privateTail, deadOwner, { flag: 'wx' })
  await link(privateTail, lockPath)
  const written = await runAcquisition({
    bundle: out,
    expectedAdapterId: 'artifact',
    expectedPlanSha256: planned.plan_sha256,
    operatorId: 'crash-tail-recovery-owner',
  })
  assert.match(written.execution_receipt_sha256, /^[a-f0-9]{64}$/)
  assert.equal(await readFile(privateTail, 'utf8'), deadOwner)
  await assert.rejects(() => access(lockPath))
})

test('a fault after dead-lock quarantine cannot poison the bundle and an immediate retry succeeds', async () => {
  const root = await mkdtemp(join(tmpdir(), 'rta-acquire-stale-quarantine-fault-'))
  const out = join(root, 'ev')
  const lockPath = join(out, '.acquisition-lock')
  const planned = await planAcquisition({ adapterId: 'artifact', request, out })
  const deadOwner = syntheticLock(
    '55555555-5555-4555-8555-555555555555',
    await deadProcessId(),
  )
  await writeFile(lockPath, deadOwner, { flag: 'wx' })
  const quarantineFault = new Error('simulated termination after dead-lock quarantine')
  let quarantinedPath
  await assert.rejects(
    () => runAcquisition({
      bundle: out,
      expectedAdapterId: 'artifact',
      expectedPlanSha256: planned.plan_sha256,
      operatorId: 'faulting-reclaimer',
    }, {
      lockFaultInjector: (phase, details) => {
        if (phase !== 'after-acquisition-lock-stale-quarantine') return
        quarantinedPath = details.quarantine
        throw quarantineFault
      },
    }),
    (error) => error === quarantineFault,
  )
  assert.equal(dirname(quarantinedPath), root)
  assert.equal(await readFile(quarantinedPath, 'utf8'), deadOwner)
  const written = await runAcquisition({
    bundle: out,
    expectedAdapterId: 'artifact',
    expectedPlanSha256: planned.plan_sha256,
    operatorId: 'retry-owner',
  })
  assert.match(written.execution_receipt_sha256, /^[a-f0-9]{64}$/)
})

test('lock acquisition never adopts a replacement published before owner inspection', async () => {
  const root = await mkdtemp(join(tmpdir(), 'rta-acquire-lock-publication-swap-'))
  const out = join(root, 'ev')
  const lockPath = join(out, '.acquisition-lock')
  const displaced = join(out, '.displaced-acquisition-lock')
  const replacement = syntheticLock('11111111-1111-4111-8111-111111111111')
  const planned = await planAcquisition({ adapterId: 'artifact', request, out })
  let swapped = false
  await assert.rejects(
    () => runAcquisition({
      bundle: out,
      expectedAdapterId: 'artifact',
      expectedPlanSha256: planned.plan_sha256,
      operatorId: 'gmaida',
    }, {
      lockFaultInjector: async (phase) => {
        if (phase !== 'after-acquisition-lock-published') return
        await rename(lockPath, displaced)
        await writeFile(lockPath, replacement, { flag: 'wx' })
        swapped = true
      },
    }),
    (error) => error?.code === 'ACQUISITION_LOCK_CHANGED',
  )
  assert.equal(swapped, true)
  assert.equal(await readFile(lockPath, 'utf8'), replacement)
})

test('lock acquisition rejects an externally hard-linked live owner and can retry', async () => {
  const root = await mkdtemp(join(tmpdir(), 'rta-acquire-lock-hardlink-'))
  const out = join(root, 'ev')
  const outside = join(root, 'outside-lock-owner.json')
  const lockPath = join(out, '.acquisition-lock')
  const planned = await planAcquisition({ adapterId: 'artifact', request, out })
  await assert.rejects(
    () => runAcquisition({
      bundle: out,
      expectedAdapterId: 'artifact',
      expectedPlanSha256: planned.plan_sha256,
      operatorId: 'linked-owner',
    }, {
      lockFaultInjector: async (phase) => {
        if (phase === 'after-acquisition-lock-published') await link(lockPath, outside)
      },
    }),
    (error) => error?.code === 'ACQUISITION_LOCK_CHANGED',
  )
  assert.match(await readFile(outside, 'utf8'), /"pid":\d+/)
  const written = await runAcquisition({
    bundle: out,
    expectedAdapterId: 'artifact',
    expectedPlanSha256: planned.plan_sha256,
    operatorId: 'retry-owner',
  })
  assert.match(written.execution_receipt_sha256, /^[a-f0-9]{64}$/)
})

test('a post-publication acquisition-lock fault removes only its exact owner and can retry', async () => {
  const out = await scratch()
  const planned = await planAcquisition({ adapterId: 'artifact', request, out })
  const publicationFault = new Error('simulated fault after acquisition lock publication')
  await assert.rejects(
    () => runAcquisition({
      bundle: out,
      expectedAdapterId: 'artifact',
      expectedPlanSha256: planned.plan_sha256,
      operatorId: 'faulting-owner',
    }, {
      lockFaultInjector: (phase) => {
        if (phase === 'after-acquisition-lock-published') throw publicationFault
      },
    }),
    (error) => error === publicationFault,
  )
  const written = await runAcquisition({
    bundle: out,
    expectedAdapterId: 'artifact',
    expectedPlanSha256: planned.plan_sha256,
    operatorId: 'retry-owner',
  })
  assert.match(written.execution_receipt_sha256, /^[a-f0-9]{64}$/)
})

test('a post-acquisition lock hook fault releases its exact owner and can retry', async () => {
  const out = await scratch()
  const planned = await planAcquisition({ adapterId: 'artifact', request, out })
  const acquisitionFault = new Error('simulated fault after acquisition lock ownership')
  await assert.rejects(
    () => runAcquisition({
      bundle: out,
      expectedAdapterId: 'artifact',
      expectedPlanSha256: planned.plan_sha256,
      operatorId: 'faulting-owner',
    }, {
      lockFaultInjector: (phase) => {
        if (phase === 'after-acquisition-lock-acquired') throw acquisitionFault
      },
    }),
    (error) => error === acquisitionFault,
  )
  const written = await runAcquisition({
    bundle: out,
    expectedAdapterId: 'artifact',
    expectedPlanSha256: planned.plan_sha256,
    operatorId: 'retry-owner',
  })
  assert.match(written.execution_receipt_sha256, /^[a-f0-9]{64}$/)
})

test('lock release never removes a replacement at the well-known path', async () => {
  const root = await mkdtemp(join(tmpdir(), 'rta-acquire-lock-replacement-'))
  const out = join(root, 'ev')
  const displaced = join(out, '.displaced-acquisition-lock')
  const lockPath = join(out, '.acquisition-lock')
  const firstReplacement = syntheticLock('22222222-2222-4222-8222-222222222222')
  const concurrentReplacement = syntheticLock('33333333-3333-4333-8333-333333333333')
  const planned = await planAcquisition({ adapterId: 'artifact', request, out })
  let replaced = false
  let reacquired = false
  await assert.rejects(
    () => runAcquisition({
      bundle: out,
      expectedAdapterId: 'artifact',
      expectedPlanSha256: planned.plan_sha256,
      operatorId: 'gmaida',
    }, {
      // A third owner publishes while the unexpected replacement is held at
      // its private quarantine name. Restoration must never overwrite it.
      lockFaultInjector: async (phase) => {
        if (phase === 'before-acquisition-lock-release-quarantine') {
          await rename(lockPath, displaced)
          await writeFile(lockPath, firstReplacement, { flag: 'wx' })
          replaced = true
        } else if (phase === 'after-acquisition-lock-release-quarantine') {
          await writeFile(lockPath, concurrentReplacement, { flag: 'wx' })
          reacquired = true
        }
      },
    }),
    (error) => error?.code === 'ACQUISITION_LOCK_CHANGED',
  )
  assert.equal(replaced, true)
  assert.equal(reacquired, true)
  assert.equal(await readFile(lockPath, 'utf8'), concurrentReplacement)
})

test('a concurrent stop is durably observed before the next target dispatch', async () => {
  const root = await mkdtemp(join(tmpdir(), 'rta-acquire-run-stop-'))
  const calls = join(root, 'calls.txt')
  const started = join(root, 'started.txt')
  const stub = await stubCli('kubectl', `
    if (args[0] === 'version') process.stdout.write('v1.31.0\\n')
    else {
      const fs = await import('node:fs')
      fs.appendFileSync(${JSON.stringify(calls)}, 'x')
      fs.writeFileSync(${JSON.stringify(started)}, 'started')
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 200))
      process.stdout.write(JSON.stringify({ apiVersion: 'v1', kind: 'Pod', metadata: { name: 'api-0' } }))
    }
  `)
  const out = join(root, 'ev')
  const liveRequest = {
    evidence_id: 'run-stop', context: 'lab', target_class: 'LAB', phi_scope: 'none',
    operator_id: 'gmaida', authorized_by: 'lead', authorization_reference: 'T-2',
    attest_authorized: true,
    operations: [1, 2].map(() => ({
      operation_id: 'k8s.resource',
      params: { kind: 'pods', name: 'api-0', namespace: 'default' },
    })),
  }
  const planned = await planAcquisition({
    adapterId: 'deployed', request: liveRequest, out, resolver: stub.resolver,
  })
  const running = runAcquisition({
    bundle: out,
    expectedAdapterId: 'deployed',
    expectedPlanSha256: planned.plan_sha256,
    operatorId: 'gmaida',
    authorizationConfirmed: true,
    resolver: stub.resolver,
  })
  await waitForFile(started)
  await requestAcquisitionStop({ bundle: out, operatorId: 'gmaida', reason: 'scope changed' })
  const written = await running
  assert.equal((await readFile(calls, 'utf8')).length, 1)
  assert.equal(written.profile.coverage_state, 'PARTIAL')
  assert.ok(written.profile.coverage_gaps.some(({ reason }) => /stopped by the operator/i.test(reason)))
  assert.equal(await isAcquisitionStopped(out), true)
})

test('validate refuses a bundle whose payload was edited after acquisition', async () => {
  const out = await scratch()
  const planned = await planAcquisition({ adapterId: 'artifact', request, out })
  await runAcquisition({ bundle: out, expectedAdapterId: 'artifact', expectedPlanSha256: planned.plan_sha256, operatorId: 'gmaida' })
  await writeFile(join(out, 'payload', 'orphan-blobs.json'), '[]')
  const validation = await validateAcquisition(out)
  assert.equal(validation.valid, false)
  assert.ok(validation.errors.some(({ code }) => code === 'PAYLOAD_DIGEST_MISMATCH'))
})

test('finalize refuses a bundle that does not verify', async () => {
  const out = await scratch()
  const planned = await planAcquisition({ adapterId: 'artifact', request, out })
  const written = await runAcquisition({ bundle: out, expectedAdapterId: 'artifact', expectedPlanSha256: planned.plan_sha256, operatorId: 'gmaida' })
  await writeFile(join(out, 'payload', 'orphan-blobs.json'), '[]')
  await assert.rejects(
    () => finalizeAcquisition(out, trustedFinalizeOptions(planned, written)),
    /uncertain provenance/i,
  )
})

test('finalize refuses a plan that never executed', async () => {
  const out = await scratch()
  const planned = await planAcquisition({ adapterId: 'artifact', request, out })
  await assert.rejects(
    () => finalizeAcquisition(out, trustedFinalizeOptions(planned)),
    (error) => error?.code === 'ACQUISITION_NOT_ACQUIRED',
  )
})

test('finalize refuses an execution receipt whose sealed root no longer matches the bundle', async () => {
  const out = await scratch()
  const planned = await planAcquisition({ adapterId: 'artifact', request, out })
  const written = await runAcquisition({
    bundle: out,
    expectedAdapterId: 'artifact',
    expectedPlanSha256: planned.plan_sha256,
    operatorId: 'gmaida',
  })
  const path = join(out, 'execution-receipt.json')
  const record = JSON.parse(await readFile(path, 'utf8'))
  record.bundle_root_sha256 = '0'.repeat(64)
  await writeFile(path, `${JSON.stringify(record, null, 2)}\n`)
  await assert.rejects(
    () => finalizeAcquisition(out, trustedFinalizeOptions(planned, written)),
    (error) => /RECEIPT|record/i.test(error?.code ?? error?.message),
  )
})

test('finalize refuses a fabricated acquired state without a trusted execution receipt', async () => {
  const out = await scratch()
  const planned = await planAcquisition({ adapterId: 'artifact', request, out })
  const source = await scratch()
  const sourcePlan = await planAcquisition({ adapterId: 'artifact', request, out: source })
  await runAcquisition({
    bundle: source,
    expectedAdapterId: 'artifact',
    expectedPlanSha256: sourcePlan.plan_sha256,
    operatorId: 'gmaida',
  })
  await rm(join(out, 'acquisition-state.json'))
  await writeFile(join(out, 'acquisition-state.json'), JSON.stringify({
    schema: 'evidence-acquisition-state-v1', state: 'ACQUIRED', plan_sha256: planned.plan_sha256,
  }))
  await assert.rejects(
    () => finalizeAcquisition(out, trustedFinalizeOptions(planned)),
    /receipt/i,
  )
})

test('finalize refuses a valid bundle and receipt copied from a different immutable plan', async () => {
  const source = await scratch()
  const sourcePlanned = await planAcquisition({ adapterId: 'artifact', request, out: source })
  const sourceWritten = await runAcquisition({
    bundle: source,
    expectedAdapterId: 'artifact',
    expectedPlanSha256: sourcePlanned.plan_sha256,
    operatorId: 'gmaida',
  })

  const target = await scratch()
  const targetPlanned = await planAcquisition({
    adapterId: 'artifact',
    request: { ...request, evidence_id: 'different-approved-target' },
    out: target,
  })
  await cp(join(source, 'payload'), join(target, 'payload'), { recursive: true })
  await copyFile(join(source, 'manifest.json'), join(target, 'manifest.json'))
  await copyFile(join(source, 'execution-receipt.json'), join(target, 'execution-receipt.json'))
  const copiedReceipt = JSON.parse(await readFile(join(target, 'execution-receipt.json'), 'utf8'))
  await writeFile(join(target, 'acquisition-state.json'), JSON.stringify({
    schema: 'evidence-acquisition-state-v1',
    state: 'ACQUIRED',
    plan_sha256: targetPlanned.plan_sha256,
    receipt_sha256: copiedReceipt.receipt_sha256,
    run_nonce: copiedReceipt.run_nonce,
  }))
  await assert.rejects(
    () => finalizeAcquisition(target, trustedFinalizeOptions(targetPlanned, sourceWritten)),
    (error) => error?.code === 'ACQUISITION_RECEIPT_PLAN_MISMATCH',
  )
})

test('legacy acquisition plans fail with an explicit migration requirement', async () => {
  const out = await scratch()
  const planned = await planAcquisition({ adapterId: 'artifact', request, out })
  const path = join(out, 'acquisition-plan.json')
  const record = JSON.parse(await readFile(path, 'utf8'))
  record.schema = 'evidence-acquisition-plan-v1'
  await writeFile(path, JSON.stringify(record))
  await assert.rejects(
    () => runAcquisition({
      bundle: out,
      expectedAdapterId: 'artifact',
      expectedPlanSha256: planned.plan_sha256,
      operatorId: 'gmaida',
    }),
    (error) => error?.code === 'ACQUISITION_PLAN_MIGRATION_REQUIRED',
  )
})

test('run rejects a re-digested plan whose adapter version/profile no longer matches runtime', async () => {
  const out = await scratch()
  await planAcquisition({ adapterId: 'artifact', request, out })
  const path = join(out, 'acquisition-plan.json')
  const record = JSON.parse(await readFile(path, 'utf8'))
  record.adapter_profile.adapter_version = '0.9.0'
  record.plan_sha256 = acquisitionPlanDigest(record)
  await writeFile(path, `${JSON.stringify(record, null, 2)}\n`)
  const statePath = join(out, 'acquisition-state.json')
  const state = JSON.parse(await readFile(statePath, 'utf8'))
  state.plan_sha256 = record.plan_sha256
  await writeFile(statePath, `${JSON.stringify(state, null, 2)}\n`)
  await assert.rejects(
    () => runAcquisition({
      bundle: out,
      expectedAdapterId: 'artifact',
      expectedPlanSha256: record.plan_sha256,
      operatorId: 'gmaida',
    }),
    /adapter.*profile|version/i,
  )
})
