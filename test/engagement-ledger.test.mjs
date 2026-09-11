import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import {
  copyFile,
  link,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  symlink,
  unlink,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import Ajv2020 from 'ajv/dist/2020.js'

import {
  EngagementLedgerError,
  openEngagementLedger,
} from '../scripts/lib/engagement-ledger.mjs'

const SHA_A = 'a'.repeat(64)
const SHA_B = 'b'.repeat(64)
const SHA_C = 'c'.repeat(64)
const SHA_D = 'd'.repeat(64)
const SHA_E = 'e'.repeat(64)
const NOW = '2026-09-11T10:00:00.000Z'

function binding(overrides = {}) {
  return {
    engagement_id: 'engagement:unified-ledger-test',
    authority_sha256: SHA_A,
    target_sha256: SHA_B,
    ...overrides,
  }
}

async function fixture(t, suffix) {
  const parent = await mkdtemp(join(tmpdir(), `last-aperture-engagement-ledger-${suffix}-`))
  t.after(() => rm(parent, { recursive: true, force: true }))
  return { parent, directory: join(parent, 'ledger') }
}

async function startedLedger(t, suffix = 'started') {
  const paths = await fixture(t, suffix)
  const ledger = await openEngagementLedger({
    directory: paths.directory,
    binding: binding(),
    initialize: true,
  })
  await ledger.start({ manifestSha256: SHA_C, startedAt: NOW })
  return { ...paths, ledger }
}

test('records one bound engagement lifecycle and resumes from canonical state', async (t) => {
  const { directory, ledger } = await startedLedger(t, 'lifecycle')

  await ledger.recordRoutePlan({
    routeId: 'route:http-recon:1',
    planSha256: SHA_D,
    plannedAt: '2026-09-11T10:00:01.000Z',
  })
  await ledger.recordRouteWaiting({
    routeId: 'route:http-recon:1',
    planSha256: SHA_D,
    reasonCode: 'CREDENTIAL_REFERENCE_UNAVAILABLE',
    waitingAt: '2026-09-11T10:00:02.000Z',
  })
  await ledger.recordResume({ resumedAt: '2026-09-11T11:00:00.000Z' })
  await ledger.recordDispatchPermit({
    routeId: 'route:http-recon:1',
    planSha256: SHA_D,
    permitSha256: SHA_C,
    permittedAt: '2026-09-11T11:00:01.000Z',
  })
  await ledger.recordRouteOutcome({
    routeId: 'route:http-recon:1',
    planSha256: SHA_D,
    status: 'SUCCEEDED',
    resultSha256: SHA_A,
    requestMayHaveBeenSent: true,
    completedAt: '2026-09-11T11:00:02.000Z',
  })
  await ledger.recordTerminal({
    status: 'COMPLETED',
    resultSha256: SHA_B,
    terminalAt: '2026-09-11T11:00:03.000Z',
  })

  const first = ledger.snapshot()
  assert.equal(first.record_count, 7)
  assert.equal(first.started, true)
  assert.equal(first.resume_count, 1)
  assert.equal(first.terminal, true)
  assert.equal(first.terminal_result.status, 'COMPLETED')
  assert.deepEqual(first.binding, binding())
  assert.deepEqual(first.routes, [{
    route_id: 'route:http-recon:1',
    plan_sha256: SHA_D,
    planned_at: '2026-09-11T10:00:01.000Z',
    state: 'SUCCEEDED',
    waiting: {
      reason_code: 'CREDENTIAL_REFERENCE_UNAVAILABLE',
      waiting_at: '2026-09-11T10:00:02.000Z',
    },
    permit_sha256: SHA_C,
    permitted_at: '2026-09-11T11:00:01.000Z',
    outcome: {
      status: 'SUCCEEDED',
      result_sha256: SHA_A,
      request_may_have_been_sent: true,
      completed_at: '2026-09-11T11:00:02.000Z',
    },
  }])

  const reopened = await openEngagementLedger({
    directory,
    binding: binding(),
    initialize: false,
    expectedHead: {
      recordCount: first.record_count,
      headSha256: first.head_sha256,
    },
  })
  assert.deepEqual(reopened.snapshot(), first)

  const names = await readdir(directory)
  assert.deepEqual(names, [
    '0000000000000001.engagement.json',
    '0000000000000002.engagement.json',
    '0000000000000003.engagement.json',
    '0000000000000004.engagement.json',
    '0000000000000005.engagement.json',
    '0000000000000006.engagement.json',
    '0000000000000007.engagement.json',
  ])
  for (const name of names) {
    const bytes = await readFile(join(directory, name))
    const record = JSON.parse(bytes)
    assert.equal(Buffer.from(`${JSON.stringify(record, null, 2)}\n`).equals(bytes), true)
  }
})

test('stop is durable and idempotent and prevents every later dispatch permit', async (t) => {
  const { ledger } = await startedLedger(t, 'stop')
  await ledger.recordRoutePlan({
    routeId: 'route:ghidra:1',
    planSha256: SHA_D,
    plannedAt: '2026-09-11T10:00:01.000Z',
  })

  const stopped = await ledger.requestStop({
    reason: 'Operator requested a global stop.',
    requestedAt: '2026-09-11T10:00:02.000Z',
  })
  const repeated = await ledger.requestStop({
    reason: 'A different repeated reason cannot rewrite the first request.',
    requestedAt: '2026-09-11T10:00:03.000Z',
  })
  assert.equal(stopped.record_count, 3)
  assert.equal(repeated.record_count, 3)
  assert.deepEqual(repeated.stop_request, {
    reason: 'Operator requested a global stop.',
    requested_at: '2026-09-11T10:00:02.000Z',
  })

  assert.throws(
    () => ledger.assertDispatchAllowed({ routeId: 'route:ghidra:1', planSha256: SHA_D }),
    (error) => error instanceof EngagementLedgerError
      && error.code === 'ENGAGEMENT_LEDGER_STOP_REQUESTED',
  )
  await assert.rejects(
    ledger.recordDispatchPermit({
      routeId: 'route:ghidra:1',
      planSha256: SHA_D,
      permitSha256: SHA_C,
      permittedAt: '2026-09-11T10:00:04.000Z',
    }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_STOP_REQUESTED',
  )

  await ledger.recordTerminal({
    status: 'STOPPED',
    resultSha256: SHA_A,
    terminalAt: '2026-09-11T10:00:05.000Z',
  })
  assert.equal(ledger.snapshot().terminal_result.status, 'STOPPED')
})

test('rejects invalid lifecycle transitions and refuses to hide an unsettled dispatch', async (t) => {
  const paths = await fixture(t, 'transitions')
  const ledger = await openEngagementLedger({
    directory: paths.directory,
    binding: binding(),
    initialize: true,
  })
  await assert.rejects(
    ledger.recordRoutePlan({ routeId: 'route:one', planSha256: SHA_D, plannedAt: NOW }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_NOT_STARTED',
  )
  await ledger.start({ manifestSha256: SHA_C, startedAt: NOW })
  await ledger.recordRoutePlan({
    routeId: 'route:one', planSha256: SHA_D, plannedAt: '2026-09-11T10:00:01.000Z',
  })
  await assert.rejects(
    ledger.recordRouteOutcome({
      routeId: 'route:one', planSha256: SHA_D, status: 'FAILED', resultSha256: SHA_A,
      requestMayHaveBeenSent: false, completedAt: '2026-09-11T10:00:02.000Z',
    }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_DISPATCH_NOT_PERMITTED',
  )
  await ledger.recordDispatchPermit({
    routeId: 'route:one', planSha256: SHA_D, permitSha256: SHA_C,
    permittedAt: '2026-09-11T10:00:02.000Z',
  })
  await assert.rejects(
    ledger.recordTerminal({
      status: 'FAILED', resultSha256: SHA_A, terminalAt: '2026-09-11T10:00:03.000Z',
    }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_DISPATCH_UNSETTLED',
  )
  await ledger.recordRouteOutcome({
    routeId: 'route:one', planSha256: SHA_D, status: 'UNCERTAIN', resultSha256: SHA_A,
    requestMayHaveBeenSent: true, completedAt: '2026-09-11T10:00:04.000Z',
  })
  await ledger.recordTerminal({
    status: 'COMPLETED_WITH_GAPS', resultSha256: SHA_B,
    terminalAt: '2026-09-11T10:00:05.000Z',
  })
  await assert.rejects(
    ledger.recordResume({ resumedAt: '2026-09-11T10:00:06.000Z' }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_TERMINAL',
  )
})

test('rejects time regressions and terminal claims that contradict route state', async (t) => {
  const { ledger } = await startedLedger(t, 'semantic-terminal')
  await assert.rejects(
    ledger.recordResume({ resumedAt: '2026-09-11T09:59:59.999Z' }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_TIME_REGRESSION',
  )

  await ledger.recordRoutePlan({
    routeId: 'route:semantic:1', planSha256: SHA_D,
    plannedAt: '2026-09-11T10:00:01.000Z',
  })
  await assert.rejects(
    ledger.recordTerminal({
      status: 'COMPLETED', resultSha256: SHA_A,
      terminalAt: '2026-09-11T10:00:02.000Z',
    }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_TERMINAL_INCOMPLETE',
  )

  await ledger.recordDispatchPermit({
    routeId: 'route:semantic:1', planSha256: SHA_D, permitSha256: SHA_C,
    permittedAt: '2026-09-11T10:00:02.000Z',
  })
  await ledger.recordRouteOutcome({
    routeId: 'route:semantic:1', planSha256: SHA_D, status: 'SUCCEEDED',
    resultSha256: SHA_A, requestMayHaveBeenSent: true,
    completedAt: '2026-09-11T10:00:03.000Z',
  })
  await assert.rejects(
    ledger.recordTerminal({
      status: 'COMPLETED_WITH_GAPS', resultSha256: SHA_B,
      terminalAt: '2026-09-11T10:00:04.000Z',
    }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_TERMINAL_STATUS_MISMATCH',
  )
  await ledger.recordTerminal({
    status: 'COMPLETED', resultSha256: SHA_B,
    terminalAt: '2026-09-11T10:00:04.000Z',
  })
  assert.equal(ledger.snapshot().terminal_result.status, 'COMPLETED')
})

test('repository child checkpoints form one durable work lease and bind its receipt', async (t) => {
  const { directory, ledger } = await startedLedger(t, 'repository-work')
  await ledger.recordRoutePlan({
    routeId: 'repository-audit', planSha256: SHA_D,
    plannedAt: '2026-09-11T10:00:01.000Z',
  })
  await ledger.recordDispatchPermit({
    routeId: 'repository-audit', planSha256: SHA_D, permitSha256: SHA_C,
    permittedAt: '2026-09-11T10:00:02.000Z',
  })
  await ledger.recordRouteOutcome({
    routeId: 'repository-audit', planSha256: SHA_D, status: 'PARTIAL',
    resultSha256: SHA_A, requestMayHaveBeenSent: false,
    completedAt: '2026-09-11T10:00:03.000Z',
  })
  await ledger.recordRepositoryChildCheckpoint({
    operation: 'INITIAL', childBundleSha256: SHA_A, childTreeSha256: SHA_B,
    statusSha256: SHA_C, checkpointSha256: SHA_D, childState: 'PLANNED', terminal: false,
    checkpointedAt: '2026-09-11T10:00:04.000Z',
  })
  const workId = `repository-work:${SHA_E}`
  await ledger.recordRepositoryWorkIssued({
    workId, envelopeSha256: SHA_A, childTreeSha256: SHA_B,
    issuedAt: '2026-09-11T10:00:05.000Z',
  })
  await assert.rejects(
    ledger.recordRepositoryWorkIssued({
      workId: `repository-work:${SHA_D}`, envelopeSha256: SHA_B,
      childTreeSha256: SHA_B, issuedAt: '2026-09-11T10:00:06.000Z',
    }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_REPOSITORY_WORK_ACTIVE',
  )
  await ledger.recordRepositoryIngestDispatch({
    workId,
    envelopeSha256: SHA_A,
    preChildTreeSha256: SHA_B,
    stagedRelativePath: `${SHA_A}-${SHA_D}.json`,
    resultSha256: SHA_D,
    resultSizeBytes: 123,
    resultState: 'SUCCEEDED',
    dispatchedAt: '2026-09-11T10:00:06.000Z',
  })
  await assert.rejects(
    ledger.recordTerminal({
      status: 'COMPLETED', resultSha256: SHA_E,
      terminalAt: '2026-09-11T10:00:07.000Z',
    }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_REPOSITORY_RECOVERY_REQUIRED',
  )
  await ledger.recordRepositoryIngestReconciliation({
    workId,
    envelopeSha256: SHA_A,
    attempt: 1,
    outcome: 'APPLIED',
    observedChildTreeSha256: SHA_C,
    reconciledAt: '2026-09-11T10:00:07.000Z',
  })
  await ledger.recordRepositoryChildCheckpoint({
    operation: 'INGEST', childBundleSha256: SHA_A, childTreeSha256: SHA_C,
    statusSha256: SHA_D, checkpointSha256: SHA_E, childState: 'RUNNING', terminal: false,
    checkpointedAt: '2026-09-11T10:00:08.000Z',
  })
  await ledger.recordRepositoryWorkResult({
    workId, envelopeSha256: SHA_A, receiptSha256: SHA_B,
    childTreeSha256: SHA_C, status: 'RESULT_INGESTED',
    recordedAt: '2026-09-11T10:00:08.000Z',
  })
  await assert.rejects(
    ledger.recordRepositoryWorkResult({
      workId, envelopeSha256: SHA_A, receiptSha256: SHA_B,
      childTreeSha256: SHA_C, status: 'RESULT_INGESTED',
      recordedAt: '2026-09-11T10:00:09.000Z',
    }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_REPOSITORY_WORK_INVALID',
  )
  await ledger.recordRepositoryChildCheckpoint({
    operation: 'STATUS', childBundleSha256: SHA_A, childTreeSha256: SHA_C,
    statusSha256: SHA_E, checkpointSha256: SHA_A, childState: 'COMPLETED', terminal: true,
    checkpointedAt: '2026-09-11T10:00:09.000Z',
  })

  const snapshot = ledger.snapshot()
  assert.equal(snapshot.repository.checkpoints.length, 3)
  assert.equal(snapshot.repository.current_checkpoint.child_state, 'COMPLETED')
  assert.equal(snapshot.repository.active_work, null)
  assert.equal(snapshot.repository.works[0].result.status, 'RESULT_INGESTED')
  assert.equal(snapshot.repository.works[0].ingest_attempts[0].reconciliation.outcome, 'APPLIED')
  const reopened = await openEngagementLedger({ directory, binding: binding(), initialize: false })
  assert.deepEqual(reopened.snapshot().repository, snapshot.repository)
})

test('rejects binding drift and optional trusted-head rollback mismatches', async (t) => {
  const { directory, ledger } = await startedLedger(t, 'binding')
  const snapshot = ledger.snapshot()

  await assert.rejects(
    openEngagementLedger({
      directory,
      binding: binding({ target_sha256: SHA_C }),
      initialize: false,
    }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_BINDING_MISMATCH',
  )
  await assert.rejects(
    openEngagementLedger({
      directory,
      binding: binding(),
      initialize: false,
      expectedHead: { recordCount: snapshot.record_count + 1, headSha256: snapshot.head_sha256 },
    }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_TRUSTED_HEAD_MISMATCH',
  )
  await assert.rejects(
    openEngagementLedger({
      directory,
      binding: binding(),
      initialize: false,
      expectedHead: { recordCount: snapshot.record_count, headSha256: SHA_D },
    }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_TRUSTED_HEAD_MISMATCH',
  )
})

test('external append-only anchors detect valid-prefix rollback and incomplete history', async (t) => {
  const paths = await fixture(t, 'external-anchor-rollback')
  const anchorDirectory = join(paths.parent, 'ledger-heads')
  const ledger = await openEngagementLedger({
    directory: paths.directory,
    anchorDirectory,
    binding: binding(),
    initialize: true,
  })
  await ledger.start({ manifestSha256: SHA_C, startedAt: NOW })
  await ledger.recordResume({ resumedAt: '2026-09-11T10:00:01.000Z' })

  assert.deepEqual(await readdir(anchorDirectory), [
    '0000000000000001.anchor.json',
    '0000000000000002.anchor.json',
  ])
  const secondAnchorBytes = await readFile(join(anchorDirectory, '0000000000000002.anchor.json'))
  const secondAnchor = JSON.parse(secondAnchorBytes)
  assert.equal(secondAnchor.kind, 'last-aperture/engagement-ledger-anchor')
  assert.equal(secondAnchor.sequence, 2)
  assert.equal(secondAnchor.record_sha256, ledger.snapshot().head_sha256)
  assert.equal(Buffer.from(`${JSON.stringify(secondAnchor, null, 2)}\n`).equals(secondAnchorBytes), true)

  const reopened = await openEngagementLedger({
    directory: paths.directory,
    anchorDirectory,
    binding: binding(),
    initialize: false,
  })
  assert.equal(reopened.snapshot().record_count, 2)

  await unlink(join(paths.directory, '0000000000000002.engagement.json'))
  await assert.rejects(
    openEngagementLedger({
      directory: paths.directory,
      anchorDirectory,
      binding: binding(),
      initialize: false,
    }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_ANCHOR_MISMATCH',
  )

  const incomplete = await fixture(t, 'external-anchor-incomplete')
  const incompleteAnchors = join(incomplete.parent, 'ledger-heads')
  const incompleteLedger = await openEngagementLedger({
    directory: incomplete.directory,
    anchorDirectory: incompleteAnchors,
    binding: binding(),
    initialize: true,
  })
  await incompleteLedger.start({ manifestSha256: SHA_C, startedAt: NOW })
  await unlink(join(incompleteAnchors, '0000000000000001.anchor.json'))
  await assert.rejects(
    openEngagementLedger({
      directory: incomplete.directory,
      anchorDirectory: incompleteAnchors,
      binding: binding(),
      initialize: false,
    }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_ANCHOR_MISMATCH',
  )
})

test('anchor directories are create-exclusive, external, and durably synced', async (t) => {
  const paths = await fixture(t, 'external-anchor-path')
  await assert.rejects(
    openEngagementLedger({
      directory: paths.directory,
      anchorDirectory: join(paths.directory, 'nested-heads'),
      binding: binding(),
      initialize: true,
    }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_ANCHOR_DIRECTORY_INVALID',
  )

  const anchorDirectory = join(paths.parent, 'ledger-heads')
  const syncedDirectories = []
  const ledger = await openEngagementLedger({
    directory: paths.directory,
    anchorDirectory,
    binding: binding(),
    initialize: true,
    fsyncFile: () => {},
    fsyncDirectory: (path) => syncedDirectories.push(path),
  })
  await ledger.start({ manifestSha256: SHA_C, startedAt: NOW })
  assert.equal(syncedDirectories.includes(paths.directory), true)
  assert.equal(syncedDirectories.includes(anchorDirectory), true)

  await assert.rejects(
    openEngagementLedger({
      directory: join(paths.parent, 'second-ledger'),
      anchorDirectory,
      binding: binding(),
      initialize: true,
    }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_ANCHOR_DIRECTORY_EXISTS',
  )
})

test('held-handle record reads reject hard-link and symbolic-link substitutions', async (t) => {
  const hardLinkFixture = await startedLedger(t, 'hard-link-substitution')
  const hardLinkRecord = join(
    hardLinkFixture.directory,
    '0000000000000001.engagement.json',
  )
  const attackerFile = join(hardLinkFixture.parent, 'attacker-controlled-record.json')
  await writeFile(attackerFile, await readFile(hardLinkRecord))
  await unlink(hardLinkRecord)
  await link(attackerFile, hardLinkRecord)
  await assert.rejects(
    openEngagementLedger({
      directory: hardLinkFixture.directory,
      binding: binding(),
      initialize: false,
    }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_RECORD_INVALID',
  )

  const symbolicFixture = await startedLedger(t, 'symbolic-link-substitution')
  const symbolicRecord = join(
    symbolicFixture.directory,
    '0000000000000001.engagement.json',
  )
  const originalRecord = join(symbolicFixture.parent, 'original-record.json')
  await rename(symbolicRecord, originalRecord)
  try {
    await symlink(originalRecord, symbolicRecord, 'file')
  } catch (error) {
    if (error?.code === 'EPERM' || error?.code === 'EACCES') {
      t.diagnostic('symbolic-link creation is unavailable; hard-link substitution was verified')
      return
    }
    throw error
  }
  await assert.rejects(
    openEngagementLedger({
      directory: symbolicFixture.directory,
      binding: binding(),
      initialize: false,
    }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_RECORD_INVALID',
  )
})

test('detects tampered, missing, reordered, and duplicate records on reopen', async (t) => {
  async function twoRecordLedger(suffix) {
    const { directory, ledger } = await startedLedger(t, suffix)
    await ledger.recordResume({ resumedAt: '2026-09-11T10:00:01.000Z' })
    return directory
  }

  const tampered = await twoRecordLedger('tampered')
  const firstPath = join(tampered, '0000000000000001.engagement.json')
  const first = JSON.parse(await readFile(firstPath, 'utf8'))
  first.event.started_at = '2026-09-11T10:00:00.001Z'
  await writeFile(firstPath, `${JSON.stringify(first, null, 2)}\n`, 'utf8')
  await assert.rejects(
    openEngagementLedger({ directory: tampered, binding: binding(), initialize: false }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_CHAIN_INVALID',
  )

  const missing = await twoRecordLedger('missing')
  await rename(
    join(missing, '0000000000000002.engagement.json'),
    join(missing, '0000000000000003.engagement.json'),
  )
  await assert.rejects(
    openEngagementLedger({ directory: missing, binding: binding(), initialize: false }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_SEQUENCE_INVALID',
  )

  const duplicate = await twoRecordLedger('duplicate')
  await copyFile(
    join(duplicate, '0000000000000001.engagement.json'),
    join(duplicate, '0000000000000002.engagement.json'),
  )
  await assert.rejects(
    openEngagementLedger({ directory: duplicate, binding: binding(), initialize: false }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_CHAIN_INVALID',
  )

  const reordered = await twoRecordLedger('reordered')
  const one = join(reordered, '0000000000000001.engagement.json')
  const two = join(reordered, '0000000000000002.engagement.json')
  const spare = join(reordered, 'spare')
  await rename(one, spare)
  await rename(two, one)
  await rename(spare, two)
  await assert.rejects(
    openEngagementLedger({ directory: reordered, binding: binding(), initialize: false }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_CHAIN_INVALID',
  )
})

test('initialization is create-exclusive and records are bound by their exact byte digest', async (t) => {
  const { parent, directory, ledger } = await startedLedger(t, 'exclusive')
  await assert.rejects(
    openEngagementLedger({ directory, binding: binding(), initialize: true }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_DIRECTORY_EXISTS',
  )

  const bytes = await readFile(join(directory, '0000000000000001.engagement.json'))
  assert.equal(ledger.snapshot().head_sha256, createHash('sha256').update(bytes).digest('hex'))

  const absent = join(parent, 'absent')
  await assert.rejects(
    openEngagementLedger({ directory: absent, binding: binding(), initialize: false }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_DIRECTORY_MISSING',
  )

  const nonEmpty = join(parent, 'non-empty')
  await mkdir(nonEmpty)
  await writeFile(join(nonEmpty, 'unexpected.txt'), 'x')
  await assert.rejects(
    openEngagementLedger({ directory: nonEmpty, binding: binding(), initialize: false }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_DIRECTORY_UNSAFE',
  )

  await assert.rejects(
    openEngagementLedger({
      directory: '\\\\?\\C:\\must-not-touch-engagement-ledger',
      binding: binding(),
      initialize: false,
    }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_DIRECTORY_INVALID',
  )
})

test('every persisted event validates against the shipped engagement ledger schema', async (t) => {
  const { directory, ledger } = await startedLedger(t, 'schema')
  await ledger.recordRoutePlan({
    routeId: 'repository-audit', planSha256: SHA_D,
    plannedAt: '2026-09-11T10:00:01.000Z',
  })
  await ledger.recordRouteWaiting({
    routeId: 'repository-audit', planSha256: SHA_D, reasonCode: 'TOOL_UNAVAILABLE',
    waitingAt: '2026-09-11T10:00:02.000Z',
  })
  await ledger.recordResume({ resumedAt: '2026-09-11T10:00:03.000Z' })
  await ledger.recordDispatchPermit({
    routeId: 'repository-audit', planSha256: SHA_D, permitSha256: SHA_C,
    permittedAt: '2026-09-11T10:00:04.000Z',
  })
  await ledger.recordRouteOutcome({
    routeId: 'repository-audit', planSha256: SHA_D, status: 'PARTIAL',
    resultSha256: SHA_A, requestMayHaveBeenSent: false,
    completedAt: '2026-09-11T10:00:05.000Z',
  })
  await ledger.recordRepositoryChildCheckpoint({
    operation: 'INITIAL', childBundleSha256: SHA_A, childTreeSha256: SHA_B,
    statusSha256: SHA_C, checkpointSha256: SHA_D, childState: 'PLANNED', terminal: false,
    checkpointedAt: '2026-09-11T10:00:06.000Z',
  })
  const workId = `repository-work:${SHA_E}`
  await ledger.recordRepositoryWorkIssued({
    workId, envelopeSha256: SHA_A, childTreeSha256: SHA_B,
    issuedAt: '2026-09-11T10:00:07.000Z',
  })
  await ledger.recordRepositoryIngestDispatch({
    workId,
    envelopeSha256: SHA_A,
    preChildTreeSha256: SHA_B,
    stagedRelativePath: `${SHA_A}-${SHA_D}.json`,
    resultSha256: SHA_D,
    resultSizeBytes: 123,
    resultState: 'SUCCEEDED',
    dispatchedAt: '2026-09-11T10:00:08.000Z',
  })
  await ledger.recordRepositoryIngestReconciliation({
    workId,
    envelopeSha256: SHA_A,
    attempt: 1,
    outcome: 'APPLIED',
    observedChildTreeSha256: SHA_C,
    reconciledAt: '2026-09-11T10:00:09.000Z',
  })
  await ledger.recordRepositoryChildCheckpoint({
    operation: 'INGEST', childBundleSha256: SHA_A, childTreeSha256: SHA_C,
    statusSha256: SHA_D, checkpointSha256: SHA_E, childState: 'RUNNING', terminal: false,
    checkpointedAt: '2026-09-11T10:00:10.000Z',
  })
  await ledger.recordRepositoryWorkResult({
    workId, envelopeSha256: SHA_A, receiptSha256: SHA_B,
    childTreeSha256: SHA_C, status: 'RESULT_INGESTED',
    recordedAt: '2026-09-11T10:00:10.000Z',
  })
  await ledger.requestStop({
    reason: 'End the schema fixture.', requestedAt: '2026-09-11T10:00:11.000Z',
  })
  await ledger.recordTerminal({
    status: 'STOPPED', resultSha256: SHA_B, terminalAt: '2026-09-11T10:00:12.000Z',
  })

  const schema = JSON.parse(await readFile('schemas/engagement-ledger-record.schema.json', 'utf8'))
  const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema)
  const names = await readdir(directory)
  for (const name of names) {
    const value = JSON.parse(await readFile(join(directory, name), 'utf8'))
    assert.equal(validate(value), true, JSON.stringify(validate.errors))
  }

  const invalid = JSON.parse(await readFile(join(directory, names[0]), 'utf8'))
  invalid.event = { type: 'TARGET_CONTENT_SELECTED_A_NEW_ROUTE' }
  assert.equal(validate(invalid), false)
})
