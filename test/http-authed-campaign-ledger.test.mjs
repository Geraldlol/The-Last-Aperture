import assert from 'node:assert/strict'
import {
  appendFile,
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

import {
  HTTP_AUTHED_CAMPAIGN_LEDGER_LIMITS,
  openHttpAuthedCampaignLedger,
  requestHttpAuthedCampaignStop,
} from '../scripts/lib/http-authed-campaign-ledger.mjs'
import { canonicalJson, sha256Hex } from '../scripts/lib/http-authed-contracts.mjs'
import { stableJson } from '../scripts/lib/run-engine.mjs'
import { publishFileCreateOnlyDurably } from '../scripts/lib/durable-file-publication.mjs'

const GRANT = 'a'.repeat(64)
const AUTHORIZATION_BINDING = 'b'.repeat(64)
const NOW = new Date('2026-08-17T12:00:00.000Z')

test('Win32 ledger publication uses a real create-only write-through move', {
  skip: process.platform !== 'win32',
}, async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'rta-win32-durable-create-'))
  t.after(() => rm(parent, { recursive: true, force: true }))
  const source = join(parent, 'record.pending')
  const destination = join(parent, 'record.json')
  await writeFile(source, 'new record')
  await writeFile(destination, 'existing record')
  await assert.rejects(
    publishFileCreateOnlyDurably(source, destination),
    (error) => error.code === 'EEXIST',
  )
  assert.equal(await readFile(source, 'utf8'), 'new record')
  assert.equal(await readFile(destination, 'utf8'), 'existing record')
  await unlink(destination)
  await publishFileCreateOnlyDurably(source, destination)
  assert.equal(await readFile(destination, 'utf8'), 'new record')
  await assert.rejects(readFile(source), (error) => error.code === 'ENOENT')
})

function candidate(overrides = {}) {
  return {
    kind: 'probe',
    test_category: 'api_security',
    method: 'PROPFIND',
    url: 'https://synthetic.example.test/SYNTHETIC_ROUTE_MARKER',
    expected_effect: 'none',
    ...overrides,
  }
}

function jsonShape(overrides = {}) {
  return {
    kind: 'red-team-audit/http-authed-json-shape',
    schema_version: '1.0.0',
    root_type: 'object',
    object_count: 2,
    array_count: 1,
    key_names: ['id', 'records'],
    value_types: [
      { path: ['records'], types: ['array'] },
      { path: ['records', '[]'], types: ['object'] },
      { path: ['records', '[]', 'id'], types: ['number'] },
    ],
    max_depth_observed: 3,
    omitted_key_count: 0,
    truncated: false,
    ...overrides,
  }
}

async function directoryFor(t, suffix) {
  const parent = await mkdtemp(join(tmpdir(), `rta-http-authed-ledger-${suffix}-`))
  t.after(() => rm(parent, { recursive: true, force: true }))
  return join(parent, 'campaign-ledger')
}

async function openLedger(directory, additions = {}) {
  return openHttpAuthedCampaignLedger({
    directory,
    campaignGrantSha256: GRANT,
    authorizationBindingSha256: AUTHORIZATION_BINDING,
    authorizationMode: 'OPERATOR_ATTESTED_AUTHED',
    independentlyVerified: false,
    operatorId: 'example-security-operator',
    initialize: true,
    now: () => NOW,
    limits: { lockTimeoutMs: 100, staleLockMs: 1, lockPollMs: 1 },
    ...additions,
  })
}

test('concurrent stop requests never expose a partial final marker', async (t) => {
  const directory = await directoryFor(t, 'concurrent-stop-publication')
  const ledger = await openLedger(directory)
  await ledger.close()
  const results = await Promise.all(Array.from({ length: 32 }, () => (
    requestHttpAuthedCampaignStop({
      directory,
      campaignGrantSha256: GRANT,
      operatorId: 'example-security-operator',
      now: () => NOW,
    })
  )))
  assert.equal(results.filter(({ status }) => status === 'STOP_REQUESTED').length, 1)
  assert.equal(results.filter(({ status }) => status === 'ALREADY_REQUESTED').length, 31)
})

test('campaign stop inspection rejects a non-controller hard-link alias', async (t) => {
  const directory = await directoryFor(t, 'stop-hard-link-alias')
  const ledger = await openLedger(directory)
  await requestHttpAuthedCampaignStop({
    directory,
    campaignGrantSha256: GRANT,
    operatorId: 'example-security-operator',
    now: () => NOW,
  })
  await link(
    join(directory, '.http-authed-campaign-stop.json'),
    join(directory, '.http-authed-campaign-stop.json.tmp-not-a-controller-publication'),
  )
  await assert.rejects(
    ledger.observeStopRequest(),
    (error) => error.code === 'HTTP_AUTHED_LEDGER_FILE_UNSAFE',
  )
  await ledger.close()
})

test('campaign stop inspection retries a valid publication link-count transition', async (t) => {
  const directory = await directoryFor(t, 'stop-publication-link-transition')
  const temporaryName = `.http-authed-campaign-stop.json.tmp-${process.pid}-cccccccccccccccccccccccc`
  const temporaryPath = join(directory, temporaryName)
  const targetPath = join(directory, '.http-authed-campaign-stop.json')
  let temporaryRemoved = false
  const ledger = await openLedger(directory, {
    faultInjector: async (phase, detail) => {
      if (phase !== 'after-ledger-file-lstat'
        || detail?.label !== 'campaign stop request'
        || temporaryRemoved) return
      temporaryRemoved = true
      await unlink(temporaryPath)
    },
  })
  await writeFile(temporaryPath, stableJson({
    schema_version: '1.0.0',
    kind: 'red-team-audit/http-authed-campaign-stop-request',
    campaign_grant_sha256: GRANT,
    operator_id: 'example-security-operator',
    requested_at: NOW.toISOString(),
    reason_code: 'OPERATOR_REQUESTED',
  }))
  await link(temporaryPath, targetPath)

  assert.equal(await ledger.observeStopRequest(), true)
  assert.equal(temporaryRemoved, true)
  assert.equal(ledger.snapshot().stopped, true)
  await ledger.close()
})

test('campaign stop inspection fails closed when the endpoint disappears after lstat', async (t) => {
  const directory = await directoryFor(t, 'stop-endpoint-disappears')
  let removed = false
  const ledger = await openLedger(directory, {
    faultInjector: async (phase, detail) => {
      if (phase !== 'after-ledger-file-lstat'
        || detail?.label !== 'campaign stop request'
        || removed) return
      removed = true
      await unlink(join(directory, '.http-authed-campaign-stop.json'))
    },
  })
  await requestHttpAuthedCampaignStop({
    directory,
    campaignGrantSha256: GRANT,
    operatorId: 'example-security-operator',
    now: () => NOW,
  })
  await assert.rejects(
    ledger.observeStopRequest(),
    (error) => error.code === 'HTTP_AUTHED_LEDGER_FILE_CHANGED',
  )
  assert.equal(removed, true)
  await ledger.close()
})

test('ledger record inspection rejects an oversized endpoint swapped after lstat', async (t) => {
  const directory = await directoryFor(t, 'bounded-record-swap')
  const ledger = await openLedger(directory)
  await ledger.close()
  const recordPath = join(directory, '0000000000000000.http-authed-campaign.json')
  let swapped = false
  await assert.rejects(
    openLedger(directory, {
      initialize: false,
      faultInjector: async (phase, detail) => {
        if (phase !== 'after-ledger-file-lstat' || detail?.path !== recordPath || swapped) return
        swapped = true
        await rm(recordPath)
        await writeFile(recordPath, 'x'.repeat(HTTP_AUTHED_CAMPAIGN_LEDGER_LIMITS.maxRecordBytes + 1))
      },
    }),
    (error) => error.code === 'HTTP_AUTHED_LEDGER_FILE_UNSAFE',
  )
  assert.equal(swapped, true)
})

test('ledger reopen reconciles a fully published stop marker temporary', async (t) => {
  const directory = await directoryFor(t, 'stop-publication-recovery')
  const ledger = await openLedger(directory)
  await ledger.close()
  const temporaryName = '.http-authed-campaign-stop.json.tmp-1234-aaaaaaaaaaaaaaaaaaaaaaaa'
  const temporaryPath = join(directory, temporaryName)
  const targetPath = join(directory, '.http-authed-campaign-stop.json')
  await writeFile(temporaryPath, stableJson({
    schema_version: '1.0.0',
    kind: 'red-team-audit/http-authed-campaign-stop-request',
    campaign_grant_sha256: GRANT,
    operator_id: 'example-security-operator',
    requested_at: NOW.toISOString(),
    reason_code: 'OPERATOR_REQUESTED',
  }))
  await link(temporaryPath, targetPath)

  const reopened = await openLedger(directory, { initialize: false })
  assert.equal(await reopened.observeStopRequest(), true)
  assert.equal(reopened.snapshot().stopped, true)
  assert.equal((await readdir(directory)).includes(temporaryName), false)
  await reopened.close()
})

test('ledger reopen does not delete a live stop publisher temporary before link', async (t) => {
  const directory = await directoryFor(t, 'active-stop-publication')
  const ledger = await openLedger(directory)
  await ledger.close()
  const temporaryName = `.http-authed-campaign-stop.json.tmp-${process.pid}-bbbbbbbbbbbbbbbbbbbbbbbb`
  const temporaryPath = join(directory, temporaryName)
  const targetPath = join(directory, '.http-authed-campaign-stop.json')
  await writeFile(temporaryPath, stableJson({
    schema_version: '1.0.0',
    kind: 'red-team-audit/http-authed-campaign-stop-request',
    campaign_grant_sha256: GRANT,
    operator_id: 'example-security-operator',
    requested_at: NOW.toISOString(),
    reason_code: 'OPERATOR_REQUESTED',
  }))

  const reopened = await openLedger(directory, { initialize: false })
  assert.equal((await readdir(directory)).includes(temporaryName), true)
  await link(temporaryPath, targetPath)
  assert.equal(await reopened.observeStopRequest(), true)
  assert.equal(reopened.snapshot().stopped, true)
  await reopened.close()
})

test('handled redirect is bound to a continuation and gaps explicitly when it cannot reopen', async (t) => {
  const directory = await directoryFor(t, 'redirect-continuation-gap')
  const ledger = await openLedger(directory)
  const source = candidate({ method: 'GET', url: 'https://synthetic.example.test/source' })
  const continuation = candidate({ method: 'GET', url: 'https://synthetic.example.test/next' })
  const sourceEnqueued = await ledger.enqueueCandidate({
    candidateDraft: source,
    provenance: 'SEALED_PLAN',
  })
  const continuationEnqueued = await ledger.enqueueCandidate({
    candidateDraft: continuation,
    provenance: 'DISCOVERED',
  })
  const lease = await ledger.leaseAction({
    candidateDraft: source,
    operatorId: 'example-security-operator',
  })
  await ledger.markPreDispatch({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'PROBE',
    requestBindingSha256: 'c'.repeat(64),
  })
  await ledger.markOutcome({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'PROBE',
    outcome: 'SETTLED',
    responseMetadata: {
      status: 302,
      bytes: 0,
      headerNames: ['location'],
      requestMayHaveBeenSent: true,
    },
  })
  await ledger.recordHandledResponseStop({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    continuationActionIds: [continuationEnqueued.actionId],
  })
  await ledger.terminalizeAction({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    outcome: 'PROBE_COMPLETED',
  })
  await ledger.close()

  const reopened = await openLedger(directory, { initialize: false })
  const sourceState = reopened.actionState(sourceEnqueued.actionId)
  const continuationState = reopened.actionState(continuationEnqueued.actionId)
  assert.deepEqual(sourceState.handled_response_stop.continuation_action_ids, [
    continuationEnqueued.actionId,
  ])
  assert.equal(continuationState.outcome, 'CAMPAIGN_STOPPED')
  assert.equal(
    continuationState.terminal_reason_code,
    'DISCOVERED_CANDIDATE_UNAVAILABLE_AFTER_RESTART',
  )
  assert.equal(reopened.snapshot().stopped, true)
  assert.equal(
    reopened.snapshot().stop_reason,
    'DISCOVERED_CANDIDATE_UNAVAILABLE_AFTER_RESTART',
  )
  await reopened.close()
})

async function recordVerifiedBeforeState(ledger, lease, binding = '4'.repeat(64)) {
  await ledger.markPreDispatch({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'CREDENTIAL_PREFLIGHT',
    requestBindingSha256: '3'.repeat(64),
  })
  await ledger.markOutcome({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'CREDENTIAL_PREFLIGHT',
    outcome: 'SETTLED',
    responseMetadata: { status: 204, bytes: 0, headerNames: [] },
  })
  await ledger.markPreDispatch({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'BEFORE_READ',
    requestBindingSha256: binding,
  })
  await ledger.markOutcome({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'BEFORE_READ',
    outcome: 'SETTLED',
    responseMetadata: { status: 200, bytes: 0, headerNames: [] },
  })
  await ledger.recordVerification({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'BEFORE_READ',
    valueMatch: true,
    contextMatch: true,
  })
}

test('campaign ledger allocates monotonic actions without an action-count ceiling', async (t) => {
  const directory = await directoryFor(t, 'monotonic')
  const ledger = await openLedger(directory)
  assert.equal(HTTP_AUTHED_CAMPAIGN_LEDGER_LIMITS.maxRecords, undefined)
  assert.equal(HTTP_AUTHED_CAMPAIGN_LEDGER_LIMITS.maxTotalBytes, undefined)

  const first = await ledger.enqueueCandidate({
    candidateDraft: candidate(),
    provenance: 'SEALED_PLAN',
  })
  const duplicate = await ledger.enqueueCandidate({
    candidateDraft: candidate({ sequence: 999_999 }),
    provenance: 'DISCOVERED',
  })
  const second = await ledger.enqueueCandidate({
    candidateDraft: candidate({ url: 'https://synthetic.example.test/SECOND_SYNTHETIC_ROUTE' }),
    provenance: 'DISCOVERED',
  })

  assert.equal(first.created, true)
  assert.equal(first.actionSequence, 1)
  assert.equal(first.allocatedAction.sequence, 1)
  assert.equal(duplicate.created, false)
  assert.equal(duplicate.actionId, first.actionId)
  assert.equal(duplicate.actionSequence, 1)
  assert.equal(second.actionSequence, 2)
  assert.equal(ledger.snapshot().queued_actions, 2)
  await ledger.close()

  const reopened = await openLedger(directory, { initialize: false })
  assert.equal(reopened.snapshot().next_action_sequence, 3)
  const replay = await reopened.enqueueCandidate({
    candidateDraft: candidate(),
    provenance: 'DISCOVERED',
  })
  assert.equal(replay.created, false)
  assert.equal(replay.actionSequence, 1)
  await reopened.close()
})

test('campaign ledger refuses reopen under an operator different from genesis', async (t) => {
  const directory = await directoryFor(t, 'operator-reopen')
  const ledger = await openLedger(directory)
  await ledger.close()

  await assert.rejects(
    openLedger(directory, {
      initialize: false,
      operatorId: 'different-security-operator',
    }),
    (error) => error.code === 'HTTP_AUTHED_LEDGER_OPERATOR_MISMATCH',
  )
})

test('ACTION_LEASED operator is immutably bound to the campaign genesis operator', async (t) => {
  const directory = await directoryFor(t, 'operator-lease-binding')
  const ledger = await openLedger(directory)
  const action = candidate()
  await ledger.enqueueCandidate({ candidateDraft: action, provenance: 'SEALED_PLAN' })

  await assert.rejects(
    ledger.leaseAction({
      candidateDraft: action,
      operatorId: 'different-security-operator',
    }),
    (error) => error.code === 'HTTP_AUTHED_LEDGER_OPERATOR_MISMATCH',
  )
  await ledger.leaseAction({
    candidateDraft: action,
    operatorId: 'example-security-operator',
  })
  await ledger.close()

  const records = await Promise.all((await readdir(directory))
    .filter((name) => name.endsWith('.http-authed-campaign.json'))
    .map(async (name) => JSON.parse(await readFile(join(directory, name), 'utf8'))))
  const genesis = records.find(({ event }) => event.type === 'CAMPAIGN_OPENED')
  const leases = records.filter(({ event }) => event.type === 'ACTION_LEASED')
  assert.equal(genesis.event.operator_id, 'example-security-operator')
  assert.equal(leases.length, 1)
  assert.equal(leases[0].event.operator_id, genesis.event.operator_id)
})

test('discovered candidate identities are ledger-private while same-process dedupe remains stable', async (t) => {
  const firstDirectory = await directoryFor(t, 'private-candidate-first')
  const secondDirectory = await directoryFor(t, 'private-candidate-second')
  const sentinel = 'SYNTHETIC_DISCOVERED_DICTIONARY_SENTINEL_8675309'
  const discovered = candidate({
    url: `https://synthetic.example.test/discovered/${sentinel}`,
  })

  const firstLedger = await openLedger(firstDirectory)
  const first = await firstLedger.enqueueCandidate({
    candidateDraft: discovered,
    provenance: 'DISCOVERED',
  })
  const duplicate = await firstLedger.enqueueCandidate({
    candidateDraft: { ...discovered, sequence: 999_999 },
    provenance: 'DISCOVERED',
  })
  assert.equal(duplicate.created, false)
  assert.equal(duplicate.actionId, first.actionId)
  assert.equal(duplicate.candidateSha256, first.candidateSha256)
  await firstLedger.close()

  const secondLedger = await openLedger(secondDirectory)
  const second = await secondLedger.enqueueCandidate({
    candidateDraft: discovered,
    provenance: 'DISCOVERED',
  })
  await secondLedger.close()
  assert.notEqual(second.candidateSha256, first.candidateSha256)
  assert.notEqual(second.actionId, first.actionId)

  const firstRecordTexts = await Promise.all((await readdir(firstDirectory))
    .filter((name) => name.endsWith('.http-authed-campaign.json'))
    .map((name) => readFile(join(firstDirectory, name), 'utf8')))
  const firstRecordText = firstRecordTexts.join('\n')
  const records = firstRecordTexts.map((text) => JSON.parse(text))
  const persisted = records.find(({ event }) => event.type === 'CANDIDATE_ENQUEUED').event
  const candidateWithoutSequence = structuredClone(discovered)
  delete candidateWithoutSequence.sequence
  const dictionaryDigests = [
    sha256Hex(Buffer.from(discovered.url, 'utf8')),
    sha256Hex(Buffer.from(canonicalJson(candidateWithoutSequence), 'utf8')),
    sha256Hex(Buffer.from(canonicalJson({
      campaign_grant_sha256: GRANT,
      candidate: candidateWithoutSequence,
    }), 'utf8')),
  ]
  for (const digest of dictionaryDigests) {
    assert.notEqual(persisted.candidate_sha256, digest)
    assert.notEqual(persisted.action_id, `http-authed-action:${digest}`)
  }
  assert.equal(firstRecordText.includes(sentinel), false)
})

test('candidate budget resolution admits a private duplicate before rejecting a new action', async (t) => {
  const directory = await directoryFor(t, 'private-candidate-budget')
  const ledger = await openLedger(directory)
  const firstCandidate = candidate({
    url: 'https://synthetic.example.test/discovered/first',
  })

  const first = await ledger.enqueueCandidate({
    candidateDraft: firstCandidate,
    provenance: 'DISCOVERED',
    maxActions: 1,
  })
  const duplicate = await ledger.enqueueCandidate({
    candidateDraft: firstCandidate,
    provenance: 'DISCOVERED',
    maxActions: 1,
  })
  const rejected = await ledger.enqueueCandidate({
    candidateDraft: candidate({
      url: 'https://synthetic.example.test/discovered/second',
    }),
    provenance: 'DISCOVERED',
    maxActions: 1,
  })
  const privateIdentityCount = ledger._discoveredCandidateIdentities.size
  const snapshot = ledger.snapshot()
  await ledger.close()

  assert.equal(first.created, true)
  assert.equal(duplicate.created, false)
  assert.equal(duplicate.actionId, first.actionId)
  assert.deepEqual(rejected, {
    created: false,
    limitReached: true,
    headSha256: first.headSha256,
  })
  assert.equal(privateIdentityCount, 1)
  assert.equal(snapshot.next_action_sequence, 2)
})

test('concurrent candidate enqueue is serialized and content-deduplicated', async (t) => {
  const directory = await directoryFor(t, 'concurrent-enqueue')
  const ledger = await openLedger(directory)
  t.after(() => ledger.close())

  const firstCandidate = candidate()
  const secondCandidate = candidate({
    url: 'https://synthetic.example.test/SECOND_CONCURRENT_SYNTHETIC_ROUTE',
  })
  const results = await Promise.allSettled([
    ledger.enqueueCandidate({
      candidateDraft: firstCandidate,
      provenance: 'DISCOVERED',
    }),
    ledger.enqueueCandidate({
      candidateDraft: secondCandidate,
      provenance: 'DISCOVERED',
    }),
    ledger.enqueueCandidate({
      candidateDraft: { ...firstCandidate, sequence: 88_000 },
      provenance: 'OPERATOR_SUPPLIED',
    }),
  ])

  assert.deepEqual(results.map(({ status }) => status), [
    'fulfilled',
    'fulfilled',
    'fulfilled',
  ])
  const values = results.map(({ value }) => value)
  assert.equal(values.filter(({ created }) => created).length, 2)
  assert.equal(new Set(values.map(({ actionId }) => actionId)).size, 2)
  assert.deepEqual(
    [...new Set(values.map(({ actionSequence }) => actionSequence))].sort(),
    [1, 2],
  )
  assert.equal(ledger.snapshot().queued_actions, 2)
  assert.equal(ledger.snapshot().record_count, 3)

  await ledger.close()
  const names = await readdir(directory)
  assert.equal(names.some((name) => name.includes('.tmp-')), false)
  const reopened = await openLedger(directory, { initialize: false })
  assert.equal(reopened.snapshot().next_action_sequence, 3)
  await reopened.close()
})

test('an active writer lock cannot be stolen and the owner remains usable', async (t) => {
  const directory = await directoryFor(t, 'active-lock')
  const owner = await openLedger(directory)

  await assert.rejects(
    () => openLedger(directory, {
      initialize: false,
      limits: { lockTimeoutMs: 20, staleLockMs: 0, lockPollMs: 1 },
    }),
    /lock|timed out/i,
  )
  const queued = await owner.enqueueCandidate({
    candidateDraft: candidate(),
    provenance: 'SEALED_PLAN',
  })
  assert.equal(queued.created, true)
  assert.equal(owner.snapshot().queued_actions, 1)
  await owner.close()
})

test('a concurrent opener waits through the lock owner publication window', async (t) => {
  const directory = await directoryFor(t, 'owner-publication-window')
  let entered
  let release
  const enteredPromise = new Promise((resolvePromise) => { entered = resolvePromise })
  const releasePromise = new Promise((resolvePromise) => { release = resolvePromise })
  let held = false
  const firstPromise = openLedger(directory, {
    faultInjector: async (phase) => {
      if (phase !== 'after-lock-directory-created' || held) return
      held = true
      entered()
      await releasePromise
    },
  })
  await enteredPromise
  const secondPromise = openLedger(directory, {
    initialize: false,
    limits: { lockTimeoutMs: 2_000, staleLockMs: 1_000, lockPollMs: 1 },
  })
  release()
  const first = await firstPromise
  await first.close()
  const second = await secondPromise
  await second.close()
  assert.equal(held, true)
})

test('a concurrent opener proceeds while the prior lock retires outside the ledger', { timeout: 10_000 }, async (t) => {
  const directory = await directoryFor(t, 'lock-retirement-window')
  let retirementEntered
  let releaseRetirement
  const retirementEnteredPromise = new Promise((resolvePromise) => {
    retirementEntered = resolvePromise
  })
  const releaseRetirementPromise = new Promise((resolvePromise) => {
    releaseRetirement = resolvePromise
  })
  t.after(() => releaseRetirement())
  let retirementArmed = false
  let retirementPath
  const first = await openLedger(directory, {
    faultInjector: async (phase, detail) => {
      if (!retirementArmed || phase !== 'after-lock-release-quarantine') return
      retirementPath = detail.quarantine
      retirementEntered()
      await releaseRetirementPromise
    },
  })
  retirementArmed = true
  const firstClosePromise = first.close()
  await retirementEnteredPromise
  assert.equal(join(retirementPath, '..'), join(directory, '..'))
  assert.equal((await readdir(directory)).includes('.http-authed-campaign.lock'), false)

  const second = await openLedger(directory, {
    initialize: false,
    limits: { lockTimeoutMs: 2_000, staleLockMs: 1_000, lockPollMs: 1 },
  })
  assert.equal((await readdir(directory)).includes('.http-authed-campaign.lock'), true)

  releaseRetirement()
  await firstClosePromise
  await second.close()
  await assert.rejects(readFile(retirementPath), (error) => error.code === 'ENOENT')
})

test('a forged in-ledger lock retirement name fails closed without deletion', async (t) => {
  const directory = await directoryFor(t, 'forged-lock-retirement')
  const initialized = await openLedger(directory)
  await initialized.close()
  const retirementPath = join(
    directory,
    `.http-authed-campaign.lock.release-${process.pid}-cccccccccccccccccccccccc`,
  )
  await writeFile(retirementPath, 'operator-owned sentinel', 'utf8')

  await assert.rejects(
    openLedger(directory, {
      initialize: false,
    }),
    (error) => error.code === 'HTTP_AUTHED_LEDGER_DIRECTORY_UNSAFE',
  )
  assert.equal(await readFile(retirementPath, 'utf8'), 'operator-owned sentinel')
})

test('an interrupted release quarantine cannot poison ledger projection', async (t) => {
  const directory = await directoryFor(t, 'interrupted-release-quarantine')
  const injectedFailure = new Error('synthetic interruption after release quarantine')
  let retirementArmed = false
  let retirementPath
  const ledger = await openLedger(directory, {
    faultInjector: async (phase, detail) => {
      if (!retirementArmed || phase !== 'after-lock-release-quarantine') return
      retirementPath = detail.quarantine
      throw injectedFailure
    },
  })
  retirementArmed = true

  await assert.rejects(
    ledger.close(),
    (error) => (
      error.code === 'HTTP_AUTHED_LEDGER_LOCK_CHANGED'
      && error.cause === injectedFailure
    ),
  )
  assert.equal(join(retirementPath, '..'), join(directory, '..'))
  assert.match(await readFile(join(retirementPath, 'owner.json'), 'utf8'), /"pid":/)

  const reopened = await openLedger(directory, { initialize: false })
  await reopened.close()
  assert.match(await readFile(join(retirementPath, 'owner.json'), 'utf8'), /"pid":/)
})

test('a failed lock acquisition removes its controller-created partial directory', async (t) => {
  const directory = await directoryFor(t, 'failed-owner-publication-cleanup')
  let injected = false
  await assert.rejects(
    openLedger(directory, {
      faultInjector: async (phase) => {
        if (phase !== 'after-lock-directory-created' || injected) return
        injected = true
        throw new Error('synthetic owner publication failure')
      },
    }),
    /synthetic owner publication failure/,
  )
  assert.equal((await readdir(directory)).includes('.http-authed-campaign.lock'), false)
  const reopened = await openLedger(directory)
  await reopened.close()
})

test('campaign ledger close never deletes a replacement live lock owner', async (t) => {
  const directory = await directoryFor(t, 'release-lock-replacement')
  const lockPath = join(directory, '.http-authed-campaign.lock')
  const ownerPath = join(lockPath, 'owner.json')
  const replacement = stableJson({
    created_at: NOW.toISOString(),
    nonce: '9'.repeat(24),
    pid: process.pid,
  })
  let replacementInstalled = false
  const ledger = await openLedger(directory, {
    faultInjector: async (phase) => {
      if (phase !== 'before-lock-release-quarantine' || replacementInstalled) return
      replacementInstalled = true
      await rm(lockPath, { recursive: true, force: true })
      await mkdir(lockPath)
      await writeFile(ownerPath, replacement)
    },
  })

  await assert.rejects(
    ledger.close(),
    (error) => error.code === 'HTTP_AUTHED_LEDGER_LOCK_CHANGED',
  )
  assert.equal(replacementInstalled, true)
  assert.equal(await readFile(ownerPath, 'utf8'), replacement)
})

test('stale-lock recovery restores a replacement live lock instead of orphaning its owner', async (t) => {
  const directory = await directoryFor(t, 'stale-lock-replacement')
  const initialized = await openLedger(directory)
  await initialized.close()

  const lockPath = join(directory, '.http-authed-campaign.lock')
  const ownerPath = join(lockPath, 'owner.json')
  await mkdir(lockPath)
  await writeFile(ownerPath, stableJson({
    created_at: '2000-01-01T00:00:00.000Z',
    nonce: 'a'.repeat(24),
    pid: 2_147_483_647,
  }))

  const replacementOwner = {
    created_at: new Date().toISOString(),
    nonce: 'b'.repeat(24),
    pid: process.pid,
  }
  const replacementBytes = stableJson(replacementOwner)
  let replaced = false
  const result = await openLedger(directory, {
    initialize: false,
    limits: { lockTimeoutMs: 20, staleLockMs: 0, lockPollMs: 1 },
    faultInjector: async (phase) => {
      if (phase !== 'before-stale-lock-quarantine' || replaced) return
      replaced = true
      const displaced = `${lockPath}.displaced-for-test`
      await rename(lockPath, displaced)
      await rm(displaced, { recursive: true, force: true })
      await mkdir(lockPath)
      await writeFile(ownerPath, replacementBytes)
    },
  }).then(
    async (ledger) => {
      await ledger.close()
      return { ledger: true }
    },
    (error) => ({ error }),
  )

  assert.equal(replaced, true, 'the replacement race must be exercised')
  assert.ok(result.error, 'a replacement live lock must block this opener')
  assert.match(result.error.message, /lock|changed|timed out/i)
  assert.equal(await readFile(ownerPath, 'utf8'), replacementBytes)
})

test('ledger leases and terminalizes one exact candidate without replay', async (t) => {
  const directory = await directoryFor(t, 'lifecycle')
  const ledger = await openLedger(directory)
  const queued = await ledger.enqueueCandidate({
    candidateDraft: candidate(),
    provenance: 'SEALED_PLAN',
  })
  const leased = await ledger.leaseAction({
    candidateDraft: candidate(),
    operatorId: 'example-security-operator',
  })
  assert.equal(leased.actionId, queued.actionId)

  const permit = await ledger.markPreDispatch({
    actionId: leased.actionId,
    leaseId: leased.leaseId,
    phase: 'PROBE',
    requestBindingSha256: 'c'.repeat(64),
  })
  assert.equal(permit.sendPermit, true)
  await assert.rejects(
    () => ledger.markPreDispatch({
      actionId: leased.actionId,
      leaseId: leased.leaseId,
      phase: 'PROBE',
      requestBindingSha256: 'c'.repeat(64),
    }),
    /already|pre.dispatch|replay/i,
  )
  await ledger.markOutcome({
    actionId: leased.actionId,
    leaseId: leased.leaseId,
    phase: 'PROBE',
    outcome: 'SETTLED',
    responseMetadata: { status: 207, bytes: 42, headerNames: ['content-type'] },
  })
  await ledger.terminalizeAction({
    actionId: leased.actionId,
    leaseId: leased.leaseId,
    outcome: 'PROBE_COMPLETED',
  })
  await assert.rejects(
    () => ledger.leaseAction({
      candidateDraft: candidate(),
      operatorId: 'example-security-operator',
    }),
    /terminal|replay|completed/i,
  )
  await ledger.close()
})

test('only shape-bearing ledger records use v1.3 and replay schema metadata without values', async (t) => {
  const directory = await directoryFor(t, 'json-shape-version')
  const ledger = await openLedger(directory)
  await ledger.enqueueCandidate({ candidateDraft: candidate(), provenance: 'SEALED_PLAN' })
  const lease = await ledger.leaseAction({
    candidateDraft: candidate(),
    operatorId: 'example-security-operator',
  })
  await ledger.markPreDispatch({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'PROBE',
    requestBindingSha256: 'c'.repeat(64),
  })
  const shape = jsonShape()
  await ledger.markOutcome({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'PROBE',
    outcome: 'SETTLED',
    responseMetadata: {
      status: 200,
      bytes: 42,
      headerNames: ['content-type'],
      jsonShape: shape,
    },
  })
  assert.deepEqual(ledger.actionState(lease.actionId).phase_outcomes.PROBE.json_shape, shape)
  await ledger.close()

  const names = (await readdir(directory))
    .filter((name) => name.endsWith('.http-authed-campaign.json'))
    .sort()
  const records = await Promise.all(names.map(async (name) => (
    JSON.parse(await readFile(join(directory, name), 'utf8'))
  )))
  const shapeRecord = records.find(({ event }) => event.json_shape !== undefined)
  assert.equal(shapeRecord.schema_version, '1.3.0')
  assert.ok(records
    .filter((record) => record !== shapeRecord)
    .every(({ schema_version: version }) => version === '1.2.0'))
  assert.equal(JSON.stringify(records).includes('response_value'), false)

  const reopened = await openLedger(directory, { initialize: false })
  assert.deepEqual(reopened.actionState(lease.actionId).phase_outcomes.PROBE.json_shape, shape)
  await reopened.close()
})

test('settled observation failure uses v1.4 bounded telemetry and cannot replay', async (t) => {
  const directory = await directoryFor(t, 'json-shape-observation-failed')
  const ledger = await openLedger(directory)
  await ledger.enqueueCandidate({ candidateDraft: candidate(), provenance: 'SEALED_PLAN' })
  const lease = await ledger.leaseAction({
    candidateDraft: candidate(),
    operatorId: 'example-security-operator',
  })
  await ledger.markPreDispatch({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'PROBE',
    requestBindingSha256: 'c'.repeat(64),
  })

  await assert.rejects(
    () => ledger.markOutcome({
      actionId: lease.actionId,
      leaseId: lease.leaseId,
      phase: 'PROBE',
      outcome: 'SETTLED',
      responseMetadata: {
        status: 500,
        bytes: 3000,
        headerNames: ['content-type'],
        responseByteBucket: 'LE_4_KIB',
        failureStageCode: 'JSON_SHAPE_OBSERVATION',
        requestMayHaveBeenSent: true,
      },
    }),
    /observation.failure response metadata/i,
  )

  await ledger.markOutcome({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'PROBE',
    outcome: 'SETTLED',
    responseMetadata: {
      status: 500,
      headerNames: ['content-type', 'x-synthetic-subject-8675309'],
      responseByteBucket: 'LE_4_KIB',
      failureStageCode: 'JSON_SHAPE_OBSERVATION',
      requestMayHaveBeenSent: true,
    },
  })
  const phase = ledger.actionState(lease.actionId).phase_outcomes.PROBE
  assert.deepEqual(phase, {
    outcome: 'SETTLED',
    request_may_have_been_sent: true,
    status: 500,
    header_names: ['content-type', 'other'],
    response_byte_bucket: 'LE_4_KIB',
    failure_stage_code: 'JSON_SHAPE_OBSERVATION',
  })
  await assert.rejects(
    () => ledger.terminalizeAction({
      actionId: lease.actionId,
      leaseId: lease.leaseId,
      outcome: 'PROBE_COMPLETED',
    }),
    /observation|completed|settled/i,
  )
  await ledger.terminalizeAction({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    outcome: 'PROBE_OBSERVATION_FAILED',
    reasonCode: 'PROBE_JSON_SHAPE_OBSERVATION_FAILED',
  })
  await ledger.close()

  const records = await Promise.all((await readdir(directory))
    .filter((name) => name.endsWith('.http-authed-campaign.json'))
    .map(async (name) => JSON.parse(await readFile(join(directory, name), 'utf8'))))
  const failureRecord = records.find(({ event }) => event.failure_stage_code !== undefined)
  assert.equal(failureRecord.schema_version, '1.4.0')
  assert.deepEqual(failureRecord.event, {
    type: 'REQUEST_SETTLED',
    action_id: lease.actionId,
    lease_id: lease.leaseId,
    phase: 'PROBE',
    outcome: 'SETTLED',
    status: 500,
    header_names: ['content-type', 'other'],
    request_may_have_been_sent: true,
    response_byte_bucket: 'LE_4_KIB',
    failure_stage_code: 'JSON_SHAPE_OBSERVATION',
  })
  assert.equal(Object.hasOwn(failureRecord.event, 'bytes'), false)
  assert.doesNotMatch(JSON.stringify(records), /8675309|cause|error_text/i)

  const reopened = await openLedger(directory, { initialize: false })
  const state = reopened.actionState(lease.actionId)
  assert.equal(state.terminal, true)
  assert.equal(state.outcome, 'PROBE_OBSERVATION_FAILED')
  await assert.rejects(
    () => reopened.leaseAction({
      candidateDraft: candidate(),
      operatorId: 'example-security-operator',
    }),
    /terminal|replay/i,
  )
  await reopened.close()
})

test('ledger rejects value-bearing shape extensions before append', async (t) => {
  const directory = await directoryFor(t, 'json-shape-invalid')
  const ledger = await openLedger(directory)
  await ledger.enqueueCandidate({ candidateDraft: candidate(), provenance: 'SEALED_PLAN' })
  const lease = await ledger.leaseAction({
    candidateDraft: candidate(),
    operatorId: 'example-security-operator',
  })
  await ledger.markPreDispatch({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'PROBE',
    requestBindingSha256: 'c'.repeat(64),
  })
  const recordCount = ledger.snapshot().record_count
  await assert.rejects(
    ledger.markOutcome({
      actionId: lease.actionId,
      leaseId: lease.leaseId,
      phase: 'PROBE',
      outcome: 'SETTLED',
      responseMetadata: {
        status: 200,
        bytes: 42,
        headerNames: [],
        jsonShape: jsonShape({ response_value: 'MUST_NOT_PERSIST' }),
      },
    }),
    (error) => error.code === 'HTTP_AUTHED_LEDGER_RESPONSE_INVALID',
  )
  assert.equal(ledger.snapshot().record_count, recordCount)
  await ledger.close()
})

test('lease identity and action kind enforce legal dispatch transitions', async (t) => {
  const directory = await directoryFor(t, 'illegal-transition')
  const ledger = await openLedger(directory)
  await ledger.enqueueCandidate({
    candidateDraft: candidate(),
    provenance: 'SEALED_PLAN',
  })
  const leased = await ledger.leaseAction({
    candidateDraft: candidate(),
    operatorId: 'example-security-operator',
  })

  await assert.rejects(
    () => ledger.markPreDispatch({
      actionId: leased.actionId,
      leaseId: '00000000-0000-4000-8000-000000000000',
      phase: 'PROBE',
      requestBindingSha256: 'c'.repeat(64),
    }),
    /lease|stale/i,
  )
  await assert.rejects(
    () => ledger.markOutcome({
      actionId: leased.actionId,
      leaseId: leased.leaseId,
      phase: 'PROBE',
      outcome: 'SETTLED',
      responseMetadata: { status: 200, bytes: 0, headerNames: [] },
    }),
    /pre.dispatch|phase|outcome/i,
  )
  await assert.rejects(
    () => ledger.markPreDispatch({
      actionId: leased.actionId,
      leaseId: leased.leaseId,
      phase: 'MUTATION',
      requestBindingSha256: 'd'.repeat(64),
    }),
    /kind|probe|phase|transition/i,
  )
  await assert.rejects(
    () => ledger.terminalizeAction({
      actionId: leased.actionId,
      leaseId: leased.leaseId,
      outcome: 'PROBE_COMPLETED',
    }),
    /settled|complete|transition|state/i,
  )

  assert.equal(ledger.actionState(leased.actionId).state, 'LEASED')
  const permit = await ledger.markPreDispatch({
    actionId: leased.actionId,
    leaseId: leased.leaseId,
    phase: 'PROBE',
    requestBindingSha256: 'e'.repeat(64),
  })
  assert.equal(permit.sendPermit, true)
  await ledger.close()
})

test('mutation phases require their exact predecessor state and verification cannot replay', async (t) => {
  const directory = await directoryFor(t, 'mutation-phase-order')
  const ledger = await openLedger(directory)
  const mutation = candidate({ kind: 'mutate', method: 'PATCH' })
  delete mutation.expected_effect
  await ledger.enqueueCandidate({ candidateDraft: mutation, provenance: 'SEALED_PLAN' })
  const lease = await ledger.leaseAction({
    candidateDraft: mutation,
    operatorId: 'example-security-operator',
  })

  for (const phase of ['BEFORE_READ', 'AFTER_READ', 'ROLLBACK', 'ROLLBACK_VERIFY']) {
    await assert.rejects(
      () => ledger.markPreDispatch({
        actionId: lease.actionId,
        leaseId: lease.leaseId,
        phase,
        requestBindingSha256: '2'.repeat(64),
      }),
      /phase|state|transition|predecessor/i,
    )
  }

  await recordVerifiedBeforeState(ledger, lease)
  await assert.rejects(
    () => ledger.recordVerification({
      actionId: lease.actionId,
      leaseId: lease.leaseId,
      phase: 'BEFORE_READ',
      valueMatch: true,
      contextMatch: true,
    }),
    /verification|state|replay|transition/i,
  )
  await assert.rejects(
    () => ledger.markPreDispatch({
      actionId: lease.actionId,
      leaseId: lease.leaseId,
      phase: 'AFTER_READ',
      requestBindingSha256: '5'.repeat(64),
    }),
    /phase|state|transition|predecessor/i,
  )
  await ledger.close()
})

test('durable mutation pre-dispatch reopens only for cleanup and is never resent', async (t) => {
  const directory = await directoryFor(t, 'uncertain')
  const ledger = await openLedger(directory)
  const mutation = candidate({ kind: 'mutate', method: 'PATCH' })
  delete mutation.expected_effect
  await ledger.enqueueCandidate({ candidateDraft: mutation, provenance: 'SEALED_PLAN' })
  const leased = await ledger.leaseAction({
    candidateDraft: mutation,
    operatorId: 'example-security-operator',
  })
  await recordVerifiedBeforeState(ledger, leased)
  await ledger.consumeAuthorization({
    actionId: leased.actionId,
    leaseId: leased.leaseId,
    nonce: 'SYNTHETIC_AUTHORIZATION_NONCE_0001',
    dispatchPermitSha256: '9'.repeat(64),
  })
  await ledger.markPreDispatch({
    actionId: leased.actionId,
    leaseId: leased.leaseId,
    phase: 'MUTATION',
    requestBindingSha256: 'd'.repeat(64),
  })
  await ledger.close()

  const recovered = await openLedger(directory, { initialize: false })
  const state = recovered.actionState(leased.actionId)
  assert.equal(state.state, 'MUTATION_FAILED')
  assert.equal(state.terminal, false)
  assert.equal(state.phase_outcomes.MUTATION.request_may_have_been_sent, true)
  assert.equal(recovered.snapshot().stopped, true)
  await assert.rejects(
    () => recovered.leaseAction({
      candidateDraft: mutation,
      operatorId: 'example-security-operator',
    }),
    /stopped|state|replay|leased|dispatched/i,
  )
  const cleanupPermit = await recovered.markPreDispatch({
    actionId: leased.actionId,
    leaseId: leased.leaseId,
    phase: 'ROLLBACK',
    requestBindingSha256: 'e'.repeat(64),
  })
  assert.equal(cleanupPermit.sendPermit, true)
  await recovered.close()
})

test('a crash after leasing but before dispatch terminalizes without replay', async (t) => {
  const directory = await directoryFor(t, 'leased-before-send')
  const ledger = await openLedger(directory)
  await ledger.enqueueCandidate({ candidateDraft: candidate(), provenance: 'SEALED_PLAN' })
  const leased = await ledger.leaseAction({
    candidateDraft: candidate(),
    operatorId: 'example-security-operator',
  })
  await ledger.close()

  const recovered = await openLedger(directory, { initialize: false })
  assert.equal(recovered.actionState(leased.actionId).outcome, 'FAILED_BEFORE_SEND')
  await assert.rejects(
    () => recovered.leaseAction({
      candidateDraft: candidate(),
      operatorId: 'example-security-operator',
    }),
    /terminal|failed|replay/i,
  )
  await recovered.close()
})

test('a failed settled probe recovers as uncertain instead of completed', async (t) => {
  const directory = await directoryFor(t, 'failed-probe-recovery')
  const ledger = await openLedger(directory)
  await ledger.enqueueCandidate({ candidateDraft: candidate(), provenance: 'SEALED_PLAN' })
  const lease = await ledger.leaseAction({
    candidateDraft: candidate(),
    operatorId: 'example-security-operator',
  })
  await ledger.markPreDispatch({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'PROBE',
    requestBindingSha256: 'a'.repeat(64),
  })
  await ledger.markOutcome({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'PROBE',
    outcome: 'FAILED',
    responseMetadata: {
      status: null,
      bytes: 0,
      headerNames: [],
      requestMayHaveBeenSent: true,
    },
  })
  await ledger.close()

  const recovered = await openLedger(directory, { initialize: false })
  const state = recovered.actionState(lease.actionId)
  assert.equal(state.terminal, true)
  assert.equal(state.outcome, 'DELIVERY_UNCERTAIN')
  await recovered.close()
})

test('a settled observation failure recovers terminally without retry or uncertainty', async (t) => {
  const directory = await directoryFor(t, 'observation-failure-recovery')
  const ledger = await openLedger(directory)
  await ledger.enqueueCandidate({ candidateDraft: candidate(), provenance: 'SEALED_PLAN' })
  const lease = await ledger.leaseAction({
    candidateDraft: candidate(),
    operatorId: 'example-security-operator',
  })
  await ledger.markPreDispatch({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'PROBE',
    requestBindingSha256: 'a'.repeat(64),
  })
  await ledger.markOutcome({
    actionId: lease.actionId,
    leaseId: lease.leaseId,
    phase: 'PROBE',
    outcome: 'SETTLED',
    responseMetadata: {
      status: 500,
      headerNames: ['content-type'],
      responseByteBucket: 'LE_1_KIB',
      failureStageCode: 'JSON_SHAPE_OBSERVATION',
      requestMayHaveBeenSent: true,
    },
  })
  await ledger.close()

  const recovered = await openLedger(directory, { initialize: false })
  const state = recovered.actionState(lease.actionId)
  assert.equal(state.terminal, true)
  assert.equal(state.outcome, 'PROBE_OBSERVATION_FAILED')
  assert.equal(recovered.snapshot().stopped, true)
  assert.equal(recovered.snapshot().stop_reason, 'TARGET_HEALTH_DEGRADED')
  await assert.rejects(
    () => recovered.leaseAction({
      candidateDraft: candidate(),
      operatorId: 'example-security-operator',
    }),
    /terminal|replay/i,
  )
  await recovered.close()
})

test('a queued discovery without persisted URL bytes becomes an explicit restart gap', async (t) => {
  const directory = await directoryFor(t, 'queued-discovery-restart')
  const ledger = await openLedger(directory)
  const discovered = candidate({
    url: 'https://synthetic.example.test/SYNTHETIC_DISCOVERED_RESTART_ROUTE',
  })
  const queued = await ledger.enqueueCandidate({
    candidateDraft: discovered,
    provenance: 'DISCOVERED',
  })
  await ledger.close()

  const recovered = await openLedger(directory, { initialize: false })
  const state = recovered.actionState(queued.actionId)
  assert.equal(state.terminal, true)
  assert.equal(state.outcome, 'CAMPAIGN_STOPPED')
  assert.equal(recovered.snapshot().queued_actions, 0)
  await recovered.close()
})

test('mutation authorization permits are durably consumed once before write dispatch', async (t) => {
  const directory = await directoryFor(t, 'authorization-replay')
  const ledger = await openLedger(directory)
  const first = candidate({ kind: 'mutate', method: 'PATCH' })
  delete first.expected_effect
  const second = candidate({
    kind: 'mutate',
    method: 'DELETE',
    url: 'https://synthetic.example.test/SECOND_MUTATION_ROUTE',
  })
  delete second.expected_effect
  await ledger.enqueueCandidate({ candidateDraft: first, provenance: 'SEALED_PLAN' })
  await ledger.enqueueCandidate({ candidateDraft: second, provenance: 'SEALED_PLAN' })
  const firstLease = await ledger.leaseAction({
    candidateDraft: first,
    operatorId: 'example-security-operator',
  })
  const secondLease = await ledger.leaseAction({
    candidateDraft: second,
    operatorId: 'example-security-operator',
  })
  await recordVerifiedBeforeState(ledger, firstLease, '4'.repeat(64))
  await recordVerifiedBeforeState(ledger, secondLease, '5'.repeat(64))
  const nonce = 'SYNTHETIC_AUTHORIZATION_NONCE_REPLAY_SENTINEL'
  const binding = '7'.repeat(64)
  await ledger.consumeAuthorization({
    actionId: firstLease.actionId,
    leaseId: firstLease.leaseId,
    nonce,
    dispatchPermitSha256: binding,
  })
  await assert.rejects(
    () => ledger.consumeAuthorization({
      actionId: firstLease.actionId,
      leaseId: firstLease.leaseId,
      nonce,
      dispatchPermitSha256: binding,
    }),
    /authorization|consum|replay|nonce/i,
  )
  await assert.rejects(
    () => ledger.consumeAuthorization({
      actionId: secondLease.actionId,
      leaseId: secondLease.leaseId,
      nonce,
      dispatchPermitSha256: '8'.repeat(64),
    }),
    /authorization|consum|replay|nonce/i,
  )
  await assert.rejects(
    () => ledger.markPreDispatch({
      actionId: secondLease.actionId,
      leaseId: secondLease.leaseId,
      phase: 'MUTATION',
      requestBindingSha256: '6'.repeat(64),
    }),
    /authorization|permit|consum/i,
  )
  await ledger.close()

  const durable = (await Promise.all(
    (await readdir(directory))
      .filter((name) => name.endsWith('.json'))
      .map((name) => readFile(join(directory, name), 'utf8')),
  )).join('\n')
  assert.doesNotMatch(durable, new RegExp(nonce))
})

test('ledger records contain no raw candidate, body, credential, or header values', async (t) => {
  const directory = await directoryFor(t, 'redaction')
  const ledger = await openLedger(directory)
  const secretCandidate = candidate({
    url: 'https://synthetic.example.test/SYNTHETIC_PRIVATE_PATH_MARKER',
    request_body: {
      body_id: 'SYNTHETIC_SECRET_BODY_IDENTIFIER',
      sha256: 'e'.repeat(64),
      byte_length: 4,
      content_type: 'application/json',
      data_class: 'synthetic_non_phi',
    },
  })
  const queued = await ledger.enqueueCandidate({
    candidateDraft: secretCandidate,
    provenance: 'SEALED_PLAN',
  })
  const leased = await ledger.leaseAction({
    candidateDraft: secretCandidate,
    operatorId: 'example-security-operator',
  })
  await ledger.markPreDispatch({
    actionId: queued.actionId,
    leaseId: leased.leaseId,
    phase: 'PROBE',
    requestBindingSha256: 'f'.repeat(64),
  })
  await ledger.markOutcome({
    actionId: queued.actionId,
    leaseId: leased.leaseId,
    phase: 'PROBE',
    outcome: 'SETTLED',
    responseMetadata: {
      status: 200,
      bytes: 4,
      headerNames: ['set-cookie', 'x-synthetic-patient-identifier-67890'],
      headerValues: ['SYNTHETIC_SECRET_COOKIE_VALUE'],
      body: 'SYNTHETIC_SECRET_RESPONSE_BODY',
    },
  })
  await ledger.close()

  const names = await readdir(directory)
  const rendered = (await Promise.all(
    names.filter((name) => name.endsWith('.json'))
      .map((name) => readFile(join(directory, name), 'utf8')),
  )).join('\n')
  assert.doesNotMatch(rendered, /SYNTHETIC_PRIVATE_PATH_MARKER/)
  assert.doesNotMatch(rendered, /SYNTHETIC_SECRET_BODY_IDENTIFIER/)
  assert.doesNotMatch(rendered, /SYNTHETIC_SECRET_COOKIE_VALUE/)
  assert.doesNotMatch(rendered, /SYNTHETIC_SECRET_RESPONSE_BODY/)
  assert.doesNotMatch(rendered, /patient-identifier-67890/)
  assert.match(rendered, /"other"/)
})

test('ledger rejects a modified canonical record and a truncated tail', async (t) => {
  const directory = await directoryFor(t, 'tamper')
  const ledger = await openLedger(directory)
  await ledger.enqueueCandidate({ candidateDraft: candidate(), provenance: 'SEALED_PLAN' })
  await ledger.close()

  const records = (await readdir(directory)).filter((name) => name.endsWith('.json')).sort()
  const target = join(directory, records.at(-1))
  const original = await readFile(target, 'utf8')
  await writeFile(target, original.replace('CANDIDATE_ENQUEUED', 'CANDIDATE_REWRITTEN'), 'utf8')
  await assert.rejects(
    () => openLedger(directory, { initialize: false }),
    /canonical|hash|event|record|tamper/i,
  )

  await writeFile(target, original, 'utf8')
  await appendFile(target, '{truncated')
  await assert.rejects(
    () => openLedger(directory, { initialize: false }),
    /canonical|json|record|truncat/i,
  )
})

test('a trusted head rejects deletion of a valid final record', async (t) => {
  const directory = await directoryFor(t, 'trusted-head-tail-deletion')
  const ledger = await openLedger(directory)
  await ledger.enqueueCandidate({ candidateDraft: candidate(), provenance: 'SEALED_PLAN' })
  const snapshot = ledger.snapshot()
  const trustedHead = {
    recordCount: snapshot.record_count,
    headSha256: snapshot.head_sha256,
  }
  await ledger.close()

  const records = (await readdir(directory)).filter((name) => name.endsWith('.json')).sort()
  await unlink(join(directory, records.at(-1)))
  const result = await openLedger(directory, {
    initialize: false,
    trustedHead,
  }).then(
    async (opened) => {
      await opened.close()
      return { opened: true }
    },
    (error) => ({ error }),
  )
  assert.ok(result.error, 'a valid-prefix tail deletion must be rejected against the trusted head')
  assert.match(result.error.message, /trusted|head|record|rollback|truncat/i)
})

test('a trusted head anchors its exact retained prefix while allowing newer records', async (t) => {
  const directory = await directoryFor(t, 'trusted-head-prefix')
  const ledger = await openLedger(directory)
  await ledger.enqueueCandidate({ candidateDraft: candidate(), provenance: 'SEALED_PLAN' })
  const retained = ledger.snapshot()
  await ledger.enqueueCandidate({
    candidateDraft: candidate({
      url: 'https://synthetic.example.test/SYNTHETIC_NEWER_TRUSTED_HEAD_ROUTE',
    }),
    provenance: 'SEALED_PLAN',
  })
  await ledger.close()

  const reopened = await openLedger(directory, {
    initialize: false,
    trustedHead: {
      recordCount: retained.record_count,
      headSha256: retained.head_sha256,
    },
  })
  assert.equal(reopened.snapshot().record_count, retained.record_count + 1)
  await reopened.close()
})

for (const terminalizedBeforeCrash of [false, true]) {
  test(`response-derived stop survives a crash ${terminalizedBeforeCrash ? 'after' : 'before'} action terminalization`, async (t) => {
    const directory = await directoryFor(
      t,
      terminalizedBeforeCrash ? 'status-stop-after-terminal' : 'status-stop-after-settlement',
    )
    const ledger = await openLedger(directory)
    const firstCandidate = candidate({ url: 'https://synthetic.example.test/FIRST_STOP_ROUTE' })
    const secondCandidate = candidate({ url: 'https://synthetic.example.test/SECOND_BLOCKED_ROUTE' })
    await ledger.enqueueCandidate({ candidateDraft: firstCandidate, provenance: 'SEALED_PLAN' })
    await ledger.enqueueCandidate({ candidateDraft: secondCandidate, provenance: 'SEALED_PLAN' })
    const first = await ledger.leaseAction({
      candidateDraft: firstCandidate,
      operatorId: 'example-security-operator',
    })
    await ledger.markPreDispatch({
      actionId: first.actionId,
      leaseId: first.leaseId,
      phase: 'PROBE',
      requestBindingSha256: 'd'.repeat(64),
    })
    await ledger.markOutcome({
      actionId: first.actionId,
      leaseId: first.leaseId,
      phase: 'PROBE',
      outcome: 'SETTLED',
      responseMetadata: {
        status: 500,
        bytes: 0,
        headerNames: [],
        requestMayHaveBeenSent: true,
      },
    })
    if (terminalizedBeforeCrash) {
      await ledger.terminalizeAction({
        actionId: first.actionId,
        leaseId: first.leaseId,
        outcome: 'PROBE_COMPLETED',
      })
    }
    await ledger.close()

    const recovered = await openLedger(directory, { initialize: false })
    const snapshot = recovered.snapshot()
    assert.equal(snapshot.stopped, true)
    assert.equal(snapshot.stop_reason, 'TARGET_HEALTH_DEGRADED')
    assert.equal(recovered.actionState(first.actionId).terminal, true)
    await assert.rejects(
      () => recovered.leaseAction({
        candidateDraft: secondCandidate,
        operatorId: 'example-security-operator',
      }),
      /stopped|current state/i,
    )
    await recovered.close()
  })
}

for (const terminalizedBeforeCrash of [false, true]) {
  test(`mutation response stop survives a crash ${terminalizedBeforeCrash ? 'after' : 'before'} action terminalization`, async (t) => {
    const directory = await directoryFor(
      t,
      terminalizedBeforeCrash
        ? 'mutation-status-stop-after-terminal'
        : 'mutation-status-stop-after-settlement',
    )
    const ledger = await openLedger(directory)
    const mutation = candidate({ kind: 'mutate', method: 'PATCH' })
    delete mutation.expected_effect
    const secondCandidate = candidate({
      url: 'https://synthetic.example.test/SECOND_AFTER_MUTATION_STOP_ROUTE',
    })
    await ledger.enqueueCandidate({ candidateDraft: mutation, provenance: 'SEALED_PLAN' })
    await ledger.enqueueCandidate({ candidateDraft: secondCandidate, provenance: 'SEALED_PLAN' })
    const first = await ledger.leaseAction({
      candidateDraft: mutation,
      operatorId: 'example-security-operator',
    })
    await ledger.markPreDispatch({
      actionId: first.actionId,
      leaseId: first.leaseId,
      phase: 'CREDENTIAL_PREFLIGHT',
      requestBindingSha256: 'f'.repeat(64),
    })
    await ledger.markOutcome({
      actionId: first.actionId,
      leaseId: first.leaseId,
      phase: 'CREDENTIAL_PREFLIGHT',
      outcome: 'SETTLED',
      responseMetadata: {
        status: 500,
        bytes: 0,
        headerNames: [],
        requestMayHaveBeenSent: true,
      },
    })
    if (terminalizedBeforeCrash) {
      await ledger.terminalizeAction({
        actionId: first.actionId,
        leaseId: first.leaseId,
        outcome: 'FAILED_BEFORE_MUTATION',
        reasonCode: 'CREDENTIAL_PREFLIGHT_FAILED',
      })
    }
    await ledger.close()

    const recovered = await openLedger(directory, { initialize: false })
    const snapshot = recovered.snapshot()
    assert.equal(snapshot.stopped, true)
    assert.equal(snapshot.stop_reason, 'TARGET_HEALTH_DEGRADED')
    assert.equal(recovered.actionState(first.actionId).terminal, true)
    await assert.rejects(
      () => recovered.leaseAction({
        candidateDraft: secondCandidate,
        operatorId: 'example-security-operator',
      }),
      /stopped|current state/i,
    )
    await recovered.close()
  })
}

for (const status of [304, 305, 306]) {
  test(`ledger replay does not reinterpret non-redirect HTTP status ${status} as a campaign stop`, async (t) => {
    const directory = await directoryFor(t, `non-redirect-${status}`)
    const ledger = await openLedger(directory)
    const firstCandidate = candidate({
      url: `https://synthetic.example.test/NON_REDIRECT_${status}_ROUTE`,
    })
    const secondCandidate = candidate({
      url: 'https://synthetic.example.test/CONTINUATION_ROUTE',
    })
    await ledger.enqueueCandidate({ candidateDraft: firstCandidate, provenance: 'SEALED_PLAN' })
    await ledger.enqueueCandidate({ candidateDraft: secondCandidate, provenance: 'SEALED_PLAN' })
    const first = await ledger.leaseAction({
      candidateDraft: firstCandidate,
      operatorId: 'example-security-operator',
    })
    await ledger.markPreDispatch({
      actionId: first.actionId,
      leaseId: first.leaseId,
      phase: 'PROBE',
      requestBindingSha256: 'd'.repeat(64),
    })
    await ledger.markOutcome({
      actionId: first.actionId,
      leaseId: first.leaseId,
      phase: 'PROBE',
      outcome: 'SETTLED',
      responseMetadata: {
        status,
        bytes: 0,
        headerNames: [],
        requestMayHaveBeenSent: true,
      },
    })
    await ledger.terminalizeAction({
      actionId: first.actionId,
      leaseId: first.leaseId,
      outcome: 'PROBE_COMPLETED',
    })
    await ledger.close()

    const recovered = await openLedger(directory, { initialize: false })
    assert.equal(recovered.snapshot().stopped, false)
    assert.equal(recovered.snapshot().stop_reason, null)
    const continuation = await recovered.leaseAction({
      candidateDraft: secondCandidate,
      operatorId: 'example-security-operator',
    })
    assert.equal(continuation.allocatedAction.url, secondCandidate.url)
    await recovered.close()
  })
}

test('ledger rejects unexpected directory entries without deleting them', async (t) => {
  const directory = await directoryFor(t, 'unexpected-entry')
  const ledger = await openLedger(directory)
  await ledger.close()
  const unexpected = join(directory, 'operator-notes.txt')
  await writeFile(unexpected, 'must not be interpreted or removed', 'utf8')

  await assert.rejects(
    () => openLedger(directory, { initialize: false }),
    /unexpected|unsafe/i,
  )
  assert.equal(await readFile(unexpected, 'utf8'), 'must not be interpreted or removed')
})

test('ledger rejects a symlink or junction in an ancestor path', async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'rta-http-authed-ledger-linked-ancestor-'))
  t.after(() => rm(parent, { recursive: true, force: true }))
  const realParent = join(parent, 'real-parent')
  const linkedParent = join(parent, 'linked-parent')
  await mkdir(realParent)
  try {
    await symlink(
      realParent,
      linkedParent,
      process.platform === 'win32' ? 'junction' : 'dir',
    )
  } catch (error) {
    if (['EPERM', 'EACCES'].includes(error.code)) {
      t.skip('directory symlink/junction creation is unavailable')
      return
    }
    throw error
  }

  const result = await openLedger(join(linkedParent, 'campaign-ledger'))
    .then((ledger) => ({ ledger }), (error) => ({ error }))
  await result.ledger?.close()
  assert.ok(result.error, 'linked ancestor must be rejected')
  assert.match(result.error.message, /ancestor|alias|junction|link/i)
})
