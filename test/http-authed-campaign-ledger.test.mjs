import assert from 'node:assert/strict'
import {
  appendFile,
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
} from '../scripts/lib/http-authed-campaign-ledger.mjs'
import { canonicalJson, sha256Hex } from '../scripts/lib/http-authed-contracts.mjs'
import { stableJson } from '../scripts/lib/run-engine.mjs'

const GRANT = 'a'.repeat(64)
const DOCUMENT = 'b'.repeat(64)
const NOW = new Date('2026-08-17T12:00:00.000Z')

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
    authorizationDocumentSha256: DOCUMENT,
    operatorId: 'peerstar-security-operator',
    initialize: true,
    now: () => NOW,
    limits: { lockTimeoutMs: 100, staleLockMs: 1, lockPollMs: 1 },
    ...additions,
  })
}

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
    operatorId: 'peerstar-security-operator',
  })
  await ledger.close()

  const records = await Promise.all((await readdir(directory))
    .filter((name) => name.endsWith('.http-authed-campaign.json'))
    .map(async (name) => JSON.parse(await readFile(join(directory, name), 'utf8'))))
  const genesis = records.find(({ event }) => event.type === 'CAMPAIGN_OPENED')
  const leases = records.filter(({ event }) => event.type === 'ACTION_LEASED')
  assert.equal(genesis.event.operator_id, 'peerstar-security-operator')
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
    operatorId: 'peerstar-security-operator',
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
      operatorId: 'peerstar-security-operator',
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
    operatorId: 'peerstar-security-operator',
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
    operatorId: 'peerstar-security-operator',
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
      operatorId: 'peerstar-security-operator',
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
    operatorId: 'peerstar-security-operator',
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
    operatorId: 'peerstar-security-operator',
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
    operatorId: 'peerstar-security-operator',
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
    operatorId: 'peerstar-security-operator',
  })
  await recordVerifiedBeforeState(ledger, leased)
  await ledger.consumeApproval({
    actionId: leased.actionId,
    leaseId: leased.leaseId,
    nonce: 'SYNTHETIC_APPROVAL_NONCE_0001',
    countersignatureBindingSha256: '9'.repeat(64),
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
      operatorId: 'peerstar-security-operator',
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
    operatorId: 'peerstar-security-operator',
  })
  await ledger.close()

  const recovered = await openLedger(directory, { initialize: false })
  assert.equal(recovered.actionState(leased.actionId).outcome, 'FAILED_BEFORE_SEND')
  await assert.rejects(
    () => recovered.leaseAction({
      candidateDraft: candidate(),
      operatorId: 'peerstar-security-operator',
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
    operatorId: 'peerstar-security-operator',
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
    operatorId: 'peerstar-security-operator',
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
  assert.equal(recovered.snapshot().stopped, false)
  await assert.rejects(
    () => recovered.leaseAction({
      candidateDraft: candidate(),
      operatorId: 'peerstar-security-operator',
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

test('mutation approval nonces are durably consumed once before write dispatch', async (t) => {
  const directory = await directoryFor(t, 'approval-replay')
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
    operatorId: 'peerstar-security-operator',
  })
  const secondLease = await ledger.leaseAction({
    candidateDraft: second,
    operatorId: 'peerstar-security-operator',
  })
  await recordVerifiedBeforeState(ledger, firstLease, '4'.repeat(64))
  await recordVerifiedBeforeState(ledger, secondLease, '5'.repeat(64))
  const nonce = 'SYNTHETIC_APPROVAL_NONCE_REPLAY_SENTINEL'
  const binding = '7'.repeat(64)
  await ledger.consumeApproval({
    actionId: firstLease.actionId,
    leaseId: firstLease.leaseId,
    nonce,
    countersignatureBindingSha256: binding,
  })
  await assert.rejects(
    () => ledger.consumeApproval({
      actionId: firstLease.actionId,
      leaseId: firstLease.leaseId,
      nonce,
      countersignatureBindingSha256: binding,
    }),
    /approval|consum|replay|nonce/i,
  )
  await assert.rejects(
    () => ledger.consumeApproval({
      actionId: secondLease.actionId,
      leaseId: secondLease.leaseId,
      nonce,
      countersignatureBindingSha256: '8'.repeat(64),
    }),
    /approval|consum|replay|nonce/i,
  )
  await assert.rejects(
    () => ledger.markPreDispatch({
      actionId: secondLease.actionId,
      leaseId: secondLease.leaseId,
      phase: 'MUTATION',
      requestBindingSha256: '6'.repeat(64),
    }),
    /approval|countersign|consum/i,
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
    operatorId: 'peerstar-security-operator',
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
