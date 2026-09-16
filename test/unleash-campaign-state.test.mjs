import assert from 'node:assert/strict'
import { resolve } from 'node:path'
import { test } from 'node:test'

import {
  UnleashCampaignStateError,
  appendUnleashCampaignState,
  assertValidUnleashCampaignState,
  nextUnleashCampaignState,
  recoverUnleashCampaignState,
} from '../scripts/lib/unleash-campaign-state.mjs'
import { digestUnleashValue } from '../scripts/lib/unleash-contracts.mjs'

const RUN_DIRECTORY = resolve('C:/synthetic/LastAperture/campaigns/campaign-0123456789abcdef01234567')
const TARGET = Object.freeze({
  family: 'https',
  canonical_locator: 'https://example.test/',
  target_id: `target:sha256:${'1'.repeat(64)}`,
  supplied_sha256: '2'.repeat(64),
})

function initialState(overrides = {}) {
  return {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-state',
    revision: 1,
    updated_at: '2026-09-15T09:30:00.000Z',
    campaign_id: `campaign:sha256:${'3'.repeat(64)}`,
    status: 'PLANNED',
    run_directory: RUN_DIRECTORY,
    plan_sha256: '4'.repeat(64),
    target: structuredClone(TARGET),
    completed_routes: [],
    route_counts: {
      total: 29,
      ready: 1,
      waiting: 10,
      unavailable: 18,
      not_applicable: 0,
      blocked: 0,
    },
    gap_count: 28,
    recon_bundle: resolve(RUN_DIRECTORY, 'recon'),
    evidence_packet_path: null,
    evidence_packet_sha256: null,
    completion_receipt_sha256: null,
    stop_reason: null,
    failure: null,
    ...overrides,
  }
}

function initialV2State(overrides = {}) {
  return {
    ...initialState(),
    schema_version: '2.0.0',
    swarm_basis_sha256: null,
    swarm_completion_sha256: null,
    candidate_frontier_sha256: null,
    candidate_frontier_head_sha256: null,
    swarm_gap_count: 0,
    ...overrides,
  }
}

function memoryStorage({ failEvent = false, failSnapshot = false } = {}) {
  const files = new Map()
  const operations = []
  return {
    files,
    operations,
    writeImmutableJson: async (filename, value) => {
      operations.push(`event:${filename}`)
      if (failEvent) throw Object.assign(new Error('uncertain publication'), { code: 'SYNTHETIC_WRITE_UNCERTAIN' })
      if (files.has(filename)) throw Object.assign(new Error('exists'), { code: 'UNLEASH_STORAGE_FILE_EXISTS' })
      files.set(filename, structuredClone(value))
      return filename
    },
    replaceMutableJson: async (filename, value) => {
      operations.push(`snapshot:${filename}`)
      if (failSnapshot) throw Object.assign(new Error('snapshot failed'), { code: 'SYNTHETIC_SNAPSHOT_FAILED' })
      files.set(filename, structuredClone(value))
      return filename
    },
    readJson: async (filename) => {
      if (!files.has(filename)) throw Object.assign(new Error('missing'), { code: 'UNLEASH_STORAGE_FILE_NOT_FOUND' })
      return structuredClone(files.get(filename))
    },
    listJsonFilenames: async () => Object.freeze([...files.keys()].sort()),
  }
}

function rejectsCode(code) {
  return (error) => error instanceof UnleashCampaignStateError && error.code === code
}

test('publishes each immutable transition before updating the mutable snapshot', async () => {
  const storage = memoryStorage()
  const planned = await appendUnleashCampaignState({ storage, nextState: initialState() })
  const running = nextUnleashCampaignState(planned, { status: 'RUNNING' }, '2026-09-15T09:30:01.000Z')
  await appendUnleashCampaignState({ storage, previousState: planned, nextState: running })

  assert.deepEqual(storage.operations, [
    'event:campaign-event-000001.json',
    'snapshot:campaign-state.json',
    'event:campaign-event-000002.json',
    'snapshot:campaign-state.json',
  ])
  const first = storage.files.get('campaign-event-000001.json')
  const second = storage.files.get('campaign-event-000002.json')
  assert.equal(first.previous_state_sha256, null)
  assert.equal(first.state_sha256, digestUnleashValue(planned))
  assert.equal(second.previous_state_sha256, digestUnleashValue(planned))
  assert.equal(second.state_sha256, digestUnleashValue(running))
  assert.deepEqual(storage.files.get('campaign-state.json'), running)
})

test('validates exact state fields and semantic status claims', () => {
  assert.equal(assertValidUnleashCampaignState(initialState()).status, 'PLANNED')
  for (const change of [
    { unknown: true },
    { revision: 0 },
    { gap_count: 27 },
    { status: 'COMPLETE_WITH_GAPS' },
    { status: 'STOPPED', stop_reason: null },
    { status: 'RECONCILIATION_REQUIRED', failure: null },
    { recon_bundle: resolve(RUN_DIRECTORY, 'elsewhere') },
  ]) {
    assert.throws(() => assertValidUnleashCampaignState(initialState(change)), rejectsCode('UNLEASH_CAMPAIGN_STATE_INVALID'))
  }
})

test('rejects illegal, rollback, and identity-changing transitions', () => {
  const planned = initialState()
  const running = nextUnleashCampaignState(planned, { status: 'RUNNING' }, '2026-09-15T09:30:01.000Z')
  for (const [changes, timestamp] of [
    [{ status: 'PLANNED' }, '2026-09-15T09:30:01.000Z'],
    [{ status: 'RUNNING', plan_sha256: '5'.repeat(64) }, '2026-09-15T09:30:01.000Z'],
    [{ status: 'RUNNING' }, '2026-09-15T09:29:59.000Z'],
  ]) {
    assert.throws(() => nextUnleashCampaignState(planned, changes, timestamp), rejectsCode('UNLEASH_CAMPAIGN_TRANSITION_INVALID'))
  }
  assert.equal(running.revision, 2)
})

test('protocol v2 retains verified recon through SWARMING and binds terminal completion', () => {
  const planned = initialV2State()
  const running = nextUnleashCampaignState(
    planned,
    { status: 'RUNNING' },
    '2026-09-15T09:30:01.000Z',
  )
  const swarming = nextUnleashCampaignState(running, {
    status: 'SWARMING',
    completed_routes: ['https-recon'],
    evidence_packet_path: resolve(RUN_DIRECTORY, 'evidence-packet.json'),
    evidence_packet_sha256: '5'.repeat(64),
    completion_receipt_sha256: '6'.repeat(64),
    swarm_basis_sha256: '7'.repeat(64),
  }, '2026-09-15T09:30:02.000Z')
  const complete = nextUnleashCampaignState(swarming, {
    status: 'COMPLETE_WITH_GAPS',
    swarm_completion_sha256: '8'.repeat(64),
    candidate_frontier_sha256: '9'.repeat(64),
    candidate_frontier_head_sha256: null,
    swarm_gap_count: 2,
  }, '2026-09-15T09:30:03.000Z')

  assert.equal(assertValidUnleashCampaignState(swarming).status, 'SWARMING')
  assert.equal(assertValidUnleashCampaignState(complete).swarm_gap_count, 2)
  assert.throws(
    () => nextUnleashCampaignState(swarming, {
      status: 'COMPLETE_WITH_GAPS',
    }, '2026-09-15T09:30:03.000Z'),
    rejectsCode('UNLEASH_CAMPAIGN_STATE_INVALID'),
  )
  assert.throws(
    () => nextUnleashCampaignState(swarming, {
      swarm_basis_sha256: 'a'.repeat(64),
    }, '2026-09-15T09:30:03.000Z'),
    rejectsCode('UNLEASH_CAMPAIGN_TRANSITION_INVALID'),
  )
  assert.throws(
    () => assertValidUnleashCampaignState(initialV2State({
      status: 'RUNNING',
      completed_routes: ['https-recon'],
      evidence_packet_path: resolve(RUN_DIRECTORY, 'evidence-packet.json'),
      evidence_packet_sha256: '5'.repeat(64),
      completion_receipt_sha256: '6'.repeat(64),
      swarm_basis_sha256: '7'.repeat(64),
    })),
    rejectsCode('UNLEASH_CAMPAIGN_STATE_INVALID'),
  )
})

test('recovers the full chain and repairs only a proven stale snapshot', async () => {
  const storage = memoryStorage()
  const planned = await appendUnleashCampaignState({ storage, nextState: initialState() })
  const running = nextUnleashCampaignState(planned, { status: 'RUNNING' }, '2026-09-15T09:30:01.000Z')
  await appendUnleashCampaignState({ storage, previousState: planned, nextState: running })
  storage.files.set('campaign-state.json', structuredClone(planned))

  const recovered = await recoverUnleashCampaignState({ storage })

  assert.equal(recovered.event_count, 2)
  assert.deepEqual(recovered.states, [planned, running])
  assert.ok(Object.isFrozen(recovered.states))
  assert.deepEqual(recovered.events.map(({ state }) => state), [planned, running])
  assert.ok(Object.isFrozen(recovered.events))
  assert.equal(recovered.snapshot_repaired, true)
  assert.equal(recovered.state.status, 'RUNNING')
  assert.deepEqual(storage.files.get('campaign-state.json'), running)
})

test('recovery admits exact protocol namespaces and rejects v2 swarm artifacts in v1', async () => {
  const v1Storage = memoryStorage()
  const v1Planned = await appendUnleashCampaignState({ storage: v1Storage, nextState: initialState() })
  v1Storage.files.set('candidate-admission-000001.json', { retained: true })
  v1Storage.files.set('candidate-frontier-state.json', { retained: true })
  assert.deepEqual((await recoverUnleashCampaignState({ storage: v1Storage })).states, [v1Planned])

  v1Storage.files.set('swarm-terminal-fence.json', { retained: true })
  await assert.rejects(
    recoverUnleashCampaignState({ storage: v1Storage }),
    rejectsCode('UNLEASH_CAMPAIGN_PROTOCOL_ARTIFACT_INVALID'),
  )
  v1Storage.files.delete('swarm-terminal-fence.json')
  v1Storage.files.set('swarm-attempt-ledger-state.json', { retained: true })
  await assert.rejects(
    recoverUnleashCampaignState({ storage: v1Storage }),
    rejectsCode('UNLEASH_CAMPAIGN_PROTOCOL_ARTIFACT_INVALID'),
  )

  const storage = memoryStorage()
  const planned = await appendUnleashCampaignState({ storage, nextState: initialV2State() })
  storage.files.set('candidate-admission-000001.json', { retained: true })
  storage.files.set('candidate-frontier-state.json', { retained: true })
  storage.files.set('swarm-attempt-ledger-state.json', { retained: true })
  storage.files.set('swarm-terminal-fence.json', { retained: true })
  storage.files.set('swarm-attempt-event-000001.json', { retained: true })
  storage.files.set('swarm-merge-r01-attack.json', { retained: true })
  storage.files.set('swarm-merge-r01-review.json', { retained: true })
  assert.deepEqual((await recoverUnleashCampaignState({ storage })).states, [planned])

  storage.files.set('candidate-frontier.json', { unexpected: true })
  await assert.rejects(
    recoverUnleashCampaignState({ storage }),
    rejectsCode('UNLEASH_CAMPAIGN_INVENTORY_INVALID'),
  )

  storage.files.delete('candidate-frontier.json')
  storage.files.set('swarm-merge-r1-attack.json', { unexpected: true })
  await assert.rejects(
    recoverUnleashCampaignState({ storage }),
    rejectsCode('UNLEASH_CAMPAIGN_INVENTORY_INVALID'),
  )
})

test('rejects forged events, forged snapshots, chain gaps, and truncated chains', async () => {
  const setup = async () => {
    const storage = memoryStorage()
    const planned = await appendUnleashCampaignState({ storage, nextState: initialState() })
    const running = nextUnleashCampaignState(planned, { status: 'RUNNING' }, '2026-09-15T09:30:01.000Z')
    await appendUnleashCampaignState({ storage, previousState: planned, nextState: running })
    return { storage, planned, running }
  }

  {
    const { storage } = await setup()
    storage.files.get('campaign-event-000002.json').state.status = 'PLANNED'
    await assert.rejects(recoverUnleashCampaignState({ storage }), rejectsCode('UNLEASH_CAMPAIGN_EVENT_INVALID'))
  }
  {
    const { storage } = await setup()
    storage.files.get('campaign-state.json').updated_at = '2026-09-15T09:30:02.000Z'
    await assert.rejects(recoverUnleashCampaignState({ storage }), rejectsCode('UNLEASH_CAMPAIGN_SNAPSHOT_FORGED'))
  }
  {
    const { storage } = await setup()
    storage.files.delete('campaign-event-000001.json')
    await assert.rejects(recoverUnleashCampaignState({ storage }), rejectsCode('UNLEASH_CAMPAIGN_CHAIN_GAP'))
  }
  {
    const { storage, running } = await setup()
    storage.files.delete('campaign-event-000002.json')
    storage.files.set('campaign-state.json', structuredClone(running))
    await assert.rejects(recoverUnleashCampaignState({ storage }), rejectsCode('UNLEASH_CAMPAIGN_CHAIN_TRUNCATED'))
  }
})

test('never overwrites the snapshot when immutable publication is ambiguous', async () => {
  const storage = memoryStorage({ failEvent: true })
  storage.files.set('campaign-state.json', { sentinel: true })

  await assert.rejects(
    appendUnleashCampaignState({ storage, nextState: initialState() }),
    rejectsCode('UNLEASH_CAMPAIGN_RECONCILIATION_REQUIRED'),
  )

  assert.deepEqual(storage.files.get('campaign-state.json'), { sentinel: true })
  assert.deepEqual(storage.operations, ['event:campaign-event-000001.json'])
})

test('recovers a durable event after a snapshot publication failure', async () => {
  const storage = memoryStorage({ failSnapshot: true })
  await assert.rejects(
    appendUnleashCampaignState({ storage, nextState: initialState() }),
    rejectsCode('UNLEASH_CAMPAIGN_SNAPSHOT_STALE'),
  )
  storage.replaceMutableJson = async (filename, value) => {
    storage.files.set(filename, structuredClone(value))
  }

  const recovered = await recoverUnleashCampaignState({ storage })
  assert.equal(recovered.state.status, 'PLANNED')
  assert.equal(recovered.snapshot_repaired, true)
})
