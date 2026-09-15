import { isAbsolute, resolve } from 'node:path'

import { digestUnleashValue } from './unleash-contracts.mjs'

const SHA256 = /^[a-f0-9]{64}$/u
const CAMPAIGN_ID = /^campaign:sha256:[a-f0-9]{64}$/u
const ROUTE_ID = /^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,159}$/u
const EVENT_FILENAME = /^campaign-event-([0-9]{6})\.json$/u
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u
const STATE_FIELDS = [
  'schema_version',
  'kind',
  'revision',
  'updated_at',
  'campaign_id',
  'status',
  'run_directory',
  'plan_sha256',
  'target',
  'completed_routes',
  'route_counts',
  'gap_count',
  'recon_bundle',
  'evidence_packet_path',
  'evidence_packet_sha256',
  'completion_receipt_sha256',
  'stop_reason',
  'failure',
]
const EVENT_FIELDS = [
  'schema_version',
  'kind',
  'revision',
  'recorded_at',
  'previous_state_sha256',
  'state_sha256',
  'state',
]
const COUNT_FIELDS = ['total', 'ready', 'waiting', 'unavailable', 'not_applicable', 'blocked']
const FAILURE_FIELDS = ['code', 'message']
const TARGET_FIELDS = ['family', 'canonical_locator', 'target_id', 'supplied_sha256']
const TERMINAL_STATUSES = new Set(['COMPLETE', 'COMPLETE_WITH_GAPS', 'STOPPED', 'OUTCOME_UNCERTAIN', 'FAILED'])
const STATUS_TRANSITIONS = new Map([
  ['PLANNED', new Set(['RUNNING', 'STOP_REQUESTED', 'STOPPED', 'OUTCOME_UNCERTAIN', 'FAILED', 'RECONCILIATION_REQUIRED'])],
  ['RUNNING', new Set(['COMPLETE', 'COMPLETE_WITH_GAPS', 'STOP_REQUESTED', 'STOPPED', 'OUTCOME_UNCERTAIN', 'FAILED', 'RECONCILIATION_REQUIRED'])],
  ['STOP_REQUESTED', new Set(['COMPLETE', 'COMPLETE_WITH_GAPS', 'STOPPED', 'OUTCOME_UNCERTAIN', 'FAILED', 'RECONCILIATION_REQUIRED'])],
  ['RECONCILIATION_REQUIRED', new Set(['COMPLETE', 'COMPLETE_WITH_GAPS', 'STOP_REQUESTED', 'STOPPED', 'OUTCOME_UNCERTAIN', 'FAILED'])],
])
const ALLOWED_JSON_FILES = new Set([
  'campaign-plan.json',
  'campaign-provider.json',
  'campaign-recon-authority.json',
  'campaign-recon-planned.json',
  'campaign-registry.json',
  'campaign-stop-request.json',
  'campaign-state.json',
  'evidence-packet.json',
  'https-recon-completion.json',
])

export class UnleashCampaignStateError extends Error {
  constructor(code, message, { cause, state } = {}) {
    super(message, cause === undefined ? undefined : { cause })
    this.name = 'UnleashCampaignStateError'
    this.code = code
    if (state !== undefined) this.state = state
  }
}

function fail(code, message, options) {
  throw new UnleashCampaignStateError(code, message, options)
}

function exactRecord(value, fields) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && [Object.prototype, null].includes(Object.getPrototypeOf(value))
    && Object.keys(value).toSorted().join(',') === [...fields].toSorted().join(',')
}

function frozenCopy(value) {
  const copy = structuredClone(value)
  const stack = [copy]
  while (stack.length > 0) {
    const current = stack.pop()
    if (current === null || typeof current !== 'object' || Object.isFrozen(current)) continue
    for (const child of Object.values(current)) stack.push(child)
    Object.freeze(current)
  }
  return copy
}

function sameValue(left, right) {
  return digestUnleashValue(left) === digestUnleashValue(right)
}

function assertTimestamp(value, label) {
  if (!TIMESTAMP.test(value ?? '') || Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) {
    fail('UNLEASH_CAMPAIGN_STATE_INVALID', `${label} must be one canonical UTC timestamp`)
  }
}

function assertCanonicalAbsolutePath(value, label) {
  if (
    typeof value !== 'string'
    || value.length < 1
    || value.length > 4096
    || /[\u0000-\u001f\u007f]/u.test(value)
    || !isAbsolute(value)
    || resolve(value) !== value
  ) fail('UNLEASH_CAMPAIGN_STATE_INVALID', `${label} must be one canonical absolute path`)
}

function assertFailure(value, status) {
  const requiresFailure = ['FAILED', 'OUTCOME_UNCERTAIN', 'RECONCILIATION_REQUIRED'].includes(status)
  if (value === null) {
    if (requiresFailure) fail('UNLEASH_CAMPAIGN_STATE_INVALID', `${status} requires a sanitized failure record`)
    return
  }
  if (
    !requiresFailure
    || !exactRecord(value, FAILURE_FIELDS)
    || typeof value.code !== 'string'
    || !/^[A-Z][A-Z0-9_]{2,159}$/u.test(value.code)
    || typeof value.message !== 'string'
    || value.message.length < 1
    || value.message.length > 1024
    || /[\u0000-\u001f\u007f]/u.test(value.message)
  ) fail('UNLEASH_CAMPAIGN_STATE_INVALID', 'campaign failure record is invalid')
}

function assertCounts(value, gapCount) {
  if (
    !exactRecord(value, COUNT_FIELDS)
    || COUNT_FIELDS.some((field) => !Number.isSafeInteger(value[field]) || value[field] < 0)
    || value.total < 1
    || value.ready + value.waiting + value.unavailable + value.not_applicable + value.blocked !== value.total
    || gapCount !== value.waiting + value.unavailable + value.blocked
  ) fail('UNLEASH_CAMPAIGN_STATE_INVALID', 'campaign route counts or gap count are inconsistent')
}

export function assertValidUnleashCampaignState(value) {
  if (
    !exactRecord(value, STATE_FIELDS)
    || value.schema_version !== '1.0.0'
    || value.kind !== 'last-aperture/unleash-state'
    || !Number.isSafeInteger(value.revision)
    || value.revision < 1
    || value.revision > 999_999
    || !CAMPAIGN_ID.test(value.campaign_id ?? '')
    || !STATUS_TRANSITIONS.has(value.status) && !TERMINAL_STATUSES.has(value.status)
    || !SHA256.test(value.plan_sha256 ?? '')
  ) fail('UNLEASH_CAMPAIGN_STATE_INVALID', 'campaign state identity, revision, or status is invalid')
  assertTimestamp(value.updated_at, 'state updated_at')
  assertCanonicalAbsolutePath(value.run_directory, 'run_directory')
  assertCanonicalAbsolutePath(value.recon_bundle, 'recon_bundle')
  if (resolve(value.recon_bundle) !== resolve(value.run_directory, 'recon')) {
    fail('UNLEASH_CAMPAIGN_STATE_INVALID', 'recon bundle must be the campaign-owned recon directory')
  }
  if (
    !exactRecord(value.target, TARGET_FIELDS)
    || value.target.family !== 'https'
    || typeof value.target.canonical_locator !== 'string'
    || !/^target:sha256:[a-f0-9]{64}$/u.test(value.target.target_id ?? '')
    || !SHA256.test(value.target.supplied_sha256 ?? '')
  ) fail('UNLEASH_CAMPAIGN_STATE_INVALID', 'campaign target projection is invalid')
  let target
  try { target = new URL(value.target.canonical_locator) } catch {
    fail('UNLEASH_CAMPAIGN_STATE_INVALID', 'campaign target projection is invalid')
  }
  if (target.protocol !== 'https:' || target.href !== value.target.canonical_locator) {
    fail('UNLEASH_CAMPAIGN_STATE_INVALID', 'campaign target projection is not canonical HTTPS')
  }
  if (
    !Array.isArray(value.completed_routes)
    || value.completed_routes.length > 1024
    || value.completed_routes.some((route) => typeof route !== 'string' || !ROUTE_ID.test(route))
    || new Set(value.completed_routes).size !== value.completed_routes.length
  ) fail('UNLEASH_CAMPAIGN_STATE_INVALID', 'completed routes must be unique bounded route IDs')
  assertCounts(value.route_counts, value.gap_count)
  const evidenceAbsent = value.evidence_packet_path === null
    && value.evidence_packet_sha256 === null
    && value.completion_receipt_sha256 === null
  const evidencePresent = typeof value.evidence_packet_path === 'string'
    && SHA256.test(value.evidence_packet_sha256 ?? '')
    && SHA256.test(value.completion_receipt_sha256 ?? '')
  if (!evidenceAbsent && !evidencePresent) {
    fail('UNLEASH_CAMPAIGN_STATE_INVALID', 'evidence packet path and digest must be both absent or both present')
  }
  if (evidencePresent) {
    assertCanonicalAbsolutePath(value.evidence_packet_path, 'evidence_packet_path')
    if (resolve(value.evidence_packet_path) !== resolve(value.run_directory, 'evidence-packet.json')) {
      fail('UNLEASH_CAMPAIGN_STATE_INVALID', 'evidence packet must be the campaign-owned packet')
    }
  }
  if (value.stop_reason !== null && (
    typeof value.stop_reason !== 'string'
    || value.stop_reason.length < 1
    || value.stop_reason.length > 1024
    || /[\u0000-\u001f\u007f]/u.test(value.stop_reason)
  )) fail('UNLEASH_CAMPAIGN_STATE_INVALID', 'stop reason is invalid')
  if (['STOP_REQUESTED', 'STOPPED'].includes(value.status) && value.stop_reason === null) {
    fail('UNLEASH_CAMPAIGN_STATE_INVALID', `${value.status} requires a stop reason`)
  }
  if (!['STOP_REQUESTED', 'STOPPED', 'OUTCOME_UNCERTAIN', 'FAILED', 'RECONCILIATION_REQUIRED', 'COMPLETE', 'COMPLETE_WITH_GAPS'].includes(value.status) && value.stop_reason !== null) {
    fail('UNLEASH_CAMPAIGN_STATE_INVALID', `${value.status} cannot carry a stop reason`)
  }
  assertFailure(value.failure, value.status)
  const isComplete = value.status === 'COMPLETE' || value.status === 'COMPLETE_WITH_GAPS'
  if (isComplete && (evidenceAbsent || value.completed_routes.length < 1)) {
    fail('UNLEASH_CAMPAIGN_STATE_INVALID', 'complete campaign state requires completed routes and verified evidence')
  }
  if (!isComplete && (!evidenceAbsent || value.completed_routes.length > 0)) {
    fail('UNLEASH_CAMPAIGN_STATE_INVALID', 'non-complete campaign state cannot claim route completion or evidence')
  }
  if (value.status === 'COMPLETE' && value.gap_count !== 0) {
    fail('UNLEASH_CAMPAIGN_STATE_INVALID', 'COMPLETE requires zero recorded coverage gaps')
  }
  if (value.status === 'COMPLETE_WITH_GAPS' && value.gap_count === 0) {
    fail('UNLEASH_CAMPAIGN_STATE_INVALID', 'COMPLETE_WITH_GAPS requires at least one recorded coverage gap')
  }
  return value
}

function immutableProjection(state) {
  return {
    schema_version: state.schema_version,
    kind: state.kind,
    campaign_id: state.campaign_id,
    run_directory: state.run_directory,
    plan_sha256: state.plan_sha256,
    target: state.target,
    route_counts: state.route_counts,
    gap_count: state.gap_count,
    recon_bundle: state.recon_bundle,
  }
}

export function assertUnleashCampaignStateTransition(previous, next) {
  assertValidUnleashCampaignState(next)
  if (previous === null) {
    if (next.revision !== 1 || next.status !== 'PLANNED') {
      fail('UNLEASH_CAMPAIGN_TRANSITION_INVALID', 'the first campaign state must be PLANNED at revision 1')
    }
    return next
  }
  assertValidUnleashCampaignState(previous)
  if (
    next.revision !== previous.revision + 1
    || Date.parse(next.updated_at) < Date.parse(previous.updated_at)
    || !sameValue(immutableProjection(previous), immutableProjection(next))
    || !STATUS_TRANSITIONS.get(previous.status)?.has(next.status)
  ) fail('UNLEASH_CAMPAIGN_TRANSITION_INVALID', `campaign transition ${previous.status} -> ${next.status} is invalid`)
  if (
    next.completed_routes.length < previous.completed_routes.length
    || previous.completed_routes.some((route, index) => next.completed_routes[index] !== route)
    || (previous.evidence_packet_sha256 !== null && (
      next.evidence_packet_sha256 !== previous.evidence_packet_sha256
      || next.evidence_packet_path !== previous.evidence_packet_path
      || next.completion_receipt_sha256 !== previous.completion_receipt_sha256
    ))
    || (previous.stop_reason !== null && next.stop_reason !== previous.stop_reason)
  ) fail('UNLEASH_CAMPAIGN_TRANSITION_INVALID', 'campaign transition rolls back or changes retained evidence')
  return next
}

function assertStorage(storage) {
  if (
    storage === null
    || typeof storage !== 'object'
    || typeof storage.writeImmutableJson !== 'function'
    || typeof storage.replaceMutableJson !== 'function'
    || typeof storage.readJson !== 'function'
    || typeof storage.listJsonFilenames !== 'function'
  ) fail('UNLEASH_CAMPAIGN_STORAGE_INVALID', 'campaign state storage interface is unavailable')
  return storage
}

function eventFilename(revision) {
  return `campaign-event-${String(revision).padStart(6, '0')}.json`
}

function buildEvent(previous, state) {
  const event = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-campaign-event',
    revision: state.revision,
    recorded_at: state.updated_at,
    previous_state_sha256: previous === null ? null : digestUnleashValue(previous),
    state_sha256: digestUnleashValue(state),
    state: structuredClone(state),
  }
  return frozenCopy(event)
}

function assertEvent(event, revision, previous) {
  if (
    !exactRecord(event, EVENT_FIELDS)
    || event.schema_version !== '1.0.0'
    || event.kind !== 'last-aperture/unleash-campaign-event'
    || event.revision !== revision
    || event.recorded_at !== event.state?.updated_at
    || event.state?.revision !== revision
    || !SHA256.test(event.state_sha256 ?? '')
    || event.state_sha256 !== digestUnleashValue(event.state)
    || event.previous_state_sha256 !== (previous === null ? null : digestUnleashValue(previous))
  ) fail('UNLEASH_CAMPAIGN_EVENT_INVALID', `campaign event ${revision} has invalid fields or digest bindings`)
  assertTimestamp(event.recorded_at, 'event recorded_at')
  assertUnleashCampaignStateTransition(previous, event.state)
  return event.state
}

export async function appendUnleashCampaignState({ storage, previousState = null, nextState } = {}) {
  assertStorage(storage)
  assertUnleashCampaignStateTransition(previousState, nextState)
  const state = frozenCopy(nextState)
  const event = buildEvent(previousState, state)
  const filename = eventFilename(state.revision)
  try {
    await storage.writeImmutableJson(filename, event)
  } catch (cause) {
    fail(
      'UNLEASH_CAMPAIGN_RECONCILIATION_REQUIRED',
      'campaign event publication could not be proven; the mutable snapshot was not overwritten',
      {
        cause,
        state: frozenCopy({
          ...state,
          status: 'RECONCILIATION_REQUIRED',
          completed_routes: [],
          evidence_packet_path: null,
          evidence_packet_sha256: null,
          completion_receipt_sha256: null,
          failure: {
            code: 'UNLEASH_CAMPAIGN_EVENT_PUBLICATION_UNCERTAIN',
            message: 'Campaign event publication requires storage reconciliation before another transition.',
          },
        }),
      },
    )
  }
  try {
    await storage.replaceMutableJson('campaign-state.json', state)
  } catch (cause) {
    fail(
      'UNLEASH_CAMPAIGN_SNAPSHOT_STALE',
      'campaign event is durable but its mutable snapshot must be recovered',
      { cause, state },
    )
  }
  return state
}

async function readSnapshot(storage) {
  try { return await storage.readJson('campaign-state.json') } catch (cause) {
    if (cause?.code === 'UNLEASH_STORAGE_FILE_NOT_FOUND') return null
    throw cause
  }
}

export async function recoverUnleashCampaignState({ storage, repairSnapshot = true } = {}) {
  assertStorage(storage)
  if (typeof repairSnapshot !== 'boolean') {
    fail('UNLEASH_CAMPAIGN_RECOVERY_INVALID', 'repairSnapshot must be boolean')
  }
  const filenames = await storage.listJsonFilenames()
  if (!Array.isArray(filenames)) fail('UNLEASH_CAMPAIGN_STORAGE_INVALID', 'campaign JSON inventory is invalid')
  const eventFiles = []
  for (const filename of filenames) {
    const match = EVENT_FILENAME.exec(filename)
    if (match) {
      eventFiles.push({ filename, revision: Number.parseInt(match[1], 10) })
    } else if (!ALLOWED_JSON_FILES.has(filename)) {
      fail('UNLEASH_CAMPAIGN_INVENTORY_INVALID', `campaign contains an unrecognized JSON artifact: ${filename}`)
    }
  }
  if (eventFiles.length < 1) fail('UNLEASH_CAMPAIGN_CHAIN_MISSING', 'campaign has no immutable state events')
  let previous = null
  const states = []
  for (const [index, descriptor] of eventFiles.entries()) {
    const expected = index + 1
    if (descriptor.revision !== expected || descriptor.filename !== eventFilename(expected)) {
      fail('UNLEASH_CAMPAIGN_CHAIN_GAP', `campaign event chain is gapped or out of order at revision ${expected}`)
    }
    const event = await storage.readJson(descriptor.filename)
    previous = frozenCopy(assertEvent(event, expected, previous))
    states.push(previous)
  }
  const head = states.at(-1)
  const snapshot = await readSnapshot(storage)
  let snapshotStale = snapshot === null
  if (snapshot !== null) {
    assertValidUnleashCampaignState(snapshot)
    if (snapshot.revision > head.revision) {
      fail('UNLEASH_CAMPAIGN_CHAIN_TRUNCATED', 'campaign snapshot references a missing event revision')
    }
    const authoritative = states[snapshot.revision - 1]
    if (authoritative === undefined || !sameValue(snapshot, authoritative)) {
      fail('UNLEASH_CAMPAIGN_SNAPSHOT_FORGED', 'campaign snapshot does not match its immutable event')
    }
    snapshotStale = snapshot.revision < head.revision
  }
  if (snapshotStale && repairSnapshot) {
    const beforeRepair = await storage.listJsonFilenames()
    if (beforeRepair.join('\n') !== filenames.join('\n')) {
      fail('UNLEASH_CAMPAIGN_STATE_CHANGED', 'campaign changed while recovery was preparing the snapshot repair')
    }
    await storage.replaceMutableJson('campaign-state.json', head)
  }
  return Object.freeze({
    state: head,
    event_count: states.length,
    state_sha256: digestUnleashValue(head),
    snapshot_repaired: snapshotStale && repairSnapshot,
  })
}

export function nextUnleashCampaignState(previous, changes, updatedAt) {
  assertValidUnleashCampaignState(previous)
  if (!exactRecord(changes, Object.keys(changes))) {
    fail('UNLEASH_CAMPAIGN_TRANSITION_INVALID', 'campaign state changes must be a plain object')
  }
  assertTimestamp(updatedAt, 'transition updatedAt')
  const next = {
    ...structuredClone(previous),
    ...structuredClone(changes),
    revision: previous.revision + 1,
    updated_at: updatedAt,
  }
  assertUnleashCampaignStateTransition(previous, next)
  return frozenCopy(next)
}

export const unleashCampaignStateFields = Object.freeze([...STATE_FIELDS])
