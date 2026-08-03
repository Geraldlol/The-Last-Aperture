import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { isDeepStrictEqual } from 'node:util'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import { compareCanonicalStrings } from './canonical-order.mjs'
import {
  isUnresolvedDatabaseDescriptor,
  routeDatabaseAdapter,
  validateDatabaseSemanticMetadata,
} from './database-adapters.mjs'
import { validateDatabaseDiscovery } from './database-discovery.mjs'
import {
  buildCategoryDenominators,
  inventoryCoverageRecords,
  measureCoverageClosure,
  sourceClosureGaps,
  uncoveredLensFilePairs,
} from './coverage-model.mjs'
import {
  exactCoverageGapId,
  filterResolvedCoverageGaps,
} from './coverage-gaps.mjs'
import { digestWorkScope, workShardId } from './work-shards.mjs'
import {
  expectedStoreContributionRelationships,
  expectedStorePathsForJob,
  normalizeStoreContribution,
  synthesizeStoreProfiles,
} from './store-synthesis.mjs'
import { validateDatabaseConformanceEvidence } from './database-conformance-contracts.mjs'

const FINDING_SCHEMA_URL = new URL('../../schemas/finding.schema.json', import.meta.url)
const STORE_PROFILE_SCHEMA_URL = new URL('../../schemas/store-profile.schema.json', import.meta.url)
const STORE_CONTRIBUTION_SCHEMA_URL = new URL(
  '../../schemas/store-contribution.schema.json',
  import.meta.url,
)
const RUN_SCHEMA_URL = new URL('../../schemas/run.schema.json', import.meta.url)
const DATABASE_DISCOVERY_SCHEMA_URL = new URL(
  '../../schemas/database-discovery.schema.json',
  import.meta.url,
)
const DATABASE_CONFORMANCE_EVIDENCE_SCHEMA_URL = new URL(
  '../../schemas/database-conformance-evidence.schema.json',
  import.meta.url,
)

export const findingSchema = JSON.parse(readFileSync(fileURLToPath(FINDING_SCHEMA_URL), 'utf8'))
export const storeProfileSchema = JSON.parse(
  readFileSync(fileURLToPath(STORE_PROFILE_SCHEMA_URL), 'utf8'),
)
export const storeContributionSchema = JSON.parse(
  readFileSync(fileURLToPath(STORE_CONTRIBUTION_SCHEMA_URL), 'utf8'),
)
export const runSchema = JSON.parse(readFileSync(fileURLToPath(RUN_SCHEMA_URL), 'utf8'))
export const databaseDiscoverySchema = JSON.parse(
  readFileSync(fileURLToPath(DATABASE_DISCOVERY_SCHEMA_URL), 'utf8'),
)
export const databaseConformanceEvidenceSchema = JSON.parse(
  readFileSync(fileURLToPath(DATABASE_CONFORMANCE_EVIDENCE_SCHEMA_URL), 'utf8'),
)

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})

ajv.addSchema(findingSchema)
ajv.addSchema(storeProfileSchema)
ajv.addSchema(storeContributionSchema)
ajv.addSchema(databaseDiscoverySchema)
ajv.addSchema(databaseConformanceEvidenceSchema)
ajv.addSchema(runSchema)

const validateFindingSchema = ajv.getSchema(findingSchema.$id)
const validateRunSchema = ajv.getSchema(runSchema.$id)
const validateDatabaseDiscoverySchema = ajv.getSchema(
  databaseDiscoverySchema.$id,
)

const TRIAGE_FIELDS = new Set([
  'effective_severity',
  'triage_disposition',
  'drop_reason',
  'raised_by',
  'component_finding_ids',
  'merged_into_candidate_id',
])

const PROOF_FIELDS = new Set([
  'existence_check',
  'proof_tier',
  'verification_status',
  'disproof_basis',
  'artifact',
  'command',
  'pre_result',
  'post_result',
  'reason',
  'blocking_reason',
])

const STAGE_ONE_FIELDS = new Set([
  'candidate_id',
  'lens',
  'topic',
  'title',
  'claimed_impact_severity',
  'location',
  'cwe',
  'evidence',
  'source_anchors',
  'quotes',
  'absence_claims',
  'attack',
  'impact',
  'reachable_from',
  'contingent_fact',
  'contingent_query',
  'confidence',
  'proof_plan',
  'store_context',
  'principal_path',
  'enforcement_plane',
  'copy_path',
  'semantic_sensitivity',
  'adapter_rule_id',
  'semantic_source',
])

const SEVERITY_RANK = new Map([
  ['Info', 0],
  ['Low', 1],
  ['Medium', 2],
  ['High', 3],
  ['Critical', 4],
])

const TERMINAL_VERIFICATION_STATUSES = new Set([
  'CONFIRMED',
  'NOT_REPRODUCED',
  'INCONCLUSIVE',
  'DISPROVED',
  'UNPROVEN',
])

const OPEN_DISPOSITIONS = new Set(['queued', 'elevated'])
const TERMINAL_RUN_STATES = new Set(['COMPLETED', 'COMPLETE_WITH_GAPS', 'ABORTED', 'FAILED'])
const TERMINAL_JOB_STATES = new Set(['SUCCEEDED', 'SKIPPED', 'FAILED'])
const MODELED_DATABASE_RUN_SCHEMAS = new Set(['3.0.0', '4.0.0', '5.0.0', '6.0.0', '7.0.0'])

function modeledDatabaseRun(run) {
  return MODELED_DATABASE_RUN_SCHEMAS.has(run?.schema_version)
}
const RUN_PHASE_RANK = new Map([
  ['RECON', 0],
  ['FANOUT', 1],
  ['TRIAGE', 2],
  ['PROOF', 3],
  ['PATCH', 4],
  ['REPORT', 5],
  ['COMPLETENESS', 6],
  ['FINALIZED', 7],
])

const RUN_STATE_TRANSITIONS = new Map([
  ['PLANNED', new Set(['PLANNED', 'RUNNING', 'ABORTED', 'FAILED'])],
  ['RUNNING', new Set(['RUNNING', 'COMPLETED', 'COMPLETE_WITH_GAPS', 'ABORTED', 'FAILED'])],
  ['COMPLETED', new Set(['COMPLETED'])],
  ['COMPLETE_WITH_GAPS', new Set(['COMPLETE_WITH_GAPS'])],
  ['ABORTED', new Set(['ABORTED'])],
  ['FAILED', new Set(['FAILED'])],
])

const JOB_STATE_TRANSITIONS = new Map([
  ['DORMANT', new Set(['DORMANT', 'PENDING', 'SKIPPED'])],
  ['PENDING', new Set(['PENDING', 'RUNNING', 'SKIPPED', 'FAILED'])],
  ['RUNNING', new Set(['PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED'])],
  ['SUCCEEDED', new Set(['SUCCEEDED'])],
  ['SKIPPED', new Set(['SKIPPED'])],
  ['FAILED', new Set(['FAILED'])],
])

const ATTEMPT_EVENT_TRANSITIONS = new Map([
  ['LEASED', new Set(['STARTED', 'FAILED'])],
  ['STARTED', new Set(['RESULT_CAPTURED', 'FAILED'])],
  ['RESULT_CAPTURED', new Set(['VALIDATED', 'FAILED'])],
  ['VALIDATED', new Set(['COMMITTED', 'FAILED'])],
  ['FAILED', new Set()],
  ['COMMITTED', new Set()],
])

const ACTIVE_ATTEMPT_EVENTS = new Set([
  'LEASED',
  'STARTED',
  'RESULT_CAPTURED',
  'VALIDATED',
])

function hasOwn(object, key) {
  return object !== null && typeof object === 'object'
    && Object.prototype.hasOwnProperty.call(object, key)
}

// A hand-edited run.json can hold a schema-valid gap whose identity cannot be
// derived. Validation must reject it, not raise out of the validator, so both
// helpers fail closed: an unidentifiable gap stays open and resolves nothing.
function coverageGapIdOrUndefined(gap) {
  try {
    return exactCoverageGapId(gap)
  } catch {
    return undefined
  }
}

function openCoverageGaps(coverage) {
  const gaps = Array.isArray(coverage?.gaps) ? coverage.gaps : []
  try {
    return filterResolvedCoverageGaps(gaps, coverage?.resolved_gap_ids ?? [])
  } catch {
    return gaps
  }
}

const CONTRACT_TIMESTAMP_PATTERN =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|([+-])(\d{2}):(\d{2}))$/

export function parseContractTimestamp(value) {
  if (typeof value !== 'string') return Number.NaN
  const match = CONTRACT_TIMESTAMP_PATTERN.exec(value)
  if (!match) return Number.NaN
  const [
    ,
    yearText,
    monthText,
    dayText,
    hourText,
    minuteText,
    secondText,
    ,
    ,
    ,
    offsetHourText,
    offsetMinuteText,
  ] = match
  const year = Number(yearText)
  const month = Number(monthText)
  const day = Number(dayText)
  const hour = Number(hourText)
  const minute = Number(minuteText)
  const second = Number(secondText)
  const offsetHour = offsetHourText === undefined ? 0 : Number(offsetHourText)
  const offsetMinute = offsetMinuteText === undefined ? 0 : Number(offsetMinuteText)
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
  const daysInMonth = [
    31,
    leapYear ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ]
  if (
    month < 1
    || month > 12
    || day < 1
    || day > daysInMonth[month - 1]
    || hour > 23
    || minute > 59
    || second > 59
    || offsetHour > 23
    || offsetMinute > 59
  ) {
    return Number.NaN
  }
  const parsed = Date.parse(value)
  return Number.isFinite(parsed) ? parsed : Number.NaN
}

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value)
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`
  }
  if (value !== null && typeof value === 'object') {
    const entries = Object.keys(value)
      .filter((key) => value[key] !== undefined)
      .sort(compareCanonicalStrings)
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    return `{${entries.join(',')}}`
  }
  throw new TypeError(`Cannot canonicalize ${typeof value} for hashing`)
}

export function hashAttemptEvent(event) {
  const unsigned = { ...event }
  delete unsigned.event_sha256
  return createHash('sha256').update(canonicalJson(unsigned), 'utf8').digest('hex')
}

function addError(errors, code, instancePath, message, params = {}) {
  errors.push({
    keyword: 'contract',
    code,
    instancePath,
    message,
    params,
  })
}

function normalizeAjvErrors(errors = []) {
  return errors.map((error) => ({
    keyword: error.keyword,
    code: `SCHEMA_${error.keyword.toUpperCase()}`,
    instancePath: error.instancePath,
    message: error.message ?? 'schema validation failed',
    params: error.params,
  }))
}

function severityAbove(value, maximum) {
  return SEVERITY_RANK.has(value)
    && SEVERITY_RANK.has(maximum)
    && SEVERITY_RANK.get(value) > SEVERITY_RANK.get(maximum)
}

function isDatabaseFinding(record) {
  return record?.lens === 'database-and-data-stores'
    || /^(?:database(?:-|$)|db\.)/.test(record?.topic ?? '')
}

// Controller synthesis is deferred until every base lens job terminates, but
// findings arrive during fan-out. A database finding filed then binds to the
// authority contribution that will become the run profile; ingest applies the
// same fallback in ensureDatabaseProfileBinding.
function authorityContributionEntry(run, storeId) {
  const profile = (run.store_contributions ?? []).find((envelope) =>
    envelope.role === 'AUTHORITY'
    && envelope.contribution?.store_id === storeId)
    ?.contribution?.profile
  return profile === undefined ? undefined : { profile }
}

function cloneJson(value) {
  return structuredClone(value)
}

function nestedEvidencePathEntries(value, pointer = '', output = []) {
  if (value === null || typeof value !== 'object') return output
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      nestedEvidencePathEntries(entry, `${pointer}/${index}`, output)
    })
    return output
  }
  for (const [key, entry] of Object.entries(value)) {
    const childPointer = `${pointer}/${key}`
    if (
      (key === 'evidence_paths' || key.endsWith('_evidence_paths'))
      && Array.isArray(entry)
    ) {
      entry.forEach((path, index) => {
        output.push({ path, pointer: `${childPointer}/${index}` })
      })
    }
    nestedEvidencePathEntries(entry, childPointer, output)
  }
  return output
}

function detectionEvidenceIsBound(claim, declaredPaths) {
  if (typeof claim !== 'string') return false
  const normalized = claim.trim().replaceAll('\\', '/')
  return [...declaredPaths].some((declaredPath) => {
    const path = String(declaredPath).replaceAll('\\', '/')
    if (normalized === path) return true
    if (!normalized.startsWith(path)) return false
    const suffix = normalized.slice(path.length)
    return /^:(?:[1-9][0-9]*)(?::[1-9][0-9]*)?(?:\s|$)/.test(suffix)
      || /^(?:#|\s)/.test(suffix)
  })
}

function storeProfileCommonInvariantErrors(profile, pointer) {
  const errors = []
  const storeId = profile?.store_context?.store_id
  const adapterDecision = routeDatabaseAdapter(profile?.store_context)
  if (
    typeof profile?.store_context?.adapter_id === 'string'
    && profile.store_context.adapter_id !== adapterDecision.adapter_id
  ) {
    addError(
      errors,
      'DATABASE_PROFILE_ADAPTER_MISMATCH',
      `${pointer}/store_context/adapter_id`,
      `store profile must use routed adapter ${adapterDecision.adapter_id}`,
      { reasons: adapterDecision.reasons },
    )
  }
  if (
    adapterDecision.selection_status !== 'SELECTED'
    && profile?.coverage_state !== 'NOT_ASSESSED'
  ) {
    addError(
      errors,
      'DATABASE_PROFILE_ROUTE_UNASSESSED',
      `${pointer}/coverage_state`,
      'a store without a selected semantic adapter must be NOT_ASSESSED',
      { reasons: adapterDecision.reasons },
    )
  }

  const declaredEvidencePaths = new Set(profile?.evidence_paths ?? [])
  for (const [evidenceIndex, claim] of (
    profile?.store_context?.detection_evidence ?? []
  ).entries()) {
    if (!detectionEvidenceIsBound(claim, declaredEvidencePaths)) {
      addError(
        errors,
        'DATABASE_PROFILE_UNBOUND_DETECTION_EVIDENCE',
        `${pointer}/store_context/detection_evidence/${evidenceIndex}`,
        'store detection evidence must start with a controller-checked profile evidence path',
      )
    }
  }
  for (const entry of nestedEvidencePathEntries(profile)) {
    if (
      !entry.pointer.startsWith('/evidence_paths/')
      && !declaredEvidencePaths.has(entry.path)
    ) {
      addError(
        errors,
        'DATABASE_PROFILE_UNDECLARED_EVIDENCE',
        `${pointer}${entry.pointer}`,
        `nested evidence path ${String(entry.path)} is absent from the profile evidence denominator`,
      )
    }
  }

  const principalValues = [
    profile?.principal_path?.authenticated_principal,
    profile?.principal_path?.session_principal,
    profile?.principal_path?.effective_principal,
    profile?.principal_path?.owner_or_definer,
    ...(profile?.principal_path?.bypass_capabilities ?? []),
  ]
  if (
    profile?.coverage_state === 'ASSESSED'
    && principalValues.some((value) => isUnresolvedDatabaseDescriptor(value))
  ) {
    addError(
      errors,
      'DATABASE_PROFILE_UNRESOLVED_PRINCIPAL',
      `${pointer}/principal_path`,
      `ASSESSED store profile ${String(storeId)} cannot retain unresolved principal semantics`,
    )
  }

  return errors
}

function deepFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value
  Object.freeze(value)
  for (const child of Object.values(value)) deepFreeze(child)
  return value
}

function result(valid, errors, extra = {}) {
  return {
    valid,
    errors,
    ...extra,
  }
}

function requestedStageNumber(stage) {
  if (stage === undefined) return undefined
  const normalized = typeof stage === 'string' ? stage.toLowerCase().replace(/[^0-9]/g, '') : stage
  const number = Number(normalized)
  if (![1, 2, 3].includes(number)) {
    throw new TypeError(`stage must be 1, 2, or 3; received ${String(stage)}`)
  }
  return number
}

export function inferFindingStage(record) {
  if (record === null || typeof record !== 'object' || Array.isArray(record)) return 0
  if ([...PROOF_FIELDS].some((field) => hasOwn(record, field))) return 3
  if ([...TRIAGE_FIELDS]
    .filter((field) => field !== 'raised_by')
    .some((field) => hasOwn(record, field))) return 2
  return 1
}

export function isExactStageOneReplay(previous, replay) {
  if (inferFindingStage(replay) !== 1) return false

  const expected = {}
  for (const field of STAGE_ONE_FIELDS) {
    if (hasOwn(previous, field)) expected[field] = previous[field]
  }
  // Zero-owner lenses attribute their originating Stage-1 record with raised_by.
  // A later triage attribution is intentionally excluded when the replay omits it.
  if (hasOwn(replay, 'raised_by')) expected.raised_by = previous.raised_by

  return isDeepStrictEqual(expected, replay)
}

// A near-miss spelling must be read as unresolved reachability, never as a
// named entry point: the schema rejects it, and the cap must not depend on the
// schema having run first.
const UNRESOLVED_REACHABILITY = /^\s*(?:unknown|contingent)/i
const REACHABILITY_DROP_GROUNDS =
  /\b(?:un)?reachab\w*|\bentry[ -]?points?\b|\bcallers?\b|\bcall[ -]?sites?\b|\bdead code\b|\bnever (?:called|invoked|reached)\b/i

function unresolvedReachability(value) {
  return typeof value === 'string' && UNRESOLVED_REACHABILITY.test(value)
}

function findingInvariantErrors(record) {
  const errors = []
  if (record === null || typeof record !== 'object' || Array.isArray(record)) return errors

  const effectiveSeverity = record.effective_severity
  const claimedSeverity = record.claimed_impact_severity

  if (
    effectiveSeverity
    && claimedSeverity
    && severityAbove(effectiveSeverity, claimedSeverity)
    && !(record.triage_disposition === 'elevated' && typeof record.raised_by === 'string')
  ) {
    addError(
      errors,
      'UNAUTHORISED_SEVERITY_ELEVATION',
      '/effective_severity',
      'effective severity may exceed the claim only for an attributed elevation',
    )
  }

  if (
    effectiveSeverity
    && unresolvedReachability(record.reachable_from)
    && severityAbove(effectiveSeverity, 'Medium')
  ) {
    addError(
      errors,
      'REACHABILITY_CAP',
      '/effective_severity',
      'unknown or contingent reachability caps effective severity at Medium',
    )
  }

  if (
    record.triage_disposition === 'dropped'
    && unresolvedReachability(record.reachable_from)
    && ['Critical', 'High'].includes(claimedSeverity)
    && (
      typeof record.drop_reason !== 'string'
      || REACHABILITY_DROP_GROUNDS.test(record.drop_reason)
    )
  ) {
    addError(
      errors,
      'REACHABILITY_DROP',
      '/drop_reason',
      'unknown or contingent reachability is not grounds for dropping a claimed Critical or High candidate; it stays in the proof queue',
    )
  }

  if (
    effectiveSeverity
    && ['T0', 'T3'].includes(record.proof_tier)
    && severityAbove(effectiveSeverity, 'Medium')
  ) {
    addError(
      errors,
      'PROOF_TIER_CAP',
      '/effective_severity',
      `${record.proof_tier} evidence caps effective severity at Medium`,
    )
  }

  if (
    effectiveSeverity
    && ['UNPROVEN', 'INCONCLUSIVE'].includes(record.verification_status)
    && severityAbove(effectiveSeverity, 'Medium')
  ) {
    addError(
      errors,
      'VERIFICATION_CAP',
      '/effective_severity',
      `${record.verification_status} caps effective severity at Medium`,
    )
  }

  if (
    record.triage_disposition === 'merged'
    && record.merged_into_candidate_id === record.candidate_id
  ) {
    addError(
      errors,
      'SELF_MERGE',
      '/merged_into_candidate_id',
      'a candidate cannot merge into itself',
    )
  }

  if (Array.isArray(record.component_finding_ids)) {
    const hostIndex = record.component_finding_ids.indexOf(record.candidate_id)
    if (
      hostIndex >= 0
      && !(
        record.raised_by === 'attack-chaining'
        && hostIndex === record.component_finding_ids.length - 1
      )
    ) {
      addError(
        errors,
        'INVALID_HOST_COMPONENT',
        '/component_finding_ids',
        'only an attack chain may include its host, exactly as the terminal component',
      )
    }
  }

  if (
    record.triage_disposition === 'elevated'
    && effectiveSeverity
    && claimedSeverity
    && !severityAbove(effectiveSeverity, claimedSeverity)
  ) {
    addError(
      errors,
      'INEFFECTIVE_ELEVATION',
      '/effective_severity',
      'an elevated disposition must actually raise effective severity above the claim',
    )
  }

  if (
    record.verification_status === 'CONFIRMED'
    && ['Critical', 'High'].includes(effectiveSeverity)
    && !['T1', 'T2'].includes(record.proof_tier)
  ) {
    addError(
      errors,
      'HIGH_SEVERITY_PROOF_REQUIRED',
      '/proof_tier',
      'confirmed Critical and High findings require T1 or T2 proof',
    )
  }

  if (record.verification_status === 'DISPROVED') {
    if (!['falsified-code-premise', 'validated-oracle'].includes(record.disproof_basis)) {
      addError(
        errors,
        'DISPROOF_BASIS_REQUIRED',
        '/disproof_basis',
        'DISPROVED requires falsified-code-premise or validated-oracle evidence',
      )
    } else if (record.disproof_basis === 'falsified-code-premise') {
      if (
        record.existence_check?.status !== 'located'
        || typeof record.existence_check?.observed !== 'string'
        || !record.existence_check.observed.trim()
      ) {
        addError(
          errors,
          'STATIC_DISPROOF_OBSERVATION_REQUIRED',
          '/existence_check/observed',
          'a falsified code premise requires a located artifact and a concrete observation',
        )
      }
    } else if (
      !['T1', 'T2'].includes(record.proof_tier)
      || !record.artifact
      || !record.command
      || !record.pre_result
      || !record.post_result
    ) {
      addError(
        errors,
        'ORACLE_DISPROOF_EVIDENCE_REQUIRED',
        '/disproof_basis',
        'validated-oracle disproof requires T1/T2 artifact, command, pre-result, and post-result evidence',
      )
    }
  } else if (hasOwn(record, 'disproof_basis')) {
    addError(
      errors,
      'DISPROOF_BASIS_WITHOUT_DISPROOF',
      '/disproof_basis',
      'disproof_basis is valid only when verification_status is DISPROVED',
    )
  }

  if (
    record.verification_status === 'NOT_REPRODUCED'
    && record.existence_check?.status === 'located'
    && (
      !['T1', 'T2'].includes(record.proof_tier)
      || !record.artifact
      || !record.command
      || !record.pre_result
      || !record.post_result
    )
  ) {
    addError(
      errors,
      'LOCATED_NONREPRODUCTION_EVIDENCE_REQUIRED',
      '/verification_status',
      'a located candidate may be NOT_REPRODUCED only with a T1/T2 validated oracle',
    )
  }

  if (isDatabaseFinding(record)) {
    const adapterDecision = routeDatabaseAdapter(record.store_context)
    if (
      adapterDecision.selection_status === 'INVENTORY_ONLY'
      && record.store_context?.adapter_id !== 'inventory-only'
    ) {
      addError(
        errors,
        'DATABASE_ADAPTER_FALLBACK_REQUIRED',
        '/store_context/adapter_id',
        'unknown, ambiguous, or under-evidenced store profiles must use the inventory-only adapter',
        { reasons: adapterDecision.reasons },
      )
    }
    if (adapterDecision.selection_status === 'SELECTED') {
      const semantic = validateDatabaseSemanticMetadata({
        adapter_id: record.store_context?.adapter_id,
        semantic_sensitivity: record.semantic_sensitivity,
        adapter_rule_id: record.adapter_rule_id,
        semantic_source: record.semantic_source,
      })
      for (const issue of semantic.errors) {
        addError(
          errors,
          `DATABASE_${issue.code.replaceAll('-', '_').toUpperCase()}`,
          `/${issue.field ?? 'semantic_sensitivity'}`,
          issue.detail,
        )
      }
    }

    if (
      adapterDecision.selection_status === 'INVENTORY_ONLY'
      && record.verification_status
      && record.verification_status !== 'UNPROVEN'
    ) {
      addError(
        errors,
        'INVENTORY_ONLY_CLEARANCE',
        '/verification_status',
        'the inventory-only database adapter cannot confirm or clear a candidate',
      )
    }

    if (
      adapterDecision.effective_severity_cap === 'Medium'
      && effectiveSeverity
      && severityAbove(effectiveSeverity, 'Medium')
    ) {
      addError(
        errors,
        'UNRESOLVED_DATABASE_SEMANTICS_CAP',
        '/effective_severity',
        'unknown database version or deployment semantics cap effective severity at Medium',
      )
    }

    const principalValues = [
      record.principal_path?.authenticated_principal,
      record.principal_path?.session_principal,
      record.principal_path?.effective_principal,
      record.principal_path?.owner_or_definer,
      ...(record.principal_path?.bypass_capabilities ?? []),
    ]
    const unresolvedPrincipal = principalValues.some(
      (value) => isUnresolvedDatabaseDescriptor(value),
    )
    if (
      unresolvedPrincipal
      && record.verification_status
      && record.verification_status !== 'UNPROVEN'
    ) {
      addError(
        errors,
        'UNRESOLVED_DATABASE_PRINCIPAL_CLEARANCE',
        '/principal_path',
        'an unresolved effective-principal or bypass path cannot confirm or clear a database candidate',
      )
    }
    if (
      unresolvedPrincipal
      && effectiveSeverity
      && severityAbove(effectiveSeverity, 'Medium')
    ) {
      addError(
        errors,
        'UNRESOLVED_DATABASE_PRINCIPAL_CAP',
        '/effective_severity',
        'unresolved database principal semantics cap effective severity at Medium',
      )
    }
  }

  return errors
}

export function validateFinding(record, options = {}) {
  const requestedStage = requestedStageNumber(options.stage)
  const schemaValid = validateFindingSchema(record)
  const errors = schemaValid ? [] : normalizeAjvErrors(validateFindingSchema.errors)
  errors.push(...findingInvariantErrors(record))

  const stage = inferFindingStage(record)
  if (requestedStage !== undefined && stage !== requestedStage) {
    addError(
      errors,
      'STAGE_MISMATCH',
      '',
      `record contains Stage ${stage} fields but Stage ${requestedStage} was required`,
      { actualStage: stage, requestedStage },
    )
  }

  return result(errors.length === 0, errors, { stage })
}

export class ContractValidationError extends Error {
  constructor(message, errors) {
    const detail = errors
      .map((error) => `${error.instancePath || '/'} [${error.code}]: ${error.message}`)
      .join('\n')
    super(detail ? `${message}\n${detail}` : message)
    this.name = 'ContractValidationError'
    this.errors = errors
  }
}

export function assertValidFinding(record, options = {}) {
  const validation = validateFinding(record, options)
  if (!validation.valid) {
    throw new ContractValidationError('Finding contract validation failed', validation.errors)
  }
  return record
}

function transitionInvariantErrors(previous, next) {
  const errors = []
  if (
    previous === null
    || next === null
    || typeof previous !== 'object'
    || typeof next !== 'object'
    || Array.isArray(previous)
    || Array.isArray(next)
  ) {
    return errors
  }

  if (previous.candidate_id !== next.candidate_id) {
    addError(
      errors,
      'CANDIDATE_ID_CHANGED',
      '/candidate_id',
      'candidate identity is immutable across transitions',
    )
  }

  const previousStage = inferFindingStage(previous)
  const nextStage = inferFindingStage(next)
  const authorizedChainElevation = (
    previousStage === 2
    && nextStage === 2
    && previous.triage_disposition === 'queued'
    && next.triage_disposition === 'elevated'
    && next.raised_by === 'attack-chaining'
    && Array.isArray(next.component_finding_ids)
    && next.component_finding_ids.length >= 2
    && next.component_finding_ids.at(-1) === next.candidate_id
    && severityAbove(next.effective_severity, previous.effective_severity)
  )
  if (nextStage < previousStage || nextStage > previousStage + 1) {
    addError(
      errors,
      'ILLEGAL_STAGE_TRANSITION',
      '',
      `finding stage may stay put or advance by one; received ${previousStage} -> ${nextStage}`,
      { previousStage, nextStage },
    )
  }

  for (const [key, previousValue] of Object.entries(previous)) {
    if (!hasOwn(next, key)) {
      addError(
        errors,
        'FIELD_REMOVED',
        `/${key}`,
        'accumulated finding fields cannot be removed',
      )
      continue
    }

    if (isDeepStrictEqual(previousValue, next[key])) continue

    if (key === 'location') {
      const priorLocations = Array.isArray(previousValue) ? previousValue : []
      const nextLocations = Array.isArray(next[key]) ? next[key] : []
      const onlyAppended = priorLocations.every((location, index) => nextLocations[index] === location)
      if (onlyAppended && nextStage === 2) continue

      addError(
        errors,
        'LOCATION_REWRITTEN',
        '/location',
        'triage may append deduplicated locations but cannot remove, reorder, or rewrite existing locations',
      )
      continue
    }

    if (
      key === 'effective_severity'
      && nextStage === 3
      && hasOwn(next, 'verification_status')
    ) {
      continue
    }
    if (
      authorizedChainElevation
      && ['effective_severity', 'triage_disposition'].includes(key)
    ) {
      continue
    }

    addError(
      errors,
      STAGE_ONE_FIELDS.has(key) ? 'CLAIM_FIELD_CHANGED' : 'ACCUMULATED_FIELD_CHANGED',
      `/${key}`,
      STAGE_ONE_FIELDS.has(key)
        ? 'candidate identity and claim semantics are immutable'
        : 'an accumulated field cannot be overwritten',
    )
  }

  const addedKeys = Object.keys(next).filter((key) => !hasOwn(previous, key))
  if (previousStage >= 2) {
    for (const key of addedKeys.filter((field) => STAGE_ONE_FIELDS.has(field))) {
      addError(
        errors,
        'LATE_CLAIM_FIELD',
        `/${key}`,
        'Stage 1 claim fields cannot be introduced after triage',
      )
    }
  }
  if (previousStage >= 3) {
    for (const key of addedKeys.filter((field) => TRIAGE_FIELDS.has(field))) {
      addError(
        errors,
        'LATE_TRIAGE_FIELD',
        `/${key}`,
        'Stage 2 triage fields cannot be introduced after proof begins',
      )
    }
  }

  const addedProofArgument = addedKeys.some((key) => PROOF_FIELDS.has(key) && key !== 'existence_check')
  if (!hasOwn(previous, 'existence_check') && addedProofArgument) {
    addError(
      errors,
      'EXISTENCE_CHECK_NOT_FIRST',
      '/existence_check',
      'existence_check must be recorded in a prior transition before tier or verification arguments',
    )
  }

  return errors
}

export function validateFindingTransition(previous, next) {
  const previousValidation = validateFinding(previous)
  const nextValidation = validateFinding(next)
  const errors = [
    ...previousValidation.errors.map((error) => ({
      ...error,
      instancePath: `/previous${error.instancePath}`,
    })),
    ...nextValidation.errors.map((error) => ({
      ...error,
      instancePath: `/next${error.instancePath}`,
    })),
    ...transitionInvariantErrors(previous, next),
  ]
  return result(errors.length === 0, errors, {
    previousStage: previousValidation.stage,
    nextStage: nextValidation.stage,
  })
}

export function assertValidFindingTransition(previous, next) {
  const validation = validateFindingTransition(previous, next)
  if (!validation.valid) {
    throw new ContractValidationError('Finding transition validation failed', validation.errors)
  }
  return next
}

function findingFinalizationErrors(record) {
  const errors = []
  const disposition = record?.triage_disposition

  if (!disposition) {
    addError(errors, 'UNTRIAGED_FINDING', '/triage_disposition', 'every finalized finding must reach triage')
    return errors
  }

  if (OPEN_DISPOSITIONS.has(disposition)) {
    if (!TERMINAL_VERIFICATION_STATUSES.has(record.verification_status)) {
      addError(
        errors,
        'UNFINISHED_PROOF',
        '/verification_status',
        'queued and elevated findings require a terminal verification status',
      )
    }

    if (
      ['Critical', 'High'].includes(record.effective_severity)
      && record.verification_status !== 'CONFIRMED'
    ) {
      addError(
        errors,
        'UNPROVEN_HIGH_SEVERITY',
        '/verification_status',
        'an active Critical or High finding must be CONFIRMED before finalization',
      )
    }
  }

  return errors
}

export function finalizeFinding(record) {
  const validation = validateFinding(record)
  const errors = [...validation.errors, ...findingFinalizationErrors(record)]
  if (errors.length > 0) {
    throw new ContractValidationError('Finding finalization failed', errors)
  }
  return deepFreeze(cloneJson(record))
}

function appendNestedErrors(target, prefix, errors) {
  for (const error of errors) {
    target.push({
      ...error,
      instancePath: `${prefix}${error.instancePath}`,
    })
  }
}

function sealedSnapshotInvariantErrors(run) {
  const errors = []
  for (const [field, expectedKind] of [
    ['source_snapshot', 'SOURCE'],
    ['control_snapshot', 'CONTROL'],
  ]) {
    const snapshot = run?.[field]
    if (!snapshot) continue
    if (snapshot.kind !== expectedKind) {
      addError(
        errors,
        'SEALED_SNAPSHOT_KIND_MISMATCH',
        `/${field}/kind`,
        `${field} must have kind ${expectedKind}`,
      )
    }
    if (!hasOwn(run.artifacts ?? {}, snapshot.index_artifact_key)) {
      addError(
        errors,
        'SEALED_SNAPSHOT_INDEX_MISSING',
        `/${field}/index_artifact_key`,
        `${field} references an index artifact that is absent from the run`,
      )
    }
  }
  return errors
}

function attemptInvariantErrors(run) {
  const errors = []
  const events = Array.isArray(run?.attempt_events) ? run.attempt_events : []
  const jobs = new Map(
    (Array.isArray(run?.jobs) ? run.jobs : [])
      .filter((job) => typeof job?.job_id === 'string')
      .map((job) => [job.job_id, job]),
  )
  const attempts = new Map()
  const activeByJob = new Map()
  const latestAttemptByJob = new Map()
  const remoteRequestIds = new Set()
  let previousHash = null
  let previousOccurredAt = parseContractTimestamp(run?.created_at)

  events.forEach((event, index) => {
    const pointer = `/attempt_events/${index}`
    if (event?.sequence !== index + 1) {
      addError(
        errors,
        'ATTEMPT_EVENT_SEQUENCE_BROKEN',
        `${pointer}/sequence`,
        `attempt event sequence must be contiguous; expected ${index + 1}`,
      )
    }
    if (event?.previous_event_sha256 !== previousHash) {
      addError(
        errors,
        'ATTEMPT_EVENT_CHAIN_BROKEN',
        `${pointer}/previous_event_sha256`,
        'attempt event does not reference the preceding event hash',
      )
    }
    try {
      const expectedHash = hashAttemptEvent(event)
      if (event?.event_sha256 !== expectedHash) {
        addError(
          errors,
          'ATTEMPT_EVENT_HASH_MISMATCH',
          `${pointer}/event_sha256`,
          'attempt event hash does not match its canonical content',
        )
      }
    } catch (error) {
      addError(
        errors,
        'ATTEMPT_EVENT_UNHASHABLE',
        pointer,
        `attempt event cannot be canonically hashed: ${error.message}`,
      )
    }
    previousHash = event?.event_sha256 ?? null
    const occurredAt = parseContractTimestamp(event?.occurred_at)
    if (!Number.isFinite(occurredAt)) {
      addError(
        errors,
        'ATTEMPT_EVENT_TIME_INVALID',
        `${pointer}/occurred_at`,
        'attempt event time must be a semantically valid timestamp',
      )
    } else {
      if (Number.isFinite(previousOccurredAt) && occurredAt < previousOccurredAt) {
        addError(
          errors,
          'ATTEMPT_EVENT_TIME_REVERSED',
          `${pointer}/occurred_at`,
          'attempt event time cannot precede run creation or the prior attempt event',
        )
      }
      previousOccurredAt = occurredAt
    }

    const job = jobs.get(event?.job_id)
    if (!job) {
      addError(
        errors,
        'ATTEMPT_JOB_MISSING',
        `${pointer}/job_id`,
        `attempt event references unknown job ${String(event?.job_id)}`,
      )
    }

    const prior = attempts.get(event?.attempt_id)
    if (!prior) {
      if (event?.event !== 'LEASED') {
        addError(
          errors,
          'ATTEMPT_MISSING_LEASE',
          `${pointer}/event`,
          'the first event for an attempt must be LEASED',
        )
      }
      const latest = latestAttemptByJob.get(event?.job_id)
      if (
        event?.event === 'LEASED'
        && latest
        && (
          latest.state !== 'FAILED'
          || latest.last_event?.recoverable !== true
        )
      ) {
        addError(
          errors,
          'ATTEMPT_RETRY_WITHOUT_RECOVERABLE_FAILURE',
          `${pointer}/event`,
          'a fresh attempt requires the prior attempt to end with a recoverable FAILED event',
        )
      }
      if (activeByJob.has(event?.job_id)) {
        addError(
          errors,
          'CONCURRENT_JOB_ATTEMPTS',
          `${pointer}/job_id`,
          `job ${String(event?.job_id)} already has an active attempt`,
        )
      }
      const entry = {
        attempt_id: event?.attempt_id,
        job_id: event?.job_id,
        state: event?.event,
        lease: event?.event === 'LEASED' ? event : undefined,
        last_event: event,
        execution_artifact_key: undefined,
        execution_artifact_sha256: undefined,
        receipt_sha256: undefined,
        failure_artifact_key: undefined,
        failure_artifact_sha256: undefined,
        partial_receipt_sha256: undefined,
      }
      attempts.set(event?.attempt_id, entry)
      if (event?.event === 'LEASED') activeByJob.set(event?.job_id, event?.attempt_id)
    } else {
      if (prior.job_id !== event?.job_id) {
        addError(
          errors,
          'ATTEMPT_JOB_CHANGED',
          `${pointer}/job_id`,
          'all events for an attempt must retain the leased job identity',
        )
      }
      const allowed = ATTEMPT_EVENT_TRANSITIONS.get(prior.state)
      if (!allowed?.has(event?.event)) {
        addError(
          errors,
          'ILLEGAL_ATTEMPT_EVENT_TRANSITION',
          `${pointer}/event`,
          `attempt cannot transition from ${String(prior.state)} to ${String(event?.event)}`,
        )
      }
      if (event?.event === 'STARTED') {
        const startedAt = parseContractTimestamp(event?.occurred_at)
        const expiresAt = parseContractTimestamp(prior.lease?.expires_at)
        if (
          !Number.isFinite(startedAt)
          || !Number.isFinite(expiresAt)
          || startedAt >= expiresAt
        ) {
          addError(
            errors,
            'ATTEMPT_START_OUTSIDE_LEASE',
            `${pointer}/occurred_at`,
            'an attempt must START at a valid time strictly before lease expiry',
          )
        }
      }
      prior.state = event?.event
      prior.last_event = event
      if (['RESULT_CAPTURED', 'VALIDATED', 'COMMITTED'].includes(event?.event)) {
        if (prior.execution_artifact_sha256 === undefined) {
          prior.execution_artifact_key = event?.execution_artifact_key
          prior.execution_artifact_sha256 = event?.execution_artifact_sha256
          prior.receipt_sha256 = event?.receipt_sha256
        } else if (
          prior.execution_artifact_key !== event?.execution_artifact_key
          ||
          prior.execution_artifact_sha256 !== event?.execution_artifact_sha256
          || prior.receipt_sha256 !== event?.receipt_sha256
        ) {
          addError(
            errors,
            'ATTEMPT_RESULT_DIGEST_CHANGED',
            pointer,
            'captured execution and receipt digests are immutable through validation and commit',
          )
        }
      }
      if (event?.event === 'FAILED' && event?.failure_artifact_key !== undefined) {
        prior.failure_artifact_key = event.failure_artifact_key
        prior.failure_artifact_sha256 = event.failure_artifact_sha256
        prior.partial_receipt_sha256 = event.partial_receipt_sha256
      }
      if (['FAILED', 'COMMITTED'].includes(event?.event)) {
        if (activeByJob.get(prior.job_id) === prior.attempt_id) {
          activeByJob.delete(prior.job_id)
        }
      }
    }
    latestAttemptByJob.set(event?.job_id, attempts.get(event?.attempt_id))

    if (event?.event === 'LEASED') {
      for (const [field, expected] of [
        ['plan_sha256', run?.plan_digest],
        ['repository_tree_sha256', run?.repository?.tree_digest],
        ['lens_pack_sha256', run?.lens_pack_digest],
        ['policy_sha256', run?.policy_digest],
        ['source_snapshot_sha256', run?.source_snapshot?.root_sha256],
        ['control_snapshot_sha256', run?.control_snapshot?.root_sha256],
      ]) {
        if (event?.[field] !== expected) {
          addError(
            errors,
            'ATTEMPT_LEASE_PROVENANCE_MISMATCH',
            `${pointer}/${field}`,
            `${field} must bind the immutable run provenance`,
          )
        }
      }
      const leaseOccurredAt = parseContractTimestamp(event?.occurred_at)
      const expiresAt = parseContractTimestamp(event?.expires_at)
      if (
        !Number.isFinite(leaseOccurredAt)
        || !Number.isFinite(expiresAt)
        || expiresAt <= leaseOccurredAt
      ) {
        addError(
          errors,
          'ATTEMPT_LEASE_EXPIRY_INVALID',
          `${pointer}/expires_at`,
          'attempt expiry must be a valid time after the lease time',
        )
      }
      if (['6.0.0', '7.0.0'].includes(run?.schema_version) && event?.backend === undefined) {
        addError(
          errors,
          'ATTEMPT_BACKEND_MISSING',
          `${pointer}/backend`,
          'v6+ attempt leases must declare their execution backend',
        )
      }
      if (event?.backend === 'REMOTE_GATEWAY') {
        if (remoteRequestIds.has(event.request_id)) {
          addError(
            errors,
            'REMOTE_ATTEMPT_REQUEST_REUSED',
            `${pointer}/request_id`,
            'remote request identifiers are one-use within a run',
          )
        }
        remoteRequestIds.add(event.request_id)
        const requestArtifact = run?.artifacts?.[event.request_artifact_key]
        if (!requestArtifact) {
          addError(
            errors,
            'REMOTE_ATTEMPT_REQUEST_ARTIFACT_MISSING',
            `${pointer}/request_artifact_key`,
            'remote attempt lease references an absent signed request artifact',
          )
        } else if (requestArtifact.sha256 !== event.request_artifact_sha256) {
          addError(
            errors,
            'REMOTE_ATTEMPT_REQUEST_ARTIFACT_MISMATCH',
            `${pointer}/request_artifact_sha256`,
            'remote request artifact digest differs from its lease',
          )
        }
      }
    }
  })

  for (const [attemptId, entry] of attempts) {
    const job = jobs.get(entry.job_id)
    if (!job) continue
    if (ACTIVE_ATTEMPT_EVENTS.has(entry.state) && job.state !== 'RUNNING') {
      addError(
        errors,
        'ACTIVE_ATTEMPT_JOB_NOT_RUNNING',
        '/jobs',
        `active attempt ${attemptId} requires job ${entry.job_id} to be RUNNING`,
      )
    }
  }

  for (const [jobId, entry] of latestAttemptByJob) {
    const job = jobs.get(jobId)
    if (!job) continue
    if (entry.state === 'FAILED') {
      const expectedState = entry.last_event?.recoverable ? 'PENDING' : 'FAILED'
      if (job.state !== expectedState) {
        addError(
          errors,
          'FAILED_ATTEMPT_JOB_STATE_MISMATCH',
          '/jobs',
          `latest failed attempt for ${jobId} requires job state ${expectedState}`,
        )
      }
      if (entry.failure_artifact_key !== undefined) {
        const artifact = run?.artifacts?.[entry.failure_artifact_key]
        if (!artifact) {
          addError(
            errors,
            'FAILED_ATTEMPT_ARTIFACT_MISSING',
            '/artifacts',
            `failed attempt ${entry.attempt_id} references a missing failure artifact`,
          )
        } else if (artifact.sha256 !== entry.failure_artifact_sha256) {
          addError(
            errors,
            'FAILED_ATTEMPT_ARTIFACT_DIGEST_MISMATCH',
            `/artifacts/${entry.failure_artifact_key}/sha256`,
            `failed attempt ${entry.attempt_id} artifact digest differs from its event`,
          )
        }
      }
    }
    if (
      entry.state === 'COMMITTED'
      && !['SUCCEEDED', 'FAILED'].includes(job.state)
    ) {
      addError(
        errors,
        'COMMITTED_ATTEMPT_JOB_NOT_TERMINAL',
        '/jobs',
        `committed attempt for ${jobId} requires a terminal provider job`,
      )
    }
  }

  for (const [jobId, job] of jobs) {
    const pointer = `/jobs/${jobId}`
    const provenanceFields = [
      'attempt_id',
      'receipt_sha256',
      'execution_artifact_key',
    ]
    if (job.coverage_authority === 'PROVIDER_DECLARED') {
      for (const field of provenanceFields) {
        if (hasOwn(job, field)) {
          addError(
            errors,
            'DECLARED_COVERAGE_RECEIPT_SMUGGLING',
            `${pointer}/${field}`,
            `provider-declared coverage cannot set controller receipt field ${field}`,
          )
        }
      }
    }
    if ([
      'CONTROLLER_OBSERVED_CONSUMPTION',
      'REMOTE_REQUEST_ACCEPTED',
    ].includes(job.coverage_authority)) {
      const remoteAuthority = job.coverage_authority === 'REMOTE_REQUEST_ACCEPTED'
      if (!['SUCCEEDED', 'FAILED'].includes(job.state)) {
        addError(
          errors,
          'OBSERVED_COVERAGE_JOB_NOT_TERMINAL',
          `${pointer}/state`,
          'authenticated coverage is assigned only when an attempt commits',
        )
      }
      for (const field of provenanceFields) {
        if (!hasOwn(job, field)) {
          addError(
            errors,
            'OBSERVED_COVERAGE_PROVENANCE_MISSING',
            `${pointer}/${field}`,
            `authenticated coverage requires ${field}`,
          )
        }
      }
      const attempt = attempts.get(job.attempt_id)
      const artifact = run?.artifacts?.[job.execution_artifact_key]
      if (
        !attempt
        || attempt.job_id !== jobId
        || attempt.state !== 'COMMITTED'
      ) {
        addError(
          errors,
          'OBSERVED_COVERAGE_ATTEMPT_MISSING',
          `${pointer}/attempt_id`,
          'authenticated coverage requires the matching committed attempt',
        )
      } else {
        if (
          remoteAuthority
            ? attempt.lease?.backend !== 'REMOTE_GATEWAY'
            : attempt.lease?.backend === 'REMOTE_GATEWAY'
        ) {
          addError(
            errors,
            'COVERAGE_AUTHORITY_BACKEND_MISMATCH',
            `${pointer}/coverage_authority`,
            'coverage authority must match the committed attempt backend',
          )
        }
        if (attempt.receipt_sha256 !== job.receipt_sha256) {
          addError(
            errors,
            'OBSERVED_COVERAGE_RECEIPT_MISMATCH',
            `${pointer}/receipt_sha256`,
            'job receipt digest does not match the committed attempt',
          )
        }
        if (artifact?.sha256 !== attempt.execution_artifact_sha256) {
          addError(
            errors,
            'OBSERVED_COVERAGE_EXECUTION_MISMATCH',
            `${pointer}/execution_artifact_key`,
            'execution artifact digest does not match the committed attempt',
          )
        }
        if (attempt.execution_artifact_key !== job.execution_artifact_key) {
          addError(
            errors,
            'OBSERVED_COVERAGE_ARTIFACT_KEY_MISMATCH',
            `${pointer}/execution_artifact_key`,
            'job execution artifact key does not match the committed attempt',
          )
        }
      }
      if (!artifact) {
        addError(
          errors,
          'OBSERVED_COVERAGE_ARTIFACT_MISSING',
          `${pointer}/execution_artifact_key`,
          'authenticated coverage references an absent execution artifact',
        )
      }
    }
    if (
      ['2.0.0', '3.0.0', '4.0.0', '5.0.0', '6.0.0', '7.0.0'].includes(run?.schema_version)
      && ['SUCCEEDED', 'FAILED'].includes(job.state)
      && job.kind !== 'REPORT'
      && (hasOwn(job, 'input_sha256') || hasOwn(job, 'producer'))
      && !hasOwn(job, 'coverage_authority')
    ) {
      addError(
        errors,
        'PROVIDER_COVERAGE_AUTHORITY_MISSING',
        `${pointer}/coverage_authority`,
        'a terminal v2 provider job must label the authority for its coverage claim',
      )
    }
  }

  return errors
}

const COVERAGE_CATEGORY_BY_CLASS = Object.freeze({
  CANONICAL_SOURCE: 'canonical-source',
  GENERATED_CODE: 'generated-code',
  TEST: 'tests',
  DOCUMENTATION: 'docs',
  BINARY: 'binaries',
})

const TERMINAL_CLOSURE_STATES = new Set([
  'CONVERGED',
  'BUDGET_EXHAUSTED',
  'UNMEASURED',
])

function coverageMeasurementMaterial(measurement) {
  return {
    round: measurement.round,
    applicable_lens_file_pairs:
      measurement.applicable_lens_file_pairs,
    examined_lens_file_pairs:
      measurement.examined_lens_file_pairs,
    uncovered_lens_file_pairs:
      measurement.uncovered_lens_file_pairs,
    uncovered_shards: measurement.uncovered_shards,
  }
}

function coverageMeasurementSha256(measurement) {
  return createHash('sha256')
    .update(canonicalJson(coverageMeasurementMaterial(measurement)), 'utf8')
    .digest('hex')
}

function addV3CoverageError(errors, code, path, message, params = {}) {
  addError(errors, code, `/coverage${path}`, message, params)
}

function databaseCandidateScopePaths(candidate) {
  const paths = candidate?.scope_paths ?? candidate?.evidence_paths ?? []
  return Array.isArray(paths)
    ? paths.filter((path) => typeof path === 'string')
    : []
}

function databaseCandidateAuthorityPath(candidate) {
  const paths = candidate?.evidence_paths ?? candidate?.scope_paths ?? []
  return Array.isArray(paths) && typeof paths[0] === 'string'
    ? paths[0]
    : undefined
}

function v3LensJobScope(coverage, job) {
  if (job?.kind !== 'LENS' || typeof job.lens !== 'string') return null
  if (job.shard === undefined) return new Set()
  const parentJobId = job.closure_round === undefined
    ? job.job_id
    : job.parent_job_id
  const shard = (coverage?.shards ?? []).find((row) =>
    row?.job_id === parentJobId
    && row?.lens === job.lens
    && isDeepStrictEqual(row?.shard, job.shard))
  return shard && Array.isArray(shard.scoped_files)
    ? new Set(shard.scoped_files)
    : null
}

function authenticatedSuccessfulV3LensJob(job) {
  return (
    job?.kind === 'LENS'
    && job.state === 'SUCCEEDED'
    && typeof job.input_sha256 === 'string'
    && /^[a-fA-F0-9]{64}$/.test(job.input_sha256)
    && job.producer !== null
    && typeof job.producer === 'object'
    && !Array.isArray(job.producer)
    && [
      'PROVIDER_DECLARED',
      'CONTROLLER_OBSERVED_CONSUMPTION',
      'REMOTE_REQUEST_ACCEPTED',
    ].includes(job.coverage_authority)
  )
}

function v3CoverageInvariantErrors(run) {
  const errors = []
  const coverage = run.coverage
  if (
    coverage === null
    || typeof coverage !== 'object'
    || Array.isArray(coverage)
  ) {
    return errors
  }
  const runJobs = Array.isArray(run.jobs) ? run.jobs : []

  let records = []
  try {
    records = inventoryCoverageRecords(coverage.inventory_records ?? [])
  } catch (error) {
    addV3CoverageError(
      errors,
      'COVERAGE_INVENTORY_RECORD_INVALID',
      '/inventory_records',
      error.message,
    )
  }
  const inventoryPaths = records.map(({ path }) => path)
  if (
    records.length > 0
    && !isDeepStrictEqual(inventoryPaths, coverage.inventory)
  ) {
    addV3CoverageError(
      errors,
      'COVERAGE_TYPED_INVENTORY_MISMATCH',
      '/inventory_records',
      'typed inventory records must exactly match the ordered inventory denominator',
    )
  }
  for (const [index, record] of records.entries()) {
    if (record.category !== COVERAGE_CATEGORY_BY_CLASS[record.coverage_class]) {
      addV3CoverageError(
        errors,
        'COVERAGE_CLASS_CATEGORY_CONFLICT',
        `/inventory_records/${index}/category`,
        `legacy category does not match authoritative class ${record.coverage_class}`,
      )
    }
  }

  try {
    const expected = buildCategoryDenominators(
      records,
      coverage.examined ?? [],
    )
    if (!isDeepStrictEqual(expected, coverage.denominators)) {
      addV3CoverageError(
        errors,
        'COVERAGE_DENOMINATOR_MISMATCH',
        '/denominators',
        'file and byte denominators must be recomputed from immutable typed inventory and examined paths',
      )
    }
  } catch (error) {
    addV3CoverageError(
      errors,
      'COVERAGE_DENOMINATOR_INVALID',
      '/denominators',
      error.message,
    )
  }

  const policy = coverage.policy
  const closure = coverage.closure
  if (policy && closure) {
    if (
      policy.require_source_closure !== closure.required_source_closure
      || policy.max_requeue_rounds !== closure.max_rounds
    ) {
      addV3CoverageError(
        errors,
        'COVERAGE_POLICY_CLOSURE_MISMATCH',
        '/closure',
        'closure policy must exactly match the immutable planned coverage policy',
      )
    }
  }

  const recordByPath = new Map(records.map((record) => [record.path, record]))
  const initialShardJobs = runJobs.filter(
    (job) =>
      job.kind === 'LENS'
      && job.closure_round === undefined
      && job.shard,
  )
  const initialJobById = new Map(
    initialShardJobs.map((job) => [job.job_id, job]),
  )
  const shardRows = Array.isArray(coverage.shards) ? coverage.shards : []
  if (shardRows.length !== initialShardJobs.length) {
    addV3CoverageError(
      errors,
      'COVERAGE_SHARD_DENOMINATOR_MISMATCH',
      '/shards',
      'coverage shards must correspond one-for-one with planned initial lens shards',
    )
  }
  const shardGroups = new Map()
  for (const [index, row] of shardRows.entries()) {
    const pointer = `/shards/${index}`
    if (row === null || typeof row !== 'object' || Array.isArray(row)) {
      addV3CoverageError(
        errors,
        'COVERAGE_SHARD_INVALID',
        pointer,
        'coverage shard must be an object',
      )
      continue
    }
    const job = initialJobById.get(row.job_id)
    if (
      !job
      || job.lens !== row.lens
      || !isDeepStrictEqual(job.shard, row.shard)
    ) {
      addV3CoverageError(
        errors,
        'COVERAGE_SHARD_JOB_MISMATCH',
        pointer,
        `coverage shard ${String(row.job_id)} does not match its immutable lens job`,
      )
      continue
    }
    const scopedFiles = Array.isArray(row.scoped_files)
      ? row.scoped_files
      : []
    if (!isDeepStrictEqual(scopedFiles, [...new Set(scopedFiles)])) {
      addV3CoverageError(
        errors,
        'COVERAGE_SHARD_SCOPE_DUPLICATE',
        `${pointer}/scoped_files`,
        'a shard scope cannot repeat an inventory path',
      )
    }
    const files = []
    for (const path of scopedFiles) {
      const record = recordByPath.get(path)
      if (!record) {
        addV3CoverageError(
          errors,
          'COVERAGE_SHARD_PATH_UNKNOWN',
          `${pointer}/scoped_files`,
          `shard path ${path} is absent from typed inventory`,
        )
      } else {
        files.push(record)
      }
    }
    if (files.length === scopedFiles.length) {
      try {
        const scopeSha256 = digestWorkScope(files)
        const byteCount = files.reduce(
          (total, { size }) => total + size,
          0,
        )
        const shard = row.shard
        if (
          shard.scope_sha256 !== scopeSha256
          || shard.shard_id !== workShardId(shard.index, scopeSha256)
          || shard.file_count !== files.length
          || shard.byte_count !== byteCount
          || shard.max_files !== policy?.max_shard_files
          || shard.max_bytes !== policy?.max_shard_bytes
          || shard.file_count > shard.max_files
          || shard.byte_count > shard.max_bytes
        ) {
          addV3CoverageError(
            errors,
            'COVERAGE_SHARD_METADATA_INVALID',
            `${pointer}/shard`,
            'shard identity, counts, bytes, or limits do not match its exact typed file scope',
          )
        }
      } catch (error) {
        addV3CoverageError(
          errors,
          'COVERAGE_SHARD_SCOPE_INVALID',
          pointer,
          error.message,
        )
      }
    }
    if (row.shard && typeof row.shard === 'object') {
      if (!shardGroups.has(row.lens)) shardGroups.set(row.lens, [])
      shardGroups.get(row.lens).push(row.shard)
    }
  }
  for (const [lens, shards] of shardGroups) {
    const ordered = [...shards].sort((left, right) => left.index - right.index)
    if (ordered.some((shard, index) =>
      shard.index !== index + 1 || shard.count !== ordered.length)) {
      addV3CoverageError(
        errors,
        'COVERAGE_SHARD_SEQUENCE_INVALID',
        '/shards',
        `lens ${lens} shard indexes and counts must form one complete sequence`,
      )
    }
  }

  const databaseCandidates = Array.isArray(
    run.database_discovery?.store_candidates,
  )
    ? run.database_discovery.store_candidates
    : []
  const validDatabaseCandidates = databaseCandidates.filter((candidate) =>
    candidate !== null
    && typeof candidate === 'object'
    && !Array.isArray(candidate)
    && typeof candidate.store_id === 'string')
  const candidateOrder = new Map(
    validDatabaseCandidates.map(
      ({ store_id: storeId }, index) => [storeId, index],
    ),
  )
  const relatedStoreIdsByPath = new Map()
  const authorityStoreIdsByPath = new Map()
  for (const candidate of validDatabaseCandidates) {
    for (const path of new Set(databaseCandidateScopePaths(candidate))) {
      if (!relatedStoreIdsByPath.has(path)) {
        relatedStoreIdsByPath.set(path, [])
      }
      relatedStoreIdsByPath.get(path).push(candidate.store_id)
    }
    const authorityPath = databaseCandidateAuthorityPath(candidate)
    if (authorityPath !== undefined) {
      if (!authorityStoreIdsByPath.has(authorityPath)) {
        authorityStoreIdsByPath.set(authorityPath, [])
      }
      authorityStoreIdsByPath.get(authorityPath).push(candidate.store_id)
    }
  }
  const orderedStoreIdsForScope = (scope, byPath) => [...new Set(
    [...scope].flatMap((path) => byPath.get(path) ?? []),
  )].sort(
    (left, right) =>
      (candidateOrder.get(left) ?? Number.MAX_SAFE_INTEGER)
      - (candidateOrder.get(right) ?? Number.MAX_SAFE_INTEGER),
  )
  const scopedFilesByInitialJob = new Map(
    shardRows
      .filter((row) =>
        row !== null
        && typeof row === 'object'
        && !Array.isArray(row)
        && typeof row.job_id === 'string'
        && Array.isArray(row.scoped_files))
      .map((row) => [row.job_id, row.scoped_files]),
  )
  const baseDatabaseJobs = runJobs
    .map((job, index) => ({ job, index }))
    .filter(({ job }) =>
      job.kind === 'LENS'
      && job.lens === 'database-and-data-stores'
      && job.closure_round === undefined)
  const authorityCountByStore = new Map(
    validDatabaseCandidates.map(({ store_id: storeId }) => [storeId, 0]),
  )

  for (const { job, index } of baseDatabaseJobs) {
    const scope = new Set(scopedFilesByInitialJob.get(job.job_id) ?? [])
    const expectedRelated = orderedStoreIdsForScope(
      scope,
      relatedStoreIdsByPath,
    )
    const expectedAuthority = orderedStoreIdsForScope(
      scope,
      authorityStoreIdsByPath,
    )

    if (!isDeepStrictEqual(job.database_store_ids, expectedRelated)) {
      addError(
        errors,
        'DATABASE_JOB_STORE_METADATA_MISMATCH',
        `/jobs/${index}/database_store_ids`,
        'database shard store IDs must be recomputed from candidate scope intersection',
      )
    }
    if (!isDeepStrictEqual(
      job.profile_authority_store_ids,
      expectedAuthority,
    )) {
      addError(
        errors,
        'DATABASE_JOB_AUTHORITY_METADATA_MISMATCH',
        `/jobs/${index}/profile_authority_store_ids`,
        'database profile authority must be assigned by the candidate evidence home path',
      )
    }
    for (const storeId of (
      Array.isArray(job.profile_authority_store_ids)
        ? job.profile_authority_store_ids
        : []
    )) {
      authorityCountByStore.set(
        storeId,
        (authorityCountByStore.get(storeId) ?? 0) + 1,
      )
    }
  }

  if (baseDatabaseJobs.length > 0) {
    for (const [storeId, count] of authorityCountByStore) {
      if (count !== 1) {
        addError(
          errors,
          'DATABASE_PROFILE_AUTHORITY_COUNT_INVALID',
          '/jobs',
          `discovered store ${storeId} must have exactly one initial profile-authority shard; received ${count}`,
        )
      }
    }
  } else {
    const resolvedGapIds = new Set(coverage.resolved_gap_ids ?? [])
    for (const { store_id: storeId } of validDatabaseCandidates) {
      const openDiscoveryGap = (coverage.gaps ?? []).some((gap) => {
        if (gap?.area !== `store:${storeId}`) return false
        try {
          return !resolvedGapIds.has(exactCoverageGapId(gap))
        } catch {
          return false
        }
      })
      if (!openDiscoveryGap) {
        addError(
          errors,
          'DATABASE_STORE_WITHOUT_LENS_GAP_MISSING',
          '/coverage/gaps',
          `discovered store ${storeId} has no database lens and must remain an explicit open coverage gap`,
        )
      }
    }
  }

  for (const [index, job] of runJobs.entries()) {
    const isDatabaseLens = (
      job.kind === 'LENS'
      && job.lens === 'database-and-data-stores'
    )
    if (
      !isDatabaseLens
      && (
        hasOwn(job, 'database_store_ids')
        || hasOwn(job, 'profile_authority_store_ids')
      )
    ) {
      addError(
        errors,
        'DATABASE_JOB_METADATA_ON_NON_DATABASE_JOB',
        `/jobs/${index}`,
        'database store and profile-authority metadata is reserved for database lens jobs',
      )
    }
    if (!isDatabaseLens || job.closure_round === undefined) continue
    const parent = initialJobById.get(job.parent_job_id)
    if (
      !parent
      || !isDeepStrictEqual(
        job.database_store_ids,
        parent.database_store_ids,
      )
      || !isDeepStrictEqual(
        job.profile_authority_store_ids,
        parent.profile_authority_store_ids,
      )
    ) {
      addError(
        errors,
        'DATABASE_RETRY_STORE_METADATA_MISMATCH',
        `/jobs/${index}`,
        'database closure retries must preserve the parent shard store and profile-authority metadata',
      )
    }
  }

  const expectedRetryCount = shardRows.length * (policy?.max_requeue_rounds ?? 0)
  const retryJobs = runJobs.filter(
    (job) => job.kind === 'LENS' && job.closure_round !== undefined,
  )
  if (retryJobs.length !== expectedRetryCount) {
    addV3CoverageError(
      errors,
      'COVERAGE_RETRY_TEMPLATE_COUNT_INVALID',
      '/shards',
      'each shard and closure round requires exactly one immutable whole-shard retry template',
    )
  }
  const retryCounts = new Map()
  for (const job of retryJobs) {
    try {
      const key = canonicalJson([
        job.closure_round,
        job.parent_job_id,
        job.lens,
        job.shard,
      ])
      retryCounts.set(key, (retryCounts.get(key) ?? 0) + 1)
    } catch {
      // The run schema reports malformed retry identities.
    }
  }
  for (let round = 1; round <= (policy?.max_requeue_rounds ?? 0); round += 1) {
    for (const row of shardRows) {
      let retryCount = 0
      try {
        const retryKey = canonicalJson([
          round,
          row.job_id,
          row.lens,
          row.shard,
        ])
        retryCount = retryCounts.get(retryKey) ?? 0
      } catch {
        retryCount = 0
      }
      if (retryCount !== 1) {
        addV3CoverageError(
          errors,
          'COVERAGE_RETRY_TEMPLATE_MISSING',
          '/shards',
          `shard ${row.job_id} round ${round} must have one sealed whole-shard retry`,
        )
      }
    }
  }

  if (TERMINAL_RUN_STATES.has(run.state)) {
    const successfulScopesByLens = new Map()
    const successfulScope = new Set()
    for (const job of runJobs.filter(authenticatedSuccessfulV3LensJob)) {
      const scope = v3LensJobScope(coverage, job)
      if (scope === null) continue
      if (!successfulScopesByLens.has(job.lens)) {
        successfulScopesByLens.set(job.lens, new Set())
      }
      const lensScope = successfulScopesByLens.get(job.lens)
      for (const path of scope) {
        lensScope.add(path)
        successfulScope.add(path)
      }
    }

    const lensExamined = new Set()
    for (const [index, row] of (coverage.lenses ?? []).entries()) {
      const supported = successfulScopesByLens.get(row.lens) ?? new Set()
      for (const path of row.examined_paths ?? []) {
        lensExamined.add(path)
        if (!supported.has(path)) {
          addV3CoverageError(
            errors,
            'TERMINAL_LENS_COVERAGE_NOT_SUCCESSFUL_JOB_SCOPED',
            `/lenses/${index}/examined_paths`,
            `terminal lens coverage ${row.lens}:${path} is outside every authenticated successful LENS job scope`,
          )
        }
      }
    }
    for (const path of coverage.examined ?? []) {
      if (!successfulScope.has(path) || !lensExamined.has(path)) {
        addV3CoverageError(
          errors,
          'TERMINAL_EXAMINED_COVERAGE_NOT_SUCCESSFUL_JOB_SCOPED',
          '/examined',
          `terminal examined path ${path} is not represented by an authenticated successful scoped LENS job`,
        )
      }
    }
  }

  const gapIds = new Set()
  for (const [index, gap] of (
    Array.isArray(coverage.gaps) ? coverage.gaps : []
  ).entries()) {
    let exactId
    try {
      exactId = exactCoverageGapId(gap)
      gapIds.add(exactId)
    } catch (error) {
      addV3CoverageError(
        errors,
        'COVERAGE_GAP_INVALID',
        `/gaps/${index}`,
        error.message,
      )
      continue
    }
    if (gap?.kind === 'LENS_FILE' && gap.gap_id !== exactId) {
      addV3CoverageError(
        errors,
        'COVERAGE_GAP_ID_INVALID',
        `/gaps/${index}/gap_id`,
        'structured gap identity must be derived only from its immutable lens and path',
      )
    }
  }
  for (const [index, gapId] of (
    Array.isArray(coverage.resolved_gap_ids)
      ? coverage.resolved_gap_ids
      : []
  ).entries()) {
    if (!gapIds.has(gapId)) {
      addV3CoverageError(
        errors,
        'COVERAGE_GAP_RESOLUTION_UNKNOWN',
        `/resolved_gap_ids/${index}`,
        'a resolution must reference an exact gap identity already present in gap history',
      )
    }
  }

  const history = Array.isArray(closure?.history) ? closure.history : []
  let priorRound = -1
  for (const [index, measurement] of history.entries()) {
    const pointer = `/closure/history/${index}`
    if (
      measurement.examined_lens_file_pairs
        + measurement.uncovered_lens_file_pairs
      !== measurement.applicable_lens_file_pairs
    ) {
      addV3CoverageError(
        errors,
        'COVERAGE_MEASUREMENT_ARITHMETIC_INVALID',
        pointer,
        'examined plus uncovered obligations must equal applicable obligations',
      )
    }
    let digestMatches = false
    try {
      digestMatches = (
        measurement.measurement_sha256
        === coverageMeasurementSha256(measurement)
      )
    } catch {
      digestMatches = false
    }
    if (!digestMatches) {
      addV3CoverageError(
        errors,
        'COVERAGE_MEASUREMENT_DIGEST_INVALID',
        `${pointer}/measurement_sha256`,
        'closure measurement digest does not match its canonical counters and shard set',
      )
    }
    if (measurement.round <= priorRound) {
      addV3CoverageError(
        errors,
        'COVERAGE_MEASUREMENT_ROUND_INVALID',
        `${pointer}/round`,
        'closure measurement rounds must be strictly increasing',
      )
    }
    priorRound = measurement.round
    if (
      (measurement.status === 'CONVERGED'
        && measurement.uncovered_lens_file_pairs !== 0)
      || (measurement.status === 'REQUEUED'
        && (
          measurement.uncovered_lens_file_pairs === 0
          || measurement.round >= closure.max_rounds
        ))
      || (measurement.status === 'BUDGET_EXHAUSTED'
        && measurement.uncovered_lens_file_pairs === 0)
    ) {
      addV3CoverageError(
        errors,
        'COVERAGE_MEASUREMENT_STATUS_INVALID',
        `${pointer}/status`,
        'closure status conflicts with the measured uncovered obligations or retry budget',
      )
    }
  }

  if (closure) {
    if (
      closure.status === 'PENDING'
      && (closure.round !== 0 || history.length !== 0)
    ) {
      addV3CoverageError(
        errors,
        'COVERAGE_CLOSURE_PENDING_INVALID',
        '/closure',
        'pending closure must be the unmeasured round-zero state',
      )
    }
    const last = history.at(-1)
    if (closure.status === 'REQUEUED' && (
      !last
      || last.status !== 'REQUEUED'
      || closure.round !== last.round + 1
    )) {
      addV3CoverageError(
        errors,
        'COVERAGE_CLOSURE_REQUEUE_INVALID',
        '/closure',
        'requeued closure must advance exactly one round beyond its latest measurement',
      )
    }
    if (TERMINAL_CLOSURE_STATES.has(closure.status)) {
      let terminalValid = false
      try {
        const measured = measureCoverageClosure(coverage, closure.round)
        terminalValid = Boolean(
          last
          && last.status === closure.status
          && last.round === closure.round
          && isDeepStrictEqual(
            coverageMeasurementMaterial(last),
            coverageMeasurementMaterial(measured),
          )
          && last.measurement_sha256 === measured.measurement_sha256
        )
      } catch {
        terminalValid = false
      }
      if (!terminalValid) {
        addV3CoverageError(
          errors,
          'COVERAGE_CLOSURE_TERMINAL_INVALID',
          '/closure',
          'terminal closure must equal a fresh controller measurement of current lens/file coverage',
        )
      }
    }
  }

  const discoveryPaths = (run.database_discovery?.path_scope ?? [])
    .map(({ path }) => path)
  if (!isDeepStrictEqual(discoveryPaths, coverage.inventory)) {
    addError(
      errors,
      'DATABASE_DISCOVERY_INVENTORY_MISMATCH',
      '/database_discovery/path_scope',
      'database discovery must disposition every inventory path exactly once in inventory order',
    )
  }
  const inventory = new Set(coverage.inventory ?? [])
  for (const [index, candidate] of (
    Array.isArray(run.database_discovery?.store_candidates)
      ? run.database_discovery.store_candidates
      : []
  ).entries()) {
    for (const path of [
      ...(candidate.evidence_paths ?? []),
      ...(candidate.scope_paths ?? []),
    ]) {
      if (!inventory.has(path)) {
        addError(
          errors,
          'DATABASE_DISCOVERY_PATH_OUTSIDE_INVENTORY',
          `/database_discovery/store_candidates/${index}`,
          `discovered store path ${path} is absent from the audit inventory`,
        )
      }
    }
  }

  return errors
}

function v4StoreSynthesisInvariantErrors(run) {
  const errors = []
  if (!['4.0.0', '5.0.0', '6.0.0', '7.0.0'].includes(run.schema_version)) return errors

  const jobs = new Map((run.jobs ?? []).map((job) => [job.job_id, job]))
  const relationships = expectedStoreContributionRelationships(run)
  const relationshipByKey = new Map(relationships.map((relationship) => [
    `${relationship.job_id}\0${relationship.store_id}`,
    relationship,
  ]))
  const contributionCounts = new Map()

  for (const [index, envelope] of (
    Array.isArray(run.store_contributions) ? run.store_contributions : []
  ).entries()) {
    const pointer = `/store_contributions/${index}`
    const job = jobs.get(envelope?.job_id)
    const contribution = envelope?.contribution
    const storeId = contribution?.store_id
    const key = `${envelope?.job_id}\0${storeId}`
    contributionCounts.set(key, (contributionCounts.get(key) ?? 0) + 1)
    const relationship = relationshipByKey.get(key)

    if (
      !job
      || job.kind !== 'LENS'
      || job.lens !== 'database-and-data-stores'
      || job.closure_round !== undefined
      || !authenticatedSuccessfulV3LensJob(job)
      || envelope.input_sha256 !== job.input_sha256
    ) {
      addError(
        errors,
        'STORE_CONTRIBUTION_PROVENANCE_INVALID',
        pointer,
        'store contribution must bind to its authenticated successful base database job',
      )
    }
    if (!relationship) {
      addError(
        errors,
        'STORE_CONTRIBUTION_NOT_ASSIGNED',
        pointer,
        `store contribution ${String(storeId)} is not assigned to job ${String(envelope?.job_id)}`,
      )
      continue
    }
    if (envelope.role !== relationship.role) {
      addError(
        errors,
        'STORE_CONTRIBUTION_ROLE_INVALID',
        `${pointer}/role`,
        'store contribution role must match controller profile authority',
      )
    }
    const hasProfile = contribution?.profile !== undefined
    if (
      (relationship.role === 'AUTHORITY' && !hasProfile)
      || (relationship.role === 'CONTEXT' && hasProfile)
    ) {
      addError(
        errors,
        'STORE_CONTRIBUTION_PROFILE_AUTHORITY_INVALID',
        `${pointer}/contribution`,
        'only the authority contribution must supply the store profile',
      )
    }
    if (
      hasProfile
      && contribution.profile?.store_context?.store_id !== storeId
    ) {
      addError(
        errors,
        'STORE_CONTRIBUTION_PROFILE_STORE_MISMATCH',
        `${pointer}/contribution/profile/store_context/store_id`,
        'authority profile store ID must match its contribution store ID',
      )
    }
    if (hasProfile) {
      errors.push(...storeProfileCommonInvariantErrors(
        contribution.profile,
        `${pointer}/contribution/profile`,
      ))
    }

    const normalized = normalizeStoreContribution(contribution)
    const expectedPaths = expectedStorePathsForJob(run, job ?? {}, storeId)
    const expectedSet = new Set(expectedPaths)
    for (const [pathIndex, path] of (
      Array.isArray(normalized?.evidence_paths)
        ? normalized.evidence_paths
        : []
    ).entries()) {
      if (!expectedSet.has(path)) {
        addError(
          errors,
          'STORE_CONTRIBUTION_EVIDENCE_OUTSIDE_SHARD',
          `${pointer}/contribution/evidence_paths/${pathIndex}`,
          `store contribution evidence ${String(path)} is outside its assigned shard/store intersection`,
        )
      }
    }
    if (
      normalized?.coverage_state === 'ASSESSED'
      && expectedPaths.some(
        (path) => !normalized.evidence_paths.includes(path),
      )
    ) {
      addError(
        errors,
        'ASSESSED_STORE_CONTRIBUTION_SCOPE_OPEN',
        `${pointer}/contribution`,
        'ASSESSED contribution must evidence every discovered store path assigned to its shard',
      )
    }
  }

  for (const [key, count] of contributionCounts) {
    if (count !== 1) {
      addError(
        errors,
        'DUPLICATE_STORE_CONTRIBUTION',
        '/store_contributions',
        `store contribution ${key.replace('\0', '/')} appears ${count} times`,
      )
    }
  }
  for (const relationship of relationships) {
    const job = jobs.get(relationship.job_id)
    if (!authenticatedSuccessfulV3LensJob(job)) continue
    const key = `${relationship.job_id}\0${relationship.store_id}`
    if ((contributionCounts.get(key) ?? 0) !== 1) {
      addError(
        errors,
        'SUCCESSFUL_DATABASE_JOB_CONTRIBUTION_MISSING',
        '/store_contributions',
        `successful database job ${relationship.job_id} must contribute exactly once for store ${relationship.store_id}`,
      )
    }
  }

  const synthesisMaterialized = !['RECON', 'FANOUT'].includes(run.phase)
  const expectedProfiles = synthesisMaterialized
    ? synthesizeStoreProfiles(run).map(({ profile }) => profile)
    : []
  if (!isDeepStrictEqual(run.store_profiles ?? [], expectedProfiles)) {
    addError(
      errors,
      'STORE_SYNTHESIS_MISMATCH',
      '/store_profiles',
      synthesisMaterialized
        ? 'schema 4/5 store profiles must equal controller synthesis from the immutable contribution ledger'
        : 'schema 4/5 store profiles cannot materialize before the fan-out barrier',
    )
  }

  return errors
}

function runInvariantErrors(run, { final = false } = {}) {
  const errors = []
  if (run === null || typeof run !== 'object' || Array.isArray(run)) return errors
  errors.push(...sealedSnapshotInvariantErrors(run))
  errors.push(...attemptInvariantErrors(run))
  if (run.database_conformance !== undefined) {
    const conformance = validateDatabaseConformanceEvidence(
      run.database_conformance,
    )
    for (const error of conformance.errors) {
      addError(
        errors,
        error.code ?? 'DATABASE_CONFORMANCE_EVIDENCE_INVALID',
        `/database_conformance${error.instancePath === '/' ? '' : error.instancePath}`,
        error.message,
        error.params,
      )
    }
  }
  if (modeledDatabaseRun(run)) {
    const schemaValid = validateDatabaseDiscoverySchema(
      run.database_discovery,
    )
    if (!schemaValid) {
      for (const error of normalizeAjvErrors(
        validateDatabaseDiscoverySchema.errors,
      )) {
        addError(
          errors,
          'DATABASE_DISCOVERY_SCHEMA_INVALID',
          `/database_discovery${error.instancePath}`,
          error.message,
          error.params,
        )
      }
    } else {
      const discovery = validateDatabaseDiscovery(run.database_discovery)
      for (const message of discovery.errors) {
        addError(
          errors,
          'DATABASE_DISCOVERY_INVALID',
          '/database_discovery',
          message,
        )
      }
    }
    errors.push(...v3CoverageInvariantErrors(run))
    errors.push(...v4StoreSynthesisInvariantErrors(run))
  }

  const findings = Array.isArray(run.findings) ? run.findings : []
  const jobIds = (run.jobs ?? []).map((job) => job?.job_id).filter(Boolean)
  if (new Set(jobIds).size !== jobIds.length) {
    addError(errors, 'DUPLICATE_JOB_ID', '/jobs', 'job_id must be unique within a run')
  }
  const proofJobs = (run.jobs ?? []).filter(({ kind }) => kind === 'PROOF')
  const proofWaveKey = (job) => job.closure_round === undefined
    ? 'base'
    : `closure:${job.closure_round}`
  const existenceByWave = new Map()
  for (const job of proofJobs) {
    if (!job.job_id?.startsWith('proof-existence:')) continue
    const key = proofWaveKey(job)
    const jobs = existenceByWave.get(key) ?? []
    jobs.push(job)
    existenceByWave.set(key, jobs)
  }
  for (const verification of proofJobs.filter(
    (job) => job.job_id?.startsWith('proof-verification:'),
  )) {
    const existenceJobs = existenceByWave.get(proofWaveKey(verification)) ?? []
    if (
      existenceJobs.length === 0
      || existenceJobs.some(({ state }) => state !== 'SUCCEEDED')
    ) {
      addError(
        errors,
        'PROOF_VERIFICATION_BEFORE_EXISTENCE_WAVE',
        '/jobs',
        `verification job ${verification.job_id} requires every existence result in its proof wave to be committed successfully`,
      )
    }
    const boundExistence = existenceJobs.filter((existence) =>
      isDeepStrictEqual(existence.candidate_ids, verification.candidate_ids))
    if (boundExistence.length !== 1) {
      addError(
        errors,
        'PROOF_PHASE_CANDIDATE_MISMATCH',
        `/jobs/${verification.job_id}/candidate_ids`,
        `verification job ${verification.job_id} must bind exactly one matching existence job in the same proof wave`,
      )
    }
  }
  const errorIds = (run.errors ?? []).map((entry) => entry?.error_id).filter(Boolean)
  if (new Set(errorIds).size !== errorIds.length) {
    addError(errors, 'DUPLICATE_ERROR_ID', '/errors', 'error_id must be unique within a run')
  }
  const byCandidate = new Map()
  findings.forEach((finding, index) => {
    const validation = validateFinding(finding)
    appendNestedErrors(errors, `/findings/${index}`, validation.errors)
    if (typeof finding?.candidate_id !== 'string') return
    if (byCandidate.has(finding.candidate_id)) {
      addError(
        errors,
        'DUPLICATE_CANDIDATE_ID',
        `/findings/${index}/candidate_id`,
        'candidate_id must be unique within a run',
      )
    } else {
      byCandidate.set(finding.candidate_id, { finding, index })
    }
  })

  const storeProfiles = Array.isArray(run.store_profiles) ? run.store_profiles : []
  const byStoreId = new Map()
  const discoveredStores = new Map(
    (run.database_discovery?.store_candidates ?? []).map((candidate) => [
      candidate.store_id,
      candidate,
    ]),
  )
  const inventoryPaths = new Set(run.coverage?.inventory ?? [])
  const databaseExaminedPaths = new Set(
    (run.coverage?.lenses ?? [])
      .filter(({ lens }) => lens === 'database-and-data-stores')
      .flatMap(({ examined_paths: paths }) => paths ?? []),
  )
  storeProfiles.forEach((profile, index) => {
    const storeId = profile?.store_context?.store_id
    const discoveredStore = discoveredStores.get(storeId)
    if (modeledDatabaseRun(run) && !discoveredStore) {
      addError(
        errors,
        'DATABASE_PROFILE_NOT_DISCOVERED',
        `/store_profiles/${index}/store_context/store_id`,
        `store profile ${String(storeId)} is absent from controller discovery`,
      )
    }
    if (
      modeledDatabaseRun(run)
      && !((run.jobs ?? []).some((job) =>
        authenticatedSuccessfulV3LensJob(job)
        && job.lens === 'database-and-data-stores'
        && (job.profile_authority_store_ids ?? []).includes(storeId)))
    ) {
      addError(
        errors,
        'DATABASE_PROFILE_NOT_AUTHORIZED_BY_SUCCESSFUL_JOB',
        `/store_profiles/${index}/store_context/store_id`,
        `store profile ${String(storeId)} is not backed by its successful profile-authority shard`,
      )
    }
    errors.push(...storeProfileCommonInvariantErrors(
      profile,
      `/store_profiles/${index}`,
    ))
    for (const [evidenceIndex, path] of (profile?.evidence_paths ?? []).entries()) {
      if (!inventoryPaths.has(path)) {
        addError(
          errors,
          'DATABASE_PROFILE_EVIDENCE_OUT_OF_SCOPE',
          `/store_profiles/${index}/evidence_paths/${evidenceIndex}`,
          `store profile evidence path ${String(path)} is not in the run inventory`,
        )
      } else if (!databaseExaminedPaths.has(path)) {
        addError(
          errors,
          'DATABASE_PROFILE_EVIDENCE_UNEXAMINED',
          `/store_profiles/${index}/evidence_paths/${evidenceIndex}`,
          `store profile evidence path ${String(path)} was not examined by the database lens`,
        )
      } else if (
        discoveredStore
        && !(discoveredStore.scope_paths ?? discoveredStore.evidence_paths ?? [])
          .includes(path)
      ) {
        addError(
          errors,
          'DATABASE_PROFILE_EVIDENCE_OUTSIDE_DISCOVERED_STORE',
          `/store_profiles/${index}/evidence_paths/${evidenceIndex}`,
          `store profile evidence path ${String(path)} is outside discovered store ${String(storeId)}`,
        )
      }
    }
    if (typeof storeId !== 'string') return
    if (byStoreId.has(storeId)) {
      addError(
        errors,
        'DUPLICATE_STORE_PROFILE',
        `/store_profiles/${index}/store_context/store_id`,
        `store_id ${storeId} must have one immutable run profile`,
      )
    } else {
      byStoreId.set(storeId, { profile, index })
    }
  })
  const databaseJobSucceeded = (run.jobs ?? []).some(
    (job) =>
      job.kind === 'LENS'
      && job.lens === 'database-and-data-stores'
      && job.state === 'SUCCEEDED',
  )
  if (
    !modeledDatabaseRun(run)
    && databaseJobSucceeded
    && (run.activated_lenses ?? []).includes('database-and-data-stores')
    && storeProfiles.length === 0
  ) {
    addError(
      errors,
      'MISSING_STORE_INVENTORY',
      '/store_profiles',
      'a successful activated database lens must record every detected store',
    )
  }
  findings.forEach((finding, index) => {
    if (!isDatabaseFinding(finding)) return
    const storeId = finding.store_context?.store_id
    const entry = byStoreId.get(storeId)
      ?? authorityContributionEntry(run, storeId)
    if (!entry) {
      addError(
        errors,
        'UNPROFILED_DATABASE_FINDING',
        `/findings/${index}/store_context/store_id`,
        `database finding references store ${String(storeId)} without a run-level store profile`,
      )
      return
    }
    if (
      !isDeepStrictEqual(entry.profile.store_context, finding.store_context)
      || !isDeepStrictEqual(entry.profile.principal_path, finding.principal_path)
    ) {
      addError(
        errors,
        'DATABASE_PROFILE_CONFLICT',
        `/findings/${index}/store_context`,
        `database finding conflicts with immutable profile ${storeId}`,
      )
    }
    if (
      entry.profile.coverage_state === 'NOT_ASSESSED'
      && finding.verification_status
      && finding.verification_status !== 'UNPROVEN'
    ) {
      addError(
        errors,
        'UNASSESSED_STORE_CLEARANCE',
        `/findings/${index}/verification_status`,
        `store ${storeId} is NOT_ASSESSED and cannot confirm or clear a finding`,
      )
    }
  })

  for (const [candidateId, entry] of byCandidate) {
    const { finding, index } = entry
    if (finding.triage_disposition !== 'merged') continue
    const targetId = finding.merged_into_candidate_id
    const target = byCandidate.get(targetId)
    if (!target) {
      addError(
        errors,
        'MISSING_MERGE_TARGET',
        `/findings/${index}/merged_into_candidate_id`,
        `merge target ${String(targetId)} does not exist in this run`,
      )
      continue
    }
    if (target.finding.topic !== finding.topic) {
      addError(
        errors,
        'CROSS_TOPIC_MERGE',
        `/findings/${index}/merged_into_candidate_id`,
        'merged candidates must share the same topic deduplication boundary',
      )
    }

    const visited = new Set([candidateId])
    let cursor = target.finding
    while (cursor?.triage_disposition === 'merged') {
      if (visited.has(cursor.candidate_id)) {
        addError(
          errors,
          'MERGE_CYCLE',
          `/findings/${index}/merged_into_candidate_id`,
          'merged_into_candidate_id lineage contains a cycle',
        )
        break
      }
      visited.add(cursor.candidate_id)
      cursor = byCandidate.get(cursor.merged_into_candidate_id)?.finding
    }
  }

  findings.forEach((finding, index) => {
    if (!Array.isArray(finding.component_finding_ids)) return
    for (const componentId of finding.component_finding_ids) {
      if (!byCandidate.has(componentId)) {
        addError(
          errors,
          'MISSING_COMPONENT_FINDING',
          `/findings/${index}/component_finding_ids`,
          `component finding ${componentId} does not exist in this run`,
        )
      }
    }
    if (
      finding.raised_by === 'attack-chaining'
      && finding.component_finding_ids.length < 2
    ) {
      addError(
        errors,
        'CHAIN_REQUIRES_MULTIPLE_COMPONENTS',
        `/findings/${index}/component_finding_ids`,
        'attack-chaining elevation requires at least two component findings',
      )
    }
    if (
      finding.raised_by === 'attack-chaining'
      && finding.component_finding_ids.at(-1) !== finding.candidate_id
    ) {
      addError(
        errors,
        'CHAIN_HOST_NOT_TERMINAL',
        `/findings/${index}/component_finding_ids`,
        'the chain host must be the final component in execution order',
      )
    }
  })

  const chainGraph = new Map(findings
    .filter((finding) => Array.isArray(finding.component_finding_ids))
    .map((finding) => [
      finding.candidate_id,
      finding.component_finding_ids.filter(
        (componentId) => componentId !== finding.candidate_id,
      ),
    ]))
  const visitedChains = new Set()
  const activeChains = new Set()
  const cycleHosts = new Set()
  function visitChain(candidateId) {
    if (activeChains.has(candidateId)) {
      cycleHosts.add(candidateId)
      return true
    }
    if (visitedChains.has(candidateId)) return false
    visitedChains.add(candidateId)
    activeChains.add(candidateId)
    let cyclic = false
    for (const componentId of chainGraph.get(candidateId) ?? []) {
      if (chainGraph.has(componentId) && visitChain(componentId)) cyclic = true
    }
    activeChains.delete(candidateId)
    if (cyclic) cycleHosts.add(candidateId)
    return cyclic
  }
  for (const candidateId of chainGraph.keys()) visitChain(candidateId)
  for (const candidateId of cycleHosts) {
    const index = byCandidate.get(candidateId)?.index
    if (index === undefined) continue
    addError(
      errors,
      'CHAIN_CYCLE',
      `/findings/${index}/component_finding_ids`,
      'component_finding_ids must form an acyclic execution graph',
    )
  }

  const artifacts = Object.values(run.artifacts ?? {})
  findings.forEach((finding, index) => {
    if (!finding.artifact) return
    const bound = artifacts.some((artifact) =>
      artifact?.path === finding.artifact.path
      && String(artifact?.sha256).toLowerCase() === String(finding.artifact.sha256).toLowerCase())
    if (!bound) {
      addError(
        errors,
        'UNBOUND_PROOF_ARTIFACT',
        `/findings/${index}/artifact`,
        'proof artifacts must be SHA-256-hash-manifested in the canonical run bundle',
      )
    }
  })

  const allowedTiers = {
    STATIC: new Set(['T0', 'T3']),
    TEST_EXECUTION: new Set(['T0', 'T1', 'T3']),
    LOCAL_DYNAMIC: new Set(['T0', 'T1', 'T2', 'T3']),
  }[run.capability_mode]
  if (allowedTiers) {
    findings.forEach((finding, index) => {
      if (finding.proof_tier && !allowedTiers.has(finding.proof_tier)) {
        addError(
          errors,
          'CAPABILITY_TIER_BYPASS',
          `/findings/${index}/proof_tier`,
          `${run.capability_mode} does not authorize ${finding.proof_tier}`,
        )
      }
    })
  }

  const coverage = run.coverage
  if (coverage && typeof coverage === 'object') {
    const inventory = new Set(Array.isArray(coverage.inventory) ? coverage.inventory : [])
    const examined = new Set(Array.isArray(coverage.examined) ? coverage.examined : [])
    const unexaminedPaths = Array.isArray(coverage.unexamined)
      ? coverage.unexamined.map((entry) => entry?.path).filter(Boolean)
      : []
    const unexamined = new Set(unexaminedPaths)

    if (unexamined.size !== unexaminedPaths.length) {
      addError(errors, 'DUPLICATE_UNEXAMINED_PATH', '/coverage/unexamined', 'each unexamined path must appear once')
    }

    for (const path of examined) {
      if (!inventory.has(path)) {
        addError(
          errors,
          'COVERAGE_OUTSIDE_INVENTORY',
          '/coverage/examined',
          `examined path ${path} is absent from the inventory denominator`,
        )
      }
      if (unexamined.has(path)) {
        addError(
          errors,
          'AMBIGUOUS_FILE_COVERAGE',
          '/coverage',
          `path ${path} is both examined and unexamined`,
        )
      }
    }
    for (const path of unexamined) {
      if (!inventory.has(path)) {
        addError(
          errors,
          'COVERAGE_OUTSIDE_INVENTORY',
          '/coverage/unexamined',
          `unexamined path ${path} is absent from the inventory denominator`,
        )
      }
    }
    const lensRows = Array.isArray(coverage.lenses) ? coverage.lenses : []
    const lensNames = lensRows.map((entry) => entry?.lens).filter(Boolean)
    if (new Set(lensNames).size !== lensNames.length) {
      addError(errors, 'DUPLICATE_LENS_COVERAGE', '/coverage/lenses', 'each lens must have one coverage disposition')
    }
    lensRows.forEach((row, index) => {
      for (const path of row?.examined_paths ?? []) {
        if (!inventory.has(path) || !examined.has(path)) {
          addError(
            errors,
            'INVALID_LENS_FILE_COVERAGE',
            `/coverage/lenses/${index}/examined_paths`,
            `lens ${row?.lens ?? index} cannot claim unexamined inventory path ${path}`,
          )
        }
      }
    })
    if (final || ['COMPLETED', 'COMPLETE_WITH_GAPS'].includes(run.state)) {
      for (const path of inventory) {
        if (!examined.has(path) && !unexamined.has(path)) {
          addError(
            errors,
            'UNACCOUNTED_FILE',
            '/coverage/inventory',
            `inventory path ${path} has no terminal coverage disposition`,
          )
        }
      }

      for (const lens of Array.isArray(run.activated_lenses) ? run.activated_lenses : []) {
        const row = lensRows.find((entry) => entry?.lens === lens)
        if (!row) {
          addError(
            errors,
            'MISSING_ACTIVATED_LENS_COVERAGE',
            '/coverage/lenses',
            `activated lens ${lens} has no coverage disposition`,
          )
        } else if (row.status === 'NOT_TRIGGERED') {
          addError(
            errors,
            'ACTIVATED_LENS_NOT_TRIGGERED',
            '/coverage/lenses',
            `activated lens ${lens} cannot be marked NOT_TRIGGERED`,
          )
        }
      }
    }
  }

  if (!modeledDatabaseRun(run)) {
    // v3 coverage invariants already report every unidentifiable gap.
    for (const [index, gap] of (
      Array.isArray(run.coverage?.gaps) ? run.coverage.gaps : []
    ).entries()) {
      try {
        exactCoverageGapId(gap)
      } catch (error) {
        addError(
          errors,
          'COVERAGE_GAP_INVALID',
          `/coverage/gaps/${index}`,
          error.message,
        )
      }
    }
  }

  const coverageGaps = [
    ...(run.coverage?.unexamined ?? []),
    ...openCoverageGaps(run.coverage),
    ...uncoveredLensFilePairs(run.coverage ?? {}),
    ...(run.coverage?.lenses ?? []).filter((entry) => ['NOT_ASSESSED', 'FAILED'].includes(entry.status)),
    ...(run.jobs ?? []).filter((job) => job.state === 'FAILED'),
    ...(run.errors ?? []),
    ...storeProfiles.filter(({ coverage_state: state }) => state !== 'ASSESSED'),
    ...(
      run.coverage?.closure && run.coverage.closure.status !== 'CONVERGED'
        ? [run.coverage.closure]
        : []
    ),
  ]
  if (
    ['COMPLETED', 'COMPLETE_WITH_GAPS'].includes(run.state)
    && run.coverage?.closure?.required_source_closure
  ) {
    if (run.coverage.closure.status !== 'CONVERGED') {
      addError(
        errors,
        'SOURCE_CLOSURE_NOT_CONVERGED',
        '/coverage/closure/status',
        'a run requiring source closure can finalize only after coverage converges',
      )
    }
    const openSourceObligations = sourceClosureGaps(run.coverage)
    if (openSourceObligations.length > 0) {
      addError(
        errors,
        'SOURCE_CLOSURE_INCOMPLETE',
        '/coverage',
        `${openSourceObligations.length} canonical source coverage obligations remain open`,
      )
    }
  }
  if (run.state === 'COMPLETED' && coverageGaps.length > 0) {
    addError(
      errors,
      'FALSE_COMPLETE_STATE',
      '/state',
      'a run with unexamined scope, failed work, errors, or coverage gaps must be COMPLETE_WITH_GAPS',
    )
  }
  if (run.state === 'COMPLETE_WITH_GAPS' && coverageGaps.length === 0) {
    addError(
      errors,
      'UNEXPLAINED_GAPS_STATE',
      '/state',
      'COMPLETE_WITH_GAPS requires at least one explicit gap, unexamined path, failed job, or error',
    )
  }

  if (TERMINAL_RUN_STATES.has(run.state)) {
    const nonterminalJobs = (run.jobs ?? []).filter(
      (job) => !TERMINAL_JOB_STATES.has(job.state),
    )
    if (nonterminalJobs.length > 0) {
      addError(
        errors,
        'NONTERMINAL_JOB_IN_TERMINAL_RUN',
        '/jobs',
        'a terminal run cannot contain PENDING or RUNNING jobs',
      )
    }
  }

  if (['COMPLETED', 'COMPLETE_WITH_GAPS'].includes(run.state)) {
    const failedRequiredJobs = (run.jobs ?? []).filter(
      (job) => ['TRIAGE', 'PROOF'].includes(job.kind) && job.state === 'FAILED',
    )
    if (failedRequiredJobs.length > 0) {
      addError(
        errors,
        'REQUIRED_JOB_FAILURE_MUST_FAIL_RUN',
        '/jobs',
        'a failed TRIAGE or PROOF job is terminal audit failure, not a reportable coverage gap',
      )
    }
    const reportJobs = (run.jobs ?? []).filter(
      (job) => job.job_id === 'report:final' && job.kind === 'REPORT',
    )
    if (reportJobs.length !== 1 || reportJobs[0].state !== 'SUCCEEDED') {
      addError(
        errors,
        'FINAL_REPORT_JOB_REQUIRED',
        '/jobs',
        'a completed run requires exactly one successful report:final job',
      )
    }
  }

  if (final) {
    if (!TERMINAL_RUN_STATES.has(run.state)) {
      addError(errors, 'NONTERMINAL_RUN', '/state', 'a finalized run must have a terminal state')
    }
    if (!['COMPLETED', 'COMPLETE_WITH_GAPS'].includes(run.state)) {
      addError(
        errors,
        'UNREPORTABLE_RUN',
        '/state',
        'only COMPLETED or COMPLETE_WITH_GAPS runs can be finalized as an audit report',
      )
    }

    findings.forEach((finding, index) => {
      try {
        finalizeFinding(finding)
      } catch (error) {
        if (error instanceof ContractValidationError) {
          appendNestedErrors(errors, `/findings/${index}`, error.errors)
        } else {
          throw error
        }
      }
    })

    for (const [key, description] of [
      ['report', 'Markdown report'],
      ['sarif', 'SARIF report'],
      ['coverage', 'final coverage record'],
    ]) {
      if (!run.artifacts?.[key]) {
        addError(
          errors,
          `MISSING_${key.toUpperCase()}_ARTIFACT`,
          `/artifacts/${key}`,
          `a finalized audit requires a hashed ${description} artifact`,
        )
      }
    }
  }

  return errors
}

export function validateRun(run) {
  const schemaValid = validateRunSchema(run)
  const errors = schemaValid ? [] : normalizeAjvErrors(validateRunSchema.errors)
  errors.push(...runInvariantErrors(run, {
    final: ['COMPLETED', 'COMPLETE_WITH_GAPS'].includes(run?.state),
  }))
  return result(errors.length === 0, errors)
}

export function assertValidRun(run) {
  const validation = validateRun(run)
  if (!validation.valid) {
    throw new ContractValidationError('Run contract validation failed', validation.errors)
  }
  return run
}

export function finalizeRun(run) {
  const schemaValid = validateRunSchema(run)
  const errors = schemaValid ? [] : normalizeAjvErrors(validateRunSchema.errors)
  errors.push(...runInvariantErrors(run, { final: true }))
  if (errors.length > 0) {
    throw new ContractValidationError('Run finalization failed', errors)
  }
  return deepFreeze(cloneJson(run))
}

function activeProofCandidateIds(run) {
  return (run.findings ?? [])
    .filter((finding) => OPEN_DISPOSITIONS.has(finding.triage_disposition))
    .map(({ candidate_id: candidateId }) => candidateId)
    .filter((candidateId) => typeof candidateId === 'string')
    .sort((left, right) => compareCanonicalStrings(left, right))
}

function proofSchedule(run, prefix) {
  return activeProofCandidateIds(run).map((candidateId) => ({
    job_id: `${prefix}:${candidateId}`,
    kind: 'PROOF',
    state: 'PENDING',
    candidate_ids: [candidateId],
  }))
}

function allJobsTerminal(run, predicate) {
  return (run.jobs ?? [])
    .filter(predicate)
    .every((job) => TERMINAL_JOB_STATES.has(job.state))
}

function expectedScheduledJobs(previous, next, addedJobs) {
  if (previous.state !== 'RUNNING' || next.state !== 'RUNNING') {
    return addedJobs.length === 0 ? [] : null
  }

  if (previous.phase === 'TRIAGE' && next.phase === 'PROOF') {
    if (!allJobsTerminal(
      previous,
      (job) => job.kind === 'TRIAGE' && job.closure_round === undefined,
    )) {
      return null
    }
    return proofSchedule(next, 'proof-existence')
  }

  if (
    previous.phase === 'PROOF'
    && next.phase === 'PROOF'
    && addedJobs.length > 0
  ) {
    const existenceJobs = (previous.jobs ?? []).filter(
      ({ job_id: jobId, kind }) =>
        kind === 'PROOF' && jobId.startsWith('proof-existence:'),
    )
    const verificationJobs = (previous.jobs ?? []).filter(
      ({ job_id: jobId, kind }) =>
        kind === 'PROOF' && jobId.startsWith('proof-verification:'),
    )
    if (
      existenceJobs.length === 0
      || !existenceJobs.every((job) => TERMINAL_JOB_STATES.has(job.state))
      || verificationJobs.length > 0
    ) {
      return null
    }
    return proofSchedule(next, 'proof-verification')
  }

  if (previous.phase === 'PROOF' && next.phase === 'PATCH') {
    const existenceJobs = (previous.jobs ?? []).filter(
      ({ job_id: jobId, kind }) =>
        kind === 'PROOF' && jobId.startsWith('proof-existence:'),
    )
    const verificationJobs = (previous.jobs ?? []).filter(
      ({ job_id: jobId, kind }) =>
        kind === 'PROOF' && jobId.startsWith('proof-verification:'),
    )
    if (
      !existenceJobs.every((job) => TERMINAL_JOB_STATES.has(job.state))
      || !verificationJobs.every((job) => TERMINAL_JOB_STATES.has(job.state))
      || (existenceJobs.length > 0 && verificationJobs.length === 0)
    ) {
      return null
    }
    return [{
      job_id: 'patch:read-only',
      kind: 'PATCH',
      state: 'SKIPPED',
      reason: 'audit mode is read-only; applying patches requires a separate explicit authorization',
    }]
  }

  if (previous.phase === 'PATCH' && next.phase === 'REPORT') {
    if (!allJobsTerminal(previous, (job) => job.kind === 'PATCH')) return null
    return [{
      job_id: 'report:final',
      kind: 'REPORT',
      state: 'PENDING',
    }]
  }

  if (previous.phase === 'COMPLETENESS' && addedJobs.length > 0) {
    const round = next.coverage?.closure?.round
    const priorIds = new Set((previous.jobs ?? []).map(({ job_id: jobId }) => jobId))
    for (const prefix of ['proof-existence', 'proof-verification']) {
      if (!addedJobs.every(({ job_id: jobId, kind, closure_round: jobRound }) =>
        kind === 'PROOF'
        && jobId.startsWith(`${prefix}:`)
        && jobRound === round)) {
        continue
      }
      return proofSchedule(next, prefix)
        .filter(({ job_id: jobId }) => !priorIds.has(jobId))
        .map((job) => ({ ...job, closure_round: round }))
    }
    return null
  }

  return addedJobs.length === 0 ? [] : null
}

function sameJobSet(actual, expected) {
  if (actual.length !== expected.length) return false
  const expectedById = new Map(expected.map((job) => [job.job_id, job]))
  return actual.every((job) =>
    expectedById.has(job.job_id)
    && isDeepStrictEqual(job, expectedById.get(job.job_id)))
}

function runTransitionErrors(previous, next) {
  const errors = []
  if (
    previous === null
    || next === null
    || typeof previous !== 'object'
    || typeof next !== 'object'
    || Array.isArray(previous)
    || Array.isArray(next)
  ) {
    return errors
  }

  if (TERMINAL_RUN_STATES.has(previous.state) && !isDeepStrictEqual(previous, next)) {
    addError(
      errors,
      'TERMINAL_RUN_MUTATION',
      '',
      'terminal runs are immutable',
    )
  }

  const immutableFields = [
    'schema_version',
    'run_id',
    'created_at',
    'capability_mode',
    'repository',
    'policy_digest',
    'lens_pack_digest',
    'plan_digest',
    'scope',
    'activated_lenses',
    'source_snapshot',
    'control_snapshot',
    'database_discovery',
    'database_conformance',
  ]
  for (const field of immutableFields) {
    if (hasOwn(previous, field) && !isDeepStrictEqual(previous[field], next[field])) {
      addError(
        errors,
        'RUN_PROVENANCE_CHANGED',
        `/${field}`,
        'run identity, scope, capability, and provenance are immutable',
      )
    }
  }

  const allowedStates = RUN_STATE_TRANSITIONS.get(previous.state)
  if (allowedStates && !allowedStates.has(next.state)) {
    addError(
      errors,
      'ILLEGAL_RUN_STATE_TRANSITION',
      '/state',
      `run state cannot transition from ${previous.state} to ${next.state}`,
    )
  }

  const previousPhase = RUN_PHASE_RANK.get(previous.phase)
  const nextPhase = RUN_PHASE_RANK.get(next.phase)
  const terminating = ['ABORTED', 'FAILED'].includes(next.state)
  if (
    previousPhase !== undefined
    && nextPhase !== undefined
    && (nextPhase < previousPhase || (!terminating && nextPhase > previousPhase + 1))
  ) {
    addError(
      errors,
      'ILLEGAL_RUN_PHASE_TRANSITION',
      '/phase',
      `run phase may advance by one; received ${previous.phase} -> ${next.phase}`,
    )
  }

  const priorActivated = Array.isArray(previous.activated_lenses) ? previous.activated_lenses : []
  const nextActivated = new Set(Array.isArray(next.activated_lenses) ? next.activated_lenses : [])
  for (const lens of priorActivated) {
    if (!nextActivated.has(lens)) {
      addError(
        errors,
        'ACTIVATED_LENS_REMOVED',
        '/activated_lenses',
        `activated lens ${lens} cannot disappear from the run`,
      )
    }
  }

  const priorFindings = new Map(
    (Array.isArray(previous.findings) ? previous.findings : [])
      .filter((finding) => typeof finding?.candidate_id === 'string')
      .map((finding) => [finding.candidate_id, finding]),
  )
  const nextFindings = new Map(
    (Array.isArray(next.findings) ? next.findings : [])
      .filter((finding) => typeof finding?.candidate_id === 'string')
      .map((finding) => [finding.candidate_id, finding]),
  )
  for (const [candidateId, nextFinding] of nextFindings) {
    if (priorFindings.has(candidateId)) continue
    const stage = inferFindingStage(nextFinding)
    const legal = (
      (stage === 1 && next.phase === 'FANOUT')
      || (stage === 2 && next.phase === 'TRIAGE')
      || (
        modeledDatabaseRun(next)
        && next.phase === 'COMPLETENESS'
        && [1, 2].includes(stage)
      )
    )
    if (!legal) {
      addError(
        errors,
        'LATE_FINDING_INJECTION',
        '/findings',
        `new Stage ${stage} finding ${candidateId} is not legal in ${next.phase}`,
      )
    }
  }
  for (const [candidateId, priorFinding] of priorFindings) {
    const nextFinding = nextFindings.get(candidateId)
    if (!nextFinding) {
      addError(
        errors,
        'FINDING_REMOVED_FROM_RUN',
        '/findings',
        `candidate ${candidateId} cannot disappear from an accumulating run`,
      )
      continue
    }
    const transition = validateFindingTransition(priorFinding, nextFinding)
    appendNestedErrors(errors, `/findings/${candidateId}`, transition.errors)
  }

  const priorJobs = new Map(
    (Array.isArray(previous.jobs) ? previous.jobs : [])
      .filter((job) => typeof job?.job_id === 'string')
      .map((job) => [job.job_id, job]),
  )
  const nextJobs = new Map(
    (Array.isArray(next.jobs) ? next.jobs : [])
      .filter((job) => typeof job?.job_id === 'string')
      .map((job) => [job.job_id, job]),
  )
  const addedJobs = (Array.isArray(next.jobs) ? next.jobs : [])
    .filter((job) =>
      typeof job?.job_id === 'string' && !priorJobs.has(job.job_id))
  const priorAttemptEvents = Array.isArray(previous.attempt_events)
    ? previous.attempt_events
    : []
  const nextAttemptEvents = Array.isArray(next.attempt_events)
    ? next.attempt_events
    : []
  if (
    !priorAttemptEvents.every(
      (event, index) => isDeepStrictEqual(event, nextAttemptEvents[index]),
    )
  ) {
    addError(
      errors,
      'ATTEMPT_EVENT_HISTORY_REWRITTEN',
      '/attempt_events',
      'attempt events are append-only and cannot be removed or rewritten',
    )
  }
  const addedAttemptEvents = nextAttemptEvents.slice(priorAttemptEvents.length)
  if (addedAttemptEvents.length > 1) {
    addError(
      errors,
      'COMPOUND_ATTEMPT_EVENT_TRANSITION',
      '/attempt_events',
      'each durable transition may append at most one attempt event',
    )
  }
  const completedProviderJobs = [...priorJobs]
    .map(([jobId, priorJob]) => ({
      priorJob,
      nextJob: nextJobs.get(jobId),
    }))
    .filter(({ priorJob, nextJob }) =>
      priorJob.state === 'RUNNING'
      && ['SUCCEEDED', 'FAILED'].includes(nextJob?.state)
      && nextJob?.kind !== 'REPORT'
      && !addedAttemptEvents.some(
        (event) =>
          event?.job_id === nextJob?.job_id
          && event?.event === 'FAILED',
      ))
  if (completedProviderJobs.length > 1) {
    addError(
      errors,
      'COMPOUND_PROVIDER_RESULT_TRANSITION',
      '/jobs',
      'one run transition may consume exactly one provider result',
    )
  }
  for (const { nextJob } of completedProviderJobs) {
    if (
      typeof nextJob.input_sha256 !== 'string'
      || !/^[a-fA-F0-9]{64}$/.test(nextJob.input_sha256)
      || nextJob.producer === null
      || typeof nextJob.producer !== 'object'
      || Array.isArray(nextJob.producer)
    ) {
      addError(
        errors,
        'UNBOUND_PROVIDER_RESULT',
        `/jobs/${nextJob.job_id}`,
        'a terminal provider job requires its dispatch digest and producer identity',
      )
    }
  }
  for (const [jobId, priorJob] of priorJobs) {
    const nextJob = nextJobs.get(jobId)
    if (!nextJob) continue
    const matchingEvents = addedAttemptEvents.filter(
      (event) => event?.job_id === jobId,
    )
    if (
      ['2.0.0', '3.0.0', '4.0.0', '5.0.0', '6.0.0', '7.0.0'].includes(next.schema_version)
      && priorJob.state === 'RUNNING'
      && nextJob.state === 'PENDING'
    ) {
      if (
        matchingEvents.length !== 1
        || matchingEvents[0]?.event !== 'FAILED'
        || matchingEvents[0]?.recoverable !== true
      ) {
        addError(
          errors,
          'JOB_RETRY_WITHOUT_RECOVERABLE_FAILURE',
          `/jobs/${jobId}/state`,
          'RUNNING may return to PENDING only with one recoverable FAILED attempt event',
        )
      }
    }
    if (
      priorJob.state === 'RUNNING'
      && ['SUCCEEDED', 'FAILED'].includes(nextJob.state)
      && [
        'CONTROLLER_OBSERVED_CONSUMPTION',
        'REMOTE_REQUEST_ACCEPTED',
      ].includes(nextJob.coverage_authority)
      && (
        matchingEvents.length !== 1
        || matchingEvents[0]?.event !== 'COMMITTED'
        || matchingEvents[0]?.attempt_id !== nextJob.attempt_id
      )
    ) {
      addError(
        errors,
        'OBSERVED_JOB_COMMIT_EVENT_MISSING',
        `/jobs/${jobId}`,
        'an observed provider result must commit its matching attempt in the same transition',
      )
    }
  }
  for (const event of addedAttemptEvents) {
    const priorJob = priorJobs.get(event?.job_id)
    const nextJob = nextJobs.get(event?.job_id)
    if (event?.event === 'LEASED' && !(
      priorJob?.state === 'PENDING' && nextJob?.state === 'RUNNING'
    )) {
      addError(
        errors,
        'ATTEMPT_LEASE_NOT_JOB_BOUND',
        '/attempt_events',
        'a LEASED event must atomically move its job from PENDING to RUNNING',
      )
    }
    if (event?.event === 'FAILED') {
      const expectedState = event.recoverable ? 'PENDING' : 'FAILED'
      if (!(
        priorJob?.state === 'RUNNING' && nextJob?.state === expectedState
      )) {
        addError(
          errors,
          'ATTEMPT_FAILURE_NOT_JOB_BOUND',
          '/attempt_events',
          `a FAILED event must atomically move its job from RUNNING to ${expectedState}`,
        )
      }
    }
    if (event?.event === 'COMMITTED' && !(
      priorJob?.state === 'RUNNING'
      && ['SUCCEEDED', 'FAILED'].includes(nextJob?.state)
      && [
        'CONTROLLER_OBSERVED_CONSUMPTION',
        'REMOTE_REQUEST_ACCEPTED',
      ].includes(nextJob?.coverage_authority)
      && nextJob?.attempt_id === event?.attempt_id
    )) {
      addError(
        errors,
        'ATTEMPT_COMMIT_NOT_JOB_BOUND',
        '/attempt_events',
        'a COMMITTED event must atomically terminate its observed provider job',
      )
    }
  }
  const scheduledJobs = expectedScheduledJobs(previous, next, addedJobs)
  if (scheduledJobs === null || !sameJobSet(addedJobs, scheduledJobs)) {
    addError(
      errors,
      'ILLEGAL_JOB_SCHEDULE',
      '/jobs',
      'new jobs must exactly match the controller schedule for the current phase transition',
    )
  }
  if (
    addedJobs.length > 0
    && [...priorJobs].some(([jobId, priorJob]) =>
      !isDeepStrictEqual(priorJob, nextJobs.get(jobId)))
  ) {
    addError(
      errors,
      'COMPOUND_JOB_SCHEDULE_TRANSITION',
      '/jobs',
      'scheduling new jobs cannot be combined with rewriting or completing existing jobs',
    )
  }
  for (const [jobId, priorJob] of priorJobs) {
    const nextJob = nextJobs.get(jobId)
    if (!nextJob) {
      addError(errors, 'JOB_REMOVED', '/jobs', `job ${jobId} cannot disappear from an accumulating run`)
      continue
    }
    if (
      priorJob.kind !== nextJob.kind
      || priorJob.lens !== nextJob.lens
      || !isDeepStrictEqual(priorJob.shard, nextJob.shard)
      || priorJob.closure_round !== nextJob.closure_round
      || priorJob.parent_job_id !== nextJob.parent_job_id
      || !isDeepStrictEqual(
        priorJob.database_store_ids,
        nextJob.database_store_ids,
      )
      || !isDeepStrictEqual(
        priorJob.profile_authority_store_ids,
        nextJob.profile_authority_store_ids,
      )
    ) {
      addError(
        errors,
        'JOB_IDENTITY_CHANGED',
        `/jobs/${jobId}`,
        'job kind, lens, shard, closure round, parent, and database authority are immutable',
      )
    }
    if (
      hasOwn(priorJob, 'candidate_ids')
      && !isDeepStrictEqual(priorJob.candidate_ids, nextJob.candidate_ids)
    ) {
      addError(
        errors,
        'JOB_CANDIDATES_CHANGED',
        `/jobs/${jobId}/candidate_ids`,
        'a job candidate set is immutable once recorded',
      )
    }
    for (const field of [
      'input_sha256',
      'producer',
      'coverage_authority',
      'attempt_id',
      'receipt_sha256',
      'execution_artifact_key',
    ]) {
      if (
        hasOwn(priorJob, field)
        && !isDeepStrictEqual(priorJob[field], nextJob[field])
      ) {
        addError(
          errors,
          'JOB_PROVENANCE_CHANGED',
          `/jobs/${jobId}/${field}`,
          'job packet and producer provenance are immutable once recorded',
        )
      }
    }
    const allowedJobStates = JOB_STATE_TRANSITIONS.get(priorJob.state)
    if (allowedJobStates && !allowedJobStates.has(nextJob.state)) {
      addError(
        errors,
        'ILLEGAL_JOB_STATE_TRANSITION',
        `/jobs/${jobId}/state`,
        `job state cannot transition from ${priorJob.state} to ${nextJob.state}`,
      )
    }
  }

  const previousCoverage = previous.coverage ?? {}
  const nextCoverage = next.coverage ?? {}
  if (!isDeepStrictEqual(previousCoverage.inventory, nextCoverage.inventory)) {
    addError(
      errors,
      'COVERAGE_INVENTORY_CHANGED',
      '/coverage/inventory',
      'the inventory coverage denominator is immutable after planning',
    )
  }
  for (const field of ['policy', 'inventory_records', 'shards']) {
    if (
      hasOwn(previousCoverage, field)
      && !isDeepStrictEqual(previousCoverage[field], nextCoverage[field])
    ) {
      addError(
        errors,
        'COVERAGE_DENOMINATOR_CHANGED',
        `/coverage/${field}`,
        `${field} is immutable after planning`,
      )
    }
  }

  const previousExamined = new Set(
    Array.isArray(previousCoverage.examined) ? previousCoverage.examined : [],
  )
  const nextExamined = new Set(
    Array.isArray(nextCoverage.examined) ? nextCoverage.examined : [],
  )
  const previousUnexamined = new Map(
    (Array.isArray(previousCoverage.unexamined) ? previousCoverage.unexamined : [])
      .map((entry) => [entry.path, entry]),
  )
  const nextUnexamined = new Map(
    (Array.isArray(nextCoverage.unexamined) ? nextCoverage.unexamined : [])
      .map((entry) => [entry.path, entry]),
  )
  for (const [path, nextEntry] of nextUnexamined) {
    const priorEntry = previousUnexamined.get(path)
    if (!priorEntry) {
      addError(
        errors,
        'UNEXAMINED_COVERAGE_ADDED',
        '/coverage/unexamined',
        `unexamined path ${path} cannot be introduced after planning`,
      )
    } else if (!isDeepStrictEqual(priorEntry, nextEntry)) {
      addError(
        errors,
        'UNEXAMINED_COVERAGE_REWRITTEN',
        '/coverage/unexamined',
        `unexamined disposition for ${path} is immutable until the path is examined`,
      )
    }
  }
  for (const path of previousUnexamined.keys()) {
    if (!nextUnexamined.has(path) && !nextExamined.has(path)) {
      addError(
        errors,
        'UNEXAMINED_COVERAGE_REMOVED_WITHOUT_EXAMINATION',
        '/coverage/unexamined',
        `unexamined path ${path} can disappear only when it becomes examined`,
      )
    }
  }
  const priorGaps = Array.isArray(previousCoverage.gaps) ? previousCoverage.gaps : []
  const nextGaps = Array.isArray(nextCoverage.gaps) ? nextCoverage.gaps : []
  if (!priorGaps.every((gap, index) => isDeepStrictEqual(gap, nextGaps[index]))) {
    addError(
      errors,
      'COVERAGE_GAP_HISTORY_REWRITTEN',
      '/coverage/gaps',
      'coverage gaps are append-only and cannot be removed or rewritten',
    )
  }
  const priorResolvedGaps = Array.isArray(previousCoverage.resolved_gap_ids)
    ? previousCoverage.resolved_gap_ids
    : []
  const nextResolvedGaps = Array.isArray(nextCoverage.resolved_gap_ids)
    ? nextCoverage.resolved_gap_ids
    : []
  if (!priorResolvedGaps.every((gapId) => nextResolvedGaps.includes(gapId))) {
    addError(
      errors,
      'RESOLVED_COVERAGE_GAP_REOPENED',
      '/coverage/resolved_gap_ids',
      'a resolved coverage gap cannot be reopened',
    )
  }
  const newlyResolvedGaps = nextResolvedGaps.filter(
    (gapId) => !priorResolvedGaps.includes(gapId),
  )
  const completingJob = completedProviderJobs.length === 1
    ? completedProviderJobs[0].nextJob
    : null
  const addedStoreIds = new Set(
    (next.store_profiles ?? [])
      .slice((previous.store_profiles ?? []).length)
      .map((profile) => profile?.store_context?.store_id)
      .filter(Boolean),
  )
  for (const gapId of newlyResolvedGaps) {
    const gap = nextGaps.find((candidate) =>
      coverageGapIdOrUndefined(candidate) === gapId)
    const lensFileResolution = (
      gap?.kind === 'LENS_FILE'
      && completingJob?.kind === 'LENS'
      && completingJob.state === 'SUCCEEDED'
      && completingJob.lens === gap.lens
      && (nextCoverage.lenses ?? [])
        .find(({ lens }) => lens === gap.lens)
        ?.examined_paths?.includes(gap.path)
    )
    const storeResolution = (
      completingJob?.kind === 'LENS'
      && completingJob.state === 'SUCCEEDED'
      && completingJob.lens === 'database-and-data-stores'
      && typeof gap?.area === 'string'
      && gap.area.startsWith('store:')
      && addedStoreIds.has(gap.area.slice('store:'.length))
    )
    const synthesisResolution = (
      ['4.0.0', '5.0.0', '6.0.0', '7.0.0'].includes(next.schema_version)
      && previous.phase === 'FANOUT'
      && next.phase === 'TRIAGE'
      && typeof gap?.area === 'string'
      && gap.area.startsWith('store:')
      && addedStoreIds.has(gap.area.slice('store:'.length))
    )
    if (
      !gap
      || (!lensFileResolution && !storeResolution && !synthesisResolution)
    ) {
      addError(
        errors,
        'COVERAGE_GAP_RESOLUTION_NOT_JOB_BACKED',
        '/coverage/resolved_gap_ids',
        `resolved coverage gap ${gapId} is not backed by the completing provider job`,
      )
    }
  }
  const priorClosure = previousCoverage.closure
  const nextClosure = nextCoverage.closure
  if (priorClosure && nextClosure) {
    for (const field of ['required_source_closure', 'max_rounds']) {
      if (!isDeepStrictEqual(priorClosure[field], nextClosure[field])) {
        addError(
          errors,
          'CLOSURE_POLICY_CHANGED',
          `/coverage/closure/${field}`,
          'coverage closure policy is immutable after planning',
        )
      }
    }
    const priorHistory = Array.isArray(priorClosure.history)
      ? priorClosure.history
      : []
    const nextHistory = Array.isArray(nextClosure.history)
      ? nextClosure.history
      : []
    if (!priorHistory.every((entry, index) =>
      isDeepStrictEqual(entry, nextHistory[index]))) {
      addError(
        errors,
        'CLOSURE_HISTORY_REWRITTEN',
        '/coverage/closure/history',
        'coverage closure history is append-only',
      )
    }
    if (
      Number.isSafeInteger(priorClosure.round)
      && Number.isSafeInteger(nextClosure.round)
      && nextClosure.round < priorClosure.round
    ) {
      addError(
        errors,
        'CLOSURE_ROUND_REWOUND',
        '/coverage/closure/round',
        'coverage closure round cannot move backward',
      )
    }
  }
  for (const path of previousExamined) {
    if (!nextExamined.has(path)) {
      addError(
        errors,
        'EXAMINED_COVERAGE_REMOVED',
        '/coverage/examined',
        `examined path ${path} cannot be removed from accumulated coverage`,
      )
    }
  }

  const previousLensRows = new Map(
    (Array.isArray(previousCoverage.lenses) ? previousCoverage.lenses : [])
      .filter((row) => typeof row?.lens === 'string')
      .map((row) => [row.lens, row]),
  )
  const nextLensRows = new Map(
    (Array.isArray(nextCoverage.lenses) ? nextCoverage.lenses : [])
      .filter((row) => typeof row?.lens === 'string')
      .map((row) => [row.lens, row]),
  )
  const jobTransitionForLens = (lens, kind, state) =>
    [...priorJobs].some(([jobId, priorJob]) => {
      const nextJob = nextJobs.get(jobId)
      return (
        priorJob.lens === lens
        && (kind === undefined || priorJob.kind === kind)
        && priorJob.state === 'RUNNING'
        && nextJob?.state === state
      )
    })
  const successfulLensCompletions = completedProviderJobs.filter(
    ({ nextJob }) =>
      nextJob?.kind === 'LENS'
      && nextJob.state === 'SUCCEEDED'
      && typeof nextJob.lens === 'string',
  )
  const successfulCompletionByLens = new Map(
    successfulLensCompletions.map(({ priorJob, nextJob }) => [
      nextJob.lens,
      {
        job: nextJob,
        scope: modeledDatabaseRun(next)
          ? v3LensJobScope(previousCoverage, priorJob)
          : null,
      },
    ]),
  )
  const successfullyExaminedByLensJob = new Set()
  for (const { priorJob, nextJob } of successfulLensCompletions) {
    const priorPaths = new Set(
      previousLensRows.get(nextJob.lens)?.examined_paths ?? [],
    )
    const scope = modeledDatabaseRun(next)
      ? v3LensJobScope(previousCoverage, priorJob)
      : null
    for (const path of nextLensRows.get(nextJob.lens)?.examined_paths ?? []) {
      if (
        !priorPaths.has(path)
        && (!modeledDatabaseRun(next) || scope?.has(path))
      ) {
        successfullyExaminedByLensJob.add(path)
      }
    }
  }

  for (const lens of nextLensRows.keys()) {
    if (!previousLensRows.has(lens)) {
      addError(
        errors,
        'LENS_COVERAGE_ADDED',
        '/coverage/lenses',
        `lens coverage row ${lens} cannot be added after planning`,
      )
    }
  }
  for (const [lens, priorRow] of previousLensRows) {
    const nextRow = nextLensRows.get(lens)
    if (!nextRow) {
      addError(
        errors,
        'LENS_COVERAGE_REMOVED',
        '/coverage/lenses',
        `lens coverage row ${lens} cannot disappear`,
      )
      continue
    }

    if (!isDeepStrictEqual(priorRow.applicable_paths, nextRow.applicable_paths)) {
      addError(
        errors,
        'LENS_APPLICABLE_PATHS_CHANGED',
        '/coverage/lenses',
        `lens ${lens} applicable path denominator is immutable`,
      )
    }

    if (priorRow.status !== nextRow.status) {
      const backedByResult = (
        (
          priorRow.status === 'NOT_ASSESSED'
          || (
            modeledDatabaseRun(next)
            && ['FAILED', 'RAN'].includes(priorRow.status)
          )
        )
        && (
          (
            nextRow.status === 'RAN'
            && jobTransitionForLens(lens, undefined, 'SUCCEEDED')
          )
          || (
            nextRow.status === 'FAILED'
            && jobTransitionForLens(lens, undefined, 'FAILED')
          )
        )
      )
      if (!backedByResult) {
        addError(
          errors,
          'LENS_COVERAGE_STATUS_REWRITTEN',
          '/coverage/lenses',
          `lens ${lens} coverage status cannot transition from ${priorRow.status} to ${nextRow.status}`,
        )
      }
    } else if (
      !isDeepStrictEqual(priorRow.reason, nextRow.reason)
      && !(
        modeledDatabaseRun(next)
        && (
          jobTransitionForLens(lens, undefined, nextRow.status === 'FAILED'
            ? 'FAILED'
            : 'SUCCEEDED')
          || (previous.phase === 'FANOUT' && next.phase === 'TRIAGE')
          || (
            previous.phase === 'COMPLETENESS'
            && next.phase === 'COMPLETENESS'
            && (nextCoverage.closure?.history?.length ?? 0)
              === (previousCoverage.closure?.history?.length ?? 0) + 1
          )
        )
      )
    ) {
      addError(
        errors,
        'LENS_COVERAGE_REASON_REWRITTEN',
        '/coverage/lenses',
        `lens ${lens} coverage reason is immutable unless its status advances`,
      )
    }

    const priorPaths = new Set(
      Array.isArray(priorRow.examined_paths) ? priorRow.examined_paths : [],
    )
    const nextPaths = new Set(
      Array.isArray(nextRow.examined_paths) ? nextRow.examined_paths : [],
    )
    for (const path of priorPaths) {
      if (!nextPaths.has(path)) {
        addError(
          errors,
          'LENS_EXAMINED_PATH_REMOVED',
          '/coverage/lenses',
          `lens ${lens} cannot remove examined path ${path}`,
        )
      }
    }
    const addedPaths = [...nextPaths].filter((path) => !priorPaths.has(path))
    if (addedPaths.length > 0) {
      const completion = successfulCompletionByLens.get(lens)
      if (!completion) {
        addError(
          errors,
          'LENS_EXAMINED_PATH_NOT_JOB_BACKED',
          '/coverage/lenses',
          `new examined paths for lens ${lens} require its exact LENS job to succeed in the same transition`,
        )
      } else if (modeledDatabaseRun(next)) {
        if (completion.scope === null) {
          addError(
            errors,
            'LENS_EXAMINED_PATH_JOB_SCOPE_UNSEALED',
            '/coverage/lenses',
            `successful LENS job ${completion.job.job_id} has no matching sealed shard scope`,
          )
        }
        for (const path of addedPaths) {
          if (!completion.scope?.has(path)) {
            addError(
              errors,
              'LENS_EXAMINED_PATH_OUTSIDE_JOB_SCOPE',
              '/coverage/lenses',
              `lens ${lens} cannot add ${path} from outside completing job ${completion.job.job_id}`,
            )
          }
        }
      }
    }
  }

  for (const path of nextExamined) {
    if (previousExamined.has(path)) continue
    if (!successfullyExaminedByLensJob.has(path)) {
      addError(
        errors,
        'EXAMINED_COVERAGE_NOT_JOB_BACKED',
        '/coverage/examined',
        modeledDatabaseRun(next)
          ? `new examined path ${path} requires the exact successful scoped LENS result in the same transition`
          : `new examined path ${path} requires a successful LENS job in the same transition`,
      )
    }
  }

  const changedFindingIds = new Set()
  for (const [candidateId, nextFinding] of nextFindings) {
    if (!isDeepStrictEqual(priorFindings.get(candidateId), nextFinding)) {
      changedFindingIds.add(candidateId)
    }
  }
  if (changedFindingIds.size > 0 && completedProviderJobs.length !== 1) {
    addError(
      errors,
      'FINDING_DELTA_NOT_JOB_BOUND',
      '/findings',
      'finding additions or updates require exactly one terminal provider job',
    )
  }
  if (completedProviderJobs.length === 1) {
    const [{ nextJob }] = completedProviderJobs
    const expectedIds = [...(nextJob.candidate_ids ?? [])].sort()
    const changedIds = [...changedFindingIds].sort()
    const closureLensReplay = (
      modeledDatabaseRun(next)
      && nextJob.state === 'SUCCEEDED'
      && nextJob.kind === 'LENS'
      && Number.isInteger(nextJob.closure_round)
      && nextJob.closure_round > 0
    )
    const replayIds = closureLensReplay
      ? expectedIds.filter((candidateId) => {
          const priorFinding = priorFindings.get(candidateId)
          const nextFinding = nextFindings.get(candidateId)
          return (
            priorFinding !== undefined
            && priorFinding.lens === nextJob.lens
            && isDeepStrictEqual(priorFinding, nextFinding)
          )
        })
      : []
    const changedExistingIds = closureLensReplay
      ? changedIds.filter((candidateId) => priorFindings.has(candidateId))
      : []
    const resultBoundIds = closureLensReplay
      ? [...new Set([...changedIds, ...replayIds])]
          .sort((left, right) => compareCanonicalStrings(left, right))
      : changedIds
    if (
      nextJob.state === 'SUCCEEDED'
      &&
      ['LENS', 'TRIAGE', 'PROOF'].includes(nextJob.kind)
      && (
        !isDeepStrictEqual(expectedIds, resultBoundIds)
        || changedExistingIds.length > 0
      )
    ) {
      addError(
        errors,
        'FINDING_DELTA_JOB_MISMATCH',
        `/jobs/${nextJob.job_id}/candidate_ids`,
        closureLensReplay
          ? 'closure LENS candidate_ids must exactly identify new findings and unchanged same-lens Stage-1 replays'
          : 'job candidate_ids must exactly identify the finding records changed by its result',
      )
    }
    if (
      (
        nextJob.state === 'FAILED'
        || !['LENS', 'TRIAGE', 'PROOF'].includes(nextJob.kind)
      )
      && changedIds.length > 0
    ) {
      addError(
        errors,
        'UNAUTHORIZED_FINDING_DELTA',
        '/findings',
        `${nextJob.kind} jobs cannot add or update findings`,
      )
    }
  }

  const priorContributionCount = Array.isArray(previous.store_contributions)
    ? previous.store_contributions.length
    : 0
  const nextContributions = Array.isArray(next.store_contributions)
    ? next.store_contributions
    : []
  const addedContributions = nextContributions.slice(priorContributionCount)
  if (addedContributions.length > 0) {
    const databaseCompletion = completedProviderJobs.length === 1
      ? completedProviderJobs[0].nextJob
      : null
    if (
      !['4.0.0', '5.0.0', '6.0.0', '7.0.0'].includes(next.schema_version)
      || databaseCompletion?.kind !== 'LENS'
      || databaseCompletion?.lens !== 'database-and-data-stores'
      || databaseCompletion?.closure_round !== undefined
      || databaseCompletion?.state !== 'SUCCEEDED'
      || addedContributions.some((envelope) =>
        envelope.job_id !== databaseCompletion.job_id
        || envelope.input_sha256 !== databaseCompletion.input_sha256)
    ) {
      addError(
        errors,
        'STORE_CONTRIBUTION_DELTA_NOT_JOB_BOUND',
        '/store_contributions',
        'store contributions may be appended only by their one successful schema 4/5 base database result',
      )
    }
  }

  const priorProfileCount = Array.isArray(previous.store_profiles)
    ? previous.store_profiles.length
    : 0
  const nextProfiles = Array.isArray(next.store_profiles) ? next.store_profiles : []
  const addedProfiles = nextProfiles.slice(priorProfileCount)
  if (addedProfiles.length > 0) {
    if (['4.0.0', '5.0.0', '6.0.0', '7.0.0'].includes(next.schema_version)) {
      const expectedProfiles = synthesizeStoreProfiles(next)
        .map(({ profile }) => profile)
      if (
        previous.phase !== 'FANOUT'
        || next.phase !== 'TRIAGE'
        || !isDeepStrictEqual(nextProfiles, expectedProfiles)
      ) {
        addError(
          errors,
          'STORE_PROFILE_DELTA_NOT_SYNTHESIZED',
          '/store_profiles',
          'schema 4/5 profiles may be appended only as exact controller synthesis at the fan-out barrier',
        )
      }
    } else {
    const databaseCompletion = completedProviderJobs.length === 1
      ? completedProviderJobs[0].nextJob
      : null
    if (
      databaseCompletion?.kind !== 'LENS'
      || databaseCompletion?.lens !== 'database-and-data-stores'
      || databaseCompletion?.state !== 'SUCCEEDED'
    ) {
      addError(
        errors,
        'STORE_PROFILE_DELTA_NOT_JOB_BOUND',
        '/store_profiles',
        'store profiles may be appended only by one successful database lens result',
      )
    } else {
      const authorizedStoreIds = new Set(
        databaseCompletion.profile_authority_store_ids ?? [],
      )
      const priorDatabaseRow = previousLensRows.get('database-and-data-stores')
      const nextDatabaseRow = nextLensRows.get('database-and-data-stores')
      const priorDatabasePaths = new Set(priorDatabaseRow?.examined_paths ?? [])
      const resultDatabasePaths = new Set(
        (nextDatabaseRow?.examined_paths ?? [])
          .filter((path) => !priorDatabasePaths.has(path)),
      )
      for (const profile of addedProfiles) {
        if (
          modeledDatabaseRun(next)
          && !authorizedStoreIds.has(profile.store_context?.store_id)
        ) {
          addError(
            errors,
            'STORE_PROFILE_NOT_JOB_AUTHORIZED',
            '/store_profiles',
            `new profile ${String(profile.store_context?.store_id)} is not assigned to completing database job ${databaseCompletion.job_id}`,
          )
        }
        for (const path of profile.evidence_paths ?? []) {
          if (!resultDatabasePaths.has(path)) {
            addError(
              errors,
              'STORE_PROFILE_EVIDENCE_NOT_RESULT_BOUND',
              '/store_profiles',
              `new profile ${String(profile.store_context?.store_id)} cites ${path} outside the completing database result`,
            )
          }
        }
      }
    }
    }
  }

  for (const field of ['errors', 'store_contributions', 'store_profiles']) {
    const priorItems = Array.isArray(previous[field]) ? previous[field] : []
    const nextItems = Array.isArray(next[field]) ? next[field] : []
    if (!priorItems.every((item, index) => isDeepStrictEqual(item, nextItems[index]))) {
      addError(errors, 'RUN_HISTORY_REWRITTEN', `/${field}`, `${field} is append-only`)
    }
  }

  for (const [name, artifact] of Object.entries(previous.artifacts ?? {})) {
    if (!isDeepStrictEqual(artifact, next.artifacts?.[name])) {
      addError(
        errors,
        'ARTIFACT_REWRITTEN',
        `/artifacts/${name}`,
        'a named artifact is immutable once recorded',
      )
    }
  }

  return errors
}

export function validateRunTransition(previous, next) {
  const previousValidation = validateRun(previous)
  const nextValidation = validateRun(next)
  const errors = [
    ...previousValidation.errors.map((error) => ({
      ...error,
      instancePath: `/previous${error.instancePath}`,
    })),
    ...nextValidation.errors.map((error) => ({
      ...error,
      instancePath: `/next${error.instancePath}`,
    })),
    ...runTransitionErrors(previous, next),
  ]
  return result(errors.length === 0, errors)
}

export function validateRunTransitionSemantics(previous, next) {
  const errors = runTransitionErrors(previous, next)
  return result(errors.length === 0, errors)
}

export function assertValidRunTransitionSemantics(previous, next) {
  const validation = validateRunTransitionSemantics(previous, next)
  if (!validation.valid) {
    throw new ContractValidationError(
      'Run transition semantic validation failed',
      validation.errors,
    )
  }
  return next
}

export function assertValidRunTransition(previous, next) {
  const validation = validateRunTransition(previous, next)
  if (!validation.valid) {
    throw new ContractValidationError('Run transition validation failed', validation.errors)
  }
  return next
}
