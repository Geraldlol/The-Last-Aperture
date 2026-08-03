import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import { artifactKeyToken } from './artifact-names.mjs'
import { compareCanonicalStrings } from './canonical-order.mjs'
import {
  isUnresolvedDatabaseDescriptor,
  routeDatabaseAdapter,
} from './database-adapters.mjs'
import {
  coverageMetrics,
  finalizedFanoutLensRows,
  isModeledCoverage,
  sourceClosureGaps,
} from './coverage-closure.mjs'
import {
  createLensFileCoverageGap,
  exactCoverageGapId,
  filterResolvedCoverageGaps,
} from './coverage-gaps.mjs'
import {
  measureCoverageClosure,
  refreshCategoryDenominators,
} from './coverage-model.mjs'
import {
  assertValidFinding,
  assertValidFindingTransition,
  assertValidRunTransition,
  findingSchema,
  finalizeRun,
  inferFindingStage,
  isExactStageOneReplay,
  storeContributionSchema,
  storeProfileSchema,
} from './contracts.mjs'
import { renderMarkdownReport, renderSarif } from './report.mjs'
import { stableJson } from './run-engine.mjs'
import {
  DATABASE_TOPIC_IDS,
  expectedStorePathsForJob,
  normalizeStoreContribution,
  synthesizeStoreProfiles,
} from './store-synthesis.mjs'

const JOB_RESULT_SCHEMA_URL = new URL('../../schemas/job-result.schema.json', import.meta.url)
export const jobResultSchema = JSON.parse(
  readFileSync(fileURLToPath(JOB_RESULT_SCHEMA_URL), 'utf8'),
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
ajv.addSchema(jobResultSchema)
const validateJobResultSchema = ajv.getSchema(jobResultSchema.$id)

const TERMINAL_JOB_STATES = new Set(['SUCCEEDED', 'SKIPPED', 'FAILED'])
const ACTIVE_FINDING_DISPOSITIONS = new Set(['queued', 'elevated'])
const EXPECTED_PHASE = {
  LENS: 'FANOUT',
  TRIAGE: 'TRIAGE',
  PROOF: 'PROOF',
  PATCH: 'PATCH',
  REPORT: 'REPORT',
  COMPLETENESS: 'COMPLETENESS',
}
const TRIAGE_LENS_ORDER = new Map([
  ['business-logic', 0],
  ['attack-chaining', 100],
])
const PROOF_SEVERITY_ORDER = new Map([
  ['Critical', 0],
  ['High', 1],
  ['Medium', 2],
  ['Low', 3],
  ['Info', 4],
])

export function compareTriageJobs(left, right) {
  const leftRank = TRIAGE_LENS_ORDER.get(left.lens) ?? 50
  const rightRank = TRIAGE_LENS_ORDER.get(right.lens) ?? 50
  return leftRank - rightRank || compareCanonicalStrings(left.job_id, right.job_id)
}

function proofReachabilityRank(finding) {
  const reachability = finding?.reachable_from
  if (typeof reachability !== 'string') return 0
  if (/^\s*unknown/i.test(reachability)) return 2
  if (/^\s*contingent/i.test(reachability)) return 1
  return 0
}

function proofQueueSeverity(finding) {
  // The queue is ordered by claimed impact so the reachability cap cannot
  // deprioritise the findings a proof would resolve. effective_severity may
  // exceed the claim only for an attributed elevation, so the stronger of the
  // two is never a capped value.
  return betterProofSeverity(
    finding?.claimed_impact_severity,
    finding?.effective_severity,
  )
}

function compareFindingsForProof(left, right) {
  return (
    (PROOF_SEVERITY_ORDER.get(proofQueueSeverity(left)) ?? 99)
      - (PROOF_SEVERITY_ORDER.get(proofQueueSeverity(right)) ?? 99)
    || proofReachabilityRank(left) - proofReachabilityRank(right)
    || compareCanonicalStrings(left.candidate_id, right.candidate_id)
  )
}

function betterProofSeverity(current, candidate) {
  if (current === undefined) return candidate
  return (PROOF_SEVERITY_ORDER.get(candidate) ?? 99)
      < (PROOF_SEVERITY_ORDER.get(current) ?? 99)
    ? candidate
    : current
}

function proofPriorityIndex(run) {
  const byId = new Map()
  const severityByCandidate = new Map()
  for (const finding of run.findings ?? []) {
    byId.set(finding.candidate_id, finding)
    const ownSeverity = proofQueueSeverity(finding)
    severityByCandidate.set(
      finding.candidate_id,
      betterProofSeverity(
        severityByCandidate.get(finding.candidate_id),
        ownSeverity,
      ),
    )
    if (
      finding.triage_disposition !== 'elevated'
      || finding.raised_by !== 'attack-chaining'
      || !Array.isArray(finding.component_finding_ids)
    ) {
      continue
    }
    for (const componentId of finding.component_finding_ids) {
      severityByCandidate.set(
        componentId,
        betterProofSeverity(
          severityByCandidate.get(componentId),
          ownSeverity,
        ),
      )
    }
  }
  return { byId, severityByCandidate }
}

export function createProofJobComparator(run) {
  const { byId, severityByCandidate } = proofPriorityIndex(run)
  const prioritizedFinding = (job) => {
    const candidateId = job.candidate_ids?.[0] ?? job.job_id
    const finding = byId.get(candidateId) ?? { candidate_id: candidateId }
    return {
      ...finding,
      claimed_impact_severity: severityByCandidate.get(candidateId)
        ?? finding.claimed_impact_severity,
    }
  }
  return (left, right) => compareFindingsForProof(
    prioritizedFinding(left),
    prioritizedFinding(right),
  )
}

function proofOperation(job) {
  if (job.job_id.startsWith('proof-existence:')) return 'existence'
  if (job.job_id.startsWith('proof-verification:')) return 'verification'
  return undefined
}

function sameProofWave(left, right) {
  return (left.closure_round ?? null) === (right.closure_round ?? null)
}

function assertProofWaveReady(run, job) {
  const operation = proofOperation(job)
  if (!operation) {
    throw resultError(`proof job ${job.job_id} has an unsupported operation`)
  }

  const wave = run.jobs.filter((candidate) =>
    candidate.kind === 'PROOF' && sameProofWave(candidate, job))
  const existenceJobs = wave.filter(
    (candidate) => proofOperation(candidate) === 'existence',
  )
  const verificationJobs = wave.filter(
    (candidate) => proofOperation(candidate) === 'verification',
  )

  if (operation === 'existence') {
    if (verificationJobs.length > 0) {
      throw resultError(
        `existence job ${job.job_id} cannot start after its verification wave was scheduled`,
      )
    }
    return
  }

  const uncommitted = existenceJobs.filter(({ state }) => state !== 'SUCCEEDED')
  if (existenceJobs.length === 0 || uncommitted.length > 0) {
    const blockedBy = uncommitted.length > 0
      ? uncommitted.map(({ job_id: jobId }) => jobId).join(', ')
      : 'the missing existence wave'
    throw resultError(
      `verification job ${job.job_id} must wait for every existence result ` +
      `in its proof wave to commit; blocked by ${blockedBy}`,
    )
  }
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function clone(value) {
  return structuredClone(value)
}

function resultError(message, details = []) {
  const error = new Error(message)
  error.name = 'JobProtocolError'
  error.details = details
  return error
}

function normalizeAjvErrors(errors = []) {
  return errors.map((error) => ({
    instancePath: error.instancePath || '/',
    keyword: error.keyword,
    message: error.message,
    params: error.params,
  }))
}

export function validateJobResult(value) {
  const valid = validateJobResultSchema(value)
  return {
    valid,
    errors: valid ? [] : normalizeAjvErrors(validateJobResultSchema.errors),
  }
}

export function assertValidJobResult(value) {
  const validation = validateJobResult(value)
  if (!validation.valid) {
    throw resultError('job result schema validation failed', validation.errors)
  }
  const ids = value.findings.map(({ candidate_id }) => candidate_id)
  if (new Set(ids).size !== ids.length) {
    throw resultError('job result contains duplicate candidate_id values')
  }
  return value
}

function findJob(run, jobId) {
  const index = run.jobs.findIndex((job) => job.job_id === jobId)
  if (index < 0) throw resultError(`unknown job ${jobId}`)
  return { index, job: run.jobs[index] }
}

function replaceJob(run, index, value) {
  run.jobs[index] = { ...run.jobs[index], ...value }
}

function pendingDatabaseProfileAuthority(run, job) {
  const localAuthority = Array.isArray(job.profile_authority_store_ids)
    ? job.profile_authority_store_ids
    : []
  if (
    job.kind !== 'LENS'
    || job.lens !== 'database-and-data-stores'
    || localAuthority.length > 0
  ) {
    return undefined
  }
  const profiled = new Set(
    (run.store_profiles ?? []).map(
      (profile) => profile.store_context.store_id,
    ),
  )
  const missing = new Set(
    (Array.isArray(job.database_store_ids) ? job.database_store_ids : [])
      .filter((storeId) => !profiled.has(storeId)),
  )
  if (missing.size === 0) return undefined
  return run.jobs.find((candidate) =>
    candidate.kind === 'LENS'
    && candidate.lens === 'database-and-data-stores'
    && candidate.closure_round === undefined
    && ['PENDING', 'RUNNING'].includes(candidate.state)
    && (Array.isArray(candidate.profile_authority_store_ids)
      ? candidate.profile_authority_store_ids
      : [])
      .some((storeId) => missing.has(storeId)))
}

function prepareJobStartInPlace(next, jobId) {
  const { index, job } = findJob(next, jobId)
  if (job.state !== 'PENDING') {
    throw resultError(`job ${jobId} must be PENDING before it starts; received ${job.state}`)
  }
  const expectedPhase = job.closure_round
    ? 'COMPLETENESS'
    : EXPECTED_PHASE[job.kind]
  if (!expectedPhase) throw resultError(`job ${jobId} has unsupported kind ${job.kind}`)

  if (next.state === 'PLANNED' && next.phase === 'RECON' && job.kind === 'LENS') {
    next.state = 'RUNNING'
    next.phase = 'FANOUT'
  }
  if (next.state !== 'RUNNING' || next.phase !== expectedPhase) {
    throw resultError(
      `job ${jobId} belongs to ${expectedPhase}, but run is ${next.state}/${next.phase}`,
    )
  }
  const pendingAuthority = pendingDatabaseProfileAuthority(next, job)
  if (pendingAuthority) {
    throw resultError(
      `database context job ${jobId} must wait for profile authority job ${pendingAuthority.job_id}`,
    )
  }
  if (job.kind === 'TRIAGE') {
    const firstUnfinished = next.jobs
      .filter((candidate) =>
        candidate.kind === 'TRIAGE'
        && candidate.state !== 'DORMANT'
        && !TERMINAL_JOB_STATES.has(candidate.state)
        && (candidate.closure_round ?? 0) === (job.closure_round ?? 0))
      .sort(compareTriageJobs)[0]
    if (firstUnfinished?.job_id !== jobId) {
      throw resultError(
        `triage job ${jobId} is out of order; ${firstUnfinished?.job_id ?? 'none'} must finish first`,
      )
    }
  }
  if (job.kind === 'PROOF') {
    assertProofWaveReady(next, job)
  }
  replaceJob(next, index, { state: 'RUNNING' })
  return next
}

export function prepareJobStart(run, jobId) {
  return prepareJobStartInPlace(clone(run), jobId)
}

export function beginJob(run, jobId) {
  const next = prepareJobStart(run, jobId)
  assertValidRunTransition(run, next)
  return next
}

function ensureExaminedScope(run, job, sidecar, jobResult) {
  const inventory = new Set(run.coverage.inventory)
  const scoped = new Set(sidecar?.scoped_files ?? [])
  for (const path of jobResult.examined_files) {
    if (!inventory.has(path)) {
      throw resultError(`job ${job.job_id} examined path outside inventory: ${path}`)
    }
    if (job.kind === 'LENS' && !scoped.has(path)) {
      throw resultError(`job ${job.job_id} examined path outside its scoped files: ${path}`)
    }
  }
  if (job.kind === 'LENS' && sidecar === undefined) {
    throw resultError(`lens job ${job.job_id} requires its immutable job sidecar`)
  }
}

function findingLocationPath(location) {
  return String(location)
    .replace(/:[1-9][0-9]*(?::[1-9][0-9]*)?$/, '')
    .replaceAll('\\', '/')
}

function ensureFindingLocations(run, job, finding, options = {}) {
  const inventory = new Set(run.coverage.inventory)
  const scoped = new Set(options.sidecar?.scoped_files ?? [])
  const examined = new Set(options.examinedFiles ?? [])
  const previousLocations = new Set(options.previous?.location ?? [])

  for (const location of finding.location) {
    const path = findingLocationPath(location)
    if (!inventory.has(path)) {
      throw resultError(
        `finding ${finding.candidate_id} cites a path outside inventory: ${path}`,
      )
    }
    if (job.kind === 'LENS' && !scoped.has(path)) {
      throw resultError(
        `finding ${finding.candidate_id} cites a path outside ${job.job_id} scope: ${path}`,
      )
    }
    if (
      (job.kind === 'LENS' || !previousLocations.has(location))
      && !examined.has(path)
    ) {
      throw resultError(
        `finding ${finding.candidate_id} cites ${path} without reporting it examined`,
      )
    }
  }
}

function ensureTopicAuthority(job, finding, sidecar, options = {}) {
  if (!options.originating) {
    if (
      options.previous?.raised_by !== finding.raised_by
      && finding.raised_by !== job.lens
    ) {
      throw resultError(
        `job ${job.job_id} cannot claim authority for ${finding.raised_by}`,
      )
    }
    return
  }
  if (
    !sidecar
    || !Array.isArray(sidecar.owned_topics)
    || !Array.isArray(sidecar.known_topics)
  ) {
    throw resultError(
      `job ${job.job_id} requires immutable topic authority in its sidecar`,
    )
  }
  if (finding.lens !== job.lens) {
    throw resultError(
      `job ${job.job_id} cannot originate a record for lens ${finding.lens}`,
    )
  }

  const owned = new Set(sidecar.owned_topics)
  const known = new Set(sidecar.known_topics)
  if (owned.size > 0) {
    if (!owned.has(finding.topic)) {
      throw resultError(
        `job ${job.job_id} does not own topic ${finding.topic}`,
      )
    }
    if (finding.raised_by !== undefined) {
      throw resultError(
        `owning lens ${job.job_id} must not claim cross-lens raised_by authority`,
      )
    }
    return
  }

  if (finding.topic !== job.lens && !known.has(finding.topic)) {
    throw resultError(
      `zero-owner lens ${job.job_id} must use a registered topic or its own triage label`,
    )
  }
  if (finding.raised_by !== job.lens) {
    throw resultError(
      `zero-owner lens ${job.job_id} must set raised_by to ${job.lens}`,
    )
  }
}

function isDatabaseFinding(finding) {
  return finding?.lens === 'database-and-data-stores'
    || /^(?:database(?:-|$)|db\.)/.test(finding?.topic ?? '')
}

function unresolvedPrincipal(profile) {
  return [
    profile.principal_path?.authenticated_principal,
    profile.principal_path?.session_principal,
    profile.principal_path?.effective_principal,
    profile.principal_path?.owner_or_definer,
    ...(profile.principal_path?.bypass_capabilities ?? []),
  ].some((value) =>
    isUnresolvedDatabaseDescriptor(value))
}

function applyStoreContributions(run, job, jobResult, options = {}) {
  const contributions = jobResult.store_contributions ?? []
  if (!['4.0.0', '5.0.0', '6.0.0', '7.0.0'].includes(run.schema_version)) {
    if (contributions.length > 0) {
      throw resultError(
        'store_contributions require a run schema 4/5 database job',
      )
    }
    return
  }
  if ((jobResult.store_profiles ?? []).length > 0) {
    throw resultError(
      'run schema 4/5 providers return store_contributions, not store_profiles',
    )
  }
  const isBaseDatabaseJob = (
    job.kind === 'LENS'
    && job.lens === 'database-and-data-stores'
    && job.closure_round === undefined
  )
  if (!isBaseDatabaseJob) {
    if (contributions.length > 0) {
      throw resultError(
        'only a base database-and-data-stores job may return store_contributions',
      )
    }
    return
  }
  if (jobResult.state !== 'SUCCEEDED') return

  const expectedStoreIds = job.database_store_ids ?? []
  const contributionStoreIds = contributions.map(
    ({ store_id: storeId }) => storeId,
  )
  if (
    contributionStoreIds.length !== expectedStoreIds.length
    || new Set(contributionStoreIds).size !== contributionStoreIds.length
    || expectedStoreIds.some((storeId) => !contributionStoreIds.includes(storeId))
  ) {
    throw resultError(
      `successful database job ${job.job_id} must contribute exactly once for every assigned store`,
    )
  }

  const examined = new Set(jobResult.examined_files)
  const scoped = new Set(options.sidecar?.scoped_files ?? [])
  const ownedTopics = new Set(options.sidecar?.owned_topics ?? [])
  const authority = new Set(job.profile_authority_store_ids ?? [])
  const discovered = new Set(
    (run.database_discovery?.store_candidates ?? [])
      .map(({ store_id: storeId }) => storeId),
  )
  const existing = new Set((run.store_contributions ?? []).map((envelope) =>
    `${envelope.job_id}\0${envelope.contribution.store_id}`))
  run.store_contributions ??= []

  for (const contribution of contributions) {
    const storeId = contribution.store_id
    if (!discovered.has(storeId)) {
      throw resultError(
        `store contribution ${storeId} is absent from controller discovery`,
      )
    }
    const role = authority.has(storeId) ? 'AUTHORITY' : 'CONTEXT'
    if (role === 'AUTHORITY' && contribution.profile === undefined) {
      throw resultError(
        `authority contribution ${storeId} must supply its local store profile`,
      )
    }
    if (role === 'CONTEXT' && contribution.profile !== undefined) {
      throw resultError(
        `context contribution ${storeId} cannot supply or rewrite a store profile`,
      )
    }
    if (
      contribution.profile
      && contribution.profile.store_context.store_id !== storeId
    ) {
      throw resultError(
        `authority contribution ${storeId} profile store ID does not match`,
      )
    }

    const normalized = normalizeStoreContribution(contribution)
    const expectedPaths = expectedStorePathsForJob(run, job, storeId)
    const expectedPathSet = new Set(expectedPaths)
    for (const path of normalized.evidence_paths) {
      if (
        !expectedPathSet.has(path)
        || !examined.has(path)
        || !scoped.has(path)
      ) {
        throw resultError(
          `store contribution ${storeId} cites unexamined or out-of-scope evidence ${path}`,
        )
      }
    }
    for (const topic of normalized.assessed_topics) {
      if (!ownedTopics.has(topic)) {
        throw resultError(
          `store contribution ${storeId} claims unowned database topic ${topic}`,
        )
      }
    }
    if (
      normalized.coverage_state === 'ASSESSED'
      && (
        normalized.coverage_gaps.length > 0
        || DATABASE_TOPIC_IDS.some(
          (topic) => !normalized.assessed_topics.includes(topic),
        )
        || expectedPaths.some(
          (path) => !normalized.evidence_paths.includes(path),
        )
      )
    ) {
      throw resultError(
        `ASSESSED store contribution ${storeId} must close every assigned path and database topic without gaps`,
      )
    }

    const identity = `${job.job_id}\0${storeId}`
    if (existing.has(identity)) {
      throw resultError(
        `duplicate or replayed store contribution ${job.job_id}/${storeId}`,
      )
    }
    existing.add(identity)
    run.store_contributions.push({
      job_id: job.job_id,
      input_sha256: jobResult.input_sha256,
      role,
      contribution,
    })
  }
}

function applyStoreProfiles(run, job, jobResult, options = {}) {
  const profiles = jobResult.store_profiles ?? []
  if (['4.0.0', '5.0.0', '6.0.0', '7.0.0'].includes(run.schema_version)) {
    if (profiles.length > 0) {
      throw resultError(
        'run schema 4/5 providers cannot append store_profiles directly',
      )
    }
    return
  }
  if (profiles.length > 0 && (
    job.kind !== 'LENS'
    || job.lens !== 'database-and-data-stores'
  )) {
    throw resultError('only the database-and-data-stores fan-out job may return store_profiles')
  }
  if (
    job.kind === 'LENS'
    && job.lens === 'database-and-data-stores'
    && jobResult.state === 'SUCCEEDED'
    && (options.sidecar?.scoped_files?.length ?? 0) > 0
    && profiles.length === 0
    && !isModeledCoverage(run.coverage)
  ) {
    throw resultError(
      'an activated database-and-data-stores job must inventory every detected store',
    )
  }
  if (profiles.length === 0) return

  const existing = new Set((run.store_profiles ?? []).map(
    (profile) => profile.store_context.store_id,
  ))
  const discoveredStores = new Map(
    (run.database_discovery?.store_candidates ?? []).map((candidate) => [
      candidate.store_id,
      candidate,
    ]),
  )
  const inventory = new Set(run.coverage.inventory)
  const examined = new Set(jobResult.examined_files)
  const scoped = new Set(options.sidecar?.scoped_files ?? [])
  const ownedTopics = new Set(options.sidecar?.owned_topics ?? [])
  const projectedAuthority = Array.isArray(
    options.sidecar?.profile_authority_store_ids,
  )
    ? options.sidecar.profile_authority_store_ids
    : (options.sidecar?.database_discovery?.store_candidates ?? [])
        .map(({ store_id: storeId }) => storeId)
  const jobAuthority = Array.isArray(job.profile_authority_store_ids)
    ? job.profile_authority_store_ids
    : projectedAuthority
  if (
    isModeledCoverage(run.coverage)
    && (
      projectedAuthority.length !== jobAuthority.length
      || projectedAuthority.some(
        (storeId, index) => storeId !== jobAuthority[index],
      )
    )
  ) {
    throw resultError(
      `database sidecar authority does not match immutable job ${job.job_id}`,
    )
  }
  const profileAuthority = new Set(projectedAuthority)
  for (const profile of profiles) {
    const storeId = profile.store_context.store_id
    const discovered = discoveredStores.get(storeId)
    if (isModeledCoverage(run.coverage) && !discovered) {
      throw resultError(
        `store profile ${storeId} is absent from the controller-owned database discovery graph`,
      )
    }
    if (
      isModeledCoverage(run.coverage)
      && !profileAuthority.has(storeId)
    ) {
      throw resultError(
        `store profile ${storeId} is not assigned to this database shard`,
      )
    }
    if (
      discovered
      && profile.coverage_state === 'ASSESSED'
      && (discovered.scope_paths ?? discovered.evidence_paths ?? [])
        .some((path) => !scoped.has(path))
    ) {
      throw resultError(
        `store profile ${storeId} cannot be ASSESSED from a shard that does not contain its complete discovered scope`,
      )
    }
    if (existing.has(storeId)) {
      throw resultError(`duplicate or rewritten store profile ${storeId}`)
    }
    existing.add(storeId)
    for (const path of profile.evidence_paths) {
      if (!inventory.has(path) || !examined.has(path) || !scoped.has(path)) {
        throw resultError(
          `store profile ${storeId} cites unexamined or out-of-scope evidence ${path}`,
        )
      }
      if (
        discovered
        && !(discovered.scope_paths ?? discovered.evidence_paths ?? []).includes(path)
      ) {
        throw resultError(
          `store profile ${storeId} cites ${path} outside its discovered store component`,
        )
      }
    }
    for (const topic of profile.assessed_topics) {
      if (!ownedTopics.has(topic)) {
        throw resultError(
          `store profile ${storeId} claims unowned database topic ${topic}`,
        )
      }
    }
    const route = routeDatabaseAdapter(profile.store_context)
    if (profile.store_context.adapter_id !== route.adapter_id) {
      throw resultError(
        `store profile ${storeId} must use routed adapter ${route.adapter_id}`,
      )
    }
    if (
      route.selection_status !== 'SELECTED'
      && profile.coverage_state !== 'NOT_ASSESSED'
    ) {
      throw resultError(
        `store profile ${storeId} cannot claim coverage without a selected adapter`,
      )
    }
    if (unresolvedPrincipal(profile) && profile.coverage_state === 'ASSESSED') {
      throw resultError(
        `store profile ${storeId} has unresolved principal semantics and cannot be ASSESSED`,
      )
    }
    for (const gap of profile.coverage_gaps) {
      run.coverage.gaps.push({
        area: `store:${storeId}:${gap.area}`,
        reason: gap.reason,
      })
    }
  }
  run.store_profiles ??= []
  run.store_profiles.push(...profiles)
  const profiledStoreAreas = new Set(
    profiles.map((profile) => `store:${profile.store_context.store_id}`),
  )
  const resolved = new Set(run.coverage.resolved_gap_ids ?? [])
  for (const gap of run.coverage.gaps ?? []) {
    if (profiledStoreAreas.has(gap.area)) {
      resolved.add(exactCoverageGapId(gap))
    }
  }
  run.coverage.resolved_gap_ids = [...resolved]
    .sort((left, right) => compareCanonicalStrings(left, right))
}

function ensureDatabaseProfileBinding(run, finding) {
  if (!isDatabaseFinding(finding)) return
  const storeId = finding.store_context?.store_id
  const profile = (run.store_profiles ?? []).find(
    (entry) => entry.store_context.store_id === finding.store_context?.store_id,
  ) ?? (run.store_contributions ?? [])
    .find((envelope) =>
      envelope.role === 'AUTHORITY'
      && envelope.contribution?.store_id === storeId)
    ?.contribution?.profile
  if (!profile) {
    throw resultError(
      `database finding ${finding.candidate_id} references an unprofiled store`,
    )
  }
  if (
    stableJson(profile.store_context, 0) !== stableJson(finding.store_context, 0)
    || stableJson(profile.principal_path, 0) !== stableJson(finding.principal_path, 0)
  ) {
    throw resultError(
      `database finding ${finding.candidate_id} conflicts with immutable store profile ` +
      `${profile.store_context.store_id}`,
    )
  }
  if (
    profile.coverage_state === 'NOT_ASSESSED'
    && finding.verification_status
    && finding.verification_status !== 'UNPROVEN'
  ) {
    throw resultError(
      `unassessed store ${profile.store_context.store_id} cannot confirm or clear a finding`,
    )
  }
}

function applyFindings(run, job, findings, options = {}) {
  const byId = new Map(run.findings.map((finding, index) => [finding.candidate_id, index]))
  const candidateIds = []

  for (const finding of findings) {
    candidateIds.push(finding.candidate_id)
    ensureDatabaseProfileBinding(run, finding)
    const existingIndex = byId.get(finding.candidate_id)
    if (job.kind === 'LENS') {
      assertValidFinding(finding, { stage: 1 })
      ensureFindingLocations(run, job, finding, options)
      ensureTopicAuthority(job, finding, options.sidecar, { originating: true })
      if (existingIndex !== undefined) {
        const isClosureRetry = (
          ['3.0.0', '4.0.0', '5.0.0', '6.0.0', '7.0.0'].includes(run.schema_version)
          && Number.isInteger(job.closure_round)
          && job.closure_round > 0
        )
        if (
          !isClosureRetry
          || !isExactStageOneReplay(run.findings[existingIndex], finding)
        ) {
          throw resultError(
            isClosureRetry
              ? `closure retry must exactly replay the immutable Stage-1 claim: ${finding.candidate_id}`
              : `candidate_id collision during fan-out: ${finding.candidate_id}`,
          )
        }
        // The validated result still records this candidate_id on the completing
        // job, but the accumulated triage/proof record remains byte-for-byte intact.
        continue
      }
      byId.set(finding.candidate_id, run.findings.length)
      run.findings.push(finding)
      continue
    }

    if (job.kind === 'TRIAGE') {
      if (existingIndex === undefined) {
        if (job.lens === 'attack-chaining') {
          throw resultError('attack-chaining may elevate existing records but cannot originate one')
        }
        assertValidFinding(finding, { stage: 2 })
        ensureFindingLocations(run, job, finding, options)
        ensureTopicAuthority(job, finding, options.sidecar, { originating: true })
        byId.set(finding.candidate_id, run.findings.length)
        run.findings.push(finding)
      } else {
        assertValidFinding(finding, { stage: 2 })
        ensureFindingLocations(run, job, finding, {
          ...options,
          previous: run.findings[existingIndex],
        })
        ensureTopicAuthority(job, finding, options.sidecar, {
          previous: run.findings[existingIndex],
          originating: false,
        })
        if (
          finding.raised_by === 'attack-chaining'
          && job.lens !== 'attack-chaining'
        ) {
          throw resultError(
            `triage job ${job.job_id} cannot claim attack-chaining authority`,
          )
        }
        assertValidFindingTransition(run.findings[existingIndex], finding)
        run.findings[existingIndex] = finding
      }
      continue
    }

    if (job.kind === 'PROOF') {
      if (existingIndex === undefined) {
        throw resultError(`proof job ${job.job_id} references unknown candidate ${finding.candidate_id}`)
      }
      const previous = run.findings[existingIndex]
      if (job.job_id.startsWith('proof-existence:')) {
        if (previous.existence_check !== undefined) {
          throw resultError(
            `existence job ${job.job_id} cannot overwrite an existing existence check`,
          )
        }
        if (finding.existence_check === undefined) {
          throw resultError(
            `existence job ${job.job_id} must add existence_check`,
          )
        }
      } else if (job.job_id.startsWith('proof-verification:')) {
        if (previous.existence_check === undefined) {
          throw resultError(
            `verification job ${job.job_id} requires a prior existence check`,
          )
        }
        if (
          finding.proof_tier === undefined
          || finding.verification_status === undefined
        ) {
          throw resultError(
            `verification job ${job.job_id} must add proof_tier and verification_status`,
          )
        }
        if (
          previous.proof_tier !== undefined
          || previous.verification_status !== undefined
        ) {
          throw resultError(
            `verification job ${job.job_id} cannot overwrite an existing proof decision`,
          )
        }
      } else {
        throw resultError(`unsupported proof operation ${job.job_id}`)
      }
      assertValidFinding(finding, { stage: 3 })
      assertValidFindingTransition(previous, finding)
      run.findings[existingIndex] = finding
      continue
    }

    if (job.kind === 'COMPLETENESS' && findings.length > 0) {
      throw resultError(
        'completeness jobs emit coverage_gaps; new vulnerability records require a new scoped fan-out round',
      )
    }

    if (!['LENS', 'TRIAGE', 'PROOF'].includes(job.kind) && findings.length > 0) {
      throw resultError(`${job.kind} jobs cannot return findings`)
    }
  }

  if (job.kind === 'PROOF') {
    const expected = [...(job.candidate_ids ?? [])].sort()
    const observed = [...candidateIds].sort()
    if (JSON.stringify(expected) !== JSON.stringify(observed)) {
      throw resultError(
        `proof job ${job.job_id} must return exactly its candidate_ids`,
      )
    }
  }
  return candidateIds
}

function updateCoverage(run, job, sidecar, jobResult) {
  const modeled = isModeledCoverage(run.coverage)
  const gapKey = (gap) => {
    try {
      return exactCoverageGapId(gap)
    } catch (error) {
      throw resultError(`coverage gap identity is invalid: ${error.message}`)
    }
  }
  const gapKeys = new Set(run.coverage.gaps.map((gap) => gapKey(gap)))
  const appendGap = (gap) => {
    const key = gapKey(gap)
    if (gapKeys.has(key)) return
    gapKeys.add(key)
    run.coverage.gaps.push(gap)
  }
  for (const gap of jobResult.coverage_gaps) appendGap(gap)

  if (job.kind === 'LENS') {
    const examined = new Set(run.coverage.examined)
    if (jobResult.state === 'SUCCEEDED') {
      for (const path of jobResult.examined_files) examined.add(path)
      run.coverage.examined = [...examined]
        .sort((left, right) => compareCanonicalStrings(left, right))
      run.coverage.unexamined = run.coverage.unexamined.filter(
        ({ path }) => !examined.has(path),
      )
    }
    const observed = new Set(jobResult.examined_files)
    for (const path of sidecar.scoped_files) {
      if (!observed.has(path)) {
        appendGap(modeled
          ? createLensFileCoverageGap({
              lens: job.lens,
              path,
              reason: 'activated lens did not report the scoped file as examined',
            })
          : {
              area: `${job.job_id}:${path}`,
              reason: 'activated lens did not report the scoped file as examined',
            })
      }
    }
    if (modeled) {
      const resolved = new Set(run.coverage.resolved_gap_ids ?? [])
      for (const path of observed) {
        const gap = createLensFileCoverageGap({
          lens: job.lens,
          path,
          reason: 'activated lens did not report the scoped file as examined',
        })
        if (gapKeys.has(gap.gap_id)) resolved.add(gap.gap_id)
      }
      run.coverage.resolved_gap_ids = [...resolved]
        .sort((left, right) => compareCanonicalStrings(left, right))
      refreshCategoryDenominators(run.coverage)
    }
  }

  if (job.lens) {
    const row = run.coverage.lenses.find((entry) => entry.lens === job.lens)
    if (!row) throw resultError(`coverage has no row for job lens ${job.lens}`)
    if (job.kind === 'LENS') {
      const examinedPaths = new Set(row.examined_paths ?? [])
      if (jobResult.state === 'SUCCEEDED') {
        for (const path of jobResult.examined_files) examinedPaths.add(path)
      }
      row.examined_paths = [...examinedPaths]
        .sort((left, right) => compareCanonicalStrings(left, right))
      if (!modeled) {
        row.status = jobResult.state === 'SUCCEEDED' ? 'RAN' : 'FAILED'
        if (jobResult.state === 'FAILED') row.reason = jobResult.error.message
        else delete row.reason
      } else {
        const examinedForLens = new Set(row.examined_paths)
        const missing = (row.applicable_paths ?? [])
          .filter((path) => !examinedForLens.has(path))
        if (missing.length === 0) {
          row.status = 'RAN'
          delete row.reason
        } else if (jobResult.state === 'FAILED') {
          row.status = 'FAILED'
          row.reason = jobResult.error.message
        }
      }
    } else {
      row.status = jobResult.state === 'SUCCEEDED' ? 'RAN' : 'FAILED'
      if (jobResult.state === 'FAILED') row.reason = jobResult.error.message
      else delete row.reason
    }
  }
}

export function applyJobResult(run, jobResult, options = {}) {
  assertValidJobResult(jobResult)
  if (
    typeof options.expectedPacketSha256 !== 'string'
    || !/^[a-fA-F0-9]{64}$/.test(options.expectedPacketSha256)
  ) {
    throw resultError(
      'accepting a job result requires the controller-derived expectedPacketSha256',
    )
  }
  if (
    jobResult.input_sha256.toLowerCase()
    !== options.expectedPacketSha256.toLowerCase()
  ) {
    throw resultError(
      `job result ${jobResult.job_id} is not bound to the expected dispatch packet`,
    )
  }
  if (run.run_id !== jobResult.run_id) {
    throw resultError(
      `job result run_id ${jobResult.run_id} does not match ${run.run_id}`,
    )
  }
  const next = clone(run)
  const { index, job } = findJob(next, jobResult.job_id)
  if (job.state !== 'RUNNING') {
    throw resultError(`job ${job.job_id} must be RUNNING before accepting a result`)
  }

  ensureExaminedScope(next, job, options.sidecar, jobResult)
  applyStoreContributions(next, job, jobResult, {
    sidecar: options.sidecar,
  })
  applyStoreProfiles(next, job, jobResult, {
    sidecar: options.sidecar,
  })
  const candidateIds = jobResult.state === 'SUCCEEDED'
    ? applyFindings(next, job, jobResult.findings, {
        sidecar: options.sidecar,
        examinedFiles: jobResult.examined_files,
      })
    : []
  updateCoverage(next, job, options.sidecar, jobResult)

  replaceJob(next, index, {
    state: jobResult.state,
    input_sha256: jobResult.input_sha256,
    producer: jobResult.producer,
    ...(typeof options.commitObservedAttempt === 'function'
      ? {}
      : { coverage_authority: 'PROVIDER_DECLARED' }),
    ...(candidateIds.length > 0 ? { candidate_ids: candidateIds } : {}),
    ...(jobResult.state === 'FAILED' ? { reason: jobResult.error.message } : {}),
  })
  if (jobResult.state === 'FAILED') {
    next.errors.push({
      error_id: `${job.job_id}:error:${next.errors.length + 1}`,
      phase: next.phase,
      code: jobResult.error.code,
      message: jobResult.error.message,
      recoverable: jobResult.error.recoverable,
      job_id: job.job_id,
    })
  }

  if (options.artifact) {
    const key = `result_${artifactKeyToken(job.job_id).toLowerCase()}`
    if (next.artifacts[key]) throw resultError(`result artifact ${key} already exists`)
    next.artifacts[key] = options.artifact
  }

  if (options.commitObservedAttempt !== undefined) {
    if (options.deferTransitionValidation === true) {
      throw resultError(
        'observed provider attempts cannot defer transition validation',
      )
    }
    if (typeof options.commitObservedAttempt !== 'function') {
      throw resultError('commitObservedAttempt must be a controller callback')
    }
    const committed = options.commitObservedAttempt(run, next)
    assertValidRunTransition(run, committed)
    return committed
  }
  if (options.deferTransitionValidation !== true) {
    assertValidRunTransition(run, next)
  }
  return next
}

function jobsOf(run, kind) {
  return run.jobs.filter((job) => job.kind === kind)
}

function jobsTerminal(run, kind) {
  return jobsOf(run, kind).every((job) => TERMINAL_JOB_STATES.has(job.state))
}

function proofExistenceJobs(run, findings) {
  return findings
    .filter((finding) => ACTIVE_FINDING_DISPOSITIONS.has(finding.triage_disposition))
    .map((finding) => ({
      job_id: `proof-existence:${finding.candidate_id}`,
      kind: 'PROOF',
      state: 'PENDING',
      candidate_ids: [finding.candidate_id],
    }))
    .sort(createProofJobComparator(run))
}

function proofVerificationJobs(run, findings) {
  return findings
    .filter((finding) => ACTIVE_FINDING_DISPOSITIONS.has(finding.triage_disposition))
    .map((finding) => ({
      job_id: `proof-verification:${finding.candidate_id}`,
      kind: 'PROOF',
      state: 'PENDING',
      candidate_ids: [finding.candidate_id],
    }))
    .sort(createProofJobComparator(run))
}

function uniqueErrorId(run, base) {
  const used = new Set(run.errors.map(({ error_id: errorId }) => errorId))
  if (!used.has(base)) return base
  let suffix = 2
  while (used.has(`${base}:${suffix}`)) suffix += 1
  return `${base}:${suffix}`
}

function failRequiredPhase(run, failedJobs) {
  const failedIds = failedJobs.map(({ job_id: jobId }) => jobId)
  const reason = `required ${run.phase.toLowerCase()} work failed: ${failedIds.join(', ')}`

  run.jobs = run.jobs.map((job) => {
    if (['DORMANT', 'PENDING'].includes(job.state)) {
      return { ...job, state: 'SKIPPED', reason }
    }
    if (job.state === 'RUNNING') {
      return { ...job, state: 'FAILED', reason }
    }
    return job
  })

  for (const job of failedJobs) {
    run.errors.push({
      error_id: uniqueErrorId(run, `terminal:${job.job_id}`),
      phase: run.phase,
      code: `REQUIRED_${run.phase}_JOB_FAILED`,
      message: `required ${run.phase.toLowerCase()} job ${job.job_id} failed; the run stopped without fabricating downstream finding state`,
      recoverable: false,
      job_id: job.job_id,
    })
  }

  run.state = 'FAILED'
  run.phase = 'FINALIZED'
  run.completed_at = new Date().toISOString()
}

function jobsMatching(run, predicate) {
  return run.jobs.filter(predicate)
}

function matchingJobsTerminal(run, predicate) {
  return jobsMatching(run, predicate)
    .every((job) => TERMINAL_JOB_STATES.has(job.state))
}

function basePhaseJobs(run, kind) {
  return jobsMatching(run, (job) =>
    job.kind === kind && job.closure_round === undefined)
}

function closureRoundJobs(run, kind, round) {
  return jobsMatching(run, (job) =>
    job.kind === kind && job.closure_round === round)
}

function replaceJobsById(run, jobIds, values) {
  const selected = new Set(jobIds)
  run.jobs = run.jobs.map((job) =>
    selected.has(job.job_id) ? { ...job, ...values } : job)
}

function skipDormantClosureTemplates(run, reason) {
  run.jobs = run.jobs.map((job) =>
    job.state === 'DORMANT'
      ? { ...job, state: 'SKIPPED', reason }
      : job)
}

function recordClosureMeasurement(coverage, measurement, status) {
  const record = { ...measurement, status }
  coverage.closure = {
    ...coverage.closure,
    round: measurement.round,
    status,
    applicable_lens_file_pairs: measurement.applicable_lens_file_pairs,
    examined_lens_file_pairs: measurement.examined_lens_file_pairs,
    uncovered_lens_file_pairs: measurement.uncovered_lens_file_pairs,
    uncovered_shards: measurement.uncovered_shards,
    measurement_sha256: measurement.measurement_sha256,
    history: [...(coverage.closure.history ?? []), record],
  }
}

function finishClosureMeasurement(run, measurementJob) {
  const round = measurementJob.closure_round ?? 0
  const measurement = measureCoverageClosure(run.coverage, round)
  if (measurementJob.state === 'FAILED') {
    recordClosureMeasurement(run.coverage, measurement, 'UNMEASURED')
    skipDormantClosureTemplates(
      run,
      `closure measurement round ${round} failed`,
    )
    return
  }

  if (measurement.uncovered_lens_file_pairs === 0) {
    recordClosureMeasurement(run.coverage, measurement, 'CONVERGED')
    run.coverage.lenses = finalizedFanoutLensRows(run)
    skipDormantClosureTemplates(run, `coverage converged at round ${round}`)
    return
  }

  const maxRounds = run.coverage.closure.max_rounds
  if (round >= maxRounds) {
    recordClosureMeasurement(run.coverage, measurement, 'BUDGET_EXHAUSTED')
    run.coverage.lenses = finalizedFanoutLensRows(run)
    skipDormantClosureTemplates(
      run,
      `coverage closure exhausted its ${maxRounds}-round retry budget`,
    )
    return
  }

  const nextRound = round + 1
  const uncoveredParents = new Set(
    measurement.uncovered_shards.map(({ job_id: jobId }) => jobId),
  )
  const retries = closureRoundJobs(run, 'LENS', nextRound)
    .filter((job) =>
      job.state === 'DORMANT' && uncoveredParents.has(job.parent_job_id))
  if (retries.length === 0) {
    recordClosureMeasurement(run.coverage, measurement, 'BUDGET_EXHAUSTED')
    run.coverage.lenses = finalizedFanoutLensRows(run)
    skipDormantClosureTemplates(
      run,
      'uncovered obligations had no sealed retry template',
    )
    return
  }

  recordClosureMeasurement(run.coverage, measurement, 'REQUEUED')
  run.coverage.closure.round = nextRound
  replaceJobsById(
    run,
    retries.map(({ job_id: jobId }) => jobId),
    { state: 'PENDING' },
  )
}

function activeProofCandidatesWithout(run, prefix) {
  const scheduled = new Set(
    run.jobs
      .filter(({ kind, job_id: jobId }) =>
        kind === 'PROOF' && jobId.startsWith(prefix))
      .flatMap(({ candidate_ids: candidateIds = [] }) => candidateIds),
  )
  return run.findings.filter((finding) =>
    ACTIVE_FINDING_DISPOSITIONS.has(finding.triage_disposition)
    && !scheduled.has(finding.candidate_id))
}

function advanceClosureRound(run) {
  const closure = run.coverage.closure
  if (!closure || ['CONVERGED', 'BUDGET_EXHAUSTED', 'UNMEASURED'].includes(
    closure.status,
  )) {
    return false
  }

  if (closure.status === 'PENDING' || closure.status === 'MEASURING') {
    const round = closure.round
    const measurementJob = round === 0
      ? basePhaseJobs(run, 'COMPLETENESS')[0]
      : closureRoundJobs(run, 'COMPLETENESS', round)[0]
    if (!measurementJob) {
      throw resultError(`closure round ${round} has no sealed completeness job`)
    }
    if (!TERMINAL_JOB_STATES.has(measurementJob.state)) return false
    finishClosureMeasurement(run, measurementJob)
    return true
  }

  if (closure.status !== 'REQUEUED') {
    throw resultError(`unsupported closure status ${closure.status}`)
  }

  const round = closure.round
  const lensJobs = closureRoundJobs(run, 'LENS', round)
    .filter(({ state }) => state !== 'DORMANT')
  if (lensJobs.some(({ state }) => !TERMINAL_JOB_STATES.has(state))) return false

  const triageJobs = closureRoundJobs(run, 'TRIAGE', round)
  if (triageJobs.every(({ state }) => state === 'DORMANT')) {
    replaceJobsById(
      run,
      triageJobs.map(({ job_id: jobId }) => jobId),
      { state: 'PENDING' },
    )
    return true
  }
  if (triageJobs.some(({ state }) => !TERMINAL_JOB_STATES.has(state))) return false
  const failedTriage = triageJobs.filter(({ state }) => state === 'FAILED')
  if (failedTriage.length > 0) {
    failRequiredPhase(run, failedTriage)
    return true
  }

  const untriaged = run.findings
    .filter((finding) => inferFindingStage(finding) < 2)
    .map(({ candidate_id: candidateId }) => candidateId)
  if (untriaged.length > 0) {
    throw resultError(
      `closure triage completed without dispositions for: ${untriaged.join(', ')}`,
    )
  }

  const missingExistence = activeProofCandidatesWithout(
    run,
    'proof-existence:',
  )
  if (missingExistence.length > 0) {
    run.jobs.push(...proofExistenceJobs(run, missingExistence).map((job) => ({
      ...job,
      closure_round: round,
    })))
    return true
  }
  const existenceJobs = jobsMatching(run, (job) =>
    job.kind === 'PROOF' && job.job_id.startsWith('proof-existence:'))
  if (existenceJobs.some(({ state }) => !TERMINAL_JOB_STATES.has(state))) return false
  const failedExistence = existenceJobs.filter(({ state }) => state === 'FAILED')
  if (failedExistence.length > 0) {
    failRequiredPhase(run, failedExistence)
    return true
  }

  const missingVerification = activeProofCandidatesWithout(
    run,
    'proof-verification:',
  )
  if (missingVerification.length > 0) {
    run.jobs.push(...proofVerificationJobs(run, missingVerification).map((job) => ({
      ...job,
      closure_round: round,
    })))
    return true
  }
  const verificationJobs = jobsMatching(run, (job) =>
    job.kind === 'PROOF' && job.job_id.startsWith('proof-verification:'))
  if (verificationJobs.some(({ state }) => !TERMINAL_JOB_STATES.has(state))) {
    return false
  }
  const failedVerification = verificationJobs.filter(
    ({ state }) => state === 'FAILED',
  )
  if (failedVerification.length > 0) {
    failRequiredPhase(run, failedVerification)
    return true
  }

  const [measurementJob] = closureRoundJobs(run, 'COMPLETENESS', round)
  if (!measurementJob) {
    throw resultError(`closure round ${round} has no completeness template`)
  }
  if (measurementJob.state === 'DORMANT') {
    replaceJobsById(run, [measurementJob.job_id], { state: 'PENDING' })
    run.coverage.closure.status = 'MEASURING'
    return true
  }
  if (!TERMINAL_JOB_STATES.has(measurementJob.state)) return false
  finishClosureMeasurement(run, measurementJob)
  return true
}

function materializeStoreSynthesis(run) {
  if (!['4.0.0', '5.0.0', '6.0.0', '7.0.0'].includes(run.schema_version)) return
  if ((run.store_profiles ?? []).length > 0) {
    throw resultError(
      'schema 4/5 store synthesis cannot rewrite an existing profile',
    )
  }
  const synthesized = synthesizeStoreProfiles(run)
  run.store_profiles = synthesized.map(({ profile }) => profile)
  const resolved = new Set(run.coverage.resolved_gap_ids ?? [])
  for (const { store_id: storeId, profile } of synthesized) {
    for (const gap of profile.coverage_gaps) {
      run.coverage.gaps.push({
        area: `store:${storeId}:${gap.area}`,
        reason: gap.reason,
      })
    }
    for (const gap of run.coverage.gaps ?? []) {
      if (gap.area === `store:${storeId}`) {
        resolved.add(exactCoverageGapId(gap))
      }
    }
  }
  run.coverage.resolved_gap_ids = [...resolved]
    .sort((left, right) => compareCanonicalStrings(left, right))
}

export function advanceRun(run) {
  const next = clone(run)
  if (next.state !== 'RUNNING') {
    if (next.state === 'FAILED') return { advanced: false, run }
    throw resultError(`only a RUNNING run can advance; received ${next.state}`)
  }

  const requiredKind = {
    TRIAGE: 'TRIAGE',
    PROOF: 'PROOF',
  }[next.phase]
  const failedRequiredJobs = requiredKind
    ? jobsOf(next, requiredKind).filter(({ state }) => state === 'FAILED')
    : []
  if (failedRequiredJobs.length > 0) {
    failRequiredPhase(next, failedRequiredJobs)
    assertValidRunTransition(run, next)
    return { advanced: true, run: next }
  }

  if (next.phase === 'FANOUT') {
    if (!basePhaseJobs(next, 'LENS')
      .every(({ state }) => TERMINAL_JOB_STATES.has(state))) {
      return { advanced: false, run }
    }
    materializeStoreSynthesis(next)
    next.coverage.lenses = finalizedFanoutLensRows(next)
    next.phase = 'TRIAGE'
  } else if (next.phase === 'TRIAGE') {
    if (!basePhaseJobs(next, 'TRIAGE')
      .every(({ state }) => TERMINAL_JOB_STATES.has(state))) {
      return { advanced: false, run }
    }
    const untriaged = next.findings
      .filter((finding) => inferFindingStage(finding) < 2)
      .map(({ candidate_id }) => candidate_id)
    if (untriaged.length > 0) {
      throw resultError(
        `triage completed without dispositions for: ${untriaged.join(', ')}`,
      )
    }
    next.jobs.push(...proofExistenceJobs(next, next.findings))
    next.phase = 'PROOF'
  } else if (next.phase === 'PROOF') {
    const existenceJobs = jobsOf(next, 'PROOF').filter(
      ({ job_id }) => job_id.startsWith('proof-existence:'),
    )
    const verificationJobs = jobsOf(next, 'PROOF').filter(
      ({ job_id }) => job_id.startsWith('proof-verification:'),
    )
    if (!existenceJobs.every(({ state }) => TERMINAL_JOB_STATES.has(state))) {
      return { advanced: false, run }
    }
    if (verificationJobs.length === 0 && existenceJobs.length > 0) {
      next.jobs.push(...proofVerificationJobs(next, next.findings))
    } else {
      if (!verificationJobs.every(({ state }) => TERMINAL_JOB_STATES.has(state))) {
        return { advanced: false, run }
      }
      next.jobs.push({
        job_id: 'patch:read-only',
        kind: 'PATCH',
        state: 'SKIPPED',
        reason: 'audit mode is read-only; applying patches requires a separate explicit authorization',
      })
      next.phase = 'PATCH'
    }
  } else if (next.phase === 'PATCH') {
    if (!jobsTerminal(next, 'PATCH')) return { advanced: false, run }
    next.jobs.push({
      job_id: 'report:final',
      kind: 'REPORT',
      state: 'PENDING',
    })
    next.phase = 'REPORT'
  } else if (next.phase === 'REPORT') {
    const { index, job } = findJob(next, 'report:final')
    if (job.state !== 'PENDING') {
      throw resultError(`report:final must be PENDING before completeness; received ${job.state}`)
    }
    replaceJob(next, index, { state: 'RUNNING' })
    next.phase = 'COMPLETENESS'
  } else if (next.phase === 'COMPLETENESS') {
    if (!advanceClosureRound(next)) return { advanced: false, run }
  } else {
    return { advanced: false, run }
  }

  assertValidRunTransition(run, next)
  return { advanced: true, run: next }
}

function hasFinalGaps(run) {
  const metrics = coverageMetrics(run.coverage)
  const openGaps = filterResolvedCoverageGaps(
    run.coverage.gaps,
    run.coverage.resolved_gap_ids ?? [],
  )
  return (
    run.coverage.unexamined.length > 0 ||
    openGaps.length > 0 ||
    metrics.obligations.open > 0 ||
    (
      run.coverage.closure
      && run.coverage.closure.status !== 'CONVERGED'
    ) ||
    run.coverage.lenses.some(({ status }) => ['NOT_ASSESSED', 'FAILED'].includes(status)) ||
    (run.store_profiles ?? []).some(
      ({ coverage_state: state }) => state !== 'ASSESSED',
    ) ||
    run.jobs.some(({ state }) => state === 'FAILED') ||
    run.errors.length > 0
  )
}

export function buildFinalizedRun(run, options = {}) {
  if (run.state !== 'RUNNING' || run.phase !== 'COMPLETENESS') {
    throw resultError(
      `run must be RUNNING/COMPLETENESS before finalization; received ${run.state}/${run.phase}`,
    )
  }
  if (!jobsTerminal(run, 'COMPLETENESS')) {
    throw resultError('all completeness jobs must be terminal before finalization')
  }
  if (
    run.coverage.closure
    && !['CONVERGED', 'BUDGET_EXHAUSTED', 'UNMEASURED'].includes(
      run.coverage.closure.status,
    )
  ) {
    throw resultError(
      `coverage closure is not terminal: ${run.coverage.closure.status}`,
    )
  }
  if (run.jobs.some((job) =>
    ['TRIAGE', 'PROOF'].includes(job.kind) && job.state === 'FAILED')) {
    throw resultError(
      'failed required TRIAGE or PROOF work must terminate the run as FAILED',
    )
  }
  if (run.jobs.some((job) =>
    ['DORMANT', 'PENDING', 'RUNNING'].includes(job.state)
      && job.job_id !== 'report:final')) {
    throw resultError('all non-report jobs must be terminal before finalization')
  }
  if (run.coverage?.closure?.required_source_closure) {
    if (run.coverage.closure.status !== 'CONVERGED') {
      throw resultError(
        `source closure is required, but coverage ended ${run.coverage.closure.status}`,
      )
    }
    const closureGaps = sourceClosureGaps(run.coverage)
    if (closureGaps.length > 0) {
      const preview = closureGaps.slice(0, 8).map((gap) =>
        gap.lens ? `${gap.lens}:${gap.path}` : gap.path)
      throw resultError(
        `source closure is required, but ${closureGaps.length} canonical source ` +
        `coverage obligation${closureGaps.length === 1 ? '' : 's'} ` +
        `remain${closureGaps.length === 1 ? 's' : ''}: ` +
        `${preview.join(', ')}${closureGaps.length > preview.length ? ', ...' : ''}`,
      )
    }
  }

  const finalRun = clone(run)
  const reportEntry = findJob(finalRun, 'report:final')
  replaceJob(finalRun, reportEntry.index, { state: 'SUCCEEDED' })
  finalRun.state = hasFinalGaps(finalRun) ? 'COMPLETE_WITH_GAPS' : 'COMPLETED'
  finalRun.phase = 'FINALIZED'
  finalRun.completed_at = (
    options.completedAt instanceof Date
      ? options.completedAt
      : new Date(options.completedAt ?? Date.now())
  ).toISOString()

  const markdown = renderMarkdownReport(finalRun)
  const sarif = stableJson(renderSarif(finalRun))
  const coverage = stableJson(finalRun.coverage)
  finalRun.artifacts.report = {
    path: 'report.md',
    sha256: sha256(markdown),
  }
  finalRun.artifacts.sarif = {
    path: 'results.sarif',
    sha256: sha256(sarif),
  }
  finalRun.artifacts.coverage = {
    path: 'coverage.json',
    sha256: sha256(coverage),
  }

  assertValidRunTransition(run, finalRun)
  return {
    run: finalizeRun(finalRun),
    report: markdown,
    sarif,
    coverage,
  }
}
