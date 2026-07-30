import { compareCanonicalStrings } from './canonical-order.mjs'

export const MAX_STORE_CONTRIBUTIONS = 4096

export const DATABASE_TOPIC_IDS = Object.freeze([
  'database-audit-identity-and-coverage',
  'database-backup-restore-and-clone-security',
  'database-integrity-transactions-and-concurrency',
  'database-lifecycle-and-copy-propagation',
  'database-migration-security-drift',
  'database-native-authorization-and-tenant-isolation',
  'database-principal-and-role-boundaries',
  'database-privileged-code-and-execution-context',
  'database-replication-cdc-history-and-sharing',
  'database-resource-governance-and-availability',
])

function candidatePaths(candidate) {
  return candidate?.scope_paths ?? candidate?.evidence_paths ?? []
}

function baseDatabaseJobs(run) {
  return (run.jobs ?? []).filter((job) =>
    job.kind === 'LENS'
    && job.lens === 'database-and-data-stores'
    && job.closure_round === undefined)
}

function shardScopeByJob(run) {
  return new Map(
    (run.coverage?.shards ?? [])
      .filter(({ job_id: jobId, scoped_files: scopedFiles }) =>
        typeof jobId === 'string' && Array.isArray(scopedFiles))
      .map(({ job_id: jobId, scoped_files: scopedFiles }) => [
        jobId,
        scopedFiles,
      ]),
  )
}

export function expectedStoreContributionRelationships(run) {
  const relationships = []
  for (const job of baseDatabaseJobs(run)) {
    for (const storeId of job.database_store_ids ?? []) {
      relationships.push({
        job_id: job.job_id,
        store_id: storeId,
        role: (job.profile_authority_store_ids ?? []).includes(storeId)
          ? 'AUTHORITY'
          : 'CONTEXT',
      })
    }
  }
  return relationships
}

export function expectedStorePathsForJob(run, job, storeId) {
  const candidate = (run.database_discovery?.store_candidates ?? [])
    .find(({ store_id: candidateId }) => candidateId === storeId)
  if (!candidate) return []
  const scope = new Set(shardScopeByJob(run).get(job.job_id) ?? [])
  return candidatePaths(candidate)
    .filter((path) => scope.has(path))
    .sort(compareCanonicalStrings)
}

export function normalizeStoreContribution(contribution) {
  if (contribution?.profile) {
    return {
      store_id: contribution.store_id,
      coverage_state: contribution.profile.coverage_state,
      assessed_topics: contribution.profile.assessed_topics,
      evidence_paths: contribution.profile.evidence_paths,
      coverage_gaps: contribution.profile.coverage_gaps,
      profile: contribution.profile,
    }
  }
  return contribution
}

function authenticatedSuccessfulJob(job) {
  return (
    job?.state === 'SUCCEEDED'
    && typeof job.input_sha256 === 'string'
    && /^[a-fA-F0-9]{64}$/.test(job.input_sha256)
    && job.producer !== null
    && typeof job.producer === 'object'
    && !Array.isArray(job.producer)
    && [
      'PROVIDER_DECLARED',
      'CONTROLLER_OBSERVED_CONSUMPTION',
    ].includes(job.coverage_authority)
  )
}

function uniqueCanonical(values) {
  return [...new Set(values)].sort(compareCanonicalStrings)
}

function canonicalGaps(gaps) {
  const byIdentity = new Map()
  for (const gap of gaps) {
    const key = JSON.stringify([gap.area, gap.reason])
    if (!byIdentity.has(key)) byIdentity.set(key, gap)
  }
  return [...byIdentity.entries()]
    .sort(([left], [right]) => compareCanonicalStrings(left, right))
    .map(([, gap]) => gap)
}

function allTopics(topics) {
  return (
    topics.length === DATABASE_TOPIC_IDS.length
    && DATABASE_TOPIC_IDS.every((topic) => topics.includes(topic))
  )
}

function intersectTopics(contributions) {
  if (contributions.length === 0) return []
  return DATABASE_TOPIC_IDS.filter((topic) =>
    contributions.every(({ assessed_topics: topics }) => topics.includes(topic)))
}

function controllerGap(storeId, jobId, reason) {
  return {
    area: `store synthesis:${storeId}:${jobId}`,
    reason,
  }
}

export function synthesizeStoreProfiles(run) {
  const jobs = new Map((run.jobs ?? []).map((job) => [job.job_id, job]))
  const envelopes = run.store_contributions ?? []
  const candidates = run.database_discovery?.store_candidates ?? []
  const relationships = expectedStoreContributionRelationships(run)
  const results = []

  for (const candidate of candidates) {
    const storeId = candidate.store_id
    const required = relationships.filter(
      ({ store_id: candidateStoreId }) => candidateStoreId === storeId,
    )
    const normalized = []
    const gaps = []
    let authorityProfile

    for (const relationship of required) {
      const matches = envelopes.filter((envelope) =>
        envelope.job_id === relationship.job_id
        && envelope.contribution?.store_id === storeId)
      const job = jobs.get(relationship.job_id)
      if (matches.length !== 1 || !authenticatedSuccessfulJob(job)) {
        gaps.push(controllerGap(
          storeId,
          relationship.job_id,
          matches.length === 0
            ? 'Required authenticated shard contribution is missing.'
            : 'Required shard contribution is duplicated or lacks authenticated successful job provenance.',
        ))
        continue
      }
      const envelope = matches[0]
      if (envelope.role !== relationship.role) {
        gaps.push(controllerGap(
          storeId,
          relationship.job_id,
          'Stored contribution role does not match controller authority.',
        ))
        continue
      }
      const value = normalizeStoreContribution(envelope.contribution)
      normalized.push(value)
      gaps.push(...value.coverage_gaps)
      const expectedPaths = expectedStorePathsForJob(run, job, storeId)
      const evidenced = new Set(value.evidence_paths)
      if (expectedPaths.some((path) => !evidenced.has(path))) {
        gaps.push(controllerGap(
          storeId,
          relationship.job_id,
          'Contribution does not evidence every discovered store path assigned to its shard.',
        ))
      }
      if (relationship.role === 'AUTHORITY') {
        authorityProfile = value.profile
      }
    }

    if (!authorityProfile) continue

    const evidencePaths = uniqueCanonical(normalized.flatMap(
      ({ evidence_paths: paths }) => paths,
    ))
    const discoveredPaths = uniqueCanonical(candidatePaths(candidate))
    if (discoveredPaths.some((path) => !evidencePaths.includes(path))) {
      gaps.push({
        area: `store synthesis:${storeId}:scope`,
        reason: 'Synthesized evidence does not cover the complete controller-discovered store scope.',
      })
    }

    const assessed = (
      normalized.length === required.length
      && authorityProfile.coverage_state === 'ASSESSED'
      && normalized.every((entry) =>
        entry.coverage_state === 'ASSESSED'
        && allTopics(entry.assessed_topics)
        && entry.coverage_gaps.length === 0)
      && discoveredPaths.every((path) => evidencePaths.includes(path))
      && gaps.length === 0
    )
    const coverageState = assessed
      ? 'ASSESSED'
      : authorityProfile.coverage_state === 'NOT_ASSESSED'
        ? 'NOT_ASSESSED'
        : 'PARTIAL'
    if (!assessed && gaps.length === 0) {
      gaps.push({
        area: `store synthesis:${storeId}`,
        reason: 'One or more shard contributions did not establish complete assessed coverage.',
      })
    }

    results.push({
      store_id: storeId,
      profile: {
        ...structuredClone(authorityProfile),
        evidence_paths: evidencePaths,
        coverage_state: coverageState,
        assessed_topics: assessed
          ? [...DATABASE_TOPIC_IDS]
          : intersectTopics(normalized),
        coverage_gaps: canonicalGaps(gaps),
      },
    })
  }

  return results
}
