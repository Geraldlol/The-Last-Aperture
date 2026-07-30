import { createHash } from 'node:crypto'
import {
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  realpath,
  rename,
  rm,
} from 'node:fs/promises'
import { basename, dirname, isAbsolute, join, parse, relative, resolve } from 'node:path'
import { buildActivationPlan, digestLensPack, loadLenses } from './activation.mjs'
import { artifactKeyToken, artifactToken } from './artifact-names.mjs'
import {
  buildCategoryDenominators,
  inventoryCoverageRecords,
} from './coverage-model.mjs'
import {
  discoverDatabaseGraph,
  serializeDatabaseDiscovery,
} from './database-discovery.mjs'
import { inventoryRepository, serializeInventory } from './inventory.mjs'
import { createStaticPolicy } from './policy.mjs'
import {
  buildSealedControlSnapshot,
  buildSealedSourceSnapshot,
} from './sealed-snapshot.mjs'
import {
  assertBundleArtifactSize,
  assertRunManifestSize,
  MAX_BUNDLE_ARTIFACTS,
  reserveBundleArtifactCapacity,
} from './resource-limits.mjs'
import {
  DEFAULT_WORK_SHARD_LIMITS,
  buildRetryJobTemplate,
  validateWorkShardLimits,
} from './work-shards.mjs'
import { MAX_STORE_CONTRIBUTIONS } from './store-synthesis.mjs'

export const PLATFORM_VERSION = '0.6.0'
export const RUN_SCHEMA_VERSION = '4.0.0'
export const DEFAULT_CLOSURE_MAX_ROUNDS = 3

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue)
  if (value === null || typeof value !== 'object') return value
  return Object.fromEntries(
    Object.keys(value)
      .sort((left, right) => left.localeCompare(right, 'en'))
      .map((key) => [key, stableValue(value[key])]),
  )
}

export function stableJson(value, spacing = 2) {
  return `${JSON.stringify(stableValue(value), null, spacing)}\n`
}

export function providerPolicyProjection(policy, policyDigest) {
  if (
    policy === null
    || typeof policy !== 'object'
    || !/^[a-f0-9]{64}$/.test(policyDigest)
  ) {
    throw new TypeError('provider policy projection requires a policy and SHA-256 digest')
  }
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/provider-policy-projection',
    controller_policy_sha256: policyDigest,
    policy_id: policy.policy_id,
    mode: policy.mode,
    capabilities: structuredClone(policy.capabilities),
  }
}

function normalizedTimestamp(value) {
  const timestamp = value instanceof Date ? value : new Date(value)
  if (Number.isNaN(timestamp.valueOf())) throw new Error('run timestamp must be a valid date')
  return timestamp.toISOString()
}

function createRunId(createdAt, planDigest) {
  return `run:${createdAt.replace(/[:.]/g, '-').replace('Z', 'Z')}:${planDigest.slice(0, 12)}`
}

function activationJobId(job) {
  if (job.job_id) return job.job_id
  const prefix = job.phase === 'fanout' ? 'lens' : job.phase
  const shardSuffix = (
    job.phase === 'fanout'
    && job.shard?.count > 1
  )
    ? `:${job.shard.shard_id}`
    : ''
  return `${prefix}:${job.lens}${shardSuffix}`
}

function activationJobToRunJob(job) {
  const kind = job.kind ?? (
    job.phase === 'fanout'
      ? 'LENS'
      : job.phase === 'completeness'
        ? 'COMPLETENESS'
        : 'TRIAGE'
  )
  return {
    job_id: activationJobId(job),
    kind,
    lens: job.lens,
    state: job.dormant
      ? 'DORMANT'
      : job.activated
        ? 'PENDING'
        : 'SKIPPED',
    ...(job.shard ? { shard: job.shard } : {}),
    ...(job.closure_round ? { closure_round: job.closure_round } : {}),
    ...(job.parent_job_id ? { parent_job_id: job.parent_job_id } : {}),
    ...(job.database_discovery
      ? {
          database_store_ids: [
            ...(job.database_discovery.related_store_ids ?? []),
          ],
          profile_authority_store_ids:
            job.database_discovery.store_candidates
              ?.map(({ store_id: storeId }) => storeId)
              ?? [],
        }
      : {}),
    ...(job.activated ? {} : { reason: 'lens activation matched no repository input' }),
  }
}

function normalizedCoveragePolicy({
  requireSourceClosure = false,
  maxRounds = DEFAULT_CLOSURE_MAX_ROUNDS,
  shardOptions = {},
} = {}) {
  if (typeof requireSourceClosure !== 'boolean') {
    throw new TypeError('requireSourceClosure must be a boolean')
  }
  const limits = validateWorkShardLimits({
    maxFiles: shardOptions.maxFiles ?? DEFAULT_WORK_SHARD_LIMITS.maxFiles,
    maxBytes: shardOptions.maxBytes ?? DEFAULT_WORK_SHARD_LIMITS.maxBytes,
  })
  if (!Number.isSafeInteger(maxRounds) || maxRounds < 0 || maxRounds > 32) {
    throw new RangeError('maxRounds must not exceed 32')
  }
  return {
    require_source_closure: requireSourceClosure,
    max_shard_files: limits.maxFiles,
    max_shard_bytes: limits.maxBytes,
    max_requeue_rounds: maxRounds,
  }
}

function planCoverage(inventory, activation, policy, databaseDiscovery) {
  const gaps = []
  for (const path of activation.coverage.unassigned_text_files) {
    gaps.push({ area: path, reason: 'text input matched no domain lens' })
  }
  for (const entry of activation.coverage.unexamined) {
    gaps.push({ area: entry.path, reason: entry.reason ?? `input classified as ${entry.kind}` })
  }
  for (const error of activation.coverage.inventory_errors) {
    gaps.push({ area: error.path, reason: `${error.operation}: ${error.code}` })
  }
  for (const exclusion of activation.coverage.configured_exclusions) {
    gaps.push({ area: exclusion.path, reason: exclusion.reason })
  }
  for (const candidate of databaseDiscovery?.store_candidates ?? []) {
    gaps.push({
      area: `store:${candidate.store_id}`,
      reason: 'controller-discovered data store has no provider assessment profile',
    })
  }
  for (const unresolved of databaseDiscovery?.unresolved ?? []) {
    gaps.push({
      area: `database-discovery:${unresolved.observation_id}`,
      reason: `${unresolved.type}: ${(unresolved.reasons ?? []).join('; ')}`,
    })
  }
  for (const gap of databaseDiscovery?.gaps ?? []) {
    gaps.push({
      area: `database-discovery:${gap.gap_id}`,
      reason: `${gap.code}: ${gap.detail}`,
    })
  }

  const rowsByLens = new Map()
  for (const job of activation.jobs) {
    let row = rowsByLens.get(job.lens)
    if (!row) {
      row = {
        lens: job.lens,
        status: job.activated ? 'NOT_ASSESSED' : 'NOT_TRIGGERED',
        applicable_paths: [],
        examined_paths: [],
        reason: job.activated
          ? 'audit job has not run'
          : 'activation matched no repository input',
      }
      rowsByLens.set(job.lens, row)
    }
    if (job.activated) {
      row.status = 'NOT_ASSESSED'
      row.reason = 'audit job has not run'
      row.applicable_paths.push(...job.scoped_files)
    }
  }
  for (const row of rowsByLens.values()) {
    row.applicable_paths = [...new Set(row.applicable_paths)]
      .sort((left, right) => left.localeCompare(right, 'en'))
  }

  const records = inventoryCoverageRecords(inventory.entries)
  return {
    model_version: '2.0.0',
    policy: structuredClone(policy),
    inventory: inventory.entries.map(({ path }) => path),
    inventory_records: records,
    examined: [],
    unexamined: inventory.entries.map(({ path, kind, category, size, reason }) => ({
      path,
      kind,
      category,
      size,
      reason: reason ?? (
        kind === 'text'
          ? 'audit job has not run'
          : `input classified as ${kind}`
      ),
    })),
    lenses: [...rowsByLens.values()],
    gaps,
    denominators: buildCategoryDenominators(records),
    shards: activation.jobs
      .filter((job) => job.phase === 'fanout' && job.activated && job.shard)
      .map((job) => ({
        job_id: activationJobId(job),
        lens: job.lens,
        scoped_files: [...job.scoped_files],
        shard: job.shard,
      })),
    resolved_gap_ids: [],
    closure: {
      required_source_closure: policy.require_source_closure,
      max_rounds: policy.max_requeue_rounds,
      round: 0,
      status: 'PENDING',
      history: [],
    },
  }
}

function closureTemplateJobs(activationJobs, maxRounds) {
  if (maxRounds === 0) return []
  const templates = []
  const fanout = activationJobs.filter(
    (job) => job.phase === 'fanout' && job.activated && job.shard,
  )
  const triage = activationJobs.filter((job) => job.phase === 'triage')
  const completeness = activationJobs.find((job) => job.phase === 'completeness')
  for (let closureRound = 1; closureRound <= maxRounds; closureRound += 1) {
    for (const parent of fanout) {
      const retry = buildRetryJobTemplate(
        { scoped_files: parent.scoped_files, shard: parent.shard },
        {
          parentJobId: activationJobId(parent),
          lens: parent.lens,
          closureRound,
        },
      )
      templates.push({
        ...parent,
        ...retry,
        phase: 'completeness',
        activation: 'controller-closure-retry',
        activated: true,
        dormant: true,
        matches: parent.matches.filter(({ path }) =>
          retry.scoped_files.includes(path)),
      })
    }
    for (const parent of triage) {
      templates.push({
        ...parent,
        job_id: `closure:${String(closureRound).padStart(2, '0')}:triage:${parent.lens}`,
        kind: 'TRIAGE',
        phase: 'completeness',
        activation: 'controller-closure-triage',
        activated: true,
        dormant: true,
        closure_round: closureRound,
        parent_job_id: activationJobId(parent),
      })
    }
    if (completeness) {
      templates.push({
        ...completeness,
        job_id: `closure:${String(closureRound).padStart(2, '0')}:completeness`,
        kind: 'COMPLETENESS',
        phase: 'completeness',
        activation: 'controller-closure-measurement',
        activated: true,
        dormant: true,
        closure_round: closureRound,
        parent_job_id: activationJobId(completeness),
      })
    }
  }
  return templates
}

function closureTemplateJobCount(activationJobs, maxRounds) {
  if (maxRounds === 0) return 0
  const perRound = activationJobs.filter(
    (job) => (
      (job.phase === 'fanout' && job.activated && job.shard)
      || job.phase === 'triage'
      || job.phase === 'completeness'
    ),
  ).length
  return perRound * maxRounds
}

function inventoryErrors(inventory) {
  return inventory.errors.map((error, index) => ({
    error_id: `recon:${String(index + 1).padStart(4, '0')}`,
    phase: 'RECON',
    code: `INVENTORY_${String(error.code).replace(/[^A-Z0-9]+/gi, '_').toUpperCase()}`,
    message: `${error.path}: ${error.operation}: ${error.message}`,
    recoverable: true,
  }))
}

function jobSidecar(job, repositoryRoot) {
  const jobId = activationJobId(job)
  const kind = job.kind ?? (
    job.phase === 'fanout'
      ? 'LENS'
      : job.phase === 'completeness'
        ? 'COMPLETENESS'
        : 'TRIAGE'
  )
  return {
    schema_version: RUN_SCHEMA_VERSION,
    job_id: jobId,
    kind,
    lens: job.lens,
    phase: job.phase.toUpperCase(),
    activated: job.activated,
    activation: job.activation,
    lens_file: job.lens_file,
    lens_digest: job.lens_digest,
    repository_root: repositoryRoot,
    scoped_files: job.scoped_files,
    matches: job.matches,
    ...(job.shard ? { shard: job.shard } : {}),
    ...(job.closure_round ? { closure_round: job.closure_round } : {}),
    ...(job.parent_job_id ? { parent_job_id: job.parent_job_id } : {}),
    ...(job.database_discovery
      ? {
          database_discovery: job.database_discovery,
          database_store_ids: [
            ...(job.database_discovery.related_store_ids ?? []),
          ],
          profile_authority_store_ids:
            job.database_discovery.store_candidates
              ?.map(({ store_id: storeId }) => storeId)
              ?? [],
        }
      : {}),
    owned_topics: job.owned_topics,
    known_topics: job.known_topics,
    trust_boundary: {
      repository_content_is_untrusted_data: true,
      may_change_scope_or_policy: false,
      may_authorize_actions: false,
    },
  }
}

export async function createRunPlan(options) {
  const {
    targetRoot,
    lensDirectory = resolve('skills/red-team-audit/lenses'),
    policy,
    createdAt = new Date(),
    inventoryOptions,
    sealSource = false,
    requireSourceClosure = options.closureOptions?.requireSourceClosure ?? false,
    shardOptions = options.shardOptions ?? options.shardPolicy ?? {},
    maxClosureRounds = options.closureOptions?.maxRounds
      ?? options.shardPolicy?.maxRounds
      ?? DEFAULT_CLOSURE_MAX_ROUNDS,
  } = options
  if (!targetRoot) throw new Error('targetRoot is required')

  const repositoryRoot = await realpath(resolve(targetRoot))
  const effectivePolicy = policy ?? createStaticPolicy({ workspaceRoot: repositoryRoot })
  if (resolve(effectivePolicy.workspace_root) !== repositoryRoot) {
    throw new Error('Rules of Engagement workspace_root does not match the repository root')
  }
  const readCapability = effectivePolicy.capabilities.read_file
  const coveragePolicy = normalizedCoveragePolicy({
    requireSourceClosure,
    maxRounds: maxClosureRounds,
    shardOptions,
  })
  const inventory = await inventoryRepository(repositoryRoot, {
    ...(inventoryOptions ?? {}),
    maxTextBytes:
      inventoryOptions?.maxTextBytes ?? coveragePolicy.max_shard_bytes,
    includedRoots: readCapability.enabled ? readCapability.roots : [],
  })
  const databaseDiscovery = discoverDatabaseGraph(inventory)
  const databaseDiscoveryContent = serializeDatabaseDiscovery(databaseDiscovery)
  const [lenses, lensPack] = await Promise.all([
    loadLenses(lensDirectory),
    digestLensPack(lensDirectory),
  ])
  const activation = buildActivationPlan(lenses, inventory, {
    shardPolicy: {
      maxFiles: coveragePolicy.max_shard_files,
      maxBytes: coveragePolicy.max_shard_bytes,
    },
    databaseDiscovery,
  })
  const plannedJobCount = activation.jobs.length + closureTemplateJobCount(
    activation.jobs,
    coveragePolicy.max_requeue_rounds,
  )
  // Each planned job has a write-once sidecar artifact. Reject impossible
  // plans before multiplying objects in memory; reserve room for the run's
  // fixed manifests and sealed snapshot indexes/shards.
  const fixedArtifactReserve = 32
  if (plannedJobCount > MAX_BUNDLE_ARTIFACTS - fixedArtifactReserve) {
    throw new RangeError(
      `coverage policy requires ${plannedJobCount} planned jobs, exceeding ` +
      `the bounded bundle capacity of ${MAX_BUNDLE_ARTIFACTS - fixedArtifactReserve}`,
    )
  }
  const templateJobs = closureTemplateJobs(
    activation.jobs,
    coveragePolicy.max_requeue_rounds,
  )
  const plannedJobs = [...activation.jobs, ...templateJobs]
  const requiredStoreContributions = activation.jobs
    .filter((job) =>
      job.lens === 'database-and-data-stores'
      && (job.kind === undefined || job.kind === 'LENS')
      && job.closure_round === undefined)
    .reduce(
      (total, job) =>
        total + (job.database_discovery?.related_store_ids?.length ?? 0),
      0,
    )
  if (requiredStoreContributions > MAX_STORE_CONTRIBUTIONS) {
    throw new RangeError(
      `database plan requires ${requiredStoreContributions} shard/store ` +
      `contributions, exceeding the bounded limit of ${MAX_STORE_CONTRIBUTIONS}`,
    )
  }
  const policyDigest = sha256(stableJson(effectivePolicy, 0))
  const corpusDigest = lensPack.digest
  const timestamp = normalizedTimestamp(createdAt)
  const providerPolicy = providerPolicyProjection(
    effectivePolicy,
    policyDigest,
  )
  const controlSnapshot = buildSealedControlSnapshot([
    {
      path: 'controls/policy.json',
      bytes: Buffer.from(stableJson(effectivePolicy), 'utf8'),
    },
    {
      path: 'controls/provider-policy.json',
      bytes: Buffer.from(stableJson(providerPolicy), 'utf8'),
    },
    {
      path: 'controls/lens-pack.json',
      bytes: Buffer.from(stableJson(lensPack), 'utf8'),
    },
    {
      path: 'controls/database-discovery.json',
      bytes: Buffer.from(databaseDiscoveryContent, 'utf8'),
    },
    ...lenses.map((lens) => ({
      path: `lenses/${lens.file}`,
      bytes: Buffer.from(lens.text, 'utf8'),
    })),
  ])
  const sourceSnapshot = sealSource
    ? buildSealedSourceSnapshot(inventory)
    : null
  const controlSnapshotMaterial = snapshotArtifactMaterial(
    'control',
    controlSnapshot,
  )
  const sourceSnapshotMaterial = sourceSnapshot
    ? snapshotArtifactMaterial('source', sourceSnapshot)
    : null

  const coverage = planCoverage(
    inventory,
    activation,
    coveragePolicy,
    databaseDiscovery,
  )
  const planMaterial = {
    schema_version: RUN_SCHEMA_VERSION,
    capability_mode: effectivePolicy.mode === 'static'
      ? 'STATIC'
      : effectivePolicy.mode === 'test'
        ? 'TEST_EXECUTION'
        : 'LOCAL_DYNAMIC',
    repository: {
      tree_digest: inventory.treeDigest,
    },
    policy_digest: policyDigest,
    lens_pack_digest: corpusDigest,
    coverage_policy: coveragePolicy,
    database_discovery_digest: databaseDiscovery.digest,
    control_snapshot_sha256: controlSnapshotMaterial.descriptor.root_sha256,
    ...(sourceSnapshotMaterial
      ? { source_snapshot_sha256: sourceSnapshotMaterial.descriptor.root_sha256 }
      : {}),
    jobs: plannedJobs.map((job) => jobSidecar(job, inventory.root)),
  }
  const planDigest = sha256(stableJson(planMaterial, 0))
  const runId = createRunId(timestamp, planDigest)
  const includedPaths = inventory.entries.map(({ path }) => path)

  const run = {
    schema_version: RUN_SCHEMA_VERSION,
    run_id: runId,
    state: 'PLANNED',
    phase: 'RECON',
    created_at: timestamp,
    capability_mode: planMaterial.capability_mode,
    tool: {
      name: 'red-team-audit',
      version: PLATFORM_VERSION,
      corpus_sha256: corpusDigest,
    },
    plan_digest: planDigest,
    policy_digest: policyDigest,
    lens_pack_digest: corpusDigest,
    repository: {
      root: inventory.root,
      tree_digest: inventory.treeDigest,
      dirty: 'unknown',
    },
    scope: {
      included_paths: includedPaths.length > 0 ? includedPaths : ['.'],
      excluded_paths: inventory.excluded,
    },
    activated_lenses: activation.active_lenses,
    jobs: plannedJobs.map(activationJobToRunJob),
    coverage,
    database_discovery: databaseDiscovery,
    store_contributions: [],
    store_profiles: [],
    findings: [],
    errors: inventoryErrors(inventory),
    artifacts: {
      ...controlSnapshotMaterial.artifacts,
      ...(sourceSnapshotMaterial?.artifacts ?? {}),
    },
    control_snapshot: controlSnapshotMaterial.descriptor,
    ...(sourceSnapshotMaterial
      ? { source_snapshot: sourceSnapshotMaterial.descriptor }
      : {}),
    attempt_events: [],
  }

  return {
    run,
    policy: effectivePolicy,
    inventory,
    activation,
    databaseDiscovery,
    lensPack,
    sealedSnapshots: {
      control: controlSnapshot,
      ...(sourceSnapshot ? { source: sourceSnapshot } : {}),
    },
    jobSidecars: plannedJobs.map((job) => jobSidecar(job, inventory.root)),
  }
}

async function atomicWrite(path, content) {
  assertBundleArtifactSize(content, `bundle artifact ${path}`)
  const temporary = `${path}.tmp`
  const handle = await open(temporary, 'wx', 0o600)
  try {
    if (Buffer.isBuffer(content)) {
      await handle.writeFile(content)
    } else {
      await handle.writeFile(content, { encoding: 'utf8' })
    }
    await handle.sync()
  } finally {
    await handle.close()
  }
  await rename(temporary, path)
}

function containedBy(root, candidate) {
  const fromRoot = relative(root, candidate)
  return fromRoot !== ''
    && !fromRoot.startsWith('..')
    && !isAbsolute(fromRoot)
}

async function ensureUnlinkedDirectoryComponents(path) {
  const absolutePath = resolve(path)
  const root = parse(absolutePath).root
  const segments = relative(root, absolutePath).split(/[\\/]/).filter(Boolean)
  let current = root
  for (const segment of segments) {
    current = join(current, segment)
    let metadata
    try {
      metadata = await lstat(current)
    } catch (error) {
      if (error.code !== 'ENOENT') throw error
      await mkdir(current, { mode: 0o700 })
      metadata = await lstat(current)
    }
    if (metadata.isSymbolicLink()) {
      throw new Error(`output path contains a symbolic link or reparse point: ${current}`)
    }
    if (!metadata.isDirectory()) {
      throw new Error(`output path component is not a directory: ${current}`)
    }
  }
  return realpath(absolutePath)
}

async function assertPathAbsent(path, label) {
  try {
    await lstat(path)
  } catch (error) {
    if (error.code === 'ENOENT') return
    throw error
  }
  throw new Error(`${label} already exists: ${path}`)
}

async function createVerifiedStagingDirectory(canonicalParent, finalDirectory) {
  const stagingNamePrefix = `.${basename(finalDirectory)}.staging-`
  const stagingDirectory = await mkdtemp(join(canonicalParent, stagingNamePrefix))
  const metadata = await lstat(stagingDirectory)
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new Error(`run bundle staging path is not an unlinked directory: ${stagingDirectory}`)
  }
  const canonicalStaging = await realpath(stagingDirectory)
  if (
    dirname(canonicalStaging) !== canonicalParent
    || !containedBy(canonicalParent, canonicalStaging)
    || !basename(canonicalStaging).startsWith(stagingNamePrefix)
  ) {
    throw new Error(`run bundle staging path escaped its canonical output parent: ${stagingDirectory}`)
  }
  return {
    path: stagingDirectory,
    canonicalPath: canonicalStaging,
    canonicalParent,
    namePrefix: stagingNamePrefix,
  }
}

async function removeVerifiedStagingDirectory(staging) {
  let metadata
  try {
    metadata = await lstat(staging.path)
  } catch (error) {
    if (error.code === 'ENOENT') return
    throw error
  }
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new Error(`refusing to clean replaced run bundle staging path: ${staging.path}`)
  }
  const observedCanonicalPath = await realpath(staging.path)
  if (
    observedCanonicalPath !== staging.canonicalPath
    || dirname(observedCanonicalPath) !== staging.canonicalParent
    || !basename(observedCanonicalPath).startsWith(staging.namePrefix)
  ) {
    throw new Error(`refusing to clean unverified run bundle staging path: ${staging.path}`)
  }
  await rm(staging.path, { recursive: true })
}

function artifact(path, content) {
  return { path, sha256: sha256(content) }
}

function snapshotArtifactMaterial(name, snapshot) {
  const indexKey = `${name}_snapshot_index`
  const indexPath = `snapshots/${name}/index.json`
  const artifacts = {
    [indexKey]: artifact(indexPath, snapshot.indexBytes),
  }
  for (const shard of snapshot.shards) {
    const key = `${name}_snapshot_${shard.shard_id}`
    artifacts[key] = artifact(
      `snapshots/${name}/${shard.shard_id}.bin`,
      shard.bytes,
    )
  }
  return {
    descriptor: {
      kind: name === 'source' ? 'SOURCE' : 'CONTROL',
      index_artifact_key: indexKey,
      root_sha256: sha256(snapshot.indexBytes),
      available_files: snapshot.index.files.filter(
        ({ availability }) => availability === 'AVAILABLE',
      ).length,
      available_bytes: snapshot.index.files
        .filter(({ availability }) => availability === 'AVAILABLE')
        .reduce((total, { size }) => total + size, 0),
    },
    artifacts,
  }
}

export async function writeRunPlanBundle(plan, outputParent) {
  const parent = resolve(outputParent)
  const canonicalParent = await ensureUnlinkedDirectoryComponents(parent)
  const directory = join(canonicalParent, plan.run.run_id.replaceAll(':', '_'))
  await assertPathAbsent(directory, 'run bundle')
  const staging = await createVerifiedStagingDirectory(canonicalParent, directory)
  let published = false
  try {
    await mkdir(join(staging.path, 'jobs'), { mode: 0o700 })
    const canonicalJobs = await ensureUnlinkedDirectoryComponents(
      join(staging.path, 'jobs'),
    )
    if (!containedBy(staging.canonicalPath, canonicalJobs)) {
      throw new Error(`job directory escaped its canonical run bundle: ${staging.path}`)
    }

    const inventoryContent = stableJson(serializeInventory(plan.inventory))
    const policyContent = stableJson(plan.policy)
    const coverageContent = stableJson(plan.run.coverage)
    const lensPackContent = stableJson(plan.lensPack)
    const databaseDiscoveryContent = serializeDatabaseDiscovery(
      plan.databaseDiscovery ?? plan.run.database_discovery,
    )
    const sidecarArtifacts = plan.jobSidecars.map((sidecar) => {
      const file = `${artifactToken(sidecar.job_id)}.json`
      return {
        sidecar,
        file,
        path: join('jobs', file),
        content: stableJson(sidecar),
      }
    })
    const snapshotWrites = Object.entries(plan.sealedSnapshots ?? {})
      .flatMap(([name, snapshot]) => [
        {
          path: `snapshots/${name}/index.json`,
          content: snapshot.indexBytes,
        },
        ...snapshot.shards.map((shard) => ({
          path: `snapshots/${name}/${shard.shard_id}.bin`,
          content: shard.bytes,
        })),
      ])
    reserveBundleArtifactCapacity(
      { artifactCount: 0, artifactBytes: 0 },
      [
        inventoryContent,
        policyContent,
        coverageContent,
        lensPackContent,
        databaseDiscoveryContent,
        ...sidecarArtifacts.map(({ content }) => content),
        ...snapshotWrites.map(({ content }) => content),
      ],
      'planned bundle artifacts',
    )
    await atomicWrite(join(staging.path, 'inventory.json'), inventoryContent)
    await atomicWrite(join(staging.path, 'policy.json'), policyContent)
    await atomicWrite(join(staging.path, 'coverage-plan.json'), coverageContent)
    await atomicWrite(join(staging.path, 'lens-pack.json'), lensPackContent)
    await atomicWrite(
      join(staging.path, 'database-discovery.json'),
      databaseDiscoveryContent,
    )
    for (const name of Object.keys(plan.sealedSnapshots ?? {})) {
      const snapshotDirectory = await ensureUnlinkedDirectoryComponents(
        join(staging.path, 'snapshots', name),
      )
      if (!containedBy(staging.canonicalPath, snapshotDirectory)) {
        throw new Error(
          `snapshot directory escaped its canonical run bundle: ${staging.path}`,
        )
      }
    }
    for (const { path, content } of snapshotWrites) {
      await atomicWrite(join(staging.path, path), content)
    }

    const artifacts = {
      ...plan.run.artifacts,
      inventory: artifact('inventory.json', inventoryContent),
      policy: artifact('policy.json', policyContent),
      coverage_plan: artifact('coverage-plan.json', coverageContent),
      lens_pack: artifact('lens-pack.json', lensPackContent),
      database_discovery: artifact(
        'database-discovery.json',
        databaseDiscoveryContent,
      ),
    }

    for (const { sidecar, path, content } of sidecarArtifacts) {
      await atomicWrite(join(staging.path, path), content)
      artifacts[`job_${artifactKeyToken(sidecar.job_id).toLowerCase()}`] = artifact(
        path.replaceAll('\\', '/'),
        content,
      )
    }

    plan.run.artifacts = artifacts
    const runContent = stableJson(plan.run)
    assertRunManifestSize(runContent)
    const stagingRunPath = join(staging.path, 'run.json')
    await atomicWrite(stagingRunPath, runContent)
    const observedRunContent = await readFile(stagingRunPath, 'utf8')
    if (observedRunContent !== runContent) {
      throw new Error('staged run manifest failed exact-byte verification')
    }

    await assertPathAbsent(directory, 'run bundle')
    await rename(staging.path, directory)
    published = true
    return {
      directory,
      runPath: join(directory, 'run.json'),
      relativeRunPath: relative(process.cwd(), join(directory, 'run.json')),
    }
  } catch (error) {
    if (!published) {
      try {
        await removeVerifiedStagingDirectory(staging)
      } catch (cleanupError) {
        throw new AggregateError(
          [error, cleanupError],
          `run bundle publication failed and staging cleanup was unsafe: ${error.message}`,
        )
      }
    }
    throw error
  }
}

export function summarizePlan(plan) {
  const activeFanout = plan.activation.jobs.filter(
    (job) => job.phase === 'fanout' && job.activated,
  )
  const activeFanoutLenses = new Set(activeFanout.map(({ lens }) => lens))
  const triage = plan.activation.jobs.filter((job) => job.phase === 'triage')
  return {
    run_id: plan.run.run_id,
    target: plan.run.repository.root,
    tree_digest: plan.run.repository.tree_digest,
    capability_mode: plan.run.capability_mode,
    active_fanout_lenses: activeFanoutLenses.size,
    fanout_shards: activeFanout.length,
    triage_lenses: triage.length,
    files: plan.inventory.entries.length,
    coverage_status: plan.activation.coverage.status,
    unassigned_text_files: plan.activation.coverage.unassigned_text_files.length,
    unexamined_files: plan.activation.coverage.unexamined.length,
    inventory_errors: plan.inventory.errors.length,
    source_sealed: Boolean(plan.run.source_snapshot),
    require_source_closure:
      plan.run.coverage.closure.required_source_closure,
    database_stores_discovered:
      plan.run.database_discovery.store_candidates.length,
    database_paths_in_scope:
      plan.run.database_discovery.path_scope
        .filter(({ state }) => state === 'in-scope').length,
    denominators: Object.fromEntries(
      plan.run.coverage.denominators.map((row) => [
        row.class ?? row.category,
        {
          files_total: row.files_total,
          bytes_total: row.bytes_total,
        },
      ]),
    ),
  }
}
