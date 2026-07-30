import { constants as fsConstants } from 'node:fs'
import {
  lstat,
  mkdir,
  open,
  realpath,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises'
import { createHash, randomBytes } from 'node:crypto'
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
} from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  assertValidDatabaseConformanceConfig,
  assertValidDatabaseConformanceEvidence,
  assertValidDatabaseConformanceManifest,
  assertValidDatabaseConformanceResult,
  assertValidDatabaseConformanceRun,
  databaseConformanceManifest,
} from './database-conformance-contracts.mjs'
import { compareCanonicalStrings } from './canonical-order.mjs'
import { executeDatabaseConformanceScenarios } from './database-conformance-scenarios.mjs'
import { runDatabaseConformanceEngine } from './database-conformance-runner.mjs'
import { stableJson } from './run-engine.mjs'

const PROJECT_ROOT = resolve(fileURLToPath(new URL('../..', import.meta.url)))
const RUN_FILE = 'run.json'
const MANIFEST_FILE = 'manifest.json'
const REPORT_FILE = 'report.md'
const LOCK_FILE = '.database-conformance.lock'
const OPEN_READ_ONLY_NO_FOLLOW = fsConstants.O_RDONLY
  | (typeof fsConstants.O_NOFOLLOW === 'number' ? fsConstants.O_NOFOLLOW : 0)
const MAX_RUN_BYTES = 2 * 1024 * 1024
const MAX_ARTIFACT_BYTES = 64 * 1024 * 1024

export class DatabaseConformanceControllerError extends Error {
  constructor(code, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'DatabaseConformanceControllerError'
    this.code = code
    if (options.details) this.details = options.details
    if (options.bundle) this.bundle = options.bundle
  }
}

function controllerError(code, message, options) {
  return new DatabaseConformanceControllerError(code, message, options)
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function timestamp(now) {
  const value = now()
  const date = value instanceof Date ? value : new Date(value)
  if (!Number.isFinite(date.getTime())) {
    throw controllerError(
      'DATABASE_CONFORMANCE_CLOCK_INVALID',
      'database conformance clock returned an invalid time',
    )
  }
  return date.toISOString()
}

function makeRunId(now, randomBytesImpl) {
  const suffix = randomBytesImpl(6)
  if (!Buffer.isBuffer(suffix) || suffix.length !== 6) {
    throw controllerError(
      'DATABASE_CONFORMANCE_RANDOM_INVALID',
      'run ID source must return exactly six bytes',
    )
  }
  return `db-lab:${timestamp(now)}:${suffix.toString('hex')}`
}

function artifactDescriptor(path, content) {
  const bytes = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8')
  return {
    path,
    sha256: sha256(bytes),
    size: bytes.length,
  }
}

function canonicalArtifacts(artifacts) {
  return [...artifacts].sort((left, right) =>
    compareCanonicalStrings(left.path, right.path))
}

function artifactRoot(artifacts) {
  return sha256(stableJson(canonicalArtifacts(artifacts), 0))
}

function isInside(parent, child) {
  const path = relative(resolve(parent), resolve(child))
  return path !== '' && !path.startsWith('..') && !isAbsolute(path)
}

async function atomicReplace(path, content) {
  const target = resolve(path)
  const temporary = `${target}.tmp-${process.pid}-${randomBytes(6).toString('hex')}`
  await writeFile(temporary, content, {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  })
  try {
    await rename(temporary, target)
  } catch (error) {
    await rm(temporary, { force: true })
    throw error
  }
}

async function exclusiveWrite(path, content) {
  await writeFile(resolve(path), content, {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  })
}

async function acquireRunLock(directory, now) {
  const path = join(directory, LOCK_FILE)
  const content = stableJson({
    schema_version: '1.0.0',
    pid: process.pid,
    acquired_at: timestamp(now),
    nonce: randomBytes(16).toString('hex'),
  })
  let handle
  try {
    handle = await open(path, 'wx', 0o600)
  } catch (error) {
    if (error.code === 'EEXIST') {
      throw controllerError(
        'DATABASE_CONFORMANCE_RUN_LOCKED',
        `database conformance bundle is already locked: ${directory}`,
      )
    }
    throw error
  }
  let writeError
  try {
    await handle.writeFile(content, { encoding: 'utf8' })
    await handle.sync()
  } catch (error) {
    writeError = error
  } finally {
    await handle.close()
  }
  if (writeError) {
    try {
      await rm(path)
    } catch (cleanupError) {
      throw new AggregateError(
        [writeError, cleanupError],
        'database conformance run lock creation failed and its partial file could not be removed',
      )
    }
    throw writeError
  }
  return { path, content }
}

async function releaseRunLock(lock) {
  const observed = await readBoundedNoFollow(
    lock.path,
    4096,
    LOCK_FILE,
  )
  if (observed.toString('utf8') !== lock.content) {
    throw controllerError(
      'DATABASE_CONFORMANCE_RUN_LOCK_CHANGED',
      'database conformance run lock changed while the controller held it',
    )
  }
  await rm(lock.path)
}

function processIsAlive(pid) {
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    if (error.code === 'ESRCH') return false
    return true
  }
}

export async function unlockDatabaseConformanceBundle(argument) {
  const loaded = await loadRun(argument)
  const path = join(loaded.directory, LOCK_FILE)
  let bytes
  try {
    bytes = await readBoundedNoFollow(path, 4096, LOCK_FILE)
  } catch (error) {
    if (error.code === 'ENOENT') {
      throw controllerError(
        'DATABASE_CONFORMANCE_RUN_NOT_LOCKED',
        'database conformance bundle has no run lock',
      )
    }
    throw error
  }
  let record
  try {
    record = JSON.parse(bytes.toString('utf8'))
  } catch (error) {
    throw controllerError(
      'DATABASE_CONFORMANCE_RUN_LOCK_INVALID',
      'database conformance run lock is not valid JSON',
      { cause: error },
    )
  }
  if (
    record?.schema_version !== '1.0.0'
    || !Number.isSafeInteger(record.pid)
    || record.pid <= 0
    || typeof record.acquired_at !== 'string'
    || typeof record.nonce !== 'string'
    || !/^[a-f0-9]{32}$/.test(record.nonce)
  ) {
    throw controllerError(
      'DATABASE_CONFORMANCE_RUN_LOCK_INVALID',
      'database conformance run lock has an invalid bounded record',
    )
  }
  if (processIsAlive(record.pid)) {
    throw controllerError(
      'DATABASE_CONFORMANCE_RUN_LOCK_ACTIVE',
      `database conformance controller process ${record.pid} is still active`,
    )
  }
  const observed = await readBoundedNoFollow(path, 4096, LOCK_FILE)
  if (!observed.equals(bytes)) {
    throw controllerError(
      'DATABASE_CONFORMANCE_RUN_LOCK_CHANGED',
      'database conformance run lock changed during stale-lock recovery',
    )
  }
  await rm(path)
  return {
    bundle: loaded.directory,
    removed_pid: record.pid,
    warning:
      'The next run will inspect and recover only exact run-labeled stale containers.',
  }
}

async function createStagingDirectory(destination) {
  const requestedTarget = resolve(destination)
  const requestedParent = dirname(requestedTarget)
  const requestedParentInfo = await lstat(requestedParent)
  if (!requestedParentInfo.isDirectory() || requestedParentInfo.isSymbolicLink()) {
    throw controllerError(
      'DATABASE_CONFORMANCE_PARENT_UNSAFE',
      'database conformance destination parent must be a real directory',
    )
  }
  const parent = await realpath(requestedParent)
  const projectRoot = await realpath(PROJECT_ROOT)
  const target = join(parent, basename(requestedTarget))
  let targetStat
  try {
    targetStat = await lstat(target)
  } catch (error) {
    if (error.code !== 'ENOENT') throw error
  }
  if (targetStat) {
    throw controllerError(
      'DATABASE_CONFORMANCE_DESTINATION_EXISTS',
      `database conformance destination already exists: ${target}`,
    )
  }
  if (isInside(projectRoot, target) || target === projectRoot) {
    throw controllerError(
      'DATABASE_CONFORMANCE_DESTINATION_INSIDE_PROJECT',
      'database conformance bundles must be written outside the project tree',
    )
  }
  const parentInfo = await lstat(parent)
  if (!parentInfo.isDirectory() || parentInfo.isSymbolicLink()) {
    throw controllerError(
      'DATABASE_CONFORMANCE_PARENT_UNSAFE',
      'database conformance destination parent must be a real directory',
    )
  }
  const staging = join(
    parent,
    `.${basename(target)}.staging-${process.pid}-${randomBytes(6).toString('hex')}`,
  )
  await mkdir(staging, { recursive: false, mode: 0o700 })
  return { target, staging }
}

function normalizeEngineIds(engineIds) {
  const available = databaseConformanceManifest.engines.map(
    ({ engine_id: engineId }) => engineId,
  )
  const requested = engineIds === undefined ? available : [...engineIds]
  if (requested.length === 0 || new Set(requested).size !== requested.length) {
    throw controllerError(
      'DATABASE_CONFORMANCE_ENGINE_SELECTION_INVALID',
      'engine selection must contain one or more unique engine IDs',
    )
  }
  for (const engineId of requested) {
    if (!available.includes(engineId)) {
      throw controllerError(
        'DATABASE_CONFORMANCE_ENGINE_SELECTION_INVALID',
        `unknown database conformance engine ${JSON.stringify(engineId)}`,
      )
    }
  }
  return requested.sort(compareCanonicalStrings)
}

export async function planDatabaseConformance({
  out,
  engineIds,
  now = () => new Date(),
  randomBytesImpl = randomBytes,
}) {
  const requested = normalizeEngineIds(engineIds)
  const { target, staging } = await createStagingDirectory(out)
  try {
    const manifestContent = stableJson(databaseConformanceManifest)
    const manifestArtifact = artifactDescriptor(MANIFEST_FILE, manifestContent)
    const omitted = databaseConformanceManifest.engines
      .map(({ engine_id: engineId }) => engineId)
      .filter((engineId) => !requested.includes(engineId))
    const run = {
      schema_version: '1.0.0',
      protocol: 'docker-database-lab-v1',
      tool: {
        name: 'red-team-audit-database-conformance',
        version: '0.7.0',
      },
      run_id: makeRunId(now, randomBytesImpl),
      state: 'PLANNED',
      capability_mode: 'LOCAL_DYNAMIC',
      assurance_scope: 'DISPOSABLE_REFERENCE_ENGINE_BEHAVIOR_ONLY',
      created_at: timestamp(now),
      manifest: manifestArtifact,
      requested_engine_ids: requested,
      results: [],
      artifacts: [manifestArtifact],
      gaps: omitted.map((engineId) => ({
        area: `engine:${engineId}`,
        reason: 'The operator planned a subset run; this engine was not executed.',
      })),
    }
    assertValidDatabaseConformanceRun(run)
    await exclusiveWrite(join(staging, MANIFEST_FILE), manifestContent)
    await exclusiveWrite(join(staging, RUN_FILE), stableJson(run))
    await mkdir(join(staging, 'results'), { recursive: false, mode: 0o700 })
    await rename(staging, target)
    return { directory: target, run }
  } catch (error) {
    await rm(staging, { recursive: true, force: true })
    throw error
  }
}

function safeArtifactPath(bundle, artifactPath) {
  const target = resolve(bundle, ...artifactPath.split('/'))
  if (!isInside(bundle, target)) {
    throw controllerError(
      'DATABASE_CONFORMANCE_ARTIFACT_PATH_ESCAPE',
      `artifact path escapes the bundle: ${JSON.stringify(artifactPath)}`,
    )
  }
  return target
}

async function readBoundedNoFollow(path, maxBytes, label) {
  const info = await lstat(path)
  if (!info.isFile() || info.isSymbolicLink()) {
    throw controllerError(
      'DATABASE_CONFORMANCE_ARTIFACT_NOT_REGULAR',
      `${label} must be a regular non-symlink file`,
    )
  }
  if (info.size > maxBytes) {
    throw controllerError(
      'DATABASE_CONFORMANCE_ARTIFACT_TOO_LARGE',
      `${label} exceeds its ${maxBytes}-byte limit`,
    )
  }
  const handle = await open(path, OPEN_READ_ONLY_NO_FOLLOW)
  try {
    const before = await handle.stat()
    const content = await handle.readFile()
    const after = await handle.stat()
    if (
      before.size !== after.size
      || before.mtimeMs !== after.mtimeMs
      || before.ino !== after.ino
      || content.length !== after.size
    ) {
      throw controllerError(
        'DATABASE_CONFORMANCE_ARTIFACT_CHANGED',
        `${label} changed while it was being read`,
      )
    }
    return content
  } finally {
    await handle.close()
  }
}

function resolveBundle(argument) {
  const value = resolve(argument)
  return basename(value).toLowerCase() === RUN_FILE
    ? { directory: dirname(value), runPath: value }
    : { directory: value, runPath: join(value, RUN_FILE) }
}

async function loadRun(argument) {
  const bundle = resolveBundle(argument)
  const realDirectory = await realpath(bundle.directory)
  const directoryInfo = await lstat(realDirectory)
  if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()) {
    throw controllerError(
      'DATABASE_CONFORMANCE_BUNDLE_UNSAFE',
      'database conformance bundle must be a real directory',
    )
  }
  const runBytes = await readBoundedNoFollow(
    join(realDirectory, RUN_FILE),
    MAX_RUN_BYTES,
    RUN_FILE,
  )
  let run
  try {
    run = JSON.parse(runBytes.toString('utf8'))
  } catch (error) {
    throw controllerError(
      'DATABASE_CONFORMANCE_RUN_JSON_INVALID',
      'database conformance run.json is invalid JSON',
      { cause: error },
    )
  }
  assertValidDatabaseConformanceRun(run)
  return {
    directory: realDirectory,
    runPath: join(realDirectory, RUN_FILE),
    sourceDigest: sha256(runBytes),
    run,
  }
}

async function verifyArtifact(bundle, artifact) {
  const path = safeArtifactPath(bundle, artifact.path)
  const bytes = await readBoundedNoFollow(
    path,
    Math.min(MAX_ARTIFACT_BYTES, Math.max(artifact.size, 1)),
    artifact.path,
  )
  if (bytes.length !== artifact.size || sha256(bytes) !== artifact.sha256) {
    throw controllerError(
      'DATABASE_CONFORMANCE_ARTIFACT_DIGEST_MISMATCH',
      `artifact ${artifact.path} does not match its committed size and SHA-256`,
    )
  }
  return bytes
}

async function verifyManifest(loaded) {
  const bytes = await verifyArtifact(loaded.directory, loaded.run.manifest)
  let manifest
  try {
    manifest = JSON.parse(bytes.toString('utf8'))
  } catch (error) {
    throw controllerError(
      'DATABASE_CONFORMANCE_MANIFEST_JSON_INVALID',
      'bundled database conformance manifest is invalid JSON',
      { cause: error },
    )
  }
  assertValidDatabaseConformanceManifest(manifest)
  if (stableJson(manifest, 0) !== stableJson(databaseConformanceManifest, 0)) {
    throw controllerError(
      'DATABASE_CONFORMANCE_MANIFEST_INSTALLATION_DRIFT',
      'bundled conformance manifest differs from the installed 0.7.0 manifest',
    )
  }
  return manifest
}

function resultPath(engineId) {
  return `results/${engineId}.json`
}

function deriveRunState(run) {
  if (run.results.some(({ state }) => state === 'FAILED')) return 'FAILED'
  if (
    run.gaps.length > 0
    || run.results.some(({ state }) => state === 'COMPLETE_WITH_GAPS')
  ) {
    return 'COMPLETE_WITH_GAPS'
  }
  return 'COMPLETE'
}

function markdownText(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('|', '&#124;')
    .replaceAll('\\', '&#92;')
    .replaceAll('`', '&#96;')
    .replaceAll('*', '&#42;')
    .replaceAll('_', '&#95;')
    .replaceAll('[', '&#91;')
    .replaceAll(']', '&#93;')
    .replaceAll(/\r?\n/g, '<br>')
}

function inlineCode(value) {
  return `\`${markdownText(value)}\``
}

export function renderDatabaseConformanceReport(run, results) {
  const lines = [
    '# Database Conformance Lab Report',
    '',
    `Run: ${inlineCode(run.run_id)}`,
    '',
    `Status: **${run.state}**`,
    '',
    'Assurance: **CONTROLLER_OBSERVED_DISPOSABLE_ENGINE_BEHAVIOR**',
    '',
    'This report records controller-observed behavior from synthetic data in',
    'digest-pinned disposable reference engines. It does not prove an audited',
    'repository, target deployment, managed-service variant, or production',
    'configuration.',
    '',
    '## Engines',
    '',
    '| Engine | Product/version | Result | Image | Cleanup |',
    '|---|---|---|---|---|',
  ]
  for (const result of results) {
    lines.push(
      `| ${markdownText(result.engine_id)} | ` +
      `${markdownText(result.server.product)} ${markdownText(result.server.version)} | ` +
      `${markdownText(result.state)} | ${inlineCode(result.backend.requested_image)} | ` +
      `${result.cleanup.container_absent ? 'verified absent' : 'not verified'} |`,
    )
  }
  lines.push('', '## Scenario matrix', '')
  lines.push('| Engine | Scenario | State | Adapter rules |')
  lines.push('|---|---|---|---|')
  for (const result of results) {
    for (const scenario of result.scenarios) {
      lines.push(
        `| ${markdownText(result.engine_id)} | ${markdownText(scenario.scenario_id)} | ` +
        `${markdownText(scenario.state)} | ` +
        `${scenario.adapter_rule_ids.map(inlineCode).join('<br>')} |`,
      )
    }
  }
  lines.push('', '## Gaps', '')
  if (run.gaps.length === 0) {
    lines.push('No controller-recorded conformance gaps.')
  } else {
    for (const gap of run.gaps) {
      lines.push(`- **${markdownText(gap.area)}:** ${markdownText(gap.reason)}`)
    }
  }
  lines.push(
    '',
    '## Non-claims',
    '',
    '- Reference-engine behavior is not target deployment proof.',
    '- Container execution is not a microVM isolation claim.',
    '- Single-node CDC and backup checks are not failover or disaster-recovery tests.',
    '- A passing adapter rule still requires target-specific version, principal, enforcement, and copy evidence.',
    '',
  )
  return lines.join('\n')
}

async function persistRun(loaded, run) {
  assertValidDatabaseConformanceRun(run)
  await atomicReplace(loaded.runPath, stableJson(run))
  loaded.run = run
  loaded.sourceDigest = sha256(stableJson(run))
}

async function finalizeRun(loaded, run, results, now) {
  const completedAt = timestamp(now)
  const stagedState = deriveRunState(run)
  const reportRun = {
    ...run,
    state: stagedState,
    completed_at: completedAt,
  }
  const report = renderDatabaseConformanceReport(reportRun, results)
  const reportArtifact = artifactDescriptor(REPORT_FILE, report)
  const artifacts = canonicalArtifacts([
    ...run.artifacts.filter(({ path }) => path !== REPORT_FILE),
    reportArtifact,
  ])
  const finalRun = {
    ...reportRun,
    artifacts,
    root_sha256: artifactRoot(artifacts),
  }
  assertValidDatabaseConformanceRun(finalRun)
  await exclusiveWrite(join(loaded.directory, REPORT_FILE), report)
  await persistRun(loaded, finalRun)
  return finalRun
}

async function abortRun(loaded, run, error, results, now) {
  const completedAt = timestamp(now)
  const gap = {
    area: 'conformance execution',
    reason: `${error.code ?? 'DATABASE_CONFORMANCE_EXECUTION_FAILED'}: ${error.message}`,
  }
  const reportRun = {
    ...run,
    state: 'ABORTED',
    completed_at: completedAt,
    gaps: [...run.gaps, gap],
  }
  const report = renderDatabaseConformanceReport(reportRun, results)
  const reportArtifact = artifactDescriptor(REPORT_FILE, report)
  const artifacts = canonicalArtifacts([
    ...run.artifacts.filter(({ path }) => path !== REPORT_FILE),
    reportArtifact,
  ])
  const finalRun = {
    ...reportRun,
    artifacts,
    root_sha256: artifactRoot(artifacts),
  }
  assertValidDatabaseConformanceRun(finalRun)
  const reportPath = join(loaded.directory, REPORT_FILE)
  try {
    await exclusiveWrite(reportPath, report)
  } catch (writeError) {
    if (writeError.code !== 'EEXIST') throw writeError
    await atomicReplace(reportPath, report)
  }
  await persistRun(loaded, finalRun)
  throw controllerError(
    'DATABASE_CONFORMANCE_RUN_ABORTED',
    `database conformance run aborted: ${error.message}`,
    {
      cause: error,
      bundle: loaded.directory,
      details: error.details,
    },
  )
}

export async function runDatabaseConformanceBundle({
  bundle,
  config,
  now = () => new Date(),
  spawnImpl,
  randomBytesImpl = randomBytes,
  runEngineImpl = runDatabaseConformanceEngine,
  executeScenarios = executeDatabaseConformanceScenarios,
}) {
  assertValidDatabaseConformanceConfig(config)
  const located = await loadRun(bundle)
  const lock = await acquireRunLock(located.directory, now)
  try {
  const loaded = await loadRun(located.directory)
  await verifyManifest(loaded)
  if (!['PLANNED', 'RUNNING'].includes(loaded.run.state)) {
    throw controllerError(
      'DATABASE_CONFORMANCE_RUN_NOT_EXECUTABLE',
      `database conformance run is already ${loaded.run.state}`,
    )
  }
  const configured = normalizeEngineIds(
    config.engine_ids ?? loaded.run.requested_engine_ids,
  )
  if (
    stableJson(configured, 0)
    !== stableJson(loaded.run.requested_engine_ids, 0)
  ) {
    throw controllerError(
      'DATABASE_CONFORMANCE_CONFIG_ENGINE_MISMATCH',
      'trusted configuration engine_ids must exactly match the planned engine set',
    )
  }
  const results = []
  let run = {
    ...loaded.run,
    state: 'RUNNING',
    started_at: loaded.run.started_at ?? timestamp(now),
  }
  await persistRun(loaded, run)

  try {
    for (const engineId of run.requested_engine_ids) {
      const existing = run.results.find(({ engine_id: id }) => id === engineId)
      if (existing) {
        const bytes = await verifyArtifact(loaded.directory, existing.artifact)
        const result = JSON.parse(bytes.toString('utf8'))
        assertValidDatabaseConformanceResult(result)
        results.push(result)
        continue
      }
      const result = await runEngineImpl({
        runId: run.run_id,
        engineId,
        config,
        executeScenarios,
        spawnImpl,
        now,
        randomBytesImpl,
      })
      const path = resultPath(engineId)
      const content = stableJson(result)
      const descriptor = artifactDescriptor(path, content)
      await exclusiveWrite(join(loaded.directory, ...path.split('/')), content)
      results.push(result)
      run = {
        ...run,
        results: [
          ...run.results,
          {
            engine_id: engineId,
            state: result.state,
            artifact: descriptor,
          },
        ],
        artifacts: canonicalArtifacts([...run.artifacts, descriptor]),
        gaps: [
          ...run.gaps,
          ...result.gaps.map((gap) => ({
            area: `engine:${engineId}:${gap.area}`,
            reason: gap.reason,
          })),
        ],
      }
      await persistRun(loaded, run)
    }
    return await finalizeRun(loaded, run, results, now)
  } catch (error) {
    return await abortRun(loaded, run, error, results, now)
  }
  } finally {
    await releaseRunLock(lock)
  }
}

export async function validateDatabaseConformanceBundle(argument) {
  const errors = []
  let loaded
  try {
    loaded = await loadRun(argument)
    await verifyManifest(loaded)
    const paths = loaded.run.artifacts.map(({ path }) => path)
    if (new Set(paths).size !== paths.length) {
      throw controllerError(
        'DATABASE_CONFORMANCE_DUPLICATE_ARTIFACT_PATH',
        'run artifacts contain duplicate paths',
      )
    }
    for (const artifact of loaded.run.artifacts) {
      await verifyArtifact(loaded.directory, artifact)
    }
    if (
      loaded.run.root_sha256
      && loaded.run.root_sha256 !== artifactRoot(loaded.run.artifacts)
    ) {
      throw controllerError(
        'DATABASE_CONFORMANCE_ROOT_DIGEST_MISMATCH',
        'run root_sha256 does not match the canonical artifact manifest',
      )
    }
    for (const summary of loaded.run.results) {
      const bytes = await verifyArtifact(loaded.directory, summary.artifact)
      const result = JSON.parse(bytes.toString('utf8'))
      assertValidDatabaseConformanceResult(result)
      if (
        result.run_id !== loaded.run.run_id
        || result.engine_id !== summary.engine_id
        || result.state !== summary.state
      ) {
        throw controllerError(
          'DATABASE_CONFORMANCE_RESULT_SUMMARY_MISMATCH',
          `result ${summary.artifact.path} does not match its run summary`,
        )
      }
    }
  } catch (error) {
    errors.push({
      code: error.code ?? 'DATABASE_CONFORMANCE_VALIDATION_FAILED',
      message: error.message,
      details: error.details,
    })
  }
  return {
    valid: errors.length === 0,
    errors,
    path: loaded?.runPath ?? resolve(argument),
    root_authenticity: {
      status: 'UNANCHORED',
      message: 'conformance artifacts are valid only relative to their unsigned local run manifest',
    },
  }
}

export async function loadDatabaseConformanceEvidence(argument) {
  const validation = await validateDatabaseConformanceBundle(argument)
  if (!validation.valid) {
    throw controllerError(
      'DATABASE_CONFORMANCE_EVIDENCE_INVALID',
      'database conformance evidence source did not validate',
      { details: validation.errors },
    )
  }
  const loaded = await loadRun(argument)
  if (loaded.run.state !== 'COMPLETE') {
    throw controllerError(
      'DATABASE_CONFORMANCE_EVIDENCE_INCOMPLETE',
      `only a COMPLETE two-engine conformance run may be attached; observed ${loaded.run.state}`,
    )
  }
  const engines = []
  for (const summary of loaded.run.results) {
    const bytes = await verifyArtifact(loaded.directory, summary.artifact)
    const result = JSON.parse(bytes.toString('utf8'))
    assertValidDatabaseConformanceResult(result)
    engines.push({
      engine_id: result.engine_id,
      adapter_id: result.adapter_id,
      product: result.server.product,
      server_version: result.server.version,
      requested_image: result.backend.requested_image,
      image_id: result.backend.image_id,
      result_sha256: summary.artifact.sha256,
      state: result.state,
      scenarios: result.scenarios.map((scenario) => ({
        scenario_id: scenario.scenario_id,
        state: scenario.state,
        adapter_rule_ids: [...scenario.adapter_rule_ids],
      })),
    })
  }
  engines.sort((left, right) =>
    compareCanonicalStrings(left.engine_id, right.engine_id))
  return assertValidDatabaseConformanceEvidence({
    schema_version: '1.0.0',
    kind: 'red-team-audit/database-conformance-evidence',
    assurance_scope: 'CONTROLLER_OBSERVED_DISPOSABLE_ENGINE_BEHAVIOR',
    target_deployment_proven: false,
    root_authenticity: 'UNANCHORED',
    source: {
      run_id: loaded.run.run_id,
      state: loaded.run.state,
      root_sha256: loaded.run.root_sha256,
      created_at: loaded.run.created_at,
      completed_at: loaded.run.completed_at,
    },
    engines,
  })
}

export async function databaseConformanceReportPath(argument) {
  const loaded = await loadRun(argument)
  const artifact = loaded.run.artifacts.find(({ path }) => path === REPORT_FILE)
  if (!artifact) {
    throw controllerError(
      'DATABASE_CONFORMANCE_REPORT_NOT_AVAILABLE',
      'database conformance report has not been generated',
    )
  }
  await verifyArtifact(loaded.directory, artifact)
  return join(loaded.directory, REPORT_FILE)
}
