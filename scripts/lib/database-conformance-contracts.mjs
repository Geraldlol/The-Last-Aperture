import { isDeepStrictEqual } from 'node:util'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { posix, win32 } from 'node:path'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import { getDatabaseAdapterRuleIds } from './database-adapters.mjs'
import { compareCanonicalStrings } from './canonical-order.mjs'

const SCHEMA_URLS = {
  manifest: new URL('../../schemas/database-conformance-manifest.schema.json', import.meta.url),
  config: new URL('../../schemas/database-conformance-config.schema.json', import.meta.url),
  result: new URL('../../schemas/database-conformance-result.schema.json', import.meta.url),
  run: new URL('../../schemas/database-conformance-run.schema.json', import.meta.url),
  evidence: new URL('../../schemas/database-conformance-evidence.schema.json', import.meta.url),
}

export const DATABASE_CONFORMANCE_MANIFEST_URL = new URL(
  '../../database-conformance/manifest.json',
  import.meta.url,
)

function loadJson(url) {
  return JSON.parse(readFileSync(fileURLToPath(url), 'utf8'))
}

export const databaseConformanceManifestSchema = loadJson(SCHEMA_URLS.manifest)
export const databaseConformanceConfigSchema = loadJson(SCHEMA_URLS.config)
export const databaseConformanceResultSchema = loadJson(SCHEMA_URLS.result)
export const databaseConformanceRunSchema = loadJson(SCHEMA_URLS.run)
export const databaseConformanceEvidenceSchema = loadJson(SCHEMA_URLS.evidence)

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})

for (const schema of [
  databaseConformanceManifestSchema,
  databaseConformanceConfigSchema,
  databaseConformanceResultSchema,
  databaseConformanceRunSchema,
  databaseConformanceEvidenceSchema,
]) {
  ajv.addSchema(schema)
}

const validators = Object.fromEntries(
  Object.entries({
    manifest: databaseConformanceManifestSchema,
    config: databaseConformanceConfigSchema,
    result: databaseConformanceResultSchema,
    run: databaseConformanceRunSchema,
    evidence: databaseConformanceEvidenceSchema,
  }).map(([key, schema]) => [key, ajv.getSchema(schema.$id)]),
)

export class DatabaseConformanceContractError extends Error {
  constructor(message, details = []) {
    super(message)
    this.name = 'DatabaseConformanceContractError'
    this.code = 'DATABASE_CONFORMANCE_CONTRACT_INVALID'
    this.details = details
  }
}

function normalizeAjvErrors(errors = []) {
  return errors.map((error) => ({
    keyword: error.keyword,
    code: `SCHEMA_${String(error.keyword).toUpperCase()}`,
    instancePath: error.instancePath || '/',
    message: error.message ?? 'schema validation failed',
    params: error.params,
  }))
}

function semanticError(code, instancePath, message, params = {}) {
  return {
    keyword: 'contract',
    code,
    instancePath,
    message,
    params,
  }
}

function unique(values) {
  return new Set(values).size === values.length
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function transcriptMaterial(transcript) {
  return JSON.stringify(transcript.map(({ code, stderr, stdout, step }) => ({
    code,
    stderr,
    stdout,
    step,
  })))
}

function sameStringSet(left, right) {
  return isDeepStrictEqual(
    [...new Set(left)].sort(compareCanonicalStrings),
    [...new Set(right)].sort(compareCanonicalStrings),
  )
}

function scenarioIds(manifest) {
  return (manifest?.scenarios ?? []).map(({ scenario_id: scenarioId }) => scenarioId)
}

function manifestSemanticErrors(manifest) {
  const errors = []
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) return errors
  const expectedScenarios = [
    'backup',
    'cdc-and-history',
    'direct-table-bypass',
    'export',
    'migration-runtime-role-separation',
    'pooled-session-reset',
    'two-tenant-authorization',
    'views-and-stored-code',
  ]
  const actualScenarios = scenarioIds(manifest)
  if (!unique(actualScenarios) || !sameStringSet(actualScenarios, expectedScenarios)) {
    errors.push(semanticError(
      'DATABASE_CONFORMANCE_SCENARIO_CATALOG_DRIFT',
      '/scenarios',
      'the manifest must contain each of the eight required scenarios exactly once',
    ))
  }

  const engines = manifest.engines ?? []
  const engineIds = engines.map(({ engine_id: engineId }) => engineId)
  const adapterIds = engines.map(({ adapter_id: adapterId }) => adapterId)
  if (!unique(engineIds)) {
    errors.push(semanticError(
      'DATABASE_CONFORMANCE_DUPLICATE_ENGINE',
      '/engines',
      'engine_id values must be unique',
    ))
  }
  if (!sameStringSet(adapterIds, ['postgresql', 'mysql'])) {
    errors.push(semanticError(
      'DATABASE_CONFORMANCE_ENGINE_PAIR_DRIFT',
      '/engines',
      'the v1 lab must contain the PostgreSQL and MySQL adapters',
    ))
  }

  for (const [engineIndex, engine] of engines.entries()) {
    const pointer = `/engines/${engineIndex}`
    const rules = engine.scenario_rules ?? []
    const boundIds = rules.map(({ scenario_id: scenarioId }) => scenarioId)
    if (!unique(boundIds) || !sameStringSet(boundIds, actualScenarios)) {
      errors.push(semanticError(
        'DATABASE_CONFORMANCE_ENGINE_SCENARIO_DRIFT',
        `${pointer}/scenario_rules`,
        'each engine must bind every manifest scenario exactly once',
      ))
    }
    const knownRules = new Set(getDatabaseAdapterRuleIds(engine.adapter_id))
    for (const [ruleSetIndex, ruleSet] of rules.entries()) {
      for (const [ruleIndex, ruleId] of (ruleSet.adapter_rule_ids ?? []).entries()) {
        if (!knownRules.has(ruleId)) {
          errors.push(semanticError(
            'DATABASE_CONFORMANCE_UNKNOWN_ADAPTER_RULE',
            `${pointer}/scenario_rules/${ruleSetIndex}/adapter_rule_ids/${ruleIndex}`,
            `rule ${JSON.stringify(ruleId)} is absent from adapter ${engine.adapter_id}`,
          ))
        }
      }
    }
    try {
      new RegExp(engine.expected_server_version_pattern)
    } catch {
      errors.push(semanticError(
        'DATABASE_CONFORMANCE_VERSION_PATTERN_INVALID',
        `${pointer}/expected_server_version_pattern`,
        'expected_server_version_pattern must compile as a JavaScript regular expression',
      ))
    }
  }
  return errors
}

export const databaseConformanceManifest = Object.freeze(loadJson(
  DATABASE_CONFORMANCE_MANIFEST_URL,
))

function configSemanticErrors(config, manifest = databaseConformanceManifest) {
  const errors = []
  if (!config || typeof config !== 'object' || Array.isArray(config)) return errors
  if (
    typeof config.runtime_path === 'string'
    && !(posix.isAbsolute(config.runtime_path) || win32.isAbsolute(config.runtime_path))
  ) {
    errors.push(semanticError(
      'DATABASE_CONFORMANCE_RUNTIME_NOT_ABSOLUTE',
      '/runtime_path',
      'runtime_path must be an absolute POSIX, drive-qualified Windows, or UNC path',
    ))
  }
  const allowed = new Set((manifest.engines ?? []).map(({ engine_id: id }) => id))
  for (const [index, engineId] of (config.engine_ids ?? []).entries()) {
    if (!allowed.has(engineId)) {
      errors.push(semanticError(
        'DATABASE_CONFORMANCE_ENGINE_NOT_PLANNED',
        `/engine_ids/${index}`,
        `engine ${JSON.stringify(engineId)} is absent from the controller manifest`,
      ))
    }
  }
  const limits = config.limits
  if (limits && typeof limits === 'object' && !Array.isArray(limits)) {
    for (const key of ['docker_command_timeout_ms', 'startup_timeout_ms']) {
      if (
        Number.isSafeInteger(limits[key])
        && Number.isSafeInteger(limits.wall_time_ms)
        && limits[key] > limits.wall_time_ms
      ) {
        errors.push(semanticError(
          'DATABASE_CONFORMANCE_TIMEOUT_EXCEEDS_WALL',
          `/limits/${key}`,
          `${key} cannot exceed wall_time_ms`,
        ))
      }
    }
    if (
      Number.isSafeInteger(limits.tmpfs_bytes)
      && Number.isSafeInteger(limits.memory_bytes)
      && limits.tmpfs_bytes > limits.memory_bytes
    ) {
      errors.push(semanticError(
        'DATABASE_CONFORMANCE_TMPFS_EXCEEDS_MEMORY',
        '/limits/tmpfs_bytes',
        'tmpfs_bytes cannot exceed memory_bytes',
      ))
    }
  }
  return errors
}

function resultSemanticErrors(result, manifest = databaseConformanceManifest) {
  const errors = []
  if (!result || typeof result !== 'object' || Array.isArray(result)) return errors
  const engine = (manifest.engines ?? []).find(
    ({ engine_id: engineId }) => engineId === result.engine_id,
  )
  if (!engine) {
    errors.push(semanticError(
      'DATABASE_CONFORMANCE_RESULT_ENGINE_UNKNOWN',
      '/engine_id',
      'result engine_id is absent from the manifest',
    ))
    return errors
  }
  if (result.adapter_id !== engine.adapter_id) {
    errors.push(semanticError(
      'DATABASE_CONFORMANCE_RESULT_ADAPTER_MISMATCH',
      '/adapter_id',
      'result adapter_id does not match its manifest engine',
    ))
  }
  if (result.backend?.requested_image !== engine.image) {
    errors.push(semanticError(
      'DATABASE_CONFORMANCE_RESULT_IMAGE_MISMATCH',
      '/backend/requested_image',
      'result requested_image does not match the digest-pinned manifest image',
    ))
  }
  if (result.server?.product !== engine.product) {
    errors.push(semanticError(
      'DATABASE_CONFORMANCE_RESULT_PRODUCT_MISMATCH',
      '/server/product',
      'result server product does not match the manifest engine',
    ))
  }
  if (
    typeof result.server?.version === 'string'
    && !new RegExp(engine.expected_server_version_pattern).test(result.server.version)
  ) {
    errors.push(semanticError(
      'DATABASE_CONFORMANCE_SERVER_VERSION_DRIFT',
      '/server/version',
      'observed server version does not match the manifest version gate',
    ))
  }
  if (
    Array.isArray(result.transcript)
    && typeof result.transcript_sha256 === 'string'
    && sha256(Buffer.from(transcriptMaterial(result.transcript), 'utf8'))
      !== result.transcript_sha256
  ) {
    errors.push(semanticError(
      'DATABASE_CONFORMANCE_TRANSCRIPT_DIGEST_MISMATCH',
      '/transcript_sha256',
      'transcript_sha256 must commit to the exact transcript entries',
    ))
  }

  const expectedByScenario = new Map(
    engine.scenario_rules.map((rule) => [rule.scenario_id, rule.adapter_rule_ids]),
  )
  const actualIds = (result.scenarios ?? []).map(({ scenario_id: scenarioId }) => scenarioId)
  if (!unique(actualIds) || !sameStringSet(actualIds, [...expectedByScenario.keys()])) {
    errors.push(semanticError(
      'DATABASE_CONFORMANCE_RESULT_SCENARIO_DRIFT',
      '/scenarios',
      'result must contain every engine scenario exactly once',
    ))
  }
  for (const [index, scenario] of (result.scenarios ?? []).entries()) {
    const expectedRules = expectedByScenario.get(scenario.scenario_id)
    if (expectedRules && !sameStringSet(scenario.adapter_rule_ids ?? [], expectedRules)) {
      errors.push(semanticError(
        'DATABASE_CONFORMANCE_RESULT_RULE_DRIFT',
        `/scenarios/${index}/adapter_rule_ids`,
        'result adapter rules must exactly match the manifest scenario binding',
      ))
    }
    const checkStates = (scenario.checks ?? []).map(({ state }) => state)
    const expectedState = checkStates.includes('FAILED')
      ? 'FAILED'
      : checkStates.includes('NOT_ASSESSED')
        ? 'NOT_ASSESSED'
        : 'PASSED'
    if (scenario.state !== expectedState) {
      errors.push(semanticError(
        'DATABASE_CONFORMANCE_SCENARIO_STATE_MISMATCH',
        `/scenarios/${index}/state`,
        'scenario state must be derived from its checks',
      ))
    }
  }
  const scenarioStates = (result.scenarios ?? []).map(({ state }) => state)
  const expectedResultState = scenarioStates.includes('FAILED')
    || result.cleanup?.container_absent === false
    ? 'FAILED'
    : scenarioStates.includes('NOT_ASSESSED') || (result.gaps ?? []).length > 0
      ? 'COMPLETE_WITH_GAPS'
      : 'PASSED'
  if (result.state !== expectedResultState) {
    errors.push(semanticError(
      'DATABASE_CONFORMANCE_RESULT_STATE_MISMATCH',
      '/state',
      'result state must reflect scenario states, gaps, and verified cleanup',
    ))
  }
  const started = Date.parse(result.started_at)
  const completed = Date.parse(result.completed_at)
  if (Number.isFinite(started) && Number.isFinite(completed) && completed < started) {
    errors.push(semanticError(
      'DATABASE_CONFORMANCE_TIME_REVERSED',
      '/completed_at',
      'completed_at cannot precede started_at',
    ))
  }
  return errors
}

function runSemanticErrors(run, manifest = databaseConformanceManifest) {
  const errors = []
  if (!run || typeof run !== 'object' || Array.isArray(run)) return errors
  const requested = run.requested_engine_ids ?? []
  const resultIds = (run.results ?? []).map(({ engine_id: engineId }) => engineId)
  if (!unique(resultIds) || resultIds.some((engineId) => !requested.includes(engineId))) {
    errors.push(semanticError(
      'DATABASE_CONFORMANCE_RUN_RESULT_BINDING_INVALID',
      '/results',
      'results must be unique and bind only requested engines',
    ))
  }
  const terminal = ['COMPLETE', 'COMPLETE_WITH_GAPS', 'FAILED', 'ABORTED'].includes(run.state)
  if (terminal && (!run.completed_at || !run.root_sha256)) {
    errors.push(semanticError(
      'DATABASE_CONFORMANCE_TERMINAL_METADATA_MISSING',
      '/',
      'a terminal run requires completed_at and root_sha256',
    ))
  }
  if (run.state === 'COMPLETE') {
    if (
      !sameStringSet(resultIds, requested)
      || run.results.some(({ state }) => state !== 'PASSED')
      || (run.gaps ?? []).length > 0
    ) {
      errors.push(semanticError(
        'DATABASE_CONFORMANCE_COMPLETE_OVERCLAIM',
        '/state',
        'COMPLETE requires one passing result per requested engine and no gaps',
      ))
    }
  }
  if (run.state === 'COMPLETE_WITH_GAPS') {
    if (
      !sameStringSet(resultIds, requested)
      || run.results.some(({ state }) => state === 'FAILED')
      || (run.gaps ?? []).length === 0
    ) {
      errors.push(semanticError(
        'DATABASE_CONFORMANCE_GAPPED_STATE_INVALID',
        '/state',
        'COMPLETE_WITH_GAPS requires all requested results, no failed result, and a gap',
      ))
    }
  }
  if (run.state === 'FAILED' && !run.results.some(({ state }) => state === 'FAILED')) {
    errors.push(semanticError(
      'DATABASE_CONFORMANCE_FAILED_WITHOUT_RESULT',
      '/state',
      'FAILED requires at least one failed engine result',
    ))
  }
  return errors
}

function evidenceSemanticErrors(evidence, manifest = databaseConformanceManifest) {
  const errors = []
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) {
    return errors
  }
  const expectedEngineIds = manifest.engines.map(
    ({ engine_id: engineId }) => engineId,
  )
  const actualEngineIds = (evidence.engines ?? []).map(
    ({ engine_id: engineId }) => engineId,
  )
  if (
    !unique(actualEngineIds)
    || !sameStringSet(actualEngineIds, expectedEngineIds)
  ) {
    errors.push(semanticError(
      'DATABASE_CONFORMANCE_EVIDENCE_ENGINE_DRIFT',
      '/engines',
      'evidence must contain each installed reference engine exactly once',
    ))
  }
  for (const [engineIndex, engineEvidence] of (evidence.engines ?? []).entries()) {
    const engine = manifest.engines.find(
      ({ engine_id: engineId }) => engineId === engineEvidence.engine_id,
    )
    if (!engine) continue
    if (
      engineEvidence.adapter_id !== engine.adapter_id
      || engineEvidence.product !== engine.product
      || engineEvidence.requested_image !== engine.image
      || !new RegExp(engine.expected_server_version_pattern)
        .test(engineEvidence.server_version ?? '')
    ) {
      errors.push(semanticError(
        'DATABASE_CONFORMANCE_EVIDENCE_IDENTITY_DRIFT',
        `/engines/${engineIndex}`,
        'evidence engine identity does not match the installed manifest',
      ))
    }
    const expectedRules = new Map(engine.scenario_rules.map((binding) => [
      binding.scenario_id,
      binding.adapter_rule_ids,
    ]))
    const scenarioIds = (engineEvidence.scenarios ?? []).map(
      ({ scenario_id: scenarioId }) => scenarioId,
    )
    if (
      !unique(scenarioIds)
      || !sameStringSet(scenarioIds, [...expectedRules.keys()])
    ) {
      errors.push(semanticError(
        'DATABASE_CONFORMANCE_EVIDENCE_SCENARIO_DRIFT',
        `/engines/${engineIndex}/scenarios`,
        'evidence must retain every manifest scenario exactly once',
      ))
    }
    for (const [scenarioIndex, scenario] of
      (engineEvidence.scenarios ?? []).entries()) {
      const rules = expectedRules.get(scenario.scenario_id)
      if (rules && !sameStringSet(scenario.adapter_rule_ids ?? [], rules)) {
        errors.push(semanticError(
          'DATABASE_CONFORMANCE_EVIDENCE_RULE_DRIFT',
          `/engines/${engineIndex}/scenarios/${scenarioIndex}/adapter_rule_ids`,
          'evidence adapter rules must exactly match the manifest binding',
        ))
      }
    }
  }
  return errors
}

function validateWith(kind, value, semanticErrors) {
  const validSchema = validators[kind](value)
  const errors = [
    ...(validSchema ? [] : normalizeAjvErrors(validators[kind].errors)),
    ...semanticErrors(value),
  ]
  return { valid: errors.length === 0, errors }
}

export function validateDatabaseConformanceManifest(value) {
  return validateWith('manifest', value, manifestSemanticErrors)
}

export function validateDatabaseConformanceConfig(value) {
  return validateWith('config', value, configSemanticErrors)
}

export function validateDatabaseConformanceResult(value) {
  return validateWith('result', value, resultSemanticErrors)
}

export function validateDatabaseConformanceRun(value) {
  return validateWith('run', value, runSemanticErrors)
}

export function validateDatabaseConformanceEvidence(value) {
  return validateWith('evidence', value, evidenceSemanticErrors)
}

function assertValidation(label, value, validate) {
  const validation = validate(value)
  if (!validation.valid) {
    throw new DatabaseConformanceContractError(
      `${label} validation failed`,
      validation.errors,
    )
  }
  return value
}

export function assertValidDatabaseConformanceManifest(value) {
  return assertValidation(
    'database conformance manifest',
    value,
    validateDatabaseConformanceManifest,
  )
}

export function assertValidDatabaseConformanceConfig(value) {
  return assertValidation(
    'database conformance configuration',
    value,
    validateDatabaseConformanceConfig,
  )
}

export function assertValidDatabaseConformanceResult(value) {
  return assertValidation(
    'database conformance result',
    value,
    validateDatabaseConformanceResult,
  )
}

export function assertValidDatabaseConformanceRun(value) {
  return assertValidation(
    'database conformance run',
    value,
    validateDatabaseConformanceRun,
  )
}

export function assertValidDatabaseConformanceEvidence(value) {
  return assertValidation(
    'database conformance evidence',
    value,
    validateDatabaseConformanceEvidence,
  )
}

assertValidDatabaseConformanceManifest(databaseConformanceManifest)
