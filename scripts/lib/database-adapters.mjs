import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

export const DATABASE_ADAPTER_MANIFEST_URL = new URL(
  '../../skills/red-team-audit/lenses/_database-adapters/manifest.json',
  import.meta.url,
)

const IDENTIFIER_PATTERN = /^[a-z0-9][a-z0-9-]*$/
const ADAPTER_FILE_PATTERN = /^[a-z0-9][a-z0-9-]*\.md$/
const HOSTNAME_PATTERN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
const UNRESOLVED_PROFILE_VALUES = new Set([
  '*',
  'any',
  'auto',
  'automatic',
  'current',
  'default',
  'latest',
  'managed',
  'n-a',
  'na',
  'none',
  'not-applicable',
  'not-available',
  'not-determined',
  'not-known',
  'not-provided',
  'not-set',
  'not-specified',
  'null',
  'pending',
  'placeholder',
  'redacted',
  'tbd',
  'to-be-confirmed',
  'to-be-determined',
  'to-be-resolved',
  'todo',
  'undetermined',
  'unavailable',
  'unknown',
  'unresolved',
  'unset',
  'unspecified',
])
const UNRESOLVED_PROFILE_TOKENS = new Set([
  'any',
  'auto',
  'automatic',
  'current',
  'default',
  'latest',
  'none',
  'null',
  'pending',
  'tbd',
  'undetermined',
  'unknown',
  'unresolved',
  'unspecified',
])
const UNRESOLVED_PROFILE_PHRASES = Object.freeze([
  'n-a',
  'na',
  'not-applicable',
  'not-available',
  'not-determined',
  'not-known',
  'not-provided',
  'not-set',
  'not-specified',
  'not-sure',
  'to-be-confirmed',
  'to-be-determined',
  'to-be-resolved',
])
const ENGINE_VERSION_PATTERN = /^(?=.{1,128}$)(?=.*[0-9])[A-Za-z0-9][A-Za-z0-9._+:/ -]*$/
const PROFILE_KEYS = new Set([
  'store_id',
  'family',
  'engine',
  'engine_version',
  'deployment_variant',
  'adapter_id',
  'detection_evidence',
  'confidence',
])
const SEMANTIC_KEYS = new Set([
  'adapter_id',
  'semantic_sensitivity',
  'adapter_rule_id',
  'semantic_source',
])
const SEMANTIC_SOURCE_KEYS = new Set(['url', 'verified_on'])

export class DatabaseAdapterManifestError extends Error {
  constructor(errors) {
    super(`Invalid database adapter manifest:\n- ${errors.join('\n- ')}`)
    this.name = 'DatabaseAdapterManifestError'
    this.errors = Object.freeze([...errors])
  }
}

function isPlainObject(value) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype
      || Object.getPrototypeOf(value) === null)
}

function isNonEmptyString(value) {
  return typeof value === 'string' && /\S/.test(value)
}

function isCanonicalIdentifier(value) {
  return typeof value === 'string' && IDENTIFIER_PATTERN.test(value)
}

function normalizedProfileSentinel(value) {
  return typeof value === 'string'
    ? value.trim().toLowerCase().replace(/[^a-z0-9*]+/g, '-').replace(/^-|-$/g, '')
    : ''
}

export function isUnresolvedDatabaseDescriptor(value) {
  const normalized = normalizedProfileSentinel(value)
  if (!normalized || UNRESOLVED_PROFILE_VALUES.has(normalized)) return true
  if (normalized.split('-').some((token) => UNRESOLVED_PROFILE_TOKENS.has(token))) {
    return true
  }
  const bounded = `-${normalized}-`
  return UNRESOLVED_PROFILE_PHRASES.some((phrase) =>
    bounded.includes(`-${phrase}-`))
}

function isDefensibleEngineVersion(value) {
  return isNonEmptyString(value)
    && ENGINE_VERSION_PATTERN.test(value.trim())
    && !isUnresolvedDatabaseDescriptor(value)
}

function isRealIsoDate(value) {
  if (typeof value !== 'string'
    || !/^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])$/.test(value)) {
    return false
  }
  const [year, month, day] = value.split('-').map(Number)
  const date = new Date(Date.UTC(year, month - 1, day))
  return date.getUTCFullYear() === year
    && date.getUTCMonth() === month - 1
    && date.getUTCDate() === day
}

function deepFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const child of Object.values(value)) deepFreeze(child)
  return Object.freeze(value)
}

function unexpectedKeys(value, allowed) {
  if (!isPlainObject(value)) return []
  return Object.keys(value).filter((key) => !allowed.has(key)).sort()
}

function addUnexpectedKeyErrors(errors, value, allowed, path) {
  for (const key of unexpectedKeys(value, allowed)) {
    errors.push(`${path} contains unsupported field ${JSON.stringify(key)}`)
  }
}

const TOP_LEVEL_KEYS = new Set([
  'schema_version',
  'manifest_id',
  'verified_on',
  'routing_policy',
  'fallback',
  'semantic_metadata',
  'adapters',
])
const ROUTING_POLICY_KEYS = new Set([
  'minimum_confidence',
  'unknown_value',
  'require_engine_version',
  'require_deployment_variant',
  'require_detection_evidence',
])
const FALLBACK_KEYS = new Set([
  'adapter_id',
  'adapter_file',
  'selection_status',
  'coverage_state',
  'verification_status',
  'effective_severity_cap',
  'can_clear',
  'can_confirm',
])
const SEMANTIC_MANIFEST_KEYS = new Set([
  'sensitivity_values',
  'required_for',
  'rule_id_pattern',
  'source_protocol',
  'source_verified_on_required',
])
const ADAPTER_KEYS = new Set([
  'adapter_id',
  'engine',
  'engine_aliases',
  'adapter_file',
  'semantic_source_hosts',
  'deployment_variants',
])
const VARIANT_KEYS = new Set(['id', 'aliases'])

export function validateDatabaseAdapterManifest(manifest) {
  const errors = []
  if (!isPlainObject(manifest)) return { valid: false, errors: ['manifest must be an object'] }

  addUnexpectedKeyErrors(errors, manifest, TOP_LEVEL_KEYS, 'manifest')

  if (manifest.schema_version !== '1.0.0') {
    errors.push('schema_version must be "1.0.0"')
  }
  if (manifest.manifest_id !== 'database-adapter-routing') {
    errors.push('manifest_id must be "database-adapter-routing"')
  }
  if (!isRealIsoDate(manifest.verified_on)) {
    errors.push('verified_on must be a real YYYY-MM-DD date')
  }

  const policy = manifest.routing_policy
  if (!isPlainObject(policy)) {
    errors.push('routing_policy must be an object')
  } else {
    addUnexpectedKeyErrors(errors, policy, ROUTING_POLICY_KEYS, 'routing_policy')
    if (policy.minimum_confidence !== 'high') {
      errors.push('routing_policy.minimum_confidence must be "high"')
    }
    if (policy.unknown_value !== 'unknown') {
      errors.push('routing_policy.unknown_value must be "unknown"')
    }
    for (const field of [
      'require_engine_version',
      'require_deployment_variant',
      'require_detection_evidence',
    ]) {
      if (policy[field] !== true) errors.push(`routing_policy.${field} must be true`)
    }
  }

  const fallback = manifest.fallback
  const requiredFallback = {
    adapter_id: 'inventory-only',
    adapter_file: 'contract.md',
    selection_status: 'INVENTORY_ONLY',
    coverage_state: 'NOT_ASSESSED',
    verification_status: 'UNPROVEN',
    effective_severity_cap: 'Medium',
    can_clear: false,
    can_confirm: false,
  }
  if (!isPlainObject(fallback)) {
    errors.push('fallback must be an object')
  } else {
    addUnexpectedKeyErrors(errors, fallback, FALLBACK_KEYS, 'fallback')
    for (const [field, expected] of Object.entries(requiredFallback)) {
      if (fallback[field] !== expected) {
        errors.push(`fallback.${field} must be ${JSON.stringify(expected)}`)
      }
    }
  }

  const semantic = manifest.semantic_metadata
  if (!isPlainObject(semantic)) {
    errors.push('semantic_metadata must be an object')
  } else {
    addUnexpectedKeyErrors(errors, semantic, SEMANTIC_MANIFEST_KEYS, 'semantic_metadata')
    const expectedSensitivity = ['stable', 'version-sensitive', 'deployment-sensitive']
    if (JSON.stringify(semantic.sensitivity_values) !== JSON.stringify(expectedSensitivity)) {
      errors.push(`semantic_metadata.sensitivity_values must be ${JSON.stringify(expectedSensitivity)}`)
    }
    const expectedRequired = ['stable', 'version-sensitive', 'deployment-sensitive']
    if (JSON.stringify(semantic.required_for) !== JSON.stringify(expectedRequired)) {
      errors.push(`semantic_metadata.required_for must be ${JSON.stringify(expectedRequired)}`)
    }
    if (!isNonEmptyString(semantic.rule_id_pattern)) {
      errors.push('semantic_metadata.rule_id_pattern must be a non-empty string')
    } else {
      try {
        new RegExp(semantic.rule_id_pattern)
      } catch {
        errors.push('semantic_metadata.rule_id_pattern must compile as a regular expression')
      }
    }
    if (semantic.source_protocol !== 'https:') {
      errors.push('semantic_metadata.source_protocol must be "https:"')
    }
    if (semantic.source_verified_on_required !== true) {
      errors.push('semantic_metadata.source_verified_on_required must be true')
    }
  }

  if (!Array.isArray(manifest.adapters) || manifest.adapters.length === 0) {
    errors.push('adapters must be a non-empty array')
    return { valid: errors.length === 0, errors }
  }

  const adapterIds = new Set()
  const engineNames = new Set()
  const canonicalVariants = new Set()
  for (const [index, adapter] of manifest.adapters.entries()) {
    const path = `adapters[${index}]`
    if (!isPlainObject(adapter)) {
      errors.push(`${path} must be an object`)
      continue
    }
    addUnexpectedKeyErrors(errors, adapter, ADAPTER_KEYS, path)

    if (!isCanonicalIdentifier(adapter.adapter_id) || adapter.adapter_id === 'inventory-only') {
      errors.push(`${path}.adapter_id must be a canonical non-fallback identifier`)
    } else if (adapterIds.has(adapter.adapter_id)) {
      errors.push(`${path}.adapter_id duplicates ${JSON.stringify(adapter.adapter_id)}`)
    } else {
      adapterIds.add(adapter.adapter_id)
    }

    if (!isCanonicalIdentifier(adapter.engine)) {
      errors.push(`${path}.engine must be a canonical identifier`)
    }
    const engineAliases = Array.isArray(adapter.engine_aliases) ? adapter.engine_aliases : []
    if (!Array.isArray(adapter.engine_aliases)) {
      errors.push(`${path}.engine_aliases must be an array`)
    }
    for (const [aliasIndex, alias] of engineAliases.entries()) {
      if (!isCanonicalIdentifier(alias)) {
        errors.push(`${path}.engine_aliases[${aliasIndex}] must be a canonical identifier`)
      }
    }
    const allEngineNames = [adapter.engine, ...engineAliases]
    if (new Set(allEngineNames).size !== allEngineNames.length) {
      errors.push(`${path} repeats an engine or engine alias`)
    }
    for (const name of allEngineNames) {
      if (engineNames.has(name)) {
        errors.push(`${path} reuses engine name or alias ${JSON.stringify(name)}`)
      } else {
        engineNames.add(name)
      }
    }

    if (typeof adapter.adapter_file !== 'string'
      || !ADAPTER_FILE_PATTERN.test(adapter.adapter_file)) {
      errors.push(`${path}.adapter_file must be a safe Markdown basename`)
    }

    const semanticSourceHosts = Array.isArray(adapter.semantic_source_hosts)
      ? adapter.semantic_source_hosts
      : []
    if (!Array.isArray(adapter.semantic_source_hosts)
      || adapter.semantic_source_hosts.length === 0) {
      errors.push(`${path}.semantic_source_hosts must be a non-empty array`)
    }
    for (const [hostIndex, host] of semanticSourceHosts.entries()) {
      if (typeof host !== 'string'
        || host !== host.toLowerCase()
        || !HOSTNAME_PATTERN.test(host)) {
        errors.push(
          `${path}.semantic_source_hosts[${hostIndex}] must be a lowercase hostname`,
        )
      }
    }
    if (new Set(semanticSourceHosts).size !== semanticSourceHosts.length) {
      errors.push(`${path}.semantic_source_hosts must not contain duplicates`)
    }

    if (!Array.isArray(adapter.deployment_variants)
      || adapter.deployment_variants.length === 0) {
      errors.push(`${path}.deployment_variants must be a non-empty array`)
      continue
    }
    const localVariantNames = new Set()
    for (const [variantIndex, variant] of adapter.deployment_variants.entries()) {
      const variantPath = `${path}.deployment_variants[${variantIndex}]`
      if (!isPlainObject(variant)) {
        errors.push(`${variantPath} must be an object`)
        continue
      }
      addUnexpectedKeyErrors(errors, variant, VARIANT_KEYS, variantPath)
      if (!isCanonicalIdentifier(variant.id) || variant.id === 'unknown') {
        errors.push(`${variantPath}.id must be a canonical, known identifier`)
      } else if (canonicalVariants.has(variant.id)) {
        errors.push(`${variantPath}.id duplicates canonical variant ${JSON.stringify(variant.id)}`)
      } else {
        canonicalVariants.add(variant.id)
      }
      const aliases = Array.isArray(variant.aliases) ? variant.aliases : []
      if (!Array.isArray(variant.aliases)) {
        errors.push(`${variantPath}.aliases must be an array`)
      }
      for (const [aliasIndex, alias] of aliases.entries()) {
        if (!isCanonicalIdentifier(alias) || alias === 'unknown') {
          errors.push(`${variantPath}.aliases[${aliasIndex}] must be a canonical, known identifier`)
        }
      }
      for (const name of [variant.id, ...aliases]) {
        if (localVariantNames.has(name)) {
          errors.push(`${variantPath} reuses local deployment variant ${JSON.stringify(name)}`)
        } else {
          localVariantNames.add(name)
        }
      }
    }
  }

  return { valid: errors.length === 0, errors }
}

export function assertValidDatabaseAdapterManifest(manifest) {
  const result = validateDatabaseAdapterManifest(manifest)
  if (!result.valid) throw new DatabaseAdapterManifestError(result.errors)
  return manifest
}

const parsedManifest = JSON.parse(
  readFileSync(fileURLToPath(DATABASE_ADAPTER_MANIFEST_URL), 'utf8'),
)
assertValidDatabaseAdapterManifest(parsedManifest)
export const databaseAdapterManifest = deepFreeze(parsedManifest)
const DATABASE_ADAPTER_DIRECTORY_URL = new URL(
  '../../skills/red-team-audit/lenses/_database-adapters/',
  import.meta.url,
)

function adapterDocumentMetadata(adapter) {
  const text = readFileSync(
    fileURLToPath(new URL(adapter.adapter_file, DATABASE_ADAPTER_DIRECTORY_URL)),
    'utf8',
  )
  const hosts = new Set()
  for (const match of text.matchAll(/https:\/\/[^\s<>()`]+/g)) {
    try {
      hosts.add(new URL(match[0].replace(/[.,;:]+$/, '')).hostname.toLowerCase())
    } catch {
      // The adapter corpus validator owns malformed documentation references.
    }
  }
  const ruleIds = new Set(
    [...text.matchAll(/`(db\.[a-z0-9-]+\.[a-z0-9-]+\.[a-z0-9][a-z0-9.-]*)`/g)]
      .map((match) => match[1])
      .filter((ruleId) => ruleId.split('.')[2] === adapter.adapter_id),
  )
  return { hosts, ruleIds }
}

const adapterDocumentMetadataById = new Map(
  databaseAdapterManifest.adapters.map((adapter) => [
    adapter.adapter_id,
    adapterDocumentMetadata(adapter),
  ]),
)
const documentationBindingErrors = databaseAdapterManifest.adapters.flatMap((adapter) =>
  adapter.semantic_source_hosts
    .filter((host) => !adapterDocumentMetadataById.get(adapter.adapter_id).hosts.has(host))
    .map((host) =>
      `${adapter.adapter_id}.semantic_source_hosts contains uncited host ${JSON.stringify(host)}`))
if (documentationBindingErrors.length > 0) {
  throw new DatabaseAdapterManifestError(documentationBindingErrors)
}

function buildManifestIndex(manifest) {
  const byAdapter = new Map()
  const byEngine = new Map()
  for (const adapter of manifest.adapters) {
    byAdapter.set(adapter.adapter_id, adapter)
    for (const engine of [adapter.engine, ...adapter.engine_aliases]) {
      byEngine.set(engine, adapter)
    }
  }
  return { byAdapter, byEngine }
}

const defaultIndex = buildManifestIndex(databaseAdapterManifest)

export const knownDatabaseAdapterIds = Object.freeze(
  databaseAdapterManifest.adapters.map(({ adapter_id: adapterId }) => adapterId),
)
export const knownDatabaseEngines = Object.freeze(
  databaseAdapterManifest.adapters.map(({ engine }) => engine),
)
export const knownDatabaseDeploymentVariants = Object.freeze(
  databaseAdapterManifest.adapters.flatMap(({ deployment_variants: variants }) =>
    variants.map(({ id }) => id)),
)

function conservativeDecision(manifest, reasons, observed = {}) {
  return deepFreeze({
    ...manifest.fallback,
    engine: observed.engine ?? null,
    engine_version: observed.engineVersion ?? null,
    deployment_variant: observed.deploymentVariant ?? null,
    reasons,
  })
}

function reason(code, field, detail) {
  return { code, field, detail }
}

function normalizeProfileValue(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : value
}

export function routeDatabaseAdapter(profile, { manifest = databaseAdapterManifest } = {}) {
  if (manifest !== databaseAdapterManifest) assertValidDatabaseAdapterManifest(manifest)
  const index = manifest === databaseAdapterManifest ? defaultIndex : buildManifestIndex(manifest)
  const reasons = []

  if (!isPlainObject(profile)) {
    return conservativeDecision(manifest, [
      reason('invalid-profile', null, 'store profile must be an object'),
    ])
  }

  for (const key of unexpectedKeys(profile, PROFILE_KEYS)) {
    reasons.push(reason(
      'unsupported-profile-field',
      key,
      'route only the immutable store_context projection',
    ))
  }

  const engine = normalizeProfileValue(profile.engine)
  const engineVersion = typeof profile.engine_version === 'string'
    ? profile.engine_version.trim()
    : profile.engine_version
  const deploymentVariant = normalizeProfileValue(profile.deployment_variant)
  const claimedAdapterId = normalizeProfileValue(profile.adapter_id)
  const confidence = normalizeProfileValue(profile.confidence)
  const observed = { engine, engineVersion, deploymentVariant }

  if (!isCanonicalIdentifier(engine)) {
    reasons.push(reason('invalid-engine', 'engine', 'engine must be a canonical identifier'))
  }
  const adapter = isCanonicalIdentifier(engine) ? index.byEngine.get(engine) : undefined
  if (!adapter) {
    reasons.push(reason('unknown-engine', 'engine', 'no exact adapter engine or alias matched'))
  }

  if (confidence !== manifest.routing_policy.minimum_confidence) {
    reasons.push(reason(
      'insufficient-detection-confidence',
      'confidence',
      `adapter routing requires ${manifest.routing_policy.minimum_confidence} confidence`,
    ))
  }

  const missingEngineVersion = !isNonEmptyString(engineVersion)
    || engineVersion.trim().toLowerCase() === manifest.routing_policy.unknown_value
  const unresolvedEngineVersion = !missingEngineVersion
    && isUnresolvedDatabaseDescriptor(engineVersion)
  if (missingEngineVersion) {
    reasons.push(reason(
      'unknown-engine-version',
      'engine_version',
      'an established engine or managed-service version marker is required',
    ))
  } else if (unresolvedEngineVersion || !isDefensibleEngineVersion(engineVersion)) {
    reasons.push(reason(
      'unresolved-engine-version',
      'engine_version',
      'engine_version must be a concrete, bounded release marker containing a digit; free-text labels do not establish engine semantics',
    ))
  }

  const missingDeploymentVariant = !isNonEmptyString(deploymentVariant)
    || deploymentVariant === manifest.routing_policy.unknown_value
  const unresolvedDeploymentVariant = !missingDeploymentVariant
    && isUnresolvedDatabaseDescriptor(deploymentVariant)
  if (missingDeploymentVariant || !isCanonicalIdentifier(deploymentVariant)) {
    reasons.push(reason(
      'unknown-deployment-variant',
      'deployment_variant',
      'an exact deployment variant is required',
    ))
  } else if (unresolvedDeploymentVariant) {
    reasons.push(reason(
      'unresolved-deployment-variant',
      'deployment_variant',
      'free-text deployment placeholders do not select a semantic variant',
    ))
  }

  if (!Array.isArray(profile.detection_evidence)
    || profile.detection_evidence.length === 0
    || profile.detection_evidence.some((item) => !isNonEmptyString(item))
    || new Set(profile.detection_evidence).size !== profile.detection_evidence.length) {
    reasons.push(reason(
      'invalid-detection-evidence',
      'detection_evidence',
      'one or more unique, non-empty evidence entries are required',
    ))
  }

  let canonicalVariant
  if (adapter && isCanonicalIdentifier(deploymentVariant)
    && deploymentVariant !== manifest.routing_policy.unknown_value
    && !unresolvedDeploymentVariant) {
    const variant = adapter.deployment_variants.find(({ id, aliases }) =>
      id === deploymentVariant || aliases.includes(deploymentVariant))
    if (!variant) {
      reasons.push(reason(
        'unsupported-deployment-variant',
        'deployment_variant',
        `variant is not declared for ${adapter.adapter_id}`,
      ))
    } else {
      canonicalVariant = variant.id
    }
  }

  if (claimedAdapterId === 'inventory-only') {
    reasons.push(reason(
      'inventory-only-requested',
      'adapter_id',
      'the upstream projection already selected conservative inventory-only handling',
    ))
  } else if (claimedAdapterId !== undefined && claimedAdapterId !== null
    && claimedAdapterId !== '') {
    if (!isCanonicalIdentifier(claimedAdapterId)) {
      reasons.push(reason(
        'invalid-adapter-id',
        'adapter_id',
        'adapter_id must be a canonical identifier',
      ))
    } else if (!index.byAdapter.has(claimedAdapterId)) {
      reasons.push(reason(
        'unknown-adapter-id',
        'adapter_id',
        'adapter_id is not declared by the manifest',
      ))
    } else if (adapter && claimedAdapterId !== adapter.adapter_id) {
      reasons.push(reason(
        'adapter-engine-conflict',
        'adapter_id',
        `claimed adapter does not match engine-selected adapter ${adapter.adapter_id}`,
      ))
    }
  }

  if (
    adapter
    && manifest === databaseAdapterManifest
    && (adapterDocumentMetadataById.get(adapter.adapter_id)?.ruleIds.size ?? 0) === 0
  ) {
    reasons.push(reason(
      'missing-rule-vocabulary',
      'adapter_id',
      `adapter ${adapter.adapter_id} has no allowlisted semantic rule vocabulary`,
    ))
  }

  if (reasons.length > 0 || !adapter || !canonicalVariant) {
    return conservativeDecision(manifest, reasons, observed)
  }

  const normalizedReasons = []
  if (engine !== adapter.engine) {
    normalizedReasons.push(reason(
      'engine-alias-normalized',
      'engine',
      `${engine} normalized to ${adapter.engine}`,
    ))
  }
  if (deploymentVariant !== canonicalVariant) {
    normalizedReasons.push(reason(
      'deployment-variant-alias-normalized',
      'deployment_variant',
      `${deploymentVariant} normalized to ${canonicalVariant}`,
    ))
  }

  return deepFreeze({
    adapter_id: adapter.adapter_id,
    adapter_file: adapter.adapter_file,
    selection_status: 'SELECTED',
    coverage_state: 'ROUTED',
    verification_status: null,
    effective_severity_cap: null,
    can_clear: false,
    can_confirm: false,
    engine: adapter.engine,
    engine_version: engineVersion,
    deployment_variant: canonicalVariant,
    reasons: normalizedReasons,
  })
}

export function getDatabaseAdapterDefinition(adapterId) {
  const normalized = normalizeProfileValue(adapterId)
  return defaultIndex.byAdapter.get(normalized) ?? null
}

function semanticError(code, field, detail) {
  return { code, field, detail }
}

export function validateDatabaseSemanticMetadata(
  metadata,
  { manifest = databaseAdapterManifest, asOf = new Date() } = {},
) {
  if (manifest !== databaseAdapterManifest) assertValidDatabaseAdapterManifest(manifest)
  const index = manifest === databaseAdapterManifest ? defaultIndex : buildManifestIndex(manifest)
  const errors = []
  if (!isPlainObject(metadata)) {
    return { valid: false, errors: [
      semanticError('invalid-semantic-metadata', null, 'semantic metadata must be an object'),
    ] }
  }

  for (const key of unexpectedKeys(metadata, SEMANTIC_KEYS)) {
    errors.push(semanticError(
      'unsupported-semantic-field',
      key,
      'semantic metadata contains an unsupported field',
    ))
  }

  const adapterId = normalizeProfileValue(metadata.adapter_id)
  const sensitivity = normalizeProfileValue(metadata.semantic_sensitivity)
  const ruleId = metadata.adapter_rule_id
  const source = metadata.semantic_source
  const selectedAdapter = index.byAdapter.get(adapterId)

  if (!selectedAdapter) {
    errors.push(semanticError(
      'semantic-adapter-not-selected',
      'adapter_id',
      'semantic claims require a selected, non-inventory adapter',
    ))
  }
  if (!manifest.semantic_metadata.sensitivity_values.includes(sensitivity)) {
    errors.push(semanticError(
      'invalid-semantic-sensitivity',
      'semantic_sensitivity',
      'semantic sensitivity is missing or unsupported',
    ))
  }

  const metadataRequired = manifest.semantic_metadata.required_for.includes(sensitivity)
  const hasRule = ruleId !== undefined && ruleId !== null
  const hasSource = source !== undefined && source !== null
  if (metadataRequired && !hasRule) {
    errors.push(semanticError(
      'missing-adapter-rule-id',
      'adapter_rule_id',
      `${sensitivity} claims require an adapter rule`,
    ))
  }
  if (metadataRequired && !hasSource) {
    errors.push(semanticError(
      'missing-semantic-source',
      'semantic_source',
      `${sensitivity} claims require a dated primary source`,
    ))
  }
  if (hasRule !== hasSource) {
    errors.push(semanticError(
      'incomplete-semantic-metadata',
      hasRule ? 'semantic_source' : 'adapter_rule_id',
      'adapter_rule_id and semantic_source must appear together',
    ))
  }

  if (hasRule) {
    let rulePattern
    try {
      rulePattern = new RegExp(manifest.semantic_metadata.rule_id_pattern)
    } catch {
      rulePattern = /$a/
    }
    if (!isNonEmptyString(ruleId) || !rulePattern.test(ruleId)) {
      errors.push(semanticError(
        'invalid-adapter-rule-id',
        'adapter_rule_id',
        'adapter rule ID does not match the stable database rule namespace',
      ))
    } else if (ruleId.split('.')[2] !== adapterId) {
      errors.push(semanticError(
        'adapter-rule-mismatch',
        'adapter_rule_id',
        'adapter rule namespace does not match the selected adapter',
      ))
    } else {
      const declaredRuleIds = manifest === databaseAdapterManifest
        ? adapterDocumentMetadataById.get(adapterId)?.ruleIds
        : null
      if (!declaredRuleIds || !declaredRuleIds.has(ruleId)) {
        errors.push(semanticError(
          'undeclared-adapter-rule-id',
          'adapter_rule_id',
          declaredRuleIds?.size === 0
            ? 'the selected adapter has no allowlisted semantic rule vocabulary'
            : 'adapter rule ID is not declared by the selected adapter document',
        ))
      }
    }
  }

  if (hasSource) {
    if (!isPlainObject(source)) {
      errors.push(semanticError(
        'invalid-semantic-source',
        'semantic_source',
        'semantic_source must be an object',
      ))
    } else {
      for (const key of unexpectedKeys(source, SEMANTIC_SOURCE_KEYS)) {
        errors.push(semanticError(
          'unsupported-semantic-source-field',
          `semantic_source.${key}`,
          'semantic_source contains an unsupported field',
        ))
      }
      try {
        const parsed = new URL(source.url)
        if (parsed.protocol !== manifest.semantic_metadata.source_protocol
          || parsed.username !== ''
          || parsed.password !== '') {
          errors.push(semanticError(
            'invalid-semantic-source-url',
            'semantic_source.url',
            'semantic source must be an HTTPS URL without embedded credentials',
          ))
        } else if (selectedAdapter
          && !selectedAdapter.semantic_source_hosts.includes(
            parsed.hostname.toLowerCase(),
          )) {
          errors.push(semanticError(
            'untrusted-semantic-source-host',
            'semantic_source.url',
            'semantic source host is not cited by the selected trusted adapter',
          ))
        }
      } catch {
        errors.push(semanticError(
          'invalid-semantic-source-url',
          'semantic_source.url',
          'semantic source must be an absolute HTTPS URL',
        ))
      }
      if (!isRealIsoDate(source.verified_on)) {
        errors.push(semanticError(
          'invalid-semantic-source-date',
          'semantic_source.verified_on',
          'verified_on must be a real YYYY-MM-DD date',
        ))
      } else {
        const asOfDate = asOf instanceof Date ? asOf : new Date(`${asOf}T00:00:00.000Z`)
        const verifiedDate = new Date(`${source.verified_on}T00:00:00.000Z`)
        if (Number.isNaN(asOfDate.getTime()) || verifiedDate > asOfDate) {
          errors.push(semanticError(
            'future-semantic-source-date',
            'semantic_source.verified_on',
            'verified_on cannot be after the validation date',
          ))
        }
      }
    }
  }

  return { valid: errors.length === 0, errors }
}
