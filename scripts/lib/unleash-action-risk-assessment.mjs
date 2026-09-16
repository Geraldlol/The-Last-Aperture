import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import Ajv2020 from 'ajv/dist/2020.js'

const SCHEMA_URL = new URL(
  '../../schemas/unleash-action-risk-assessment.schema.json',
  import.meta.url,
)

export const unleashActionRiskAssessmentSchema = JSON.parse(
  readFileSync(fileURLToPath(SCHEMA_URL), 'utf8'),
)

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})
const validateRiskDocumentSchema = ajv.compile(unleashActionRiskAssessmentSchema)

function deeplyFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const child of Object.values(value)) deeplyFreeze(child)
  return Object.freeze(value)
}

export const UNLEASH_ACTION_RISK_CATALOG = deeplyFreeze({
  catalog_id: 'last-aperture/defender-action-risk',
  catalog_version: '1.0.0',
  reviewed_at: '2026-09-16',
  sources: [
    {
      source_id: 'mitre-attack-detection-strategies',
      url: 'https://attack.mitre.org/detectionstrategies/',
    },
    {
      source_id: 'microsoft-sentinel-normalization-content',
      url: 'https://learn.microsoft.com/en-us/azure/sentinel/normalization-content',
    },
    {
      source_id: 'microsoft-sentinel-web-session-schema',
      url: 'https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-web',
    },
    {
      source_id: 'microsoft-defender-xdr-hunting-schema',
      url: 'https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables',
    },
    {
      source_id: 'aws-guardduty-data-sources',
      url: 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_data-sources.html',
    },
    {
      source_id: 'google-security-command-center-threats',
      url: 'https://docs.cloud.google.com/security-command-center/docs/overview-threats',
    },
  ],
})

export const UNLEASH_ACTION_RISK_DETECTION_PATTERN_MODEL = deeplyFreeze({
  model_id: 'last-aperture/generic-defender-detection-patterns',
  model_version: '1.0.0',
  patterns: [
    {
      pattern_id: 'pattern:single-request',
      title: 'Single request',
      match_all: [{ trait: 'REQUEST_COUNT', operator: 'EQUALS', value: 1 }],
      control_domains: ['SIEM_LOGGING', 'NETWORK', 'APPLICATION'],
      potential_telemetry: [
        'AUDIT_OR_SECURITY_EVENT', 'NETWORK_CONNECTION_EVENT', 'APPLICATION_REQUEST_EVENT',
      ],
      rationale: 'One target request can be represented by application, network, or forwarded audit telemetry when those collection paths are enabled.',
      source_ids: [
        'microsoft-sentinel-web-session-schema', 'aws-guardduty-data-sources',
        'google-security-command-center-threats',
      ],
    },
    {
      pattern_id: 'pattern:request-sequence',
      title: 'Request sequence',
      match_all: [{ trait: 'REQUEST_COUNT', operator: 'GREATER_THAN', value: 1 }],
      control_domains: ['SIEM_LOGGING', 'NETWORK', 'APPLICATION'],
      potential_telemetry: ['AUDIT_OR_SECURITY_EVENT', 'NETWORK_REQUEST_SEQUENCE'],
      rationale: 'Multiple target requests can form a sequence across application, network, or forwarded audit telemetry when those collection paths are enabled.',
      source_ids: [
        'microsoft-sentinel-web-session-schema', 'aws-guardduty-data-sources',
        'google-security-command-center-threats',
      ],
    },
    {
      pattern_id: 'pattern:high-rate-request-activity',
      title: 'High-rate request activity',
      match_all: [
        { trait: 'REQUEST_COUNT', operator: 'GREATER_THAN', value: 1 },
        { trait: 'REQUESTS_PER_MINUTE', operator: 'GREATER_THAN', value: 60 },
      ],
      control_domains: ['SIEM_LOGGING', 'NETWORK', 'APPLICATION'],
      potential_telemetry: ['AUDIT_OR_SECURITY_EVENT', 'NETWORK_REQUEST_SEQUENCE'],
      rationale: 'A declared rate above sixty requests per minute can increase event density when relevant collection is enabled.',
      source_ids: [
        'microsoft-sentinel-normalization-content', 'microsoft-sentinel-web-session-schema',
      ],
    },
    {
      pattern_id: 'pattern:parallel-request-activity',
      title: 'Parallel request activity',
      match_all: [
        { trait: 'REQUEST_COUNT', operator: 'GREATER_THAN', value: 1 },
        { trait: 'MAX_PARALLEL_REQUESTS', operator: 'GREATER_THAN', value: 1 },
      ],
      control_domains: ['SIEM_LOGGING', 'NETWORK', 'APPLICATION'],
      potential_telemetry: ['AUDIT_OR_SECURITY_EVENT', 'NETWORK_REQUEST_SEQUENCE'],
      rationale: 'Concurrent target requests can overlap in application, network, or forwarded audit telemetry when those collection paths are enabled.',
      source_ids: [
        'microsoft-sentinel-normalization-content', 'microsoft-sentinel-web-session-schema',
      ],
    },
    {
      pattern_id: 'pattern:authenticated-access',
      title: 'Authenticated access',
      match_all: [{ trait: 'AUTHENTICATED_ACCESS', operator: 'EQUALS', value: 1 }],
      control_domains: ['SIEM_LOGGING', 'IDENTITY', 'APPLICATION'],
      potential_telemetry: ['AUDIT_OR_SECURITY_EVENT', 'AUTHENTICATION_EVENT'],
      rationale: 'Authenticated access can be represented by identity, application, or forwarded audit telemetry when those collection paths are enabled.',
      source_ids: [
        'microsoft-sentinel-normalization-content', 'microsoft-defender-xdr-hunting-schema',
      ],
    },
    {
      pattern_id: 'pattern:application-state-change',
      title: 'Application state change',
      match_all: [{ trait: 'APPLICATION_STATE_CHANGE', operator: 'EQUALS', value: 1 }],
      control_domains: ['SIEM_LOGGING', 'APPLICATION'],
      potential_telemetry: ['AUDIT_OR_SECURITY_EVENT', 'APPLICATION_STATE_CHANGE_EVENT'],
      rationale: 'A declared application state change can be represented by application or forwarded audit telemetry when those collection paths are enabled.',
      source_ids: [
        'microsoft-sentinel-normalization-content', 'aws-guardduty-data-sources',
      ],
    },
    {
      pattern_id: 'pattern:workload-execution',
      title: 'Workload execution',
      match_all: [{ trait: 'WORKLOAD_EXECUTION', operator: 'EQUALS', value: 1 }],
      control_domains: ['ENDPOINT', 'SIEM_LOGGING'],
      potential_telemetry: ['PROCESS_OR_WORKLOAD_START_EVENT', 'AUDIT_OR_SECURITY_EVENT'],
      rationale: 'A declared workload execution can be represented by endpoint or forwarded audit telemetry when those collection paths are enabled.',
      source_ids: [
        'mitre-attack-detection-strategies', 'microsoft-defender-xdr-hunting-schema',
      ],
    },
    {
      pattern_id: 'pattern:data-transfer',
      title: 'Canary or evidence data transfer',
      match_all: [{ trait: 'DATA_TRANSFER', operator: 'EQUALS', value: 1 }],
      control_domains: ['SIEM_LOGGING', 'NETWORK', 'APPLICATION'],
      potential_telemetry: [
        'AUDIT_OR_SECURITY_EVENT', 'NETWORK_CONNECTION_EVENT', 'APPLICATION_REQUEST_EVENT',
      ],
      rationale: 'A declared canary or evidence transfer can be represented by application, network, or forwarded audit telemetry when those collection paths are enabled.',
      source_ids: [
        'mitre-attack-detection-strategies', 'microsoft-sentinel-web-session-schema',
      ],
    },
  ],
})

export const UNLEASH_ACTION_RISK_OPERATIONAL_PROFILES = Object.freeze([
  'aggressive',
  'balanced',
  'cautious',
])

export const UNLEASH_ACTION_RISK_CONTROL_DOMAINS = Object.freeze([
  'ENDPOINT',
  'SIEM_LOGGING',
  'NETWORK',
  'CLOUD',
  'IDENTITY',
  'APPLICATION',
])

export const UNLEASH_ACTION_RISK_PROFILE_CONSTRAINTS = deeplyFreeze({
  aggressive: {
    max_parallel_requests: 8,
    max_requests_per_minute: 240,
    minimum_interval_ms: 250,
    risk_confirmation_threshold: 75,
    noise_confirmation_threshold: 80,
  },
  balanced: {
    max_parallel_requests: 4,
    max_requests_per_minute: 120,
    minimum_interval_ms: 500,
    risk_confirmation_threshold: 50,
    noise_confirmation_threshold: 60,
  },
  cautious: {
    max_parallel_requests: 1,
    max_requests_per_minute: 30,
    minimum_interval_ms: 2000,
    risk_confirmation_threshold: 25,
    noise_confirmation_threshold: 40,
  },
})

const FORBIDDEN_PROFILE_NAMES = new Set(['evasive', 'bypass', 'stealth', 'stealthy'])
const ACTION_FACT_FIELDS = ['tool_id', 'parameters', 'target', 'effect', 'volume']
const VOLUME_FIELDS = [
  'request_count',
  'max_parallel_requests',
  'max_requests_per_minute',
  'minimum_interval_ms',
]
const RECEIPT_INPUT_FIELDS = ['action_id', 'assessment']
const CONFIRMATION_INPUT_FIELDS = ['receipt', 'confirmation']
const CONFIRMATION_FIELDS = [
  'schema_version',
  'kind',
  'action_id',
  'assessment_sha256',
  'receipt_sha256',
  'confirmed',
]
const ID = /^[A-Za-z0-9][A-Za-z0-9._:/+-]{2,159}$/u
const MAX_JSON_DEPTH = 32
const MAX_JSON_NODES = 10_000
const MAX_ACTION_BYTES = 1_048_576

const EFFECT_RISK = Object.freeze({
  OBSERVE: 10,
  PROBE: 20,
  AUTHENTICATED_REQUEST: 30,
  MUTATE_REVERSIBLE: 50,
  EXECUTE_PROOF: 45,
  EXFILTRATE_CANARY: 60,
  PUBLISH_EVIDENCE: 40,
})
const EFFECT_RATIONALE = Object.freeze({
  OBSERVE: 'The declared effect observes target state without changing it.',
  PROBE: 'The declared effect actively probes a bounded target surface.',
  AUTHENTICATED_REQUEST: 'The declared effect uses an authenticated target interaction.',
  MUTATE_REVERSIBLE: 'The declared effect changes target state and declares reversible handling.',
  EXECUTE_PROOF: 'The declared effect executes a bounded proof action under controller limits.',
  EXFILTRATE_CANARY: 'The declared effect transfers controller-approved canary material.',
  PUBLISH_EVIDENCE: 'The declared effect publishes evidence to a controller-approved destination.',
})

export class UnleashActionRiskAssessmentError extends Error {
  constructor(code, message, details = []) {
    super(message)
    this.name = 'UnleashActionRiskAssessmentError'
    this.code = code
    this.details = details
  }
}

function fail(code, message, details = []) {
  throw new UnleashActionRiskAssessmentError(code, message, details)
}

function exactDataValues(value, fields, label) {
  let prototype
  let descriptors
  try {
    prototype = Object.getPrototypeOf(value)
    descriptors = Object.getOwnPropertyDescriptors(value)
  } catch {
    fail('UNLEASH_ACTION_RISK_INPUT_INVALID', `${label} must be an inspectable plain data record`)
  }
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || ![Object.prototype, null].includes(prototype)
  ) fail('UNLEASH_ACTION_RISK_INPUT_INVALID', `${label} must be one plain data record`)
  const keys = Reflect.ownKeys(descriptors)
  if (
    keys.length !== fields.length
    || keys.some((key) => typeof key !== 'string'
      || !fields.includes(key)
      || descriptors[key].enumerable !== true
      || !Object.hasOwn(descriptors[key], 'value'))
  ) fail('UNLEASH_ACTION_RISK_INPUT_INVALID', `${label} contains missing, unknown, or computed fields`)
  return Object.fromEntries(fields.map((field) => [field, descriptors[field].value]))
}

function clonePlainJson(value, state = { nodes: 0 }, depth = 0) {
  state.nodes += 1
  if (state.nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH) {
    fail('UNLEASH_ACTION_RISK_INPUT_INVALID', 'value exceeds the bounded JSON structure limit')
  }
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      fail('UNLEASH_ACTION_RISK_INPUT_INVALID', 'values must contain finite JSON numbers')
    }
    return value
  }
  if (typeof value !== 'object') {
    fail('UNLEASH_ACTION_RISK_INPUT_INVALID', 'values must contain plain JSON data')
  }

  let prototype
  let descriptors
  try {
    prototype = Object.getPrototypeOf(value)
    descriptors = Object.getOwnPropertyDescriptors(value)
  } catch {
    fail('UNLEASH_ACTION_RISK_INPUT_INVALID', 'values must be inspectable plain JSON data')
  }
  const keys = Reflect.ownKeys(descriptors)
  if (Array.isArray(value)) {
    if (prototype !== Array.prototype) {
      fail('UNLEASH_ACTION_RISK_INPUT_INVALID', 'arrays must use the ordinary array prototype')
    }
    const itemKeys = keys.filter((key) => key !== 'length')
    if (
      itemKeys.length !== value.length
      || itemKeys.some((key, index) => key !== String(index)
        || descriptors[key].enumerable !== true
        || !Object.hasOwn(descriptors[key], 'value'))
    ) fail('UNLEASH_ACTION_RISK_INPUT_INVALID', 'arrays must be plain and dense')
    return itemKeys.map((key) => clonePlainJson(descriptors[key].value, state, depth + 1))
  }
  if (![Object.prototype, null].includes(prototype)) {
    fail('UNLEASH_ACTION_RISK_INPUT_INVALID', 'objects must use a plain prototype')
  }
  if (keys.some((key) => typeof key !== 'string'
    || descriptors[key].enumerable !== true
    || !Object.hasOwn(descriptors[key], 'value'))) {
    fail('UNLEASH_ACTION_RISK_INPUT_INVALID', 'objects must contain enumerable data fields only')
  }
  const copy = {}
  for (const key of keys.toSorted()) {
    Object.defineProperty(copy, key, {
      enumerable: true,
      configurable: true,
      writable: true,
      value: clonePlainJson(descriptors[key].value, state, depth + 1),
    })
  }
  return copy
}

function canonicalJson(value) {
  return JSON.stringify(clonePlainJson(value))
}

function digest(value) {
  return createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')
}

function frozenCopy(value) {
  return deeplyFreeze(clonePlainJson(value))
}

function catalogFields() {
  return {
    catalog_id: UNLEASH_ACTION_RISK_CATALOG.catalog_id,
    catalog_version: UNLEASH_ACTION_RISK_CATALOG.catalog_version,
    reviewed_at: UNLEASH_ACTION_RISK_CATALOG.reviewed_at,
    sources: structuredClone(UNLEASH_ACTION_RISK_CATALOG.sources),
    detection_pattern_model_id: UNLEASH_ACTION_RISK_DETECTION_PATTERN_MODEL.model_id,
    detection_pattern_model_version: UNLEASH_ACTION_RISK_DETECTION_PATTERN_MODEL.model_version,
  }
}

export function normalizeUnleashActionRiskProfile(value) {
  if (typeof value !== 'string') {
    fail('UNLEASH_ACTION_RISK_PROFILE_INVALID', 'operational profile must be one supported profile name')
  }
  const normalized = value.trim().toLowerCase()
  if (FORBIDDEN_PROFILE_NAMES.has(normalized)) {
    fail(
      'UNLEASH_ACTION_RISK_PROFILE_FORBIDDEN',
      `operational profile ${JSON.stringify(value)} is explicitly forbidden`,
    )
  }
  if (value !== normalized || !UNLEASH_ACTION_RISK_OPERATIONAL_PROFILES.includes(value)) {
    fail(
      'UNLEASH_ACTION_RISK_PROFILE_INVALID',
      'operational profile must be aggressive, balanced, or cautious',
    )
  }
  return value
}

export function selectUnleashActionRiskProfile(value) {
  let profile
  if (typeof value === 'string') profile = normalizeUnleashActionRiskProfile(value)
  else {
    const selected = exactDataValues(value, ['operational_profile'], 'profile selection')
    profile = normalizeUnleashActionRiskProfile(selected.operational_profile)
  }
  return frozenCopy({
    operational_profile: profile,
    constraints: UNLEASH_ACTION_RISK_PROFILE_CONSTRAINTS[profile],
  })
}

function canonicalTarget(value) {
  if (typeof value !== 'string' || value.length > 4096 || /[\u0000-\u0020\u007f]/u.test(value)) {
    fail('UNLEASH_ACTION_RISK_ACTION_INVALID', 'target must be one canonical HTTPS URL')
  }
  let url
  try { url = new URL(value) } catch {
    fail('UNLEASH_ACTION_RISK_ACTION_INVALID', 'target must be one canonical HTTPS URL')
  }
  if (
    url.protocol !== 'https:'
    || url.username.length > 0
    || url.password.length > 0
    || url.hash.length > 0
    || url.hostname.endsWith('.')
    || url.href !== value
  ) fail('UNLEASH_ACTION_RISK_ACTION_INVALID', 'target must be one canonical credential-free HTTPS URL')
  return value
}

function positiveInteger(value, maximum, field, { allowZero = false } = {}) {
  if (
    !Number.isSafeInteger(value)
    || value < (allowZero ? 0 : 1)
    || value > maximum
  ) fail('UNLEASH_ACTION_RISK_ACTION_INVALID', `${field} is outside its finite bound`)
  return value
}

function normalizeVolume(value) {
  const volume = exactDataValues(value, VOLUME_FIELDS, 'action volume')
  positiveInteger(volume.request_count, 1_000_000, 'request_count')
  positiveInteger(volume.max_parallel_requests, 1024, 'max_parallel_requests')
  positiveInteger(volume.max_requests_per_minute, 1_000_000, 'max_requests_per_minute')
  positiveInteger(volume.minimum_interval_ms, 3_600_000, 'minimum_interval_ms', { allowZero: true })
  if (volume.max_parallel_requests > volume.request_count) {
    fail('UNLEASH_ACTION_RISK_ACTION_INVALID', 'max_parallel_requests cannot exceed request_count')
  }
  return volume
}

function normalizeActionFacts(value) {
  const input = exactDataValues(value, ACTION_FACT_FIELDS, 'action facts')
  const parameters = clonePlainJson(input.parameters)
  if (
    parameters === null
    || typeof parameters !== 'object'
    || Array.isArray(parameters)
    || Object.keys(parameters).length > 32
    || Buffer.byteLength(JSON.stringify(parameters), 'utf8') > MAX_ACTION_BYTES
  ) fail('UNLEASH_ACTION_RISK_ACTION_INVALID', 'parameters must be one bounded plain JSON object')
  const facts = {
    tool_id: input.tool_id,
    parameters,
    target: canonicalTarget(input.target),
    effect: input.effect,
    volume: normalizeVolume(input.volume),
  }
  if (typeof facts.tool_id !== 'string' || !ID.test(facts.tool_id)) {
    fail('UNLEASH_ACTION_RISK_ACTION_INVALID', 'tool_id is invalid')
  }
  if (!Object.hasOwn(EFFECT_RISK, facts.effect)) {
    fail('UNLEASH_ACTION_RISK_ACTION_INVALID', 'effect is not recognized')
  }
  if (
    facts.tool_id === 'tool:https-recon'
    && (
      canonicalJson(facts.parameters) !== canonicalJson({ method: 'HEAD' })
      || facts.effect !== 'OBSERVE'
      || facts.volume.request_count !== 1
      || facts.volume.max_parallel_requests !== 1
    )
  ) {
    fail(
      'UNLEASH_ACTION_RISK_ACTION_INVALID',
      'tool:https-recon assessment is limited to one inert OBSERVE HEAD request',
    )
  }
  return facts
}

function volumeRisk(volume) {
  if (volume.request_count === 1) return 0
  const requestContribution = Math.min(14, Math.ceil(Math.log2(volume.request_count)) * 2)
  const parallelContribution = Math.min(8, (volume.max_parallel_requests - 1) * 2)
  const rateContribution = volume.max_requests_per_minute > 60
    ? 4
    : volume.max_requests_per_minute > 30 ? 2 : 1
  const intervalContribution = volume.minimum_interval_ms === 0
    ? 3
    : volume.minimum_interval_ms < 500 ? 2 : 0
  return Math.min(25,
    requestContribution + parallelContribution + rateContribution + intervalContribution)
}

function actionContext(facts) {
  const { effect, volume } = facts
  return {
    endpoint_activity: effect === 'EXECUTE_PROOF' ? 'EXECUTE' : 'NONE',
    network_activity: volume.request_count === 1 ? 'SINGLE_REQUEST' : 'REQUEST_SEQUENCE',
    cloud_activity: 'NONE',
    identity_activity: effect === 'AUTHENTICATED_REQUEST'
      ? 'AUTHENTICATE'
      : 'NONE',
    application_activity: effect === 'AUTHENTICATED_REQUEST'
      ? 'AUTHENTICATED_READ'
      : ['MUTATE_REVERSIBLE', 'PUBLISH_EVIDENCE'].includes(effect)
        ? 'STATE_CHANGE'
        : 'READ',
    data_sensitivity: effect === 'EXFILTRATE_CANARY'
      ? 'CANARY'
      : effect === 'AUTHENTICATED_REQUEST' ? 'INTERNAL' : 'METADATA',
    privilege: 'NONE',
    reversibility: effect === 'MUTATE_REVERSIBLE' ? 'REVERSIBLE' : 'NOT_APPLICABLE',
    service_impact: effect === 'EXECUTE_PROOF' || volume.request_count > 100
      ? 'POSSIBLE'
      : 'NONE',
  }
}

function detectionPatternTraits(facts, context) {
  return {
    REQUEST_COUNT: facts.volume.request_count,
    REQUESTS_PER_MINUTE: facts.volume.max_requests_per_minute,
    MAX_PARALLEL_REQUESTS: facts.volume.max_parallel_requests,
    AUTHENTICATED_ACCESS: context.identity_activity === 'AUTHENTICATE' ? 1 : 0,
    APPLICATION_STATE_CHANGE: context.application_activity === 'STATE_CHANGE' ? 1 : 0,
    WORKLOAD_EXECUTION: context.endpoint_activity === 'EXECUTE' ? 1 : 0,
    DATA_TRANSFER: ['EXFILTRATE_CANARY', 'PUBLISH_EVIDENCE'].includes(facts.effect) ? 1 : 0,
  }
}

function detectionPatternConditionMatches(condition, traits) {
  if (!Object.hasOwn(traits, condition.trait)) {
    fail('UNLEASH_ACTION_RISK_MODEL_INVALID', 'detection-pattern model names an unknown trait')
  }
  if (condition.operator === 'EQUALS') return traits[condition.trait] === condition.value
  if (condition.operator === 'GREATER_THAN') return traits[condition.trait] > condition.value
  fail('UNLEASH_ACTION_RISK_MODEL_INVALID', 'detection-pattern model names an unknown operator')
}

function matchedDetectionPatternIds(facts, context) {
  const traits = detectionPatternTraits(facts, context)
  return UNLEASH_ACTION_RISK_DETECTION_PATTERN_MODEL.patterns
    .filter(({ match_all: conditions }) => conditions.every(
      (condition) => detectionPatternConditionMatches(condition, traits),
    ))
    .map(({ pattern_id: patternId }) => patternId)
}

function relativeExposureLevel(score) {
  if (score === 0) return 'NONE'
  if (score < 30) return 'LOW'
  if (score < 60) return 'MEDIUM'
  return 'HIGH'
}

function riskLevel(score) {
  if (score < 20) return 'MINIMAL'
  if (score < 40) return 'LOW'
  if (score < 60) return 'MODERATE'
  if (score < 80) return 'HIGH'
  return 'CRITICAL'
}

function noiseLevel(score) {
  if (score < 20) return 'MINIMAL'
  if (score < 40) return 'LOW'
  if (score < 60) return 'MODERATE'
  if (score < 80) return 'HIGH'
  return 'VERY_HIGH'
}

function impactLevel(score) {
  if (score === 0) return 'NONE'
  if (score < 30) return 'LOW'
  if (score < 60) return 'MODERATE'
  if (score < 80) return 'HIGH'
  return 'SEVERE'
}

function volumeSignalContribution(volume) {
  if (volume.request_count === 1) return 0
  return Math.min(35,
    Math.min(25, Math.ceil(Math.log2(volume.request_count)) * 4)
    + Math.min(6, (volume.max_parallel_requests - 1) * 2)
    + (volume.max_requests_per_minute >= 120
      ? 4
      : volume.max_requests_per_minute >= 60 ? 2 : 1))
}

function signal(control, score, potentialTelemetry, rationale) {
  const boundedScore = Math.min(100, score)
  return {
    control,
    relative_exposure_score: boundedScore,
    relative_exposure_level: relativeExposureLevel(boundedScore),
    potential_telemetry: potentialTelemetry,
    telemetry_coverage: 'UNKNOWN',
    collection_precondition: 'UNKNOWN',
    rationale,
  }
}

function controlSignals(context, volume) {
  const volumeContribution = volumeSignalContribution(volume)
  const endpoint = context.endpoint_activity === 'NONE'
    ? signal(
      'ENDPOINT',
      0,
      [],
      'No endpoint-specific activity is declared; endpoint telemetry exposure remains unassessed because collection coverage is unknown.',
    )
    : signal(
      'ENDPOINT',
      75,
      ['PROCESS_OR_WORKLOAD_START_EVENT'],
      'If relevant endpoint telemetry collection is enabled, process or workload execution may be represented; collection coverage has not been verified.',
    )
  const loggingScore = Math.min(90, 60 + Math.floor(volumeContribution / 2))
  const siem = signal(
    'SIEM_LOGGING',
    loggingScore,
    ['AUDIT_OR_SECURITY_EVENT'],
    volume.request_count === 1
      ? 'If relevant source collection, normalization, and forwarding are enabled, the action may contribute an audit or security event; collection coverage has not been verified.'
      : 'If relevant source collection, normalization, and forwarding are enabled, the request sequence may contribute multiple audit or security events; collection coverage has not been verified.',
  )
  const network = volume.request_count === 1
    ? signal(
      'NETWORK',
      45,
      ['NETWORK_CONNECTION_EVENT'],
      'If relevant network telemetry collection is enabled at an observation point, one bounded request may be represented as connection or request telemetry; collection coverage has not been verified.',
    )
    : signal(
      'NETWORK',
      50 + volumeContribution,
      ['NETWORK_CONNECTION_EVENT', 'NETWORK_REQUEST_SEQUENCE'],
      'If relevant network telemetry collection is enabled at an observation point, declared request count, rate, concurrency, and interval determine relative exposure; collection coverage has not been verified.',
    )
  const cloud = signal(
    'CLOUD',
    0,
    [],
    'No cloud data-plane or control-plane activity is declared; cloud telemetry exposure remains unassessed because target context and collection coverage are unknown.',
  )
  const identity = context.identity_activity === 'NONE'
    ? signal(
      'IDENTITY',
      0,
      [],
      'No identity activity is declared; identity telemetry exposure remains unassessed because collection coverage is unknown.',
    )
    : signal(
      'IDENTITY',
      60,
      ['AUTHENTICATION_EVENT'],
      'If identity-provider telemetry collection is enabled, authentication activity may be represented; collection coverage has not been verified.',
    )
  const applicationBase = context.application_activity === 'STATE_CHANGE'
    ? 85
    : context.application_activity === 'AUTHENTICATED_READ' ? 65 : 45
  const application = signal(
    'APPLICATION',
    applicationBase + Math.floor(volumeContribution / 2),
    context.application_activity === 'STATE_CHANGE'
      ? ['APPLICATION_STATE_CHANGE_EVENT']
      : context.application_activity === 'AUTHENTICATED_READ'
        ? ['APPLICATION_REQUEST_EVENT', 'APPLICATION_AUTHENTICATION_CONTEXT']
        : ['APPLICATION_REQUEST_EVENT'],
    context.application_activity === 'STATE_CHANGE'
      ? 'If application request or audit collection is enabled, the declared state change may be represented; collection coverage has not been verified.'
      : 'If application request collection is enabled, request volume and authentication context affect relative exposure; collection coverage has not been verified.',
  )
  return [endpoint, siem, network, cloud, identity, application]
}

function inherentRiskScore(facts, context) {
  const endpoint = context.endpoint_activity === 'EXECUTE' ? 15 : 0
  const network = facts.volume.request_count === 1 ? 5 : 8
  const identity = context.identity_activity === 'AUTHENTICATE' ? 10 : 0
  const application = context.application_activity === 'STATE_CHANGE'
    ? 18
    : context.application_activity === 'AUTHENTICATED_READ' ? 10 : 5
  const data = { METADATA: 3, INTERNAL: 8, CANARY: 12 }[context.data_sensitivity]
  const reversibility = context.reversibility === 'REVERSIBLE' ? 3 : 0
  const service = context.service_impact === 'POSSIBLE' ? 10 : 0
  return Math.min(100,
    EFFECT_RISK[facts.effect]
    + endpoint
    + network
    + identity
    + application
    + data
    + reversibility
    + service
    + volumeRisk(facts.volume))
}

function inherentNoiseScore(signals) {
  const scores = signals.map(({ relative_exposure_score: score }) => score)
  const maximum = Math.max(...scores)
  const average = scores.reduce((total, score) => total + score, 0) / scores.length
  return Math.min(100, Math.round((maximum * 0.5) + (average * 0.5)))
}

function profileConstraintViolations(volume, constraints) {
  const violations = []
  if (volume.max_parallel_requests > constraints.max_parallel_requests) {
    violations.push('MAX_PARALLEL_REQUESTS_EXCEEDED')
  }
  if (volume.max_requests_per_minute > constraints.max_requests_per_minute) {
    violations.push('MAX_REQUESTS_PER_MINUTE_EXCEEDED')
  }
  if (volume.request_count > 1 && volume.minimum_interval_ms < constraints.minimum_interval_ms) {
    violations.push('MINIMUM_INTERVAL_NOT_MET')
  }
  return violations
}

function likelyImpacts(facts, context, noiseScore) {
  const confidentialityScore = context.data_sensitivity === 'CANARY'
    ? 75
    : context.data_sensitivity === 'INTERNAL' ? 45 : 25
  const integrityScore = context.application_activity === 'STATE_CHANGE' ? 80 : 0
  const availabilityScore = context.service_impact === 'POSSIBLE' ? 50 : 0
  return [
    {
      impact: 'CONFIDENTIALITY',
      score: confidentialityScore,
      level: impactLevel(confidentialityScore),
      rationale: 'Declared data classification and read or transfer effect determine confidentiality impact.',
    },
    {
      impact: 'INTEGRITY',
      score: integrityScore,
      level: impactLevel(integrityScore),
      rationale: integrityScore === 0
        ? 'No resource, identity, cloud, or application state change is declared.'
        : 'The declared application state change determines integrity impact.',
    },
    {
      impact: 'AVAILABILITY',
      score: availabilityScore,
      level: impactLevel(availabilityScore),
      rationale: availabilityScore === 0
        ? 'No service impact or high-volume activity is declared.'
        : 'Declared execution and request volume create a possible service impact.',
    },
    {
      impact: 'OPERATIONAL_RESPONSE',
      score: noiseScore,
      level: impactLevel(noiseScore),
      rationale: 'The uncalibrated relative-exposure score indicates potential triage or response workload if relevant telemetry collection is enabled.',
    },
  ]
}

function confirmationReasons(riskScore, noiseScore, constraints, violations) {
  const reasons = []
  if (riskScore >= constraints.risk_confirmation_threshold) reasons.push('RISK_THRESHOLD_MET')
  if (noiseScore >= constraints.noise_confirmation_threshold) reasons.push('NOISE_THRESHOLD_MET')
  if (violations.length > 0) reasons.push('PROFILE_CONSTRAINT_EXCEEDED')
  return reasons
}

function assessmentRationale(facts, signals, selection) {
  return [
    `Catalog ${UNLEASH_ACTION_RISK_CATALOG.catalog_id} version ${UNLEASH_ACTION_RISK_CATALOG.catalog_version} was reviewed ${UNLEASH_ACTION_RISK_CATALOG.reviewed_at}.`,
    EFFECT_RATIONALE[facts.effect],
    ...signals
      .filter(({ relative_exposure_score: score }) => score > 0)
      .map(({ control, rationale }) => `${control}: ${rationale}`),
    `Declared volume is ${facts.volume.request_count} request(s), at most ${facts.volume.max_parallel_requests} in parallel and ${facts.volume.max_requests_per_minute} per minute.`,
    `Profile ${selection.operational_profile} requires controller confirmation at risk >= ${selection.constraints.risk_confirmation_threshold} or noise >= ${selection.constraints.noise_confirmation_threshold}.`,
  ]
}

function buildAssessment(facts, selection) {
  const context = actionContext(facts)
  const matchedPatternIds = matchedDetectionPatternIds(facts, context)
  const signals = controlSignals(context, facts.volume)
  const riskScore = inherentRiskScore(facts, context)
  const noiseScore = inherentNoiseScore(signals)
  const violations = profileConstraintViolations(facts.volume, selection.constraints)
  const reasons = confirmationReasons(riskScore, noiseScore, selection.constraints, violations)
  return {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-action-risk-assessment',
    ...catalogFields(),
    scope: 'DEFENDER_OBSERVABILITY_ASSESSMENT',
    methodology: 'HEURISTIC_UNCALIBRATED',
    control_signal_score_semantics: 'RELATIVE_EXPOSURE_NOT_ALERT_PROBABILITY',
    telemetry_coverage: 'UNKNOWN',
    collection_precondition: 'UNKNOWN',
    action_state: 'PROPOSED_INERT',
    executable: false,
    execution_authorized: false,
    ...structuredClone(facts),
    action_fingerprint_sha256: digest(facts),
    matched_pattern_ids: matchedPatternIds,
    operational_profile: selection.operational_profile,
    profile_constraints: structuredClone(selection.constraints),
    profile_constraints_met: violations.length === 0,
    constraint_violations: violations,
    control_signals: signals,
    risk_score: riskScore,
    risk_level: riskLevel(riskScore),
    noise_score: noiseScore,
    noise_level: noiseLevel(noiseScore),
    rationale: assessmentRationale(facts, signals, selection),
    likely_impacts: likelyImpacts(facts, context, noiseScore),
    controller_confirmation_required: reasons.length > 0,
    confirmation_reasons: reasons,
  }
}

function schemaDetails(errors = []) {
  return errors.map((error) => ({
    keyword: error.keyword,
    instance_path: error.instancePath || '/',
    message: error.message ?? 'schema validation failed',
  }))
}

function assertSchema(value, kind, code) {
  const snapshot = clonePlainJson(value)
  if (snapshot.kind !== kind || !validateRiskDocumentSchema(snapshot)) {
    fail(code, `${kind} violates the action-risk schema`, schemaDetails(validateRiskDocumentSchema.errors))
  }
  return snapshot
}

export function assertValidUnleashActionRiskAssessment(value) {
  const snapshot = assertSchema(
    value,
    'last-aperture/unleash-action-risk-assessment',
    'UNLEASH_ACTION_RISK_ASSESSMENT_INVALID',
  )
  const facts = normalizeActionFacts(Object.fromEntries(
    ACTION_FACT_FIELDS.map((field) => [field, snapshot[field]]),
  ))
  const selection = selectUnleashActionRiskProfile(snapshot.operational_profile)
  const expected = buildAssessment(facts, selection)
  if (canonicalJson(snapshot) !== canonicalJson(expected)) {
    fail(
      'UNLEASH_ACTION_RISK_ASSESSMENT_INVALID',
      'action-risk assessment differs from its deterministic classification',
    )
  }
  return value
}

export function assessUnleashActionRisk(value, profile) {
  const facts = normalizeActionFacts(value)
  const selection = selectUnleashActionRiskProfile(profile)
  const assessment = buildAssessment(facts, selection)
  assertValidUnleashActionRiskAssessment(assessment)
  return frozenCopy(assessment)
}

function receiptWithoutDigest(actionId, assessment) {
  return {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-action-risk-receipt',
    ...catalogFields(),
    action_id: actionId,
    action_fingerprint_sha256: assessment.action_fingerprint_sha256,
    assessment_sha256: digest(assessment),
    assessment: structuredClone(assessment),
    controller_confirmation_required: assessment.controller_confirmation_required,
    profile_constraints_met: assessment.profile_constraints_met,
  }
}

export function createUnleashActionRiskReceipt(value) {
  const input = exactDataValues(value, RECEIPT_INPUT_FIELDS, 'action-risk receipt input')
  if (typeof input.action_id !== 'string' || !ID.test(input.action_id)) {
    fail('UNLEASH_ACTION_RISK_RECEIPT_INVALID', 'receipt action_id is invalid')
  }
  assertValidUnleashActionRiskAssessment(input.assessment)
  const assessment = clonePlainJson(input.assessment)
  const unsigned = receiptWithoutDigest(input.action_id, assessment)
  const receipt = { ...unsigned, receipt_sha256: digest(unsigned) }
  assertValidUnleashActionRiskReceipt(receipt, { action_id: input.action_id })
  return frozenCopy(receipt)
}

export function assertValidUnleashActionRiskReceipt(value, binding) {
  const snapshot = assertSchema(
    value,
    'last-aperture/unleash-action-risk-receipt',
    'UNLEASH_ACTION_RISK_RECEIPT_INVALID',
  )
  assertValidUnleashActionRiskAssessment(snapshot.assessment)
  const unsigned = receiptWithoutDigest(snapshot.action_id, snapshot.assessment)
  const expected = { ...unsigned, receipt_sha256: digest(unsigned) }
  if (canonicalJson(snapshot) !== canonicalJson(expected)) {
    fail('UNLEASH_ACTION_RISK_RECEIPT_INVALID', 'receipt digest or assessment projection is invalid')
  }
  if (binding !== undefined) {
    const expectedBinding = exactDataValues(binding, ['action_id'], 'receipt action binding')
    if (expectedBinding.action_id !== snapshot.action_id) {
      fail(
        'UNLEASH_ACTION_RISK_RECEIPT_BINDING_MISMATCH',
        'receipt is not bound to the expected action_id',
      )
    }
  }
  return value
}

export function assertUnleashActionRiskConfirmation(value) {
  const input = exactDataValues(value, CONFIRMATION_INPUT_FIELDS, 'action-risk confirmation input')
  assertValidUnleashActionRiskReceipt(input.receipt)
  if (!input.receipt.profile_constraints_met) {
    fail(
      'UNLEASH_ACTION_RISK_PROFILE_CONSTRAINT_EXCEEDED',
      'action volume exceeds the selected profile execution constraints',
    )
  }
  if (!input.receipt.controller_confirmation_required) {
    if (input.confirmation !== null) {
      fail(
        'UNLEASH_ACTION_RISK_CONFIRMATION_MISMATCH',
        'a confirmation record is not valid when the assessment does not require one',
      )
    }
    return input.receipt
  }
  if (input.confirmation === null) {
    fail(
      'UNLEASH_ACTION_RISK_CONFIRMATION_REQUIRED',
      'controller confirmation is required before action admission',
    )
  }
  const confirmation = exactDataValues(
    input.confirmation,
    CONFIRMATION_FIELDS,
    'controller confirmation',
  )
  assertSchema(
    confirmation,
    'last-aperture/unleash-action-risk-confirmation',
    'UNLEASH_ACTION_RISK_CONFIRMATION_MISMATCH',
  )
  if (
    confirmation.action_id !== input.receipt.action_id
    || confirmation.assessment_sha256 !== input.receipt.assessment_sha256
    || confirmation.receipt_sha256 !== input.receipt.receipt_sha256
    || confirmation.confirmed !== true
  ) {
    fail(
      'UNLEASH_ACTION_RISK_CONFIRMATION_MISMATCH',
      'controller confirmation is not bound to the exact action-risk receipt',
    )
  }
  return input.receipt
}
