import { readFileSync } from 'node:fs'
import { posix, win32 } from 'node:path'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'

const FINDING_SCHEMA_URL = new URL('../../schemas/finding.schema.json', import.meta.url)
const STORE_PROFILE_SCHEMA_URL = new URL('../../schemas/store-profile.schema.json', import.meta.url)
const STORE_CONTRIBUTION_SCHEMA_URL = new URL(
  '../../schemas/store-contribution.schema.json',
  import.meta.url,
)
const JOB_RESULT_SCHEMA_URL = new URL('../../schemas/job-result.schema.json', import.meta.url)
const PROVIDER_CONFIG_SCHEMA_URL = new URL(
  '../../schemas/provider-config.schema.json',
  import.meta.url,
)
const PROVIDER_EXECUTION_SCHEMA_URL = new URL(
  '../../schemas/provider-execution.schema.json',
  import.meta.url,
)
const CONTROLLER_EXECUTION_ENVELOPE_SCHEMA_URL = new URL(
  '../../schemas/controller-execution-envelope.schema.json',
  import.meta.url,
)
const CONTROLLER_FAILURE_ENVELOPE_SCHEMA_URL = new URL(
  '../../schemas/controller-failure-envelope.schema.json',
  import.meta.url,
)

function loadJson(url) {
  return JSON.parse(readFileSync(fileURLToPath(url), 'utf8'))
}

const findingSchema = loadJson(FINDING_SCHEMA_URL)
const storeProfileSchema = loadJson(STORE_PROFILE_SCHEMA_URL)
const storeContributionSchema = loadJson(STORE_CONTRIBUTION_SCHEMA_URL)
export const jobResultSchema = loadJson(JOB_RESULT_SCHEMA_URL)
export const providerConfigSchema = loadJson(PROVIDER_CONFIG_SCHEMA_URL)
export const providerExecutionSchema = loadJson(PROVIDER_EXECUTION_SCHEMA_URL)
export const controllerExecutionEnvelopeSchema = loadJson(
  CONTROLLER_EXECUTION_ENVELOPE_SCHEMA_URL,
)
export const controllerFailureEnvelopeSchema = loadJson(
  CONTROLLER_FAILURE_ENVELOPE_SCHEMA_URL,
)

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})

for (const schema of [
  findingSchema,
  storeProfileSchema,
  storeContributionSchema,
  jobResultSchema,
  providerConfigSchema,
  providerExecutionSchema,
  controllerExecutionEnvelopeSchema,
  controllerFailureEnvelopeSchema,
]) {
  ajv.addSchema(schema)
}

const validateConfigSchema = ajv.getSchema(providerConfigSchema.$id)
const validateExecutionSchema = ajv.getSchema(providerExecutionSchema.$id)
const validateControllerEnvelopeSchema = ajv.getSchema(
  controllerExecutionEnvelopeSchema.$id,
)
const validateControllerFailureEnvelopeSchema = ajv.getSchema(
  controllerFailureEnvelopeSchema.$id,
)

export class ProviderContractError extends Error {
  constructor(message, details = []) {
    super(message)
    this.name = 'ProviderContractError'
    this.code = 'PROVIDER_CONTRACT_INVALID'
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

function contractError(code, instancePath, message, params = {}) {
  return {
    keyword: 'contract',
    code,
    instancePath,
    message,
    params,
  }
}

export function isPortableAbsolutePath(value) {
  return typeof value === 'string'
    && (posix.isAbsolute(value) || win32.isAbsolute(value))
}

function providerConfigSemanticErrors(value) {
  const errors = []
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return errors

  for (const key of ['runtime_path', 'receipt_signing_private_key_path']) {
    if (value[key] !== undefined && !isPortableAbsolutePath(value[key])) {
      errors.push(contractError(
        'PROVIDER_PATH_NOT_ABSOLUTE',
        `/${key}`,
        `${key} must be an absolute POSIX, drive-qualified Windows, or UNC path`,
      ))
    }
    if (typeof value[key] === 'string' && /[\u0000-\u001f\u007f]/.test(value[key])) {
      errors.push(contractError(
        'PROVIDER_PATH_HAS_CONTROL_CHARACTER',
        `/${key}`,
        `${key} cannot contain control characters`,
      ))
    }
  }

  const limits = value.limits
  if (limits === null || typeof limits !== 'object' || Array.isArray(limits)) {
    return errors
  }

  if (
    Number.isSafeInteger(limits.max_file_bytes)
    && Number.isSafeInteger(limits.max_total_delivery_bytes)
    && limits.max_file_bytes > limits.max_total_delivery_bytes
  ) {
    errors.push(contractError(
      'PROVIDER_FILE_LIMIT_EXCEEDS_TOTAL',
      '/limits/max_file_bytes',
      'max_file_bytes cannot exceed max_total_delivery_bytes',
    ))
  }

  if (
    Number.isSafeInteger(limits.max_file_bytes)
    && Number.isSafeInteger(limits.max_frame_bytes)
  ) {
    const minimumDeliveryFrame = Math.ceil(limits.max_file_bytes / 3) * 4 + 8192
    if (limits.max_frame_bytes < minimumDeliveryFrame) {
      errors.push(contractError(
        'PROVIDER_FRAME_TOO_SMALL_FOR_FILE_LIMIT',
        '/limits/max_frame_bytes',
        'max_frame_bytes must fit a base64 file delivery plus bounded protocol metadata',
        { minimum: minimumDeliveryFrame },
      ))
    }
  }

  if (
    Number.isSafeInteger(limits.max_stdout_bytes)
    && Number.isSafeInteger(limits.max_frame_bytes)
    && limits.max_stdout_bytes < limits.max_frame_bytes
  ) {
    errors.push(contractError(
      'PROVIDER_STDOUT_LIMIT_BELOW_FRAME_LIMIT',
      '/limits/max_stdout_bytes',
      'max_stdout_bytes cannot be smaller than max_frame_bytes',
    ))
  }

  if (
    Number.isSafeInteger(limits.tmpfs_bytes)
    && Number.isSafeInteger(limits.memory_bytes)
    && limits.tmpfs_bytes > limits.memory_bytes
  ) {
    errors.push(contractError(
      'PROVIDER_TMPFS_EXCEEDS_MEMORY',
      '/limits/tmpfs_bytes',
      'tmpfs_bytes cannot exceed memory_bytes',
    ))
  }

  for (const key of [
    'docker_command_timeout_ms',
    'idle_timeout_ms',
    'delivery_timeout_ms',
  ]) {
    if (
      Number.isSafeInteger(limits[key])
      && Number.isSafeInteger(limits.wall_time_ms)
      && limits[key] > limits.wall_time_ms
    ) {
      errors.push(contractError(
        'PROVIDER_TIMEOUT_EXCEEDS_WALL_TIME',
        `/limits/${key}`,
        `${key} cannot exceed wall_time_ms`,
      ))
    }
  }

  return errors
}

export function validateProviderConfig(value) {
  const validSchema = validateConfigSchema(value)
  const errors = [
    ...(validSchema ? [] : normalizeAjvErrors(validateConfigSchema.errors)),
    ...providerConfigSemanticErrors(value),
  ]
  return { valid: errors.length === 0, errors }
}

export function assertValidProviderConfig(value) {
  const validation = validateProviderConfig(value)
  if (!validation.valid) {
    throw new ProviderContractError(
      'provider configuration validation failed',
      validation.errors,
    )
  }
  return value
}

function deliverySemanticErrors(delivery, index) {
  const errors = []
  const path = `/receipt/deliveries/${index}`
  if (!Array.isArray(delivery?.events)) return errors

  if (
    delivery.events.length !== 2
    || delivery.events[0]?.state !== 'DELIVERED'
    || delivery.events[1]?.state !== 'CONSUMED'
  ) {
    errors.push(contractError(
      'PROVIDER_DELIVERY_NOT_CONSUMED',
      `${path}/events`,
      'a completed provider execution must contain DELIVERED then CONSUMED events',
    ))
    return errors
  }

  if (delivery.events[0].bytes_sent !== delivery.size) {
    errors.push(contractError(
      'PROVIDER_DELIVERY_SIZE_MISMATCH',
      `${path}/events/0/bytes_sent`,
      'the controller-observed byte count must equal the declared delivery size',
    ))
  }
  if (
    typeof delivery.expected_sha256 === 'string'
    && typeof delivery.events[0].transport_sha256 === 'string'
    && delivery.events[0].transport_sha256 !== delivery.expected_sha256
  ) {
    errors.push(contractError(
      'PROVIDER_DELIVERY_DIGEST_MISMATCH',
      `${path}/events/0/transport_sha256`,
      'the controller-observed transport digest must equal the expected artifact digest',
    ))
  }

  const deliveredAt = Date.parse(delivery.events[0].observed_at)
  const consumedAt = Date.parse(delivery.events[1].observed_at)
  if (Number.isFinite(deliveredAt) && Number.isFinite(consumedAt) && consumedAt < deliveredAt) {
    errors.push(contractError(
      'PROVIDER_CONSUMED_BEFORE_DELIVERY',
      `${path}/events/1/observed_at`,
      'CONSUMED cannot precede DELIVERED',
    ))
  }
  return errors
}

function providerExecutionSemanticErrors(value) {
  const errors = []
  const result = value?.job_result
  const receipt = value?.receipt
  if (
    result === null
    || typeof result !== 'object'
    || receipt === null
    || typeof receipt !== 'object'
  ) {
    return errors
  }

  for (const [resultKey, receiptKey] of [
    ['run_id', 'run_id'],
    ['job_id', 'job_id'],
    ['input_sha256', 'packet_sha256'],
  ]) {
    if (
      typeof result[resultKey] === 'string'
      && typeof receipt[receiptKey] === 'string'
      && result[resultKey].toLowerCase() !== receipt[receiptKey].toLowerCase()
    ) {
      errors.push(contractError(
        'PROVIDER_EXECUTION_BINDING_MISMATCH',
        `/receipt/${receiptKey}`,
        `receipt ${receiptKey} must bind the raw job_result ${resultKey}`,
      ))
    }
  }

  const startedAt = Date.parse(receipt.started_at)
  const completedAt = Date.parse(receipt.completed_at)
  if (Number.isFinite(startedAt) && Number.isFinite(completedAt) && completedAt < startedAt) {
    errors.push(contractError(
      'PROVIDER_EXECUTION_TIME_REVERSED',
      '/receipt/completed_at',
      'completed_at cannot precede started_at',
    ))
  }

  const deliveryIds = new Set()
  const artifactIds = new Set()
  const consumedFiles = new Set()
  const deliveries = Array.isArray(receipt.deliveries) ? receipt.deliveries : []
  for (const [index, delivery] of deliveries.entries()) {
    if (deliveryIds.has(delivery.delivery_id)) {
      errors.push(contractError(
        'PROVIDER_DUPLICATE_DELIVERY_ID',
        `/receipt/deliveries/${index}/delivery_id`,
        'delivery_id values must be unique within an execution receipt',
      ))
    }
    deliveryIds.add(delivery.delivery_id)

    if (artifactIds.has(delivery.artifact_id)) {
      errors.push(contractError(
        'PROVIDER_DUPLICATE_ARTIFACT_DELIVERY',
        `/receipt/deliveries/${index}/artifact_id`,
        'an artifact may be delivered at most once in one provider execution',
      ))
    }
    artifactIds.add(delivery.artifact_id)
    errors.push(...deliverySemanticErrors(delivery, index))
    if (
      delivery.artifact_kind === 'FILE'
      && delivery.events?.[1]?.state === 'CONSUMED'
    ) {
      consumedFiles.add(delivery.logical_name)
    }
  }

  const examinedFiles = Array.isArray(result.examined_files) ? result.examined_files : []
  for (const [index, path] of examinedFiles.entries()) {
    if (!consumedFiles.has(path)) {
      errors.push(contractError(
        'PROVIDER_EXAMINED_FILE_NOT_CONSUMED',
        `/job_result/examined_files/${index}`,
        'examined_files may cite only controller-delivered, challenge-consumed FILE artifacts',
        { path },
      ))
    }
  }

  return errors
}

export function validateProviderExecution(value) {
  const validSchema = validateExecutionSchema(value)
  const errors = [
    ...(validSchema ? [] : normalizeAjvErrors(validateExecutionSchema.errors)),
    ...providerExecutionSemanticErrors(value),
  ]
  return { valid: errors.length === 0, errors }
}

export function assertValidProviderExecution(value) {
  const validation = validateProviderExecution(value)
  if (!validation.valid) {
    throw new ProviderContractError(
      'provider execution validation failed',
      validation.errors,
    )
  }
  return value
}

export function validateControllerExecutionEnvelope(value) {
  const valid = validateControllerEnvelopeSchema(value)
  return {
    valid,
    errors: valid ? [] : normalizeAjvErrors(validateControllerEnvelopeSchema.errors),
  }
}

export function assertValidControllerExecutionEnvelope(value) {
  const validation = validateControllerExecutionEnvelope(value)
  if (!validation.valid) {
    throw new ProviderContractError(
      'controller execution envelope validation failed',
      validation.errors,
    )
  }
  return value
}

export function validateControllerFailureEnvelope(value) {
  const valid = validateControllerFailureEnvelopeSchema(value)
  const errors = valid
    ? []
    : normalizeAjvErrors(validateControllerFailureEnvelopeSchema.errors)
  if (
    valid
    && (
      Object.hasOwn(value.failure, 'partial_receipt')
      !== Object.hasOwn(value.controller, 'partial_receipt_sha256')
    )
  ) {
    errors.push(contractError(
      'CONTROLLER_FAILURE_PARTIAL_RECEIPT_BINDING_MISSING',
      '/controller/partial_receipt_sha256',
      'partial receipt content and digest must either both be present or both be absent',
    ))
  }
  return { valid: errors.length === 0, errors }
}

export function assertValidControllerFailureEnvelope(value) {
  const validation = validateControllerFailureEnvelope(value)
  if (!validation.valid) {
    throw new ProviderContractError(
      'controller failure envelope validation failed',
      validation.errors,
    )
  }
  return value
}
