import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import {
  EVIDENCE_ARTIFACT_KINDS,
  EVIDENCE_CLASSES,
  EVIDENCE_CLASS_ORDER,
  EVIDENCE_COVERAGE_STATES,
  evidenceCoverageStateClears,
  normalizeEvidenceId,
} from './evidence-classes.mjs'

const EVIDENCE_BUNDLE_SCHEMA_URL = new URL(
  '../../schemas/evidence-bundle.schema.json',
  import.meta.url,
)

export const EVIDENCE_BUNDLE_SCHEMA_VERSION = 'evidence-bundle-v1'
export const EVIDENCE_CONTRACT_VERSION = 1

export const evidenceBundleSchema = JSON.parse(
  readFileSync(fileURLToPath(EVIDENCE_BUNDLE_SCHEMA_URL), 'utf8'),
)

// One ajv instance per control plane, as http-recon-contracts.mjs does. The
// repository plane's contracts.mjs stays untouched.
const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})
const validateSchema = ajv.compile(evidenceBundleSchema)

// The schema is data and the registry is code; a drift between them would let
// a bundle declare a class no lens can consume. Fail at import, not at audit.
function assertEnumParity(actual, expected, label) {
  if (JSON.stringify(actual) !== JSON.stringify([...expected])) {
    throw new Error(
      `evidence-bundle.schema.json ${label} has drifted from evidence-classes.mjs`,
    )
  }
}
assertEnumParity(
  evidenceBundleSchema.$defs.evidenceContext.properties.evidence_class.enum,
  EVIDENCE_CLASS_ORDER,
  'evidence_class',
)
assertEnumParity(
  evidenceBundleSchema.properties.coverage_state.enum,
  EVIDENCE_COVERAGE_STATES,
  'coverage_state',
)
assertEnumParity(
  evidenceBundleSchema.properties.artifact_kind.enum,
  EVIDENCE_ARTIFACT_KINDS,
  'artifact_kind',
)

function addError(errors, code, instancePath, message) {
  errors.push({ code, instancePath, message })
}

function normalizeAjvErrors(ajvErrors) {
  return (ajvErrors ?? []).map((error) => ({
    code: `SCHEMA_${String(error.keyword).toUpperCase()}`,
    instancePath: error.instancePath || '',
    message: error.message ?? 'schema validation failed',
  }))
}

// Credential values never enter a bundle; only a credential_ref does
// (contract.md:48). The check is coarse on purpose — a false positive costs an
// operator one rename, a false negative writes a secret to disk.
const CREDENTIAL_VALUE_PATTERNS = [
  /(?:^|[\s"'`])-{1,2}p(?:assword)?[=\s]\S/i,
  /\b(?:password|passwd|secret|token|api[_-]?key|bearer)\s*[:=]\s*\S/i,
  /\b[a-z]+:\/\/[^/\s:@]+:[^/\s@]+@/i,
  /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/,
]

function scanForCredentialValues(value, pointer, errors) {
  if (typeof value === 'string') {
    if (CREDENTIAL_VALUE_PATTERNS.some((pattern) => pattern.test(value))) {
      addError(
        errors,
        'CREDENTIAL_VALUE_PRESENT',
        pointer,
        'a bundle carries a credential reference, never a credential value',
      )
    }
    return
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => scanForCredentialValues(item, `${pointer}/${index}`, errors))
    return
  }
  if (value !== null && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      scanForCredentialValues(item, `${pointer}/${key}`, errors)
    }
  }
}

function profileInvariantErrors(profile) {
  const errors = []
  if (profile === null || typeof profile !== 'object' || Array.isArray(profile)) {
    return errors
  }

  try {
    normalizeEvidenceId(profile.evidence_context?.evidence_id)
  } catch (error) {
    addError(errors, 'EVIDENCE_ID_INVALID', '/evidence_context/evidence_id', error.message)
  }

  const state = profile.coverage_state
  const files = Array.isArray(profile.files) ? profile.files : []
  const gaps = Array.isArray(profile.coverage_gaps) ? profile.coverage_gaps : []

  // No adapter may report COVERED with an empty payload. A missing dependency
  // is a failure, never an empty success.
  if (state === 'COVERED' && files.length === 0) {
    addError(
      errors,
      'EMPTY_COVERED_PAYLOAD',
      '/files',
      'COVERED requires at least one acquired file; an empty payload is NOT_ASSESSED',
    )
  }
  if (
    typeof state === 'string'
    && EVIDENCE_COVERAGE_STATES.includes(state)
    && !evidenceCoverageStateClears(state)
    && gaps.length === 0
  ) {
    addError(
      errors,
      'UNNAMED_COVERAGE_GAP',
      '/coverage_gaps',
      `${state} requires a named reason in coverage_gaps`,
    )
  }
  if (state === 'PARTIAL' && gaps.length === 0) {
    addError(
      errors,
      'UNNAMED_COVERAGE_GAP',
      '/coverage_gaps',
      'PARTIAL requires the omissions to be listed in coverage_gaps',
    )
  }

  const evidenceClass = profile.evidence_context?.evidence_class
  const hasArtifactKind = Object.hasOwn(profile, 'artifact_kind')
  if (evidenceClass === EVIDENCE_CLASSES.BUILT_ARTIFACT && !hasArtifactKind) {
    addError(
      errors,
      'ARTIFACT_KIND_REQUIRED',
      '/artifact_kind',
      'a built-artifact bundle names the artifact kind it carries',
    )
  }
  if (evidenceClass !== EVIDENCE_CLASSES.BUILT_ARTIFACT && hasArtifactKind) {
    addError(
      errors,
      'ARTIFACT_KIND_NOT_APPLICABLE',
      '/artifact_kind',
      `artifact_kind is meaningless for evidence class ${String(evidenceClass)}`,
    )
  }

  if (profile.phi_bearing === true && profile.phi_scope === 'none') {
    addError(
      errors,
      'PHI_SCOPE_CONTRADICTION',
      '/phi_bearing',
      'phi_bearing content cannot be captured under an attested phi_scope of none',
    )
  }

  const paths = new Set()
  for (const [index, file] of files.entries()) {
    if (paths.has(file?.path)) {
      addError(
        errors,
        'DUPLICATE_BUNDLE_PATH',
        `/files/${index}/path`,
        `bundle payload contains duplicate path: ${String(file?.path)}`,
      )
    }
    paths.add(file?.path)
  }

  scanForCredentialValues(profile, '', errors)
  return errors
}

export function validateEvidenceProfile(profile) {
  const schemaValid = validateSchema(profile)
  const errors = schemaValid ? [] : normalizeAjvErrors(validateSchema.errors)
  errors.push(...profileInvariantErrors(profile))
  return { valid: errors.length === 0, errors }
}

export class EvidenceContractValidationError extends Error {
  constructor(message, errors) {
    const detail = errors
      .map((error) => `${error.instancePath || '/'} [${error.code}]: ${error.message}`)
      .join('\n')
    super(detail ? `${message}\n${detail}` : message)
    this.name = 'EvidenceContractValidationError'
    this.errors = errors
  }
}

export function assertValidEvidenceProfile(profile) {
  const validation = validateEvidenceProfile(profile)
  if (!validation.valid) {
    throw new EvidenceContractValidationError(
      'Evidence bundle contract validation failed',
      validation.errors,
    )
  }
  return profile
}
