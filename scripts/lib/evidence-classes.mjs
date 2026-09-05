// Canonical evidence classes. This is the detection-precedence rule from
// _database-adapters/contract.md:435-444 promoted from one lens to the
// registry: a built artifact outranks the source that claims to produce it,
// and runtime state outranks both. Pure data plus predicates — no file I/O, so
// the rules stay testable without the corpus.
//
// Not to be confused with coverage-model.mjs's COVERAGE_CLASSES, which
// classifies files in the repository. That is a different axis; everything
// here is prefixed EVIDENCE_.
export const EVIDENCE_CLASSES = Object.freeze({
  SOURCE: 'source',
  BUILT_ARTIFACT: 'built-artifact',
  DEPLOYED_STATE: 'deployed-state',
  LIVE_RUNTIME: 'live-runtime',
})

// Ascending precedence: index + 1 is the rank. Exploitation is deliberately
// absent — it is a mutation tier layered on live-runtime in Phase 3, not a
// class.
export const EVIDENCE_CLASS_ORDER = Object.freeze([
  EVIDENCE_CLASSES.SOURCE,
  EVIDENCE_CLASSES.BUILT_ARTIFACT,
  EVIDENCE_CLASSES.DEPLOYED_STATE,
  EVIDENCE_CLASSES.LIVE_RUNTIME,
])

export const EVIDENCE_ARTIFACT_KINDS = Object.freeze([
  'apk',
  'desktop-package',
  'dist-bundle',
  'firmware-image',
  'ipa',
  'jar',
  'model-bundle',
  'native-executable',
  'oci-image',
  'sbom',
  'shared-library',
  'smart-contract-build',
  'vex',
])

// The database contract's coverage vocabulary, verbatim. A parallel state set
// would be the shadow-registry failure _schema.md:107 warns about, and these
// five already carry the never-render-as-clean rule this whole subsystem
// exists to reuse.
export const EVIDENCE_COVERAGE_STATES = Object.freeze([
  'COVERED',
  'PARTIAL',
  'INVENTORY_ONLY',
  'NOT_ASSESSED',
  'NOT_APPLICABLE',
])

const NON_CLEARING_COVERAGE_STATES = new Set(['INVENTORY_ONLY', 'NOT_ASSESSED'])

// What a finding derived from a non-source class is permitted to assert. A
// lens bounds itself to a subset of these in activates_on.evidence_classes;
// an unbounded vocabulary would let every lens claim every class.
export const EVIDENCE_CLAIM_KINDS = Object.freeze([
  'artifact-signature-invalid',
  'binary-hardening-missing',
  'drift-from-source',
  'firmware-trust-gap',
  'model-integrity-or-robustness-gap',
  'resilience-policy-misconfiguration',
  'runtime-misconfiguration',
  'secret-present-in-artifact',
  'sensitive-data-at-rest',
  'smart-contract-deployment-drift',
  'telemetry-delivery-failure',
  'unexpected-artifact-content',
  'vulnerable-component-present',
])

// The floor, not the requirement. An adapter declares its own requirements in
// manifest.json and may exceed these; it may never fall below them. Reading a
// supplied tarball needs no attestation, so built-artifact's floor is empty
// and the registry adapter raises its own bar.
const AUTHORIZATION_FLOOR = Object.freeze({
  [EVIDENCE_CLASSES.SOURCE]: Object.freeze({
    attestation: false,
    credential_ref: false,
    target_class: false,
    operator_identity: false,
    impact_counters: false,
    kill_switch: false,
  }),
  [EVIDENCE_CLASSES.BUILT_ARTIFACT]: Object.freeze({
    attestation: false,
    credential_ref: false,
    target_class: false,
    operator_identity: false,
    impact_counters: false,
    kill_switch: false,
  }),
  // An unbounded read against production is an availability risk regardless of
  // intent, so counters and a kill switch are floors for both live classes
  // even though both are read-only.
  [EVIDENCE_CLASSES.DEPLOYED_STATE]: Object.freeze({
    attestation: true,
    credential_ref: false,
    target_class: true,
    operator_identity: true,
    impact_counters: true,
    kill_switch: true,
  }),
  [EVIDENCE_CLASSES.LIVE_RUNTIME]: Object.freeze({
    attestation: true,
    credential_ref: false,
    target_class: true,
    operator_identity: true,
    impact_counters: true,
    kill_switch: true,
  }),
})

const EVIDENCE_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/
// store_id may not carry a hostname (contract.md:163-164) and neither may an
// evidence id: a handle that names where the evidence came from leaks target
// topology into every finding that references it. Dots are already excluded by
// the pattern, so only the dotless host-shaped names need naming here.
const HOST_SHAPED_EVIDENCE_IDS = new Set([
  'host',
  'hostname',
  'localhost',
  'localdomain',
])

export function isEvidenceClass(value) {
  return EVIDENCE_CLASS_ORDER.includes(value)
}

export function assertEvidenceClass(value) {
  if (!isEvidenceClass(value)) {
    throw new TypeError(
      `unknown evidence class ${JSON.stringify(value)}; expected one of `
      + EVIDENCE_CLASS_ORDER.join(', '),
    )
  }
  return value
}

export function evidenceClassPrecedence(value) {
  return EVIDENCE_CLASS_ORDER.indexOf(assertEvidenceClass(value)) + 1
}

export function compareEvidenceClassPrecedence(left, right) {
  return evidenceClassPrecedence(left) - evidenceClassPrecedence(right)
}

export function higherPrecedenceEvidenceClass(left, right) {
  return compareEvidenceClassPrecedence(left, right) >= 0 ? left : right
}

export function isEvidenceCoverageState(value) {
  return EVIDENCE_COVERAGE_STATES.includes(value)
}

export function evidenceCoverageStateClears(state) {
  if (!isEvidenceCoverageState(state)) {
    throw new TypeError(`unknown evidence coverage state ${JSON.stringify(state)}`)
  }
  return !NON_CLEARING_COVERAGE_STATES.has(state)
}

export function isEvidenceArtifactKind(value) {
  return EVIDENCE_ARTIFACT_KINDS.includes(value)
}

export function isEvidenceClaimKind(value) {
  return EVIDENCE_CLAIM_KINDS.includes(value)
}

export function evidenceClassAuthorizationFloor(value) {
  return AUTHORIZATION_FLOOR[assertEvidenceClass(value)]
}

export function normalizeEvidenceId(value) {
  if (typeof value !== 'string') {
    throw new TypeError('evidence_id must be a string')
  }
  const normalized = value.trim()
  if (!EVIDENCE_ID_PATTERN.test(normalized)) {
    throw new TypeError(
      'evidence_id must be 1-64 lowercase ASCII characters, digits or hyphens, '
      + `starting with a letter or digit; received ${JSON.stringify(value)}`,
    )
  }
  if (HOST_SHAPED_EVIDENCE_IDS.has(normalized) || /^\d+(?:-\d+){3}$/.test(normalized)) {
    throw new TypeError(`evidence_id must not name a host: ${JSON.stringify(value)}`)
  }
  return normalized
}
