import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { compareCanonicalStrings } from './canonical-order.mjs'
import { EVIDENCE_CLASS_ORDER, isEvidenceClass } from './evidence-classes.mjs'

export const EVIDENCE_ADAPTER_MANIFEST_URL = new URL(
  '../../skills/last-aperture/lenses/_evidence-adapters/manifest.json',
  import.meta.url,
)

export const evidenceAdapterManifest = JSON.parse(
  readFileSync(fileURLToPath(EVIDENCE_ADAPTER_MANIFEST_URL), 'utf8'),
)

const BY_ID = new Map(
  evidenceAdapterManifest.adapters.map((adapter) => [adapter.adapter_id, adapter]),
)

const FALLBACK = Object.freeze({
  ...evidenceAdapterManifest.fallback,
  evidence_class: null,
  external_dependency: null,
  authorization: Object.freeze({
    attestation: false,
    credential_ref: false,
    target_class: false,
    operator_identity: false,
    impact_counters: false,
    kill_switch: false,
  }),
})

export function evidenceAdapterIds() {
  return [...BY_ID.keys(), evidenceAdapterManifest.fallback.adapter_id]
    .sort(compareCanonicalStrings)
}

/**
 * An unlisted acquisition target selects inventory-only, mirroring the
 * database router. Manufacturing an adapter ID from a hostname or a file
 * extension is the failure this prevents.
 */
export function resolveEvidenceAdapter(adapterId) {
  const adapter = BY_ID.get(adapterId)
  if (!adapter) return FALLBACK
  return Object.freeze({
    adapter_id: adapter.adapter_id,
    evidence_class: adapter.evidence_class,
    adapter_file: adapter.adapter_file,
    selection_status: 'SELECTED',
    external_dependency: adapter.external_dependency,
    authorization: Object.freeze({ ...adapter.authorization }),
  })
}

const SEGMENT_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/
const VERSION_SUFFIX_PATTERN = /(?:^|-)v[0-9]+$/
const SEVERITY_TOKENS = new Set(['critical', 'high', 'medium', 'low', 'info'])

export function evidenceRuleIdErrors(ruleId, { adapterId } = {}) {
  const errors = []
  if (typeof ruleId !== 'string' || ruleId !== ruleId.toLowerCase()) {
    return ['rule ID must be a lowercase ASCII string']
  }
  const segments = ruleId.split('.')
  if (segments.length !== 4 || segments[0] !== 'ev') {
    return [`rule ID must be ev.<evidence-class>.<adapter-id>.<semantic-name>: ${ruleId}`]
  }
  const [, evidenceClass, adapterSegment, semanticName] = segments
  if (!isEvidenceClass(evidenceClass)) {
    errors.push(
      `rule ID class segment must be one of ${EVIDENCE_CLASS_ORDER.join(', ')}: ${evidenceClass}`,
    )
  }
  for (const [label, segment] of [['adapter', adapterSegment], ['semantic name', semanticName]]) {
    if (!SEGMENT_PATTERN.test(segment)) {
      errors.push(`rule ID ${label} segment must be lowercase hyphen-separated ASCII: ${segment}`)
    }
  }
  if (adapterId !== undefined && adapterSegment !== adapterId) {
    errors.push(
      `rule ID adapter segment ${adapterSegment} is not the selected adapter ${adapterId}`,
    )
  }
  if (VERSION_SUFFIX_PATTERN.test(semanticName) || /\d/.test(semanticName.split('-').at(-1))) {
    errors.push(`rule ID must carry no version or sequence number: ${semanticName}`)
  }
  if (semanticName.split('-').some((token) => SEVERITY_TOKENS.has(token))) {
    errors.push(`rule ID must carry no severity: ${semanticName}`)
  }
  return errors
}

const RULE_ANCHOR_PATTERN = /^#{3,}\s+`(ev\.[a-z0-9.-]+)`\s*$/gm

/**
 * A rule ID is valid only where the owning document declares it as an anchor.
 * The predicate is positional for the same reason R8's is: a rule ID quoted in
 * prose or inside a fenced example is discussion, not a declaration.
 */
export function declaredEvidenceRuleAnchors(markdownText) {
  const anchors = new Set()
  const withoutFences = String(markdownText).replace(/^ {0,3}```[\s\S]*?^ {0,3}```\s*$/gm, '')
  for (const match of withoutFences.matchAll(RULE_ANCHOR_PATTERN)) {
    anchors.add(match[1])
  }
  return anchors
}
