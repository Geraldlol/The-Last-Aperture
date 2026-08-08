import { createHash } from 'node:crypto'

export const PHI_SCOPES = Object.freeze(['none', 'possible', 'confirmed'])
export const PHI_RETENTION_DAYS = 30
const DEFAULT_MAX_DEPTH = 12
// Structure is identified by the FIELD NAME, never by the shape of the value.
// A value-shape heuristic leaks: base64 PHI is frequently pure alphanumeric and
// is indistinguishable from a resource kind by inspection. These five names are
// what an audit needs to reason at all, and none of them carries record data.
const STRUCTURAL_DEPTH = 2
const STRUCTURAL_KEYS = new Set(['kind', 'apiVersion', 'name', 'namespace', 'type'])

/**
 * Gated on declared PHI scope, independent of target class, so a non-PHI
 * production system pays no PHI friction while a PHI-bearing lab still does.
 *
 * The default matters more than the option: a deployed-state or live-runtime
 * read against production can pull real PHI into a local bundle, and writing
 * an unencrypted PHI-bearing bundle would create a new breach surface using
 * the audit tool itself.
 */
export function resolvePhiPolicy({ phiScope, captureContents = false, acknowledged = false } = {}) {
  if (!PHI_SCOPES.includes(phiScope)) {
    throw new Error(
      `phi_scope must be one of ${PHI_SCOPES.join(', ')}; received ${JSON.stringify(phiScope)}`,
    )
  }
  if (phiScope === 'none') {
    return { scope: phiScope, capture_contents: true, phi_bearing: false, retention_days: null }
  }
  if (!captureContents) {
    return { scope: phiScope, capture_contents: false, phi_bearing: false, retention_days: null }
  }
  if (phiScope === 'confirmed' && !acknowledged) {
    throw new Error(
      'capturing contents under phi_scope confirmed requires an explicit acknowledgment',
    )
  }
  return {
    scope: phiScope,
    capture_contents: true,
    phi_bearing: true,
    retention_days: phiScope === 'confirmed' ? PHI_RETENTION_DAYS : null,
  }
}

function scalarMetadata(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value) ?? String(value)
  return {
    type: typeof value,
    bytes: Buffer.byteLength(text, 'utf8'),
    sha256: createHash('sha256').update(text, 'utf8').digest('hex'),
  }
}

/**
 * Metadata-only means names, shapes, sizes, hashes and key names — never
 * values or record contents. Key names survive because "there is a key called
 * PATIENT_EXPORT here" is exactly the finding; its bytes are not.
 */
export function redactToMetadata(value, { maxDepth = DEFAULT_MAX_DEPTH, depth = 0 } = {}) {
  if (depth >= maxDepth) return '[depth]'
  if (value === null || value === undefined) return value ?? null
  if (Array.isArray(value)) {
    return value.map((item) => redactToMetadata(item, { maxDepth, depth: depth + 1 }))
  }
  if (typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        key,
        typeof item === 'string'
          && STRUCTURAL_KEYS.has(key)
          && depth + 1 <= STRUCTURAL_DEPTH
          ? item
          : redactToMetadata(item, { maxDepth, depth: depth + 1 }),
      ]),
    )
  }
  return scalarMetadata(value)
}
