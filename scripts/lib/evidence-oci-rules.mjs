export const OCI_EVIDENCE_RULE = Object.freeze({
  whiteout: 'ev.built-artifact.oci.whiteout-named-file-with-content',
  orphan: 'ev.built-artifact.oci.blob-unreferenced-by-manifest',
  sibling: 'ev.built-artifact.oci.sibling-size-mtime-outlier',
  recursive: 'ev.built-artifact.oci.recursive-encoded-payload',
  history: 'ev.built-artifact.oci.secret-in-config-history',
})

export const OCI_EVIDENCE_RULE_CLAIMS = Object.freeze({
  [OCI_EVIDENCE_RULE.whiteout]: 'unexpected-artifact-content',
  [OCI_EVIDENCE_RULE.orphan]: 'unexpected-artifact-content',
  [OCI_EVIDENCE_RULE.sibling]: 'unexpected-artifact-content',
  [OCI_EVIDENCE_RULE.recursive]: 'unexpected-artifact-content',
  [OCI_EVIDENCE_RULE.history]: 'secret-present-in-artifact',
})

export const OCI_EVIDENCE_RULE_SUPPORT = Object.freeze({
  [OCI_EVIDENCE_RULE.whiteout]: Object.freeze({
    lens: 'cloud-and-iac',
    topic: 'dockerfile-and-image-content',
    claim: 'unexpected-artifact-content',
  }),
  [OCI_EVIDENCE_RULE.orphan]: Object.freeze({
    lens: 'cloud-and-iac',
    topic: 'dockerfile-and-image-content',
    claim: 'unexpected-artifact-content',
  }),
  [OCI_EVIDENCE_RULE.sibling]: Object.freeze({
    lens: 'cloud-and-iac',
    topic: 'dockerfile-and-image-content',
    claim: 'unexpected-artifact-content',
  }),
  [OCI_EVIDENCE_RULE.recursive]: Object.freeze({
    lens: 'cloud-and-iac',
    topic: 'dockerfile-and-image-content',
    claim: 'unexpected-artifact-content',
  }),
  [OCI_EVIDENCE_RULE.history]: Object.freeze({
    lens: 'crypto-and-key-management',
    topic: 'hardcoded-credentials-and-key-material',
    claim: 'secret-present-in-artifact',
  }),
})

export const OCI_EVIDENCE_RULE_IDS = Object.freeze(
  Object.keys(OCI_EVIDENCE_RULE_CLAIMS).sort(),
)

const EXPLICIT_CREDENTIAL_PATTERNS = Object.freeze([
  /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
  /\bgh[pousr]_[A-Za-z0-9]{30,}\b/,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
  /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,
])

const CREDENTIAL_FIELD = /(?:^|[_-])(?:password|passwd|pass|secret|token|api[_-]?key|private[_-]?key)(?:$|[_-])/i
const NON_CREDENTIAL_FIELD = /(?:^|[_-])(?:policy|prompt|field|label|name|path|file|manager|length|minimum|maximum|rotation|ttl|expiry|algorithm|url|uri|id|identifier|arn|ref|reference)(?:$|[_-])/i
const PLACEHOLDER_VALUE_PATTERNS = Object.freeze([
  /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/,
  /^(?:env|file|keychain|vault):/i,
  /^(?:true|false|null|none|required|optional|enabled|disabled|redacted|masked|changeme|change[-_]?me|example|dummy|placeholder|password|secret|token|policy)$/i,
  /^(?:your|my)[-_]?(?:password|secret|token|api[-_]?key)(?:[-_]?here)?$/i,
  /^(?:<[^>]+>|\{\{[^}]+\}\}|\[[^\]]+\]|\*+)$/,
  /^\/(?:run|var\/run)\/secrets?\//i,
])

function concreteAssignedCredential(value) {
  const candidate = String(value).trim()
  const concreteDefault = candidate.match(
    /^\$\{[A-Za-z_][A-Za-z0-9_]*:-([^}]*)\}$/,
  )
  if (concreteDefault) return concreteAssignedCredential(concreteDefault[1])
  return candidate.length >= 6
    && /[A-Za-z0-9]/.test(candidate)
    && !/[$`]/.test(candidate)
    && !PLACEHOLDER_VALUE_PATTERNS.some((pattern) => pattern.test(candidate))
}

function compareText(left, right) {
  const a = String(left)
  const b = String(right)
  return a < b ? -1 : a > b ? 1 : 0
}

/**
 * Detect credential material in an OCI config history command without
 * returning the command or matched value. A keyword by itself is not proof:
 * the history must contain a concrete assignment value or a credential format
 * whose shape is independently discriminating.
 */
export function historyContainsCredentialMaterial(value) {
  const command = String(value ?? '')
  if (EXPLICIT_CREDENTIAL_PATTERNS.some((pattern) => pattern.test(command))) {
    return true
  }
  for (const match of command.matchAll(
    /\b[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:([^/\s@]+)@/gi,
  )) {
    if (concreteAssignedCredential(match[1])) return true
  }
  const assignments = command.matchAll(
    /\b([A-Za-z_][A-Za-z0-9_-]*)["']?\s*(?:=|:)\s*(?:"([^"\r\n]*)"|'([^'\r\n]*)'|([^\s;&|,]+))/g,
  )
  for (const match of assignments) {
    if (!CREDENTIAL_FIELD.test(match[1])) continue
    if (NON_CREDENTIAL_FIELD.test(match[1])) continue
    if (concreteAssignedCredential(match[2] ?? match[3] ?? match[4] ?? '')) {
      return true
    }
  }
  return false
}

/**
 * Mark file entries that differ in both size and mtime from a stable sibling
 * baseline. The baseline is a joint pair shared by at least four files. Equal
 * largest groups are ambiguous and intentionally produce no match.
 */
export function markOciSiblingOutliers(entries) {
  const byDirectory = new Map()
  for (const entry of entries) {
    if (entry.kind !== 'layer-entry' || entry.type !== 'file') continue
    const segments = entry.path.split('/')
    const directory = segments.slice(0, -1).join('/')
    const key = `${entry.layer}\0${directory}`
    const siblings = byDirectory.get(key) ?? []
    siblings.push(entry)
    byDirectory.set(key, siblings)
  }

  for (const siblings of byDirectory.values()) {
    const groups = new Map()
    for (const sibling of siblings) {
      const key = JSON.stringify([sibling.size, sibling.mtime])
      const group = groups.get(key) ?? {
        size: sibling.size,
        mtime: sibling.mtime,
        count: 0,
      }
      group.count += 1
      groups.set(key, group)
    }
    const baselines = [...groups.values()]
      .filter(({ count }) => count >= 4)
      .sort((left, right) =>
        right.count - left.count
        || left.size - right.size
        || compareText(left.mtime, right.mtime))
    if (
      baselines.length === 0
      || (baselines[1] && baselines[1].count === baselines[0].count)
    ) {
      continue
    }
    const baseline = baselines[0]
    for (const entry of siblings) {
      if (entry.size !== baseline.size && entry.mtime !== baseline.mtime) {
        entry.matched_rule_ids ??= []
        if (!entry.matched_rule_ids.includes(OCI_EVIDENCE_RULE.sibling)) {
          entry.matched_rule_ids.push(OCI_EVIDENCE_RULE.sibling)
        }
      }
    }
  }
}
