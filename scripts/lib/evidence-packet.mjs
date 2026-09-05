import { createHash } from 'node:crypto'
import { compareCanonicalStrings } from './canonical-order.mjs'
import {
  loadEvidenceBundle,
  readEvidencePayloadFile,
} from './evidence-bundle.mjs'
import {
  OCI_EVIDENCE_RULE,
  OCI_EVIDENCE_RULE_IDS,
  OCI_EVIDENCE_RULE_SUPPORT,
  historyContainsCredentialMaterial,
  markOciSiblingOutliers,
} from './evidence-oci-rules.mjs'

export const DEFAULT_EVIDENCE_PACKET_LIMITS = Object.freeze({
  maxEntriesPerBundle: 2000,
})

function decodePrintableBase64(text) {
  if (!/^[A-Za-z0-9+/]{16,}={0,2}$/.test(text)) return null
  const decoded = Buffer.from(text, 'base64').toString('utf8')
  return /^[\x20-\x7e\s]+$/.test(decoded) ? decoded : null
}

function containsRecursiveEncoding(bytes) {
  const text = bytes.toString('utf8')
  return (text.match(/[A-Za-z0-9+/]{16,}={0,2}/g) ?? []).some((token) => {
    const once = decodePrintableBase64(token)
    return once !== null && decodePrintableBase64(once.trim()) !== null
  })
}

/**
 * The normalized entry index of one acquired bundle, read at plan time.
 *
 * Fan-out gets bounded observations, not the bytes. The controller verifies
 * every indexed payload read against the sealed manifest and evaluates the
 * declared OCI rules before dispatch. A lens may cite only a locator/rule pair
 * that this controller-owned analysis matched. Embedding complete image bytes
 * in every provider packet would multiply sensitive evidence unnecessarily.
 *
 * Truncation is reported, never silent: a lens that was handed 2000 of 5000
 * entries and told nothing would report on a subset as though it were the set.
 */
export async function readEvidenceIndex(directory, limits = DEFAULT_EVIDENCE_PACKET_LIMITS) {
  const maxEntriesPerBundle = limits?.maxEntriesPerBundle
    ?? DEFAULT_EVIDENCE_PACKET_LIMITS.maxEntriesPerBundle
  if (!Number.isSafeInteger(maxEntriesPerBundle) || maxEntriesPerBundle < 1) {
    throw new RangeError('maxEntriesPerBundle must be a positive safe integer')
  }
  let bundle
  try {
    bundle = await loadEvidenceBundle(directory)
  } catch {
    return {
      locator_index_kind: 'oci-layer-v1',
      entries: [],
      layers: [],
      truncated: 0,
      unreadable: true,
    }
  }
  const declaredFiles = new Map(
    (bundle.profile.files ?? []).map((file) => [file.path, file]),
  )
  const readBytes = async (path) => {
    try {
      const bytes = await readEvidencePayloadFile(directory, path)
      const declared = declaredFiles.get(path)
      const digest = createHash('sha256').update(bytes).digest('hex')
      if (
        !declared
        || declared.size !== bytes.length
        || declared.sha256 !== digest
      ) {
        return null
      }
      return bytes
    } catch {
      return null
    }
  }
  const read = async (path) => {
    const bytes = await readBytes(path)
    if (bytes === null) return null
    try {
      return JSON.parse(bytes.toString('utf8'))
    } catch {
      return null
    }
  }
  if (
    bundle.evidence_context.evidence_class !== 'built-artifact'
    || bundle.profile.artifact_kind !== 'oci-image'
  ) {
    return {
      locator_index_kind: 'unsupported',
      unsupported_reason:
        'provider evidence-byte delivery is not implemented for this evidence class and artifact kind',
      entries: [],
      layers: [],
      truncated: 0,
      unreadable: false,
    }
  }

  const normalized = await read('payload/normalized.json')
  const history = await read('payload/config/history.json')
  const orphans = await read('payload/orphan-blobs.json')
  if (
    !normalized
    || !Array.isArray(normalized.layers)
    || !Array.isArray(history)
    || !Array.isArray(orphans)
  ) {
    return {
      locator_index_kind: 'oci-layer-v1',
      entries: [],
      layers: [],
      truncated: 0,
      unreadable: true,
    }
  }

  const entries = []
  const locators = new Set()
  const completeLayerMetadata = []
  let truncated = 0
  for (const layer of normalized.layers ?? []) {
    const layerEntries = await read(`payload/layers/${layer.directory}/entries.json`)
    if (!Array.isArray(layerEntries)) {
      return {
        locator_index_kind: 'oci-layer-v1',
        entries,
        layers: [],
        truncated,
        unreadable: true,
      }
    }
    for (const entry of layerEntries) {
      const locator = `layer/${layer.directory}/${entry.path}`
      if (locators.has(locator)) {
        return {
          locator_index_kind: 'oci-layer-v1',
          entries,
          layers: [],
          truncated,
          unreadable: true,
        }
      }
      locators.add(locator)
      completeLayerMetadata.push({
        locator,
        kind: 'layer-entry',
        path: entry.path,
        layer: layer.index,
        mode: entry.mode,
        size: entry.size,
        mtime: entry.mtime,
        type: entry.type,
        whiteout: entry.whiteout,
        matched_rule_ids: [],
      })
      if (entries.length >= maxEntriesPerBundle) {
        truncated += 1
        continue
      }
      const contentPath = `payload/layers/${layer.directory}/content/${entry.path}`
      const contentCaptured = declaredFiles.has(contentPath)
      const matchedRuleIds = []
      if (
        entry.path.split('/').at(-1).startsWith('.wh.')
        && entry.whiteout === false
      ) {
        matchedRuleIds.push(OCI_EVIDENCE_RULE.whiteout)
      }
      if (contentCaptured) {
        const content = await readBytes(contentPath)
        if (content === null) {
          return {
            locator_index_kind: 'oci-layer-v1',
            entries,
            layers: [],
            truncated,
            unreadable: true,
          }
        }
        if (containsRecursiveEncoding(content)) {
          matchedRuleIds.push(OCI_EVIDENCE_RULE.recursive)
        }
      }
      entries.push({
        locator,
        kind: 'layer-entry',
        path: entry.path,
        layer: layer.index,
        mode: entry.mode,
        size: entry.size,
        mtime: entry.mtime,
        type: entry.type,
        whiteout: entry.whiteout,
        content_captured: contentCaptured,
        matched_rule_ids: matchedRuleIds,
      })
    }
  }

  // A sibling baseline is contextual: deriving it from the packet prefix can
  // manufacture an outlier when truncation splits two equally sized groups.
  // Evaluate against the complete, manifest-verified metadata and project only
  // the verdicts for entries retained in the bounded provider packet.
  markOciSiblingOutliers(completeLayerMetadata)
  const siblingMatches = new Set(
    completeLayerMetadata
      .filter(({ matched_rule_ids: ids }) => ids.includes(OCI_EVIDENCE_RULE.sibling))
      .map(({ locator }) => locator),
  )
  for (const entry of entries) {
    if (siblingMatches.has(entry.locator)) {
      entry.matched_rule_ids.push(OCI_EVIDENCE_RULE.sibling)
    }
  }

  for (const orphan of orphans) {
    const locator = `orphan/${orphan.digest}`
    if (locators.has(locator)) {
      return {
        locator_index_kind: 'oci-layer-v1',
        entries,
        layers: [],
        truncated,
        unreadable: true,
      }
    }
    locators.add(locator)
    if (entries.length >= maxEntriesPerBundle) {
      truncated += 1
      continue
    }
    entries.push({
      locator,
      kind: 'orphan',
      digest: orphan.digest,
      size: orphan.size,
      content_captured: true,
      matched_rule_ids: [OCI_EVIDENCE_RULE.orphan],
    })
  }

  for (const [index, item] of history.entries()) {
    if (entries.length >= maxEntriesPerBundle) {
      truncated += 1
      continue
    }
    const locator = `config/history[${index}]`
    const createdBy = String(item?.created_by ?? '')
    const credentialMaterialDetected = historyContainsCredentialMaterial(createdBy)
    entries.push({
      locator,
      kind: 'config-history',
      history_index: index,
      content_captured: true,
      credential_material_detected: credentialMaterialDetected,
      created_by_sha256: createHash('sha256').update(createdBy).digest('hex'),
      matched_rule_ids: credentialMaterialDetected
        ? [OCI_EVIDENCE_RULE.history]
        : [],
    })
  }

  for (const entry of entries) {
    entry.matched_rule_ids.sort(compareCanonicalStrings)
  }

  return {
    locator_index_kind: 'oci-layer-v1',
    rule_analysis: {
      evaluated_rule_ids: OCI_EVIDENCE_RULE_IDS,
      controller_evaluated: true,
      raw_evidence_bytes_delivered: false,
    },
    entries,
    layers: (normalized.layers ?? []).map(({ index, directory: dir, digest, entry_count: count }) => ({
      index,
      directory: dir,
      digest,
      entry_count: count,
    })),
    truncated,
    unreadable: false,
  }
}

function requiredMatchesForLens(lensName, bundle) {
  const index = bundle.index
  if (
    index?.locator_index_kind !== 'oci-layer-v1'
    || index.unreadable !== false
    || !Number.isSafeInteger(index.truncated)
    || index.truncated < 0
    || index.rule_analysis?.controller_evaluated !== true
  ) {
    return []
  }
  const matches = []
  for (const entry of index.entries ?? []) {
    for (const ruleId of entry.matched_rule_ids ?? []) {
      const support = OCI_EVIDENCE_RULE_SUPPORT[ruleId]
      if (support?.lens !== lensName) continue
      matches.push({
        evidence_id: bundle.evidence_context.evidence_id,
        locator: entry.locator,
        adapter_rule_id: ruleId,
        topic: support.topic,
        evidence_claim: support.claim,
      })
    }
  }
  return matches.sort((left, right) =>
    compareCanonicalStrings(left.evidence_id, right.evidence_id)
    || compareCanonicalStrings(left.locator, right.locator)
    || compareCanonicalStrings(left.adapter_rule_id, right.adapter_rule_id))
}

/**
 * Which acquired bundles one lens may reason over, and the evidence it is
 * handed for each.
 *
 * A lens sees a bundle only where it declares that class `consumed`, and — for
 * `built-artifact` — only where it declares that artifact kind. A lens with no
 * rule for an APK must not be handed one and left to improvise; that is what
 * the `INVENTORY_ONLY` coverage cell records instead.
 */
export function evidenceForLens(lensName, declarations, bundles) {
  const declared = declarations.get(lensName)
  if (!declared) return []
  return bundles
    .filter((bundle) => {
      const entry = declared[bundle.evidence_class]
      if (entry?.state !== 'consumed') return false
      if (bundle.evidence_class !== 'built-artifact') return true
      return (entry.artifact_kinds ?? []).includes(bundle.artifact_kind)
    })
    .map((bundle) => ({
      evidence_context: bundle.evidence_context,
      artifact_kind: bundle.artifact_kind,
      root_sha256: bundle.root_sha256,
      may_conclude: declared[bundle.evidence_class].may_conclude ?? [],
      required_matches: requiredMatchesForLens(lensName, bundle),
      // Absence means no index was supplied. When one was read, retain its
      // completeness state so ingest cannot confuse an unreadable/truncated
      // denominator with a complete empty one.
      ...(bundle.index
        ? {
            locator_index_kind: bundle.index.locator_index_kind,
            ...(bundle.index.unsupported_reason
              ? { unsupported_reason: bundle.index.unsupported_reason }
              : {}),
            ...(bundle.index.rule_analysis
              ? { rule_analysis: bundle.index.rule_analysis }
              : {}),
            layers: bundle.index.layers ?? [],
            entries: bundle.index.entries ?? [],
            truncated_entry_count: bundle.index.truncated ?? 0,
            entry_index_unreadable: bundle.index.unreadable === true,
          }
        : {}),
    }))
    .sort((left, right) => compareCanonicalStrings(
      left.evidence_context.evidence_id,
      right.evidence_context.evidence_id,
    ))
}
