import { compareCanonicalStrings } from './canonical-order.mjs'
import { readEvidencePayloadFile } from './evidence-bundle.mjs'

export const DEFAULT_EVIDENCE_PACKET_LIMITS = Object.freeze({
  maxEntriesPerBundle: 2000,
})

/**
 * The normalized entry index of one acquired bundle, read at plan time.
 *
 * Fan-out gets the index, not the bytes: a lens reasons about what is in the
 * artifact — paths, modes, sizes, mtimes, whiteout verdicts — and cites a
 * locator, which `existence_check` resolves against the sealed bundle later.
 * Embedding contents would put a whole image inside every packet.
 *
 * Truncation is reported, never silent: a lens that was handed 2000 of 5000
 * entries and told nothing would report on a subset as though it were the set.
 */
export async function readEvidenceIndex(directory, limits = DEFAULT_EVIDENCE_PACKET_LIMITS) {
  const read = async (path) => {
    try {
      return JSON.parse((await readEvidencePayloadFile(directory, path)).toString('utf8'))
    } catch {
      return null
    }
  }

  const normalized = await read('payload/normalized.json')
  if (!normalized) {
    return { entries: [], layers: [], truncated: 0, unreadable: true }
  }

  const entries = []
  let truncated = 0
  for (const layer of normalized.layers ?? []) {
    const layerEntries = await read(`payload/layers/${layer.directory}/entries.json`) ?? []
    for (const entry of layerEntries) {
      if (entries.length >= limits.maxEntriesPerBundle) {
        truncated += 1
        continue
      }
      entries.push({
        locator: `layer/${layer.directory}/${entry.path}`,
        path: entry.path,
        layer: layer.index,
        mode: entry.mode,
        size: entry.size,
        mtime: entry.mtime,
        type: entry.type,
        whiteout: entry.whiteout,
      })
    }
  }

  return {
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
      layers: bundle.index?.layers ?? [],
      entries: bundle.index?.entries ?? [],
      truncated_entry_count: bundle.index?.truncated ?? 0,
    }))
    .sort((left, right) => compareCanonicalStrings(
      left.evidence_context.evidence_id,
      right.evidence_context.evidence_id,
    ))
}
