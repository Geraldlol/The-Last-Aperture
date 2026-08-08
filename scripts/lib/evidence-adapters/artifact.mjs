import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { compareCanonicalStrings } from '../canonical-order.mjs'
import { writeEvidenceBundle } from '../evidence-bundle.mjs'
import {
  DEFAULT_NORMALIZER_LIMITS,
  layerContentBytes,
  normalizeOciLayout,
  readTarEntries,
  readTarEntryBytes,
} from '../oci-normalizer.mjs'

const ADAPTER_VERSION = '1.0.0'
export const DEFAULT_ARTIFACT_LIMITS = Object.freeze({
  ...DEFAULT_NORMALIZER_LIMITS,
  maxCapturedEntryBytes: 1024 * 1024,
})

// Every canonical capability, declared once. Offline file reading touches no
// target, so there is nothing for this adapter to count: impact accounting
// belongs to whatever does reach a target.
const CAPABILITIES = Object.freeze({
  'target-identity': 'NATIVE',
  'content-enumeration': 'NATIVE',
  'content-retrieval': 'NATIVE',
  'layer-or-revision-history': 'NATIVE',
  'metadata-provenance': 'COMPOSABLE',
  'deletion-recoverability': 'NATIVE',
  'effective-configuration': 'EXTERNAL_ONLY',
  'principal-and-permission-state': 'EXTERNAL_ONLY',
  'secret-material-surface': 'NATIVE',
  'impact-accounting': 'EXTERNAL_ONLY',
})

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

// Zero-padded so a ten-layer image still sorts correctly, and so
// `<evidence_id>:layer/02/<path>` resolves to exactly one directory.
function layerDirectory(index) {
  return String(index).padStart(2, '0')
}

/**
 * The bundle payload built from a normalized image. Shared so a second
 * built-artifact adapter emits the identical layout rather than a parallel one.
 */
export function buildArtifactPayload(archiveBytes, normalized, limits = DEFAULT_ARTIFACT_LIMITS) {
  const gaps = normalized.gaps.map(({ area, reason }) => ({ area, reason }))
  const payload = [
    {
      path: 'normalized.json',
      bytes: Buffer.from(JSON.stringify({
        format: normalized.format,
        config_digest: normalized.config.digest,
        diff_ids: normalized.config.diff_ids,
        layers: normalized.layers.map(({ index, digest, media_type: mediaType, entry_count: count }) => ({
          index,
          directory: layerDirectory(index),
          digest,
          media_type: mediaType,
          entry_count: count,
        })),
        gaps,
      }, null, 2), 'utf8'),
    },
    {
      path: 'config/history.json',
      bytes: Buffer.from(JSON.stringify(normalized.config.history, null, 2), 'utf8'),
    },
    {
      path: 'orphan-blobs.json',
      bytes: Buffer.from(JSON.stringify(normalized.orphan_blobs, null, 2), 'utf8'),
    },
  ]

  for (const layer of normalized.layers) {
    payload.push({
      path: `layers/${layerDirectory(layer.index)}/entries.json`,
      bytes: Buffer.from(JSON.stringify(layer.entries, null, 2), 'utf8'),
    })
  }

  // Entry contents, addressable by the locator a finding will cite. The outer
  // archive is indexed once rather than per layer.
  let omitted = 0
  if (normalized.format !== 'unknown') {
    const outer = readTarEntries(archiveBytes, limits)
    const byPath = new Map(outer.map((entry) => [entry.path, entry]))
    for (const layer of normalized.layers) {
      const directory = layerDirectory(layer.index)
      const layerBytes = layerContentBytes(archiveBytes, layer, byPath)
      if (layerBytes === null) continue
      for (const entry of readTarEntries(layerBytes, limits)) {
        if (entry.type !== 'file' || entry.size === 0) continue
        if (entry.size > limits.maxCapturedEntryBytes) {
          omitted += 1
          continue
        }
        payload.push({
          path: `layers/${directory}/content/${entry.path}`,
          bytes: Buffer.from(readTarEntryBytes(layerBytes, entry)),
        })
      }
    }
  }
  if (omitted > 0) {
    gaps.push({
      area: 'layer content',
      reason: `${omitted} entr${omitted === 1 ? 'y was' : 'ies were'} above the `
        + `${limits.maxCapturedEntryBytes}-byte content cap and are listed but not captured`,
    })
  }

  payload.sort((left, right) => compareCanonicalStrings(left.path, right.path))
  return { payload, gaps }
}

export function createArtifactAdapter({
  clock = () => new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
  limits = {},
} = {}) {
  const effectiveLimits = { ...DEFAULT_ARTIFACT_LIMITS, ...limits }

  return {
    describe: () => ({
      adapter_id: 'artifact',
      evidence_class: 'built-artifact',
      adapter_version: ADAPTER_VERSION,
      capabilities: { ...CAPABILITIES },
      external_dependency: null,
    }),

    // Planning reads the supplied bytes to seal an exact identity and nothing
    // else. A missing source fails here, not silently at run time as an empty
    // success — a missing dependency is a failure, never an empty success.
    plan: async (request) => {
      let bytes
      try {
        bytes = await readFile(request.source_path)
      } catch (error) {
        throw new Error(`artifact source not found: ${request.source_path} (${error.code})`)
      }
      const digest = sha256(bytes)
      return {
        plan_id: `artifact:${digest.slice(0, 16)}`,
        source_path: request.source_path,
        evidence_context_seed: {
          evidence_id: request.evidence_id,
          evidence_class: 'built-artifact',
          adapter_id: 'artifact',
          target_identity: `sha256:${digest}`,
          acquisition_mode: 'offline-export',
          detection_evidence: [`${request.source_path} sha256:${digest.slice(0, 8)}`],
          confidence: 'high',
        },
        target_class: request.target_class ?? 'LAB',
        phi_scope: request.phi_scope ?? 'none',
        dependency: { name: null, present: true, version: null },
      }
    },

    run: async (planned, { out }) => {
      const bytes = await readFile(planned.source_path)
      const normalized = normalizeOciLayout(bytes, effectiveLimits)
      const { payload, gaps } = buildArtifactPayload(bytes, normalized, effectiveLimits)

      const coverageState = normalized.layers.length === 0
        ? 'NOT_ASSESSED'
        : gaps.length > 0 ? 'PARTIAL' : 'COVERED'

      return writeEvidenceBundle({
        directory: out,
        profile: {
          schema: 'evidence-bundle-v1',
          evidence_context: {
            ...planned.evidence_context_seed,
            acquired_on: clock(),
          },
          target_class: planned.target_class,
          phi_scope: planned.phi_scope,
          phi_bearing: false,
          adapter_version: ADAPTER_VERSION,
          contract_version: 1,
          coverage_state: coverageState,
          artifact_kind: 'oci-image',
          attestation: null,
          coverage_gaps: gaps,
        },
        payload,
      })
    },
  }
}
