import { createHash } from 'node:crypto'
import { compareCanonicalStrings } from './canonical-order.mjs'

export const DEFAULT_COVERAGE_GAP_EXAMPLE_LIMIT = 20
export const MAX_COVERAGE_GAP_EXAMPLE_LIMIT = 100
export const MAX_COVERAGE_GAP_EXAMPLE_TEXT = 240

const GAP_ID_PREFIX = 'coverage-gap:sha256:'

function nonEmptyString(value, name) {
  if (typeof value !== 'string' || !/\S/.test(value)) {
    throw new TypeError(`${name} must be a non-empty string`)
  }
  return value
}

function normalizedLens(value) {
  const lens = nonEmptyString(value, 'lens').trim()
  if (!/^[a-z0-9][a-z0-9-]*$/.test(lens)) {
    throw new TypeError('lens must be a canonical lower-case lens name')
  }
  return lens
}

function normalizedInventoryPath(value) {
  const original = nonEmptyString(value, 'path').trim()
  const normalized = original
    .replaceAll('\\', '/')
    .replace(/^\.\/+/, '')
    .replace(/\/+/g, '/')
  const segments = normalized.split('/')
  if (
    normalized.length === 0
    || normalized.startsWith('/')
    || /^[A-Za-z]:/.test(normalized)
    || segments.some((segment) => segment === '' || segment === '.' || segment === '..')
  ) {
    throw new TypeError('path must be a canonical repository-relative inventory path')
  }
  return normalized
}

function isLensFileGap(value) {
  return value?.kind === 'LENS_FILE'
}

function lensFileIdentity(value) {
  return [
    'LENS_FILE',
    normalizedLens(value.lens),
    normalizedInventoryPath(value.path),
  ]
}

function legacyIdentity(value) {
  return [
    'LEGACY',
    nonEmptyString(value?.area, 'area'),
    nonEmptyString(value?.reason, 'reason'),
  ]
}

function exactIdentity(value) {
  return isLensFileGap(value) ? lensFileIdentity(value) : legacyIdentity(value)
}

function digestIdentity(identity) {
  return createHash('sha256')
    .update(JSON.stringify(identity), 'utf8')
    .digest('hex')
}

/**
 * Return the stable identity of one exact gap.
 *
 * Structured lens/file gaps are identified by the immutable lens and inventory
 * path. Provider wording and retry job IDs are deliberately not identity.
 * Legacy gaps retain their historical exact `{ area, reason }` identity.
 */
export function exactCoverageGapId(gap) {
  return `${GAP_ID_PREFIX}${digestIdentity(exactIdentity(gap))}`
}

/**
 * Create a legacy-compatible lens/file gap with controller-stable identity.
 * Extra caller metadata, including a retry job ID, is intentionally discarded.
 */
export function createLensFileCoverageGap({ lens, path, reason }) {
  const normalized = {
    kind: 'LENS_FILE',
    lens: normalizedLens(lens),
    path: normalizedInventoryPath(path),
    reason: nonEmptyString(reason, 'reason').trim(),
  }
  return {
    gap_id: exactCoverageGapId(normalized),
    ...normalized,
    area: `lens:${normalized.lens}:${normalized.path}`,
  }
}

function resolutionId(value) {
  if (typeof value === 'string') return nonEmptyString(value, 'resolved gap ID')
  return nonEmptyString(value?.gap_id, 'resolution.gap_id')
}

function resolutionSet(values) {
  if (!(Array.isArray(values) || values instanceof Set)) {
    throw new TypeError('resolved gap IDs must be an array or Set')
  }
  return new Set([...values].map(resolutionId))
}

/**
 * Filter resolved identities without rewriting the surviving gap records.
 * This preserves historical `{ area, reason }` objects byte-for-byte at the
 * object-property level for callers that still persist the legacy shape.
 */
export function filterResolvedCoverageGaps(gaps, resolvedGapIds = []) {
  if (!Array.isArray(gaps)) throw new TypeError('coverage gaps must be an array')
  const resolved = resolutionSet(resolvedGapIds)
  return gaps.filter((gap) => !resolved.has(exactCoverageGapId(gap)))
}

function conceptualIdentity(gap) {
  // One conceptual lens coverage failure can affect many exact file
  // obligations. Reports expose both denominators instead of inflating the
  // conceptual count by the shard/file fan-out.
  if (isLensFileGap(gap)) {
    return ['LENS_FILE_LENS', normalizedLens(gap.lens)]
  }
  return ['LEGACY_AREA', nonEmptyString(gap?.area, 'area')]
}

function canonicalRecordKey(gap) {
  return JSON.stringify([
    gap.area,
    isLensFileGap(gap) ? gap.lens : '',
    isLensFileGap(gap) ? gap.path : '',
    gap.reason,
    exactCoverageGapId(gap),
  ])
}

function preferredRecord(current, candidate) {
  if (current === undefined) return candidate
  return compareCanonicalStrings(canonicalRecordKey(candidate), canonicalRecordKey(current)) < 0
    ? candidate
    : current
}

function boundedText(value) {
  const text = String(value)
  if (text.length <= MAX_COVERAGE_GAP_EXAMPLE_TEXT) return text
  return `${text.slice(0, MAX_COVERAGE_GAP_EXAMPLE_TEXT - 1)}…`
}

function renderedExample(gap) {
  return {
    gap_id: exactCoverageGapId(gap),
    area: boundedText(gap.area),
    reason: boundedText(gap.reason),
    ...(isLensFileGap(gap)
      ? {
          kind: 'LENS_FILE',
          lens: gap.lens,
          path: boundedText(gap.path),
        }
      : {}),
  }
}

function exampleLimit(value) {
  if (
    !Number.isSafeInteger(value)
    || value < 0
    || value > MAX_COVERAGE_GAP_EXAMPLE_LIMIT
  ) {
    throw new RangeError(
      `maxExamples must be an integer from 0 through ${MAX_COVERAGE_GAP_EXAMPLE_LIMIT}`,
    )
  }
  return value
}

/**
 * Produce bounded reporting counters without treating retry attempts as new
 * conceptual coverage holes.
 *
 * - `exact_open_gap_count` counts stable exact identities.
 * - `unique_open_gap_count` groups legacy records by area and structured
 *   lens/file records by lens-level coverage failure.
 * - `exact_open_lens_file_gap_count` counts exact `(lens, path)` obligations.
 */
export function projectCoverageGaps(
  gaps,
  {
    resolvedGapIds = [],
    maxExamples = DEFAULT_COVERAGE_GAP_EXAMPLE_LIMIT,
  } = {},
) {
  if (!Array.isArray(gaps)) throw new TypeError('coverage gaps must be an array')
  const limit = exampleLimit(maxExamples)
  const resolved = resolutionSet(resolvedGapIds)
  const allExact = new Map()
  const openExact = new Map()
  const openConcepts = new Map()
  const openLensFiles = new Set()
  const openLensConcepts = new Set()
  const openLegacyConcepts = new Set()
  let openInputGapCount = 0

  for (const gap of gaps) {
    const exactId = exactCoverageGapId(gap)
    allExact.set(exactId, preferredRecord(allExact.get(exactId), gap))
    if (resolved.has(exactId)) continue
    openInputGapCount += 1
    openExact.set(exactId, preferredRecord(openExact.get(exactId), gap))
    const conceptId = digestIdentity(conceptualIdentity(gap))
    openConcepts.set(
      conceptId,
      preferredRecord(openConcepts.get(conceptId), gap),
    )
    if (isLensFileGap(gap)) {
      openLensFiles.add(exactId)
      openLensConcepts.add(normalizedLens(gap.lens))
    } else {
      openLegacyConcepts.add(nonEmptyString(gap?.area, 'area'))
    }
  }

  const examples = [...openConcepts.values()]
    .sort((left, right) =>
      compareCanonicalStrings(canonicalRecordKey(left), canonicalRecordKey(right)))
    .slice(0, limit)
    .map(renderedExample)

  return {
    input_gap_count: gaps.length,
    open_input_gap_count: openInputGapCount,
    resolved_input_gap_count: gaps.length - openInputGapCount,
    exact_gap_count: allExact.size,
    exact_open_gap_count: openExact.size,
    unique_open_gap_count: openConcepts.size,
    unique_open_lens_gap_count: openLensConcepts.size,
    unique_open_non_lens_gap_count: openLegacyConcepts.size,
    exact_open_lens_file_gap_count: openLensFiles.size,
    examples,
    omitted_example_count: Math.max(0, openConcepts.size - examples.length),
  }
}
