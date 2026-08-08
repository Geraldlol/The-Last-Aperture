import { createHash } from 'node:crypto'
import { compareCanonicalStrings } from './canonical-order.mjs'
import {
  DEFAULT_WORK_SHARD_LIMITS,
  packWorkShards,
} from './work-shards.mjs'

export const COVERAGE_CLASSES = Object.freeze({
  CANONICAL_SOURCE: 'CANONICAL_SOURCE',
  GENERATED_CODE: 'GENERATED_CODE',
  TEST: 'TEST',
  DOCUMENTATION: 'DOCUMENTATION',
  BINARY: 'BINARY',
})

export const DEFAULT_COVERAGE_POLICY = Object.freeze({
  ...DEFAULT_WORK_SHARD_LIMITS,
  maxRounds: 3,
})

const COVERAGE_CLASS_ORDER = Object.freeze([
  COVERAGE_CLASSES.CANONICAL_SOURCE,
  COVERAGE_CLASSES.GENERATED_CODE,
  COVERAGE_CLASSES.TEST,
  COVERAGE_CLASSES.DOCUMENTATION,
  COVERAGE_CLASSES.BINARY,
])

const LEGACY_CATEGORY_BY_CLASS = Object.freeze({
  [COVERAGE_CLASSES.CANONICAL_SOURCE]: 'canonical-source',
  [COVERAGE_CLASSES.GENERATED_CODE]: 'generated-code',
  [COVERAGE_CLASSES.TEST]: 'tests',
  [COVERAGE_CLASSES.DOCUMENTATION]: 'docs',
  [COVERAGE_CLASSES.BINARY]: 'binaries',
})

const TEST_DIRECTORY_NAMES = new Set([
  '__tests__',
  'e2e',
  'integration-test',
  'integration-tests',
  'mocks',
  'spec',
  'specs',
  'test',
  'testdata',
  'tests',
])
const GENERATED_DIRECTORY_NAMES = new Set([
  '.next',
  '.nuxt',
  '.svelte-kit',
  'autogen',
  'bin',
  'build',
  'codegen',
  'coverage',
  'dist',
  'gen',
  'generated',
  'node_modules',
  'obj',
  'out',
  'target',
  'third-party',
  'third_party',
  'vendor',
  'vendors',
])
const DOCUMENTATION_DIRECTORY_NAMES = new Set([
  'adr',
  'doc',
  'docs',
  'documentation',
  'rfc',
  'rfcs',
])
const DOCUMENTATION_EXTENSIONS = new Set([
  '.adoc',
  '.asciidoc',
  '.markdown',
  '.md',
  '.mdx',
  '.rst',
  '.txt',
])
const DOCUMENTATION_BASENAMES = /^(?:authors|changelog|code[-_]of[-_]conduct|contributing|contributors|copying|history|license|notice|readme|security)(?:\.[^.]+)?$/i
const TEST_BASENAMES = /(?:^test[_-].+|.+[_-]test|.+\.(?:spec|test))\.[^.]+$/i
const LANGUAGE_TEST_BASENAMES = /(?:_test\.go|tests?\.(?:cls(?:-meta\.xml)?|cs|java|kt|swift))$/i
const GENERATED_BASENAMES = /(?:\.g|\.gen|\.generated|\.min)\.[^.]+$|\.pb\.(?:cc|go|h|java|js|py|rb|ts)$/i
const GENERATED_CONTENT_MARKERS = [
  /@generated\b/i,
  /\bauto[- ]generated\b/i,
  /\bautomatically generated\b/i,
  /\bcode generated\b[^\r\n]{0,120}\bdo not edit\b/i,
  /\bgenerated automatically\b/i,
  /\bthis file (?:is|was) generated\b/i,
]

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue)
  if (value === null || typeof value !== 'object') return value
  return Object.fromEntries(
    Object.keys(value)
      .sort((left, right) => compareCanonicalStrings(left, right))
      .map((key) => [key, stableValue(value[key])]),
  )
}

function canonicalPath(value) {
  const normalized = String(value).replaceAll('\\', '/').replace(/^(?:\.\/)+/, '')
  if (!normalized) throw new TypeError('coverage path must be a non-empty string')
  return normalized
}

function pathParts(path) {
  const normalized = canonicalPath(path)
  const parts = normalized.split('/')
  return {
    lowerParts: parts.map((part) => part.toLowerCase()),
    basename: parts.at(-1),
  }
}

function extensionOf(basename) {
  const index = basename.lastIndexOf('.')
  return index <= 0 ? '' : basename.slice(index).toLowerCase()
}

function hasDirectory(lowerParts, names) {
  return lowerParts.slice(0, -1).some((part) => names.has(part))
}

/**
 * Assigns one exhaustive coverage class with stable, explicit precedence:
 * binary > test > generated/vendor > documentation > canonical source.
 */
export function classifyCoverageEntry(entry) {
  if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
    throw new TypeError('coverage entry must be an object')
  }
  const { lowerParts, basename } = pathParts(entry.path)

  if (entry.kind === 'binary') {
    return {
      coverage_class: COVERAGE_CLASSES.BINARY,
      classification_reason: 'kind:binary',
    }
  }

  if (hasDirectory(lowerParts, TEST_DIRECTORY_NAMES)) {
    return {
      coverage_class: COVERAGE_CLASSES.TEST,
      classification_reason: 'path:test-directory',
    }
  }
  if (TEST_BASENAMES.test(basename) || LANGUAGE_TEST_BASENAMES.test(basename)) {
    return {
      coverage_class: COVERAGE_CLASSES.TEST,
      classification_reason: 'path:test-filename',
    }
  }

  const generatedDirectory = lowerParts
    .slice(0, -1)
    .find((part) => GENERATED_DIRECTORY_NAMES.has(part))
  if (generatedDirectory) {
    return {
      coverage_class: COVERAGE_CLASSES.GENERATED_CODE,
      classification_reason: [
        'node_modules',
        'third-party',
        'third_party',
        'vendor',
        'vendors',
      ].includes(generatedDirectory)
        ? 'path:vendor-directory'
        : 'path:generated-directory',
    }
  }
  if (GENERATED_BASENAMES.test(basename)) {
    return {
      coverage_class: COVERAGE_CLASSES.GENERATED_CODE,
      classification_reason: 'path:generated-filename',
    }
  }
  if (
    typeof entry.content === 'string'
    && GENERATED_CONTENT_MARKERS.some((pattern) =>
      pattern.test(entry.content.slice(0, 16 * 1024)))
  ) {
    return {
      coverage_class: COVERAGE_CLASSES.GENERATED_CODE,
      classification_reason: 'content:generated-marker',
    }
  }

  if (hasDirectory(lowerParts, DOCUMENTATION_DIRECTORY_NAMES)) {
    return {
      coverage_class: COVERAGE_CLASSES.DOCUMENTATION,
      classification_reason: 'path:documentation-directory',
    }
  }
  if (DOCUMENTATION_BASENAMES.test(basename)) {
    return {
      coverage_class: COVERAGE_CLASSES.DOCUMENTATION,
      classification_reason: 'path:documentation-filename',
    }
  }
  if (DOCUMENTATION_EXTENSIONS.has(extensionOf(basename))) {
    return {
      coverage_class: COVERAGE_CLASSES.DOCUMENTATION,
      classification_reason: 'path:documentation-extension',
    }
  }

  return {
    coverage_class: COVERAGE_CLASSES.CANONICAL_SOURCE,
    classification_reason: 'default:canonical-source',
  }
}

function buildTypedDenominators(records, examinedPaths = []) {
  if (!Array.isArray(records)) {
    throw new TypeError('coverage denominators require typed inventory records')
  }
  if (!Array.isArray(examinedPaths)) {
    throw new TypeError('examinedPaths must be an array')
  }
  const examined = new Set(examinedPaths.map(canonicalPath))
  const rows = new Map(COVERAGE_CLASS_ORDER.map((coverageClass) => [
    coverageClass,
    {
      class: coverageClass,
      files_total: 0,
      bytes_total: 0,
      files_examined: 0,
      bytes_examined: 0,
      files_unexamined: 0,
      bytes_unexamined: 0,
      paths: [],
      files: [],
    },
  ]))

  const seenPaths = new Set()
  for (const entry of records) {
    const coverageClass = entry.coverage_class
    const row = rows.get(coverageClass)
    if (!row) {
      throw new TypeError(`unknown coverage class for ${String(entry.path)}: ${coverageClass}`)
    }
    const path = canonicalPath(entry.path)
    if (seenPaths.has(path)) {
      throw new TypeError(`inventory contains duplicate path: ${path}`)
    }
    seenPaths.add(path)
    if (!Number.isSafeInteger(entry.size) || entry.size < 0) {
      throw new TypeError(`inventory size must be a non-negative safe integer: ${path}`)
    }
    row.files_total += 1
    row.bytes_total += entry.size
    if (!Number.isSafeInteger(row.bytes_total)) {
      throw new RangeError(`coverage byte total exceeds safe integer range for ${coverageClass}`)
    }
    row.paths.push(path)
    row.files.push({ path, size: entry.size })
    if (examined.has(path)) {
      row.files_examined += 1
      row.bytes_examined += entry.size
    }
  }

  return COVERAGE_CLASS_ORDER.map((coverageClass) => {
    const row = rows.get(coverageClass)
    row.paths.sort((left, right) => compareCanonicalStrings(left, right))
    row.files.sort((left, right) => compareCanonicalStrings(left.path, right.path))
    row.files_unexamined = row.files_total - row.files_examined
    row.bytes_unexamined = row.bytes_total - row.bytes_examined
    return row
  })
}

export function inventoryCoverageRecords(entries) {
  if (!Array.isArray(entries)) {
    throw new TypeError('inventory coverage records require entries')
  }
  return entries.map((entry) => {
    const path = canonicalPath(entry?.path)
    if (!Number.isSafeInteger(entry?.size) || entry.size < 0) {
      throw new TypeError(`inventory size must be a non-negative safe integer: ${path}`)
    }
    const hasCoverageClass = typeof entry.coverage_class === 'string'
    const hasClassificationReason = typeof entry.classification_reason === 'string'
    if (hasCoverageClass !== hasClassificationReason) {
      throw new TypeError(
        `inventory classification metadata must be complete: ${path}`,
      )
    }
    const classified = hasCoverageClass
      ? {
          coverage_class: entry.coverage_class,
          classification_reason: entry.classification_reason,
        }
      : classifyCoverageEntry(entry)
    const coverageClass = classified.coverage_class
    const classificationReason = classified.classification_reason
    if (!COVERAGE_CLASS_ORDER.includes(coverageClass)) {
      throw new TypeError(`unknown coverage class for ${path}: ${coverageClass}`)
    }
    if (!classificationReason.trim()) {
      throw new TypeError(`classification reason must be non-empty: ${path}`)
    }
    const derivedCategory = LEGACY_CATEGORY_BY_CLASS[coverageClass]
    if (entry.category !== undefined && entry.category !== derivedCategory) {
      throw new TypeError(`legacy inventory category conflicts with coverage class: ${path}`)
    }
    const category = entry.category ?? derivedCategory
    return {
      path,
      size: entry.size,
      kind: String(entry.kind),
      coverage_class: coverageClass,
      classification_reason: classificationReason,
      category,
      ...(typeof entry.sha256 === 'string' ? { sha256: entry.sha256 } : {}),
    }
  })
}

export function buildCoverageDenominators(inventory, examinedPaths = []) {
  if (
    inventory === null
    || typeof inventory !== 'object'
    || !Array.isArray(inventory.entries)
  ) {
    throw new TypeError('coverage denominators require an inventory with entries')
  }
  return buildTypedDenominators(
    inventoryCoverageRecords(inventory.entries),
    examinedPaths,
  )
}

export function deterministicScopeShards(
  scopedFiles,
  inventoryEntries,
  limits = DEFAULT_COVERAGE_POLICY,
) {
  if (!Array.isArray(scopedFiles)) throw new TypeError('scopedFiles must be an array')
  if (!Array.isArray(inventoryEntries)) {
    throw new TypeError('inventoryEntries must be an array')
  }
  const entriesByPath = new Map()
  for (const entry of inventoryEntries) {
    const path = canonicalPath(entry?.path)
    if (entriesByPath.has(path)) {
      throw new TypeError(`inventory contains duplicate path: ${path}`)
    }
    if (!Number.isSafeInteger(entry?.size) || entry.size < 0) {
      throw new TypeError(`inventory size must be a non-negative safe integer: ${path}`)
    }
    entriesByPath.set(path, entry)
  }

  const normalizedScope = scopedFiles.map(canonicalPath)
  if (new Set(normalizedScope).size !== normalizedScope.length) {
    throw new TypeError('scopedFiles must not contain duplicate paths')
  }
  normalizedScope.sort((left, right) => compareCanonicalStrings(left, right))
  const material = normalizedScope.map((path) => {
    const entry = entriesByPath.get(path)
    if (!entry) throw new TypeError(`scoped file is absent from inventory: ${path}`)
    return {
      path,
      size: entry.size,
      ...(typeof entry.sha256 === 'string' ? { sha256: entry.sha256 } : {}),
    }
  })

  return packWorkShards(material, {
    maxFiles: limits.maxFiles ?? DEFAULT_WORK_SHARD_LIMITS.maxFiles,
    maxBytes: limits.maxBytes ?? DEFAULT_WORK_SHARD_LIMITS.maxBytes,
  }).map(({ scoped_files: scopedFiles, shard }) => ({
    // The old helper remains as a zero-based compatibility adapter. Packing,
    // bounds, and scope identity now have one controller authority.
    index: shard.index - 1,
    count: shard.count,
    file_count: shard.file_count,
    byte_count: shard.byte_count,
    scoped_files: [...scopedFiles],
    scope_sha256: shard.scope_sha256,
  }))
}

/**
 * Backward-compatible function name retained for run-engine callers. The
 * returned rows use the authoritative uppercase coverage-class contract.
 */
export function buildCategoryDenominators(records, examinedPaths = []) {
  return buildTypedDenominators(records, examinedPaths)
}

export function refreshCategoryDenominators(coverage) {
  coverage.denominators = buildCategoryDenominators(
    coverage.inventory_records ?? [],
    coverage.examined ?? [],
  )
  return coverage.denominators
}

export function applicableLensFilePairs(coverage) {
  return (coverage.lenses ?? [])
    .flatMap(({ lens, applicable_paths: applicablePaths = [] }) =>
      applicablePaths.map((path) => ({ lens, path })))
    .sort((left, right) =>
      compareCanonicalStrings(left.lens, right.lens)
      || compareCanonicalStrings(left.path, right.path))
}

export function uncoveredLensFilePairs(coverage) {
  return (coverage.lenses ?? [])
    .flatMap(({ lens, applicable_paths: applicablePaths = [], examined_paths: examinedPaths = [] }) => {
      const examined = new Set(examinedPaths)
      return applicablePaths
        .filter((path) => !examined.has(path))
        .map((path) => ({ lens, path }))
    })
    .sort((left, right) =>
      compareCanonicalStrings(left.lens, right.lens)
      || compareCanonicalStrings(left.path, right.path))
}

export function measureCoverageClosure(coverage, round = 0) {
  const pairs = applicableLensFilePairs(coverage)
  const uncovered = uncoveredLensFilePairs(coverage)
  const uncoveredKeys = new Set(
    uncovered.map(({ lens, path }) => `${lens}\0${path}`),
  )
  const uncoveredShards = (coverage.shards ?? [])
    .filter(({ lens, scoped_files: scopedFiles = [] }) =>
      scopedFiles.some((path) => uncoveredKeys.has(`${lens}\0${path}`)))
    .map(({ job_id: jobId, lens, shard_id: legacyShardId, shard }) => ({
      job_id: jobId,
      lens,
      shard_id: shard?.shard_id ?? legacyShardId,
    }))
    .sort((left, right) => compareCanonicalStrings(left.job_id, right.job_id))
  const material = {
    round,
    applicable_lens_file_pairs: pairs.length,
    examined_lens_file_pairs: pairs.length - uncovered.length,
    uncovered_lens_file_pairs: uncovered.length,
    uncovered_shards: uncoveredShards,
  }
  return {
    ...material,
    measurement_sha256: sha256(JSON.stringify(stableValue(material))),
  }
}

export function sourceClosureGaps(coverage) {
  const canonicalPaths = new Set(
    Array.isArray(coverage.inventory_records)
      ? coverage.inventory_records
          .filter(({ coverage_class: coverageClass, category }) =>
            coverageClass === COVERAGE_CLASSES.CANONICAL_SOURCE
            || (coverageClass === undefined && category === 'canonical-source'))
          .map(({ path }) => path)
      : (coverage.denominators ?? [])
          .filter(({ class: coverageClass }) =>
            coverageClass === COVERAGE_CLASSES.CANONICAL_SOURCE)
          .flatMap(({ paths = [], files = [] }) =>
            paths.length > 0 ? paths : files.map(({ path }) => path)),
  )
  const examined = new Set(coverage.examined ?? [])
  const applicablePairs = applicableLensFilePairs(coverage)
    .filter(({ path }) => canonicalPaths.has(path))
  // Source closure is a property of the canonical source inventory, not of the
  // activated lens set: a canonical file no lens declares applicable is still
  // an unexamined source file.
  const fileGaps = [...canonicalPaths]
    .filter((path) => !examined.has(path))
    .sort((left, right) => compareCanonicalStrings(left, right))
    .map((path) => ({ kind: 'canonical-source-file', path }))
  const examinedByLens = new Map(
    (coverage.lenses ?? []).map(({ lens, examined_paths: paths = [] }) => [
      lens,
      new Set(paths),
    ]),
  )
  const pairGaps = applicablePairs
    .filter(({ lens, path }) => !examinedByLens.get(lens)?.has(path))
    .map(({ lens, path }) => ({
      kind: 'canonical-source-lens-file',
      lens,
      path,
    }))
  return [...fileGaps, ...pairGaps]
}
