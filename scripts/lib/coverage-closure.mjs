import {
  COVERAGE_CLASSES,
  applicableLensFilePairs,
  sourceClosureGaps,
  uncoveredLensFilePairs,
} from './coverage-model.mjs'
import {
  filterResolvedCoverageGaps,
  projectCoverageGaps,
} from './coverage-gaps.mjs'

function modeledCoverage(coverage) {
  return (
    coverage?.model_version === '2.0.0'
    && coverage.policy !== null
    && typeof coverage.policy === 'object'
    && Array.isArray(coverage.inventory_records)
    && Array.isArray(coverage.denominators)
    && Array.isArray(coverage.shards)
    && coverage.closure !== null
    && typeof coverage.closure === 'object'
  )
}

function coverageClass(row) {
  if (row?.class) return row.class
  return {
    'canonical-source': COVERAGE_CLASSES.CANONICAL_SOURCE,
    'generated-code': COVERAGE_CLASSES.GENERATED_CODE,
    tests: COVERAGE_CLASSES.TEST,
    docs: COVERAGE_CLASSES.DOCUMENTATION,
    binaries: COVERAGE_CLASSES.BINARY,
  }[row?.category]
}

export function finalizedFanoutLensRows(run) {
  const coverage = run?.coverage
  return (coverage?.lenses ?? []).map((row) => {
    const lensJobs = (run.jobs ?? []).filter(
      (job) => job.kind === 'LENS' && job.lens === row.lens,
    )
    if (
      // A row that declares no lens/file obligations is a legacy row whose
      // status is authored by the ingest path, not reconciled here.
      !Array.isArray(row.applicable_paths)
      || lensJobs.length === 0
      || row.status === 'NOT_TRIGGERED'
      || !lensJobs.some(({ state }) => state !== 'SKIPPED' && state !== 'DORMANT')
    ) {
      return row
    }
    const examined = new Set(row.examined_paths ?? [])
    const missing = (row.applicable_paths ?? [])
      .filter((path) => !examined.has(path))
    if (missing.length === 0) {
      if (row.status === 'RAN') return row
      const { reason: _reason, ...withoutReason } = row
      return { ...withoutReason, status: 'RAN' }
    }
    const failed = lensJobs.some(({ state }) => state === 'FAILED')
    const nextStatus = failed ? 'FAILED' : 'NOT_ASSESSED'
    if (row.status === nextStatus) return row
    const rounds = 1 + Math.max(
      0,
      ...lensJobs
        .filter(({ state }) => state !== 'DORMANT')
        .map((job) => job.closure_round ?? 0),
    )
    return {
      ...row,
      status: nextStatus,
      reason: (
        `${missing.length} lens/file obligation${missing.length === 1 ? '' : 's'} ` +
        `remain after ${rounds} bounded coverage round${rounds === 1 ? '' : 's'}`
      ),
    }
  })
}

export function coverageMetrics(coverage) {
  const examined = new Set(coverage?.examined ?? [])
  const recordsByClass = new Map()
  for (const record of coverage?.inventory_records ?? []) {
    const key = record.coverage_class ?? coverageClass(record)
    if (!recordsByClass.has(key)) recordsByClass.set(key, [])
    recordsByClass.get(key).push(record)
  }
  const denominatorRows = (coverage?.denominators ?? []).map((row) => {
    const files = row.files
      ?? recordsByClass.get(coverageClass(row))
      ?? (row.paths ?? []).map((path) => ({ path, size: 0 }))
    const examinedFiles = files.filter(({ path }) => examined.has(path))
    const bytesTotal = files.reduce((total, { size = 0 }) => total + size, 0)
    const bytesExamined = examinedFiles.reduce(
      (total, { size = 0 }) => total + size,
      0,
    )
    return {
      class: coverageClass(row),
      files_total: files.length,
      bytes_total: bytesTotal,
      files_examined: examinedFiles.length,
      bytes_examined: bytesExamined,
      files_unexamined: files.length - examinedFiles.length,
      bytes_unexamined: bytesTotal - bytesExamined,
    }
  })
  const obligationsByLens = (coverage?.lenses ?? []).map((row) => {
    const applicable = new Set(row.applicable_paths ?? [])
    const lensExamined = new Set(row.examined_paths ?? [])
    const examinedCount = [...applicable].filter((path) => lensExamined.has(path)).length
    return {
      lens: row.lens,
      total: applicable.size,
      examined: examinedCount,
      open: applicable.size - examinedCount,
    }
  })
  const uniqueOpenFiles = new Set(
    (coverage?.unexamined ?? []).map(({ path }) => path),
  )
  for (const gap of filterResolvedCoverageGaps(
    coverage?.gaps ?? [],
    coverage?.resolved_gap_ids ?? [],
  )) {
    if (typeof gap.path === 'string') uniqueOpenFiles.add(gap.path)
  }
  const projected = projectCoverageGaps(
    coverage?.gaps ?? [],
    { resolvedGapIds: coverage?.resolved_gap_ids ?? [] },
  )
  return {
    unique_files: {
      total: coverage?.inventory?.length ?? 0,
      examined: examined.size,
      open: uniqueOpenFiles.size,
    },
    denominators: denominatorRows,
    obligations: {
      total: obligationsByLens.reduce((total, row) => total + row.total, 0),
      examined: obligationsByLens.reduce((total, row) => total + row.examined, 0),
      open: obligationsByLens.reduce((total, row) => total + row.open, 0),
      by_lens: obligationsByLens,
    },
    unique_non_file_gap_groups:
      projected.unique_open_non_lens_gap_count,
    raw_open_gap_records: projected.open_input_gap_count,
    gap_projection: projected,
  }
}

export function isModeledCoverage(coverage) {
  return modeledCoverage(coverage)
}

export { applicableLensFilePairs, sourceClosureGaps, uncoveredLensFilePairs }
