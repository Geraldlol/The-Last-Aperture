import test from 'node:test'
import assert from 'node:assert/strict'

import {
  createLensFileCoverageGap,
  exactCoverageGapId,
  filterResolvedCoverageGaps,
  MAX_COVERAGE_GAP_EXAMPLE_LIMIT,
  MAX_COVERAGE_GAP_EXAMPLE_TEXT,
  projectCoverageGaps,
} from '../scripts/lib/coverage-gaps.mjs'

test('lens/file identity is stable across retry jobs, reasons, and path separators', () => {
  const first = createLensFileCoverageGap({
    lens: 'web-and-api',
    path: './src\\routes\\orders.ts',
    reason: 'first provider attempt omitted the scoped file',
    job_id: 'closure:r1:lens:web-and-api:attempt-1',
  })
  const retry = createLensFileCoverageGap({
    lens: 'web-and-api',
    path: 'src/routes/orders.ts',
    reason: 'retry timed out before examining the scoped file',
    job_id: 'closure:r1:lens:web-and-api:attempt-2',
  })

  assert.equal(first.gap_id, retry.gap_id)
  assert.equal(first.area, 'lens:web-and-api:src/routes/orders.ts')
  assert.equal(Object.hasOwn(first, 'job_id'), false)
  assert.equal(exactCoverageGapId(first), first.gap_id)
})

test('legacy area/reason gaps retain exact identity and survive filtering unchanged', () => {
  const legacy = {
    area: 'generated/client.js',
    reason: 'text input matched no domain lens',
  }
  const open = filterResolvedCoverageGaps([legacy])

  assert.equal(open[0], legacy)
  assert.match(exactCoverageGapId(legacy), /^coverage-gap:sha256:[a-f0-9]{64}$/)
  assert.deepEqual(projectCoverageGaps([legacy], { maxExamples: 1 }).examples, [{
    gap_id: exactCoverageGapId(legacy),
    area: legacy.area,
    reason: legacy.reason,
  }])
})

test('repeated retry gaps deduplicate and one exact resolution closes every retry', () => {
  const first = createLensFileCoverageGap({
    lens: 'privacy-and-data-protection',
    path: 'src/export.ts',
    reason: 'initial closure attempt did not examine the file',
  })
  const retry = createLensFileCoverageGap({
    lens: 'privacy-and-data-protection',
    path: 'src/export.ts',
    reason: 'second closure attempt did not examine the file',
  })

  const open = projectCoverageGaps([first, retry])
  assert.equal(open.input_gap_count, 2)
  assert.equal(open.exact_open_gap_count, 1)
  assert.equal(open.unique_open_gap_count, 1)
  assert.equal(open.unique_open_lens_gap_count, 1)
  assert.equal(open.unique_open_non_lens_gap_count, 0)
  assert.equal(open.exact_open_lens_file_gap_count, 1)

  const resolved = projectCoverageGaps(
    [first, retry],
    { resolvedGapIds: [{ gap_id: first.gap_id }] },
  )
  assert.equal(resolved.open_input_gap_count, 0)
  assert.equal(resolved.resolved_input_gap_count, 2)
  assert.equal(resolved.exact_open_gap_count, 0)
  assert.equal(resolved.unique_open_gap_count, 0)
  assert.equal(resolved.unique_open_lens_gap_count, 0)
  assert.equal(resolved.unique_open_non_lens_gap_count, 0)
  assert.equal(resolved.exact_open_lens_file_gap_count, 0)
  assert.deepEqual(filterResolvedCoverageGaps(
    [first, retry],
    new Set([first.gap_id]),
  ), [])
})

test('conceptual legacy projection groups reason variants without losing exact counts', () => {
  const gaps = [
    { area: 'src/unassigned.ts', reason: 'matched no domain lens' },
    { area: 'src/unassigned.ts', reason: 'provider reported no applicable lens' },
  ]
  const forward = projectCoverageGaps(gaps, { maxExamples: 1 })
  const reverse = projectCoverageGaps([...gaps].reverse(), { maxExamples: 1 })

  assert.equal(forward.exact_open_gap_count, 2)
  assert.equal(forward.unique_open_gap_count, 1)
  assert.equal(forward.unique_open_lens_gap_count, 0)
  assert.equal(forward.unique_open_non_lens_gap_count, 1)
  assert.equal(forward.exact_open_lens_file_gap_count, 0)
  assert.deepEqual(forward, reverse)
})

test('conceptual lens gaps stay separate from exact lens/file obligations', () => {
  const gaps = [
    createLensFileCoverageGap({
      lens: 'web-and-api',
      path: 'src/routes/a.ts',
      reason: 'not examined',
    }),
    createLensFileCoverageGap({
      lens: 'web-and-api',
      path: 'src/routes/b.ts',
      reason: 'not examined',
    }),
    createLensFileCoverageGap({
      lens: 'privacy-and-data-protection',
      path: 'src/routes/a.ts',
      reason: 'not examined',
    }),
  ]
  const projection = projectCoverageGaps(gaps)

  assert.equal(projection.unique_open_gap_count, 2)
  assert.equal(projection.unique_open_lens_gap_count, 2)
  assert.equal(projection.unique_open_non_lens_gap_count, 0)
  assert.equal(projection.exact_open_gap_count, 3)
  assert.equal(projection.exact_open_lens_file_gap_count, 3)
})

test('rendered examples are deterministically ordered and strictly bounded', () => {
  const gaps = Array.from({ length: 5 }, (_, index) => ({
    area: `src/${String(4 - index)}.ts`,
    reason: `gap ${index}: ${'x'.repeat(MAX_COVERAGE_GAP_EXAMPLE_TEXT * 2)}`,
  }))
  const projection = projectCoverageGaps(gaps, { maxExamples: 2 })

  assert.equal(projection.examples.length, 2)
  assert.equal(projection.omitted_example_count, 3)
  assert.deepEqual(
    projection.examples.map(({ area }) => area),
    ['src/0.ts', 'src/1.ts'],
  )
  assert.ok(projection.examples.every(
    ({ reason }) => reason.length <= MAX_COVERAGE_GAP_EXAMPLE_TEXT,
  ))
  assert.throws(
    () => projectCoverageGaps(gaps, {
      maxExamples: MAX_COVERAGE_GAP_EXAMPLE_LIMIT + 1,
    }),
    /maxExamples/,
  )
})
